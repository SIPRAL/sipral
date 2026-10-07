// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What one stack does with two hundred calls on it at once.
//!
//! `sipral_media_*` locks only the call's own session, never the stack
//! (`docs/08-ffi.md`, "Audio on its own thread"). This checks that claim under
//! contention: 200 calls on 4 threads, asserting no [`SipralStatus::Busy`] and
//! a bounded cost per frame. `scripts/bench.sh` collects the printed numbers
//! into `docs/19-numbers.md`. No sockets: audio goes through
//! `sipral_media_receive`, so only the library's cost is measured.

use core::ffi::c_char;
use core::ptr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use crate::call::tests::{accepted, deliver, managed_config, media_line, place, sent};
use crate::media::tests::{FRAME, media_of, release};
use crate::media::{sipral_media_playback, sipral_media_receive};
use crate::stack::tests::{Observed, poll};
use crate::status::SipralStatus;

const CALLS: usize = 200;

/// A thread pool, as an application would use.
const THREADS: usize = 4;

/// Five seconds of 20 ms frames; `SIPRAL_LOAD_FRAMES` raises it for bench.
const FRAMES: usize = 250;

/// Each call on its own port, so media cannot be confused.
fn answer_for(n: usize) -> Vec<u8> {
    format!(
        "v=0\r\n\
         o=bob 1 1 IN IP4 203.0.113.5\r\n\
         s=-\r\n\
         c=IN IP4 203.0.113.5\r\n\
         t=0 0\r\n\
         m=audio {} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=sendrecv\r\n",
        41_000 + n
    )
    .into_bytes()
}

fn packet(n: usize, seq: u16) -> Vec<u8> {
    let mut out = vec![0x80, 0x00];
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    // one SSRC per call
    out.extend_from_slice(&(0xDEAD_0000_u32 + u32::try_from(n).unwrap_or(0)).to_be_bytes());
    out.extend_from_slice(&[0xFF; FRAME]);
    out
}

/// The negotiated peer address; a session takes audio only from there.
fn peer_for(n: usize) -> String {
    format!("203.0.113.5:{}", 41_000 + n)
}

/// An environment override; `scripts/bench.sh` runs 1 and 200 calls so the
/// peak-memory difference is the cost of a call.
fn sized(name: &str, fallback: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(fallback)
}

// one scenario read top to bottom: set up, drive, judge
#[allow(clippy::too_many_lines)]
#[test]
fn two_hundred_calls_run_on_four_threads_without_one_waiting_on_another() {
    let calls = sized("SIPRAL_LOAD_CALLS", CALLS);
    let mut observed = Observed::default();
    let starting = Instant::now();
    // past the default ceiling of 128 calls
    let (stack, account) = media_line(&mut observed, |config| {
        config.max_dialogs = u32::try_from(calls).unwrap_or(u32::MAX);
    });
    let started = starting.elapsed();

    let mut media = Vec::with_capacity(calls);
    // the stack refuses two sessions on one port
    let addresses: Vec<String> = (0..calls)
        .map(|n| format!("192.0.2.10:{}", 40_000 + n))
        .collect();
    let setting_up = Instant::now();
    for (n, address) in addresses.iter().enumerate() {
        let mut config = managed_config();
        config.media_address = address.as_ptr().cast::<c_char>();
        config.media_address_len = address.len();
        // time must not go backwards, so calls are 100 ms apart
        let at = 1_000 + u64::try_from(n).unwrap_or(0) * 100;
        let (status, call) = place(stack, account, &config, at);
        assert_eq!(
            status,
            SipralStatus::Ok,
            "call {n} was not placed: {}",
            crate::error::last_error_text()
        );
        // not `one`: the queue also holds ACKs for earlier calls
        let invite = sent(stack)
            .into_iter()
            .rev()
            .find(|message| message.starts_with(b"INVITE"))
            .expect("the INVITE this call just placed");
        deliver(stack, &accepted(&invite, &answer_for(n), true), at + 50);
        poll(stack, at + 50);
        media.push(media_of(stack, call));
    }
    let per_call_setup = setting_up.elapsed() / u32::try_from(calls).unwrap_or(1);
    let peers: Vec<String> = (0..calls).map(peer_for).collect();
    let audio_from = 1_000 + u64::try_from(calls).unwrap_or(0) * 100 + 100;

    let frames = sized("SIPRAL_LOAD_FRAMES", FRAMES);

    let busy = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let nanos = Arc::new(AtomicU64::new(0));
    let start = Arc::new(Barrier::new(THREADS));
    let began = Instant::now();

    thread::scope(|scope| {
        for thread_index in 0..THREADS {
            let media = &media;
            let peers = &peers;
            let busy = Arc::clone(&busy);
            let refused = Arc::clone(&refused);
            let nanos = Arc::clone(&nanos);
            let start = Arc::clone(&start);
            scope.spawn(move || {
                let mut samples = [0_i16; FRAME];
                let mut written = 0_usize;
                start.wait();
                let mine = began;
                let _ = mine;
                let turn = Instant::now();
                for frame in 0..frames {
                    for (n, handle) in media.iter().enumerate() {
                        if n % THREADS != thread_index {
                            continue;
                        }
                        let seq = u16::try_from(frame % usize::from(u16::MAX)).unwrap_or(0);
                        let mut datagram = packet(n, seq);
                        let status = unsafe {
                            sipral_media_receive(
                                *handle,
                                datagram.as_mut_ptr(),
                                datagram.len(),
                                peers[n].as_ptr().cast::<c_char>(),
                                peers[n].len(),
                                audio_from + u64::try_from(frame).unwrap_or(0) * 20,
                                ptr::null_mut(),
                            )
                        };
                        count(&busy, &refused, status);
                        let status = unsafe {
                            sipral_media_playback(
                                *handle,
                                samples.as_mut_ptr(),
                                samples.len(),
                                &raw mut written,
                                ptr::null_mut(),
                            )
                        };
                        count(&busy, &refused, status);
                    }
                }
                nanos.fetch_add(
                    u64::try_from(turn.elapsed().as_nanos()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
            });
        }
    });

    let elapsed = began.elapsed();
    let turns = calls * frames;
    let per_frame = nanos.load(Ordering::Relaxed) / u64::try_from(turns).unwrap_or(1);
    println!(
        "load: {calls} calls, {THREADS} threads, {frames} frames each: {turns} frames in \
         {:.2}s, {per_frame} ns of wall time per frame (receive and playback), \
         {} us to open the stack, {} us to bring up a call, {} busy, {} refused",
        elapsed.as_secs_f64(),
        started.as_micros(),
        per_call_setup.as_micros(),
        busy.load(Ordering::Relaxed),
        refused.load(Ordering::Relaxed),
    );

    assert_eq!(
        busy.load(Ordering::Relaxed),
        0,
        "a thread was told another call's session was busy"
    );
    assert_eq!(
        refused.load(Ordering::Relaxed),
        0,
        "a frame was refused outright"
    );
    // A regression floor: a frame is 20 ms of audio, measured cost is about
    // three orders of magnitude below.
    assert!(
        per_frame < 2_000_000,
        "a frame cost {per_frame} ns of wall time"
    );

    for handle in media {
        release(handle);
    }
}

/// Count instead of panicking, so the run reports how often it happens.
fn count(busy: &AtomicUsize, refused: &AtomicUsize, status: SipralStatus) {
    match status {
        SipralStatus::Ok => {}
        SipralStatus::Busy => {
            busy.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            refused.fetch_add(1, Ordering::Relaxed);
        }
    }
}
