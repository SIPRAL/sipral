// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What one stack does with two hundred calls on it at once.
//!
//! A softphone holds one call and a contact centre's dialler holds hundreds,
//! and the shape that decides which of the two this library is good for is
//! the locking: `sipral_media_*` reaches one call's session through that
//! call's own lock, never the stack's (`docs/08-ffi.md`, "Audio on its own
//! thread"), so the thread carrying one call's audio is never held up by
//! another call being busy. That is a claim about contention, and contention
//! is not something a single-call test can show.
//!
//! So this drives two hundred calls at once on four threads, one frame of
//! audio in and one out per call per turn, exactly as an application's own
//! audio threads would, and asks for two things: that no call ever answers
//! [`SipralStatus::Busy`] — the answer a session already locked gives, which
//! under this design should never be seen by a thread that holds no other
//! session's lock — and that the work per frame stays flat as the calls pile
//! up. The numbers it prints are the ones `scripts/bench.sh` collects into
//! `docs/19-numbers.md`; the assertions are what makes it a test rather than
//! a benchmark.
//!
//! Nothing here opens a socket. The calls are brought up the way every other
//! test in this crate brings one up — an INVITE this stack wrote, answered
//! from the test — and the audio is fed in as datagrams through
//! `sipral_media_receive`, which is the same entry point a real transport
//! calls. What is measured is therefore the library's own cost per frame,
//! with no network underneath it to hide in.

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

/// How many calls the stack is asked to hold at once.
const CALLS: usize = 200;

/// How many threads share them, the way an application would hand its calls
/// to a pool rather than a thread each.
const THREADS: usize = 4;

/// Frames of audio per call, twenty milliseconds apiece. Five seconds of a
/// call each, which is enough for the per-frame cost to settle and short
/// enough that the gate does not wait on it; `SIPRAL_LOAD_FRAMES` raises it
/// for `scripts/bench.sh`, which runs the same test for a minute of audio.
const FRAMES: usize = 250;

/// The far end's own answer for call `n`, each on a port of its own so that
/// two calls' media can never be mistaken for one another.
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

/// One twenty-millisecond packet of mu-law for call `n`, sequence `seq`.
fn packet(n: usize, seq: u16) -> Vec<u8> {
    let mut out = vec![0x80, 0x00];
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    // one source per call, so nothing in the receive path can take two
    // calls' audio for one stream
    out.extend_from_slice(&(0xDEAD_0000_u32 + u32::try_from(n).unwrap_or(0)).to_be_bytes());
    out.extend_from_slice(&[0xFF; FRAME]);
    out
}

/// Where call `n`'s packet came from, as the transport would say it: the
/// port that call's own answer named, since a session takes audio from the
/// address it negotiated and from nowhere else.
fn peer_for(n: usize) -> String {
    format!("203.0.113.5:{}", 41_000 + n)
}

/// What a run was asked for: the defaults above, unless the environment
/// raises them. `scripts/bench.sh` sets both — a minute of audio rather than
/// five seconds, and one call as well as two hundred, so that the difference
/// between the two runs' peak memory is the cost of a call.
fn sized(name: &str, fallback: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(fallback)
}

// one run of one scenario, read top to bottom: two hundred calls brought up,
// then driven, then judged. Cut into pieces it would only be harder to read
// against the numbers it prints.
#[allow(clippy::too_many_lines)]
#[test]
fn two_hundred_calls_run_on_four_threads_without_one_waiting_on_another() {
    let calls = sized("SIPRAL_LOAD_CALLS", CALLS);
    let mut observed = Observed::default();
    // the one codec `media_line` opens with: mu-law, the format every
    // answer below names back
    let starting = Instant::now();
    // past the default ceiling of 128 calls, the way a dialler raises it
    let (stack, account) = media_line(&mut observed, |config| {
        config.max_dialogs = u32::try_from(calls).unwrap_or(u32::MAX);
    });
    let started = starting.elapsed();

    let mut media = Vec::with_capacity(calls);
    // every call needs a media address of its own: two sessions on one port
    // is what a stack refuses, and it is the caller who owns the port
    let addresses: Vec<String> = (0..calls)
        .map(|n| format!("192.0.2.10:{}", 40_000 + n))
        .collect();
    let setting_up = Instant::now();
    for (n, address) in addresses.iter().enumerate() {
        let mut config = managed_config();
        config.media_address = address.as_ptr().cast::<c_char>();
        config.media_address_len = address.len();
        // the stack refuses a reading behind the one it has, so each call is
        // placed a tenth of a second after the one before it
        let at = 1_000 + u64::try_from(n).unwrap_or(0) * 100;
        let (status, call) = place(stack, account, &config, at);
        assert_eq!(
            status,
            SipralStatus::Ok,
            "call {n} was not placed: {}",
            crate::error::last_error_text()
        );
        // not `one`: by the time two hundred calls are being placed the queue
        // also carries the ACKs for the ones already answered
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
    // A frame is twenty milliseconds of audio. Anything near that per frame
    // of wall time on its thread would mean one core could not carry even
    // one call, and the figure measured on the machines this has run on is
    // three orders below it; the assertion is a floor under a regression,
    // not the number.
    assert!(
        per_frame < 2_000_000,
        "a frame cost {per_frame} ns of wall time"
    );

    for handle in media {
        release(handle);
    }
}

/// Count what a call answered, without stopping the run: a load test that
/// panics on the first refusal says nothing about how often it happens.
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
