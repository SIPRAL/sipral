// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One call's `sipral::HeadlessSession` — the socket's frames on one side, a
//! codec's on the other — driven by whatever order of operations the input
//! names: the caller's audio heard, the agent's queued, frames filled for
//! the codec, barge-ins, codec-rate changes, frames read for the agent.
//!
//! `headless` covers the bytes an agent sends before they are a message;
//! this covers what the messages then do. Beyond not panicking, three
//! things are checked on every step: neither queue ever holds more than its
//! capacity, a frame read for the agent is always exactly one frame, and
//! after a barge-in nothing plays until the agent queues something new —
//! not even audio that had already been resampled for the codec when the
//! barge-in came.
//!
//! The first byte is the session: socket rate, codec rate, frame duration
//! and queue capacity, two bits each. Then operations, each an opcode and a
//! length octet, the samples an operation needs following in native-endian
//! pairs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral::HeadlessSession;
use sipral_headless::{AudioConfig, SampleRate, write_samples};

const RATES: [u32; 4] = [8_000, 16_000, 24_000, 48_000];
const DURATIONS_MS: [u32; 4] = [10, 20, 30, 60];

fn samples(bytes: &[u8]) -> Vec<i16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| i16::from_ne_bytes(*pair))
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&setup, rest)) = data.split_first() else {
        return;
    };
    let pick = |shift: u8| usize::from((setup >> shift) & 3);
    let (Some(&socket_hz), Some(&codec_hz), Some(&duration)) = (
        RATES.get(pick(0)),
        RATES.get(pick(2)),
        DURATIONS_MS.get(pick(4)),
    ) else {
        return;
    };
    let capacity = pick(6);
    let Ok(rate) = SampleRate::try_from(socket_hz) else {
        return;
    };
    let Ok(audio) = AudioConfig::with_frame_duration_ms(rate, duration) else {
        return;
    };
    let Ok(frame_bytes) = audio.frame_bytes() else {
        return;
    };
    let frame_bytes = usize::from(frame_bytes);
    let Ok(mut session) =
        HeadlessSession::open("fuzz".to_owned(), audio, codec_hz, capacity, capacity)
    else {
        return;
    };
    // a barge-in with nothing queued since: the codec gets silence
    let mut barged = false;

    let mut cursor = rest;
    while let Some((&[op, len], tail)) = cursor.split_first_chunk::<2>() {
        let take = (usize::from(len) * 2).min(tail.len());
        let (payload, tail) = tail.split_at(take);
        cursor = tail;
        match op % 6 {
            0 => {
                let _ = session.hear(&samples(payload));
            }
            1 => {
                // the samples given, padded with silence to one whole frame
                let filled: Vec<i16> = samples(payload)
                    .into_iter()
                    .chain(core::iter::repeat(0))
                    .take(frame_bytes / 2)
                    .collect();
                let mut frame = Vec::with_capacity(frame_bytes);
                write_samples(&filled, &mut frame);
                if session.protocol_mut().push_playback(frame).is_ok() {
                    barged = false;
                }
            }
            2 => {
                let mut room = vec![1_i16; usize::from(len) * 4];
                let real = session.fill_outbound(&mut room);
                if barged && !room.is_empty() {
                    assert!(
                        !real,
                        "audio played after a barge-in with nothing new queued"
                    );
                    assert!(room.iter().all(|&sample| sample == 0), "not silence");
                }
            }
            3 => {
                session.protocol_mut().barge_in();
                barged = true;
            }
            4 => {
                if let Some(&rate) = RATES.get(usize::from(len & 3)) {
                    let _ = session.set_codec_rate(rate);
                }
            }
            _ => {
                if let Some(frame) = session.protocol_mut().pop_capture() {
                    assert_eq!(
                        frame.len(),
                        frame_bytes,
                        "a capture frame of the wrong size"
                    );
                }
            }
        }
        assert!(
            session.protocol().capture_depth() <= capacity,
            "capture past capacity"
        );
        assert!(
            session.protocol().playback_depth() <= capacity,
            "playback past capacity"
        );
    }
});
