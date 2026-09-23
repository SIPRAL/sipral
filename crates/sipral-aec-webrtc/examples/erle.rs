// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Measures echo return loss enhancement: how much quieter the echo is once
//! [`WebrtcAec`] has had time to adapt, against the same signal run with
//! nothing attached.
//!
//! No SIP call and no server is needed to prove this — echo cancellation is
//! a property of the `Processor` seam alone, and `crates/sipral/src/echo.rs`
//! already does the render-to-capture alignment `docs/05-media.md`
//! describes before a processor ever sees a frame. So this feeds
//! [`WebrtcAec::process`] an already-aligned pair directly, the same
//! contract `sipral::MediaSession::attach_processor` promises it, and
//! reads back what a real call's own encoder would have been handed.
//!
//! The far end is a sum of three tones with a slow amplitude envelope, not
//! silence or a single sine: broadband and non-stationary, closer to what a
//! real caller's voice puts through a loudspeaker, and further from a
//! signal AEC3's adaptive filter converges on for reasons special to a pure
//! tone. The near end is that same signal, scaled down and *not* delayed —
//! the delay is what a device's render-to-capture path adds, already
//! removed by `sipral::Echo`'s own alignment by the time a processor is
//! reached, so a synthetic test standing in for the delayed device path
//! reproduces the seam's actual contract by not delaying it either. Run
//! with `cargo run --example erle -p sipral-aec-webrtc` (or via
//! `--manifest-path crates/sipral-aec-webrtc/Cargo.toml`, since this crate
//! is outside the workspace).

use sipral_aec_webrtc::WebrtcAec;
use sipral_media::processor::Processor;

const RATE_HZ: u32 = 16_000;
/// Twenty milliseconds: the frame length every codec this stack negotiates
/// today cuts at, two of `WebrtcAec`'s own ten-millisecond frames.
const FRAME_SAMPLES: usize = (RATE_HZ as usize / 1000) * 20;
const SECONDS: usize = 8;
/// The direct-path acoustic coupling this measures against: the echo is a
/// quarter the level of what was played, about -12 dB, a plausible laptop
/// loudspeaker-into-microphone figure.
const ECHO_GAIN: f64 = 0.25;

/// One sample of the synthetic far end, in `[-1.0, 1.0]`.
///
/// `sample_index` crosses to `f64` exactly: eight seconds at 16 kHz is
/// 128,000 samples, and `f64`'s mantissa carries an integer that size
/// without rounding for several more decades of a call.
fn far_end_sample(sample_index: u64) -> f64 {
    // 128,000 at most (eight seconds at 16 kHz), far inside the integer an
    // f64 mantissa carries exactly.
    #[allow(clippy::cast_precision_loss)]
    let t = sample_index as f64 / f64::from(RATE_HZ);
    let tau = std::f64::consts::TAU;
    let carrier = (tau * 220.0 * t).sin() * 0.5
        + (tau * 540.0 * t).sin() * 0.3
        + (tau * 1200.0 * t).sin() * 0.2;
    let envelope = 0.6 + 0.4 * (tau * 0.5 * t).sin();
    (carrier * envelope).clamp(-1.0, 1.0)
}

/// `value`, in `[-1.0, 1.0]`, as the `i16` an RTP payload carries.
fn to_i16(value: f64) -> i16 {
    let scaled = (value * f64::from(i16::MAX)).clamp(f64::from(i16::MIN), f64::from(i16::MAX));
    // Clamped into i16's own range immediately above.
    #[allow(clippy::cast_possible_truncation)]
    {
        scaled as i16
    }
}

fn erle_db(without_sq: f64, with_sq: f64) -> f64 {
    10.0 * (without_sq / with_sq.max(1.0)).log10()
}

fn main() {
    let total_frames = (RATE_HZ as usize * SECONDS) / FRAME_SAMPLES;
    // The first quarter is discarded: AEC3 has not converged yet, and
    // counting it would understate what the canceller does once it has.
    let warmup_frames = total_frames / 4;

    // A measurement tool with nothing to measure is nothing to run: failing
    // loudly here, rather than threading a `Result` through `main`, is the
    // whole of what a binary with no caller but a person at a terminal
    // needs to do about it.
    #[allow(clippy::expect_used)]
    let mut aec = WebrtcAec::new(RATE_HZ).expect("webrtc-audio-processing at 16 kHz");
    let mut without_sq = 0.0_f64;
    let mut with_sq = 0.0_f64;
    let mut measured_frames = 0_usize;

    for frame in 0..total_frames {
        let far: Vec<i16> = (0..FRAME_SAMPLES)
            .map(|offset| {
                let sample_index = (frame * FRAME_SAMPLES + offset) as u64;
                to_i16(far_end_sample(sample_index))
            })
            .collect();
        let near: Vec<i16> = far
            .iter()
            .map(|&sample| to_i16(f64::from(sample) / f64::from(i16::MAX) * ECHO_GAIN))
            .collect();
        let original = near.clone();
        let mut processed = near;
        aec.process(&mut processed, &far);

        if frame >= warmup_frames {
            measured_frames += 1;
            without_sq += original
                .iter()
                .map(|&s| f64::from(s) * f64::from(s))
                .sum::<f64>();
            with_sq += processed
                .iter()
                .map(|&s| f64::from(s) * f64::from(s))
                .sum::<f64>();
        }
    }

    println!("sample rate: {RATE_HZ} Hz, frame: {FRAME_SAMPLES} samples (20 ms)");
    println!(
        "echo path: {:.1} dB direct coupling, no delay (already aligned)",
        20.0 * ECHO_GAIN.log10()
    );
    println!("measured over the last {measured_frames} of {total_frames} frames (after adapting)");
    println!("echo energy without the processor: {without_sq:.3e}");
    println!("echo energy with the processor:    {with_sq:.3e}");
    println!("ERLE: {:.1} dB", erle_db(without_sq, with_sq));
}
