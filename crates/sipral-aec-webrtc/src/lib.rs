// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! An echo canceller, gain controller and noise suppressor over
//! `webrtc-audio-processing` (BSD-3-Clause), attached to a `MediaSession`
//! through the seam `sipral_media::processor` declares.
//!
//! Not linked by any other crate in this workspace, on purpose:
//! `docs/05-media.md`'s "Where the canceller itself comes from" names this
//! the last row of its table, "the seam", and this crate is one thing an
//! application can attach to it, not part of the facade. The whole of using
//! it is
//!
//! ```ignore
//! let processor = sipral_aec_webrtc::WebrtcAec::new(session.sample_rate())?;
//! session.attach_processor(Box::new(processor));
//! ```
//!
//! Two conversions happen on every frame, because the two libraries agree on
//! neither the type nor the scale of a sample. `sipral_media::Processor`
//! works in `i16`, the width an RTP payload is decoded to; this library
//! works in `f32` normalised to `[-1.0, 1.0]`, and its own examples are the
//! only place that says so — the header comments talk about "samples"
//! without a range. Every frame is copied through that conversion twice,
//! and back.
//!
//! The two libraries also disagree about how long a frame is. This library
//! fixes its own at ten milliseconds — [`Inner::num_samples_per_frame`]
//! says how many samples that is at a given rate, and panics on anything
//! else — while a call's frame is whatever its codec cuts, twenty
//! milliseconds for every codec this stack negotiates today, which divides
//! evenly into two. [`WebrtcAec::process`] documents what it does with a
//! frame that does not.
//!
//! Excluded from this workspace's default build: `Cargo.toml` beside this
//! file says why, and `docs/05-media.md` says what a build that wants this
//! attached has to do.

#![warn(missing_docs)]
#![warn(unreachable_pub)]

use sipral_media::processor::Processor;
use webrtc_audio_processing::Processor as Inner;
use webrtc_audio_processing::config::{
    Config, EchoCanceller, GainController, GainController1, GainControllerMode, HighPassFilter,
    NoiseSuppression,
};

pub use webrtc_audio_processing::Error;

/// A sample in `[-1.0, 1.0]`'s worth of an `i16`'s full range, once, so the
/// conversion each way is stated in one place rather than typed twice.
const SCALE: f32 = 32_768.0;

/// [`Processor`] over `webrtc-audio-processing`'s echo canceller, gain
/// controller and noise suppressor, all three run from one call the way
/// `docs/05-media.md` says a real implementation usually has to.
pub struct WebrtcAec {
    inner: Inner,
    /// [`Inner::num_samples_per_frame`], read once at construction: fixed by
    /// the sample rate this was built for and never asked again.
    frame: usize,
    near: Vec<f32>,
    far: Vec<f32>,
}

impl WebrtcAec {
    /// Build one for a stream at `sample_rate_hz`, with a sensible default
    /// for a phone call turned on: echo cancellation (the full AEC3
    /// implementation, left to estimate its own delay, because the near and
    /// far frames [`Processor::process`] is handed are already the aligned
    /// pair `sipral::MediaSession::attach_processor`'s own documentation
    /// promises — this is not a claim that AEC3's estimator is redundant,
    /// only that there is nothing here for a `stream_delay_ms` to add),
    /// moderate noise suppression, and gain controller 1 in its digital
    /// mode — its default, adaptive-analog mode asks a caller to couple it
    /// to an OS mixer's own analog level through an API this wrapper does
    /// not expose, and answers every frame with `Error::StreamParameterNotSet`
    /// until one does; there is no analog level here to couple it to, a
    /// call's own microphone gain being the device crate's concern, not
    /// this seam's.
    ///
    /// Not the only configuration a call could want: [`WebrtcAec::inner`]
    /// reaches the `webrtc_audio_processing::Processor` this wraps, and
    /// `Inner::set_config` takes over from there.
    ///
    /// # Errors
    ///
    /// Whatever `webrtc_audio_processing::Processor::new` answers for a
    /// `sample_rate_hz` the underlying library will not run at.
    pub fn new(sample_rate_hz: u32) -> Result<Self, Error> {
        let inner = Inner::new(sample_rate_hz)?;
        inner.set_config(Config {
            high_pass_filter: Some(HighPassFilter::default()),
            echo_canceller: Some(EchoCanceller::Full {
                stream_delay_ms: None,
            }),
            noise_suppression: Some(NoiseSuppression::default()),
            gain_controller: Some(GainController::GainController1(GainController1 {
                mode: GainControllerMode::AdaptiveDigital,
                ..GainController1::default()
            })),
            ..Config::default()
        });
        let frame = inner.num_samples_per_frame();
        Ok(Self {
            inner,
            frame,
            near: vec![0.0; frame],
            far: vec![0.0; frame],
        })
    }

    /// The `webrtc_audio_processing::Processor` this wraps, for an
    /// application that wants `Inner::get_stats` or a `Inner::set_config`
    /// other than [`WebrtcAec::new`]'s own.
    #[must_use]
    pub const fn inner(&self) -> &Inner {
        &self.inner
    }
}

impl Processor for WebrtcAec {
    /// Runs the underlying library over `near_end` and `reference` ten
    /// milliseconds at a time, converting each slice to `[-1.0, 1.0]` and
    /// back around the call.
    ///
    /// `near_end` is left exactly as it arrived — the frame sipral's own
    /// encoder would have been given without a processor attached — when
    /// its length is not a whole multiple of what this library fixes its
    /// own frame at, or does not match `reference`'s: guessed at instead,
    /// this would be a wrong answer on a byte boundary a caller has no way
    /// to see coming, rather than the plainly-audible zero effect a call
    /// with the wrong frame length already has to notice.
    fn process(&mut self, near_end: &mut [i16], reference: &[i16]) {
        let frame = self.frame;
        if frame == 0 || near_end.len() != reference.len() || !near_end.len().is_multiple_of(frame)
        {
            return;
        }
        for (near_chunk, far_chunk) in near_end.chunks_mut(frame).zip(reference.chunks(frame)) {
            for (dst, &src) in self.far.iter_mut().zip(far_chunk) {
                *dst = f32::from(src) / SCALE;
            }
            // The render frame teaches the canceller what the loudspeaker
            // was given; a failure here leaves the frame's own samples
            // wherever this scratch buffer already had them, which the next
            // render call overwrites, so it is not propagated further.
            let _ = self.inner.process_render_frame([self.far.as_mut_slice()]);

            for (dst, &src) in self.near.iter_mut().zip(near_chunk.iter()) {
                *dst = f32::from(src) / SCALE;
            }
            if self
                .inner
                .process_capture_frame([self.near.as_mut_slice()])
                .is_err()
            {
                // Left as captured: a processor that failed silently is a
                // worse bug than a processor that did nothing this frame.
                continue;
            }
            for (dst, &src) in near_chunk.iter_mut().zip(self.near.iter()) {
                let clamped = (src * SCALE).clamp(f32::from(i16::MIN), f32::from(i16::MAX));
                // Clamped into i16's own range immediately above, so the
                // truncation this cast could otherwise do never happens.
                #[allow(clippy::cast_possible_truncation)]
                {
                    *dst = clamped as i16;
                }
            }
        }
    }

    /// Drops the estimated echo path and everything else the underlying
    /// library has learned, keeping its configuration.
    fn reset(&mut self) {
        self.inner.reinitialize();
    }
}

#[cfg(test)]
// `expect` fails a test with its own message, which is the point of using it
// here rather than in the library above; `examples/erle.rs`, run against a
// broadband signal over several seconds, is the real measurement this
// module's last test only has to reproduce in miniature.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::WebrtcAec;
    use sipral_media::processor::Processor;

    #[test]
    fn a_frame_whose_length_is_not_ten_milliseconds_worth_is_left_alone() {
        let mut processor = WebrtcAec::new(8000).expect("webrtc-audio-processing at 8 kHz");
        let original = [1_i16, -2, 3, 4, 5];
        let mut frame = original;
        processor.process(&mut frame, &[0; 5]);
        assert_eq!(frame, original);
    }

    #[test]
    fn mismatched_lengths_are_left_alone() {
        let mut processor = WebrtcAec::new(8000).expect("webrtc-audio-processing at 8 kHz");
        let original = [1_i16; 80];
        let mut frame = original;
        processor.process(&mut frame, &[0; 40]);
        assert_eq!(frame, original);
    }

    #[test]
    fn a_call_frame_of_two_webrtc_frames_runs_without_panicking() {
        // 8 kHz, 20 ms: 160 samples, exactly two of webrtc-audio-processing's
        // own 80-sample (10 ms) frames -- the shape every codec this stack
        // negotiates today cuts a frame at.
        let mut processor = WebrtcAec::new(8000).expect("webrtc-audio-processing at 8 kHz");
        let mut near = [0_i16; 160];
        let far = [0_i16; 160];
        processor.process(&mut near, &far);
        processor.reset();
        processor.process(&mut near, &far);
    }

    #[test]
    fn an_echo_fed_back_is_attenuated_once_the_canceller_has_adapted() {
        // A few seconds of a synthetic tone as both the far end and, scaled
        // down, the near end -- the shape a real loudspeaker-into-microphone
        // echo has -- run long enough for AEC3 to adapt, then measured
        // against the same signal run through with nothing attached.
        // `examples/erle.rs` is the same measurement against a broadband
        // signal, with a number attached.
        let rate = 16_000_u32;
        let frame_samples = 320_usize; // 20 ms at 16 kHz, two webrtc frames
        let frames = 200_usize; // four seconds
        let tone = |sample: usize| {
            // The 8000.0 factor keeps the tone well inside i16's range
            // without reaching its edges, and 0.05 radians a sample gives a
            // few hundred hertz at 16 kHz -- both chosen for a signal AEC3
            // has something to adapt to, not for any acoustic meaning. 200
            // frames of 320 samples is 64,000, well inside what an f32
            // mantissa carries as an integer without rounding.
            #[allow(clippy::cast_precision_loss)]
            let radians = sample as f32 * 0.05;
            let value = (radians.sin() * 8000.0).clamp(f32::from(i16::MIN), f32::from(i16::MAX));
            // Clamped into i16's own range immediately above.
            #[allow(clippy::cast_possible_truncation)]
            {
                value as i16
            }
        };

        let mut processor = WebrtcAec::new(rate).expect("webrtc-audio-processing at 16 kHz");
        let mut with_aec_energy = 0.0_f64;
        let mut without_energy = 0.0_f64;
        let mut sample = 0_usize;
        for frame in 0..frames {
            let far: Vec<i16> = (0..frame_samples)
                .map(|_| {
                    let value = tone(sample);
                    sample += 1;
                    value
                })
                .collect();
            // The echo: the far end at a quarter its own level, exactly
            // aligned -- attach_processor's own contract, kept here by hand
            // since there is no MediaSession in this test.
            let near: Vec<i16> = far.iter().map(|&value| value / 4).collect();
            let mut processed = near.clone();
            processor.process(&mut processed, &far);
            // Only the last second, once AEC3 has had time to adapt, counts
            // toward the measurement below.
            if frame >= frames - 50 {
                with_aec_energy += processed
                    .iter()
                    .map(|&s| f64::from(s) * f64::from(s))
                    .sum::<f64>();
                without_energy += near
                    .iter()
                    .map(|&s| f64::from(s) * f64::from(s))
                    .sum::<f64>();
            }
        }
        assert!(
            with_aec_energy < without_energy / 4.0,
            "echo energy with the canceller attached ({with_aec_energy}) was not well below \
             what it was without it ({without_energy})"
        );
    }
}
