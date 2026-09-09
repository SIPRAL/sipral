// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Lining up what was played against what is being captured.
//!
//! [`sipral_media::processor::Processor`] takes two frames covering the same
//! span of time: the microphone's, and the far end's audio as it left the
//! loudspeaker while that microphone was open. Only the second is hard to
//! produce. It was handed out by [`MediaSession::playback`] some milliseconds
//! ago — through a device ring, a driver, and whatever the hardware adds — and
//! the echo in the microphone is *that* frame, not the one about to be played
//! next. Handing a canceller the wrong frame is not a weaker cancellation, it
//! is none: the two signals do not correlate at all, and an adaptive filter
//! given uncorrelated input diverges.
//!
//! So this keeps the recent past of the loudspeaker and hands back the slice
//! that lines up. How far back to look is the render-to-capture delay of the
//! device, which only the platform knows — CoreAudio reports it per device,
//! WASAPI per stream — so it arrives from above rather than being guessed
//! here.
//!
//! Everything is allocated when a processor is attached and not before. A
//! build with nothing attached, which includes every headless one, carries no
//! history and copies no frames.
//!
//! [`MediaSession::playback`]: crate::MediaSession::playback

use std::time::Duration;

use sipral_media::processor::Processor;

/// The longest render-to-capture delay history is kept for.
///
/// Half a second is far beyond any device that works: a headset is a few
/// milliseconds, a Bluetooth link with its own codec is tens, and a delay
/// above about a hundred is heard as an echo by the person on the other end
/// whether or not anything cancels it. The limit exists so that a wrong number
/// arriving from a platform is refused rather than turned into megabytes of
/// ring per call.
pub const MAX_RENDER_DELAY: Duration = Duration::from_millis(500);

/// A processor, the loudspeaker history it needs, and the frames it works in.
pub(crate) struct Echo {
    processor: Box<dyn Processor>,
    ring: Vec<i16>,
    /// Where the next rendered sample goes.
    write: usize,
    /// How much of the ring has been written since it was last cleared, so
    /// that the start of a call correlates against silence rather than
    /// against whatever the allocation held.
    filled: usize,
    delay: usize,
    near_end: Vec<i16>,
    far_end: Vec<i16>,
}

impl Echo {
    /// Attach `processor` to a stream of `frame` samples at `rate`, looking
    /// `delay` back for its reference.
    pub(crate) fn new(
        processor: Box<dyn Processor>,
        rate: u32,
        frame: usize,
        delay: Duration,
    ) -> Self {
        let capacity = samples_in(rate, MAX_RENDER_DELAY)
            .saturating_add(frame.saturating_mul(2))
            .max(1);
        Self {
            processor,
            ring: vec![0; capacity],
            write: 0,
            filled: 0,
            delay: samples_in(rate, delay),
            near_end: vec![0; frame],
            far_end: vec![0; frame],
        }
    }

    /// Look `delay` back from now on.
    ///
    /// The history already held stays: it is the same loudspeaker, and only
    /// the opinion about how long it takes to reach the microphone changed.
    pub(crate) fn set_delay(&mut self, rate: u32, delay: Duration) {
        self.delay = samples_in(rate, delay);
    }

    /// Keep one frame the loudspeaker was given.
    pub(crate) fn rendered(&mut self, frame: &[i16]) {
        let capacity = self.ring.len();
        for &sample in frame {
            if let Some(slot) = self.ring.get_mut(self.write) {
                *slot = sample;
            }
            self.write = self.write.saturating_add(1) % capacity;
            self.filled = self.filled.saturating_add(1).min(capacity);
        }
    }

    /// Run the processor over one captured frame and give back what it left.
    ///
    /// The frame comes back borrowed from this structure's own buffer rather
    /// than written through the caller's slice, because the caller's is the
    /// application's capture buffer and a stack that edits it in place is a
    /// stack that changes what the application recorded, metered or drew.
    pub(crate) fn process(&mut self, samples: &[i16]) -> &[i16] {
        let count = samples.len().min(self.near_end.len());
        let near = self.near_end.get_mut(..count).unwrap_or_default();
        near.copy_from_slice(samples.get(..count).unwrap_or_default());
        let far = self.far_end.get_mut(..count).unwrap_or_default();
        align(&self.ring, self.write, self.filled, self.delay, far);
        self.processor.process(near, far);
        self.near_end.get(..count).unwrap_or_default()
    }

    /// Forget the echo path and the history it was built from.
    pub(crate) fn reset(&mut self) {
        self.processor.reset();
        self.ring.fill(0);
        self.write = 0;
        self.filled = 0;
    }
}

impl core::fmt::Debug for Echo {
    /// Written out because a `Box<dyn Processor>` has nothing to print and
    /// the ring has too much.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Echo")
            .field("delay_samples", &self.delay)
            .field("history_samples", &self.ring.len())
            .finish_non_exhaustive()
    }
}

/// Fill `out` with the loudspeaker frame that lines up with a capture
/// happening now.
///
/// The last sample of `out` is the one written `delay + 1` places behind the
/// head, so a delay of zero pairs a capture with the frame handed out by the
/// [`playback`](crate::MediaSession::playback) immediately before it. What is
/// not there yet — the first frames of a call — is silence, which is what it
/// really was.
fn align(ring: &[i16], write: usize, filled: usize, delay: usize, out: &mut [i16]) {
    let capacity = ring.len();
    let frame = out.len();
    for (index, slot) in out.iter_mut().enumerate() {
        let back = delay.saturating_add(frame - index);
        *slot = if back > filled || back > capacity {
            0
        } else {
            ring.get((write + capacity - back) % capacity)
                .copied()
                .unwrap_or(0)
        };
    }
}

/// Samples of a stream at `rate` in `span`.
fn samples_in(rate: u32, span: Duration) -> usize {
    let micros = u64::try_from(span.as_micros()).unwrap_or(u64::MAX);
    let samples = u64::from(rate).saturating_mul(micros) / 1_000_000;
    usize::try_from(samples).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{Echo, MAX_RENDER_DELAY, align, samples_in};
    use sipral_media::processor::Processor;
    use std::time::Duration;

    /// Hands back whatever reference it was given, so a test can assert on
    /// the alignment rather than on a canceller's arithmetic.
    struct Mirror {
        seen: Vec<i16>,
        resets: usize,
    }

    impl Processor for Mirror {
        fn process(&mut self, near_end: &mut [i16], reference: &[i16]) {
            self.seen.clear();
            self.seen.extend_from_slice(reference);
            for sample in near_end.iter_mut() {
                *sample = sample.saturating_add(1);
            }
        }

        fn reset(&mut self) {
            self.resets += 1;
        }
    }

    #[test]
    fn a_capture_with_no_delay_pairs_with_the_frame_just_played() {
        let mut echo = Echo::new(
            Box::new(Mirror {
                seen: vec![],
                resets: 0,
            }),
            8_000,
            4,
            Duration::ZERO,
        );
        echo.rendered(&[1, 2, 3, 4]);
        echo.process(&[0, 0, 0, 0]);
        let mut far = [0_i16; 4];
        super::align(&echo.ring, echo.write, echo.filled, echo.delay, &mut far);
        assert_eq!(far, [1, 2, 3, 4]);
    }

    #[test]
    fn a_delay_of_one_frame_pairs_with_the_frame_before_that() {
        let rate = 8_000;
        // four samples at eight kilohertz is half a millisecond
        let mut echo = Echo::new(
            Box::new(Mirror {
                seen: vec![],
                resets: 0,
            }),
            rate,
            4,
            Duration::from_micros(500),
        );
        echo.rendered(&[1, 2, 3, 4]);
        echo.rendered(&[5, 6, 7, 8]);
        let mut far = [0_i16; 4];
        super::align(&echo.ring, echo.write, echo.filled, echo.delay, &mut far);
        assert_eq!(far, [1, 2, 3, 4]);
    }

    #[test]
    fn the_start_of_a_call_correlates_against_silence_not_against_the_allocation() {
        let ring = [7_i16; 16];
        let mut far = [9_i16; 4];
        align(&ring, 0, 0, 0, &mut far);
        assert_eq!(far, [0; 4]);
    }

    #[test]
    fn history_shorter_than_the_delay_gives_silence_rather_than_a_wrong_frame() {
        let mut ring = [0_i16; 32];
        for (index, slot) in ring.iter_mut().enumerate() {
            *slot = i16::try_from(index).unwrap_or(0);
        }
        let mut far = [1_i16; 4];
        // eight samples written, and a delay that reaches back twenty
        align(&ring, 8, 8, 20, &mut far);
        assert_eq!(far, [0; 4]);
    }

    #[test]
    fn the_ring_wraps_without_losing_alignment() {
        let mut echo = Echo::new(
            Box::new(Mirror {
                seen: vec![],
                resets: 0,
            }),
            8_000,
            2,
            Duration::ZERO,
        );
        let capacity = echo.ring.len();
        // several times round, so the head is nowhere near where it started
        for round in 0..(capacity * 3) {
            let value = i16::try_from(round % 1_000).unwrap_or(0);
            echo.rendered(&[value, value]);
        }
        let last = i16::try_from((capacity * 3 - 1) % 1_000).unwrap_or(0);
        let mut far = [0_i16; 2];
        align(&echo.ring, echo.write, echo.filled, echo.delay, &mut far);
        assert_eq!(far, [last, last]);
    }

    #[test]
    fn the_processor_sees_the_reference_and_the_caller_keeps_its_own_frame() {
        let mut echo = Echo::new(
            Box::new(Mirror {
                seen: vec![],
                resets: 0,
            }),
            8_000,
            3,
            Duration::ZERO,
        );
        echo.rendered(&[10, 20, 30]);
        let captured = [1_i16, 2, 3];
        let processed = echo.process(&captured);
        assert_eq!(processed, [2, 3, 4]);
        assert_eq!(captured, [1, 2, 3], "the application's buffer was edited");
    }

    #[test]
    fn a_reset_forgets_the_loudspeaker_as_well_as_the_processor() {
        let mut echo = Echo::new(
            Box::new(Mirror {
                seen: vec![],
                resets: 0,
            }),
            8_000,
            2,
            Duration::ZERO,
        );
        echo.rendered(&[100, 200]);
        echo.reset();
        let mut far = [1_i16; 2];
        align(&echo.ring, echo.write, echo.filled, echo.delay, &mut far);
        assert_eq!(far, [0; 2]);
    }

    #[test]
    fn a_shorter_capture_frame_than_the_stream_negotiated_is_processed_whole() {
        let mut echo = Echo::new(
            Box::new(Mirror {
                seen: vec![],
                resets: 0,
            }),
            8_000,
            8,
            Duration::ZERO,
        );
        echo.rendered(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(echo.process(&[0, 0, 0]), [1, 1, 1]);
    }

    #[test]
    fn the_history_covers_the_longest_delay_that_can_be_set() {
        let rate = 48_000;
        let frame = 960;
        let echo = Echo::new(
            Box::new(Mirror {
                seen: vec![],
                resets: 0,
            }),
            rate,
            frame,
            MAX_RENDER_DELAY,
        );
        assert!(echo.ring.len() >= samples_in(rate, MAX_RENDER_DELAY) + frame);
    }

    #[test]
    fn a_delay_changes_without_throwing_the_history_away() {
        let mut echo = Echo::new(
            Box::new(Mirror {
                seen: vec![],
                resets: 0,
            }),
            8_000,
            4,
            Duration::ZERO,
        );
        echo.rendered(&[1, 2, 3, 4]);
        echo.set_delay(8_000, Duration::from_micros(500));
        assert_eq!(echo.filled, 4);
        assert_eq!(echo.delay, 4);
    }

    #[test]
    fn a_span_shorter_than_a_sample_is_no_delay_at_all() {
        assert_eq!(samples_in(8_000, Duration::from_micros(100)), 0);
        assert_eq!(samples_in(8_000, Duration::from_millis(20)), 160);
        assert_eq!(samples_in(48_000, Duration::from_millis(20)), 960);
    }
}
