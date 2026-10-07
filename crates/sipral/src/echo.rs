// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Lining up what was played with what is being captured.
//!
//! [`sipral_media::processor::Processor`] takes two frames covering the same time span: the
//! microphone's, and the far-end audio that left the loudspeaker while the microphone was open. The
//! second was handed out by [`MediaSession::playback`] some milliseconds earlier, through device
//! buffers and drivers. A canceller given the wrong frame does not just cancel less: the signals do
//! not correlate and the adaptive filter diverges.
//!
//! So this keeps the loudspeaker's recent history and returns the aligned slice. The look-back is
//! the device's render-to-capture delay, which only the platform knows (WASAPI per stream,
//! CoreAudio from four properties per direction); the `sipral-io-*` crates supply it.
//!
//! Nothing is allocated until a processor is attached, so headless builds carry no history.
//!
//! [`MediaSession::playback`]: crate::MediaSession::playback

use std::time::Duration;

use sipral_media::processor::Processor;

/// The longest render-to-capture delay history is kept for.
///
/// Far beyond any working device (a laptop's own speakers and microphone report a little over 100
/// ms with voice processing on). It exists so a wrong platform value is refused instead of becoming
/// megabytes of ring per call.
pub const MAX_RENDER_DELAY: Duration = Duration::from_millis(500);

/// A processor, the loudspeaker history it needs, and the frames it works in.
pub(crate) struct Echo {
    processor: Box<dyn Processor>,
    ring: Vec<i16>,
    /// Where the next rendered sample goes.
    write: usize,
    /// How much of the ring has been written since it was cleared, so the start of a call
    /// correlates against silence, not leftover memory.
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

    /// Look back `delay` from now on. The history stays: same loudspeaker, only the delay estimate
    /// changed.
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

    /// Run the processor on one captured frame and return the result.
    ///
    /// Returned from this structure's buffer rather than written into the caller's, which is the
    /// application's capture buffer and may be recorded, metered or drawn.
    pub(crate) fn process(&mut self, samples: &[i16]) -> &[i16] {
        let count = samples.len().min(self.near_end.len());
        let near = self.near_end.get_mut(..count).unwrap_or_default();
        near.copy_from_slice(samples.get(..count).unwrap_or_default());
        let far = self.far_end.get_mut(..count).unwrap_or_default();
        align(&self.ring, self.write, self.filled, self.delay, far);
        self.processor.process(near, far);
        self.near_end.get(..count).unwrap_or_default()
    }

    /// Return the application's processor so a stream that changed codec can wrap it in rings of
    /// the new size. The application cannot hand it over again, so losing it would silently end
    /// echo cancellation.
    pub(crate) fn into_processor(self) -> Box<dyn Processor> {
        self.processor
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
    /// Written by hand: a `Box<dyn Processor>` prints nothing useful and the ring too much.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Echo")
            .field("delay_samples", &self.delay)
            .field("history_samples", &self.ring.len())
            .finish_non_exhaustive()
    }
}

/// Fill `out` with the loudspeaker frame aligned with a capture now.
///
/// The last sample of `out` is `delay + 1` behind the head, so delay zero pairs a capture with the
/// frame from the immediately preceding [`playback`](crate::MediaSession::playback). Anything not
/// yet written (start of a call) is silence, which it was.
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

    /// Returns whatever reference it got, so tests check alignment rather than cancellation.
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
        // four samples at 8 kHz is half a millisecond
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
        // eight samples written, delay reaching back twenty
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
        // several laps, so the head is far from its start
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
