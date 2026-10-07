// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The seam echo cancellation, gain control and noise suppression attach at.
//!
//! Attached, not implemented here (`docs/05-media.md`): permissive
//! implementations exist. One seam for all three, since gain control and
//! noise suppression run on what echo cancellation left. [`NoProcessor`]
//! passes frames through unchanged.

/// Where echo cancellation, gain control and noise suppression attach.
///
/// One per processed direction; it owns its state between frames.
///
/// `Send`: frames come from the audio thread and the session is also reached
/// from the signalling thread.
///
/// **Never call back into the engine that owns this session from inside
/// [`Processor::process`] or [`Processor::reset`].** Both run with the
/// session's lock held, and most engine paths (timeouts, scheduled reports)
/// take that lock without a re-entry check, so the call deadlocks on its own
/// thread.
pub trait Processor: Send {
    /// Process one frame of near-end audio in place: the signal captured
    /// from the microphone, about to be encoded and sent.
    ///
    /// `reference` is the far-end audio rendered to the speaker over the
    /// same span of time — what an echo canceller correlates `near_end`
    /// against to know what echo to remove. A processor with nothing to
    /// cancel may ignore it. Sample alignment is the device I/O crate's job.
    fn process(&mut self, near_end: &mut [i16], reference: &[i16]);

    /// Forget whatever state this processor holds.
    ///
    /// A new call, a device change, or a codec change mid-call invalidates
    /// an echo path estimate or a noise floor built for a different signal;
    /// carrying it forward would make the processor fight the new one for a
    /// while instead of adapting to it cleanly.
    fn reset(&mut self);
}

/// A processor that does nothing.
///
/// What a build runs when no echo canceller, gain control or noise
/// suppressor is attached: the seam is always present, whether or not
/// anything fills it, so a caller never has to special-case its absence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoProcessor;

impl Processor for NoProcessor {
    fn process(&mut self, _near_end: &mut [i16], _reference: &[i16]) {}

    fn reset(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::{NoProcessor, Processor};

    #[test]
    fn no_processor_leaves_the_frame_unchanged() {
        let mut processor = NoProcessor;
        let original = [1_i16, -2, 3, -32_768, 32_767];
        let mut frame = original;
        processor.process(&mut frame, &[100, 200, 300, 400, 500]);
        assert_eq!(frame, original);
    }

    #[test]
    fn no_processor_ignores_a_reference_of_any_length() {
        let mut processor = NoProcessor;
        let mut frame = [7_i16; 4];
        processor.process(&mut frame, &[]);
        assert_eq!(frame, [7; 4]);
        processor.process(&mut frame, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(frame, [7; 4]);
    }

    #[test]
    fn no_processor_reset_does_nothing_and_never_panics() {
        let mut processor = NoProcessor;
        processor.reset();
        processor.reset();
        let mut frame = [42_i16];
        processor.process(&mut frame, &[]);
        assert_eq!(frame, [42]);
    }

    #[test]
    fn no_processor_is_the_default() {
        // built generically, through the `Default` bound itself, rather than
        // as `NoProcessor::default()` -- otherwise this is just testing that
        // a unit struct's literal and its `Default::default()` are the same
        // value, which the compiler already guarantees
        fn build<P: Default>() -> P {
            P::default()
        }
        let mut processor: NoProcessor = build();
        let mut frame = [5_i16, 6];
        processor.process(&mut frame, &[9, 9]);
        assert_eq!(frame, [5, 6]);
    }

    /// A minimal, deliberately un-realistic implementation used only to prove
    /// the trait's shape is usable through a `dyn Processor` and actually
    /// reaches both frames -- not a canceller of any kind.
    struct SubtractsReference {
        resets: usize,
    }

    impl Processor for SubtractsReference {
        fn process(&mut self, near_end: &mut [i16], reference: &[i16]) {
            for (sample, &far) in near_end.iter_mut().zip(reference) {
                *sample = sample.saturating_sub(far);
            }
        }

        fn reset(&mut self) {
            self.resets += 1;
        }
    }

    #[test]
    fn a_processor_is_usable_as_a_trait_object_and_sees_both_frames() {
        let mut processor: Box<dyn Processor> = Box::new(SubtractsReference { resets: 0 });
        let mut frame = [10_i16, 20, 30];
        processor.process(&mut frame, &[1, 2, 3]);
        assert_eq!(frame, [9, 18, 27]);
        processor.reset();
    }

    #[test]
    fn a_shorter_reference_leaves_the_remaining_samples_untouched() {
        let mut processor = SubtractsReference { resets: 0 };
        let mut frame = [10_i16, 20, 30];
        processor.process(&mut frame, &[1]);
        assert_eq!(frame, [9, 20, 30]);
        assert_eq!(processor.resets, 0);
        processor.reset();
        assert_eq!(processor.resets, 1);
    }
}
