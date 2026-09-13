// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The seam echo cancellation, gain control and noise suppression attach at.
//!
//! `docs/05-media.md` is explicit that these are attached here rather than
//! implemented here: each is a field of signal processing research on its
//! own, each already exists under a permissive licence, and rewriting one
//! from an RFC would buy this project nothing a customer pays for — unlike
//! the jitter buffer or the codecs, where the implementation itself is the
//! product. What belongs in this crate is only the shape a processor takes,
//! so a caller can wire a real one in, or wire nothing in, without either
//! choice touching anything else in the pipeline.
//!
//! The three concerns share a seam rather than getting one each because a
//! real implementation usually is one component: gain control needs to run
//! on what echo cancellation left behind, not on the raw capture, and noise
//! suppression the same. [`Processor`] is that single attachment point.
//! [`NoProcessor`] is what a build with nothing attached runs — every frame
//! passes through unchanged, so the pipeline compiles, runs and does nothing
//! extra whether or not a real processor is ever wired in.

/// Where echo cancellation, gain control and noise suppression attach.
///
/// A call has one of these per direction that needs processing, and it owns
/// whatever state a real implementation keeps between frames — an echo path
/// estimate, a noise spectrum, an automatic gain's current level. Nothing
/// in this crate reads that state; the trait only says how frames go in and
/// come out.
///
/// `Send`, because the call it belongs to is. Its frames are handed over by
/// whichever thread carries the call's audio, and the session that owns the
/// processor is reached from those threads as well as from the one that runs
/// signalling, so the processor has to be able to move between them. The
/// alternative was the library asserting that of an implementation somebody
/// else wrote, which is a promise it has no way to keep; an implementation
/// that cannot move is one no real audio device API could drive anyway.
pub trait Processor: Send {
    /// Process one frame of near-end audio in place: the signal captured
    /// from the microphone, about to be encoded and sent.
    ///
    /// `reference` is the far-end audio rendered to the speaker over the
    /// same span of time — what an echo canceller correlates `near_end`
    /// against to know what echo to remove. A processor with nothing to
    /// cancel, gain control alone say, is free to ignore it. Both frames
    /// cover the same span of time; aligning them to the sample is the
    /// business of whichever device I/O crate produced them, which knows the
    /// render-to-capture delay of the hardware, not this trait's.
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
