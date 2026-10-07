// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Keeping two clocks that both claim to run at the same rate from drifting
//! apart over the length of a call.
//!
//! A 50 ppm crystal gains 400 samples an hour at 8 kHz; left alone, a buffer
//! overflows or underruns.
//!
//! Two terms drive the correction: the rate difference, filtered over about
//! sixty frames, and the level the buffer has already moved, with a much
//! longer time constant so the buffer returns to where it started. Their sum
//! accumulates in fractions of a sample and acts on each whole one.
//!
//! A correction warps the quietest window of a frame by one sample, keeping
//! its endpoints, so there is no click, only a brief pitch shift. One sample
//! per frame (6000 ppm at 20 ms) is the ceiling; [`Drift::excess`] reports
//! when more is needed.
//!
//! The tracker is separate from the warp, so a jitter buffer can act on
//! [`Drift`]'s decision its own way. Nothing allocates.

use crate::mix;
use core::fmt;

/// Fifteen fractional bits, for the smoothed estimate and the warp's
/// interpolation.
const SHIFT: u32 = 15;

/// One, in that fixed point.
const ONE: i64 = 1 << SHIFT;

/// How hard the rate estimate is filtered: each frame moves it a sixty-fourth
/// of the way to the truth, so the time constant is around sixty frames, which
/// at twenty milliseconds a frame is a second and a bit. Long enough to ignore
/// a device that hands over two frames at once, short enough to catch a real
/// drift before the buffer notices it.
const SMOOTHING: u32 = 6;

/// How long the level term takes to bring the buffer back to where it started,
/// in frames: four seconds at twenty milliseconds a frame. Slow on purpose —
/// it is correcting an offset of a sample or two, and there is nothing to be
/// gained by doing it in a hurry.
const RECOVERY_FRAMES: i64 = 200;

/// The most unacted-on correction the pace may accumulate, in samples.
///
/// Without it, a drift past what one edit per frame can fix would wind the
/// accumulator up without bound, and every quiet frame after the drift went
/// away would be warped paying off a debt that no longer means anything.
const MAX_DEBT: i64 = 2 * ONE;

/// The length of the window that gets warped, in milliseconds.
///
/// Eight milliseconds is one sample in sixty-four at 8 kHz: a pitch shift of
/// one and a half percent for the length of the window, which is under what
/// anybody can hear, and short enough that the odds of it landing on a
/// consonant are small.
const WINDOW_MS: u32 = 8;

/// The shortest warp window worth building. Below this the pitch shift inside
/// the window stops being subtle.
const MIN_WINDOW: usize = 16;

/// The longest. At 48 kHz eight milliseconds would be 384 samples, and there
/// is nothing to gain from spreading a single sample any thinner than this.
const MAX_WINDOW: usize = 256;

/// What the tracker wants done to the next frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Correction {
    /// The two clocks agree closely enough. Pass the frame through.
    #[default]
    None,
    /// More has been produced than consumed: one sample has to come out.
    Remove,
    /// Less has been produced than consumed: one sample has to go in.
    Insert,
}

/// The long-term ratio between two clocks, and the sample-sized corrections
/// that hold them together.
///
/// One per stream and per direction. Samples arriving from the device side go
/// through [`process`](Self::process), which counts them; samples taken off
/// the other side are reported with [`consumed`](Self::consumed). What the
/// tracker holds is the rate the two counts are moving apart at and how far
/// apart they have already moved.
#[derive(Clone, Debug)]
pub struct Drift {
    window: usize,
    produced: u64,
    consumed: u64,
    /// Samples this has added, less those it has removed.
    applied: i64,
    /// The difference between the two counts when the first frame arrived,
    /// which is the level the stream is regulated back to.
    origin: i64,
    /// Frames seen, only to tell the first one from the rest.
    frames: u64,
    /// The difference between the two counts as it was at the last frame, so
    /// that the rate can be measured from how much it moved.
    previous: i64,
    /// The filtered difference in the two clocks, in Q15 samples per frame.
    rate: i64,
    /// Corrections owed but not yet made, in Q15 samples.
    debt: i64,
    corrections: u64,
}

impl Drift {
    /// A tracker for a stream at `sample_rate`.
    ///
    /// The rate is used only to size the warp window; a rate of zero, or one
    /// too low to hold a window, gets the shortest window rather than an
    /// error, because a nonsense rate is not worth a `Result` in a path that
    /// otherwise cannot fail.
    #[must_use]
    pub fn new(sample_rate: u32) -> Self {
        let window = usize::try_from(sample_rate.saturating_mul(WINDOW_MS) / 1_000)
            .unwrap_or(MAX_WINDOW)
            .clamp(MIN_WINDOW, MAX_WINDOW);
        Self {
            window,
            produced: 0,
            consumed: 0,
            applied: 0,
            origin: 0,
            frames: 0,
            previous: 0,
            rate: 0,
            debt: 0,
            corrections: 0,
        }
    }

    /// Counts samples that came in from the producing clock, and advances the
    /// estimate one frame.
    ///
    /// [`process`](Self::process) does this itself; a caller doing its own
    /// warping calls it once per frame, since a frame is the step the estimate
    /// moves in.
    pub fn produced(&mut self, samples: usize) {
        self.produced = self
            .produced
            .saturating_add(u64::try_from(samples).unwrap_or(u64::MAX));

        let difference = self.difference();
        self.frames = self.frames.saturating_add(1);
        if self.frames == 1 {
            // whatever the pipeline is holding when the first frame arrives is
            // the level to regulate back to, and there is no previous frame to
            // measure a rate against
            self.origin = difference;
            self.previous = difference;
            return;
        }

        // how far the two clocks moved apart since the last frame, which is
        // whole samples and mostly zero: the filter is what turns it into the
        // fraction of a sample a frame really is
        let moved = (difference - self.previous).saturating_mul(ONE);
        self.previous = difference;
        self.rate += (moved - self.rate) >> SMOOTHING;

        // and the level, so that the buffer comes back to where it started
        // rather than settling wherever the drift carried it
        let level = (self.excess() * ONE) / RECOVERY_FRAMES;
        self.debt = (self.debt + self.rate + level).clamp(-MAX_DEBT, MAX_DEBT);
    }

    /// Counts samples the consuming clock took off the other end.
    pub fn consumed(&mut self, samples: usize) {
        self.consumed = self
            .consumed
            .saturating_add(u64::try_from(samples).unwrap_or(u64::MAX));
    }

    /// What the tracker wants done, and the decision is taken: the sample it
    /// asks for is counted as already added or removed, so asking twice
    /// without acting cannot double-correct.
    ///
    /// Returns [`Correction::None`] until the pace has accumulated a whole
    /// sample, which at an ordinary drift is once every few seconds.
    pub fn poll(&mut self) -> Correction {
        if self.debt >= ONE {
            self.debt -= ONE;
            self.applied -= 1;
            self.corrections = self.corrections.saturating_add(1);
            Correction::Remove
        } else if self.debt <= -ONE {
            self.debt += ONE;
            self.applied += 1;
            self.corrections = self.corrections.saturating_add(1);
            Correction::Insert
        } else {
            Correction::None
        }
    }

    /// Copies a frame through, adding or removing one sample where the frame
    /// is quietest if the two clocks have come far enough apart.
    ///
    /// Returns how many samples were written, which is the length of the frame
    /// plus or minus one. `output` must have room for one more sample than
    /// `input` holds; anything shorter is left untouched and nothing is
    /// counted, since a frame that cannot be written cannot have been
    /// produced.
    pub fn process(&mut self, input: &[i16], output: &mut [i16]) -> usize {
        if output.len() <= input.len() {
            return 0;
        }
        self.produced(input.len());
        // a window plus the sample it swallows has to fit inside the frame,
        // and the search needs somewhere to put it
        let correction = if input.len() > self.window {
            self.poll()
        } else {
            Correction::None
        };
        match correction {
            Correction::None => {
                for (slot, sample) in output.iter_mut().zip(input) {
                    *slot = *sample;
                }
                input.len()
            }
            Correction::Remove => warp(input, output, self.window + 1, self.window),
            Correction::Insert => warp(input, output, self.window, self.window + 1),
        }
    }

    /// How far the buffer between the two clocks has moved from where it
    /// stood when the first frame arrived, counting what has been added or
    /// removed on the way.
    ///
    /// It swings by a frame within each cycle, so read it at the same point
    /// each time. It should hold within a sample or two; a steady walk means
    /// the drift is beyond one sample a frame.
    #[must_use]
    pub fn excess(&self) -> i64 {
        self.difference() + self.applied - self.origin
    }

    /// What the two clocks say, before anything this did to the stream.
    fn difference(&self) -> i64 {
        let produced = i64::try_from(self.produced).unwrap_or(i64::MAX);
        let consumed = i64::try_from(self.consumed).unwrap_or(i64::MAX);
        produced - consumed
    }

    /// How far the producing clock runs ahead of the consuming one, in parts
    /// per million, straight from the two counts.
    ///
    /// Positive means the producer is fast. Zero until anything has been
    /// consumed; only meaningful after a minute or so.
    #[must_use]
    pub fn drift_ppm(&self) -> i32 {
        if self.consumed == 0 {
            return 0;
        }
        let produced = i128::from(self.produced);
        let consumed = i128::from(self.consumed);
        let parts = ((produced - consumed) * 1_000_000) / consumed;
        i32::try_from(parts).unwrap_or(if parts < 0 { i32::MIN } else { i32::MAX })
    }

    /// How many single-sample corrections have been made since the last reset.
    #[must_use]
    pub const fn corrections(&self) -> u64 {
        self.corrections
    }

    /// The length of the window a correction is spread over, in samples.
    #[must_use]
    pub const fn window(&self) -> usize {
        self.window
    }

    /// Forgets both counts and the estimate: a new call, or a device that has
    /// just been restarted and whose counts no longer follow on.
    pub fn reset(&mut self) {
        self.produced = 0;
        self.consumed = 0;
        self.applied = 0;
        self.origin = 0;
        self.frames = 0;
        self.previous = 0;
        self.rate = 0;
        self.debt = 0;
        self.corrections = 0;
    }
}

/// Copies the frame with one window resampled from `span` samples to
/// `produce`, which differ by one.
fn warp(input: &[i16], output: &mut [i16], span: usize, produce: usize) -> usize {
    let start = quietest(input, span);
    let (Some(head), Some(body), Some(tail)) = (
        input.get(..start),
        input.get(start..start + span),
        input.get(start + span..),
    ) else {
        return 0;
    };
    let written = head.len() + produce + tail.len();
    let Some(room) = output.get_mut(..written) else {
        return 0;
    };
    let Some((front, rest)) = room.split_at_mut_checked(head.len()) else {
        return 0;
    };
    front.copy_from_slice(head);
    let Some((middle, back)) = rest.split_at_mut_checked(produce) else {
        return 0;
    };
    stretch_into(body, middle);
    back.copy_from_slice(tail);
    written
}

/// Where in `input` a window of `span` samples has the least in it.
///
/// The sum of magnitudes rather than of squares: the two pick the same window
/// on anything that is not pathological, and this one cannot overflow however
/// long the frame is. Ties go to the earliest window, so the choice is
/// repeatable.
#[must_use]
pub fn quietest(input: &[i16], span: usize) -> usize {
    if span == 0 || input.len() <= span {
        return 0;
    }
    let mut running: u64 = input.iter().take(span).copied().map(magnitude).sum();
    let mut best = running;
    let mut at = 0;
    for (index, (leaving, entering)) in input.iter().zip(input.iter().skip(span)).enumerate() {
        running = running - magnitude(*leaving) + magnitude(*entering);
        if running < best {
            best = running;
            at = index + 1;
        }
    }
    at
}

/// Writes `input` into `output` as one sample fewer, by compressing it in
/// time.
///
/// The first and last samples come through exactly, so neither seam steps.
/// Returns how many samples were written, or zero if the slices are too short
/// (three in, room for one fewer out).
pub fn compress(input: &[i16], output: &mut [i16]) -> usize {
    let Some(produce) = input.len().checked_sub(1) else {
        return 0;
    };
    if produce < 2 || output.len() < produce {
        return 0;
    }
    let Some(room) = output.get_mut(..produce) else {
        return 0;
    };
    stretch_into(input, room);
    produce
}

/// Writes `input` into `output` as one sample more, by stretching it in time.
///
/// The mirror of [`compress`], with the same guarantee at the ends.
pub fn stretch(input: &[i16], output: &mut [i16]) -> usize {
    if input.len() < 2 {
        return 0;
    }
    let produce = input.len() + 1;
    let Some(room) = output.get_mut(..produce) else {
        return 0;
    };
    stretch_into(input, room);
    produce
}

/// Resamples `input` to fill `output` exactly, whatever the two lengths are.
///
/// Exact rational positions keep both end samples bit for bit. Catmull-Rom in
/// between, which passes through the samples rather than smoothing them; the
/// missing neighbour at each end is the end sample repeated.
fn stretch_into(input: &[i16], output: &mut [i16]) {
    let (Some(last_in), Some(steps)) = (input.len().checked_sub(1), output.len().checked_sub(1))
    else {
        return;
    };
    if steps == 0 {
        if let (Some(slot), Some(sample)) = (output.first_mut(), input.first()) {
            *slot = *sample;
        }
        return;
    }
    for (index, slot) in output.iter_mut().enumerate() {
        let scaled = index * last_in;
        let position = scaled / steps;
        let remainder = scaled % steps;
        let fraction =
            (i64::try_from(remainder).unwrap_or(0) * ONE) / i64::try_from(steps).unwrap_or(1);
        *slot = interpolate(input, position, fraction);
    }
}

/// One sample `fraction` of the way past `position`, by Catmull-Rom.
fn interpolate(input: &[i16], position: usize, fraction: i64) -> i16 {
    let at = |index: usize| -> i64 {
        let bounded = index.min(input.len().saturating_sub(1));
        i64::from(input.get(bounded).copied().unwrap_or(0))
    };
    let before = at(position.saturating_sub(1));
    let start = at(position);
    let end = at(position + 1);
    let after = at(position + 2);

    let linear = end - before;
    let square = 2 * before - 5 * start + 4 * end - after;
    let cube = 3 * start - 3 * end + after - before;
    let squared = (fraction * fraction) >> SHIFT;
    let cubed = (squared * fraction) >> SHIFT;
    // twice the value, in Q15, so that the halving in the spline is a shift
    let scaled = 2 * start * ONE + linear * fraction + square * squared + cube * cubed;
    let rounded = (scaled + ONE) >> (SHIFT + 1);
    mix::clip(i32::try_from(rounded).unwrap_or(if rounded < 0 { i32::MIN } else { i32::MAX }))
}

fn magnitude(sample: i16) -> u64 {
    u64::from(sample.unsigned_abs())
}

impl fmt::Display for Correction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match *self {
            Self::None => "none",
            Self::Remove => "remove one",
            Self::Insert => "insert one",
        };
        f.write_str(word)
    }
}

#[cfg(test)]
mod tests {
    use super::{Correction, Drift, MIN_WINDOW, compress, quietest, stretch};

    /// A frame at the default packetisation, at the rate G.711 runs at.
    const FRAME: usize = 160;

    fn ramp(count: usize, step: i32) -> Vec<i16> {
        (0..count)
            .map(|index| i16::try_from(i32::try_from(index).unwrap() * step - 8_000).unwrap())
            .collect()
    }

    /// What an hour of a drifting clock did.
    struct Call {
        corrections: u64,
        lowest: i64,
        highest: i64,
        settled: i64,
    }

    /// Runs a call of `seconds` in twenty millisecond frames with the
    /// producing clock off by `ppm`, and watches the buffer level.
    fn call(seconds: u64, ppm: i64) -> Call {
        let mut drift = Drift::new(8_000);
        let mut carried: i64 = 0;
        let frames = seconds * 50;
        let mut report = Call {
            corrections: 0,
            lowest: 0,
            highest: 0,
            settled: 0,
        };
        for frame in 0..frames {
            // the device hands over a frame that is a little long or a little
            // short, in whole samples, with the fraction carried over
            carried += i64::try_from(FRAME).unwrap() * ppm;
            let extra = carried / 1_000_000;
            carried -= extra * 1_000_000;
            let arrived = usize::try_from(i64::try_from(FRAME).unwrap() + extra).unwrap();
            drift.produced(arrived);
            drift.poll();
            // read at the same point in every cycle, before the far end takes
            // its frame back out
            let level = drift.excess();
            drift.consumed(FRAME);
            // the first ten seconds are the estimate finding the drift; what
            // matters is where it holds afterwards
            if frame > 500 {
                report.lowest = report.lowest.min(level);
                report.highest = report.highest.max(level);
            }
            report.settled = level;
        }
        report.corrections = drift.corrections();
        report
    }

    #[test]
    fn clocks_that_agree_are_left_alone() {
        let report = call(3_600, 0);
        assert_eq!(report.corrections, 0);
        assert_eq!((report.lowest, report.highest), (0, 0));
    }

    #[test]
    fn an_hour_of_a_drifting_clock_does_not_run_the_buffer_dry() {
        // a hundred parts per million is a bad but ordinary crystal: 2880
        // samples an hour at 8 kHz, which is a third of a second of audio
        for ppm in [-200, -100, -25, 25, 100, 200] {
            let report = call(3_600, ppm);
            let expected = u64::try_from((3_600 * 8_000 * ppm.abs()) / 1_000_000).unwrap();
            assert!(
                report.corrections.abs_diff(expected) * 100 < expected,
                "{ppm} ppm: {} corrections against {expected}",
                report.corrections
            );
            // the buffer holds where it started, within the sample or two the
            // estimate needs to notice a change
            assert!(
                report.lowest > -3,
                "{ppm} ppm: buffer down to {}",
                report.lowest
            );
            assert!(
                report.highest < 3,
                "{ppm} ppm: buffer up to {}",
                report.highest
            );
            assert!(
                report.settled.abs() <= 1,
                "{ppm} ppm: settled at {}",
                report.settled
            );
        }
    }

    #[test]
    fn the_drift_it_reports_is_the_drift_it_was_given() {
        let mut drift = Drift::new(8_000);
        assert_eq!(drift.drift_ppm(), 0);
        for _ in 0..50 * 600 {
            drift.produced(160);
            drift.consumed(160);
        }
        assert_eq!(drift.drift_ppm(), 0);
        // ten minutes of a hundred parts per million: 480 samples
        let mut fast = Drift::new(8_000);
        for _ in 0..50 * 600 {
            fast.produced(160);
            fast.consumed(160);
        }
        for _ in 0..480 {
            fast.produced(1);
        }
        assert_eq!(fast.drift_ppm(), 100);
    }

    #[test]
    fn a_drift_past_what_a_frame_can_fix_still_stops_the_buffer_growing() {
        // a whole sample per frame is six thousand parts per million, which is
        // exactly the ceiling: the loop can hold the buffer but cannot bring
        // it back, and it must not wind itself up trying
        let mut drift = Drift::new(8_000);
        let mut level_at_500 = 0;
        for frame in 0..2_000 {
            drift.produced(FRAME + 1);
            drift.poll();
            drift.consumed(FRAME);
            if frame == 500 {
                level_at_500 = drift.excess();
            }
        }
        let settled = drift.excess();
        assert!(settled <= level_at_500, "{level_at_500} then {settled}");
        assert!(drift.corrections() >= 1_900, "{} made", drift.corrections());
        // and once the drift goes away, the debt it could not pay off does not
        // keep warping quiet frames for the rest of the call
        let before = drift.corrections();
        for _ in 0..200 {
            drift.produced(FRAME);
            drift.poll();
            drift.consumed(FRAME);
        }
        assert!(
            drift.corrections() - before < 200,
            "{} more corrections after the drift stopped",
            drift.corrections() - before
        );
    }

    #[test]
    fn a_frame_comes_back_one_sample_shorter_or_longer() {
        let mut drift = Drift::new(8_000);
        let quiet = vec![0_i16; FRAME];
        let mut output = vec![0_i16; FRAME + 1];

        // nothing to correct yet
        assert_eq!(drift.process(&quiet, &mut output), FRAME);
        // run the producer ahead and the next frame comes back shorter
        for _ in 0..200 {
            drift.produced(FRAME + 2);
            drift.consumed(FRAME);
        }
        assert_eq!(drift.process(&quiet, &mut output), FRAME - 1);

        let mut behind = Drift::new(8_000);
        for _ in 0..200 {
            behind.produced(FRAME);
            behind.consumed(FRAME + 2);
        }
        assert_eq!(behind.process(&quiet, &mut output), FRAME + 1);
    }

    #[test]
    fn the_warp_lands_where_the_frame_is_quiet() {
        let mut drift = Drift::new(8_000);
        // loud in the first half, silent in the second
        let mut frame = vec![0_i16; FRAME];
        for (index, sample) in frame.iter_mut().enumerate().take(FRAME / 2) {
            *sample = if index % 2 == 0 { 20_000 } else { -20_000 };
        }
        for _ in 0..200 {
            drift.produced(FRAME + 2);
            drift.consumed(FRAME);
        }
        let mut output = vec![0_i16; FRAME + 1];
        let written = drift.process(&frame, &mut output);
        assert_eq!(written, FRAME - 1);
        // the loud half is untouched, sample for sample
        let loud = frame.get(..FRAME / 2).unwrap();
        assert_eq!(output.get(..FRAME / 2).unwrap(), loud);
    }

    #[test]
    fn the_seams_of_a_warp_are_exact() {
        let line = ramp(64, 50);
        let mut shorter = vec![0_i16; 63];
        assert_eq!(compress(&line, &mut shorter), 63);
        assert_eq!(shorter.first(), line.first());
        assert_eq!(shorter.last(), line.last());

        let mut longer = vec![0_i16; 65];
        assert_eq!(stretch(&line, &mut longer), 65);
        assert_eq!(longer.first(), line.first());
        assert_eq!(longer.last(), line.last());
    }

    #[test]
    fn a_warp_of_a_constant_is_the_constant() {
        for level in [i16::MIN, -1_000, 0, 1, 12_345, i16::MAX] {
            let flat = vec![level; 48];
            let mut shorter = vec![0_i16; 47];
            compress(&flat, &mut shorter);
            assert!(shorter.iter().all(|sample| *sample == level), "at {level}");
            let mut longer = vec![0_i16; 49];
            stretch(&flat, &mut longer);
            assert!(longer.iter().all(|sample| *sample == level), "at {level}");
        }
    }

    #[test]
    fn a_warp_of_a_straight_line_stays_straight() {
        // a ramp interpolated by a spline that reproduces lines has to come
        // back as a ramp, give or take the ends where the neighbour is missing
        let line = ramp(65, 40);
        let mut shorter = vec![0_i16; 64];
        compress(&line, &mut shorter);
        for (index, window) in shorter.windows(2).enumerate().skip(1).take(61) {
            let step = i32::from(window[1]) - i32::from(window[0]);
            assert!((39..=42).contains(&step), "step {step} at {index}");
        }
    }

    #[test]
    fn a_warp_does_not_overshoot_into_a_wrap() {
        let square: Vec<i16> = (0..64)
            .map(|index| {
                if (index / 4) % 2 == 0 {
                    i16::MAX
                } else {
                    i16::MIN
                }
            })
            .collect();
        let mut shorter = vec![0_i16; 63];
        compress(&square, &mut shorter);
        for (index, window) in shorter.windows(2).enumerate() {
            let step = i32::from(window[1]) - i32::from(window[0]);
            assert!(step.abs() <= 65_535, "step {step} at {index}");
        }
        // the spline overshoots a step, and the overshoot has to clip
        assert!(shorter.contains(&i16::MAX));
        assert!(shorter.contains(&i16::MIN));
    }

    #[test]
    fn the_quietest_window_is_the_quietest_window() {
        let mut frame = vec![1_000_i16; 100];
        for sample in frame.iter_mut().skip(40).take(10) {
            *sample = 0;
        }
        assert_eq!(quietest(&frame, 10), 40);
        // ties go to the earliest
        assert_eq!(quietest(&[5_i16; 100], 10), 0);
        // and a window that does not fit starts at the beginning
        assert_eq!(quietest(&frame, 200), 0);
        assert_eq!(quietest(&[], 4), 0);
    }

    #[test]
    fn slices_too_short_to_warp_are_refused() {
        let mut output = [0_i16; 8];
        assert_eq!(compress(&[], &mut output), 0);
        assert_eq!(compress(&[1], &mut output), 0);
        assert_eq!(compress(&[1, 2], &mut output), 0);
        assert_eq!(compress(&[1, 2, 3], &mut output), 2);
        assert_eq!(stretch(&[1], &mut output), 0);
        assert_eq!(stretch(&[1, 2], &mut output), 3);
        // no room to write into
        let mut cramped = [0_i16; 2];
        assert_eq!(stretch(&[1, 2], &mut cramped), 0);
        assert_eq!(compress(&[1, 2, 3, 4], &mut cramped), 0);
    }

    #[test]
    fn a_frame_with_nowhere_to_put_the_warp_is_passed_through() {
        let mut drift = Drift::new(8_000);
        for _ in 0..400 {
            drift.produced(FRAME + 2);
            drift.consumed(FRAME);
        }
        // shorter than the window, so there is no room to hide a correction
        let tiny = vec![100_i16; 8];
        let mut output = vec![0_i16; 9];
        assert_eq!(drift.process(&tiny, &mut output), 8);
        assert_eq!(output.get(..8).unwrap(), tiny.as_slice());
        // and the correction is still owed, so it happens on the next frame
        // that has room for it
        let full = vec![100_i16; FRAME];
        let mut room = vec![0_i16; FRAME + 1];
        assert_eq!(drift.process(&full, &mut room), FRAME - 1);
    }

    #[test]
    fn an_output_with_no_room_writes_nothing() {
        let mut drift = Drift::new(8_000);
        let frame = vec![7_i16; FRAME];
        let mut exact = vec![0_i16; FRAME];
        assert_eq!(drift.process(&frame, &mut exact), 0);
        assert!(exact.iter().all(|sample| *sample == 0));
        // and nothing was counted, so the frame can be offered again
        assert_eq!(drift.excess(), 0);
    }

    #[test]
    fn the_window_is_sized_by_the_rate_and_bounded_both_ways() {
        assert_eq!(Drift::new(8_000).window(), 64);
        assert_eq!(Drift::new(16_000).window(), 128);
        assert_eq!(Drift::new(48_000).window(), 256);
        assert_eq!(Drift::new(0).window(), MIN_WINDOW);
        assert_eq!(Drift::new(u32::MAX).window(), 256);
    }

    #[test]
    fn reset_forgets_both_clocks() {
        let mut drift = Drift::new(8_000);
        for _ in 0..100 {
            drift.produced(FRAME + 1);
            drift.poll();
            drift.consumed(FRAME);
        }
        assert!(drift.corrections() > 0);
        drift.reset();
        assert_eq!(drift.excess(), 0);
        assert_eq!(drift.corrections(), 0);
        assert_eq!(drift.drift_ppm(), 0);
        assert_eq!(drift.poll(), Correction::None);
    }

    #[test]
    fn a_correction_prints_as_what_it_is() {
        assert_eq!(Correction::default(), Correction::None);
        assert_eq!(Correction::Remove.to_string(), "remove one");
        assert_eq!(Correction::Insert.to_string(), "insert one");
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Arbitrary rates, arbitrary frame lengths (including the wrap of the
    /// `u64` counts `produced` and `consumed` accumulate over a very long
    /// call), and an output slice sized however the caller happened to size
    /// it: `process` must never panic, and it must keep the one promise its
    /// own doc comment makes, that a frame comes back the length it went in
    /// at, or one more, or one fewer.
    #[test]
    fn arbitrary_traffic_never_panics_and_the_length_never_drifts_by_more_than_one() {
        let mut seed = 0xB16B_00B5_C0DE_1234_u64;
        for _ in 0..200 {
            let rate = 1 + u32::try_from(xorshift64(&mut seed) % 96_000).unwrap_or(8_000);
            let mut drift = Drift::new(rate);
            // occasionally start the two counters near the wrap, so a run of
            // ordinary frames has to cross it
            if xorshift64(&mut seed).is_multiple_of(5) {
                let near_wrap = u64::MAX - (xorshift64(&mut seed) % 1_000);
                drift.produced = near_wrap;
                drift.consumed = near_wrap;
            }
            for _ in 0..40 {
                let input_len = usize::try_from(xorshift64(&mut seed) % 800).unwrap_or(0);
                let slack = xorshift64(&mut seed) % 4; // 0..=3 extra room
                let output_len = input_len + usize::try_from(slack).unwrap_or(0);
                let input = vec![0_i16; input_len];
                let mut output = vec![0_i16; output_len];
                let written = drift.process(&input, &mut output);
                if slack == 0 {
                    assert_eq!(written, 0, "no room offered but {written} was written");
                } else {
                    let delta =
                        i64::try_from(written).unwrap_or(0) - i64::try_from(input_len).unwrap_or(0);
                    assert!(
                        (-1..=1).contains(&delta),
                        "a frame of {input_len} came back as {written}"
                    );
                }
                drift.consumed(input_len);
            }
        }
    }
}
