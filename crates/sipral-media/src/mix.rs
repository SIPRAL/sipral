// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Summing streams: the legs of a conference, and the tones a client plays
//! into a call that is already running.
//!
//! Adding two samples together needs more room than either of them has, and
//! what happens when the sum does not fit is the only real decision here. The
//! rule is: sum in thirty-two bits, clamp to the sixteen the stream carries,
//! and report both how many samples were clamped and how far the sum reached
//! before clamping. Clamping flattens the peaks of a mix that is too loud,
//! which is a distortion everybody can still talk through; wrapping, which is
//! what `i16 + i16` does on its own, turns the loudest moment of the call into
//! a burst of noise. Nothing here rides the gain by itself, because an
//! attenuation applied the instant a mix clips pumps audibly:
//! [`Clipping::gain_to_fit`] says what would have fitted and the caller
//! decides how fast to move towards it.
//!
//! A mix of several sources is formed once, in the wider accumulator, and
//! clipped once, which is what [`sum_into`] does. [`add_into`] folds one more
//! source into a buffer that already holds a mix, and it can only clamp at
//! every step: once a sum has been clamped, a later source that would have
//! brought it back inside the range no longer can. Where both are possible,
//! sum once.

use core::fmt;

/// Fifteen fractional bits, which is where a gain of one lives.
const SHIFT: u32 = 15;

/// A gain of one in Q15.
const ONE: i32 = 1 << SHIFT;

/// Half a step, for rounding.
const HALF: i64 = 1 << (SHIFT - 1);

/// The most a leg can be lifted: four times, twelve decibels. Past that the
/// caller is fixing a level problem in the wrong place.
const MAX_GAIN: i32 = 4 * ONE;

/// A level to apply to a source on its way into a mix, in Q15.
///
/// Fixed point rather than a float, so a build with a floating point unit and
/// a build without produce the same samples. Gains are never negative: an
/// inverted source is not a level, it is a different signal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gain(i32);

impl Gain {
    /// The source arrives at the level it left.
    pub const UNITY: Self = Self(ONE);

    /// The source contributes nothing.
    pub const SILENT: Self = Self(0);

    /// A gain straight from Q15, clamped to the range this type allows.
    #[must_use]
    pub const fn from_q15(value: i32) -> Self {
        if value < 0 {
            Self(0)
        } else if value > MAX_GAIN {
            Self(MAX_GAIN)
        } else {
            Self(value)
        }
    }

    /// The gain `numerator / denominator`, which is how a mixer usually says
    /// it: one over the number of legs, or three quarters for a tone under
    /// speech. A denominator of zero, or a negative ratio, is silence.
    #[must_use]
    pub fn ratio(numerator: i32, denominator: i32) -> Self {
        if numerator <= 0 || denominator <= 0 {
            return Self::SILENT;
        }
        let scaled = (i64::from(numerator) * i64::from(ONE)) / i64::from(denominator);
        Self::from_q15(narrow(scaled))
    }

    /// The gain as a Q15 integer.
    #[must_use]
    pub const fn to_q15(self) -> i32 {
        self.0
    }

    /// One sample at this level, rounded and clipped.
    #[must_use]
    pub fn apply(self, sample: i16) -> i16 {
        clip(narrow(scale(i64::from(sample), self.0)))
    }
}

impl fmt::Display for Gain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 >> SHIFT;
        let thousandths = ((self.0 - (whole << SHIFT)) * 1000) >> SHIFT;
        write!(f, "{whole}.{thousandths:03}")
    }
}

/// What a mix did to the samples that did not fit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Clipping {
    /// How many samples were clamped.
    pub samples: usize,
    /// The largest magnitude any sum reached before clamping, so a caller can
    /// work out the level that would have fitted. Zero when nothing clipped.
    pub peak: u32,
}

impl Clipping {
    /// Whether anything was clamped at all.
    #[must_use]
    pub const fn occurred(self) -> bool {
        self.samples > 0
    }

    /// The gain that would have kept this mix inside the range.
    ///
    /// Unity when nothing clipped. Applied to every source of a mix that did
    /// clip it removes the clipping from that mix; applied suddenly it is
    /// audible as a step, so a caller with a level to hold should move towards
    /// it over some tens of milliseconds rather than in one frame.
    #[must_use]
    pub fn gain_to_fit(self) -> Gain {
        let ceiling = u32::from(i16::MAX.unsigned_abs());
        if self.peak <= ceiling {
            return Gain::UNITY;
        }
        let fitted = (i64::from(i16::MAX) << SHIFT) / i64::from(self.peak);
        Gain::from_q15(narrow(fitted))
    }

    fn record(&mut self, sum: i32) -> i16 {
        let clipped = clip(sum);
        if i32::from(clipped) != sum {
            self.samples = self.samples.saturating_add(1);
            self.peak = self.peak.max(sum.unsigned_abs());
        }
        clipped
    }
}

/// The clipping rule, in one place: a sum wider than a sample, brought back
/// into the range a sample has.
///
/// Clamped, never wrapped. The two differ only on material that is already too
/// loud, and there they differ completely: clamping keeps the shape of the
/// waveform and squares off its peaks, wrapping replaces each peak with a
/// full-scale jump to the opposite rail.
#[must_use]
pub fn clip(sum: i32) -> i16 {
    let bounded = sum.clamp(i32::from(i16::MIN), i32::from(i16::MAX));
    i16::try_from(bounded).unwrap_or(0)
}

/// Adds `source` into `mix`, sample for sample.
///
/// Runs to the end of whichever slice is shorter, so a source that stops early
/// simply stops contributing. Each sum is clamped as it is formed, which is
/// the price of folding into a buffer that is already a mix; [`sum_into`] does
/// not pay it.
pub fn add_into(mix: &mut [i16], source: &[i16]) -> Clipping {
    add_scaled_into(mix, source, Gain::UNITY)
}

/// Adds `source` into `mix` at `gain`.
///
/// The level is applied to the source on the way in, so a source at
/// [`Gain::SILENT`] leaves the mix exactly as it was.
pub fn add_scaled_into(mix: &mut [i16], source: &[i16], gain: Gain) -> Clipping {
    let mut clipping = Clipping::default();
    if gain == Gain::SILENT {
        return clipping;
    }
    for (slot, sample) in mix.iter_mut().zip(source) {
        let sum = i64::from(*slot) + scale(i64::from(*sample), gain.to_q15());
        *slot = clipping.record(narrow(sum));
    }
    clipping
}

/// Fills `mix` with the sum of every source, forming each sum once.
///
/// Sources shorter than `mix` contribute silence past their end, and nothing
/// past the end of `mix` is read. This is the one to use for a conference: the
/// accumulator is wide enough that no intermediate sum can clip, so only the
/// total is ever clamped, and the peak reported is the peak of the real sum
/// rather than of a sum that was already flattened on the way.
pub fn sum_into(mix: &mut [i16], sources: &[&[i16]]) -> Clipping {
    let mut clipping = Clipping::default();
    for (index, slot) in mix.iter_mut().enumerate() {
        let mut sum: i32 = 0;
        for source in sources {
            let sample = source.get(index).copied().unwrap_or(0);
            sum = sum.saturating_add(i32::from(sample));
        }
        *slot = clipping.record(sum);
    }
    clipping
}

/// Fills `mix` with the sum of every source at its own level.
///
/// Levels are taken in order, and a source with no level of its own arrives at
/// unity: a caller mixing `n` legs at `1/n` passes `n` gains, and a caller
/// whose sources are already at the right level passes none.
pub fn sum_scaled_into(mix: &mut [i16], sources: &[&[i16]], gains: &[Gain]) -> Clipping {
    let mut clipping = Clipping::default();
    let unity = core::iter::repeat(&Gain::UNITY);
    for (index, slot) in mix.iter_mut().enumerate() {
        let mut sum: i64 = 0;
        for (source, gain) in sources.iter().zip(gains.iter().chain(unity.clone())) {
            let sample = i64::from(source.get(index).copied().unwrap_or(0));
            sum = sum.saturating_add(scale(sample, gain.to_q15()));
        }
        *slot = clipping.record(narrow(sum));
    }
    clipping
}

/// A sample at a Q15 level, rounded away from zero so that a signal and its
/// mirror image still cancel.
fn scale(sample: i64, gain: i32) -> i64 {
    let scaled = sample * i64::from(gain);
    if scaled < 0 {
        -((-scaled + HALF) >> SHIFT)
    } else {
        (scaled + HALF) >> SHIFT
    }
}

/// An accumulator down to the width the clipping rule works in, saturating.
fn narrow(value: i64) -> i32 {
    i32::try_from(value).unwrap_or(if value < 0 { i32::MIN } else { i32::MAX })
}

#[cfg(test)]
mod tests {
    use super::{Clipping, Gain, add_into, add_scaled_into, clip, sum_into, sum_scaled_into};

    #[test]
    fn unity_gain_leaves_every_sample_alone() {
        for sample in i16::MIN..=i16::MAX {
            assert_eq!(Gain::UNITY.apply(sample), sample, "at {sample}");
        }
    }

    #[test]
    fn silence_is_silence_at_the_negative_rail_too() {
        assert_eq!(Gain::SILENT.apply(i16::MIN), 0);
        assert_eq!(Gain::SILENT.apply(i16::MAX), 0);
    }

    #[test]
    fn a_gain_above_the_ceiling_is_the_ceiling() {
        assert_eq!(Gain::from_q15(i32::MAX), Gain::from_q15(4 * 32_768));
        assert_eq!(Gain::from_q15(-1), Gain::SILENT);
        assert_eq!(Gain::ratio(1, 0), Gain::SILENT);
        assert_eq!(Gain::ratio(-1, 2), Gain::SILENT);
        assert_eq!(Gain::ratio(1, 2).to_q15(), 16_384);
        assert_eq!(Gain::ratio(1, 1), Gain::UNITY);
        // ten times is asked for, four times is given
        assert_eq!(Gain::ratio(10, 1), Gain::from_q15(4 * 32_768));
    }

    #[test]
    fn a_gain_amplifies_and_saturates_rather_than_wrapping() {
        let loud = Gain::ratio(2, 1);
        assert_eq!(loud.apply(1_000), 2_000);
        assert_eq!(loud.apply(20_000), i16::MAX);
        assert_eq!(loud.apply(-20_000), i16::MIN);
    }

    #[test]
    fn the_clipping_rule_clamps_where_wrapping_would_flip() {
        assert_eq!(clip(40_000), i16::MAX);
        assert_eq!(clip(-40_000), i16::MIN);
        assert_eq!(clip(0), 0);
        assert_eq!(clip(i32::from(i16::MAX)), i16::MAX);
        // what the rule exists to avoid
        assert!(
            i16::MAX.wrapping_add(7_233) < 0,
            "the wrap changes the sign"
        );
    }

    #[test]
    fn a_mix_that_fits_is_untouched() {
        let mut mix = [1_000, -2_000, 3_000];
        let report = add_into(&mut mix, &[500, 500, -500]);
        assert_eq!(mix, [1_500, -1_500, 2_500]);
        assert_eq!(report, Clipping::default());
        assert!(!report.occurred());
        assert_eq!(report.gain_to_fit(), Gain::UNITY);
    }

    #[test]
    fn a_source_shorter_than_the_mix_stops_contributing() {
        let mut mix = [100, 100, 100, 100];
        add_into(&mut mix, &[10, 10]);
        assert_eq!(mix, [110, 110, 100, 100]);
        // and the other way round: nothing past the end of the mix is read
        let mut short = [100];
        add_into(&mut short, &[10, 10, 10]);
        assert_eq!(short, [110]);
    }

    #[test]
    fn both_rails_saturate_and_are_counted() {
        let mut mix = [i16::MAX, i16::MIN, 0];
        let report = add_into(&mut mix, &[i16::MAX, i16::MIN, 0]);
        assert_eq!(mix, [i16::MAX, i16::MIN, 0]);
        assert_eq!(report.samples, 2);
        assert_eq!(report.peak, 65_536);
    }

    #[test]
    fn the_sum_of_several_sources_is_formed_once_and_clipped_once() {
        // pairwise saturation clamps at the second source and never finds its
        // way back; one accumulator does
        let loud = [30_000_i16; 4];
        let quiet = [-30_000_i16; 4];
        let mut mix = [0_i16; 4];
        let report = sum_into(&mut mix, &[&loud, &loud, &quiet]);
        assert_eq!(mix, [30_000; 4]);
        assert!(!report.occurred());

        let mut folded = [0_i16; 4];
        add_into(&mut folded, &loud);
        add_into(&mut folded, &loud);
        add_into(&mut folded, &quiet);
        assert_eq!(
            folded, [2_767; 4],
            "the fold clamped on the way and lost it"
        );
    }

    #[test]
    fn the_peak_reported_is_the_peak_of_the_real_sum() {
        let source = [20_000_i16; 2];
        let mut mix = [0_i16; 2];
        let report = sum_into(&mut mix, &[&source, &source, &source]);
        assert_eq!(mix, [i16::MAX; 2]);
        assert_eq!(report.samples, 2);
        assert_eq!(report.peak, 60_000);

        // and the gain it names really does fit the sum inside
        let fitted = report.gain_to_fit();
        let scaled = i32::from(fitted.apply(20_000));
        assert!(scaled * 3 <= i32::from(i16::MAX), "{scaled} times three");
    }

    #[test]
    fn levels_are_applied_on_the_way_in() {
        let leg = [8_000_i16; 3];
        let mut mix = [0_i16; 3];
        let report = sum_scaled_into(
            &mut mix,
            &[&leg, &leg, &leg],
            &[Gain::ratio(1, 2), Gain::ratio(1, 4)],
        );
        // a half, a quarter, and one that was given no level at all
        assert_eq!(mix, [4_000 + 2_000 + 8_000; 3]);
        assert!(!report.occurred());
    }

    #[test]
    fn a_silent_source_changes_nothing() {
        let mut mix = [123, -456, 789];
        let before = mix;
        let report = add_scaled_into(&mut mix, &[9_000, 9_000, 9_000], Gain::SILENT);
        assert_eq!(mix, before);
        assert!(!report.occurred());
    }

    #[test]
    fn an_empty_mix_is_not_a_special_case() {
        let mut empty: [i16; 0] = [];
        assert_eq!(add_into(&mut empty, &[1, 2, 3]), Clipping::default());
        assert_eq!(sum_into(&mut empty, &[&[1, 2][..]]), Clipping::default());
        let mut mix = [7_i16; 2];
        assert_eq!(sum_into(&mut mix, &[]), Clipping::default());
        assert_eq!(
            mix,
            [0, 0],
            "no sources sum to silence, not to what was there"
        );
    }

    #[test]
    fn rounding_a_level_does_not_creep() {
        // a signal and its mirror image have to land the same distance from
        // zero, or a mix of the two would not cancel
        let half = Gain::ratio(1, 2);
        for sample in [1_i16, 3, 999, 12_345, 32_767] {
            assert_eq!(
                i32::from(half.apply(sample)) + i32::from(half.apply(-sample)),
                0,
                "at {sample}"
            );
        }
    }

    #[test]
    fn a_gain_prints_as_a_number() {
        assert_eq!(Gain::UNITY.to_string(), "1.000");
        assert_eq!(Gain::SILENT.to_string(), "0.000");
        assert_eq!(Gain::ratio(1, 2).to_string(), "0.500");
        assert_eq!(Gain::ratio(1, 4).to_string(), "0.250");
    }
}
