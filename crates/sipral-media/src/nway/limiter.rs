// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Keeping a mix that is too loud inside the range a sample has.
//!
//! A conference sums its legs, and eight people talking at once sum to far
//! more than sixteen bits hold. [`mix::clip`] alone would square off every
//! peak of that sum, which is intelligible but harsh. The limiter here rides
//! the level down before the rail is reached, and shapes whatever still gets
//! past it, so that the rail itself is never touched.
//!
//! It works in two stages, one sample at a time:
//!
//! 1. **Gain riding.** An envelope follows the magnitude of the input. It
//!    rises with time constant [`ATTACK_MS`] and falls with [`RELEASE_MS`].
//!    Above [`CEILING`] the sample is scaled by `CEILING / envelope`. The
//!    envelope never exceeds the largest input, so material under the
//!    ceiling passes untouched.
//! 2. **Soft clipping.** The attack is not instant, so the first peaks of a
//!    loud onset reach the output before the gain has come down. Above the
//!    ceiling, magnitudes are bent onto a curve that starts with a slope of
//!    one and approaches full scale without ever reaching it:
//!    `c + h·u / (u + h)`, where `c` is the ceiling, `h` the headroom above it
//!    and `u` how far the sample went past the ceiling. The curve has no
//!    corner, so it adds far fewer harmonics than a clamp.
//!
//! [`mix::clip`] runs last but never acts; it keeps one narrowing rule for
//! the crate. Integer arithmetic throughout.

use crate::mix;

/// Time constant of the envelope when the level rises, in milliseconds.
pub const ATTACK_MS: u32 = 1;

/// Time constant of the envelope when the level falls, in milliseconds.
pub const RELEASE_MS: u32 = 80;

/// The magnitude the limiter holds a loud mix to, and the knee of the soft
/// clipper: three quarters of full scale, about 2.5 dB below it.
pub const CEILING: i32 = 24_576;

/// The room between the ceiling and the rail that the soft clipper bends
/// overshoot into.
const HEADROOM: i64 = i16::MAX as i64 - CEILING as i64;

/// Fractional bits the envelope is kept with, so that a slow release still
/// moves when the gap it closes is a fraction of a step.
const ENVELOPE_SHIFT: u32 = 8;

/// A peak limiter for one stream, at one sample rate.
///
/// The stream may be louder than a sample: the input is a wide sum, and the
/// output is always a sample. The module documentation gives the attack, the
/// release and the ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limiter {
    /// The followed magnitude, with [`ENVELOPE_SHIFT`] fractional bits.
    envelope: i64,
    /// Samples in one attack time constant.
    attack: i64,
    /// Samples in one release time constant.
    release: i64,
}

impl Limiter {
    /// A limiter for a stream at `sample_rate`, with its gain at unity.
    ///
    /// The rate only sets how many samples the attack and release span; a rate
    /// of zero is treated as one sample per time constant.
    #[must_use]
    pub fn new(sample_rate: u32) -> Self {
        Self {
            envelope: 0,
            attack: samples_in(sample_rate, ATTACK_MS),
            release: samples_in(sample_rate, RELEASE_MS),
        }
    }

    /// Forgets the level: the next sample meets a gain of unity.
    pub fn reset(&mut self) {
        self.envelope = 0;
    }

    /// The gain the next sample would meet if it were no louder than the
    /// last, in Q15: `32768` is unity.
    #[must_use]
    pub fn gain_q15(&self) -> i32 {
        let ceiling = i64::from(CEILING) << ENVELOPE_SHIFT;
        if self.envelope <= ceiling {
            return 1 << 15;
        }
        i32::try_from((ceiling << 15) / self.envelope).unwrap_or(0)
    }

    /// Limits one sample of a wide sum.
    pub fn process(&mut self, sample: i32) -> i16 {
        let magnitude = i64::from(sample.unsigned_abs()) << ENVELOPE_SHIFT;
        if magnitude > self.envelope {
            // rounded up, so that a rise always moves the envelope
            let gap = magnitude - self.envelope;
            self.envelope += (gap + self.attack - 1) / self.attack;
        } else {
            self.envelope -= (self.envelope - magnitude) / self.release;
        }

        let ceiling = i64::from(CEILING) << ENVELOPE_SHIFT;
        let ridden = if self.envelope > ceiling {
            // truncated towards zero, so the gain never lifts a sample
            i64::from(sample) * ceiling / self.envelope
        } else {
            i64::from(sample)
        };
        soft_clip(ridden)
    }

    /// Limits a run of samples, writing as many as the shorter slice holds.
    pub fn process_into(&mut self, input: &[i32], output: &mut [i16]) {
        for (slot, sample) in output.iter_mut().zip(input) {
            *slot = self.process(*sample);
        }
    }
}

/// Samples in `ms` milliseconds at `sample_rate`, never fewer than one.
fn samples_in(sample_rate: u32, ms: u32) -> i64 {
    (i64::from(sample_rate) * i64::from(ms) / 1_000).max(1)
}

/// Bends a magnitude above the ceiling onto a curve that approaches the rail
/// and never reaches it.
fn soft_clip(sample: i64) -> i16 {
    let magnitude = sample.abs();
    let knee = i64::from(CEILING);
    if magnitude <= knee {
        return mix::clip(narrow(sample));
    }
    let over = magnitude - knee;
    let bent = knee + HEADROOM * over / (over + HEADROOM);
    mix::clip(narrow(if sample < 0 { -bent } else { bent }))
}

/// A wide value down to the width [`mix::clip`] takes, saturating.
fn narrow(value: i64) -> i32 {
    i32::try_from(value).unwrap_or(if value < 0 { i32::MIN } else { i32::MAX })
}

#[cfg(test)]
mod tests {
    use super::{CEILING, Limiter, soft_clip};

    const RATE: u32 = 48_000;

    #[test]
    fn material_under_the_ceiling_passes_untouched() {
        let mut limiter = Limiter::new(RATE);
        for n in 0..4_800 {
            let sample = if n % 2 == 0 { CEILING } else { -CEILING };
            assert_eq!(i32::from(limiter.process(sample)), sample, "at {n}");
        }
        assert_eq!(limiter.gain_q15(), 1 << 15);
    }

    #[test]
    fn the_soft_clipper_never_reaches_the_rail() {
        for sample in [
            i64::from(CEILING) + 1,
            40_000,
            1_000_000,
            i64::from(i32::MAX),
            -40_000,
            i64::from(i32::MIN),
        ] {
            let bent = soft_clip(sample);
            assert!(
                bent > i16::MIN + 1 && bent < i16::MAX,
                "{sample} became {bent}"
            );
            assert!(
                i32::from(bent).abs() >= CEILING,
                "{sample} was bent under the ceiling"
            );
        }
        // no corner at the knee: just past it the curve still has a slope of
        // about one
        let past = i32::from(soft_clip(i64::from(CEILING) + 100)) - CEILING;
        assert!((98..=100).contains(&past), "{past} for 100 past the knee");
    }

    #[test]
    fn a_loud_step_is_held_to_the_ceiling_within_the_attack() {
        let mut limiter = Limiter::new(RATE);
        let loud = 4 * i32::from(i16::MAX);
        // five attack time constants
        for _ in 0..240 {
            limiter.process(loud);
        }
        let held = i32::from(limiter.process(loud));
        assert!(
            held <= CEILING + CEILING / 50,
            "{held} after five time constants"
        );
        assert!(held >= CEILING - CEILING / 50, "{held} was pushed too far");
    }

    #[test]
    fn the_first_sample_of_a_loud_onset_is_bent_not_clamped() {
        let mut limiter = Limiter::new(RATE);
        let first = limiter.process(4 * i32::from(i16::MAX));
        assert!(first < i16::MAX && i32::from(first) > CEILING, "{first}");
    }

    #[test]
    fn the_gain_recovers_with_the_release_time_constant() {
        let mut limiter = Limiter::new(RATE);
        let loud = 2 * CEILING;
        for _ in 0..4_800 {
            limiter.process(loud);
        }
        let floored = limiter.gain_q15();
        assert!(
            floored < 17_000,
            "gain {floored} after 100 ms of twice the ceiling"
        );
        // one release time constant of silence: the envelope has fallen 63%
        // of the way from twice the ceiling, so it is back under it and the
        // gain is unity; half a time constant is not enough
        for _ in 0..1_920 {
            limiter.process(0);
        }
        assert!(limiter.gain_q15() < 1 << 15, "recovered after 40 ms");
        for _ in 0..1_920 {
            limiter.process(0);
        }
        assert_eq!(limiter.gain_q15(), 1 << 15, "not recovered after 80 ms");
    }

    #[test]
    fn a_reset_forgets_the_level() {
        let mut limiter = Limiter::new(RATE);
        for _ in 0..480 {
            limiter.process(1_000_000);
        }
        limiter.reset();
        assert_eq!(limiter.process(CEILING), i16::try_from(CEILING).unwrap());
    }
}
