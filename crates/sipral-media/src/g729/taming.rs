// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Keeping the adaptive codebook from running away: the encoder's taming of
//! the pitch gain.
//!
//! A pitch gain above one makes the excitation grow each time it is copied
//! forward a delay, and a decoder that lost a frame goes on copying from an
//! excitation different from the encoder's; if the encoder has been
//! choosing such gains for a while, the difference between the two grows
//! with them. So the encoder keeps a bound on how much an error in the past
//! excitation could have been amplified by now, per stretch of forty
//! samples of the past, and while the bound for the stretch a delay reads
//! from is too large, it holds the pitch gain below one.
//!
//! The Recommendation names this procedure only in its list of software
//! files ("Pitch instability control"), and the conformance streams do not
//! reach it: on the stream made to test it the bound peaks near 8900, far
//! below the limit, so every stream encodes the same with the taming as
//! without it. What is here — the limit, the stretches of forty samples,
//! the bound's update, and the two places the gain is held (below 0.95 for
//! the adaptive codebook's gain before the fixed-codebook search, and below
//! one in the gain quantizer) — is therefore not checked against any
//! reference, and is kept so that an encoder whose pitch gain runs away is
//! held back the way the published encoder holds it back.

use super::arith::{Split, long_add, long_shift_left};

/// Samples in one stretch of the past the bound is kept for.
const STRETCH: i16 = 40;

/// The bound for a stretch at which the pitch gain is held down: 60000, in
/// Q14.
const LIMIT: i32 = 60_000 << 14;

/// One, Q14: an error that has not been amplified.
const ONE: i32 = 1 << 14;

/// The bound on the amplification of an error in the four stretches of
/// forty samples before the current subframe, newest first, Q14.
#[derive(Debug, Clone)]
pub(super) struct Taming {
    bounds: [i32; 4],
}

impl Taming {
    pub(super) const fn new() -> Self {
        Self { bounds: [ONE; 4] }
    }

    /// Whether the pitch gain must be held down for a subframe whose delay
    /// is `integer` and `fraction` thirds: whether any stretch the adaptive
    /// codebook reads from — the interpolation reaches ten samples either
    /// side of the delay — has a bound above [`LIMIT`].
    pub(super) fn needed(&self, integer: i16, fraction: i16) -> bool {
        let delay = if fraction > 0 { integer + 1 } else { integer };
        let newest = stretch((delay - STRETCH - 10).max(0));
        let oldest = stretch(delay + 8);
        (newest..=oldest)
            .filter_map(|index| self.bounds.get(index))
            .fold(-1, |most, bound| most.max(*bound))
            > LIMIT
    }

    /// After a subframe with pitch gain `gain` (Q14) and whole delay
    /// `integer`: the error in this subframe is at most one plus `gain`
    /// times the worst bound among the stretches it was copied from. A delay
    /// shorter than the subframe copies from the subframe itself, and the
    /// bound goes round twice.
    pub(super) fn update(&mut self, gain: i16, integer: i16) {
        let amplified =
            |bound: i32| long_add(ONE, long_shift_left(Split::of(bound).times(gain), 1));
        let mut worst = -1;
        if integer < STRETCH {
            let once = amplified(self.bounds.first().copied().unwrap_or(ONE));
            let twice = amplified(once);
            worst = worst.max(once).max(twice);
        } else {
            let newest = stretch(integer - STRETCH);
            let oldest = stretch(integer - 1);
            for index in newest..=oldest {
                if let Some(bound) = self.bounds.get(index) {
                    worst = worst.max(amplified(*bound));
                }
            }
        }
        self.bounds.rotate_right(1);
        if let Some(newest) = self.bounds.first_mut() {
            *newest = worst;
        }
    }
}

/// Which stretch of forty samples before the current subframe a distance
/// into the past falls in.
fn stretch(distance: i16) -> usize {
    usize::try_from(distance / STRETCH).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{LIMIT, ONE, Taming};

    #[test]
    fn a_fresh_encoder_needs_no_taming() {
        let taming = Taming::new();
        for delay in 20..=143 {
            assert!(!taming.needed(delay, 0));
        }
    }

    /// A pitch gain above one, kept up, drives the bound over the limit
    /// within a few dozen subframes, and a gain well below one brings it
    /// back.
    #[test]
    fn a_gain_above_one_is_tamed_and_a_gain_below_releases() {
        let mut taming = Taming::new();
        let mut subframes = 0;
        while !taming.needed(60, 0) {
            taming.update(19_000, 60);
            subframes += 1;
            assert!(subframes < 400);
        }
        assert!(taming.bounds.iter().any(|bound| *bound > LIMIT));
        for _ in 0..8 {
            taming.update(4_000, 60);
        }
        assert!(!taming.needed(60, 0));
        assert!(taming.bounds.iter().all(|bound| *bound >= ONE));
    }
}
