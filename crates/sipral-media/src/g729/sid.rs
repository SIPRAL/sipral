// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The energy of a SID frame (B.4.2.1): five bits on a logarithmic scale,
//! and the level each one decodes to.
//!
//! The quantizer works on `1024 log2` of the energy: below −8 dB it gives
//! the −12 dB level, above 65 dB the 66 dB one, up to 14 dB the nearest of
//! the 4 dB steps from −4, and above that the 2 dB steps from 18. The
//! boundaries and the scalings into steps are in that same unit, and each
//! one was checked against the Annex B conformance streams.

use super::arith::{
    Split, add, log2, long_add, long_shift_left, mult, mult_round, shift_left, shift_right, sub,
};
use super::tables::{SID_ENERGY_FACTOR, SID_ENERGY_HEADROOM};

/// A quantized energy: the index sent, and the level it stands for in
/// decibels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Level {
    pub(super) index: u8,
    pub(super) decibels: i16,
}

/// Equation B.15 and the quantizer: the average of the last `energies`
/// (one or two residual energies of B.4.1.2, each an upper half and the
/// power of two it is to be scaled by, newest first), scaled by `αw` and the
/// number of samples they were summed over, and quantized.
pub(super) fn quantize_residuals(energies: &[(i16, i16)]) -> Level {
    let count = energies.len().clamp(1, 2);
    let used = energies.get(..count).unwrap_or_default();
    let smallest = used.iter().map(|(_, shift)| *shift).min().unwrap_or(0);
    let headroom = SID_ENERGY_HEADROOM.get(count).copied().unwrap_or(0);
    let shift = add(smallest, sub(16, headroom));
    let mut sum = 0_i32;
    for (energy, own) in used {
        sum = long_add(
            sum,
            long_shift_left(i32::from(*energy), i32::from(sub(shift, *own))),
        );
    }
    let factor = SID_ENERGY_FACTOR.get(count).copied().unwrap_or(0);
    quantize(Split::of(sum).times(factor), shift)
}

/// B.4.5: the energy of the last good speech frame's excitation — an upper
/// half and its power of two — averaged over its eighty samples and
/// quantized, for a pause whose first SID frame was lost.
pub(super) fn quantize_excitation(energy: i16, shift: i16) -> Level {
    let whole = long_shift_left(i32::from(energy), i32::from(shift));
    let factor = SID_ENERGY_FACTOR.first().copied().unwrap_or(0);
    quantize(Split::of(whole).times(factor), 0)
}

/// `value × 2^−shift` onto the thirty-two levels.
fn quantize(value: i32, shift: i16) -> Level {
    // −8, 65 and 14 dB, and 10 and 1 dB, in units of 1/1024 of an octave
    const BOTTOM: i16 = -2721;
    const TOP: i16 = 22_111;
    const FOUR_DB_STEPS_END: i16 = 4762;
    const TEN_DB: i16 = 3401;
    const ONE_DB: i16 = 340;
    // a quarter and a half of the steps per unit, Q15 and Q17
    const PER_FOUR_DB: i16 = 24;
    const PER_TWO_DB: i16 = 193;

    let (whole, fraction) = log2(value);
    let octaves = add(
        shift_left(sub(whole, shift), 10),
        mult_round(fraction, 1024),
    );
    if octaves <= BOTTOM {
        return Level {
            index: 0,
            decibels: -12,
        };
    }
    if octaves > TOP {
        return Level {
            index: 31,
            decibels: 66,
        };
    }
    if octaves <= FOUR_DB_STEPS_END {
        let index = mult(add(octaves, TEN_DB), PER_FOUR_DB).max(1);
        return Level {
            index: u8::try_from(index).unwrap_or(1),
            decibels: sub(shift_left(index, 2), 8),
        };
    }
    let index = sub(shift_right(mult(sub(octaves, ONE_DB), PER_TWO_DB), 2), 1).max(6);
    Level {
        index: u8::try_from(index).unwrap_or(6),
        decibels: add(shift_left(index, 1), 4),
    }
}

#[cfg(test)]
mod tests {
    use super::{Level, quantize};

    /// An energy of `E` given as `E × 2^s` with `s` = 0.
    fn level_of(energy: f64) -> Level {
        #[expect(clippy::cast_possible_truncation, reason = "the test's energies fit")]
        let value = energy as i32;
        quantize(value, 0)
    }

    /// Energies at the decibel levels B.4.2.1 names come back as those
    /// levels, and the index and the level agree with `payload::Sid`'s
    /// reading of the index.
    #[test]
    fn each_level_quantizes_to_itself() {
        for (decibels, index) in [
            (-12, 0),
            (-4, 1),
            (0, 2),
            (4, 3),
            (8, 4),
            (12, 5),
            (16, 6),
            (18, 7),
            (30, 13),
            (50, 23),
            (66, 31),
        ] {
            let energy = 10_f64.powf(f64::from(decibels) / 10.0);
            // below 1 the value is scaled up by the shift instead
            let level = if energy < 1.0 {
                #[expect(clippy::cast_possible_truncation, reason = "a small energy scaled")]
                let value = (energy * 65_536.0) as i32;
                quantize(value, 16)
            } else {
                level_of(energy * 1.01)
            };
            assert_eq!(level.decibels, decibels, "{decibels} dB");
            assert_eq!(usize::from(level.index), index, "{decibels} dB");
            let sid = crate::g729::Sid::from_octets([0, level.index << 1]);
            assert_eq!(i16::from(sid.energy_db()), level.decibels);
        }
    }

    #[test]
    fn the_ends_hold() {
        // one, scaled down by 2^10: −30 dB
        assert_eq!(quantize(1, 10).index, 0);
        assert_eq!(level_of(f64::from(i32::MAX)).index, 31);
    }
}
