// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The adaptive codebook: the delay a subframe's index names, and the past
//! excitation read back at that delay (§3.7, §4.1.3).

use super::arith::{mac, round};
use super::tables::INTERPOLATION_B30;

/// The shortest whole delay the first subframe can name, and the longest any
/// subframe can.
pub(super) const SHORTEST: i16 = 20;
pub(super) const LONGEST: i16 = 143;

/// A delay in thirds of a sample: `integer + fraction / 3`, with the
/// fraction −1, 0 or 1 (§3.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Delay {
    pub(super) integer: i16,
    pub(super) fraction: i16,
}

impl Delay {
    /// A whole number of samples, which is what concealment uses.
    pub(super) const fn whole(integer: i16) -> Self {
        Self {
            integer,
            fraction: 0,
        }
    }

    /// §4.1.3: `P1` to `T1`. Below 197 the index counts thirds from 19⅓;
    /// from 197 up it counts whole samples from 85.
    pub(super) fn first(index: u16) -> Self {
        let index = i16::try_from(index & 0xff).unwrap_or(0);
        if index < 197 {
            let integer = (index + 2) / 3 + 19;
            Self {
                integer,
                fraction: index - 3 * integer + 58,
            }
        } else {
            Self::whole(index - 112)
        }
    }

    /// §4.1.3: `P2` to `T2`, in thirds around the first subframe's whole
    /// delay.
    pub(super) fn second(index: u16, first: i16) -> Self {
        let index = i16::try_from(index & 0x1f).unwrap_or(0);
        let lowest = search_floor(first);
        let steps = (index + 2) / 3 - 1;
        Self {
            integer: steps + lowest,
            fraction: index - 2 - 3 * steps,
        }
    }
}

/// `tmin` of §4.1.3: five below the first subframe's whole delay, held
/// inside the range with room for nine above it.
fn search_floor(first: i16) -> i16 {
    let lowest = (first - 5).max(SHORTEST);
    if lowest + 9 > LONGEST {
        LONGEST - 9
    } else {
        lowest
    }
}

/// Equation 40: write `v(n)`, the past excitation interpolated at `delay`,
/// into the forty samples of `excitation` that start at `start`.
///
/// In equation 40 the sample read is `u(n − k + t/3)`: the nearest older
/// sample `u(n − k)` is `t/3` away and weighs `b30(t + 3i)`, the nearest
/// newer one `u(n − k + 1)` is `(3 − t)/3` away and weighs `b30(3 − t + 3i)`.
/// So a delay of `T + 1/3` is `k = T + 1` with `t = 2`, a delay of `T − 1/3`
/// is `k = T` with `t = 1`, and a whole delay is `t = 0`.
///
/// The samples are produced in order and each is written before the next is
/// computed, so a delay shorter than the subframe reads back the vector it
/// is building, which is how the codebook repeats a pitch pulse.
pub(super) fn interpolate(excitation: &mut [i16], start: usize, delay: Delay) {
    let (back, phase) = match delay.fraction {
        1 => (delay.integer + 1, 2_usize),
        -1 => (delay.integer, 1_usize),
        _ => (delay.integer, 0_usize),
    };
    let back = usize::try_from(back).unwrap_or(0);
    for n in start..start + 40 {
        let Some(newest_older) = n.checked_sub(back) else {
            continue;
        };
        let mut sum = 0_i32;
        for i in 0..10 {
            let older = newest_older
                .checked_sub(i)
                .and_then(|at| excitation.get(at))
                .copied()
                .unwrap_or(0);
            let newer = excitation.get(newest_older + 1 + i).copied().unwrap_or(0);
            let older_tap = INTERPOLATION_B30.get(phase + 3 * i).copied().unwrap_or(0);
            let newer_tap = INTERPOLATION_B30
                .get(3 - phase + 3 * i)
                .copied()
                .unwrap_or(0);
            sum = mac(sum, older, older_tap);
            sum = mac(sum, newer, newer_tap);
        }
        if let Some(slot) = excitation.get_mut(n) {
            *slot = round(sum);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Delay, interpolate};
    use crate::g729::tables::INTERPOLATION_B30;

    #[test]
    fn the_first_index_counts_thirds_then_whole_samples() {
        // index 0 is 19 and a third
        assert_eq!(
            Delay::first(0),
            Delay {
                integer: 19,
                fraction: 1
            }
        );
        assert_eq!(
            Delay::first(1),
            Delay {
                integer: 20,
                fraction: -1
            }
        );
        assert_eq!(
            Delay::first(2),
            Delay {
                integer: 20,
                fraction: 0
            }
        );
        assert_eq!(
            Delay::first(3),
            Delay {
                integer: 20,
                fraction: 1
            }
        );
        // the last fractional delay is 84 and two thirds, written 85 − 1/3
        assert_eq!(
            Delay::first(196),
            Delay {
                integer: 85,
                fraction: -1
            }
        );
        assert_eq!(Delay::first(197), Delay::whole(85));
        assert_eq!(Delay::first(255), Delay::whole(143));
    }

    #[test]
    fn the_second_index_is_relative_to_the_first() {
        // tmin is five below the first delay, and index 2 is tmin itself
        assert_eq!(
            Delay::second(2, 60),
            Delay {
                integer: 55,
                fraction: 0
            }
        );
        assert_eq!(
            Delay::second(0, 60),
            Delay {
                integer: 54,
                fraction: 1
            }
        );
        // and index 31 is nine and two thirds above it
        assert_eq!(
            Delay::second(31, 60),
            Delay {
                integer: 65,
                fraction: -1
            }
        );
        // near the ends of the range tmin is held so the nine above still fit
        assert_eq!(Delay::second(2, 20).integer, 20);
        assert_eq!(Delay::second(2, 143).integer, 134);
    }

    /// A single pulse in the past, read at a whole delay, comes back as the
    /// filter's own phase-zero taps around the delayed position.
    #[test]
    fn a_whole_delay_reads_the_pulse_through_the_phase_zero_taps() {
        let mut excitation = vec![0_i16; 234];
        excitation[100] = 16_384;
        interpolate(&mut excitation, 154, Delay::whole(54));
        // v(154) reads u(100) through b30(0); v(155), a sample on, reads it
        // as its second older sample, through b30(3)
        let half = |tap: i16| i16::try_from((i32::from(tap) * 16_384 * 2 + 0x8000) >> 16).unwrap();
        assert_eq!(excitation[154], half(INTERPOLATION_B30[0]));
        assert_eq!(excitation[155], half(INTERPOLATION_B30[3]));
        assert_eq!(excitation[153], 0, "the past is left alone");
    }

    /// A delay a third of a sample longer than a whole one looks between the
    /// two samples, closer to the older.
    #[test]
    fn a_fractional_delay_reads_between_samples() {
        let mut excitation = vec![0_i16; 234];
        excitation[100] = 16_384;
        interpolate(
            &mut excitation,
            154,
            Delay {
                integer: 54,
                fraction: 1,
            },
        );
        // k = 55, t = 2: v(155) reads u(100) as its nearest older sample,
        // two thirds away; v(154) reads it as its nearest newer one, a third
        // away, and weighs it more
        let half = |tap: i16| i16::try_from((i32::from(tap) * 16_384 * 2 + 0x8000) >> 16).unwrap();
        assert_eq!(excitation[155], half(INTERPOLATION_B30[2]));
        assert_eq!(excitation[154], half(INTERPOLATION_B30[1]));
        assert!(excitation[154] > excitation[155]);
    }
}
