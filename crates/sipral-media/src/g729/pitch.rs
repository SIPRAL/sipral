// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The adaptive codebook: the delay a subframe's index names, and the past
//! excitation read back at that delay (§3.7, §4.1.3).

use super::arith::{
    Split, abs, add, at, divide, dot, dot_checked, inverse_sqrt, long_norm, long_shift_left, low,
    mac, mac_checked, mult, round, shift_left, shift_right, shift_right_signed, sub, to_word,
};
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

impl Delay {
    /// Equation 41: `P1` for the first subframe's delay.
    pub(super) fn first_index(self) -> u16 {
        let index = if self.integer <= 85 {
            3 * self.integer - 58 + self.fraction
        } else {
            self.integer + 112
        };
        u16::try_from(index).unwrap_or(0)
    }

    /// Equation 42: `P2` for the second subframe's delay, relative to the
    /// first subframe's whole delay.
    pub(super) fn second_index(self, first: i16) -> u16 {
        let index = 3 * (self.integer - search_floor(first)) + 2 + self.fraction;
        u16::try_from(index).unwrap_or(0)
    }
}

/// §3.7: the whole delays the first subframe's closed-loop search tries,
/// three either side of the open-loop estimate and seven in all, held inside
/// the codebook's range.
pub(super) fn first_range(open_loop: i16) -> (i16, i16) {
    let lowest = (open_loop - 3).max(SHORTEST);
    if lowest + 6 > LONGEST {
        (LONGEST - 6, LONGEST)
    } else {
        (lowest, lowest + 6)
    }
}

/// §3.7: the whole delays the second subframe's search tries, `tmin` to
/// `tmax` around the first subframe's whole delay.
pub(super) fn second_range(first: i16) -> (i16, i16) {
    let lowest = search_floor(first);
    (lowest, lowest + 9)
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

/// Samples of the weighted speech kept before the frame for the open-loop
/// search: the longest delay.
pub(super) const OPEN_LOOP_PAST: usize = LONGEST as usize;

/// A.3.4: the open-loop pitch estimate `Top` of a frame of weighted speech.
///
/// `signal` holds [`OPEN_LOOP_PAST`] samples before the frame, then its
/// eighty. Correlations (equation A.4) are taken over the even samples only.
/// Each of the three ranges — 20 to 39, 40 to 79, 80 to 143 — keeps its
/// largest, the first of equal ones; in the third only the even delays are
/// tried first, then the delay one above the best and the one below. Each
/// maximum is normalised by the energy of the signal at its delay (equation
/// A.5).
///
/// A delay in a lower range is favoured over one in a higher range if the
/// higher is close to twice or three times it (A.3.4 says only that much):
/// within five of twice, or within seven of three times, the lower range's
/// normalised correlation is raised by a quarter of the higher's (for the
/// second range against the third) or a fifth (for the first against the
/// second). Then the lower range wins unless the higher's is strictly
/// larger. The conformance streams fix each of those four numbers: with
/// four and six, six and eight, an eighth or a fifth for the quarter, or a
/// quarter for the fifth, four of the seven inputs encode differently.
///
/// The signal is scaled first so that the sums neither overflow nor lose
/// their precision: down by eight if its energy leaves the word, up by eight
/// if its energy is below `2^20` (with `2^19` or `2^21` the speech input
/// encodes differently).
pub(super) fn open_loop(signal: &[i16; OPEN_LOOP_PAST + 80]) -> i16 {
    const QUIET: i32 = 1 << 20;
    // a fifth, Q15
    const FIFTH: i16 = 6554;
    let (energy, overflowed) =
        signal
            .iter()
            .step_by(2)
            .fold((0_i32, false), |(sum, flag), value| {
                let (next, held) = mac_checked(sum, *value, *value);
                (next, flag || held)
            });
    let mut scaled = *signal;
    if overflowed {
        for slot in &mut scaled {
            *slot = shift_right(*slot, 3);
        }
    } else if energy < QUIET {
        for slot in &mut scaled {
            *slot = shift_left(*slot, 3);
        }
    }

    let correlation = |delay: i16| -> i32 {
        let back = usize::try_from(delay).unwrap_or(0);
        (0..80).step_by(2).fold(0_i32, |sum, n| {
            let now = at(&scaled, OPEN_LOOP_PAST + n);
            let then = at(&scaled, OPEN_LOOP_PAST + n - back);
            mac(sum, now, then)
        })
    };
    let normalised = |delay: i16, correlation: i32| -> i16 {
        let back = usize::try_from(delay).unwrap_or(0);
        let energy = (0..80).step_by(2).fold(0_i32, |sum, n| {
            let then = at(&scaled, OPEN_LOOP_PAST + n - back);
            mac(sum, then, then)
        });
        let inverse = inverse_sqrt(energy);
        low(Split::of(correlation).times_split(Split::of(inverse)))
    };
    let best_of = |delays: &mut dyn Iterator<Item = i16>| -> (i16, i32) {
        let mut best = (0, i32::MIN);
        for delay in delays {
            let value = correlation(delay);
            if value > best.1 {
                best = (delay, value);
            }
        }
        best
    };

    let (first_delay, first_max) = best_of(&mut (20..40));
    let (second_delay, second_max) = best_of(&mut (40..80));
    let (mut third_delay, mut third_max) = best_of(&mut (80..143).step_by(2));
    let centre = third_delay;
    for delay in [centre + 1, centre - 1] {
        let value = correlation(delay);
        if value > third_max {
            third_max = value;
            third_delay = delay;
        }
    }

    let mut first = normalised(first_delay, first_max);
    let mut second = normalised(second_delay, second_max);
    let third = normalised(third_delay, third_max);

    let twice = sub(shift_left(second_delay, 1), third_delay);
    if abs(twice) < 5 {
        second = add(second, shift_right(third, 2));
    }
    if abs(add(twice, second_delay)) < 7 {
        second = add(second, shift_right(third, 2));
    }
    let twice = sub(shift_left(first_delay, 1), second_delay);
    if abs(twice) < 5 {
        first = add(first, mult(second, FIFTH));
    }
    if abs(add(twice, first_delay)) < 7 {
        first = add(first, mult(second, FIFTH));
    }

    let (mut best, mut best_delay) = (first, first_delay);
    if best < second {
        best = second;
        best_delay = second_delay;
    }
    if best < third {
        best_delay = third_delay;
    }
    best_delay
}

/// A.3.7: the closed-loop search for a subframe's delay, between `lowest`
/// and `highest` whole samples, by the correlation of equation A.7 alone.
///
/// `backward` is the target filtered backwards through the impulse response
/// (`xb(n)`). The past excitation at each whole delay is correlated with it
/// — for a delay shorter than the subframe the samples not yet known are
/// the LP residual, which the caller has put in their place — and the first
/// of equal maxima kept. Then the fractions −1/3, 0 and +1/3 around it are
/// tried on the excitation interpolated by `b30` (equation A.8), 0 first and
/// each of the other two only if strictly better, except in the first
/// subframe beyond 84, where the codebook has no fractions.
///
/// Leaves the chosen delay's adaptive-codebook vector in `excitation` from
/// `start`.
pub(super) fn closed_loop(
    excitation: &mut [i16],
    start: usize,
    backward: &[i16; 40],
    (lowest, highest): (i16, i16),
    first_subframe: bool,
) -> Delay {
    let mut best = lowest;
    let mut best_correlation = i32::MIN;
    for delay in lowest..=highest {
        let from = start - usize::try_from(delay).unwrap_or(0);
        let past = excitation.get(from..from + 40).unwrap_or_default();
        let value = dot(0, backward, past);
        if value > best_correlation {
            best_correlation = value;
            best = delay;
        }
    }

    let score = |excitation: &mut [i16], fraction: i16| -> i32 {
        interpolate(
            excitation,
            start,
            Delay {
                integer: best,
                fraction,
            },
        );
        dot(
            0,
            backward,
            excitation.get(start..start + 40).unwrap_or_default(),
        )
    };
    let mut chosen = Delay::whole(best);
    let mut most = score(excitation, 0);
    if first_subframe && best > 84 {
        return chosen;
    }
    for fraction in [-1, 1] {
        let value = score(excitation, fraction);
        if value > most {
            most = value;
            chosen.fraction = fraction;
        }
    }
    if chosen.fraction != 1 {
        interpolate(excitation, start, chosen);
    }
    chosen
}

/// Equation 43: the adaptive-codebook gain, Q14, and the two correlations it
/// came from, which the gain quantizer uses again.
///
/// Each correlation is normalised and rounded to sixteen bits, its exponent
/// kept. `y·y` starts from one so that it is never zero. If either sum
/// leaves the word, it is taken again over `y` divided by four, and its
/// exponent says so. A gain whose correlation `x·y` is not positive is zero;
/// otherwise the quotient is bounded by 1.2.
pub(super) fn gain(target: &[i16; 40], filtered: &[i16; 40]) -> (i16, Correlations) {
    // 1.2, Q14
    const HIGHEST_GAIN: i16 = 19_661;
    let mut quartered = [0_i16; 40];
    for (slot, value) in quartered.iter_mut().zip(filtered) {
        *slot = shift_right(*value, 2);
    }
    let normalise = |sum: i32| -> (i16, i16) {
        let shift = long_norm(sum);
        (
            round(long_shift_left(sum, i32::try_from(shift).unwrap_or(0))),
            to_word(shift),
        )
    };

    let (energy, overflowed) = dot_checked(1, filtered, filtered);
    let (energy, energy_shift) = if overflowed {
        let (value, shift) = normalise(dot(1, &quartered, &quartered));
        (value, sub(shift, 4))
    } else {
        normalise(energy)
    };
    let (cross, overflowed) = dot_checked(0, target, filtered);
    let (cross, cross_shift) = if overflowed {
        let (value, shift) = normalise(dot(0, target, &quartered));
        (value, sub(shift, 2))
    } else {
        normalise(cross)
    };
    let mut correlations = Correlations {
        energy,
        energy_exponent: sub(15, energy_shift),
        cross,
        cross_exponent: sub(15, cross_shift),
    };
    if cross < 4 {
        // a correlation that is not positive is reported to the gain
        // quantizer as the smallest the format holds, a unit at the bottom
        // of thirty-one bits; the conformance streams' silent first
        // subframes quantize their gains only that way
        correlations.cross_exponent = -15;
        return (0, correlations);
    }
    let quotient = divide(shift_right(cross, 1), energy);
    let gain = shift_right_signed(quotient, sub(cross_shift, energy_shift));
    (gain.min(HIGHEST_GAIN), correlations)
}

/// `y·y` and `x·y` of equation 43, each a normalised mantissa and the power
/// of two it stands for: the value is `mantissa × 2^(exponent − 15)`.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Correlations {
    pub(super) energy: i16,
    pub(super) energy_exponent: i16,
    pub(super) cross: i16,
    pub(super) cross_exponent: i16,
}

#[cfg(test)]
mod tests {
    use super::{
        Correlations, Delay, OPEN_LOOP_PAST, first_range, gain, interpolate, open_loop,
        second_range,
    };
    use crate::g729::tables::INTERPOLATION_B30;

    /// Every delay the encoder can send comes back from its codeword.
    #[test]
    fn the_delay_codewords_invert_the_decoding() {
        for index in 0..=255_u16 {
            let delay = Delay::first(index);
            // the encoder never sends 84 and two thirds; its codeword is 196
            assert_eq!(delay.first_index(), index);
        }
        for first in [20, 21, 60, 139, 143] {
            for index in 0..32_u16 {
                let delay = Delay::second(index, first);
                assert_eq!(delay.second_index(first), index, "{first} {index}");
            }
        }
        assert_eq!(first_range(21), (20, 26));
        assert_eq!(first_range(142), (137, 143));
        assert_eq!(first_range(60), (57, 63));
        assert_eq!(second_range(143), (134, 143));
    }

    /// A weighted speech signal repeating every 57 samples is found to have
    /// that period, and not a multiple of it.
    #[test]
    fn the_open_loop_search_finds_the_period() {
        let signal: [i16; OPEN_LOOP_PAST + 80] = core::array::from_fn(|n| {
            let phase = f64::from(u16::try_from(n % 57).unwrap()) / 57.0;
            #[expect(clippy::cast_possible_truncation, reason = "bounded by the amplitude")]
            let sample = (3000.0 * (core::f64::consts::TAU * phase).sin()
                + 1500.0 * (2.0 * core::f64::consts::TAU * phase).sin())
                as i16;
            sample
        });
        let found = open_loop(&signal);
        assert!((56..=58).contains(&found), "{found}");
    }

    /// The gain is the least-squares one, bounded by 1.2, and nothing for a
    /// target that does not correlate.
    #[test]
    fn the_pitch_gain_is_x_y_over_y_y() {
        let filtered: [i16; 40] = core::array::from_fn(|n| i16::try_from(n).unwrap() * 50 - 1000);
        let half: [i16; 40] = core::array::from_fn(|n| filtered[n] / 2);
        let (g, correlations): (i16, Correlations) = gain(&half, &filtered);
        assert!((i32::from(g) - 8192).abs() < 40, "{g}");
        assert!(correlations.energy > 0);
        let double: [i16; 40] = core::array::from_fn(|n| filtered[n] * 2);
        assert_eq!(gain(&double, &filtered).0, 19_661);
        let opposite: [i16; 40] = core::array::from_fn(|n| -filtered[n]);
        assert_eq!(gain(&opposite, &filtered).0, 0);
    }

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
