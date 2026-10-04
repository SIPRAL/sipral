// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The fixed codebook: four signed unit pulses on interleaved tracks
//! (§3.8, Table 7, §4.1.4).

use super::arith::{
    add, at, dot, high, long_mult, long_norm, mac, msu, mult, negate, round, shift_left,
    shift_right, sub,
};
use super::lpc::backward;

/// A pulse of `+1` and one of `−1`, in the codebook's Q13.
///
/// Not symmetric. `+1` in Q13 is 8192, which a sixteen-bit word holds, but
/// the conformance streams decode only with a positive pulse one unit
/// smaller: every stream's excitation comes out a unit off wherever a
/// positive pulse meets a gain that puts it on a rounding boundary.
const PLUS_ONE: i16 = 8191;
const MINUS_ONE: i16 = -8192;

/// Samples in a subframe.
pub(super) const SUBFRAME: usize = 40;

/// Equations 61 and 62 read backwards: three bits of position for each of
/// the first three pulses, four for the last — three of position and, below
/// them, one for which of the two tracks Table 7 gives it — and one sign bit
/// each, set for a positive pulse.
pub(super) fn decode(positions: u16, signs: u16) -> [i16; SUBFRAME] {
    let mut code = [0_i16; SUBFRAME];
    for (pulse, place) in places(positions).into_iter().enumerate() {
        let positive = (signs >> pulse) & 1 == 1;
        if let Some(slot) = code.get_mut(place) {
            *slot = if positive { PLUS_ONE } else { MINUS_ONE };
        }
    }
    code
}

/// The positions of the four pulses a codeword `C` names.
fn places(positions: u16) -> [usize; 4] {
    [
        5 * (positions & 7),
        5 * ((positions >> 3) & 7) + 1,
        5 * ((positions >> 6) & 7) + 2,
        5 * ((positions >> 10) & 7) + 3 + ((positions >> 9) & 1),
    ]
    .map(usize::from)
}

/// Equation 48: for a pitch delay shorter than the subframe, the vector is
/// passed through `1 / (1 − βz^−T)` of equation 46 within the subframe, so
/// each pulse is echoed a delay later at `β` times its height — and, for a
/// delay under half the subframe, echoed again from the echo. `beta` is the
/// last subframe's quantized pitch gain within its bounds, Q14.
pub(super) fn sharpen(code: &mut [i16; SUBFRAME], delay: i16, beta: i16) {
    let Ok(delay) = usize::try_from(delay) else {
        return;
    };
    if delay >= SUBFRAME || delay == 0 {
        return;
    }
    let factor = shift_left(beta, 1);
    for n in delay..SUBFRAME {
        let echo = mult(code.get(n - delay).copied().unwrap_or(0), factor);
        if let Some(slot) = code.get_mut(n) {
            *slot = add(*slot, echo);
        }
    }
}

/// What the fixed-codebook search chose for a subframe.
#[derive(Debug, Clone)]
pub(super) struct Choice {
    /// `C`, equation 62.
    pub(super) positions: u16,
    /// `S`, equation 61.
    pub(super) signs: u16,
    /// The codevector with its pitch sharpening, as the decoder rebuilds it.
    pub(super) code: [i16; SUBFRAME],
    /// The codevector filtered through the weighted synthesis filter, `z(n)`
    /// of equation 64, Q12.
    pub(super) filtered: [i16; SUBFRAME],
}

/// The pulse positions of the five tracks: 0, 5, …, 35 for the first, up to
/// 4, 9, …, 39 for the fifth. The fourth pulse takes either of the last two.
fn track(first: usize) -> impl Iterator<Item = usize> {
    (first..SUBFRAME).step_by(5)
}

/// Q15 fractions the energies are accumulated with: a half, a quarter, an
/// eighth, a sixteenth.
const HALF: i16 = 16_384;
const QUARTER: i16 = 8192;
const EIGHTH: i16 = 4096;
const SIXTEENTH: i16 = 2048;

/// The correlations of the impulse response, `φ(i, j)` of equation 51, with
/// the signs of `d(n)` folded in off the diagonal (equation 56), and `|d(n)|`.
struct Correlations {
    phi: [[i16; SUBFRAME]; SUBFRAME],
    magnitude: [i16; SUBFRAME],
    positive: [bool; SUBFRAME],
}

impl Correlations {
    /// `φ` of `response`, which is first scaled so that its energy nearly
    /// fills the word: halved if its upper half is above 32000, otherwise
    /// shifted up by half of its normalising shift. No conformance input
    /// tells a threshold of 32000 from one of 30000.
    ///
    /// Each `φ(i, j)` is a sum of products along a diagonal of `h`, and the
    /// sums for one diagonal grow by one product per step back from the end
    /// of the subframe, so each diagonal is walked once from the end. Each
    /// element is the upper half of its thirty-two-bit sum, truncated.
    fn new(response: &[i16; SUBFRAME], backward: &[i16; SUBFRAME]) -> Self {
        let energy = dot(0, response, response);
        let mut h = *response;
        if high(energy) > 32_000 {
            for value in &mut h {
                *value = shift_right(*value, 1);
            }
        } else {
            let shift = long_norm(energy) >> 1;
            for value in &mut h {
                *value = shift_left(*value, shift);
            }
        }

        let mut phi = [[0_i16; SUBFRAME]; SUBFRAME];
        for distance in 0..SUBFRAME {
            let mut sum = 0_i32;
            for step in 0..SUBFRAME - distance {
                sum = mac(sum, at(&h, step), at(&h, step + distance));
                let later = SUBFRAME - 1 - step;
                let earlier = later - distance;
                let value = high(sum);
                if let Some(slot) = phi.get_mut(earlier).and_then(|row| row.get_mut(later)) {
                    *slot = value;
                }
                if let Some(slot) = phi.get_mut(later).and_then(|row| row.get_mut(earlier)) {
                    *slot = value;
                }
            }
        }

        let mut magnitude = [0_i16; SUBFRAME];
        let mut positive = [true; SUBFRAME];
        for ((slot, sign), value) in magnitude.iter_mut().zip(&mut positive).zip(backward) {
            *sign = *value >= 0;
            *slot = if *sign { *value } else { negate(*value) };
        }

        // the sign of a pair of pulses: a product of like signs is taken as
        // the largest fraction below one, of unlike signs as minus one
        for (i, row) in phi.iter_mut().enumerate() {
            for (j, slot) in row.iter_mut().enumerate() {
                if i != j {
                    let alike = positive.get(i).copied().unwrap_or(true)
                        == positive.get(j).copied().unwrap_or(true);
                    *slot = mult(*slot, if alike { i16::MAX } else { i16::MIN });
                }
            }
        }
        Self {
            phi,
            magnitude,
            positive,
        }
    }

    fn phi(&self, i: usize, j: usize) -> i16 {
        self.phi
            .get(i)
            .and_then(|row| row.get(j))
            .copied()
            .unwrap_or(0)
    }

    fn d(&self, i: usize) -> i16 {
        at(&self.magnitude, i)
    }
}

/// A candidate's criterion, equation 53: `C²/E`, kept as the square of the
/// correlation and the energy, each sixteen bits, and compared by
/// cross-multiplying.
#[derive(Debug, Clone, Copy)]
struct Criterion {
    square: i16,
    energy: i16,
}

impl Criterion {
    const NONE: Self = Self {
        square: -1,
        energy: 1,
    };

    /// Whether `square/energy` is strictly above this one's.
    fn beaten_by(self, square: i16, energy: i16) -> bool {
        msu(long_mult(self.energy, square), self.square, energy) > 0
    }
}

/// A.3.8.1: the depth-first search for the four pulses.
///
/// The four pulses are placed two at a time. The fourth pulse's track is
/// tried both ways, and for each, twice over: once starting from the third
/// pulse and the fourth, and once starting from the fourth and the first.
/// Each start pairs the two positions of its first track with the largest
/// `|d(n)|` with every position of its second track, and keeps the best
/// pair; the two remaining pulses are then searched over all their
/// positions together, with the pair fixed. The best of the four
/// candidates is the codevector.
///
/// The criterion of equation 53 is kept at a scale that differs per stage:
/// a pair's energy is a quarter of `E`, a full candidate's a sixteenth, and
/// the energies are rounded to sixteen bits where each stage compares them.
///
/// `response` is `h(n)` of the subframe; it is sharpened here (equation 49),
/// and the pulses are chosen on the target `target`, `x′(n)` of equation 50.
pub(super) fn search(
    target: &[i16; SUBFRAME],
    response: &[i16; SUBFRAME],
    delay: i16,
    beta: i16,
) -> Choice {
    let mut h = *response;
    sharpen(&mut h, delay, beta);
    let backward = backward(&h, target);
    let correlations = Correlations::new(&h, &backward);

    let mut best = Criterion::NONE;
    let mut pulses = [0, 1, 2, 3];
    for fourth in [3, 4] {
        // the third and fourth pulses first, then the first and second
        let (third_at, fourth_at, sum, energy) = best_pair(&correlations, 2, fourth);
        let (criterion, first_at, second_at) =
            best_completion(&correlations, (third_at, fourth_at), sum, energy, 0, 1);
        if best.beaten_by(criterion.square, criterion.energy) {
            best = criterion;
            pulses = [first_at, second_at, third_at, fourth_at];
        }

        // the fourth and first pulses first, then the second and third
        let (fourth_at, first_at, sum, energy) = best_pair(&correlations, fourth, 0);
        let (criterion, second_at, third_at) =
            best_completion(&correlations, (fourth_at, first_at), sum, energy, 1, 2);
        if best.beaten_by(criterion.square, criterion.energy) {
            best = criterion;
            pulses = [first_at, second_at, third_at, fourth_at];
        }
    }

    let mut signs = 0_u16;
    for (index, place) in pulses.iter().enumerate() {
        if correlations.positive.get(*place).copied().unwrap_or(true) {
            signs |= 1 << index;
        }
    }
    let [first, second, third, fourth] = pulses.map(|place| u16::try_from(place).unwrap_or(0));
    let positions = first / 5
        + ((second / 5) << 3)
        + ((third / 5) << 6)
        + ((2 * (fourth / 5) + (fourth % 5).saturating_sub(3)) << 9);
    Choice::new(positions, signs, response, delay, beta)
}

impl Choice {
    /// The codevector a codeword pair `C` and `S` names in a subframe with
    /// impulse response `response`, pitch delay `delay` and sharpening
    /// `beta`, and its filtered form: the response, sharpened as in the
    /// search, added in at each pulse with the pulse's sign.
    pub(super) fn new(
        positions: u16,
        signs: u16,
        response: &[i16; SUBFRAME],
        delay: i16,
        beta: i16,
    ) -> Self {
        let mut h = *response;
        sharpen(&mut h, delay, beta);
        let mut filtered = [0_i16; SUBFRAME];
        for (index, place) in places(positions).iter().enumerate() {
            let positive = (signs >> index) & 1 == 1;
            for (slot, value) in filtered.iter_mut().skip(*place).zip(h) {
                *slot = if positive {
                    add(*slot, value)
                } else {
                    sub(*slot, value)
                };
            }
        }
        let mut code = decode(positions, signs);
        sharpen(&mut code, delay, beta);
        Self {
            positions,
            signs,
            code,
            filtered,
        }
    }
}

/// The first stage of a depth-first search: the lead pulse at either of the
/// two positions of track `lead` with the largest `|d(n)|`, the other at
/// every position of track `other`. Returns the best pair, its correlation
/// and its energy, a quarter of `E`, rounded.
fn best_pair(correlations: &Correlations, lead: usize, other: usize) -> (usize, usize, i16, i16) {
    let mut best = Criterion::NONE;
    let mut chosen = (0, 0, 0, 0);
    let mut previous = None;
    for _ in 0..2 {
        let mut largest = -1;
        let mut start = 0;
        for place in track(lead) {
            let value = correlations.d(place);
            if value > largest && previous != Some(place) {
                largest = value;
                start = place;
            }
        }
        previous = Some(start);
        let sum = correlations.d(start);
        let energy = long_mult(correlations.phi(start, start), QUARTER);
        for place in track(other) {
            let pair_sum = add(sum, correlations.d(place));
            let pair_energy = mac(
                mac(energy, correlations.phi(start, place), HALF),
                correlations.phi(place, place),
                QUARTER,
            );
            let square = mult(pair_sum, pair_sum);
            let rounded = round(pair_energy);
            if best.beaten_by(square, rounded) {
                best = Criterion {
                    square,
                    energy: rounded,
                };
                chosen = (start, place, pair_sum, rounded);
            }
        }
    }
    chosen
}

/// The second stage: with the pair fixed, every position of track `first`
/// with every position of track `second`. What the pair adds to each
/// position of `second` is worked out once beforehand. Returns the criterion
/// of the best candidate and the two positions.
fn best_completion(
    correlations: &Correlations,
    (a, b): (usize, usize),
    sum: i16,
    energy: i16,
    first: usize,
    second: usize,
) -> (Criterion, usize, usize) {
    let base = long_mult(energy, QUARTER);
    let mut partial = [0_i16; 8];
    for (slot, place) in partial.iter_mut().zip(track(second)) {
        let value = long_mult(correlations.phi(a, place), QUARTER);
        let value = mac(value, correlations.phi(b, place), QUARTER);
        *slot = round(mac(value, correlations.phi(place, place), EIGHTH));
    }

    let mut best = Criterion::NONE;
    let mut chosen = (0, 0);
    for one in track(first) {
        let one_sum = add(sum, correlations.d(one));
        let mut one_energy = mac(base, correlations.phi(one, a), EIGHTH);
        one_energy = mac(one_energy, correlations.phi(one, b), EIGHTH);
        one_energy = mac(one_energy, correlations.phi(one, one), SIXTEENTH);
        for (other, extra) in track(second).zip(partial) {
            let total_sum = add(one_sum, correlations.d(other));
            let total_energy = mac(
                mac(one_energy, correlations.phi(one, other), EIGHTH),
                extra,
                HALF,
            );
            let square = mult(total_sum, total_sum);
            let rounded = round(total_energy);
            if best.beaten_by(square, rounded) {
                best = Criterion {
                    square,
                    energy: rounded,
                };
                chosen = (one, other);
            }
        }
    }
    (best, chosen.0, chosen.1)
}

#[cfg(test)]
mod tests {
    use super::{Choice, MINUS_ONE, PLUS_ONE, decode, search, sharpen};

    /// An impulse response that is a single sample, so that the target is
    /// the codevector itself: the search finds the four pulses it was
    /// given, signs and all, and its filtered vector is that target.
    #[test]
    fn the_search_finds_a_codevector_that_is_its_own_target() {
        let mut response = [0_i16; 40];
        response[0] = 4096;
        let mut target = [0_i16; 40];
        for (place, value) in [(10, 3000), (21, -3000), (7, 3000), (33, -3000)] {
            target[place] = value;
        }
        let choice = search(&target, &response, 60, 3277);
        let expected = Choice::new(choice.positions, choice.signs, &response, 60, 3277);
        assert_eq!(choice.filtered, expected.filtered);
        let code = decode(choice.positions, choice.signs);
        for (place, value) in [
            (10, PLUS_ONE),
            (21, MINUS_ONE),
            (7, PLUS_ONE),
            (33, MINUS_ONE),
        ] {
            assert_eq!(code[place], value, "{place}");
        }
        assert_eq!(choice.filtered[10], 4096);
        assert_eq!(choice.filtered[21], -4096);
    }

    #[test]
    fn the_pulses_land_on_their_tracks() {
        // every position index zero, all signs negative: pulses at 0, 1, 2, 3
        let code = decode(0, 0);
        assert_eq!(&code[..5], &[MINUS_ONE, MINUS_ONE, MINUS_ONE, MINUS_ONE, 0]);
        // the fourth pulse's extra bit moves it to the track starting at 4
        let code = decode(1 << 9, 0b1000);
        assert_eq!(code[4], PLUS_ONE);
        assert_eq!(code[3], 0);
        // the largest indices reach the end of each track
        let code = decode(0x1fff, 0b1111);
        for place in [35, 36, 37, 39] {
            assert_eq!(code[place], PLUS_ONE, "position {place}");
        }
        // equation 62's example weights: C = m0/5 + 8 m1/5 + 64 m2/5 + 512 (2 m3/5 + jx)
        let code = decode(3 + 8 * 2 + 64 * 7 + 512 * (2 * 5 + 1), 0b0101);
        assert_eq!(code[15], PLUS_ONE);
        assert_eq!(code[11], MINUS_ONE);
        assert_eq!(code[37], PLUS_ONE);
        assert_eq!(code[29], MINUS_ONE);
    }

    #[test]
    fn sharpening_echoes_each_pulse_one_delay_later() {
        let mut code = decode(0, 0b0001);
        // 0.5 in Q14
        sharpen(&mut code, 25, 8192);
        assert_eq!(code[0], PLUS_ONE);
        assert_eq!(code[25], 4095, "half of 8191, rounded down");
        // a delay of a whole subframe or more leaves the vector alone
        let mut code = decode(0, 0b0001);
        sharpen(&mut code, 40, 8192);
        assert_eq!(code.iter().filter(|value| **value != 0).count(), 4);
    }

    /// Below half the subframe the filter's recursion shows: the echo is
    /// echoed.
    #[test]
    fn a_short_delay_echoes_the_echo() {
        let mut code = [0_i16; 40];
        code[0] = PLUS_ONE;
        sharpen(&mut code, 15, 8192);
        assert_eq!(code[15], 4095);
        assert_eq!(code[30], 2047);
    }
}
