// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The short-term filter, from four indices to two sets of LP coefficients
//! (§3.2.4 to §3.2.6, §4.1.1, §4.4.1).
//!
//! The indices name a two-stage vector in the LSF domain; the vector is
//! spaced out so that no two neighbours come too close, weighed against what
//! a switched MA predictor expects from the last four frames, checked for
//! stability, and turned into cosines. The first subframe uses the midpoint
//! of these cosines and the last frame's, the second uses them as they are,
//! and each set is expanded into the ten coefficients of `A(z)`.
//!
//! Formats: LSFs are Q13 radians, so π is 25736; LSPs (the cosines) are Q15;
//! LP coefficients are Q12, so `a0 = 1` is 4096; the polynomials `F1` and
//! `F2` are Q24 in thirty-two bits.

use super::arith::{
    Split, add, high, long_add, long_mult, long_shift_left, long_shift_right,
    long_shift_right_round, long_sub, low, mac, msu, mult, shift_right, sub,
};
use super::tables::{
    COSINE, COSINE_SLOPE, FIRST_STAGE, INITIAL_LSF, MA_CURRENT_WEIGHT, MA_CURRENT_WEIGHT_INVERSE,
    MA_PREDICTOR, SECOND_STAGE_HIGH, SECOND_STAGE_LOW,
};

/// Ten LSFs, or ten LSPs.
pub(super) type Vector = [i16; 10];

/// The coefficients of `A(z)`, `a0` first.
pub(super) type Coefficients = [i16; 11];

/// `J` for the first spacing pass, 0.0012 in Q13.
const FIRST_GAP: i16 = 10;

/// `J` for the second, 0.0006.
const SECOND_GAP: i16 = 5;

/// The stability check's floor for `ω̂1`, 0.005, as the nearest Q13 value.
/// No conformance stream reaches it, so 40 would decode them all as well.
const LOWEST: i16 = 41;

/// Its minimum distance between neighbours. The text prints 0.0391, whose
/// nearest Q13 value is 320; the conformance streams need 321, 0.03918, and
/// six of the ten decode differently with 320.
const MINIMUM_DISTANCE: i16 = 321;

/// Its ceiling for `ω̂10`, 3.135, as the nearest Q13 value. No conformance
/// stream reaches it either.
const HIGHEST: i16 = 25_682;

/// `2/π` in Q15. An LSF in Q13 radians times this is its position along the
/// sixty-four segments of [`COSINE`], in Q8.
const TO_TABLE: i16 = 20_861;

/// The LSF quantizer's memory: the last four frames' quantizer outputs, the
/// last LSFs decoded, and which predictor produced them.
#[derive(Debug, Clone)]
pub(super) struct Quantizer {
    /// `l̂(m−1)` to `l̂(m−4)`, newest first.
    history: [Vector; 4],
    /// `ω̂` of the last frame, for an erasure to repeat.
    last: Vector,
    /// `L0` of the last good frame, for an erasure to predict with.
    predictor: usize,
}

impl Quantizer {
    /// Table 9: every `l̂` of the past is `iπ/11`.
    pub(super) const fn new() -> Self {
        Self {
            history: [INITIAL_LSF; 4],
            last: INITIAL_LSF,
            predictor: 0,
        }
    }

    /// Equations 19 and 20 and the stability check: the LSFs a good frame's
    /// indices name.
    pub(super) fn decode(
        &mut self,
        predictor: u16,
        first: u16,
        second_low: u16,
        second_high: u16,
    ) -> Vector {
        let predictor = usize::from(predictor & 1);
        let first = FIRST_STAGE
            .get(usize::from(first))
            .copied()
            .unwrap_or_default();
        let lower = SECOND_STAGE_LOW
            .get(usize::from(second_low))
            .copied()
            .unwrap_or_default();
        let upper = SECOND_STAGE_HIGH
            .get(usize::from(second_high))
            .copied()
            .unwrap_or_default();

        // equation 19
        let mut output: Vector = [0; 10];
        let corrections = lower.iter().chain(upper.iter());
        for ((slot, base), correction) in output.iter_mut().zip(first).zip(corrections) {
            *slot = add(base, *correction);
        }
        space(&mut output, FIRST_GAP);
        space(&mut output, SECOND_GAP);

        let mut lsf = self.predict(&output, predictor);
        self.remember(output);
        stabilise(&mut lsf);
        self.last = lsf;
        self.predictor = predictor;
        lsf
    }

    /// §4.4.1: an erased frame repeats the last LSFs, and the quantizer
    /// output that would have produced them under the last good frame's
    /// predictor (equation 92) takes the lost one's place in the memory.
    pub(super) fn conceal(&mut self) -> Vector {
        let taps = MA_PREDICTOR
            .get(self.predictor)
            .copied()
            .unwrap_or_default();
        let inverse = MA_CURRENT_WEIGHT_INVERSE
            .get(self.predictor)
            .copied()
            .unwrap_or_default();
        let mut output: Vector = [0; 10];
        for (index, slot) in output.iter_mut().enumerate() {
            let mut sum = i32::from(self.last.get(index).copied().unwrap_or(0)) << 16;
            for (past, row) in self.history.iter().zip(taps) {
                sum = msu(
                    sum,
                    row.get(index).copied().unwrap_or(0),
                    past.get(index).copied().unwrap_or(0),
                );
            }
            // the remainder in Q13 times the Q12 reciprocal is Q26; three more
            // bits bring the upper half back to Q13
            let remainder = high(sum);
            let scaled = long_mult(remainder, inverse.get(index).copied().unwrap_or(0));
            *slot = high(long_shift_left(scaled, 3));
        }
        self.remember(output);
        self.last
    }

    /// Equation 20: `(1 − Σ p̂) l̂(m) + Σ p̂ l̂(m−k)`, a Q13 vector times Q15
    /// weights, summed in thirty-two bits and taken back to Q13 from the
    /// upper half.
    fn predict(&self, output: &Vector, predictor: usize) -> Vector {
        let taps = MA_PREDICTOR.get(predictor).copied().unwrap_or_default();
        let current = MA_CURRENT_WEIGHT
            .get(predictor)
            .copied()
            .unwrap_or_default();
        let mut lsf: Vector = [0; 10];
        for (index, slot) in lsf.iter_mut().enumerate() {
            let mut sum = long_mult(
                output.get(index).copied().unwrap_or(0),
                current.get(index).copied().unwrap_or(0),
            );
            for (past, row) in self.history.iter().zip(taps) {
                sum = mac(
                    sum,
                    row.get(index).copied().unwrap_or(0),
                    past.get(index).copied().unwrap_or(0),
                );
            }
            *slot = high(sum);
        }
        lsf
    }

    fn remember(&mut self, output: Vector) {
        self.history.rotate_right(1);
        if let Some(newest) = self.history.first_mut() {
            *newest = output;
        }
    }
}

/// §3.2.4's rearrangement: wherever a coefficient comes within `gap` of the
/// one above it, the two are pushed apart about their midpoint by half of
/// the shortfall each.
fn space(lsf: &mut Vector, gap: i16) {
    for upper in 1..lsf.len() {
        let below = lsf.get(upper - 1).copied().unwrap_or(0);
        let above = lsf.get(upper).copied().unwrap_or(0);
        let shortfall = sub(add(below, gap), above);
        if shortfall > 0 {
            let half = shift_right(shortfall, 1);
            if let Some(slot) = lsf.get_mut(upper - 1) {
                *slot = sub(below, half);
            }
            if let Some(slot) = lsf.get_mut(upper) {
                *slot = add(above, half);
            }
        }
    }
}

/// §3.2.4's stability check, in its four steps: order, a floor, a minimum
/// distance between neighbours, a ceiling.
fn stabilise(lsf: &mut Vector) {
    lsf.sort_unstable();
    if let Some(first) = lsf.first_mut() {
        *first = (*first).max(LOWEST);
    }
    for upper in 1..lsf.len() {
        let below = lsf.get(upper - 1).copied().unwrap_or(0);
        if let Some(slot) = lsf.get_mut(upper)
            && sub(*slot, below) < MINIMUM_DISTANCE
        {
            *slot = add(below, MINIMUM_DISTANCE);
        }
    }
    if let Some(last) = lsf.last_mut() {
        *last = (*last).min(HIGHEST);
    }
}

/// Equation 18 read backwards, `q = cos(ω)` for each LSF: the position along
/// the table's sixty-four segments, its whole part picking the segment and
/// its eight bits of fraction scaling the segment's slope.
pub(super) fn to_cosines(lsf: &Vector) -> Vector {
    let mut lsp: Vector = [0; 10];
    for (slot, frequency) in lsp.iter_mut().zip(lsf) {
        let position = mult(*frequency, TO_TABLE);
        let segment = usize::try_from(position >> 8).unwrap_or(0).min(63);
        let offset = position & 0xff;
        let base = COSINE.get(segment).copied().unwrap_or(0);
        let slope = COSINE_SLOPE.get(segment).copied().unwrap_or(0);
        // the slope is sixteen times a segment's fall, so the Q8 offset's
        // product needs twelve bits off, and the doubling of the product one
        let step = low(long_shift_right(long_mult(slope, offset), 13));
        *slot = add(base, step);
    }
    lsp
}

/// Equation 24 for the first subframe: halfway between the last frame's
/// LSPs and this one's, each halved before the two are added.
pub(super) fn midpoint(previous: &Vector, current: &Vector) -> Vector {
    let mut out: Vector = [0; 10];
    for ((slot, a), b) in out.iter_mut().zip(previous).zip(current) {
        *slot = add(shift_right(*a, 1), shift_right(*b, 1));
    }
    out
}

/// §3.2.6: the LP coefficients from the LSPs.
///
/// `F1` and `F2` are built up one quadratic factor at a time from the odd
/// and the even LSPs, multiplied by `1 + z⁻¹` and `1 − z⁻¹` (equation 25),
/// and averaged into `A(z)` (equation 26), each coefficient rounded from Q24
/// with the halving folded into the shift.
pub(super) fn to_coefficients(lsp: &Vector) -> Coefficients {
    let mut odd = [0_i16; 5];
    let mut even = [0_i16; 5];
    for (pair, (o, e)) in lsp.chunks_exact(2).zip(odd.iter_mut().zip(even.iter_mut())) {
        if let [first, second] = pair {
            *o = *first;
            *e = *second;
        }
    }
    let mut sum = polynomial(&odd);
    let mut difference = polynomial(&even);
    for index in (1..6).rev() {
        let previous = sum.get(index - 1).copied().unwrap_or(0);
        if let Some(slot) = sum.get_mut(index) {
            *slot = long_add(*slot, previous);
        }
        let previous = difference.get(index - 1).copied().unwrap_or(0);
        if let Some(slot) = difference.get_mut(index) {
            *slot = long_sub(*slot, previous);
        }
    }

    let mut a: Coefficients = [0; 11];
    if let Some(first) = a.first_mut() {
        *first = 4096;
    }
    for index in 1..6 {
        let f1 = sum.get(index).copied().unwrap_or(0);
        let f2 = difference.get(index).copied().unwrap_or(0);
        if let Some(slot) = a.get_mut(index) {
            *slot = low(long_shift_right_round(long_add(f1, f2), 13));
        }
        if let Some(slot) = a.get_mut(11 - index) {
            *slot = low(long_shift_right_round(long_sub(f1, f2), 13));
        }
    }
    a
}

/// `F1` or `F2` of equations 13 and 14, coefficients 0 to 5, from its five
/// LSPs, by the recursion under equation 26. Each new factor
/// `1 − 2q z⁻¹ + z⁻²` updates the coefficients from the top down, so every
/// update reads the values of the order before.
fn polynomial(lsp: &[i16; 5]) -> [i32; 6] {
    let mut f = [0_i32; 6];
    if let Some(slot) = f.first_mut() {
        *slot = 1 << 24;
    }
    // −2q in Q24 is a Q15 q times −1024, and the product is doubled
    if let Some(slot) = f.get_mut(1) {
        *slot = long_mult(lsp.first().copied().unwrap_or(0), -512);
    }
    for (order, q) in (2..6).zip(lsp.iter().skip(1)) {
        // the new top coefficient starts as its mirror two below, and the
        // loop below adds the same again with the cross term
        let mirror = f.get(order - 2).copied().unwrap_or(0);
        if let Some(slot) = f.get_mut(order) {
            *slot = mirror;
        }
        for index in (2..=order).rev() {
            let cross = long_shift_left(
                Split::of(f.get(index - 1).copied().unwrap_or(0)).times(*q),
                1,
            );
            let two_below = f.get(index - 2).copied().unwrap_or(0);
            if let Some(slot) = f.get_mut(index) {
                *slot = long_sub(long_add(*slot, two_below), cross);
            }
        }
        if let Some(slot) = f.get_mut(1) {
            *slot = msu(*slot, *q, 512);
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::{
        HIGHEST, LOWEST, MINIMUM_DISTANCE, Quantizer, midpoint, space, stabilise, to_coefficients,
        to_cosines,
    };
    use crate::g729::tables::INITIAL_LSF;

    #[test]
    fn spacing_pushes_close_neighbours_apart() {
        let mut lsf = [100, 105, 300, 900, 1500, 2000, 2500, 3000, 3500, 4000];
        space(&mut lsf, 10);
        // five short of ten apart: each moves by two, half the shortfall
        // rounded down
        assert_eq!(&lsf[..2], &[98, 107]);
        assert_eq!(&lsf[2..], &[300, 900, 1500, 2000, 2500, 3000, 3500, 4000]);
    }

    #[test]
    fn stability_orders_bounds_and_separates() {
        let mut lsf = [5000, 10, 3000, 3100, 3110, 9000, 12000, 15000, 20000, 26000];
        stabilise(&mut lsf);
        assert_eq!(lsf[0], LOWEST);
        for pair in lsf.windows(2) {
            assert!(pair[1] - pair[0] >= MINIMUM_DISTANCE, "{lsf:?}");
        }
        assert_eq!(lsf[9], HIGHEST);
    }

    /// A quarter turn in Q13 is π/2, whose cosine is 0; the table's own
    /// sample points come out exactly; and `iπ/11` comes out as its cosine
    /// to within the table's interpolation.
    #[test]
    fn cosines_come_out_of_the_table() {
        let quarter = to_cosines(&[12_868, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(quarter[0].abs() < 16, "{}", quarter[0]);
        assert_eq!(quarter[1], 32_767);
        let lsp = to_cosines(&INITIAL_LSF);
        for (index, value) in lsp.iter().enumerate() {
            let i = f64::from(u8::try_from(index + 1).unwrap());
            let exact = (i * core::f64::consts::PI / 11.0).cos() * 32768.0;
            assert!((f64::from(*value) - exact).abs() < 12.0, "{value} {exact}");
        }
    }

    #[test]
    fn the_midpoint_halves_each_side_first() {
        assert_eq!(midpoint(&[100; 10], &[300; 10]), [200; 10]);
        // −3/2 and 3/2 round down separately, to −2 and 1
        assert_eq!(midpoint(&[-3; 10], &[3; 10]), [-1; 10]);
    }

    /// Evenly spaced LSFs describe a flat spectrum, whose LP filter is nearly
    /// `A(z) = 1`: every coefficient small against `a0`.
    #[test]
    fn evenly_spaced_lsps_give_a_nearly_flat_filter() {
        let a = to_coefficients(&to_cosines(&INITIAL_LSF));
        assert_eq!(a[0], 4096);
        for value in &a[1..] {
            assert!(value.abs() < 400, "{a:?}");
        }
    }

    /// Equations 13, 14, 25 and 26 worked in floating point — multiply out
    /// the five quadratic factors of each polynomial, multiply by `1 ± z⁻¹`,
    /// average — agree with the fixed-point recursion to within the rounding
    /// of its Q12 result.
    #[test]
    fn the_coefficients_are_the_product_of_the_factors() {
        let lsp = [
            30_000, 26_000, 21_000, 15_000, 8_000, 0, -8_000, -15_000, -21_000, -26_000,
        ];
        let expand = |roots: &[i16]| -> Vec<f64> {
            let mut poly = vec![1.0_f64];
            for q in roots {
                let q = f64::from(*q) / 32_768.0;
                let mut next = vec![0.0; poly.len() + 2];
                for (i, c) in poly.iter().enumerate() {
                    next[i] += c;
                    next[i + 1] -= 2.0 * q * c;
                    next[i + 2] += c;
                }
                poly = next;
            }
            poly
        };
        let odd: Vec<i16> = lsp.iter().step_by(2).copied().collect();
        let even: Vec<i16> = lsp.iter().skip(1).step_by(2).copied().collect();
        let f1 = expand(&odd);
        let f2 = expand(&even);
        let a = to_coefficients(&lsp);
        for i in 1..=10 {
            // F1(z)(1 + z⁻¹) + F2(z)(1 − z⁻¹), halved
            let exact = 0.5 * (f1[i] + f1[i - 1] + f2[i] - f2[i - 1]);
            let ours = f64::from(a[i]) / 4096.0;
            assert!(
                (ours - exact).abs() < 2.0 / 4096.0,
                "a{i}: {ours} against {exact}"
            );
        }
    }

    #[test]
    fn an_erasure_repeats_the_last_frequencies() {
        let mut quantizer = Quantizer::new();
        let good = quantizer.decode(0, 17, 5, 9);
        assert_eq!(quantizer.conceal(), good);
        assert_eq!(quantizer.conceal(), good);
    }
}
