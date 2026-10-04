// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the encoder does to the signal before any codebook is searched: the
//! input filter (§3.1), the LP analysis (§3.2.1, §3.2.2) and the conversion
//! of the LP filter to line spectral pairs (§3.2.3 with A.3.2.3).
//!
//! The analysis is carried in thirty-two bits split into two halves
//! (`arith::Split`), because a tenth-order recursion in sixteen bits loses
//! the filter: the autocorrelations and the coefficients of every order are
//! kept that way, and only the finished coefficients are rounded to Q12.

use super::arith::{
    Split, abs, add, at, divide, dot, dot_checked, high, long_abs, long_add, long_mult,
    long_negate, long_norm, long_shift_left, long_shift_right, low, mac, msu, mult_round, negate,
    norm, round, shift_right, sub,
};
use super::lsp::{Coefficients, Vector};
use super::tables::{GRID, INPUT_HIGH_PASS_POLES, INPUT_HIGH_PASS_ZEROS, LAG_WINDOW, LP_WINDOW};

/// Samples the LP analysis window covers: 120 before the frame, its 80 and
/// the 40 of look-ahead.
pub(super) const WINDOW: usize = 240;

/// A reflection coefficient this close to one, Q15, is taken as a filter
/// about to become unstable, and the frame keeps the last one it had. No
/// conformance input comes near it, so the value is not checked by them.
const UNSTABLE: i16 = 32_750;

/// §3.1: `Hh1(z)` of equation 1, which halves the input as it filters it.
/// The output's past is kept in thirty-two bits and multiplied in two
/// halves, as the output filter's is.
#[derive(Debug, Clone)]
pub(super) struct InputFilter {
    inputs: [i16; 2],
    outputs: [i32; 2],
}

impl InputFilter {
    pub(super) const fn new() -> Self {
        Self {
            inputs: [0; 2],
            outputs: [0; 2],
        }
    }

    /// Filter `signal` in place. The Q12 coefficients leave the sum in Q13;
    /// three bits up gives the output in Q16, which is what is kept, and its
    /// upper half, rounded, is the sample.
    pub(super) fn run(&mut self, signal: &mut [i16]) {
        let [b0, b1, b2] = INPUT_HIGH_PASS_ZEROS;
        let [_, a1, a2] = INPUT_HIGH_PASS_POLES;
        for slot in signal.iter_mut() {
            let [x1, x2] = self.inputs;
            let [y1, y2] = self.outputs;
            let mut sum = long_add(Split::of(y1).times(a1), Split::of(y2).times(a2));
            sum = mac(sum, *slot, b0);
            sum = mac(sum, x1, b1);
            sum = mac(sum, x2, b2);
            let output = long_shift_left(sum, 3);
            self.inputs = [*slot, x1];
            self.outputs = [output, y1];
            *slot = round(output);
        }
    }
}

/// Lags of the autocorrelation kept: the LP analysis reads `r(0)` to
/// `r(10)`, Annex B's voice activity detector up to `r(12)` (B.3.1).
pub(super) const LAGS: usize = 13;

/// Equations 4, 5 and 7: the windowed signal's autocorrelations, normalised
/// together so that `r(0)` fills the word.
#[derive(Debug, Clone, Copy)]
pub(super) struct Autocorrelation {
    /// `r(0)` to `r(12)` with the lag window applied.
    pub(super) windowed: [Split; LAGS],
    /// The same before the lag window.
    pub(super) plain: [Split; LAGS],
    /// The power of two the normalised values are to be scaled by to give
    /// the sums of doubled products: one, plus two for each time the signal
    /// was divided by four, less the normalising shift.
    pub(super) exponent: i16,
}

/// Equations 4, 5 and 7: the windowed signal's autocorrelations `r(0)` to
/// `r(12)`, before and after the lag window.
///
/// `r(0)` starts from one rather than zero, which is the text's lower bound
/// on it (no conformance input tells the two apart). If the energy leaves
/// the word, the windowed signal is divided by four and the sums taken
/// again, as often as it takes.
pub(super) fn autocorrelation(signal: &[i16; WINDOW]) -> Autocorrelation {
    let mut windowed = [0_i16; WINDOW];
    for ((slot, sample), weight) in windowed.iter_mut().zip(signal).zip(LP_WINDOW) {
        *slot = mult_round(*sample, weight);
    }
    let mut exponent = 1_i16;
    let energy = loop {
        let (energy, overflowed) = dot_checked(1, &windowed, &windowed);
        if !overflowed {
            break energy;
        }
        for slot in &mut windowed {
            *slot = shift_right(*slot, 2);
        }
        exponent = add(exponent, 4);
    };
    let normalising = long_norm(energy);
    let shift = i32::try_from(normalising).unwrap_or(0);
    exponent = sub(exponent, super::arith::to_word(normalising));

    let mut plain = [Split::of(0); LAGS];
    for (lag, slot) in plain.iter_mut().enumerate() {
        let sum = if lag == 0 {
            energy
        } else {
            let later = windowed.get(lag..).unwrap_or_default();
            dot(0, later, &windowed)
        };
        *slot = Split::of(long_shift_left(sum, shift));
    }
    let mut lagged = plain;
    for (slot, (high_half, low_half)) in lagged.iter_mut().skip(1).zip(LAG_WINDOW) {
        let weight = Split {
            high: high_half,
            low: low_half,
        };
        *slot = Split::of(slot.times_split(weight));
    }
    Autocorrelation {
        windowed: lagged,
        plain,
        exponent,
    }
}

/// What the Levinson-Durbin recursion gives: the LP coefficients, the
/// second reflection coefficient (Annex B's detector reads it) and the
/// prediction error it ends with (Annex B's DTX reads that).
#[derive(Debug, Clone, Copy)]
pub(super) struct Prediction {
    /// `A(z)`, Q12.
    pub(super) a: Coefficients,
    /// `k2`, Q15.
    pub(super) reflection: i16,
    /// The final prediction error, in the scale of `r(0)`'s upper half; not
    /// known when the recursion stopped short and the last filter was kept.
    pub(super) error: Option<i16>,
}

/// §3.2.2: the Levinson-Durbin recursion, with the filter of the last frame
/// it succeeded on kept for a frame on which it does not.
#[derive(Debug, Clone)]
pub(super) struct Levinson {
    previous: Coefficients,
    /// `k2` of the last recursion that finished.
    previous_reflection: i16,
}

impl Levinson {
    pub(super) const fn new() -> Self {
        let mut previous = [0; 11];
        previous[0] = 4096;
        Self {
            previous,
            previous_reflection: 0,
        }
    }

    /// The LP coefficients, Q12, that the autocorrelations `r` (the first
    /// eleven of them) describe, with the second reflection coefficient and
    /// the prediction error.
    ///
    /// The coefficients of each order are held in Q27 and the prediction
    /// error `E` normalised, with its exponent kept apart, so that each
    /// reflection coefficient `k = −(Σ a r)/E` is a division of two
    /// thirty-two-bit values. A reflection coefficient of magnitude
    /// [`UNSTABLE`] or more stops the recursion and the last filter and
    /// `k2` it finished with are used again.
    pub(super) fn run(&mut self, r: &[Split]) -> Prediction {
        let r0 = r.first().copied().unwrap_or(Split::of(0));
        let mut a = [Split::of(0); 11];

        // order one: k = −r(1)/r(0), and a1 = k in Q27
        let r1 = r.get(1).map_or(0, |value| value.join());
        let mut k = divide_by(r1, r0);
        if let Some(slot) = a.get_mut(1) {
            *slot = Split::of(long_shift_right(k, 4));
        }
        let mut second = 0;
        let (mut error, mut exponent) = shrink(r0, Split::of(k));

        for order in 2..=10 {
            // Σ a(j) r(order − j) for j = 1..order−1, from Q27 to Q31, and
            // r(order) itself
            let mut sum = 0_i32;
            for j in 1..order {
                let correlation = r.get(j).copied().unwrap_or(Split::of(0));
                let coefficient = a.get(order - j).copied().unwrap_or(Split::of(0));
                sum = long_add(sum, correlation.times_split(coefficient));
            }
            sum = long_add(
                long_shift_left(sum, 4),
                r.get(order).map_or(0, |value| value.join()),
            );
            k = long_shift_left(divide_by(sum, error), exponent);
            let reflection = Split::of(k);
            if abs(reflection.high) > UNSTABLE {
                return Prediction {
                    a: self.previous,
                    reflection: self.previous_reflection,
                    error: None,
                };
            }
            if order == 2 {
                second = reflection.high;
            }

            // a(j) + k a(order − j) for every j below the order, and the
            // new top coefficient is k itself
            let mut next = a;
            for j in 1..order {
                let own = a.get(j).copied().unwrap_or(Split::of(0));
                let mirror = a.get(order - j).copied().unwrap_or(Split::of(0));
                if let Some(slot) = next.get_mut(j) {
                    *slot = Split::of(long_add(reflection.times_split(mirror), own.join()));
                }
            }
            if let Some(slot) = next.get_mut(order) {
                *slot = Split::of(long_shift_right(k, 4));
            }
            a = next;

            let (shrunk, shift) = shrink(error, reflection);
            error = shrunk;
            exponent += shift;
        }

        let mut out: Coefficients = [0; 11];
        if let Some(first) = out.first_mut() {
            *first = 4096;
        }
        for (slot, value) in out.iter_mut().zip(a).skip(1) {
            *slot = round(long_shift_left(value.join(), 1));
        }
        self.previous = out;
        self.previous_reflection = second;
        Prediction {
            a: out,
            reflection: second,
            error: Some(shift_right(
                error.high,
                u32::try_from(exponent).unwrap_or(0),
            )),
        }
    }
}

/// `−numerator / denominator` for a normalised denominator: the magnitudes
/// divided and the sign put back.
fn divide_by(numerator: i32, denominator: Split) -> i32 {
    let quotient = super::arith::divide_long(long_abs(numerator), denominator);
    if numerator > 0 {
        long_negate(quotient)
    } else {
        quotient
    }
}

/// `E (1 − k²)`, normalised, and the shift that normalised it.
fn shrink(error: Split, k: Split) -> (Split, i32) {
    let square = long_abs(k.times_split(k));
    let remainder = Split::of(super::arith::long_sub(i32::MAX, square));
    let product = error.times_split(remainder);
    let shift = i32::try_from(long_norm(product)).unwrap_or(0);
    (Split::of(long_shift_left(product, shift)), shift)
}

/// §3.2.3 and A.3.2.3: the ten LSPs of `A(z)`, as cosines in Q15, found as
/// the roots of `F1` and `F2` (equations 11 to 17).
///
/// The two polynomials are sampled at the fifty-one points of [`GRID`], from
/// `cos 0` down to `cos π`, alternately — the roots of the two interlace, so
/// after a root of one the search continues on the other from that root.
/// Each sign change is halved twice and the root placed by a straight line
/// between the ends of what is left. If fewer than ten roots are found, the
/// last frame's LSPs are used again.
///
/// The coefficients of `F1` and `F2` are Q11; if building them from the Q12
/// LP coefficients leaves the word anywhere, they are built again in Q10 and
/// evaluated at that precision.
pub(super) fn to_lsp(a: &Coefficients, previous: &Vector) -> Vector {
    let (mut f1, mut f2, overflowed) = polynomials(a, 16_384, 2048);
    let precision = if overflowed {
        let (g1, g2, _) = polynomials(a, 8192, 1024);
        f1 = g1;
        f2 = g2;
        Precision::Q10
    } else {
        Precision::Q11
    };

    let mut lsp: Vector = [0; 10];
    let mut found = 0;
    let mut on_first = true;
    let mut low_x = GRID.first().copied().unwrap_or(0);
    let mut low_y = chebyshev(low_x, &f1, precision);
    let mut point = 0;
    while found < 10 && point < GRID.len() - 1 {
        point += 1;
        let coefficients = if on_first { &f1 } else { &f2 };
        let mut high_x = low_x;
        let mut high_y = low_y;
        low_x = GRID.get(point).copied().unwrap_or(0);
        low_y = chebyshev(low_x, coefficients, precision);
        if long_mult(low_y, high_y) > 0 {
            continue;
        }
        for _ in 0..2 {
            let middle_x = add(shift_right(low_x, 1), shift_right(high_x, 1));
            let middle_y = chebyshev(middle_x, coefficients, precision);
            if long_mult(low_y, middle_y) <= 0 {
                high_y = middle_y;
                high_x = middle_x;
            } else {
                low_y = middle_y;
                low_x = middle_x;
            }
        }
        let root = interpolate_root(low_x, low_y, high_x, high_y);
        if let Some(slot) = lsp.get_mut(found) {
            *slot = root;
        }
        found += 1;
        low_x = root;
        on_first = !on_first;
        let next = if on_first { &f1 } else { &f2 };
        low_y = chebyshev(low_x, next, precision);
    }
    if found < 10 { *previous } else { lsp }
}

/// The point where the straight line through `(low_x, low_y)` and
/// `(high_x, high_y)` crosses zero: `low_x − low_y (high_x − low_x)/(high_y
/// − low_y)`, the slope formed as a normalised sixteen-bit division and
/// brought to Q11.
fn interpolate_root(low_x: i16, low_y: i16, high_x: i16, high_y: i16) -> i16 {
    let run = sub(high_x, low_x);
    let rise = sub(high_y, low_y);
    if rise == 0 {
        return low_x;
    }
    let magnitude = abs(rise);
    let shift = norm(magnitude);
    let normalised = super::arith::shift_left(magnitude, shift);
    let inverse = divide(16_383, normalised);
    let slope = long_shift_right(long_mult(run, inverse), 20 - to_count(shift));
    let mut slope = low(slope);
    if rise < 0 {
        slope = negate(slope);
    }
    let step = long_shift_right(long_mult(low_y, slope), 11);
    sub(low_x, low(step))
}

const fn to_count(shift: u32) -> i32 {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "a normalising shift is at most 15 here"
    )]
    let count = shift as i32;
    count
}

/// Which Q format the coefficients of `F1` and `F2` were built in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Precision {
    Q11,
    Q10,
}

/// Equation 15: `f1(i+1) = a(i+1) + a(10−i) − f1(i)` and `f2(i+1) = a(i+1) −
/// a(10−i) + f2(i)`, `f(0)` one. `half` halves a Q12 coefficient into the
/// format (16384 for Q11, 8192 for Q10) and `one` is 1.0 in it. Says whether
/// any step left the word.
fn polynomials(a: &Coefficients, half: i16, one: i16) -> ([i16; 6], [i16; 6], bool) {
    let mut f1 = [0_i16; 6];
    let mut f2 = [0_i16; 6];
    if let (Some(first), Some(second)) = (f1.first_mut(), f2.first_mut()) {
        *first = one;
        *second = one;
    }
    let mut overflowed = false;
    for i in 0..5 {
        let upper = at(a, i + 1);
        let mirror = at(a, 10 - i);
        // (a + b)/2 and (a − b)/2 in thirty-two bits cannot leave the word;
        // only the running sums below can
        let sum = high(mac(long_mult(upper, half), mirror, half));
        let difference = high(msu(long_mult(upper, half), mirror, half));
        let (previous1, previous2) = (at(&f1, i), at(&f2, i));
        let next1 = i32::from(sum) - i32::from(previous1);
        let next2 = i32::from(difference) + i32::from(previous2);
        overflowed |= i16::try_from(next1).is_err() || i16::try_from(next2).is_err();
        if let Some(slot) = f1.get_mut(i + 1) {
            *slot = sub(sum, previous1);
        }
        if let Some(slot) = f2.get_mut(i + 1) {
            *slot = add(difference, previous2);
        }
    }
    (f1, f2, overflowed)
}

/// `C(x)` of equation 17 by the recursion below it: `b(k) = 2x b(k+1) −
/// b(k+2) + f(5−k)` from `b(5) = 1`, `b(6) = 0`, and `C = x b(1) − b(2) +
/// f(5)/2`. The `b` are kept in two halves at the coefficients' precision
/// plus thirteen bits, and the result is Q14.
fn chebyshev(x: i16, f: &[i16; 6], precision: Precision) -> i16 {
    // one in the working format — Q24 for Q11 coefficients, Q23 for Q10,
    // so that a coefficient enters it by the same factor either way — and
    // the shift that takes the result to Q30
    let (one, to_q30) = match precision {
        Precision::Q11 => (256, 6),
        Precision::Q10 => (128, 7),
    };
    let scale = 4096;
    let mut older = Split { high: one, low: 0 };
    // b(4) = 2x + f(1)
    let mut newer = Split::of(mac(long_mult(x, one * 2), at(f, 1), scale));
    for i in 2..5 {
        let mut sum = long_shift_left(newer.times(x), 1);
        sum = mac(sum, older.high, i16::MIN);
        sum = msu(sum, older.low, 1);
        sum = mac(sum, at(f, i), scale);
        older = newer;
        newer = Split::of(sum);
    }
    let mut sum = newer.times(x);
    sum = mac(sum, older.high, i16::MIN);
    sum = msu(sum, older.low, 1);
    sum = mac(sum, at(f, 5), scale / 2);
    // the bottom of the word is kept one unit off, so that the magnitude
    // of any value found here fits a word too; no conformance input reaches
    // it
    high(long_shift_left(sum, to_q30)).max(-i16::MAX)
}

#[cfg(test)]
mod tests {
    use super::{InputFilter, Levinson, WINDOW, autocorrelation, to_lsp};
    use crate::g729::lsp::to_coefficients;
    use crate::g729::tables::INITIAL_LSP;

    #[test]
    fn the_input_filter_halves_and_removes_a_constant() {
        let mut filter = InputFilter::new();
        let mut constant = [1000_i16; 800];
        filter.run(&mut constant);
        assert!(constant[799].abs() < 10, "{}", constant[799]);

        let mut filter = InputFilter::new();
        let mut tone: Vec<i16> = (0..1600)
            .map(|n| {
                let t = f64::from(n) / 8000.0;
                #[expect(clippy::cast_possible_truncation, reason = "bounded by the amplitude")]
                let sample = (8000.0 * (core::f64::consts::TAU * 1000.0 * t).sin()) as i16;
                sample
            })
            .collect();
        filter.run(&mut tone);
        let peak = tone[800..].iter().map(|s| s.abs()).max().unwrap();
        assert!((3800..=4200).contains(&peak), "{peak}");
    }

    /// A signal made by a known second-order resonance comes back out of
    /// the analysis as that resonance: the LP synthesis filter peaks where
    /// the resonance is, at the poles' angle, 0.4636 of a radian — 590 Hz.
    #[test]
    fn the_analysis_finds_a_resonance() {
        // x(n) = 1.6 x(n−1) − 0.81 x(n−2) + a little noise
        let mut signal = [0_i16; WINDOW];
        let mut state = 0x1234_5678_u32;
        let (mut x1, mut x2) = (0.0_f64, 0.0_f64);
        for slot in &mut signal {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let noise = f64::from(state % 200) - 100.0;
            let x = 1.6 * x1 - 0.81 * x2 + noise;
            x2 = x1;
            x1 = x;
            #[expect(clippy::cast_possible_truncation, reason = "bounded by the resonance")]
            let sample = x.clamp(-32000.0, 32000.0) as i16;
            *slot = sample;
        }
        let r = autocorrelation(&signal);
        let a = Levinson::new().run(&r.windowed).a;
        assert_eq!(a[0], 4096);
        // |A(e^jω)| is smallest where 1/A peaks
        let magnitude = |hertz: f64| -> f64 {
            let omega = core::f64::consts::TAU * hertz / 8000.0;
            let (mut re, mut im) = (0.0, 0.0);
            for (k, coefficient) in a.iter().enumerate() {
                let phase = omega * f64::from(u8::try_from(k).unwrap());
                re += f64::from(*coefficient) * phase.cos();
                im -= f64::from(*coefficient) * phase.sin();
            }
            (re * re + im * im).sqrt()
        };
        let peak = (0..400)
            .map(|step| f64::from(step) * 10.0)
            .min_by(|x, y| magnitude(*x).total_cmp(&magnitude(*y)))
            .unwrap();
        assert!((peak - 590.0).abs() < 60.0, "peak at {peak} Hz, {a:?}");
    }

    /// LP coefficients built from known LSPs convert back to those LSPs to
    /// within the precision of the search.
    #[test]
    fn lsps_survive_the_round_trip_through_the_filter() {
        let lsp = INITIAL_LSP;
        let a = to_coefficients(&lsp);
        let back = to_lsp(&a, &[0; 10]);
        for (original, found) in lsp.iter().zip(back) {
            assert!(
                (i32::from(*original) - i32::from(found)).abs() < 40,
                "{lsp:?} against {back:?}"
            );
        }
    }

    /// A filter whose roots cannot all be found — here, one that is not
    /// minimum phase — keeps the last LSPs.
    #[test]
    fn a_filter_without_ten_roots_keeps_the_last_lsps() {
        let a = [
            4096, 8000, 8000, 8000, 8000, 8000, 8000, 8000, 8000, 8000, 8000,
        ];
        let previous = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(to_lsp(&a, &previous), previous);
    }

    /// An unstable recursion keeps the last filter.
    #[test]
    fn an_unstable_recursion_keeps_the_last_filter() {
        let mut levinson = Levinson::new();
        let mut signal = [0_i16; WINDOW];
        for (n, slot) in signal.iter_mut().enumerate() {
            *slot = if n % 2 == 0 { 20_000 } else { -20_000 };
        }
        let first = levinson.run(&autocorrelation(&signal).windowed);
        let constant = [16_000_i16; WINDOW];
        let second = levinson.run(&autocorrelation(&constant).windowed);
        assert_eq!(first.a[0], 4096);
        assert_eq!(second.a[0], 4096);
        assert!(first.error.is_some());
    }

    /// The prediction error the recursion ends with is `r(0) Π (1 − k²)`: a
    /// white signal leaves nearly all of its energy, and a resonance little.
    #[test]
    fn the_prediction_error_is_what_the_filter_leaves() {
        let mut state = 0x2468_ace1_u32;
        let mut white = [0_i16; WINDOW];
        let mut tone = [0_i16; WINDOW];
        for (n, (w, t)) in white.iter_mut().zip(tone.iter_mut()).enumerate() {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *w = i16::try_from(i64::from(state % 8000) - 4000).unwrap();
            let phase = f64::from(u16::try_from(n).unwrap()) * 0.3;
            #[expect(clippy::cast_possible_truncation, reason = "bounded by the amplitude")]
            let sample = (8000.0 * phase.sin()) as i16;
            *t = sample;
        }
        let r = autocorrelation(&white);
        let error = Levinson::new().run(&r.windowed).error.unwrap();
        // r(0) fills the word, so its upper half is near 2^14 or above
        assert!(
            error > r.windowed[0].high / 2,
            "{error} of {}",
            r.windowed[0].high
        );
        let r = autocorrelation(&tone);
        let error = Levinson::new().run(&r.windowed).error.unwrap();
        assert!(
            error < r.windowed[0].high / 100,
            "{error} of {}",
            r.windowed[0].high
        );
    }
}
