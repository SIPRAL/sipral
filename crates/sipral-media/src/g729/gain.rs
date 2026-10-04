// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The two gains of a subframe (§3.9, §4.1.5, §4.4.2, §4.4.3).
//!
//! The pitch gain is sent as it is. The fixed-codebook gain is sent as a
//! correction `γ̂` to a prediction made from the energies of the last four
//! subframes' fixed-codebook contributions (equations 66 to 72), so both
//! ends keep the same four numbers: `Û`, the quantized prediction error in
//! decibels, which is `20 log γ̂`.
//!
//! Formats: the pitch gain is Q14, the fixed-codebook gain Q1, `γ̂` Q13 in
//! the codebooks, and `Û` Q10 decibels.

use super::arith::{
    Split, add, deposit_high, divide, dot, high, log2, long_add, long_mult, long_norm,
    long_shift_left, long_shift_right, long_sub, low, mac, mult, negate, pow2, round, shift_right,
    shift_right_signed, sub, to_word,
};
use super::pitch::Correlations;
use super::tables::{
    GA, GA_CODEWORD, GA_ROW, GA_THRESHOLDS, GAIN_PREDICTOR, GB, GB_CODEWORD, GB_ROW, GB_THRESHOLDS,
    PRESELECTION_OFFSETS, PRESELECTION_SLOPES,
};

/// `Û` before the first subframe and its floor after an erasure: −14 dB.
const FLOOR: i16 = -14 * 1024;

/// What an erasure takes off the average of `Û`: 4 dB (equation 95).
const ERASURE_PENALTY: i16 = 4 * 1024;

/// The constant part of `Ē − E` in equations 67 and 71, Q8 decibels. The
/// codevector's energy is summed in Q27 (Q13 pulses, doubled products), so
/// `E = 10 log(Σc²/40) = 10 log(sum) − 10 log(2^27) − 10 log(40)`, and
/// `Ē − E = 30 + 81.278 + 16.021 − 10 log(sum)`: 127.30 dB.
const ENERGY_OFFSET: i16 = 32_588;

/// `−10 log(2)` in Q13: decibels of energy per octave, negated.
const DECIBELS_PER_OCTAVE: i16 = -24_660;

/// `20 log(2)` in Q12: decibels of amplitude per octave.
const AMPLITUDE_DECIBELS_PER_OCTAVE: i16 = 24_660;

/// Octaves of amplitude per decibel, Q15: `log2(10)/20` is 0.16610, 5443,
/// but the conformance streams decode with 5439, 0.16599. With any other
/// value from 5436 to 5445, every one of the ten streams decodes
/// differently, all of them within their first thirteen frames.
const OCTAVES_PER_DECIBEL: i16 = 5_439;

/// The attenuation of the pitch gain in an erasure, 0.9 (equation 94), Q15.
///
/// Equation 94 also bounds the result below 0.9. The conformance streams do
/// not: after a subframe with a pitch gain of 1.035, the erased one that
/// follows in the erasure stream carries 0.9 × 1.035, and the stream decodes
/// only that way. So there is no bound here.
const PITCH_DECAY: i16 = 29_491;

/// The attenuation of the fixed-codebook gain, 0.98 (equation 93), Q15.
/// The nearest value, 32113, decodes the erasure stream differently; 32112,
/// the value truncated, decodes it as the reference does.
const CODE_DECAY: i16 = 32_112;

/// The gain predictor's memory, and the last gains decoded, which an erasure
/// attenuates.
#[derive(Debug, Clone)]
pub(super) struct Gains {
    /// `Û(m−1)` to `Û(m−4)`, newest first.
    history: [i16; 4],
    pitch: i16,
    code: i16,
}

impl Gains {
    pub(super) const fn new() -> Self {
        Self {
            history: [FLOOR; 4],
            pitch: 0,
            code: 0,
        }
    }

    /// §4.1.5: the pitch gain (Q14) and fixed-codebook gain (Q1) a
    /// subframe's `GA` and `GB` codewords name, given its fixed-codebook
    /// vector, whose energy the prediction depends on.
    pub(super) fn decode(&mut self, ga: u16, gb: u16, code: &[i16; 40]) -> (i16, i16) {
        let first = GA_ROW
            .get(usize::from(ga & 7))
            .and_then(|row| GA.get(usize::from(*row)))
            .copied()
            .unwrap_or_default();
        let second = GB_ROW
            .get(usize::from(gb & 15))
            .and_then(|row| GB.get(usize::from(*row)))
            .copied()
            .unwrap_or_default();
        let [first_pitch, first_correction] = first;
        let [second_pitch, second_correction] = second;

        // equation 73
        let pitch = add(first_pitch, second_pitch);

        // equation 74: γ̂ in Q13 can pass the top of a word, so the two
        // halves are added in thirty-two bits and the sum halved into Q12
        // before it scales the prediction
        let correction = long_add(i32::from(first_correction), i32::from(second_correction));
        let (mantissa, exponent) = self.predict(code);
        let product = long_mult(low(long_shift_right(correction, 1)), mantissa);
        let gain = high(long_shift_left(product, i32::from(add(exponent, 4))));

        self.remember(correction);
        self.pitch = pitch;
        self.code = gain;
        (pitch, gain)
    }

    /// §3.9: the `GA` and `GB` codewords for a subframe. The memory is not
    /// touched; decoding the codewords sent brings it up to date and gives
    /// the gains.
    ///
    /// `terms` are the five correlations of equation 63 as its error is
    /// written with the gains factored out — `y·y`, `−2x·y`, `z·z`, `−2x·z`
    /// and `2y·z` — each a mantissa and an exponent (see [`Terms`]).
    ///
    /// The unquantized optimum of the two gains is solved for first, the
    /// pitch gain held to 0.94 if `tame` says the adaptive codebook must not
    /// grow. The preselection keeps the four rows of `GA` and the eight of
    /// `GB` whose neighbourhoods that optimum falls in, and equation 63 is
    /// evaluated for the thirty-two combinations, skipping — when `tame` is
    /// set — any whose pitch gain reaches one. The first of equal errors is
    /// kept.
    pub(super) fn encode(&self, code: &[i16; 40], terms: &Terms, tame: bool) -> (u16, u16) {
        // 0.94, Q9, and just below one, Q14: the taming's two limits here,
        // which no conformance input reaches (see `taming`)
        const TAMED_OPTIMUM: i16 = 481;
        const TAMED_GAIN: i16 = 16_383;

        let (mantissa, exponent) = self.predict(code);
        let predicted_exponent = negate(exponent);
        let [(c0, e0), (c1, e1), (c2, e2), (c3, e3), (c4, e4)] = terms.values;

        // −1/(4 c0 c2 − c4²)
        let (denominator, denominator_exponent) = difference(
            long_mult(c0, c2),
            e0 + e2 - 1,
            long_mult(c4, c4),
            e4 + e4 + 1,
            0,
        );
        let inverse = negate(divide(16_384, denominator));
        let inverse_exponent = sub(29, denominator_exponent);

        // (2 c2 c1 − c3 c4) × that, the pitch gain, Q9
        let (numerator, numerator_exponent) = difference(
            long_mult(c2, c1),
            e2 + e1,
            long_mult(c3, c4),
            e3 + e4 + 1,
            1,
        );
        let shift = sub(add(numerator_exponent, inverse_exponent), 9 + 16 - 1);
        let mut best_pitch = high(long_shift_right(
            long_mult(numerator, inverse),
            i32::from(shift),
        ));
        if tame {
            best_pitch = best_pitch.min(TAMED_OPTIMUM);
        }

        // (2 c0 c3 − c1 c4) × that, the fixed-codebook gain, Q2
        let (numerator, numerator_exponent) = difference(
            long_mult(c0, c3),
            e0 + e3,
            long_mult(c1, c4),
            e1 + e4 + 1,
            1,
        );
        let shift = sub(add(numerator_exponent, inverse_exponent), 2 + 16 - 1);
        let best_code = high(long_shift_right(
            long_mult(numerator, inverse),
            i32::from(shift),
        ));

        // the predicted gain in Q4
        let predicted = if predicted_exponent >= 4 {
            shift_right_signed(mantissa, sub(predicted_exponent, 4))
        } else {
            high(long_shift_left(
                i32::from(mantissa),
                i32::from(sub(20, predicted_exponent)),
            ))
        };
        let (first_row, second_row) = preselect(best_pitch, best_code, predicted);

        // align the five terms to the smallest exponent the products will
        // have, and keep them in two halves
        let exponents = [
            e0 + 13,
            e1 + 14,
            e2 + 2 * predicted_exponent - 21,
            e3 + predicted_exponent - 3,
            e4 + predicted_exponent - 4,
        ];
        let smallest = exponents.iter().copied().fold(i16::MAX, i16::min);
        let mut aligned = [Split::of(0); 5];
        for ((slot, (value, _)), exponent) in aligned.iter_mut().zip(terms.values).zip(exponents) {
            *slot = Split::of(long_shift_right(
                deposit_high(value),
                i32::from(exponent - smallest),
            ));
        }
        let [a0, a1, a2, a3, a4] = aligned;

        let mut least = i32::MAX;
        let mut chosen = (first_row, second_row);
        for first in first_row..first_row + 4 {
            let [first_pitch, first_correction] = GA.get(first).copied().unwrap_or_default();
            for second in second_row..second_row + 8 {
                let [second_pitch, second_correction] = GB.get(second).copied().unwrap_or_default();
                let pitch = add(first_pitch, second_pitch);
                if tame && pitch >= TAMED_GAIN {
                    continue;
                }
                let correction = low(long_shift_right(
                    long_add(i32::from(first_correction), i32::from(second_correction)),
                    1,
                ));
                let gain = mult(mantissa, correction);
                let mut error = a0.times(mult(pitch, pitch));
                error = long_add(error, a1.times(pitch));
                error = long_add(error, a2.times(mult(gain, gain)));
                error = long_add(error, a3.times(gain));
                error = long_add(error, a4.times(mult(gain, pitch)));
                if error < least {
                    least = error;
                    chosen = (first, second);
                }
            }
        }

        let (first, second) = chosen;
        (
            u16::from(GA_CODEWORD.get(first).copied().unwrap_or(0)),
            u16::from(GB_CODEWORD.get(second).copied().unwrap_or(0)),
        )
    }

    /// §4.4.2 and §4.4.3: an erased subframe's gains are the last ones
    /// attenuated, and the predictor's memory is given the average of its
    /// last four entries less four decibels, no lower than its floor.
    pub(super) fn conceal(&mut self) -> (i16, i16) {
        self.pitch = mult(self.pitch, PITCH_DECAY);
        self.code = mult(self.code, CODE_DECAY);

        let total = self
            .history
            .iter()
            .fold(0_i32, |sum, value| long_add(sum, i32::from(*value)));
        let average = sub(low(long_shift_right(total, 2)), ERASURE_PENALTY).max(FLOOR);
        self.history.rotate_right(1);
        if let Some(newest) = self.history.first_mut() {
            *newest = average;
        }
        (self.pitch, self.code)
    }

    /// Equations 66, 69 and 71: the predicted fixed-codebook gain `g′c`, as a
    /// Q14 mantissa and the power of two it is to be scaled by.
    fn predict(&self, code: &[i16; 40]) -> (i16, i16) {
        let energy = code
            .iter()
            .fold(0_i32, |sum, sample| mac(sum, *sample, *sample));
        let (whole, fraction) = log2(energy);

        // Ē − E in Q14, from the logarithm in Q16 times −10 log(2) in Q13
        let octaves = Split {
            high: whole,
            low: fraction,
        };
        let mut decibels = octaves.times(DECIBELS_PER_OCTAVE);
        decibels = mac(decibels, ENERGY_OFFSET, 32);
        // to Q24, where the Q13 predictor times the Q10 memory lands
        decibels = long_shift_left(decibels, 10);
        for (coefficient, past) in GAIN_PREDICTOR.iter().zip(self.history) {
            decibels = mac(decibels, *coefficient, past);
        }
        let predicted = high(decibels);

        // 10^(dB/20) = 2^(dB × log2(10)/20), in Q16 octaves
        let octaves = Split::of(long_shift_right(
            long_mult(predicted, OCTAVES_PER_DECIBEL),
            8,
        ));
        let mantissa = low(pow2(14, octaves.low));
        (mantissa, sub(octaves.high, 14))
    }

    /// Equation 72: `Û = 20 log γ̂` joins the predictor's memory. The
    /// correction is Q13, so its logarithm is thirteen octaves high.
    fn remember(&mut self, correction: i32) {
        let (whole, fraction) = log2(correction);
        let octaves = Split {
            high: sub(whole, 13),
            low: fraction,
        }
        .join();
        let scaled = high(long_shift_left(octaves, 13));
        let decibels = mult(scaled, AMPLITUDE_DECIBELS_PER_OCTAVE);
        self.history.rotate_right(1);
        if let Some(newest) = self.history.first_mut() {
            *newest = decibels;
        }
    }
}

/// The five correlations of equation 63 with the gains factored out, in the
/// order `y·y`, `−2x·y`, `z·z`, `−2x·z`, `2y·z`: each a normalised sixteen-bit
/// mantissa and an exponent, the value being `mantissa × 2^(−exponent)` up
/// to a scale the five share.
#[derive(Debug, Clone, Copy)]
pub(super) struct Terms {
    values: [(i16, i16); 5],
}

impl Terms {
    /// The first two from the adaptive-codebook gain's correlations; the
    /// other three from the target `x`, the filtered adaptive-codebook
    /// vector `y` and the filtered codevector `z`, which is divided by eight
    /// first. Each of those three sums starts from one.
    pub(super) fn new(
        target: &[i16; 40],
        pitch_filtered: &[i16; 40],
        code_filtered: &[i16; 40],
        correlations: Correlations,
    ) -> Self {
        let mut scaled = [0_i16; 40];
        for (slot, value) in scaled.iter_mut().zip(code_filtered) {
            *slot = shift_right(*value, 3);
        }
        let normalise = |sum: i32, offset: i16| -> (i16, i16) {
            let shift = long_norm(sum);
            (
                round(long_shift_left(sum, i32::try_from(shift).unwrap_or(0))),
                add(to_word(shift), offset),
            )
        };
        let (zz, zz_exponent) = normalise(dot(1, &scaled, &scaled), 19 - 16);
        let (xz, xz_exponent) = normalise(dot(1, target, &scaled), 10 - 16);
        let (yz, yz_exponent) = normalise(dot(1, pitch_filtered, &scaled), 10 - 16);
        Self {
            values: [
                (correlations.energy, negate(correlations.energy_exponent)),
                (
                    negate(correlations.cross),
                    negate(add(correlations.cross_exponent, 1)),
                ),
                (zz, zz_exponent),
                (negate(xz), sub(xz_exponent, 1)),
                (yz, sub(yz_exponent, 1)),
            ],
        }
    }
}

/// `a − b` for two products with exponents `a_exponent` and `b_exponent`:
/// the one with the larger exponent is shifted down to the other's, both
/// are shifted down a further `headroom` bits, and the difference is
/// normalised into a sixteen-bit mantissa and its exponent.
fn difference(a: i32, a_exponent: i16, b: i32, b_exponent: i16, headroom: i16) -> (i16, i16) {
    let (a_shift, b_shift, exponent) = if a_exponent > b_exponent {
        (
            a_exponent - b_exponent + headroom,
            headroom,
            b_exponent - headroom,
        )
    } else {
        (
            headroom,
            b_exponent - a_exponent + headroom,
            a_exponent - headroom,
        )
    };
    let value = long_sub(
        long_shift_right(a, i32::from(a_shift)),
        long_shift_right(b, i32::from(b_shift)),
    );
    let shift = long_norm(value);
    (
        high(long_shift_left(value, i32::try_from(shift).unwrap_or(0))),
        exponent + to_word(shift) - 16,
    )
}

/// §3.9.2's preselection: the first row of the four of `GA`, and of the
/// eight of `GB`, that the search tries.
///
/// The two codebooks' rows lie near two lines in the plane of pitch gain and
/// correction factor. The optimum gains `pitch` (Q9) and `code` (Q2),
/// relative to the predicted gain `predicted` (Q4), are carried into
/// coordinates along the two lines, and each codebook's cluster starts at
/// the first of its thresholds, scaled by the prediction, that the
/// coordinate does not pass.
fn preselect(pitch: i16, code: i16, predicted: i16) -> (usize, usize) {
    // −1/(31.134575 − 0.481389), −0.032623, Q19 and truncated; the
    // conformance inputs encode the same with −17104, so they do not check
    // the last unit
    const INVERSE: i16 = -17_103;
    let [steep, shallow] = PRESELECTION_SLOPES;
    let [steep_offset, shallow_offset] = PRESELECTION_OFFSETS;

    // along the second: (code − (31.13 pitch + 0.053) predicted) × INVERSE,
    // Q15
    let scaled_pitch = long_mult(steep, pitch);
    let on_line = high(long_add(scaled_pitch, long_shift_right(shallow_offset, 15)));
    let expected = long_mult(on_line, predicted);
    let apart = long_sub(long_shift_left(i32::from(code), 7), expected);
    let along_second = long_mult(high(long_shift_left(apart, 2)), INVERSE);

    // along the first: (0.481 (31.13 pitch − 1.61) predicted − 31.13 code)
    // × INVERSE, Q16
    let on_line = mult(
        high(long_sub(scaled_pitch, long_shift_right(steep_offset, 10))),
        predicted,
    );
    let scaled = long_mult(on_line, shallow);
    let apart = long_sub(scaled, long_shift_right(long_mult(steep, code), 3));
    let along_first = long_mult(high(long_shift_left(apart, 2)), INVERSE);

    let passes = |coordinate: i32, threshold: i16, shift: i32| -> bool {
        let edge = long_shift_right(long_mult(threshold, predicted), shift);
        let beyond = long_sub(coordinate, edge);
        if predicted > 0 {
            beyond > 0
        } else {
            beyond < 0
        }
    };
    let mut first = 0;
    while first < 4
        && passes(
            along_first,
            GA_THRESHOLDS.get(first).copied().unwrap_or(0),
            3,
        )
    {
        first += 1;
    }
    let mut second = 0;
    while second < 8
        && passes(
            along_second,
            GB_THRESHOLDS.get(second).copied().unwrap_or(0),
            5,
        )
    {
        second += 1;
    }
    (first, second)
}

#[cfg(test)]
mod tests {
    use super::{FLOOR, Gains, Terms};
    use crate::g729::acelp::decode;
    use crate::g729::pitch::gain;

    /// A target made of the two contributions at known gains is quantized
    /// to gains near them: the adaptive codebook's within a tenth, the fixed
    /// codebook's within a quarter.
    #[test]
    fn the_quantizer_recovers_the_gains_a_target_was_made_with() {
        let code = decode(0b0001_0010_1001_0100, 0b1010);
        let mut z = [0_i16; 40];
        for (n, slot) in z.iter_mut().enumerate() {
            // a response of 1, 0.5, 0.25 at each pulse, Q12
            for (lag, tap) in [(0, 4096), (1, 2048), (2, 1024)] {
                if let Some(pulse) = n.checked_sub(lag).map(|at| code[at]) {
                    *slot += i16::try_from(i32::from(pulse) * tap / 8192).unwrap();
                }
            }
        }
        let y: [i16; 40] = core::array::from_fn(|n| {
            i16::try_from((i32::try_from(n).unwrap() * 97 % 400) - 200).unwrap()
        });
        let mut gains = Gains::new();
        // warm the predictor up on the same subframe, as a steady signal would
        for _ in 0..8 {
            let x: [i16; 40] = core::array::from_fn(|n| {
                i16::try_from((i32::from(y[n]) * 3) / 4 + i32::from(z[n]) * 40 / 4096).unwrap()
            });
            let (_, correlations) = gain(&x, &y);
            let terms = Terms::new(&x, &y, &z, correlations);
            let (ga, gb) = gains.encode(&code, &terms, false);
            let (pitch, fixed) = gains.decode(ga, gb, &code);
            assert!(pitch > 0 && fixed > 0);
        }
        let x: [i16; 40] = core::array::from_fn(|n| {
            i16::try_from((i32::from(y[n]) * 3) / 4 + i32::from(z[n]) * 40 / 4096).unwrap()
        });
        let (_, correlations) = gain(&x, &y);
        let terms = Terms::new(&x, &y, &z, correlations);
        let (ga, gb) = gains.encode(&code, &terms, false);
        let (pitch, fixed) = gains.decode(ga, gb, &code);
        let pitch = f64::from(pitch) / 16384.0;
        let fixed = f64::from(fixed) / 2.0;
        assert!((pitch - 0.75).abs() < 0.1, "pitch gain {pitch}");
        assert!((fixed - 40.0).abs() < 10.0, "fixed gain {fixed}");
    }

    #[test]
    fn the_predictor_starts_at_its_floor() {
        let gains = Gains::new();
        assert_eq!(gains.history, [FLOOR; 4]);
    }

    /// Four unit pulses have an energy ten decibels below the forty-sample
    /// mean, so at the starting memory of −14 dB the predicted gain is
    /// `10^((−14 × 1.79 + 30 + 10) / 20)`.
    #[test]
    fn the_prediction_follows_equation_71() {
        let gains = Gains::new();
        let code = decode(0, 0b1111);
        let (mantissa, exponent) = gains.predict(&code);
        let predicted = f64::from(mantissa) * 2_f64.powi(i32::from(exponent));
        let exact = 10_f64.powf((-14.0 * 1.79 + 30.0 + 10.0) / 20.0);
        assert!(
            (predicted - exact).abs() < exact * 0.01,
            "{predicted} against {exact}"
        );
    }

    /// `Û` is `20 log γ̂`: GA row 7 and GB row 11 give γ̂ = 27162 + 14276 in
    /// Q13, 5.058, which is 14.08 dB.
    #[test]
    fn the_memory_takes_the_correction_in_decibels() {
        let mut gains = Gains::new();
        let code = decode(0, 0b1111);
        // GA codeword 2 names row 7, GB codeword 13 names row 11
        gains.decode(2, 13, &code);
        let decibels = f64::from(gains.history[0]) / 1024.0;
        let exact = 20.0 * (f64::from(27_162 + 14_276) / 8192.0).log10();
        assert!(
            (decibels - exact).abs() < 0.01,
            "{decibels} against {exact}"
        );
    }

    #[test]
    fn an_erasure_attenuates_and_forgets() {
        let mut gains = Gains::new();
        let code = decode(0, 0b1111);
        let (pitch, gain) = gains.decode(3, 5, &code);
        let (faded_pitch, faded_gain) = gains.conceal();
        assert_eq!(
            faded_pitch,
            i16::try_from((i32::from(pitch) * 29_491) >> 15).unwrap()
        );
        assert_eq!(
            faded_gain,
            i16::try_from((i32::from(gain) * 32_112) >> 15).unwrap()
        );
        assert!(gains.history[0] >= FLOOR);
        // the average of the four, less four decibels
        let mut gains = Gains::new();
        gains.history = [4096, 2048, 0, -2048];
        gains.conceal();
        assert_eq!(gains.history[0], 1024 - 4096);
    }
}
