// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
    Split, add, high, log2, long_add, long_mult, long_shift_left, long_shift_right, low, mac, mult,
    pow2, sub,
};
use super::tables::{GA, GA_ROW, GAIN_PREDICTOR, GB, GB_ROW};

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

#[cfg(test)]
mod tests {
    use super::{FLOOR, Gains};
    use crate::g729::acelp::decode;

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
