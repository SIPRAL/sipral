// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the decoder does to its own output before anyone hears it: the
//! Annex A postfilter (A.4.2) and the output high-pass filter (§4.2.5).
//!
//! `A(z)` here is always the quantized filter the frame carried, the text's
//! A with a hat. Per subframe, the reconstructed speech is inverse filtered
//! through `A(z/γn)`; that residual goes through the long-term postfilter,
//! whose delay is a whole number of samples within three of the transmitted
//! one; then through the tilt compensation, which in Annex A comes *before*
//! the synthesis filter `1/A(z/γd)`; and the result is brought back to the
//! energy of what went in by a gain that moves smoothly from sample to
//! sample. After the whole frame, a second-order high-pass at 100 Hz, and a
//! doubling that undoes the halving at the encoder's input.
//!
//! The text gives the filters and the criteria; how each is computed in
//! sixteen bits — which signal the long-term search correlates, how its
//! energies are normalised before they are compared, how the gains are
//! rounded — is written next to the code that does it, with the conformance
//! stream that decided it.

use super::arith::{
    Split, add, divide, high, inverse_sqrt, long_add, long_mult, long_norm, long_shift_left,
    long_shift_right, long_sub, mac, mult, round, shift_right, sub, to_word,
};
use super::lpc::{expand, residual, synthesise};
use super::lsp::Coefficients;
use super::tables::{OUTPUT_HIGH_PASS_POLES, OUTPUT_HIGH_PASS_ZEROS};

/// `γn = 0.55` and `γd = 0.7` (A.4.2.2), Q15.
const GAMMA_N: i16 = 18_022;
const GAMMA_D: i16 = 22_938;

/// `γp = 0.5` (§4.2.1), Q15.
const GAMMA_P: i16 = 16_384;

/// The long-term postfilter's two weights at a gain `gl` of one:
/// `1/(1 + γp)` for the present and `γp/(1 + γp)` for the past, Q15.
const PRESENT_AT_FULL_GAIN: i16 = 21_845;
const PAST_AT_FULL_GAIN: i16 = 10_923;

/// `γt = 0.8` (A.4.2.3), Q15.
const GAMMA_T: i16 = 26_214;

/// The adaptive gain's smoothing (A.4.2.4), `g(n) = 0.9 g(n−1) + 0.1 G`, Q15.
/// 0.1 is 3276.8 in Q15; the conformance streams take the lower of the two,
/// and every one of them decodes differently with the upper.
const GAIN_KEEP: i16 = 29_491;
const GAIN_TAKE: i16 = 3_276;

/// The longest transmitted delay the long-term search centres on (A.4.2.1),
/// and how far either side of it it looks.
const CENTRE_CEILING: i16 = 140;
const REACH: i16 = 3;

/// The residual kept for the long-term search: the longest delay it can
/// reach, 143, before the subframe in hand.
const HISTORY: usize = 143;

/// Samples of the truncated impulse response the tilt is measured on: `hf(0)`
/// to `hf(21)`, from the sums of equation A.14.
const RESPONSE: usize = 22;

/// The postfilter's state across subframes.
#[derive(Debug, Clone)]
pub(super) struct Postfilter {
    /// The residual `r̂(n)` of the last 143 samples, then room for one
    /// subframe.
    residual: [i16; HISTORY + 40],
    /// The last ten outputs of `1/A(z/γd)`.
    synthesis: [i16; 10],
    /// The last input of the tilt filter.
    tilt: i16,
    /// `g(n)` at the end of the last subframe, Q12.
    gain: i16,
}

impl Postfilter {
    /// Table 9: `g(−1)` is one; everything else starts at zero.
    pub(super) const fn new() -> Self {
        Self {
            residual: [0; HISTORY + 40],
            synthesis: [0; 10],
            tilt: 0,
            gain: 4096,
        }
    }

    /// Postfilter one subframe. `speech` holds the ten samples before it and
    /// then its forty; `a` is the subframe's `A(z)`; `delay` the whole part
    /// of the pitch delay it was decoded with, or `None` for comfort noise,
    /// which has no pitch to enhance and passes the long-term postfilter
    /// untouched. The forty postfiltered samples go to `out`.
    pub(super) fn subframe(
        &mut self,
        a: &Coefficients,
        speech: &[i16; 50],
        delay: Option<i16>,
        out: &mut [i16; 40],
    ) {
        let numerator = expand(a, GAMMA_N);
        let denominator = expand(a, GAMMA_D);

        let mut current = [0_i16; 40];
        residual(&numerator, speech, 10, &mut current);
        for (slot, value) in self.residual.iter_mut().skip(HISTORY).zip(current) {
            *slot = value;
        }

        let mut filtered = match delay {
            Some(delay) => self.long_term(delay.min(CENTRE_CEILING)),
            None => current,
        };
        self.compensate_tilt(&numerator, &denominator, &mut filtered);
        synthesise(&denominator, &filtered, &self.synthesis, out);
        for (slot, value) in self.synthesis.iter_mut().zip(out.iter().skip(30)) {
            *slot = *value;
        }

        let mut reference = [0_i16; 40];
        for (slot, value) in reference.iter_mut().zip(speech.iter().skip(10)) {
            *slot = *value;
        }
        self.control_gain(&reference, out);

        self.residual.copy_within(40.., 0);
    }

    /// A.4.2.1 and equations 80 to 83: find the whole delay within three of
    /// the transmitted one at which the residual best matches its own past,
    /// and add that past in at a weight that falls to nothing when the match
    /// is too weak to be worth three decibels.
    ///
    /// Three things here the text leaves open, and the conformance streams
    /// decided:
    ///
    /// - the search, the energies and the gain are all worked on the
    ///   residual divided by four (an arithmetic shift, so rounded down),
    ///   while the filter itself is applied to the residual as it is;
    /// - both energies start from one rather than zero, which decides the
    ///   three-decibel test when the past is silent — the pitch stream's
    ///   second frame and the LSP stream's twentieth turn on it; from zero no
    ///   stream decodes, and from two eight of the ten do not;
    /// - the correlation and the two energies are normalised together, by
    ///   the shift that suits the largest of the three, and the gain is
    ///   computed from those normalised values.
    fn long_term(&self, centre: i16) -> [i16; 40] {
        let mut scaled = [0_i16; HISTORY + 40];
        for (slot, value) in scaled.iter_mut().zip(self.residual) {
            *slot = shift_right(value, 2);
        }
        let now = scaled.get(HISTORY..).unwrap_or_default();
        let past = |signal: &[i16; HISTORY + 40], delay: usize, n: usize| -> i16 {
            (HISTORY + n)
                .checked_sub(delay)
                .and_then(|at| signal.get(at))
                .copied()
                .unwrap_or(0)
        };

        let lowest = usize::try_from(centre - REACH).unwrap_or(0);
        let highest = usize::try_from(centre + REACH).unwrap_or(0);
        let mut best = lowest;
        let mut best_correlation = i32::MIN;
        for delay in lowest..=highest {
            let correlation = now.iter().enumerate().fold(0_i32, |sum, (n, value)| {
                mac(sum, *value, past(&scaled, delay, n))
            });
            // the first of equal maxima is kept
            if correlation > best_correlation {
                best_correlation = correlation;
                best = delay;
            }
        }
        let delayed_energy = (0..40).fold(1_i32, |sum, n| {
            let value = past(&scaled, best, n);
            mac(sum, value, value)
        });
        let energy = now
            .iter()
            .fold(1_i32, |sum, value| mac(sum, *value, *value));

        let shift =
            i32::try_from(long_norm(best_correlation.max(delayed_energy).max(energy))).unwrap_or(0);
        let correlation = round(long_shift_left(best_correlation, shift));
        let delayed = round(long_shift_left(delayed_energy, shift));
        let own = round(long_shift_left(energy, shift));

        let mut out = [0_i16; 40];
        let present = self.residual.get(HISTORY..).unwrap_or_default();

        // equation 82: off when the squared normalised correlation is below
        // one half, and then the residual passes as it is
        let test = long_sub(
            long_mult(correlation, correlation),
            long_shift_right(long_mult(delayed, own), 1),
        );
        if test < 0 {
            for (slot, value) in out.iter_mut().zip(present) {
                *slot = *value;
            }
            return out;
        }

        // equation 83 bounded by one, then A.11's weights: γp gl / (1 + γp gl)
        // for the past, with both terms halved so the sum stays in the word,
        // and what is left of one for the present
        let (weight_present, weight_past) = if correlation > delayed {
            (PRESENT_AT_FULL_GAIN, PAST_AT_FULL_GAIN)
        } else {
            let numerator = shift_right(mult(correlation, GAMMA_P), 1);
            let total = add(numerator, shift_right(delayed, 1));
            let past_weight = divide(numerator, total);
            (sub(i16::MAX, past_weight), past_weight)
        };
        // each product truncated on its own, then the two added
        for (n, (slot, value)) in out.iter_mut().zip(present).enumerate() {
            let delayed_sample = past(&self.residual, best, n);
            *slot = add(
                mult(weight_present, *value),
                mult(weight_past, delayed_sample),
            );
        }
        out
    }

    /// A.4.2.3: `1 + γt k′1 z⁻¹`, where `k′1` is the first reflection
    /// coefficient of the truncated impulse response of `A(z/γn)/A(z/γd)`
    /// and `γt` is 0.8 when it is negative and zero otherwise.
    ///
    /// The two correlations of equation A.14 are summed in thirty-two bits
    /// and only their upper halves divided; the conformance streams decode
    /// that way and not with the halves normalised first.
    fn compensate_tilt(
        &mut self,
        numerator: &Coefficients,
        denominator: &Coefficients,
        signal: &mut [i16; 40],
    ) {
        let mut input = [0_i16; RESPONSE];
        for (slot, value) in input.iter_mut().zip(numerator) {
            *slot = *value;
        }
        let mut response = [0_i16; RESPONSE];
        synthesise(denominator, &input, &[0; 10], &mut response);

        let zero = high(
            response
                .iter()
                .fold(0_i32, |sum, value| mac(sum, *value, *value)),
        );
        let one = high(response.windows(2).fold(0_i32, |sum, pair| match pair {
            [a, b] => mac(sum, *a, *b),
            _ => sum,
        }));
        // k′1 = −one/zero; γt k′1 is the factor subtracted below
        let factor = if one <= 0 {
            0
        } else {
            divide(mult(one, GAMMA_T), zero)
        };

        let mut previous = self.tilt;
        for slot in signal.iter_mut() {
            let value = *slot;
            *slot = sub(value, mult(factor, previous));
            previous = value;
        }
        self.tilt = previous;
    }

    /// A.4.2.4: scale the postfiltered subframe so that its energy follows
    /// the reconstructed speech's, with the factor `G` of equation A.15
    /// reached gradually.
    ///
    /// The energies are summed over the samples divided by four, as the
    /// long-term search's are. A subframe that is silent after that division
    /// passes as it is and leaves the smoothed gain at zero, to climb back
    /// from there; the conformance streams decode only so.
    fn control_gain(&mut self, reference: &[i16; 40], signal: &mut [i16; 40]) {
        let quarter_energy = |values: &[i16; 40]| -> i32 {
            values.iter().fold(0_i32, |sum, value| {
                let quarter = shift_right(*value, 2);
                mac(sum, quarter, quarter)
            })
        };
        let out_energy = quarter_energy(signal);
        if out_energy == 0 {
            self.gain = 0;
            return;
        }
        // one bit short of normalised, so that it divides by the other
        let mut exponent = to_word(long_norm(out_energy)) - 1;
        let out_mantissa = round(long_shift_left(out_energy, i32::from(exponent)));

        let in_energy = quarter_energy(reference);
        let target = if in_energy == 0 {
            0
        } else {
            let shift = long_norm(in_energy);
            let in_mantissa = round(long_shift_left(
                in_energy,
                i32::try_from(shift).unwrap_or(0),
            ));
            exponent = sub(exponent, to_word(shift));
            // out/in in Q22, whose inverse square root is G in Q19; nine
            // bits up and the upper half is G in Q12
            let ratio = long_shift_left(i32::from(divide(out_mantissa, in_mantissa)), 7);
            let ratio = long_shift_right(ratio, i32::from(exponent));
            let root = round(long_shift_left(inverse_sqrt(ratio), 9));
            mult(root, GAIN_TAKE)
        };

        let mut gain = self.gain;
        for slot in signal.iter_mut() {
            gain = add(mult(gain, GAIN_KEEP), target);
            *slot = high(long_shift_left(long_mult(*slot, gain), 3));
        }
        self.gain = gain;
    }
}

/// §4.2.5: `Hh2(z)` of equation 91, then the doubling. The output's past is
/// kept in thirty-two bits and multiplied in two halves, because a pole this
/// close to the unit circle turns the rounding of a sixteen-bit memory into
/// an audible hum.
#[derive(Debug, Clone)]
pub(super) struct HighPass {
    inputs: [i16; 2],
    outputs: [i32; 2],
}

impl HighPass {
    pub(super) const fn new() -> Self {
        Self {
            inputs: [0; 2],
            outputs: [0; 2],
        }
    }

    /// Filter and double `signal` in place. The Q13 coefficients leave the
    /// sum in Q14; two bits up gives the output in Q16, which is what is
    /// kept, and one more is the doubling.
    pub(super) fn run(&mut self, signal: &mut [i16]) {
        let [b0, b1, b2] = OUTPUT_HIGH_PASS_ZEROS;
        let [_, a1, a2] = OUTPUT_HIGH_PASS_POLES;
        for slot in signal.iter_mut() {
            let [x1, x2] = self.inputs;
            let [y1, y2] = self.outputs;
            let mut sum = long_add(Split::of(y1).times(a1), Split::of(y2).times(a2));
            sum = mac(sum, *slot, b0);
            sum = mac(sum, x1, b1);
            sum = mac(sum, x2, b2);
            let output = long_shift_left(sum, 2);
            self.inputs = [*slot, x1];
            self.outputs = [output, y1];
            *slot = round(long_shift_left(output, 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HighPass, Postfilter};

    #[test]
    fn the_high_pass_removes_a_constant_and_doubles_speech_band_tones() {
        let mut filter = HighPass::new();
        let mut constant = [1000_i16; 800];
        filter.run(&mut constant);
        assert!(constant[799].abs() < 20, "{}", constant[799]);

        let mut filter = HighPass::new();
        let mut tone: Vec<i16> = (0..1600)
            .map(|n| {
                let t = f64::from(n) / 8000.0;
                #[expect(clippy::cast_possible_truncation, reason = "bounded by the amplitude")]
                let sample = (4000.0 * (core::f64::consts::TAU * 1000.0 * t).sin()) as i16;
                sample
            })
            .collect();
        filter.run(&mut tone);
        let peak = tone[800..].iter().map(|s| s.abs()).max().unwrap();
        assert!((7600..=8400).contains(&peak), "{peak}");
    }

    /// The first output sample is the first input times `b0`, doubled:
    /// `2 × 0.93980581 × 1000`, rounded.
    #[test]
    fn the_high_pass_starts_as_its_first_coefficient() {
        let mut filter = HighPass::new();
        let mut one = [1000_i16, 0];
        filter.run(&mut one);
        assert_eq!(one[0], 1880);
    }

    #[test]
    fn silence_stays_silent() {
        let mut filter = Postfilter::new();
        let a = [4096, -2000, 500, 0, 0, 0, 0, 0, 0, 0, 0];
        let speech = [0_i16; 50];
        let mut out = [1_i16; 40];
        filter.subframe(&a, &speech, Some(60), &mut out);
        assert_eq!(out, [0; 40]);
        filter.subframe(&a, &speech, None, &mut out);
        assert_eq!(out, [0; 40]);
    }

    /// A signal too quiet for the energies, which are taken over quarters,
    /// passes the gain control unscaled.
    #[test]
    fn a_whisper_passes_the_gain_control_as_it_is() {
        let mut filter = Postfilter::new();
        let mut signal = [0_i16; 40];
        // a quarter of each, rounded down, is zero; a negative sample would
        // not be, since −1/4 rounds down to −1
        signal[3] = 3;
        signal[4] = 2;
        let reference = signal;
        filter.control_gain(&reference, &mut signal);
        assert_eq!(signal, reference);
        assert_eq!(filter.gain, 0);
    }

    /// With the past a copy of the present, the long-term filter is at a
    /// gain of one: two thirds of the present and a third of the past, which
    /// add back up to the present less the two products' truncations.
    #[test]
    fn a_perfectly_periodic_residual_passes_through_the_long_term_filter() {
        let mut filter = Postfilter::new();
        for (n, slot) in filter.residual.iter_mut().enumerate() {
            let phase = i16::try_from(n % 60).unwrap();
            *slot = (phase - 30) * 100;
        }
        let out = filter.long_term(60);
        let present = &filter.residual[143..];
        for (y, x) in out.iter().zip(present) {
            assert!((0..=2).contains(&(x - y)), "{y} against {x}");
        }
    }

    /// With no past, a quiet present fails the three-decibel test and passes
    /// exactly. A loud one does not fail it — the past's energy of one
    /// vanishes when the three are normalised to the present's — and passes
    /// at the largest fraction below one, a unit off every positive sample.
    /// The pitch stream's second frame decodes only this way.
    #[test]
    fn a_residual_with_no_past_passes_whole_or_a_unit_short() {
        let mut filter = Postfilter::new();
        for (n, slot) in filter.residual.iter_mut().skip(143).enumerate() {
            *slot = i16::try_from(n % 5).unwrap() * 4 - 8;
        }
        let out = filter.long_term(60);
        assert_eq!(&out[..], &filter.residual[143..]);

        for (n, slot) in filter.residual.iter_mut().skip(143).enumerate() {
            *slot = i16::try_from(n).unwrap() * 37 - 700;
        }
        let out = filter.long_term(60);
        for (y, x) in out.iter().zip(&filter.residual[143..]) {
            assert_eq!(*y, if *x > 0 { x - 1 } else { *x });
        }
    }
}
