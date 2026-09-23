// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The encoding half, in Annex A's reduced-complexity form (A.3).
//!
//! Per frame: the input is filtered (§3.1); the LP filter is found from a
//! window reaching five milliseconds past the frame (§3.2.1 to §3.2.3),
//! quantized as LSPs (§3.2.4) and interpolated for the two subframes
//! (§3.2.5, §3.2.6); the frame's residual through the quantized filter is
//! computed and weighted into the signal the open-loop pitch search reads
//! (A.3.3, A.3.4). Per subframe: the impulse response of the weighted
//! synthesis filter `1/A(z/γ)` — `A` always the quantized filter here — and
//! the target (A.3.5, A.3.6); the adaptive codebook's delay and gain (A.3.7);
//! the fixed codebook's four pulses (A.3.8); the two gains quantized
//! together (§3.9); and the excitation and the filter's memory brought up
//! to date (A.3.10).

use super::acelp;
use super::analysis::{self, InputFilter, Levinson, WINDOW};
use super::arith::{add, high, long_mult, long_shift_left, mac, mult, round, sub};
use super::bits::{Frame, Subframe};
use super::gain::{Gains, Terms};
use super::lpc::{expand, residual, synthesise};
use super::lsp::{self, Coefficients, Quantizer, Vector};
use super::pitch::{self, OPEN_LOOP_PAST};
use super::tables::INITIAL_LSP;
use super::taming::Taming;
use super::{FRAME_OCTETS, FRAME_SAMPLES, PAST, SHARPENING_HIGHEST, SHARPENING_LOWEST, SUBFRAME};

/// `γ` of the weighting filter, fixed at 0.75 in Annex A (equation A.1),
/// Q15.
const GAMMA: i16 = 24_576;

/// The pole of the low-pass A.3.3 adds to the weighted speech the
/// open-loop search reads, `1 − 0.7 z⁻¹`, Q15.
const LOW_PASS: i16 = 22_938;

/// The pitch gain the taming holds a subframe to, 0.95, Q14. Never reached
/// by a conformance input (see `taming`).
const TAMED_GAIN: i16 = 15_564;

/// Where the frame starts in the speech buffer: after the 120 samples of the
/// past the analysis window reaches back to.
const FRAME_START: usize = WINDOW - FRAME_SAMPLES - LOOK_AHEAD;

/// Samples of look-ahead: five milliseconds.
const LOOK_AHEAD: usize = 40;

/// The encoding half.
///
/// Stateful, as every CELP encoder is: its speech buffer reaches back past
/// the frame and five milliseconds ahead of it, and the filters' memories,
/// the excitation, the LSF and gain predictors and the taming all carry
/// forward. The decoder holds the same state for the same frames, which is
/// why a stream is encoded by one encoder from its first frame.
#[derive(Debug, Clone)]
pub struct Encoder {
    input: InputFilter,
    /// The filtered input: 120 samples of the past, the frame, and the 40 of
    /// look-ahead.
    speech: [i16; WINDOW],
    levinson: Levinson,
    /// The unquantized LSPs of the last frame, which a frame whose LSPs
    /// cannot all be found repeats.
    lsp: Vector,
    /// The quantized LSPs of the last frame, for the first subframe's
    /// interpolation.
    quantized: Vector,
    quantizer: Quantizer,
    /// The weighted speech: the longest delay's worth of the past, then the
    /// frame.
    weighted: [i16; OPEN_LOOP_PAST + FRAME_SAMPLES],
    /// The weighting filter's memory for the weighted speech.
    weighting_memory: [i16; 10],
    /// The past excitation, then the current frame's residual, replaced
    /// subframe by subframe with its excitation.
    excitation: [i16; PAST + FRAME_SAMPLES],
    /// `ew(n)` of the last ten samples: the weighted synthesis filter's
    /// memory for the target (A.3.10).
    error: [i16; 10],
    /// `β`, the last subframe's quantized pitch gain within its bounds.
    sharpening: i16,
    gains: Gains,
    taming: Taming,
}

impl Encoder {
    /// An encoder in the state §4.3 and Table 9 describe, with the same two
    /// departures as the decoder's: `β` starts at its lower bound and the
    /// quantized LSPs of the frame before the first are
    /// `tables::INITIAL_LSP`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            input: InputFilter::new(),
            speech: [0; WINDOW],
            levinson: Levinson::new(),
            lsp: INITIAL_LSP,
            quantized: INITIAL_LSP,
            quantizer: Quantizer::new(),
            weighted: [0; OPEN_LOOP_PAST + FRAME_SAMPLES],
            weighting_memory: [0; 10],
            excitation: [0; PAST + FRAME_SAMPLES],
            error: [0; 10],
            sharpening: SHARPENING_LOWEST,
            gains: Gains::new(),
            taming: Taming::new(),
        }
    }

    /// Put it back where it started, for a stream that begins again.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Encode eighty samples into one frame of ten octets.
    pub fn encode(&mut self, samples: &[i16; FRAME_SAMPLES]) -> [u8; FRAME_OCTETS] {
        self.frame(samples).pack()
    }

    /// Encode as many whole frames as `samples` holds and `octets` has room
    /// for, the way an RTP payload of several frames is built (RFC 3551
    /// §4.5.6), and return the octets written. Samples left over after the
    /// last whole frame are not encoded.
    pub fn encode_into(&mut self, samples: &[i16], octets: &mut [u8]) -> usize {
        let frames = (samples.len() / FRAME_SAMPLES).min(octets.len() / FRAME_OCTETS);
        for (input, out) in samples
            .chunks_exact(FRAME_SAMPLES)
            .zip(octets.chunks_exact_mut(FRAME_OCTETS))
            .take(frames)
        {
            let mut frame = [0_i16; FRAME_SAMPLES];
            frame.copy_from_slice(input);
            out.copy_from_slice(&self.encode(&frame));
        }
        frames * FRAME_OCTETS
    }

    fn frame(&mut self, samples: &[i16; FRAME_SAMPLES]) -> Frame {
        // the new samples, filtered, at the end of the buffer
        self.speech.copy_within(FRAME_SAMPLES.., 0);
        let fresh = self
            .speech
            .get_mut(WINDOW - FRAME_SAMPLES..)
            .unwrap_or_default();
        fresh.copy_from_slice(samples);
        self.input.run(fresh);

        // §3.2: the LP filter, its LSPs, their quantization and the two
        // subframes' filters
        let a = self.levinson.run(&analysis::autocorrelation(&self.speech));
        let lsp = analysis::to_lsp(&a, &self.lsp);
        self.lsp = lsp;
        // the indices are searched for, then decoded as the decoder will
        // decode them, which also brings the predictor's memory up to date
        let indices = self.quantizer.encode(&lsp::to_frequencies(&lsp));
        let lsf = self.quantizer.decode(
            indices.predictor,
            indices.first,
            indices.second_low,
            indices.second_high,
        );
        let quantized = lsp::to_cosines(&lsf);
        let filters: [Coefficients; 2] = [
            lsp::to_coefficients(&lsp::midpoint(&self.quantized, &quantized)),
            lsp::to_coefficients(&quantized),
        ];
        self.quantized = quantized;
        let weighting = filters.map(|a| expand(&a, GAMMA));

        // A.3.3: the residual of each subframe, which stands in for the
        // excitation not yet known, and the weighted speech from it
        for (index, (a, weighted_a)) in filters.iter().zip(&weighting).enumerate() {
            let at = PAST + SUBFRAME * index;
            let mut error = [0_i16; SUBFRAME];
            residual(a, &self.speech, FRAME_START + SUBFRAME * index, &mut error);
            if let Some(slot) = self.excitation.get_mut(at..at + SUBFRAME) {
                slot.copy_from_slice(&error);
            }
            // A′(z) = A(z/γ)(1 − 0.7 z⁻¹) of A.3.3, each product truncated
            // (the conformance streams are not encoded with them rounded),
            // and kept at the tenth order: the eleventh coefficient the
            // product has is left out
            let mut low_passed: Coefficients = *weighted_a;
            for (i, slot) in low_passed.iter_mut().enumerate().skip(1) {
                let previous = weighted_a.get(i - 1).copied().unwrap_or(0);
                *slot = sub(*slot, mult(previous, LOW_PASS));
            }
            let mut out = [0_i16; SUBFRAME];
            synthesise(&low_passed, &error, &self.weighting_memory, &mut out);
            for (slot, value) in self.weighting_memory.iter_mut().zip(out.iter().skip(30)) {
                *slot = *value;
            }
            let from = OPEN_LOOP_PAST + SUBFRAME * index;
            if let Some(slot) = self.weighted.get_mut(from..from + SUBFRAME) {
                slot.copy_from_slice(&out);
            }
        }
        let open_loop = pitch::open_loop(&self.weighted);

        let mut frame = Frame {
            predictor: indices.predictor,
            first_stage: indices.first,
            second_low: indices.second_low,
            second_high: indices.second_high,
            ..Frame::default()
        };
        let mut range = pitch::first_range(open_loop);
        let mut first_integer = 0;
        for (index, weighted_a) in weighting.iter().enumerate() {
            let subframe = self.subframe(index, weighted_a, &mut range, &mut first_integer);
            if index == 0 {
                frame.parity = Frame::parity_of(subframe.delay);
            }
            if let Some(slot) = frame.subframes.get_mut(index) {
                *slot = subframe;
            }
        }

        self.excitation.copy_within(FRAME_SAMPLES.., 0);
        self.weighted.copy_within(FRAME_SAMPLES.., 0);
        frame
    }

    /// One subframe's search, from its weighted synthesis filter
    /// `1/A(z/γ)`, leaving its excitation in place and the filter's memory
    /// up to date.
    fn subframe(
        &mut self,
        index: usize,
        weighted_a: &Coefficients,
        range: &mut (i16, i16),
        first_integer: &mut i16,
    ) -> Subframe {
        let start = PAST + SUBFRAME * index;

        // A.3.5 and A.3.6: the impulse response, Q12, and the target
        let mut impulse = [0_i16; SUBFRAME];
        if let Some(first) = impulse.first_mut() {
            *first = 4096;
        }
        let mut response = [0_i16; SUBFRAME];
        synthesise(weighted_a, &impulse, &[0; 10], &mut response);
        let mut target = [0_i16; SUBFRAME];
        let residue = self
            .excitation
            .get(start..start + SUBFRAME)
            .unwrap_or_default();
        synthesise(weighted_a, residue, &self.error, &mut target);

        // A.3.7: the delay, its codeword, and the adaptive-codebook vector
        let backward = super::lpc::backward(&response, &target);
        let delay = pitch::closed_loop(&mut self.excitation, start, &backward, *range, index == 0);
        let delay_index = if index == 0 {
            *first_integer = delay.integer;
            *range = pitch::second_range(delay.integer);
            delay.first_index()
        } else {
            delay.second_index(*first_integer)
        };
        pitch::interpolate(&mut self.excitation, start, delay);
        let mut vector = [0_i16; SUBFRAME];
        if let Some(slice) = self.excitation.get(start..start + SUBFRAME) {
            vector.copy_from_slice(slice);
        }
        // §3.7.3: `y(n)`, the zero-state response of the weighted synthesis
        // filter to `v(n)`. The text computes it as the convolution of
        // equation 44; the conformance streams are encoded with the filter
        // itself run from rest, which rounds each sample as it goes.
        let mut pitch_filtered = [0_i16; SUBFRAME];
        synthesise(weighted_a, &vector, &[0; 10], &mut pitch_filtered);
        let (mut pitch_gain, correlations) = pitch::gain(&target, &pitch_filtered);
        let tame = self.taming.needed(delay.integer, delay.fraction);
        if tame {
            pitch_gain = pitch_gain.min(TAMED_GAIN);
        }

        // A.3.8: the fixed codebook, on the target less the adaptive
        // codebook's contribution (equation 50)
        let mut remaining = [0_i16; SUBFRAME];
        for ((slot, x), y) in remaining.iter_mut().zip(target).zip(pitch_filtered) {
            *slot = sub(x, high(long_shift_left(long_mult(y, pitch_gain), 1)));
        }
        let choice = acelp::search(&remaining, &response, delay.integer, self.sharpening);

        // §3.9: the two gains, chosen, then decoded as the decoder will
        // decode them, which also brings the predictor's memory up to date
        let terms = Terms::new(&target, &pitch_filtered, &choice.filtered, correlations);
        let (ga, gb) = self.gains.encode(&choice.code, &terms, tame);
        let (pitch_gain, code_gain) = self.gains.decode(ga, gb, &choice.code);
        self.sharpening = pitch_gain.clamp(SHARPENING_LOWEST, SHARPENING_HIGHEST);

        // A.3.10: the excitation (equation A.9), and the filter's memory
        // from the weighted error of its last ten samples (equation A.10)
        if let Some(current) = self.excitation.get_mut(start..start + SUBFRAME) {
            for (sample, pulse) in current.iter_mut().zip(choice.code) {
                let mixed = mac(long_mult(*sample, pitch_gain), pulse, code_gain);
                *sample = round(long_shift_left(mixed, 1));
            }
        }
        self.taming.update(pitch_gain, delay.integer);
        for (slot, ((x, y), z)) in self.error.iter_mut().zip(
            target
                .iter()
                .zip(pitch_filtered)
                .zip(choice.filtered)
                .skip(SUBFRAME - 10),
        ) {
            let pitch_part = high(long_shift_left(long_mult(y, pitch_gain), 1));
            let code_part = high(long_shift_left(long_mult(z, code_gain), 2));
            *slot = sub(*x, add(pitch_part, code_part));
        }

        Subframe {
            delay: delay_index,
            positions: choice.positions,
            signs: choice.signs,
            ga,
            gb,
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Encoder;
    use crate::g729::{Decoder, FRAME_OCTETS, FRAME_SAMPLES};

    /// A vowel-like signal: a 120 Hz pulse train through two resonances,
    /// the way a voice is a buzz through a vocal tract, with a little noise.
    fn voiced(frames: usize) -> Vec<i16> {
        let mut state = 0x2545_f491_u32;
        let (mut a1, mut a2, mut b1, mut b2) = (0.0_f64, 0.0, 0.0, 0.0);
        (0..frames * FRAME_SAMPLES)
            .map(|n| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let noise = f64::from(state % 64) - 32.0;
                let pulse = if n % 67 == 0 { 6000.0 } else { 0.0 };
                // resonances near 700 Hz and 1200 Hz
                let a = pulse + noise + 1.73 * a1 - 0.90 * a2;
                a2 = a1;
                a1 = a;
                let b = a + 1.30 * b1 - 0.85 * b2;
                b2 = b1;
                b1 = b;
                #[expect(clippy::cast_possible_truncation, reason = "clamped to i16")]
                let sample = (b * 0.25).clamp(-32_000.0, 32_000.0) as i16;
                sample
            })
            .collect()
    }

    fn encode_all(encoder: &mut Encoder, samples: &[i16]) -> Vec<[u8; FRAME_OCTETS]> {
        samples
            .chunks_exact(FRAME_SAMPLES)
            .map(|chunk| encoder.encode(&chunk.try_into().unwrap()))
            .collect()
    }

    /// Speech through both halves comes back as speech: after the first
    /// frames, the decoded signal follows the input, delayed by the
    /// encoder's five milliseconds of look-ahead, with an error well below
    /// the signal.
    #[test]
    fn a_voice_survives_the_round_trip() {
        let input = voiced(100);
        let frames = encode_all(&mut Encoder::new(), &input);
        let mut decoder = Decoder::new();
        let output: Vec<i16> = frames.iter().flat_map(|f| decoder.decode(f)).collect();
        // the codec's delay is the look-ahead: forty samples
        let (mut signal, mut error) = (0.0, 0.0);
        for (x, y) in input[800..7_900].iter().zip(&output[840..7_940]) {
            signal += f64::from(*x).powi(2);
            error += (f64::from(*x) - f64::from(*y)).powi(2);
        }
        let snr = 10.0 * (signal / error).log10();
        assert!(snr > 3.0, "{snr} dB");
    }

    #[test]
    fn a_reset_encoder_repeats_itself() {
        let input = voiced(20);
        let mut encoder = Encoder::new();
        let first = encode_all(&mut encoder, &input);
        encoder.reset();
        assert_eq!(encode_all(&mut encoder, &input), first);
    }

    #[test]
    fn several_frames_in_one_payload_encode_as_they_would_one_by_one() {
        let input = voiced(3);
        let expected: Vec<u8> = encode_all(&mut Encoder::new(), &input)
            .into_iter()
            .flatten()
            .collect();
        let mut samples = input.clone();
        samples.extend_from_slice(&[1, 2, 3]);
        let mut octets = vec![0_u8; 3 * FRAME_OCTETS];
        assert_eq!(Encoder::new().encode_into(&samples, &mut octets), 30);
        assert_eq!(octets, expected);
        // a buffer with room for less gets what fits
        let mut cramped = vec![0_u8; 15];
        assert_eq!(Encoder::new().encode_into(&samples, &mut cramped), 10);
    }

    /// Inputs at the ends of the word — full-scale squares, clicks,
    /// full-scale noise, silence — encode without panicking, and what comes
    /// out decodes.
    #[test]
    fn extreme_inputs_encode_without_panicking() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new();
        let mut state = 0x9e37_79b9_u32;
        for frame in 0..600_usize {
            let samples: [i16; FRAME_SAMPLES] = core::array::from_fn(|n| match frame / 100 {
                0 => {
                    if (n / 4) % 2 == 0 {
                        i16::MAX
                    } else {
                        i16::MIN
                    }
                }
                1 => {
                    if n == 0 {
                        i16::MIN
                    } else {
                        0
                    }
                }
                2 | 4 => {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    i16::from_ne_bytes(state.to_ne_bytes()[..2].try_into().unwrap())
                }
                3 => 0,
                _ => i16::MAX,
            });
            decoder.decode(&encoder.encode(&samples));
        }
    }
}
