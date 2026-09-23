// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! G.729: eight kilobits of narrowband speech, CS-ACELP, written from the
//! Recommendation — the encoder and the decoder of Annex A, its
//! reduced-complexity form.
//!
//! A frame is ten milliseconds, eighty samples at eight kilohertz, carried
//! in eighty bits: ten octets. Each frame names a tenth-order LP filter by
//! four indices into a predictive vector quantizer of its line spectral
//! frequencies, and each of its two five-millisecond subframes names an
//! excitation — a stretch of the past excitation at a delay in thirds of a
//! sample, plus four signed pulses — and the two gains that mix them. The
//! encoder ([`Encoder`]) analyses the speech and searches the codebooks for
//! those indices; the decoder ([`Decoder`]) rebuilds the excitation, runs it
//! through the filter, and postfilters what comes out.
//!
//! Everything is sixteen- and thirty-two-bit fixed point, because the
//! Recommendation is defined that way (§2.4) and a codec that rounds
//! anywhere else produces a different stream or a different signal. The
//! operators are in `arith`; each module after that is one part of §3 and
//! §4, named for what it does: `analysis` (the input filter, the LP analysis
//! and the LP → LSP conversion), `lsp` (the LSP quantizer both ways, and the
//! LSP → LP conversion), `pitch` (the open-loop and closed-loop pitch
//! searches and the adaptive codebook), `acelp` (the fixed codebook and its
//! search), `gain` (the gain quantizer both ways), `taming` (the encoder's
//! control of pitch-gain instability), `lpc` (the filters), `postfilter`,
//! `bits`, `tables`, and `encoder` for the encoder's frame loop. Where the
//! text does not pin the arithmetic down to the bit, the ITU's conformance
//! streams decided, and the constant or the step says so where it is
//! written.
//!
//! **Annex A and the main body decode each other's streams** (A.1): the
//! bitstream is the same, and only the encoder's searches and the decoder's
//! postfilter differ. This decoder carries the Annex A postfilter, so its
//! output matches the Annex A conformance streams to the bit; a stream from
//! a main-body encoder decodes to the same speech, postfiltered the Annex A
//! way. The encoder is Annex A's, and its streams are what the Annex A
//! reference encoder produces from the same input, to the bit.
//!
//! # Conformance
//!
//! The ITU publishes conformance streams for Annex A with the
//! Recommendation. They are not in this repository: they are part of the
//! publication, which reserves all rights, so they are used where they were
//! obtained and never committed. The tests in `conformance` read them from
//! the directory named by `SIPRAL_G729_VECTORS` — the `G729_Release3`
//! directory of the ITU's archive, holding `g729AnnexA/test_vectors` — or,
//! without it, from `intern/itu/g729-vectors/Software/G729_Release3` at the
//! top of the checkout, and are ignored unless asked for:
//!
//! ```text
//! SIPRAL_G729_VECTORS=/path/to/G729_Release3 \
//!     cargo test -p sipral-media --lib g729::conformance -- --ignored
//! ```
//!
//! All seven Annex A inputs encode to their reference streams bit for bit,
//! and all ten Annex A streams decode to their reference output sample for
//! sample; `docs/05-media.md` records the result.

mod acelp;
mod analysis;
mod arith;
mod bits;
mod encoder;
mod gain;
mod lpc;
mod lsp;
mod pitch;
mod postfilter;
mod tables;
mod taming;

#[cfg(test)]
mod conformance;

pub use encoder::Encoder;

use arith::{long_mult, long_shift_left, mac, round, shift_right};
use bits::{Frame, Subframe};
use gain::Gains;
use lsp::{Coefficients, Quantizer, Vector};
use pitch::Delay;
use postfilter::{HighPass, Postfilter};
use tables::INITIAL_LSP;

/// What the codec hears and produces: eight kilohertz.
pub const SAMPLE_RATE: u32 = 8_000;

/// What RTP counts in (RFC 3551 §4.5.6). Unlike G.722's, the same number.
pub const CLOCK_RATE: u32 = 8_000;

/// The static payload type RFC 3551 Table 4 gives it.
pub const PAYLOAD_TYPE: u8 = 18;

/// The name an `a=rtpmap` line carries.
pub const ENCODING_NAME: &str = "G729";

/// Samples in one frame: ten milliseconds.
pub const FRAME_SAMPLES: usize = 80;

/// Octets in one frame: eighty bits.
pub const FRAME_OCTETS: usize = 10;

/// Samples in a subframe, five milliseconds.
const SUBFRAME: usize = 40;

/// Excitation kept from before the current frame: the longest delay, 143,
/// and the ten samples of the interpolation filter's reach, and one more.
const PAST: usize = 154;

/// `β`'s bounds (equation 47), Q14. The text gives 0.2 and 0.8. The lower
/// is 0.2 to the nearest unit; the upper that the conformance streams decode
/// with is 13017, 0.7945, and nothing within a few units of it — 0.8 itself
/// is 13107 — decodes them.
const SHARPENING_LOWEST: i16 = 3_277;
const SHARPENING_HIGHEST: i16 = 13_017;

/// `β` before the first subframe. Table 9 gives 0.8; the conformance
/// streams' first subframes decode from 0.2, the lower bound, and not one of
/// the ten from 0.8.
const SHARPENING_START: i16 = SHARPENING_LOWEST;

/// The whole delay an erased subframe, or a first subframe whose parity
/// failed, falls back on before any subframe has been decoded. §4.3 would
/// make it zero, which is not a delay the codebook has; this is the
/// shortest one it has. No conformance stream loses its first frame, so
/// nothing here is checked against them.
const FALLBACK_START: i16 = pitch::SHORTEST;

/// The concealment's random generator starts here (§4.4.4).
const SEED: i16 = 21_845;

/// The decoding half.
///
/// Stateful, as every CELP decoder is: the excitation of the last frames,
/// the LSF predictor's memory, the gain predictor's memory and the
/// postfilter's all carry forward, and a stream decoded in two halves by two
/// decoders is not the same stream.
#[derive(Debug, Clone)]
pub struct Decoder {
    /// The past excitation, then the current frame's.
    excitation: [i16; PAST + FRAME_SAMPLES],
    /// The synthesis filter's last ten outputs, which are also the ten
    /// samples of speech the postfilter needs before each subframe.
    memory: [i16; 10],
    /// `q̂` of the last frame, for the first subframe's interpolation.
    lsp: Vector,
    quantizer: Quantizer,
    gains: Gains,
    /// `β`, the last subframe's pitch gain within its bounds.
    sharpening: i16,
    /// The whole delay an erased subframe, or a first subframe whose parity
    /// failed, falls back on: the last one decoded (§4.1.2), stretched by a
    /// sample for each erased subframe (§4.4.4).
    fallback_delay: i16,
    seed: i16,
    postfilter: Postfilter,
    high_pass: HighPass,
}

impl Decoder {
    /// A decoder in the state §4.3 and Table 9 describe, with the two
    /// departures `SHARPENING_START` and `tables::INITIAL_LSP` document.
    #[must_use]
    pub fn new() -> Self {
        Self {
            excitation: [0; PAST + FRAME_SAMPLES],
            memory: [0; 10],
            lsp: INITIAL_LSP,
            quantizer: Quantizer::new(),
            gains: Gains::new(),
            sharpening: SHARPENING_START,
            fallback_delay: FALLBACK_START,
            seed: SEED,
            postfilter: Postfilter::new(),
            high_pass: HighPass::new(),
        }
    }

    /// Put it back where it started, for a stream that begins again.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Decode one frame of ten octets into eighty samples.
    ///
    /// Every pattern of eighty bits is a frame; there is nothing to reject.
    /// A frame whose pitch parity fails (§4.1.2) is decoded with its first
    /// subframe's delay taken from the frame before.
    pub fn decode(&mut self, frame: &[u8; FRAME_OCTETS]) -> [i16; FRAME_SAMPLES] {
        self.run(Some(Frame::unpack(frame)))
    }

    /// Produce eighty samples for a frame that never arrived (§4.4, A.4.4):
    /// the last filter repeated, the last delay stretched by a sample a
    /// subframe, the gains decaying, and pulses at random.
    pub fn conceal(&mut self) -> [i16; FRAME_SAMPLES] {
        self.run(None)
    }

    /// Decode as many whole frames as `octets` holds and `samples` has room
    /// for, the way an RTP payload of several frames arrives (RFC 3551
    /// §4.5.6), and return the samples written. Octets left over after the
    /// last whole frame are not decoded.
    pub fn decode_into(&mut self, octets: &[u8], samples: &mut [i16]) -> usize {
        let frames = (octets.len() / FRAME_OCTETS).min(samples.len() / FRAME_SAMPLES);
        for (frame, out) in octets
            .chunks_exact(FRAME_OCTETS)
            .zip(samples.chunks_exact_mut(FRAME_SAMPLES))
            .take(frames)
        {
            let mut bytes = [0_u8; FRAME_OCTETS];
            bytes.copy_from_slice(frame);
            out.copy_from_slice(&self.decode(&bytes));
        }
        frames * FRAME_SAMPLES
    }

    fn run(&mut self, frame: Option<Frame>) -> [i16; FRAME_SAMPLES] {
        let erased = frame.is_none();
        let frame = frame.unwrap_or_default();
        let parity_failed = !erased && !frame.parity_holds();

        // §4.1.1: the frame's LSPs, and the two subframes' filters
        let lsf = if erased {
            self.quantizer.conceal()
        } else {
            self.quantizer.decode(
                frame.predictor,
                frame.first_stage,
                frame.second_low,
                frame.second_high,
            )
        };
        let lsp = lsp::to_cosines(&lsf);
        let filters: [Coefficients; 2] = [
            lsp::to_coefficients(&lsp::midpoint(&self.lsp, &lsp)),
            lsp::to_coefficients(&lsp),
        ];
        self.lsp = lsp;

        // the synthesis filter's memory, then the frame it reconstructs
        let mut speech = [0_i16; 10 + FRAME_SAMPLES];
        for (slot, value) in speech.iter_mut().zip(self.memory) {
            *slot = value;
        }
        let mut delays = [0_i16; 2];
        let mut first_delay = 0;
        for (index, (subframe, a)) in frame.subframes.iter().zip(&filters).enumerate() {
            let delay = self.delay(index, subframe.delay, first_delay, erased, parity_failed);
            if index == 0 {
                first_delay = delay.integer;
            }
            if let Some(slot) = delays.get_mut(index) {
                *slot = delay.integer;
            }
            let reconstructed = self.subframe(index, subframe, a, delay, erased);
            for (slot, value) in speech
                .iter_mut()
                .skip(10 + SUBFRAME * index)
                .zip(reconstructed)
            {
                *slot = value;
            }
        }

        // §4.2 and A.4.2: postfilter each subframe with its own filter and
        // delay, then high-pass and double the frame
        let mut output = [0_i16; FRAME_SAMPLES];
        for (index, (a, delay)) in filters.iter().zip(delays).enumerate() {
            let mut window = [0_i16; 50];
            for (slot, value) in window.iter_mut().zip(speech.iter().skip(SUBFRAME * index)) {
                *slot = *value;
            }
            let mut filtered = [0_i16; SUBFRAME];
            self.postfilter.subframe(a, &window, delay, &mut filtered);
            for (slot, value) in output.iter_mut().skip(SUBFRAME * index).zip(filtered) {
                *slot = value;
            }
        }
        self.high_pass.run(&mut output);

        self.excitation.copy_within(FRAME_SAMPLES.., 0);
        output
    }

    /// §4.1.2, §4.1.3 and §4.4.4: the delay a subframe is decoded with.
    ///
    /// An erased subframe takes the fallback delay and stretches it by a
    /// sample for the next, up to the longest delay. A first subframe whose
    /// parity failed takes it as it is, and its second subframe is decoded
    /// relative to it. Any other subframe's delay is its own and becomes the
    /// fallback.
    fn delay(
        &mut self,
        index: usize,
        index_bits: u16,
        first_delay: i16,
        erased: bool,
        parity_failed: bool,
    ) -> Delay {
        if erased {
            let delay = Delay::whole(self.fallback_delay);
            self.fallback_delay = (self.fallback_delay + 1).min(pitch::LONGEST);
            return delay;
        }
        let delay = if index == 0 {
            if parity_failed {
                Delay::whole(self.fallback_delay)
            } else {
                Delay::first(index_bits)
            }
        } else {
            Delay::second(index_bits, first_delay)
        };
        self.fallback_delay = delay.integer;
        delay
    }

    /// One subframe: the excitation of §4.1.3 to §4.1.5 built in place, and
    /// the forty samples of speech it synthesises (§4.1.6).
    fn subframe(
        &mut self,
        index: usize,
        subframe: &Subframe,
        a: &Coefficients,
        delay: Delay,
        erased: bool,
    ) -> [i16; SUBFRAME] {
        let start = PAST + SUBFRAME * index;
        pitch::interpolate(&mut self.excitation, start, delay);

        // §4.4.4: an erased subframe's pulses are drawn at random, the
        // positions first; A.4.4 keeps both contributions
        let (positions, signs) = if erased {
            let positions = self.random() & 0x1fff;
            let signs = self.random() & 0xf;
            (positions, signs)
        } else {
            (subframe.positions, subframe.signs)
        };
        let mut code = acelp::decode(positions, signs);
        acelp::sharpen(&mut code, delay.integer, self.sharpening);

        let (pitch_gain, code_gain) = if erased {
            self.gains.conceal()
        } else {
            self.gains.decode(subframe.ga, subframe.gb, &code)
        };
        self.sharpening = pitch_gain.clamp(SHARPENING_LOWEST, SHARPENING_HIGHEST);

        // equation 75: the Q14 pitch gain on the Q0 past and the Q1 code
        // gain on the Q13 pulses both land in Q15; a bit up and rounded
        let current = self
            .excitation
            .get_mut(start..start + SUBFRAME)
            .unwrap_or_default();
        for (sample, pulse) in current.iter_mut().zip(code) {
            let mixed = mac(long_mult(*sample, pitch_gain), pulse, code_gain);
            *sample = round(long_shift_left(mixed, 1));
        }

        // an excitation loud enough to drive the synthesis past the end of
        // the word is scaled down by four, all of it, and synthesised again
        let mut reconstructed = [0_i16; SUBFRAME];
        let excitation = self
            .excitation
            .get(start..start + SUBFRAME)
            .unwrap_or_default();
        if lpc::synthesise(a, excitation, &self.memory, &mut reconstructed) {
            for sample in &mut self.excitation {
                *sample = shift_right(*sample, 2);
            }
            let excitation = self
                .excitation
                .get(start..start + SUBFRAME)
                .unwrap_or_default();
            lpc::synthesise(a, excitation, &self.memory, &mut reconstructed);
        }
        for (slot, value) in self.memory.iter_mut().zip(reconstructed.iter().skip(30)) {
            *slot = *value;
        }
        reconstructed
    }

    /// Equation 96, in sixteen bits: `seed = 31821 seed + 13849`.
    fn random(&mut self) -> u16 {
        self.seed = self.seed.wrapping_mul(31_821).wrapping_add(13_849);
        u16::from_ne_bytes(self.seed.to_ne_bytes())
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CLOCK_RATE, Decoder, ENCODING_NAME, FRAME_OCTETS, FRAME_SAMPLES, PAYLOAD_TYPE, SAMPLE_RATE,
    };

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn arbitrary_frames(count: usize, seed: u64) -> Vec<[u8; FRAME_OCTETS]> {
        let mut state = seed;
        (0..count)
            .map(|_| core::array::from_fn(|_| xorshift64(&mut state).to_le_bytes()[0]))
            .collect()
    }

    #[test]
    fn the_constants_are_rfc_3551s() {
        assert_eq!(SAMPLE_RATE, 8_000);
        assert_eq!(CLOCK_RATE, 8_000);
        assert_eq!(PAYLOAD_TYPE, 18);
        assert_eq!(ENCODING_NAME, "G729");
        assert_eq!(FRAME_SAMPLES, 80);
        assert_eq!(FRAME_OCTETS, 10);
    }

    #[test]
    fn a_reset_decoder_repeats_itself() {
        let frames = arbitrary_frames(20, 0x5EED_0001);
        let mut decoder = Decoder::new();
        let first: Vec<[i16; 80]> = frames.iter().map(|f| decoder.decode(f)).collect();
        decoder.reset();
        let second: Vec<[i16; 80]> = frames.iter().map(|f| decoder.decode(f)).collect();
        assert_eq!(first, second);
    }

    #[test]
    fn several_frames_in_one_payload_decode_as_they_would_one_by_one() {
        let frames = arbitrary_frames(3, 0x5EED_0002);
        let mut one_by_one = Decoder::new();
        let expected: Vec<i16> = frames.iter().flat_map(|f| one_by_one.decode(f)).collect();

        let payload: Vec<u8> = frames
            .iter()
            .flatten()
            .copied()
            .chain([0xAA, 0x55])
            .collect();
        let mut together = Decoder::new();
        let mut samples = vec![0_i16; 3 * FRAME_SAMPLES];
        assert_eq!(together.decode_into(&payload, &mut samples), 240);
        assert_eq!(samples, expected);

        // a buffer with room for less decodes what fits
        let mut cramped = vec![0_i16; 100];
        assert_eq!(Decoder::new().decode_into(&payload, &mut cramped), 80);
    }

    /// A lost frame after a run of good ones fades rather than stops: the
    /// concealment repeats the filter and decays the gains, so the first
    /// concealed frame still carries energy and the tenth carries less.
    #[test]
    fn concealment_fades_rather_than_stops() {
        let energy = |samples: &[i16; 80]| -> f64 {
            samples.iter().map(|s| f64::from(*s) * f64::from(*s)).sum()
        };
        let mut decoder = Decoder::new();
        for frame in arbitrary_frames(30, 0x5EED_0003) {
            decoder.decode(&frame);
        }
        let first = energy(&decoder.conceal());
        let mut last = first;
        for _ in 0..9 {
            last = energy(&decoder.conceal());
        }
        assert!(first > 0.0);
        assert!(
            last < first,
            "{last} after ten erasures against {first} after one"
        );
    }

    /// Octets nobody encoded: every pattern is a frame, so the decoder must
    /// turn each one into something and never panic doing it — including
    /// erasures among them.
    #[test]
    fn arbitrary_frames_and_erasures_decode_without_panicking() {
        let mut decoder = Decoder::new();
        for (n, frame) in arbitrary_frames(2_000, 0x9E37_79B9_7F4A_7C15)
            .iter()
            .enumerate()
        {
            if n % 7 == 3 {
                decoder.conceal();
            } else {
                decoder.decode(frame);
            }
        }
        // and a long run of nothing but erasures
        for _ in 0..500 {
            decoder.conceal();
        }
    }

    /// Frames of all zeros and all ones: the extremes of every index at once.
    #[test]
    fn the_extreme_frames_decode_without_panicking() {
        let mut decoder = Decoder::new();
        for _ in 0..200 {
            decoder.decode(&[0xff; FRAME_OCTETS]);
        }
        for _ in 0..200 {
            decoder.decode(&[0; FRAME_OCTETS]);
        }
    }
}
