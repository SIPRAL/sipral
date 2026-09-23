// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Comfort noise, RFC 3389.
//!
//! A codec with no silence suppression of its own — G.711 among them — needs
//! somewhere to put "nothing was said here, but here is roughly what the line
//! sounded like" so the far end does not hear dead air. RFC 3389 defines the
//! payload for that: a noise level, in negative dBov, and an optional
//! spectral envelope as reflection coefficients, carried on payload type 13
//! at the 8 kHz clock G.711 shares with it (§4). What the RFC does not
//! define is the comfort noise generator itself — §5 says so outright, "the
//! comfort noise analysis and synthesis... are unspecified and left
//! implementation-specific" — so what is built here generates flat-spectrum
//! noise at the level a payload states and stops there. The reflection
//! coefficients are decoded and held for a caller that wants them; nothing
//! here applies them as a spectral shaping filter, because that synthesis
//! step is exactly the part the RFC declined to pin down.
//!
//! [`ComfortNoise`] is one parsed or constructed payload. [`Generator`] turns
//! a stream of those — arriving far less often than once a frame, per §5 —
//! into a continuous run of noise frames, remembering the last level it was
//! told about between packets.

use crate::mix::Gain;
use core::fmt;

/// The static RTP payload type CN is assigned at the 8 kHz clock rate RFC
/// 3389 §4 fixes for `RTP/AVP`. Any other clock rate needs a dynamic
/// binding, which is `sipral-core`'s business to negotiate, not this
/// module's to assume.
pub const PAYLOAD_TYPE: u8 = 13;

/// The clock rate the static payload type above is bound to (§4).
pub const STATIC_CLOCK_RATE: u32 = 8_000;

/// The name §6.1 registers for an `a=rtpmap` line: `CN/<rate>`.
pub const ENCODING_NAME: &str = "CN";

/// The largest noise-level magnitude §3.1's seven bits can carry.
pub const MAX_LEVEL: u8 = 127;

/// The deepest reflection-coefficient model this module will hold.
///
/// §3 leaves the model order to the sender and has the receiver read it off
/// the payload length, so this is not a protocol limit — it is the size of
/// the array a payload is parsed into. Sixteen is generous for any linear
/// predictive model of speech at a telephony bandwidth; §3 itself gives a
/// receiver licence to reduce a payload's order for exactly this reason.
pub const MAX_MODEL_ORDER: usize = 16;

/// The full-scale reference amplitude §3.1 calls "the overload of the
/// system": for the sixteen-bit linear PCM this crate carries samples as,
/// the largest sample the format can hold. §3.1's own example ties 0 dBov
/// to a specific square-wave amplitude for a mu-law system's calibration,
/// which is a property of that companding law's test signal, not of dBov
/// itself; a full-scale linear sample is what "the overload of the system"
/// means for linear PCM.
pub const REFERENCE_AMPLITUDE: i16 = i16::MAX;

/// Q15 gain applied to [`REFERENCE_AMPLITUDE`] at each `-dBov` level: index
/// `n` holds `round(32768 * 10^(-n/20))`, so index 0 is unity — 0 dBov, full
/// scale — and every twenty entries is another power of ten down, which is
/// an exact identity independent of how the table itself was rounded and is
/// what the tests check it against. Computed once, offline, from the
/// definition of the decibel; no codec's calibration is in it.
const LEVEL_TO_GAIN_Q15: [i32; 128] = [
    32_768, 29_205, 26_029, 23_198, 20_675, 18_427, 16_423, 14_637, 13_045, 11_627, 10_362, 9_235,
    8_231, 7_336, 6_538, 5_827, 5_193, 4_629, 4_125, 3_677, 3_277, 2_920, 2_603, 2_320, 2_068,
    1_843, 1_642, 1_464, 1_305, 1_163, 1_036, 924, 823, 734, 654, 583, 519, 463, 413, 368, 328,
    292, 260, 232, 207, 184, 164, 146, 130, 116, 104, 92, 82, 73, 65, 58, 52, 46, 41, 37, 33, 29,
    26, 23, 21, 18, 16, 15, 13, 12, 10, 9, 8, 7, 7, 6, 5, 5, 4, 4, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

/// The Q15 gain the noise-level byte implies.
fn gain_for_level(level: u8) -> Gain {
    let index = usize::from(level.min(MAX_LEVEL));
    let value = LEVEL_TO_GAIN_Q15.get(index).copied().unwrap_or(0);
    Gain::from_q15(value)
}

/// The level whose table entry is closest to `gain`, breaking a tie toward
/// the louder (lower) level: a linear search of a hundred and twenty-eight
/// entries, run once per outgoing SID rather than once per sample.
fn level_for_gain(gain: Gain) -> u8 {
    let target = gain.to_q15();
    let mut best_level = 0_u8;
    let mut best_distance = i32::MAX;
    for (index, &value) in LEVEL_TO_GAIN_Q15.iter().enumerate() {
        let distance = (value - target).abs();
        if distance < best_distance {
            best_distance = distance;
            best_level = u8::try_from(index).unwrap_or(MAX_LEVEL);
        }
    }
    best_level
}

/// One reflection coefficient index (§3.2) as a Q15 value, or `None` for
/// the index §3.2 reserves.
///
/// `k_i = 258*(N-127)/32768`: the numerator is already an exact integer, so
/// nothing here rounds — the conversion loses nothing §3.2 did not already
/// discard when it quantised the coefficient to eight bits.
fn decode_reflection(index: u8) -> Option<i16> {
    if index == 255 {
        return None;
    }
    let scaled = 258 * (i32::from(index) - 127); // exactly -32_766..=32_766
    i16::try_from(scaled).ok()
}

/// The index §3.2 would encode `value` as: the nearest integer solution of
/// the formula [`decode_reflection`] reads, rounded away from zero for the
/// same reason [`crate::mix::Gain`] does — a coefficient and its mirror image
/// should encode to symmetric indices — and clamped to the range eight bits
/// allow. Never returns the reserved value 255.
fn encode_reflection(value: i16) -> u8 {
    let n = round_div(i32::from(value), 258);
    let index = (n + 127).clamp(0, 254);
    u8::try_from(index).unwrap_or(254)
}

/// `numerator / denominator`, rounded to the nearest integer and away from
/// zero on a tie, for a positive `denominator`.
fn round_div(numerator: i32, denominator: i32) -> i32 {
    if numerator >= 0 {
        (numerator + denominator / 2) / denominator
    } else {
        -((-numerator + denominator / 2) / denominator)
    }
}

/// Why a payload could not be built or parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComfortNoiseError {
    /// §3 requires at least the level byte; nothing arrived to read one
    /// from.
    Empty,
    /// §3.1's magnitude fits seven bits; the level offered does not.
    LevelTooLoud {
        /// The level that was offered.
        level: u8,
    },
    /// More reflection coefficients were offered than [`MAX_MODEL_ORDER`]
    /// holds. Refused rather than silently narrowed: §3's licence for a
    /// decoder to reduce the order of a payload it received is not licence
    /// to build a payload that already exceeds it.
    TooManyCoefficients {
        /// How many were offered.
        offered: usize,
    },
}

impl fmt::Display for ComfortNoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "a CN payload needs at least a level byte"),
            Self::LevelTooLoud { level } => {
                write!(f, "noise level {level} does not fit in seven bits")
            }
            Self::TooManyCoefficients { offered } => {
                write!(
                    f,
                    "{offered} reflection coefficients offered, {MAX_MODEL_ORDER} held"
                )
            }
        }
    }
}

impl core::error::Error for ComfortNoiseError {}

/// A buffer too short to hold an encoded payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTooShort {
    /// How many bytes the payload needs.
    pub needed: usize,
}

impl fmt::Display for BufferTooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "buffer too short: needs {} bytes", self.needed)
    }
}

impl core::error::Error for BufferTooShort {}

/// One CN payload: §3.1's noise level and §3.2's optional reflection
/// coefficients.
#[derive(Clone, Copy)]
pub struct ComfortNoise {
    level: u8,
    coefficients: [i16; MAX_MODEL_ORDER],
    order: usize,
}

impl ComfortNoise {
    /// A payload at `level` with `coefficients` as §3.2's Q15 reflection
    /// values, most significant term first as §3.3 packs them. An empty
    /// slice is §3.3's zeroth-order model — "no spectral envelope
    /// information".
    ///
    /// # Errors
    /// [`ComfortNoiseError::LevelTooLoud`] if `level` exceeds
    /// [`MAX_LEVEL`]; [`ComfortNoiseError::TooManyCoefficients`] if more than
    /// [`MAX_MODEL_ORDER`] are offered.
    pub fn new(level: u8, coefficients: &[i16]) -> Result<Self, ComfortNoiseError> {
        if level > MAX_LEVEL {
            return Err(ComfortNoiseError::LevelTooLoud { level });
        }
        if coefficients.len() > MAX_MODEL_ORDER {
            return Err(ComfortNoiseError::TooManyCoefficients {
                offered: coefficients.len(),
            });
        }
        let mut stored = [0_i16; MAX_MODEL_ORDER];
        for (slot, &value) in stored.iter_mut().zip(coefficients) {
            *slot = value;
        }
        Ok(Self {
            level,
            coefficients: stored,
            order: coefficients.len(),
        })
    }

    /// Parse one payload as §3.3 packs it: a level byte followed by zero or
    /// more reflection coefficient indices.
    ///
    /// §3.1's eighth bit is unused and meant to always be zero; a sender
    /// that set it anyway is not followed off the edge of the payload for
    /// one stray bit, so it is masked rather than rejected. An index of 255
    /// (§3.2's reservation) decodes as no tilt at that position, keeping the
    /// coefficients that follow it at the order they arrived in rather than
    /// shifting them down. A payload offering more terms than
    /// [`MAX_MODEL_ORDER`] holds is the situation §3 already describes for a
    /// receiver — "may reduce the model order... by setting higher order
    /// reflection coefficients to zero" — so the excess is dropped rather
    /// than refused.
    ///
    /// # Errors
    /// [`ComfortNoiseError::Empty`] for a payload with no level byte.
    pub fn decode(payload: &[u8]) -> Result<Self, ComfortNoiseError> {
        let (&level_byte, rest) = payload.split_first().ok_or(ComfortNoiseError::Empty)?;
        let level = level_byte & 0x7f;

        let mut coefficients = [0_i16; MAX_MODEL_ORDER];
        for (slot, &index) in coefficients.iter_mut().zip(rest) {
            *slot = decode_reflection(index).unwrap_or(0);
        }
        let order = rest.len().min(MAX_MODEL_ORDER);

        Ok(Self {
            level,
            coefficients,
            order,
        })
    }

    /// Write this payload as §3.3 packs it: the level byte followed by any
    /// reflection coefficients, most significant first. Returns the number
    /// of bytes written, `1 + order`.
    ///
    /// Refuses a buffer that cannot hold the whole payload rather than
    /// writing part of one, the same convention
    /// [`crate::resample::Resampler::process`] uses for a short output.
    ///
    /// # Errors
    /// [`BufferTooShort`] naming how many bytes were needed.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, BufferTooShort> {
        let needed = 1 + self.order;
        let Some(slice) = out.get_mut(..needed) else {
            return Err(BufferTooShort { needed });
        };
        let Some((level_byte, coefficients)) = slice.split_first_mut() else {
            return Err(BufferTooShort { needed });
        };
        *level_byte = self.level;
        for (slot, &value) in coefficients
            .iter_mut()
            .zip(self.coefficients.iter().take(self.order))
        {
            *slot = encode_reflection(value);
        }
        Ok(needed)
    }

    /// The magnitude §3.1 packs, `0..=`[`MAX_LEVEL`].
    #[must_use]
    pub const fn level(&self) -> u8 {
        self.level
    }

    /// The level as §3.1 actually defines it: a negative number of dBov,
    /// `0` down to `-127`.
    #[must_use]
    pub fn dbov(&self) -> i32 {
        -i32::from(self.level)
    }

    /// This payload's reflection coefficients, in Q15, most significant term
    /// first. Empty for a zeroth-order model.
    #[must_use]
    pub fn coefficients(&self) -> &[i16] {
        self.coefficients.get(..self.order).unwrap_or(&[])
    }

    /// How many reflection coefficients this payload carries.
    #[must_use]
    pub const fn order(&self) -> usize {
        self.order
    }

    /// The Q15 gain this payload's level implies against
    /// [`REFERENCE_AMPLITUDE`].
    #[must_use]
    pub fn gain(&self) -> Gain {
        gain_for_level(self.level)
    }

    /// The payload whose level comes closest to describing `amplitude` as a
    /// linear peak against [`REFERENCE_AMPLITUDE`], with no spectral
    /// envelope. The inverse of [`Self::gain`], to the resolution §3.1's
    /// seven bits allow.
    #[must_use]
    pub fn from_amplitude(amplitude: i16) -> Self {
        let gain = Gain::ratio(
            i32::from(amplitude.unsigned_abs()),
            i32::from(REFERENCE_AMPLITUDE),
        );
        Self {
            level: level_for_gain(gain),
            coefficients: [0; MAX_MODEL_ORDER],
            order: 0,
        }
    }
}

impl fmt::Debug for ComfortNoise {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComfortNoise")
            .field("level", &self.level)
            .field("coefficients", &self.coefficients())
            .finish_non_exhaustive()
    }
}

impl PartialEq for ComfortNoise {
    fn eq(&self, other: &Self) -> bool {
        self.level == other.level && self.coefficients() == other.coefficients()
    }
}

impl Eq for ComfortNoise {}

/// Generates the noise a stream of CN payloads describes.
///
/// §5 leaves the update rate to the sender — "may be sent periodically or
/// only when there is a significant change" — so this remembers the last
/// payload it was told about and keeps producing that level of noise between
/// packets, rather than assuming a fresh one arrives every frame.
pub struct Generator {
    noise: Option<ComfortNoise>,
    state: u64,
}

/// An arbitrary nonzero odd seed: xorshift's zero state is a fixed point, and
/// this is simply a constant that is not it.
const DEFAULT_SEED: u64 = 0xA5A1_5A5E_ED01_F00D;

impl Generator {
    /// A generator with nothing received yet, seeded so two default
    /// instances produce the same sequence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            noise: None,
            state: DEFAULT_SEED,
        }
    }

    /// A generator seeded explicitly, for a caller that wants a repeatable
    /// sequence — tests, mainly. Two live streams sounding identical is not
    /// wanted in production, which is why [`Self::new`] does not expose its
    /// own seed.
    #[must_use]
    pub const fn with_seed(seed: u64) -> Self {
        Self {
            noise: None,
            state: if seed == 0 { DEFAULT_SEED } else { seed },
        }
    }

    /// A CN packet arrived: remember what it describes.
    pub fn received(&mut self, noise: ComfortNoise) {
        self.noise = Some(noise);
    }

    /// Whether any CN packet has arrived for this stream yet.
    #[must_use]
    pub fn is_silent(&self) -> bool {
        self.noise.is_none()
    }

    /// Forget the stream: a new call, or a codec change that makes the last
    /// noise description stale.
    pub fn reset(&mut self) {
        self.noise = None;
    }

    /// Fill `out` with one frame of comfort noise at the level of the last
    /// payload received, or with digital silence if none has arrived yet.
    /// Generating noise at a level nobody sent would invent a background the
    /// far end never had.
    ///
    /// The spectral envelope a payload's reflection coefficients describe is
    /// not applied — see the module docs for why — so what is written is
    /// flat-spectrum noise scaled to the payload's level, not shaped by it.
    pub fn fill(&mut self, out: &mut [i16]) {
        let Some(noise) = self.noise else {
            out.fill(0);
            return;
        };
        let gain = noise.gain();
        for sample in out.iter_mut() {
            *sample = gain.apply(self.next_sample());
        }
    }

    fn next_sample(&mut self) -> i16 {
        self.state = xorshift64(self.state);
        let top = self.state >> 48; // 0..=65_535, the high bits carry the best statistical quality
        let unsigned = u16::try_from(top).unwrap_or(0);
        let centred = i32::from(unsigned) - 32_768; // -32_768..=32_767
        i16::try_from(centred).unwrap_or(0)
    }
}

impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Generator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generator")
            .field("level", &self.noise.as_ref().map(ComfortNoise::level))
            .finish_non_exhaustive()
    }
}

/// Marsaglia's xorshift64: a fast, public-domain generator good enough for
/// dithering comfort noise, not for anything that needs unpredictability.
const fn xorshift64(state: u64) -> u64 {
    let mut x = state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

#[cfg(test)]
mod tests {
    use super::{
        BufferTooShort, ComfortNoise, ComfortNoiseError, ENCODING_NAME, Generator,
        LEVEL_TO_GAIN_Q15, MAX_LEVEL, MAX_MODEL_ORDER, PAYLOAD_TYPE, REFERENCE_AMPLITUDE,
        STATIC_CLOCK_RATE, decode_reflection, encode_reflection,
    };
    use crate::mix::Gain;

    #[test]
    fn the_static_assignment_matches_rfc_3389() {
        assert_eq!(PAYLOAD_TYPE, 13);
        assert_eq!(STATIC_CLOCK_RATE, 8_000);
        assert_eq!(ENCODING_NAME, "CN");
        assert_eq!(MAX_LEVEL, 127);
        assert_eq!(REFERENCE_AMPLITUDE, i16::MAX);
    }

    #[test]
    fn every_reflection_index_but_the_reserved_one_round_trips() {
        for index in 0_u8..=254 {
            let value = decode_reflection(index).expect("only 255 is reserved");
            assert_eq!(encode_reflection(value), index, "index {index}");
        }
        assert_eq!(decode_reflection(255), None);
    }

    #[test]
    fn reflection_decode_matches_the_formula_at_its_extremes_and_centre() {
        assert_eq!(decode_reflection(127), Some(0)); // the centre index is no tilt
        assert_eq!(decode_reflection(0), Some(-32_766)); // 258*(0-127)
        assert_eq!(decode_reflection(254), Some(32_766)); // 258*(254-127)
    }

    #[test]
    fn the_gain_table_matches_the_exact_decade_identities() {
        // 20 dB is exactly a factor of ten, independent of how the table
        // rounds any individual entry -- an anchor that does not depend on
        // trusting the table's own derivation
        assert_eq!(LEVEL_TO_GAIN_Q15[0], 32_768);
        let ratio_20 = f64::from(LEVEL_TO_GAIN_Q15[0]) / f64::from(LEVEL_TO_GAIN_Q15[20]);
        assert!((ratio_20 - 10.0).abs() < 0.01, "ratio was {ratio_20}");
        let ratio_40 = f64::from(LEVEL_TO_GAIN_Q15[0]) / f64::from(LEVEL_TO_GAIN_Q15[40]);
        assert!((ratio_40 - 100.0).abs() < 1.0, "ratio was {ratio_40}");
    }

    #[test]
    fn level_zero_is_unity_gain() {
        let noise = ComfortNoise::new(0, &[]).unwrap();
        assert_eq!(noise.gain(), Gain::UNITY);
        assert_eq!(noise.dbov(), 0);
    }

    #[test]
    fn a_zeroth_order_payload_round_trips_through_the_wire_format() {
        let noise = ComfortNoise::new(42, &[]).unwrap();
        let mut wire = [0_u8; 1];
        assert_eq!(noise.encode_into(&mut wire).unwrap(), 1);
        assert_eq!(wire, [42]);

        let back = ComfortNoise::decode(&wire).unwrap();
        assert_eq!(back, noise);
        assert_eq!(back.order(), 0);
        assert!(back.coefficients().is_empty());
    }

    #[test]
    fn a_payload_with_coefficients_round_trips_exactly() {
        let coefficients = [-32_766, -258, 0, 258, 32_766];
        let noise = ComfortNoise::new(30, &coefficients).unwrap();
        let mut wire = [0_u8; 6];
        assert_eq!(noise.encode_into(&mut wire).unwrap(), 6);

        let back = ComfortNoise::decode(&wire).unwrap();
        assert_eq!(back, noise);
        assert_eq!(back.coefficients(), &coefficients);
    }

    #[test]
    fn decode_masks_the_reserved_top_bit_instead_of_refusing_it() {
        let noise = ComfortNoise::decode(&[0x81]).unwrap(); // bit 7 set, level 1
        assert_eq!(noise.level(), 1);
    }

    #[test]
    fn decode_of_an_empty_payload_fails() {
        assert_eq!(ComfortNoise::decode(&[]), Err(ComfortNoiseError::Empty));
    }

    #[test]
    fn decode_reads_the_reserved_index_as_no_tilt_without_shifting_the_order() {
        let noise = ComfortNoise::decode(&[10, 200, 255, 100]).unwrap();
        assert_eq!(noise.order(), 3);
        assert_eq!(noise.coefficients().get(1), Some(&0));
        assert_eq!(noise.coefficients().get(2), decode_reflection(100).as_ref());
    }

    #[test]
    fn decode_truncates_a_payload_longer_than_the_model_order_this_holds() {
        let mut payload = vec![50_u8];
        payload.extend(std::iter::repeat_n(127_u8, MAX_MODEL_ORDER + 5));
        let noise = ComfortNoise::decode(&payload).unwrap();
        assert_eq!(noise.order(), MAX_MODEL_ORDER);
    }

    #[test]
    fn new_refuses_a_level_past_seven_bits() {
        assert_eq!(
            ComfortNoise::new(200, &[]),
            Err(ComfortNoiseError::LevelTooLoud { level: 200 })
        );
    }

    #[test]
    fn new_refuses_more_coefficients_than_the_model_order_holds() {
        let too_many = vec![0_i16; MAX_MODEL_ORDER + 1];
        assert_eq!(
            ComfortNoise::new(0, &too_many),
            Err(ComfortNoiseError::TooManyCoefficients {
                offered: MAX_MODEL_ORDER + 1
            })
        );
    }

    #[test]
    fn encode_into_refuses_a_short_buffer_and_says_how_much_it_needed() {
        let noise = ComfortNoise::new(5, &[1, 2, 3]).unwrap();
        let mut short = [0_u8; 2];
        assert_eq!(
            noise.encode_into(&mut short),
            Err(BufferTooShort { needed: 4 })
        );
    }

    #[test]
    fn from_amplitude_and_gain_agree_within_the_tables_resolution() {
        let noise = ComfortNoise::from_amplitude(3_277); // roughly -20 dBov
        assert_eq!(noise.level(), 20);
    }

    #[test]
    fn generator_writes_silence_until_something_arrives() {
        let mut generator = Generator::new();
        assert!(generator.is_silent());
        let mut frame = [1_i16; 8];
        generator.fill(&mut frame);
        assert_eq!(frame, [0; 8]);
    }

    #[test]
    fn generator_produces_noise_once_a_payload_arrives() {
        let mut generator = Generator::with_seed(1);
        generator.received(ComfortNoise::new(0, &[]).unwrap());
        assert!(!generator.is_silent());

        let mut frame = [0_i16; 64];
        generator.fill(&mut frame);
        assert!(frame.iter().any(|&sample| sample != 0));
    }

    #[test]
    fn the_same_seed_produces_the_same_sequence() {
        let mut a = Generator::with_seed(99);
        let mut b = Generator::with_seed(99);
        a.received(ComfortNoise::new(10, &[]).unwrap());
        b.received(ComfortNoise::new(10, &[]).unwrap());

        let mut out_a = [0_i16; 32];
        let mut out_b = [0_i16; 32];
        a.fill(&mut out_a);
        b.fill(&mut out_b);
        assert_eq!(out_a, out_b);
    }

    #[test]
    fn a_quieter_level_produces_smaller_amplitude_noise_on_average() {
        let mut loud = Generator::with_seed(7);
        loud.received(ComfortNoise::new(0, &[]).unwrap());
        let mut quiet = Generator::with_seed(7);
        quiet.received(ComfortNoise::new(40, &[]).unwrap());

        let mut loud_frame = [0_i16; 256];
        let mut quiet_frame = [0_i16; 256];
        loud.fill(&mut loud_frame);
        quiet.fill(&mut quiet_frame);

        let mean_abs = |frame: &[i16]| -> i64 {
            frame.iter().map(|&s| i64::from(s).abs()).sum::<i64>()
                / i64::try_from(frame.len()).unwrap()
        };
        assert!(mean_abs(&loud_frame) > mean_abs(&quiet_frame) * 10);
    }

    #[test]
    fn reset_returns_the_generator_to_silence() {
        let mut generator = Generator::with_seed(3);
        generator.received(ComfortNoise::new(0, &[]).unwrap());
        assert!(!generator.is_silent());
        generator.reset();
        assert!(generator.is_silent());
    }

    #[test]
    fn generator_debug_does_not_panic_either_side_of_a_reception() {
        let mut generator = Generator::new();
        let _ = format!("{generator:?}");
        generator.received(ComfortNoise::new(5, &[]).unwrap());
        let _ = format!("{generator:?}");
    }

    #[test]
    fn comfort_noise_debug_does_not_panic() {
        let noise = ComfortNoise::new(10, &[1, -1]).unwrap();
        let _ = format!("{noise:?}");
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// A payload §3.3 never promised was well formed: any length, any bytes.
    /// `decode` must either refuse it or hand back a value whose own
    /// invariants hold — order within [`MAX_MODEL_ORDER`], level within
    /// [`MAX_LEVEL`] — and that value must round-trip through `encode_into`
    /// into a buffer sized by what it says it needs, byte for byte back
    /// through `decode` again.
    #[test]
    fn arbitrary_bytes_either_are_refused_or_decode_to_something_that_encodes_back() {
        let mut seed = 0xFEED_FACE_C0FF_EE00_u64;
        for _ in 0..500 {
            let length = usize::try_from(xorshift64(&mut seed) % 40).unwrap_or(0);
            let payload: Vec<u8> = (0..length)
                .map(|_| u8::try_from(xorshift64(&mut seed) % 256).unwrap_or(0))
                .collect();

            let Ok(noise) = ComfortNoise::decode(&payload) else {
                assert!(payload.is_empty(), "only an empty payload is refused");
                continue;
            };
            assert!(noise.level() <= MAX_LEVEL);
            assert!(noise.order() <= MAX_MODEL_ORDER);
            assert_eq!(noise.coefficients().len(), noise.order());

            let mut wire = vec![0_u8; 1 + noise.order()];
            let written = noise
                .encode_into(&mut wire)
                .expect("the buffer was sized for exactly what encode_into needs");
            assert_eq!(written, 1 + noise.order());
            let back = ComfortNoise::decode(&wire).expect("what was just encoded decodes");
            assert_eq!(
                back, noise,
                "payload {payload:?} round-tripped to something else"
            );

            // whatever it decoded to, generating noise from it never panics
            // and never produces a sample the frame's own type could not hold
            let mut generator = Generator::with_seed(seed);
            generator.received(noise);
            let mut frame = [0_i16; 32];
            generator.fill(&mut frame);
        }
    }
}
