// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! G.722: seven kilohertz of audio in sixty-four kilobits, written from the
//! Recommendation.
//!
//! A filter pair splits the sixteen-kilohertz input into two bands of eight
//! (§5); the lower band is coded with six bits a sample and the higher with
//! two (§6); one octet carries one sample of each, so a twenty-millisecond
//! frame is three hundred and twenty samples and one hundred and sixty
//! octets. Everything is integer arithmetic on sixteen-bit words, because
//! that is what the Recommendation specifies and any other choice would
//! decode differently on the far end.
//!
//! Written in-tree rather than linked, and `docs/05-media.md` says why: the
//! library everyone reaches for is one `docs/02-clean-room.md` rules out, and
//! the Rust crate that looks free of it carries that library's own comments
//! word for word. A Recommendation is a specification, and a specification is
//! what this is implemented from.
//!
//! **The trap worth knowing before wiring this up:** RFC 3551 §4.5.2 fixes
//! G.722's RTP clock rate at 8000 even though it samples at 16000, "for
//! historical reasons". So a twenty-millisecond frame advances the RTP
//! timestamp by 160 while carrying 320 samples. [`SAMPLE_RATE`] and
//! [`CLOCK_RATE`] are separate constants here for exactly that reason, and a
//! caller that uses one where it means the other gets audio at half or twice
//! the speed with nothing to say it went wrong.

mod band;
mod qmf;
mod tables;

pub use band::Mode;

use band::{Band, Half};
use qmf::{Analysis, Synthesis};

/// What the codec hears and produces: sixteen kilohertz.
pub const SAMPLE_RATE: u32 = 16_000;

/// What RTP counts in, which is not the same thing (RFC 3551 §4.5.2).
pub const CLOCK_RATE: u32 = 8_000;

/// The static payload type RFC 3551 Table 4 gives it.
pub const PAYLOAD_TYPE: u8 = 9;

/// The name an `a=rtpmap` line carries.
pub const ENCODING_NAME: &str = "G722";

/// One channel; the Recommendation defines nothing else.
pub const CHANNELS: u8 = 1;

/// What a packet carries unless the negotiation says otherwise.
pub const DEFAULT_PTIME_MS: u32 = 20;

/// Samples in a frame of `millis` milliseconds, at the rate the codec hears.
#[must_use]
pub const fn frame_samples(millis: u32) -> usize {
    (SAMPLE_RATE as usize) * (millis as usize) / 1000
}

/// Octets in that frame: one per two samples, since each octet holds six bits
/// of the lower band and two of the higher.
#[must_use]
pub const fn frame_octets(millis: u32) -> usize {
    frame_samples(millis) / 2
}

/// RTP timestamp ticks in that frame, which is the octet count and not the
/// sample count (RFC 3551 §4.5.2).
#[must_use]
pub const fn frame_ticks(millis: u32) -> u32 {
    CLOCK_RATE * millis / 1000
}

/// The encoding half.
///
/// Stateful, because ADPCM is: the predictor and the step size carry from one
/// sample to the next, and a stream cut in half and encoded by two of these
/// is not the same stream.
#[derive(Debug, Clone)]
pub struct Encoder {
    filter: Analysis,
    lower: Band,
    higher: Band,
}

impl Encoder {
    /// A fresh encoder, in the state the Recommendation's reset condition
    /// describes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            filter: Analysis::new(),
            lower: Band::new(Half::Lower),
            higher: Band::new(Half::Higher),
        }
    }

    /// Put it back where it started, for a stream that begins again.
    pub fn reset(&mut self) {
        self.filter.reset();
        self.lower.reset();
        self.higher.reset();
    }

    /// Encode a frame, two samples to an octet.
    ///
    /// Converts as many whole sample pairs as both buffers allow and returns
    /// the octets written, so a caller that sized the two from
    /// [`frame_samples`] and [`frame_octets`] gets the whole frame and one
    /// that did not gets a number it can check. An odd trailing sample is
    /// left alone: half an octet cannot be written, and dropping it silently
    /// would put the two ends half a sample apart for the rest of the call.
    pub fn encode_into(&mut self, samples: &[i16], octets: &mut [u8]) -> usize {
        let pairs = (samples.len() / 2).min(octets.len());
        for (pair, octet) in samples
            .as_chunks::<2>()
            .0
            .iter()
            .zip(octets.iter_mut())
            .take(pairs)
        {
            let (low, high) = self
                .filter
                .split(*pair.first().unwrap_or(&0), *pair.get(1).unwrap_or(&0));
            let lower = self.lower.encode(low);
            let higher = self.higher.encode(high);
            *octet = (higher << 6) | (lower & 0x3f);
        }
        pairs
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// The decoding half.
#[derive(Debug, Clone)]
pub struct Decoder {
    filter: Synthesis,
    lower: Band,
    higher: Band,
    mode: Mode,
}

impl Decoder {
    /// A fresh decoder for a stream at `mode`.
    ///
    /// Almost every peer sends [`Mode::Rate64`]; the other two exist because
    /// the Recommendation gives the lower band's least significant bits to an
    /// auxiliary data channel, and a decoder that guesses wrong there
    /// reconstructs from bits that are not audio.
    #[must_use]
    pub fn new(mode: Mode) -> Self {
        Self {
            filter: Synthesis::new(),
            lower: Band::new(Half::Lower),
            higher: Band::new(Half::Higher),
            mode,
        }
    }

    /// Put it back where it started.
    pub fn reset(&mut self) {
        self.filter.reset();
        self.lower.reset();
        self.higher.reset();
    }

    /// Decode a frame, one octet to two samples.
    ///
    /// Returns the samples written, which is twice the octets consumed.
    pub fn decode_into(&mut self, octets: &[u8], samples: &mut [i16]) -> usize {
        let pairs = octets.len().min(samples.len() / 2);
        for (octet, pair) in octets
            .iter()
            .zip(samples.as_chunks_mut::<2>().0)
            .take(pairs)
        {
            let low = self.lower.decode(*octet & 0x3f, self.mode);
            let high = self.higher.decode(*octet >> 6, self.mode);
            let (first, second) = self.filter.join(low, high);
            *pair = [first, second];
        }
        pairs * 2
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(Mode::Rate64)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CLOCK_RATE, DEFAULT_PTIME_MS, Decoder, ENCODING_NAME, Encoder, Mode, PAYLOAD_TYPE,
        SAMPLE_RATE, frame_octets, frame_samples, frame_ticks,
    };

    fn tone(count: usize, hertz: f64, amplitude: f64) -> Vec<i16> {
        (0..count)
            .map(|n| {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "a sample index of this size is exact in f64"
                )]
                let t = n as f64 / f64::from(SAMPLE_RATE);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "the sine is bounded by the amplitude, which is inside i16"
                )]
                let sample = (amplitude * (core::f64::consts::TAU * hertz * t).sin()) as i16;
                sample
            })
            .collect()
    }

    /// The filter pair delays by twenty-two samples, and the first stretch of
    /// any stream is the step size climbing out of its reset value, so both
    /// are taken off before the two are compared.
    const DELAY: usize = 22;
    const SETTLE: usize = 2_000;

    fn signal_to_noise(reference: &[i16], decoded: &[i16]) -> f64 {
        let mut signal = 0.0_f64;
        let mut noise = 0.0_f64;
        for (a, b) in reference
            .iter()
            .zip(decoded.get(DELAY..).unwrap_or_default())
            .skip(SETTLE)
        {
            let x = f64::from(*a);
            let y = f64::from(*b);
            signal += x * x;
            noise += (x - y) * (x - y);
        }
        10.0 * (signal / noise.max(1.0)).log10()
    }

    // RFC 3551 §4.5.2, and the reason the two constants exist separately
    #[test]
    fn the_clock_rate_is_not_the_sample_rate() {
        assert_eq!(SAMPLE_RATE, 16_000);
        assert_eq!(CLOCK_RATE, 8_000);
        assert_eq!(PAYLOAD_TYPE, 9);
        assert_eq!(ENCODING_NAME, "G722");
        assert_eq!(frame_samples(DEFAULT_PTIME_MS), 320);
        assert_eq!(frame_octets(DEFAULT_PTIME_MS), 160);
        assert_eq!(frame_ticks(DEFAULT_PTIME_MS), 160);
        assert_eq!(frame_samples(10), 160);
        assert_eq!(frame_octets(10), 80);
        assert_eq!(frame_ticks(10), 80);
    }

    #[test]
    fn a_frame_is_half_as_many_octets_as_samples() {
        let mut encoder = Encoder::new();
        let samples = tone(frame_samples(20), 440.0, 8_000.0);
        let mut octets = vec![0_u8; frame_octets(20)];
        assert_eq!(encoder.encode_into(&samples, &mut octets), 160);

        let mut decoder = Decoder::default();
        let mut back = vec![0_i16; frame_samples(20)];
        assert_eq!(decoder.decode_into(&octets, &mut back), 320);
    }

    /// The number the codec exists for. G.722 at 64 kbit/s is specified to
    /// hold a wide margin over the difference signal; a tone in the lower
    /// band should come back with far more signal than error.
    #[test]
    fn a_tone_survives_the_round_trip() {
        for (hertz, floor) in [(300.0, 20.0), (1_000.0, 20.0), (3_000.0, 18.0)] {
            let mut encoder = Encoder::new();
            let mut decoder = Decoder::default();
            let samples = tone(16_000, hertz, 8_000.0);
            let mut octets = vec![0_u8; samples.len() / 2];
            encoder.encode_into(&samples, &mut octets);
            let mut back = vec![0_i16; samples.len()];
            decoder.decode_into(&octets, &mut back);

            // the filter pair delays by its length, so the comparison starts
            // after the delay line has filled and the step size has settled
            let ratio = signal_to_noise(&samples, &back);
            assert!(
                ratio > floor,
                "{hertz} Hz came back {ratio:.1} dB above the error, wanted {floor}"
            );
        }
    }

    /// The half of the band G.711 cannot reach, which is the entire argument
    /// for using this codec at all.
    #[test]
    fn the_wideband_half_survives_too() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::default();
        let samples = tone(16_000, 5_500.0, 6_000.0);
        let mut octets = vec![0_u8; samples.len() / 2];
        encoder.encode_into(&samples, &mut octets);
        let mut back = vec![0_i16; samples.len()];
        decoder.decode_into(&octets, &mut back);

        let energy: f64 = back
            .iter()
            .skip(4_000)
            .map(|s| f64::from(*s) * f64::from(*s))
            .sum();
        let sent: f64 = samples
            .iter()
            .skip(4_000)
            .map(|s| f64::from(*s) * f64::from(*s))
            .sum();
        assert!(
            energy > sent / 8.0,
            "5.5 kHz went in at {sent:.0} and came back at {energy:.0}, so the higher band is lost"
        );
    }

    /// Silence does not decode to exact zeros and cannot: the quantizer has
    /// no zero interval, so the smallest thing either band can say is one
    /// step. What has to hold is that the step falls back to near its floor,
    /// so what is left is far below anything audible.
    #[test]
    fn silence_decays_to_far_below_anything_audible() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::default();
        let samples = vec![0_i16; 16_000];
        let mut octets = vec![0_u8; samples.len() / 2];
        encoder.encode_into(&samples, &mut octets);
        let mut back = vec![0_i16; samples.len()];
        decoder.decode_into(&octets, &mut back);

        let residue = back
            .iter()
            .skip(SETTLE)
            .map(|s| i32::from(*s).abs())
            .max()
            .unwrap_or(0);
        // full scale is 16384, so this is more than sixty decibels down
        assert!(residue < 16, "silence left a residue of {residue}");
    }

    /// Encoding a stream in one call and in twenty must give the same octets,
    /// or the state does not really carry across a frame boundary and every
    /// packet edge is a click.
    #[test]
    fn framing_does_not_change_the_bits() {
        let samples = tone(3_200, 700.0, 9_000.0);

        let mut whole = Encoder::new();
        let mut once = vec![0_u8; samples.len() / 2];
        whole.encode_into(&samples, &mut once);

        let mut piecewise = Encoder::new();
        let mut many = Vec::with_capacity(once.len());
        for chunk in samples.chunks(160) {
            let mut out = vec![0_u8; chunk.len() / 2];
            piecewise.encode_into(chunk, &mut out);
            many.extend_from_slice(&out);
        }
        assert_eq!(once, many);
    }

    #[test]
    fn a_decoder_reset_starts_the_stream_again() {
        let samples = tone(1_600, 800.0, 7_000.0);
        let mut encoder = Encoder::new();
        let mut octets = vec![0_u8; samples.len() / 2];
        encoder.encode_into(&samples, &mut octets);

        let mut first = Decoder::default();
        let mut a = vec![0_i16; samples.len()];
        first.decode_into(&octets, &mut a);
        first.reset();
        let mut b = vec![0_i16; samples.len()];
        first.decode_into(&octets, &mut b);
        assert_eq!(a, b, "a reset decoder did not repeat itself");
    }

    /// A decoder told the wrong mode reads bits that are not audio. It must
    /// still produce something bounded rather than noise at full scale — the
    /// auxiliary-data modes exist so a stream can be decoded at all, not so
    /// it can be decoded well.
    #[test]
    fn the_narrower_modes_still_track_the_signal() {
        let samples = tone(8_000, 600.0, 8_000.0);
        let mut encoder = Encoder::new();
        let mut octets = vec![0_u8; samples.len() / 2];
        encoder.encode_into(&samples, &mut octets);

        let mut ratios = Vec::new();
        for mode in [Mode::Rate64, Mode::Rate56, Mode::Rate48] {
            let mut decoder = Decoder::new(mode);
            let mut back = vec![0_i16; samples.len()];
            decoder.decode_into(&octets, &mut back);
            ratios.push(signal_to_noise(&samples, &back));
        }
        let (full, reduced, narrow) = (
            *ratios.first().unwrap_or(&0.0),
            *ratios.get(1).unwrap_or(&0.0),
            *ratios.get(2).unwrap_or(&0.0),
        );
        assert!(
            full > reduced,
            "64 kbit/s gave {full:.1} dB, 56 gave {reduced:.1}"
        );
        assert!(
            reduced > narrow,
            "56 kbit/s gave {reduced:.1} dB, 48 gave {narrow:.1}"
        );
        assert!(
            narrow > 8.0,
            "48 kbit/s gave {narrow:.1} dB, which is noise"
        );
    }

    #[test]
    fn a_buffer_too_small_converts_what_fits_and_says_so() {
        let mut encoder = Encoder::new();
        let samples = tone(320, 440.0, 8_000.0);
        let mut cramped = vec![0_u8; 100];
        assert_eq!(encoder.encode_into(&samples, &mut cramped), 100);

        let mut decoder = Decoder::default();
        let mut few = vec![0_i16; 50];
        assert_eq!(decoder.decode_into(&cramped, &mut few), 50);
    }

    /// An odd sample cannot be half an octet, and taking it would leave the
    /// two ends of the call half a sample apart from then on.
    #[test]
    fn an_odd_trailing_sample_is_left_where_it_is() {
        let mut encoder = Encoder::new();
        let samples = tone(321, 440.0, 8_000.0);
        let mut octets = vec![0_u8; 200];
        assert_eq!(encoder.encode_into(&samples, &mut octets), 160);
    }

    /// Full-scale input must not wrap into the opposite sign anywhere in the
    /// chain, which is what the saturating arithmetic in §6.2 is for. Full
    /// scale here is §5.1's, not the word's: "limited to a range of –16384 to
    /// 16383", because the converter's most significant bit sits at the third
    /// bit of the word.
    #[test]
    fn a_signal_at_the_top_of_the_scale_does_not_wrap() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::default();
        let samples = tone(16_000, 400.0, 16_383.0);
        let mut octets = vec![0_u8; samples.len() / 2];
        encoder.encode_into(&samples, &mut octets);
        let mut back = vec![0_i16; samples.len()];
        decoder.decode_into(&octets, &mut back);

        for (n, sample) in back.iter().enumerate() {
            assert!(
                (-16_384..=16_383).contains(sample),
                "sample {n} left the range §5.1 fixes, at {sample}"
            );
        }
        let ratio = signal_to_noise(&samples, &back);
        assert!(
            ratio > 18.0,
            "a full-scale tone came back {ratio:.1} dB above the error, so something wrapped"
        );
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Octets nobody encoded: every bit pattern is a legal codeword, so
    /// `decode_into` has no invalid input to refuse, only bytes it has to
    /// turn into something. It must never panic, and §5.1's range is a
    /// property of every band's `decode`, not just of what this codec's own
    /// encoder happens to produce — so it has to hold for these octets too.
    #[test]
    fn arbitrary_octets_decode_without_panicking_and_stay_inside_the_range() {
        let mut seed = 0x0DEC_0DED_BAD5_EED5_u64;
        for _ in 0..150 {
            let mode = match xorshift64(&mut seed) % 3 {
                0 => Mode::Rate64,
                1 => Mode::Rate56,
                _ => Mode::Rate48,
            };
            let mut decoder = Decoder::new(mode);
            for _ in 0..8 {
                let length = usize::try_from(xorshift64(&mut seed) % 400).unwrap_or(0);
                let octets: Vec<u8> = (0..length)
                    .map(|_| u8::try_from(xorshift64(&mut seed) % 256).unwrap_or(0))
                    .collect();
                let mut samples = vec![0_i16; octets.len() * 2];
                let written = decoder.decode_into(&octets, &mut samples);
                assert_eq!(written, octets.len() * 2);
                for sample in &samples[..written] {
                    assert!(
                        (-16_384..=16_383).contains(sample),
                        "{mode:?}: sample {sample} left the range S5.1 fixes"
                    );
                }
            }
        }
    }

    /// Samples nobody's microphone produced — full-scale runs, alternating
    /// full scale, and plain noise — go into the encoder across several
    /// frames of arbitrary, including odd, length. Encoding must never panic
    /// and, fed straight back through a fresh decoder, must never leave the
    /// range either.
    #[test]
    fn arbitrary_samples_encode_and_round_trip_without_panicking() {
        let mut seed = 0x51DE_BA0D_600D_F00D_u64;
        for _ in 0..150 {
            let mut encoder = Encoder::new();
            let mut decoder = Decoder::default();
            for _ in 0..8 {
                let length = usize::try_from(xorshift64(&mut seed) % 400).unwrap_or(0);
                let pattern = xorshift64(&mut seed) % 3;
                let samples: Vec<i16> = (0..length)
                    .map(|index| match pattern {
                        0 if index % 2 == 0 => i16::MAX,
                        0 => i16::MIN,
                        1 => i16::MAX,
                        _ => {
                            let top = xorshift64(&mut seed) >> 48;
                            let unsigned = u16::try_from(top).unwrap_or(0);
                            i16::try_from(i32::from(unsigned) - 32_768).unwrap_or(0)
                        }
                    })
                    .collect();
                let mut octets = vec![0_u8; samples.len() / 2];
                let written = encoder.encode_into(&samples, &mut octets);
                assert_eq!(written, samples.len() / 2);

                let mut back = vec![0_i16; written * 2];
                let produced = decoder.decode_into(&octets[..written], &mut back);
                assert_eq!(produced, written * 2);
                for sample in &back[..produced] {
                    assert!((-16_384..=16_383).contains(sample));
                }
            }
        }
    }
}
