// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! L16: sixteen-bit linear PCM on RTP, RFC 3551 §4.5.11 and the `audio/L16`
//! media type of RFC 2586.
//!
//! Nothing is compressed. Each sample is a sixteen-bit two's complement
//! value from -32768 to 32767, sent most significant octet first, "network
//! byte order" in the words of §4.5.11, which is the opposite of what this
//! crate's samples and a WAV file hold on every common machine. That is the
//! whole codec, and getting it backwards is the whole way to break it.
//!
//! What varies is the rate and the channel count. `audio/L16` requires a
//! `rate` and takes an optional `channels` defaulting to one (RFC 2586), and
//! any combination can be bound to a dynamic payload type:
//! `a=rtpmap:96 L16/16000`, `a=rtpmap:97 L16/48000/2`. Only two are static,
//! payload types 10 and 11, both at 44.1 kHz (RFC 3551 §6). [`Format`]
//! is one such combination.
//!
//! With more than one channel, the samples of one sampling instant go out
//! together, one after the other, before the next instant's (§4.1), and for
//! two channels the first is the left and the second the right. The RTP
//! timestamp counts sampling instants, not samples, so a stereo frame moves
//! it by as much as a mono one ([`Format::frame_ticks`]).

use core::fmt;

/// The encoding name on an `a=rtpmap` line, and the `audio/L16` subtype.
pub const ENCODING_NAME: &str = "L16";

/// The packetisation interval RFC 3551 §4.2 gives as the default for a
/// sample-based encoding such as L16, in milliseconds.
pub const DEFAULT_PTIME_MS: u32 = 20;

/// Octets in one sample.
pub const SAMPLE_OCTETS: usize = 2;

/// The static payload type for two channels at 44.1 kHz (RFC 3551 §6).
pub const STEREO_PAYLOAD_TYPE: u8 = 10;

/// The static payload type for one channel at 44.1 kHz (RFC 3551 §6).
pub const MONO_PAYLOAD_TYPE: u8 = 11;

/// The clock rate both static payload types are bound to.
pub const STATIC_CLOCK_RATE: u32 = 44_100;

/// Why a rate, a channel count or an `a=rtpmap` encoding was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// A clock rate of zero.
    ZeroRate,
    /// A channel count of zero.
    ZeroChannels,
    /// An encoding name other than `L16`.
    NotL16,
    /// Something that is not `name/rate` or `name/rate/channels` with
    /// decimal numbers that fit.
    Malformed,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroRate => "an L16 clock rate of zero",
            Self::ZeroChannels => "an L16 channel count of zero",
            Self::NotL16 => "not the L16 encoding",
            Self::Malformed => "not an rtpmap encoding of the form L16/rate[/channels]",
        })
    }
}

impl core::error::Error for FormatError {}

/// One rate and channel count that L16 is carried at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Format {
    clock_rate: u32,
    channels: u8,
}

impl Format {
    /// L16 at `clock_rate` hertz with `channels` interleaved channels.
    ///
    /// # Errors
    ///
    /// [`FormatError::ZeroRate`] and [`FormatError::ZeroChannels`].
    pub const fn new(clock_rate: u32, channels: u8) -> Result<Self, FormatError> {
        if clock_rate == 0 {
            return Err(FormatError::ZeroRate);
        }
        if channels == 0 {
            return Err(FormatError::ZeroChannels);
        }
        Ok(Self {
            clock_rate,
            channels,
        })
    }

    /// The format a static payload type names, if it names an L16 one.
    #[must_use]
    pub const fn from_payload_type(payload_type: u8) -> Option<Self> {
        let channels = match payload_type {
            STEREO_PAYLOAD_TYPE => 2,
            MONO_PAYLOAD_TYPE => 1,
            _ => return None,
        };
        Some(Self {
            clock_rate: STATIC_CLOCK_RATE,
            channels,
        })
    }

    /// The static payload type for this format, if it has one; every other
    /// format needs a dynamic binding.
    #[must_use]
    pub const fn payload_type(self) -> Option<u8> {
        match (self.clock_rate, self.channels) {
            (STATIC_CLOCK_RATE, 2) => Some(STEREO_PAYLOAD_TYPE),
            (STATIC_CLOCK_RATE, 1) => Some(MONO_PAYLOAD_TYPE),
            _ => None,
        }
    }

    /// The format an `a=rtpmap` encoding describes: `L16/<rate>` or
    /// `L16/<rate>/<channels>`, the part after the payload type.
    ///
    /// The encoding name is matched without regard to case, as media type
    /// names are; a missing channel count is one.
    ///
    /// # Errors
    ///
    /// [`FormatError::NotL16`] for another encoding, [`FormatError::Malformed`]
    /// for anything that does not parse, and the errors of [`Format::new`].
    pub fn from_rtpmap(encoding: &str) -> Result<Self, FormatError> {
        let mut fields = encoding.trim().split('/');
        let name = fields.next().unwrap_or_default();
        if !name.eq_ignore_ascii_case(ENCODING_NAME) {
            return Err(FormatError::NotL16);
        }
        let rate = fields
            .next()
            .and_then(parse_decimal::<u32>)
            .ok_or(FormatError::Malformed)?;
        let channels = match fields.next() {
            None => 1,
            Some(field) => parse_decimal::<u8>(field).ok_or(FormatError::Malformed)?,
        };
        if fields.next().is_some() {
            return Err(FormatError::Malformed);
        }
        Self::new(rate, channels)
    }

    /// The `a=rtpmap` encoding for this format, `L16/<rate>`, with
    /// `/<channels>` only when there is more than one (RFC 4566 §6 lets it be
    /// left out for one).
    #[must_use]
    pub const fn rtpmap(self) -> Rtpmap {
        Rtpmap(self)
    }

    /// The clock rate, which is also the sampling rate.
    #[must_use]
    pub const fn clock_rate(self) -> u32 {
        self.clock_rate
    }

    /// The channel count.
    #[must_use]
    pub const fn channels(self) -> u8 {
        self.channels
    }

    /// Octets in one sampling instant: one sample of every channel.
    #[must_use]
    pub const fn frame_bytes(self) -> usize {
        SAMPLE_OCTETS * self.channels as usize
    }

    /// Sampling instants in `millis` milliseconds, per channel.
    #[must_use]
    pub const fn frame_samples(self, millis: u32) -> usize {
        (self.clock_rate as usize).saturating_mul(millis as usize) / 1000
    }

    /// Octets a packet of `millis` milliseconds occupies on the wire.
    #[must_use]
    pub const fn frame_octets(self, millis: u32) -> usize {
        self.frame_samples(millis)
            .saturating_mul(self.frame_bytes())
    }

    /// How far the RTP timestamp moves for `millis` milliseconds: one tick
    /// per sampling instant, whatever the channel count.
    #[must_use]
    pub fn frame_ticks(self, millis: u32) -> u32 {
        let ticks = u64::from(self.clock_rate).saturating_mul(u64::from(millis)) / 1000;
        u32::try_from(ticks).unwrap_or(u32::MAX)
    }

    /// Encode interleaved samples into `octets`, big-endian.
    ///
    /// Converts as many whole sampling instants as both buffers hold and
    /// returns how many samples that was, so a trailing partial instant in
    /// either is left alone.
    pub fn encode_into(self, samples: &[i16], octets: &mut [u8]) -> usize {
        let width = self.channels as usize;
        let instants = (samples.len() / width).min(octets.len() / self.frame_bytes());
        let converted = instants * width;
        for (sample, pair) in samples
            .iter()
            .take(converted)
            .zip(octets.chunks_exact_mut(SAMPLE_OCTETS))
        {
            pair.copy_from_slice(&sample.to_be_bytes());
        }
        converted
    }

    /// Decode a payload into interleaved samples.
    ///
    /// Converts as many whole sampling instants as both buffers hold and
    /// returns how many samples that was. Octets past the last whole instant
    /// are not audio L16 can carry and are ignored.
    pub fn decode_into(self, octets: &[u8], samples: &mut [i16]) -> usize {
        let width = self.channels as usize;
        let instants = (octets.len() / self.frame_bytes()).min(samples.len() / width);
        let converted = instants * width;
        for (pair, sample) in octets
            .chunks_exact(SAMPLE_OCTETS)
            .zip(samples.iter_mut())
            .take(converted)
        {
            *sample = i16::from_be_bytes([
                pair.first().copied().unwrap_or(0),
                pair.get(1).copied().unwrap_or(0),
            ]);
        }
        converted
    }
}

fn parse_decimal<T: core::str::FromStr>(field: &str) -> Option<T> {
    if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

/// The `a=rtpmap` encoding of a [`Format`], written with [`fmt::Display`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rtpmap(Format);

impl fmt::Display for Rtpmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ENCODING_NAME}/{}", self.0.clock_rate)?;
        if self.0.channels > 1 {
            write!(f, "/{}", self.0.channels)?;
        }
        Ok(())
    }
}

/// Encode two channels given apart, `left` and `right`, as one stereo
/// payload.
///
/// Converts as many sampling instants as both sides and the payload hold,
/// and returns how many.
pub fn encode_stereo_into(left: &[i16], right: &[i16], octets: &mut [u8]) -> usize {
    let mut instants = 0;
    for ((l, r), out) in left
        .iter()
        .zip(right)
        .zip(octets.chunks_exact_mut(2 * SAMPLE_OCTETS))
    {
        let [l0, l1] = l.to_be_bytes();
        let [r0, r1] = r.to_be_bytes();
        out.copy_from_slice(&[l0, l1, r0, r1]);
        instants += 1;
    }
    instants
}

/// Decode a stereo payload into its two channels.
///
/// Converts as many whole sampling instants as the payload and both sides
/// hold, and returns how many.
pub fn decode_stereo_into(octets: &[u8], left: &mut [i16], right: &mut [i16]) -> usize {
    let mut instants = 0;
    for ((frame, l), r) in octets
        .chunks_exact(2 * SAMPLE_OCTETS)
        .zip(left.iter_mut())
        .zip(right.iter_mut())
    {
        if let [l0, l1, r0, r1] = *frame {
            *l = i16::from_be_bytes([l0, l1]);
            *r = i16::from_be_bytes([r0, r1]);
            instants += 1;
        }
    }
    instants
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PTIME_MS, ENCODING_NAME, Format, FormatError, MONO_PAYLOAD_TYPE,
        STEREO_PAYLOAD_TYPE, decode_stereo_into, encode_stereo_into,
    };

    #[test]
    fn samples_go_out_most_significant_octet_first() {
        let mono = Format::new(8_000, 1).unwrap();
        let samples = [0x1234_i16, -2, i16::MIN, i16::MAX, 0, 1];
        let mut octets = [0_u8; 12];
        assert_eq!(mono.encode_into(&samples, &mut octets), 6);
        assert_eq!(
            octets,
            [
                0x12, 0x34, 0xFF, 0xFE, 0x80, 0x00, 0x7F, 0xFF, 0x00, 0x00, 0x00, 0x01
            ]
        );
        let mut back = [0_i16; 6];
        assert_eq!(mono.decode_into(&octets, &mut back), 6);
        assert_eq!(back, samples);
    }

    #[test]
    fn stereo_interleaves_left_then_right_for_each_instant() {
        let stereo = Format::new(48_000, 2).unwrap();
        let left = [0x0102_i16, 0x0304];
        let right = [0x0A0B_i16, -1];
        let mut octets = [0_u8; 8];
        assert_eq!(encode_stereo_into(&left, &right, &mut octets), 2);
        assert_eq!(octets, [0x01, 0x02, 0x0A, 0x0B, 0x03, 0x04, 0xFF, 0xFF]);

        // the interleaved path produces the same payload
        let mut interleaved = [0_u8; 8];
        assert_eq!(
            stereo.encode_into(&[0x0102, 0x0A0B, 0x0304, -1], &mut interleaved),
            4
        );
        assert_eq!(interleaved, octets);

        let (mut l, mut r) = ([0_i16; 2], [0_i16; 2]);
        assert_eq!(decode_stereo_into(&octets, &mut l, &mut r), 2);
        assert_eq!((l, r), (left, right));
        let mut samples = [0_i16; 4];
        assert_eq!(stereo.decode_into(&octets, &mut samples), 4);
        assert_eq!(samples, [0x0102, 0x0A0B, 0x0304, -1]);
    }

    #[test]
    fn only_whole_sampling_instants_are_converted() {
        let stereo = Format::new(16_000, 2).unwrap();
        // three samples are one instant and a half; seven octets likewise
        let mut octets = [0xEE_u8; 8];
        assert_eq!(stereo.encode_into(&[1, 2, 3], &mut octets), 2);
        assert_eq!(&octets[4..], &[0xEE; 4], "the half instant is not written");
        let mut samples = [7_i16; 4];
        assert_eq!(stereo.decode_into(&octets[..7], &mut samples), 2);
        assert_eq!(samples, [1, 2, 7, 7]);
        // and the shorter of the two buffers decides
        assert_eq!(stereo.encode_into(&[1, 2, 3, 4], &mut [0; 6]), 2);
        assert_eq!(stereo.decode_into(&[0; 8], &mut [0; 3]), 2);
        let (mut l, mut r) = ([0_i16; 1], [0_i16; 4]);
        assert_eq!(decode_stereo_into(&[0; 11], &mut l, &mut r), 1);
        assert_eq!(encode_stereo_into(&[1, 2], &[3], &mut [0; 16]), 1);
    }

    #[test]
    fn a_frame_is_sized_by_rate_and_channels_and_ticks_by_instants() {
        assert_eq!(DEFAULT_PTIME_MS, 20);
        for (rate, samples) in [(8_000, 160), (16_000, 320), (44_100, 882), (48_000, 960)] {
            let mono = Format::new(rate, 1).unwrap();
            let stereo = Format::new(rate, 2).unwrap();
            assert_eq!(mono.frame_samples(20), samples);
            assert_eq!(stereo.frame_samples(20), samples);
            assert_eq!(mono.frame_octets(20), samples * 2);
            assert_eq!(stereo.frame_octets(20), samples * 4);
            assert_eq!(mono.frame_ticks(20), u32::try_from(samples).unwrap());
            assert_eq!(stereo.frame_ticks(20), u32::try_from(samples).unwrap());
        }
        assert_eq!(Format::new(8_000, 6).unwrap().frame_bytes(), 12);
        assert_eq!(
            Format::new(u32::MAX, 1).unwrap().frame_ticks(2_000),
            u32::MAX
        );
    }

    #[test]
    fn the_static_payload_types_are_the_two_at_44_1_khz() {
        let stereo = Format::from_payload_type(STEREO_PAYLOAD_TYPE).unwrap();
        let mono = Format::from_payload_type(MONO_PAYLOAD_TYPE).unwrap();
        assert_eq!((stereo.clock_rate(), stereo.channels()), (44_100, 2));
        assert_eq!((mono.clock_rate(), mono.channels()), (44_100, 1));
        assert_eq!(stereo.payload_type(), Some(10));
        assert_eq!(mono.payload_type(), Some(11));
        assert_eq!(Format::from_payload_type(0), None);
        assert_eq!(Format::from_payload_type(9), None);
        assert_eq!(Format::new(48_000, 2).unwrap().payload_type(), None);
        assert_eq!(Format::new(44_100, 3).unwrap().payload_type(), None);
    }

    #[test]
    fn the_rtpmap_encoding_round_trips_and_leaves_out_a_single_channel() {
        assert_eq!(ENCODING_NAME, "L16");
        for (text, rate, channels, written) in [
            ("L16/8000", 8_000, 1, "L16/8000"),
            ("L16/16000", 16_000, 1, "L16/16000"),
            ("L16/44100/2", 44_100, 2, "L16/44100/2"),
            ("L16/48000/2", 48_000, 2, "L16/48000/2"),
            ("l16/48000/1", 48_000, 1, "L16/48000"),
            (" L16/8000 ", 8_000, 1, "L16/8000"),
        ] {
            let format = Format::from_rtpmap(text).unwrap();
            assert_eq!((format.clock_rate(), format.channels()), (rate, channels));
            assert_eq!(format.rtpmap().to_string(), written);
        }
    }

    #[test]
    fn the_codec_sits_at_the_crate_root_beside_the_others() {
        let format = crate::l16::Format::new(8_000, 1).unwrap();
        assert_eq!(format.rtpmap().to_string(), "L16/8000");
        assert_eq!(
            crate::l16::ENCODING_NAME,
            crate::formats::l16::ENCODING_NAME
        );
    }

    #[test]
    fn a_format_needs_a_rate_and_a_channel() {
        assert_eq!(Format::new(0, 1), Err(FormatError::ZeroRate));
        assert_eq!(Format::new(8_000, 0), Err(FormatError::ZeroChannels));
        assert_eq!(Format::from_rtpmap("L16/0"), Err(FormatError::ZeroRate));
        assert_eq!(
            Format::from_rtpmap("L16/8000/0"),
            Err(FormatError::ZeroChannels)
        );
        assert_eq!(Format::from_rtpmap("PCMU/8000"), Err(FormatError::NotL16));
        assert_eq!(Format::from_rtpmap("L24/48000"), Err(FormatError::NotL16));
        for malformed in [
            "L16",
            "L16/",
            "L16/8k",
            "L16/+8000",
            "L16/8000/",
            "L16/8000/2/1",
            "L16/8000/256",
            "L16/99999999999",
        ] {
            assert_eq!(
                Format::from_rtpmap(malformed),
                Err(FormatError::Malformed),
                "{malformed}"
            );
        }
    }
}
