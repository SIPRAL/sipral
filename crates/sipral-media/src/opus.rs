// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Opus, the one codec in this crate that is linked rather than written.
//!
//! libopus is built from vendored source by `opusic-sys` and reached through
//! the `opus` crate. It is BSD-3-Clause with royalty-free patent grants; see
//! `THIRD-PARTY-NOTICES.md` and `docs/05-media.md`.
//!
//! This module wraps it as one channel, one of Opus's five rates and six frame
//! durations, with typed errors. No binding type appears in a signature, and
//! wrong-length frames are refused here rather than in C.
//!
//! # Two rules of RFC 7587 that are easy to get wrong
//!
//! The RTP timestamp advances at [`CLOCK_RATE`] whatever rate the codec is
//! fed at (§4.1), so a 20 ms frame at 8 kHz moves it by 960 and not by 160.
//! [`FrameDuration::timestamp_increment`] is that number, and it is the whole
//! of Table 2's first row.
//!
//! And `a=rtpmap` reads `opus/48000/2` even for a stream that is mono in both
//! directions (§7): [`RTPMAP_CHANNELS`] is a rule of the payload format, not
//! a description of what is being sent. The line itself is written in
//! `sipral-core`, which owns SDP and the `fmtp` parameters — `maxplaybackrate`,
//! `stereo`, `useinbandfec`, `usedtx`, `ptime`. What those parameters settle
//! on arrives here as a rate, a duration, a bitrate and two switches.
//!
//! # Loss
//!
//! [`Decoder::recover`] decodes the in-band FEC copy of a lost frame from the
//! packet after it; [`Decoder::conceal`] extrapolates when there is none. On
//! the encoder, [`Encoder::set_inband_fec`] does nothing until
//! [`Encoder::set_expected_loss`] reports loss.
//!
//! Nothing allocates after construction.

use ::opus as libopus;
use core::fmt;

/// The rate the RTP timestamp advances at, in hertz, for every mode and every
/// sampling rate Opus runs at (RFC 7587 §4.1).
///
/// Not the rate the codec is fed at. See [`SampleRate`] for that.
pub const CLOCK_RATE: u32 = 48_000;

/// Channels this module encodes and decodes: one.
///
/// The pipeline around it is mono, and a telephone call has nothing to put in
/// a second channel. A stereo stream from the far end still decodes through a
/// mono decoder, because Opus carries the channel count in the bitstream and
/// downmixes on the way out.
pub const CHANNELS: u8 = 1;

/// What the channel count on an `a=rtpmap` line must say: two, whatever is
/// actually being sent (RFC 7587 §7).
///
/// It looks like a bug every time somebody reads the SDP, and it is not one.
pub const RTPMAP_CHANNELS: u8 = 2;

/// The encoding name on an `a=rtpmap` line, from the `audio/opus` media type
/// registered in RFC 7587 §6.1. There is no static payload type; the binding
/// is always dynamic.
pub const ENCODING_NAME: &str = "opus";

/// The packetisation interval to offer when nothing says otherwise, in
/// milliseconds. Twenty, as for G.711, and what almost every peer expects.
pub const DEFAULT_PTIME_MS: u32 = 20;

/// The longest one Opus frame may be, in octets.
///
/// RFC 6716 §3.2.1 can represent at most 255*4+255 as a frame length, and
/// requirement R2 forbids exceeding it so that a gateway can always
/// repacketise. At 20 ms this is 510 kbit/s, which is [`MAX_BITRATE`].
pub const MAX_FRAME_BYTES: usize = 1_275;

/// The lowest bitrate Opus is defined at, in bits per second (RFC 7587 §3.1).
pub const MIN_BITRATE: u32 = 6_000;

/// And the highest.
pub const MAX_BITRATE: u32 = 510_000;

/// The sampling rates Opus runs at: the five audio bandwidths of RFC 7587
/// Table 1, and no others.
///
/// This is the rate samples cross the API at, not the rate on the wire —
/// Opus decides its internal bandwidth for itself from the bitrate and the
/// signal, and a decoder at any of these rates decodes a packet encoded at
/// any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SampleRate {
    /// 8 kHz, narrowband. What a leg bridged to G.711 arrives at, and the
    /// only rate here that buys nothing over G.711 but the bitrate.
    Narrowband,
    /// 12 kHz, mediumband.
    Mediumband,
    /// 16 kHz, wideband. The rate "HD voice" means, and the one worth
    /// defaulting to against a carrier that will take it.
    Wideband,
    /// 24 kHz, super-wideband.
    SuperWideband,
    /// 48 kHz, fullband, and the rate the timestamp clock already runs at.
    Fullband,
}

impl SampleRate {
    /// The rate in hertz.
    #[must_use]
    pub const fn hertz(self) -> u32 {
        match self {
            Self::Narrowband => 8_000,
            Self::Mediumband => 12_000,
            Self::Wideband => 16_000,
            Self::SuperWideband => 24_000,
            Self::Fullband => 48_000,
        }
    }

    /// The rate a number of hertz names.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedRate`] for anything but the five. 44100 is
    /// the one that gets asked for; it is a device rate, and it belongs on
    /// the far side of [`crate::resample`].
    pub const fn from_hertz(hertz: u32) -> Result<Self, CodecError> {
        match hertz {
            8_000 => Ok(Self::Narrowband),
            12_000 => Ok(Self::Mediumband),
            16_000 => Ok(Self::Wideband),
            24_000 => Ok(Self::SuperWideband),
            48_000 => Ok(Self::Fullband),
            _ => Err(CodecError::UnsupportedRate { hertz }),
        }
    }
}

/// The frame durations Opus encodes: the six columns of RFC 7587 Table 2.
///
/// Named in microseconds because the shortest is two and a half milliseconds
/// and half a millisecond does not fit in an integer count of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FrameDuration {
    /// 2.5 ms. Table 2 marks this unsupported in the voice mode: Opus will
    /// encode it, by dropping to the MDCT layer, and the result is a packet
    /// per 2.5 ms of audio, which is header overhead nobody wants on a call.
    Micros2500,
    /// 5 ms, with the same caveat.
    Micros5000,
    /// 10 ms.
    Micros10000,
    /// 20 ms, which is [`DEFAULT_PTIME_MS`] and what a peer assumes.
    Micros20000,
    /// 40 ms.
    Micros40000,
    /// 60 ms. Longest Opus encodes in one frame; a longer packet is several
    /// frames, which is not what this module produces.
    Micros60000,
}

impl FrameDuration {
    /// The duration in microseconds.
    #[must_use]
    pub const fn micros(self) -> u32 {
        match self {
            Self::Micros2500 => 2_500,
            Self::Micros5000 => 5_000,
            Self::Micros10000 => 10_000,
            Self::Micros20000 => 20_000,
            Self::Micros40000 => 40_000,
            Self::Micros60000 => 60_000,
        }
    }

    /// The duration a number of microseconds names.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedFrame`] for anything else. A peer that asks
    /// for 30 ms with `a=ptime` is asking for something Opus cannot cut, and
    /// the answer is to say so rather than to let libopus refuse the encode
    /// once a call is up.
    pub const fn from_micros(micros: u32) -> Result<Self, CodecError> {
        match micros {
            2_500 => Ok(Self::Micros2500),
            5_000 => Ok(Self::Micros5000),
            10_000 => Ok(Self::Micros10000),
            20_000 => Ok(Self::Micros20000),
            40_000 => Ok(Self::Micros40000),
            60_000 => Ok(Self::Micros60000),
            _ => Err(CodecError::UnsupportedFrame { micros }),
        }
    }

    /// How many samples one frame holds at `rate`, per channel.
    ///
    /// Every one of the thirty combinations comes out whole, which is why the
    /// short durations are legal at 8 kHz at all: 2.5 ms is twenty samples.
    #[must_use]
    pub const fn samples(self, rate: SampleRate) -> usize {
        (rate.hertz() as usize).saturating_mul(self.micros() as usize) / 1_000_000
    }

    /// How far the RTP timestamp moves for one such frame — the first row of
    /// RFC 7587 Table 2, and the same numbers whatever rate the codec runs at,
    /// because the timestamp clock is [`CLOCK_RATE`] and nothing else.
    #[must_use]
    pub const fn timestamp_increment(self) -> u32 {
        match self {
            Self::Micros2500 => 120,
            Self::Micros5000 => 240,
            Self::Micros10000 => 480,
            Self::Micros20000 => 960,
            Self::Micros40000 => 1_920,
            Self::Micros60000 => 2_880,
        }
    }

    /// The largest packet one frame of this duration can occupy, in octets.
    ///
    /// An upper bound, and a loose one at telephony bitrates, but the number
    /// a caller sizing a packet buffer once at call setup needs. The speech
    /// layer codes 40 and 60 ms as a single Opus frame, so those would fit in
    /// [`MAX_FRAME_BYTES`] plus a table-of-contents octet; the MDCT layer
    /// cannot code more than 20 ms at a time and packs two or three frames
    /// into one packet instead (RFC 6716 §3.2.5), which costs the frame-count
    /// octet and a two-octet length for every frame but the last.
    #[must_use]
    pub const fn max_packet_bytes(self) -> usize {
        let frames = self.opus_frames();
        let header = if frames == 1 { 1 } else { 2 + 2 * (frames - 1) };
        header + frames * MAX_FRAME_BYTES
    }

    /// How many Opus frames the MDCT layer would need for this duration,
    /// which is what bounds [`max_packet_bytes`](Self::max_packet_bytes).
    const fn opus_frames(self) -> usize {
        match self {
            Self::Micros2500 | Self::Micros5000 | Self::Micros10000 | Self::Micros20000 => 1,
            Self::Micros40000 => 2,
            Self::Micros60000 => 3,
        }
    }
}

/// Why an encode, a decode or a setting was refused.
///
/// Everything libopus can say is folded into this, so nothing from the
/// bindings crosses this crate's boundary. The last four variants are the
/// library's own codes and should not be reachable through this API: the
/// arguments it would refuse are checked here first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// A sampling rate Opus does not run at.
    UnsupportedRate {
        /// What was asked for, in hertz.
        hertz: u32,
    },
    /// A frame duration Opus does not cut.
    UnsupportedFrame {
        /// What was asked for, in microseconds.
        micros: u32,
    },
    /// A bitrate outside [`MIN_BITRATE`] to [`MAX_BITRATE`].
    UnsupportedBitrate {
        /// What was asked for, in bits per second.
        bits_per_second: u32,
    },
    /// A packet loss estimate that is not a percentage.
    UnsupportedLoss {
        /// What was asked for.
        percent: u32,
    },
    /// A frame of samples that is not the length this codec was built for.
    FrameLength {
        /// What the rate and duration come to.
        expected: usize,
        /// What was handed over.
        supplied: usize,
    },
    /// The slice offered was too short for what had to go in it.
    BufferTooSmall {
        /// How long it was.
        supplied: usize,
    },
    /// The payload is not an Opus packet, or is one that was damaged on the
    /// way. An empty payload lands here too; a gap is [`Decoder::conceal`],
    /// not a zero-length packet.
    InvalidPacket,
    /// libopus refused an argument. Reaching this means a check above it is
    /// missing.
    Rejected,
    /// libopus could not allocate a codec state.
    OutOfMemory,
    /// libopus failed for a reason of its own.
    Internal,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnsupportedRate { hertz } => {
                write!(f, "{hertz} Hz is not one of the five rates Opus runs at")
            }
            Self::UnsupportedFrame { micros } => {
                write!(f, "{micros} us is not a frame duration Opus cuts")
            }
            Self::UnsupportedBitrate { bits_per_second } => write!(
                f,
                "{bits_per_second} bit/s is outside {MIN_BITRATE} to {MAX_BITRATE}"
            ),
            Self::UnsupportedLoss { percent } => {
                write!(f, "a loss estimate of {percent} is not a percentage")
            }
            Self::FrameLength { expected, supplied } => {
                write!(f, "a frame of {supplied} samples, {expected} expected")
            }
            Self::BufferTooSmall { supplied } => {
                write!(f, "a buffer of {supplied}, which is too short")
            }
            Self::InvalidPacket => f.write_str("not a decodable Opus packet"),
            Self::Rejected => f.write_str("libopus refused an argument"),
            Self::OutOfMemory => f.write_str("libopus could not allocate"),
            Self::Internal => f.write_str("libopus failed internally"),
        }
    }
}

impl core::error::Error for CodecError {}

/// One error from the bindings as one of ours.
///
/// `buffer` is the length of the slice the failing call was given, which is
/// the one thing `OPUS_BUFFER_TOO_SMALL` does not carry. Calls that pass no
/// slice pass zero and cannot produce that code.
fn translate(error: &libopus::Error, buffer: usize) -> CodecError {
    match error.code() {
        libopus::ErrorCode::BufferTooSmall => CodecError::BufferTooSmall { supplied: buffer },
        libopus::ErrorCode::InvalidPacket => CodecError::InvalidPacket,
        libopus::ErrorCode::BadArg => CodecError::Rejected,
        libopus::ErrorCode::AllocFail => CodecError::OutOfMemory,
        libopus::ErrorCode::InternalError
        | libopus::ErrorCode::InvalidState
        | libopus::ErrorCode::Unimplemented
        | libopus::ErrorCode::Unknown => CodecError::Internal,
    }
}

/// One outgoing stream's encoder, at a fixed rate and frame duration.
///
/// Built in the voice mode: RFC 7587 §3 splits Opus into a voice mode and an
/// audio mode, and this is a telephony stack. The difference is not a tuning
/// preference — in-band FEC exists only in the voice mode (§3.3), so choosing
/// the audio mode would give up [`Encoder::set_inband_fec`] along with it.
///
/// The bitrate libopus picks for itself is a function of the rate and is a
/// reasonable place to start; RFC 7587 §3.1.1 gives the sweet spots worth
/// setting instead, and [`set_bitrate`](Self::set_bitrate) is how.
pub struct Encoder {
    inner: libopus::Encoder,
    rate: SampleRate,
    frame: FrameDuration,
    /// One for a call's stream, two for a stereo recording.
    channels: u8,
}

impl Encoder {
    /// An encoder for a stream at `rate`, cutting frames of `frame`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus will not build the state, which at these
    /// arguments means it could not allocate.
    pub fn new(rate: SampleRate, frame: FrameDuration) -> Result<Self, CodecError> {
        let inner = libopus::Encoder::new(
            rate.hertz(),
            libopus::Channels::Mono,
            libopus::Application::Voip,
        )
        .map_err(|error| translate(&error, 0))?;
        Ok(Self {
            inner,
            rate,
            frame,
            channels: CHANNELS,
        })
    }

    /// A two-channel encoder, for a file rather than a call: a recording
    /// with the local side on the left and the remote side on the right.
    ///
    /// Nothing on a call's wire is stereo — [`CHANNELS`] says why — but a
    /// recording kept in Opus is, and encoding the two sides as one stereo
    /// stream keeps them in one file on one clock. Still the voice mode: the
    /// two channels are two people talking.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus will not build the state.
    pub fn stereo(rate: SampleRate, frame: FrameDuration) -> Result<Self, CodecError> {
        let inner = libopus::Encoder::new(
            rate.hertz(),
            libopus::Channels::Stereo,
            libopus::Application::Voip,
        )
        .map_err(|error| translate(&error, 0))?;
        Ok(Self {
            inner,
            rate,
            frame,
            channels: 2,
        })
    }

    /// The rate it was built at.
    #[must_use]
    pub const fn rate(&self) -> SampleRate {
        self.rate
    }

    /// The frame duration it was built at.
    #[must_use]
    pub const fn frame(&self) -> FrameDuration {
        self.frame
    }

    /// How many samples one frame is in each channel.
    /// [`encode`](Self::encode) takes exactly this many from a mono encoder,
    /// and twice this many, interleaved, from a [`stereo`](Self::stereo) one.
    #[must_use]
    pub const fn frame_samples(&self) -> usize {
        self.frame.samples(self.rate)
    }

    /// One, or two for an encoder built with [`stereo`](Self::stereo).
    #[must_use]
    pub const fn channels(&self) -> u8 {
        self.channels
    }

    /// How far the encoder's output lags its input, in samples at the rate
    /// it was built at: the delay libopus reports for the configuration it
    /// is in, which is what a decoder has to discard from the front of the
    /// stream to line the audio back up.
    ///
    /// Asked of libopus because it depends on rate and mode.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus refuses the query.
    pub fn lookahead(&mut self) -> Result<u32, CodecError> {
        let samples = self
            .inner
            .get_lookahead()
            .map_err(|error| translate(&error, 0))?;
        u32::try_from(samples).map_err(|_| CodecError::Internal)
    }

    /// [`lookahead`](Self::lookahead) at 48 kHz, rounded up: the pre-skip an
    /// Ogg Opus identification header carries for a stream this encoder
    /// produced. RFC 7845 §4.2 counts it at 48 kHz whatever rate the input
    /// was at.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus refuses the query, and
    /// [`CodecError::Internal`] for a delay no sixteen-bit field holds.
    pub fn pre_skip(&mut self) -> Result<u16, CodecError> {
        let at_rate = u64::from(self.lookahead()?);
        let rate = u64::from(self.rate.hertz());
        let at_48k = (at_rate * u64::from(CLOCK_RATE)).div_ceil(rate);
        u16::try_from(at_48k).map_err(|_| CodecError::Internal)
    }

    /// Aim for `bits_per_second`.
    ///
    /// This is a target for a variable-rate encoder, not a promise about any
    /// one packet. RFC 7587 §3.1.1: 8 to 12 kbit/s for narrowband speech, 16
    /// to 20 for wideband, 28 to 40 for fullband.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedBitrate`] outside [`MIN_BITRATE`] to
    /// [`MAX_BITRATE`], where libopus would clamp silently.
    pub fn set_bitrate(&mut self, bits_per_second: u32) -> Result<(), CodecError> {
        let out_of_range = CodecError::UnsupportedBitrate { bits_per_second };
        if !(MIN_BITRATE..=MAX_BITRATE).contains(&bits_per_second) {
            return Err(out_of_range);
        }
        let bits = i32::try_from(bits_per_second).map_err(|_| out_of_range)?;
        self.inner
            .set_bitrate(libopus::Bitrate::Bits(bits))
            .map_err(|error| translate(&error, 0))
    }

    /// Let the encoder spend bits on in-band forward error correction.
    ///
    /// On its own this changes nothing: libopus adds the redundant copy of
    /// the previous frame only when it also believes there is loss, which is
    /// what [`set_expected_loss`](Self::set_expected_loss) is for. Both are
    /// needed, and the far end has to be willing to use it — that is the
    /// `useinbandfec` parameter of RFC 7587 §6.1, negotiated in
    /// `sipral-core`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus refuses the setting.
    pub fn set_inband_fec(&mut self, enabled: bool) -> Result<(), CodecError> {
        self.inner
            .set_inband_fec(enabled)
            .map_err(|error| translate(&error, 0))
    }

    /// Tell the encoder how much of what it sends is expected to go missing.
    ///
    /// It trades quality for robustness against this number, and it is the
    /// switch that makes [`set_inband_fec`](Self::set_inband_fec) do
    /// anything. The receive-side loss rate from RTCP is the number to feed
    /// it; a stale one costs bitrate for nothing.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedLoss`] above 100.
    pub fn set_expected_loss(&mut self, percent: u32) -> Result<(), CodecError> {
        let out_of_range = CodecError::UnsupportedLoss { percent };
        if percent > 100 {
            return Err(out_of_range);
        }
        let percent = i32::try_from(percent).map_err(|_| out_of_range)?;
        self.inner
            .set_packet_loss_perc(percent)
            .map_err(|error| translate(&error, 0))
    }

    /// Stop sending during silence.
    ///
    /// With this on, [`encode`](Self::encode) returns one or two octets for a
    /// frame libopus decided not to transmit, and the caller drops it instead
    /// of putting it in a packet. The receiver's decoder conceals the gap,
    /// which is why RFC 7587 §3.1.3 discourages RFC 3389 comfort noise on an
    /// Opus stream — the codec already has an answer, and it is a better one.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus refuses the setting.
    pub fn set_dtx(&mut self, enabled: bool) -> Result<(), CodecError> {
        self.inner
            .set_dtx(enabled)
            .map_err(|error| translate(&error, 0))
    }

    /// Encode one frame into `packet`, returning how many octets it took.
    ///
    /// `samples` must be exactly [`frame_samples`](Self::frame_samples) long
    /// on a mono encoder, and that many interleaved pairs on a stereo one.
    /// `packet` should be [`FrameDuration::max_packet_bytes`] long: libopus
    /// silently lowers quality to fit a shorter one.
    ///
    /// A return of one or two octets means DTX decided the frame was not
    /// worth sending; see [`set_dtx`](Self::set_dtx).
    ///
    /// # Errors
    ///
    /// [`CodecError::FrameLength`] for a frame of the wrong length, and
    /// [`CodecError::BufferTooSmall`] for a packet buffer with no room at all.
    pub fn encode(&mut self, samples: &[i16], packet: &mut [u8]) -> Result<usize, CodecError> {
        let expected = self.frame_samples() * usize::from(self.channels);
        if samples.len() != expected {
            return Err(CodecError::FrameLength {
                expected,
                supplied: samples.len(),
            });
        }
        let room = packet.len();
        // libopus calls a zero-length output a bad argument rather than a
        // small buffer, which is the wrong thing to tell whoever sized it
        if room == 0 {
            return Err(CodecError::BufferTooSmall { supplied: room });
        }
        self.inner
            .encode(samples, packet)
            .map_err(|error| translate(&error, room))
    }

    /// Forget the stream: a new call, or a codec change mid-call.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus refuses to reset.
    pub fn reset(&mut self) -> Result<(), CodecError> {
        self.inner
            .reset_state()
            .map_err(|error| translate(&error, 0))
    }
}

/// Written out rather than derived: the state behind it is a C pointer that
/// nobody can read and that changes on every frame.
impl fmt::Debug for Encoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Encoder")
            .field("rate", &self.rate)
            .field("frame", &self.frame)
            .field("channels", &self.channels)
            .finish_non_exhaustive()
    }
}

/// One incoming stream's decoder, at a fixed rate and frame duration.
///
/// The rate is the rate samples come out at, and it need not be the rate the
/// far end encoded at — Opus resamples internally, so a decoder built for a
/// narrowband device plays a fullband stream without anything in between.
///
/// The frame duration is what the stream was packetised at, and it is used
/// for the two calls that have no packet to read a duration from:
/// [`conceal`](Self::conceal) and [`recover`](Self::recover). A packet that
/// arrives carrying some other duration still decodes, as long as the slice
/// offered has room for it.
pub struct Decoder {
    inner: libopus::Decoder,
    rate: SampleRate,
    frame: FrameDuration,
}

impl Decoder {
    /// A decoder producing samples at `rate`, for a stream packetised at
    /// `frame`.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus will not build the state, which at these
    /// arguments means it could not allocate.
    pub fn new(rate: SampleRate, frame: FrameDuration) -> Result<Self, CodecError> {
        let inner = libopus::Decoder::new(rate.hertz(), libopus::Channels::Mono)
            .map_err(|error| translate(&error, 0))?;
        Ok(Self { inner, rate, frame })
    }

    /// The rate it was built at.
    #[must_use]
    pub const fn rate(&self) -> SampleRate {
        self.rate
    }

    /// The frame duration it was built at.
    #[must_use]
    pub const fn frame(&self) -> FrameDuration {
        self.frame
    }

    /// How many samples one frame of that duration is.
    #[must_use]
    pub const fn frame_samples(&self) -> usize {
        self.frame.samples(self.rate)
    }

    /// How many samples `packet` would produce at this decoder's rate,
    /// without decoding it.
    ///
    /// What a jitter buffer needs to know how far a packet advances the
    /// playout clock before it decides whether to keep it.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidPacket`] for a payload that is not an Opus
    /// packet, including an empty one.
    pub fn samples_in(&self, packet: &[u8]) -> Result<usize, CodecError> {
        if packet.is_empty() {
            return Err(CodecError::InvalidPacket);
        }
        self.inner
            .get_nb_samples(packet)
            .map_err(|error| translate(&error, 0))
    }

    /// Decode one packet that really arrived, returning how many samples it
    /// produced.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidPacket`] for a payload that is empty or does not
    /// decode, and [`CodecError::BufferTooSmall`] when `samples` has less
    /// room than the packet needs. An empty payload is refused because libopus
    /// would silently conceal it.
    pub fn decode(&mut self, packet: &[u8], samples: &mut [i16]) -> Result<usize, CodecError> {
        if packet.is_empty() {
            return Err(CodecError::InvalidPacket);
        }
        let room = samples.len();
        if room < self.frame_samples() {
            return Err(CodecError::BufferTooSmall { supplied: room });
        }
        self.inner
            .decode(packet, samples, false)
            .map_err(|error| translate(&error, room))
    }

    /// Fill one frame that was lost and cannot be recovered, with Opus's own
    /// concealment.
    ///
    /// Prefer [`recover`](Self::recover) whenever the packet after the gap is
    /// already in hand: this extrapolates from what came before, and that
    /// decodes what was actually said.
    ///
    /// # Errors
    ///
    /// [`CodecError::FrameLength`] unless `samples` is exactly
    /// [`frame_samples`](Self::frame_samples) long — libopus reads the length
    /// of the slice as the duration to conceal, and it has to be a duration
    /// Opus cuts.
    pub fn conceal(&mut self, samples: &mut [i16]) -> Result<usize, CodecError> {
        let expected = self.frame_samples();
        if samples.len() != expected {
            return Err(CodecError::FrameLength {
                expected,
                supplied: samples.len(),
            });
        }
        self.inner
            .decode(&[], samples, false)
            .map_err(|error| translate(&error, expected))
    }

    /// Rebuild the frame before `following` out of the forward error
    /// correction carried inside it.
    ///
    /// The encoder at the far end puts a low-bitrate copy of frame N-1 into
    /// packet N (RFC 7587 §3.3), so a receiver that has packet N and lost
    /// N-1 can decode the copy instead of concealing. It costs one packet of
    /// jitter buffer depth and it is worth it.
    ///
    /// Feed it the packet that arrived *after* the gap, and follow it with
    /// the ordinary [`decode`](Self::decode) of that same packet. If there is
    /// no FEC copy in it — the far end never enabled it, or spent no bits on
    /// it that frame — libopus conceals instead, so this degrades to
    /// [`conceal`](Self::conceal) rather than failing.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidPacket`] for a payload that is empty or does not
    /// decode, and [`CodecError::FrameLength`] unless `samples` is exactly
    /// [`frame_samples`](Self::frame_samples) long, which is the duration of
    /// the frame being recovered.
    pub fn recover(&mut self, following: &[u8], samples: &mut [i16]) -> Result<usize, CodecError> {
        if following.is_empty() {
            return Err(CodecError::InvalidPacket);
        }
        let expected = self.frame_samples();
        if samples.len() != expected {
            return Err(CodecError::FrameLength {
                expected,
                supplied: samples.len(),
            });
        }
        self.inner
            .decode(following, samples, true)
            .map_err(|error| translate(&error, expected))
    }

    /// Forget the stream: a new call, or a codec change mid-call.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if libopus refuses to reset.
    pub fn reset(&mut self) -> Result<(), CodecError> {
        self.inner
            .reset_state()
            .map_err(|error| translate(&error, 0))
    }
}

/// Written out for the same reason as [`Encoder`]'s.
impl fmt::Debug for Decoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Decoder")
            .field("rate", &self.rate)
            .field("frame", &self.frame)
            .finish_non_exhaustive()
    }
}

/// Whether `packet` carries an in-band FEC copy of the frame sent before it,
/// which [`Decoder::recover`] can decode when that frame was lost.
///
/// The copy is a low-bitrate redundancy ("LBRR") frame of the SILK layer
/// (RFC 6716 §4.2.4), so a CELT-only packet never has one, and a SILK or
/// hybrid packet says whether it does in its first few bits: after the voice
/// activity flag of each of its SILK frames comes the LBRR flag (§4.2.3,
/// mid channel first, then side). Those bits are read here with the range
/// decoder of §4.1, taken as far as the flag and no further. A packet too
/// short or too malformed to say carries none.
///
/// [`Decoder::recover`] on a packet without a copy conceals instead, which
/// sounds the same as [`Decoder::conceal`]; asking first is how a receiver
/// counts what FEC actually brought back.
#[must_use]
pub fn carries_fec(packet: &[u8]) -> bool {
    let Some((&toc, rest)) = packet.split_first() else {
        return false;
    };
    let config = toc >> 3;
    // SILK frames in each Opus frame: a 10 or 20 ms frame holds one, a 40
    // ms frame two and a 60 ms frame three (§4.2.2); configurations 16 and
    // up are CELT alone (§3.1, Table 2)
    let silk_frames = match config {
        0..=11 => match config % 4 {
            0 | 1 => 1,
            2 => 2,
            _ => 3,
        },
        12..=15 => 1,
        _ => return false,
    };
    let channels = if toc & 0x04 == 0 { 1 } else { 2 };
    let Some(frame) = first_frame(toc & 0x03, rest) else {
        return false;
    };
    if frame.is_empty() {
        return false;
    }
    let mut bits = RangeBits::new(frame);
    for _ in 0..channels {
        for _ in 0..silk_frames {
            // the voice activity flag of each SILK frame
            bits.bit();
        }
        if bits.bit() {
            return true;
        }
    }
    false
}

/// The bytes of the first Opus frame in a packet whose table of contents
/// ends in `code` (RFC 6716 §3.2), `rest` being everything after that byte.
fn first_frame(code: u8, rest: &[u8]) -> Option<&[u8]> {
    match code {
        // one frame
        0 => Some(rest),
        // two of equal length
        1 => rest.get(..rest.len() / 2),
        // two, the first one's length given
        2 => {
            let (length, used) = frame_length(rest)?;
            rest.get(used..used.checked_add(length)?)
        }
        // any number, behind a count byte and its optional padding (§3.2.5)
        _ => {
            let (&count, mut at) = rest.split_first().map(|(count, _)| (count, 1))?;
            let frames = usize::from(count & 0x3F);
            if frames == 0 {
                return None;
            }
            let mut padding = 0_usize;
            if count & 0x40 != 0 {
                loop {
                    let byte = *rest.get(at)?;
                    at += 1;
                    padding += if byte == 255 { 254 } else { usize::from(byte) };
                    if byte != 255 {
                        break;
                    }
                }
            }
            let end = rest.len().checked_sub(padding)?;
            if count & 0x80 == 0 {
                // constant bitrate: the frames share what is left alike
                let data = rest.get(at..end)?;
                return data.get(..data.len() / frames);
            }
            // variable bitrate: every frame's length but the last's, in order
            let mut first = None;
            for _ in 1..frames {
                let (length, used) = frame_length(rest.get(at..end)?)?;
                first.get_or_insert(length);
                at += used;
            }
            let data = rest.get(at..end)?;
            data.get(..first.unwrap_or(data.len()))
        }
    }
}

/// A frame length as §3.2.1 codes it, and the bytes it took: one byte under
/// 252, else that byte plus four times the next.
fn frame_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = usize::from(*bytes.first()?);
    if first < 252 {
        return Some((first, 1));
    }
    let second = usize::from(*bytes.get(1)?);
    Some((first + 4 * second, 2))
}

/// Just enough of RFC 6716's range decoder (§4.1) to read the equiprobable
/// bits a SILK frame begins with: initialisation (§4.1.1), renormalisation
/// (§4.1.2.1) and `ec_dec_bit_logp` with a probability of one half
/// (§4.1.3.1). Bytes past the end of the frame read as zero, as §4.1.2.1
/// has it.
struct RangeBits<'a> {
    data: &'a [u8],
    next: usize,
    rng: u32,
    val: u32,
    /// The low bit of the last byte read, which is the high bit of the next
    /// symbol.
    left_over: u8,
}

impl<'a> RangeBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        let first = data.first().copied().unwrap_or(0);
        let mut bits = Self {
            data,
            next: 1,
            rng: 128,
            val: 127 - u32::from(first >> 1),
            left_over: first & 1,
        };
        bits.normalise();
        bits
    }

    fn normalise(&mut self) {
        while self.rng <= 1 << 23 {
            self.rng <<= 8;
            let byte = self.data.get(self.next).copied().unwrap_or(0);
            self.next += 1;
            let symbol = (self.left_over << 7) | (byte >> 1);
            self.left_over = byte & 1;
            self.val = ((self.val << 8) + (255 - u32::from(symbol))) & 0x7FFF_FFFF;
        }
    }

    /// One bit at a probability of one half: a 1 takes the lower half of
    /// the range, a 0 the upper.
    fn bit(&mut self) -> bool {
        let half = self.rng >> 1;
        let one = self.val < half;
        if one {
            self.rng = half;
        } else {
            self.val -= half;
            self.rng -= half;
        }
        self.normalise();
        one
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CHANNELS, CLOCK_RATE, CodecError, DEFAULT_PTIME_MS, Decoder, ENCODING_NAME, Encoder,
        FrameDuration, MAX_BITRATE, MAX_FRAME_BYTES, MIN_BITRATE, RTPMAP_CHANNELS, SampleRate,
        carries_fec,
    };

    const RATES: [SampleRate; 5] = [
        SampleRate::Narrowband,
        SampleRate::Mediumband,
        SampleRate::Wideband,
        SampleRate::SuperWideband,
        SampleRate::Fullband,
    ];

    const DURATIONS: [FrameDuration; 6] = [
        FrameDuration::Micros2500,
        FrameDuration::Micros5000,
        FrameDuration::Micros10000,
        FrameDuration::Micros20000,
        FrameDuration::Micros40000,
        FrameDuration::Micros60000,
    ];

    /// A voiced-sounding signal: a triangle at about 200 Hz under a slower
    /// amplitude envelope, so the encoder has both a pitch and a changing
    /// level to work with rather than a stationary tone it can code in
    /// almost no bits. Integer throughout, so the samples are identical on
    /// every platform and a failure is a failure everywhere.
    fn speech(index: usize, rate: SampleRate) -> i16 {
        let period = (rate.hertz() as usize / 200).max(2);
        let span = i32::try_from(period).unwrap();
        let phase = i32::try_from(index % period).unwrap();
        let half = span / 2;
        let shape = if phase < half {
            (2 * 8_000 * phase / half) - 8_000
        } else {
            8_000 - (2 * 8_000 * (phase - half) / (span - half))
        };
        // an envelope that opens and closes over about a fifth of a second
        let envelope = i32::try_from(index % (rate.hertz() as usize / 5)).unwrap();
        let level = 4_096 + envelope % 4_096;
        i16::try_from((shape * level / 8_192).clamp(-32_768, 32_767)).unwrap()
    }

    fn frame_of(rate: SampleRate, frame: FrameDuration, at: usize) -> Vec<i16> {
        let len = frame.samples(rate);
        (at * len..(at + 1) * len)
            .map(|n| speech(n, rate))
            .collect()
    }

    fn energy(samples: &[i16]) -> i64 {
        samples
            .iter()
            .map(|sample| {
                let value = i64::from(*sample);
                value * value
            })
            .sum()
    }

    /// An encoder set up the way a call would set one up, with FEC armed.
    fn encoder(rate: SampleRate, frame: FrameDuration, bitrate: u32, loss: u32) -> Encoder {
        let mut encoder = Encoder::new(rate, frame).unwrap();
        encoder.set_bitrate(bitrate).unwrap();
        encoder.set_inband_fec(true).unwrap();
        encoder.set_expected_loss(loss).unwrap();
        encoder
    }

    #[test]
    fn the_constants_are_the_ones_rfc_7587_fixed() {
        // the timestamp clock is 48 kHz whatever the codec is fed at
        assert_eq!(CLOCK_RATE, 48_000);
        assert_eq!(CHANNELS, 1);
        // and the rtpmap line says two channels regardless
        assert_eq!(RTPMAP_CHANNELS, 2);
        assert_eq!(ENCODING_NAME, "opus");
        assert_eq!(DEFAULT_PTIME_MS, 20);
        assert_eq!(MAX_FRAME_BYTES, 255 * 4 + 255);
        assert_eq!(MIN_BITRATE, 6_000);
        assert_eq!(MAX_BITRATE, 510_000);
    }

    #[test]
    fn the_five_rates_are_the_five_bandwidths_of_table_1() {
        let hertz: Vec<u32> = RATES.iter().map(|rate| rate.hertz()).collect();
        assert_eq!(hertz, vec![8_000, 12_000, 16_000, 24_000, 48_000]);
        for rate in RATES {
            assert_eq!(SampleRate::from_hertz(rate.hertz()), Ok(rate));
        }
        // the device rates, which belong on the far side of the resampler
        for asked in [0, 11_025, 32_000, 44_100, 96_000] {
            assert_eq!(
                SampleRate::from_hertz(asked),
                Err(CodecError::UnsupportedRate { hertz: asked })
            );
        }
    }

    #[test]
    fn the_six_durations_are_the_six_columns_of_table_2() {
        let micros: Vec<u32> = DURATIONS.iter().map(|frame| frame.micros()).collect();
        assert_eq!(micros, vec![2_500, 5_000, 10_000, 20_000, 40_000, 60_000]);
        for frame in DURATIONS {
            assert_eq!(FrameDuration::from_micros(frame.micros()), Ok(frame));
        }
        // 30 ms is what a carrier asks for with a=ptime and Opus cannot cut
        for asked in [0, 15_000, 30_000, 80_000, 120_000] {
            assert_eq!(
                FrameDuration::from_micros(asked),
                Err(CodecError::UnsupportedFrame { micros: asked })
            );
        }

        // the ts incr row of Table 2, which is the duration at 48 kHz
        let increments: Vec<u32> = DURATIONS
            .iter()
            .map(|frame| frame.timestamp_increment())
            .collect();
        assert_eq!(increments, vec![120, 240, 480, 960, 1_920, 2_880]);
        for frame in DURATIONS {
            assert_eq!(
                frame.timestamp_increment(),
                u32::try_from(frame.samples(SampleRate::Fullband)).unwrap()
            );
        }

        // every one of the thirty combinations is a whole number of samples
        for rate in RATES {
            for frame in DURATIONS {
                let samples = frame.samples(rate);
                assert_eq!(
                    samples * 1_000_000,
                    rate.hertz() as usize * frame.micros() as usize,
                    "{rate:?} at {frame:?}"
                );
            }
        }
        // and the one everybody writes down
        assert_eq!(
            FrameDuration::Micros20000.samples(SampleRate::Narrowband),
            160
        );
        assert_eq!(
            FrameDuration::Micros2500.samples(SampleRate::Narrowband),
            20
        );
        assert_eq!(
            FrameDuration::Micros60000.samples(SampleRate::Fullband),
            2880
        );
    }

    #[test]
    fn a_frame_survives_a_round_trip_at_every_rate() {
        for rate in RATES {
            let frame = FrameDuration::Micros20000;
            let samples = frame.samples(rate);
            let mut encoder = encoder(rate, frame, 24_000, 0);
            let mut decoder = Decoder::new(rate, frame).unwrap();

            let mut packet = vec![0_u8; frame.max_packet_bytes()];
            let mut played = vec![0_i16; samples];
            let mut last = Vec::new();
            // several frames, because the first one out of a cold encoder is
            // the one it knows least about
            for n in 0..8 {
                let source = frame_of(rate, frame, n);
                let written = encoder.encode(&source, &mut packet).unwrap();
                assert!(written > 2, "{rate:?}: {written} octets is a DTX frame");
                assert!(written <= frame.max_packet_bytes());

                let packet = &packet[..written];
                assert_eq!(decoder.samples_in(packet).unwrap(), samples);
                assert_eq!(decoder.decode(packet, &mut played).unwrap(), samples);
                last = source;
            }

            // lossy, so the test is on energy and not on samples: what comes
            // back is the same order of loudness as what went in
            let (there, back) = (energy(&last), energy(&played));
            assert!(there > 0 && back > 0, "{rate:?}: {there} in, {back} out");
            assert!(
                back * 4 > there && back < there * 4,
                "{rate:?}: energy {there} in, {back} out"
            );
        }
    }

    #[test]
    fn every_frame_duration_round_trips() {
        let rate = SampleRate::Wideband;
        for frame in DURATIONS {
            let samples = frame.samples(rate);
            let mut encoder = encoder(rate, frame, 24_000, 0);
            let mut decoder = Decoder::new(rate, frame).unwrap();

            let mut packet = vec![0_u8; frame.max_packet_bytes()];
            let mut played = vec![0_i16; samples];
            for n in 0..4 {
                let source = frame_of(rate, frame, n);
                let written = encoder.encode(&source, &mut packet).unwrap();
                assert_eq!(
                    decoder.decode(&packet[..written], &mut played).unwrap(),
                    samples,
                    "{frame:?}"
                );
            }
            assert!(energy(&played) > 0, "{frame:?} decoded to silence");
        }
    }

    #[test]
    fn a_frame_of_the_wrong_length_is_refused_here_and_not_in_c() {
        let rate = SampleRate::Narrowband;
        let frame = FrameDuration::Micros20000;
        let mut encoder = encoder(rate, frame, 16_000, 0);
        let mut packet = vec![0_u8; frame.max_packet_bytes()];

        assert_eq!(encoder.frame_samples(), 160);
        for supplied in [0, 100, 159, 161, 320] {
            let source = vec![0_i16; supplied];
            assert_eq!(
                encoder.encode(&source, &mut packet),
                Err(CodecError::FrameLength {
                    expected: 160,
                    supplied
                })
            );
        }
        // and the right length is taken
        let source = frame_of(rate, frame, 0);
        assert!(encoder.encode(&source, &mut packet).unwrap() > 2);
    }

    #[test]
    fn a_packet_buffer_with_no_room_is_refused() {
        let rate = SampleRate::Wideband;
        let frame = FrameDuration::Micros20000;
        let mut encoder = encoder(rate, frame, 24_000, 0);
        let source = frame_of(rate, frame, 0);
        assert_eq!(
            encoder.encode(&source, &mut []),
            Err(CodecError::BufferTooSmall { supplied: 0 })
        );
    }

    #[test]
    fn an_empty_payload_is_not_a_packet() {
        let rate = SampleRate::Wideband;
        let frame = FrameDuration::Micros20000;
        let mut decoder = Decoder::new(rate, frame).unwrap();
        let mut played = vec![0_i16; frame.samples(rate)];

        assert_eq!(
            decoder.decode(&[], &mut played),
            Err(CodecError::InvalidPacket)
        );
        assert_eq!(
            decoder.recover(&[], &mut played),
            Err(CodecError::InvalidPacket)
        );
        assert_eq!(decoder.samples_in(&[]), Err(CodecError::InvalidPacket));
        // and a payload that is not Opus at all
        assert_eq!(
            decoder.samples_in(&[0xff, 0xff, 0xff, 0xff]),
            Err(CodecError::InvalidPacket)
        );
    }

    #[test]
    fn a_short_output_slice_is_refused_before_libopus_sees_it() {
        let rate = SampleRate::Wideband;
        let frame = FrameDuration::Micros20000;
        let mut encoder = encoder(rate, frame, 24_000, 0);
        let mut decoder = Decoder::new(rate, frame).unwrap();

        let mut packet = vec![0_u8; frame.max_packet_bytes()];
        let written = encoder
            .encode(&frame_of(rate, frame, 0), &mut packet)
            .unwrap();

        let mut short = vec![0_i16; frame.samples(rate) - 1];
        assert_eq!(
            decoder.decode(&packet[..written], &mut short),
            Err(CodecError::BufferTooSmall {
                supplied: frame.samples(rate) - 1
            })
        );
        // conceal and recover want the length exactly, since it is where they
        // read the duration from
        assert_eq!(
            decoder.conceal(&mut short),
            Err(CodecError::FrameLength {
                expected: frame.samples(rate),
                supplied: frame.samples(rate) - 1
            })
        );
        assert_eq!(
            decoder.recover(&packet[..written], &mut short),
            Err(CodecError::FrameLength {
                expected: frame.samples(rate),
                supplied: frame.samples(rate) - 1
            })
        );
    }

    #[test]
    fn a_lost_packet_conceals_rather_than_failing() {
        let rate = SampleRate::Wideband;
        let frame = FrameDuration::Micros20000;
        let samples = frame.samples(rate);
        let mut encoder = encoder(rate, frame, 24_000, 0);
        let mut decoder = Decoder::new(rate, frame).unwrap();

        let mut packet = vec![0_u8; frame.max_packet_bytes()];
        let mut played = vec![0_i16; samples];
        for n in 0..8 {
            let written = encoder
                .encode(&frame_of(rate, frame, n), &mut packet)
                .unwrap();
            decoder.decode(&packet[..written], &mut played).unwrap();
        }

        // the gap: a frame, not an error, and not silence either
        let mut concealed = vec![0_i16; samples];
        assert_eq!(decoder.conceal(&mut concealed).unwrap(), samples);
        assert!(
            energy(&concealed) > 0,
            "concealment produced nothing at all"
        );

        // and it keeps working while the gap runs on, fading as Opus fades it
        let mut second = vec![0_i16; samples];
        assert_eq!(decoder.conceal(&mut second).unwrap(), samples);
        assert!(energy(&second) <= energy(&concealed));
    }

    #[test]
    fn forward_error_correction_decodes_something_concealment_cannot() {
        let rate = SampleRate::Wideband;
        let frame = FrameDuration::Micros20000;
        let samples = frame.samples(rate);
        // low enough that the speech layer codes it, with loss declared so
        // libopus actually spends bits on the redundant copy
        let mut encoder = encoder(rate, frame, 24_000, 30);

        let mut packets = Vec::new();
        for n in 0..10 {
            let mut packet = vec![0_u8; frame.max_packet_bytes()];
            let written = encoder
                .encode(&frame_of(rate, frame, n), &mut packet)
                .unwrap();
            packet.truncate(written);
            packets.push(packet);
        }

        // two decoders fed identically up to the gap, so what differs after
        // it is the recovery and nothing else
        let mut concealing = Decoder::new(rate, frame).unwrap();
        let mut recovering = Decoder::new(rate, frame).unwrap();
        let mut scratch = vec![0_i16; samples];
        for packet in packets.iter().take(8) {
            concealing.decode(packet, &mut scratch).unwrap();
            recovering.decode(packet, &mut scratch).unwrap();
        }

        // packet 8 is lost; packet 9 carries a copy of the frame in it
        let mut concealed = vec![0_i16; samples];
        assert_eq!(concealing.conceal(&mut concealed).unwrap(), samples);

        let mut recovered = vec![0_i16; samples];
        assert_eq!(
            recovering.recover(&packets[9], &mut recovered).unwrap(),
            samples
        );

        assert_ne!(
            concealed, recovered,
            "the FEC copy decoded to what concealment would have invented"
        );

        // the recovery is a coded version of the frame that was lost, so it
        // lands nearer to it than an extrapolation does
        let truth = frame_of(rate, frame, 8);
        assert!(distance(&recovered, &truth) < distance(&concealed, &truth));
        assert!(carries_fec(&packets[9]), "the packet the copy came out of");
    }

    /// Packets of `frames` frames of the voiced signal, from an encoder at
    /// `bitrate` with FEC `fec` and `loss` per cent expected.
    fn packets(
        rate: SampleRate,
        bitrate: u32,
        fec: bool,
        loss: u32,
        frames: usize,
    ) -> Vec<Vec<u8>> {
        let frame = FrameDuration::Micros20000;
        let mut encoder = Encoder::new(rate, frame).unwrap();
        encoder.set_bitrate(bitrate).unwrap();
        encoder.set_inband_fec(fec).unwrap();
        encoder.set_expected_loss(loss).unwrap();
        (0..frames)
            .map(|n| {
                let mut packet = vec![0_u8; frame.max_packet_bytes()];
                let written = encoder
                    .encode(&frame_of(rate, frame, n), &mut packet)
                    .unwrap();
                packet.truncate(written);
                packet
            })
            .collect()
    }

    #[test]
    fn a_packet_says_whether_it_carries_a_copy_of_the_one_before() {
        let frame = FrameDuration::Micros20000;
        for rate in [SampleRate::Wideband, SampleRate::Fullband] {
            // Asked for, with loss to spend it on. libopus decides frame by
            // frame whether a copy is worth its bits, so what the flag says
            // is checked against what decoding does: with each packet's
            // predecessor lost, recovering from the packet decodes something
            // other than concealment exactly when it carries a copy.
            let with = packets(rate, 24_000, true, 20, 50);
            let mut carrying = 0;
            for lost in 1..with.len() - 1 {
                let mut concealing = Decoder::new(rate, frame).unwrap();
                let mut recovering = Decoder::new(rate, frame).unwrap();
                let mut scratch = vec![0_i16; frame.samples(rate)];
                for packet in with.iter().take(lost) {
                    concealing.decode(packet, &mut scratch).unwrap();
                    recovering.decode(packet, &mut scratch).unwrap();
                }
                let mut concealed = vec![0_i16; frame.samples(rate)];
                let mut recovered = vec![0_i16; frame.samples(rate)];
                concealing.conceal(&mut concealed).unwrap();
                recovering.recover(&with[lost + 1], &mut recovered).unwrap();
                let says = carries_fec(&with[lost + 1]);
                carrying += usize::from(says);
                // where the encoder changed mode or bandwidth between the two,
                // the decoder conceals in the new packet's configuration
                // rather than the old one's, which differs from concealment
                // with or without a copy
                if with[lost + 1][0] != with[lost][0] {
                    continue;
                }
                assert_eq!(
                    says,
                    concealed != recovered,
                    "{rate:?}, packet {}: the flag and the decoder disagree",
                    lost + 1
                );
            }
            assert!(
                carrying >= 10,
                "{rate:?}: only {carrying} packets carry a copy"
            );
            // never asked for, or asked for with no loss expected: none
            for (fec, loss) in [(false, 20), (true, 0)] {
                let without = packets(rate, 24_000, fec, loss, 50);
                assert!(
                    !without.iter().any(|p| carries_fec(p)),
                    "{rate:?}, FEC {fec}, {loss} %: a copy nobody asked for"
                );
            }
        }
    }

    #[test]
    fn what_carries_no_copy_says_so() {
        assert!(!carries_fec(&[]));
        // a table of contents alone, SILK at 20 ms: no frame to read
        assert!(!carries_fec(&[1 << 3]));
        // CELT-only configurations have no SILK layer to copy from, whatever
        // the bits after them
        for config in 16_u8..32 {
            assert!(!carries_fec(&[config << 3, 0x00, 0x00, 0x00]));
        }
        // the frame count byte of a code 3 packet saying no frames
        assert!(!carries_fec(&[(1 << 3) | 3, 0x00]));
        // a code 2 packet whose first frame runs past its end
        assert!(!carries_fec(&[(1 << 3) | 2, 200, 0x00]));
    }

    #[test]
    fn the_flag_is_read_from_the_first_frame_however_the_packet_is_framed() {
        let rate = SampleRate::Wideband;
        let with = packets(rate, 24_000, true, 20, 4);
        let without = packets(rate, 24_000, false, 20, 4);
        let (copy, plain) = (&with[3], &without[3]);
        assert!(carries_fec(copy) && !carries_fec(plain));
        // the same frame framed as code 2 (two frames, the first one's length
        // given) and code 3 (a count, lengths of all but the last), its table
        // of contents otherwise kept: the first frame is what is read
        for (first, second, expected) in [(copy, plain, true), (plain, copy, false)] {
            let toc = first[0] & !0x03;
            let (a, b) = (&first[1..], &second[1..]);
            assert!(a.len() < 252);
            let mut code2 = vec![toc | 2, u8::try_from(a.len()).unwrap()];
            code2.extend_from_slice(a);
            code2.extend_from_slice(b);
            assert_eq!(carries_fec(&code2), expected, "code 2");
            let mut code3 = vec![toc | 3, 0x80 | 2, u8::try_from(a.len()).unwrap()];
            code3.extend_from_slice(a);
            code3.extend_from_slice(b);
            assert_eq!(carries_fec(&code3), expected, "code 3, variable");
            let mut padded = vec![toc | 3, 0xC0 | 2, 3, u8::try_from(a.len()).unwrap()];
            padded.extend_from_slice(a);
            padded.extend_from_slice(b);
            padded.extend_from_slice(&[0, 0, 0]);
            assert_eq!(carries_fec(&padded), expected, "code 3, padded");
        }
    }

    /// Mean squared difference between two frames of the same length.
    fn distance(one: &[i16], other: &[i16]) -> i64 {
        let count = i64::try_from(one.len().max(1)).unwrap();
        one.iter()
            .zip(other)
            .map(|(a, b)| {
                let step = i64::from(*a) - i64::from(*b);
                step * step
            })
            .sum::<i64>()
            / count
    }

    #[test]
    fn a_bitrate_outside_the_defined_range_is_refused() {
        let mut encoder = Encoder::new(SampleRate::Wideband, FrameDuration::Micros20000).unwrap();
        for asked in [0, 500, MIN_BITRATE - 1, MAX_BITRATE + 1, 1_000_000] {
            assert_eq!(
                encoder.set_bitrate(asked),
                Err(CodecError::UnsupportedBitrate {
                    bits_per_second: asked
                })
            );
        }
        for asked in [MIN_BITRATE, 24_000, MAX_BITRATE] {
            assert_eq!(encoder.set_bitrate(asked), Ok(()));
        }
    }

    #[test]
    fn a_loss_estimate_that_is_not_a_percentage_is_refused() {
        let mut encoder = Encoder::new(SampleRate::Wideband, FrameDuration::Micros20000).unwrap();
        for asked in [101, 255, 1_000] {
            assert_eq!(
                encoder.set_expected_loss(asked),
                Err(CodecError::UnsupportedLoss { percent: asked })
            );
        }
        for asked in [0, 30, 100] {
            assert_eq!(encoder.set_expected_loss(asked), Ok(()));
        }
    }

    #[test]
    fn the_packet_bound_holds_at_the_highest_bitrate() {
        // 510 kbit/s at 48 kHz is the corner the bound was worked out for
        let rate = SampleRate::Fullband;
        for frame in DURATIONS {
            let mut encoder = encoder(rate, frame, MAX_BITRATE, 0);
            let mut packet = vec![0_u8; frame.max_packet_bytes()];
            for n in 0..4 {
                let written = encoder
                    .encode(&frame_of(rate, frame, n), &mut packet)
                    .unwrap();
                assert!(
                    written <= frame.max_packet_bytes(),
                    "{frame:?}: {written} octets past the bound"
                );
            }
        }
        // one frame plus its table-of-contents octet, and the multi-frame
        // packets the MDCT layer needs for the two long durations
        assert_eq!(FrameDuration::Micros20000.max_packet_bytes(), 1_276);
        assert_eq!(FrameDuration::Micros40000.max_packet_bytes(), 2_554);
        assert_eq!(FrameDuration::Micros60000.max_packet_bytes(), 3_831);
    }

    #[test]
    fn dtx_stops_sending_through_silence() {
        let rate = SampleRate::Wideband;
        let frame = FrameDuration::Micros20000;
        let mut encoder = Encoder::new(rate, frame).unwrap();
        encoder.set_bitrate(24_000).unwrap();
        encoder.set_dtx(true).unwrap();

        let quiet = vec![0_i16; frame.samples(rate)];
        let mut packet = vec![0_u8; frame.max_packet_bytes()];
        let mut smallest = usize::MAX;
        for _ in 0..40 {
            smallest = smallest.min(encoder.encode(&quiet, &mut packet).unwrap());
        }
        assert!(
            smallest <= 2,
            "DTX never stopped: the smallest packet was {smallest} octets"
        );
    }

    #[test]
    fn a_reset_codec_is_a_cold_one() {
        let rate = SampleRate::Wideband;
        let frame = FrameDuration::Micros20000;
        let samples = frame.samples(rate);
        let mut encoder = encoder(rate, frame, 24_000, 0);
        let mut decoder = Decoder::new(rate, frame).unwrap();

        let mut packet = vec![0_u8; frame.max_packet_bytes()];
        let mut played = vec![0_i16; samples];
        for n in 0..4 {
            let written = encoder
                .encode(&frame_of(rate, frame, n), &mut packet)
                .unwrap();
            decoder.decode(&packet[..written], &mut played).unwrap();
        }

        assert_eq!(encoder.reset(), Ok(()));
        assert_eq!(decoder.reset(), Ok(()));
        assert_eq!(encoder.rate(), rate);
        assert_eq!(decoder.frame(), frame);

        // a reset decoder has nothing to extend, so it conceals silence
        let mut concealed = vec![0_i16; samples];
        assert_eq!(decoder.conceal(&mut concealed).unwrap(), samples);
        assert_eq!(energy(&concealed), 0);

        // and both still work afterwards
        let written = encoder
            .encode(&frame_of(rate, frame, 0), &mut packet)
            .unwrap();
        assert_eq!(
            decoder.decode(&packet[..written], &mut played).unwrap(),
            samples
        );
    }

    /// The pre-skip of a recording is the encoder's own delay, and that
    /// delay is libopus's to report: at 48 kHz the two are the same number,
    /// and at every other rate the pre-skip is the delay scaled to 48 kHz.
    #[test]
    fn the_pre_skip_is_the_lookahead_libopus_reports_counted_at_48_khz() {
        for rate in RATES {
            let mut encoder = Encoder::new(rate, FrameDuration::Micros20000).unwrap();
            let lookahead = encoder.lookahead().unwrap();
            let frame = u32::try_from(FrameDuration::Micros20000.samples(rate)).unwrap();
            assert!(
                lookahead > 0 && lookahead < frame,
                "{rate:?}: a lookahead of {lookahead} samples"
            );
            let expected = (u64::from(lookahead) * 48_000).div_ceil(u64::from(rate.hertz()));
            assert_eq!(u64::from(encoder.pre_skip().unwrap()), expected, "{rate:?}");
        }
        let mut fullband = Encoder::new(SampleRate::Fullband, FrameDuration::Micros20000).unwrap();
        assert_eq!(
            u32::from(fullband.pre_skip().unwrap()),
            fullband.lookahead().unwrap()
        );
    }

    /// A stereo encoder takes interleaved pairs and says so in every packet:
    /// the `s` bit of the table-of-contents byte (RFC 6716 §3.1) is what a
    /// decoder reads the channel count from.
    #[test]
    fn a_stereo_encoder_takes_pairs_and_marks_its_packets_stereo() {
        let rate = SampleRate::Wideband;
        let frame = FrameDuration::Micros20000;
        let mut stereo = Encoder::stereo(rate, frame).unwrap();
        assert_eq!(stereo.channels(), 2);
        let samples = stereo.frame_samples();
        let mut packet = vec![0_u8; frame.max_packet_bytes()];

        assert_eq!(
            stereo.encode(&vec![0; samples], &mut packet).unwrap_err(),
            CodecError::FrameLength {
                expected: samples * 2,
                supplied: samples
            },
            "a mono frame handed to a stereo encoder"
        );

        let mut decoder = Decoder::new(rate, frame).unwrap();
        let mut played = vec![0_i16; samples];
        for n in 0..6 {
            let left = frame_of(rate, frame, n);
            let interleaved: Vec<i16> = left.iter().flat_map(|&l| [l, l / 3]).collect();
            let written = stereo.encode(&interleaved, &mut packet).unwrap();
            assert!(written > 2);
            assert_ne!(packet[0] & 0x04, 0, "the TOC byte says mono");
            // a mono decoder takes a stereo stream and downmixes it
            assert_eq!(
                decoder.decode(&packet[..written], &mut played).unwrap(),
                samples
            );
        }
        assert!(energy(&played) > 0);

        let mut mono = Encoder::new(rate, frame).unwrap();
        assert_eq!(mono.channels(), 1);
        let written = mono.encode(&frame_of(rate, frame, 0), &mut packet).unwrap();
        assert!(written > 0);
        assert_eq!(packet[0] & 0x04, 0, "a mono encoder's TOC byte says stereo");
    }

    #[test]
    fn the_error_messages_say_what_went_wrong() {
        assert_eq!(
            CodecError::UnsupportedRate { hertz: 44_100 }.to_string(),
            "44100 Hz is not one of the five rates Opus runs at"
        );
        assert_eq!(
            CodecError::FrameLength {
                expected: 160,
                supplied: 100
            }
            .to_string(),
            "a frame of 100 samples, 160 expected"
        );
        assert_eq!(
            CodecError::InvalidPacket.to_string(),
            "not a decodable Opus packet"
        );
    }
}
