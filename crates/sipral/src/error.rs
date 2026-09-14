// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What can go wrong where signalling meets media.
//!
//! Every variant here is a refusal with a reason, never a silence. A codec
//! order naming something this build does not contain is rejected where it is
//! set rather than ignored where it is used, and a call whose media could not
//! be opened says so instead of standing up with no audio in it.

use core::fmt;

use sipral_core::sdp::SdpError;
#[cfg(feature = "opus")]
use sipral_media::opus::CodecError;
use sipral_ua::UaError;

use crate::codec::Codec;

/// Why a media operation did not happen.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MediaError {
    /// A codec order named the same codec twice, or named one that is not in
    /// this build.
    ///
    /// The set of codecs is a compile-time fact, so this is the answer a
    /// configuration gets, not a run-time surprise later.
    UnsupportedCodec {
        /// What was asked for.
        name: String,
    },
    /// A codec order was empty. An offer has to name at least one format.
    NoCodecs,
    /// A packetisation interval no codec here can cut a frame at.
    BadFrameLength {
        /// What was asked for, in milliseconds.
        millis: u32,
    },
    /// The negotiation settled on a payload type this build cannot decode.
    ///
    /// It means the peer answered with something that was not in the offer,
    /// which happens, and it is better said than played as noise.
    UnknownPayload {
        /// The type the answer named.
        payload: u8,
        /// What its `a=rtpmap` called it.
        encoding: String,
    },
    /// The description this end wrote or the one that arrived could not be
    /// read.
    Description(SdpError),
    /// The two descriptions were read but they agree on nothing that can carry
    /// audio.
    NoCommonCodec,
    /// One end refused the stream: a port of zero in the answer, which
    /// RFC 3264 §6 makes the way to say no to an offered stream. The call is
    /// up and carries no audio, which is a thing a peer is allowed to want.
    StreamRefused,
    /// There is no session description to work from: an INVITE with no body
    /// that was answered without one either, or a call whose media was never
    /// opened.
    NoDescription,
    /// The call is not one this engine placed or answered.
    NoSuchCall,
    /// The negotiation would have keyed the stream from a DTLS handshake, and
    /// there is no DTLS in this build.
    ///
    /// Refused rather than opened in the clear on a secure profile. The whole
    /// of what this build does about keys is SDES, and
    /// [`Capabilities`](crate::Capabilities) says so before a call is placed.
    NoDtlsSrtp,
    /// The call asked for SRTP and would have carried audio without it: a
    /// plain offer arriving at a call set to [`SrtpPolicy::Required`], or a
    /// plain re-offer inside one.
    ///
    /// The refusal is the point. Answering it plainly would be a silent
    /// downgrade, and there is no way for anyone on either end to notice one.
    ///
    /// [`SrtpPolicy::Required`]: crate::SrtpPolicy::Required
    SrtpRequired,
    /// The crypto line the negotiation settled on asks for something this
    /// build will not be held to: more than one master key on the line, one
    /// of RFC 4568 §6.3's session parameters that turns off encryption or
    /// authentication, a key derivation rate, or a parameter that has to be
    /// honoured and cannot be read.
    ///
    /// Refused rather than half-honoured: a stream opened on terms only one
    /// end believes produces packets the far end drops, which looks like a
    /// network fault for as long as somebody is willing to keep looking.
    UnusableKeying,
    /// The codec refused a frame. Opus is the only one that can, and it does
    /// so for a frame length it was not built for — so a build with the
    /// `opus` feature off has nothing that produces this and no variant for
    /// it.
    #[cfg(feature = "opus")]
    Codec(CodecError),
    /// The packet did not fit the buffer it had to be built in.
    PacketTooLong {
        /// What it needed.
        need: usize,
        /// What there was.
        got: usize,
    },
    /// A render-to-capture delay longer than anything between a loudspeaker
    /// and a microphone in the same room.
    ///
    /// Refused where it is set rather than turned into half a second of
    /// history per call: a number that large is a platform reporting
    /// something other than what was asked of it.
    RenderDelayTooLong {
        /// What was asked for.
        asked: std::time::Duration,
        /// The longest this build keeps history for.
        most: std::time::Duration,
    },
    /// A digit was asked for on a call that negotiated no telephone event
    /// payload type.
    ///
    /// The far end never offered one, so there is nowhere in the media to put
    /// it. The INFO form on the user agent is what is left.
    NoDtmf,
    /// A digit shorter than legacy equipment recognises.
    DigitTooShort {
        /// What was asked for.
        asked: std::time::Duration,
        /// The floor RFC 4733 §2.5.2.1 takes from ITU-T Q.24.
        least: std::time::Duration,
    },
    /// A digit longer than any key is held: the same ceiling a digit sent or
    /// received by INFO is held to.
    DigitTooLong {
        /// What was asked for.
        asked: std::time::Duration,
        /// The longest a digit may last.
        most: std::time::Duration,
    },
    /// More digits than one call will hold waiting.
    TooManyDigits,
    /// A dial string held a character no keypad has.
    UnknownDigit {
        /// The character.
        key: char,
    },
    /// A recording could not be started, or stopped writing part-way through.
    ///
    /// The kind rather than the error itself, because a call carries on when
    /// its recording fails and this has to be comparable and cloneable to
    /// travel in an event.
    Recording(std::io::ErrorKind),
    /// Nothing is being recorded on this call.
    NotRecording,
    /// A recording was asked for while one was already running. Two writers on
    /// one stream would interleave frames into both files.
    AlreadyRecording,
    /// A re-negotiation moved the sample rate or the frame length under a
    /// recording that was running.
    ///
    /// A WAVE header is written once, at the start, and names the rate the
    /// file is to be played back at; audio taken at another rate written in
    /// behind it plays at the wrong speed for the rest of the file. So the
    /// recording is closed properly — the lengths patched, the file playable —
    /// and the application is told, because it is the only one that can decide
    /// whether to open a second file.
    CodecChanged,
    /// The user agent refused the request the media was for.
    Signalling(UaError),
}

impl MediaError {
    /// The codec this build has no encoder for, when that is what went wrong.
    ///
    /// A caller reporting a failed call wants the name, and digging it out of
    /// the variant at every call site is how a log line ends up saying
    /// "media error".
    #[must_use]
    pub fn unsupported(codec: &str) -> Self {
        Self::UnsupportedCodec {
            name: codec.to_owned(),
        }
    }

    /// Whether this is the codec's own refusal.
    ///
    // the variant is Opus's and exists only where Opus does, so the link has
    // to as well or a build without it documents a variant it has not got
    #[cfg_attr(
        feature = "opus",
        doc = "That is [`MediaError::Codec`], and it is what Opus produces \
               for a frame it was not built to cut."
    )]
    #[cfg_attr(
        not(feature = "opus"),
        doc = "The variant that would say so is Opus's, this build has no \
               Opus, and so this is always `false`."
    )]
    ///
    /// Asked rather than matched, because the variant exists only where Opus
    /// does and a crate above this one cannot write that `cfg`: a Cargo
    /// feature belongs to the crate that declares it, so an arm written
    /// under `sipral-ffi`'s own `opus` goes missing in a build whose facade
    /// linked the codec, and the refusal falls through to whatever the
    /// catch-all beneath it says.
    #[must_use]
    pub const fn is_codec(&self) -> bool {
        #[cfg(feature = "opus")]
        {
            matches!(*self, Self::Codec(_))
        }
        #[cfg(not(feature = "opus"))]
        {
            false
        }
    }
}

impl From<SdpError> for MediaError {
    fn from(error: SdpError) -> Self {
        Self::Description(error)
    }
}

#[cfg(feature = "opus")]
impl From<CodecError> for MediaError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<UaError> for MediaError {
    fn from(error: UaError) -> Self {
        Self::Signalling(error)
    }
}

impl From<std::io::Error> for MediaError {
    fn from(error: std::io::Error) -> Self {
        Self::Recording(error.kind())
    }
}

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCodec { name } => {
                write!(f, "this build has no codec called {name}; it has ")?;
                for (index, codec) in Codec::ALL.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(codec.encoding_name())?;
                }
                Ok(())
            }
            Self::NoCodecs => f.write_str("a codec order with nothing in it"),
            Self::BadFrameLength { millis } => {
                write!(f, "no codec here cuts a frame at {millis} ms")
            }
            Self::UnknownPayload { payload, encoding } => {
                write!(
                    f,
                    "the answer settled on {encoding}, payload type {payload}, which this build cannot decode"
                )
            }
            Self::Description(error) => write!(f, "session description: {error}"),
            Self::NoCommonCodec => f.write_str("the two descriptions have no codec in common"),
            Self::StreamRefused => {
                f.write_str("the stream was refused, so the call carries no audio")
            }
            Self::NoDescription => f.write_str("no session description has been agreed"),
            Self::NoSuchCall => f.write_str("no such call"),
            Self::NoDtlsSrtp => {
                f.write_str("the keys were to come from a DTLS handshake, which this build has no")
            }
            Self::SrtpRequired => {
                f.write_str("this call requires SRTP and the far end described none")
            }
            Self::UnusableKeying => {
                f.write_str("the crypto line asks for terms this build will not be held to")
            }
            #[cfg(feature = "opus")]
            Self::Codec(error) => write!(f, "codec: {error}"),
            Self::PacketTooLong { need, got } => {
                write!(f, "the packet needs {need} octets and there are {got}")
            }
            Self::RenderDelayTooLong { asked, most } => write!(
                f,
                "a render-to-capture delay of {} ms; this build keeps {} ms of history",
                asked.as_millis(),
                most.as_millis()
            ),
            Self::NoDtmf => f.write_str("this call negotiated no telephone event payload type"),
            Self::DigitTooShort { asked, least } => write!(
                f,
                "a digit of {} ms; equipment recognises {} ms and up",
                asked.as_millis(),
                least.as_millis()
            ),
            Self::DigitTooLong { asked, most } => write!(
                f,
                "a digit of {} ms; no key is held for more than {} ms",
                asked.as_millis(),
                most.as_millis()
            ),
            Self::TooManyDigits => f.write_str("too many digits are already waiting to be sent"),
            Self::UnknownDigit { key } => write!(f, "no keypad has {key:?}"),
            Self::Recording(kind) => write!(f, "recording: {kind}"),
            Self::NotRecording => f.write_str("nothing is being recorded on this call"),
            Self::AlreadyRecording => f.write_str("this call is already being recorded"),
            Self::CodecChanged => {
                f.write_str("the recording stopped: the call moved to a codec at another rate")
            }
            Self::Signalling(error) => write!(f, "user agent: {error}"),
        }
    }
}

impl core::error::Error for MediaError {}
