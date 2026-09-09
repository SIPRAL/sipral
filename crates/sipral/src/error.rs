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
    /// The codec refused a frame. Opus is the only one that can, and it does
    /// so for a frame length it was not built for.
    Codec(CodecError),
    /// The packet did not fit the buffer it had to be built in.
    PacketTooLong {
        /// What it needed.
        need: usize,
        /// What there was.
        got: usize,
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
}

impl From<SdpError> for MediaError {
    fn from(error: SdpError) -> Self {
        Self::Description(error)
    }
}

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
            Self::Codec(error) => write!(f, "codec: {error}"),
            Self::PacketTooLong { need, got } => {
                write!(f, "the packet needs {need} octets and there are {got}")
            }
            Self::Recording(kind) => write!(f, "recording: {kind}"),
            Self::NotRecording => f.write_str("nothing is being recorded on this call"),
            Self::AlreadyRecording => f.write_str("this call is already being recorded"),
            Self::Signalling(error) => write!(f, "user agent: {error}"),
        }
    }
}

impl core::error::Error for MediaError {}
