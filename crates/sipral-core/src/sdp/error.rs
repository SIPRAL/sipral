// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a session description can be refused for.

use core::fmt;

/// Why a session description could not be read, or an answer could not be
/// built from one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SdpError {
    /// Bytes that are not UTF-8. RFC 4566 §5 makes the text ISO-10646 in
    /// UTF-8 unless `a=charset` says otherwise, and that attribute is not
    /// implemented here.
    NotUtf8,
    /// Nothing to read.
    Empty,
    /// A line that is not `<type>=<value>`.
    BadLine {
        /// Which line, counted from one.
        line: usize,
    },
    /// A type letter that is not one of the fourteen §5 defines.
    ///
    /// The whole description is refused rather than the line: "The set of type
    /// letters is deliberately small and not intended to be extensible — an
    /// SDP parser MUST completely ignore any session description that contains
    /// a type letter that it does not understand."
    UnknownType {
        /// Which line, counted from one.
        line: usize,
        /// The letter.
        kind: char,
    },
    /// A line that is legal SDP but not where §5 puts it.
    OutOfOrder {
        /// Which line, counted from one.
        line: usize,
        /// The letter.
        kind: char,
    },
    /// `v=` is not `0`, the only version there is.
    UnsupportedVersion,
    /// A line §5 makes mandatory is absent.
    Missing(&'static str),
    /// A field that has to be a number is not one, or does not fit.
    BadNumber {
        /// Which line, counted from one.
        line: usize,
    },
    /// A line with fewer sub-fields than its syntax demands.
    Incomplete {
        /// Which line, counted from one.
        line: usize,
    },
    /// An answer with a different number of streams than the offer: RFC 3264
    /// §6 matches them up by position, so the counts have to agree.
    StreamCount {
        /// How many the offer had.
        offered: usize,
        /// How many the answer was given.
        answered: usize,
    },
    /// A stream accepted without one media format in common with the offer.
    /// §6.1 answers that case with a rejected stream, not a made-up one.
    NoCommonFormat {
        /// Which stream, counted from zero.
        stream: usize,
    },
    /// The body is longer than the configured bound.
    BodyTooLarge {
        /// The bound that was exceeded.
        limit: u32,
    },
    /// A line longer than the configured bound.
    LineTooLong {
        /// Which line, counted from one.
        line: usize,
        /// The bound that was exceeded.
        limit: u32,
    },
    /// More `m=` blocks than the configured bound.
    TooManyStreams {
        /// The bound that was exceeded.
        limit: u16,
    },
    /// More `a=` lines than the configured bound, session level and media
    /// level together.
    TooManyAttributes {
        /// The bound that was exceeded.
        limit: u16,
    },
    /// More `a=` lines than the configured bound in one section alone — the
    /// session level, or one `m=` block.
    TooManyAttributesInSection {
        /// The bound that was exceeded.
        limit: u16,
    },
    /// More format tokens on one `m=` line than the configured bound.
    TooManyFormats {
        /// The bound that was exceeded.
        limit: u16,
    },
    /// A plan was asked for a stream one of the two descriptions does not
    /// have.
    NoSuchStream {
        /// Which stream, counted from zero.
        stream: usize,
    },
    /// Two descriptions of one session with different numbers of streams.
    /// RFC 3264 §6 matches them up by position, so there is no way to tell
    /// which stream is which.
    StreamMismatch {
        /// How many this end wrote.
        local: usize,
        /// How many the peer wrote.
        remote: usize,
    },
    /// A stream whose `c=` is a host name rather than an address. Resolving it
    /// is I/O, and nothing here does I/O.
    NoAddress {
        /// Which stream, counted from zero.
        stream: usize,
    },
    /// A stream both ends accepted with no codec in common, which should have
    /// been a rejected stream instead.
    NoCodec {
        /// Which stream, counted from zero.
        stream: usize,
    },
    /// An `a=crypto` in one description that answers nothing in the other.
    /// RFC 4568 §5.1.2 has the answer carry "the tag and crypto-suite from the
    /// accepted crypto attribute in the offer", so a tag that was never
    /// offered means the two ends are not talking about the same key.
    CryptoNotOffered {
        /// Which stream, counted from zero.
        stream: usize,
    },
    /// A stream on a secure profile that ended up with no keying material at
    /// all. Sending in the clear because the keys did not arrive is the one
    /// outcome worse than dropping the stream.
    CryptoMissing {
        /// Which stream, counted from zero.
        stream: usize,
    },
    /// The far end sent back a master key we offered. RFC 4568 §7.1.2: "the
    /// master key(s) included in the answer MUST be different from those in
    /// the offer", because the default transform is insecure when one key
    /// protects two streams — the same keystream would encrypt both
    /// directions.
    CryptoKeyReused {
        /// Which stream, counted from zero.
        stream: usize,
    },
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotUtf8 => f.write_str("not UTF-8"),
            Self::Empty => f.write_str("empty session description"),
            Self::BadLine { line } => write!(f, "line {line} is not type=value"),
            Self::UnknownType { line, kind } => {
                write!(f, "unknown type letter {kind:?} on line {line}")
            }
            Self::OutOfOrder { line, kind } => {
                write!(f, "{kind}= out of order on line {line}")
            }
            Self::UnsupportedVersion => f.write_str("only SDP version 0 exists"),
            Self::Missing(what) => write!(f, "no {what} line"),
            Self::BadNumber { line } => write!(f, "malformed number on line {line}"),
            Self::Incomplete { line } => write!(f, "line {line} is missing sub-fields"),
            Self::StreamCount { offered, answered } => write!(
                f,
                "the offer has {offered} streams and the answer {answered}"
            ),
            Self::NoCommonFormat { stream } => {
                write!(f, "stream {stream} was accepted with no offered format")
            }
            Self::BodyTooLarge { limit } => write!(f, "body exceeds {limit} bytes"),
            Self::LineTooLong { line, limit } => {
                write!(f, "line {line} exceeds {limit} bytes")
            }
            Self::TooManyStreams { limit } => write!(f, "more than {limit} media descriptions"),
            Self::TooManyAttributes { limit } => write!(f, "more than {limit} attributes"),
            Self::TooManyAttributesInSection { limit } => {
                write!(f, "more than {limit} attributes in one section")
            }
            Self::TooManyFormats { limit } => {
                write!(f, "more than {limit} formats on one m= line")
            }
            Self::NoSuchStream { stream } => write!(f, "there is no stream {stream}"),
            Self::StreamMismatch { local, remote } => {
                write!(f, "we describe {local} streams and the peer {remote}")
            }
            Self::NoAddress { stream } => {
                write!(f, "stream {stream} has no connection address")
            }
            Self::NoCodec { stream } => write!(f, "stream {stream} settled on no codec"),
            Self::CryptoNotOffered { stream } => {
                write!(f, "stream {stream} names keys that were never offered")
            }
            Self::CryptoMissing { stream } => {
                write!(f, "stream {stream} is secured and has no keys")
            }
            Self::CryptoKeyReused { stream } => {
                write!(f, "stream {stream} came back with a key we sent")
            }
        }
    }
}

impl core::error::Error for SdpError {}
