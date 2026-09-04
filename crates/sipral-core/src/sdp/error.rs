// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
        }
    }
}

impl core::error::Error for SdpError {}
