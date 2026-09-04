// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a parse can refuse, and why.

use core::fmt;

/// Why a message could not be parsed.
///
/// Every variant carries enough to point at the offending byte, because the
/// first question about a rejected message on a live port is always "where".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Nothing to parse.
    Empty,
    /// The request or status line does not conform.
    BadStartLine {
        /// Offset of the start line.
        at: u32,
    },
    /// A header line has no name, no colon, or an unusable value.
    BadHeaderLine {
        /// Offset of the offending line.
        at: u32,
    },
    /// The headers never end: no empty line before the buffer runs out.
    UnterminatedHeaders,
    /// `Content-Length` claims more than the buffer holds.
    BodyTruncated {
        /// What the header claimed.
        declared: u32,
        /// What was actually there.
        available: u32,
    },
    /// Two `Content-Length` headers that do not agree, so framing is undefined.
    ConflictingContentLength {
        /// The first value seen.
        first: u32,
        /// The value that contradicted it.
        second: u32,
    },
    /// A header value is longer than the configured bound.
    HeaderValueTooLong {
        /// Offset of that header's name.
        name_at: u32,
        /// The bound that was exceeded.
        limit: u32,
    },
    /// More headers than the configured bound.
    TooManyHeaders {
        /// The bound that was exceeded.
        limit: u16,
    },
    /// The message is longer than the configured bound.
    MessageTooLarge {
        /// The bound that was exceeded.
        limit: u32,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Empty => f.write_str("empty message"),
            Self::BadStartLine { at } => write!(f, "malformed start line at {at}"),
            Self::BadHeaderLine { at } => write!(f, "malformed header line at {at}"),
            Self::UnterminatedHeaders => f.write_str("headers are not terminated by an empty line"),
            Self::BodyTruncated {
                declared,
                available,
            } => write!(f, "Content-Length says {declared}, {available} available"),
            Self::ConflictingContentLength { first, second } => {
                write!(f, "Content-Length given as both {first} and {second}")
            }
            Self::HeaderValueTooLong { name_at, limit } => {
                write!(f, "header value at {name_at} exceeds {limit} bytes")
            }
            Self::TooManyHeaders { limit } => write!(f, "more than {limit} headers"),
            Self::MessageTooLarge { limit } => write!(f, "message exceeds {limit} bytes"),
        }
    }
}

impl core::error::Error for ParseError {}
