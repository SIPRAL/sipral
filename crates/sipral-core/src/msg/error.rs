// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
    /// A message arrived on a stream transport without a `Content-Length`.
    ///
    /// RFC 3261 §18.3 makes the field mandatory there, because it is the only
    /// thing that says where one message ends and the next begins. A datagram
    /// may leave it out; a stream may not.
    MissingContentLength,
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
            Self::MissingContentLength => f.write_str("no Content-Length on a stream transport"),
        }
    }
}

impl core::error::Error for ParseError {}

/// Why one header field's value could not be interpreted.
///
/// A message whose framing is sound can still carry a header nobody can read.
/// That is not a reason to have refused the message: it is a decision for the
/// layer that wanted the field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The field is not in the message.
    Missing,
    /// The value does not match the field's grammar.
    Malformed(&'static str),
    /// The field appears more times than it may.
    UnexpectedRepeat,
    /// A value that must be a number is legal digits but does not fit.
    OutOfRange,
    /// Bytes that are not UTF-8 where the grammar requires text.
    NotUtf8,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Missing => f.write_str("header field is absent"),
            Self::Malformed(what) => write!(f, "malformed header field: {what}"),
            Self::UnexpectedRepeat => f.write_str("header field appears more than once"),
            Self::OutOfRange => f.write_str("numeric value out of range"),
            Self::NotUtf8 => f.write_str("not UTF-8"),
        }
    }
}

impl core::error::Error for HeaderError {}
