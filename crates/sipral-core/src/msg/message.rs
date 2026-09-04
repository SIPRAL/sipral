// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A parsed message as a view over the buffer it arrived in.

use super::method::{Method, StatusCode};
use super::span::{HeaderSlot, Span};

/// Whether a message is a request or a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind<'a> {
    /// A request, and its method.
    Request(Method<'a>),
    /// A response, and its status code.
    Response(StatusCode),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum StartLine {
    Request { method: Span, uri: Span },
    Response { code: StatusCode, reason: Span },
}

/// A parsed message. Every accessor locates and validates a span; none
/// allocates and none copies. The view borrows both the message buffer and the
/// index built by [`super::parse`], so it never outlives either.
#[derive(Clone, Copy)]
pub struct RawMessage<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) start: StartLine,
    pub(crate) headers: &'a [HeaderSlot],
    pub(crate) body: Span,
}

impl<'a> RawMessage<'a> {
    /// Request or response.
    #[must_use]
    pub fn kind(&self) -> MessageKind<'a> {
        match self.start {
            StartLine::Request { method, .. } => {
                // the parser only builds this variant from a valid token
                MessageKind::Request(
                    Method::from_bytes(method.slice(self.buf)).unwrap_or(Method::Extension("")),
                )
            }
            StartLine::Response { code, .. } => MessageKind::Response(code),
        }
    }

    /// The method, for a request.
    #[must_use]
    pub fn method(&self) -> Option<Method<'a>> {
        match self.kind() {
            MessageKind::Request(m) => Some(m),
            MessageKind::Response(_) => None,
        }
    }

    /// The status code, for a response.
    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        match self.start {
            StartLine::Response { code, .. } => Some(code),
            StartLine::Request { .. } => None,
        }
    }

    /// The reason phrase, for a response. May be empty, which is legal.
    #[must_use]
    pub fn reason(&self) -> Option<&'a [u8]> {
        match self.start {
            StartLine::Response { reason, .. } => Some(reason.slice(self.buf)),
            StartLine::Request { .. } => None,
        }
    }

    /// The Request-URI as it appeared, for a request. Parsing it is the URI
    /// layer's job.
    #[must_use]
    pub fn request_uri(&self) -> Option<&'a [u8]> {
        match self.start {
            StartLine::Request { uri, .. } => Some(uri.slice(self.buf)),
            StartLine::Response { .. } => None,
        }
    }

    /// The message body, delimited by `Content-Length` when one was present.
    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        self.body.slice(self.buf)
    }

    /// The located header fields, in wire order.
    #[must_use]
    pub fn header_slots(&self) -> &'a [HeaderSlot] {
        self.headers
    }

    /// Name and value of every header field, in wire order. A folded value
    /// still carries its interior CRLF; unfolding belongs to the typed
    /// accessors.
    pub fn raw_headers(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + use<'a> {
        let buf = self.buf;
        self.headers
            .iter()
            .map(move |slot| (slot.name.slice(buf), slot.value.slice(buf)))
    }

    /// Every value of one header field, matched case-insensitively on the
    /// exact name given. Compact forms are the typed accessors' business.
    pub fn raw_header_values(&self, name: &'a [u8]) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        self.raw_headers()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// The whole message as it was received, body included.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }
}

impl core::fmt::Debug for RawMessage<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawMessage")
            .field("kind", &self.kind())
            .field("headers", &self.headers.len())
            .field("body", &self.body.len())
            .finish()
    }
}
