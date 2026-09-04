// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A parsed message as a view over the buffer it arrived in, and the owned
//! form the stack keeps.

use std::sync::Arc;

use super::error::HeaderError;
use super::header::HeaderName;
use super::lex::{CommaList, trim};
use super::method::{Method, StatusCode};
use super::scalar::{CSeq, Digits, RAck, digits, rseq};
use super::span::{HeaderSlot, Span};
use super::uri::{UriError, UriRef};
use super::via::ViaRef;

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

    /// The Request-URI exactly as it appeared, for a request.
    #[must_use]
    pub fn request_uri_bytes(&self) -> Option<&'a [u8]> {
        match self.start {
            StartLine::Request { uri, .. } => Some(uri.slice(self.buf)),
            StartLine::Response { .. } => None,
        }
    }

    /// The Request-URI, parsed. `None` for a response; `Some(Err(_))` when the
    /// message is a request whose URI does not parse, which is a rejection the
    /// layer above has to make, not a reason to have refused the message.
    #[must_use]
    pub fn request_uri(&self) -> Option<Result<UriRef<'a>, UriError>> {
        self.request_uri_bytes().map(UriRef::parse)
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

    /// The names of every header field, in wire order.
    pub fn header_names(&self) -> impl Iterator<Item = HeaderName<'a>> + use<'a> {
        self.raw_headers()
            .filter_map(|(n, _)| HeaderName::from_bytes(n))
    }

    /// Every value of one field, in wire order. Compact and long forms are the
    /// same field, so asking for `Via` finds a `v:` line too.
    pub fn header_values<'n>(
        &self,
        name: HeaderName<'n>,
    ) -> impl Iterator<Item = &'a [u8]> + use<'a, 'n> {
        self.raw_headers()
            .filter(move |(n, _)| HeaderName::from_bytes(n).is_some_and(|got| got == name))
            .map(|(_, v)| v)
    }

    /// The first value of one field, if it is present.
    #[must_use]
    pub fn header(&self, name: HeaderName<'_>) -> Option<&'a [u8]> {
        self.header_values(name).next()
    }

    /// How many times a field appears. Several `Via` lines are normal; several
    /// `Call-ID` lines are a malformed message the layers above must refuse.
    #[must_use]
    pub fn header_count(&self, name: HeaderName<'_>) -> usize {
        self.header_values(name).count()
    }

    /// The one value of a field that may appear only once.
    ///
    /// # Errors
    /// [`HeaderError::Missing`] when it is absent, [`HeaderError::UnexpectedRepeat`]
    /// when it appears more than once — RFC 4475 §3.3.8 is a message that does
    /// exactly that, and picking one of the values silently is how a stack ends
    /// up disagreeing with the proxy in front of it.
    pub fn single(&self, name: HeaderName<'_>) -> Result<&'a [u8], HeaderError> {
        let mut it = self.header_values(name);
        let first = it.next().ok_or(HeaderError::Missing)?;
        if it.next().is_some() {
            return Err(HeaderError::UnexpectedRepeat);
        }
        Ok(first)
    }

    /// Every `Via` value, in the order that decides where a response goes.
    ///
    /// Header lines in wire order, and within each line the comma-separated
    /// values in wire order, because RFC 3261 §7.3.1 says the two spellings
    /// have to mean the same thing. The top one is the first item.
    pub fn via(&self) -> impl Iterator<Item = Result<ViaRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::Via)
            .flat_map(CommaList::new)
            .map(ViaRef::parse)
    }

    /// The topmost `Via`, which is the one the transport layer answers to.
    ///
    /// # Errors
    /// [`HeaderError::Missing`] when there is none, or whatever
    /// [`ViaRef::parse`] refused.
    pub fn top_via(&self) -> Result<ViaRef<'a>, HeaderError> {
        self.via().next().unwrap_or(Err(HeaderError::Missing))
    }

    /// `Call-ID`, opaque (RFC 3261 §20.8).
    ///
    /// # Errors
    /// See [`RawMessage::single`].
    pub fn call_id(&self) -> Result<&'a [u8], HeaderError> {
        self.single(HeaderName::CallId).map(trim)
    }

    /// `CSeq` (RFC 3261 §20.16).
    ///
    /// # Errors
    /// See [`CSeq::parse`] and [`RawMessage::single`].
    pub fn cseq(&self) -> Result<CSeq<'a>, HeaderError> {
        CSeq::parse(self.single(HeaderName::CSeq)?)
    }

    /// `Max-Forwards` (RFC 3261 §20.22).
    ///
    /// # Errors
    /// See [`digits`] and [`RawMessage::single`].
    pub fn max_forwards(&self) -> Result<Digits, HeaderError> {
        digits(self.single(HeaderName::MaxForwards)?)
    }

    /// `Expires` (RFC 3261 §20.19).
    ///
    /// # Errors
    /// See [`digits`] and [`RawMessage::single`].
    pub fn expires(&self) -> Result<Digits, HeaderError> {
        digits(self.single(HeaderName::Expires)?)
    }

    /// `Content-Length` (RFC 3261 §20.14).
    ///
    /// The parser already used this to frame the body; this is the field as
    /// written, for a layer that wants to reason about it.
    ///
    /// # Errors
    /// See [`digits`] and [`RawMessage::single`].
    pub fn content_length(&self) -> Result<Digits, HeaderError> {
        digits(self.single(HeaderName::ContentLength)?)
    }

    /// `RSeq` (RFC 3262 §7.1).
    ///
    /// # Errors
    /// See [`rseq`] and [`RawMessage::single`].
    pub fn rseq(&self) -> Result<u32, HeaderError> {
        rseq(self.single(HeaderName::RSeq)?)
    }

    /// `RAck` (RFC 3262 §7.2).
    ///
    /// # Errors
    /// See [`RAck::parse`] and [`RawMessage::single`].
    pub fn rack(&self) -> Result<RAck<'a>, HeaderError> {
        RAck::parse(self.single(HeaderName::RAck)?)
    }

    /// The whole message as it was received, body included.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// The one seam where a borrowed view becomes something the stack can keep.
    ///
    /// The bytes are copied once into a refcounted buffer and the header index
    /// is moved alongside them; every span stays valid because it was already
    /// an offset from the start of the message. Anything past the body — a
    /// second request sharing the datagram, say — is left behind.
    #[must_use]
    pub fn to_owned(&self) -> OwnedMessage {
        let end = (self.body.end as usize).min(self.buf.len());
        OwnedMessage {
            bytes: Arc::from(self.buf.get(..end).unwrap_or(self.buf)),
            start: self.start,
            headers: Arc::from(self.headers),
            body: self.body,
        }
    }
}

/// A message the stack owns.
///
/// The same bytes and the same header index as the [`RawMessage`] it came
/// from, so every accessor works unchanged through [`OwnedMessage::as_raw`].
/// Cloning is two refcount bumps; a retransmission never re-copies and never
/// re-parses.
#[derive(Clone)]
pub struct OwnedMessage {
    bytes: Arc<[u8]>,
    start: StartLine,
    headers: Arc<[HeaderSlot]>,
    body: Span,
}

impl OwnedMessage {
    /// A borrowed view, with the whole accessor surface on it.
    #[must_use]
    pub fn as_raw(&self) -> RawMessage<'_> {
        RawMessage {
            buf: &self.bytes,
            start: self.start,
            headers: &self.headers,
            body: self.body,
        }
    }

    /// The wire bytes, ready to hand to a transport. Cheap to clone.
    #[must_use]
    pub fn bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }

    /// How many bytes go on the wire.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether there is nothing to send, which a parsed message never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl core::fmt::Debug for OwnedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.as_raw().fmt(f)
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
