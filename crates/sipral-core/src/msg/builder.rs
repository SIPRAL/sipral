// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Writing a message out.
//!
//! The same inputs always produce the same bytes: a retransmission has to be
//! the identical datagram (RFC 3261 §17.1.1.2). Field order is fixed: `Via`
//! first (§7), then routing and dialog fields, then the caller's fields in
//! the order added, then `Content-Type` and `Content-Length`.
//!
//! Inputs are borrowed and copied once at [`RequestBuilder::build`].
//!
//! A fold in a value goes out as one space (§7.3.1), so a value copied from
//! a folded message can be written back. Any other CR or LF is refused: it
//! would inject a header or a body.

use std::sync::Arc;

use super::error::ParseError;
use super::header::HeaderName;
use super::message::OwnedMessage;
use super::method::{Method, StatusCode, is_token_byte};
use super::parse::{Limits, ParseMode, parse_with_limits};
use super::span::ParseScratch;

/// Why a message could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A field RFC 3261 §8.1.1 requires is missing.
    MissingField(&'static str),
    /// A value holds something that cannot go on a header line.
    IllegalValue(&'static str),
    /// A field the building layer writes itself was added by name. Two lines
    /// of it would be read differently by the two ends.
    OwnedField(&'static str),
    /// The output does not parse: a bug here, not in the caller.
    NotWellFormed(ParseError),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::MissingField(name) => write!(f, "{name} is required"),
            Self::IllegalValue(what) => write!(f, "illegal value: {what}"),
            Self::OwnedField(name) => {
                write!(f, "{name} is written here and is not taken by name")
            }
            Self::NotWellFormed(e) => write!(f, "the built message does not parse: {e}"),
        }
    }
}

impl core::error::Error for BuildError {}

/// The order fields go out in. Everything else follows in the order it was
/// added, and the body's own two fields come last.
const ORDER: &[HeaderName<'static>] = &[
    HeaderName::Via,
    HeaderName::Route,
    HeaderName::RecordRoute,
    HeaderName::MaxForwards,
    HeaderName::From,
    HeaderName::To,
    HeaderName::CallId,
    HeaderName::CSeq,
    HeaderName::Contact,
];

#[derive(Clone, Debug, Default)]
struct Fields<'a> {
    headers: Vec<(HeaderName<'a>, Value<'a>)>,
    content_type: Option<&'a [u8]>,
    body: &'a [u8],
}

/// A header value, borrowed from the caller or built here for a number.
#[derive(Clone, Copy, Debug)]
enum Value<'a> {
    Bytes(&'a [u8]),
    Number(u32),
    NumberThenMethod(u32, Method<'a>),
    ToWithTag(&'a [u8], &'a [u8]),
}

impl Fields<'_> {
    fn has(&self, name: HeaderName<'_>) -> bool {
        self.headers.iter().any(|(n, _)| *n == name)
    }

    fn require(&self, name: HeaderName<'_>, label: &'static str) -> Result<(), BuildError> {
        if self.has(name) {
            Ok(())
        } else {
            Err(BuildError::MissingField(label))
        }
    }

    fn write_into(&self, out: &mut Vec<u8>) -> Result<(), BuildError> {
        for wanted in ORDER {
            for (name, value) in &self.headers {
                if name == wanted {
                    write_header(out, *name, *value)?;
                }
            }
        }
        for (name, value) in &self.headers {
            if !ORDER.contains(name) {
                write_header(out, *name, *value)?;
            }
        }
        if let Some(ct) = self.content_type {
            write_header(out, HeaderName::ContentType, Value::Bytes(ct))?;
        }
        // always written: a stream needs it, and §20.14 asks for it anyway
        let len = u32::try_from(self.body.len())
            .map_err(|_| BuildError::IllegalValue("body does not fit in 32 bits"))?;
        write_header(out, HeaderName::ContentLength, Value::Number(len))?;
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(self.body);
        Ok(())
    }
}

fn write_header(
    out: &mut Vec<u8>,
    name: HeaderName<'_>,
    value: Value<'_>,
) -> Result<(), BuildError> {
    out.extend_from_slice(name.canonical().as_bytes());
    out.extend_from_slice(b": ");
    match value {
        Value::Bytes(v) => write_value(out, v)?,
        Value::Number(n) => write_number(out, n),
        Value::NumberThenMethod(n, m) => {
            write_number(out, n);
            out.extend_from_slice(b" ");
            out.extend_from_slice(m.as_str().as_bytes());
        }
        Value::ToWithTag(v, tag) => {
            if tag.is_empty() || !tag.iter().copied().all(is_token_byte) {
                return Err(BuildError::IllegalValue("a tag is a token"));
            }
            write_value(out, v)?;
            out.extend_from_slice(b";tag=");
            out.extend_from_slice(tag);
        }
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// One header value, on one line.
///
/// RFC 3261 §7.3.1: a fold stands for a single SP, so each fold goes out as
/// a space. Any other CR or LF is refused.
fn write_value(out: &mut Vec<u8>, value: &[u8]) -> Result<(), BuildError> {
    let mut i = 0;
    while let Some(&byte) = value.get(i) {
        if !matches!(byte, b'\r' | b'\n') {
            out.push(byte);
            i += 1;
            continue;
        }
        let lf = if byte == b'\r' { i + 1 } else { i };
        if value.get(lf) != Some(&b'\n') || !matches!(value.get(lf + 1), Some(b' ' | b'\t')) {
            return Err(BuildError::IllegalValue(
                "a header value cannot hold CR or LF",
            ));
        }
        i = lf + 1;
        while matches!(value.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        out.push(b' ');
    }
    Ok(())
}

fn write_number(out: &mut Vec<u8>, mut n: u32) {
    let mut digits = [0_u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        if let Some(d) = digits.get_mut(i) {
            *d = b'0' + u8::try_from(n % 10).unwrap_or(0);
        }
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(digits.get(i..).unwrap_or_default());
}

fn check(value: &[u8]) -> Result<(), BuildError> {
    if value.iter().any(|&b| b == b'\r' || b == b'\n') {
        return Err(BuildError::IllegalValue(
            "a header value cannot hold CR or LF",
        ));
    }
    Ok(())
}

/// Read back what was written, strictly, so nothing leaves that this stack
/// would not accept.
///
/// The per-value bound is lifted: a response must carry back the request's
/// fields as they arrived (§8.2.6.2), even the one that was too long.
fn finish(out: Vec<u8>) -> Result<OwnedMessage, BuildError> {
    let bytes: Arc<[u8]> = Arc::from(out);
    let mut scratch = ParseScratch::new();
    let limits = Limits {
        max_header_value_bytes: Limits::DEFAULT.max_message_bytes,
        ..Limits::DEFAULT
    };
    let raw = parse_with_limits(&bytes, &mut scratch, ParseMode::Strict, limits)
        .map_err(BuildError::NotWellFormed)?;
    Ok(OwnedMessage::adopt(Arc::clone(&bytes), &raw))
}

/// Writes a request.
#[derive(Clone, Debug)]
pub struct RequestBuilder<'a> {
    method: Method<'a>,
    uri: &'a [u8],
    fields: Fields<'a>,
}

impl<'a> RequestBuilder<'a> {
    /// Start a request.
    #[must_use]
    pub fn new(method: Method<'a>, request_uri: &'a [u8]) -> Self {
        Self {
            method,
            uri: request_uri,
            fields: Fields::default(),
        }
    }

    /// Add one `Via` value. Call it again for another, topmost first.
    #[must_use]
    pub fn via(self, value: &'a [u8]) -> Self {
        self.header(HeaderName::Via, value)
    }

    /// `From`, tag included.
    #[must_use]
    pub fn from(self, value: &'a [u8]) -> Self {
        self.header(HeaderName::From, value)
    }

    /// `To`.
    #[must_use]
    pub fn to(self, value: &'a [u8]) -> Self {
        self.header(HeaderName::To, value)
    }

    /// `Call-ID`.
    #[must_use]
    pub fn call_id(self, value: &'a [u8]) -> Self {
        self.header(HeaderName::CallId, value)
    }

    /// `CSeq`. The method is the request's own, which §8.1.1.5 requires.
    #[must_use]
    pub fn cseq(mut self, seq: u32) -> Self {
        self.fields
            .headers
            .push((HeaderName::CSeq, Value::NumberThenMethod(seq, self.method)));
        self
    }

    /// `Max-Forwards`. 70 is the value §8.1.1.6 tells a UAC to use.
    #[must_use]
    pub fn max_forwards(mut self, n: u32) -> Self {
        self.fields
            .headers
            .push((HeaderName::MaxForwards, Value::Number(n)));
        self
    }

    /// `Contact`.
    #[must_use]
    pub fn contact(self, value: &'a [u8]) -> Self {
        self.header(HeaderName::Contact, value)
    }

    /// Add one `Route` value. Call it again for the next hop, in order.
    #[must_use]
    pub fn route(self, value: &'a [u8]) -> Self {
        self.header(HeaderName::Route, value)
    }

    /// Any other field. Repeated calls add repeated lines, in order.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'a>, value: &'a [u8]) -> Self {
        self.fields.headers.push((name, Value::Bytes(value)));
        self
    }

    /// The body and the type that describes it.
    #[must_use]
    pub fn body(mut self, content_type: &'a [u8], body: &'a [u8]) -> Self {
        self.fields.content_type = Some(content_type);
        self.fields.body = body;
        self
    }

    /// Write the message.
    ///
    /// # Errors
    /// [`BuildError::MissingField`] for any of the six fields §8.1.1 makes
    /// mandatory in a request, and [`BuildError::IllegalValue`] for a value
    /// with a line break in it that is not a fold.
    pub fn build(self) -> Result<OwnedMessage, BuildError> {
        self.fields.require(HeaderName::Via, "Via")?;
        self.fields
            .require(HeaderName::MaxForwards, "Max-Forwards")?;
        self.fields.require(HeaderName::From, "From")?;
        self.fields.require(HeaderName::To, "To")?;
        self.fields.require(HeaderName::CallId, "Call-ID")?;
        self.fields.require(HeaderName::CSeq, "CSeq")?;
        if self.uri.is_empty() {
            return Err(BuildError::MissingField("Request-URI"));
        }
        check(self.uri)?;
        if self.uri.iter().any(|&b| b == b' ' || b == b'\t') {
            return Err(BuildError::IllegalValue("the Request-URI holds whitespace"));
        }

        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(self.method.as_str().as_bytes());
        out.extend_from_slice(b" ");
        out.extend_from_slice(self.uri);
        out.extend_from_slice(b" SIP/2.0\r\n");
        self.fields.write_into(&mut out)?;
        finish(out)
    }
}

/// Writes a response to a request.
#[derive(Clone, Debug)]
pub struct ResponseBuilder<'a> {
    status: StatusCode,
    reason: Option<&'a [u8]>,
    fields: Fields<'a>,
}

impl<'a> ResponseBuilder<'a> {
    /// Start a response, copying what RFC 3261 §8.2.6.2 says must be equal:
    /// every `Via` in order, `From`, `To`, `Call-ID`, `CSeq`.
    ///
    /// The `To` tag is added by [`ResponseBuilder::to_tag`], since a 100 Trying
    /// has none. `Record-Route` is added by
    /// [`ResponseBuilder::copy_record_route`], since only the answerer knows if
    /// this response establishes a dialog (§12.1.1).
    #[must_use]
    pub fn for_request(request: &super::message::RawMessage<'a>, status: StatusCode) -> Self {
        let mut fields = Fields::default();
        for via in request.header_values(HeaderName::Via) {
            fields.headers.push((HeaderName::Via, Value::Bytes(via)));
        }
        for name in [
            HeaderName::From,
            HeaderName::To,
            HeaderName::CallId,
            HeaderName::CSeq,
        ] {
            if let Some(value) = request.header(name) {
                fields.headers.push((name, Value::Bytes(value)));
            }
        }
        Self {
            status,
            reason: None,
            fields,
        }
    }

    /// Copy the request's `Record-Route` values, in order, which §12.1.1
    /// requires of a response that establishes a dialog.
    #[must_use]
    pub fn copy_record_route(mut self, request: &super::message::RawMessage<'a>) -> Self {
        for value in request.header_values(HeaderName::RecordRoute) {
            self.fields
                .headers
                .push((HeaderName::RecordRoute, Value::Bytes(value)));
        }
        self
    }

    /// Add a tag to `To`, unless the request already carried one.
    ///
    /// §8.2.6.2: with a tag in the request, `To` is copied whole.
    #[must_use]
    pub fn to_tag(mut self, tag: &'a [u8]) -> Self {
        let already = self
            .fields
            .headers
            .iter()
            .any(|(n, v)| *n == HeaderName::To && has_tag(*v));
        if already {
            return self;
        }
        for (name, value) in &mut self.fields.headers {
            if *name == HeaderName::To
                && let Value::Bytes(v) = *value
            {
                *value = Value::ToWithTag(v, tag);
            }
        }
        self
    }

    /// Use a reason phrase other than the one RFC 3261 §21 registers.
    #[must_use]
    pub fn reason(mut self, reason: &'a [u8]) -> Self {
        self.reason = Some(reason);
        self
    }

    /// `Contact`, which §12.1.1 requires of a response that establishes a
    /// dialog.
    #[must_use]
    pub fn contact(self, value: &'a [u8]) -> Self {
        self.header(HeaderName::Contact, value)
    }

    /// Any other field.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'a>, value: &'a [u8]) -> Self {
        self.fields.headers.push((name, Value::Bytes(value)));
        self
    }

    /// The body and the type that describes it.
    #[must_use]
    pub fn body(mut self, content_type: &'a [u8], body: &'a [u8]) -> Self {
        self.fields.content_type = Some(content_type);
        self.fields.body = body;
        self
    }

    /// Write the message.
    ///
    /// # Errors
    /// [`BuildError::MissingField`] when the request was missing one of the
    /// fields §8.2.6.2 has to copy, and [`BuildError::IllegalValue`] for a
    /// value with a line break in it that is not a fold.
    pub fn build(self) -> Result<OwnedMessage, BuildError> {
        self.fields.require(HeaderName::Via, "Via")?;
        self.fields.require(HeaderName::From, "From")?;
        self.fields.require(HeaderName::To, "To")?;
        self.fields.require(HeaderName::CallId, "Call-ID")?;
        self.fields.require(HeaderName::CSeq, "CSeq")?;
        self.build_refusal()
    }

    /// Write a refusal of a request that lacks some of what a response copies,
    /// copying whichever of `From`, `To`, `Call-ID`, `CSeq` it had.
    ///
    /// RFC 4475 §3.3.1 sends a request with no `From`, `To` or `Call-ID` and
    /// expects a 400. The `Via` is still required: the answer is routed
    /// (§18.2.2) and matched (§17.1.3) by it. For stateless 4xx or 5xx only.
    ///
    /// # Errors
    /// [`BuildError::MissingField`] without a `Via`, and
    /// [`BuildError::IllegalValue`] for a line break that is not a fold.
    pub fn build_refusal(self) -> Result<OwnedMessage, BuildError> {
        self.fields.require(HeaderName::Via, "Via")?;

        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(b"SIP/2.0 ");
        write_number(&mut out, u32::from(self.status.get()));
        out.extend_from_slice(b" ");
        match self.reason {
            Some(r) => {
                check(r)?;
                out.extend_from_slice(r);
            }
            None => out.extend_from_slice(self.status.reason().unwrap_or_default().as_bytes()),
        }
        out.extend_from_slice(b"\r\n");
        self.fields.write_into(&mut out)?;
        finish(out)
    }
}

/// The fields RFC 3261 itself gives a one-letter form (§7.3.3, §20).
///
/// Later extensions' compact forms are left long on purpose: a far end that
/// only knows the long name silently misses the field. These ten are a MUST
/// to accept (§7.3.3).
const RFC3261_COMPACT: &[HeaderName<'static>] = &[
    HeaderName::CallId,
    HeaderName::Contact,
    HeaderName::ContentEncoding,
    HeaderName::ContentLength,
    HeaderName::ContentType,
    HeaderName::From,
    HeaderName::Subject,
    HeaderName::Supported,
    HeaderName::To,
    HeaderName::Via,
];

/// Fields whose value is a comma-separated list of tokens, and so is the same
/// list with no whitespace around its commas.
const TOKEN_LISTS: &[HeaderName<'static>] = &[
    HeaderName::Allow,
    HeaderName::Supported,
    HeaderName::Require,
    HeaderName::ProxyRequire,
    HeaderName::Unsupported,
];

/// The same request in fewer bytes, for one too large for its transport.
///
/// Uses the compact forms of §7.3.3, no space after colons (§7.3.1) and no
/// whitespace around commas in token lists. Fields in `leave_out` are
/// dropped: meant for `Allow`, which §13.2.1 only recommends and §20.5 lets
/// be absent, but not trimmed. Body, start line and field order are kept.
///
/// # Errors
/// [`BuildError::IllegalValue`] for a line break that is not a fold, and
/// [`BuildError::NotWellFormed`] if the output does not parse (a bug here).
pub fn compact_request(
    request: &super::message::RawMessage<'_>,
    leave_out: &[HeaderName<'_>],
) -> Result<OwnedMessage, BuildError> {
    let bytes = request.as_bytes();
    let start = bytes
        .windows(2)
        .position(|pair| pair == b"\r\n")
        .and_then(|end| bytes.get(..end))
        .ok_or(BuildError::MissingField("start line"))?;
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(start);
    out.extend_from_slice(b"\r\n");
    for (written, value) in request.raw_headers() {
        let name = HeaderName::from_bytes(written);
        if name.is_some_and(|name| leave_out.contains(&name)) {
            continue;
        }
        match name {
            Some(known) if RFC3261_COMPACT.contains(&known) => {
                out.push(known.compact().unwrap_or_default());
            }
            _ => out.extend_from_slice(written),
        }
        out.push(b':');
        if name.is_some_and(|name| TOKEN_LISTS.contains(&name)) {
            write_tight_list(&mut out, value)?;
        } else {
            write_value(&mut out, value)?;
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(request.body());
    finish(out)
}

/// A list of tokens with the whitespace around its commas taken out, folds
/// included.
fn write_tight_list(out: &mut Vec<u8>, value: &[u8]) -> Result<(), BuildError> {
    let mut first = true;
    for item in value.split(|&byte| byte == b',') {
        let item = super::lex::trim(item);
        if item.is_empty() {
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        write_value(out, item)?;
    }
    Ok(())
}

fn has_tag(value: Value<'_>) -> bool {
    match value {
        Value::Bytes(v) => super::addr::NameAddrRef::parse(v).is_ok_and(|a| a.tag().is_some()),
        Value::ToWithTag(..) => true,
        Value::Number(_) | Value::NumberThenMethod(..) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{BuildError, RequestBuilder, ResponseBuilder};
    use crate::msg::{
        HeaderName, HostRef, Method, OwnedMessage, ParseMode, ParseScratch, RawMessage, StatusCode,
        parse,
    };

    fn invite() -> OwnedMessage {
        RequestBuilder::new(Method::Invite, b"sip:bob@example.com")
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8;rport")
            .max_forwards(70)
            .from(b"\"Alice\" <sip:alice@example.com>;tag=1928301774")
            .to(b"Bob <sip:bob@example.com>")
            .call_id(b"a84b4c76e66710@192.0.2.1")
            .cseq(314_159)
            .contact(b"<sip:alice@192.0.2.1>")
            .body(b"application/sdp", b"v=0\r\n")
            .build()
            .expect("a request")
    }

    #[test]
    fn a_request_comes_out_in_a_fixed_order() {
        assert_eq!(
            invite().as_raw().as_bytes(),
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8;rport\r\n\
Max-Forwards: 70\r\n\
From: \"Alice\" <sip:alice@example.com>;tag=1928301774\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710@192.0.2.1\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@192.0.2.1>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 5\r\n\
\r\n\
v=0\r\n"
        );
    }

    #[test]
    fn the_order_does_not_depend_on_the_order_the_caller_used() {
        let other = RequestBuilder::new(Method::Invite, b"sip:bob@example.com")
            .body(b"application/sdp", b"v=0\r\n")
            .contact(b"<sip:alice@192.0.2.1>")
            .cseq(314_159)
            .call_id(b"a84b4c76e66710@192.0.2.1")
            .to(b"Bob <sip:bob@example.com>")
            .from(b"\"Alice\" <sip:alice@example.com>;tag=1928301774")
            .max_forwards(70)
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8;rport")
            .build()
            .expect("a request");
        assert_eq!(other.as_raw().as_bytes(), invite().as_raw().as_bytes());
    }

    #[test]
    fn what_was_built_reads_back_through_the_accessors() {
        let built = invite();
        let m = built.as_raw();
        assert_eq!(m.method(), Some(Method::Invite));
        assert_eq!(m.request_uri_bytes(), Some(&b"sip:bob@example.com"[..]));
        assert_eq!(m.call_id(), Ok(&b"a84b4c76e66710@192.0.2.1"[..]));
        let cseq = m.cseq().expect("a CSeq");
        assert_eq!((cseq.seq, cseq.method), (314_159, Method::Invite));
        assert_eq!(
            m.from().expect("From").tag().as_deref(),
            Some(&b"1928301774"[..])
        );
        assert_eq!(m.to().expect("To").tag(), None);
        assert!(m.content_type().expect("a type").is("application", "sdp"));
        assert_eq!(m.body(), b"v=0\r\n");
        assert!(m.top_via().expect("Via").has_magic_cookie());
    }

    #[test]
    fn several_via_and_route_values_keep_the_order_they_were_added_in() {
        let built = RequestBuilder::new(Method::Invite, b"sip:bob@example.com")
            .via(b"SIP/2.0/UDP first;branch=z9hG4bK1")
            .via(b"SIP/2.0/TCP second;branch=z9hG4bK2")
            .route(b"<sip:p1.example.com;lr>")
            .route(b"<sip:p2.example.com;lr>")
            .max_forwards(70)
            .from(b"<sip:a@example.com>;tag=1")
            .to(b"<sip:b@example.com>")
            .call_id(b"c")
            .cseq(1)
            .build()
            .expect("a request");
        let m = built.as_raw();
        assert_eq!(m.via().count(), 2);
        assert_eq!(m.top_via().expect("Via").host, HostRef::Name("first"));
        let hops: Vec<_> = m
            .route()
            .map(|r| r.expect("a hop").uri().to_string())
            .collect();
        assert_eq!(hops, vec!["sip:p1.example.com;lr", "sip:p2.example.com;lr"]);
    }

    #[test]
    fn a_request_without_one_of_the_six_mandatory_fields_is_refused() {
        let bare = || RequestBuilder::new(Method::Options, b"sip:b@example.com");
        assert_eq!(bare().build().err(), Some(BuildError::MissingField("Via")));
        assert_eq!(
            bare().via(b"SIP/2.0/UDP h;branch=z9hG4bK1").build().err(),
            Some(BuildError::MissingField("Max-Forwards"))
        );
        assert_eq!(
            bare()
                .via(b"SIP/2.0/UDP h;branch=z9hG4bK1")
                .max_forwards(70)
                .from(b"<sip:a@example.com>;tag=1")
                .to(b"<sip:b@example.com>")
                .cseq(1)
                .build()
                .err(),
            Some(BuildError::MissingField("Call-ID"))
        );
    }

    #[test]
    fn a_value_with_a_line_break_in_it_cannot_be_written() {
        // otherwise the caller's data writes headers of its own
        let built = RequestBuilder::new(Method::Options, b"sip:b@example.com")
            .via(b"SIP/2.0/UDP h;branch=z9hG4bK1")
            .max_forwards(70)
            .from(b"<sip:a@example.com>;tag=1")
            .to(b"<sip:b@example.com>\r\nContact: <sip:evil@example.net>")
            .call_id(b"c")
            .cseq(1)
            .build();
        assert!(matches!(built, Err(BuildError::IllegalValue(_))));
    }

    #[test]
    fn a_request_uri_with_whitespace_is_refused() {
        let built = RequestBuilder::new(Method::Options, b"sip:b@example.com extra")
            .via(b"SIP/2.0/UDP h;branch=z9hG4bK1")
            .max_forwards(70)
            .from(b"<sip:a@example.com>;tag=1")
            .to(b"<sip:b@example.com>")
            .call_id(b"c")
            .cseq(1)
            .build();
        assert!(matches!(built, Err(BuildError::IllegalValue(_))));
    }

    fn with_request<T>(buf: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
        let mut scratch = ParseScratch::new();
        let m = parse(buf, &mut scratch, ParseMode::Strict).expect("a request");
        f(&m)
    }

    const REQUEST: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP first;branch=z9hG4bK1\r\n\
Via: SIP/2.0/TCP second;branch=z9hG4bK2\r\n\
Record-Route: <sip:p1.example.com;lr>\r\n\
Record-Route: <sip:p2.example.com;lr>\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
\r\n";

    #[test]
    fn a_response_copies_what_it_must() {
        // RFC 3261 8.2.6.2
        let built = with_request(REQUEST, |m| {
            ResponseBuilder::for_request(m, StatusCode::RINGING)
                .to_tag(b"a6c85cf")
                .build()
                .expect("a response")
        });
        assert_eq!(
            built.as_raw().as_bytes(),
            b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP first;branch=z9hG4bK1\r\n\
Via: SIP/2.0/TCP second;branch=z9hG4bK2\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
        );
    }

    #[test]
    fn a_response_to_a_folded_request_writes_each_fold_as_one_space() {
        // RFC 3261 §7.3.1: a fold is a single SP
        let folded = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP\r\n first;branch=z9hG4bK1\r\n\
Record-Route:\r\n <sip:p1.example.com;lr>\r\n\
Max-Forwards: 70\r\n\
From: Alice\r\n\t <sip:alice@example.com>;tag=1928301774\r\n\
To:\r\n <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159\r\n  INVITE\r\n\
\r\n";
        let built = with_request(folded, |m| {
            ResponseBuilder::for_request(m, StatusCode::OK)
                .copy_record_route(m)
                .to_tag(b"a6c85cf")
                .build()
                .expect("a response")
        });
        assert_eq!(
            built.as_raw().as_bytes(),
            b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP first;branch=z9hG4bK1\r\n\
Record-Route: <sip:p1.example.com;lr>\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
        );

        // while a line break that does not begin a fold is still not a value
        for value in [
            &b"<sip:b@example.com>\rContact: <sip:evil@example.net>"[..],
            b"<sip:b@example.com>\nContact: <sip:evil@example.net>",
            b"<sip:b@example.com>\r Contact: <sip:evil@example.net>",
            b"<sip:b@example.com>\r\n",
            b"<sip:b@example.com>\r",
        ] {
            let built = RequestBuilder::new(Method::Options, b"sip:b@example.com")
                .via(b"SIP/2.0/UDP h;branch=z9hG4bK1")
                .max_forwards(70)
                .from(b"<sip:a@example.com>;tag=1")
                .to(value)
                .call_id(b"c")
                .cseq(1)
                .build();
            assert!(
                matches!(built, Err(BuildError::IllegalValue(_))),
                "written: {:?}",
                String::from_utf8_lossy(value)
            );
        }
    }

    #[test]
    fn a_to_tag_the_request_already_carried_is_not_replaced() {
        // 8.2.6.2: with a tag in the request, the whole To field is equal
        let request = b"BYE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=theirs\r\n\
Call-ID: c\r\n\
CSeq: 2 BYE\r\n\
\r\n";
        let built = with_request(request, |m| {
            ResponseBuilder::for_request(m, StatusCode::OK)
                .to_tag(b"ours")
                .build()
                .expect("a response")
        });
        assert_eq!(
            built.as_raw().to().expect("To").tag().as_deref(),
            Some(&b"theirs"[..])
        );
    }

    #[test]
    fn record_route_is_copied_only_when_asked_for() {
        let plain = with_request(REQUEST, |m| {
            ResponseBuilder::for_request(m, StatusCode::TRYING)
                .build()
                .expect("a response")
        });
        assert_eq!(plain.as_raw().record_route().count(), 0);

        let dialog = with_request(REQUEST, |m| {
            ResponseBuilder::for_request(m, StatusCode::OK)
                .copy_record_route(m)
                .to_tag(b"ours")
                .contact(b"<sip:bob@192.0.2.4>")
                .build()
                .expect("a response")
        });
        let hops: Vec<_> = dialog
            .as_raw()
            .record_route()
            .map(|r| r.expect("a hop").uri().to_string())
            .collect();
        assert_eq!(hops, vec!["sip:p1.example.com;lr", "sip:p2.example.com;lr"]);
    }

    #[test]
    fn the_reason_phrase_comes_from_the_table_unless_one_is_given() {
        let custom = with_request(REQUEST, |m| {
            ResponseBuilder::for_request(m, StatusCode::BUSY_HERE)
                .reason(b"Ocupat")
                .to_tag(b"ours")
                .build()
                .expect("a response")
        });
        assert_eq!(custom.as_raw().reason(), Some(&b"Ocupat"[..]));
        assert_eq!(custom.as_raw().status(), Some(StatusCode::BUSY_HERE));

        let unknown = with_request(REQUEST, |m| {
            ResponseBuilder::for_request(m, StatusCode::new(499).expect("a status"))
                .to_tag(b"ours")
                .build()
                .expect("a response")
        });
        assert_eq!(unknown.as_raw().reason(), Some(&b""[..]));
    }

    #[test]
    fn a_response_to_a_request_missing_a_mandatory_field_is_refused() {
        let request = b"OPTIONS sip:b@example.com SIP/2.0\r\nVia: SIP/2.0/UDP h\r\n\r\n";
        let built = with_request(request, |m| {
            ResponseBuilder::for_request(m, StatusCode::OK).build()
        });
        assert_eq!(built.err(), Some(BuildError::MissingField("From")));
    }

    #[test]
    fn a_refusal_copies_what_the_request_had_and_invents_nothing() {
        // RFC 4475 §3.3.1 insuf: only a `Via` and a `CSeq`
        let request = b"INVITE sip:user@example.com SIP/2.0\r\n\
CSeq: 193942 INVITE\r\n\
Via: SIP/2.0/UDP 192.0.2.95;branch=z9hG4bKkdj.insuf\r\n\
\r\n";
        let built = with_request(request, |m| {
            ResponseBuilder::for_request(m, StatusCode::BAD_REQUEST)
                .to_tag(b"ours")
                .reason(b"Bad Call-ID")
                .build_refusal()
                .expect("a refusal")
        });
        assert_eq!(
            built.as_raw().as_bytes(),
            b"SIP/2.0 400 Bad Call-ID\r\n\
Via: SIP/2.0/UDP 192.0.2.95;branch=z9hG4bKkdj.insuf\r\n\
CSeq: 193942 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
        );
        // a complete request gets the same fields as `build` writes
        let whole = |refusal: bool| {
            with_request(REQUEST, |m| {
                let builder =
                    ResponseBuilder::for_request(m, StatusCode::BAD_REQUEST).to_tag(b"ours");
                if refusal {
                    builder.build_refusal()
                } else {
                    builder.build()
                }
                .expect("a response")
            })
        };
        assert_eq!(
            whole(true).as_raw().as_bytes(),
            whole(false).as_raw().as_bytes()
        );
    }

    #[test]
    fn a_refusal_still_needs_a_via_to_go_anywhere() {
        let request = b"OPTIONS sip:b@example.com SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n";
        let built = with_request(request, |m| {
            ResponseBuilder::for_request(m, StatusCode::BAD_REQUEST).build_refusal()
        });
        assert_eq!(built.err(), Some(BuildError::MissingField("Via")));
    }

    #[test]
    fn an_extra_field_keeps_its_place_after_the_known_ones() {
        let built = with_request(REQUEST, |m| {
            ResponseBuilder::for_request(m, StatusCode::UNAUTHORIZED)
                .to_tag(b"ours")
                .header(
                    HeaderName::WwwAuthenticate,
                    b"Digest realm=\"example.com\", nonce=\"n\"",
                )
                .header(HeaderName::Supported, b"100rel")
                .build()
                .expect("a response")
        });
        let names: Vec<_> = built
            .as_raw()
            .header_names()
            .map(|n| n.canonical())
            .collect();
        assert_eq!(
            names,
            vec![
                "Via",
                "Via",
                "From",
                "To",
                "Call-ID",
                "CSeq",
                "WWW-Authenticate",
                "Supported",
                "Content-Length",
            ]
        );
    }

    fn a_long_invite() -> OwnedMessage {
        RequestBuilder::new(Method::Invite, b"sip:bob@example.com")
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8;rport")
            .max_forwards(70)
            .from(b"<sip:alice@example.com>;tag=1928301774")
            .to(b"<sip:bob@example.com>")
            .call_id(b"a84b4c76e66710")
            .cseq(1)
            .contact(b"<sip:alice@192.0.2.1>")
            .header(HeaderName::Supported, b"timer, replaces,\r\n 100rel")
            .header(HeaderName::Allow, b"INVITE, ACK, CANCEL, BYE")
            .header(HeaderName::SessionExpires, b"1800")
            .header(HeaderName::UserAgent, b"a phone")
            .body(b"application/sdp", b"v=0\r\n")
            .build()
            .expect("a request")
    }

    #[test]
    fn a_compacted_request_uses_the_rfc_3261_short_names_and_tight_lists() {
        let compact =
            super::compact_request(&a_long_invite().as_raw(), &[]).expect("a compact request");
        assert_eq!(
            compact.as_raw().as_bytes(),
            b"INVITE sip:bob@example.com SIP/2.0\r\n\
v:SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8;rport\r\n\
Max-Forwards:70\r\n\
f:<sip:alice@example.com>;tag=1928301774\r\n\
t:<sip:bob@example.com>\r\n\
i:a84b4c76e66710\r\n\
CSeq:1 INVITE\r\n\
m:<sip:alice@192.0.2.1>\r\n\
k:timer,replaces,100rel\r\n\
Allow:INVITE,ACK,CANCEL,BYE\r\n\
Session-Expires:1800\r\n\
User-Agent:a phone\r\n\
c:application/sdp\r\n\
l:5\r\n\
\r\n\
v=0\r\n"
                .as_slice()
        );
    }

    #[test]
    fn a_compacted_request_reads_as_the_same_request() {
        let long = a_long_invite();
        let compact = super::compact_request(&long.as_raw(), &[]).expect("a compact request");
        let (long, compact) = (long.as_raw(), compact.as_raw());
        assert!(compact.len() < long.len());
        for name in HeaderName::KNOWN {
            let one: Vec<Vec<u8>> = long
                .header_values(*name)
                .map(|value| crate::msg::unfold(value).into_owned())
                .collect();
            let other: Vec<Vec<u8>> = compact
                .header_values(*name)
                .map(|value| crate::msg::unfold(value).into_owned())
                .collect();
            if matches!(name, HeaderName::Supported | HeaderName::Allow) {
                assert_eq!(one.len(), other.len(), "{name:?}");
                continue;
            }
            assert_eq!(one, other, "{name:?}");
        }
        assert_eq!(
            long.supported().collect::<Vec<_>>(),
            compact.supported().collect::<Vec<_>>()
        );
        assert_eq!(
            long.allow().collect::<Vec<_>>(),
            compact.allow().collect::<Vec<_>>()
        );
        assert_eq!(long.body(), compact.body());
        let mut scratch = ParseScratch::new();
        assert!(parse(compact.as_bytes(), &mut scratch, ParseMode::Strict).is_ok());
    }

    #[test]
    fn a_field_left_out_of_a_compacted_request_is_gone_and_nothing_else_is() {
        let long = a_long_invite();
        let lean = super::compact_request(&long.as_raw(), &[HeaderName::Allow])
            .expect("a compact request");
        let lean = lean.as_raw();
        assert_eq!(lean.header_count(HeaderName::Allow), 0);
        assert_eq!(
            lean.header_names().count() + 1,
            long.as_raw().header_names().count()
        );
    }
}
