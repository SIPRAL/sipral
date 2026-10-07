// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A parsed message as a view over the buffer it arrived in, and the owned
//! form the stack keeps.

use std::sync::Arc;

use super::addr::{ContactIter, Contacts, NameAddrRef};
use super::auth::{ChallengeRef, CredentialsRef};
use super::error::HeaderError;
use super::events::{EventRef, SubscriptionStateRef};
use super::header::HeaderName;
use super::lex::{CommaList, trim};
use super::method::{Method, StatusCode, is_token_byte};
use super::route::RouteIter;
use super::scalar::{CSeq, Digits, RAck, SipDate, digits, rseq};
use super::span::{HeaderSlot, Span};
use super::tokens::{MediaTypeRef, TokenIter};
use super::uri::{UriError, UriRef};
use super::via::ViaRef;

/// A `From` or `To` whose tag is a token, or the field is malformed.
///
/// §25.1: `tag-param = "tag" EQUAL token`. The dialog writes this tag back
/// after `;tag=`, so anything that would not go out as one value is refused.
fn tagged_by_a_token(addr: NameAddrRef<'_>) -> Result<NameAddrRef<'_>, HeaderError> {
    match addr.tag() {
        Some(tag) if tag.is_empty() || !tag.iter().copied().all(is_token_byte) => {
            Err(HeaderError::Malformed("a tag is a token"))
        }
        _ => Ok(addr),
    }
}

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

/// A parsed message. Accessors locate and validate spans without copying.
/// Borrows both the buffer and the index built by [`super::parse`].
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

    /// The Request-URI, parsed. `None` for a response. A URI that does not
    /// parse is for the layer above to reject.
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

    /// Name and value of every header field, in wire order. Folds are kept.
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

    /// Every value of one field, in wire order. Compact forms match too.
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

    /// How many times a field appears.
    #[must_use]
    pub fn header_count(&self, name: HeaderName<'_>) -> usize {
        self.header_values(name).count()
    }

    /// Every value of one comma-separated field, in wire order, across lines
    /// and commas alike (RFC 3261 §7.3.1).
    #[must_use]
    pub fn field_values(&self, name: HeaderName<'a>) -> FieldValues<'a> {
        FieldValues {
            buf: self.buf,
            slots: self.headers.iter(),
            name,
            current: None,
        }
    }

    /// The one value of a field that may appear only once.
    ///
    /// # Errors
    /// [`HeaderError::Missing`] when absent, [`HeaderError::UnexpectedRepeat`]
    /// when repeated (RFC 4475 §3.3.8). Picking one silently would disagree
    /// with the proxy in front.
    pub fn single(&self, name: HeaderName<'_>) -> Result<&'a [u8], HeaderError> {
        let mut it = self.header_values(name);
        let first = it.next().ok_or(HeaderError::Missing)?;
        if it.next().is_some() {
            return Err(HeaderError::UnexpectedRepeat);
        }
        Ok(first)
    }

    /// Every `Via` value, top first, across lines and commas (RFC 3261 §7.3.1).
    pub fn via(&self) -> impl Iterator<Item = Result<ViaRef<'a>, HeaderError>> + use<'a> {
        self.field_values(HeaderName::Via).map(ViaRef::parse)
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

    /// `From` (RFC 3261 §20.20). One value: `from-spec` has no list form.
    ///
    /// # Errors
    /// See [`NameAddrRef::parse`] and [`RawMessage::single`], and
    /// [`HeaderError::Malformed`] for a `tag` that is not a token.
    pub fn from(&self) -> Result<NameAddrRef<'a>, HeaderError> {
        tagged_by_a_token(NameAddrRef::parse(self.single(HeaderName::From)?)?)
    }

    /// `To` (RFC 3261 §20.39). One value, like `From`.
    ///
    /// # Errors
    /// As [`RawMessage::from`].
    pub fn to(&self) -> Result<NameAddrRef<'a>, HeaderError> {
        tagged_by_a_token(NameAddrRef::parse(self.single(HeaderName::To)?)?)
    }

    /// `Contact` (RFC 3261 §20.10): the addresses, or `*`. Empty when absent.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when `*` comes with an address: the grammar
    /// offers one or the other.
    pub fn contact(&self) -> Result<Contacts<'a>, HeaderError> {
        let values = self.field_values(HeaderName::Contact);
        let mut count = 0_usize;
        let mut star = false;
        for value in values.clone() {
            count += 1;
            star |= matches!(trim(value), b"*");
        }
        if star {
            if count > 1 {
                return Err(HeaderError::Malformed(
                    "Contact: * is the whole field or nothing",
                ));
            }
            return Ok(Contacts::Star);
        }
        Ok(Contacts::Addrs(ContactIter::new(values)))
    }

    /// `WWW-Authenticate` (RFC 3261 §20.44), most preferred first. One line is
    /// one challenge (RFC 8760 §2.3).
    pub fn www_authenticate(
        &self,
    ) -> impl Iterator<Item = Result<ChallengeRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::WwwAuthenticate)
            .map(ChallengeRef::parse)
    }

    /// `Proxy-Authenticate` (RFC 3261 §20.27). A separate credential space from
    /// `WWW-Authenticate` (§22.1).
    pub fn proxy_authenticate(
        &self,
    ) -> impl Iterator<Item = Result<ChallengeRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::ProxyAuthenticate)
            .map(ChallengeRef::parse)
    }

    /// `Authorization` (RFC 3261 §20.7). One per line: §20.7 exempts it from
    /// comma joining.
    pub fn authorization(
        &self,
    ) -> impl Iterator<Item = Result<CredentialsRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::Authorization)
            .map(CredentialsRef::parse)
    }

    /// `Proxy-Authorization` (RFC 3261 §20.28). Read as a list since a proxy
    /// only takes its own realm (§22.3).
    pub fn proxy_authorization(
        &self,
    ) -> impl Iterator<Item = Result<CredentialsRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::ProxyAuthorization)
            .map(CredentialsRef::parse)
    }

    /// `Require` (RFC 3261 §20.32). An unknown entry gets a 420.
    #[must_use]
    pub fn require(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::Require))
    }

    /// `Proxy-Require` (RFC 3261 §20.29): the same, addressed to proxies.
    #[must_use]
    pub fn proxy_require(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::ProxyRequire))
    }

    /// `Supported` (RFC 3261 §20.37). Present and empty is not absent.
    #[must_use]
    pub fn supported(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::Supported))
    }

    /// `Unsupported` (RFC 3261 §20.40): what a 420 could not honour.
    #[must_use]
    pub fn unsupported(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::Unsupported))
    }

    /// `Content-Encoding` (RFC 3261 §20.12), outermost first.
    #[must_use]
    pub fn content_encoding(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::ContentEncoding))
    }

    /// `Accept` (RFC 3261 §20.1). Absent assumes `application/sdp`; present and
    /// empty accepts nothing.
    #[must_use]
    pub fn accept(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::Accept))
    }

    /// `Allow` (RFC 3261 §20.5). The grammar's verbs are case-sensitive, so
    /// `invite` is [`Method::Extension`]. Absent says nothing.
    pub fn allow(&self) -> impl Iterator<Item = Method<'a>> + use<'a> {
        TokenIter::new(self.field_values(HeaderName::Allow)).filter_map(Method::from_bytes)
    }

    /// `Allow-Events` (RFC 6665 §8.2.2). A present list is complete (§4.4.4):
    /// other packages get a 489. Absent says nothing.
    #[must_use]
    pub fn allow_events(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::AllowEvents))
    }

    /// `Event` (RFC 6665 §8.2.1).
    ///
    /// # Errors
    /// See [`EventRef::parse`] and [`RawMessage::single`]. One event type per
    /// field (§8.2.1).
    pub fn event(&self) -> Result<EventRef<'a>, HeaderError> {
        EventRef::parse(self.single(HeaderName::Event)?)
    }

    /// `Subscription-State` (RFC 6665 §8.2.3).
    ///
    /// # Errors
    /// See [`SubscriptionStateRef::parse`] and [`RawMessage::single`].
    pub fn subscription_state(&self) -> Result<SubscriptionStateRef<'a>, HeaderError> {
        SubscriptionStateRef::parse(self.single(HeaderName::SubscriptionState)?)
    }

    /// `Content-Type` (RFC 3261 §20.15).
    ///
    /// # Errors
    /// See [`MediaTypeRef::parse`] and [`RawMessage::single`].
    pub fn content_type(&self) -> Result<MediaTypeRef<'a>, HeaderError> {
        MediaTypeRef::parse(self.single(HeaderName::ContentType)?)
    }

    /// `Route` (RFC 3261 §20.34), in the order the request has to follow.
    #[must_use]
    pub fn route(&self) -> RouteIter<'a> {
        RouteIter::new(self.field_values(HeaderName::Route))
    }

    /// `Record-Route` (RFC 3261 §20.30), in wire order: §12.1.1 takes it as is
    /// and §12.1.2 reversed.
    #[must_use]
    pub fn record_route(&self) -> RouteIter<'a> {
        RouteIter::new(self.field_values(HeaderName::RecordRoute))
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

    /// `Content-Length` (RFC 3261 §20.14), as written.
    ///
    /// # Errors
    /// See [`digits`] and [`RawMessage::single`].
    pub fn content_length(&self) -> Result<Digits, HeaderError> {
        digits(self.single(HeaderName::ContentLength)?)
    }

    /// `Date` (RFC 3261 §20.17), GMT only.
    ///
    /// # Errors
    /// See [`SipDate::parse`] and [`RawMessage::single`].
    pub fn date(&self) -> Result<SipDate, HeaderError> {
        SipDate::parse(self.single(HeaderName::Date)?)
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

    /// The method the transaction table is keyed on.
    ///
    /// A request uses its own, except ACK, which uses INVITE (RFC 3261
    /// §17.2.1). A response uses its `CSeq` method (§17.1.3). CANCEL keeps its
    /// own: it forms a separate transaction (§9.1).
    ///
    /// # Errors
    /// See [`RawMessage::cseq`], for a response.
    pub fn transaction_lookup_method(&self) -> Result<Method<'a>, HeaderError> {
        match self.kind() {
            MessageKind::Request(Method::Ack) => Ok(Method::Invite),
            MessageKind::Request(m) => Ok(m),
            MessageKind::Response(_) => Ok(self.cseq()?.method),
        }
    }

    /// Whether the stack can act on this message, or it draws a 400.
    ///
    /// The parser does not know which fields the caller reads, so field
    /// content is checked here. Only present fields that carry the message are
    /// checked; unknown extensions are not faults.
    ///
    /// # Errors
    /// [`Invalid`], naming the field and what was wrong with it.
    pub fn validate(&self) -> Result<(), Invalid> {
        if let Some(uri) = self.request_uri() {
            let uri =
                uri.map_err(|_| Invalid::field("Request-URI", HeaderError::Malformed("URI")))?;
            // §8.1.3.4: no URI headers in a Request-URI (RFC 4475 §3.1.2.11)
            if uri.sip().is_some_and(|u| !u.headers_raw().is_empty()) {
                return Err(Invalid::field(
                    "Request-URI",
                    HeaderError::Malformed("a Request-URI carries no headers"),
                ));
            }
        }

        // all values: RFC 4475 §3.1.2.1 hides its fault in the second
        let mut seen_via = false;
        for via in self.via() {
            via.map_err(|e| Invalid::field("Via", e))?;
            seen_via = true;
        }
        if !seen_via {
            return Err(Invalid::field("Via", HeaderError::Missing));
        }
        self.call_id().map_err(|e| Invalid::field("Call-ID", e))?;
        let cseq = self.cseq().map_err(|e| Invalid::field("CSeq", e))?;
        if let Some(method) = self.method()
            && cseq.method != method
        {
            // §8.1.1.5: case-sensitive, matches the start line (RFC 4475 §3.1.2.17-18)
            return Err(Invalid::field(
                "CSeq",
                HeaderError::Malformed("CSeq names a different method than the start line"),
            ));
        }
        self.from().map_err(|e| Invalid::field("From", e))?;
        self.to().map_err(|e| Invalid::field("To", e))?;

        match self.contact() {
            Err(e) => return Err(Invalid::field("Contact", e)),
            Ok(Contacts::Star) => {}
            Ok(Contacts::Addrs(addrs)) => {
                for contact in addrs {
                    contact.map_err(|e| Invalid::field("Contact", e))?;
                }
            }
        }
        for (name, hops) in [
            ("Route", self.route()),
            ("Record-Route", self.record_route()),
        ] {
            for hop in hops {
                hop.map_err(|e| Invalid::field(name, e))?;
            }
        }
        for challenge in self.www_authenticate() {
            challenge.map_err(|e| Invalid::field("WWW-Authenticate", e))?;
        }
        for challenge in self.proxy_authenticate() {
            challenge.map_err(|e| Invalid::field("Proxy-Authenticate", e))?;
        }
        for credentials in self.authorization() {
            credentials.map_err(|e| Invalid::field("Authorization", e))?;
        }
        for credentials in self.proxy_authorization() {
            credentials.map_err(|e| Invalid::field("Proxy-Authorization", e))?;
        }

        for (name, present, parsed) in [
            (
                "Max-Forwards",
                self.header_count(HeaderName::MaxForwards),
                self.max_forwards().map(|_| ()),
            ),
            (
                "Expires",
                self.header_count(HeaderName::Expires),
                self.expires().map(|_| ()),
            ),
            (
                "Content-Length",
                self.header_count(HeaderName::ContentLength),
                self.content_length().map(|_| ()),
            ),
            (
                "Content-Type",
                self.header_count(HeaderName::ContentType),
                self.content_type().map(|_| ()),
            ),
            (
                "Date",
                self.header_count(HeaderName::Date),
                self.date().map(|_| ()),
            ),
        ] {
            if present > 0 {
                parsed.map_err(|e| Invalid::field(name, e))?;
            }
        }
        Ok(())
    }

    /// The whole message as it was received, body included.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// How many bytes of the buffer this message takes up. Less when another
    /// message followed it.
    #[must_use]
    pub fn len(&self) -> usize {
        self.body.end as usize
    }

    /// Whether the message is zero bytes long, which a parsed one never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy the message into a refcounted buffer the stack can keep.
    ///
    /// Spans are offsets, so the index moves as is. Bytes past the body stay
    /// behind.
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

/// What is wrong with a message that arrived intact but cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid {
    /// The field at fault, in its canonical spelling.
    pub field: &'static str,
    /// What was wrong with it.
    pub error: HeaderError,
}

impl Invalid {
    const fn field(field: &'static str, error: HeaderError) -> Self {
        Self { field, error }
    }
}

impl core::fmt::Display for Invalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.field, self.error)
    }
}

impl core::error::Error for Invalid {}

/// Every value of one field, across lines and commas, in wire order.
#[derive(Clone, Debug)]
pub struct FieldValues<'a> {
    buf: &'a [u8],
    slots: core::slice::Iter<'a, HeaderSlot>,
    name: HeaderName<'a>,
    current: Option<CommaList<'a>>,
}

impl<'a> Iterator for FieldValues<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(list) = self.current.as_mut()
                && let Some(value) = list.next()
            {
                return Some(value);
            }
            self.current = None;
            let slot = self.slots.next()?;
            if HeaderName::from_bytes(slot.name.slice(self.buf)).is_some_and(|n| n == self.name) {
                self.current = Some(CommaList::new(slot.value.slice(self.buf)));
            }
        }
    }
}

/// A message the stack owns. Same bytes and index as the [`RawMessage`] it
/// came from (see [`OwnedMessage::as_raw`]); cloning is two refcount bumps.
#[derive(Clone)]
pub struct OwnedMessage {
    bytes: Arc<[u8]>,
    start: StartLine,
    headers: Arc<[HeaderSlot]>,
    body: Span,
}

impl OwnedMessage {
    /// Take ownership of the buffer `raw` was parsed from, without a copy.
    /// Private because every span is an offset into `bytes`.
    pub(super) fn adopt(bytes: Arc<[u8]>, raw: &RawMessage<'_>) -> Self {
        Self {
            bytes,
            start: raw.start,
            headers: Arc::from(raw.headers),
            body: raw.body,
        }
    }

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
