// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
/// §25.1: `tag-param = "tag" EQUAL token`. The tag read here is the one a
/// dialog is named by and the one it writes back after `;tag=` on every request
/// it sends, so it has to be something that goes back out as one parameter
/// value. [`NameAddrRef::tag`] undoes quoting, which keeps `tag="a1"` readable
/// as `a1`; a quoted value holding a `;`, an unquoted one running on to a
/// comma, or an empty one would each be written back as parameters or an
/// address the peer added.
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

    /// Every value of one comma-separated field, in wire order.
    ///
    /// RFC 3261 §7.3.1 makes several lines of such a field and one line with
    /// commas the same message, so this walks both: line by line, and within
    /// each line comma by comma, with quotes and `<...>` respected.
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

    /// `From` (RFC 3261 §20.20).
    ///
    /// One value, never a list: `from-spec` has no `COMMA` alternative, so a
    /// second address on the line is a malformed field rather than a second
    /// caller.
    ///
    /// # Errors
    /// See [`NameAddrRef::parse`] and [`RawMessage::single`], and
    /// [`HeaderError::Malformed`] for a `tag` that is not a token.
    pub fn from(&self) -> Result<NameAddrRef<'a>, HeaderError> {
        tagged_by_a_token(NameAddrRef::parse(self.single(HeaderName::From)?)?)
    }

    /// `To` (RFC 3261 §20.39). One value, for the same reason as `From`.
    ///
    /// # Errors
    /// As [`RawMessage::from`].
    pub fn to(&self) -> Result<NameAddrRef<'a>, HeaderError> {
        tagged_by_a_token(NameAddrRef::parse(self.single(HeaderName::To)?)?)
    }

    /// `Contact` (RFC 3261 §20.10): the addresses, or the `*` wildcard.
    ///
    /// A message with no `Contact` gives an empty iterator, not an error —
    /// most requests carry none.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when `*` arrives alongside an address. The
    /// grammar offers `STAR` *or* the list, so the two together are outside
    /// it, however sensible each half looks on its own.
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

    /// `WWW-Authenticate` (RFC 3261 §20.44): the challenges a UAS, registrar
    /// or redirect server sent with a 401, most preferred first.
    ///
    /// One line is one challenge. RFC 8760 §2.3 offers several algorithms as
    /// several lines in preference order, and joining them would produce a
    /// value with two scheme keywords that the grammar cannot read back.
    pub fn www_authenticate(
        &self,
    ) -> impl Iterator<Item = Result<ChallengeRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::WwwAuthenticate)
            .map(ChallengeRef::parse)
    }

    /// `Proxy-Authenticate` (RFC 3261 §20.27): the challenges a proxy sent
    /// with a 407.
    ///
    /// A separate credential space from `WWW-Authenticate` — different status
    /// code, different role (§22.1) — so answering one with the other is
    /// wrong however alike they read.
    pub fn proxy_authenticate(
        &self,
    ) -> impl Iterator<Item = Result<ChallengeRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::ProxyAuthenticate)
            .map(ChallengeRef::parse)
    }

    /// `Authorization` (RFC 3261 §20.7).
    ///
    /// One line each: §20.7 exempts this field from the comma-joining rule of
    /// §7.3.1 explicitly.
    pub fn authorization(
        &self,
    ) -> impl Iterator<Item = Result<CredentialsRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::Authorization)
            .map(CredentialsRef::parse)
    }

    /// `Proxy-Authorization` (RFC 3261 §20.28).
    ///
    /// A proxy must not consume a value whose `realm` is not its own (§22.3),
    /// so these are read as a list rather than searched by scheme.
    pub fn proxy_authorization(
        &self,
    ) -> impl Iterator<Item = Result<CredentialsRef<'a>, HeaderError>> + use<'a> {
        self.header_values(HeaderName::ProxyAuthorization)
            .map(CredentialsRef::parse)
    }

    /// `Require` (RFC 3261 §20.32): the extensions the peer insists on.
    ///
    /// Must not be ignored when present — a UAS that cannot honour one of
    /// these answers 420 and lists it in `Unsupported`.
    #[must_use]
    pub fn require(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::Require))
    }

    /// `Proxy-Require` (RFC 3261 §20.29): the same, addressed to proxies.
    #[must_use]
    pub fn proxy_require(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::ProxyRequire))
    }

    /// `Supported` (RFC 3261 §20.37): the extensions the peer can do.
    ///
    /// Present and empty means none, which is not the same as absent.
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

    /// `Accept` (RFC 3261 §20.1): the body types the peer will take, as
    /// written.
    ///
    /// Absent means `application/sdp` is assumed; present and empty means
    /// nothing is acceptable, so the two cannot be collapsed.
    #[must_use]
    pub fn accept(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::Accept))
    }

    /// `Allow` (RFC 3261 §20.5): the methods the peer implements.
    ///
    /// The six RFC 3261 verbs are fixed-case literals in the grammar, so
    /// `Allow: invite` yields [`Method::Extension`], not [`Method::Invite`].
    /// Absent says nothing about what is supported (§20.5); it is not a claim
    /// that nothing is.
    pub fn allow(&self) -> impl Iterator<Item = Method<'a>> + use<'a> {
        TokenIter::new(self.field_values(HeaderName::Allow)).filter_map(Method::from_bytes)
    }

    /// `Allow-Events` (RFC 6665 §8.2.2): the event packages the peer can
    /// notify for.
    ///
    /// §4.4.4 makes the list "comprehensive and inclusive", so a package that
    /// is not in a list that is present is one the peer will refuse with a
    /// 489. Absent says nothing at all.
    #[must_use]
    pub fn allow_events(&self) -> TokenIter<'a> {
        TokenIter::new(self.field_values(HeaderName::AllowEvents))
    }

    /// `Event` (RFC 6665 §8.2.1).
    ///
    /// # Errors
    /// See [`EventRef::parse`] and [`RawMessage::single`]. §8.2.1: "There MUST
    /// be exactly one event type listed per `Event` header field. Multiple
    /// events per message are disallowed."
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
    /// See [`MediaTypeRef::parse`] and [`RawMessage::single`]. One media type,
    /// never a list, so a second one is a repeat rather than another value.
    pub fn content_type(&self) -> Result<MediaTypeRef<'a>, HeaderError> {
        MediaTypeRef::parse(self.single(HeaderName::ContentType)?)
    }

    /// `Route` (RFC 3261 §20.34), in the order the request has to follow.
    #[must_use]
    pub fn route(&self) -> RouteIter<'a> {
        RouteIter::new(self.field_values(HeaderName::Route))
    }

    /// `Record-Route` (RFC 3261 §20.30), in wire order.
    ///
    /// Wire order, not dialog order: §12.1.1 has the UAS take these as they
    /// come and §12.1.2 has the UAC reverse them, so reversing here would make
    /// one of the two wrong.
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

    /// The method the transaction table is keyed on for this message.
    ///
    /// A request answers with its own method, except an ACK, which answers
    /// INVITE: the INVITE server transaction absorbs the ACK to a non-2xx
    /// (RFC 3261 §17.2.1), and an ACK to a 2xx simply finds no transaction
    /// under that key and belongs to the dialog instead. A response answers
    /// with its `CSeq` method, because that is what §17.1.3 matches on
    /// alongside the branch — a response carries no method of its own.
    ///
    /// CANCEL stays CANCEL: it shares the branch of the request it cancels
    /// but forms a transaction of its own (§9.1).
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

    /// Whether this is a message the stack can act on, or one that draws a
    /// 400.
    ///
    /// A message can be framed correctly and still be unusable: a `From` whose
    /// display name is not a display name, a `CSeq` that names a different
    /// method than the start line, a `Date` in a time zone nobody can read.
    /// The parser has no business refusing those — it does not know which
    /// fields the caller will read — so the question is asked here, once, by
    /// whoever is about to answer.
    ///
    /// Only the fields that carry the message are checked, and only when they
    /// are present. An extension header nobody understands is not a fault.
    ///
    /// # Errors
    /// [`Invalid`], naming the field and what was wrong with it.
    pub fn validate(&self) -> Result<(), Invalid> {
        if let Some(uri) = self.request_uri() {
            let uri =
                uri.map_err(|_| Invalid::field("Request-URI", HeaderError::Malformed("URI")))?;
            // 8.1.3.4 has a UAC copy a target URI into the Request-URI
            // "except for the method-param and header URI parameters", so
            // headers have no business arriving in one (RFC 4475 §3.1.2.11)
            if uri.sip().is_some_and(|u| !u.headers_raw().is_empty()) {
                return Err(Invalid::field(
                    "Request-URI",
                    HeaderError::Malformed("a Request-URI carries no headers"),
                ));
            }
        }

        // every one, not just the top: a response walks the whole list back,
        // and RFC 4475 §3.1.2.1 hides its fault in the second value
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
            // 8.1.1.5: the method part of CSeq is case-sensitive and matches
            // the request's own (RFC 4475 §3.1.2.17 and §3.1.2.18)
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

    /// How many bytes of the buffer this message takes up.
    ///
    /// Less than the buffer when something followed it — a second request
    /// sharing a datagram, or the next message on a stream.
    #[must_use]
    pub fn len(&self) -> usize {
        self.body.end as usize
    }

    /// Whether the message is zero bytes long, which a parsed one never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

/// Every value of one field, across the lines it appears on and across the
/// commas within them, in wire order.
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
    /// Take ownership of a buffer that was just parsed, without copying it a
    /// second time.
    ///
    /// `bytes` has to be the buffer `raw` was parsed from, which is why this
    /// is not public: every span is an offset into it. The builders use it so
    /// that writing a message costs one allocation rather than two.
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
