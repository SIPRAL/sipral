// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the caller describes, and what the endpoint fills in.
//!
//! The split is the point. The caller knows who is calling whom, what body to
//! carry and which transport to leave on; the endpoint knows the branch, the
//! sent-by, the sequence number and the tag, and none of those are safe to
//! let a caller choose. A `Via` written by hand is a `Via` whose branch
//! repeats, and a repeated branch is a response delivered to the wrong
//! transaction.
//!
//! These own their contents, unlike the builders in `msg`, because they cross
//! the boundary into the endpoint and are held until the message goes out. A
//! borrowed form would tie the caller's buffers to the transaction's lifetime.

use std::net::SocketAddr;
use std::sync::Arc;

use super::transport::TransportId;
use crate::dialog::CallId;
use crate::msg::{BuildError, HeaderName, Method, StatusCode, Uri};

/// The fields an endpoint writes itself, from what it keeps, and therefore
/// refuses to take from a caller by name.
///
/// A second line of any of them is not a harmless repeat. Each is either a
/// field that appears once, so that two lines are a malformed message every
/// hop on the path resolves by guessing, or one whose value decides where the
/// message goes or where it ends, so that a second line sends it somewhere
/// the endpoint did not. [`OutgoingRequest::header`] and its two siblings
/// cannot refuse on the spot, being builders, so the refusal is
/// [`BuildError::OwnedField`] from the call that sends: nothing is built and
/// nothing leaves.
pub const ENDPOINT_FIELDS: &[HeaderName<'static>] = &[
    // §8.1.1.7, §18.2.2: the branch keys the transaction, and the sent-by is
    // where the response comes back to
    HeaderName::Via,
    // §8.1.1.2, §8.1.1.3: the tags name the dialog, and each field is one
    HeaderName::From,
    HeaderName::To,
    // §8.1.1.4: the dialog's name, once
    HeaderName::CallId,
    // §8.1.1.5, §12.2.1.1: the number a transaction and a dialog are ordered by
    HeaderName::CSeq,
    // §8.1.1.6: the hop count a loop is caught by
    HeaderName::MaxForwards,
    // §8.1.1.8, §12.1.1: the remote target the far end sends the dialog to
    HeaderName::Contact,
    // §8.1.2, §12.2.1.1: the route set; a hop written by hand detours the
    // request through a proxy the caller named
    HeaderName::Route,
    // §12.1.1: copied from the request into a response that opens a dialog,
    // and the far end reads its route set off it
    HeaderName::RecordRoute,
    // §7.4.1, §20.15: what the body is, written with the body
    HeaderName::ContentType,
    // §18.3, §20.14: where the message ends on a stream, so a second one is
    // the start of a second message
    HeaderName::ContentLength,
];

/// One header the caller added, kept in the case it was written in.
#[derive(Clone, Debug)]
pub(crate) struct Extra {
    name: Box<[u8]>,
    value: Box<[u8]>,
}

impl Extra {
    /// The name and value, ready for a builder.
    pub(crate) fn parts(&self) -> Option<(HeaderName<'_>, &[u8])> {
        Some((HeaderName::from_bytes(&self.name)?, &self.value))
    }

    /// The same, refused rather than skipped when it cannot be written: a
    /// name that is not a token, or a field the endpoint writes itself.
    ///
    /// A header the caller asked for and did not get, with nothing said, is
    /// found in a capture a week later.
    pub(crate) fn field(&self) -> Result<(HeaderName<'_>, &[u8]), BuildError> {
        let Some((name, value)) = self.parts() else {
            return Err(BuildError::IllegalValue("a header field name is a token"));
        };
        match ENDPOINT_FIELDS.iter().find(|owned| **owned == name) {
            Some(owned) => Err(BuildError::OwnedField(owned.canonical())),
            None => Ok((name, value)),
        }
    }
}

/// A request the caller wants sent, out of dialog.
///
/// REGISTER, OPTIONS, SUBSCRIBE, MESSAGE, INVITE — anything that starts
/// something rather than continuing it. What is inside a dialog comes from
/// the dialog instead, which already knows the target, the route and the
/// numbering.
#[derive(Clone, Debug)]
pub struct OutgoingRequest {
    pub(crate) method: Box<[u8]>,
    pub(crate) request_uri: Uri,
    pub(crate) transport: TransportId,
    pub(crate) remote: SocketAddr,
    pub(crate) to: Option<Box<[u8]>>,
    pub(crate) from: Option<Box<[u8]>>,
    pub(crate) call_id: Option<CallId>,
    pub(crate) cseq: Option<u32>,
    pub(crate) route: Vec<Box<[u8]>>,
    pub(crate) contact: Option<Box<[u8]>>,
    pub(crate) extra: Vec<Extra>,
    pub(crate) content_type: Option<Box<[u8]>>,
    pub(crate) body: Option<Arc<[u8]>>,
    pub(crate) max_forwards: u32,
}

impl OutgoingRequest {
    /// A request of `method` to `request_uri`, leaving on `transport` for
    /// `remote`.
    ///
    /// The endpoint does not choose the transport or resolve the address.
    /// RFC 3263 resolution is I/O and belongs to whoever owns the sockets;
    /// what the endpoint asks about is a target it found in a message rather
    /// than one the caller handed it.
    #[must_use]
    pub fn new(
        method: Method<'_>,
        request_uri: Uri,
        transport: TransportId,
        remote: SocketAddr,
    ) -> Self {
        Self {
            method: Box::from(method.as_str().as_bytes()),
            request_uri,
            transport,
            remote,
            to: None,
            from: None,
            call_id: None,
            cseq: None,
            route: Vec::new(),
            contact: None,
            extra: Vec::new(),
            content_type: None,
            body: None,
            max_forwards: 70,
        }
    }

    /// The `To` value, as it goes on the wire: a `name-addr` or an
    /// `addr-spec`, with a display name if there is one. Required.
    #[must_use]
    pub fn to(mut self, value: &[u8]) -> Self {
        self.to = Some(Box::from(value));
        self
    }

    /// The `From` value. Required.
    ///
    /// A tag is added if there is none: §8.1.1.3 makes it mandatory on a
    /// request, and a caller that has no reason to pick one should not have
    /// to invent an unguessable string.
    #[must_use]
    pub fn from(mut self, value: &[u8]) -> Self {
        self.from = Some(Box::from(value));
        self
    }

    /// The `Call-ID`, when it has to be a particular one.
    ///
    /// §10.2 asks a user agent to reuse one `Call-ID` for every registration
    /// it sends to the same registrar, so that the registrar can tell a
    /// refresh from a second device. Everything else gets a fresh one.
    #[must_use]
    pub fn call_id(mut self, call_id: CallId) -> Self {
        self.call_id = Some(call_id);
        self
    }

    /// The sequence number, when it has to continue a series.
    ///
    /// Registrations again: §10.2 wants the number to increase across
    /// refreshes. Left alone it starts at 1, which §8.1.1.5 allows for a
    /// request that starts something.
    #[must_use]
    pub const fn cseq(mut self, seq: u32) -> Self {
        self.cseq = Some(seq);
        self
    }

    /// A `Route` value, in the angle brackets `route-param` requires. Call
    /// again for the next hop, in the order they go on the wire.
    #[must_use]
    pub fn route(mut self, value: &[u8]) -> Self {
        self.route.push(Box::from(value));
        self
    }

    /// The `Contact` value: where this endpoint can be reached for what this
    /// request starts.
    #[must_use]
    pub fn contact(mut self, value: &[u8]) -> Self {
        self.contact = Some(Box::from(value));
        self
    }

    /// Any other header field.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'_>, value: &[u8]) -> Self {
        self.extra.push(Extra {
            name: Box::from(name.canonical().as_bytes()),
            value: Box::from(value),
        });
        self
    }

    /// The body and what it is.
    #[must_use]
    pub fn body(mut self, content_type: &[u8], body: Arc<[u8]>) -> Self {
        self.content_type = Some(Box::from(content_type));
        self.body = Some(body);
        self
    }

    /// `Max-Forwards`, which is 70 unless said otherwise (§8.1.1.6).
    #[must_use]
    pub const fn max_forwards(mut self, hops: u32) -> Self {
        self.max_forwards = hops;
        self
    }
}

/// A request the caller wants sent inside a dialog.
///
/// Much shorter than the out-of-dialog form, because the dialog already knows
/// almost all of it: the Request-URI, the route set, both addresses with their
/// tags, the `Call-ID` and the sequence number are §12.2.1.1's business and
/// not the caller's.
#[derive(Clone, Debug)]
pub struct OutgoingInDialogRequest {
    pub(crate) method: Box<[u8]>,
    pub(crate) contact: Option<Box<[u8]>>,
    pub(crate) extra: Vec<Extra>,
    pub(crate) content_type: Option<Box<[u8]>>,
    pub(crate) body: Option<Arc<[u8]>>,
    pub(crate) max_forwards: u32,
}

impl OutgoingInDialogRequest {
    /// A request of `method` in whichever dialog it is sent into.
    #[must_use]
    pub fn new(method: Method<'_>) -> Self {
        Self {
            method: Box::from(method.as_str().as_bytes()),
            contact: None,
            extra: Vec::new(),
            content_type: None,
            body: None,
            max_forwards: 70,
        }
    }

    /// The method, read back.
    #[must_use]
    pub fn method(&self) -> Method<'_> {
        // the bytes came from a Method, so they are a token
        Method::from_bytes(&self.method).unwrap_or(Method::Extension(""))
    }

    /// The `Contact` value, for a request that refreshes the target.
    #[must_use]
    pub fn contact(mut self, value: &[u8]) -> Self {
        self.contact = Some(Box::from(value));
        self
    }

    /// Any other header field.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'_>, value: &[u8]) -> Self {
        self.extra.push(Extra {
            name: Box::from(name.canonical().as_bytes()),
            value: Box::from(value),
        });
        self
    }

    /// The body and what it is.
    #[must_use]
    pub fn body(mut self, content_type: &[u8], body: Arc<[u8]>) -> Self {
        self.content_type = Some(Box::from(content_type));
        self.body = Some(body);
        self
    }

    /// `Max-Forwards`, which is 70 unless said otherwise.
    #[must_use]
    pub const fn max_forwards(mut self, hops: u32) -> Self {
        self.max_forwards = hops;
        self
    }
}

/// A response the caller wants sent.
///
/// Everything the response has to echo from the request — `Via`, `From`,
/// `To`, `Call-ID`, `CSeq` — is taken from the request by the endpoint
/// (§8.2.6.2), so none of it is here.
#[derive(Clone, Debug)]
pub struct OutgoingResponse {
    pub(crate) status: StatusCode,
    pub(crate) reason: Option<Box<[u8]>>,
    pub(crate) to_tag: Option<Box<[u8]>>,
    pub(crate) contact: Option<Box<[u8]>>,
    pub(crate) extra: Vec<Extra>,
    pub(crate) content_type: Option<Box<[u8]>>,
    pub(crate) body: Option<Arc<[u8]>>,
}

impl OutgoingResponse {
    /// A response with this status and the reason phrase the RFC gives it.
    #[must_use]
    pub const fn new(status: StatusCode) -> Self {
        Self {
            status,
            reason: None,
            to_tag: None,
            contact: None,
            extra: Vec::new(),
            content_type: None,
            body: None,
        }
    }

    /// The status it will carry, read back.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// A reason phrase of your own, in place of the registered one.
    ///
    /// §21 makes the phrase advisory and explicitly allows replacing it, and
    /// a carrier that says why in it is easier to debug against than one that
    /// does not.
    #[must_use]
    pub fn reason(mut self, reason: &[u8]) -> Self {
        self.reason = Some(Box::from(reason));
        self
    }

    /// The tag to put in `To`, when the request had none.
    ///
    /// Left alone, the endpoint adds one: §8.2.6.2 makes a tag mandatory on
    /// every response except a 100, and a response without one cannot be part
    /// of a dialog.
    #[must_use]
    pub fn to_tag(mut self, tag: &[u8]) -> Self {
        self.to_tag = Some(Box::from(tag));
        self
    }

    /// The `Contact` value, for the responses that carry one.
    #[must_use]
    pub fn contact(mut self, value: &[u8]) -> Self {
        self.contact = Some(Box::from(value));
        self
    }

    /// Any other header field.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'_>, value: &[u8]) -> Self {
        self.extra.push(Extra {
            name: Box::from(name.canonical().as_bytes()),
            value: Box::from(value),
        });
        self
    }

    /// The body and what it is.
    #[must_use]
    pub fn body(mut self, content_type: &[u8], body: Arc<[u8]>) -> Self {
        self.content_type = Some(Box::from(content_type));
        self.body = Some(body);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{OutgoingRequest, OutgoingResponse};
    use crate::endpoint::TransportId;
    use crate::msg::{HeaderName, Method, StatusCode, Uri};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn request() -> OutgoingRequest {
        OutgoingRequest::new(
            Method::Options,
            Uri::parse_str("sip:bob@example.com").unwrap(),
            TransportId(1),
            "192.0.2.9:5060".parse::<SocketAddr>().unwrap(),
        )
    }

    #[test]
    fn a_request_starts_with_the_defaults_the_rfc_gives_it() {
        let request = request();
        assert_eq!(request.max_forwards, 70);
        assert_eq!(&*request.method, b"OPTIONS");
        assert!(request.call_id.is_none(), "the endpoint mints one");
        assert!(request.cseq.is_none());
    }

    #[test]
    fn a_header_added_by_name_comes_back_as_that_name() {
        let request = request()
            .header(HeaderName::UserAgent, b"sipral")
            .header(HeaderName::Extension("X-Thing"), b"1");
        let named: Vec<_> = request
            .extra
            .iter()
            .filter_map(|extra| extra.parts())
            .collect();
        assert_eq!(named.len(), 2);
        assert_eq!(
            named.first().map(|(name, _)| *name),
            Some(HeaderName::UserAgent)
        );
        assert_eq!(
            named.get(1).map(|(name, _)| *name),
            Some(HeaderName::Extension("X-Thing"))
        );
        assert_eq!(named.get(1).map(|(_, value)| *value), Some(&b"1"[..]));
    }

    #[test]
    fn routes_keep_the_order_they_were_added_in() {
        let request = request()
            .route(b"<sip:p1.example.com;lr>")
            .route(b"<sip:p2.example.com;lr>");
        assert_eq!(request.route.len(), 2);
        assert_eq!(&*request.route[0], &b"<sip:p1.example.com;lr>"[..]);
        assert_eq!(&*request.route[1], &b"<sip:p2.example.com;lr>"[..]);
    }

    #[test]
    fn a_body_carries_its_type_with_it() {
        let request = request().body(b"application/sdp", Arc::from(&b"v=0\r\n"[..]));
        assert_eq!(
            request.content_type.as_deref(),
            Some(&b"application/sdp"[..])
        );
        assert_eq!(request.body.as_deref(), Some(&b"v=0\r\n"[..]));
    }

    #[test]
    fn a_response_says_nothing_the_endpoint_will_say_for_it() {
        let response = OutgoingResponse::new(StatusCode::new(200).unwrap());
        assert!(response.reason.is_none(), "the registered phrase is used");
        assert!(response.to_tag.is_none(), "the endpoint mints one");
        assert!(response.body.is_none());
    }
}
