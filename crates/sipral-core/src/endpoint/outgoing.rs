// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the caller describes, and what the endpoint fills in.
//!
//! The endpoint owns branch, sent-by, sequence number and tag: a hand-written
//! `Via` repeats its branch and misroutes responses. These types own their
//! contents because they are held until the message goes out.

use std::net::SocketAddr;
use std::sync::Arc;

use super::transport::TransportId;
use crate::dialog::CallId;
use crate::msg::{BuildError, HeaderName, Method, StatusCode, Uri};

/// The fields an endpoint writes itself and refuses from a caller.
///
/// A second line of any of them is either malformed or redirects the
/// message. Builders cannot refuse on the spot, so the sending call returns
/// [`BuildError::OwnedField`] and nothing leaves.
pub const ENDPOINT_FIELDS: &[HeaderName<'static>] = &[
    // §8.1.1.7, §18.2.2: branch keys the transaction, sent-by routes responses
    HeaderName::Via,
    // §8.1.1.2, §8.1.1.3: the tags name the dialog
    HeaderName::From,
    HeaderName::To,
    // §8.1.1.4
    HeaderName::CallId,
    // §8.1.1.5, §12.2.1.1
    HeaderName::CSeq,
    // §8.1.1.6
    HeaderName::MaxForwards,
    // §8.1.1.8, §12.1.1
    HeaderName::Contact,
    // §8.1.2, §12.2.1.1: a hand-written hop detours the request
    HeaderName::Route,
    // §12.1.1
    HeaderName::RecordRoute,
    // §7.4.1, §20.15
    HeaderName::ContentType,
    // §18.3, §20.14: a second one starts a second message on a stream
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

    /// The same, but refused rather than silently skipped when the name is not a
    /// token or is an endpoint field.
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

/// A request the caller wants sent, out of dialog (REGISTER, OPTIONS, INVITE
/// and so on). In-dialog requests take their fields from the dialog.
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
    /// `remote`. The endpoint does not resolve addresses (RFC 3263 is I/O).
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

    /// The `From` value. Required. A tag is added if missing (§8.1.1.3).
    #[must_use]
    pub fn from(mut self, value: &[u8]) -> Self {
        self.from = Some(Box::from(value));
        self
    }

    /// The `Call-ID`, when it has to be a particular one. §10.2 reuses one per
    /// registrar; everything else gets a fresh one.
    #[must_use]
    pub fn call_id(mut self, call_id: CallId) -> Self {
        self.call_id = Some(call_id);
        self
    }

    /// The sequence number, to continue a series (§10.2). Defaults to 1
    /// (§8.1.1.5).
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

/// A request the caller wants sent inside a dialog. Request-URI, routes,
/// tags, `Call-ID` and `CSeq` come from the dialog (§12.2.1.1).
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

/// A response the caller wants sent. Fields echoed from the request are
/// filled in by the endpoint (§8.2.6.2).
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

    /// A reason phrase of your own. §21 makes the phrase advisory.
    #[must_use]
    pub fn reason(mut self, reason: &[u8]) -> Self {
        self.reason = Some(Box::from(reason));
        self
    }

    /// The tag to put in `To`, when the request had none. Left alone, the
    /// endpoint adds one (§8.2.6.2).
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
