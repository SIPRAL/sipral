// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A request the dialog has filled in (§12.2.1.1).
//!
//! `Via`, `Contact` and the body are left to the caller, on the builder
//! this hands back.

use super::key::CallId;
use crate::msg::{HeaderName, Method, RawMessage, RequestBuilder, Uri};

/// Everything the dialog puts into the next request it sends.
#[derive(Clone, Debug)]
pub struct InDialogRequest {
    method: Box<[u8]>,
    request_uri: Uri,
    route: Box<[Box<[u8]>]>,
    to: Box<[u8]>,
    from: Box<[u8]>,
    call_id: CallId,
    cseq: u32,
    credentials: Vec<(HeaderName<'static>, Box<[u8]>)>,
}

impl InDialogRequest {
    pub(super) fn new(
        method: Method<'_>,
        request_uri: Uri,
        route: &[Uri],
        to: Box<[u8]>,
        from: Box<[u8]>,
        call_id: CallId,
        cseq: u32,
    ) -> Self {
        Self {
            method: Box::from(method.as_str().as_bytes()),
            request_uri,
            route: route.iter().map(angle_bracketed).collect(),
            to,
            from,
            call_id,
            cseq,
            credentials: Vec::new(),
        }
    }

    /// Carry the credentials of another request into this one.
    ///
    /// §13.2.2.4: the ACK to a 2xx has the INVITE's credentials. Copied line
    /// by line, since §20.7 exempts these fields from the comma rule.
    pub(super) fn copy_credentials(&mut self, from: &RawMessage<'_>) {
        for name in [HeaderName::Authorization, HeaderName::ProxyAuthorization] {
            for value in from.header_values(name) {
                self.credentials.push((name, Box::from(value)));
            }
        }
    }

    /// The method, which is also the method in `CSeq`.
    #[must_use]
    pub fn method(&self) -> Method<'_> {
        // the bytes came from a Method, so they are a token
        Method::from_bytes(&self.method).unwrap_or(Method::Extension(""))
    }

    /// The Request-URI: the remote target, or the first hop when the route
    /// set starts at a strict router.
    #[must_use]
    pub const fn request_uri(&self) -> &Uri {
        &self.request_uri
    }

    /// The `Route` values, in the order they go on the wire, each already in
    /// the angle brackets `route-param` requires.
    pub fn route(&self) -> impl Iterator<Item = &[u8]> {
        self.route.iter().map(AsRef::as_ref)
    }

    /// The `To` value: the remote URI, with the remote tag when there is one.
    #[must_use]
    pub const fn to(&self) -> &[u8] {
        &self.to
    }

    /// The `From` value: the local URI and our tag.
    #[must_use]
    pub const fn from(&self) -> &[u8] {
        &self.from
    }

    /// The dialog's `Call-ID`.
    #[must_use]
    pub const fn call_id(&self) -> &CallId {
        &self.call_id
    }

    /// The sequence number for this request.
    #[must_use]
    pub const fn cseq(&self) -> u32 {
        self.cseq
    }

    /// The credentials carried over from another request, if any.
    pub fn credentials(&self) -> impl Iterator<Item = (HeaderName<'static>, &[u8])> {
        self.credentials
            .iter()
            .map(|(name, value)| (*name, value.as_ref()))
    }

    /// A builder carrying everything above. Still missing: `Via`,
    /// `Max-Forwards`, an optional `Contact`, and the body.
    #[must_use]
    pub fn builder(&self) -> RequestBuilder<'_> {
        let mut builder = RequestBuilder::new(self.method(), self.request_uri.as_bytes())
            .from(&self.from)
            .to(&self.to)
            .call_id(self.call_id.as_bytes())
            .cseq(self.cseq);
        for hop in self.route() {
            builder = builder.route(hop);
        }
        for (name, value) in self.credentials() {
            builder = builder.header(name, value);
        }
        builder
    }
}

/// Brackets are required: without them a `;lr` on the URI would parse as a
/// header parameter.
fn angle_bracketed(uri: &Uri) -> Box<[u8]> {
    let mut out = Vec::with_capacity(uri.as_bytes().len() + 2);
    out.push(b'<');
    out.extend_from_slice(uri.as_bytes());
    out.push(b'>');
    out.into_boxed_slice()
}
