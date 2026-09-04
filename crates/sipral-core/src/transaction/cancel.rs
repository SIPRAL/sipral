// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Building a CANCEL, and knowing when it may go (RFC 3261 §9.1).
//!
//! A CANCEL is built to look exactly like the INVITE it cancels — same
//! Request-URI, `Call-ID`, `To`, `From` and `CSeq` number, tags and all, and
//! the same single top `Via` with the same branch — so that whoever receives
//! it can pair the two. Only the `CSeq` method differs, which is what makes it
//! a transaction in its own right rather than a retransmission.
//!
//! `Route` is copied, "so that stateless proxies are able to route CANCEL
//! requests properly". `Require` and `Proxy-Require` are not copied at all:
//! §9.1 forbids them here outright, and a CANCEL that demands an extension is
//! a CANCEL a proxy is entitled to reject.
//!
//! The timing is the part that catches people out. A CANCEL may not be sent
//! before a provisional response has arrived, because the server could then
//! receive the CANCEL before the INVITE it refers to and have nothing to
//! cancel. So the user is never made to wait for the right moment: asking to
//! cancel is always accepted while the transaction is open, and the request is
//! held until the first provisional arrives.

use super::super::msg::{BuildError, HeaderName, Method, OwnedMessage, RawMessage, RequestBuilder};

/// What asking to cancel means right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CancelDisposition {
    /// Nothing has come back yet: the CANCEL is held until the first
    /// provisional response arrives.
    Deferred,
    /// A provisional has arrived, so the CANCEL can go out now.
    Now,
    /// There is a final response already, and a CANCEL "has no effect on
    /// requests that have already generated a final response".
    TooLate,
}

/// Build the CANCEL for a request.
///
/// # Errors
/// [`BuildError::MissingField`] when the request is missing a field the CANCEL
/// has to copy.
pub(crate) fn cancel_for_request(request: &RawMessage<'_>) -> Result<OwnedMessage, BuildError> {
    let uri = request
        .request_uri_bytes()
        .ok_or(BuildError::MissingField("Request-URI"))?;
    let via = request
        .header(HeaderName::Via)
        .ok_or(BuildError::MissingField("Via"))?;
    let from = request
        .header(HeaderName::From)
        .ok_or(BuildError::MissingField("From"))?;
    // the To of the request, tag and all: a CANCEL is paired with the request
    // it cancels, not with the dialog a response would have started
    let to = request
        .header(HeaderName::To)
        .ok_or(BuildError::MissingField("To"))?;
    let call_id = request
        .header(HeaderName::CallId)
        .ok_or(BuildError::MissingField("Call-ID"))?;
    let cseq = request
        .cseq()
        .map_err(|_| BuildError::MissingField("CSeq"))?;

    let mut builder = RequestBuilder::new(Method::Cancel, uri)
        .via(via)
        .from(from)
        .to(to)
        .call_id(call_id)
        // the number is the INVITE's; only the method changes, which is what
        // makes this its own transaction
        .cseq(cseq.seq);

    builder = match request.header(HeaderName::MaxForwards) {
        Some(value) => builder.header(HeaderName::MaxForwards, value),
        None => builder.max_forwards(70),
    };
    for hop in request.field_values(HeaderName::Route) {
        builder = builder.route(hop);
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::cancel_for_request;
    use crate::msg::{HeaderName, Method, ParseMode, ParseScratch, parse};

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
Route: <sip:p1.example.com;lr>\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Require: 100rel\r\n\
Proxy-Require: something\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 4\r\n\
\r\n\
v=0\n";

    #[test]
    fn the_cancel_is_the_invite_with_one_thing_changed() {
        let mut scratch = ParseScratch::new();
        let invite = parse(INVITE, &mut scratch, ParseMode::Strict).expect("the INVITE");
        let built = cancel_for_request(&invite).expect("a CANCEL");
        assert_eq!(
            built.as_raw().as_bytes(),
            b"CANCEL sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
Route: <sip:p1.example.com;lr>\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n"
        );
    }

    #[test]
    fn the_branch_is_the_same_so_the_two_can_be_paired() {
        let mut scratch = ParseScratch::new();
        let invite = parse(INVITE, &mut scratch, ParseMode::Strict).expect("the INVITE");
        let built = cancel_for_request(&invite).expect("a CANCEL");
        let cancel = built.as_raw();

        assert_eq!(
            cancel.top_via().expect("Via").branch(),
            invite.top_via().expect("Via").branch()
        );
        assert_eq!(cancel.header_count(HeaderName::Via), 1);
        let cseq = cancel.cseq().expect("CSeq");
        assert_eq!((cseq.seq, cseq.method), (314_159, Method::Cancel));
        assert_eq!(cancel.route().count(), 1, "stateless proxies need it");
    }

    #[test]
    fn a_cancel_carries_no_require_and_no_body() {
        // 9.1: "MUST NOT contain any Require or Proxy-Require header fields"
        let mut scratch = ParseScratch::new();
        let invite = parse(INVITE, &mut scratch, ParseMode::Strict).expect("the INVITE");
        let built = cancel_for_request(&invite).expect("a CANCEL");
        let cancel = built.as_raw();

        assert_eq!(cancel.require().count(), 0);
        assert_eq!(cancel.proxy_require().count(), 0);
        assert_eq!(cancel.body(), b"", "the offer is not repeated");
        assert_eq!(cancel.validate(), Ok(()));
    }
}
