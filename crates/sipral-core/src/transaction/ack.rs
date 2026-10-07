// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The ACK a client transaction sends for a non-2xx final response
//! (RFC 3261 §17.1.1.3).
//!
//! - Request-URI, `Call-ID`, `From` and `Route`: the original request's.
//! - `To`: the *response's*, which holds the remote tag.
//! - `Via`: exactly one, the request's topmost.
//! - `CSeq`: the request's number, method `ACK`.
//!
//! The ACK for a 2xx belongs to the dialog (§13) and is built there.

use super::super::msg::{BuildError, HeaderName, Method, OwnedMessage, RawMessage, RequestBuilder};

/// Build the ACK for a final response of 300 to 699.
///
/// # Errors
/// [`BuildError::MissingField`] when the request or the response is missing a
/// field the ACK has to carry.
pub(crate) fn ack_for_response(
    request: &RawMessage<'_>,
    response: &RawMessage<'_>,
) -> Result<OwnedMessage, BuildError> {
    let uri = request
        .request_uri_bytes()
        .ok_or(BuildError::MissingField("Request-URI"))?;
    let via = request
        .header(HeaderName::Via)
        .ok_or(BuildError::MissingField("Via"))?;
    let from = request
        .header(HeaderName::From)
        .ok_or(BuildError::MissingField("From"))?;
    let call_id = request
        .header(HeaderName::CallId)
        .ok_or(BuildError::MissingField("Call-ID"))?;
    // the response's To carries the remote tag; without it the ACK does not
    // match
    let to = response
        .header(HeaderName::To)
        .ok_or(BuildError::MissingField("To"))?;
    let cseq = request
        .cseq()
        .map_err(|_| BuildError::MissingField("CSeq"))?;

    let mut builder = RequestBuilder::new(Method::Ack, uri)
        .via(via)
        .from(from)
        .to(to)
        .call_id(call_id)
        .cseq(cseq.seq);

    builder = match request.header(HeaderName::MaxForwards) {
        Some(value) => builder.header(HeaderName::MaxForwards, value),
        None => builder.max_forwards(70),
    };
    // "If the INVITE request whose response is being acknowledged had Route
    // header fields, those header fields MUST appear in the ACK"
    for hop in request.field_values(HeaderName::Route) {
        builder = builder.route(hop);
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::ack_for_response;
    use crate::msg::{HeaderName, Method, ParseMode, ParseScratch, parse};

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK0\r\n\
Route: <sip:p1.example.com;lr>\r\n\
Route: <sip:p2.example.com;lr>\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

    const BUSY: &[u8] = b"SIP/2.0 486 Busy Here\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

    #[test]
    fn the_ack_takes_each_half_from_the_right_message() {
        let mut one = ParseScratch::new();
        let mut two = ParseScratch::new();
        let request = parse(INVITE, &mut one, ParseMode::Strict).expect("a request");
        let response = parse(BUSY, &mut two, ParseMode::Strict).expect("a response");

        let built = ack_for_response(&request, &response).expect("an ACK");
        assert_eq!(
            built.as_raw().as_bytes(),
            b"ACK sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Route: <sip:p1.example.com;lr>\r\n\
Route: <sip:p2.example.com;lr>\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1928301774\r\n\
To: <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 ACK\r\n\
Content-Length: 0\r\n\
\r\n"
        );
    }

    #[test]
    fn the_to_tag_comes_from_the_response_and_the_via_from_the_request() {
        let mut one = ParseScratch::new();
        let mut two = ParseScratch::new();
        let request = parse(INVITE, &mut one, ParseMode::Strict).expect("a request");
        let response = parse(BUSY, &mut two, ParseMode::Strict).expect("a response");
        let built = ack_for_response(&request, &response).expect("an ACK");
        let ack = built.as_raw();

        assert_eq!(
            ack.to().expect("To").tag().as_deref(),
            Some(&b"a6c85cf"[..]),
            "the tag is the one the far end chose"
        );
        assert_eq!(
            ack.header_count(HeaderName::Via),
            1,
            "exactly one Via, the topmost"
        );
        assert_eq!(
            ack.top_via().expect("Via").branch().as_deref(),
            Some(&b"z9hG4bK1"[..])
        );
        let cseq = ack.cseq().expect("CSeq");
        assert_eq!((cseq.seq, cseq.method), (314_159, Method::Ack));
        assert_eq!(ack.route().count(), 2, "the route set survives");
        assert_eq!(ack.validate(), Ok(()));
    }

    #[test]
    fn a_request_without_the_fields_the_ack_needs_is_refused() {
        let mut one = ParseScratch::new();
        let mut two = ParseScratch::new();
        let request = parse(
            b"INVITE sip:b@example.com SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\r\n",
            &mut one,
            ParseMode::Strict,
        )
        .expect("a request");
        let response = parse(BUSY, &mut two, ParseMode::Strict).expect("a response");
        assert!(ack_for_response(&request, &response).is_err());
    }
}
