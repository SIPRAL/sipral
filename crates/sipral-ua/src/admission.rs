// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a request has to be before this agent acts on it (RFC 3261 §8.2).
//!
//! §8.2 asks a UAS its questions in an order, and each one that fails ends
//! the request with its own status: the method (§8.2.1, 405), the
//! Request-URI's scheme (§8.2.2.1, 416), the `Require` header (§8.2.2.3,
//! 420, in [`crate::reliable`]) and then the body (§8.2.3, 415). None of them
//! has a policy in it, so none of them is handed to the application: a peer
//! that is told nothing retransmits until its own timer gives up, and one
//! that is told 200 believes it was understood.
//!
//! One question more comes from the other direction. An INVITE whose
//! `Accept` rules out `application/sdp` asks for an answer this agent cannot
//! write, since every 2xx to an INVITE carries a session description, and
//! RFC 4475 §3.3.15 has it refused with a 406 rather than rung and answered
//! against the peer's own terms.
//!
//! RFC 4475 §3.3 is the test of all of it: each of its messages goes through
//! this agent in `rfc4475_tests`, received the way a peer would send it.

use std::time::Instant;

use sipral_core::endpoint::{Event, OutgoingResponse};
use sipral_core::msg::{
    HeaderName, MediaTypeRef, Method, Params, RawMessage, StatusCode, UriScheme,
};

use crate::agent::UserAgent;
use crate::renegotiate::ALLOW;

/// §21.4.6, which §8.2.1 answers a method this agent does not implement
/// with.
const METHOD_NOT_ALLOWED: StatusCode = match StatusCode::new(405) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// §21.4.7: "only capable of generating response entities that have content
/// characteristics not acceptable according to the Accept header field sent
/// in the request".
const NOT_ACCEPTABLE: StatusCode = match StatusCode::new(406) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// §21.4.14, which §8.2.2.1 answers a Request-URI scheme this agent does not
/// support with.
const UNSUPPORTED_URI_SCHEME: StatusCode = match StatusCode::new(416) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// The one body type this agent reads in an INVITE, which is also what a
/// 415 lists in `Accept` (§8.2.3: "the response MUST contain an Accept
/// header field listing the types of all bodies it understands").
const ACCEPT: &[u8] = b"application/sdp";

/// The one content coding this agent reads, which is none at all.
const ACCEPT_ENCODING: &[u8] = b"identity";

/// §20.2, which the core's list of header names does not carry.
const ACCEPT_ENCODING_FIELD: HeaderName<'static> = HeaderName::Extension("Accept-Encoding");

/// §20.11, which the core's list of header names does not carry either.
const CONTENT_DISPOSITION_FIELD: HeaderName<'static> = HeaderName::Extension("Content-Disposition");

impl UserAgent {
    /// §8.2.1 and §8.2.2.1, before anything else acts on a request that
    /// opens nothing yet: an initial INVITE, or a request outside a dialog.
    ///
    /// Inside a dialog neither question is asked again. The method of a
    /// request there is one the dialog's own handlers claim or leave, and its
    /// Request-URI is the `Contact` this end wrote.
    pub(crate) fn on_admission_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingInvite {
                transaction,
                ref request,
            } => {
                let Some(refusal) = scheme_refusal(&request.as_raw()) else {
                    return Some(event);
                };
                self.endpoint
                    .respond_invite(transaction, &refusal, now)
                    .ok();
                None
            }
            Event::IncomingOutOfDialog {
                transaction,
                ref request,
            } => {
                let raw = request.as_raw();
                let Some(refusal) = method_refusal(&raw).or_else(|| scheme_refusal(&raw)) else {
                    return Some(event);
                };
                self.endpoint.respond(transaction, &refusal, now).ok();
                None
            }
            _ => Some(event),
        }
    }
}

/// §8.2.1: "If the UAS recognizes but does not support the method of a
/// request, it MUST generate a 405 (Method Not Allowed) response", with the
/// `Allow` §21.4.6 makes compulsory.
///
/// REGISTER is the method it is written for here. A registrar keeps
/// bindings, and this agent keeps none of anyone else's: RFC 4475 §3.3.7 has
/// "endpoints choosing not to act as registrars ... simply reject the
/// request", with a 405. Every other method that reaches this point out of a
/// dialog is either claimed by a handler further on or left to the
/// application, which may be the one that implements it.
fn method_refusal(request: &RawMessage<'_>) -> Option<OutgoingResponse> {
    (request.method() == Some(Method::Register))
        .then(|| OutgoingResponse::new(METHOD_NOT_ALLOWED).header(HeaderName::Allow, ALLOW))
}

/// §8.2.2.1: "If the Request-URI uses a scheme not supported by the UAS, it
/// SHOULD reject the request with a 416 (Unsupported URI Scheme) response."
///
/// `sip` and `sips` are what this agent is addressed by. `tel` is let through
/// as well: §19.1.6 has a proxy hand one on, and a line reached on a number
/// is still a line. Anything else is an address this agent can never be,
/// which is RFC 4475 §3.3.3's reason for answering an IANA-registered scheme
/// the same way as one nobody has heard of (§3.3.2).
fn scheme_refusal(request: &RawMessage<'_>) -> Option<OutgoingResponse> {
    let target = request.request_uri()?.ok()?;
    match target.scheme() {
        UriScheme::Sip | UriScheme::Sips | UriScheme::Tel => None,
        UriScheme::Other(_) => Some(OutgoingResponse::new(UNSUPPORTED_URI_SCHEME)),
    }
}

/// §8.2.3 for an INVITE that opens a call, and then the `Accept` it came
/// with: `None` when the request can be acted on, the refusal when it cannot.
///
/// Asked after §8.2.2.3's `Require`, which is the order §8.2 puts them in.
pub(crate) fn content_refusal(request: &RawMessage<'_>) -> Option<OutgoingResponse> {
    // "If there are any bodies whose type (indicated by the Content-Type),
    // language (indicated by the Content-Language) or encoding (indicated by
    // the Content-Encoding) are not understood, and that body part is not
    // optional (as indicated by the Content-Disposition header field), the
    // UAS MUST reject the request with a 415". A request with no body has
    // nothing to understand, whatever `Content-Type` it names
    let refusable = !request.body().is_empty() && !optional_body(request);
    // "If the request contained content encodings not understood by the
    // UAS, the response MUST contain an Accept-Encoding header field listing
    // the encodings understood by the UAS"
    let encoded = request
        .content_encoding()
        .any(|coding| !coding.eq_ignore_ascii_case(ACCEPT_ENCODING));
    if refusable && encoded {
        return Some(
            OutgoingResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                .header(ACCEPT_ENCODING_FIELD, ACCEPT_ENCODING),
        );
    }
    // "The response MUST contain an Accept header field listing the types of
    // all bodies it understands"
    let unreadable = refusable
        && !request
            .content_type()
            .is_ok_and(|kind| kind.is("application", "sdp"));
    if unreadable {
        return Some(
            OutgoingResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                .header(HeaderName::Accept, ACCEPT),
        );
    }
    (!takes_sdp(request)).then(|| OutgoingResponse::new(NOT_ACCEPTABLE))
}

/// Whether the body is one the sender marked as safe to ignore: §20.11's
/// `handling=optional`, which is what §8.2.3 means by a body part that "is
/// not optional (as indicated by the Content-Disposition header field)".
fn optional_body(request: &RawMessage<'_>) -> bool {
    request
        .header(CONTENT_DISPOSITION_FIELD)
        .is_some_and(|value| {
            Params::split(value).1.any(|(name, value)| {
                name.eq_ignore_ascii_case(b"handling")
                    && value.is_some_and(|value| value.eq_ignore_ascii_case(b"optional"))
            })
        })
}

/// Whether the peer will take a session description in the answer.
///
/// §20.1: an absent `Accept` means `application/sdp`, and "an empty Accept
/// header field means that no formats are acceptable". A media range takes
/// SDP when it is `application/sdp`, `application/*` or `*/*` and does not
/// carry a `q` of zero, which is how the HTTP rules §20.1 borrows say "not
/// this".
fn takes_sdp(request: &RawMessage<'_>) -> bool {
    if request.header_count(HeaderName::Accept) == 0 {
        return true;
    }
    request.accept().any(|range| {
        let Ok(kind) = MediaTypeRef::parse(range) else {
            return false;
        };
        let covers =
            kind.is("application", "sdp") || kind.is("application", "*") || kind.is("*", "*");
        let refused = kind.params().any(|(name, value)| {
            name.eq_ignore_ascii_case(b"q") && value.is_some_and(is_zero_quality)
        });
        covers && !refused
    })
}

/// `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`: zero when
/// it is a `0` followed by nothing but zeros.
fn is_zero_quality(value: &[u8]) -> bool {
    let Some((first, rest)) = value.split_first() else {
        return false;
    };
    if *first != b'0' {
        return false;
    }
    match rest.split_first() {
        None => true,
        Some((b'.', digits)) => digits.iter().all(|digit| *digit == b'0'),
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use sipral_core::msg::{ParseMode, ParseScratch, parse};

    use super::{content_refusal, is_zero_quality, takes_sdp};

    fn invite(extra: &str, body: &str) -> Vec<u8> {
        format!(
            "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKadm\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=b\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: admission\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.0.2.9>\r\n\
{extra}Content-Length: {}\r\n\
\r\n\
{body}",
            body.len()
        )
        .into_bytes()
    }

    fn accepts_sdp(extra: &str) -> bool {
        let bytes = invite(extra, "");
        let mut scratch = ParseScratch::new();
        takes_sdp(&parse(&bytes, &mut scratch, ParseMode::Strict).expect("an INVITE"))
    }

    fn refused_with(extra: &str, body: &str) -> Option<u16> {
        let bytes = invite(extra, body);
        let mut scratch = ParseScratch::new();
        let request = parse(&bytes, &mut scratch, ParseMode::Strict).expect("an INVITE");
        content_refusal(&request).map(|refusal| refusal.status().get())
    }

    #[test]
    fn a_quality_of_zero_is_a_zero_followed_by_zeros() {
        for zero in ["0", "0.", "0.0", "0.00", "0.000"] {
            assert!(is_zero_quality(zero.as_bytes()), "{zero}");
        }
        for not_zero in ["", "1", "0.001", "0.5", "1.000", "00"] {
            assert!(!is_zero_quality(not_zero.as_bytes()), "{not_zero}");
        }
    }

    #[test]
    fn an_accept_takes_sdp_when_one_of_its_ranges_covers_it() {
        // §20.1: absent is application/sdp
        assert!(accepts_sdp(""));
        for taken in [
            "Accept: application/sdp\r\n",
            "Accept: APPLICATION/SDP\r\n",
            "Accept: text/plain, application/sdp;level=1\r\n",
            "Accept: application/*\r\n",
            "Accept: */*\r\n",
            "Accept: text/plain\r\nAccept: application/sdp;q=0.5\r\n",
        ] {
            assert!(accepts_sdp(taken), "{taken}");
        }
        for refused in [
            // RFC 4475 §3.3.15, sdp01
            "Accept: text/nobodyKnowsThis\r\n",
            // "an empty Accept header field means that no formats are
            // acceptable"
            "Accept:\r\n",
            "Accept: application/sdp;q=0\r\n",
            "Accept: */*;q=0.000\r\n",
            "Accept: application/sdpx\r\n",
        ] {
            assert!(!accepts_sdp(refused), "{refused}");
        }
    }

    #[test]
    fn a_body_this_agent_cannot_read_is_415_and_one_it_can_is_taken() {
        let sdp = "v=0\r\n";
        assert_eq!(refused_with("Content-Type: application/sdp\r\n", sdp), None);
        assert_eq!(
            refused_with("Content-Type: application/unknownformat\r\n", "<audio/>"),
            Some(415)
        );
        // a body with no type at all is not one this agent understands
        assert_eq!(refused_with("", sdp), Some(415));
        // a type with no body names nothing to read
        assert_eq!(refused_with("Content-Type: text/html\r\n", ""), None);
        assert_eq!(
            refused_with(
                "Content-Type: application/sdp\r\nContent-Encoding: gzip\r\n",
                sdp
            ),
            Some(415)
        );
        assert_eq!(
            refused_with(
                "Content-Type: application/sdp\r\nContent-Encoding: identity\r\n",
                sdp
            ),
            None
        );
        // a body its sender said may be ignored is ignored rather than
        // refused (§8.2.3, §20.11), and one it said is required is not
        assert_eq!(
            refused_with(
                "Content-Type: application/unknownformat\r\n\
Content-Disposition: render;handling=optional\r\n",
                "<audio/>"
            ),
            None
        );
        assert_eq!(
            refused_with(
                "Content-Type: application/unknownformat\r\n\
Content-Disposition: session;handling=required\r\n",
                "<audio/>"
            ),
            Some(415)
        );
        assert_eq!(
            refused_with("Accept: text/nobodyKnowsThis\r\n", ""),
            Some(406)
        );
    }
}
