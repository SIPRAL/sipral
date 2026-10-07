// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a request has to be before this agent acts on it (RFC 3261 §8.2).
//!
//! The checks run in §8.2's order, each with its own status: method
//! (§8.2.1, 405), Request-URI scheme (§8.2.2.1, 416), `Require` (§8.2.2.3,
//! 420, in [`crate::reliable`]), body (§8.2.3, 415). None involves policy,
//! so none reaches the application.
//!
//! REGISTER is refused first. Any other method is refused only after every
//! handler has passed it over, inside a dialog by the usage RFC 5057 §5.3
//! matches it to.
//!
//! An INVITE whose `Accept` rules out `application/sdp` gets a 406 (RFC 4475
//! §3.3.15): every 2xx to an INVITE carries SDP. `rfc4475_tests` runs all of
//! RFC 4475 §3.3 through this agent.

use std::time::Instant;

use sipral_core::endpoint::{Event, OutgoingResponse};
use sipral_core::msg::{
    HeaderName, MediaTypeRef, Method, Params, RawMessage, StatusCode, UriScheme,
};

use crate::agent::UserAgent;
use crate::renegotiate::ALLOW;
use crate::transfer::{FORBIDDEN, names_a_dialog};

/// §21.4.6, for a method this agent does not implement (§8.2.1).
const METHOD_NOT_ALLOWED: StatusCode = match StatusCode::new(405) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// §21.5.2, for a method this agent does not recognise (§8.2.1).
const NOT_IMPLEMENTED: StatusCode = match StatusCode::new(501) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// §21.4.7, for an `Accept` that rules out every body this agent writes.
const NOT_ACCEPTABLE: StatusCode = match StatusCode::new(406) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// §21.4.14, for an unsupported Request-URI scheme (§8.2.2.1).
const UNSUPPORTED_URI_SCHEME: StatusCode = match StatusCode::new(416) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// The only body read in an INVITE, re-INVITE, UPDATE or PRACK; a 415 lists
/// it in `Accept` (§8.2.3).
const ACCEPT: &[u8] = b"application/sdp";

const ACCEPT_ENCODING: &[u8] = b"identity";

/// §20.2.
const ACCEPT_ENCODING_FIELD: HeaderName<'static> = HeaderName::Extension("Accept-Encoding");

/// §20.11.
const CONTENT_DISPOSITION_FIELD: HeaderName<'static> = HeaderName::Extension("Content-Disposition");

/// RFC 6086 §11.6: "469 Bad Info Package".
const BAD_INFO_PACKAGE: StatusCode = match StatusCode::new(469) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// RFC 6086 §7.2.
const INFO_PACKAGE_FIELD: HeaderName<'static> = HeaderName::Extension("Info-Package");

/// RFC 6086 §7.3. Sent empty in a 469: this agent takes no package.
const RECV_INFO_FIELD: HeaderName<'static> = HeaderName::Extension("Recv-Info");

/// The INFO bodies [`crate::dtmf`] reads; a 415 to an INFO lists them.
const INFO_ACCEPT: &[u8] = b"application/dtmf-relay, application/dtmf";

impl UserAgent {
    /// §8.2.1 and §8.2.2.1 for an initial INVITE or a request outside a
    /// dialog. Inside a dialog the Request-URI is our own `Contact`, so
    /// neither check applies.
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

    /// Answers a request every handler passed over (§8.2.1). Runs last.
    ///
    /// The application cannot answer it through the C ABI, and an
    /// unanswered request is retransmitted until the peer times out; inside
    /// a dialog that timeout terminates the dialog (§12.2.1.2), hanging up
    /// the call. Statuses: [`unclaimed_refusal`], [`in_dialog_answer`]. The
    /// exception is an INFO in a call when the application answers INFO
    /// itself ([`UserAgent::hand_over_info`]).
    pub(crate) fn on_unclaimed_request(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingOutOfDialog {
                transaction,
                ref request,
            } => {
                let refusal = unclaimed_refusal(&request.as_raw());
                self.endpoint.respond(transaction, &refusal, now).ok();
                None
            }
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } => {
                let raw = request.as_raw();
                let in_call = self.by_dialog.contains_key(&dialog);
                if in_call && self.info_handed_over && raw.method() == Some(Method::Info) {
                    return Some(event);
                }
                let answer = in_dialog_answer(&raw, in_call);
                self.endpoint.respond(transaction, &answer, now).ok();
                None
            }
            // re-INVITE in a dialog with no call: 481 ends the missing invite
            // usage and nothing else (RFC 5057 §5.1 note 8, §5.3)
            Event::IncomingReinvite { transaction, .. } => {
                let gone = OutgoingResponse::new(StatusCode::CALL_DOES_NOT_EXIST);
                self.endpoint.respond_invite(transaction, &gone, now).ok();
                None
            }
            // PRACK for a call a CANCEL already ended: it still matches an
            // unacknowledged reliable 1xx, so it gets a 2xx (RFC 3262 §3)
            Event::IncomingPrack { transaction, .. } => {
                let taken = OutgoingResponse::new(StatusCode::OK).header(HeaderName::Allow, ALLOW);
                self.endpoint.respond(transaction, &taken, now).ok();
                None
            }
            _ => Some(event),
        }
    }
}

/// What a request inside a dialog that nothing here claimed is answered
/// with, by the usage RFC 5057 §5.3 matches it to.
///
/// - **INFO in a call** that [`crate::dtmf`] did not claim (RFC 6086
///   §4.2.2): 469 with an empty `Recv-Info` if it names an `Info-Package`;
///   415 for a non-optional body it cannot read; otherwise 200. Some
///   equipment sends a bodiless INFO as a keepalive.
/// - **481** for UPDATE, PRACK, INFO, BYE in a dialog with no call: it ends
///   only the missing invite usage (RFC 5057 §5.1).
/// - **403** for a REFER: a new usage refused on policy.
/// - **501** for an unrecognised method (§21.5.2).
/// - **405** with [`ALLOW`] for any other known method (SUBSCRIBE other than
///   `refer`, PUBLISH, REGISTER); it affects only the transaction (RFC 5057
///   §5.1 note 3).
fn in_dialog_answer(request: &RawMessage<'_>, in_call: bool) -> OutgoingResponse {
    match request.method() {
        Some(Method::Info) if in_call => legacy_info_answer(request),
        Some(Method::Refer) => OutgoingResponse::new(FORBIDDEN),
        Some(Method::Bye | Method::Update | Method::Info | Method::Prack) => {
            OutgoingResponse::new(StatusCode::CALL_DOES_NOT_EXIST)
        }
        Some(Method::Extension(_)) | None => OutgoingResponse::new(NOT_IMPLEMENTED),
        Some(_) => OutgoingResponse::new(METHOD_NOT_ALLOWED).header(HeaderName::Allow, ALLOW),
    }
}

/// RFC 6086 §4.2.2; see [`in_dialog_answer`].
fn legacy_info_answer(request: &RawMessage<'_>) -> OutgoingResponse {
    if request.header(INFO_PACKAGE_FIELD).is_some() {
        return OutgoingResponse::new(BAD_INFO_PACKAGE).header(RECV_INFO_FIELD, b"");
    }
    if !request.body().is_empty() && !optional_body(request) {
        return OutgoingResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE)
            .header(HeaderName::Accept, INFO_ACCEPT);
    }
    OutgoingResponse::new(StatusCode::OK)
}

/// What a request outside a dialog that nothing here claimed is answered
/// with.
///
/// - **481** when its `To` tag names a dialog this agent lacks (§12.2.2).
/// - **481** for BYE, UPDATE, INFO, PRACK: they only work inside a dialog,
///   and a 405 would list in `Allow` the method it refused.
/// - **403** for a REFER the application has not opted into
///   ([`crate::referral`]). Not 405: REFER works inside a call.
/// - **405** with [`ALLOW`] for SUBSCRIBE and PUBLISH (§8.2.1, §21.4.6);
///   REGISTER gets the same earlier, in [`method_refusal`].
/// - **501** for an unrecognised method (§21.5.2).
fn unclaimed_refusal(request: &RawMessage<'_>) -> OutgoingResponse {
    match request.method() {
        _ if names_a_dialog(request) => OutgoingResponse::new(StatusCode::CALL_DOES_NOT_EXIST),
        Some(Method::Refer) => OutgoingResponse::new(FORBIDDEN),
        Some(Method::Bye | Method::Update | Method::Info | Method::Prack) => {
            OutgoingResponse::new(StatusCode::CALL_DOES_NOT_EXIST)
        }
        Some(Method::Extension(_)) | None => OutgoingResponse::new(NOT_IMPLEMENTED),
        Some(_) => OutgoingResponse::new(METHOD_NOT_ALLOWED).header(HeaderName::Allow, ALLOW),
    }
}

/// 405 with `Allow` for REGISTER (§8.2.1, §21.4.6): this agent is no
/// registrar (RFC 4475 §3.3.7). Asked before the Request-URI, as §8.2 orders.
fn method_refusal(request: &RawMessage<'_>) -> Option<OutgoingResponse> {
    (request.method() == Some(Method::Register))
        .then(|| OutgoingResponse::new(METHOD_NOT_ALLOWED).header(HeaderName::Allow, ALLOW))
}

/// 416 for a scheme other than `sip`, `sips` or `tel` (§8.2.2.1). `tel`
/// passes because a proxy may forward one (§19.1.6); registered and unknown
/// schemes are treated alike (RFC 4475 §3.3.2, §3.3.3).
fn scheme_refusal(request: &RawMessage<'_>) -> Option<OutgoingResponse> {
    let target = request.request_uri()?.ok()?;
    match target.scheme() {
        UriScheme::Sip | UriScheme::Sips | UriScheme::Tel => None,
        UriScheme::Other(_) => Some(OutgoingResponse::new(UNSUPPORTED_URI_SCHEME)),
    }
}

/// §8.2.3, then `Accept`, for an initial INVITE; `None` if it can proceed.
/// Called after the `Require` check (§8.2 order).
pub(crate) fn content_refusal(request: &RawMessage<'_>) -> Option<OutgoingResponse> {
    body_refusal(request)
        .or_else(|| (!takes_sdp(request)).then(|| OutgoingResponse::new(NOT_ACCEPTABLE)))
}

/// §8.2.3 for any request whose body this agent reads (INVITE, re-INVITE,
/// UPDATE, PRACK). `None` for SDP, no body, or an optional body.
///
/// A non-SDP re-INVITE must get a 415 here; passed on, it would end up as a
/// 488, which claims the session was read.
pub(crate) fn body_refusal(request: &RawMessage<'_>) -> Option<OutgoingResponse> {
    // an empty body has nothing to understand, whatever its Content-Type
    let refusable = !request.body().is_empty() && !optional_body(request);
    let encoded = request
        .content_encoding()
        .any(|coding| !coding.eq_ignore_ascii_case(ACCEPT_ENCODING));
    if refusable && encoded {
        return Some(
            OutgoingResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                .header(ACCEPT_ENCODING_FIELD, ACCEPT_ENCODING),
        );
    }
    let unreadable = refusable
        && !request
            .content_type()
            .is_ok_and(|kind| kind.is("application", "sdp"));
    unreadable.then(|| {
        OutgoingResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE).header(HeaderName::Accept, ACCEPT)
    })
}

/// `handling=optional` in `Content-Disposition` (§20.11, §8.2.3).
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
/// §20.1: absent means `application/sdp`, empty means nothing. The most
/// specific covering range decides (RFC 2616 §14.1): type and subtype first,
/// then the number of media-type parameters. SDP is refused when that range
/// has `q=0`.
///
/// Any parameter on `application/sdp` still means our SDP: RFC 4566 §8.1
/// defines none.
fn takes_sdp(request: &RawMessage<'_>) -> bool {
    if request.header_count(HeaderName::Accept) == 0 {
        return true;
    }
    // (how specific the range is, whether a range that specific takes SDP)
    let mut deciding: Option<(Specificity, bool)> = None;
    for range in request.accept() {
        let Ok(kind) = MediaTypeRef::parse(range) else {
            continue;
        };
        let tier = if kind.is("application", "sdp") {
            2
        } else if kind.is("application", "*") {
            1
        } else if kind.is("*", "*") {
            0
        } else {
            continue;
        };
        // parameters after `q` are accept-extensions, not the media type's
        let mut parameters = 0_usize;
        let mut taken = true;
        for (name, value) in kind.params() {
            if name.eq_ignore_ascii_case(b"q") {
                taken = !value.is_some_and(is_zero_quality);
                break;
            }
            parameters = parameters.saturating_add(1);
        }
        let specificity = Specificity { tier, parameters };
        deciding = match deciding {
            Some((held, before)) if held > specificity => Some((held, before)),
            Some((held, before)) if held == specificity => Some((held, before || taken)),
            _ => Some((specificity, taken)),
        };
    }
    deciding.is_some_and(|(_, taken)| taken)
}

/// Ordered by tier, `application/sdp` over `application/*` over `*/*`, then
/// by parameter count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Specificity {
    tier: u8,
    parameters: usize,
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
    fn the_most_specific_range_in_an_accept_decides() {
        // RFC 2616 §14.1: the narrower range wins either way
        for refused in [
            "Accept: application/sdp;q=0, */*\r\n",
            "Accept: */*\r\nAccept: application/sdp;q=0\r\n",
            "Accept: application/*;q=0, */*\r\n",
            "Accept: application/sdp;q=0, application/*\r\n",
        ] {
            assert!(!accepts_sdp(refused), "{refused}");
        }
        for taken in [
            "Accept: */*;q=0, application/sdp\r\n",
            "Accept: application/*;q=0, application/sdp\r\n",
            "Accept: */*;q=0, application/*\r\n",
            "Accept: text/plain;q=0, */*\r\n",
        ] {
            assert!(accepts_sdp(taken), "{taken}");
        }
    }

    #[test]
    fn a_media_type_parameter_makes_a_range_more_specific() {
        // RFC 2616 §14.1: "text/html;level=1" outranks "text/html"
        for refused in [
            "Accept: application/sdp;level=1;q=0, application/sdp\r\n",
            "Accept: application/sdp\r\nAccept: application/sdp;level=1;q=0\r\n",
            "Accept: application/sdp;level=1;version=2;q=0, application/sdp;level=1\r\n",
            "Accept: application/*;x=1;q=0, application/*, */*\r\n",
        ] {
            assert!(!accepts_sdp(refused), "{refused}");
        }
        for taken in [
            "Accept: application/sdp;level=1, application/sdp;q=0\r\n",
            "Accept: application/sdp;level=1;version=2, application/sdp;level=1;q=0\r\n",
            // RFC 3261 §20.1's own example
            "Accept: application/sdp;level=1, application/x-private, text/html\r\n",
            // what follows the q is an accept-extension, not the type's
            "Accept: application/sdp;q=0;ext=1;more=2, application/sdp;level=1\r\n",
            // a narrower type outranks any number of parameters
            "Accept: application/*;a=1;b=2;q=0, application/sdp\r\n",
        ] {
            assert!(accepts_sdp(taken), "{taken}");
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
        // §8.2.3, §20.11: an optional body is ignored, a required one is not
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
