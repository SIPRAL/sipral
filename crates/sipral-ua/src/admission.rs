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
//! The method question is asked twice. REGISTER is refused before anything
//! else reads the request; any other method is refused only after every
//! handler that claims one has passed it over, because only then is it known
//! that nothing here implements it — outside a dialog, and inside one, where
//! RFC 5057 §5.3 says which usage the request belongs to and so which
//! refusal it gets.
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
use crate::transfer::{FORBIDDEN, names_a_dialog};

/// §21.4.6, which §8.2.1 answers a method this agent does not implement
/// with.
const METHOD_NOT_ALLOWED: StatusCode = match StatusCode::new(405) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// §21.5.2, which §8.2.1 answers a method this agent does not recognise
/// with.
const NOT_IMPLEMENTED: StatusCode = match StatusCode::new(501) {
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

/// The one body type this agent reads in an INVITE, a re-INVITE, an UPDATE
/// or a PRACK, which is also what a 415 lists in `Accept` (§8.2.3: "the
/// response MUST contain an Accept header field listing the types of all
/// bodies it understands").
const ACCEPT: &[u8] = b"application/sdp";

/// The one content coding this agent reads, which is none at all.
const ACCEPT_ENCODING: &[u8] = b"identity";

/// §20.2, which the core's list of header names does not carry.
const ACCEPT_ENCODING_FIELD: HeaderName<'static> = HeaderName::Extension("Accept-Encoding");

/// §20.11, which the core's list of header names does not carry either.
const CONTENT_DISPOSITION_FIELD: HeaderName<'static> = HeaderName::Extension("Content-Disposition");

/// RFC 6086 §11.6: "469 Bad Info Package".
const BAD_INFO_PACKAGE: StatusCode = match StatusCode::new(469) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// RFC 6086 §7.2, the field an INFO names its Info Package in.
const INFO_PACKAGE_FIELD: HeaderName<'static> = HeaderName::Extension("Info-Package");

/// RFC 6086 §7.3, the field a 469 lists the packages it would take in —
/// empty here, since this agent takes none: `Recv-Info = "Recv-Info" HCOLON
/// [info-package-list]`.
const RECV_INFO_FIELD: HeaderName<'static> = HeaderName::Extension("Recv-Info");

/// The bodies this agent reads in an INFO, which is what a 415 to one lists
/// in `Accept` (§8.2.3): the two DTMF forms of [`crate::dtmf`].
const INFO_ACCEPT: &[u8] = b"application/dtmf-relay, application/dtmf";

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

    /// §8.2.1 for a request outside a dialog that every handler of this
    /// agent passed over: it is answered here rather than handed to the
    /// application, which has no way to answer it through the C ABI and
    /// would otherwise leave the peer retransmitting until the endpoint's
    /// own 408 thirty-two seconds later.
    ///
    /// Run last, after every handler that claims a method outside a dialog
    /// (OPTIONS, NOTIFY, MESSAGE) has had its turn, so nothing a handler
    /// takes is ever refused here. See [`unclaimed_refusal`] for the status.
    ///
    /// Inside a dialog it is the same question with one fact more — whether
    /// the dialog is a call's — and the same reason to answer it here: a
    /// request nobody answers is retransmitted until the far end's own
    /// timer gives up, and RFC 3261 §12.2.1.2 has a UAC whose request inside
    /// a dialog timed out "terminate the dialog", which is the call hung up
    /// over a SUBSCRIBE it sent in passing. See [`in_dialog_answer`] for the
    /// status. The one exception is an INFO in a call that the application
    /// said it answers itself ([`UserAgent::hand_over_info`]).
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
            // a re-INVITE in a dialog that holds no call: RFC 5057 §5.3 puts
            // an INVITE in the dialog's invite usage, and there is none here
            // — a subscription's dialog, or a call that has just gone. 481
            // says the usage does not exist and destroys nothing else (§5.1,
            // note 8)
            Event::IncomingReinvite { transaction, .. } => {
                let gone = OutgoingResponse::new(StatusCode::CALL_DOES_NOT_EXIST);
                self.endpoint.respond_invite(transaction, &gone, now).ok();
                None
            }
            // a PRACK the endpoint matched to a reliable provisional response
            // of a call this layer no longer holds — one a CANCEL ended while
            // the response was still unacknowledged. RFC 3262 §3: "If the
            // PRACK does match an unacknowledged reliable provisional
            // response, it MUST be responded to with a 2xx response"
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
/// - **An INFO in a call** is legacy INFO usage (RFC 6086 §3) of a kind
///   this agent does not read — anything but `application/dtmf-relay` and
///   `application/dtmf`, which [`crate::dtmf`] claims first — and is
///   answered by RFC 6086 §4.2.2: **469** with an empty `Recv-Info` when it
///   names an `Info-Package`, since this agent indicated willingness to
///   receive none; **415** with an `Accept` naming the two DTMF types for a
///   body it cannot read that its sender did not mark optional (RFC 3261
///   §8.2.3); and **200** for one with no body, or an optional one: "if the
///   INFO request is syntactically correct and well structured, the UA MUST
///   send a 200 (OK) response". Refusing those would answer the INFO some
///   equipment sends as a keepalive with an error.
/// - **481** for the other methods of an invite usage (UPDATE, PRACK, INFO,
///   BYE) in a dialog that holds no call: the usage they belong to does not
///   exist, and RFC 5057 §5.1 has a 481 destroy that usage and nothing more.
/// - **403** for a REFER, as outside a dialog: a new usage refused on
///   policy, which RFC 5057 §5.1 counts against the transaction alone.
/// - **501** for a method this agent does not recognise (RFC 3261 §21.5.2),
///   which RFC 5057 §5.3 expects of a server and which affects the
///   transaction only.
/// - **405** with [`ALLOW`] for any other method it recognises and does
///   not take here: a SUBSCRIBE (other than the `refer` package, which
///   [`crate::transfer`] claims), a PUBLISH, a REGISTER. RFC 5057 §5.1, note
///   3: for a request "not integral to the usage ... only the transaction
///   will be affected".
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

/// RFC 6086 §4.2.2 for an INFO in a call that is not one of this agent's
/// DTMF forms. See [`in_dialog_answer`].
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
/// - **481** when it names a dialog — a tag in its `To` — that this agent
///   does not have (§12.2.2: "it MUST respond to the request with a 481
///   (Call/Transaction Does Not Exist) status code"), whatever its method.
/// - **481** for a method this agent implements only inside a dialog —
///   BYE (§15.1.2), UPDATE, INFO and PRACK — since a request that names no
///   dialog has none of this agent's to act in. All but INFO are in
///   [`ALLOW`], so a 405 would list the very method it refused.
/// - **403** for a REFER, which names no dialog and asks this end to place
///   a call of its own (RFC 3515 §4.1's own example is one). It reaches here
///   only when the application has not taken them on
///   ([`crate::referral`]), and then it is refused on policy: "the server
///   understood the request, but is refusing to fulfill it" (§21.4.4). Not
///   481, which would claim it names a dialog, and not 405, which would
///   claim this agent does not do REFER at all when it does inside a call.
/// - **405** with [`ALLOW`] for any other method RFC 3261 and its
///   extensions define that this agent does not take outside a dialog:
///   SUBSCRIBE (it is no notifier) and PUBLISH (it is no event state
///   compositor). "If the UAS recognizes but does not support the method of
///   a request, it MUST generate a 405 (Method Not Allowed) response", and
///   §21.4.6 makes the `Allow` compulsory. REGISTER is refused the same
///   way, earlier ([`method_refusal`]).
/// - **501** for a method it does not recognise at all: "If the method is
///   not recognized ... the UAS SHOULD generate a 501 (Not Implemented)"
///   (§21.5.2).
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

/// §8.2.1: "If the UAS recognizes but does not support the method of a
/// request, it MUST generate a 405 (Method Not Allowed) response", with the
/// `Allow` §21.4.6 makes compulsory.
///
/// REGISTER is the method it is written for here. A registrar keeps
/// bindings, and this agent keeps none of anyone else's: RFC 4475 §3.3.7 has
/// "endpoints choosing not to act as registrars ... simply reject the
/// request", with a 405. It is refused here, before the Request-URI, because
/// §8.2 asks about the method first. Every other method that reaches this
/// point out of a dialog is either claimed by a handler further on or, if
/// none claims it, refused by [`UserAgent::on_unclaimed_request`].
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
    body_refusal(request)
        .or_else(|| (!takes_sdp(request)).then(|| OutgoingResponse::new(NOT_ACCEPTABLE)))
}

/// §8.2.3 alone, for every request whose body this agent reads: the INVITE
/// that opens a call, and the re-INVITE, UPDATE and PRACK that carry an offer
/// inside one. `None` when the body is one this agent understands, or there
/// is none, or its sender said it may be ignored.
///
/// §8.2 is what a UAS asks of any request before it acts on it, not only of
/// the first: a re-INVITE whose body is not a session description cannot be
/// answered as an offer, and handing it on had it answered later with
/// whatever the application made of it — a 488 at best, which says the
/// session was read and refused.
pub(crate) fn body_refusal(request: &RawMessage<'_>) -> Option<OutgoingResponse> {
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
    unreadable.then(|| {
        OutgoingResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE).header(HeaderName::Accept, ACCEPT)
    })
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
/// header field means that no formats are acceptable". The ranges that
/// cover SDP are `application/sdp`, `application/*` and `*/*`, and §20.1
/// keeps HTTP's semantics for them: "Media ranges can be overridden by more
/// specific media ranges or specific media types. If more than one media
/// range applies to a given type, the most specific reference has
/// precedence" (RFC 2616 §14.1), whose own example ranks `text/html;level=1`
/// above `text/html`. So a range is as specific as its type and subtype
/// say, and then more so for each media-type parameter it names. SDP is
/// taken when the most specific of those present does not carry a `q` of
/// zero, which is how those rules say "not this".
///
/// A parameter on `application/sdp` is read as naming the SDP this agent
/// writes: RFC 4566 §8.1 registers the type with no parameters at all, so
/// none can single out a description this one is not, and §20.1's own
/// example, `application/sdp;level=1`, is a peer asking for SDP.
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
        // `accept-params = ";" "q" "=" qvalue *( accept-extension )`: what
        // comes before the `q` belongs to the media type, and what comes
        // after it says nothing about which type this is
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

/// How specific a media range is, compared field by field in this order:
/// `application/sdp` over `application/*` over `*/*`, and then a range that
/// names more media-type parameters over one that names fewer.
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
        // §20.1 keeps the semantics of HTTP's Accept, and RFC 2616 §14.1 has
        // "Media ranges can be overridden by more specific media ranges or
        // specific media types. If more than one media range applies to a
        // given type, the most specific reference has precedence." A wider
        // range that takes everything does not take back what a narrower one
        // ruled out, and the other way round
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
        // RFC 2616 §14.1, which §20.1 keeps: "text/html;level=1" takes
        // precedence over "text/html". So `application/sdp;level=1;q=0` is
        // the more specific word on SDP than a bare `application/sdp`, and
        // the other way round
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
            // however many parameters a wider range names, a narrower type
            // outranks it
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
