// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The `trickle-ice` Info Package: trickled ICE candidates carried in INFO
//! requests inside the call's dialog (RFC 8840 §10, on RFC 6086's Info
//! Packages).
//!
//! What this layer does is the SIP half; the candidates themselves are the
//! media layer's, which reads and writes the
//! `application/trickle-ice-sdpfrag` bodies and hands them here whole.
//!
//! **Saying so.** A call announces the package when its description declares
//! `a=ice-options:trickle`: the INVITE, and every response this end sends to
//! one, carry `Supported: trickle-ice` and `Recv-Info: trickle-ice` (RFC 8840
//! §4, items 1 and 4; RFC 6086 §5.2.3). An INVITE placed with
//! [`OutgoingCall::require_trickle_ice`](crate::OutgoingCall::require_trickle_ice)
//! carries `Require: trickle-ice` too, which RFC 8840 §5.1 asks of an offer
//! that assumes the far end trickles: a far end that does not answers 420
//! and the failure is plain. On the answering side, a `Require` naming the
//! package is honoured only once [`UserAgent::accept_trickle_ice`] says so;
//! otherwise it is 420 like any other unknown extension. A response to an
//! INVITE that listed `Recv-Info` and that this end will not trickle on
//! carries an empty `Recv-Info`, as RFC 6086 §5.2.3 requires of a reliable
//! 18x and a 2xx.
//!
//! **When an INFO may go.** Only once the far end has listed the package in
//! its own `Recv-Info` (RFC 6086 §5.2.2), and only once the dialog exists at
//! both ends (RFC 8840 §4.3). The end that placed the call knows that from
//! the first response that created the dialog. The end that answered knows
//! it from the PRACK of a reliable provisional (§4.3.1), the ACK of its 2xx,
//! or the far end's own first INFO (§4.3.2): an answerer here never sends
//! an INFO the far end might not yet have a dialog for. Until then the body
//! waits.
//!
//! **One at a time, newest last.** "A Trickle ICE Agent MUST NOT have more
//! than one INFO request pending at any one time" (§10.9), and every body
//! repeats every candidate sent before it (§4.4), so a body handed in while
//! one is in flight replaces any that was waiting: the next INFO carries the
//! newest, and nothing is lost. A 469 means the far end stopped taking the
//! package, and nothing more is sent; any other failure is a transaction's
//! only (RFC 6086 §4.2.1), and the next body tries again.
//!
//! **Receiving.** An INFO naming the package, on a call that announced it, is
//! answered 200 and handed up as [`UaEvent::TrickleIce`]; one whose body is
//! not `application/trickle-ice-sdpfrag` gets a 415, and one past
//! [`MAX_BODY`] a 413. On a call that did not announce it, the INFO goes on
//! to the 469 every unknown package gets (`crate::admission`). A multipart
//! body is not unpacked: RFC 8840's own examples carry the fragment alone.

use std::sync::Arc;
use std::time::Instant;

use sipral_core::endpoint::{Event, OutgoingInDialogRequest, OutgoingResponse};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, RawMessage, StatusCode};
use sipral_core::sdp::SessionDescription;
use sipral_core::transaction::AnyTransactionId;

use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::error::UaError;
use crate::event::UaEvent;

/// The Info Package's name (RFC 8840 §10.4), in `Info-Package` and
/// `Recv-Info`.
pub const PACKAGE: &str = "trickle-ice";

/// The SIP option tag of the same name (RFC 8840 §10.6), in `Supported` and
/// `Require`.
pub const OPTION_TAG: &str = "trickle-ice";

/// The body type the package carries (RFC 8840 §9).
pub const MEDIA_TYPE: &str = "application/trickle-ice-sdpfrag";

/// The longest body taken: the media layer's own bound on what it reads.
pub const MAX_BODY: usize = 48 * 1024;

/// RFC 6086 §7.2.
pub(crate) const INFO_PACKAGE: HeaderName<'static> = HeaderName::Extension("Info-Package");

/// RFC 6086 §7.3.
pub(crate) const RECV_INFO: HeaderName<'static> = HeaderName::Extension("Recv-Info");

/// RFC 6086 §4.3.1: the body part an Info Package carries is marked so.
const CONTENT_DISPOSITION: HeaderName<'static> = HeaderName::Extension("Content-Disposition");

/// RFC 6086 §11.6.
const BAD_INFO_PACKAGE: StatusCode = match StatusCode::new(469) {
    Ok(code) => code,
    Err(_) => StatusCode::SERVER_ERROR,
};

/// What one call knows about trickling.
///
/// Five facts learned at different moments from different messages, each
/// true or not on its own; a state machine over them would have states no
/// call reaches.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
pub(crate) struct Trickle {
    /// This end listed the package in `Recv-Info`, so takes its INFOs.
    pub(crate) receiving: bool,
    /// The far end listed it, so may be sent them.
    pub(crate) sending: bool,
    /// The far end is known to hold the dialog (RFC 8840 §4.3).
    pub(crate) confirmed: bool,
    /// The far end's INVITE carried a `Recv-Info`, so every reliable 18x and
    /// 2xx to it carries one too (RFC 6086 §5.2.3).
    pub(crate) asked: bool,
    /// The INFO in flight.
    pub(crate) in_flight: Option<AnyTransactionId>,
    /// The newest body, waiting for its turn.
    pub(crate) next: Option<Arc<[u8]>>,
    /// The far end answered 469: it takes no more.
    pub(crate) refused: bool,
}

/// Whether a description declares trickle ICE: `trickle` among the
/// `ice-options` tokens, at the session level or on any stream (RFC 8838 §3).
pub(crate) fn declares_trickle(description: &SessionDescription) -> bool {
    let trickle = |value: Option<&str>| {
        value.is_some_and(|tokens| tokens.split_whitespace().any(|token| token == "trickle"))
    };
    description
        .attributes
        .iter()
        .chain(
            description
                .media
                .iter()
                .flat_map(|media| media.attributes.iter()),
        )
        .filter(|attribute| attribute.name.eq_ignore_ascii_case("ice-options"))
        .any(|attribute| trickle(attribute.value.as_deref()))
}

/// Whether a comma-separated field lists `token`.
pub(crate) fn lists(message: &RawMessage<'_>, name: HeaderName<'_>, token: &str) -> bool {
    message.header_values(name).any(|value| {
        value.split(|byte| *byte == b',').any(|item| {
            // an Info-Package or Recv-Info value may carry parameters
            let bare = item.split(|byte| *byte == b';').next().unwrap_or_default();
            bare.trim_ascii().eq_ignore_ascii_case(token.as_bytes())
        })
    })
}

/// Add an option tag to the `Supported` field among `headers`, or the field
/// itself when there is none.
pub(crate) fn fold_option(headers: &mut Vec<(HeaderName<'static>, Box<[u8]>)>, token: &[u8]) {
    if let Some((_, value)) = headers
        .iter_mut()
        .find(|(name, _)| *name == HeaderName::Supported)
    {
        let mut merged = value.to_vec();
        merged.extend_from_slice(b", ");
        merged.extend_from_slice(token);
        *value = merged.into_boxed_slice();
    } else {
        headers.push((HeaderName::Supported, Box::from(token)));
    }
}

/// Whether a request or response says it supports or requires the package.
fn announces(message: &RawMessage<'_>) -> bool {
    lists(message, HeaderName::Supported, OPTION_TAG)
        || lists(message, HeaderName::Require, OPTION_TAG)
}

impl UserAgent {
    /// Take INVITEs that require trickle ICE (`Require: trickle-ice`) rather
    /// than refusing them 420, list the option tag in answers to OPTIONS
    /// (RFC 8840 §10.6), and announce the package on every response to an
    /// INVITE whose offer trickles. Off by default.
    ///
    /// Turn it on when the media layer answers such offers with trickle ICE
    /// (`sipral`'s `IceTrickle`): the far end then sends candidates in INFO
    /// requests, which arrive as [`UaEvent::TrickleIce`].
    pub fn accept_trickle_ice(&mut self, accept: bool) {
        self.trickle_ice = accept;
    }

    /// Whether [`UserAgent::accept_trickle_ice`] is on.
    #[must_use]
    pub const fn accepts_trickle_ice(&self) -> bool {
        self.trickle_ice
    }

    /// Send the far end this end's trickled candidates: `body` is a whole
    /// `application/trickle-ice-sdpfrag` (RFC 8840 §9) repeating every
    /// candidate sent before it, the new ones last.
    ///
    /// It goes in an INFO as soon as the package allows (see the module
    /// documentation): at once, or when the far end has listed the package
    /// and holds the dialog, or after the INFO in flight is answered. A newer
    /// body handed in before then takes this one's place.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`]; [`UaError::Send`] when the INFO could not be
    /// built or sent, after which the body waits for the next try.
    pub fn trickle_ice(
        &mut self,
        call: CallHandle,
        body: Arc<[u8]>,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
        held.trickle.next = Some(body);
        let sent = self.send_trickle(call, now);
        self.drain(now);
        sent
    }

    /// Whether the far end takes trickled candidates on this call: it listed
    /// the package and has not refused it since.
    #[must_use]
    pub fn takes_trickle_ice(&self, call: CallHandle) -> bool {
        self.calls
            .get(&call)
            .is_some_and(|held| held.trickle.sending && !held.trickle.refused)
    }

    /// Send the waiting body if the package allows it now. What the endpoint
    /// reports about it is read by the drain this runs under, or the one the
    /// caller runs next.
    pub(crate) fn send_trickle(&mut self, call: CallHandle, now: Instant) -> Result<(), UaError> {
        let Some(held) = self.calls.get_mut(&call) else {
            return Ok(());
        };
        let trickle = &mut held.trickle;
        let ready = trickle.sending
            && trickle.confirmed
            && !trickle.refused
            && trickle.in_flight.is_none()
            && trickle.next.is_some();
        let Some(dialog) = held.dialog.filter(|_| ready) else {
            return Ok(());
        };
        let Some(body) = held.trickle.next.take() else {
            return Ok(());
        };
        let request = OutgoingInDialogRequest::new(Method::Info)
            .header(INFO_PACKAGE, PACKAGE.as_bytes())
            .header(CONTENT_DISPOSITION, b"Info-Package")
            .body(MEDIA_TYPE.as_bytes(), Arc::clone(&body));
        let transaction = match self.endpoint.request_in_dialog(dialog, &request, now) {
            Ok(transaction) => transaction,
            Err(error) => {
                if let Some(held) = self.calls.get_mut(&call) {
                    held.trickle.next.get_or_insert(body);
                }
                return Err(error.into());
            }
        };
        let id = AnyTransactionId::NonInviteClient(transaction);
        self.remember_request(call, id, Method::Info);
        if let Some(held) = self.calls.get_mut(&call) {
            held.trickle.in_flight = Some(id);
        }
        Ok(())
    }

    /// An INFO of the package was answered, or never will be.
    pub(crate) fn trickle_info_over(
        &mut self,
        id: AnyTransactionId,
        call: CallHandle,
        status: StatusCode,
        now: Instant,
    ) {
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        if held.trickle.in_flight != Some(id) {
            return;
        }
        held.trickle.in_flight = None;
        if status == BAD_INFO_PACKAGE {
            held.trickle.refused = true;
            held.trickle.next = None;
            return;
        }
        // the next body, if one came meanwhile; a refusal of this one was
        // the transaction's only (RFC 6086 §4.2.1)
        self.send_trickle(call, now).ok();
    }

    /// The challenged INFO was sent again under credentials: the retry is
    /// the one in flight.
    pub(crate) fn trickle_retried(
        &mut self,
        call: CallHandle,
        refused: AnyTransactionId,
        retried: AnyTransactionId,
    ) {
        if let Some(held) = self.calls.get_mut(&call)
            && held.trickle.in_flight == Some(refused)
        {
            held.trickle.in_flight = Some(retried);
        }
    }

    /// What an INVITE this end sends says about the package, given its
    /// offer: the fields to add, and whether the call takes the package.
    pub(crate) fn trickle_for_invite(
        offer: Option<&SessionDescription>,
        required: bool,
    ) -> (Vec<(HeaderName<'static>, &'static [u8])>, bool) {
        let declared = required || offer.is_some_and(declares_trickle);
        if !declared {
            return (Vec::new(), false);
        }
        let mut fields = vec![(RECV_INFO, PACKAGE.as_bytes())];
        if required {
            fields.push((HeaderName::Require, OPTION_TAG.as_bytes()));
        }
        (fields, true)
    }

    /// The far end's `Recv-Info` and dialog, from a response to the INVITE
    /// this end sent: a dialog-creating response means the far end holds the
    /// dialog it created (RFC 8840 §4.3.1, §4.3.2).
    pub(crate) fn trickle_heard(
        &mut self,
        call: CallHandle,
        response: &OwnedMessage,
        now: Instant,
    ) {
        let raw = response.as_raw();
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        if !held.trickle.receiving {
            return;
        }
        if raw.header(RECV_INFO).is_some() {
            held.trickle.sending = lists(&raw, RECV_INFO, PACKAGE);
        }
        if held.dialog.is_some() {
            held.trickle.confirmed = true;
        }
        self.send_trickle(call, now).ok();
    }

    /// An INVITE that arrived: whether it lists `Recv-Info`, and the package
    /// in it.
    pub(crate) fn trickle_invited(&mut self, call: CallHandle, request: &RawMessage<'_>) {
        let asked = request.header(RECV_INFO).is_some();
        let sending = lists(request, RECV_INFO, PACKAGE);
        if let Some(held) = self.calls.get_mut(&call) {
            held.trickle.asked = asked;
            held.trickle.sending = sending;
        }
    }

    /// The fields a response to the call's INVITE carries about the package,
    /// given the description it carries, if any; and the call takes the
    /// package from then on when they announce it.
    ///
    /// Announced when the response's description declares trickle, or, for
    /// one without a description, when this agent takes the package and the
    /// INVITE's offer trickled. Otherwise an empty `Recv-Info` where RFC 6086
    /// §5.2.3 needs one: on a reliable 18x or a 2xx to an INVITE that listed
    /// one.
    pub(crate) fn trickle_for_response(
        &mut self,
        call: CallHandle,
        described: Option<&SessionDescription>,
        reliable: bool,
    ) -> Vec<(HeaderName<'static>, &'static [u8])> {
        let accepting = self.trickle_ice;
        let Some(held) = self.calls.get_mut(&call) else {
            return Vec::new();
        };
        let invited = held.invited.as_ref();
        let offered = invited.is_some_and(|invite| announces(&invite.as_raw()))
            || held.session.remote().is_some_and(declares_trickle);
        // once announced, every later response to the INVITE says the same
        // (RFC 6086 §5.2.3: "the same Recv-Info header field value [...] in
        // all responses for the same transaction")
        let announced = held.trickle.receiving
            || match described {
                Some(description) => declares_trickle(description),
                None => accepting && offered,
            };
        if announced {
            held.trickle.receiving = true;
            return vec![(RECV_INFO, PACKAGE.as_bytes())];
        }
        if held.trickle.asked && reliable {
            return vec![(RECV_INFO, b"")];
        }
        Vec::new()
    }

    /// The far end is known to hold the dialog now: its PRACK, its ACK, or
    /// any request of its own in it arrived.
    pub(crate) fn trickle_confirmed(&mut self, call: CallHandle, now: Instant) {
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        if !held.trickle.receiving || held.trickle.confirmed {
            return;
        }
        held.trickle.confirmed = true;
        self.send_trickle(call, now).ok();
    }

    /// `None` when this answered an INFO of the package on a call that takes
    /// it; the event back otherwise, for the 469 or 481 further down.
    pub(crate) fn on_trickle_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let Event::IncomingInDialog {
            transaction,
            dialog,
            ref request,
        } = event
        else {
            return Some(event);
        };
        let raw = request.as_raw();
        if raw.method() != Some(Method::Info) || !lists(&raw, INFO_PACKAGE, PACKAGE) {
            return Some(event);
        }
        let Some(call) = self.by_dialog.get(&dialog).copied() else {
            return Some(event);
        };
        if !self
            .calls
            .get(&call)
            .is_some_and(|held| held.trickle.receiving)
        {
            return Some(event);
        }
        let typed = raw
            .content_type()
            .is_ok_and(|kind| kind.is("application", "trickle-ice-sdpfrag"));
        let answer = if !typed {
            OutgoingResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                .header(HeaderName::Accept, MEDIA_TYPE.as_bytes())
        } else if raw.body().len() > MAX_BODY {
            OutgoingResponse::new(StatusCode::REQUEST_ENTITY_TOO_LARGE)
        } else {
            OutgoingResponse::new(StatusCode::OK)
        };
        let taken = typed && raw.body().len() <= MAX_BODY;
        self.endpoint.respond(transaction, &answer, now).ok();
        if taken {
            self.events.push_back(UaEvent::TrickleIce {
                call,
                body: Arc::from(raw.body()),
            });
        }
        // the far end could only send it inside a dialog it holds
        self.trickle_confirmed(call, now);
        None
    }
}

#[cfg(test)]
mod tests {
    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};
    use sipral_core::sdp;

    use super::{PACKAGE, RECV_INFO, declares_trickle, lists};

    fn description(extra: &str) -> sdp::SessionDescription {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
m=audio 4000 RTP/AVP 0\r\na=ice-ufrag:8hhY\r\na=ice-pwd:asd88fgpdd777uzjYhagZg\r\n{extra}"
        );
        sdp::parse(text.as_bytes()).expect("a description")
    }

    #[test]
    fn a_description_declares_trickle_by_its_ice_options() {
        assert!(declares_trickle(&description(
            "a=ice-options:trickle ice2\r\n"
        )));
        assert!(declares_trickle(&description(
            "a=ice-options:ice2 trickle\r\n"
        )));
        assert!(!declares_trickle(&description("a=ice-options:ice2\r\n")));
        assert!(!declares_trickle(&description("")));
    }

    #[test]
    fn a_package_is_found_among_several_and_past_its_parameters() {
        let text = "INFO sip:a@192.0.2.1 SIP/2.0\r\nRecv-Info: foo, trickle-ice;x=1\r\n\
Info-Package: Trickle-ICE\r\nContent-Length: 0\r\n\r\n";
        let mut scratch = ParseScratch::new();
        let raw = parse(text.as_bytes(), &mut scratch, ParseMode::Lenient).expect("a request");
        assert!(lists(&raw, RECV_INFO, PACKAGE));
        assert!(
            lists(&raw, super::INFO_PACKAGE, PACKAGE),
            "tokens compare without case"
        );
        assert!(!lists(&raw, HeaderName::Supported, PACKAGE));
    }
}
