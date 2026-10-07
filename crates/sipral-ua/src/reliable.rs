// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Reliable provisional responses (RFC 3262).
//!
//! A lost 183 loses the offer or answer it carried. The layer below
//! retransmits and matches the PRACK; this module decides when to use it and
//! what the answer holds.
//!
//! `Require: 100rel` makes every non-100 provisional reliable, `Supported`
//! allows it (§3). A reliable provisional with a session description holds
//! the 2xx until its PRACK (§5), so an early answer is queued here and sent
//! when the PRACK arrives.
//!
//! The option tags listed here also decide which `Require` gets a 420
//! (RFC 3261 §8.2.2.3).

use std::sync::Arc;
use std::time::Instant;

use sipral_core::endpoint::{Event, OutgoingResponse};
use sipral_core::msg::{HeaderName, OwnedMessage, RawMessage, StatusCode};
use sipral_core::sdp::SessionDescription;
use sipral_core::transaction::{
    AnyTransactionId, DialogId, InviteServer, NonInviteServer, ProvisionalResponseId, TransactionId,
};

use crate::account::Account;
use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::renegotiate::{ALLOW, WHY_488};

/// Option tags always honoured in `Require`; anything else gets a 420.
///
/// `norefersub` because every REFER is granted RFC 4488's `Refer-Sub: false`;
/// `answermode` because [`crate::answering`] reads RFC 5373 fields. `gruu`
/// is conditional, see [`unsupported`].
pub(crate) const UNDERSTOOD: [&[u8]; 5] = [
    b"100rel",
    b"timer",
    b"replaces",
    b"norefersub",
    b"answermode",
];

/// RFC 3261 §21.4.15.
const BAD_EXTENSION: StatusCode = StatusCode::BAD_EXTENSION;

/// What a reliable provisional this end sent is still waiting for.
#[derive(Clone, Debug)]
pub(crate) struct Unacknowledged {
    pub(crate) provisional: ProvisionalResponseId,
    /// It carried a session description, so the 2xx waits (§5).
    pub(crate) described: bool,
    /// A 200 the application asked for meanwhile, sent on the PRACK.
    pub(crate) held: Option<Arc<[u8]>>,
}

/// The option tags a request demands that this agent does not implement.
///
/// `gruu` is accepted when the addressed account asked its registrar for one
/// (RFC 5627 §4.4), `siprec` when the application takes recording sessions
/// ([`UserAgent::accept_recording_sessions`]).
pub(crate) fn unsupported(request: &RawMessage<'_>, gruu: bool, siprec: bool) -> Vec<Vec<u8>> {
    request
        .require()
        .filter(|token| {
            let known = UNDERSTOOD
                .iter()
                .any(|known| known.eq_ignore_ascii_case(token))
                || (gruu && token.eq_ignore_ascii_case(b"gruu"))
                || (siprec && token.eq_ignore_ascii_case(crate::siprec::OPTION_TAG.as_bytes()));
            !known
        })
        .map(<[u8]>::to_vec)
        .collect()
}

/// Whether provisionals to this request go reliably (§3).
pub(crate) fn wants_reliable(request: &RawMessage<'_>) -> bool {
    lists(request, HeaderName::Require) || lists(request, HeaderName::Supported)
}

fn lists(request: &RawMessage<'_>, name: HeaderName<'_>) -> bool {
    request
        .field_values(name)
        .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"100rel"))
}

impl UserAgent {
    /// Whether a provisional response to this call has to go reliably (§3).
    ///
    /// A media layer needs this for RFC 6337 §3.1.1: a description sent in a
    /// reliable provisional is the answer and the 2xx must not repeat it; sent
    /// unreliably, it was a preview and the 2xx still carries the answer.
    #[must_use]
    pub fn reliably(&self, call: CallHandle) -> bool {
        self.calls
            .get(&call)
            .and_then(|held| held.invited.as_ref())
            .is_some_and(|invite| wants_reliable(&invite.as_raw()))
    }

    /// Whether a 2xx for this call has to wait (§5).
    pub(crate) fn answer_is_held(&self, call: CallHandle) -> bool {
        self.calls
            .get(&call)
            .and_then(|held| held.unacknowledged.as_ref())
            .is_some_and(|waiting| waiting.described)
    }

    pub(crate) fn watch_provisional(
        &mut self,
        call: CallHandle,
        provisional: ProvisionalResponseId,
        described: bool,
    ) {
        if let Some(held) = self.calls.get_mut(&call) {
            held.unacknowledged = Some(Unacknowledged {
                provisional,
                described,
                held: None,
            });
        }
    }

    /// Keep a 200 the application asked for until §5 allows it out.
    pub(crate) fn hold_answer(&mut self, call: CallHandle, sdp: Option<Arc<[u8]>>) {
        if let Some(waiting) = self
            .calls
            .get_mut(&call)
            .and_then(|held| held.unacknowledged.as_mut())
        {
            waiting.held = sdp.or_else(|| Some(Arc::from(&b""[..])));
        }
    }

    /// `None` when the event was about a reliable provisional and was handled.
    ///
    /// A PRACK refused under RFC 3261 §8.2 (its `Require`, its body)
    /// acknowledges nothing: the provisional and any held 2xx wait for the
    /// resent PRACK (RFC 3262 §3).
    ///
    /// A description in a PRACK is the answer when the provisional carried
    /// our offer; otherwise it is a new offer, answered as a re-offer (§5).
    pub(crate) fn on_reliable_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let Event::IncomingPrack {
            transaction,
            provisional,
            ref request,
        } = event
        else {
            return Some(event);
        };
        let Some(call) = self.call_of_provisional(provisional) else {
            return Some(event);
        };
        let request = request.clone();
        let raw = request.as_raw();
        // RFC 3261 §8.2.3: 415 for a non-optional body we cannot read
        if let Some(refusal) = crate::admission::body_refusal(&raw) {
            self.endpoint
                .refuse_prack(transaction, provisional, &refusal, now)
                .ok();
            return None;
        }
        // an optional non-SDP body is ignored, as in an ACK (§3)
        let described = !raw.body().is_empty()
            && raw
                .content_type()
                .is_ok_and(|kind| kind.is("application", "sdp"));
        if !described {
            self.confirm_prack(call, transaction, None, now);
            return None;
        }
        let parsed = sipral_core::sdp::parse_with_limits(raw.body(), self.sdp_limits);
        let answers_ours = self
            .calls
            .get(&call)
            .is_some_and(|held| held.session.has_local() && !held.session.has_remote());
        match parsed {
            // unparseable SDP: 488 (RFC 3261 §14.2, via RFC 3262 §5)
            Err(_) => {
                let refusal = OutgoingResponse::new(StatusCode::NOT_ACCEPTABLE_HERE)
                    .header(HeaderName::Warning, WHY_488);
                self.endpoint
                    .refuse_prack(transaction, provisional, &refusal, now)
                    .ok();
            }
            // §5: the answer to our offer
            Ok(answer) if answers_ours => {
                if let Some(held) = self.calls.get_mut(&call) {
                    held.session.set_remote(answer);
                }
                self.report_session(call);
                self.confirm_prack(call, transaction, None, now);
            }
            Ok(offer) => {
                self.answer_prack_offer(call, transaction, provisional, offer, &request, now);
            }
        }
        None
    }

    /// A PRACK carrying an offer; the answer goes in its 2xx (RFC 3262 §5).
    ///
    /// Crossing our own offer: 491. While an earlier far-end offer is with
    /// the application: 500 with a retry time (RFC 3311 §5.2). Same media is
    /// answered here; anything else becomes
    /// [`UaEvent::Reoffer`](crate::UaEvent::Reoffer) with the PRACK held open:
    /// [`UserAgent::accept_reoffer`] answers in its 2xx,
    /// [`UserAgent::reject_reoffer`] refuses it and leaves the provisional
    /// unacknowledged.
    fn answer_prack_offer(
        &mut self,
        call: CallHandle,
        transaction: TransactionId<NonInviteServer>,
        provisional: ProvisionalResponseId,
        offer: SessionDescription,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let (crossing, pending) = self.calls.get(&call).map_or((false, false), |held| {
            let crossing = held.session.answer_owed
                || held
                    .offering
                    .as_ref()
                    .is_some_and(|offer| offer.transaction.is_some());
            (crossing, held.answering.is_some())
        });
        if crossing || pending {
            let refusal = if crossing {
                OutgoingResponse::new(StatusCode::REQUEST_PENDING)
            } else {
                self.too_soon(StatusCode::SERVER_ERROR)
            };
            self.endpoint
                .refuse_prack(transaction, provisional, &refusal, now)
                .ok();
            return;
        }
        let answer = self.calls.get_mut(&call).and_then(|held| {
            if !held.session.is_same_media(&offer) {
                return None;
            }
            let wanted = held.session.hold.local;
            held.session.answer(&offer, wanted)
        });
        let Some(answer) = answer else {
            self.hand_over(
                call,
                AnyTransactionId::NonInviteServer(transaction),
                offer,
                Some(provisional),
                request,
            );
            return;
        };
        let body: Arc<[u8]> = Arc::from(answer.to_bytes());
        if let Some(held) = self.calls.get_mut(&call) {
            held.session.set_remote(offer);
            held.session.set_local(answer);
            held.overtake();
        }
        self.report_session(call);
        self.confirm_prack(call, transaction, Some(body), now);
    }

    /// 2xx the PRACK (§3) and release the held answer.
    fn confirm_prack(
        &mut self,
        call: CallHandle,
        transaction: TransactionId<NonInviteServer>,
        answer: Option<Arc<[u8]>>,
        now: Instant,
    ) {
        let mut response = OutgoingResponse::new(StatusCode::OK).header(HeaderName::Allow, ALLOW);
        if let Some(answer) = answer {
            response = response.body(b"application/sdp", answer);
        }
        self.endpoint.respond(transaction, &response, now).ok();
        self.acknowledged(call, now);
    }

    /// The awaited PRACK arrived: send the 2xx §5 was holding.
    pub(crate) fn acknowledged(&mut self, call: CallHandle, now: Instant) {
        let waiting = self
            .calls
            .get_mut(&call)
            .and_then(|held| held.unacknowledged.take());
        if let Some(sdp) = waiting.and_then(|waiting| waiting.held) {
            let sdp = (!sdp.is_empty()).then_some(sdp);
            self.answer(call, sdp, now).ok();
        }
    }

    fn call_of_provisional(&self, provisional: ProvisionalResponseId) -> Option<CallHandle> {
        self.calls
            .iter()
            .find(|(_, held)| {
                held.unacknowledged
                    .as_ref()
                    .is_some_and(|waiting| waiting.provisional == provisional)
            })
            .map(|(handle, _)| *handle)
    }

    /// 420 with `Unsupported` for any request whose `Require` we cannot honour
    /// (RFC 3261 §8.2.2.3), in or out of a dialog. A 200 would make the peer
    /// believe it got the extension.
    ///
    /// Runs before the handlers, since refusing an applied session change
    /// would be a second change. A refused PRACK acknowledges nothing.
    /// CANCEL and ACK must ignore `Require` (same section) and never reach
    /// here.
    pub(crate) fn on_require_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let missing = match event {
            Event::IncomingReinvite {
                ref request,
                dialog,
                ..
            }
            | Event::IncomingInDialog {
                ref request,
                dialog,
                ..
            } => {
                let gruu = self.account_wants_gruu(&request.as_raw(), Some(dialog));
                unsupported(&request.as_raw(), gruu, self.recording_server)
            }
            Event::IncomingOutOfDialog { ref request, .. } => {
                let gruu = self.account_wants_gruu(&request.as_raw(), None);
                unsupported(&request.as_raw(), gruu, self.recording_server)
            }
            // RFC 3262 §3 runs RFC 3261 §8.2 on a PRACK too
            Event::IncomingPrack {
                ref request,
                provisional,
                ..
            } => {
                let gruu = self.account_wants_gruu(&request.as_raw(), Some(provisional.dialog()));
                unsupported(&request.as_raw(), gruu, self.recording_server)
            }
            _ => return Some(event),
        };
        if missing.is_empty() {
            return Some(event);
        }
        let refusal =
            OutgoingResponse::new(BAD_EXTENSION).header(HeaderName::Unsupported, &listed(&missing));
        match event {
            Event::IncomingReinvite { transaction, .. } => {
                self.endpoint
                    .respond_invite(transaction, &refusal, now)
                    .ok();
            }
            Event::IncomingInDialog { transaction, .. }
            | Event::IncomingOutOfDialog { transaction, .. } => {
                self.endpoint.respond(transaction, &refusal, now).ok();
            }
            Event::IncomingPrack {
                transaction,
                provisional,
                ..
            } => {
                self.endpoint
                    .refuse_prack(transaction, provisional, &refusal, now)
                    .ok();
            }
            _ => return Some(event),
        }
        None
    }

    /// Whether the request's account asked its registrar for GRUUs
    /// (RFC 5627 §4.1). Out of a dialog the account comes from `line_for`.
    fn account_wants_gruu(&self, request: &RawMessage<'_>, dialog: Option<DialogId>) -> bool {
        let account = dialog
            .and_then(|dialog| self.by_dialog.get(&dialog))
            .and_then(|call| self.calls.get(call))
            .and_then(|held| held.account)
            .or_else(|| self.line_for(request));
        account
            .and_then(|id| self.accounts.get(&id))
            .is_some_and(Account::wants_gruu)
    }

    pub(crate) fn refuse_extension(
        &mut self,
        transaction: TransactionId<InviteServer>,
        missing: &[Vec<u8>],
        now: Instant,
    ) {
        let refusal =
            OutgoingResponse::new(BAD_EXTENSION).header(HeaderName::Unsupported, &listed(missing));
        self.endpoint
            .respond_invite(transaction, &refusal, now)
            .ok();
    }
}

/// The `Unsupported` value (RFC 3261 §8.2.2.3).
fn listed(missing: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for token in missing {
        if !out.is_empty() {
            out.extend_from_slice(b", ");
        }
        out.extend_from_slice(token);
    }
    out
}
