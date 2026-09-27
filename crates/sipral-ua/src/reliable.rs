// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Provisional responses that are not allowed to be lost (RFC 3262).
//!
//! A 180 that vanishes costs a moment of silence. A 183 that vanishes costs
//! the offer or the answer it was carrying, and then the call is set up wrong
//! or not at all — which is why RFC 3262 exists and why carriers turn it on.
//! The layer below already retransmits a reliable provisional and matches the
//! PRACK that acknowledges it. What is decided here is when to use it, and
//! what to put in the answer.
//!
//! **When.** §3 leaves no room: `Require: 100rel` in the INVITE makes every
//! non-100 provisional reliable, `Supported: 100rel` makes it allowed, and
//! neither makes it forbidden. The 100 is never reliable under any of them.
//!
//! **What the 2xx has to wait for.** §5: a reliable provisional that carried a
//! session description holds up the 2xx until it is acknowledged. Sending the
//! 2xx first would put two unanswered offers on the wire at once, and the far
//! end has no way to tell which one the answer belongs to. So an application
//! that answers a call whose early media is still unacknowledged has its 200
//! held here and sent the moment the PRACK arrives — which is a wait measured
//! in one round trip, and better than a session negotiated twice.
//!
//! **The option tags this agent understands**, which is also what decides
//! whether a `Require` gets a 420 (§8.2.2.3). The list is short on purpose: an
//! extension nobody implements is one nobody should claim.

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

/// Everything this agent will always answer `Require` for.
///
/// `100rel` because this module implements it, `timer` because
/// [`crate::timers`] does, `replaces` because [`crate::transfer`] does,
/// `norefersub` because it grants RFC 4488's `Refer-Sub: false` to every
/// REFER it takes, and nothing else unconditionally. RFC 3261 §8.2.2.3
/// answers a `Require` outside this list with a 420 and says which token it
/// was -- except `gruu`, which
/// [`unsupported`] also accepts once the account the request is addressed to
/// has asked its own registrar for one (RFC 5627 §4.4 is written from a UA's
/// own use of GRUUs, but an account that understands the mechanism well
/// enough to ask for one has no reason to refuse a peer that names it).
pub(crate) const UNDERSTOOD: [&[u8]; 4] = [b"100rel", b"timer", b"replaces", b"norefersub"];

/// §21.4.15, and the only status §8.2.2.3 allows for an option tag this agent
/// has not implemented.
const BAD_EXTENSION: StatusCode = StatusCode::BAD_EXTENSION;

/// What a reliable provisional this end sent is still waiting for.
#[derive(Clone, Debug)]
pub(crate) struct Unacknowledged {
    /// The response, so that the wait can be told from an idle call.
    pub(crate) provisional: ProvisionalResponseId,
    /// Whether it carried a session description, which is what §5 makes the
    /// 2xx wait for.
    pub(crate) described: bool,
    /// A 200 the application asked for while this was outstanding, held until
    /// the PRACK arrives.
    pub(crate) held: Option<Arc<[u8]>>,
}

/// The option tags a request demands that this agent does not implement.
///
/// `gruu` is understood too when `gruu` is `true` -- the caller's job to
/// decide, since it depends on which account the request is addressed to.
pub(crate) fn unsupported(request: &RawMessage<'_>, gruu: bool) -> Vec<Vec<u8>> {
    request
        .require()
        .filter(|token| {
            let known = UNDERSTOOD
                .iter()
                .any(|known| known.eq_ignore_ascii_case(token))
                || (gruu && token.eq_ignore_ascii_case(b"gruu"));
            !known
        })
        .map(<[u8]>::to_vec)
        .collect()
}

/// Whether §3 says a provisional response to this request must, may, or must
/// not go reliably.
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
    /// Public, and not only for [`UserAgent::ring`]'s own use: a layer that
    /// joins media to this agent — `sipral::MediaEngine`, in this tree — has
    /// to make the same choice RFC 6337 §3.1.1 makes about what a later 2xx
    /// may carry, once a description already went out in a provisional
    /// response. Sent reliably, that description is the real answer and
    /// nothing after it may repeat it; sent unreliably, it was only a
    /// preview, and the 2xx — the exchange's first reliable non-failure
    /// response — still owes the far end the answer. This is the one fact
    /// that decision turns on, and it is already computed here from the
    /// INVITE's own `Require`/`Supported`, so it is exposed rather than
    /// recomputed.
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

    /// Remember a reliable provisional that has just gone out.
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

    /// `None` when the event was not about a reliable provisional.
    ///
    /// RFC 3262 §3 has the PRACK processed "according to the procedures of
    /// Sections 8.2 and 12.2.2 of RFC 3261" before it counts as the
    /// acknowledgement, so whatever §8.2 refuses — its `Require` (asked
    /// earlier, in [`UserAgent::on_require_event`]), its body here — goes
    /// through [`sipral_core::endpoint::Endpoint::refuse_prack`]: the
    /// response stays unacknowledged, a 2xx §5 is holding back behind it
    /// stays held, and the PRACK the far end sends again without what was
    /// refused (§8.1.3.5) is the one that lets it go.
    ///
    /// A session description in a PRACK is one of two things (§5). When the
    /// provisional response carried this end's offer — the INVITE came
    /// without one — it is the answer, and it is taken. Otherwise it is a
    /// new offer, and it is answered the way a re-offer is
    /// (`answer_prack_offer`): here when it changes nothing
    /// this layer would have to ask about, by the application through
    /// [`UaEvent::Reoffer`](crate::UaEvent::Reoffer) when it does.
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
        // RFC 3261 §8.2.3: a body that is not a session description, and that
        // its sender did not mark optional, is refused 415 rather than read
        if let Some(refusal) = crate::admission::body_refusal(&raw) {
            self.endpoint
                .refuse_prack(transaction, provisional, &refusal, now)
                .ok();
            return None;
        }
        // only a session description is an offer or an answer; a body of
        // another type that got this far was marked optional, and is ignored
        // — §3 has "any other type of body" treated "in the same way that
        // body in an ACK would be treated", which is not at all
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
            // bytes that say they are a session description and are not one:
            // neither an offer that can be answered nor an answer that can be
            // taken (RFC 3261 §14.2's 488, which RFC 3262 §5 applies here)
            Err(_) => {
                let refusal = OutgoingResponse::new(StatusCode::NOT_ACCEPTABLE_HERE)
                    .header(HeaderName::Warning, WHY_488);
                self.endpoint
                    .refuse_prack(transaction, provisional, &refusal, now)
                    .ok();
            }
            // §5: "If the UAC receives a reliable provisional response with an
            // offer ... it MUST generate an answer in the PRACK"
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

    /// A PRACK that carried an offer (RFC 3262 §5: "If the UAS receives a
    /// PRACK with an offer, it MUST place the answer in the 2xx to the
    /// PRACK"), asked what a re-offer is asked.
    ///
    /// One that crosses an offer of this end's own is told to wait with a
    /// 491, and one that arrives while an earlier offer of the far end's is
    /// still with the application with a 500 saying when to come back (RFC
    /// 3311 §5.2, which names the PRACK among the requests an offer may
    /// arrive in). An offer that keeps the streams, the formats and the
    /// keying is answered here, in the PRACK's 2xx. Anything else — a codec
    /// change, a stream added, a secured stream — needs what the application
    /// holds, so it is handed over as
    /// [`UaEvent::Reoffer`](crate::UaEvent::Reoffer) with the PRACK held open
    /// for it: [`UserAgent::accept_reoffer`] puts the answer in the PRACK's
    /// 2xx, and [`UserAgent::reject_reoffer`] refuses the PRACK and leaves
    /// the provisional response unacknowledged.
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

    /// Answer a PRACK 2xx (§3: "it MUST be responded to with a 2xx
    /// response"), with the answer to its offer when it carried one, and let
    /// go of what the provisional response it acknowledged was holding back.
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

    /// The reliable provisional response this call was waiting on has been
    /// acknowledged: §5 held the 2xx to the INVITE until now, and it can go.
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

    /// The call a reliable provisional belongs to.
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

    /// §8.2.2.3: a `Require` this agent cannot honour is a 420, and the
    /// response says which token it was so the far end can try without it.
    /// §8.2.2.3 for every request that arrives, not only the one that opens a
    /// call.
    ///
    /// "If a UAS does not understand an option-tag listed in a Require header
    /// field, it MUST respond by generating a response with status code 420
    /// (Bad Extension)." It says a UAS, not an INVITE: a re-INVITE, an UPDATE,
    /// an OPTIONS or a NOTIFY that demands an extension this agent has not
    /// implemented cannot be honoured as sent, and answering it as though it
    /// could is worse than saying so — a peer that asked for something and got
    /// a 200 believes it got it.
    ///
    /// This runs before the handlers that would act on the request, for the
    /// same reason the screening hook runs before the call layer: by the time
    /// a session change has been applied, refusing it is a second change. A
    /// PRACK is among them: refused here, it has acknowledged nothing, so the
    /// provisional response it names is put back and a 2xx held behind it
    /// waits for the PRACK that comes again without the extension.
    ///
    /// `Require: gruu` is the one token whose answer depends on who the
    /// request is for: honoured for an account that has asked its own
    /// registrar for GRUUs, 420 for one that has not (RFC 5627 §4.4).
    ///
    /// CANCEL and ACK are not here and must not be. The same section: "Note
    /// that Require and Proxy-Require MUST NOT be used in a SIP CANCEL
    /// request, or in an ACK request sent for a non-2xx response. These header
    /// fields MUST be ignored if they are present in these requests." Neither
    /// arrives as one of the events below.
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
                unsupported(&request.as_raw(), gruu)
            }
            Event::IncomingOutOfDialog { ref request, .. } => {
                let gruu = self.account_wants_gruu(&request.as_raw(), None);
                unsupported(&request.as_raw(), gruu)
            }
            // a PRACK is a request inside the dialog like any other (RFC 3262
            // §3: "the UAS core processes it according to the procedures of
            // Sections 8.2 and 12.2.2 of RFC 3261"), and §8.2.2.3 is one of them
            Event::IncomingPrack {
                ref request,
                provisional,
                ..
            } => {
                let gruu = self.account_wants_gruu(&request.as_raw(), Some(provisional.dialog()));
                unsupported(&request.as_raw(), gruu)
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
            // refused before it acknowledged anything: the provisional it
            // names stays unacknowledged, and a 2xx held behind it stays held
            // until the PRACK the far end sends again without the extension
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

    /// Whether the account behind a request has asked its registrar for
    /// GRUUs (RFC 5627 §4.1), which is what lets `unsupported` accept
    /// `Require: gruu` rather than answer it 420.
    ///
    /// In a dialog the account is the call's own; out of one, it is whichever
    /// line the Request-URI or the `To` names -- the same answer `line_for`
    /// gives an incoming INVITE before there is a call to ask.
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

/// §8.2.2.3: "The UAS MUST add an Unsupported header field, and list in it
/// those options it does not understand amongst those in the Require header
/// field of the request."
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
