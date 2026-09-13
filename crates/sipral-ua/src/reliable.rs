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
use sipral_core::msg::{HeaderName, RawMessage, StatusCode};
use sipral_core::transaction::{DialogId, InviteServer, ProvisionalResponseId, TransactionId};

use crate::account::Account;
use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::renegotiate::ALLOW;

/// Everything this agent will always answer `Require` for.
///
/// `100rel` because this module implements it, `timer` because
/// [`crate::timers`] does, `replaces` because [`crate::transfer`] does, and
/// nothing else unconditionally. RFC 3261 §8.2.2.3 answers a `Require` outside
/// this list with a 420 and says which token it was -- except `gruu`, which
/// [`unsupported`] also accepts once the account the request is addressed to
/// has asked its own registrar for one (RFC 5627 §4.4 is written from a UA's
/// own use of GRUUs, but an account that understands the mechanism well
/// enough to ask for one has no reason to refuse a peer that names it).
pub(crate) const UNDERSTOOD: [&[u8]; 3] = [b"100rel", b"timer", b"replaces"];

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
    pub(crate) fn reliably(&self, call: CallHandle) -> bool {
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

        // §5: "If the UAS receives a PRACK with an offer, it MUST place the
        // answer in the 2xx to the PRACK." An offer this layer can answer —
        // the same hold or resume `is_same_media` takes anywhere else — gets
        // its answer in the 2xx below.
        //
        // One that it cannot is a gap, and a named one. The 2xx still has to
        // go (§3: a PRACK "MUST be responded to with a 2xx response"), it goes
        // without a body, and nothing is adopted: `answer_for` returns before
        // it touches `set_remote`, so a PRACK carrying a downgrade leaves the
        // call on the secure description it already had. That is the safe half
        // and it is not an accident. The unsafe half is that the application
        // is never told an offer arrived and was dropped, and there is no
        // event shaped to tell it — the 2xx has already gone, so there is no
        // transaction left for an application to answer into. Saying so is
        // what this comment is for, and it is the one thing this path owes
        // that it does not yet pay.
        let body = request.as_raw().body().to_vec();
        let answer = if body.is_empty() {
            None
        } else {
            self.answer_for(call, &body)
        };

        // §3: "it MUST be responded to with a 2xx response"
        let mut response = OutgoingResponse::new(StatusCode::OK).header(HeaderName::Allow, ALLOW);
        if let Some(ref answer) = answer {
            response = response.body(b"application/sdp", Arc::clone(answer));
        }
        self.endpoint.respond(transaction, &response, now).ok();

        let waiting = self
            .calls
            .get_mut(&call)
            .and_then(|held| held.unacknowledged.take());
        // §5 held the 2xx to the INVITE; it can go now
        if let Some(sdp) = waiting.and_then(|waiting| waiting.held) {
            let sdp = (!sdp.is_empty()).then_some(sdp);
            self.answer(call, sdp, now).ok();
        }
        None
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

    /// The answer to an offer that arrived in a PRACK, when this layer can
    /// write one at all.
    fn answer_for(&mut self, call: CallHandle, body: &[u8]) -> Option<Arc<[u8]>> {
        let offer = sipral_core::sdp::parse_with_limits(body, self.sdp_limits).ok()?;
        let held = self.calls.get_mut(&call)?;
        if !held.session.is_same_media(&offer) {
            return None;
        }
        let wanted = held.session.hold.local;
        let answer = held.session.answer(&offer, wanted)?;
        held.session.set_remote(offer);
        held.session.set_local(answer.clone());
        Some(Arc::from(answer.to_bytes()))
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
    /// a session change has been applied, refusing it is a second change.
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
