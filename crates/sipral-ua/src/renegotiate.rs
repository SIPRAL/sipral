// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Changing a session that is already running: hold, resume, and whatever
//! either end offers afterwards.
//!
//! **Which request carries it.** A confirmed dialog uses a re-INVITE, because
//! RFC 3311 §5.1 says so in as many words — "although UPDATE can be used on
//! confirmed dialogs, it is RECOMMENDED that a re-INVITE be used instead" —
//! and the reason it gives is that an UPDATE has to be answered at once, which
//! rules out asking a person first. Before the call is answered there is no
//! choice in the other direction: §14.1 forbids a second INVITE while the
//! first is running, so an early session changes by UPDATE, and only when the
//! far end listed UPDATE in an `Allow` (RFC 3311 §4).
//!
//! **What this layer answers by itself.** An offer that keeps the streams and
//! the formats that were negotiated is a hold, a resume, or a peer moving its
//! media address, and answering it needs nothing this layer does not have: the
//! answer is this end's own ports and formats, with the direction RFC 3264
//! §6.1 leaves. An offer that changes the codecs, adds a stream or drops one
//! needs a device, so it goes to the application whole — with the transaction
//! kept open, because a re-INVITE nobody answers is retransmitted and then
//! ends the call.
//!
//! **Glare.** Both ends pressing hold in the same instant is the ordinary way
//! two offers cross. The refusal is a 491, the wait is drawn from two ranges
//! that do not overlap, and the change is offered once more — §14.1 says "once
//! more", not "until it works".
//!
//! One judgement call, and it is RFC 3311 §5.2's: an UPDATE "MUST be responded
//! to promptly", and a UAS that "cannot change the session parameters without
//! prompting the user ... SHOULD reject the request with a 504". An
//! application here is not a person being prompted — a voice agent answers in
//! microseconds — so an UPDATE this layer cannot answer is still handed over
//! rather than refused on its behalf. An application that does ask a person
//! should answer 504 itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Event, OutgoingInDialogRequest, OutgoingResponse};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, RawMessage, StatusCode};
use sipral_core::sdp::{self, SessionDescription};
use sipral_core::transaction::AnyTransactionId;

use crate::agent::UserAgent;
use crate::call::{Answering, CallHandle, CallState, Direction, Offer};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::registration::spread;
use crate::session::Hold;

/// What this agent will answer, advertised so that the far end knows an UPDATE
/// is worth sending (RFC 3311 §4).
///
/// It lists what is answered here and nothing more.
pub(crate) const ALLOW: &[u8] = b"INVITE, ACK, CANCEL, BYE, UPDATE, PRACK, REFER, NOTIFY";

/// §14.1 and RFC 3311 §5.3: the wait for the end that generated the `Call-ID`,
/// in milliseconds.
const OWNER_BACKOFF: (u64, u64) = (2_100, 4_000);
/// And for the end that did not.
const GUEST_BACKOFF: (u64, u64) = (0, 2_000);
/// Both are drawn "in units of 10 ms".
const BACKOFF_STEP: u64 = 10;
/// RFC 3311 §5.2 wants a `Retry-After` "between 0 and 10 seconds".
const RETRY_AFTER_CEILING: u32 = 11;
/// §14.2 and RFC 3311 §5.2 both say a 488 "SHOULD include a Warning header
/// field". 399 is §20.43's miscellaneous code, which is what this is.
const WHY_488: &[u8] = b"399 sipral \"the session description could not be read\"";

// -- what the application asks for -------------------------------------------

impl UserAgent {
    /// Put a call on hold (RFC 3264 §8.4).
    ///
    /// The description is this layer's to write: the one already negotiated,
    /// with every stream's direction changed to say this end will not receive,
    /// and an `o=` version that has moved. Asking for a hold that is already
    /// in place sends nothing.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::NoSession`] when nothing has been
    /// described yet, [`UaError::ChangeInProgress`] when a change is already
    /// running, [`UaError::CannotRenegotiate`] when the call is not up and the
    /// far end never advertised UPDATE, or [`UaError::Send`].
    pub fn hold(&mut self, call: CallHandle, now: Instant) -> Result<(), UaError> {
        self.change_hold(call, true, now)
    }

    /// Take it off hold again.
    ///
    /// Every stream goes back to the direction it had before the hold, which
    /// is not always `sendrecv`: a stream that was offered `recvonly` is
    /// resumed to `recvonly`.
    ///
    /// # Errors
    /// As [`UserAgent::hold`].
    pub fn resume(&mut self, call: CallHandle, now: Instant) -> Result<(), UaError> {
        self.change_hold(call, false, now)
    }

    /// Which way a call is held.
    #[must_use]
    pub fn hold_state(&self, call: CallHandle) -> Option<Hold> {
        self.calls.get(&call).map(|held| held.session.hold)
    }

    /// Offer a new session description inside a call.
    ///
    /// For a codec change, a media address that moved, or anything else the
    /// application decides. Hold and resume have their own calls because the
    /// description they need is derivable and writing it out by hand is how
    /// the direction attributes get wrong.
    ///
    /// # Errors
    /// As [`UserAgent::hold`], plus [`UaError::Sdp`] when the description
    /// cannot be read.
    pub fn reoffer(&mut self, call: CallHandle, sdp: &[u8], now: Instant) -> Result<(), UaError> {
        let mut description = sdp::parse(sdp).map_err(UaError::Sdp)?;
        let held = {
            let state = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            state.session.stamp(&mut description);
            state.session.hold.local
        };
        self.send_offer(call, description, held, false, now)
    }

    /// Answer a [`UaEvent::Reoffer`] the far end sent.
    ///
    /// `sdp` is the answer to the offer it carried, and is left out only for a
    /// request that carried none.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when nothing is
    /// waiting to be answered, [`UaError::Sdp`], or [`UaError::Respond`].
    pub fn accept_reoffer(
        &mut self,
        call: CallHandle,
        sdp: Option<&[u8]>,
        now: Instant,
    ) -> Result<(), UaError> {
        let (answering, contact) = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            let answering = held.answering.take().ok_or(UaError::WrongState(state))?;
            (answering, held.contact.clone())
        };
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW);
        let written = match sdp {
            Some(bytes) => {
                let parsed = sdp::parse(bytes).map_err(UaError::Sdp)?;
                response = response.body(b"application/sdp", Arc::from(bytes.to_vec()));
                Some(parsed)
            }
            None => None,
        };
        self.answer_with(call, answering.transaction, &response, now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            if let Some(offer) = answering.offer {
                held.session.set_remote(offer);
            }
            if let Some(answer) = written {
                held.session.set_local(answer);
            }
        }
        self.report_session(call);
        self.drain(now);
        Ok(())
    }

    /// Refuse one instead.
    ///
    /// §14.1: the session stands, exactly as it was. 488 is the status that
    /// says the description was the problem rather than the request.
    ///
    /// # Errors
    /// As [`UserAgent::accept_reoffer`].
    pub fn reject_reoffer(
        &mut self,
        call: CallHandle,
        status: StatusCode,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
        let state = held.state;
        let answering = held.answering.take().ok_or(UaError::WrongState(state))?;
        let mut response = OutgoingResponse::new(status);
        if status == StatusCode::NOT_ACCEPTABLE_HERE {
            response = response.header(HeaderName::Warning, WHY_488);
        }
        self.answer_with(call, answering.transaction, &response, now)?;
        self.drain(now);
        Ok(())
    }
}

// -- sending -----------------------------------------------------------------

impl UserAgent {
    fn change_hold(&mut self, call: CallHandle, held: bool, now: Instant) -> Result<(), UaError> {
        let offer = {
            let call_state = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            if call_state.session.hold.local == held {
                return Ok(());
            }
            call_state.session.offer(held).ok_or(UaError::NoSession)?
        };
        self.send_offer(call, offer, held, false, now)
    }

    fn send_offer(
        &mut self,
        call: CallHandle,
        offer: SessionDescription,
        held: bool,
        retried: bool,
        now: Instant,
    ) -> Result<(), UaError> {
        let (state, dialog, contact, allows_update) = {
            let call_state = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            if call_state.offering.is_some() || call_state.answering.is_some() {
                return Err(UaError::ChangeInProgress);
            }
            (
                call_state.state,
                call_state.dialog.ok_or(UaError::CannotRenegotiate)?,
                call_state.contact.clone(),
                call_state.update_allowed,
            )
        };
        let method = match state {
            CallState::Confirmed => Method::Invite,
            early if early.is_early() && allows_update => Method::Update,
            _ => return Err(UaError::CannotRenegotiate),
        };

        let body: Arc<[u8]> = Arc::from(offer.to_bytes());
        // §8.1.1.8 makes Contact a MUST on anything that can refresh a target,
        // and both of these can
        let request = OutgoingInDialogRequest::new(method)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW)
            .body(b"application/sdp", body);
        let transaction = if method == Method::Invite {
            AnyTransactionId::InviteClient(self.endpoint.reinvite(dialog, &request, now)?)
        } else {
            AnyTransactionId::NonInviteClient(
                self.endpoint.request_in_dialog(dialog, &request, now)?,
            )
        };

        if let Some(call_state) = self.calls.get_mut(&call) {
            call_state.offering = Some(Offer {
                transaction: Some(transaction),
                description: Some(offer),
                held,
                retried,
                refresh: false,
            });
        }
        self.by_offer.insert(transaction, call);
        self.drain(now);
        Ok(())
    }

    /// A change that was told to wait is offered again (§14.1).
    fn retry_offer(&mut self, call: CallHandle, now: Instant) {
        let Some(offer) = self
            .calls
            .get_mut(&call)
            .and_then(|held| held.offering.take())
        else {
            return;
        };
        let Some(description) = offer.description else {
            return;
        };
        if self
            .send_offer(call, description, offer.held, true, now)
            .is_err()
        {
            self.events.push_back(UaEvent::SessionChangeFailed {
                call,
                status: None,
                retry_in: None,
                response: None,
            });
        }
    }

    /// Whatever this layer scheduled for a call: the second attempt after a
    /// 491, and the session timer.
    pub(crate) fn fire_call_timers(&mut self, now: Instant) {
        self.fire_session_timers(now);
        let due: Vec<CallHandle> = self
            .calls
            .iter()
            .filter(|(_, held)| held.retry_at.is_some_and(|at| at <= now))
            .map(|(handle, _)| *handle)
            .collect();
        for call in due {
            if let Some(held) = self.calls.get_mut(&call) {
                held.retry_at = None;
            }
            self.retry_offer(call, now);
        }
    }

    /// When this layer next has something to do about a call.
    pub(crate) fn call_deadline(&self) -> Option<Instant> {
        self.calls
            .values()
            .flat_map(|held| [held.retry_at, held.timer.map(|timer| timer.due)])
            .flatten()
            .min()
    }

    fn answer_with(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        response: &OutgoingResponse,
        now: Instant,
    ) -> Result<(), UaError> {
        match transaction {
            AnyTransactionId::InviteServer(id) => {
                self.endpoint.respond_invite(id, response, now)?;
                // §13.3.1.4 wants a BYE if this one is never acknowledged
                if response.status().is_success()
                    && let Some(held) = self.calls.get_mut(&call)
                {
                    held.awaiting_ack = Some(id);
                }
            }
            AnyTransactionId::NonInviteServer(id) => {
                self.endpoint.respond(id, response, now)?;
            }
            AnyTransactionId::InviteClient(_) | AnyTransactionId::NonInviteClient(_) => {
                return Err(UaError::CannotRenegotiate);
            }
        }
        Ok(())
    }

    /// A refusal that says when to come back, with the interval drawn rather
    /// than fixed so that two peers do not repeat the collision.
    fn too_soon(&mut self, status: StatusCode) -> OutgoingResponse {
        let seconds = (spread(&self.endpoint.token()) % RETRY_AFTER_CEILING).to_string();
        OutgoingResponse::new(status).header(HeaderName::RetryAfter, seconds.as_bytes())
    }

    /// Remember that the far end can be sent an UPDATE (RFC 3311 §4).
    pub(crate) fn note_allow(&mut self, call: CallHandle, message: &RawMessage<'_>) {
        if !message.allow().any(|method| method == Method::Update) {
            return;
        }
        if let Some(held) = self.calls.get_mut(&call) {
            held.update_allowed = true;
        }
    }

    fn report_session(&mut self, call: CallHandle) {
        let Some(current) = self.calls.get(&call) else {
            return;
        };
        let hold = current.session.hold;
        let (local, remote) = current.session.described();
        self.events.push_back(UaEvent::SessionChanged {
            call,
            hold,
            local: local.map(Arc::from),
            remote: remote.map(Arc::from),
        });
    }
}

// -- what comes back ---------------------------------------------------------

impl UserAgent {
    /// `None` when the event was about a session change; the event back when
    /// it was not.
    pub(crate) fn on_session_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::ReinviteProgress { invite, .. } => {
                let id = AnyTransactionId::InviteClient(invite);
                if !self.by_offer.contains_key(&id) {
                    return Some(event);
                }
                // §14.2 lets a UAS skip provisionals to a re-INVITE, and one
                // that arrives says nothing the 2xx will not say again
                None
            }
            Event::ReinviteAnswered {
                invite,
                ref response,
                ..
            } => {
                let id = AnyTransactionId::InviteClient(invite);
                let Some(call) = self.by_offer.get(&id).copied() else {
                    return Some(event);
                };
                // this end offered, so §13.2.2.4 leaves the ACK nothing to
                // carry — but it still has to go, and go again for every
                // retransmission of the 2xx
                self.endpoint.ack_reinvite(invite, None, now).ok();
                let answer = response.as_raw().body().to_vec();
                self.on_offer_taken(call, id, &answer);
                None
            }
            Event::ReinviteFailed {
                invite,
                status,
                ref response,
                ..
            } => {
                let id = AnyTransactionId::InviteClient(invite);
                let Some(call) = self.by_offer.get(&id).copied() else {
                    return Some(event);
                };
                let response = response.clone();
                self.on_offer_refused(call, id, status, response);
                None
            }
            Event::ReinviteGlare {
                invite,
                retry_in,
                ref response,
                ..
            } => {
                let id = AnyTransactionId::InviteClient(invite);
                let Some(call) = self.by_offer.get(&id).copied() else {
                    return Some(event);
                };
                let response = response.clone();
                self.on_glare(call, id, retry_in, Some(response), now);
                None
            }
            Event::Response {
                transaction,
                status,
                ref response,
            } => {
                let id = AnyTransactionId::NonInviteClient(transaction);
                let Some(call) = self.by_offer.get(&id).copied() else {
                    return Some(event);
                };
                let response = response.clone();
                self.on_update_response(call, id, status, &response, now);
                None
            }
            Event::RequestFailed { transaction, .. } => {
                let id = AnyTransactionId::NonInviteClient(transaction);
                let Some(call) = self.by_offer.get(&id).copied() else {
                    return Some(event);
                };
                // §12.2.1.2 treats no answer as a 408, and the dialog goes
                // with it; the call layer hears that separately
                self.on_offer_refused(call, id, None, None);
                None
            }
            other => self.on_change_arriving(other, now),
        }
    }

    /// A re-INVITE or an UPDATE the far end sent.
    fn on_change_arriving(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingReinvite {
                transaction,
                dialog,
                ref request,
            } => {
                let Some(call) = self.by_dialog.get(&dialog).copied() else {
                    return Some(event);
                };
                let request = request.clone();
                self.on_offer_in(
                    call,
                    AnyTransactionId::InviteServer(transaction),
                    &request,
                    now,
                );
                None
            }
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Update) => {
                let Some(call) = self.by_dialog.get(&dialog).copied() else {
                    return Some(event);
                };
                let request = request.clone();
                self.on_offer_in(
                    call,
                    AnyTransactionId::NonInviteServer(transaction),
                    &request,
                    now,
                );
                None
            }
            other => Some(other),
        }
    }

    /// The far end took the change this end offered.
    fn on_offer_taken(&mut self, call: CallHandle, id: AnyTransactionId, answer: &[u8]) {
        self.by_offer.remove(&id);
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        let Some(offer) = held.offering.take() else {
            return;
        };
        held.retry_at = None;
        // a session-timer refresh changes nothing but the clock (RFC 4028
        // §7.4), so there is no session to commit and nothing to report
        if offer.refresh {
            return;
        }
        if let Some(description) = offer.description {
            held.session.set_local(description);
        }
        held.session.hold.local = offer.held;
        if let Ok(described) = sdp::parse(answer) {
            held.session.set_remote(described);
        }
        self.report_session(call);
    }

    /// It did not.
    ///
    /// §14.1: "the session parameters MUST remain unchanged, as if no
    /// re-INVITE had been issued".
    fn on_offer_refused(
        &mut self,
        call: CallHandle,
        id: AnyTransactionId,
        status: Option<StatusCode>,
        response: Option<OwnedMessage>,
    ) {
        self.by_offer.remove(&id);
        if let Some(held) = self.calls.get_mut(&call) {
            held.offering = None;
            held.retry_at = None;
        }
        self.events.push_back(UaEvent::SessionChangeFailed {
            call,
            status,
            retry_in: None,
            response,
        });
    }

    /// Two offers crossed (§14.2, RFC 3311 §5.2).
    fn on_glare(
        &mut self,
        call: CallHandle,
        id: AnyTransactionId,
        retry_in: Duration,
        response: Option<OwnedMessage>,
        now: Instant,
    ) {
        self.by_offer.remove(&id);
        let again = match self
            .calls
            .get_mut(&call)
            .and_then(|held| held.offering.as_mut())
        {
            Some(offer) if !offer.retried => {
                offer.transaction = None;
                true
            }
            _ => false,
        };
        if !again {
            self.on_offer_refused(call, id, Some(StatusCode::REQUEST_PENDING), response);
            return;
        }
        if let Some(held) = self.calls.get_mut(&call) {
            held.retry_at = Some(now + retry_in);
        }
        self.events.push_back(UaEvent::SessionChangeFailed {
            call,
            status: Some(StatusCode::REQUEST_PENDING),
            retry_in: Some(retry_in),
            response,
        });
    }

    /// The answer to an UPDATE this end sent (RFC 3311 §5.3).
    fn on_update_response(
        &mut self,
        call: CallHandle,
        id: AnyTransactionId,
        status: StatusCode,
        response: &OwnedMessage,
        now: Instant,
    ) {
        if status.is_provisional() {
            return;
        }
        if status.is_success() {
            self.on_offer_taken(call, id, response.as_raw().body());
            return;
        }
        if status == StatusCode::REQUEST_PENDING {
            // §5.3 repeats §14.1's timer for UPDATE, ranges included, and the
            // end that generated the Call-ID is the end that placed the call
            let owner = self
                .calls
                .get(&call)
                .is_some_and(|held| held.direction == Direction::Outgoing);
            let retry_in = glare_backoff(owner, &self.endpoint.token());
            self.on_glare(call, id, retry_in, Some(response.clone()), now);
            return;
        }
        self.on_offer_refused(call, id, Some(status), Some(response.clone()));
    }

    /// A request the far end sent to change the session.
    fn on_offer_in(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let raw = request.as_raw();
        self.note_allow(call, &raw);
        // RFC 4028 §7.4: any request inside the dialog that carries a
        // Session-Expires is a refresh, whatever else it is doing
        self.on_refresh_in(call, &raw, now);
        let arriving = arriving(&raw);
        let invite = matches!(transaction, AnyTransactionId::InviteServer(_));

        // an UPDATE with no description only refreshes the target: there is
        // nothing to answer, and nothing it could collide with
        if matches!(arriving, Arriving::Nothing) && !invite {
            self.acknowledge_only(call, transaction, now);
            return;
        }

        // RFC 3311 §5.2, generalised to both requests: an offer that crossed
        // one of ours earns a 491, and one that arrives while an earlier offer
        // of theirs is still unanswered earns a 500 saying when to come back.
        // A re-INVITE with no description is not exempt — §14.1 has it ask
        // *this* end to offer, which is the same exchange starting over
        if self
            .calls
            .get(&call)
            .is_some_and(|held| held.offering.is_some())
        {
            let pending = OutgoingResponse::new(StatusCode::REQUEST_PENDING);
            self.answer_with(call, transaction, &pending, now).ok();
            return;
        }
        if self
            .calls
            .get(&call)
            .is_some_and(|held| held.answering.is_some())
        {
            let busy = self.too_soon(StatusCode::SERVER_ERROR);
            self.answer_with(call, transaction, &busy, now).ok();
            return;
        }

        match arriving {
            Arriving::Nothing => self.offer_in_answer(call, transaction, now),
            // a body that says it is a session description and is not one
            Arriving::Unreadable => {
                let refusal = OutgoingResponse::new(StatusCode::NOT_ACCEPTABLE_HERE)
                    .header(HeaderName::Warning, WHY_488);
                self.answer_with(call, transaction, &refusal, now).ok();
            }
            Arriving::Foreign => self.hand_over(call, transaction, None, request),
            Arriving::Offer(offer) => {
                if !self.take_offer(call, transaction, &offer, now) {
                    self.hand_over(call, transaction, Some(*offer), request);
                }
            }
        }
    }

    /// A change the far end offered will not be answered after all, because
    /// the dialog it was in has ended.
    ///
    /// §15.1.2: "The UAS MUST still respond to any pending requests received
    /// for that dialog. It is RECOMMENDED that a 487 (Request Terminated)
    /// response be generated to those pending requests." Left alone, that
    /// transaction is retransmitted at the far end until it gives up.
    pub(crate) fn abandon_change(&mut self, call: CallHandle, now: Instant) {
        let Some(answering) = self
            .calls
            .get_mut(&call)
            .and_then(|held| held.answering.take())
        else {
            return;
        };
        let gone = OutgoingResponse::new(StatusCode::REQUEST_TERMINATED);
        self.answer_with(call, answering.transaction, &gone, now)
            .ok();
    }

    /// Answer an offer that changes nothing this layer would have to ask
    /// about. `false` when it is not one, or cannot be answered from here.
    fn take_offer(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        offer: &SessionDescription,
        now: Instant,
    ) -> bool {
        let prepared = {
            let Some(held) = self.calls.get_mut(&call) else {
                return false;
            };
            if !held.session.is_same_media(offer) {
                return false;
            }
            let wanted = held.session.hold.local;
            let Some(answer) = held.session.answer(offer, wanted) else {
                return false;
            };
            (answer, held.contact.clone())
        };
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&prepared.1)
            .header(HeaderName::Allow, ALLOW)
            .body(b"application/sdp", Arc::from(prepared.0.to_bytes()));
        if let Some(value) = self.timer_echo(call) {
            response = response.header(HeaderName::SessionExpires, &value);
        }
        if self.answer_with(call, transaction, &response, now).is_err() {
            return false;
        }
        if let Some(held) = self.calls.get_mut(&call) {
            held.session.set_remote(offer.clone());
            held.session.set_local(prepared.0);
        }
        self.report_session(call);
        true
    }

    /// Answer a re-INVITE that carried no offer with one of our own (§14.1).
    fn offer_in_answer(&mut self, call: CallHandle, transaction: AnyTransactionId, now: Instant) {
        let prepared = {
            let Some(held) = self.calls.get_mut(&call) else {
                return;
            };
            let wanted = held.session.hold.local;
            (held.session.offer(wanted), held.contact.clone())
        };
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&prepared.1)
            .header(HeaderName::Allow, ALLOW);
        if let Some(value) = self.timer_echo(call) {
            response = response.header(HeaderName::SessionExpires, &value);
        }
        if let Some(ref description) = prepared.0 {
            response = response.body(b"application/sdp", Arc::from(description.to_bytes()));
        }
        if self.answer_with(call, transaction, &response, now).is_err() {
            return;
        }
        if let (Some(held), Some(description)) = (self.calls.get_mut(&call), prepared.0) {
            held.session.set_local(description);
            held.session.answer_owed = true;
        }
    }

    /// Answer a request that only refreshed the target.
    fn acknowledge_only(&mut self, call: CallHandle, transaction: AnyTransactionId, now: Instant) {
        let contact = self
            .calls
            .get(&call)
            .map(|held| held.contact.clone())
            .unwrap_or_default();
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW);
        if let Some(value) = self.timer_echo(call) {
            response = response.header(HeaderName::SessionExpires, &value);
        }
        self.answer_with(call, transaction, &response, now).ok();
    }

    /// Hand a change to the application, keeping the transaction open for it.
    fn hand_over(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        offer: Option<SessionDescription>,
        request: &OwnedMessage,
    ) {
        if let Some(held) = self.calls.get_mut(&call) {
            held.answering = Some(Answering { transaction, offer });
        }
        self.events.push_back(UaEvent::Reoffer {
            call,
            request: request.clone(),
        });
    }

    /// The ACK for a 2xx this end answered with an offer.
    pub(crate) fn on_ack(&mut self, call: CallHandle, request: &OwnedMessage) {
        let body = request.as_raw().body();
        if body.is_empty() {
            return;
        }
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        if !held.session.answer_owed {
            return;
        }
        // owed either way: an answer that cannot be read is not going to
        // arrive a second time, and leaving the flag set would have the next
        // ACK on this dialog read as one
        held.session.answer_owed = false;
        let Ok(answer) = sdp::parse(body) else {
            return;
        };
        held.session.set_remote(answer);
        self.report_session(call);
    }
}

/// What a request that could change the session actually carried.
enum Arriving {
    /// No body at all.
    Nothing,
    /// A session description, boxed because it dwarfs the other three.
    Offer(Box<SessionDescription>),
    /// Bytes that claim to be one and are not.
    Unreadable,
    /// A body of some other type, which is the application's to read.
    Foreign,
}

fn arriving(request: &RawMessage<'_>) -> Arriving {
    let body = request.body();
    if body.is_empty() {
        return Arriving::Nothing;
    }
    match request.content_type() {
        Ok(kind) if kind.is("application", "sdp") => sdp::parse(body)
            .map_or(Arriving::Unreadable, |offer| {
                Arriving::Offer(Box::new(offer))
            }),
        _ => Arriving::Foreign,
    }
}

/// How long to wait before offering the same change again (§14.1, RFC 3311
/// §5.3).
///
/// The two ranges do not overlap, which is the whole point: if both ends drew
/// from the same one they would collide again as often as they did the first
/// time. Which one applies is decided by who generated the `Call-ID`, and that
/// is whoever placed the call.
fn glare_backoff(owner: bool, entropy: &[u8]) -> Duration {
    let (low, high) = if owner { OWNER_BACKOFF } else { GUEST_BACKOFF };
    let steps = (high - low) / BACKOFF_STEP + 1;
    Duration::from_millis(low + (u64::from(spread(entropy)) % steps) * BACKOFF_STEP)
}
