// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Placing calls, answering them, and ending them from either side.
//!
//! The core reports what happened and decides nothing. Here the decisions get
//! made, and there are three worth naming.
//!
//! **The ACK is sent, not offered.** §13.2.2.4 leaves the ACK for a 2xx to the
//! layer above because it may have to carry an answer, and the core keeps that
//! open. A user agent closes it: a 2xx that is not acknowledged is
//! retransmitted for thirty-two seconds and then hung up by the far end, which
//! is not a decision worth handing to an application. The one case that has to
//! wait is a call placed with no offer, where the answer travels in the ACK
//! and only the application has one.
//!
//! **A fork is not hidden.** One INVITE, three phones ringing, three early
//! dialogs, and every 2xx among them has to be acknowledged whether it is
//! wanted or not. So each branch becomes a call of its own, and
//! [`ForkPolicy`] says what happens to the ones that are not kept — hang them
//! up, or hand them all over.
//!
//! **Hanging up means different things at different moments.** Before the
//! INVITE is answered it is a CANCEL, after it is a BYE, and on a call that
//! has come in and not been answered it is a refusal. One call does all three,
//! because an application that has to know which is an application that will
//! get it wrong during the second it matters.

use std::sync::Arc;
use std::time::Instant;

use sipral_core::dialog::CallId;
use sipral_core::endpoint::{
    DialogEndReason, Event, FailureReason, OutgoingRequest, OutgoingResponse, TerminationReason,
};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, RawMessage, StatusCode, Uri};
use sipral_core::sdp;
use sipral_core::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, TransactionId,
};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::call::{
    Call, CallEndReason, CallHandle, CallState, Direction, ForkPolicy, OutgoingCall,
};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::renegotiate::ALLOW;
use crate::timers::FLOOR;

/// The refusal a call gets when it is hung up before it was answered.
///
/// §21.4.6: "the callee's end system was contacted successfully but the callee
/// is currently not willing or able to take additional calls".
const NOT_NOW: StatusCode = StatusCode::BUSY_HERE;

// -- what the application asks for -------------------------------------------

impl UserAgent {
    /// Place a call.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], or [`UaError::Send`] when the INVITE cannot
    /// be built or its transport is unknown.
    pub fn call(
        &mut self,
        account: AccountId,
        outgoing: &OutgoingCall,
        now: Instant,
    ) -> Result<CallHandle, UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        let contact = config.contact_value();
        let asked = config.session_interval;
        let mut call = Call::outgoing(account, outgoing.forks, contact);
        // minted here rather than by the endpoint, because §7.3 has a 422
        // asked again on the same Call-ID with the number moved on
        call.id = Some(CallId::new(&self.endpoint.token()));
        call.placed = Some(outgoing.clone());
        call.asked = asked;
        if let Some(described) = outgoing
            .offer
            .as_deref()
            .and_then(|sdp| sdp::parse(sdp).ok())
        {
            call.session.set_local(described);
        }
        let handle = self.keep(call);
        self.dial(account, outgoing, handle, now)?;
        self.drain(now);
        Ok(handle)
    }

    /// Put the INVITE on the wire for a call that already has a handle.
    ///
    /// Called again, with a higher number and the same `Call-ID`, when a 422
    /// says the session interval was too short (RFC 4028 §7.3).
    pub(crate) fn dial(
        &mut self,
        account: AccountId,
        outgoing: &OutgoingCall,
        call: CallHandle,
        now: Instant,
    ) -> Result<(), UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        let (transport, remote) = outgoing
            .destination
            .unwrap_or((config.transport, config.remote));
        let contact = config.contact_value();
        let from = config.sender_value();
        let (call_id, cseq, asked) = {
            let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            (held.id.clone(), held.cseq, held.asked)
        };
        let mut request =
            OutgoingRequest::new(Method::Invite, outgoing.target.clone(), transport, remote)
                .to(&bracketed(&outgoing.target))
                .from(&from)
                .contact(&contact)
                // RFC 3311 §4: "a UAC compliant to this specification SHOULD
                // also include an Allow header field in the INVITE request,
                // listing the method UPDATE"
                .header(HeaderName::Allow, ALLOW)
                .cseq(cseq);
        if let Some(call_id) = call_id {
            request = request.call_id(call_id);
        }
        for (name, value) in &self.asking_for(call, asked) {
            request = request.header(*name, value);
        }
        if let Some(ref offer) = outgoing.offer {
            request = request.body(b"application/sdp", Arc::clone(offer));
        }
        for extra in &outgoing.extra {
            if let Some(name) = HeaderName::from_bytes(&extra.name) {
                request = request.header(name, &extra.value);
            }
        }

        let invite = self.endpoint.invite(&request, now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.invite = Some(invite);
        }
        self.by_invite.insert(invite, call);
        Ok(())
    }

    /// Say the phone is ringing (180), optionally with early media (183).
    ///
    /// A body makes it a 183 Session Progress, because 180 Ringing with a
    /// session description is a contradiction the far end has to guess at.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] for a call this end
    /// placed or has already answered, or [`UaError::Respond`].
    pub fn ring(
        &mut self,
        call: CallHandle,
        early: Option<Arc<[u8]>>,
        now: Instant,
    ) -> Result<(), UaError> {
        let transaction = self.answerable(call)?;
        let status = if early.is_some() {
            StatusCode::SESSION_PROGRESS
        } else {
            StatusCode::RINGING
        };
        let contact = self.contact_of(call)?;
        let mut response = OutgoingResponse::new(status)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW);
        let described = early.as_deref().and_then(|sdp| sdp::parse(sdp).ok());
        if let Some(sdp) = early {
            response = response.body(b"application/sdp", sdp);
        }
        // RFC 3262 §3: reliably when the INVITE said so, and never otherwise
        let carries_sdp = described.is_some();
        let dialog = if self.reliably(call) {
            let provisional = self
                .endpoint
                .respond_reliable(transaction, &response, now)?;
            self.watch_provisional(call, provisional, carries_sdp);
            Some(provisional.dialog())
        } else {
            self.endpoint.respond_invite(transaction, &response, now)?
        };
        if let Some(held) = self.calls.get_mut(&call) {
            held.state = if status == StatusCode::RINGING {
                CallState::Ringing
            } else {
                CallState::EarlyMedia
            };
            held.dialog = dialog;
            if let Some(described) = described {
                held.session.set_local(described);
            }
        }
        if let Some(dialog) = dialog {
            self.by_dialog.insert(dialog, call);
        }
        self.drain(now);
        Ok(())
    }

    /// Answer a call that came in.
    ///
    /// The body is the answer when the INVITE carried an offer, and an offer
    /// of its own when it did not — in which case the far end's answer arrives
    /// in the ACK, as [`UaEvent::CallConfirmed`].
    ///
    /// # Errors
    /// As [`UserAgent::ring`].
    pub fn answer(
        &mut self,
        call: CallHandle,
        sdp: Option<Arc<[u8]>>,
        now: Instant,
    ) -> Result<(), UaError> {
        // RFC 3262 §5: a reliable provisional that carried a description holds
        // the 2xx until it is acknowledged, or two unanswered offers are on the
        // wire at once and nothing says which the answer belongs to
        if self.answer_is_held(call) {
            self.hold_answer(call, sdp);
            return Ok(());
        }
        let transaction = self.answerable(call)?;
        let contact = self.contact_of(call)?;
        // RFC 3311 §4: "a 2xx response SHOULD contain an Allow header field
        // listing the UPDATE method"
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW)
            .header(HeaderName::Supported, b"timer");
        let invited = self.calls.get(&call).and_then(|held| held.invited.clone());
        if let Some(ref invited) = invited
            && let Some((value, demand)) = self.timer_for_answer(call, &invited.as_raw(), now)
        {
            response = response.header(HeaderName::SessionExpires, &value);
            if demand {
                // §9: refresher=uac obliges the UAS to say the far end has to
                // understand this, because it is the one that has to act
                response = response.header(HeaderName::Require, b"timer");
            }
        }
        let described = sdp.as_deref().and_then(|sdp| sdp::parse(sdp).ok());
        if let Some(sdp) = sdp {
            response = response.body(b"application/sdp", sdp);
        }
        let dialog = self.endpoint.respond_invite(transaction, &response, now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.dialog = dialog;
            // §12.1.1 confirms the dialog here, but the call is not up until
            // the ACK arrives; until then the 2xx is still being retransmitted
            held.state = CallState::Ringing;
            // and §13.3.1.4 wants a BYE if it never is
            held.awaiting_ack = Some(transaction);
            if let Some(described) = described {
                // an INVITE that carried nothing is answered with an offer,
                // and §13.2.2.4 puts the answer to it in the ACK
                held.session.answer_owed = !held.session.has_remote();
                held.session.set_local(described);
            }
        }
        if let Some(dialog) = dialog {
            self.by_dialog.insert(dialog, call);
        }
        // §3891 §3: "it accepts the new INVITE by sending a 200-class
        // response, and shuts down the replaced dialog"
        self.shut_down_replaced(call, now);
        self.drain(now);
        Ok(())
    }

    /// Refuse a call that came in, with a status of your choosing.
    ///
    /// # Errors
    /// As [`UserAgent::ring`].
    pub fn reject(
        &mut self,
        call: CallHandle,
        status: StatusCode,
        now: Instant,
    ) -> Result<(), UaError> {
        let transaction = self.answerable(call)?;
        self.endpoint
            .respond_invite(transaction, &OutgoingResponse::new(status), now)?;
        self.finish(call, CallEndReason::LocalHangup, Some(status), None, now);
        self.drain(now);
        Ok(())
    }

    /// Answer an offer that arrived in a reliable provisional response.
    ///
    /// RFC 3262 §5: "If the UAC receives an offer in a reliable provisional
    /// response, it MUST generate an answer in the PRACK." Only for a call
    /// placed without an offer, which is the one case a provisional carries
    /// one, and reported by `answer_wanted` on
    /// [`UaEvent::CallProgress`](crate::UaEvent::CallProgress).
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when nothing is
    /// waiting for one, or [`UaError::Sdp`].
    pub fn answer_early(
        &mut self,
        call: CallHandle,
        sdp: &[u8],
        now: Instant,
    ) -> Result<(), UaError> {
        let described = sdp::parse(sdp).map_err(UaError::Sdp)?;
        let (provisional, state) = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            (
                held.owed_prack.take().ok_or(UaError::WrongState(state))?,
                state,
            )
        };
        let _ = state;
        let prack = self
            .endpoint
            .prack(provisional, Some(Arc::from(sdp.to_vec())), now)
            .map_err(|_| UaError::WrongState(state))?;
        self.by_request
            .insert(AnyTransactionId::NonInviteClient(prack), call);
        if let Some(held) = self.calls.get_mut(&call) {
            held.session.set_local(described);
        }
        self.drain(now);
        Ok(())
    }

    /// Acknowledge a 2xx whose offer is still waiting for an answer.
    ///
    /// Only for a call placed without an offer, which is the one case the ACK
    /// is not sent automatically: the offer arrived in the 2xx and the answer
    /// has nowhere else to travel (§13.2.2.4).
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when the call is not
    /// waiting for one, or [`UaError::Ack`].
    pub fn acknowledge(
        &mut self,
        call: CallHandle,
        answer: Option<&[u8]>,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
        let state = held.state;
        if held.acknowledged {
            return Err(UaError::WrongState(state));
        }
        let dialog = held.dialog.ok_or(UaError::WrongState(state))?;
        self.endpoint.ack_2xx(dialog, answer, now)?;
        let described = answer.and_then(|sdp| sdp::parse(sdp).ok());
        if let Some(held) = self.calls.get_mut(&call) {
            held.acknowledged = true;
            if let Some(described) = described {
                held.session.set_local(described);
            }
        }
        self.drain(now);
        Ok(())
    }

    /// End a call, whatever it is doing.
    ///
    /// A CANCEL while the INVITE this end sent is unanswered (§9.1, held by the
    /// endpoint until the first provisional response if it has to be), a BYE
    /// once the call is up, and a refusal for one that came in and has not
    /// been answered. A call that is already ending is left alone.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], or the error of whatever it turned into.
    pub fn hangup(&mut self, call: CallHandle, now: Instant) -> Result<(), UaError> {
        let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
        let (state, direction, invite, dialog, server) = (
            held.state,
            held.direction,
            held.invite,
            held.dialog,
            held.server,
        );

        match state {
            CallState::Terminating | CallState::Terminated => Ok(()),
            CallState::Incoming | CallState::Ringing | CallState::EarlyMedia
                if direction == Direction::Incoming =>
            {
                let _ = server;
                self.reject(call, NOT_NOW, now)
            }
            CallState::Confirmed => {
                let dialog = dialog.ok_or(UaError::WrongState(state))?;
                let bye = self.endpoint.bye(dialog, now)?;
                self.by_request
                    .insert(AnyTransactionId::NonInviteClient(bye), call);
                self.mark(call, CallState::Terminating);
                self.drain(now);
                Ok(())
            }
            _ => {
                let invite = invite.ok_or(UaError::WrongState(state))?;
                // §9.1: a CANCEL may not go before a provisional response has
                // arrived, and the endpoint holds it until one does. Asking
                // too early is not a failure and needs no timer here
                self.endpoint.cancel(invite, now).ok();
                if let Some(held) = self.calls.get_mut(&call) {
                    held.hangup_wanted = true;
                    held.state = CallState::Terminating;
                }
                self.drain(now);
                Ok(())
            }
        }
    }

    /// Where a call is.
    #[must_use]
    pub fn call_state(&self, call: CallHandle) -> Option<CallState> {
        self.calls.get(&call).map(|held| held.state)
    }

    /// The dialog a call is in, once there is one.
    #[must_use]
    pub fn call_dialog(&self, call: CallHandle) -> Option<DialogId> {
        self.calls.get(&call).and_then(|held| held.dialog)
    }
}

// -- bookkeeping -------------------------------------------------------------

impl UserAgent {
    fn keep(&mut self, call: Call) -> CallHandle {
        let handle = CallHandle(self.next_call);
        self.next_call = self.next_call.wrapping_add(1);
        self.calls.insert(handle, call);
        handle
    }

    /// The server transaction of a call that can still be answered.
    fn answerable(
        &self,
        call: CallHandle,
    ) -> Result<TransactionId<sipral_core::transaction::InviteServer>, UaError> {
        let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
        held.server.ok_or(UaError::WrongState(held.state))
    }

    fn contact_of(&self, call: CallHandle) -> Result<Box<[u8]>, UaError> {
        self.calls
            .get(&call)
            .map(|held| held.contact.clone())
            .ok_or(UaError::NoSuchCall)
    }

    fn mark(&mut self, call: CallHandle, state: CallState) {
        if let Some(held) = self.calls.get_mut(&call) {
            held.state = state;
        }
    }

    /// The call is over: say so once, and let the handle go stale.
    fn finish(
        &mut self,
        call: CallHandle,
        reason: CallEndReason,
        status: Option<StatusCode>,
        response: Option<OwnedMessage>,
        now: Instant,
    ) {
        if self
            .calls
            .get(&call)
            .is_none_or(|held| held.state == CallState::Terminated)
        {
            return;
        }
        // §15.1.2: a request of theirs that is still waiting for an answer
        // gets one before the dialog goes, or it is retransmitted at the far
        // end until it gives up
        self.abandon_change(call, now);
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        held.state = CallState::Terminated;
        self.events.push_back(UaEvent::CallEnded {
            call,
            reason,
            status,
            response,
        });
        self.forget(call);
    }

    /// The session timer ran out and nobody refreshed it (RFC 4028 §10).
    pub(crate) fn finish_expired(&mut self, call: CallHandle, now: Instant) {
        self.finish(call, CallEndReason::Expired, None, None, now);
    }

    fn forget(&mut self, call: CallHandle) {
        self.by_invite.retain(|_, held| *held != call);
        self.by_server.retain(|_, held| *held != call);
        self.by_dialog.retain(|_, held| *held != call);
        self.by_request.retain(|_, held| *held != call);
        self.by_offer.retain(|_, held| *held != call);
        self.calls.remove(&call);
    }

    /// The account an incoming INVITE was addressed to, when it can be told.
    ///
    /// The Request-URI is where the registrar sent it, so it is this end's
    /// contact; the `To` is the address of record. Either identifies a line.
    /// Neither matching is not a reason to refuse the call — a misrouted INVITE
    /// that vanishes silently is worse than one the application can see.
    fn line_for(&self, request: &RawMessage<'_>) -> Option<AccountId> {
        let target = request
            .request_uri_bytes()
            .and_then(|bytes| Uri::parse(bytes).ok());
        let record = request
            .to()
            .ok()
            .and_then(|to| Uri::parse(to.uri_bytes()).ok());
        self.accounts
            .iter()
            .find(|(_, config)| {
                target
                    .as_ref()
                    .is_some_and(|uri| config.contact.equivalent(uri))
                    || record
                        .as_ref()
                        .is_some_and(|uri| config.aor.equivalent(uri))
            })
            .map(|(id, _)| *id)
    }
}

/// `<uri>`, which is how a URI goes into `To` without its parameters being
/// read as the header field's.
fn bracketed(uri: &Uri) -> Box<[u8]> {
    let mut out = Vec::with_capacity(uri.as_bytes().len() + 2);
    out.push(b'<');
    out.extend_from_slice(uri.as_bytes());
    out.push(b'>');
    out.into_boxed_slice()
}

// -- what comes back ---------------------------------------------------------

impl UserAgent {
    /// `None` when the event belonged to a call; the event back when it did
    /// not.
    pub(crate) fn on_call_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::Provisional {
                invite,
                dialog,
                status,
                ref response,
            } => {
                let call = self.branch(invite, dialog)?;
                self.on_progress(call, status, response, false, now);
                None
            }
            Event::ReliableProvisional {
                invite,
                dialog,
                provisional,
                status,
                ref response,
            } => {
                let call = self.branch(invite, Some(dialog))?;
                let response = response.clone();
                self.on_reliable_progress(call, provisional, status, &response, now);
                None
            }
            Event::Established {
                invite,
                dialog,
                ref response,
                ..
            } => {
                let call = self.branch(invite, Some(dialog))?;
                self.on_answered(call, dialog, response, now);
                None
            }
            Event::Failed {
                invite,
                status,
                reason,
                ref response,
            } => {
                // RFC 4028 §7.3: a 422 says the session interval was too
                // short, not that the call cannot happen
                if status.map(StatusCode::get) == Some(422)
                    && let Some(call) = self.by_invite.get(&invite).copied()
                    && let Some(refusal) = response.as_ref()
                {
                    let refusal = refusal.clone();
                    if self.on_session_too_brief(call, &refusal.as_raw(), now) {
                        return None;
                    }
                }
                let ended = match reason {
                    FailureReason::Refused => CallEndReason::Refused,
                    // the enum is non-exhaustive across crate versions, and
                    // anything new is still a call that did not connect
                    _ => CallEndReason::Unreachable,
                };
                self.end_branches(invite, ended, status, response.as_ref(), now)
            }
            Event::Cancelled { invite } => {
                self.end_branches(invite, CallEndReason::Cancelled, None, None, now)
            }
            Event::CancelSent { invite, cancel } => {
                let call = self.by_invite.get(&invite).copied()?;
                self.by_request
                    .insert(AnyTransactionId::NonInviteClient(cancel), call);
                self.mark(call, CallState::Terminating);
                None
            }
            Event::CancelLostRace { invite, dialog } => {
                self.on_cancel_lost(invite, dialog, now);
                None
            }
            Event::IncomingInvite { .. }
            | Event::IncomingCancel { .. }
            | Event::IncomingAck { .. }
            | Event::IncomingBye { .. } => self.on_incoming(event, now),
            Event::DialogTerminated { dialog, reason } => self.on_dialog_over(dialog, reason, now),
            Event::Challenged { transaction, .. } => {
                let AnyTransactionId::InviteClient(invite) = transaction else {
                    return Some(event);
                };
                let call = self.by_invite.get(&invite).copied()?;
                self.on_call_challenged(call, transaction, now);
                None
            }
            Event::Response { transaction, .. } | Event::RequestFailed { transaction, .. } => {
                // a BYE, a CANCEL or a PRACK this layer sent. Its answer
                // changes nothing the application has not already been told.
                // Anything else is not ours, and goes on
                let id = AnyTransactionId::NonInviteClient(transaction);
                if !self.by_request.contains_key(&id) {
                    return Some(event);
                }
                None
            }
            Event::TransactionTerminated {
                transaction,
                reason,
            } => {
                self.on_transaction_over(transaction, reason, now);
                None
            }
            other => Some(other),
        }
    }

    /// A dialog has ended, and with it the call that was in it.
    fn on_dialog_over(
        &mut self,
        dialog: DialogId,
        reason: DialogEndReason,
        now: Instant,
    ) -> Option<Event> {
        let call = self.by_dialog.get(&dialog).copied()?;
        // a refusal reported by the dialog layer is the same refusal the
        // INVITE transaction is about to report, and that one knows whether
        // the 487 was one we asked for. Wait for it rather than answer first
        // and answer worse
        if reason == DialogEndReason::Refused && self.still_calling(call) {
            self.by_dialog.remove(&dialog);
            if let Some(held) = self.calls.get_mut(&call) {
                held.dialog = None;
            }
            return None;
        }
        self.finish(call, ended_by(reason), None, None, now);
        None
    }

    /// A provisional response the far end will retransmit until it is
    /// acknowledged (RFC 3262 §4).
    fn on_reliable_progress(
        &mut self,
        call: CallHandle,
        provisional: sipral_core::transaction::ProvisionalResponseId,
        status: StatusCode,
        response: &OwnedMessage,
        now: Instant,
    ) {
        // §5: an offer here is answered in the PRACK, and only the application
        // has an answer. Everything else is acknowledged at once, because §4
        // makes that a MUST and a response nobody acknowledges is retransmitted
        // until the INVITE is abandoned
        let offered = !response.as_raw().body().is_empty()
            && self
                .calls
                .get(&call)
                .is_some_and(|held| !held.session.has_local());
        self.on_progress(call, status, response, offered, now);
        if offered {
            if let Some(held) = self.calls.get_mut(&call) {
                held.owed_prack = Some(provisional);
            }
        } else if let Ok(prack) = self.endpoint.prack(provisional, None, now) {
            self.by_request
                .insert(AnyTransactionId::NonInviteClient(prack), call);
        }
    }

    /// The CANCEL lost its race and the call connected anyway.
    ///
    /// §13.2.2.4 still wants the ACK — a 2xx is acknowledged whether or not it
    /// is wanted — and only then can the call be hung up.
    fn on_cancel_lost(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
        now: Instant,
    ) {
        let Some(call) = self.branch(invite, Some(dialog)) else {
            return;
        };
        self.endpoint.ack_2xx(dialog, None, now).ok();
        if let Some(held) = self.calls.get_mut(&call) {
            held.acknowledged = true;
            held.state = CallState::Confirmed;
        }
        self.hangup(call, now).ok();
    }

    /// A request the far end sent inside a call, or one that starts one.
    fn on_incoming(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingInvite {
                transaction,
                ref request,
            } => {
                // RFC 4028 §9: an interval below the floor is refused with the
                // floor, and the far end asks again. There is no policy in it,
                // so the application is not troubled with it
                // §8.2.2.3: a Require this agent cannot honour is refused
                // before anything else looks at the request
                let missing = crate::reliable::unsupported(&request.as_raw());
                if !missing.is_empty() {
                    self.refuse_extension(transaction, &missing, now);
                    return None;
                }
                // RFC 3891 §3: a Replaces names one of this end's own calls,
                // and every way it can fail to is a different status code
                let replaced = match self.replaced_by(&request.as_raw()) {
                    Ok(replaced) => replaced,
                    Err(status) => {
                        self.refuse_replaces(transaction, status, now);
                        return None;
                    }
                };
                if Self::too_brief(&request.as_raw()) {
                    let refusal = OutgoingResponse::new(StatusCode::SESSION_INTERVAL_TOO_SMALL)
                        .header(HeaderName::MinSe, &crate::timers::seconds(FLOOR));
                    self.endpoint
                        .respond_invite(transaction, &refusal, now)
                        .ok();
                    return None;
                }
                let account = self.line_for(&request.as_raw());
                let contact = account.and_then(|id| self.accounts.get(&id)).map_or_else(
                    || Box::from(&b""[..]),
                    crate::account::Account::contact_value,
                );
                let call = self.keep(Call::incoming(account, transaction, contact));
                if let Some(held) = self.calls.get_mut(&call) {
                    held.invited = Some(request.clone());
                    held.replaces = replaced;
                }
                self.by_server.insert(transaction, call);
                self.note_allow(call, &request.as_raw());
                if let Some(offer) = sdp::parse(request.as_raw().body()).ok()
                    && let Some(held) = self.calls.get_mut(&call)
                {
                    held.session.set_remote(offer);
                }
                self.events.push_back(UaEvent::IncomingCall {
                    call,
                    account,
                    request: request.clone(),
                });
                None
            }
            Event::IncomingCancel { invite } => {
                let call = self.by_server.get(&invite).copied()?;
                // the endpoint has already sent the 200 and the 487; §9.2
                // makes both unconditional, and what is left is to stop ringing
                self.finish(call, CallEndReason::Cancelled, None, None, now);
                None
            }
            Event::IncomingAck {
                dialog,
                ref request,
            } => {
                let call = self.by_dialog.get(&dialog).copied()?;
                // a re-INVITE is acknowledged here too, and a call is only
                // confirmed once
                let first = self.calls.get(&call).is_some_and(|held| !held.acknowledged);
                if let Some(held) = self.calls.get_mut(&call) {
                    held.state = CallState::Confirmed;
                    held.acknowledged = true;
                    held.awaiting_ack = None;
                }
                if first {
                    self.events.push_back(UaEvent::CallConfirmed {
                        call,
                        response: None,
                        answer_wanted: false,
                    });
                }
                // the answer to an offer this end put in a 2xx travels here
                let request = request.clone();
                self.on_ack(call, &request);
                None
            }
            Event::IncomingBye {
                transaction,
                dialog,
            } => {
                let call = self.by_dialog.get(&dialog).copied()?;
                // §15.1.2: the dialog is over, and answering it 200 is the only
                // thing left. There is nothing to decide, so nothing is asked
                self.endpoint
                    .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
                    .ok();
                self.finish(call, CallEndReason::RemoteHangup, None, None, now);
                None
            }
            other => Some(other),
        }
    }

    /// The call a response on this INVITE belongs to, minting a sibling when
    /// the dialog it names is a second one.
    ///
    /// §13.2.2: one INVITE can open several dialogs, and each of them is a
    /// call in its own right — every 2xx among them has to be acknowledged
    /// whether or not it is wanted.
    fn branch(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: Option<DialogId>,
    ) -> Option<CallHandle> {
        let call = self.by_invite.get(&invite).copied()?;
        let Some(dialog) = dialog else {
            // a 100, or a provisional with no tag to name a dialog by
            return Some(call);
        };
        if let Some(known) = self.by_dialog.get(&dialog) {
            return Some(*known);
        }
        let held = self.calls.get(&call)?;
        if held.dialog.is_none() {
            if let Some(held) = self.calls.get_mut(&call) {
                held.dialog = Some(dialog);
            }
            self.by_dialog.insert(dialog, call);
            return Some(call);
        }

        let mut sibling = Call::sibling_of(held, call);
        sibling.dialog = Some(dialog);
        let handle = self.keep(sibling);
        self.by_dialog.insert(dialog, handle);
        self.events.push_back(UaEvent::CallForked {
            call,
            sibling: handle,
        });
        Some(handle)
    }

    /// What a response the far end sent says about the session and about what
    /// the far end can be asked to do.
    fn note_session(&mut self, call: CallHandle, response: &OwnedMessage) {
        let raw = response.as_raw();
        self.note_allow(call, &raw);
        if let Ok(described) = sdp::parse(raw.body())
            && let Some(held) = self.calls.get_mut(&call)
        {
            held.session.set_remote(described);
        }
    }

    /// Whether the INVITE that would open this call is still running.
    fn still_calling(&self, call: CallHandle) -> bool {
        self.calls.get(&call).is_some_and(|held| {
            !held.state.is_confirmed()
                && held
                    .invite
                    .is_some_and(|invite| self.by_invite.contains_key(&invite))
        })
    }

    /// End every branch of one INVITE.
    ///
    /// A refusal names the transaction, not a dialog, and one transaction can
    /// have opened several: a proxy that forked to three phones and then gave
    /// up has refused all three.
    fn end_branches(
        &mut self,
        invite: TransactionId<InviteClient>,
        reason: CallEndReason,
        status: Option<StatusCode>,
        response: Option<&OwnedMessage>,
        now: Instant,
    ) -> Option<Event> {
        let branches: Vec<CallHandle> = self
            .calls
            .iter()
            .filter(|(_, held)| held.invite == Some(invite))
            .map(|(handle, _)| *handle)
            .collect();
        for call in branches {
            self.finish(call, reason, status, response.cloned(), now);
        }
        None
    }

    fn on_progress(
        &mut self,
        call: CallHandle,
        status: StatusCode,
        response: &OwnedMessage,
        answer_wanted: bool,
        now: Instant,
    ) {
        self.note_session(call, response);
        let early = !response.as_raw().body().is_empty();
        let state = if early {
            CallState::EarlyMedia
        } else if status.get() >= 180 {
            CallState::Ringing
        } else {
            CallState::Calling
        };
        if let Some(held) = self.calls.get_mut(&call)
            // a hangup already asked for is not undone by the far end ringing
            && held.state != CallState::Terminating
        {
            held.state = state;
        }
        let state = self.call_state(call).unwrap_or(state);
        self.events.push_back(UaEvent::CallProgress {
            call,
            state,
            status,
            response: response.clone(),
            answer_wanted,
        });
        self.report_transfer(call, status, now);
    }

    /// A 2xx for one of our INVITEs.
    fn on_answered(
        &mut self,
        call: CallHandle,
        dialog: DialogId,
        response: &OwnedMessage,
        now: Instant,
    ) {
        self.note_session(call, response);
        self.on_timer_answer(call, &response.as_raw(), now);
        let Some(held) = self.calls.get(&call) else {
            return;
        };
        let (offered, forks, forked) = (
            held.session.has_local(),
            held.forks,
            held.forked_from.is_some(),
        );

        // §13.2.2.4: the ACK goes now unless it has to carry an answer that
        // only the application has. A 2xx nobody acknowledges is retransmitted
        // for 64*T1 and then hung up at the other end
        let acknowledged = offered && self.endpoint.ack_2xx(dialog, None, now).is_ok();
        if let Some(held) = self.calls.get_mut(&call) {
            held.acknowledged = acknowledged;
            held.state = CallState::Confirmed;
        }

        // a branch that lost, under the policy that keeps one: acknowledged
        // first, because §13.2.2.4 is not conditional, and hung up after
        if forked && forks == ForkPolicy::KeepFirst {
            self.events.push_back(UaEvent::CallConfirmed {
                call,
                response: Some(response.clone()),
                answer_wanted: !acknowledged,
            });
            if acknowledged {
                self.hangup(call, now).ok();
            } else {
                self.finish(call, CallEndReason::ForkLost, None, None, now);
            }
            return;
        }

        self.events.push_back(UaEvent::CallConfirmed {
            call,
            response: Some(response.clone()),
            answer_wanted: !acknowledged,
        });
        // a call placed because of a REFER owes the referrer a last word
        self.report_transfer(call, StatusCode::OK, now);
        // a CANCEL that lost its race leaves the call up and the wish to end it
        if self.calls.get(&call).is_some_and(|held| held.hangup_wanted) {
            self.hangup(call, now).ok();
        }
    }

    /// A proxy challenged an INVITE. The account has the password.
    fn on_call_challenged(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        now: Instant,
    ) {
        let credentials = self
            .calls
            .get(&call)
            .and_then(|held| held.account)
            .and_then(|id| self.accounts.get(&id))
            .and_then(|config| config.credentials.clone());
        let Some(credentials) = credentials else {
            return;
        };
        let Ok(AnyTransactionId::InviteClient(retried)) =
            self.endpoint
                .retry_with_credentials(transaction, &credentials, now)
        else {
            return;
        };
        if let AnyTransactionId::InviteClient(old) = transaction {
            self.by_invite.remove(&old);
        }
        self.by_invite.insert(retried, call);
        if let Some(held) = self.calls.get_mut(&call) {
            held.invite = Some(retried);
            held.state = CallState::Calling;
        }
    }

    /// A transaction has ended. Most of that is plumbing; one case is not.
    fn on_transaction_over(
        &mut self,
        transaction: AnyTransactionId,
        reason: TerminationReason,
        now: Instant,
    ) {
        self.by_request.remove(&transaction);
        let AnyTransactionId::InviteServer(id) = transaction else {
            // the INVITE this end sent keeps its mapping until the call goes:
            // a fork's late 2xx is reported after the transaction is retired,
            // and the branch it names still has to be found
            return;
        };
        if let Some(call) = self.by_server.remove(&id)
            && let Some(held) = self.calls.get_mut(&call)
        {
            held.server = None;
        }
        if reason == TerminationReason::TimedOut {
            self.on_unacknowledged(id, now);
        }
    }

    /// A 2xx this end sent was never acknowledged.
    ///
    /// §13.3.1.4, and §14.2 says the same about a re-INVITE: "If a UAS
    /// generates a 2xx response and never receives an ACK, it SHOULD generate
    /// a BYE to terminate the dialog." Nothing else will — the far end is not
    /// answering, and a dialog left standing here would keep a line busy for
    /// as long as the process runs.
    fn on_unacknowledged(&mut self, id: TransactionId<InviteServer>, now: Instant) {
        let Some(call) = self
            .calls
            .iter()
            .find(|(_, held)| held.awaiting_ack == Some(id))
            .map(|(handle, _)| *handle)
        else {
            // a non-2xx that went unacknowledged is the transaction's own
            // business, and there is no dialog to end
            return;
        };
        let dialog = self.calls.get(&call).and_then(|held| held.dialog);
        if let Some(held) = self.calls.get_mut(&call) {
            held.awaiting_ack = None;
        }
        if let Some(dialog) = dialog {
            self.endpoint.bye(dialog, now).ok();
        }
        // reported before the BYE's own dialog event arrives, so the reason
        // says what happened rather than who sent the last message
        self.finish(call, CallEndReason::Unreachable, None, None, now);
    }
}

/// What ended the dialog, in the vocabulary of calls.
const fn ended_by(reason: DialogEndReason) -> CallEndReason {
    match reason {
        DialogEndReason::LocalBye => CallEndReason::LocalHangup,
        DialogEndReason::RemoteBye => CallEndReason::RemoteHangup,
        DialogEndReason::Refused => CallEndReason::Refused,
        DialogEndReason::Abandoned => CallEndReason::Abandoned,
        // non-exhaustive across crate versions; anything new still ended it
        DialogEndReason::Failed | DialogEndReason::Gone | _ => CallEndReason::Unreachable,
    }
}
