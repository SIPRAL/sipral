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

use sipral_core::endpoint::{
    DialogEndReason, Event, FailureReason, OutgoingRequest, OutgoingResponse,
};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, RawMessage, StatusCode, Uri};
use sipral_core::transaction::{AnyTransactionId, DialogId, InviteClient, TransactionId};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::call::{
    Call, CallEndReason, CallHandle, CallState, Direction, ForkPolicy, OutgoingCall,
};
use crate::error::UaError;
use crate::event::UaEvent;

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
        let (transport, remote) = outgoing
            .destination
            .unwrap_or((config.transport, config.remote));
        let contact = config.contact_value();
        let mut request =
            OutgoingRequest::new(Method::Invite, outgoing.target.clone(), transport, remote)
                .to(&bracketed(&outgoing.target))
                .from(&config.sender_value())
                .contact(&contact);
        if let Some(ref offer) = outgoing.offer {
            request = request.body(b"application/sdp", Arc::clone(offer));
        }
        for extra in &outgoing.extra {
            if let Some(name) = HeaderName::from_bytes(&extra.name) {
                request = request.header(name, &extra.value);
            }
        }

        let invite = self.endpoint.invite(&request, now)?;
        let mut call = Call::outgoing(account, outgoing.forks, outgoing.offer.is_some(), contact);
        call.invite = Some(invite);
        let handle = self.keep(call);
        self.by_invite.insert(invite, handle);
        self.drain(now);
        Ok(handle)
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
        let mut response = OutgoingResponse::new(status).contact(&contact);
        if let Some(sdp) = early {
            response = response.body(b"application/sdp", sdp);
        }
        let dialog = self.endpoint.respond_invite(transaction, &response, now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.state = if status == StatusCode::RINGING {
                CallState::Ringing
            } else {
                CallState::EarlyMedia
            };
            held.dialog = dialog;
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
        let transaction = self.answerable(call)?;
        let contact = self.contact_of(call)?;
        let mut response = OutgoingResponse::new(StatusCode::OK).contact(&contact);
        if let Some(sdp) = sdp {
            response = response.body(b"application/sdp", sdp);
        }
        let dialog = self.endpoint.respond_invite(transaction, &response, now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.dialog = dialog;
            // §12.1.1 confirms the dialog here, but the call is not up until
            // the ACK arrives; until then the 2xx is still being retransmitted
            held.state = CallState::Ringing;
        }
        if let Some(dialog) = dialog {
            self.by_dialog.insert(dialog, call);
        }
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
        self.finish(call, CallEndReason::LocalHangup, Some(status), None);
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
        if let Some(held) = self.calls.get_mut(&call) {
            held.acknowledged = true;
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
    ) {
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        if held.state == CallState::Terminated {
            return;
        }
        held.state = CallState::Terminated;
        self.events.push_back(UaEvent::CallEnded {
            call,
            reason,
            status,
            response,
        });
        self.forget(call);
    }

    fn forget(&mut self, call: CallHandle) {
        self.by_invite.retain(|_, held| *held != call);
        self.by_server.retain(|_, held| *held != call);
        self.by_dialog.retain(|_, held| *held != call);
        self.by_request.retain(|_, held| *held != call);
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
                self.on_progress(call, status, response);
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
                self.on_progress(call, status, response);
                // RFC 3262 §4 makes acknowledging it a MUST, and a response
                // that is not acknowledged is retransmitted until the INVITE
                // is abandoned. The body it may need — the answer to an offer
                // that arrived in a 1xx, for a call placed without one — is
                // 5.5's, and so is the offer this PRACK could carry
                if let Ok(prack) = self.endpoint.prack(provisional, None, now) {
                    self.by_request
                        .insert(AnyTransactionId::NonInviteClient(prack), call);
                }
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
                let ended = match reason {
                    FailureReason::Refused => CallEndReason::Refused,
                    // the enum is non-exhaustive across crate versions, and
                    // anything new is still a call that did not connect
                    _ => CallEndReason::Unreachable,
                };
                self.end_branches(invite, ended, status, response.as_ref())
            }
            Event::Cancelled { invite } => {
                self.end_branches(invite, CallEndReason::Cancelled, None, None)
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
            Event::DialogTerminated { dialog, reason } => {
                let call = self.by_dialog.get(&dialog).copied()?;
                // a refusal reported by the dialog layer is the same refusal
                // the INVITE transaction is about to report, and that one
                // knows whether the 487 was one we asked for. Wait for it
                // rather than answer first and answer worse
                if reason == DialogEndReason::Refused && self.still_calling(call) {
                    self.by_dialog.remove(&dialog);
                    if let Some(held) = self.calls.get_mut(&call) {
                        held.dialog = None;
                    }
                    return None;
                }
                self.finish(call, ended_by(reason), None, None);
                None
            }
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
                // changes nothing the application has not already been told
                let id = AnyTransactionId::NonInviteClient(transaction);
                self.by_request.contains_key(&id).then_some(())?;
                None
            }
            Event::TransactionTerminated { transaction, .. } => {
                self.on_transaction_over(transaction).then_some(())?;
                None
            }
            other => Some(other),
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
                let account = self.line_for(&request.as_raw());
                let contact = account.and_then(|id| self.accounts.get(&id)).map_or_else(
                    || Box::from(&b""[..]),
                    crate::account::Account::contact_value,
                );
                let call = self.keep(Call::incoming(account, transaction, contact));
                self.by_server.insert(transaction, call);
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
                self.finish(call, CallEndReason::Cancelled, None, None);
                None
            }
            Event::IncomingAck { dialog, .. } => {
                let call = self.by_dialog.get(&dialog).copied()?;
                if let Some(held) = self.calls.get_mut(&call) {
                    held.state = CallState::Confirmed;
                    held.acknowledged = true;
                }
                self.events.push_back(UaEvent::CallConfirmed {
                    call,
                    response: None,
                    answer_wanted: false,
                });
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
                self.finish(call, CallEndReason::RemoteHangup, None, None);
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
    ) -> Option<Event> {
        let branches: Vec<CallHandle> = self
            .calls
            .iter()
            .filter(|(_, held)| held.invite == Some(invite))
            .map(|(handle, _)| *handle)
            .collect();
        for call in branches {
            self.finish(call, reason, status, response.cloned());
        }
        None
    }

    fn on_progress(&mut self, call: CallHandle, status: StatusCode, response: &OwnedMessage) {
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
        });
    }

    /// A 2xx for one of our INVITEs.
    fn on_answered(
        &mut self,
        call: CallHandle,
        dialog: DialogId,
        response: &OwnedMessage,
        now: Instant,
    ) {
        let Some(held) = self.calls.get(&call) else {
            return;
        };
        let (offered, forks, forked) = (held.offered, held.forks, held.forked_from.is_some());

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
                self.finish(call, CallEndReason::ForkLost, None, None);
            }
            return;
        }

        self.events.push_back(UaEvent::CallConfirmed {
            call,
            response: Some(response.clone()),
            answer_wanted: !acknowledged,
        });
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

    /// Whether a transaction that has just ended was one of ours.
    fn on_transaction_over(&mut self, transaction: AnyTransactionId) -> bool {
        if self.by_request.remove(&transaction).is_some() {
            return true;
        }
        match transaction {
            AnyTransactionId::InviteClient(id) => {
                // the mapping stays until the call does: a fork's late 2xx is
                // reported after the transaction is retired, and the branch it
                // names still has to be found
                self.by_invite.contains_key(&id)
            }
            AnyTransactionId::InviteServer(id) => {
                let Some(call) = self.by_server.get(&id).copied() else {
                    return false;
                };
                if let Some(held) = self.calls.get_mut(&call) {
                    held.server = None;
                }
                self.by_server.remove(&id);
                true
            }
            AnyTransactionId::NonInviteClient(_) | AnyTransactionId::NonInviteServer(_) => false,
        }
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
