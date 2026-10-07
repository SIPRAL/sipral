// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Placing calls, answering them, and ending them from either side.
//!
//! **The ACK is sent, not offered.** §13.2.2.4 leaves the ACK for a 2xx to the
//! layer above; a user agent sends it, since an unacknowledged 2xx gets the
//! call hung up by the far end. The exception is a call placed with no offer:
//! the answer travels in the ACK and only the application has one.
//!
//! **A fork is not hidden.** Every 2xx has to be acknowledged, so each branch
//! becomes a call of its own, and [`ForkPolicy`] decides what happens to the
//! ones not kept: hang them up, or hand them all over.
//!
//! **Hanging up depends on the moment.** Before the answer it is a CANCEL,
//! after it a BYE, and on an incoming call not yet answered a refusal. One
//! call does all three.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use sipral_core::dialog::CallId;
use sipral_core::endpoint::{
    DialogEndReason, Event, FailureReason, OutgoingInDialogRequest, OutgoingRequest,
    OutgoingResponse, PrackError, TerminationReason, TransportProtocol,
};
use sipral_core::msg::{
    HeaderName, Method, NameAddrRef, OwnedMessage, RawMessage, StatusCode, Uri,
};
use sipral_core::sdp;
use sipral_core::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteClient, NonInviteServer,
    TransactionId,
};

use crate::account::{Account, AccountId, Extra};
use crate::agent::UserAgent;
use crate::answering::Answering;
use crate::call::{
    Call, CallEndReason, CallHandle, CallIdentity, CallState, Direction, ForkPolicy, KeptBranch,
    OutgoingCall, Refusal, RequestRefusal,
};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::headers::{HeadersFor, onto_request, onto_response};
use crate::identity::{ASSERTED, CallerIdentity, DIVERSION, PRIVACY};
use crate::parked::needs_a_stream;
use crate::reason::{Reason, ReasonProtocol, with_reason};
use crate::redirect::Redirect;
use crate::registration::{anonymous, dialog_contact};
use crate::renegotiate::ALLOW;
use crate::timers::FLOOR;

/// The refusal a call gets when it is hung up before it was answered.
///
/// §21.4.6: "the callee's end system was contacted successfully but the callee
/// is currently not willing or able to take additional calls".
const NOT_NOW: StatusCode = StatusCode::BUSY_HERE;

/// Take out the parked refusals that have settled, leaving behind the ones
/// whose retry the endpoint is still holding for want of a connection.
pub(crate) fn settled<K, V>(parked: &mut HashMap<K, V>, waiting: impl Fn(&V) -> bool) -> Vec<(K, V)>
where
    K: Copy + Eq + std::hash::Hash,
{
    let done: Vec<K> = parked
        .iter()
        .filter(|(_, value)| !waiting(value))
        .map(|(key, _)| *key)
        .collect();
    done.into_iter()
        .filter_map(|key| parked.remove_entry(&key))
        .collect()
}

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
        // a refused field leaves no call behind and nothing on the wire
        HeadersFor::Call.check_each(&outgoing.extra)?;
        let Some((_, remote)) = outgoing.destination.or_else(|| config.destination()) else {
            return Err(UaError::NotLocated);
        };
        // no address in Contact or offer the far end cannot reach
        crate::advertise::check_contact(&config.contact, remote)?;
        if let Some(offered) = outgoing
            .offer
            .as_deref()
            .and_then(|sdp| sdp::parse_with_limits(sdp, self.sdp_limits).ok())
        {
            crate::advertise::check_description(&offered, remote)?;
        }
        let asked = config.session_interval;
        let from = config.caller_value();
        let mut call = Call::outgoing(
            account,
            outgoing.forks,
            outgoing.destination,
            anonymous(&outgoing.extra) || config.privacy.requested(),
            from,
            config.contact_value(),
        );
        // minted here rather than by the endpoint, because §7.3 has a 422
        // asked again on the same Call-ID with the number moved on
        call.id = Some(CallId::new(&self.endpoint.token()));
        call.placed = Some(outgoing.clone());
        call.asked = asked;
        call.contact_context.features = outgoing.contact_features();
        call.recording.clone_from(&outgoing.metadata);
        let limits = self.sdp_limits;
        if let Some(described) = outgoing
            .offer
            .as_deref()
            .and_then(|sdp| sdp::parse_with_limits(sdp, limits).ok())
        {
            call.session.set_local(described);
        }
        // RFC 8224 §6.1, once, before anything is kept: a call that cannot
        // be signed as its account asks is not placed unsigned
        #[cfg(feature = "stir")]
        {
            let own_date = outgoing
                .extra
                .iter()
                .any(|extra| extra.name.eq_ignore_ascii_case(b"Date"));
            call.signed = self.sign_for(account, &outgoing.target, own_date, now)?;
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
            .or_else(|| config.destination())
            .ok_or(UaError::NotLocated)?;
        let from = config.caller_value();
        let identifying = identifying_fields(config, &outgoing.extra, remote);
        // read fresh on every attempt: RFC 5627 §4.4 forbids a GRUU whose
        // registration is gone
        let (call_id, cseq, asked, signed, request_uri) = {
            let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            (
                held.id.clone(),
                held.cseq,
                held.asked,
                held.signed.clone(),
                // where a 3xx sent the call, once one did (RFC 3261 §8.1.3.4)
                held.redirection
                    .target
                    .clone()
                    .unwrap_or_else(|| outgoing.target.clone()),
            )
        };
        let contact = self.current_contact(call, now);
        let mut request = OutgoingRequest::new(Method::Invite, request_uri, transport, remote)
            .to(&bracketed(&outgoing.target))
            .from(&from)
            .contact(&contact)
            // RFC 3311 §4: the INVITE SHOULD list UPDATE in Allow
            .header(HeaderName::Allow, ALLOW)
            .cseq(cseq);
        if let Some(call_id) = call_id {
            request = request.call_id(call_id);
        }
        // RFC 3608 §6.1: preloaded Route, order preserved
        if let Some(learned) = self.learned_for(account, outgoing.destination, now) {
            for hop in learned.service_route() {
                request = request.route(hop);
            }
        }
        let mut asked_for = self.asking_for(call, asked);
        self.fold_gruu(call, &mut asked_for);
        for (name, value) in &asked_for {
            request = request.header(*name, value);
        }
        match (outgoing.offer.as_ref(), outgoing.metadata.as_deref()) {
            (Some(offer), Some(metadata)) => {
                // RFC 7866 §6.1 Require: siprec; §9.1 offer and metadata in
                // one multipart/mixed body
                let body = crate::siprec::written_session_body(offer, metadata)
                    .map_err(UaError::Recording)?;
                let content_type = body.content_type().to_owned();
                request = request
                    .header(HeaderName::Require, crate::siprec::OPTION_TAG.as_bytes())
                    .body(content_type.as_bytes(), Arc::from(body.into_body()));
            }
            (Some(offer), None) => {
                request = request.body(b"application/sdp", Arc::clone(offer));
            }
            (None, _) => {}
        }
        for (name, value) in &identifying.added {
            request = request.header(*name, value);
        }
        // RFC 8224 §6.1 Steps 3 and 4
        if let Some(signed) = signed {
            if let Some(date) = signed.date.as_deref() {
                request = request.header(HeaderName::Date, date);
            }
            request = request.header(crate::call::IDENTITY, &signed.identity);
        }
        for extra in &outgoing.extra {
            if identifying.withheld(&extra.name) {
                continue;
            }
            if let Some(name) = HeaderName::from_bytes(&extra.name) {
                request = request.header(name, &extra.value);
            }
        }

        let invite = self.endpoint.invite(&request, now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.invite = Some(invite);
            // what a `Replaces` naming this call is checked against (RFC 3891 §3)
            held.peer = Some(remote);
        }
        self.by_invite.insert(invite, call);
        Ok(())
    }

    /// Say the phone is ringing (180), optionally with early media (183).
    ///
    /// A body makes it a 183 Session Progress.
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
        self.not_verifying(call)?;
        let transaction = self.answerable(call)?;
        let limits = self.sdp_limits;
        let status = if early.is_some() {
            StatusCode::SESSION_PROGRESS
        } else {
            StatusCode::RINGING
        };
        let contact = self.current_contact(call, now);
        self.check_advertised(call, &contact, early.as_deref())?;
        let mut response = onto_response(
            OutgoingResponse::new(status)
                .contact(&contact)
                .header(HeaderName::Allow, ALLOW),
            &self.application_headers(call),
        );
        if self.wants_gruu(call) {
            // RFC 5627 §4.4: 18x and 2xx with a To tag carry it
            response = response.header(HeaderName::Supported, b"gruu");
        }
        let described = early
            .as_deref()
            .and_then(|sdp| sdp::parse_with_limits(sdp, limits).ok());
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
    /// As [`UserAgent::ring`], and [`UaError::WrongState`] for a call this
    /// end has already answered, whether or not its ACK has come.
    pub fn answer(
        &mut self,
        call: CallHandle,
        sdp: Option<Arc<[u8]>>,
        now: Instant,
    ) -> Result<(), UaError> {
        // the server transaction outlives its 2xx (RFC 6026 §7.1), so a second
        // answer would go out; refuse it instead
        self.not_verifying(call)?;
        if let Some(held) = self.calls.get(&call)
            && (held.awaiting_ack.is_some() || held.acknowledged)
        {
            return Err(UaError::WrongState(held.state));
        }
        // RFC 3262 §5: the 2xx waits for the PRACK of a reliable provisional
        // with a description, or two offers would be open at once
        if self.answer_is_held(call) {
            self.hold_answer(call, sdp);
            return Ok(());
        }
        let transaction = self.answerable(call)?;
        let limits = self.sdp_limits;
        let contact = self.current_contact(call, now);
        self.check_advertised(call, &contact, sdp.as_deref())?;
        let mut supported: Vec<u8> = b"timer".to_vec();
        // RFC 5627 §4.4
        if self.wants_gruu(call) {
            supported.extend_from_slice(b", gruu");
        }
        // RFC 3311 §4: a 2xx SHOULD list UPDATE in Allow
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW)
            .header(HeaderName::Supported, &supported);
        let invited = self.calls.get(&call).and_then(|held| held.invited.clone());
        if let Some(ref invited) = invited
            && let Some((value, demand)) = self.timer_for_answer(call, &invited.as_raw(), now)
        {
            response = response.header(HeaderName::SessionExpires, &value);
            if demand {
                // RFC 4028 §9: refresher=uac needs Require: timer
                response = response.header(HeaderName::Require, b"timer");
            }
        }
        response = onto_response(response, &self.application_headers(call));
        let described = sdp
            .as_deref()
            .and_then(|sdp| sdp::parse_with_limits(sdp, limits).ok());
        if let Some(sdp) = sdp {
            response = response.body(b"application/sdp", sdp);
        }
        let dialog = self.endpoint.respond_invite(transaction, &response, now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.dialog = dialog;
            // not up until the ACK; §13.3.1.4 wants a BYE if it never comes
            held.state = CallState::Ringing;
            held.awaiting_ack = Some(transaction);
            if let Some(described) = described {
                // no offer in the INVITE: the answer comes in the ACK (§13.2.2.4)
                held.session.answer_owed = !held.session.has_remote();
                held.session.set_local(described);
            }
        }
        if let Some(dialog) = dialog {
            self.by_dialog.insert(dialog, call);
        }
        // RFC 3891 §3: answering ends the replaced dialog
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
        let headers = self.application_headers(call);
        self.refuse(call, status, &headers, now)
    }

    /// Answer a call that came in with a 3xx: somewhere else to try
    /// (RFC 3261 §21.3), and, when the [`Redirect`] says why, a `Diversion`
    /// naming this end as the party that diverted the call (RFC 5806).
    ///
    /// The `Contact` lists every target with its `q`. The `Diversion` names
    /// the INVITE's `To` with the reason and `counter=1`, followed by the
    /// `Diversion` values the INVITE already carried, so the chain survives.
    ///
    /// # Errors
    /// [`UaError::NotARedirection`] for no targets with any status but 380;
    /// otherwise as [`UserAgent::reject`].
    pub fn redirect(
        &mut self,
        call: CallHandle,
        redirect: &Redirect,
        now: Instant,
    ) -> Result<(), UaError> {
        if redirect.targets.is_empty() && redirect.status.get() != 380 {
            return Err(UaError::NotARedirection(redirect.status));
        }
        let transaction = self.answerable(call)?;
        let invited = self.calls.get(&call).and_then(|held| held.invited.clone());
        let mut response = OutgoingResponse::new(redirect.status);
        if !redirect.targets.is_empty() {
            response = response.contact(&redirect.contact_value());
        }
        if let Some(invited) = invited.as_ref() {
            let raw = invited.as_raw();
            let diverting = raw.to().ok().map(|to| to.uri_bytes().to_vec());
            if let Some(ours) = diverting.and_then(|to| redirect.diversion_value(&to)) {
                response = response.header(DIVERSION, &ours);
                for earlier in raw.header_values(DIVERSION) {
                    response = response.header(DIVERSION, earlier);
                }
            }
        }
        let response = onto_response(response, &self.application_headers(call));
        self.endpoint.respond_invite(transaction, &response, now)?;
        self.finish(
            call,
            CallEndReason::LocalHangup,
            Some(redirect.status),
            None,
            now,
        );
        self.drain(now);
        Ok(())
    }

    /// [`UserAgent::reject`], carrying `headers`.
    fn refuse(
        &mut self,
        call: CallHandle,
        status: StatusCode,
        headers: &[Extra],
        now: Instant,
    ) -> Result<(), UaError> {
        let transaction = self.answerable(call)?;
        self.endpoint.respond_invite(
            transaction,
            &onto_response(OutgoingResponse::new(status), headers),
            now,
        )?;
        self.finish(call, CallEndReason::LocalHangup, Some(status), None, now);
        self.drain(now);
        Ok(())
    }

    /// Answer an offer that arrived in a reliable provisional response.
    ///
    /// RFC 3262 §5: the answer goes in the PRACK. Only for a call placed
    /// without an offer, signalled by `answer_wanted` on
    /// [`UaEvent::CallProgress`](crate::UaEvent::CallProgress).
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when nothing is
    /// waiting for one, or [`UaError::Sdp`]. [`UaError::Send`] when the PRACK
    /// needs a stream that is not open yet (RFC 3261 §18.1.1): the answer is
    /// still owed; call again once the stream is bound.
    pub fn answer_early(
        &mut self,
        call: CallHandle,
        sdp: &[u8],
        now: Instant,
    ) -> Result<(), UaError> {
        let described = sdp::parse_with_limits(sdp, self.sdp_limits).map_err(UaError::Sdp)?;
        if let Some(peer) = self.calls.get(&call).and_then(|held| held.peer) {
            crate::advertise::check_description(&described, peer)?;
        }
        let (provisional, state) = {
            let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            (
                held.owed_prack.ok_or(UaError::WrongState(held.state))?,
                held.state,
            )
        };
        let prack = match self
            .endpoint
            .prack(provisional, Some(Arc::from(sdp.to_vec())), now)
        {
            Ok(prack) => prack,
            Err(PrackError::Send(error)) if needs_a_stream(&error) => {
                return Err(UaError::Send(error));
            }
            Err(_) => {
                if let Some(held) = self.calls.get_mut(&call) {
                    held.owed_prack = None;
                }
                return Err(UaError::WrongState(state));
            }
        };
        self.remember_request(
            call,
            AnyTransactionId::NonInviteClient(prack),
            Method::Prack,
        );
        if let Some(held) = self.calls.get_mut(&call) {
            held.owed_prack = None;
            held.session.set_local(described);
        }
        self.drain(now);
        Ok(())
    }

    /// Acknowledge a 2xx whose offer is still waiting for an answer.
    ///
    /// Only for a call placed without an offer: the offer came in the 2xx and
    /// the answer travels in the ACK (§13.2.2.4), so it is not sent for you.
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
        let described = answer.and_then(|sdp| sdp::parse_with_limits(sdp, self.sdp_limits).ok());
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
    /// A CANCEL while the INVITE this end sent is unanswered (§9.1, held until
    /// the first provisional if needed), a BYE once the call is up, a refusal
    /// for an incoming call not yet answered. A call already ending is left
    /// alone.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], or the error of whatever it turned into.
    pub fn hangup(&mut self, call: CallHandle, now: Instant) -> Result<(), UaError> {
        let headers = self.application_headers(call);
        self.end_call(call, &headers, &[], now)
    }

    /// [`UserAgent::hangup`], saying why (RFC 3326).
    ///
    /// `reasons` go in a `Reason` field on the BYE or CANCEL, one value per
    /// protocol (§2); later duplicates are dropped. On a refusal only the
    /// Q.850 values go (RFC 6432): a SIP one would repeat the status.
    ///
    /// # Errors
    /// As [`UserAgent::hangup`].
    pub fn hangup_for(
        &mut self,
        call: CallHandle,
        reasons: &[Reason],
        now: Instant,
    ) -> Result<(), UaError> {
        let headers = self.application_headers(call);
        self.end_call(call, &headers, reasons, now)
    }

    /// [`UserAgent::hangup`], carrying `headers` on the refusal or BYE. A
    /// CANCEL carries none (§16.10).
    pub(crate) fn end_call(
        &mut self,
        call: CallHandle,
        headers: &[Extra],
        reasons: &[Reason],
        now: Instant,
    ) -> Result<(), UaError> {
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
                let q850: Vec<Reason> = reasons
                    .iter()
                    .filter(|reason| reason.protocol == ReasonProtocol::Q850)
                    .cloned()
                    .collect();
                let headers = with_reason(headers, &q850);
                self.refuse(call, NOT_NOW, &headers, now)
            }
            CallState::Confirmed | CallState::Consulting => {
                let dialog = dialog.ok_or(UaError::WrongState(state))?;
                let headers = with_reason(headers, reasons);
                let bye = self.endpoint.bye_with(
                    dialog,
                    &onto_request(OutgoingInDialogRequest::new(Method::Bye), &headers),
                    now,
                )?;
                self.remember_request(call, AnyTransactionId::NonInviteClient(bye), Method::Bye);
                self.mark(call, CallState::Terminating);
                self.drain(now);
                Ok(())
            }
            _ => {
                let invite = invite.ok_or(UaError::WrongState(state))?;
                // §9.1: the endpoint holds an early CANCEL until a provisional
                match Reason::field(reasons) {
                    Some(value) => self.endpoint.cancel_with_reason(invite, &value, now).ok(),
                    None => self.endpoint.cancel(invite, now).ok(),
                };
                if let Some(held) = self.calls.get_mut(&call) {
                    held.hangup_wanted = true;
                    held.state = CallState::Terminating;
                }
                self.drain(now);
                Ok(())
            }
        }
    }

    /// Every call this agent still holds, in handle order.
    #[must_use]
    pub fn calls(&self) -> Vec<CallHandle> {
        let mut held: Vec<CallHandle> = self.calls.keys().copied().collect();
        held.sort_unstable();
        held
    }

    /// Where a call is.
    #[must_use]
    pub fn call_state(&self, call: CallHandle) -> Option<CallState> {
        self.calls.get(&call).map(|held| held.state)
    }

    /// Whether this end has sent a session description of its own for this
    /// call.
    ///
    /// Ask before writing an early answer: RFC 3261 §13.2.1 and RFC 6337
    /// §3.1.1 require every response to one INVITE to carry the same one.
    #[must_use]
    pub fn has_described(&self, call: CallHandle) -> bool {
        self.calls
            .get(&call)
            .is_some_and(|held| held.session.has_local())
    }

    /// The dialog a call is in, once there is one.
    #[must_use]
    pub fn call_dialog(&self, call: CallHandle) -> Option<DialogId> {
        self.calls.get(&call).and_then(|held| held.dialog)
    }

    /// The account a call belongs to: the one it was placed from, or the
    /// line it arrived on. `None` for a call that arrived on no account of
    /// this agent's, and for one that has ended.
    #[must_use]
    pub fn call_account(&self, call: CallHandle) -> Option<AccountId> {
        self.calls.get(&call)?.account
    }

    /// Whether this call's signalling runs over TLS or secure WebSocket: the
    /// dialog's transport, or the INVITE's before there is a dialog. `None`
    /// once the call is gone.
    ///
    /// When `false`, SDES keys in its descriptions travel in clear
    /// (RFC 4568 §8.3).
    #[must_use]
    pub fn call_signalling_secure(&self, call: CallHandle) -> Option<bool> {
        let held = self.calls.get(&call)?;
        let transaction = held
            .server
            .map(AnyTransactionId::InviteServer)
            .or_else(|| held.invite.map(AnyTransactionId::InviteClient));
        self.endpoint
            .signalling_protocol(held.dialog, transaction)
            .map(TransportProtocol::is_secure)
    }

    /// Whether a call placed now from `account` as `outgoing` would be
    /// signalled over TLS or secure WebSocket: the transport it would leave
    /// on is bound, and is one of those. `None` for an unknown account, one
    /// not yet located, or a transport not bound. Decides whether the offer
    /// may carry an SDES key.
    #[must_use]
    pub fn placing_securely(&self, account: AccountId, outgoing: &OutgoingCall) -> Option<bool> {
        let config = self.accounts.get(&account)?;
        let (transport, _) = outgoing.destination.or_else(|| config.destination())?;
        let (protocol, _) = self.endpoint.bound_transport(transport)?;
        Some(protocol.is_secure())
    }

    /// Whether this end placed the call or answered it, which decides which
    /// of [`CallIdentity`]'s two URIs is this end's own.
    #[must_use]
    pub fn call_direction(&self, call: CallHandle) -> Option<Direction> {
        self.calls.get(&call).map(|held| held.direction)
    }

    /// The `From` and `To` of the request that opened this call, and its
    /// `Call-ID`.
    ///
    /// `None` once the call is gone. A fork branch answers with its parent's.
    #[must_use]
    pub fn call_identity(&self, call: CallHandle) -> Option<CallIdentity> {
        self.identity_now(call)
    }

    /// [`UserAgent::call_identity`], read.
    fn identity_now(&self, call: CallHandle) -> Option<CallIdentity> {
        let held = self.calls.get(&call)?;
        match held.direction {
            Direction::Incoming => match held.identity.as_deref() {
                Some(read) => Some(read.clone()),
                None => CallIdentity::of_request(held.invited.as_ref()?),
            },
            Direction::Outgoing => {
                let from = NameAddrRef::parse(&held.from).ok()?;
                let target = held.placed.as_ref()?.target.as_bytes();
                let call_id = held.id.as_ref()?.as_bytes();
                Some(CallIdentity {
                    from_uri: Box::from(from.uri_bytes()),
                    from_display: display_of(&from),
                    to_uri: Box::from(target),
                    call_id: Box::from(call_id),
                    caller: CallerIdentity::default(),
                    answering: Answering::default(),
                })
            }
        }
    }

    /// The header fields to put on what this call sends at the application's
    /// request, from now until they are replaced.
    ///
    /// They go on [`UserAgent::ring`], [`UserAgent::answer`],
    /// [`UserAgent::reject`], the refusal or BYE of [`UserAgent::hangup`], and
    /// the re-INVITE or UPDATE of [`UserAgent::hold`], [`UserAgent::resume`]
    /// and [`UserAgent::reoffer`], 491 retries included. They are kept, not
    /// spent on the first message.
    ///
    /// Not on a CANCEL (hop by hop, RFC 3261 §16.10), not on the answer to a
    /// change the far end offered, and not on anything this layer sends by
    /// itself (session refresh, BYE for an unacknowledged 2xx or a lost fork).
    ///
    /// Replaces the previous set whole; an empty list clears it. Every field
    /// is checked first ([`crate::HeadersFor::Call`]); on a refusal the old
    /// set stays.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], or [`UaError::Header`] for the first field
    /// refused.
    pub fn respond_with_headers(
        &mut self,
        call: CallHandle,
        headers: &[(HeaderName<'_>, &[u8])],
    ) -> Result<(), UaError> {
        if !self.calls.contains_key(&call) {
            return Err(UaError::NoSuchCall);
        }
        let kept: Vec<Extra> = headers
            .iter()
            .map(|(name, value)| Extra {
                name: Box::from(name.canonical().as_bytes()),
                value: Box::from(*value),
            })
            .collect();
        HeadersFor::Call.check_each(&kept)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.headers = kept;
        }
        Ok(())
    }

    /// The application's fields for a call, copied out.
    pub(crate) fn application_headers(&self, call: CallHandle) -> Vec<Extra> {
        self.calls
            .get(&call)
            .map(|held| held.headers.clone())
            .unwrap_or_default()
    }
}

impl UserAgent {
    fn keep(&mut self, call: Call) -> CallHandle {
        let handle = CallHandle(self.next_call);
        self.next_call = self.next_call.wrapping_add(1);
        self.calls.insert(handle, call);
        handle
    }

    /// Refuse to ring or answer a call held back for its verdict
    /// ([`crate::stir`]). Refusing and hanging up are still allowed.
    #[cfg(feature = "stir")]
    fn not_verifying(&self, call: CallHandle) -> Result<(), UaError> {
        if self.verifying(call) {
            return Err(UaError::WrongState(CallState::Incoming));
        }
        Ok(())
    }

    #[cfg(not(feature = "stir"))]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    const fn not_verifying(&self, _call: CallHandle) -> Result<(), UaError> {
        Ok(())
    }

    /// The server transaction of a call that can still be answered.
    pub(crate) fn answerable(
        &self,
        call: CallHandle,
    ) -> Result<TransactionId<sipral_core::transaction::InviteServer>, UaError> {
        let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
        held.server.ok_or(UaError::WrongState(held.state))
    }

    /// Refuse to hand the far end of `call` a `Contact` or a session
    /// description it cannot reach this end at ([`crate::advertise`]). A call
    /// whose far end the transport never named is not checked.
    fn check_advertised(
        &self,
        call: CallHandle,
        contact: &[u8],
        sdp: Option<&[u8]>,
    ) -> Result<(), UaError> {
        let Some(peer) = self.calls.get(&call).and_then(|held| held.peer) else {
            return Ok(());
        };
        crate::advertise::check_contact_value(contact, peer)?;
        if let Some(described) =
            sdp.and_then(|sdp| sdp::parse_with_limits(sdp, self.sdp_limits).ok())
        {
            crate::advertise::check_description(&described, peer)?;
        }
        Ok(())
    }

    /// The `Contact` this call names now: the public GRUU while registered,
    /// the temporary one on an anonymous call, else the plain contact, plus
    /// the call's feature parameters. Read fresh every time, because RFC 5627
    /// §4.4 forbids naming a GRUU whose registration is gone.
    pub(crate) fn current_contact(&self, call: CallHandle, now: Instant) -> Box<[u8]> {
        let Some(held) = self.calls.get(&call) else {
            return Box::from(&b""[..]);
        };
        let address = match held
            .account
            .and_then(|id| Some((id, self.accounts.get(&id)?)))
        {
            Some((account, config)) => {
                let learned = self.learned_for(account, held.contact_context.destination, now);
                dialog_contact(config, learned, held.contact_context.anonymous)
            }
            None => held.contact_context.plain.clone(),
        };
        let features = &held.contact_context.features;
        if features.is_empty() {
            return address;
        }
        let mut out = Vec::with_capacity(address.len() + features.len());
        out.extend_from_slice(&address);
        out.extend_from_slice(features);
        out.into_boxed_slice()
    }

    /// Say, or stop saying, that this end is the focus of a conference the
    /// call belongs to (RFC 4579 §4.2): `isfocus` in every `Contact` the call
    /// sends from here on. A far end already in the call learns it from the
    /// next re-INVITE or UPDATE (RFC 3261 §12.2).
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`].
    pub fn set_focus(&mut self, call: CallHandle, focus: bool) -> Result<(), UaError> {
        let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
        let features = &mut held.contact_context.features;
        let already = contains_feature(features, b";isfocus");
        if focus == already {
            return Ok(());
        }
        let mut changed = features.to_vec();
        if focus {
            changed.extend_from_slice(b";isfocus");
        } else if let Some(at) = changed
            .windows(b";isfocus".len())
            .position(|window| window == b";isfocus")
        {
            changed.drain(at..at + b";isfocus".len());
        }
        *features = changed.into_boxed_slice();
        Ok(())
    }

    /// Take recording sessions (RFC 7866 §6.2): `Require: siprec` is accepted
    /// instead of refused 420. The session arrives as an ordinary
    /// [`UaEvent::IncomingCall`]; [`crate::siprec::read_recording_offer`]
    /// reads its offer and metadata, and
    /// [`crate::siprec::contact_has_feature_tag`] checks `+sip.src`.
    pub fn accept_recording_sessions(&mut self, accept: bool) {
        self.recording_server = accept;
    }

    /// Whether this end says it is the focus of the call's conference
    /// ([`OutgoingCall::focus`], [`UserAgent::set_focus`]).
    #[must_use]
    pub fn is_focus(&self, call: CallHandle) -> bool {
        self.calls
            .get(&call)
            .is_some_and(|held| contains_feature(&held.contact_context.features, b";isfocus"))
    }

    /// The conference the call belongs to when its far end is a focus: the
    /// URI of its `Contact` that carried `isfocus` (RFC 4579 §4.2).
    #[must_use]
    pub fn call_conference(&self, call: CallHandle) -> Option<Uri> {
        self.calls.get(&call)?.remote_focus.clone()
    }

    /// Subscribe to the conference package of the call's focus, outside the
    /// call's dialog, from the call's account (RFC 4579 §3.4). The
    /// subscription outlives the call; [`UaEvent::ConferenceChanged`] reports
    /// what it learns.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::NotAFocus`] for a call whose far
    /// end did not say it is a focus, and [`UaError::NoSuchAccount`] for a
    /// call that arrived on no account of this agent's.
    pub fn subscribe_call_conference(
        &mut self,
        call: CallHandle,
        now: Instant,
    ) -> Result<crate::SubscriptionHandle, UaError> {
        let account = self
            .calls
            .get(&call)
            .ok_or(UaError::NoSuchCall)?
            .account
            .ok_or(UaError::NoSuchAccount)?;
        let conference = self.call_conference(call).ok_or(UaError::NotAFocus)?;
        self.subscribe_conference(account, conference, now)
    }

    /// The headers `asking_for` wrote for an INVITE or a re-INVITE, with
    /// `gruu` added to `Supported` when the account asked for GRUUs (RFC 5627
    /// §4.4).
    pub(crate) fn fold_gruu(
        &self,
        call: CallHandle,
        headers: &mut [(HeaderName<'static>, Box<[u8]>)],
    ) {
        if !self.wants_gruu(call) {
            return;
        }
        if let Some((_, value)) = headers
            .iter_mut()
            .find(|(name, _)| *name == HeaderName::Supported)
        {
            let mut merged = value.to_vec();
            merged.extend_from_slice(b", gruu");
            *value = merged.into_boxed_slice();
        }
    }

    /// Whether the call's account asked its registrar for GRUUs (RFC 5627 §4.1).
    pub(crate) fn wants_gruu(&self, call: CallHandle) -> bool {
        self.calls
            .get(&call)
            .and_then(|held| held.account)
            .and_then(|id| self.accounts.get(&id))
            .is_some_and(Account::wants_gruu)
    }

    fn mark(&mut self, call: CallHandle, state: CallState) {
        if let Some(held) = self.calls.get_mut(&call) {
            held.state = state;
        }
    }

    /// The call is over: say so once, and let the handle go stale.
    pub(crate) fn finish(
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
        // §15.1.2: answer their pending request before the dialog goes
        self.abandon_change(call, now);
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        held.state = CallState::Terminated;
        // the BYE's or CANCEL's Reason, else the refusal's (RFC 6432)
        let mut causes = core::mem::take(&mut held.ended_by);
        let request = held.ended_with.take();
        if causes.is_empty()
            && let Some(refusal) = response.as_ref()
        {
            causes = Reason::all_in(&refusal.as_raw());
        }
        self.events.push_back(UaEvent::CallEnded {
            call,
            reason,
            status,
            response,
            request,
            causes,
        });
        // RFC 3515 §2.4.7: a transfer always gets its closing NOTIFY; a call
        // that never got an answer reports 408 (RFC 3261 §21.4.9). Must run
        // before `forget`, which drops the record it reads.
        let reported = status.unwrap_or(match StatusCode::new(408) {
            Ok(timeout) => timeout,
            Err(_) => StatusCode::SERVER_ERROR,
        });
        self.report_transfer(call, reported, now);
        // before `forget` too: the RFC 6035 report sent on `CallEnded` needs
        // the account and identity `forget` removes

        self.stash_ended_call(call);
        self.forget(call);
    }

    /// The session timer ran out and nobody refreshed it (RFC 4028 §10).
    pub(crate) fn finish_expired(&mut self, call: CallHandle, now: Instant) {
        self.finish(call, CallEndReason::Expired, None, None, now);
    }

    fn forget(&mut self, call: CallHandle) {
        // a caller that gave up while its certificate was being fetched
        #[cfg(feature = "stir")]
        self.stop_verifying(call);
        for other in self.calls.values_mut() {
            if other.consulting == Some(call) {
                other.consulting = None;
            }
            // the transfer target is gone: an ordinary call from here on
            if other.consulting_for == Some(call) {
                other.consulting_for = None;
                if other.state == CallState::Consulting {
                    other.state = CallState::Confirmed;
                }
            }
        }
        self.let_go_of_invite(call);
        self.by_invite.retain(|_, held| *held != call);
        self.by_server.retain(|_, held| *held != call);
        self.by_dialog.retain(|_, held| *held != call);
        self.by_offer.retain(|_, held| *held != call);
        self.challenged_offers
            .retain(|_, parked| parked.call != call);
        self.calls.remove(&call);
        // queued digits would otherwise never drain
        self.dtmf_queue.remove(&call);
        self.holds_waiting.remove(&call);
        // by_request stays: the BYE outlives the call, and
        // `on_transaction_over` clears it
    }

    /// A call placed by this end is going, and the INVITE that placed it may
    /// still be answered.
    ///
    /// 2xx keep arriving until timer M (RFC 6026 §8.4) and each must be
    /// acknowledged and ended with a BYE (§13.2.2.4). A sibling still up takes
    /// the INVITE over; with none left, a late answer goes to
    /// [`UserAgent::let_go_late_branch`] under either [`ForkPolicy`].
    fn let_go_of_invite(&mut self, call: CallHandle) {
        let Some(held) = self.calls.get(&call) else {
            return;
        };
        let Some(invite) = held.invite else {
            return;
        };
        let offered = held.session.has_local();
        let sibling = self
            .calls
            .iter()
            .find(|(handle, other)| **handle != call && other.invite == Some(invite))
            .map(|(handle, _)| *handle);
        if let Some(sibling) = sibling {
            if self.by_invite.get(&invite) == Some(&call) {
                self.by_invite.insert(invite, sibling);
            }
            return;
        }
        if self.endpoint.transaction_state(invite).is_some() {
            self.kept_branches.entry(invite).or_insert(KeptBranch {
                dialog: None,
                offered,
            });
        }
    }

    /// Keep why the far end's BYE or CANCEL says it is ending `call` (RFC
    /// 3326), for the end to be reported with.
    fn ended_because(&mut self, call: CallHandle, request: &OwnedMessage) {
        if let Some(held) = self.calls.get_mut(&call) {
            held.ended_by = Reason::all_in(&request.as_raw());
            held.ended_with = Some(request.clone());
        }
    }

    /// Who an incoming INVITE says is calling, behind the trust gate of the
    /// account it arrived for: RFC 3325 §8 has what the network asserts
    /// believed only from a peer that account trusts.
    fn identity_of(
        &self,
        account: Option<AccountId>,
        source: Option<SocketAddr>,
        request: &OwnedMessage,
    ) -> Option<Arc<CallIdentity>> {
        let trusted = account
            .and_then(|id| self.accounts.get(&id))
            .zip(source)
            .is_some_and(|(config, peer)| config.trusts(peer.ip()));
        CallIdentity::of_invite(request, trusted).map(Arc::new)
    }

    /// The account an incoming INVITE was addressed to, when it can be told.
    ///
    /// The Request-URI (this end's contact) beats the `To`: a forking proxy
    /// rewrites the Request-URI per line and leaves `To` alone (RFC 3261
    /// §16.6). Ties go to the arrival transport, then the source server. With
    /// no match, a line on the arrival flow whose contact has the
    /// Request-URI's user wins. No match at all does not refuse the call.
    pub(crate) fn line_for(&self, request: &RawMessage<'_>) -> Option<AccountId> {
        let target = request
            .request_uri_bytes()
            .and_then(|bytes| Uri::parse(bytes).ok());
        let record = request
            .to()
            .ok()
            .and_then(|to| Uri::parse(to.uri_bytes()).ok());
        let flow = self.guard.arrived_on();
        let source = self.guard.source();
        let named = |config: &Account| {
            target
                .as_ref()
                .is_some_and(|uri| config.contact.equivalent(uri))
        };
        let closeness = |config: &Account| {
            (
                named(config),
                flow.is_some_and(|transport| transport == config.transport),
                source.is_some_and(|peer| peer == config.remote),
            )
        };
        let best = |candidates: &mut dyn Iterator<Item = (&AccountId, &Account)>| {
            candidates
                .max_by(|(a, one), (b, other)| {
                    closeness(one)
                        .cmp(&closeness(other))
                        // oldest among equals, independent of map order
                        .then_with(|| b.cmp(a))
                })
                .map(|(id, _)| *id)
        };
        let addressed = best(&mut self.accounts.iter().filter(|(_, config)| {
            named(config)
                || record
                    .as_ref()
                    .is_some_and(|uri| config.aor.equivalent(uri))
        }));
        if addressed.is_some() {
            return addressed;
        }
        // a server that rewrote the host still names the registered user
        let user = target
            .as_ref()
            .and_then(|uri| uri.sip().and_then(|sip| sip.user.map(str::to_owned)))?;
        best(&mut self.accounts.iter().filter(|(_, config)| {
            flow.is_some_and(|transport| transport == config.transport)
                && config
                    .contact
                    .sip()
                    .and_then(|sip| sip.user)
                    .is_some_and(|own| own == user)
        }))
    }
}

/// What an INVITE says about who placed it, beyond `From`: the fields this
/// layer adds, and whether the application's own identity fields go.
struct Identifying {
    /// `Privacy` and `P-Asserted-Identity`, when the account asked for
    /// anonymity and the application wrote neither itself.
    added: Vec<(HeaderName<'static>, Box<[u8]>)>,
    /// The application's `P-Asserted-Identity`/`P-Preferred-Identity` are
    /// dropped: the INVITE leaves the account's trust domain.
    untrusted: bool,
}

impl Identifying {
    fn withheld(&self, name: &[u8]) -> bool {
        self.untrusted
            && (name.eq_ignore_ascii_case(b"P-Asserted-Identity")
                || name.eq_ignore_ascii_case(b"P-Preferred-Identity"))
    }
}

/// RFC 3323 and RFC 3325 for an INVITE from `config` to `remote`: the
/// account's `Privacy`, its identity asserted only toward a trusted peer
/// (§7), and the application's identity fields kept off a request leaving the
/// trust domain (§6). No trusted peer named means no trust domain.
fn identifying_fields(config: &Account, extra: &[Extra], remote: SocketAddr) -> Identifying {
    let trusted = config.trusts(remote.ip());
    let wrote = |name: &[u8]| extra.iter().any(|one| one.name.eq_ignore_ascii_case(name));
    let mut added = Vec::new();
    if config.privacy.requested() {
        if !wrote(b"Privacy")
            && let Some(value) = config.privacy.to_value()
        {
            added.push((PRIVACY, value.into_boxed_slice()));
        }
        if trusted && !wrote(b"P-Asserted-Identity") && !wrote(b"P-Preferred-Identity") {
            added.push((ASSERTED, config.sender_value()));
        }
    }
    Identifying {
        added,
        untrusted: !config.trusted.is_empty() && !trusted,
    }
}

/// `<uri>`, so its parameters are not read as the header field's.
fn bracketed(uri: &Uri) -> Box<[u8]> {
    let mut out = Vec::with_capacity(uri.as_bytes().len() + 2);
    out.push(b'<');
    out.extend_from_slice(uri.as_bytes());
    out.push(b'>');
    out.into_boxed_slice()
}

/// Whether a list of `Contact` feature parameters written by this crate names
/// `feature` (`;isfocus`, say), whole.
fn contains_feature(features: &[u8], feature: &[u8]) -> bool {
    features
        .split(|byte| *byte == b';')
        .any(|one| !one.is_empty() && feature.strip_prefix(b";") == Some(one))
}

/// A `From` or `To`'s display name, resolved (RFC 3261 §25.1), or empty when
/// it named none.
fn display_of(addr: &NameAddrRef<'_>) -> Box<[u8]> {
    addr.display_name()
        .map_or_else(|| Box::from(&b""[..]), |name| Box::from(name.as_ref()))
}

impl CallIdentity {
    /// Who is on the call an incoming INVITE opens, read from the INVITE
    /// alone, so it works after the call is gone (say, cancelled before the
    /// event was taken). `None` when `From`, `To` or `Call-ID` cannot be read.
    ///
    /// Read as untrusted: [`CallIdentity::caller`] carries no asserted
    /// identity. [`UaEvent::IncomingCall`]'s `identity` is the trusted read.
    #[must_use]
    pub fn of_request(request: &OwnedMessage) -> Option<Self> {
        Self::of_invite(request, false)
    }

    /// [`CallIdentity::of_request`], with `trusted` saying whether the
    /// INVITE came from a peer the account it arrived for trusts (RFC 3325
    /// §8).
    #[must_use]
    pub fn of_invite(request: &OwnedMessage, trusted: bool) -> Option<Self> {
        let raw = request.as_raw();
        let from = raw.from().ok()?;
        let to = raw.to().ok()?;
        Some(Self {
            from_uri: Box::from(from.uri_bytes()),
            from_display: display_of(&from),
            to_uri: Box::from(to.uri_bytes()),
            call_id: Box::from(raw.call_id().ok()?),
            caller: CallerIdentity::of_request(&raw, trusted),
            answering: Answering::of_request(&raw),
        })
    }
}

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
                self.on_established(invite, dialog, response, now);
                None
            }
            Event::Failed {
                invite,
                status,
                reason,
                ref response,
            } => self.on_call_failed(invite, status, reason, response.as_ref(), now),
            Event::Cancelled { invite } => {
                self.end_branches(invite, CallEndReason::Cancelled, None, None, now)
            }
            Event::CancelSent { invite, cancel } => {
                let call = self.by_invite.get(&invite).copied()?;
                self.remember_request(
                    call,
                    AnyTransactionId::NonInviteClient(cancel),
                    Method::Cancel,
                );
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
                self.forget_parked_in(dialog);
                self.on_dialog_over(dialog, reason, now)
            }
            Event::Challenged { transaction, .. } | Event::TokenChallenged { transaction, .. } => {
                if self.on_challenge_in_call(transaction, now) {
                    None
                } else {
                    Some(event)
                }
            }
            Event::Response {
                transaction,
                status,
                ..
            } => self.on_request_answered(transaction, status, event, now),
            Event::RequestFailed {
                transaction,
                reason,
            } => {
                let id = AnyTransactionId::NonInviteClient(transaction);
                let Some(&(call, _)) = self.by_request.get(&id) else {
                    return Some(event);
                };
                self.release_refer(id, false);
                // no response: §8.1.3.1 says what stands for one
                if let Some(status) = unanswered(reason) {
                    self.dtmf_info_over(id, call, status, now);
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
        // the INVITE transaction reports the same refusal and knows whether
        // the 487 was ours: wait for it
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
        // §5: an offer here is answered in the PRACK by the application;
        // anything else is PRACKed at once (§4)
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
        } else {
            self.prack_by_itself(call, provisional, now);
        }
    }

    /// The CANCEL lost its race and the call connected anyway.
    ///
    /// §13.2.2.4: ACK first, then hang up. A 2xx on any other branch after
    /// this one goes to [`UserAgent::let_go_late_branch`].
    fn on_cancel_lost(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
        now: Instant,
    ) {
        // other branches: `Established` follows and lets them go
        let Some(call) = self.branch(invite, Some(dialog)) else {
            return;
        };
        // a retransmitted 2xx while ACK and hangup wait for a stream
        // must not ask for another connection
        if self.ack_parked_in(dialog) {
            return;
        }
        let offered = self
            .calls
            .get(&call)
            .is_some_and(|held| held.session.has_local());
        self.kept_branches.entry(invite).or_insert(KeptBranch {
            dialog: Some(dialog),
            offered,
        });
        self.ack_by_itself(dialog, now);
        if let Some(held) = self.calls.get_mut(&call) {
            held.acknowledged = true;
            held.state = CallState::Confirmed;
        }
        self.hang_up_by_itself(call, now);
    }

    /// §8.2.2.3 then §8.2.3: an unsupported `Require` is refused 420 first,
    /// then an unreadable body or an `Accept` without SDP. `true` when the
    /// INVITE was refused.
    fn refuse_unreadable(
        &mut self,
        transaction: TransactionId<InviteServer>,
        request: &RawMessage<'_>,
        account_wants_gruu: bool,
        now: Instant,
    ) -> bool {
        let missing =
            crate::reliable::unsupported(request, account_wants_gruu, self.recording_server);
        if !missing.is_empty() {
            self.refuse_extension(transaction, &missing, now);
            return true;
        }
        // a recording session's multipart body is understood (§8.2.3)
        if self.recording_server && crate::siprec::session_part(request).is_some() {
            return false;
        }
        let Some(refusal) = crate::admission::content_refusal(request) else {
            return false;
        };
        self.endpoint
            .respond_invite(transaction, &refusal, now)
            .ok();
        true
    }

    /// The session description an INVITE offers: its body, or the SDP part
    /// of a recording session's to an agent that takes them.
    fn offer_in(&self, request: &RawMessage<'_>) -> Option<sdp::SessionDescription> {
        let described = self
            .recording_server
            .then(|| crate::siprec::session_part(request))
            .flatten()
            .unwrap_or(request.body());
        sdp::parse_with_limits(described, self.sdp_limits).ok()
    }

    /// The `Contact` a call that arrived for `account` answers with.
    ///
    /// For an INVITE addressed to no account, the address it arrived on.
    fn answering_contact(&self, account: Option<AccountId>) -> Box<[u8]> {
        account
            .and_then(|id| self.accounts.get(&id))
            .map(Account::contact_value)
            .or_else(|| {
                self.guard.arrival().map(|(address, protocol)| {
                    crate::contact::contact_for_arrival(address, protocol)
                })
            })
            .unwrap_or_else(|| Box::from(&b""[..]))
    }

    /// A request the far end sent inside a call, or one that starts one.
    fn on_incoming(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingInvite {
                transaction,
                ref request,
            } => {
                // found first: the Require check needs its GRUU setting
                let account = self.line_for(&request.as_raw());
                let account_wants_gruu = account
                    .and_then(|id| self.accounts.get(&id))
                    .is_some_and(Account::wants_gruu);
                if self.refuse_unreadable(transaction, &request.as_raw(), account_wants_gruu, now) {
                    return None;
                }
                // RFC 3891 §3: each way a Replaces fails has its own status
                let replaced = match self.replaced_by(request) {
                    Ok(replaced) => replaced,
                    Err(status) => {
                        self.refuse_replaces(transaction, status, now);
                        return None;
                    }
                };
                // RFC 4028 §9: refused with the floor; the far end asks again
                if Self::too_brief(&request.as_raw()) {
                    let refusal = OutgoingResponse::new(StatusCode::SESSION_INTERVAL_TOO_SMALL)
                        .header(HeaderName::MinSe, &crate::timers::seconds(FLOOR));
                    self.endpoint
                        .respond_invite(transaction, &refusal, now)
                        .ok();
                    return None;
                }
                // our local URI is the INVITE's `To` (RFC 3261 §12.1.1), not
                // the AOR: the caller may have dialled an alias. Kept for a
                // later `Referred-By` (RFC 3892 §2.2); URI only, the display
                // name is the far end's
                let from = request
                    .as_raw()
                    .to()
                    .ok()
                    .and_then(|to| Uri::parse(to.uri_bytes()).ok())
                    .map_or_else(|| Box::from(&b""[..]), |uri| bracketed(&uri));
                let plain = self.answering_contact(account);
                let source = self.guard.source();
                let identity = self.identity_of(account, source, request);
                let call = self.keep(Call::incoming(account, transaction, from, plain));
                if let Some(held) = self.calls.get_mut(&call) {
                    held.invited = Some(request.clone());
                    held.replaces = replaced;
                    (held.peer, held.identity) = (source, identity.clone());
                }
                self.by_server.insert(transaction, call);
                self.note_far_end(call, &request.as_raw());
                if let Some(offer) = self.offer_in(&request.as_raw())
                    && let Some(held) = self.calls.get_mut(&call)
                {
                    held.session.set_remote(offer);
                }
                self.deliver_incoming(call, account, request, identity, now);
                None
            }
            Event::IncomingCancel {
                invite,
                ref request,
            } => {
                let call = self.by_server.get(&invite).copied()?;
                self.ended_because(call, request);
                // the endpoint already sent the 200 and the 487 (§9.2)
                self.finish(call, CallEndReason::Cancelled, None, None, now);
                None
            }
            Event::IncomingAck {
                dialog,
                ref request,
            } => {
                let call = self.by_dialog.get(&dialog).copied()?;
                // re-INVITEs are acknowledged here too; confirm only once
                let first = self.calls.get(&call).is_some_and(|held| !held.acknowledged);
                if let Some(held) = self.calls.get_mut(&call) {
                    held.state = held.up();
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
                ref request,
            } => {
                let call = self.by_dialog.get(&dialog).copied()?;
                self.on_bye(call, transaction, request, now);
                None
            }
            other => Some(other),
        }
    }

    /// Tell the application a call has arrived: at once, or once its
    /// verdict is in where its account verifies callers (`crate::stir`).
    #[cfg(feature = "stir")]
    fn deliver_incoming(
        &mut self,
        call: CallHandle,
        account: Option<AccountId>,
        request: &OwnedMessage,
        identity: Option<Arc<CallIdentity>>,
        now: Instant,
    ) {
        self.screen_identity(call, account, request, identity, now);
    }

    #[cfg(not(feature = "stir"))]
    fn deliver_incoming(
        &mut self,
        call: CallHandle,
        account: Option<AccountId>,
        request: &OwnedMessage,
        identity: Option<Arc<CallIdentity>>,
        _now: Instant,
    ) {
        self.events.push_back(UaEvent::IncomingCall {
            call,
            account,
            request: request.clone(),
            identity,
        });
    }

    /// The far end hung up.
    fn on_bye(
        &mut self,
        call: CallHandle,
        transaction: TransactionId<NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        self.ended_because(call, request);
        // §15.1.2: always 200
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
            .ok();
        self.finish(call, CallEndReason::RemoteHangup, None, None, now);
    }

    /// The call a response on this INVITE belongs to, minting a sibling when
    /// the dialog it names is a second one.
    ///
    /// §13.2.2: one INVITE can open several dialogs, each a call of its own.
    fn branch(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: Option<DialogId>,
    ) -> Option<CallHandle> {
        // once a branch is kept, the others have nothing to report
        if let Some(dialog) = dialog
            && self
                .kept_branches
                .get(&invite)
                .is_some_and(|kept| kept.dialog != Some(dialog))
        {
            return None;
        }
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

    /// Record the session and capabilities a far-end response describes.
    fn note_session(&mut self, call: CallHandle, response: &OwnedMessage) {
        let raw = response.as_raw();
        self.note_far_end(call, &raw);
        if let Ok(described) = sdp::parse_with_limits(raw.body(), self.sdp_limits)
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

    /// An INVITE came back refused. Two of those are not what they look like.
    fn on_call_failed(
        &mut self,
        invite: TransactionId<InviteClient>,
        status: Option<StatusCode>,
        reason: FailureReason,
        response: Option<&OwnedMessage>,
        now: Instant,
    ) -> Option<Event> {
        // RFC 4028 §7.3: a 422 means retry with a longer interval
        if status.map(StatusCode::get) == Some(422)
            && let Some(call) = self.by_invite.get(&invite).copied()
            && let Some(refusal) = response
        {
            let refusal = refusal.clone();
            if self.on_session_too_brief(call, &refusal.as_raw(), now) {
                return None;
            }
        }
        let ended = match reason {
            FailureReason::Refused => CallEndReason::Refused,
            _ => CallEndReason::Unreachable,
        };
        // §22.2, §22.3: the core reports the refusal before the challenge;
        // keep the call for the retry
        if matches!(status.map(StatusCode::get), Some(401 | 407))
            && self.by_invite.contains_key(&invite)
        {
            self.challenged.insert(
                invite,
                Refusal {
                    reason: ended,
                    status,
                    response: response.cloned(),
                    waiting_for_stream: false,
                },
            );
            return None;
        }
        // RFC 3261 §8.1.3.4: try the next target a 3xx named
        if let Some(call) = self.by_invite.get(&invite).copied()
            && self.follow_redirect(call, invite, status, response, now)
        {
            return None;
        }
        self.end_branches(invite, ended, status, response, now)
    }

    /// A refusal that carried a challenge and got no retry was a refusal.
    ///
    /// The core answers a challenge once: a repeat without `stale` means a
    /// wrong password (§22.1), and retrying would lock the account.
    pub(crate) fn settle_call_challenges(&mut self, now: Instant) {
        let refused: Vec<(TransactionId<InviteClient>, Refusal)> =
            settled(&mut self.challenged, |refusal| refusal.waiting_for_stream);
        for (invite, refusal) in refused {
            self.end_branches(
                invite,
                refusal.reason,
                refusal.status,
                refusal.response.as_ref(),
                now,
            );
        }
    }

    /// The same, for the requests a call sends inside its dialog.
    pub(crate) fn settle_request_challenges(&mut self, now: Instant) {
        let refused: Vec<(AnyTransactionId, RequestRefusal)> =
            settled(&mut self.challenged_requests, |refusal| {
                refusal.waiting_for_stream
            });
        for (id, refusal) in refused {
            self.release_refer(id, false);
            self.by_request.remove(&id);
            self.account_of.remove(&id);
            // Only REFER and a DTMF INFO need an event here. A refused REFER
            // opens no subscription (RFC 3515 §2.4.2), so nothing else would
            // ever report it. BYE, CANCEL, PRACK and NOTIFY are reported by
            // the dialog ending, the INVITE's own path, or Timer B.
            if refusal.method == Method::Refer
                && let Some(status) = refusal.status
            {
                self.events.push_back(UaEvent::TransferDone {
                    call: refusal.call,
                    status,
                });
            }
            if refusal.method == Method::Info
                && let Some(status) = refusal.status
            {
                self.dtmf_info_over(id, refusal.call, status, now);
            }
            self.by_dtmf_info.remove(&id);
        }
    }

    /// End every branch of one INVITE.
    ///
    /// A refusal names the transaction, which may have opened several dialogs
    /// through a fork.
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

    /// A 2xx for one of our INVITEs. One on a branch other than the kept one
    /// is let go before it becomes a call.
    fn on_established(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
        response: &OwnedMessage,
        now: Instant,
    ) {
        if self.let_go_late_branch(invite, dialog, now) {
            return;
        }
        if let Some(call) = self.branch(invite, Some(dialog)) {
            self.on_answered(call, dialog, response, now);
        }
    }

    /// A 2xx for one of our INVITEs.
    fn on_answered(
        &mut self,
        call: CallHandle,
        dialog: DialogId,
        response: &OwnedMessage,
        now: Instant,
    ) {
        // a retransmitted 2xx while its ACK waits for a stream
        if self.ack_parked_in(dialog) {
            return;
        }
        let Some(held) = self.calls.get(&call) else {
            return;
        };
        // `on_cancel_lost` already acknowledged it and hung up
        if held.acknowledged {
            return;
        }
        let (offered, forks, invite) = (held.session.has_local(), held.forks, held.invite);
        // hung up before any branch answered: keep nothing
        let giving_up = held.hangup_wanted
            || invite
                .and_then(|invite| self.by_invite.get(&invite))
                .and_then(|placed| self.calls.get(placed))
                .is_some_and(|placed| placed.hangup_wanted);
        // the first answer is recorded even when giving up, so later ones are
        // let go (`let_go_late_branch`)
        let kept = match invite {
            Some(invite) if giving_up => {
                self.kept_branches.entry(invite).or_insert(KeptBranch {
                    dialog: Some(dialog),
                    offered,
                });
                None
            }
            Some(invite) if forks == ForkPolicy::KeepFirst => {
                self.keep_branch(call, invite, dialog, offered);
                Some(invite)
            }
            _ => None,
        };
        self.note_session(call, response);
        self.on_timer_answer(call, &response.as_raw(), now);

        // §13.2.2.4: ACK now unless it must carry the application's answer.
        // An ACK held for a stream (§18.1.1) is still ours to send
        let acknowledged = offered && self.ack_by_itself(dialog, now);
        if let Some(held) = self.calls.get_mut(&call) {
            held.acknowledged = acknowledged;
            held.state = held.up();
        }

        self.events.push_back(UaEvent::CallConfirmed {
            call,
            response: Some(response.clone()),
            answer_wanted: !acknowledged,
        });
        self.report_transfer(call, StatusCode::OK, now);
        // after `CallConfirmed`, so the facade can move state to the kept
        // branch before the others end
        if let Some(invite) = kept {
            self.let_go_other_branches(call, invite, now);
        }
        if giving_up {
            self.hang_up_by_itself(call, now);
        }
    }

    /// [`ForkPolicy::KeepFirst`] keeps the first branch to answer. When that
    /// is a sibling, the placed call's transfer and consultation links move
    /// onto it.
    fn keep_branch(
        &mut self,
        call: CallHandle,
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
        offered: bool,
    ) {
        self.kept_branches.insert(
            invite,
            KeptBranch {
                dialog: Some(dialog),
                offered,
            },
        );
        let Some(placed) = self.calls.get(&call).and_then(|held| held.forked_from) else {
            return;
        };
        self.by_invite.insert(invite, call);
        let (reporting_to, consulting_for) = self
            .calls
            .get_mut(&placed)
            .map(|held| (held.reporting_to.take(), held.consulting_for.take()))
            .unwrap_or_default();
        if let Some(held) = self.calls.get_mut(&call) {
            held.reporting_to = reporting_to;
            held.consulting_for = consulting_for;
        }
        for other in self.calls.values_mut() {
            if other.consulting == Some(placed) {
                other.consulting = Some(call);
            }
            if let Some(referred) = other.referred.as_mut()
                && referred.placed == Some(placed)
            {
                referred.placed = Some(call);
            }
        }
    }

    /// End every branch but the kept one; the proxy cancels them (RFC 3261
    /// §16.7 step 10). A late 2xx on one goes to
    /// [`UserAgent::let_go_late_branch`].
    fn let_go_other_branches(
        &mut self,
        kept: CallHandle,
        invite: TransactionId<InviteClient>,
        now: Instant,
    ) {
        let others: Vec<CallHandle> = self
            .calls
            .iter()
            .filter(|(handle, held)| **handle != kept && held.invite == Some(invite))
            .map(|(handle, _)| *handle)
            .collect();
        for other in others {
            self.finish(other, CallEndReason::ForkLost, None, None, now);
        }
    }

    /// A 2xx on a branch other than the one [`ForkPolicy::KeepFirst`] kept,
    /// or than the first to answer a call the user had put down. `true` when
    /// it was one, and has been dealt with.
    ///
    /// §13.2.2.4: ACK, then BYE, with no event. A 2xx carrying the offer would
    /// need the application's answer in the ACK, so it is left for its sender
    /// to give up on (§13.3.1.4).
    fn let_go_late_branch(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
        now: Instant,
    ) -> bool {
        let Some(kept) = self.kept_branches.get(&invite).copied() else {
            return false;
        };
        if kept.dialog == Some(dialog) {
            return false;
        }
        // a retransmission; the BYE already waits behind the ACK
        if self.ack_parked_in(dialog) {
            return true;
        }
        // RFC 3326 §3.1: "call completed elsewhere"
        if kept.offered && self.ack_by_itself(dialog, now) {
            self.bye_by_itself_for(dialog, Some(&Reason::completed_elsewhere()), now);
        }
        true
    }

    /// Remember a request this layer sent inside a call.
    ///
    /// The account is kept apart from the call: a BYE outlives its call and
    /// may still be challenged.
    pub(crate) fn remember_request(
        &mut self,
        call: CallHandle,
        id: AnyTransactionId,
        method: Method<'static>,
    ) {
        self.by_request.insert(id, (call, method));
        if let Some(account) = self.calls.get(&call).and_then(|held| held.account) {
            self.account_of.insert(id, account);
        }
    }

    /// A challenge to something this layer sent. `true` when it was ours.
    fn on_challenge_in_call(&mut self, transaction: AnyTransactionId, now: Instant) -> bool {
        match transaction {
            // a re-INVITE belongs to the session layer
            AnyTransactionId::InviteClient(invite) => {
                let Some(call) = self.by_invite.get(&invite).copied() else {
                    return false;
                };
                self.on_call_challenged(call, transaction, now);
                true
            }
            // an UPDATE is not in this map and goes to the session layer
            AnyTransactionId::NonInviteClient(_) if self.by_request.contains_key(&transaction) => {
                self.on_request_challenged(transaction, now);
                true
            }
            _ => false,
        }
    }

    /// BYE, CANCEL, PRACK, REFER or NOTIFY inside a call was challenged
    /// (§22.2).
    fn on_request_challenged(&mut self, transaction: AnyTransactionId, now: Instant) {
        let Some((call, method)) = self.by_request.get(&transaction).copied() else {
            return;
        };
        let account = self.account_of.get(&transaction).copied();
        let credentials = self.credentials_for_challenge(account, transaction);
        // no password: a REFER gives its seat back, as no subscription was
        // opened (RFC 3515 §2.4.2); a no-op for other methods
        let Some(credentials) = credentials else {
            self.release_refer(transaction, false);
            return;
        };
        let retried = match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => retried,
            // waiting for a stream (§18.1.1): the seat stays
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let Some(parked) = self.challenged_requests.get_mut(&transaction) {
                    parked.waiting_for_stream = true;
                }
                return;
            }
            Err(_) => {
                self.release_refer(transaction, false);
                return;
            }
        };
        self.request_retry_went(call, method, transaction, retried, account);
    }

    /// The in-dialog retry is a transaction now, so everything that named the
    /// refused one names this one.
    fn request_retry_went(
        &mut self,
        call: CallHandle,
        method: Method<'static>,
        transaction: AnyTransactionId,
        retried: AnyTransactionId,
        account: Option<AccountId>,
    ) {
        self.challenged_requests.remove(&transaction);
        self.by_request.remove(&transaction);
        self.account_of.remove(&transaction);
        if let Some(digit) = self.by_dtmf_info.remove(&transaction) {
            self.by_dtmf_info.insert(retried, digit);
        }
        self.by_request.insert(retried, (call, method));
        if let Some(account) = account {
            self.account_of.insert(retried, account);
        }
        // the REFER is the one of these the call holds a seat for, and the
        // seat has to follow it or a transfer can never be asked for again
        if !self
            .calls
            .get(&call)
            .is_some_and(|held| held.referring == Some(transaction))
        {
            return;
        }
        // the retry has a new CSeq, and RFC 3515 §2.4.6 names the
        // subscription by it
        let id = self
            .calls
            .get(&call)
            .and_then(|held| held.dialog)
            .and_then(|dialog| self.endpoint.dialog(dialog))
            .and_then(|snapshot| snapshot.local_seq);
        if let Some(held) = self.calls.get_mut(&call) {
            held.referring = Some(retried);
            if let Some(subscription) = held.refer_subscription.as_mut() {
                subscription.id = id;
            }
        }
    }

    /// A REFER that will never open a subscription has been answered, so the
    /// call is free to ask again.
    ///
    /// On a 2xx (`accepted`) the seat stays: the far end opened a
    /// subscription (RFC 3515 §2.4.2), and `on_notify` frees it on the
    /// terminating NOTIFY (§2.4.7). A refusal opened none, so it is freed here.
    fn release_refer(&mut self, id: AnyTransactionId, accepted: bool) {
        if accepted {
            return;
        }
        let Some(call) = self.by_request.get(&id).map(|(call, _)| *call) else {
            return;
        };
        if let Some(held) = self.calls.get_mut(&call)
            && held.referring == Some(id)
        {
            held.referring = None;
            held.refer_subscription = None;
        }
    }

    /// A REFER of ours was refused or gave up while holding its seat: no
    /// NOTIFY will follow (RFC 3515 §2.4.2), so [`UaEvent::TransferDone`]
    /// reports it. Told once; a no-op for other requests.
    fn refer_refused(&mut self, id: AnyTransactionId, status: StatusCode) {
        let Some(&(call, method)) = self.by_request.get(&id) else {
            return;
        };
        if method != Method::Refer
            || !self
                .calls
                .get(&call)
                .is_some_and(|held| held.referring == Some(id))
        {
            return;
        }
        self.events
            .push_back(UaEvent::TransferDone { call, status });
    }

    /// Report a DTMF INFO's outcome once, whichever path gets here first, and
    /// move the [`UserAgent::send_dtmf_info`] queue on.
    fn dtmf_info_over(
        &mut self,
        id: AnyTransactionId,
        call: CallHandle,
        status: StatusCode,
        now: Instant,
    ) {
        let Some(digit) = self.by_dtmf_info.remove(&id) else {
            return;
        };
        self.events.push_back(UaEvent::DtmfSent {
            call,
            digit,
            status,
        });
        self.continue_dtmf_queue(call, status, now);
    }

    /// On a 2xx the next queued digit goes out; anything else drops the rest
    /// rather than send it out of order.
    fn continue_dtmf_queue(&mut self, call: CallHandle, status: StatusCode, now: Instant) {
        if !status.is_success() {
            self.dtmf_queue.remove(&call);
            return;
        }
        let Some(queue) = self.dtmf_queue.get_mut(&call) else {
            return;
        };
        // the entry stays while a digit is in flight, so new keys queue
        let Some(next) = queue.waiting.pop_front() else {
            self.dtmf_queue.remove(&call);
            return;
        };
        let digit = char::from(next.key);
        if self.send_one_dtmf_info(call, next, now).is_err() {
            self.dtmf_queue.remove(&call);
            // never sent: nothing else would report it (§8.1.3.1)
            self.events.push_back(UaEvent::DtmfSent {
                call,
                digit,
                status: StatusCode::SERVICE_UNAVAILABLE,
            });
        }
    }

    /// A proxy challenged an INVITE. The account has the password.
    fn on_call_challenged(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        now: Instant,
    ) {
        let account = self.calls.get(&call).and_then(|held| held.account);
        let Some(credentials) = self.credentials_for_challenge(account, transaction) else {
            return;
        };
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(AnyTransactionId::InviteClient(retried)) => {
                self.call_retry_went(call, transaction, retried);
            }
            // waiting for a connection (§18.1.1): still being placed
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let AnyTransactionId::InviteClient(old) = transaction
                    && let Some(parked) = self.challenged.get_mut(&old)
                {
                    parked.waiting_for_stream = true;
                }
            }
            // the settle pass reports the refusal
            Ok(_) | Err(_) => {}
        }
    }

    /// The retry is a transaction now, so everything that named the refused
    /// one names this one.
    pub(crate) fn call_retry_went(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        retried: TransactionId<InviteClient>,
    ) {
        if let AnyTransactionId::InviteClient(old) = transaction {
            self.by_invite.remove(&old);
            self.challenged.remove(&old);
        }
        self.by_invite.insert(retried, call);
        if let Some(held) = self.calls.get_mut(&call) {
            held.invite = Some(retried);
            held.state = CallState::Calling;
        }
    }

    /// Send the INVITE retries §18.1.1 held back, now that there is a
    /// connection.
    pub(crate) fn resume_parked_calls(&mut self, now: Instant) {
        let waiting: Vec<TransactionId<InviteClient>> = self
            .challenged
            .iter()
            .filter(|(_, refusal)| refusal.waiting_for_stream)
            .map(|(invite, _)| *invite)
            .collect();
        for invite in waiting {
            let old = AnyTransactionId::InviteClient(invite);
            let Some(call) = self.by_invite.get(&invite).copied() else {
                self.stop_waiting_for_call(invite);
                continue;
            };
            let account = self.calls.get(&call).and_then(|held| held.account);
            let Some(credentials) = self.credentials_for_challenge(account, old) else {
                self.stop_waiting_for_call(invite);
                continue;
            };
            match self.endpoint.retry_with_credentials(old, &credentials, now) {
                Ok(AnyTransactionId::InviteClient(retried)) => {
                    self.call_retry_went(call, old, retried);
                }
                Err(error) if crate::agent::wants_a_stream(&error) => {}
                // anything else leaves it for the settle pass to report
                Ok(_) | Err(_) => self.stop_waiting_for_call(invite),
            }
        }
    }

    /// The same for the requests inside a dialog.
    pub(crate) fn resume_parked_requests(&mut self, now: Instant) {
        let waiting: Vec<(AnyTransactionId, CallHandle, Method<'static>)> = self
            .challenged_requests
            .iter()
            .filter(|(_, parked)| parked.waiting_for_stream)
            .map(|(id, parked)| (*id, parked.call, parked.method))
            .collect();
        for (id, call, method) in waiting {
            let account = self.account_of.get(&id).copied();
            let Some(credentials) = self.credentials_for_challenge(account, id) else {
                self.stop_waiting_for_request(id);
                continue;
            };
            match self.endpoint.retry_with_credentials(id, &credentials, now) {
                Ok(retried) => self.request_retry_went(call, method, id, retried, account),
                Err(error) if crate::agent::wants_a_stream(&error) => {}
                Err(_) => self.stop_waiting_for_request(id),
            }
        }
    }

    /// Stop holding one back, so the next settle reports the refusal it still
    /// carries.
    fn stop_waiting_for_call(&mut self, invite: TransactionId<InviteClient>) {
        if let Some(parked) = self.challenged.get_mut(&invite) {
            parked.waiting_for_stream = false;
        }
    }

    /// The same, for a request inside a dialog.
    fn stop_waiting_for_request(&mut self, id: AnyTransactionId) {
        if let Some(parked) = self.challenged_requests.get_mut(&id) {
            parked.waiting_for_stream = false;
        }
    }

    /// A request this layer sent inside a call was answered.
    ///
    /// A refused REFER frees the call to try again; anything not ours is
    /// returned untouched.
    fn on_request_answered(
        &mut self,
        transaction: TransactionId<NonInviteClient>,
        status: StatusCode,
        event: Event,
        now: Instant,
    ) -> Option<Event> {
        let id = AnyTransactionId::NonInviteClient(transaction);
        let Some(&(call, method)) = self.by_request.get(&id) else {
            return Some(event);
        };
        // parked: a refusal only if no retry follows in this drain
        if matches!(status.get(), 401 | 407) {
            self.challenged_requests.insert(
                id,
                RequestRefusal {
                    call,
                    method,
                    status: Some(status),
                    waiting_for_stream: false,
                },
            );
            return None;
        }
        if status.is_final() {
            if !status.is_success() {
                self.refer_refused(id, status);
            }
            self.release_refer(id, status.is_success());
            // the one answer here the application is owed
            if method == Method::Info {
                self.dtmf_info_over(id, call, status, now);
            }
        }
        None
    }

    /// A transaction has ended.
    fn on_transaction_over(
        &mut self,
        transaction: AnyTransactionId,
        reason: TerminationReason,
        now: Instant,
    ) {
        let failed = match reason {
            TerminationReason::TimedOut => unanswered(FailureReason::Timeout),
            TerminationReason::TransportFailed => unanswered(FailureReason::TransportFailed),
            _ => None,
        };
        // an unanswered REFER frees its seat and reports 408/503 (§8.1.3.1).
        // Before `by_request` forgets the call: the core raises this before
        // `RequestFailed` on the timer and transport paths
        if let Some(status) = failed {
            self.refer_refused(transaction, status);
            self.release_refer(transaction, false);
        }
        // an incoming REFER nobody answered; the endpoint sent 408
        if let AnyTransactionId::NonInviteServer(server) = transaction {
            self.forget_unanswered_refer(server);
        }
        let call = self.by_request.remove(&transaction).map(|(call, _)| call);
        self.account_of.remove(&transaction);
        match (call, failed) {
            (Some(call), Some(status)) => self.dtmf_info_over(transaction, call, status, now),
            // still parked: `settle_request_challenges` reports it (Timer K
            // is zero on reliable transports)
            _ if self.challenged_requests.contains_key(&transaction) => {}
            _ => {
                self.by_dtmf_info.remove(&transaction);
            }
        }
        // the answer window has closed (RFC 6026 §7.2)
        if let AnyTransactionId::InviteClient(invite) = transaction {
            self.kept_branches.remove(&invite);
        }
        let AnyTransactionId::InviteServer(id) = transaction else {
            // client INVITEs keep their mapping: a late fork 2xx may follow
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
    /// §13.3.1.4 and §14.2: send a BYE to end the dialog.
    fn on_unacknowledged(&mut self, id: TransactionId<InviteServer>, now: Instant) {
        let Some(call) = self
            .calls
            .iter()
            .find(|(_, held)| held.awaiting_ack == Some(id))
            .map(|(handle, _)| *handle)
        else {
            // a non-2xx: no dialog to end
            return;
        };
        let dialog = self.calls.get(&call).and_then(|held| held.dialog);
        if let Some(held) = self.calls.get_mut(&call) {
            held.awaiting_ack = None;
        }
        if let Some(dialog) = dialog {
            self.bye_by_itself(dialog, now);
        }
        // before the BYE's dialog event, so the reason is Unreachable
        self.finish(call, CallEndReason::Unreachable, None, None, now);
    }
}

/// RFC 3261 §8.1.3.1: a timeout counts as 408, a transport error as 503.
/// `None` for a real response.
const fn unanswered(reason: FailureReason) -> Option<StatusCode> {
    match reason {
        FailureReason::Timeout => Some(StatusCode::REQUEST_TIMEOUT),
        FailureReason::TransportFailed => Some(StatusCode::SERVICE_UNAVAILABLE),
        // non-exhaustive across crate versions; a refusal carried its own code
        FailureReason::Refused | _ => None,
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
