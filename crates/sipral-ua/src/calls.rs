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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use sipral_core::dialog::CallId;
use sipral_core::endpoint::{
    DialogEndReason, Event, FailureReason, OutgoingInDialogRequest, OutgoingRequest,
    OutgoingResponse, PrackError, TerminationReason,
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
///
/// Draining the lot, which is what these used to do, turns a retry waiting on
/// a socket into a refusal reported in the same breath as the request for the
/// socket.
fn settled<K, V>(parked: &mut HashMap<K, V>, waiting: impl Fn(&V) -> bool) -> Vec<(K, V)>
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
        // before anything is kept or built, so a refused field leaves no call
        // behind and nothing on the wire
        HeadersFor::Call.check_each(&outgoing.extra)?;
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
        let from = config.caller_value();
        let identifying = identifying_fields(config, &outgoing.extra, remote);
        // read fresh rather than kept from when the call was placed (RFC 5627
        // §4.4 forbids naming a GRUU once the registration that issued it is
        // gone), which is why a 422 asked again on the same handle still comes
        // through here rather than repeating a value from the first attempt
        let (call_id, cseq, asked) = {
            let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            (held.id.clone(), held.cseq, held.asked)
        };
        let contact = self.current_contact(call, now);
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
        // RFC 3608 §6.1: the service route is "a preloaded Route header field
        // in outgoing initial requests", and "the UA MUST preserve the order"
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
                // RFC 7866 §6.1: "An SRC MUST include the "siprec" option tag
                // in the Require header when initiating an RS", and §9.1 the
                // offer and the metadata as one multipart/mixed body
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
            // where this call's signalling goes, which is what a `Replaces`
            // naming it is measured against (RFC 3891 §3)
            held.peer = Some(remote);
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
        let limits = self.sdp_limits;
        let status = if early.is_some() {
            StatusCode::SESSION_PROGRESS
        } else {
            StatusCode::RINGING
        };
        let contact = self.current_contact(call, now);
        let mut response = onto_response(
            OutgoingResponse::new(status)
                .contact(&contact)
                .header(HeaderName::Allow, ALLOW),
            &self.application_headers(call),
        );
        if self.wants_gruu(call) {
            // RFC 5627 §4.4 SHOULD: "a 2xx or 18x response to an INVITE which
            // contains a To tag" is among the responses that carry it
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
        // the INVITE's server transaction outlives its 2xx by 64*T1 (RFC 6026
        // §7.1, Accepted), and a second 2xx through it would be sent, and would
        // put a call that is up back to waiting for an ACK that already came:
        // a call answered once is refused here, not answered again
        if let Some(held) = self.calls.get(&call)
            && (held.awaiting_ack.is_some() || held.acknowledged)
        {
            return Err(UaError::WrongState(held.state));
        }
        // RFC 3262 §5: a reliable provisional that carried a description holds
        // the 2xx until it is acknowledged, or two unanswered offers are on the
        // wire at once and nothing says which the answer belongs to
        if self.answer_is_held(call) {
            self.hold_answer(call, sdp);
            return Ok(());
        }
        let transaction = self.answerable(call)?;
        let limits = self.sdp_limits;
        let contact = self.current_contact(call, now);
        let mut supported: Vec<u8> = b"timer".to_vec();
        // RFC 5627 §4.4 SHOULD, folded in beside `timer`: "a 2xx ... response
        // to an INVITE which contains a To tag" is among what carries it
        if self.wants_gruu(call) {
            supported.extend_from_slice(b", gruu");
        }
        // RFC 3311 §4: "a 2xx response SHOULD contain an Allow header field
        // listing the UPDATE method"
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
                // §9: refresher=uac obliges the UAS to say the far end has to
                // understand this, because it is the one that has to act
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
        let headers = self.application_headers(call);
        self.refuse(call, status, &headers, now)
    }

    /// Answer a call that came in with a 3xx: somewhere else to try
    /// (RFC 3261 §21.3), and, when the [`Redirect`] says why, a `Diversion`
    /// naming this end as the party that diverted the call (RFC 5806).
    ///
    /// The `Contact` lists every target the redirect names, each with its
    /// `q` when one was given. The `Diversion` names the address the call
    /// was made to — the INVITE's `To` — with the reason and `counter=1`,
    /// and the `Diversion` values the INVITE already carried follow it,
    /// most recent first, so the next phone sees the whole chain. The
    /// application's own header fields ride along as they do on a refusal.
    ///
    /// # Errors
    /// [`UaError::NotARedirection`] for a redirect that names nowhere to go
    /// with any status but 380 (Alternative Service, whose alternative is in
    /// the body rather than a `Contact`); otherwise as [`UserAgent::reject`].
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
    /// RFC 3262 §5: "If the UAC receives an offer in a reliable provisional
    /// response, it MUST generate an answer in the PRACK." Only for a call
    /// placed without an offer, which is the one case a provisional carries
    /// one, and reported by `answer_wanted` on
    /// [`UaEvent::CallProgress`](crate::UaEvent::CallProgress).
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when nothing is
    /// waiting for one, or [`UaError::Sdp`]. [`UaError::Send`] when the PRACK
    /// is too large for a datagram and no stream is open (RFC 3261 §18.1.1):
    /// the answer is still owed, and the same call sends it once the stream
    /// the endpoint asked for is bound.
    pub fn answer_early(
        &mut self,
        call: CallHandle,
        sdp: &[u8],
        now: Instant,
    ) -> Result<(), UaError> {
        let described = sdp::parse_with_limits(sdp, self.sdp_limits).map_err(UaError::Sdp)?;
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
    /// A CANCEL while the INVITE this end sent is unanswered (§9.1, held by the
    /// endpoint until the first provisional response if it has to be), a BYE
    /// once the call is up, and a refusal for one that came in and has not
    /// been answered. A call that is already ending is left alone.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], or the error of whatever it turned into.
    pub fn hangup(&mut self, call: CallHandle, now: Instant) -> Result<(), UaError> {
        let headers = self.application_headers(call);
        self.end_call(call, &headers, &[], now)
    }

    /// [`UserAgent::hangup`], saying why (RFC 3326).
    ///
    /// `reasons` go in a `Reason` field on the BYE or the CANCEL the hangup
    /// turns into, one value per protocol — a later value of a protocol
    /// already given is left out, since §2 allows one each. On the refusal
    /// of a call that came in and was never answered, only the Q.850
    /// values go: RFC 6432 lets those ride on any response, and a SIP one
    /// would repeat the status the refusal already carries.
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

    /// [`UserAgent::hangup`], carrying `headers` on the refusal or the BYE it
    /// turns into: the application's own when it asked, none when this layer
    /// decided by itself. A CANCEL carries none either way (§16.10).
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
                // §9.1: a CANCEL may not go before a provisional response has
                // arrived, and the endpoint holds it until one does. Asking
                // too early is not a failure and needs no timer here
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

    /// Every call this agent still holds, in handle order — for a report of
    /// the whole agent, such as a crash report's state snapshot.
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

    /// Whether this end has a session description of its own on record for
    /// this call — for one that came in, whether [`UserAgent::ring`] or
    /// [`UserAgent::answer`] has already sent one that parsed.
    ///
    /// What a layer that writes an early answer of its own has to ask first.
    /// RFC 3261 §13.2.1 allows only "that same exact answer" in any other
    /// response to one INVITE, and RFC 6337 §3.1.1 has every description in
    /// those responses identical, so a call whose provisional response
    /// already carried bytes somebody else wrote cannot be given a second,
    /// different one.
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

    /// Whether this end placed the call or answered it, which is what
    /// decides which of [`CallIdentity`]'s two URIs is this end's own and
    /// which is the far end's.
    #[must_use]
    pub fn call_direction(&self, call: CallHandle) -> Option<Direction> {
        self.calls.get(&call).map(|held| held.direction)
    }

    /// The `From` and `To` of the request that opened this call, and its
    /// `Call-ID`.
    ///
    /// `None` once the call is gone: read it while the call is still known,
    /// not from a report that arrives after it no longer is. A branch a fork
    /// produced answers with its parent's own, read before either had one, for
    /// the same reason a sibling shares the request that opened it rather than
    /// carrying its own copy.
    #[must_use]
    pub fn call_identity(&self, call: CallHandle) -> Option<CallIdentity> {
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
    /// They go on the 180 or 183 from [`UserAgent::ring`], on the 200 from
    /// [`UserAgent::answer`] whether RFC 3262 §5 holds it back or not, on the
    /// refusal from [`UserAgent::reject`], on the refusal or the BYE a
    /// [`UserAgent::hangup`] turns into, and on the re-INVITE or UPDATE that
    /// [`UserAgent::hold`], [`UserAgent::resume`] and [`UserAgent::reoffer`]
    /// send, the retry after a 491 included. Kept rather than spent on the
    /// first of those: an application that labels a call labels all of it,
    /// and a label spent on a provisional response that left first is a label
    /// silently missing from the 200 that mattered.
    ///
    /// Not on a CANCEL, which is hop by hop: a proxy answers it and sends its
    /// own to every branch (RFC 3261 §16.10), so nothing written on it reaches
    /// the far end. Not on the answer to a change the far end offered, which
    /// belongs to the far end's request. And not on anything this layer sends
    /// by itself — a session refresh, the BYE for a 2xx that was never
    /// acknowledged, for a fork that lost or for a hangup whose CANCEL lost
    /// the race — because a field the application wrote is the application
    /// speaking, on a message it asked for.
    ///
    /// Replaces what was set before, whole; an empty list takes every field
    /// off. Every field is checked first ([`crate::HeadersFor::Call`]), and a
    /// refusal keeps none of the new ones and leaves the old ones in place.
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

    /// The fields the application wants on what it sends for a call, copied
    /// out so that the call can be borrowed again while they are written.
    pub(crate) fn application_headers(&self, call: CallHandle) -> Vec<Extra> {
        self.calls
            .get(&call)
            .map(|held| held.headers.clone())
            .unwrap_or_default()
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

    /// The `Contact` this call names right now: this account's public GRUU
    /// while it is registered and issued, its temporary one on an anonymous
    /// call, or the plain contact when neither is current.
    ///
    /// Read fresh on every request and response a call builds rather than
    /// kept from when the dialog opened, because RFC 5627 §4.4 forbids naming
    /// a GRUU once the registration that issued it has expired or been
    /// removed — which a re-INVITE, a session-timer `UPDATE`, a REFER or a
    /// NOTIFY sent long into a call would otherwise do by repeating the
    /// `Contact` the INVITE opened with. Subscriptions already read theirs
    /// this way; this is the same read for a call.
    ///
    /// The call's feature parameters (`isfocus`, `+sip.src`) follow whichever
    /// address it is: they say what the dialog is, which does not change with
    /// the registration.
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
    /// call belongs to (RFC 4579 §4.2): `isfocus` in the `Contact` of every
    /// request and response the call sends from here on — the answer to an
    /// INVITE not yet answered, and the next re-INVITE or UPDATE, which is
    /// how a far end already talking to this end learns it (a target
    /// refresh, RFC 3261 §12.2).
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

    /// Take recording sessions (RFC 7866 §6.2): the `siprec` option tag an
    /// SRC's INVITE requires is answered rather than refused 420, which is
    /// what this agent does with a tag it does not implement (RFC 3261
    /// §8.2.2.3). The recording session then arrives as an ordinary
    /// [`UaEvent::IncomingCall`]; [`crate::siprec::read_recording_offer`]
    /// reads its offer and metadata, and §6.2's other half — that its
    /// `Contact` carries `+sip.src` — is
    /// [`crate::siprec::contact_has_feature_tag`].
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

    /// The conference the call belongs to, when its far end is a focus: the
    /// URI of the far end's `Contact`, which carried `isfocus` (RFC 4579
    /// §4.2: "the resulting dialog belongs to a conference, identified by the
    /// URI in the Contact header field"). `None` for every other call.
    #[must_use]
    pub fn call_conference(&self, call: CallHandle) -> Option<Uri> {
        self.calls.get(&call)?.remote_focus.clone()
    }

    /// Subscribe to the conference package of the call's focus (RFC 4579
    /// §3.4: a conference-aware UA "SHOULD subscribe to the conference
    /// package if the 'isfocus' parameter is in the remote target URI of a
    /// dialog"), outside the call's dialog as §3.4 asks, from the call's own
    /// account. The subscription outlives the call; it is kept like any
    /// other, and [`UaEvent::ConferenceChanged`] says what it learns.
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
    /// `gruu` folded into their `Supported` when this call's account has asked
    /// for GRUUs — RFC 5627 §4.4 SHOULD: "a UA SHOULD include a Supported
    /// header field with the option tag gruu in requests and responses it
    /// generates".
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

    /// Whether the account this call belongs to has asked its registrar for
    /// GRUUs (RFC 5627 §4.1), which decides whether `Supported: gruu` goes on
    /// what this call sends and answers.
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
        // the BYE's or the CANCEL's own, kept when it arrived; otherwise
        // whatever the refusal carried (RFC 6432)
        let mut causes = core::mem::take(&mut held.ended_by);
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
            causes,
        });
        // §2.4.7 makes the closing NOTIFY the last word on a transfer, and
        // that is owed whether the referred call was answered or not: a
        // refusal reports the status that refused it, and one that never got
        // an answer at all -- Timer B, a transport failure, this end giving
        // up on its own -- has none to report, so it is the 408 a transaction
        // that gave up on itself would have carried (RFC 3261 §21.4.9).
        // `report_transfer` is a no-op for a call nothing REFERred, so this
        // runs unconditionally rather than only after `on_call_failed`.
        // Before `forget`: that call removes the record `report_transfer`
        // reads to find who is owed the NOTIFY.
        let reported = status.unwrap_or(match StatusCode::new(408) {
            Ok(timeout) => timeout,
            Err(_) => StatusCode::SERVER_ERROR,
        });
        self.report_transfer(call, reported, now);
        // Before `forget`, for the same reason `report_transfer` is: an
        // account that asked for an RFC 6035 quality report is answered by
        // the facade above this crate reacting to the `CallEnded` event just
        // queued, and by then `forget` has already taken the account and
        // identity that report needs off this call (`quality_report.rs`).
        self.stash_ended_call(call);
        self.forget(call);
    }

    /// The session timer ran out and nobody refreshed it (RFC 4028 §10).
    pub(crate) fn finish_expired(&mut self, call: CallHandle, now: Instant) {
        self.finish(call, CallEndReason::Expired, None, None, now);
    }

    fn forget(&mut self, call: CallHandle) {
        for other in self.calls.values_mut() {
            if other.consulting == Some(call) {
                other.consulting = None;
            }
            // the call it was placed to be handed to is gone, so there is
            // nobody left to hand it to: an ordinary call from here on
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
        // a digit still waiting behind the one in flight has nowhere left to
        // go once the call is gone; without this a late 2xx to that last
        // INFO would otherwise find the queue and try to send into a call
        // `send_one_dtmf_info` can no longer find either -- harmless, but a
        // queue nothing will ever empty again is a leak for the life of the
        // process
        self.dtmf_queue.remove(&call);
        // and a hold or a resume waiting for a change to finish has no
        // session left to change: `CallEnded` is the last word on it
        self.holds_waiting.remove(&call);
        // by_request is not touched: the BYE that ended the call outlives the
        // call, and its answer is still this layer's rather than the
        // application's. `on_transaction_over` clears the entry when the
        // transaction it names ends, which is what bounds the map
    }

    /// A call placed by this end is going, and the INVITE that placed it may
    /// still be answered.
    ///
    /// §13.2.2.4: "If, after acknowledging any 2xx response to an INVITE, the
    /// UAC does not want to continue with that dialog, then the UAC MUST
    /// terminate the dialog by sending a BYE request". The client transaction
    /// passes up every 2xx until timer M, or timer D after a refusal (RFC
    /// 6026 §8.4), and the call it would have belonged to is found through
    /// `by_invite` — which is about to lose it. A sibling still up takes the
    /// INVITE over, so a later branch is minted beside it as before; with
    /// none left, whatever answers next is let go by
    /// [`UserAgent::let_go_late_branch`], ACK and BYE, under either
    /// [`ForkPolicy`]. Once the transaction is retired nothing more can come,
    /// and nothing is kept.
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
        // no dialog is exempt: a 2xx on one this end has acknowledged is
        // answered with the same ACK by the core and never gets here, and one
        // on a dialog that never was is a call nobody is on
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
    /// The Request-URI is where the registrar sent it, so it is this end's
    /// contact; the `To` is the address of record. Either identifies a line.
    /// Neither matching is not a reason to refuse the call — a misrouted INVITE
    /// that vanishes silently is worse than one the application can see.
    ///
    /// General enough for any incoming request, not only an INVITE, because
    /// `reliable::on_require_event` needs the same answer for a request that
    /// opens no dialog and names no call yet.
    pub(crate) fn line_for(&self, request: &RawMessage<'_>) -> Option<AccountId> {
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

/// What an INVITE says about who placed it, beyond `From`: the fields this
/// layer adds, and whether the application's own identity fields go.
struct Identifying {
    /// `Privacy` and `P-Asserted-Identity`, when the account asked for
    /// anonymity and the application wrote neither itself.
    added: Vec<(HeaderName<'static>, Box<[u8]>)>,
    /// Whether the application's own `P-Asserted-Identity` and
    /// `P-Preferred-Identity` are left off: the account names a trust
    /// domain and the INVITE is going outside it.
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
/// `Privacy` the account asked for, the account's own identity asserted
/// only toward a peer it trusts (RFC 3325 §7 has that peer strip it before
/// it leaves the trust domain), and an identity field of the application's
/// own kept off a request going to a peer outside a trust domain the account
/// named (§6). An account that names no trusted peer has made no claim about
/// a trust domain, and the application's fields go as written.
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

/// `<uri>`, which is how a URI goes into `To` without its parameters being
/// read as the header field's.
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
    /// Who is on the call an INVITE that arrived opens, read out of the INVITE
    /// itself.
    ///
    /// Needs nothing but the request, so it answers for a call this agent has
    /// already let go of: [`UaEvent::IncomingCall`] carries the INVITE whole,
    /// and a CANCEL that followed it before the event was taken out has
    /// already ended the call behind it. `None` when the `From`, the `To` or
    /// the `Call-ID` cannot be read.
    ///
    /// Read as though from a peer nobody trusts: [`CallIdentity::caller`]
    /// carries no asserted identity. [`UaEvent::IncomingCall`]'s own
    /// `identity` is the one read behind the account's trust gate.
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
                // whatever was waiting for a stream to go out in it will not
                self.forget_parked_in(dialog);
                self.on_dialog_over(dialog, reason, now)
            }
            Event::Challenged { transaction, .. } => {
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
                // no response arrived, and §8.1.3.1 says what stands for one;
                // where the transaction was retired first, `on_transaction_over`
                // has already said it
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
        } else {
            self.prack_by_itself(call, provisional, now);
        }
    }

    /// The CANCEL lost its race and the call connected anyway.
    ///
    /// §13.2.2.4 still wants the ACK — a 2xx is acknowledged whether or not it
    /// is wanted — and only then can the call be hung up. The first 2xx to
    /// cross the CANCEL also speaks for the answer window: one on any other
    /// branch after it is [`UserAgent::let_go_late_branch`]'s, whether or not
    /// the call it would have belonged to is still around to hang up.
    fn on_cancel_lost(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
        now: Instant,
    ) {
        // none on a branch other than the first to cross it: `Established`
        // follows for the same 2xx, and lets it go without minting a call
        let Some(call) = self.branch(invite, Some(dialog)) else {
            return;
        };
        // the same 2xx again, retransmitted while its ACK and the hangup after
        // it wait for a stream: both are already held, and asking again would
        // ask for another connection per retransmission
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

    /// §8.2.2.3 and then §8.2.3, for an INVITE that would open a call: a
    /// `Require` this agent cannot honour is refused 420 before anything else
    /// looks at the request, then a body it cannot read or an `Accept` that
    /// rules out the session description every answer carries. `true` when
    /// the INVITE was refused.
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
        // a recording session's offer and metadata, to an agent that takes
        // them: both parts are understood, which is what §8.2.3 asks
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
    /// An INVITE addressed to no account still arrives (the event says why),
    /// and answering it still needs a `Contact`: the address it arrived on is
    /// the one this end is sure of.
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
                // the line this INVITE is addressed to, found now so the
                // Require check below can tell whether it has asked its
                // registrar for GRUUs
                let account = self.line_for(&request.as_raw());
                let account_wants_gruu = account
                    .and_then(|id| self.accounts.get(&id))
                    .is_some_and(Account::wants_gruu);
                // RFC 4028 §9: an interval below the floor is refused with the
                // floor, and the far end asks again. There is no policy in it,
                // so the application is not troubled with it
                if self.refuse_unreadable(transaction, &request.as_raw(), account_wants_gruu, now) {
                    return None;
                }
                // RFC 3891 §3: a Replaces names one of this end's own calls,
                // and every way it can fail to is a different status code
                let replaced = match self.replaced_by(request) {
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
                // the `From` this call answers with, kept for a `Referred-By`
                // it may write later (RFC 3892 §2.2) — the `Contact` of the
                // answer itself is read fresh, at the moment it is sent
                // (`current_contact`), not decided here
                // which is this dialog's local URI, the To this INVITE came
                // with (RFC 3261 §12.1.1), and not the account's address of
                // record: a line found by its contact may have been called on
                // a number or an alias the far end was never shown the record
                // behind. The URI alone, since a display name there is the far
                // end's own writing
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
                    // and where this one's signalling came from, and who it
                    // says is calling
                    (held.peer, held.identity) = (source, identity.clone());
                }
                self.by_server.insert(transaction, call);
                self.note_far_end(call, &request.as_raw());
                if let Some(offer) = self.offer_in(&request.as_raw())
                    && let Some(held) = self.calls.get_mut(&call)
                {
                    held.session.set_remote(offer);
                }
                self.events.push_back(UaEvent::IncomingCall {
                    call,
                    account,
                    request: request.clone(),
                    identity,
                });
                None
            }
            Event::IncomingCancel {
                invite,
                ref request,
            } => {
                let call = self.by_server.get(&invite).copied()?;
                self.ended_because(call, request);
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
                // confirmed once. What "up" means is the call's to say: a
                // consultation stays one across every change the target asks
                // for
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

    /// The far end hung up.
    fn on_bye(
        &mut self,
        call: CallHandle,
        transaction: TransactionId<NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        self.ended_because(call, request);
        // §15.1.2: the dialog is over, and answering it 200 is the only
        // thing left. There is nothing to decide, so nothing is asked
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
            .ok();
        self.finish(call, CallEndReason::RemoteHangup, None, None, now);
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
        // a branch other than the one kept has nothing left to report: the
        // ones that were ringing ended when it was kept, one heard of only
        // now is not a call anybody will take, and a 2xx that crossed the
        // CANCEL after the first one did is `let_go_late_branch`'s
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

    /// What a response the far end sent says about the session and about what
    /// the far end can be asked to do.
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
        // RFC 4028 §7.3: a 422 says the session interval was too short, not
        // that the call cannot happen
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
            // the enum is non-exhaustive across crate versions, and anything
            // new is still a call that did not connect
            _ => CallEndReason::Unreachable,
        };
        // §22.2 and §22.3: a challenge is a refusal that says how to ask
        // again, and the core reports the refusal before it reports that.
        // Ending the call here would leave nothing to retry
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
        self.end_branches(invite, ended, status, response, now)
    }

    /// A refusal that carried a challenge and got no retry was a refusal.
    ///
    /// The core answers a challenge once: the same nonce coming back without
    /// `stale` is §22.1's way of saying the password was wrong, and repeating
    /// it is how a client locks an account. So nothing follows the refusal in
    /// that case, and the silence is the answer.
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
    ///
    /// This is the half that did not exist. A BYE whose retry never went left
    /// the call in `Terminating` with nothing said to anybody, and a REFER
    /// left the seat taken so `refer` refused every later transfer on that
    /// call for the life of the call.
    pub(crate) fn settle_request_challenges(&mut self, now: Instant) {
        let refused: Vec<(AnyTransactionId, RequestRefusal)> =
            settled(&mut self.challenged_requests, |refusal| {
                refusal.waiting_for_stream
            });
        for (id, refusal) in refused {
            // whatever the method, the seat goes back: nothing more is coming
            // on this transaction. A no-op unless the call was holding it
            self.release_refer(id, false);
            self.by_request.remove(&id);
            self.account_of.remove(&id);
            // Only the REFER and an INFO carrying a digit need an event of
            // their own; the INFO's follows this one. RFC 3515 §2.4.2 has
            // only a 2xx oblige the far end to open the subscription that
            // would have reported how the transfer went, so a REFER that was
            // never authenticated leaves nothing that will ever report it:
            // without this the application waits for news that cannot come,
            // on a transfer that did not happen.
            //
            // The other four are already covered, each by something that was
            // going to happen anyway, and saying it twice here would be a
            // second event for one outcome. A BYE: the dialog ends when its
            // transaction gets a final answer, whatever the answer was, and
            // `on_dialog_over` reports the call ended — checked, not assumed.
            // A CANCEL: the INVITE it was trying to stop resolves through its
            // own path, and `hangup_wanted` sends a BYE if the call is
            // answered anyway. A PRACK: the provisional goes unacknowledged
            // and the INVITE's own Timer B reports that. A NOTIFY: it is this
            // end telling a referrer how a transfer went, and the local
            // bookkeeping was final before it was sent — the referrer is left
            // uninformed, and nothing at this end can reach them.
            if refusal.method == Method::Refer
                && let Some(status) = refusal.status
            {
                self.events.push_back(UaEvent::TransferDone {
                    call: refusal.call,
                    status,
                });
            }
            // an INFO carrying a digit, for the reason its 415 is reported at
            // all: the refusal is news the application gets no other way.
            // Whatever the method, a digit this was carrying goes with it
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

    /// A 2xx for one of our INVITEs, on whichever branch it came from. One on
    /// a branch other than the one kept is let go before it can be minted a
    /// call of its own.
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
        // the same 2xx again, retransmitted while its ACK waits for a stream:
        // the call was reported up the first time, and the ACK goes when the
        // stream does
        if self.ack_parked_in(dialog) {
            return;
        }
        let Some(held) = self.calls.get(&call) else {
            return;
        };
        // the 2xx a CANCEL lost its race to: `on_cancel_lost` has just
        // acknowledged it and hung up, and a second pass would acknowledge it
        // again and report up a call that is on its way down
        if held.acknowledged {
            return;
        }
        let (offered, forks, invite) = (held.session.has_local(), held.forks, held.invite);
        // the user put the call down before any branch answered: whichever
        // branch this is, nothing of it is kept
        let giving_up = held.hangup_wanted
            || invite
                .and_then(|invite| self.by_invite.get(&invite))
                .and_then(|placed| self.calls.get(placed))
                .is_some_and(|placed| placed.hangup_wanted);
        // the first branch to answer, under the policy that keeps one: the
        // later ones never get here (`let_go_late_branch`). A call put down
        // keeps nothing, and its first answer speaks for the window all the
        // same, so that a later one is let go even after this one has gone
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

        // §13.2.2.4: the ACK goes now unless it has to carry an answer that
        // only the application has. A 2xx nobody acknowledges is retransmitted
        // for 64*T1 and then hung up at the other end. One that §18.1.1 holds
        // back for a stream is still this layer's to send, not an answer the
        // application owes
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
        // a call placed because of a REFER owes the referrer a last word
        self.report_transfer(call, StatusCode::OK, now);
        // after the branch kept is reported up, so that whatever follows the
        // call from one branch to another — the relay a description named,
        // in the facade above — has somewhere to go before its old branch ends
        if let Some(invite) = kept {
            self.let_go_other_branches(call, invite, now);
        }
        // a CANCEL that lost its race leaves the call up and the wish to end it
        if giving_up {
            self.hang_up_by_itself(call, now);
        }
    }

    /// The first branch of a fork to answer is the one
    /// [`ForkPolicy::KeepFirst`] keeps, and when it is not the call that was
    /// placed it becomes that call: what belonged to the attempt rather than
    /// to one of its dialogs — a transfer to report on, the call it is a
    /// consultation for — moves onto it before the branch it came from ends.
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
        // the INVITE names the call it placed, and that is this one now: the
        // mapping stays when the branch it named ends
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

    /// Every branch of the INVITE but the one kept, over: they had not
    /// answered, and the proxy that forked them is cancelling them (RFC 3261
    /// §16.7 step 10). Their early dialogs stay with the core until the answer
    /// window closes, and a 2xx that still arrives on one of them is
    /// [`UserAgent::let_go_late_branch`]'s.
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
    /// §13.2.2.4 has every 2xx acknowledged whether it is wanted or not, and
    /// then the dialog it confirmed is ended with a BYE. There is no call to
    /// report it on: the branch ended when another was kept, is heard of
    /// only now, or belongs to a call that is over or on its way down. A
    /// branch still ringing when the user put the call down ends when that
    /// BYE is answered. A 2xx that carries the offer, to an INVITE that carried
    /// none, would need an answer in its ACK that only the application could
    /// write, so it is left for its sender to give up on (§13.3.1.4).
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
        // the same 2xx again, while its ACK waits for a stream: the BYE is
        // already waiting behind it
        if self.ack_parked_in(dialog) {
            return true;
        }
        // RFC 3326 §3.1: the phone that answered too late is told another
        // branch of the call was answered, which it shows as answered
        // elsewhere rather than as a call hung up on it
        if kept.offered && self.ack_by_itself(dialog, now) {
            self.bye_by_itself_for(dialog, Some(&Reason::completed_elsewhere()), now);
        }
        true
    }

    /// Remember a request this layer sent inside a call.
    ///
    /// The account goes into a map of its own rather than being read back off
    /// the call, because the BYE that ends a call outlives it and a challenge
    /// to that BYE still has to be answered.
    /// The method travels with it, because what a request leaves behind when
    /// its answer never arrives depends on which one it was, and the bytes
    /// are not kept.
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
            // an INVITE this layer did not place is a re-INVITE, and that
            // belongs to the session layer. Claiming it here would drop it
            AnyTransactionId::InviteClient(invite) => {
                let Some(call) = self.by_invite.get(&invite).copied() else {
                    return false;
                };
                self.on_call_challenged(call, transaction, now);
                true
            }
            // a BYE, a CANCEL, a PRACK, a REFER or the NOTIFY that reports one.
            // An UPDATE is not in this map and goes on to the session layer
            AnyTransactionId::NonInviteClient(_) if self.by_request.contains_key(&transaction) => {
                self.on_request_challenged(transaction, now);
                true
            }
            _ => false,
        }
    }

    /// A request this layer sent inside a call was challenged (§22.2).
    ///
    /// Everything that is not the INVITE opening the call arrives here: BYE,
    /// CANCEL, PRACK, REFER, and the NOTIFY that says how a transfer is going.
    fn on_request_challenged(&mut self, transaction: AnyTransactionId, now: Instant) {
        let Some((call, method)) = self.by_request.get(&transaction).copied() else {
            return;
        };
        let account = self.account_of.get(&transaction).copied();
        let credentials = account
            .and_then(|account| self.accounts.get(&account))
            .and_then(|config| config.credentials.clone());
        // With no password the request is unsent for good, so a REFER that
        // took the call's seat has to give it back on the way past. RFC 3515
        // §2.4.2 obliges the far end to open a subscription on a 2xx and on
        // nothing else, so a REFER refused for want of a password opened
        // none, and a record of one left standing would accept notifications
        // nobody promised. `release_refer` reads the seat itself, so it is a
        // no-op for the BYE, CANCEL, PRACK and NOTIFY that also arrive here.
        let Some(credentials) = credentials else {
            self.release_refer(transaction, false);
            return;
        };
        let retried = match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => retried,
            // §18.1.1 wants a connection first and the endpoint still holds
            // the challenge, so the seat is not given back: the retry that
            // will keep it has not been sent, not refused
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
        // the refusal that came with the challenge was the first half of this
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
        // §22.2 makes the retry a new request with a new number, and the
        // subscription that REFER opened is named by whichever number
        // actually went out: RFC 3515 §2.4.6's `id` is the `CSeq` of the
        // REFER, so a record still holding the refused one would refuse the
        // notifications that follow the accepted one.
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
    /// `accepted` says whether the answer was a 2xx, which is the one case
    /// this function has nothing to do for: RFC 3515 §2.4.2 has a 2xx oblige
    /// the far end to "create a subscription and send notifications of the
    /// status of the refer", so the seat it took stays taken — a second
    /// REFER while the first's subscription is still open would leave a
    /// NOTIFY with nothing to say which one it is about. `on_notify` gives it
    /// back when the terminating NOTIFY says the subscription itself is over
    /// (§2.4.7), which is the only event that actually frees this call to
    /// ask again. A REFER that was refused opened no subscription, so there
    /// is nothing left to wait for and the seat is given back here instead.
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

    /// The last word on an INFO carrying a digit, told to the application
    /// once: whichever of its answer, a challenge nothing could answer, or a
    /// transaction that gave up without either gets here first takes the
    /// digit with it.
    ///
    /// This is also where a string handed to [`UserAgent::send_dtmf_info`]
    /// moves on: a 2xx here sends the digit waiting behind this one, and
    /// anything else ends the sequence and drops it (8.3.11-bis).
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

    /// After one digit of a string [`UserAgent::send_dtmf_info`] sent reaches
    /// its final answer: the next one waiting goes out on a 2xx, and
    /// anything else — a refusal, a timeout, a transport failure — discards
    /// whatever is still queued rather than send it out of order
    /// (8.3.11-bis).
    fn continue_dtmf_queue(&mut self, call: CallHandle, status: StatusCode, now: Instant) {
        if !status.is_success() {
            self.dtmf_queue.remove(&call);
            return;
        }
        let Some(queue) = self.dtmf_queue.get_mut(&call) else {
            return;
        };
        // the entry stays while the next digit is in flight, and only an
        // answer to the last one, with nothing waiting behind it, retires it:
        // a key handed over before then has to wait its turn
        let Some(next) = queue.waiting.pop_front() else {
            self.dtmf_queue.remove(&call);
            return;
        };
        // with nothing in flight, nothing would ever move the rest on, and a
        // key handed over later would wait behind them for the life of the
        // call
        let digit = char::from(next.key);
        if self.send_one_dtmf_info(call, next, now).is_err() {
            self.dtmf_queue.remove(&call);
            // this digit never went out at all, and §8.1.3.1 is what a
            // request that could not even be sent stands for: nobody else
            // will ever tell the application this one is over, and dropping
            // it silently would leave `send_dtmf_info` looking like it never
            // returned for the rest of the string
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
        let credentials = self
            .calls
            .get(&call)
            .and_then(|held| held.account)
            .and_then(|id| self.accounts.get(&id))
            .and_then(|config| config.credentials.clone());
        let Some(credentials) = credentials else {
            return;
        };
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(AnyTransactionId::InviteClient(retried)) => {
                self.call_retry_went(call, transaction, retried);
            }
            // §18.1.1 wants a connection first. The endpoint keeps the
            // challenge, so this is a call still being placed rather than one
            // that was refused
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let AnyTransactionId::InviteClient(old) = transaction
                    && let Some(parked) = self.challenged.get_mut(&old)
                {
                    parked.waiting_for_stream = true;
                }
            }
            // an INVITE retried is an INVITE, so the first cannot happen; any
            // other failure is the refusal the settle pass already holds
            Ok(_) | Err(_) => {}
        }
    }

    /// The retry is a transaction now, so everything that named the refused
    /// one names this one.
    fn call_retry_went(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        retried: TransactionId<InviteClient>,
    ) {
        if let AnyTransactionId::InviteClient(old) = transaction {
            self.by_invite.remove(&old);
            // the refusal that came with the challenge was the first half of
            // this, not news
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
            let credentials = self
                .calls
                .get(&call)
                .and_then(|held| held.account)
                .and_then(|id| self.accounts.get(&id))
                .and_then(|config| config.credentials.clone());
            let Some(credentials) = credentials else {
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
            let credentials = account
                .and_then(|account| self.accounts.get(&account))
                .and_then(|config| config.credentials.clone());
            let Some(credentials) = credentials else {
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
    /// Its answer changes nothing the application has not already been told,
    /// save that a REFER which was refused frees the call to try again.
    /// Anything that is not ours goes back to the caller untouched.
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
        // A challenge is not a refusal yet, and the retry which follows keeps
        // the seat it is holding. But it is only not a refusal while a retry
        // is still possible, so it is parked here: a drain that ends without
        // one then has something to report, which used to be nothing at all.
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
            self.release_refer(id, status.is_success());
            // an INFO carrying a digit is the one request in this map whose
            // answer the application is owed: BYE, CANCEL, PRACK, REFER and
            // NOTIFY are all this layer's own business, but a 415 to a digit
            // is news the caller cannot get any other way
            if method == Method::Info {
                self.dtmf_info_over(id, call, status, now);
            }
        }
        None
    }

    /// A transaction has ended. Most of that is plumbing; one case is not.
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
        // a REFER that gave up here without ever being answered opened no
        // subscription (§2.4.2 obliges that only on a 2xx), so the seat it
        // took has to go back -- read before `by_request` forgets which call
        // held it, because on the timer and the transport paths the core
        // raises `TransactionTerminated` before `RequestFailed`, and the
        // release that arm would otherwise do finds nothing left to key on.
        // A transaction that instead completed normally (`reason` is
        // `Completed`) already had its answer seen by `on_request_answered`,
        // which is the one place a 2xx REFER's seat may be kept, so nothing
        // here may re-run for it.
        if failed.is_some() {
            self.release_refer(transaction, false);
        }
        // a REFER the far end sent that nobody took or refused: the endpoint
        // answered it 408 when 64·T1 ran out, and the seat it held has to go
        // back here, since this arm is where its end is reported and
        // `transfer` never sees it
        if let AnyTransactionId::NonInviteServer(server) = transaction {
            self.forget_unanswered_refer(server);
        }
        let call = self.by_request.remove(&transaction).map(|(call, _)| call);
        self.account_of.remove(&transaction);
        match (call, failed) {
            // the timer or the transport that ended it retires the
            // transaction before it reports why, so this is where an INFO
            // that got no answer is first seen to be over
            (Some(call), Some(status)) => self.dtmf_info_over(transaction, call, status, now),
            // a challenge still parked is `settle_request_challenges`' to
            // report, and a reliable transport's zero Timer K retires the
            // transaction before that settle has run
            _ if self.challenged_requests.contains_key(&transaction) => {}
            _ => {
                self.by_dtmf_info.remove(&transaction);
            }
        }
        // the answer window has closed (§13.2.2.4, RFC 6026 §7.2): the core
        // passes up no 2xx for this INVITE from here on, so there is no late
        // branch left to tell from the one kept
        if let AnyTransactionId::InviteClient(invite) = transaction {
            self.kept_branches.remove(&invite);
        }
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
            self.bye_by_itself(dialog, now);
        }
        // reported before the BYE's own dialog event arrives, so the reason
        // says what happened rather than who sent the last message
        self.finish(call, CallEndReason::Unreachable, None, None, now);
    }
}

/// The status RFC 3261 §8.1.3.1 has a request that got no response treated
/// as: a timeout "as if a 408 (Request Timeout) status code has been
/// received", a fatal transport error "as a 503 (Service Unavailable) status
/// code". `None` for a failure that was a response after all.
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
