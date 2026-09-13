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
use crate::headers::onto_request;
use crate::parked::{Parked, call_needs_a_stream};
use crate::registration::spread;
use crate::session::Hold;

/// An offer refused with a challenge, kept until the drain round ends.
///
/// The core reports the refusal before it reports the challenge, so acting on
/// the refusal at once would tear down the offer the retry needs. This is that
/// refusal, held back; `settle_offer_challenges` delivers it if no retry took
/// its place.
#[derive(Debug)]
pub(crate) struct ParkedOffer {
    pub(crate) call: CallHandle,
    pub(crate) status: Option<StatusCode>,
    pub(crate) response: Option<OwnedMessage>,
    /// The retry is built and the endpoint is holding it until there is a
    /// connection to send it over (§18.1.1). Until then this is not a refusal
    /// and `settle_offer_challenges` leaves it alone.
    pub(crate) waiting_for_stream: bool,
}

/// What this agent will answer, advertised so that the far end knows an UPDATE
/// is worth sending (RFC 3311 §4).
///
/// It lists what is answered here and nothing more.
pub(crate) const ALLOW: &[u8] = b"INVITE, ACK, CANCEL, BYE, OPTIONS, UPDATE, PRACK, REFER, NOTIFY";

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
        let mut description = sdp::parse_with_limits(sdp, self.sdp_limits).map_err(UaError::Sdp)?;
        let held = {
            let state = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            state.session.stamp(&mut description);
            state.session.hold.local
        };
        let fields = self.application_headers(call);
        self.send_offer(call, description, held, false, &fields, now)
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
        let answering = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            held.answering.take().ok_or(UaError::WrongState(state))?
        };
        let contact = self.current_contact(call, now);
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW);
        let written = match sdp {
            Some(bytes) => {
                let parsed =
                    sdp::parse_with_limits(bytes, self.sdp_limits).map_err(UaError::Sdp)?;
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
        let fields = self.application_headers(call);
        self.send_offer(call, offer, held, false, &fields, now)
    }

    fn send_offer(
        &mut self,
        call: CallHandle,
        offer: SessionDescription,
        held: bool,
        retried: bool,
        fields: &[crate::account::Extra],
        now: Instant,
    ) -> Result<(), UaError> {
        let (state, dialog, allows_update) = {
            let call_state = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            if call_state.offering.is_some() || call_state.answering.is_some() {
                return Err(UaError::ChangeInProgress);
            }
            (
                call_state.state,
                call_state.dialog.ok_or(UaError::CannotRenegotiate)?,
                call_state.update_allowed,
            )
        };
        let method = match state {
            CallState::Confirmed | CallState::Consulting => Method::Invite,
            early if early.is_early() && allows_update => Method::Update,
            _ => return Err(UaError::CannotRenegotiate),
        };

        let contact = self.current_contact(call, now);
        let body: Arc<[u8]> = Arc::from(offer.to_bytes());
        // §8.1.1.8 makes Contact a MUST on anything that can refresh a target,
        // and both of these can
        let mut request = onto_request(
            OutgoingInDialogRequest::new(method)
                .contact(&contact)
                .header(HeaderName::Allow, ALLOW),
            fields,
        )
        .body(b"application/sdp", body);
        if method == Method::Invite && self.wants_gruu(call) {
            // RFC 5627 §4.4 SHOULD, on a re-INVITE as on the INVITE that
            // opened the call: "a UA SHOULD include a Supported header field
            // with the option tag gruu in requests and responses it generates"
            request = request.header(HeaderName::Supported, b"gruu");
        }
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
    ///
    /// Or held back again, when §18.1.1 wants a stream for it: that retry has
    /// not been sent rather than refused, so it is not reported as a change
    /// that failed, and it goes once the stream is bound.
    pub(crate) fn retry_offer(&mut self, call: CallHandle, now: Instant) {
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
        // a refresh is this layer's own message, and offering it again after a
        // 491 does not make it the application's
        let fields = if offer.refresh {
            Vec::new()
        } else {
            self.application_headers(call)
        };
        match self.send_offer(call, description.clone(), offer.held, true, &fields, now) {
            Ok(()) => {}
            Err(ref error) if call_needs_a_stream(error) => {
                let dialog = self.calls.get_mut(&call).and_then(|held| {
                    held.offering = Some(Offer {
                        transaction: None,
                        description: Some(description),
                        ..offer
                    });
                    held.dialog
                });
                if let Some(dialog) = dialog {
                    self.park(Parked::Offer { call, dialog });
                }
            }
            Err(_) => {
                self.events.push_back(UaEvent::SessionChangeFailed {
                    call,
                    status: None,
                    retry_in: None,
                    response: None,
                });
            }
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
                // RFC 5627 §4.4 names "a 2xx or 18x response to an INVITE
                // which contains a To tag", and a 2xx to a re-INVITE is one
                let with_gruu = (response.status().is_success() && self.wants_gruu(call))
                    .then(|| response.clone().header(HeaderName::Supported, b"gruu"));
                self.endpoint
                    .respond_invite(id, with_gruu.as_ref().unwrap_or(response), now)?;
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
                dialog,
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
                self.ack_reinvite_by_itself(invite, dialog, now);
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
                self.on_offer_refused_or_challenged(call, id, status, response);
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
            // §22.2: an offer refused with a challenge is asked again with the
            // credentials, whether it went as a re-INVITE or as an UPDATE
            Event::Challenged { transaction, .. } => {
                if !self.by_offer.contains_key(&transaction) {
                    return Some(event);
                }
                self.on_offer_challenged(transaction, now);
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
        if let Ok(described) = sdp::parse_with_limits(answer, self.sdp_limits) {
            held.session.set_remote(described);
        }
        self.report_session(call);
    }

    /// It did not — but a refusal that carries a challenge is not one yet.
    ///
    /// §22.2 makes a 401 or a 407 a request to ask again with credentials, and
    /// the core reports the refusal before it reports the challenge. Delivering
    /// the refusal here would take the offer with it and leave the retry
    /// nothing to send, so it waits for the round to end.
    fn on_offer_refused_or_challenged(
        &mut self,
        call: CallHandle,
        id: AnyTransactionId,
        status: Option<StatusCode>,
        response: Option<OwnedMessage>,
    ) {
        if matches!(status.map(StatusCode::get), Some(401 | 407)) {
            self.challenged_offers.insert(
                id,
                ParkedOffer {
                    call,
                    status,
                    response,
                    waiting_for_stream: false,
                },
            );
            return;
        }
        self.on_offer_refused(call, id, status, response);
    }

    /// A proxy or a registrar challenged the offer. The account has the
    /// password.
    fn on_offer_challenged(&mut self, id: AnyTransactionId, now: Instant) {
        let Some(call) = self.by_offer.get(&id).copied() else {
            return;
        };
        let credentials = self
            .calls
            .get(&call)
            .and_then(|held| held.account)
            .and_then(|account| self.accounts.get(&account))
            .and_then(|config| config.credentials.clone());
        let Some(credentials) = credentials else {
            return;
        };
        match self.endpoint.retry_with_credentials(id, &credentials, now) {
            Ok(retried) => self.offer_retry_went(id, call, retried),
            // §18.1.1 wants a connection first. The endpoint keeps the
            // challenge, so this waits rather than being reported as a
            // session change that failed
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let Some(parked) = self.challenged_offers.get_mut(&id) {
                    parked.waiting_for_stream = true;
                }
            }
            Err(_) => {}
        }
    }

    /// The retry is a transaction now, so everything that named the refused
    /// one names this one.
    fn offer_retry_went(
        &mut self,
        id: AnyTransactionId,
        call: CallHandle,
        retried: AnyTransactionId,
    ) {
        self.by_offer.remove(&id);
        // the refusal that came with the challenge was the first half of this
        self.challenged_offers.remove(&id);
        self.by_offer.insert(retried, call);
        if let Some(offer) = self
            .calls
            .get_mut(&call)
            .and_then(|held| held.offering.as_mut())
        {
            offer.transaction = Some(retried);
        }
    }

    /// Send the offer retries §18.1.1 held back, now that there is a
    /// connection.
    pub(crate) fn resume_parked_offers(&mut self, now: Instant) {
        let waiting: Vec<(AnyTransactionId, CallHandle)> = self
            .challenged_offers
            .iter()
            .filter(|(_, parked)| parked.waiting_for_stream)
            .map(|(id, parked)| (*id, parked.call))
            .collect();
        for (id, call) in waiting {
            let credentials = self
                .calls
                .get(&call)
                .and_then(|held| held.account)
                .and_then(|account| self.accounts.get(&account))
                .and_then(|config| config.credentials.clone());
            let Some(credentials) = credentials else {
                self.stop_waiting_for_offer(id);
                continue;
            };
            match self.endpoint.retry_with_credentials(id, &credentials, now) {
                Ok(retried) => self.offer_retry_went(id, call, retried),
                Err(error) if crate::agent::wants_a_stream(&error) => {}
                Err(_) => self.stop_waiting_for_offer(id),
            }
        }
    }

    /// Stop holding one back, so the next settle reports the refusal it
    /// still carries.
    fn stop_waiting_for_offer(&mut self, id: AnyTransactionId) {
        if let Some(parked) = self.challenged_offers.get_mut(&id) {
            parked.waiting_for_stream = false;
        }
    }

    /// An offer refused with a challenge that got no retry was refused.
    ///
    /// The core answers a challenge once; the same nonce coming back is §22.1
    /// saying the password is wrong, and repeating it is how an account gets
    /// locked. So the silence after it is the answer.
    pub(crate) fn settle_offer_challenges(&mut self) {
        let parked: Vec<(AnyTransactionId, ParkedOffer)> = self.challenged_offers.drain().collect();
        for (id, offer) in parked {
            self.on_offer_refused(offer.call, id, offer.status, offer.response);
        }
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
        self.on_offer_refused_or_challenged(call, id, Some(status), Some(response.clone()));
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
        let arriving = arriving(&raw, self.sdp_limits);
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
        let answer = {
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
            answer
        };
        let contact = self.current_contact(call, now);
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW)
            .body(b"application/sdp", Arc::from(answer.to_bytes()));
        if let Some(value) = self.timer_echo(call) {
            response = response.header(HeaderName::SessionExpires, &value);
        }
        if self.answer_with(call, transaction, &response, now).is_err() {
            return false;
        }
        if let Some(held) = self.calls.get_mut(&call) {
            held.session.set_remote(offer.clone());
            held.session.set_local(answer);
        }
        self.report_session(call);
        true
    }

    /// Answer a re-INVITE that carried no offer with one of our own (§14.1).
    fn offer_in_answer(&mut self, call: CallHandle, transaction: AnyTransactionId, now: Instant) {
        let offered = {
            let Some(held) = self.calls.get_mut(&call) else {
                return;
            };
            let wanted = held.session.hold.local;
            held.session.offer(wanted)
        };
        let contact = self.current_contact(call, now);
        let mut response = OutgoingResponse::new(StatusCode::OK)
            .contact(&contact)
            .header(HeaderName::Allow, ALLOW);
        if let Some(value) = self.timer_echo(call) {
            response = response.header(HeaderName::SessionExpires, &value);
        }
        if let Some(ref description) = offered {
            response = response.body(b"application/sdp", Arc::from(description.to_bytes()));
        }
        if self.answer_with(call, transaction, &response, now).is_err() {
            return;
        }
        if let (Some(held), Some(description)) = (self.calls.get_mut(&call), offered) {
            held.session.set_local(description);
            held.session.answer_owed = true;
        }
    }

    /// Answer a request that only refreshed the target.
    fn acknowledge_only(&mut self, call: CallHandle, transaction: AnyTransactionId, now: Instant) {
        let contact = self.current_contact(call, now);
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
        let Ok(answer) = sdp::parse_with_limits(body, self.sdp_limits) else {
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

fn arriving(request: &RawMessage<'_>, limits: sdp::Limits) -> Arriving {
    let body = request.body();
    if body.is_empty() {
        return Arriving::Nothing;
    }
    match request.content_type() {
        Ok(kind) if kind.is("application", "sdp") => sdp::parse_with_limits(body, limits)
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
