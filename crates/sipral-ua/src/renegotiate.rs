// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Changing a session that is already running: hold, resume, and whatever
//! either end offers afterwards.
//!
//! A confirmed dialog changes by re-INVITE (RFC 3311 §5.1); an early one by
//! UPDATE, only if the far end allows it (RFC 3311 §4), since a second INVITE
//! cannot run beside the first (RFC 3261 §14.1).
//!
//! An offer that keeps the negotiated streams and formats (hold, resume, a
//! moved address) is answered here. Anything else goes to the application
//! with the transaction kept open, since an unanswered re-INVITE ends the
//! call.
//!
//! Glare: 491, a wait from non-overlapping ranges, and one retry (§14.1),
//! rewritten against the session the far end's change left.
//!
//! One change at a time (§14.1, RFC 3264 §4). A hold or resume asked
//! meanwhile waits, and only the latest goes. An application-written
//! description is refused instead, as it targets a session about to move.
//!
//! An UPDATE we cannot answer is still handed over, not refused 504
//! (RFC 3311 §5.2): an application answers quickly. One that prompts a
//! person should answer 504 itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Event, OutgoingInDialogRequest, OutgoingResponse};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, RawMessage, StatusCode, Uri};
use sipral_core::sdp::{self, SessionDescription};
use sipral_core::transaction::{
    AnyTransactionId, DialogId, NonInviteServerState, ProvisionalResponseId,
};

use crate::agent::UserAgent;
use crate::call::{Answering, Author, CallHandle, CallState, Direction, Offer};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::headers::onto_request;
use crate::parked::{Parked, call_needs_a_stream};
use crate::registration::spread;
use crate::session::Hold;

/// An offer refused with a challenge, kept until the drain round ends.
///
/// The core reports the refusal before the challenge, so acting at once would
/// tear down the offer the retry needs; `settle_offer_challenges` delivers it
/// if no retry replaced it.
#[derive(Debug)]
pub(crate) struct ParkedOffer {
    pub(crate) call: CallHandle,
    pub(crate) status: Option<StatusCode>,
    pub(crate) response: Option<OwnedMessage>,
    /// The retry waits for a connection (§18.1.1); not a refusal yet.
    pub(crate) waiting_for_stream: bool,
}

#[derive(Clone, Copy, Debug)]
struct Asked {
    held: bool,
    /// The one retry §14.1 allows after a 491.
    retried: bool,
    author: Author,
}

/// Advertised so the far end knows UPDATE is usable (RFC 3311 §4).
pub(crate) const ALLOW: &[u8] =
    b"INVITE, ACK, CANCEL, BYE, OPTIONS, UPDATE, PRACK, REFER, NOTIFY, MESSAGE, INFO";

/// Glare wait in ms for the `Call-ID` owner (§14.1, RFC 3311 §5.3).
const OWNER_BACKOFF: (u64, u64) = (2_100, 4_000);
const GUEST_BACKOFF: (u64, u64) = (0, 2_000);
const BACKOFF_STEP: u64 = 10;
/// `Retry-After` within 0-10 s (RFC 3311 §5.2).
const RETRY_AFTER_CEILING: u32 = 11;
/// A 488 should carry a `Warning` (§14.2); 399 is miscellaneous (§20.43).
pub(crate) const WHY_488: &[u8] = b"399 sipral \"the session description could not be read\"";

impl UserAgent {
    /// Put a call on hold (RFC 3264 §8.4).
    ///
    /// The description is written here from the negotiated one. A hold
    /// already in place or on its way sends nothing.
    ///
    /// While another session change runs in the call, it waits and goes
    /// after (RFC 3261 §14.1); only the last state asked for goes. The
    /// outcome is the [`UaEvent::SessionChanged`] or
    /// [`UaEvent::SessionChangeFailed`] of the request that carries it.
    ///
    /// # Errors
    /// When sent at once: [`UaError::NoSuchCall`], [`UaError::NoSession`]
    /// when nothing is described yet, [`UaError::CannotRenegotiate`] when the
    /// call is not up and the far end never allowed UPDATE, or
    /// [`UaError::Send`]. A waiting one that cannot go is reported as
    /// [`UaEvent::SessionChangeFailed`] with no status; one still waiting
    /// when the call ends is dropped.
    pub fn hold(&mut self, call: CallHandle, now: Instant) -> Result<(), UaError> {
        self.change_hold(call, true, now)
    }

    /// Take it off hold again.
    ///
    /// Each stream returns to its pre-hold direction, not always `sendrecv`.
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
    /// Sent as written, directions included. Prefer [`UserAgent::hold`],
    /// [`UserAgent::resume`] or [`UserAgent::change_formats`] where they fit.
    ///
    /// The hold state is read back from what this sends, so
    /// [`UserAgent::hold_state`] follows it once agreed.
    ///
    /// It does not wait behind a running change: it is refused, since it was
    /// written against a session about to move. After a 491, if the far
    /// end's change was answered during the wait, it is reported as
    /// [`UaEvent::SessionChangeFailed`] with no status rather than resent.
    ///
    /// # Errors
    /// As [`UserAgent::hold`], plus [`UaError::ChangeInProgress`] when a
    /// session change is running in the call in either direction, and
    /// [`UaError::Sdp`] when the description cannot be read.
    pub fn reoffer(&mut self, call: CallHandle, sdp: &[u8], now: Instant) -> Result<(), UaError> {
        let mut description = sdp::parse_with_limits(sdp, self.sdp_limits).map_err(UaError::Sdp)?;
        self.carrier(call)?;
        let held = {
            let state = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            state.session.stamp(&mut description);
            state.session.holds_them(&description)
        };
        let fields = self.application_headers(call);
        let asked = Asked {
            held,
            retried: false,
            author: Author::Application,
        };
        self.send_offer(call, description, asked, &fields, now)
    }

    /// Offer new formats (RFC 3264 §8.3.2) without changing direction.
    ///
    /// Directions are rewritten from the hold state, so a held call stays
    /// held. Copying the last answer's directions would turn a hold by the
    /// far end into a hold from both. Refused while another change runs, as
    /// [`UserAgent::reoffer`].
    ///
    /// # Errors
    /// As [`UserAgent::reoffer`].
    pub fn change_formats(
        &mut self,
        call: CallHandle,
        sdp: &[u8],
        now: Instant,
    ) -> Result<(), UaError> {
        let mut description = sdp::parse_with_limits(sdp, self.sdp_limits).map_err(UaError::Sdp)?;
        self.carrier(call)?;
        let held = {
            let state = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            state.session.stamp(&mut description);
            let held = state.session.hold.local;
            state.session.direct(&mut description, held);
            held
        };
        let fields = self.application_headers(call);
        let asked = Asked {
            held,
            retried: false,
            author: Author::Application,
        };
        self.send_offer(call, description, asked, &fields, now)
    }

    /// Answer a [`UaEvent::Reoffer`] the far end sent.
    ///
    /// `sdp` is required: every [`UaEvent::Reoffer`] carries an offer
    /// (RFC 3264 §5). For an offer that came in a PRACK, the answer goes in
    /// the PRACK's 2xx (RFC 3262 §5), and a 2xx to the INVITE held behind it
    /// goes right after.
    ///
    /// A hold this end asked for is kept: streams the answer reopens are
    /// narrowed back (`Session::keep_hold`); otherwise the answer goes byte
    /// for byte. `Session-Expires` is added when owed (RFC 4028 §9).
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when nothing is
    /// waiting, [`UaError::Sdp`], or [`UaError::Respond`]. An unreadable
    /// answer is refused before the request is touched, so it can still be
    /// answered.
    pub fn accept_reoffer(
        &mut self,
        call: CallHandle,
        sdp: &[u8],
        now: Instant,
    ) -> Result<(), UaError> {
        let mut written = sdp::parse_with_limits(sdp, self.sdp_limits).map_err(UaError::Sdp)?;
        let (answering, rewritten) = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            let answering = held.answering.take().ok_or(UaError::WrongState(state))?;
            let rewritten = held.session.keep_hold(&mut written);
            (answering, rewritten)
        };
        let body = if rewritten {
            written.to_bytes()
        } else {
            sdp.to_vec()
        };
        let mut response = OutgoingResponse::new(StatusCode::OK).header(HeaderName::Allow, ALLOW);
        // a PRACK's 2xx has no Contact (RFC 3262 §6) and refreshes no
        // session (RFC 4028 §1)
        if answering.prack.is_none() {
            let contact = self.current_contact(call, now);
            response = response.contact(&contact);
            if let Some(value) = self.timer_echo(call) {
                response = response.header(HeaderName::SessionExpires, &value);
            }
        }
        let response = response.body(b"application/sdp", Arc::from(body));
        if let Err(error) = self.answer_with(call, answering.transaction, &response, now) {
            // the far end's change is over anyway; send a waiting hold now,
            // not at the next drain
            self.send_waiting_holds(now);
            return Err(error);
        }
        if let Some(held) = self.calls.get_mut(&call) {
            held.session.set_remote(answering.offer);
            held.session.set_local(written);
            held.overtake();
        }
        self.report_session(call);
        if answering.prack.is_some() {
            self.acknowledged(call, now);
        }
        self.drain(now);
        Ok(())
    }

    /// Refuse a [`UaEvent::Reoffer`]; the session stays as it was (§14.1).
    /// Use 488 when the description is the problem.
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
        let sent = match (answering.prack, answering.transaction) {
            // a refused PRACK acknowledged nothing; the far end resends it
            // (RFC 3262 §3, RFC 3261 §8.1.3.5)
            (Some(provisional), AnyTransactionId::NonInviteServer(transaction)) => self
                .endpoint
                .refuse_prack(transaction, provisional, &response, now)
                .map_err(UaError::Respond),
            _ => self.answer_with(call, answering.transaction, &response, now),
        };
        if let Err(error) = sent {
            self.send_waiting_holds(now);
            return Err(error);
        }
        self.drain(now);
        Ok(())
    }
}

impl UserAgent {
    fn change_hold(&mut self, call: CallHandle, held: bool, now: Instant) -> Result<(), UaError> {
        {
            let call_state = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            if !call_state.session.has_local() {
                return Err(UaError::NoSession);
            }
            // compare with where the call is headed, not the last agreed state
            let heading = call_state
                .offering
                .as_ref()
                .map_or(call_state.session.hold.local, |offer| offer.held);
            if call_state.changing() {
                // §14.1
                if held == heading {
                    self.holds_waiting.remove(&call);
                } else {
                    self.holds_waiting.insert(call, held);
                }
                return Ok(());
            }
            // this supersedes a stale waiting one
            self.holds_waiting.remove(&call);
            if heading == held {
                return Ok(());
            }
        }
        self.carrier(call)?;
        let offer = self
            .calls
            .get_mut(&call)
            .and_then(|call_state| call_state.session.offer(held))
            .ok_or(UaError::NoSession)?;
        let fields = self.application_headers(call);
        let asked = Asked {
            held,
            retried: false,
            author: Author::Session,
        };
        self.send_offer(call, offer, asked, &fields, now)
    }

    /// Send new metadata to the recording server (RFC 7866 §9.1).
    ///
    /// It goes with an offer repeating the current session, since the
    /// metadata names SDP labels the offer must define. Later offers carry
    /// it too.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`]; [`UaError::WrongState`] if not a recording
    /// session ([`crate::OutgoingCall::recording_session`]);
    /// [`UaError::Recording`] for unwritable metadata;
    /// [`UaError::ChangeInProgress`] while another change runs (the metadata
    /// is kept for the next offer; ask again once it is reported); and what
    /// [`UserAgent::hold`] returns when no offer can be sent.
    pub fn update_recording_metadata(
        &mut self,
        call: CallHandle,
        metadata: &crate::siprec::RecordingMetadata,
        now: Instant,
    ) -> Result<(), UaError> {
        let written = metadata.to_xml().map_err(UaError::Recording)?;
        let recording = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
        if recording.recording.is_none() {
            return Err(UaError::WrongState(recording.state));
        }
        recording.recording = Some(Arc::from(written));
        if recording.changing() {
            return Err(UaError::ChangeInProgress);
        }
        let as_held = recording.session.hold.local;
        self.carrier(call)?;
        let offer = self
            .calls
            .get_mut(&call)
            .and_then(|call_state| call_state.session.offer(as_held))
            .ok_or(UaError::NoSession)?;
        let fields = self.application_headers(call);
        let asked = Asked {
            held: as_held,
            retried: false,
            author: Author::Session,
        };
        self.send_offer(call, offer, asked, &fields, now)
    }

    /// The method and dialog that would carry an offer now, or why none can.
    ///
    /// Checked before writing an offer too: writing moves the `o=` version,
    /// which must not skip a number (RFC 3264 §8).
    fn carrier(&self, call: CallHandle) -> Result<(Method<'static>, DialogId), UaError> {
        let call_state = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
        if call_state.changing() {
            return Err(UaError::ChangeInProgress);
        }
        let dialog = call_state.dialog.ok_or(UaError::CannotRenegotiate)?;
        match call_state.state {
            CallState::Confirmed | CallState::Consulting => Ok((Method::Invite, dialog)),
            early if early.is_early() && call_state.update_allowed => Ok((Method::Update, dialog)),
            _ => Err(UaError::CannotRenegotiate),
        }
    }

    /// Send holds and resumes that waited for a change to finish. One that
    /// cannot go is reported as [`UaEvent::SessionChangeFailed`].
    pub(crate) fn send_waiting_holds(&mut self, now: Instant) {
        if self.holds_waiting.is_empty() {
            return;
        }
        let calls = &self.calls;
        let ready: Vec<CallHandle> = self
            .holds_waiting
            .keys()
            .filter(|call| calls.get(call).is_some_and(|held| !held.changing()))
            .copied()
            .collect();
        for call in ready {
            // a drain inside the loop may have sent it already
            let Some(held) = self.holds_waiting.remove(&call) else {
                continue;
            };
            if self.change_hold(call, held, now).is_err() {
                self.events.push_back(UaEvent::SessionChangeFailed {
                    call,
                    status: None,
                    retry_in: None,
                    response: None,
                });
            }
        }
    }

    fn send_offer(
        &mut self,
        call: CallHandle,
        offer: SessionDescription,
        asked: Asked,
        fields: &[crate::account::Extra],
        now: Instant,
    ) -> Result<(), UaError> {
        let (method, dialog) = self.carrier(call)?;

        let contact = self.current_contact(call, now);
        let sdp = offer.to_bytes();
        // RFC 7866 §9.1
        let recording = self
            .calls
            .get(&call)
            .and_then(|held| held.recording.clone());
        let (content_type, body): (Vec<u8>, Arc<[u8]>) = match recording {
            Some(metadata) => {
                let built = crate::siprec::written_session_body(&sdp, &metadata)
                    .map_err(UaError::Recording)?;
                (
                    built.content_type().as_bytes().to_vec(),
                    Arc::from(built.into_body()),
                )
            }
            None => (b"application/sdp".to_vec(), Arc::from(sdp)),
        };
        // §8.1.1.8: target refreshes carry Contact
        let mut request = onto_request(
            OutgoingInDialogRequest::new(method)
                .contact(&contact)
                .header(HeaderName::Allow, ALLOW),
            fields,
        )
        .body(&content_type, body);
        if method == Method::Invite && self.wants_gruu(call) {
            // RFC 5627 §4.4
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
                held: asked.held,
                retried: asked.retried,
                author: asked.author,
                overtaken: false,
            });
        }
        self.by_offer.insert(transaction, call);
        self.drain(now);
        Ok(())
    }

    /// Retry a change told to wait by a 491 (§14.1). If it needs a stream
    /// (§18.1.1) it is parked, not failed.
    ///
    /// The far end's change may have arrived during the wait. Still being
    /// answered: wait again. Already answered: a hold or resume is rewritten
    /// from the new session (RFC 3264 §8), a refresh is repeated, and an
    /// application description is reported failed, as [`UserAgent::reoffer`].
    pub(crate) fn retry_offer(&mut self, call: CallHandle, now: Instant) {
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        if held.offering.is_none() {
            return;
        }
        if held.answering.is_some() || held.session.answer_owed {
            let owner = held.direction == Direction::Outgoing;
            let wait = glare_backoff(owner, &self.endpoint.token());
            if let Some(held) = self.calls.get_mut(&call) {
                held.retry_at = Some(now + wait);
            }
            return;
        }
        let Some(offer) = held.offering.take() else {
            return;
        };
        if offer.author == Author::Refresh {
            // RFC 4028 §7.4
            self.send_refresh(call, true, now);
            return;
        }
        let description = match offer.description {
            // nothing said since: same bytes, same version (§8)
            Some(ref description) if !offer.overtaken => Some(description.clone()),
            // asked first, because writing one moves the version
            Some(_) if offer.author == Author::Session && self.carrier(call).is_ok() => self
                .calls
                .get_mut(&call)
                .and_then(|held| held.session.offer(offer.held)),
            _ => None,
        };
        let Some(description) = description else {
            self.events.push_back(UaEvent::SessionChangeFailed {
                call,
                status: None,
                retry_in: None,
                response: None,
            });
            return;
        };
        let fields = self.application_headers(call);
        let asked = Asked {
            held: offer.held,
            retried: true,
            author: offer.author,
        };
        match self.send_offer(call, description.clone(), asked, &fields, now) {
            Ok(()) => {}
            Err(ref error) if call_needs_a_stream(error) => {
                let dialog = self.calls.get_mut(&call).and_then(|held| {
                    held.offering = Some(Offer {
                        transaction: None,
                        description: Some(description),
                        overtaken: false,
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

    /// Glare retries and session timers.
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
                // RFC 5627 §4.4
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

    /// A refusal with a random `Retry-After`, so two peers do not collide
    /// again.
    pub(crate) fn too_soon(&mut self, status: StatusCode) -> OutgoingResponse {
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

    /// From a target-refreshing message: UPDATE support and conference focus.
    pub(crate) fn note_far_end(&mut self, call: CallHandle, message: &RawMessage<'_>) {
        self.note_allow(call, message);
        self.note_focus(call, message);
    }

    /// `isfocus` in the far end's `Contact` names the conference URI
    /// (RFC 4579 §4.2). No `Contact` leaves what was known.
    fn note_focus(&mut self, call: CallHandle, message: &RawMessage<'_>) {
        let Ok(sipral_core::msg::Contacts::Addrs(addrs)) = message.contact() else {
            return;
        };
        let Some(Ok(first)) = addrs.into_iter().next() else {
            return;
        };
        let conference = first
            .params()
            .has("isfocus")
            .then(|| Uri::parse(first.uri_bytes()).ok())
            .flatten();
        if let Some(held) = self.calls.get_mut(&call) {
            held.remote_focus = conference;
        }
    }

    pub(crate) fn report_session(&mut self, call: CallHandle) {
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

impl UserAgent {
    /// `None` when the event was about a session change and was handled.
    pub(crate) fn on_session_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::ReinviteProgress { invite, .. } => {
                let id = AnyTransactionId::InviteClient(invite);
                if !self.by_offer.contains_key(&id) {
                    return Some(event);
                }
                // provisionals to a re-INVITE add nothing (§14.2)
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
                // an empty ACK, resent for every 2xx retransmission (§13.2.2.4)
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
                // a 408 (§12.2.1.2); the call layer handles the dialog
                self.on_offer_refused(call, id, None, None);
                None
            }
            // §22.2
            Event::Challenged { transaction, .. } | Event::TokenChallenged { transaction, .. } => {
                if !self.by_offer.contains_key(&transaction) {
                    return Some(event);
                }
                self.on_offer_challenged(transaction, now);
                None
            }
            other => self.on_change_arriving(other, now),
        }
    }

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

    fn on_offer_taken(&mut self, call: CallHandle, id: AnyTransactionId, answer: &[u8]) {
        self.by_offer.remove(&id);
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        let Some(offer) = held.offering.take() else {
            return;
        };
        held.retry_at = None;
        // a refresh changes only the clock (RFC 4028 §7.4)
        if offer.author == Author::Refresh {
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

    /// A 401/407 is parked until the round ends: the core reports it before
    /// the challenge, and failing now would drop the offer the retry needs.
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

    fn on_offer_challenged(&mut self, id: AnyTransactionId, now: Instant) {
        let Some(call) = self.by_offer.get(&id).copied() else {
            return;
        };
        let account = self.calls.get(&call).and_then(|held| held.account);
        let Some(credentials) = self.credentials_for_challenge(account, id) else {
            return;
        };
        match self.endpoint.retry_with_credentials(id, &credentials, now) {
            Ok(retried) => self.offer_retry_went(id, call, retried),
            // needs a connection first (§18.1.1); wait, do not fail
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let Some(parked) = self.challenged_offers.get_mut(&id) {
                    parked.waiting_for_stream = true;
                }
            }
            Err(_) => {}
        }
    }

    fn offer_retry_went(
        &mut self,
        id: AnyTransactionId,
        call: CallHandle,
        retried: AnyTransactionId,
    ) {
        self.by_offer.remove(&id);
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

    /// Send offer retries that waited for a connection (§18.1.1).
    pub(crate) fn resume_parked_offers(&mut self, now: Instant) {
        let waiting: Vec<(AnyTransactionId, CallHandle)> = self
            .challenged_offers
            .iter()
            .filter(|(_, parked)| parked.waiting_for_stream)
            .map(|(id, parked)| (*id, parked.call))
            .collect();
        for (id, call) in waiting {
            let account = self.calls.get(&call).and_then(|held| held.account);
            let Some(credentials) = self.credentials_for_challenge(account, id) else {
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

    fn stop_waiting_for_offer(&mut self, id: AnyTransactionId) {
        if let Some(parked) = self.challenged_offers.get_mut(&id) {
            parked.waiting_for_stream = false;
        }
    }

    /// A challenged offer that got no retry is reported as refused. The core
    /// answers a challenge once, since repeating a wrong password locks
    /// accounts (§22.1). Ones waiting for a connection are skipped.
    pub(crate) fn settle_offer_challenges(&mut self) {
        let parked: Vec<(AnyTransactionId, ParkedOffer)> =
            crate::calls::settled(&mut self.challenged_offers, |offer| {
                offer.waiting_for_stream
            });
        for (id, offer) in parked {
            self.on_offer_refused(offer.call, id, offer.status, offer.response);
        }
    }

    /// The session stays unchanged (§14.1).
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
            // §5.3 reuses §14.1's ranges; the caller owns the Call-ID
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

    fn on_offer_in(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let raw = request.as_raw();
        // RFC 3261 §8.2.3 runs first: a 415 refreshes no session timer
        // (RFC 4028 §9). Recording metadata rides beside the offer
        // (RFC 7866 §9.1)
        let recorded = self
            .recording_server
            .then(|| crate::siprec::session_part(&raw))
            .flatten();
        if recorded.is_none()
            && let Some(refusal) = crate::admission::body_refusal(&raw)
        {
            self.answer_with(call, transaction, &refusal, now).ok();
            return;
        }
        self.note_far_end(call, &raw);
        // RFC 4028 §7.4
        self.on_refresh_in(call, &raw, now);
        let arriving = match recorded {
            Some(described) => sdp::parse_with_limits(described, self.sdp_limits)
                .map_or(Arriving::Unreadable, |offer| {
                    Arriving::Offer(Box::new(offer))
                }),
            None => arriving(&raw, self.sdp_limits),
        };
        let invite = matches!(transaction, AnyTransactionId::InviteServer(_));

        // an UPDATE without SDP only refreshes the target
        if matches!(arriving, Arriving::Nothing) && !invite {
            self.acknowledge_only(call, transaction, now);
            return;
        }

        // RFC 3311 §5.2 for both methods: crossing our offer gets 491, an
        // earlier far-end offer still pending gets 500 with Retry-After. A
        // re-INVITE without SDP counts too. Ours crosses only while on the
        // wire; one already refused 491 is over, so the far end's retry in
        // that wait is accepted. An offer we put in a 2xx is pending until
        // the ACK, so a request overtaking that ACK is told to wait
        if self.calls.get(&call).is_some_and(|held| {
            held.session.answer_owed
                || held
                    .offering
                    .as_ref()
                    .is_some_and(|offer| offer.transaction.is_some())
        }) {
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
            Arriving::Unreadable => {
                let refusal = OutgoingResponse::new(StatusCode::NOT_ACCEPTABLE_HERE)
                    .header(HeaderName::Warning, WHY_488);
                self.answer_with(call, transaction, &refusal, now).ok();
            }
            Arriving::Offer(offer) => {
                if !self.take_offer(call, transaction, &offer, now) {
                    self.hand_over(call, transaction, *offer, None, request);
                }
            }
        }
    }

    /// The dialog ended with a far-end change pending: answer it 487
    /// (§15.1.2) so the far end stops retransmitting.
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

    /// Clear far-end UPDATE/PRACK offers the application never answered and
    /// the endpoint closed (408 after 64·T1). Left pending, every later offer
    /// would get 500 (RFC 3311 §5.2). The session is unchanged. For a PRACK
    /// the held 2xx to the INVITE goes now, as its provisional was already
    /// matched (RFC 3262 §3).
    ///
    /// Read from transaction state, not `TransactionTerminated`: on UDP
    /// Timer J keeps it `Completed` 32 s longer (RFC 3261 §17.2.2).
    pub(crate) fn settle_unanswered_changes(&mut self, now: Instant) {
        let endpoint = &self.endpoint;
        let settled: Vec<(CallHandle, bool)> = self
            .calls
            .iter()
            .filter_map(|(handle, held)| {
                let answering = held.answering.as_ref()?;
                let AnyTransactionId::NonInviteServer(transaction) = answering.transaction else {
                    return None;
                };
                let open = matches!(
                    endpoint.transaction_state(transaction),
                    Some(NonInviteServerState::Trying | NonInviteServerState::Proceeding)
                );
                (!open).then_some((*handle, answering.prack.is_some()))
            })
            .collect();
        for (call, prack) in settled {
            if let Some(held) = self.calls.get_mut(&call) {
                held.answering = None;
            }
            if prack {
                self.acknowledged(call, now);
            }
        }
    }

    /// Answer a same-media offer here; `false` when it must go to the
    /// application.
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
            held.overtake();
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
            held.overtake();
        }
    }

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
    pub(crate) fn hand_over(
        &mut self,
        call: CallHandle,
        transaction: AnyTransactionId,
        offer: SessionDescription,
        prack: Option<ProvisionalResponseId>,
        request: &OwnedMessage,
    ) {
        if let Some(held) = self.calls.get_mut(&call) {
            held.answering = Some(Answering {
                transaction,
                offer,
                prack,
            });
        }
        self.events.push_back(UaEvent::Reoffer {
            call,
            request: request.clone(),
        });
    }

    /// The ACK for a 2xx this end answered with an offer.
    pub(crate) fn on_ack(&mut self, call: CallHandle, request: &OwnedMessage) {
        let Some(held) = self.calls.get_mut(&call) else {
            return;
        };
        if !held.session.answer_owed {
            return;
        }
        // cleared even if the answer is missing or bad: only this ACK may
        // carry it (§13.2.2.4), and a stuck flag would block every change
        held.session.answer_owed = false;
        let body = request.as_raw().body();
        if body.is_empty() {
            return;
        }
        let Ok(answer) = sdp::parse_with_limits(body, self.sdp_limits) else {
            return;
        };
        held.session.set_remote(answer);
        self.report_session(call);
    }
}

enum Arriving {
    Nothing,
    Offer(Box<SessionDescription>),
    /// Labelled SDP that does not parse.
    Unreadable,
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
        // an optional body (RFC 3261 §20.11) is ignored (RFC 3204 §6): the
        // request is answered as if it had none
        _ => Arriving::Nothing,
    }
}

/// The glare wait (§14.1, RFC 3311 §5.3). The caller and callee draw from
/// non-overlapping ranges so they do not collide again.
fn glare_backoff(owner: bool, entropy: &[u8]) -> Duration {
    let (low, high) = if owner { OWNER_BACKOFF } else { GUEST_BACKOFF };
    let steps = (high - low) / BACKOFF_STEP + 1;
    Duration::from_millis(low + (u64::from(spread(entropy)) % steps) * BACKOFF_STEP)
}
