// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Renegotiating a session that is already up (RFC 3261 §14).
//!
//! A re-INVITE reads like an INVITE and behaves like nothing of the sort.
//! "Unlike an INVITE, which can fork, a re-INVITE will never fork, and
//! therefore, only ever generate a single final response" (§14.1) — its
//! Request-URI names the one user agent the dialog was established with, not
//! an address of record a proxy could spread across three phones. So its
//! responses never reach a [`crate::dialog::DialogSet`] looking for branches
//! to open. There is one dialog, it already exists, and the response is fed
//! straight to it.
//!
//! The ACK is the dialog's, exactly as for the first 2xx, and is built from
//! *this* INVITE: §13.2.2.4 makes its `CSeq` the acknowledged request's, and a
//! re-INVITE carries a number the original INVITE never had. It is kept and
//! sent again for every retransmission of the 2xx it answers.
//!
//! Then there is glare. Both ends putting the call on hold at the same instant
//! is the ordinary way two INVITEs cross inside one dialog, and §14 answers it
//! from both sides: the end that receives one while its own is outstanding
//! says 491, and the end that receives the 491 waits a random interval before
//! trying again. Random on purpose — a fixed wait collides a second time — and
//! drawn here because the endpoint owns the entropy and the caller owns the
//! clock.
//!
//! What is *not* here is RFC 3311 §5.2's other half. Its 491 and 500 for
//! UPDATE turn on whether an offer is outstanding, and this crate has no
//! opinion about offers: `sdp` parses them, and which one is answered is the
//! layer above's. Only the rule that turns on transaction state — a second
//! UPDATE before the first is answered — can be decided here, and it is.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::driver::Endpoint;
use super::error::AckError;
use super::event::{DialogEndReason, Event, FailureReason};
use super::outgoing::OutgoingResponse;
use super::table::Flow;
use crate::diag::{Direction, Reason};
use crate::dialog::DialogState;
use crate::msg::{HeaderName, OwnedMessage, RawMessage, StatusCode};
use crate::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteServer, TransactionId,
};

/// §14.1's back-off for the end that owns the `Call-ID`.
const OWNER_BACKOFF: (Duration, Duration) = (Duration::from_millis(2_100), Duration::from_secs(4));
/// And for the end that does not.
const GUEST_BACKOFF: (Duration, Duration) = (Duration::ZERO, Duration::from_secs(2));
/// §14.2 and RFC 3311 §5.2 both ask for a `Retry-After` "between 0 and 10
/// seconds", and the field carries whole seconds.
const RETRY_AFTER_CEILING: u32 = 11;

/// One re-INVITE this end sent.
#[derive(Debug)]
struct Sent {
    dialog: DialogId,
    /// The request as it went out. The ACK takes its `CSeq` and its
    /// credentials from here rather than from the INVITE that opened the call.
    request: OwnedMessage,
    /// Whether a 2xx has arrived, which is what makes an ACK possible.
    answered: bool,
    /// Whether any final response has. §14.1 lets a new INVITE go once the
    /// transaction is "completed or terminated", and a refusal completes it —
    /// the ACK for a non-2xx is the transaction's own, not the dialog's.
    settled: bool,
    /// The ACK once the caller has built it, kept for the retransmissions.
    ack: Option<OwnedMessage>,
}

/// The INVITEs and UPDATEs running inside dialogs, in both directions.
#[derive(Debug, Default)]
pub(super) struct Reinvites {
    ours: HashMap<TransactionId<InviteClient>, Sent>,
    /// The dialog each of ours is in, so that a second one is refused.
    sending: HashMap<DialogId, TransactionId<InviteClient>>,
    /// The INVITE the far end has unanswered in a dialog.
    their_invite: HashMap<DialogId, TransactionId<InviteServer>>,
    /// The UPDATE it has unanswered there (RFC 3311 §5.2).
    their_update: HashMap<DialogId, TransactionId<NonInviteServer>>,
}

impl Reinvites {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Follow a re-INVITE that is about to go out.
    pub(super) fn start(
        &mut self,
        id: TransactionId<InviteClient>,
        dialog: DialogId,
        request: OwnedMessage,
    ) {
        self.ours.insert(
            id,
            Sent {
                dialog,
                request,
                answered: false,
                settled: false,
                ack: None,
            },
        );
        self.sending.insert(dialog, id);
    }

    /// The dialog a re-INVITE is in, and `None` for an INVITE that opened one.
    pub(super) fn dialog_of(&self, id: TransactionId<InviteClient>) -> Option<DialogId> {
        self.ours.get(&id).map(|sent| sent.dialog)
    }

    /// Ours in this dialog, while it is still running.
    pub(super) fn ours_in(&self, dialog: DialogId) -> Option<TransactionId<InviteClient>> {
        self.sending.get(&dialog).copied()
    }

    /// The re-INVITE as it went out.
    fn request(&self, id: TransactionId<InviteClient>) -> Option<&OwnedMessage> {
        self.ours.get(&id).map(|sent| &sent.request)
    }

    /// A 2xx arrived for it.
    fn answer(&mut self, id: TransactionId<InviteClient>) {
        if let Some(sent) = self.ours.get_mut(&id) {
            sent.answered = true;
            sent.settled = true;
        }
    }

    /// A final response that is not a 2xx arrived.
    fn settle(&mut self, id: TransactionId<InviteClient>) {
        if let Some(sent) = self.ours.get_mut(&id) {
            sent.settled = true;
        }
    }

    /// Whether §14.1 still forbids a second INVITE because of this one.
    fn outstanding(&self, id: TransactionId<InviteClient>) -> bool {
        self.ours.get(&id).is_some_and(|sent| {
            if sent.answered {
                sent.ack.is_none()
            } else {
                !sent.settled
            }
        })
    }

    fn answered(&self, id: TransactionId<InviteClient>) -> bool {
        self.ours.get(&id).is_some_and(|sent| sent.answered)
    }

    /// The ACK, once there is one.
    fn ack_for(&self, id: TransactionId<InviteClient>) -> Option<&OwnedMessage> {
        self.ours.get(&id).and_then(|sent| sent.ack.as_ref())
    }

    fn keep_ack(&mut self, id: TransactionId<InviteClient>, ack: OwnedMessage) {
        if let Some(sent) = self.ours.get_mut(&id) {
            sent.ack = Some(ack);
        }
    }

    /// The transaction is over, and so is everything hung on it.
    pub(super) fn finish(&mut self, id: TransactionId<InviteClient>) {
        let Some(sent) = self.ours.remove(&id) else {
            return;
        };
        if self.sending.get(&sent.dialog) == Some(&id) {
            self.sending.remove(&sent.dialog);
        }
    }

    /// Every re-INVITE of a dialog that has ended.
    pub(super) fn forget_dialog(&mut self, dialog: DialogId) {
        self.ours.retain(|_, sent| sent.dialog != dialog);
        self.sending.remove(&dialog);
        self.their_invite.remove(&dialog);
        self.their_update.remove(&dialog);
    }

    /// An INVITE the far end has sent us and we have not finally answered.
    pub(super) fn receive_invite(
        &mut self,
        dialog: DialogId,
        id: TransactionId<InviteServer>,
    ) -> Option<TransactionId<InviteServer>> {
        self.their_invite.insert(dialog, id)
    }

    pub(super) fn their_invite_in(&self, dialog: DialogId) -> Option<TransactionId<InviteServer>> {
        self.their_invite.get(&dialog).copied()
    }

    /// Likewise for an UPDATE (RFC 3311 §5.2).
    pub(super) fn receive_update(
        &mut self,
        dialog: DialogId,
        id: TransactionId<NonInviteServer>,
    ) -> Option<TransactionId<NonInviteServer>> {
        self.their_update.insert(dialog, id)
    }

    pub(super) fn their_update_in(
        &self,
        dialog: DialogId,
    ) -> Option<TransactionId<NonInviteServer>> {
        self.their_update.get(&dialog).copied()
    }

    /// A final response has gone out on one of theirs.
    pub(super) fn answered_theirs(&mut self, id: AnyTransactionId) {
        match id {
            AnyTransactionId::InviteServer(inner) => {
                self.their_invite.retain(|_, known| *known != inner);
            }
            AnyTransactionId::NonInviteServer(inner) => {
                self.their_update.retain(|_, known| *known != inner);
            }
            AnyTransactionId::InviteClient(_) | AnyTransactionId::NonInviteClient(_) => (),
        }
    }
}

// -- what this end sends -----------------------------------------------------

impl Endpoint {
    /// Acknowledge the 2xx to a re-INVITE (§14.1, §13.2.2.4).
    ///
    /// Separate from [`Endpoint::ack_2xx`] because the two acknowledge
    /// different things. That one answers the INVITE that opened the call and
    /// has to say which of several forked dialogs it is answering for; this
    /// one answers a request inside a dialog that already exists, and there is
    /// only ever one. A re-INVITE sent without an offer is answered by an
    /// offer in the 2xx, so the answer travels in this ACK — which is why the
    /// caller builds it and the endpoint cannot know when it is ready.
    ///
    /// Afterwards the ACK belongs to the dialog: every retransmission of the
    /// 2xx is answered with the same bytes and the caller hears nothing more.
    ///
    /// # Errors
    /// [`AckError`] when the handle names no re-INVITE this endpoint is
    /// following, when no 2xx has arrived for it, or when it has already been
    /// acknowledged.
    pub fn ack_reinvite(
        &mut self,
        invite: TransactionId<InviteClient>,
        answer: Option<&[u8]>,
        now: Instant,
    ) -> Result<(), AckError> {
        self.mark(now);
        let dialog = self
            .reinvites
            .dialog_of(invite)
            .ok_or(AckError::NoSuchDialog)?;
        if !self.reinvites.answered(invite) {
            return Err(AckError::NotAnswered);
        }
        if self.reinvites.ack_for(invite).is_some() {
            return Err(AckError::AlreadyAcknowledged);
        }
        let flow = self.dialogs.flow(dialog).ok_or(AckError::NoSuchDialog)?;
        let request = self
            .reinvites
            .request(invite)
            .ok_or(AckError::NoSuchDialog)?
            .clone();
        let plan = self
            .dialogs
            .get(dialog)
            .ok_or(AckError::NoSuchDialog)?
            .ack_2xx(&request.as_raw())
            .map_err(|_| AckError::NotAnswered)?;
        let ack = self.build_in_dialog(&plan, flow, None, answer)?;
        self.reinvites.keep_ack(invite, ack.clone());
        self.note_wire(
            &ack.as_raw(),
            Reason::RequestSent,
            Direction::Outbound,
            flow,
        );
        self.queue(flow.transmit(ack.bytes()));
        Ok(())
    }

    /// Whether this end has an INVITE outstanding in the dialog (§14.1).
    ///
    /// Outstanding is not "its client transaction still exists". §14.1 lets a
    /// new INVITE go once the old transaction is "completed or terminated",
    /// and both a 2xx that has been acknowledged and a refusal complete it —
    /// the ACK for a non-2xx belongs to the transaction, not to the dialog.
    /// Reading it any other way would hold the dialog shut for the timer that
    /// only exists to absorb duplicates: 64·T1 after a 2xx under RFC 6026, or
    /// 32 seconds after a refusal, which is a great deal longer than the 2.1
    /// to 4 seconds §14.1 gives a 491 before it wants the change offered
    /// again.
    pub(super) fn invite_outstanding(&self, dialog: DialogId) -> bool {
        if let Some(id) = self.reinvites.ours_in(dialog) {
            return self.reinvites.outstanding(id);
        }
        if self.dialogs.opening_invite(dialog).is_none() {
            return false;
        }
        let Some(set) = self.dialogs.branch_set(dialog) else {
            return false;
        };
        let Some(key) = self.dialogs.get(dialog).map(|d| d.key().clone()) else {
            return false;
        };
        self.dialogs
            .set(set)
            .is_none_or(|branches| branches.ack_for(&key).is_none())
    }

    /// Follow a re-INVITE that has just gone out.
    pub(super) fn watch_reinvite(
        &mut self,
        id: TransactionId<InviteClient>,
        dialog: DialogId,
        request: OwnedMessage,
    ) {
        self.reinvites.start(id, dialog, request);
    }
}

// -- what comes back ---------------------------------------------------------

impl Endpoint {
    /// A response to a re-INVITE this end sent.
    ///
    /// Not a fork: §14.1 says a re-INVITE never forks, so nothing here looks
    /// for a dialog to open. The dialog is the one the request was sent in,
    /// and the response feeds it directly (§12.2.1.2) — the remote target from
    /// a 2xx, and the dialog itself from a 481 or a 408.
    pub(super) fn on_reinvite_response(
        &mut self,
        id: TransactionId<InviteClient>,
        dialog: DialogId,
        response: &RawMessage<'_>,
        flow: Flow,
    ) {
        let Some(status) = response.status() else {
            return;
        };
        // a 100 is hop by hop and names nothing
        if status == StatusCode::TRYING {
            return;
        }

        // §13.2.2.4: "The ACK MUST be passed to the client transport every
        // time a retransmission of the 2xx final response that triggered the
        // ACK arrives." The caller heard about the answer once
        if status.is_success()
            && let Some(ack) = self.reinvites.ack_for(id).cloned()
        {
            self.note_wire(
                &ack.as_raw(),
                Reason::RequestRetransmitted,
                Direction::Outbound,
                flow,
            );
            self.queue(flow.transmit(ack.bytes()));
            return;
        }

        let state = self
            .dialogs
            .get_mut(dialog)
            .and_then(|held| held.on_response(response).ok());

        if status.is_provisional() {
            self.push(Event::ReinviteProgress {
                invite: id,
                dialog,
                status,
                response: response.to_owned(),
            });
            return;
        }

        if status.is_success() {
            self.reinvites.answer(id);
            self.push(Event::ReinviteAnswered {
                invite: id,
                dialog,
                status,
                response: response.to_owned(),
            });
            return;
        }

        self.reinvites.settle(id);
        if status == StatusCode::REQUEST_PENDING {
            // §14.1: "it SHOULD start a timer with a value T chosen as
            // follows" — and try once more when it fires, if the session still
            // needs changing. Whether it does is the caller's to know
            let retry_in = self.glare_backoff(dialog);
            self.push(Event::ReinviteGlare {
                invite: id,
                dialog,
                retry_in,
                response: response.to_owned(),
            });
        } else {
            self.push(Event::ReinviteFailed {
                invite: id,
                dialog,
                status: Some(status),
                reason: FailureReason::Refused,
                response: Some(response.to_owned()),
            });
        }

        // §12.2.1.2: a 481 or a 408 to a request inside a dialog takes the
        // dialog with it. No BYE goes out for it — the far end has just said
        // it has no such dialog, and a BYE would earn the same 481
        if state == Some(DialogState::Terminated) {
            self.forget_dialog(dialog, DialogEndReason::Gone);
        }
    }

    /// A re-INVITE will not be answered: the transport died, or nothing came
    /// back within 64·T1.
    ///
    /// §12.2.1.2 treats a timeout as a 408, and terminates the dialog on one.
    pub(super) fn reinvite_gave_up(
        &mut self,
        id: TransactionId<InviteClient>,
        dialog: DialogId,
        reason: FailureReason,
    ) {
        self.push(Event::ReinviteFailed {
            invite: id,
            dialog,
            status: None,
            reason,
            response: None,
        });
        if let Some(held) = self.dialogs.get_mut(dialog) {
            held.terminate();
        }
        self.forget_dialog(dialog, DialogEndReason::Gone);
    }

    /// How long to wait before offering the same change again (§14.1).
    ///
    /// The two ranges do not overlap, which is the point: if both ends drew
    /// from the same one they would collide a second time as often as the
    /// first. Which range applies is decided by who generated the `Call-ID`,
    /// and that is the end that placed the call — the only end whose dialogs
    /// are branches of an INVITE it sent.
    fn glare_backoff(&mut self, dialog: DialogId) -> Duration {
        let (low, high) = if self.dialogs.branch_set(dialog).is_some() {
            OWNER_BACKOFF
        } else {
            GUEST_BACKOFF
        };
        self.tokens.interval(low, high)
    }
}

// -- what arrives ------------------------------------------------------------

impl Endpoint {
    /// Whether §14.2 answers this INVITE itself rather than handing it up.
    ///
    /// Two cases, both MUST, told apart by who has the other INVITE in flight.
    /// Ours means the two crossed, and 491 sends the far end away to back off
    /// by an interval that will not collide with ours. Theirs means it sent a
    /// second INVITE before we answered the first, which is not glare but a
    /// peer getting ahead of itself; §14.2 answers that 500 with a
    /// `Retry-After`, so that it does not repeat immediately.
    pub(super) fn refuse_crossing_invite(
        &mut self,
        dialog: DialogId,
        transaction: TransactionId<InviteServer>,
        flow: Flow,
        now: Instant,
    ) -> bool {
        let response = if self.invite_outstanding(dialog) {
            OutgoingResponse::new(StatusCode::REQUEST_PENDING)
        } else if self.reinvites.their_invite_in(dialog).is_some() {
            self.too_soon(StatusCode::SERVER_ERROR)
        } else {
            return false;
        };
        self.refuse(
            AnyTransactionId::InviteServer(transaction),
            &response,
            flow,
            now,
        );
        true
    }

    /// RFC 3311 §5.2: "A UAS that receives an UPDATE before it has generated a
    /// final response to a previous UPDATE on the same dialog MUST return a
    /// 500 response to the new UPDATE, and MUST include a Retry-After header
    /// field."
    pub(super) fn refuse_crossing_update(
        &mut self,
        dialog: DialogId,
        transaction: TransactionId<NonInviteServer>,
        flow: Flow,
        now: Instant,
    ) -> bool {
        if self.reinvites.their_update_in(dialog).is_none() {
            return false;
        }
        let response = self.too_soon(StatusCode::SERVER_ERROR);
        self.refuse(
            AnyTransactionId::NonInviteServer(transaction),
            &response,
            flow,
            now,
        );
        true
    }

    /// A refusal that says when to come back, with the interval drawn rather
    /// than fixed so that two peers do not repeat the collision.
    fn too_soon(&mut self, status: StatusCode) -> OutgoingResponse {
        let seconds = self
            .tokens
            .number(RETRY_AFTER_CEILING)
            .saturating_sub(1)
            .to_string();
        OutgoingResponse::new(status).header(HeaderName::RetryAfter, seconds.as_bytes())
    }

    /// Send a final response the endpoint decided on by itself.
    fn refuse(
        &mut self,
        transaction: AnyTransactionId,
        response: &OutgoingResponse,
        flow: Flow,
        now: Instant,
    ) {
        let request = match transaction {
            AnyTransactionId::InviteServer(id) => self
                .transactions
                .invite_server(id)
                .map(|e| e.request.clone()),
            AnyTransactionId::NonInviteServer(id) => self
                .transactions
                .non_invite_server(id)
                .map(|e| e.request.clone()),
            AnyTransactionId::InviteClient(_) | AnyTransactionId::NonInviteClient(_) => None,
        };
        let Some(request) = request else {
            return;
        };
        let tag = self.tag_or_mint(transaction);
        if let Ok(message) = super::driver::build_response(&request, response, Some(&tag)) {
            self.respond_raw(transaction, message, flow, now);
        }
    }
}
