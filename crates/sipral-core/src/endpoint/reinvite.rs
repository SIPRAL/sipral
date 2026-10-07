// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Renegotiating a session that is already up (RFC 3261 §14).
//!
//! A re-INVITE never forks (§14.1), so its responses go straight to the one
//! dialog, never through a [`crate::dialog::DialogSet`]. Its ACK carries this
//! INVITE's `CSeq` (§13.2.2.4) and is resent for every 2xx retransmission.
//!
//! Glare (§14): the end that receives a crossing INVITE says 491, and the
//! other waits a random interval. The endpoint draws it because it owns the
//! entropy.
//!
//! RFC 3311 §5.2's offer-based rules for UPDATE belong to the layer above;
//! only the second-UPDATE-before-answer rule is enforced here.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::driver::Endpoint;
use super::error::AckError;
use super::event::{DialogEndReason, Event, FailureReason};
use super::outgoing::OutgoingResponse;
use super::reliable;
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
    /// The request as it went out; the ACK takes its `CSeq` and credentials.
    request: OwnedMessage,
    answered: bool,
    /// Whether any final response has; a refusal completes it (§14.1).
    settled: bool,
    /// The ACK and the flow it left on (maybe a stream, §18.1.1).
    ack: Option<(OwnedMessage, Flow)>,
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

    /// The ACK and the flow it left on, once there is one.
    fn ack_for(&self, id: TransactionId<InviteClient>) -> Option<(&OwnedMessage, Flow)> {
        self.ours
            .get(&id)
            .and_then(|sent| sent.ack.as_ref())
            .map(|(ack, flow)| (ack, *flow))
    }

    fn keep_ack(&mut self, id: TransactionId<InviteClient>, ack: OwnedMessage, flow: Flow) {
        if let Some(sent) = self.ours.get_mut(&id) {
            sent.ack = Some((ack, flow));
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
    /// Unlike [`Endpoint::ack_2xx`], there is no fork to pick from. The
    /// `answer` is for a 2xx that carried an offer. Retransmitted 2xx get the
    /// same ACK without involving the caller.
    ///
    /// # Errors
    /// [`AckError`] for an unknown handle, no 2xx yet, a second ACK, or as
    /// [`Endpoint::ack_2xx`] when §18.1.1 finds no stream.
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
        let (ack, flow) = self.build_in_dialog(&plan, flow, None, answer)?;
        self.reinvites.keep_ack(invite, ack.clone(), flow);
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
    /// An acknowledged 2xx or a refusal completes it, even while the
    /// transaction lingers to absorb duplicates; otherwise the dialog would
    /// stay shut far longer than the 491 back-off.
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
    /// Fed directly to the dialog (§12.2.1.2).
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
        if status == StatusCode::TRYING {
            return;
        }

        // §13.2.2.4: resend the kept ACK for each 2xx retransmission, on the
        // flow the first went on
        if status.is_success()
            && let Some((ack, went_on)) = self
                .reinvites
                .ack_for(id)
                .map(|(ack, went_on)| (ack.clone(), went_on))
        {
            if let Some(went_on) = self.flow_for_kept_ack(went_on, flow, &ack) {
                self.note_wire(
                    &ack.as_raw(),
                    Reason::RequestRetransmitted,
                    Direction::Outbound,
                    went_on,
                );
                self.count_retransmission(true, None);
                self.queue(went_on.transmit(ack.bytes()));
            }
            return;
        }

        let before = self
            .dialogs
            .get(dialog)
            .map(|held| held.remote_target().as_str().to_owned());
        let state = self
            .dialogs
            .get_mut(dialog)
            .and_then(|held| held.on_response(response).ok());
        self.resolve_if_target_moved(dialog, before.as_deref());

        if status.is_provisional() {
            // RFC 3262 §3 and §4 apply inside a dialog too
            let provisional = reliable::is_reliable(response)
                .then(|| self.keep_reliable_provisional(dialog, response, flow))
                .flatten()
                .map(|(_, provisional)| provisional);
            self.push(Event::ReinviteProgress {
                invite: id,
                dialog,
                status,
                provisional,
                response: response.to_owned(),
            });
            return;
        }

        if status.is_success() {
            // a retransmitted 2xx before the first ACK is built: report once
            if self.reinvites.answered(id) {
                return;
            }
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
            // §14.1: retrying is the caller's choice
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

        // §12.2.1.2: a 481 or 408 ends the dialog, and no BYE goes out
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
    /// The ranges do not overlap. The `Call-ID` owner is the end that placed
    /// the call, the one whose dialogs are branches.
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
    /// Ours in flight: 491. Theirs still unanswered: 500 with `Retry-After`.
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

    /// RFC 3311 §5.2: a second UPDATE before the first is answered gets 500
    /// with `Retry-After`.
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

    /// A refusal with a random `Retry-After`.
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
