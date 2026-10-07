// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The endpoint's half of RFC 3262. Bookkeeping lives in `reliable`; this is
//! where it is touched: sending, a PRACK arriving (or a 481 when it matches
//! nothing), a reliable 1xx arriving, and 64·T1 passing, after which §3
//! rejects the INVITE with a 5xx.

use std::sync::Arc;
use std::time::Instant;

use super::driver::{Deadline, Endpoint, assemble_response};
use super::error::{PrackError, RespondError, SendError};
use super::event::Event;
use super::outgoing::{OutgoingInDialogRequest, OutgoingResponse};
use super::reliable::{self, FIRST_RSEQ_CEILING, OPTION_100REL, Reliable, Sent};
use super::table::Flow;
use crate::diag::{Direction, Reason};
use crate::msg::{HeaderName, Method, RawMessage, StatusCode};
use crate::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteServer, ProvisionalResponseId,
    Raw, TransactionId,
};

impl Endpoint {
    /// Answer an INVITE with a provisional response retransmitted until it is
    /// acknowledged (RFC 3262 §3).
    ///
    /// # Errors
    /// [`RespondError::NotProvisional`] for anything but 101 to 199,
    /// [`RespondError::NotOffered`] when the INVITE did not list `100rel`, and
    /// [`RespondError::StillUnacknowledged`] while a previous one is outstanding.
    pub fn respond_reliable(
        &mut self,
        transaction: TransactionId<InviteServer>,
        response: &OutgoingResponse,
        now: Instant,
    ) -> Result<ProvisionalResponseId, RespondError> {
        self.mark(now);
        let entry = self
            .transactions
            .invite_server(transaction)
            .ok_or(RespondError::NoSuchTransaction)?;
        let flow = entry.flow;
        let request = entry.request.clone();
        let status = response.status;

        // §3: only 101 to 199 may be sent reliably
        if !status.is_provisional() || status.get() < 101 {
            return Err(RespondError::NotProvisional);
        }
        if !reliable::offers_100rel(&request.as_raw()) {
            return Err(RespondError::NotOffered);
        }
        if self.reliable.outstanding_on(transaction) {
            return Err(RespondError::StillUnacknowledged);
        }

        let cseq = request
            .as_raw()
            .cseq()
            .map_err(|_| RespondError::Build(crate::msg::BuildError::MissingField("CSeq")))?
            .seq;
        let method = reliable::answered_method(&request.as_raw());

        let tag = self.tag_or_mint(AnyTransactionId::InviteServer(transaction));
        let first = self.tokens.number(FIRST_RSEQ_CEILING);
        let rseq = self.reliable.next_rseq(transaction, first);

        // §3: Require: 100rel and RSeq are mandatory
        let marked = response
            .clone()
            .header(HeaderName::Require, OPTION_100REL.as_bytes())
            .header(HeaderName::RSeq, rseq.to_string().as_bytes());
        let message = super::driver::build_response(&request, &marked, Some(&tag))?;

        // §4 has the 1xx establish a dialog; the sender must make that true
        let dialog =
            self.open_uas_dialog(&request, &tag, status, flow)
                .ok_or(RespondError::Build(crate::msg::BuildError::MissingField(
                    "Contact",
                )))?;
        // the dialog exists now and counts against the ceiling on its own
        self.admitted.remove(&transaction);

        let entry = self
            .transactions
            .invite_server_mut(transaction)
            .ok_or(RespondError::NoSuchTransaction)?;
        let effects = entry.machine.respond(message.clone(), now);
        if effects.send.is_none() {
            return Err(RespondError::TooLate);
        }
        self.apply(effects, flow, AnyTransactionId::InviteServer(transaction));

        // §3: doubles from T1 with no cap, unlike a 2xx
        let raw = self.reliable.keep(Reliable {
            dialog,
            rseq,
            cseq,
            method,
            flow,
            sent: Some(Sent {
                invite: transaction,
                message,
                attempt: 0,
                give_up_at: now + self.config.timers.sixty_four_t1(),
                timer: None,
                acknowledged: false,
                quiet: false,
            }),
        });
        self.arm_reliable(raw, now);
        Ok(ProvisionalResponseId::new(dialog, rseq, raw))
    }

    /// Acknowledge a reliable provisional response (RFC 3262 §4).
    ///
    /// The body is the answer when the response carried an offer (§5).
    ///
    /// # Errors
    /// [`PrackError`] when the response is no longer outstanding, or its
    /// dialog has ended.
    pub fn prack(
        &mut self,
        provisional: ProvisionalResponseId,
        body: Option<Arc<[u8]>>,
        now: Instant,
    ) -> Result<TransactionId<crate::transaction::NonInviteClient>, PrackError> {
        let raw = provisional.raw;
        let held = self.reliable.get(raw).ok_or(PrackError::NoSuchResponse)?;
        let dialog = held.dialog;
        let rack = reliable::rack_value(held);

        let mut request =
            OutgoingInDialogRequest::new(Method::Prack).header(HeaderName::RAck, &rack);
        if let Some(body) = body {
            request = request.body(b"application/sdp", body);
        }
        let id = self
            .request_in_dialog(dialog, &request, now)
            .map_err(|error| match error {
                SendError::NoSuchDialog => PrackError::NoSuchDialog,
                other => PrackError::Send(other),
            })?;
        // §4: a retransmitted 1xx is dropped before the caller sees it, so the
        // PRACK is never retransmitted for it
        self.reliable.forget(raw);
        Ok(id)
    }
}

impl Endpoint {
    /// Answer a PRACK with a refusal, and put the provisional response it
    /// named back on the list of unacknowledged ones.
    ///
    /// RFC 3262 §3 removes the response only after RFC 3261 §8.2 processing,
    /// which can refuse the PRACK (420, 415, or 488 per §14.2 and RFC 3262 §5).
    /// Such a PRACK acknowledged nothing, and the retry with the same `RAck`
    /// would otherwise get a 481 that ends the dialog (§12.2.1.2). So the
    /// response goes back on the list and retransmits again, unless the INVITE
    /// already has its final response. A 2xx puts nothing back.
    ///
    /// # Errors
    /// As [`Self::respond`]; nothing is put back when the answer could not go.
    pub fn refuse_prack(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        provisional: ProvisionalResponseId,
        response: &OutgoingResponse,
        now: Instant,
    ) -> Result<(), RespondError> {
        self.respond(transaction, response, now)?;
        if response.status.is_success() {
            return Ok(());
        }
        let raw = provisional.raw;
        let Some(sent) = self
            .reliable
            .get_mut(raw)
            .and_then(|reliable| reliable.sent.as_mut())
        else {
            return Ok(());
        };
        if !sent.acknowledged {
            return Ok(());
        }
        sent.acknowledged = false;
        let quiet = sent.quiet;
        if !quiet {
            self.arm_reliable(raw, now);
        }
        Ok(())
    }
}

impl Endpoint {
    /// RFC 3262 §4 bookkeeping for a reliable 1xx: mint the PRACK handle, or
    /// `None` when it is out of order. Also used for re-INVITE provisionals,
    /// which §3 does not exclude.
    pub(super) fn keep_reliable_provisional(
        &mut self,
        dialog: DialogId,
        response: &RawMessage<'_>,
        flow: Flow,
    ) -> Option<(StatusCode, ProvisionalResponseId)> {
        let (Ok(rseq), Ok(cseq), Some(status)) =
            (response.rseq(), response.cseq(), response.status())
        else {
            return None;
        };
        // §4: retransmissions and gaps are not processed
        if !self.reliable.in_order(dialog, rseq) {
            return None;
        }
        let raw = self.reliable.keep(Reliable {
            dialog,
            rseq,
            cseq: cseq.seq,
            method: Box::from(cseq.method.as_str().as_bytes()),
            flow,
            sent: None,
        });
        Some((status, ProvisionalResponseId::new(dialog, rseq, raw)))
    }

    /// A provisional response to an initial INVITE that says it was sent
    /// reliably.
    pub(super) fn on_reliable_provisional(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
        response: &RawMessage<'_>,
        flow: Flow,
    ) {
        let Some((status, provisional)) = self.keep_reliable_provisional(dialog, response, flow)
        else {
            return;
        };
        self.push(Event::ReliableProvisional {
            invite,
            dialog,
            provisional,
            status,
            response: response.to_owned(),
        });
    }

    /// A PRACK arrived on a server transaction we have just created.
    ///
    /// A PRACK that matches nothing is answered 481 here (§3).
    pub(super) fn on_prack(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        dialog: Option<DialogId>,
        request: &RawMessage<'_>,
        now: Instant,
    ) {
        let matched = dialog.zip(request.rack().ok()).and_then(|(dialog, rack)| {
            self.reliable
                .answered_by(dialog, &rack)
                .map(|raw| (dialog, raw))
        });

        let Some((dialog, raw)) = matched else {
            // §3: no matching unacknowledged response means 481
            self.answer_status(transaction, StatusCode::CALL_DOES_NOT_EXIST, now);
            return;
        };

        // §3: stop retransmitting. Marked, not forgotten, since the layer above
        // may still refuse it ([`Self::refuse_prack`]).
        let rseq = self.acknowledge_reliable(raw).unwrap_or_default();
        self.push(Event::IncomingPrack {
            transaction,
            provisional: ProvisionalResponseId::new(dialog, rseq, raw),
            request: request.to_owned(),
        });
    }
}

impl Endpoint {
    /// Schedule the next retransmission of a reliable provisional response.
    fn arm_reliable(&mut self, raw: Raw, now: Instant) {
        let Some(reliable) = self.reliable.get(raw) else {
            return;
        };
        let Some(sent) = reliable.sent.as_ref() else {
            return;
        };
        let at = now + self.config.timers.retransmit(sent.attempt, None);
        let handle = self.schedule(at, Deadline::Reliable(raw));
        if let Some(sent) = self
            .reliable
            .get_mut(raw)
            .and_then(|reliable| reliable.sent.as_mut())
        {
            sent.timer = Some(handle);
        }
    }

    /// The retransmission timer of a reliable provisional response fired.
    pub(super) fn retransmit_reliable(&mut self, raw: Raw, now: Instant) {
        let Some(reliable) = self.reliable.get(raw) else {
            return;
        };
        let flow = reliable.flow;
        let Some(sent) = reliable.sent.as_ref() else {
            return;
        };
        if now >= sent.give_up_at {
            // §3: 64·T1 without a PRACK, reject the INVITE with a 5xx
            let invite = sent.invite;
            self.reliable.forget(raw);
            self.count_timeout();
            self.refuse_unacknowledged(invite, now);
            return;
        }

        let repeated = sent.message.clone();
        let invite = sent.invite;
        self.note_wire(
            &repeated.as_raw(),
            Reason::ResponseRetransmitted,
            Direction::Outbound,
            flow,
        );
        self.count_retransmission(false, Some(AnyTransactionId::InviteServer(invite)));
        self.queue(flow.transmit(repeated.bytes()));
        if let Some(sent) = self
            .reliable
            .get_mut(raw)
            .and_then(|reliable| reliable.sent.as_mut())
        {
            sent.attempt = sent.attempt.saturating_add(1);
        }
        self.arm_reliable(raw, now);
    }

    /// Stop retransmitting one a PRACK matched, without forgetting it.
    fn acknowledge_reliable(&mut self, raw: Raw) -> Option<u32> {
        let reliable = self.reliable.get_mut(raw)?;
        let rseq = reliable.rseq;
        let handle = reliable.sent.as_mut().and_then(|sent| {
            sent.acknowledged = true;
            sent.timer.take()
        });
        if let Some(handle) = handle {
            self.deadlines.cancel(handle);
        }
        Some(rseq)
    }

    /// Stop retransmitting one, and forget it. Returns its `RSeq`.
    pub(super) fn stop_reliable(&mut self, raw: Raw) -> Option<u32> {
        let reliable = self.reliable.forget(raw)?;
        if let Some(handle) = reliable.sent.and_then(|sent| sent.timer) {
            self.deadlines.cancel(handle);
        }
        Some(reliable.rseq)
    }

    /// Stop retransmitting everything this INVITE sent, without forgetting it.
    ///
    /// §3: after a final response, stop retransmitting but still accept PRACKs.
    pub(super) fn quiet_reliable(&mut self, invite: TransactionId<InviteServer>) {
        for raw in self.reliable.on_invite(invite) {
            let handle = self
                .reliable
                .get_mut(raw)
                .and_then(|reliable| reliable.sent.as_mut())
                .and_then(|sent| {
                    sent.quiet = true;
                    sent.timer.take()
                });
            if let Some(handle) = handle {
                self.deadlines.cancel(handle);
            }
        }
    }

    /// This INVITE is over: forget what it was holding.
    pub(super) fn forget_reliable_on(&mut self, invite: TransactionId<InviteServer>) {
        for raw in self.reliable.on_invite(invite) {
            self.stop_reliable(raw);
        }
        self.reliable.forget_series(invite);
    }

    /// This dialog is over: forget what it was holding.
    pub(super) fn forget_reliable_in(&mut self, dialog: DialogId) {
        for raw in self.reliable.on_dialog(dialog) {
            self.stop_reliable(raw);
        }
        self.reliable.forget_heard(dialog);
    }

    /// Nothing acknowledged the reliable provisional response, so the call
    /// cannot go on.
    fn refuse_unacknowledged(&mut self, invite: TransactionId<InviteServer>, now: Instant) {
        let Some(entry) = self.transactions.invite_server(invite) else {
            return;
        };
        let flow = entry.flow;
        let request = entry.request.clone();
        let tag = self.tag_for(AnyTransactionId::InviteServer(invite));
        let Ok(message) = assemble_response(&request, StatusCode::SERVER_ERROR, tag.as_deref())
        else {
            return;
        };
        // the refusal ends the early dialog the unacknowledged response opened
        let early = self.early_dialog_of(invite);
        if let Some(entry) = self.transactions.invite_server_mut(invite) {
            let effects = entry.machine.respond(message, now);
            let refused = effects.send.is_some();
            self.apply(effects, flow, AnyTransactionId::InviteServer(invite));
            if refused {
                self.end_refused_early(invite, early);
            }
        }
    }

    /// Answer a server transaction with a bare status.
    fn answer_status(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        status: StatusCode,
        now: Instant,
    ) {
        let response = OutgoingResponse::new(status);
        self.respond(transaction, &response, now).ok();
    }
}
