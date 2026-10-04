// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Where the endpoint writes its decisions down.
//!
//! The decisions themselves are made in the modules beside this one and were
//! made before any of this existed; what is here is the reading end and the
//! four helpers the writing end calls, so that a decision site costs one line
//! and cannot get the bookkeeping wrong.
//!
//! Every record is found by `Call-ID`, which is the only name a call has that
//! both ends, every proxy and every capture agree on. What belongs to no call
//! — a transport that failed before anything was sent on it, a stranger's
//! request refused for want of room — goes to the endpoint's own record, which
//! is never the one evicted when the set is full.

use std::time::Instant;

use super::driver::Endpoint;
use super::event::FailureReason;
use super::table::Flow;
use crate::diag::{Decision, Direction, Reason, Record, WireEvent};
use crate::dialog::CallId;
use crate::msg::RawMessage;
use crate::transaction::{AnyTransactionId, DialogId};

/// The code for a failure the layer above is being told about.
///
/// One family of three, shared by an INVITE that will not connect and by an
/// ordinary request that will not be answered, because the question a reader
/// asks of both is the same one.
const fn failure_code(reason: FailureReason) -> Reason {
    match reason {
        FailureReason::Timeout => Reason::FailedTimeout,
        FailureReason::TransportFailed => Reason::FailedTransport,
        FailureReason::Refused => Reason::FailedRefused,
    }
}

impl Endpoint {
    /// What this endpoint decided about one call.
    ///
    /// Readable at any moment: while the call is ringing, while it is up, and
    /// after it has failed, for as long as the record has not been evicted to
    /// make room for a newer one
    /// ([`EndpointConfig::diagnostics`](super::EndpointConfig::diagnostics)).
    #[must_use]
    pub fn call_record(&self, call: &CallId) -> Option<&Record> {
        self.diag.record(call)
    }

    /// What this endpoint decided outside any call.
    ///
    /// Transports, floods, and everything else that happens before a call
    /// exists or after the last one has gone.
    #[must_use]
    pub const fn endpoint_record(&self) -> &Record {
        self.diag.endpoint()
    }

    /// Every call with a record, least recently written first — so the front
    /// of this is what the endpoint is about to forget.
    pub fn recorded_calls(&self) -> impl Iterator<Item = &CallId> {
        self.diag.calls()
    }

    /// How many records were made and have since been evicted.
    ///
    /// Not the same number as [`Record::dropped`], which counts decisions
    /// inside one record. This one climbing means the endpoint is holding more
    /// calls at once than it is configured to remember.
    #[must_use]
    pub const fn records_dropped(&self) -> u64 {
        self.diag.dropped()
    }

    /// Every record as one JSON document: what a bug report carries.
    #[must_use]
    pub fn diagnostics_json(&self) -> String {
        self.diag.to_json()
    }

    /// The time the caller is driving the endpoint at.
    ///
    /// Called by every entry point that takes one. Nothing here reads a clock,
    /// and no time passes inside a call into the endpoint, so this is the
    /// instant every decision that call makes is stamped with.
    pub(super) const fn mark(&mut self, now: Instant) {
        self.diag.mark(now);
    }

    /// One decision, against a call or against the endpoint.
    pub(super) fn note(&mut self, call: Option<&[u8]>, decision: Decision) {
        self.diag.note(call, decision);
    }

    /// A decision the layer above made about a message this endpoint handed
    /// it, written into the record of the call the message names.
    ///
    /// The endpoint delivers a response to a REGISTER and has no opinion about
    /// most of what is in it; the user agent reads further, and what it
    /// refuses to trust belongs in the same record as the send and the
    /// arrival around it rather than in a second one a reader has to line up
    /// by hand. The entry carries what every other one does — the reason, and
    /// the message by method or status and size — and never a header value,
    /// which is the rule that keeps a record safe to send unread.
    pub fn note_arrival(&mut self, message: &RawMessage<'_>, reason: Reason, now: Instant) {
        self.mark(now);
        let bytes = message.as_bytes().len();
        let wire = if let Some(status) = message.status() {
            WireEvent::response(status, Direction::Inbound, bytes)
        } else if let Some(method) = message.method() {
            WireEvent::request(method, Direction::Inbound, bytes)
        } else {
            return;
        };
        let decision = Decision::of(reason).caused_by(wire);
        self.diag.note(message.call_id().ok(), decision);
    }

    /// One decision about a message, which names the call it belongs to.
    pub(super) fn note_wire(
        &mut self,
        message: &RawMessage<'_>,
        reason: Reason,
        direction: Direction,
        flow: Flow,
    ) {
        // the length of the message as it stands is the length the caller
        // writes, which is what B1 asks to be readable without a capture
        let bytes = message.as_bytes().len();
        let wire = if let Some(status) = message.status() {
            WireEvent::response(status, direction, bytes)
        } else if let Some(method) = message.method() {
            WireEvent::request(method, direction, bytes)
        } else {
            return;
        };
        let decision = Decision::of(reason)
            .caused_by(wire)
            .at_address(flow.destination)
            .over(flow.protocol);
        self.diag.note(message.call_id().ok(), decision);
    }

    /// A request or a call this end sent will not succeed, and why.
    pub(super) fn note_failure(&mut self, call: Option<&CallId>, reason: FailureReason) {
        let decision = Decision::of(failure_code(reason));
        self.diag.note(call.map(CallId::as_bytes), decision);
    }

    /// The same, where a message that arrived is what said so.
    pub(super) fn note_failure_for(&mut self, message: &RawMessage<'_>, reason: FailureReason) {
        let mut decision = Decision::of(failure_code(reason));
        if let Some(status) = message.status() {
            decision = decision.caused_by(WireEvent::response(
                status,
                Direction::Inbound,
                message.as_bytes().len(),
            ));
        }
        self.diag.note(message.call_id().ok(), decision);
    }

    /// The call a transaction belongs to, taken off the request it carries.
    ///
    /// Owned rather than borrowed because every caller of this is about to
    /// take `&mut self` to write the decision down.
    pub(super) fn call_of(&self, id: AnyTransactionId) -> Option<CallId> {
        let store = self.store();
        let message = match id {
            AnyTransactionId::InviteClient(inner) => {
                store.invite_client(inner).map(|e| e.machine.request())
            }
            AnyTransactionId::NonInviteClient(inner) => {
                store.non_invite_client(inner).map(|e| e.machine.request())
            }
            AnyTransactionId::InviteServer(inner) => store.invite_server(inner).map(|e| &e.request),
            AnyTransactionId::NonInviteServer(inner) => {
                store.non_invite_server(inner).map(|e| &e.request)
            }
        }?;
        message.as_raw().call_id().ok().map(CallId::new)
    }

    /// The call a dialog belongs to, while the dialog is still there.
    pub(super) fn call_of_dialog(&self, dialog: DialogId) -> Option<CallId> {
        self.dialogs
            .get(dialog)
            .map(|held| held.key().call_id().clone())
    }
}
