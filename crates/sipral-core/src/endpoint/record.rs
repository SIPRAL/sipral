// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Where the endpoint writes its decisions down.
//!
//! Records are keyed by `Call-ID`, the one name every party and capture
//! agrees on. Decisions outside any call go to the endpoint's own record,
//! which is never evicted.

use std::time::Instant;

use super::driver::Endpoint;
use super::event::FailureReason;
use super::table::Flow;
use crate::diag::{Decision, Direction, Reason, Record, WireEvent};
use crate::dialog::CallId;
use crate::msg::RawMessage;
use crate::transaction::{AnyTransactionId, DialogId};

/// The code for a failure reported to the layer above, shared by INVITEs
/// and plain requests.
const fn failure_code(reason: FailureReason) -> Reason {
    match reason {
        FailureReason::Timeout => Reason::FailedTimeout,
        FailureReason::TransportFailed => Reason::FailedTransport,
        FailureReason::Refused => Reason::FailedRefused,
    }
}

impl Endpoint {
    /// What this endpoint decided about one call, until the record is evicted
    /// ([`EndpointConfig::diagnostics`](super::EndpointConfig::diagnostics)).
    #[must_use]
    pub fn call_record(&self, call: &CallId) -> Option<&Record> {
        self.diag.record(call)
    }

    /// What this endpoint decided outside any call (transports, floods).
    #[must_use]
    pub const fn endpoint_record(&self) -> &Record {
        self.diag.endpoint()
    }

    /// Every call with a record, least recently written (next to evict) first.
    pub fn recorded_calls(&self) -> impl Iterator<Item = &CallId> {
        self.diag.calls()
    }

    /// How many records were evicted. Unlike [`Record::dropped`], which counts
    /// inside one record; a rising value means too many concurrent calls.
    #[must_use]
    pub const fn records_dropped(&self) -> u64 {
        self.diag.dropped()
    }

    /// Every record as one JSON document: what a bug report carries.
    #[must_use]
    pub fn diagnostics_json(&self) -> String {
        self.diag.to_json()
    }

    /// The caller's time for this entry point. Nothing reads a clock, so every
    /// decision in the call is stamped with it.
    pub(super) const fn mark(&mut self, now: Instant) {
        self.diag.mark(now);
    }

    pub(super) fn note(&mut self, call: Option<&[u8]>, decision: Decision) {
        self.diag.note(call, decision);
    }

    /// A decision the layer above made about a message this endpoint handed
    /// it, written into that call's record. Like every entry it carries the
    /// method or status and size, never a header value, so a record is safe
    /// to send unread.
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

    pub(super) fn note_wire(
        &mut self,
        message: &RawMessage<'_>,
        reason: Reason,
        direction: Direction,
        flow: Flow,
    ) {
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

    /// The call a transaction belongs to. Owned, since callers then take
    /// `&mut self`.
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

    pub(super) fn call_of_dialog(&self, dialog: DialogId) -> Option<CallId> {
        self.dialogs
            .get(dialog)
            .map(|held| held.key().call_id().clone())
    }
}
