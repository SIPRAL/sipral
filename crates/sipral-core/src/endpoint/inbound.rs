// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What happens to bytes that arrive, and to time that passes.
//!
//! The order of the questions matters, and it is the RFC's order. A response
//! is checked against our own `Via` before anything else looks at it
//! (§18.1.2), then matched to a transaction (§17.1.3), then — only if it is a
//! response to an INVITE — offered to the dialogs that INVITE has produced.
//! A request is matched to a server transaction first (§17.2.3), because a
//! retransmission has to be answered from what was already sent rather than
//! handed up a second time; only a request that matches nothing is new.
//!
//! Two things are done here without asking, because the RFC leaves no choice
//! and there is no policy in either. A CANCEL that matches an INVITE gets its
//! 200 and the INVITE gets its 487 (§9.2, two MUSTs). A request whose `CSeq`
//! runs backwards inside a dialog gets a 500 (§12.2.2, one more). Everything
//! else is reported and left to the layer above.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use super::driver::{Deadline, Endpoint, assemble_response};
use super::error::ReceiveError;
use super::event::{DialogEndReason, Event, FailureReason, TerminationReason};
use super::reliable;
use super::table::Flow;
use super::via;
use crate::diag::{Decision, Direction, Reason, WireEvent};
use crate::dialog::{CallId, Dialog, DialogKey, DialogState, Fork, Incoming};
use crate::msg::{
    Method, OwnedMessage, ParseScratch, RawMessage, ResponseBuilder, StatusCode, parse_with_limits,
};
use crate::transaction::{
    AnyTransactionId, Client, DialogId, Effects, InviteClient, NonInviteClient, NonInviteServer,
    Notify, Raw, Role, Server, ServerKey, TimerName, TransactionId, cancel_for_request,
};

/// A single CRLF, the answer a double-CRLF ping is owed (RFC 5626 §4.4.1).
const PONG: &[u8] = b"\r\n";
/// The ping itself.
const PING: &[u8] = b"\r\n\r\n";
/// §4.4.1: "If a pong is not received within 10 seconds after sending a ping
/// ... then the client MUST treat the flow as failed."
///
/// Not configurable. The interval between pings is a trade-off between battery
/// and availability and the RFC says so; this one is the MUST, and a stack that
/// let it be turned up would be a stack that can be configured out of
/// conformance.
const PONG_DUE: core::time::Duration = core::time::Duration::from_secs(10);

impl Endpoint {
    pub(super) fn on_datagram(
        &mut self,
        transport: super::TransportId,
        remote: SocketAddr,
        local: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Result<(), ReceiveError> {
        let bound = self
            .transports
            .get(transport)
            .ok_or(ReceiveError::UnknownTransport)?;
        if bound.protocol.is_stream() {
            return Err(ReceiveError::WrongKindOfTransport);
        }
        let protocol = bound.protocol;
        let advertised = bound.local;

        // the scratch is taken out so that the parsed view borrows a local
        // rather than a field, which leaves the rest of the endpoint free to
        // be mutated while the message is being read
        let mut scratch = core::mem::replace(&mut self.scratch, ParseScratch::new());
        let mode = self.config.parse_mode;
        let limits = self.config.limits;
        let outcome = match parse_with_limits(data, &mut scratch, mode, limits) {
            Ok(message) => {
                let flow = Self::flow_for(&message, transport, remote, Some(local), protocol);
                self.dispatch(&message, flow, advertised, now);
                Ok(())
            }
            Err(error) => Err(ReceiveError::Malformed(error)),
        };
        self.scratch = scratch;
        outcome
    }

    pub(super) fn on_stream(
        &mut self,
        transport: super::TransportId,
        data: &[u8],
        now: Instant,
    ) -> Result<(), ReceiveError> {
        let bound = self
            .transports
            .get(transport)
            .ok_or(ReceiveError::UnknownTransport)?;
        if !bound.protocol.is_stream() {
            return Err(ReceiveError::WrongKindOfTransport);
        }
        let protocol = bound.protocol;
        let advertised = bound.local;
        // a connected transport has one far end; the destination of anything
        // written to it is ignored by the caller, and carried so a log line
        // says where it went
        let remote = bound.remote.unwrap_or(advertised);
        let Some(mut framer) = self
            .transports
            .get_mut(transport)
            .and_then(|bound| bound.framer.take())
        else {
            return Err(ReceiveError::WrongKindOfTransport);
        };

        let mode = self.config.parse_mode;
        let mut outcome = framer.push(data).map_err(ReceiveError::Malformed);
        while outcome.is_ok() {
            match framer.next_message(mode) {
                Ok(Some(message)) => {
                    let flow = Self::flow_for(&message, transport, remote, None, protocol);
                    self.dispatch(&message, flow, advertised, now);
                }
                Ok(None) => break,
                Err(error) => outcome = Err(ReceiveError::Malformed(error)),
            }
        }
        // RFC 5626 5.4 makes answering a ping a MUST for whoever receives it,
        // and owes one CRLF per double-CRLF. It says nothing about how many
        // writes that is, and a segment holds thousands of pings: one write
        // each would let a peer trade four bytes in for a syscall out
        let mut pings = 0usize;
        while framer.take_ping() {
            pings = pings.saturating_add(1);
        }
        if pings > 0 {
            self.queue(
                Flow {
                    transport,
                    destination: remote,
                    source: None,
                    protocol,
                }
                .transmit(Arc::from(PONG.repeat(pings))),
            );
        }
        // and the answer to ours is the only thing that says the flow is alive
        let mut answered = false;
        while framer.take_pong() {
            answered = true;
        }
        if answered {
            self.pong_arrived(transport);
        }

        match outcome {
            Ok(()) => {
                if let Some(bound) = self.transports.get_mut(transport) {
                    bound.framer = Some(framer);
                }
                Ok(())
            }
            // "a stream whose framing is wrong cannot be resynchronised": the
            // connection is gone, and the framer with it
            Err(error) => {
                self.lose_transport(transport);
                Err(error)
            }
        }
    }

    /// Where a response to this request has to go (§18.2.2, RFC 3581 §4).
    fn flow_for(
        message: &RawMessage<'_>,
        transport: super::TransportId,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        protocol: super::TransportProtocol,
    ) -> Flow {
        let destination = message
            .top_via()
            .ok()
            .and_then(|via| via::response_destination(&via, remote, protocol))
            .unwrap_or(remote);
        Flow {
            transport,
            destination,
            source: local,
            protocol,
        }
    }

    fn dispatch(
        &mut self,
        message: &RawMessage<'_>,
        flow: Flow,
        advertised: SocketAddr,
        now: Instant,
    ) {
        if message.status().is_some() {
            self.on_response(message, flow, advertised, now);
        } else {
            self.on_request(message, flow, now);
        }
    }
}

// -- responses --------------------------------------------------------------

impl Endpoint {
    fn on_response(
        &mut self,
        response: &RawMessage<'_>,
        flow: Flow,
        advertised: SocketAddr,
        now: Instant,
    ) {
        // 18.1.2: "If the value does not match, the response MUST be
        // discarded" — before anything else looks at it
        let Ok(via) = response.top_via() else {
            return;
        };
        if !via::is_ours(&via, advertised, flow.protocol) {
            return;
        }
        match self.transactions.client_for(response) {
            Some(Client::NonInvite(id)) => self.on_non_invite_response(id, response, now),
            Some(Client::Invite(id)) => self.on_invite_response(id, response, now),
            // a response to a transaction that has already terminated, or to
            // one that was never ours. There is nothing to do with it: 17.1.3
            // sends it to the core, and this core has no use for a stray
            None => (),
        }
    }

    fn on_non_invite_response(
        &mut self,
        id: TransactionId<NonInviteClient>,
        response: &RawMessage<'_>,
        now: Instant,
    ) {
        let Some(entry) = self.transactions.non_invite_client_mut(id) else {
            return;
        };
        let flow = entry.flow;
        let sent = entry.machine.request().clone();
        let effects = entry.machine.on_response(response, now);
        let notify = effects.notify;
        let ending =
            self.apply_deferred(effects, flow, AnyTransactionId::NonInviteClient(id), false);

        match notify {
            Some(Notify::Response) => {
                if let Some(status) = response.status() {
                    self.push(Event::Response {
                        transaction: id,
                        status,
                        response: response.to_owned(),
                    });
                }
                self.on_challenge(AnyTransactionId::NonInviteClient(id), response, sent, flow);
            }
            Some(Notify::TimedOut) => {
                self.note_failure_for(response, FailureReason::Timeout);
                self.push(Event::RequestFailed {
                    transaction: id,
                    reason: FailureReason::Timeout,
                });
            }
            Some(Notify::TransportFailed) => {
                self.note_failure_for(response, FailureReason::TransportFailed);
                self.push(Event::RequestFailed {
                    transaction: id,
                    reason: FailureReason::TransportFailed,
                });
            }
            Some(Notify::Ack) | None => (),
        }

        if let Some(reason) = ending {
            self.retire(AnyTransactionId::NonInviteClient(id), reason);
        }
    }

    fn on_invite_response(
        &mut self,
        id: TransactionId<InviteClient>,
        response: &RawMessage<'_>,
        now: Instant,
    ) {
        let Some(entry) = self.transactions.invite_client_mut(id) else {
            return;
        };
        let flow = entry.flow;
        let sent = entry.machine.request().clone();
        let effects = entry.machine.on_response(response, now);
        let notify = effects.notify;
        let cancel_due = entry.machine.take_deferred_cancel();
        let renegotiated = self.reinvites.dialog_of(id);
        // read while the request is still here and only when it is wanted:
        // `sent` is handed to `on_challenge` further down
        let call = (notify == Some(Notify::TimedOut))
            .then(|| sent.as_raw().call_id().ok().map(CallId::new))
            .flatten();
        let ending = self.apply_deferred(effects, flow, AnyTransactionId::InviteClient(id), false);

        if notify == Some(Notify::Response) {
            // §14.1: a re-INVITE never forks, so its answer is not one of
            // several a dialog set has to tell apart — it belongs to the one
            // dialog it was sent in
            if let Some(dialog) = renegotiated {
                self.on_reinvite_response(id, dialog, response, flow);
            } else {
                self.on_fork(id, response, flow);
            }
            self.on_challenge(AnyTransactionId::InviteClient(id), response, sent, flow);
        }
        if notify == Some(Notify::TimedOut) {
            self.invite_gave_up(id, renegotiated, FailureReason::Timeout, call.as_ref());
        }
        // 9.1: the CANCEL was asked for before anything had come back, and
        // the first provisional response is what releases it
        if cancel_due {
            self.send_cancel(id, now).ok();
        }

        if let Some(reason) = ending {
            self.retire(AnyTransactionId::InviteClient(id), reason);
        }
    }

    /// Offer a response to the dialogs the INVITE has produced.
    fn on_fork(&mut self, id: TransactionId<InviteClient>, response: &RawMessage<'_>, flow: Flow) {
        let Some(status) = response.status() else {
            return;
        };
        let Some(set) = self.dialogs.set_for(id) else {
            return;
        };
        let Some(branches) = self.dialogs.set_mut(set) else {
            return;
        };
        let Ok(fork) = branches.on_response(response) else {
            return;
        };

        match fork {
            Fork::Opened(key) | Fork::Advanced(key) => {
                let fresh = self.dialogs.find(&key).is_none();
                let dialog = self.dialogs.name_branch(set, key.clone(), flow);
                if fresh {
                    self.note_wire(response, Reason::DialogCreated, Direction::Inbound, flow);
                    self.ask_to_resolve(dialog);
                }
                if status.is_success() {
                    // 13.2.2.4: "The ACK MUST be passed to the client
                    // transport every time a retransmission of the 2xx final
                    // response that triggered the ACK arrives." The caller
                    // heard about this call once and does not hear again
                    if let Some(ack) = self
                        .dialogs
                        .set(set)
                        .and_then(|branches| branches.ack_for(&key))
                        .cloned()
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
                    if self.was_cancelled(id) {
                        // the CANCEL lost the race: this is a live call, and
                        // hanging it up is the caller's decision
                        self.push(Event::CancelLostRace { invite: id, dialog });
                    }
                    self.push(Event::Established {
                        invite: id,
                        dialog,
                        status,
                        response: response.to_owned(),
                    });
                } else if reliable::is_reliable(response) {
                    self.on_reliable_provisional(id, dialog, response, flow);
                } else {
                    self.push(Event::Provisional {
                        invite: id,
                        dialog: Some(dialog),
                        status,
                        response: response.to_owned(),
                    });
                }
            }
            Fork::Refused => {
                self.end_branches(set, DialogEndReason::Refused);
                self.note_failure_for(response, FailureReason::Refused);
                if status.get() == 487 && self.was_cancelled(id) {
                    self.push(Event::Cancelled { invite: id });
                } else {
                    self.push(Event::Failed {
                        invite: id,
                        status: Some(status),
                        reason: FailureReason::Refused,
                        response: Some(response.to_owned()),
                    });
                }
            }
            // a 100, or a response with no tag to name a dialog by
            Fork::Ignored => {
                if status.is_provisional() {
                    self.push(Event::Provisional {
                        invite: id,
                        dialog: None,
                        status,
                        response: response.to_owned(),
                    });
                }
            }
        }
    }
}

// -- requests ---------------------------------------------------------------

impl Endpoint {
    fn on_request(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        // 17.2.3 first: a retransmission is answered from what was already
        // sent, not handed up again
        if let Some(server) = self.transactions.server_for(request) {
            self.on_known_request(server, request, flow, now);
            return;
        }

        let method = request.method();
        // an ACK creates nothing and is never answered, so there is nothing to
        // refuse and nothing to refuse it with
        if method != Some(Method::Ack) && self.refuse_when_full(request, flow) {
            return;
        }
        match method {
            // "when a UAS core sends a 2xx response to INVITE, the server
            // transaction is destroyed. This means that when the ACK arrives,
            // there will be no matching server transaction"
            Some(Method::Ack) => self.on_ack_for_2xx(request),
            Some(Method::Cancel) => self.on_cancel(request, flow, now),
            Some(Method::Invite) => self.on_invite(request, flow, now),
            Some(_) => self.on_other_request(request, flow, now),
            None => (),
        }
    }

    /// The ceiling on what a stranger may make this endpoint hold.
    ///
    /// A request inside a dialog we already have is never refused, whatever the
    /// count says: it manages state that exists, and a BYE turned away leaves
    /// the call standing for the life of the process. Nor is a CANCEL that
    /// matches an INVITE of ours, for the same reason and because §9.2 makes
    /// answering it a MUST. A stranger's request is the other case, and past
    /// the ceiling it gets §21.5.4's 503 — "temporarily unable to process the
    /// request due to a temporary overloading" — written straight to the flow,
    /// because the point of refusing is not to keep anything. No `Retry-After`
    /// goes with it: §21.5.4 has a client that gets none treat it as a 500 and
    /// try somewhere else, which is what should happen, while one that names a
    /// delay asks a proxy to stop sending here for that long.
    fn refuse_when_full(&mut self, request: &RawMessage<'_>, flow: Flow) -> bool {
        let ours = DialogKey::as_uas(request)
            .ok()
            .is_some_and(|key| self.dialogs.find(&key).is_some());
        if ours {
            return false;
        }
        // and neither is a CANCEL that matches something: §9.2 makes answering
        // one a MUST, and it ends a transaction rather than starting one worth
        // counting. A CANCEL that matches nothing is a stranger like any other
        if request.method() == Some(Method::Cancel)
            && ServerKey::for_cancelled(request)
                .ok()
                .and_then(|key| self.transactions.server_by_key(&key))
                .is_some()
        {
            return false;
        }
        let transactions = self.transactions.servers_len() >= self.config.max_server_transactions;
        // a call is refused before it rings rather than after it is answered:
        // the dialog would be created by our own 2xx, and by then the far end
        // has heard ringback
        let dialogs = request.method() == Some(Method::Invite)
            && self.dialogs.len() >= self.config.max_dialogs;
        if !transactions && !dialogs {
            return false;
        }

        self.refused = self.refused.saturating_add(1);
        let refused = self.refused;
        // on the endpoint's record rather than the call's: a flood arrives
        // with a fresh Call-ID every time, and refusals that made records of
        // their own would evict the calls this endpoint is actually carrying
        let mut decision =
            Decision::of(Reason::RequestRefusedWhenFull).at_address(flow.destination);
        if let Some(method) = request.method() {
            decision = decision.caused_by(WireEvent::request(
                method,
                Direction::Inbound,
                request.as_bytes().len(),
            ));
        }
        self.note(None, decision);
        self.push(Event::Overloaded { refused });
        // §8.2.6.2 wants a tag on every response but a 100. It is minted and
        // forgotten: nothing here holds a transaction to remember it against,
        // so a retransmission of the request earns a second refusal with a
        // second tag, which is what a stateless answer costs
        let tag = self.mint_tag();
        let built = ResponseBuilder::for_request(request, StatusCode::SERVICE_UNAVAILABLE)
            .to_tag(&tag)
            .build();
        if let Ok(message) = built {
            self.queue(flow.transmit(message.bytes()));
        }
        true
    }

    fn on_known_request(
        &mut self,
        server: Server,
        request: &RawMessage<'_>,
        flow: Flow,
        now: Instant,
    ) {
        match server {
            Server::Invite(id) => {
                let Some(entry) = self.transactions.invite_server_mut(id) else {
                    return;
                };
                let effects = if request.method() == Some(Method::Ack) {
                    entry.machine.on_ack(now)
                } else {
                    entry.machine.on_request()
                };
                let notify = effects.notify;
                self.apply(effects, flow, AnyTransactionId::InviteServer(id));
                // RFC 6026 8.1: an ACK arriving in Accepted is the dialog's,
                // and is passed up rather than absorbed
                if notify == Some(Notify::Ack) {
                    self.on_ack_for_2xx(request);
                }
            }
            Server::NonInvite(id) => {
                let Some(entry) = self.transactions.non_invite_server_mut(id) else {
                    return;
                };
                let effects = entry.machine.on_request();
                self.apply(effects, flow, AnyTransactionId::NonInviteServer(id));
            }
        }
    }

    fn on_ack_for_2xx(&mut self, request: &RawMessage<'_>) {
        let Ok(key) = DialogKey::as_uas(request) else {
            return;
        };
        let Some(dialog) = self.dialogs.find(&key) else {
            return;
        };
        if let Some(state) = self.dialogs.get_mut(dialog) {
            state.confirm();
        }
        self.push(Event::IncomingAck {
            dialog,
            request: request.to_owned(),
        });
    }

    fn on_invite(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        let existing = DialogKey::as_uas(request)
            .ok()
            .and_then(|key| self.dialogs.find(&key));

        let timers = self.config.timers;
        let Ok((id, effects)) = self
            .transactions
            .start_invite_server(request, flow, timers, now)
        else {
            return;
        };
        self.apply(effects, flow, AnyTransactionId::InviteServer(id));

        // 14.2: a re-INVITE inside a dialog renegotiates it; the ordering
        // check and the target refresh are the dialog's
        if let Some(dialog) = existing {
            self.remember_tag(AnyTransactionId::InviteServer(id), key_tag(request));
            if self.reject_out_of_order(dialog, request, id.into(), flow, now) {
                return;
            }
            // 14.2 answers a crossing INVITE itself, and both answers are
            // MUSTs; neither reaches the caller
            if self.refuse_crossing_invite(dialog, id, flow, now) {
                return;
            }
            self.reinvites.receive_invite(dialog, id);
            self.push(Event::IncomingReinvite {
                transaction: id,
                dialog,
                request: request.to_owned(),
            });
            return;
        }
        let tag = self.mint_tag();
        self.remember_tag(AnyTransactionId::InviteServer(id), tag);
        self.push(Event::IncomingInvite {
            transaction: id,
            request: request.to_owned(),
        });
    }

    fn on_cancel(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        let timers = self.config.timers;
        let Ok(cancel) = self
            .transactions
            .start_non_invite_server(request, flow, timers)
        else {
            return;
        };

        // 9.2: "the UAS MUST immediately respond to the CANCEL with a 200"
        // whether or not it matched anything
        let owned = request.to_owned();
        self.answer(cancel, &owned, StatusCode::OK, now);

        let Ok(key) = ServerKey::for_cancelled(request) else {
            return;
        };
        let Some(Server::Invite(invite)) = self.transactions.server_by_key(&key) else {
            return;
        };
        // "it MUST respond to the original request with a 487" — a no-op if a
        // final response has already gone, which is exactly what 9.2 wants
        let Some(entry) = self.transactions.invite_server(invite) else {
            return;
        };
        let invite_flow = entry.flow;
        let original = entry.request.clone();
        let tag = self.tag_for(AnyTransactionId::InviteServer(invite));
        if let Ok(message) =
            assemble_response(&original, StatusCode::REQUEST_TERMINATED, tag.as_deref())
            && let Some(entry) = self.transactions.invite_server_mut(invite)
        {
            let effects = entry.machine.respond(message, now);
            self.apply(effects, invite_flow, AnyTransactionId::InviteServer(invite));
        }
        self.push(Event::IncomingCancel { invite });
    }

    fn on_other_request(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        let dialog = DialogKey::as_uas(request)
            .ok()
            .and_then(|key| self.dialogs.find(&key));

        let timers = self.config.timers;
        let Ok(id) = self
            .transactions
            .start_non_invite_server(request, flow, timers)
        else {
            return;
        };

        let Some(dialog) = dialog else {
            let tag = self.mint_tag();
            self.remember_tag(AnyTransactionId::NonInviteServer(id), tag);
            // a PRACK naming no dialog at all matches no outstanding response
            // either, and §3 answers that 481 rather than handing it up
            if request.method() == Some(Method::Prack) {
                self.on_prack(id, None, request, now);
                return;
            }
            self.push(Event::IncomingOutOfDialog {
                transaction: id,
                request: request.to_owned(),
            });
            return;
        };

        self.remember_tag(AnyTransactionId::NonInviteServer(id), key_tag(request));
        if self.reject_out_of_order(dialog, request, id.into(), flow, now) {
            return;
        }

        // RFC 3262 §3: a PRACK is answered here whether or not it matches
        // something, and the matching is on three numbers rather than on the
        // dialog alone
        if request.method() == Some(Method::Prack) {
            self.on_prack(id, Some(dialog), request, now);
            return;
        }

        // RFC 3311 §5.2: a second UPDATE arriving before the first is answered
        // is refused here, because that rule turns on transaction state. Its
        // siblings turn on whether an offer is outstanding, which is not
        // something this crate has an opinion about
        if request.method() == Some(Method::Update) {
            if self.refuse_crossing_update(dialog, id, flow, now) {
                return;
            }
            self.reinvites.receive_update(dialog, id);
        }

        if request.method() == Some(Method::Bye) {
            // 15.1.2: the dialog is over the moment the BYE is accepted, and
            // whether to answer it 200 is still the caller's
            if let Some(state) = self.dialogs.get_mut(dialog) {
                state.terminate();
            }
            self.push(Event::IncomingBye {
                transaction: id,
                dialog,
            });
            self.forget_dialog(dialog, DialogEndReason::RemoteBye);
            return;
        }
        self.push(Event::IncomingInDialog {
            transaction: id,
            dialog,
            request: request.to_owned(),
        });
    }

    /// §12.2.2: a request whose `CSeq` runs backwards "is out of order and
    /// MUST be rejected with a 500". Nothing in the dialog changes.
    fn reject_out_of_order(
        &mut self,
        dialog: DialogId,
        request: &RawMessage<'_>,
        transaction: AnyTransactionId,
        flow: Flow,
        now: Instant,
    ) -> bool {
        let out_of_order = self
            .dialogs
            .get_mut(dialog)
            .is_some_and(|state| state.on_request(request) == Ok(Incoming::OutOfOrder));
        if !out_of_order {
            return false;
        }
        let owned = request.to_owned();
        let status = StatusCode::SERVER_ERROR;
        let tag = self.tag_for(transaction);
        if let Ok(message) = assemble_response(&owned, status, tag.as_deref()) {
            self.respond_raw(transaction, message, flow, now);
        }
        true
    }
}

// -- time -------------------------------------------------------------------

impl Endpoint {
    pub(super) fn fire_transaction(&mut self, id: AnyTransactionId, now: Instant) {
        match id {
            AnyTransactionId::InviteClient(inner) => {
                while let Some((name, effects)) = self
                    .transactions
                    .invite_client_mut(inner)
                    .and_then(|entry| entry.machine.handle_timeout(now))
                {
                    let flow = self.flow_of(id);
                    let notify = effects.notify;
                    // read before applying: timer B terminates the
                    // transaction, and retiring it forgets what it was
                    let renegotiated = self.reinvites.dialog_of(inner);
                    let over = name == TimerName::B && notify == Some(Notify::TimedOut);
                    // and the same for the name the record is kept under, which
                    // is why it is read here and not where it is used
                    let call = over.then(|| self.call_of(id)).flatten();
                    self.apply_again(effects, flow, id);
                    if over {
                        self.invite_gave_up(
                            inner,
                            renegotiated,
                            FailureReason::Timeout,
                            call.as_ref(),
                        );
                    }
                }
            }
            AnyTransactionId::NonInviteClient(inner) => {
                while let Some((_, effects)) = self
                    .transactions
                    .non_invite_client_mut(inner)
                    .and_then(|entry| entry.machine.handle_timeout(now))
                {
                    let flow = self.flow_of(id);
                    let notify = effects.notify;
                    let over = notify == Some(Notify::TimedOut);
                    let call = over.then(|| self.call_of(id)).flatten();
                    self.apply_again(effects, flow, id);
                    if over {
                        self.note_failure(call.as_ref(), FailureReason::Timeout);
                        self.push(Event::RequestFailed {
                            transaction: inner,
                            reason: FailureReason::Timeout,
                        });
                    }
                }
            }
            AnyTransactionId::InviteServer(inner) => {
                while let Some((_, effects)) = self
                    .transactions
                    .invite_server_mut(inner)
                    .and_then(|entry| entry.machine.handle_timeout(now))
                {
                    let flow = self.flow_of(id);
                    // timer H: the final response was repeated for 64*T1 and
                    // the far end never acknowledged it. Nothing above hears
                    // about this, so the record is the only place it exists
                    let unacknowledged = effects.notify == Some(Notify::TimedOut);
                    let call = unacknowledged.then(|| self.call_of(id)).flatten();
                    self.apply_again(effects, flow, id);
                    if unacknowledged {
                        self.note(
                            call.as_ref().map(CallId::as_bytes),
                            Decision::of(Reason::TransactionUnacknowledged)
                                .at_address(flow.destination)
                                .over(flow.protocol),
                        );
                    }
                }
                let _ = inner;
            }
            AnyTransactionId::NonInviteServer(inner) => {
                while let Some((_, effects)) = self
                    .transactions
                    .non_invite_server_mut(inner)
                    .and_then(|entry| entry.machine.handle_timeout(now))
                {
                    let flow = self.flow_of(id);
                    self.apply_again(effects, flow, id);
                }
                let _ = inner;
            }
        }
    }

    pub(super) fn arm_keepalives(&mut self, now: Instant) {
        let Some(interval) = self.config.keepalive_interval else {
            return;
        };
        for transport in self.transports.streams_without_keepalive() {
            let at = now + self.tokens.jitter(interval);
            let handle = self.schedule(at, Deadline::Keepalive(transport));
            if let Some(bound) = self.transports.get_mut(transport) {
                bound.keepalive = Some(handle);
            }
        }
    }

    pub(super) fn send_keepalive(&mut self, transport: super::TransportId, now: Instant) {
        let Some(bound) = self.transports.get(transport) else {
            return;
        };
        let flow = Flow {
            transport,
            destination: bound.remote.unwrap_or(bound.local),
            source: None,
            protocol: bound.protocol,
        };
        self.queue(flow.transmit(Arc::from(PING)));
        let next = self
            .config
            .keepalive_interval
            .map(|interval| now + self.tokens.jitter(interval))
            .map(|at| self.schedule(at, Deadline::Keepalive(transport)));
        // one deadline for the flow rather than one per ping: a pong is not
        // matched to the ping it answers, so the ten seconds run from the
        // earliest ping still unanswered
        let armed = self.transports.get(transport).and_then(|bound| bound.pong);
        let overdue = armed
            .unwrap_or_else(|| self.schedule(now + PONG_DUE, Deadline::PongOverdue(transport)));
        if let Some(bound) = self.transports.get_mut(transport) {
            bound.keepalive = next;
            bound.pong = Some(overdue);
        }
    }

    /// The far end answered, so the flow is alive and the clock stops.
    fn pong_arrived(&mut self, transport: super::TransportId) {
        let Some(handle) = self
            .transports
            .get_mut(transport)
            .and_then(|bound| bound.pong.take())
        else {
            return;
        };
        self.deadlines.cancel(handle);
    }

    /// Ten seconds without a pong: §4.4.1 makes this a dead flow, and a dead
    /// flow is taken down rather than kept and hoped for.
    pub(super) fn flow_failed(&mut self, transport: super::TransportId) {
        let Some(bound) = self.transports.get(transport) else {
            return;
        };
        let decision = Decision::of(Reason::FlowDead)
            .at_address(bound.remote.unwrap_or(bound.local))
            .over(bound.protocol);
        self.note(None, decision);
        self.push(Event::FlowFailed { transport });
        self.lose_transport(transport);
    }

    pub(super) fn lose_transport(&mut self, transport: super::TransportId) {
        if let Some(bound) = self.transports.unbind(transport) {
            let decision = Decision::of(Reason::TransportLost)
                .at_address(bound.remote.unwrap_or(bound.local))
                .over(bound.protocol);
            self.note(None, decision);
            for handle in [bound.keepalive, bound.pong].into_iter().flatten() {
                self.deadlines.cancel(handle);
            }
        }
        let mut hit = core::mem::take(&mut self.hit);
        self.transactions.on_transport(transport, &mut hit);
        for id in &hit {
            self.fail_transaction(*id);
        }
        self.hit = hit;
    }

    fn fail_transaction(&mut self, id: AnyTransactionId) {
        let flow = self.flow_of(id);
        let effects = match id {
            AnyTransactionId::InviteClient(inner) => self
                .transactions
                .invite_client_mut(inner)
                .map(|entry| entry.machine.on_transport_error()),
            AnyTransactionId::NonInviteClient(inner) => self
                .transactions
                .non_invite_client_mut(inner)
                .map(|entry| entry.machine.on_transport_error()),
            AnyTransactionId::InviteServer(inner) => self
                .transactions
                .invite_server(inner)
                .map(|entry| entry.machine.on_transport_error()),
            AnyTransactionId::NonInviteServer(_) => None,
        };
        let Some(effects) = effects else {
            return;
        };
        let notify = effects.notify;
        let call = self.call_of(id);
        let renegotiated = match id {
            AnyTransactionId::InviteClient(inner) => self.reinvites.dialog_of(inner),
            AnyTransactionId::NonInviteClient(_)
            | AnyTransactionId::InviteServer(_)
            | AnyTransactionId::NonInviteServer(_) => None,
        };
        self.apply(effects, flow, id);
        if notify == Some(Notify::TransportFailed) {
            match id {
                AnyTransactionId::InviteClient(inner) => {
                    self.invite_gave_up(
                        inner,
                        renegotiated,
                        FailureReason::TransportFailed,
                        call.as_ref(),
                    );
                }
                AnyTransactionId::NonInviteClient(inner) => {
                    self.note_failure(call.as_ref(), FailureReason::TransportFailed);
                    self.push(Event::RequestFailed {
                        transaction: inner,
                        reason: FailureReason::TransportFailed,
                    });
                }
                AnyTransactionId::InviteServer(_) | AnyTransactionId::NonInviteServer(_) => (),
            }
        }
    }
}

// -- shared plumbing --------------------------------------------------------

impl Endpoint {
    /// Send what a machine asked to send, and retire it if it is done.
    pub(super) fn apply(&mut self, effects: Effects, flow: Flow, id: AnyTransactionId) {
        if let Some(reason) = self.apply_deferred(effects, flow, id, false) {
            self.retire(id, reason);
        }
    }

    /// The same, for a send a retransmission timer asked for.
    ///
    /// Split from [`Endpoint::apply`] rather than given a flag by every caller
    /// because `fire_transaction` is the only place a timer drives one, and a
    /// retransmission is the entry in the record that says a datagram is not
    /// arriving.
    pub(super) fn apply_again(&mut self, effects: Effects, flow: Flow, id: AnyTransactionId) {
        if let Some(reason) = self.apply_deferred(effects, flow, id, true) {
            self.retire(id, reason);
        }
    }

    /// Send what a machine asked to send, and hand back why it should be
    /// retired rather than retiring it.
    ///
    /// Timer D is zero on a reliable transport (§17.1.1.2) and so is timer K
    /// (§17.1.2.2), so a final response that arrives over TCP or TLS ends the
    /// client transaction in the very call that delivered it. Both sections
    /// still make passing that response to the TU a MUST, and everything that
    /// reads it lives in state [`Endpoint::retire`] takes away: the dialogs
    /// the INVITE forked into, the CANCEL that was racing it, the nonce a
    /// challenge answered, the dialog an in-dialog request belongs to. A
    /// caller that reports first and retires afterwards sees the same events
    /// in the same order whatever the transport was; over UDP the transaction
    /// stands for another 32 seconds and none of this shows.
    fn apply_deferred(
        &mut self,
        effects: Effects,
        flow: Flow,
        id: AnyTransactionId,
        repeat: bool,
    ) -> Option<TerminationReason> {
        let ending = effects.terminated.then_some(match effects.notify {
            Some(Notify::TimedOut) => TerminationReason::TimedOut,
            Some(Notify::TransportFailed) => TerminationReason::TransportFailed,
            _ => TerminationReason::Completed,
        });
        self.send_from(effects.send, flow, id, repeat);
        ending
    }

    /// Queue what a machine handed over, and write down that it went.
    ///
    /// A client transaction's first send goes through
    /// [`Endpoint::apply_client`], so anything a client sends from here is
    /// either a retransmission or the ACK for a refusal.
    fn send_from(
        &mut self,
        message: Option<OwnedMessage>,
        flow: Flow,
        id: AnyTransactionId,
        repeat: bool,
    ) {
        let Some(message) = message else {
            return;
        };
        let reason = match (id.role() == Role::Client, repeat) {
            (true, false) => Reason::RequestSent,
            (true, true) => Reason::RequestRetransmitted,
            (false, false) => Reason::ResponseSent,
            (false, true) => Reason::ResponseRetransmitted,
        };
        self.note_wire(&message.as_raw(), reason, Direction::Outbound, flow);
        self.queue(flow.transmit(message.bytes()));
    }

    /// Send what a client machine asked to send at the moment it started.
    pub(super) fn apply_client(&mut self, effects: Effects, flow: Flow) {
        if let Some(message) = effects.send {
            self.note_wire(
                &message.as_raw(),
                Reason::RequestSent,
                Direction::Outbound,
                flow,
            );
            self.queue(flow.transmit(message.bytes()));
        }
    }

    fn retire(&mut self, id: AnyTransactionId, reason: TerminationReason) {
        match id {
            AnyTransactionId::InviteClient(inner) => {
                if let Some(set) = self.dialogs.set_for(inner) {
                    // 13.2.2.4: 64*T1 after the first 2xx "no more new 2xx
                    // responses are expected to arrive", and every branch
                    // still early is over
                    if let Some(branches) = self.dialogs.set_mut(set) {
                        branches.no_more_answers();
                    }
                    self.end_branches(set, DialogEndReason::Abandoned);
                    self.dialogs.invite_done(set);
                }
                self.forget_cancelled(inner);
                // §14: the ACK for a re-INVITE is kept for as long as a 2xx
                // can still arrive again, which is exactly timer M
                self.reinvites.finish(inner);
                self.transactions.drop_invite_client(inner);
            }
            AnyTransactionId::NonInviteClient(inner) => {
                self.transactions.drop_non_invite_client(inner);
            }
            AnyTransactionId::InviteServer(inner) => {
                self.forget_reliable_on(inner);
                self.reinvites.answered_theirs(id);
                self.transactions.drop_invite_server(inner);
            }
            AnyTransactionId::NonInviteServer(inner) => {
                self.reinvites.answered_theirs(id);
                self.transactions.drop_non_invite_server(inner);
            }
        }
        self.forget_tag(id);
        // the allowance a challenged request was carrying, when this
        // transaction ended any way other than by being challenged again
        self.challenges.forget(id);
        self.dialogs_of.remove(&id);
        self.push(Event::TransactionTerminated {
            transaction: id,
            reason,
        });
    }

    /// Report and forget every dialog of a set that has just ended.
    pub(super) fn end_branches(&mut self, set: Raw, reason: DialogEndReason) {
        for id in self.dialogs.ids() {
            if self.dialogs.branch_set(id) != Some(set) {
                continue;
            }
            if self.dialogs.get(id).map(Dialog::state) == Some(DialogState::Terminated) {
                self.forget_dialog(id, reason);
            }
        }
    }

    pub(super) fn forget_dialog(&mut self, dialog: DialogId, reason: DialogEndReason) {
        // read before the forget, which is what takes the name away
        let call = self.call_of_dialog(dialog);
        if self.dialogs.forget(dialog).is_some() {
            self.note(
                call.as_ref().map(CallId::as_bytes),
                Decision::of(Reason::DialogDestroyed),
            );
            self.forget_reliable_in(dialog);
            self.reinvites.forget_dialog(dialog);
            self.push(Event::DialogTerminated { dialog, reason });
        }
    }

    /// An INVITE this end sent will not be answered.
    ///
    /// `renegotiated` is the dialog it was sent inside, when it was a
    /// re-INVITE, and has to be read before the transaction is retired —
    /// retiring it is what forgets that.
    fn invite_gave_up(
        &mut self,
        id: TransactionId<InviteClient>,
        renegotiated: Option<DialogId>,
        reason: FailureReason,
        call: Option<&CallId>,
    ) {
        self.note_failure(call, reason);
        match renegotiated {
            Some(dialog) => self.reinvite_gave_up(id, dialog, reason),
            None => self.push(Event::Failed {
                invite: id,
                status: None,
                reason,
                response: None,
            }),
        }
    }

    /// Build and send the CANCEL for an INVITE that has had a provisional.
    pub(super) fn send_cancel(
        &mut self,
        invite: TransactionId<InviteClient>,
        now: Instant,
    ) -> Result<(), super::error::CancelError> {
        let Some(entry) = self.transactions.invite_client(invite) else {
            return Err(super::error::CancelError::NoSuchTransaction);
        };
        let flow = entry.flow;
        let request = entry.machine.request().clone();
        let message = cancel_for_request(&request.as_raw())?;
        let timers = self.config.timers;
        let (cancel, effects) = self
            .transactions
            .start_non_invite_client(message, flow, timers, now)
            .map_err(|_| super::error::CancelError::NoSuchTransaction)?;
        self.apply_client(effects, flow);
        self.remember_cancelled(invite);
        self.push(Event::CancelSent { invite, cancel });
        Ok(())
    }

    /// A dialog we open by answering a request (§12.1.1).
    ///
    /// Two callers, and the second is the reason this says "request" rather
    /// than "INVITE": answering a NOTIFY is what opens a subscriber's dialog
    /// (RFC 6665 §4.4.1), and everything §12.1.1 asks for — the route set in
    /// the order it arrived, the remote target from the `Contact`, the two
    /// URIs, the remote sequence number — is read off the request the same
    /// way whichever method it was.
    pub(super) fn open_uas_dialog(
        &mut self,
        request: &OwnedMessage,
        tag: &[u8],
        status: StatusCode,
        flow: Flow,
    ) -> Option<DialogId> {
        let raw = request.as_raw();
        let key = DialogKey::new(
            crate::dialog::CallId::new(raw.call_id().ok()?),
            crate::dialog::Tag::new(tag),
            raw.from().ok()?.tag().map(|t| crate::dialog::Tag::new(&t)),
        );
        if let Some(known) = self.dialogs.find(&key) {
            if status.is_success()
                && let Some(dialog) = self.dialogs.get_mut(known)
            {
                dialog.confirm();
            }
            return Some(known);
        }
        let secure = flow.protocol.is_secure();
        let dialog = Dialog::from_request(&raw, tag, status, secure).ok()?;
        let named = self.dialogs.answer(dialog, flow);
        self.note_wire(&raw, Reason::DialogCreated, Direction::Inbound, flow);
        self.ask_to_resolve(named);
        Some(named)
    }

    /// Answer a request on a server transaction with nothing but a status.
    fn answer(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        request: &OwnedMessage,
        status: StatusCode,
        now: Instant,
    ) {
        let Some(entry) = self.transactions.non_invite_server(transaction) else {
            return;
        };
        let flow = entry.flow;
        let tag = self.tag_or_mint(AnyTransactionId::NonInviteServer(transaction));
        if let Ok(message) = assemble_response(request, status, Some(&tag)) {
            self.respond_raw(
                AnyTransactionId::NonInviteServer(transaction),
                message,
                flow,
                now,
            );
        }
    }

    /// The tag this end already used on a server transaction, or a fresh one.
    ///
    /// §8.2.6.2 makes a tag mandatory on every response but a 100, and every
    /// response of one transaction has to carry the same one.
    pub(super) fn tag_or_mint(&mut self, id: AnyTransactionId) -> Box<[u8]> {
        if let Some(known) = self.tag_for(id) {
            return known;
        }
        let fresh = self.mint_tag();
        self.remember_tag(id, fresh.clone());
        fresh
    }

    pub(super) fn respond_raw(
        &mut self,
        transaction: AnyTransactionId,
        message: OwnedMessage,
        flow: Flow,
        now: Instant,
    ) {
        let effects = match transaction {
            AnyTransactionId::NonInviteServer(id) => self
                .transactions
                .non_invite_server_mut(id)
                .map(|entry| entry.machine.respond(message, now)),
            AnyTransactionId::InviteServer(id) => self
                .transactions
                .invite_server_mut(id)
                .map(|entry| entry.machine.respond(message, now)),
            AnyTransactionId::InviteClient(_) | AnyTransactionId::NonInviteClient(_) => None,
        };
        if let Some(effects) = effects {
            self.apply(effects, flow, transaction);
        }
    }
}

/// The tag we already put in `To`, read back off a request that carries it.
fn key_tag(request: &RawMessage<'_>) -> Box<[u8]> {
    request
        .to()
        .ok()
        .and_then(|to| to.tag())
        .map(|tag| Box::from(tag.as_ref()))
        .unwrap_or_default()
}
