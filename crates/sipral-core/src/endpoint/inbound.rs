// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What happens to bytes that arrive, and to time that passes.
//!
//! The order is the RFC's. A response is checked against our own `Via` (§18.1.2), matched to a
//! transaction (§17.1.3), and, for an INVITE, offered to its dialogs. A request is matched to a
//! server transaction first (§17.2.3), so a retransmission is answered from what was sent; only an
//! unmatched request is new.
//!
//! Two things are done without asking, because the RFC leaves no choice: a matching CANCEL gets its
//! 200 and the INVITE its 487 (§9.2), and a request whose `CSeq` runs backwards in a dialog gets a
//! 500 (§12.2.2).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::driver::{Deadline, Endpoint, assemble_response};
use super::error::ReceiveError;
use super::event::{DialogEndReason, Event, FailureReason, TerminationReason};
use super::reliable;
use super::table::Flow;
use super::via;
use crate::diag::{Decision, Direction, Reason, WireEvent};
use crate::dialog::{CallId, Dialog, DialogKey, DialogState, Fork, Incoming};
use crate::msg::{
    Contacts, Framed, HeaderName, Invalid, Method, OwnedMessage, ParseError, ParseScratch,
    RawMessage, ResponseBuilder, StatusCode, field_value_len, parse_with_limits, salvage_request,
};
use crate::transaction::{
    AnyTransactionId, Client, DialogId, Effects, InviteClient, NonInviteClient, NonInviteServer,
    NonInviteServerState, Notify, Raw, Role, Server, TimerName, TransactionId, cancel_for_request,
};

/// A single CRLF, the answer a double-CRLF ping is owed (RFC 5626 §4.4.1).
const PONG: &[u8] = b"\r\n";
/// The ping itself.
const PING: &[u8] = b"\r\n\r\n";
/// §4.4.1: no pong within 10 seconds of a ping means the flow failed.
///
/// Not configurable: this one is a MUST, unlike the ping interval.
const PONG_DUE: core::time::Duration = core::time::Duration::from_secs(10);

/// The most non-INVITE server transactions one dialog may have open at once.
///
/// In-dialog requests are exempt from [`super::EndpointConfig::max_server_transactions`] (docs/03),
/// so a peer inside the dialog needs a ceiling of its own. Sixteen is well past what one call needs
/// live (DTMF, a PRACK, an UPDATE).
///
/// A BYE in order never draws from it: §15.1.1 has its sender consider the session over anyway, so
/// a 503 only leaves a dead dialog behind. A BYE whose `CSeq` runs backwards ends nothing (§12.2.2)
/// and is counted, or low-numbered BYEs would bypass the limit.
const MAX_DIALOG_NON_INVITE_TRANSACTIONS: usize = 16;
/// `Retry-After` on the 503 of [`Endpoint::refuse_when_dialog_full`]. RFC 5057 names no value; one
/// second suits a burst inside a healthy call.
const DIALOG_BUSY_RETRY_AFTER_SECONDS: u32 = 1;
/// `Retry-After` on the 503 an INVITE gets at [`super::EndpointConfig::max_dialogs`] (RFC 3261
/// §21.5.4, §20.33).
///
/// At the default ceiling (128 calls of three minutes) room frees every 1.4 seconds, rounded up to
/// two. Longer would send callers elsewhere while room exists; none at all reads as a 500
/// (§21.5.4), broken rather than full.
const DIALOG_CEILING_RETRY_AFTER_SECONDS: u32 = 2;

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

        // taken out so the parsed view borrows a local, leaving `self` free to mutate
        let mut scratch = core::mem::replace(&mut self.scratch, ParseScratch::new());
        let mode = self.config.parse_mode;
        let limits = self.config.limits;
        let outcome = match parse_with_limits(data, &mut scratch, mode, limits) {
            Ok(message) => {
                let flow = Self::flow_for(&message, transport, remote, Some(local), protocol);
                self.dispatch(&message, flow, advertised, now);
                Ok(())
            }
            Err(error) => Err(error),
        };
        self.scratch = scratch;
        outcome.map_err(|error| {
            let arrival = Arrival {
                transport,
                remote,
                local: Some(local),
                protocol,
            };
            self.answer_unreadable(data, data.len(), error, arrival);
            ReceiveError::Malformed(error)
        })
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
        // a connected transport has one far end; the destination is only for logs
        let named_far_end = bound.remote;
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
                Ok(Some(Framed::Message(message))) => {
                    if let Some(tap) = self.stream_tap.as_mut() {
                        tap.push(super::StreamMessage {
                            transport,
                            remote: named_far_end,
                            // the framer's buffer runs on past the message
                            bytes: message
                                .as_bytes()
                                .get(..message.len())
                                .unwrap_or_default()
                                .into(),
                        });
                    }
                    let flow = Self::flow_for(&message, transport, remote, None, protocol);
                    self.dispatch(&message, flow, advertised, now);
                }
                // refused, and already passed over: the connection reads on
                Ok(Some(Framed::Refused {
                    head,
                    length,
                    error,
                })) => {
                    let arrival = Arrival {
                        transport,
                        remote,
                        local: None,
                        protocol,
                    };
                    self.answer_unreadable(head, length, error, arrival);
                }
                Ok(None) => break,
                Err(error) => outcome = Err(ReceiveError::Malformed(error)),
            }
        }
        // framing lost: nothing can be answered and the connection goes below. Still counted
        if let Err(ReceiveError::Malformed(error)) = outcome {
            self.unreadable = self.unreadable.saturating_add(1);
            let mut decision = Decision::of(Reason::MessageDroppedUnreadable)
                .at_address(remote)
                .over(protocol);
            if let ParseError::MessageTooLarge { limit } = error {
                decision = decision.measured(framer.pending(), limit);
            }
            self.note(None, decision);
        }
        // RFC 5626 5.4: one CRLF per double-CRLF, but in one write, or a peer trades four bytes for
        // a syscall
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
        // a pong is the only proof the flow is alive
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
            // a stream with broken framing cannot be resynchronised
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

    /// Answer what the parser refused when an answer can be addressed, and record it either way.
    ///
    /// §8.2 has a UAS answer what it cannot process rather than leave the client retransmitting:
    /// 513 past [`crate::msg::Limits::max_message_bytes`] (§21.5.14), 400 otherwise (§21.4.1), with
    /// a phrase naming the bound or fault. Built statelessly from what [`salvage_request`]
    /// recovers.
    ///
    /// Nothing is answered for a response, an ACK (§17.1.1.3), or a request whose top `Via` cannot
    /// be read (§18.2.2, §17.1.3). Missing `From`, `To`, `Call-ID` or `CSeq` do not stop it
    /// ([`ResponseBuilder::build_refusal`]). Recorded on the endpoint's record, not a call's, so a
    /// stranger's garbage cannot evict real calls.
    ///
    /// `bytes` is what was refused (a datagram, or a stream message's head); `length` is the whole
    /// message.
    fn answer_unreadable(
        &mut self,
        bytes: &[u8],
        length: usize,
        error: ParseError,
        arrival: Arrival,
    ) {
        self.unreadable = self.unreadable.saturating_add(1);
        let measure = match error {
            ParseError::MessageTooLarge { limit } => Some((length, limit)),
            ParseError::HeaderValueTooLong { name_at, limit } => {
                field_value_len(bytes, name_at).map(|size| (size, limit))
            }
            _ => None,
        };
        let measured = |decision: Decision| match measure {
            Some((size, limit)) => decision.measured(size, limit),
            None => decision,
        };

        let dropped = Decision::of(Reason::MessageDroppedUnreadable)
            .at_address(arrival.remote)
            .over(arrival.protocol);
        let mut scratch = ParseScratch::new();
        let value_bound = self.config.limits.max_header_value_bytes as usize;
        let request = salvage_request(bytes, &mut scratch, self.config.limits.max_headers)
            .filter(|request| can_be_answered(request, value_bound));
        let Some(request) = request else {
            self.note(None, measured(dropped));
            return;
        };

        let (status, phrase) = refusal(error, bytes);
        let tag = self.mint_tag();
        let built = ResponseBuilder::for_request(&request, status)
            .to_tag(&tag)
            .reason(phrase.as_bytes())
            .build_refusal();
        // copied fields, the phrase and a tag can push past the size bound
        let Ok(message) = built else {
            self.note(None, measured(dropped));
            return;
        };

        let flow = Self::flow_for(
            &request,
            arrival.transport,
            arrival.remote,
            arrival.local,
            arrival.protocol,
        );
        let mut decision = Decision::of(Reason::RequestRefusedUnreadable)
            .at_address(flow.destination)
            .over(arrival.protocol);
        if let Some(method) = request.method() {
            decision = decision.caused_by(WireEvent::request(method, Direction::Inbound, length));
        }
        self.note(None, measured(decision));
        self.queue(flow.transmit(message.bytes()));
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

impl Endpoint {
    fn on_response(
        &mut self,
        response: &RawMessage<'_>,
        flow: Flow,
        advertised: SocketAddr,
        now: Instant,
    ) {
        // §18.1.2: a response whose Via does not match MUST be discarded
        let Ok(via) = response.top_via() else {
            return;
        };
        let named = self
            .transports
            .get(flow.transport)
            .and_then(|bound| bound.sent_by.as_deref());
        let ours = match named {
            Some(name) => via::is_ours_named(&via, name, flow.protocol),
            None => via::is_ours(&via, advertised, flow.protocol),
        };
        if !ours {
            return;
        }
        match self.transactions.client_for(response) {
            Some(Client::NonInvite(id)) => self.on_non_invite_response(id, response, now),
            Some(Client::Invite(id)) => self.on_invite_response(id, response, now),
            // a stray or late response: §17.1.3 hands it to the core, which has no use for it
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
        // RFC 3263 §4.3: a 503, a timeout or a transport failure may go to the next server
        let unreached = match notify {
            Some(Notify::Response) => response.status() == Some(StatusCode::SERVICE_UNAVAILABLE),
            Some(Notify::TimedOut | Notify::TransportFailed) => true,
            Some(Notify::Ack) | None => false,
        };
        if unreached {
            self.keep_unreached(AnyTransactionId::NonInviteClient(id), &sent, flow);
        }

        match notify {
            Some(Notify::Response) => {
                if let Some(status) = response.status() {
                    self.push(Event::Response {
                        transaction: id,
                        status,
                        response: response.to_owned(),
                    });
                    // a challenge is not a refusal; `on_challenge` records its own entries
                    if status.is_final()
                        && !status.is_success()
                        && status != StatusCode::UNAUTHORIZED
                        && status != StatusCode::PROXY_AUTH_REQUIRED
                    {
                        self.note_failure_for(response, FailureReason::Refused);
                    }
                }
                self.on_challenge(AnyTransactionId::NonInviteClient(id), response, sent, flow);
            }
            Some(Notify::TimedOut) => {
                self.note_failure_for(response, FailureReason::Timeout);
                self.push(Event::RequestFailed {
                    transaction: id,
                    reason: FailureReason::Timeout,
                });
                self.failover_in_dialog(id, flow);
            }
            Some(Notify::TransportFailed) => {
                self.note_failure_for(response, FailureReason::TransportFailed);
                self.push(Event::RequestFailed {
                    transaction: id,
                    reason: FailureReason::TransportFailed,
                });
                self.failover_in_dialog(id, flow);
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
        // read only when wanted, before `sent` moves into `on_challenge`
        let call = (notify == Some(Notify::TimedOut))
            .then(|| sent.as_raw().call_id().ok().map(CallId::new))
            .flatten();
        let ending = self.apply_deferred(effects, flow, AnyTransactionId::InviteClient(id), false);
        // RFC 3263 §4.3, as for a non-INVITE
        let unreached = match notify {
            Some(Notify::Response) => response.status() == Some(StatusCode::SERVICE_UNAVAILABLE),
            Some(Notify::TimedOut | Notify::TransportFailed) => true,
            Some(Notify::Ack) | None => false,
        };
        if unreached {
            self.keep_unreached(AnyTransactionId::InviteClient(id), &sent, flow);
        }

        if notify == Some(Notify::Response) {
            // §14.1: a re-INVITE never forks, so its answer belongs to its dialog
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
        // §9.1: the CANCEL held for the first provisional goes now
        if cancel_due {
            self.send_cancel(id, now).ok();
        }

        if let Some(reason) = ending {
            self.retire(AnyTransactionId::InviteClient(id), reason);
        }
    }

    /// Whether a response to our INVITE may open a branch its set does not have yet.
    ///
    /// The first dialog and the first 2xx always open (a forked call may ring one phone and be
    /// answered on another). Further branches need room under `max_dialogs`. A 2xx without room is
    /// left unacknowledged, so its sender gives up with a BYE (§13.3.1.4); answering it here would
    /// let every forged 2xx trigger requests to a Contact of the sender's choice.
    fn fork_has_room(&self, set: Raw, status: StatusCode) -> bool {
        self.dialogs.set(set).is_some_and(|branches| {
            branches.is_empty()
                || (status.is_success()
                    && !branches
                        .dialogs()
                        .any(|dialog| dialog.state() == DialogState::Confirmed))
        }) || self.dialogs_held() < self.config.max_dialogs
    }

    /// Offer a response to the dialogs the INVITE has produced.
    fn on_fork(&mut self, id: TransactionId<InviteClient>, response: &RawMessage<'_>, flow: Flow) {
        let Some(status) = response.status() else {
            return;
        };
        let Some(set) = self.dialogs.set_for(id) else {
            return;
        };
        let room = self.fork_has_room(set, status);
        let Some(branches) = self.dialogs.set_mut(set) else {
            return;
        };
        let Ok(fork) = branches.on_response_with_room(response, room) else {
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
                    self.dialogs.answered(set);
                    // §13.2.2.4: every retransmitted 2xx gets the ACK again, on the flow the first
                    // ACK went, never a closed stream. The caller is not told twice
                    if let Some((ack, went_on)) = self
                        .dialogs
                        .kept_ack(dialog)
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
                    if self.was_cancelled(id) {
                        // the CANCEL lost the race; hanging up is the caller's call
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
                self.end_refused_set(set);
                // a challenge is not a refusal, as on the non-INVITE path
                if status != StatusCode::UNAUTHORIZED && status != StatusCode::PROXY_AUTH_REQUIRED {
                    self.note_failure_for(response, FailureReason::Refused);
                }
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
            // a 100, a response with no tag, or one with no room for its dialog
            Fork::Ignored => {
                let names_a_dialog = response.to().is_ok_and(|to| to.tag().is_some());
                if status.is_provisional() {
                    self.push(Event::Provisional {
                        invite: id,
                        dialog: None,
                        status,
                        response: response.to_owned(),
                    });
                } else if status.is_success() && !room && names_a_dialog {
                    // §13.3.1.4: the far end gives this up with a BYE; record it so the call does
                    // not vanish without trace
                    self.note_wire(
                        response,
                        Reason::ForkDroppedAtLimit,
                        Direction::Inbound,
                        flow,
                    );
                }
            }
        }
    }
}

impl Endpoint {
    fn on_request(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        // §8.2: a syntax error MUST get a 400. The parser does not know which fields will be read,
        // so it is asked here, before the retransmission check: a request never accepted has no
        // transaction to answer from.
        if let Err(invalid) = request.validate() {
            self.refuse_as_malformed(request, flow, &invalid);
            return;
        }
        // §17.2.3: a retransmission is answered from what was sent
        if let Some(server) = self.transactions.server_for(request) {
            self.on_known_request(server, request, flow, now);
            return;
        }

        let method = request.method();
        // an ACK creates nothing and is never answered
        if method != Some(Method::Ack) && self.refuse_when_full(request, flow) {
            return;
        }
        match method {
            // §17.2.1: the 2xx destroyed the server transaction, so its ACK matches none
            Some(Method::Ack) => self.on_ack_for_2xx(request),
            Some(Method::Cancel) => self.on_cancel(request, flow, now),
            Some(Method::Invite) => self.on_invite(request, flow, now),
            Some(_) => self.on_other_request(request, flow, now),
            None => (),
        }
    }

    /// Answer 400 to a request that arrived whole but cannot be acted on, naming the field.
    ///
    /// §8.2 wants a phrase that identifies the problem, so `Bad CSeq` rather than `Bad Request`.
    /// Stateless, like the overload refusal. A request missing a field the answer copies is still
    /// answered (RFC 4475 §3.3.1 `insuf`); only the `Via` is indispensable
    /// ([`ResponseBuilder::build_refusal`]).
    ///
    /// Not answered: an ACK (§17.1.1.3), and a request with no `Via` (§18.2.2). Responses are not
    /// judged here: §18.1.2 already filters them, and a fault in a field nobody reads should not
    /// break a call.
    fn refuse_as_malformed(&mut self, request: &RawMessage<'_>, flow: Flow, invalid: &Invalid) {
        let mut decision =
            Decision::of(Reason::RequestRefusedAsMalformed).at_address(flow.destination);
        if let Some(method) = request.method() {
            decision = decision.caused_by(WireEvent::request(
                method,
                Direction::Inbound,
                request.as_bytes().len(),
            ));
        }
        self.note(None, decision);
        if request.method() == Some(Method::Ack) {
            return;
        }
        let phrase = format!("Bad {}", invalid.field);
        let tag = self.mint_tag();
        let built = ResponseBuilder::for_request(request, StatusCode::BAD_REQUEST)
            .to_tag(&tag)
            .reason(phrase.as_bytes())
            .build_refusal();
        if let Ok(message) = built {
            self.queue(flow.transmit(message.bytes()));
        }
    }

    /// The ceiling on what a stranger may make this endpoint hold.
    ///
    /// A request inside one of our dialogs is held to [`Endpoint::refuse_when_dialog_full`]
    /// instead. A CANCEL that matches one of our transactions is never refused (§9.2 makes
    /// answering it a MUST). Everything else past the ceiling gets §21.5.4's 503, written straight
    /// to the flow, keeping nothing.
    ///
    /// An INVITE refused at `max_dialogs` carries `Retry-After`
    /// [`DIALOG_CEILING_RETRY_AFTER_SECONDS`]: this end is full, not broken. A refusal for server
    /// transactions alone carries none, since that ceiling is met by a flood and the sender should
    /// go elsewhere.
    fn refuse_when_full(&mut self, request: &RawMessage<'_>, flow: Flow) -> bool {
        // a CANCEL that matches nothing is held to the ceiling like any request; `on_cancel` counts
        // it against its dialog
        if request.method() == Some(Method::Cancel)
            && self.transactions.cancelled_by(request).is_some()
        {
            return false;
        }
        let dialog = DialogKey::as_uas(request)
            .ok()
            .and_then(|key| self.dialogs.find(&key));
        if let Some(dialog) = dialog {
            return self.refuse_when_dialog_full(dialog, request, flow);
        }
        let transactions = self.transactions.servers_len() >= self.config.max_server_transactions;
        // refused before it rings, counting admitted calls too: each becomes a dialog once answered
        let dialogs = request.method() == Some(Method::Invite)
            && self.dialogs_held() >= self.config.max_dialogs;
        if !transactions && !dialogs {
            return false;
        }

        self.refused = self.refused.saturating_add(1);
        let refused = self.refused;
        // on the endpoint's record: a flood with fresh Call-IDs would otherwise evict real calls
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
        // §8.2.6.2 wants a tag; minted and forgotten, since a stateless answer keeps nothing
        let tag = self.mint_tag();
        let seconds = DIALOG_CEILING_RETRY_AFTER_SECONDS.to_string();
        let mut builder =
            ResponseBuilder::for_request(request, StatusCode::SERVICE_UNAVAILABLE).to_tag(&tag);
        if dialogs {
            builder = builder.header(HeaderName::RetryAfter, seconds.as_bytes());
        }
        if let Ok(message) = builder.build() {
            self.queue(flow.transmit(message.bytes()));
        }
        true
    }

    /// [`MAX_DIALOG_NON_INVITE_TRANSACTIONS`]: the ceiling for a dialog we hold, in place of the
    /// endpoint-wide one.
    ///
    /// A re-INVITE is held to `max_dialogs` instead, and a BYE in order is exempt (see the
    /// constant). Past the ceiling a request gets a stateless 503 with `Retry-After`: RFC 5057 has
    /// a 503 end only its transaction, so the peer slows down without dropping the call.
    fn refuse_when_dialog_full(
        &mut self,
        dialog: DialogId,
        request: &RawMessage<'_>,
        flow: Flow,
    ) -> bool {
        let exempt = match request.method() {
            Some(Method::Invite) => true,
            // only a BYE that ends the dialog; an out-of-order one gets 500 and changes nothing
            Some(Method::Bye) => {
                let seen = self.dialogs.get(dialog).and_then(Dialog::remote_seq);
                !matches!((seen, request.cseq()), (Some(remote), Ok(cseq)) if cseq.seq < remote)
            }
            _ => false,
        };
        if exempt
            || self.dialogs.non_invite_transactions(dialog) < MAX_DIALOG_NON_INVITE_TRANSACTIONS
        {
            return false;
        }

        let call = self.call_of_dialog(dialog);
        let mut decision =
            Decision::of(Reason::RequestRefusedByDialog).at_address(flow.destination);
        if let Some(method) = request.method() {
            decision = decision.caused_by(WireEvent::request(
                method,
                Direction::Inbound,
                request.as_bytes().len(),
            ));
        }
        self.note(call.as_ref().map(CallId::as_bytes), decision);

        let tag = self.mint_tag();
        let seconds = DIALOG_BUSY_RETRY_AFTER_SECONDS.to_string();
        let built = ResponseBuilder::for_request(request, StatusCode::SERVICE_UNAVAILABLE)
            .to_tag(&tag)
            .header(HeaderName::RetryAfter, seconds.as_bytes())
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
                let ack = request.method() == Some(Method::Ack);
                let effects = if ack {
                    entry.machine.on_ack(now)
                } else {
                    entry.machine.on_request()
                };
                let notify = effects.notify;
                // the INVITE again: resend the answer the far end missed
                if ack {
                    self.apply(effects, flow, AnyTransactionId::InviteServer(id));
                } else {
                    self.apply_again(effects, flow, AnyTransactionId::InviteServer(id));
                }
                // RFC 6026 8.1: an ACK in Accepted belongs to the dialog
                if notify == Some(Notify::Ack) {
                    self.on_ack_for_2xx(request);
                }
            }
            Server::NonInvite(id) => {
                let Some(entry) = self.transactions.non_invite_server_mut(id) else {
                    return;
                };
                let effects = entry.machine.on_request();
                self.apply_again(effects, flow, AnyTransactionId::NonInviteServer(id));
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
        let Some(state) = self.dialogs.get(dialog) else {
            return;
        };
        // §13.3.1.4: only a confirmed dialog has had a 2xx to acknowledge. An early one's tag went
        // out in a 180, and taking an ACK for it would report a ringing call as up
        if state.state() != DialogState::Confirmed {
            return;
        }
        // §13.2.2.4, §17.1.1.3: the ACK's `CSeq` is that of the INVITE whose 2xx we sent last, not
        // the dialog's remote number, which a PRACK or UPDATE may have moved. Stale or repeated
        // ACKs are absorbed
        let Ok(cseq) = request.cseq() else {
            return;
        };
        if !self.dialogs.take_ack(dialog, cseq.seq) {
            return;
        }
        if let Some(entry) = self
            .dialogs
            .answered_by(dialog)
            .and_then(|answered| self.transactions.invite_server_mut(answered))
        {
            entry.machine.acknowledged_elsewhere();
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

        // §8.2.2.2: no To tag, and From tag, Call-ID and CSeq of a live server transaction on the
        // same line under another branch: a fork reaching us twice. Answered 482 on its own
        // transaction; the first call is untouched. A To tag makes it §12.2.2's case instead
        if existing.is_none() && self.transactions.merged_with(request) {
            self.refuse_merged_invite(request, flow, now);
            return;
        }
        // §8.1.1.8: a dialog-creating request MUST carry exactly one Contact, the only source of
        // the remote target (§12.1.1). Without one, a 2xx would open no dialog for the ACK or BYE.
        // RFC 2543 did not require it (RFC 4475 §3.4.1 inv2543), so say so with a refusal
        if existing.is_none() && !names_a_contact(request) {
            self.refuse_uncontactable_invite(request, flow, now);
            return;
        }

        let timers = self.config.timers;
        let Ok((id, effects)) = self
            .transactions
            .start_invite_server(request, flow, timers, now)
        else {
            return;
        };
        self.apply(effects, flow, AnyTransactionId::InviteServer(id));

        // §14.2: a re-INVITE; ordering and target refresh are the dialog's
        if let Some(dialog) = existing {
            self.remember_tag(AnyTransactionId::InviteServer(id), key_tag(request));
            if self.reject_out_of_order(dialog, request, id.into(), flow, now) {
                return;
            }
            // §14.2 answers a crossing INVITE itself (both MUSTs)
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
        // the room its dialog will take is held from here
        self.admitted.insert(id);
        self.push(Event::IncomingInvite {
            transaction: id,
            request: request.to_owned(),
        });
    }

    /// §8.2.2.2: answer a merged INVITE 482 on its own transaction, without touching the first
    /// copy's call.
    fn refuse_merged_invite(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        let timers = self.config.timers;
        let Ok((id, effects)) = self
            .transactions
            .start_invite_server(request, flow, timers, now)
        else {
            return;
        };
        self.apply(effects, flow, AnyTransactionId::InviteServer(id));
        let tag = self.mint_tag();
        self.remember_tag(AnyTransactionId::InviteServer(id), tag.clone());
        let owned = request.to_owned();
        let Ok(message) = assemble_response(&owned, StatusCode::LOOP_DETECTED, Some(&tag)) else {
            return;
        };
        let Some(entry) = self.transactions.invite_server_mut(id) else {
            return;
        };
        let effects = entry.machine.respond(message, now);
        self.apply(effects, flow, AnyTransactionId::InviteServer(id));
    }

    /// §8.1.1.8: answer an INVITE with no `Contact` with a 400, on its own transaction so
    /// retransmissions are answered from it.
    fn refuse_uncontactable_invite(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        let timers = self.config.timers;
        let Ok((id, effects)) = self
            .transactions
            .start_invite_server(request, flow, timers, now)
        else {
            return;
        };
        self.apply(effects, flow, AnyTransactionId::InviteServer(id));
        let tag = self.mint_tag();
        self.remember_tag(AnyTransactionId::InviteServer(id), tag.clone());
        let decision = Decision::of(Reason::RequestRefusedAsMalformed)
            .at_address(flow.destination)
            .caused_by(WireEvent::request(
                Method::Invite,
                Direction::Inbound,
                request.as_bytes().len(),
            ));
        self.note(None, decision);
        let Ok(message) = ResponseBuilder::for_request(request, StatusCode::BAD_REQUEST)
            .to_tag(&tag)
            .reason(b"Missing Contact")
            .build()
        else {
            return;
        };
        let Some(entry) = self.transactions.invite_server_mut(id) else {
            return;
        };
        let effects = entry.machine.respond(message, now);
        self.apply(effects, flow, AnyTransactionId::InviteServer(id));
    }

    fn on_cancel(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        let timers = self.config.timers;
        let Ok(cancel) = self
            .transactions
            .start_non_invite_server(request, flow, timers)
        else {
            return;
        };
        // an in-dialog CANCEL counts against the dialog's budget until it retires
        if let Some(dialog) = DialogKey::as_uas(request)
            .ok()
            .and_then(|key| self.dialogs.find(&key))
        {
            self.dialogs.reserve_non_invite_transaction(dialog);
            self.remember_dialog(AnyTransactionId::NonInviteServer(cancel), dialog);
        }

        // §9.2: 200 for a CANCEL matching a transaction of any method (by §17.2.3's rules), 481
        // otherwise
        let owned = request.to_owned();
        let Some(matched) = self.transactions.cancelled_by(request) else {
            self.answer(cancel, &owned, StatusCode::CALL_DOES_NOT_EXIST, now);
            return;
        };
        // §9.2: the CANCEL's To tag SHOULD match the original's, so reuse the INVITE's tag
        let original = match matched {
            Server::Invite(id) => AnyTransactionId::InviteServer(id),
            Server::NonInvite(id) => AnyTransactionId::NonInviteServer(id),
        };
        let tag = self.tag_or_mint(original);
        self.remember_tag(AnyTransactionId::NonInviteServer(cancel), tag);
        self.answer(cancel, &owned, StatusCode::OK, now);
        // §9.2: a CANCEL does not affect non-INVITE transactions
        let Server::Invite(invite) = matched else {
            return;
        };
        // §9.2: 487 for the INVITE, a no-op if it already has a final response
        let Some(entry) = self.transactions.invite_server(invite) else {
            return;
        };
        let invite_flow = entry.flow;
        let original = entry.request.clone();
        let tag = self.tag_for(AnyTransactionId::InviteServer(invite));
        let early = self.early_dialog_of(invite);
        let mut refused = false;
        if let Ok(message) =
            assemble_response(&original, StatusCode::REQUEST_TERMINATED, tag.as_deref())
            && let Some(entry) = self.transactions.invite_server_mut(invite)
        {
            let effects = entry.machine.respond(message, now);
            refused = effects.send.is_some();
            self.apply(effects, invite_flow, AnyTransactionId::InviteServer(invite));
        }
        // §9.2: a CANCEL after the final response has no effect, so nothing to report
        if !refused {
            return;
        }
        // RFC 3262 §3: stop retransmitting reliable provisionals; a PRACK is still answered
        self.quiet_reliable(invite);
        self.push(Event::IncomingCancel {
            invite,
            request: owned,
        });
        // after the CANCEL, so the caller hears why before the dialog ends
        self.admitted.remove(&invite);
        self.end_refused_early(invite, early);
    }

    /// What [`super::EndpointConfig::max_dialogs`] counts: dialogs held, admitted calls, and placed
    /// calls not yet answered.
    pub(super) fn dialogs_held(&self) -> usize {
        self.dialogs
            .len()
            .saturating_add(self.admitted.len())
            .saturating_add(self.dialogs.unopened())
    }

    /// The early dialog an INVITE of theirs opened, if any.
    ///
    /// §12.3: a non-2xx final ends the early dialogs its provisionals created. Read before the
    /// refusal goes out. A `To` tag equal to ours means an in-dialog re-INVITE, whose refusal
    /// leaves the dialog standing; any other tag names a dialog we lack, so the INVITE is a new
    /// call (§12.2.2).
    pub(super) fn early_dialog_of(
        &self,
        invite: TransactionId<crate::transaction::InviteServer>,
    ) -> Option<DialogId> {
        let request = self.transactions.invite_server(invite)?.request.as_raw();
        let tag = crate::dialog::Tag::new(
            self.local_tags
                .get(&AnyTransactionId::InviteServer(invite))?,
        );
        let named = request.to().ok()?.tag();
        if named.is_some_and(|named| crate::dialog::Tag::new(&named) == tag) {
            return None;
        }
        let key = DialogKey::new(
            CallId::new(request.call_id().ok()?),
            tag,
            request
                .from()
                .ok()?
                .tag()
                .map(|t| crate::dialog::Tag::new(&t)),
        );
        let dialog = self.dialogs.find(&key)?;
        (self.dialogs.get(dialog)?.state() == DialogState::Early).then_some(dialog)
    }

    /// End the early dialog [`Endpoint::early_dialog_of`] found, now that its INVITE was refused.
    ///
    /// Without this, ring-and-cancel pairs would fill `max_dialogs`. Not while a reliable
    /// provisional is unacknowledged: RFC 3262 §3 keeps the UAS ready for PRACKs, matched inside
    /// the dialog. Retiring the transaction ends it then.
    pub(super) fn end_refused_early(
        &mut self,
        invite: TransactionId<crate::transaction::InviteServer>,
        early: Option<DialogId>,
    ) {
        let Some(dialog) = early else {
            return;
        };
        if self.reliable.outstanding_on(invite) {
            return;
        }
        if let Some(state) = self.dialogs.get_mut(dialog) {
            state.terminate();
        }
        self.forget_dialog(dialog, DialogEndReason::Refused);
    }

    fn on_other_request(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        let dialog = DialogKey::as_uas(request)
            .ok()
            .and_then(|key| self.dialogs.find(&key));
        // §8.2.2.2 as in `on_invite`, read before this transaction joins the index
        let merged = dialog.is_none() && self.transactions.merged_with(request);

        let timers = self.config.timers;
        let Ok(id) = self
            .transactions
            .start_non_invite_server(request, flow, timers)
        else {
            return;
        };
        // §17.2.2 gives Trying/Proceeding no timer; this one answers 408 if the application never
        // does
        let deadline = self.schedule(
            now + timers.sixty_four_t1(),
            Deadline::UnansweredNonInvite(id),
        );
        self.unanswered.insert(id, deadline);
        if let Some(dialog) = dialog {
            self.dialogs.reserve_non_invite_transaction(dialog);
            self.remember_dialog(AnyTransactionId::NonInviteServer(id), dialog);
        }
        // a merged copy is answered here and never handed up
        if merged {
            self.answer(id, &request.to_owned(), StatusCode::LOOP_DETECTED, now);
            return;
        }

        let Some(dialog) = dialog else {
            let tag = self.mint_tag();
            self.remember_tag(AnyTransactionId::NonInviteServer(id), tag);
            // a PRACK with no dialog matches nothing; §3 answers it 481
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

        // RFC 3262 §3: a PRACK is answered here, matched on RSeq, CSeq and method
        if request.method() == Some(Method::Prack) {
            self.on_prack(id, Some(dialog), request, now);
            return;
        }

        // RFC 3311 §5.2: a second UPDATE before the first is answered is refused here; offer state
        // is not ours to judge
        if request.method() == Some(Method::Update) {
            if self.refuse_crossing_update(dialog, id, flow, now) {
                return;
            }
            self.reinvites.receive_update(dialog, id);
        }

        if request.method() == Some(Method::Bye) {
            // §15.1.2: the dialog ends when the BYE is accepted; the 200 is the caller's
            if let Some(state) = self.dialogs.get_mut(dialog) {
                state.terminate();
            }
            self.push(Event::IncomingBye {
                transaction: id,
                dialog,
                request: request.to_owned(),
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
        let before = self
            .dialogs
            .get(dialog)
            .map(|state| state.remote_target().as_str().to_owned());
        let out_of_order = self
            .dialogs
            .get_mut(dialog)
            .is_some_and(|state| state.on_request(request) == Ok(Incoming::OutOfOrder));
        // an out-of-order request never reaches the target refresh; an accepted one asks the caller
        // to resolve (§12.2.1.2)
        self.resolve_if_target_moved(dialog, before.as_deref());
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
                    // read before applying: timer B retires the transaction
                    let renegotiated = self.reinvites.dialog_of(inner);
                    let over = name == TimerName::B && notify == Some(Notify::TimedOut);
                    // likewise the name the record is kept under
                    let call = over.then(|| self.call_of(id)).flatten();
                    // and the request, for RFC 3263 §4.3
                    if over {
                        self.keep_unreached_in_flight(id, flow);
                    }
                    self.apply_again(effects, flow, id);
                    if over {
                        self.count_timeout();
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
                    // read before applying: retiring forgets the dialog
                    let dialog = over.then(|| self.dialog_of(id)).flatten();
                    // and the request, for RFC 3263 §4.3
                    if over {
                        self.keep_unreached_in_flight(id, flow);
                    }
                    self.apply_again(effects, flow, id);
                    if over {
                        self.count_timeout();
                        self.note_failure(call.as_ref(), FailureReason::Timeout);
                        self.push(Event::RequestFailed {
                            transaction: inner,
                            reason: FailureReason::Timeout,
                        });
                        if let Some(dialog) = dialog {
                            self.failover(dialog, flow);
                        }
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
                    // timer H: never acknowledged. Only the record says so
                    let unacknowledged = effects.notify == Some(Notify::TimedOut);
                    let call = unacknowledged.then(|| self.call_of(id)).flatten();
                    self.apply_again(effects, flow, id);
                    if unacknowledged {
                        self.count_timeout();
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
        for transport in self.transports.streams_without_keepalive() {
            let Some(interval) = self.keepalive_interval_of(transport) else {
                continue;
            };
            let at = now + self.tokens.jitter(interval);
            let handle = self.schedule(at, Deadline::Keepalive(transport));
            if let Some(bound) = self.transports.get_mut(transport) {
                bound.keepalive = Some(handle);
            }
        }
    }

    pub(super) fn send_keepalive(&mut self, transport: super::TransportId, now: Instant) {
        let Some(bound) = self.transports.get_mut(transport) else {
            return;
        };
        let flow = Flow {
            transport,
            destination: bound.remote.unwrap_or(bound.local),
            source: None,
            protocol: bound.protocol,
        };
        // the next lone CRLF answers this ping
        if let Some(framer) = bound.framer.as_mut() {
            framer.ping_sent();
        }
        self.queue(flow.transmit(Arc::from(PING)));
        let next = self
            .keepalive_interval_of(transport)
            .map(|interval| now + self.tokens.jitter(interval))
            .map(|at| self.schedule(at, Deadline::Keepalive(transport)));
        // One pong deadline per flow, from the earliest unanswered ping, since pongs are not
        // matched to pings. None on a flow that never answered: §4.4 expects pongs only after an
        // explicit indication, and Asterisk sends none.
        let (armed, answers) = self
            .transports
            .get(transport)
            .map_or((None, false), |bound| (bound.pong, bound.answers_pings));
        let overdue =
            if answers {
                Some(armed.unwrap_or_else(|| {
                    self.schedule(now + PONG_DUE, Deadline::PongOverdue(transport))
                }))
            } else {
                None
            };
        if let Some(bound) = self.transports.get_mut(transport) {
            bound.keepalive = next;
            bound.pong = overdue;
        }
    }

    /// How often a stream transport is pinged: the interval its owner asked
    /// for it ([`Endpoint::keep_stream_alive`]), or the endpoint's own.
    pub(super) fn keepalive_interval_of(&self, transport: super::TransportId) -> Option<Duration> {
        self.stream_keepalives
            .get(&transport)
            .copied()
            .or(self.config.keepalive_interval)
    }

    /// The far end answered: the clock stops, and from now on an unanswered ping counts.
    fn pong_arrived(&mut self, transport: super::TransportId) {
        let Some(handle) = self.transports.get_mut(transport).and_then(|bound| {
            bound.answers_pings = true;
            bound.pong.take()
        }) else {
            return;
        };
        self.deadlines.cancel(handle);
    }

    /// 64·T1 after a non-INVITE server transaction was created with no final response: §17.2.2
    /// gives `Trying`/`Proceeding` no timer, so the endpoint answers 408 itself. The client's Timer
    /// F (§17.1.2.2) has fired by now anyway.
    ///
    /// A no-op once a final response was sent. A transaction answered over a datagram is still in
    /// `Completed` when this fires.
    pub(super) fn non_invite_app_timeout(
        &mut self,
        id: TransactionId<NonInviteServer>,
        now: Instant,
    ) {
        self.unanswered.remove(&id);
        let Some(entry) = self.transactions.non_invite_server(id) else {
            return;
        };
        if !matches!(
            entry.machine.state(),
            NonInviteServerState::Trying | NonInviteServerState::Proceeding
        ) {
            return;
        }
        let flow = entry.flow;
        let request = entry.request.clone();
        let call = request.as_raw().call_id().ok().map(CallId::new);
        let tag = self.tag_or_mint(AnyTransactionId::NonInviteServer(id));
        let Ok(message) = assemble_response(&request, StatusCode::REQUEST_TIMEOUT, Some(&tag))
        else {
            return;
        };
        let Some(entry) = self.transactions.non_invite_server_mut(id) else {
            return;
        };
        let effects = entry.machine.respond(message, now);
        self.apply(effects, flow, AnyTransactionId::NonInviteServer(id));
        // RFC 3311 §5.2: the 408 ends a pending UPDATE like any final
        self.reinvites
            .answered_theirs(AnyTransactionId::NonInviteServer(id));
        self.note(
            call.as_ref().map(CallId::as_bytes),
            Decision::of(Reason::RequestAnsweredByTimeout)
                .at_address(flow.destination)
                .over(flow.protocol),
        );
    }

    /// Ten seconds without a pong on a flow that answered before: dead under §4.4.1, so taken down.
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
        // read before applying retires them: the request (RFC 3263 §4.3) and the dialog
        if notify == Some(Notify::TransportFailed) {
            self.keep_unreached_in_flight(id, flow);
        }
        let dialog = match id {
            AnyTransactionId::NonInviteClient(_) => self.dialog_of(id),
            AnyTransactionId::InviteClient(_)
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
                    if let Some(dialog) = dialog {
                        self.failover(dialog, flow);
                    }
                }
                AnyTransactionId::InviteServer(_) | AnyTransactionId::NonInviteServer(_) => (),
            }
        }
    }
}

impl Endpoint {
    /// Send what a machine asked to send, and retire it if it is done.
    pub(super) fn apply(&mut self, effects: Effects, flow: Flow, id: AnyTransactionId) {
        if let Some(reason) = self.apply_deferred(effects, flow, id, false) {
            self.retire(id, reason);
        }
    }

    /// The same, for a send a retransmission timer asked for, recorded as a retransmission.
    pub(super) fn apply_again(&mut self, effects: Effects, flow: Flow, id: AnyTransactionId) {
        if let Some(reason) = self.apply_deferred(effects, flow, id, true) {
            self.retire(id, reason);
        }
    }

    /// Send what a machine asked to send, and return why it should be retired instead of retiring
    /// it.
    ///
    /// Timers D and K are zero on reliable transports (§17.1.1.2, §17.1.2.2), so a final response
    /// over TCP ends the transaction in the same call. The response must still reach the TU, and
    /// what reads it (forks, a racing CANCEL, a nonce, the dialog) lives in state
    /// [`Endpoint::retire`] removes. Reporting first keeps events in the same order on every
    /// transport.
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

    /// Queue what a machine handed over, and record it.
    ///
    /// A client's first send goes through [`Endpoint::apply_client`], so a client send here is a
    /// retransmission or the ACK for a refusal.
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
        let client = id.role() == Role::Client;
        // the ACK to a refusal (§17.1.1.3) is compacted like any request we build
        let message = if client && message.bytes().starts_with(b"ACK ") {
            self.written_for_the_datagram(flow, message.clone())
                .unwrap_or(message)
        } else {
            message
        };
        let reason = match (client, repeat) {
            (true, false) => Reason::RequestSent,
            (true, true) => Reason::RequestRetransmitted,
            (false, false) => Reason::ResponseSent,
            (false, true) => Reason::ResponseRetransmitted,
        };
        if repeat {
            self.count_retransmission(client, Some(id));
        }
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
                    // §13.2.2.4: 64*T1 after the first 2xx no more are expected; early branches end
                    if let Some(branches) = self.dialogs.set_mut(set) {
                        branches.no_more_answers();
                    }
                    self.end_branches(set, DialogEndReason::Abandoned);
                    self.dialogs.invite_done(set);
                }
                self.forget_cancelled(inner);
                // §14: the re-INVITE's ACK lives until timer M
                self.reinvites.finish(inner);
                self.transactions.drop_invite_client(inner);
            }
            AnyTransactionId::NonInviteClient(inner) => {
                self.transactions.drop_non_invite_client(inner);
            }
            AnyTransactionId::InviteServer(inner) => {
                // an early dialog kept for RFC 3262 §3 PRACKs goes with the transaction; read while
                // its tag remains
                let early = self.early_dialog_of(inner);
                self.forget_reliable_on(inner);
                self.reinvites.answered_theirs(id);
                self.admitted.remove(&inner);
                self.end_refused_early(inner, early);
                self.transactions.release_invite_merge(inner);
                self.transactions.drop_invite_server(inner);
            }
            AnyTransactionId::NonInviteServer(inner) => {
                // release the dialog budget slot
                if let Some(dialog) = self.dialog_of(id) {
                    self.dialogs.release_non_invite_transaction(dialog);
                }
                // and the 408 deadline
                if let Some(deadline) = self.unanswered.remove(&inner) {
                    self.deadlines.cancel(deadline);
                }
                self.reinvites.answered_theirs(id);
                self.transactions.release_non_invite_merge(inner);
                self.transactions.drop_non_invite_server(inner);
            }
        }
        self.forget_tag(id);
        // the challenge allowance, unless challenged again
        self.challenges.forget(id);
        self.dialogs_of.remove(&id);
        self.push(Event::TransactionTerminated {
            transaction: id,
            reason,
        });
    }

    /// The INVITE a set follows was refused: the call it placed stops
    /// counting against `max_dialogs`, and every dialog it opened ends.
    fn end_refused_set(&mut self, set: Raw) {
        self.dialogs.refused(set);
        self.end_branches(set, DialogEndReason::Refused);
    }

    /// Report and forget every dialog of a set that has just ended.
    pub(super) fn end_branches(&mut self, set: Raw, reason: DialogEndReason) {
        for id in self.dialogs.branches_of(set) {
            if self.dialogs.get(id).map(Dialog::state) == Some(DialogState::Terminated) {
                self.forget_dialog(id, reason);
            }
        }
    }

    pub(super) fn forget_dialog(&mut self, dialog: DialogId, reason: DialogEndReason) {
        // read before `forget` takes the name away
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
    /// `renegotiated` is the re-INVITE's dialog, read before retiring forgets it.
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
        let reason = self.cancel_reasons.get(&invite).cloned();
        let message = cancel_for_request(&request.as_raw(), reason.as_deref())?;
        // compacted like any request; a CANCEL is small, so only `Compaction::Always` matters
        let message = self
            .written_for_the_datagram(flow, message.clone())
            .unwrap_or(message);
        // §9.1: a CANCEL already running under this key retransmits itself; a second would steal
        // its responses
        if self.transactions.has_client_for(&message.as_raw()) {
            return Ok(());
        }
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

    /// A dialog we open by answering a request (§12.1.1): an INVITE, or a NOTIFY for a subscriber
    /// (RFC 6665 §4.4.1). §12.1.1 reads the same fields off either.
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
    /// §8.2.6.2: one tag on every response of a transaction but a 100.
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

/// Where refused bytes came from, to route an answer before their `Via` is read.
#[derive(Clone, Copy)]
struct Arrival {
    transport: super::TransportId,
    remote: SocketAddr,
    local: Option<SocketAddr>,
    protocol: super::TransportProtocol,
}

/// Whether what [`salvage_request`] recovered can be answered: not an ACK, and a readable top `Via`
/// within the value bound.
///
/// The `Via` routes the answer (§18.2.2), so an oversize one is not trusted. `From`, `To`,
/// `Call-ID` and `CSeq` are copied whole, or left out when absent.
fn can_be_answered(request: &RawMessage<'_>, value_bound: usize) -> bool {
    request.method().is_some_and(|method| method != Method::Ack)
        && request
            .header(HeaderName::Via)
            .is_some_and(|top| top.len() <= value_bound)
        && request.top_via().is_ok()
}

/// The status a request the parser refused is answered with, and a reason
/// phrase that says why (§21.4.1 asks a 400 to name the problem).
fn refusal(error: ParseError, bytes: &[u8]) -> (StatusCode, String) {
    let bad = |phrase: String| (StatusCode::BAD_REQUEST, phrase);
    match error {
        ParseError::MessageTooLarge { limit } => (
            StatusCode::MESSAGE_TOO_LARGE,
            format!("Message Too Large (limit {limit} bytes)"),
        ),
        ParseError::HeaderValueTooLong { name_at, limit } => bad(format!(
            "{} Too Long (limit {limit} bytes)",
            field_name(bytes, name_at)
        )),
        ParseError::TooManyHeaders { limit } => {
            bad(format!("Too Many Header Fields (limit {limit})"))
        }
        ParseError::BodyTruncated { .. } => bad("Content-Length Exceeds Message".to_owned()),
        ParseError::ConflictingContentLength { .. } => bad("Conflicting Content-Length".to_owned()),
        ParseError::MissingContentLength => bad("Missing Content-Length".to_owned()),
        ParseError::BadHeaderLine { .. } => bad("Malformed Header Line".to_owned()),
        ParseError::UnterminatedHeaders => bad("Headers Not Terminated".to_owned()),
        ParseError::BadStartLine { .. } => bad("Malformed Request Line".to_owned()),
        ParseError::Empty => bad("Empty Message".to_owned()),
    }
}

/// The field name at `at` as the peer wrote it, when it fits a reason phrase unescaped (§25.1);
/// `Header` otherwise.
fn field_name(bytes: &[u8], at: u32) -> &str {
    const LONGEST: usize = 64;
    let from = bytes.get(at as usize..).unwrap_or_default();
    let end = from
        .iter()
        .position(|byte| matches!(byte, b':' | b' ' | b'\t'))
        .unwrap_or(from.len());
    let name = from.get(..end).unwrap_or_default();
    let writable = name
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.!~*'+".contains(byte));
    if name.is_empty() || name.len() > LONGEST || !writable {
        return "Header";
    }
    core::str::from_utf8(name).unwrap_or("Header")
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

/// Whether a request has a `Contact` with an address. `*` is REGISTER's alone (§10.2.2).
fn names_a_contact(request: &RawMessage<'_>) -> bool {
    match request.contact() {
        Ok(Contacts::Addrs(mut addrs)) => addrs.next().is_some_and(|addr| addr.is_ok()),
        Ok(Contacts::Star) | Err(_) => false,
    }
}
