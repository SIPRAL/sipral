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
/// §4.4.1: "If a pong is not received within 10 seconds after sending a ping
/// ... then the client MUST treat the flow as failed."
///
/// Not configurable. The interval between pings is a trade-off between battery
/// and availability and the RFC says so; this one is the MUST, and a stack that
/// let it be turned up would be a stack that can be configured out of
/// conformance.
const PONG_DUE: core::time::Duration = core::time::Duration::from_secs(10);

/// The most non-INVITE server transactions one dialog may have open at once.
///
/// A request inside a dialog we hold is exempt from
/// [`super::EndpointConfig::max_server_transactions`] — docs/03 says why: a
/// stranger's flood must not starve a call that is up. That exemption has no
/// ceiling of its own unless something gives it one, and a peer already
/// inside the dialog — including one that has since gone hostile, or a bug on
/// the far end that never stops sending INFO — could otherwise open as many
/// of these as it likes, which is the endpoint-wide flood again with a
/// friendlier address on it. Sixteen is well past what a real exchange inside
/// one call needs live at once (DTMF, a PRACK or two, an UPDATE) and well
/// short of turning one noisy dialog into an unbounded one.
///
/// A BYE in order never draws from this budget, however many of the sixteen
/// are already open: RFC 3261 §15.1.1 has the caller "consider the session
/// terminated" from the moment it sends one, whatever answer comes back, so
/// a 503 here does not slow a flood down — it leaves the far end holding a
/// dialog the other side has already hung up on. Only one BYE is ever worth
/// answering per dialog in any case, since the dialog itself, and the
/// budget with it, is gone once it is. A BYE whose `CSeq` runs backwards is
/// the exception: §12.2.2 answers it 500 and the dialog stands, so it ends
/// nothing and is held to the budget like any other request — otherwise a
/// peer could open transactions past it without limit by numbering its BYEs
/// low.
const MAX_DIALOG_NON_INVITE_TRANSACTIONS: usize = 16;
/// `Retry-After` on the 503 [`Endpoint::refuse_when_dialog_full`] answers
/// with. RFC 5057 does not name a value for this refusal; one second is
/// short because the load it answers is a burst inside a call that is
/// otherwise healthy, not a stranger to be sent away.
const DIALOG_BUSY_RETRY_AFTER_SECONDS: u32 = 1;

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
                Ok(Some(Framed::Message(message))) => {
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
        // framing lost: nothing says where the message ends, so nothing can be
        // answered, and the connection goes below. Counted all the same
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

    /// Answer what the parser refused, when an answer can be addressed, and
    /// leave a trace of it either way.
    ///
    /// §8.2 has a UAS answer a request it cannot process instead of leaving
    /// the client to retransmit into silence until timer B or F gives up:
    /// §21.5.14's 513 for one longer than [`crate::msg::Limits::max_message_bytes`],
    /// §21.4.1's 400 for anything else, with a reason phrase that names the
    /// bound or the fault — a peer told `Subject Too Long (limit 16384 bytes)`
    /// knows what to change, and one told `Bad Request` does not. The answer
    /// is written from what [`salvage_request`] still recovers of it, and is
    /// stateless for the reason [`Endpoint::refuse_as_malformed`] gives: there
    /// is nothing worth remembering about a message this end could not read.
    ///
    /// Nothing is answered when the bytes are a response, an ACK (never
    /// answered, §17.1.1.3), or a request whose top `Via` cannot be read,
    /// since that `Via` is where an answer goes (§18.2.2) and what the client
    /// matches it on (§17.1.3). A `From`, `To`, `Call-ID` or `CSeq` that is
    /// missing or cannot be read is not a reason to stay silent: the answer
    /// copies whichever of them are there ([`ResponseBuilder::build_refusal`]),
    /// as the answer to a request that parsed but lacks them does. Either way the
    /// count behind [`Endpoint::unreadable`] moves and the endpoint's record
    /// says which of the two happened, on the endpoint's record rather than a
    /// call's for the same reason overload refusals are: a stranger's garbage
    /// must not push the calls this endpoint carries out of the set.
    ///
    /// `bytes` is what was refused — the whole datagram, or only the head of
    /// a message on a stream — and `length` how long the whole message is.
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
        // the copied fields, a longer status line and a tag can pass the
        // message bound the builder still holds an answer to: nothing to send
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
                    // a challenge is not a refusal: `on_challenge`, below,
                    // is what decides whether this one is answered, and its
                    // own entries (`auth.challenge.received` and
                    // `auth.challenge.answered`) already say what happened
                    // to it
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
        // The call the caller placed always opens: the first dialog of an
        // INVITE this end sent, and the first 2xx to it. Those are not always
        // one branch, since a forking proxy rings the desk phone and the
        // mobile and the mobile answers. Every branch past them is the far
        // end's to multiply, and opens only while max_dialogs has room: a
        // provisional that finds none is reported without a dialog, and a 2xx
        // is left unacknowledged for its sender to give up with a BYE
        // (§13.3.1.4). Acknowledging and hanging it up here instead would turn
        // every forged 2xx into two requests and their retransmissions, sent
        // to a Contact the sender chose.
        let room = self.dialogs.set(set).is_some_and(|branches| {
            branches.is_empty()
                || (status.is_success()
                    && !branches
                        .dialogs()
                        .any(|dialog| dialog.state() == DialogState::Confirmed))
        }) || self.dialogs_held() < self.config.max_dialogs;
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
                    // 13.2.2.4: "The ACK MUST be passed to the client
                    // transport every time a retransmission of the 2xx final
                    // response that triggered the ACK arrives." The caller
                    // heard about this call once and does not hear again. It
                    // goes where the first one went, which is not the flow
                    // the 2xx came in on when §18.1.1 moved the ACK onto a
                    // stream, and never to a stream that has since closed
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
                            self.queue(went_on.transmit(ack.bytes()));
                        }
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
                // the same carve-out the non-INVITE path makes, for the same
                // reason and so that one counter does not mean two things
                // depending on the method: a challenge is not a refusal, and
                // `auth.challenge.received` already says one arrived
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
            // a 100, a response with no tag to name a dialog by, or one that
            // found no room for the dialog it would have opened
            Fork::Ignored => {
                let names_a_dialog = response.to().ok().is_some_and(|to| to.tag().is_some());
                if status.is_provisional() {
                    self.push(Event::Provisional {
                        invite: id,
                        dialog: None,
                        status,
                        response: response.to_owned(),
                    });
                } else if status.is_success() && !room && names_a_dialog {
                    // §13.3.1.4 has the far end give this up with a BYE of its
                    // own; nothing here is wrong enough to report upward, but
                    // a call that vanishes without a trace is exactly what
                    // this record exists to replace
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

// -- requests ---------------------------------------------------------------

impl Endpoint {
    fn on_request(&mut self, request: &RawMessage<'_>, flow: Flow, now: Instant) {
        // §8.2.x, before anything acts on it: "If the UAS detects a syntax
        // error, it MUST respond with a 400". The parser does not ask this
        // question -- it does not know which fields will be read -- so this is
        // where it is asked, once, by the end that is about to answer. Before
        // the retransmission check too: a request this endpoint never accepted
        // has no server transaction to be answered from, and matching one on a
        // CSeq that disagrees with its own start line is exactly the confusion
        // being refused.
        if let Err(invalid) = request.validate() {
            self.refuse_as_malformed(request, flow, &invalid);
            return;
        }
        // 17.2.3: a retransmission is answered from what was already sent, not
        // handed up again
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

    /// Answer 400 to a request that arrived whole and cannot be acted on, and
    /// say which field it was.
    ///
    /// §8.2.x asks for "a Reason-Phrase that identifies the syntax problem",
    /// so the field's own name goes in it: a peer that gets `Bad CSeq` knows
    /// where to look, and one that gets `Bad Request` has to guess. The
    /// answer is stateless, for the same reason the overload refusal is: there
    /// is nothing here worth remembering about a message this end could not
    /// read, and a retransmission of it earns the same answer again.
    ///
    /// A request missing a field the answer would copy is answered all the
    /// same, with what it had: RFC 4475 §3.3.1's `insuf` has no `From`, `To`
    /// or `Call-ID` and "ideally" gets a 400, and the one field an answer
    /// cannot go without is the `Via` that routes it
    /// ([`ResponseBuilder::build_refusal`]).
    ///
    /// Three of them are answered with nothing at all. An ACK is never
    /// answered (§17.1.1.3), so a malformed one is dropped where it stands.
    /// A request with no `Via` names no place to send an answer to, and
    /// §18.2.2 has the response go to where the `Via` says; the builder
    /// refuses to write one, and the refusal is the drop. And a response is
    /// not judged here at all: §18.1.2 already
    /// discards one whose `Via` is not ours, and each reader of a response
    /// handles the field it reads, so a response carrying a fault in a field
    /// nobody reads stays usable rather than becoming a call that never
    /// connects.
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
    /// A request inside a dialog we already have is never refused *for this*,
    /// whatever the count says: it manages state that exists. It is held to
    /// [`Endpoint::refuse_when_dialog_full`] instead, which is its own,
    /// smaller ceiling — except a BYE in order, which that ceiling exempts too: a BYE
    /// turned away leaves the call standing for the life of the process, and
    /// §15.1.1 has the far end consider the session over the moment it sent
    /// one regardless of what comes back, so refusing it buys nothing. Nor is
    /// a CANCEL that matches a transaction of ours, for the same reason and
    /// because §9.2 makes answering it a MUST, in or out of a dialog. A
    /// stranger's request is the remaining case, and
    /// past the ceiling it gets §21.5.4's 503 — "temporarily unable to
    /// process the request due to a temporary overloading" — written straight
    /// to the flow, because the point of refusing is not to keep anything. No
    /// `Retry-After` goes with it: §21.5.4 has a client that gets none treat
    /// it as a 500 and try somewhere else, which is what should happen, while
    /// one that names a delay asks a proxy to stop sending here for that
    /// long.
    fn refuse_when_full(&mut self, request: &RawMessage<'_>, flow: Flow) -> bool {
        // and neither is a CANCEL that matches something: §9.2 makes answering
        // one a MUST, and it ends a transaction rather than starting one worth
        // counting. A CANCEL that matches nothing is held to the same ceiling
        // as any other request: the endpoint's outside a dialog, and inside
        // one the dialog's own, which `on_cancel` counts it against
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
        // a call is refused before it rings rather than after it is answered:
        // the dialog would be created by our own 2xx, and by then the far end
        // has heard ringback
        // and it is measured against the calls already let in as well as the
        // dialogs already made, since each of those becomes a dialog the moment
        // it is answered
        let dialogs = request.method() == Some(Method::Invite)
            && self.dialogs_held() >= self.config.max_dialogs;
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

    /// [`MAX_DIALOG_NON_INVITE_TRANSACTIONS`]: the ceiling a dialog we hold
    /// gets in place of the endpoint-wide one, which never applies to it.
    ///
    /// A re-INVITE is an INVITE server transaction and is held to
    /// `max_dialogs` like any other INVITE — §14.1 refuses a second one in
    /// the same dialog anyway while one is outstanding — so only a
    /// non-INVITE request draws from this budget, and a BYE in order never
    /// does either: §15.1.1 has the caller "consider the session terminated"
    /// the moment its BYE is sent, whatever answer comes back, so a 503 here
    /// buys nothing but a far end left holding a dialog the other side has
    /// already abandoned, and only one BYE is ever worth honouring per
    /// dialog regardless of how many other transactions are open on it. A
    /// BYE whose `CSeq` runs backwards ends nothing (§12.2.2 answers it 500)
    /// and draws from the budget like any other request. Past
    /// it, every other non-INVITE request is answered 503, statelessly
    /// exactly as the endpoint-wide ceiling is, but *with* a `Retry-After`:
    /// RFC 5057 classes a 503 as ending only the transaction it answers, so
    /// the call underneath it is untouched, and `Retry-After` tells this one
    /// peer's own client transaction to slow down rather than read the
    /// refusal as a reason to give the call up.
    fn refuse_when_dialog_full(
        &mut self,
        dialog: DialogId,
        request: &RawMessage<'_>,
        flow: Flow,
    ) -> bool {
        let exempt = match request.method() {
            Some(Method::Invite) => true,
            // only a BYE that will end the dialog: one numbered below what the
            // dialog has already seen is answered 500 by `reject_out_of_order`
            // and leaves the dialog, and this budget, exactly where they were
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
        let Some(state) = self.dialogs.get(dialog) else {
            return;
        };
        // §13.3.1.4: the ACK is the one "for the response", and a dialog only
        // a provisional has opened has had no 2xx to acknowledge. Its tag went
        // out in that provisional, so whoever saw the 180 can write this ACK,
        // and taking it would report a call that is still ringing as up. Every
        // 2xx this end sends confirms its dialog on the way out
        // (`open_uas_dialog`), so an ACK is never what confirms one.
        if state.state() != DialogState::Confirmed {
            return;
        }
        // §13.2.2.4 and §17.1.1.3: "The sequence number of the CSeq header
        // field MUST be the same as the INVITE being acknowledged." That is
        // the INVITE whose 2xx this end sent last, not the dialog's remote
        // sequence number, which a PRACK or an UPDATE arriving before the ACK
        // has already moved past it. An ACK naming an earlier INVITE is stale,
        // and one naming an INVITE whose ACK was already reported is a repeat;
        // both are absorbed.
        let Ok(cseq) = request.cseq() else {
            return;
        };
        if !self.dialogs.take_ack(dialog, cseq.seq) {
            return;
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

        // §8.2.2.2: a request with no To tag whose From tag, Call-ID and CSeq
        // already belong to an ongoing server transaction, under a branch
        // that does not itself match it, has reached this end by a second
        // path — almost always a fork. It is answered 482 on a transaction of
        // its own, and the call the first copy is opening is not touched by
        // it. A To tag, even one naming no dialog here, makes it §12.2.2's
        // case instead
        if existing.is_none() && self.transactions.merged_with(request) {
            self.refuse_merged_invite(request, flow, now);
            return;
        }
        // §8.1.1.8: "The Contact header field MUST be present and contain
        // exactly one SIP or SIPS URI in any request that can result in the
        // establishment of a dialog", and §12.1.1 takes the dialog's remote
        // target from nowhere else. An INVITE without one could be rung and
        // answered, and its 2xx would open no dialog for the ACK or a BYE to
        // find: the caller would hear a call connect that this end never
        // held. RFC 2543 did not require the field (RFC 4475 §3.4.1's
        // inv2543 has none), and a refusal that says so is the answer that
        // leaves both ends knowing where they stand
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
        // the room its dialog will take is held from here
        self.admitted.insert(id);
        self.push(Event::IncomingInvite {
            transaction: id,
            request: request.to_owned(),
        });
    }

    /// §8.2.2.2: answer a merged INVITE with 482, on a transaction of its
    /// own, without ever naming the call the first copy already opened.
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

    /// §8.1.1.8: answer an INVITE that names no `Contact` with a 400 that
    /// says so, on a transaction of its own so that its retransmissions are
    /// answered from it rather than refused afresh.
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
        // a CANCEL inside a dialog is one of that dialog's non-INVITE server
        // transactions like any other, and holds a place in its budget until
        // it retires, which on a stream is the answer just below
        if let Some(dialog) = DialogKey::as_uas(request)
            .ok()
            .and_then(|key| self.dialogs.find(&key))
        {
            self.dialogs.reserve_non_invite_transaction(dialog);
            self.remember_dialog(AnyTransactionId::NonInviteServer(cancel), dialog);
        }

        // §9.2 keeps the 200 for a CANCEL that "matched an existing
        // transaction", "regardless of the method of the original request":
        // "If the UAS did not find a matching transaction for the CANCEL
        // according to the procedure above, it SHOULD respond to the CANCEL
        // with a 481". The transaction is found by §17.2.3's rules, with the
        // CANCEL's own branch and sent-by and any method but CANCEL or ACK
        let owned = request.to_owned();
        let Some(matched) = self.transactions.cancelled_by(request) else {
            self.answer(cancel, &owned, StatusCode::CALL_DOES_NOT_EXIST, now);
            return;
        };
        // §9.2: "The To tag of the response to the CANCEL and the To tag in
        // the response to the original request SHOULD be the same." Every
        // server transaction is given its tag when it arrives, so this is the
        // one its 180 carried and its 487 below will; minting the CANCEL a
        // tag of its own gave the far end two names for one dialog
        let original = match matched {
            Server::Invite(id) => AnyTransactionId::InviteServer(id),
            Server::NonInvite(id) => AnyTransactionId::NonInviteServer(id),
        };
        let tag = self.tag_or_mint(original);
        self.remember_tag(AnyTransactionId::NonInviteServer(cancel), tag);
        self.answer(cancel, &owned, StatusCode::OK, now);
        // "A CANCEL request has no impact on the processing of transactions
        // with any other method defined in this specification"
        let Server::Invite(invite) = matched else {
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
        // §9.2: a CANCEL that reaches an INVITE already given its final
        // response has "no effect on any session state", so there is nothing
        // to report. Reporting it anyway told the layer above that a call
        // which is up had been given up on.
        if !refused {
            return;
        }
        // RFC 3262 §3: after a final response a reliable provisional "SHOULD
        // NOT" go on being retransmitted, though a PRACK for it is still owed
        // an answer
        self.quiet_reliable(invite);
        self.push(Event::IncomingCancel { invite });
        // after the CANCEL is reported, so that what the caller hears first is
        // why the call ended rather than that its dialog did
        self.admitted.remove(&invite);
        self.end_refused_early(invite, early);
    }

    /// What [`super::EndpointConfig::max_dialogs`] is measured against: the
    /// dialogs held, and the calls let in that are still to open theirs.
    pub(super) fn dialogs_held(&self) -> usize {
        self.dialogs.len().saturating_add(self.admitted.len())
    }

    /// The early dialog an INVITE of theirs opened, if it opened one.
    ///
    /// §12.3: "if a request outside of a dialog generates a non-2xx final
    /// response, any early dialogs created through provisional responses to
    /// that request are terminated." Read before the refusal goes out, while
    /// the transaction is certain to be there. Only the request that created
    /// the dialog counts. One sent inside the dialog names it already, by the
    /// tag this end put in `To`, and a re-INVITE refused there leaves the
    /// dialog standing, exactly as a refused UPDATE does on the calling side.
    /// Any other tag in `To` names a dialog this end does not have: the INVITE
    /// carrying it was taken as a new call (§12.2.2), and it is what created
    /// the early dialog. The dialog is named by the tag this end put on the
    /// transaction's responses.
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

    /// End the early dialog [`Endpoint::early_dialog_of`] found, now that the
    /// INVITE that opened it has been refused.
    ///
    /// Without this an INVITE that rang and was cancelled left its dialog
    /// standing for the life of the process, and a peer that repeated the
    /// pair filled `max_dialogs` and had every later call refused.
    ///
    /// Not while a reliable provisional response of that INVITE is still
    /// unacknowledged. RFC 3262 §3 has a UAS that refuses with one outstanding
    /// stay "prepared to process PRACK requests for those outstanding
    /// responses", and a PRACK is matched inside the dialog. The dialog then
    /// ends with the INVITE transaction, which retiring it sees to, so it is
    /// held for no longer than the transaction is.
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
        // §8.2.2.2 for every method, as `on_invite` asks it for an INVITE:
        // read before this request's own transaction joins the index
        let merged = dialog.is_none() && self.transactions.merged_with(request);

        let timers = self.config.timers;
        let Ok(id) = self
            .transactions
            .start_non_invite_server(request, flow, timers)
        else {
            return;
        };
        // §17.2.2 gives Trying/Proceeding no timer of its own; this is the
        // endpoint's, `non_invite_app_timeout` is a no-op against whatever
        // already answered it by the time it fires, and retiring the
        // transaction first takes it off the schedule
        let deadline = self.schedule(
            now + timers.sixty_four_t1(),
            Deadline::UnansweredNonInvite(id),
        );
        self.unanswered.insert(id, deadline);
        if let Some(dialog) = dialog {
            self.dialogs.reserve_non_invite_transaction(dialog);
            self.remember_dialog(AnyTransactionId::NonInviteServer(id), dialog);
        }
        // a second copy of a request already being processed is answered
        // here, on a transaction of its own, and never handed up
        if merged {
            self.answer(id, &request.to_owned(), StatusCode::LOOP_DETECTED, now);
            return;
        }

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
        let before = self
            .dialogs
            .get(dialog)
            .map(|state| state.remote_target().as_str().to_owned());
        let out_of_order = self
            .dialogs
            .get_mut(dialog)
            .is_some_and(|state| state.on_request(request) == Ok(Incoming::OutOfOrder));
        // §12.2.2's ordering check runs before the target-refresh mutation,
        // so an out-of-order request never reaches it and this is a no-op
        // for one; a target refresh that was accepted asks the caller to
        // resolve exactly as a 2xx to one does (§12.2.1.2).
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
                    // read before applying: retiring a non-INVITE client
                    // transaction forgets which dialog it was inside
                    let dialog = over.then(|| self.dialog_of(id)).flatten();
                    self.apply_again(effects, flow, id);
                    if over {
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

    /// 64·T1 after a non-INVITE server transaction was created, still with no
    /// final response of its own: §17.2.2 gives `Trying`/`Proceeding` no timer
    /// at all, so an application that never answers would otherwise hold the
    /// slot forever, and past `max_server_transactions` of those every
    /// stranger gets 503 for it. The client gave this request up by now
    /// anyway — its own Timer F is the same 64·T1 (§17.1.2.2) — so the
    /// endpoint answers 408 on the application's behalf and lets the
    /// transaction retire the ordinary way.
    ///
    /// A no-op against a transaction that already has a final response, by
    /// the application or by this endpoint on some other path. Retiring the
    /// transaction takes the deadline off the schedule, but one answered on a
    /// datagram transport is still live, in `Completed`, when it fires.
    pub(super) fn non_invite_app_timeout(
        &mut self,
        id: TransactionId<NonInviteServer>,
        now: Instant,
    ) {
        // the deadline that brought this here is off the schedule already
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
        self.note(
            call.as_ref().map(CallId::as_bytes),
            Decision::of(Reason::RequestAnsweredByTimeout)
                .at_address(flow.destination)
                .over(flow.protocol),
        );
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
        // read before applying, same as `renegotiated`: retiring a non-INVITE
        // client transaction forgets which dialog it was inside
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
                // an early dialog a refusal left standing for the PRACKs
                // RFC 3262 §3 still expects goes with the transaction; read
                // while the transaction and its tag are still here
                let early = self.early_dialog_of(inner);
                self.forget_reliable_on(inner);
                self.reinvites.answered_theirs(id);
                // a call that ends unanswered gives its room back too
                self.admitted.remove(&inner);
                self.end_refused_early(inner, early);
                self.transactions.release_invite_merge(inner);
                self.transactions.drop_invite_server(inner);
            }
            AnyTransactionId::NonInviteServer(inner) => {
                // give the per-dialog budget its place back, for a
                // transaction that was ever admitted into one
                if let Some(dialog) = self.dialog_of(id) {
                    self.dialogs.release_non_invite_transaction(dialog);
                }
                // and the schedule the deadline an unanswered one would have
                // been given its 408 by
                if let Some(deadline) = self.unanswered.remove(&inner) {
                    self.deadlines.cancel(deadline);
                }
                self.reinvites.answered_theirs(id);
                self.transactions.release_non_invite_merge(inner);
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
        for id in self.dialogs.branches_of(set) {
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
        // §9.1 has a CANCEL retransmitted by its own transaction. One that is
        // already running carries this branch and this method, and a second
        // under that key would take its responses and leave it retransmitting
        // until timer F reported it failed
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

/// Where bytes the parser refused came from: what an answer to them is
/// routed from, before their own `Via` has had its say.
#[derive(Clone, Copy)]
struct Arrival {
    transport: super::TransportId,
    remote: SocketAddr,
    local: Option<SocketAddr>,
    protocol: super::TransportProtocol,
}

/// Whether what [`salvage_request`] recovered is enough to answer: a request
/// that is not an ACK, with a top `Via` that reads and is inside the bound on
/// one value.
///
/// The top `Via` is what routes the answer (§18.2.2) — its `maddr`, its port —
/// and one past the bound is a field the parser refused, or would have had it
/// got that far: nothing read from it decides where this end sends anything.
/// `From`, `To`, `Call-ID` and `CSeq` go back whole whatever their length,
/// since they only have to match, and an answer goes without any of them the
/// request did not carry.
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

/// The name of the field starting at `at`, as the peer wrote it, when it can
/// go in a reason phrase as it stands: short, and nothing in it the phrase's
/// grammar would have to escape (§25.1). `Header` otherwise.
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

/// Whether a request names somewhere a dialog it opens could send to: a
/// `Contact` with an address in it. `*` is REGISTER's alone (§10.2.2) and
/// names nowhere.
fn names_a_contact(request: &RawMessage<'_>) -> bool {
    match request.contact() {
        Ok(Contacts::Addrs(mut addrs)) => addrs.next().is_some_and(|addr| addr.is_ok()),
        Ok(Contacts::Star) | Err(_) => false,
    }
}
