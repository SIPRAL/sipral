// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The endpoint itself.
//!
//! Five calls, and the shape of them is the whole design. `receive` takes
//! bytes and a time. `handle_timeout` takes a time on its own, because a
//! caller woken by a deadline has no bytes in hand. `poll_transmit` and
//! `poll_event` are drained to empty afterwards, and `poll_timeout` says when
//! to come back. Nothing blocks, nothing allocates a socket, nothing reads a
//! clock.
//!
//! What the endpoint fills in is what a caller must not be allowed to get
//! wrong: the branch, the sent-by, the sequence numbers, the tags, the
//! retransmissions, the ACK for a failed INVITE, and which of several forked
//! answers a message belongs to. What it refuses to decide is policy — which
//! fork to keep, when to give up on a ringing phone, whether to answer a
//! challenge — because a core that decides those is a core the layer above
//! has to fight.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use super::config::EndpointConfig;
use super::dialogs::Dialogs;
use super::error::{AckError, CancelError, ReceiveError, RespondError, SendError};
use super::event::Event;
use super::outgoing::{Extra, OutgoingInDialogRequest, OutgoingRequest, OutgoingResponse};
use super::table::{Flow, Transports};
use super::tokens::Tokens;
use super::transport::{Input, Transmit, TransportId, TransportProtocol};
use super::via;
use crate::dialog::{CallId, DialogSet, DialogState, InDialogRequest};
use crate::msg::{Method, OwnedMessage, ParseScratch, RequestBuilder, ResponseBuilder, StatusCode};
use crate::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteClient, NonInviteServer,
    TransactionId, TransactionKind, Transactions,
};
use crate::transaction::{TimerHandle, Timers};

/// Something that is neither a transaction nor a dialog, and still has to
/// happen at a particular time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Deadline {
    /// A double CRLF is due on a byte stream (RFC 5626 §4.4.1).
    Keepalive(TransportId),
}

/// One SIP endpoint: everything in flight, and nothing that does I/O.
#[derive(Debug)]
pub struct Endpoint {
    pub(super) config: EndpointConfig,
    pub(super) tokens: Tokens,
    pub(super) transports: Transports,
    pub(super) transactions: Transactions,
    pub(super) dialogs: Dialogs,
    pub(super) deadlines: Timers<Deadline>,
    pub(super) transmits: VecDeque<Transmit>,
    pub(super) events: VecDeque<Event>,
    /// Reused across calls, so that receiving a datagram allocates nothing.
    pub(super) scratch: ParseScratch,
    /// Reused too: the transactions whose timers are due, or whose transport
    /// has failed.
    pub(super) hit: Vec<AnyTransactionId>,
    /// The tag this end put in `To` for each server transaction. Every
    /// response of one transaction has to carry the same one (§8.2.6.2), and
    /// several of them may be sent.
    pub(super) local_tags: HashMap<AnyTransactionId, Box<[u8]>>,
    /// The INVITEs a CANCEL has gone out for, so that a 487 can be told from
    /// an ordinary refusal and a 2xx from a race that was lost.
    pub(super) cancelled: HashSet<TransactionId<InviteClient>>,
}

impl Endpoint {
    /// A new endpoint.
    ///
    /// `seed` is thirty-two bytes of entropy, and every branch, tag,
    /// `Call-ID` and `cnonce` this endpoint ever writes is derived from it.
    /// It is the caller's to supply for the same reason the clock and the
    /// sockets are: a library that reaches for `/dev/urandom` on its own is a
    /// library that cannot be run where the caller needs it. Two endpoints
    /// must never be given the same seed.
    #[must_use]
    pub fn new(config: EndpointConfig, seed: [u8; 32]) -> Self {
        Self {
            config,
            tokens: Tokens::new(seed),
            transports: Transports::new(),
            transactions: Transactions::new(),
            dialogs: Dialogs::new(),
            deadlines: Timers::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            scratch: ParseScratch::new(),
            hit: Vec::new(),
            local_tags: HashMap::new(),
            cancelled: HashSet::new(),
        }
    }

    /// Bytes, or news about a transport.
    ///
    /// # Errors
    /// [`ReceiveError`] when the transport is unknown or the bytes are not a
    /// message. Neither is a fault of this endpoint: a malformed datagram is
    /// the normal case on a public SIP port, and the caller logs it and
    /// carries on. On a byte stream it is fatal to the connection, which the
    /// endpoint has already forgotten by the time the error is returned.
    pub fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        match input {
            Input::TransportBound {
                transport,
                protocol,
                local,
                remote,
            } => {
                self.transports
                    .bind(transport, protocol, local, remote, self.config.limits);
                self.arm_keepalives(now);
                Ok(())
            }
            Input::TransportFailed { transport, .. } | Input::StreamClosed { transport } => {
                self.lose_transport(transport);
                Ok(())
            }
            Input::Datagram {
                transport,
                remote,
                local,
                data,
            } => self.on_datagram(transport, remote, local, data, now),
            Input::StreamData { transport, data } => self.on_stream(transport, data, now),
        }
    }

    /// Time has passed.
    pub fn handle_timeout(&mut self, now: Instant) {
        while let Some(deadline) = self.deadlines.fire(now) {
            match deadline {
                Deadline::Keepalive(transport) => self.send_keepalive(transport, now),
            }
        }

        // firing one timer can arm another, and a caller that comes back late
        // has several rounds to work through
        loop {
            self.transactions.due(now, &mut self.hit);
            if self.hit.is_empty() {
                return;
            }
            let due = core::mem::take(&mut self.hit);
            for id in &due {
                self.fire_transaction(*id, now);
            }
            self.hit = due;
        }
    }

    /// Bytes to put on a transport. Drain to empty.
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Something the layer above has to know. Drain to empty.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When to call [`Endpoint::handle_timeout`], if nothing arrives first.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        match (
            self.transactions.next_deadline(),
            self.deadlines.next_deadline(),
        ) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    /// The state of a transaction, or `None` if the handle has gone stale.
    #[must_use]
    pub fn transaction_state<K: TransactionKind>(&self, id: TransactionId<K>) -> Option<K::State> {
        K::state_of(self, id)
    }

    /// What is known about a dialog.
    #[must_use]
    pub fn dialog(&self, id: DialogId) -> Option<DialogSnapshot> {
        let dialog = self.dialogs.get(id)?;
        Some(DialogSnapshot {
            state: dialog.state(),
            call_id: dialog.key().call_id().clone(),
            local_tag: dialog.key().local_tag().clone(),
            remote_tag: dialog.key().remote_tag().cloned(),
            local_seq: dialog.local_seq(),
            remote_seq: dialog.remote_seq(),
            route_set: Arc::from(dialog.route_set()),
            remote_target: dialog.remote_target().clone(),
            secure: dialog.is_secure(),
        })
    }

    /// How many transactions and dialogs are live, for a caller that wants to
    /// know whether it can shut down.
    #[must_use]
    pub fn in_flight(&self) -> (usize, usize) {
        (self.transactions.len(), self.dialogs.len())
    }

    pub(crate) const fn store(&self) -> &Transactions {
        &self.transactions
    }

    /// Queue bytes for the caller to write.
    pub(super) fn queue(&mut self, transmit: Transmit) {
        self.transmits.push_back(transmit);
    }

    /// Queue something for the caller to know.
    pub(super) fn push(&mut self, event: Event) {
        self.events.push_back(event);
    }

    /// Hang a deadline that is not a transaction's.
    pub(super) fn schedule(&mut self, at: Instant, deadline: Deadline) -> TimerHandle {
        self.deadlines.schedule(at, deadline)
    }

    /// Where a transaction's messages go, or nowhere if it has gone.
    pub(super) fn flow_of(&self, id: AnyTransactionId) -> Flow {
        let flow = match id {
            AnyTransactionId::InviteClient(inner) => {
                self.transactions.invite_client(inner).map(|e| e.flow)
            }
            AnyTransactionId::NonInviteClient(inner) => {
                self.transactions.non_invite_client(inner).map(|e| e.flow)
            }
            AnyTransactionId::InviteServer(inner) => {
                self.transactions.invite_server(inner).map(|e| e.flow)
            }
            AnyTransactionId::NonInviteServer(inner) => {
                self.transactions.non_invite_server(inner).map(|e| e.flow)
            }
        };
        flow.unwrap_or(NOWHERE)
    }

    /// A tag nobody can guess, for `To` or `From`.
    pub(super) fn mint_tag(&mut self) -> Box<[u8]> {
        self.tokens.token()
    }

    /// Remember the tag this end used on a server transaction.
    pub(super) fn remember_tag(&mut self, id: AnyTransactionId, tag: Box<[u8]>) {
        if !tag.is_empty() {
            self.local_tags.insert(id, tag);
        }
    }

    /// The tag this end used on a server transaction.
    pub(super) fn tag_for(&self, id: AnyTransactionId) -> Option<Box<[u8]>> {
        self.local_tags.get(&id).cloned()
    }

    pub(super) fn forget_tag(&mut self, id: AnyTransactionId) {
        self.local_tags.remove(&id);
    }

    pub(super) fn remember_cancelled(&mut self, id: TransactionId<InviteClient>) {
        self.cancelled.insert(id);
    }

    pub(super) fn was_cancelled(&self, id: TransactionId<InviteClient>) -> bool {
        self.cancelled.contains(&id)
    }

    pub(super) fn forget_cancelled(&mut self, id: TransactionId<InviteClient>) {
        self.cancelled.remove(&id);
    }
}

/// A response with nothing in it but a status and a tag.
pub(super) fn assemble_response(
    request: &OwnedMessage,
    status: StatusCode,
    tag: Option<&[u8]>,
) -> Result<OwnedMessage, RespondError> {
    let raw = request.as_raw();
    let mut builder = ResponseBuilder::for_request(&raw, status);
    if let Some(tag) = tag {
        builder = builder.to_tag(tag);
    }
    Ok(builder.build()?)
}

/// The flow of a transaction that is no longer there.
///
/// Reaching for it means a machine asked to send after it was dropped, which
/// cannot happen; the address is one RFC 5737 reserves for documentation, so
/// a packet that somehow went out would be visible in a capture rather than
/// delivered to somebody real.
const NOWHERE: Flow = Flow {
    transport: TransportId(u32::MAX),
    destination: SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 0)),
        0,
    ),
    source: None,
    protocol: TransportProtocol::Udp,
};

/// What a dialog looks like from outside.
///
/// Both sequence numbers are optional, and for the same reason: §12.1.1 and
/// §12.1.2 each leave one of them empty at creation, because a dialog only has
/// a number in a direction once something has been sent in it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DialogSnapshot {
    /// Early, confirmed or over.
    pub state: DialogState,
    /// The `Call-ID` all three of its identifiers share.
    pub call_id: CallId,
    /// Our tag.
    pub local_tag: crate::dialog::Tag,
    /// Theirs, absent for a peer that predates RFC 3261.
    pub remote_tag: Option<crate::dialog::Tag>,
    /// The number of the last request we sent in it.
    pub local_seq: Option<u32>,
    /// The number of the last request they sent in it.
    pub remote_seq: Option<u32>,
    /// The proxies that asked to stay on the path.
    pub route_set: Arc<[crate::msg::Uri]>,
    /// Where the far end actually lives.
    pub remote_target: crate::msg::Uri,
    /// Whether §12.1's secure flag is set.
    pub secure: bool,
}

// -- sending ----------------------------------------------------------------

impl Endpoint {
    /// Send a request that starts something: REGISTER, OPTIONS, SUBSCRIBE,
    /// MESSAGE, anything out of dialog that is not an INVITE.
    ///
    /// # Errors
    /// [`SendError`] when a field is missing, the transport is unknown, or
    /// the request is too large for a datagram and there is nothing else open.
    pub fn request(
        &mut self,
        request: &OutgoingRequest,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        let (message, flow) = self.build_request(request)?;
        let (id, effects) =
            self.transactions
                .start_non_invite_client(message, flow, self.config.timers, now)?;
        self.apply_client(effects, flow);
        Ok(id)
    }

    /// Place a call.
    ///
    /// # Errors
    /// As [`Endpoint::request`].
    pub fn invite(
        &mut self,
        request: &OutgoingRequest,
        now: Instant,
    ) -> Result<TransactionId<InviteClient>, SendError> {
        let (message, flow) = self.build_request(request)?;
        let secure = flow.protocol.is_secure();
        let set = DialogSet::new(message.clone(), secure);
        let (id, effects) =
            self.transactions
                .start_invite_client(message, flow, self.config.timers, now)?;
        self.dialogs.watch(set, id);
        self.apply_client(effects, flow);
        Ok(id)
    }

    /// Give up on a call that has not been answered (§9.1).
    ///
    /// Always accepted while the transaction is live. A CANCEL may not go
    /// before a provisional response has arrived — the server could otherwise
    /// receive it before the INVITE and have nothing to cancel — so one asked
    /// for too early is held and released at the first provisional. The caller
    /// never has to time that itself; [`Event::CancelSent`] says when it went.
    ///
    /// # Errors
    /// [`CancelError`] when the transaction is unknown, or has already been
    /// answered with a final response.
    pub fn cancel(
        &mut self,
        invite: TransactionId<InviteClient>,
        now: Instant,
    ) -> Result<(), CancelError> {
        let Some(entry) = self.transactions.invite_client_mut(invite) else {
            return Err(CancelError::NoSuchTransaction);
        };
        match entry.machine.request_cancel() {
            crate::transaction::CancelDisposition::Deferred => Ok(()),
            crate::transaction::CancelDisposition::Now => self.send_cancel(invite, now),
            crate::transaction::CancelDisposition::TooLate => Err(CancelError::AlreadyAnswered),
        }
    }

    /// Acknowledge a 2xx (§13.2.2.4).
    ///
    /// Called once. The ACK may carry the answer when the offer came in the
    /// 2xx, which is why the caller builds it rather than the endpoint, and
    /// why the endpoint cannot know when it is ready. After this the ACK
    /// belongs to the dialog: every retransmitted 2xx is answered with the
    /// same bytes, and the caller hears nothing more about it.
    ///
    /// # Errors
    /// [`AckError`] when the dialog is unknown, has no 2xx to acknowledge, or
    /// has already been acknowledged.
    pub fn ack_2xx(
        &mut self,
        dialog: DialogId,
        answer: Option<&[u8]>,
        _now: Instant,
    ) -> Result<(), AckError> {
        let Some(set) = self.dialogs.branch_set(dialog) else {
            return Err(AckError::NotOurCall);
        };
        let Some(flow) = self.dialogs.flow(dialog) else {
            return Err(AckError::NoSuchDialog);
        };
        let Some(key) = self.dialogs.get(dialog).map(|d| d.key().clone()) else {
            return Err(AckError::NoSuchDialog);
        };
        let Some(branches) = self.dialogs.set(set) else {
            return Err(AckError::NoSuchDialog);
        };
        if branches.ack_for(&key).is_some() {
            return Err(AckError::AlreadyAcknowledged);
        }
        let plan = branches.ack_2xx(&key).map_err(|_| AckError::NotAnswered)?;
        let ack = self.build_in_dialog(&plan, flow, None, answer)?;
        if let Some(branches) = self.dialogs.set_mut(set) {
            branches.keep_ack(&key, ack.clone()).ok();
        }
        self.transmits.push_back(flow.transmit(ack.bytes()));
        Ok(())
    }

    /// Hang up (§15.1.1).
    ///
    /// # Errors
    /// As [`Endpoint::request_in_dialog`].
    pub fn bye(
        &mut self,
        dialog: DialogId,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        let id = self.request_in_dialog(dialog, &OutgoingInDialogRequest::new(Method::Bye), now)?;
        // §15.1.1: "The UAC MUST consider the session terminated ... as soon
        // as the BYE request is passed to the client transaction." Whether the
        // far end answers it changes nothing here
        if let Some(state) = self.dialogs.get_mut(dialog) {
            state.terminate();
        }
        self.forget_dialog(dialog, super::event::DialogEndReason::LocalBye);
        Ok(id)
    }

    /// Send a request inside a dialog: BYE, INFO, NOTIFY, UPDATE, REFER.
    ///
    /// The Request-URI, the route set, both addresses with their tags, the
    /// `Call-ID` and the sequence number all come from the dialog (§12.2.1.1),
    /// including the rewrite that makes a request routable through a proxy
    /// which predates loose routing.
    ///
    /// # Errors
    /// [`SendError`] when the dialog is unknown or the request cannot be
    /// built.
    pub fn request_in_dialog(
        &mut self,
        dialog: DialogId,
        request: &OutgoingInDialogRequest,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        let flow = self.dialogs.flow(dialog).ok_or(SendError::NoSuchDialog)?;
        let plan = self
            .dialogs
            .get_mut(dialog)
            .ok_or(SendError::NoSuchDialog)?
            .next_request(request.method())
            .map_err(SendError::Dialog)?;
        let message = self.build_in_dialog(&plan, flow, Some(request), request.body.as_deref())?;
        let (id, effects) =
            self.transactions
                .start_non_invite_client(message, flow, self.config.timers, now)?;
        self.apply_client(effects, flow);
        Ok(id)
    }

    /// Renegotiate inside a confirmed dialog: hold, resume, a codec change.
    ///
    /// # Errors
    /// As [`Endpoint::request_in_dialog`].
    pub fn reinvite(
        &mut self,
        dialog: DialogId,
        offer: Option<Arc<[u8]>>,
        now: Instant,
    ) -> Result<TransactionId<InviteClient>, SendError> {
        let flow = self.dialogs.flow(dialog).ok_or(SendError::NoSuchDialog)?;
        let mut request = OutgoingInDialogRequest::new(Method::Invite);
        if let Some(offer) = offer {
            request = request.body(b"application/sdp", offer);
        }
        let plan = self
            .dialogs
            .get_mut(dialog)
            .ok_or(SendError::NoSuchDialog)?
            .next_request(Method::Invite)
            .map_err(SendError::Dialog)?;
        let message = self.build_in_dialog(&plan, flow, Some(&request), request.body.as_deref())?;
        let (id, effects) =
            self.transactions
                .start_invite_client(message, flow, self.config.timers, now)?;
        self.apply_client(effects, flow);
        Ok(id)
    }

    /// Answer a request that is not an INVITE.
    ///
    /// # Errors
    /// [`RespondError`] when the transaction is unknown or has already sent a
    /// final response.
    pub fn respond(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        response: &OutgoingResponse,
        now: Instant,
    ) -> Result<(), RespondError> {
        let entry = self
            .transactions
            .non_invite_server(transaction)
            .ok_or(RespondError::NoSuchTransaction)?;
        let flow = entry.flow;
        let request = entry.request.clone();
        let tag = self.tag_or_mint(AnyTransactionId::NonInviteServer(transaction));
        let message = build_response(&request, response, Some(&tag))?;
        let entry = self
            .transactions
            .non_invite_server_mut(transaction)
            .ok_or(RespondError::NoSuchTransaction)?;
        let effects = entry.machine.respond(message, now);
        if effects.send.is_none() {
            return Err(RespondError::TooLate);
        }
        self.apply(
            effects,
            flow,
            AnyTransactionId::NonInviteServer(transaction),
        );
        Ok(())
    }

    /// Answer an INVITE.
    ///
    /// A 2xx opens the dialog and hands it back; anything else does not. The
    /// endpoint keeps retransmitting a non-2xx final response until the ACK
    /// arrives (§17.2.1), and absorbs retransmissions of the INVITE after a
    /// 2xx (RFC 6026 §8.1) — but the 2xx itself is the caller's to repeat,
    /// because only the caller knows whether the answer it carried is still
    /// the answer.
    ///
    /// # Errors
    /// [`RespondError`] when the transaction is unknown or has already
    /// answered.
    pub fn respond_invite(
        &mut self,
        transaction: TransactionId<InviteServer>,
        response: &OutgoingResponse,
        now: Instant,
    ) -> Result<Option<DialogId>, RespondError> {
        let entry = self
            .transactions
            .invite_server(transaction)
            .ok_or(RespondError::NoSuchTransaction)?;
        let flow = entry.flow;
        let request = entry.request.clone();
        let status = response.status;

        let tag = match response.to_tag {
            Some(ref chosen) => {
                self.remember_tag(AnyTransactionId::InviteServer(transaction), chosen.clone());
                chosen.clone()
            }
            None => self.tag_or_mint(AnyTransactionId::InviteServer(transaction)),
        };
        let message = build_response(&request, response, Some(&tag))?;

        // §12.1.1: only a 101-199 or a 2xx opens a dialog. A 100 names
        // nothing, and a failure ends whatever was already open
        let opens = status.get() >= 101 && (status.is_provisional() || status.is_success());
        let dialog = opens
            .then(|| self.open_uas_dialog(&request, &tag, status, flow))
            .flatten();

        let entry = self
            .transactions
            .invite_server_mut(transaction)
            .ok_or(RespondError::NoSuchTransaction)?;
        let effects = entry.machine.respond(message, now);
        if effects.send.is_none() {
            return Err(RespondError::TooLate);
        }
        self.apply(effects, flow, AnyTransactionId::InviteServer(transaction));
        Ok(dialog)
    }
}

// -- building ---------------------------------------------------------------

impl Endpoint {
    /// Turn what the caller described into bytes, and decide where they go.
    fn build_request(
        &mut self,
        request: &OutgoingRequest,
    ) -> Result<(OwnedMessage, Flow), SendError> {
        let to = request.to.as_deref().ok_or(SendError::MissingField("To"))?;
        let from = request
            .from
            .as_deref()
            .ok_or(SendError::MissingField("From"))?;

        let bound = self
            .transports
            .get(request.transport)
            .ok_or(SendError::UnknownTransport)?;
        let mut flow = Flow {
            transport: request.transport,
            destination: request.remote,
            source: None,
            protocol: bound.protocol,
        };
        let mut local = bound.local;

        // 8.1.1.3: a request has to carry a From tag, and picking an
        // unguessable one is not something a caller should have to do
        let tagged;
        let from = if has_tag(from) {
            from
        } else {
            tagged = with_tag(from, &self.tokens.token());
            &tagged
        };
        let call_id = match request.call_id {
            Some(ref id) => Box::from(id.as_bytes()),
            None => self.tokens.token(),
        };
        let branch = self.tokens.branch();
        let cseq = request.cseq.unwrap_or(1);

        let mut message =
            self.assemble(request, &flow, local, &branch, from, to, &call_id, cseq)?;

        // 18.1.1: too large for a datagram means it leaves over something
        // congestion controlled, and the Via has to say so
        if !flow.protocol.is_reliable()
            && self
                .config
                .datagram_limit
                .too_big_for_a_datagram(message.len())
        {
            let Some(stream) = self.transports.any_speaking(TransportProtocol::Tcp) else {
                self.events.push_back(Event::TransportWanted {
                    protocol: TransportProtocol::Tcp,
                    destination: request.remote,
                });
                return Err(SendError::NeedsStreamTransport);
            };
            let bound = self
                .transports
                .get(stream)
                .ok_or(SendError::UnknownTransport)?;
            flow = Flow {
                transport: stream,
                destination: bound.remote.unwrap_or(request.remote),
                source: None,
                protocol: bound.protocol,
            };
            local = bound.local;
            message = self.assemble(request, &flow, local, &branch, from, to, &call_id, cseq)?;
        }

        Ok((message, flow))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "assembling a request needs every field of one, and grouping them into a struct would only move the list"
    )]
    fn assemble(
        &self,
        request: &OutgoingRequest,
        flow: &Flow,
        local: SocketAddr,
        branch: &[u8],
        from: &[u8],
        to: &[u8],
        call_id: &[u8],
        cseq: u32,
    ) -> Result<OwnedMessage, SendError> {
        let via = via::local_via(
            flow.protocol,
            local,
            branch,
            self.config.always_request_rport,
        );
        let method =
            Method::from_bytes(&request.method).ok_or(SendError::MissingField("method"))?;
        let mut builder = RequestBuilder::new(method, request.request_uri.as_bytes())
            .via(&via)
            .from(from)
            .to(to)
            .call_id(call_id)
            .cseq(cseq)
            .max_forwards(request.max_forwards);
        for hop in &request.route {
            builder = builder.route(hop);
        }
        if let Some(ref contact) = request.contact {
            builder = builder.contact(contact);
        }
        builder = add_extra(builder, &request.extra);
        if let (Some(kind), Some(body)) = (request.content_type.as_deref(), request.body.as_deref())
        {
            builder = builder.body(kind, body);
        }
        Ok(builder.build()?)
    }

    /// Finish a request the dialog has already decided everything about.
    fn build_in_dialog(
        &mut self,
        plan: &InDialogRequest,
        flow: Flow,
        extra: Option<&OutgoingInDialogRequest>,
        body: Option<&[u8]>,
    ) -> Result<OwnedMessage, SendError> {
        let bound = self
            .transports
            .get(flow.transport)
            .ok_or(SendError::UnknownTransport)?;
        let local = bound.local;
        let branch = self.tokens.branch();
        let via = via::local_via(
            flow.protocol,
            local,
            &branch,
            self.config.always_request_rport,
        );

        let mut builder = plan
            .builder()
            .via(&via)
            .max_forwards(extra.map_or(70, |extra| extra.max_forwards));
        if let Some(extra) = extra {
            if let Some(ref contact) = extra.contact {
                builder = builder.contact(contact);
            }
            builder = add_extra(builder, &extra.extra);
            if let (Some(kind), Some(body)) = (extra.content_type.as_deref(), body) {
                builder = builder.body(kind, body);
            }
        } else if let Some(body) = body {
            // the ACK for a 2xx, carrying the answer to an offer that arrived
            // in the response
            builder = builder.body(b"application/sdp", body);
        }
        Ok(builder.build()?)
    }
}

fn build_response(
    request: &OwnedMessage,
    response: &OutgoingResponse,
    tag: Option<&[u8]>,
) -> Result<OwnedMessage, RespondError> {
    let raw = request.as_raw();
    let mut builder = ResponseBuilder::for_request(&raw, response.status);
    // 8.2.6.2 makes a tag mandatory on every response but a 100, and every
    // response of one transaction has to carry the same one
    if let Some(tag) = tag.filter(|_| response.status != StatusCode::TRYING) {
        builder = builder.to_tag(tag);
    }
    if let Some(ref reason) = response.reason {
        builder = builder.reason(reason);
    }
    if let Some(ref contact) = response.contact {
        builder = builder.contact(contact);
    }
    // a dialog-creating response has to carry the path back (§12.1.1)
    if response.status.is_provisional() || response.status.is_success() {
        builder = builder.copy_record_route(&raw);
    }
    for extra in &response.extra {
        if let Some((name, value)) = extra.parts() {
            builder = builder.header(name, value);
        }
    }
    if let (Some(kind), Some(body)) = (response.content_type.as_deref(), response.body.as_deref()) {
        builder = builder.body(kind, body);
    }
    Ok(builder.build()?)
}

fn add_extra<'a>(mut builder: RequestBuilder<'a>, extra: &'a [Extra]) -> RequestBuilder<'a> {
    for one in extra {
        if let Some((name, value)) = one.parts() {
            builder = builder.header(name, value);
        }
    }
    builder
}

/// Whether a `From` or `To` value already carries a tag.
fn has_tag(value: &[u8]) -> bool {
    crate::msg::NameAddrRef::parse(value).is_ok_and(|addr| addr.tag().is_some())
}

/// The same value with a tag on the end.
fn with_tag(value: &[u8], tag: &[u8]) -> Box<[u8]> {
    let mut out = Vec::with_capacity(value.len() + tag.len() + 5);
    out.extend_from_slice(value);
    out.extend_from_slice(b";tag=");
    out.extend_from_slice(tag);
    out.into_boxed_slice()
}
