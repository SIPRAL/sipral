// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The endpoint itself: `receive` and `handle_timeout` feed it, `poll_transmit`, `poll_event` and
//! `poll_timeout` drain it. It never blocks, opens a socket or reads a clock.
//!
//! It fills in what a caller must not get wrong (branches, tags, sequence numbers, retransmissions,
//! the ACK for a failed INVITE, fork matching) and leaves policy to the layer above.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use super::auth::{Challenges, Known};
use super::config::EndpointConfig;
use super::dialogs::Dialogs;
use super::error::{AckError, CancelError, ReceiveError, RespondError, SendError};
use super::event::Event;
use super::outgoing::{Extra, OutgoingInDialogRequest, OutgoingRequest, OutgoingResponse};
use super::reinvite::Reinvites;
use super::reliable::Reliables;
use super::table::{Flow, Transports};
use super::tokens::Tokens;
use super::transport::{Input, Transmit, TransportId, TransportProtocol};
use super::via;
use crate::auth::{Answered, Credentials};
use crate::diag::{Decision, Direction, Reason, Records};
use crate::dialog::{CallId, DialogSet, DialogState, InDialogRequest};
use crate::msg::{
    BuildError, HeaderName, Method, OwnedMessage, ParseScratch, RequestBuilder, ResponseBuilder,
    StatusCode,
};
use crate::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteClient, NonInviteServer,
    TimerConfigError, TransactionId, TransactionKind, Transactions,
};
use crate::transaction::{Raw, TimerHandle, Timers};

/// A deadline that belongs to neither a transaction nor a dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Deadline {
    /// A double CRLF is due on a byte stream (RFC 5626 §4.4.1).
    Keepalive(TransportId),
    /// A ping has gone unanswered long enough that §4.4.1 calls the flow dead.
    PongOverdue(TransportId),
    /// A reliable provisional response has to go out again (RFC 3262 §3).
    Reliable(Raw),
    /// 64·T1 after a non-INVITE server transaction was created: §17.2.2 gives `Trying`/`Proceeding`
    /// no timer of their own.
    UnansweredNonInvite(TransactionId<NonInviteServer>),
}

/// One whole message framed off a connection, for [`Endpoint::tap_streams`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamMessage {
    /// The connection it arrived on.
    pub transport: TransportId,
    /// Its far end, or `None` for a connection bound without one.
    pub remote: Option<SocketAddr>,
    /// The message, from its start line to the end of its body.
    pub bytes: Box<[u8]>,
}

/// Retransmissions and timeouts since the endpoint was created. Every figure only grows; over TCP
/// and TLS only `timeouts` moves (RFC 3261 §17.1.1.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Retransmissions {
    /// Requests sent again: timers A and E, and ACKs for a repeated 2xx (§13.2.2.4).
    pub requests: u64,
    /// Responses sent again: timer G, reliable provisionals (RFC 3262 §3), and answers to a
    /// repeated request.
    pub responses: u64,
    /// Transactions ended unanswered or unacknowledged: timers B, F, H, L, and unPRACKed reliable
    /// provisionals.
    pub timeouts: u64,
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
    /// Reused, so receiving a datagram allocates nothing.
    pub(super) scratch: ParseScratch,
    pub(super) hit: Vec<AnyTransactionId>,
    /// The `To` tag of each server transaction; all its responses carry the same one (§8.2.6.2).
    pub(super) local_tags: HashMap<AnyTransactionId, Box<[u8]>>,
    /// INVITEs a CANCEL went out for: a 487 is then no refusal, a 2xx a lost race.
    pub(super) cancelled: HashSet<TransactionId<InviteClient>>,
    /// The `Reason` (RFC 3326) for each CANCEL, which may wait for a provisional (§9.1).
    pub(super) cancel_reasons: HashMap<TransactionId<InviteClient>, Box<[u8]>>,
    pub(super) reliable: Reliables,
    /// INVITEs and UPDATEs inside dialogs (RFC 3261 §14), the ones that cross.
    pub(super) reinvites: Reinvites,
    pub(super) challenges: Challenges,
    /// Requests outside a dialog that found no server, kept for
    /// [`Endpoint::send_elsewhere`] (RFC 3263 §4.3).
    pub(super) unreached: super::failover::Unreached,
    /// The dialog a client transaction is in; a retry after a challenge takes its `CSeq` from it.
    pub(super) dialogs_of: HashMap<AnyTransactionId, DialogId>,
    /// What each destination challenged with, for credentials up front (§22.2).
    pub(super) known: Known,
    /// Requests refused for want of room. Only grows.
    pub(super) refused: u64,
    /// Messages the parser refused. Only grows.
    pub(super) unreadable: u64,
    pub(super) retransmissions: Retransmissions,
    /// Admitted calls whose dialog is not open yet; each holds its room under
    /// [`EndpointConfig::max_dialogs`].
    pub(super) admitted: HashSet<TransactionId<InviteServer>>,
    /// The `UnansweredNonInvite` deadline per live transaction, cancelled when it retires so the
    /// schedule stays bounded.
    pub(super) unanswered: HashMap<TransactionId<NonInviteServer>, TimerHandle>,
    /// Diagnostic records (`docs/14-diagnostics.md`).
    pub(super) diag: Records,
    /// Addresses `Event::TransportWanted` asked a stream for.
    pub(super) streams_wanted: HashSet<SocketAddr>,
    /// Addresses no stream is coming to ([`Endpoint::no_stream_coming`]).
    pub(super) streamless: HashSet<SocketAddr>,
    /// Per-transport ping intervals ([`Endpoint::keep_stream_alive`]), keyed by name to survive a
    /// rebind.
    pub(super) stream_keepalives: HashMap<TransportId, core::time::Duration>,
    /// Framed stream messages while [`Endpoint::tap_streams`] is on, the newest
    /// [`STREAM_TAP_KEPT`].
    pub(super) stream_tap: Option<VecDeque<StreamMessage>>,
}

/// How many tapped stream messages wait for [`Endpoint::take_stream_messages`] before the oldest is
/// dropped. A tap left on by an application that stopped taking would otherwise copy every message
/// for the life of the connection.
pub(super) const STREAM_TAP_KEPT: usize = 1_024;

impl Endpoint {
    /// A new endpoint. `seed` is thirty-two bytes of entropy that every branch, tag, `Call-ID` and
    /// `cnonce` derives from; never share one between endpoints.
    ///
    /// # Errors
    /// [`TimerConfigError`] when `config.timers` cannot be armed
    /// ([`crate::transaction::TimerConfig::validate`]), and
    /// [`TimerConfigError::KeepaliveUnarmable`] for a zero `keepalive_interval`: either would make
    /// `handle_timeout` loop forever.
    pub fn new(config: EndpointConfig, seed: [u8; 32]) -> Result<Self, TimerConfigError> {
        config.timers.validate()?;
        if config.keepalive_interval == Some(core::time::Duration::ZERO) {
            return Err(TimerConfigError::KeepaliveUnarmable);
        }
        Ok(Self {
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
            cancel_reasons: HashMap::new(),
            reliable: Reliables::new(),
            reinvites: Reinvites::new(),
            challenges: Challenges::new(),
            unreached: super::failover::Unreached::new(),
            dialogs_of: HashMap::new(),
            known: Known::new(),
            refused: 0,
            unreadable: 0,
            retransmissions: Retransmissions::default(),
            admitted: HashSet::new(),
            unanswered: HashMap::new(),
            diag: Records::new(config.diagnostics),
            streams_wanted: HashSet::new(),
            streamless: HashSet::new(),
            stream_keepalives: HashMap::new(),
            stream_tap: None,
        })
    }

    /// Keep a copy of every message framed off a connection for [`Endpoint::take_stream_messages`],
    /// or stop and drop the copies. Off by default. Only the framer knows where a stream message
    /// ends (§18.3).
    pub fn tap_streams(&mut self, on: bool) {
        match (on, self.stream_tap.is_some()) {
            (true, false) => self.stream_tap = Some(VecDeque::new()),
            (false, true) => self.stream_tap = None,
            _ => {}
        }
    }

    /// The messages [`Endpoint::tap_streams`] kept, in order, each once: the newest 1,024 since
    /// the last take, the older ones dropped.
    pub fn take_stream_messages(&mut self) -> Vec<StreamMessage> {
        self.stream_tap
            .as_mut()
            .map(|tap| Vec::from(core::mem::take(tap)))
            .unwrap_or_default()
    }

    /// Keep a copy of one framed stream message while the tap is on, dropping the oldest past
    /// [`STREAM_TAP_KEPT`].
    pub(super) fn tap_stream(
        &mut self,
        transport: TransportId,
        remote: Option<SocketAddr>,
        bytes: &[u8],
    ) {
        let Some(tap) = self.stream_tap.as_mut() else {
            return;
        };
        if tap.len() >= STREAM_TAP_KEPT {
            tap.pop_front();
        }
        tap.push_back(StreamMessage {
            transport,
            remote,
            bytes: bytes.into(),
        });
    }

    /// The stream a `TransportWanted` asked for cannot be had. `true` when a request held back may
    /// now go.
    ///
    /// Under [`DatagramLimit::without_stream_bytes`](super::DatagramLimit::without_stream_bytes),
    /// requests up to that size then go over the datagram to those addresses (recorded as
    /// `transport.kept.datagram`) until a stream is bound. Otherwise nothing changes.
    pub fn no_stream_coming(&mut self) -> bool {
        if self.config.datagram_limit.without_stream_bytes.is_none()
            || self.streams_wanted.is_empty()
        {
            self.streams_wanted.clear();
            return false;
        }
        self.streamless.extend(self.streams_wanted.drain());
        true
    }

    /// Bytes, or news about a transport.
    ///
    /// # Errors
    /// [`ReceiveError`] when the transport is unknown or the bytes are not a message; malformed
    /// datagrams are routine, log and carry on. On a stream only lost framing is returned, and the
    /// connection is already forgotten.
    pub fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        self.mark(now);
        match input {
            Input::TransportBound {
                transport,
                protocol,
                local,
                remote,
            } => {
                // RFC 5626 §4.4.1 is per flow: cancel the old connection's deadlines, or the pong
                // one kills the replacement. Handles are never reused, so this is safe
                let replaced =
                    self.transports
                        .bind(transport, protocol, local, remote, self.config.limits);
                if let Some(old) = replaced {
                    for handle in [old.keepalive, old.pong].into_iter().flatten() {
                        self.deadlines.cancel(handle);
                    }
                }
                // a stream after all: requests go back on it
                if protocol.is_reliable() {
                    if let Some(remote) = remote {
                        self.streams_wanted.remove(&remote);
                        self.streamless.remove(&remote);
                    } else {
                        self.streams_wanted.clear();
                        self.streamless.clear();
                    }
                }
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
        self.mark(now);
        while let Some(deadline) = self.deadlines.fire(now) {
            match deadline {
                Deadline::Keepalive(transport) => self.send_keepalive(transport, now),
                Deadline::PongOverdue(transport) => self.flow_failed(transport),
                Deadline::Reliable(raw) => self.retransmit_reliable(raw, now),
                Deadline::UnansweredNonInvite(id) => self.non_invite_app_timeout(id, now),
            }
        }

        // firing one timer can arm another
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

    /// Bytes to put on a transport. Drain to empty. `payload.len()` is the on-wire size; a request
    /// §18.1.1 refused arrives as [`Event::TransportWanted`] instead, and both sizes are in
    /// [`Endpoint::call_record`].
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

    /// An unguessable token from the stream branches, tags and `Call-ID`s come from, so it never
    /// collides with them. Only for values sent in clear: a replay recording carries this stream's
    /// seed ([`Endpoint::reseed`]).
    #[must_use]
    pub fn token(&mut self) -> Box<[u8]> {
        self.tokens.token()
    }

    /// Move the token stream onto a fresh, one-way derived seed and return it, for a replay
    /// recording (`docs/18-replay.md`). Calling it again after the recording makes later
    /// identifiers unpredictable from it.
    pub fn reseed(&mut self) -> [u8; 32] {
        self.tokens.reseed()
    }

    /// The protocol and bound address of a transport, or `None` if it is not bound.
    #[must_use]
    pub fn bound_transport(
        &self,
        transport: TransportId,
    ) -> Option<(TransportProtocol, SocketAddr)> {
        self.transports
            .get(transport)
            .map(|bound| (bound.protocol, bound.local))
    }

    /// Advertise `name` as the `sent-by` on `transport` until it is bound again. For a WebSocket
    /// client's random `.invalid` host (RFC 7118 Appendix B.1, §5.2.3); responses match by it
    /// (§18.1.2).
    ///
    /// `false`, and no change, when the transport is not bound or `name` is not a `hostname` (RFC
    /// 3261 §25.1).
    pub fn advertise_name(&mut self, transport: TransportId, name: &str) -> bool {
        let valid = !name.is_empty()
            && name.len() <= 253
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
        match self.transports.get_mut(transport) {
            Some(bound) if valid => {
                bound.sent_by = Some(Box::from(name));
                true
            }
            _ => false,
        }
    }

    /// The `Via` for `transport`: its advertised name if any, else `local`.
    pub(super) fn via_on(
        &self,
        transport: TransportId,
        protocol: TransportProtocol,
        local: SocketAddr,
        branch: &[u8],
    ) -> Box<[u8]> {
        let rport = self.config.always_request_rport;
        match self
            .transports
            .get(transport)
            .and_then(|bound| bound.sent_by.as_deref())
        {
            Some(name) => via::named_via(protocol, name, branch, rport),
            None => via::local_via(protocol, local, branch, rport),
        }
    }

    /// A bound transport of `protocol` connected to `destination`, or an unconnected one.
    #[must_use]
    pub fn transport_to(
        &self,
        protocol: TransportProtocol,
        destination: SocketAddr,
    ) -> Option<TransportId> {
        self.transports.speaking_to(protocol, destination)
    }

    /// The address of any bound transport, to pick the family a name is looked up for.
    #[must_use]
    pub fn any_bound_address(&self) -> Option<SocketAddr> {
        self.transports.any_local()
    }

    /// Ping the stream `transport` every `every`, or with `None` at
    /// [`EndpointConfig::keepalive_interval`] (RFC 5626 §4.4.1, jittered 80-100%). Kept by name
    /// across rebinds; the schedule is redrawn at once.
    ///
    /// # Errors
    /// [`TimerConfigError::KeepaliveUnarmable`] for zero; nothing changes.
    pub fn keep_stream_alive(
        &mut self,
        transport: TransportId,
        every: Option<core::time::Duration>,
        now: Instant,
    ) -> Result<(), TimerConfigError> {
        match every {
            Some(core::time::Duration::ZERO) => return Err(TimerConfigError::KeepaliveUnarmable),
            Some(interval) => {
                self.stream_keepalives.insert(transport, interval);
            }
            None => {
                self.stream_keepalives.remove(&transport);
            }
        }
        if let Some(handle) = self
            .transports
            .get_mut(transport)
            .and_then(|bound| bound.keepalive.take())
        {
            self.deadlines.cancel(handle);
        }
        self.arm_keepalives(now);
        Ok(())
    }

    /// The interval a stream transport is pinged at, or `None` when it is not.
    #[must_use]
    pub fn stream_keepalive(&self, transport: TransportId) -> Option<core::time::Duration> {
        self.keepalive_interval_of(transport)
    }

    /// What this endpoint was configured with.
    #[must_use]
    pub const fn config(&self) -> &EndpointConfig {
        &self.config
    }

    /// Live transactions and dialogs, to know whether it can shut down.
    #[must_use]
    pub fn in_flight(&self) -> (usize, usize) {
        (self.transactions.len(), self.dialogs.len())
    }

    /// Requests refused with a 503 for want of room; the number [`Event::Overloaded`] carries.
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.refused
    }

    /// Messages the parser refused, answered or not. Each also leaves `request.refused.unreadable`
    /// or `message.dropped.unreadable` in [`Endpoint::endpoint_record`].
    #[must_use]
    pub const fn unreadable(&self) -> u64 {
        self.unreadable
    }

    /// Retransmissions and timeouts: a lossy path shows here before a call fails.
    #[must_use]
    pub const fn retransmissions(&self) -> Retransmissions {
        self.retransmissions
    }

    /// The transport a call's signalling uses: the flow of `dialog`, else of the live
    /// `transaction`. An SDES key is only as safe as this (RFC 4568 §8.3).
    #[must_use]
    pub fn signalling_protocol(
        &self,
        dialog: Option<DialogId>,
        transaction: Option<AnyTransactionId>,
    ) -> Option<TransportProtocol> {
        dialog
            .and_then(|dialog| self.dialogs.flow(dialog))
            .or_else(|| {
                transaction
                    .filter(|id| self.transactions.retransmissions(*id).is_some())
                    .map(|id| self.flow_of(id))
            })
            .map(|flow| flow.protocol)
    }

    /// How often a live transaction resent its message; `None` once it has ended.
    #[must_use]
    pub fn transaction_retransmissions(&self, id: impl Into<AnyTransactionId>) -> Option<u32> {
        self.transactions.retransmissions(id.into())
    }

    pub(super) fn count_retransmission(&mut self, request: bool, id: Option<AnyTransactionId>) {
        let total = if request {
            &mut self.retransmissions.requests
        } else {
            &mut self.retransmissions.responses
        };
        *total = total.saturating_add(1);
        if let Some(id) = id {
            self.transactions.count_retransmission(id);
        }
    }

    pub(super) const fn count_timeout(&mut self) {
        self.retransmissions.timeouts = self.retransmissions.timeouts.saturating_add(1);
    }

    pub(crate) const fn store(&self) -> &Transactions {
        &self.transactions
    }

    pub(super) fn queue(&mut self, transmit: Transmit) {
        self.transmits.push_back(transmit);
    }

    pub(super) fn push(&mut self, event: Event) {
        self.events.push_back(event);
    }

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

    pub(super) fn mint_tag(&mut self) -> Box<[u8]> {
        self.tokens.token()
    }

    pub(super) fn remember_tag(&mut self, id: AnyTransactionId, tag: Box<[u8]>) {
        if !tag.is_empty() {
            self.local_tags.insert(id, tag);
        }
    }

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
        self.cancel_reasons.remove(&id);
    }

    pub(super) fn remember_dialog(&mut self, id: AnyTransactionId, dialog: DialogId) {
        self.dialogs_of.insert(id, dialog);
    }

    pub(super) fn dialog_of(&self, id: AnyTransactionId) -> Option<DialogId> {
        self.dialogs_of.get(&id).copied()
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

/// The flow of a transaction that is gone. The address is RFC 5737 documentation space, so a stray
/// packet reaches nobody.
const NOWHERE: Flow = Flow {
    transport: TransportId(u32::MAX),
    destination: SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 0)),
        0,
    ),
    source: None,
    protocol: TransportProtocol::Udp,
};

/// What a dialog looks like from outside. Sequence numbers stay `None` until something is sent in
/// that direction (§12.1.1, §12.1.2).
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

impl Endpoint {
    /// Send a non-INVITE request outside a dialog: REGISTER, OPTIONS, SUBSCRIBE, MESSAGE.
    ///
    /// # Errors
    /// [`SendError`] when a field is missing, the transport is unknown, or the request needs a
    /// stream and none is open.
    pub fn request(
        &mut self,
        request: &OutgoingRequest,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        self.send_request(request, None, now)
    }

    /// The same, with credentials for a challenge this destination already made (§22.2). Safe on a
    /// first request; it saves the 401 round trip on refreshes. The password is not kept; the
    /// endpoint owns the nonce count.
    ///
    /// # Errors
    /// As [`Endpoint::request`].
    pub fn request_with_credentials(
        &mut self,
        request: &OutgoingRequest,
        credentials: &Credentials,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        self.send_request(request, Some(credentials), now)
    }

    fn send_request(
        &mut self,
        request: &OutgoingRequest,
        credentials: Option<&Credentials>,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        self.mark(now);
        let (message, flow) = self.build_request(request, credentials)?;
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
        self.send_invite(request, None, now)
    }

    /// Place a call, as [`Endpoint::request_with_credentials`].
    ///
    /// # Errors
    /// As [`Endpoint::request`].
    pub fn invite_with_credentials(
        &mut self,
        request: &OutgoingRequest,
        credentials: &Credentials,
        now: Instant,
    ) -> Result<TransactionId<InviteClient>, SendError> {
        self.send_invite(request, Some(credentials), now)
    }

    fn send_invite(
        &mut self,
        request: &OutgoingRequest,
        credentials: Option<&Credentials>,
        now: Instant,
    ) -> Result<TransactionId<InviteClient>, SendError> {
        self.mark(now);
        if self.dialogs_held() >= self.config.max_dialogs {
            return Err(SendError::LimitReached {
                limit: self.config.max_dialogs,
            });
        }
        let (message, flow) = self.build_request(request, credentials)?;
        let secure = flow.protocol.is_secure();
        let set = DialogSet::new(message.clone(), secure);
        let (id, effects) =
            self.transactions
                .start_invite_client(message, flow, self.config.timers, now)?;
        self.dialogs.watch(set, id);
        self.apply_client(effects, flow);
        Ok(id)
    }

    /// Give up on an unanswered call (§9.1). A CANCEL asked for before the first provisional waits
    /// for it; [`Event::CancelSent`] says when it went.
    ///
    /// # Errors
    /// [`CancelError`] when the transaction is unknown or already has a final response.
    pub fn cancel(
        &mut self,
        invite: TransactionId<InviteClient>,
        now: Instant,
    ) -> Result<(), CancelError> {
        self.mark(now);
        let Some(entry) = self.transactions.invite_client_mut(invite) else {
            return Err(CancelError::NoSuchTransaction);
        };
        match entry.machine.request_cancel() {
            crate::transaction::CancelDisposition::Deferred => Ok(()),
            crate::transaction::CancelDisposition::Now => self.send_cancel(invite, now),
            crate::transaction::CancelDisposition::TooLate => Err(CancelError::AlreadyAnswered),
        }
    }

    /// [`Endpoint::cancel`] with a `Reason` (RFC 3326 §2): `reason` is the field value as it goes
    /// on the wire.
    ///
    /// # Errors
    /// As [`Endpoint::cancel`].
    pub fn cancel_with_reason(
        &mut self,
        invite: TransactionId<InviteClient>,
        reason: &[u8],
        now: Instant,
    ) -> Result<(), CancelError> {
        if self.transactions.invite_client(invite).is_none() {
            return Err(CancelError::NoSuchTransaction);
        }
        self.cancel_reasons
            .entry(invite)
            .or_insert_with(|| Box::from(reason));
        self.cancel(invite, now)
    }

    /// Acknowledge a 2xx (§13.2.2.4), once. The caller builds the ACK since it may carry an answer;
    /// the dialog then repeats it for every retransmitted 2xx.
    ///
    /// # Errors
    /// [`AckError`] when the dialog is unknown, unanswered or already acknowledged;
    /// [`AckError::Build`] with [`SendError::NeedsStreamTransport`] when a stream is needed: call
    /// again once it is bound.
    pub fn ack_2xx(
        &mut self,
        dialog: DialogId,
        answer: Option<&[u8]>,
        now: Instant,
    ) -> Result<(), AckError> {
        self.mark(now);
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
        let (ack, flow) = self.build_in_dialog(&plan, flow, None, answer)?;
        self.dialogs.keep_ack(dialog, ack.clone(), flow);
        self.note_wire(
            &ack.as_raw(),
            Reason::RequestSent,
            Direction::Outbound,
            flow,
        );
        self.transmits.push_back(flow.transmit(ack.bytes()));
        Ok(())
    }

    /// Hang up (§15.1.1).
    ///
    /// # Errors
    /// As [`Endpoint::request_in_dialog`]; after [`SendError::NeedsStreamTransport`] the dialog is
    /// still up.
    pub fn bye(
        &mut self,
        dialog: DialogId,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        self.bye_with(dialog, &OutgoingInDialogRequest::new(Method::Bye), now)
    }

    /// Hang up with the caller's own BYE.
    ///
    /// # Errors
    /// [`SendError::WrongMethod`] for anything but a BYE; otherwise as [`Endpoint::bye`].
    pub fn bye_with(
        &mut self,
        dialog: DialogId,
        request: &OutgoingInDialogRequest,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        self.mark(now);
        if request.method() != Method::Bye {
            return Err(SendError::WrongMethod);
        }
        let id = self.request_in_dialog(dialog, request, now)?;
        // §15.1.1: the session ends once the BYE is passed to the transaction, whatever the answer
        if let Some(state) = self.dialogs.get_mut(dialog) {
            state.terminate();
        }
        self.forget_dialog(dialog, super::event::DialogEndReason::LocalBye);
        Ok(id)
    }

    /// Send a request inside a dialog: BYE, INFO, NOTIFY, UPDATE, REFER. Addressing and numbering
    /// come from the dialog (§12.2.1.1).
    ///
    /// # Errors
    /// [`SendError`] when the dialog is unknown or the request cannot be built, including
    /// [`SendError::NeedsStreamTransport`] (§18.1.1).
    pub fn request_in_dialog(
        &mut self,
        dialog: DialogId,
        request: &OutgoingInDialogRequest,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        self.mark(now);
        // an INVITE needs an INVITE transaction and an ACK of its own
        if request.method() == Method::Invite {
            return Err(SendError::WrongMethod);
        }
        let flow = self.dialogs.flow(dialog).ok_or(SendError::NoSuchDialog)?;
        let plan = self
            .dialogs
            .get_mut(dialog)
            .ok_or(SendError::NoSuchDialog)?
            .next_request(request.method())
            .map_err(SendError::Dialog)?;
        let (message, flow) =
            self.build_in_dialog(&plan, flow, Some(request), request.body.as_deref())?;
        let (id, effects) =
            self.transactions
                .start_non_invite_client(message, flow, self.config.timers, now)?;
        self.apply_client(effects, flow);
        self.remember_dialog(AnyTransactionId::NonInviteClient(id), dialog);
        Ok(id)
    }

    /// Renegotiate inside a dialog (§14.1). `Contact` is required (§8.1.1.8). The answer arrives as
    /// [`Event::ReinviteAnswered`] and is acknowledged with [`Endpoint::ack_reinvite`], not
    /// [`Endpoint::ack_2xx`].
    ///
    /// # Errors
    /// [`SendError::InviteInProgress`] while another INVITE runs in the dialog; otherwise as
    /// [`Endpoint::request_in_dialog`].
    pub fn reinvite(
        &mut self,
        dialog: DialogId,
        request: &OutgoingInDialogRequest,
        now: Instant,
    ) -> Result<TransactionId<InviteClient>, SendError> {
        self.mark(now);
        if request.contact.is_none() {
            return Err(SendError::MissingField("Contact"));
        }
        let flow = self.dialogs.flow(dialog).ok_or(SendError::NoSuchDialog)?;
        // §14.1: no new INVITE while another is in progress in either direction
        if self.invite_outstanding(dialog) || self.reinvites.their_invite_in(dialog).is_some() {
            return Err(SendError::InviteInProgress);
        }
        let plan = self
            .dialogs
            .get_mut(dialog)
            .ok_or(SendError::NoSuchDialog)?
            .next_request(Method::Invite)
            .map_err(SendError::Dialog)?;
        let (message, flow) =
            self.build_in_dialog(&plan, flow, Some(request), request.body.as_deref())?;
        let (id, effects) = self.transactions.start_invite_client(
            message.clone(),
            flow,
            self.config.timers,
            now,
        )?;
        self.watch_reinvite(id, dialog, message);
        self.apply_client(effects, flow);
        self.remember_dialog(AnyTransactionId::InviteClient(id), dialog);
        Ok(id)
    }

    /// Answer a request that is not an INVITE.
    ///
    /// # Errors
    /// [`RespondError`] when the transaction is unknown or already answered.
    pub fn respond(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        response: &OutgoingResponse,
        now: Instant,
    ) -> Result<(), RespondError> {
        self.mark(now);
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
        // RFC 3311 §5.2 counts an UPDATE as pending only until it is answered
        if response.status.is_final() {
            self.reinvites
                .answered_theirs(AnyTransactionId::NonInviteServer(transaction));
        }
        Ok(())
    }

    /// Open a dialog around a NOTIFY that arrived outside one (RFC 6665 §4.4.1): a SUBSCRIBE's 2xx
    /// creates none. `local_seq` continues this end's `CSeq` series
    /// ([`Dialog::resume_from`](crate::dialog::Dialog::resume_from)).
    ///
    /// `None` when the transaction has gone or the request lacks a `To` tag or a usable `Contact`.
    /// Call it **before** answering: on a reliable transport the final response retires the
    /// transaction (§17.2.2).
    #[must_use]
    pub fn open_dialog(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        local_seq: Option<u32>,
    ) -> Option<DialogId> {
        let entry = self.transactions.non_invite_server(transaction)?;
        let flow = entry.flow;
        let request = entry.request.clone();
        let tag = request.as_raw().to().ok()?.tag()?;
        if tag.is_empty() {
            return None;
        }
        // §12.1.1: no early half here, the dialog is confirmed or absent
        let dialog = self.open_uas_dialog(&request, &tag, StatusCode::OK, flow)?;
        if let (Some(seq), Some(state)) = (local_seq, self.dialogs.get_mut(dialog)) {
            state.resume_from(seq);
        }
        Some(dialog)
    }

    /// Open the dialog this end's 2xx to an out-of-dialog REFER creates (RFC 3261 §12.1.1, RFC 3515
    /// §2.4.4), with the tag [`Endpoint::respond`] will write.
    ///
    /// `None` when the transaction has gone, the request has a `To` tag, or no usable `Contact`.
    /// Call it **before** answering.
    #[must_use]
    pub fn open_dialog_answering(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
    ) -> Option<DialogId> {
        let entry = self.transactions.non_invite_server(transaction)?;
        let flow = entry.flow;
        let request = entry.request.clone();
        if request.as_raw().to().ok()?.tag().is_some() {
            return None;
        }
        let tag = self.tag_or_mint(AnyTransactionId::NonInviteServer(transaction));
        self.open_uas_dialog(&request, &tag, StatusCode::OK, flow)
    }

    /// Forget a dialog whose usage ended with nothing on the wire (RFC 6665 §4.4.1); otherwise each
    /// re-subscription leaks one. [`Event::DialogTerminated`] with
    /// [`DialogEndReason::Closed`](super::DialogEndReason::Closed) follows.
    pub fn close_dialog(&mut self, dialog: DialogId) {
        if let Some(state) = self.dialogs.get_mut(dialog) {
            state.terminate();
        }
        self.forget_dialog(dialog, super::event::DialogEndReason::Closed);
    }

    /// Answer an INVITE; a 2xx opens the dialog and returns it. Non-2xx finals are retransmitted
    /// until the ACK (§17.2.1); repeating the 2xx is the caller's job (RFC 6026 §8.1).
    ///
    /// # Errors
    /// [`RespondError`] when the transaction is unknown or already answered.
    pub fn respond_invite(
        &mut self,
        transaction: TransactionId<InviteServer>,
        response: &OutgoingResponse,
        now: Instant,
    ) -> Result<Option<DialogId>, RespondError> {
        self.mark(now);
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

        // RFC 3262 §3: with `Require: 100rel`, every non-100 provisional MUST be reliable
        if status.is_provisional()
            && status.get() >= 101
            && super::reliable::demands_100rel(&request.as_raw())
        {
            return Err(RespondError::MustBeReliable);
        }
        // §3: a final stops reliable retransmissions; a late PRACK still gets answered
        if status.is_final() {
            self.quiet_reliable(transaction);
        }

        // §12.1.1: only a 101-199 or a 2xx opens a dialog
        let opens = status.get() >= 101 && (status.is_provisional() || status.is_success());
        let dialog = opens
            .then(|| self.open_uas_dialog(&request, &tag, status, flow))
            .flatten();
        // §12.3: a refusal ends what a provisional of this INVITE opened
        let early = (status.is_final() && !status.is_success())
            .then(|| self.early_dialog_of(transaction))
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
        // §13.2.2.4: the ACK for this 2xx carries this INVITE's `CSeq`
        if status.is_success()
            && let Some(dialog) = dialog
            && let Ok(seq) = request.as_raw().cseq().map(|cseq| cseq.seq)
        {
            self.dialogs.answer_invite(dialog, seq, transaction);
        }
        self.end_refused_early(transaction, early);
        // the call stops holding room once a dialog opened or a final went out
        if dialog.is_some() || status.is_final() {
            self.admitted.remove(&transaction);
        }
        // §14.2: the dialog is free for another INVITE once this one is answered
        if status.is_final() {
            self.reinvites
                .answered_theirs(AnyTransactionId::InviteServer(transaction));
        }
        Ok(dialog)
    }
}

impl Endpoint {
    fn build_request(
        &mut self,
        request: &OutgoingRequest,
        credentials: Option<&Credentials>,
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
        // §26.2.2: SIPS needs TLS on every hop. Checked before anything is drawn, so a refusal
        // leaves no trace
        if !bound.protocol.is_secure() && asks_for_tls(request) {
            return Err(SendError::SipsNeedsTls);
        }
        let mut flow = Flow {
            transport: request.transport,
            destination: request.remote,
            source: None,
            protocol: bound.protocol,
        };
        let mut local = bound.local;

        // 8.1.1.3: every request carries an unguessable From tag
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
        // §22.2 re-use. Drawn here because a nonce count spent twice is a replay to the server.
        // Drawing does not spend it: the size rule below may still refuse the send.
        let answers = match credentials {
            Some(credentials) => self.answer_ahead(request, credentials, &call_id),
            None => Answered::default(),
        };
        // RFC 3262 §4: the UAC SHOULD offer 100rel on every INVITE
        let supported = (request.method.as_ref() == Method::Invite.as_str().as_bytes())
            .then(|| offering_100rel(&request.extra));
        let minted = Minted {
            branch: &branch,
            from,
            to,
            call_id: &call_id,
            cseq: request.cseq.unwrap_or(1),
            supported: supported.as_deref(),
            credentials: answers.fields(),
        };

        let mut message = self.assemble(request, &flow, local, &minted)?;
        self.note(
            Some(&call_id),
            Decision::of(Reason::TransportSelected)
                .at_address(flow.destination)
                .over(flow.protocol),
        );
        message = self.written_for_the_datagram(flow, message)?;

        // §18.1.1: too large for a datagram goes over a stream, and the Via says so
        if !flow.protocol.is_reliable()
            && self
                .config
                .datagram_limit
                .too_big_for_a_datagram(message.len())
            && !self.keep_on_datagram(flow, message.len(), Some(&call_id))
        {
            let overlong = message.len();
            let stream = self.stream_to(request.remote, overlong, Some(&call_id))?;
            let bound = self
                .transports
                .get(stream)
                .ok_or(SendError::UnknownTransport)?;
            flow = Flow {
                transport: stream,
                destination: request.remote,
                source: None,
                protocol: bound.protocol,
            };
            local = bound.local;
            message = self.assemble(request, &flow, local, &minted)?;
            self.note_promotion(Some(&call_id), flow, overlong);
        }

        // the bytes are settled: the nonce count is spent
        if !answers.is_empty()
            && let Some(to) = request.to.as_deref().and_then(super::auth::destination)
        {
            self.spend_answer(&to, &answers);
        }

        Ok((message, flow))
    }

    /// A request bound for a datagram, compacted as [`Compaction`](super::Compaction) says, before
    /// §18.1.1 measures it. Streams are never compacted; `Allow` goes too if compact is not enough.
    /// Recorded as `transport.compacted.size` when size forced it.
    pub(super) fn written_for_the_datagram(
        &mut self,
        flow: Flow,
        message: OwnedMessage,
    ) -> Result<OwnedMessage, SendError> {
        use super::config::Compaction;

        let limit = self.config.datagram_limit;
        let oversize = limit.too_big_for_a_datagram(message.len());
        let wanted = match limit.compaction {
            Compaction::Never => false,
            Compaction::WhenOversize => oversize,
            Compaction::Always => true,
        };
        if flow.protocol.is_reliable() || !wanted {
            return Ok(message);
        }
        let mut compact = crate::msg::compact_request(&message.as_raw(), &[])?;
        if limit.too_big_for_a_datagram(compact.len()) {
            compact = crate::msg::compact_request(&message.as_raw(), &[HeaderName::Allow])?;
        }
        if oversize {
            let call = message.as_raw().call_id().ok().map(<[u8]>::to_vec);
            let limit_bytes = self.datagram_limit_bytes();
            self.note(
                call.as_deref(),
                Decision::of(Reason::TransportCompactedBySize)
                    .at_address(flow.destination)
                    .over(flow.protocol)
                    .measured(compact.len(), limit_bytes),
            );
        }
        Ok(compact)
    }

    /// §18.1.1 for a request built outside `build_request`: `None` when the datagram carries it,
    /// else the stream flow and its `Via` address, or [`SendError::NeedsStreamTransport`]. A retry
    /// carrying `Authorization` is the usual request that outgrows the limit.
    pub(super) fn promote_if_too_big(
        &mut self,
        flow: Flow,
        bytes: usize,
        call: Option<&[u8]>,
    ) -> Result<Option<(Flow, SocketAddr)>, SendError> {
        if flow.protocol.is_reliable() || !self.config.datagram_limit.too_big_for_a_datagram(bytes)
        {
            return Ok(None);
        }
        if self.keep_on_datagram(flow, bytes, call) {
            return Ok(None);
        }
        let stream = self.stream_to(flow.destination, bytes, call)?;
        let bound = self
            .transports
            .get(stream)
            .ok_or(SendError::UnknownTransport)?;
        let promoted = Flow {
            transport: stream,
            destination: flow.destination,
            source: None,
            protocol: bound.protocol,
        };
        let local = bound.local;
        self.note_promotion(call, promoted, bytes);
        Ok(Some((promoted, local)))
    }

    /// The flow a kept ACK is resent on when its 2xx repeats (§13.2.2.4): its first flow while
    /// open, else the 2xx's flow held to §18.1.1, or `None` while a stream is awaited.
    pub(super) fn flow_for_kept_ack(
        &mut self,
        went_on: Flow,
        arrived_on: Flow,
        ack: &OwnedMessage,
    ) -> Option<Flow> {
        if self.transports.get(went_on.transport).is_some() {
            return Some(went_on);
        }
        let call = ack.as_raw().call_id().ok();
        match self.promote_if_too_big(arrived_on, ack.len(), call) {
            Ok(None) => Some(arrived_on),
            Ok(Some((stream, _))) => Some(stream),
            Err(_) => None,
        }
    }

    /// §18.1.1 moved a request off the datagram; size and limit go in the record together.
    fn note_promotion(&mut self, call: Option<&[u8]>, flow: Flow, bytes: usize) {
        let limit = self.datagram_limit_bytes();
        self.note(
            call,
            Decision::of(Reason::TransportPromotedBySize)
                .at_address(flow.destination)
                .over(flow.protocol)
                .measured(bytes, limit),
        );
    }

    /// Whether an oversize request goes over a datagram anyway ([`Endpoint::no_stream_coming`],
    /// [`DatagramLimit::without_stream_bytes`](super::DatagramLimit::without_stream_bytes)).
    /// Recorded when it does.
    fn keep_on_datagram(&mut self, flow: Flow, bytes: usize, call: Option<&[u8]>) -> bool {
        let kept = self.streamless.contains(&flow.destination)
            && self.config.datagram_limit.fits_without_stream(bytes)
            && self
                .transports
                .speaking_to(TransportProtocol::Tcp, flow.destination)
                .is_none();
        if kept {
            let limit = self.config.datagram_limit.without_stream_bytes.unwrap_or(0);
            self.note(
                call,
                Decision::of(Reason::TransportKeptOnDatagram)
                    .at_address(flow.destination)
                    .over(flow.protocol)
                    .measured(bytes, limit),
            );
        }
        kept
    }

    /// The largest request a datagram would still take; 0 when the path MTU leaves no room.
    pub(super) fn datagram_limit_bytes(&self) -> u32 {
        self.config
            .datagram_limit
            .largest_datagram_request()
            .unwrap_or(0)
    }

    /// The stream an oversize request leaves on, asking the caller for one when none is open to
    /// that destination (§18.1.1).
    fn stream_to(
        &mut self,
        destination: SocketAddr,
        request_bytes: usize,
        call: Option<&[u8]>,
    ) -> Result<TransportId, SendError> {
        let open = self
            .transports
            .speaking_to(TransportProtocol::Tcp, destination);
        if let Some(stream) = open {
            return Ok(stream);
        }
        let limit_bytes = self.datagram_limit_bytes();
        self.streams_wanted.insert(destination);
        self.events.push_back(Event::TransportWanted {
            protocol: TransportProtocol::Tcp,
            destination,
            request_bytes,
            limit_bytes,
        });
        self.note(
            call,
            Decision::of(Reason::TransportRefusedBySize)
                .at_address(destination)
                .over(TransportProtocol::Udp)
                .measured(request_bytes, limit_bytes),
        );
        Err(SendError::NeedsStreamTransport)
    }

    fn assemble(
        &self,
        request: &OutgoingRequest,
        flow: &Flow,
        local: SocketAddr,
        minted: &Minted<'_>,
    ) -> Result<OwnedMessage, SendError> {
        let via = self.via_on(flow.transport, flow.protocol, local, minted.branch);
        let method =
            Method::from_bytes(&request.method).ok_or(SendError::MissingField("method"))?;
        let mut builder = RequestBuilder::new(method, request.request_uri.as_bytes())
            .via(&via)
            .from(minted.from)
            .to(minted.to)
            .call_id(minted.call_id)
            .cseq(minted.cseq)
            .max_forwards(request.max_forwards);
        if let Some(supported) = minted.supported {
            builder = builder.header(HeaderName::Supported, supported);
        }
        for hop in &request.route {
            builder = builder.route(hop);
        }
        if let Some(ref contact) = request.contact {
            builder = builder.contact(contact);
        }
        for (name, value) in minted.credentials {
            builder = builder.header(*name, value.as_bytes());
        }
        builder = add_extra(
            builder,
            &request.extra,
            minted.supported.is_some(),
            minted.credentials,
        )?;
        if let (Some(kind), Some(body)) = (request.content_type.as_deref(), request.body.as_deref())
        {
            builder = builder.body(kind, body);
        }
        Ok(builder.build()?)
    }

    /// Finish a request the dialog planned and pick its flow. §18.1.1 applies here since every
    /// in-dialog request, the 2xx ACK included, passes through. The dialog keeps its own flow; a
    /// `CSeq` drawn for a failed attempt is not reused (§12.2.2).
    pub(super) fn build_in_dialog(
        &mut self,
        plan: &InDialogRequest,
        flow: Flow,
        extra: Option<&OutgoingInDialogRequest>,
        body: Option<&[u8]>,
    ) -> Result<(OwnedMessage, Flow), SendError> {
        let local = self
            .transports
            .get(flow.transport)
            .ok_or(SendError::UnknownTransport)?
            .local;
        let branch = self.tokens.branch();
        let message = self.assemble_in_dialog(plan, flow, local, &branch, extra, body)?;
        let message = self.written_for_the_datagram(flow, message)?;
        let promoted = {
            let call = message.as_raw().call_id().ok();
            self.promote_if_too_big(flow, message.len(), call)?
        };
        match promoted {
            None => Ok((message, flow)),
            Some((stream, local)) => {
                let message = self.assemble_in_dialog(plan, stream, local, &branch, extra, body)?;
                Ok((message, stream))
            }
        }
    }

    fn assemble_in_dialog(
        &self,
        plan: &InDialogRequest,
        flow: Flow,
        local: SocketAddr,
        branch: &[u8],
        extra: Option<&OutgoingInDialogRequest>,
        body: Option<&[u8]>,
    ) -> Result<OwnedMessage, SendError> {
        let via = self.via_on(flow.transport, flow.protocol, local, branch);

        let mut builder = plan
            .builder()
            .via(&via)
            .max_forwards(extra.map_or(70, |extra| extra.max_forwards));
        if let Some(extra) = extra {
            if let Some(ref contact) = extra.contact {
                builder = builder.contact(contact);
            }
            builder = add_extra(builder, &extra.extra, false, &[])?;
            if let (Some(kind), Some(body)) = (extra.content_type.as_deref(), body) {
                builder = builder.body(kind, body);
            }
        } else if let Some(body) = body {
            // the 2xx ACK, carrying the answer
            builder = builder.body(b"application/sdp", body);
        }
        Ok(builder.build()?)
    }
}

pub(super) fn build_response(
    request: &OwnedMessage,
    response: &OutgoingResponse,
    tag: Option<&[u8]>,
) -> Result<OwnedMessage, RespondError> {
    let raw = request.as_raw();
    let mut builder = ResponseBuilder::for_request(&raw, response.status);
    // §8.2.6.2: the same tag on every response but a 100
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
    // last, so a field the endpoint owns is refused rather than duplicated
    for extra in &response.extra {
        let (name, value) = extra.field()?;
        builder = builder.header(name, value);
    }
    if let (Some(kind), Some(body)) = (response.content_type.as_deref(), response.body.as_deref()) {
        builder = builder.body(kind, body);
    }
    Ok(builder.build()?)
}

/// Everything the caller added by name, minus a `Supported` the endpoint already merged.
///
/// # Errors
/// [`BuildError::OwnedField`] for a field in [`super::ENDPOINT_FIELDS`],
/// [`BuildError::IllegalValue`] for a bad name.
fn add_extra<'a>(
    mut builder: RequestBuilder<'a>,
    extra: &'a [Extra],
    supported_written: bool,
    credentials: &[(HeaderName<'static>, String)],
) -> Result<RequestBuilder<'a>, BuildError> {
    for one in extra {
        let (name, value) = one.field()?;
        if supported_written && name == HeaderName::Supported {
            continue;
        }
        // the endpoint's own credentials win; two for one realm leave the server guessing
        if credentials.iter().any(|(written, _)| *written == name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    Ok(builder)
}

/// What the caller put in `Supported`, with `100rel` in it.
fn offering_100rel(extra: &[Extra]) -> Box<[u8]> {
    let mut out: Vec<u8> = Vec::new();
    for one in extra {
        let Some((name, value)) = one.parts() else {
            continue;
        };
        if name != HeaderName::Supported {
            continue;
        }
        if !out.is_empty() {
            out.extend_from_slice(b", ");
        }
        out.extend_from_slice(value);
    }
    let has_it = out
        .split(|byte| *byte == b',')
        .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"100rel"));
    if has_it {
        return out.into_boxed_slice();
    }
    if !out.is_empty() {
        out.extend_from_slice(b", ");
    }
    out.extend_from_slice(b"100rel");
    out.into_boxed_slice()
}

/// What the endpoint chose for one request.
struct Minted<'a> {
    branch: &'a [u8],
    from: &'a [u8],
    to: &'a [u8],
    call_id: &'a [u8],
    cseq: u32,
    supported: Option<&'a [u8]>,
    /// Credentials for a remembered challenge.
    credentials: &'a [(HeaderName<'static>, String)],
}

/// Whether a request asks for TLS under RFC 3261 §26.2.2: a `sips:` Request-URI, first `Route`,
/// `Contact` (§8.1.1.8), or REGISTER `To` (§10.2).
fn asks_for_tls(request: &OutgoingRequest) -> bool {
    let sips = |value: &[u8]| {
        crate::msg::NameAddrRef::parse(value).is_ok_and(|addr| addr.uri().scheme().is_secure())
    };
    request.request_uri.is_secure()
        || request.route.first().is_some_and(|hop| sips(hop))
        || request.contact.as_deref().is_some_and(sips)
        || (request.method.as_ref() == Method::Register.as_str().as_bytes()
            && request.to.as_deref().is_some_and(sips))
}

fn has_tag(value: &[u8]) -> bool {
    crate::msg::NameAddrRef::parse(value).is_ok_and(|addr| addr.tag().is_some())
}

fn with_tag(value: &[u8], tag: &[u8]) -> Box<[u8]> {
    let mut out = Vec::with_capacity(value.len() + tag.len() + 5);
    out.extend_from_slice(value);
    out.extend_from_slice(b";tag=");
    out.extend_from_slice(tag);
    out.into_boxed_slice()
}
