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

/// Something that is neither a transaction nor a dialog, and still has to
/// happen at a particular time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Deadline {
    /// A double CRLF is due on a byte stream (RFC 5626 §4.4.1).
    Keepalive(TransportId),
    /// A ping has gone unanswered long enough that §4.4.1 calls the flow dead.
    PongOverdue(TransportId),
    /// A reliable provisional response has to go out again (RFC 3262 §3).
    Reliable(Raw),
    /// 64·T1 after a non-INVITE server transaction was created, RFC 3261
    /// §17.2.2 gives its `Trying`/`Proceeding` states no timer of their own,
    /// so an application that never answers holds the slot forever. This is
    /// the endpoint's own: a no-op when it fires against a transaction that
    /// already has a final response, and taken off the schedule when the
    /// transaction retires before it fires.
    UnansweredNonInvite(TransactionId<NonInviteServer>),
}

/// One whole message framed off a connection, as it arrived, for a trace
/// ([`Endpoint::tap_streams`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamMessage {
    /// The connection it arrived on.
    pub transport: TransportId,
    /// Its far end, or `None` for a connection bound without one named
    /// (`Input::TransportBound`'s `remote`).
    pub remote: Option<SocketAddr>,
    /// The message, from its start line to the end of its body.
    pub bytes: Box<[u8]>,
}

/// What an endpoint has had to send twice, and what it stopped waiting for,
/// since it was created.
///
/// Every figure only ever grows. Over UDP each one is a message the network
/// lost, or delivered too late to count: a request goes out again when timer
/// A or E fires with no answer, a response when timer G fires with no ACK or
/// when the far end's own request arrives again because the answer to it did
/// not. Over TCP and TLS nothing retransmits at the transaction layer
/// (RFC 3261 §17.1.1.2), so there the first two stay at zero and only a
/// timeout moves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Retransmissions {
    /// Requests sent again: timers A and E (§17.1.1.2, §17.1.2.2), and an
    /// ACK repeated because the 2xx it acknowledges arrived again
    /// (§13.2.2.4).
    pub requests: u64,
    /// Responses sent again: timer G (§17.2.1), a reliable provisional
    /// response's own timer (RFC 3262 §3), and the last response of a server
    /// transaction repeated because its request arrived again (§17.2.1,
    /// §17.2.2).
    pub responses: u64,
    /// Transactions that ended because the far end never answered or never
    /// acknowledged: timer B or F with no final response, timer H or L with
    /// no ACK, and a reliable provisional response never PRACKed for 64·T1.
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
    /// The `Reason` value (RFC 3326) the CANCEL of each INVITE is to carry,
    /// when it was asked for with one: kept here because a CANCEL asked for
    /// before any provisional response goes only once one arrives (§9.1).
    pub(super) cancel_reasons: HashMap<TransactionId<InviteClient>, Box<[u8]>>,
    /// Reliable provisional responses in both directions (RFC 3262).
    pub(super) reliable: Reliables,
    /// The INVITEs and UPDATEs running inside dialogs (RFC 3261 §14), which
    /// are the ones that cross.
    pub(super) reinvites: Reinvites,
    /// Requests that were refused with a challenge, waiting for a password.
    pub(super) challenges: Challenges,
    /// Requests outside a dialog that found no server, kept for
    /// [`Endpoint::send_elsewhere`] (RFC 3263 §4.3).
    pub(super) unreached: super::failover::Unreached,
    /// Which dialog a client transaction is inside, when it is inside one.
    /// A retry after a challenge has to take its `CSeq` from there.
    pub(super) dialogs_of: HashMap<AnyTransactionId, DialogId>,
    /// What each destination has already challenged with, so that the next
    /// request to it can carry credentials instead of paying for a refusal
    /// (§22.2), and so that a second refusal with the same nonce can be told
    /// from a fresh challenge. §22.1 does not answer the first twice.
    pub(super) known: Known,
    /// How many requests have been refused for want of room. Only ever grows,
    /// because the number an operator wants is "how often has this happened",
    /// not "how often since somebody last looked".
    pub(super) refused: u64,
    /// How many messages the parser refused, answered or not. Only ever
    /// grows, for the same reason [`Endpoint::refused`] does.
    pub(super) unreadable: u64,
    /// What had to go out twice, and what was never answered.
    pub(super) retransmissions: Retransmissions,
    /// Calls let in under [`EndpointConfig::max_dialogs`] that have not opened
    /// their dialog yet.
    ///
    /// The dialog of an incoming call is made by this end's own 180 or 2xx,
    /// long after the ceiling was applied to its INVITE, so each call holds
    /// the room its dialog will take from the moment it is admitted until a
    /// response opens the dialog or a refusal says there will be none.
    pub(super) admitted: HashSet<TransactionId<InviteServer>>,
    /// The deadline `Deadline::UnansweredNonInvite` hung on each non-INVITE
    /// server transaction still live, so that retiring one takes its deadline
    /// with it. A transaction answered at once on a stream retires at once,
    /// and a deadline left behind would outlive it by 64·T1: the schedule
    /// would then grow with the rate requests arrive rather than stay within
    /// what `max_server_transactions` lets a peer hold.
    pub(super) unanswered: HashMap<TransactionId<NonInviteServer>, TimerHandle>,
    /// What this endpoint decided, per call and for itself
    /// (`docs/14-diagnostics.md`).
    pub(super) diag: Records,
    /// Where `Event::TransportWanted` asked for a stream that nobody has
    /// bound yet.
    pub(super) streams_wanted: HashSet<SocketAddr>,
    /// Where the caller said no stream is coming
    /// ([`Endpoint::no_stream_coming`]), until one is bound after all.
    pub(super) streamless: HashSet<SocketAddr>,
    /// The stream transports pinged at an interval of their own rather than
    /// at [`EndpointConfig::keepalive_interval`]
    /// ([`Endpoint::keep_stream_alive`]). Keyed by name rather than kept on
    /// the open transport, so that a connection bound again under the same
    /// name keeps the interval its owner asked for.
    pub(super) stream_keepalives: HashMap<TransportId, core::time::Duration>,
    /// Every message framed off a connection since the last
    /// [`Endpoint::take_stream_messages`], while [`Endpoint::tap_streams`]
    /// has it kept; `None` while it does not.
    pub(super) stream_tap: Option<Vec<StreamMessage>>,
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
    ///
    /// # Errors
    /// [`TimerConfigError`] when `config.timers` cannot be armed at all —
    /// [`crate::transaction::TimerConfig::validate`]'s doc says which values
    /// and why — and [`TimerConfigError::KeepaliveUnarmable`] for a
    /// `keepalive_interval` of zero. Accepting one of those would not fail
    /// later; it would make timer A, E or G, or the next keep-alive, re-arm at
    /// the instant it just fired, and `handle_timeout` would never return.
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

    /// Keep a copy of every message framed off a connection, whole, for
    /// [`Endpoint::take_stream_messages`] to hand over — or stop, and drop
    /// what was kept.
    ///
    /// A datagram is a message already, and a caller that traces one has it
    /// in hand. What arrives on a connection is bytes in whatever sizes the
    /// reads came in (§18.3), and only the framing here knows where one
    /// message ends: a trace written off the reads would cut messages in two
    /// and run two together. Off by default, since the copy is only worth
    /// its cost to a caller that writes it somewhere.
    pub fn tap_streams(&mut self, on: bool) {
        match (on, self.stream_tap.is_some()) {
            (true, false) => self.stream_tap = Some(Vec::new()),
            (false, true) => self.stream_tap = None,
            _ => {}
        }
    }

    /// The messages [`Endpoint::tap_streams`] kept, in the order they were
    /// framed, and none of them again. Empty when the tap is off.
    pub fn take_stream_messages(&mut self) -> Vec<StreamMessage> {
        self.stream_tap
            .as_mut()
            .map(core::mem::take)
            .unwrap_or_default()
    }

    /// The stream a `TransportWanted` asked for cannot be had: the caller
    /// tried and failed, or opens none.
    ///
    /// Under [`DatagramLimit::without_stream_bytes`](super::DatagramLimit::without_stream_bytes),
    /// every address a stream was asked for is from now on sent a request up
    /// to that size over the datagram — the retries held back for want of the
    /// stream included, once the caller sends them again — each one recorded
    /// as `transport.kept.datagram`; until a stream to that address is bound,
    /// which is preferred again from then on. Without it, nothing changes.
    ///
    /// `true` when something did: a request held back may now go.
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
    /// [`ReceiveError`] when the transport is unknown or the bytes are not a
    /// message. Neither is a fault of this endpoint: a malformed datagram is
    /// the normal case on a public SIP port, and the caller logs it and
    /// carries on — a request among them has already been answered when it
    /// could be ([`Endpoint::unreadable`]). On a byte stream only lost framing
    /// is returned, and it is fatal to the connection, which the endpoint has
    /// already forgotten by the time the error is returned.
    pub fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        self.mark(now);
        match input {
            Input::TransportBound {
                transport,
                protocol,
                local,
                remote,
            } => {
                // RFC 5626 §4.4.1 is about a flow, not about a name. The
                // caller reused the identifier, so the deadlines of the
                // connection that is gone are still on the schedule, and the
                // pong one would call the replacement dead ten seconds
                // later. A timer handle carries the sequence number it was
                // issued with and those are never reused, so cancelling a
                // stale one cannot reach a deadline belonging to the
                // replacement.
                let replaced =
                    self.transports
                        .bind(transport, protocol, local, remote, self.config.limits);
                if let Some(old) = replaced {
                    for handle in [old.keepalive, old.pong].into_iter().flatten() {
                        self.deadlines.cancel(handle);
                    }
                }
                // a stream after all: what was asked for is had, and what was
                // sent over the datagram for want of it goes on the stream
                if protocol.is_reliable() {
                    if let Some(remote) = remote {
                        self.streams_wanted.remove(&remote);
                        self.streamless.remove(&remote);
                    } else {
                        // bound without a far end, it may carry anything
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
    ///
    /// [`Transmit::payload`] is the message exactly as it goes on the wire, so
    /// its length **is** the on-wire size of every request and response this
    /// endpoint sends, and there is no counter or event here that would say it
    /// any better. An application that wants that size logged has it in hand
    /// at the point it writes the bytes:
    ///
    /// ```ignore
    /// while let Some(transmit) = endpoint.poll_transmit() {
    ///     eprintln!("{} bytes to {}", transmit.payload.len(), transmit.destination);
    ///     socket.send_to(&transmit.payload, transmit.destination)?;
    /// }
    /// ```
    ///
    /// The one size that is *not* in hand there is the size of a request that
    /// never became a `Transmit` because §18.1.1 refused it, and that one
    /// arrives as [`Event::TransportWanted`] with the limit beside it.
    ///
    /// An application that would rather not log at all has both sizes without
    /// doing anything: they are in the call's record
    /// ([`Endpoint::call_record`], `docs/14-diagnostics.md`).
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

    /// An unguessable token from the stream this endpoint's own branches, tags
    /// and `Call-ID`s come from.
    ///
    /// The layer above needs them too — §10.2.4 wants one `Call-ID` for every
    /// registration of a boot cycle, and something has to mint it — and
    /// drawing from this one guarantees the values never collide with a
    /// branch.
    ///
    /// This is the stream for everything that goes on the wire in clear, and
    /// only for that. Media keys come from a generator of their own, seeded
    /// separately, because a replay recording carries the seed this stream
    /// runs on while it records ([`Endpoint::reseed`]) and a recording must
    /// not carry the means to decrypt what it recorded.
    #[must_use]
    pub fn token(&mut self) -> Box<[u8]> {
        self.tokens.token()
    }

    /// Move the stream every branch, tag, `Call-ID` and client nonce comes
    /// from onto a seed of its own, and return that seed.
    ///
    /// The seed comes from a second stream derived one way from the one
    /// [`Endpoint::new`] was given, so it says nothing about that seed and
    /// nothing about the seed the next call here moves to. It is what a
    /// replay recording started now carries (`docs/18-replay.md`): a replay
    /// built with it draws exactly what this endpoint draws from here on,
    /// and once the recording ends, calling this again leaves the recording
    /// unable to predict any identifier drawn after it.
    pub fn reseed(&mut self) -> [u8; 32] {
        self.tokens.reseed()
    }

    /// What a bound transport speaks and the address it was bound at — the
    /// one that goes in its `Via` — or `None` for one that is not bound.
    ///
    /// For a layer above that has to know whether a flow is a datagram one
    /// and where it is bound, without having kept its own copy of what it
    /// said when it bound it: keeping a UDP flow's NAT binding open is that
    /// layer's, and only when the address the flow is seen from outside is
    /// not the one it is bound at.
    #[must_use]
    pub fn bound_transport(
        &self,
        transport: TransportId,
    ) -> Option<(TransportProtocol, SocketAddr)> {
        self.transports
            .get(transport)
            .map(|bound| (bound.protocol, bound.local))
    }

    /// A bound transport of `protocol` that carries a message to
    /// `destination`: one connected to it, or an unconnected one of that
    /// protocol, the first found. For a layer above that keeps an account on
    /// a flow of its own and adopts whichever transport the application
    /// bound for it.
    #[must_use]
    pub fn transport_to(
        &self,
        protocol: TransportProtocol,
        destination: SocketAddr,
    ) -> Option<TransportId> {
        self.transports.speaking_to(protocol, destination)
    }

    /// The address one bound transport is bound at, any of them: the family
    /// a name is looked up for when the transport an account will use is not
    /// bound yet.
    #[must_use]
    pub fn any_bound_address(&self) -> Option<SocketAddr> {
        self.transports.any_local()
    }

    /// Ping the stream transport `transport` every `every` rather than every
    /// [`EndpointConfig::keepalive_interval`], or with `None` go back to the
    /// endpoint's own interval (RFC 5626 §4.4.1's double CRLF, jittered
    /// between 80% and 100% of the interval like every other ping here).
    ///
    /// For a layer above that knows a flow needs to be kept open more often
    /// than the endpoint as a whole does — an account behind a NAT that
    /// forgets a connection sooner than the default — or at all, when the
    /// endpoint's own keep-alive is off. The interval is kept under the
    /// transport's name, so a connection bound again under it keeps it; a
    /// datagram transport, or a name not bound yet, is pinged only once it is
    /// a stream. What was scheduled on the transport is drawn again from the
    /// new interval at once.
    ///
    /// # Errors
    /// [`TimerConfigError::KeepaliveUnarmable`] for an interval of zero, which
    /// would re-arm a ping at the instant it went; nothing changes.
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

    /// The interval a stream transport is pinged at, as
    /// [`Endpoint::keep_stream_alive`] and the configuration leave it, or
    /// `None` when it is not pinged at all.
    #[must_use]
    pub fn stream_keepalive(&self, transport: TransportId) -> Option<core::time::Duration> {
        self.keepalive_interval_of(transport)
    }

    /// What this endpoint was configured with, as it stands.
    #[must_use]
    pub const fn config(&self) -> &EndpointConfig {
        &self.config
    }

    /// How many transactions and dialogs are live, for a caller that wants to
    /// know whether it can shut down.
    #[must_use]
    pub fn in_flight(&self) -> (usize, usize) {
        (self.transactions.len(), self.dialogs.len())
    }

    /// How many requests have been refused with a 503 for want of room
    /// ([`EndpointConfig::max_server_transactions`],
    /// [`EndpointConfig::max_dialogs`]).
    ///
    /// The same number [`Event::Overloaded`] carries, for a caller that would
    /// rather sample a gauge than watch events go by.
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.refused
    }

    /// How many messages arrived that the parser refused — past one of
    /// [`EndpointConfig::limits`], or not a SIP message at all — whether or
    /// not an answer could be written to them.
    ///
    /// A request is answered 400 or 513 whenever the fields a response is
    /// built from can still be recovered, and each one that is also leaves a
    /// `request.refused.unreadable` entry in [`Endpoint::endpoint_record`];
    /// one that cannot be answered — a response, an ACK, a request with no
    /// `Via` to send an answer to — leaves `message.dropped.unreadable`
    /// instead. This is both, counted, for a caller that samples numbers
    /// rather than reading records.
    #[must_use]
    pub const fn unreadable(&self) -> u64 {
        self.unreadable
    }

    /// What this endpoint has sent again, and how many transactions it gave
    /// up on, since it was created: the numbers that say a path is losing
    /// messages before any call fails on it.
    #[must_use]
    pub const fn retransmissions(&self) -> Retransmissions {
        self.retransmissions
    }

    /// How many times one transaction has sent its request or its response
    /// again, while it is live; `None` once it has ended or for a handle
    /// that never named one.
    #[must_use]
    pub fn transaction_retransmissions(&self, id: impl Into<AnyTransactionId>) -> Option<u32> {
        self.transactions.retransmissions(id.into())
    }

    /// Count a message that went out again: a request or a response, and the
    /// transaction it belongs to when it belongs to one.
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

    /// Count a transaction the far end left unanswered or unacknowledged.
    pub(super) const fn count_timeout(&mut self) {
        self.retransmissions.timeouts = self.retransmissions.timeouts.saturating_add(1);
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
        self.cancel_reasons.remove(&id);
    }

    /// Record that a client transaction is inside a dialog.
    pub(super) fn remember_dialog(&mut self, id: AnyTransactionId, dialog: DialogId) {
        self.dialogs_of.insert(id, dialog);
    }

    /// The dialog a client transaction is inside.
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
        self.send_request(request, None, now)
    }

    /// The same, carrying credentials for a challenge this destination has
    /// already made (§22.2).
    ///
    /// "UAs SHOULD cache the credentials for a given value of the To header
    /// field and 'realm' and attempt to re-use these values on the next
    /// request for that destination." Nothing goes on the request unless this
    /// endpoint has been challenged by that destination and the challenge is
    /// still worth answering, so this is safe to use for the first request as
    /// well as for the tenth; what it saves is the 401 and the round trip
    /// after it, which a registration that refreshes every hour was otherwise
    /// paying for every hour.
    ///
    /// The password is borrowed for the length of the call and not kept. What
    /// the endpoint keeps is the nonce, the client nonce and the count, which
    /// have to have one owner: `nc` "MUST" differ on every request carrying
    /// the same nonce, and two places counting would repeat one.
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

    /// Place a call carrying credentials for a challenge this destination has
    /// already made, as [`Endpoint::request_with_credentials`].
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

    /// Give up on a call that has not been answered (§9.1).
    ///
    /// Always accepted while the transaction is live. A CANCEL may not go
    /// before a provisional response has arrived — the server could otherwise
    /// receive it before the INVITE and have nothing to cancel — so one asked
    /// for too early is held and released at the first provisional. The caller
    /// never has to time that itself; [`Event::CancelSent`] says when it went.
    /// Asking again while that CANCEL is still running sends nothing more: it
    /// is a transaction of its own, and retransmits itself.
    ///
    /// # Errors
    /// [`CancelError`] when the transaction is unknown, or has already been
    /// answered with a final response.
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

    /// [`Endpoint::cancel`], with a `Reason` (RFC 3326 §2) on the CANCEL:
    /// `reason` is the field's value as it goes on the wire, one or several
    /// comma-separated reason-values.
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

    /// Acknowledge a 2xx (§13.2.2.4).
    ///
    /// Called once. The ACK may carry the answer when the offer came in the
    /// 2xx, which is why the caller builds it rather than the endpoint, and
    /// why the endpoint cannot know when it is ready. After this the ACK
    /// belongs to the dialog: every retransmitted 2xx is answered with the
    /// same bytes, and the caller hears nothing more about it.
    ///
    /// The ACK is held to §18.1.1 like any other request, and one too large
    /// for a datagram goes on a stream to the same address. Every
    /// retransmission of the 2xx is answered on that same flow while it is
    /// open, not on the one the 2xx came in on; once it has closed, on another
    /// stream to that address, or not until the caller has opened one.
    ///
    /// # Errors
    /// [`AckError`] when the dialog is unknown, has no 2xx to acknowledge, or
    /// has already been acknowledged. [`AckError::Build`] carrying
    /// [`SendError::NeedsStreamTransport`] when the ACK does not fit a
    /// datagram and no stream is open: nothing is kept, and the same call
    /// sends it once the transport is bound.
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
    /// As [`Endpoint::request_in_dialog`]. A BYE refused with
    /// [`SendError::NeedsStreamTransport`] has not been passed to a
    /// transaction, so the dialog is not over and the same call hangs it up
    /// once the transport is bound.
    pub fn bye(
        &mut self,
        dialog: DialogId,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        self.bye_with(dialog, &OutgoingInDialogRequest::new(Method::Bye), now)
    }

    /// Hang up with a BYE of the caller's own: the one an application ends a
    /// call with carries the header fields it added.
    ///
    /// # Errors
    /// [`SendError::WrongMethod`] for a request that is not a BYE, because
    /// what follows the send is the end of the dialog and nothing else ends
    /// one. Otherwise as [`Endpoint::bye`].
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
    /// built, and [`SendError::NeedsStreamTransport`] when it is too large for
    /// a datagram with no stream open to the dialog's next hop (§18.1.1).
    pub fn request_in_dialog(
        &mut self,
        dialog: DialogId,
        request: &OutgoingInDialogRequest,
        now: Instant,
    ) -> Result<TransactionId<NonInviteClient>, SendError> {
        self.mark(now);
        // an INVITE runs on a different machine and owns an ACK of its own;
        // sending one from here would give it a non-INVITE transaction and no
        // way to acknowledge the 2xx
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

    /// Renegotiate inside a dialog: hold, resume, a codec change (§14.1).
    ///
    /// The `Contact` is required and not defaulted. §8.1.1.8 makes it a MUST
    /// on any request that can establish a dialog, a re-INVITE refreshes the
    /// target the far end will address the rest of the call to, and the
    /// endpoint does not know what this end is reachable as — it was told a
    /// transport and a peer address, not a public URI.
    ///
    /// The response comes back as [`Event::ReinviteAnswered`] and is
    /// acknowledged with [`Endpoint::ack_reinvite`], not with
    /// [`Endpoint::ack_2xx`]: a re-INVITE never forks, so there is no set of
    /// dialogs to say which one is being acknowledged.
    ///
    /// # Errors
    /// [`SendError::InviteInProgress`] when another INVITE is already running
    /// in the dialog — §14.1 makes a second one a MUST NOT, and glare is
    /// exactly what that rule prevents. Otherwise as
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
        // §14.1: "a UAC MUST NOT initiate a new INVITE transaction within a
        // dialog while another INVITE transaction is in progress in either
        // direction"
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
    /// [`RespondError`] when the transaction is unknown or has already sent a
    /// final response.
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

    /// Open a dialog around a request that arrived outside one
    /// (RFC 6665 §4.4.1).
    ///
    /// The one method that needs this is NOTIFY. A SUBSCRIBE creates no dialog
    /// when it is answered — §4.4.1: "the dialog usage is established by the
    /// NOTIFY request, the route set at the subscriber is taken from the
    /// NOTIFY request itself, as opposed to the route set present in the
    /// 200-class response to the SUBSCRIBE request" — so the subscriber's side
    /// of the dialog is built here, from the notification, and everything
    /// afterwards is an ordinary in-dialog request.
    ///
    /// `local_seq` is the sequence number of the request this end already sent
    /// outside the dialog, so that the refresh continues the series rather than
    /// restarting it; see [`Dialog::resume_from`](crate::dialog::Dialog::resume_from).
    /// `None` for a caller with nothing to continue.
    ///
    /// `None` comes back when the transaction has gone, or when the request
    /// cannot name a dialog: no tag in `To` — which is our own tag echoed
    /// back, so a request without one matched nothing to begin with — no
    /// `Contact` to address later requests to, or an address that will not
    /// parse.
    ///
    /// Call it **before** answering the request, not after. The dialog is
    /// built from the request and the flow it arrived on, and both live on the
    /// server transaction — which §17.2.2 retires the moment a final response
    /// goes out on a reliable transport, because Timer J is zero there.
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
        // 12.1.1 has the state a dialog starts in decided by the response;
        // there is no early half here, so the dialog exists confirmed or not
        // at all
        let dialog = self.open_uas_dialog(&request, &tag, StatusCode::OK, flow)?;
        if let (Some(seq), Some(state)) = (local_seq, self.dialogs.get_mut(dialog)) {
            state.resume_from(seq);
        }
        Some(dialog)
    }

    /// Open the dialog this end's 2xx to a request outside one creates, the
    /// answering side's own half of [`Endpoint::open_dialog`] (RFC 3261
    /// §12.1.1).
    ///
    /// The method that needs it is REFER. RFC 3515 §2.4.4 has the NOTIFYs a
    /// REFER asks for carry "the dialog identifiers (To, From, and Call-ID)
    /// ... of the REFER as they would if the REFER had been a SUBSCRIBE
    /// request", and one that arrived outside any dialog has no `To` tag to
    /// read them from: the tag is the one this end is about to write into its
    /// answer. So the dialog is built around that tag — the same one
    /// [`Endpoint::respond`] then writes, because both draw it from the one
    /// kept for this transaction — and the far end's own `From` tag.
    ///
    /// `None` when the transaction has gone, when the request already names a
    /// dialog (a `To` tag it carries is a dialog this end does not have, and
    /// nothing is opened around somebody else's), or when it cannot open one:
    /// no `Contact`, or one that will not parse.
    ///
    /// Call it **before** answering the request, for the reason
    /// [`Endpoint::open_dialog`] gives.
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

    /// Forget a dialog whose usage is over, when nothing on the wire ends it
    /// (RFC 6665 §4.4.1).
    ///
    /// The counterpart of [`Endpoint::open_dialog`], and the other half of a
    /// subscription's life: "the destruction of a subscription results in the
    /// termination of its associated dialog", and there is no request that
    /// says so — the closing NOTIFY has already been answered. Without this a
    /// phone watching thirty extensions across a day of re-subscriptions
    /// accumulates a dialog per attempt and never gives one back.
    ///
    /// A [`Event::DialogTerminated`] with
    /// [`DialogEndReason::Closed`](super::DialogEndReason::Closed) follows,
    /// so anything above that was holding the handle hears about it the same
    /// way it hears about a BYE. Calling it twice does nothing the second
    /// time.
    pub fn close_dialog(&mut self, dialog: DialogId) {
        if let Some(state) = self.dialogs.get_mut(dialog) {
            state.terminate();
        }
        self.forget_dialog(dialog, super::event::DialogEndReason::Closed);
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

        // RFC 3262 §3: "The UAS MUST send any non-100 provisional response
        // reliably if the initial request contained a Require header field
        // with the option tag 100rel"
        if status.is_provisional()
            && status.get() >= 101
            && super::reliable::demands_100rel(&request.as_raw())
        {
            return Err(RespondError::MustBeReliable);
        }
        // §3: a final response stops the retransmissions of anything still
        // unacknowledged, without forgetting it — a PRACK for one may still
        // arrive and still has to be answered
        if status.is_final() {
            self.quiet_reliable(transaction);
        }

        // §12.1.1: only a 101-199 or a 2xx opens a dialog. A 100 names
        // nothing, and a failure ends whatever was already open
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
        // §13.2.2.4: the ACK this 2xx is owed carries this INVITE's own
        // number, whatever the dialog has seen from the far end since
        if status.is_success()
            && let Some(dialog) = dialog
            && let Ok(seq) = request.as_raw().cseq().map(|cseq| cseq.seq)
        {
            self.dialogs.answer_invite(dialog, seq, transaction);
        }
        self.end_refused_early(transaction, early);
        // a dialog opened, or a final response said there will be none: the
        // call holds no room of its own any more either way
        if dialog.is_some() || status.is_final() {
            self.admitted.remove(&transaction);
        }
        // §14.2's rule is about "a second INVITE before it sends the final
        // response to a first", so the dialog is free for another one here
        if status.is_final() {
            self.reinvites
                .answered_theirs(AnyTransactionId::InviteServer(transaction));
        }
        Ok(dialog)
    }
}

// -- building ---------------------------------------------------------------

impl Endpoint {
    /// Turn what the caller described into bytes, and decide where they go.
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
        // §22.2's re-use, when the caller handed over a password and this
        // destination has challenged before. Drawn here rather than in
        // `assemble` because a step of the nonce count spent twice on one
        // request is a replay as far as the server is concerned. Drawing it
        // does not spend it: the size rule below can still refuse to send
        // this, and a number that never reaches the wire must not be gone.
        let answers = match credentials {
            Some(credentials) => self.answer_ahead(request, credentials, &call_id),
            None => Answered::default(),
        };
        // RFC 3262 §4: "The UAC SHOULD include this in all INVITE requests."
        // Without it the far end may not answer reliably, and an offer in a
        // 1xx has no recovery from a lost datagram
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

        // 18.1.1: too large for a datagram means it leaves over something
        // congestion controlled, and the Via has to say so
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

        // The bytes are settled, so the count the answer used is now a count
        // that has gone out. Above this line every path out is an error, and
        // an answer drawn on one of those is dropped with its number unspent.
        if !answers.is_empty()
            && let Some(to) = request.to.as_deref().and_then(super::auth::destination)
        {
            self.spend_answer(&to, &answers);
        }

        Ok((message, flow))
    }

    /// §18.1.1 for a request assembled somewhere other than `build_request`.
    ///
    /// `None` when the datagram carries it. Otherwise the flow to send it on
    /// instead and the address its `Via` has to name, or
    /// [`SendError::NeedsStreamTransport`] when there is no connection to use
    /// and the caller has been asked to open one.
    ///
    /// The switch belongs wherever a request is built rather than only on the
    /// path that happened to have it. The request that fragmented in the field
    /// and died in silence was the one carrying `Authorization` — three
    /// hundred bytes larger than the attempt that had fitted, and built by the
    /// retry rather than by the first send.
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

    /// The flow a kept ACK is passed to again when its 2xx is retransmitted
    /// (§13.2.2.4).
    ///
    /// The one it first left on, for as long as that transport is open:
    /// §18.1.1 may have made it a stream the 2xx does not arrive on. Once that
    /// transport has gone, the flow the 2xx arrived on, held to §18.1.1 as the
    /// first ACK was — a stream to the same address when one is open, and
    /// `None` when none is and the caller has been asked for one.
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

    /// §18.1.1 moved a request off the datagram it did not fit in.
    ///
    /// The size and the limit go down together, because either on its own is
    /// the number that made a fragmented request read as "authentication is
    /// broken" for two days.
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

    /// Whether a request too large for a datagram goes over one anyway: no
    /// stream is coming to its address ([`Endpoint::no_stream_coming`]), none
    /// is open there, and it fits
    /// [`DatagramLimit::without_stream_bytes`](super::DatagramLimit::without_stream_bytes).
    /// Written down, measured against that limit, when it does.
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

    /// The largest request that would still have gone in a datagram.
    ///
    /// Nothing fits at all is reported as nothing fits, which is what a path
    /// MTU below the §18.1.1 headroom means.
    pub(super) fn datagram_limit_bytes(&self) -> u32 {
        self.config
            .datagram_limit
            .largest_datagram_request()
            .unwrap_or(0)
    }

    /// The stream transport a request too large for a datagram leaves on,
    /// asking the caller for one when there is none.
    ///
    /// §18.1.1 recommends reusing a connection already open to "an IP address,
    /// port, and transport" the request is destined for, and that is also the
    /// only connection that would deliver it: writing a request to a
    /// connection open to somebody else sends it to somebody else. A transport
    /// bound without a far end is taken at its word, since only the caller
    /// knows what it is attached to.
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
        let via = via::local_via(
            flow.protocol,
            local,
            minted.branch,
            self.config.always_request_rport,
        );
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

    /// Finish a request the dialog has already decided everything about, and
    /// decide what carries it.
    ///
    /// §18.1.1 is applied here because this is the one path every request
    /// inside a dialog is built on, the ACK to a 2xx included — and that one
    /// no transaction carries, so nothing further down would ever look at its
    /// size. The flow that comes back is the one to send on: the dialog's own,
    /// or a stream to the same address when the request outgrew the datagram.
    /// The dialog keeps its flow either way. The rule is about the size of one
    /// request, and the next one may fit.
    ///
    /// With no stream to move to, the caller has been asked for one and
    /// nothing is kept. The sequence number the dialog drew for the attempt,
    /// for anything but an ACK, is not given back: §12.2.2 lets the far end
    /// see a gap, and a number reused after a request that went out in the
    /// meantime would reach it out of order.
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

    /// The bytes of one request inside a dialog, with the `Via` the flow it
    /// leaves on has to name.
    fn assemble_in_dialog(
        &self,
        plan: &InDialogRequest,
        flow: Flow,
        local: SocketAddr,
        branch: &[u8],
        extra: Option<&OutgoingInDialogRequest>,
        body: Option<&[u8]>,
    ) -> Result<OwnedMessage, SendError> {
        let via = via::local_via(
            flow.protocol,
            local,
            branch,
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
            builder = add_extra(builder, &extra.extra, false, &[])?;
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

pub(super) fn build_response(
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
    // after everything the endpoint wrote, so that a field it owns is refused
    // here rather than written a second time beside its own
    for extra in &response.extra {
        let (name, value) = extra.field()?;
        builder = builder.header(name, value);
    }
    if let (Some(kind), Some(body)) = (response.content_type.as_deref(), response.body.as_deref()) {
        builder = builder.body(kind, body);
    }
    Ok(builder.build()?)
}

/// Everything the caller added by name.
///
/// `Supported` is skipped when the endpoint has written its own: the two would
/// otherwise arrive as two lines of one field, which is legal but reads as a
/// stack that does not know what it supports. What it has written is the
/// caller's `Supported` with `100rel` merged in, so nothing is lost.
///
/// # Errors
/// [`BuildError::OwnedField`] for a field in [`super::ENDPOINT_FIELDS`], and
/// [`BuildError::IllegalValue`] for a name that is not a token.
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
        // the endpoint's own answer wins over one the caller wrote by
        // hand, for the same reason a retry replaces rather than stacks:
        // two sets of credentials for one realm is one of them ignored,
        // and which one is the server's guess
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

/// The values the endpoint chose for one request.
struct Minted<'a> {
    branch: &'a [u8],
    from: &'a [u8],
    to: &'a [u8],
    call_id: &'a [u8],
    cseq: u32,
    /// `Supported`, when the endpoint has something of its own to add to it.
    supported: Option<&'a [u8]>,
    /// `Authorization` and `Proxy-Authorization`, when a challenge from this
    /// destination is remembered and the caller handed over a password.
    credentials: &'a [(HeaderName<'static>, String)],
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
