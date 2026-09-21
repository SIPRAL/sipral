// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The TURN client: allocate, refresh, permit, bind, relay (RFC 8656).
//!
//! Sans-I/O on the same terms as the binding client. Nothing here opens a
//! socket, reads a clock or draws a random number: the caller hands in the
//! time, hands in transaction ids, hands in what arrived, and takes back what
//! to send and when to come back.
//!
//! The data path prefers channels. A Send indication costs thirty-six octets
//! of header on every packet and a ChannelData message costs four, so the
//! client installs the permission, binds a channel, and uses indications only
//! for the moment between the two.

use core::fmt;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::stun::binding::{
    FEATURE_PASSWORD_ALGORITHMS, Key, derive_key, response_is_authentic, security_features,
};
use crate::stun::{
    AttributeType, BuildError, Class, DEFAULT_RC, DEFAULT_RM, DEFAULT_RTO, Integrity,
    LongTermCredentials, Message, MessageBuilder, Method, PasswordAlgorithm, TransactionId,
    error_code,
};

use super::attribute::{
    self, AddressFamily, CHANNEL_LIFETIME, DEFAULT_LIFETIME, EvenPort, Icmp, PERMISSION_LIFETIME,
    PROTOCOL_UDP, ReservationToken, method,
};
use super::channel::{ChannelData, ChannelNumber, FIRST_CHANNEL, LAST_CHANNEL};
use super::framing::Transport;

/// "Ti SHOULD be configurable and SHOULD have a default of 39.5 s"
/// (RFC 8489 §6.2.2). It is the whole life of a transaction on a stream, where
/// TCP does the retransmitting.
pub const DEFAULT_TI: Duration = Duration::from_millis(39_500);

/// How long before something expires the client renews it.
///
/// "It is suggested that the client refresh the allocation roughly 1 minute
/// before it expires" (§8), and the same margin serves the permissions and the
/// channels, whose lifetimes are fixed at five and ten minutes.
const RENEW_MARGIN: Duration = Duration::from_secs(60);

/// "the client MUST wait 5 minutes after the channel binding expires before
/// attempting to bind the channel number to a different transport address or
/// the transport address to a different channel number" (§12).
const CHANNEL_QUARANTINE: Duration = Duration::from_secs(300);

/// How many different nonces one transaction may be sent under before the
/// exchange is called a loop rather than a renewal.
const MAX_STALE_NONCES: usize = 3;

/// How many transaction ids the client would like to be holding.
const POOL: usize = 8;

/// A ceiling on any single wait, so an absurd Rc still ends.
const MAX_INTERVAL: Duration = Duration::from_secs(600);

/// Which relayed address families to ask for (§7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FamilyRequest {
    /// Say nothing, and take what the server gives — which §7.2 says is IPv4.
    #[default]
    Whatever,
    /// One address, of this family, in REQUESTED-ADDRESS-FAMILY.
    Only(AddressFamily),
    /// One of each, in ADDITIONAL-ADDRESS-FAMILY. Saves a local port and a
    /// round trip against running two allocations.
    Dual,
}

/// How the client behaves.
#[derive(Debug)]
pub struct TurnConfig {
    /// How the client reaches the server.
    pub transport: Transport,
    /// The credential the server will ask for. A relay that hands out
    /// bandwidth to anyone who asks is a relay somebody else will use, so in
    /// practice this is always set.
    pub credentials: Option<LongTermCredentials>,
    /// What to put in SOFTWARE, if anything. Off by default: naming the exact
    /// build tells an attacker which bugs to try.
    pub software: Option<String>,
    /// Whether to add FINGERPRINT to requests.
    pub fingerprint: bool,
    /// The allocation lifetime to ask for. The server decides; the response
    /// says what it decided.
    pub lifetime: Option<Duration>,
    /// Which relayed address families to ask for.
    pub families: FamilyRequest,
    /// Whether to ask for an even relayed port, and for the next one to be
    /// held. Only pre-RFC 3550 RTP needs this.
    pub even_port: Option<EvenPort>,
    /// A port the server is already holding for us, from an earlier
    /// allocation that asked for one.
    pub reservation_token: Option<ReservationToken>,
    /// Whether to ask the relay to set the DF bit onward. Asking in the
    /// Allocate is how a client finds out whether the server can do it at all
    /// (§7.1).
    pub dont_fragment: bool,
    /// The first retransmission interval on a datagram transport.
    pub rto: Duration,
    /// Requests to send before giving up on a datagram transport.
    pub rc: u32,
    /// Multiples of `rto` to wait after the last one.
    pub rm: u32,
    /// How long a transaction lives on a stream transport, where there are no
    /// retransmissions to count.
    pub ti: Duration,
}

impl Default for TurnConfig {
    fn default() -> Self {
        Self {
            transport: Transport::Udp,
            credentials: None,
            software: None,
            fingerprint: true,
            lifetime: None,
            families: FamilyRequest::Whatever,
            even_port: None,
            reservation_token: None,
            dont_fragment: false,
            rto: DEFAULT_RTO,
            rc: DEFAULT_RC,
            rm: DEFAULT_RM,
            ti: DEFAULT_TI,
        }
    }
}

/// Something worth telling the caller about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The allocation exists and this is the address to hand to peers.
    Allocated {
        /// Where peers should send.
        relayed: SocketAddr,
        /// Where the server sees us from, offered as a convenience so an ICE
        /// agent need not run a separate binding transaction (§7.2).
        mapped: Option<SocketAddr>,
        /// What the server granted, which may be less than was asked for.
        lifetime: Duration,
    },
    /// The second relayed address of a dual allocation.
    AlsoAllocated {
        /// The other family's address.
        relayed: SocketAddr,
    },
    /// A dual allocation the server could only half satisfy (§7.3).
    FamilyRefused {
        /// The family that was refused.
        family: AddressFamily,
        /// 440 means never ask again; 508 means wait a minute.
        code: u16,
    },
    /// The allocation was renewed.
    Refreshed {
        /// What it is good for now.
        lifetime: Duration,
    },
    /// A peer may now reach the relayed address.
    PermissionInstalled {
        /// Whose address.
        peer: IpAddr,
    },
    /// It may not, and here is why.
    PermissionFailed {
        /// Whose address.
        peer: IpAddr,
        /// What went wrong.
        reason: TurnError,
    },
    /// The peer now has a four-byte header instead of a thirty-six byte one.
    ChannelBound {
        /// Whose address.
        peer: SocketAddr,
        /// The number bound to it.
        channel: ChannelNumber,
    },
    /// The binding did not happen, or stopped being true.
    ChannelFailed {
        /// Whose address.
        peer: SocketAddr,
        /// The number that was being bound.
        channel: ChannelNumber,
        /// What went wrong.
        reason: TurnError,
    },
    /// The allocation is gone and nothing on it will work again.
    Closed(TurnError),
    /// The allocation was deleted because we asked for it to be.
    Deleted,
}

/// Why something stopped working.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnError {
    /// No response, after the whole retransmission schedule.
    TimedOut,
    /// Responses arrived and every one failed its integrity check
    /// (RFC 8489 §9.2.5).
    IntegrityViolated,
    /// The server refused the credentials, or asked for ones that were never
    /// configured.
    Unauthenticated,
    /// 437: the server has no allocation on this 5-tuple. An intervening NAT
    /// has probably reassigned a mapping that belonged to somebody who
    /// crashed. Bind a different local port and allocate again; after three
    /// tries, leave the server alone for two minutes (§7.4).
    AllocationMismatch,
    /// 441: these credentials did not create this allocation (§19).
    WrongCredentials,
    /// 486: this user has as many allocations as the server allows (§7.4).
    QuotaReached,
    /// 508: the server has nothing left to hand out (§7.4).
    InsufficientCapacity,
    /// 440: the server does not do that address family. Do not ask again
    /// (§7.4).
    AddressFamilyNotSupported,
    /// 442: the server does not relay over the protocol asked for (§19).
    UnsupportedTransport,
    /// 443: a peer address of a family this allocation does not relay (§19).
    PeerAddressFamilyMismatch,
    /// 403: allowed by the protocol, refused by the administrator (§19).
    Forbidden,
    /// A comprehension-required attribute nobody here understands, or a 420
    /// saying the server felt the same about ours.
    UnknownAttribute,
    /// 300: the same request belongs at this address instead. Following it in
    /// a loop is what the specification warns about, so it is the caller's
    /// decision.
    Alternate(SocketAddr),
    /// The nonce went stale more often than a nonce can honestly go stale.
    StaleNonceLoop,
    /// The nonce promises a choice of password algorithm that the challenge
    /// did not carry, which is what stripping the choice would look like.
    BidDown,
    /// The server offered password algorithms and none of them is one this
    /// implementation has.
    UnsupportedPasswordAlgorithm,
    /// A success response missing the attribute that is the point of it.
    Malformed,
    /// The relayed address is of a family that was not asked for (§7.3).
    FamilyMismatch,
    /// A ChannelBind came back 400, which means the two sides disagree about
    /// what is bound. §12.3 says to throw the allocation away and start over.
    ChannelOutOfSync,
    /// The request would not fit a STUN message.
    Oversized,
    /// An error response this client does not act on.
    Rejected {
        /// The code the server sent.
        code: u16,
    },
}

impl TurnError {
    /// How long to wait before asking this server for anything again.
    ///
    /// The two capacity errors carry the RFC's own advice: "SHOULD wait at
    /// least 1 minute before trying to create any more allocations" (§7.4).
    /// The 437 figure is the two minutes that section gives after three
    /// attempts on three different local ports.
    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        match self {
            Self::QuotaReached | Self::InsufficientCapacity => Some(Duration::from_secs(60)),
            Self::AllocationMismatch => Some(Duration::from_secs(120)),
            _ => None,
        }
    }
}

impl fmt::Display for TurnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TimedOut => f.write_str("no response"),
            Self::IntegrityViolated => f.write_str("every response failed its integrity check"),
            Self::Unauthenticated => f.write_str("the server refused the credentials"),
            Self::AllocationMismatch => f.write_str("the server has no allocation on this 5-tuple"),
            Self::WrongCredentials => {
                f.write_str("these credentials did not create this allocation")
            }
            Self::QuotaReached => f.write_str("this user is at the allocation quota"),
            Self::InsufficientCapacity => f.write_str("the server has nothing left to allocate"),
            Self::AddressFamilyNotSupported => f.write_str("the server does not relay that family"),
            Self::UnsupportedTransport => f.write_str("the server does not relay over that"),
            Self::PeerAddressFamilyMismatch => {
                f.write_str("a peer of a family this allocation does not relay")
            }
            Self::Forbidden => f.write_str("refused by the server's administrator"),
            Self::UnknownAttribute => {
                f.write_str("a comprehension-required attribute nobody here understands")
            }
            Self::Alternate(address) => write!(f, "redirected to {address}"),
            Self::StaleNonceLoop => f.write_str("the nonce keeps going stale"),
            Self::BidDown => f.write_str("the nonce promises password algorithms that are missing"),
            Self::UnsupportedPasswordAlgorithm => {
                f.write_str("no password algorithm in common with the server")
            }
            Self::Malformed => f.write_str("a success response with nothing in it"),
            Self::FamilyMismatch => f.write_str("a relayed address of a family nobody asked for"),
            Self::ChannelOutOfSync => f.write_str("the channel bindings disagree with the server"),
            Self::Oversized => f.write_str("the request does not fit a message"),
            Self::Rejected { code } => write!(f, "error response {code}"),
        }
    }
}

impl core::error::Error for TurnError {}

/// Why a transaction could not be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// There is already an allocation, or one on the way.
    Busy,
    /// There is no allocation to act on.
    NotAllocated,
    /// The pool holds no transaction id. Supply one and try again.
    NoTransactionId,
    /// RESERVATION-TOKEN and EVEN-PORT in the same request (§7.1).
    TokenAndEvenPort,
    /// RESERVATION-TOKEN and a family request in the same request: the token
    /// already decides which address you get (§7.1).
    TokenAndFamily,
    /// A dual allocation and a request to hold the next port: the success
    /// response has room for one reservation token, not two (§7.1).
    DualAndReservation,
    /// The request would not fit a STUN message.
    Oversized,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Busy => f.write_str("an allocation is already under way"),
            Self::NotAllocated => f.write_str("there is no allocation"),
            Self::NoTransactionId => f.write_str("no transaction id in the pool"),
            Self::TokenAndEvenPort => {
                f.write_str("a reservation token leaves nothing for EVEN-PORT to ask")
            }
            Self::TokenAndFamily => {
                f.write_str("a reservation token already decides the address family")
            }
            Self::DualAndReservation => {
                f.write_str("a dual allocation cannot also hold the next port")
            }
            Self::Oversized => f.write_str("the request does not fit a message"),
        }
    }
}

impl core::error::Error for StartError {}

/// Why a packet could not be handed to the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// There is no allocation to send on.
    NotAllocated,
    /// No permission for the peer's address, so the relay would drop it and
    /// sending would only tell an attacker that we are here (§11.1).
    NoPermission,
    /// A Send indication needs a transaction id and the pool is empty. Bind a
    /// channel, which needs none.
    NoTransactionId,
    /// More data than the message can carry.
    TooLarge,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotAllocated => f.write_str("there is no allocation"),
            Self::NoPermission => f.write_str("no permission for that peer"),
            Self::NoTransactionId => f.write_str("no transaction id in the pool"),
            Self::TooLarge => f.write_str("more data than a message can carry"),
        }
    }
}

impl core::error::Error for SendError {}

/// What a buffer handed to the client turned out to be.
///
/// Application data comes back as a position in that buffer rather than as a
/// borrow of it. A borrow would freeze the caller's datagram for as long as it
/// held the answer, and what the caller does next with a relayed packet is
/// unprotect it in place — so the type that said "here it is" would be the
/// type that stopped it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// Control traffic, already dealt with. Drain the events.
    Consumed,
    /// Application data from a peer, at this position in the buffer handed in.
    Data {
        /// Who sent it.
        peer: SocketAddr,
        /// Where in the buffer their packet is, with the relay's wrapping
        /// taken off.
        range: core::ops::Range<usize>,
    },
    /// The relay could not reach a peer and said why (§11.6).
    Unreachable {
        /// Which peer.
        peer: SocketAddr,
        /// The type, code and error data the relay saw.
        icmp: Icmp,
    },
    /// Nothing here belongs to this client.
    Foreign,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Idle,
    Allocating,
    Allocated,
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    /// Send the same bytes again.
    Retransmit,
    /// Build the request afresh, under a new transaction id, because the
    /// credentials changed underneath it.
    Rebuild,
}

#[derive(Clone)]
enum Kind {
    Allocate,
    /// `None` leaves LIFETIME out and takes the default; `Some(0)` deletes.
    Refresh(Option<u32>),
    CreatePermission(Vec<IpAddr>),
    ChannelBind(ChannelNumber, SocketAddr),
}

impl Kind {
    fn method(&self) -> Method {
        match self {
            Self::Allocate => method::ALLOCATE,
            Self::Refresh(_) => method::REFRESH,
            Self::CreatePermission(_) => method::CREATE_PERMISSION,
            Self::ChannelBind(..) => method::CHANNEL_BIND,
        }
    }
}

struct Transaction {
    id: TransactionId,
    kind: Kind,
    request: Vec<u8>,
    sends: u32,
    deadline: Instant,
    authenticated: bool,
    integrity_violated: bool,
    challenges: u32,
    stale: Vec<Vec<u8>>,
    pending: Pending,
}

/// What the server told us to authenticate with.
#[derive(Default)]
struct Auth {
    realm: Vec<u8>,
    nonce: Vec<u8>,
    algorithms: Option<Vec<u8>>,
    algorithm: Option<PasswordAlgorithm>,
    key: Option<Key>,
}

struct Permission {
    peer: IpAddr,
    /// When the relay stops honouring it, if it ever started.
    until: Option<Instant>,
    /// When to send the next CreatePermission for it.
    due: Instant,
}

struct Channel {
    number: ChannelNumber,
    peer: SocketAddr,
    /// When the binding lapses, if it was ever confirmed.
    until: Option<Instant>,
    /// When to rebind.
    due: Instant,
}

struct Quarantine {
    number: ChannelNumber,
    peer: SocketAddr,
    until: Instant,
}

/// A TURN allocation and everything hanging off it.
pub struct TurnClient {
    config: TurnConfig,
    state: State,
    ids: VecDeque<TransactionId>,
    outbox: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    auth: Auth,
    transactions: Vec<Transaction>,
    relayed: Vec<SocketAddr>,
    mapped: Option<SocketAddr>,
    token: Option<ReservationToken>,
    refresh_at: Option<Instant>,
    permissions: Vec<Permission>,
    channels: Vec<Channel>,
    quarantine: Vec<Quarantine>,
    /// Whether the reservation attributes were dropped after a 508.
    drop_reservation: bool,
    /// Whether DONT-FRAGMENT was dropped after a 420 naming it.
    drop_dont_fragment: bool,
    /// Whether the server took DONT-FRAGMENT, which is the only way to know
    /// that a Send indication may carry it (§7.1).
    dont_fragment: bool,
}

impl TurnClient {
    /// A client with no allocation yet.
    #[must_use]
    pub fn new(config: TurnConfig) -> Self {
        Self {
            config,
            state: State::Idle,
            ids: VecDeque::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            auth: Auth::default(),
            transactions: Vec::new(),
            relayed: Vec::new(),
            mapped: None,
            token: None,
            refresh_at: None,
            permissions: Vec::new(),
            channels: Vec::new(),
            quarantine: Vec::new(),
            drop_reservation: false,
            drop_dont_fragment: false,
            dont_fragment: false,
        }
    }

    /// Hand the client a transaction id drawn from a cryptographic source.
    ///
    /// RFC 8489 §5 requires every message, indications included, to carry one
    /// that is uniformly and cryptographically random, and this crate has no
    /// generator. Keep the pool full: a client with an empty pool cannot start
    /// a transaction and will not invent one.
    pub fn supply_transaction_id(&mut self, id: TransactionId) {
        if self.ids.len() < POOL {
            self.ids.push_back(id);
        }
    }

    /// How many more ids the client would like to be holding.
    #[must_use]
    pub fn transaction_ids_wanted(&self) -> usize {
        POOL - self.ids.len().min(POOL)
    }

    /// Ask for a relayed transport address.
    ///
    /// The first request goes out with no credentials in it, because RFC 8489
    /// §9.2.3.1 says it must: the client does not know the realm yet, and the
    /// 401 that comes back is what tells it.
    ///
    /// # Errors
    ///
    /// An allocation already under way, an empty id pool, or a combination of
    /// attributes §7.1 rules out.
    pub fn allocate(&mut self, now: Instant) -> Result<(), StartError> {
        if self.state != State::Idle {
            return Err(StartError::Busy);
        }
        if self.config.reservation_token.is_some() {
            if self.config.even_port.is_some() {
                return Err(StartError::TokenAndEvenPort);
            }
            if self.config.families != FamilyRequest::Whatever {
                return Err(StartError::TokenAndFamily);
            }
        }
        if self.config.families == FamilyRequest::Dual
            && self.config.even_port == Some(EvenPort::EvenAndReserveNext)
        {
            return Err(StartError::DualAndReservation);
        }
        self.begin(Kind::Allocate, now)?;
        self.state = State::Allocating;
        Ok(())
    }

    /// Give the allocation back, with a Refresh whose lifetime is zero (§8.1).
    ///
    /// # Errors
    ///
    /// No allocation to delete, or an empty id pool.
    pub fn delete(&mut self, now: Instant) -> Result<(), StartError> {
        if self.state != State::Allocated {
            return Err(StartError::NotAllocated);
        }
        self.refresh_at = None;
        self.begin(Kind::Refresh(Some(0)), now)
    }

    /// Let a peer's address reach the relayed address.
    ///
    /// The request goes out at once when there is an allocation and an id to
    /// send it under, and otherwise as soon as there is.
    pub fn permit(&mut self, peer: IpAddr, now: Instant) {
        if !self.permissions.iter().any(|entry| entry.peer == peer) {
            self.permissions.push(Permission {
                peer,
                until: None,
                due: now,
            });
        }
        self.schedule(now);
    }

    /// Bind a channel to a peer, and install the permission it needs.
    ///
    /// Answers the number that will carry the peer's data, or nothing at all
    /// when every one of the 4096 is either bound or sitting out the five
    /// minutes §12 makes it wait before it can name a different peer.
    pub fn bind_channel(&mut self, peer: SocketAddr, now: Instant) -> Option<ChannelNumber> {
        if let Some(existing) = self.channels.iter().find(|entry| entry.peer == peer) {
            return Some(existing.number);
        }
        let number = self.free_channel(peer, now)?;
        self.channels.push(Channel {
            number,
            peer,
            until: None,
            due: now,
        });
        self.permit(peer.ip(), now);
        Some(number)
    }

    /// Wrap application data for a peer and put it on the end of `out`.
    ///
    /// A bound channel gets a ChannelData message; anything else gets a Send
    /// indication, which costs a STUN header, an address and an attribute
    /// header on every packet. That is the whole reason to bind a channel.
    ///
    /// # Errors
    ///
    /// No allocation, no permission for the peer, no transaction id for the
    /// indication, or more data than a message can hold.
    pub fn send_to(
        &mut self,
        peer: SocketAddr,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SendError> {
        if self.state != State::Allocated {
            return Err(SendError::NotAllocated);
        }
        if !self.has_permission(peer.ip()) {
            return Err(SendError::NoPermission);
        }
        if let Some(channel) = self.channel(peer) {
            return ChannelData::encode(channel, data, self.config.transport, out)
                .map_err(|_| SendError::TooLarge);
        }
        let Some(id) = self.ids.pop_front() else {
            return Err(SendError::NoTransactionId);
        };
        let indication = self
            .build_send(id, peer, data)
            .map_err(|_| SendError::TooLarge)?;
        out.extend_from_slice(&indication);
        Ok(())
    }

    /// Take one datagram, or one frame off a stream.
    pub fn handle_input(&mut self, bytes: &[u8], now: Instant) -> Input {
        match bytes.first() {
            Some(0..=3) => self.on_stun(bytes, now),
            Some(64..=79) => self.on_channel_data(bytes),
            _ => Input::Foreign,
        }
    }

    /// Take the passing of time: retransmit, renew, rebind, give up.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.state == State::Closed {
            return;
        }
        let due: Vec<TransactionId> = self
            .transactions
            .iter()
            .filter(|entry| entry.deadline <= now)
            .map(|entry| entry.id)
            .collect();
        for id in due {
            if let Some(index) = self.transactions.iter().position(|entry| entry.id == id) {
                self.on_transaction_timeout(index, now);
            }
        }
        self.schedule(now);
    }

    /// When something has to happen next.
    ///
    /// A deadline in the past means work is waiting on something the caller
    /// owes: usually a transaction id, since a challenged request has to go
    /// out again under a new one and this crate will not invent it.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        let mut earliest = None;
        for entry in &self.transactions {
            earliest = sooner(earliest, Some(entry.deadline));
        }
        if self.state == State::Allocated {
            earliest = sooner(earliest, self.refresh_at);
            for entry in &self.permissions {
                earliest = sooner(earliest, Some(entry.due));
            }
            for entry in &self.channels {
                earliest = sooner(earliest, Some(entry.due));
            }
        }
        earliest
    }

    /// The next control message to put on the wire.
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.outbox.pop_front()
    }

    /// The next thing that happened.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// The relayed transport addresses, one per family.
    #[must_use]
    pub fn relayed_addresses(&self) -> &[SocketAddr] {
        &self.relayed
    }

    /// Where the server sees this client from (§7.2).
    #[must_use]
    pub const fn mapped_address(&self) -> Option<SocketAddr> {
        self.mapped
    }

    /// The token for the port the server is holding, if one was asked for and
    /// granted.
    #[must_use]
    pub const fn reservation_token(&self) -> Option<ReservationToken> {
        self.token
    }

    /// Whether there is an allocation to use.
    #[must_use]
    pub fn is_allocated(&self) -> bool {
        self.state == State::Allocated
    }

    /// The channel bound to a peer, once the server has confirmed it.
    #[must_use]
    pub fn channel(&self, peer: SocketAddr) -> Option<ChannelNumber> {
        self.channels
            .iter()
            .find(|entry| entry.peer == peer && entry.until.is_some())
            .map(|entry| entry.number)
    }

    /// Whether the relay is currently letting this address through.
    #[must_use]
    pub fn has_permission(&self, peer: IpAddr) -> bool {
        self.permissions
            .iter()
            .any(|entry| entry.peer == peer && entry.until.is_some())
    }
}

/// Building requests.
impl TurnClient {
    fn begin(&mut self, kind: Kind, now: Instant) -> Result<(), StartError> {
        let Some(id) = self.ids.pop_front() else {
            return Err(StartError::NoTransactionId);
        };
        let request = self.build(&kind, id).map_err(|_| StartError::Oversized)?;
        self.outbox.push_back(request.clone());
        self.transactions.push(Transaction {
            id,
            kind,
            request,
            sends: 1,
            deadline: now,
            authenticated: self.auth.key.is_some(),
            integrity_violated: false,
            challenges: 0,
            stale: Vec::new(),
            pending: Pending::Retransmit,
        });
        let index = self.transactions.len().saturating_sub(1);
        self.arm(index, now);
        Ok(())
    }

    fn build(&self, kind: &Kind, id: TransactionId) -> Result<Vec<u8>, BuildError> {
        let mut builder = MessageBuilder::new(Class::Request, kind.method(), id);
        if let Some(software) = &self.config.software {
            builder.add(AttributeType::SOFTWARE, software.as_bytes())?;
        }
        match kind {
            Kind::Allocate => self.write_allocate(&mut builder)?,
            Kind::Refresh(seconds) => {
                if let Some(seconds) = seconds {
                    builder.add_u32(AttributeType::LIFETIME, *seconds)?;
                }
            }
            Kind::CreatePermission(peers) => {
                // "The port portion of each XOR-PEER-ADDRESS attribute will be
                // ignored and can be any arbitrary value" (§10.1)
                for peer in peers {
                    builder.add_xor_address(
                        AttributeType::XOR_PEER_ADDRESS,
                        SocketAddr::new(*peer, 0),
                    )?;
                }
            }
            Kind::ChannelBind(channel, peer) => {
                // the number, then two octets reserved for future use (§18.1)
                builder.add_u32(
                    AttributeType::CHANNEL_NUMBER,
                    u32::from(channel.get()) << 16,
                )?;
                builder.add_xor_address(AttributeType::XOR_PEER_ADDRESS, *peer)?;
            }
        }
        self.write_credentials(&mut builder)?;
        if self.config.fingerprint {
            builder.add_fingerprint()?;
        }
        Ok(builder.finish())
    }

    fn write_allocate(&self, builder: &mut MessageBuilder) -> Result<(), BuildError> {
        builder.add(AttributeType::REQUESTED_TRANSPORT, &[PROTOCOL_UDP, 0, 0, 0])?;
        if let Some(lifetime) = self.config.lifetime {
            builder.add_u32(AttributeType::LIFETIME, seconds(lifetime))?;
        }
        if self.config.dont_fragment && !self.drop_dont_fragment {
            builder.add_flag(AttributeType::DONT_FRAGMENT)?;
        }
        let token = self
            .config
            .reservation_token
            .filter(|_| !self.drop_reservation);
        if let Some(token) = token {
            builder.add(AttributeType::RESERVATION_TOKEN, token.as_bytes())?;
            return Ok(());
        }
        if let Some(even) = self.config.even_port.filter(|_| !self.drop_reservation) {
            builder.add(AttributeType::EVEN_PORT, &even.encode())?;
        }
        match self.config.families {
            FamilyRequest::Whatever => {}
            FamilyRequest::Only(family) => {
                builder.add(AttributeType::REQUESTED_ADDRESS_FAMILY, &family.encode())?;
            }
            // "The attribute value in the ADDITIONAL-ADDRESS-FAMILY MUST be
            // set to 0x02" (§7.1): the IPv4 address is the one you get anyway
            FamilyRequest::Dual => {
                builder.add(
                    AttributeType::ADDITIONAL_ADDRESS_FAMILY,
                    &AddressFamily::V6.encode(),
                )?;
            }
        }
        Ok(())
    }

    fn write_credentials(&self, builder: &mut MessageBuilder) -> Result<(), BuildError> {
        let Some(key) = self.auth.key.as_ref() else {
            return Ok(());
        };
        let username = self
            .config
            .credentials
            .as_ref()
            .map_or("", LongTermCredentials::username);
        builder.add(AttributeType::USERNAME, username.as_bytes())?;
        builder.add(AttributeType::REALM, &self.auth.realm)?;
        builder.add(AttributeType::NONCE, &self.auth.nonce)?;
        match (&self.auth.algorithms, self.auth.algorithm) {
            (Some(algorithms), Some(algorithm)) => {
                builder.add(AttributeType::PASSWORD_ALGORITHMS, algorithms)?;
                let mut chosen = Vec::from(algorithm.code().to_be_bytes());
                chosen.extend_from_slice(&0_u16.to_be_bytes());
                builder.add(AttributeType::PASSWORD_ALGORITHM, &chosen)?;
                // "If the response contains a PASSWORD-ALGORITHMS attribute,
                // all the subsequent requests MUST be authenticated using
                // MESSAGE-INTEGRITY-SHA256 only" (RFC 8489 §9.2.5)
                builder.add_message_integrity_sha256(key.as_bytes())
            }
            _ => builder.add_message_integrity(key.as_bytes()),
        }
    }

    fn build_send(
        &self,
        id: TransactionId,
        peer: SocketAddr,
        data: &[u8],
    ) -> Result<Vec<u8>, BuildError> {
        let mut builder = MessageBuilder::new(Class::Indication, method::SEND, id);
        builder.add_xor_address(AttributeType::XOR_PEER_ADDRESS, peer)?;
        if self.dont_fragment {
            builder.add_flag(AttributeType::DONT_FRAGMENT)?;
        }
        builder.add(AttributeType::DATA, data)?;
        // no FINGERPRINT here: it is eight octets on every packet of the data
        // path, and the server tells our traffic from anyone else's by the
        // 5-tuple rather than by a checksum
        Ok(builder.finish())
    }
}

/// Reading what arrives.
impl TurnClient {
    fn on_stun(&mut self, bytes: &[u8], now: Instant) -> Input {
        let Ok(message) = Message::parse(bytes) else {
            return Input::Foreign;
        };
        match message.class() {
            Class::Indication => self.on_indication(&message),
            Class::Success | Class::Error => {
                self.on_response(&message, now);
                Input::Consumed
            }
            Class::Request => Input::Foreign,
        }
    }

    fn on_indication(&self, message: &Message<'_>) -> Input {
        if message.method() != method::DATA || self.state != State::Allocated {
            return Input::Foreign;
        }
        let Some(peer) = attribute::peer_address(message) else {
            return Input::Foreign;
        };
        // "The client SHOULD also check that the XOR-PEER-ADDRESS attribute
        // value contains an IP address with which the client believes there is
        // an active permission" (§11.4), which is what stops a server that has
        // been talked into an unwanted permission from delivering on it
        if !self.has_permission(peer.ip()) {
            return Input::Foreign;
        }
        if let Some(icmp) = attribute::icmp(message) {
            return Input::Unreachable { peer, icmp };
        }
        match message.find_range(AttributeType::DATA) {
            Some(range) => Input::Data { peer, range },
            None => Input::Foreign,
        }
    }

    fn on_channel_data(&self, bytes: &[u8]) -> Input {
        if self.state != State::Allocated {
            return Input::Foreign;
        }
        // whatever delimited this — a datagram boundary or the stream framer —
        // has already dealt with the padding
        let Ok(frame) = ChannelData::parse_frame(bytes) else {
            return Input::Foreign;
        };
        let Some(channel) = self
            .channels
            .iter()
            .find(|entry| entry.number == frame.channel() && entry.until.is_some())
        else {
            return Input::Foreign;
        };
        if !self.has_permission(channel.peer.ip()) {
            return Input::Foreign;
        }
        Input::Data {
            peer: channel.peer,
            range: frame.range(),
        }
    }

    fn on_response(&mut self, message: &Message<'_>, now: Instant) {
        let Some(index) = self
            .transactions
            .iter()
            .position(|entry| entry.id == message.transaction_id())
        else {
            return;
        };
        let Some((method, authenticated)) = self
            .transactions
            .get(index)
            .map(|entry| (entry.kind.method(), entry.authenticated))
        else {
            return;
        };
        if message.method() != method || message.verify_fingerprint() == Integrity::Invalid {
            return;
        }
        if message.check_comprehension().is_err() {
            self.expire(index, TurnError::UnknownAttribute, now);
            return;
        }

        let code = message.error_code().map(|error| error.code());
        // a 401 has no key to be signed with and a 438 says the key material
        // is stale, so both are read before the integrity check (§9.2.4)
        if message.class() == Class::Error
            && matches!(
                code,
                Some(error_code::UNAUTHENTICATED | error_code::STALE_NONCE)
            )
        {
            self.on_challenge(index, message, now);
            return;
        }
        if authenticated
            && !self
                .auth
                .key
                .as_ref()
                .is_some_and(|key| response_is_authentic(message, key))
        {
            if let Some(entry) = self.transactions.get_mut(index) {
                entry.integrity_violated = true;
            }
            return;
        }

        match message.class() {
            Class::Success => self.on_success(index, message, now),
            Class::Error => self.on_error(index, message, code.unwrap_or_default(), now),
            Class::Request | Class::Indication => {}
        }
    }

    fn on_success(&mut self, index: usize, message: &Message<'_>, now: Instant) {
        let Some(transaction) = self.take(index) else {
            return;
        };
        match transaction.kind {
            Kind::Allocate => self.allocated(message, now),
            Kind::Refresh(seconds) => self.refreshed(message, seconds, now),
            Kind::CreatePermission(peers) => {
                for peer in peers {
                    self.install_permission(peer, now);
                }
            }
            Kind::ChannelBind(number, peer) => {
                self.bound(number, peer, now);
            }
        }
    }

    fn on_error(&mut self, index: usize, message: &Message<'_>, code: u16, now: Instant) {
        let Some(transaction) = self.take(index) else {
            return;
        };
        // "If the client receives a 437 error response to a request to delete
        // the allocation, then the allocation no longer exists and it should
        // consider its request as having effectively succeeded" (§8.3)
        if code == error_code::ALLOCATION_MISMATCH
            && matches!(transaction.kind, Kind::Refresh(Some(0)))
        {
            self.close(Event::Deleted);
            return;
        }
        if matches!(transaction.kind, Kind::Allocate) && self.retry_allocate(code, message, now) {
            return;
        }
        self.abandon(transaction.kind, refusal(code, message), now);
    }

    /// Whether an Allocate error is one to answer by asking for less.
    ///
    /// Two of them are, and both are the server telling us which attribute it
    /// could not honour: a 420 naming DONT-FRAGMENT means it cannot set the
    /// bit at all, and a 508 while we are asking for a particular port means
    /// that port rather than the server is what ran out (§7.4).
    fn retry_allocate(&mut self, code: u16, message: &Message<'_>, now: Instant) -> bool {
        let reserving = self.config.even_port.is_some() || self.config.reservation_token.is_some();
        let drop =
            if code == error_code::INSUFFICIENT_CAPACITY && reserving && !self.drop_reservation {
                &mut self.drop_reservation
            } else if code == error_code::UNKNOWN_ATTRIBUTE
                && self.config.dont_fragment
                && !self.drop_dont_fragment
                && message
                    .unknown_attributes()
                    .any(|kind| kind == AttributeType::DONT_FRAGMENT)
            {
                &mut self.drop_dont_fragment
            } else {
                return false;
            };
        *drop = true;
        self.begin(Kind::Allocate, now).is_ok()
    }

    fn on_challenge(&mut self, index: usize, message: &Message<'_>, now: Instant) {
        let (Some(realm), Some(nonce)) = (message.realm(), message.nonce()) else {
            self.expire(index, TurnError::Unauthenticated, now);
            return;
        };
        if self.config.credentials.is_none() {
            self.expire(index, TurnError::Unauthenticated, now);
            return;
        }
        let offered = message.password_algorithms().is_some();
        if security_features(nonce).is_some_and(|features| {
            features
                .first()
                .is_some_and(|byte| byte & FEATURE_PASSWORD_ALGORITHMS != 0)
        }) && !offered
        {
            self.expire(index, TurnError::BidDown, now);
            return;
        }
        let algorithm = if offered {
            let Some(chosen) = best_algorithm(message) else {
                self.expire(index, TurnError::UnsupportedPasswordAlgorithm, now);
                return;
            };
            chosen
        } else {
            PasswordAlgorithm::Md5
        };

        let stale = message
            .error_code()
            .is_some_and(|error| error.code() == error_code::STALE_NONCE);
        if let Some(verdict) = self.answerable(index, nonce, stale) {
            self.expire(index, verdict, now);
            return;
        }
        if let Some(entry) = self.transactions.get_mut(index) {
            if stale {
                entry.stale.push(nonce.to_vec());
            } else {
                entry.challenges += 1;
            }
        }

        let key = {
            let Some(credentials) = self.config.credentials.as_ref() else {
                return;
            };
            derive_key(
                credentials.username().as_bytes(),
                realm,
                credentials.password(),
                algorithm,
            )
        };
        self.auth = Auth {
            realm: realm.to_vec(),
            nonce: nonce.to_vec(),
            algorithms: message.password_algorithms().map(<[u8]>::to_vec),
            algorithm: offered.then_some(algorithm),
            key: Some(key),
        };
        if let Some(entry) = self.transactions.get_mut(index) {
            entry.pending = Pending::Rebuild;
        }
        self.rebuild(index, now);
    }

    /// Whether this challenge may be answered at all, and what to fail with if
    /// not.
    ///
    /// A 438 is answered once per nonce: a second one naming a nonce we have
    /// already used is a server that will never be satisfied. A second 401 in
    /// the same exchange is the server saying the password is wrong, since
    /// §9.2.5 forbids retrying without changing the username, realm or
    /// password, and none of those changed.
    fn answerable(&self, index: usize, nonce: &[u8], stale: bool) -> Option<TurnError> {
        let entry = self.transactions.get(index)?;
        if stale {
            if entry.stale.iter().any(|seen| seen == nonce) || entry.stale.len() >= MAX_STALE_NONCES
            {
                return Some(TurnError::StaleNonceLoop);
            }
            return None;
        }
        (entry.challenges > 0).then_some(TurnError::Unauthenticated)
    }
}

/// What a successful response changes.
impl TurnClient {
    fn allocated(&mut self, message: &Message<'_>, now: Instant) {
        let relayed = attribute::relayed_addresses(message);
        let Some(&first) = relayed.first() else {
            self.close(Event::Closed(TurnError::Malformed));
            return;
        };
        // "the client MUST check that the mapped address and the relayed
        // transport address or addresses are part of an address family or
        // families that the client understands and is prepared to handle"
        // (§7.3): both families are handled here, so the only mismatch worth
        // refusing is a family other than the one asked for
        if let FamilyRequest::Only(wanted) = self.config.families
            && relayed
                .iter()
                .any(|address| AddressFamily::of(address.ip()) != wanted)
        {
            self.close(Event::Closed(TurnError::FamilyMismatch));
            return;
        }

        let lifetime = attribute::lifetime(message).unwrap_or(DEFAULT_LIFETIME);
        // an allocation that has already expired is not one, and taking it at
        // its word would put the refresh timer at this instant for ever
        if lifetime.is_zero() {
            self.close(Event::Closed(TurnError::Malformed));
            return;
        }
        self.state = State::Allocated;
        self.relayed = relayed;
        self.mapped = message.xor_mapped_address();
        self.token = attribute::reservation_token(message);
        self.dont_fragment = self.config.dont_fragment && !self.drop_dont_fragment;
        self.refresh_at = now.checked_add(renew_after(lifetime));
        self.events.push_back(Event::Allocated {
            relayed: first,
            mapped: self.mapped,
            lifetime,
        });
        for extra in self.relayed.iter().skip(1) {
            self.events
                .push_back(Event::AlsoAllocated { relayed: *extra });
        }
        if let Some(refused) = attribute::address_error_code(message) {
            self.events.push_back(Event::FamilyRefused {
                family: refused.family(),
                code: refused.code(),
            });
        }
        self.schedule(now);
    }

    fn refreshed(&mut self, message: &Message<'_>, asked: Option<u32>, now: Instant) {
        if asked == Some(0) {
            self.close(Event::Deleted);
            return;
        }
        let lifetime = attribute::lifetime(message).unwrap_or(DEFAULT_LIFETIME);
        // the server answering a renewal with no time left is the server
        // saying it let the allocation go
        if lifetime.is_zero() {
            self.close(Event::Deleted);
            return;
        }
        self.refresh_at = now.checked_add(renew_after(lifetime));
        self.events.push_back(Event::Refreshed { lifetime });
    }

    /// Record a permission the server has confirmed.
    ///
    /// It may not be one we are already tracking: a ChannelBind installs a
    /// permission of its own (§12.1), so a peer whose CreatePermission was
    /// refused a moment ago can come back through the channel it is bound to.
    fn install_permission(&mut self, peer: IpAddr, now: Instant) {
        let until = now.checked_add(PERMISSION_LIFETIME);
        let due = now
            .checked_add(renew_after(PERMISSION_LIFETIME))
            .unwrap_or(now);
        if let Some(entry) = self.permissions.iter_mut().find(|entry| entry.peer == peer) {
            entry.until = until;
            entry.due = due;
        } else {
            self.permissions.push(Permission { peer, until, due });
        }
        self.events.push_back(Event::PermissionInstalled { peer });
    }

    fn bound(&mut self, number: ChannelNumber, peer: SocketAddr, now: Instant) {
        let Some(entry) = self
            .channels
            .iter_mut()
            .find(|entry| entry.number == number && entry.peer == peer)
        else {
            return;
        };
        entry.until = now.checked_add(CHANNEL_LIFETIME);
        entry.due = now
            .checked_add(renew_after(CHANNEL_LIFETIME))
            .unwrap_or(now);
        // "A ChannelBind transaction also creates or refreshes a permission
        // towards the peer" (§12.1), and the permission is the shorter of the
        // two lifetimes, so its own clock has to be reset here as well
        self.install_permission(peer.ip(), now);
        self.events.push_back(Event::ChannelBound {
            peer,
            channel: number,
        });
    }
}

/// What a failure changes.
impl TurnClient {
    fn abandon(&mut self, kind: Kind, error: TurnError, now: Instant) {
        match kind {
            Kind::Allocate | Kind::Refresh(_) => self.close(Event::Closed(error)),
            Kind::CreatePermission(peers) => {
                for peer in peers {
                    self.permissions.retain(|entry| entry.peer != peer);
                    self.events.push_back(Event::PermissionFailed {
                        peer,
                        reason: error,
                    });
                }
            }
            Kind::ChannelBind(number, peer) => {
                self.channels
                    .retain(|entry| entry.number != number || entry.peer != peer);
                self.quarantine.push(Quarantine {
                    number,
                    peer,
                    until: now.checked_add(CHANNEL_QUARANTINE).unwrap_or(now),
                });
                self.events.push_back(Event::ChannelFailed {
                    peer,
                    channel: number,
                    reason: error,
                });
                // "If the client receives a ChannelBind failure response that
                // indicates that the channel information is out of sync
                // between the client and the server [...] it is RECOMMENDED
                // that the client immediately delete the allocation" (§12.3)
                if matches!(error, TurnError::Rejected { code: 400 }) {
                    let _unsent = self.begin(Kind::Refresh(Some(0)), now);
                    self.close(Event::Closed(TurnError::ChannelOutOfSync));
                }
            }
        }
    }

    fn expire(&mut self, index: usize, error: TurnError, now: Instant) {
        let Some(transaction) = self.take(index) else {
            return;
        };
        self.abandon(transaction.kind, error, now);
    }

    fn close(&mut self, event: Event) {
        self.state = State::Closed;
        self.transactions.clear();
        self.permissions.clear();
        self.channels.clear();
        self.quarantine.clear();
        self.refresh_at = None;
        self.events.push_back(event);
    }

    fn take(&mut self, index: usize) -> Option<Transaction> {
        if index < self.transactions.len() {
            Some(self.transactions.remove(index))
        } else {
            None
        }
    }
}

/// Clocks.
impl TurnClient {
    fn on_transaction_timeout(&mut self, index: usize, now: Instant) {
        let Some(entry) = self.transactions.get(index) else {
            return;
        };
        if entry.pending == Pending::Rebuild {
            self.rebuild(index, now);
            return;
        }
        let spent = if self.config.transport.is_stream() {
            entry.sends >= 1
        } else {
            entry.sends >= self.config.rc
        };
        if spent {
            let error = if entry.integrity_violated {
                TurnError::IntegrityViolated
            } else {
                TurnError::TimedOut
            };
            self.expire(index, error, now);
            return;
        }
        let again = entry.request.clone();
        self.outbox.push_back(again);
        if let Some(entry) = self.transactions.get_mut(index) {
            entry.sends += 1;
        }
        self.arm(index, now);
    }

    /// Build a challenged transaction again under a fresh id.
    ///
    /// A retry after a 401 or a 438 is a new transaction, not a retransmission
    /// of the old one, so it needs an id the caller has not used. Without one
    /// the transaction waits where it is: the caller learns from
    /// `transaction_ids_wanted` that it has work to do.
    fn rebuild(&mut self, index: usize, now: Instant) {
        let Some(kind) = self.transactions.get(index).map(|entry| entry.kind.clone()) else {
            return;
        };
        let Some(id) = self.ids.pop_front() else {
            if let Some(entry) = self.transactions.get_mut(index) {
                entry.deadline = now;
            }
            return;
        };
        let Ok(request) = self.build(&kind, id) else {
            self.expire(index, TurnError::Oversized, now);
            return;
        };
        self.outbox.push_back(request.clone());
        let authenticated = self.auth.key.is_some();
        if let Some(entry) = self.transactions.get_mut(index) {
            entry.id = id;
            entry.request = request;
            entry.sends = 1;
            entry.authenticated = authenticated;
            entry.integrity_violated = false;
            entry.pending = Pending::Retransmit;
        }
        self.arm(index, now);
    }

    /// The gap after the nth request: `RTO * 2^(n-1)` while requests are left,
    /// then `Rm * RTO` before the transaction is called dead
    /// (RFC 8489 §6.2.1). A stream transport does none of this and waits Ti.
    fn arm(&mut self, index: usize, now: Instant) {
        let stream = self.config.transport.is_stream();
        let (rto, rc, rm, ti) = (
            self.config.rto,
            self.config.rc,
            self.config.rm,
            self.config.ti,
        );
        let Some(entry) = self.transactions.get_mut(index) else {
            return;
        };
        let wait = if stream {
            Some(ti)
        } else if entry.sends < rc {
            rto.checked_mul(1_u32 << entry.sends.saturating_sub(1).min(16))
        } else {
            rto.checked_mul(rm)
        };
        let wait = wait.unwrap_or(MAX_INTERVAL).min(MAX_INTERVAL);
        entry.deadline = now.checked_add(wait).unwrap_or(now);
    }

    /// Start whatever the clock says is due: the allocation renewal, the
    /// permissions, the channel bindings.
    fn schedule(&mut self, now: Instant) {
        if self.state != State::Allocated {
            return;
        }
        self.lapse(now);
        if self.refresh_at.is_some_and(|at| at <= now)
            && !self
                .transactions
                .iter()
                .any(|entry| matches!(entry.kind, Kind::Refresh(_)))
        {
            // a configured lifetime of zero would delete the allocation on the
            // first renewal, which is not what asking for a short one means
            let seconds = self
                .config
                .lifetime
                .map(seconds)
                .filter(|value| *value != 0);
            if self.begin(Kind::Refresh(seconds), now).is_ok() {
                self.refresh_at = None;
            }
        }

        let peers: Vec<IpAddr> = self
            .permissions
            .iter()
            .filter(|entry| entry.due <= now)
            .map(|entry| entry.peer)
            .filter(|peer| !self.permission_in_flight(*peer))
            .collect();
        if !peers.is_empty() {
            let _unsent = self.begin(Kind::CreatePermission(peers), now);
        }

        let channels: Vec<(ChannelNumber, SocketAddr)> = self
            .channels
            .iter()
            .filter(|entry| entry.due <= now)
            .map(|entry| (entry.number, entry.peer))
            .filter(|(number, _)| !self.channel_in_flight(*number))
            .collect();
        for (number, peer) in channels {
            if self.begin(Kind::ChannelBind(number, peer), now).is_err() {
                break;
            }
        }
    }

    /// Notice what has run out.
    fn lapse(&mut self, now: Instant) {
        for entry in &mut self.permissions {
            if entry.until.is_some_and(|until| until <= now) {
                entry.until = None;
                entry.due = now;
            }
        }
        self.quarantine.retain(|entry| entry.until > now);
        let lost: Vec<(ChannelNumber, SocketAddr)> = self
            .channels
            .iter()
            .filter(|entry| entry.until.is_some_and(|until| until <= now))
            .map(|entry| (entry.number, entry.peer))
            .collect();
        for (number, peer) in lost {
            self.abandon(Kind::ChannelBind(number, peer), TurnError::TimedOut, now);
        }
    }

    fn permission_in_flight(&self, peer: IpAddr) -> bool {
        self.transactions.iter().any(|entry| match &entry.kind {
            Kind::CreatePermission(peers) => peers.contains(&peer),
            _ => false,
        })
    }

    fn channel_in_flight(&self, number: ChannelNumber) -> bool {
        self.transactions
            .iter()
            .any(|entry| matches!(entry.kind, Kind::ChannelBind(bound, _) if bound == number))
    }

    /// A number that may be bound to this peer now.
    ///
    /// A number that was bound to the same peer can be reused at once, because
    /// rebinding it is a refresh; anything else has to sit out the five
    /// minutes §12 imposes to keep the two sides from disagreeing about what
    /// a number means.
    fn free_channel(&self, peer: SocketAddr, now: Instant) -> Option<ChannelNumber> {
        if let Some(held) = self
            .quarantine
            .iter()
            .find(|entry| entry.peer == peer && entry.until > now)
        {
            return Some(held.number);
        }
        (FIRST_CHANNEL..=LAST_CHANNEL)
            .filter_map(ChannelNumber::new)
            .find(|number| {
                !self.channels.iter().any(|entry| entry.number == *number)
                    && !self
                        .quarantine
                        .iter()
                        .any(|entry| entry.number == *number && entry.until > now)
            })
    }
}

impl fmt::Debug for TurnClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnClient")
            .field("state", &self.state)
            .field("transport", &self.config.transport)
            .field("relayed", &self.relayed)
            .field("permissions", &self.permissions.len())
            .field("channels", &self.channels.len())
            .finish_non_exhaustive()
    }
}

/// The error a code means to a TURN client.
fn refusal(code: u16, message: &Message<'_>) -> TurnError {
    match code {
        error_code::TRY_ALTERNATE => message
            .alternate_server()
            .map_or(TurnError::Rejected { code }, TurnError::Alternate),
        error_code::FORBIDDEN => TurnError::Forbidden,
        error_code::UNAUTHENTICATED => TurnError::Unauthenticated,
        error_code::UNKNOWN_ATTRIBUTE => TurnError::UnknownAttribute,
        error_code::ALLOCATION_MISMATCH => TurnError::AllocationMismatch,
        error_code::ADDRESS_FAMILY_NOT_SUPPORTED => TurnError::AddressFamilyNotSupported,
        error_code::WRONG_CREDENTIALS => TurnError::WrongCredentials,
        error_code::UNSUPPORTED_TRANSPORT => TurnError::UnsupportedTransport,
        error_code::PEER_ADDRESS_FAMILY_MISMATCH => TurnError::PeerAddressFamilyMismatch,
        error_code::ALLOCATION_QUOTA_REACHED => TurnError::QuotaReached,
        error_code::INSUFFICIENT_CAPACITY => TurnError::InsufficientCapacity,
        code => TurnError::Rejected { code },
    }
}

/// Which password algorithm to answer a challenge with.
///
/// "if this attribute contains both MD5 and SHA-256 algorithms, and the client
/// also supports both the algorithms, the request MUST contain a
/// PASSWORD-ALGORITHM attribute with the SHA-256 algorithm" (§6), so the
/// strongest one offered wins rather than the first one listed.
fn best_algorithm(message: &Message<'_>) -> Option<PasswordAlgorithm> {
    let mut best = None;
    for code in message.offered_password_algorithms() {
        match PasswordAlgorithm::from_code(code) {
            Some(PasswordAlgorithm::Sha256) => return Some(PasswordAlgorithm::Sha256),
            Some(weaker) => best = best.or(Some(weaker)),
            None => {}
        }
    }
    best
}

/// When to renew something that lasts this long.
fn renew_after(lifetime: Duration) -> Duration {
    match lifetime.checked_sub(RENEW_MARGIN) {
        Some(early) if early > RENEW_MARGIN => early,
        _ => lifetime / 2,
    }
}

fn seconds(lifetime: Duration) -> u32 {
    u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX)
}

fn sooner(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Event, FamilyRequest, Input, SendError, StartError, TurnClient, TurnConfig, TurnError,
    };
    use crate::stun::binding::derive_key;
    use crate::stun::{
        AttributeType, Class, LongTermCredentials, Message, MessageBuilder, Method,
        PasswordAlgorithm, TransactionId,
    };
    use crate::turn::attribute::{AddressFamily, EvenPort, method};
    use crate::turn::channel::{ChannelData, ChannelNumber};
    use crate::turn::framing::Transport;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::{Duration, Instant};

    const REALM: &[u8] = b"example.com";
    const NONCE: &[u8] = b"nonce-one";
    /// The nonce from §20, whose cookie sets the "password algorithm" bit.
    const RFC_NONCE: &[u8] = b"obMatJos2gAAAadl7W7PeDU4hKE72jda";

    fn relay() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 15)), 50000)
    }

    fn relay_v6() -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 15)),
            50001,
        )
    }

    fn peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 150)), 32102)
    }

    fn other_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 151)), 32103)
    }

    fn key() -> Vec<u8> {
        derive_key(b"George", REALM, b"hunter2", PasswordAlgorithm::Md5)
            .as_bytes()
            .to_vec()
    }

    fn sha256_key() -> Vec<u8> {
        derive_key(b"George", REALM, b"hunter2", PasswordAlgorithm::Sha256)
            .as_bytes()
            .to_vec()
    }

    fn config() -> TurnConfig {
        TurnConfig {
            credentials: Some(LongTermCredentials::new("George", "hunter2")),
            ..TurnConfig::default()
        }
    }

    /// Transaction ids the caller would have drawn from a real generator.
    struct Ids(u32);

    impl Ids {
        fn new() -> Self {
            Self(0)
        }

        fn feed(&mut self, client: &mut TurnClient) {
            while client.transaction_ids_wanted() > 0 {
                self.0 += 1;
                let mut bytes = [0_u8; 12];
                bytes[..4].copy_from_slice(&self.0.to_be_bytes());
                client.supply_transaction_id(TransactionId::new(bytes));
            }
        }
    }

    fn sent(client: &mut TurnClient) -> Vec<u8> {
        client.poll_transmit().expect("something to send")
    }

    fn events(client: &mut TurnClient) -> Vec<Event> {
        let mut all = Vec::new();
        while let Some(event) = client.poll_event() {
            all.push(event);
        }
        all
    }

    fn challenge(request: &Message<'_>, code: u16, nonce: &[u8]) -> Vec<u8> {
        let mut builder =
            MessageBuilder::new(Class::Error, request.method(), request.transaction_id());
        builder.add_error_code(code, b"try again").unwrap();
        builder.add(AttributeType::REALM, REALM).unwrap();
        builder.add(AttributeType::NONCE, nonce).unwrap();
        builder.finish()
    }

    fn error(request: &Message<'_>, code: u16) -> Vec<u8> {
        let mut builder =
            MessageBuilder::new(Class::Error, request.method(), request.transaction_id());
        builder.add_error_code(code, b"no").unwrap();
        builder.add_message_integrity(&key()).unwrap();
        builder.finish()
    }

    fn success(request: &Message<'_>, fill: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut builder =
            MessageBuilder::new(Class::Success, request.method(), request.transaction_id());
        fill(&mut builder);
        builder.add_message_integrity(&key()).unwrap();
        builder.finish()
    }

    fn allocated_body(relayed: &[SocketAddr], lifetime: u32) -> impl FnOnce(&mut MessageBuilder) {
        let relayed = relayed.to_vec();
        move |builder: &mut MessageBuilder| {
            builder.add_u32(AttributeType::LIFETIME, lifetime).unwrap();
            for address in relayed {
                builder
                    .add_xor_address(AttributeType::XOR_RELAYED_ADDRESS, address)
                    .unwrap();
            }
            builder
                .add_xor_address(
                    AttributeType::XOR_MAPPED_ADDRESS,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 7000),
                )
                .unwrap();
        }
    }

    /// Run a client through the two-pass exchange up to a live allocation.
    fn allocate(client: &mut TurnClient, ids: &mut Ids, now: Instant, relayed: &[SocketAddr]) {
        ids.feed(client);
        client.allocate(now).unwrap();
        let first = sent(client);
        let request = Message::parse(&first).unwrap();
        let refusal = challenge(&request, 401, NONCE);
        assert_eq!(client.handle_input(&refusal, now), Input::Consumed);

        ids.feed(client);
        let second = sent(client);
        let request = Message::parse(&second).unwrap();
        let response = success(&request, allocated_body(relayed, 600));
        assert_eq!(client.handle_input(&response, now), Input::Consumed);
    }

    fn ready(now: Instant) -> (TurnClient, Ids) {
        let mut ids = Ids::new();
        let mut client = TurnClient::new(config());
        allocate(&mut client, &mut ids, now, &[relay()]);
        let _seen = events(&mut client);
        (client, ids)
    }

    #[test]
    fn the_first_allocate_carries_no_credentials_and_names_udp() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();

        let bytes = sent(&mut client);
        let request = Message::parse(&bytes).unwrap();
        assert_eq!(request.method(), method::ALLOCATE);
        assert_eq!(request.class(), Class::Request);
        assert_eq!(
            request.find(AttributeType::REQUESTED_TRANSPORT),
            Some(&[17, 0, 0, 0][..])
        );
        // "The first request from the client to the server [...] MUST omit the
        // USERNAME [...] MESSAGE-INTEGRITY, REALM, NONCE" (RFC 8489 §9.2.3.1)
        assert_eq!(request.username(), None);
        assert_eq!(request.realm(), None);
        assert_eq!(request.nonce(), None);
        assert!(!request.has_integrity());
    }

    #[test]
    fn a_challenge_is_answered_under_a_new_id_with_the_realm_and_nonce_echoed() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();

        let first = sent(&mut client);
        let first = Message::parse(&first).unwrap();
        let refusal = challenge(&first, 401, NONCE);
        client.handle_input(&refusal, now);

        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();
        assert_ne!(second.transaction_id(), first.transaction_id());
        assert_eq!(second.username(), Some(&b"George"[..]));
        assert_eq!(second.realm(), Some(REALM));
        assert_eq!(second.nonce(), Some(NONCE));
        assert_eq!(
            second.verify_integrity(&key()),
            crate::stun::Integrity::Valid
        );
        // the attributes of the request itself survive the retry
        assert_eq!(
            second.find(AttributeType::REQUESTED_TRANSPORT),
            Some(&[17, 0, 0, 0][..])
        );
    }

    #[test]
    fn an_allocate_success_yields_the_address_and_a_refresh_a_minute_early() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        allocate(&mut client, &mut ids, now, &[relay()]);

        assert!(client.is_allocated());
        assert_eq!(client.relayed_addresses(), &[relay()]);
        assert_eq!(
            client.mapped_address(),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                7000
            ))
        );
        assert_eq!(
            events(&mut client),
            vec![Event::Allocated {
                relayed: relay(),
                mapped: client.mapped_address(),
                lifetime: Duration::from_secs(600),
            }]
        );
        assert_eq!(client.deadline(), Some(now + Duration::from_secs(540)));
    }

    #[test]
    fn the_refresh_goes_out_before_the_allocation_expires() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);

        let later = now + Duration::from_secs(540);
        client.handle_timeout(later);
        let bytes = sent(&mut client);
        let request = Message::parse(&bytes).unwrap();
        assert_eq!(request.method(), method::REFRESH);
        // nothing was asked for, so LIFETIME is left out and the server's own
        // default applies
        assert_eq!(request.find(AttributeType::LIFETIME), None);
        assert_eq!(request.nonce(), Some(NONCE));

        let response = success(&request, |builder| {
            builder.add_u32(AttributeType::LIFETIME, 1200).unwrap();
        });
        client.handle_input(&response, later);
        assert_eq!(
            events(&mut client),
            vec![Event::Refreshed {
                lifetime: Duration::from_secs(1200)
            }]
        );
        assert_eq!(client.deadline(), Some(later + Duration::from_secs(1140)));
    }

    #[test]
    fn deleting_asks_for_a_lifetime_of_zero_and_a_437_to_it_counts_as_done() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        client.delete(now).unwrap();

        let bytes = sent(&mut client);
        let request = Message::parse(&bytes).unwrap();
        assert_eq!(request.method(), method::REFRESH);
        assert_eq!(
            request.find(AttributeType::LIFETIME),
            Some(&[0, 0, 0, 0][..])
        );

        // "If the client receives a 437 error response to a request to delete
        // the allocation [...] it should consider its request as having
        // effectively succeeded" (§8.3)
        let response = error(&request, 437);
        client.handle_input(&response, now);
        assert_eq!(events(&mut client), vec![Event::Deleted]);
        assert!(!client.is_allocated());
    }

    #[test]
    fn a_437_to_a_refresh_means_the_allocation_is_gone() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        client.handle_timeout(now + Duration::from_secs(540));

        let bytes = sent(&mut client);
        let request = Message::parse(&bytes).unwrap();
        let response = error(&request, 437);
        client.handle_input(&response, now);
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::AllocationMismatch)]
        );
        assert_eq!(
            TurnError::AllocationMismatch.retry_after(),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn wrong_credentials_and_a_quota_end_the_allocation_with_their_own_reasons() {
        for (code, expected, wait) in [
            (441_u16, TurnError::WrongCredentials, None),
            (486, TurnError::QuotaReached, Some(Duration::from_secs(60))),
            (440, TurnError::AddressFamilyNotSupported, None),
            (403, TurnError::Forbidden, None),
        ] {
            let now = Instant::now();
            let mut client = TurnClient::new(config());
            let mut ids = Ids::new();
            ids.feed(&mut client);
            client.allocate(now).unwrap();
            let first = sent(&mut client);
            let first = Message::parse(&first).unwrap();
            client.handle_input(&challenge(&first, 401, NONCE), now);
            ids.feed(&mut client);
            let second = sent(&mut client);
            let second = Message::parse(&second).unwrap();

            client.handle_input(&error(&second, code), now);
            assert_eq!(events(&mut client), vec![Event::Closed(expected)], "{code}");
            assert_eq!(expected.retry_after(), wait, "{code}");
        }
    }

    #[test]
    fn a_508_drops_the_even_port_and_tries_again_once() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            even_port: Some(EvenPort::EvenAndReserveNext),
            ..config()
        });
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let first = sent(&mut client);
        let first = Message::parse(&first).unwrap();
        assert_eq!(first.find(AttributeType::EVEN_PORT), Some(&[0x80][..]));
        client.handle_input(&challenge(&first, 401, NONCE), now);

        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();
        client.handle_input(&error(&second, 508), now);

        // "the client MAY choose to remove or modify this attribute and try
        // again immediately" (§7.4)
        let third = sent(&mut client);
        let third = Message::parse(&third).unwrap();
        assert_eq!(third.find(AttributeType::EVEN_PORT), None);
        assert!(third.has_integrity());
        assert!(events(&mut client).is_empty());

        client.handle_input(&error(&third, 508), now);
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::InsufficientCapacity)]
        );
    }

    #[test]
    fn a_stale_nonce_is_answered_once_per_nonce_and_no_more() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let first = sent(&mut client);
        let first = Message::parse(&first).unwrap();
        client.handle_input(&challenge(&first, 401, NONCE), now);

        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();
        client.handle_input(&challenge(&second, 438, b"nonce-two"), now);

        ids.feed(&mut client);
        let third = sent(&mut client);
        let third = Message::parse(&third).unwrap();
        assert_eq!(third.nonce(), Some(&b"nonce-two"[..]));
        assert_ne!(third.transaction_id(), second.transaction_id());
        assert!(events(&mut client).is_empty());

        // the same nonce going stale twice is a server that will never be
        // satisfied, not a nonce that needs renewing
        client.handle_input(&challenge(&third, 438, b"nonce-two"), now);
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::StaleNonceLoop)]
        );
    }

    #[test]
    fn a_second_401_is_the_password_being_wrong() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let first = sent(&mut client);
        let first = Message::parse(&first).unwrap();
        client.handle_input(&challenge(&first, 401, NONCE), now);

        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();
        client.handle_input(&challenge(&second, 401, b"nonce-two"), now);
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::Unauthenticated)]
        );
    }

    #[test]
    fn a_nonce_that_promises_algorithms_without_offering_them_is_a_bid_down() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let first = sent(&mut client);
        let first = Message::parse(&first).unwrap();
        client.handle_input(&challenge(&first, 401, RFC_NONCE), now);
        assert_eq!(events(&mut client), vec![Event::Closed(TurnError::BidDown)]);
    }

    #[test]
    fn an_offer_of_password_algorithms_is_echoed_and_answered_with_sha256() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let first = sent(&mut client);
        let first = Message::parse(&first).unwrap();

        let offer = [0, 1, 0, 0, 0, 2, 0, 0];
        let mut builder =
            MessageBuilder::new(Class::Error, method::ALLOCATE, first.transaction_id());
        builder.add_error_code(401, b"try again").unwrap();
        builder.add(AttributeType::REALM, REALM).unwrap();
        builder.add(AttributeType::NONCE, RFC_NONCE).unwrap();
        builder
            .add(AttributeType::PASSWORD_ALGORITHMS, &offer)
            .unwrap();
        client.handle_input(&builder.finish(), now);

        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();
        // the offer goes back byte for byte, and the choice is the strongest
        // algorithm both sides have
        assert_eq!(second.password_algorithms(), Some(&offer[..]));
        assert_eq!(
            second.find(AttributeType::PASSWORD_ALGORITHM),
            Some(&[0, 2, 0, 0][..])
        );
        assert_eq!(
            second.verify_integrity_sha256(&sha256_key()),
            crate::stun::Integrity::Valid
        );
        assert_eq!(
            second.find(AttributeType::MESSAGE_INTEGRITY),
            None,
            "§9.2.5 says SHA-256 only once algorithms are offered"
        );
    }

    #[test]
    fn create_permission_names_every_peer_and_ignores_the_port() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        client.permit(peer().ip(), now);
        client.permit(other_peer().ip(), now);

        let bytes = sent(&mut client);
        let request = Message::parse(&bytes).unwrap();
        assert_eq!(request.method(), method::CREATE_PERMISSION);
        let peers: Vec<&[u8]> = request.find_all(AttributeType::XOR_PEER_ADDRESS).collect();
        assert_eq!(peers.len(), 1);
        // the second permit went out on its own request, because the first was
        // still in flight and a rejection of a new peer must not take an
        // established one down with it
        let bytes = sent(&mut client);
        let second = Message::parse(&bytes).unwrap();
        let addresses: Vec<SocketAddr> = second
            .find_all(AttributeType::XOR_PEER_ADDRESS)
            .filter_map(|value| crate::stun::address::decode_xor(value, second.transaction_id()))
            .collect();
        assert_eq!(addresses, vec![SocketAddr::new(other_peer().ip(), 0)]);

        client.handle_input(&success(&request, |_| {}), now);
        assert!(client.has_permission(peer().ip()));
        assert_eq!(
            events(&mut client),
            vec![Event::PermissionInstalled { peer: peer().ip() }]
        );
    }

    #[test]
    fn a_permission_lapses_after_five_minutes_and_is_installed_again() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        client.permit(peer().ip(), now);
        let bytes = sent(&mut client);
        let request = Message::parse(&bytes).unwrap();
        client.handle_input(&success(&request, |_| {}), now);
        let _seen = events(&mut client);

        // renewed a minute before the five the specification fixes
        assert_eq!(client.deadline(), Some(now + Duration::from_secs(240)));
        client.handle_timeout(now + Duration::from_secs(240));
        assert!(client.has_permission(peer().ip()));
        let bytes = sent(&mut client);
        assert_eq!(
            Message::parse(&bytes).unwrap().method(),
            method::CREATE_PERMISSION
        );

        // nothing came back, so at 300 seconds the permission is gone
        client.handle_timeout(now + Duration::from_secs(300));
        assert!(!client.has_permission(peer().ip()));
    }

    #[test]
    fn data_goes_by_indication_until_the_channel_is_bound_and_by_channel_after() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);

        let mut out = Vec::new();
        assert_eq!(
            client.send_to(peer(), b"hi", &mut out),
            Err(SendError::NoPermission)
        );

        let number = client.bind_channel(peer(), now).unwrap();
        assert!((0x4000..=0x4fff).contains(&number.get()));
        let permission = Message::parse(&sent(&mut client)).unwrap().transaction_id();
        let bind = sent(&mut client);
        let bind = Message::parse(&bind).unwrap();
        assert_eq!(bind.method(), method::CHANNEL_BIND);
        assert_eq!(
            bind.find(AttributeType::CHANNEL_NUMBER),
            Some(&[0x40, 0x00, 0, 0][..])
        );

        let mut builder =
            MessageBuilder::new(Class::Success, method::CREATE_PERMISSION, permission);
        builder.add_message_integrity(&key()).unwrap();
        client.handle_input(&builder.finish(), now);

        // the permission is in, the channel is not: a Send indication carries
        // the packet and pays thirty-six octets to do it
        ids.feed(&mut client);
        client.send_to(peer(), b"hi", &mut out).unwrap();
        let indication = Message::parse(&out).unwrap();
        assert_eq!(indication.method(), method::SEND);
        assert_eq!(indication.class(), Class::Indication);
        assert_eq!(indication.find(AttributeType::DATA), Some(&b"hi"[..]));
        assert!(out.len() > 30);

        client.handle_input(&success(&bind, |_| {}), now);
        assert_eq!(client.channel(peer()), Some(number));

        out.clear();
        client.send_to(peer(), b"hi", &mut out).unwrap();
        assert_eq!(out, vec![0x40, 0x00, 0x00, 0x02, b'h', b'i']);
    }

    #[test]
    fn channel_data_comes_back_as_data_from_the_peer_the_number_names() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        let number = client.bind_channel(peer(), now).unwrap();
        let permission = Message::parse(&sent(&mut client)).unwrap().transaction_id();
        let bind = sent(&mut client);
        let bind = Message::parse(&bind).unwrap();
        let mut builder =
            MessageBuilder::new(Class::Success, method::CREATE_PERMISSION, permission);
        builder.add_message_integrity(&key()).unwrap();
        client.handle_input(&builder.finish(), now);
        client.handle_input(&success(&bind, |_| {}), now);
        let _seen = events(&mut client);

        let mut frame = Vec::new();
        ChannelData::encode(number, b"voice", Transport::Udp, &mut frame).unwrap();
        let Input::Data { peer: from, range } = client.handle_input(&frame, now) else {
            panic!("a bound channel carries data");
        };
        assert_eq!(from, peer());
        // the range is into the frame the caller still owns, which is the
        // whole point of answering with one
        assert_eq!(&frame[range], b"voice");

        // a number nobody bound is not ours, whatever it holds
        let mut stray = Vec::new();
        ChannelData::encode(
            ChannelNumber::new(0x4fff).unwrap(),
            b"voice",
            Transport::Udp,
            &mut stray,
        )
        .unwrap();
        assert_eq!(client.handle_input(&stray, now), Input::Foreign);
    }

    #[test]
    fn a_data_indication_needs_a_permission_and_an_address() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);

        let mut builder =
            MessageBuilder::new(Class::Indication, method::DATA, TransactionId::new([9; 12]));
        builder
            .add_xor_address(AttributeType::XOR_PEER_ADDRESS, peer())
            .unwrap();
        builder.add(AttributeType::DATA, b"voice").unwrap();
        let indication = builder.finish();

        // no permission yet, so the relay should not have sent this and we do
        // not believe it (§11.4)
        assert_eq!(client.handle_input(&indication, now), Input::Foreign);

        client.permit(peer().ip(), now);
        let request = sent(&mut client);
        let request = Message::parse(&request).unwrap();
        client.handle_input(&success(&request, |_| {}), now);

        let Input::Data { peer: from, range } = client.handle_input(&indication, now) else {
            panic!("a permitted peer's indication carries data");
        };
        assert_eq!(from, peer());
        assert_eq!(&indication[range], b"voice");
    }

    #[test]
    fn a_data_indication_with_an_icmp_attribute_reports_the_error() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        client.permit(peer().ip(), now);
        let raw = sent(&mut client);
        let request = Message::parse(&raw).unwrap();
        client.handle_input(&success(&request, |_| {}), now);

        let mut builder =
            MessageBuilder::new(Class::Indication, method::DATA, TransactionId::new([3; 12]));
        builder
            .add_xor_address(AttributeType::XOR_PEER_ADDRESS, peer())
            .unwrap();
        builder
            .add(AttributeType::ICMP, &[0, 0, 3, 4, 0, 0, 0x05, 0x00])
            .unwrap();
        let indication = builder.finish();

        match client.handle_input(&indication, now) {
            Input::Unreachable { peer: from, icmp } => {
                assert_eq!(from, peer());
                assert_eq!(icmp.path_mtu(AddressFamily::V4), Some(1280));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_response_that_fails_its_integrity_check_is_dropped_and_named_at_the_end() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let raw = sent(&mut client);
        let first = Message::parse(&raw).unwrap();
        client.handle_input(&challenge(&first, 401, NONCE), now);
        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();

        let mut builder =
            MessageBuilder::new(Class::Success, method::ALLOCATE, second.transaction_id());
        allocated_body(&[relay()], 600)(&mut builder);
        builder.add_message_integrity(b"the wrong key").unwrap();
        assert_eq!(client.handle_input(&builder.finish(), now), Input::Consumed);
        assert!(events(&mut client).is_empty());
        assert!(!client.is_allocated());

        // and the transaction dies of silence, named for what actually
        // happened rather than for the silence (RFC 8489 §9.2.5)
        let mut at = now;
        for _ in 0..8 {
            at += Duration::from_secs(60);
            client.handle_timeout(at);
        }
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::IntegrityViolated)]
        );
    }

    #[test]
    fn the_datagram_schedule_sends_seven_times_and_then_gives_up() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            credentials: None,
            ..TurnConfig::default()
        });
        client.supply_transaction_id(TransactionId::new([1; 12]));
        client.allocate(now).unwrap();

        let mut sends = 1;
        assert!(client.poll_transmit().is_some());
        for offset in [500_u64, 1500, 3500, 7500, 15500, 31500] {
            client.handle_timeout(now + Duration::from_millis(offset));
            assert!(client.deadline().is_some());
            sends += 1;
            assert!(client.poll_transmit().is_some(), "{offset}");
            assert_eq!(client.poll_transmit(), None, "{offset}");
        }
        assert_eq!(sends, 7);
        assert_eq!(client.deadline(), Some(now + Duration::from_millis(39500)));

        client.handle_timeout(now + Duration::from_millis(39500));
        assert_eq!(client.poll_transmit(), None);
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::TimedOut)]
        );
    }

    #[test]
    fn a_stream_transport_sends_once_and_waits_the_whole_ti() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            transport: Transport::Tls,
            credentials: None,
            ..TurnConfig::default()
        });
        client.supply_transaction_id(TransactionId::new([1; 12]));
        client.allocate(now).unwrap();
        assert!(client.poll_transmit().is_some());
        assert_eq!(client.deadline(), Some(now + Duration::from_millis(39500)));

        client.handle_timeout(now + Duration::from_millis(1000));
        assert_eq!(client.poll_transmit(), None, "TCP does the retransmitting");

        client.handle_timeout(now + Duration::from_millis(39500));
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::TimedOut)]
        );
    }

    #[test]
    fn a_channel_number_waits_five_minutes_before_it_can_name_another_peer() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);

        let first = client.bind_channel(peer(), now).unwrap();
        let _permission = sent(&mut client);
        let bind = sent(&mut client);
        let bind = Message::parse(&bind).unwrap();
        client.handle_input(&error(&bind, 508), now);
        assert_eq!(client.channel(peer()), None);

        ids.feed(&mut client);
        let second = client.bind_channel(other_peer(), now).unwrap();
        assert_ne!(second, first, "the number is still sitting out its wait");

        // the same peer may have the same number back at once, because
        // rebinding it is a refresh rather than a change of meaning
        ids.feed(&mut client);
        assert_eq!(client.bind_channel(peer(), now), Some(first));
    }

    #[test]
    fn a_dual_allocation_reports_both_addresses() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            families: FamilyRequest::Dual,
            ..config()
        });
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let first = sent(&mut client);
        let first = Message::parse(&first).unwrap();
        assert_eq!(
            first.find(AttributeType::ADDITIONAL_ADDRESS_FAMILY),
            Some(&[0x02, 0, 0, 0][..])
        );
        client.handle_input(&challenge(&first, 401, NONCE), now);

        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();
        let response = success(&second, allocated_body(&[relay(), relay_v6()], 600));
        client.handle_input(&response, now);

        assert_eq!(client.relayed_addresses(), &[relay(), relay_v6()]);
        assert_eq!(
            events(&mut client),
            vec![
                Event::Allocated {
                    relayed: relay(),
                    mapped: client.mapped_address(),
                    lifetime: Duration::from_secs(600),
                },
                Event::AlsoAllocated {
                    relayed: relay_v6()
                },
            ]
        );
    }

    #[test]
    fn a_half_served_dual_allocation_says_which_family_it_refused() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            families: FamilyRequest::Dual,
            ..config()
        });
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let raw = sent(&mut client);
        let first = Message::parse(&raw).unwrap();
        client.handle_input(&challenge(&first, 401, NONCE), now);
        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();

        let response = success(&second, |builder| {
            allocated_body(&[relay()], 600)(builder);
            builder
                .add(AttributeType::ADDRESS_ERROR_CODE, &[0x02, 0, 5, 8])
                .unwrap();
        });
        client.handle_input(&response, now);

        let seen = events(&mut client);
        assert_eq!(
            seen.last(),
            Some(&Event::FamilyRefused {
                family: AddressFamily::V6,
                code: 508
            })
        );
    }

    #[test]
    fn a_relayed_address_appended_after_the_integrity_is_not_there() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let raw = sent(&mut client);
        let first = Message::parse(&raw).unwrap();
        client.handle_input(&challenge(&first, 401, NONCE), now);
        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();

        let mut response = success(&second, allocated_body(&[relay()], 600));
        // an on-path attacker adds a second relayed address after the
        // integrity attribute, where nothing covers it
        let mut value = Vec::new();
        crate::stun::address::encode_xor(relay_v6(), second.transaction_id(), &mut value);
        response.extend_from_slice(&AttributeType::XOR_RELAYED_ADDRESS.code().to_be_bytes());
        response.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        response.extend_from_slice(&value);
        let body = u16::try_from(response.len() - 20).unwrap();
        response[2..4].copy_from_slice(&body.to_be_bytes());

        client.handle_input(&response, now);
        assert_eq!(client.relayed_addresses(), &[relay()]);
    }

    #[test]
    fn a_relayed_address_of_a_family_nobody_asked_for_ends_the_allocation() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            families: FamilyRequest::Only(AddressFamily::V6),
            ..config()
        });
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let raw = sent(&mut client);
        let first = Message::parse(&raw).unwrap();
        assert_eq!(
            first.find(AttributeType::REQUESTED_ADDRESS_FAMILY),
            Some(&[0x02, 0, 0, 0][..])
        );
        client.handle_input(&challenge(&first, 401, NONCE), now);
        ids.feed(&mut client);
        let second = sent(&mut client);
        let second = Message::parse(&second).unwrap();

        let response = success(&second, allocated_body(&[relay()], 600));
        client.handle_input(&response, now);
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::FamilyMismatch)]
        );
    }

    #[test]
    fn the_attribute_combinations_the_specification_forbids_are_refused() {
        let now = Instant::now();
        let token = crate::turn::attribute::ReservationToken::new([1; 8]);
        let cases = [
            (
                TurnConfig {
                    reservation_token: Some(token),
                    even_port: Some(EvenPort::Even),
                    ..config()
                },
                StartError::TokenAndEvenPort,
            ),
            (
                TurnConfig {
                    reservation_token: Some(token),
                    families: FamilyRequest::Dual,
                    ..config()
                },
                StartError::TokenAndFamily,
            ),
            (
                TurnConfig {
                    families: FamilyRequest::Dual,
                    even_port: Some(EvenPort::EvenAndReserveNext),
                    ..config()
                },
                StartError::DualAndReservation,
            ),
        ];
        for (config, expected) in cases {
            let mut client = TurnClient::new(config);
            client.supply_transaction_id(TransactionId::new([1; 12]));
            assert_eq!(client.allocate(now), Err(expected));
        }
    }

    #[test]
    fn an_empty_pool_stops_the_client_rather_than_making_an_id_up() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        assert_eq!(client.transaction_ids_wanted(), 8);
        assert_eq!(client.allocate(now), Err(StartError::NoTransactionId));

        client.supply_transaction_id(TransactionId::new([1; 12]));
        assert_eq!(client.transaction_ids_wanted(), 7);
        client.allocate(now).unwrap();
        assert_eq!(client.allocate(now), Err(StartError::Busy));
    }

    #[test]
    fn a_channel_bind_refuses_a_number_the_specification_does_not_have() {
        // the client only ever picks from the range, and the range is the one
        // Table 2 gives after RFC 7983 took the top of it back
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        for index in 0..5_u16 {
            let address = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, u8::try_from(index).unwrap())),
                3000,
            );
            ids.feed(&mut client);
            let number = client.bind_channel(address, now).unwrap();
            assert_eq!(number.get(), 0x4000 + index);
            assert!(ChannelNumber::new(number.get()).is_some());
        }
    }

    #[test]
    fn a_send_indication_carries_dont_fragment_only_when_the_server_took_it() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            dont_fragment: true,
            ..config()
        });
        let mut ids = Ids::new();
        allocate(&mut client, &mut ids, now, &[relay()]);
        let _seen = events(&mut client);
        ids.feed(&mut client);
        client.permit(peer().ip(), now);
        let raw = sent(&mut client);
        let request = Message::parse(&raw).unwrap();
        client.handle_input(&success(&request, |_| {}), now);

        let mut out = Vec::new();
        client.send_to(peer(), b"x", &mut out).unwrap();
        let indication = Message::parse(&out).unwrap();
        assert_eq!(indication.find(AttributeType::DONT_FRAGMENT), Some(&[][..]));
        // and the indication is not signed, because §5 says indications never
        // are
        assert!(!indication.has_integrity());
    }

    #[test]
    fn a_420_naming_dont_fragment_is_answered_by_asking_for_less() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            dont_fragment: true,
            ..config()
        });
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let raw = sent(&mut client);
        let first = Message::parse(&raw).unwrap();
        assert_eq!(first.find(AttributeType::DONT_FRAGMENT), Some(&[][..]));
        client.handle_input(&challenge(&first, 401, NONCE), now);

        ids.feed(&mut client);
        let raw = sent(&mut client);
        let second = Message::parse(&raw).unwrap();
        let mut builder =
            MessageBuilder::new(Class::Error, method::ALLOCATE, second.transaction_id());
        builder.add_error_code(420, b"no").unwrap();
        builder
            .add_unknown_attributes(&[AttributeType::DONT_FRAGMENT])
            .unwrap();
        builder.add_message_integrity(&key()).unwrap();
        client.handle_input(&builder.finish(), now);

        // "the client now knows that the server does not support the
        // DONT-FRAGMENT attribute [...] but MAY choose to retry the Allocate
        // request without the DONT-FRAGMENT attribute" (§7.4)
        let raw = sent(&mut client);
        let third = Message::parse(&raw).unwrap();
        assert_eq!(third.find(AttributeType::DONT_FRAGMENT), None);
        assert!(events(&mut client).is_empty());

        let response = success(&third, allocated_body(&[relay()], 600));
        client.handle_input(&response, now);
        ids.feed(&mut client);
        client.permit(peer().ip(), now);
        let raw = sent(&mut client);
        let request = Message::parse(&raw).unwrap();
        client.handle_input(&success(&request, |_| {}), now);

        let mut out = Vec::new();
        client.send_to(peer(), b"x", &mut out).unwrap();
        let indication = Message::parse(&out).unwrap();
        assert_eq!(indication.find(AttributeType::DONT_FRAGMENT), None);
    }

    #[test]
    fn a_420_naming_something_else_is_the_end_of_the_allocation() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            dont_fragment: true,
            ..config()
        });
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let raw = sent(&mut client);
        let first = Message::parse(&raw).unwrap();
        client.handle_input(&challenge(&first, 401, NONCE), now);
        ids.feed(&mut client);
        let raw = sent(&mut client);
        let second = Message::parse(&raw).unwrap();

        let mut builder =
            MessageBuilder::new(Class::Error, method::ALLOCATE, second.transaction_id());
        builder.add_error_code(420, b"no").unwrap();
        builder
            .add_unknown_attributes(&[AttributeType::EVEN_PORT])
            .unwrap();
        builder.add_message_integrity(&key()).unwrap();
        client.handle_input(&builder.finish(), now);
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::UnknownAttribute)]
        );
    }

    #[test]
    fn an_allocation_with_no_time_left_is_not_an_allocation() {
        let now = Instant::now();
        let mut client = TurnClient::new(config());
        let mut ids = Ids::new();
        ids.feed(&mut client);
        client.allocate(now).unwrap();
        let raw = sent(&mut client);
        let first = Message::parse(&raw).unwrap();
        client.handle_input(&challenge(&first, 401, NONCE), now);
        ids.feed(&mut client);
        let raw = sent(&mut client);
        let second = Message::parse(&raw).unwrap();

        let response = success(&second, allocated_body(&[relay()], 0));
        client.handle_input(&response, now);
        assert_eq!(
            events(&mut client),
            vec![Event::Closed(TurnError::Malformed)]
        );
        assert_eq!(client.deadline(), None);
    }

    #[test]
    fn a_refresh_answered_with_no_time_left_means_the_server_let_it_go() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        client.handle_timeout(now + Duration::from_secs(540));
        let raw = sent(&mut client);
        let request = Message::parse(&raw).unwrap();
        let response = success(&request, |builder| {
            builder.add_u32(AttributeType::LIFETIME, 0).unwrap();
        });
        client.handle_input(&response, now);
        assert_eq!(events(&mut client), vec![Event::Deleted]);
        assert!(!client.is_allocated());
    }

    #[test]
    fn a_channel_bind_installs_the_permission_a_refused_request_did_not() {
        let now = Instant::now();
        let (mut client, mut ids) = ready(now);
        ids.feed(&mut client);
        client.bind_channel(peer(), now).unwrap();

        let raw = sent(&mut client);
        let permission = Message::parse(&raw).unwrap();
        let raw = sent(&mut client);
        let bind = Message::parse(&raw).unwrap();
        client.handle_input(&error(&permission, 508), now);
        assert!(!client.has_permission(peer().ip()));

        // "A ChannelBind transaction also creates or refreshes a permission
        // towards the peer" (§12.1), so the peer is reachable again on the
        // strength of the binding alone
        client.handle_input(&success(&bind, |_| {}), now);
        assert!(client.has_permission(peer().ip()));
        let mut out = Vec::new();
        client.send_to(peer(), b"x", &mut out).unwrap();
        assert_eq!(out.first(), Some(&0x40));
    }

    #[test]
    fn a_stream_framed_channel_message_has_already_lost_its_padding() {
        let now = Instant::now();
        let mut client = TurnClient::new(TurnConfig {
            transport: Transport::Tls,
            ti: Duration::from_secs(3600),
            ..config()
        });
        let mut ids = Ids::new();
        allocate(&mut client, &mut ids, now, &[relay()]);
        let _seen = events(&mut client);
        ids.feed(&mut client);

        let number = client.bind_channel(peer(), now).unwrap();
        let raw = sent(&mut client);
        let permission = Message::parse(&raw).unwrap();
        let raw = sent(&mut client);
        let bind = Message::parse(&raw).unwrap();
        client.handle_input(&success(&permission, |_| {}), now);
        client.handle_input(&success(&bind, |_| {}), now);

        // what the framer hands over is the message without the padding that
        // kept the next frame aligned
        let mut wire = Vec::new();
        ChannelData::encode(number, b"abcde", Transport::Tls, &mut wire).unwrap();
        assert_eq!(wire.len(), 12);
        let mut framer = crate::turn::framing::StreamFraming::new();
        framer.push(&wire);
        let frame = framer.next_frame().unwrap().unwrap().to_vec();
        assert_eq!(frame.len(), 9);
        let Input::Data { peer: from, range } = client.handle_input(&frame, now) else {
            panic!("a bound channel carries data");
        };
        assert_eq!(from, peer());
        assert_eq!(&frame[range], b"abcde");

        // and what goes out over the same transport is padded again
        let mut out = Vec::new();
        client.send_to(peer(), b"abcde", &mut out).unwrap();
        assert_eq!(out.len(), 12);
    }

    #[test]
    fn a_response_for_a_transaction_nobody_started_is_ignored() {
        let now = Instant::now();
        let (mut client, _ids) = ready(now);
        let mut builder = MessageBuilder::new(
            Class::Success,
            method::REFRESH,
            TransactionId::new([0xaa; 12]),
        );
        builder.add_u32(AttributeType::LIFETIME, 600).unwrap();
        builder.add_message_integrity(&key()).unwrap();
        assert_eq!(client.handle_input(&builder.finish(), now), Input::Consumed);
        assert!(events(&mut client).is_empty());
        assert!(client.is_allocated());
    }

    #[test]
    fn a_binding_response_is_not_a_turn_response() {
        let now = Instant::now();
        let (mut client, _ids) = ready(now);
        let builder = MessageBuilder::new(
            Class::Success,
            Method::BINDING,
            TransactionId::new([0xbb; 12]),
        );
        assert_eq!(client.handle_input(&builder.finish(), now), Input::Consumed);
        assert!(events(&mut client).is_empty());
    }

    #[test]
    fn noise_on_the_socket_belongs_to_somebody_else() {
        let now = Instant::now();
        let (mut client, _ids) = ready(now);
        assert_eq!(client.handle_input(&[], now), Input::Foreign);
        assert_eq!(
            client.handle_input(&[0x80, 0x08, 0, 1], now),
            Input::Foreign
        );
        assert_eq!(client.handle_input(&[22, 0xfe, 0xfd], now), Input::Foreign);
    }
}
