// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The full agent: gathering, connectivity checks, nomination, role
//! conflicts, restarts, keepalives and consent (RFC 8445 in the full role,
//! RFC 7675 for consent freshness).
//!
//! Sans-I/O on the same terms as the rest of the crate. The caller binds the
//! host sockets and says which they are, supplies transaction ids drawn from a
//! cryptographic source, hands in every datagram that arrives on those sockets
//! with the time, and takes back what to send, from which socket, to where,
//! and when to call again. The agent never resolves a name, never reads a
//! clock and never draws a random number.
//!
//! One agent is one ICE session: a checklist per data stream, one role, one
//! tiebreaker and one set of local credentials for all of them (RFC 8839
//! §5.4 lets those be session-level). A restart restarts every stream.
//!
//! Two scope decisions are deliberate, and written down here so that they are
//! not mistaken for gaps:
//!
//! - **No trickle.** Candidates are gathered to completion before the caller
//!   writes its description, and [`IceEvent::GatheringComplete`] says when.
//!   Trickle ICE for SIP (RFC 8840) needs INFO packages that the PBXs this
//!   stack is aimed at do not carry, and gathering to completion costs a
//!   bounded, configurable wait ([`IceConfig::gathering_timeout`]).
//! - **RTP and RTCP multiplexed.** A stream normally has one component. The
//!   agent is written over component ids and works with two, but the SDP side
//!   pairs only what both ends offered, which with `a=rtcp-mux` on both is
//!   component 1 alone (RFC 5761 §5.1.3).

mod checks;
mod consent;
mod gather;
mod serve;
#[cfg(test)]
mod tests;

use core::fmt;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::agent::Role;
use super::candidate::{Candidate, CandidateType, ComponentId};
use super::checklist::{MAX_PRIORITY, PairState};
use super::sdp::RemoteIce;
use crate::demux::{Demux, classify};
use crate::stun::{BindingClient, Class, LongTermCredentials, Message, TransactionId};
use crate::turn::{Input, TurnClient};

/// Ta, the pacing timer: "ICE agents SHOULD use a default Ta value, 50 ms"
/// (RFC 8445 §14.2).
pub const DEFAULT_TA: Duration = Duration::from_millis(50);

/// The pair limit for a checklist set: "The default limit of candidate pairs
/// for the checklist set is 100, but the value MUST be configurable"
/// (RFC 8445 §6.1.2.5).
pub const DEFAULT_MAX_PAIRS: usize = 100;

/// Tr, the keepalive interval: "Agents SHOULD use a Tr value of 15 seconds.
/// Agents MAY use a bigger value but MUST NOT use a value smaller than 15
/// seconds" (RFC 8445 §11). Also the floor a configured value is raised to.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(15);

/// How long consent lasts without a fresh response: "Consent expires after 30
/// seconds" (RFC 7675 §5.1). Not configurable, because the RFC does not make
/// it so.
pub const CONSENT_EXPIRY: Duration = Duration::from_secs(30);

/// The basic period between consent checks: "Implementations SHOULD set a
/// default interval of 5 seconds" (RFC 7675 §5.1).
pub const DEFAULT_CONSENT_INTERVAL: Duration = Duration::from_secs(5);

/// "the combination of all transactions from all agents ... MUST NOT be sent
/// more often than once every 5 ms" (RFC 8445 §14.2). One agent cannot see the
/// others, so this is only its own floor; several agents in one process have
/// to share the budget above it.
const MIN_TA: Duration = Duration::from_millis(5);

/// The most a peer's `a=ice-pacing` is believed. RFC 8839 §5.5 allows ten
/// digits of milliseconds; nothing honest asks for more than a fraction of a
/// second, and a bound keeps every timer computed from Ta small.
const MAX_TA: Duration = Duration::from_secs(10);

/// How many transaction ids the agent likes to hold. Retransmissions reuse an
/// id; every new check, consent request and TURN transaction takes one.
const POOL: usize = 32;

/// Limits on what the caller configures, so that the local preferences
/// computed from them stay distinct inside sixteen bits.
const MAX_STREAMS: usize = 16;
const MAX_HOSTS: usize = 16;
const MAX_SERVERS: usize = 8;

/// How many checks that arrived before the peer's credentials the agent
/// remembers for later (RFC 8445 §7.3).
const MAX_EARLY: usize = 32;

/// The most datagrams an agent holds for [`IceAgent::poll_transmit`], and the
/// most answers the facade's lite end holds for the same.
///
/// Every Binding request that reaches a candidate is answered, a stranger's
/// unsigned one included (a 400 or a 401, RFC 8445 §7.3), so without a
/// ceiling the queue is as long as the flood an application that is slow to
/// drain it lets in. Past this many, the datagram being queued is dropped and
/// counted in [`IceAgent::transmits_dropped`]; what is already queued stays
/// and goes out in order. The new one gives way rather than the oldest
/// because every datagram here is a STUN transaction's, and a lost one is what
/// STUN retransmits for: the peer's check comes again, and the agent's own
/// is sent again on its own timer (RFC 8489 §6.2.1). Two hundred and
/// fifty-six is more than one pass of the agent queues of its own at the
/// default pair limit, so an application that drains after every call, as it
/// is told to, never reaches it.
pub const TRANSMIT_CEILING: usize = 256;

/// A TURN server to gather a relayed candidate from.
#[derive(Clone, Debug)]
pub struct TurnServer {
    /// Where it listens for UDP.
    pub address: SocketAddr,
    /// The long-term credential it expects, if any.
    pub credentials: Option<LongTermCredentials>,
}

/// How the agent behaves.
#[derive(Clone, Debug)]
pub struct IceConfig {
    /// The Ta this agent proposes in `a=ice-pacing`; the one it uses is the
    /// larger of this and the peer's, a peer that proposes none counting as
    /// proposing [`DEFAULT_TA`] (RFC 8445 §14.2).
    pub ta: Duration,
    /// The most candidate pairs the checklist set may hold (RFC 8445
    /// §6.1.2.5).
    pub max_pairs: usize,
    /// The most remote candidates a stream keeps, counting those learned from
    /// checks. Every one comes from the peer.
    pub max_remote_candidates: usize,
    /// STUN servers to learn server-reflexive candidates from.
    pub stun_servers: Vec<SocketAddr>,
    /// TURN servers to allocate relayed candidates on.
    pub turn_servers: Vec<TurnServer>,
    /// How long gathering may take before the candidates that have not
    /// arrived are given up on. A dead STUN server would otherwise hold the
    /// offer for the 39.5 seconds of a whole STUN transaction.
    pub gathering_timeout: Duration,
    /// How long a controlling agent waits, after a component's first valid
    /// pair, for a higher-priority pair to succeed before nominating the best
    /// one it has. RFC 8445 §8.1.1 leaves the stopping criterion to the
    /// implementation.
    pub nomination_wait: Duration,
    /// Tr (RFC 8445 §11); raised to fifteen seconds if set below.
    pub keepalive: Duration,
    /// The basic period between consent checks (RFC 7675 §5.1), randomised by
    /// ±20% on every check; no gap is ever shorter than four seconds.
    pub consent_interval: Duration,
    /// How long a checklist that has nothing to check is waited on before it
    /// Fails — the timer of RFC 8863, whose whole subject is that an agent
    /// with no pair left is not an agent that has failed.
    ///
    /// Two situations reach it, and neither is rare. A peer whose candidates
    /// were all unusable — a different address family, an FQDN, TCP only —
    /// leaves a checklist with no pairs at all. A checklist whose pairs have
    /// all failed is the same thing one step later. In both, a peer behind a
    /// NAT can still arrive with a check that forms a peer-reflexive pair and
    /// connects the call (§7.3.1.3), so failing at once would throw away a
    /// call that was about to work.
    ///
    /// The default is [`crate::turn::DEFAULT_TI`], the life of one whole STUN
    /// transaction: long enough that a peer whose first check was lost has
    /// retransmitted every time it is going to, and no longer.
    pub patience: Duration,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            ta: DEFAULT_TA,
            max_pairs: DEFAULT_MAX_PAIRS,
            max_remote_candidates: 32,
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            gathering_timeout: Duration::from_secs(5),
            nomination_wait: Duration::from_secs(1),
            keepalive: DEFAULT_KEEPALIVE,
            consent_interval: DEFAULT_CONSENT_INTERVAL,
            patience: crate::turn::DEFAULT_TI,
        }
    }
}

/// A username fragment and password (RFC 8445 §5.3, RFC 8839 §5.4).
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    ufrag: String,
    pwd: String,
}

impl Credentials {
    /// Credentials this agent will advertise.
    ///
    /// RFC 8445 §5.3 wants "at least 128 bits of random number generator
    /// output used to generate the password, and at least 24 bits of output
    /// to generate the username fragment", which the caller draws. What is
    /// checked here is the shape RFC 8839 §5.4 gives them on the way out: a
    /// fragment of 4 to 32 `ice-char`s and a password of 22 to 256.
    ///
    /// # Errors
    ///
    /// [`IceError::InvalidCredentials`] for anything outside that shape.
    pub fn new(ufrag: &str, pwd: &str) -> Result<Self, IceError> {
        Self::checked(ufrag, pwd, 32)
    }

    /// Credentials read from the peer, which "MUST accept up to 256
    /// characters" in the fragment (RFC 8839 §5.4).
    fn remote(ufrag: &str, pwd: &str) -> Result<Self, IceError> {
        Self::checked(ufrag, pwd, 256)
    }

    fn checked(ufrag: &str, pwd: &str, longest_ufrag: usize) -> Result<Self, IceError> {
        let ufrag_ok = (4..=longest_ufrag).contains(&ufrag.len()) && ice_chars(ufrag);
        let pwd_ok = (22..=256).contains(&pwd.len()) && ice_chars(pwd);
        if !ufrag_ok || !pwd_ok {
            return Err(IceError::InvalidCredentials);
        }
        Ok(Self {
            ufrag: ufrag.to_owned(),
            pwd: pwd.to_owned(),
        })
    }

    /// The username fragment, for `a=ice-ufrag`.
    #[must_use]
    pub fn ufrag(&self) -> &str {
        &self.ufrag
    }

    /// The password, for `a=ice-pwd`.
    #[must_use]
    pub fn pwd(&self) -> &str {
        &self.pwd
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("ufrag", &self.ufrag)
            .finish_non_exhaustive()
    }
}

fn ice_chars(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

/// A data stream of the session, in the order it was added, which is also
/// the checklist set's order (RFC 8445 §6.1.2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(usize);

impl StreamId {
    /// The stream's position, from zero.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// A datagram to put on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// The host socket to send it from.
    pub source: SocketAddr,
    /// Where to send it: a peer, a STUN server or a TURN server.
    pub destination: SocketAddr,
    /// The bytes.
    pub data: Vec<u8>,
}

/// Where [`IceAgent::send`] wants application data to go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// The host socket to send from.
    pub source: SocketAddr,
    /// The peer, or the TURN server when the pair is relayed.
    pub destination: SocketAddr,
}

/// What a datagram handed to [`IceAgent::handle_datagram`] turned out to be.
///
/// Application data comes back as a position in that datagram rather than as
/// a borrow of it, because what the caller does next with it is unprotect it
/// in place, and it cannot take a writable slice of a buffer this type is
/// still holding a shared one of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    /// Application data for a stream: RTP, RTCP, or anything else that is not
    /// STUN, with the relay's wrapping taken off if it came through one.
    /// Receiving is allowed on any candidate (RFC 8445 §12.2), so this says
    /// nothing about which pair is selected.
    ///
    /// The bytes are still whatever the peer sent: this layer separates STUN
    /// from everything else and reads no further, so DTLS records and RTP
    /// alike arrive here and the caller classifies them again.
    Data {
        /// The stream it belongs to.
        stream: StreamId,
        /// The component whose candidate it arrived on.
        component: ComponentId,
        /// Where the payload is in the datagram that was handed in.
        range: core::ops::Range<usize>,
    },
    /// ICE, STUN or TURN traffic, already dealt with.
    Consumed,
    /// Not on a socket this agent was given.
    Foreign,
}

/// A selected pair, as the caller needs it: what to put in `c=` and `m=`, and
/// where the media goes (RFC 8839 §4.2.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedPair {
    /// The local candidate's transport address.
    pub local: SocketAddr,
    /// What kind of candidate that is.
    pub local_kind: CandidateType,
    /// The remote candidate's transport address.
    pub remote: SocketAddr,
    /// What kind of candidate that is.
    pub remote_kind: CandidateType,
}

/// Something the caller should know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceEvent {
    /// Every candidate that is coming has come; the description can be
    /// written.
    GatheringComplete,
    /// A component has a selected pair: its checklist is Completed, or a
    /// later nomination of higher priority replaced the pair (RFC 8445
    /// §8.1.1).
    Selected {
        /// The stream.
        stream: StreamId,
        /// The component.
        component: ComponentId,
        /// The pair.
        pair: SelectedPair,
    },
    /// A stream's checklist Failed (RFC 8445 §7.2.5.4). The stream has to be
    /// removed or the session restarted.
    StreamFailed {
        /// The stream.
        stream: StreamId,
    },
    /// Every checklist is Completed (RFC 8445 §8.1.2).
    Completed,
    /// Every checklist Failed.
    Failed,
    /// No authenticated response on a selected pair for thirty seconds, or a
    /// 403 revoking consent (RFC 7675 §5). Nothing more may be sent on that
    /// pair, and the same credentials may not be used on it again: only a
    /// restart brings it back.
    ConsentLost {
        /// The stream.
        stream: StreamId,
        /// The component.
        component: ComponentId,
    },
    /// A role conflict switched this agent's role (RFC 8445 §7.2.5.1,
    /// §7.3.1.1).
    RoleChanged(Role),
}

/// The state of the session (RFC 8445 §6.1.3), with the two phases before
/// checks start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceState {
    /// Streams may be added; nothing has started.
    New,
    /// Gathering candidates.
    Gathering,
    /// Waiting for the peer, or checking.
    Running,
    /// Every checklist Completed.
    Completed,
    /// Every checklist Failed.
    Failed,
}

/// Why application data could not be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// No such stream, or no such component in it.
    UnknownStream,
    /// There is no valid pair to send on yet, or the stream's checklist has
    /// Failed and nothing may be sent on it any more (RFC 8445 §12.1).
    NoRoute,
    /// Consent on the selected pair is gone (RFC 7675 §5.1: "the endpoint
    /// MUST cease transmission on that 5-tuple").
    NoConsent,
    /// The pair is relayed and the TURN client could not wrap the data.
    Relay(crate::turn::SendError),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownStream => f.write_str("no such stream or component"),
            Self::NoRoute => f.write_str("no pair data may be sent on"),
            Self::NoConsent => f.write_str("consent to send has been lost"),
            Self::Relay(error) => write!(f, "relay: {error}"),
        }
    }
}

impl core::error::Error for SendError {}

/// Why a call to the agent was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceError {
    /// A username fragment or password outside the shape RFC 8839 §5.4
    /// gives them.
    InvalidCredentials,
    /// A restart that did not change both the fragment and the password,
    /// which RFC 8445 §9 requires.
    SameCredentials,
    /// The peer's credentials for a stream changed without a restart.
    RestartRequired,
    /// No such stream.
    UnknownStream,
    /// Streams can only be added, and gathering only started, before
    /// gathering has started.
    AlreadyStarted,
    /// More streams, host addresses or servers than the agent handles.
    TooMany,
    /// A stream with no host address the agent may use: loopback,
    /// unspecified, site-local and the deprecated IPv6 forms are refused
    /// (RFC 8445 §5.1.1.1).
    NoUsableHost,
    /// A server-reflexive address named a base that is not a host candidate
    /// of that stream and component — or gathering has not started, so there
    /// is no host candidate yet for it to be the base of.
    UnknownBase,
    /// A candidate arrived for a stream whose candidates have already been
    /// paired with the peer's, where it would be advertised and never checked.
    AlreadyPaired,
}

impl fmt::Display for IceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCredentials => "credentials outside the shape RFC 8839 gives them",
            Self::SameCredentials => "a restart has to change the fragment and the password",
            Self::RestartRequired => "the peer's credentials changed without a restart",
            Self::UnknownStream => "no such stream",
            Self::AlreadyStarted => "gathering has already started",
            Self::TooMany => "more streams, addresses or servers than the agent handles",
            Self::NoUsableHost => "no host address the agent may use",
            Self::UnknownBase => "not a host candidate of that stream and component",
            Self::AlreadyPaired => "the stream's candidates have already been paired",
        })
    }
}

impl core::error::Error for IceError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Gathering,
    Gathered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChecklistState {
    Running,
    Completed,
    Failed,
}

/// A host socket the caller bound.
struct Base {
    stream: usize,
    component: ComponentId,
    address: SocketAddr,
    /// The highest local preference in this base's block; see
    /// [`gather`](self::gather) for how the block is laid out.
    top: u16,
}

/// A local candidate: host, server-reflexive, peer-reflexive or relayed.
struct LocalCandidate {
    stream: usize,
    candidate: Candidate,
    /// The base (RFC 8445 §4): itself for host and relayed candidates, the
    /// host candidate for reflexive ones.
    base: SocketAddr,
    /// The host socket that packets for this candidate leave from.
    socket: SocketAddr,
    /// The allocation, for a relayed candidate.
    relay: Option<usize>,
    local_preference: u16,
}

struct Remote {
    stream: usize,
    candidate: Candidate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    Pending,
    Running,
    Done,
    /// A relayed candidate that ICE no longer needs was given back
    /// (RFC 8445 §8.3.1).
    Freed,
}

/// A STUN Binding transaction from one base to one server.
struct Gatherer {
    base: usize,
    server: SocketAddr,
    local_preference: u16,
    client: BindingClient,
    progress: Progress,
    /// Whether it produced a candidate, which is what makes the mapping worth
    /// keeping alive.
    produced: bool,
    /// When to ask again, keeping the server-reflexive mapping alive until
    /// ICE concludes (RFC 8445 §5.1.1.4).
    refresh_at: Option<Instant>,
}

/// A TURN allocation from one base on one server.
struct Allocation {
    base: usize,
    server: SocketAddr,
    relay_preference: u16,
    reflexive_preference: u16,
    client: TurnClient,
    progress: Progress,
    candidate: Option<usize>,
    /// When to send the next Binding indication to the server, so that the
    /// NAT mapping towards it outlives a long wait for the answer.
    refresh_at: Option<Instant>,
}

struct Stream {
    remote: Option<Credentials>,
    formed: bool,
    state: ChecklistState,
    triggered: VecDeque<u32>,
    components: Vec<Component>,
    /// When patience with a checklist that has nothing to check runs out
    /// (RFC 8863). Set when the checklist is formed — which is the first
    /// moment this agent has done everything it can and the rest is the
    /// peer's — and cleared by a restart, which starts the wait again.
    patience_until: Option<Instant>,
}

struct Component {
    id: ComponentId,
    first_valid: Option<Instant>,
    nominating: Option<u32>,
    selected: Option<usize>,
    consent: Option<Consent>,
}

#[derive(Clone, Copy)]
struct Consent {
    expires: Instant,
    next: Instant,
    last_sent: Instant,
    lost: bool,
}

struct Pair {
    id: u32,
    stream: usize,
    component: ComponentId,
    local: usize,
    remote: usize,
    priority: u64,
    state: PairState,
    /// The next check carries USE-CANDIDATE (RFC 8445 §8.1.1).
    nominate: bool,
    /// A USE-CANDIDATE request arrived before this pair succeeded; the valid
    /// pair its triggered check produces is nominated (RFC 8445 §7.3.1.5).
    nominate_on_success: bool,
    valid: Option<usize>,
}

struct Valid {
    stream: usize,
    component: ComponentId,
    local: usize,
    remote: usize,
    /// The host or relayed candidate the check left from, which is where data
    /// on this pair leaves from too.
    via: usize,
    generating: u32,
    priority: u64,
    nominated: bool,
    /// Removed from the valid list by a failed nomination (RFC 8445
    /// §7.2.5.3.4); kept in place so that indices stay stable.
    dead: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Connectivity { pair: u32 },
    Consent { previous: bool },
}

struct Check {
    id: TransactionId,
    purpose: Purpose,
    stream: usize,
    component: ComponentId,
    via: usize,
    destination: SocketAddr,
    request: Vec<u8>,
    key: Vec<u8>,
    use_candidate: bool,
    controlling: bool,
    priority: u32,
    sends: u32,
    rto: Duration,
    deadline: Instant,
    cancelled: bool,
}

/// A check that arrived before the peer's credentials did (RFC 8445 §7.3:
/// "Once the answer is received, it MUST proceed with the remaining steps").
struct Early {
    via: usize,
    from: SocketAddr,
    priority: u32,
    use_candidate: bool,
    remote_ufrag: Vec<u8>,
}

/// A selected pair from before a restart, still carrying data and still
/// under consent until the new session selects (RFC 8445 §12.1, RFC 7675
/// §5.1).
struct PreviousRoute {
    stream: usize,
    component: ComponentId,
    via: usize,
    destination: SocketAddr,
    local: Credentials,
    remote: Credentials,
    consent: Consent,
}

/// A full ICE agent.
pub struct IceAgent {
    config: IceConfig,
    local: Credentials,
    role: Role,
    tiebreaker: u64,
    ta: Duration,
    remote_lite: bool,
    phase: Phase,
    ids: VecDeque<TransactionId>,
    streams: Vec<Stream>,
    bases: Vec<Base>,
    locals: Vec<LocalCandidate>,
    remotes: Vec<Remote>,
    /// Every (type, base address, server address) a foundation has been
    /// handed out for, in the order they were; a foundation is its position
    /// plus one (RFC 8445 §5.1.1.3).
    foundations: Vec<(CandidateType, IpAddr, Option<IpAddr>)>,
    gatherers: Vec<Gatherer>,
    relays: Vec<Allocation>,
    gathering_until: Option<Instant>,
    pairs: Vec<Pair>,
    next_pair: u32,
    learned: u32,
    valid: Vec<Valid>,
    checks: Vec<Check>,
    early: Vec<Early>,
    previous: Vec<PreviousRoute>,
    next_paced: Option<Instant>,
    last_paced: Option<Instant>,
    cursor: usize,
    concluded: Option<Instant>,
    outbox: VecDeque<Transmit>,
    /// Datagrams [`TRANSMIT_CEILING`] kept out of `outbox`.
    dropped: u64,
    events: VecDeque<IceEvent>,
}

impl IceAgent {
    /// An agent with its configuration, the credentials it will advertise,
    /// its starting role ([`Role::initial_full`]) and a random 64-bit
    /// tiebreaker (RFC 8445 §7.3.1.1).
    ///
    /// # Errors
    ///
    /// [`IceError::TooMany`] for more than eight STUN or eight TURN servers.
    pub fn new(
        config: IceConfig,
        local: Credentials,
        role: Role,
        tiebreaker: u64,
    ) -> Result<Self, IceError> {
        if config.stun_servers.len() > MAX_SERVERS || config.turn_servers.len() > MAX_SERVERS {
            return Err(IceError::TooMany);
        }
        let mut config = config;
        config.ta = config.ta.clamp(MIN_TA, MAX_TA);
        config.keepalive = config.keepalive.max(DEFAULT_KEEPALIVE);
        Ok(Self {
            ta: config.ta,
            config,
            local,
            role,
            tiebreaker,
            remote_lite: false,
            phase: Phase::New,
            ids: VecDeque::new(),
            streams: Vec::new(),
            bases: Vec::new(),
            locals: Vec::new(),
            remotes: Vec::new(),
            foundations: Vec::new(),
            gatherers: Vec::new(),
            relays: Vec::new(),
            gathering_until: None,
            pairs: Vec::new(),
            next_pair: 0,
            learned: 0,
            valid: Vec::new(),
            checks: Vec::new(),
            early: Vec::new(),
            previous: Vec::new(),
            next_paced: None,
            last_paced: None,
            cursor: 0,
            concluded: None,
            outbox: VecDeque::new(),
            dropped: 0,
            events: VecDeque::new(),
        })
    }

    /// Add a data stream, with the host sockets the caller bound for it: one
    /// or more per component, in the caller's order of preference.
    ///
    /// Addresses RFC 8445 §5.1.1.1 rules out — loopback, unspecified,
    /// multicast, IPv6 site-local, IPv4-compatible and IPv4-mapped IPv6 — are
    /// left out rather than refused, and the stream is refused only if
    /// nothing is left.
    ///
    /// # Errors
    ///
    /// [`IceError::AlreadyStarted`] once gathering has begun,
    /// [`IceError::TooMany`] past sixteen streams or sixteen addresses for a
    /// component, [`IceError::NoUsableHost`] when no address is usable.
    pub fn add_stream(
        &mut self,
        hosts: &[(ComponentId, SocketAddr)],
    ) -> Result<StreamId, IceError> {
        if self.phase != Phase::New {
            return Err(IceError::AlreadyStarted);
        }
        if self.streams.len() >= MAX_STREAMS {
            return Err(IceError::TooMany);
        }
        let usable: Vec<(ComponentId, SocketAddr)> = hosts
            .iter()
            .copied()
            .filter(|(_, address)| usable_host(*address))
            .collect();
        if usable.is_empty() {
            return Err(IceError::NoUsableHost);
        }
        let mut components: Vec<ComponentId> = usable.iter().map(|(id, _)| *id).collect();
        components.sort_unstable();
        components.dedup();
        if components
            .iter()
            .any(|id| usable.iter().filter(|(c, _)| c == id).count() > MAX_HOSTS)
        {
            return Err(IceError::TooMany);
        }
        let stream = self.streams.len();
        self.streams.push(Stream {
            remote: None,
            formed: false,
            state: ChecklistState::Running,
            triggered: VecDeque::new(),
            patience_until: None,
            components: components.iter().map(|id| Component::new(*id)).collect(),
        });
        let block = self.preference_block();
        for (component, address) in usable {
            let rank = self
                .bases
                .iter()
                .filter(|base| base.stream == stream && base.component == component)
                .count();
            let offset = u16::try_from(rank)
                .unwrap_or(u16::MAX)
                .saturating_mul(block);
            self.bases.push(Base {
                stream,
                component,
                address,
                top: u16::MAX.saturating_sub(offset),
            });
        }
        Ok(StreamId(stream))
    }

    /// The credentials this agent advertises, for `a=ice-ufrag` and
    /// `a=ice-pwd`.
    #[must_use]
    pub const fn local_credentials(&self) -> &Credentials {
        &self.local
    }

    /// Controlling or controlled, as of now.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The Ta in use: the larger of this agent's and the peer's.
    #[must_use]
    pub const fn ta(&self) -> Duration {
        self.ta
    }

    /// The state of the session.
    #[must_use]
    pub fn state(&self) -> IceState {
        match self.phase {
            Phase::New => IceState::New,
            Phase::Gathering => IceState::Gathering,
            Phase::Gathered => {
                let states = || self.streams.iter().map(|stream| stream.state);
                if self.streams.is_empty() {
                    IceState::Running
                } else if states().all(|state| state == ChecklistState::Completed) {
                    IceState::Completed
                } else if states().all(|state| state == ChecklistState::Failed) {
                    IceState::Failed
                } else {
                    IceState::Running
                }
            }
        }
    }

    /// Accept what the peer said about a stream: its credentials, its
    /// candidates, whether it is lite and its pacing.
    ///
    /// Call it once per stream per session; again with the same credentials
    /// adds any candidates that were not there before. Candidates for a
    /// component this stream does not have are left out, which is how a
    /// multiplexed stream ignores a peer's RTCP candidates; a peer that offered
    /// fewer components than this stream has reduces the stream to those
    /// ("the minimum across both agents of the maximum component ID", RFC
    /// 8445 §6.1.2.2).
    ///
    /// # Errors
    ///
    /// [`IceError::UnknownStream`], [`IceError::InvalidCredentials`] for
    /// credentials outside RFC 8839 §5.4's shape, and
    /// [`IceError::RestartRequired`] when the credentials differ from the
    /// ones this session already holds for the stream.
    pub fn set_remote(
        &mut self,
        stream: StreamId,
        remote: &RemoteIce,
        now: Instant,
    ) -> Result<(), IceError> {
        let index = stream.0;
        let credentials = Credentials::remote(&remote.ufrag, &remote.pwd)?;
        let Some(entry) = self.streams.get_mut(index) else {
            return Err(IceError::UnknownStream);
        };
        match &entry.remote {
            Some(existing) if *existing != credentials => return Err(IceError::RestartRequired),
            Some(_) => {}
            None => {
                entry.remote = Some(credentials);
                if let Some(highest) = remote.candidates.iter().map(|c| c.component).max()
                    && entry.components.iter().any(|c| c.id <= highest)
                {
                    entry.components.retain(|c| c.id <= highest);
                }
            }
        }
        // "If an agent does not propose a value, the default value is used for
        // that agent when comparing which value is higher" (RFC 8445 §14.2);
        // a lite peer never proposes one
        let proposed = remote.pacing.unwrap_or(DEFAULT_TA);
        self.ta = self.ta.max(proposed.clamp(MIN_TA, MAX_TA));
        if remote.lite {
            self.remote_lite = true;
            if self.role == Role::Controlled {
                self.switch_role(Role::Controlling);
            }
        }
        self.add_remote_candidates(index, &remote.candidates);
        self.permit_remotes(index, now);
        if self.phase == Phase::Gathered {
            self.form_checklist(index, now);
            self.replay_early(index, now);
        }
        Ok(())
    }

    /// Restart ICE on every stream (RFC 8445 §9) with new credentials.
    ///
    /// Everything the session learned is flushed except the role, the
    /// tiebreaker and the gathered candidates. A pair that was selected keeps
    /// carrying data, and keeps being checked for consent under the old
    /// credentials, until the new session selects a pair for its component
    /// (RFC 8445 §12.1, RFC 7675 §5.1). The peer's new credentials and
    /// candidates come in through [`Self::set_remote`] as before.
    ///
    /// # Errors
    ///
    /// [`IceError::SameCredentials`] unless both the fragment and the
    /// password change.
    pub fn restart(&mut self, local: Credentials) -> Result<(), IceError> {
        if local.ufrag == self.local.ufrag || local.pwd == self.local.pwd {
            return Err(IceError::SameCredentials);
        }
        self.keep_previous_routes();
        self.local = local;
        self.pairs.clear();
        self.valid.clear();
        self.remotes.clear();
        self.early.clear();
        // Ta is "the larger of the two agents' values" for a session (RFC 8445
        // §14.2), and a restart is a new session: back to this agent's own
        // proposal, for the next `set_remote` to widen again if the peer asks.
        // Carrying it forward let one peer's `a=ice-pacing` slow every check,
        // every gathering transaction and every retransmission of this agent
        // for the rest of its life — including across the restart that a
        // network change makes, which is when the pacing matters most.
        self.ta = self.config.ta;
        self.checks
            .retain(|check| check.purpose == Purpose::Consent { previous: true });
        for (index, stream) in self.streams.iter_mut().enumerate() {
            stream.remote = None;
            stream.formed = false;
            stream.state = ChecklistState::Running;
            stream.triggered.clear();
            // a restart is a fresh session on the same sockets, so the wait
            // starts again rather than carrying the old one's remainder
            stream.patience_until = None;
            let mut ids: Vec<ComponentId> = self
                .bases
                .iter()
                .filter(|base| base.stream == index)
                .map(|base| base.component)
                .collect();
            ids.sort_unstable();
            ids.dedup();
            stream.components = ids.into_iter().map(Component::new).collect();
        }
        self.concluded = None;
        self.next_paced = None;
        Ok(())
    }

    /// Hand in a datagram that arrived on one of the host sockets.
    ///
    /// `local` is the socket it arrived on and `from` where it came from.
    pub fn handle_datagram(
        &mut self,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Received {
        let Some(base) = self.bases.iter().position(|entry| entry.address == local) else {
            return Received::Foreign;
        };
        if self.on_gatherer_datagram(base, from, data, now) {
            return Received::Consumed;
        }
        if let Some(relay) = self
            .relays
            .iter()
            .position(|entry| entry.base == base && entry.server == from)
        {
            return self.on_relay_datagram(relay, data, now);
        }
        let Some(host) = self.host_of(base) else {
            return Received::Foreign;
        };
        self.arrive(host, from, data, 0..data.len(), now)
    }

    /// Take the passing of time. Harmless to call early.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.gathering_timeout(now);
        self.checks_timeout(now);
        self.consider_nomination(now);
        self.consent_timeout(now);
        self.free_if_due(now);
        if self.next_paced.is_some_and(|at| at <= now) {
            self.paced(now);
        }
    }

    /// When [`Self::handle_timeout`] next has something to do.
    ///
    /// A deadline in the past means work is waiting on something the caller
    /// owes, which is always a transaction id.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        [
            self.gathering_deadline(),
            self.checks_deadline(),
            self.consent_deadline(),
            self.next_paced,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The next datagram to send.
    ///
    /// Drain it to empty after every call that moves the agent. What waits
    /// here is held to [`TRANSMIT_CEILING`], and what the ceiling kept out is
    /// counted in [`Self::transmits_dropped`].
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.outbox.pop_front()
    }

    /// How many datagrams this agent has dropped, since it was built, because
    /// [`TRANSMIT_CEILING`] of them were already waiting to be taken. A count
    /// that moves means the application is not draining
    /// [`Self::poll_transmit`] as fast as datagrams arrive, or that somebody
    /// is sending the port more checks than it can answer.
    #[must_use]
    pub const fn transmits_dropped(&self) -> u64 {
        self.dropped
    }

    /// The next event.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<IceEvent> {
        self.events.pop_front()
    }

    /// Hand the agent a transaction id drawn from a cryptographic source.
    ///
    /// Every check, consent request and TURN transaction needs one, and RFC
    /// 7675 §5.1 is explicit that consent is only as good as their
    /// unpredictability. A role conflict also takes one, as the new
    /// tiebreaker RFC 8445 §7.2.5.1 requires. Keep the pool full.
    pub fn supply_transaction_id(&mut self, id: TransactionId) {
        if self.ids.len() < POOL {
            self.ids.push_back(id);
        }
    }

    /// How many more ids the agent would like to be holding.
    #[must_use]
    pub fn transaction_ids_wanted(&self) -> usize {
        POOL - self.ids.len().min(POOL)
    }

    /// Wrap application data for a component and put it on the end of `out`.
    ///
    /// The pair is the selected one once there is one, the previous session's
    /// during a restart, and before that the highest-priority valid pair
    /// (RFC 8445 §12.1). A relayed pair's data goes through the TURN client.
    ///
    /// # Errors
    ///
    /// No such stream or component, no pair to send on, consent lost, or a
    /// relay that could not take the data.
    pub fn send(
        &mut self,
        stream: StreamId,
        component: ComponentId,
        data: &[u8],
        out: &mut Vec<u8>,
        now: Instant,
    ) -> Result<Route, SendError> {
        let (via, destination) = self.data_route(stream.0, component)?;
        let Some(local) = self.locals.get(via) else {
            return Err(SendError::NoRoute);
        };
        let source = local.socket;
        let route = match local.relay {
            None => {
                out.extend_from_slice(data);
                Route {
                    source,
                    destination,
                }
            }
            Some(relay) => {
                self.feed_relay(relay);
                let Some(entry) = self.relays.get_mut(relay) else {
                    return Err(SendError::NoRoute);
                };
                entry
                    .client
                    .send_to(destination, data, out)
                    .map_err(SendError::Relay)?;
                Route {
                    source,
                    destination: entry.server,
                }
            }
        };
        self.note_sent(stream.0, component, now);
        Ok(route)
    }

    /// Where [`Self::send`] would put a component's data, without sending any.
    ///
    /// The same question and the same rule as [`Self::send`] — the selected
    /// pair, the previous session's during a restart, otherwise the
    /// highest-priority valid pair — asked without handing over the data and
    /// without counting as traffic for the keepalive timer.
    ///
    /// It exists for a caller whose producer borrows its own buffer: one that
    /// cannot find out there is nowhere to send by trying, because by then it
    /// has already built a frame it will have to throw away, or taken a
    /// handshake record out of a flight it cannot put back. Asking first is
    /// what lets "there is no route" be a precondition rather than a failure.
    ///
    /// # Errors
    ///
    /// No such stream or component, no pair to send on, or consent lost.
    pub fn route(&self, stream: StreamId, component: ComponentId) -> Result<Route, SendError> {
        let (via, destination) = self.data_route(stream.0, component)?;
        let local = self.locals.get(via).ok_or(SendError::NoRoute)?;
        let source = local.socket;
        match local.relay {
            None => Ok(Route {
                source,
                destination,
            }),
            // a relayed pair's data goes to the server, not to the peer, and
            // the caller is told the address it will actually send to
            Some(relay) => Ok(Route {
                source,
                destination: self.relays.get(relay).ok_or(SendError::NoRoute)?.server,
            }),
        }
    }

    /// The selected pair for a component, once there is one.
    #[must_use]
    pub fn selected_pair(&self, stream: StreamId, component: ComponentId) -> Option<SelectedPair> {
        let selected = self
            .streams
            .get(stream.0)?
            .components
            .iter()
            .find(|entry| entry.id == component)?
            .selected?;
        self.describe(selected)
    }

    /// The candidates to advertise for a stream: host, server-reflexive and
    /// relayed, never peer-reflexive (RFC 8445 §7.2.5.3.1 learns those rather
    /// than exchanging them), and not a relayed candidate that has been given
    /// back.
    #[must_use]
    pub fn local_candidates(&self, stream: StreamId) -> Vec<Candidate> {
        self.locals
            .iter()
            .filter(|local| local.stream == stream.0)
            .filter(|local| local.candidate.kind != CandidateType::PeerReflexive)
            .filter(|local| {
                local.relay.is_none_or(|relay| {
                    self.relays
                        .get(relay)
                        .is_some_and(|entry| entry.progress != Progress::Freed)
                })
            })
            .map(|local| local.candidate.clone())
            .collect()
    }

    /// The candidate to put in `c=` and `m=` (or `a=rtcp`) for a component
    /// before nomination (RFC 8839 §4.2.1.2): the relayed one if there is one,
    /// since it is the most likely to reach a peer that does not do ICE, then
    /// server-reflexive, then host.
    #[must_use]
    pub fn default_candidate(&self, stream: StreamId, component: ComponentId) -> Option<Candidate> {
        let rank = |kind: CandidateType| match kind {
            CandidateType::Relay => 0,
            CandidateType::ServerReflexive => 1,
            CandidateType::Host => 2,
            CandidateType::PeerReflexive => 3,
        };
        self.local_candidates(stream)
            .into_iter()
            .filter(|candidate| candidate.component == component)
            .min_by_key(|candidate| (rank(candidate.kind), u32::MAX - candidate.priority))
    }

    fn on_relay_datagram(&mut self, relay: usize, data: &[u8], now: Instant) -> Received {
        self.feed_relay(relay);
        let Some(entry) = self.relays.get_mut(relay) else {
            return Received::Foreign;
        };
        let delivered = match entry.client.handle_input(data, now) {
            Input::Data { peer, range } => entry.candidate.map(|local| (local, peer, range)),
            Input::Consumed | Input::Unreachable { .. } => None,
            Input::Foreign => return Received::Foreign,
        };
        self.drain_relay(relay, now);
        match delivered {
            // the relay hands back a position in the same datagram, so the
            // range the caller is given is still one into what it passed in
            Some((local, peer, range)) => {
                let inner = data.get(range.clone()).unwrap_or_default();
                self.arrive(local, peer, inner, range, now)
            }
            None => Received::Consumed,
        }
    }

    /// A datagram that arrived on a local candidate: a host socket, or a
    /// relayed address with the TURN wrapping already taken off.
    fn arrive(
        &mut self,
        local: usize,
        from: SocketAddr,
        data: &[u8],
        range: core::ops::Range<usize>,
        now: Instant,
    ) -> Received {
        let Some(entry) = self.locals.get(local) else {
            return Received::Foreign;
        };
        let (stream, component) = (entry.stream, entry.candidate.component);
        if classify(data) != Demux::Stun {
            return Received::Data {
                stream: StreamId(stream),
                component,
                range,
            };
        }
        let Ok(message) = Message::parse(data) else {
            return Received::Consumed;
        };
        match message.class() {
            Class::Request => self.serve(local, from, &message, now),
            Class::Success | Class::Error => self.on_response(local, from, &message, now),
            // a keepalive (RFC 8445 §11): its only job was to cross the NAT
            Class::Indication => {}
        }
        Received::Consumed
    }

    fn host_of(&self, base: usize) -> Option<usize> {
        let address = self.bases.get(base)?.address;
        self.locals.iter().position(|local| {
            local.candidate.kind == CandidateType::Host && local.candidate.address == address
        })
    }

    fn take_id(&mut self) -> Option<TransactionId> {
        self.ids.pop_front()
    }

    fn feed_relay(&mut self, relay: usize) {
        let Some(entry) = self.relays.get_mut(relay) else {
            return;
        };
        while entry.client.transaction_ids_wanted() > 0 {
            let Some(id) = self.ids.pop_front() else {
                break;
            };
            entry.client.supply_transaction_id(id);
        }
    }

    /// Put a STUN message on the wire from a local candidate: straight out of
    /// the host socket, or through the TURN client for a relayed candidate.
    fn transmit(&mut self, via: usize, destination: SocketAddr, data: &[u8]) -> bool {
        let Some(local) = self.locals.get(via) else {
            return false;
        };
        let source = local.socket;
        let Some(relay) = local.relay else {
            self.queue(Transmit {
                source,
                destination,
                data: data.to_vec(),
            });
            return true;
        };
        self.feed_relay(relay);
        let Some(entry) = self.relays.get_mut(relay) else {
            return false;
        };
        let mut wrapped = Vec::new();
        if entry
            .client
            .send_to(destination, data, &mut wrapped)
            .is_err()
        {
            return false;
        }
        let server = entry.server;
        self.queue(Transmit {
            source,
            destination: server,
            data: wrapped,
        });
        true
    }

    /// Put a datagram in the outbox, or drop and count it when
    /// [`TRANSMIT_CEILING`] are already waiting.
    ///
    /// A dropped datagram still counts as sent to whatever queued it: to the
    /// transaction it belongs to it is a datagram the network lost.
    fn queue(&mut self, transmit: Transmit) {
        if self.outbox.len() >= TRANSMIT_CEILING {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.outbox.push_back(transmit);
    }

    fn switch_role(&mut self, role: Role) {
        if self.role == role {
            return;
        }
        self.role = role;
        self.reprioritise();
        self.events.push_back(IceEvent::RoleChanged(role));
    }

    fn describe(&self, valid: usize) -> Option<SelectedPair> {
        let entry = self.valid.get(valid)?;
        let local = &self.locals.get(entry.local)?.candidate;
        let remote = &self.remotes.get(entry.remote)?.candidate;
        Some(SelectedPair {
            local: local.address,
            local_kind: local.kind,
            remote: remote.address,
            remote_kind: remote.kind,
        })
    }

    /// Local preferences are handed out in blocks, one per host address of a
    /// component, so that every candidate of a component gets a distinct one
    /// and a peer-reflexive priority derived from its base does too
    /// (RFC 8445 §5.1.2.1: "the local preference MUST be unique"). A block
    /// holds the host candidate, one server-reflexive candidate per STUN
    /// server, and a relayed and a server-reflexive candidate per TURN server.
    fn preference_block(&self) -> u16 {
        let servers = 1 + self.config.stun_servers.len() + 2 * self.config.turn_servers.len();
        u16::try_from(servers).unwrap_or(u16::MAX)
    }
}

impl Component {
    const fn new(id: ComponentId) -> Self {
        Self {
            id,
            first_valid: None,
            nominating: None,
            selected: None,
            consent: None,
        }
    }
}

impl fmt::Debug for IceAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceAgent")
            .field("role", &self.role)
            .field("state", &self.state())
            .field("streams", &self.streams.len())
            .field("pairs", &self.pairs.len())
            .finish_non_exhaustive()
    }
}

/// Whether RFC 8445 §5.1.1.1 lets a host address be a candidate.
fn usable_host(address: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            let [first, second, third, fourth, fifth, sixth, _, _] = v6.segments();
            let site_local = first & 0xffc0 == 0xfec0;
            let compatible = [first, second, third, fourth, fifth, sixth] == [0; 6];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || site_local
                || compatible
                || v6.to_ipv4_mapped().is_some())
        }
    }
}

/// Whether an address is IPv6 link-local, which "MUST NOT be paired with other
/// than link-local addresses" (RFC 8445 §6.1.2.2).
fn link_local(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => v6
            .segments()
            .first()
            .is_some_and(|first| first & 0xffc0 == 0xfe80),
    }
}

/// Whether a priority read from the peer is one RFC 8445 §5.1.2 allows.
const fn priority_in_range(priority: u32) -> bool {
    priority != 0 && priority <= MAX_PRIORITY
}
