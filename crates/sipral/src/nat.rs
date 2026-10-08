// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Where this end appears from, asked of a STUN server (RFC 8489), and where the answer goes.
//!
//! Behind a NAT a softphone writes a private address into two places the far end acts on: the
//! `Contact` of REGISTER and INVITE, and the `c=`/`m=` lines of each description. `rport` (RFC
//! 3581) and symmetric RTP (RFC 7362) fix most paths (`docs/06-nat.md`), but not a registrar
//! without a NAT helper or a peer that sends only where `c=` says. For those this end must state
//! the right address, learned with a STUN Binding request from the socket in question.
//!
//! # Two sockets, two answers
//!
//! The signalling socket and each media socket are separate NAT bindings and usually map to
//! different public ports. [`Mappings`] runs one Binding transaction per named socket.
//!
//! - **The signalling socket** stays mapped while open ([`Keep::Refreshed`]): asked again every
//!   [`Mappings::refresh`] interval, 25 s by default like the endpoint's stream keepalive. An idle
//!   mapping is released by the NAT, and a changed answer is [`MappingEvent::Moved`]. Both answers
//!   go to [`UserAgent::readdress`](crate::UserAgent::readdress), which moves every account's
//!   `Contact` and re-registers.
//! - **A media socket** is asked before its description is written ([`Keep::Once`]), and the answer
//!   goes to [`CallMedia::public_address`](crate::CallMedia::public_address). Until the call it is
//!   refreshed like the signalling socket, since nothing else crosses its binding. Once the call
//!   runs, RTP and RTCP hold the binding and the application forgets the socket.
//!
//! # More than one server
//!
//! Public STUN servers disappear without notice. [`Mappings::fallbacks`] lists servers in order. A
//! transaction that ends without an address (no answer in 5.5 s, or a refusal) moves every socket
//! using that server to the next one at once. The failed server is skipped for 30 s, doubling per
//! failure up to 10 minutes, and an answer clears that. While it backs off only a signalling
//! refresh retries it, so a recovered better server is found again without spending a media
//! socket's first answer, which a call waits for. [`MappingEvent::ServerChanged`] reports a switch;
//! [`MappingEvent::ServersFailed`] reports that every server of the family failed, and sockets then
//! keep their last answer or their own address. [`Mappings::set_servers`] replaces the list at run
//! time.
//!
//! # What this does not do
//!
//! **No socket**: the application sends what [`Mappings::poll_transmit`] returns and hands in what
//! arrives. **No `Via` change**: `sent-by` stays local, since `rport` already routes responses and
//! a strict server could catch a `Via` naming an address the host does not own. **No NAT
//! classification**, which RFC 5389 dropped.
//!
//! Transaction ids come from an application seed or the media engine's generator
//! ([`MediaEngine::mappings`]). They are all that stops an off-path attacker from answering first
//! with an address of its choosing, which this end would then advertise in every `Contact` and
//! offer.
//!
//! [`MediaEngine::mappings`]: crate::MediaEngine::mappings

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::auth::KeySource;
use sipral_nat::stun::{BindingClient, BindingConfig, Failure, Progress, TransactionId};

/// How often the signalling socket's mapping is refreshed unless [`Mappings::refresh`] says
/// otherwise.
///
/// 25 s, as `EndpointConfig::keepalive_interval`: short enough for NATs that drop idle UDP mappings
/// after 30 s, which RFC 4787 §4.3 forbids but which exist.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(25);

/// Requests per transaction before giving up: at 0, 0.5, 1.5 and 3.5 s, then 2 s for the last
/// answer, 5.5 s in all. RFC 8489 §6.2.1's default Rc of 7 waits 39.5 s, too long to hold a
/// REGISTER or an offer.
const REQUESTS: u32 = 4;

/// Multiples of the RTO waited after the last request (RFC 8489 §6.2.1's Rm).
const LAST_WAIT: u32 = 4;

/// How long a failed server is first skipped. Longer than the 25 s refresh, so the next refresh
/// goes to the replacement.
const FIRST_BACK_OFF: Duration = Duration::from_secs(30);

/// The longest a failed server is skipped: a dead server costs one unanswered refresh every ten
/// minutes, and a recovered one is used again within ten minutes.
const LONGEST_BACK_OFF: Duration = Duration::from_secs(600);

/// How many events wait for [`Mappings::poll_event`] before the oldest is dropped. An application
/// that asks [`Mappings::public`] instead of reading them would otherwise keep one for every socket
/// it ever mapped, a call's worth each, for the life of the process.
const EVENTS_KEPT: usize = 256;

/// Queue `event`, dropping the oldest past [`EVENTS_KEPT`].
fn queue_event(events: &mut VecDeque<MappingEvent>, event: MappingEvent) {
    if events.len() >= EVENTS_KEPT {
        events.pop_front();
    }
    events.push_back(event);
}

/// How long a socket's mapping is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// Refreshed every [`Mappings::refresh`] while mapped: the signalling socket, idle for minutes,
    /// whose mapping must outlive the silence.
    Refreshed,
    /// A media socket, whose own traffic holds the binding once its call runs. Named again, it
    /// drops its old answer; once answered it is refreshed every [`Mappings::refresh`] until
    /// forgotten, so a call's address is never older than that.
    Once,
}

/// Where one socket's mapping stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingState {
    /// Asked, not answered yet. A description naming this socket would be wrong, so wait; the
    /// answer comes within 5.5 s either way.
    Asking,
    /// This socket appears at this address.
    Mapped(SocketAddr),
    /// The server did not answer. The socket is described by its own address, as without STUN.
    Unmapped,
}

/// What [`Mappings`] learned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingEvent {
    /// A socket's first answer: it appears at `public`.
    Learned {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// Where the server saw it.
        public: SocketAddr,
    },
    /// A refresh returned a different address: the NAT made a new mapping or the network changed.
    /// Anything advertising `previous` is now unreachable. A media socket waiting for its call is
    /// described with `public`.
    Moved {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// What it was.
        previous: SocketAddr,
        /// What it is now.
        public: SocketAddr,
    },
    /// The first transaction for a socket ([`Mappings::map`]) ended without an address and no other
    /// server was left. The socket is [`MappingState::Unmapped`] and described by its own address;
    /// a [`Keep::Refreshed`] socket asks again at the next refresh, and a later answer arrives as
    /// [`MappingEvent::Learned`].
    ///
    /// An unanswered refresh is not reported: the last address stays the best guess.
    Unanswered {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// Why.
        failure: Failure,
    },
    /// The server used for `server`'s address family changed: `previous` failed and the next took
    /// over, a refresh found an earlier server answering again, or [`Mappings::set_servers`]
    /// replaced the list. Learned addresses stand until the new server says otherwise, possibly as
    /// [`MappingEvent::Moved`] behind a NAT that maps per destination.
    ServerChanged {
        /// The server that was in use.
        previous: SocketAddr,
        /// The server in use now.
        server: SocketAddr,
    },
    /// Every server of `last`'s family failed and is backing off. Sockets keep their last address
    /// or their own, and refreshes keep asking the server whose back-off ends first. Reported once
    /// until a server answers again.
    ServersFailed {
        /// The server whose failure left none.
        last: SocketAddr,
    },
}

/// A Binding request for the application's socket to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StunDatagram {
    /// The socket to send it from: the one the mapping is about.
    pub local: SocketAddr,
    /// The STUN server.
    pub destination: SocketAddr,
    /// The request.
    pub payload: Vec<u8>,
}

/// One socket's transaction and what it has learned.
struct Socket {
    keep: Keep,
    client: BindingClient,
    public: Option<SocketAddr>,
    /// Whether a transaction is running.
    asking: bool,
    /// Whether the first transaction has ended, either way.
    settled: bool,
    /// When a [`Keep::Refreshed`] socket asks again.
    refresh_at: Option<Instant>,
    /// The server the running transaction, or the last one, asked.
    server: Option<SocketAddr>,
}

/// One server in the list, and how its last failure left it.
struct Server {
    address: SocketAddr,
    /// How long it was last passed over for; zero while it answers.
    back_off: Duration,
    /// Until when it is passed over, if it is.
    until: Option<Instant>,
}

impl Server {
    fn backing_off(&self, now: Instant) -> bool {
        self.until.is_some_and(|until| until > now)
    }
}

/// The [`PerFamily`] slot of `address`: `true` for IPv4.
const fn family(address: SocketAddr) -> bool {
    address.is_ipv4()
}

/// Something kept once for IPv4 and once for IPv6.
#[derive(Clone, Copy, Debug, Default)]
struct PerFamily<T> {
    v4: T,
    v6: T,
}

impl<T> PerFamily<T> {
    const fn of(&self, ipv4: bool) -> &T {
        if ipv4 { &self.v4 } else { &self.v6 }
    }

    const fn of_mut(&mut self, ipv4: bool) -> &mut T {
        if ipv4 { &mut self.v4 } else { &mut self.v6 }
    }
}

/// The STUN mappings of the application's sockets, against one server and its fallbacks.
///
/// Sans-I/O: `now` is passed in, the application's sockets do the I/O, and nothing here reads a
/// clock or OS randomness.
pub struct Mappings {
    /// In order of preference; never empty.
    servers: Vec<Server>,
    /// The first server, reported as the one asked when the list has no IPv4 server.
    first: SocketAddr,
    /// The server in use, per address family, once one has been asked.
    in_use: PerFamily<Option<SocketAddr>>,
    /// Whether [`MappingEvent::ServersFailed`] was reported per family, with no answer since.
    exhausted: PerFamily<bool>,
    refresh: Duration,
    keys: KeySource,
    sockets: BTreeMap<SocketAddr, Socket>,
    outbox: VecDeque<StunDatagram>,
    events: VecDeque<MappingEvent>,
}

impl Mappings {
    /// Mappings against `server`, with transaction ids drawn from `seed`.
    ///
    /// `seed` must be 32 bytes from a cryptographic generator, not shared with any other part of
    /// the stack; see the module docs for why.
    /// [`MediaEngine::mappings`](crate::MediaEngine::mappings) uses the engine's generator instead.
    #[must_use]
    pub fn new(server: SocketAddr, seed: [u8; 32]) -> Self {
        Self {
            servers: vec![Server {
                address: server,
                back_off: Duration::ZERO,
                until: None,
            }],
            first: server,
            in_use: PerFamily::default(),
            exhausted: PerFamily::default(),
            refresh: DEFAULT_REFRESH,
            keys: KeySource::new(seed),
            sockets: BTreeMap::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Refresh every `every` instead of [`DEFAULT_REFRESH`], for [`Keep::Refreshed`] sockets and
    /// answered [`Keep::Once`] ones. Zero is taken as one second so it cannot spin.
    #[must_use]
    pub fn refresh(mut self, every: Duration) -> Self {
        self.refresh = every.max(Duration::from_secs(1));
        self
    }

    /// Fall back to `more`, in order, when the server before them fails. Duplicates are ignored.
    /// See the module docs for the switching rules.
    #[must_use]
    pub fn fallbacks(mut self, more: impl IntoIterator<Item = SocketAddr>) -> Self {
        for address in more {
            self.add(address);
        }
        self
    }

    fn add(&mut self, address: SocketAddr) {
        if !self.servers.iter().any(|server| server.address == address) {
            self.servers.push(Server {
                address,
                back_off: Duration::ZERO,
                until: None,
            });
        }
    }

    /// The server a new IPv4 socket would ask now: the one in use, or the first in the list.
    #[must_use]
    pub fn server(&self) -> SocketAddr {
        self.in_use
            .v4
            .filter(|current| self.servers.iter().any(|server| server.address == *current))
            .or_else(|| {
                self.servers
                    .iter()
                    .find(|server| server.address.is_ipv4())
                    .map(|server| server.address)
            })
            .unwrap_or(self.first)
    }

    /// Every server, in order of preference.
    pub fn servers(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.servers.iter().map(|server| server.address)
    }

    /// Replace the server list on a running stack with `first` then `rest`, keeping every socket.
    ///
    /// Every socket is asked again at once of its family's first server, abandoning transactions to
    /// servers no longer listed. Learned addresses stand until the new server answers. A server
    /// kept from the old list keeps its back-off. [`MappingEvent::ServerChanged`] reports where the
    /// server in use changes. Sockets of a family with no server stop being asked and keep what
    /// they learned.
    pub fn set_servers(
        &mut self,
        first: SocketAddr,
        rest: impl IntoIterator<Item = SocketAddr>,
        now: Instant,
    ) {
        self.first = first;
        let mut old = core::mem::take(&mut self.servers);
        for address in core::iter::once(first).chain(rest) {
            if self.servers.iter().any(|server| server.address == address) {
                continue;
            }
            let kept = old
                .iter()
                .position(|server| server.address == address)
                .map(|at| old.swap_remove(at));
            self.servers.push(kept.unwrap_or(Server {
                address,
                back_off: Duration::ZERO,
                until: None,
            }));
        }
        self.exhausted = PerFamily::default();
        let all: Vec<SocketAddr> = self.sockets.keys().copied().collect();
        for local in &all {
            self.outbox.retain(|datagram| datagram.local != *local);
            if self.serves(*local) {
                self.ask(*local, now, true);
            } else if let Some(socket) = self.sockets.get_mut(local) {
                socket.asking = false;
                socket.refresh_at = None;
                if !socket.settled && socket.public.is_none() {
                    socket.settled = true;
                    queue_event(
                        &mut self.events,
                        MappingEvent::Unanswered {
                            local: *local,
                            failure: Failure::TimedOut,
                        },
                    );
                }
            }
        }
        for slot in [true, false] {
            // otherwise nothing would move the in-use server off an unlisted one
            let listed = self
                .in_use
                .of(slot)
                .is_some_and(|current| self.servers.iter().any(|server| server.address == current));
            if !listed
                && !all
                    .iter()
                    .any(|local| family(*local) == slot && self.serves(*local))
            {
                *self.in_use.of_mut(slot) = None;
            }
        }
    }

    /// Start asking where `local` appears from.
    ///
    /// A socket named again is asked again at once, and the answer is reported either way; `keep`
    /// replaces its old setting. [`Keep::Refreshed`] keeps its address until the answer differs
    /// ([`MappingEvent::Moved`]). [`Keep::Once`] drops its old answer and is
    /// [`MappingState::Asking`] until [`MappingEvent::Learned`] or [`MappingEvent::Unanswered`].
    ///
    /// Servers of the other family are never asked: a socket with no server of its family is
    /// [`MappingState::Unmapped`] at once, reported as [`MappingEvent::Unanswered`] with
    /// [`Failure::TimedOut`].
    pub fn map(&mut self, local: SocketAddr, keep: Keep, now: Instant) {
        let socket = self.sockets.entry(local).or_insert_with(|| Socket {
            keep,
            client: BindingClient::new(config()),
            public: None,
            asking: false,
            settled: false,
            refresh_at: None,
            server: None,
        });
        socket.keep = keep;
        // a renamed media socket drops its old answer: the application renamed it because nothing
        // kept it true, so descriptions wait for the new one. A signalling socket keeps its
        // address, which every `Contact` already names
        if keep == Keep::Once {
            socket.public = None;
        }
        if socket.public.is_none() {
            socket.settled = false;
        }
        if !self.serves(local) {
            if let Some(socket) = self.sockets.get_mut(&local) {
                socket.settled = true;
                socket.asking = false;
                socket.refresh_at = None;
            }
            queue_event(
                &mut self.events,
                MappingEvent::Unanswered {
                    local,
                    failure: Failure::TimedOut,
                },
            );
            return;
        }
        self.ask(local, now, keep == Keep::Refreshed);
    }

    /// Whether some server in the list is of `local`'s address family.
    fn serves(&self, local: SocketAddr) -> bool {
        self.servers
            .iter()
            .any(|server| family(server.address) == family(local))
    }

    /// Ask again now, ignoring the schedule, typically after a network change. Uses the first
    /// server not backing off, as a refresh does. No-op for an unmapped socket.
    pub fn ask_again(&mut self, local: SocketAddr, now: Instant) {
        if self.sockets.contains_key(&local) && self.serves(local) {
            self.ask(local, now, true);
        }
    }

    /// Stop keeping `local`: nothing more is sent, and its answer is forgotten.
    pub fn forget(&mut self, local: SocketAddr) {
        self.sockets.remove(&local);
        self.outbox.retain(|datagram| datagram.local != local);
    }

    /// Where `local`'s mapping stands, or `None` for a socket never named.
    #[must_use]
    pub fn state(&self, local: SocketAddr) -> Option<MappingState> {
        let socket = self.sockets.get(&local)?;
        Some(match (socket.public, socket.settled) {
            (Some(public), _) => MappingState::Mapped(public),
            (None, false) => MappingState::Asking,
            (None, true) => MappingState::Unmapped,
        })
    }

    /// The address `local` appears at, once a server has said.
    #[must_use]
    pub fn public(&self, local: SocketAddr) -> Option<SocketAddr> {
        self.sockets.get(&local).and_then(|socket| socket.public)
    }

    /// Feed a datagram that arrived on `local` from `from`, and say whether it was STUN from a
    /// listed server; if so, pass it nowhere else.
    ///
    /// Any STUN message from a listed server is taken, even when nothing is in flight (a
    /// retransmitted or late answer), so it does not reach the SIP or RTP parser. Only the server
    /// the transaction asked is believed; anything from elsewhere is left alone even if it looks
    /// like STUN.
    pub fn receive(
        &mut self,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        if !self.servers.iter().any(|server| server.address == from)
            || sipral_nat::classify(data) != sipral_nat::Demux::Stun
        {
            return false;
        }
        let Some(socket) = self.sockets.get_mut(&local) else {
            return false;
        };
        if socket.server != Some(from) {
            return true;
        }
        let progress = socket.client.on_datagram(data);
        self.on_progress(local, progress, now);
        true
    }

    /// The next request to send, from the socket it names. Drain after every [`Mappings::map`],
    /// every datagram handed in and every [`Mappings::poll_timeout`] deadline.
    pub fn poll_transmit(&mut self) -> Option<StunDatagram> {
        self.outbox.pop_front()
    }

    /// The next thing learned. At most 256 wait; past that the oldest is dropped, so an application
    /// that reads [`Mappings::public`] instead holds a bounded queue.
    pub fn poll_event(&mut self) -> Option<MappingEvent> {
        self.events.pop_front()
    }

    /// When something is next due: a retransmission, a timeout or a refresh.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.sockets
            .values()
            .filter_map(|socket| {
                if socket.asking {
                    socket.client.deadline()
                } else {
                    socket.refresh_at
                }
            })
            .min()
    }

    /// Take the passing of time.
    pub fn handle_timeout(&mut self, now: Instant) {
        let due: Vec<SocketAddr> = self
            .sockets
            .iter()
            .filter(|(_, socket)| {
                if socket.asking {
                    socket.client.deadline().is_some_and(|at| at <= now)
                } else {
                    socket.refresh_at.is_some_and(|at| at <= now)
                }
            })
            .map(|(local, _)| *local)
            .collect();
        for local in due {
            let Some(socket) = self.sockets.get_mut(&local) else {
                continue;
            };
            if socket.asking {
                let progress = socket.client.on_timeout(now);
                self.on_progress(local, progress, now);
            } else {
                let probe = socket.keep == Keep::Refreshed;
                self.ask(local, now, probe);
            }
        }
    }

    /// The server for a new transaction of `slot`'s family. A `probe` (a signalling refresh, or a
    /// question after a network change) takes the first server not backing off, so a recovered
    /// better server is found again; otherwise stay with the server in use. If all are backing off,
    /// the one whose back-off ends first.
    fn choose(&self, slot: bool, now: Instant, probe: bool) -> Option<SocketAddr> {
        if !probe
            && let Some(current) = *self.in_use.of(slot)
            && self
                .servers
                .iter()
                .any(|server| server.address == current && !server.backing_off(now))
        {
            return Some(current);
        }
        let of_family = || {
            self.servers
                .iter()
                .filter(move |server| family(server.address) == slot)
        };
        if let Some(server) = of_family().find(|server| !server.backing_off(now)) {
            return Some(server.address);
        }
        of_family()
            .min_by_key(|server| server.until)
            .map(|server| server.address)
    }

    /// A new transaction on `local`, to the server [`Mappings::choose`] picks.
    fn ask(&mut self, local: SocketAddr, now: Instant, probe: bool) {
        let slot = family(local);
        let Some(server) = self.choose(slot, now, probe) else {
            return;
        };
        if self.in_use.of(slot).is_none() {
            *self.in_use.of_mut(slot) = Some(server);
        }
        self.start(local, server, now);
    }

    /// A fresh transaction on `local`, to `server`.
    fn start(&mut self, local: SocketAddr, server: SocketAddr, now: Instant) {
        let block = self.keys.block();
        let mut id = [0_u8; 12];
        for (slot, byte) in id.iter_mut().zip(block.iter()) {
            *slot = *byte;
        }
        let Some(socket) = self.sockets.get_mut(&local) else {
            return;
        };
        socket.client = BindingClient::new(config());
        socket.asking = true;
        socket.refresh_at = None;
        socket.server = Some(server);
        let progress = socket.client.start(TransactionId::new(id), now);
        self.on_progress(local, progress, now);
    }

    /// The server in use for `slot`'s family is `server` from now on.
    fn use_server(&mut self, slot: bool, server: SocketAddr) {
        match *self.in_use.of(slot) {
            Some(previous) if previous != server => {
                queue_event(
                    &mut self.events,
                    MappingEvent::ServerChanged { previous, server },
                );
            }
            _ => {}
        }
        *self.in_use.of_mut(slot) = Some(server);
    }

    /// `asked` failed a transaction of `local`: it backs off, and if another server of the family
    /// is available every socket using `asked` moves there. `true` if so, and then nothing is
    /// reported.
    fn fail_over(&mut self, local: SocketAddr, asked: SocketAddr, now: Instant) -> bool {
        let slot = family(local);
        if let Some(server) = self
            .servers
            .iter_mut()
            .find(|server| server.address == asked)
            && !server.backing_off(now)
        {
            // a server already backing off failed a transaction started earlier, or one asked for
            // lack of a better one: the same failure, not a new one
            server.back_off = (server.back_off * 2).clamp(FIRST_BACK_OFF, LONGEST_BACK_OFF);
            server.until = now.checked_add(server.back_off);
        }
        let next = self
            .servers
            .iter()
            .find(|server| family(server.address) == slot && !server.backing_off(now))
            .map(|server| server.address);
        let Some(next) = next else {
            if !*self.exhausted.of(slot) {
                *self.exhausted.of_mut(slot) = true;
                queue_event(
                    &mut self.events,
                    MappingEvent::ServersFailed { last: asked },
                );
            }
            return false;
        };
        self.use_server(slot, next);
        let moving: Vec<SocketAddr> = self
            .sockets
            .iter()
            .filter(|(other, socket)| {
                **other == local || (socket.asking && socket.server == Some(asked))
            })
            .map(|(other, _)| *other)
            .collect();
        for other in moving {
            self.outbox.retain(|datagram| datagram.local != other);
            self.start(other, next, now);
        }
        true
    }

    fn on_progress(&mut self, local: SocketAddr, progress: Progress, now: Instant) {
        let refresh = self.refresh;
        let Some(socket) = self.sockets.get_mut(&local) else {
            return;
        };
        let Some(asked) = socket.server else {
            return;
        };
        let failure = match progress {
            Progress::Idle => return,
            Progress::Transmit => {
                self.outbox.push_back(StunDatagram {
                    local,
                    destination: asked,
                    payload: socket.client.datagram().to_vec(),
                });
                return;
            }
            Progress::Mapped(_) => None,
            // no credentials are configured, so a challenge ends like a refusal
            Progress::Challenged => Some(Failure::Unauthenticated),
            Progress::Failed(failure) => Some(failure),
        };
        let slot = family(local);
        if failure.is_some() {
            socket.asking = false;
            if self.fail_over(local, asked, now) {
                return;
            }
        } else {
            if let Some(server) = self
                .servers
                .iter_mut()
                .find(|server| server.address == asked)
            {
                server.back_off = Duration::ZERO;
                server.until = None;
            }
            *self.exhausted.of_mut(slot) = false;
            self.use_server(slot, asked);
        }
        let Some(socket) = self.sockets.get_mut(&local) else {
            return;
        };
        // only the failure of a socket's first transaction is reported; see
        // `MappingEvent::Unanswered`
        let first = socket.public.is_none() && !socket.settled;
        let ended = match (progress, failure) {
            (Progress::Mapped(public), _) => {
                let event = match socket.public {
                    None => Some(MappingEvent::Learned { local, public }),
                    Some(previous) if previous != public => Some(MappingEvent::Moved {
                        local,
                        previous,
                        public,
                    }),
                    Some(_) => None,
                };
                socket.public = Some(public);
                event
            }
            (_, Some(failure)) => first.then_some(MappingEvent::Unanswered { local, failure }),
            (_, None) => None,
        };
        socket.asking = false;
        socket.settled = true;
        // refresh a waiting media socket's answer, since nothing else holds its binding before the
        // call. A socket that never got an answer uses its own address and is left alone
        socket.refresh_at = match socket.keep {
            Keep::Refreshed => now.checked_add(refresh),
            Keep::Once => socket.public.and_then(|_| now.checked_add(refresh)),
        };
        if let Some(event) = ended {
            queue_event(&mut self.events, event);
        }
    }
}

/// Written by hand to print what was learned, not every transaction, and to keep the seed out of
/// logs.
impl core::fmt::Debug for Mappings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mappings")
            .field("servers", &self.servers().collect::<Vec<_>>())
            .field("in_use", &self.in_use)
            .field("refresh", &self.refresh)
            .field(
                "sockets",
                &self
                    .sockets
                    .iter()
                    .map(|(local, socket)| (*local, socket.public))
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// The retransmission schedule every transaction here runs on.
fn config() -> BindingConfig {
    BindingConfig {
        rc: REQUESTS,
        rm: LAST_WAIT,
        ..BindingConfig::default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use sipral_nat::stun::{
        AttributeType, Class, Failure, Message, MessageBuilder, Method, TransactionId,
    };

    use super::{EVENTS_KEPT, Keep, MappingEvent, MappingState, Mappings, StunDatagram};

    const SERVER: &str = "198.51.100.1:3478";
    const SIP: &str = "192.168.1.10:5060";
    const MEDIA: &str = "192.168.1.10:40000";

    fn at(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    fn drain(mappings: &mut Mappings) -> Vec<StunDatagram> {
        let mut all = Vec::new();
        while let Some(datagram) = mappings.poll_transmit() {
            all.push(datagram);
        }
        all
    }

    fn events(mappings: &mut Mappings) -> Vec<MappingEvent> {
        let mut all = Vec::new();
        while let Some(event) = mappings.poll_event() {
            all.push(event);
        }
        all
    }

    /// A STUN server's answer: the request's id and the address it came from.
    pub(crate) fn answer(request: &[u8], seen: SocketAddr) -> Vec<u8> {
        let id = Message::parse(request)
            .expect("a STUN request")
            .transaction_id();
        let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, id);
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, seen)
            .expect("an address");
        builder.add_fingerprint().expect("a fingerprint");
        builder.finish()
    }

    #[test]
    fn a_socket_learns_the_address_the_server_saw() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(SIP), Keep::Refreshed, now);
        assert_eq!(mappings.state(at(SIP)), Some(MappingState::Asking));
        let sent = drain(&mut mappings);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].local, at(SIP));
        assert_eq!(sent[0].destination, at(SERVER));
        assert_eq!(
            sent[0].payload.len(),
            28,
            "the header and FINGERPRINT, the figure docs/06-nat.md gives"
        );

        let taken = mappings.receive(
            at(SIP),
            at(SERVER),
            &answer(&sent[0].payload, at("203.0.113.7:41000")),
            now,
        );
        assert!(taken);
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::Learned {
                local: at(SIP),
                public: at("203.0.113.7:41000"),
            }]
        );
        assert_eq!(mappings.public(at(SIP)), Some(at("203.0.113.7:41000")));
    }

    #[test]
    fn an_application_that_reads_the_address_and_not_the_events_holds_a_bounded_queue() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        let calls = u16::try_from(EVENTS_KEPT).expect("a port count") + 44;
        for call in 0..calls {
            let local = SocketAddr::new(at(MEDIA).ip(), 40_000 + 2 * call);
            let public = SocketAddr::new(at("203.0.113.7:0").ip(), 50_000 + 2 * call);
            mappings.map(local, Keep::Once, now);
            let sent = drain(&mut mappings);
            assert!(mappings.receive(local, at(SERVER), &answer(&sent[0].payload, public), now));
            // what such an application reads, before the call takes the socket and ends
            assert_eq!(mappings.public(local), Some(public));
            mappings.forget(local);
        }
        let kept = events(&mut mappings);
        assert_eq!(kept.len(), EVENTS_KEPT);
        assert_eq!(
            kept.first(),
            Some(&MappingEvent::Learned {
                local: SocketAddr::new(at(MEDIA).ip(), 40_000 + 2 * 44),
                public: SocketAddr::new(at("203.0.113.7:0").ip(), 50_000 + 2 * 44),
            }),
            "the oldest were dropped first"
        );
    }

    #[test]
    fn only_the_server_is_believed() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(MEDIA), Keep::Once, now);
        let sent = drain(&mut mappings);
        let forged = answer(&sent[0].payload, at("198.51.100.66:9"));
        assert!(!mappings.receive(at(MEDIA), at("198.51.100.66:3478"), &forged, now));
        assert_eq!(mappings.state(at(MEDIA)), Some(MappingState::Asking));
        assert!(events(&mut mappings).is_empty());
    }

    #[test]
    fn an_answer_to_a_question_nobody_asked_changes_nothing() {
        // right server address and well-formed answer, but an id we never sent: what an off-path
        // attacker must guess
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(MEDIA), Keep::Once, now);
        let _sent = drain(&mut mappings);
        let mut builder =
            MessageBuilder::new(Class::Success, Method::BINDING, TransactionId::new([9; 12]));
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, at("198.51.100.66:9"))
            .expect("an address");
        assert!(mappings.receive(at(MEDIA), at(SERVER), &builder.finish(), now));
        assert_eq!(mappings.state(at(MEDIA)), Some(MappingState::Asking));
        assert!(events(&mut mappings).is_empty());
    }

    #[test]
    fn a_datagram_that_is_not_stun_is_left_for_the_caller() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(SIP), Keep::Refreshed, now);
        assert!(!mappings.receive(at(SIP), at(SERVER), b"SIP/2.0 200 OK\r\n\r\n", now));
    }

    #[test]
    fn two_transactions_never_share_an_id() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(SIP), Keep::Refreshed, now);
        mappings.map(at(MEDIA), Keep::Once, now);
        let ids: Vec<TransactionId> = drain(&mut mappings)
            .iter()
            .map(|datagram| {
                Message::parse(&datagram.payload)
                    .expect("STUN")
                    .transaction_id()
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn a_silent_server_leaves_the_socket_unmapped_within_the_budget() {
        let start = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(MEDIA), Keep::Once, start);
        let mut sent = drain(&mut mappings).len();
        let mut now = start;
        while let Some(due) = mappings.poll_timeout() {
            now = due;
            mappings.handle_timeout(now);
            sent += drain(&mut mappings).len();
        }
        assert_eq!(sent, 4, "Rc requests, and no more");
        assert_eq!(now - start, Duration::from_millis(5_500));
        assert_eq!(mappings.state(at(MEDIA)), Some(MappingState::Unmapped));
        assert_eq!(
            events(&mut mappings),
            vec![
                MappingEvent::ServersFailed { last: at(SERVER) },
                MappingEvent::Unanswered {
                    local: at(MEDIA),
                    failure: Failure::TimedOut,
                }
            ],
            "the one server there is has failed, and nothing is left to ask"
        );
        assert!(
            mappings.poll_timeout().is_none(),
            "a media socket is asked once"
        );
    }

    #[test]
    fn the_signalling_socket_is_asked_again_and_a_moved_mapping_is_reported() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]).refresh(Duration::from_secs(25));
        mappings.map(at(SIP), Keep::Refreshed, now);
        let first = drain(&mut mappings);
        mappings.receive(
            at(SIP),
            at(SERVER),
            &answer(&first[0].payload, at("203.0.113.7:41000")),
            now,
        );
        let _learned = events(&mut mappings);
        assert_eq!(mappings.poll_timeout(), Some(now + Duration::from_secs(25)));

        // the same answer again says nothing
        let later = now + Duration::from_secs(25);
        mappings.handle_timeout(later);
        let second = drain(&mut mappings);
        assert_eq!(second.len(), 1);
        mappings.receive(
            at(SIP),
            at(SERVER),
            &answer(&second[0].payload, at("203.0.113.7:41000")),
            later,
        );
        assert!(events(&mut mappings).is_empty());

        // a different one is the mapping having moved
        let moved = later + Duration::from_secs(25);
        mappings.handle_timeout(moved);
        let third = drain(&mut mappings);
        mappings.receive(
            at(SIP),
            at(SERVER),
            &answer(&third[0].payload, at("203.0.113.7:52000")),
            moved,
        );
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::Moved {
                local: at(SIP),
                previous: at("203.0.113.7:41000"),
                public: at("203.0.113.7:52000"),
            }]
        );
    }

    #[test]
    fn an_unanswered_refresh_keeps_the_address_it_had() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(SIP), Keep::Refreshed, now);
        let first = drain(&mut mappings);
        mappings.receive(
            at(SIP),
            at(SERVER),
            &answer(&first[0].payload, at("203.0.113.7:41000")),
            now,
        );
        let _learned = events(&mut mappings);
        let mut clock = now + super::DEFAULT_REFRESH;
        mappings.handle_timeout(clock);
        // the refresh goes unanswered and the next one is scheduled after it
        let mut requests = 0;
        while let Some(next) = mappings.poll_timeout() {
            requests += drain(&mut mappings).len();
            if next > now + 2 * super::DEFAULT_REFRESH {
                break;
            }
            clock = next;
            mappings.handle_timeout(clock);
        }
        assert_eq!(requests, 4, "the refresh was asked, and went unanswered");
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::ServersFailed { last: at(SERVER) }],
            "the socket keeps its address, and the server that failed is said to have"
        );
        assert_eq!(mappings.public(at(SIP)), Some(at("203.0.113.7:41000")));
    }

    #[test]
    fn a_socket_of_the_other_family_is_not_asked() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at("[2001:db8::1]:40000"), Keep::Once, now);
        assert!(drain(&mut mappings).is_empty());
        assert_eq!(
            mappings.state(at("[2001:db8::1]:40000")),
            Some(MappingState::Unmapped)
        );
    }

    /// Run every deadline until nothing is due or `until` passes, counting requests sent.
    fn run_out(mappings: &mut Mappings, until: Instant) -> usize {
        let mut sent = drain(mappings).len();
        while let Some(due) = mappings.poll_timeout() {
            if due > until {
                break;
            }
            mappings.handle_timeout(due);
            sent += drain(mappings).len();
        }
        sent
    }

    #[test]
    fn a_socket_named_again_after_a_silence_is_a_new_question_with_its_own_answer() {
        // the application retries a media socket before the call and must get an event either way
        let start = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(MEDIA), Keep::Once, start);
        assert_eq!(run_out(&mut mappings, start + Duration::from_secs(60)), 4);
        assert_eq!(
            events(&mut mappings),
            vec![
                MappingEvent::ServersFailed { last: at(SERVER) },
                MappingEvent::Unanswered {
                    local: at(MEDIA),
                    failure: Failure::TimedOut,
                }
            ]
        );

        let again = start + Duration::from_secs(10);
        mappings.map(at(MEDIA), Keep::Once, again);
        assert_eq!(
            mappings.state(at(MEDIA)),
            Some(MappingState::Asking),
            "a call described now would name the private address while the answer is on its way"
        );
        assert_eq!(run_out(&mut mappings, again + Duration::from_secs(60)), 4);
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::Unanswered {
                local: at(MEDIA),
                failure: Failure::TimedOut,
            }],
            "the second question is answered too"
        );
        assert_eq!(mappings.state(at(MEDIA)), Some(MappingState::Unmapped));
    }

    #[test]
    fn a_media_socket_named_again_does_not_lend_the_old_answer_to_the_new_call() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(MEDIA), Keep::Once, now);
        let first = drain(&mut mappings);
        mappings.receive(
            at(MEDIA),
            at(SERVER),
            &answer(&first[0].payload, at("203.0.113.7:41002")),
            now,
        );
        let _learned = events(&mut mappings);

        // asked again: the socket is Asking until the server answers, and the answer is reported as
        // such
        let later = now + Duration::from_secs(120);
        mappings.map(at(MEDIA), Keep::Once, later);
        assert_eq!(mappings.state(at(MEDIA)), Some(MappingState::Asking));
        let second = drain(&mut mappings);
        mappings.receive(
            at(MEDIA),
            at(SERVER),
            &answer(&second[0].payload, at("203.0.113.7:52002")),
            later,
        );
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::Learned {
                local: at(MEDIA),
                public: at("203.0.113.7:52002"),
            }]
        );
    }

    #[test]
    fn a_media_answer_waiting_for_its_call_does_not_grow_old() {
        // mapped right after one call, used for a call ten minutes later: NATs drop idle mappings
        // long before (RFC 4787 REQ-5 allows two minutes, 30 s exists), so a waiting socket is
        // refreshed like signalling
        let start = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(MEDIA), Keep::Once, start);
        let first = drain(&mut mappings);
        mappings.receive(
            at(MEDIA),
            at(SERVER),
            &answer(&first[0].payload, at("203.0.113.7:41002")),
            start,
        );
        let _learned = events(&mut mappings);

        let due = mappings
            .poll_timeout()
            .expect("an answer nothing keeps true is left to age");
        assert!(due <= start + super::DEFAULT_REFRESH);
        mappings.handle_timeout(due);
        let again = drain(&mut mappings);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].local, at(MEDIA));
        assert_eq!(
            mappings.state(at(MEDIA)),
            Some(MappingState::Mapped(at("203.0.113.7:41002"))),
            "the answer in hand stands while the next one is on its way"
        );

        mappings.receive(
            at(MEDIA),
            at(SERVER),
            &answer(&again[0].payload, at("203.0.113.7:52002")),
            due,
        );
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::Moved {
                local: at(MEDIA),
                previous: at("203.0.113.7:41002"),
                public: at("203.0.113.7:52002"),
            }]
        );
        assert_eq!(mappings.public(at(MEDIA)), Some(at("203.0.113.7:52002")));
    }

    #[test]
    fn an_ipv6_socket_reads_the_address_the_way_rfc_8489_masks_it() {
        // the answer built by hand from RFC 8489 §14.2, not with our builder: port XORed with the
        // cookie's top 16 bits, address with cookie then transaction id
        const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
        let server = at("[2001:db8::1]:3478");
        let local = at("[2001:db8:ffff::10]:40000");
        let seen = at("[2001:db8:1234:5678:11:2233:4455:6677]:32853");
        let now = Instant::now();
        let mut mappings = Mappings::new(server, [7; 32]);
        mappings.map(local, Keep::Once, now);
        let sent = drain(&mut mappings);
        assert_eq!(sent.len(), 1);
        let request = &sent[0].payload;

        let mut mask = Vec::from(COOKIE);
        mask.extend_from_slice(request.get(8..20).expect("a whole header"));
        let std::net::IpAddr::V6(ip) = seen.ip() else {
            panic!("an IPv6 address");
        };
        let mut out = vec![0x01, 0x01, 0x00, 0x18];
        out.extend_from_slice(&COOKIE);
        out.extend_from_slice(request.get(8..20).expect("a whole header"));
        out.extend_from_slice(&[0x00, 0x20, 0x00, 0x14, 0x00, 0x02]);
        out.extend_from_slice(&(seen.port() ^ 0x2112).to_be_bytes());
        out.extend(ip.octets().iter().zip(mask.iter()).map(|(a, m)| a ^ m));

        assert!(mappings.receive(local, server, &out, now));
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::Learned {
                local,
                public: seen,
            }]
        );
    }

    #[test]
    fn a_forgotten_socket_sends_nothing_more() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(MEDIA), Keep::Once, now);
        mappings.forget(at(MEDIA));
        assert!(drain(&mut mappings).is_empty());
        assert!(mappings.poll_timeout().is_none());
        assert_eq!(mappings.state(at(MEDIA)), None);
    }

    const SECOND: &str = "198.51.100.2:3478";
    const THIRD: &str = "198.51.100.3:3478";

    /// Two servers; the first never answers.
    fn two() -> Mappings {
        Mappings::new(at(SERVER), [7; 32]).fallbacks([at(SECOND)])
    }

    /// Run deadlines up to `until`, answering requests to `alive` and dropping the rest; returns
    /// every request destination in order.
    fn run_with(
        mappings: &mut Mappings,
        alive: &[&str],
        seen: &str,
        until: Instant,
    ) -> Vec<String> {
        let mut asked = Vec::new();
        let mut now = None;
        loop {
            let sent = drain(mappings);
            for datagram in &sent {
                asked.push(datagram.destination.to_string());
                if alive.contains(&datagram.destination.to_string().as_str()) {
                    let at_time = now.unwrap_or(until);
                    mappings.receive(
                        datagram.local,
                        datagram.destination,
                        &answer(&datagram.payload, at(seen)),
                        at_time,
                    );
                }
            }
            match mappings.poll_timeout() {
                Some(due) if due <= until => {
                    now = Some(due);
                    mappings.handle_timeout(due);
                }
                _ if sent.is_empty() => return asked,
                _ => {}
            }
        }
    }

    /// A server's error response to the request's id.
    fn refusal(request: &[u8], code: u16) -> Vec<u8> {
        let id = Message::parse(request)
            .expect("a STUN request")
            .transaction_id();
        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, id);
        builder
            .add_error_code(code, b"Refused")
            .expect("an error code");
        builder.add_fingerprint().expect("a fingerprint");
        builder.finish()
    }

    #[test]
    fn a_silent_first_server_hands_every_socket_asking_it_to_the_next() {
        let start = Instant::now();
        let mut mappings = two();
        mappings.map(at(SIP), Keep::Refreshed, start);
        mappings.map(at(MEDIA), Keep::Once, start);
        let first = drain(&mut mappings);
        assert!(
            first
                .iter()
                .all(|datagram| datagram.destination == at(SERVER)),
            "the first in the list is asked first: {first:?}"
        );

        // both transactions fail together; the first detected moves the other too, so it does not
        // wait 5.5 s on a known-dead server
        let mut now = start;
        while mappings.state(at(SIP)) == Some(MappingState::Asking)
            && drain(&mut mappings)
                .iter()
                .all(|d| d.destination == at(SERVER))
        {
            now = mappings.poll_timeout().expect("a deadline");
            mappings.handle_timeout(now);
            if events(&mut mappings)
                .iter()
                .any(|event| matches!(event, MappingEvent::ServerChanged { .. }))
            {
                break;
            }
        }
        assert_eq!(now - start, Duration::from_millis(5_500));
        assert_eq!(mappings.server(), at(SECOND));
        let moved = drain(&mut mappings);
        let mut locals: Vec<SocketAddr> = moved.iter().map(|datagram| datagram.local).collect();
        locals.sort();
        assert_eq!(locals, vec![at(SIP), at(MEDIA)], "{moved:?}");
        assert!(
            moved
                .iter()
                .all(|datagram| datagram.destination == at(SECOND))
        );

        for datagram in &moved {
            assert!(mappings.receive(
                datagram.local,
                at(SECOND),
                &answer(&datagram.payload, at("203.0.113.7:41000")),
                now,
            ));
        }
        let said = events(&mut mappings);
        assert!(
            said.iter()
                .all(|event| matches!(event, MappingEvent::Learned { .. })),
            "the failure was nobody's to report once somebody answered: {said:?}"
        );
        assert_eq!(said.len(), 2);
    }

    #[test]
    fn the_server_that_failed_changes_the_one_in_use_and_says_so() {
        let start = Instant::now();
        let mut mappings = two();
        mappings.map(at(SIP), Keep::Refreshed, start);
        let asked = run_with(
            &mut mappings,
            &[SECOND],
            "203.0.113.7:41000",
            start + Duration::from_secs(10),
        );
        assert_eq!(asked.iter().filter(|to| *to == SERVER).count(), 4);
        assert_eq!(asked.last().map(String::as_str), Some(SECOND));
        assert_eq!(
            events(&mut mappings),
            vec![
                MappingEvent::ServerChanged {
                    previous: at(SERVER),
                    server: at(SECOND),
                },
                MappingEvent::Learned {
                    local: at(SIP),
                    public: at("203.0.113.7:41000"),
                },
            ]
        );
    }

    #[test]
    fn a_failed_server_backs_off_longer_each_time_and_a_refresh_finds_it_again() {
        let start = Instant::now();
        let mut mappings = two();
        mappings.map(at(SIP), Keep::Refreshed, start);
        let failed_at = start + Duration::from_millis(5_500);

        // skipped for 30 s: the 30.5 s refresh goes to the second server, the 55.5 s one retries
        // the first, which fails again and is skipped for 60 s from 61 s
        let asked = run_with(
            &mut mappings,
            &[SECOND],
            "203.0.113.7:41000",
            failed_at + Duration::from_secs(120),
        );
        let runs: Vec<(String, usize)> = asked.iter().fold(Vec::new(), |mut runs, to| {
            match runs.last_mut() {
                Some((last, count)) if last == to => *count += 1,
                _ => runs.push((to.clone(), 1)),
            }
            runs
        });
        let expected: Vec<(String, usize)> = vec![
            (SERVER.into(), 4),
            // first answer, then the 30.5 s refresh
            (SECOND.into(), 2),
            // 55.5 s: back-off over
            (SERVER.into(), 4),
            // 61 s, then refreshes at 86 s and 111 s; the first server is skipped until 121 s
            (SECOND.into(), 3),
        ];
        assert_eq!(runs, expected, "{asked:?}");
        let said = events(&mut mappings);
        assert_eq!(
            said.iter()
                .filter(|event| matches!(event, MappingEvent::ServerChanged { .. }))
                .count(),
            1,
            "a probe that failed changed nothing in use: {said:?}"
        );
        assert!(
            !said
                .iter()
                .any(|event| matches!(event, MappingEvent::ServersFailed { .. })),
            "{said:?}"
        );
    }

    #[test]
    fn a_media_socket_is_never_spent_on_finding_out_whether_a_server_came_back() {
        let start = Instant::now();
        let mut mappings = two();
        mappings.map(at(SIP), Keep::Refreshed, start);
        let _ = run_with(
            &mut mappings,
            &[SECOND],
            "203.0.113.7:41000",
            start + Duration::from_secs(10),
        );
        let _ = events(&mut mappings);

        // the first server's 30 s are over and a call is waiting
        let later = start + Duration::from_secs(40);
        mappings.map(at(MEDIA), Keep::Once, later);
        let sent = drain(&mut mappings);
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].destination,
            at(SECOND),
            "the server in use is asked, not the one that may have come back"
        );
    }

    #[test]
    fn a_better_server_that_answers_again_is_in_use_again() {
        let start = Instant::now();
        let mut mappings = two();
        mappings.map(at(SIP), Keep::Refreshed, start);
        let _ = run_with(
            &mut mappings,
            &[SECOND],
            "203.0.113.7:41000",
            start + Duration::from_secs(10),
        );
        let _ = events(&mut mappings);

        // the refresh after the back-off retries the first server, which answers
        let asked = run_with(
            &mut mappings,
            &[SERVER, SECOND],
            "203.0.113.7:41000",
            start + Duration::from_secs(60),
        );
        assert_eq!(asked.last().map(String::as_str), Some(SERVER), "{asked:?}");
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::ServerChanged {
                previous: at(SECOND),
                server: at(SERVER),
            }]
        );
        assert_eq!(mappings.server(), at(SERVER));
    }

    #[test]
    fn when_every_server_has_failed_it_is_said_once() {
        let start = Instant::now();
        let mut mappings = two();
        mappings.map(at(SIP), Keep::Refreshed, start);
        let asked = run_with(
            &mut mappings,
            &[],
            "203.0.113.7:41000",
            start + Duration::from_secs(12),
        );
        assert_eq!(asked.len(), 8, "four to each: {asked:?}");
        assert_eq!(
            events(&mut mappings),
            vec![
                MappingEvent::ServerChanged {
                    previous: at(SERVER),
                    server: at(SECOND),
                },
                MappingEvent::ServersFailed { last: at(SECOND) },
                MappingEvent::Unanswered {
                    local: at(SIP),
                    failure: Failure::TimedOut,
                },
            ]
        );
        assert_eq!(mappings.state(at(SIP)), Some(MappingState::Unmapped));

        // refreshes continue to the server whose back-off ends first, and are not reported again
        let asked = run_with(
            &mut mappings,
            &[],
            "203.0.113.7:41000",
            start + Duration::from_secs(40),
        );
        assert!(!asked.is_empty());
        assert!(events(&mut mappings).is_empty());

        // until one answers
        let asked = run_with(
            &mut mappings,
            &[SERVER, SECOND],
            "203.0.113.7:41000",
            start + Duration::from_secs(70),
        );
        assert!(!asked.is_empty());
        let said = events(&mut mappings);
        assert!(
            said.contains(&MappingEvent::Learned {
                local: at(SIP),
                public: at("203.0.113.7:41000"),
            }),
            "{said:?}"
        );
    }

    #[test]
    fn a_refusal_hands_the_socket_on_as_a_silence_does() {
        let now = Instant::now();
        let mut mappings = two();
        mappings.map(at(MEDIA), Keep::Once, now);
        let first = drain(&mut mappings);
        assert!(mappings.receive(at(MEDIA), at(SERVER), &refusal(&first[0].payload, 500), now));
        let next = drain(&mut mappings);
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].destination, at(SECOND));
        assert_eq!(
            events(&mut mappings),
            vec![MappingEvent::ServerChanged {
                previous: at(SERVER),
                server: at(SECOND),
            }]
        );
        assert_eq!(mappings.state(at(MEDIA)), Some(MappingState::Asking));
    }

    #[test]
    fn a_late_answer_from_the_server_left_behind_is_taken_and_not_believed() {
        let now = Instant::now();
        let mut mappings = two();
        mappings.map(at(MEDIA), Keep::Once, now);
        let first = drain(&mut mappings);
        let failed = now + Duration::from_millis(5_500);
        let _ = run_with(&mut mappings, &[], "0.0.0.0:1", failed);
        assert_eq!(mappings.server(), at(SECOND));
        let _ = events(&mut mappings);

        let late = answer(&first[0].payload, at("198.51.100.66:9"));
        assert!(
            mappings.receive(at(MEDIA), at(SERVER), &late, failed),
            "the first server's own answer is not SIP or RTP to hand anywhere else"
        );
        assert_eq!(mappings.state(at(MEDIA)), Some(MappingState::Asking));
        assert!(events(&mut mappings).is_empty());
    }

    #[test]
    fn a_new_list_on_a_running_stack_is_asked_at_once() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]);
        mappings.map(at(SIP), Keep::Refreshed, now);
        let first = drain(&mut mappings);
        mappings.receive(
            at(SIP),
            at(SERVER),
            &answer(&first[0].payload, at("203.0.113.7:41000")),
            now,
        );
        let _learned = events(&mut mappings);

        let later = now + Duration::from_secs(5);
        mappings.set_servers(at(THIRD), [at(SECOND)], later);
        assert_eq!(
            mappings.servers().collect::<Vec<_>>(),
            vec![at(THIRD), at(SECOND)]
        );
        let asked = drain(&mut mappings);
        assert_eq!(asked.len(), 1, "not at the next refresh: now");
        assert_eq!(asked[0].destination, at(THIRD));
        assert_eq!(
            mappings.public(at(SIP)),
            Some(at("203.0.113.7:41000")),
            "what was learned stands until the new server says"
        );
        assert!(
            !mappings.receive(
                at(SIP),
                at(SERVER),
                &answer(&first[0].payload, at("198.51.100.66:9")),
                later
            ),
            "a server no longer listed is nobody's to believe"
        );
        mappings.receive(
            at(SIP),
            at(THIRD),
            &answer(&asked[0].payload, at("203.0.113.7:52000")),
            later,
        );
        assert_eq!(
            events(&mut mappings),
            vec![
                MappingEvent::ServerChanged {
                    previous: at(SERVER),
                    server: at(THIRD),
                },
                MappingEvent::Moved {
                    local: at(SIP),
                    previous: at("203.0.113.7:41000"),
                    public: at("203.0.113.7:52000"),
                },
            ]
        );
    }

    #[test]
    fn a_server_of_the_other_family_further_down_the_list_is_the_one_its_sockets_ask() {
        let now = Instant::now();
        let mut mappings = Mappings::new(at(SERVER), [7; 32]).fallbacks([at("[2001:db8::1]:3478")]);
        mappings.map(at("[2001:db8::10]:40000"), Keep::Once, now);
        let sent = drain(&mut mappings);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].destination, at("[2001:db8::1]:3478"));
        assert_eq!(mappings.server(), at(SERVER), "the IPv4 one is untouched");
    }
}
