// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Where this end appears from, asked of a STUN server (RFC 8489), and the
//! two places the answer goes.
//!
//! A softphone behind a NAT writes its own address into two things the far
//! end reads and acts on: the `Contact` of every REGISTER and INVITE, which is
//! where requests for it are sent, and the `c=` and `m=` lines of every
//! description, which is where its audio is sent. Both name a private address
//! nobody outside can reach unless something corrects them. `rport` corrects
//! the path a response takes (RFC 3581) and symmetric RTP at the far end
//! corrects the media (RFC 7362), and `docs/06-nat.md` explains why those
//! carry most paths without any of this. What they cannot carry is a far end
//! that believes what it was told: a registrar with no NAT helper, a peer
//! that sends where `c=` says and nowhere else. For those, this end has to
//! say the right address in the first place, and a STUN Binding request from
//! the socket in question is how it learns it.
//!
//! # Two sockets, two answers
//!
//! The signalling socket and each media socket are different NAT bindings,
//! and a NAT that maps them to different public ports — most do — answers
//! differently for each. So [`Mappings`] keeps one Binding transaction per
//! socket the application names, and says for each one where it appears
//! from.
//!
//! - **The signalling socket** is kept mapped for as long as it is open
//!   ([`Keep::Refreshed`]): a request every [`Mappings::refresh`] interval,
//!   twenty-five seconds unless set otherwise — the figure the endpoint's own
//!   stream keepalive uses, for the same NATs. Signalling is idle for minutes
//!   at a time, a mapping nothing refreshes is released, and an answer that
//!   comes back different is a mapping that moved, which is
//!   [`MappingEvent::Moved`]. Both answers go to
//!   [`UserAgent::readdress`](crate::UserAgent::readdress), which moves every
//!   account's `Contact` onto the public address and registers it again.
//! - **A media socket** is asked before the description that names it is
//!   written ([`Keep::Once`]), and the answer goes to
//!   [`CallMedia::public_address`](crate::CallMedia::public_address). Until
//!   then it is asked again every refresh interval, as the signalling socket
//!   is: nothing else crosses its binding while it waits, and an answer
//!   minutes old names a mapping the NAT may have let go. From the call on,
//!   RTP every frame and RTCP every few seconds hold the binding, a STUN
//!   request beside them would only compete with them for the same mapping,
//!   and the application forgets the socket.
//!
//! # More than one server
//!
//! A public STUN server is somebody else's machine, and it goes away without
//! notice. [`Mappings::fallbacks`] names the servers to turn to, in order, and
//! a transaction that ends without an address — no answer in five and a half
//! seconds, or a refusal, since a server that answers without an address is
//! no more use than a silent one — moves every socket asking that server onto
//! the next one in the list at once. The server that failed backs off: it is
//! passed over for thirty seconds, then for twice as long each time it fails
//! again, up to ten minutes, and an answer from it clears that. While it
//! backs off, only a signalling socket's refresh ever goes back to it, once
//! its time is up, so a better server that recovers is used again without a
//! media socket's first answer — which a call is waiting for — ever being
//! spent on finding out. [`MappingEvent::ServerChanged`] says when the server
//! in use moves, and [`MappingEvent::ServersFailed`] when every server of the
//! socket's family has failed and none is left to turn to: the sockets are
//! then described as the last answer had them, or by their own address.
//! [`Mappings::set_servers`] replaces the list on a running stack.
//!
//! # What this does not do
//!
//! **No socket.** The application's socket sends what
//! [`Mappings::poll_transmit`] hands back and hands in what arrives, exactly
//! as it does for signalling and media. **No `Via`.** The `sent-by` of a
//! request stays the local address: `rport` already takes the response back
//! along the path the request came in on, and a `Via` naming a public address
//! the local host does not own would be a lie a strict server can catch.
//! **No NAT classification**, for the reason RFC 5389 removed it.
//!
//! The transaction ids come from a seed the application supplies, or from
//! the media engine's own generator through [`MediaEngine::mappings`]. They
//! are the whole of what stops an attacker off the path from answering
//! first: a response carrying a guessed id and an address of the attacker's
//! choosing would have this end advertise that address as its own, in every
//! `Contact` and every offer.
//!
//! [`MediaEngine::mappings`]: crate::MediaEngine::mappings

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::auth::KeySource;
use sipral_nat::stun::{BindingClient, BindingConfig, Failure, Progress, TransactionId};

/// How often the signalling socket's mapping is asked again, unless
/// [`Mappings::refresh`] says otherwise.
///
/// Twenty-five seconds, the interval the endpoint's own keepalive on a stream
/// uses (`EndpointConfig::keepalive_interval`): short enough for the NATs that
/// release an idle UDP mapping after thirty seconds, which RFC 4787 §4.3
/// forbids and which are deployed all the same.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(25);

/// How many requests one transaction sends before it gives up.
///
/// Four, at 0, 0.5, 1.5 and 3.5 seconds, and then two more seconds for the
/// last one to be answered: five and a half seconds in all. RFC 8489 §6.2.1
/// lets Rc be configured, and its default of seven waits 39.5 seconds —
/// which, for the first answer, is a REGISTER or an offer held that long for
/// a server that is not there. The same order as ICE's own gathering timeout.
const REQUESTS: u32 = 4;

/// Multiples of the RTO waited after the last request (RFC 8489 §6.2.1's Rm).
const LAST_WAIT: u32 = 4;

/// How long a server that failed is passed over the first time: past the
/// twenty-five-second refresh, so that the refresh straight after a failure
/// goes to the server that took over rather than back to the one that just
/// failed.
const FIRST_BACK_OFF: Duration = Duration::from_secs(30);

/// The longest a failed server is ever passed over. A server that has been
/// down for an hour costs one unanswered refresh every ten minutes, and one
/// that comes back is in use again within ten minutes of it.
const LONGEST_BACK_OFF: Duration = Duration::from_secs(600);

/// How long a socket's mapping is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// Asked again every [`Mappings::refresh`] for as long as the socket is
    /// mapped: the signalling socket, which is idle for minutes at a time
    /// and whose mapping has to outlive the silence.
    Refreshed,
    /// A media socket, whose own traffic holds its binding once a call is
    /// running on it. Named again, it drops the answer it had; answered, it
    /// is asked again every [`Mappings::refresh`] until it is forgotten, so
    /// that the answer a call is described with is never older than that.
    Once,
}

/// Where one socket's mapping stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingState {
    /// Asked, and not answered yet. A description that names this socket
    /// would name the wrong address, so the answer is worth waiting for: it
    /// arrives within five and a half seconds either way.
    Asking,
    /// This socket appears at this address.
    Mapped(SocketAddr),
    /// The server did not answer. The socket is described by its own
    /// address, which is what it would have been with no STUN at all — the
    /// fallback is the configuration that worked before STUN was turned on.
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
    /// A refresh came back with a different address: the NAT released the
    /// mapping and made another, or the network under the socket changed.
    /// Everything that advertised `previous` now names somewhere that reaches
    /// nothing. For a media socket still waiting for its call, the call it is
    /// described in names `public`.
    Moved {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// What it was.
        previous: SocketAddr,
        /// What it is now.
        public: SocketAddr,
    },
    /// The transaction [`Mappings::map`] started ended without an address,
    /// on a socket with none to fall back on. The
    /// socket is [`MappingState::Unmapped`] and described by its own address;
    /// a socket kept [`Keep::Refreshed`] asks again at the next refresh, and a
    /// later answer arrives as [`MappingEvent::Learned`].
    ///
    /// A refresh that goes unanswered is not reported: the last address the
    /// server gave is still the best knowledge there is, and the next refresh
    /// asks again.
    Unanswered {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// Why.
        failure: Failure,
    },
    /// The server in use for sockets of `server`'s address family is another
    /// one now: `previous` failed and the next in the list took over, a
    /// refresh found a server earlier in the list answering again, or
    /// [`Mappings::set_servers`] named another list. What was learned stands
    /// until the new server's answers say otherwise, which may be
    /// [`MappingEvent::Moved`] behind a NAT that maps per destination.
    ServerChanged {
        /// The server that was in use.
        previous: SocketAddr,
        /// The server in use now.
        server: SocketAddr,
    },
    /// Every server of `last`'s address family has failed and each one is
    /// backing off: there is nobody left to ask. Sockets keep the address
    /// they last learned, or are described by their own, and refreshes go on
    /// asking the server whose back-off ends first. Said once until a server
    /// answers again.
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

/// Which address family `address` is, as [`PerFamily`] reads it: `true` for
/// IPv4.
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

/// The STUN mappings of the sockets an application named, against one
/// server and the ones behind it.
///
/// Sans-I/O, like everything else in this crate: `now` arrives at every entry
/// point, the application's sockets send and receive, and nothing here reads
/// a clock or draws from the operating system.
pub struct Mappings {
    /// In order of preference; never empty.
    servers: Vec<Server>,
    /// The first of them, which is where a stack whose list has no IPv4
    /// server at all says it asks.
    first: SocketAddr,
    /// The server in use, per address family, once one has been asked.
    in_use: PerFamily<Option<SocketAddr>>,
    /// Whether [`MappingEvent::ServersFailed`] was said, per address family,
    /// and no server has answered since.
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
    /// `seed` must be thirty-two bytes from the platform's cryptographic
    /// generator, and not bytes any other part of the stack is given: see
    /// the module documentation for what a guessable id is worth to an
    /// attacker. [`MediaEngine::mappings`](crate::MediaEngine::mappings)
    /// draws them from the engine's own generator instead.
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

    /// Ask again every `every` instead of [`DEFAULT_REFRESH`], on sockets
    /// kept [`Keep::Refreshed`] and on answered ones kept [`Keep::Once`]. A
    /// zero is taken as one second, so that a setting cannot make the refresh
    /// spin.
    #[must_use]
    pub fn refresh(mut self, every: Duration) -> Self {
        self.refresh = every.max(Duration::from_secs(1));
        self
    }

    /// Turn to `more`, in this order, when the server before them fails. A
    /// server already in the list is not added twice. See the module
    /// documentation for when a server is turned to and when it is turned
    /// back from.
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

    /// The server a new IPv4 socket would be asked about now: the one in
    /// use, or the first in the list before any has been asked.
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

    /// Ask `first`, and `rest` behind it in this order, from now on: the
    /// list replaced on a running stack, with no socket forgotten.
    ///
    /// Every socket is asked again at once of the first server of its
    /// family — a transaction in flight to a server no longer listed is
    /// abandoned — and what each one learned stands until the new server
    /// answers. A server kept from the old list keeps its back-off, so that
    /// naming the list again does not make a dead server look alive.
    /// [`MappingEvent::ServerChanged`] says so where the server in use moves.
    /// A socket of a family the new list has no server of stops being
    /// asked, and keeps what it learned.
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
                    self.events.push_back(MappingEvent::Unanswered {
                        local: *local,
                        failure: Failure::TimedOut,
                    });
                }
            }
        }
        for slot in [true, false] {
            // with no socket of the family asked again, nothing will move
            // the server in use off one that is not listed any more
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
    /// A socket named again is asked again at once, and the answer is
    /// reported whichever way it goes; `keep` replaces what it was kept as.
    /// Kept [`Keep::Refreshed`], it keeps the address it had until the answer
    /// says otherwise, and an answer that differs is
    /// [`MappingEvent::Moved`]. Kept [`Keep::Once`], its old answer is
    /// dropped: it is [`MappingState::Asking`] until the server says, and
    /// what the server says is [`MappingEvent::Learned`] or
    /// [`MappingEvent::Unanswered`], as the first time.
    ///
    /// A server of the other address family is never asked: a socket of a
    /// family no server in the list is of is [`MappingState::Unmapped`] at
    /// once, and [`MappingEvent::Unanswered`] says so with
    /// [`Failure::TimedOut`], since that is what asking would have come to.
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
        // named again, a socket is asked a new question, and its answer is
        // reported whichever way it goes. A media socket's old answer is
        // dropped with it: the application named it again because nothing
        // kept that answer true, so a description written before the new one
        // arrives is refused rather than lent the old one. A signalling
        // socket keeps what it had, because every `Contact` already names it
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
            self.events.push_back(MappingEvent::Unanswered {
                local,
                failure: Failure::TimedOut,
            });
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

    /// Ask again now, whatever the schedule said: after a network change,
    /// when the old answer is the one thing most likely to be wrong. The
    /// first server of the list that is not backing off is asked, as a
    /// refresh would. Nothing for a socket that is not mapped.
    pub fn ask_again(&mut self, local: SocketAddr, now: Instant) {
        if self.sockets.contains_key(&local) && self.serves(local) {
            self.ask(local, now, true);
        }
    }

    /// Stop keeping `local`: nothing more is sent for it, and what it
    /// learned is forgotten.
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

    /// Hand in a datagram that arrived on `local` from `from`, and say
    /// whether it was a STUN message from a server this asks — which the
    /// caller then passes to nothing else.
    ///
    /// A STUN message from a listed server is taken whether or not it
    /// answers anything still in flight: a retransmitted answer that arrives
    /// after the first one is still the server's, and so is a late answer
    /// from a server the socket has since been moved off, and handing either
    /// to the SIP parser or the RTP session instead would be a malformed
    /// message logged for nothing. Only the server the socket's transaction
    /// asked is believed, and a datagram from anywhere else is left alone,
    /// even if it looks like STUN.
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

    /// The next request to send, from the socket it names.
    ///
    /// Drain to empty after every [`Mappings::map`], every datagram handed
    /// in and every deadline [`Mappings::poll_timeout`] named.
    pub fn poll_transmit(&mut self) -> Option<StunDatagram> {
        self.outbox.pop_front()
    }

    /// The next thing learned.
    pub fn poll_event(&mut self) -> Option<MappingEvent> {
        self.events.pop_front()
    }

    /// When something is next due: a retransmission, a transaction giving
    /// up, or a refresh.
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

    /// The server a new transaction for a socket of `slot`'s family goes
    /// to. A `probe` — a signalling socket's refresh, or a question asked
    /// after a network change — takes the first in the list that is not
    /// backing off, which is how a better server that came back is found
    /// again; anything else stays with the server in use while it holds.
    /// With every one backing off, the one whose back-off ends first.
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

    /// A fresh transaction on `local`, to the server [`Mappings::choose`]
    /// picks.
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
                self.events
                    .push_back(MappingEvent::ServerChanged { previous, server });
            }
            _ => {}
        }
        *self.in_use.of_mut(slot) = Some(server);
    }

    /// `asked` failed a transaction of `local`'s: it backs off, and when
    /// another server of the family is not backing off, every socket asking
    /// `asked` is asked again there, `local` among them. `true` when that
    /// happened, and the failure is then nobody's to report.
    fn fail_over(&mut self, local: SocketAddr, asked: SocketAddr, now: Instant) -> bool {
        let slot = family(local);
        if let Some(server) = self
            .servers
            .iter_mut()
            .find(|server| server.address == asked)
            && !server.backing_off(now)
        {
            // a server already backing off failed a transaction started
            // before it was found out, or one asked with nothing better to
            // ask: that is the same failure, not a second one
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
                self.events
                    .push_back(MappingEvent::ServersFailed { last: asked });
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
            // no credentials are ever configured here, so a challenge is a
            // server that wants what this client cannot give: the same end as
            // a refusal
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
        // only the transaction that was to give a socket its first address
        // is reported when it fails; see `MappingEvent::Unanswered`
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
        // a media socket's answer is asked again on the same schedule for as
        // long as it waits for its call: nothing else crosses that NAT
        // binding until the call's RTP does, and an answer that is minutes
        // old names a mapping the NAT may have let go. A socket that never
        // had an answer is described by its own address and left alone
        socket.refresh_at = match socket.keep {
            Keep::Refreshed => now.checked_add(refresh),
            Keep::Once => socket.public.and_then(|_| now.checked_add(refresh)),
        };
        if let Some(event) = ended {
            self.events.push_back(event);
        }
    }
}

/// Written by hand, so that what is printed is what was learned rather than
/// the state of every transaction, and so that the seed stays out of a log.
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

    use super::{Keep, MappingEvent, MappingState, Mappings, StunDatagram};

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

    /// What a STUN server writes back: the request's own id, and the
    /// address it saw the request come from.
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
        // the server's own address, and a well-formed answer, but an id this
        // end never sent: what an attacker who can spoof the server's address
        // and cannot see the request has to guess, and cannot
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
        // the whole refresh transaction goes unanswered, and the next
        // refresh is scheduled behind it
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

    /// Run every deadline until nothing more is due or `until` is passed, and
    /// count the requests that went out.
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
        // what an application does when the server did not answer for a media
        // socket and it tries once more before the call: it waits for the
        // event again, and it must get one either way
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

        // asked again: until the server says, the socket is being asked
        // about, and the answer that comes back is reported as what it is
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
        // an application that maps the socket for its next call as soon as
        // the last one ends, and places that call ten minutes later: a NAT
        // lets an idle mapping go long before that (RFC 4787 REQ-5 allows
        // two minutes, and thirty seconds is deployed), and the answer it
        // gave then names a port that reaches nothing now. Until a call is
        // described on it, the socket is asked again as the signalling one is
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
        // the answer written out by hand from RFC 8489 §14.2 rather than
        // with this tree's own builder: the port masked with the cookie's
        // top sixteen bits, the address with the cookie and then the
        // transaction id
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

    // -- more than one server ------------------------------------------------

    const SECOND: &str = "198.51.100.2:3478";
    const THIRD: &str = "198.51.100.3:3478";

    /// Two servers, the first one silent.
    fn two() -> Mappings {
        Mappings::new(at(SERVER), [7; 32]).fallbacks([at(SECOND)])
    }

    /// Run the deadlines up to `until`, answering every request sent to one
    /// of `alive` as the server would and leaving the rest unanswered; the
    /// destinations of every request, in order.
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

    /// What a server writes back when it will not say: an error response
    /// to the request's own id.
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

        // both transactions give up together; the first to be found out
        // takes the other with it, so the second is not left to spend its
        // own five and a half seconds on a server already known to be gone
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

        // passed over for thirty seconds: the refresh at 30.5 s goes to the
        // second server, the one at 55.5 s is past the back-off and tries
        // the first again, which is still silent, so it is passed over for
        // sixty seconds from 61 s, and the refreshes until then stay away
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
            // first answer, then the refresh at 30.5 s
            (SECOND.into(), 2),
            // 55.5 s: the back-off has run out
            (SERVER.into(), 4),
            // 61 s, straight after, and the refreshes at 86 s and 111 s;
            // the first server is passed over until 121 s
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

        // the first server's thirty seconds are over, and a call is waiting
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

        // the refresh past the back-off asks the first again, and it answers
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

        // the refreshes go on, to the server whose back-off ends first, and
        // a second round of silence is not a second announcement
        let asked = run_with(
            &mut mappings,
            &[],
            "203.0.113.7:41000",
            start + Duration::from_secs(40),
        );
        assert!(!asked.is_empty());
        assert!(events(&mut mappings).is_empty());

        // until one answers, which clears it
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
