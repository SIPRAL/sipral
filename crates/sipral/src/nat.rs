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
//! - **A media socket** is asked once, before the description that names it
//!   is written ([`Keep::Once`]), and the answer goes to
//!   [`CallMedia::public_address`](crate::CallMedia::public_address). From
//!   then on RTP every frame and RTCP every few seconds hold the binding for
//!   the length of the call, and a STUN request beside them would only
//!   compete with them for the same mapping.
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

/// How long a socket's mapping is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// Asked again every [`Mappings::refresh`] for as long as the socket is
    /// mapped: the signalling socket, which is idle for minutes at a time
    /// and whose mapping has to outlive the silence.
    Refreshed,
    /// Asked once. A media socket, whose own traffic holds its binding once a
    /// call is running on it.
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
    /// nothing.
    Moved {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// What it was.
        previous: SocketAddr,
        /// What it is now.
        public: SocketAddr,
    },
    /// The first transaction on a socket ended without an address. The
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
}

/// The STUN mappings of the sockets an application named, against one
/// server.
///
/// Sans-I/O, like everything else in this crate: `now` arrives at every entry
/// point, the application's sockets send and receive, and nothing here reads
/// a clock or draws from the operating system.
pub struct Mappings {
    server: SocketAddr,
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
            server,
            refresh: DEFAULT_REFRESH,
            keys: KeySource::new(seed),
            sockets: BTreeMap::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Ask again every `every` instead of [`DEFAULT_REFRESH`], on sockets
    /// kept [`Keep::Refreshed`]. A zero is taken as one second, so that a
    /// setting cannot make the refresh spin.
    #[must_use]
    pub fn refresh(mut self, every: Duration) -> Self {
        self.refresh = every.max(Duration::from_secs(1));
        self
    }

    /// The server every mapping is asked of.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// Start asking where `local` appears from.
    ///
    /// A socket already mapped is asked again at once, and keeps the address
    /// it had until the answer says otherwise; `keep` replaces what it was
    /// kept as. A server of the other address family is never asked: a
    /// socket of that family is [`MappingState::Unmapped`] at once, and
    /// [`MappingEvent::Unanswered`] says so with
    /// [`Failure::TimedOut`], since that is what asking would have come to.
    pub fn map(&mut self, local: SocketAddr, keep: Keep, now: Instant) {
        let socket = self.sockets.entry(local).or_insert_with(|| Socket {
            keep,
            client: BindingClient::new(config()),
            public: None,
            asking: false,
            settled: false,
            refresh_at: None,
        });
        socket.keep = keep;
        if local.is_ipv4() != self.server.is_ipv4() {
            socket.settled = true;
            socket.asking = false;
            socket.refresh_at = None;
            self.events.push_back(MappingEvent::Unanswered {
                local,
                failure: Failure::TimedOut,
            });
            return;
        }
        self.ask(local, now);
    }

    /// Ask again now, whatever the schedule said: after a network change,
    /// when the old answer is the one thing most likely to be wrong.
    /// Nothing for a socket that is not mapped.
    pub fn ask_again(&mut self, local: SocketAddr, now: Instant) {
        if self.sockets.contains_key(&local) && local.is_ipv4() == self.server.is_ipv4() {
            self.ask(local, now);
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
    /// whether it was a STUN message from the server this asks — which the
    /// caller then passes to nothing else.
    ///
    /// A STUN message from the server is taken whether or not it answers
    /// anything still in flight: a retransmitted answer that arrives after
    /// the first one is still the server's, and handing it to the SIP parser
    /// or the RTP session instead would be a malformed message logged for
    /// nothing. A datagram from anywhere else is left alone, even if it looks
    /// like STUN: only the server's answer is believed.
    pub fn receive(
        &mut self,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        if from != self.server || sipral_nat::classify(data) != sipral_nat::Demux::Stun {
            return false;
        }
        let Some(socket) = self.sockets.get_mut(&local) else {
            return false;
        };
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
                self.ask(local, now);
            }
        }
    }

    /// A fresh transaction on `local`.
    fn ask(&mut self, local: SocketAddr, now: Instant) {
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
        let progress = socket.client.start(TransactionId::new(id), now);
        self.on_progress(local, progress, now);
    }

    fn on_progress(&mut self, local: SocketAddr, progress: Progress, now: Instant) {
        let refresh = self.refresh;
        let server = self.server;
        let Some(socket) = self.sockets.get_mut(&local) else {
            return;
        };
        // only the transaction that was to give a socket its first address
        // is reported when it fails; see `MappingEvent::Unanswered`
        let first = socket.public.is_none() && !socket.settled;
        let ended = match progress {
            Progress::Idle => return,
            Progress::Transmit => {
                self.outbox.push_back(StunDatagram {
                    local,
                    destination: server,
                    payload: socket.client.datagram().to_vec(),
                });
                return;
            }
            Progress::Mapped(public) => {
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
            // no credentials are ever configured here, so a challenge is a
            // server that wants what this client cannot give: the same end as
            // a refusal
            Progress::Challenged => first.then_some(MappingEvent::Unanswered {
                local,
                failure: Failure::Unauthenticated,
            }),
            Progress::Failed(failure) => {
                first.then_some(MappingEvent::Unanswered { local, failure })
            }
        };
        socket.asking = false;
        socket.settled = true;
        socket.refresh_at = match socket.keep {
            Keep::Refreshed => now.checked_add(refresh),
            Keep::Once => None,
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
            .field("server", &self.server)
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
            vec![MappingEvent::Unanswered {
                local: at(MEDIA),
                failure: Failure::TimedOut,
            }]
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
        assert!(events(&mut mappings).is_empty());
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
}
