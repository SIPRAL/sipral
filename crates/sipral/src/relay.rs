// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A relay on a TURN server (RFC 8656), allocated from a media socket before
//! the call that will use it, and handed to that call as its relayed ICE
//! candidate.
//!
//! The last resort `docs/06-nat.md` describes: two ends whose NATs let
//! nothing through that the end behind them did not start — or a network
//! that lets nothing through at all but the way to one server — reach each
//! other only through a server both can reach. The full ICE agent the call
//! runs checks every pair it has and uses the relay only when nothing
//! cheaper answers (RFC 8445 §5.1.2.2 gives a relayed candidate the lowest
//! type preference there is).
//!
//! # Why the application allocates, and not the call
//!
//! An Allocate is two round trips — the first request goes out bare and is
//! answered 401 with a realm and a nonce (RFC 8489 §9.2) — and an agent that
//! ran them itself would hold the offer until they came back, which turns a
//! description written in one pass into one written in two, in the Rust API
//! and in the C ABI alike. The STUN answer for the same socket is asked
//! before the call for the same reason ([`Mappings`](crate::Mappings)), and
//! this is the same shape one server further: [`Relays::allocate`] when the
//! socket is bound, the application's socket sends what
//! [`Relays::poll_transmit`] hands back and hands in what arrives, and
//! [`Relays::take`] gives the finished allocation to
//! [`CallMedia::relay`](crate::CallMedia::relay).
//!
//! From there the allocation is the call's. Its agent installs the
//! permissions the peer's candidates need, binds a channel for the data
//! (ChannelData's four bytes against a Send indication's thirty-six), keeps
//! the NAT binding towards the server alive, refreshes the allocation before
//! it lapses, gives it back three seconds after ICE settles on a pair that
//! does not use it (RFC 8445 §8.3.1), and gives it back when the call ends —
//! a Refresh with a lifetime of zero, among the call's farewells
//! ([`MediaEngine::poll_farewell`](crate::MediaEngine::poll_farewell)). A
//! call whose peer does no ICE never uses it, and gives it back the same way.
//!
//! # The credential
//!
//! A TURN server hands out bandwidth, so it asks for a long-term credential
//! (RFC 8489 §9.2), and this is where the password lives. It never reaches a
//! `Debug` of anything here, and it and the key derived from it are
//! overwritten when they are dropped — with the best effort
//! `sipral-nat`'s `Password` documents, since a volatile write needs
//! `unsafe` and this crate has none.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::auth::KeySource;
use sipral_nat::stun::{
    Class, LongTermCredentials, Message, MessageBuilder, Method, TransactionId,
};
use sipral_nat::turn::{Event, Input, TurnClient, TurnConfig, TurnError};

/// How often a socket holding an allocation, and waiting for its call, sends
/// the server a Binding indication.
///
/// The allocation itself lasts ten minutes and is refreshed a minute before
/// it lapses, but the NAT binding it rides on is released by most consumer
/// routers after thirty seconds of silence, and a relay reached from a port
/// the server no longer recognises is a relay that answers 437 (RFC 8656
/// §7.4). Twenty-five seconds is the figure [`Mappings`](crate::Mappings)
/// uses for the same NATs.
const KEEPALIVE: Duration = Duration::from_secs(25);

/// What [`Relays`] learned about a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayEvent {
    /// The server allocated a relay for `local`, and it is ready to hand to a
    /// call with [`Relays::take`].
    Allocated {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// Where the server relays from: the address the call's relayed
        /// candidate names.
        relayed: SocketAddr,
        /// Where the server saw the socket from (XOR-MAPPED-ADDRESS), when it
        /// said.
        mapped: Option<SocketAddr>,
    },
    /// There is no relay for `local`: the server refused, did not answer, or
    /// took back an allocation that had been made. A call placed on the
    /// socket is placed without one, and ICE finds whatever path it can on
    /// the candidates it has.
    Failed {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// Why.
        failure: TurnError,
    },
}

/// A request for the TURN server, for the application's socket to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayDatagram {
    /// The socket to send it from: the one the allocation is for.
    pub local: SocketAddr,
    /// The TURN server.
    pub destination: SocketAddr,
    /// The request.
    pub payload: Vec<u8>,
}

/// One socket's allocation, while it waits for its call.
struct Pending {
    client: TurnClient,
    /// When the next Binding indication goes out, once allocated.
    keepalive_at: Option<Instant>,
}

/// The relays an application allocated on one TURN server, one per media
/// socket, until each is handed to its call.
///
/// Sans-I/O, like everything else in this crate: `now` arrives at every entry
/// point, the application's sockets send and receive, and nothing here reads
/// a clock or draws from the operating system.
pub struct Relays {
    server: SocketAddr,
    credentials: LongTermCredentials,
    keys: KeySource,
    sockets: BTreeMap<SocketAddr, Pending>,
    outbox: VecDeque<RelayDatagram>,
    events: VecDeque<RelayEvent>,
}

impl Relays {
    /// Relays on the TURN server at `server`, which knows this end by
    /// `username` and `password`, with transaction ids drawn from `seed`.
    ///
    /// `seed` must be thirty-two bytes from the platform's cryptographic
    /// generator and given to nothing else: a transaction id an attacker off
    /// the path can guess is a response it can forge, and a forged Allocate
    /// response names a relay of its choosing.
    /// [`MediaEngine::relays`](crate::MediaEngine::relays) draws them from the
    /// engine's own generator instead.
    #[must_use]
    pub fn new(server: SocketAddr, username: &str, password: &str, seed: [u8; 32]) -> Self {
        Self {
            server,
            credentials: LongTermCredentials::new(username, password),
            keys: KeySource::new(seed),
            sockets: BTreeMap::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// The server every relay is allocated on.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// Allocate a relay for `local`.
    ///
    /// Nothing for a socket that already has one, or is getting one. A server
    /// of the other address family is never asked: the socket is
    /// [`RelayEvent::Failed`] at once, with
    /// [`TurnError::AddressFamilyNotSupported`].
    pub fn allocate(&mut self, local: SocketAddr, now: Instant) {
        if self.sockets.contains_key(&local) {
            return;
        }
        if local.is_ipv4() != self.server.is_ipv4() {
            self.events.push_back(RelayEvent::Failed {
                local,
                failure: TurnError::AddressFamilyNotSupported,
            });
            return;
        }
        let mut client = TurnClient::new(TurnConfig {
            credentials: Some(self.credentials.clone()),
            ..TurnConfig::default()
        });
        top_up(&mut self.keys, &mut client);
        match client.allocate(now) {
            Ok(()) => {
                self.sockets.insert(
                    local,
                    Pending {
                        client,
                        keepalive_at: None,
                    },
                );
                self.drain(local, now);
            }
            // a fresh client with a full pool refuses only a request that
            // does not fit a message, which a user name of hundreds of bytes
            // would be
            Err(_) => self.events.push_back(RelayEvent::Failed {
                local,
                failure: TurnError::Oversized,
            }),
        }
    }

    /// Hand in a datagram that arrived on `local` from `from`, and say
    /// whether it was the TURN server's — which the caller then passes to
    /// nothing else.
    ///
    /// Before a call there is no peer with a permission, so the server has
    /// nothing to relay yet; whatever it sends is an answer to a request of
    /// this end's, and is taken here — except a Binding response, which is
    /// the answer to a [`Mappings`](crate::Mappings) request when one server
    /// is both the STUN and the TURN server, as a coturn usually is. So an
    /// application that keeps both hands a datagram here first and to
    /// `Mappings` after.
    pub fn receive(
        &mut self,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        if from != self.server
            || Message::parse(data).is_ok_and(|message| message.method() == Method::BINDING)
        {
            return false;
        }
        let Some(pending) = self.sockets.get_mut(&local) else {
            return false;
        };
        top_up(&mut self.keys, &mut pending.client);
        let input = pending.client.handle_input(data, now);
        if input == Input::Foreign {
            return false;
        }
        self.drain(local, now);
        true
    }

    /// The next request to send, from the socket it names.
    ///
    /// Drain to empty after every [`Relays::allocate`], every datagram handed
    /// in and every deadline [`Relays::poll_timeout`] named.
    pub fn poll_transmit(&mut self) -> Option<RelayDatagram> {
        self.outbox.pop_front()
    }

    /// The next thing learned.
    pub fn poll_event(&mut self) -> Option<RelayEvent> {
        self.events.pop_front()
    }

    /// When something is next due: a retransmission, a transaction giving
    /// up, a refresh, or a keepalive.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.sockets
            .values()
            .flat_map(|pending| [pending.client.deadline(), pending.keepalive_at])
            .flatten()
            .min()
    }

    /// Take the passing of time.
    pub fn handle_timeout(&mut self, now: Instant) {
        let due: Vec<SocketAddr> = self
            .sockets
            .iter()
            .filter(|(_, pending)| {
                pending.client.deadline().is_some_and(|at| at <= now)
                    || pending.keepalive_at.is_some_and(|at| at <= now)
            })
            .map(|(local, _)| *local)
            .collect();
        for local in due {
            let Some(pending) = self.sockets.get_mut(&local) else {
                continue;
            };
            top_up(&mut self.keys, &mut pending.client);
            if pending.client.deadline().is_some_and(|at| at <= now) {
                pending.client.handle_timeout(now);
            }
            if pending.keepalive_at.is_some_and(|at| at <= now) {
                pending.keepalive_at = now.checked_add(KEEPALIVE);
                if let Some(payload) = binding_indication(&mut self.keys) {
                    self.outbox.push_back(RelayDatagram {
                        local,
                        destination: self.server,
                        payload,
                    });
                }
            }
            self.drain(local, now);
        }
    }

    /// Whether `local` has asked for a relay and the server has not said yet.
    ///
    /// A call described on the socket now would go without the relay that is
    /// on its way, and the answer is at most thirty-nine and a half seconds
    /// off (RFC 8489 §6.2.1's default schedule), usually two round trips.
    #[must_use]
    pub fn pending(&self, local: SocketAddr) -> bool {
        self.sockets
            .get(&local)
            .is_some_and(|pending| !pending.client.is_allocated())
    }

    /// The relay allocated for `local`, for the call about to be placed,
    /// rung or answered on it — or `None` while the server has not answered,
    /// and for a socket that has no relay.
    ///
    /// Taken, it is the call's: nothing here sends for that socket again.
    pub fn take(&mut self, local: SocketAddr) -> Option<Relay> {
        if !self
            .sockets
            .get(&local)
            .is_some_and(|pending| pending.client.is_allocated())
        {
            return None;
        }
        let mut pending = self.sockets.remove(&local)?;
        top_up(&mut self.keys, &mut pending.client);
        Some(Relay {
            server: self.server,
            client: pending.client,
        })
    }

    /// Give `local`'s relay back to the server, for a socket that will not
    /// carry a call after all: a Refresh with a lifetime of zero, sent from
    /// [`Relays::poll_transmit`]. A socket still waiting for its answer is
    /// simply forgotten.
    pub fn release(&mut self, local: SocketAddr, now: Instant) {
        let Some(mut pending) = self.sockets.remove(&local) else {
            return;
        };
        if pending.client.is_allocated() {
            top_up(&mut self.keys, &mut pending.client);
            let _unallocated = pending.client.delete(now);
            while let Some(payload) = pending.client.poll_transmit() {
                self.outbox.push_back(RelayDatagram {
                    local,
                    destination: self.server,
                    payload,
                });
            }
        }
    }

    /// Send what a client queued and report what it said.
    fn drain(&mut self, local: SocketAddr, now: Instant) {
        let Some(pending) = self.sockets.get_mut(&local) else {
            return;
        };
        while let Some(payload) = pending.client.poll_transmit() {
            self.outbox.push_back(RelayDatagram {
                local,
                destination: self.server,
                payload,
            });
        }
        let mut closed = None;
        while let Some(event) = pending.client.poll_event() {
            match event {
                Event::Allocated {
                    relayed, mapped, ..
                } => {
                    pending.keepalive_at = now.checked_add(KEEPALIVE);
                    self.events.push_back(RelayEvent::Allocated {
                        local,
                        relayed,
                        mapped,
                    });
                }
                Event::Closed(failure) => closed = Some(failure),
                Event::AlsoAllocated { .. }
                | Event::FamilyRefused { .. }
                | Event::Refreshed { .. }
                | Event::PermissionInstalled { .. }
                | Event::PermissionFailed { .. }
                | Event::ChannelBound { .. }
                | Event::ChannelFailed { .. }
                | Event::Deleted => {}
            }
        }
        if let Some(failure) = closed {
            self.sockets.remove(&local);
            self.events.push_back(RelayEvent::Failed { local, failure });
        }
    }
}

/// Written by hand, so that nothing of the credential is printed: the user
/// name says who, which the server's own logs say too, and the password is
/// left out entirely.
impl core::fmt::Debug for Relays {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Relays")
            .field("server", &self.server)
            .field("sockets", &self.sockets.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// An allocation on a TURN server, made from one media socket and on its way
/// to the call that will use it.
///
/// Not `Clone`: it is the allocation, and two calls cannot hold one relay.
pub struct Relay {
    server: SocketAddr,
    client: TurnClient,
}

impl Relay {
    /// The TURN server it is on.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// Where the server relays from: the relayed candidate's address.
    ///
    /// `None` only for an allocation of no address at all, which
    /// [`Relays::take`] never hands out.
    #[must_use]
    pub fn relayed(&self) -> Option<SocketAddr> {
        self.client.relayed_addresses().first().copied()
    }

    /// Where the server saw the socket from, when it said: the same answer a
    /// STUN server gives, from the same socket.
    #[must_use]
    pub const fn mapped(&self) -> Option<SocketAddr> {
        self.client.mapped_address()
    }

    /// The server and the client, for the agent that takes the allocation
    /// over.
    pub(crate) fn into_parts(self) -> (SocketAddr, TurnClient) {
        (self.server, self.client)
    }

    /// Give the allocation back, for a call that will not use it: the
    /// Refresh with a lifetime of zero, to send to [`Relay::server`] from the
    /// socket it was allocated from.
    pub(crate) fn release(mut self, now: Instant) -> Vec<Vec<u8>> {
        let _unallocated = self.client.delete(now);
        let mut out = Vec::new();
        while let Some(payload) = self.client.poll_transmit() {
            out.push(payload);
        }
        out
    }
}

/// The addresses, and nothing of the credential or the key.
impl core::fmt::Debug for Relay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Relay")
            .field("server", &self.server)
            .field("relayed", &self.relayed())
            .field("mapped", &self.mapped())
            .finish_non_exhaustive()
    }
}

/// Keep a client's pool of transaction ids full, from a cryptographic
/// stream: two twelve-byte ids out of each thirty-two-byte block.
fn top_up(keys: &mut KeySource, client: &mut TurnClient) {
    let mut wanted = client.transaction_ids_wanted();
    while wanted > 0 {
        let block = keys.block();
        for chunk in block.chunks_exact(12).take(wanted.min(2)) {
            let mut id = [0_u8; 12];
            id.copy_from_slice(chunk);
            client.supply_transaction_id(TransactionId::new(id));
            wanted -= 1;
        }
    }
}

/// "A STUN Binding Indication ... MUST NOT utilize any authentication
/// mechanism. It SHOULD contain the FINGERPRINT attribute" (RFC 8445 §11):
/// the keepalive a NAT binding towards the server needs, and nothing the
/// server has to answer.
fn binding_indication(keys: &mut KeySource) -> Option<Vec<u8>> {
    let block = keys.block();
    let mut id = [0_u8; 12];
    id.copy_from_slice(block.get(..12)?);
    let mut builder =
        MessageBuilder::new(Class::Indication, Method::BINDING, TransactionId::new(id));
    builder.add_fingerprint().ok()?;
    Some(builder.finish())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use sipral_nat::stun::{AttributeType, Class, Message, MessageBuilder, Method};
    use sipral_nat::turn::{TurnError, method};

    use super::{RelayDatagram, RelayEvent, Relays};

    pub(crate) const SERVER: &str = "198.51.100.9:3478";
    const MEDIA: &str = "192.168.1.10:40000";
    pub(crate) const RELAYED: &str = "198.51.100.9:50000";
    pub(crate) const MAPPED: &str = "203.0.113.7:41002";

    fn at(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    fn drain(relays: &mut Relays) -> Vec<RelayDatagram> {
        let mut all = Vec::new();
        while let Some(datagram) = relays.poll_transmit() {
            all.push(datagram);
        }
        all
    }

    fn events(relays: &mut Relays) -> Vec<RelayEvent> {
        let mut all = Vec::new();
        while let Some(event) = relays.poll_event() {
            all.push(event);
        }
        all
    }

    /// The lifetime a Refresh asks for, or `None` for a message that is not
    /// one.
    pub(crate) fn refresh_lifetime(datagram: &[u8]) -> Option<u32> {
        let message = Message::parse(datagram).ok()?;
        if message.class() != Class::Request || message.method() != method::REFRESH {
            return None;
        }
        let value = message.find(AttributeType::LIFETIME)?;
        Some(u32::from_be_bytes(value.try_into().ok()?))
    }

    /// What a TURN server that asks for no credential writes back to any
    /// request: success, and for an Allocate the relayed address, the mapped
    /// one and ten minutes. The long-term exchange is `sipral-nat`'s to
    /// test, and the lab's against a real server; what is tested here is
    /// where the answers go.
    pub(crate) fn answer(request: &[u8]) -> Option<Vec<u8>> {
        let message = Message::parse(request).ok()?;
        if message.class() != Class::Request {
            return None;
        }
        let mut builder =
            MessageBuilder::new(Class::Success, message.method(), message.transaction_id());
        if message.method() == method::ALLOCATE {
            builder
                .add_xor_address(AttributeType::XOR_RELAYED_ADDRESS, at(RELAYED))
                .ok()?;
            builder
                .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, at(MAPPED))
                .ok()?;
            builder.add_u32(AttributeType::LIFETIME, 600).ok()?;
        }
        if message.method() == method::REFRESH {
            let lifetime = message
                .find(AttributeType::LIFETIME)
                .and_then(|value| value.try_into().ok())
                .map_or(600, u32::from_be_bytes);
            builder.add_u32(AttributeType::LIFETIME, lifetime).ok()?;
        }
        builder.add_fingerprint().ok()?;
        Some(builder.finish())
    }

    fn allocated(now: Instant) -> Relays {
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [5; 32]);
        relays.allocate(at(MEDIA), now);
        let requests = drain(&mut relays);
        assert_eq!(requests.len(), 1, "one Allocate");
        assert_eq!(requests[0].local, at(MEDIA));
        assert_eq!(requests[0].destination, at(SERVER));
        let reply = answer(&requests[0].payload).expect("an answer");
        assert!(relays.receive(at(MEDIA), at(SERVER), &reply, now));
        relays
    }

    #[test]
    fn an_allocation_is_reported_and_handed_to_the_call_once() {
        let now = Instant::now();
        let mut relays = allocated(now);
        assert_eq!(
            events(&mut relays),
            vec![RelayEvent::Allocated {
                local: at(MEDIA),
                relayed: at(RELAYED),
                mapped: Some(at(MAPPED)),
            }]
        );
        let relay = relays.take(at(MEDIA)).expect("the relay");
        assert_eq!(relay.relayed(), Some(at(RELAYED)));
        assert_eq!(relay.mapped(), Some(at(MAPPED)));
        assert_eq!(relay.server(), at(SERVER));
        // the call's now: nothing here keeps it or sends for it any more
        assert!(relays.take(at(MEDIA)).is_none());
        assert_eq!(relays.poll_timeout(), None);
    }

    #[test]
    fn the_password_is_in_no_debug() {
        let now = Instant::now();
        let mut relays = allocated(now);
        assert!(!format!("{relays:?}").contains("correct horse"));
        let relay = relays.take(at(MEDIA)).expect("the relay");
        let printed = format!("{relay:?}");
        assert!(!printed.contains("correct horse"), "{printed}");
        assert!(printed.contains(RELAYED), "{printed}");
    }

    #[test]
    fn a_socket_waiting_for_its_call_keeps_the_binding_towards_the_server_alive() {
        let now = Instant::now();
        let mut relays = allocated(now);
        let _ = events(&mut relays);
        let due = relays.poll_timeout().expect("a keepalive is due");
        assert_eq!(due, now + Duration::from_secs(25));
        relays.handle_timeout(due);
        let sent = drain(&mut relays);
        assert_eq!(sent.len(), 1);
        let message = Message::parse(&sent[0].payload).expect("STUN");
        assert_eq!(message.class(), Class::Indication);
        assert_eq!(message.method(), Method::BINDING);
        assert_eq!(sent[0].destination, at(SERVER));
    }

    #[test]
    fn a_relay_that_will_not_be_used_is_given_back() {
        let now = Instant::now();
        let mut relays = allocated(now);
        relays.release(at(MEDIA), now);
        let sent = drain(&mut relays);
        assert_eq!(sent.len(), 1);
        assert_eq!(refresh_lifetime(&sent[0].payload), Some(0));
        assert!(relays.take(at(MEDIA)).is_none());
    }

    #[test]
    fn a_server_that_never_answers_is_a_failure_and_no_relay() {
        let mut now = Instant::now();
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [6; 32]);
        relays.allocate(at(MEDIA), now);
        let mut failed = None;
        for _ in 0..32 {
            let _ = drain(&mut relays);
            if let Some(RelayEvent::Failed { failure, .. }) = relays.poll_event() {
                failed = Some(failure);
                break;
            }
            let Some(due) = relays.poll_timeout() else {
                break;
            };
            now = due;
            relays.handle_timeout(now);
        }
        assert_eq!(failed, Some(TurnError::TimedOut));
        assert!(relays.take(at(MEDIA)).is_none());
    }

    #[test]
    fn a_socket_of_the_other_family_is_refused_without_asking() {
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [7; 32]);
        relays.allocate(at("[2001:db8::1]:40000"), Instant::now());
        assert!(drain(&mut relays).is_empty());
        assert_eq!(
            events(&mut relays),
            vec![RelayEvent::Failed {
                local: at("[2001:db8::1]:40000"),
                failure: TurnError::AddressFamilyNotSupported,
            }]
        );
    }

    #[cfg(feature = "stun")]
    #[test]
    fn a_binding_answer_from_the_same_server_is_left_for_the_mappings() {
        let now = Instant::now();
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [9; 32]);
        relays.allocate(at(MEDIA), now);
        assert!(relays.pending(at(MEDIA)));
        let _ = drain(&mut relays);
        let stun = crate::nat::tests::answer(
            &MessageBuilder::new(
                Class::Request,
                Method::BINDING,
                sipral_nat::stun::TransactionId::new([3; 12]),
            )
            .finish(),
            at(MAPPED),
        );
        assert!(!relays.receive(at(MEDIA), at(SERVER), &stun, now));
        assert!(
            relays.pending(at(MEDIA)),
            "still waiting for its own answer"
        );
    }

    #[test]
    fn only_the_server_is_believed() {
        let now = Instant::now();
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [8; 32]);
        relays.allocate(at(MEDIA), now);
        let request = drain(&mut relays).remove(0);
        let reply = answer(&request.payload).expect("an answer");
        assert!(!relays.receive(at(MEDIA), at("198.51.100.66:3478"), &reply, now));
        assert!(events(&mut relays).is_empty());
    }
}
