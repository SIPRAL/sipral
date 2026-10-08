// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A relay on a TURN server (RFC 8656), allocated from a media socket before the call and handed to
//! it as its relayed ICE candidate.
//!
//! The last resort of `docs/06-nat.md`, for ends whose NATs or networks block everything but one
//! server. The call's full ICE agent uses it only when nothing cheaper answers (RFC 8445 §5.1.2.2
//! gives relayed candidates the lowest type preference).
//!
//! # Why the application allocates
//!
//! An Allocate takes two round trips (a bare request, then a 401 with realm and nonce, RFC 8489
//! §9.2). Doing it inside the call would make offers two-pass in both the Rust API and the C ABI.
//! So, like [`Mappings`](crate::Mappings): call [`Relays::allocate`] when the socket is bound, send
//! what [`Relays::poll_transmit`] returns, hand in what arrives, and give [`Relays::take`]'s result
//! to [`CallMedia::relay`](crate::CallMedia::relay).
//!
//! # Over TCP or TLS
//!
//! Where UDP is blocked, [`Relays::over`] reaches the server over TCP or TLS (RFC 8656 §3.1); the
//! relay still uses UDP toward the peer. The application opens one connection per media socket (the
//! server identifies the allocation by it, §3.2), and for TLS checks the certificate with the
//! platform stack as for SIP. Output is written on that connection in order
//! ([`RelayDatagram::transport`]), input goes to [`Relays::receive_stream`] in any chunking, and a
//! closed connection is [`Relays::stream_closed`], which loses the relay.
//!
//! Once taken, the allocation belongs to the call's agent: it installs permissions, binds a channel
//! (4 bytes of ChannelData against 36 for a Send indication), keeps the NAT binding alive,
//! refreshes the allocation, releases it 3 s after ICE picks a pair without it (RFC 8445 §8.3.1),
//! and releases it when the call ends with a zero-lifetime Refresh among the farewells
//! ([`MediaEngine::poll_farewell`](crate::MediaEngine::poll_farewell)). A peer without ICE never
//! uses it, and it is released the same way.
//!
//! # The credential
//!
//! TURN uses a long-term credential (RFC 8489 §9.2). The password never appears in `Debug`, and it
//! and its derived key are overwritten on drop, with the best effort `sipral-nat`'s `Password`
//! documents (a volatile write would need `unsafe`).

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::auth::KeySource;
use sipral_nat::stun::{
    Class, LongTermCredentials, Message, MessageBuilder, Method, TransactionId,
};
use sipral_nat::turn::{Event, FrameError, Input, Transport, TurnClient, TurnConfig, TurnError};

/// Binding indication interval for a socket holding an allocation while it waits for its call.
///
/// The allocation lasts ten minutes and is refreshed a minute early, but most home routers drop the
/// NAT binding after 30 s, and then the server answers 437 (RFC 8656 §7.4). 25 s, as in
/// [`Mappings`](crate::Mappings).
const KEEPALIVE: Duration = Duration::from_secs(25);

/// How many events wait for [`Relays::poll_event`] before the oldest is dropped. An application
/// that asks [`Relays::holds`] and [`Relays::take`] instead of reading them would otherwise keep
/// one for every allocation, a call's worth each, for the life of the process.
const EVENTS_KEPT: usize = 256;

/// Queue `event`, dropping the oldest past [`EVENTS_KEPT`].
fn queue_event(events: &mut VecDeque<RelayEvent>, event: RelayEvent) {
    if events.len() >= EVENTS_KEPT {
        events.pop_front();
    }
    events.push_back(event);
}

/// What [`Relays`] learned about a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayEvent {
    /// The server allocated a relay for `local`; get it with [`Relays::take`].
    Allocated {
        /// The socket, as the application named it.
        local: SocketAddr,
        /// Where the server relays from: the address the call's relayed
        /// candidate names.
        relayed: SocketAddr,
        /// Where the server saw the socket from (XOR-MAPPED-ADDRESS), if it said. Never over TCP or
        /// TLS, where it saw the connection.
        mapped: Option<SocketAddr>,
    },
    /// No relay for `local`: refused, unanswered, or taken back by the server. A call on the socket
    /// goes without, and ICE uses the other candidates.
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
    /// How it goes: [`Transport::Udp`] is a datagram from `local`; [`Transport::Tcp`] or
    /// [`Transport::Tls`] is bytes to write, in order, on `local`'s connection to `destination`
    /// ([`Relays::over`]).
    pub transport: Transport,
}

/// One socket's allocation, while it waits for its call.
struct Pending {
    client: TurnClient,
    /// When the next Binding indication goes out, once allocated.
    keepalive_at: Option<Instant>,
}

/// The relays allocated on one TURN server, one per media socket, until each is handed to its call.
///
/// Sans-I/O: `now` is passed in, the application's sockets do the I/O, and nothing reads a clock or
/// OS randomness.
pub struct Relays {
    server: SocketAddr,
    transport: Transport,
    credentials: LongTermCredentials,
    keys: KeySource,
    sockets: BTreeMap<SocketAddr, Pending>,
    /// Sockets released while their Allocate was in flight. The server may still allocate, so the
    /// client waits for the answer to release it ([`Relays::release`]).
    leaving: BTreeMap<SocketAddr, TurnClient>,
    outbox: VecDeque<RelayDatagram>,
    events: VecDeque<RelayEvent>,
}

impl Relays {
    /// Relays on the TURN server at `server`, authenticated as `username`/`password`, with
    /// transaction ids from `seed`.
    ///
    /// `seed` must be 32 cryptographically random bytes used for nothing else: a guessable id lets
    /// an off-path attacker forge an Allocate response naming its own relay.
    /// [`MediaEngine::relays`](crate::MediaEngine::relays) uses the engine's generator instead.
    #[must_use]
    pub fn new(server: SocketAddr, username: &str, password: &str, seed: [u8; 32]) -> Self {
        Self {
            server,
            transport: Transport::Udp,
            credentials: LongTermCredentials::new(username, password),
            keys: KeySource::new(seed),
            sockets: BTreeMap::new(),
            leaving: BTreeMap::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Reach the server over `transport` instead of UDP: TCP where UDP is blocked, TLS where one
    /// port is open or the certificate should be checked (RFC 8656 §3.1). The relay still uses UDP
    /// toward the peer.
    ///
    /// Call [`Relays::allocate`] for a socket only once its connection to [`Relays::server`] is
    /// open, and for TLS once the application's platform TLS has verified the certificate.
    #[must_use]
    pub const fn over(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// The server every relay is allocated on.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// How every relay reaches [`Relays::server`].
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// Allocate a relay for `local`.
    ///
    /// No-op if it has one or is getting one. A server of the other address family is never asked:
    /// the socket gets [`RelayEvent::Failed`] at once with
    /// [`TurnError::AddressFamilyNotSupported`]. Over TCP or TLS, call only once `local`'s
    /// connection is open ([`Relays::over`]).
    pub fn allocate(&mut self, local: SocketAddr, now: Instant) {
        if self.sockets.contains_key(&local) {
            return;
        }
        // released while the Allocate was in flight and wanted again: reuse that request, since a
        // second one from the same socket would be refused as a mismatch (RFC 8656 §7.2)
        if let Some(client) = self.leaving.remove(&local) {
            self.sockets.insert(
                local,
                Pending {
                    client,
                    keepalive_at: None,
                },
            );
            return;
        }
        if local.is_ipv4() != self.server.is_ipv4() {
            queue_event(
                &mut self.events,
                RelayEvent::Failed {
                    local,
                    failure: TurnError::AddressFamilyNotSupported,
                },
            );
            return;
        }
        let mut client = TurnClient::new(TurnConfig {
            transport: self.transport,
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
            // a fresh client only refuses a request too big for a message, e.g. a huge user name
            Err(_) => queue_event(
                &mut self.events,
                RelayEvent::Failed {
                    local,
                    failure: TurnError::Oversized,
                },
            ),
        }
    }

    /// Feed a datagram that arrived on `local` from `from`, and say whether it was the TURN
    /// server's; if so, pass it nowhere else.
    ///
    /// Before a call there is no peer permission, so anything from the server answers our requests.
    /// Binding responses are left alone: they answer [`Mappings`](crate::Mappings) when one server
    /// does both STUN and TURN (typical for coturn). So hand datagrams here first, then to
    /// `Mappings`.
    ///
    /// Over TCP or TLS nothing arrives as a datagram; use [`Relays::receive_stream`].
    pub fn receive(
        &mut self,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        if from != self.server
            || self.transport.is_stream()
            || Message::parse(data).is_ok_and(|message| message.method() == Method::BINDING)
        {
            return false;
        }
        let Some(pending) = self.sockets.get_mut(&local) else {
            return self.receive_leaving(local, data, now);
        };
        top_up(&mut self.keys, &mut pending.client);
        let input = pending.client.handle_input(data, now);
        if input == Input::Foreign {
            return false;
        }
        self.drain(local, now);
        true
    }

    /// Feed bytes read off `local`'s TCP or TLS connection to the server ([`Relays::over`]), in any
    /// chunking. Messages are reassembled (RFC 8656 §12.5) and handled like [`Relays::receive`].
    ///
    /// `Ok(false)` when no relay here uses that connection (never allocated, taken by a call, or
    /// lost).
    ///
    /// # Errors
    ///
    /// Something neither STUN nor a channel message, or a STUN length not in whole words. A stream
    /// cannot resync, so the relay is lost ([`RelayEvent::Failed`] with
    /// [`TurnError::ConnectionLost`]) and the application closes the connection.
    pub fn receive_stream(
        &mut self,
        local: SocketAddr,
        bytes: &[u8],
        now: Instant,
    ) -> Result<bool, FrameError> {
        if !self.transport.is_stream() {
            return Ok(false);
        }
        if let Some(pending) = self.sockets.get_mut(&local) {
            pending.client.push_stream(bytes);
            let mut frame = Vec::new();
            loop {
                let Some(pending) = self.sockets.get_mut(&local) else {
                    return Ok(true);
                };
                top_up(&mut self.keys, &mut pending.client);
                let taken = pending.client.poll_stream(&mut frame, now);
                self.drain(local, now);
                match taken {
                    Ok(Some(_)) => {}
                    Ok(None) => return Ok(true),
                    Err(error) => return Err(error),
                }
            }
        }
        let Some(client) = self.leaving.get_mut(&local) else {
            return Ok(false);
        };
        client.push_stream(bytes);
        let mut frame = Vec::new();
        loop {
            let Some(client) = self.leaving.get_mut(&local) else {
                return Ok(true);
            };
            top_up(&mut self.keys, client);
            match client.poll_stream(&mut frame, now) {
                Ok(Some(Input::Foreign)) => {}
                Ok(Some(_)) => {
                    self.settle_leaving(local, now);
                }
                Ok(None) => return Ok(true),
                Err(error) => {
                    self.leaving.remove(&local);
                    return Err(error);
                }
            }
        }
    }

    /// `local`'s TCP or TLS connection to the server closed, and its relay went with it (RFC 8656
    /// §3.2). A socket waiting for or holding one gets [`RelayEvent::Failed`] with
    /// [`TurnError::ConnectionLost`], and calls on it go without; [`Relays::allocate`] on a new
    /// connection asks again. No-op otherwise.
    pub fn stream_closed(&mut self, local: SocketAddr, now: Instant) {
        if !self.transport.is_stream() {
            return;
        }
        self.leaving.remove(&local);
        if let Some(pending) = self.sockets.get_mut(&local) {
            pending.client.stream_closed();
            self.drain(local, now);
        }
    }

    /// The next request to send, from the socket it names. Drain after every [`Relays::allocate`],
    /// every datagram handed in and every [`Relays::poll_timeout`] deadline.
    pub fn poll_transmit(&mut self) -> Option<RelayDatagram> {
        self.outbox.pop_front()
    }

    /// The next thing learned. At most 256 wait; past that the oldest is dropped, so an application
    /// that asks [`Relays::holds`] instead holds a bounded queue.
    pub fn poll_event(&mut self) -> Option<RelayEvent> {
        self.events.pop_front()
    }

    /// When something is next due: a retransmission, a timeout, a refresh or a keepalive.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let waiting = self
            .sockets
            .values()
            .flat_map(|pending| [pending.client.deadline(), pending.keepalive_at]);
        let leaving = self.leaving.values().map(TurnClient::deadline);
        waiting.chain(leaving).flatten().min()
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
                        transport: self.transport,
                    });
                }
            }
            self.drain(local, now);
        }
        // a released socket's Allocate is not retransmitted; its answer is awaited only as long as
        // the transaction would have waited
        self.leaving.retain(|_, client| {
            if client.deadline().is_some_and(|at| at <= now) {
                client.handle_timeout(now);
                while client.poll_transmit().is_some() {}
            }
            let closed = std::iter::from_fn(|| client.poll_event())
                .any(|event| matches!(event, Event::Closed(_)));
            !closed && client.deadline().is_some()
        });
    }

    /// Handle the answer to a released socket's in-flight Allocate, and say whether it was one. A
    /// reported allocation is released at once; the client is done either way, since a refusal (401
    /// included) allocated nothing.
    fn receive_leaving(&mut self, local: SocketAddr, data: &[u8], now: Instant) -> bool {
        let Some(client) = self.leaving.get_mut(&local) else {
            return false;
        };
        top_up(&mut self.keys, client);
        if client.handle_input(data, now) == Input::Foreign {
            return false;
        }
        self.settle_leaving(local, now);
        true
    }

    /// A released socket's Allocate was answered: the client is done, and any allocation goes
    /// straight back.
    fn settle_leaving(&mut self, local: SocketAddr, now: Instant) {
        let Some(mut client) = self.leaving.remove(&local) else {
            return;
        };
        while client.poll_transmit().is_some() {}
        if client.is_allocated() {
            let _unallocated = client.delete(now);
            while let Some(payload) = client.poll_transmit() {
                self.outbox.push_back(RelayDatagram {
                    local,
                    destination: self.server,
                    payload,
                    transport: self.transport,
                });
            }
        }
    }

    /// Whether `local` asked for a relay and has no answer yet.
    ///
    /// A call described now would go without it; the answer is at most 39.5 s away (RFC 8489
    /// §6.2.1), usually two round trips.
    #[must_use]
    pub fn pending(&self, local: SocketAddr) -> bool {
        self.sockets
            .get(&local)
            .is_some_and(|pending| !pending.client.is_allocated())
    }

    /// Whether a relay is in progress or held for `local` here: requested, allocated and waiting,
    /// or released before its answer. `false` after [`Relays::take`] and for sockets that never had
    /// one.
    #[must_use]
    pub fn holds(&self, local: SocketAddr) -> bool {
        self.sockets.contains_key(&local) || self.leaving.contains_key(&local)
    }

    /// The relay for `local`, for the call about to be placed, rung or answered there; `None`
    /// before the answer or without a relay. Once taken it is the call's, and nothing here sends
    /// for that socket again.
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
            local,
            server: self.server,
            client: pending.client,
        })
    }

    /// Take back a relay from [`Relays::take`] whose call was never placed, for example one
    /// returned by [`MediaEngine::poll_returned_relay`](crate::MediaEngine::poll_returned_relay).
    /// It is kept alive as before and handed to the next call on its socket. If the socket already
    /// has another relay, or the relay is on a different server, it is released instead (a
    /// zero-lifetime Refresh from [`Relays::poll_transmit`]).
    pub fn put_back(&mut self, relay: Relay, now: Instant) {
        let Relay {
            local,
            server,
            mut client,
        } = relay;
        top_up(&mut self.keys, &mut client);
        if server != self.server
            || client.transport() != self.transport
            || self.sockets.contains_key(&local)
            || !client.is_allocated()
        {
            let _unallocated = client.delete(now);
            let transport = client.transport();
            while let Some(payload) = client.poll_transmit() {
                self.outbox.push_back(RelayDatagram {
                    local,
                    destination: server,
                    payload,
                    transport,
                });
            }
            return;
        }
        self.sockets.insert(
            local,
            Pending {
                client,
                keepalive_at: now.checked_add(KEEPALIVE),
            },
        );
        self.drain(local, now);
    }

    /// Release `local`'s relay because the socket will carry no call: a zero-lifetime Refresh from
    /// [`Relays::poll_transmit`]. If the Allocate is still in flight nothing more is sent, but its
    /// answer (handed in through [`Relays::receive`]) still releases any allocation;
    /// [`Relays::allocate`] before then reuses that request.
    pub fn release(&mut self, local: SocketAddr, now: Instant) {
        let Some(mut pending) = self.sockets.remove(&local) else {
            return;
        };
        if !pending.client.is_allocated() {
            if pending.client.deadline().is_some() {
                self.leaving.insert(local, pending.client);
            }
            return;
        }
        top_up(&mut self.keys, &mut pending.client);
        let _unallocated = pending.client.delete(now);
        while let Some(payload) = pending.client.poll_transmit() {
            self.outbox.push_back(RelayDatagram {
                local,
                destination: self.server,
                payload,
                transport: self.transport,
            });
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
                transport: self.transport,
            });
        }
        let mut closed = None;
        while let Some(event) = pending.client.poll_event() {
            match event {
                Event::Allocated {
                    relayed, mapped, ..
                } => {
                    pending.keepalive_at = now.checked_add(KEEPALIVE);
                    queue_event(
                        &mut self.events,
                        RelayEvent::Allocated {
                            local,
                            relayed,
                            mapped: mapped.filter(|_| !self.transport.is_stream()),
                        },
                    );
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
            queue_event(&mut self.events, RelayEvent::Failed { local, failure });
        }
    }
}

/// Written by hand: the user name may appear (the server logs it too), the password never.
impl core::fmt::Debug for Relays {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Relays")
            .field("server", &self.server)
            .field("transport", &self.transport)
            .field("sockets", &self.sockets.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// A TURN allocation made from one media socket, on its way to a call.
///
/// Not `Clone`: two calls cannot share one relay.
pub struct Relay {
    local: SocketAddr,
    server: SocketAddr,
    client: TurnClient,
}

impl Relay {
    /// The media socket it was allocated from, and the only one it relays for; the server knows the
    /// allocation by that socket's source address.
    #[must_use]
    pub const fn local(&self) -> SocketAddr {
        self.local
    }

    /// The TURN server it is on.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// How it reaches [`Relay::server`]: UDP from [`Relay::local`], or the TCP or TLS connection it
    /// was allocated on.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.client.transport()
    }

    /// The relayed candidate's address. `None` only for an address-less allocation, which
    /// [`Relays::take`] never returns.
    #[must_use]
    pub fn relayed(&self) -> Option<SocketAddr> {
        self.client.relayed_addresses().first().copied()
    }

    /// Where the server saw the socket from, if it said; the same as a STUN answer. `None` over TCP
    /// or TLS, where it saw the connection, not the socket's datagrams.
    #[must_use]
    pub fn mapped(&self) -> Option<SocketAddr> {
        self.client
            .mapped_address()
            .filter(|_| !self.client.transport().is_stream())
    }

    /// The server and client, for the agent that takes over the allocation.
    pub(crate) fn into_parts(self) -> (SocketAddr, TurnClient) {
        (self.server, self.client)
    }

    /// Rebuild a relay from an agent that will never run: `client` on `server`, allocated from
    /// `local`.
    pub(crate) const fn from_parts(
        local: SocketAddr,
        server: SocketAddr,
        client: TurnClient,
    ) -> Self {
        Self {
            local,
            server,
            client,
        }
    }

    /// Release the allocation for a call that will not use it: the zero-lifetime Refresh to send to
    /// [`Relay::server`] from its socket.
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
            .field("local", &self.local)
            .field("server", &self.server)
            .field("transport", &self.transport())
            .field("relayed", &self.relayed())
            .field("mapped", &self.mapped())
            .finish_non_exhaustive()
    }
}

/// Keep a client's transaction id pool full from a cryptographic stream: two 12-byte ids per
/// 32-byte block.
fn top_up(keys: &mut KeySource, client: &mut TurnClient) {
    let mut wanted = client.transaction_ids_wanted();
    while wanted > 0 {
        let block = keys.block();
        for chunk in block.as_chunks::<12>().0.iter().take(wanted.min(2)) {
            let mut id = [0_u8; 12];
            id.copy_from_slice(chunk);
            client.supply_transaction_id(TransactionId::new(id));
            wanted -= 1;
        }
    }
}

/// The NAT keepalive toward the server. A Binding indication "MUST NOT utilize any authentication
/// mechanism. It SHOULD contain the FINGERPRINT attribute" (RFC 8445 §11), and needs no answer.
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
    use sipral_nat::turn::{FrameError, Transport, TurnError, method};

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

    /// A credential-less TURN server's reply to any request: success, plus relayed and mapped
    /// addresses and ten minutes for an Allocate. The long-term exchange is tested in `sipral-nat`
    /// and the lab; here only routing is.
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
        // the call owns it now; nothing here sends for it
        assert!(relays.take(at(MEDIA)).is_none());
        assert_eq!(relays.poll_timeout(), None);
    }

    #[test]
    fn an_application_that_takes_relays_without_reading_events_holds_a_bounded_queue() {
        let now = Instant::now();
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [5; 32]);
        let calls = u16::try_from(super::EVENTS_KEPT).expect("a port count") + 44;
        for call in 0..calls {
            let local = SocketAddr::new(at(MEDIA).ip(), 40_000 + 2 * call);
            relays.allocate(local, now);
            let requests = drain(&mut relays);
            let reply = answer(&requests[0].payload).expect("an answer");
            assert!(relays.receive(local, at(SERVER), &reply, now));
            // what such an application asks, before the call takes the relay
            assert!(relays.holds(local));
            assert!(relays.take(local).is_some());
        }
        let kept = events(&mut relays);
        assert_eq!(kept.len(), super::EVENTS_KEPT);
        assert_eq!(
            kept.first(),
            Some(&RelayEvent::Allocated {
                local: SocketAddr::new(at(MEDIA).ip(), 40_000 + 2 * 44),
                relayed: at(RELAYED),
                mapped: Some(at(MAPPED)),
            }),
            "the oldest were dropped first"
        );
    }

    /// An Allocate over TCP, its answer handed in `chunk` octets at a time.
    fn allocated_over_tcp(now: Instant, chunk: usize) -> Relays {
        let mut relays =
            Relays::new(at(SERVER), "alice", "correct horse", [13; 32]).over(Transport::Tcp);
        relays.allocate(at(MEDIA), now);
        let requests = drain(&mut relays);
        assert_eq!(requests.len(), 1, "one Allocate");
        assert_eq!(requests[0].transport, Transport::Tcp);
        assert_eq!(requests[0].destination, at(SERVER));
        let reply = answer(&requests[0].payload).expect("an answer");
        for piece in reply.chunks(chunk) {
            assert_eq!(relays.receive_stream(at(MEDIA), piece, now), Ok(true));
        }
        relays
    }

    #[test]
    fn an_allocation_over_tcp_arrives_in_whatever_pieces_and_names_no_mapping() {
        let now = Instant::now();
        for chunk in [1, 5, 13, 4096] {
            let mut relays = allocated_over_tcp(now, chunk);
            // the server saw the connection's mapping, not the socket's
            assert_eq!(
                events(&mut relays),
                vec![RelayEvent::Allocated {
                    local: at(MEDIA),
                    relayed: at(RELAYED),
                    mapped: None,
                }],
                "{chunk}"
            );
            let relay = relays.take(at(MEDIA)).expect("the relay");
            assert_eq!(relay.transport(), Transport::Tcp);
            assert_eq!(relay.mapped(), None);
        }
    }

    #[test]
    fn a_relay_over_tcp_keeps_its_binding_and_goes_back_on_the_connection() {
        let now = Instant::now();
        let mut relays = allocated_over_tcp(now, 64);
        let _ = events(&mut relays);
        let due = relays.poll_timeout().expect("a keepalive is due");
        relays.handle_timeout(due);
        let kept = drain(&mut relays);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].transport, Transport::Tcp);
        relays.release(at(MEDIA), due);
        let sent = drain(&mut relays);
        assert_eq!(sent.len(), 1);
        assert_eq!(refresh_lifetime(&sent[0].payload), Some(0));
        assert_eq!(sent[0].transport, Transport::Tcp);
    }

    #[test]
    fn a_datagram_from_the_server_is_not_the_answer_over_tcp() {
        let now = Instant::now();
        let mut relays =
            Relays::new(at(SERVER), "alice", "correct horse", [14; 32]).over(Transport::Tcp);
        relays.allocate(at(MEDIA), now);
        let request = drain(&mut relays).remove(0);
        let reply = answer(&request.payload).expect("an answer");
        assert!(!relays.receive(at(MEDIA), at(SERVER), &reply, now));
        assert!(relays.pending(at(MEDIA)), "still waiting on the connection");
    }

    #[test]
    fn a_closed_connection_fails_its_socket_and_asks_nothing_more() {
        let now = Instant::now();
        let mut relays =
            Relays::new(at(SERVER), "alice", "correct horse", [15; 32]).over(Transport::Tcp);
        relays.allocate(at(MEDIA), now);
        let _ = drain(&mut relays);
        relays.stream_closed(at(MEDIA), now);
        assert_eq!(
            events(&mut relays),
            vec![RelayEvent::Failed {
                local: at(MEDIA),
                failure: TurnError::ConnectionLost,
            }]
        );
        assert!(!relays.pending(at(MEDIA)));
        assert!(relays.take(at(MEDIA)).is_none());
        assert_eq!(relays.poll_timeout(), None);
        assert!(drain(&mut relays).is_empty());
        assert_eq!(
            relays.receive_stream(at(MEDIA), &[1, 1, 0, 0], now),
            Ok(false)
        );
    }

    #[test]
    fn a_connection_that_stops_making_sense_fails_its_socket() {
        let now = Instant::now();
        let mut relays = allocated_over_tcp(now, 64);
        let _ = events(&mut relays);
        assert_eq!(
            relays.receive_stream(at(MEDIA), &[22, 0xfe, 0xfd, 0], now),
            Err(FrameError::NotTurn(22))
        );
        assert_eq!(
            events(&mut relays),
            vec![RelayEvent::Failed {
                local: at(MEDIA),
                failure: TurnError::ConnectionLost,
            }]
        );
        assert!(relays.take(at(MEDIA)).is_none());
    }

    #[test]
    fn a_socket_released_over_tcp_before_its_answer_gives_back_what_the_answer_allocated() {
        let now = Instant::now();
        let mut relays =
            Relays::new(at(SERVER), "alice", "correct horse", [16; 32]).over(Transport::Tcp);
        relays.allocate(at(MEDIA), now);
        let request = drain(&mut relays).remove(0);
        relays.release(at(MEDIA), now);
        let reply = answer(&request.payload).expect("an answer");
        let (first, second) = reply.split_at(9);
        assert_eq!(relays.receive_stream(at(MEDIA), first, now), Ok(true));
        assert_eq!(relays.receive_stream(at(MEDIA), second, now), Ok(true));
        let sent = drain(&mut relays);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(refresh_lifetime(&sent[0].payload), Some(0));
        assert_eq!(sent[0].transport, Transport::Tcp);
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
    fn a_relay_released_before_its_answer_is_given_back_when_the_answer_comes() {
        let now = Instant::now();
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [10; 32]);
        relays.allocate(at(MEDIA), now);
        let request = drain(&mut relays).remove(0);
        relays.release(at(MEDIA), now);
        assert!(drain(&mut relays).is_empty(), "nothing allocated yet");

        let reply = answer(&request.payload).expect("an answer");
        assert!(relays.receive(at(MEDIA), at(SERVER), &reply, now));
        let sent = drain(&mut relays);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(refresh_lifetime(&sent[0].payload), Some(0));
        assert_eq!(
            (sent[0].local, sent[0].destination),
            (at(MEDIA), at(SERVER))
        );
        assert!(
            events(&mut relays).is_empty(),
            "a socket let go hears nothing"
        );
        assert!(relays.take(at(MEDIA)).is_none());
        assert_eq!(relays.poll_timeout(), None, "nothing left to wait for");
        assert!(
            !relays.receive(at(MEDIA), at(SERVER), &reply, now),
            "answered once"
        );
    }

    #[test]
    fn a_relay_released_and_never_answered_is_forgotten_without_asking_again() {
        let mut now = Instant::now();
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [11; 32]);
        relays.allocate(at(MEDIA), now);
        let _ = drain(&mut relays);
        relays.release(at(MEDIA), now);
        let mut rounds = 0;
        while let Some(due) = relays.poll_timeout() {
            rounds += 1;
            assert!(rounds < 32, "still waiting at {:?}", due - now);
            now = due;
            relays.handle_timeout(now);
            assert!(drain(&mut relays).is_empty(), "the Allocate went again");
        }
        assert!(events(&mut relays).is_empty());
    }

    #[test]
    fn a_relay_released_and_wanted_again_before_its_answer_is_the_same_request() {
        let now = Instant::now();
        let mut relays = Relays::new(at(SERVER), "alice", "correct horse", [12; 32]);
        relays.allocate(at(MEDIA), now);
        let request = drain(&mut relays).remove(0);
        relays.release(at(MEDIA), now);
        relays.allocate(at(MEDIA), now);
        assert!(
            drain(&mut relays).is_empty(),
            "a second Allocate from the same socket would be a mismatch"
        );
        assert!(relays.pending(at(MEDIA)));
        let reply = answer(&request.payload).expect("an answer");
        assert!(relays.receive(at(MEDIA), at(SERVER), &reply, now));
        assert!(drain(&mut relays).is_empty(), "nothing given back");
        assert!(relays.take(at(MEDIA)).is_some(), "the socket's relay");
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
