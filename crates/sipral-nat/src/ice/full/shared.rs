// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One TURN allocation that several ICE sessions use at once.
//!
//! A forked INVITE carries one offer to every branch, with one relayed
//! candidate in it, and one allocation stands behind that candidate. It
//! cannot be one per branch: the server knows an allocation by the addresses
//! it runs between, and "If the client wishes to allocate a second relayed
//! transport address, it must create a second allocation using a different
//! 5-tuple" (RFC 8656 §3.2), while the offer named one socket. It does not
//! need to be either: "Since SIP supports forking, TURN supports multiple
//! peers per relayed transport address" (RFC 8656 §2), and RFC 8839 §7 runs
//! each answer as "an independent offer/answer exchange, with its own set of
//! local candidates, pairs, checklists, states". So every branch's agent
//! holds the one allocation as a relayed candidate of its own, asks it for
//! the permissions and the channels its own peer needs, and hears the
//! relayed traffic of its own peer; and the allocation is given back only
//! when the last of them lets go of it — "Once all ICE sessions have ceased
//! using a given local candidate (a candidate may be used by multiple ICE
//! sessions, e.g., in forking scenarios), the agent can free that
//! candidate" (RFC 8445 §8.3.1).
//!
//! The client sits behind a lock because each branch's agent runs on the
//! thread that carries that branch's audio. Everything the client reports is
//! handed to every agent that holds it, each through a queue of its own, so
//! that the agent that happened to take the server's answer is not the only
//! one to hear that a permission is in or that the allocation is gone.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use crate::stun::TransactionId;
use crate::turn::{ChannelNumber, Event, Input, SendError, StartError, TurnClient};

/// The most reports one holder keeps unread. A holder drains its queue every
/// time it touches the allocation, so this is only reached by one that has
/// stopped running without letting go, and the oldest report gives way.
const QUEUED: usize = 64;

/// A TURN allocation that the ICE sessions of one forked call share.
///
/// A handle: cloning it shares the same allocation. Nothing is sent and
/// nothing is taken from the server by a handle alone; an agent takes it up
/// with [`IceAgent::add_shared_relay`](super::IceAgent::add_shared_relay),
/// and from then on the agent is one of its holders.
#[derive(Clone)]
pub struct SharedRelay {
    pool: Arc<Mutex<Pool>>,
}

struct Pool {
    server: SocketAddr,
    client: TurnClient,
    holders: Vec<Holder>,
    next: u64,
}

struct Holder {
    id: u64,
    /// What the client reported that this holder has not read yet.
    events: VecDeque<Event>,
    /// When the oldest of those arrived, so that an agent asked when it next
    /// has work comes back for them at once.
    news_at: Option<Instant>,
    /// The peers this holder asked the relay to let through.
    peers: Vec<IpAddr>,
}

impl SharedRelay {
    /// An allocation on `server`, held by nobody yet. What the client
    /// reported before it was shared — its own Allocate's success above all
    /// — is history by then, and is dropped rather than handed to its first
    /// holder as news.
    #[must_use]
    pub fn new(server: SocketAddr, mut client: TurnClient) -> Self {
        while client.poll_event().is_some() {}
        Self {
            pool: Arc::new(Mutex::new(Pool {
                server,
                client,
                holders: Vec::new(),
                next: 0,
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The TURN server it is on.
    #[must_use]
    pub fn server(&self) -> SocketAddr {
        self.lock().server
    }

    /// The relayed address of the family `like` is of, while the allocation
    /// lasts.
    #[must_use]
    pub fn relayed(&self, like: SocketAddr) -> Option<SocketAddr> {
        let pool = self.lock();
        if !pool.client.is_allocated() {
            return None;
        }
        pool.client
            .relayed_addresses()
            .iter()
            .find(|relayed| relayed.is_ipv4() == like.is_ipv4())
            .copied()
    }

    /// Where the server saw the socket from, when it said.
    #[must_use]
    pub fn mapped(&self) -> Option<SocketAddr> {
        self.lock().client.mapped_address()
    }

    /// How many agents hold it.
    #[must_use]
    pub fn holders(&self) -> usize {
        self.lock().holders.len()
    }

    /// Whether the server still holds the allocation for us.
    #[must_use]
    pub fn is_allocated(&self) -> bool {
        self.lock().client.is_allocated()
    }

    /// Who sent a datagram the server relayed, and where their packet is in
    /// it, without taking it (see [`TurnClient::peek`]).
    #[must_use]
    pub fn peek(&self, bytes: &[u8]) -> Option<(SocketAddr, Range<usize>)> {
        self.lock().client.peek(bytes)
    }

    /// The server and the client, when this is the one handle left and no
    /// agent holds it: an allocation that is still whole, for the
    /// application to keep for the next call. `Err` gives the handle back
    /// otherwise.
    ///
    /// # Errors
    ///
    /// The handle itself, while another handle or an agent still holds it.
    pub fn into_parts(self) -> Result<(SocketAddr, TurnClient), Self> {
        match Arc::try_unwrap(self.pool) {
            Ok(pool) => {
                let pool = pool.into_inner().unwrap_or_else(PoisonError::into_inner);
                if pool.holders.is_empty() {
                    Ok((pool.server, pool.client))
                } else {
                    Err(Self {
                        pool: Arc::new(Mutex::new(pool)),
                    })
                }
            }
            Err(pool) => Err(Self { pool }),
        }
    }

    /// Take the allocation up as one of its holders.
    pub(super) fn hold(&self) -> Held {
        let mut pool = self.lock();
        let id = pool.next;
        pool.next = pool.next.wrapping_add(1);
        pool.holders.push(Holder {
            id,
            events: VecDeque::new(),
            news_at: None,
            peers: Vec::new(),
        });
        Held {
            relay: self.clone(),
            id,
            released: false,
        }
    }
}

impl core::fmt::Debug for SharedRelay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let pool = self.lock();
        f.debug_struct("SharedRelay")
            .field("server", &pool.server)
            .field("relayed", &pool.client.relayed_addresses())
            .field("holders", &pool.holders.len())
            .finish_non_exhaustive()
    }
}

/// One agent's hold on a [`SharedRelay`]: the [`TurnClient`] calls the agent
/// makes, made on the shared client, with the reports read out of this
/// holder's own queue.
pub(super) struct Held {
    relay: SharedRelay,
    id: u64,
    /// Whether this holder has let go ([`Held::delete`]).
    released: bool,
}

impl Held {
    /// The shared handle, for another agent to take up.
    pub(super) fn relay(&self) -> &SharedRelay {
        &self.relay
    }

    /// Move what the client reported into every holder's queue, and run `f`
    /// on the client and this holder.
    fn with<R>(&self, f: impl FnOnce(&mut TurnClient, Option<&mut Holder>) -> R) -> R {
        let mut pool = self.relay.lock();
        let Pool {
            client, holders, ..
        } = &mut *pool;
        let id = self.id;
        f(client, holders.iter_mut().find(|holder| holder.id == id))
    }

    /// Hand what the client reported to every holder.
    fn spread(pool: &mut Pool, now: Option<Instant>) {
        while let Some(event) = pool.client.poll_event() {
            for holder in &mut pool.holders {
                if holder.events.len() >= QUEUED {
                    holder.events.pop_front();
                }
                holder.events.push_back(event.clone());
                if holder.news_at.is_none() {
                    holder.news_at = now;
                }
            }
        }
    }

    pub(super) fn allocate(&mut self, now: Instant) -> Result<(), StartError> {
        let mut pool = self.relay.lock();
        let started = pool.client.allocate(now);
        Self::spread(&mut pool, Some(now));
        started
    }

    /// Let go of the allocation: give it back to the server (a Refresh with a
    /// lifetime of zero, RFC 8656 §8) when this is its last holder, and
    /// otherwise stop keeping the peers only this holder asked for let
    /// through, and leave the allocation to the others.
    pub(super) fn delete(&mut self, now: Instant) -> Result<(), StartError> {
        if self.released {
            return Err(StartError::NotAllocated);
        }
        self.released = true;
        let mut pool = self.relay.lock();
        let Some(position) = pool.holders.iter().position(|holder| holder.id == self.id) else {
            return Err(StartError::NotAllocated);
        };
        let leaving = pool.holders.remove(position);
        if pool.holders.is_empty() {
            let deleted = pool.client.delete(now);
            Self::spread(&mut pool, Some(now));
            return deleted;
        }
        for peer in leaving.peers {
            let still_wanted = pool
                .holders
                .iter()
                .any(|holder| holder.peers.contains(&peer));
            if !still_wanted {
                pool.client.withdraw(peer, now);
            }
        }
        Ok(())
    }

    pub(super) fn permit(&mut self, peer: IpAddr, now: Instant) {
        let mut pool = self.relay.lock();
        if let Some(holder) = pool.holders.iter_mut().find(|holder| holder.id == self.id)
            && !holder.peers.contains(&peer)
        {
            holder.peers.push(peer);
        }
        pool.client.permit(peer, now);
        Self::spread(&mut pool, Some(now));
    }

    pub(super) fn bind_channel(&mut self, peer: SocketAddr, now: Instant) -> Option<ChannelNumber> {
        let mut pool = self.relay.lock();
        if let Some(holder) = pool.holders.iter_mut().find(|holder| holder.id == self.id)
            && !holder.peers.contains(&peer.ip())
        {
            holder.peers.push(peer.ip());
        }
        let number = pool.client.bind_channel(peer, now);
        Self::spread(&mut pool, Some(now));
        number
    }

    pub(super) fn send_to(
        &mut self,
        peer: SocketAddr,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SendError> {
        self.with(|client, _| client.send_to(peer, data, out))
    }

    pub(super) fn handle_input(&mut self, bytes: &[u8], now: Instant) -> Input {
        let mut pool = self.relay.lock();
        let input = pool.client.handle_input(bytes, now);
        Self::spread(&mut pool, Some(now));
        input
    }

    pub(super) fn handle_timeout(&mut self, now: Instant) {
        let mut pool = self.relay.lock();
        pool.client.handle_timeout(now);
        Self::spread(&mut pool, Some(now));
    }

    /// When the client next has something to do, or when reports are waiting
    /// in this holder's queue that another holder's traffic produced.
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.with(|client, holder| {
            let news = holder.and_then(|holder| holder.news_at);
            [client.deadline(), news].into_iter().flatten().min()
        })
    }

    pub(super) fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.with(|client, _| client.poll_transmit())
    }

    pub(super) fn poll_event(&mut self) -> Option<Event> {
        let mut pool = self.relay.lock();
        Self::spread(&mut pool, None);
        let holder = pool
            .holders
            .iter_mut()
            .find(|holder| holder.id == self.id)?;
        let event = holder.events.pop_front();
        if holder.events.is_empty() {
            holder.news_at = None;
        }
        event
    }

    pub(super) fn supply_transaction_id(&mut self, id: TransactionId) {
        self.with(|client, _| client.supply_transaction_id(id));
    }

    pub(super) fn transaction_ids_wanted(&self) -> usize {
        self.with(|client, _| client.transaction_ids_wanted())
    }

    /// Whether the allocation is live and this holder has not let go of it.
    pub(super) fn is_allocated(&self) -> bool {
        !self.released && self.with(|client, _| client.is_allocated())
    }

    pub(super) fn has_permission(&self, peer: IpAddr) -> bool {
        self.with(|client, _| client.has_permission(peer))
    }
}

/// An agent dropped without letting go — replaced, or never run — stops
/// being a holder, so its queue stops filling; the allocation is left to the
/// others, or to lapse at its server if there are none.
impl Drop for Held {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let mut pool = self.relay.lock();
        pool.holders.retain(|holder| holder.id != self.id);
    }
}
