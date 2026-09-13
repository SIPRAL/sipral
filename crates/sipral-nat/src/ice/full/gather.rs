// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Gathering (RFC 8445 §5.1.1), keeping what was gathered alive until ICE
//! concludes (§5.1.1.4), and giving back what was not used (§8.3.1).
//!
//! Host candidates come straight from the sockets the caller bound. Each host
//! candidate is then paired with every configured server of its family: a
//! Binding request to a STUN server for a server-reflexive candidate, an
//! Allocate to a TURN server for a relayed candidate and, from the same
//! response, a second server-reflexive one. Those transactions are paced by
//! Ta, the same pacing the checks get (§5.1.1.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::checks::Paced;
use super::{
    Allocation, Gatherer, IceAgent, IceError, IceEvent, LocalCandidate, Phase, Progress, Transmit,
};
use crate::ice::candidate::{Candidate, CandidateType, Foundation, candidate_priority};
use crate::ice::checklist::PairState;
use crate::stun::{
    BindingClient, BindingConfig, Class, MessageBuilder, Method, Progress as BindingProgress,
    TransactionId,
};
use crate::turn::{Event, StartError, TurnClient, TurnConfig, TurnError};

/// "Once a checklist has reached the Completed state, the agent SHOULD wait an
/// additional three seconds" before letting go of candidates it did not
/// select (RFC 8445 §8.3.1).
const FREE_AFTER: Duration = Duration::from_secs(3);

/// The floor RFC 8445 §14.3 puts under every RTO.
const MIN_RTO: Duration = Duration::from_millis(500);

impl IceAgent {
    /// Start gathering: host candidates at once, and a paced STUN or TURN
    /// transaction per host candidate and server.
    ///
    /// [`IceEvent::GatheringComplete`] follows when every transaction has
    /// answered or [`super::IceConfig::gathering_timeout`] has passed.
    ///
    /// # Errors
    ///
    /// [`IceError::AlreadyStarted`] when gathering has already begun.
    pub fn gather(&mut self, now: Instant) -> Result<(), IceError> {
        if self.phase != Phase::New {
            return Err(IceError::AlreadyStarted);
        }
        self.phase = Phase::Gathering;
        let stun = self.config.stun_servers.clone();
        let turn = self.config.turn_servers.clone();

        // RFC 8445 §14.3: "RTO = MAX (500ms, Ta * (Num-Of-Cands))", counting
        // the server-reflexive and relayed candidates being asked for
        let wanted: usize = self
            .bases
            .iter()
            .map(|base| {
                let family = |server: &SocketAddr| server.is_ipv4() == base.address.is_ipv4();
                stun.iter().filter(|server| family(server)).count()
                    + 2 * turn.iter().filter(|server| family(&server.address)).count()
            })
            .sum();
        let rto = self
            .ta
            .checked_mul(u32::try_from(wanted).unwrap_or(u32::MAX))
            .unwrap_or(MIN_RTO)
            .max(MIN_RTO);

        for index in 0..self.bases.len() {
            let Some(base) = self.bases.get(index) else {
                continue;
            };
            let (stream, component, address, top) =
                (base.stream, base.component, base.address, base.top);
            let foundation = self.foundation(CandidateType::Host, address.ip(), None);
            self.locals.push(LocalCandidate {
                stream,
                candidate: Candidate {
                    foundation,
                    component,
                    priority: candidate_priority(CandidateType::Host, top, component),
                    address,
                    kind: CandidateType::Host,
                    related: None,
                },
                base: address,
                socket: address,
                relay: None,
                local_preference: top,
            });
            for (offset, server) in stun.iter().enumerate() {
                if server.is_ipv4() != address.is_ipv4() {
                    continue;
                }
                self.gatherers.push(Gatherer {
                    base: index,
                    server: *server,
                    local_preference: below(top, 1 + offset),
                    client: BindingClient::new(BindingConfig {
                        rto,
                        ..BindingConfig::default()
                    }),
                    progress: Progress::Pending,
                    produced: false,
                    refresh_at: None,
                });
            }
            for (offset, server) in turn.iter().enumerate() {
                if server.address.is_ipv4() != address.is_ipv4() {
                    continue;
                }
                self.relays.push(Allocation {
                    base: index,
                    server: server.address,
                    relay_preference: below(top, 1 + stun.len() + offset),
                    reflexive_preference: below(top, 1 + stun.len() + turn.len() + offset),
                    client: TurnClient::new(TurnConfig {
                        credentials: server.credentials.clone(),
                        rto,
                        ..TurnConfig::default()
                    }),
                    progress: Progress::Pending,
                    candidate: None,
                    refresh_at: None,
                });
            }
        }

        self.gathering_until = now.checked_add(self.config.gathering_timeout);
        if self.gatherers.is_empty() && self.relays.is_empty() {
            self.finish_gathering(now);
        } else {
            self.wake_pacer(now);
        }
        Ok(())
    }

    /// Start the next gathering transaction, if one is waiting for its turn.
    pub(super) fn gathering_step(&mut self, now: Instant) -> Paced {
        if self.phase != Phase::Gathering {
            return Paced::Idle;
        }
        if let Some(index) = self
            .gatherers
            .iter()
            .position(|entry| entry.progress == Progress::Pending)
        {
            let Some(id) = self.ids.pop_front() else {
                return Paced::Starved;
            };
            let Some(entry) = self.gatherers.get_mut(index) else {
                return Paced::Idle;
            };
            entry.progress = Progress::Running;
            let progress = entry.client.start(id, now);
            self.on_binding_progress(index, progress, now);
            return Paced::Sent;
        }
        if let Some(index) = self
            .relays
            .iter()
            .position(|entry| entry.progress == Progress::Pending)
        {
            self.feed_relay(index);
            let Some(entry) = self.relays.get_mut(index) else {
                return Paced::Idle;
            };
            match entry.client.allocate(now) {
                Ok(()) => entry.progress = Progress::Running,
                Err(StartError::NoTransactionId) => return Paced::Starved,
                Err(_) => entry.progress = Progress::Done,
            }
            self.drain_relay(index, now);
            return Paced::Sent;
        }
        Paced::Idle
    }

    /// A datagram from a STUN server this base is gathering from. `false`
    /// when it was not the answer to anything in flight, so that the caller
    /// can look at it again as something else.
    pub(super) fn on_gatherer_datagram(
        &mut self,
        base: usize,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        let Some(index) = self
            .gatherers
            .iter()
            .position(|entry| entry.base == base && entry.server == from)
        else {
            return false;
        };
        let Some(entry) = self.gatherers.get_mut(index) else {
            return false;
        };
        let progress = entry.client.on_datagram(data);
        if progress == BindingProgress::Idle {
            return false;
        }
        self.on_binding_progress(index, progress, now);
        true
    }

    fn on_binding_progress(&mut self, index: usize, progress: BindingProgress, now: Instant) {
        let keepalive = self.config.keepalive;
        let Some(entry) = self.gatherers.get(index) else {
            return;
        };
        let (base, server, preference) = (entry.base, entry.server, entry.local_preference);
        let first = entry.progress == Progress::Running;
        match progress {
            BindingProgress::Idle => {}
            BindingProgress::Transmit => {
                let data = entry.client.datagram().to_vec();
                if let Some(source) = self.bases.get(base).map(|entry| entry.address) {
                    self.outbox.push_back(Transmit {
                        source,
                        destination: server,
                        data,
                    });
                }
            }
            BindingProgress::Mapped(mapped) => {
                if first {
                    self.add_reflexive(base, mapped, server.ip(), preference);
                }
                if let Some(entry) = self.gatherers.get_mut(index) {
                    if first {
                        entry.progress = Progress::Done;
                        entry.produced = true;
                    }
                    entry.refresh_at = now.checked_add(keepalive);
                }
            }
            BindingProgress::Challenged | BindingProgress::Failed(_) => {
                if let Some(entry) = self.gatherers.get_mut(index) {
                    if first {
                        entry.progress = Progress::Done;
                    }
                    // a refresh that went unanswered is tried again, since the
                    // mapping it keeps alive is still advertised
                    entry.refresh_at = if entry.produced {
                        now.checked_add(keepalive)
                    } else {
                        None
                    };
                }
            }
        }
        self.check_gathering_complete(now);
    }

    /// A server-reflexive candidate, unless it is redundant with one already
    /// held: "A candidate is redundant if and only if its transport address
    /// and base equal those of another candidate. The agent SHOULD eliminate
    /// the redundant candidate with the lower priority" (RFC 8445 §5.1.3).
    /// The common case is a host with no NAT in front of it, whose
    /// server-reflexive address is its host address.
    fn add_reflexive(
        &mut self,
        base: usize,
        mapped: SocketAddr,
        server: IpAddr,
        local_preference: u16,
    ) {
        let Some(entry) = self.bases.get(base) else {
            return;
        };
        let (stream, component, address) = (entry.stream, entry.component, entry.address);
        let kind = CandidateType::ServerReflexive;
        let priority = candidate_priority(kind, local_preference, component);
        let foundation = self.foundation(kind, address.ip(), Some(server));
        if let Some(existing) = self.locals.iter_mut().find(|local| {
            local.stream == stream
                && local.candidate.component == component
                && local.candidate.address == mapped
                && local.base == address
        }) {
            if existing.candidate.kind == kind && existing.candidate.priority < priority {
                existing.candidate.priority = priority;
                existing.candidate.foundation = foundation;
                existing.local_preference = local_preference;
            }
            return;
        }
        self.locals.push(LocalCandidate {
            stream,
            candidate: Candidate {
                foundation,
                component,
                priority,
                address: mapped,
                kind,
                related: Some(address),
            },
            base: address,
            socket: address,
            relay: None,
            local_preference,
        });
    }

    /// Send what a TURN client has queued and act on what it reports.
    pub(super) fn drain_relay(&mut self, relay: usize, now: Instant) {
        let Some((base, server)) = self
            .relays
            .get(relay)
            .map(|entry| (entry.base, entry.server))
        else {
            return;
        };
        let Some(source) = self.bases.get(base).map(|entry| entry.address) else {
            return;
        };
        loop {
            let Some(entry) = self.relays.get_mut(relay) else {
                return;
            };
            if let Some(data) = entry.client.poll_transmit() {
                self.outbox.push_back(Transmit {
                    source,
                    destination: server,
                    data,
                });
                continue;
            }
            let Some(event) = entry.client.poll_event() else {
                break;
            };
            self.on_relay_event(relay, &event, now);
        }
        self.check_gathering_complete(now);
    }

    fn on_relay_event(&mut self, relay: usize, event: &Event, now: Instant) {
        match *event {
            Event::Allocated {
                relayed, mapped, ..
            } => self.allocated(relay, relayed, mapped, now),
            Event::Closed(error) => self.relay_closed(relay, error, now),
            Event::PermissionInstalled { .. } => self.wake_pacer(now),
            Event::PermissionFailed { peer, .. } => self.permission_failed(relay, peer, now),
            Event::Deleted
            | Event::AlsoAllocated { .. }
            | Event::FamilyRefused { .. }
            | Event::Refreshed { .. }
            | Event::ChannelBound { .. }
            | Event::ChannelFailed { .. } => {}
        }
    }

    fn allocated(
        &mut self,
        relay: usize,
        relayed: SocketAddr,
        mapped: Option<SocketAddr>,
        now: Instant,
    ) {
        let keepalive = self.config.keepalive;
        let Some(entry) = self.relays.get(relay) else {
            return;
        };
        let (base, server) = (entry.base, entry.server);
        let (relay_preference, reflexive_preference) =
            (entry.relay_preference, entry.reflexive_preference);
        if entry.progress != Progress::Running || self.phase != Phase::Gathering {
            // gathering gave up on this one and nobody was told about it, so
            // the relay's resources go back at once
            self.feed_relay(relay);
            if let Some(entry) = self.relays.get_mut(relay) {
                let _unasked = entry.client.delete(now);
                entry.progress = Progress::Freed;
            }
            return;
        }
        let Some(host) = self.bases.get(base) else {
            return;
        };
        let (stream, component, socket) = (host.stream, host.component, host.address);
        if let Some(entry) = self.relays.get_mut(relay) {
            entry.progress = Progress::Done;
            entry.refresh_at = now.checked_add(keepalive);
        }

        // "If a relayed candidate is identical to a host candidate (which can
        // happen in rare cases), the relayed candidate MUST be discarded"
        // (RFC 8445 §5.1.1.2)
        let duplicate = self.locals.iter().any(|local| {
            local.candidate.kind == CandidateType::Host && local.candidate.address == relayed
        });
        if !duplicate {
            let kind = CandidateType::Relay;
            let foundation = self.foundation(kind, relayed.ip(), Some(server.ip()));
            self.locals.push(LocalCandidate {
                stream,
                candidate: Candidate {
                    foundation,
                    component,
                    priority: candidate_priority(kind, relay_preference, component),
                    address: relayed,
                    kind,
                    // RFC 8839 §5.1: the related address of a relayed
                    // candidate is the mapped address the Allocate returned,
                    // and the privacy form when there was none
                    related: Some(mapped.unwrap_or_else(|| withheld(relayed))),
                },
                base: relayed,
                socket,
                relay: Some(relay),
                local_preference: relay_preference,
            });
            let index = self.locals.len() - 1;
            if let Some(entry) = self.relays.get_mut(relay) {
                entry.candidate = Some(index);
            }
        }
        if let Some(mapped) = mapped {
            self.add_reflexive(base, mapped, server.ip(), reflexive_preference);
        }
    }

    fn relay_closed(&mut self, relay: usize, error: TurnError, now: Instant) {
        let gathering = self.phase == Phase::Gathering;
        let Some(entry) = self.relays.get_mut(relay) else {
            return;
        };
        let was_running = entry.progress == Progress::Running;
        if entry.progress != Progress::Freed {
            entry.progress = Progress::Done;
        }
        entry.refresh_at = None;
        let (base, server, preference) = (entry.base, entry.server, entry.reflexive_preference);
        // "If the Allocate request is rejected because the server lacks
        // resources to fulfill it, the agent SHOULD instead send a Binding
        // request to obtain a server-reflexive candidate" (RFC 8445 §5.1.1.2)
        if was_running
            && gathering
            && matches!(
                error,
                TurnError::QuotaReached | TurnError::InsufficientCapacity
            )
        {
            self.gatherers.push(Gatherer {
                base,
                server,
                local_preference: preference,
                client: BindingClient::new(BindingConfig::default()),
                progress: Progress::Pending,
                produced: false,
                refresh_at: None,
            });
            self.wake_pacer(now);
        }
    }

    /// The relay would not let a peer's address through, so no check from
    /// the relayed candidate to that address can ever be sent.
    fn permission_failed(&mut self, relay: usize, peer: IpAddr, now: Instant) {
        let Some(local) = self.relays.get(relay).and_then(|entry| entry.candidate) else {
            return;
        };
        let remotes = &self.remotes;
        for pair in &mut self.pairs {
            if pair.local == local
                && matches!(pair.state, PairState::Frozen | PairState::Waiting)
                && remotes
                    .get(pair.remote)
                    .is_some_and(|remote| remote.candidate.address.ip() == peer)
            {
                pair.state = PairState::Failed;
            }
        }
        for stream in 0..self.streams.len() {
            self.update_checklist(stream, now);
        }
        self.wake_pacer(now);
    }

    /// Ask every relay on a stream to let the stream's remote candidates
    /// through: "the client MUST create a permission first" (RFC 8445
    /// §7.2.1), and doing it as soon as the candidates are known means the
    /// relayed checks are not held up waiting for one.
    pub(super) fn permit_remotes(&mut self, stream: usize, now: Instant) {
        let relays: Vec<(usize, SocketAddr)> = self
            .locals
            .iter()
            .filter(|local| local.stream == stream)
            .filter_map(|local| local.relay.map(|relay| (relay, local.candidate.address)))
            .collect();
        let peers: Vec<IpAddr> = self
            .remotes
            .iter()
            .filter(|remote| remote.stream == stream)
            .map(|remote| remote.candidate.address.ip())
            .collect();
        for (relay, relayed) in relays {
            let Some(entry) = self.relays.get_mut(relay) else {
                continue;
            };
            if entry.progress == Progress::Freed {
                continue;
            }
            for peer in peers
                .iter()
                .filter(|peer| peer.is_ipv4() == relayed.is_ipv4())
            {
                entry.client.permit(*peer, now);
            }
            self.feed_relay(relay);
            self.drain_relay(relay, now);
        }
    }

    fn check_gathering_complete(&mut self, now: Instant) {
        let open = |progress: Progress| matches!(progress, Progress::Pending | Progress::Running);
        if self.phase == Phase::Gathering
            && !self.gatherers.iter().any(|entry| open(entry.progress))
            && !self.relays.iter().any(|entry| open(entry.progress))
        {
            self.finish_gathering(now);
        }
    }

    fn finish_gathering(&mut self, now: Instant) {
        self.phase = Phase::Gathered;
        self.gathering_until = None;
        for entry in &mut self.gatherers {
            if matches!(entry.progress, Progress::Pending | Progress::Running) {
                entry.progress = Progress::Done;
                // a fresh client has nothing in flight and so nothing to
                // retransmit for a candidate nobody will hear about
                entry.client = BindingClient::new(BindingConfig::default());
            }
        }
        for entry in &mut self.relays {
            if matches!(entry.progress, Progress::Pending | Progress::Running) {
                entry.progress = Progress::Done;
            }
        }
        self.events.push_back(IceEvent::GatheringComplete);
        for stream in 0..self.streams.len() {
            if self
                .streams
                .get(stream)
                .is_some_and(|entry| entry.remote.is_some())
            {
                // the peer's candidates may have arrived before a relay did,
                // and that relay needs its permissions as much as any other
                self.permit_remotes(stream, now);
                self.form_checklist(stream, now);
                self.replay_early(stream, now);
            }
        }
    }

    /// Retransmissions and timeouts of the gathering transactions, the
    /// refreshes that keep server-reflexive mappings alive, and the gathering
    /// deadline.
    pub(super) fn gathering_timeout(&mut self, now: Instant) {
        let live = self.concluded.is_none();
        for index in 0..self.gatherers.len() {
            let Some(entry) = self.gatherers.get_mut(index) else {
                continue;
            };
            if entry
                .client
                .deadline()
                .is_some_and(|deadline| deadline <= now)
            {
                let progress = entry.client.on_timeout(now);
                self.on_binding_progress(index, progress, now);
                continue;
            }
            // "For server-reflexive candidates learned through a Binding
            // request, the bindings MUST be kept alive by additional Binding
            // requests to the server" (RFC 8445 §5.1.1.4)
            if live && entry.produced && entry.refresh_at.is_some_and(|at| at <= now) {
                let Some(id) = self.ids.pop_front() else {
                    continue;
                };
                entry.refresh_at = None;
                let progress = entry.client.start(id, now);
                self.on_binding_progress(index, progress, now);
            }
        }

        for index in 0..self.relays.len() {
            let due = self.relays.get(index).is_some_and(|entry| {
                entry
                    .client
                    .deadline()
                    .is_some_and(|deadline| deadline <= now)
            });
            if due {
                self.feed_relay(index);
                if let Some(entry) = self.relays.get_mut(index) {
                    entry.client.handle_timeout(now);
                }
                self.drain_relay(index, now);
            }
            self.refresh_relay_mapping(index, live, now);
        }

        if self.phase == Phase::Gathering && self.gathering_until.is_some_and(|at| at <= now) {
            self.finish_gathering(now);
        }
    }

    /// A Binding indication to the TURN server, so that the NAT mapping the
    /// allocation rides on outlives a wait for the answer longer than the
    /// mapping's own timeout. The allocation refresh alone comes every nine
    /// minutes, which no consumer NAT waits for.
    fn refresh_relay_mapping(&mut self, index: usize, live: bool, now: Instant) {
        let keepalive = self.config.keepalive;
        let Some(entry) = self.relays.get(index) else {
            return;
        };
        let due = live
            && entry.progress == Progress::Done
            && entry.candidate.is_some()
            && entry.refresh_at.is_some_and(|at| at <= now);
        if !due {
            return;
        }
        let (base, server) = (entry.base, entry.server);
        let Some(id) = self.ids.pop_front() else {
            return;
        };
        let (Some(data), Some(source)) = (
            binding_indication(id),
            self.bases.get(base).map(|entry| entry.address),
        ) else {
            return;
        };
        self.outbox.push_back(Transmit {
            source,
            destination: server,
            data,
        });
        if let Some(entry) = self.relays.get_mut(index) {
            entry.refresh_at = now.checked_add(keepalive);
        }
    }

    pub(super) fn gathering_deadline(&self) -> Option<Instant> {
        let live = self.concluded.is_none();
        let gatherers = self.gatherers.iter().flat_map(|entry| {
            [
                entry.client.deadline(),
                entry.refresh_at.filter(|_| live && entry.produced),
            ]
        });
        let relays = self.relays.iter().flat_map(|entry| {
            [
                entry.client.deadline(),
                entry.refresh_at.filter(|_| {
                    live && entry.progress == Progress::Done && entry.candidate.is_some()
                }),
            ]
        });
        let until = self
            .gathering_until
            .filter(|_| self.phase == Phase::Gathering);
        gatherers
            .chain(relays)
            .chain([until, self.free_at()])
            .flatten()
            .min()
    }

    fn free_at(&self) -> Option<Instant> {
        let at = self.concluded?.checked_add(FREE_AFTER)?;
        (0..self.relays.len())
            .any(|relay| self.releasable(relay))
            .then_some(at)
    }

    /// A relay whose candidate no selected pair, current or from before a
    /// restart, sends through.
    fn releasable(&self, relay: usize) -> bool {
        let Some(entry) = self.relays.get(relay) else {
            return false;
        };
        let Some(local) = entry.candidate else {
            return false;
        };
        let selected = self.streams.iter().any(|stream| {
            stream.components.iter().any(|component| {
                component
                    .selected
                    .and_then(|valid| self.valid.get(valid))
                    .is_some_and(|valid| valid.via == local)
            })
        });
        let previous = self.previous.iter().any(|route| route.via == local);
        entry.progress == Progress::Done && !selected && !previous
    }

    /// Give back the allocations ICE did not end up using (RFC 8445 §8.3.1).
    pub(super) fn free_if_due(&mut self, now: Instant) {
        if self.free_at().is_none_or(|at| at > now) {
            return;
        }
        for relay in 0..self.relays.len() {
            if !self.releasable(relay) {
                continue;
            }
            self.feed_relay(relay);
            if let Some(entry) = self.relays.get_mut(relay) {
                let _unallocated = entry.client.delete(now);
                entry.progress = Progress::Freed;
            }
            self.drain_relay(relay, now);
        }
    }

    /// Two candidates share a foundation when they have "the same type", bases
    /// with "the same IP address", were obtained from servers with the same IP
    /// address, and over the same transport, which here is always UDP
    /// (RFC 8445 §5.1.1.3).
    fn foundation(
        &mut self,
        kind: CandidateType,
        base: IpAddr,
        server: Option<IpAddr>,
    ) -> Foundation {
        let key = (kind, base, server);
        let position = if let Some(known) = self.foundations.iter().position(|entry| *entry == key)
        {
            known
        } else {
            self.foundations.push(key);
            self.foundations.len() - 1
        };
        Foundation::numbered(u32::try_from(position + 1).unwrap_or(u32::MAX))
    }

    /// A local candidate learned from a check (RFC 8445 §7.2.5.3.1): type
    /// peer-reflexive, its base the local candidate the check left from, its
    /// priority the PRIORITY the check carried.
    pub(super) fn add_peer_reflexive(
        &mut self,
        via: usize,
        mapped: SocketAddr,
        priority: u32,
    ) -> Option<usize> {
        let from = self.locals.get(via)?;
        let (stream, component, base, socket, relay, local_preference) = (
            from.stream,
            from.candidate.component,
            from.base,
            from.socket,
            from.relay,
            from.local_preference,
        );
        let foundation = self.foundation(CandidateType::PeerReflexive, base.ip(), None);
        self.locals.push(LocalCandidate {
            stream,
            candidate: Candidate {
                foundation,
                component,
                priority,
                address: mapped,
                kind: CandidateType::PeerReflexive,
                related: Some(base),
            },
            base,
            socket,
            relay,
            local_preference,
        });
        Some(self.locals.len() - 1)
    }
}

/// A local preference `steps` below the top of a base's block.
fn below(top: u16, steps: usize) -> u16 {
    top.saturating_sub(u16::try_from(steps).unwrap_or(u16::MAX))
}

/// The address RFC 8839 §5.1 writes for a related address an agent does not
/// want to reveal: "0.0.0.0" or "::" and port 9.
fn withheld(address: SocketAddr) -> SocketAddr {
    let ip = if address.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    SocketAddr::new(ip, 9)
}

/// A keepalive: "a STUN Binding Indication ... MUST NOT utilize any
/// authentication mechanism. It SHOULD contain the FINGERPRINT attribute to
/// aid in demultiplexing, but it SHOULD NOT contain any other attributes"
/// (RFC 8445 §11).
pub(super) fn binding_indication(id: TransactionId) -> Option<Vec<u8>> {
    let mut builder = MessageBuilder::new(Class::Indication, Method::BINDING, id);
    builder.add_fingerprint().ok()?;
    Some(builder.finish())
}
