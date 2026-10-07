// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Connectivity checks, from the checklist to the nomination (RFC 8445
//! §6.1.2, §6.1.4, §7.2 and §8.1).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::{
    CONSENT_EXPIRY, Check, ChecklistState, Consent, Credentials, IceAgent, IceEvent, Pair,
    PairOutcome, Phase, Purpose, Remote, Valid, link_local, priority_in_range,
};
use crate::ice::agent::Role;
use crate::ice::candidate::{
    Candidate, CandidateType, ComponentId, Foundation, candidate_priority,
};
use crate::ice::checklist::{
    PairState, Slot, initially_waiting, pair_priority, prune_sorted, trim_evenly,
};
use crate::stun::{
    AttributeType, Class, Integrity, Message, MessageBuilder, Method, TransactionId, error_code,
};

/// "Agents MUST NOT use an RTO value smaller than 500 ms" (RFC 8445 §14.3).
const MIN_RTO: Duration = Duration::from_millis(500);

/// A ceiling on the RTO a long checklist computes, so that a lost first
/// request does not cost a pair minutes.
const MAX_RTO: Duration = Duration::from_secs(5);

/// Requests a check sends before it gives up, and multiples of the RTO it
/// waits after the last one (RFC 8489 §6.2.1).
const RC: u32 = 7;
const RM: u32 = 16;

/// What a paced opportunity was used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Paced {
    /// A transaction went out; the next one waits Ta.
    Sent,
    /// Nothing was waiting.
    Idle,
    /// Something was waiting for a transaction id the caller has not given.
    Starved,
}

impl IceAgent {
    /// Keep the peer's candidates for a stream, as far as they can be used
    /// and as far as the bound on them allows.
    pub(super) fn add_remote_candidates(&mut self, stream: usize, candidates: &[Candidate]) {
        let Some(entry) = self.streams.get(stream) else {
            return;
        };
        let components: Vec<ComponentId> = entry.components.iter().map(|c| c.id).collect();
        for candidate in candidates {
            if self.remote_count(stream) >= self.config.max_remote_candidates {
                break;
            }
            let usable = priority_in_range(candidate.priority)
                && candidate.address.port() != 0
                && !candidate.address.ip().is_unspecified()
                && components.contains(&candidate.component);
            if !usable
                || self
                    .remote_at(stream, candidate.component, candidate.address)
                    .is_some()
            {
                continue;
            }
            self.remotes.push(Remote {
                stream,
                candidate: candidate.clone(),
            });
        }
    }

    /// Form a stream's checklist, or extend it with pairs for candidates that
    /// arrived since (RFC 8445 §6.1.2).
    pub(super) fn form_checklist(&mut self, stream: usize, now: Instant) {
        let Some(entry) = self.streams.get(stream) else {
            return;
        };
        if entry.remote.is_none() || entry.state != ChecklistState::Running {
            return;
        }
        let components: Vec<ComponentId> = entry.components.iter().map(|c| c.id).collect();

        // §6.1.2.2 and §6.1.2.3: every local candidate with every remote
        // candidate of the same component and address family, and a priority
        // for each; §6.1.2.4: a reflexive local candidate replaced by its base
        let mut formed: Vec<(u64, usize, usize, ComponentId)> = Vec::new();
        for (index, local) in self.locals.iter().enumerate() {
            let component = local.candidate.component;
            if local.stream != stream
                || local.candidate.kind == CandidateType::PeerReflexive
                || !components.contains(&component)
                || self.freed(index)
            {
                continue;
            }
            let Some(base) = self.base_of(index) else {
                continue;
            };
            for (remote_index, remote) in self.remotes.iter().enumerate() {
                let address = remote.candidate.address;
                if remote.stream != stream
                    || remote.candidate.component != component
                    || address.is_ipv4() != local.base.is_ipv4()
                    || link_local(address) != link_local(local.base)
                {
                    continue;
                }
                let priority = ordered(
                    self.role,
                    local.candidate.priority,
                    remote.candidate.priority,
                );
                formed.push((priority, base, remote_index, component));
            }
        }
        formed.sort_by_key(|pair| core::cmp::Reverse(pair.0));
        prune_sorted(&mut formed, |pair| (pair.1, pair.2));
        formed.retain(|pair| self.pair_between(stream, pair.1, pair.2).is_none());

        let first = self.next_pair;
        for (priority, local, remote, component) in formed {
            let id = self.next_pair;
            self.pairs.push(Pair {
                id: self.next_pair,
                stream,
                component,
                local,
                remote,
                priority,
                state: PairState::Frozen,
                nominate: false,
                nominate_on_success: false,
                valid: None,
            });
            self.next_pair = self.next_pair.saturating_add(1);
            self.remember(id);
        }
        self.sort_pairs();
        self.enforce_pair_limit();
        self.unfreeze_new(first);
        let patience = self.config.patience;
        if let Some(entry) = self.streams.get_mut(stream) {
            entry.formed = true;
            // RFC 8863: from here on everything this agent can do it has
            // done, and anything further is the peer's to send. The wait
            // starts here rather than at `gather`, because before the peer's
            // parameters arrive there is nothing to be patient about, and it
            // is set even when pairs were formed: a checklist whose pairs all
            // fail arrives at the same place one round trip later.
            entry.patience_until = now.checked_add(patience);
        }
        self.wake_pacer(now);
    }

    /// §6.1.2.5, over the whole checklist set.
    ///
    /// Only a pair no check has touched is discarded: Frozen, or Waiting with
    /// no nomination on it and no place in the triggered-check queue. A pair
    /// that is In-Progress, has finished, is queued or carries a nomination
    /// is what the valid list, a nomination and the queue refer to, and
    /// discarding it when a later candidate exchange extends the checklist
    /// would leave them pointing at nothing — a valid pair whose check could
    /// never be repeated with USE-CANDIDATE.
    fn enforce_pair_limit(&mut self) {
        let sizes: Vec<usize> = (0..self.streams.len())
            .map(|stream| {
                self.pairs
                    .iter()
                    .filter(|pair| pair.stream == stream)
                    .count()
            })
            .collect();
        let kept = trim_evenly(&sizes, self.config.max_pairs);
        let queued: Vec<u32> = self
            .streams
            .iter()
            .flat_map(|entry| entry.triggered.iter().copied())
            .collect();
        let mut seen = vec![0_usize; sizes.len()];
        let mut discarded = Vec::new();
        self.pairs.retain(|pair| {
            let Some(count) = seen.get_mut(pair.stream) else {
                return false;
            };
            *count += 1;
            let untouched = matches!(pair.state, PairState::Frozen | PairState::Waiting)
                && !pair.nominate
                && !pair.nominate_on_success
                && !queued.contains(&pair.id);
            let keep = !untouched || *count <= kept.get(pair.stream).copied().unwrap_or(0);
            if !keep {
                discarded.push(pair.id);
            }
            keep
        });
        for id in discarded {
            self.settle_pair(id, PairOutcome::NotChecked);
        }
        let live: Vec<u32> = self.pairs.iter().map(|pair| pair.id).collect();
        for entry in &mut self.streams {
            entry.triggered.retain(|id| live.contains(id));
        }
    }

    /// The starting states of pairs just formed (§6.1.2.6, step 4). A
    /// foundation some older pair already has is left to that pair's fate.
    fn unfreeze_new(&mut self, first: u32) {
        let waiting: Vec<u32> = {
            let mut ids = Vec::new();
            let mut slots = Vec::new();
            for pair in self.pairs.iter().filter(|pair| pair.id >= first) {
                let Some(foundation) = self.foundation_of(pair) else {
                    continue;
                };
                let taken = self
                    .pairs
                    .iter()
                    .any(|older| older.id < first && self.foundation_of(older) == Some(foundation));
                if taken {
                    continue;
                }
                ids.push(pair.id);
                slots.push(Slot {
                    checklist: pair.stream,
                    component: pair.component,
                    priority: pair.priority,
                    foundation,
                });
            }
            initially_waiting(&slots)
                .into_iter()
                .filter_map(|position| ids.get(position).copied())
                .collect()
        };
        for id in waiting {
            if let Some(pair) = self.pair_mut(id) {
                pair.state = PairState::Waiting;
            }
        }
    }

    /// Ask for a paced opportunity: at once if Ta has passed since the last
    /// one, when it will have otherwise.
    pub(super) fn wake_pacer(&mut self, now: Instant) {
        if self.next_paced.is_some() {
            return;
        }
        let earliest = self
            .last_paced
            .and_then(|at| at.checked_add(self.ta))
            .map_or(now, |at| at.max(now));
        self.next_paced = Some(earliest);
    }

    /// One paced opportunity: a gathering transaction if one is waiting, a
    /// check otherwise (RFC 8445 §5.1.1.2, §6.1.4.2).
    pub(super) fn paced(&mut self, now: Instant) {
        self.next_paced = None;
        let outcome = match self.gathering_step(now) {
            Paced::Idle => self.check_step(now),
            other => other,
        };
        match outcome {
            Paced::Sent => {
                self.last_paced = Some(now);
                self.next_paced = now.checked_add(self.ta);
            }
            Paced::Starved => self.next_paced = Some(now),
            Paced::Idle => {}
        }
    }

    /// §6.1.4.2: the next Running checklist in the set, and a check in it;
    /// a checklist with nothing to check hands its turn straight on.
    fn check_step(&mut self, now: Instant) -> Paced {
        if self.phase != Phase::Gathered {
            return Paced::Idle;
        }
        let count = self.streams.len();
        for offset in 0..count {
            let stream = (self.cursor + offset) % count;
            let running = self
                .streams
                .get(stream)
                .is_some_and(|entry| entry.formed && entry.state == ChecklistState::Running);
            if !running {
                continue;
            }
            match self.check_one(stream, now) {
                Paced::Idle => {}
                Paced::Sent => {
                    self.cursor = (stream + 1) % count;
                    return Paced::Sent;
                }
                Paced::Starved => return Paced::Starved,
            }
        }
        Paced::Idle
    }

    fn check_one(&mut self, stream: usize, now: Instant) -> Paced {
        // step 1: the triggered-check queue
        if let Some(id) = self.next_triggered(stream) {
            return self.perform(id, now);
        }

        // step 2: with nothing Waiting, unfreeze a pair of every foundation
        // that has nothing Waiting or In-Progress anywhere in the set
        let waiting = self.pairs.iter().any(|pair| {
            pair.stream == stream && pair.state == PairState::Waiting && self.ready(pair)
        });
        if !waiting {
            let mut unfrozen: Vec<(Foundation, Foundation)> = Vec::new();
            let mut thaw = Vec::new();
            for pair in self
                .pairs
                .iter()
                .filter(|pair| pair.stream == stream && pair.state == PairState::Frozen)
            {
                let Some((local, remote)) = self.foundation_of(pair) else {
                    continue;
                };
                let busy = self.pairs.iter().any(|other| {
                    matches!(other.state, PairState::Waiting | PairState::InProgress)
                        && self.foundation_of(other) == Some((local, remote))
                });
                let key = (local.clone(), remote.clone());
                if !busy && !unfrozen.contains(&key) {
                    unfrozen.push(key);
                    thaw.push(pair.id);
                }
            }
            for id in thaw {
                if let Some(pair) = self.pair_mut(id) {
                    pair.state = PairState::Waiting;
                }
            }
        }

        // step 3: the highest-priority Waiting pair, the lowest component on
        // a tie
        let pick = self
            .pairs
            .iter()
            .filter(|pair| {
                pair.stream == stream && pair.state == PairState::Waiting && self.ready(pair)
            })
            .max_by(|left, right| {
                left.priority
                    .cmp(&right.priority)
                    .then(right.component.cmp(&left.component))
            })
            .map(|pair| pair.id);
        match pick {
            Some(id) => self.perform(id, now),
            None => Paced::Idle,
        }
    }

    /// The first pair in a stream's triggered-check queue that can go now.
    /// Entries whose pair is gone, or no longer wants a check, are dropped;
    /// entries waiting on a relay permission stay where they are.
    fn next_triggered(&mut self, stream: usize) -> Option<u32> {
        let queue: Vec<u32> = self
            .streams
            .get(stream)?
            .triggered
            .iter()
            .copied()
            .collect();
        let mut chosen = None;
        let mut kept = VecDeque::new();
        for id in queue {
            let Some(pair) = self.pair(id) else {
                continue;
            };
            if !(pair.nominate || pair.state == PairState::Waiting) {
                continue;
            }
            if chosen.is_none() && self.ready(pair) {
                chosen = Some(id);
            } else {
                kept.push_back(id);
            }
        }
        if let Some(entry) = self.streams.get_mut(stream) {
            entry.triggered = kept;
        }
        chosen
    }

    /// Whether a check on this pair can be sent: a relayed candidate needs the
    /// relay's permission for the peer first (RFC 8445 §7.2.1).
    fn ready(&self, pair: &Pair) -> bool {
        let Some(local) = self.locals.get(pair.local) else {
            return false;
        };
        let Some(relay) = local.relay else {
            return true;
        };
        let Some(remote) = self.remotes.get(pair.remote) else {
            return false;
        };
        self.relays
            .get(relay)
            .is_some_and(|entry| entry.client.has_permission(remote.candidate.address.ip()))
    }

    /// Send a check on a pair (RFC 8445 §7.2.4).
    fn perform(&mut self, id: u32, now: Instant) -> Paced {
        let Some(pair) = self.pair(id) else {
            return Paced::Idle;
        };
        let (stream, component, via, nominate) =
            (pair.stream, pair.component, pair.local, pair.nominate);
        let Some(destination) = self
            .remotes
            .get(pair.remote)
            .map(|remote| remote.candidate.address)
        else {
            return Paced::Idle;
        };
        let Some(remote) = self
            .streams
            .get(stream)
            .and_then(|entry| entry.remote.clone())
        else {
            return Paced::Idle;
        };
        let Some(local_preference) = self.locals.get(via).map(|local| local.local_preference)
        else {
            return Paced::Idle;
        };
        // "set to the value computed by the algorithm in Section 5.1.2 for
        // the local candidate, but with the candidate type preference of
        // peer-reflexive candidates" (§7.1.1)
        let priority =
            candidate_priority(CandidateType::PeerReflexive, local_preference, component);
        let controlling = self.role == Role::Controlling;
        let use_candidate = nominate && controlling;
        let Some(transaction) = self.take_id() else {
            return Paced::Starved;
        };
        let Some(request) = build_check(
            transaction,
            &remote,
            &self.local.ufrag,
            priority,
            use_candidate,
            controlling,
            self.tiebreaker,
        ) else {
            return Paced::Idle;
        };

        self.cancel_checks_of(id, now);
        let rto = self.check_rto();
        if let Some(pair) = self.pair_mut(id) {
            pair.state = PairState::InProgress;
        }
        self.transmit(via, destination, &request);
        self.checks.push(Check {
            id: transaction,
            purpose: Purpose::Connectivity { pair: id },
            stream,
            component,
            via,
            destination,
            request,
            key: remote.pwd.into_bytes(),
            use_candidate,
            controlling,
            priority,
            sends: 1,
            rto,
            deadline: now.checked_add(rto).unwrap_or(now),
            cancelled: false,
        });
        Paced::Sent
    }

    /// The RTO of a check about to start.
    ///
    /// RFC 8445 §14.3 gives `MAX(500ms, Ta * N * (Num-Waiting +
    /// Num-In-Progress))`, which grows with the square of the checklist and,
    /// at the default pair limit, reaches minutes. This uses RFC 5245's form,
    /// without the N — "Agents MAY calculate the RTO value using other
    /// mechanisms than those described above" — kept above the 500 ms floor
    /// and under a five-second ceiling.
    fn check_rto(&self) -> Duration {
        let active = self
            .pairs
            .iter()
            .filter(|pair| matches!(pair.state, PairState::Waiting | PairState::InProgress))
            .count();
        self.ta
            .checked_mul(u32::try_from(active).unwrap_or(u32::MAX))
            .unwrap_or(MAX_RTO)
            .clamp(MIN_RTO, MAX_RTO)
    }

    /// "Cancellation means that the agent will not retransmit the Binding
    /// requests associated with the connectivity-check transaction, will not
    /// treat the lack of response to be a failure, but will wait the duration
    /// of the transaction timeout for a response" (RFC 8445 §7.3.1.4).
    fn cancel_checks_of(&mut self, pair: u32, now: Instant) {
        for check in &mut self.checks {
            if check.purpose == (Purpose::Connectivity { pair }) && !check.cancelled {
                check.cancelled = true;
                check.deadline = check
                    .rto
                    .checked_mul(RM)
                    .and_then(|wait| now.checked_add(wait))
                    .unwrap_or(now);
            }
        }
        // a peer re-triggering the same pairs over and over could otherwise
        // grow this list without end; the cancelled checks are the ones worth
        // least, and the oldest of them go first
        let limit = self.config.max_pairs.saturating_mul(2).max(16);
        while self.checks.len() > limit {
            let Some(oldest) = self.checks.iter().position(|check| check.cancelled) else {
                break;
            };
            self.checks.remove(oldest);
        }
    }

    /// A response to one of this agent's checks (RFC 8445 §7.2.5).
    pub(super) fn on_response(
        &mut self,
        local: usize,
        from: SocketAddr,
        message: &Message<'_>,
        now: Instant,
    ) {
        let Some(index) = self
            .checks
            .iter()
            .position(|check| check.id == message.transaction_id())
        else {
            return;
        };
        let Some(check) = self.checks.get(index) else {
            return;
        };
        if message.method() != Method::BINDING || message.verify_fingerprint() == Integrity::Invalid
        {
            return;
        }
        let code = message.error_code().map(|error| error.code());
        // "If the value does not match, or if both MESSAGE-INTEGRITY and
        // MESSAGE-INTEGRITY-SHA256 are absent [...] the response MUST be
        // discarded, as if it had never been received" (RFC 8489 §9.1.4),
        // errors included: a 400 or a 401 a peer answers before it knows a
        // key is indistinguishable from one written by anybody who saw the
        // request, and believing it would let them fail the pair. The check
        // retransmits and, if nothing signed ever comes, times out
        if !signed_with(message, &check.key) {
            return;
        }
        let check = self.checks.swap_remove(index);
        // §7.2.5.2.1
        let symmetric = local == check.via && from == check.destination;
        match check.purpose {
            Purpose::Consent { previous } => {
                self.on_consent_response(&check, previous, symmetric, message, code, now);
            }
            Purpose::Connectivity { pair } => {
                if check.cancelled && !(symmetric && message.class() == Class::Success) {
                    return;
                }
                match (symmetric, message.class(), code) {
                    (true, Class::Success, _) => self.check_succeeded(&check, pair, message, now),
                    (true, Class::Error, Some(error_code::ROLE_CONFLICT)) => {
                        self.role_conflict(&check, pair, now);
                    }
                    (true, Class::Error, code) => {
                        let code = code.unwrap_or(0);
                        self.check_failed(&check, pair, PairOutcome::Refused { code }, now);
                    }
                    _ => self.check_failed(&check, pair, PairOutcome::NotSymmetric, now),
                }
            }
        }
    }

    /// §7.2.5.3.
    fn check_succeeded(&mut self, check: &Check, id: u32, message: &Message<'_>, now: Instant) {
        let Some(mapped) = message.xor_mapped_address() else {
            self.check_failed(check, id, PairOutcome::Unusable, now);
            return;
        };
        self.reopen_pair(id);
        let Some(pair) = self.pair(id) else {
            return;
        };
        let (stream, component, remote, nominate_on_success) = (
            pair.stream,
            pair.component,
            pair.remote,
            pair.nominate_on_success,
        );

        // §7.2.5.3.1
        let known = self.locals.iter().position(|local| {
            local.stream == stream
                && local.candidate.component == component
                && local.candidate.address == mapped
        });
        let local = match known {
            Some(index) => index,
            None if self.locals.len() >= self.config.max_pairs.saturating_add(self.bases.len()) => {
                check.via
            }
            None => self
                .add_peer_reflexive(check.via, mapped, check.priority)
                .unwrap_or(check.via),
        };

        // §7.2.5.3.2
        let equal = self.pair_between(stream, local, remote);
        let valid = if let Some(existing) = self.valid.iter().position(|entry| {
            entry.stream == stream
                && entry.component == component
                && entry.local == local
                && entry.remote == remote
        }) {
            if let Some(entry) = self.valid.get_mut(existing) {
                entry.dead = false;
            }
            existing
        } else {
            let priority = if let Some(other) = equal.and_then(|other| self.pair(other)) {
                other.priority
            } else {
                let local_priority = self
                    .locals
                    .get(local)
                    .map_or(0, |entry| entry.candidate.priority);
                let remote_priority = self
                    .remotes
                    .get(remote)
                    .map_or(0, |entry| entry.candidate.priority);
                ordered(self.role, local_priority, remote_priority)
            };
            self.valid.push(Valid {
                stream,
                component,
                local,
                remote,
                via: check.via,
                generating: id,
                priority,
                nominated: false,
                dead: false,
            });
            self.valid.len() - 1
        };

        // §7.2.5.3.3
        for succeeded in [Some(id), equal].into_iter().flatten() {
            if let Some(pair) = self.pair_mut(succeeded) {
                pair.state = PairState::Succeeded;
                pair.valid = Some(valid);
                pair.nominate = false;
                pair.nominate_on_success = false;
            }
        }
        self.unfreeze_foundation(id);
        if let Some(slot) = self
            .streams
            .get_mut(stream)
            .and_then(|entry| entry.components.iter_mut().find(|c| c.id == component))
        {
            slot.first_valid.get_or_insert(now);
        }

        // §7.2.5.3.4
        if check.use_candidate || (self.role == Role::Controlled && nominate_on_success) {
            self.nominate_valid(valid, now);
        }
        self.update_checklist(stream, now);
        self.wake_pacer(now);
    }

    /// §7.2.5.2, and `why` is written down as what became of the pair.
    fn check_failed(&mut self, check: &Check, id: u32, why: PairOutcome, now: Instant) {
        self.settle_pair(id, why);
        let Some(pair) = self.pair_mut(id) else {
            return;
        };
        let nomination = check.use_candidate || pair.nominate_on_success;
        let (stream, component, valid) = (pair.stream, pair.component, pair.valid);
        pair.state = PairState::Failed;
        pair.nominate = false;
        pair.nominate_on_success = false;
        if nomination {
            // "the agent MUST remove the candidate pair from the valid list,
            // set the candidate pair state to Failed, and set the checklist
            // state to Failed" (§7.2.5.3.4)
            if let Some(entry) = valid.and_then(|index| self.valid.get_mut(index)) {
                entry.dead = true;
            }
            if let Some(slot) = self
                .streams
                .get_mut(stream)
                .and_then(|entry| entry.components.iter_mut().find(|c| c.id == component))
            {
                slot.nominating = None;
            }
            self.fail_checklist(stream, now);
        } else {
            self.update_checklist(stream, now);
        }
        self.wake_pacer(now);
    }

    /// §7.2.5.1: a 487 to this agent's own check.
    fn role_conflict(&mut self, check: &Check, id: u32, now: Instant) {
        let other = if check.controlling {
            Role::Controlled
        } else {
            Role::Controlling
        };
        // only if this agent still holds the role the request claimed; a
        // request that crossed with a switch already made changes nothing
        if self.role != other {
            // "The agent MUST change the tiebreaker value"
            let source = self.take_id().unwrap_or(check.id);
            self.tiebreaker = tiebreaker_from(source);
            self.switch_role(other);
        }
        let Some(pair) = self.pair_mut(id) else {
            return;
        };
        pair.state = PairState::Waiting;
        let stream = pair.stream;
        self.enqueue(stream, id);
        self.wake_pacer(now);
    }

    /// §7.3.1.4, for a pair already on the checklist.
    pub(super) fn retrigger(&mut self, id: u32, now: Instant) {
        let Some(pair) = self.pair(id) else {
            return;
        };
        let (state, stream) = (pair.state, pair.stream);
        match state {
            PairState::Succeeded => return,
            PairState::InProgress => self.cancel_checks_of(id, now),
            PairState::Waiting | PairState::Frozen | PairState::Failed => {}
        }
        if let Some(pair) = self.pair_mut(id) {
            pair.state = PairState::Waiting;
        }
        self.reopen_pair(id);
        self.enqueue(stream, id);
        self.wake_pacer(now);
    }

    /// §7.3.1.4, for a pair that is not: "The pair is inserted into the
    /// checklist based on its priority. Its state is set to Waiting. The pair
    /// is enqueued into the triggered-check queue." Unless the checklist set
    /// is already at its limit, which is what the limit is for.
    pub(super) fn insert_triggered(
        &mut self,
        stream: usize,
        component: ComponentId,
        local: usize,
        remote: usize,
        now: Instant,
    ) -> Option<u32> {
        if self.pairs.len() >= self.config.max_pairs {
            return None;
        }
        let priority = ordered(
            self.role,
            self.locals.get(local)?.candidate.priority,
            self.remotes.get(remote)?.candidate.priority,
        );
        let id = self.next_pair;
        self.next_pair = self.next_pair.saturating_add(1);
        self.pairs.push(Pair {
            id,
            stream,
            component,
            local,
            remote,
            priority,
            state: PairState::Waiting,
            nominate: false,
            nominate_on_success: false,
            valid: None,
        });
        self.remember(id);
        self.sort_pairs();
        self.enqueue(stream, id);
        self.wake_pacer(now);
        Some(id)
    }

    /// Set a valid pair's nominated flag, and select it if it is its
    /// component's first nomination or outranks the one before (RFC 8445
    /// §7.2.5.3.4, §7.3.1.5, §8.1.1, §8.1.2).
    pub(super) fn nominate_valid(&mut self, valid: usize, now: Instant) {
        let Some(entry) = self.valid.get(valid) else {
            return;
        };
        // a Failed checklist has concluded for its stream (§7.2.5.4, §8.1.2):
        // a success that arrives afterwards, for a check cancelled when it
        // failed, selects nothing and starts no consent
        let failed = self
            .streams
            .get(entry.stream)
            .is_none_or(|stream| stream.state == ChecklistState::Failed);
        if entry.dead || failed {
            return;
        }
        let Some(entry) = self.valid.get_mut(valid) else {
            return;
        };
        entry.nominated = true;
        let (stream, component, priority) = (entry.stream, entry.component, entry.priority);
        let current = self
            .streams
            .get(stream)
            .and_then(|entry| entry.components.iter().find(|c| c.id == component))
            .map(|slot| slot.selected);
        let Some(current) = current else {
            return;
        };
        let outranks = current
            .and_then(|index| self.valid.get(index))
            .is_none_or(|selected| selected.priority < priority);
        if !outranks {
            return;
        }
        let interval = self.config.consent_interval;
        if let Some(slot) = self
            .streams
            .get_mut(stream)
            .and_then(|entry| entry.components.iter_mut().find(|c| c.id == component))
        {
            slot.nominating = None;
            slot.selected = Some(valid);
            slot.consent = Some(Consent {
                expires: now.checked_add(CONSENT_EXPIRY).unwrap_or(now),
                next: now.checked_add(interval).unwrap_or(now),
                last_sent: now,
                lost: false,
            });
        }
        if current.is_none() {
            self.remove_component_pairs(stream, component, now);
        }
        self.bind_channel(valid, now);
        self.drop_previous(stream, component);

        let Some(entry) = self.streams.get_mut(stream) else {
            return;
        };
        let complete = entry.components.iter().all(|slot| slot.selected.is_some());
        let announce: Vec<ComponentId> = match entry.state {
            ChecklistState::Running if complete => {
                entry.state = ChecklistState::Completed;
                entry.triggered.clear();
                entry.components.iter().map(|slot| slot.id).collect()
            }
            ChecklistState::Completed => vec![component],
            ChecklistState::Running | ChecklistState::Failed => Vec::new(),
        };
        for id in announce {
            let described =
                self.selected_pair(super::StreamId(stream), id)
                    .map(|pair| IceEvent::Selected {
                        stream: super::StreamId(stream),
                        component: id,
                        pair,
                    });
            if let Some(event) = described {
                self.events.push_back(event);
            }
        }
        self.conclude_if_done(now);
    }

    /// §8.1.2: "the ICE agent MUST remove all candidate pairs for the same
    /// component from the checklist and from the triggered-check queue". The
    /// pairs that Succeeded are kept, because a Succeeded pair generates
    /// nothing more (§7.3.1.4) and still says which valid pair a later
    /// request on it refers to.
    fn remove_component_pairs(&mut self, stream: usize, component: ComponentId, now: Instant) {
        let removed: Vec<u32> = self
            .pairs
            .iter()
            .filter(|pair| {
                pair.stream == stream
                    && pair.component == component
                    && pair.state != PairState::Succeeded
            })
            .map(|pair| pair.id)
            .collect();
        for id in &removed {
            self.cancel_checks_of(*id, now);
            self.settle_pair(*id, PairOutcome::NominatedElsewhere);
        }
        self.pairs.retain(|pair| !removed.contains(&pair.id));
        for pair in &mut self.pairs {
            if pair.stream == stream && pair.component == component {
                pair.nominate = false;
                pair.nominate_on_success = false;
            }
        }
        if let Some(entry) = self.streams.get_mut(stream) {
            entry.triggered.retain(|id| !removed.contains(id));
        }
    }

    /// "If the local candidate is a relayed candidate, it is RECOMMENDED that
    /// an agent creates a channel on the TURN server towards the remote
    /// candidate" (RFC 8445 §12.1), once there is a pair to send media on.
    fn bind_channel(&mut self, valid: usize, now: Instant) {
        let Some(entry) = self.valid.get(valid) else {
            return;
        };
        let Some(relay) = self.locals.get(entry.via).and_then(|local| local.relay) else {
            return;
        };
        let Some(peer) = self
            .remotes
            .get(entry.remote)
            .map(|remote| remote.candidate.address)
        else {
            return;
        };
        self.feed_relay(relay);
        if let Some(entry) = self.relays.get_mut(relay) {
            let _number = entry.client.bind_channel(peer, now);
        }
        self.drain_relay(relay, now);
    }

    /// §7.2.5.4: a checklist whose pairs have all finished without a valid
    /// pair for every component has Failed — but not the instant they finish.
    ///
    /// Per RFC 8863, the agent waits [`IceConfig::patience`] from checklist
    /// formation first: a peer behind a NAT may still arrive and form a
    /// peer-reflexive pair (§7.3.1.3). A checklist that never had a pair takes
    /// the same path, so it cannot stay Running with no deadline.
    pub(super) fn update_checklist(&mut self, stream: usize, now: Instant) {
        let Some(entry) = self.streams.get(stream) else {
            return;
        };
        if entry.state != ChecklistState::Running || !entry.formed {
            return;
        }
        if entry.patience_until.is_some_and(|until| now < until) {
            return;
        }
        let finished = self
            .pairs
            .iter()
            .filter(|pair| pair.stream == stream)
            .all(|pair| matches!(pair.state, PairState::Succeeded | PairState::Failed))
            && entry.triggered.is_empty()
            && !self.checks.iter().any(|check| {
                check.stream == stream
                    && !check.cancelled
                    && matches!(check.purpose, Purpose::Connectivity { .. })
            });
        if !finished {
            return;
        }
        let valid_everywhere = entry.components.iter().all(|slot| {
            self.valid
                .iter()
                .any(|valid| valid.stream == stream && valid.component == slot.id && !valid.dead)
        });
        if !valid_everywhere {
            self.fail_checklist(stream, now);
        }
    }

    fn fail_checklist(&mut self, stream: usize, now: Instant) {
        let Some(entry) = self.streams.get_mut(stream) else {
            return;
        };
        if entry.state == ChecklistState::Failed {
            return;
        }
        entry.state = ChecklistState::Failed;
        entry.triggered.clear();
        for slot in &mut entry.components {
            slot.nominating = None;
            slot.consent = None;
        }
        for check in &mut self.checks {
            if check.stream == stream && matches!(check.purpose, Purpose::Connectivity { .. }) {
                check.cancelled = true;
            }
        }
        let unfinished: Vec<u32> = self
            .pairs
            .iter()
            .filter(|pair| {
                pair.stream == stream
                    && matches!(
                        pair.state,
                        PairState::Frozen | PairState::Waiting | PairState::InProgress
                    )
            })
            .map(|pair| pair.id)
            .collect();
        for id in unfinished {
            self.settle_pair(id, PairOutcome::NotChecked);
        }
        self.events.push_back(IceEvent::StreamFailed {
            stream: super::StreamId(stream),
        });
        self.conclude_if_done(now);
    }

    fn conclude_if_done(&mut self, now: Instant) {
        if self.concluded.is_some() || self.streams.is_empty() {
            return;
        }
        let states = || self.streams.iter().map(|entry| entry.state);
        if states().any(|state| state == ChecklistState::Running) {
            return;
        }
        self.concluded = Some(now);
        if states().all(|state| state == ChecklistState::Completed) {
            self.events.push_back(IceEvent::Completed);
        } else if states().all(|state| state == ChecklistState::Failed) {
            self.events.push_back(IceEvent::Failed);
        }
    }

    /// A controlling agent's stopping criterion (RFC 8445 §8.1.1, which
    /// leaves it to the implementation): nominate a component's best valid
    /// pair once no pair of higher priority can still succeed, or once
    /// [`super::IceConfig::nomination_wait`] has passed since its first valid
    /// pair, whichever comes first.
    pub(super) fn consider_nomination(&mut self, now: Instant) {
        if self.role != Role::Controlling || self.phase != Phase::Gathered {
            return;
        }
        for stream in 0..self.streams.len() {
            let Some(entry) = self.streams.get(stream) else {
                continue;
            };
            if entry.state != ChecklistState::Running || !entry.formed {
                continue;
            }
            let waiting: Vec<(ComponentId, Instant)> = entry
                .components
                .iter()
                .filter(|slot| slot.selected.is_none() && slot.nominating.is_none())
                .filter_map(|slot| slot.first_valid.map(|at| (slot.id, at)))
                .collect();
            for (component, first) in waiting {
                let Some(best) = self
                    .valid
                    .iter()
                    .filter(|valid| {
                        valid.stream == stream && valid.component == component && !valid.dead
                    })
                    .max_by_key(|valid| valid.priority)
                else {
                    continue;
                };
                let (priority, generating) = (best.priority, best.generating);
                let higher_pending = self.pairs.iter().any(|pair| {
                    pair.stream == stream
                        && pair.component == component
                        && pair.priority > priority
                        && matches!(
                            pair.state,
                            PairState::Frozen | PairState::Waiting | PairState::InProgress
                        )
                });
                let waited = first
                    .checked_add(self.config.nomination_wait)
                    .is_none_or(|at| at <= now);
                if higher_pending && !waited {
                    continue;
                }
                let Some(pair) = self.pair_mut(generating) else {
                    continue;
                };
                pair.nominate = true;
                if let Some(slot) = self
                    .streams
                    .get_mut(stream)
                    .and_then(|entry| entry.components.iter_mut().find(|c| c.id == component))
                {
                    slot.nominating = Some(generating);
                }
                self.enqueue(stream, generating);
                self.wake_pacer(now);
            }
        }
    }

    /// Retransmissions and timeouts (RFC 8489 §6.2.1, RFC 8445 §7.2.5.2.3).
    pub(super) fn checks_timeout(&mut self, now: Instant) {
        let due: Vec<TransactionId> = self
            .checks
            .iter()
            .filter(|check| check.deadline <= now)
            .map(|check| check.id)
            .collect();
        for id in due {
            let Some(index) = self.checks.iter().position(|check| check.id == id) else {
                continue;
            };
            let Some(check) = self.checks.get_mut(index) else {
                continue;
            };
            let connectivity = matches!(check.purpose, Purpose::Connectivity { .. });
            if connectivity && !check.cancelled && check.sends < RC {
                check.sends += 1;
                let wait = if check.sends < RC {
                    check.rto.checked_mul(1 << (check.sends - 1).min(16))
                } else {
                    check.rto.checked_mul(RM)
                };
                check.deadline = wait.and_then(|wait| now.checked_add(wait)).unwrap_or(now);
                let (via, destination, request) =
                    (check.via, check.destination, check.request.clone());
                self.transmit(via, destination, &request);
                continue;
            }
            let check = self.checks.swap_remove(index);
            if let Purpose::Connectivity { pair } = check.purpose
                && !check.cancelled
            {
                self.check_failed(&check, pair, PairOutcome::TimedOut, now);
            }
        }
        self.patience_timeout(now);
    }

    /// Every checklist whose patience (RFC 8863) has run out, asked once
    /// whether it has anything left to check.
    ///
    /// This is the only caller of [`Self::update_checklist`] that does not
    /// need a check to have been answered first, and it is the whole reason a
    /// checklist with no pairs can now Fail: the other three callers are
    /// reached from a response or a timeout on a check, and a checklist with
    /// no pairs never sent one.
    fn patience_timeout(&mut self, now: Instant) {
        let spent: Vec<usize> = self
            .streams
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.state == ChecklistState::Running && entry.formed)
            .filter(|(_, entry)| entry.patience_until.is_some_and(|until| until <= now))
            .map(|(stream, _)| stream)
            .collect();
        for stream in spent {
            self.update_checklist(stream, now);
        }
    }

    pub(super) fn checks_deadline(&self) -> Option<Instant> {
        let checks = self.checks.iter().map(|check| check.deadline).min();
        let nomination = if self.role == Role::Controlling {
            self.streams
                .iter()
                .filter(|entry| entry.state == ChecklistState::Running)
                .flat_map(|entry| entry.components.iter())
                .filter(|slot| slot.selected.is_none() && slot.nominating.is_none())
                .filter_map(|slot| slot.first_valid)
                .filter_map(|at| at.checked_add(self.config.nomination_wait))
                .min()
        } else {
            None
        };
        // without this term `deadline()` answers `None` for a checklist that
        // has nothing to check, and a caller that sleeps on it sleeps for ever
        let patience = self
            .streams
            .iter()
            .filter(|entry| entry.state == ChecklistState::Running && entry.formed)
            .filter_map(|entry| entry.patience_until)
            .min();
        [checks, nomination, patience].into_iter().flatten().min()
    }

    /// Recompute every priority after a role switch (RFC 8445 §7.2.5.1:
    /// "A role switch requires an agent to recompute pair priorities").
    pub(super) fn reprioritise(&mut self) {
        let role = self.role;
        for pair in &mut self.pairs {
            if let (Some(local), Some(remote)) =
                (self.locals.get(pair.local), self.remotes.get(pair.remote))
            {
                pair.priority = ordered(role, local.candidate.priority, remote.candidate.priority);
            }
        }
        for valid in &mut self.valid {
            if let (Some(local), Some(remote)) =
                (self.locals.get(valid.local), self.remotes.get(valid.remote))
            {
                valid.priority = ordered(role, local.candidate.priority, remote.candidate.priority);
            }
        }
        self.sort_pairs();
    }

    fn sort_pairs(&mut self) {
        self.pairs
            .sort_by_key(|pair| core::cmp::Reverse(pair.priority));
    }

    fn unfreeze_foundation(&mut self, id: u32) {
        let Some(foundation) = self
            .pair(id)
            .and_then(|pair| self.foundation_of(pair))
            .map(|(local, remote)| (local.clone(), remote.clone()))
        else {
            return;
        };
        let thaw: Vec<u32> = self
            .pairs
            .iter()
            .filter(|pair| pair.state == PairState::Frozen)
            .filter(|pair| {
                self.foundation_of(pair).is_some_and(|(local, remote)| {
                    *local == foundation.0 && *remote == foundation.1
                })
            })
            .map(|pair| pair.id)
            .collect();
        for id in thaw {
            if let Some(pair) = self.pair_mut(id) {
                pair.state = PairState::Waiting;
            }
        }
    }

    fn enqueue(&mut self, stream: usize, id: u32) {
        if let Some(entry) = self.streams.get_mut(stream)
            && !entry.triggered.contains(&id)
        {
            entry.triggered.push_back(id);
        }
    }

    fn foundation_of(&self, pair: &Pair) -> Option<(&Foundation, &Foundation)> {
        Some((
            &self.locals.get(pair.local)?.candidate.foundation,
            &self.remotes.get(pair.remote)?.candidate.foundation,
        ))
    }

    /// The host or relayed candidate a local candidate sends from: itself, or
    /// the host candidate that is its base.
    fn base_of(&self, local: usize) -> Option<usize> {
        let entry = self.locals.get(local)?;
        if matches!(
            entry.candidate.kind,
            CandidateType::Host | CandidateType::Relay
        ) {
            return Some(local);
        }
        self.locals.iter().position(|other| {
            other.stream == entry.stream
                && other.candidate.component == entry.candidate.component
                && matches!(
                    other.candidate.kind,
                    CandidateType::Host | CandidateType::Relay
                )
                && other.candidate.address == entry.base
        })
    }

    fn freed(&self, local: usize) -> bool {
        self.locals
            .get(local)
            .and_then(|entry| entry.relay)
            .and_then(|relay| self.relays.get(relay))
            .is_some_and(|entry| entry.progress == super::Progress::Freed)
    }

    pub(super) fn pair(&self, id: u32) -> Option<&Pair> {
        self.pairs.iter().find(|pair| pair.id == id)
    }

    pub(super) fn pair_mut(&mut self, id: u32) -> Option<&mut Pair> {
        self.pairs.iter_mut().find(|pair| pair.id == id)
    }

    pub(super) fn pair_between(&self, stream: usize, local: usize, remote: usize) -> Option<u32> {
        self.pairs
            .iter()
            .find(|pair| pair.stream == stream && pair.local == local && pair.remote == remote)
            .map(|pair| pair.id)
    }
}

/// A pair priority from this agent's point of view: G is the controlling
/// agent's candidate, whichever side that is.
fn ordered(role: Role, local: u32, remote: u32) -> u64 {
    match role {
        Role::Controlling => pair_priority(local, remote),
        Role::Controlled => pair_priority(remote, local),
    }
}

/// A connectivity check (RFC 8445 §7.1, §7.2.2, §7.2.4): the short-term
/// credential, PRIORITY, the role and its tiebreaker, USE-CANDIDATE when
/// nominating, and FINGERPRINT.
pub(super) fn build_check(
    id: TransactionId,
    remote: &Credentials,
    local_ufrag: &str,
    priority: u32,
    use_candidate: bool,
    controlling: bool,
    tiebreaker: u64,
) -> Option<Vec<u8>> {
    let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, id);
    // "The username for the credential is formed by concatenating the
    // username fragment provided by the peer with the username fragment of
    // the ICE agent sending the request, separated by a colon" (§7.2.2)
    let username = format!("{}:{}", remote.ufrag, local_ufrag);
    builder
        .add(AttributeType::USERNAME, username.as_bytes())
        .ok()?;
    builder.add_u32(AttributeType::PRIORITY, priority).ok()?;
    if use_candidate {
        builder.add_flag(AttributeType::USE_CANDIDATE).ok()?;
    }
    let role = if controlling {
        AttributeType::ICE_CONTROLLING
    } else {
        AttributeType::ICE_CONTROLLED
    };
    builder.add_u64(role, tiebreaker).ok()?;
    builder.add_message_integrity(remote.pwd.as_bytes()).ok()?;
    builder.add_fingerprint().ok()?;
    Some(builder.finish())
}

/// Whether a response carries a message-integrity attribute that checks out
/// under the key; absent counts as a failure (RFC 8489 §9.1.4).
pub(super) fn signed_with(message: &Message<'_>, key: &[u8]) -> bool {
    match message.verify_integrity_sha256(key) {
        Integrity::Valid => true,
        Integrity::Invalid => false,
        Integrity::Absent => message.verify_integrity(key) == Integrity::Valid,
    }
}

/// Sixty-four bits out of a transaction id the caller drew from a
/// cryptographic source, for a tiebreaker that has to change.
fn tiebreaker_from(id: TransactionId) -> u64 {
    let bytes = id.as_bytes();
    let mut high = [0_u8; 8];
    for (slot, byte) in high.iter_mut().zip(bytes) {
        *slot = byte;
    }
    u64::from_be_bytes(high)
}
