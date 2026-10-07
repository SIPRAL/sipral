// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What became of every candidate pair and every relay an agent tried.
//!
//! For support: each pair and what happened to it (unanswered, refused,
//! answered from elsewhere, blocked by the relay, or worked but lost).
//! Recorded as it happens, since §8.1.2 removes losing pairs from the
//! checklist at selection.

use std::net::SocketAddr;

use super::{ChecklistState, IceAgent, Progress, StreamId};
use crate::ice::candidate::{CandidateType, ComponentId};
use crate::ice::checklist::PairState;
use crate::turn::TurnError;

/// The most pairs one session remembers the fate of. Twice the default pair
/// limit (RFC 8445 §6.1.2.5), since pairs a peer's checks add (§7.3.1.4)
/// and pairs the limit discards are remembered too; past it the oldest pair
/// whose fate is settled is forgotten first.
const REMEMBERED: usize = 2 * super::DEFAULT_MAX_PAIRS;

/// What became of one candidate pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairOutcome {
    /// Nothing has decided it yet: frozen, waiting its turn, or with its
    /// check on the wire.
    Waiting,
    /// Its check succeeded, and nothing has been selected yet.
    Valid,
    /// The selected pair: the one that carries the media (RFC 8445 §8.1.2).
    Selected,
    /// Its check succeeded, and a pair of higher priority was selected.
    Outranked,
    /// Another pair was nominated before this one could be: its check had
    /// not finished when the selection took it off the checklist (RFC 8445
    /// §8.1.2), or it succeeded with a priority the nomination did not wait
    /// for (§8.1.1 leaves when to stop waiting to the controlling agent).
    NominatedElsewhere,
    /// Its check was never answered (RFC 8489 §6.2.1, RFC 8445 §7.2.5.2.2).
    TimedOut,
    /// The peer answered its check with this STUN error (RFC 8445 §7.2.5.2.4).
    Refused {
        /// The error code.
        code: u16,
    },
    /// The answer came from an address other than the one the check went to,
    /// or reached a socket other than the one it left from (RFC 8445
    /// §7.2.5.2.1).
    NotSymmetric,
    /// The answer was a success that named no address (RFC 8445 §7.2.5.3
    /// needs the XOR-MAPPED-ADDRESS to find the valid pair).
    Unusable,
    /// The relay would not let the peer's address through, and no check on
    /// this relayed pair could be sent (RFC 8656 §9).
    RelayRefused(TurnError),
    /// It was never checked: the pair limit discarded it (RFC 8445
    /// §6.1.2.5), or the checklist ended before its turn came.
    NotChecked,
}

/// What became of one relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Still being allocated.
    Waiting,
    /// Held, and the selected pair does not run through it — or nothing has
    /// been selected yet.
    Held,
    /// The selected pair runs through it.
    Selected,
    /// Given back: ICE concluded on a pair that does not use it (RFC 8445
    /// §8.3.1), or the session let go of it.
    Released,
    /// The server refused the allocation (RFC 8656 §7.3).
    Refused(TurnError),
    /// The allocation was lost after it was made: a refresh the server
    /// refused or never answered (RFC 8656 §8).
    Lost(TurnError),
}

/// One candidate pair, as the checklist formed it, and what became of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairReport {
    /// The stream.
    pub stream: StreamId,
    /// The component.
    pub component: ComponentId,
    /// The local candidate the checks left from: a host candidate, or a
    /// relayed one (a reflexive candidate is paired as its base, §6.1.2.4).
    pub local: SocketAddr,
    /// What kind of candidate that is.
    pub local_kind: CandidateType,
    /// The remote candidate.
    pub remote: SocketAddr,
    /// What kind of candidate that is: peer-reflexive for one learned from
    /// the peer's own check (§7.3.1.3).
    pub remote_kind: CandidateType,
    /// The pair's priority (§6.1.2.3), from this agent's role.
    pub priority: u64,
    /// What became of it.
    pub outcome: PairOutcome,
}

/// One relay the agent held, and what became of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayReport {
    /// The TURN server.
    pub server: SocketAddr,
    /// The relayed address, once there is one.
    pub relayed: Option<SocketAddr>,
    /// What became of it.
    pub outcome: RelayOutcome,
}

/// A pair as it was formed, and how it ended once something ended it.
pub(super) struct Tried {
    pub(super) id: u32,
    stream: usize,
    component: ComponentId,
    local: usize,
    remote: usize,
    priority: u64,
    pub(super) ended: Option<PairOutcome>,
}

impl IceAgent {
    /// Start remembering a pair the checklist just took in.
    pub(super) fn remember(&mut self, id: u32) {
        let Some(pair) = self.pair(id) else {
            return;
        };
        let tried = Tried {
            id,
            stream: pair.stream,
            component: pair.component,
            local: pair.local,
            remote: pair.remote,
            priority: pair.priority,
            ended: None,
        };
        if self.tried.len() >= REMEMBERED {
            let settled = self
                .tried
                .iter()
                .position(|entry| entry.ended.is_some())
                .unwrap_or(0);
            self.tried.remove(settled);
        }
        self.tried.push(tried);
    }

    /// Write down how a pair ended, unless something already has.
    pub(super) fn settle_pair(&mut self, id: u32, outcome: PairOutcome) {
        if let Some(entry) = self.tried.iter_mut().find(|entry| entry.id == id)
            && entry.ended.is_none()
        {
            entry.ended = Some(outcome);
        }
    }

    /// A pair that is being checked again: whatever ended it before is
    /// history (§7.3.1.4 puts a Failed pair back to Waiting).
    pub(super) fn reopen_pair(&mut self, id: u32) {
        if let Some(entry) = self.tried.iter_mut().find(|entry| entry.id == id) {
            entry.ended = None;
        }
    }

    /// Every pair this session's checklists held, with what became of each,
    /// in the order they were formed; a restart (RFC 8445 §9) starts the list
    /// again with the new session.
    #[must_use]
    pub fn pair_report(&self, stream: StreamId) -> Vec<PairReport> {
        self.tried
            .iter()
            .filter(|entry| entry.stream == stream.0)
            .filter_map(|entry| {
                let local = self.locals.get(entry.local)?;
                let remote = self.remotes.get(entry.remote)?;
                let priority = self
                    .pair(entry.id)
                    .map_or(entry.priority, |pair| pair.priority);
                Some(PairReport {
                    stream,
                    component: entry.component,
                    local: local.candidate.address,
                    local_kind: local.candidate.kind,
                    remote: remote.candidate.address,
                    remote_kind: remote.candidate.kind,
                    priority,
                    outcome: self.outcome_of(entry),
                })
            })
            .collect()
    }

    fn outcome_of(&self, entry: &Tried) -> PairOutcome {
        if let Some(ended) = entry.ended {
            return ended;
        }
        let Some(pair) = self.pair(entry.id) else {
            return PairOutcome::NotChecked;
        };
        match pair.state {
            PairState::Frozen | PairState::Waiting | PairState::InProgress => PairOutcome::Waiting,
            PairState::Failed => PairOutcome::NotChecked,
            PairState::Succeeded => {
                let Some(valid) = pair.valid else {
                    return PairOutcome::Valid;
                };
                let selected = self
                    .streams
                    .get(entry.stream)
                    .and_then(|stream| {
                        stream
                            .components
                            .iter()
                            .find(|slot| slot.id == entry.component)
                    })
                    .and_then(|slot| slot.selected);
                match selected {
                    Some(chosen) if chosen == valid => PairOutcome::Selected,
                    Some(chosen) => {
                        let theirs = self.valid.get(chosen).map_or(0, |entry| entry.priority);
                        let ours = self.valid.get(valid).map_or(0, |entry| entry.priority);
                        if ours < theirs {
                            PairOutcome::Outranked
                        } else {
                            PairOutcome::NominatedElsewhere
                        }
                    }
                    None => PairOutcome::Valid,
                }
            }
        }
    }

    /// Every relay this agent held — gathered, handed to it, or shared with
    /// the other branches of a fork — and what became of it.
    #[must_use]
    pub fn relay_report(&self) -> Vec<RelayReport> {
        self.relays
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let relayed = entry
                    .candidate
                    .and_then(|local| self.locals.get(local))
                    .map(|local| local.candidate.address);
                let outcome = match entry.fate {
                    Some(fate) => fate,
                    None if entry.progress == Progress::Freed => RelayOutcome::Released,
                    None if matches!(entry.progress, Progress::Pending | Progress::Running) => {
                        RelayOutcome::Waiting
                    }
                    None if self.carries(index) => RelayOutcome::Selected,
                    None => RelayOutcome::Held,
                };
                RelayReport {
                    server: entry.server,
                    relayed,
                    outcome,
                }
            })
            .collect()
    }

    /// Whether a selected pair sends through this relay.
    fn carries(&self, relay: usize) -> bool {
        let Some(local) = self.relays.get(relay).and_then(|entry| entry.candidate) else {
            return false;
        };
        self.streams.iter().any(|stream| {
            stream.state != ChecklistState::Failed
                && stream.components.iter().any(|slot| {
                    slot.selected
                        .and_then(|valid| self.valid.get(valid))
                        .is_some_and(|valid| valid.via == local)
                })
        })
    }
}
