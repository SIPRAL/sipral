// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Answering checks as a full agent (RFC 8445 §7.3 and §7.3.1).
//!
//! The authentication and the role-conflict arithmetic are the lite agent's
//! too and live in [`crate::ice::server`]. What a full agent adds is what it
//! does with a request it accepted: learn the peer-reflexive candidate the
//! request came from, trigger a check back on the same pair, and — when it is
//! controlled — take a USE-CANDIDATE as a nomination.

use std::net::SocketAddr;
use std::time::Instant;

use super::{ChecklistState, Early, IceAgent, MAX_EARLY, Phase, Remote, priority_in_range};
use crate::ice::agent::Role;
use crate::ice::candidate::{Candidate, CandidateType, Foundation};
use crate::ice::checklist::PairState;
use crate::ice::server::{self, Verdict};
use crate::stun::{Message, error_code};

impl IceAgent {
    /// A Binding request that arrived on a local candidate.
    pub(super) fn serve(
        &mut self,
        local: usize,
        from: SocketAddr,
        message: &Message<'_>,
        now: Instant,
    ) {
        // a pair selected before a restart keeps answering under the
        // credentials it was selected with, or the peer's consent checks on
        // it would fail the moment this side restarted (RFC 7675 §5.1)
        let username = message.username().unwrap_or_default();
        let previous = self
            .previous
            .iter()
            .find(|route| server::remote_ufrag(username, route.local.ufrag.as_bytes()).is_some())
            .map(|route| route.local.clone());
        let is_previous = previous.is_some();
        let credentials = previous.unwrap_or_else(|| self.local.clone());
        let key = credentials.pwd.as_bytes();

        let accepted = match server::authenticate(message, credentials.ufrag.as_bytes(), key) {
            Verdict::Ignore => return,
            Verdict::Refuse(reply) => {
                self.transmit_refusal(local, from, &reply);
                return;
            }
            Verdict::Accept(accepted) => accepted,
        };

        // PRIORITY "MUST be included in a Binding request" (RFC 8445 §7.1.1);
        // without it there is no priority for the peer-reflexive candidate
        // the request might reveal, so the request is not accepted (§7.3.1.5
        // names 400 for a request the agent does not accept)
        let Some(priority) = message.priority().filter(|value| priority_in_range(*value)) else {
            if let Some(reply) = server::error_signed(
                message,
                error_code::BAD_REQUEST,
                b"missing priority",
                key,
                accepted.sha256,
            ) {
                self.transmit(local, from, &reply);
            }
            return;
        };

        let mut role = self.role;
        if server::resolve_role(&mut role, self.tiebreaker, message) {
            if let Some(reply) = server::error_signed(
                message,
                error_code::ROLE_CONFLICT,
                b"role conflict",
                key,
                accepted.sha256,
            ) {
                self.transmit(local, from, &reply);
            }
            return;
        }
        self.switch_role(role);

        // a controlled agent that will not follow a nomination through says
        // so, rather than answering with a success it then drops: "If the
        // controlled agent does not accept the request from the controlling
        // agent, the controlled agent MUST reject the nomination request with
        // an appropriate error code response (e.g., 400)" (§7.3.1.5)
        if !is_previous
            && self.role == Role::Controlled
            && message.use_candidate()
            && !self.will_follow(local, from, accepted.remote_ufrag)
        {
            if let Some(reply) = server::error_signed(
                message,
                error_code::BAD_REQUEST,
                b"nomination not accepted",
                key,
                accepted.sha256,
            ) {
                self.transmit(local, from, &reply);
            }
            return;
        }

        // "the source transport address used for STUN processing (namely,
        // generation of the XOR-MAPPED-ADDRESS attribute) is the transport
        // address as seen by the TURN server" for a relayed candidate
        // (§7.3.1.2), which is what `from` already is
        let Some(reply) = server::success(message, from, key, accepted.sha256) else {
            return;
        };
        self.transmit(local, from, &reply);
        if is_previous {
            return;
        }
        let early = Early {
            via: local,
            from,
            priority,
            use_candidate: message.use_candidate(),
            remote_ufrag: accepted.remote_ufrag.to_vec(),
        };
        self.after_accept(early, now);
    }

    /// The steps after the response (§7.3.1.3 to §7.3.1.5), now if the peer's
    /// credentials and this agent's checklist are both in place, later
    /// otherwise: "It is possible (and in fact very likely) that the
    /// initiating agent will receive a Binding request prior to receiving the
    /// candidates from its peer" (§7.3).
    fn after_accept(&mut self, early: Early, now: Instant) {
        let Some(stream) = self.locals.get(early.via).map(|local| local.stream) else {
            return;
        };
        let Some(entry) = self.streams.get(stream) else {
            return;
        };
        let ready = self.phase == Phase::Gathered && entry.formed;
        match &entry.remote {
            Some(remote) if remote.ufrag.as_bytes() != early.remote_ufrag.as_slice() => {
                // signed with this session's password but naming another
                // peer fragment: there is no password to check back with
            }
            Some(_) if ready => self.learn_and_trigger(&early, now),
            _ => {
                if self.early.len() < MAX_EARLY {
                    self.early.push(early);
                }
            }
        }
    }

    /// Whether the steps after the response (§7.3.1.3 to §7.3.1.5) would act
    /// on a request rather than drop it: the peer fragment it names is the
    /// one the stream holds, the stream's checklist has not Failed, the
    /// component it reached is still part of the stream, and there is room —
    /// among the checks waiting for the answer, or else for its source as a
    /// remote candidate and for the pair it forms. These are the conditions
    /// [`Self::after_accept`] and [`Self::learn_and_trigger`] apply.
    fn will_follow(&self, via: usize, from: SocketAddr, remote_ufrag: &[u8]) -> bool {
        let Some(local) = self.locals.get(via) else {
            return false;
        };
        let (stream, component) = (local.stream, local.candidate.component);
        let Some(entry) = self.streams.get(stream) else {
            return false;
        };
        let Some(remote) = &entry.remote else {
            return self.early.len() < MAX_EARLY;
        };
        if remote.ufrag.as_bytes() != remote_ufrag
            || entry.state == ChecklistState::Failed
            || !entry.components.iter().any(|slot| slot.id == component)
        {
            return false;
        }
        if !(self.phase == Phase::Gathered && entry.formed) {
            return self.early.len() < MAX_EARLY;
        }
        let known = self.remote_at(stream, component, from);
        if known.is_none() && self.remote_count(stream) >= self.config.max_remote_candidates {
            return false;
        }
        known
            .and_then(|remote| self.pair_between(stream, via, remote))
            .is_some()
            || self.pairs.len() < self.config.max_pairs
    }

    /// Run the checks that arrived before a stream was ready.
    pub(super) fn replay_early(&mut self, stream: usize, now: Instant) {
        let waiting = core::mem::take(&mut self.early);
        let (mine, others): (Vec<Early>, Vec<Early>) = waiting.into_iter().partition(|early| {
            self.locals
                .get(early.via)
                .is_some_and(|local| local.stream == stream)
        });
        self.early = others;
        for early in mine {
            self.after_accept(early, now);
        }
    }

    fn learn_and_trigger(&mut self, early: &Early, now: Instant) {
        let Some(local) = self.locals.get(early.via) else {
            return;
        };
        let (stream, component) = (local.stream, local.candidate.component);
        let Some(entry) = self.streams.get(stream) else {
            return;
        };
        if entry.state == ChecklistState::Failed {
            return;
        }
        let Some(nominated) = entry
            .components
            .iter()
            .find(|entry| entry.id == component)
            .map(|entry| entry.selected.is_some())
        else {
            return;
        };

        // §7.3.1.3: a source nobody told us about is a peer-reflexive remote
        // candidate, with the component of the candidate it reached
        let remote = if let Some(known) = self.remote_at(stream, component, early.from) {
            known
        } else {
            if self.remote_count(stream) >= self.config.max_remote_candidates {
                return;
            }
            self.learned = self.learned.saturating_add(1);
            self.remotes.push(Remote {
                stream,
                candidate: Candidate {
                    foundation: Foundation::learned(self.learned),
                    component,
                    priority: early.priority,
                    address: early.from,
                    kind: CandidateType::PeerReflexive,
                    related: None,
                },
            });
            self.remotes.len() - 1
        };

        let controlled_nomination = self.role == Role::Controlled && early.use_candidate;
        let existing = self.pair_between(stream, early.via, remote);
        if nominated {
            // the component is done; only a controlling agent written to RFC
            // 5245, nominating again, still gets an answer (§8.1.1: "use the
            // pairs with the highest priority")
            if controlled_nomination
                && let Some(valid) = existing
                    .and_then(|id| self.pair(id))
                    .filter(|pair| pair.state == PairState::Succeeded)
                    .and_then(|pair| pair.valid)
            {
                self.nominate_valid(valid, now);
            }
            return;
        }

        // §7.3.1.4
        let pair = if let Some(id) = existing {
            self.retrigger(id, now);
            id
        } else {
            let Some(id) = self.insert_triggered(stream, component, early.via, remote, now) else {
                return;
            };
            id
        };

        // §7.3.1.5
        if controlled_nomination {
            let Some(entry) = self.pair_mut(pair) else {
                return;
            };
            if let (PairState::Succeeded, Some(valid)) = (entry.state, entry.valid) {
                self.nominate_valid(valid, now);
            } else {
                entry.nominate_on_success = true;
            }
        }
    }

    pub(super) fn remote_at(
        &self,
        stream: usize,
        component: crate::ice::candidate::ComponentId,
        address: SocketAddr,
    ) -> Option<usize> {
        self.remotes.iter().position(|remote| {
            remote.stream == stream
                && remote.candidate.component == component
                && remote.candidate.address == address
        })
    }

    pub(super) fn remote_count(&self, stream: usize) -> usize {
        self.remotes
            .iter()
            .filter(|remote| remote.stream == stream)
            .count()
    }
}
