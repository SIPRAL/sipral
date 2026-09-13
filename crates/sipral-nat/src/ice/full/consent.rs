// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! After selection: which pair data goes on (RFC 8445 §12.1), consent to keep
//! sending on it (RFC 7675), keepalives (RFC 8445 §11), and the selected pair
//! a restart leaves carrying data until the new session selects.
//!
//! A consent check is an ordinary connectivity check — the same credentials,
//! PRIORITY and role attribute — sent once, never retransmitted, every four to
//! six seconds. An authenticated success response from the peer's address
//! renews consent for thirty seconds; nothing for thirty seconds, or an
//! authenticated 403, ends it, and it does not come back under the same
//! credentials. A keepalive, a Binding indication, goes out only when nothing
//! else has been sent on the pair for Tr, which with consent checks running
//! at their default interval never happens; it is there for a configured
//! consent interval longer than Tr.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::checks::build_check;
use super::gather::binding_indication;
use super::{
    CONSENT_EXPIRY, Check, ChecklistState, Consent, Credentials, IceAgent, IceEvent, PreviousRoute,
    Purpose, SendError, StreamId,
};
use crate::ice::agent::Role;
use crate::ice::candidate::{CandidateType, ComponentId, candidate_priority};
use crate::stun::{Class, Message, TransactionId, error_code};

/// "Implementations MUST NOT set the period between checks to less than 4
/// seconds" (RFC 7675 §5.1).
const MIN_CONSENT_GAP: Duration = Duration::from_secs(4);

/// One selected pair under consent: the current session's for a component,
/// or one carried over a restart.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    Current {
        stream: usize,
        component: ComponentId,
    },
    Previous(usize),
}

/// What a consent check on a selected pair needs.
struct Target {
    stream: usize,
    component: ComponentId,
    via: usize,
    destination: SocketAddr,
    local: Credentials,
    remote: Credentials,
    consent: Consent,
}

impl IceAgent {
    /// Where data for a component goes: the selected pair, a pair selected
    /// before a restart, or the best valid pair (RFC 8445 §12.1: "An ICE agent
    /// MAY send data on any valid pair before selected pairs have been
    /// produced").
    pub(super) fn data_route(
        &self,
        stream: usize,
        component: ComponentId,
    ) -> Result<(usize, SocketAddr), SendError> {
        let entry = self.streams.get(stream).ok_or(SendError::UnknownStream)?;
        // "Unless an agent is able to produce a selected pair for each
        // component associated with a data stream, the agent MUST NOT
        // continue sending data for any component associated with that data
        // stream" (RFC 8445 §12.1), which a Failed checklist never will: not
        // on a component selected before another failed, not on a pair kept
        // from before a restart, not on a valid pair
        if entry.state == ChecklistState::Failed {
            return Err(SendError::NoRoute);
        }
        let slot = entry.components.iter().find(|slot| slot.id == component);
        if let Some(slot) = slot
            && let Some(selected) = slot.selected
        {
            if slot.consent.is_some_and(|consent| consent.lost) {
                return Err(SendError::NoConsent);
            }
            let valid = self.valid.get(selected).ok_or(SendError::NoRoute)?;
            let remote = self.remotes.get(valid.remote).ok_or(SendError::NoRoute)?;
            return Ok((valid.via, remote.candidate.address));
        }
        if let Some(route) = self
            .previous
            .iter()
            .find(|route| route.stream == stream && route.component == component)
        {
            if route.consent.lost {
                return Err(SendError::NoConsent);
            }
            return Ok((route.via, route.destination));
        }
        if slot.is_none() {
            return Err(SendError::UnknownStream);
        }
        let best = self
            .valid
            .iter()
            .filter(|valid| valid.stream == stream && valid.component == component && !valid.dead)
            .max_by_key(|valid| valid.priority)
            .ok_or(SendError::NoRoute)?;
        let remote = self.remotes.get(best.remote).ok_or(SendError::NoRoute)?;
        Ok((best.via, remote.candidate.address))
    }

    /// Data went out on a component's pair, which counts as traffic for the
    /// keepalive timer (RFC 8445 §11).
    pub(super) fn note_sent(&mut self, stream: usize, component: ComponentId, now: Instant) {
        if let Some(consent) = self
            .streams
            .get_mut(stream)
            .and_then(|entry| {
                entry
                    .components
                    .iter_mut()
                    .find(|slot| slot.id == component)
            })
            .filter(|slot| slot.selected.is_some())
            .and_then(|slot| slot.consent.as_mut())
        {
            consent.last_sent = now;
            return;
        }
        if let Some(route) = self
            .previous
            .iter_mut()
            .find(|route| route.stream == stream && route.component == component)
        {
            route.consent.last_sent = now;
        }
    }

    /// At a restart, keep every selected pair that still has consent,
    /// together with the credentials it was selected under.
    pub(super) fn keep_previous_routes(&mut self) {
        let mut kept = Vec::new();
        for (index, entry) in self.streams.iter().enumerate() {
            let Some(remote) = entry.remote.clone() else {
                continue;
            };
            for slot in &entry.components {
                let (Some(selected), Some(consent)) = (slot.selected, slot.consent) else {
                    continue;
                };
                if consent.lost {
                    continue;
                }
                let (Some(valid), Some(pair)) = (self.valid.get(selected), self.describe(selected))
                else {
                    continue;
                };
                kept.push(PreviousRoute {
                    stream: index,
                    component: slot.id,
                    via: valid.via,
                    destination: pair.remote,
                    local: self.local.clone(),
                    remote: remote.clone(),
                    consent,
                });
            }
        }
        for route in kept {
            self.previous
                .retain(|old| !(old.stream == route.stream && old.component == route.component));
            self.previous.push(route);
        }
        for check in &mut self.checks {
            if check.purpose == (Purpose::Consent { previous: false }) {
                check.purpose = Purpose::Consent { previous: true };
            }
        }
    }

    /// The new session selected a pair for this component, so the old one
    /// stops carrying data and stops being checked.
    pub(super) fn drop_previous(&mut self, stream: usize, component: ComponentId) {
        self.previous
            .retain(|route| !(route.stream == stream && route.component == component));
    }

    /// Consent expiry, consent checks and keepalives, for every selected pair.
    pub(super) fn consent_timeout(&mut self, now: Instant) {
        let mut owners = Vec::new();
        for (stream, entry) in self.streams.iter().enumerate() {
            for slot in &entry.components {
                if slot.selected.is_some() && slot.consent.is_some_and(|consent| !consent.lost) {
                    owners.push(Owner::Current {
                        stream,
                        component: slot.id,
                    });
                }
            }
        }
        owners.extend(
            self.previous
                .iter()
                .enumerate()
                .filter(|(_, route)| !route.consent.lost)
                .map(|(index, _)| Owner::Previous(index)),
        );
        for owner in owners {
            let Some(target) = self.target(owner) else {
                continue;
            };
            let consent = target.consent;
            if consent.expires <= now {
                // "if a valid STUN binding response has not been received from
                // the remote peer's transport address in 30 seconds, the
                // endpoint MUST cease transmission on that 5-tuple"
                self.lose_consent(owner, target.stream, target.component);
            } else if consent.next <= now {
                self.send_consent(owner, &target, now);
            } else if consent
                .last_sent
                .checked_add(self.config.keepalive)
                .is_some_and(|due| due <= now)
            {
                self.send_keepalive(owner, &target, now);
            }
        }
    }

    pub(super) fn consent_deadline(&self) -> Option<Instant> {
        let keepalive = self.config.keepalive;
        let deadlines = |consent: &Consent| {
            [
                Some(consent.expires),
                Some(consent.next),
                consent.last_sent.checked_add(keepalive),
            ]
        };
        let current = self
            .streams
            .iter()
            .flat_map(|entry| entry.components.iter())
            .filter(|slot| slot.selected.is_some())
            .filter_map(|slot| slot.consent)
            .filter(|consent| !consent.lost)
            .flat_map(|consent| deadlines(&consent));
        let previous = self
            .previous
            .iter()
            .filter(|route| !route.consent.lost)
            .flat_map(|route| deadlines(&route.consent));
        current.chain(previous).flatten().min()
    }

    /// A response to a consent check.
    pub(super) fn on_consent_response(
        &mut self,
        check: &Check,
        previous: bool,
        symmetric: bool,
        message: &Message<'_>,
        code: Option<u16>,
        now: Instant,
    ) {
        // "a matching, authenticated, non-error STUN binding response from the
        // remote peer's transport address" (RFC 7675 §5.1)
        if !symmetric {
            return;
        }
        let owner = if previous {
            match self.previous.iter().position(|route| {
                route.stream == check.stream
                    && route.component == check.component
                    && route.via == check.via
                    && route.destination == check.destination
            }) {
                Some(index) => Owner::Previous(index),
                None => return,
            }
        } else {
            Owner::Current {
                stream: check.stream,
                component: check.component,
            }
        };
        let Some(target) = self.target(owner) else {
            return;
        };
        if target.via != check.via || target.destination != check.destination || target.consent.lost
        {
            // a response for a pair no longer selected, or after expiry,
            // which "do not re-establish consent"
            return;
        }
        match (message.class(), code) {
            (Class::Success, _) => {
                if let Some(consent) = self.consent_mut(owner) {
                    consent.expires = now.checked_add(CONSENT_EXPIRY).unwrap_or(now);
                }
            }
            // "Consent for sending application data is immediately revoked by
            // receipt of ... a valid and authenticated STUN response with error
            // code Forbidden (403)" (RFC 7675 §5.2)
            (Class::Error, Some(error_code::FORBIDDEN)) => {
                self.lose_consent(owner, target.stream, target.component);
            }
            (Class::Error, Some(error_code::ROLE_CONFLICT)) => {
                let other = if check.controlling {
                    Role::Controlled
                } else {
                    Role::Controlling
                };
                if self.role != other {
                    let source = self.take_id().unwrap_or(check.id);
                    self.tiebreaker = tiebreaker_of(source);
                    self.switch_role(other);
                }
            }
            _ => {}
        }
    }

    fn target(&self, owner: Owner) -> Option<Target> {
        match owner {
            Owner::Current { stream, component } => {
                let entry = self.streams.get(stream)?;
                let slot = entry.components.iter().find(|slot| slot.id == component)?;
                let valid = self.valid.get(slot.selected?)?;
                Some(Target {
                    stream,
                    component,
                    via: valid.via,
                    destination: self.remotes.get(valid.remote)?.candidate.address,
                    local: self.local.clone(),
                    remote: entry.remote.clone()?,
                    consent: slot.consent?,
                })
            }
            Owner::Previous(index) => {
                let route = self.previous.get(index)?;
                Some(Target {
                    stream: route.stream,
                    component: route.component,
                    via: route.via,
                    destination: route.destination,
                    local: route.local.clone(),
                    remote: route.remote.clone(),
                    consent: route.consent,
                })
            }
        }
    }

    fn consent_mut(&mut self, owner: Owner) -> Option<&mut Consent> {
        match owner {
            Owner::Current { stream, component } => self
                .streams
                .get_mut(stream)?
                .components
                .iter_mut()
                .find(|slot| slot.id == component)?
                .consent
                .as_mut(),
            Owner::Previous(index) => Some(&mut self.previous.get_mut(index)?.consent),
        }
    }

    fn send_consent(&mut self, owner: Owner, target: &Target, now: Instant) {
        let Some(local_preference) = self
            .locals
            .get(target.via)
            .map(|local| local.local_preference)
        else {
            return;
        };
        let priority = candidate_priority(
            CandidateType::PeerReflexive,
            local_preference,
            target.component,
        );
        // "Each STUN binding request for consent MUST use a new STUN
        // transaction identifier"; without one the check waits for the
        // caller, and the deadline in the past says so
        let Some(id) = self.take_id() else {
            return;
        };
        let controlling = self.role == Role::Controlling;
        let Some(request) = build_check(
            id,
            &target.remote,
            &target.local.ufrag,
            priority,
            false,
            controlling,
            self.tiebreaker,
        ) else {
            return;
        };
        self.transmit(target.via, target.destination, &request);
        self.checks.push(Check {
            id,
            purpose: Purpose::Consent {
                previous: matches!(owner, Owner::Previous(_)),
            },
            stream: target.stream,
            component: target.component,
            via: target.via,
            destination: target.destination,
            // "transmitted once only", so nothing is kept to send again
            request: Vec::new(),
            key: target.remote.pwd.as_bytes().to_vec(),
            use_candidate: false,
            controlling,
            priority,
            sends: 1,
            rto: CONSENT_EXPIRY,
            // "All outstanding STUN consent transactions for a candidate pair
            // MUST be discarded when consent expires", which a transaction
            // older than the expiry has at the latest
            deadline: now.checked_add(CONSENT_EXPIRY).unwrap_or(now),
            cancelled: false,
        });
        let gap = self.consent_gap(id);
        if let Some(consent) = self.consent_mut(owner) {
            consent.next = now.checked_add(gap).unwrap_or(now);
            consent.last_sent = now;
        }
    }

    fn send_keepalive(&mut self, owner: Owner, target: &Target, now: Instant) {
        let Some(id) = self.take_id() else {
            return;
        };
        let Some(indication) = binding_indication(id) else {
            return;
        };
        self.transmit(target.via, target.destination, &indication);
        if let Some(consent) = self.consent_mut(owner) {
            consent.last_sent = now;
        }
    }

    fn lose_consent(&mut self, owner: Owner, stream: usize, component: ComponentId) {
        let previous = matches!(owner, Owner::Previous(_));
        if let Some(consent) = self.consent_mut(owner) {
            consent.lost = true;
        }
        self.checks.retain(|check| {
            !(check.purpose == Purpose::Consent { previous }
                && check.stream == stream
                && check.component == component)
        });
        self.events.push_back(IceEvent::ConsentLost {
            stream: StreamId(stream),
            component,
        });
    }

    /// The gap before the next consent check: "each interval MUST be
    /// randomized from between 0.8 and 1.2 times the basic period", and never
    /// under four seconds (RFC 7675 §5.1). The randomness is the first two
    /// bytes of the transaction id the check just went out under, which the
    /// caller drew from a cryptographic source and nobody could have
    /// predicted before it was sent.
    fn consent_gap(&self, id: TransactionId) -> Duration {
        let bytes = id.as_bytes();
        let draw = u64::from(u16::from_be_bytes([
            bytes.first().copied().unwrap_or(0),
            bytes.get(1).copied().unwrap_or(0),
        ]));
        let factor = 800 + 400 * draw / u64::from(u16::MAX);
        let basic = u64::try_from(self.config.consent_interval.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(basic.saturating_mul(factor) / 1000).max(MIN_CONSENT_GAP)
    }
}

fn tiebreaker_of(id: TransactionId) -> u64 {
    let bytes = id.as_bytes();
    let mut high = [0_u8; 8];
    for (slot, byte) in high.iter_mut().zip(bytes) {
        *slot = byte;
    }
    u64::from_be_bytes(high)
}
