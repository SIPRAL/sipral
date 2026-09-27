// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Keeping a registration reachable through a NAT, over UDP.
//!
//! A registrar reaches this end at the address its REGISTER came from, and
//! behind a NAT that is a mapping the NAT made for the flow between this
//! socket and the registrar. RFC 4787 §5 lets a NAT filter what comes back
//! into a mapping by the address and port it was sent to — "Address and
//! Port-Dependent Filtering" — and most do: an INVITE the registrar forwards
//! gets in only while the NAT still remembers this end sending to the
//! registrar's own address and port. A STUN request every twenty-five
//! seconds, which is what keeps the signalling socket's *mapping* alive
//! (`sipral::Mappings`), goes to the STUN server and so says nothing for
//! that filter; the REGISTER refresh does, but once an hour, and a NAT
//! forgets a UDP flow in minutes. In the lab a call 330 seconds after the
//! REGISTER was dropped at exactly that filter.
//!
//! So each account that STUN showed to be behind a NAT sends something to
//! its registrar's flow every [`DEFAULT_KEEPALIVE`], which is what RFC 5626
//! §3.5 calls a keep-alive. That RFC names the two ways to write one: a
//! double CRLF for a connection-oriented flow (§3.5.1) and a STUN Binding
//! request for a datagram one (§3.5.2, §4.4.2), the latter so that the pong
//! also tells the client whether its mapping moved. Neither is answered by
//! the registrars this is deployed against on UDP — Asterisk answers no STUN
//! on its SIP port, and no registrar pongs a CRLF on a datagram — so a STUN
//! request here would buy nothing a CRLF does not, and would ask a registrar
//! to parse a protocol it never agreed to. What is sent is the widely
//! deployed double CRLF on its own, as a datagram: RFC 3261 §7.5 has a
//! receiver ignore CRLFs ahead of a start line, a datagram holding nothing
//! else is no message at all, and a registrar drops it — while the NAT on
//! the way out has seen this end send to the registrar's address and port,
//! which is the whole of what the filter asks (RFC 4787 §4.3, REQ-6: a
//! mapping is refreshed by outbound traffic). The mapping itself moving is still caught
//! by the STUN refresh, which does get an answer.
//!
//! **When.** Only for an account whose `Contact` a STUN answer moved
//! ([`UserAgent::readdress`]) onto an address that is not the socket's own
//! — the one fact that says the account is behind a NAT — on a datagram
//! transport, with a registrar, while its registration holds a binding or
//! is getting one. A stream has the endpoint's own CRLF keep-alive (RFC 5626
//! §4.4.1), a trunk has no binding to keep, and an account whose address
//! STUN found to be its own has no NAT to keep open.
//!
//! **How often.** Every [`DEFAULT_KEEPALIVE`] unless set otherwise
//! ([`UserAgent::keep_registrar_flows_alive`]), each interval drawn between
//! 80% and 100% of that — the spread RFC 5626 §4.4 asks for around a
//! server's own figure — so that a registrar does not hear every client in
//! the same instant. Twenty-five
//! seconds sits inside RFC 5626 §4.4.2's "random number between 24 and 29
//! seconds" for UDP, chosen there because "many NATs have UDP timeouts as low
//! as 30 seconds" — which RFC 4787 REQ-5 forbids and which is deployed all
//! the same. Longer than [`MAX_KEEPALIVE`] is refused: REQ-5's two minutes
//! is the shortest a conforming NAT may forget a flow in, so a longer
//! interval keeps nothing open that the REGISTER refresh would not.
//!
//! **Not while suspended.** A process the operating system is about to stop
//! has nothing scheduled ([`UserAgent::suspending`]), and a phone that
//! sleeps is woken by a push (RFC 8599), not by holding a NAT open from a
//! process that is not running. They start again with the REGISTER that
//! proves the binding again after [`UserAgent::resumed`], and stop while
//! there is no interface or the recovery gave up.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Transmit, TransportProtocol};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::error::UaError;
use crate::event::RegistrationState;
use crate::lifecycle::LifecycleState;
use crate::registration::spread;

/// How often an account behind a NAT sends to its registrar, unless told
/// otherwise: RFC 5626 §4.4.2's UDP interval, and the one the signalling
/// socket's STUN refresh and the endpoint's stream keep-alive use.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(25);

/// The longest interval [`UserAgent::keep_registrar_flows_alive`] takes:
/// RFC 4787 §4.3, REQ-5, "A NAT UDP mapping timer MUST NOT expire in less
/// than two minutes".
pub const MAX_KEEPALIVE: Duration = Duration::from_secs(120);

/// The shortest it takes. Anything under a second is a registrar flooded
/// for no NAT that exists.
pub const MIN_KEEPALIVE: Duration = Duration::from_secs(1);

/// What goes out: a double CRLF, RFC 5626 §3.5.1's ping, alone in a datagram.
const PING: &[u8] = b"\r\n\r\n";

/// What this agent keeps about keeping registrars' flows open.
#[derive(Debug)]
pub(crate) struct Keepalives {
    /// The interval, or `None` for none at all.
    every: Option<Duration>,
    /// The accounts a STUN answer showed to be behind a NAT.
    behind: HashSet<AccountId>,
    /// When each account that is being kept alive sends next.
    due: HashMap<AccountId, Instant>,
    /// Pings on their way out through [`UserAgent::poll_transmit`].
    out: VecDeque<Transmit>,
}

impl Default for Keepalives {
    fn default() -> Self {
        Self {
            every: Some(DEFAULT_KEEPALIVE),
            behind: HashSet::new(),
            due: HashMap::new(),
            out: VecDeque::new(),
        }
    }
}

impl UserAgent {
    /// How often each account behind a NAT sends to its registrar over UDP,
    /// or `None` to send nothing (see [`crate::keepalive`]). On, every
    /// [`DEFAULT_KEEPALIVE`], unless said otherwise.
    ///
    /// What was already scheduled is drawn again from the new interval.
    ///
    /// # Errors
    /// [`UaError::InvalidKeepalive`] for an interval under [`MIN_KEEPALIVE`]
    /// or over [`MAX_KEEPALIVE`]; nothing changes.
    pub fn keep_registrar_flows_alive(
        &mut self,
        every: Option<Duration>,
        now: Instant,
    ) -> Result<(), UaError> {
        if let Some(interval) = every
            && !(MIN_KEEPALIVE..=MAX_KEEPALIVE).contains(&interval)
        {
            return Err(UaError::InvalidKeepalive(interval));
        }
        self.keepalives.every = every;
        self.keepalives.due.clear();
        self.settle_keepalives(now);
        Ok(())
    }

    /// The interval [`UserAgent::keep_registrar_flows_alive`] set, or `None`
    /// when it is off.
    #[must_use]
    pub const fn registrar_keepalive(&self) -> Option<Duration> {
        self.keepalives.every
    }

    /// Whether this account's registrar flow is being kept open right now:
    /// it is behind a NAT, on UDP, holding a binding or getting one, and the
    /// stack is not suspended.
    #[must_use]
    pub fn keeping_registrar_flow_alive(&self, account: AccountId) -> bool {
        self.keepalives.due.contains_key(&account)
    }

    /// Whether a STUN answer said this account is behind a NAT, from what
    /// [`UserAgent::readdress`] was told.
    pub(crate) fn note_nat(&mut self, account: AccountId, behind: bool) {
        if behind {
            self.keepalives.behind.insert(account);
        } else {
            self.keepalives.behind.remove(&account);
        }
    }

    /// The account is gone, and nothing is kept for it.
    pub(crate) fn forget_keepalive(&mut self, account: AccountId) {
        self.keepalives.behind.remove(&account);
        self.keepalives.due.remove(&account);
    }

    /// The next ping on its way out.
    pub(crate) fn poll_keepalive(&mut self) -> Option<Transmit> {
        self.keepalives.out.pop_front()
    }

    /// When the next one is due.
    pub(crate) fn keepalive_deadline(&self) -> Option<Instant> {
        self.keepalives.due.values().min().copied()
    }

    /// Send every ping that is due, and draw the next.
    pub(crate) fn fire_keepalives(&mut self, now: Instant) {
        let Some(every) = self.keepalives.every else {
            return;
        };
        let due: Vec<AccountId> = self
            .keepalives
            .due
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(account, _)| *account)
            .collect();
        for account in due {
            let Some(config) = self.accounts.get(&account) else {
                self.keepalives.due.remove(&account);
                continue;
            };
            self.keepalives.out.push_back(Transmit {
                transport: config.transport,
                destination: config.remote,
                source: None,
                payload: Arc::from(PING),
                protocol: TransportProtocol::Udp,
            });
            let next = now + self.jittered(every);
            self.keepalives.due.insert(account, next);
        }
    }

    /// Start keeping alive what now qualifies, and stop what no longer does.
    /// Run at the end of every round of work, so that a registration won or
    /// lost, a suspend or a wake, an account added or moved is followed at
    /// once.
    pub(crate) fn settle_keepalives(&mut self, now: Instant) {
        let Some(every) = self.keepalives.every else {
            self.keepalives.due.clear();
            return;
        };
        let accounts: Vec<AccountId> = self.accounts.keys().copied().collect();
        for account in accounts {
            let wanted = self.qualifies(account);
            let scheduled = self.keepalives.due.contains_key(&account);
            if wanted && !scheduled {
                let first = now + self.jittered(every);
                self.keepalives.due.insert(account, first);
            } else if !wanted && scheduled {
                self.keepalives.due.remove(&account);
            }
        }
    }

    /// Whether this account's registrar flow is one to keep open.
    fn qualifies(&self, account: AccountId) -> bool {
        if !matches!(
            self.lifecycle(),
            LifecycleState::Running | LifecycleState::Recovering | LifecycleState::ResolutionLost
        ) {
            return false;
        }
        if !self.keepalives.behind.contains(&account) {
            return false;
        }
        let Some(config) = self.accounts.get(&account) else {
            return false;
        };
        if config.registrar.is_none() {
            return false;
        }
        let datagram = self
            .endpoint
            .bound_transport(config.transport)
            .is_some_and(|(protocol, _)| protocol == TransportProtocol::Udp);
        if !datagram {
            return false;
        }
        self.registrations.get(&account).is_some_and(|reg| {
            !reg.unregistering
                && matches!(
                    reg.state,
                    RegistrationState::Registering
                        | RegistrationState::Registered
                        | RegistrationState::Refreshing
                        | RegistrationState::Retrying
                        | RegistrationState::Restored
                )
        })
    }

    /// RFC 5626 §4.4: "randomly distributed between 80% and 100%" of the
    /// interval.
    fn jittered(&mut self, every: Duration) -> Duration {
        let percent = 80 + spread(&self.endpoint.token()) % 21;
        every * percent / 100
    }
}
