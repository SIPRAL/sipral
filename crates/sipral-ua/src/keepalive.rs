// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Keeping a registration reachable through a NAT, over UDP.
//!
//! Most NATs filter inbound traffic by the address and port it was sent to
//! (RFC 4787 §5, "Address and Port-Dependent Filtering"). The STUN refresh
//! goes to the STUN server, so it does not keep the registrar's flow open,
//! and the hourly REGISTER refresh is too rare: in the lab a call 330 s after
//! the REGISTER was dropped at that filter.
//!
//! So each account behind a NAT sends a keep-alive (RFC 5626 §3.5) to its
//! registrar every [`DEFAULT_KEEPALIVE`](crate::keepalive::DEFAULT_KEEPALIVE).
//! It is a bare double CRLF datagram, not a STUN request: deployed registrars
//! answer neither on UDP (Asterisk answers no STUN on its SIP port), and a
//! receiver ignores CRLFs before a start line (RFC 3261 §7.5). Outbound
//! traffic is all the NAT needs (RFC 4787 §4.3, REQ-6). A moved mapping is
//! still caught by the STUN refresh.
//!
//! **When.** For an account whose `Contact` a STUN answer moved
//! ([`UserAgent::readdress`]) to an address that is not the socket's own, on
//! a datagram transport, with a registrar, while it holds or is getting a
//! binding. A stream has the endpoint's own CRLF keep-alive (RFC 5626
//! §4.4.1); a trunk has no binding to keep.
//!
//! **Or when the application says so.** An account with its own interval
//! ([`Account::keepalive`](crate::Account::keepalive)) is kept open whatever
//! STUN found, or with no STUN at all, on any transport: a datagram flow gets
//! the CRLF from this agent, a stream is pinged by the endpoint at that
//! interval. With no registrar it is kept open toward its outbound proxy
//! while the agent runs.
//!
//! **How often.** Each interval is drawn between 80% and 100% of the setting
//! (RFC 5626 §4.4), so clients do not all fire at once. 25 s sits inside RFC
//! 5626 §4.4.2's 24 to 29 s, chosen because many NATs time UDP out at 30 s.
//! Over [`MAX_KEEPALIVE`](crate::keepalive::MAX_KEEPALIVE) is refused: RFC
//! 4787 REQ-5's two minutes is the shortest a conforming NAT may forget a
//! flow in.
//!
//! **Not while suspended** ([`UserAgent::suspending`]): a sleeping phone is
//! woken by a push (RFC 8599). Pings start again with the REGISTER after
//! [`UserAgent::resumed`], and stop while there is no interface or recovery
//! gave up.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Transmit, TransportId, TransportProtocol};

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

/// The shortest it takes.
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
    /// When each account kept alive over a datagram transport sends next,
    /// and at what interval.
    due: HashMap<AccountId, (Instant, Duration)>,
    /// The stream transports this agent asked the endpoint to ping at an
    /// account's own interval, and that interval.
    streams: HashMap<TransportId, Duration>,
    /// The accounts whose stream is being pinged for them.
    streamed: HashSet<AccountId>,
    /// Pings on their way out through [`UserAgent::poll_transmit`].
    out: VecDeque<Transmit>,
}

impl Default for Keepalives {
    fn default() -> Self {
        Self {
            every: Some(DEFAULT_KEEPALIVE),
            behind: HashSet::new(),
            due: HashMap::new(),
            streams: HashMap::new(),
            streamed: HashSet::new(),
            out: VecDeque::new(),
        }
    }
}

impl UserAgent {
    /// How often each account behind a NAT sends to its registrar over UDP,
    /// or `None` to send nothing (see [`crate::keepalive`]). On, every
    /// [`DEFAULT_KEEPALIVE`], unless said otherwise.
    ///
    /// What was already scheduled is drawn again from the new interval. An
    /// account with an interval of its own ([`Account::keepalive`]) keeps
    /// it, whatever this says.
    ///
    /// # Errors
    /// [`UaError::InvalidKeepalive`] for an interval under [`MIN_KEEPALIVE`]
    /// or over [`MAX_KEEPALIVE`]; nothing changes.
    ///
    /// [`Account::keepalive`]: crate::Account::keepalive
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
    /// it is behind a NAT, on UDP, or has an interval of its own
    /// ([`Account::keepalive`]) on any transport; it holds a binding or is
    /// getting one; and the stack is not suspended.
    ///
    /// [`Account::keepalive`]: crate::Account::keepalive
    #[must_use]
    pub fn keeping_registrar_flow_alive(&self, account: AccountId) -> bool {
        self.keepalives.due.contains_key(&account) || self.keepalives.streamed.contains(&account)
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

    /// The account is gone. Its stream returns to the endpoint's own
    /// interval at the next settle.
    pub(crate) fn forget_keepalive(&mut self, account: AccountId) {
        self.keepalives.behind.remove(&account);
        self.keepalives.due.remove(&account);
        self.keepalives.streamed.remove(&account);
    }

    /// The next ping on its way out.
    pub(crate) fn poll_keepalive(&mut self) -> Option<Transmit> {
        self.keepalives.out.pop_front()
    }

    /// When the next one is due.
    pub(crate) fn keepalive_deadline(&self) -> Option<Instant> {
        self.keepalives.due.values().map(|(at, _)| *at).min()
    }

    /// Send every ping that is due, and draw the next.
    pub(crate) fn fire_keepalives(&mut self, now: Instant) {
        let due: Vec<(AccountId, Duration)> = self
            .keepalives
            .due
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .map(|(account, (_, every))| (*account, *every))
            .collect();
        for (account, every) in due {
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
            self.keepalives.due.insert(account, (next, every));
        }
    }

    /// Start keeping alive what now qualifies, and stop what no longer does.
    /// Runs at the end of every round of work.
    ///
    /// A datagram flow is pinged here; a stream is pinged by the endpoint at
    /// the shortest interval any account on it wants, and handed back to its
    /// own interval when none does.
    pub(crate) fn settle_keepalives(&mut self, now: Instant) {
        let accounts: Vec<AccountId> = self.accounts.keys().copied().collect();
        let mut streams: HashMap<TransportId, Duration> = HashMap::new();
        let mut streamed = HashSet::new();
        for account in accounts {
            let wanted = self.wanted_keepalive(account);
            let protocol = self.accounts.get(&account).and_then(|config| {
                self.endpoint
                    .bound_transport(config.transport)
                    .map(|(protocol, _)| (config.transport, protocol))
            });
            match (wanted, protocol) {
                (Some(every), Some((_, TransportProtocol::Udp))) => {
                    let scheduled = self
                        .keepalives
                        .due
                        .get(&account)
                        .map(|(_, interval)| *interval);
                    if scheduled != Some(every) {
                        let first = now + self.jittered(every);
                        self.keepalives.due.insert(account, (first, every));
                    }
                }
                (Some(every), Some((transport, protocol))) if protocol.is_stream() => {
                    self.keepalives.due.remove(&account);
                    streams
                        .entry(transport)
                        .and_modify(|shortest| *shortest = (*shortest).min(every))
                        .or_insert(every);
                    streamed.insert(account);
                }
                _ => {
                    self.keepalives.due.remove(&account);
                }
            }
        }
        let released: Vec<TransportId> = self
            .keepalives
            .streams
            .keys()
            .filter(|transport| !streams.contains_key(transport))
            .copied()
            .collect();
        for transport in released {
            // `None` is always taken
            let _ = self.endpoint.keep_stream_alive(transport, None, now);
        }
        for (transport, every) in &streams {
            if self.keepalives.streams.get(transport) != Some(every) {
                // never zero: an account's interval is at least MIN_KEEPALIVE
                let _ = self
                    .endpoint
                    .keep_stream_alive(*transport, Some(*every), now);
            }
        }
        self.keepalives.streams = streams;
        self.keepalives.streamed = streamed;
    }

    /// The interval this account's flow is to be kept open at right now, or
    /// `None` when it is not one to keep open.
    ///
    /// An account with its own interval ([`Account::keepalive`]) is kept
    /// open on any transport while it registers, or always with no
    /// registrar. Any other only when behind a NAT, over UDP, while it
    /// registers.
    ///
    /// [`Account::keepalive`]: crate::Account::keepalive
    fn wanted_keepalive(&self, account: AccountId) -> Option<Duration> {
        if !matches!(
            self.lifecycle(),
            LifecycleState::Running | LifecycleState::Recovering | LifecycleState::ResolutionLost
        ) {
            return None;
        }
        let config = self
            .accounts
            .get(&account)
            .filter(|config| config.located)?;
        let every = if let Some(own) = config.keepalive {
            own
        } else {
            let datagram = self
                .endpoint
                .bound_transport(config.transport)
                .is_some_and(|(protocol, _)| protocol == TransportProtocol::Udp);
            if !datagram || !self.keepalives.behind.contains(&account) {
                return None;
            }
            self.keepalives.every?
        };
        if config.registrar.is_none() {
            return config.keepalive.map(|_| every);
        }
        let registering = self.registrations.get(&account).is_some_and(|reg| {
            !reg.unregistering
                && matches!(
                    reg.state,
                    RegistrationState::Registering
                        | RegistrationState::Registered
                        | RegistrationState::Refreshing
                        | RegistrationState::Retrying
                        | RegistrationState::Restored
                )
        });
        registering.then_some(every)
    }

    /// RFC 5626 §4.4: "randomly distributed between 80% and 100%" of the
    /// interval.
    fn jittered(&mut self, every: Duration) -> Duration {
        let percent = 80 + spread(&self.endpoint.token()) % 21;
        every * percent / 100
    }
}
