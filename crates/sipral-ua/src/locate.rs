// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Keeping an account's server located by name (RFC 3263).
//!
//! An account made with [`Account::located`](crate::Account::located) or
//! [`Account::unregistered_located`](crate::Account::unregistered_located)
//! names its registrar or its outbound proxy by a URI rather than an address,
//! and this module keeps an address for it. The procedure is
//! [`Locator`]'s; the lookups are the application's resolver's, asked for
//! with [`UaEvent::LookupWanted`] and answered with [`UserAgent::looked_up`],
//! the same division as the endpoint's own [`Event::ResolveNeeded`] for a
//! dialog: the core decides what to ask and what the answers mean, and never
//! does I/O.
//!
//! **When a lookup runs.** For an account that registers, when a REGISTER is
//! to go and there is no address — the first one, and the one after every
//! address found has failed — and the REGISTER waits for the answer. For a
//! trunk, from the first round of work after it was added. And for either,
//! again once the shortest time-to-live of the last answer has run out, while
//! the address it gave stays in use: a PBX that moves is followed as soon as
//! its DNS says so, without a restart and without a failed request first.
//!
//! **Failing over.** RFC 3263 §4.3 keeps every address the answer named, in
//! order, and "if the transport in the first server proved to be unusable,
//! then the client SHOULD retry the request ... [with] a different server".
//! A REGISTER that times out, or whose transport fails, is sent again at once
//! to the next address; RFC 3261 §10.2.7's "SHOULD NOT immediately re-attempt
//! a registration to the same registrar" is about the one that failed. Once
//! every address has failed, the account backs off as it always does
//! (RFC 5626 §4.5), and the attempt after the wait looks the name up again.
//! A final response from the registrar — a 404, a 503 — is an answer from the
//! right server and moves nothing.
//!
//! **A time-to-live.** Honoured, but with a floor of [`MIN_TTL`] so that a
//! zone publishing zero does not turn an account into a stream of lookups,
//! and a ceiling of [`MAX_TTL`] so that a PBX that moved is found within a
//! day whatever its zone claimed. A lookup that fails while an older answer
//! is held keeps the older answer — an address the DNS last named is a better
//! guess than none — and tries again after the account's back-off.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{AddressFamily, Answer, LocateError, Located, Locator, Query};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::error::UaError;
use crate::event::{RegistrationState, UaEvent};
use crate::registration::{backoff_delay, spread};

/// The shortest a located address is held before the name is looked up again,
/// whatever the DNS said.
pub const MIN_TTL: Duration = Duration::from_secs(60);

/// The longest.
pub const MAX_TTL: Duration = Duration::from_hours(24);

/// What is kept for one located account.
#[derive(Debug, Default)]
struct Location {
    /// The lookup running, if one is.
    lookup: Option<Locator>,
    /// Every address the last answer named, in §4.3's order.
    targets: Vec<SocketAddr>,
    /// Which of them requests go to now.
    at: usize,
    /// When to look the name up again: the answer's time-to-live, or the end
    /// of a back-off after a lookup that failed.
    again: Option<Instant>,
    /// A REGISTER waiting for an answer, and whether it takes the binding
    /// away.
    waiting: Option<bool>,
    /// Lookups that failed in a row.
    failures: u32,
}

/// Every located account's location.
#[derive(Debug, Default)]
pub(crate) struct Locations {
    held: HashMap<AccountId, Location>,
}

impl UserAgent {
    /// The resolver's answer to a [`UaEvent::LookupWanted`] for `account`.
    ///
    /// Every query handed out is waited for, so answer each one, with
    /// [`Answer::Failed`] when the resolver failed and [`Answer::Nothing`]
    /// when the name has no such record — which is also the answer from a
    /// resolver that cannot ask for NAPTR or SRV, and then the host's own
    /// addresses are used. An answer to a query no lookup is waiting for any
    /// more changes nothing.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`]; anything a REGISTER the answer releases
    /// runs into is reported as that REGISTER's failure, not here.
    pub fn looked_up(
        &mut self,
        account: AccountId,
        query: &Query,
        answer: Answer,
        now: Instant,
    ) -> Result<(), UaError> {
        if !self.accounts.contains_key(&account) {
            return Err(UaError::NoSuchAccount);
        }
        let Some(location) = self.locations.held.get_mut(&account) else {
            return Ok(());
        };
        let Some(lookup) = location.lookup.as_mut() else {
            return Ok(());
        };
        if !lookup.answer(query, answer) {
            return Ok(());
        }
        self.pump_lookup(account, now);
        self.drain(now);
        Ok(())
    }

    /// Every address the last lookup for `account` named, first the one its
    /// requests go to now; empty for an account made with an address, or one
    /// not located yet.
    #[must_use]
    pub fn located_targets(&self, account: AccountId) -> Vec<SocketAddr> {
        self.locations
            .held
            .get(&account)
            .map(|location| {
                let mut targets = location.targets.clone();
                if location.at < targets.len() {
                    targets.rotate_left(location.at);
                }
                targets
            })
            .unwrap_or_default()
    }

    /// Whether a REGISTER for `account` has to wait for a lookup first: a
    /// located account with no address in hand. Starts the lookup when none
    /// is running, and remembers the REGISTER.
    pub(crate) fn register_waits_for_location(
        &mut self,
        account: AccountId,
        unregistering: bool,
        now: Instant,
    ) -> bool {
        let Some(config) = self.accounts.get(&account) else {
            return false;
        };
        // an unbound transport has no family to look up for, and the
        // REGISTER goes on to be refused for it the way any other is
        if config.server.is_none() || self.endpoint.bound_transport(config.transport).is_none() {
            return false;
        }
        let location = self.locations.held.entry(account).or_default();
        if location.at < location.targets.len() {
            return false;
        }
        location.waiting = Some(unregistering);
        if location.lookup.is_none() {
            self.start_lookup(account, now);
        }
        // either it waits, or a lookup that settled at once — a numeric host
        // — has already sent it; both are this function's to have handled
        true
    }

    /// A REGISTER for `account` timed out or lost its transport. Move it to
    /// the next address the last answer named and send it there, and say
    /// whether that happened; when there is none, forget the answer so that
    /// the next attempt looks the name up again.
    pub(crate) fn fail_over_registration(&mut self, account: AccountId, now: Instant) -> bool {
        let Some(location) = self.locations.held.get_mut(&account) else {
            return false;
        };
        let next = location.at + 1;
        let Some(address) = location.targets.get(next).copied() else {
            location.targets.clear();
            location.at = 0;
            return false;
        };
        location.at = next;
        let unregistering = self
            .registrations
            .get(&account)
            .is_some_and(|reg| reg.unregistering);
        if let Some(config) = self.accounts.get_mut(&account) {
            config.remote = address;
        }
        self.send_register(account, unregistering, now).is_ok()
    }

    /// The account is gone, and nothing is looked up for it.
    pub(crate) fn forget_location(&mut self, account: AccountId) {
        self.locations.held.remove(&account);
    }

    /// When a located address is next due to be looked up again.
    pub(crate) fn location_deadline(&self) -> Option<Instant> {
        self.locations
            .held
            .values()
            .filter(|location| location.lookup.is_none())
            .filter_map(|location| location.again)
            .min()
    }

    /// Look again whatever has come due, keeping the address in hand while
    /// the lookup runs.
    pub(crate) fn fire_locations(&mut self, now: Instant) {
        let due: Vec<AccountId> = self
            .locations
            .held
            .iter()
            .filter(|(_, location)| {
                location.lookup.is_none() && location.again.is_some_and(|at| at <= now)
            })
            .map(|(account, _)| *account)
            .collect();
        for account in due {
            if let Some(location) = self.locations.held.get_mut(&account) {
                location.again = None;
            }
            self.start_lookup(account, now);
        }
    }

    /// Start the first lookup of every located trunk that has none, once its
    /// transport is bound. Run at the end of every round of work.
    pub(crate) fn settle_locations(&mut self, now: Instant) {
        let trunks: Vec<AccountId> = self
            .accounts
            .iter()
            .filter(|(_, config)| {
                config.server.is_some() && config.registrar.is_none() && !config.located
            })
            .map(|(account, _)| *account)
            .collect();
        for account in trunks {
            let idle = self
                .locations
                .held
                .get(&account)
                .is_none_or(|location| location.lookup.is_none() && location.again.is_none());
            if idle {
                self.start_lookup(account, now);
            }
        }
    }

    /// Start a lookup of `account`'s server, over the family and for the
    /// protocol of the transport it is bound to. An unbound transport leaves
    /// nothing started: there is no family to ask for yet.
    fn start_lookup(&mut self, account: AccountId, now: Instant) {
        let Some(config) = self.accounts.get(&account) else {
            return;
        };
        let Some(server) = config.server.clone() else {
            return;
        };
        let naptr = config.naptr;
        let Some((protocol, local)) = self.endpoint.bound_transport(config.transport) else {
            return;
        };
        let seed = u64::from(spread(&self.endpoint.token())) << 32
            | u64::from(spread(&self.endpoint.token()));
        let locator = Locator::new(
            &server,
            protocol,
            AddressFamily::of(local.ip()),
            naptr,
            seed,
        );
        self.locations.held.entry(account).or_default().lookup = Some(locator);
        self.pump_lookup(account, now);
    }

    /// Hand out the queries the lookup has made, and apply its outcome once
    /// it has one.
    fn pump_lookup(&mut self, account: AccountId, now: Instant) {
        let Some(location) = self.locations.held.get_mut(&account) else {
            return;
        };
        let Some(lookup) = location.lookup.as_mut() else {
            return;
        };
        while let Some(query) = lookup.poll_query() {
            self.events
                .push_back(UaEvent::LookupWanted { account, query });
        }
        let Some(outcome) = lookup.take_outcome() else {
            return;
        };
        location.lookup = None;
        match outcome {
            Ok(located) => self.on_located(account, located, now),
            Err(reason) => self.on_locate_failed(account, reason, now),
        }
    }

    fn on_located(&mut self, account: AccountId, located: Located, now: Instant) {
        let Some(location) = self.locations.held.get_mut(&account) else {
            return;
        };
        let Some(config) = self.accounts.get_mut(&account) else {
            return;
        };
        location.failures = 0;
        location.again = located.ttl.map(|ttl| now + ttl.clamp(MIN_TTL, MAX_TTL));
        // a refresh that still names the address in use keeps it: moving a
        // working registration to an equal peer for no reason is a REGISTER
        // and a new flow through the NAT for nothing
        let kept = config
            .located
            .then(|| {
                located
                    .targets
                    .iter()
                    .position(|target| *target == config.remote)
            })
            .flatten();
        let moved = kept.is_none();
        location.at = kept.unwrap_or(0);
        location.targets = located.targets;
        let Some(address) = location.targets.get(location.at).copied() else {
            return;
        };
        config.remote = address;
        config.located = true;
        let waiting = location.waiting.take();
        self.events.push_back(UaEvent::Located {
            account,
            targets: self.located_targets(account),
        });
        match waiting {
            Some(unregistering) if self.send_register(account, unregistering, now).is_err() => {
                self.retry_later(account, None, None, None, now);
            }
            None if moved => self.follow_move(account, now),
            Some(_) | None => {}
        }
    }

    /// The name now points somewhere else than the address a registration
    /// holds: register there at once, as [`UserAgent::retarget`] does, rather
    /// than wait for a refresh or a failure to find out.
    fn follow_move(&mut self, account: AccountId, now: Instant) {
        let Some(reg) = self.registrations.get(&account) else {
            return;
        };
        let live = reg.transaction.is_some()
            || matches!(
                reg.state,
                RegistrationState::Registered
                    | RegistrationState::Refreshing
                    | RegistrationState::Registering
                    | RegistrationState::Retrying
                    | RegistrationState::Restored
            );
        if !live || reg.unregistering {
            return;
        }
        if self.send_register(account, false, now).is_err() {
            self.retry_later(account, None, None, None, now);
        }
    }

    fn on_locate_failed(&mut self, account: AccountId, reason: LocateError, now: Instant) {
        let entropy = self.endpoint.token();
        let Some(location) = self.locations.held.get_mut(&account) else {
            return;
        };
        location.failures = location.failures.saturating_add(1);
        let retry_in = backoff_delay(location.failures, &entropy);
        let waiting = location.waiting.take();
        // a REGISTER that was waiting backs off as the registration does, and
        // its retry looks the name up again; anything else looks again here
        location.again = if waiting.is_some() {
            None
        } else {
            Some(now + retry_in)
        };
        self.events.push_back(UaEvent::LocateFailed {
            account,
            reason,
            retry_in,
        });
        if waiting.is_some() {
            self.retry_later(account, None, None, None, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TTL, MIN_TTL};
    use crate::account::{Account, AccountId};
    use crate::agent::UserAgent;
    use crate::call::OutgoingCall;
    use crate::event::{RegistrationFailure, UaEvent};
    use crate::{EndpointConfig, Input, TransportId, TransportProtocol, UaError, Uri};
    use sipral_core::endpoint::{Answer, LocateError, Query, Record, RecordType, Srv};
    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    const UDP: TransportId = TransportId(1);

    fn local() -> SocketAddr {
        "192.0.2.1:5060".parse().unwrap()
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).unwrap()
    }

    fn agent(now: Instant) -> UserAgent {
        let mut agent = UserAgent::new(EndpointConfig::default(), [23; 32]).unwrap();
        agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local: local(),
                    remote: None,
                },
                now,
            )
            .unwrap();
        agent
    }

    fn located(registrar: &str) -> Account {
        Account::located(
            uri("sip:alice@example.com"),
            uri(registrar),
            uri("sip:alice@192.0.2.1"),
            UDP,
        )
    }

    /// A resolver answering from a table; anything not in it has nothing.
    #[derive(Default, Clone)]
    struct Dns(HashMap<(String, RecordType), Answer>);

    impl Dns {
        fn with(mut self, name: &str, record: RecordType, answer: Answer) -> Self {
            self.0.insert((name.to_owned(), record), answer);
            self
        }

        fn srv(self, name: &str, targets: &[(u16, &str)], ttl: u64) -> Self {
            let records = targets
                .iter()
                .enumerate()
                .map(|(at, (port, target))| {
                    Record::Srv(Srv {
                        priority: u16::try_from(at).unwrap(),
                        weight: 0,
                        port: *port,
                        target: (*target).into(),
                        ttl: Duration::from_secs(ttl),
                    })
                })
                .collect();
            self.with(name, RecordType::Srv, Answer::Records(records))
        }

        fn a(self, name: &str, address: &str, ttl: u64) -> Self {
            self.with(
                name,
                RecordType::A,
                Answer::Records(vec![Record::Address {
                    address: address.parse().unwrap(),
                    ttl: Duration::from_secs(ttl),
                }]),
            )
        }
    }

    /// Everything that happened: what left, where to, and the events, with
    /// every lookup asked for answered from `dns` as it goes.
    #[derive(Default)]
    struct Seen {
        sent: Vec<(SocketAddr, Vec<u8>)>,
        events: Vec<UaEvent>,
        asked: Vec<Query>,
    }

    impl Seen {
        fn registers(&self) -> Vec<SocketAddr> {
            self.sent
                .iter()
                .filter(|(_, bytes)| bytes.starts_with(b"REGISTER "))
                .map(|(to, _)| *to)
                .collect()
        }
    }

    fn settle(agent: &mut UserAgent, account: AccountId, dns: &Dns, now: Instant) -> Seen {
        let mut seen = Seen::default();
        loop {
            let mut moved = false;
            while let Some(transmit) = agent.poll_transmit() {
                seen.sent
                    .push((transmit.destination, transmit.payload.to_vec()));
                moved = true;
            }
            while let Some(event) = agent.poll_event() {
                moved = true;
                if let UaEvent::LookupWanted { query, .. } = &event {
                    seen.asked.push(query.clone());
                    let answer = dns
                        .0
                        .get(&(query.name.to_string(), query.record))
                        .cloned()
                        .unwrap_or(Answer::Nothing);
                    agent.looked_up(account, query, answer, now).unwrap();
                }
                seen.events.push(event);
            }
            if !moved {
                return seen;
            }
        }
    }

    fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Lenient).unwrap();
        message.header(name).unwrap_or_default().to_vec()
    }

    fn granted(request: &[u8]) -> Vec<u8> {
        let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
        for (name, value) in [
            ("Via", header(request, HeaderName::Via)),
            ("From", header(request, HeaderName::From)),
            ("To", header(request, HeaderName::To)),
            ("Call-ID", header(request, HeaderName::CallId)),
            ("CSeq", header(request, HeaderName::CSeq)),
            ("Contact", header(request, HeaderName::Contact)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Expires: 3600\r\nContent-Length: 0\r\n\r\n");
        out
    }

    fn deliver(agent: &mut UserAgent, from: SocketAddr, bytes: &[u8], now: Instant) {
        agent
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: from,
                    local: local(),
                    data: bytes,
                },
                now,
            )
            .unwrap();
    }

    /// Run every deadline up to `until`, answering lookups on the way.
    fn run(
        agent: &mut UserAgent,
        account: AccountId,
        dns: &Dns,
        from: Instant,
        until: Instant,
    ) -> Seen {
        let mut all = settle(agent, account, dns, from);
        let mut now = from;
        while let Some(due) = agent.poll_timeout() {
            if due > until {
                break;
            }
            now = due.max(now);
            agent.handle_timeout(now);
            let seen = settle(agent, account, dns, now);
            all.sent.extend(seen.sent);
            all.events.extend(seen.events);
            all.asked.extend(seen.asked);
        }
        all
    }

    fn pbx(ttl: u64) -> Dns {
        Dns::default()
            .srv(
                "_sip._udp.pbx.example.com",
                &[(5080, "sip1.example.com"), (5080, "sip2.example.com")],
                ttl,
            )
            .a("sip1.example.com", "192.0.2.40", ttl)
            .a("sip2.example.com", "198.51.100.41", ttl)
    }

    #[test]
    fn a_registrar_named_by_srv_is_registered_with_where_srv_and_a_point() {
        // the trial's failure: a UDP registrar could only be given as ip:port
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(located("sip:pbx.example.com"));
        assert_eq!(
            agent
                .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
                .err(),
            Some(UaError::NotLocated),
            "nowhere to send a call before the first answer"
        );
        agent.register(id, t0).unwrap();
        let seen = settle(&mut agent, id, &pbx(300), t0);
        assert_eq!(
            seen.asked
                .iter()
                .map(|query| (query.name.to_string(), query.record))
                .collect::<Vec<_>>(),
            [
                ("_sip._udp.pbx.example.com".to_owned(), RecordType::Srv),
                ("sip1.example.com".to_owned(), RecordType::A),
                ("sip2.example.com".to_owned(), RecordType::A),
            ]
        );
        assert_eq!(
            seen.registers(),
            [addr("192.0.2.40:5080")],
            "one REGISTER, there"
        );
        let (_, request) = seen.sent.last().unwrap();
        assert!(request.starts_with(b"REGISTER sip:pbx.example.com SIP/2.0"));
        assert!(seen.events.iter().any(|event| matches!(
            event,
            UaEvent::Located { account, targets }
                if *account == id
                    && targets == &[addr("192.0.2.40:5080"), addr("198.51.100.41:5080")]
        )));
        assert_eq!(
            agent.located_targets(id),
            [addr("192.0.2.40:5080"), addr("198.51.100.41:5080")]
        );
    }

    #[test]
    fn a_register_that_times_out_goes_to_the_next_address_at_once() {
        // RFC 3263 §4.3: the first server proved unusable, so the next
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(located("sip:pbx.example.com"));
        agent.register(id, t0).unwrap();
        let dns = pbx(3_600);
        let seen = settle(&mut agent, id, &dns, t0);
        assert_eq!(seen.registers(), [addr("192.0.2.40:5080")]);
        // timer F, 64·T1, and not a moment's back-off after it
        let seen = run(&mut agent, id, &dns, t0, t0 + Duration::from_secs(33));
        let registers = seen.registers();
        assert_eq!(registers.last(), Some(&addr("198.51.100.41:5080")));
        assert!(
            !seen
                .events
                .iter()
                .any(|event| matches!(event, UaEvent::RegistrationFailed { .. })),
            "a failover is not a failure"
        );
        assert!(seen.asked.is_empty(), "nothing looked up again yet");
        let (_, request) = seen
            .sent
            .iter()
            .rev()
            .find(|(to, _)| *to == addr("198.51.100.41:5080"))
            .unwrap();
        let answered = t0 + Duration::from_secs(33);
        deliver(
            &mut agent,
            addr("198.51.100.41:5080"),
            &granted(request),
            answered,
        );
        let seen = settle(&mut agent, id, &dns, answered);
        assert!(
            seen.events
                .iter()
                .any(|event| matches!(event, UaEvent::Registered { .. }))
        );
    }

    #[test]
    fn once_every_address_has_failed_the_name_is_looked_up_again_and_followed() {
        // the PBX moved: every address the old answer named is dead, and the
        // retry after the back-off asks the DNS again and finds it
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(located("sip:pbx.example.com"));
        agent.register(id, t0).unwrap();
        let old = Dns::default()
            .srv(
                "_sip._udp.pbx.example.com",
                &[(5060, "sip.example.com")],
                3_600,
            )
            .a("sip.example.com", "192.0.2.40", 3_600);
        let seen = settle(&mut agent, id, &old, t0);
        assert_eq!(seen.registers(), [addr("192.0.2.40:5060")]);

        let moved = Dns::default()
            .srv(
                "_sip._udp.pbx.example.com",
                &[(5060, "sip.example.com")],
                3_600,
            )
            .a("sip.example.com", "203.0.113.77", 3_600);
        let seen = run(&mut agent, id, &moved, t0, t0 + Duration::from_secs(33));
        assert!(seen.events.iter().any(|event| matches!(
            event,
            UaEvent::RegistrationFailed {
                reason: RegistrationFailure::Unreachable,
                retry_in: Some(_),
                ..
            }
        )));
        let seen = run(
            &mut agent,
            id,
            &moved,
            t0 + Duration::from_secs(33),
            t0 + Duration::from_secs(33 + 600),
        );
        assert!(
            seen.asked
                .iter()
                .any(|query| query.record == RecordType::Srv),
            "the retry looked the name up again"
        );
        assert_eq!(seen.registers().first(), Some(&addr("203.0.113.77:5060")));
    }

    #[test]
    fn when_the_answer_expires_a_registration_follows_the_name_to_its_new_address() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(located("sip:pbx.example.com"));
        agent.register(id, t0).unwrap();
        let dns = Dns::default()
            .srv(
                "_sip._udp.pbx.example.com",
                &[(5060, "sip.example.com")],
                600,
            )
            .a("sip.example.com", "192.0.2.40", 300);
        let seen = settle(&mut agent, id, &dns, t0);
        let (_, request) = seen.sent.last().unwrap();
        deliver(&mut agent, addr("192.0.2.40:5060"), &granted(request), t0);
        let _ = settle(&mut agent, id, &dns, t0);

        // the same answer at 300 s: looked up, and nothing sent
        let at = t0 + Duration::from_secs(300);
        let seen = run(&mut agent, id, &dns, t0, at);
        assert_eq!(
            seen.asked.len(),
            2,
            "SRV and A, once the A record's 300 s ran out"
        );
        assert!(
            seen.registers().is_empty(),
            "the address in use is still named"
        );

        // then the PBX moves, and the next expiry follows it at once
        let moved = Dns::default()
            .srv(
                "_sip._udp.pbx.example.com",
                &[(5060, "sip.example.com")],
                600,
            )
            .a("sip.example.com", "203.0.113.77", 300);
        let later = at + Duration::from_secs(300);
        let seen = run(&mut agent, id, &moved, at, later);
        assert_eq!(seen.registers(), [addr("203.0.113.77:5060")]);
    }

    #[test]
    fn a_time_to_live_is_held_between_a_minute_and_a_day() {
        let t0 = Instant::now();
        for (ttl, expected) in [(0, MIN_TTL), (5, MIN_TTL), (7 * 86_400, MAX_TTL)] {
            let mut agent = agent(t0);
            let id = agent.add_account(located("sip:pbx.example.com:5060"));
            agent.register(id, t0).unwrap();
            let dns = Dns::default().a("pbx.example.com", "192.0.2.40", ttl);
            let _ = settle(&mut agent, id, &dns, t0);
            assert_eq!(
                agent.location_deadline(),
                Some(t0 + expected),
                "a TTL of {ttl}"
            );
        }
    }

    #[test]
    fn a_name_that_resolves_to_nothing_fails_the_register_and_backs_off() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(located("sip:nowhere.example.com"));
        agent.register(id, t0).unwrap();
        let seen = settle(&mut agent, id, &Dns::default(), t0);
        assert!(seen.sent.is_empty());
        assert!(seen.events.iter().any(|event| matches!(
            event,
            UaEvent::LocateFailed {
                reason: LocateError::NotFound,
                ..
            }
        )));
        assert!(seen.events.iter().any(|event| matches!(
            event,
            UaEvent::RegistrationFailed {
                reason: RegistrationFailure::Unreachable,
                retry_in: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn a_numeric_registrar_is_registered_with_at_once_and_only_once() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(located("sip:192.0.2.9"));
        agent.register(id, t0).unwrap();
        let seen = settle(&mut agent, id, &Dns::default(), t0);
        assert!(seen.asked.is_empty());
        assert_eq!(seen.registers(), [addr("192.0.2.9:5060")]);
        assert_eq!(agent.location_deadline(), None, "a literal never expires");
    }

    #[test]
    fn a_trunk_named_by_host_is_located_on_its_first_round_and_can_then_call() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(Account::unregistered_located(
            uri("sip:pbx@example.com"),
            uri("sip:pbx@192.0.2.1"),
            UDP,
            uri("sip:proxy.example.com"),
        ));
        agent.handle_timeout(t0);
        let dns = Dns::default().a("proxy.example.com", "198.51.100.20", 3_600);
        let seen = settle(&mut agent, id, &dns, t0);
        assert_eq!(seen.asked.len(), 2, "SRV, then the host");
        assert_eq!(agent.located_targets(id), [addr("198.51.100.20:5060")]);
        agent
            .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
            .unwrap();
        let seen = settle(&mut agent, id, &dns, t0);
        assert!(
            seen.sent
                .iter()
                .any(|(to, bytes)| bytes.starts_with(b"INVITE ")
                    && *to == addr("198.51.100.20:5060"))
        );
    }
}
