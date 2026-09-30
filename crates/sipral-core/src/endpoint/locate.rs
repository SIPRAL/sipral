// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Finding the server a URI names (RFC 3263 §4), without doing the finding.
//!
//! RFC 3263 turns a SIP URI into an ordered list of addresses with three kinds
//! of DNS lookup — NAPTR, then SRV, then A or AAAA — and the order of those
//! lookups, which answers to keep, how to rank what they return and when the
//! answer stops being true are protocol, not I/O. The lookups themselves are
//! I/O, and the platform's resolver is better than one a library would carry
//! (`docs/01-architecture.md`). So [`Locator`] is the procedure with the
//! resolver taken out: it hands out a [`Query`] at a time, is told the
//! [`Answer`] the caller's resolver gave, and ends with the addresses to try,
//! first to last, and how long the DNS said they hold.
//!
//! What it does, section by section, written from the RFCs; where the text of
//! a section is recalled rather than quoted, the comment says so.
//!
//! - §4.1: the transport is not chosen here. It is the one the caller already
//!   has bound for the traffic — an account's transport — so a NAPTR lookup,
//!   when asked for, only picks which SRV name serves that transport, by the
//!   services RFC 3263 registers (`SIP+D2U`, `SIP+D2T`, `SIPS+D2T`).
//! - §4.2: a numeric host needs no lookup; a host with a port is looked up for
//!   its addresses alone; otherwise the SRV name for the transport
//!   (`_sip._udp`, `_sip._tcp`, `_sips._tcp`) is asked, and when it has no
//!   records the host's own addresses are, at the transport's default port.
//! - RFC 2782: SRV records are tried by ascending priority, and within one
//!   priority in a random order weighted by their weights; a single record
//!   whose target is `.` says the service is decidedly not available there.
//! - §4.3: every address found is kept, in that order, so a caller whose first
//!   server does not answer tries the next rather than asking again.
//!
//! Only the address family the caller's transport can reach is asked for: a
//! socket bound to an IPv4 address sends nothing to an IPv6 one.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::resolve::target_host;
use super::transport::{Host, TransportProtocol};
use crate::msg::Uri;

/// Which kind of record a [`Query`] asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// RFC 3403: which services a domain offers, and under which names.
    Naptr,
    /// RFC 2782: which hosts, at which ports, serve one service.
    Srv,
    /// An IPv4 address.
    A,
    /// An IPv6 address.
    Aaaa,
}

/// One DNS lookup the caller's resolver is asked to make.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Query {
    /// The name, as it is to be asked: `_sip._udp.example.com`, or a host.
    pub name: Arc<str>,
    /// What to ask it for.
    pub record: RecordType,
}

/// A NAPTR record (RFC 3403 §4.1), with the fields RFC 3263 reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Naptr {
    /// Lower first.
    pub order: u16,
    /// Lower first, among records of the same order.
    pub preference: u16,
    /// `S` for a record whose replacement is an SRV name, the only kind
    /// RFC 3263 §4.1 follows.
    pub flags: Box<str>,
    /// `SIP+D2U`, `SIP+D2T`, `SIPS+D2T`, ...
    pub service: Box<str>,
    /// The SRV name to ask next.
    pub replacement: Box<str>,
    /// How long the record holds.
    pub ttl: Duration,
}

/// An SRV record (RFC 2782).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srv {
    /// Lower first.
    pub priority: u16,
    /// Relative share among records of the same priority.
    pub weight: u16,
    /// The port the service is on at `target`.
    pub port: u16,
    /// The host, or `.` for none.
    pub target: Box<str>,
    /// How long the record holds.
    pub ttl: Duration,
}

/// One record of an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// An answer to a NAPTR query.
    Naptr(Naptr),
    /// An answer to an SRV query.
    Srv(Srv),
    /// An answer to an A or AAAA query.
    Address {
        /// The address.
        address: IpAddr,
        /// How long it holds.
        ttl: Duration,
    },
}

/// What the caller's resolver said to a [`Query`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The records it returned. Records of a kind the query did not ask for
    /// are passed over.
    Records(Vec<Record>),
    /// The name has no record of that kind, or does not exist at all. Also
    /// the right answer from a resolver that cannot ask for the kind — a
    /// platform lookup that only knows addresses answers every NAPTR and SRV
    /// query with this, and the procedure goes on to the host's addresses.
    Nothing,
    /// The resolver could not answer: no server reachable, a timeout, a
    /// server failure.
    Failed,
}

/// Why a [`Locator`] ended without an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocateError {
    /// The DNS answered, and what it answered names no address of the family
    /// the transport can reach: no record, or an SRV target of `.`.
    NotFound,
    /// The resolver failed on every lookup that could have given an address.
    Unanswered,
    /// The transport has no RFC 3263 procedure here: WebSocket names no SRV
    /// service and no default port, so only a numeric host, or a host with a
    /// port, can be located for it.
    Unsupported,
}

impl core::fmt::Display for LocateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "the DNS names no reachable address for the server",
            Self::Unanswered => "the resolver gave no answer for the server",
            Self::Unsupported => "RFC 3263 has no lookup for this transport without a port",
        })
    }
}

impl core::error::Error for LocateError {}

/// Where a URI's server is: every address to try, first to last, and how long
/// the answer holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located {
    /// The addresses, in the order §4.3 has them tried.
    pub targets: Vec<SocketAddr>,
    /// The shortest time-to-live of every record the answer was built from,
    /// or `None` for a numeric host, which never has to be looked up again.
    pub ttl: Option<Duration>,
}

/// One host whose addresses are asked for, at the port the service is on.
#[derive(Debug)]
struct HostLookup {
    name: Arc<str>,
    port: u16,
    /// `None` until answered; the addresses, or `Err(failed)` for none.
    found: Option<Result<Vec<IpAddr>, bool>>,
}

#[derive(Debug)]
enum Stage {
    /// Waiting for the NAPTR answer for the domain.
    Naptr,
    /// Waiting for the SRV answer for the front name; the rest are the ones a
    /// NAPTR answer ranked after it.
    Srv(VecDeque<Arc<str>>),
    /// Waiting for the addresses of every host.
    Hosts(Vec<HostLookup>),
    /// Nothing more to ask.
    Done,
}

/// RFC 3263 §4 for one URI, one transport and one address family, driven by
/// the caller's resolver.
///
/// ```
/// use std::time::Duration;
/// use sipral_core::endpoint::{
///     AddressFamily, Answer, Locator, Record, RecordType, Srv, TransportProtocol,
/// };
/// use sipral_core::msg::Uri;
///
/// let uri = Uri::parse_str("sip:pbx.example.com").unwrap();
/// let mut locator = Locator::new(&uri, TransportProtocol::Udp, AddressFamily::Ipv4, false, 7);
/// let srv = locator.poll_query().unwrap();
/// assert_eq!((&*srv.name, srv.record), ("_sip._udp.pbx.example.com", RecordType::Srv));
/// locator.answer(&srv, Answer::Records(vec![Record::Srv(Srv {
///     priority: 10, weight: 0, port: 5080, target: "sip1.example.com".into(),
///     ttl: Duration::from_secs(300),
/// })]));
/// let a = locator.poll_query().unwrap();
/// locator.answer(&a, Answer::Records(vec![Record::Address {
///     address: "192.0.2.40".parse().unwrap(), ttl: Duration::from_secs(60),
/// }]));
/// let located = locator.outcome().unwrap().as_ref().unwrap();
/// assert_eq!(located.targets, ["192.0.2.40:5080".parse().unwrap()]);
/// assert_eq!(located.ttl, Some(Duration::from_secs(60)));
/// ```
#[derive(Debug)]
pub struct Locator {
    protocol: TransportProtocol,
    family: AddressFamily,
    /// The TARGET of §4: the `maddr`, or the host.
    domain: Arc<str>,
    stage: Stage,
    /// Queries made and not yet handed to the caller.
    queue: VecDeque<Query>,
    /// The shortest TTL of every record used so far.
    ttl: Option<Duration>,
    /// Whether any lookup that could have given an address failed.
    failed: bool,
    /// xorshift64 state, for RFC 2782's weighted draw.
    draw: u64,
    outcome: Option<Result<Located, LocateError>>,
}

/// The addresses a transport can send to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// A records only.
    Ipv4,
    /// AAAA records only.
    Ipv6,
}

impl AddressFamily {
    /// The family of the address a transport is bound to.
    #[must_use]
    pub const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    const fn holds(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }

    const fn record(self) -> RecordType {
        match self {
            Self::Ipv4 => RecordType::A,
            Self::Ipv6 => RecordType::Aaaa,
        }
    }
}

impl Locator {
    /// Start locating `target`'s server for `protocol` over `family`.
    ///
    /// `naptr` asks the domain's NAPTR records first (RFC 3263 §4.1), which a
    /// deployment that publishes none — most of them — spends a round trip
    /// on; without it the procedure starts at SRV, which §4.1 allows a client
    /// that already knows its transport. `seed` is entropy for RFC 2782's
    /// weighted order, the caller's to draw like every other random number in
    /// this crate.
    ///
    /// A URI that is not a SIP URI, or that names a numeric host, is settled
    /// here and asks nothing.
    #[must_use]
    pub fn new(
        target: &Uri,
        protocol: TransportProtocol,
        family: AddressFamily,
        naptr: bool,
        seed: u64,
    ) -> Self {
        let mut locator = Self {
            protocol,
            family,
            domain: Arc::from(""),
            stage: Stage::Done,
            queue: VecDeque::new(),
            ttl: None,
            failed: false,
            draw: seed | 1,
            outcome: None,
        };
        let Some(sip) = target.sip() else {
            locator.outcome = Some(Err(LocateError::NotFound));
            return locator;
        };
        let port = sip.port.or_else(|| protocol.default_port());
        match target_host(&sip) {
            Host::Ip(address) => {
                locator.outcome = Some(match (family.holds(address), port) {
                    (true, Some(port)) => Ok(Located {
                        targets: vec![SocketAddr::new(address, port)],
                        ttl: None,
                    }),
                    (false, _) => Err(LocateError::NotFound),
                    (true, None) => Err(LocateError::Unsupported),
                });
            }
            Host::Name(name) => {
                locator.domain = name;
                if let Some(port) = sip.port {
                    // §4.2: "If the TARGET was not a numeric IP address, but a
                    // port is present in the URI, the client performs an A or
                    // AAAA record lookup of the domain name"
                    let domain = locator.domain.clone();
                    locator.ask_hosts(vec![(domain, port)]);
                } else if naptr && locator.naptr_service().is_some() {
                    locator.stage = Stage::Naptr;
                    locator.ask(locator.domain.clone(), RecordType::Naptr);
                } else {
                    locator.ask_srv(VecDeque::new());
                }
            }
        }
        locator
    }

    /// The next lookup to make, until there is none. Every query handed out
    /// is waited for: answer each one, [`Answer::Failed`] included, or the
    /// procedure never ends.
    pub fn poll_query(&mut self) -> Option<Query> {
        self.queue.pop_front()
    }

    /// How the procedure ended, once it has.
    #[must_use]
    pub const fn outcome(&self) -> Option<&Result<Located, LocateError>> {
        self.outcome.as_ref()
    }

    /// How it ended, taken.
    pub const fn take_outcome(&mut self) -> Option<Result<Located, LocateError>> {
        self.outcome.take()
    }

    /// What the resolver said to `query`.
    ///
    /// Answers to a query this locator is not waiting for — a stale one, or
    /// one answered twice — change nothing, and are reported with `false`.
    pub fn answer(&mut self, query: &Query, answer: Answer) -> bool {
        match core::mem::replace(&mut self.stage, Stage::Done) {
            Stage::Naptr if query.record == RecordType::Naptr && *query.name == *self.domain => {
                self.on_naptr(answer);
                true
            }
            Stage::Srv(mut names)
                if query.record == RecordType::Srv
                    && names.front().is_some_and(|name| **name == *query.name) =>
            {
                names.pop_front();
                self.on_srv(names, answer);
                true
            }
            Stage::Hosts(mut hosts) if query.record == self.family.record() => {
                let mut taken = false;
                for host in &mut hosts {
                    if host.found.is_none() && host.name.eq_ignore_ascii_case(&query.name) {
                        host.found = Some(self.addresses(&answer));
                        taken = true;
                    }
                }
                if hosts.iter().all(|host| host.found.is_some()) {
                    self.finish(&hosts);
                } else {
                    self.stage = Stage::Hosts(hosts);
                }
                taken
            }
            other => {
                self.stage = other;
                false
            }
        }
    }

    /// RFC 3263 §4.1: the services a NAPTR record names for each transport.
    const fn naptr_service(&self) -> Option<&'static str> {
        match self.protocol {
            TransportProtocol::Udp => Some("SIP+D2U"),
            TransportProtocol::Tcp => Some("SIP+D2T"),
            TransportProtocol::Tls => Some("SIPS+D2T"),
            TransportProtocol::Ws | TransportProtocol::Wss => None,
        }
    }

    /// RFC 3263 §4.2's SRV name for the transport, under the domain.
    fn srv_name(&self) -> Option<Arc<str>> {
        let prefix = match self.protocol {
            TransportProtocol::Udp => "_sip._udp.",
            TransportProtocol::Tcp => "_sip._tcp.",
            TransportProtocol::Tls => "_sips._tcp.",
            TransportProtocol::Ws | TransportProtocol::Wss => return None,
        };
        Some(Arc::from(format!("{prefix}{}", self.domain)))
    }

    fn ask(&mut self, name: Arc<str>, record: RecordType) {
        self.queue.push_back(Query { name, record });
    }

    fn note_ttl(&mut self, ttl: Duration) {
        self.ttl = Some(self.ttl.map_or(ttl, |held| held.min(ttl)));
    }

    /// Ask the SRV names a NAPTR answer ranked, or the transport's own when it
    /// ranked none.
    fn ask_srv(&mut self, mut names: VecDeque<Arc<str>>) {
        if names.is_empty() {
            let Some(name) = self.srv_name() else {
                self.outcome = Some(Err(LocateError::Unsupported));
                return;
            };
            names.push_back(name);
        }
        if let Some(first) = names.front().cloned() {
            self.ask(first, RecordType::Srv);
        }
        self.stage = Stage::Srv(names);
    }

    fn ask_hosts(&mut self, hosts: Vec<(Arc<str>, u16)>) {
        let mut lookups: Vec<HostLookup> = Vec::with_capacity(hosts.len());
        for (name, port) in hosts {
            if lookups
                .iter()
                .any(|held| held.port == port && held.name.eq_ignore_ascii_case(&name))
            {
                continue;
            }
            let asked = lookups
                .iter()
                .any(|held| held.name.eq_ignore_ascii_case(&name));
            if !asked {
                self.ask(name.clone(), self.family.record());
            }
            lookups.push(HostLookup {
                name,
                port,
                found: None,
            });
        }
        if lookups.is_empty() {
            self.finish(&lookups);
        } else {
            self.stage = Stage::Hosts(lookups);
        }
    }

    fn on_naptr(&mut self, answer: Answer) {
        let Some(service) = self.naptr_service() else {
            self.ask_srv(VecDeque::new());
            return;
        };
        let mut usable: Vec<Naptr> = match answer {
            Answer::Records(records) => records
                .into_iter()
                .filter_map(|record| match record {
                    Record::Naptr(naptr)
                        if naptr.flags.eq_ignore_ascii_case("s")
                            && naptr.service.eq_ignore_ascii_case(service) =>
                    {
                        Some(naptr)
                    }
                    _ => None,
                })
                .collect(),
            // NAPTR is optional in practice: a domain with none, or a
            // resolver that cannot ask, goes on to SRV (§4.1, as recalled:
            // "If no NAPTR records are found, the client constructs SRV
            // queries for those transport protocols it supports")
            Answer::Nothing | Answer::Failed => Vec::new(),
        };
        usable.sort_by_key(|naptr| (naptr.order, naptr.preference));
        for naptr in &usable {
            self.note_ttl(naptr.ttl);
        }
        // a domain whose NAPTR records offer other transports and not this
        // one: the SRV name for this one is asked all the same. RFC 3263
        // would have the client pick a transport the records offer; here the
        // transport is fixed by the socket the caller bound, so the records
        // can only say where it is served, not change what it is.
        let names = usable
            .into_iter()
            .map(|naptr| Arc::from(&*naptr.replacement))
            .collect();
        self.ask_srv(names);
    }

    fn on_srv(&mut self, rest: VecDeque<Arc<str>>, answer: Answer) {
        let records: Vec<Srv> = match answer {
            Answer::Records(records) => records
                .into_iter()
                .filter_map(|record| match record {
                    Record::Srv(srv) => Some(srv),
                    _ => None,
                })
                .collect(),
            Answer::Nothing => Vec::new(),
            Answer::Failed => {
                self.failed = true;
                Vec::new()
            }
        };
        // RFC 2782: "A Target of \".\" means that the service is decidedly
        // not available at this domain."
        if let [only] = records.as_slice()
            && only.target.trim_end_matches('.').is_empty()
        {
            self.note_ttl(only.ttl);
            self.outcome = Some(Err(LocateError::NotFound));
            return;
        }
        if records.is_empty() {
            if !rest.is_empty() {
                self.ask_srv(rest);
                return;
            }
            // §4.2: no SRV records, so the domain's own addresses at the
            // transport's default port
            let Some(port) = self.protocol.default_port() else {
                self.outcome = Some(Err(LocateError::Unsupported));
                return;
            };
            let domain = self.domain.clone();
            self.ask_hosts(vec![(domain, port)]);
            return;
        }
        for srv in &records {
            self.note_ttl(srv.ttl);
        }
        let hosts = self
            .rank(records)
            .into_iter()
            .filter(|srv| !srv.target.trim_end_matches('.').is_empty())
            .map(|srv| (Arc::from(&*srv.target), srv.port))
            .collect();
        self.ask_hosts(hosts);
    }

    /// RFC 2782's order: ascending priority, and within one priority a
    /// weighted random draw, the records of weight zero placed first so that
    /// they are chosen only when the draw lands on zero.
    fn rank(&mut self, mut records: Vec<Srv>) -> Vec<Srv> {
        records.sort_by_key(|srv| srv.priority);
        let mut ranked = Vec::with_capacity(records.len());
        while !records.is_empty() {
            let priority = records.first().map_or(0, |srv| srv.priority);
            let split = records
                .iter()
                .position(|srv| srv.priority != priority)
                .unwrap_or(records.len());
            let mut group: Vec<Srv> = records.drain(..split).collect();
            // zero weights first, the order they came in otherwise kept
            group.sort_by_key(|srv| srv.weight != 0);
            while !group.is_empty() {
                let total: u64 = group.iter().map(|srv| u64::from(srv.weight)).sum();
                let pick = self.next() % (total + 1);
                let mut running = 0;
                let mut chosen = group.len() - 1;
                for (at, srv) in group.iter().enumerate() {
                    running += u64::from(srv.weight);
                    if running >= pick {
                        chosen = at;
                        break;
                    }
                }
                ranked.push(group.remove(chosen));
            }
        }
        ranked
    }

    fn next(&mut self) -> u64 {
        self.draw ^= self.draw << 13;
        self.draw ^= self.draw >> 7;
        self.draw ^= self.draw << 17;
        self.draw
    }

    fn addresses(&mut self, answer: &Answer) -> Result<Vec<IpAddr>, bool> {
        match answer {
            Answer::Records(records) => {
                let mut found = Vec::new();
                for record in records {
                    if let Record::Address { address, ttl } = *record
                        && self.family.holds(address)
                    {
                        self.note_ttl(ttl);
                        found.push(address);
                    }
                }
                if found.is_empty() {
                    Err(false)
                } else {
                    Ok(found)
                }
            }
            Answer::Nothing => Err(false),
            Answer::Failed => Err(true),
        }
    }

    fn finish(&mut self, hosts: &[HostLookup]) {
        let mut targets: Vec<SocketAddr> = Vec::new();
        for host in hosts {
            match host.found.as_ref() {
                Some(Ok(addresses)) => {
                    for address in addresses {
                        let target = SocketAddr::new(*address, host.port);
                        if !targets.contains(&target) {
                            targets.push(target);
                        }
                    }
                }
                Some(Err(true)) => self.failed = true,
                Some(Err(false)) | None => {}
            }
        }
        self.outcome = Some(if targets.is_empty() {
            Err(if self.failed {
                LocateError::Unanswered
            } else {
                LocateError::NotFound
            })
        } else {
            Ok(Located {
                targets,
                ttl: self.ttl,
            })
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressFamily, Answer, LocateError, Located, Locator, Naptr, Query, Record, RecordType, Srv,
    };
    use crate::endpoint::TransportProtocol;
    use crate::msg::Uri;
    use std::collections::HashMap;
    use std::time::Duration;

    /// A resolver that answers from a table, and remembers what it was asked.
    #[derive(Default)]
    struct FakeDns {
        table: HashMap<(String, RecordType), Answer>,
        asked: Vec<(String, RecordType)>,
    }

    impl FakeDns {
        fn with(mut self, name: &str, record: RecordType, answer: Answer) -> Self {
            self.table.insert((name.to_owned(), record), answer);
            self
        }

        fn run(&mut self, locator: &mut Locator) -> Result<Located, LocateError> {
            while let Some(query) = locator.poll_query() {
                self.asked.push((query.name.to_string(), query.record));
                let answer = self
                    .table
                    .get(&(query.name.to_string(), query.record))
                    .cloned()
                    .unwrap_or(Answer::Nothing);
                assert!(locator.answer(&query, answer), "{query:?} was asked");
            }
            locator.take_outcome().expect("the procedure ended")
        }
    }

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).unwrap()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn srv(priority: u16, weight: u16, port: u16, target: &str, ttl: u64) -> Record {
        Record::Srv(Srv {
            priority,
            weight,
            port,
            target: target.into(),
            ttl: secs(ttl),
        })
    }

    fn a(address: &str, ttl: u64) -> Record {
        Record::Address {
            address: address.parse().unwrap(),
            ttl: secs(ttl),
        }
    }

    fn naptr(order: u16, service: &str, replacement: &str) -> Record {
        Record::Naptr(Naptr {
            order,
            preference: 50,
            flags: "s".into(),
            service: service.into(),
            replacement: replacement.into(),
            ttl: secs(900),
        })
    }

    fn udp(text: &str) -> Locator {
        Locator::new(
            &uri(text),
            TransportProtocol::Udp,
            AddressFamily::Ipv4,
            false,
            42,
        )
    }

    fn addresses(located: &Located) -> Vec<String> {
        located.targets.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn srv_records_are_tried_by_priority_and_their_hosts_looked_up() {
        let mut dns = FakeDns::default()
            .with(
                "_sip._udp.pbx.example.com",
                RecordType::Srv,
                Answer::Records(vec![
                    srv(20, 0, 5062, "backup.example.com", 600),
                    srv(10, 0, 5080, "main.example.com", 300),
                ]),
            )
            .with(
                "main.example.com",
                RecordType::A,
                Answer::Records(vec![a("192.0.2.10", 120), a("192.0.2.11", 120)]),
            )
            .with(
                "backup.example.com",
                RecordType::A,
                Answer::Records(vec![a("198.51.100.20", 3_600)]),
            );
        let located = dns.run(&mut udp("sip:pbx.example.com")).unwrap();
        assert_eq!(
            addresses(&located),
            ["192.0.2.10:5080", "192.0.2.11:5080", "198.51.100.20:5062"]
        );
        // the shortest TTL of anything the answer was built from
        assert_eq!(located.ttl, Some(secs(120)));
        assert!(
            !dns.asked.iter().any(|(_, kind)| *kind == RecordType::Naptr),
            "no NAPTR unless asked for"
        );
    }

    #[test]
    fn with_no_srv_records_the_hosts_own_address_is_used_at_the_default_port() {
        // RFC 3263 §4.2, and the resolver that only knows addresses: every
        // SRV query answered with nothing
        let mut dns = FakeDns::default().with(
            "pbx.example.com",
            RecordType::A,
            Answer::Records(vec![a("203.0.113.5", 30)]),
        );
        let located = dns.run(&mut udp("sip:alice@pbx.example.com")).unwrap();
        assert_eq!(addresses(&located), ["203.0.113.5:5060"]);
        assert_eq!(
            dns.asked,
            [
                ("_sip._udp.pbx.example.com".to_owned(), RecordType::Srv),
                ("pbx.example.com".to_owned(), RecordType::A),
            ]
        );

        // TLS asks `_sips._tcp` and falls back to 5061
        let mut dns = FakeDns::default().with(
            "pbx.example.com",
            RecordType::A,
            Answer::Records(vec![a("203.0.113.5", 30)]),
        );
        let mut locator = Locator::new(
            &uri("sip:pbx.example.com"),
            TransportProtocol::Tls,
            AddressFamily::Ipv4,
            false,
            1,
        );
        let located = dns.run(&mut locator).unwrap();
        assert_eq!(addresses(&located), ["203.0.113.5:5061"]);
        assert_eq!(dns.asked[0].0, "_sips._tcp.pbx.example.com");

        // and TCP `_sip._tcp`
        let mut dns = FakeDns::default();
        let mut locator = Locator::new(
            &uri("sip:pbx.example.com"),
            TransportProtocol::Tcp,
            AddressFamily::Ipv4,
            false,
            1,
        );
        assert_eq!(dns.run(&mut locator), Err(LocateError::NotFound));
        assert_eq!(dns.asked[0].0, "_sip._tcp.pbx.example.com");
    }

    #[test]
    fn a_port_in_the_uri_skips_srv_and_a_numeric_host_asks_nothing() {
        let mut dns = FakeDns::default().with(
            "pbx.example.com",
            RecordType::A,
            Answer::Records(vec![a("192.0.2.7", 60)]),
        );
        let located = dns.run(&mut udp("sip:pbx.example.com:5070")).unwrap();
        assert_eq!(addresses(&located), ["192.0.2.7:5070"]);
        assert_eq!(dns.asked, [("pbx.example.com".to_owned(), RecordType::A)]);

        let mut dns = FakeDns::default();
        let located = dns.run(&mut udp("sip:192.0.2.9")).unwrap();
        assert_eq!(addresses(&located), ["192.0.2.9:5060"]);
        assert_eq!(located.ttl, None, "a numeric host never expires");
        assert!(dns.asked.is_empty());
    }

    #[test]
    fn maddr_is_the_target_rather_than_the_host() {
        let mut dns = FakeDns::default().with(
            "proxy.example.net",
            RecordType::A,
            Answer::Records(vec![a("192.0.2.33", 60)]),
        );
        let located = dns
            .run(&mut udp("sip:pbx.example.com;maddr=proxy.example.net"))
            .unwrap();
        assert_eq!(addresses(&located), ["192.0.2.33:5060"]);
        assert_eq!(dns.asked[0].0, "_sip._udp.proxy.example.net");
    }

    #[test]
    fn naptr_picks_the_srv_name_that_serves_this_transport() {
        let mut dns = FakeDns::default()
            .with(
                "example.com",
                RecordType::Naptr,
                Answer::Records(vec![
                    naptr(10, "SIP+D2T", "_sip._tcp.example.com"),
                    naptr(20, "SIP+D2U", "_sip._udp.sbc.example.com"),
                    naptr(5, "E2U+sip", "ignored.example.com"),
                ]),
            )
            .with(
                "_sip._udp.sbc.example.com",
                RecordType::Srv,
                Answer::Records(vec![srv(0, 0, 5060, "sbc1.example.com", 300)]),
            )
            .with(
                "sbc1.example.com",
                RecordType::A,
                Answer::Records(vec![a("192.0.2.50", 300)]),
            );
        let mut locator = Locator::new(
            &uri("sip:example.com"),
            TransportProtocol::Udp,
            AddressFamily::Ipv4,
            true,
            3,
        );
        let located = dns.run(&mut locator).unwrap();
        assert_eq!(addresses(&located), ["192.0.2.50:5060"]);
        assert_eq!(
            dns.asked,
            [
                ("example.com".to_owned(), RecordType::Naptr),
                ("_sip._udp.sbc.example.com".to_owned(), RecordType::Srv),
                ("sbc1.example.com".to_owned(), RecordType::A),
            ]
        );
    }

    #[test]
    fn a_domain_with_no_naptr_goes_on_to_srv() {
        let mut dns = FakeDns::default()
            .with(
                "_sip._udp.example.com",
                RecordType::Srv,
                Answer::Records(vec![srv(0, 0, 5060, "sip.example.com", 300)]),
            )
            .with(
                "sip.example.com",
                RecordType::A,
                Answer::Records(vec![a("192.0.2.51", 300)]),
            );
        let mut locator = Locator::new(
            &uri("sip:example.com"),
            TransportProtocol::Udp,
            AddressFamily::Ipv4,
            true,
            3,
        );
        let located = dns.run(&mut locator).unwrap();
        assert_eq!(addresses(&located), ["192.0.2.51:5060"]);
        assert_eq!(dns.asked[0].1, RecordType::Naptr);
    }

    #[test]
    fn a_target_of_dot_says_the_service_is_not_there() {
        let mut dns = FakeDns::default().with(
            "_sip._udp.example.com",
            RecordType::Srv,
            Answer::Records(vec![srv(0, 0, 0, ".", 300)]),
        );
        assert_eq!(
            dns.run(&mut udp("sip:example.com")),
            Err(LocateError::NotFound)
        );
        assert_eq!(dns.asked.len(), 1, "no address is looked up for it");
    }

    #[test]
    fn weights_share_out_the_first_place_within_a_priority() {
        // RFC 2782: a server of weight 90 beside one of 10 comes first about
        // nine times in ten
        let mut heavy_first = 0;
        for seed in 0..1_000_u64 {
            let mut dns = FakeDns::default()
                .with(
                    "_sip._udp.example.com",
                    RecordType::Srv,
                    Answer::Records(vec![
                        srv(1, 10, 5060, "light.example.com", 300),
                        srv(1, 90, 5060, "heavy.example.com", 300),
                    ]),
                )
                .with(
                    "light.example.com",
                    RecordType::A,
                    Answer::Records(vec![a("192.0.2.1", 300)]),
                )
                .with(
                    "heavy.example.com",
                    RecordType::A,
                    Answer::Records(vec![a("192.0.2.2", 300)]),
                );
            let mut locator = Locator::new(
                &uri("sip:example.com"),
                TransportProtocol::Udp,
                AddressFamily::Ipv4,
                false,
                seed.wrapping_mul(0x9e37_79b9_7f4a_7c15),
            );
            let located = dns.run(&mut locator).unwrap();
            assert_eq!(located.targets.len(), 2, "both are kept");
            if located.targets[0].to_string() == "192.0.2.2:5060" {
                heavy_first += 1;
            }
        }
        assert!((820..=970).contains(&heavy_first), "{heavy_first} of 1000");
    }

    #[test]
    fn only_the_transports_family_is_asked_for_and_kept() {
        let mut dns = FakeDns::default().with(
            "pbx.example.com",
            RecordType::Aaaa,
            Answer::Records(vec![a("2001:db8::5", 60), a("192.0.2.5", 60)]),
        );
        let mut locator = Locator::new(
            &uri("sip:pbx.example.com:5060"),
            TransportProtocol::Udp,
            AddressFamily::Ipv6,
            false,
            1,
        );
        let located = dns.run(&mut locator).unwrap();
        assert_eq!(addresses(&located), ["[2001:db8::5]:5060"]);

        // an IPv6 literal on an IPv4 transport is nowhere it can send
        let mut dns = FakeDns::default();
        assert_eq!(
            dns.run(&mut udp("sip:[2001:db8::5]")),
            Err(LocateError::NotFound)
        );
    }

    #[test]
    fn a_resolver_that_fails_everywhere_is_told_apart_from_a_name_with_nothing() {
        let mut dns = FakeDns::default()
            .with("_sip._udp.example.com", RecordType::Srv, Answer::Failed)
            .with("example.com", RecordType::A, Answer::Failed);
        assert_eq!(
            dns.run(&mut udp("sip:example.com")),
            Err(LocateError::Unanswered)
        );
        let mut dns = FakeDns::default();
        assert_eq!(
            dns.run(&mut udp("sip:example.com")),
            Err(LocateError::NotFound)
        );
    }

    #[test]
    fn an_answer_to_a_question_not_asked_changes_nothing() {
        let mut locator = udp("sip:example.com");
        let srv_query = locator.poll_query().unwrap();
        let stray = Query {
            name: "example.com".into(),
            record: RecordType::A,
        };
        assert!(!locator.answer(&stray, Answer::Records(vec![a("192.0.2.66", 60)])));
        assert!(locator.outcome().is_none());
        assert!(locator.answer(&srv_query, Answer::Nothing));
        assert!(
            !locator.answer(&srv_query, Answer::Nothing),
            "answered twice"
        );
        let host = locator.poll_query().unwrap();
        assert_eq!(host.record, RecordType::A);
        assert!(locator.answer(&host, Answer::Records(vec![a("192.0.2.67", 60)])));
        assert_eq!(
            locator.outcome().cloned(),
            Some(Ok(Located {
                targets: vec!["192.0.2.67:5060".parse().unwrap()],
                ttl: Some(secs(60)),
            }))
        );
    }
}
