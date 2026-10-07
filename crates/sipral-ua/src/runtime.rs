// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The reference loop: sockets, a thread each, and the five calls.
//!
//! The only place that opens sockets: `std::net`, blocking reads, one thread
//! per socket feeding a channel. It makes a first call take twenty lines and
//! gives the bindings something to mirror. Behind a feature flag, off by
//! default, because a real deployment needs what it lacks:
//!
//! - **NAPTR and SRV.** `std::net` only resolves A records, so RFC 3263
//!   ordering never happens; bring your own resolver. A failed lookup is
//!   handed to the application with the name, and when a registrar's own
//!   name fails too the agent is told
//!   [`UserAgent::name_resolution_lost`](crate::UserAgent::name_resolution_lost).
//!   One bad name from a far end does not count.
//! - **TLS.** None is linked. This loop opens plain UDP and TCP; a plain
//!   WebSocket is TCP here and the agent does the rest ([`crate::websocket`]).
//! - **Wildcard binds.** Without `IP_PKTINFO` a datagram's local address is
//!   unknown, and RFC 3581 §4 needs it, so bind to a named address.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{
    AddressFamily, Answer, EndpointConfig, Event, Host, Input, Query, Record, RecordType,
    TransportId, TransportProtocol,
};
use sipral_core::msg::HostRef;

use crate::agent::UserAgent;
use crate::event::UaEvent;

const DATAGRAM: usize = 65_535;
/// Read buffer only; messages are framed by `Content-Length` further down.
const CHUNK: usize = 8_192;
/// Read timeout with no deadline, so [`Handler::on_tick`] still runs.
const IDLE: Duration = Duration::from_millis(200);

/// How long one turn may sit in a read. `None` means until a packet.
fn sleep_for(deadline: Option<Instant>, cap: Option<Duration>, now: Instant) -> Option<Duration> {
    let until = deadline.map(|at| at.saturating_duration_since(now));
    match (until, cap) {
        (Some(until), Some(cap)) => Some(until.min(cap)),
        (left, right) => left.or(right),
    }
}

/// Whether the loop keeps going.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Control {
    /// Round again.
    Continue,
    /// Come out of [`Runtime::run`].
    Stop,
}

/// What an application does with what happens.
pub trait Handler {
    /// Something happened; the agent is passed so the handler can react.
    fn on_event(&mut self, agent: &mut UserAgent, event: UaEvent, now: Instant);

    /// Called once per turn, whether or not anything arrived: place calls,
    /// decide when to stop.
    fn on_tick(&mut self, agent: &mut UserAgent, now: Instant) -> Control {
        let _ = (agent, now);
        Control::Continue
    }
}

#[derive(Debug)]
enum Link {
    /// With the address it was bound to.
    Datagram(Arc<UdpSocket>, SocketAddr),
    Stream(Arc<TcpStream>),
}

#[derive(Debug)]
enum Arrival {
    Datagram {
        transport: TransportId,
        remote: SocketAddr,
        data: Vec<u8>,
    },
    Stream {
        transport: TransportId,
        data: Vec<u8>,
    },
    Closed {
        transport: TransportId,
    },
}

/// A user agent with sockets under it.
#[derive(Debug)]
pub struct Runtime {
    agent: UserAgent,
    links: HashMap<TransportId, Link>,
    inbox: Receiver<Arrival>,
    postbox: Sender<Arrival>,
    udp: TransportId,
    local: SocketAddr,
    next: u32,
    cap: Option<Duration>,
    resolver: Resolver,
}

impl Runtime {
    /// Bind a UDP socket and put a user agent on it.
    ///
    /// `local` must not be a wildcard (see the module docs). `seed` is the
    /// endpoint's 32 bytes of entropy.
    ///
    /// # Errors
    /// Whatever binding the socket returns, and
    /// [`io::ErrorKind::InvalidInput`] when a timer in `config` cannot be
    /// armed (see [`UserAgent::new`]).
    pub fn bind(config: EndpointConfig, seed: [u8; 32], local: SocketAddr) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(local)?);
        let local = socket.local_addr()?;
        let (postbox, inbox) = channel();
        let udp = TransportId(1);
        let agent = UserAgent::new(config, seed)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        let mut runtime = Self {
            agent,
            links: HashMap::new(),
            inbox,
            postbox,
            udp,
            local,
            next: 2,
            cap: Some(IDLE),
            resolver: look_up,
        };
        runtime
            .links
            .insert(udp, Link::Datagram(Arc::clone(&socket), local));
        runtime.read_datagrams(udp, socket);
        runtime.tell(Input::TransportBound {
            transport: udp,
            protocol: TransportProtocol::Udp,
            local,
            remote: None,
        });
        Ok(runtime)
    }

    /// The UDP transport, to configure accounts with.
    #[must_use]
    pub const fn transport(&self) -> TransportId {
        self.udp
    }

    /// The bound address, with the real port when zero was asked for.
    #[must_use]
    pub const fn local(&self) -> SocketAddr {
        self.local
    }

    /// The agent underneath.
    #[must_use]
    pub const fn agent(&mut self) -> &mut UserAgent {
        &mut self.agent
    }

    /// The longest one turn may wait when nothing has a deadline.
    ///
    /// 200 ms by default, so [`Handler::on_tick`] runs often. On a phone
    /// that is five wake-ups a second for nothing: `None` removes the cap,
    /// and an [`UserAgent::idle`] stack then sleeps until a packet arrives.
    /// Without a cap, [`Runtime::run`] cannot return from a turn until
    /// something arrives. See `docs/16-lifecycle.md`.
    pub const fn idle_cap(&mut self, cap: Option<Duration>) {
        self.cap = cap;
    }

    /// Round the loop until the handler says to stop.
    ///
    /// # Errors
    /// Always `Ok` (see [`Runtime::turn`]).
    pub fn run(&mut self, handler: &mut impl Handler) -> io::Result<()> {
        while self.turn(handler, Instant::now())? == Control::Continue {}
        Ok(())
    }

    /// One pass: write what is waiting, report what arrived, wait for the
    /// next packet or timer. Lets a test drive the loop with its own clock.
    ///
    /// # Errors
    /// Always `Ok`. A refused datagram is dropped; a failed stream closes
    /// itself as if the peer had closed it.
    pub fn turn(&mut self, handler: &mut impl Handler, now: Instant) -> io::Result<Control> {
        self.flush()?;
        self.report(handler, now);
        let control = handler.on_tick(&mut self.agent, now);
        // a handler that stops has usually just hung up: send the BYE first
        self.flush()?;
        if control == Control::Stop {
            return Ok(Control::Stop);
        }
        self.wait(now);
        Ok(Control::Continue)
    }
}

// -- what goes out -----------------------------------------------------------

impl Runtime {
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the Result stays so turn/run's public signature does not have to move"
    )]
    fn flush(&mut self) -> io::Result<()> {
        while let Some(transmit) = self.agent.poll_transmit() {
            let Some(link) = self.links.get(&transmit.transport) else {
                // gone transport: the transaction times out (§17)
                continue;
            };
            match *link {
                // one refused destination does not make the shared socket
                // bad; the transaction's own §17 timeout notices
                Link::Datagram(ref socket, _) => {
                    socket.send_to(&transmit.payload, transmit.destination).ok();
                }
                // a stream is one peer: a failed write ends only it
                Link::Stream(ref socket) => {
                    if io::Write::write_all(&mut socket.as_ref(), &transmit.payload).is_err() {
                        let transport = transmit.transport;
                        self.links.remove(&transport);
                        self.tell(Input::StreamClosed { transport });
                    }
                }
            }
        }
        Ok(())
    }

    fn tell(&mut self, input: Input<'_>) {
        // nothing to do about an unparsable datagram
        self.agent.receive(input, Instant::now()).ok();
    }
}

// -- what comes in -----------------------------------------------------------

impl Runtime {
    /// Hand the application everything except what this loop answers itself.
    fn report(&mut self, handler: &mut impl Handler, now: Instant) {
        while let Some(event) = self.agent.poll_event() {
            match event {
                UaEvent::Unclaimed(Event::ResolveNeeded {
                    dialog,
                    host,
                    port,
                    protocol,
                }) => {
                    if let Ok(addresses) = (self.resolver)(&host, port, protocol) {
                        if !addresses.is_empty() {
                            self.agent.endpoint().resolved(dialog, &addresses, protocol);
                        }
                    } else {
                        // the application hears the name; registrations are
                        // distrusted only if the resolver itself is gone
                        if self.resolver_is_gone(&host) {
                            self.agent.name_resolution_lost(now);
                        }
                        handler.on_event(
                            &mut self.agent,
                            UaEvent::Unclaimed(Event::ResolveNeeded {
                                dialog,
                                host,
                                port,
                                protocol,
                            }),
                            now,
                        );
                    }
                }
                // RFC 3263: no NAPTR/SRV here, so the locator falls back to
                // the host's addresses at the transport's port
                UaEvent::LookupWanted { account, query } => {
                    let answer = self.answer_lookup(&query);
                    let _ = self.agent.looked_up(account, &query, answer, now);
                }
                // reported anyway: only here does the application see the sizes
                UaEvent::Unclaimed(Event::TransportWanted {
                    protocol,
                    destination,
                    request_bytes,
                    limit_bytes,
                }) => {
                    self.open(protocol, destination);
                    handler.on_event(
                        &mut self.agent,
                        UaEvent::Unclaimed(Event::TransportWanted {
                            protocol,
                            destination,
                            request_bytes,
                            limit_bytes,
                        }),
                        now,
                    );
                }
                // RFC 5626 §4.4.1: dead flow; dropping the link closes it
                UaEvent::Unclaimed(Event::FlowFailed { transport }) => {
                    self.links.remove(&transport);
                    handler.on_event(
                        &mut self.agent,
                        UaEvent::Unclaimed(Event::FlowFailed { transport }),
                        now,
                    );
                }
                other => handler.on_event(&mut self.agent, other, now),
            }
        }
    }

    fn wait(&mut self, now: Instant) {
        let arrived = match sleep_for(self.agent.poll_timeout(), self.cap, now) {
            Some(until) => self.inbox.recv_timeout(until).ok(),
            None => self.inbox.recv().ok(),
        };
        match arrived {
            Some(arrival) => {
                self.arrived(arrival);
                // a public UDP port always has something waiting; without
                // this a due timer would never fire under steady traffic
                if self.agent.poll_timeout().is_some_and(|due| due <= now) {
                    self.agent.handle_timeout(now);
                }
            }
            None => self.agent.handle_timeout(Instant::now()),
        }
    }

    fn arrived(&mut self, arrival: Arrival) {
        match arrival {
            Arrival::Datagram {
                transport,
                remote,
                data,
            } => {
                let Some(local) = self.local_of(transport) else {
                    return;
                };
                self.tell(Input::Datagram {
                    transport,
                    remote,
                    local,
                    data: &data,
                });
            }
            Arrival::Stream { transport, data } => {
                self.tell(Input::StreamData {
                    transport,
                    data: &data,
                });
            }
            Arrival::Closed { transport } => {
                self.links.remove(&transport);
                self.tell(Input::StreamClosed { transport });
            }
        }
    }

    /// Where responses must leave from (§18.2.1).
    fn local_of(&self, transport: TransportId) -> Option<SocketAddr> {
        match self.links.get(&transport) {
            Some(&Link::Datagram(_, local)) => Some(local),
            _ => None,
        }
    }

    /// Opens a TCP stream: for §18.1.1 (too large for a datagram) or an
    /// account's own connection. A WebSocket handshake is the agent's
    /// ([`crate::websocket`]).
    fn open(&mut self, protocol: TransportProtocol, destination: SocketAddr) {
        // no TLS here
        if !matches!(protocol, TransportProtocol::Tcp | TransportProtocol::Ws) {
            return;
        }
        let Ok(socket) = TcpStream::connect(destination) else {
            return;
        };
        let Ok(local) = socket.local_addr() else {
            return;
        };
        let socket = Arc::new(socket);
        let transport = TransportId(self.next);
        self.next = self.next.saturating_add(1);
        self.links
            .insert(transport, Link::Stream(Arc::clone(&socket)));
        self.read_stream(transport, socket);
        self.tell(Input::TransportBound {
            transport,
            protocol,
            local,
            remote: Some(destination),
        });
    }

    fn read_datagrams(&self, transport: TransportId, socket: Arc<UdpSocket>) {
        let postbox = self.postbox.clone();
        thread::spawn(move || {
            let mut buffer = vec![0_u8; DATAGRAM];
            while let Ok((read, remote)) = socket.recv_from(&mut buffer) {
                let data = buffer.get(..read).unwrap_or_default().to_vec();
                if postbox
                    .send(Arrival::Datagram {
                        transport,
                        remote,
                        data,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    fn read_stream(&self, transport: TransportId, socket: Arc<TcpStream>) {
        let postbox = self.postbox.clone();
        thread::spawn(move || {
            let mut buffer = vec![0_u8; CHUNK];
            loop {
                let read = io::Read::read(&mut socket.as_ref(), &mut buffer);
                let sent = match read {
                    Ok(0) | Err(_) => postbox.send(Arrival::Closed { transport }),
                    Ok(read) => postbox.send(Arrival::Stream {
                        transport,
                        data: buffer.get(..read).unwrap_or_default().to_vec(),
                    }),
                };
                if sent.is_err() || matches!(read, Ok(0) | Err(_)) {
                    break;
                }
            }
        });
    }
}

impl Runtime {
    /// Whether the resolver is gone, not just one name unknown. `std::net`
    /// gives the same error for both, so a registrar's name is the probe:
    /// it failing too means the resolver is gone. No registrar by name means
    /// nothing to distrust.
    fn resolver_is_gone(&self, failed: &Host) -> bool {
        let registrars: Vec<(Host, Option<u16>)> = self
            .agent
            .accounts()
            .into_iter()
            .filter_map(|id| {
                let uri = self.agent.account(id)?.registrar()?.sip()?;
                matches!(uri.host, HostRef::Name(_)).then(|| (Host::from_ref(uri.host), uri.port))
            })
            .collect();
        if registrars.is_empty() {
            return false;
        }
        let same = |host: &Host| match (host, failed) {
            (Host::Name(a), Host::Name(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        };
        registrars.iter().any(|(host, _)| same(host))
            || registrars
                .iter()
                .all(|(host, port)| (self.resolver)(host, *port, None).is_err())
    }
}

impl Runtime {
    /// The system resolver has no TTL, so [`crate::locate::MIN_TTL`] is used.
    fn answer_lookup(&self, query: &Query) -> Answer {
        let family = match query.record {
            RecordType::A => AddressFamily::Ipv4,
            RecordType::Aaaa => AddressFamily::Ipv6,
            RecordType::Naptr | RecordType::Srv => return Answer::Nothing,
        };
        match (self.resolver)(&Host::Name(query.name.clone()), Some(0), None) {
            Err(_) => Answer::Failed,
            Ok(addresses) => {
                let records: Vec<Record> = addresses
                    .into_iter()
                    .map(|address| address.ip())
                    .filter(|address| AddressFamily::of(*address) == family)
                    .map(|address| Record::Address {
                        address,
                        ttl: crate::locate::MIN_TTL,
                    })
                    .collect();
                if records.is_empty() {
                    Answer::Nothing
                } else {
                    Answer::Records(records)
                }
            }
        }
    }
}

/// [`look_up`], replaceable in tests.
type Resolver = fn(&Host, Option<u16>, Option<TransportProtocol>) -> io::Result<Vec<SocketAddr>>;

/// A/AAAA only, no SRV. An IP host returns nothing.
///
/// # Errors
/// The system resolver's error: unknown name or no resolver.
fn look_up(
    host: &Host,
    port: Option<u16>,
    protocol: Option<TransportProtocol>,
) -> io::Result<Vec<SocketAddr>> {
    let Host::Name(ref name) = *host else {
        return Ok(Vec::new());
    };
    let port = port
        .or_else(|| protocol.and_then(TransportProtocol::default_port))
        .unwrap_or(5060);
    (name.as_ref(), port)
        .to_socket_addrs()
        .map(Iterator::collect)
}

#[cfg(test)]
mod tests {
    use super::{Control, Handler, IDLE, Link, Runtime, sleep_for};
    use crate::event::UaEvent;
    use crate::{Account, UserAgent};
    use sipral_core::endpoint::{EndpointConfig, Event, OutgoingRequest, TransportProtocol};
    use sipral_core::msg::{HeaderName, Method, Uri};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    /// Everything the loop handed up, in order.
    #[derive(Debug, Default)]
    struct Recorder {
        seen: Vec<UaEvent>,
    }

    impl Handler for Recorder {
        fn on_event(&mut self, _agent: &mut UserAgent, event: UaEvent, _now: Instant) {
            self.seen.push(event);
        }

        fn on_tick(&mut self, _agent: &mut UserAgent, _now: Instant) -> Control {
            Control::Stop
        }
    }

    #[test]
    fn the_application_hears_the_two_sizes_even_though_the_loop_answers_the_event() {
        let local: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("a peer address");
        let mut runtime =
            Runtime::bind(EndpointConfig::default(), [11; 32], local).expect("a loopback socket");
        let transport = runtime.transport();

        let padding = vec![b'x'; 1_400];
        let big = OutgoingRequest::new(
            Method::Options,
            Uri::parse_str("sip:bob@example.com").expect("a URI"),
            transport,
            peer,
        )
        .to(b"<sip:bob@example.com>")
        .from(b"Alice <sip:alice@127.0.0.1>")
        .header(HeaderName::Subject, &padding);
        assert!(
            runtime
                .agent()
                .endpoint()
                .request(&big, Instant::now())
                .is_err(),
            "1400 bytes of Subject does not go in a datagram"
        );

        // the endpoint was called directly: move its events up first
        let now = Instant::now();
        runtime.agent().handle_timeout(now);

        let mut recorder = Recorder::default();
        runtime.turn(&mut recorder, now).expect("a turn");
        let sizes = recorder.seen.iter().find_map(|event| match *event {
            UaEvent::Unclaimed(Event::TransportWanted {
                request_bytes,
                limit_bytes,
                ..
            }) => Some((request_bytes, limit_bytes)),
            _ => None,
        });
        assert_eq!(sizes.map(|(_, limit)| limit), Some(1_300), "{recorder:?}");
        assert!(sizes.is_some_and(|(size, _)| size > 1_400), "{sizes:?}");
    }

    #[test]
    fn a_deadline_is_never_slept_past_however_generous_the_cap_is() {
        let t0 = Instant::now();
        let soon = t0 + Duration::from_millis(20);
        assert_eq!(
            sleep_for(Some(soon), Some(IDLE), t0),
            Some(Duration::from_millis(20))
        );
        assert_eq!(
            sleep_for(Some(soon), None, t0),
            Some(Duration::from_millis(20))
        );
        let overdue = t0.checked_sub(Duration::from_secs(1)).expect("a past time");
        assert_eq!(
            sleep_for(Some(overdue), Some(IDLE), t0),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn a_stack_with_nothing_scheduled_and_no_cap_waits_for_a_packet() {
        let t0 = Instant::now();
        assert_eq!(sleep_for(None, None, t0), None);
        assert_eq!(sleep_for(None, Some(IDLE), t0), Some(IDLE));
    }

    #[test]
    fn the_cap_is_what_the_application_last_said_it_was() {
        let local: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        let mut runtime =
            Runtime::bind(EndpointConfig::default(), [12; 32], local).expect("a loopback socket");
        assert_eq!(runtime.cap, Some(IDLE));
        runtime.idle_cap(None);
        assert_eq!(runtime.cap, None);
        runtime.idle_cap(Some(Duration::from_secs(5)));
        assert_eq!(runtime.cap, Some(Duration::from_secs(5)));
    }

    #[derive(Debug)]
    struct Busy;

    impl Handler for Busy {
        fn on_event(&mut self, _agent: &mut UserAgent, _event: UaEvent, _now: Instant) {}
        fn on_tick(&mut self, _agent: &mut UserAgent, _now: Instant) -> Control {
            Control::Continue
        }
    }

    #[test]
    fn timers_still_run_while_datagrams_keep_arriving() {
        let local: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("a peer address");
        let mut runtime =
            Runtime::bind(EndpointConfig::default(), [13; 32], local).expect("a loopback socket");
        let transport = runtime.transport();
        let t0 = Instant::now();
        let request = OutgoingRequest::new(
            Method::Options,
            Uri::parse_str("sip:bob@example.com").expect("a URI"),
            transport,
            peer,
        )
        .to(b"<sip:bob@example.com>")
        .from(b"Alice <sip:alice@127.0.0.1>");
        runtime
            .agent()
            .endpoint()
            .request(&request, t0)
            .expect("the OPTIONS goes");
        let deadline = runtime
            .agent()
            .poll_timeout()
            .expect("a transaction that has just been sent has a deadline");

        let mut busy = Busy;
        let late = deadline + Duration::from_secs(600);
        for _ in 0..8 {
            runtime
                .postbox
                .send(super::Arrival::Datagram {
                    transport,
                    remote: peer,
                    data: b"this is not a SIP message\r\n\r\n".to_vec(),
                })
                .expect("the channel is open");
            runtime.turn(&mut busy, late).expect("a turn");
        }

        let after = runtime.agent().poll_timeout();
        assert!(
            after.is_none_or(|at| at > late),
            "a deadline ten minutes past is still not run: {:?} behind",
            after.map(|at| late.saturating_duration_since(at))
        );
    }

    #[test]
    fn a_send_that_failed_does_not_end_the_loop() {
        let local: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        let mut runtime =
            Runtime::bind(EndpointConfig::default(), [15; 32], local).expect("a loopback socket");
        let transport = runtime.transport();
        let refused: SocketAddr = "255.255.255.255:9".parse().expect("an address");
        let now = Instant::now();
        let request = OutgoingRequest::new(
            Method::Options,
            Uri::parse_str("sip:bob@example.com").expect("a URI"),
            transport,
            refused,
        )
        .to(b"<sip:bob@example.com>")
        .from(b"Alice <sip:alice@127.0.0.1>");
        runtime
            .agent()
            .endpoint()
            .request(&request, now)
            .expect("the OPTIONS goes");

        let mut busy = Busy;
        let outcome = runtime.turn(&mut busy, now);
        assert!(
            outcome.is_ok(),
            "one datagram that would not go ends the whole user agent: {outcome:?}"
        );
    }

    #[test]
    fn a_stream_that_will_not_take_a_write_is_the_one_thing_that_ends() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let peer = listener.local_addr().expect("its address");
        let local: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        let mut runtime =
            Runtime::bind(EndpointConfig::default(), [16; 32], local).expect("a loopback socket");

        runtime.open(TransportProtocol::Tcp, peer);
        let _peer_stays = listener.accept().expect("the connection arrives");
        let stream = runtime
            .links
            .iter()
            .find(|(_, link)| matches!(link, Link::Stream(_)))
            .map(|(transport, _)| *transport)
            .expect("the stream was linked");

        // only the write half: a full shutdown would end the stream on the
        // read path and leave the write path untested
        if let Some(Link::Stream(socket)) = runtime.links.get(&stream) {
            socket
                .shutdown(std::net::Shutdown::Write)
                .expect("the write half shuts down");
        }

        let now = Instant::now();
        let request = OutgoingRequest::new(
            Method::Options,
            Uri::parse_str("sip:bob@example.com").expect("a URI"),
            stream,
            peer,
        )
        .to(b"<sip:bob@example.com>")
        .from(b"Alice <sip:alice@127.0.0.1>");
        runtime
            .agent()
            .endpoint()
            .request(&request, now)
            .expect("the OPTIONS goes");

        let mut busy = Busy;
        let outcome = runtime.turn(&mut busy, now);
        assert!(
            outcome.is_ok(),
            "a write that failed ended the whole user agent: {outcome:?}"
        );
        assert!(
            !runtime.links.contains_key(&stream),
            "the connection that refused the write is still linked"
        );
    }

    fn no_resolver(
        _host: &sipral_core::endpoint::Host,
        _port: Option<u16>,
        _protocol: Option<TransportProtocol>,
    ) -> std::io::Result<Vec<SocketAddr>> {
        Err(std::io::Error::other("no resolver to ask"))
    }

    fn field(message: &str, name: &str) -> String {
        message
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
            .unwrap_or_default()
            .to_owned()
    }

    /// Knows only the registrar; `callee.invalid` exists nowhere (RFC 2606).
    fn knows_the_registrar(
        host: &sipral_core::endpoint::Host,
        _port: Option<u16>,
        _protocol: Option<TransportProtocol>,
    ) -> std::io::Result<Vec<SocketAddr>> {
        match *host {
            sipral_core::endpoint::Host::Name(ref name) if &**name == "registrar.example" => {
                Ok(vec!["127.0.0.1:5060".parse().expect("an address")])
            }
            _ => Err(std::io::Error::other("no such name")),
        }
    }

    /// A call answered with `Contact: <sip:bob@callee.invalid>`, turned until
    /// that name was looked up with `resolver`.
    fn answered_by_a_name(resolver: super::Resolver) -> (Runtime, Recorder) {
        let far = std::net::UdpSocket::bind("127.0.0.1:0").expect("a far end");
        far.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a read timeout");
        let far_address = far.local_addr().expect("its address");
        let local: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        let mut runtime =
            Runtime::bind(EndpointConfig::default(), [17; 32], local).expect("a loopback socket");
        runtime.resolver = resolver;
        let transport = runtime.transport();
        runtime.agent().add_account(Account::new(
            Uri::parse_str("sip:alice@registrar.example").expect("a URI"),
            Uri::parse_str("sip:registrar.example").expect("a URI"),
            Uri::parse_str("sip:alice@127.0.0.1").expect("a URI"),
            transport,
            far_address,
        ));
        let t0 = Instant::now();
        let invite = OutgoingRequest::new(
            Method::Invite,
            Uri::parse_str("sip:bob@127.0.0.1").expect("a URI"),
            transport,
            far_address,
        )
        .to(b"<sip:bob@127.0.0.1>")
        .from(b"Alice <sip:alice@127.0.0.1>")
        .contact(b"<sip:alice@127.0.0.1>");
        runtime
            .agent()
            .endpoint()
            .invite(&invite, t0)
            .expect("the INVITE goes");
        let mut recorder = Recorder::default();
        runtime.turn(&mut recorder, t0).expect("a turn");

        let mut buffer = [0_u8; 4_096];
        let (read, _) = far.recv_from(&mut buffer).expect("the INVITE arrives");
        let request = String::from_utf8_lossy(buffer.get(..read).unwrap_or_default()).into_owned();
        let answer = format!(
            "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=far\r\nCall-ID: {}\r\n\
             CSeq: {}\r\nContact: <sip:bob@callee.invalid>\r\nContent-Length: 0\r\n\r\n",
            field(&request, "Via"),
            field(&request, "From"),
            field(&request, "To"),
            field(&request, "Call-ID"),
            field(&request, "CSeq"),
        );
        far.send_to(answer.as_bytes(), runtime.local())
            .expect("the answer goes");

        let mut at = t0;
        for _ in 0..20 {
            if recorder
                .seen
                .iter()
                .any(|event| matches!(*event, UaEvent::Unclaimed(Event::ResolveNeeded { .. })))
            {
                break;
            }
            // the recorder stops before the wait, so wait here
            at += Duration::from_millis(10);
            runtime.wait(at);
            runtime.turn(&mut recorder, at).expect("a turn");
        }
        let asked = recorder.seen.iter().find_map(|event| match *event {
            UaEvent::Unclaimed(Event::ResolveNeeded { ref host, .. }) => Some(host.to_string()),
            _ => None,
        });
        assert_eq!(
            asked.as_deref(),
            Some("callee.invalid"),
            "the name that did not resolve never reached the application: {:?}",
            recorder.seen
        );
        (runtime, recorder)
    }

    #[test]
    fn a_registrar_given_by_name_is_located_and_registered_with() {
        let far = std::net::UdpSocket::bind("127.0.0.1:0").expect("a registrar");
        far.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a read timeout");
        let port = far.local_addr().expect("its address").port();
        let local: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        let mut runtime =
            Runtime::bind(EndpointConfig::default(), [19; 32], local).expect("a loopback socket");
        runtime.resolver = knows_the_registrar;
        let transport = runtime.transport();
        let t0 = Instant::now();
        let id = runtime.agent().add_account(Account::located(
            Uri::parse_str("sip:alice@registrar.example").expect("a URI"),
            Uri::parse_str(&format!("sip:registrar.example:{port}")).expect("a URI"),
            Uri::parse_str("sip:alice@127.0.0.1").expect("a URI"),
            transport,
        ));
        runtime
            .agent()
            .register(id, t0)
            .expect("the REGISTER waits");
        let mut recorder = Recorder::default();
        runtime.turn(&mut recorder, t0).expect("a turn");
        let mut buffer = [0_u8; 4_096];
        let (read, _) = far.recv_from(&mut buffer).expect("the REGISTER arrives");
        assert!(
            buffer
                .get(..read)
                .unwrap_or_default()
                .starts_with(b"REGISTER sip:registrar.example:"),
            "{:?}",
            recorder.seen
        );
        assert_eq!(
            runtime.agent().located_targets(id),
            [SocketAddr::from(([127, 0, 0, 1], port))]
        );
    }

    #[test]
    fn a_name_the_resolver_cannot_answer_is_reported_and_not_dropped() {
        let (mut runtime, recorder) = answered_by_a_name(no_resolver);
        assert_eq!(
            runtime.agent().lifecycle(),
            crate::LifecycleState::ResolutionLost,
            "the agent was never told its names stopped resolving"
        );
        assert!(
            recorder.seen.iter().any(|event| matches!(
                *event,
                UaEvent::Lifecycle {
                    state: crate::LifecycleState::ResolutionLost,
                    ..
                }
            )),
            "{:?}",
            recorder.seen
        );
    }

    /// One unknown name from a far end is not a lost resolver.
    #[test]
    fn a_name_that_does_not_exist_leaves_the_registrations_trusted() {
        let (mut runtime, recorder) = answered_by_a_name(knows_the_registrar);
        assert_ne!(
            runtime.agent().lifecycle(),
            crate::LifecycleState::ResolutionLost,
            "one unknown name was taken for a resolver that had gone: {:?}",
            recorder.seen
        );
        assert!(
            !recorder
                .seen
                .iter()
                .any(|event| matches!(*event, UaEvent::Lifecycle { .. })),
            "{:?}",
            recorder.seen
        );
    }
}
