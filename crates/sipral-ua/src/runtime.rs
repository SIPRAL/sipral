// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The reference loop: sockets, a thread each, and the five calls.
//!
//! Nothing else in this tree opens a socket, and that is the design rather
//! than an omission — a stack that owns its I/O imposes its runtime on
//! everyone who embeds it. What is here is the plainest thing that closes the
//! gap: `std::net`, blocking reads, one thread per socket feeding a channel,
//! and a loop that does what [`crate::UserAgent`] asks. It exists so that the
//! first call anyone makes with Sipral takes twenty lines, and so that the
//! bindings have something to mirror.
//!
//! It is behind a feature flag and off by default, because two things it does
//! not do are things a real deployment needs.
//!
//! **NAPTR and SRV.** `std::net` resolves a name to addresses and nothing
//! else, so [`Event::ResolveNeeded`] is answered with what
//! `ToSocketAddrs` gives back and the RFC 3263 ordering never happens. A
//! deployment that reaches a carrier through SRV supplies its own resolver —
//! every platform has one, and on a phone it is the only one allowed to answer
//! while the radio is asleep.
//!
//! **TLS.** No implementation is linked here and none will be.
//! `TransportProtocol::Tls` describes a transport the caller has already
//! secured; this loop opens plain TCP and plain UDP, and stops there.
//!
//! One more thing it does not do, and this one is `std::net`'s fault: a
//! datagram socket cannot say which of several local addresses a packet
//! arrived on without `IP_PKTINFO`, which the standard library does not
//! expose. RFC 3581 §4 needs that address to answer from the right one, so
//! this loop binds to an address you name rather than to a wildcard. A stack
//! listening on every interface writes its own loop, which is a dozen lines
//! over a real socket API.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{EndpointConfig, Event, Host, Input, TransportId, TransportProtocol};

use crate::agent::UserAgent;
use crate::event::UaEvent;

/// The largest datagram worth reading. A SIP message over UDP that does not
/// fit has already been moved to a stream by §18.1.1.
const DATAGRAM: usize = 65_535;
/// How much of a stream to take at once. Messages are found by
/// `Content-Length` further down, so the size here is only a buffer.
const CHUNK: usize = 8_192;
/// How long to sit in a read when nothing has a deadline, so that
/// [`Handler::on_tick`] still runs on a quiet line.
const IDLE: Duration = Duration::from_millis(200);

/// How long one turn may sit in a read.
///
/// `None` means until a deadline or a packet, and on a stack with no call and
/// nothing scheduled that is for ever. Separated out so that the arithmetic —
/// which is all this decision is — can be tested without waiting for any of it.
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
    /// Something happened. The agent is here too, because the answer to an
    /// event is usually to tell it something: answer the call, hang up, hold.
    fn on_event(&mut self, agent: &mut UserAgent, event: UaEvent, now: Instant);

    /// Called once round every loop, whether or not anything arrived. This is
    /// where an application does what nothing prompted it to do — place a
    /// call, and decide when it has had enough.
    fn on_tick(&mut self, agent: &mut UserAgent, now: Instant) -> Control {
        let _ = (agent, now);
        Control::Continue
    }
}

/// One socket the loop owns.
#[derive(Debug)]
enum Link {
    /// A datagram socket, with the address it was bound to.
    Datagram(Arc<UdpSocket>, SocketAddr),
    /// One connection.
    Stream(Arc<TcpStream>),
}

/// What a reader thread found.
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
}

impl Runtime {
    /// Bind a UDP socket and put a user agent on it.
    ///
    /// `local` is an address, not a wildcard: see the note at the top of this
    /// module. `seed` is the endpoint's thirty-two bytes of entropy.
    ///
    /// # Errors
    /// Whatever binding the socket returns.
    pub fn bind(config: EndpointConfig, seed: [u8; 32], local: SocketAddr) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(local)?);
        let local = socket.local_addr()?;
        let (postbox, inbox) = channel();
        let udp = TransportId(1);

        let mut runtime = Self {
            agent: UserAgent::new(config, seed),
            links: HashMap::new(),
            inbox,
            postbox,
            udp,
            local,
            next: 2,
            cap: Some(IDLE),
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

    /// The UDP transport, which is what an account is configured with.
    #[must_use]
    pub const fn transport(&self) -> TransportId {
        self.udp
    }

    /// The address it ended up on, which matters when port zero was asked for.
    #[must_use]
    pub const fn local(&self) -> SocketAddr {
        self.local
    }

    /// The agent underneath: accounts, calls, everything.
    #[must_use]
    pub const fn agent(&mut self) -> &mut UserAgent {
        &mut self.agent
    }

    /// The longest one turn may wait when nothing has a deadline.
    ///
    /// Two hundred milliseconds by default, so that [`Handler::on_tick`] runs
    /// often enough for an application to do what nothing prompted it to do.
    /// That is five wake-ups a second on a line where nothing is happening,
    /// which is the wrong trade on a phone in somebody's pocket: `None`
    /// removes the cap, and a turn then waits for a deadline or for a packet.
    /// On a stack with no call and nothing scheduled — which is what
    /// [`UserAgent::idle`] answers — there is neither, so the turn waits
    /// indefinitely and the process costs nothing until something arrives.
    ///
    /// An application that removes the cap has to make sure something will
    /// arrive, because [`Runtime::run`] cannot come out of a turn that is
    /// waiting for ever. See `docs/16-lifecycle.md`.
    pub const fn idle_cap(&mut self, cap: Option<Duration>) {
        self.cap = cap;
    }

    /// Round the loop until the handler says to stop.
    ///
    /// # Errors
    /// Always `Ok`. A transmit that a socket refuses is not this loop's to
    /// stop over: see [`Runtime::turn`].
    pub fn run(&mut self, handler: &mut impl Handler) -> io::Result<()> {
        while self.turn(handler, Instant::now())? == Control::Continue {}
        Ok(())
    }

    /// One pass: write what is waiting, report what arrived, wait for the
    /// next thing or for a timer.
    ///
    /// Separate from [`Runtime::run`] so that a test can drive it a step at a
    /// time and say what the clock reads.
    ///
    /// # Errors
    /// Always `Ok`. A datagram one destination refuses is not the socket's
    /// fault and does not end the loop; a stream that fails closes itself,
    /// reported the same way a read that found nothing on the wire is.
    /// Kept as a `Result` so a caller already matching on one need not change.
    pub fn turn(&mut self, handler: &mut impl Handler, now: Instant) -> io::Result<Control> {
        self.flush()?;
        self.report(handler, now);
        let control = handler.on_tick(&mut self.agent, now);
        // before the answer, not after: a handler that stops has usually just
        // hung up, and a BYE that is still in the queue when the loop ends is
        // a call the far end keeps for as long as it runs
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
    // no transmit failure reaches a caller from here any more: a datagram
    // is swallowed and a stream closes itself through the ordinary
    // `Input::StreamClosed` path, so nothing is left for `Result` to carry.
    // `Runtime::turn` and `Runtime::run` keep their `io::Result` regardless,
    // so that nobody who already matches on it has to change
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the Result stays so turn/run's public signature does not have to move"
    )]
    fn flush(&mut self) -> io::Result<()> {
        while let Some(transmit) = self.agent.poll_transmit() {
            let Some(link) = self.links.get(&transmit.transport) else {
                // a transport that has gone. §17 has the transaction find out
                // by timing out, which is what happens if nothing is said
                continue;
            };
            match *link {
                // one destination refusing a datagram says nothing about the
                // others sharing this socket -- a broadcast that needs a
                // permission this process was never given, or a route that
                // does not exist for one peer, does not make the socket
                // itself bad. Silence and a transaction's own §17 timeout is
                // how the failure is noticed, same as the missing link above
                Link::Datagram(ref socket, _) => {
                    socket.send_to(&transmit.payload, transmit.destination).ok();
                }
                // a stream is one connection to one peer, so a write that
                // fails means that connection, and nothing else, is over --
                // the same ending a closed read reports through `arrived`
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
        // a datagram that will not parse is not an error the loop can do
        // anything about, and the far end is not going to hear about it either
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
                    ref host,
                    port,
                    protocol,
                }) => {
                    let addresses = look_up(host, port, protocol);
                    if !addresses.is_empty() {
                        self.agent.endpoint().resolved(dialog, &addresses);
                    }
                }
                // opened here, and reported anyway: the two sizes on it are
                // the only place the application ever sees how large the
                // request that did not fit was
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
                // RFC 5626 §4.4.1 called the flow dead. The endpoint has
                // already forgotten it; the socket is this loop's, and dropping
                // the last handle to it is what closes it
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

    /// Wait for something to arrive, or for the next deadline.
    fn wait(&mut self, now: Instant) {
        let arrived = match sleep_for(self.agent.poll_timeout(), self.cap, now) {
            Some(until) => self.inbox.recv_timeout(until).ok(),
            None => self.inbox.recv().ok(),
        };
        match arrived {
            Some(arrival) => {
                self.arrived(arrival);
                // a socket that always has something waiting is what a UDP
                // port on the open internet looks like, and `arrived` never
                // runs a timer -- a deadline already due when this turn
                // started otherwise never fires as long as datagrams keep
                // coming
                if self.agent.poll_timeout().is_some_and(|due| due <= now) {
                    self.agent.handle_timeout(now);
                }
            }
            // nothing came, or every reader thread is gone. Either way the
            // timers still have to run: that is how a transaction finds out
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

    /// The address a datagram transport is bound to, which is what §18.2.1
    /// makes the address a response has to leave from.
    fn local_of(&self, transport: TransportId) -> Option<SocketAddr> {
        match self.links.get(&transport) {
            Some(&Link::Datagram(_, local)) => Some(local),
            _ => None,
        }
    }

    /// §18.1.1's switch: a message too large for a datagram needs a stream,
    /// and opening one is the caller's.
    fn open(&mut self, protocol: TransportProtocol, destination: SocketAddr) {
        // TLS is a transport the caller secures; this loop does not link one
        if protocol != TransportProtocol::Tcp {
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

/// The addresses a name stands for.
///
/// An A lookup and nothing else: the ordering RFC 3263 asks for needs SRV,
/// which `std::net` cannot ask for. A host that is already an address needs no
/// answer at all, and gets none.
fn look_up(host: &Host, port: Option<u16>, protocol: Option<TransportProtocol>) -> Vec<SocketAddr> {
    let Host::Name(ref name) = *host else {
        return Vec::new();
    };
    let port = port
        .or_else(|| protocol.and_then(TransportProtocol::default_port))
        .unwrap_or(5060);
    (name.as_ref(), port)
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{Control, Handler, IDLE, Link, Runtime, sleep_for};
    use crate::UserAgent;
    use crate::event::UaEvent;
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
        // this loop opens the connection itself, and an event it swallowed
        // would take the only two numbers that explain the failure with it
        let local: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
        // discard, and nothing is listening on it here either
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

        // the endpoint is asked directly here, so nothing has yet moved its
        // events up into the user agent's own queue; a turn of the loop would
        // do it after waiting out an idle read
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
        // a deadline already past does not become a wait
        let overdue = t0.checked_sub(Duration::from_secs(1)).expect("a past time");
        assert_eq!(
            sleep_for(Some(overdue), Some(IDLE), t0),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn a_stack_with_nothing_scheduled_and_no_cap_waits_for_a_packet() {
        // C5: the whole cost of an idle turn, and there is none
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

    /// A handler that keeps the loop going and does nothing else.
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
        // one datagram waiting on every turn is what a UDP port on the public
        // internet looks like, and `wait` ran the timers only when nothing
        // came
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
        // `flush` used `?`, so one datagram the kernel refused came out of
        // `run` as an io::Error with every call, registration and
        // subscription frozen behind it -- and the datagram it had already
        // taken off the queue was gone
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
        // the other half of the same repair, and the half that is not
        // symmetric with it: a datagram socket serves every peer, so one
        // refusal says nothing about the rest, but a stream is one connection
        // to one peer. A write that fails means that connection is over and
        // nothing else is
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

        // only this end's write half, and the peer is deliberately kept
        // alive: shutting the whole socket would have the reader thread see
        // the end of the stream and report it, and then this test would pass
        // on the read path while the write path it names went untested. It
        // did, the first time it was written.
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
}
