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

    /// Round the loop until the handler says to stop.
    ///
    /// # Errors
    /// A socket that cannot be written to.
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
    /// A socket that cannot be written to.
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
    fn flush(&mut self) -> io::Result<()> {
        while let Some(transmit) = self.agent.poll_transmit() {
            let Some(link) = self.links.get(&transmit.transport) else {
                // a transport that has gone. §17 has the transaction find out
                // by timing out, which is what happens if nothing is said
                continue;
            };
            match *link {
                Link::Datagram(ref socket, _) => {
                    socket.send_to(&transmit.payload, transmit.destination)?;
                }
                Link::Stream(ref socket) => {
                    io::Write::write_all(&mut socket.as_ref(), &transmit.payload)?;
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
                UaEvent::Unclaimed(Event::TransportWanted {
                    protocol,
                    destination,
                }) => self.open(protocol, destination),
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
        let until = self
            .agent
            .poll_timeout()
            .map_or(IDLE, |at| at.saturating_duration_since(now).min(IDLE));
        match self.inbox.recv_timeout(until) {
            Ok(arrival) => self.arrived(arrival),
            // nothing came, or every reader thread is gone. Either way the
            // timers still have to run: that is how a transaction finds out
            Err(_) => self.agent.handle_timeout(Instant::now()),
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
