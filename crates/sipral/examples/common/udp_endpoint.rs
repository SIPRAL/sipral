// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A user agent and a media engine over a plain UDP SIP socket: the plumbing `call.rs`,
//! `register-and-call.rs` and `headless-agent.rs` share. `tls.rs` uses another transport and has
//! its own.
//!
//! `sipral::MediaEngine::poll_event` is the only place events may be drained (it drains the agent
//! too), so the event loop is: bind a socket, start a user agent on it, then repeatedly flush,
//! drain and read.
//!
//! Included into each example with `#[path = "common/udp_endpoint.rs"]`. No single example uses
//! every method, so `dead_code` is allowed here rather than inventing uses.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sipral::{
    AccountId, CallHandle, Event, Input, MediaEngine, Transmit, TransportId, TransportProtocol,
    UserAgent,
};

use crate::media_socket::MediaSocket;

/// A user agent and a media engine with a real UDP socket for SIP under them.
pub(crate) struct Endpoint {
    pub(crate) agent: UserAgent,
    pub(crate) engine: MediaEngine,
    sip: UdpSocket,
    pub(crate) local: SocketAddr,
    pub(crate) transport: TransportId,
    /// One RTP socket per call with media, opened before placing or answering so its port can go in
    /// the SDP.
    pub(crate) media: HashMap<CallHandle, MediaSocket>,
    sip_inbox: Vec<u8>,
    /// The thread reading the SIP socket, once [`Endpoint::read_in_background`] started it; until
    /// then the loop reads the socket itself.
    reader: Option<Reader>,
    /// Output the agent wrote for a transport other than this socket (a connection the example
    /// opened itself), oldest first, for the example to send. Empty in single-transport examples.
    pub(crate) elsewhere: VecDeque<Transmit>,
    /// Every SIP datagram read, once set to `Some`, for tests that need a header no event carries.
    pub(crate) tap: Option<Vec<Vec<u8>>>,
}

/// One SIP datagram as the reader thread took it off the socket.
type Datagram = (Vec<u8>, SocketAddr);

/// How long the reader thread blocks before checking that the socket is still the endpoint's. A
/// retired socket is normally woken at once by an empty datagram ([`Reader`]'s `Drop`); this bounds
/// how long it stays bound when that datagram cannot arrive (the address left with the network).
/// Long, so an idle reader wakes twelve times a minute.
const READER_LOOK: Duration = Duration::from_secs(5);

/// Pause after a read error other than a timeout, so a repeating failure cannot spin.
const READER_PAUSE: Duration = Duration::from_millis(10);

/// The SIP socket read on its own thread, each datagram sent over a channel.
///
/// Waiting on the socket uses `SO_RCVTIMEO`, which Linux counts in scheduler ticks: a 5 ms wait at
/// 250 Hz ends 4 to 8 ms later. A channel wait ends at its deadline within timer slack, and
/// immediately when a datagram arrives. One thread per process regardless of call count.
struct Reader {
    inbox: mpsc::Receiver<Datagram>,
    /// Taken off the channel by a wait, not yet handed to the user agent.
    held: VecDeque<Datagram>,
    /// Set when the socket is no longer the endpoint's; the thread notices at its next read and
    /// exits, closing its copy.
    retired: Arc<AtomicBool>,
    /// The socket's bound address, where `Drop` sends the wake-up.
    bound: SocketAddr,
}

impl Reader {
    /// Start a thread reading `sip`, switched to blocking reads with a [`READER_LOOK`] timeout. The
    /// endpoint only writes to it afterwards, which works the same on a blocking socket.
    fn spawn(sip: &UdpSocket) -> std::io::Result<Self> {
        let socket = sip.try_clone()?;
        socket.set_nonblocking(false)?;
        socket.set_read_timeout(Some(READER_LOOK))?;
        let bound = socket.local_addr()?;
        let (sender, inbox) = mpsc::channel();
        let retired = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&retired);
        std::thread::Builder::new()
            .name("sip-reader".to_owned())
            .spawn(move || {
                let mut buffer = vec![0_u8; 65_535];
                while !seen.load(Ordering::Relaxed) {
                    match socket.recv_from(&mut buffer) {
                        // anything after retirement, including the wake-up datagram, is no longer
                        // the endpoint's
                        Ok(_) if seen.load(Ordering::Relaxed) => return,
                        Ok((length, from)) => {
                            let data = buffer.get(..length).unwrap_or_default().to_vec();
                            // the endpoint is gone; so is the thread
                            if sender.send((data, from)).is_err() {
                                return;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::WouldBlock | ErrorKind::TimedOut
                            ) => {}
                        // other datagram socket errors concern one datagram, not the socket
                        Err(_) => std::thread::sleep(READER_PAUSE),
                    }
                }
            })?;
        Ok(Self {
            inbox,
            held: VecDeque::new(),
            retired,
            bound,
        })
    }

    /// Wait for the next datagram until `until`, or indefinitely with `None`. `false` when the
    /// thread has ended.
    fn wait(&mut self, until: Option<Instant>) -> bool {
        if !self.held.is_empty() {
            return true;
        }
        let got = match until {
            Some(until) => match until.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => self.inbox.recv_timeout(left),
                _ => return true,
            },
            None => self
                .inbox
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
        };
        match got {
            Ok(datagram) => {
                self.held.push_back(datagram);
                true
            }
            Err(mpsc::RecvTimeoutError::Timeout) => true,
            Err(mpsc::RecvTimeoutError::Disconnected) => false,
        }
    }

    /// The next datagram already read, without waiting.
    fn take(&mut self) -> Option<Datagram> {
        self.held.pop_front().or_else(|| self.inbox.try_recv().ok())
    }
}

impl Drop for Reader {
    /// Retire the thread and wake its read with an empty datagram, so it ends now rather than after
    /// [`READER_LOOK`].
    fn drop(&mut self) {
        self.retired.store(true, Ordering::Relaxed);
        let to = if self.bound.ip().is_unspecified() {
            SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), self.bound.port())
        } else {
            self.bound
        };
        let _ =
            UdpSocket::bind(SocketAddr::new(to.ip(), 0)).and_then(|waker| waker.send_to(&[], to));
    }
}

impl Endpoint {
    /// Bind the SIP socket and start a user agent on it. `bind_addr` should be routable
    /// ([`route_to`] finds one), not a wildcard: it is the endpoint's own address and, through
    /// [`Endpoint::open_media`], the media address calls advertise.
    pub(crate) fn bind(
        bind_addr: SocketAddr,
        mut agent: UserAgent,
        engine: MediaEngine,
        now: Instant,
    ) -> std::io::Result<Self> {
        let sip = UdpSocket::bind(bind_addr)?;
        sip.set_nonblocking(true)?;
        let local = sip.local_addr()?;
        let transport = TransportId(1);
        // §18.1.1: a transport must be reported open, with its address, before anything is written
        // to it
        let _ = agent.receive(
            Input::TransportBound {
                transport,
                protocol: TransportProtocol::Udp,
                local,
                remote: None,
            },
            now,
        );
        Ok(Self {
            agent,
            engine,
            sip,
            local,
            transport,
            media: HashMap::new(),
            sip_inbox: vec![0_u8; 65_535],
            reader: None,
            elsewhere: VecDeque::new(),
            tap: None,
        })
    }

    /// From now on read SIP on a thread, so [`Endpoint::wait_sip`] waits on a channel that ends on
    /// time rather than on scheduler ticks ([`Reader`]). [`Endpoint::read_sip`] takes what it read,
    /// and [`Endpoint::rebind_sip`] starts a new thread on the new socket.
    ///
    /// # Errors
    ///
    /// Cloning the socket, switching it to blocking, or starting the thread.
    pub(crate) fn read_in_background(&mut self) -> std::io::Result<()> {
        self.reader = Some(Reader::spawn(&self.sip)?);
        Ok(())
    }

    /// Bind a fresh RTP socket for a call about to be placed or answered, and return the media
    /// address for its SDP.
    pub(crate) fn open_media(
        &mut self,
        call: CallHandle,
        now: Instant,
    ) -> std::io::Result<SocketAddr> {
        let media = MediaSocket::bind(now)?;
        let port = media.port()?;
        self.media.insert(call, media);
        Ok(SocketAddr::new(self.local.ip(), port))
    }

    /// Rebind the SIP socket at `ip` on the same port and tell the agent its transport is open
    /// there, which an application does first when its old address is gone. Returns the new socket
    /// address.
    ///
    /// # Errors
    ///
    /// Binding, or the agent refusing the transport.
    pub(crate) fn rebind_sip(
        &mut self,
        ip: std::net::IpAddr,
        now: Instant,
    ) -> Result<SocketAddr, String> {
        let sip = UdpSocket::bind(SocketAddr::new(ip, self.local.port()))
            .or_else(|_| UdpSocket::bind(SocketAddr::new(ip, 0)))
            .map_err(|error| format!("cannot bind at {ip}: {error}"))?;
        sip.set_nonblocking(true)
            .map_err(|error| format!("cannot make the SIP socket non-blocking: {error}"))?;
        let local = sip
            .local_addr()
            .map_err(|error| format!("the SIP socket has no address: {error}"))?;
        self.agent
            .receive(
                Input::TransportBound {
                    transport: self.transport,
                    protocol: TransportProtocol::Udp,
                    local,
                    remote: None,
                },
                now,
            )
            .map_err(|error| format!("cannot bind the transport again: {error}"))?;
        if let Some(old) = self.reader.as_mut() {
            // datagrams already sent to the old socket are still this agent's and are handed over
            // first
            let mut new = Reader::spawn(&sip)
                .map_err(|error| format!("cannot read the new SIP socket: {error}"))?;
            while let Some(datagram) = old.take() {
                new.held.push_back(datagram);
            }
            self.reader = Some(new);
        }
        self.sip = sip;
        self.local = local;
        Ok(local)
    }

    /// Re-offer `call` from the endpoint's current address on its existing RTP port, answering
    /// `UaEvent::CallAddressWanted` after [`Endpoint::rebind_sip`]. RTP sockets are bound to the
    /// wildcard, so they keep receiving; only the description changes. Failures go to stderr.
    pub(crate) fn readdress(&mut self, call: CallHandle, now: Instant) {
        let Some(port) = self.media.get(&call).and_then(|media| media.port().ok()) else {
            eprintln!("{call:?} has no media socket to offer again");
            return;
        };
        let local = SocketAddr::new(self.local.ip(), port);
        if let Err(error) = self
            .engine
            .readdress(&mut self.agent, call, local, None, now)
        {
            eprintln!("cannot offer {call:?} again at {local}: {error}");
        }
    }

    /// Drop a call's RTP socket after the call ended. Short-lived examples like `call.rs` never
    /// notice; a long-running one like `headless-agent.rs` leaks a socket per call without it, so
    /// call this on `CallEnded`.
    pub(crate) fn close_media(&mut self, call: CallHandle) {
        self.media.remove(&call);
    }

    /// Write what is waiting, and drain every event the engine has.
    pub(crate) fn pump(&mut self, now: Instant) -> Vec<Event> {
        self.flush();
        let mut events = Vec::new();
        while let Some(event) = self.engine.poll_event(&mut self.agent, now) {
            events.push(event);
        }
        events
    }

    fn flush(&mut self) {
        while let Some(transmit) = self.agent.poll_transmit() {
            if transmit.transport == self.transport {
                let _ = self.sip.send_to(&transmit.payload, transmit.destination);
            } else {
                self.elsewhere.push_back(transmit);
            }
        }
    }

    /// Run one media tick for every active call, passing its socket and session to `per_call` (a
    /// device, a WAV file or an echo), and send whatever the engine queued for the call (RTCP, a
    /// BYE, a DTLS record).
    pub(crate) fn run_media(
        &mut self,
        now: Instant,
        mut per_call: impl FnMut(CallHandle, &mut MediaSocket, &mut sipral::MediaSession, Instant),
    ) {
        for call in self.engine.active().collect::<Vec<_>>() {
            let Some(mut session) = self.engine.session(call) else {
                continue;
            };
            if let Some(media) = self.media.get_mut(&call) {
                per_call(call, media, &mut session, now);
            }
            // `session` (a `SessionGuard`) derefs to the `&mut MediaSession` that `per_call`
            // receives
        }
        while let Some((call, destination, payload)) = self.engine.poll_rtcp(now) {
            if let Some(media) = self.media.get(&call) {
                media.send_rtcp(destination, &payload);
            }
        }
        while let Some((call, destination, payload)) = self.engine.poll_farewell() {
            if let Some(media) = self.media.get(&call) {
                media.send_rtcp(destination, &payload);
            }
        }
        // `MediaEngine::poll_transmit` exists only with `dtls` or `ice`
        #[cfg(any(feature = "dtls", feature = "ice"))]
        while let Some((call, destination, payload)) = self.engine.poll_transmit(now) {
            if let Some(media) = self.media.get(&call) {
                media.send(destination, &payload);
            }
        }
    }

    pub(crate) fn timers(&mut self, now: Instant) {
        self.engine.handle_timeout(now);
        self.agent.handle_timeout(now);
    }

    /// Read whatever SIP datagrams have arrived without blocking, from the socket or from the
    /// reader thread once [`Endpoint::read_in_background`] started one. `true` if any arrived.
    ///
    /// Datagrams the parser refused are logged to stderr: the stack already answered 400 or 513
    /// where it could and counted them, but an operator watching the process sees this line.
    pub(crate) fn read_sip(&mut self, now: Instant) -> bool {
        let mut arrived = false;
        if self.reader.is_some() {
            while let Some((data, from)) = self.reader.as_mut().and_then(Reader::take) {
                arrived = true;
                self.deliver(&data, from, now);
            }
            return arrived;
        }
        loop {
            match self.sip.recv_from(&mut self.sip_inbox) {
                Ok((length, from)) => {
                    arrived = true;
                    let data = std::mem::take(&mut self.sip_inbox);
                    self.deliver(data.get(..length).unwrap_or_default(), from, now);
                    self.sip_inbox = data;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        arrived
    }

    /// Hand one datagram to the user agent and log a refusal to stderr.
    fn deliver(&mut self, data: &[u8], from: SocketAddr, now: Instant) {
        if let Some(kept) = self.tap.as_mut() {
            kept.push(data.to_vec());
        }
        let received = self.agent.receive(
            Input::Datagram {
                transport: self.transport,
                remote: from,
                local: self.local,
                data,
            },
            now,
        );
        if let Err(error) = received {
            eprintln!("refused {} bytes from {from}: {error}", data.len());
        }
    }

    /// Wait until a SIP datagram is ready or `until` arrives; with `None`, until a datagram.
    /// Nothing is handed to the agent; [`Endpoint::read_sip`] does that.
    ///
    /// With a reader thread the wait is on its channel and ends on time. Without one it peeks the
    /// socket with a timeout counted in scheduler ticks ([`Reader`]). If switching blocking mode
    /// fails, the wait returns at once rather than hang, and if the reader thread has ended the
    /// socket is waited on and read here again.
    pub(crate) fn wait_sip(&mut self, until: Option<Instant>) {
        if let Some(reader) = self.reader.as_mut() {
            if reader.wait(until) {
                return;
            }
            self.reader = None;
            if self.sip.set_nonblocking(true).is_err() {
                return;
            }
        }
        let timeout = match until {
            Some(until) => match until.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => Some(left),
                _ => return,
            },
            None => None,
        };
        if self.sip.set_read_timeout(timeout).is_err() || self.sip.set_nonblocking(false).is_err() {
            return;
        }
        // one byte shows a datagram is there; peeking leaves it queued
        let mut look = [0_u8; 1];
        let _ = self.sip.peek_from(&mut look);
        let _ = self.sip.set_nonblocking(true);
    }

    /// Add an account.
    pub(crate) fn add_account(&mut self, account: sipral::Account) -> AccountId {
        self.agent.add_account(account)
    }
}

/// Bind an RTP socket, place `outgoing` on it, and store the socket under the new call handle.
///
/// Together because the handle only exists after [`MediaEngine::place`] returns, while the socket
/// must exist before so its port can go in the offer.
///
/// # Errors
///
/// Whatever binding or placing returns.
pub(crate) fn place(
    endpoint: &mut Endpoint,
    account: AccountId,
    outgoing: sipral::OutgoingCall,
    now: Instant,
) -> Result<CallHandle, Box<dyn std::error::Error>> {
    let media = MediaSocket::bind(now)?;
    let port = media.port()?;
    let local = SocketAddr::new(endpoint.local.ip(), port);
    let call = endpoint
        .engine
        .place(&mut endpoint.agent, account, outgoing, local, now)?;
    endpoint.media.insert(call, media);
    Ok(call)
}

/// The local address a datagram to `remote` would leave from, for `Contact`. A wildcard bind would
/// advertise `0.0.0.0`, and a registrar sending calls there sends them nowhere.
pub(crate) fn route_to(remote: SocketAddr) -> std::net::IpAddr {
    sipral::route_to(remote).unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]))
}
