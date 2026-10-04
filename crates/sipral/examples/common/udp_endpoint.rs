// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A user agent and a media engine, with a plain UDP socket for SIP under
//! them: the plumbing `call.rs`, `register-and-call.rs` and
//! `headless-agent.rs` all need. `tls.rs` signals over a different transport
//! and writes its own.
//!
//! `sipral::MediaEngine::poll_event` is the one place events may be drained
//! from — its own documentation says so, because it drains the agent under it
//! too — so this is the whole of the event loop: bind a socket, start a user
//! agent on it, and round a loop that flushes what is queued, drains what
//! that produced, and reads what arrived.
//!
//! This is shared source, included afresh into each example's own binary
//! (`#[path = "common/udp_endpoint.rs"]`), and no single example calls every
//! method it offers — `headless-agent.rs` opens media for a call it is about
//! to answer, which nothing that only ever places one does. `dead_code`
//! reads that as an unused method in whichever binary does not happen to
//! call it, so it is silenced here rather than by inventing a use for it in
//! an example that has no reason to make one.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sipral::{
    AccountId, CallHandle, Event, Input, MediaEngine, TransportId, TransportProtocol, UserAgent,
};

use crate::media_socket::MediaSocket;

/// A user agent and a media engine with a real UDP socket for SIP under them.
pub(crate) struct Endpoint {
    pub(crate) agent: UserAgent,
    pub(crate) engine: MediaEngine,
    sip: UdpSocket,
    pub(crate) local: SocketAddr,
    pub(crate) transport: TransportId,
    /// One RTP socket per call that has media, opened before the call is
    /// placed or answered so its port can go in the offer or the answer.
    pub(crate) media: HashMap<CallHandle, MediaSocket>,
    sip_inbox: Vec<u8>,
    /// The thread reading the SIP socket, once [`Endpoint::read_in_background`]
    /// started one; until then the socket is read where the loop turns.
    reader: Option<Reader>,
}

/// One SIP datagram as the reader thread took it off the socket.
type Datagram = (Vec<u8>, SocketAddr);

/// How long the reader thread blocks on the SIP socket before it looks
/// whether the socket is still the endpoint's. A socket given up (a move to
/// another address, the endpoint dropped) is sent an empty datagram that
/// ends the read at once ([`Reader`]'s `Drop`); this is the most it stays
/// bound when that datagram cannot reach it, an address gone with the
/// network that held it. Long, so an idle agent's reader wakes twelve times
/// a minute and no more.
const READER_LOOK: Duration = Duration::from_secs(5);

/// How long the reader thread pauses after a read that failed for a reason
/// other than its timeout, so that a failure which repeats cannot spin.
const READER_PAUSE: Duration = Duration::from_millis(10);

/// The SIP socket read on a thread of its own, every datagram handed over a
/// channel.
///
/// A loop that waits on the socket itself waits with `SO_RCVTIMEO`, which
/// Linux counts in scheduler ticks: a 5 ms wait at the common 250 ticks a
/// second is two of them, and ends anywhere from 4 to 8 ms later. A
/// channel's wait ends at its deadline to within the system's timer slack,
/// and as soon as a datagram is sent on it, so a loop waiting there turns
/// when it said it would and still answers SIP the moment it arrives. One
/// thread for the process, whatever the number of calls.
struct Reader {
    inbox: mpsc::Receiver<Datagram>,
    /// Taken off the channel by a wait, not yet handed to the user agent.
    held: VecDeque<Datagram>,
    /// Set when the socket the thread reads is no longer the endpoint's; the
    /// thread sees it at its next read and ends, closing its copy.
    retired: Arc<AtomicBool>,
    /// Where the socket the thread reads is bound, which `Drop` wakes it at.
    bound: SocketAddr,
}

impl Reader {
    /// Start a thread reading `sip`, which is switched to blocking reads
    /// with a timeout of [`READER_LOOK`]: the endpoint only writes to it
    /// from then on, which a blocking UDP socket does as well.
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
                        // whatever arrived once the socket was given up is
                        // not the endpoint's any more, the datagram that
                        // woke this read to say so among it
                        Ok(_) if seen.load(Ordering::Relaxed) => return,
                        Ok((length, from)) => {
                            let data = buffer.get(..length).unwrap_or_default().to_vec();
                            // the endpoint has gone, and the thread with it
                            if sender.send((data, from)).is_err() {
                                return;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::WouldBlock | ErrorKind::TimedOut
                            ) => {}
                        // whatever else a datagram socket reports is about one
                        // datagram, not the socket
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

    /// Wait for the next datagram no later than `until`, or for as long as
    /// it takes with `None`. `false` when the thread has ended.
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
    /// Retire the thread, and wake its read with an empty datagram so that it
    /// ends now rather than at its next [`READER_LOOK`].
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
    /// Bind the SIP socket and start a user agent on it. `bind_addr` should
    /// already name a routable address — [`route_to`] finds one — not a
    /// wildcard: it becomes both this endpoint's own idea of its address and,
    /// through [`Endpoint::open_media`], the address a call's offer or answer
    /// advertises for its media.
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
        // §18.1.1: a transport has to say it is open, and what it is open on,
        // before anything is written to it
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
        })
    }

    /// Read the SIP socket on a thread of its own from now on, so that
    /// [`Endpoint::wait_sip`] waits on a channel, which ends on time, rather
    /// than on the socket, which ends on the next scheduler tick ([`Reader`]
    /// says why that matters). [`Endpoint::read_sip`] then takes what the
    /// thread read, and [`Endpoint::rebind_sip`] starts a thread on the new
    /// socket.
    ///
    /// # Errors
    /// Copying the socket, switching it to blocking reads, or starting the
    /// thread.
    pub(crate) fn read_in_background(&mut self) -> std::io::Result<()> {
        self.reader = Some(Reader::spawn(&self.sip)?);
        Ok(())
    }

    /// Bind a fresh RTP socket for a call about to be placed or answered, and
    /// say where its offer or its answer should send media.
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

    /// Bind the SIP socket again at `ip`, on the port it had, and tell the
    /// agent its transport is open there now: what an application does
    /// first when the address it was reached at is gone. The answer is where
    /// the socket is.
    ///
    /// # Errors
    /// Binding the new socket, or the agent refusing the transport.
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
            // what the old socket had already been sent is still for this
            // agent, and is handed over before anything the new one reads
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

    /// Offer `call` again from this endpoint's own address, on the port its
    /// RTP socket already has — the answer to `UaEvent::CallAddressWanted`
    /// once [`Endpoint::rebind_sip`] moved the endpoint. Every example's RTP
    /// socket is bound to the wildcard address, so it goes on receiving at
    /// the new address unchanged, and only the description has to say so.
    /// A call that cannot be offered again is said on standard error.
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

    /// Forget a call's RTP socket once the call itself has ended, closing the
    /// port along with it. A process that places or answers one call and
    /// exits, such as `call.rs`, never notices its absence; one that keeps
    /// running and keeps answering, such as `headless-agent.rs`, leaks a
    /// bound socket per call otherwise — call this from a `CallEnded` handler.
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
            let _ = self.sip.send_to(&transmit.payload, transmit.destination);
        }
    }

    /// Run every active call's media for one tick, handing each one's socket
    /// and session to `per_call` — which is where the example puts a real
    /// device, a WAV file or an echo — and carry whatever the engine had
    /// queued to send on a call's behalf (RTCP, a goodbye, a DTLS record).
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
            // `session` (a `SessionGuard`) derefs to `&mut MediaSession`,
            // which is what `per_call` above actually receives
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
        // A DTLS-SRTP handshake record, from whichever of `dtls` or `ice`
        // this build has; `MediaEngine::poll_transmit` does not exist
        // without at least one of them.
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

    /// Read whatever SIP datagrams have arrived, non-blockingly: off the
    /// socket, or what the reader thread took off it once
    /// [`Endpoint::read_in_background`] started one. `true` when at least one
    /// did.
    ///
    /// A datagram the parser refused is said on standard error: the stack has
    /// already answered it 400 or 513 when it could be addressed, and counted
    /// it either way, but a line here is what an operator watching this
    /// process sees without asking.
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

    /// Hand one datagram to the user agent, and say on standard error when
    /// it refused it.
    fn deliver(&mut self, data: &[u8], from: SocketAddr, now: Instant) {
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

    /// Wait until a SIP datagram is waiting to be read or `until` has come,
    /// whichever is first; with `until` `None`, until a datagram. Nothing
    /// is handed to the user agent: [`Endpoint::read_sip`] does that.
    ///
    /// With a reader thread the wait is on its channel, and ends on time.
    /// Without one it is on the socket itself, which is non-blocking
    /// everywhere else and blocks, with a timeout, on a look at the next
    /// datagram that leaves it queued; that timeout is counted in scheduler
    /// ticks ([`Reader`]). A failure to switch either way is a wait that
    /// does not happen — the caller turns at once — never one that does not
    /// end, and a reader thread that has ended leaves the socket to be
    /// waited on and read here again.
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
        // one byte is enough to know a datagram is there; the rest of it is
        // left where it is, since this only looks
        let mut look = [0_u8; 1];
        let _ = self.sip.peek_from(&mut look);
        let _ = self.sip.set_nonblocking(true);
    }

    /// Add an account.
    pub(crate) fn add_account(&mut self, account: sipral::Account) -> AccountId {
        self.agent.add_account(account)
    }
}

/// Bind an RTP socket, place `outgoing` on it, and remember the socket under
/// the call handle placing it mints.
///
/// The three steps go together because a [`CallHandle`] does not exist until
/// [`MediaEngine::place`] returns one, and the socket has to exist before
/// that call so its port can go in the offer — the same reordering every
/// application places a call around.
///
/// # Errors
/// Whatever binding the RTP socket or placing the call returns.
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

/// Which of this host's addresses a datagram to `remote` would leave from —
/// what goes in `Contact`, so the far end has somewhere to send its own
/// requests back to. Binding to a wildcard address answers with it, and a
/// registrar told to send calls to `0.0.0.0` sends them nowhere.
pub(crate) fn route_to(remote: SocketAddr) -> std::net::IpAddr {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect(remote)?;
            socket.local_addr()
        })
        .map_or(std::net::IpAddr::from([127, 0, 0, 1]), |address| {
            address.ip()
        })
}
