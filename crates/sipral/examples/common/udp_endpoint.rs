// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

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
        })
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
                media.send(destination, &payload);
            }
        }
        while let Some((call, destination, payload)) = self.engine.poll_farewell() {
            if let Some(media) = self.media.get(&call) {
                media.send(destination, &payload);
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

    /// Read whatever SIP datagrams have arrived, non-blockingly. `true` when
    /// at least one did.
    pub(crate) fn read_sip(&mut self, now: Instant) -> bool {
        let mut arrived = false;
        loop {
            match self.sip.recv_from(&mut self.sip_inbox) {
                Ok((length, from)) => {
                    arrived = true;
                    let data = self.sip_inbox.get(..length).unwrap_or_default();
                    let _ = self.agent.receive(
                        Input::Datagram {
                            transport: self.transport,
                            remote: from,
                            local: self.local,
                            data,
                        },
                        now,
                    );
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        arrived
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
