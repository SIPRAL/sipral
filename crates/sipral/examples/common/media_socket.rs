// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One call's RTP socket, shared by every example here.
//!
//! `sipral::MediaSession` owns no socket or device (`docs/01-architecture.md`). Binding a port,
//! moving datagrams to and from the session, and pacing frames like an audio device is what every
//! embedding application writes; it lives here once so each example can focus on what it
//! demonstrates.
//!
//! What goes in and what happens to what comes out stays per example (microphone and speaker, a WAV
//! file, an echo): [`MediaSocket::turn`] takes them as two closures.
//!
//! Included into each example's binary; see `udp_endpoint.rs` for why `dead_code` is allowed.
#![allow(dead_code)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use sipral::{MediaSession, RtcpPlan};

/// The largest frame in samples of any codec in the default build: Opus at 20 ms and 48 kHz (RFC
/// 7587 §7), four times G.722's. Sized for any catalogue an example may build.
pub(crate) const MAX_SAMPLES: usize = 960;

/// Frame interval, matching [`sipral::CodecCatalog`]'s default 20 ms.
pub(crate) const PACE: Duration = Duration::from_millis(20);

/// Ports to try before giving up on an RTP/RTCP pair: about half are odd, and some have their next
/// port taken.
const PAIR_ATTEMPTS: usize = 64;

/// One call's RTP socket plus the next port, held from the bind and used for RTCP if the call keeps
/// RTCP separate.
pub(crate) struct MediaSocket {
    socket: UdpSocket,
    /// The port after RTP, bound once the plan puts RTCP there (RFC 3550 §11): a peer that did not
    /// agree to mux (RFC 5761) sends reports to it and expects ours from it.
    rtcp: Option<UdpSocket>,
    /// That port, held from the RTP bind until the plan decides. Binding it only then lost it to
    /// another call's RTP in one call of 25 at a thousand concurrent calls.
    reserved: Option<UdpSocket>,
    /// Whether binding it failed, so it is not retried every frame.
    rtcp_refused: bool,
    running: bool,
    started: Instant,
    /// When the next frame is captured and sent.
    next: Instant,
    /// When the next frame is taken for the earpiece.
    next_play: Instant,
    inbox: [u8; 2_048],
}

impl MediaSocket {
    /// Bind an RTP socket so the SDP can name its port, and hold the next port for RTCP.
    pub(crate) fn bind(now: Instant) -> std::io::Result<Self> {
        let (socket, reserved) = bind_pair(|| UdpSocket::bind("0.0.0.0:0"))?;
        socket.set_nonblocking(true)?;
        reserved.set_nonblocking(true)?;
        Ok(Self {
            socket,
            rtcp: None,
            reserved: Some(reserved),
            rtcp_refused: false,
            running: false,
            started: now,
            next: now,
            next_play: now,
            inbox: [0; 2_048],
        })
    }

    /// The port to put in the offer or the answer.
    pub(crate) fn port(&self) -> std::io::Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }

    /// The RTCP receive port if separate; `None` while muxed or before the plan decided.
    pub(crate) fn rtcp_port(&self) -> Option<u16> {
        self.rtcp
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
            .map(|address| address.port())
    }

    /// Send a datagram the engine returned for the RTP port (a DTLS record, an ICE check) from this
    /// call's socket.
    pub(crate) fn send(&self, destination: SocketAddr, payload: &[u8]) {
        let _ = self.socket.send_to(payload, destination);
    }

    /// Send an RTCP report or BYE from the RTCP port if separate, since the peer expects reports
    /// from there, else from the RTP socket.
    pub(crate) fn send_rtcp(&self, destination: SocketAddr, payload: &[u8]) {
        let socket = self.rtcp.as_ref().unwrap_or(&self.socket);
        let _ = socket.send_to(payload, destination);
    }

    /// Adopt the RTCP port the plan names, the first time: the held port if it matches, else bind
    /// now. A muxed or RTCP-less plan releases the held port. A port in use elsewhere is logged;
    /// the call then sends reports from the RTP port and receives none.
    fn follow_rtcp_plan(&mut self, session: &MediaSession) {
        if self.rtcp.is_some() || self.rtcp_refused {
            return;
        }
        let RtcpPlan::SeparatePort { local, .. } = session.plan().rtcp else {
            self.reserved = None;
            return;
        };
        let held = self.reserved.take().filter(|socket| {
            socket
                .local_addr()
                .is_ok_and(|at| at.port() == local.port())
        });
        if let Some(socket) = held {
            self.rtcp = Some(socket);
            return;
        }
        match UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), local.port()))
            .and_then(|socket| socket.set_nonblocking(true).map(|()| socket))
        {
            Ok(socket) => self.rtcp = Some(socket),
            Err(error) => {
                eprintln!("cannot bind RTCP at port {}: {error}", local.port());
                self.rtcp_refused = true;
            }
        }
    }

    /// Feed the session whatever arrived on this call's sockets, without capturing or playing. Used
    /// for calls in a local conference, whose tick does the capture and playback.
    pub(crate) fn receive(&mut self, session: &mut MediaSession, now: Instant) {
        self.follow_rtcp_plan(session);
        loop {
            match self.socket.recv_from(&mut self.inbox) {
                Ok((length, from)) => {
                    let datagram = self.inbox.get_mut(..length).unwrap_or_default();
                    // the session acts on drops and control packets; this loop need not tell them
                    // apart
                    let _ = session.receive(datagram, from, now);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        while let Some(rtcp) = &self.rtcp {
            match rtcp.recv_from(&mut self.inbox) {
                Ok((length, from)) => {
                    let datagram = self.inbox.get_mut(..length).unwrap_or_default();
                    let _ = session.receive(datagram, from, now);
                }
                Err(_) => break,
            }
        }
    }

    /// Run one tick: capture a frame from `source` and send it, read what arrived, and pass every
    /// due frame to `sink`.
    ///
    /// `source` fills `session.frame_samples()` samples per call, at the pace above. `sink`
    /// receives every due frame, whatever [`MediaSession::playback`] filled it with (decoded,
    /// concealed, comfort noise or silence), as a real earpiece would. Passing only decoded frames
    /// would drop the pauses of a far end using silence suppression, and a recording would come out
    /// a fifth of its length.
    pub(crate) fn turn(
        &mut self,
        session: &mut MediaSession,
        now: Instant,
        mut source: impl FnMut(&mut [i16]),
        mut sink: impl FnMut(&[i16]),
    ) {
        // the socket was bound before the call came up, maybe seconds ago; the first turn sends the
        // frame due now, not a burst of everything since the bind
        if !self.running {
            self.running = true;
            self.started = now;
            self.next = now;
            self.next_play = now;
        }
        self.follow_rtcp_plan(session);
        let frame = session.frame_samples().min(MAX_SAMPLES);
        let mut samples = [0_i16; MAX_SAMPLES];

        while now >= self.next {
            let Some(room) = samples.get_mut(..frame) else {
                break;
            };
            source(room);
            if let Ok(Some(datagram)) = session.capture(room, now) {
                let _ = self.socket.send_to(datagram.payload, datagram.destination);
            }
            self.next += PACE;
        }

        self.receive(session, now);

        let mut played = [0_i16; MAX_SAMPLES];
        while now >= self.next_play {
            let Some(room) = played.get_mut(..frame) else {
                break;
            };
            // played regardless of what filled it
            let _ = session.playback(room);
            sink(room);
            self.next_play += PACE;
        }
    }
}

/// An RTP socket on an even port from `pick`, and RTCP on the next port (RFC 3550 §11), as a pair:
/// odd ports, or ones whose next port is taken, are released and another is tried.
fn bind_pair(
    mut pick: impl FnMut() -> std::io::Result<UdpSocket>,
) -> std::io::Result<(UdpSocket, UdpSocket)> {
    let mut held = None;
    for _ in 0..PAIR_ATTEMPTS {
        let media = pick()?;
        let port = media.local_addr()?.port();
        let Some(next) = port.checked_add(1).filter(|_| port.is_multiple_of(2)) else {
            continue;
        };
        match UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), next)) {
            Ok(control) => return Ok((media, control)),
            Err(error) => held = Some(error),
        }
    }
    Err(held.unwrap_or_else(|| {
        std::io::Error::new(ErrorKind::AddrInUse, "no even port with its next one free")
    }))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    use super::bind_pair;

    fn any() -> std::io::Result<UdpSocket> {
        UdpSocket::bind("0.0.0.0:0")
    }

    fn port(socket: &UdpSocket) -> u16 {
        socket.local_addr().unwrap().port()
    }

    #[test]
    fn rtp_is_bound_on_an_even_port_with_the_next_one_held() {
        for _ in 0..32 {
            let (media, control) = bind_pair(any).unwrap();
            assert!(port(&media).is_multiple_of(2));
            assert_eq!(port(&control), port(&media) + 1);
            let taken = UdpSocket::bind(SocketAddr::new(
                Ipv4Addr::UNSPECIFIED.into(),
                port(&control),
            ));
            assert!(taken.is_err(), "the RTCP port is not held");
        }
    }

    #[test]
    fn a_port_whose_next_one_is_held_is_let_go_of() {
        // an even port whose next one another socket already has
        let (blocked, squatter) = loop {
            let (media, control) = bind_pair(any).unwrap();
            let even = port(&media);
            drop(control);
            if let Ok(squatter) =
                UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), even + 1))
            {
                break (media, squatter);
            }
        };
        let refused = port(&blocked);
        let mut offered = Some(blocked);
        let (media, control) = bind_pair(|| offered.take().map_or_else(any, Ok)).unwrap();
        assert_ne!(port(&media), refused, "a pair whose RTCP port was held");
        assert_eq!(port(&control), port(&media) + 1);
        drop(squatter);
    }
}
