// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One call's RTP socket, shared by every example in this directory.
//!
//! `sipral::MediaSession` is the codec, the jitter buffer, the concealment and
//! the RTP session; it owns neither a socket nor a device, by design (see
//! `docs/01-architecture.md`). Binding a port, moving datagrams between it and
//! the session, and pacing a frame in and a frame out the way a real audio
//! device would: that is what any application embedding the facade writes for
//! itself, and every example here needs the same few dozen lines of it. It
//! lives once, here, rather than four times, so that each example can stay
//! about the thing it is actually demonstrating — placing a call, holding it,
//! securing it — instead of about pacing a socket.
//!
//! What is deliberately still per-example is *what* goes in and *what* is done
//! with what comes out: a microphone and a speaker, a WAV file, or an answered
//! call's own audio handed straight back. [`MediaSocket::turn`] takes those as
//! two closures rather than owning either.
//!
//! Shared source, included afresh into each example's own binary — see
//! `udp_endpoint.rs`'s own note on why `dead_code` is silenced here too.
#![allow(dead_code)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use sipral::{MediaSession, RtcpPlan};

/// The largest frame any codec in this crate's default build produces, in
/// samples: Opus's own, at its default twenty-millisecond packetisation and
/// its fixed 48 kHz clock rate (RFC 7587 §7) — four times G.722's, which
/// hears twice as fast as it counts and would otherwise look like the bound.
/// An example that offers a catalogue with Opus left out of it never
/// produces a frame this large, but the buffer is sized for whichever
/// catalogue an example built, not for the narrowest one any of them
/// happens to choose.
pub(crate) const MAX_SAMPLES: usize = 960;

/// How often a frame goes out, matching [`sipral::CodecCatalog`]'s default
/// twenty-millisecond packetisation.
pub(crate) const PACE: Duration = Duration::from_millis(20);

/// How many ports the system is asked for before an RTP and RTCP pair is
/// given up on: about half of what it hands out is odd, and a few of the
/// rest have their next port held.
const PAIR_ATTEMPTS: usize = 64;

/// One call's RTP socket, and the port after it, held from the bind and
/// kept for RTCP when the call keeps RTCP on a port of its own.
pub(crate) struct MediaSocket {
    socket: UdpSocket,
    /// The port after the RTP one, bound once the call's plan says RTCP
    /// runs there (RFC 3550 §11): a peer that did not agree to multiplex
    /// the two (RFC 5761) sends its reports to it, and expects ours from it.
    rtcp: Option<UdpSocket>,
    /// That port, held from the moment the RTP one was bound and until the
    /// plan says whether RTCP runs there: bound only once the plan said so,
    /// it had been taken meanwhile by another call's RTP in one call of
    /// twenty-five at a thousand at once.
    reserved: Option<UdpSocket>,
    /// Whether binding it was tried and failed, so it is not tried again
    /// every frame.
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
    /// Bind a socket for RTP, so the offer or the answer can name its port,
    /// and hold the one after it for RTCP.
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

    /// The port RTCP is received on when it has one of its own; `None`
    /// while RTP and RTCP share one, or before the call's plan said.
    pub(crate) fn rtcp_port(&self) -> Option<u16> {
        self.rtcp
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
            .map(|address| address.port())
    }

    /// Send a datagram the engine handed back for the RTP port — a DTLS
    /// handshake record, an ICE check — from this call's own socket.
    pub(crate) fn send(&self, destination: SocketAddr, payload: &[u8]) {
        let _ = self.socket.send_to(payload, destination);
    }

    /// Send an RTCP report or goodbye the engine handed back: from the RTCP
    /// port when the call has one of its own, since that is where the peer
    /// reads the report as coming from, and from the RTP socket when the two
    /// are multiplexed.
    pub(crate) fn send_rtcp(&self, destination: SocketAddr, payload: &[u8]) {
        let socket = self.rtcp.as_ref().unwrap_or(&self.socket);
        let _ = socket.send_to(payload, destination);
    }

    /// Take the RTCP port the call's plan names, the first time it names one:
    /// the one held beside the RTP port when that is it, else bound now. A
    /// plan that multiplexes the two, or has no RTCP, lets the held one go.
    /// A port somebody else holds is said on standard error; the call then
    /// runs with its reports going out from the RTP port and none coming in.
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

    /// Drive this call's session for one tick: capture a frame from `source`
    /// and send it, read whatever arrived and hand every decoded frame to
    /// `sink`.
    ///
    /// `source` fills a buffer of `session.frame_samples()` samples every time
    /// it is called, at the pace above; `sink` is given every frame the pace
    /// makes due, whatever [`MediaSession::playback`] filled it with — a
    /// decoded packet, a concealed one, comfort noise or silence — which is
    /// what a real earpiece is handed. Handing it only the decoded ones drops
    /// every pause a far end that stops sending in silence leaves, and a
    /// recording of the call comes out a fifth of its length.
    pub(crate) fn turn(
        &mut self,
        session: &mut MediaSession,
        now: Instant,
        mut source: impl FnMut(&mut [i16]),
        mut sink: impl FnMut(&[i16]),
    ) {
        // The socket was bound before the call was placed or answered, so its
        // port could go in the description, and the call may have taken
        // seconds to come up after that. The first turn sends the frame due
        // now, not a burst of every frame that would have been due since the
        // socket was bound.
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

        loop {
            match self.socket.recv_from(&mut self.inbox) {
                Ok((length, from)) => {
                    let datagram = self.inbox.get_mut(..length).unwrap_or_default();
                    // `Arrival::Dropped` and every non-media control datagram
                    // are for the session to act on, not this loop: nothing
                    // here has to know a report from a goodbye
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

        let mut played = [0_i16; MAX_SAMPLES];
        while now >= self.next_play {
            let Some(room) = played.get_mut(..frame) else {
                break;
            };
            // what filled the frame does not change that it is played
            let _ = session.playback(room);
            sink(room);
            self.next_play += PACE;
        }
    }
}

/// An RTP socket on an even port, from `pick`, and an RTCP one on the port
/// after it (RFC 3550 §11), taken as a pair: a port `pick` hands out odd, or
/// whose next port somebody else holds, is let go of and another asked for.
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
