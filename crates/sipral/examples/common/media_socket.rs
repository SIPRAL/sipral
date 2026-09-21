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
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use sipral::MediaSession;

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

/// One call's RTP socket.
pub(crate) struct MediaSocket {
    socket: UdpSocket,
    running: bool,
    started: Instant,
    /// When the next frame is captured and sent.
    next: Instant,
    /// When the next frame is taken for the earpiece.
    next_play: Instant,
    inbox: [u8; 2_048],
}

impl MediaSocket {
    /// Bind a socket for RTP, so the offer or the answer can name its port.
    pub(crate) fn bind(now: Instant) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
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

    /// Send a datagram the engine handed back — a periodic RTCP report, or a
    /// DTLS handshake record — from this call's own socket.
    pub(crate) fn send(&self, destination: SocketAddr, payload: &[u8]) {
        let _ = self.socket.send_to(payload, destination);
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
