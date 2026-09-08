// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The media half of a flow: a socket, an RTP session, and a tone.
//!
//! Signalling that agrees on a codec proves the two ends can talk about a
//! call. It does not prove anybody can hear it, and until this module existed
//! the harness negotiated media and then sent nothing — so a call to an echo
//! test passed on the strength of its 200 OK.
//!
//! What happens here is deliberately the smallest thing that answers the
//! question: send a tone the far end can only be echoing back, and measure
//! what returns. An echo service that is working returns the tone; one that is
//! not returns silence, or nothing at all, and the two are easy to tell apart
//! without knowing anything about speech.

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use sipral_core::sdp::MediaPlan;
use sipral_media::g711::Law;
use sipral_rtp::{
    Activity, BufferConfig, PayloadTypes, Pull, Quality, Received, RtpSession, StreamConfig,
};

/// Twenty milliseconds at eight kilohertz.
const FRAME: usize = 160;

/// The same, as the timestamp ticks one packet covers.
const FRAME_TICKS: u32 = 160;

/// Samples in one period of the tone at eight kilohertz.
const PERIOD: u32 = 18;

/// How loud it is: a quarter of full scale.
const AMPLITUDE: i16 = 8000;

/// How often a frame goes out.
const PACE: Duration = Duration::from_millis(20);

/// Mean absolute sample value above which a frame counts as sound rather than
/// silence. G.711 silence sits within a handful of units of zero; a tone at a
/// quarter of full scale is thousands. Anything in between is neither, and the
/// gap is wide enough that the threshold does not need to be argued about.
const AUDIBLE: i32 = 500;

/// A tone the far end cannot produce by itself, so hearing it back means it
/// came from us. Roughly 440 Hz, square rather than sine.
///
/// Square because it needs no floating point and lands exactly on values
/// G.711 represents, so nothing about the signal can be blamed for what comes
/// back. Its harmonics alias, and for the question being asked — did sound
/// return — that does not matter.
fn tone(samples: &mut [i16], phase: &mut u32) {
    for slot in samples.iter_mut() {
        *slot = if *phase % PERIOD < PERIOD / 2 {
            AMPLITUDE
        } else {
            -AMPLITUDE
        };
        *phase = phase.wrapping_add(1);
    }
}

/// What the far end sent back.
#[derive(Debug, Default)]
pub(crate) struct Heard {
    /// Packets we put on the wire.
    pub(crate) sent: u32,
    /// Datagrams the session accepted.
    pub(crate) received: u32,
    /// Frames the buffer handed back with sound in them.
    pub(crate) audible: u32,
    /// Datagrams it refused, and why the first one was refused.
    pub(crate) refused: u32,
}

/// One media stream, driven by the same tick as the signalling.
pub(crate) struct Media {
    socket: UdpSocket,
    session: Option<RtpSession>,
    law: Law,
    started: Instant,
    next: Instant,
    phase: u32,
    samples: [i16; FRAME],
    payload: [u8; FRAME],
    packet: [u8; 1500],
    decoded: [i16; FRAME],
    heard: Heard,
}

impl Media {
    /// Bind a socket for RTP and report the port, so the offer can name it.
    ///
    /// # Errors
    /// When the socket cannot be bound or put in non-blocking mode.
    pub(crate) fn bind(now: Instant) -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|error| format!("cannot bind an RTP socket: {error}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| format!("cannot make the RTP socket non-blocking: {error}"))?;
        Ok(Self {
            socket,
            session: None,
            law: Law::Mu,
            started: now,
            next: now,
            phase: 0,
            samples: [0; FRAME],
            payload: [0; FRAME],
            packet: [0; 1500],
            decoded: [0; FRAME],
            heard: Heard::default(),
        })
    }

    /// The port the offer has to advertise.
    ///
    /// # Errors
    /// When the socket cannot say what it was bound to.
    pub(crate) fn port(&self) -> Result<u16, String> {
        self.socket
            .local_addr()
            .map(|address| address.port())
            .map_err(|error| format!("the RTP socket has no address: {error}"))
    }

    /// Start sending, now that the answer has said where and in what.
    ///
    /// The law comes from the negotiated payload type rather than from what we
    /// would have preferred: the first real PBX this met allows A-law only.
    pub(crate) fn start(&mut self, plan: &MediaPlan, ssrc: u32, now: Instant) {
        let payload_type = plan.codec.payload();
        let law = Law::from_payload_type(payload_type).unwrap_or(Law::Mu);
        self.law = law;
        self.session = Some(RtpSession::new(
            &StreamConfig {
                ssrc,
                payload_type,
                // whatever we agreed, plus the other law: a peer that answers
                // with one and sends the other is a real thing, and dropping
                // its audio would look like silence rather than like a fault
                accepted: PayloadTypes::none().with(0).with(8),
                clock_rate: plan.codec.clock_rate(),
                sequence: 0,
                timestamp: 0,
                remote: plan.remote,
                silence_suppression: false,
                playout: BufferConfig::new(FRAME_TICKS),
                cname: format!("sipral-interop@{}", plan.local.ip()),
                rtcp_bandwidth: 1000.0,
            },
            1.0,
        ));
        self.next = now;
    }

    /// Send what is due and take in what arrived.
    pub(crate) fn turn(&mut self, now: Instant) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let elapsed = now.saturating_duration_since(self.started);

        while now >= self.next {
            tone(&mut self.samples, &mut self.phase);
            let written = self.law.encode_into(&self.samples, &mut self.payload);
            if let Ok(length) = session.send(
                self.payload.get(..written).unwrap_or_default(),
                FRAME_TICKS,
                &mut self.packet,
            ) && let Some(datagram) = self.packet.get(..length)
                && self.socket.send_to(datagram, session.destination()).is_ok()
            {
                self.heard.sent = self.heard.sent.saturating_add(1);
            }
            self.next += PACE;
        }

        let mut inbox = [0_u8; 2048];
        loop {
            match self.socket.recv_from(&mut inbox) {
                Ok((length, from)) => {
                    let datagram = inbox.get(..length).unwrap_or_default();
                    match session.receive(datagram, from, elapsed) {
                        Received::Queued => {
                            self.heard.received = self.heard.received.saturating_add(1);
                        }
                        Received::Dropped(_) => {
                            self.heard.refused = self.heard.refused.saturating_add(1);
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        while let Pull::Packet(frame) = session.pull(Activity::Speech) {
            let count = self.law.decode_into(frame.payload, &mut self.decoded);
            let played = self.decoded.get(..count).unwrap_or_default();
            if loudness(played) >= AUDIBLE {
                self.heard.audible = self.heard.audible.saturating_add(1);
            }
        }
    }

    /// What came back.
    pub(crate) const fn heard(&self) -> &Heard {
        &self.heard
    }

    /// What the de-jitter buffer made of it. Empty before a call is up.
    pub(crate) fn quality(&self) -> Option<Quality> {
        self.session.as_ref().map(RtpSession::quality)
    }
}

/// Mean absolute sample value.
fn loudness(samples: &[i16]) -> i32 {
    if samples.is_empty() {
        return 0;
    }
    let total: i64 = samples
        .iter()
        .map(|value| i64::from(value.saturating_abs()))
        .sum();
    let count = i64::try_from(samples.len()).unwrap_or(1).max(1);
    i32::try_from(total / count).unwrap_or(i32::MAX)
}
