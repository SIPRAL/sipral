// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One call's RTP socket: a tone to send, and what came back of it.
//!
//! `sipral::MediaSession` is the RTP session, the codec and the concealment
//! now — the negotiation, the jitter buffer, the companding tables and the
//! DTMF generator all live there, and none of them belongs here any more.
//! What is left is what any application embedding the facade still has to
//! write for itself, because the facade owns neither a socket nor a signal:
//! bind a port, put frames of PCM in and take frames of PCM out on the pace
//! a real device would, and count what a real device cannot — packets sent,
//! packets accepted, packets refused, and frames loud enough to be the tone
//! rather than concealment. Those four numbers are what the lab's result
//! line has always printed, and they still come from watching the session
//! from outside it, the same way a real audio device would. A G.729 call
//! that uses Annex B adds three: the SID frames sent and taken back, and the
//! frames played as comfort noise.

use std::env;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use sipral::{Arrival, MediaSession, Playback};

use crate::quality;

/// The audio quality gate — segmental SNR and splice continuity, `quality`'s
/// own — is extra bookkeeping on every played frame, worth paying for only
/// where something is actually going to read it: `scripts/lab.sh`'s own
/// netem step, which sets this. Every other step, and every flow but the
/// one that dwells on the tone, never asks and never pays for it.
const AUDIO_GATE_ENV: &str = "SIPRAL_AUDIO_GATE";

/// The largest frame any codec in this build produces, in samples: G.722's,
/// which hears twice as fast as it counts. Opus is not linked here — see
/// `Cargo.toml` — so this build's largest is fixed.
const MAX_SAMPLES: usize = 320;

/// How often a frame goes out, matching `sipral::CodecCatalog`'s default
/// twenty-millisecond packetisation.
const PACE: Duration = Duration::from_millis(20);

/// Roughly 440 Hz, whatever the rate: the period is in samples, so it has to
/// come from the rate rather than being a constant.
const TONE_HZ: u32 = 444;

/// How loud the tone is: a quarter of full scale.
const AMPLITUDE: i16 = 8_000;

/// How long the tone sounds, and how long it then stops for.
///
/// A continuous tone never lets a de-jitter buffer give back the delay it
/// grew over an interruption, because that only happens in a pause — see
/// `docs/11-testing.md`. 1200 ms of tone, 600 ms of silence, repeating.
const SPURT: Duration = Duration::from_millis(1_200);
const PAUSE: Duration = Duration::from_millis(600);

/// Mean absolute sample value above which a frame counts as sound rather than
/// silence. G.711 and G.722 silence sit within a handful of units of zero; a
/// tone at a quarter of full scale is thousands.
pub(crate) const AUDIBLE: i32 = 500;

/// Whether the tone is sounding at this point in the call.
///
/// `crate::join` reads this too, against the lab's own 9000 — the tone
/// extension every flow in this table dials — to tell a frame that could
/// only have come from this end's own call apart from one that could only
/// have come from the far end of a joined pair.
pub(crate) fn in_spurt(elapsed: Duration) -> bool {
    let cycle = SPURT.saturating_add(PAUSE).as_millis().max(1);
    elapsed.as_millis() % cycle < SPURT.as_millis()
}

/// The tone's own period, in samples, at `rate`.
fn tone_period(rate: u32) -> u32 {
    (rate / TONE_HZ).max(2)
}

/// The tone's ideal value at `phase` samples into a period of `period`, with
/// no side effect on the phase itself — what [`tone`] writes.
fn tone_sample(phase: u32, period: u32) -> i16 {
    if phase % period < period / 2 {
        AMPLITUDE
    } else {
        -AMPLITUDE
    }
}

/// What this end sends. Square rather than sine, so nothing about the signal
/// itself can be blamed for what comes back.
pub(crate) fn tone(samples: &mut [i16], phase: &mut u32, rate: u32) {
    let period = tone_period(rate);
    for slot in samples.iter_mut() {
        *slot = tone_sample(*phase, period);
        *phase = phase.wrapping_add(1);
    }
}

/// Mean absolute sample value.
pub(crate) fn loudness(samples: &[i16]) -> i32 {
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

/// Whether a frame is loud enough to be the tone rather than silence between
/// spurts — the same test [`Heard::audible`] is counted by, shared with
/// `quality` so a frame it scores and a frame this file already calls
/// audible are never two different ideas of loud.
pub(crate) fn is_audible(samples: &[i16]) -> bool {
    loudness(samples) >= AUDIBLE
}

/// What the far end sent back, counted the same way the harness has always
/// counted it: from outside the session, watching what each call returns.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Heard {
    /// Packets `MediaSession::capture` handed back for this end to send.
    pub(crate) sent: u32,
    /// Datagrams `MediaSession::receive` reported as [`Arrival::Queued`].
    pub(crate) received: u32,
    /// Frames `MediaSession::playback` reported as [`Playback::Packet`] and
    /// that were loud enough to be the tone rather than a decoding fluke.
    pub(crate) audible: u32,
    /// Datagrams `MediaSession::receive` reported as [`Arrival::Dropped`].
    pub(crate) refused: u32,
    /// G.729 packets this end sent and took back whose payload ended in an
    /// Annex B SID frame, and frames `MediaSession::playback` reported as
    /// [`Playback::ComfortNoise`]: what says Annex B crossed the far end.
    pub(crate) sid_sent: u32,
    pub(crate) sid_received: u32,
    pub(crate) comfort: u32,
}

/// G.729's static payload type (RFC 3551 table 4).
const G729: u8 = 18;

/// Whether an RTP datagram is G.729 whose payload ends in an Annex B SID
/// frame: ten octets a speech frame and two for the SID (RFC 3551 §4.5.6),
/// behind this harness's own fixed twelve-octet header — the facade writes
/// neither contributing sources nor an extension.
fn carries_sid(datagram: &[u8]) -> bool {
    let is_g729 = datagram.get(1).is_some_and(|octet| octet & 0x7f == G729);
    is_g729
        && datagram
            .len()
            .checked_sub(12)
            .is_some_and(|payload| payload % 10 == 2)
}

/// One call's RTP socket, and what has crossed it.
pub(crate) struct Media {
    socket: UdpSocket,
    /// Whether a session has been driven on this socket yet: the pace below
    /// starts from the first turn, not from the moment the socket was bound.
    running: bool,
    started: Instant,
    /// When the next frame is captured and sent.
    next: Instant,
    /// When the next frame is taken for the earpiece.
    next_play: Instant,
    phase: u32,
    heard: Heard,
    inbox: [u8; 2_048],
    /// `Some` only when [`AUDIO_GATE_ENV`] is set — see its own doc comment.
    quality: Option<quality::Gate>,
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
            running: false,
            started: now,
            next: now,
            next_play: now,
            phase: 0,
            heard: Heard::default(),
            inbox: [0; 2_048],
            quality: env::var_os(AUDIO_GATE_ENV)
                .is_some()
                .then(quality::Gate::new),
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

    /// Send a datagram the engine handed back — a periodic report, or the
    /// goodbye — from this call's own socket.
    pub(crate) fn send(&self, destination: SocketAddr, payload: &[u8]) {
        let _ = self.socket.send_to(payload, destination);
    }

    /// Hand whatever arrived on this socket, before any call is running on it,
    /// to `mappings` as having arrived on `local`: the STUN server's answer
    /// about where the socket appears from outside (`crate::ice_nat`).
    /// Anything else that arrives this early is nobody's and is dropped.
    pub(crate) fn receive_stun(
        &mut self,
        mappings: &mut sipral::Mappings,
        local: SocketAddr,
        now: Instant,
    ) {
        while let Ok((length, from)) = self.socket.recv_from(&mut self.inbox) {
            let data = self.inbox.get(..length).unwrap_or_default();
            let _ = mappings.receive(local, from, data, now);
        }
    }

    /// The same for a relay being allocated on the socket
    /// (`crate::ice_nat`'s TURN step): what the TURN server says goes to
    /// `relays`, as having arrived on `local`.
    pub(crate) fn receive_relay(
        &mut self,
        relays: &mut sipral::Relays,
        local: SocketAddr,
        now: Instant,
    ) {
        while let Ok((length, from)) = self.socket.recv_from(&mut self.inbox) {
            let data = self.inbox.get(..length).unwrap_or_default();
            let _ = relays.receive(local, from, data, now);
        }
    }

    /// The receiving half of [`Media::turn`] alone, for a caller that drives
    /// the sending half itself.
    ///
    /// `crate::join` is the one caller: a joined pair's own frame comes from
    /// `sipral::MediaEngine::mix`, which decodes both sessions together, so
    /// nothing here may call `MediaSession::capture`/`playback` on either one
    /// on its own — that is exactly the double consumption `turn` on its own
    /// would cause.
    pub(crate) fn receive_into(&mut self, session: &mut MediaSession, now: Instant) {
        loop {
            match self.socket.recv_from(&mut self.inbox) {
                Ok((length, from)) => {
                    let datagram = self.inbox.get_mut(..length).unwrap_or_default();
                    match session.receive(datagram, from, now) {
                        Arrival::Queued => {
                            self.heard.received = self.heard.received.saturating_add(1);
                            if carries_sid(datagram) {
                                self.heard.sid_received = self.heard.sid_received.saturating_add(1);
                            }
                        }
                        Arrival::Dropped(_) => {
                            self.heard.refused = self.heard.refused.saturating_add(1);
                        }
                        _ => {}
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    /// Drive this call's session for one tick: send what is due, take in
    /// what arrived, and play it.
    ///
    /// Everything about the codec, the jitter buffer and the concealment is
    /// `session`'s; this only watches what crosses the socket, the way a real
    /// audio device and a real network would.
    pub(crate) fn turn(&mut self, session: &mut MediaSession, now: Instant) {
        // The socket was bound before the call was placed or answered, so its
        // port could go in the description, and the call may have taken
        // seconds to come up after that. The microphone starts with the
        // session: the first turn sends the frame due now, not a burst of
        // every frame that would have been due since the socket was bound.
        if !self.running {
            self.running = true;
            self.started = now;
            self.next = now;
            self.next_play = now;
        }
        let elapsed = now.saturating_duration_since(self.started);
        let frame = session.frame_samples().min(MAX_SAMPLES);
        let rate = session.sample_rate();
        let mut samples = [0_i16; MAX_SAMPLES];

        while now >= self.next {
            if in_spurt(elapsed) {
                tone(
                    samples.get_mut(..frame).unwrap_or_default(),
                    &mut self.phase,
                    rate,
                );
            } else if let Some(silence) = samples.get_mut(..frame) {
                silence.fill(0);
            }
            if let Ok(Some(datagram)) =
                session.capture(samples.get(..frame).unwrap_or_default(), now)
                && self
                    .socket
                    .send_to(datagram.payload, datagram.destination)
                    .is_ok()
            {
                self.heard.sent = self.heard.sent.saturating_add(1);
                if carries_sid(datagram.payload) {
                    self.heard.sid_sent = self.heard.sid_sent.saturating_add(1);
                }
            }
            self.next += PACE;
        }

        loop {
            match self.socket.recv_from(&mut self.inbox) {
                Ok((length, from)) => {
                    let datagram = self.inbox.get_mut(..length).unwrap_or_default();
                    match session.receive(datagram, from, now) {
                        Arrival::Queued => {
                            self.heard.received = self.heard.received.saturating_add(1);
                            if carries_sid(datagram) {
                                self.heard.sid_received = self.heard.sid_received.saturating_add(1);
                            }
                        }
                        Arrival::Dropped(_) => {
                            self.heard.refused = self.heard.refused.saturating_add(1);
                        }
                        // a report, a goodbye, or a control datagram this end
                        // did not believe: none of the four counted here.
                        // `sipral::Arrival` is `#[non_exhaustive]` besides
                        _ => {}
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // one frame out per frame of time, like the capture above:
        // `MediaSession::playback` is one frame of the device's time per
        // call, and this loop turns far more often than every twenty
        // milliseconds, so a frame taken on every turn drains the jitter
        // buffer as fast as packets arrive and leaves it no delay to hold
        let mut played = [0_i16; MAX_SAMPLES];
        while now >= self.next_play {
            let room = played.get_mut(..frame).unwrap_or_default();
            let outcome = session.playback(room);
            if matches!(outcome, Playback::Packet) && loudness(room) >= AUDIBLE {
                self.heard.audible = self.heard.audible.saturating_add(1);
            }
            if matches!(outcome, Playback::ComfortNoise) {
                self.heard.comfort = self.heard.comfort.saturating_add(1);
            }
            if let Some(gate) = self.quality.as_mut() {
                gate.observe(outcome, room, rate);
            }
            self.next_play += PACE;
        }
    }

    /// What came back.
    pub(crate) const fn heard(&self) -> Heard {
        self.heard
    }

    /// What the audio quality gate measured, when [`AUDIO_GATE_ENV`] asked
    /// for one.
    pub(crate) fn quality_report(&self) -> Option<quality::Report> {
        self.quality.as_ref().map(quality::Gate::report)
    }
}

#[cfg(test)]
mod tests {
    use super::{TONE_HZ, tone};

    /// The tone has to stay at the same pitch when the rate doubles, or a
    /// G.722 flow is measuring a different signal from a G.711 one.
    #[test]
    fn the_tone_keeps_its_pitch_across_the_rates() {
        for rate in [8_000_u32, 16_000] {
            let mut phase = 0_u32;
            let mut samples = vec![0_i16; usize::try_from(rate).unwrap_or(8_000)];
            tone(&mut samples, &mut phase, rate);
            let crossings = samples
                .windows(2)
                .filter(|pair| pair[0].signum() != pair[1].signum())
                .count();
            let hertz = crossings / 2;
            assert!(
                hertz.abs_diff(TONE_HZ as usize) < 10,
                "at {rate} Hz the tone came out at {hertz} Hz"
            );
        }
    }
}
