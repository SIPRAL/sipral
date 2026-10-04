// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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

/// [`Media::arm_mark`]'s own frame: full scale, so it cannot be mistaken for
/// the tone at a quarter of it, for silence, or for anything concealment
/// invents from either. `crate::latency` is the one caller.
const MARK_AMPLITUDE: i16 = i16::MAX;

/// Loud enough that only [`MARK_AMPLITUDE`] reaches it: above the tone's own
/// [`AMPLITUDE`] by a factor a codec's quantisation cannot close.
const MARK_LOUDNESS: i32 = 20_000;

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

/// A frame that can only be [`Media::arm_mark`]'s own marker: loud enough
/// that neither the tone nor concealment reaches it.
fn is_marker(samples: &[i16]) -> bool {
    loudness(samples) >= MARK_LOUDNESS
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
    /// Frames taken for the earpiece, whatever they held: the count a clock
    /// is measured against, since it is the earpiece's clock that decides it.
    pub(crate) played: u32,
    /// Frames `MediaSession::playback` reported as [`Playback::Silence`]:
    /// nothing was due, because the buffer was still filling or had run dry
    /// and gone back to filling.
    pub(crate) silent: u32,
    /// Runs of that silence that began straight after the tone or ended
    /// straight into it, once each: the tone cut off, which the ear hears as
    /// a gap. The far end's own pauses arrive as quiet packets, not as
    /// silence, so a buffer that runs dry in a pause is not counted here and
    /// one that runs dry in a word is.
    pub(crate) cut: u32,
    /// Frames `MediaSession::playback` reported as [`Playback::Concealed`]:
    /// a packet that never came, filled in, or a pause stretched by a frame.
    /// Counted here rather than read off the buffer's own loss count, which
    /// also counts the sequence numbers it skipped over without playing
    /// anything in their place.
    pub(crate) concealed: u32,
    /// The longest run of [`Heard::silent`] frames there has been: how far
    /// the buffer's own count of under-runs, which settles a run only once
    /// the packet after it is played, can be behind this one at any moment.
    pub(crate) longest_silence: u32,
}

/// Where the earpiece's silence falls against the tone, frame by frame.
#[derive(Debug, Default)]
struct Gaps {
    /// Whether the last frame was the tone.
    was_audible: bool,
    /// Whether the last frame was silence.
    was_silent: bool,
    /// Whether the run of silence going on now has been counted.
    counted: bool,
}

impl Gaps {
    /// Take one frame, audible or silent (or neither: a quiet packet, a
    /// concealed one), and say whether it is the frame that makes a run of
    /// silence a [`Heard::cut`]: one that began straight after the tone, or
    /// one that ended straight into it. Either way the tone lost frames to
    /// it, and a run is counted once.
    fn cuts(&mut self, audible: bool, silent: bool) -> bool {
        let cut = if silent {
            let starts_in_tone = self.was_audible;
            if starts_in_tone {
                self.counted = true;
            }
            starts_in_tone
        } else {
            let ends_in_tone = audible && self.was_silent && !self.counted;
            self.counted = false;
            ends_in_tone
        };
        self.was_audible = audible;
        self.was_silent = silent;
        cut
    }
}

/// A marker [`Media::arm_mark`] has put on the wire, or is waiting for the
/// next captured frame to carry: `crate::latency`'s own round trip, from the
/// microphone's own instant to whichever frame comes back at [`MARK_LOUDNESS`].
#[derive(Clone, Copy)]
struct PendingMark {
    /// The instant `arm_mark` was called: the microphone's own moment, so
    /// the round trip this becomes counts the wait for the next captured
    /// frame the way a real capture-to-network delay would.
    armed: Instant,
    /// The instant a captured frame actually carried it, once one has.
    sent: Option<Instant>,
}

/// One marker's completed round trip: `crate::latency` reads three numbers
/// out of it rather than one, because "the delay" is three stages added
/// together and only one of them — the buffer's own target when the echo
/// came back — is `sipral`'s own to ask for.
pub(crate) struct Mark {
    /// The wait for the next captured frame: [`PendingMark::sent`] less
    /// [`PendingMark::armed`], at most one packetisation interval.
    pub(crate) capture_wait: Duration,
    /// [`PendingMark::armed`] to the instant this end's own playback took
    /// the echo back: the whole round trip, capture wait included.
    pub(crate) round_trip: Duration,
    /// The jitter buffer's own target delay the instant the echo was taken,
    /// read off `sipral::MediaSession::statistics` the way every other
    /// caller of it in this file already does.
    pub(crate) buffer_target: Duration,
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
    /// Whether [`Media::turn`] reads the socket for its session. Not when
    /// the socket is shared by the branches of a forked call
    /// ([`Media::share`]): only the engine can say which branch a datagram
    /// is for, so the flow reads it once and hands it to the engine
    /// ([`Media::receive_early`]).
    reads: bool,
    /// Whether a session has been driven on this socket yet: the pace below
    /// starts from the first turn, not from the moment the socket was bound.
    running: bool,
    started: Instant,
    /// When the next frame is captured and sent.
    next: Instant,
    /// When the next frame is taken for the earpiece.
    next_play: Instant,
    /// How long the earpiece takes to play one frame: [`PACE`], unless
    /// [`Media::skew_playout`] set its clock off by a known amount.
    play_pace: Duration,
    /// Frames the earpiece takes at each callback: one, unless
    /// [`Media::earpiece_frames`] made its device period longer.
    callback_frames: u32,
    /// The run of silence going on now, for [`Heard::longest_silence`].
    silence_run: u32,
    /// What decides whether a run of silence is [`Heard::cut`].
    gaps: Gaps,
    phase: u32,
    heard: Heard,
    inbox: [u8; 2_048],
    /// `Some` only when [`AUDIO_GATE_ENV`] is set — see its own doc comment.
    quality: Option<quality::Gate>,
    /// [`Media::arm_mark`]'s own marker, waiting for a captured frame to
    /// carry it or for its echo to come back.
    pending_mark: Option<PendingMark>,
    /// Marks whose echo has come back since the last [`Media::take_marks`].
    marks: Vec<Mark>,
    /// A payload type written on the wire as another: `(sent, wire)`. What
    /// `Flow::Renumbered` stands between the stack and a far end that
    /// renumbered a dynamic type with (see [`Media::rewrite_payload`]).
    rewrite: Option<(u8, u8)>,
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
        Ok(Self::bind_on(socket, now))
    }

    /// A call's media on `socket`, already bound and non-blocking.
    fn bind_on(socket: UdpSocket, now: Instant) -> Self {
        Self {
            socket,
            reads: true,
            running: false,
            started: now,
            next: now,
            next_play: now,
            play_pace: PACE,
            callback_frames: 1,
            silence_run: 0,
            gaps: Gaps::default(),
            phase: 0,
            heard: Heard::default(),
            inbox: [0; 2_048],
            quality: env::var_os(AUDIO_GATE_ENV)
                .is_some()
                .then(quality::Gate::new),
            pending_mark: None,
            marks: Vec::new(),
            rewrite: None,
        }
    }

    /// A second call's own capture, earpiece and count on this socket: the
    /// sibling of a forked call, which one offer described on the socket the
    /// call placed was. From here on neither reads the socket in
    /// [`Media::turn`]; [`Media::receive_early`] reads it for both.
    ///
    /// # Errors
    /// When the socket cannot be shared.
    pub(crate) fn share(&mut self, now: Instant) -> Result<Self, String> {
        let socket = self
            .socket
            .try_clone()
            .map_err(|error| format!("cannot share the RTP socket: {error}"))?;
        self.reads = false;
        let mut shared = Self::bind_on(socket, now);
        shared.reads = false;
        Ok(shared)
    }

    /// Hand whatever arrived on this socket, known to the calls as `local`,
    /// to `engine`, which gives each datagram to the branch it is for
    /// (`MediaEngine::receive_early`). How many arrived.
    pub(crate) fn receive_early(
        &mut self,
        engine: &mut sipral::MediaEngine,
        local: SocketAddr,
        now: Instant,
    ) -> u32 {
        let mut arrived = 0_u32;
        while let Ok((length, from)) = self.socket.recv_from(&mut self.inbox) {
            let data = self.inbox.get(..length).unwrap_or_default();
            let _ = engine.receive_early(local, from, data, now);
            arrived = arrived.saturating_add(1);
        }
        arrived
    }

    /// Arm a marker for the next captured frame in place of whatever else
    /// this end would have sent, so its own echo can be told apart from the
    /// tone when it comes back. `now` is the microphone's own instant: the
    /// round trip [`Media::take_marks`] later reports is measured from here,
    /// the wait for the next captured frame included, the way a real
    /// capture-to-network delay would be.
    ///
    /// Replaces whatever mark was still waiting: one that has not come back
    /// by the time the next is armed is lost rather than left to be
    /// mistaken for this one's own echo.
    pub(crate) fn arm_mark(&mut self, now: Instant) {
        self.pending_mark = Some(PendingMark {
            armed: now,
            sent: None,
        });
    }

    /// Marks whose echo came back since the last call, oldest first.
    pub(crate) fn take_marks(&mut self) -> Vec<Mark> {
        std::mem::take(&mut self.marks)
    }

    /// Run this call's earpiece on a clock `ppm` parts per million fast (or
    /// slow, below zero) against the one the microphone and the network run
    /// on, and say how far off the pace that gives actually is.
    ///
    /// Two ends of a real call never share a clock, and the lab's do: every
    /// container on one host reads the same one, so a call there has no
    /// drift for the jitter buffer to absorb unless one is made. This makes
    /// one of a known size. A fast earpiece asks for frames sooner than they
    /// arrive, so the buffer has to invent some; a slow one leaves them
    /// piling up, so it has to drop some; either way the count it keeps says
    /// what it did, against a number known before the call.
    ///
    /// The pace is whole nanoseconds, so the skew actually run is not quite
    /// the one asked for — a quarter of a nanosecond in twenty milliseconds,
    /// a hundredth of a part per million — and the one returned is the one
    /// to compare against.
    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn skew_playout(&mut self, ppm: i32) -> f64 {
        // a clock `ppm` fast plays 1 + ppm/10^6 frames in the time the other
        // plays one, so each of its frames lasts that much less
        let pace = i128::try_from(PACE.as_nanos()).unwrap_or(i128::MAX);
        let nanos = (pace * 1_000_000 / (1_000_000 + i128::from(ppm)).max(1)).max(1);
        self.play_pace = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
        (pace as f64 / nanos as f64 - 1.0) * 1e6
    }

    /// Take `frames` frames at each of the earpiece's callbacks, all at the
    /// same instant, and call it that many frames' time later: a device whose
    /// period is longer than a packet, as a 40 ms callback on 20 ms packets
    /// is. The jitter buffer then sees two pulls at once for every two
    /// packets, and the second of each pair is the one that finds the queue
    /// short (`docs/05-media.md`, "An earpiece that takes two frames at
    /// once").
    pub(crate) const fn earpiece_frames(&mut self, frames: u32) {
        self.callback_frames = if frames == 0 { 1 } else { frames };
    }

    /// The port the offer has to advertise.
    ///
    /// # Errors
    /// When the socket cannot say what it was bound to.
    /// A second handle on this call's socket, for a thread of its own to
    /// send on: the audio engine's pump, which encodes the call's frames
    /// and hands each packet to whoever sends it (`crate::own_controls`).
    ///
    /// # Errors
    /// When the socket cannot be shared.
    pub(crate) fn sender(&self) -> Result<UdpSocket, String> {
        self.socket
            .try_clone()
            .map_err(|error| format!("cannot share the RTP socket: {error}"))
    }

    pub(crate) fn port(&self) -> Result<u16, String> {
        self.socket
            .local_addr()
            .map(|address| address.port())
            .map_err(|error| format!("the RTP socket has no address: {error}"))
    }

    /// Bind this call's socket again at `ip`, on a port of its own, keeping
    /// everything counted so far: what an application does once the address
    /// its old socket was bound to has left the machine. Answers where the
    /// new socket is.
    ///
    /// # Errors
    /// When the new socket cannot be bound or put in non-blocking mode.
    pub(crate) fn rebind(&mut self, ip: std::net::IpAddr) -> Result<SocketAddr, String> {
        let socket = UdpSocket::bind(SocketAddr::new(ip, 0))
            .map_err(|error| format!("cannot bind an RTP socket at {ip}: {error}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| format!("cannot make the RTP socket non-blocking: {error}"))?;
        let local = socket
            .local_addr()
            .map_err(|error| format!("the RTP socket has no address: {error}"))?;
        self.socket = socket;
        Ok(local)
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
    /// Write every RTP packet this end sends with payload type `sent` as
    /// `wire` instead, marker bit kept: the far end numbered the format
    /// `sent` in its answer and is the one listening, but the server on the
    /// other side of this socket numbers it `wire`.
    pub(crate) const fn rewrite_payload(&mut self, sent: u8, wire: u8) {
        self.rewrite = Some((sent, wire));
    }

    #[allow(clippy::too_many_lines)]
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
            if let Some(pending) = self
                .pending_mark
                .as_mut()
                .filter(|mark| mark.sent.is_none())
            {
                if let Some(slot) = samples.get_mut(..frame) {
                    slot.fill(MARK_AMPLITUDE);
                }
                pending.sent = Some(now);
            } else if in_spurt(elapsed) {
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
                    .send_to(
                        &rewritten(datagram.payload, self.rewrite),
                        datagram.destination,
                    )
                    .is_ok()
            {
                self.heard.sent = self.heard.sent.saturating_add(1);
                if carries_sid(datagram.payload) {
                    self.heard.sid_sent = self.heard.sid_sent.saturating_add(1);
                }
            }
            self.next += PACE;
        }

        while self.reads {
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
            for _ in 0..self.callback_frames {
                self.play_one(session, &mut played, frame, rate, now);
            }
            self.next_play += self.play_pace * self.callback_frames;
        }
    }

    /// One frame for the earpiece, and what it was.
    fn play_one(
        &mut self,
        session: &mut MediaSession,
        played: &mut [i16; MAX_SAMPLES],
        frame: usize,
        rate: u32,
        now: Instant,
    ) {
        let room = played.get_mut(..frame).unwrap_or_default();
        // the gate's evidence tells a pause stretched from a packet
        // concealed, which `Playback` reports alike; the buffer's own
        // count moving across the frame is what says which it was
        let stretched = self
            .quality
            .is_some()
            .then(|| session.statistics(now).quality.stretched);
        let outcome = session.playback(room);
        if let Some(before) = stretched
            && session.statistics(now).quality.stretched > before
            && let Some(gate) = self.quality.as_mut()
        {
            gate.stretched();
        }
        let audible = matches!(outcome, Playback::Packet) && loudness(room) >= AUDIBLE;
        if audible {
            self.heard.audible = self.heard.audible.saturating_add(1);
        }
        if matches!(outcome, Playback::Packet)
            && is_marker(room)
            && let Some(PendingMark {
                armed,
                sent: Some(sent),
            }) = self.pending_mark
        {
            self.pending_mark = None;
            self.marks.push(Mark {
                capture_wait: sent.saturating_duration_since(armed),
                round_trip: now.saturating_duration_since(armed),
                buffer_target: session.statistics(now).quality.target_delay,
            });
        }
        if matches!(outcome, Playback::ComfortNoise) {
            self.heard.comfort = self.heard.comfort.saturating_add(1);
        }
        if matches!(outcome, Playback::Concealed) {
            self.heard.concealed = self.heard.concealed.saturating_add(1);
        }
        let silent = matches!(outcome, Playback::Silence);
        if silent {
            self.heard.silent = self.heard.silent.saturating_add(1);
            self.silence_run = self.silence_run.saturating_add(1);
            self.heard.longest_silence = self.heard.longest_silence.max(self.silence_run);
        } else {
            self.silence_run = 0;
        }
        if self.gaps.cuts(audible, silent) {
            self.heard.cut = self.heard.cut.saturating_add(1);
        }
        if let Some(gate) = self.quality.as_mut() {
            gate.observe(outcome, room, rate);
        }
        self.heard.played = self.heard.played.saturating_add(1);
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

/// `packet` with its payload type moved as `rewrite` says, `(from, to)`, when
/// it carries `from`; as it is otherwise.
fn rewritten(packet: &[u8], rewrite: Option<(u8, u8)>) -> std::borrow::Cow<'_, [u8]> {
    match (rewrite, packet.get(1)) {
        (Some((from, to)), Some(&second)) if second & 0x7f == from => {
            let mut moved = packet.to_vec();
            if let Some(byte) = moved.get_mut(1) {
                *byte = (second & 0x80) | to;
            }
            std::borrow::Cow::Owned(moved)
        }
        _ => std::borrow::Cow::Borrowed(packet),
    }
}

#[cfg(test)]
mod tests {
    use super::{AMPLITUDE, Gaps, MARK_AMPLITUDE, TONE_HZ, is_marker, tone};

    /// Frames as the earpiece took them: `T` the tone, `q` a quiet packet
    /// (the far end's own pause), `s` silence because the buffer had nothing.
    /// How many runs of silence the tone was cut by.
    fn cuts(frames: &str) -> usize {
        let mut gaps = Gaps::default();
        frames
            .chars()
            .filter(|frame| gaps.cuts(*frame == 'T', *frame == 's'))
            .count()
    }

    /// A buffer that runs dry in the tone cuts it, once however long the
    /// silence lasts; one that runs dry in the far end's pause does not.
    #[test]
    fn silence_in_the_tone_is_a_cut_and_in_a_pause_is_not() {
        assert_eq!(cuts("TTsTT"), 1);
        assert_eq!(cuts("TTsssTT"), 1);
        assert_eq!(cuts("TTqqsqqTT"), 0);
    }

    /// Silence that began in a pause and ended where the tone had already
    /// started again took the start of the tone with it.
    #[test]
    fn silence_that_runs_on_into_the_tone_is_a_cut() {
        assert_eq!(cuts("TTqqssssTT"), 1);
        assert_eq!(cuts("TTsqqTTssTT"), 2);
    }

    /// `crate::latency`'s own marker has to read apart from the tone in
    /// both directions — a codec's own quantisation could in principle move
    /// either — or a call's own echo of it could be mistaken for the tone,
    /// or a loud moment of the tone could be mistaken for the echo.
    #[test]
    fn the_marker_reads_apart_from_the_tone() {
        assert!(is_marker(&[MARK_AMPLITUDE; 160]));
        assert!(!is_marker(&[AMPLITUDE; 160]));
        assert!(!is_marker(&[0; 160]));
    }

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
