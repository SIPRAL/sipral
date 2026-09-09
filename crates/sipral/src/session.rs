// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One call's audio: the RTP session, the codec, and the taps on the path
//! between them.
//!
//! This is the piece the tree was missing. `sipral-rtp` knows how to carry a
//! payload and `sipral-media` knows how to make one, and neither has ever been
//! told which codec a call agreed on, because that is a fact about a
//! negotiation and neither of them sees a negotiation. A [`MediaPlan`] is
//! exactly that fact, and this is what a plan turns into: a stream that takes
//! datagrams and gives back frames of PCM, and takes frames of PCM and gives
//! back datagrams.
//!
//! # What it does not own
//!
//! No socket and no device. The application reads a datagram and hands it
//! over; the application takes a frame and puts it in a ring buffer for
//! whatever `sipral-io-*` it linked. That is the same division the rest of the
//! tree keeps, and it is what lets one session serve a softphone with a
//! headset and an agent with a pipe.
//!
//! No clock either. `now` arrives from the caller at every entry point, as it
//! does everywhere else, which is what makes an hour of a call a test that
//! runs in a millisecond. The one thing that cannot be derived from a
//! monotonic instant — the wall clock a sender report carries — comes from
//! [`WallClock`], set once.
//!
//! # The order the two directions run in
//!
//! Receiving is: datagram in, into the de-jitter buffer, out at the playout
//! point, decoded, played. Sending is: frame in, encoded, packetised, out.
//! They meet in exactly two places. The voice activity detector runs on what
//! was *decoded*, because that is the signal the buffer's adaptation schedule
//! is about — RFC 3550's buffer may only move its delay in a pause, and the
//! pause it cares about is the far end's. And the recorder sees both, which is
//! the whole point of it.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::sdp::{Direction, MediaPlan, RtcpPlan};
use sipral_media::comfort_noise::{ComfortNoise, Generator, PAYLOAD_TYPE as COMFORT_NOISE};
use sipral_media::vad::{self, Vad};
use sipral_rtp::{
    Activity, BufferConfig, Discard, Due, PayloadTypes, Pull, Received, RtcpReceived, RtpSession,
    StreamConfig, is_rtcp,
};

use crate::clock::WallClock;
use crate::codec::Codec;
use crate::error::MediaError;
use crate::event::MediaEvent;
use crate::pipeline::Coder;
use crate::record::{Recorder, RecordingSink};
use crate::stats::StreamStatistics;

/// The largest datagram this session will build.
///
/// Not a path MTU: RTP does not discover one, and a payload that would not fit
/// here is a payload no codec in this build produces. It is the bound on the
/// two scratch buffers, and it is generous enough that SRTP's tag and index
/// still fit behind the largest Opus frame.
const DATAGRAM: usize = 1_500;

/// How long a stream may be silent before that is news, unless the
/// application says otherwise.
///
/// Ten seconds rather than one or two, because a peer doing silence
/// suppression legitimately sends nothing while nobody is talking, and a
/// watchdog that fires on a pause in the conversation is a watchdog that gets
/// turned off. Ten seconds of one-way silence is not a pause.
const DEFAULT_STALL: Duration = Duration::from_secs(10);

/// This session's share of the call's RTCP bandwidth, in octets per second.
///
/// RFC 3550 §6.2 recommends five percent of the session bandwidth. A
/// two-party narrowband call runs at about ten kilo-octets a second with
/// headers, so five percent of it is this. The interval the scheduler derives
/// from it is floored at five seconds by §6.2 regardless, which is what
/// actually decides the cadence on a call this small.
const RTCP_BANDWIDTH: f64 = 500.0;

/// A datagram to put on the media socket.
///
/// Borrowed from the session's own buffer rather than allocated, because this
/// is produced fifty times a second per call and a stack that allocates here
/// is a stack that pauses here.
#[derive(Clone, Copy, Debug)]
pub struct Datagram<'a> {
    /// Where to send it. Symmetric RTP means this moves once the far end's
    /// first packet arrives, which is what makes most NAT traversal
    /// unnecessary.
    pub destination: SocketAddr,
    /// The octets.
    pub payload: &'a [u8],
}

/// What a datagram turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Arrival {
    /// Audio, held for playout.
    Queued,
    /// Audio that was not used, and why.
    Dropped(Discard),
    /// A reception or sender report. Whatever it said about this stream has
    /// been folded into [`MediaSession::statistics`].
    Control,
    /// The far end says it is leaving the session (RFC 3550 §6.6). Audio will
    /// stop; the call has not ended until signalling says so.
    Goodbye,
    /// Control traffic that was not believed: from the wrong address, or not
    /// a well-formed compound packet.
    ControlRefused,
}

/// Where the frame that was just played came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Playback {
    /// A packet the far end sent.
    Packet,
    /// One it sent and this end did not get, filled in by the concealment.
    Concealed,
    /// Comfort noise, from an RFC 3389 payload the far end sent instead of
    /// audio.
    ComfortNoise,
    /// Nothing was due: the buffer is still filling, or the far end has
    /// stopped. Silence was written, or comfort noise where the far end has
    /// described some.
    Silence,
}

/// How a session behaves, as against what it negotiated.
///
/// Everything here is a choice rather than a consequence of the offer and the
/// answer. Nothing in it can be quietly ignored: a value that does not apply
/// to a call is one this type does not have.
#[derive(Clone, Debug, PartialEq)]
pub struct MediaConfig {
    /// The canonical name in every RTCP SDES (RFC 3550 §6.5.1). `None` builds
    /// one from the address the media is on, which is what §6.5.1 asks for
    /// when there is no user name worth putting in it.
    pub cname: Option<String>,
    /// This session's share of the call's RTCP bandwidth, in octets a second.
    pub rtcp_bandwidth: f64,
    /// How long inbound audio may stop before [`MediaEvent::Stalled`].
    /// `None` switches the watchdog off.
    pub stall_after: Option<Duration>,
    /// Whether to stop sending during silence.
    ///
    /// Off by default. It halves the bandwidth of a call in which one person
    /// is listening, and it costs a peer's own stall watchdog a reason to
    /// fire — this stack sends no RFC 3389 payload of its own to say that the
    /// silence is deliberate, so a gap looks the same from the far end as a
    /// stream that died.
    pub silence_suppression: bool,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            cname: None,
            rtcp_bandwidth: RTCP_BANDWIDTH,
            stall_after: Some(DEFAULT_STALL),
            silence_suppression: false,
        }
    }
}

/// The three unpredictable numbers RFC 3550 §5.1 asks a stream to start from,
/// and the seed for the draws its report scheduling needs.
///
/// They arrive from above rather than being drawn here, for the reason
/// everything else in this tree does: a library that reaches for entropy is a
/// library that cannot be run twice and get the same answer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamIdentity {
    pub(crate) ssrc: u32,
    pub(crate) sequence: u16,
    pub(crate) timestamp: u32,
    pub(crate) seed: u64,
}

/// One call's media.
#[derive(Debug)]
pub struct MediaSession {
    rtp: RtpSession,
    coder: Coder,
    plan: MediaPlan,
    /// This session's zero on the RTP clock: `sipral-rtp` works in a duration
    /// since a point the caller chooses, and this is that point.
    origin: Instant,
    clock: WallClock,
    draws: Draws,
    frame_ms: u32,
    frame_ticks: u32,
    /// One RTP datagram, and one RTCP datagram, each held rather than
    /// allocated. Two buffers and not one, so that a report being built cannot
    /// tread on audio the caller has not sent yet.
    rtp_out: Vec<u8>,
    rtcp_out: Vec<u8>,
    payload: Vec<u8>,
    packets_sent: u64,
    octets_sent: u64,
    last_inbound: Instant,
    stall_after: Option<Duration>,
    stalled: bool,
    /// What the far end's last decoded frame was, which is what the buffer is
    /// allowed to move its delay on.
    activity: Activity,
    inbound_voice: Vad,
    outbound_voice: Vad,
    suppressing: bool,
    noise: Generator,
    recorder: Option<Recorder>,
    events: VecDeque<MediaEvent>,
}

impl MediaSession {
    /// Open the media for a plan the negotiation produced.
    ///
    /// # Errors
    /// [`MediaError::UnknownPayload`] when the answer named a format this
    /// build cannot decode, and [`MediaError::Codec`] when the codec refuses
    /// the frame length.
    pub(crate) fn open(
        plan: &MediaPlan,
        frame_ms: u32,
        config: &MediaConfig,
        identity: StreamIdentity,
        clock: WallClock,
        now: Instant,
    ) -> Result<Self, MediaError> {
        let agreed = Codec::of_plan(plan)?;
        let coder = Coder::new(agreed, frame_ms)?;
        let frame_ticks = agreed.frame_ticks(frame_ms);
        let rtp = RtpSession::new(
            &StreamConfig {
                ssrc: identity.ssrc,
                payload_type: plan.codec.payload(),
                accepted: accepted(plan),
                clock_rate: plan.codec.clock_rate(),
                sequence: identity.sequence,
                timestamp: identity.timestamp,
                remote: plan.remote,
                silence_suppression: config.silence_suppression,
                playout: BufferConfig::new(frame_ticks),
                cname: config
                    .cname
                    .clone()
                    .unwrap_or_else(|| format!("sipral@{}", plan.local.ip())),
                rtcp_bandwidth: config.rtcp_bandwidth,
            },
            0.5,
        );
        Ok(Self {
            rtp,
            coder,
            plan: plan.clone(),
            origin: now,
            clock,
            draws: Draws::new(identity.seed),
            frame_ms,
            frame_ticks,
            rtp_out: vec![0; DATAGRAM],
            rtcp_out: vec![0; DATAGRAM],
            payload: vec![0; agreed.max_payload(frame_ms)],
            packets_sent: 0,
            octets_sent: 0,
            last_inbound: now,
            stall_after: config.stall_after,
            stalled: false,
            activity: Activity::Speech,
            inbound_voice: Vad::new(agreed.sample_rate()),
            outbound_voice: Vad::new(agreed.sample_rate()),
            suppressing: config.silence_suppression,
            noise: Generator::new(),
            recorder: None,
            events: VecDeque::new(),
        })
    }

    /// What the negotiation settled on.
    #[must_use]
    pub const fn codec(&self) -> Codec {
        self.coder.codec()
    }

    /// The rate the samples handed to and taken from this session are at,
    /// which is the codec's and not the RTP clock's.
    #[must_use]
    pub fn sample_rate(&self) -> u32 {
        self.codec().sample_rate()
    }

    /// Samples in one frame. Both [`MediaSession::playback`] and
    /// [`MediaSession::capture`] work in exactly this many.
    #[must_use]
    pub const fn frame_samples(&self) -> usize {
        self.coder.frame_samples()
    }

    /// Which way audio may flow, as seen from here.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.plan.direction
    }

    /// Whether this end is meant to be sending: false while it holds the far
    /// end, or while the far end has refused to receive.
    #[must_use]
    pub const fn is_sending(&self) -> bool {
        matches!(self.direction(), Direction::SendRecv | Direction::SendOnly)
    }

    /// Whether this end is meant to be receiving.
    #[must_use]
    pub const fn is_receiving(&self) -> bool {
        matches!(self.direction(), Direction::SendRecv | Direction::RecvOnly)
    }

    /// Where audio goes: the address packets are arriving from once any have,
    /// and the negotiated one until then.
    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        self.rtp.destination()
    }

    /// Where control traffic goes, or `None` when the negotiation switched
    /// RTCP off.
    #[must_use]
    pub fn control_destination(&self) -> Option<SocketAddr> {
        match self.plan.rtcp {
            RtcpPlan::Muxed => Some(self.destination()),
            RtcpPlan::SeparatePort { remote, .. } => Some(remote),
            RtcpPlan::Off => None,
        }
    }

    /// Something the application has to know about this stream. Drain to
    /// empty.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<MediaEvent> {
        self.events.pop_front()
    }

    /// What the stream has cost, and what it is costing now.
    ///
    /// Cheap enough to poll at the frame rate of a user interface: everything
    /// in it is already counted, and nothing here allocates or walks a
    /// history. `now` is here for the same reason it is everywhere else —
    /// "how long since a packet arrived" is a question about the present, and
    /// nothing in this crate is allowed to ask a clock what the present is.
    #[must_use]
    pub fn statistics(&self, now: Instant) -> StreamStatistics {
        StreamStatistics {
            codec: self.codec(),
            quality: self.rtp.quality(),
            round_trip: self.rtp.round_trip_time(),
            packets_sent: self.packets_sent,
            octets_sent: self.octets_sent,
            silent_for: now.saturating_duration_since(self.last_inbound),
        }
    }
}

// -- what arrives ------------------------------------------------------------

impl MediaSession {
    /// Take a datagram off the media socket.
    ///
    /// RTP and RTCP are told apart by RFC 5761 §4's rule on the payload type
    /// field, which is what makes a multiplexed stream work at all; it costs
    /// one comparison on a stream that is not multiplexed, and it means an
    /// application that put both on one socket does not have to sort them
    /// itself.
    pub fn receive(&mut self, datagram: &mut [u8], from: SocketAddr, now: Instant) -> Arrival {
        if is_rtcp(datagram) {
            return self.receive_control(datagram, from, now);
        }
        let elapsed = self.elapsed(now);
        match self.rtp.receive(datagram, from, elapsed) {
            Received::Queued => {
                self.note_arrival(now);
                Arrival::Queued
            }
            Received::Dropped(why) => Arrival::Dropped(why),
        }
    }

    /// Take a datagram off the control socket, for a call whose RTCP has a
    /// port of its own.
    pub fn receive_control(
        &mut self,
        datagram: &mut [u8],
        from: SocketAddr,
        now: Instant,
    ) -> Arrival {
        let elapsed = self.elapsed(now);
        let ntp = self.clock.at(now);
        match self.rtp.rtcp_receive(datagram, from, elapsed, ntp) {
            RtcpReceived::Report => Arrival::Control,
            RtcpReceived::Goodbye { .. } => Arrival::Goodbye,
            RtcpReceived::ForeignAddress
            | RtcpReceived::Malformed(_)
            | RtcpReceived::Insecure(_) => Arrival::ControlRefused,
        }
    }

    /// Take the frame that is due for the earpiece, and say where it came
    /// from.
    ///
    /// `out` is filled to [`MediaSession::frame_samples`] and anything beyond
    /// that is left alone. Every variant fills it, concealment and silence
    /// included, because a device that is handed nothing for one frame plays
    /// whatever was in its buffer last and that is a far worse sound than the
    /// one being concealed.
    pub fn playback(&mut self, out: &mut [i16]) -> Playback {
        let frame = self.frame_samples().min(out.len());
        let room = out.get_mut(..frame).unwrap_or_default();
        let played = self.fill(room);
        // the buffer may only move its delay in a pause, and the pause it
        // cares about is the far end's — so the verdict handed to the next
        // pull is the one on the frame that has just been decoded
        self.activity = match self.inbound_voice.process(room) {
            vad::Activity::Speech => Activity::Speech,
            vad::Activity::Silence => Activity::Silence,
        };
        if let Some(error) = self
            .recorder
            .as_mut()
            .and_then(|recorder| recorder.played(room).err())
        {
            self.recording_stopped(error);
        }
        played
    }

    /// Decode whatever the jitter buffer had for this frame into `room`.
    fn fill(&mut self, room: &mut [i16]) -> Playback {
        let coder = &mut self.coder;
        let noise = &mut self.noise;
        let payload_type = self.plan.codec.payload();
        match self.rtp.pull(self.activity) {
            Pull::Packet(frame) if frame.payload_type == COMFORT_NOISE => {
                if let Ok(described) = ComfortNoise::decode(frame.payload) {
                    noise.received(described);
                }
                noise.fill(room);
                Playback::ComfortNoise
            }
            Pull::Packet(frame) if frame.payload_type == payload_type => {
                match coder.decode(frame.payload, room) {
                    // a payload the codec refuses is a corrupt one, and the
                    // right thing to play for it is the frame it displaced
                    Ok(_) => Playback::Packet,
                    Err(_) => conceal(coder, room),
                }
            }
            // a type that was negotiated but is neither of those is the named
            // events, which are not audio and leave the earpiece alone
            Pull::Packet(_) | Pull::Conceal | Pull::Stretch => conceal(coder, room),
            Pull::Empty => {
                if noise.is_silent() {
                    room.fill(0);
                    Playback::Silence
                } else {
                    noise.fill(room);
                    Playback::ComfortNoise
                }
            }
        }
    }

    /// Remember that audio arrived, and say so if it had stopped.
    fn note_arrival(&mut self, now: Instant) {
        if self.stalled {
            self.stalled = false;
            self.events.push_back(MediaEvent::Resumed {
                silent_for: now.saturating_duration_since(self.last_inbound),
            });
        }
        self.last_inbound = now;
    }
}

// -- what goes out -----------------------------------------------------------

impl MediaSession {
    /// Put one frame from the microphone on the wire.
    ///
    /// `Ok(None)` for a frame that was deliberately not sent: this end is
    /// holding the far end, or silence suppression swallowed it. The RTP
    /// timestamp still moves by a frame either way, because §5.1 makes it a
    /// measure of time rather than of packets, and a far end whose timestamps
    /// stopped while the call went on would hear the resumption as a jump.
    ///
    /// # Errors
    /// [`MediaError::Codec`] when the codec refuses the frame, and
    /// [`MediaError::PacketTooLong`] for a payload no buffer here can hold,
    /// which no codec in this build produces.
    pub fn capture(&mut self, samples: &[i16]) -> Result<Option<Datagram<'_>>, MediaError> {
        if let Some(error) = self
            .recorder
            .as_mut()
            .and_then(|recorder| recorder.captured(samples).err())
        {
            self.recording_stopped(error);
        }
        let silent =
            self.suppressing && self.outbound_voice.process(samples) == vad::Activity::Silence;
        if !self.is_sending() || silent {
            self.rtp.suppress(self.frame_ticks);
            return Ok(None);
        }
        let written = self.coder.encode(samples, &mut self.payload)?;
        let payload = self.payload.get(..written).unwrap_or_default();
        let length = self
            .rtp
            .send(payload, self.frame_ticks, &mut self.rtp_out)
            .map_err(|_| MediaError::PacketTooLong {
                need: written,
                got: self.rtp_out.len(),
            })?;
        self.packets_sent = self.packets_sent.saturating_add(1);
        self.octets_sent = self
            .octets_sent
            .saturating_add(u64::try_from(written).unwrap_or(0));
        Ok(Some(Datagram {
            destination: self.rtp.destination(),
            payload: self.rtp_out.get(..length).unwrap_or_default(),
        }))
    }

    /// The periodic RTCP report, when one is due.
    ///
    /// Call it whenever [`MediaSession::poll_timeout`] says to and whenever a
    /// frame goes out; it answers `None` until §6.3's schedule says otherwise,
    /// and answers `None` for ever on a call that negotiated no RTCP.
    #[must_use]
    pub fn poll_rtcp(&mut self, now: Instant) -> Option<Datagram<'_>> {
        let destination = self.control_destination()?;
        let elapsed = self.elapsed(now);
        if !matches!(self.rtp.rtcp_due(elapsed, self.draws.unit()), Due::Send) {
            return None;
        }
        let ntp = self.clock.at(now);
        let draw = self.draws.unit();
        let (length, _) = self
            .rtp
            .build_report(&mut self.rtcp_out, elapsed, ntp, draw)
            .ok()?;
        Some(Datagram {
            destination,
            payload: self.rtcp_out.get(..length).unwrap_or_default(),
        })
    }

    /// The RTCP BYE that says this end has left (RFC 3550 §6.6).
    ///
    /// Sent once, when the call ends and before the socket is closed. A far
    /// end that gets it stops expecting audio immediately instead of waiting
    /// for its own timeout, which is the difference between a call that ends
    /// and one that trails off.
    #[must_use]
    pub fn goodbye(&mut self, now: Instant) -> Option<Datagram<'_>> {
        let destination = self.control_destination()?;
        let elapsed = self.elapsed(now);
        let draw = self.draws.unit();
        let length = self
            .rtp
            .send_bye(&mut self.rtcp_out, elapsed, b"", draw)
            .ok()?;
        Some(Datagram {
            destination,
            payload: self.rtcp_out.get(..length).unwrap_or_default(),
        })
    }
}

// -- time --------------------------------------------------------------------

impl MediaSession {
    /// When to call [`MediaSession::handle_timeout`], if nothing arrives
    /// first.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let rtcp = self
            .control_destination()
            .map(|_| self.origin + self.rtp.next_rtcp_deadline());
        let stall = self
            .stall_after
            .filter(|_| self.is_receiving() && !self.stalled)
            .map(|after| self.last_inbound + after);
        match (rtcp, stall) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    /// Time has passed. The only thing this decides is whether the stream has
    /// stopped; a report that is due is taken with
    /// [`MediaSession::poll_rtcp`], because it needs somewhere to be written.
    pub fn handle_timeout(&mut self, now: Instant) {
        let Some(after) = self.stall_after else {
            return;
        };
        if self.stalled || !self.is_receiving() {
            return;
        }
        let silent_for = now.saturating_duration_since(self.last_inbound);
        if silent_for >= after {
            self.stalled = true;
            self.events.push_back(MediaEvent::Stalled { silent_for });
        }
    }

    /// Whether inbound audio is currently considered stopped.
    #[must_use]
    pub const fn is_stalled(&self) -> bool {
        self.stalled
    }

    /// Whether §6.3's schedule has reached the next report, without the side
    /// effects of asking it properly.
    ///
    /// [`RtpSession::rtcp_due`] both answers and reconsiders, and reconsidering
    /// twice per report would move the cadence — so a caller looking for the
    /// one session out of several that has something to send asks this first.
    #[must_use]
    pub fn rtcp_deadline_passed(&self, now: Instant) -> bool {
        self.control_destination().is_some() && self.elapsed(now) >= self.rtp.next_rtcp_deadline()
    }

    /// This session's own timeline, which is what `sipral-rtp` counts in.
    fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.origin)
    }
}

// -- what changes under a live call ------------------------------------------

impl MediaSession {
    /// Take a plan that has moved: a hold, a resume, or a far end that
    /// changed its media address.
    ///
    /// The codec is not allowed to change here — a stream that swapped codecs
    /// would need a new encoder, a new decoder and a new frame length, and
    /// the honest way to get those is a new session — so
    /// [`MediaEngine`](crate::MediaEngine) opens one rather than calling this
    /// when the answer names a different one.
    pub(crate) fn adopt(&mut self, plan: &MediaPlan, now: Instant) {
        if plan.remote != self.plan.remote {
            self.rtp.relocate(plan.remote);
            // a far end that moved its media address has almost always
            // restarted the stream behind it, and the sequence numbers of the
            // old one say nothing about the new
            self.rtp.resync();
            self.last_inbound = now;
        }
        self.plan = plan.clone();
        // a stream that has just been told to stop receiving must not be
        // reported as stalled for having done so
        if !self.is_receiving() {
            self.stalled = false;
        }
    }

    /// The plan this session is running.
    #[must_use]
    pub const fn plan(&self) -> &MediaPlan {
        &self.plan
    }

    /// How long a frame is, in milliseconds.
    #[must_use]
    pub const fn frame_length(&self) -> u32 {
        self.frame_ms
    }
}

// -- recording ---------------------------------------------------------------

impl MediaSession {
    /// Start recording this call into `sink`.
    ///
    /// Both directions, mixed, as WAVE at [`MediaSession::sample_rate`]. It
    /// can be started and stopped as often as the person on the phone presses
    /// the button; each recording is a file of its own, because a sink that
    /// was written to twice would have two headers in it.
    ///
    /// # Errors
    /// [`MediaError::AlreadyRecording`] when one is already running, and
    /// [`MediaError::Recording`] when the sink refused the header.
    pub fn start_recording(&mut self, sink: Box<dyn RecordingSink>) -> Result<(), MediaError> {
        if self.recorder.is_some() {
            return Err(MediaError::AlreadyRecording);
        }
        let recorder = Recorder::start(sink, self.sample_rate(), self.frame_samples())?;
        self.recorder = Some(recorder);
        Ok(())
    }

    /// Stop the recording and close the file.
    ///
    /// # Errors
    /// [`MediaError::NotRecording`], and [`MediaError::Recording`] when the
    /// lengths in the header could not be patched — which leaves a file with
    /// all of the audio in it and zeroes in two fields.
    pub fn stop_recording(&mut self) -> Result<(), MediaError> {
        let recorder = self.recorder.take().ok_or(MediaError::NotRecording)?;
        recorder.finish()?;
        Ok(())
    }

    /// Whether a recording is running.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recorder.is_some()
    }

    /// How much audio the current recording has taken.
    #[must_use]
    pub fn recorded(&self) -> Option<Duration> {
        self.recorder
            .as_ref()
            .map(|recorder| self.span(recorder.written()))
    }

    /// A recording that failed part-way through: the file is let go, an event
    /// says so, and the call is untouched.
    ///
    /// The sink is dropped without the header being patched, because the
    /// header cannot be patched — whatever refused the audio will refuse that
    /// too. The audio is in the file; two fields in front of it are zero.
    fn recording_stopped(&mut self, error: std::io::Error) {
        let written = self
            .recorder
            .take()
            .map_or(0, |recorder| recorder.written());
        self.events.push_back(MediaEvent::RecordingStopped {
            reason: MediaError::from(error),
            written: self.span(written),
        });
    }

    /// A count of samples as a length of time at this session's rate.
    fn span(&self, samples: u64) -> Duration {
        let rate = u64::from(self.sample_rate()).max(1);
        Duration::from_nanos(samples.saturating_mul(1_000_000_000) / rate)
    }
}

/// The payload types this stream will take in: what was agreed, the named
/// events if any were, and comfort noise.
///
/// Nothing else, and deliberately. A peer that answers with one companding law
/// and sends the other is a real thing, and accepting it would mean decoding
/// A-law through a mu-law table, which is not quiet distortion but loud
/// distortion. Dropping it shows up in the statistics and then in the stall
/// watchdog, which is a fault somebody can act on.
fn accepted(plan: &MediaPlan) -> PayloadTypes {
    let types = PayloadTypes::none()
        .with(plan.codec.payload())
        .with(COMFORT_NOISE);
    match plan.dtmf {
        Some(payload) => types.with(payload),
        None => types,
    }
}

/// Conceal one frame, whichever concealment this codec has.
fn conceal(coder: &mut Coder, room: &mut [i16]) -> Playback {
    if coder.conceal(room).is_err() {
        room.fill(0);
    }
    Playback::Concealed
}

/// The uniform draws on `[0, 1)` that RFC 3550 §6.3.1 asks for when it
/// schedules a report.
///
/// Seeded from above like everything else unpredictable in this tree, and
/// SplitMix64 behind it — published, tiny, and with no state to carry beyond
/// the counter. Nothing here is a source of secrecy: a report interval that an
/// observer could predict tells them when the next report goes and nothing
/// else, and the seed comes from the same stream the branches and tags do
/// because there is no reason to ask the caller for a second one.
#[derive(Debug)]
struct Draws {
    state: u64,
}

impl Draws {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// One draw, uniform on `[0, 1)`.
    fn unit(&mut self) -> f64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        // the top thirty-two bits over two to the thirty-two: exactly
        // representable, and short of one by construction
        f64::from(u32::try_from(z >> 32).unwrap_or(0)) / 4_294_967_296.0
    }
}
