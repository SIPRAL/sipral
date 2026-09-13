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

use sipral_core::sdp::{CryptoPolicy, Direction, Keying, MediaPlan, RtcpPlan};
use sipral_media::comfort_noise::{ComfortNoise, Generator, PAYLOAD_TYPE as COMFORT_NOISE};
use sipral_media::processor::Processor;
use sipral_media::vad::{self, Vad};
use sipral_rtp::srtp::{Master, Policy, Rekeyed};
use sipral_rtp::{
    Activity, BufferConfig, Discard, Due as RtcpDue, EVENT_LEN, EventReceiver, Outcome,
    PayloadTypes, Pull, Received, Reported, RtcpReceived, RtpSession, StreamConfig, StreamFormat,
    is_rtcp,
};

use crate::clock::WallClock;
use crate::codec::{Codec, CodecCandidate};
use crate::dtmf::{self, DIGIT_GAP, Dialling, Digit, Due, SHORTEST_DIGIT};
use crate::echo::{Echo, MAX_RENDER_DELAY};
use crate::error::MediaError;
use crate::event::MediaEvent;
use crate::keying;
use crate::pipeline::Coder;
use crate::record::{Recorder, RecordingSink};
use crate::stats::StreamStatistics;

/// The largest datagram this session will build.
///
/// Not a path MTU: RTP does not discover one, and a payload that would not fit
/// here is a payload no codec in this build produces. It is the bound on the
/// two scratch buffers, and it is generous enough that SRTP's tag and index
/// still fit behind the largest frame anything here can produce: twelve
/// octets of fixed header, at most 1275 of payload — the largest Opus frame
/// (`opus::MAX_FRAME_BYTES`), and only where the codec is linked, against 160
/// for twenty milliseconds of G.711 — and ten of tag, so 1297 at the top, and
/// a protected compound report is thirty-nine octets under the same roof.
/// `RtpSession` subtracts its own overhead from whatever it is handed and
/// refuses a buffer that is short before a sequence number is spent, so a
/// number that stopped being enough would be a refused frame rather than a
/// truncated one.
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
    /// How long the loudspeaker takes to reach the microphone on this device,
    /// which is what [`MediaSession::attach_processor`] aligns its reference
    /// against.
    ///
    /// Zero unless the application says otherwise, and it can only say so from
    /// the platform, through whichever `sipral-io-*` it linked: no portable
    /// guess is worth making. It is kept whether or not a
    /// processor is ever attached — attaching one later must not need the
    /// number set a second time — and refused above
    /// [`MAX_RENDER_DELAY`](crate::MAX_RENDER_DELAY), because a delay that
    /// long is a wrong number rather than a slow device.
    pub render_delay: Duration,
    /// Which physical device this call's audio is on, as an opaque identity
    /// the application chose.
    ///
    /// This crate never opens a device and never reads this string; it only
    /// carries it, the way it carries [`MediaConfig::render_delay`], so that
    /// "which headset is call X on" (A2 in `docs/13-client-requirements.md`)
    /// has an answer on the call itself rather than in a side table an
    /// application has to keep in step with the call table by hand — which is
    /// exactly the kind of global D6 is about, because the table only has one
    /// entry per call until somebody starts a second call on a different
    /// headset. `None` is a call whose device has not been recorded, not a
    /// call known to be on the system default.
    pub device: Option<String>,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            cname: None,
            rtcp_bandwidth: RTCP_BANDWIDTH,
            stall_after: Some(DEFAULT_STALL),
            silence_suppression: false,
            render_delay: Duration::ZERO,
            device: None,
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
    /// Echo cancellation, gain control and noise suppression, when the
    /// application attached any. `None` is the whole of the cost of not
    /// having one: no history, no copy, no call.
    echo: Option<Echo>,
    render_delay: Duration,
    /// The digits this end still owes the far end, and the one going out.
    dialling: Dialling,
    /// The digits coming the other way, when the call negotiated a type for
    /// them.
    heard: Option<EventReceiver>,
    events: VecDeque<MediaEvent>,
    /// D5: what became of every codec this call's catalogue could have used.
    codec_candidates: Vec<CodecCandidate>,
    /// A2, D6: which device this call's audio is on, carried rather than
    /// interpreted. See [`MediaConfig::device`].
    device: Option<String>,
}

impl MediaSession {
    /// Open the media for a plan the negotiation produced.
    ///
    /// `candidates` is D5's record of what became of every codec this call's
    /// catalogue could have used, already worked out by the caller — a
    /// negotiation this crate does not repeat and cannot get wrong twice.
    ///
    /// # Errors
    /// [`MediaError::UnknownPayload`] when the answer named a format this
    /// build cannot decode,
    // the variant is Opus's and exists only where Opus does, so the link has
    // to as well, or the documentation of a build without it points at
    // nothing and promises an error that build cannot produce
    #[cfg_attr(
        feature = "opus",
        doc = "[`MediaError::Codec`] when the codec refuses the frame length,"
    )]
    /// [`MediaError::RenderDelayTooLong`] for a render-to-capture delay no
    /// device has, and [`MediaError::NoDtlsSrtp`] or
    /// [`MediaError::UnusableKeying`] for a plan whose keys this build cannot
    /// open a stream with.
    pub(crate) fn open(
        plan: &MediaPlan,
        frame_ms: u32,
        config: &MediaConfig,
        identity: StreamIdentity,
        clock: WallClock,
        candidates: Vec<CodecCandidate>,
        now: Instant,
    ) -> Result<Self, MediaError> {
        let agreed = Codec::of_plan(plan)?;
        if config.render_delay > MAX_RENDER_DELAY {
            return Err(MediaError::RenderDelayTooLong {
                asked: config.render_delay,
                most: MAX_RENDER_DELAY,
            });
        }
        let coder = Coder::new(agreed, frame_ms)?;
        let frame_ticks = agreed.frame_ticks(frame_ms);
        let stream = StreamConfig {
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
        };
        // the first RTCP report's random factor draws from this call's own
        // seeded randomness like every later one does (RFC 3550 §6.2, §6.3.2)
        // rather than a fixed number, or every call opened from the same
        // catalogue of codecs would schedule its first report at the same
        // point in its interval
        let mut draws = Draws::new(identity.seed);
        // the keys the negotiation produced, if it produced any. Everything
        // the protected session builds goes out encrypted and everything
        // arriving is verified before any of it is believed, so this is the
        // last point at which the two shapes of stream differ
        let rtp = match keying::security(plan)? {
            Some(security) => RtpSession::protected(&stream, draws.unit(), security),
            None => RtpSession::new(&stream, draws.unit()),
        };
        Ok(Self {
            rtp,
            coder,
            plan: plan.clone(),
            origin: now,
            clock,
            draws,
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
            echo: None,
            render_delay: config.render_delay,
            dialling: Dialling::new(ticks_of(DIGIT_GAP, plan.codec.clock_rate())),
            heard: plan.dtmf.map(EventReceiver::new),
            events: VecDeque::new(),
            codec_candidates: candidates,
            device: config.device.clone(),
        })
    }

    /// What the negotiation settled on.
    #[must_use]
    pub const fn codec(&self) -> Codec {
        self.coder.codec()
    }

    /// D5: what became of every codec this call's catalogue could have used.
    /// Exactly one entry carries [`crate::CodecOutcome::Chosen`], and it names
    /// [`MediaSession::codec`].
    #[must_use]
    pub fn codec_candidates(&self) -> &[CodecCandidate] {
        &self.codec_candidates
    }

    /// Which device this call's audio is on, as the opaque identity the
    /// application last gave it — see [`MediaConfig::device`].
    #[must_use]
    pub fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }

    /// Say which device this call has moved to, or that it has none.
    ///
    /// Matches [`MediaSession::set_render_delay`] in shape and in reason: a
    /// headset reconnecting over Bluetooth mid-call is exactly when this
    /// changes, so the application learns it after the call is already up as
    /// often as before it.
    pub fn set_device(&mut self, device: Option<String>) {
        self.device = device;
    }

    /// Whether this call's audio is encrypted.
    ///
    /// True only for a stream whose keys were actually negotiated and are
    /// actually in use, which is what a padlock on a screen has to mean. A
    /// call that asked for SDES and got a plain answer never reaches here —
    /// the stream is refused or the session is not opened — so there is no
    /// state in which this says yes and the packets say otherwise.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        matches!(self.plan.keying, Some(Keying::Sdes { .. }))
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
        // this is the frame the loudspeaker is about to have, so it is the
        // one a canceller will be looking for in the microphone a device
        // delay from now
        if let Some(echo) = self.echo.as_mut() {
            echo.rendered(room);
        }
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
        let heard = &mut self.heard;
        let events = &mut self.events;
        let payload_type = self.plan.codec.payload();
        let rate = self.plan.codec.clock_rate();
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
            // events, which are not audio and leave the earpiece alone. The
            // receiver collapses a digit's updates and its closing packet's
            // three transmissions into one report, keyed on the timestamp that
            // identifies the event -- reporting per packet would turn one
            // keypress into five
            Pull::Packet(frame) => {
                if let Some(receiver) = heard.as_mut()
                    && let Ok(Outcome::Reported(reported)) = receiver.receive(frame)
                {
                    events.push_back(digit_heard(&reported, rate));
                }
                conceal(coder, room)
            }
            Pull::Conceal | Pull::Stretch => conceal(coder, room),
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
    // the variant is Opus's and exists only where Opus does, so the link has
    // to as well or the documentation of a build without it points at nothing
    #[cfg_attr(
        feature = "opus",
        doc = "[`MediaError::Codec`] when the codec refuses the frame, and"
    )]
    /// [`MediaError::PacketTooLong`] for a payload no buffer here can hold,
    /// which no codec in this build produces.
    pub fn capture(&mut self, samples: &[i16]) -> Result<Option<Datagram<'_>>, MediaError> {
        // the processor is lifted out for the length of the frame so that the
        // audio it produces can be borrowed from it while the rest of the
        // session is still being written to
        let mut echo = self.echo.take();
        let sent = self.encode_frame(samples, echo.as_mut());
        self.echo = echo;
        Ok(sent?.map(|length| Datagram {
            destination: self.rtp.destination(),
            payload: self.rtp_out.get(..length).unwrap_or_default(),
        }))
    }

    /// One captured frame as far as the octets in `rtp_out`, or `None` for a
    /// frame that was deliberately not sent.
    fn encode_frame(
        &mut self,
        samples: &[i16],
        echo: Option<&mut Echo>,
    ) -> Result<Option<usize>, MediaError> {
        // everything below works on what the processor left, not on the raw
        // microphone: silence suppression measuring uncancelled echo would
        // hold the stream open through the far end's own talking, and a
        // recording of the raw capture would not be a recording of the call
        let samples = match echo {
            Some(echo) => echo.process(samples),
            None => samples,
        };
        if let Some(error) = self
            .recorder
            .as_mut()
            .and_then(|recorder| recorder.captured(samples).err())
        {
            self.recording_stopped(error);
        }
        if !self.is_sending() {
            self.rtp.suppress(self.frame_ticks);
            return Ok(None);
        }
        if let Some(length) = self.dial_frame()? {
            return Ok(Some(length));
        }
        let silent =
            self.suppressing && self.outbound_voice.process(samples) == vad::Activity::Silence;
        if silent {
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
        Ok(Some(length))
    }

    /// One packet of a digit that is being dialled, when there is one.
    ///
    /// `None` means nothing is being dialled and the frame is the audio's.
    ///
    /// # Errors
    /// [`MediaError::PacketTooLong`], which the four-octet payload of a named
    /// event cannot really produce.
    fn dial_frame(&mut self) -> Result<Option<usize>, MediaError> {
        let Some(payload_type) = self.plan.dtmf else {
            self.dialling.clear();
            return Ok(None);
        };
        let frame = self.frame_ticks;
        let rtp = &self.rtp;
        let due = self
            .dialling
            .next(frame, |event| rtp.start_event(event, dtmf::VOLUME));
        let Due::Event { outgoing, repeat } = due else {
            return Ok(None);
        };
        let length = self
            .rtp
            .send_event(outgoing, payload_type, &mut self.rtp_out)
            .map_err(|_| MediaError::PacketTooLong {
                need: EVENT_LEN,
                got: self.rtp_out.len(),
            })?;
        // an update carries the duration so far and moves the audio clock with
        // it; the two repeats of the closing packet report a duration already
        // reported and move nothing, so the frame of real time they take is
        // silence like any other and has to be accounted for
        if repeat {
            self.rtp.suppress(frame);
        }
        self.packets_sent = self.packets_sent.saturating_add(1);
        self.octets_sent = self
            .octets_sent
            .saturating_add(u64::try_from(EVENT_LEN).unwrap_or(0));
        Ok(Some(length))
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
        if !matches!(self.rtp.rtcp_due(elapsed, self.draws.unit()), RtcpDue::Send) {
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
        // a digit whose three closing packets were all lost is still a digit
        // that was pressed, and this is the last moment it can be reported
        if let Some(reported) = self.heard.as_mut().and_then(EventReceiver::flush) {
            let rate = self.plan.codec.clock_rate();
            self.events.push_back(digit_heard(&reported, rate));
        }
        self.dialling.clear();
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

/// One direction's keying, as a re-negotiation left it.
struct Rekey {
    policy: Policy,
    master: Master,
    what: Rekeyed,
}

impl Rekey {
    /// What has to happen to one direction, given the crypto line it was
    /// running under and the one the negotiation settled on.
    ///
    /// # Errors
    /// As [`keying::context`], for a fresh line this build cannot open a
    /// stream with.
    fn between(was: &CryptoPolicy, now: &CryptoPolicy) -> Result<Option<Self>, MediaError> {
        // the key and salt alone, because RFC 3711 §4.3.1 derives the session
        // keys from them and the index and from nothing else: a lifetime or an
        // identifier written beside an unchanged key has re-keyed nothing
        let same_key = was
            .keys
            .iter()
            .map(|inline| &inline.keys)
            .eq(now.keys.iter().map(|inline| &inline.keys));
        let what = if same_key {
            if was == now {
                return Ok(None);
            }
            Rekeyed::Terms
        } else {
            Rekeyed::Key
        };
        let (policy, master) = keying::context(now)?;
        Ok(Some(Self {
            policy,
            master,
            what,
        }))
    }
}

impl MediaSession {
    /// Take a plan that has moved: a hold, a resume, or a far end that
    /// changed its media address.
    ///
    /// The codec is not allowed to change here — a stream that swapped codecs
    /// would need a new encoder, a new decoder and a new frame length, and
    /// the honest way to get those is a new session — so
    /// [`MediaEngine`](crate::MediaEngine) opens one rather than calling this
    /// when the answer names a different one.
    ///
    /// `candidates` replaces D5's record with what the fresh pair of
    /// descriptions says now — a hold or a resume still runs a negotiation,
    /// and the losers it names can differ from the ones that opened the
    /// session even though the codec itself did not move.
    ///
    /// Keys move here too, one direction at a time, and only the direction
    /// whose master key actually changed. A re-negotiation is free to carry
    /// the key it already named; re-keying on that would restart the packet
    /// index under a key that has already sent, which is the one thing RFC
    /// 3711 §9.1 asks never to happen.
    ///
    /// # Errors
    /// [`MediaError::NoDtlsSrtp`] and [`MediaError::UnusableKeying`], for a
    /// fresh crypto line this build cannot open a stream with. Both are
    /// decided before anything is written, so a plan that fails leaves the
    /// session exactly as it was rather than half adopted.
    pub(crate) fn adopt(
        &mut self,
        plan: &MediaPlan,
        candidates: Vec<CodecCandidate>,
        now: Instant,
    ) -> Result<(), MediaError> {
        let (fresh_local, fresh_remote) = Self::rekeyed(&self.plan, plan)?;
        if plan.remote != self.plan.remote {
            self.rtp.relocate(plan.remote);
            // a far end that moved its media address has almost always
            // restarted the stream behind it, and the sequence numbers of the
            // old one say nothing about the new
            self.rtp.resync();
            self.last_inbound = now;
        }
        if let Some(Rekey {
            policy,
            master,
            what,
        }) = fresh_local
        {
            self.rtp.rekey_local(policy, master, what);
        }
        if let Some(Rekey {
            policy,
            master,
            what,
        }) = fresh_remote
        {
            self.rtp.rekey_remote(policy, master, what);
        }
        let was_receiving = self.is_receiving();
        self.plan = plan.clone();
        self.codec_candidates = candidates;
        // a stream that has just been told to stop receiving must not be
        // reported as stalled for having done so
        if !self.is_receiving() {
            self.stalled = false;
        }
        // and the mirror, which is the half that was missing. The watchdog
        // measures from the last packet that arrived, and during a hold none
        // do; a resume that kept the media address — which is nearly every
        // resume, since only the direction attribute moved — left that mark
        // where the hold began. The first timer tick after resuming then read
        // the whole length of the hold as silence and reported a stalled
        // stream, before the far end's first resumed packet could possibly
        // have arrived.
        if !was_receiving && self.is_receiving() {
            self.last_inbound = now;
        }
        Ok(())
    }

    /// Carry this session on under a codec the negotiation has just moved to.
    ///
    /// The alternative is to open a session and drop this one, and that is
    /// what this exists to replace. Dropping it rewound the stream to the
    /// numbers the *call* opened with — RFC 3550 §5.1 has a source that resets
    /// its counters read as a different source, and under SRTP the packet
    /// index is `2^16 · ROC + sequence`, so a rewind under an unchanged master
    /// key hands a second packet a keystream already spent. It also threw away
    /// everything the running session held, none of which has anything to do
    /// with which codec the audio is in.
    ///
    /// Carried, because it belongs to the call and the call has not ended: the
    /// stream itself with both SRTP contexts ([`RtpSession::reformat`] says
    /// what that keeps), the cumulative octet and packet totals, the timeline
    /// the RTCP interval is counted on, the RTCP randomisation, the stall
    /// watchdog, the render delay and the device the application chose at run
    /// time, the events it has not collected yet, the digits this end still
    /// owes, the recording, and the processor it attached.
    ///
    /// Rebuilt, because it is measured in the old codec's units: the coder,
    /// the frame length, the payload buffer, the voice detectors, the comfort
    /// noise, the event receiver, and D5's record of what became of each
    /// candidate.
    ///
    /// # Errors
    /// As [`MediaSession::open`]. Every one of them is ruled out before
    /// anything is written, so a re-negotiation naming a codec this build
    /// cannot open leaves the call running on the one it has.
    pub(crate) fn reformat(
        &mut self,
        plan: &MediaPlan,
        frame_ms: u32,
        config: &MediaConfig,
        candidates: Vec<CodecCandidate>,
        now: Instant,
    ) -> Result<(), MediaError> {
        // open()'s own order, and all of it before the first assignment
        let agreed = Codec::of_plan(plan)?;
        if config.render_delay > MAX_RENDER_DELAY {
            return Err(MediaError::RenderDelayTooLong {
                asked: config.render_delay,
                most: MAX_RENDER_DELAY,
            });
        }
        let coder = Coder::new(agreed, frame_ms)?;
        let (fresh_local, fresh_remote) = Self::rekeyed(&self.plan, plan)?;

        let was_rate = self.sample_rate();
        let was_samples = self.frame_samples();
        let was_clock = self.plan.codec.clock_rate();
        let frame_ticks = agreed.frame_ticks(frame_ms);

        self.rtp.reformat(&StreamFormat {
            payload_type: plan.codec.payload(),
            accepted: accepted(plan),
            clock_rate: plan.codec.clock_rate(),
            remote: plan.remote,
            silence_suppression: config.silence_suppression,
            playout: BufferConfig::new(frame_ticks),
        });
        if let Some(Rekey {
            policy,
            master,
            what,
        }) = fresh_local
        {
            self.rtp.rekey_local(policy, master, what);
        }
        if let Some(Rekey {
            policy,
            master,
            what,
        }) = fresh_remote
        {
            self.rtp.rekey_remote(policy, master, what);
        }

        let rate = agreed.sample_rate();
        let samples = coder.frame_samples();
        let resized = rate != was_rate || samples != was_samples;
        self.retain_recording(resized, was_rate);
        self.retain_processor(resized, rate, samples);
        self.dialling.reformat(was_clock, plan.codec.clock_rate());

        self.coder = coder;
        self.frame_ms = frame_ms;
        self.frame_ticks = frame_ticks;
        self.payload = vec![0; agreed.max_payload(frame_ms)];
        self.activity = Activity::Speech;
        self.inbound_voice = Vad::new(rate);
        self.outbound_voice = Vad::new(rate);
        self.suppressing = config.silence_suppression;
        self.noise = Generator::new();
        self.stall_after = config.stall_after;
        self.heard = plan.dtmf.map(EventReceiver::new);
        self.plan = plan.clone();
        self.codec_candidates = candidates;
        self.last_inbound = now;
        // adopt's guard, for the same reason: a stream told to stop receiving
        // must not be reported as stalled for having done so
        if !self.is_receiving() {
            self.stalled = false;
        }
        Ok(())
    }

    /// Keep the recording running, or close it and say why.
    ///
    /// A recorder is pinned to the rate and the frame length it started at —
    /// `Recorder::start` writes both into the header — so it survives every
    /// codec change that moves neither, which is most of them: the three
    /// eight-kilohertz codecs are interchangeable under one recording.
    fn retain_recording(&mut self, resized: bool, was_rate: u32) {
        if !resized {
            return;
        }
        let Some(recorder) = self.recorder.take() else {
            return;
        };
        let samples = recorder.written();
        // at the rate the audio was taken at, not the one about to replace it
        let written = Duration::from_nanos(
            samples.saturating_mul(1_000_000_000) / u64::from(was_rate.max(1)),
        );
        // the lengths are patched and the file is playable; this is a
        // recording that ended, not one that broke
        let reason = recorder
            .finish()
            .err()
            .map_or(MediaError::CodecChanged, MediaError::from);
        self.events
            .push_back(MediaEvent::RecordingStopped { reason, written });
    }

    /// Keep the application's processor, with rings the new codec's size.
    ///
    /// The object came from the application once and there is no second
    /// chance to ask for it: nothing tells an application that a
    /// re-negotiation is about to happen. Losing it here would leave the rest
    /// of the call with no echo cancellation and no way to notice.
    fn retain_processor(&mut self, resized: bool, rate: u32, samples: usize) {
        let Some(echo) = self.echo.take() else {
            return;
        };
        let mut echo = if resized {
            Echo::new(echo.into_processor(), rate, samples, self.render_delay)
        } else {
            echo
        };
        // `Processor::reset` names a codec change mid-call in as many words:
        // what it has learned describes a signal that no longer exists
        echo.reset();
        self.echo = Some(echo);
    }

    /// What a re-negotiated plan does to each direction, or `None` for a
    /// direction it leaves exactly as it found it.
    ///
    /// The two are told apart by the key material alone, because that is what
    /// the derivation reads. A re-offer is free to keep the same `inline:` and
    /// move only the terms around it — `AES_CM_128_HMAC_SHA1_80` giving way to
    /// `_32` keeps all thirty octets and shortens only the tag — and the
    /// session keys then come out identical. Calling that a new key would hand
    /// a stream that has already sent a packet index starting again at zero,
    /// under a keystream already spent: the reuse RFC 3711 §9.1 exists to
    /// forbid. So the terms follow and the index does not restart.
    ///
    /// A change of shape is neither, and is not decided here. Encryption
    /// turning on or off mid-call, or SDES giving way to DTLS, is not
    /// expressible as a context for a stream that is running; the session
    /// keeps the keys it has, and the engine's `keying_holds` is where a
    /// stream that lost a required policy is refused.
    fn rekeyed(
        was: &MediaPlan,
        plan: &MediaPlan,
    ) -> Result<(Option<Rekey>, Option<Rekey>), MediaError> {
        let (
            Some(Keying::Sdes {
                local: was_local,
                remote: was_remote,
            }),
            Some(Keying::Sdes { local, remote }),
        ) = (&was.keying, &plan.keying)
        else {
            return Ok((None, None));
        };
        Ok((
            Rekey::between(was_local, local)?,
            Rekey::between(was_remote, remote)?,
        ))
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

// -- dialling ----------------------------------------------------------------

impl MediaSession {
    /// Send one key of the keypad to the far end as a named telephone event
    /// (RFC 4733).
    ///
    /// The digit replaces the audio for as long as it lasts — §2.1 has an
    /// event use the audio stream's own sequence numbers and timestamps, so
    /// the two cannot both be on the wire — and it goes out over the frames
    /// that follow rather than all at once. A key pressed while another digit
    /// is still going waits its turn, because somebody typing an extension
    /// presses four keys faster than four digits can be sent and all four have
    /// to arrive.
    ///
    /// This is the form that works. The other one, an INFO carrying the digit
    /// in a body, is signalling rather than media and lives on
    /// [`UserAgent`](crate::UserAgent); it exists for peers that will not take
    /// a digit in the media at all.
    ///
    /// # Errors
    /// [`MediaError::NoDtmf`] when the negotiation settled on no telephone
    /// event payload type, which is the honest answer for a call whose far end
    /// never offered one; [`MediaError::DigitTooShort`] below the length legacy
    /// equipment recognises; and [`MediaError::TooManyDigits`] when the queue
    /// is full.
    pub fn send_dtmf(&mut self, digit: Digit, length: Duration) -> Result<(), MediaError> {
        if self.plan.dtmf.is_none() {
            return Err(MediaError::NoDtmf);
        }
        if length < SHORTEST_DIGIT {
            return Err(MediaError::DigitTooShort {
                asked: length,
                least: SHORTEST_DIGIT,
            });
        }
        if self
            .dialling
            .push(digit, ticks_of(length, self.plan.codec.clock_rate()))
        {
            Ok(())
        } else {
            Err(MediaError::TooManyDigits)
        }
    }

    /// Send a whole dial string, one key at a time.
    ///
    /// Nothing is queued unless every character is a key, so a string with a
    /// typo in it is refused whole rather than half dialled — half of an
    /// extension is worse than none, because it reaches somebody.
    ///
    /// # Errors
    /// [`MediaError::UnknownDigit`] for a character no keypad has, plus
    /// everything [`MediaSession::send_dtmf`] can answer.
    pub fn dial(&mut self, keys: &str, length: Duration) -> Result<usize, MediaError> {
        let digits = keys
            .chars()
            .map(|key| Digit::from_char(key).ok_or(MediaError::UnknownDigit { key }))
            .collect::<Result<Vec<_>, _>>()?;
        if self.plan.dtmf.is_none() {
            return Err(MediaError::NoDtmf);
        }
        if length < SHORTEST_DIGIT {
            return Err(MediaError::DigitTooShort {
                asked: length,
                least: SHORTEST_DIGIT,
            });
        }
        if self.dialling.waiting() + digits.len() > crate::dtmf::WAITING {
            return Err(MediaError::TooManyDigits);
        }
        let ticks = ticks_of(length, self.plan.codec.clock_rate());
        let sent = digits.len();
        for digit in digits {
            if !self.dialling.push(digit, ticks) {
                return Err(MediaError::TooManyDigits);
            }
        }
        Ok(sent)
    }

    /// Whether a digit is going out or waiting to.
    #[must_use]
    pub fn is_dialling(&self) -> bool {
        self.dialling.is_busy()
    }

    /// How many digits have not started yet.
    #[must_use]
    pub fn digits_waiting(&self) -> usize {
        self.dialling.waiting()
    }

    /// Drop everything queued and stop the digit going out.
    ///
    /// What a call being taken away wants: the digit in flight gets no closing
    /// packet, because there is nowhere left to send one.
    pub fn stop_dialling(&mut self) {
        self.dialling.clear();
    }
}

/// One reported event, as the application hears about it.
fn digit_heard(reported: &Reported, rate: u32) -> MediaEvent {
    MediaEvent::DigitReceived {
        digit: reported.digit,
        event: reported.event,
        held: Duration::from_micros(
            u64::from(reported.duration)
                .saturating_mul(1_000_000)
                .checked_div(u64::from(rate).max(1))
                .unwrap_or(0),
        ),
    }
}

/// `span` on a stream whose RTP clock runs at `rate`.
fn ticks_of(span: Duration, rate: u32) -> u32 {
    let micros = u64::try_from(span.as_micros()).unwrap_or(u64::MAX);
    let ticks = u64::from(rate).saturating_mul(micros) / 1_000_000;
    u32::try_from(ticks).unwrap_or(u32::MAX)
}

// -- echo cancellation, gain control, noise suppression ----------------------

impl MediaSession {
    /// Run `processor` over every captured frame, against the far-end audio
    /// this session played [`MediaSession::render_delay`] earlier.
    ///
    /// The three concerns share one attachment point because a real
    /// implementation is usually one component — gain control has to run on
    /// what cancellation left, not on the raw capture — and `sipral-media`'s
    /// [`Processor`] is that point. Nothing in this tree implements one:
    /// on Apple platforms the operating system's own voice-processing unit
    /// does it below the device crate, and elsewhere it is attached from
    /// outside.
    ///
    /// What was attached before is dropped, along with the echo path it had
    /// learned. Attaching mid-call is allowed and costs the first few hundred
    /// milliseconds of a fresh adaptation, which is the same price a call
    /// pays at its start.
    pub fn attach_processor(&mut self, processor: Box<dyn Processor>) {
        self.echo = Some(Echo::new(
            processor,
            self.sample_rate(),
            self.frame_samples(),
            self.render_delay,
        ));
    }

    /// Stop running one, and say whether there was one to stop.
    ///
    /// The frames the application hands over reach the encoder untouched
    /// again from the next one, and the loudspeaker history is released.
    pub fn detach_processor(&mut self) -> bool {
        self.echo.take().is_some()
    }

    /// Whether a processor is attached.
    #[must_use]
    pub const fn has_processor(&self) -> bool {
        self.echo.is_some()
    }

    /// Forget the echo path, the noise floor and the gain this processor has
    /// learned, keeping the processor itself.
    ///
    /// What a device change asks for: the estimate was built for a different
    /// loudspeaker and a different microphone, and carrying it forward makes
    /// the processor fight it for a while instead of adapting cleanly.
    /// Answers whether there was a processor to reset.
    pub fn reset_processor(&mut self) -> bool {
        self.echo.as_mut().map(Echo::reset).is_some()
    }

    /// How long this device takes to get from the loudspeaker to the
    /// microphone.
    #[must_use]
    pub const fn render_delay(&self) -> Duration {
        self.render_delay
    }

    /// Say how long it takes, once the platform has measured it.
    ///
    /// It changes mid-call whenever the device does — a headset connecting
    /// over Bluetooth adds tens of milliseconds to a path that had none — and
    /// a processor already attached picks the new number up on the next
    /// frame, keeping what it has learned.
    ///
    /// # Errors
    /// [`MediaError::RenderDelayTooLong`] above
    /// [`MAX_RENDER_DELAY`](crate::MAX_RENDER_DELAY). Nothing between a
    /// loudspeaker and a microphone in the same room takes half a second, so
    /// such a number is a platform reporting something else and is refused
    /// here rather than believed.
    pub fn set_render_delay(&mut self, delay: Duration) -> Result<(), MediaError> {
        if delay > MAX_RENDER_DELAY {
            return Err(MediaError::RenderDelayTooLong {
                asked: delay,
                most: MAX_RENDER_DELAY,
            });
        }
        self.render_delay = delay;
        let rate = self.sample_rate();
        if let Some(echo) = self.echo.as_mut() {
            echo.set_delay(rate, delay);
        }
        Ok(())
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
