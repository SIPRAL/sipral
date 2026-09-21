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
use sipral_media::g711::Law;
use sipral_media::processor::Processor;
use sipral_media::vad::{self, Vad};
#[cfg(feature = "ice")]
use sipral_nat::ice::{IceEvent, Received as IceReceived};
use sipral_rtp::srtp::{Master, Policy, Rekeyed};
use sipral_rtp::{
    Activity, BufferConfig, BuildError, Discard, Due as RtcpDue, EVENT_LEN, EventReceiver, Outcome,
    PayloadTypes, Pull, Received, Reported, RtcpReceived, RtpSession, StreamConfig, StreamFormat,
    is_rtcp,
};

use crate::clock::WallClock;
use crate::codec::{Codec, CodecCandidate};
use crate::dtmf::{self, DIGIT_GAP, Dialling, Digit, Due, LONGEST_DIGIT, SHORTEST_DIGIT};
use crate::echo::{Echo, MAX_RENDER_DELAY};
use crate::error::MediaError;
use crate::event::MediaEvent;
use crate::keying::{self, Opening};
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
    /// A record of the DTLS-SRTP handshake that keys this call (RFC 5764).
    ///
    /// The handshake has been driven with it, and whatever it owes the far
    /// end in reply is waiting in [`MediaSession::poll_transmit`] — which is
    /// what this arrival is the signal to drain.
    #[cfg(feature = "dtls")]
    Handshake,
    /// ICE traffic, dealt with by the agent: a connectivity check, its
    /// response, a consent request or a keepalive (RFC 8445 §7, RFC 7675).
    ///
    /// Whatever it produced in reply is waiting in
    /// [`MediaSession::poll_transmit`] — which is what this arrival is the
    /// signal to drain, exactly as [`Arrival::Handshake`] is.
    #[cfg(feature = "ice")]
    Check,
    /// Something arrived on a stream that agreed to be secured and has no
    /// keys yet, so there was nothing to verify it with.
    ///
    /// The ordinary way this happens is a peer that starts sending the moment
    /// its own half of the handshake finishes, which is before ours does.
    NotKeyed,
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

/// What the engine brings to opening a session, as against what the
/// negotiation decided.
///
/// Five things a description cannot hold: the numbers this stream starts
/// counting from, the wall clock its reports will carry, the handshake that
/// will key it, the ICE agent that will choose its path, and the instant it
/// is being opened at. Grouped rather than listed because they travel
/// together and always have — every one of them comes from the engine and
/// none of them is a property of the call.
// `Copy` where there is nothing to move: without `dtls` and `ice` the whole
// of it is three numbers and an instant, and clippy is right that passing it
// by value then consumes nothing. With either feature it owns something, and
// the move is the point.
#[cfg_attr(not(any(feature = "dtls", feature = "ice")), derive(Clone, Copy))]
pub(crate) struct Start {
    pub(crate) identity: StreamIdentity,
    pub(crate) clock: WallClock,
    /// The DTLS-SRTP handshake that will key this stream, already started.
    #[cfg(feature = "dtls")]
    pub(crate) handshake: Option<crate::dtls::Handshake>,
    /// The ICE agent that will choose this stream's path, already gathered
    /// and already told what the peer said.
    #[cfg(feature = "ice")]
    pub(crate) ice: Option<crate::ice::Ice>,
    pub(crate) now: Instant,
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
    /// The DTLS-SRTP handshake that will key this stream, while it is still
    /// running. `None` on every other call, and on this one once the keys are
    /// in or the handshake has given up.
    #[cfg(feature = "dtls")]
    dtls: Option<Dtls>,
    /// One handshake record, held rather than allocated, so that
    /// [`MediaSession::poll_transmit`] hands back a borrow like every other
    /// thing this session puts on the wire.
    #[cfg(feature = "dtls")]
    dtls_out: Vec<u8>,

    /// The ICE agent for this call, once the negotiation produced one.
    ///
    /// `None` is every call that is not using ICE, and that is the ordinary
    /// case: the policy is off by default, and a peer that answered without
    /// ICE attributes leaves it `None` too. Nothing on the media path behaves
    /// differently for such a call than it did before this field existed —
    /// which is the whole of the fallback RFC 8445 §2.6 asks for.
    #[cfg(feature = "ice")]
    ice: Option<crate::ice::Ice>,
}

/// Which of this session's own buffers a datagram was built in.
///
/// Every producer here builds into a buffer the session owns and hands back a
/// borrow of it. When ICE picked the path, the bytes are wrapped for that
/// path first and the borrow is of the wrapping instead — so what goes out
/// has to be named rather than passed, or the borrow of one field would have
/// to outlive the mutable borrow of the other.
#[cfg(feature = "ice")]
#[derive(Clone, Copy)]
enum Built {
    /// `rtp_out`: audio, or a named event.
    Rtp,
    /// `rtcp_out`: a report, or the BYE.
    Rtcp,
    /// `dtls_out`: a record of the handshake that keys the call.
    #[cfg(feature = "dtls")]
    Handshake,
}

/// The content type of a DTLS handshake record (RFC 6347 §4.1), which is the
/// one kind this session will take from an address it has not heard from
/// before. Everything else on that connection — the alerts above all — is
/// believed only from the address a handshake record came from first.
#[cfg(feature = "dtls")]
const HANDSHAKE_RECORD: u8 = 22;

/// A running handshake and the address its records are believed from.
#[cfg(feature = "dtls")]
#[derive(Debug)]
struct Dtls {
    handshake: crate::dtls::Handshake,
    /// Where the far end's records come from, once one has arrived.
    ///
    /// The same latch RTP keeps, kept separately because no RTP arrives while
    /// the handshake runs, so the stream's own latch has not closed yet.
    ///
    /// It matters more here than it does there. A DTLS connection ends on any
    /// fatal alert, and an alert arriving before the keys exist cannot be
    /// authenticated — there is nothing to authenticate it with — so without
    /// a latch one forged datagram from anywhere on the path would end any
    /// call on this stack that had agreed to be encrypted. The latch closes
    /// on the first *handshake* record to arrive, never on an alert, which
    /// narrows that to the same race the RTP latch already has: an attacker
    /// must beat the far end's first flight rather than pick its moment.
    ///
    /// Narrows, and does not close. Closing it needs the candidate exchange
    /// of ICE, which this stack negotiates and does not assume; see
    /// `docs/06-nat.md`.
    peer: Option<SocketAddr>,
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
        candidates: Vec<CodecCandidate>,
        start: Start,
    ) -> Result<Self, MediaError> {
        let Start {
            identity,
            clock,
            #[cfg(feature = "dtls")]
            handshake,
            #[cfg(feature = "ice")]
            ice,
            now,
        } = start;
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
        let rtp = match keying::opening(plan)? {
            Opening::Keyed(security) => RtpSession::protected(&stream, draws.unit(), security),
            // the keys are a handshake away and nothing may go out or be
            // believed until they land: see `RtpSession::awaiting`
            #[cfg(feature = "dtls")]
            Opening::Awaiting(most) => RtpSession::awaiting(&stream, draws.unit(), most),
            Opening::Clear => RtpSession::new(&stream, draws.unit()),
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
            #[cfg(feature = "dtls")]
            dtls: handshake.map(|handshake| Dtls {
                handshake,
                peer: None,
            }),
            #[cfg(feature = "dtls")]
            dtls_out: Vec::new(),
            #[cfg(feature = "ice")]
            ice,
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
    /// True only for a stream whose keys are actually in use, which is what a
    /// padlock on a screen has to mean. A call that asked for SDES and got a
    /// plain answer never reaches here — the stream is refused or the session
    /// is not opened — so there is no state in which this says yes and the
    /// packets say otherwise.
    ///
    /// Read off the stream rather than off the plan, and that is the whole of
    /// the difference DTLS-SRTP makes to it: a plan can say a call is keyed
    /// by a handshake from the moment the answer is parsed, and the handshake
    /// finishes a round trip later. For that round trip this says no, because
    /// for that round trip nothing has been encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.rtp.is_protected()
    }

    /// Whether this call agreed to be encrypted and is still waiting for the
    /// handshake that keys it.
    ///
    /// Neither [`MediaSession::is_encrypted`] nor a plain call: no audio
    /// moves in either direction while this is true, and it becomes false
    /// either because [`MediaEvent::Secured`] was emitted or because
    /// [`MediaEvent::Failed`] was.
    #[must_use]
    pub const fn is_awaiting_keys(&self) -> bool {
        self.rtp.awaiting_keys()
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
        // ICE first, and before the classification below, because a
        // connectivity check is not RTP, is not RTCP and is not a handshake
        // record: it is the agent's own traffic, and until this line existed
        // it reached `rtp.receive` and was thrown away as a broken packet.
        // A relayed datagram also has the relay's wrapping taken off here, so
        // everything below reads the bytes the peer actually sent.
        #[cfg(feature = "ice")]
        let datagram = match self.receive_check(datagram, from, now) {
            Ok(payload) => payload,
            Err(arrival) => return arrival,
        };
        #[cfg(feature = "dtls")]
        if sipral_nat::classify(datagram) == sipral_nat::Demux::Dtls {
            return self.receive_handshake(datagram, from, now);
        }
        if is_rtcp(datagram) {
            return self.receive_control(datagram, from, now);
        }
        let elapsed = self.elapsed(now);
        match self.rtp.receive(datagram, from, elapsed) {
            Received::Queued => {
                self.note_arrival(now);
                Arrival::Queued
            }
            Received::Dropped(Discard::NotKeyed) => Arrival::NotKeyed,
            Received::Dropped(why) => Arrival::Dropped(why),
        }
    }

    /// Let the agent have the datagram first, and give back what is left for
    /// the rest of the path to read.
    ///
    /// `Err` is a datagram this session is done with: the agent consumed it,
    /// or it came from somewhere the agent does not know. `Ok` is application
    /// data, at the position the agent put it — which for a relayed pair is
    /// past the channel header and for every other one is the whole datagram.
    ///
    /// A call not using ICE takes the datagram back unchanged, which is what
    /// makes this line free for the calls that are the overwhelming majority.
    #[cfg(feature = "ice")]
    fn receive_check<'a>(
        &mut self,
        datagram: &'a mut [u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<&'a mut [u8], Arrival> {
        let Some(ice) = self.ice.as_mut() else {
            return Ok(datagram);
        };
        // N9: the pool is filled immediately before the agent is moved, not
        // on a schedule of its own. An agent with no id cannot answer a check
        // and puts its own deadline in the past, which spins the caller's loop
        // while consent runs out on a call that was working
        ice.top_up();
        let taken = ice.handle_datagram(from, datagram, now);
        self.drain_ice(now);
        match taken {
            IceReceived::Consumed => Err(Arrival::Check),
            IceReceived::Foreign => Err(Arrival::Dropped(Discard::ForeignAddress)),
            // `range` indexes the datagram that was handed in, so the `None`
            // arm is unreachable: it would be `sipral-nat` reporting a
            // position in a buffer it was not given. It is written rather
            // than unwrapped because a panic on the media path is worse than
            // a dropped packet, and the fuzz target `ice` asserts the range
            // indexes the datagram precisely so this stays unreachable.
            IceReceived::Data { range, .. } => datagram.get_mut(range).ok_or(Arrival::Check),
        }
    }

    /// Turn what the agent has to say into this session's own events.
    ///
    /// Called after everything that can move the agent, in the one place, so
    /// that "a lost path is reported exactly once" is a property of the
    /// session rather than of every caller.
    #[cfg(feature = "ice")]
    fn drain_ice(&mut self, now: Instant) {
        let Some(ice) = self.ice.as_mut() else {
            return;
        };
        let mut lost = false;
        let mut selected = None;
        while let Some(event) = ice.poll_event() {
            match event {
                IceEvent::Selected { pair, .. } => selected = Some(pair),
                // RFC 7675 §5: nothing more may be sent on that pair, and the
                // same credentials may not be used on it again. This stack
                // has no re-offer of its own yet, so the only remedy an
                // application has is to end the call — which is what the
                // event's own documentation says, rather than leaving it to
                // be worked out from the silence
                IceEvent::ConsentLost { .. } | IceEvent::Failed | IceEvent::StreamFailed { .. } => {
                    lost = true;
                }
                IceEvent::GatheringComplete | IceEvent::Completed | IceEvent::RoleChanged(_) => {}
            }
        }
        if let Some(pair) = selected {
            // symmetric RTP's latch is the poor version of the check the
            // agent has already run, and leaving it armed would cut the audio
            // for good the first time a mid-call re-selection moved the pair
            self.rtp.relocate(pair.remote);
            self.events.push_back(MediaEvent::PathChosen {
                local: pair.local,
                remote: pair.remote,
            });
        }
        if lost {
            self.ice = None;
            self.events
                .push_back(MediaEvent::Failed(MediaError::IcePathLost));
        }
        let _ = now;
    }

    /// Put a datagram this session built on the path ICE chose, or on the
    /// signalled one when this call is not using ICE.
    ///
    /// N5's precondition, in the one place all four producers reach it: a
    /// producer asks for the route *before* it hands anything over, because
    /// by the time it has built a frame or taken a handshake record out of a
    /// flight it is too late to be told there is nowhere to send.
    #[cfg(feature = "ice")]
    fn on_path(
        &mut self,
        built: Built,
        length: usize,
        signalled: SocketAddr,
        now: Instant,
    ) -> Option<Datagram<'_>> {
        let data: &[u8] = match built {
            Built::Rtp => self.rtp_out.get(..length).unwrap_or_default(),
            Built::Rtcp => self.rtcp_out.get(..length).unwrap_or_default(),
            #[cfg(feature = "dtls")]
            Built::Handshake => self.dtls_out.get(..length).unwrap_or_default(),
        };
        let Some(ice) = self.ice.as_mut() else {
            return Some(Datagram {
                destination: signalled,
                payload: data,
            });
        };
        let (destination, payload) = ice.send(data, now).ok()?;
        Some(Datagram {
            destination,
            payload,
        })
    }

    /// Whether there is anywhere to send, asked without sending.
    ///
    /// `true` for a call not using ICE, which has had somewhere to send since
    /// the description named it.
    #[cfg(feature = "ice")]
    fn has_path(&self) -> bool {
        self.ice.as_ref().is_none_or(|ice| ice.route().is_some())
    }

    /// Take a record of the handshake that keys this call.
    ///
    /// `last_inbound` is deliberately not touched. The watchdog behind
    /// [`MediaEvent::Stalled`] measures audio, and a peer retransmitting its
    /// flights into a call that will never key is exactly the case it must
    /// not be talked out of reporting. What reports a handshake that does not
    /// finish is the handshake's own budget.
    #[cfg(feature = "dtls")]
    fn receive_handshake(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) -> Arrival {
        let Some(dtls) = self.dtls.as_mut() else {
            // the keys are in, or the handshake gave up: a record arriving
            // now is a retransmission the far end has not stopped sending, or
            // it is nobody's
            return Arrival::Dropped(Discard::ForeignAddress);
        };
        match dtls.peer {
            Some(latched) if latched != from => {
                return Arrival::Dropped(Discard::ForeignAddress);
            }
            Some(_) => {}
            // RFC 6347 §4.1: a record's first octet is its content type, and
            // 22 is a handshake. Latching on one of those and not on an alert
            // is what keeps an unauthenticated alert — the one thing a peer
            // can send before there are keys that ends the connection — from
            // arriving from anywhere at all
            None if datagram.first() == Some(&HANDSHAKE_RECORD) => dtls.peer = Some(from),
            None => return Arrival::Dropped(Discard::ForeignAddress),
        }
        dtls.handshake.on_datagram(datagram, now);
        self.settle_handshake();
        Arrival::Handshake
    }

    /// Install what the handshake produced, or report why there will be none.
    ///
    /// Called after anything that could have moved it. Doing it in one place
    /// is what makes "the keys are installed exactly once" a property of the
    /// session rather than of every caller.
    #[cfg(feature = "dtls")]
    fn settle_handshake(&mut self) {
        let Some(dtls) = self.dtls.as_mut() else {
            return;
        };
        let peer = dtls.peer;
        match dtls.handshake.take_outcome() {
            Some(Ok((suite, security))) => {
                // `keyed` is false for a stream that was not waiting, which
                // is a session that has already been keyed once: the event
                // goes out with the keys or not at all
                let installed = self.rtp.keyed(security);
                if installed {
                    self.events.push_back(MediaEvent::Secured { suite, peer });
                }
            }
            Some(Err(error)) => self.events.push_back(MediaEvent::Failed(error)),
            None => {}
        }
        // the handshake is kept either way rather than dropped. A far end
        // that lost our last flight retransmits its own, and a connection
        // that is still here answers it; one that had been thrown away would
        // leave the peer retransmitting into a call that is already carrying
        // audio.
    }

    /// A datagram this session owes the far end that is neither audio nor a
    /// report: today, a record of the DTLS-SRTP handshake.
    ///
    /// Drain it to empty after every [`MediaSession::receive`] and at every
    /// deadline [`MediaSession::poll_timeout`] named. A handshake that is not
    /// drained is a handshake whose ClientHello never leaves, and a call that
    /// is up with no audio and no error.
    ///
    /// `now` is read and moves nothing, as everywhere else here. It is what
    /// tells the agent that traffic went out on the pair it chose, which is
    /// what RFC 8445 §11 lets it stop sending keepalives for.
    #[cfg(any(feature = "dtls", feature = "ice"))]
    #[must_use]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Datagram<'_>> {
        // the agent's own traffic first, and ungated: a check is how a route
        // comes to exist, so gating it on there being one would be a session
        // that never starts
        #[cfg(feature = "ice")]
        {
            let ready = match self.ice.as_mut() {
                Some(ice) => {
                    ice.top_up();
                    ice.take_probe()
                }
                None => None,
            };
            // the address comes back by value and the bytes are read in a
            // second borrow: a borrow of the bytes taken here would be held
            // open by the datagram this returns, and the handshake below
            // needs `self` mutably
            if let Some(destination) = ready {
                return Some(Datagram {
                    destination,
                    payload: self.ice.as_ref().map_or(&[][..], crate::ice::Ice::probe),
                });
            }
        }
        #[cfg(feature = "dtls")]
        {
            // N5: asked before `take_outbound`, never after. Taking the
            // record first and dropping it for want of a route destroys a
            // flight the handshake will not rebuild, and the call then fails
            // for a reason nothing on the path can explain
            #[cfg(feature = "ice")]
            if !self.has_path() {
                return None;
            }
            let record = self.dtls.as_mut()?.handshake.take_outbound()?;
            self.dtls_out = record;
            // the stream's own address, which is the signalled one until a
            // packet has been seen from somewhere else and the latched one
            // afterwards: a handshake follows symmetric RTP and follows a
            // re-negotiation that moved the stream, with no second copy of
            // the answer to keep in step
            let signalled = self.rtp.destination();
            #[cfg(feature = "ice")]
            {
                let length = self.dtls_out.len();
                self.on_path(Built::Handshake, length, signalled, now)
            }
            #[cfg(not(feature = "ice"))]
            {
                let _ = now;
                Some(Datagram {
                    destination: signalled,
                    payload: &self.dtls_out,
                })
            }
        }
        #[cfg(not(feature = "dtls"))]
        {
            let _ = now;
            None
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
            RtcpReceived::NotKeyed => Arrival::NotKeyed,
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
        // a peer that answered with one G.711 law and sends the other: real
        // equipment does this, and `accepted` (below) already lets the
        // datagram through rather than refusing it as an unnegotiated type.
        // What is left is to decode it with the law it actually names instead
        // of the one the coder was built for — the two share a frame shape
        // (RFC 3551 table 4), so nothing about `room`'s size has to change.
        // Unless this call's own negotiation put its named events on that
        // number: what arrives there is then a key, not audio, and the arm
        // for named events below is the one that has to see it.
        let dtmf = self.plan.dtmf;
        let foreign_law = sibling_law(coder.codec()).filter(|&(sibling, _)| dtmf != Some(sibling));
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
            Pull::Packet(frame)
                if foreign_law.is_some_and(|(sibling, _)| sibling == frame.payload_type) =>
            {
                let (_, law) = foreign_law.unwrap_or((0, Law::Mu));
                let written = law.decode_into(frame.payload, room);
                if let Some(rest) = room.get_mut(written..) {
                    rest.fill(0);
                }
                Playback::Packet
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
    pub fn capture(
        &mut self,
        samples: &[i16],
        now: Instant,
    ) -> Result<Option<Datagram<'_>>, MediaError> {
        // N5: the route is asked for before the frame is built, not after.
        // Encoding a frame and then throwing it away because there is nowhere
        // to send it costs the encoder's state as well as the work — Opus
        // carries one frame's history into the next — and the RTP timestamp
        // would have moved for a packet that never existed
        #[cfg(feature = "ice")]
        if !self.has_path() {
            return Ok(None);
        }
        // the processor is lifted out for the length of the frame so that the
        // audio it produces can be borrowed from it while the rest of the
        // session is still being written to
        let mut echo = self.echo.take();
        let sent = self.encode_frame(samples, echo.as_mut());
        self.echo = echo;
        let Some(length) = sent? else {
            return Ok(None);
        };
        let signalled = self.rtp.destination();
        #[cfg(feature = "ice")]
        {
            Ok(self.on_path(Built::Rtp, length, signalled, now))
        }
        #[cfg(not(feature = "ice"))]
        {
            let _ = now;
            Ok(Some(Datagram {
                destination: signalled,
                payload: self.rtp_out.get(..length).unwrap_or_default(),
            }))
        }
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
        let length = match self.rtp.send(payload, self.frame_ticks, &mut self.rtp_out) {
            Ok(length) => length,
            // a stream that agreed to be secured and is still waiting for its
            // keys drops the frame rather than queueing it. A frame held for
            // the length of a handshake is a frame that arrives too late to
            // play, and the clock has moved on by then anyway (§5.1)
            Err(BuildError::NotKeyed) => return Ok(None),
            Err(_) => {
                return Err(MediaError::PacketTooLong {
                    need: written,
                    got: self.rtp_out.len(),
                });
            }
        };
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
        let length = match self
            .rtp
            .send_event(outgoing, payload_type, &mut self.rtp_out)
        {
            Ok(length) => length,
            // as on the audio path, and with one more consequence: the digit
            // this packet belonged to is abandoned rather than half sent.
            // RFC 4733 §2.5.1.4 builds a digit out of a run of updates, and a
            // run with a hole in it is a digit the far end reads as two
            Err(BuildError::NotKeyed) => {
                self.dialling.clear();
                return Ok(None);
            }
            Err(_) => {
                return Err(MediaError::PacketTooLong {
                    need: EVENT_LEN,
                    got: self.rtp_out.len(),
                });
            }
        };
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
        // refused before the schedule is asked, not after. `rtcp_due` both
        // answers and reconsiders, and a report that was scheduled and then
        // refused by the protection step would leave the deadline where it
        // was — so every later poll would see it passed, and a caller driven
        // by `poll_timeout` would spin for the whole handshake
        if self.rtp.awaiting_keys() {
            return None;
        }
        // and for the same reason one line up: `rtcp_due` reconsiders the
        // schedule as it answers, so a report refused after asking would
        // leave the deadline in the past and spin a caller driven by it
        #[cfg(feature = "ice")]
        if !self.has_path() {
            return None;
        }
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
        #[cfg(feature = "ice")]
        {
            self.on_path(Built::Rtcp, length, destination, now)
        }
        #[cfg(not(feature = "ice"))]
        Some(Datagram {
            destination,
            payload: self.rtcp_out.get(..length).unwrap_or_default(),
        })
    }

    /// Say goodbye to the far end's DTLS stack, before the socket closes.
    ///
    /// RFC 6347 §4.2.8's `close_notify`. A peer that gets one stops
    /// retransmitting its flights into a call that has already hung up, which
    /// on a handshake that never finished is the difference between ending
    /// and trailing off for two minutes — the same difference the RTCP BYE
    /// makes to the media, and the reason both are sent here.
    ///
    /// The records it produces come out of [`MediaSession::poll_transmit`]
    /// like any others. Nothing waits for an answer; there will not be one.
    #[cfg(feature = "dtls")]
    pub fn close_handshake(&mut self) {
        if let Some(dtls) = self.dtls.as_mut() {
            dtls.handshake.close();
        }
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
        #[cfg(feature = "ice")]
        {
            self.on_path(Built::Rtcp, length, destination, now)
        }
        #[cfg(not(feature = "ice"))]
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
            .filter(|_| !self.rtp.awaiting_keys())
            .map(|_| self.origin + self.rtp.next_rtcp_deadline());
        let stall = self
            .stall_after
            .filter(|_| self.is_receiving() && !self.stalled)
            .map(|after| self.last_inbound + after);
        #[cfg(feature = "dtls")]
        let handshake = self
            .dtls
            .as_ref()
            .and_then(|dtls| dtls.handshake.poll_timeout());
        #[cfg(not(feature = "dtls"))]
        let handshake = None;
        #[cfg(feature = "ice")]
        let ice = self.ice.as_ref().and_then(crate::ice::Ice::deadline);
        #[cfg(not(feature = "ice"))]
        let ice = None;
        [rtcp, stall, handshake, ice].into_iter().flatten().min()
    }

    /// Time has passed. The only thing this decides is whether the stream has
    /// stopped; a report that is due is taken with
    /// [`MediaSession::poll_rtcp`], because it needs somewhere to be written.
    pub fn handle_timeout(&mut self, now: Instant) {
        // first and unconditionally. Everything below this line is the stall
        // watchdog, which an application is free to turn off and which a
        // `sendonly` call does not run at all — and a handshake driven only
        // when the watchdog happens to be armed is a handshake that never
        // retransmits and never gives up
        #[cfg(feature = "dtls")]
        if let Some(dtls) = self.dtls.as_mut() {
            dtls.handshake.on_timeout(now);
            self.settle_handshake();
        }
        // and the agent, for the same reason: checks, consent and keepalives
        // are all on its own clock, and an agent driven only when the
        // watchdog happens to be armed is an agent that never checks anything
        #[cfg(feature = "ice")]
        if let Some(ice) = self.ice.as_mut() {
            ice.top_up();
            ice.handle_timeout(now);
            self.drain_ice(now);
        }
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

    /// The path ICE chose for this call: the local socket and the peer, once
    /// there is a selected pair (RFC 8445 §12.1).
    ///
    /// `None` until the checks settle, and `None` for ever on a call that is
    /// not using ICE — which is most calls, and which
    /// [`MediaSession::destination`] answers for instead. What
    /// [`MediaEvent::PathChosen`] reports at the moment it changes, for an
    /// application that would rather ask than keep the event.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn ice_path(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.ice
            .as_ref()?
            .selected_pair()
            .map(|pair| (pair.local, pair.remote))
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
        !self.rtp.awaiting_keys()
            && self.control_destination().is_some()
            && self.elapsed(now) >= self.rtp.next_rtcp_deadline()
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
    ///
    /// # Errors
    /// [`MediaError::DtlsFingerprintChanged`] for a re-negotiation that names
    /// a different certificate. RFC 5763 §6.6 asks for a **new** DTLS
    /// association there, which this does not start; what it does instead is
    /// refuse the plan by name, so the session keeps running on keys both
    /// ends still agree on and the application is told. Carrying on silently
    /// would be worse than either: the far end would have moved to a
    /// certificate this end never checked, and the media would keep flowing
    /// as though it had.
    fn rekeyed(
        was: &MediaPlan,
        plan: &MediaPlan,
    ) -> Result<(Option<Rekey>, Option<Rekey>), MediaError> {
        #[cfg(feature = "dtls")]
        if let (
            Some(Keying::Dtls {
                fingerprints: had, ..
            }),
            Some(Keying::Dtls {
                fingerprints: now, ..
            }),
        ) = (&was.keying, &plan.keying)
            && had != now
        {
            return Err(MediaError::DtlsFingerprintChanged);
        }
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
    /// equipment recognises; [`MediaError::DigitTooLong`] above the longest
    /// any form of DTMF sends; and [`MediaError::TooManyDigits`] when the
    /// queue is full.
    pub fn send_dtmf(&mut self, digit: Digit, length: Duration) -> Result<(), MediaError> {
        if self.plan.dtmf.is_none() {
            return Err(MediaError::NoDtmf);
        }
        digit_length(length)?;
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
        digit_length(length)?;
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

/// Whether a digit this long is one any form of DTMF sends.
///
/// Read through `sipral_ua::dtmf::duration_ms`, the one bound INFO sending is
/// held to as well, so that RFC 4733 refuses exactly the lengths it does
/// (8.3.11); a length received by INFO shares only the ceiling, because it
/// reports a tone the peer already held (8.3.11-bis). A zero `Duration` is a
/// length here and too
/// short, where zero milliseconds there asks for the default, so it is read
/// as the shortest length that is not zero.
fn digit_length(length: Duration) -> Result<(), MediaError> {
    let millis = u32::try_from(length.as_millis()).unwrap_or(u32::MAX).max(1);
    match sipral_ua::dtmf::duration_ms(millis) {
        Ok(_) => Ok(()),
        Err(sipral_ua::DtmfError::ToneTooShort(_)) => Err(MediaError::DigitTooShort {
            asked: length,
            least: SHORTEST_DIGIT,
        }),
        // the only other refusal a length can get; a digit is not read here
        Err(_) => Err(MediaError::DigitTooLong {
            asked: length,
            most: LONGEST_DIGIT,
        }),
    }
}

/// One reported event, as the application hears about it.
fn digit_heard(reported: &Reported, rate: u32) -> MediaEvent {
    MediaEvent::DigitReceived {
        digit: reported.digit,
        event: reported.event,
        held: Some(Duration::from_micros(
            u64::from(reported.duration)
                .saturating_mul(1_000_000)
                .checked_div(u64::from(rate).max(1))
                .unwrap_or(0),
        )),
        source: crate::event::DigitSource::Rtp,
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
/// events if any were, comfort noise, and — for G.711 — the sibling law.
///
/// The last of those is not a courtesy. A peer that answers with one
/// companding law and sends the other is a real thing this stack has met, and
/// refusing the datagram at the RTP layer would show up as silence rather
/// than as the fault it is; [`fill`](MediaSession::fill) decodes it with the
/// law it actually names, which the two share a frame shape for (RFC 3551
/// table 4).
fn accepted(plan: &MediaPlan) -> PayloadTypes {
    let mut types = PayloadTypes::none()
        .with(plan.codec.payload())
        .with(COMFORT_NOISE);
    if let Ok(codec) = Codec::of_plan(plan)
        && let Some((sibling, _)) = sibling_law(codec)
    {
        types = types.with(sibling);
    }
    match plan.dtmf {
        Some(payload) => types.with(payload),
        None => types,
    }
}

/// The other G.711 law's static payload type and the law itself, for a codec
/// that has one. `None` for G.722 and Opus, whose frame shape a G.711 payload
/// does not fit.
const fn sibling_law(codec: Codec) -> Option<(u8, Law)> {
    match codec {
        Codec::Pcmu => Some((Law::A.payload_type(), Law::A)),
        Codec::Pcma => Some((Law::Mu.payload_type(), Law::Mu)),
        Codec::G722 => None,
        #[cfg(feature = "opus")]
        Codec::Opus => None,
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
