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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "ice")]
use crate::ice::{PathNews, Taken};
use sipral_core::sdp::{CryptoPolicy, Direction, Keying, MediaPlan, RtcpPlan};
use sipral_media::comfort_noise::{ComfortNoise, Generator, PAYLOAD_TYPE as COMFORT_NOISE};
use sipral_media::g711::Law;
use sipral_media::processor::Processor;
use sipral_media::vad::{self, Vad};
use sipral_rtp::srtp::{Master, Policy, Rekeyed, Suite};
use sipral_rtp::{
    Activity, BufferConfig, BuildError, Discard, Due as RtcpDue, EVENT_LEN, EventReceiver, Outcome,
    PayloadTypes, Pull, Received, Reported, RtcpReceived, RtpSession, StreamConfig, StreamFormat,
    UNAVAILABLE, VoipMetricsBlock, is_rtcp,
};
use sipral_ua::{QualityReportMetrics, RemoteQualityMetrics};

use crate::capabilities::SrtpKeying;
use crate::clock::WallClock;
use crate::codec::{Codec, CodecCandidate};
use crate::dtmf::{self, DIGIT_GAP, Dialling, Digit, Due, LONGEST_DIGIT, SHORTEST_DIGIT};
use crate::echo::{Echo, MAX_RENDER_DELAY};
use crate::error::MediaError;
use crate::event::MediaEvent;
use crate::inband::{ConsentTone, DtmfDetection, ProgressDetection, Signals};
use crate::keying::{self, Opening, Shape};
use crate::pipeline::{Coder, Decoded};
use crate::record::{Recorder, RecordingOptions, RecordingSink};
use crate::share::{Outbox, Ready};
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
    /// How it leaves. [`TurnTransport::Udp`](crate::TurnTransport::Udp) is
    /// a datagram from the media socket, which is everything unless the call
    /// was given a relay over TCP or TLS ([`crate::Relays::over`]): then
    /// what goes through the relay is bytes to write, as they are and in
    /// order, on the media socket's connection to the TURN server, which is
    /// `destination`.
    #[cfg(feature = "ice")]
    pub transport: crate::TurnTransport,
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
    /// audio, or from a G.729 payload that held nothing but an Annex B SID
    /// frame.
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
    /// How long inbound audio may stop before [`MediaEvent::Stalled`] — or,
    /// in a G.729 pause the far end announced (Annex B), how long its RTCP
    /// reports may stop as well. `None` switches the watchdog off.
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
    /// When to listen for keypad digits in the far end's audio, as well as
    /// in its RFC 4733 events. [`DtmfDetection::Auto`] unless told
    /// otherwise: on exactly the calls that negotiated no telephone event.
    pub dtmf_detection: DtmfDetection,
    /// Listen for call-progress tones on early media and decide who
    /// answered. `None`, the default: it is for calls this end places to
    /// reach a person, and costs a detector on every frame until it has
    /// decided.
    pub progress: Option<ProgressDetection>,
    /// Beep while the call is being recorded. `None`, the default: whether
    /// the parties have to be told is a matter of where they are, and the
    /// application's to decide.
    pub consent_tone: Option<ConsentTone>,
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
            dtmf_detection: DtmfDetection::Auto,
            progress: None,
            consent_tone: None,
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
    /// Whether both descriptions allowed G.729's Annex B, so that the
    /// encoder sends SID frames and nothing in the pauses. Meaningless for
    /// any other codec.
    pub(crate) annex_b: bool,
    pub(crate) now: Instant,
}

/// How one stream of a call is protected: one entry of
/// [`MediaSession::encryption`], the encryption report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamEncryption {
    /// What the stream carries, as its `m=` line names it: `audio`.
    pub media: &'static str,
    /// Whether what it sends is encrypted and what it takes is
    /// authenticated, now. False for a stream still waiting for the
    /// handshake that keys it.
    pub encrypted: bool,
    /// How its keys were exchanged: in the SDP (RFC 4568) or by a DTLS
    /// handshake on the media path (RFC 5764). `None` for a stream that was
    /// never meant to be encrypted.
    pub key_exchange: Option<SrtpKeying>,
    /// The transform it runs, once it runs one.
    pub suite: Option<Suite>,
    /// Whether the key exchange authenticated the far end: true for a
    /// DTLS-SRTP stream once its handshake finished, since the far end's
    /// certificate had to match the fingerprint its signalling carried
    /// (RFC 8122 §5.1). An SDES key is exactly as authentic as the
    /// signalling transport that carried it, which this layer cannot see,
    /// so it is false for one.
    pub authenticated: bool,
    /// Whether it agreed to be encrypted and is still waiting for its keys.
    pub awaiting_keys: bool,
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
    /// When the far end's last control report was believed: what says it is
    /// still there while it sends no audio on purpose, in a pause it
    /// announced (G.729's Annex B).
    last_control: Instant,
    stall_after: Option<Duration>,
    stalled: bool,
    /// What the far end's last decoded frame was, which is what the buffer is
    /// allowed to move its delay on.
    activity: Activity,
    inbound_voice: Vad,
    outbound_voice: Vad,
    /// Whether the configuration asked for silence suppression, and whether
    /// this end's own detector does it — which it does not when G.729's
    /// Annex B is doing it instead.
    silence_suppression: bool,
    suppressing: bool,
    noise: Generator,
    recorder: Option<Recorder>,
    /// Digits, tones and the consent beep carried in the audio itself.
    signals: Signals,
    /// A captured frame as it goes out when a digit or a beep has been
    /// written into it, held rather than allocated.
    shaped: Vec<i16>,
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
    events: Outbox,
    /// D5: what became of every codec this call's catalogue could have used.
    codec_candidates: Vec<CodecCandidate>,
    /// The transform the last DTLS-SRTP handshake on this stream agreed,
    /// once one has: the signalling does not say (RFC 5764 §4.1.2), so the
    /// encryption report reads it here. An SDES stream's is in its plan.
    handshake_suite: Option<Suite>,
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
    /// The last whole message the relay's connection to its TURN server
    /// carried, held here so that one read does not allocate for every
    /// frame in it ([`MediaSession::receive_stream`]).
    #[cfg(feature = "ice")]
    stream_in: Vec<u8>,
    /// The call's real-time text stream (RFC 4103), when both descriptions
    /// agreed one: see [`crate::text`].
    text: Option<crate::text::TextStream>,
    /// One text datagram, held rather than allocated, for the borrow
    /// [`MediaSession::poll_text`] hands back.
    text_out: Vec<u8>,
    /// What this call's audio is copied to, while a recording server is
    /// recording it: see [`crate::siprec`].
    tap: Option<crate::siprec::Tap>,
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
    /// A new association the far end has begun on this call while the one
    /// above keys it (RFC 6347 §4.2.8), until it either produces keys — and
    /// replaces it — or gives up and is dropped, with the call still on the
    /// keys it had. See [`crate::dtls::Handshake::renewal`].
    next: Option<crate::dtls::Handshake>,
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
    /// on the first *handshake* record to arrive, never on an alert, and —
    /// without ICE — only on one from the host the signalling named
    /// ([`MediaSession::handshake_source_possible`]): an attacker must send
    /// from the far end's own address, and beat its first flight, rather
    /// than pick a moment from anywhere.
    ///
    /// Narrows, and does not close. Closing it needs the candidate exchange
    /// of ICE, which this stack negotiates and does not assume; see
    /// `docs/06-nat.md`. With ICE the pair the agent selects moves it, and a
    /// re-negotiation that moves the far end's media address opens it again
    /// for the first record from the new one.
    ///
    /// This end's own flights go here while RTP has no latch, which it has
    /// none of until there are keys: see [`MediaSession::poll_transmit`].
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
            annex_b,
            now,
        } = start;
        let agreed = Codec::of_plan(plan)?;
        if config.render_delay > MAX_RENDER_DELAY {
            return Err(MediaError::RenderDelayTooLong {
                asked: config.render_delay,
                most: MAX_RENDER_DELAY,
            });
        }
        let mut coder = Coder::new(agreed, frame_ms)?;
        coder.set_annex_b(annex_b);
        let discontinuous = coder.annex_b();
        let frame_ticks = agreed.frame_ticks(frame_ms);
        let stream = stream_config(plan, config, &identity, discontinuous, frame_ticks);
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
            last_control: now,
            stall_after: config.stall_after,
            stalled: false,
            activity: Activity::Speech,
            inbound_voice: Vad::new(agreed.sample_rate()),
            outbound_voice: Vad::new(agreed.sample_rate()),
            // Annex B has its own detector, and suppressing frames before it
            // hears them would leave it deciding on half a conversation
            silence_suppression: config.silence_suppression,
            suppressing: config.silence_suppression && !discontinuous,
            noise: Generator::new(),
            recorder: None,
            signals: Signals::new(
                agreed.sample_rate(),
                plan.dtmf.is_some(),
                config.dtmf_detection,
                config.progress,
                config.consent_tone,
            ),
            shaped: Vec::new(),
            echo: None,
            render_delay: config.render_delay,
            dialling: Dialling::new(ticks_of(DIGIT_GAP, plan.codec.clock_rate())),
            heard: plan.dtmf_in.map(EventReceiver::new),
            events: Outbox::default(),
            codec_candidates: candidates,
            handshake_suite: None,
            device: config.device.clone(),
            #[cfg(feature = "dtls")]
            dtls: handshake.map(|handshake| Dtls {
                handshake,
                peer: None,
                next: None,
            }),
            #[cfg(feature = "dtls")]
            dtls_out: Vec::new(),
            #[cfg(feature = "ice")]
            ice,
            #[cfg(feature = "ice")]
            stream_in: Vec::new(),
            text: None,
            text_out: Vec::new(),
            tap: None,
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

    /// How each of this call's streams is protected, at this moment: the
    /// encryption report.
    ///
    /// One entry per stream the call carries, which for this stack is its
    /// one audio stream. [`MediaEvent::Secured`] is the moment a DTLS-SRTP
    /// stream's entry becomes encrypted; an SDES stream's is encrypted from
    /// the moment its session opens.
    #[must_use]
    pub fn encryption(&self) -> Vec<StreamEncryption> {
        let (key_exchange, suite, authenticated) = match &self.plan.keying {
            None => (None, None, false),
            Some(Keying::Sdes { local, .. }) => (
                Some(SrtpKeying::Sdes),
                Some(keying::transform(local.suite)),
                false,
            ),
            // the handshake refuses a certificate the signalling's
            // fingerprint does not name before any key is exported, so a
            // stream it keyed is one whose far end was authenticated
            Some(Keying::Dtls { .. }) => (
                Some(SrtpKeying::Dtls),
                self.handshake_suite,
                self.is_encrypted(),
            ),
        };
        vec![StreamEncryption {
            media: "audio",
            encrypted: self.is_encrypted(),
            key_exchange,
            suite: suite.filter(|_| self.is_encrypted()),
            authenticated,
            awaiting_keys: self.is_awaiting_keys(),
        }]
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

    /// Have this session put `call` on the engine's list of calls with an
    /// event waiting, from now on, whenever it queues one.
    pub(crate) fn report_to(&mut self, call: sipral_ua::CallHandle, ready: Arc<Ready>) {
        self.events.report_to(call, ready);
    }

    /// The engine found this session on its list: the next event, and
    /// whether it has another after it.
    pub(crate) fn take_for_engine(&mut self) -> (Option<MediaEvent>, bool) {
        self.events.take_for_engine()
    }

    /// Queue an event as the session itself would.
    #[cfg(test)]
    pub(crate) fn push_event_for_test(&mut self, event: MediaEvent) {
        self.events.push_back(event);
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
        let feedback = self.rtp.feedback();
        StreamStatistics {
            codec: self.codec(),
            quality: self.rtp.quality(),
            round_trip: self.rtp.round_trip_time(),
            packets_sent: self.packets_sent,
            octets_sent: self.octets_sent,
            silent_for: now.saturating_duration_since(self.last_inbound),
            voip_metrics: self.rtp.voip_metrics(self.codec().quality_model()),
            feedback: feedback.map(|(negotiated, _)| negotiated),
            feedback_counts: feedback.map(|(_, counts)| counts).unwrap_or_default(),
        }
    }

    /// What RTP/AVPF feedback this stream agreed (RFC 4585, RFC 5506), or
    /// `None` for one running plain RTP/AVP.
    #[must_use]
    pub fn feedback(&self) -> Option<sipral_rtp::avpf::Negotiated> {
        self.rtp.feedback().map(|(negotiated, _)| negotiated)
    }

    /// Run this stream's RTCP as RTP/AVPF from `now` on, with what the two
    /// descriptions agreed (RFC 4585, RFC 5506), or take what a later
    /// exchange agreed for one already running it.
    pub(crate) fn use_feedback(&mut self, agreed: sipral_rtp::avpf::Negotiated, now: Instant) {
        let elapsed = self.elapsed(now);
        let draw = self.draws.unit();
        self.rtp.use_feedback(agreed, elapsed, draw);
    }

    /// The RFC 6035 quality report `sipral_ua::UserAgent::send_quality_report`
    /// wants for this stream, from what it has measured so far. `None` when
    /// this stream has not identified a source to report on yet
    /// ([`sipral_rtp::RtpSession::voip_metrics`]) — a call ending before its
    /// first RTP packet has nothing RFC 3611 measured to publish.
    #[must_use]
    pub(crate) fn quality_report_metrics(&self, now: Instant) -> Option<QualityReportMetrics> {
        let block = self.rtp.voip_metrics(self.codec().quality_model())?;
        let (start, stop) = self.session_span(now);
        Some(QualityReportMetrics {
            local_addr: self.plan.local,
            local_ssrc: self.rtp.local_ssrc(),
            remote_addr: self.plan.remote,
            remote_ssrc: block.ssrc,
            start,
            stop,
            payload_type: self.plan.codec.payload(),
            payload_desc: self.codec().encoding_name(),
            sample_rate: self.plan.codec.clock_rate(),
            loss_rate: block.loss_rate,
            discard_rate: block.discard_rate,
            burst_density: block.burst_density,
            burst_duration_ms: block.burst_duration_ms,
            gap_density: block.gap_density,
            gap_duration_ms: block.gap_duration_ms,
            gmin: block.gmin,
            round_trip_delay_ms: block.round_trip_delay_ms,
            end_system_delay_ms: block.end_system_delay_ms,
            jitter_buffer_adaptive: block.rx_config.jba as u8,
            jitter_buffer_rate: block.rx_config.jb_rate,
            jitter_buffer_nominal_ms: block.jb_nominal_ms,
            jitter_buffer_maximum_ms: block.jb_maximum_ms,
            jitter_buffer_abs_max_ms: block.jb_abs_max_ms,
            r_factor: (block.r_factor != UNAVAILABLE).then_some(block.r_factor),
            mos_lq_x10: (block.mos_lq != UNAVAILABLE).then_some(block.mos_lq),
            mos_cq_x10: (block.mos_cq != UNAVAILABLE).then_some(block.mos_cq),
            remote: self.rtp.far_voip_metrics().as_ref().map(remote_metrics),
        })
    }

    /// When this stream began, and `now`, both as Unix time — the span RFC
    /// 6035's `Timestamps` line wants, read off this session's own wall
    /// clock rather than one taken at the moment of the report, so a report
    /// built well after the stream actually ended (a queued goodbye, a
    /// slow poll loop) still names when the audio itself ran.
    fn session_span(&self, now: Instant) -> (std::time::SystemTime, std::time::SystemTime) {
        let epoch = std::time::SystemTime::UNIX_EPOCH;
        (
            epoch + Duration::from_secs(self.clock.unix_at(self.origin)),
            epoch + Duration::from_secs(self.clock.unix_at(now)),
        )
    }
}

/// The RFC 6035 `RemoteMetrics` set, from the far end's own RFC 3611 §4.7
/// block about this end's stream, each "unavailable" sentinel (§4.7.4,
/// §4.7.5) left out rather than written as a reading.
fn remote_metrics(block: &VoipMetricsBlock) -> RemoteQualityMetrics {
    let known = |value: u8| (value != UNAVAILABLE).then_some(value);
    let level = |value: i8| (value != UNAVAILABLE.cast_signed()).then_some(value);
    RemoteQualityMetrics {
        loss_rate: block.loss_rate,
        discard_rate: block.discard_rate,
        burst_density: block.burst_density,
        burst_duration_ms: block.burst_duration_ms,
        gap_density: block.gap_density,
        gap_duration_ms: block.gap_duration_ms,
        gmin: block.gmin,
        round_trip_delay_ms: block.round_trip_delay_ms,
        end_system_delay_ms: block.end_system_delay_ms,
        signal_level_dbm0: level(block.signal_level_dbm0),
        noise_level_dbm0: level(block.noise_level_dbm0),
        rerl_db: known(block.rerl_db),
        jitter_buffer_adaptive: block.rx_config.jba as u8,
        jitter_buffer_rate: block.rx_config.jb_rate,
        jitter_buffer_nominal_ms: block.jb_nominal_ms,
        jitter_buffer_maximum_ms: block.jb_maximum_ms,
        jitter_buffer_abs_max_ms: block.jb_abs_max_ms,
        r_factor: known(block.r_factor),
        ext_r_factor: known(block.ext_r_factor),
        mos_lq_x10: known(block.mos_lq),
        mos_cq_x10: known(block.mos_cq),
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
        self.receive_payload(datagram, from, now)
    }

    /// Take bytes read off the TCP or TLS connection this call's relay runs
    /// over to its TURN server ([`crate::Relays::over`]), in whatever pieces
    /// the connection delivered them.
    ///
    /// The messages in them are put back together (RFC 8656 §12.5), and each
    /// is taken as [`MediaSession::receive`] takes a datagram from the
    /// server: the relay's own traffic by the agent, and a peer's audio,
    /// reports and handshake records, unwrapped, by the rest of the session.
    /// Drain [`MediaSession::poll_transmit`] after it, as after a
    /// [`Arrival::Check`].
    ///
    /// `Ok(false)` for a session whose relay runs over no connection, or has
    /// none, and the bytes are not this call's.
    ///
    /// # Errors
    ///
    /// The connection carried something that is neither STUN nor a channel
    /// message, or a STUN length that is not whole words: nothing in a
    /// stream marks where a message starts, so it cannot find its place
    /// again. The relay is lost with it — as if the connection had closed —
    /// and the application closes the connection.
    #[cfg(feature = "ice")]
    pub fn receive_stream(
        &mut self,
        bytes: &[u8],
        now: Instant,
    ) -> Result<bool, crate::TurnStreamError> {
        let Some(ice) = self.ice.as_mut() else {
            return Ok(false);
        };
        if ice.stream_server().is_none() || !ice.push_stream(bytes) {
            return Ok(false);
        }
        let mut frame = core::mem::take(&mut self.stream_in);
        let result = loop {
            match self.next_stream_frame(&mut frame, now) {
                Ok(true) => self.take_stream_frame(&mut frame, now),
                Ok(false) => break Ok(true),
                Err(error) => break Err(error),
            }
        };
        self.stream_in = frame;
        result
    }

    /// Hand the relay bytes read off its connection to the TURN server, for
    /// [`MediaSession::next_stream_frame`] to read back whole, and name that
    /// server; `None` when this call's relay runs over no connection.
    #[cfg(feature = "ice")]
    pub(crate) fn push_stream(&mut self, bytes: &[u8]) -> Option<SocketAddr> {
        let ice = self.ice.as_mut()?;
        let server = ice.stream_server()?;
        ice.push_stream(bytes).then_some(server)
    }

    /// The next whole message the connection this call's relay runs over
    /// carried, copied into `frame` and not yet taken: `Ok(false)` once none
    /// is waiting. The engine reads the one connection the branches of a
    /// forked call share this way, and hands each message to the branch it
    /// is for ([`MediaSession::take_stream_frame`]).
    ///
    /// # Errors
    ///
    /// As [`MediaSession::receive_stream`].
    #[cfg(feature = "ice")]
    pub(crate) fn next_stream_frame(
        &mut self,
        frame: &mut Vec<u8>,
        now: Instant,
    ) -> Result<bool, crate::TurnStreamError> {
        let Some(ice) = self.ice.as_mut() else {
            frame.clear();
            return Ok(false);
        };
        ice.top_up();
        let taken = ice.next_stream_frame(frame, now);
        self.drain_ice(now);
        taken
    }

    /// Take `frame`, one whole message off the relay's connection, as
    /// [`MediaSession::receive_stream`] takes each it reads: a peer's data
    /// goes where a relayed datagram goes, from the server's address, and
    /// the relay's own traffic stays with the relay.
    #[cfg(feature = "ice")]
    pub(crate) fn take_stream_frame(&mut self, frame: &mut [u8], now: Instant) {
        let Some(ice) = self.ice.as_mut() else {
            return;
        };
        let Some(server) = ice.stream_server() else {
            return;
        };
        ice.top_up();
        let taken = ice.take_stream_frame(frame, now);
        self.drain_ice(now);
        // the server is where a relayed datagram comes from, on a connection
        // as on UDP, and it is what the rest of the path has always been
        // handed for one
        if let Taken::Data(range) = taken
            && let Some(payload) = frame.get_mut(range)
        {
            let _ = self.receive_payload(payload, server, now);
        }
    }

    /// The connection this call's relay ran over to its TURN server closed,
    /// and the relay went with it: the server knew the allocation by that
    /// connection (RFC 8656 §3.2). A pair through it stops carrying the call
    /// when its consent runs out (RFC 7675 §5.1) — reported as
    /// [`MediaError::IcePathLost`] — and whatever pair ICE found without it
    /// goes on. Nothing for a session whose relay runs over no connection.
    #[cfg(feature = "ice")]
    pub fn stream_closed(&mut self, now: Instant) {
        if let Some(ice) = self.ice.as_mut() {
            ice.stream_closed(now);
        }
        self.drain_ice(now);
    }

    /// Everything [`MediaSession::receive`] does with a datagram once the
    /// agent has taken off any relay wrapping and passed on what is not its
    /// own.
    fn receive_payload(&mut self, datagram: &mut [u8], from: SocketAddr, now: Instant) -> Arrival {
        #[cfg(feature = "dtls")]
        if sipral_nat::classify(datagram) == sipral_nat::Demux::Dtls {
            return self.receive_handshake(datagram, from, now);
        }
        if is_rtcp(datagram) {
            return self.receive_control(datagram, from, now);
        }
        #[cfg(feature = "ice")]
        self.follow_before_selection();
        let elapsed = self.elapsed(now);
        match self.rtp.receive(datagram, from, elapsed) {
            Received::Queued => {
                self.note_arrival(now);
                // verified and opened in place: what is left in front of
                // the tag SRTP carried is the packet the far end sent
                if let Some(tap) = self.tap.as_mut() {
                    let plain = datagram.len().saturating_sub(self.rtp.rtp_overhead());
                    tap.received(datagram.get(..plain).unwrap_or_default());
                }
                Arrival::Queued
            }
            Received::Dropped(Discard::NotKeyed) => Arrival::NotKeyed,
            Received::Dropped(why) => Arrival::Dropped(why),
        }
    }

    /// Let RTP's latch follow the far end until ICE has selected a pair.
    ///
    /// Before the selection the far end may send on any pair its own checks
    /// have found valid, and moves to a better one as they find it (RFC 8445
    /// §12.1), while this end receives on any of them (§12.2). The latch
    /// closes on the first packet that arrives, so the far end's audio was
    /// refused from its second pair on — through the caller's relay first,
    /// say, and then straight from its own — until the selection opened the
    /// latch again, which on a regular nomination is up to a second later,
    /// `nomination_wait`. So until then a packet from another address that
    /// passes everything else moves the latch rather than being refused
    /// ([`RtpSession::set_following`]); from the selection on it holds,
    /// armed as [`MediaSession::drain_ice`] leaves it, on the chosen path. A
    /// call not using ICE keeps symmetric RTP's rule as it always was.
    #[cfg(feature = "ice")]
    fn follow_before_selection(&mut self) {
        let unselected = self
            .ice
            .as_ref()
            .is_some_and(|ice| ice.selected_pair().is_none());
        self.rtp.set_following(unselected);
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
            Taken::Consumed => Err(Arrival::Check),
            Taken::Foreign => Err(Arrival::Dropped(Discard::ForeignAddress)),
            // `range` indexes the datagram that was handed in, so the `None`
            // arm is unreachable: it would be `sipral-nat` reporting a
            // position in a buffer it was not given. It is written rather
            // than unwrapped because a panic on the media path is worse than
            // a dropped packet, and the fuzz target `ice` asserts the range
            // indexes the datagram precisely so this stays unreachable.
            Taken::Data(range) => datagram.get_mut(range).ok_or(Arrival::Check),
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
        while let Some(news) = ice.poll_news() {
            match news {
                PathNews::Selected(pair) => selected = Some(pair),
                // RFC 7675 §5: nothing more may be sent on that pair, and the
                // same credentials may not be used on it again. What the
                // application can do about it is restart ICE, which draws new
                // ones (`MediaEngine::restart_ice`), or end the call — which
                // is what the event's own documentation says, rather than
                // leaving it to be worked out from the silence
                PathNews::Lost => lost = true,
            }
        }
        if let Some(pair) = selected {
            // symmetric RTP's latch is the poor version of the check the
            // agent has already run, and leaving it armed would cut the audio
            // for good the first time a mid-call re-selection moved the pair
            self.rtp.relocate(pair.remote);
            // and the handshake's latch goes with it, for the same reason: a
            // far end that began its handshake on one pair and then nominated
            // another would otherwise have every record from the pair it
            // chose dropped, while this end's flights went there
            #[cfg(feature = "dtls")]
            if let Some(dtls) = self.dtls.as_mut() {
                dtls.peer = Some(pair.remote);
            }
            self.events.push_back(MediaEvent::PathChosen {
                local: pair.local,
                remote: pair.remote,
            });
        }
        if lost {
            // and the agent is **kept**. Dropping it here would be the exact
            // opposite of what RFC 7675 §5.1 asks — "the endpoint MUST cease
            // transmission on that 5-tuple" — because a session with no agent
            // is a session that sends to the address the signalling named,
            // which is the unchecked path this call chose not to trust. Kept,
            // the agent answers `NoConsent` to every route asked of it and
            // every producer here stops, which is the rule stated once in the
            // layer that owns it.
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
                transport: crate::TurnTransport::Udp,
            });
        };
        // N9's third place. `send` spends no id while the pair is direct, and
        // will spend one the moment a relayed pair has a refresh due; filling
        // here costs one subtraction on a full pool and means the rule does
        // not have to be remembered again then
        ice.top_up();
        let (destination, transport, payload) = ice.send(data, now).ok()?;
        Some(Datagram {
            destination,
            payload,
            transport,
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
        let possible = self.handshake_source_possible(from);
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
            // arriving from anywhere at all. And only from a source that could
            // be the far end: see `handshake_source_possible`
            None if possible && datagram.first() == Some(&HANDSHAKE_RECORD) => {
                dtls.peer = Some(from);
            }
            None => return Arrival::Dropped(Discard::ForeignAddress),
        }
        // RFC 6347 §4.2.8: a ClientHello that starts over, to a server whose
        // association is up, begins a new one beside it. The running
        // connection would take it and ignore it, and a far end that starts
        // over on a re-negotiation — Asterisk does, on a hold — then waits for
        // a handshake that never comes. One at a time: while one is being
        // answered, everything goes to it
        if dtls.next.is_none()
            && dtls.handshake.role() == sipral_dtls::Role::Server
            && dtls.handshake.is_keyed()
            && crate::dtls::begins_an_association(datagram)
            && let Ok(next) = dtls.handshake.renewal(now)
        {
            dtls.next = Some(next);
        }
        match dtls.next.as_mut() {
            Some(next) => next.on_datagram(datagram, now),
            None => dtls.handshake.on_datagram(datagram, now),
        }
        self.settle_handshake();
        Arrival::Handshake
    }

    /// Open the handshake's latch again, for a re-negotiation that moved the
    /// far end's media address: RTP's own latch has just been dropped for
    /// the same reason, and the next record from the new host closes this
    /// one again. A no-op without a handshake, and without the feature.
    #[cfg_attr(not(feature = "dtls"), allow(clippy::unused_self))]
    fn forget_handshake_source(&mut self) {
        #[cfg(feature = "dtls")]
        if let Some(dtls) = self.dtls.as_mut() {
            dtls.peer = None;
        }
    }

    /// Whether a handshake record from `from` may close this call's DTLS
    /// latch.
    ///
    /// Nothing before the fingerprint check authenticates anything, so the
    /// first record the latch takes decides whose records the handshake is
    /// run with. Taken from anywhere, one datagram from anybody who read the
    /// port out of the description — one octet, 22 — closed it on the
    /// sender, and every record from the real far end was then dropped until
    /// the handshake gave up: a single packet that kept any encrypted call
    /// from ever being keyed. So without ICE only the host the signalling
    /// named may close it, which is the rule RTCP already has before its own
    /// latch (`rtcp_origin_possible` in `sipral-rtp`), applied before there
    /// are any keys. Any port on that host, as there, for a far end behind a
    /// NAT that keeps its address and moves its port. What is left is an
    /// attacker who can send from the far end's own address, which is the
    /// race `Dtls::peer` has always documented and only ICE closes.
    ///
    /// With ICE the agent has already dropped every source that is not a
    /// candidate it checked, and the pair it chose moves the latch itself.
    #[cfg(feature = "dtls")]
    fn handshake_source_possible(&self, from: SocketAddr) -> bool {
        #[cfg(feature = "ice")]
        if self.ice.is_some() {
            return true;
        }
        from.ip() == self.rtp.destination().ip()
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
        if let Some(next) = dtls.next.as_mut() {
            match next.take_outcome() {
                // "After a correct Finished message is received, the server
                // MUST abandon the previous association" (§4.2.8). Each
                // direction moves to its new key the way a re-key does: what
                // this end sends, from now; what arrives, with the old context
                // kept for the packets already in flight under it. The keys
                // are new, so each index starting again repeats nothing
                // (RFC 3711 §9.1)
                Some(Ok(exported)) => {
                    let suite = exported.suite;
                    self.handshake_suite = Some(suite);
                    self.rtp
                        .rekey_local(exported.policy, exported.local, Rekeyed::Key);
                    self.rtp
                        .rekey_remote(exported.policy, exported.remote, Rekeyed::Key);
                    if let Some(next) = dtls.next.take() {
                        dtls.handshake = next;
                    }
                    self.events.push_back(MediaEvent::Secured { suite, peer });
                }
                // one that gave up, or was never going to finish, is dropped
                // and the call stays on the association it had. Not reported:
                // the prompt for it arrives in the clear, and reporting what
                // anybody who can send from the far end's address could
                // provoke would be handing them a way to fail any call. A far
                // end that did move and could not finish stops sending, and
                // the stall watchdog says so
                Some(Err(_)) => dtls.next = None,
                None => {}
            }
            return;
        }
        match dtls.handshake.take_outcome() {
            Some(Ok(exported)) => {
                let suite = exported.suite;
                // `keyed` is false for a stream that was not waiting, which
                // is a session that has already been keyed once: the event
                // goes out with the keys or not at all
                let installed = self.rtp.keyed(exported.into_security());
                if installed {
                    self.handshake_suite = Some(suite);
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
            if let Some((destination, transport)) = ready {
                return Some(Datagram {
                    destination,
                    payload: self.ice.as_ref().map_or(&[][..], crate::ice::Ice::probe),
                    transport,
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
            // a new association's records first: it is the one being set up,
            // and the running one only ever answers retransmissions
            let dtls = self.dtls.as_mut()?;
            let record = match dtls
                .next
                .as_mut()
                .and_then(crate::dtls::Handshake::take_outbound)
            {
                Some(record) => record,
                None => dtls.handshake.take_outbound()?,
            };
            self.dtls_out = record;
            // where the far end's own records come from, while the stream has
            // no latch of its own — and it has none for as long as the
            // handshake runs, because nothing on RTP can close one before
            // there are keys to authenticate a packet with. Following the
            // stream's address alone left a far end whose port the path had
            // moved sending ClientHellos to an answer that went elsewhere.
            // Once RTP has latched, on a packet that authenticated, that is
            // the better witness and is followed instead; before the far end
            // has said anything, the signalled address is all there is
            let latched = self.dtls.as_ref().and_then(|dtls| dtls.peer);
            let destination = match (self.rtp.latched(), latched) {
                (None, Some(peer)) => peer,
                _ => self.rtp.destination(),
            };
            #[cfg(feature = "ice")]
            {
                let length = self.dtls_out.len();
                self.on_path(Built::Handshake, length, destination, now)
            }
            #[cfg(not(feature = "ice"))]
            {
                let _ = now;
                Some(Datagram {
                    destination,
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
            // a reduced-size packet is the far end all the same: feedback
            // alone, which RFC 5506 lets it send between its reports
            RtcpReceived::Report | RtcpReceived::Feedback => {
                self.last_control = now;
                Arrival::Control
            }
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
        // digits, tones and who answered are listened for in what the far
        // end sent, before anything of this end's is mixed into it
        self.signals.heard(room, &mut self.events);
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
        // the consent beep this end hears, which the recording already has
        // on its own side
        self.signals.beep_locally(room);
        // this is the frame the loudspeaker is about to have, so it is the
        // one a canceller will be looking for in the microphone a device
        // delay from now
        if let Some(echo) = self.echo.as_mut() {
            echo.rendered(room);
        }
        played
    }

    /// Decode whatever the jitter buffer had for this frame into `room`.
    fn fill(&mut self, room: &mut [i16]) -> Playback {
        let coder = &mut self.coder;
        let noise = &mut self.noise;
        let heard = &mut self.heard;
        let events = &mut self.events;
        let signals = &mut self.signals;
        // the codec arrives on this end's own number for it, which a peer
        // that renumbered a dynamic type (RFC 3264 §6.1) sends with
        let payload_type = self.plan.codec_in;
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
        let dtmf = self.plan.dtmf_in;
        let foreign_law = sibling_law(coder.codec()).filter(|&(sibling, _)| dtmf != Some(sibling));
        match self.rtp.pull(self.activity) {
            Pull::Packet(frame) if frame.payload_type == COMFORT_NOISE => {
                if let Ok(described) = ComfortNoise::decode(frame.payload) {
                    noise.received(described);
                }
                noise.fill(room);
                coder.interrupted();
                Playback::ComfortNoise
            }
            Pull::Packet(frame) if frame.payload_type == payload_type => {
                match coder.decode(frame.payload, room) {
                    Ok(Decoded::Audio(_)) => Playback::Packet,
                    // a G.729 payload of a SID frame alone: the codec's own
                    // comfort noise, which it carries on through the frames
                    // the far end then does not send (below)
                    Ok(Decoded::Noise(_)) => Playback::ComfortNoise,
                    // a payload the codec refuses is a corrupt one, and the
                    // right thing to play for it is the frame it displaced
                    Ok(Decoded::Unreadable) | Err(_) => conceal(coder, room),
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
                    let event = digit_heard(&reported, rate);
                    if let MediaEvent::DigitReceived {
                        digit,
                        held: Some(held),
                        ..
                    } = event
                    {
                        // the same press may be in the audio as well
                        signals.received_event(digit, held);
                    }
                    events.push_back(event);
                }
                conceal(coder, room)
            }
            Pull::Conceal => conceal(coder, room),
            // a pause being made longer, or one the far end is keeping: a
            // G.729 far end in an Annex B pause sent nothing on purpose, and
            // its decoder carries the comfort noise on (B.4.5)
            Pull::Stretch => {
                if coder.pause(room).is_some() {
                    Playback::ComfortNoise
                } else {
                    stretch(coder, room)
                }
            }
            // nothing the coder decoded or concealed is played, so its
            // concealer's history stops here (`Coder::interrupted`)
            Pull::Empty => {
                coder.interrupted();
                if coder.pause(room).is_some() {
                    Playback::ComfortNoise
                } else if noise.is_silent() {
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
        // and the buffer a digit or a beep is written into, for the same
        // reason: what goes out is borrowed from it
        let mut shaped = core::mem::take(&mut self.shaped);
        // the frame about to be stamped stands for now on the media clock,
        // which is what a sender report pairs with the wall clock (RFC 3550
        // §6.4.1)
        self.rtp.clock_at(self.elapsed(now));
        let sent = self.encode_frame(samples, echo.as_mut(), &mut shaped);
        self.shaped = shaped;
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
        shaped: &mut Vec<i16>,
    ) -> Result<Option<usize>, MediaError> {
        // everything below works on what the processor left, not on the raw
        // microphone: silence suppression measuring uncancelled echo would
        // hold the stream open through the far end's own talking, and a
        // recording of the raw capture would not be a recording of the call
        let samples = match echo {
            Some(echo) => echo.process(samples),
            None => samples,
        };
        // a digit being written in the audio, or the consent beep: what the
        // far end is sent, and so what the recording keeps of this side
        let tone = self.signals.shape(
            samples,
            shaped,
            self.dialling.is_busy() && self.plan.dtmf.is_some(),
        );
        let samples = if tone { shaped.as_slice() } else { samples };
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
        // a digit or a beep is never a pause, whatever the detector makes of
        // a steady tone
        let silent = self.suppressing
            && !tone
            && self.outbound_voice.process(samples) == vad::Activity::Silence;
        if silent {
            self.rtp.suppress(self.frame_ticks);
            return Ok(None);
        }
        let sent = self.coder.encode(samples, &mut self.payload)?;
        let written = sent.octets;
        // G.729 with Annex B: a frame the DTX sent nothing for is time that
        // passed, as a suppressed one is, and so is the start of a frame
        // whose payload begins after a pause ended inside it
        if written == 0 {
            self.rtp.suppress(self.frame_ticks);
            return Ok(None);
        }
        let skipped = ticks_in(sent.skipped, self.frame_ticks, self.coder.frame_samples());
        if skipped > 0 {
            self.rtp.suppress(skipped);
        }
        let payload = self.payload.get(..written).unwrap_or_default();
        let ticks = self.frame_ticks.saturating_sub(skipped);
        let length = match self.rtp.send(payload, ticks, &mut self.rtp_out) {
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
        if let Some(tap) = self.tap.as_mut() {
            tap.sent(self.rtp_out.get(..length).unwrap_or_default(), payload);
        }
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
        let codec = self.codec().quality_model();
        let (length, _) = self
            .rtp
            .build_report(&mut self.rtcp_out, elapsed, ntp, draw, codec)
            .ok()?;
        // RTP/AVPF can spend a slot on nothing: a Regular packet `trr-int`
        // suppressed, or an Early one whose loss turned up after all
        if length == 0 {
            return None;
        }
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
            if let Some(next) = dtls.next.as_mut() {
                next.close();
            }
        }
    }

    /// Begin a new association from this end, the way a far end that starts
    /// over on a re-negotiation does (RFC 6347 §4.2.8): the half of it this
    /// stack never starts by itself, played by a test so that the other half
    /// can be seen answering it. `false` for a stream no handshake keys.
    #[cfg(all(test, feature = "dtls"))]
    pub(crate) fn start_the_handshake_over(&mut self, now: Instant) -> bool {
        let Some(dtls) = self.dtls.as_mut() else {
            return false;
        };
        match dtls.handshake.renewal(now) {
            Ok(next) => {
                dtls.next = Some(next);
                true
            }
            Err(_) => false,
        }
    }

    /// Which end of the call's DTLS association this one is, or `None` for a
    /// stream no handshake keys.
    ///
    /// Answered for as long as the session lasts, finished or not: the role
    /// is what every later negotiation on the call has to leave where it is
    /// (RFC 8842 §5.3), and the engine asks it of the running session rather
    /// than working it out again from descriptions that may have moved on.
    #[cfg(feature = "dtls")]
    pub(crate) fn dtls_role(&self) -> Option<sipral_dtls::Role> {
        self.dtls.as_ref().map(|dtls| dtls.handshake.role())
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
            // and for the same reason: `rtcp_due` both answers and
            // reconsiders, so a report this deadline woke a caller for and
            // `poll_rtcp` then refused would leave the deadline where it was
            // — and every later poll would see it passed. A caller driven by
            // this would spin for the whole of the checks
            .filter(|_| self.has_path_or_none())
            .map(|_| self.origin + self.rtp.next_rtcp_deadline());
        let stall = self
            .stall_after
            .filter(|_| self.is_receiving() && !self.stalled)
            .map(|after| self.heard_from() + after);
        #[cfg(feature = "dtls")]
        let handshake = self.dtls.as_ref().and_then(|dtls| {
            let running = dtls.handshake.poll_timeout();
            let next = dtls
                .next
                .as_ref()
                .and_then(crate::dtls::Handshake::poll_timeout);
            [running, next].into_iter().flatten().min()
        });
        #[cfg(not(feature = "dtls"))]
        let handshake = None;
        #[cfg(feature = "ice")]
        let ice = self.ice.as_ref().and_then(crate::ice::Ice::deadline);
        #[cfg(not(feature = "ice"))]
        let ice = None;
        let text = self
            .text
            .as_ref()
            .and_then(crate::text::TextStream::deadline);
        [rtcp, stall, handshake, ice, text]
            .into_iter()
            .flatten()
            .min()
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
            if let Some(next) = dtls.next.as_mut() {
                next.on_timeout(now);
            }
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
        // and the text stream's gaps, which are given up on its own clock
        if let Some(text) = self.text.as_mut() {
            text.handle_timeout(now);
            self.report_text();
        }
        let Some(after) = self.stall_after else {
            return;
        };
        if self.stalled || !self.is_receiving() {
            return;
        }
        if now.saturating_duration_since(self.heard_from()) >= after {
            self.stalled = true;
            self.events.push_back(MediaEvent::Stalled {
                silent_for: now.saturating_duration_since(self.last_inbound),
            });
        }
    }

    /// When the far end was last known to be there, which is what the stall
    /// watchdog measures from: its last packet of audio — or, in a G.729
    /// pause it announced with an Annex B SID frame, its last control report
    /// if that is later, since in that pause no audio is what it said it
    /// would send. A stream whose reports stop too is stalled as any other.
    fn heard_from(&self) -> Instant {
        if self.coder.far_end_paused() {
            self.last_inbound.max(self.last_control)
        } else {
            self.last_inbound
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

    /// How many of the ICE agent's own datagrams — checks, consent requests,
    /// keepalives, answers to the peer's checks — were dropped because
    /// `sipral_nat::ice::TRANSMIT_CEILING` of them were already waiting for
    /// [`MediaSession::poll_transmit`], or were refusals of checks that failed
    /// authentication once `sipral_nat::ice::REFUSAL_CEILING` were. Zero on a
    /// call not using ICE.
    ///
    /// Every check that reaches the media port is answered, a stranger's
    /// unsigned one included, so a queue nobody drains would grow with
    /// whatever anybody sends it. It stops at the ceiling instead, and the
    /// datagram that would have gone past it is the one dropped: to the STUN
    /// transaction it belongs to that is a lost datagram, which it
    /// retransmits. A stranger's refusals stop at half the ceiling, so a
    /// flood of them leaves room for the peer's checks and the agent's own. A
    /// count that moves on a working call means the application drains less
    /// often than it is told to, or that the port is being flooded.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn ice_transmits_dropped(&self) -> u64 {
        self.ice
            .as_ref()
            .map_or(0, crate::ice::Ice::transmits_dropped)
    }

    /// Give back the relays this call's agent holds, for a call that has
    /// ended: what to send, and where. See [`crate::ice::Ice::release`].
    #[cfg(feature = "ice")]
    pub(crate) fn release_relays(
        &mut self,
        now: Instant,
    ) -> Vec<(SocketAddr, crate::TurnTransport, Vec<u8>)> {
        self.ice
            .as_mut()
            .map(|ice| ice.release(now))
            .unwrap_or_default()
    }

    /// Whether this session runs an ICE agent, which is what a connectivity
    /// check handed to [`MediaSession::receive`] reaches.
    #[cfg(feature = "ice")]
    pub(crate) const fn runs_ice(&self) -> bool {
        self.ice.is_some()
    }

    /// Carry what the call's descriptions now say about ICE onto the running
    /// agent: the credentials a restart gave it, and the peer's side of the
    /// same exchange. See [`crate::ice::Ice::follow`].
    ///
    /// # Errors
    ///
    /// As [`crate::ice::Ice::follow`].
    #[cfg(feature = "ice")]
    pub(crate) fn follow_ice(
        &mut self,
        local: Option<&crate::ice::LocalIce>,
        remote: Option<&sipral_nat::ice::RemoteIce>,
        now: Instant,
    ) -> Result<(), MediaError> {
        let (Some(ice), Some(local)) = (self.ice.as_mut(), local) else {
            return Ok(());
        };
        let followed = ice.follow(local, remote, now);
        self.drain_ice(now);
        followed
    }

    /// Whether a datagram that arrived on this call's socket is this
    /// session's, when the branches of a forked call share the socket.
    ///
    /// A session running ICE answers as its agent does
    /// ([`sipral_nat::ice::IceAgent::claims`]): a check naming its own
    /// peer's fragment, an answer to its own check, anything from an address
    /// among its peer's candidates. One that is not claims what comes from
    /// the address its description named, which is how early media from two
    /// phones on one socket is told apart when neither does ICE.
    #[cfg(feature = "ice")]
    pub(crate) fn claims(&self, from: SocketAddr, data: &[u8]) -> sipral_nat::ice::Claim {
        use sipral_nat::ice::Claim;
        match &self.ice {
            Some(ice) => ice.claims(from, data),
            None if from == self.destination() || Some(from) == self.control_destination() => {
                Claim::Mine
            }
            None => Claim::Not,
        }
    }

    /// Every candidate pair this call's ICE agent checked and every relay it
    /// held, with what became of each: D5's transport and NAT half, beside
    /// [`MediaSession::codec_candidates`]. Empty for a call not using ICE,
    /// whose one path is the address its description named.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn path_candidates(&self) -> Vec<crate::PathCandidate> {
        self.ice
            .as_ref()
            .map(crate::ice::Ice::path_candidates)
            .unwrap_or_default()
    }

    /// Tell the agent which credentials a restart offered, or answered, on
    /// this call carries, or with `None` that it will not happen. See
    /// [`crate::ice::Ice::expect_restart`].
    #[cfg(feature = "ice")]
    pub(crate) fn expect_ice_restart(&mut self, restarting: Option<&crate::ice::LocalIce>) {
        if let Some(ice) = self.ice.as_mut() {
            ice.expect_restart(restarting);
        }
    }

    /// The candidates this session's full agent still holds, for a restart
    /// to write. See [`crate::ice::Ice::gathered`].
    #[cfg(feature = "ice")]
    pub(crate) fn ice_candidates(&self) -> Option<Vec<sipral_nat::ice::Candidate>> {
        self.ice.as_ref().and_then(crate::ice::Ice::gathered)
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
            && self.has_path_or_none()
            && self.control_destination().is_some()
            && self.elapsed(now) >= self.rtp.next_rtcp_deadline()
    }

    /// Whether there is anywhere to send, for the two places that ask without
    /// the `ice` feature having to exist.
    ///
    /// `true` in a build with no agent, which has had somewhere to send since
    /// the description named it — and where the `self` it does not read is
    /// the whole of the difference between the two builds.
    #[cfg_attr(not(feature = "ice"), allow(clippy::unused_self))]
    fn has_path_or_none(&self) -> bool {
        #[cfg(feature = "ice")]
        {
            self.has_path()
        }
        #[cfg(not(feature = "ice"))]
        true
    }

    /// This session's own timeline, which is what `sipral-rtp` counts in.
    fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.origin)
    }
}

// -- real-time text (RFC 4103) -----------------------------------------------

impl MediaSession {
    /// Whether the call negotiated a real-time text stream.
    #[must_use]
    pub const fn has_text(&self) -> bool {
        self.text.is_some()
    }

    /// Queue typed text for the far end: sent in the next transmission
    /// interval (300 ms), at no more characters a second than the far end
    /// said it takes, each block carried twice more as redundancy where both
    /// ends agreed `red` (RFC 4103 §4, §5).
    ///
    /// A CR LF, a lone CR or a lone LF goes as the LINE SEPARATOR T.140 uses
    /// for a new line, and BACKSPACE (U+0008) erases the last character at
    /// the far end.
    ///
    /// # Errors
    /// [`MediaError::NoText`] on a call that negotiated no text stream, and
    /// [`MediaError::TextBufferFull`] for more than it holds unsent.
    pub fn send_text(&mut self, text: &str) -> Result<(), MediaError> {
        self.text.as_mut().ok_or(MediaError::NoText)?.send(text)
    }

    /// The next text datagram due, to send from the call's text socket.
    ///
    /// Call it whenever [`MediaSession::poll_timeout`] says to, or with every
    /// frame of audio: `None` until a packet is due.
    #[must_use]
    pub fn poll_text(&mut self, now: Instant) -> Option<Datagram<'_>> {
        let (destination, packet) = self.text.as_mut()?.poll_transmit(now)?;
        self.text_out = packet;
        Some(Datagram {
            destination,
            payload: &self.text_out,
            #[cfg(feature = "ice")]
            transport: crate::TurnTransport::Udp,
        })
    }

    /// Take a datagram off the call's text socket. `false` when it was not
    /// this call's text: not RTP, another payload type, from somewhere other
    /// than where the stream has latched, or on a call with no text.
    ///
    /// What was typed arrives as [`MediaEvent::TextReceived`].
    pub fn receive_text(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) -> bool {
        let Some(text) = self.text.as_mut() else {
            return false;
        };
        let taken = text.receive(datagram, from, now);
        self.report_text();
        taken
    }

    /// What two descriptions agreed about text, taken up: the stream opened
    /// on the first agreement, moved by a later one, and closed by one that
    /// refused it.
    pub(crate) fn set_text(&mut self, plan: Option<crate::text::TextPlan>, now: Instant) {
        match (plan, self.text.as_mut()) {
            (Some(plan), Some(running)) => {
                if let Err(error) = running.update(plan) {
                    self.text = None;
                    self.events.push_back(MediaEvent::Failed(error));
                }
            }
            (Some(plan), None) => {
                let numbers = (
                    self.draws.word(),
                    u16::try_from(self.draws.word() & 0x7fff).unwrap_or(0),
                    self.draws.word(),
                );
                match crate::text::TextStream::open(plan, numbers, now) {
                    Ok(stream) => self.text = Some(stream),
                    Err(error) => self.events.push_back(MediaEvent::Failed(error)),
                }
            }
            (None, _) => self.text = None,
        }
    }

    /// Raise what the text stream received, if it received anything.
    fn report_text(&mut self) {
        if let Some(heard) = self
            .text
            .as_mut()
            .and_then(crate::text::TextStream::take_heard)
        {
            self.events.push_back(MediaEvent::TextReceived {
                text: heard.text,
                missing: heard.missing,
            });
        }
    }
}

// -- copies for a recording server (RFC 7866) ---------------------------------

impl MediaSession {
    /// The next copy of this call's audio for the recording server recording
    /// it ([`crate::MediaEngine::record_to`]), to send from the socket it
    /// names. `None` while there is none, which is always on a call nothing
    /// records.
    ///
    /// Collect it with every frame: a copy nobody collects for a second is
    /// dropped, the oldest first.
    #[must_use]
    pub fn poll_recording(&mut self) -> Option<crate::siprec::RecordingDatagram<'_>> {
        self.tap.as_mut()?.poll()
    }

    /// Whether this call's audio is being copied to a recording server.
    #[must_use]
    pub const fn is_copied(&self) -> bool {
        self.tap.is_some()
    }

    /// Start copying this call's audio as `tap` says, or stop, and hand back
    /// the copies that were running.
    pub(crate) const fn tap_to(
        &mut self,
        tap: Option<crate::siprec::Tap>,
    ) -> Option<crate::siprec::Tap> {
        core::mem::replace(&mut self.tap, tap)
    }

    /// The copies running, to point them somewhere else.
    pub(crate) const fn tap(&mut self) -> Option<&mut crate::siprec::Tap> {
        self.tap.as_mut()
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
        annex_b: bool,
        now: Instant,
    ) -> Result<(), MediaError> {
        let (fresh_local, fresh_remote) = Self::rekeyed(&self.plan, plan)?;
        // a re-negotiation that allowed or refused G.729's Annex B from here
        // on: the encoder starts again with its DTX on or off, and the
        // stream's marker bit and this end's own detector follow it
        if self.coder.annex_b() != annex_b {
            self.coder.set_annex_b(annex_b);
            let discontinuous = self.coder.annex_b();
            self.rtp
                .set_silence_suppression(self.silence_suppression || discontinuous);
            self.suppressing = self.silence_suppression && !discontinuous;
        }
        if plan.remote != self.plan.remote {
            self.rtp.relocate(plan.remote);
            // a far end that moved its media address has almost always
            // restarted the stream behind it, and the sequence numbers of the
            // old one say nothing about the new
            self.rtp.resync();
            self.last_inbound = now;
            self.forget_handshake_source();
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
        // a re-offer can add or drop the named events, which is what
        // listening for digits in the audio decides on by default
        self.signals
            .reformat(self.coder.codec().sample_rate(), plan.dtmf.is_some());
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
        annex_b: bool,
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
        let mut coder = Coder::new(agreed, frame_ms)?;
        coder.set_annex_b(annex_b);
        let discontinuous = coder.annex_b();
        let (fresh_local, fresh_remote) = Self::rekeyed(&self.plan, plan)?;

        let was_rate = self.sample_rate();
        let was_samples = self.frame_samples();
        let was_clock = self.plan.codec.clock_rate();
        let frame_ticks = agreed.frame_ticks(frame_ms);

        let moved = plan.remote != self.plan.remote;
        self.rtp.reformat(&StreamFormat {
            payload_type: plan.codec.payload(),
            accepted: accepted(plan),
            clock_rate: plan.codec.clock_rate(),
            remote: plan.remote,
            silence_suppression: config.silence_suppression || discontinuous,
            playout: BufferConfig::new(frame_ticks),
        });
        if moved {
            self.forget_handshake_source();
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

        let rate = agreed.sample_rate();
        let samples = coder.frame_samples();
        let resized = rate != was_rate || samples != was_samples;
        self.retain_recording(rate);
        self.signals.reformat(rate, plan.dtmf.is_some());
        self.retain_processor(resized, rate, samples);
        self.dialling.reformat(was_clock, plan.codec.clock_rate());

        self.coder = coder;
        self.frame_ms = frame_ms;
        self.frame_ticks = frame_ticks;
        self.payload = vec![0; agreed.max_payload(frame_ms)];
        self.activity = Activity::Speech;
        self.inbound_voice = Vad::new(rate);
        self.outbound_voice = Vad::new(rate);
        self.silence_suppression = config.silence_suppression;
        self.suppressing = config.silence_suppression && !discontinuous;
        self.noise = Generator::new();
        self.stall_after = config.stall_after;
        self.heard = plan.dtmf_in.map(EventReceiver::new);
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

    /// Keep the recording running into the same file.
    ///
    /// The file has a rate of its own, fixed when it started, and the two
    /// directions are converted to it on the way in; a codec at another rate
    /// only changes what they are converted from. A sink that refuses what
    /// is left of the old rate stops the recording the way any other refusal
    /// does.
    fn retain_recording(&mut self, rate: u32) {
        if let Some(error) = self
            .recorder
            .as_mut()
            .and_then(|recorder| recorder.reformat(rate).err())
        {
            self.recording_stopped(error);
        }
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
    /// A change of shape is neither, and is refused. Encryption turning on or
    /// off mid-call, or SDES giving way to DTLS, is not expressible as a
    /// context for a stream that is running ([`Shape`]). Adopting such a plan
    /// used to leave the stream on the old keys while the plan said the new:
    /// SRTP sent to a far end expecting RTP, RTP sent to one that had been
    /// told it was DTLS-SRTP, and — since the plan is also what later
    /// re-negotiations compare against — a certificate that had gone away and
    /// come back as another one compared against nothing at all.
    ///
    /// # Errors
    /// [`MediaError::KeyingChanged`] for a change of shape.
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
        if Shape::of(was.keying.as_ref()) != Shape::of(plan.keying.as_ref()) {
            return Err(MediaError::KeyingChanged);
        }
        #[cfg(feature = "dtls")]
        if let (
            Some(Keying::Dtls {
                fingerprints: had, ..
            }),
            Some(Keying::Dtls {
                fingerprints: now, ..
            }),
        ) = (&was.keying, &plan.keying)
            && !crate::dtls::same_fingerprints(had, now)
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

    /// Date this session's sender reports by `clock` from here on.
    pub(crate) const fn set_wall_clock(&mut self, clock: WallClock) {
        self.clock = clock;
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
    /// A call whose negotiation settled on no telephone event payload type
    /// has no event to send, and gets the digit the way its far end can hear
    /// one: written into the audio as the two tones, in place of the
    /// microphone, as [`MediaSession::dial_in_band`] does.
    ///
    /// # Errors
    /// [`MediaError::DigitTooShort`] below the length legacy equipment
    /// recognises; [`MediaError::DigitTooLong`] above the longest any form of
    /// DTMF sends; and [`MediaError::TooManyDigits`] when the queue is full.
    pub fn send_dtmf(&mut self, digit: Digit, length: Duration) -> Result<(), MediaError> {
        if self.plan.dtmf.is_none() {
            return self.dial_in_band(&digit.to_string(), length).map(drop);
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
    /// extension is worse than none, because it reaches somebody. On a call
    /// with no telephone event the digits go in the audio, as
    /// [`MediaSession::send_dtmf`] says.
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
            return self.dial_in_band(keys, length);
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

    /// Send a dial string as the two tones of each key, written into the
    /// outgoing audio in place of the microphone — each key for `length`,
    /// with [`DIGIT_GAP`] of silence after it — whatever the negotiation
    /// settled on.
    ///
    /// For the far end that negotiated a telephone event and then listens
    /// only to the audio: an interactive voice system behind a gateway that
    /// drops the events. A digit written this way goes through every codec
    /// in this build and survives transcoding to G.711, which is where it is
    /// usually going; G.729 carries it less reliably, as that codec does any
    /// tone. Keys wait behind a digit going out as an event rather than sound
    /// under it.
    ///
    /// # Errors
    /// As [`MediaSession::dial`].
    pub fn dial_in_band(&mut self, keys: &str, length: Duration) -> Result<usize, MediaError> {
        let keys: Vec<char> = keys.chars().collect();
        if let Some(&key) = keys.iter().find(|key| Digit::from_char(**key).is_none()) {
            return Err(MediaError::UnknownDigit { key });
        }
        digit_length(length)?;
        self.signals.dial(&keys, length)
    }

    /// Whether a digit is going out or waiting to, as an event or in the
    /// audio.
    #[must_use]
    pub fn is_dialling(&self) -> bool {
        self.dialling.is_busy() || self.signals.is_dialling()
    }

    /// How many digits have not started yet.
    #[must_use]
    pub fn digits_waiting(&self) -> usize {
        self.dialling.waiting() + self.signals.digits_waiting()
    }

    /// Drop everything queued and stop the digit going out.
    ///
    /// What a call being taken away wants: the digit in flight gets no closing
    /// packet, because there is nowhere left to send one, and a digit
    /// sounding in the audio stops where it is.
    pub fn stop_dialling(&mut self) {
        self.dialling.clear();
        self.signals.stop_dialling();
    }

    /// When to listen for keypad digits in the far end's audio, from the
    /// next frame on.
    pub fn set_dtmf_detection(&mut self, detection: DtmfDetection) {
        self.signals.set_detection(detection);
    }

    /// When digits are listened for in the far end's audio.
    #[must_use]
    pub const fn dtmf_detection(&self) -> DtmfDetection {
        self.signals.detection()
    }
}

// -- call progress, and who answered -----------------------------------------

impl MediaSession {
    /// Listen for call progress and decide who answered, from the next
    /// frame on, or stop with `None`.
    ///
    /// A detection started afresh: tones already reported may be reported
    /// again, and a call already answered starts deciding who answered from
    /// the moment the engine next says it was.
    pub fn detect_progress(&mut self, detection: Option<ProgressDetection>) {
        self.signals.set_progress(detection);
    }

    /// Whether call progress is still being listened for: detection was
    /// asked for and has not come to its end — the call answered with no
    /// answering-machine detection, a verdict, a beep, or the time allowed
    /// for one.
    #[must_use]
    pub fn is_detecting_progress(&self) -> bool {
        self.signals.is_listening_for_progress()
    }

    /// The call was answered: who answered is decided from here.
    pub(crate) fn answered(&mut self) {
        self.signals.answered();
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
    /// Both directions, mixed, as WAVE at [`MediaSession::sample_rate`]:
    /// [`MediaSession::start_recording_with`] and the defaults of
    /// [`RecordingOptions`].
    ///
    /// # Errors
    /// As [`MediaSession::start_recording_with`].
    pub fn start_recording(&mut self, sink: Box<dyn RecordingSink>) -> Result<(), MediaError> {
        self.start_recording_with(sink, &RecordingOptions::default())
    }

    /// Start recording this call into `sink`, written as `options` say.
    ///
    /// It can be started and stopped as often as the person on the phone
    /// presses the button; each recording is a file of its own, because a
    /// sink that was written to twice would have two headers in it. It
    /// carries on through a re-negotiation onto another codec, at the rate
    /// the file started at, and it is finished whichever way it ends — see
    /// `crate::record`'s documentation for what a crash leaves.
    ///
    /// A [`ConsentTone`] set on the call starts beeping now.
    ///
    /// # Errors
    /// [`MediaError::AlreadyRecording`] when one is already running,
    /// [`MediaError::RecordingRate`] and [`MediaError::RecordingBitrate`]
    /// for options the format cannot be written with, and
    /// [`MediaError::Recording`] when the sink refused the header.
    pub fn start_recording_with(
        &mut self,
        sink: Box<dyn RecordingSink>,
        options: &RecordingOptions,
    ) -> Result<(), MediaError> {
        if self.recorder.is_some() {
            return Err(MediaError::AlreadyRecording);
        }
        let serial = self.draws.word();
        let recorder = Recorder::start(sink, options, self.sample_rate(), serial)?;
        self.recorder = Some(recorder);
        self.signals.recording_started();
        Ok(())
    }

    /// Stop the recording and finish the file.
    ///
    /// # Errors
    /// [`MediaError::NotRecording`], and [`MediaError::Recording`] when the
    /// file could not be finished — which leaves the audio up to the last
    /// checkpoint playable.
    pub fn stop_recording(&mut self) -> Result<(), MediaError> {
        let recorder = self.recorder.take().ok_or(MediaError::NotRecording)?;
        self.signals.recording_stopped();
        recorder.finish()
    }

    /// Whether a recording is running.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recorder.is_some()
    }

    /// How much audio the current recording has taken.
    #[must_use]
    pub fn recorded(&self) -> Option<Duration> {
        self.recorder.as_ref().map(Recorder::recorded)
    }

    /// Beep while this call is being recorded, from now on, or stop with
    /// `None`. A recording already running starts beeping at once.
    ///
    /// # Errors
    /// [`MediaError::ConsentTone`] for a tone that is not a beep, which
    /// changes nothing.
    pub fn set_consent_tone(&mut self, tone: Option<ConsentTone>) -> Result<(), MediaError> {
        if let Some(tone) = tone.as_ref() {
            tone.check()?;
        }
        self.signals.set_consent(tone, self.recorder.is_some());
        Ok(())
    }

    /// The consent tone this call beeps with while it is recorded.
    #[must_use]
    pub const fn consent_tone(&self) -> Option<ConsentTone> {
        self.signals.consent()
    }

    /// A recording that failed part-way through: the file is let go, an event
    /// says so, and the call is untouched.
    ///
    /// Letting it go finishes it as far as the sink allows — whatever
    /// refused the audio may refuse the header too, which leaves it as it
    /// stood at the last checkpoint.
    fn recording_stopped(&mut self, reason: MediaError) {
        self.signals.recording_stopped();
        let written = self
            .recorder
            .take()
            .map_or(Duration::ZERO, |recorder| recorder.recorded());
        self.events
            .push_back(MediaEvent::RecordingStopped { reason, written });
    }
}

/// The RTP stream a call opens on `plan`: its identity, what it takes in,
/// where it sends, and how its reports are sized. `discontinuous` is Annex
/// B's DTX, which marks talk spurts the way this end's own suppression does.
fn stream_config(
    plan: &MediaPlan,
    config: &MediaConfig,
    identity: &StreamIdentity,
    discontinuous: bool,
    frame_ticks: u32,
) -> StreamConfig {
    StreamConfig {
        ssrc: identity.ssrc,
        payload_type: plan.codec.payload(),
        accepted: accepted(plan),
        clock_rate: plan.codec.clock_rate(),
        sequence: identity.sequence,
        timestamp: identity.timestamp,
        remote: plan.remote,
        // a stream that stops sending in its pauses, whether this end's own
        // suppression or Annex B's DTX does it, marks each talk spurt's first
        // packet
        silence_suppression: config.silence_suppression || discontinuous,
        playout: BufferConfig::new(frame_ticks),
        cname: config
            .cname
            .clone()
            .unwrap_or_else(|| format!("sipral@{}", plan.local.ip())),
        rtcp_bandwidth: config.rtcp_bandwidth,
        voip_metrics_xr: plan.voip_metrics_xr,
    }
}

/// The payload types this stream will take in: what was agreed, the named
/// events if any were, comfort noise, and — for G.711 — the sibling law. The
/// first two under this end's own numbers for them, which are what the far
/// end sends with (RFC 3264 §5.1) when an answer renumbered them.
///
/// The last of those is not a courtesy. A peer that answers with one
/// companding law and sends the other is a real thing this stack has met, and
/// refusing the datagram at the RTP layer would show up as silence rather
/// than as the fault it is; [`fill`](MediaSession::fill) decodes it with the
/// law it actually names, which the two share a frame shape for (RFC 3551
/// table 4).
fn accepted(plan: &MediaPlan) -> PayloadTypes {
    let mut types = PayloadTypes::none().with(plan.codec_in).with(COMFORT_NOISE);
    if let Ok(codec) = Codec::of_plan(plan)
        && let Some((sibling, _)) = sibling_law(codec)
    {
        types = types.with(sibling);
    }
    match plan.dtmf_in {
        Some(payload) => types.with(payload),
        None => types,
    }
}

/// The other G.711 law's static payload type and the law itself, for a codec
/// that has one. `None` for G.722, G.729, L16 and Opus, whose frame shape a
/// G.711 payload does not fit.
const fn sibling_law(codec: Codec) -> Option<(u8, Law)> {
    match codec {
        Codec::Pcmu => Some((Law::A.payload_type(), Law::A)),
        Codec::Pcma => Some((Law::Mu.payload_type(), Law::Mu)),
        Codec::G722 | Codec::G729 | Codec::L16Narrowband | Codec::L16Wideband => None,
        #[cfg(feature = "opus")]
        Codec::Opus => None,
    }
}

/// `samples` of a frame of `frame_samples` as RTP ticks, when the frame is
/// `frame_ticks` long: the two differ for a codec whose clock is not its
/// sampling rate, and for G.729, the only codec that skips any, they are the
/// same.
fn ticks_in(samples: usize, frame_ticks: u32, frame_samples: usize) -> u32 {
    let samples = u64::try_from(samples).unwrap_or(u64::MAX);
    let whole = u64::try_from(frame_samples).unwrap_or(1).max(1);
    u32::try_from(samples.saturating_mul(u64::from(frame_ticks)) / whole).unwrap_or(frame_ticks)
}

/// Conceal one frame, whichever concealment this codec has.
fn conceal(coder: &mut Coder, room: &mut [i16]) -> Playback {
    if coder.conceal(room).is_err() {
        room.fill(0);
    }
    Playback::Concealed
}

/// Lengthen a pause by one frame, concealed as a loss would be but with the
/// stream's history left whole: nothing the far end sent is missing.
fn stretch(coder: &mut Coder, room: &mut [i16]) -> Playback {
    if coder.stretch(room).is_err() {
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
        // the top thirty-two bits over two to the thirty-two: exactly
        // representable, and short of one by construction
        f64::from(self.word()) / 4_294_967_296.0
    }

    /// One draw of thirty-two bits, the top half of the next output: also
    /// the numbers RFC 3550 §5.1 asks a second stream of the same call to
    /// start from.
    fn word(&mut self) -> u32 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        u32::try_from(z >> 32).unwrap_or(0)
    }
}
