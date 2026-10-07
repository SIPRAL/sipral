// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One call's audio: the RTP session, the codec, and the taps between them.
//!
//! A [`MediaPlan`] is what the negotiation agreed. This turns it into a stream that takes datagrams
//! and returns PCM frames, and takes PCM frames and returns datagrams.
//!
//! # What it does not own
//!
//! No socket and no device: the application moves datagrams and frames, so the same session serves
//! a softphone and a headless agent. No clock either: every entry point takes `now`, which lets an
//! hour of call run as a millisecond test. The wall clock for sender reports comes from
//! [`WallClock`].
//!
//! # Direction order
//!
//! Receive: datagram, jitter buffer, decode, play. Send: frame, encode, packetise. They meet twice.
//! Voice activity detection runs on the decoded far-end audio, because the jitter buffer may only
//! adjust its delay in the far end's pauses. The recorder sees both directions.

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

use crate::app_rate::{APPLICATION_RATES, ApplicationRate, frame_at};
use crate::capabilities::SrtpKeying;
use crate::clock::WallClock;
use crate::codec::{Codec, CodecCandidate};
use crate::dtmf::{self, DIGIT_GAP, Dialling, Digit, Due, LONGEST_DIGIT, SHORTEST_DIGIT};
use crate::echo::{Echo, MAX_RENDER_DELAY};
use crate::error::MediaError;
use crate::event::MediaEvent;
use crate::inband::{ConsentTone, DtmfDetection, ProgressDetection, Signals};
use crate::keying::{self, Opening, Shape};
use crate::pipeline::{self, Coder, Decoded, EXPECTED_LOSS_AT_START};
use crate::record::{Recorder, RecordingOptions, RecordingSink};
use crate::share::{Outbox, Ready};
use crate::stats::StreamStatistics;

/// The largest datagram this session builds; the bound on the two scratch buffers.
///
/// Not a path MTU. It fits 12 octets of header, the largest Opus frame (`opus::MAX_FRAME_BYTES`,
/// 1275) and a 10-octet SRTP tag. `RtpSession` refuses a short buffer before spending a sequence
/// number, so an overflow is a refused frame, not a truncated one.
const DATAGRAM: usize = 1_500;

/// Default silence before a stream counts as stalled. Ten seconds, so a peer doing silence
/// suppression does not trip it.
const DEFAULT_STALL: Duration = Duration::from_secs(10);

/// This session's RTCP bandwidth in octets per second: 5% of a narrowband call (RFC 3550 §6.2). The
/// §6.2 five-second minimum decides the actual cadence.
const RTCP_BANDWIDTH: f64 = 500.0;

/// A datagram to send on the media socket. Borrowed from the session's buffer to avoid allocating
/// 50 times a second.
#[derive(Clone, Copy, Debug)]
pub struct Datagram<'a> {
    /// Where to send it. With symmetric RTP this follows the far end's first packet.
    pub destination: SocketAddr,
    /// The octets.
    pub payload: &'a [u8],
    /// How it leaves. [`TurnTransport::Udp`](crate::TurnTransport::Udp) is a datagram from the
    /// media socket. With a relay over TCP or TLS ([`crate::Relays::over`]) the bytes go on the
    /// connection to the TURN server at `destination`, in order.
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
    /// A reception or sender report, folded into [`MediaSession::statistics`].
    Control,
    /// The far end is leaving (RFC 3550 §6.6). The call ends only when signalling says so.
    Goodbye,
    /// Control traffic that was not believed: wrong address or malformed compound packet.
    ControlRefused,
    /// A DTLS-SRTP handshake record (RFC 5764). Any reply is waiting in
    /// [`MediaSession::poll_transmit`].
    #[cfg(feature = "dtls")]
    Handshake,
    /// ICE traffic handled by the agent: a check, its response, a consent request or a keepalive
    /// (RFC 8445 §7, RFC 7675). Any reply is waiting in [`MediaSession::poll_transmit`].
    #[cfg(feature = "ice")]
    Check,
    /// Arrived on a secured stream that has no keys yet, typically because the peer finished its
    /// half of the handshake first.
    NotKeyed,
}

/// Where the frame that was just played came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Playback {
    /// A packet the far end sent.
    Packet,
    /// A lost packet, concealed, or for Opus rebuilt from the FEC copy in the next packet
    /// ([`StreamStatistics::fec_recovered`]).
    ///
    /// [`StreamStatistics::fec_recovered`]: crate::StreamStatistics::fec_recovered
    Concealed,
    /// Comfort noise from an RFC 3389 payload or a G.729 Annex B SID frame.
    ComfortNoise,
    /// Nothing was due: the buffer is filling or the far end stopped. Silence, or comfort noise if
    /// described, was written.
    Silence,
}

/// What a held party is sent instead of the captured frames ([`MediaConfig::held_audio`]). A held
/// stream stays `sendonly` (RFC 3264 §8.4), and only the application knows where its frames come
/// from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HeldAudio {
    /// Silence. For frames from a microphone, such as the C ABI device mode.
    #[default]
    Silence,
    /// The application's frames as they are: hold music, an announcement, a voice agent's speech.
    Captured,
}

/// How a session behaves, as opposed to what it negotiated.
#[derive(Clone, Debug, PartialEq)]
pub struct MediaConfig {
    /// The RTCP SDES canonical name (RFC 3550 §6.5.1). `None` builds one from the media address.
    pub cname: Option<String>,
    /// This session's share of the call's RTCP bandwidth, in octets a second.
    pub rtcp_bandwidth: f64,
    /// How long inbound audio may stop before [`MediaEvent::Stalled`]. In a G.729 Annex B pause,
    /// RTCP must stop too. `None` disables the watchdog.
    pub stall_after: Option<Duration>,
    /// Whether to stop sending during silence. Off by default: this stack sends no RFC 3389
    /// payload, so the far end cannot tell the gap from a dead stream.
    pub silence_suppression: bool,
    /// Loudspeaker-to-microphone delay on this device, used by [`MediaSession::attach_processor`]
    /// to align its reference.
    ///
    /// Zero by default; only the platform can measure it. Kept even without a processor. Values
    /// above [`MAX_RENDER_DELAY`](crate::MAX_RENDER_DELAY) are refused as wrong.
    pub render_delay: Duration,
    /// Which physical device the call's audio uses, as an opaque string the application chose.
    /// Carried, never read, so "which headset is call X on" (A2 in
    /// `docs/13-client-requirements.md`) is answered per call. `None` means not recorded, not the
    /// system default.
    pub device: Option<String>,
    /// When to listen for keypad digits in the far-end audio, besides RFC 4733 events.
    /// [`DtmfDetection::Auto`] by default: only on calls without a telephone event.
    pub dtmf_detection: DtmfDetection,
    /// Listen for call-progress tones on early media and decide who answered. `None` by default; it
    /// costs a detector per frame.
    pub progress: Option<ProgressDetection>,
    /// Beep while the call is recorded. `None` by default; whether to tell the parties is the
    /// application's call.
    pub consent_tone: Option<ConsentTone>,
    /// What a held party is sent. [`HeldAudio::Silence`] by default, since sending the microphone
    /// to a held party cannot be undone.
    pub held_audio: HeldAudio,
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
            held_audio: HeldAudio::Silence,
        }
    }
}

/// The three unpredictable starting numbers of RFC 3550 §5.1, plus the seed for report scheduling.
/// Passed in so runs are reproducible.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamIdentity {
    pub(crate) ssrc: u32,
    pub(crate) sequence: u16,
    pub(crate) timestamp: u32,
    pub(crate) seed: u64,
}

/// What the engine supplies when opening a session: starting numbers, wall clock, DTLS handshake,
/// ICE agent and the current instant.
// `Copy` only without `dtls` and `ice`: then it holds three numbers and an instant. With either
// feature it owns something and must move.
#[cfg_attr(not(any(feature = "dtls", feature = "ice")), derive(Clone, Copy))]
pub(crate) struct Start {
    pub(crate) identity: StreamIdentity,
    pub(crate) clock: WallClock,
    /// The DTLS-SRTP handshake that will key this stream, already started.
    #[cfg(feature = "dtls")]
    pub(crate) handshake: Option<crate::dtls::Handshake>,
    /// The ICE agent for this stream, gathered and given the peer's side.
    #[cfg(feature = "ice")]
    pub(crate) ice: Option<crate::ice::Ice>,
    /// Whether both descriptions allowed G.729 Annex B. Ignored for other codecs.
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
    /// Whether it sends encrypted and authenticates what it receives, now. False while waiting for
    /// the handshake.
    pub encrypted: bool,
    /// How keys were exchanged: SDP (RFC 4568) or DTLS (RFC 5764). `None` for an unencrypted
    /// stream.
    pub key_exchange: Option<SrtpKeying>,
    /// The transform in use, once there is one.
    pub suite: Option<Suite>,
    /// Whether the key exchange authenticated the far end. True for DTLS-SRTP after the handshake
    /// (fingerprint checked, RFC 8122 §5.1). False for SDES, which is only as authentic as the
    /// signalling; see [`MediaEngine::keys_in_clear`](crate::MediaEngine::keys_in_clear).
    pub authenticated: bool,
    /// Whether it agreed to encryption and is still waiting for keys.
    pub awaiting_keys: bool,
}

/// What this end's frames carry to the far end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carries {
    /// What the application captured, as the processor left it.
    Microphone,
    /// Silence or captured audio while this end holds the far end ([`MediaConfig::held_audio`]).
    Held,
}

/// One call's media.
#[derive(Debug)]
pub struct MediaSession {
    rtp: RtpSession,
    coder: Coder,
    plan: MediaPlan,
    /// Zero point of this session's RTP clock.
    origin: Instant,
    clock: WallClock,
    draws: Draws,
    frame_ms: u32,
    frame_ticks: u32,
    /// Reusable RTP and RTCP buffers. Separate so building a report cannot overwrite unsent audio.
    rtp_out: Vec<u8>,
    rtcp_out: Vec<u8>,
    payload: Vec<u8>,
    packets_sent: u64,
    octets_sent: u64,
    /// Frames rebuilt from FEC ([`Coder::recover`]).
    recovered: u64,
    /// The loss percentage the encoder is told to expect, and how many far-end reports it has
    /// followed ([`MediaSession::follow_far_loss`]).
    expected_loss: u32,
    far_reports: u64,
    last_inbound: Instant,
    /// When the last far-end report was accepted. Shows the far end is alive during an Annex B
    /// pause.
    last_control: Instant,
    stall_after: Option<Duration>,
    stalled: bool,
    /// The far end's last decoded frame activity; the jitter buffer adjusts only on silence.
    activity: Activity,
    inbound_voice: Vad,
    outbound_voice: Vad,
    /// Whether silence suppression was asked for and this end's detector does it (not when Annex B
    /// does).
    silence_suppression: bool,
    suppressing: bool,
    noise: Generator,
    recorder: Option<Recorder>,
    /// Digits, tones and the consent beep carried in the audio itself.
    signals: Signals,
    /// Reusable buffer for a captured frame with a digit or beep written in.
    shaped: Vec<i16>,
    /// What outgoing frames carry. While holding the far end (RFC 3264 §8.4) the stream still
    /// sends, as `held_audio` says.
    carries: Carries,
    held_audio: HeldAudio,
    /// Reusable silent frame sent instead of the microphone while holding.
    hush: Vec<i16>,
    /// Echo cancellation, gain control and noise suppression, if attached. `None` costs nothing.
    echo: Option<Echo>,
    render_delay: Duration,
    /// The digits this end still owes the far end, and the one going out.
    dialling: Dialling,
    /// Incoming digits, if a telephone event type was negotiated.
    heard: Option<EventReceiver>,
    events: Outbox,
    /// D5: what became of every codec this call's catalogue could have used.
    codec_candidates: Vec<CodecCandidate>,
    /// The transform the last DTLS handshake agreed. The signalling does not say (RFC 5764 §4.1.2);
    /// an SDES stream's is in its plan.
    handshake_suite: Option<Suite>,
    /// Which device this call uses, carried not interpreted ([`MediaConfig::device`]).
    device: Option<String>,
    /// The running DTLS-SRTP handshake. `None` once keyed or failed, and on non-DTLS calls.
    #[cfg(feature = "dtls")]
    dtls: Option<Dtls>,
    /// Reusable handshake record buffer, so [`MediaSession::poll_transmit`] can return a borrow.
    #[cfg(feature = "dtls")]
    dtls_out: Vec<u8>,

    /// The ICE agent, if the call uses ICE.
    ///
    /// `None` is the common case. Such calls behave exactly as without ICE, the fallback RFC 8445
    /// §2.6 asks for.
    #[cfg(feature = "ice")]
    ice: Option<crate::ice::Ice>,
    /// Reusable buffer for one message from the relay's TURN connection
    /// ([`MediaSession::receive_stream`]).
    #[cfg(feature = "ice")]
    stream_in: Vec<u8>,
    /// The real-time text stream (RFC 4103), if agreed; see [`crate::text`].
    text: Option<crate::text::TextStream>,
    /// Reusable text datagram buffer for [`MediaSession::poll_text`].
    text_out: Vec<u8>,
    /// Where audio is copied while a recording server records the call; see [`crate::siprec`].
    tap: Option<crate::siprec::Tap>,
    /// The application's frame rate, if different from the codec's; see [`crate::app_rate`].
    application: Option<ApplicationRate>,
}

/// Which session buffer a datagram was built in.
///
/// With ICE the bytes may be wrapped for the path, and the borrow is of the wrapping. Naming the
/// buffer avoids borrowing one field while the other is borrowed mutably.
#[cfg(feature = "ice")]
#[derive(Clone, Copy)]
enum Built {
    /// `rtp_out`: audio or a named event.
    Rtp,
    /// `rtcp_out`: a report or the BYE.
    Rtcp,
    /// `dtls_out`: a handshake record.
    #[cfg(feature = "dtls")]
    Handshake,
}

/// The DTLS handshake content type (RFC 6347 §4.1). Only this is accepted from an address not heard
/// from before; alerts are believed only from the latched address.
#[cfg(feature = "dtls")]
const HANDSHAKE_RECORD: u8 = 22;

/// A running handshake and the address its records are believed from.
#[cfg(feature = "dtls")]
#[derive(Debug)]
struct Dtls {
    handshake: crate::dtls::Handshake,
    /// A new association the far end started while the current one keys the call (RFC 6347 §4.2.8).
    /// Replaces it once keyed; dropped if it fails. See [`crate::dtls::Handshake::renewal`].
    next: Option<crate::dtls::Handshake>,
    /// Where the far end's records come from, once one has arrived.
    ///
    /// A separate latch from RTP's, because no RTP arrives during the handshake. Any fatal alert
    /// ends a DTLS connection, and before keys exist an alert cannot be authenticated. So the latch
    /// closes only on a handshake record, never an alert, and without ICE only from the signalled
    /// host ([`MediaSession::handshake_source_possible`]). An attacker then has to spoof the far
    /// end's address and beat its first flight.
    ///
    /// This narrows the race but does not close it; only ICE does (`docs/06-nat.md`). With ICE the
    /// selected pair moves the latch, and a renegotiation that moves the far end's address reopens
    /// it. Until RTP has a latch, this end's flights also go here; see
    /// [`MediaSession::poll_transmit`].
    peer: Option<SocketAddr>,
}

impl MediaSession {
    /// Open the media for a negotiated plan.
    ///
    /// `candidates` is the caller's D5 record of what became of each catalogue codec.
    ///
    /// # Errors
    ///
    /// [`MediaError::UnknownPayload`] when the answer named a format this build cannot decode,
    // the variant exists only with Opus, so the link must too
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
        // the first report's random factor comes from this call's seed (RFC 3550 §6.2, §6.3.2), or
        // calls with the same catalogue would all report at the same point
        let mut draws = Draws::new(identity.seed);
        // from here on everything sent is encrypted and everything received verified
        let rtp = match keying::opening(plan)? {
            Opening::Keyed(security) => RtpSession::protected(&stream, draws.unit(), security),
            // nothing is sent or believed until the handshake keys the stream; see
            // `RtpSession::awaiting`
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
            recovered: 0,
            expected_loss: EXPECTED_LOSS_AT_START,
            far_reports: 0,
            last_inbound: now,
            last_control: now,
            stall_after: config.stall_after,
            stalled: false,
            activity: Activity::Speech,
            inbound_voice: Vad::new(agreed.sample_rate()),
            outbound_voice: Vad::new(agreed.sample_rate()),
            // Annex B has its own detector; suppressing before it would hide half the conversation
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
            carries: Carries::Microphone,
            held_audio: config.held_audio,
            hush: Vec::new(),
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
            application: None,
        })
    }

    /// What the negotiation settled on.
    #[must_use]
    pub const fn codec(&self) -> Codec {
        self.coder.codec()
    }

    /// D5: what became of each codec in the catalogue. Exactly one is
    /// [`crate::CodecOutcome::Chosen`], the one in [`MediaSession::codec`].
    #[must_use]
    pub fn codec_candidates(&self) -> &[CodecCandidate] {
        &self.codec_candidates
    }

    /// The device this call uses, as the application last set it; see [`MediaConfig::device`].
    #[must_use]
    pub fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }

    /// Record which device this call moved to, or none. A Bluetooth headset reconnecting mid-call
    /// is the usual case.
    pub fn set_device(&mut self, device: Option<String>) {
        self.device = device;
    }

    /// Whether this call's audio is encrypted right now.
    ///
    /// True only when keys are in use. A call that asked for SDES and got a plain answer never gets
    /// a session. For DTLS-SRTP this stays false until the handshake finishes, even though the plan
    /// says keyed.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.rtp.is_protected()
    }

    /// How each stream is protected right now: the encryption report. One entry per stream, which
    /// here is the audio stream. A DTLS-SRTP entry turns encrypted at [`MediaEvent::Secured`]; SDES
    /// is encrypted from the start.
    #[must_use]
    pub fn encryption(&self) -> Vec<StreamEncryption> {
        let (key_exchange, suite, authenticated) = match &self.plan.keying {
            None => (None, None, false),
            Some(Keying::Sdes { local, .. }) => (
                Some(SrtpKeying::Sdes),
                Some(keying::transform(local.suite)),
                false,
            ),
            // the handshake rejects a certificate that does not match the fingerprint before
            // exporting keys, so a DTLS-keyed stream has an authenticated far end
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

    /// Whether the call agreed to encryption and still waits for the handshake. No audio flows
    /// meanwhile; it ends with [`MediaEvent::Secured`] or [`MediaEvent::Failed`].
    #[must_use]
    pub const fn is_awaiting_keys(&self) -> bool {
        self.rtp.awaiting_keys()
    }

    /// Sample rate of the frames passed in and out: the codec's, not the RTP clock's.
    #[must_use]
    pub fn sample_rate(&self) -> u32 {
        self.codec().sample_rate()
    }

    /// Samples per frame for [`MediaSession::playback`] and [`MediaSession::capture`].
    #[must_use]
    pub const fn frame_samples(&self) -> usize {
        self.coder.frame_samples()
    }

    /// Which way audio may flow, as seen from here.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.plan.direction
    }

    /// Whether this end should send: false while the far end holds this one or refuses to receive.
    #[must_use]
    pub const fn is_sending(&self) -> bool {
        matches!(self.direction(), Direction::SendRecv | Direction::SendOnly)
    }

    /// Whether this end is meant to be receiving.
    #[must_use]
    pub const fn is_receiving(&self) -> bool {
        matches!(self.direction(), Direction::SendRecv | Direction::RecvOnly)
    }

    /// Whether this end holds the far end, and sends [`MediaSession::held_audio`] instead of
    /// captured frames.
    #[must_use]
    pub const fn is_holding(&self) -> bool {
        matches!(self.carries, Carries::Held)
    }

    /// What a party this end holds is sent ([`MediaConfig::held_audio`]).
    #[must_use]
    pub const fn held_audio(&self) -> HeldAudio {
        self.held_audio
    }

    /// Send a held party `held` from now on, for this call only. Applies from the next frame.
    pub const fn set_held_audio(&mut self, held: HeldAudio) {
        self.held_audio = held;
    }

    /// Apply the hold the signalling settled: `true` when this end's hold is in force, `false`
    /// after resume.
    pub(crate) const fn set_holding(&mut self, holding: bool) {
        self.carries = if holding {
            Carries::Held
        } else {
            Carries::Microphone
        };
    }

    /// Where audio goes: the latched source address once packets arrive, the negotiated one before.
    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        self.rtp.destination()
    }

    /// Where RTCP goes, or `None` if RTCP was negotiated off.
    #[must_use]
    pub fn control_destination(&self) -> Option<SocketAddr> {
        match self.plan.rtcp {
            RtcpPlan::Muxed => Some(self.destination()),
            RtcpPlan::SeparatePort { remote, .. } => Some(remote),
            RtcpPlan::Off => None,
        }
    }

    /// The next stream event for the application. Drain until `None`.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<MediaEvent> {
        self.events.pop_front()
    }

    /// From now on, put `call` on the engine's ready list whenever this session queues an event.
    pub(crate) fn report_to(&mut self, call: sipral_ua::CallHandle, ready: Arc<Ready>) {
        self.events.report_to(call, ready);
    }

    /// The next event for the engine, and whether another follows.
    pub(crate) fn take_for_engine(&mut self) -> (Option<MediaEvent>, bool) {
        self.events.take_for_engine()
    }

    /// The loss, in per cent, the encoder is being told to expect.
    #[cfg(all(test, feature = "opus"))]
    pub(crate) const fn expected_loss_for_test(&self) -> u32 {
        self.expected_loss
    }

    /// Queue an event as the session itself would.
    #[cfg(test)]
    pub(crate) fn push_event_for_test(&mut self, event: MediaEvent) {
        self.events.push_back(event);
    }

    /// What the stream has cost so far.
    ///
    /// Cheap enough to poll at UI frame rate: nothing is allocated or scanned.
    #[must_use]
    pub fn statistics(&self, now: Instant) -> StreamStatistics {
        let feedback = self.rtp.feedback();
        StreamStatistics {
            codec: self.codec(),
            quality: self.rtp.quality(),
            round_trip: self.rtp.round_trip_time(),
            packets_sent: self.packets_sent,
            octets_sent: self.octets_sent,
            fec_recovered: self.recovered,
            silent_for: now.saturating_duration_since(self.last_inbound),
            voip_metrics: self.rtp.voip_metrics(self.codec().quality_model()),
            feedback: feedback.map(|(negotiated, _)| negotiated),
            feedback_counts: feedback.map(|(_, counts)| counts).unwrap_or_default(),
        }
    }

    /// The RTP/AVPF feedback this stream agreed (RFC 4585, RFC 5506), or `None` for plain RTP/AVP.
    #[must_use]
    pub fn feedback(&self) -> Option<sipral_rtp::avpf::Negotiated> {
        self.rtp.feedback().map(|(negotiated, _)| negotiated)
    }

    /// Switch this stream's RTCP to RTP/AVPF with what was agreed (RFC 4585, RFC 5506), or update
    /// it.
    pub(crate) fn use_feedback(&mut self, agreed: sipral_rtp::avpf::Negotiated, now: Instant) {
        let elapsed = self.elapsed(now);
        let draw = self.draws.unit();
        self.rtp.use_feedback(agreed, elapsed, draw);
    }

    /// The RFC 6035 quality report for `sipral_ua::UserAgent::send_quality_report`. `None` before
    /// the first RTP packet identified a source ([`sipral_rtp::RtpSession::voip_metrics`]).
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

    /// Start of the stream and `now` as Unix time, for RFC 6035 `Timestamps`. Uses the session's
    /// own wall clock, so a late report still dates the audio correctly.
    fn session_span(&self, now: Instant) -> (std::time::SystemTime, std::time::SystemTime) {
        let epoch = std::time::SystemTime::UNIX_EPOCH;
        (
            epoch + Duration::from_secs(self.clock.unix_at(self.origin)),
            epoch + Duration::from_secs(self.clock.unix_at(now)),
        )
    }
}

/// The RFC 6035 `RemoteMetrics` from the far end's RFC 3611 §4.7 block, leaving out "unavailable"
/// values (§4.7.4, §4.7.5).
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

impl MediaSession {
    /// Take a datagram off the media socket. RTP and RTCP are separated by the payload type rule of
    /// RFC 5761 §4, so a multiplexed socket needs no sorting.
    pub fn receive(&mut self, datagram: &mut [u8], from: SocketAddr, now: Instant) -> Arrival {
        // ICE first: a check is not RTP, RTCP or DTLS. Relay wrapping is removed here too
        #[cfg(feature = "ice")]
        let datagram = match self.receive_check(datagram, from, now) {
            Ok(payload) => payload,
            Err(arrival) => return arrival,
        };
        self.receive_payload(datagram, from, now)
    }

    /// Take bytes read off the TCP or TLS connection to the relay's TURN server
    /// ([`crate::Relays::over`]), in any chunking.
    ///
    /// Messages are reassembled (RFC 8656 §12.5) and handled like datagrams from the server in
    /// [`MediaSession::receive`]. Drain [`MediaSession::poll_transmit`] afterwards. `Ok(false)`
    /// when the relay does not use a connection.
    ///
    /// # Errors
    ///
    /// Something that is neither STUN nor a channel message, or a STUN length not in whole words. A
    /// stream cannot resync, so the relay is lost and the application should close the connection.
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

    /// Feed bytes from the TURN connection to the relay for [`MediaSession::next_stream_frame`],
    /// and return the server; `None` without a connection.
    #[cfg(feature = "ice")]
    pub(crate) fn push_stream(&mut self, bytes: &[u8]) -> Option<SocketAddr> {
        let ice = self.ice.as_mut()?;
        let server = ice.stream_server()?;
        ice.push_stream(bytes).then_some(server)
    }

    /// Copy the next whole message from the relay connection into `frame`; `Ok(false)` when none is
    /// waiting. The engine uses it to route a shared fork connection to each branch
    /// ([`MediaSession::take_stream_frame`]).
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

    /// Handle one whole message from the relay connection: peer data like a relayed datagram from
    /// the server, relay traffic by the relay.
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
        // relayed data comes from the server, over TCP as over UDP
        if let Taken::Data(range) = taken
            && let Some(payload) = frame.get_mut(range)
        {
            let _ = self.receive_payload(payload, server, now);
        }
    }

    /// The relay's TURN connection closed and the allocation went with it (RFC 8656 §3.2). A pair
    /// through it fails when consent runs out (RFC 7675 §5.1, [`MediaError::IcePathLost`]); other
    /// pairs continue.
    #[cfg(feature = "ice")]
    pub fn stream_closed(&mut self, now: Instant) {
        if let Some(ice) = self.ice.as_mut() {
            ice.stream_closed(now);
        }
        self.drain_ice(now);
    }

    /// The rest of [`MediaSession::receive`], after the agent removed relay wrapping and passed on
    /// what is not its own.
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
                // decrypted in place; the bytes before the tag are the packet the far end sent
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

    /// Let RTP's latch follow the far end until ICE selects a pair.
    ///
    /// Before selection the far end may send on any valid pair and switch as checks progress (RFC
    /// 8445 §12.1, §12.2). A fixed latch would drop its audio until selection, up to
    /// `nomination_wait`. So until then a packet from a new address moves the latch
    /// ([`RtpSession::set_following`]); after it holds, as [`MediaSession::drain_ice`] set it.
    /// Non-ICE calls keep symmetric RTP.
    #[cfg(feature = "ice")]
    fn follow_before_selection(&mut self) {
        let unselected = self
            .ice
            .as_ref()
            .is_some_and(|ice| ice.selected_pair().is_none());
        self.rtp.set_following(unselected);
    }

    /// Give the agent the datagram first and return the rest for the media path.
    ///
    /// `Err` means done: the agent consumed it or it came from an unknown source. `Ok` is
    /// application data, past the channel header on a relayed pair. Without ICE the datagram passes
    /// unchanged.
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
        // N9: refill the transaction id pool right before moving the agent. Without an id it cannot
        // answer a check and spins the caller's loop
        ice.top_up();
        let taken = ice.handle_datagram(from, datagram, now);
        self.drain_ice(now);
        match taken {
            Taken::Consumed => Err(Arrival::Check),
            Taken::Foreign => Err(Arrival::Dropped(Discard::ForeignAddress)),
            // `range` always indexes the input; written without unwrap because a panic on the media
            // path is worse than a dropped packet. The `ice` fuzz target asserts it
            Taken::Data(range) => datagram.get_mut(range).ok_or(Arrival::Check),
        }
    }

    /// Turn the agent's news into session events, in one place, so a lost path is reported once.
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
                // RFC 7675 §5: stop sending on the pair. The application can restart ICE
                // (`MediaEngine::restart_ice`) or hang up
                PathNews::Lost => lost = true,
            }
        }
        if let Some(pair) = selected {
            // the agent's checks supersede the RTP latch, which would otherwise cut audio on a
            // mid-call re-selection
            self.rtp.relocate(pair.remote);
            // same for the DTLS latch, or records from the newly chosen pair would be dropped
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
            // keep the agent: without it the session would send to the unchecked signalled address.
            // RFC 7675 §5.1 requires stopping, and the agent answers `NoConsent` to every route
            // request
            self.events
                .push_back(MediaEvent::Failed(MediaError::IcePathLost));
        }
        let _ = now;
    }

    /// Route a datagram on the ICE-chosen path, or the signalled one without ICE.
    ///
    /// N5: producers ask for the route before building anything, since a built frame or taken
    /// handshake record cannot be put back.
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
        // N9 again: `send` spends an id when a relayed pair needs a refresh
        ice.top_up();
        let (destination, transport, payload) = ice.send(data, now).ok()?;
        Some(Datagram {
            destination,
            payload,
            transport,
        })
    }

    /// Whether there is anywhere to send. Always `true` without ICE.
    #[cfg(feature = "ice")]
    fn has_path(&self) -> bool {
        self.ice.as_ref().is_none_or(|ice| ice.route().is_some())
    }

    /// Take a DTLS handshake record.
    ///
    /// Does not touch `last_inbound`: the stall watchdog measures audio, and a peer retransmitting
    /// into a call that never keys must still be reported. The handshake has its own timeout.
    #[cfg(feature = "dtls")]
    fn receive_handshake(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) -> Arrival {
        let possible = self.handshake_source_possible(from);
        let Some(dtls) = self.dtls.as_mut() else {
            // already keyed or failed: a late retransmission, or nobody's
            return Arrival::Dropped(Discard::ForeignAddress);
        };
        match dtls.peer {
            Some(latched) if latched != from => {
                return Arrival::Dropped(Discard::ForeignAddress);
            }
            Some(_) => {}
            // RFC 6347 §4.1: content type 22 is a handshake. Latch only on that, never on an
            // unauthenticated alert, and only from a plausible source (`handshake_source_possible`)
            None if possible && datagram.first() == Some(&HANDSHAKE_RECORD) => {
                dtls.peer = Some(from);
            }
            None => return Arrival::Dropped(Discard::ForeignAddress),
        }
        // RFC 6347 §4.2.8: a fresh ClientHello to an established server starts a new association.
        // Asterisk does this on hold. One at a time
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

    /// Reopen the DTLS latch after a renegotiation moved the far end's media address. No-op without
    /// a handshake.
    #[cfg_attr(not(feature = "dtls"), allow(clippy::unused_self))]
    fn forget_handshake_source(&mut self) {
        #[cfg(feature = "dtls")]
        if let Some(dtls) = self.dtls.as_mut() {
            dtls.peer = None;
        }
    }

    /// Whether a handshake record from `from` may close the DTLS latch.
    ///
    /// Nothing is authenticated before the fingerprint check. If any source could close the latch,
    /// one forged byte (22) from anyone who read the SDP would block the real handshake. So without
    /// ICE only the signalled host may close it, any port (for NATs that move ports), as
    /// `rtcp_origin_possible` in `sipral-rtp` does. Spoofing the far end's own address remains
    /// possible; only ICE closes that.
    ///
    /// With ICE the agent already drops unchecked sources and the chosen pair moves the latch.
    #[cfg(feature = "dtls")]
    fn handshake_source_possible(&self, from: SocketAddr) -> bool {
        #[cfg(feature = "ice")]
        if self.ice.is_some() {
            return true;
        }
        from.ip() == self.rtp.destination().ip()
    }

    /// Install the handshake's keys, or report why there are none. Done in one place so keys are
    /// installed exactly once.
    #[cfg(feature = "dtls")]
    fn settle_handshake(&mut self) {
        let Some(dtls) = self.dtls.as_mut() else {
            return;
        };
        let peer = dtls.peer;
        if let Some(next) = dtls.next.as_mut() {
            match next.take_outcome() {
                // RFC 6347 §4.2.8: after Finished, abandon the old association. Sending switches
                // now; receiving keeps the old context for packets in flight. New keys, so
                // restarting the index reuses nothing (RFC 3711 §9.1)
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
                // a failed renewal is dropped and the call stays on its association. Not reported:
                // anyone able to spoof the far end could trigger it. A real failure stops traffic
                // and the stall watchdog reports it
                Some(Err(_)) => dtls.next = None,
                None => {}
            }
            return;
        }
        match dtls.handshake.take_outcome() {
            Some(Ok(exported)) => {
                let suite = exported.suite;
                // `keyed` is false if the stream was already keyed, so the event is sent once
                let installed = self.rtp.keyed(exported.into_security());
                if installed {
                    self.handshake_suite = Some(suite);
                    self.events.push_back(MediaEvent::Secured { suite, peer });
                }
            }
            Some(Err(error)) => self.events.push_back(MediaEvent::Failed(error)),
            None => {}
        }
        // keep the handshake: a peer that lost our last flight retransmits, and must be answered
    }

    /// A datagram owed to the far end that is neither audio nor RTCP: ICE traffic or a DTLS record.
    ///
    /// Drain to `None` after every [`MediaSession::receive`] and at every
    /// [`MediaSession::poll_timeout`] deadline, or the ClientHello never leaves. `now` tells the
    /// agent traffic used the chosen pair, which lets it skip keepalives (RFC 8445 §11).
    #[cfg(any(feature = "dtls", feature = "ice"))]
    #[must_use]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Datagram<'_>> {
        // agent traffic first, ungated: checks are how a route comes to exist
        #[cfg(feature = "ice")]
        {
            let ready = match self.ice.as_mut() {
                Some(ice) => {
                    ice.top_up();
                    ice.take_probe()
                }
                None => None,
            };
            // return the address by value and borrow the bytes later, since the handshake below
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
            // N5: ask for the route before taking the record; a dropped flight is not rebuilt
            #[cfg(feature = "ice")]
            if !self.has_path() {
                return None;
            }
            // a new association's records first; the running one only answers retransmissions
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
            // while RTP has no latch (none before keys), use the DTLS latch; following only the
            // stream address broke peers whose port the path moved. Once RTP latched on an
            // authenticated packet, prefer it; before anything arrived, use the signalled address
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

    /// Take a datagram off the RTCP socket, when RTCP has its own port.
    pub fn receive_control(
        &mut self,
        datagram: &mut [u8],
        from: SocketAddr,
        now: Instant,
    ) -> Arrival {
        let elapsed = self.elapsed(now);
        let ntp = self.clock.at(now);
        match self.rtp.rtcp_receive(datagram, from, elapsed, ntp) {
            // a reduced-size packet (RFC 5506) counts as hearing from the far end
            RtcpReceived::Report | RtcpReceived::Feedback => {
                self.last_control = now;
                self.follow_far_loss();
                Arrival::Control
            }
            RtcpReceived::Goodbye { .. } => Arrival::Goodbye,
            RtcpReceived::NotKeyed => Arrival::NotKeyed,
            RtcpReceived::ForeignAddress
            | RtcpReceived::Malformed(_)
            | RtcpReceived::Insecure(_) => Arrival::ControlRefused,
        }
    }

    /// Tell the encoder the loss rate from the far end's latest report, once per report
    /// ([`pipeline::expected_loss`]). Opus sizes its FEC by it; other codecs just keep the figure.
    fn follow_far_loss(&mut self) {
        let Some((fraction_lost, reports)) = self.rtp.far_loss() else {
            return;
        };
        if reports == self.far_reports {
            return;
        }
        self.far_reports = reports;
        self.expected_loss = pipeline::expected_loss(self.expected_loss, fraction_lost);
        self.coder.expect_loss(self.expected_loss);
    }

    /// Take the frame due for the earpiece and say where it came from.
    ///
    /// `out` is filled to [`MediaSession::frame_samples`]; the rest is untouched. Every variant
    /// fills it, because a device given nothing replays its last buffer.
    pub fn playback(&mut self, out: &mut [i16]) -> Playback {
        let frame = self.frame_samples().min(out.len());
        let room = out.get_mut(..frame).unwrap_or_default();
        let played = self.fill(room);
        // detectors listen to the far end before anything of ours is mixed in
        self.signals.heard(room, &mut self.events);
        // the jitter buffer moves its delay only in the far end's pauses, judged on this decoded
        // frame
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
        // the local consent beep; the recording already has it
        self.signals.beep_locally(room);
        // this is what the loudspeaker plays, so the canceller's reference
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
        // a peer that answered one G.711 law and sends the other: decode with the law it names
        // (same frame shape, RFC 3551 table 4), unless our named events use that number
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
                    // a G.729 SID-only payload: codec comfort noise
                    Ok(Decoded::Noise(_)) => Playback::ComfortNoise,
                    // a corrupt payload is concealed like a loss
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
            // named events are not audio. The receiver collapses a digit's updates and three final
            // packets into one report
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
                        // the same press may also be in the audio
                        signals.received_event(digit, held);
                    }
                    events.push_back(event);
                }
                conceal(coder, room)
            }
            // Opus FEC: rebuild the lost frame from the next packet if it is already here
            Pull::Conceal => {
                let rebuilt = self
                    .rtp
                    .following()
                    .filter(|next| next.payload_type == payload_type)
                    .and_then(|next| coder.recover(next.payload, room));
                if rebuilt.is_some() {
                    self.recovered = self.recovered.saturating_add(1);
                    Playback::Concealed
                } else {
                    conceal(coder, room)
                }
            }
            // stretching a pause, or a G.729 Annex B pause where the decoder continues comfort
            // noise (B.4.5)
            Pull::Stretch => {
                if coder.pause(room).is_some() {
                    Playback::ComfortNoise
                } else {
                    stretch(coder, room)
                }
            }
            // nothing decoded or concealed is played, so stop the concealer history
            // (`Coder::interrupted`)
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

impl MediaSession {
    /// Exchange frames with the application at `hertz` (one of [`APPLICATION_RATES`]) whatever the
    /// codec rate, or `None` for the codec's rate, the default.
    ///
    /// Only [`MediaSession::playback_at_application_rate`] and
    /// [`MediaSession::capture_at_application_rate`] convert; codec, processor, recording and
    /// detectors keep the codec rate. Frame duration stays the same, so 20 ms of G.711 at 24 kHz is
    /// 480 samples. Setting the same rate again keeps the filter state.
    ///
    /// # Errors
    ///
    /// [`MediaError::ApplicationRate`] for an unsupported rate; the setting is unchanged.
    pub fn set_application_rate(&mut self, hertz: Option<u32>) -> Result<(), MediaError> {
        match hertz {
            None => self.application = None,
            Some(hertz) if !APPLICATION_RATES.contains(&hertz) => {
                return Err(MediaError::ApplicationRate { hertz });
            }
            Some(hertz) => {
                if self.application.as_ref().map(ApplicationRate::hertz) != Some(hertz) {
                    self.application = Some(ApplicationRate::new(hertz));
                }
            }
        }
        Ok(())
    }

    /// The application frame rate: the one set, or the codec's.
    #[must_use]
    pub fn application_rate(&self) -> u32 {
        self.application
            .as_ref()
            .map_or_else(|| self.sample_rate(), ApplicationRate::hertz)
    }

    /// Samples per frame at [`MediaSession::application_rate`].
    #[must_use]
    pub fn application_frame_samples(&self) -> usize {
        frame_at(
            self.frame_samples(),
            self.sample_rate(),
            self.application_rate(),
        )
    }

    /// [`MediaSession::playback`], at [`MediaSession::application_rate`]:
    /// `out` is filled to [`MediaSession::application_frame_samples`].
    pub fn playback_at_application_rate(&mut self, out: &mut [i16]) -> Playback {
        let Some(bridge) = self.bridge_now() else {
            return self.playback(out);
        };
        // taken out for the frame, as `capture` does
        let mut codec = core::mem::take(&mut bridge.codec);
        let wanted = bridge.application_frame().min(out.len());
        let played = self.playback(&mut codec);
        if let Some(bridge) = self.bridge_now() {
            bridge
                .heard
                .run(&codec, out.get_mut(..wanted).unwrap_or_default());
            bridge.codec = codec;
        }
        played
    }

    /// [`MediaSession::capture`], at [`MediaSession::application_rate`]:
    /// `samples` is one frame of [`MediaSession::application_frame_samples`].
    ///
    /// # Errors
    ///
    /// What [`MediaSession::capture`] answers.
    pub fn capture_at_application_rate(
        &mut self,
        samples: &[i16],
        now: Instant,
    ) -> Result<Option<Datagram<'_>>, MediaError> {
        if self.bridge_now().is_none() {
            return self.capture(samples, now);
        }
        #[cfg(feature = "ice")]
        if !self.has_path() {
            return Ok(None);
        }
        let Some(bridge) = self.bridge_now() else {
            return Ok(None);
        };
        let mut codec = core::mem::take(&mut bridge.codec);
        bridge.said.run(samples, &mut codec);
        let sent = self.encode_captured(&codec, now);
        if let Some(bridge) = self.bridge_now() {
            bridge.codec = codec;
        }
        let Some(length) = sent? else {
            return Ok(None);
        };
        Ok(self.captured_datagram(length, now))
    }

    /// The rate conversion filters for the current codec, or `None` if no conversion is needed.
    fn bridge_now(&mut self) -> Option<&mut crate::app_rate::Bridge> {
        let (rate, frame) = (self.sample_rate(), self.frame_samples());
        self.application
            .as_mut()
            .and_then(|application| application.bridge(rate, frame))
    }
}

impl MediaSession {
    /// Send one microphone frame.
    ///
    /// `Ok(None)` when deliberately not sent: on hold without sending, or suppressed as silence.
    /// While holding the far end (`sendonly`, RFC 3264 §8.4) silence goes out instead of the
    /// microphone. The RTP timestamp advances anyway, since it measures time (§5.1).
    ///
    /// # Errors
    // the variant exists only with Opus, so the link must too
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
        // N5: ask for the route before encoding. Discarding an encoded frame would corrupt Opus
        // state and move the timestamp for a packet never sent
        #[cfg(feature = "ice")]
        if !self.has_path() {
            return Ok(None);
        }
        let Some(length) = self.encode_captured(samples, now)? else {
            return Ok(None);
        };
        Ok(self.captured_datagram(length, now))
    }

    /// Encode one captured frame into `rtp_out` without returning it, so borrowed session buffers
    /// can be restored first.
    fn encode_captured(
        &mut self,
        samples: &[i16],
        now: Instant,
    ) -> Result<Option<usize>, MediaError> {
        // take the processor out so its output can be borrowed while the session is written
        let mut echo = self.echo.take();
        // likewise the digit/beep buffer
        let mut shaped = core::mem::take(&mut self.shaped);
        // and the hold silence frame
        let mut hush = core::mem::take(&mut self.hush);
        // stamp the media clock for sender reports (RFC 3550 §6.4.1)
        self.rtp.clock_at(self.elapsed(now));
        let sent = self.encode_frame(samples, echo.as_mut(), &mut shaped, &mut hush);
        self.hush = hush;
        self.shaped = shaped;
        self.echo = echo;
        sent
    }

    /// The packet left in `rtp_out`, addressed to the current audio destination: always without
    /// ICE, only on a chosen path with it.
    #[cfg_attr(not(feature = "ice"), allow(clippy::unnecessary_wraps))]
    fn captured_datagram(&mut self, length: usize, now: Instant) -> Option<Datagram<'_>> {
        let signalled = self.rtp.destination();
        #[cfg(feature = "ice")]
        {
            self.on_path(Built::Rtp, length, signalled, now)
        }
        #[cfg(not(feature = "ice"))]
        {
            let _ = now;
            Some(Datagram {
                destination: signalled,
                payload: self.rtp_out.get(..length).unwrap_or_default(),
            })
        }
    }

    /// Encode one frame into `rtp_out`, or `None` if deliberately not sent.
    fn encode_frame(
        &mut self,
        samples: &[i16],
        echo: Option<&mut Echo>,
        shaped: &mut Vec<i16>,
        hush: &mut Vec<i16>,
    ) -> Result<Option<usize>, MediaError> {
        // use the processed audio: suppression on raw capture would hear echo, and the recording
        // should be what was sent
        let samples = match echo {
            Some(echo) => echo.process(samples),
            None => samples,
        };
        // a held far end hears silence unless the application supplies hold audio. The processor
        // still ran on the mic to keep its room model
        let samples = if self.is_holding() && self.held_audio == HeldAudio::Silence {
            hush.clear();
            hush.resize(samples.len(), 0);
            hush.as_slice()
        } else {
            samples
        };
        // a digit or the consent beep, also kept in the recording
        let tone = self.signals.shape(
            samples,
            shaped,
            self.dialling.is_busy() && self.plan.dtmf.is_some(),
        );
        let samples = if tone { shaped.as_slice() } else { samples };
        // on hold either way, the recording gets silence for this side
        let on_hold = self.direction() != Direction::SendRecv;
        if let Some(error) = self.recorder.as_mut().and_then(|recorder| {
            if on_hold {
                recorder.captured_on_hold(samples.len()).err()
            } else {
                recorder.captured(samples).err()
            }
        }) {
            self.recording_stopped(error);
        }
        if !self.is_sending() {
            self.rtp.suppress(self.frame_ticks);
            return Ok(None);
        }
        if let Some(length) = self.dial_frame()? {
            return Ok(Some(length));
        }
        // a digit or beep is never a pause
        let silent = self.suppressing
            && !tone
            && self.outbound_voice.process(samples) == vad::Activity::Silence;
        if silent {
            self.rtp.suppress(self.frame_ticks);
            return Ok(None);
        }
        let sent = self.coder.encode(samples, &mut self.payload)?;
        let written = sent.octets;
        // G.729 Annex B: a frame DTX skipped still advances time, as does a payload starting after
        // a pause
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
            // drop frames while waiting for keys; queued ones would play too late
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

    /// One packet of the digit being dialled, or `None` when nothing is dialled.
    ///
    /// # Errors
    ///
    /// [`MediaError::PacketTooLong`], which a four-octet event payload cannot really cause.
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
            // abandon the digit rather than send it with a hole: RFC 4733 §2.5.1.4 would read two
            // digits
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
        // updates advance the clock; the two repeats of the end packet do not, so their frame
        // counts as silence
        if repeat {
            self.rtp.suppress(frame);
        }
        self.packets_sent = self.packets_sent.saturating_add(1);
        self.octets_sent = self
            .octets_sent
            .saturating_add(u64::try_from(EVENT_LEN).unwrap_or(0));
        Ok(Some(length))
    }

    /// The periodic RTCP report, when due.
    ///
    /// Call it when [`MediaSession::poll_timeout`] says and after each frame. Always `None` on a
    /// call without RTCP.
    #[must_use]
    pub fn poll_rtcp(&mut self, now: Instant) -> Option<Datagram<'_>> {
        // check before asking the schedule: `rtcp_due` reconsiders as it answers, and a refused
        // report would leave the deadline in the past and spin the caller
        if self.rtp.awaiting_keys() {
            return None;
        }
        // same reason
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
        // RTP/AVPF may use a slot for nothing: suppressed by `trr-int`, or an early one no longer
        // needed
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

    /// Send DTLS `close_notify` (RFC 6347 §4.2.8) before the socket closes, so the peer stops
    /// retransmitting. Records come out of [`MediaSession::poll_transmit`]; no answer is expected.
    #[cfg(feature = "dtls")]
    pub fn close_handshake(&mut self) {
        if let Some(dtls) = self.dtls.as_mut() {
            dtls.handshake.close();
            if let Some(next) = dtls.next.as_mut() {
                next.close();
            }
        }
    }

    /// Start a new association from this end, as a peer does on renegotiation (RFC 6347 §4.2.8), so
    /// tests can see the answer. `false` when not DTLS-keyed.
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

    /// This end's DTLS role, or `None` when not DTLS-keyed.
    ///
    /// Kept for the whole session, since every renegotiation must keep it (RFC 8842 §5.3).
    #[cfg(feature = "dtls")]
    pub(crate) fn dtls_role(&self) -> Option<sipral_dtls::Role> {
        self.dtls.as_ref().map(|dtls| dtls.handshake.role())
    }

    /// The RTCP BYE (RFC 3550 §6.6), sent once when the call ends so the far end stops waiting
    /// immediately.
    #[must_use]
    pub fn goodbye(&mut self, now: Instant) -> Option<Datagram<'_>> {
        // a digit whose end packets were all lost is still reported
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

impl MediaSession {
    /// When to call [`MediaSession::handle_timeout`], if nothing arrives
    /// first.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let rtcp = self
            .control_destination()
            .filter(|_| !self.rtp.awaiting_keys())
            // same reason as in `poll_rtcp`: a refused report would leave a past deadline and spin
            // the caller during checks
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

    /// Time has passed: decide whether the stream stalled. Due reports are taken with
    /// [`MediaSession::poll_rtcp`].
    pub fn handle_timeout(&mut self, now: Instant) {
        // first and always: the watchdog below can be off or skipped, and the handshake must still
        // retransmit and time out
        #[cfg(feature = "dtls")]
        if let Some(dtls) = self.dtls.as_mut() {
            dtls.handshake.on_timeout(now);
            if let Some(next) = dtls.next.as_mut() {
                next.on_timeout(now);
            }
            self.settle_handshake();
        }
        // likewise the ICE agent's timers
        #[cfg(feature = "ice")]
        if let Some(ice) = self.ice.as_mut() {
            ice.top_up();
            ice.handle_timeout(now);
            self.drain_ice(now);
        }
        // and text stream gaps
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

    /// When the far end was last heard: its last audio packet, or during an announced Annex B pause
    /// its last RTCP report if later.
    fn heard_from(&self) -> Instant {
        if self.coder.far_end_paused() {
            self.last_inbound.max(self.last_control)
        } else {
            self.last_inbound
        }
    }

    /// The ICE-selected path, local socket and peer (RFC 8445 §12.1). `None` before selection and
    /// without ICE; see [`MediaSession::destination`] then. Same data as
    /// [`MediaEvent::PathChosen`].
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn ice_path(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.ice
            .as_ref()?
            .selected_pair()
            .map(|pair| (pair.local, pair.remote))
    }

    /// ICE datagrams dropped because `sipral_nat::ice::TRANSMIT_CEILING` were already queued, or
    /// refusals dropped beyond `sipral_nat::ice::REFUSAL_CEILING`. Zero without ICE.
    ///
    /// Every check is answered, so an undrained queue would grow without bound; past the ceiling
    /// the new datagram is dropped and its transaction retransmits. Refusals stop at half, leaving
    /// room for real checks. A rising count means the application drains too rarely or the port is
    /// flooded.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn ice_transmits_dropped(&self) -> u64 {
        self.ice
            .as_ref()
            .map_or(0, crate::ice::Ice::transmits_dropped)
    }

    /// Release this call's relays when it ends: what to send and where
    /// ([`crate::ice::Ice::release`]).
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

    /// Whether this session runs an ICE agent.
    #[cfg(feature = "ice")]
    pub(crate) const fn runs_ice(&self) -> bool {
        self.ice.is_some()
    }

    /// Apply the ICE in the current descriptions to the agent: restart credentials and the peer's
    /// side ([`crate::ice::Ice::follow`]).
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

    /// Whether a datagram on a shared fork socket belongs to this session. With ICE, as
    /// [`sipral_nat::ice::IceAgent::claims`]; without, by the described address.
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

    /// D5's transport half: every pair checked and every relay held, with outcomes. Empty without
    /// ICE.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn path_candidates(&self) -> Vec<crate::PathCandidate> {
        self.ice
            .as_ref()
            .map(crate::ice::Ice::path_candidates)
            .unwrap_or_default()
    }

    /// Tell the agent the credentials of an offered or answered restart, or `None` if it will not
    /// happen ([`crate::ice::Ice::expect_restart`]).
    #[cfg(feature = "ice")]
    pub(crate) fn expect_ice_restart(&mut self, restarting: Option<&crate::ice::LocalIce>) {
        if let Some(ice) = self.ice.as_mut() {
            ice.expect_restart(restarting);
        }
    }

    /// Candidates the full agent still holds, for a restart offer ([`crate::ice::Ice::gathered`]).
    #[cfg(feature = "ice")]
    pub(crate) fn ice_candidates(&self) -> Option<Vec<sipral_nat::ice::Candidate>> {
        self.ice.as_ref().and_then(crate::ice::Ice::gathered)
    }

    /// Whether inbound audio is currently considered stopped.
    #[must_use]
    pub const fn is_stalled(&self) -> bool {
        self.stalled
    }

    /// Whether the next report is due, without the side effects of [`RtpSession::rtcp_due`], which
    /// reconsiders the schedule each time it is asked.
    #[must_use]
    pub fn rtcp_deadline_passed(&self, now: Instant) -> bool {
        !self.rtp.awaiting_keys()
            && self.has_path_or_none()
            && self.control_destination().is_some()
            && self.elapsed(now) >= self.rtp.next_rtcp_deadline()
    }

    /// Whether there is anywhere to send, callable without the `ice` feature. Always `true` without
    /// it.
    #[cfg_attr(not(feature = "ice"), allow(clippy::unused_self))]
    fn has_path_or_none(&self) -> bool {
        #[cfg(feature = "ice")]
        {
            self.has_path()
        }
        #[cfg(not(feature = "ice"))]
        true
    }

    /// Time since this session's origin, the unit `sipral-rtp` uses.
    fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.origin)
    }
}

impl MediaSession {
    /// Whether the call negotiated a real-time text stream.
    #[must_use]
    pub const fn has_text(&self) -> bool {
        self.text.is_some()
    }

    /// Queue text for the far end. Sent every 300 ms, within the far end's character rate, with two
    /// redundant generations if both agreed `red` (RFC 4103 §4, §5).
    ///
    /// CR LF, CR or LF become the T.140 LINE SEPARATOR; BACKSPACE (U+0008) erases the last
    /// character at the far end.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoText`] without a text stream, [`MediaError::TextBufferFull`] when the unsent
    /// buffer is full.
    pub fn send_text(&mut self, text: &str) -> Result<(), MediaError> {
        self.text.as_mut().ok_or(MediaError::NoText)?.send(text)
    }

    /// The next text datagram due, sent from the text socket. Call it at
    /// [`MediaSession::poll_timeout`] or with each audio frame.
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

    /// Take a datagram off the text socket. `false` if it is not this call's text. Typed text
    /// arrives as [`MediaEvent::TextReceived`].
    pub fn receive_text(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) -> bool {
        let Some(text) = self.text.as_mut() else {
            return false;
        };
        let taken = text.receive(datagram, from, now);
        self.report_text();
        taken
    }

    /// Apply what the descriptions agreed about text: open, move or close the stream.
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

impl MediaSession {
    /// The next copy of this call's audio for its recording server
    /// ([`crate::MediaEngine::record_to`]), with the socket to send from. Collect it every frame;
    /// copies older than a second are dropped.
    #[must_use]
    pub fn poll_recording(&mut self) -> Option<crate::siprec::RecordingDatagram<'_>> {
        self.tap.as_mut()?.poll()
    }

    /// Whether this call's audio is being copied to a recording server.
    #[must_use]
    pub const fn is_copied(&self) -> bool {
        self.tap.is_some()
    }

    /// Start or stop copying audio as `tap` says, returning the previous copies.
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

/// One direction's keying, as a re-negotiation left it.
struct Rekey {
    policy: Policy,
    master: Master,
    what: Rekeyed,
}

impl Rekey {
    /// What happens to one direction, given its old and new crypto lines.
    ///
    /// # Errors
    ///
    /// As [`keying::context`] for a line this build cannot open; [`MediaError::UnusableKeying`] for
    /// the same key under a suite with another cipher mode ([`keying::key_carries_over`]).
    fn between(was: &CryptoPolicy, now: &CryptoPolicy) -> Result<Option<Self>, MediaError> {
        // only key and salt matter: RFC 3711 §4.3.1 derives session keys from them and the index
        // alone
        let same_key = was
            .keys
            .iter()
            .map(|inline| &inline.keys)
            .eq(now.keys.iter().map(|inline| &inline.keys));
        if same_key && !keying::key_carries_over(was.suite, now.suite) {
            return Err(MediaError::UnusableKeying);
        }
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
    /// Apply a changed plan: hold, resume, or a moved far-end address.
    ///
    /// The codec cannot change here; [`MediaEngine`](crate::MediaEngine) uses
    /// [`MediaSession::reformat`] for that. `candidates` replaces the D5 record. Only a direction
    /// whose master key actually changed is re-keyed; restarting the index under a used key would
    /// break RFC 3711 §9.1.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoDtlsSrtp`] and [`MediaError::UnusableKeying`] for a line this build cannot
    /// open. Checked before any change, so the session is left as it was.
    pub(crate) fn adopt(
        &mut self,
        plan: &MediaPlan,
        candidates: Vec<CodecCandidate>,
        annex_b: bool,
        now: Instant,
    ) -> Result<(), MediaError> {
        let (fresh_local, fresh_remote) = Self::rekeyed(&self.plan, plan)?;
        // Annex B turned on or off: restart the encoder and follow with the marker bit and detector
        if self.coder.annex_b() != annex_b {
            self.coder.set_annex_b(annex_b);
            let discontinuous = self.coder.annex_b();
            self.rtp
                .set_silence_suppression(self.silence_suppression || discontinuous);
            self.suppressing = self.silence_suppression && !discontinuous;
        }
        if plan.remote != self.plan.remote {
            self.rtp.relocate(plan.remote);
            // a far end that moved has almost always restarted its stream
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
        // a re-offer can add or drop named events, which decides in-band detection by default
        self.signals
            .reformat(self.coder.codec().sample_rate(), plan.dtmf.is_some());
        // not receiving is not a stall
        if !self.is_receiving() {
            self.stalled = false;
        }
        // resuming: restart the watchdog's mark, or the hold's length reads as a stall before the
        // first packet can arrive
        if !was_receiving && self.is_receiving() {
            self.last_inbound = now;
        }
        Ok(())
    }

    /// Continue this session on the codec the negotiation moved to.
    ///
    /// Opening a new session would rewind the stream: RFC 3550 §5.1 reads reset counters as a new
    /// source, and under SRTP the index `2^16 · ROC + sequence` would reuse keystream.
    ///
    /// Kept: the stream and both SRTP contexts ([`RtpSession::reformat`]), totals, RTCP timeline
    /// and randomness, stall watchdog, render delay, device, pending events and digits, the
    /// recording and the processor. Rebuilt in the new codec's units: coder, frame length, payload
    /// buffer, voice detectors, comfort noise, event receiver and the D5 record.
    ///
    /// # Errors
    ///
    /// As [`MediaSession::open`], all checked before anything is written.
    pub(crate) fn reformat(
        &mut self,
        plan: &MediaPlan,
        frame_ms: u32,
        config: &MediaConfig,
        candidates: Vec<CodecCandidate>,
        annex_b: bool,
        now: Instant,
    ) -> Result<(), MediaError> {
        // open()'s order, all before the first assignment
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

        // reported loss belongs to the path, not the codec
        coder.expect_loss(self.expected_loss);
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
        // as in `adopt`: not receiving is not a stall
        if !self.is_receiving() {
            self.stalled = false;
        }
        Ok(())
    }

    /// Keep the recording in the same file. The file keeps its rate; only the conversion source
    /// changes. A sink refusal stops the recording as usual.
    fn retain_recording(&mut self, rate: u32) {
        if let Some(error) = self
            .recorder
            .as_mut()
            .and_then(|recorder| recorder.reformat(rate).err())
        {
            self.recording_stopped(error);
        }
    }

    /// Keep the application's processor, resized for the new codec. There is no way to ask for it
    /// again, and losing it would silently drop echo cancellation.
    fn retain_processor(&mut self, resized: bool, rate: u32, samples: usize) {
        let Some(echo) = self.echo.take() else {
            return;
        };
        let mut echo = if resized {
            Echo::new(echo.into_processor(), rate, samples, self.render_delay)
        } else {
            echo
        };
        // `Processor::reset` is documented for mid-call codec changes
        echo.reset();
        self.echo = Some(echo);
    }

    /// What a renegotiated plan does to each direction, or `None` for an unchanged one.
    ///
    /// Compared by key material alone, as the derivation is. A re-offer may keep the `inline:` key
    /// and change only its terms (`_80` to `_32` changes only the tag); re-keying then would
    /// restart the index under a used keystream (RFC 3711 §9.1).
    ///
    /// A change of shape (encryption on or off, SDES to DTLS) is refused ([`Shape`]).
    ///
    /// # Errors
    ///
    /// [`MediaError::KeyingChanged`] for a change of shape. [`MediaError::DtlsFingerprintChanged`]
    /// for a different certificate: RFC 5763 §6.6 asks for a new association, which this does not
    /// start, so the plan is refused and the session keeps its agreed keys.
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

impl MediaSession {
    /// Send one keypad key as an RFC 4733 named event.
    ///
    /// The event replaces the audio while it lasts (§2.1 shares sequence numbers and timestamps)
    /// and spans the following frames. Keys pressed during a digit are queued.
    ///
    /// For SIP INFO digits see [`UserAgent`](crate::UserAgent). Without a negotiated telephone
    /// event the digit is written into the audio as tones, as [`MediaSession::dial_in_band`] does.
    ///
    /// # Errors
    ///
    /// [`MediaError::DigitTooShort`], [`MediaError::DigitTooLong`], and
    /// [`MediaError::TooManyDigits`] when the queue is full.
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

    /// Send a dial string one key at a time. Nothing is queued unless every character is a key,
    /// since half an extension reaches somebody.
    ///
    /// # Errors
    ///
    /// [`MediaError::UnknownDigit`], plus whatever [`MediaSession::send_dtmf`] returns.
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

    /// Send a dial string as tones in the outgoing audio, replacing the microphone: each key for
    /// `length`, then [`DIGIT_GAP`] of silence, regardless of negotiation.
    ///
    /// For IVRs behind gateways that drop events. Survives transcoding to G.711; G.729 carries
    /// tones less reliably. Keys wait behind an event digit already going out.
    ///
    /// # Errors
    ///
    /// As [`MediaSession::dial`].
    pub fn dial_in_band(&mut self, keys: &str, length: Duration) -> Result<usize, MediaError> {
        let keys: Vec<char> = keys.chars().collect();
        if let Some(&key) = keys.iter().find(|key| Digit::from_char(**key).is_none()) {
            return Err(MediaError::UnknownDigit { key });
        }
        digit_length(length)?;
        self.signals.dial(&keys, length)
    }

    /// Whether a digit is going out or queued.
    #[must_use]
    pub fn is_dialling(&self) -> bool {
        self.dialling.is_busy() || self.signals.is_dialling()
    }

    /// How many digits have not started yet.
    #[must_use]
    pub fn digits_waiting(&self) -> usize {
        self.dialling.waiting() + self.signals.digits_waiting()
    }

    /// Drop the queue and stop the current digit, without an end packet.
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
    /// Listen for call progress and decide who answered, from the next frame, or stop with `None`.
    /// Restarts detection, so tones may be reported again.
    pub fn detect_progress(&mut self, detection: Option<ProgressDetection>) {
        self.signals.set_progress(detection);
    }

    /// Whether progress detection is still running.
    #[must_use]
    pub fn is_detecting_progress(&self) -> bool {
        self.signals.is_listening_for_progress()
    }

    /// The call was answered: who answered is decided from here.
    pub(crate) fn answered(&mut self) {
        self.signals.answered();
    }
}

/// Whether a digit length is one DTMF can send.
///
/// Uses `sipral_ua::dtmf::duration_ms`, the same bound as INFO (8.3.11); received INFO shares only
/// the ceiling (8.3.11-bis). A zero `Duration` is treated as the shortest non-zero length, since
/// zero means default there.
fn digit_length(length: Duration) -> Result<(), MediaError> {
    let millis = u32::try_from(length.as_millis()).unwrap_or(u32::MAX).max(1);
    match sipral_ua::dtmf::duration_ms(millis) {
        Ok(_) => Ok(()),
        Err(sipral_ua::DtmfError::ToneTooShort(_)) => Err(MediaError::DigitTooShort {
            asked: length,
            least: SHORTEST_DIGIT,
        }),
        // the only other refusal
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
    /// Run `processor` on every captured frame, against the far-end audio played
    /// [`MediaSession::render_delay`] earlier.
    ///
    /// Echo cancellation, gain control and noise suppression share one [`Processor`] because gain
    /// must run after cancellation. Nothing in this tree implements one: Apple's voice processing
    /// unit does it below the device crate, elsewhere it is supplied from outside.
    ///
    /// Replaces any previous processor and its learned echo path. Attaching mid-call costs a short
    /// re-adaptation.
    pub fn attach_processor(&mut self, processor: Box<dyn Processor>) {
        self.echo = Some(Echo::new(
            processor,
            self.sample_rate(),
            self.frame_samples(),
            self.render_delay,
        ));
    }

    /// Remove the processor and say whether there was one. Captured frames go straight to the
    /// encoder again.
    pub fn detach_processor(&mut self) -> bool {
        self.echo.take().is_some()
    }

    /// Whether a processor is attached.
    #[must_use]
    pub const fn has_processor(&self) -> bool {
        self.echo.is_some()
    }

    /// Forget the learned echo path, noise floor and gain, keeping the processor. Use after a
    /// device change. Returns whether there was a processor.
    pub fn reset_processor(&mut self) -> bool {
        self.echo.as_mut().map(Echo::reset).is_some()
    }

    /// Loudspeaker-to-microphone delay of this device.
    #[must_use]
    pub const fn render_delay(&self) -> Duration {
        self.render_delay
    }

    /// Set the delay once the platform has measured it. Changes with the device (Bluetooth adds
    /// tens of ms); an attached processor picks it up on the next frame.
    ///
    /// # Errors
    ///
    /// [`MediaError::RenderDelayTooLong`] above [`MAX_RENDER_DELAY`](crate::MAX_RENDER_DELAY); such
    /// a number is wrong, not a slow device.
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

impl MediaSession {
    /// Record this call into `sink`: both directions mixed, WAVE at [`MediaSession::sample_rate`],
    /// the [`RecordingOptions`] defaults.
    ///
    /// # Errors
    ///
    /// As [`MediaSession::start_recording_with`].
    pub fn start_recording(&mut self, sink: Box<dyn RecordingSink>) -> Result<(), MediaError> {
        self.start_recording_with(sink, &RecordingOptions::default())
    }

    /// Record this call into `sink` as `options` say.
    ///
    /// Each start makes a new file. Continues across codec changes at the file's rate, and is
    /// finished however it ends (see `crate::record`). A [`ConsentTone`] starts beeping now.
    ///
    /// # Errors
    ///
    /// [`MediaError::AlreadyRecording`], [`MediaError::RecordingRate`] and
    /// [`MediaError::RecordingBitrate`] for unsupported options, [`MediaError::Recording`] if the
    /// sink refused the header.
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
    ///
    /// [`MediaError::NotRecording`], and [`MediaError::Recording`] if finishing failed; audio up to
    /// the last checkpoint stays playable.
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

    /// Beep while recorded, or stop with `None`. A running recording starts beeping at once.
    ///
    /// # Errors
    ///
    /// [`MediaError::ConsentTone`] for a tone that is not a beep; nothing changes.
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

    /// A recording failed: release the file and raise an event; the call continues. The file is
    /// finished as far as the sink allows.
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

/// The RTP stream config for `plan`. `discontinuous` is Annex B DTX, which marks talk spurts like
/// suppression does.
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
        // any stream that pauses marks the first packet of each talk spurt
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

/// Payload types this stream accepts: the agreed codec, named events, comfort noise, and for G.711
/// the other law. The first two use our numbers, which the far end uses (RFC 3264 §5.1).
///
/// The other law is accepted because real peers answer one and send the other;
/// [`fill`](MediaSession::fill) decodes it with the law it names (RFC 3551 table 4).
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

/// The other G.711 law's static payload type and law. `None` for codecs without a sibling.
const fn sibling_law(codec: Codec) -> Option<(u8, Law)> {
    match codec {
        Codec::Pcmu => Some((Law::A.payload_type(), Law::A)),
        Codec::Pcma => Some((Law::Mu.payload_type(), Law::Mu)),
        Codec::G722 | Codec::G729 | Codec::L16Narrowband | Codec::L16Wideband => None,
        #[cfg(feature = "opus")]
        Codec::Opus => None,
    }
}

/// `samples` of a `frame_samples` frame as RTP ticks for a frame of `frame_ticks`.
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

/// Lengthen a pause by one frame, concealed like a loss but keeping the stream history.
fn stretch(coder: &mut Coder, room: &mut [i16]) -> Playback {
    if coder.stretch(room).is_err() {
        room.fill(0);
    }
    Playback::Concealed
}

/// Uniform draws on `[0, 1)` for RFC 3550 §6.3.1 report scheduling.
///
/// SplitMix64, seeded from above. Not a secret: predicting the report interval only reveals when
/// the next report is sent.
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
        // top 32 bits over 2^32: exact, and below one
        f64::from(self.word()) / 4_294_967_296.0
    }

    /// 32 bits, the top half of the next output. Also the starting numbers (RFC 3550 §5.1) for a
    /// second stream of the same call.
    fn word(&mut self) -> u32 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        u32::try_from(z >> 32).unwrap_or(0)
    }
}
