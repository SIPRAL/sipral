// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A softphone stack in one crate: signalling joined to media.
//!
//! Everything below this is deliberately unjoined. `sipral-ua` places and
//! answers calls and has never heard of a codec; `sipral-rtp` carries payloads
//! and has never seen a negotiation; `sipral-media` encodes audio and has
//! never seen a call. `docs/01-architecture.md` makes that a rule rather than
//! an accident — **signalling and media never call each other** — because the
//! agent build links no audio pipeline at all and a user agent that reached
//! into one could not be built without it.
//!
//! The rule leaves exactly one place for the two halves to meet, and this is
//! it. What crosses is a description: [`MediaCapabilities`] on the way into an
//! offer and [`MediaPlan`] on the way out of the answer, both of them written
//! down in `sipral-core::sdp` and neither of them naming a socket, a device or
//! a codec implementation.
//!
//! # What is here
//!
//! - [`CodecCatalog`] — what this build contains and in what order it is
//!   offered, and [`Codec`] to report back what a live call agreed.
//! - [`MediaSession`] — one call's audio: the RTP session, the codec, the
//!   concealment, the recording tap and the watchdog that notices when the far
//!   end goes quiet.
//! - [`MediaEngine`] — the join. It writes the offers, reads the answers,
//!   attaches a session to a call that is answered and lets it go when the
//!   call ends. It is also, unrelatedly, where a *local* join lives:
//!   [`MediaEngine::join`] pairs two of its own calls into a conference of
//!   three with this end, [`MediaEngine::mix`] drives a frame of it, and
//!   [`mix_two`] is the arithmetic either one or `sipral-ffi`'s own media
//!   handles can call it through.
//! - [`SessionShare`] — one call's media, for a thread that carries its audio
//!   while another runs signalling. Each session has its own lock, so neither
//!   thread waits on the other for longer than a frame.
//! - `redacted_call_record` and `redacted_recording`, behind the `redaction`
//!   feature (on by default) — a call's D1 record and a D2 recording with the
//!   personal data taken out, for a report that leaves the organisation.
//!   Beside them, behind the same feature: [`Log`], the engine's log through
//!   a sink the application installs, rate-limited and redacted; and
//!   [`EngineState`], one bounded, redacted snapshot of accounts, calls,
//!   media and counters for a crash report.
//! - [`RtpPorts`] — the range a deployment's media ports come from, even
//!   ports for RTP with the odd one above each kept for its RTCP, handed out
//!   by [`MediaEngine::reserve_rtp_port`] and refused once none is free.
//! - Everything `sipral-ua` exports, re-exported, so that an application
//!   depends on this crate and nothing else.
//!
//! # What is deliberately not here
//!
//! **No sockets and no audio device.** The application owns both, as it does
//! everywhere else in this tree: it reads a datagram and hands it over, and it
//! takes a frame of PCM and gives it to whichever `sipral-io-*` it linked. A
//! facade that opened a socket would be a facade that could not be embedded in
//! the runtimes this stack exists to be embedded in.
//!
//! **No clock.** `now: Instant` arrives at every entry point that needs one,
//! which is what makes an hour of a call a test that finishes in a
//! millisecond. The single number that cannot be derived from a monotonic
//! instant — the wall clock an RTCP sender report carries — is set once, as a
//! [`WallClock`].
//!
//! # Features
//!
//! One, `opus`, and it is on by default. It is the only part of this stack a
//! build can be without, because libopus is the only part that is licensed
//! rather than written: the patent pool over Opus names IP phones as a
//! category and prices them per unit, so a product shipping this stack
//! inside hardware has to be able to leave the codec out of the binary
//! rather than argue about it. `LICENSING.md` at the root of the repository
//! carries the two arms this crate is offered under and
//! `THIRD-PARTY-NOTICES.md` the position on libopus itself;
//! `docs/05-media.md` says which customer needs it out.
//!
//! With the feature off there is no `Codec::Opus` variant at all and no
//! `MediaError::Codec` for it to refuse anything with, so [`Codec::ALL`] is
//! G.722, the two G.711 laws and G.729, [`Capabilities::opus`] reads false,
//! and nothing links libopus. Nothing else is a special case: a codec order
//! naming `opus` is refused where it is set, by name, exactly as one naming
//! G.723 is, and a peer that offers nothing else ends as no common codec on
//! the ordinary path. The published documentation is built with every
//! feature on, so what is written here is the whole surface.
//!
//! # Driving it
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use std::time::Instant;
//! use sipral::{CodecCatalog, Event, MediaConfig, MediaEngine, WallClock};
//! use sipral::{EndpointConfig, OutgoingCall, UserAgent, Uri};
//!
//! # fn run(config: EndpointConfig, seed: [u8; 32], media_seed: [u8; 32],
//! #        account: sipral::AccountId, target: Uri, media: SocketAddr,
//! #        unix_seconds: u64) {
//! let now = Instant::now();
//! // two independent draws, never the same bytes: the first is written into
//! // a replay recording in clear, the second derives every SRTP key
//! let mut agent = UserAgent::new(config, seed).expect("timers that can be armed");
//! let mut engine = MediaEngine::new(
//!     CodecCatalog::new(),
//!     MediaConfig::default(),
//!     WallClock::from_unix(now, unix_seconds, 0),
//!     media_seed,
//! );
//!
//! // the offer is written from the catalogue, and names the address the
//! // application bound its own media socket to
//! let call = engine
//!     .place(&mut agent, account, OutgoingCall::new(target), media, now)
//!     .expect("the user agent took the call");
//!
//! // one drain, so that media is attached before the application hears that
//! // the call was answered
//! while let Some(event) = engine.poll_event(&mut agent, Instant::now()) {
//!     match event {
//!         Event::Signalling(_) => {}
//!         Event::Media { call, event } => {
//!             let _ = (call, event);
//!         }
//!         _ => {}
//!     }
//! }
//! # let _ = call;
//! # }
//! ```

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
// tests say what they mean; the no-panic discipline is for the library
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

mod capabilities;
mod clock;
mod codec;
mod counters;
#[cfg(feature = "redaction")]
mod diagnostics;
#[cfg(feature = "dtls")]
mod dtls;
mod dtmf;
mod echo;
mod engine;
mod error;
mod event;
mod feedback;
#[cfg(feature = "headless")]
mod headless;
mod ice;
mod inband;
mod join;
mod keying;
#[cfg(feature = "redaction")]
mod log;
#[cfg(feature = "stun")]
mod nat;
mod payloads;
mod pipeline;
mod ports;
mod record;
#[cfg(feature = "ice")]
mod relay;
mod session;
mod share;
mod siprec;
#[cfg(test)]
mod srtp_policy_tests;
#[cfg(feature = "redaction")]
mod state;
mod stats;
#[cfg(all(test, feature = "stir"))]
mod stir_tests;
#[cfg(test)]
mod tests;
mod text;

pub use capabilities::{Capabilities, SrtpKeying};
pub use clock::WallClock;
pub use codec::{Codec, CodecCandidate, CodecCatalog, CodecOutcome, DEFAULT_FRAME_MS};
pub use counters::{CallDispositionCounts, Counter, Counters, Gauge, RegistrationFailureCounts};
#[cfg(feature = "redaction")]
pub use diagnostics::{
    ExportError, RedactError, RedactionMode, Redactor, Replayed, redact_text, redacted_call_record,
    redacted_recording, replayed_capture,
};
#[cfg(feature = "dtls")]
pub use dtls::Identity;
pub use dtmf::{DEFAULT_DIGIT, DIGIT_GAP, Digit, LONGEST_DIGIT, SHORTEST_DIGIT};
pub use echo::MAX_RENDER_DELAY;
pub use engine::{CallMedia, MediaEngine};
pub use error::MediaError;
pub use event::{DigitSource, Event, MediaEvent};
#[cfg(feature = "headless")]
pub use headless::{
    HeadlessMediaError, HeadlessSession, call_state_of, dtmf_received_of, send_digit,
};
pub use ice::IcePolicy;
#[cfg(feature = "ice")]
pub use ice::{CandidateKind, PathCandidate, PathKind, PathOutcome};
pub use inband::{AmdConfig, AmdReason, AmdVerdict, BeepConfig, CallProgress, ConsentTone};
pub use inband::{DtmfDetection, IN_BAND_DIGIT_HOLD, ProgressConfig, ProgressDetection};
pub use inband::{ProgressTone, ToneRegion};
pub use join::{MixOutcome, mix_two};
pub use keying::{AccountSrtp, SrtpPolicy};
#[cfg(feature = "redaction")]
pub use log::{BURST, Log, LogLevel, LogRecord, LogSink, PER_SECOND, QUEUE_CEILING, Travel};
#[cfg(feature = "stun")]
pub use nat::{DEFAULT_REFRESH, Keep, MappingEvent, MappingState, Mappings, StunDatagram};
pub use ports::{PortsExhausted, RtpPorts, RtpPortsError};
pub use record::{RecordingFormat, RecordingLayout, RecordingOptions, RecordingSink};
#[cfg(feature = "ice")]
pub use relay::{Relay, RelayDatagram, RelayEvent, Relays};
pub use session::{Arrival, Datagram, MediaConfig, MediaSession, Playback, StreamEncryption};
pub use share::{SessionGuard, SessionShare, SessionUnavailable};
/// Why a STUN transaction ended without an address, as
/// [`MappingEvent::Unanswered`] reports it.
#[cfg(feature = "stun")]
pub use sipral_nat::stun::Failure as StunFailure;
/// Why the TCP or TLS connection to a TURN server stopped carrying whole
/// messages, as [`Relays::receive_stream`] and
/// [`MediaSession::receive_stream`] report it: the connection is closed after
/// it, and the relay on it is lost.
#[cfg(feature = "ice")]
pub use sipral_nat::turn::FrameError as TurnStreamError;
/// How a relay reaches its TURN server, [`Relays::over`], and so how what is
/// written for the server leaves: [`RelayDatagram::transport`],
/// [`Datagram::transport`].
#[cfg(feature = "ice")]
pub use sipral_nat::turn::Transport as TurnTransport;
/// Why a TURN server gave no relay, or took one back, as
/// [`RelayEvent::Failed`] reports it.
#[cfg(feature = "ice")]
pub use sipral_nat::turn::TurnError as TurnFailure;
pub use siprec::{RecordTo, RecordingDatagram};
#[cfg(feature = "redaction")]
pub use state::{AccountState, CallSnapshot, EngineState, LISTED, MediaState, StreamState};
pub use stats::StreamStatistics;

/// What the negotiation produces and consumes, from the layer that owns the
/// offer/answer model. These two are the seam this crate exists to carry, so
/// an application that reads a plan or builds a capability set does not have
/// to name `sipral-core` to do it.
pub use sipral_core::sdp::{
    Direction, Keying, MediaCapabilities, MediaPlan, NegotiatedCodec, RtcpPlan, SessionDescription,
    SrtpSupport,
};
/// Where echo cancellation, gain control and noise suppression attach. None
/// of the three is implemented in this tree — `docs/05-media.md` says why —
/// so an application that has one wires it in through this trait, and
/// [`MediaSession::attach_processor`] runs it against the far-end audio this
/// crate kept for it.
pub use sipral_media::processor::{NoProcessor, Processor};
/// What the de-jitter buffer counted, which is most of what a stream statistic
/// is.
pub use sipral_rtp::avpf::{FeedbackCounts, Negotiated as FeedbackAgreed};
pub use sipral_rtp::srtp::Suite as SrtpSuite;
pub use sipral_rtp::{Discard, Quality, UNAVAILABLE, VoipMetricsBlock};
/// The STIR/SHAKEN crate itself: [`stir::Signer`], [`stir::TrustAnchors`],
/// [`stir::Tn`], and the PASSporT underneath, for an application that signs
/// or verifies outside a call as well.
#[cfg(feature = "stir")]
pub use sipral_stir as stir;
/// Which end placed a call, renamed on the way through: `sipral-ua` and
/// `sipral-core::sdp` both have a `Direction` and they are about different
/// things, so the one an application meets less often gets the longer name.
pub use sipral_ua::Direction as CallDirection;
/// What [`UserAgent::stop_recording`] hands back, for `redacted_recording`
/// to be named against.
pub use sipral_ua::Recording;
/// The whole user agent, so that a softphone depends on this crate and nothing
/// else: accounts, registration, calls, hold, transfer, and the five calls
/// that drive them.
pub use sipral_ua::{
    Account, AccountId, CallEndReason, CallHandle, CallState, Credentials, DtmfError, DtmfInfoForm,
    EndpointConfig, ForkPolicy, Hold, Incoming, Input, Link, MAX_UNSAFE_BODY_BYTES, MessageHandle,
    MessageSummary, Network, OutgoingCall, OutgoingExtras, Rate, RateError, ReceiveError, Recovery,
    Refusals, RegistrationFailure, RegistrationState, Replacing, Screen, Screening, StatusCode,
    Subscribe, SubscriptionEnd, SubscriptionHandle, SubscriptionState, Transmit, TransportId,
    TransportProtocol, UaError, UaEvent, Uri, UserAgent,
};
/// Who is on a call and how it asked to be answered, why it ended, and where
/// to send it instead: RFC 3325's asserted identity behind a per-account
/// trust gate, RFC 3323's privacy, RFC 5806's `Diversion`, RFC 7044's
/// `History-Info`, `verstat`, RFC 5373's answer modes, `Alert-Info`, RFC
/// 3326's `Reason`, and a 3xx redirect.
pub use sipral_ua::{
    AnswerMode, AnswerModeField, Answering, CallIdentity, CallerIdentity, Diversion, HistoryEntry,
    Party, Privacy, Reason, ReasonProtocol, Redirect, RemoteParty, Retarget, RingSource, Verstat,
};
/// This end's own verdict on who is calling (RFC 8224 §6.2), and what an
/// account asks its verification service to do with it.
pub use sipral_ua::{
    Attestation, CallerVerification, StirVerification, VerificationFailure, VerificationOutcome,
};
/// STIR/SHAKEN in calls: what an account signs with, and what the agent
/// verifies against — [`UserAgent::set_stir`], [`Account::stir_signing`].
#[cfg(feature = "stir")]
pub use sipral_ua::{DEFAULT_CERTIFICATE_WAIT, StirConfig, StirSigning};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
