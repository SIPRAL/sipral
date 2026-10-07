// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A softphone stack in one crate: signalling joined to media.
//!
//! The crates below are kept apart on purpose: `sipral-ua` handles calls and knows no codec,
//! `sipral-rtp` carries payloads and sees no negotiation, `sipral-media` encodes audio and sees no
//! call. `docs/01-architecture.md` makes it a rule that **signalling and media never call each
//! other**, so the agent build can link no audio pipeline at all.
//!
//! This crate is the one place they meet. What crosses is a description: [`MediaCapabilities`]
//! into an offer and [`MediaPlan`] out of the answer, both from `sipral-core::sdp`, neither naming
//! a socket, device or codec implementation.
//!
//! # What is here
//!
//! - [`CodecCatalog`]: what this build contains and the offer order; [`Codec`] reports what a
//!   call agreed.
//! - [`MediaSession`]: one call's audio: RTP session, codec, concealment, recording tap, and the
//!   watchdog that notices when the far end goes quiet.
//! - [`MediaEngine`]: the join. It writes offers, reads answers, attaches a session when a call
//!   is answered and releases it when the call ends. It also hosts local mixing:
//!   [`MediaEngine::join`] pairs two calls into a three-way conference with this end,
//!   [`MediaEngine::mix`] drives one frame, and [`mix_two`] is the arithmetic (also used by
//!   `sipral-ffi`). [`LocalConference`] is the general case: any number of calls on any codecs and
//!   rates, with or without this end.
//! - [`SessionShare`]: one call's media for an audio thread while another thread runs signalling.
//!   Each session has its own lock, so neither waits longer than a frame.
//! - `redacted_call_record` and `redacted_recording`, behind the default `redaction` feature: a
//!   call's D1 record and a D2 recording with personal data removed, for reports leaving the
//!   organisation. Also behind it: [`Log`], the rate-limited, redacted engine log, and
//!   [`EngineState`], a bounded, redacted snapshot for crash reports.
//! - [`RtpPorts`]: the media port range (even RTP ports, the odd port above for RTCP), handed out
//!   by [`MediaEngine::reserve_rtp_port`] until none is free.
//! - Everything `sipral-ua` exports, re-exported, so an application needs only this crate.
//!
//! # What is deliberately not here
//!
//! **No sockets and no audio device.** The application owns both: it hands over datagrams and
//! passes PCM frames to whichever `sipral-io-*` it linked, so the stack embeds in any runtime. The
//! one exception is [`route_to`], which opens and connects a datagram socket, without sending, to
//! ask the OS which local address routes toward a peer; otherwise an application that forgot to
//! choose would advertise `127.0.0.1` ([`advertised_address`]).
//!
//! **No clock.** Every entry point takes `now: Instant`, so an hour of call runs as a millisecond
//! test. The wall clock for RTCP sender reports is set once, as a [`WallClock`].
//!
//! # The `opus` feature
//!
//! On by default. Opus is the only codec a build can leave out, because libopus is licensed
//! rather than written and the Opus patent pool prices IP phones per unit, so hardware products
//! must be able to ship without it. `LICENSING.md` gives this crate's two licences,
//! `THIRD-PARTY-NOTICES.md` the position on libopus, and `docs/05-media.md` who needs it out.
//!
//! Without it there is no `Codec::Opus` and no `MediaError::Codec`: [`Codec::ALL`] is G.722, both
//! G.711 laws and G.729, [`Capabilities::opus`] is false, and libopus is not linked. A codec order
//! naming `opus` is refused by name like any unknown codec, and a peer offering only Opus ends with
//! no common codec. The published docs are built with every feature on.
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

mod app_rate;
mod capabilities;
mod clock;
mod codec;
// measured on the default catalogue, whose INVITE offers Opus
#[cfg(all(test, feature = "opus"))]
mod compact_tests;
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
#[cfg(test)]
mod flows_tests;
#[cfg(feature = "headless")]
mod headless;
mod ice;
mod inband;
mod join;
mod keying;
mod local_conference;
#[cfg(test)]
mod local_conference_tests;
#[cfg(feature = "redaction")]
mod log;
#[cfg(feature = "stun")]
mod nat;
pub mod network_test;
mod payloads;
// the published INVITE sizes, measured on the shipped catalogue with Opus and ICE
#[cfg(all(test, feature = "opus", feature = "ice"))]
mod numbers_tests;
#[cfg(test)]
mod pin_tests;
mod pipeline;
mod ports;
#[cfg(test)]
mod realtime_tests;
mod record;
#[cfg(feature = "ice")]
mod relay;
mod route;
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

pub use app_rate::APPLICATION_RATES;
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
pub use keying::{AccountSrtp, SdesSignalling, SrtpPolicy};
pub use local_conference::{
    ConferenceChange, ConferenceDirection, ConferencePacket, Departure, Gain, LocalConference,
    LocalConferenceConfig, MAX_CONFERENCE_MEMBERS, Member, MemberFilter,
};
#[cfg(feature = "redaction")]
pub use log::{
    BURST, Log, LogLevel, LogRecord, LogSink, MIN_SALT, PER_SECOND, PseudonymKey, QUEUE_CEILING,
    SaltTooShort, Travel, derived_pseudonym_key, pseudonym_key,
};
#[cfg(feature = "stun")]
pub use nat::{DEFAULT_REFRESH, Keep, MappingEvent, MappingState, Mappings, StunDatagram};
pub use ports::{PortsExhausted, RtpPorts, RtpPortsError};
pub use record::{RecordingFormat, RecordingLayout, RecordingOptions, RecordingSink};
#[cfg(feature = "ice")]
pub use relay::{Relay, RelayDatagram, RelayEvent, Relays};
pub use route::{AdvertiseError, advertised_address, route_to};
pub use session::{
    Arrival, Datagram, HeldAudio, MediaConfig, MediaSession, Playback, StreamEncryption,
};
pub use share::{SessionGuard, SessionShare, SessionUnavailable};
/// Why a STUN transaction ended without an address, as
/// [`MappingEvent::Unanswered`] reports it.
#[cfg(feature = "stun")]
pub use sipral_nat::stun::Failure as StunFailure;
/// Why a TCP or TLS connection to a TURN server stopped carrying whole messages
/// ([`Relays::receive_stream`], [`MediaSession::receive_stream`]). The connection is then closed
/// and its relay lost.
#[cfg(feature = "ice")]
pub use sipral_nat::turn::FrameError as TurnStreamError;
/// How a relay reaches its TURN server ([`Relays::over`]), and so how its traffic leaves:
/// [`RelayDatagram::transport`], [`Datagram::transport`].
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

/// The negotiation's input and output types, re-exported so applications need not depend on
/// `sipral-core`.
pub use sipral_core::sdp::{
    Direction, Keying, MediaCapabilities, MediaPlan, NegotiatedCodec, RtcpPlan, SessionDescription,
    SrtpSupport,
};
/// Where echo cancellation, gain control and noise suppression attach. None is implemented in this
/// tree (`docs/05-media.md` says why); [`MediaSession::attach_processor`] runs an application's
/// implementation against the far-end audio.
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
/// Which end placed a call. Renamed because `sipral-core::sdp` also has a `Direction`, about
/// something else.
pub use sipral_ua::Direction as CallDirection;
/// What [`UserAgent::stop_recording`] hands back, for `redacted_recording`
/// to be named against.
pub use sipral_ua::Recording;
/// SIP over a WebSocket the stack opens on the application's connection
/// (RFC 7118): where it asks to go, set per far end with
/// [`UserAgent::set_websocket_target`].
pub use sipral_ua::WebSocketTarget;
/// RFC 3263 for an account that names its registrar or its outbound proxy
/// ([`Account::located`]): the lookups [`UaEvent::LookupWanted`] asks for, the
/// answers [`UserAgent::looked_up`] takes, and the procedure itself.
pub use sipral_ua::locate::{MAX_TTL as MAX_LOCATION_TTL, MIN_TTL as MIN_LOCATION_TTL};
/// The whole user agent, so a softphone depends only on this crate: accounts, registration, calls,
/// hold, transfer, and the calls that drive them.
pub use sipral_ua::{
    Account, AccountId, BearerChallenge, BearerError, CallEndReason, CallHandle, CallState,
    ChallengeRefusal, Compaction, Credentials, DatagramLimit, DtmfError, DtmfInfoForm,
    EndpointConfig, ForkPolicy, Hold, Incoming, Input, Link, MAX_UNSAFE_BODY_BYTES, MessageHandle,
    MessageSummary, Network, OutgoingCall, OutgoingExtras, Rate, RateError, ReceiveError, Recovery,
    Refusals, RegistrationFailure, RegistrationState, Replacing, STREAM_WAIT, Screen, Screening,
    StatusCode, Subscribe, SubscriptionEnd, SubscriptionHandle, SubscriptionState, Transmit,
    TransportId, TransportProtocol, UaError, UaEvent, Uri, UserAgent,
};
pub use sipral_ua::{
    AddressFamily, Answer, LocateError, Located, Locator, Naptr, Query, Record, RecordType, Srv,
};
/// Caller identity, answer mode, end reason and redirection: RFC 3325 asserted identity behind a
/// per-account trust gate, RFC 3323 privacy, RFC 5806 `Diversion`, RFC 7044 `History-Info`,
/// `verstat`, RFC 5373 answer modes, `Alert-Info`, RFC 3326 `Reason`, and 3xx redirects.
pub use sipral_ua::{
    AnswerMode, AnswerModeField, Answering, CallIdentity, CallerIdentity, Diversion, HistoryEntry,
    Party, Privacy, Reason, ReasonProtocol, Redirect, RemoteParty, Retarget, RingSource, Verstat,
};
/// This end's own verdict on who is calling (RFC 8224 §6.2), and what an
/// account asks its verification service to do with it.
pub use sipral_ua::{
    Attestation, CallerVerification, StirVerification, VerificationFailure, VerificationOutcome,
};
/// A PBX's self-signed TLS certificate, trusted by its SHA-256 fingerprint
/// ([`Account::tls_pin`]) and checked by the application's certificate
/// verifier with [`CertificatePin::check`].
pub use sipral_ua::{CertificatePin, PinError, PinMismatch, PinnedCertificate};
/// STIR/SHAKEN in calls: what an account signs with and what the agent verifies against
/// ([`UserAgent::set_stir`], [`Account::stir_signing`]), and the numbering plan
/// ([`UserAgent::set_number_plan`]).
#[cfg(feature = "stir")]
pub use sipral_ua::{DEFAULT_CERTIFICATE_WAIT, NumberPlan, StirConfig, StirSigning};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
