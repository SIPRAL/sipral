// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! User agent layer.
//!
//! Registration and refresh, calls, hold, transfer, out-of-dialog REFER
//! ([`referral`]), SUBSCRIBE/NOTIFY for message waiting and busy lamp field,
//! screening of incoming INVITEs, and sleep/wake handling: push-announced
//! calls, registration snapshots, and a lifecycle machine.
//!
//! Sans-I/O, like the core: policy and sequencing over [`sipral_core`], driven
//! by the same five calls as the endpoint. A year of refreshes is a test that
//! runs in a millisecond.
//!
//! This layer holds what the core refuses to decide: passwords (answering a
//! challenge twice locks an account), refresh intervals the RFC does not give,
//! and randomised back-off so a thousand phones do not return in the same
//! second.

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

mod account;
mod admission;
pub mod advertise;
mod agent;
mod announce;
mod answering;
#[cfg(test)]
mod audit_tests;
#[cfg(test)]
mod auth_scope_tests;
#[cfg(test)]
mod bridging_tests;
mod call;
mod calls;
/// The conference event package (RFC 4575) and the merged picture kept from
/// it. Its own path, since `User`, `Endpoint` and `Media` are its vocabulary.
pub mod conference;
mod contact;
mod dialoginfo;
/// Digit validation and the two ad hoc INFO `Content-Type`s. Its own path so
/// bindings and fuzz targets can name the bounds and the parser; most
/// applications only need [`UserAgent::send_dtmf_info`].
pub mod dtmf;
mod error;
mod event;
mod flow;
mod headers;
mod identity;
/// Keeping a UDP registration reachable through a NAT, and the interval
/// bounds a binding checks against.
pub mod keepalive;
mod lifecycle;
pub mod locate;
mod message;
mod mwi;
#[cfg(test)]
mod oauth_tests;
mod options;
mod oversize;
mod parked;
/// Presence documents (RFC 3863) with RFC 4480 activities. Its own path,
/// since `Tuple`, `Note` and `Contact` are PIDF's vocabulary.
pub mod presence;
mod probe;
mod publish;
mod publishing;
mod quality_report;
mod reason;
mod redirect;
pub mod referral;
#[cfg(test)]
mod referral_tests;
mod registration;
mod reliable;
mod renegotiate;
#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod rfc4475_tests;
#[cfg(feature = "reference-loop")]
mod runtime;
mod screening;
mod session;
#[cfg(test)]
mod signalling_tests;
/// SIPREC metadata (RFC 7865, RFC 7866) and the recording-session INVITE.
/// Its own path, since it has its own `Session` and `Stream`.
pub mod siprec;
#[cfg(feature = "stir")]
mod stir;
#[cfg(all(test, feature = "stir"))]
mod stir_tests;
mod subscription;
#[cfg(test)]
mod tests;
mod timers;
mod transfer;
mod verification;
pub mod websocket;
#[cfg(test)]
mod websocket_tests;

pub use account::{Account, AccountId, Push};
pub use agent::UserAgent;
pub use announce::{Announced, Announcement, AnnouncementId};
pub use answering::{AnswerMode, AnswerModeField, Answering, RingSource};
pub use call::{
    CallEndReason, CallHandle, CallIdentity, CallState, Direction, ForkPolicy, OutgoingCall,
    OutgoingExtras,
};
pub use conference::{Conference, ConferenceInfo, ConferenceInfoError, ConferenceUpdate};
pub use dialoginfo::{
    DialogEnded, DialogInfo, DialogInfoError, DialogInfoTable, DialogPhase, Initiated, Participant,
    WatchedDialog,
};
pub use dtmf::{DtmfError, DtmfInfo, DtmfInfoForm, InfoRefusal};
pub use error::UaError;
pub use event::{ChallengeRefusal, RegistrationFailure, RegistrationState, UaEvent};
pub use headers::{HeaderRefused, HeadersFor};
pub use identity::{
    CallerIdentity, Diversion, HistoryEntry, Party, Privacy, RemoteParty, Retarget, Verstat,
};
pub use lifecycle::{
    Idle, LifecycleState, Link, Network, Recovery, RecoveryFailure, Rung, Suspending,
};
pub use message::{MAX_UNSAFE_BODY_BYTES, MessageHandle};
pub use mwi::{MessageClass, MessageSummary, MessageSummaryError};
pub use oversize::STREAM_WAIT;
pub use presence::{Presence, PresenceError};
pub use probe::{ProbeHandle, ProbeOutcome};
pub use publish::{
    Publication, PublishError, PublishEvent, PublishFailure, PublishKind, PublishRequest,
};
pub use publishing::{PRESENCE_EVENT, PublicationHandle, Publish};
pub use quality_report::{QualityReportMetrics, RemoteQualityMetrics};
pub use reason::{Reason, ReasonProtocol};
pub use redirect::Redirect;
pub use registration::{PushEcho, RegistrarInfo, SnapshotError};
#[cfg(feature = "reference-loop")]
pub use runtime::{Control, Handler, Runtime};
pub use screening::{Incoming, Rate, RateError, Refusals, Replacing, Screen, Screening};
pub use session::Hold;
#[cfg(feature = "stir")]
pub use stir::{DEFAULT_CERTIFICATE_WAIT, NumberPlan, StirConfig, StirSigning};
pub use subscription::{
    DEFAULT_EXPIRES, Subscribe, SubscriptionEnd, SubscriptionHandle, SubscriptionState,
};
pub use verification::{
    Attestation, CallerVerification, StirVerification, VerificationFailure, VerificationOutcome,
};
pub use websocket::WebSocketTarget;

/// Re-exported so an application need not name `sipral-core`.
pub use sipral_core::auth::Credentials;
/// What [`UaEvent::TokenRequired`] carries (RFC 8898).
pub use sipral_core::auth::{BearerChallenge, BearerError};
/// RFC 3263 lookups for [`UaEvent::LookupWanted`] and
/// [`UserAgent::looked_up`], and the procedure itself.
pub use sipral_core::endpoint::{
    AddressFamily, Answer, LocateError, Located, Locator, Naptr, Query, Record, RecordType, Srv,
};
pub use sipral_core::endpoint::{
    Compaction, DatagramLimit, EndpointConfig, Input, ReceiveError, Transmit, TransportId,
    TransportProtocol,
};
pub use sipral_core::msg::{StatusCode, Uri};
/// A TLS server certificate trusted by its SHA-256 fingerprint, per account
/// ([`Account::tls_pin`]).
pub use sipral_core::pin::{CertificatePin, PinError, PinMismatch, PinnedCertificate};
/// Session record and replay, as for the endpoint (`docs/18-replay.md`).
pub use sipral_core::replay::{Driven, Played, Recorder, Recording, Replay};
