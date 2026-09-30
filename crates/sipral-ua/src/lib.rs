// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! User agent layer.
//!
//! Registration with refresh, outgoing and incoming calls, hold and resume,
//! blind and attended transfer — and, where the application allows it, a
//! REFER from outside any call ([`referral`]) — the SUBSCRIBE/NOTIFY
//! subscriptions behind message waiting and busy lamp field, the policy that
//! decides whether an INVITE off the internet is ever heard at all, and what
//! all of that stops being worth when the machine underneath it goes to
//! sleep: a call announced by a push before there is a transport, a
//! registration that can be written down and read back, and a lifecycle that
//! says which of the two is which.
//!
//! Also sans-I/O: this is policy and sequencing over [`sipral_core`], not
//! transport. The five calls are the endpoint's five calls, so the same event
//! loop drives either, and a year of registration refreshes is a test that
//! finishes in a millisecond.
//!
//! What lives here is everything the core deliberately refuses to decide.
//! Answering a challenge needs a password and answering it twice locks an
//! account. Refreshing a binding needs a number the RFC does not give. Backing
//! off after an outage needs a random interval, or a thousand phones come back
//! in the same second. None of those are protocol, and all of them are the
//! difference between a stack that parses SIP and a phone that stays
//! reachable.

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
mod agent;
mod announce;
mod answering;
#[cfg(test)]
mod audit_tests;
mod call;
mod calls;
/// The conference event package (RFC 4575): the document a focus notifies,
/// and the merged picture of a conference kept from it — under its own path
/// because its element types (`User`, `Endpoint`, `Media`) are the
/// package's vocabulary, not this crate's.
pub mod conference;
mod contact;
mod dialoginfo;
/// Validation shared by every way a digit crosses this stack's boundary, and
/// the two ad hoc `Content-Type`s an INFO carries one in — grouped under its
/// own path rather than flattened like the rest of this crate's surface,
/// because [`UserAgent::send_dtmf_info`] and the incoming parser are the only
/// callers most applications ever need and the bound and the parser are what
/// a binding or a fuzz target reaches for by name.
pub mod dtmf;
mod error;
mod event;
mod headers;
mod identity;
/// Keeping a registration reachable through a NAT over UDP: what is sent to
/// the registrar, when and how often, grouped under its own path for the
/// bounds a binding checks its own setting against.
pub mod keepalive;
mod lifecycle;
pub mod locate;
mod message;
mod mwi;
mod options;
mod oversize;
mod parked;
/// Presence documents (RFC 3863) with the rich presence activities of
/// RFC 4480 — under their own path because `Tuple`, `Note` and `Contact`
/// are PIDF's vocabulary, not this crate's.
pub mod presence;
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
/// SIPREC recording metadata (RFC 7865, RFC 7866) and the pieces of the
/// INVITE that offers a recording session, grouped under its own path: its
/// model has a `Session` and a `Stream` of its own.
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
pub use event::{RegistrationFailure, RegistrationState, UaEvent};
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
pub use stir::{DEFAULT_CERTIFICATE_WAIT, StirConfig, StirSigning};
pub use subscription::{
    DEFAULT_EXPIRES, Subscribe, SubscriptionEnd, SubscriptionHandle, SubscriptionState,
};
pub use verification::{
    Attestation, CallerVerification, StirVerification, VerificationFailure, VerificationOutcome,
};

/// What a caller needs from the layer below to drive this one, re-exported so
/// that an application does not have to name `sipral-core` to use a phone.
pub use sipral_core::auth::Credentials;
/// RFC 3263's lookups, as [`UaEvent::LookupWanted`] asks for them and
/// [`UserAgent::looked_up`] takes their answers, and the procedure itself for
/// an application that locates something of its own.
pub use sipral_core::endpoint::{
    AddressFamily, Answer, LocateError, Located, Locator, Naptr, Query, Record, RecordType, Srv,
};
pub use sipral_core::endpoint::{
    EndpointConfig, Input, ReceiveError, Transmit, TransportId, TransportProtocol,
};
pub use sipral_core::msg::{StatusCode, Uri};
/// Recording a session and feeding it back, which a user agent is driven by
/// exactly as the endpoint under it is (`docs/18-replay.md`).
pub use sipral_core::replay::{Driven, Played, Recorder, Recording, Replay};
