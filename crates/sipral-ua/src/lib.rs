// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! User agent layer.
//!
//! Registration with refresh, outgoing and incoming calls, hold and resume,
//! blind and attended transfer, the SUBSCRIBE/NOTIFY subscriptions behind
//! message waiting and busy lamp field, the policy that decides whether an
//! INVITE off the internet is ever heard at all, and what all of that stops
//! being worth when the machine underneath it goes to sleep: a call announced
//! by a push before there is a transport, a registration that can be written
//! down and read back, and a lifecycle that says which of the two is which.
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
mod agent;
mod announce;
mod call;
mod calls;
mod dialoginfo;
mod error;
mod event;
mod lifecycle;
mod options;
mod registration;
mod reliable;
mod renegotiate;
#[cfg(test)]
mod replay_tests;
#[cfg(feature = "reference-loop")]
mod runtime;
mod screening;
mod session;
mod subscription;
#[cfg(test)]
mod tests;
mod timers;
mod transfer;

pub use account::{Account, AccountId, Push};
pub use agent::UserAgent;
pub use announce::{Announced, Announcement, AnnouncementId};
pub use call::{CallEndReason, CallHandle, CallState, Direction, ForkPolicy, OutgoingCall};
pub use dialoginfo::{
    DialogEnded, DialogInfo, DialogInfoError, DialogInfoTable, DialogPhase, Initiated, Participant,
    WatchedDialog,
};
pub use error::UaError;
pub use event::{RegistrationFailure, RegistrationState, UaEvent};
pub use lifecycle::{
    Idle, LifecycleState, Link, Network, Recovery, RecoveryFailure, Rung, Suspending,
};
pub use registration::{PushEcho, SnapshotError};
#[cfg(feature = "reference-loop")]
pub use runtime::{Control, Handler, Runtime};
pub use screening::{Incoming, Rate, RateError, Refusals, Replacing, Screen, Screening};
pub use session::Hold;
pub use subscription::{
    DEFAULT_EXPIRES, Subscribe, SubscriptionEnd, SubscriptionHandle, SubscriptionState,
};

/// What a caller needs from the layer below to drive this one, re-exported so
/// that an application does not have to name `sipral-core` to use a phone.
pub use sipral_core::auth::Credentials;
pub use sipral_core::endpoint::{
    EndpointConfig, Input, ReceiveError, Transmit, TransportId, TransportProtocol,
};
pub use sipral_core::msg::{StatusCode, Uri};
/// Recording a session and feeding it back, which a user agent is driven by
/// exactly as the endpoint under it is (`docs/18-replay.md`).
pub use sipral_core::replay::{Driven, Played, Recorder, Recording, Replay};
