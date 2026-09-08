// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! User agent layer.
//!
//! Registration with refresh, outgoing and incoming calls, hold and resume,
//! blind and attended transfer, and the SUBSCRIBE/NOTIFY subscriptions behind
//! message waiting and busy lamp field.
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
mod call;
mod calls;
mod error;
mod event;
mod registration;
mod renegotiate;
#[cfg(feature = "reference-loop")]
mod runtime;
mod session;
#[cfg(test)]
mod tests;

pub use account::{Account, AccountId};
pub use agent::UserAgent;
pub use call::{CallEndReason, CallHandle, CallState, Direction, ForkPolicy, OutgoingCall};
pub use error::UaError;
pub use event::{RegistrationFailure, RegistrationState, UaEvent};
#[cfg(feature = "reference-loop")]
pub use runtime::{Control, Handler, Runtime};
pub use session::Hold;

/// What a caller needs from the layer below to drive this one, re-exported so
/// that an application does not have to name `sipral-core` to use a phone.
pub use sipral_core::auth::Credentials;
pub use sipral_core::endpoint::{
    EndpointConfig, Input, ReceiveError, Transmit, TransportId, TransportProtocol,
};
pub use sipral_core::msg::{StatusCode, Uri};
