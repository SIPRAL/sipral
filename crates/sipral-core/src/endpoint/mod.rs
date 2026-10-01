// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The endpoint: bytes and time in, bytes and events out.
//!
//! Every layer below this one exists on its own and is tested on its own — a
//! parser with no transactions, four state machines with nothing that owns
//! them, dialogs that never see a socket. This is where they are bound
//! together, and therefore the first place where the model either holds or
//! does not.
//!
//! The shape is five calls. The caller hands in what arrived and what time it
//! is, then drains what has to go out and what has to be reported, and comes
//! back when the next deadline passes. Nothing here opens a socket, reads a
//! clock, resolves a name or draws a random number: all four are the caller's,
//! which is what makes a full RFC 3261 §17 timer diagram an ordinary unit test
//! rather than a wait.

mod auth;
#[cfg(test)]
mod auth_tests;
mod config;
mod dialogs;
mod driver;
mod error;
mod event;
mod failover;
mod inbound;
mod locate;
mod outgoing;
mod prack;
#[cfg(test)]
mod prack_tests;
mod record;
#[cfg(test)]
mod record_tests;
mod reinvite;
#[cfg(test)]
mod reinvite_tests;
mod reliable;
mod resolve;
#[cfg(test)]
mod store_tests;
mod table;
#[cfg(test)]
mod tests;
mod tokens;
mod transport;
#[cfg(test)]
mod unreadable_tests;
mod via;

pub(crate) use table::Flow;

pub use auth::ChallengeOrigin;
pub use config::{Compaction, DatagramLimit, EndpointConfig};
pub use driver::{DialogSnapshot, Endpoint, Retransmissions, StreamMessage};
pub use error::{
    AckError, AuthRetryError, CancelError, PrackError, ReceiveError, RespondError, SendError,
};
pub use event::{DialogEndReason, Event, FailureReason, TerminationReason};
pub use failover::UnreachedRequest;
pub use locate::{
    AddressFamily, Answer, LocateError, Located, Locator, Naptr, Query, Record, RecordType, Srv,
};
pub use outgoing::{ENDPOINT_FIELDS, OutgoingInDialogRequest, OutgoingRequest, OutgoingResponse};
pub use transport::{Host, Input, Transmit, TransportErrorKind, TransportId, TransportProtocol};
