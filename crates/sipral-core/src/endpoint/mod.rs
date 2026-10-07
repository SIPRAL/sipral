// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The endpoint: bytes and time in, bytes and events out.
//!
//! This binds parser, transactions and dialogs together. It never opens a
//! socket, reads a clock, resolves a name or draws a random number; the
//! caller does, so a full RFC 3261 §17 timer diagram is a plain unit test.

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
