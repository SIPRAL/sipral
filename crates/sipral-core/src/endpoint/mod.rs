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

mod config;
mod transport;

pub use config::{DatagramLimit, EndpointConfig};
pub use transport::{Host, Input, Transmit, TransportErrorKind, TransportId, TransportProtocol};
