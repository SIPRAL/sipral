// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Sans-I/O SIP protocol core.
//!
//! Parsing and serialization of SIP messages, the transaction layer (RFC 3261
//! timers A through K), the dialog layer, SDP offer/answer and digest
//! authentication.
//!
//! Nothing here opens a socket, spawns a thread or reads a clock. The caller
//! feeds bytes and the current time, and gets back bytes and events. Every
//! state machine is therefore reproducible in a unit test without a network.
//!
//! Written from the RFCs listed in `docs/09-rfc-index.md`. See
//! `docs/02-clean-room.md` for why that matters here.

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

pub mod auth;
pub mod dialog;
pub mod msg;
pub mod sdp;
pub mod transaction;
