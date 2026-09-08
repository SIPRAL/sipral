// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! NAT traversal.
//!
//! STUN and TURN clients and ICE-lite. Symmetric RTP with rport covers most
//! carriers on its own; the rest is what this crate is for.
//!
//! Sans-I/O, like the rest of the tree: nothing here opens a socket, reads a
//! clock or draws a random number. The caller supplies the datagrams, the
//! time and the transaction ids, and takes back what to send.
//!
//! The hashes STUN needs are written out in this crate rather than pulled in,
//! because the tree has no dependencies. Every one of them is checked against
//! the digests published with its own specification.
//!
//! Written from RFC 8489, RFC 8445, RFC 8656 and RFC 8839; see
//! `docs/02-clean-room.md` for why that matters here.

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

mod crypto;
mod demux;
pub mod ice;
pub mod stun;
pub mod turn;

pub use demux::{Demux, classify};
