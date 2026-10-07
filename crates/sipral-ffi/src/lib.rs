// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Stable C ABI.
//!
//! The one surface the Swift, .NET, Kotlin and Python bindings are generated
//! over: handles, opaque pointers and an event callback.
//!
//! Four rules: only plain data crosses, and structs carry their size
//! (`versioned`); library objects are named by handles, so use after free is
//! an error code ([`handle`]); no panic unwinds into C ([`error`]); the ABI
//! states its version, checked at load ([`version`]). Threading and
//! re-entrancy from the callback are answered in [`stack`]; events come back
//! as one tagged union ([`event`]).
//!
//! Every item is declared through an [`abi`] macro that also records its
//! shape; the C header and bindings are printed from that and committed, so
//! a binding that misses a function fails the build.
//!
//! ABI stability rules are in `docs/08-ffi.md`.

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

pub mod abi;
pub mod account;
pub mod advertise;
pub mod announce;
#[cfg(test)]
mod app_rate_tests;
pub mod audio;
pub mod call;
pub mod capabilities;
pub mod conference;
pub mod counters;
pub mod diagnostics;
pub mod error;
pub mod event;
pub mod handle;
pub mod header;
pub mod identity;
pub mod inband;
pub mod lifecycle;
/// Two hundred calls on one stack from four threads: the locking, measured.
#[cfg(test)]
mod load;
pub mod local_conference;
pub mod locate;
pub mod log;
pub mod media;
pub mod message;
mod names;
pub mod nat;
pub mod network_test;
pub mod pin;
pub mod ports;
pub mod presence;
#[cfg(test)]
mod realtime_tests;
pub mod realtime_text;
pub mod record;
pub mod resolve;
#[cfg(test)]
mod robust;
pub mod screening;
pub mod security;
#[cfg(all(test, feature = "stir"))]
mod security_tests;
pub mod siprec;
pub mod stack;
pub mod status;
pub mod subscription;
mod text;
pub mod transport;
pub mod version;
mod versioned;
