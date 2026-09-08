// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Stable C ABI.
//!
//! The single surface that the Swift Package, the NuGet package and the AAR are
//! generated over. Kept deliberately narrow: handles, opaque pointers, and an
//! event callback. Everything expressive lives on the language side.
//!
//! Four rules hold the whole thing up, and each has a module. Nothing crosses
//! but plain data, and a struct that crosses carries its own size, so a caller
//! and a library built a year apart still agree ([`versioned`]). Nothing the
//! library owns is named by an address, so a handle used after it was freed is
//! an error code rather than somebody else's memory ([`handle`]). Nothing
//! unwinds past the boundary, because a panic that reaches C takes the host
//! process with it ([`error`]). And the ABI says what version it is, so a
//! binding that was generated against another one finds out at load rather
//! than in the first call that reads a member which is not there
//! ([`version`]).
//!
//! On top of those four sit the operations: a stack is configured and polled
//! ([`stack`]), accounts are registered ([`account`]), calls are placed,
//! answered, held, handed on and hung up ([`call`]), and everything the stack
//! has to say comes back on one callback as one tagged union ([`event`]).
//! Whether a stack may be used from two threads at once, and whether the
//! library may be re-entered from inside that callback, are both answered in
//! [`stack`], because a binding author who cannot find the answer will assume
//! the wrong one.
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

pub mod account;
pub mod call;
pub mod error;
pub mod event;
pub mod handle;
mod names;
pub mod stack;
pub mod status;
mod text;
pub mod version;
mod versioned;
