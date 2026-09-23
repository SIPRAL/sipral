// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Stable C ABI.
//!
//! The single surface that the Swift Package, the NuGet package and the AAR are
//! generated over. Kept deliberately narrow: handles, opaque pointers, and an
//! event callback. Everything expressive lives on the language side.
//!
//! Four rules hold the whole thing up, and each has a module. Nothing crosses
//! but plain data, and a struct that crosses carries its own size, so a
//! caller and a library built a year apart still agree (`versioned`, the one
//! of the four kept private: what it holds is the discipline the other
//! modules are written to, and nothing a caller names). Nothing the library
//! owns is named by an address, so a handle used after it was freed is an
//! error code rather than somebody else's memory ([`handle`]). Nothing
//! unwinds past the boundary, because a panic that reaches C takes the host
//! process with it ([`error`]). And the ABI says what version it is, so a
//! binding that was generated against another one finds out at load rather
//! than in the first call that reads a member which is not there
//! ([`version`]).
//!
//! On top of those four sit the operations: a stack is configured and polled
//! ([`stack`]), accounts are registered ([`account`]), calls are placed,
//! answered, held, handed on and hung up ([`call`]), audio is negotiated,
//! carried and measured ([`media`]), signalling goes on and comes off the wire
//! ([`transport`]), a conversation is written to a file ([`record`]), the
//! header fields an application adds go on and come back out of a message
//! ([`header`]), and everything the stack has to say comes back on one callback
//! as one tagged union ([`event`]). Whether a stack may be used from two threads at once, and
//! whether the library may be re-entered from inside that callback, are both
//! answered in [`stack`], because a binding author who cannot find the answer
//! will assume the wrong one. Two more answer questions an application asks
//! about the library rather than about a call: what this build can do at all
//! ([`capabilities`]), and whether the deployment it is running in is healthy
//! ([`counters`]).
//!
//! Every one of those declares itself through a macro from [`abi`], which
//! emits the declaration and, beside it, what the declaration was made of. The
//! C header and the Swift, Kotlin and .NET bindings are printed from that and
//! committed, so a function added here and forgotten in a binding is a build
//! failure rather than a crash on one platform in the field.
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
pub mod announce;
pub mod call;
pub mod capabilities;
pub mod counters;
pub mod diagnostics;
pub mod error;
pub mod event;
pub mod handle;
pub mod header;
pub mod lifecycle;
/// Two hundred calls on one stack, driven from four threads: the shape of
/// the locking, measured rather than asserted. Tests only — nothing here
/// crosses the ABI.
#[cfg(test)]
mod load;
pub mod media;
pub mod message;
mod names;
pub mod record;
pub mod resolve;
pub mod screening;
pub mod stack;
pub mod status;
pub mod subscription;
mod text;
pub mod transport;
pub mod version;
mod versioned;
