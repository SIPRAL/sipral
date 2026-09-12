// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Digest authentication (RFC 3261 §22, RFC 8760).
//!
//! SIP authenticates the way HTTP does: the server refuses the request with a
//! nonce, the client hashes the nonce together with what it knows, and the
//! server checks the hash. The password never crosses the wire, and neither
//! side has to keep a shared secret beyond it.
//!
//! Everything a client needs is here — MD5 for the registrars that still
//! challenge with it, the SHA-2 algorithms RFC 8760 added, the counter that
//! makes a stolen response useless twice, and the cache that spares every
//! request a round trip. What is not here is the server side: this stack
//! answers challenges, it does not issue them.
//!
//! The hashes are written out in full because the crate has no dependencies,
//! and every one of them is checked against published digests before it is
//! used for anything.

mod cache;
pub(crate) mod digest;
mod keysource;
mod md5;
mod secret;
pub(crate) mod sha2;

pub use cache::{Answered, AuthCache, Learned};
pub use digest::{Challenge, DigestAlgorithm};
pub use keysource::KeySource;
pub use secret::{Credentials, Secret};
