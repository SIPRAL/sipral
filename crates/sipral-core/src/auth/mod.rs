// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Digest authentication (RFC 3261 §22, RFC 8760).
//!
//! The client side only: answers challenges, never issues them. MD5 for the
//! registrars that still use it, the SHA-2 algorithms of RFC 8760, the nonce
//! counter that makes a stolen response useless twice, and a cache that saves
//! a round trip per request. The hashes are written here because the crate
//! has no dependencies; each is checked against published digests.
//!
//! The `Bearer` scheme of RFC 8898 sits beside it: same challenge, same
//! cache, answered with an OAuth 2.0 token the application obtained.

mod bearer;
mod cache;
pub(crate) mod digest;
mod keysource;
mod md5;
mod secret;
pub(crate) mod sha2;

pub use bearer::{BearerChallenge, BearerError};
pub use cache::{Answered, AuthCache, Learned};
pub use digest::{Challenge, DigestAlgorithm};
pub use keysource::KeySource;
pub use secret::{Credentials, NotAToken, Secret, is_access_token};
