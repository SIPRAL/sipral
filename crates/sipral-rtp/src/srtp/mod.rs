// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The secure profile of RTP, from RFC 3711.
//!
//! A `Protector` turns the packets the rest of this crate builds into SRTP,
//! and an `Unprotector` turns arriving ones back. Both work in the caller's
//! own buffer: protecting encrypts the payload where it lies and writes the
//! authentication tag after it, unprotecting verifies and decrypts in place
//! and reports the shorter length, so the packet that comes out can go
//! straight into `RtpSession::receive` with nothing copied on the way.
//!
//! What is here is the transform. Where the master key comes from is not:
//! §4.3 takes it as given, and RFC 4568 carries it in SDP, which is
//! `sipral-core`'s side of the boundary. Nothing in this module draws a
//! random number or reads a clock.
//!
//! AES itself comes from the `aes` crate, for the reason its entry in
//! `Cargo.toml` gives. SHA-1, HMAC, counter mode, f8, the key derivation,
//! the index estimate and the replay list are written here from the RFCs.

mod cipher;
mod index;
mod kdf;
mod session;
mod sha1;
#[cfg(test)]
mod testing;

pub use index::WINDOW as REPLAY_WINDOW;
pub use kdf::{KEY, Master, Rate, SALT};
pub use session::{Mki, Policy, Protector, Security, SrtpError, Suite, Unprotector};
