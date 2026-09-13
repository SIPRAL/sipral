// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! DTLS 1.2, for keying SRTP.
//!
//! Written for one purpose: the DTLS-SRTP handshake of RFC 5764, with the one
//! cipher suite WebRTC peers are required to support,
//! `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 8827 §6.5), and self-signed
//! certificates checked against `a=fingerprint` (RFC 8122) and against nothing
//! else. No renegotiation, no session resumption, no DTLS 1.3.
//!
//! # What is here
//!
//! The ground the handshake state machines stand on, each piece complete and
//! tested on its own:
//!
//! - [`prf`]: the TLS 1.2 PRF with SHA-256, the master secret and the extended
//!   master secret, the Finished `verify_data`, the record key block;
//! - [`exporter`]: the keying material exporter of RFC 5705 and the SRTP key
//!   layout of RFC 5764 §4.2;
//! - [`record`]: the record header with its epoch and 48-bit sequence number,
//!   AES-128-GCM protection per RFC 5288, the anti-replay window;
//! - [`handshake`]: the DTLS handshake header, fragmentation to a path MTU and
//!   bounded reassembly, the transcript hash, every message of the handshake
//!   with the six extensions it carries, and HelloVerifyRequest cookies;
//! - [`keys`]: P-256 keys for ECDHE and ECDSA, made from the caller's
//!   randomness;
//! - [`x509`]: a self-signed certificate written in DER, the public key read
//!   out of a peer's certificate, and certificate fingerprints.
//!
//! # What is not here yet
//!
//! The handshake itself: the client and server state machines, flight
//! retransmission, alerts and closure, and the connection that joins them to
//! a media session. Nothing in the tree calls this crate yet.
//!
//! # What is not written here at all
//!
//! The primitives. P-256 (ECDH and ECDSA), AES-GCM, SHA-256 and HMAC are the
//! RustCrypto crates: constant-time elliptic curve arithmetic is the place
//! where an implementation of one's own is a liability rather than a virtue.
//! What is written here is the protocol around them.
//!
//! SHA-1 is the exception, written in-tree like the two other copies in the
//! tree, because its only use is reading an old `sha-1` fingerprint of a
//! certificate that is public anyway: nothing secret goes through it, so how
//! long it takes reveals nothing.
//!
//! # The extended master secret
//!
//! RFC 5764 predates RFC 7627 and does not mention it; RFC 8827 does not
//! require it either. RFC 7627 §5.4 does: a session that continues without
//! it "MUST disable \[RFC5705\]", and RFC 5705 is the exporter every DTLS-SRTP
//! key comes out of. RFC 9325 §3.5 then requires TLS 1.2 implementations to
//! support the extension. So [`MasterSecret::export`] refuses a master secret
//! derived the old way, and a peer whose TLS library predates RFC 7627 cannot
//! key SRTP through this crate.
//!
//! # Sans-I/O
//!
//! Like the rest of the tree, nothing here opens a socket, reads a clock or
//! draws a random number. Datagrams, the current time for a certificate's
//! validity, and every random octet ([`Random`]) come from the caller.
//!
//! Written from RFC 6347, RFC 5246, RFC 5288, RFC 5289, RFC 5705, RFC 5746,
//! RFC 5764, RFC 7627, RFC 8422, RFC 5280, RFC 5480, RFC 5758, RFC 3279 and
//! RFC 8122; see `docs/02-clean-room.md` for why that matters here.
//!
//! [`MasterSecret::export`]: prf::MasterSecret::export

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

mod ct;
mod error;
pub mod exporter;
pub mod handshake;
pub mod keys;
pub mod prf;
mod random;
pub mod record;
mod wire;
pub mod x509;

pub use error::Error;
pub use random::Random;

/// Which end of a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The end that sends ClientHello.
    Client,
    /// The end that answers it.
    Server,
}

impl Role {
    /// The other end.
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_is_the_other_end_and_its_own_inverse() {
        assert_eq!(Role::Client.peer(), Role::Server);
        assert_eq!(Role::Server.peer(), Role::Client);
        for role in [Role::Client, Role::Server] {
            assert_eq!(role.peer().peer(), role);
        }
    }
}
