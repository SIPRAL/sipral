// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
//! The handshake, for either end:
//!
//! - [`connection`]: the client and server state machines of RFC 6347 with
//!   the server's stateless cookie exchange, flight retransmission, alerts
//!   and closure, `use_srtp` negotiation, mutual authentication checked
//!   against the peer's signalled fingerprint, and the SRTP keys exported
//!   once both Finished messages are verified;
//! - [`setup`]: which end is the client, from `a=setup` (RFC 4145, RFC 5763
//!   §5);
//! - [`alert`]: the alert codec.
//!
//! And the ground they stand on, each piece complete and tested on its own:
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
//! # Primitives
//!
//! P-256, AES-GCM, SHA-2 and HMAC come from RustCrypto: constant-time curve
//! arithmetic is not something to write in-house. Only the protocol is
//! written here. SHA-1 is in-tree, used only for legacy `sha-1`
//! fingerprints of public certificates, where timing reveals nothing.
//!
//! # The extended master secret
//!
//! RFC 7627 §5.4 says a session without it "MUST disable \[RFC5705\]", the
//! exporter all DTLS-SRTP keys come from (RFC 9325 §3.5 also requires
//! support). So [`MasterSecret::export`] refuses an old-style master secret,
//! and a peer whose TLS predates RFC 7627 cannot key SRTP here.
//!
//! # Sans-I/O
//!
//! Datagrams, the time and every random octet ([`Random`]) come from the
//! caller.
//!
//! Written from RFC 6347, RFC 5246, RFC 5288, RFC 5289, RFC 5705, RFC 5746,
//! RFC 5763, RFC 5764, RFC 7714, RFC 4145, RFC 7627, RFC 8422, RFC 8827, RFC
//! 5280, RFC 5480, RFC 5758, RFC 3279 and RFC 8122; see
//! `docs/02-clean-room.md` for why that matters here.
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

pub mod alert;
pub mod connection;
mod ct;
mod error;
pub mod exporter;
pub mod handshake;
pub mod keys;
pub mod prf;
mod random;
pub mod record;
pub mod setup;
mod wire;
pub mod x509;

pub use connection::{Config, Connection, Event, Failure, Retransmission, SrtpKeying, State};
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
