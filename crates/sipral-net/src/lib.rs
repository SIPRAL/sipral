// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Networking ready to use: the sockets, the TLS and the DNS lookups the sans-I/O core leaves to
//! its caller, for an application that does not want to write them.
//!
//! The core never opens a socket (`docs/01-architecture.md`, "Who owns the sockets, the resolver
//! and TLS"). Every binding opens its own with the platform's APIs; an application that drives the
//! core directly, in Rust or through the C ABI, writes that layer itself or uses this crate. It is
//! optional and nothing else in the workspace depends on it but the C ABI's `network` feature, so
//! an application that brings its own networking links none of it.
//!
//! # What is here
//!
//! - [`Network`]: the I/O half of the loop. It binds UDP sockets, opens TCP and TLS connections,
//!   answers the core's lookups, writes what the core wants written and hands back, through
//!   [`Network::wait`], everything that arrived as a [`Happening`]: a datagram, stream bytes, a
//!   connection made or refused with the reason, a lookup answered. The caller feeds those to the
//!   user agent as `Input`s and answers, exactly as it would with sockets of its own.
//! - [`Resolver`]: RFC 3263's NAPTR, SRV, A and AAAA lookups (`docs/04-ua.md`), against the
//!   system's resolver configuration or the name servers the application names, with
//!   [`Resolver::locate`] running the core's own `Locator` to the end for a caller that wants an
//!   address before any stack exists.
//! - [`Trust`] and [`ClientCertificate`]: the same choices the bindings give a TLS connection —
//!   the platform's trust store, a private authority beside it or alone, one certificate pinned by
//!   its SHA-256 fingerprint — and a client certificate presented when the server asks for one.
//! - [`Failure`] and [`TlsFailure`]: why a connection failed, classified the way the bindings
//!   classify it, ready for the C ABI's `sipral_transport_failure_t`.
//!
//! # How a loop uses it
//!
//! ```no_run
//! use std::time::Duration;
//! use sipral_core::endpoint::TransportId;
//! use sipral_net::{Happening, Network, NetworkConfig};
//!
//! # fn run() -> std::io::Result<()> {
//! let mut network = Network::new(NetworkConfig::default())?;
//! let main = TransportId(0);
//! let local = network.bind_datagram(main, "192.0.2.10:0".parse().expect("an address"))?;
//! // tell the user agent: `Input::TransportBound { transport: main, local, .. }`
//! loop {
//!     // write what the agent has queued: `network.send(transport, destination, &payload)`
//!     for happening in network.wait(Some(Duration::from_millis(100))) {
//!         match happening {
//!             Happening::Datagram { .. } | Happening::StreamData { .. } => { /* `agent.receive` */ }
//!             Happening::LookedUp { .. } => { /* `agent.looked_up` */ }
//!             _ => {}
//!         }
//!     }
//! #   let _ = local;
//! #   break;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # What it checks, and what it does not
//!
//! A TLS connection is checked by rustls's `webpki` against the authorities of the platform's
//! trust store (read with `rustls-native-certs`), beside or instead of the application's own,
//! against the server name the caller gives, by the rules HTTPS uses: that is what every binding
//! checks too (`docs/22-tls.md`). RFC 5922's stricter reading of a SIP certificate — `sip:` URIs
//! in `subjectAltName` first, no wildcard — is not applied here yet. A pin replaces the chain, the
//! name and the dates, and the handshake signature is still verified. On iOS and Android the
//! platform's store cannot be read this way, so a connection there trusts a private authority or
//! a pin, or the Swift and Kotlin layers' own TLS.

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

mod failure;
mod network;
mod resolver;
mod stream;
mod trust;

pub use failure::{Failure, TlsFailure};
pub use network::{Happening, MediaSender, Network, NetworkConfig, StreamTarget};
pub use resolver::Resolver;
pub use trust::{ClientCertificate, ClientCertificateError, Trust, TrustError};
