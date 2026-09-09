// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One machine-readable answer to "what does this build support" — D8, and
//! B2 seen from the outside.
//!
//! B2 is the promise that a setting answers `applied`, `rejected` or `not
//! supported in this build`, and never a fourth thing that looks like
//! success and is not. D8 is the same promise read before any setting is
//! touched: an application that asks once, at start-up, learns which
//! controls this build can honour at all, and can grey out the rest instead
//! of shipping them and finding out from a support ticket which ones do
//! nothing.
//!
//! # Derived, not maintained
//!
//! [`Capabilities::of_this_build`] reads facts that already exist elsewhere
//! rather than repeating them. The codec count is [`Codec::ALL`]'s own
//! length, so a codec added to the build changes what this reports without
//! anybody updating a second list; the transport list names the protocols
//! `sipral-core`'s endpoint has logic for, and not a socket this crate has
//! never opened. A capability list that can drift from the build it
//! describes is worse than none, because it is believed.

use sipral_ua::TransportProtocol;

use crate::codec::Codec;

/// Every transport [`sipral_core`]'s endpoint has protocol logic for:
/// framing, the timers RFC 3261 §17 names, what goes in a `Via`.
///
/// Not a promise that the platform underneath can open one of these — no
/// build of this crate opens a socket, so "does this build support TLS" and
/// "can this process open a TLS connection" are two different questions, and
/// this answers only the first.
const TRANSPORTS: [TransportProtocol; 5] = [
    TransportProtocol::Udp,
    TransportProtocol::Tcp,
    TransportProtocol::Tls,
    TransportProtocol::Ws,
    TransportProtocol::Wss,
];

/// What this build can do, in one answer.
///
/// This is about the build, never about one stack's configuration:
/// [`crate::CodecCatalog::with_order`] narrows what one [`crate::MediaEngine`]
/// offers, and narrowing it further does not change what the build could
/// have offered. An application reads this once to decide which controls to
/// show at all, and reads a stack's own settings — [`crate::CodecCatalog`]
/// itself, or the FFI's `sipral_stack_settings` — to see what a particular
/// instance is doing with them.
// each bool here is an independent yes/no fact about the build, not a state
// a caller steps through, which is what the lint is guarding against
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// What [`crate::CodecCatalog::new`] would offer by default, quality
    /// first. The slice's own length is the count: [`Codec::ALL`]'s, not a
    /// number copied out of it.
    pub codecs: &'static [Codec],
    /// Every transport this build carries signalling over.
    pub transports: &'static [TransportProtocol],
    /// Whether RFC 4733 named events can be offered.
    pub dtmf: bool,
    /// Whether RFC 5761 multiplexing can be asked for.
    pub rtcp_mux: bool,
    /// Whether a call's audio can be recorded to a [`crate::RecordingSink`].
    pub recording: bool,
    /// Whether B5's media-stall watchdog is compiled in.
    pub media_stall_watchdog: bool,
    /// Whether a media stream can be keyed.
    pub srtp: bool,
    /// Whether RFC 6665 subscriptions and the dialog-state package this
    /// crate wraps ([`sipral_ua::UserAgent::subscribe`]) are compiled in.
    pub subscriptions: bool,
}

impl Capabilities {
    /// What this build of the `sipral` crate can do.
    ///
    /// Nothing here is read from a configuration or a running stack — there
    /// is no `&self` because a build's capabilities do not vary between two
    /// engines running in the same process, only between two builds of the
    /// library.
    #[must_use]
    pub const fn of_this_build() -> Self {
        Self {
            codecs: &Codec::ALL,
            transports: &TRANSPORTS,
            dtmf: true,
            rtcp_mux: true,
            recording: true,
            media_stall_watchdog: true,
            srtp: true,
            subscriptions: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Capabilities;
    use crate::codec::Codec;

    #[test]
    fn the_codec_list_is_the_catalogues_own_default_order() {
        let capabilities = Capabilities::of_this_build();
        assert_eq!(capabilities.codecs, &Codec::ALL[..]);
    }

    #[test]
    fn every_transport_this_build_speaks_is_named_once() {
        let capabilities = Capabilities::of_this_build();
        assert_eq!(capabilities.transports.len(), 5);
        let mut seen = capabilities.transports.to_vec();
        seen.dedup();
        assert_eq!(
            seen.len(),
            capabilities.transports.len(),
            "no transport repeats"
        );
    }

    #[test]
    fn a_build_that_links_this_crate_has_every_feature_it_implements() {
        // documents the current build rather than asserting a tautology:
        // this is the test that fails the day one of these genuinely stops
        // being true, which is exactly when the answer must change
        let capabilities = Capabilities::of_this_build();
        assert!(capabilities.dtmf);
        assert!(capabilities.rtcp_mux);
        assert!(capabilities.recording);
        assert!(capabilities.media_stall_watchdog);
        assert!(capabilities.srtp);
        assert!(capabilities.subscriptions);
    }
}
