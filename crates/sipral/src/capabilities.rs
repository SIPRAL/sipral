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

/// How a stream on this build can come to have keys.
///
/// An enumeration rather than a pair of flags, so that
/// [`Capabilities::srtp_keying`] can only name a key exchange that has a
/// variant, and a variant that is missing from that list is missing because
/// nothing in this build reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SrtpKeying {
    /// RFC 4568's `a=crypto`, keyed from the seeded token stream and offered
    /// per call — see [`SrtpPolicy`](crate::SrtpPolicy).
    Sdes,
    /// RFC 5764's handshake on the media path.
    ///
    /// Named here and deliberately absent from [`KEYING`]: `sipral-core`
    /// reads an `a=fingerprint` and carries it through, and there is no DTLS
    /// anywhere in this tree — no handshake, no certificate, nothing that
    /// could produce a key. A plan keyed this way is refused with
    /// [`MediaError::NoDtlsSrtp`](crate::MediaError::NoDtlsSrtp) rather than
    /// opened in the clear, which is the behaviour this absence is derived
    /// from.
    Dtls,
}

/// The key exchanges a call on this build can actually complete.
///
/// Not "the ones SRTP defines" and not "the ones something in this workspace
/// has a type for": the ones a call placed or answered through
/// [`MediaEngine`](crate::MediaEngine) reaches, which today is SDES and only
/// SDES.
const KEYING: [SrtpKeying; 1] = [SrtpKeying::Sdes];

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
    /// Whether a media stream can be keyed at all, which is
    /// [`Capabilities::srtp_keying`] having anything in it and never a fact
    /// of its own.
    ///
    /// It said `true` before any of the keying was reachable, which is
    /// exactly the drift the head of this file is about: RFC 3711 was written
    /// and tested, RFC 4568 was written and tested, and no offer this stack
    /// wrote had ever named a secure profile.
    pub srtp: bool,
    /// Which key exchanges a call can complete, and therefore which ones are
    /// worth showing a control for.
    ///
    /// SDES is in it. DTLS-SRTP is not, and the enumeration has a variant for
    /// it so that its absence is something an application can read rather
    /// than something it has to know.
    pub srtp_keying: &'static [SrtpKeying],
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
            srtp: !KEYING.is_empty(),
            srtp_keying: &KEYING,
            subscriptions: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, SrtpKeying};
    use sipral_core::sdp::{Direction, KeySalt, Keying, NegotiatedCodec, RtcpPlan, RtpMap};

    use crate::codec::{Codec, CodecCatalog};
    use crate::error::MediaError;
    use crate::keying::{SrtpPolicy, security};

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

    /// The claim is that SDES is reachable and DTLS-SRTP is not, and both
    /// halves are checked against the behaviour rather than restated: an
    /// offer written under a policy that asks for SDES has to name the secure
    /// profile and carry a key, and a plan keyed by a handshake has to be
    /// refused.
    #[test]
    fn the_keying_this_build_lists_is_the_keying_a_call_can_reach() {
        let capabilities = Capabilities::of_this_build();
        assert_eq!(capabilities.srtp_keying, [SrtpKeying::Sdes]);
        assert_eq!(
            capabilities.srtp,
            !capabilities.srtp_keying.is_empty(),
            "the flag is the list and not a second opinion about it"
        );

        let offer = CodecCatalog::new()
            .with_srtp(SrtpPolicy::Offered)
            .offering(Some(KeySalt::new([3; 16], [4; 14])))
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(offer.proto, "RTP/SAVP");
        assert!(
            offer
                .attribute("crypto")
                .and_then(|line| line.value.as_deref())
                .is_some_and(|value| value.contains("inline:")),
            "SDES is listed as reachable and the offer carries no key"
        );

        assert!(
            !capabilities.srtp_keying.contains(&SrtpKeying::Dtls),
            "there is no DTLS in this tree"
        );
        let handshaken = sipral_core::sdp::MediaPlan {
            local: "192.0.2.1:40000".parse().expect("an address"),
            remote: "192.0.2.2:40002".parse().expect("an address"),
            codec: NegotiatedCodec::new(RtpMap {
                payload: 0,
                encoding: "PCMU".to_owned(),
                clock_rate: 8_000,
                parameters: None,
            }),
            direction: Direction::SendRecv,
            dtmf: None,
            rtcp: RtcpPlan::Off,
            keying: Some(Keying::Dtls {
                fingerprint: "sha-256 AA:BB".to_owned(),
                setup: None,
            }),
        };
        assert_eq!(
            security(&handshaken).err(),
            Some(MediaError::NoDtlsSrtp),
            "DTLS-SRTP is left off the list, so it has to be refused where it arrives"
        );
    }
}
