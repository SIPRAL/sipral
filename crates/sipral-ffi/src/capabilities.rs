// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One machine-readable answer to "what does this build support", across the
//! boundary — D8, and B2 seen from the outside.
//!
//! A binding that ships a control for something this build cannot do finds
//! out from a support ticket, months after the control shipped, because
//! nothing before this call said otherwise. [`sipral_capabilities`] answers
//! once, before any stack exists: which codecs this build contains, which
//! transports its signalling can carry, and which optional features are
//! compiled in. An application reads it at start-up and greys out exactly the
//! controls this build cannot honour, instead of shipping every control and
//! discovering which ones do nothing from whoever files the ticket.
//!
//! # Two layers, one honest answer each
//!
//! [`sipral::Capabilities::of_this_build`] answers for the `sipral` crate:
//! what `sipral_ua::UserAgent` can do, whether or not this ABI has grown an
//! entry point for it yet. This module answers for the ABI itself, and the
//! two are always allowed to differ: a thing `UserAgent` can do and this ABI
//! has no entry point in front of reads absent here, whatever the crate
//! underneath answers. [`SIPRAL_FEATURE_SUBSCRIPTIONS`] was the one that did,
//! from the first version of this module until
//! [`crate::subscription::sipral_account_subscribe`] arrived with event kind
//! 15 behind it; it now reads whatever the facade says, and every bit here is
//! once again the facade's own answer. The next feature to be built below
//! before it is built here takes its place, and this paragraph is the shape of
//! the answer for it.

use sipral::{Capabilities, SrtpKeying};
use sipral_ua::TransportProtocol;

use crate::abi::{constants, record};
use crate::error::entry;
use crate::stack::SipralTransport;
use crate::versioned::{Versioned, write_versioned};

constants! {
    /// Bits of [`SipralCapabilities::transports`]. A caller checks
    /// `capabilities.transports & SIPRAL_TRANSPORT_BIT_TLS != 0` rather than a
    /// growing list of booleans, so a transport this ABI has not learned a bit
    /// for yet reads as absent rather than refusing to compile against an
    /// older header.
    ///
    /// Named after [`SipralTransport`]'s own numbers (`1 << (value - 1)`), so
    /// a transport added there in the future gets a bit here without the two
    /// numbering schemes ever being asked to agree by hand.
    pub const SIPRAL_TRANSPORT_BIT_UDP: u32 = 1 << (SipralTransport::Udp as u32 - 1);
    /// See [`SIPRAL_TRANSPORT_BIT_UDP`].
    pub const SIPRAL_TRANSPORT_BIT_TCP: u32 = 1 << (SipralTransport::Tcp as u32 - 1);
    /// See [`SIPRAL_TRANSPORT_BIT_UDP`].
    pub const SIPRAL_TRANSPORT_BIT_TLS: u32 = 1 << (SipralTransport::Tls as u32 - 1);
    /// See [`SIPRAL_TRANSPORT_BIT_UDP`].
    pub const SIPRAL_TRANSPORT_BIT_WS: u32 = 1 << (SipralTransport::Ws as u32 - 1);
    /// See [`SIPRAL_TRANSPORT_BIT_UDP`].
    pub const SIPRAL_TRANSPORT_BIT_WSS: u32 = 1 << (SipralTransport::Wss as u32 - 1);

    /// Bits of [`SipralCapabilities::features`].
    pub const SIPRAL_FEATURE_DTMF: u32 = 1 << 0;
    /// See [`SIPRAL_FEATURE_DTMF`].
    pub const SIPRAL_FEATURE_RTCP_MUX: u32 = 1 << 1;
    /// See [`SIPRAL_FEATURE_DTMF`].
    pub const SIPRAL_FEATURE_RECORDING: u32 = 1 << 2;
    /// See [`SIPRAL_FEATURE_DTMF`].
    pub const SIPRAL_FEATURE_MEDIA_STALL_WATCHDOG: u32 = 1 << 3;
    /// See [`SIPRAL_FEATURE_DTMF`].
    pub const SIPRAL_FEATURE_SRTP: u32 = 1 << 4;
    /// See [`SIPRAL_FEATURE_DTMF`]. RFC 6665 subscriptions and the
    /// dialog-state package a busy lamp field is built on, reached with
    /// [`sipral_account_subscribe`](crate::subscription::sipral_account_subscribe).
    pub const SIPRAL_FEATURE_SUBSCRIPTIONS: u32 = 1 << 5;
    /// See [`SIPRAL_FEATURE_DTMF`]. Opus is behind a compile-time feature,
    /// because libopus is the one part of the audio path that is licensed
    /// rather than written, so a build meant for hardware can leave it out.
    /// The bit is how an application finds out without having to enumerate
    /// the codecs, and it is set from the catalogue this build offers rather
    /// than from any crate's feature flag; `SIPRAL_CODEC_OPUS` keeps its
    /// number either way, since a value that has left this header is spent
    /// for good.
    pub const SIPRAL_FEATURE_OPUS: u32 = 1 << 6;
    /// DTLS-SRTP (RFC 5764): the keys for a call's media come from a
    /// handshake on the media path rather than from the body of a message.
    ///
    /// Behind a compile-time feature for the reason Opus is: a build that
    /// will only ever place SDES calls over a protected SIP transport has no
    /// use for an elliptic curve, and a desk phone counts its flash. Both
    /// `SIPRAL_SRTP_DTLS` and `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers
    /// in a build without it — a value that has left this header is spent —
    /// and naming one there answers `SIPRAL_STATUS_NOT_SUPPORTED` rather than
    /// quietly placing an unencrypted call.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    pub const SIPRAL_FEATURE_DTLS_SRTP: u32 = 1 << 7;
    /// See [`SIPRAL_FEATURE_DTMF`]. ICE in the full role (RFC 8445), with
    /// consent freshness (RFC 7675) and the SDP attributes of RFC 8839: a
    /// call's media path is chosen by checking it rather than taken from what
    /// the signalling said.
    ///
    /// Behind a compile-time feature for the reason DTLS-SRTP is, and off by
    /// policy even where it is compiled in — `docs/06-nat.md` tabulates what
    /// it costs on the wire and why it buys nothing against a PBX that learns
    /// the caller's address from the media it receives. Both `SIPRAL_ICE_OFFERED`
    /// and `SIPRAL_ICE_REQUIRED` keep their numbers in a build without it, and
    /// naming one there answers `SIPRAL_STATUS_NOT_SUPPORTED`.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    pub const SIPRAL_FEATURE_ICE: u32 = 1 << 8;
    /// See [`SIPRAL_FEATURE_DTMF`]. STUN (RFC 8489): a stack created with
    /// `SIPRAL_NAT_STUN` asks a server where its sockets appear from and
    /// writes the answer in the `Contact` and in `c=` and `m=`.
    ///
    /// Behind a compile-time feature of its own, which brings nothing ICE
    /// does not already bring. `SIPRAL_NAT_STUN` keeps its number in a build
    /// without it, and naming it there answers `SIPRAL_STATUS_NOT_SUPPORTED`.
    pub const SIPRAL_FEATURE_STUN: u32 = 1 << 9;
    /// See [`SIPRAL_FEATURE_DTMF`]. A TURN server reached over TCP or TLS
    /// (RFC 8656 §3.1): `sipral_stack_config_t::turn_transport`, and the
    /// connection the application opens for each media socket when
    /// `SIPRAL_EVENT_KIND_TURN_STREAM` asks — for the network that lets no
    /// UDP out.
    ///
    /// It comes with `SIPRAL_FEATURE_ICE`, since a relay is only ever a
    /// call's relayed ICE candidate, and without it `turn_transport` other
    /// than UDP answers `SIPRAL_STATUS_NOT_SUPPORTED` as a `turn_server`
    /// does.
    pub const SIPRAL_FEATURE_TURN_STREAM: u32 = 1 << 10;
    /// See [`SIPRAL_FEATURE_DTMF`]. The built-in audio engine: a stack
    /// created with `sipral_stack_config_t::audio` set to
    /// `SIPRAL_AUDIO_DEVICE` opens the platform's devices and pumps every
    /// managed call itself, with the `sipral_audio_*` entry points to list,
    /// choose and control them. Clear on a platform this build has no
    /// backend for — Linux and Android today — where `SIPRAL_AUDIO_DEVICE`
    /// answers `SIPRAL_STATUS_NOT_SUPPORTED` and the application pumps the
    /// frames as it always has.
    ///
    /// This crate's own answer rather than the facade's: the engine sits
    /// beside the facade, not under it, so the facade has nothing to say.
    pub const SIPRAL_FEATURE_AUDIO_DEVICE: u32 = 1 << 11;
    /// See [`SIPRAL_FEATURE_DTMF`]. A call in progress moves with the
    /// network under it: `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` names each
    /// call whose media address is gone, and `sipral_call_media_readdress`
    /// offers it at the socket the application bound on the new network.
    pub const SIPRAL_FEATURE_CALL_READDRESS: u32 = 1 << 13;
    /// See [`SIPRAL_FEATURE_DTMF`]. Who is calling and how the call asked to
    /// be answered, on every call event: the asserted identity behind the
    /// account's `trusted_peers` (RFC 3325), `verstat`, `Privacy`,
    /// `Diversion` and `History-Info`, `Answer-Mode` and `Alert-Info`;
    /// why a call ended (`cause_sip`, `cause_q850`, RFC 3326) and
    /// `sipral_call_hangup_for` to say why this end is ending one;
    /// `sipral_call_redirect`; and an account's `privacy` and
    /// `session_timer`.
    pub const SIPRAL_FEATURE_CALLER_IDENTITY: u32 = 1 << 12;
}

record! {
    /// What this build of the library can do: codecs compiled in, transports
    /// this ABI carries signalling over, and which optional features are
    /// present.
    ///
    /// Nothing here is configuration — this answers "can this build ever do X",
    /// never "is X turned on for this stack". `sipral_stack_settings` answers
    /// that once a stack exists, and `sipral_codec_count` /
    /// `sipral_stack_codec_order` already enumerate the codecs this reports only
    /// the count of, so this does not repeat what they say.
    ///
    /// Set `size` to `sizeof(sipral_capabilities_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralCapabilities {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// How many codecs this build contains. `sipral_codec_count` gives the
        /// same number; `sipral_codec_at` says which, and in what order they are
        /// offered by default.
        pub codec_count: usize,
        /// Which transports this build carries signalling over, as the bits
        /// named `SIPRAL_TRANSPORT_BIT_*`.
        pub transports: u32,
        /// Which optional features this build has compiled in, as the bits named
        /// `SIPRAL_FEATURE_*`.
        pub features: u32,
    }
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each.
unsafe impl Versioned for SipralCapabilities {
    const NAME: &'static str = "sipral_capabilities";
    const MIN_SIZE: usize = crate::versioned::min_size::CAPABILITIES;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

const fn transport_bit(protocol: TransportProtocol) -> u32 {
    match protocol {
        TransportProtocol::Udp => SIPRAL_TRANSPORT_BIT_UDP,
        TransportProtocol::Tcp => SIPRAL_TRANSPORT_BIT_TCP,
        TransportProtocol::Tls => SIPRAL_TRANSPORT_BIT_TLS,
        TransportProtocol::Ws => SIPRAL_TRANSPORT_BIT_WS,
        TransportProtocol::Wss => SIPRAL_TRANSPORT_BIT_WSS,
        // sipral-core has grown a transport this ABI has no bit for yet;
        // saying nothing beats picking one that is wrong
        _ => 0,
    }
}

fn capabilities_of(capabilities: Capabilities) -> SipralCapabilities {
    let transports = capabilities
        .transports
        .iter()
        .fold(0_u32, |bits, protocol| bits | transport_bit(*protocol));
    let mut features = 0_u32;
    if capabilities.dtmf {
        features |= SIPRAL_FEATURE_DTMF;
    }
    if capabilities.rtcp_mux {
        features |= SIPRAL_FEATURE_RTCP_MUX;
    }
    if capabilities.recording {
        features |= SIPRAL_FEATURE_RECORDING;
    }
    if capabilities.media_stall_watchdog {
        features |= SIPRAL_FEATURE_MEDIA_STALL_WATCHDOG;
    }
    if capabilities.srtp {
        features |= SIPRAL_FEATURE_SRTP;
    }
    // opus: read off the value the facade handed down like every other bit
    // here, and deliberately not off this crate's own `opus` feature. Cargo
    // features are per-crate and additive, so a build of this crate with the
    // feature off can sit on a facade that linked the codec -- and a bit
    // derived from the wrong crate's flag would tell an application to grey
    // out a control this build can honour. A build genuinely without it
    // offers G.711 and G.722, `codec_count` is one lower, and this bit is
    // clear
    if capabilities.opus {
        features |= SIPRAL_FEATURE_OPUS;
    }
    // subscriptions: reached from C since `sipral_account_subscribe`, so the
    // bit is the facade's answer like every other one here
    if capabilities.subscriptions {
        features |= SIPRAL_FEATURE_SUBSCRIPTIONS;
    }
    // read off the facade's own list of what a call can actually complete,
    // not off this crate's feature flag, for the reason the Opus bit gives:
    // the two crates are compiled separately and a bit derived from the wrong
    // one would promise what the build below cannot do
    if capabilities.srtp_keying.contains(&SrtpKeying::Dtls) {
        features |= SIPRAL_FEATURE_DTLS_SRTP;
    }
    // and the same again: the facade's own answer, not this crate's flag
    if capabilities.ice {
        features |= SIPRAL_FEATURE_ICE;
    }
    if capabilities.stun {
        features |= SIPRAL_FEATURE_STUN;
    }
    if capabilities.turn_streams {
        features |= SIPRAL_FEATURE_TURN_STREAM;
    }
    if crate::audio::available() {
        features |= SIPRAL_FEATURE_AUDIO_DEVICE;
    }
    if capabilities.call_readdress {
        features |= SIPRAL_FEATURE_CALL_READDRESS;
    }
    if capabilities.caller_identity {
        features |= SIPRAL_FEATURE_CALLER_IDENTITY;
    }
    SipralCapabilities {
        size: size_of::<SipralCapabilities>(),
        codec_count: capabilities.codecs.len(),
        transports,
        features,
    }
}

entry! {
    /// What this build of the library can do, in one call.
    ///
    /// Names no stack, and answers the same way before any stack is created
    /// as after: a build's capabilities do not change while it runs. Safe to
    /// call from any thread, at any time, including from inside the event
    /// callback.
    ///
    /// # Safety
    ///
    /// `out_capabilities` must point at a `sipral_capabilities_t` whose
    /// `size` member says how long it is.
    fn sipral_capabilities(out_capabilities: *mut SipralCapabilities) {
        // checked before it is filled in, so a caller that got its size
        // wrong is told that rather than reading a struct it never asked for
        unsafe { crate::versioned::declared_size(out_capabilities.cast_const()) }?;
        let capabilities = capabilities_of(Capabilities::of_this_build());
        unsafe { write_versioned(out_capabilities, capabilities) }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SIPRAL_FEATURE_AUDIO_DEVICE, SIPRAL_FEATURE_CALL_READDRESS, SIPRAL_FEATURE_CALLER_IDENTITY,
        SIPRAL_FEATURE_DTMF, SIPRAL_FEATURE_ICE, SIPRAL_FEATURE_MEDIA_STALL_WATCHDOG,
        SIPRAL_FEATURE_OPUS, SIPRAL_FEATURE_RECORDING, SIPRAL_FEATURE_RTCP_MUX,
        SIPRAL_FEATURE_SRTP, SIPRAL_FEATURE_SUBSCRIPTIONS, SIPRAL_FEATURE_TURN_STREAM,
        SIPRAL_TRANSPORT_BIT_TCP, SIPRAL_TRANSPORT_BIT_TLS, SIPRAL_TRANSPORT_BIT_UDP,
        SIPRAL_TRANSPORT_BIT_WS, SIPRAL_TRANSPORT_BIT_WSS, SipralCapabilities, sipral_capabilities,
    };
    use crate::error::last_error_text;
    use crate::status::SipralStatus;
    use sipral::{Capabilities, Codec};

    fn zeroed() -> SipralCapabilities {
        SipralCapabilities {
            size: size_of::<SipralCapabilities>(),
            codec_count: usize::MAX,
            transports: u32::MAX,
            features: u32::MAX,
        }
    }

    fn read() -> SipralCapabilities {
        let mut out = zeroed();
        let status = unsafe { sipral_capabilities(&raw mut out) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        out
    }

    #[test]
    fn the_codec_count_matches_the_catalogue_this_build_actually_contains() {
        assert_eq!(read().codec_count, Codec::ALL.len());
    }

    #[test]
    fn every_transport_bit_this_build_sets_is_one_the_abi_has_a_name_for() {
        let capabilities = read();
        let known = SIPRAL_TRANSPORT_BIT_UDP
            | SIPRAL_TRANSPORT_BIT_TCP
            | SIPRAL_TRANSPORT_BIT_TLS
            | SIPRAL_TRANSPORT_BIT_WS
            | SIPRAL_TRANSPORT_BIT_WSS;
        assert_eq!(
            capabilities.transports & !known,
            0,
            "an unnamed bit was set"
        );
        assert_eq!(
            capabilities.transports, known,
            "this build has protocol logic for every transport the ABI names"
        );
    }

    #[test]
    fn the_features_this_build_compiles_in_are_reported() {
        let capabilities = read();
        for bit in [
            SIPRAL_FEATURE_DTMF,
            SIPRAL_FEATURE_RTCP_MUX,
            SIPRAL_FEATURE_RECORDING,
            SIPRAL_FEATURE_MEDIA_STALL_WATCHDOG,
            SIPRAL_FEATURE_SRTP,
        ] {
            assert_ne!(capabilities.features & bit, 0, "bit {bit:#x} should be set");
        }
    }

    /// The bit and the codec list are two ways of asking the same question
    /// and have to agree, or an application greys out a control this build
    /// can honour, or offers one it cannot.
    ///
    /// Asked of the catalogue and never of `cfg!(feature = "opus")`: this
    /// crate's feature is its own, and `--no-default-features` here over a
    /// facade built with `sipral/opus` is a legal configuration in which the
    /// flag says no and the build can negotiate the codec.
    #[test]
    fn opus_reads_present_exactly_when_the_catalogue_contains_it() {
        let capabilities = read();
        assert_eq!(
            capabilities.features & SIPRAL_FEATURE_OPUS != 0,
            Codec::ALL
                .iter()
                .any(|codec| codec.encoding_name() == "opus"),
            "the bit and the catalogue disagree about what was linked"
        );
        assert_eq!(
            capabilities.features & SIPRAL_FEATURE_OPUS != 0,
            Capabilities::of_this_build().opus,
            "the bit is the facade's answer and not a second opinion"
        );
    }

    #[test]
    fn subscriptions_read_present_now_that_this_abi_reaches_one() {
        // the bit was off for as long as `sipral_ua::UserAgent` could
        // subscribe and this crate had no way to ask it to; it is the
        // facade's answer again now that `sipral_account_subscribe` exists,
        // and this test is what would catch an entry point removed without
        // the bit following it
        assert_eq!(
            read().features & SIPRAL_FEATURE_SUBSCRIPTIONS != 0,
            Capabilities::of_this_build().subscriptions,
            "the bit is the facade's answer and not a second opinion"
        );
        assert!(read().features & SIPRAL_FEATURE_SUBSCRIPTIONS != 0);
    }

    /// A relay over TCP or TLS is the facade's answer too, and comes with
    /// ICE: a build that has no agent to hand a relay to has no connection to
    /// carry one on.
    #[test]
    fn turn_over_a_stream_reads_present_exactly_when_the_facade_says() {
        let features = read().features;
        assert_eq!(
            features & SIPRAL_FEATURE_TURN_STREAM != 0,
            Capabilities::of_this_build().turn_streams,
            "the bit is the facade's answer and not a second opinion"
        );
        assert_eq!(
            features & SIPRAL_FEATURE_TURN_STREAM != 0,
            features & SIPRAL_FEATURE_ICE != 0
        );
        assert_eq!(SIPRAL_FEATURE_TURN_STREAM, 1024);
    }

    /// The engine's bit is this crate's answer, and it is set exactly where
    /// `sipral-audio` has a backend for the platform the test runs on.
    #[test]
    fn the_audio_engine_reads_present_exactly_where_the_platform_has_a_backend() {
        assert_eq!(
            read().features & SIPRAL_FEATURE_AUDIO_DEVICE != 0,
            sipral_audio::platform_has_backend()
        );
        assert_eq!(
            read().features & SIPRAL_FEATURE_AUDIO_DEVICE != 0,
            cfg!(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "windows"
            ))
        );
        assert_eq!(SIPRAL_FEATURE_AUDIO_DEVICE, 2048);
    }

    /// Moving a call with the network is the facade's answer as well, and
    /// has no feature of its own to be missing from.
    #[test]
    fn moving_a_call_with_the_network_reads_present_exactly_when_the_facade_says() {
        assert_eq!(
            read().features & SIPRAL_FEATURE_CALL_READDRESS != 0,
            Capabilities::of_this_build().call_readdress
        );
        assert_eq!(SIPRAL_FEATURE_CALL_READDRESS, 1 << 13);
    }

    #[test]
    fn caller_identity_reads_present_exactly_when_the_facade_says() {
        assert_eq!(
            read().features & SIPRAL_FEATURE_CALLER_IDENTITY != 0,
            Capabilities::of_this_build().caller_identity
        );
        assert_eq!(SIPRAL_FEATURE_CALLER_IDENTITY, 1 << 12);
    }

    #[test]
    fn a_null_out_parameter_is_a_bad_argument() {
        let status = unsafe { sipral_capabilities(std::ptr::null_mut()) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn a_capabilities_struct_that_declares_the_wrong_size_is_refused() {
        let mut out = zeroed();
        out.size = size_of::<SipralCapabilities>() - 1;
        let status = unsafe { sipral_capabilities(&raw mut out) };
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(out.codec_count, usize::MAX, "nothing was written");
    }

    #[test]
    fn asking_twice_answers_the_same_way() {
        assert_eq!(read().features, read().features);
        assert_eq!(read().transports, read().transports);
    }
}
