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
//! two are not always the same build — subscriptions are wired into
//! `UserAgent` (RFC 6665, and the busy-lamp field on top of it) with no C
//! entry point in front of them, because `SIPRAL_EVENT_KIND` 15 is still
//! reserved (`docs/08-ffi.md`) and nothing here can deliver the event a
//! binding would need to use one. [`SIPRAL_FEATURE_SUBSCRIPTIONS`] is
//! therefore never set by this build, and will be the day event 15 stops
//! being reserved and starts being a kind — the derivation changes with the
//! ABI, not with a note in this comment.

use sipral::Capabilities;
use sipral_ua::TransportProtocol;

use crate::error::entry;
use crate::stack::SipralTransport;
use crate::versioned::{Versioned, write_versioned};

/// Bits of [`SipralCapabilities::transports`]. A caller checks
/// `capabilities.transports & SIPRAL_TRANSPORT_BIT_TLS != 0` rather than a
/// growing list of booleans, so a transport this ABI has not learned a bit
/// for yet reads as absent rather than refusing to compile against an older
/// header.
///
/// Named after [`SipralTransport`]'s own numbers (`1 << (value - 1)`), so a
/// transport added there in the future gets a bit here without the two
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
/// See [`SIPRAL_FEATURE_DTMF`], and the module documentation for why this
/// build never sets it.
pub const SIPRAL_FEATURE_SUBSCRIPTIONS: u32 = 1 << 5;

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
#[repr(C)]
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

// Safety: integers, no invariant between them, and zero is a valid value of
// each.
unsafe impl Versioned for SipralCapabilities {
    const NAME: &'static str = "sipral_capabilities";
    const MIN_SIZE: usize = size_of::<Self>();

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
    // subscriptions: sipral_ua::UserAgent has them, this ABI has no entry
    // point that reaches one yet (event kind 15 is reserved), so the honest
    // answer here is the ABI's and not the crate underneath it — see the
    // module documentation
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
        SIPRAL_FEATURE_DTMF, SIPRAL_FEATURE_MEDIA_STALL_WATCHDOG, SIPRAL_FEATURE_RECORDING,
        SIPRAL_FEATURE_RTCP_MUX, SIPRAL_FEATURE_SRTP, SIPRAL_FEATURE_SUBSCRIPTIONS,
        SIPRAL_TRANSPORT_BIT_TCP, SIPRAL_TRANSPORT_BIT_TLS, SIPRAL_TRANSPORT_BIT_UDP,
        SIPRAL_TRANSPORT_BIT_WS, SIPRAL_TRANSPORT_BIT_WSS, SipralCapabilities, sipral_capabilities,
    };
    use crate::error::last_error_text;
    use crate::status::SipralStatus;
    use sipral::Codec;

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

    #[test]
    fn subscriptions_read_absent_because_this_abi_has_no_entry_point_for_one() {
        // sipral_ua::UserAgent can subscribe; this crate cannot yet ask it
        // to, so the honest answer for the ABI is off, not the crate
        // underneath it
        assert_eq!(read().features & SIPRAL_FEATURE_SUBSCRIPTIONS, 0);
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
