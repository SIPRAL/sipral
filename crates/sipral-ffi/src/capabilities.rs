// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What this build supports, across the boundary (D8, and B2 seen from outside).
//!
//! [`sipral_capabilities`] answers before any stack exists: codecs, signalling
//! transports and compiled-in features. An application reads it at start-up and
//! greys out the controls this build cannot honour.
//!
//! [`sipral::Capabilities::of_this_build`] answers for the `sipral` crate; this
//! module answers for the ABI. They may differ: a feature `UserAgent` has but
//! this ABI has no entry point for reads absent here.

use sipral::{Capabilities, SrtpKeying};
use sipral_ua::TransportProtocol;

use crate::abi::{constants, record};
use crate::error::entry;
use crate::stack::SipralTransport;
use crate::versioned::{Versioned, write_versioned};

constants! {
    /// Bits of [`SipralCapabilities::transports`]. A transport this ABI has no
    /// bit for yet reads as absent.
    ///
    /// Derived from [`SipralTransport`]'s numbers (`1 << (value - 1)`), so the
    /// two numberings never have to be kept in step by hand.
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
    /// See [`SIPRAL_FEATURE_DTMF`]. Opus is behind a compile-time feature
    /// (libopus is licensed, not written here). Set from the codec catalogue,
    /// not from a crate feature flag. `SIPRAL_CODEC_OPUS` keeps its number either way.
    pub const SIPRAL_FEATURE_OPUS: u32 = 1 << 6;
    /// DTLS-SRTP (RFC 5764): media keys come from a handshake on the media path.
    ///
    /// Behind a compile-time feature. `SIPRAL_SRTP_DTLS` and
    /// `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers in a build without it and
    /// answer `SIPRAL_STATUS_NOT_SUPPORTED` there, never an unencrypted call.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    pub const SIPRAL_FEATURE_DTLS_SRTP: u32 = 1 << 7;
    /// See [`SIPRAL_FEATURE_DTMF`]. ICE in the full role (RFC 8445), with
    /// consent freshness (RFC 7675) and the SDP attributes of RFC 8839.
    ///
    /// Behind a compile-time feature and off by policy (`docs/06-nat.md`).
    /// `SIPRAL_ICE_OFFERED` and `SIPRAL_ICE_REQUIRED` keep their numbers in a
    /// build without it and answer `SIPRAL_STATUS_NOT_SUPPORTED` there.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    pub const SIPRAL_FEATURE_ICE: u32 = 1 << 8;
    /// See [`SIPRAL_FEATURE_DTMF`]. STUN (RFC 8489): a stack created with
    /// `SIPRAL_NAT_STUN` learns its public address and writes it in `Contact`,
    /// `c=` and `m=`. Without the feature, `SIPRAL_NAT_STUN` answers
    /// `SIPRAL_STATUS_NOT_SUPPORTED`.
    pub const SIPRAL_FEATURE_STUN: u32 = 1 << 9;
    /// See [`SIPRAL_FEATURE_DTMF`]. A TURN server over TCP or TLS
    /// (RFC 8656 §3.1): `sipral_stack_config_t::turn_transport` and
    /// `SIPRAL_EVENT_KIND_TURN_STREAM`. Comes with `SIPRAL_FEATURE_ICE`;
    /// without it a non-UDP `turn_transport` answers `SIPRAL_STATUS_NOT_SUPPORTED`.
    pub const SIPRAL_FEATURE_TURN_STREAM: u32 = 1 << 10;
    /// See [`SIPRAL_FEATURE_DTMF`]. The built-in audio engine
    /// (`sipral_stack_config_t::audio` = `SIPRAL_AUDIO_DEVICE`, and the
    /// `sipral_audio_*` entry points). Clear where there is no backend (Linux,
    /// Android below API 28); `SIPRAL_AUDIO_DEVICE` then answers
    /// `SIPRAL_STATUS_NOT_SUPPORTED`. On Android it is the phone's answer, read
    /// at call time. This crate's own answer: the engine is not under the facade.
    pub const SIPRAL_FEATURE_AUDIO_DEVICE: u32 = 1 << 11;
    /// See [`SIPRAL_FEATURE_DTMF`]. Caller identity on every call event:
    /// asserted identity behind `trusted_peers` (RFC 3325), `verstat`,
    /// `Privacy`, `Diversion`, `History-Info`, `Answer-Mode`, `Alert-Info`;
    /// end causes (RFC 3326) and `sipral_call_hangup_for`;
    /// `sipral_call_redirect`; an account's `privacy` and `session_timer`.
    pub const SIPRAL_FEATURE_CALLER_IDENTITY: u32 = 1 << 12;
    /// See [`SIPRAL_FEATURE_DTMF`]. A call follows a network change:
    /// `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` and `sipral_call_media_readdress`.
    pub const SIPRAL_FEATURE_CALL_READDRESS: u32 = 1 << 13;
    /// See [`SIPRAL_FEATURE_DTMF`]. The redacted, rate-limited log callback
    /// (`sipral_stack_log`) and the state snapshot (`sipral_stack_state_text`).
    /// Set in every build.
    pub const SIPRAL_FEATURE_LOGGING: u32 = 1 << 14;
    /// See [`SIPRAL_FEATURE_DTMF`]. Stack ceilings (`max_dialogs`,
    /// `max_server_transactions`, `diagnostic_decisions`, `diagnostic_records`),
    /// `SIPRAL_STATUS_LIMIT_REACHED`, and the counters in `sipral_counters_t`.
    pub const SIPRAL_FEATURE_LIMITS: u32 = 1 << 15;
    /// See [`SIPRAL_FEATURE_DTMF`]. STIR/SHAKEN (RFC 8224, RFC 8588): signing
    /// (`stir_key`, `stir_certificate_url`) and verification
    /// (`sipral_stack_stir`, `SIPRAL_EVENT_KIND_CALLER_VERIFICATION`,
    /// `sipral_call_stir_certificate`). Behind a compile-time feature, on by default.
    pub const SIPRAL_FEATURE_STIR: u32 = 1 << 16;
    /// See [`SIPRAL_FEATURE_DTMF`]. SRTP policy and suites per account,
    /// `SIPRAL_SRTP_DTLS_OR_SDES`, `SIPRAL_STATUS_SECURITY_POLICY`, and
    /// `sipral_media_encryption_at`.
    pub const SIPRAL_FEATURE_SRTP_POLICY: u32 = 1 << 17;
    /// See [`SIPRAL_FEATURE_DTMF`]. In-band signals: DTMF detection
    /// (`sipral_stack_config_t::dtmf_detection`, `sipral_call_dtmf_detection`,
    /// `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`) and generation (`SIPRAL_DTMF_IN_BAND`),
    /// progress and answering-machine detection (`sipral_call_detect_progress`,
    /// `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`), and `sipral_call_consent_tone`.
    pub const SIPRAL_FEATURE_IN_BAND_SIGNALS: u32 = 1 << 18;
    /// See [`SIPRAL_FEATURE_DTMF`]. Recording formats
    /// (`sipral_media_record_start_with`): mixed or stereo, WAV/RF64,
    /// checkpointed, Ogg Opus with [`SIPRAL_FEATURE_OPUS`]; and L16 at 8 and 16 kHz.
    pub const SIPRAL_FEATURE_RECORDING_FORMATS: u32 = 1 << 19;
    /// See [`SIPRAL_FEATURE_DTMF`]. SIPREC (RFC 7866): `sipral_call_record_to`
    /// and `sipral_media_poll_recording`.
    pub const SIPRAL_FEATURE_SIPREC: u32 = 1 << 20;
    /// See [`SIPRAL_FEATURE_DTMF`]. Conference package (RFC 4575,
    /// `sipral_subscription_conference`), focus `isfocus` (RFC 4579,
    /// `sipral_call_conference_uri`), presence publish (RFC 3903) and watch (RFC 3856).
    pub const SIPRAL_FEATURE_CONFERENCE: u32 = 1 << 21;
    /// See [`SIPRAL_FEATURE_DTMF`]. Real-time text (RFC 4103): `text_address`,
    /// `sipral_media_send_text`, `SIPRAL_EVENT_KIND_TEXT_RECEIVED`.
    pub const SIPRAL_FEATURE_REALTIME_TEXT: u32 = 1 << 22;
    /// See [`SIPRAL_FEATURE_DTMF`]. RTP/AVPF with Generic NACK and reduced-size
    /// RTCP (RFC 4585, RFC 5506): `feedback`, reported in `sipral_media_info_t`.
    pub const SIPRAL_FEATURE_RTCP_FEEDBACK: u32 = 1 << 23;
    /// See [`SIPRAL_FEATURE_DTMF`]. A local conference of calls on any codec
    /// and rate: `sipral_local_conference_create`,
    /// `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`.
    pub const SIPRAL_FEATURE_LOCAL_CONFERENCE: u32 = 1 << 24;
}

record! {
    /// What this build can do: codecs, signalling transports, optional features.
    ///
    /// Not configuration: `sipral_stack_settings` answers what a stack has on.
    ///
    /// Set `size` to `sizeof(sipral_capabilities_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralCapabilities {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// How many codecs this build contains (same as `sipral_codec_count`).
        pub codec_count: usize,
        /// Transports for signalling, as `SIPRAL_TRANSPORT_BIT_*` bits.
        pub transports: u32,
        /// Compiled-in features, as `SIPRAL_FEATURE_*` bits.
        pub features: u32,
    }
}

// Safety: integers only, zero is valid for each.
unsafe impl Versioned for SipralCapabilities {
    const NAME: &'static str = "sipral_capabilities";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralCapabilities, features);

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
        // a transport this ABI has no bit for: say nothing rather than guess
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
    // opus: from the facade's answer, not this crate's `opus` feature. Cargo
    // features are per-crate, so this crate's flag can be off over a facade
    // that linked the codec.
    if capabilities.opus {
        features |= SIPRAL_FEATURE_OPUS;
    }
    if capabilities.subscriptions {
        features |= SIPRAL_FEATURE_SUBSCRIPTIONS;
    }
    // from the facade's list, for the reason the Opus bit gives
    if capabilities.srtp_keying.contains(&SrtpKeying::Dtls) {
        features |= SIPRAL_FEATURE_DTLS_SRTP;
    }
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
    // this crate's own surface, present in every build
    features |= SIPRAL_FEATURE_LIMITS;
    if capabilities.logging {
        features |= SIPRAL_FEATURE_LOGGING;
    }
    if capabilities.stir {
        features |= SIPRAL_FEATURE_STIR;
    }
    if capabilities.srtp_per_account {
        features |= SIPRAL_FEATURE_SRTP_POLICY;
    }
    if capabilities.in_band_signals {
        features |= SIPRAL_FEATURE_IN_BAND_SIGNALS;
    }
    if capabilities.recording_formats {
        features |= SIPRAL_FEATURE_RECORDING_FORMATS;
    }
    if capabilities.siprec {
        features |= SIPRAL_FEATURE_SIPREC;
    }
    if capabilities.conference_and_presence {
        features |= SIPRAL_FEATURE_CONFERENCE;
    }
    if capabilities.realtime_text {
        features |= SIPRAL_FEATURE_REALTIME_TEXT;
    }
    if capabilities.rtcp_feedback {
        features |= SIPRAL_FEATURE_RTCP_FEEDBACK;
    }
    if capabilities.local_conference {
        features |= SIPRAL_FEATURE_LOCAL_CONFERENCE;
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
    /// Answers the same before and after any stack exists. Safe from any
    /// thread, including the event callback.
    ///
    /// # Safety
    ///
    /// `out_capabilities` must point at a `sipral_capabilities_t` whose
    /// `size` member says how long it is.
    fn sipral_capabilities(out_capabilities: *mut SipralCapabilities) {
        // size checked first, so a wrong size is reported, not half-filled
        unsafe { crate::versioned::declared_size(out_capabilities.cast_const()) }?;
        let capabilities = capabilities_of(Capabilities::of_this_build());
        unsafe { write_versioned(out_capabilities, capabilities) }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SIPRAL_FEATURE_AUDIO_DEVICE, SIPRAL_FEATURE_CALL_READDRESS, SIPRAL_FEATURE_CALLER_IDENTITY,
        SIPRAL_FEATURE_CONFERENCE, SIPRAL_FEATURE_DTMF, SIPRAL_FEATURE_ICE, SIPRAL_FEATURE_LIMITS,
        SIPRAL_FEATURE_LOCAL_CONFERENCE, SIPRAL_FEATURE_LOGGING,
        SIPRAL_FEATURE_MEDIA_STALL_WATCHDOG, SIPRAL_FEATURE_OPUS, SIPRAL_FEATURE_REALTIME_TEXT,
        SIPRAL_FEATURE_RECORDING, SIPRAL_FEATURE_RTCP_FEEDBACK, SIPRAL_FEATURE_RTCP_MUX,
        SIPRAL_FEATURE_SIPREC, SIPRAL_FEATURE_SRTP, SIPRAL_FEATURE_SRTP_POLICY,
        SIPRAL_FEATURE_STIR, SIPRAL_FEATURE_SUBSCRIPTIONS, SIPRAL_FEATURE_TURN_STREAM,
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

    /// The bit and the codec list must agree. Checked against the catalogue,
    /// not `cfg!(feature = "opus")`: this crate's flag can be off over a facade
    /// built with `sipral/opus`.
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

    /// The protocol bits are the facade's answers, at their published numbers.
    #[test]
    fn the_protocol_bits_read_what_the_facade_says() {
        let features = read().features;
        let facade = Capabilities::of_this_build();
        for (bit, number, present) in [
            (SIPRAL_FEATURE_SIPREC, 20, facade.siprec),
            (
                SIPRAL_FEATURE_CONFERENCE,
                21,
                facade.conference_and_presence,
            ),
            (SIPRAL_FEATURE_REALTIME_TEXT, 22, facade.realtime_text),
            (SIPRAL_FEATURE_RTCP_FEEDBACK, 23, facade.rtcp_feedback),
            (SIPRAL_FEATURE_LOCAL_CONFERENCE, 24, facade.local_conference),
        ] {
            assert_eq!(bit, 1 << number);
            assert_eq!(features & bit != 0, present, "bit {number}");
            assert!(present, "bit {number} is in every build");
        }
    }

    #[test]
    fn subscriptions_read_present_now_that_this_abi_reaches_one() {
        // catches an entry point removed without the bit following it
        assert_eq!(
            read().features & SIPRAL_FEATURE_SUBSCRIPTIONS != 0,
            Capabilities::of_this_build().subscriptions,
            "the bit is the facade's answer and not a second opinion"
        );
        assert!(read().features & SIPRAL_FEATURE_SUBSCRIPTIONS != 0);
    }

    /// TURN over a stream is the facade's answer and comes with ICE.
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

    /// This crate's answer: set where `sipral-audio` has a backend.
    #[test]
    fn the_audio_engine_reads_present_exactly_where_the_platform_has_a_backend() {
        assert_eq!(
            read().features & SIPRAL_FEATURE_AUDIO_DEVICE != 0,
            sipral_audio::platform_has_backend()
        );
        // on Android it depends on the phone's API level
        if cfg!(not(target_os = "android")) {
            assert_eq!(
                read().features & SIPRAL_FEATURE_AUDIO_DEVICE != 0,
                cfg!(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "windows"
                ))
            );
        }
        assert_eq!(SIPRAL_FEATURE_AUDIO_DEVICE, 2048);
    }

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
    fn logging_reads_present_in_every_build_of_this_library() {
        assert!(Capabilities::of_this_build().logging);
        assert_ne!(read().features & SIPRAL_FEATURE_LOGGING, 0);
        assert_eq!(SIPRAL_FEATURE_LOGGING, 1 << 14);
    }

    #[test]
    fn every_build_has_the_limits_and_their_counters() {
        assert_ne!(read().features & SIPRAL_FEATURE_LIMITS, 0);
        assert_eq!(SIPRAL_FEATURE_LIMITS, 1 << 15);
    }

    #[test]
    fn stir_and_the_srtp_policy_read_present_exactly_when_the_facade_says() {
        let features = read().features;
        assert_eq!(
            features & SIPRAL_FEATURE_STIR != 0,
            Capabilities::of_this_build().stir
        );
        assert_eq!(features & SIPRAL_FEATURE_STIR != 0, cfg!(feature = "stir"));
        assert_ne!(features & SIPRAL_FEATURE_SRTP_POLICY, 0);
        assert_eq!(SIPRAL_FEATURE_STIR, 1 << 16);
        assert_eq!(SIPRAL_FEATURE_SRTP_POLICY, 1 << 17);
    }

    #[test]
    fn in_band_signals_and_recording_formats_read_as_the_facade_says() {
        let facade = Capabilities::of_this_build();
        assert_eq!(
            read().features & super::SIPRAL_FEATURE_IN_BAND_SIGNALS != 0,
            facade.in_band_signals
        );
        assert_eq!(
            read().features & super::SIPRAL_FEATURE_RECORDING_FORMATS != 0,
            facade.recording_formats
        );
        assert_eq!(super::SIPRAL_FEATURE_IN_BAND_SIGNALS, 1 << 18);
        assert_eq!(super::SIPRAL_FEATURE_RECORDING_FORMATS, 1 << 19);
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
