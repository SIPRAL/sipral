// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One machine-readable answer to "what does this build support" (D8, and B2 seen from outside).
//!
//! B2 promises a setting answers `applied`, `rejected` or `not supported in this build`. D8 lets an
//! application ask once at start-up which controls this build can honour, and grey out the rest.
//!
//! # Derived, not maintained
//!
//! [`Capabilities::of_this_build`] reads facts from where they already live: the codec list is
//! [`Codec::ALL`], [`Capabilities::opus`] is that list read for one codec, and the transports are
//! the ones `sipral-core`'s endpoint implements. A capability list that can drift from the build is
//! worse than none, because people believe it.

use sipral_ua::TransportProtocol;

use crate::codec::Codec;

/// Every transport [`sipral_core`]'s endpoint implements: framing, RFC 3261 §17 timers, `Via`
/// contents.
///
/// Not a promise the platform can open one; this crate opens no sockets.
const TRANSPORTS: [TransportProtocol; 5] = [
    TransportProtocol::Udp,
    TransportProtocol::Tcp,
    TransportProtocol::Tls,
    TransportProtocol::Ws,
    TransportProtocol::Wss,
];

/// How a stream on this build can get keys. An enum, so a missing exchange is simply absent from
/// [`Capabilities::srtp_keying`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SrtpKeying {
    /// RFC 4568 `a=crypto`, keyed from the seeded token stream, per call; see
    /// [`SrtpPolicy`](crate::SrtpPolicy).
    Sdes,
    /// RFC 5764 handshake on the media path.
    ///
    /// Listed only with the `dtls` feature. Without it a DTLS-keyed plan is refused with
    /// [`MediaError::NoDtlsSrtp`](crate::MediaError::NoDtlsSrtp) instead of opening in the clear.
    Dtls,
}

/// Whether a catalogue contains Opus, by walking it rather than asking a `cfg`, so
/// [`Capabilities::opus`] and the C ABI's `SIPRAL_FEATURE_OPUS` answer from the catalogue and not
/// from some crate's feature flag.
const fn contains_opus(codecs: &[Codec]) -> bool {
    let mut rest = codecs;
    while let Some((codec, tail)) = rest.split_first() {
        if codec.is_opus() {
            return true;
        }
        rest = tail;
    }
    false
}

/// The key exchanges a call through [`MediaEngine`](crate::MediaEngine) can complete: SDES always,
/// DTLS-SRTP with the `dtls` feature.
#[cfg(feature = "dtls")]
const KEYING: [SrtpKeying; 2] = [SrtpKeying::Sdes, SrtpKeying::Dtls];

/// Without the feature only SDES; DTLS-keyed plans are refused.
#[cfg(not(feature = "dtls"))]
const KEYING: [SrtpKeying; 1] = [SrtpKeying::Sdes];

/// What this build can do.
///
/// About the build, not one stack's configuration: [`crate::CodecCatalog::with_order`] narrows what
/// one [`crate::MediaEngine`] offers without changing this. Read this once to decide which controls
/// to show; read [`crate::CodecCatalog`] or the FFI's `sipral_stack_settings` for what an instance
/// is doing.
// independent yes/no facts about the build, not states
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// What [`crate::CodecCatalog::new`] offers by default, best first. Its length is the count.
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
    /// Whether a stream can be keyed at all: [`Capabilities::srtp_keying`] is non-empty.
    pub srtp: bool,
    /// Which key exchanges a call can complete, so which controls are worth showing. SDES always;
    /// DTLS-SRTP with the default `dtls` feature. Without it the slice is shorter, so applications
    /// can read the absence.
    pub srtp_keying: &'static [SrtpKeying],
    /// Whether RFC 6665 subscriptions and the dialog-state package this
    /// crate wraps ([`sipral_ua::UserAgent::subscribe`]) are compiled in.
    pub subscriptions: bool,
    /// Whether this build has Opus: [`Capabilities::codecs`] contains it.
    ///
    /// The only optional codec, because it is linked rather than written (`docs/05-media.md`). A
    /// field instead of a `cfg` because another crate's feature flags say nothing about this one.
    pub opus: bool,
    /// Whether this build runs full-role ICE (RFC 8445), which [`IcePolicy::Offered`] and
    /// [`IcePolicy::Required`] need.
    ///
    /// A compile-time feature like DTLS-SRTP. Without it the ABI values for those policies stay,
    /// and selecting one is refused rather than placing the call on an unchecked path. An
    /// application using either policy must drain `sipral_media_poll_transmit`, or checks never
    /// leave.
    ///
    /// [`IcePolicy::Offered`]: crate::IcePolicy::Offered
    /// [`IcePolicy::Required`]: crate::IcePolicy::Required
    pub ice: bool,
    /// Whether this build can ask a STUN server where its sockets appear (RFC 8489): `Mappings`,
    /// and the public address in `Contact` and `c=`.
    ///
    /// Without the feature a public address known another way still works through
    /// [`CallMedia::public_address`].
    ///
    /// [`CallMedia::public_address`]: crate::CallMedia::public_address
    pub stun: bool,
    /// Whether a relay can reach its TURN server over TCP or TLS as well as UDP (RFC 8656 §3.1):
    /// [`Relays::over`]. The application owns the connection and, for TLS, the handshake. Comes
    /// with [`Capabilities::ice`].
    ///
    /// [`Relays::over`]: crate::Relays::over
    pub turn_streams: bool,
    /// Whether a call in progress can be described at a new address after
    /// the network under it changed: [`MediaEngine::readdress`], asked for by
    /// [`UaEvent::CallAddressWanted`](crate::UaEvent::CallAddressWanted).
    ///
    /// [`MediaEngine::readdress`]: crate::MediaEngine::readdress
    pub call_readdress: bool,
    /// Whether incoming caller identity (RFC 3325 asserted identity behind a per-account trust
    /// gate, `Diversion`, `History-Info`, `verstat`, `Privacy`), answer mode (RFC 5373,
    /// `Alert-Info`), call end reason (RFC 3326) and 3xx redirects are read and written.
    pub caller_identity: bool,
    /// Whether the engine can log through an application sink ([`crate::Log`]) and snapshot its
    /// state for crash reports ([`crate::MediaEngine::state`]). Both redact, so both need the
    /// default `redaction` feature.
    pub logging: bool,
    /// Whether an account can sign the calls it places and have the callers
    /// of the ones it receives verified (STIR/SHAKEN, RFC 8224 and RFC 8588):
    /// [`crate::StirSigning`], [`crate::StirConfig`]. Behind the `stir`
    /// feature, on by default.
    pub stir: bool,
    /// Whether each account can hold its calls to an SRTP policy and suites
    /// of its own ([`crate::MediaEngine::set_account_srtp`]), and each call
    /// report how its streams are protected ([`crate::MediaSession::encryption`]).
    /// In every build.
    pub srtp_per_account: bool,
    /// Whether in-band signals are handled: DTMF in the audio both ways ([`crate::DtmfDetection`],
    /// [`crate::MediaSession::dial_in_band`]), call progress and answer detection
    /// ([`crate::ProgressDetection`]), and the recording beep ([`crate::ConsentTone`]).
    pub in_band_signals: bool,
    /// Whether recordings follow [`crate::RecordingOptions`]: mixed or stereo, WAV/RF64, own rate,
    /// crash checkpoints, and Ogg Opus when [`Capabilities::opus`] is true.
    pub recording_formats: bool,
    /// Whether a call can be recorded to a recording server (SIPREC, RFC
    /// 7866): [`crate::MediaEngine::record_to`].
    pub siprec: bool,
    /// Whether the conference package (RFC 4575) is kept by the agent,
    /// `isfocus` read and written (RFC 4579), and presence published (RFC
    /// 3903) and watched (RFC 3856).
    pub conference_and_presence: bool,
    /// Whether a call can carry real-time text (RFC 4103):
    /// [`crate::CallMedia::text`].
    pub realtime_text: bool,
    /// Whether a call can negotiate RTP/AVPF and reduced-size RTCP (RFC
    /// 4585, RFC 5506): [`crate::CodecCatalog::with_feedback`].
    pub rtcp_feedback: bool,
    /// Whether calls on different codecs and rates can be mixed into one conference, with or
    /// without this end: [`crate::LocalConference`].
    pub local_conference: bool,
}

impl Capabilities {
    /// What this build of the `sipral` crate can do. No `&self`: capabilities differ between
    /// builds, not between engines.
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
            opus: contains_opus(&Codec::ALL),
            ice: cfg!(feature = "ice"),
            stun: cfg!(feature = "stun"),
            turn_streams: cfg!(feature = "ice"),
            call_readdress: true,
            caller_identity: true,
            logging: cfg!(feature = "redaction"),
            stir: cfg!(feature = "stir"),
            srtp_per_account: true,
            in_band_signals: true,
            recording_formats: true,
            siprec: true,
            conference_and_presence: true,
            realtime_text: true,
            rtcp_feedback: true,
            local_conference: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, SrtpKeying};
    use sipral_core::sdp::{Direction, KeySalt, Keying, NegotiatedCodec, RtcpPlan, RtpMap};

    use crate::codec::{Codec, CodecCatalog};
    #[cfg(not(feature = "dtls"))]
    use crate::error::MediaError;
    #[cfg(feature = "dtls")]
    use crate::keying::Opening;
    use crate::keying::{SrtpPolicy, opening};

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
        // records the current build: it fails the day one of these stops being true, which is when
        // the answer must change
        let capabilities = Capabilities::of_this_build();
        assert!(capabilities.dtmf);
        assert!(capabilities.rtcp_mux);
        assert!(capabilities.recording);
        assert!(capabilities.media_stall_watchdog);
        assert!(capabilities.srtp);
        assert!(capabilities.subscriptions);
        assert!(capabilities.in_band_signals);
        assert!(capabilities.recording_formats);
    }

    /// The Opus flag (behind `SIPRAL_FEATURE_OPUS`) and the catalogue (what is negotiated) must
    /// agree, or a UI would enable a control that negotiates nothing.
    #[test]
    fn opus_reads_present_exactly_when_the_catalogue_contains_it() {
        let capabilities = Capabilities::of_this_build();
        assert_eq!(
            capabilities.opus,
            capabilities
                .codecs
                .iter()
                .any(|codec| codec.encoding_name() == "opus"),
            "the flag and the catalogue disagree about what was linked"
        );
        assert_eq!(
            capabilities.opus,
            cfg!(feature = "opus"),
            "this crate owns the feature, so here the two are the same fact"
        );
    }

    /// Claims are checked against behaviour: an SDES offer names the secure profile and carries a
    /// key, and a DTLS-keyed plan opens waiting with the feature and is refused without it.
    #[test]
    fn the_keying_this_build_lists_is_the_keying_a_call_can_reach() {
        let capabilities = Capabilities::of_this_build();
        assert!(capabilities.srtp_keying.contains(&SrtpKeying::Sdes));
        assert_eq!(
            capabilities.srtp,
            !capabilities.srtp_keying.is_empty(),
            "the flag is the list and not a second opinion about it"
        );

        // one key per `crate::keying::OFFERED` suite, in order
        let offer = CodecCatalog::new()
            .with_srtp(SrtpPolicy::Offered)
            .offering(
                Some(vec![
                    (
                        sipral_core::sdp::CryptoSuite::AeadAes256Gcm,
                        KeySalt::new(&[3; 32], &[4; 12]),
                    ),
                    (
                        sipral_core::sdp::CryptoSuite::AesCm80,
                        KeySalt::new(&[9; 16], &[10; 14]),
                    ),
                ]),
                None,
            )
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(offer.proto, "RTP/SAVP");
        assert!(
            offer
                .attribute("crypto")
                .and_then(|line| line.value.as_deref())
                .is_some_and(|value| value.contains("inline:")),
            "SDES is listed as reachable and the offer carries no key"
        );

        assert_eq!(
            capabilities.srtp_keying.contains(&SrtpKeying::Dtls),
            cfg!(feature = "dtls"),
            "the list and the build disagree about DTLS-SRTP"
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
            dtmf_in: None,
            codec_in: 0,
            rtcp: RtcpPlan::Off,
            keying: Some(Keying::Dtls {
                fingerprints: vec!["sha-256 AA:BB".to_owned()],
                setup: None,
            }),
            voip_metrics_xr: false,
        };
        // a build that does not list DTLS-SRTP must refuse such a plan, and one that lists it must
        // open the stream waiting for the handshake
        #[cfg(feature = "dtls")]
        assert!(
            matches!(opening(&handshaken), Ok(Opening::Awaiting(_))),
            "DTLS-SRTP is listed as reachable and a plan keyed that way is not opened"
        );
        #[cfg(not(feature = "dtls"))]
        assert_eq!(
            opening(&handshaken).err(),
            Some(MediaError::NoDtlsSrtp),
            "DTLS-SRTP is left off the list, so it has to be refused where it arrives"
        );
    }
}
