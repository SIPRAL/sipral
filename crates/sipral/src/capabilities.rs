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
//! anybody updating a second list; [`Capabilities::opus`] is that same list
//! read for one codec rather than a second copy of the feature that fills
//! it; the transport list names the protocols `sipral-core`'s endpoint has
//! logic for, and not a socket this crate has never opened. A capability
//! list that can drift from the build it describes is worse than none,
//! because it is believed.

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
    /// Listed only where the `dtls` feature put a handshake behind it. In a
    /// build without it, `sipral-core` still reads an `a=fingerprint` and
    /// carries it through, and nothing can produce a key from it: a plan
    /// keyed this way is then refused with
    /// [`MediaError::NoDtlsSrtp`](crate::MediaError::NoDtlsSrtp) rather than
    /// opened in the clear, which is the behaviour that absence is derived
    /// from.
    Dtls,
}

/// Whether a catalogue contains Opus, walked rather than asked of a `cfg`.
///
/// What a build can encode is the catalogue and nothing else, and this is
/// the one place that reads it for a single codec, so that every layer above
/// — [`Capabilities::opus`], and the C ABI's `SIPRAL_FEATURE_OPUS` on top of
/// it — answers from the same fact instead of from whichever crate's feature
/// flag was nearest.
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

/// The key exchanges a call on this build can actually complete.
///
/// Not "the ones SRTP defines" and not "the ones something in this workspace
/// has a type for": the ones a call placed or answered through
/// [`MediaEngine`](crate::MediaEngine) reaches. SDES always, and DTLS-SRTP
/// wherever the `dtls` feature put a handshake behind it.
#[cfg(feature = "dtls")]
const KEYING: [SrtpKeying; 2] = [SrtpKeying::Sdes, SrtpKeying::Dtls];

/// Without the feature there is no handshake, no certificate and nothing that
/// could produce a key on the media path, so the list is one long and a plan
/// keyed by a handshake is refused where it arrives.
#[cfg(not(feature = "dtls"))]
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
    /// SDES is always in it. DTLS-SRTP joins it when the `dtls` feature is
    /// compiled in, which it is by default; a build without it keeps the
    /// enumeration's variant and leaves the slice short, so that the absence
    /// is something an application can read rather than something it has to
    /// know.
    pub srtp_keying: &'static [SrtpKeying],
    /// Whether RFC 6665 subscriptions and the dialog-state package this
    /// crate wraps ([`sipral_ua::UserAgent::subscribe`]) are compiled in.
    pub subscriptions: bool,
    /// Whether this build has an Opus encoder and decoder, which is
    /// [`Capabilities::codecs`] containing it and never a fact of its own.
    ///
    /// The one codec a build can be without, because it is licensed rather
    /// than written — `docs/05-media.md` says which customer needs it out.
    /// It is a field and not a `cfg` a caller writes for itself so that a
    /// crate above this one answers the question from this build's
    /// catalogue: a Cargo feature belongs to the crate that declares it, and
    /// another crate's is not evidence about this one.
    pub opus: bool,
    /// Whether this build can run ICE in the full role (RFC 8445), which is
    /// what makes [`IcePolicy::Offered`] and [`IcePolicy::Required`] mean
    /// anything.
    ///
    /// Behind a compile-time feature for the reason DTLS-SRTP is: a build
    /// that will only ever place calls to one PBX on one network has no use
    /// for a checklist, and off is what the policy defaults to anyway. The
    /// numbers the ABI gives the two policies keep their values in a build
    /// without it, and naming one there is refused rather than quietly
    /// placing the call on a path nothing checked.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`: a connectivity check that never leaves
    /// is a call that never chooses a path.
    ///
    /// [`IcePolicy::Offered`]: crate::IcePolicy::Offered
    /// [`IcePolicy::Required`]: crate::IcePolicy::Required
    pub ice: bool,
    /// Whether this build can ask a STUN server where its sockets appear
    /// from (RFC 8489): `Mappings`, and the public address it puts in a
    /// `Contact` and a `c=` line.
    ///
    /// Behind a compile-time feature of its own. Without it a call can still
    /// be described by a public address the application knows some other
    /// way — [`CallMedia::public_address`] takes one from anywhere — and only
    /// the asking is gone.
    ///
    /// [`CallMedia::public_address`]: crate::CallMedia::public_address
    pub stun: bool,
    /// Whether a relay can reach its TURN server over TCP or over TLS
    /// (RFC 8656 §3.1) as well as over UDP: [`Relays::over`], for the
    /// network that lets no UDP out. The connection is the application's,
    /// and for TLS so is the handshake, with the platform's own stack.
    ///
    /// It comes with [`Capabilities::ice`], since a relay is only ever a
    /// call's relayed ICE candidate.
    ///
    /// [`Relays::over`]: crate::Relays::over
    pub turn_streams: bool,
    /// Whether a call in progress can be described at a new address after
    /// the network under it changed: [`MediaEngine::readdress`], asked for by
    /// [`UaEvent::CallAddressWanted`](crate::UaEvent::CallAddressWanted).
    ///
    /// [`MediaEngine::readdress`]: crate::MediaEngine::readdress
    pub call_readdress: bool,
    /// Whether an incoming call's typed identity (RFC 3325's asserted
    /// identity behind a per-account trust gate, `Diversion`,
    /// `History-Info`, `verstat`, `Privacy`), how it asked to be answered
    /// (RFC 5373, `Alert-Info`), why a call ended (RFC 3326) and a 3xx
    /// redirect are all read and written.
    pub caller_identity: bool,
    /// Whether the engine can write a log through a sink the application
    /// installs ([`crate::Log`]) and take a snapshot of its state for a crash
    /// report ([`crate::MediaEngine::state`]). Both redact what they write,
    /// so both come with the `redaction` feature, on by default.
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
    /// Whether what a call carries inside its audio is heard and written:
    /// keypad digits in the audio both ways ([`crate::DtmfDetection`],
    /// [`crate::MediaSession::dial_in_band`]), call-progress tones and who
    /// answered ([`crate::ProgressDetection`]), and the beep that says a call
    /// is recorded ([`crate::ConsentTone`]).
    pub in_band_signals: bool,
    /// Whether a recording can be written as [`crate::RecordingOptions`]
    /// says — mixed or stereo, WAV growing into RF64, at a rate of its own,
    /// checkpointed against a crash — and in Ogg Opus where
    /// [`Capabilities::opus`] is true too.
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
        assert!(capabilities.in_band_signals);
        assert!(capabilities.recording_formats);
    }

    /// The two ways of asking "does this build have Opus" have to agree,
    /// because everything above reads one of them: the flag is what the C
    /// ABI's `SIPRAL_FEATURE_OPUS` is derived from, and the catalogue is
    /// what a negotiation actually offers. A build whose flag said yes and
    /// whose catalogue had nothing in it would grey in a control that
    /// negotiates nothing.
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

    /// Every claim is checked against the behaviour rather than restated: an
    /// offer written under a policy that asks for SDES has to name the secure
    /// profile and carry a key, and a plan keyed by a handshake has to be
    /// opened waiting where the build has one and refused where it does not.
    #[test]
    fn the_keying_this_build_lists_is_the_keying_a_call_can_reach() {
        let capabilities = Capabilities::of_this_build();
        assert!(capabilities.srtp_keying.contains(&SrtpKeying::Sdes));
        assert_eq!(
            capabilities.srtp,
            !capabilities.srtp_keying.is_empty(),
            "the flag is the list and not a second opinion about it"
        );

        // one key per suite crate::keying::OFFERED names, in that order:
        // AEAD_AES_256_GCM, then AES_CM_128_HMAC_SHA1_80
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
            rtcp: RtcpPlan::Off,
            keying: Some(Keying::Dtls {
                fingerprints: vec!["sha-256 AA:BB".to_owned()],
                setup: None,
            }),
            voip_metrics_xr: false,
        };
        // the list and the code that reads a plan have to agree: a build that
        // does not list DTLS-SRTP must refuse a plan keyed that way rather
        // than open it in the clear, and a build that lists it must open the
        // stream waiting for the handshake rather than refuse it
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
