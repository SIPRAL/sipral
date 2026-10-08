// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What this build can encode, in what order, and what a call settled on.
//!
//! The offer order is configuration: a carrier billing by the minute wants narrowband first, an
//! internal network wants wideband. With RFC 3264 §6.1 the peer's preference decides among what
//! both list, so the order matters.
//!
//! Three separate things: [`Codec::ALL`] is what the build contains (compile time).
//! [`CodecCatalog`] is what to offer and in what order. [`Codec::of`] is what one call agreed. A
//! codec the build lacks is **rejected where it is set**, by name, since a silently ignored setting
//! is the hardest bug to find.
//!
//! # Three numbers, not one
//!
//! Samples per frame, octets per frame and RTP ticks per frame are all 160 for G.711, but not for
//! others: G.722 is 320/160/160 (RFC 3551 §4.5.2 fixes its clock at 8000 "for historical reasons"),
//! Opus is 960/variable/960, G.729 is 160/20/160. Hence separate [`Codec::sample_rate`] and
//! [`Codec::clock_rate`].
//!
//! # In the build is not in the offer
//!
//! G.729 is in [`Codec::ALL`] but not in [`CodecCatalog::new`]: it sounds worse than the others and
//! a peer might still pick it first. A site that needs it names it ([`CodecCatalog::with_order`]).

use sipral_core::sdp::{
    KeySalt, MediaCapabilities, MediaDescription, MediaPlan, NegotiatedCodec, RtpMap, SrtpSupport,
    static_rtpmap,
};
#[cfg(feature = "opus")]
use sipral_media::opus;
use sipral_media::{g711, g722, g729, l16};
use sipral_rtp::srtp::Suite;

use crate::error::MediaError;
use crate::ice::IcePolicy;
use crate::keying::{self, SdesSignalling, SrtpPolicy};

/// Default packetisation. 20 ms is what every peer expects and every codec here cuts cleanly.
pub const DEFAULT_FRAME_MS: u32 = 20;

/// The first dynamic payload type (RFC 3551 table 5).
///
/// Assigned in offer order to codecs without a static number, which so far means Opus. Without Opus
/// the named-event type is the first to get 96; `named_events_get_a_dynamic_type_no_codec_took`
/// checks both cases.
const FIRST_DYNAMIC: u8 = 96;

const L16_NARROWBAND: u32 = 8_000;

const L16_WIDEBAND: u32 = 16_000;

/// Largest payload of one frame: the longest Opus frame (RFC 6716). The 1500-octet datagram is
/// sized around it.
const LARGEST_PAYLOAD: usize = 1_275;

/// G.729 `a=fmtp` parameters (RFC 4856 §2.1.9). Always written explicitly so readers need not know
/// the default.
const fn annex_b_parameter(allowed: bool) -> &'static str {
    if allowed { "annexb=yes" } else { "annexb=no" }
}

/// Whether a G.729 `a=fmtp` allows Annex B. A missing `annexb` means `yes` (RFC 4856 §2.1.9).
pub(crate) fn annex_b_allowed(fmtp: Option<&str>) -> bool {
    !fmtp.is_some_and(|parameters| {
        parameters.split(';').any(|parameter| {
            parameter.split_once('=').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("annexb")
                    && value.trim().eq_ignore_ascii_case("no")
            })
        })
    })
}

/// One codec this build contains, with an encoder and decoder behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Codec {
    /// G.711 mu-law, payload type 0; RFC 3551 makes it mandatory.
    Pcmu,
    /// G.711 A-law, payload type 8; the usual European default.
    Pcma,
    /// G.722: wideband at narrowband bitrate, supported by almost every PBX.
    G722,
    /// G.729 Annex A: 8 kbit/s narrowband for carriers that require it. Always built, never offered
    /// by default ([`Codec::offered_by_default`]). Annex B is used where both ends allow it
    /// ([`CodecCatalog::with_g729_annex_b`]).
    G729,
    /// Opus. The only linked (not written) codec, so it sits behind the `opus` feature; see
    /// `docs/05-media.md`.
    #[cfg(feature = "opus")]
    Opus,
    /// L16 at 8 kHz mono (RFC 3551 §4.5.11): raw samples at 128 kbit/s, for recorders, speech
    /// engines or transcoding bridges. Not offered by default; dynamic payload type as `L16/8000`.
    L16Narrowband,
    /// L16 at 16 kHz mono, 256 kbit/s, dynamic payload type as `L16/16000`.
    L16Wideband,
}

impl Codec {
    /// Every codec this build contains, best quality first, which is the default offer order.
    ///
    /// The length depends on the build; read it from the array. G.729 and the two L16s come last
    /// and are not offered by default ([`Codec::offered_by_default`]).
    #[cfg(feature = "opus")]
    pub const ALL: [Self; 7] = [
        Self::Opus,
        Self::G722,
        Self::Pcmu,
        Self::Pcma,
        Self::G729,
        Self::L16Wideband,
        Self::L16Narrowband,
    ];
    /// Every codec this build contains, without Opus.
    #[cfg(not(feature = "opus"))]
    pub const ALL: [Self; 6] = [
        Self::G722,
        Self::Pcmu,
        Self::Pcma,
        Self::G729,
        Self::L16Wideband,
        Self::L16Narrowband,
    ];

    /// Whether [`CodecCatalog::new`] offers it: all but G.729 and the two L16s.
    ///
    /// The peer's preference decides (RFC 3264 §6.1), so offering G.729 by default would give
    /// narrowband calls with peers that prefer it. L16 costs 8 to 16 times G.711's bandwidth. Both
    /// are a site's choice.
    #[must_use]
    pub const fn offered_by_default(self) -> bool {
        !matches!(self, Self::G729 | Self::L16Narrowband | Self::L16Wideband)
    }

    /// The name in a codec order: the encoding name, plus the rate for L16 (`L16/8000`,
    /// `L16/16000`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::L16Narrowband => "L16/8000",
            Self::L16Wideband => "L16/16000",
            other => other.encoding_name(),
        }
    }

    /// The `a=rtpmap` encoding name, as IANA registered it.
    #[must_use]
    pub const fn encoding_name(self) -> &'static str {
        match self {
            Self::Pcmu => "PCMU",
            Self::Pcma => "PCMA",
            Self::G722 => g722::ENCODING_NAME,
            Self::G729 => g729::ENCODING_NAME,
            #[cfg(feature = "opus")]
            Self::Opus => opus::ENCODING_NAME,
            Self::L16Narrowband | Self::L16Wideband => l16::ENCODING_NAME,
        }
    }

    /// Whether this is Opus, the codec a build can lack.
    ///
    /// Answered from the value because Cargo features are per crate: `sipral-ffi`'s own `opus` flag
    /// says nothing about this crate's build.
    #[must_use]
    pub const fn is_opus(self) -> bool {
        match self {
            Self::Pcmu
            | Self::Pcma
            | Self::G722
            | Self::G729
            | Self::L16Narrowband
            | Self::L16Wideband => false,
            #[cfg(feature = "opus")]
            Self::Opus => true,
        }
    }

    /// The RFC 3551 table 4 payload type, for the four codecs that have one. Opus is always
    /// dynamic, and the table's L16 types (10, 11) are 44.1 kHz.
    #[must_use]
    pub const fn static_payload(self) -> Option<u8> {
        match self {
            Self::Pcmu => Some(0),
            Self::Pcma => Some(8),
            Self::G722 => Some(g722::PAYLOAD_TYPE),
            Self::G729 => Some(g729::PAYLOAD_TYPE),
            #[cfg(feature = "opus")]
            Self::Opus => None,
            Self::L16Narrowband | Self::L16Wideband => None,
        }
    }

    /// The ITU-T G.113 Appendix I `Ie`/`Bpl` pair for the RFC 3611 §4.7.5 R factor and MOS, or
    /// `None` if Table I.4 does not rate this codec.
    ///
    /// G.722 and Opus get `None`: G.722 has its own entry (not in our copy of the text), and Opus
    /// postdates the list. RFC 3611 §4.7.5 wants the sentinel rather than a guess; see
    /// `sipral_rtp::RtpSession::voip_metrics`. G.729 gets `None` too: Table I.4 rates it only with
    /// Annex B, which depends on the call, and Table I.1 gives no `Bpl` for Annex A alone.
    ///
    /// G.711 is rated with concealment, since this stack conceals every lost G.711 frame
    /// (`sipral_media::plc`); G.107 Table 3, Note 5: "the Bpl must match the codec, packet size and
    /// packet loss concealment (PLC) assumed".
    #[must_use]
    pub const fn quality_model(self) -> Option<sipral_rtp::CodecQualityModel> {
        match self {
            Self::Pcmu | Self::Pcma => Some(sipral_rtp::codec_quality_model(
                sipral_rtp::CodecFamily::G711Concealed,
            )),
            Self::G722 | Self::G729 | Self::L16Narrowband | Self::L16Wideband => None,
            #[cfg(feature = "opus")]
            Self::Opus => None,
        }
    }

    /// The RTP timestamp clock, as written in `a=rtpmap`.
    ///
    /// G.722's is 8000 although it samples at 16000; a peer reading 16000 on a G.722 line refuses
    /// the stream.
    #[must_use]
    pub const fn clock_rate(self) -> u32 {
        match self {
            Self::Pcmu | Self::Pcma | Self::G722 => g711::CLOCK_RATE,
            Self::G729 => g729::CLOCK_RATE,
            #[cfg(feature = "opus")]
            Self::Opus => opus::CLOCK_RATE,
            Self::L16Narrowband => L16_NARROWBAND,
            Self::L16Wideband => L16_WIDEBAND,
        }
    }

    /// The rate the codec samples at, which is the rate of the frames passed in and out.
    #[must_use]
    pub const fn sample_rate(self) -> u32 {
        match self {
            Self::Pcmu | Self::Pcma => g711::CLOCK_RATE,
            Self::G722 => g722::SAMPLE_RATE,
            Self::G729 => g729::SAMPLE_RATE,
            #[cfg(feature = "opus")]
            Self::Opus => opus::CLOCK_RATE,
            // L16: the clock counts samples
            Self::L16Narrowband | Self::L16Wideband => self.clock_rate(),
        }
    }

    /// Samples in a frame of `millis` milliseconds. Every rate is a whole number of samples per
    /// millisecond, so dividing first loses nothing.
    #[must_use]
    pub fn frame_samples(self, millis: u32) -> usize {
        usize::try_from(self.sample_rate() / 1_000 * millis).unwrap_or(usize::MAX)
    }

    /// RTP ticks a frame of `millis` milliseconds covers.
    #[must_use]
    pub const fn frame_ticks(self, millis: u32) -> u32 {
        self.clock_rate() / 1_000 * millis
    }

    /// The largest payload one frame can produce, which the send buffer must hold. Exact for the
    /// written codecs, a bound for Opus.
    #[must_use]
    pub fn max_payload(self, millis: u32) -> usize {
        match self {
            Self::Pcmu | Self::Pcma => self.frame_samples(millis),
            Self::G722 => self.frame_samples(millis) / 2,
            Self::G729 => self.frame_samples(millis) / g729::FRAME_SAMPLES * g729::FRAME_OCTETS,
            #[cfg(feature = "opus")]
            Self::Opus => opus::MAX_FRAME_BYTES,
            Self::L16Narrowband | Self::L16Wideband => self
                .frame_samples(millis)
                .saturating_mul(l16::SAMPLE_OCTETS),
        }
    }

    /// Whether a frame of `millis` fits one datagram. Only L16 can exceed it, since its payload
    /// grows with the frame. The limit is the longest Opus frame (RFC 6716), 1275 octets.
    #[must_use]
    pub fn fits(self, millis: u32) -> bool {
        self.max_payload(millis) <= LARGEST_PAYLOAD
    }

    /// The `a=rtpmap` for this codec at the given payload type.
    ///
    /// Opus is always `opus/48000/2`, even mono (RFC 7587 §7); a peer seeing 1 may refuse the
    /// stream.
    #[must_use]
    pub fn rtpmap(self, payload: u8) -> RtpMap {
        RtpMap {
            payload,
            encoding: self.encoding_name().to_owned(),
            clock_rate: self.clock_rate(),
            parameters: match self {
                #[cfg(feature = "opus")]
                Self::Opus => Some(opus::RTPMAP_CHANNELS.to_string()),
                // one channel, which a missing count means (RFC 4566 §6)
                Self::Pcmu
                | Self::Pcma
                | Self::G722
                | Self::G729
                | Self::L16Narrowband
                | Self::L16Wideband => None,
            },
        }
    }

    /// The `a=fmtp` parameters to offer, if any.
    ///
    /// Opus gets `useinbandfec=1` (RFC 7587 §7.1): free when unused, and it recovers lost packets
    /// when the peer sends FEC. G.729 gets `annexb=yes`, or `annexb=no` with
    /// [`CodecCatalog::with_g729_annex_b`] off. In answers, other codecs echo the offer's
    /// parameters.
    #[must_use]
    pub const fn fmtp(self) -> Option<&'static str> {
        match self {
            #[cfg(feature = "opus")]
            Self::Opus => Some("useinbandfec=1"),
            Self::G729 => Some(annex_b_parameter(true)),
            Self::Pcmu | Self::Pcma | Self::G722 | Self::L16Narrowband | Self::L16Wideband => None,
        }
    }

    /// Which codec a negotiated stream uses, or `None` if this build cannot decode it.
    ///
    /// Decided by encoding name, not payload type, since a dynamic number means whatever its
    /// `a=rtpmap` says. For L16 the rate and channel count must match too: `L16/44100/2` is neither
    /// of ours.
    #[must_use]
    pub fn of(negotiated: &NegotiatedCodec) -> Option<Self> {
        Self::ALL.into_iter().find(|codec| {
            negotiated.is_encoding(codec.encoding_name())
                && match codec {
                    Self::L16Narrowband | Self::L16Wideband => {
                        negotiated.clock_rate() == codec.clock_rate()
                            && negotiated
                                .rtpmap
                                .parameters
                                .as_deref()
                                .is_none_or(|channels| channels.trim() == "1")
                    }
                    _ => true,
                }
        })
    }

    /// The codec a plan settled on.
    ///
    /// # Errors
    ///
    /// [`MediaError::UnknownPayload`] when the far end answered with a format not in the offer.
    pub fn of_plan(plan: &MediaPlan) -> Result<Self, MediaError> {
        Self::of(&plan.codec).ok_or_else(|| MediaError::UnknownPayload {
            payload: plan.codec.payload(),
            encoding: plan.codec.rtpmap.encoding.clone(),
        })
    }

    /// Every codec this build recognises among a stream's formats, in no particular order. Only
    /// membership matters; preference already chose the winner passed to
    /// [`CodecCatalog::candidates`].
    #[must_use]
    pub fn named_in(stream: &MediaDescription) -> Vec<Self> {
        stream
            .formats
            .iter()
            .filter_map(|format| {
                let payload: u8 = format.parse().ok()?;
                let rtpmap = stream.rtpmap(payload).or_else(|| static_rtpmap(payload))?;
                Self::of(&NegotiatedCodec::new(rtpmap))
            })
            .collect()
    }
}

impl core::fmt::Display for Codec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// The fingerprint (RFC 8122) and `a=setup` (RFC 4145) lines for a DTLS-SRTP description. Borrowed,
/// since the engine owns them longer than the description.
#[cfg(feature = "dtls")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Keyed<'a> {
    pub(crate) fingerprint: &'a str,
    pub(crate) setup: &'a str,
}

/// Never constructed without `dtls`; the signature still needs a type.
#[cfg(not(feature = "dtls"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Keyed<'a>(core::marker::PhantomData<&'a ()>);

/// What to offer, in what order, and how frames are cut.
///
/// A stack keeps one as its site policy and every call uses it by default. D6 in
/// `docs/13-client-requirements.md` needs a per-call exception, for example a consultation leg to a
/// one-codec gateway during an attended transfer; [`place_with`](crate::MediaEngine::place_with)
/// and [`answer_with`](crate::MediaEngine::answer_with) take a catalogue for one call instead of
/// mutating a shared one.
// independent site choices (named events, mux, Annex B, feedback), not a state machine
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecCatalog {
    order: Vec<Codec>,
    frame_ms: u32,
    dtmf: bool,
    rtcp_mux: bool,
    srtp: SrtpPolicy,
    /// SRTP transforms in preference order, if set ([`CodecCatalog::with_srtp_suites`]); `None`
    /// uses this build's defaults.
    srtp_suites: Option<Vec<Suite>>,
    /// Whether an SDES key may travel in unencrypted signalling
    /// ([`CodecCatalog::with_sdes_signalling`]).
    sdes_signalling: SdesSignalling,
    ice: IcePolicy,
    annex_b: bool,
    feedback: bool,
    voip_metrics: bool,
}

impl CodecCatalog {
    /// Every codec offered by default ([`Codec::offered_by_default`]), best first, 20 ms frames,
    /// named events on, RTCP on its own port, no SRTP, Annex B allowed if G.729 is named.
    ///
    /// RTCP mux is off because RFC 5761 §5.1.1 needs both ends to ask, and typical Asterisk PBXs
    /// behind NAT do not. SDES is off for similar reasons; see [`SrtpPolicy::NotOffered`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            order: Codec::ALL
                .into_iter()
                .filter(|codec| codec.offered_by_default())
                .collect(),
            frame_ms: DEFAULT_FRAME_MS,
            dtmf: true,
            rtcp_mux: false,
            srtp: SrtpPolicy::NotOffered,
            srtp_suites: None,
            sdes_signalling: SdesSignalling::AnyTransport,
            ice: IcePolicy::Off,
            annex_b: true,
            feedback: false,
            voip_metrics: true,
        }
    }

    /// The same, offering only these codecs in this order.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoCodecs`] for an empty order, [`MediaError::UnsupportedCodec`] for an unknown
    /// or duplicate name.
    pub fn with_order(codecs: &[&str]) -> Result<Self, MediaError> {
        Self::new().with_codecs(codecs)
    }

    /// This catalogue with only these codecs in this order, keeping every other setting. Starting
    /// from [`CodecCatalog::with_order`] would reset them.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoCodecs`] for an empty order, [`MediaError::UnsupportedCodec`] for an unknown
    /// or duplicate name, [`MediaError::BadFrameLength`] when the current frame length does not
    /// suit the new codecs (Opus at 30 ms, for example).
    pub fn with_codecs(self, codecs: &[&str]) -> Result<Self, MediaError> {
        if codecs.is_empty() {
            return Err(MediaError::NoCodecs);
        }
        let mut order = Vec::with_capacity(codecs.len());
        for name in codecs {
            let codec = Codec::ALL
                .into_iter()
                .find(|codec| codec.name().eq_ignore_ascii_case(name))
                .ok_or_else(|| MediaError::unsupported(name))?;
            if order.contains(&codec) {
                return Err(MediaError::unsupported(name));
            }
            order.push(codec);
        }
        let frame_ms = self.frame_ms;
        Self { order, ..self }.with_frame_length(frame_ms)
    }

    /// Cut frames at `millis` milliseconds instead of 20.
    ///
    /// # Errors
    ///
    /// [`MediaError::BadFrameLength`] for zero, for a length Opus cannot encode when Opus is
    /// offered, and for a length that is not a multiple of 10 ms when G.729 is offered (RFC 3551
    /// §4.5.6). G.711 and G.722 accept any whole millisecond.
    pub fn with_frame_length(mut self, millis: u32) -> Result<Self, MediaError> {
        #[cfg(feature = "opus")]
        let opus_refuses = self.order.contains(&Codec::Opus)
            && opus::FrameDuration::from_micros(millis.saturating_mul(1_000)).is_err();
        // only G.729 constrains the frame length here
        #[cfg(not(feature = "opus"))]
        let opus_refuses = false;
        let g729_refuses = self.order.contains(&Codec::G729)
            && !Codec::G729
                .frame_samples(millis)
                .is_multiple_of(g729::FRAME_SAMPLES);
        let too_long = self.order.iter().any(|codec| !codec.fits(millis));
        if millis == 0 || opus_refuses || g729_refuses || too_long {
            return Err(MediaError::BadFrameLength { millis });
        }
        self.frame_ms = millis;
        Ok(self)
    }

    /// Whether RFC 4733 named events are offered. On by default, so menus can be navigated.
    #[must_use]
    pub const fn with_dtmf(mut self, dtmf: bool) -> Self {
        self.dtmf = dtmf;
        self
    }

    /// Say whether RFC 5761 multiplexing is asked for.
    #[must_use]
    pub const fn with_rtcp_mux(mut self, rtcp_mux: bool) -> Self {
        self.rtcp_mux = rtcp_mux;
        self
    }

    /// What this call does about SRTP. Off by default; see [`SrtpPolicy`].
    #[must_use]
    pub const fn with_srtp(mut self, srtp: SrtpPolicy) -> Self {
        self.srtp = srtp;
        self
    }

    /// What this call does about SRTP.
    #[must_use]
    pub const fn srtp(&self) -> SrtpPolicy {
        self.srtp
    }

    /// Whether an SDES key may travel in unencrypted signalling ([`SdesSignalling`]). Allowed by
    /// default, and reported.
    #[must_use]
    pub const fn with_sdes_signalling(mut self, sdes: SdesSignalling) -> Self {
        self.sdes_signalling = sdes;
        self
    }

    /// Whether an SDES key may travel in signalling that is not encrypted.
    #[must_use]
    pub const fn sdes_signalling(&self) -> SdesSignalling {
        self.sdes_signalling
    }

    /// Use only these SRTP transforms, most preferred first, wherever a suite is chosen: SDES offer
    /// lines (one each, in this order), SDES answers (offerer's order, RFC 4568 §5.1.2, among
    /// these), and DTLS-SRTP profiles for the four with profiles: `AEAD_AES_256_GCM`,
    /// `AEAD_AES_128_GCM` (RFC 7714 §14.2) and the two AES-CM ones (RFC 5764 §4.1.2).
    ///
    /// Unset, an SDES offer names `AEAD_AES_256_GCM` then `AES_CM_128_HMAC_SHA1_80`, an answer
    /// accepts any of the seven, and a handshake offers the four strongest first. Each line adds to
    /// the INVITE (RFC 3261 §18.1.1); more than two or three suites over UDP needs TCP.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoSrtpSuite`] for an empty list or a duplicate.
    pub fn with_srtp_suites(mut self, suites: &[Suite]) -> Result<Self, MediaError> {
        let repeated = suites
            .iter()
            .enumerate()
            .any(|(at, suite)| suites.iter().take(at).any(|earlier| earlier == suite));
        if suites.is_empty() || repeated {
            return Err(MediaError::NoSrtpSuite);
        }
        self.srtp_suites = Some(suites.to_vec());
        Ok(self)
    }

    /// The SRTP transforms this call is limited to, if set.
    #[must_use]
    pub fn srtp_suites(&self) -> Option<&[Suite]> {
        self.srtp_suites.as_deref()
    }

    /// The SRTP transforms in order: those set with [`CodecCatalog::with_srtp_suites`], or the
    /// build defaults.
    #[must_use]
    pub fn srtp_suites_in_force(&self) -> Vec<Suite> {
        self.srtp_suites.clone().unwrap_or_else(|| {
            keying::OFFERED
                .iter()
                .map(|suite| keying::transform(*suite))
                .collect()
        })
    }

    /// The suites an SDES offer from this catalogue names, in order.
    pub(crate) fn sdes_offered(&self) -> Vec<sipral_core::sdp::CryptoSuite> {
        keying::sdes_suites(self.srtp_suites())
    }

    /// What this call does about ICE. Off by default; see [`IcePolicy`].
    ///
    /// A policy that offers ICE also forces RFC 5761 mux, as DTLS does: a second component would
    /// need a second address, and the offer would fail our own mismatch check (RFC 8839 §4.2.5).
    #[must_use]
    pub const fn with_ice(mut self, ice: IcePolicy) -> Self {
        self.ice = ice;
        self
    }

    /// What this call does about ICE.
    #[must_use]
    pub const fn ice(&self) -> IcePolicy {
        self.ice
    }

    /// Whether G.729 Annex B (SID frames and comfort noise in pauses) is allowed.
    ///
    /// On by default, as `G729` with no parameter means (RFC 4856 §2.1.9): offers say `annexb=yes`,
    /// answers say `yes` only if the offer allowed it. Off, both say `annexb=no`, telling the far
    /// end not to send SID (RFC 3551 §4.5.6). The encoder uses Annex B only where both allowed it;
    /// the decoder always plays SID frames.
    #[must_use]
    pub const fn with_g729_annex_b(mut self, annex_b: bool) -> Self {
        self.annex_b = annex_b;
        self
    }

    /// Whether G.729's Annex B is allowed.
    #[must_use]
    pub const fn g729_annex_b(&self) -> bool {
        self.annex_b
    }

    /// Whether this call asks for RTCP feedback: RTP/AVPF (RFC 4585), or RTP/SAVPF (RFC 5124) and
    /// UDP/TLS/RTP/SAVPF when keyed, with Generic NACK and reduced-size RTCP (RFC 5506).
    ///
    /// Off by default: the profile is on the `m=` line, and a peer knowing only RTP/AVP refuses the
    /// stream. When both descriptions name a feedback profile, RTCP follows RFC 4585
    /// ([`sipral_rtp::RtpSession::use_feedback`]); the result is in
    /// [`crate::StreamStatistics::feedback`].
    #[must_use]
    pub const fn with_feedback(mut self, feedback: bool) -> Self {
        self.feedback = feedback;
        self
    }

    /// Whether this call asks for RTCP feedback.
    #[must_use]
    pub const fn feedback(&self) -> bool {
        self.feedback
    }

    /// Whether offers and answers ask for the RFC 3611 §4.7 VoIP metrics report
    /// (`a=rtcp-xr:voip-metrics`, §5.1).
    ///
    /// On by default, so an outgoing call learns what the far end measured. Off saves 24 bytes per
    /// INVITE. An offer that asks is still sent the report (§5.2).
    #[must_use]
    pub const fn with_voip_metrics(mut self, voip_metrics: bool) -> Self {
        self.voip_metrics = voip_metrics;
        self
    }

    /// Whether this catalogue asks for the VoIP metrics report.
    #[must_use]
    pub const fn voip_metrics(&self) -> bool {
        self.voip_metrics
    }

    /// The `a=fmtp` this catalogue offers for `codec`: [`Codec::fmtp`], except G.729's `annexb`,
    /// which is the catalogue's.
    pub(crate) const fn offered_fmtp(&self, codec: Codec) -> Option<&'static str> {
        match codec {
            Codec::G729 => Some(annex_b_parameter(self.annex_b)),
            other => other.fmtp(),
        }
    }

    /// The `a=fmtp` this end states for `codec` in an answer to `offered`: only G.729's `annexb`,
    /// `yes` only if the offer (absent means `yes`, RFC 4856 §2.1.9) and the catalogue both allow
    /// it.
    pub(crate) fn answered_fmtp(
        &self,
        codec: Codec,
        offered: Option<&str>,
    ) -> Option<&'static str> {
        (codec == Codec::G729).then(|| annex_b_parameter(self.annex_b && annex_b_allowed(offered)))
    }

    /// What is offered, in the order it is offered.
    #[must_use]
    pub fn codecs(&self) -> &[Codec] {
        &self.order
    }

    /// How long a frame is, in milliseconds.
    #[must_use]
    pub const fn frame_length(&self) -> u32 {
        self.frame_ms
    }

    /// This catalogue as [`MediaCapabilities`] for `sipral-core`'s offer/answer.
    ///
    /// Payload types are assigned here: static ones per RFC 3551, dynamic ones from 96 in offer
    /// order. No `a=crypto` or secure profile: keys come from the engine's seeded stream, so
    /// [`MediaEngine`](crate::MediaEngine) adds them per description.
    #[must_use]
    pub fn capabilities(&self) -> MediaCapabilities {
        let mut next_dynamic = FIRST_DYNAMIC;
        let codecs = self
            .order
            .iter()
            .map(|codec| {
                let payload = codec.static_payload().unwrap_or_else(|| {
                    let assigned = next_dynamic;
                    next_dynamic = next_dynamic.saturating_add(1);
                    assigned
                });
                let mapped = NegotiatedCodec::new(codec.rtpmap(payload));
                match self.offered_fmtp(*codec) {
                    Some(fmtp) => mapped.with_fmtp(fmtp),
                    None => mapped,
                }
            })
            .collect();
        MediaCapabilities::new(codecs)
            .with_dtmf(self.dtmf)
            .with_voip_metrics_xr(self.voip_metrics)
            // one ICE component is what mux gives
            .with_rtcp_mux(self.rtcp_mux || self.ice.offers())
    }

    /// The same, with the keying for a description under this policy.
    ///
    /// `keys` holds one master key and salt per suite in [`CodecCatalog::sdes_offered`]; `dtls` is
    /// the certificate fingerprint and `a=setup`. With neither, the offer is plain `RTP/AVP`.
    ///
    /// A DTLS description always asks for `a=rtcp-mux`, since RFC 5764 §4.2 would otherwise need a
    /// second handshake. Under [`SrtpPolicy::DtlsOrSdes`] this is the SDES offer on `RTP/SAVP` with
    /// mux; the engine adds the fingerprint afterwards, because [`SrtpSupport`] names only one
    /// keying method.
    pub(crate) fn offering(
        &self,
        keys: Option<Vec<(sipral_core::sdp::CryptoSuite, KeySalt)>>,
        dtls: Option<Keyed<'_>>,
    ) -> MediaCapabilities {
        let capabilities = self.capabilities();
        #[cfg(feature = "dtls")]
        if self.srtp.falls_back() {
            return match keys {
                Some(keys) => capabilities
                    .with_rtcp_mux(true)
                    .with_srtp(SrtpSupport::Sdes(keying::offer_lines(keys))),
                None => capabilities,
            };
        }
        #[cfg(feature = "dtls")]
        if let Some(keyed) = dtls.filter(|_| self.srtp.offers()) {
            return capabilities
                .with_rtcp_mux(true)
                .with_srtp(SrtpSupport::Dtls {
                    fingerprint: keyed.fingerprint.to_owned(),
                    setup: keyed.setup.to_owned(),
                });
        }
        #[cfg(not(feature = "dtls"))]
        let _ = dtls;
        match keys.filter(|_| self.srtp.offers()) {
            // `SrtpPolicy::BestEffort`: same lines, plain profile
            Some(keys) if self.srtp.on_plain_profile() => {
                capabilities.with_srtp(SrtpSupport::SdesOnAvp(keying::offer_lines(keys)))
            }
            Some(keys) => capabilities.with_srtp(SrtpSupport::Sdes(keying::offer_lines(keys))),
            None => capabilities,
        }
    }

    /// What became of every codec in this catalogue once the call settled on `winner` (D5).
    ///
    /// `remote` is the far end's description the winner was read from
    /// ([`SessionDescription::media_plan`](sipral_core::sdp::SessionDescription::media_plan)).
    /// Computed when negotiating, because a later reconstruction can disagree in exactly the case
    /// being debugged.
    #[must_use]
    pub fn candidates(&self, remote: &MediaDescription, winner: Codec) -> Vec<CodecCandidate> {
        let named = Codec::named_in(remote);
        self.order
            .iter()
            .map(|&codec| {
                let outcome = if codec == winner {
                    CodecOutcome::Chosen
                } else if named.contains(&codec) {
                    CodecOutcome::Outranked(winner)
                } else {
                    CodecOutcome::NotNamed
                };
                CodecCandidate { codec, outcome }
            })
            .collect()
    }
}

/// One codec this build could have used on a call, and what became of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecCandidate {
    /// The codec.
    pub codec: Codec,
    /// What happened to it.
    pub outcome: CodecOutcome,
}

/// Why a candidate did or did not become the call's codec.
///
/// The diagnosis behind "PCMU was chosen" ([`crate::MediaEvent::Started`]), so a configuration
/// error is visible without a packet capture (D5, B6 in `docs/13-client-requirements.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecOutcome {
    /// The codec the call uses. Exactly one per call, the one
    /// [`MediaSession::codec`](crate::MediaSession::codec) returns.
    Chosen,
    /// The far end's description never named it.
    NotNamed,
    /// The far end named it, but the carried candidate was preferred (RFC 3264 §6.1: the far end's
    /// order decides).
    Outranked(Codec),
}

impl Default for CodecCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Codec, CodecCandidate, CodecCatalog, CodecOutcome, DEFAULT_FRAME_MS};
    use crate::error::MediaError;
    use crate::keying::SrtpPolicy;
    use sipral_core::sdp::{Direction, NegotiatedCodec, RtpMap};

    /// A codec this build has that the test peer never names: Opus when built, G.722 otherwise.
    /// Shared with `crate::tests`.
    #[cfg(feature = "opus")]
    pub(crate) const UNMATCHED: (&str, Codec) = ("opus", Codec::Opus);
    /// See the other declaration.
    #[cfg(not(feature = "opus"))]
    pub(crate) const UNMATCHED: (&str, Codec) = ("G722", Codec::G722);

    /// A lost G.711 frame is concealed (`sipral_media::plc`), so a call's own E-model takes G.113's
    /// concealed entry. The unconcealed one rated 3.66 % random loss R 50 where 81 is the figure.
    #[test]
    fn g711_is_rated_as_the_concealed_g711_this_stack_plays() {
        for codec in [Codec::Pcmu, Codec::Pcma] {
            let model = codec.quality_model().expect("G.113 rates G.711");
            assert!(
                (model.bpl - 25.1).abs() < f64::EPSILON,
                "{codec:?}: {model:?}"
            );
            let report = sipral_rtp::evaluate_e_model(sipral_rtp::EModelInputs {
                one_way_delay_ms: 54,
                packet_loss_percent: 3.66,
                burst_ratio: sipral_rtp::BurstRatio::RANDOM,
                codec: Some(model),
            });
            assert_eq!(report.r_factor, 81, "{codec:?}");
        }
    }

    /// A trap the interop harness fell into once.
    #[test]
    fn a_frame_is_three_different_numbers() {
        assert_eq!(Codec::Pcmu.frame_samples(DEFAULT_FRAME_MS), 160);
        assert_eq!(Codec::Pcmu.max_payload(DEFAULT_FRAME_MS), 160);
        assert_eq!(Codec::Pcmu.frame_ticks(DEFAULT_FRAME_MS), 160);

        assert_eq!(Codec::G722.frame_samples(DEFAULT_FRAME_MS), 320);
        assert_eq!(Codec::G722.max_payload(DEFAULT_FRAME_MS), 160);
        assert_eq!(Codec::G722.frame_ticks(DEFAULT_FRAME_MS), 160);

        // two 10-octet frames, the RFC 3551 §4.5.6 default packet
        assert_eq!(Codec::G729.frame_samples(DEFAULT_FRAME_MS), 160);
        assert_eq!(Codec::G729.max_payload(DEFAULT_FRAME_MS), 20);
        assert_eq!(Codec::G729.frame_ticks(DEFAULT_FRAME_MS), 160);
        assert_eq!(Codec::G729.max_payload(10), 10);

        #[cfg(feature = "opus")]
        {
            assert_eq!(Codec::Opus.frame_samples(DEFAULT_FRAME_MS), 960);
            assert_eq!(Codec::Opus.frame_ticks(DEFAULT_FRAME_MS), 960);
        }
    }

    /// G.722's clock is half its sample rate, and real peers refuse a line that says otherwise.
    #[test]
    fn g722_counts_at_half_the_rate_it_hears_at() {
        assert_eq!(Codec::G722.clock_rate(), 8_000);
        assert_eq!(Codec::G722.sample_rate(), 16_000);
        assert_eq!(Codec::G722.rtpmap(9).to_value(), "9 G722/8000");
    }

    #[cfg(feature = "opus")]
    #[test]
    fn opus_advertises_two_channels_whatever_it_carries() {
        assert_eq!(Codec::Opus.rtpmap(96).to_value(), "96 opus/48000/2");
    }

    #[test]
    fn the_static_payload_types_are_the_ones_rfc_3551_assigned() {
        assert_eq!(Codec::Pcmu.static_payload(), Some(0));
        assert_eq!(Codec::Pcma.static_payload(), Some(8));
        assert_eq!(Codec::G722.static_payload(), Some(9));
        assert_eq!(Codec::G729.static_payload(), Some(18));
        #[cfg(feature = "opus")]
        assert_eq!(Codec::Opus.static_payload(), None);
    }

    /// L16 is named by rate, offered only when ordered, on a dynamic type with the rate in
    /// `a=rtpmap`, and recognised only at that rate and mono.
    #[test]
    fn l16_is_named_and_recognised_by_its_rate() {
        assert!(!CodecCatalog::new().codecs().contains(&Codec::L16Wideband));
        assert!(!CodecCatalog::new().codecs().contains(&Codec::L16Narrowband));
        let catalog = CodecCatalog::with_order(&["l16/16000", "L16/8000", "PCMU"]).unwrap();
        assert_eq!(
            catalog.codecs(),
            [Codec::L16Wideband, Codec::L16Narrowband, Codec::Pcmu]
        );
        let offer = catalog
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        // named events on both clocks
        assert_eq!(offer.formats, ["96", "97", "0", "98", "99"]);
        assert_eq!(
            offer.rtpmap(98).map(|map| map.to_value()).as_deref(),
            Some("98 telephone-event/16000")
        );
        assert_eq!(
            offer.rtpmap(99).map(|map| map.to_value()).as_deref(),
            Some("99 telephone-event/8000")
        );
        assert_eq!(
            offer.rtpmap(96).map(|map| map.to_value()).as_deref(),
            Some("96 L16/16000")
        );
        assert_eq!(
            offer.rtpmap(97).map(|map| map.to_value()).as_deref(),
            Some("97 L16/8000")
        );
        assert_eq!(Codec::L16Wideband.to_string(), "L16/16000");
        assert!(
            CodecCatalog::with_order(&["L16"]).is_err(),
            "a rate has to be named"
        );

        let read = |value: &str| {
            let (payload, rest) = value.split_once(' ').unwrap();
            let mut parts = rest.split('/');
            Codec::of(&NegotiatedCodec::new(RtpMap {
                payload: payload.parse().unwrap(),
                encoding: parts.next().unwrap().to_owned(),
                clock_rate: parts.next().unwrap().parse().unwrap(),
                parameters: parts.next().map(str::to_owned),
            }))
        };
        assert_eq!(read("100 L16/16000"), Some(Codec::L16Wideband));
        assert_eq!(read("100 L16/8000/1"), Some(Codec::L16Narrowband));
        assert_eq!(read("100 L16/44100"), None);
        assert_eq!(
            read("100 L16/16000/2"),
            None,
            "two channels is not this codec"
        );
        assert_eq!(read("11 L16/44100"), None);
    }

    /// L16 frames that would not fit a datagram are refused when set, not when the first packet is
    /// built.
    #[test]
    fn a_frame_l16_cannot_fit_in_a_datagram_is_refused() {
        let wide = CodecCatalog::with_order(&["L16/16000"]).unwrap();
        assert_eq!(Codec::L16Wideband.max_payload(20), 640);
        assert!(wide.clone().with_frame_length(30).is_ok());
        assert_eq!(
            wide.with_frame_length(40).unwrap_err(),
            MediaError::BadFrameLength { millis: 40 }
        );
        let narrow = CodecCatalog::with_order(&["L16/8000"]).unwrap();
        assert!(narrow.clone().with_frame_length(60).is_ok());
        assert_eq!(
            narrow.with_frame_length(80).unwrap_err(),
            MediaError::BadFrameLength { millis: 80 }
        );
    }

    /// G.729 is built but not offered by default; when ordered it is offered on 18 with its Annex B
    /// setting.
    #[test]
    fn g729_is_offered_only_when_an_order_names_it() {
        assert!(Codec::ALL.contains(&Codec::G729));
        assert!(!CodecCatalog::new().codecs().contains(&Codec::G729));
        assert!(
            Codec::ALL
                .into_iter()
                .filter(|codec| {
                    !matches!(
                        codec,
                        Codec::G729 | Codec::L16Narrowband | Codec::L16Wideband
                    )
                })
                .all(|codec| CodecCatalog::new().codecs().contains(&codec)),
            "every other codec but L16 is still offered"
        );

        let offer = CodecCatalog::with_order(&["g729", "PCMA"])
            .unwrap()
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(offer.formats, ["18", "8", "96"]);
        assert_eq!(
            offer.rtpmap(18).map(|map| map.to_value()).as_deref(),
            Some("18 G729/8000")
        );
        assert_eq!(offer.fmtp(18), Some("annexb=yes"));
        let without = CodecCatalog::with_order(&["G729"])
            .unwrap()
            .with_g729_annex_b(false)
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(without.fmtp(18), Some("annexb=no"));
    }

    /// RFC 4856 §2.1.9: absent `annexb` means `yes`, only `no` refuses. Answers say `yes` only when
    /// offer and catalogue allow it, and nothing for other codecs.
    #[test]
    fn an_answer_allows_annex_b_only_where_the_offer_did() {
        use super::annex_b_allowed;
        assert!(annex_b_allowed(None));
        assert!(annex_b_allowed(Some("annexb=yes")));
        assert!(annex_b_allowed(Some("bitrate=8")));
        assert!(!annex_b_allowed(Some("annexb=no")));
        assert!(!annex_b_allowed(Some("foo=1; AnnexB = No")));

        let on = CodecCatalog::with_order(&["G729"]).unwrap();
        let off = on.clone().with_g729_annex_b(false);
        assert!(on.g729_annex_b());
        assert!(!off.g729_annex_b());
        assert_eq!(on.answered_fmtp(Codec::G729, None), Some("annexb=yes"));
        assert_eq!(
            on.answered_fmtp(Codec::G729, Some("annexb=yes")),
            Some("annexb=yes")
        );
        assert_eq!(
            on.answered_fmtp(Codec::G729, Some("annexb=no")),
            Some("annexb=no")
        );
        assert_eq!(off.answered_fmtp(Codec::G729, None), Some("annexb=no"));
        assert_eq!(
            off.answered_fmtp(Codec::G729, Some("annexb=yes")),
            Some("annexb=no")
        );
        assert_eq!(on.answered_fmtp(Codec::Pcma, None), None);
    }

    /// With G.729 only multiples of 10 ms are accepted; without it the same length is fine.
    #[test]
    fn g729_takes_only_whole_ten_millisecond_frames() {
        let g729 = CodecCatalog::with_order(&["G729"]).unwrap();
        for millis in [10, 20, 30, 40, 60] {
            assert_eq!(
                g729.clone()
                    .with_frame_length(millis)
                    .map(|catalog| catalog.frame_length()),
                Ok(millis)
            );
        }
        for millis in [5, 15, 25] {
            assert_eq!(
                g729.clone().with_frame_length(millis).unwrap_err(),
                MediaError::BadFrameLength { millis }
            );
        }
        let narrowband = CodecCatalog::with_order(&["PCMU"])
            .unwrap()
            .with_frame_length(25)
            .unwrap();
        assert_eq!(
            narrowband.with_codecs(&["G729"]).unwrap_err(),
            MediaError::BadFrameLength { millis: 25 }
        );
    }

    #[test]
    fn an_order_names_the_codecs_and_keeps_them_in_that_order() {
        let catalog = CodecCatalog::with_order(&["PCMA", "G722"]).unwrap();
        assert_eq!(catalog.codecs(), [Codec::Pcma, Codec::G722]);
        let offered: Vec<u8> = catalog
            .capabilities()
            .codecs
            .iter()
            .map(NegotiatedCodec::payload)
            .collect();
        assert_eq!(offered, [8, 9]);
    }

    /// For Opus, which has no static number, the order decides the dynamic types.
    #[cfg(feature = "opus")]
    #[test]
    fn an_order_naming_opus_gives_it_the_first_dynamic_type_left() {
        let catalog = CodecCatalog::with_order(&["PCMA", "opus"]).unwrap();
        assert_eq!(catalog.codecs(), [Codec::Pcma, Codec::Opus]);
        let offered: Vec<u8> = catalog
            .capabilities()
            .codecs
            .iter()
            .map(NegotiatedCodec::payload)
            .collect();
        assert_eq!(offered, [8, 96]);
    }

    /// D6: `with_codecs` keeps the other four settings, unlike starting over with `with_order`.
    #[test]
    fn naming_codecs_on_a_catalogue_keeps_everything_else_it_was_built_with() {
        let site = CodecCatalog::with_order(&["PCMU", "G722"])
            .unwrap()
            .with_frame_length(40)
            .unwrap()
            .with_dtmf(false)
            .with_rtcp_mux(true)
            .with_srtp(SrtpPolicy::Required);

        let call = site.clone().with_codecs(&["G722"]).unwrap();

        assert_eq!(call.codecs(), [Codec::G722]);
        assert_eq!(call.frame_length(), site.frame_length());
        assert_eq!(call.srtp(), site.srtp());
        assert_eq!(call.capabilities().dtmf, site.capabilities().dtmf);
        assert_eq!(call.capabilities().rtcp_mux, site.capabilities().rtcp_mux);
    }

    /// The frame length is still checked against the new order.
    #[cfg(feature = "opus")]
    #[test]
    fn naming_codecs_rechecks_the_frame_length_against_the_new_order() {
        // 30 ms suits the written codecs but not Opus
        let narrowband = CodecCatalog::with_order(&["PCMU"])
            .unwrap()
            .with_frame_length(30)
            .unwrap();
        assert_eq!(
            narrowband.clone().with_codecs(&["opus"]).unwrap_err(),
            MediaError::BadFrameLength { millis: 30 }
        );
        // a length Opus can encode is accepted
        assert!(
            narrowband
                .with_frame_length(20)
                .unwrap()
                .with_codecs(&["opus"])
                .is_ok()
        );
    }

    /// B2: a codec without an encoder is refused by name rather than ignored.
    #[test]
    fn a_codec_this_build_does_not_have_is_refused_by_name() {
        // alone, so the duplicate check cannot be what refuses it
        let error = CodecCatalog::with_order(&["SILK"]).unwrap_err();
        assert_eq!(
            error,
            MediaError::UnsupportedCodec {
                name: "SILK".to_owned()
            }
        );
        assert!(error.to_string().contains("SILK"));
        // the message lists what the build has
        assert!(error.to_string().contains("G722"));
        #[cfg(feature = "opus")]
        assert!(error.to_string().contains("opus"));

        // a valid codec beside it does not make the order acceptable
        assert!(CodecCatalog::with_order(&["PCMU", "SILK"]).is_err());
    }

    #[test]
    fn the_same_codec_twice_is_refused() {
        assert!(CodecCatalog::with_order(&["PCMU", "pcmu"]).is_err());
        assert_eq!(
            CodecCatalog::with_order(&[]).unwrap_err(),
            MediaError::NoCodecs
        );
    }

    /// Opus constrains frame length: 30 ms is fine for G.711 but not for Opus, so the answer
    /// depends on what is offered.
    #[cfg(feature = "opus")]
    #[test]
    fn a_frame_length_opus_has_no_frame_for_is_refused_only_where_opus_is() {
        assert_eq!(
            CodecCatalog::new().with_frame_length(30).unwrap_err(),
            MediaError::BadFrameLength { millis: 30 }
        );
        assert_eq!(
            CodecCatalog::with_order(&["PCMU"])
                .unwrap()
                .with_frame_length(30)
                .unwrap()
                .frame_length(),
            30
        );
        assert_eq!(
            CodecCatalog::new().with_frame_length(0).unwrap_err(),
            MediaError::BadFrameLength { millis: 0 }
        );
        assert_eq!(
            CodecCatalog::new()
                .with_frame_length(10)
                .unwrap()
                .frame_length(),
            10
        );
    }

    /// Without Opus, 30 ms is accepted and only zero is refused.
    #[cfg(not(feature = "opus"))]
    #[test]
    fn without_opus_every_whole_millisecond_cuts_a_frame() {
        assert_eq!(
            CodecCatalog::new()
                .with_frame_length(30)
                .unwrap()
                .frame_length(),
            30
        );
        assert_eq!(
            CodecCatalog::new().with_frame_length(0).unwrap_err(),
            MediaError::BadFrameLength { millis: 0 }
        );
    }

    /// The named-event payload type must not clash with any codec, whatever the order.
    #[test]
    fn named_events_get_a_dynamic_type_no_codec_took() {
        let capabilities = CodecCatalog::new().capabilities();
        #[cfg(feature = "opus")]
        {
            // Opus takes 96, events the next
            assert_eq!(
                capabilities.codecs.first().map(NegotiatedCodec::payload),
                Some(96)
            );
            assert_eq!(capabilities.dtmf_payload(), Some(97));
        }
        #[cfg(not(feature = "opus"))]
        {
            // all remaining codecs are static, so events take 96
            assert_eq!(
                capabilities.codecs.first().map(NegotiatedCodec::payload),
                Some(9)
            );
            assert_eq!(capabilities.dtmf_payload(), Some(96));
        }

        let narrow = CodecCatalog::with_order(&["PCMU"]).unwrap().capabilities();
        assert_eq!(narrow.dtmf_payload(), Some(96));
    }

    #[test]
    fn dtmf_can_be_turned_off_and_then_there_is_no_payload_type_for_it() {
        let capabilities = CodecCatalog::new().with_dtmf(false).capabilities();
        assert_eq!(capabilities.dtmf_payload(), None);
    }

    /// The offer names exactly the catalogue's codecs, with Opus's fmtp.
    #[test]
    fn the_offer_names_what_the_catalogue_holds() {
        let offer = CodecCatalog::new()
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        #[cfg(feature = "opus")]
        {
            // named events on Opus's clock and on 8 kHz, which includes G.722 (RFC 3551 §4.5.2)
            assert_eq!(offer.formats, ["96", "9", "0", "8", "97", "98"]);
            assert_eq!(offer.fmtp(96), Some("useinbandfec=1"));
            assert_eq!(offer.fmtp(97), Some("0-15"));
            assert_eq!(offer.rtpmap(97).map(|map| map.clock_rate), Some(48_000));
            assert_eq!(offer.fmtp(98), Some("0-15"));
            assert_eq!(offer.rtpmap(98).map(|map| map.clock_rate), Some(8_000));
        }
        #[cfg(not(feature = "opus"))]
        {
            assert_eq!(offer.formats, ["9", "0", "8", "96"]);
            assert_eq!(offer.fmtp(96), Some("0-15"));
        }
        assert!(!offer.has_flag("rtcp-mux"));
    }

    #[test]
    fn multiplexing_is_asked_for_only_when_it_was_configured() {
        let offer = CodecCatalog::new()
            .with_rtcp_mux(true)
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        assert!(offer.has_flag("rtcp-mux"));
    }

    /// The encoding name decides, not the number.
    #[test]
    fn a_negotiated_codec_is_recognised_by_name_not_by_number() {
        let opus = NegotiatedCodec::new(RtpMap {
            payload: 111,
            encoding: "OPUS".to_owned(),
            clock_rate: 48_000,
            parameters: Some("2".to_owned()),
        });
        #[cfg(feature = "opus")]
        assert_eq!(Codec::of(&opus), Some(Codec::Opus));
        // without Opus the name is not recognised
        #[cfg(not(feature = "opus"))]
        assert_eq!(Codec::of(&opus), None);

        let unknown = NegotiatedCodec::new(RtpMap {
            payload: 0,
            encoding: "SPEEX".to_owned(),
            clock_rate: 8_000,
            parameters: None,
        });
        assert_eq!(Codec::of(&unknown), None);
    }

    /// A stream's formats are read as codecs whatever this catalogue offers.
    #[test]
    fn named_in_reads_every_codec_a_stream_lists_by_encoding_not_by_number() {
        let stream = CodecCatalog::with_order(&[UNMATCHED.0, "PCMU"])
            .unwrap()
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(Codec::named_in(&stream), [UNMATCHED.1, Codec::Pcmu]);

        // named events and comfort noise are not codecs
        let catalog = CodecCatalog::new();
        let with_events = catalog
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(Codec::named_in(&with_events), catalog.codecs());
    }

    /// D5: the chosen codec, and why each other one lost: not named by the far end, or outranked by
    /// its own list.
    #[test]
    fn candidates_says_why_each_codec_that_was_not_chosen_was_not() {
        let catalog = CodecCatalog::with_order(&[UNMATCHED.0, "PCMA", "PCMU"]).unwrap();
        // the far end names only PCMA and PCMU, PCMA first
        let remote = CodecCatalog::with_order(&["PCMA", "PCMU"])
            .unwrap()
            .capabilities()
            .offer("audio", 40_002, Direction::SendRecv);

        let outcomes = catalog.candidates(&remote, Codec::Pcma);
        assert_eq!(
            outcomes,
            vec![
                CodecCandidate {
                    codec: UNMATCHED.1,
                    outcome: CodecOutcome::NotNamed,
                },
                CodecCandidate {
                    codec: Codec::Pcma,
                    outcome: CodecOutcome::Chosen,
                },
                CodecCandidate {
                    codec: Codec::Pcmu,
                    outcome: CodecOutcome::Outranked(Codec::Pcma),
                },
            ]
        );
    }
}
