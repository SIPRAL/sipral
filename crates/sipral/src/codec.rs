// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What this build can encode, in what order, and what a call settled on.
//!
//! A fixed codec order is not enough. Which codec a site wants first is a
//! configuration — a carrier that bills by the minute wants the narrowband one
//! and a company on its own network wants the wideband one — and the order is
//! the whole of the negotiation's outcome, since RFC 3264 §6.1 has the peer's
//! preference decide among what both ends list.
//!
//! Three things are therefore separate here. What the build contains is
//! [`Codec::ALL`], and it is a compile-time fact: no configuration can add a
//! codec that was not linked. What to offer and in what order is
//! [`CodecCatalog`], and it is set once. What one call actually agreed is
//! [`Codec::of`], read back off the plan the negotiation produced.
//!
//! A codec named in an order that this build does not contain is **rejected
//! where it is set**, with the name in the error. That is deliberate: a
//! setting that is accepted and then ignored is the failure that costs months,
//! because neither side can tell it happened.
//!
//! # Three numbers, not one
//!
//! For G.711 the samples in a frame, the octets in a frame and the RTP
//! timestamp ticks a frame covers are all 160, so one constant appears to
//! serve all three. It does not. G.722's are 320, 160 and 160 — RFC 3551
//! §4.5.2 fixes its RTP clock at 8000 although it samples at 16000, "for
//! historical reasons" — and Opus's are 960, whatever the encoder produced,
//! and 960. Anything written against the G.711 shape encodes half a frame and
//! calls it a packet, which is why [`Codec::sample_rate`] and
//! [`Codec::clock_rate`] are two functions and not one. G.729 is the fourth
//! shape: 160 samples, 160 ticks and twenty octets, eight samples to the
//! octet.
//!
//! # In the build is not in the offer
//!
//! G.729 is in [`Codec::ALL`] and not in what [`CodecCatalog::new`] offers.
//! It is narrowband and eight kilobits, worse than G.711 to the ear and far
//! worse than G.722 or Opus, and a peer offered it beside them may still pick
//! it first; it is here for the carrier that insists on it, and a site that
//! wants it names it ([`CodecCatalog::with_order`]).

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

/// The packetisation this stack offers unless told otherwise. Twenty
/// milliseconds is what every peer expects and what every codec here cuts
/// cleanly.
pub const DEFAULT_FRAME_MS: u32 = 20;

/// The first dynamic payload type, from RFC 3551 table 5's "96-127 dynamic".
///
/// Handed out from here, in offer order, to every codec in the catalogue that
/// has no static number of its own — which is Opus, and has only ever been
/// Opus. A build that linked it therefore offers it on 96, and in a build
/// without it no codec takes this number at all: every one left is in table
/// 4, and the first thing to reach 96 is the named-event type the DTMF line
/// carries. `named_events_get_a_dynamic_type_no_codec_took` asserts both
/// halves.
const FIRST_DYNAMIC: u8 = 96;

/// The rate [`Codec::L16Narrowband`] is sampled and clocked at.
const L16_NARROWBAND: u32 = 8_000;

/// The rate [`Codec::L16Wideband`] is sampled and clocked at.
const L16_WIDEBAND: u32 = 16_000;

/// The largest payload one frame of any codec here may be: RFC 6716's
/// longest Opus frame, and the bound the 1500-octet datagram a session
/// builds is sized around.
const LARGEST_PAYLOAD: usize = 1_275;

/// G.729's `a=fmtp` parameters: whether Annex B is allowed (RFC 4856
/// §2.1.9), written out either way rather than left to the default of
/// `yes` a missing parameter means, so that a reader of the description does
/// not have to know the default.
const fn annex_b_parameter(allowed: bool) -> &'static str {
    if allowed { "annexb=yes" } else { "annexb=no" }
}

/// Whether a G.729 `a=fmtp` line allows Annex B. RFC 4856 §2.1.9 reads a
/// missing `annexb` as `yes`, so only one that says `no` refuses it.
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

/// One codec this build contains.
///
/// Not a list of everything with an IANA name: a variant here means there is
/// an encoder and a decoder behind it, which is what makes the enumeration
/// worth reporting to a user interface at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Codec {
    /// G.711 mu-law: payload type 0, the one format RFC 3551 makes every
    /// implementation carry.
    Pcmu,
    /// G.711 A-law: payload type 8, and the ordinary European default. The
    /// first real PBX this stack met allowed nothing else.
    Pcma,
    /// G.722: wideband at the price of a narrowband stream, and accepted by
    /// almost every PBX in service.
    G722,
    /// G.729 with Annex A: eight kilobits of narrowband speech, for the
    /// carrier that insists on it. Always in the build and never in the
    /// default offer — see [`Codec::offered_by_default`]. Annex B's silence
    /// compression goes with it where both ends allow it — see
    /// [`CodecCatalog::with_g729_annex_b`].
    G729,
    /// Opus: the best of them, and the only one here that is linked rather
    /// than written, which is why it is the one behind a feature. A build
    /// with the `opus` feature off has no variant for it at all — see
    /// `docs/05-media.md`.
    #[cfg(feature = "opus")]
    Opus,
    /// L16 at 8 kHz, one channel (RFC 3551 §4.5.11): the samples
    /// themselves, 128 kbit/s of them, for a far end that wants audio no
    /// codec has touched — a recorder, a speech engine, a bridge that
    /// transcodes anyway. Never in the default offer, like G.729, and on a
    /// dynamic payload type as `L16/8000`.
    L16Narrowband,
    /// L16 at 16 kHz, one channel: wideband with nothing lost, at 256
    /// kbit/s, on a dynamic payload type as `L16/16000`.
    L16Wideband,
}

impl Codec {
    /// Every codec this build contains.
    ///
    /// The order is quality first, which is the order to offer them in when
    /// nobody has said otherwise; [`CodecCatalog::with_order`] is how a site
    /// says otherwise.
    ///
    /// Its length is the build's own and not a number to be relied on: seven
    /// here, six where the `opus` feature is off. Anything that needs the
    /// count reads it from this array.
    ///
    /// G.729 and the two L16s are last, and they are the members
    /// [`CodecCatalog::new`] leaves out: see [`Codec::offered_by_default`].
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
    /// Every codec this build contains, which is the written ones: the
    /// `opus` feature is off, so there is no encoder for Opus to offer. See
    /// the other declaration of this constant for the rest.
    #[cfg(not(feature = "opus"))]
    pub const ALL: [Self; 6] = [
        Self::G722,
        Self::Pcmu,
        Self::Pcma,
        Self::G729,
        Self::L16Wideband,
        Self::L16Narrowband,
    ];

    /// Whether [`CodecCatalog::new`] offers it: every codec but G.729 and
    /// the two L16s.
    ///
    /// Those are offered only where an order names them. A peer's own
    /// preference decides among what both ends list (RFC 3264 §6.1), so a
    /// narrowband codec in every offer is a narrowband call with every peer
    /// that happens to prefer it — and the one reason to carry it at all is
    /// a carrier that accepts nothing else, which is a site's configuration
    /// and not a default. L16 is the other way round: the best sound there
    /// is, at eight to sixteen times G.711's bandwidth, which is also a
    /// site's to choose.
    #[must_use]
    pub const fn offered_by_default(self) -> bool {
        !matches!(self, Self::G729 | Self::L16Narrowband | Self::L16Wideband)
    }

    /// What a codec order calls it: the encoding name, and for L16, which is
    /// one name at two rates, the rate after it — `L16/8000`, `L16/16000`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::L16Narrowband => "L16/8000",
            Self::L16Wideband => "L16/16000",
            other => other.encoding_name(),
        }
    }

    /// The name that goes on an `a=rtpmap` line, spelled as IANA registered
    /// it.
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

    /// Whether this is Opus: the one codec in the catalogue that is linked
    /// rather than written, and therefore the one a build can be without.
    ///
    /// The question has to be answerable from the value, because a crate
    /// above this one cannot ask a `cfg` for it. Cargo features are
    /// per-crate and additive, so `sipral-ffi`'s own `opus` being off says
    /// nothing about whether this catalogue has the codec in it — and an
    /// answer derived from the wrong crate's flag is an ABI that lies about
    /// what the build can negotiate. The variant is the fact; the feature
    /// only decides whether there is one.
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

    /// The payload type RFC 3551 table 4 assigns it, for the four that have
    /// one. Opus does not: it is newer than the static table and always
    /// travels as a dynamic type. Nor does L16 at these rates: the table's
    /// two L16 types, 10 and 11, are 44.1 kHz.
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

    /// The ITU-T G.113 Appendix I `Ie`/`Bpl` pair this codec is rated with,
    /// for the RFC 3611 §4.7.5 R factor and MOS a call's VoIP Metrics
    /// report carries — `None` for a codec Table I.4 does not tabulate.
    ///
    /// G.722 gets `None` rather than G.711's numbers: it is a different
    /// codec with its own entry in G.113, not on this build's copy of the
    /// Recommendation text, and reporting the R.711 figures for a
    /// wideband stream would rate it either better or worse than it
    /// actually sounds, in a direction nothing here has measured. Opus
    /// gets `None` for the same reason: it postdates G.113's own codec
    /// list. RFC 3611 §4.7.5's own answer for a metric this stack cannot
    /// honestly compute is the sentinel, not a guess — see
    /// `sipral_rtp::RtpSession::voip_metrics`.
    ///
    /// G.729 gets `None` too, for a narrower reason. Table I.4 does rate it,
    /// but only as "G.729 Annex A with Annex B (VAD)", and a call here runs
    /// Annex B only where both ends allowed it — which the codec alone, all
    /// this function is asked about, does not say. A call with Annex B off is
    /// not the configuration the table rates, and Table I.1 rates Annex A
    /// alone for `Ie` and gives no `Bpl` to go with it. Half a pair is not a
    /// model.
    #[must_use]
    pub const fn quality_model(self) -> Option<sipral_rtp::CodecQualityModel> {
        match self {
            Self::Pcmu | Self::Pcma => Some(sipral_rtp::codec_quality_model(
                sipral_rtp::CodecFamily::G711,
            )),
            Self::G722 | Self::G729 | Self::L16Narrowband | Self::L16Wideband => None,
            #[cfg(feature = "opus")]
            Self::Opus => None,
        }
    }

    /// The RTP timestamp clock, which is what the `a=rtpmap` line carries and
    /// what the timestamps on the wire count in.
    ///
    /// G.722's is 8000 and it samples at 16000. That is not a mistake to be
    /// tidied up: a peer that reads 16000 on a G.722 line refuses the stream.
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

    /// The rate the codec actually hears at, which is what the samples handed
    /// to it and taken from it are in.
    #[must_use]
    pub const fn sample_rate(self) -> u32 {
        match self {
            Self::Pcmu | Self::Pcma => g711::CLOCK_RATE,
            Self::G722 => g722::SAMPLE_RATE,
            Self::G729 => g729::SAMPLE_RATE,
            #[cfg(feature = "opus")]
            Self::Opus => opus::CLOCK_RATE,
            // a sample-based encoding: the clock counts samples
            Self::L16Narrowband | Self::L16Wideband => self.clock_rate(),
        }
    }

    /// Samples in one frame of `millis` milliseconds, at the rate the codec
    /// hears.
    ///
    /// Every rate here is a whole number of samples per millisecond, so the
    /// division comes first and nothing is lost to it.
    #[must_use]
    pub fn frame_samples(self, millis: u32) -> usize {
        usize::try_from(self.sample_rate() / 1_000 * millis).unwrap_or(usize::MAX)
    }

    /// RTP timestamp ticks one frame of `millis` milliseconds covers, at the
    /// clock the wire counts in.
    #[must_use]
    pub const fn frame_ticks(self, millis: u32) -> u32 {
        self.clock_rate() / 1_000 * millis
    }

    /// The largest payload one frame can turn into, which is what a send
    /// buffer has to hold.
    ///
    /// Fixed for the four written here — one octet a sample, one per two for
    /// G.722, ten per eighty for G.729 — and a bound rather than a size for
    /// Opus, whose whole point is that the size depends on what was said.
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

    /// Whether a frame of `millis` milliseconds fits the one datagram an RTP
    /// packet of this build is: every codec's does but L16's past a length,
    /// since L16 is the one whose payload grows with the frame and is never
    /// small. The ceiling is the largest payload any codec here writes,
    /// the 1275 octets of RFC 6716's longest Opus frame, so that header, tag
    /// and payload stay inside the 1500-octet datagram a session builds.
    #[must_use]
    pub fn fits(self, millis: u32) -> bool {
        self.max_payload(millis) <= LARGEST_PAYLOAD
    }

    /// The `a=rtpmap` mapping this codec gets at the payload type given.
    ///
    /// Opus is written `opus/48000/2` even for one channel: RFC 7587 §7 makes
    /// the channel count on the line always two, "regardless of the number of
    /// channels actually being used", and a peer that sees a 1 there may
    /// refuse the stream.
    #[must_use]
    pub fn rtpmap(self, payload: u8) -> RtpMap {
        RtpMap {
            payload,
            encoding: self.encoding_name().to_owned(),
            clock_rate: self.clock_rate(),
            parameters: match self {
                #[cfg(feature = "opus")]
                Self::Opus => Some(opus::RTPMAP_CHANNELS.to_string()),
                // one channel, which RFC 4566 §6 has a missing count mean
                Self::Pcmu
                | Self::Pcma
                | Self::G722
                | Self::G729
                | Self::L16Narrowband
                | Self::L16Wideband => None,
            },
        }
    }

    /// The `a=fmtp` parameters to offer with it, where there are any worth
    /// sending.
    ///
    /// Opus gets `useinbandfec=1`, which RFC 7587 §7.1 defines as this end
    /// being prepared to use the redundancy the far end may put in its
    /// packets. It costs nothing when the peer does not send it and it is the
    /// difference between a lost packet and a heard one when it does.
    ///
    /// G.729 gets `annexb=yes`, which is what a default catalogue offers;
    /// one made with [`CodecCatalog::with_g729_annex_b`] off offers
    /// `annexb=no` instead, and its answers say what that method describes.
    /// Every other codec's parameters in an answer are the offer's own,
    /// echoed, the way `sipral_core`'s answer writes them.
    #[must_use]
    pub const fn fmtp(self) -> Option<&'static str> {
        match self {
            #[cfg(feature = "opus")]
            Self::Opus => Some("useinbandfec=1"),
            Self::G729 => Some(annex_b_parameter(true)),
            Self::Pcmu | Self::Pcma | Self::G722 | Self::L16Narrowband | Self::L16Wideband => None,
        }
    }

    /// Which codec a negotiated stream ended up on, or `None` for one this
    /// build cannot decode.
    ///
    /// The encoding name decides, not the payload type: a static type means
    /// what the table says it means, but a dynamic one means whatever the
    /// `a=rtpmap` called it, and reading the number alone is how a stack
    /// decodes Opus as if it were somebody else's codec. For L16 the rate
    /// and the channel count decide too, because the name alone is every
    /// rate and every count: `L16/44100/2` is not a stream either L16 here
    /// can decode.
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
    /// [`MediaError::UnknownPayload`] when the far end answered with a format
    /// that was not in the offer, which happens and is better said than played
    /// as noise.
    pub fn of_plan(plan: &MediaPlan) -> Result<Self, MediaError> {
        Self::of(&plan.codec).ok_or_else(|| MediaError::UnknownPayload {
            payload: plan.codec.payload(),
            encoding: plan.codec.rtpmap.encoding.clone(),
        })
    }

    /// Every codec this build recognises among a stream's listed formats.
    ///
    /// Membership only, in no particular order: telling one candidate from
    /// another only needs to know whether the far end named it at all, and
    /// which one it preferred is already spent deciding the winner a caller
    /// hands to [`CodecCatalog::candidates`].
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

/// The two lines a DTLS-SRTP description carries, as the engine worked them
/// out: the fingerprint of this stack's certificate (RFC 8122) and the
/// `a=setup` that says which end starts the handshake (RFC 4145).
///
/// Borrowed rather than owned because they are written once into a
/// description and the engine holds both for longer than that.
#[cfg(feature = "dtls")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Keyed<'a> {
    /// The value of `a=fingerprint`.
    pub(crate) fingerprint: &'a str,
    /// The value of `a=setup`.
    pub(crate) setup: &'a str,
}

/// With the `dtls` feature off nothing ever constructs one, and the signature
/// that takes it still has to name a type.
#[cfg(not(feature = "dtls"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Keyed<'a>(core::marker::PhantomData<&'a ()>);

/// What to offer, in what order, and how a frame is cut.
///
/// A stack keeps one as its site policy — what a carrier or a PBX deployment
/// configures once — and every call takes it unless told otherwise, which is
/// what keeps two calls on the same engine comparable rather than each one a
/// surprise. D6 in `docs/13-client-requirements.md` still asks for a way out:
/// an attended transfer holds two calls at once, and a consultation leg to a
/// gateway that only speaks one codec needs its own order without changing
/// what every other call on the same engine offers.
/// [`place_with`](crate::MediaEngine::place_with) and
/// [`answer_with`](crate::MediaEngine::answer_with) are that way out — an
/// explicit catalogue named for one call, not a global anybody could be
/// mutating underneath a call already in progress, which is the race D6 is
/// actually about.
// each bool is an independent choice a site makes about what its calls offer
// (named events, multiplexing, Annex B, feedback), not a state stepped through
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecCatalog {
    order: Vec<Codec>,
    frame_ms: u32,
    dtmf: bool,
    rtcp_mux: bool,
    srtp: SrtpPolicy,
    /// The SRTP transforms this call will run, most preferred first, when
    /// something named them ([`CodecCatalog::with_srtp_suites`]); `None`
    /// for this build's own choice in each place a suite is chosen.
    srtp_suites: Option<Vec<Suite>>,
    /// Whether an SDES key may travel in signalling that is not encrypted
    /// ([`CodecCatalog::with_sdes_signalling`]).
    sdes_signalling: SdesSignalling,
    ice: IcePolicy,
    annex_b: bool,
    feedback: bool,
    voip_metrics: bool,
}

impl CodecCatalog {
    /// Every codec this build offers by default — all it contains but G.729
    /// ([`Codec::offered_by_default`]) — quality first, twenty-millisecond
    /// frames, named events offered, RTCP on its own port, no SRTP offered,
    /// and G.729's Annex B allowed where G.729 is named.
    ///
    /// RTCP multiplexing is off because RFC 5761 §5.1.1 only permits it when
    /// both ends asked, and the equipment this stack is deployed against —
    /// an Asterisk-family PBX behind consumer NAT — does not. Asking for it
    /// unasked costs a line in every offer and buys a port on the calls where
    /// nobody answers. SDES is off for the same shape of reason, which
    /// [`SrtpPolicy::NotOffered`] states in full.
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

    /// The same, offering these codecs in this order and nothing else.
    ///
    /// # Errors
    /// [`MediaError::NoCodecs`] for an empty order, and
    /// [`MediaError::UnsupportedCodec`] for a name this build has no encoder
    /// for or for one named twice — a duplicate would put the same payload
    /// type on the `m=` line twice, which no peer has to make sense of.
    pub fn with_order(codecs: &[&str]) -> Result<Self, MediaError> {
        Self::new().with_codecs(codecs)
    }

    /// This catalogue, offering these codecs in this order and nothing else.
    ///
    /// Everything else it was built with — frame length, named events,
    /// multiplexing, SRTP — is kept. That is what makes this the way one call
    /// says what it offers without also inheriting the defaults for the four
    /// settings it said nothing about, which is what starting again from
    /// [`CodecCatalog::with_order`] would hand it.
    ///
    /// # Errors
    /// [`MediaError::NoCodecs`] for an empty order, and
    /// [`MediaError::UnsupportedCodec`] for a name this build has no encoder
    /// for or for one named twice — a duplicate would put the same payload
    /// type on the `m=` line twice, which no peer has to make sense of.
    /// [`MediaError::BadFrameLength`] when the frame length already set is one
    /// the new order has no frame size for: Opus arriving in a catalogue cut
    /// at thirty milliseconds is that case, and the answer is the same
    /// refusal [`CodecCatalog::with_frame_length`] would have given had the
    /// two been named the other way round.
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

    /// Cut frames at `millis` milliseconds instead of twenty.
    ///
    /// # Errors
    /// [`MediaError::BadFrameLength`] for zero, for an interval Opus has no
    /// frame size for when Opus is in this build and is one of the codecs
    /// offered, and for one that is not a whole number of ten-millisecond
    /// frames when G.729 is offered. G.711 and G.722 cut a whole number of
    /// samples at any whole millisecond, because every rate here is a
    /// multiple of a thousand; Opus has a fixed set of frame durations and
    /// encodes nothing else, and G.729 codes ten milliseconds at a time and
    /// nothing shorter (RFC 3551 §4.5.6), so a packet of fifteen would carry
    /// a frame and a half.
    pub fn with_frame_length(mut self, millis: u32) -> Result<Self, MediaError> {
        #[cfg(feature = "opus")]
        let opus_refuses = self.order.contains(&Codec::Opus)
            && opus::FrameDuration::from_micros(millis.saturating_mul(1_000)).is_err();
        // the one opinion about frame length left is G.729's, below
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

    /// Say whether RFC 4733 named events are offered. On by default: a phone
    /// that cannot send a digit cannot navigate a menu.
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

    /// Say what this call does about SRTP.
    ///
    /// Per call rather than per engine, and off by default: see
    /// [`SrtpPolicy`] for both halves of the reason.
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

    /// Say whether an SDES key may travel in signalling that is not
    /// encrypted ([`SdesSignalling`]): by default it may, and the call says
    /// it did.
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

    /// Run only these SRTP transforms, most preferred first, wherever a
    /// suite is chosen: the `a=crypto` lines an SDES offer carries, in this
    /// order and one each; the offered lines an SDES answer will take, still
    /// in the offerer's order (RFC 4568 §5.1.2) but only among these; and
    /// the protection profiles a DTLS-SRTP handshake offers and accepts, in
    /// this order, of the four there are profiles for — `AEAD_AES_256_GCM`
    /// and `AEAD_AES_128_GCM` (RFC 7714 §14.2) and the two AES-CM ones (RFC
    /// 5764 §4.1.2). Leaving the two GCM suites out is how an account turns
    /// them off, and naming them first is how it asks for them first.
    ///
    /// Unset, an SDES offer names `AEAD_AES_256_GCM` then
    /// `AES_CM_128_HMAC_SHA1_80`, an answer takes any of the seven, and a
    /// handshake the four strongest first. Every line is in the INVITE, so
    /// a long list costs octets RFC 3261 §18.1.1 counts against a datagram:
    /// past two or three suites an offer over UDP needs a stream.
    ///
    /// # Errors
    /// [`MediaError::NoSrtpSuite`] for an empty list or one naming a suite
    /// twice.
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

    /// The SRTP transforms this call is held to, when something named them.
    #[must_use]
    pub fn srtp_suites(&self) -> Option<&[Suite]> {
        self.srtp_suites.as_deref()
    }

    /// The SRTP transforms this catalogue's calls run, in order: the ones it
    /// named ([`CodecCatalog::with_srtp_suites`]), or this build's own when
    /// it named none.
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

    /// Say what this call does about ICE.
    ///
    /// Per call rather than per engine, and off by default: see [`IcePolicy`]
    /// for both halves of the reason.
    ///
    /// A policy that offers ICE also asks for RFC 5761 multiplexing, whatever
    /// [`CodecCatalog::with_rtcp_mux`] was told and in the same way a DTLS
    /// policy does. Without it the stream has a second ICE component, and a
    /// facade that knows one local address cannot give the second one a
    /// candidate — an offer written that way fails this stack's own mismatch
    /// check (RFC 8839 §4.2.5) before any peer sees it.
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

    /// Say whether G.729's Annex B — silence compression: SID frames and
    /// nothing in a pause, and the comfort noise both ends make from them —
    /// is allowed.
    ///
    /// On by default, which is what `G729` means with no parameter (RFC 4856
    /// §2.1.9): an offer says `annexb=yes`, and an answer says whatever the
    /// offer did, `yes` included only where the offer allowed it. Off, both
    /// say `annexb=no`, which RFC 3551 §4.5.6 makes the far end's cue to
    /// send no SID frames. The encoder uses Annex B only where both
    /// descriptions allowed it; the decoder plays a SID frame whatever was
    /// said, since a peer that sends one anyway is better heard than not.
    /// Nothing changes for a catalogue that does not name G.729.
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

    /// Say whether this call asks for RTCP feedback: RTP/AVPF (RFC 4585),
    /// or RTP/SAVPF (RFC 5124) and UDP/TLS/RTP/SAVPF where it is keyed, with
    /// Generic NACKs (`a=rtcp-fb:* nack`) and reduced-size RTCP
    /// (`a=rtcp-rsize`, RFC 5506).
    ///
    /// Off by default, and for the reason RTCP multiplexing is: the profile
    /// is on the `m=` line itself, and a peer that knows only RTP/AVP refuses
    /// a stream offered on RTP/AVPF rather than falling back. On, an offer
    /// names the feedback profile, and an offer that arrived naming one is
    /// answered with the feedback this stack does. Either way, a stream
    /// whose offer and answer both name a feedback profile runs its RTCP by
    /// RFC 4585's rules ([`sipral_rtp::RtpSession::use_feedback`]), and what
    /// was agreed is in [`crate::StreamStatistics::feedback`].
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

    /// Whether an offer asks for, and an answer offers, the VoIP metrics
    /// report of RFC 3611 §4.7 (`a=rtcp-xr:voip-metrics`, §5.1).
    ///
    /// On by default: it is what lets a call this end placed hear what the
    /// far end measured of its audio, for the quality report. Off, the
    /// line is not written — twenty-four bytes off an INVITE that has to fit
    /// a datagram — and a call reports only what this end measured itself;
    /// an offer that asks for the report is still sent it, since RFC 3611
    /// §5.2 makes that the offerer's request and not this end's.
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

    /// The `a=fmtp` parameters this catalogue offers `codec` with:
    /// [`Codec::fmtp`], but for G.729, whose `annexb` is this catalogue's
    /// to say.
    pub(crate) const fn offered_fmtp(&self, codec: Codec) -> Option<&'static str> {
        match codec {
            Codec::G729 => Some(annex_b_parameter(self.annex_b)),
            other => other.fmtp(),
        }
    }

    /// The `a=fmtp` parameters this end writes for `codec` in an answer to
    /// an offer that gave it `offered`, where this end states them rather
    /// than echoes the offer's: only G.729's `annexb`, which is `yes` only
    /// if the offer allowed it (RFC 4856 §2.1.9 reads its absence as `yes`)
    /// and this catalogue does.
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

    /// The vocabulary the negotiation takes: this catalogue as
    /// [`MediaCapabilities`], which is what crosses the seam into
    /// `sipral-core`'s offer/answer.
    ///
    /// Payload types are assigned here rather than being fields of
    /// [`Codec`]: the three static ones are what RFC 3551 says they are, and
    /// the dynamic ones are handed out in offer order from 96, so the same
    /// build offering a different order writes different numbers and is right
    /// both times.
    ///
    /// No `a=crypto` and no secure profile, whatever [`CodecCatalog::srtp`]
    /// says. A key cannot be invented here: it comes out of the seeded token
    /// stream the user agent owns, so
    /// [`MediaEngine`](crate::MediaEngine) draws one per description and adds
    /// the line itself. This is the vocabulary; the keys are the engine's.
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
            // an ICE stream has one component, and that is what asking for
            // multiplexing makes true
            .with_rtcp_mux(self.rtcp_mux || self.ice.offers())
    }

    /// The same, with the keying a description under this policy carries.
    ///
    /// `keys` is one master key and salt per suite
    /// [`CodecCatalog::sdes_offered`] names, each already drawn for the
    /// description being written and paired with its suite, and `dtls` is
    /// the fingerprint of this stack's certificate with the `a=setup` that
    /// goes beside it. A policy that does not offer, or a description with
    /// neither to write, leaves the offer on `RTP/AVP` with nothing in the
    /// body that has to be kept secret.
    ///
    /// A DTLS description also asks for `a=rtcp-mux` whatever the catalogue
    /// says, because RFC 5764 §4.2 puts a second handshake on a separate RTCP
    /// port and this stack runs one; asking here is what keeps that from
    /// becoming a refusal later.
    ///
    /// Under [`SrtpPolicy::DtlsOrSdes`] the offer is the SDES one, on
    /// `RTP/SAVP` and asking for `a=rtcp-mux`; the engine adds the
    /// fingerprint and `a=setup` beside its crypto lines once it is written,
    /// since [`SrtpSupport`] names one way to key a stream and this offer
    /// names two.
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
            // `SrtpPolicy::BestEffort`: the same lines, on the plain profile
            Some(keys) if self.srtp.on_plain_profile() => {
                capabilities.with_srtp(SrtpSupport::SdesOnAvp(keying::offer_lines(keys)))
            }
            Some(keys) => capabilities.with_srtp(SrtpSupport::Sdes(keying::offer_lines(keys))),
            None => capabilities,
        }
    }

    /// What became of every codec in this catalogue, once a call settled on
    /// `winner` — D5's losers, not only its winner.
    ///
    /// `remote` is the far end's own description of the stream: the answer,
    /// when this build placed the call, and the offer, when it answered one
    /// — whichever [`SessionDescription::media_plan`](sipral_core::sdp::SessionDescription::media_plan)
    /// read `winner` off of. Computed once, at the point the negotiation is
    /// worked out, rather than reconstructed afterwards from the two SDP
    /// bodies: a reconstruction can disagree with what the negotiation
    /// actually did in exactly the case somebody is debugging.
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

/// Why a candidate did or did not become the codec a call is using.
///
/// "PCMU was chosen" is a fact a live call already reports
/// ([`crate::MediaEvent::Started`]); this is the diagnosis, and it is what
/// turns a wrong configuration into something visible instead of something
/// inferred from a packet capture (D5, B6, in
/// `docs/13-client-requirements.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecOutcome {
    /// This is what the call settled on. Appears exactly once per call, on
    /// [`MediaSession::codec`](crate::MediaSession::codec)'s own answer.
    Chosen,
    /// The far end's own description of the stream never named it, so there
    /// was nothing on the other side to agree with — "Opus was offered and
    /// the answer did not name it" is this variant.
    NotNamed,
    /// The far end named it too, but the candidate this carries was
    /// preferred first — "G.722 was offered and this build ranked it below
    /// PCMU" is this variant, carrying PCMU. RFC 3264 §6.1 is what has the
    /// far end's own listed order decide between two candidates both sides
    /// could use.
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

    /// A codec this build has that the far end in these tests never names,
    /// spelled the way an order spells it and named the way the enumeration
    /// names it.
    ///
    /// Which codec that is depends on the build: Opus where it is compiled
    /// in, and G.722 where it is not. What the tests using it are about is a
    /// codec on this side that the other side does not offer — so that there
    /// is always a candidate to come back `NotNamed` — and that has to be
    /// some codec in either build. Declared once and shared with the
    /// two-stack tests in `crate::tests`, which want the same thing of it.
    #[cfg(feature = "opus")]
    pub(crate) const UNMATCHED: (&str, Codec) = ("opus", Codec::Opus);
    /// See the other declaration.
    #[cfg(not(feature = "opus"))]
    pub(crate) const UNMATCHED: (&str, Codec) = ("G722", Codec::G722);

    /// The trap the interop harness walked into once already, kept here so
    /// that it cannot be walked into again from the other side.
    #[test]
    fn a_frame_is_three_different_numbers() {
        assert_eq!(Codec::Pcmu.frame_samples(DEFAULT_FRAME_MS), 160);
        assert_eq!(Codec::Pcmu.max_payload(DEFAULT_FRAME_MS), 160);
        assert_eq!(Codec::Pcmu.frame_ticks(DEFAULT_FRAME_MS), 160);

        assert_eq!(Codec::G722.frame_samples(DEFAULT_FRAME_MS), 320);
        assert_eq!(Codec::G722.max_payload(DEFAULT_FRAME_MS), 160);
        assert_eq!(Codec::G722.frame_ticks(DEFAULT_FRAME_MS), 160);

        // two ten-octet frames: RFC 3551 §4.5.6's default packet
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

    /// G.722 counts at half the rate it hears at, and a line that says
    /// otherwise is refused by real peers.
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

    /// L16 is named by its rate, offered only where an order names it, on a
    /// dynamic type with the rate on its `a=rtpmap` line, and read back off a
    /// description only at that rate and one channel.
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
        // and named events on each of the two clocks the codecs run on
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

    /// L16 is the codec whose payload grows with the frame and is never
    /// small, so a frame that would not fit a datagram is refused where it
    /// is set rather than when the first packet is built.
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

    /// G.729 is in the build and out of the default offer, and an order
    /// that names it offers it, on 18, saying whether it takes Annex B.
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

    /// RFC 4856 §2.1.9: `annexb` absent is `yes`, and only `no` refuses it;
    /// an answer says `yes` only where the offer and the catalogue both
    /// allow it, and nothing of its own for any codec but G.729.
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

    /// G.729 codes ten milliseconds at a time, so an order naming it takes a
    /// frame length only in whole tens — and the same length without it is
    /// still taken.
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

    /// The same, for the one codec that has no static number: it is the
    /// dynamic types this build hands out that the order decides.
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

    /// D6: one call names its own order without also losing the four settings
    /// it said nothing about. Starting again from `with_order` would hand it
    /// the defaults for all four, which is the bug this method exists to stop.
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

    /// And the one setting that is not independent of the order stays
    /// checked: a frame length the new order has no size for is refused here
    /// rather than discovered in the offer.
    #[cfg(feature = "opus")]
    #[test]
    fn naming_codecs_rechecks_the_frame_length_against_the_new_order() {
        // thirty milliseconds is a whole number of samples for all three
        // written codecs and no frame Opus encodes
        let narrowband = CodecCatalog::with_order(&["PCMU"])
            .unwrap()
            .with_frame_length(30)
            .unwrap();
        assert_eq!(
            narrowband.clone().with_codecs(&["opus"]).unwrap_err(),
            MediaError::BadFrameLength { millis: 30 }
        );
        // and the same order at a length Opus does encode is taken
        assert!(
            narrowband
                .with_frame_length(20)
                .unwrap()
                .with_codecs(&["opus"])
                .is_ok()
        );
    }

    /// B2: a setting that is accepted and ignored is worse than one that is
    /// refused. A codec this build has no encoder for is refused, by name.
    #[test]
    fn a_codec_this_build_does_not_have_is_refused_by_name() {
        // on its own, so that the refusal is about the name and cannot be the
        // duplicate check answering for it
        let error = CodecCatalog::with_order(&["SILK"]).unwrap_err();
        assert_eq!(
            error,
            MediaError::UnsupportedCodec {
                name: "SILK".to_owned()
            }
        );
        assert!(error.to_string().contains("SILK"));
        // and the message says what there is instead, which is what the build
        // has and not a list written out somewhere
        assert!(error.to_string().contains("G722"));
        #[cfg(feature = "opus")]
        assert!(error.to_string().contains("opus"));

        // and beside a codec that does exist, where the order is still refused
        // rather than quietly shortened
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

    /// Opus is the codec with an opinion about frame length. Thirty
    /// milliseconds is a perfectly ordinary `ptime` for G.711 and Opus has no
    /// such frame, so which answer comes back depends on what is being
    /// offered — and both answers have to be the right one.
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

    /// The other half of that, for the build with no Opus in it: nothing
    /// left has an opinion about frame length, so thirty milliseconds is
    /// taken and only zero is refused.
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

    /// The named-event payload type has to fall clear of the codecs, whatever
    /// order they were put in.
    #[test]
    fn named_events_get_a_dynamic_type_no_codec_took() {
        let capabilities = CodecCatalog::new().capabilities();
        #[cfg(feature = "opus")]
        {
            // Opus is first and takes the first dynamic type, so events take
            // the next one
            assert_eq!(
                capabilities.codecs.first().map(NegotiatedCodec::payload),
                Some(96)
            );
            assert_eq!(capabilities.dtmf_payload(), Some(97));
        }
        #[cfg(not(feature = "opus"))]
        {
            // every codec left has a static number of its own, so events take
            // the first dynamic one
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

    /// The offer this catalogue writes has to name every codec in it and
    /// nothing else, with the fmtp line Opus needs.
    #[test]
    fn the_offer_names_what_the_catalogue_holds() {
        let offer = CodecCatalog::new()
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        #[cfg(feature = "opus")]
        {
            // named events on Opus's clock and on the others' eight
            // kilohertz, G.722's RTP clock included (RFC 3551 §4.5.2)
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

    /// The name decides, not the number: a dynamic type means whatever the
    /// rtpmap called it.
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
        // and a build that compiled it out does not recognise it, which is
        // the whole of what "no Opus" means on the receiving side
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

    /// A stream's own formats, read back as codecs regardless of what this
    /// catalogue offers — membership, not agreement.
    #[test]
    fn named_in_reads_every_codec_a_stream_lists_by_encoding_not_by_number() {
        let stream = CodecCatalog::with_order(&[UNMATCHED.0, "PCMU"])
            .unwrap()
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(Codec::named_in(&stream), [UNMATCHED.1, Codec::Pcmu]);

        // named events and comfort noise are not codecs, whatever number they
        // land on
        let catalog = CodecCatalog::new();
        let with_events = catalog
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(Codec::named_in(&with_events), catalog.codecs());
    }

    /// D5: the codec chosen and why each other candidate was not — a lost
    /// candidate is either never named by the far end, or named and beaten by
    /// whichever candidate its own list preferred first.
    #[test]
    fn candidates_says_why_each_codec_that_was_not_chosen_was_not() {
        let catalog = CodecCatalog::with_order(&[UNMATCHED.0, "PCMA", "PCMU"]).unwrap();
        // the far end's own description names only PCMA and PCMU, PCMA first
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
