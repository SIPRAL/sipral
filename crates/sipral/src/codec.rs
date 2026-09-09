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
//! [`Codec::clock_rate`] are two functions and not one.

use sipral_core::sdp::{
    MediaCapabilities, MediaDescription, MediaPlan, NegotiatedCodec, RtpMap, static_rtpmap,
};
use sipral_media::{g711, g722, opus};

use crate::error::MediaError;

/// The packetisation this stack offers unless told otherwise. Twenty
/// milliseconds is what every peer expects and what every codec here cuts
/// cleanly.
pub const DEFAULT_FRAME_MS: u32 = 20;

/// The first dynamic payload type, from RFC 3551 table 5's "96-127 dynamic".
/// Opus has no static number and takes this one.
const FIRST_DYNAMIC: u8 = 96;

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
    /// Opus: the best of them, and the only one here that is linked rather
    /// than written.
    Opus,
}

impl Codec {
    /// Every codec this build contains.
    ///
    /// The order is quality first, which is the order to offer them in when
    /// nobody has said otherwise; [`CodecCatalog::with_order`] is how a site
    /// says otherwise.
    pub const ALL: [Self; 4] = [Self::Opus, Self::G722, Self::Pcmu, Self::Pcma];

    /// The name that goes on an `a=rtpmap` line, spelled as IANA registered
    /// it.
    #[must_use]
    pub const fn encoding_name(self) -> &'static str {
        match self {
            Self::Pcmu => "PCMU",
            Self::Pcma => "PCMA",
            Self::G722 => g722::ENCODING_NAME,
            Self::Opus => opus::ENCODING_NAME,
        }
    }

    /// The payload type RFC 3551 table 4 assigns it, for the three that have
    /// one. Opus does not: it is newer than the static table and always
    /// travels as a dynamic type.
    #[must_use]
    pub const fn static_payload(self) -> Option<u8> {
        match self {
            Self::Pcmu => Some(0),
            Self::Pcma => Some(8),
            Self::G722 => Some(g722::PAYLOAD_TYPE),
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
            Self::Opus => opus::CLOCK_RATE,
        }
    }

    /// The rate the codec actually hears at, which is what the samples handed
    /// to it and taken from it are in.
    #[must_use]
    pub const fn sample_rate(self) -> u32 {
        match self {
            Self::Pcmu | Self::Pcma => g711::CLOCK_RATE,
            Self::G722 => g722::SAMPLE_RATE,
            Self::Opus => opus::CLOCK_RATE,
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
    /// Fixed for the three written here — one octet a sample, or one per two
    /// for G.722 — and a bound rather than a size for Opus, whose whole point
    /// is that the size depends on what was said.
    #[must_use]
    pub fn max_payload(self, millis: u32) -> usize {
        match self {
            Self::Pcmu | Self::Pcma => self.frame_samples(millis),
            Self::G722 => self.frame_samples(millis) / 2,
            Self::Opus => opus::MAX_FRAME_BYTES,
        }
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
                Self::Opus => Some(opus::RTPMAP_CHANNELS.to_string()),
                Self::Pcmu | Self::Pcma | Self::G722 => None,
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
    #[must_use]
    pub const fn fmtp(self) -> Option<&'static str> {
        match self {
            Self::Opus => Some("useinbandfec=1"),
            Self::Pcmu | Self::Pcma | Self::G722 => None,
        }
    }

    /// Which codec a negotiated stream ended up on, or `None` for one this
    /// build cannot decode.
    ///
    /// The encoding name decides, not the payload type: a static type means
    /// what the table says it means, but a dynamic one means whatever the
    /// `a=rtpmap` called it, and reading the number alone is how a stack
    /// decodes Opus as if it were somebody else's codec.
    #[must_use]
    pub fn of(negotiated: &NegotiatedCodec) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|codec| negotiated.is_encoding(codec.encoding_name()))
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
        f.write_str(self.encoding_name())
    }
}

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecCatalog {
    order: Vec<Codec>,
    frame_ms: u32,
    dtmf: bool,
    rtcp_mux: bool,
}

impl CodecCatalog {
    /// Every codec this build contains, quality first, twenty-millisecond
    /// frames, named events offered and RTCP on its own port.
    ///
    /// RTCP multiplexing is off because RFC 5761 §5.1.1 only permits it when
    /// both ends asked, and the equipment this stack is deployed against —
    /// an Asterisk-family PBX behind consumer NAT — does not. Asking for it
    /// unasked costs a line in every offer and buys a port on the calls where
    /// nobody answers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            order: Codec::ALL.to_vec(),
            frame_ms: DEFAULT_FRAME_MS,
            dtmf: true,
            rtcp_mux: false,
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
        if codecs.is_empty() {
            return Err(MediaError::NoCodecs);
        }
        let mut order = Vec::with_capacity(codecs.len());
        for name in codecs {
            let codec = Codec::ALL
                .into_iter()
                .find(|codec| codec.encoding_name().eq_ignore_ascii_case(name))
                .ok_or_else(|| MediaError::unsupported(name))?;
            if order.contains(&codec) {
                return Err(MediaError::unsupported(name));
            }
            order.push(codec);
        }
        Ok(Self {
            order,
            ..Self::new()
        })
    }

    /// Cut frames at `millis` milliseconds instead of twenty.
    ///
    /// # Errors
    /// [`MediaError::BadFrameLength`] for zero, and for an interval Opus has
    /// no frame size for when Opus is one of the codecs offered. The three
    /// written codecs cut a whole number of samples at any whole millisecond,
    /// because every rate here is a multiple of a thousand; Opus has a fixed
    /// set of frame durations and encodes nothing else.
    pub fn with_frame_length(mut self, millis: u32) -> Result<Self, MediaError> {
        let opus_refuses = self.order.contains(&Codec::Opus)
            && opus::FrameDuration::from_micros(millis.saturating_mul(1_000)).is_err();
        if millis == 0 || opus_refuses {
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
                match codec.fmtp() {
                    Some(fmtp) => mapped.with_fmtp(fmtp),
                    None => mapped,
                }
            })
            .collect();
        MediaCapabilities::new(codecs)
            .with_dtmf(self.dtmf)
            .with_rtcp_mux(self.rtcp_mux)
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
mod tests {
    use super::{Codec, CodecCandidate, CodecCatalog, CodecOutcome, DEFAULT_FRAME_MS};
    use crate::error::MediaError;
    use sipral_core::sdp::{Direction, NegotiatedCodec, RtpMap};

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

        assert_eq!(Codec::Opus.frame_samples(DEFAULT_FRAME_MS), 960);
        assert_eq!(Codec::Opus.frame_ticks(DEFAULT_FRAME_MS), 960);
    }

    /// G.722 counts at half the rate it hears at, and a line that says
    /// otherwise is refused by real peers.
    #[test]
    fn g722_counts_at_half_the_rate_it_hears_at() {
        assert_eq!(Codec::G722.clock_rate(), 8_000);
        assert_eq!(Codec::G722.sample_rate(), 16_000);
        assert_eq!(Codec::G722.rtpmap(9).to_value(), "9 G722/8000");
    }

    #[test]
    fn opus_advertises_two_channels_whatever_it_carries() {
        assert_eq!(Codec::Opus.rtpmap(96).to_value(), "96 opus/48000/2");
    }

    #[test]
    fn the_static_payload_types_are_the_ones_rfc_3551_assigned() {
        assert_eq!(Codec::Pcmu.static_payload(), Some(0));
        assert_eq!(Codec::Pcma.static_payload(), Some(8));
        assert_eq!(Codec::G722.static_payload(), Some(9));
        assert_eq!(Codec::Opus.static_payload(), None);
    }

    #[test]
    fn an_order_names_the_codecs_and_keeps_them_in_that_order() {
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
        // and the message says what there is instead
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

    /// The named-event payload type has to fall clear of the codecs, whatever
    /// order they were put in.
    #[test]
    fn named_events_get_a_dynamic_type_no_codec_took() {
        let capabilities = CodecCatalog::new().capabilities();
        assert_eq!(
            capabilities.codecs.first().map(NegotiatedCodec::payload),
            Some(96)
        );
        assert_eq!(capabilities.dtmf_payload(), Some(97));

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
        assert_eq!(offer.formats, ["96", "9", "0", "8", "97"]);
        assert_eq!(offer.fmtp(96), Some("useinbandfec=1"));
        assert_eq!(offer.fmtp(97), Some("0-15"));
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
        assert_eq!(Codec::of(&opus), Some(Codec::Opus));

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
        let stream = CodecCatalog::with_order(&["opus", "PCMU"])
            .unwrap()
            .capabilities()
            .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(Codec::named_in(&stream), [Codec::Opus, Codec::Pcmu]);

        // named events and comfort noise are not codecs, whatever number they
        // land on
        let with_events =
            CodecCatalog::new()
                .capabilities()
                .offer("audio", 40_000, Direction::SendRecv);
        assert_eq!(
            Codec::named_in(&with_events),
            [Codec::Opus, Codec::G722, Codec::Pcmu, Codec::Pcma]
        );
    }

    /// D5: the codec chosen and why each other candidate was not — a lost
    /// candidate is either never named by the far end, or named and beaten by
    /// whichever candidate its own list preferred first.
    #[test]
    fn candidates_says_why_each_codec_that_was_not_chosen_was_not() {
        let catalog = CodecCatalog::with_order(&["opus", "PCMA", "PCMU"]).unwrap();
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
                    codec: Codec::Opus,
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
