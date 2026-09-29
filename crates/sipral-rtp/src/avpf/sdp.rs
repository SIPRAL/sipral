// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a session description says about feedback: the AVPF profile names
//! (RFC 4585 §4.1, RFC 5124), `a=rtcp-fb` (RFC 4585 §4.2) and
//! `a=rtcp-rsize` (RFC 5506 §5), read from and written into the
//! [`MediaDescription`] and [`Attribute`] the rest of the tree negotiates
//! with.

use core::fmt;
use std::time::Duration;

use sipral_core::sdp::{Attribute, MediaDescription};

/// The attribute name of RFC 4585 §4.2.
pub const RTCP_FB: &str = "rtcp-fb";
/// The attribute name of RFC 5506 §5.
pub const RTCP_RSIZE: &str = "rtcp-rsize";
/// The largest RTP payload type, the seven bits of RFC 3550 §5.1.
const MAX_PAYLOAD_TYPE: u8 = 127;

/// The four RTP profiles an audio `m=` line can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RtpProfile {
    /// `RTP/AVP` (RFC 3551): no feedback.
    Avp,
    /// `RTP/SAVP` (RFC 3711): secured, no feedback.
    Savp,
    /// `RTP/AVPF` (RFC 4585).
    Avpf,
    /// `RTP/SAVPF` (RFC 5124): secured, with feedback.
    Savpf,
}

impl RtpProfile {
    /// Read the transport of an `m=` line. Other transports — and the
    /// `UDP/TLS/` forms, which say something about keying this does not
    /// model — are `None`. Case is ignored, as `sipral_core` ignores it when
    /// it asks whether a stream is secured.
    #[must_use]
    pub fn from_proto(proto: &str) -> Option<Self> {
        [Self::Avp, Self::Savp, Self::Avpf, Self::Savpf]
            .into_iter()
            .find(|profile| profile.as_str().eq_ignore_ascii_case(proto))
    }

    /// The profile of `media`, when it is one of the four.
    #[must_use]
    pub fn of(media: &MediaDescription) -> Option<Self> {
        Self::from_proto(&media.proto)
    }

    /// The name as written on an `m=` line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avp => "RTP/AVP",
            Self::Savp => "RTP/SAVP",
            Self::Avpf => "RTP/AVPF",
            Self::Savpf => "RTP/SAVPF",
        }
    }

    /// Whether the profile carries the timing rules and feedback messages
    /// of RFC 4585.
    #[must_use]
    pub const fn has_feedback(self) -> bool {
        matches!(self, Self::Avpf | Self::Savpf)
    }

    /// Whether the profile is secured by SRTP.
    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Savp | Self::Savpf)
    }
}

impl fmt::Display for RtpProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which payload types an `a=rtcp-fb` line speaks for (RFC 4585 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FeedbackPayload {
    /// `*`: every payload type of the stream.
    All,
    /// One payload type.
    Type(u8),
}

impl FeedbackPayload {
    /// Whether the line applies to `payload`.
    #[must_use]
    pub const fn covers(self, payload: u8) -> bool {
        match self {
            Self::All => true,
            Self::Type(pt) => pt == payload,
        }
    }
}

impl fmt::Display for FeedbackPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("*"),
            Self::Type(pt) => write!(f, "{pt}"),
        }
    }
}

/// The feedback an `a=rtcp-fb` line asks for, of the kinds an audio stream
/// uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FeedbackValue {
    /// `nack` with no parameter: the Generic NACK (§4.2, §6.2.1).
    GenericNack,
    /// `trr-int <milliseconds>`: `T_rr_interval` (§4.2, §3.4).
    TrrInt(u32),
}

/// One `a=rtcp-fb` line (RFC 4585 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RtcpFb {
    /// The payload types it applies to.
    pub payload: FeedbackPayload,
    /// What it asks for.
    pub value: FeedbackValue,
}

impl RtcpFb {
    /// Read the value of an `a=rtcp-fb` line.
    ///
    /// `None` for anything not written as §4.2's grammar allows and for
    /// everything this stack does not use — `ack`, `nack` with a parameter
    /// such as `pli`, `ccm`, and any identifier registered since — since
    /// "the receiver MUST ignore" feedback types it does not understand
    /// (§4.2) rather than refuse the description.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let mut tokens = value.split(' ');
        let payload = match tokens.next()? {
            "*" => FeedbackPayload::All,
            pt => FeedbackPayload::Type(parse_payload(pt)?),
        };
        let value = match (tokens.next()?, tokens.next(), tokens.next()) {
            ("nack", None, None) => FeedbackValue::GenericNack,
            ("trr-int", Some(ms), None) => FeedbackValue::TrrInt(parse_digits(ms)?),
            _ => return None,
        };
        Some(Self { payload, value })
    }

    /// Read an attribute, when it is an `a=rtcp-fb` line this stack uses.
    #[must_use]
    pub fn from_attribute(attribute: &Attribute) -> Option<Self> {
        if attribute.name != RTCP_FB {
            return None;
        }
        Self::parse(attribute.value.as_deref()?)
    }

    /// The line's value, as it goes back on the wire.
    #[must_use]
    pub fn to_value(&self) -> String {
        match self.value {
            FeedbackValue::GenericNack => format!("{} nack", self.payload),
            FeedbackValue::TrrInt(ms) => format!("{} trr-int {ms}", self.payload),
        }
    }

    /// The line as an attribute, for a [`MediaDescription`].
    #[must_use]
    pub fn to_attribute(&self) -> Attribute {
        Attribute::with_value(RTCP_FB, &self.to_value())
    }
}

/// A payload type in decimal, without the sign or leading `+` that
/// `str::parse` would allow.
fn parse_payload(text: &str) -> Option<u8> {
    let pt: u8 = parse_digits(text)?.try_into().ok()?;
    (pt <= MAX_PAYLOAD_TYPE).then_some(pt)
}

/// `1*DIGIT`, refused when it overflows.
fn parse_digits(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Every `a=rtcp-fb` line of `media` this stack uses, in the order written;
/// the rest are ignored (§4.2).
pub fn rtcp_fb(media: &MediaDescription) -> impl Iterator<Item = RtcpFb> + '_ {
    media.attributes.iter().filter_map(RtcpFb::from_attribute)
}

/// What `a=rtcp-fb` asks of one payload type of a stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Feedback {
    /// Generic NACKs are wanted.
    pub generic_nack: bool,
    /// `T_rr_interval`, when a `trr-int` applies. A line for the payload
    /// type itself wins over a `*` line; among lines of the same kind the
    /// first one written wins.
    pub trr_interval: Option<Duration>,
}

impl Feedback {
    /// Collect the lines of `media` that apply to `payload`.
    #[must_use]
    pub fn of(media: &MediaDescription, payload: u8) -> Self {
        let mut specific = None;
        let mut wildcard = None;
        let mut generic_nack = false;
        for line in rtcp_fb(media).filter(|line| line.payload.covers(payload)) {
            match line.value {
                FeedbackValue::GenericNack => generic_nack = true,
                FeedbackValue::TrrInt(ms) => {
                    let slot = match line.payload {
                        FeedbackPayload::All => &mut wildcard,
                        FeedbackPayload::Type(_) => &mut specific,
                    };
                    slot.get_or_insert(Duration::from_millis(u64::from(ms)));
                }
            }
        }
        Self {
            generic_nack,
            trr_interval: specific.or(wildcard),
        }
    }
}

/// Whether `media` carries `a=rtcp-rsize` (RFC 5506 §5).
#[must_use]
pub fn offers_rsize(media: &MediaDescription) -> bool {
    media.has_flag(RTCP_RSIZE)
}

/// Whether reduced-size RTCP was negotiated for a stream: only when the
/// offer and the answer both carry `a=rtcp-rsize`. Anything less falls back
/// to compound RTCP in both directions (RFC 5506 §5).
#[must_use]
pub fn rsize_negotiated(offer: &MediaDescription, answer: &MediaDescription) -> bool {
    offers_rsize(offer) && offers_rsize(answer)
}

/// The feedback attributes an answer carries for an offered stream: the
/// `a=rtcp-fb` lines this stack understands, for `*` or for one of the
/// payload types `accepted`, and `a=rtcp-rsize` when it was offered and
/// `rsize` says this end wants it. Lines not understood are left out, which
/// is how an answerer declines them (RFC 4585 §4.2). Nothing is returned for
/// an offer whose profile has no feedback.
#[must_use]
pub fn answer_attributes(offer: &MediaDescription, accepted: &[u8], rsize: bool) -> Vec<Attribute> {
    if !RtpProfile::of(offer).is_some_and(RtpProfile::has_feedback) {
        return Vec::new();
    }
    let mut out: Vec<Attribute> = rtcp_fb(offer)
        .filter(|line| match line.payload {
            FeedbackPayload::All => true,
            FeedbackPayload::Type(pt) => accepted.contains(&pt),
        })
        .map(|line| line.to_attribute())
        .collect();
    if rsize && offers_rsize(offer) {
        out.push(Attribute::flag(RTCP_RSIZE));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sipral_core::sdp::{Attribute, MediaDescription, parse};

    use super::{
        Feedback, FeedbackPayload, FeedbackValue, RTCP_RSIZE, RtcpFb, RtpProfile,
        answer_attributes, offers_rsize, rsize_negotiated, rtcp_fb,
    };

    fn media(body: &str) -> MediaDescription {
        let sdp = parse(body.replace('\n', "\r\n").as_bytes()).unwrap();
        sdp.media.into_iter().next().unwrap()
    }

    const OFFER: &str = "v=0
o=alice 2890844526 2890844526 IN IP4 192.0.2.10
s=-
c=IN IP4 192.0.2.10
t=0 0
m=audio 49170 RTP/AVPF 0 96
a=rtpmap:96 telephone-event/8000
a=rtcp-fb:* nack
a=rtcp-fb:0 trr-int 100
a=rtcp-fb:* trr-int 500
a=rtcp-fb:96 nack pli
a=rtcp-fb:0 ack rpsi
a=rtcp-fb:* goog-remb
a=rtcp-rsize
";

    #[test]
    fn the_profiles_are_told_apart() {
        for (proto, profile, feedback, secure) in [
            ("RTP/AVP", RtpProfile::Avp, false, false),
            ("RTP/SAVP", RtpProfile::Savp, false, true),
            ("RTP/AVPF", RtpProfile::Avpf, true, false),
            ("RTP/SAVPF", RtpProfile::Savpf, true, true),
            ("rtp/avpf", RtpProfile::Avpf, true, false),
        ] {
            let read = RtpProfile::from_proto(proto).unwrap();
            assert_eq!(read, profile);
            assert_eq!(read.has_feedback(), feedback);
            assert_eq!(read.is_secure(), secure);
        }
        assert_eq!(RtpProfile::Savpf.to_string(), "RTP/SAVPF");
        for other in ["UDP/TLS/RTP/SAVPF", "RTP/AVPFX", "udp", ""] {
            assert_eq!(RtpProfile::from_proto(other), None);
        }
        assert_eq!(RtpProfile::of(&media(OFFER)), Some(RtpProfile::Avpf));
    }

    #[test]
    fn the_two_audio_forms_of_rtcp_fb_are_read() {
        assert_eq!(
            RtcpFb::parse("* nack"),
            Some(RtcpFb {
                payload: FeedbackPayload::All,
                value: FeedbackValue::GenericNack
            })
        );
        assert_eq!(
            RtcpFb::parse("96 trr-int 100"),
            Some(RtcpFb {
                payload: FeedbackPayload::Type(96),
                value: FeedbackValue::TrrInt(100)
            })
        );
    }

    #[test]
    fn unknown_or_unused_feedback_is_ignored() {
        for ignored in [
            "96 nack pli",
            "96 nack sli",
            "96 nack rpsi",
            "96 nack app",
            "* ack rpsi",
            "* ack",
            "* ccm fir",
            "* goog-remb",
            "* transport-cc",
        ] {
            assert_eq!(RtcpFb::parse(ignored), None, "{ignored}");
        }
    }

    #[test]
    fn malformed_lines_are_refused() {
        for bad in [
            "",
            "*",
            "* ",
            "128 nack",
            "256 nack",
            "-1 nack",
            "+5 nack",
            "x nack",
            "*  nack",
            "* nack ",
            "* trr-int",
            "* trr-int x",
            "* trr-int +5",
            "* trr-int -5",
            "* trr-int 4294967296",
            "* trr-int 5 6",
            "* NACK",
        ] {
            assert_eq!(RtcpFb::parse(bad), None, "{bad:?}");
        }
        assert!(RtcpFb::parse("127 nack").is_some());
        assert!(RtcpFb::parse("* trr-int 4294967295").is_some());
    }

    #[test]
    fn lines_are_written_back_as_read() {
        for line in ["* nack", "0 nack", "96 trr-int 100", "* trr-int 0"] {
            let parsed = RtcpFb::parse(line).unwrap();
            assert_eq!(parsed.to_value(), line);
            let attribute = parsed.to_attribute();
            assert_eq!(attribute.to_string(), format!("a=rtcp-fb:{line}\r\n"));
            assert_eq!(RtcpFb::from_attribute(&attribute), Some(parsed));
        }
        assert_eq!(
            RtcpFb::from_attribute(&Attribute::with_value("rtcp", "* nack")),
            None
        );
        assert_eq!(RtcpFb::from_attribute(&Attribute::flag("rtcp-fb")), None);
    }

    #[test]
    fn a_media_description_yields_only_the_lines_understood() {
        let offer = media(OFFER);
        assert_eq!(rtcp_fb(&offer).count(), 3);
    }

    #[test]
    fn a_specific_trr_int_wins_over_the_wildcard() {
        let offer = media(OFFER);
        assert_eq!(
            Feedback::of(&offer, 0),
            Feedback {
                generic_nack: true,
                trr_interval: Some(Duration::from_millis(100)),
            }
        );
        assert_eq!(
            Feedback::of(&offer, 96),
            Feedback {
                generic_nack: true,
                trr_interval: Some(Duration::from_millis(500)),
            }
        );
        let wildcard_first = media(&OFFER.replace(
            "a=rtcp-fb:0 trr-int 100\na=rtcp-fb:* trr-int 500\n",
            "a=rtcp-fb:* trr-int 500\na=rtcp-fb:0 trr-int 100\n",
        ));
        assert_eq!(
            Feedback::of(&wildcard_first, 0).trr_interval,
            Some(Duration::from_millis(100))
        );
        let plain = media(&OFFER.replace("a=rtcp-fb:", "a=x-"));
        assert_eq!(Feedback::of(&plain, 0), Feedback::default());
    }

    #[test]
    fn rsize_needs_both_offer_and_answer() {
        let offer = media(OFFER);
        let without = media(&OFFER.replace("a=rtcp-rsize\n", ""));
        assert!(offers_rsize(&offer));
        assert!(!offers_rsize(&without));
        assert!(rsize_negotiated(&offer, &offer));
        assert!(!rsize_negotiated(&offer, &without));
        assert!(!rsize_negotiated(&without, &offer));
    }

    #[test]
    fn an_answer_keeps_what_is_understood_and_accepted() {
        let offer = media(OFFER);
        let attributes = answer_attributes(&offer, &[0], true);
        let lines: Vec<String> = attributes.iter().map(ToString::to_string).collect();
        assert_eq!(
            lines,
            [
                "a=rtcp-fb:* nack\r\n",
                "a=rtcp-fb:0 trr-int 100\r\n",
                "a=rtcp-fb:* trr-int 500\r\n",
                "a=rtcp-rsize\r\n",
            ]
        );
        let declined = answer_attributes(&offer, &[96], false);
        assert!(declined.iter().all(|a| a.name != RTCP_RSIZE));
        assert_eq!(declined.len(), 2);
        let avp = media(&OFFER.replace("RTP/AVPF", "RTP/AVP"));
        assert!(answer_attributes(&avp, &[0], true).is_empty());
        let rsize_not_offered = media(&OFFER.replace("a=rtcp-rsize\n", ""));
        assert!(
            answer_attributes(&rsize_not_offered, &[0], true)
                .iter()
                .all(|a| a.name != RTCP_RSIZE)
        );
    }
}
