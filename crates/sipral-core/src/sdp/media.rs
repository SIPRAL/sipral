// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One media stream of a session description (RFC 4566 §5.14).

use core::fmt;

use super::session::{Attribute, Connection};

/// Which way media may flow (RFC 4566 §6, RFC 3264 §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Both ways. The default when nothing says otherwise.
    SendRecv,
    /// The one who wrote it sends and does not receive.
    SendOnly,
    /// The one who wrote it receives and does not send.
    RecvOnly,
    /// Neither way, and the stream stays in the session.
    Inactive,
}

impl Direction {
    /// The attribute name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendRecv => "sendrecv",
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::Inactive => "inactive",
        }
    }

    /// Read one of the four attribute names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "sendrecv" => Self::SendRecv,
            "sendonly" => Self::SendOnly,
            "recvonly" => Self::RecvOnly,
            "inactive" => Self::Inactive,
            _ => return None,
        })
    }

    /// The direction an answer may carry, given what was offered and what the
    /// answerer wants (RFC 3264 §6.1).
    ///
    /// The offer decides what is possible and the answerer decides within it.
    /// A stream offered `sendonly` can only be answered `recvonly` or
    /// `inactive` — there is nothing to argue about, because the offerer has
    /// already said it will not listen. An offer of `inactive` leaves one
    /// answer. Only `sendrecv` leaves the choice open, and it is the caller's.
    #[must_use]
    pub const fn answer_to(offer: Self, wanted: Self) -> Self {
        match offer {
            Self::SendRecv => wanted,
            // "If a stream is offered as sendonly, the corresponding stream
            // MUST be marked as recvonly or inactive in the answer."
            Self::SendOnly => match wanted {
                Self::RecvOnly | Self::SendRecv => Self::RecvOnly,
                Self::SendOnly | Self::Inactive => Self::Inactive,
            },
            // "If a media stream is listed as recvonly in the offer, the
            // answer MUST be marked as sendonly or inactive in the answer."
            Self::RecvOnly => match wanted {
                Self::SendOnly | Self::SendRecv => Self::SendOnly,
                Self::RecvOnly | Self::Inactive => Self::Inactive,
            },
            // "If an offered media stream is listed as inactive, it MUST be
            // marked as inactive in the answer."
            Self::Inactive => Self::Inactive,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `a=rtpmap:<payload type> <encoding name>/<clock rate>[/<parameters>]`
/// (RFC 4566 §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpMap {
    /// The payload type it names.
    pub payload: u8,
    /// `PCMU`, `telephone-event`, and so on.
    pub encoding: String,
    /// In hertz.
    pub clock_rate: u32,
    /// Channel count for audio, when written.
    pub parameters: Option<String>,
}

impl RtpMap {
    /// Read the value of an `a=rtpmap` line.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let (payload, rest) = value.split_once(' ')?;
        let payload = payload.parse().ok()?;
        let mut parts = rest.splitn(3, '/');
        let encoding = parts.next()?;
        let clock_rate = parts.next()?.parse().ok()?;
        if encoding.is_empty() {
            return None;
        }
        Some(Self {
            payload,
            encoding: encoding.to_owned(),
            clock_rate,
            parameters: parts.next().map(str::to_owned),
        })
    }

    /// The line's value, as it goes back on the wire.
    #[must_use]
    pub fn to_value(&self) -> String {
        let mut out = format!("{} {}/{}", self.payload, self.encoding, self.clock_rate);
        if let Some(parameters) = &self.parameters {
            out.push('/');
            out.push_str(parameters);
        }
        out
    }
}

/// One `m=` block: the stream and everything said about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaDescription {
    /// `audio`, `video`, `application`, and the rest of §5.14's list.
    pub media: String,
    /// Where the answerer wants this stream. Zero means rejected.
    pub port: u16,
    /// `m=video 49170/2 RTP/AVP 31`: how many ports, when more than one.
    pub port_count: Option<u16>,
    /// `RTP/AVP`, `RTP/SAVP`, and so on.
    pub proto: String,
    /// The formats, as written. For RTP they are payload type numbers; for
    /// other transports they are whatever that transport uses, so they are
    /// kept as text rather than forced into numbers.
    pub formats: Vec<String>,
    /// `i=`
    pub information: Option<String>,
    /// `c=`, when this stream overrides the session-level one.
    pub connection: Option<Connection>,
    /// `b=`, kept as written.
    pub bandwidth: Vec<String>,
    /// `k=`, kept as written.
    pub key: Option<String>,
    /// `a=`, in the order they were written.
    pub attributes: Vec<Attribute>,
}

impl MediaDescription {
    /// A stream with nothing said about it yet.
    #[must_use]
    pub fn new(media: &str, port: u16, proto: &str, formats: Vec<String>) -> Self {
        Self {
            media: media.to_owned(),
            port,
            port_count: None,
            proto: proto.to_owned(),
            formats,
            information: None,
            connection: None,
            bandwidth: Vec::new(),
            key: None,
            attributes: Vec::new(),
        }
    }

    /// Whether the stream is refused. RFC 3264 §6: "To reject an offered
    /// stream, the port number in the corresponding stream in the answer MUST
    /// be set to zero."
    #[must_use]
    pub const fn is_rejected(&self) -> bool {
        self.port == 0
    }

    /// The formats that are RTP payload type numbers, in the order written,
    /// which §6.1 makes the order of preference.
    pub fn payload_types(&self) -> impl Iterator<Item = u8> {
        self.formats.iter().filter_map(|f| f.parse().ok())
    }

    /// The first attribute of that name.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Whether a flag attribute is present.
    #[must_use]
    pub fn has_flag(&self, name: &str) -> bool {
        self.attributes.iter().any(|a| a.name == name)
    }

    /// The direction written on this stream, if one is.
    #[must_use]
    pub fn direction(&self) -> Option<Direction> {
        self.attributes
            .iter()
            .find_map(|a| Direction::from_name(&a.name))
    }

    /// The `a=rtpmap` for one payload type.
    #[must_use]
    pub fn rtpmap(&self, payload: u8) -> Option<RtpMap> {
        self.attributes
            .iter()
            .filter(|a| a.name == "rtpmap")
            .filter_map(|a| RtpMap::parse(a.value.as_deref()?))
            .find(|map| map.payload == payload)
    }

    /// The `a=fmtp` parameters for one payload type.
    #[must_use]
    pub fn fmtp(&self, payload: u8) -> Option<&str> {
        self.attributes
            .iter()
            .filter(|a| a.name == "fmtp")
            .filter_map(|a| a.value.as_deref())
            .find_map(|value| {
                let (format, parameters) = value.split_once(' ')?;
                (format.parse::<u8>().ok()? == payload).then_some(parameters)
            })
    }

    /// `a=ptime`, the packetisation interval in milliseconds.
    #[must_use]
    pub fn ptime(&self) -> Option<u32> {
        self.attribute("ptime")?.value.as_deref()?.parse().ok()
    }

    /// `a=rtcp-mux` (RFC 5761): RTP and RTCP share one port.
    #[must_use]
    pub fn has_rtcp_mux(&self) -> bool {
        self.has_flag("rtcp-mux")
    }
}

impl fmt::Display for MediaDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m={} {}", self.media, self.port)?;
        if let Some(count) = self.port_count {
            write!(f, "/{count}")?;
        }
        write!(f, " {}", self.proto)?;
        for format in &self.formats {
            write!(f, " {format}")?;
        }
        f.write_str("\r\n")?;
        if let Some(information) = &self.information {
            write!(f, "i={information}\r\n")?;
        }
        if let Some(connection) = &self.connection {
            write!(f, "{connection}")?;
        }
        for bandwidth in &self.bandwidth {
            write!(f, "b={bandwidth}\r\n")?;
        }
        if let Some(key) = &self.key {
            write!(f, "k={key}\r\n")?;
        }
        for attribute in &self.attributes {
            write!(f, "{attribute}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Direction, MediaDescription, RtpMap};
    use crate::sdp::Attribute;

    const ALL: [Direction; 4] = [
        Direction::SendRecv,
        Direction::SendOnly,
        Direction::RecvOnly,
        Direction::Inactive,
    ];

    const fn sends(direction: Direction) -> bool {
        matches!(direction, Direction::SendRecv | Direction::SendOnly)
    }

    const fn receives(direction: Direction) -> bool {
        matches!(direction, Direction::SendRecv | Direction::RecvOnly)
    }

    #[test]
    fn the_answer_direction_table_of_section_6_1() {
        use Direction::{Inactive, RecvOnly, SendOnly, SendRecv};
        for (offer, wanted, expected) in [
            // "If an offered media stream is listed as sendrecv ... the
            // corresponding stream in the answer MAY be marked as sendonly,
            // recvonly, sendrecv, or inactive."
            (SendRecv, SendRecv, SendRecv),
            (SendRecv, SendOnly, SendOnly),
            (SendRecv, RecvOnly, RecvOnly),
            (SendRecv, Inactive, Inactive),
            // "If a stream is offered as sendonly, the corresponding stream
            // MUST be marked as recvonly or inactive in the answer."
            (SendOnly, SendRecv, RecvOnly),
            (SendOnly, RecvOnly, RecvOnly),
            (SendOnly, SendOnly, Inactive),
            (SendOnly, Inactive, Inactive),
            // "If a media stream is listed as recvonly in the offer, the
            // answer MUST be marked as sendonly or inactive in the answer."
            (RecvOnly, SendRecv, SendOnly),
            (RecvOnly, SendOnly, SendOnly),
            (RecvOnly, RecvOnly, Inactive),
            (RecvOnly, Inactive, Inactive),
            // "If an offered media stream is listed as inactive, it MUST be
            // marked as inactive in the answer."
            (Inactive, SendRecv, Inactive),
            (Inactive, SendOnly, Inactive),
            (Inactive, RecvOnly, Inactive),
            (Inactive, Inactive, Inactive),
        ] {
            assert_eq!(
                Direction::answer_to(offer, wanted),
                expected,
                "offer {offer}, wanted {wanted}"
            );
        }
    }

    #[test]
    fn an_answer_never_claims_more_than_either_side_allowed() {
        for offer in ALL {
            for wanted in ALL {
                let answer = Direction::answer_to(offer, wanted);
                assert!(
                    !sends(answer) || receives(offer),
                    "{answer} would send to an offer of {offer}, which is not listening"
                );
                assert!(
                    !receives(answer) || sends(offer),
                    "{answer} would wait for an offer of {offer}, which sends nothing"
                );
                assert!(!sends(answer) || sends(wanted), "more than was wanted");
                assert!(
                    !receives(answer) || receives(wanted),
                    "more than was wanted"
                );
            }
        }
    }

    #[test]
    fn an_rtpmap_survives_the_round_trip() {
        for value in ["0 PCMU/8000", "101 telephone-event/8000", "98 L16/16000/2"] {
            let map = RtpMap::parse(value).expect("an rtpmap");
            assert_eq!(map.to_value(), value);
        }
        assert_eq!(
            RtpMap::parse("98 L16/16000/2")
                .expect("channels")
                .parameters,
            Some("2".to_owned())
        );
        for bad in ["", "0", "x PCMU/8000", "0 PCMU", "0 /8000", "0 PCMU/x"] {
            assert!(RtpMap::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_format_that_is_not_a_payload_type_is_not_counted_as_one() {
        // "m=application 9 UDP/DTLS/SCTP webrtc-datachannel"
        let media = MediaDescription::new(
            "application",
            9,
            "UDP/DTLS/SCTP",
            vec!["webrtc-datachannel".to_owned()],
        );
        assert_eq!(media.payload_types().count(), 0);
        assert!(!media.is_rejected());
    }

    #[test]
    fn a_port_of_zero_is_a_refusal() {
        let media = MediaDescription::new("audio", 0, "RTP/AVP", vec!["0".to_owned()]);
        assert!(media.is_rejected());
    }

    #[test]
    fn the_attributes_answer_the_questions_asked_of_them() {
        let mut media = MediaDescription::new("audio", 49_170, "RTP/AVP", vec!["0".to_owned()]);
        media.attributes = vec![
            Attribute::with_value("rtpmap", "0 PCMU/8000"),
            Attribute::with_value("fmtp", "101 0-15"),
            Attribute::with_value("ptime", "20"),
            Attribute::flag("rtcp-mux"),
            Attribute::flag("recvonly"),
        ];
        assert_eq!(media.rtpmap(0).expect("rtpmap").encoding, "PCMU");
        assert!(media.rtpmap(8).is_none());
        assert_eq!(media.fmtp(101), Some("0-15"));
        assert!(media.fmtp(0).is_none());
        assert_eq!(media.ptime(), Some(20));
        assert!(media.has_rtcp_mux());
        assert_eq!(media.direction(), Some(Direction::RecvOnly));
    }
}
