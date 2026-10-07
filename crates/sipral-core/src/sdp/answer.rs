// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Building the answer to an offer (RFC 3264 §6).
//!
//! The answer mirrors the offer: same `m=` lines in the same order, same
//! `t=` line. Which codecs and streams to keep are arguments. The rules
//! the RFC fixes are applied here: the direction, the payload type numbers
//! and the `a=rtpmap` lines of §6.1.

use super::error::SdpError;
use super::media::{Direction, MediaDescription};
use super::session::{Attribute, Connection, Origin, SessionDescription};

/// What to do with one offered stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamAnswer {
    /// Refuse it. "An offered stream MAY be rejected in the answer, for any
    /// reason", and the way to say so is a port of zero.
    Reject,
    /// Take it.
    Accept(AcceptedStream),
}

/// A stream the answerer is taking, and on what terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedStream {
    /// Where this end wants the media. Present even for sendonly streams;
    /// RTCP uses the next port up.
    pub port: u16,
    /// A `c=` for this stream alone, when it differs from the session's.
    pub connection: Option<Connection>,
    /// The formats to keep, in order of preference. At least one must be in
    /// the offer; extra ones are allowed by §6.1.
    pub formats: Vec<String>,
    /// What this end wants. What it gets is this narrowed by the offer.
    pub direction: Direction,
    /// Anything else about the stream: `ptime`, `rtcp-mux`, `crypto`. A
    /// direction attribute here is ignored.
    pub attributes: Vec<Attribute>,
}

impl AcceptedStream {
    /// Take a stream with the formats given, in the order given.
    #[must_use]
    pub fn new(port: u16, formats: Vec<String>) -> Self {
        Self {
            port,
            connection: None,
            formats,
            direction: Direction::SendRecv,
            attributes: Vec::new(),
        }
    }

    /// Take a stream, keeping the formats this end supports in the order the
    /// offer listed them. §6.1 recommends this so both ends pick the same codec.
    #[must_use]
    pub fn in_offer_order(port: u16, offered: &MediaDescription, supported: &[&str]) -> Self {
        let formats = offered
            .formats
            .iter()
            .filter(|format| supported.iter().any(|s| s == &format.as_str()))
            .cloned()
            .collect();
        Self::new(port, formats)
    }

    /// Say which way media may flow, as far as this end is concerned.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Add an attribute.
    #[must_use]
    pub fn with_attribute(mut self, attribute: Attribute) -> Self {
        self.attributes.push(attribute);
        self
    }
}

impl SessionDescription {
    /// Answer this offer (RFC 3264 §6).
    ///
    /// One [`StreamAnswer`] per `m=` line of the offer, in order. The origin is
    /// the answerer's own, as §6 requires.
    ///
    /// # Errors
    /// [`SdpError::StreamCount`] when the number of answers does not match the
    /// offer, and [`SdpError::NoCommonFormat`] when an accepted stream keeps
    /// no offered format (§6.1 rejects such a stream instead).
    pub fn answer(
        &self,
        origin: Origin,
        connection: Connection,
        streams: &[StreamAnswer],
    ) -> Result<Self, SdpError> {
        if streams.len() != self.media.len() {
            return Err(SdpError::StreamCount {
                offered: self.media.len(),
                answered: streams.len(),
            });
        }

        let mut answer = Self::new(origin, connection);
        // §6: the `t=` line of the answer equals the offer's
        answer.timing.clone_from(&self.timing);

        for (index, (offered, wanted)) in self.media.iter().zip(streams).enumerate() {
            answer.media.push(match wanted {
                StreamAnswer::Reject => reject(offered),
                StreamAnswer::Accept(accepted) => self.accept(index, offered, accepted)?,
            });
        }
        Ok(answer)
    }

    fn accept(
        &self,
        index: usize,
        offered: &MediaDescription,
        accepted: &AcceptedStream,
    ) -> Result<MediaDescription, SdpError> {
        if !accepted
            .formats
            .iter()
            .any(|format| offered.formats.contains(format))
        {
            return Err(SdpError::NoCommonFormat { stream: index });
        }

        // §6: the media type must match, and so must the transport
        let mut media = MediaDescription::new(
            &offered.media,
            accepted.port,
            &offered.proto,
            accepted.formats.clone(),
        );
        media.connection.clone_from(&accepted.connection);

        // §6.1: rtpmap is required for dynamic types. The offer's mappings
        // apply unless the caller wrote its own.
        let caller_defines = |name: &str, payload: u8| {
            accepted.attributes.iter().any(|a| {
                a.name == name
                    && a.value
                        .as_deref()
                        .and_then(|v| v.split([' ', '/']).next())
                        .and_then(|v| v.parse::<u8>().ok())
                        == Some(payload)
            })
        };
        for payload in media.payload_types().collect::<Vec<_>>() {
            if !caller_defines("rtpmap", payload)
                && let Some(rtpmap) = offered.rtpmap(payload)
            {
                media
                    .attributes
                    .push(Attribute::with_value("rtpmap", &rtpmap.to_value()));
            }
            // §6.1: matching fmtp is required. Without knowing the codec we cannot
            // tell configuring parameters from hints, so all are kept.
            if !caller_defines("fmtp", payload)
                && let Some(fmtp) = offered.fmtp(payload)
            {
                media
                    .attributes
                    .push(Attribute::with_value("fmtp", &format!("{payload} {fmtp}")));
            }
        }

        let direction = Direction::answer_to(self.direction_of(offered), accepted.direction);
        media.attributes.push(Attribute::flag(direction.as_str()));
        media.attributes.extend(
            accepted
                .attributes
                .iter()
                .filter(|a| a.direction().is_none())
                .cloned(),
        );
        Ok(media)
    }
}

/// A stream turned down: port zero, formats ignored but at least one
/// present (§6).
fn reject(offered: &MediaDescription) -> MediaDescription {
    MediaDescription::new(
        &offered.media,
        0,
        &offered.proto,
        offered.formats.first().cloned().into_iter().collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{AcceptedStream, StreamAnswer};
    use crate::sdp::{Attribute, Connection, Direction, Origin, SdpError, parse};

    /// The offer of RFC 3264 §10.1, byte for byte.
    const OFFER: &str = "v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 host.anywhere.com\r\n\
s=\r\n\
c=IN IP4 host.anywhere.com\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
m=video 51372 RTP/AVP 31\r\n\
a=rtpmap:31 H261/90000\r\n\
m=video 53000 RTP/AVP 32\r\n\
a=rtpmap:32 MPV/90000\r\n";

    fn offer() -> crate::sdp::SessionDescription {
        parse(OFFER.as_bytes()).expect("the offer")
    }

    fn bob() -> Origin {
        Origin {
            username: "bob".to_owned(),
            session_id: 2_890_844_730,
            version: 2_890_844_730,
            network: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            address: "host.example.com".to_owned(),
        }
    }

    fn to_bob() -> Connection {
        Connection {
            network: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            address: "host.example.com".to_owned(),
        }
    }

    #[test]
    fn the_worked_example_of_section_10_1() {
        // Bob "does not want to receive or send the first video stream"
        let answer = offer()
            .answer(
                bob(),
                to_bob(),
                &[
                    StreamAnswer::Accept(AcceptedStream::new(49_920, vec!["0".to_owned()])),
                    StreamAnswer::Reject,
                    StreamAnswer::Accept(AcceptedStream::new(53_000, vec!["32".to_owned()])),
                ],
            )
            .expect("an answer");

        // The RFC omits the default sendrecv lines; we write them.
        assert_eq!(
            String::from_utf8(answer.to_bytes()).expect("utf-8"),
            "v=0\r\n\
o=bob 2890844730 2890844730 IN IP4 host.example.com\r\n\
s=-\r\n\
c=IN IP4 host.example.com\r\n\
t=0 0\r\n\
m=audio 49920 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n\
m=video 0 RTP/AVP 31\r\n\
m=video 53000 RTP/AVP 32\r\n\
a=rtpmap:32 MPV/90000\r\n\
a=sendrecv\r\n"
        );
    }

    #[test]
    fn the_answer_has_one_stream_per_offered_stream_and_no_more() {
        let refused = offer().answer(bob(), to_bob(), &[StreamAnswer::Reject]);
        assert_eq!(
            refused.unwrap_err(),
            SdpError::StreamCount {
                offered: 3,
                answered: 1
            }
        );
    }

    #[test]
    fn a_stream_accepted_with_nothing_the_offer_listed_is_a_mistake_not_an_answer() {
        let answer = offer().answer(
            bob(),
            to_bob(),
            &[
                StreamAnswer::Accept(AcceptedStream::new(49_920, vec!["8".to_owned()])),
                StreamAnswer::Reject,
                StreamAnswer::Reject,
            ],
        );
        assert_eq!(answer.unwrap_err(), SdpError::NoCommonFormat { stream: 0 });
    }

    #[test]
    fn the_formats_keep_the_order_the_offer_gave_them() {
        let offer = parse(
            b"v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 8 22 48\r\n",
        )
        .expect("an offer");
        let stream = AcceptedStream::in_offer_order(
            5000,
            offer.media.first().expect("audio"),
            &["48", "8", "111"],
        );
        assert_eq!(stream.formats, ["8", "48"]);
    }

    #[test]
    fn the_answer_carries_the_mappings_the_offer_defined() {
        let offer = parse(
            b"v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\n\
a=ptime:20\r\n",
        )
        .expect("an offer");

        let answer = offer
            .answer(
                bob(),
                to_bob(),
                &[StreamAnswer::Accept(AcceptedStream::new(
                    5000,
                    vec!["0".to_owned(), "101".to_owned()],
                ))],
            )
            .expect("an answer");
        let audio = answer.media.first().expect("audio");

        assert_eq!(audio.rtpmap(101).expect("101").encoding, "telephone-event");
        assert_eq!(audio.rtpmap(0).expect("0").encoding, "PCMU");
        assert_eq!(audio.fmtp(101), Some("0-15"));
        // ptime is the answerer's own business, and it did not ask for one
        assert_eq!(audio.ptime(), None);
    }

    #[test]
    fn what_the_caller_writes_itself_stands_instead() {
        let offer = parse(
            b"v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 101\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\n",
        )
        .expect("an offer");

        let answer = offer
            .answer(
                bob(),
                to_bob(),
                &[StreamAnswer::Accept(
                    AcceptedStream::new(5000, vec!["101".to_owned()])
                        .with_attribute(Attribute::with_value("fmtp", "101 0-11"))
                        .with_attribute(Attribute::with_value("ptime", "20")),
                )],
            )
            .expect("an answer");
        let audio = answer.media.first().expect("audio");
        assert_eq!(
            audio.fmtp(101),
            Some("0-11"),
            "not copied over the caller's"
        );
        assert_eq!(
            audio.attributes.iter().filter(|a| a.name == "fmtp").count(),
            1
        );
        assert_eq!(audio.ptime(), Some(20));
    }

    #[test]
    fn the_offer_decides_what_the_answer_may_say() {
        let held = parse(
            b"v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=sendonly\r\n",
        )
        .expect("an offer");

        let answer = held
            .answer(
                bob(),
                to_bob(),
                &[StreamAnswer::Accept(
                    AcceptedStream::new(5000, vec!["0".to_owned()])
                        .with_direction(Direction::SendRecv)
                        .with_attribute(Attribute::flag("sendrecv")),
                )],
            )
            .expect("an answer");
        let audio = answer.media.first().expect("audio");
        assert_eq!(audio.direction(), Some(Direction::RecvOnly));
        assert_eq!(
            audio
                .attributes
                .iter()
                .filter(|a| a.direction().is_some())
                .count(),
            1,
            "one direction line, and it is the one the offer allows"
        );
    }

    #[test]
    fn the_time_of_the_session_is_not_negotiable() {
        let offer = parse(
            b"v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=3034423619 3042462419\r\n\
r=604800 3600 0 90000\r\n\
m=audio 49170 RTP/AVP 0\r\n",
        )
        .expect("an offer");
        let answer = offer
            .answer(
                bob(),
                to_bob(),
                &[StreamAnswer::Accept(AcceptedStream::new(
                    5000,
                    vec!["0".to_owned()],
                ))],
            )
            .expect("an answer");
        assert_eq!(answer.timing, offer.timing);
    }

    #[test]
    fn a_stream_may_be_answered_from_an_address_of_its_own() {
        let answer = offer()
            .answer(
                bob(),
                to_bob(),
                &[
                    StreamAnswer::Accept(AcceptedStream {
                        connection: Some(Connection::new("192.0.2.7".parse().expect("an address"))),
                        ..AcceptedStream::new(5000, vec!["0".to_owned()])
                    }),
                    StreamAnswer::Reject,
                    StreamAnswer::Reject,
                ],
            )
            .expect("an answer");
        let audio = answer.media.first().expect("audio");
        assert_eq!(
            answer.connection_of(audio).expect("c=").address,
            "192.0.2.7"
        );
    }
}
