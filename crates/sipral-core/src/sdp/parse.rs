// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Reading a session description (RFC 4566 §5).
//!
//! SDP is a list of `<type>=<value>` lines whose order is fixed, not a format
//! with a grammar to recurse through. So the parser is a walk down the lines
//! with one rule: a line may not appear before a line that has to precede it.
//! Each type letter has a rank, and the rank may never go backwards, which is
//! the whole of §5's ordering in one comparison.
//!
//! A type letter that is not one of the fourteen refuses the entire
//! description, not the line. That is what §5 asks for — "an SDP parser MUST
//! completely ignore any session description that contains a type letter that
//! it does not understand" — and it is not the usual be-liberal rule: SDP
//! deliberately has no room for new letters, so one that appears means the
//! sender and the reader disagree about what the description says.

use super::error::SdpError;
use super::media::MediaDescription;
use super::session::{Attribute, Connection, Origin, SessionDescription, Timing};

/// Read a session description.
///
/// # Errors
/// See [`SdpError`].
pub fn parse(bytes: &[u8]) -> Result<SessionDescription, SdpError> {
    let text = core::str::from_utf8(bytes).map_err(|_| SdpError::NotUtf8)?;
    Parser::new().run(text)
}

/// Where each type letter may appear at session level. The order is §5's, and
/// `r=` shares its rank with the `t=` it belongs to.
const fn session_rank(kind: char) -> Option<u8> {
    Some(match kind {
        'v' => 0,
        'o' => 1,
        's' => 2,
        'i' => 3,
        'u' => 4,
        'e' => 5,
        'p' => 6,
        'c' => 7,
        'b' => 8,
        't' | 'r' => 9,
        'z' => 10,
        'k' => 11,
        'a' => 12,
        _ => return None,
    })
}

/// The same for the lines inside an `m=` block.
const fn media_rank(kind: char) -> Option<u8> {
    Some(match kind {
        'i' => 1,
        'c' => 2,
        'b' => 3,
        'k' => 4,
        'a' => 5,
        _ => return None,
    })
}

struct Parser {
    version: bool,
    origin: Option<Origin>,
    name: Option<String>,
    session: SessionFields,
    media: Vec<MediaDescription>,
    rank: u8,
}

#[derive(Default)]
struct SessionFields {
    information: Option<String>,
    uri: Option<String>,
    contacts: Vec<String>,
    phones: Vec<String>,
    connection: Option<Connection>,
    bandwidth: Vec<String>,
    timing: Vec<Timing>,
    timezones: Option<String>,
    key: Option<String>,
    attributes: Vec<Attribute>,
}

impl Parser {
    const fn new() -> Self {
        Self {
            version: false,
            origin: None,
            name: None,
            session: SessionFields {
                information: None,
                uri: None,
                contacts: Vec::new(),
                phones: Vec::new(),
                connection: None,
                bandwidth: Vec::new(),
                timing: Vec::new(),
                timezones: None,
                key: None,
                attributes: Vec::new(),
            },
            media: Vec::new(),
            rank: 0,
        }
    }

    fn run(mut self, text: &str) -> Result<SessionDescription, SdpError> {
        if text.trim().is_empty() {
            return Err(SdpError::Empty);
        }
        for (index, raw) in text.split('\n').enumerate() {
            let number = index + 1;
            // "parsers SHOULD be tolerant and also accept records terminated
            // with a single newline character"
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if line.is_empty() {
                continue;
            }
            let (kind, value) = split_line(line, number)?;
            if kind == 'm' {
                self.rank = 0;
                self.media.push(media_line(value, number)?);
                continue;
            }
            match self.media.last_mut() {
                Some(media) => self.rank = media_field(media, kind, value, number, self.rank)?,
                None => self.rank = self.session_field(kind, value, number)?,
            }
        }

        let origin = self.origin.ok_or(SdpError::Missing("o="))?;
        let name = self.name.ok_or(SdpError::Missing("s="))?;
        if !self.version {
            return Err(SdpError::Missing("v="));
        }
        if self.session.timing.is_empty() {
            return Err(SdpError::Missing("t="));
        }
        Ok(SessionDescription {
            origin,
            name,
            information: self.session.information,
            uri: self.session.uri,
            contacts: self.session.contacts,
            phones: self.session.phones,
            connection: self.session.connection,
            bandwidth: self.session.bandwidth,
            timing: self.session.timing,
            timezones: self.session.timezones,
            key: self.session.key,
            attributes: self.session.attributes,
            media: self.media,
        })
    }

    fn session_field(&mut self, kind: char, value: &str, line: usize) -> Result<u8, SdpError> {
        let rank = session_rank(kind).ok_or(SdpError::UnknownType { line, kind })?;
        if rank < self.rank {
            return Err(SdpError::OutOfOrder { line, kind });
        }
        match kind {
            'v' => {
                if value != "0" {
                    return Err(SdpError::UnsupportedVersion);
                }
                self.version = true;
            }
            'o' => self.origin = Some(origin_line(value, line)?),
            's' => self.name = Some(value.to_owned()),
            'i' => self.session.information = Some(value.to_owned()),
            'u' => self.session.uri = Some(value.to_owned()),
            'e' => self.session.contacts.push(value.to_owned()),
            'p' => self.session.phones.push(value.to_owned()),
            'c' => self.session.connection = Some(connection_line(value, line)?),
            'b' => self.session.bandwidth.push(value.to_owned()),
            't' => self.session.timing.push(timing_line(value, line)?),
            'r' => {
                // an r= describes the t= above it, and there has to be one
                let timing = self
                    .session
                    .timing
                    .last_mut()
                    .ok_or(SdpError::OutOfOrder { line, kind })?;
                timing.repeats.push(value.to_owned());
            }
            'z' => self.session.timezones = Some(value.to_owned()),
            'k' => self.session.key = Some(value.to_owned()),
            _ => self.session.attributes.push(attribute_line(value)),
        }
        Ok(rank)
    }
}

fn media_field(
    media: &mut MediaDescription,
    kind: char,
    value: &str,
    line: usize,
    previous: u8,
) -> Result<u8, SdpError> {
    let rank = media_rank(kind).ok_or(match session_rank(kind) {
        // a legal letter, but not one that may follow an m=
        Some(_) => SdpError::OutOfOrder { line, kind },
        None => SdpError::UnknownType { line, kind },
    })?;
    if rank < previous {
        return Err(SdpError::OutOfOrder { line, kind });
    }
    match kind {
        'i' => media.information = Some(value.to_owned()),
        'c' => media.connection = Some(connection_line(value, line)?),
        'b' => media.bandwidth.push(value.to_owned()),
        'k' => media.key = Some(value.to_owned()),
        _ => media.attributes.push(attribute_line(value)),
    }
    Ok(rank)
}

fn split_line(line: &str, number: usize) -> Result<(char, &str), SdpError> {
    let mut chars = line.chars();
    let kind = chars.next().ok_or(SdpError::BadLine { line: number })?;
    if chars.next() != Some('=') || !kind.is_ascii_alphabetic() {
        return Err(SdpError::BadLine { line: number });
    }
    let value = line.get(2..).unwrap_or_default();
    Ok((kind, value))
}

fn origin_line(value: &str, line: usize) -> Result<Origin, SdpError> {
    let mut parts = value.split_ascii_whitespace();
    let mut next = || parts.next().ok_or(SdpError::Incomplete { line });
    let username = next()?.to_owned();
    let session_id = number(next()?, line)?;
    let version = number(next()?, line)?;
    let network = next()?.to_owned();
    let address_type = next()?.to_owned();
    let address = next()?.to_owned();
    Ok(Origin {
        username,
        session_id,
        version,
        network,
        address_type,
        address,
    })
}

fn connection_line(value: &str, line: usize) -> Result<Connection, SdpError> {
    let mut parts = value.split_ascii_whitespace();
    let mut next = || parts.next().ok_or(SdpError::Incomplete { line });
    Ok(Connection {
        network: next()?.to_owned(),
        address_type: next()?.to_owned(),
        address: next()?.to_owned(),
    })
}

fn timing_line(value: &str, line: usize) -> Result<Timing, SdpError> {
    let mut parts = value.split_ascii_whitespace();
    let mut next = || parts.next().ok_or(SdpError::Incomplete { line });
    let start = number(next()?, line)?;
    let stop = number(next()?, line)?;
    Ok(Timing {
        start,
        stop,
        repeats: Vec::new(),
    })
}

fn media_line(value: &str, line: usize) -> Result<MediaDescription, SdpError> {
    let mut parts = value.split_ascii_whitespace();
    let mut next = || parts.next().ok_or(SdpError::Incomplete { line });
    let media = next()?.to_owned();
    let written = next()?;
    let proto = next()?.to_owned();
    let (port, port_count) = match written.split_once('/') {
        Some((port, count)) => (number16(port, line)?, Some(number16(count, line)?)),
        None => (number16(written, line)?, None),
    };
    Ok(MediaDescription {
        media,
        port,
        port_count,
        proto,
        formats: parts.map(str::to_owned).collect(),
        information: None,
        connection: None,
        bandwidth: Vec::new(),
        key: None,
        attributes: Vec::new(),
    })
}

fn attribute_line(value: &str) -> Attribute {
    match value.split_once(':') {
        Some((name, value)) => Attribute {
            name: name.to_owned(),
            value: Some(value.to_owned()),
        },
        None => Attribute {
            name: value.to_owned(),
            value: None,
        },
    }
}

fn number(value: &str, line: usize) -> Result<u64, SdpError> {
    value.parse().map_err(|_| SdpError::BadNumber { line })
}

fn number16(value: &str, line: usize) -> Result<u16, SdpError> {
    value.parse().map_err(|_| SdpError::BadNumber { line })
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::sdp::{Direction, SdpError};

    const OFFER: &str = "v=0\r\n\
o=- 3823 3823 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\n\
a=ptime:20\r\n\
a=sendrecv\r\n";

    #[test]
    fn a_plain_offer_comes_apart_into_its_lines() {
        let sdp = parse(OFFER.as_bytes()).expect("an offer");
        assert_eq!(sdp.origin.username, "-");
        assert_eq!(sdp.origin.session_id, 3823);
        assert_eq!(sdp.name, "-");
        assert_eq!(
            sdp.connection.as_ref().expect("c=").ip(),
            Some("192.0.2.1".parse().expect("an address"))
        );
        assert_eq!(sdp.timing.len(), 1);
        assert_eq!(sdp.media.len(), 1);

        let audio = sdp.media.first().expect("the stream");
        assert_eq!(audio.media, "audio");
        assert_eq!(audio.port, 49170);
        assert_eq!(audio.proto, "RTP/AVP");
        assert_eq!(audio.payload_types().collect::<Vec<_>>(), [0, 8, 101]);
        assert_eq!(audio.direction(), Some(Direction::SendRecv));
        assert_eq!(audio.ptime(), Some(20));
        assert_eq!(audio.fmtp(101), Some("0-15"), "the colon splits once");
        let rtpmap = audio.rtpmap(8).expect("a=rtpmap:8");
        assert_eq!(rtpmap.encoding, "PCMA");
        assert_eq!(rtpmap.clock_rate, 8000);
    }

    #[test]
    fn what_is_read_is_written_back_unchanged() {
        let sdp = parse(OFFER.as_bytes()).expect("an offer");
        assert_eq!(String::from_utf8(sdp.to_bytes()).expect("utf-8"), OFFER);
    }

    #[test]
    fn a_line_ending_of_one_newline_is_accepted() {
        // "parsers SHOULD be tolerant and also accept records terminated with
        // a single newline character"
        let lf = OFFER.replace("\r\n", "\n");
        let sdp = parse(lf.as_bytes()).expect("an offer");
        assert_eq!(sdp.media.len(), 1);
        // and comes back out with the CRLF the RFC asks for
        assert_eq!(String::from_utf8(sdp.to_bytes()).expect("utf-8"), OFFER);
    }

    #[test]
    fn a_type_letter_we_do_not_know_refuses_the_whole_description() {
        // "an SDP parser MUST completely ignore any session description that
        // contains a type letter that it does not understand"
        let odd = OFFER.replace("t=0 0\r\n", "t=0 0\r\nq=something\r\n");
        assert_eq!(
            parse(odd.as_bytes()).unwrap_err(),
            SdpError::UnknownType { line: 6, kind: 'q' }
        );
    }

    #[test]
    fn lines_out_of_the_order_section_5_fixes_are_refused() {
        let swapped = "v=0\r\ns=-\r\no=- 1 1 IN IP4 192.0.2.1\r\nt=0 0\r\n";
        assert_eq!(
            parse(swapped.as_bytes()).unwrap_err(),
            SdpError::OutOfOrder { line: 3, kind: 'o' }
        );
        // and a t= after the first m= belongs to no stream
        let late = format!("{OFFER}t=0 0\r\n");
        assert_eq!(
            parse(late.as_bytes()).unwrap_err(),
            SdpError::OutOfOrder {
                line: 13,
                kind: 't'
            }
        );
    }

    #[test]
    fn the_mandatory_lines_are_mandatory() {
        for (missing, without) in [
            ("v=", OFFER.replace("v=0\r\n", "")),
            (
                "o=",
                OFFER.replace("o=- 3823 3823 IN IP4 192.0.2.1\r\n", ""),
            ),
            ("s=", OFFER.replace("s=-\r\n", "")),
            ("t=", OFFER.replace("t=0 0\r\n", "")),
        ] {
            assert_eq!(
                parse(without.as_bytes()).unwrap_err(),
                SdpError::Missing(missing)
            );
        }
    }

    #[test]
    fn there_is_only_one_version_of_sdp() {
        let future = OFFER.replace("v=0", "v=1");
        assert_eq!(
            parse(future.as_bytes()).unwrap_err(),
            SdpError::UnsupportedVersion
        );
    }

    #[test]
    fn a_media_level_line_belongs_to_its_stream_and_not_to_the_session() {
        let two_streams = "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
a=sendrecv\r\n\
m=audio 49170 RTP/AVP 0\r\n\
c=IN IP4 192.0.2.9\r\n\
a=sendonly\r\n\
m=video 51372 RTP/AVP 31\r\n\
a=inactive\r\n";
        let sdp = parse(two_streams.as_bytes()).expect("two streams");
        assert_eq!(sdp.direction(), Some(Direction::SendRecv));
        assert_eq!(sdp.attributes.len(), 1, "one session-level attribute");

        let audio = sdp.media.first().expect("audio");
        let video = sdp.media.get(1).expect("video");
        assert_eq!(sdp.direction_of(audio), Direction::SendOnly);
        assert_eq!(sdp.direction_of(video), Direction::Inactive);
        assert_eq!(
            sdp.connection_of(audio).expect("c=").address,
            "192.0.2.9",
            "the stream's own c= wins"
        );
        assert_eq!(
            sdp.connection_of(video).expect("c=").address,
            "192.0.2.1",
            "and the session's stands in when there is none"
        );
    }

    #[test]
    fn a_stream_with_no_direction_is_sendrecv() {
        let bare = "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n";
        let sdp = parse(bare.as_bytes()).expect("an offer");
        let audio = sdp.media.first().expect("audio");
        assert_eq!(audio.direction(), None);
        assert_eq!(sdp.direction_of(audio), Direction::SendRecv);
    }

    #[test]
    fn the_old_way_of_holding_a_call_is_still_recognised() {
        let held = OFFER.replace("c=IN IP4 192.0.2.1", "c=IN IP4 0.0.0.0");
        let sdp = parse(held.as_bytes()).expect("an offer");
        assert!(sdp.connection.as_ref().expect("c=").is_black_hole());
    }

    #[test]
    fn what_is_not_a_line_at_all() {
        assert_eq!(parse(b"").unwrap_err(), SdpError::Empty);
        assert_eq!(parse(&[0xff]).unwrap_err(), SdpError::NotUtf8);
        assert_eq!(
            parse(b"v=0\r\nnonsense\r\n").unwrap_err(),
            SdpError::BadLine { line: 2 }
        );
        assert_eq!(
            parse(b"v=0\r\no=- 1 1 IN IP4\r\n").unwrap_err(),
            SdpError::Incomplete { line: 2 }
        );
        assert_eq!(
            parse(b"v=0\r\no=- x 1 IN IP4 192.0.2.1\r\n").unwrap_err(),
            SdpError::BadNumber { line: 2 }
        );
    }

    #[test]
    fn nothing_in_a_body_makes_the_parser_panic() {
        for len in 0..14_usize {
            for seed in 0..64_u8 {
                let body: String = (0..len)
                    .map(|i| {
                        let b = seed
                            .wrapping_mul(31)
                            .wrapping_add(u8::try_from(i).unwrap_or(0));
                        char::from(b'\n' + b % 100)
                    })
                    .collect();
                let _ = parse(body.as_bytes());
                let _ = parse(format!("v=0\r\n{body}").as_bytes());
                let _ = parse(format!("{OFFER}{body}").as_bytes());
            }
        }
    }
}
