// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The SDP that negotiates a text stream: an `m=text` line offering `red`
//! ahead of bare `t140`, both at 1000 Hz, the `red` format parameters that
//! list the payload type of the primary and of each redundant generation
//! (RFC 2198 §5, used by RFC 4103 §4 with `t140` in every place), and the
//! `cps` parameter a receiver uses to say how fast it can take characters
//! (RFC 4103 §6).
//!
//! Only strings are written and read here; placing them in a session
//! description is for whoever owns it.

use std::fmt::Write as _;

use super::{CLOCK_RATE, DEFAULT_GENERATIONS, Redundancy};

/// A text stream's formats, as one side offers or accepts them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextFormat {
    /// The payload type for `t140/1000`.
    pub t140_payload_type: u8,
    /// The payload type for `red/1000` and the generations it carries, if
    /// redundancy is offered.
    pub redundancy: Option<Redundancy>,
    /// The most characters a second this side can take, to be written as
    /// `cps`; `None` leaves the parameter out, which means 30.
    pub cps: Option<u32>,
}

impl TextFormat {
    /// `t140` on `t140_payload_type`, inside `red` on `red_payload_type`
    /// with the two generations RFC 4103 §4 recommends, and no `cps`.
    #[must_use]
    pub const fn new(t140_payload_type: u8, red_payload_type: u8) -> Self {
        Self {
            t140_payload_type,
            redundancy: Some(Redundancy {
                payload_type: red_payload_type,
                generations: DEFAULT_GENERATIONS,
            }),
            cps: None,
        }
    }

    /// The `m=` line, without its line ending: `red` first, the format
    /// preferred.
    #[must_use]
    pub fn media_line(&self, port: u16, profile: &str) -> String {
        let mut line = format!("m=text {port} {profile}");
        if let Some(red) = self.redundancy {
            let _ = write!(line, " {}", red.payload_type);
        }
        let _ = write!(line, " {}", self.t140_payload_type);
        line
    }

    /// The value of the `red` format's `a=fmtp`: the `t140` payload type
    /// once for the primary and once for each redundant generation,
    /// separated by `/`.
    #[must_use]
    pub fn red_fmtp(&self) -> Option<String> {
        let red = self.redundancy?;
        let t140 = self.t140_payload_type.to_string();
        let places = usize::from(red.generations) + 1;
        Some(vec![t140.as_str(); places].join("/"))
    }

    /// The attribute lines that go with [`media_line`](Self::media_line),
    /// each without its line ending.
    #[must_use]
    pub fn attributes(&self) -> Vec<String> {
        let t140 = self.t140_payload_type;
        let mut lines = vec![format!("a=rtpmap:{t140} t140/{CLOCK_RATE}")];
        if let Some(red) = self.redundancy {
            lines.push(format!("a=rtpmap:{} red/{CLOCK_RATE}", red.payload_type));
            if let Some(fmtp) = self.red_fmtp() {
                lines.push(format!("a=fmtp:{} {fmtp}", red.payload_type));
            }
        }
        if let Some(cps) = self.cps {
            lines.push(format!("a=fmtp:{t140} cps={cps}"));
        }
        lines
    }

    /// The whole media section: the `m=` line and its attributes, each
    /// ended with CRLF.
    #[must_use]
    pub fn media_section(&self, port: u16, profile: &str) -> String {
        let mut out = self.media_line(port, profile);
        out.push_str("\r\n");
        for line in self.attributes() {
            out.push_str(&line);
            out.push_str("\r\n");
        }
        out
    }
}

/// Read a `red` format's `a=fmtp` value: how many redundant generations it
/// carries, if every place names `t140_payload_type`. `None` when it lists
/// anything else, or nothing.
#[must_use]
pub fn parse_red_fmtp(value: &str, t140_payload_type: u8) -> Option<u8> {
    let mut places = 0_u16;
    for place in value.trim().split('/') {
        if place.trim().parse::<u8>().ok()? != t140_payload_type {
            return None;
        }
        places += 1;
    }
    u8::try_from(places.checked_sub(1)?).ok()
}

/// Read the `cps` parameter out of a `t140` format's `a=fmtp` value, a
/// `;`-separated list of `name=value`. `None` when it is absent or not a
/// positive number; the receiver then takes the default of 30.
#[must_use]
pub fn parse_cps(value: &str) -> Option<u32> {
    value.split(';').find_map(|parameter| {
        let (name, number) = parameter.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("cps") {
            return None;
        }
        number.trim().parse::<u32>().ok().filter(|cps| *cps > 0)
    })
}

#[cfg(test)]
mod tests {
    use super::{TextFormat, parse_cps, parse_red_fmtp};
    use crate::rtt::Redundancy;

    #[test]
    fn the_rfc_4103_offer_with_two_generations() {
        // the shape of RFC 4103's own example: t140 on 98, red on 100
        // listing 98 once for the primary and once per generation
        let format = TextFormat::new(98, 100);
        assert_eq!(
            format.media_section(11000, "RTP/AVP"),
            "m=text 11000 RTP/AVP 100 98\r\n\
             a=rtpmap:98 t140/1000\r\n\
             a=rtpmap:100 red/1000\r\n\
             a=fmtp:100 98/98/98\r\n"
        );
    }

    #[test]
    fn cps_is_a_t140_format_parameter() {
        let format = TextFormat {
            cps: Some(20),
            ..TextFormat::new(98, 100)
        };
        assert_eq!(
            format.attributes().last().map(String::as_str),
            Some("a=fmtp:98 cps=20")
        );
    }

    #[test]
    fn without_redundancy_only_t140_is_offered() {
        let format = TextFormat {
            t140_payload_type: 96,
            redundancy: None,
            cps: None,
        };
        assert_eq!(
            format.media_line(5004, "RTP/SAVP"),
            "m=text 5004 RTP/SAVP 96"
        );
        assert_eq!(format.attributes(), ["a=rtpmap:96 t140/1000"]);
        assert_eq!(format.red_fmtp(), None);
    }

    #[test]
    fn the_red_fmtp_lists_one_place_per_generation() {
        for generations in 0..=4 {
            let format = TextFormat {
                t140_payload_type: 98,
                redundancy: Some(Redundancy {
                    payload_type: 100,
                    generations,
                }),
                cps: None,
            };
            let fmtp = format.red_fmtp().unwrap();
            assert_eq!(fmtp.split('/').count(), usize::from(generations) + 1);
            assert_eq!(parse_red_fmtp(&fmtp, 98), Some(generations));
        }
    }

    #[test]
    fn a_red_fmtp_naming_another_format_is_not_text_redundancy() {
        assert_eq!(parse_red_fmtp("98/98/98", 98), Some(2));
        assert_eq!(parse_red_fmtp(" 98 / 98 ", 98), Some(1));
        assert_eq!(parse_red_fmtp("98/0", 98), None);
        assert_eq!(parse_red_fmtp("98/98", 97), None);
        assert_eq!(parse_red_fmtp("", 98), None);
        assert_eq!(parse_red_fmtp("98//98", 98), None);
    }

    #[test]
    fn cps_is_read_out_of_the_parameters() {
        assert_eq!(parse_cps("cps=20"), Some(20));
        assert_eq!(parse_cps("x=1; CPS = 45"), Some(45));
        assert_eq!(parse_cps("x=1"), None);
        assert_eq!(parse_cps("cps=0"), None);
        assert_eq!(parse_cps("cps=fast"), None);
        assert_eq!(parse_cps(""), None);
    }
}
