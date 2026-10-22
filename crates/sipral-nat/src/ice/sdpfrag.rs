// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The `application/trickle-ice-sdpfrag` body that carries trickled
//! candidates in SIP INFO requests (RFC 8840 §9), read and written.
//!
//! The body is a fragment of SDP: session-level `a=` lines first, then one
//! section per stream, each opened by a pseudo `m=` line whose only job is to
//! open it — "the receiving agent MUST ignore any remaining content of the
//! pseudo 'm=' line" (§4.4) — and tied to the real stream by `a=mid`. The
//! credentials say which ICE generation the candidates belong to, and "An
//! agent MUST discard any received INFO requests containing 'ice-pwd' and
//! 'ice-ufrag' attributes that do not match those of the current ICE
//! Negotiation Session" (§4.4). That comparison is the caller's, since only
//! the caller knows the current generation; [`SdpFrag::credentials_for`]
//! gives it the pair to compare.
//!
//! Every INFO repeats every candidate sent before under the same credentials,
//! in the same order, new ones last (§4.4). A reader therefore keeps what it
//! has seen and hands the agent only what is new; [`SdpFrag::new_candidates`]
//! does that comparison, by address, port, transport and component, the
//! equality §4.4 names.
//!
//! What is read: `a=ice-ufrag`, `a=ice-pwd`, `a=candidate`,
//! `a=end-of-candidates` at either level, `a=mid` and `a=rtcp-mux` in a
//! section. Everything else the grammar of §9.2 allows (`ice-lite`,
//! `ice-options`, `ice-pacing`, `group:BUNDLE`, `rtcp`, `rtcp-mux-only`,
//! `remote-candidates`, extension attributes) is passed over, as "An Agent
//! MUST ignore any received unknown extension-attribute-fields" asks. A line
//! that is not an attribute or a pseudo `m=` line is no part of the grammar
//! and makes the body unreadable. Attribute names compare without regard to
//! case, as §9.2 asks of a receiver.

use core::fmt;
use core::fmt::Write as _;

use super::candidate::Candidate;
use super::full::Credentials;
use super::sdp::END_OF_CANDIDATES;

/// The media type of the body (RFC 8840 §12.2).
pub const MEDIA_TYPE: &str = "application/trickle-ice-sdpfrag";

/// The longest body read. A call's stream carries a few candidates, and the
/// 32 an agent keeps of one are under 4 KiB; anything past this is not a
/// body an honest peer sends, and it still fits one UDP datagram with the
/// INFO around it.
pub const MAX_BODY: usize = 48 * 1024;

/// The most stream sections read, the most streams an agent has.
pub(crate) const MAX_SECTIONS: usize = 16;

/// The most candidate lines read in one section.
pub(crate) const MAX_CANDIDATES: usize = 64;

/// The pseudo `m=` line a section opens with when nothing more is known about
/// the stream: "The media field is set to 'audio'. The port value is set to
/// '9'. The proto value is set to 'RTP/AVP'. The fmt field MUST appear only
/// once and is set to '0'" (RFC 8840 §4.4).
pub(crate) const PSEUDO_MEDIA: &str = "m=audio 9 RTP/AVP 0";

/// Why a body could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FragError {
    /// Longer than [`MAX_BODY`].
    TooLong,
    /// Not text.
    NotText,
    /// A line that is neither an attribute nor a pseudo `m=` line.
    NotAFragment,
    /// More than 16 sections, the most streams an agent has, or more than 64
    /// candidate lines in one.
    TooMany,
}

impl fmt::Display for FragError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "a trickle body longer than any honest peer sends",
            Self::NotText => "a trickle body that is not text",
            Self::NotAFragment => "a line that is neither an attribute nor a pseudo m= line",
            Self::TooMany => "more sections or candidate lines than an agent keeps",
        })
    }
}

impl core::error::Error for FragError {}

/// One stream's section: the candidates for the stream whose `a=mid` it
/// names.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FragSection {
    /// The stream's identification tag (RFC 5888), when the section has one.
    pub mid: Option<String>,
    /// Credentials written in the section, overriding the session level's.
    pub ufrag: Option<String>,
    /// The password beside [`FragSection::ufrag`].
    pub pwd: Option<String>,
    /// Every `a=candidate` line this agent could read, in order. A line it
    /// could not — a name, a transport other than UDP — is absent, as in a
    /// description (RFC 8839 §5.1).
    pub candidates: Vec<Candidate>,
    /// `a=end-of-candidates` in the section: nothing more for this stream.
    pub end_of_candidates: bool,
    /// `a=rtcp-mux` in the section (RFC 8840 §6).
    pub rtcp_mux: bool,
}

/// A whole body.
///
/// [`fmt::Debug`] leaves the passwords out, as a description's does.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SdpFrag {
    /// The session-level `a=ice-ufrag`.
    pub ufrag: Option<String>,
    /// The session-level `a=ice-pwd`.
    pub pwd: Option<String>,
    /// A session-level `a=end-of-candidates`: "the end of all trickling from
    /// that agent" (RFC 8840 §4.4).
    pub end_of_candidates: bool,
    /// The stream sections, in order.
    pub sections: Vec<FragSection>,
}

impl fmt::Debug for FragSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FragSection")
            .field("mid", &self.mid)
            .field("ufrag", &self.ufrag)
            .field("candidates", &self.candidates)
            .field("end_of_candidates", &self.end_of_candidates)
            .field("rtcp_mux", &self.rtcp_mux)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SdpFrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdpFrag")
            .field("ufrag", &self.ufrag)
            .field("end_of_candidates", &self.end_of_candidates)
            .field("sections", &self.sections)
            .finish_non_exhaustive()
    }
}

impl SdpFrag {
    /// Read a body.
    ///
    /// Lines end in CRLF; a bare LF is taken too, as SDP readers take it.
    ///
    /// # Errors
    ///
    /// [`FragError`], naming what made the body unreadable.
    pub fn parse(body: &[u8]) -> Result<Self, FragError> {
        if body.len() > MAX_BODY {
            return Err(FragError::TooLong);
        }
        let text = core::str::from_utf8(body).map_err(|_| FragError::NotText)?;
        let mut frag = Self::default();
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.trim().is_empty() {
                continue;
            }
            if let Some(media) = line.strip_prefix("m=") {
                if media.split_whitespace().count() < 4 {
                    return Err(FragError::NotAFragment);
                }
                if frag.sections.len() >= MAX_SECTIONS {
                    return Err(FragError::TooMany);
                }
                frag.sections.push(FragSection::default());
                continue;
            }
            let Some(attribute) = line.strip_prefix("a=") else {
                return Err(FragError::NotAFragment);
            };
            let (name, value) = match attribute.split_once(':') {
                Some((name, value)) => (name, Some(value)),
                None => (attribute, None),
            };
            match frag.sections.last_mut() {
                None => frag.session_line(name, value),
                Some(section) => section.line(name, value)?,
            }
        }
        Ok(frag)
    }

    fn session_line(&mut self, name: &str, value: Option<&str>) {
        if name.eq_ignore_ascii_case("ice-ufrag") {
            self.ufrag = value.map(str::to_owned);
        } else if name.eq_ignore_ascii_case("ice-pwd") {
            self.pwd = value.map(str::to_owned);
        } else if name.eq_ignore_ascii_case(END_OF_CANDIDATES) {
            self.end_of_candidates = true;
        }
    }

    /// The section for the stream tagged `mid`, or — for a stream with no
    /// tag, or a peer that wrote none — the only section there is.
    #[must_use]
    pub fn section(&self, mid: Option<&str>) -> Option<&FragSection> {
        if let Some(found) = self
            .sections
            .iter()
            .find(|section| section.mid.is_some() && section.mid.as_deref() == mid)
        {
            return Some(found);
        }
        match self.sections.as_slice() {
            [only] if only.mid.is_none() || mid.is_none() => Some(only),
            _ => None,
        }
    }

    /// The credentials the section for `mid` was sent under: its own, or the
    /// session level's (RFC 8840 §9.2). `None` when either half is missing,
    /// which makes the body one nobody can tie to a generation.
    #[must_use]
    pub fn credentials_for(&self, mid: Option<&str>) -> Option<(&str, &str)> {
        let section = self.section(mid);
        let ufrag = section
            .and_then(|section| section.ufrag.as_deref())
            .or(self.ufrag.as_deref())?;
        let pwd = section
            .and_then(|section| section.pwd.as_deref())
            .or(self.pwd.as_deref())?;
        Some((ufrag, pwd))
    }

    /// Whether the peer said it has finished for the stream tagged `mid`:
    /// in the stream's section, or for the whole session.
    #[must_use]
    pub fn ended(&self, mid: Option<&str>) -> bool {
        self.end_of_candidates
            || self
                .section(mid)
                .is_some_and(|section| section.end_of_candidates)
    }

    /// The candidates of the section for `mid` that `known` does not already
    /// hold, in the order they were sent. Two candidates are the same "if
    /// their IP address port, transport, and component ID are the same"
    /// (RFC 8840 §4.4); every candidate read here is UDP.
    #[must_use]
    pub fn new_candidates(&self, mid: Option<&str>, known: &[Candidate]) -> Vec<Candidate> {
        let Some(section) = self.section(mid) else {
            return Vec::new();
        };
        let mut fresh: Vec<Candidate> = Vec::new();
        for candidate in &section.candidates {
            let same = |other: &Candidate| {
                other.address == candidate.address && other.component == candidate.component
            };
            if !known.iter().any(same) && !fresh.iter().any(same) {
                fresh.push(candidate.clone());
            }
        }
        fresh
    }

    /// The body, as it goes in an INFO request: CRLF after every line.
    #[must_use]
    pub fn write(&self) -> String {
        let mut out = String::new();
        if let Some(ufrag) = self.ufrag.as_deref() {
            let _ = write!(out, "a=ice-ufrag:{ufrag}\r\n");
        }
        if let Some(pwd) = self.pwd.as_deref() {
            let _ = write!(out, "a=ice-pwd:{pwd}\r\n");
        }
        if self.end_of_candidates {
            let _ = write!(out, "a={END_OF_CANDIDATES}\r\n");
        }
        for section in &self.sections {
            let _ = write!(out, "{PSEUDO_MEDIA}\r\n");
            if let Some(ufrag) = section.ufrag.as_deref() {
                let _ = write!(out, "a=ice-ufrag:{ufrag}\r\n");
            }
            if let Some(pwd) = section.pwd.as_deref() {
                let _ = write!(out, "a=ice-pwd:{pwd}\r\n");
            }
            if section.rtcp_mux {
                out.push_str("a=rtcp-mux\r\n");
            }
            // "Such 'mid' attributes MUST immediately precede the list of
            // candidates for that specific 'm=' line" (§4.4)
            if let Some(mid) = section.mid.as_deref() {
                let _ = write!(out, "a=mid:{mid}\r\n");
            }
            for candidate in &section.candidates {
                let attribute = candidate.to_attribute();
                let _ = write!(
                    out,
                    "a=candidate:{}\r\n",
                    attribute.value.as_deref().unwrap_or_default()
                );
            }
            if section.end_of_candidates {
                let _ = write!(out, "a={END_OF_CANDIDATES}\r\n");
            }
        }
        out
    }

    /// The body one agent sends for one stream: its credentials at the level
    /// the description wrote them, which in this crate is the stream's
    /// ([`super::write_stream`]), every candidate it has sent under them, in
    /// order, and whether it has finished.
    #[must_use]
    pub fn for_stream(
        credentials: &Credentials,
        mid: Option<&str>,
        candidates: &[Candidate],
        end_of_candidates: bool,
    ) -> Self {
        Self {
            ufrag: None,
            pwd: None,
            end_of_candidates: false,
            sections: vec![FragSection {
                mid: mid.map(str::to_owned),
                ufrag: Some(credentials.ufrag().to_owned()),
                pwd: Some(credentials.pwd().to_owned()),
                candidates: candidates.to_vec(),
                end_of_candidates,
                rtcp_mux: true,
            }],
        }
    }
}

impl FragSection {
    fn line(&mut self, name: &str, value: Option<&str>) -> Result<(), FragError> {
        if name.eq_ignore_ascii_case("candidate") {
            if self.candidates.len() >= MAX_CANDIDATES {
                return Err(FragError::TooMany);
            }
            if let Some(candidate) = value.and_then(Candidate::parse) {
                self.candidates.push(candidate);
            }
        } else if name.eq_ignore_ascii_case("mid") {
            self.mid = value.map(|tag| tag.trim().to_owned());
        } else if name.eq_ignore_ascii_case("ice-ufrag") {
            self.ufrag = value.map(str::to_owned);
        } else if name.eq_ignore_ascii_case("ice-pwd") {
            self.pwd = value.map(str::to_owned);
        } else if name.eq_ignore_ascii_case(END_OF_CANDIDATES) {
            self.end_of_candidates = true;
        } else if name.eq_ignore_ascii_case("rtcp-mux") {
            self.rtcp_mux = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{FragError, MAX_BODY, MAX_CANDIDATES, SdpFrag};
    use crate::ice::candidate::{Candidate, CandidateType, ComponentId, Foundation};
    use crate::ice::full::Credentials;

    /// RFC 8840 Figure 7, with the candidate lines joined as the figure's
    /// note says a real request has them.
    const FIGURE_7: &str = "a=ice-pwd:asd88fgpdd777uzjYhagZg\r\n\
a=ice-ufrag:8hhY\r\n\
m=audio 9 RTP/AVP 0\r\n\
a=mid:1\r\n\
a=candidate:1 1 UDP 2130706432 2001:db8:a0b:12f0::1 5000 typ host\r\n\
a=candidate:1 2 UDP 2130706432 2001:db8:a0b:12f0::1 5001 typ host\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.1 5010 typ host\r\n\
a=candidate:1 2 UDP 2130706431 192.0.2.1 5011 typ host\r\n\
a=candidate:2 1 UDP 1694498815 192.0.2.3 5010 typ srflx raddr 192.0.2.1 rport 8998\r\n\
a=candidate:2 2 UDP 1694498815 192.0.2.3 5011 typ srflx raddr 192.0.2.1 rport 8998\r\n\
a=end-of-candidates\r\n\
m=audio 9 RTP/AVP 0\r\n\
a=mid:2\r\n\
a=candidate:1 1 UDP 2130706432 2001:db8:a0b:12f0::1 6000 typ host\r\n\
a=candidate:1 2 UDP 2130706432 2001:db8:a0b:12f0::1 6001 typ host\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.1 6010 typ host\r\n\
a=candidate:1 2 UDP 2130706431 192.0.2.1 6011 typ host\r\n\
a=candidate:2 1 UDP 1694498815 192.0.2.3 6010 typ srflx raddr 192.0.2.1 rport 9998\r\n\
a=candidate:2 2 UDP 1694498815 192.0.2.3 6011 typ srflx raddr 192.0.2.1 rport 9998\r\n\
a=end-of-candidates\r\n";

    fn host(port: u16) -> Candidate {
        Candidate {
            foundation: Foundation::numbered(1),
            component: ComponentId::RTP,
            priority: 2_130_706_431,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port),
            kind: CandidateType::Host,
            related: None,
        }
    }

    #[test]
    fn the_rfcs_own_example_is_read_section_by_section() {
        let frag = SdpFrag::parse(FIGURE_7.as_bytes()).expect("Figure 7 is a body");
        assert_eq!(frag.ufrag.as_deref(), Some("8hhY"));
        assert!(!frag.end_of_candidates);
        assert_eq!(frag.sections.len(), 2);
        let first = frag.section(Some("1")).expect("the section tagged 1");
        assert_eq!(first.candidates.len(), 6);
        assert!(first.end_of_candidates);
        assert_eq!(
            first.candidates[4].related,
            Some("192.0.2.1:8998".parse().expect("address"))
        );
        let second = frag.section(Some("2")).expect("the section tagged 2");
        assert_eq!(second.candidates[2].address.port(), 6010);
        assert_eq!(
            frag.credentials_for(Some("2")),
            Some(("8hhY", "asd88fgpdd777uzjYhagZg"))
        );
        assert!(frag.ended(Some("2")));
        assert!(frag.section(Some("3")).is_none());
    }

    #[test]
    fn a_written_body_reads_back_the_same() {
        let credentials = Credentials::new("8hhY", "asd88fgpdd777uzjYhagZg").expect("shape");
        let candidates = [host(5000), host(5002)];
        let frag = SdpFrag::for_stream(&credentials, Some("0"), &candidates, true);
        let written = frag.write();
        assert!(written.ends_with("a=end-of-candidates\r\n"), "{written}");
        assert!(
            written.contains("a=mid:0\r\na=candidate:1 1 UDP"),
            "the tag right before the candidates: {written}"
        );
        let read = SdpFrag::parse(written.as_bytes()).expect("its own body");
        assert_eq!(read, frag);
        assert_eq!(
            read.credentials_for(Some("0")),
            Some(("8hhY", "asd88fgpdd777uzjYhagZg"))
        );
    }

    #[test]
    fn what_was_sent_before_is_not_new_again() {
        let credentials = Credentials::new("8hhY", "asd88fgpdd777uzjYhagZg").expect("shape");
        let earlier = [host(5000)];
        let mut repeated = host(5000);
        // the same address and component under another foundation and
        // priority is still the same candidate (RFC 8840 §4.4)
        repeated.priority = 7;
        let frag = SdpFrag::for_stream(&credentials, None, &[repeated, host(5002)], false);
        let fresh = frag.new_candidates(None, &earlier);
        assert_eq!(fresh, vec![host(5002)]);
        assert!(!frag.ended(None));
    }

    #[test]
    fn a_section_without_a_tag_answers_for_the_only_stream() {
        let body = "a=ice-ufrag:8hhY\r\na=ice-pwd:asd88fgpdd777uzjYhagZg\r\nm=audio 9 RTP/AVP 0\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host\r\n";
        let frag = SdpFrag::parse(body.as_bytes()).expect("a body");
        assert_eq!(frag.new_candidates(Some("0"), &[]).len(), 1);
        assert_eq!(frag.new_candidates(None, &[]).len(), 1);
    }

    #[test]
    fn a_session_level_end_ends_every_stream() {
        let body = "a=ice-ufrag:8hhY\na=ice-pwd:asd88fgpdd777uzjYhagZg\na=end-of-candidates\n";
        let frag = SdpFrag::parse(body.as_bytes()).expect("a bare LF is taken");
        assert!(frag.ended(Some("audio")));
        assert!(frag.sections.is_empty());
    }

    #[test]
    fn what_the_grammar_allows_and_this_does_not_read_is_passed_over() {
        let body = "a=group:BUNDLE foo bar\r\na=ice-options:trickle\r\na=ice-lite\r\n\
a=ice-ufrag:8hhY\r\na=ice-pwd:asd88fgpdd777uzjYhagZg\r\nm=audio 9 RTP/AVP 0\r\na=MID:foo\r\n\
a=rtcp-mux\r\na=rtcp-mux-only\r\na=remote-candidates:1 192.0.2.1 5000\r\na=x-vendor:anything\r\n\
a=candidate:1 1 TCP 2130706431 192.0.2.1 5000 typ host tcptype active\r\n\
a=candidate:1 1 UDP 2130706431 host.example 5000 typ host\r\n\
a=candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host\r\n";
        let frag = SdpFrag::parse(body.as_bytes()).expect("a body");
        let section = frag.section(Some("foo")).expect("tags compare as written");
        assert!(section.rtcp_mux);
        assert_eq!(
            section.candidates.len(),
            1,
            "TCP and a name are not candidates this agent can use"
        );
    }

    #[test]
    fn a_body_that_is_not_a_fragment_is_refused() {
        assert_eq!(
            SdpFrag::parse(b"v=0\r\na=ice-ufrag:8hhY\r\n"),
            Err(FragError::NotAFragment)
        );
        assert_eq!(SdpFrag::parse(b"m=audio\r\n"), Err(FragError::NotAFragment));
        assert_eq!(SdpFrag::parse(&[0xff, 0xfe]), Err(FragError::NotText));
        assert_eq!(
            SdpFrag::parse(&vec![b'\n'; MAX_BODY + 1]),
            Err(FragError::TooLong)
        );
        let mut crowded = String::from("m=audio 9 RTP/AVP 0\r\n");
        for port in 0..=MAX_CANDIDATES {
            let _ = write!(
                crowded,
                "a=candidate:1 1 UDP 2130706431 192.0.2.1 {} typ host\r\n",
                5000 + port
            );
        }
        assert_eq!(SdpFrag::parse(crowded.as_bytes()), Err(FragError::TooMany));
        let sections = "m=audio 9 RTP/AVP 0\r\n".repeat(super::MAX_SECTIONS + 1);
        assert_eq!(SdpFrag::parse(sections.as_bytes()), Err(FragError::TooMany));
    }

    #[test]
    fn the_password_does_not_reach_a_log() {
        let credentials = Credentials::new("9uB6", "YH75Fviy6338Vbrhrlp8Yh").expect("shape");
        let mut frag = SdpFrag::for_stream(&credentials, Some("0"), &[], false);
        frag.pwd = Some("YH75Fviy6338Vbrhrlp8Yh".to_owned());
        let printed = format!("{frag:?}");
        assert!(!printed.contains("YH75Fviy6338Vbrhrlp8Yh"), "{printed}");
        assert!(printed.contains("9uB6"), "{printed}");
    }
}
