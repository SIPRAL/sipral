// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The lines a WebRTC peer puts around its streams: the BUNDLE group (RFC
//! 8843 §7, written as RFC 5888's `a=group`), each stream's identification-tag
//! (`a=mid`, RFC 5888 §4), the RTP header extensions it maps (`a=extmap`, RFC
//! 8285 §5) and exclusive RTP/RTCP multiplexing (`a=rtcp-mux-only`, RFC 8858
//! §3).
//!
//! Reading only, and only what the lines say. Whether a stream is bundled,
//! and what an answer says back, is the caller's to decide.

use super::{MediaDescription, SessionDescription};

/// The RTP header extension that carries the identification-tag of the
/// stream a packet belongs to (RFC 8843 §14.1, one of RFC 7941's SDES items
/// carried in a header extension).
pub const MID_EXTENSION: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";

/// The grouping semantics of RFC 8843 §16.1.
const BUNDLE: &str = "BUNDLE";

/// Whether `text` is RFC 4566 §9's `token`, which an identification-tag is
/// (RFC 5888 §4).
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| {
            matches!(byte,
                0x21 | 0x23..=0x27 | 0x2A | 0x2B | 0x2D | 0x2E
                | b'0'..=b'9' | b'A'..=b'Z' | 0x5E..=0x7E)
        })
}

impl SessionDescription {
    /// The identification-tags of the first BUNDLE group, in the order
    /// written (`a=group:BUNDLE 0 1`; RFC 5888 §5, RFC 8843 §7.1). The first
    /// one is the tag the writer suggests for the shared transport (§7.2).
    ///
    /// `None` when no group names BUNDLE, or the first that does names a tag
    /// that is not a token. A group with no tags at all is an empty list.
    #[must_use]
    pub fn bundle_group(&self) -> Option<Vec<&str>> {
        let value = self
            .attributes
            .iter()
            .filter(|attribute| attribute.name == "group")
            .filter_map(|attribute| attribute.value.as_deref())
            .find(|value| value.split(' ').next() == Some(BUNDLE))?;
        let tags: Vec<&str> = value
            .split(' ')
            .skip(1)
            .filter(|tag| !tag.is_empty())
            .collect();
        tags.iter().all(|tag| is_token(tag)).then_some(tags)
    }
}

impl MediaDescription {
    /// The stream's identification-tag, `a=mid` (RFC 5888 §4), if it has one
    /// that is a token.
    #[must_use]
    pub fn mid(&self) -> Option<&str> {
        self.attribute("mid")
            .and_then(|mid| mid.value.as_deref())
            .filter(|mid| is_token(mid))
    }

    /// `a=rtcp-mux-only` (RFC 8858 §3): the writer multiplexes RTP and RTCP
    /// on one port or not at all.
    #[must_use]
    pub fn has_rtcp_mux_only(&self) -> bool {
        self.has_flag("rtcp-mux-only")
    }

    /// The number `a=extmap` gives the header extension named `uri` (RFC 8285
    /// §5: `a=extmap:<value>["/"<direction>] <URI> [<attributes>]`), when it
    /// is one a packet can carry: 1 to 14 in the one-byte form, up to 255 in
    /// the two-byte one (§4.2, §4.3). The URI is compared as written.
    #[must_use]
    pub fn extmap_id(&self, uri: &str) -> Option<u8> {
        self.attributes
            .iter()
            .filter(|attribute| attribute.name == "extmap")
            .filter_map(|attribute| attribute.value.as_deref())
            .find_map(|value| {
                let mut words = value.split(' ');
                let entry = words.next()?;
                if words.next()? != uri {
                    return None;
                }
                let number = entry.split_once('/').map_or(entry, |(number, _)| number);
                if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                number.parse::<u8>().ok().filter(|id| *id != 0)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::MID_EXTENSION;
    use crate::sdp::parse;

    fn description(session: &str, media: &str) -> crate::sdp::SessionDescription {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n{session}\
             m=audio 4000 UDP/TLS/RTP/SAVPF 111 0\r\n{media}"
        );
        parse(text.as_bytes()).expect("a description")
    }

    #[test]
    fn the_bundle_group_is_read_in_its_own_order() {
        let offer = description(
            "a=group:LS 1 2\r\na=group:BUNDLE audio 0\r\n",
            "a=mid:audio\r\n",
        );
        assert_eq!(offer.bundle_group(), Some(vec!["audio", "0"]));
        let empty = description("a=group:BUNDLE\r\n", "");
        assert_eq!(empty.bundle_group(), Some(Vec::new()));
        assert_eq!(description("a=group:LS 1\r\n", "").bundle_group(), None);
        // the semantics are a token compared as written, and a tag must be one
        assert_eq!(description("a=group:bundle 0\r\n", "").bundle_group(), None);
        assert_eq!(
            description("a=group:BUNDLE 0 a,b\r\n", "").bundle_group(),
            None
        );
    }

    #[test]
    fn a_stream_says_its_tag_its_mux_and_its_extensions() {
        let offer = description(
            "",
            "a=mid:0\r\na=rtcp-mux\r\na=rtcp-mux-only\r\n\
             a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
             a=extmap:9/sendrecv urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
        );
        let stream = offer.media.first().expect("a stream");
        assert_eq!(stream.mid(), Some("0"));
        assert!(stream.has_rtcp_mux_only());
        assert_eq!(stream.extmap_id(MID_EXTENSION), Some(9));
        assert_eq!(stream.extmap_id("urn:ietf:params:rtp-hdrext:toffset"), None);
    }

    #[test]
    fn numbers_no_packet_can_carry_are_not_numbers() {
        for (line, read) in [
            ("a=extmap:0 urn:ietf:params:rtp-hdrext:sdes:mid\r\n", None),
            ("a=extmap:256 urn:ietf:params:rtp-hdrext:sdes:mid\r\n", None),
            (
                "a=extmap:4096 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
                None,
            ),
            ("a=extmap:+3 urn:ietf:params:rtp-hdrext:sdes:mid\r\n", None),
            ("a=extmap: urn:ietf:params:rtp-hdrext:sdes:mid\r\n", None),
            (
                "a=extmap:15 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
                Some(15),
            ),
            (
                "a=extmap:3/recvonly urn:ietf:params:rtp-hdrext:sdes:mid x\r\n",
                Some(3),
            ),
        ] {
            let offer = description("", line);
            let stream = offer.media.first().expect("a stream");
            assert_eq!(stream.extmap_id(MID_EXTENSION), read, "{line}");
        }
        let blank = description("", "a=mid:\r\n");
        assert_eq!(blank.media.first().and_then(|s| s.mid()), None);
    }
}
