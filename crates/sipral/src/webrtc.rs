// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a WebRTC line writes around its one audio stream, and the answer to
//! an offer that bundles.
//!
//! A PBX's WebRTC endpoint describes its audio the way a browser does: the
//! stream in a BUNDLE group (RFC 8843) under an identification-tag (`a=mid`,
//! RFC 5888), the header extension that carries the tag in RTP (RFC 8843
//! §14), RTP and RTCP on one port and no other (`a=rtcp-mux-only`, RFC 8858),
//! and the source named by `a=msid` (RFC 8830) and `a=ssrc` with its CNAME
//! (RFC 5576). With one stream there is one section in the group, so
//! BUNDLE changes no transport here: the stream already has its 5-tuple, and
//! RFC 7983's first octet already tells STUN, DTLS and RTP apart on it
//! (`sipral_nat::demux`). What it changes is the description, which a peer
//! that bundles reads and requires.
//!
//! The transport itself is the rest of the catalogue's
//! ([`CodecCatalog::with_webrtc`](crate::CodecCatalog::with_webrtc)):
//! DTLS-SRTP, ICE, and the feedback profile that makes `UDP/TLS/RTP/SAVP`
//! into `UDP/TLS/RTP/SAVPF` (`crate::feedback`).

use sipral_core::sdp::{Attribute, MID_EXTENSION, MediaDescription, SessionDescription};

/// The identification-tag this end's offer gives its audio stream: a counter
/// within the group, as RFC 8843 §20 asks of a tag, which must not say
/// anything about the user.
const TAG: &str = "0";

/// The number this end's offer gives the MID header extension (RFC 8285 §5),
/// in the one-byte form's range.
const MID_ID: u8 = 1;

/// The one source a WebRTC line's stream sends from.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Source<'a> {
    /// The stream's SSRC (RFC 3550 §5.1), which `a=ssrc` announces.
    pub(crate) ssrc: u32,
    /// The CNAME its RTCP carries (RFC 3550 §6.5.1), the same text.
    pub(crate) cname: &'a str,
    /// What the `a=msid` identifier is drawn from: the call's session id,
    /// already unpredictable and already in the `o=` line.
    pub(crate) stream: u64,
}

impl Source<'_> {
    /// `a=msid` (RFC 8830 §2): the media stream, then the track.
    fn msid(&self) -> Attribute {
        Attribute::with_value("msid", &format!("{:016x} audio", self.stream))
    }

    /// `a=ssrc` with the CNAME (RFC 5576 §4.1, §6.1).
    fn ssrc(&self) -> Attribute {
        Attribute::with_value("ssrc", &format!("{} cname:{}", self.ssrc, self.cname))
    }
}

/// Where a stream's own lines go: before its direction, which an offer from
/// here writes last.
fn before_direction(stream: &MediaDescription) -> usize {
    stream
        .attributes
        .iter()
        .position(|attribute| attribute.direction().is_some())
        .unwrap_or(stream.attributes.len())
}

/// `a=rtcp-mux-only` right after the `a=rtcp-mux` it goes with (RFC 8858
/// §4.2 has one never without the other).
fn add_mux_only(stream: &mut MediaDescription) {
    if stream.has_rtcp_mux_only() {
        return;
    }
    if let Some(at) = stream
        .attributes
        .iter()
        .position(|attribute| attribute.name == "rtcp-mux")
    {
        stream
            .attributes
            .insert(at + 1, Attribute::flag("rtcp-mux-only"));
    }
}

/// The header extension line for the tag, under `id`.
fn mid_extmap(id: u8) -> Attribute {
    Attribute::with_value("extmap", &format!("{id} {MID_EXTENSION}"))
}

/// Make a freshly written offer a WebRTC line's: its first live audio stream
/// tagged and alone in a BUNDLE group (RFC 8843 §7.2), mapping the MID header
/// extension (§9.1), multiplexing RTCP exclusively (§9.3.1.1, RFC 8858
/// §4.2), and naming its source.
pub(crate) fn offer(description: &mut SessionDescription, source: &Source<'_>) {
    let Some(stream) = description
        .media
        .iter_mut()
        .find(|stream| stream.media == "audio" && !stream.is_rejected())
    else {
        return;
    };
    // trickle ICE may have tagged the stream already (RFC 8840 §4.1.1): one tag, first
    stream
        .attributes
        .retain(|attribute| attribute.name != "mid");
    stream
        .attributes
        .insert(0, Attribute::with_value("mid", TAG));
    add_mux_only(stream);
    let at = before_direction(stream);
    stream
        .attributes
        .splice(at..at, [mid_extmap(MID_ID), source.msid(), source.ssrc()]);
    description
        .attributes
        .insert(0, Attribute::with_value("group", &format!("BUNDLE {TAG}")));
}

/// Whether `offered`, a stream of `offer`, is in the offer's BUNDLE group.
pub(crate) fn bundled(offer: &SessionDescription, offered: &MediaDescription) -> bool {
    offered
        .mid()
        .zip(offer.bundle_group())
        .is_some_and(|(mid, group)| group.contains(&mid))
}

/// Whether an answer to `offered` has to multiplex RTP and RTCP whatever
/// this end would choose: the offer allows nothing else (RFC 8858 §4.3), or
/// bundles the stream, which RFC 8843 §9.3.1.2 makes the same thing. Always
/// `false` for a stream that did not offer `a=rtcp-mux` at all.
pub(crate) fn mux_required(offer: &SessionDescription, offered: &MediaDescription) -> bool {
    offered.has_rtcp_mux() && (offered.has_rtcp_mux_only() || bundled(offer, offered))
}

/// Put on a freshly written answer what RFC 8843 asks of one to an offer
/// that tags or bundles its streams: each accepted stream's tag back (RFC
/// 5888 §9.2), the group of those accepted that the offer bundled, in the
/// offer's order so that the first is the tag the offerer suggested (§7.3.1),
/// and in each bundled stream the MID extension under the offer's number
/// (§9.1) and `a=rtcp-mux-only` where the offer said it (§9.3.1.2). The audio
/// stream names its source when it is bundled or `line` says this is a
/// WebRTC line.
///
/// A stream refused in the answer is left out of the group (§7.3.3).
pub(crate) fn answer(
    answer: &mut SessionDescription,
    offer: &SessionDescription,
    source: &Source<'_>,
    line: bool,
) {
    let mut accepted: Vec<&str> = Vec::new();
    for (offered, answered) in offer.media.iter().zip(answer.media.iter_mut()) {
        if answered.is_rejected() {
            continue;
        }
        if let Some(mid) = offered.mid() {
            // the offer's tag, which trickle ICE may have echoed already (RFC 5888 §9.1)
            answered
                .attributes
                .retain(|attribute| attribute.name != "mid");
            answered
                .attributes
                .insert(0, Attribute::with_value("mid", mid));
        }
        let in_group = bundled(offer, offered);
        if let Some(mid) = offered.mid().filter(|_| in_group) {
            accepted.push(mid);
            if offered.has_rtcp_mux_only() {
                add_mux_only(answered);
            }
        }
        let at = before_direction(answered);
        let mut lines = Vec::new();
        if let Some(id) = offered
            .extmap_id(MID_EXTENSION)
            .filter(|_| in_group && answered.media == "audio")
        {
            lines.push(mid_extmap(id));
        }
        if answered.media == "audio" && (in_group || line) {
            lines.extend([source.msid(), source.ssrc()]);
        }
        answered.attributes.splice(at..at, lines);
    }
    let Some(group) = offer.bundle_group() else {
        return;
    };
    let tags: Vec<&str> = group
        .into_iter()
        .filter(|tag| accepted.contains(tag))
        .collect();
    if !tags.is_empty() {
        answer.attributes.insert(
            0,
            Attribute::with_value("group", &format!("BUNDLE {}", tags.join(" "))),
        );
    }
}

/// The first audio stream of a description that is not refused.
fn live_audio(description: &SessionDescription) -> Option<&MediaDescription> {
    description
        .media
        .iter()
        .find(|stream| stream.media == "audio" && !stream.is_rejected())
}

/// The tag and extension number this end's audio is to carry (RFC 8843
/// §15), when both descriptions map the MID header extension to the same
/// number on their first live audio stream and ours names the stream's tag.
pub(crate) fn mid_to_send(
    ours: &SessionDescription,
    theirs: &SessionDescription,
) -> Option<(u8, String)> {
    let (mine, far) = (live_audio(ours)?, live_audio(theirs)?);
    let id = mine.extmap_id(MID_EXTENSION)?;
    if far.extmap_id(MID_EXTENSION)? != id {
        return None;
    }
    Some((id, mine.mid()?.to_owned()))
}

#[cfg(test)]
mod tests {
    use sipral_core::sdp::{MID_EXTENSION, SessionDescription, parse};

    use super::{Source, answer, bundled, mid_to_send, mux_required, offer};

    const SOURCE: Source<'static> = Source {
        ssrc: 0x1234_5678,
        cname: "sipral@192.0.2.1",
        stream: 0xabcd,
    };

    fn description(session: &str, streams: &str) -> SessionDescription {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
             {session}{streams}"
        );
        parse(text.as_bytes()).expect("a description")
    }

    fn lines(description: &SessionDescription) -> String {
        String::from_utf8(description.to_bytes()).expect("text")
    }

    #[test]
    fn a_webrtc_offer_bundles_its_one_stream_and_says_where_it_comes_from() {
        let mut written = description(
            "",
            "m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\na=rtcp-mux\r\na=setup:actpass\r\na=sendrecv\r\n",
        );
        offer(&mut written, &SOURCE);
        let text = lines(&written);
        assert!(
            text.contains("t=0 0\r\na=group:BUNDLE 0\r\nm=audio"),
            "{text}"
        );
        assert!(
            text.contains(
                "m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\na=mid:0\r\na=rtcp-mux\r\na=rtcp-mux-only\r\n\
                 a=setup:actpass\r\na=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
                 a=msid:000000000000abcd audio\r\na=ssrc:305419896 cname:sipral@192.0.2.1\r\n\
                 a=sendrecv\r\n"
            ),
            "{text}"
        );
        let stream = written.media.first().expect("a stream");
        assert!(bundled(&written, stream));
        assert!(mux_required(&written, stream));
    }

    #[test]
    fn a_bundled_offer_is_answered_with_its_tag_its_group_and_its_extension() {
        let offered = description(
            "a=group:BUNDLE 0\r\na=msid-semantic: WMS *\r\n",
            "m=audio 4000 UDP/TLS/RTP/SAVPF 111 0\r\na=mid:0\r\na=rtcp-mux\r\n\
             a=rtcp-mux-only\r\na=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
             a=rtcp-fb:111 transport-cc\r\na=msid:s t\r\na=ssrc:1 cname:far\r\n",
        );
        let stream = offered.media.first().expect("a stream");
        assert!(mux_required(&offered, stream), "RFC 8843 §9.3.1.2");
        let mut written = description(
            "",
            "m=audio 5000 UDP/TLS/RTP/SAVPF 0\r\na=rtcp-mux\r\na=sendrecv\r\n",
        );
        answer(&mut written, &offered, &SOURCE, false);
        let text = lines(&written);
        assert!(
            text.contains("t=0 0\r\na=group:BUNDLE 0\r\nm=audio"),
            "{text}"
        );
        assert!(
            text.contains(
                "a=mid:0\r\na=rtcp-mux\r\na=rtcp-mux-only\r\n\
                 a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
                 a=msid:000000000000abcd audio\r\na=ssrc:305419896 cname:sipral@192.0.2.1\r\n\
                 a=sendrecv\r\n"
            ),
            "{text}"
        );
        assert_eq!(mid_to_send(&written, &offered), Some((4, "0".to_owned())));
    }

    #[test]
    fn a_refused_stream_leaves_the_group_and_the_next_tag_leads_it() {
        let offered = description(
            "a=group:BUNDLE v a\r\n",
            "m=video 4002 UDP/TLS/RTP/SAVPF 96\r\na=mid:v\r\na=rtcp-mux\r\n\
             m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\na=mid:a\r\na=rtcp-mux\r\n",
        );
        let mut written = description(
            "",
            "m=video 0 UDP/TLS/RTP/SAVPF 96\r\nm=audio 5000 UDP/TLS/RTP/SAVPF 0\r\na=rtcp-mux\r\n",
        );
        answer(&mut written, &offered, &SOURCE, false);
        assert_eq!(written.bundle_group(), Some(vec!["a"]));
        assert_eq!(written.media.first().and_then(|s| s.mid()), None);
        let audio = written.media.get(1).expect("the audio");
        assert_eq!(audio.mid(), Some("a"));
        assert!(!audio.has_rtcp_mux_only(), "the offer did not say it");
        assert_eq!(
            audio.extmap_id(MID_EXTENSION),
            None,
            "the offer did not map it"
        );
    }

    #[test]
    fn a_plain_offer_gets_a_plain_answer_unless_this_end_is_a_webrtc_line() {
        let offered = description("", "m=audio 4000 RTP/AVP 0\r\na=rtcp-mux-only\r\n");
        let stream = offered.media.first().expect("a stream");
        assert!(!mux_required(&offered, stream), "mux-only without mux");
        let template = description("", "m=audio 5000 RTP/AVP 0\r\na=sendrecv\r\n");
        let mut written = template.clone();
        answer(&mut written, &offered, &SOURCE, false);
        assert_eq!(written, template);
        answer(&mut written, &offered, &SOURCE, true);
        assert!(lines(&written).contains("a=ssrc:305419896 cname:"));
        assert!(written.bundle_group().is_none());

        let muxed_only = description(
            "",
            "m=audio 4000 RTP/AVP 0\r\na=rtcp-mux\r\na=rtcp-mux-only\r\n",
        );
        let stream = muxed_only.media.first().expect("a stream");
        assert!(mux_required(&muxed_only, stream), "RFC 8858 §4.3");
    }

    #[test]
    fn the_tag_goes_out_only_when_both_ends_mapped_it_alike() {
        let ours = description(
            "a=group:BUNDLE 0\r\n",
            "m=audio 5000 UDP/TLS/RTP/SAVPF 0\r\na=mid:0\r\n\
             a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
        );
        let alike = description(
            "",
            "m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\na=mid:0\r\n\
             a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
        );
        let other = description(
            "",
            "m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\na=mid:0\r\n\
             a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
        );
        let none = description("", "m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\na=mid:0\r\n");
        assert_eq!(mid_to_send(&ours, &alike), Some((1, "0".to_owned())));
        assert_eq!(mid_to_send(&ours, &other), None);
        assert_eq!(mid_to_send(&ours, &none), None);
    }
}
