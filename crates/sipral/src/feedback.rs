// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! RTCP feedback in a call's descriptions: the feedback profiles (RFC 4585
//! §4.1, RFC 5124, RFC 5764 §8), `a=rtcp-fb` (RFC 4585 §4.2) and
//! `a=rtcp-rsize` (RFC 5506 §5), and what a pair of descriptions agreed.
//!
//! The profile is the negotiation. A stream offered on RTP/AVPF is answered
//! on it or refused (RFC 4585 §4.1 gives an answerer no way to accept the
//! stream on RTP/AVP), so a stream whose offer and answer both name a
//! feedback profile runs RFC 4585's RTCP whether or not a single `a=rtcp-fb`
//! line was agreed. The lines add what that RTCP carries: Generic NACKs when
//! both descriptions named `nack` for the stream's codec or for `*`, a
//! `trr-int` when either named one, and reduced size when both said
//! `a=rtcp-rsize`.

use sipral_core::sdp::{Attribute, MediaDescription};
use sipral_rtp::avpf::{
    Feedback, FeedbackPayload, FeedbackValue, Negotiated, RTCP_RSIZE, RtcpFb, answer_attributes,
    offers_rsize,
};

/// Whether a transport names one of the feedback profiles: its last token
/// is `AVPF` or `SAVPF` (`RTP/AVPF`, `RTP/SAVPF`, `UDP/TLS/RTP/SAVPF`).
pub(crate) fn has_feedback(proto: &str) -> bool {
    proto
        .rsplit('/')
        .next()
        .is_some_and(|last| last.eq_ignore_ascii_case("AVPF") || last.eq_ignore_ascii_case("SAVPF"))
}

/// Turn an offer's stream into one asking for feedback: the profile with
/// feedback beside the one it named (`RTP/AVP` to `RTP/AVPF`, `RTP/SAVP` to
/// `RTP/SAVPF`, `UDP/TLS/RTP/SAVP` to `UDP/TLS/RTP/SAVPF`), Generic NACKs for
/// every format, and reduced-size RTCP.
pub(crate) fn offer(stream: &mut MediaDescription) {
    if !has_feedback(&stream.proto) {
        stream.proto.push('F');
    }
    let nack = RtcpFb {
        payload: FeedbackPayload::All,
        value: FeedbackValue::GenericNack,
    };
    // before the direction, which an offer writes last
    let at = stream
        .attributes
        .iter()
        .position(|attribute| attribute.direction().is_some())
        .unwrap_or(stream.attributes.len());
    stream
        .attributes
        .splice(at..at, [nack.to_attribute(), Attribute::flag(RTCP_RSIZE)]);
}

/// The feedback lines an answer to `offered` carries, for the formats it
/// accepted: the `nack` and `trr-int` lines of the offer this stack does, and
/// `a=rtcp-rsize` when the offer said it. Nothing for an offer on a profile
/// without feedback.
pub(crate) fn answer(offered: &MediaDescription, accepted: &[String]) -> Vec<Attribute> {
    let payloads: Vec<u8> = accepted
        .iter()
        .filter_map(|format| format.parse().ok())
        .collect();
    answer_attributes(offered, &payloads, true)
}

/// What our description and the far end's agreed about feedback on the
/// stream whose codec has payload type `payload` — our number for it, then
/// theirs, which differ where an answer renumbered it — or `None` when either does
/// not name a feedback profile.
///
/// `trr-int` is the longer of the two when both name one, since each end
/// asks for its Regular reports to be no closer than that (RFC 4585 §3.4 m),
/// and the one that asks for less is also satisfied by more.
pub(crate) fn negotiated(
    ours: &MediaDescription,
    theirs: &MediaDescription,
    payload: (u8, u8),
) -> Option<Negotiated> {
    if !has_feedback(&ours.proto) || !has_feedback(&theirs.proto) {
        return None;
    }
    let (mine, far) = (
        Feedback::of(ours, payload.0),
        Feedback::of(theirs, payload.1),
    );
    let trr_interval = match (mine.trr_interval, far.trr_interval) {
        (Some(left), Some(right)) => left.max(right),
        (left, right) => left.or(right).unwrap_or_default(),
    };
    Some(Negotiated {
        generic_nack: mine.generic_nack && far.generic_nack,
        trr_interval,
        reduced_size: offers_rsize(ours) && offers_rsize(theirs),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sipral_core::sdp::{MediaDescription, parse};
    use sipral_rtp::avpf::Negotiated;

    use super::{answer, has_feedback, negotiated, offer};

    fn stream(lines: &str) -> MediaDescription {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n{lines}"
        );
        parse(text.as_bytes())
            .expect("a description")
            .media
            .into_iter()
            .next()
            .expect("a stream")
    }

    #[test]
    fn the_feedback_profiles_are_recognised_whatever_the_keying() {
        for proto in ["RTP/AVPF", "RTP/SAVPF", "UDP/TLS/RTP/SAVPF", "rtp/avpf"] {
            assert!(has_feedback(proto), "{proto}");
        }
        for proto in ["RTP/AVP", "RTP/SAVP", "UDP/TLS/RTP/SAVP", "udp"] {
            assert!(!has_feedback(proto), "{proto}");
        }
    }

    #[test]
    fn an_offer_asks_for_feedback_on_the_profile_beside_its_own() {
        for (plain, with) in [
            ("RTP/AVP", "RTP/AVPF"),
            ("RTP/SAVP", "RTP/SAVPF"),
            ("UDP/TLS/RTP/SAVP", "UDP/TLS/RTP/SAVPF"),
        ] {
            let mut written = stream(&format!("m=audio 4000 {plain} 0\r\na=sendrecv\r\n"));
            offer(&mut written);
            assert_eq!(written.proto, with);
            let names: Vec<String> = written
                .attributes
                .iter()
                .map(|attribute| attribute.name.clone())
                .collect();
            assert_eq!(names, ["rtcp-fb", "rtcp-rsize", "sendrecv"]);
        }
    }

    #[test]
    fn an_answer_keeps_what_was_offered_and_is_done_here() {
        let offered = stream(
            "m=audio 4000 RTP/AVPF 0 8\r\na=rtcp-fb:* nack\r\na=rtcp-fb:8 trr-int 100\r\n\
a=rtcp-fb:* nack pli\r\na=rtcp-rsize\r\n",
        );
        let lines: Vec<String> = answer(&offered, &["0".to_owned()])
            .iter()
            .map(|attribute| {
                format!(
                    "{}:{}",
                    attribute.name,
                    attribute.value.clone().unwrap_or_default()
                )
            })
            .collect();
        assert_eq!(lines, ["rtcp-fb:* nack", "rtcp-rsize:"]);
        let plain = stream("m=audio 4000 RTP/AVP 0\r\na=rtcp-fb:* nack\r\n");
        assert!(answer(&plain, &["0".to_owned()]).is_empty());
    }

    #[test]
    fn what_was_agreed_needs_both_descriptions() {
        let full = stream("m=audio 4000 RTP/AVPF 0\r\na=rtcp-fb:* nack\r\na=rtcp-rsize\r\n");
        let bare = stream("m=audio 4000 RTP/AVPF 0\r\n");
        let plain = stream("m=audio 4000 RTP/AVP 0\r\na=rtcp-fb:* nack\r\n");
        assert_eq!(
            negotiated(&full, &full, (0, 0)),
            Some(Negotiated {
                generic_nack: true,
                trr_interval: Duration::ZERO,
                reduced_size: true,
            })
        );
        assert_eq!(
            negotiated(&full, &bare, (0, 0)),
            Some(Negotiated::default()),
            "the profile alone is RFC 4585's timing, with nothing more agreed"
        );
        assert_eq!(negotiated(&full, &plain, (0, 0)), None);
        let slow = stream("m=audio 4000 RTP/AVPF 0\r\na=rtcp-fb:0 trr-int 5000\r\n");
        let slower = stream("m=audio 4000 RTP/AVPF 0\r\na=rtcp-fb:* trr-int 8000\r\n");
        assert_eq!(
            negotiated(&slow, &slower, (0, 0)).map(|agreed| agreed.trr_interval),
            Some(Duration::from_secs(8))
        );
        assert_eq!(
            negotiated(&slow, &bare, (0, 0)).map(|agreed| agreed.trr_interval),
            Some(Duration::from_secs(5))
        );
    }
}
