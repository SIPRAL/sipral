// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the session description parser.
//!
//! Two properties. No input reaches a panic, as everywhere else in the receive
//! path. And a description that parses, written back out, parses again into
//! exactly the same description: SDP travels through a call inside messages
//! that get forwarded, so a body that changes meaning by passing through here
//! is a bug even when nothing crashes.
//!
//! The answer is built too. It is derived from the offer, so an offer that is
//! strange enough is the shortest way to a strange answer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::sdp::{
    AcceptedStream, Connection, Limits, Origin, SessionDescription, StreamAnswer, parse,
    parse_with_limits,
};

/// `to_bytes` always closes a line with CRLF, the ending RFC 4566 itself
/// writes; `parse` tolerates a bare LF too, per its own doc comment, which is
/// what a body close to the size limit and built with one grows by once it
/// gets its `\r` back: one octet per line, and two on a last line that had no
/// ending at all. A line is at least two bytes, so that growth cannot exceed
/// the input's own length plus one -- and `parse(data)` below already bounds
/// that length to `Limits::DEFAULT.max_body_bytes`. So a body that
/// was at most the default limit going in is at most double that plus one
/// coming back out, and re-parsing under that relaxed body limit -- every
/// other bound left at the default -- is what makes the assertion below test
/// the real property: that writing a description does not change what it
/// means, not that its canonical form stays inside the size a wire policy
/// puts on bytes a stranger sent.
const ROUND_TRIP_LIMITS: Limits = Limits {
    max_body_bytes: Limits::DEFAULT.max_body_bytes * 2 + 1,
    ..Limits::DEFAULT
};

/// The answer is read back under bounds of its own, for the same reason and
/// because it is not the offer written again. Every line of it is one of
/// three things. One of the four it opens with -- `v=`, `o=`, `s=`, `c=` --
/// 56 octets as this target has them written. A direction line, 12 octets,
/// one per stream, so at most `Limits::DEFAULT.max_media` of them. Or a line
/// of the offer written again, each at most once: the `t=` and `r=` lines
/// (RFC 3264 §6), and for each stream its `m=` line and the `rtpmap` and
/// `fmtp` of the one format it keeps. None of those comes out longer than it
/// went in, except an `m=` line, whose port is written as 5000 where the
/// offer's may have been one digit: four octets more at most, for any port a
/// `u16` holds, which is the line bound below. With its CRLF, a line of the
/// offer of at least two bytes comes back at most double its length, and so
/// does an `m=` line with its four extra octets, since one is at least seven.
/// So the answer is at most twice the offer plus the 56 + 12 x 16 = 248
/// octets it writes of its own, which is under three times the default body
/// limit. The counts need no room: as many streams as the offer, and at most
/// one format and three attributes in each.
const ANSWER_LIMITS: Limits = Limits {
    max_body_bytes: Limits::DEFAULT.max_body_bytes * 3,
    max_line_bytes: Limits::DEFAULT.max_line_bytes + 4,
    ..Limits::DEFAULT
};

fuzz_target!(|data: &[u8]| {
    let Ok(offer) = parse(data) else {
        return;
    };
    walk(&offer);

    let written = offer.to_bytes();
    let again = parse_with_limits(&written, ROUND_TRIP_LIMITS)
        .expect("what was written out has to read back in");
    assert_eq!(offer, again, "writing a description changed it");
    assert_eq!(written, again.to_bytes());

    // accept every stream with the formats it was offered, which is the widest
    // answer there is, and the one most likely to trip over an odd offer
    let streams: Vec<StreamAnswer> = offer
        .media
        .iter()
        .map(|media| match media.formats.first() {
            Some(format) => StreamAnswer::Accept(AcceptedStream::new(5000, vec![format.clone()])),
            None => StreamAnswer::Reject,
        })
        .collect();
    let address = "192.0.2.1".parse().expect("an address");
    if let Ok(answer) = offer.answer(
        Origin::new(1, 1, address),
        Connection::new(address),
        &streams,
    ) {
        walk(&answer);
        let written = answer.to_bytes();
        assert_eq!(
            parse_with_limits(&written, ANSWER_LIMITS).expect("an answer has to read back in"),
            answer
        );
    }
});

fn walk(sdp: &SessionDescription) {
    let _ = sdp.direction();
    for media in &sdp.media {
        let _ = sdp.direction_of(media);
        let _ = sdp.connection_of(media);
        let _ = media.is_rejected();
        let _ = media.ptime();
        let _ = media.has_rtcp_mux();
        for payload in media.payload_types() {
            let _ = media.rtpmap(payload);
            let _ = media.fmtp(payload);
        }
    }
    if let Some(connection) = &sdp.connection {
        let _ = connection.ip();
        let _ = connection.is_black_hole();
    }
}
