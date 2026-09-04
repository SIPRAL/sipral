// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
use sipral_core::sdp::{AcceptedStream, Connection, Origin, SessionDescription, StreamAnswer, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(offer) = parse(data) else {
        return;
    };
    walk(&offer);

    let written = offer.to_bytes();
    let again = parse(&written).expect("what was written out has to read back in");
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
            parse(&written).expect("an answer has to read back in"),
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
