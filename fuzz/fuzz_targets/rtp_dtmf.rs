// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A stream of RTP datagrams, through the packet parser and the RFC 4733
//! named-event receiver it feeds.
//!
//! `RtpPacket::parse` reads every datagram that lands on the media socket and
//! has no target of its own; `EventReceiver` is the state machine that turns
//! a run of those into one reported DTMF digit, keyed on nothing a sender
//! has to prove -- the payload type, the RTP timestamp and four bytes of
//! payload are all a hostile peer controls. The input is cut into datagrams
//! -- an octet of length, then that many bytes -- with one call to `receive`
//! per packet that parses, so a single seed can walk the receiver through
//! the sequence of
//! timestamps and end bits that its own doc comment says are the subtle
//! part: reordering, a repeated timestamp, an event that never carries the
//! end bit, one that starts before the last one closed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_rtp::{EventReceiver, Frame, RtpPacket};

/// Fixed so every run drives the same receiver identity; the fuzzed payload
/// type in each packet is what decides whether a given packet is "this
/// receiver's own", same as a real call's negotiated dynamic type would.
const PAYLOAD_TYPE: u8 = 101;

fuzz_target!(|data: &[u8]| {
    let mut receiver = EventReceiver::new(PAYLOAD_TYPE);
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let take = usize::from(len).min(tail.len());
        let (datagram, tail) = tail.split_at(take);
        rest = tail;

        let Ok(packet) = RtpPacket::parse(datagram) else {
            continue;
        };
        let header = packet.header();
        let frame = Frame {
            sequence: header.sequence,
            timestamp: header.timestamp,
            payload_type: header.payload_type,
            marker: header.marker,
            payload: packet.payload(),
        };
        let _ = receiver.receive(frame);
    }
    let _ = receiver.flush();
});
