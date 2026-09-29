// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A stream of RTP datagrams, through the packet parser and the RFC 4103
//! real-time text receiver it feeds.
//!
//! Everything the receiver acts on is the peer's to choose: the sequence
//! numbers that place each block, the RFC 2198 headers that say how many
//! redundant generations a packet holds and how long each is, and the
//! octets that are meant to be UTF-8. The input is cut into datagrams --
//! an octet of length, then that many bytes -- and each one that parses is
//! received a tenth of a second after the one before, so a run of them
//! reaches the reordering wait and gives gaps up, as well as filling them.
//! The events are drained as they come, and at the end the clock jumps far
//! enough ahead that nothing can still be waiting.

#![no_main]

use core::time::Duration;

use libfuzzer_sys::fuzz_target;
use sipral_rtp::rtt::{ReceiverConfig, TextReceiver};
use sipral_rtp::{Frame, RtpPacket};

/// The formats a call would have negotiated: `t140/1000` and `red/1000`
/// carrying it. Whether a fuzzed packet is this receiver's is decided by
/// the payload type in it, as in a real call.
const T140: u8 = 98;
const RED: u8 = 100;

/// How far apart the datagrams arrive.
const STEP: Duration = Duration::from_millis(100);

fuzz_target!(|data: &[u8]| {
    let Ok(mut receiver) = TextReceiver::new(ReceiverConfig::new(T140, Some(RED))) else {
        return;
    };
    let mut now = Duration::ZERO;
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let take = usize::from(len).min(tail.len());
        let (datagram, tail) = tail.split_at(take);
        rest = tail;
        now += STEP;

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
        let _ = receiver.receive(frame, now);
        receiver.poll(now);
        receiver.events().for_each(drop);
    }
    receiver.poll(now + Duration::from_secs(3600));
    receiver.events().for_each(drop);
    assert_eq!(receiver.deadline(), None);
});
