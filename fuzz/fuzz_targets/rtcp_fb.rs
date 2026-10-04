// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the RTCP feedback readers: a datagram read as
//! compound or reduced-size RTCP under both answers to whether `a=rtcp-rsize`
//! was negotiated, each feedback message it carries, and the same bytes as
//! an `a=rtcp-fb` value.
//!
//! No input reaches a panic. A Generic NACK that parses is written back from
//! its own entries and must come out as the same entries.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_rtp::avpf::{
    FeedbackPacket, GenericNackBuilder, NackEntry, ReceivedRtcp, ReducedSize, RtcpFb,
};

fuzz_target!(|data: &[u8]| {
    for policy in [ReducedSize::new(false), ReducedSize::new(true)] {
        let Ok(received) = ReceivedRtcp::parse(data, &policy) else {
            continue;
        };
        let _ = received.form();
        let _ = received.compound();
        for packet in received.packets() {
            let _ = (packet.packet_type(), packet.count(), packet.bytes());
        }
        for feedback in received.feedback() {
            let FeedbackPacket::GenericNack(nack) = feedback else {
                continue;
            };
            let entries: Vec<NackEntry> = nack.entries().collect();
            let lost: Vec<u16> = nack.lost().collect();
            assert_eq!(lost.len(), entries.iter().map(|e| e.lost().count()).sum());
            let builder = GenericNackBuilder {
                sender_ssrc: nack.sender_ssrc(),
                media_ssrc: nack.media_ssrc(),
                entries: &entries,
            };
            let mut out = vec![0; builder.encoded_len()];
            let written = builder.write(&mut out);
            assert_eq!(written, Ok(out.len()));
            let Ok(FeedbackPacket::GenericNack(again)) = FeedbackPacket::parse(&out) else {
                panic!("a NACK written from parsed entries did not parse");
            };
            assert!(again.entries().eq(entries.iter().copied()));
            let _ = NackEntry::pack(lost);
        }
    }
    let _ = FeedbackPacket::parse(data);
    if let Ok(text) = core::str::from_utf8(data)
        && let Some(line) = RtcpFb::parse(text)
    {
        assert_eq!(RtcpFb::parse(&line.to_value()), Some(line));
    }
});
