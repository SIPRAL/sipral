// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Anything at all, through the RTCP compound packet parser and every typed
//! accessor it hands back.
//!
//! RTCP arrives on the same socket as RTP -- unencrypted RTCP does, and
//! `sipral-rtp` has no target of its own yet even though the parser reads a
//! byte count, a report count and a chunk length straight off the wire for
//! every packet type §6 defines. No input reaches a panic, and a packet that
//! parses is walked the way `endpoint` walks one on the receive path.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_rtp::{CompoundPacket, RtcpPacket};

fuzz_target!(|data: &[u8]| {
    let Ok(compound) = CompoundPacket::parse(data) else {
        return;
    };
    for packet in compound.packets() {
        match packet {
            RtcpPacket::SenderReport(sr) => {
                let _ = sr.ssrc();
                let _ = sr.info();
                let _ = sr.report_count();
                for block in sr.reports() {
                    let _ = block;
                }
            }
            RtcpPacket::ReceiverReport(rr) => {
                let _ = rr.ssrc();
                let _ = rr.report_count();
                for block in rr.reports() {
                    let _ = block;
                }
            }
            RtcpPacket::SourceDescription(sdes) => {
                let _ = sdes.cname();
                for chunk in sdes.chunks() {
                    let _ = chunk.ssrc();
                    let _ = chunk.cname();
                    for item in chunk.items() {
                        let _ = item;
                    }
                }
            }
            RtcpPacket::Goodbye(bye) => {
                for source in bye.sources() {
                    let _ = source;
                }
            }
            RtcpPacket::Other { packet_type } => {
                let _ = packet_type;
            }
        }
    }
});
