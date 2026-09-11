// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A byte stream cut at arbitrary places, through the TURN stream framer, and
//! ChannelData read both ways it can arrive: already delimited (UDP) and
//! self-delimiting inside a stream (TCP/TLS).
//!
//! `StreamFraming` is TURN's own analogue of `sipral-core`'s `framer` target
//! and has none of its own; a stream that desynchronises is fatal by design,
//! so a single bad byte from a relay has to be handled every time, not just
//! survived once. `ChannelData::parse`/`parse_frame` are the messages that
//! framer hands out, fuzzed directly as well since a datagram transport
//! delivers them with no framer ahead of them at all.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_nat::turn::{ChannelData, StreamFraming, Transport};

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };

    // ChannelData, read as a self-contained datagram and as a stream frame
    // with each transport's padding rule
    let _ = ChannelData::parse_frame(rest);
    for transport in [Transport::Udp, Transport::Tcp, Transport::Tls] {
        if let Ok((message, consumed)) = ChannelData::parse(rest, transport) {
            assert!(consumed <= rest.len(), "parse consumed past the buffer");
            let _ = message.channel();
            let _ = message.data();
        }
    }

    // the stream framer, fed in chunks sized by the first byte so one seed
    // covers both "arrives whole" and "arrives one byte at a time"
    let chunk = usize::from(first).max(1);
    let mut framer = StreamFraming::new();
    for piece in rest.chunks(chunk) {
        framer.push(piece);
        loop {
            match framer.next_frame() {
                Ok(Some(frame)) => assert!(frame.len() <= rest.len()),
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
});
