// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A byte stream cut at arbitrary places, through the headless control
//! channel: the frame reassembler and the JSON control message it decodes.
//!
//! Both sides of this are reachable straight off the socket a voice agent
//! connects on, before a single call exists to give any of it structure --
//! the first byte the peer sends can be a frame's kind byte. Modelled on
//! `framer`: the first byte of the input picks the read size, so one seed
//! covers both a message that arrives whole and one that trickles in one
//! byte at a time.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_headless::{ControlMessage, FrameDecoder};

const MAX_PAYLOAD: u16 = 65535;

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(first).max(1);

    let mut decoder = FrameDecoder::new(MAX_PAYLOAD);
    for piece in rest.chunks(chunk) {
        decoder.push(piece);
        loop {
            match decoder.next_frame() {
                Ok(Some(frame)) => {
                    // decode must never panic on a peer's bytes, whether or
                    // not they happen to be valid JSON, and whether or not
                    // the kind byte names a real frame kind
                    let _ = ControlMessage::decode(frame.kind(), frame.payload());
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
});
