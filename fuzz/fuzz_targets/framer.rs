// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A byte stream cut at arbitrary places, through the framer.
//!
//! The first byte of the input is the size of each read, so one input covers
//! both "the whole message in one go" and "one byte at a time", which are the
//! two shapes that break a reassembler. The framer must never hand out a
//! message longer than what it was given, never keep more than its bound once
//! the messages in front of it have been taken, and never panic on either. A
//! message it refuses and passes over is salvaged the way the endpoint
//! salvages one to answer it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::msg::{Framed, ParseMode, ParseScratch, StreamFramer, salvage_request};

const MAX: u32 = 8192;

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(first).max(1);

    let mut framer = StreamFramer::new(MAX);
    for piece in rest.chunks(chunk) {
        if framer.push(piece).is_err() {
            // a head past the bound: nothing says where the message ends, so
            // the caller closes the connection and this input is done
            return;
        }

        loop {
            match framer.next_message(ParseMode::Strict) {
                Ok(Some(Framed::Message(message))) => {
                    assert!(message.len() <= rest.len());
                    let _ = message.validate();
                    let _ = message.to_owned();
                }
                Ok(Some(Framed::Refused { head, length, .. })) => {
                    assert!(head.len() <= rest.len());
                    assert!(head.len() <= length);
                    let mut scratch = ParseScratch::new();
                    if let Some(request) = salvage_request(head, &mut scratch, 128) {
                        let _ = request.top_via();
                        let _ = request.from();
                        let _ = request.to();
                        let _ = request.call_id();
                        let _ = request.cseq();
                    }
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
        assert!(framer.pending() <= MAX as usize);
        while framer.take_ping() {}
    }
});
