// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A byte stream cut at arbitrary places, through the framer.
//!
//! The first byte of the input is the size of each read, so one input covers
//! both "the whole message in one go" and "one byte at a time", which are the
//! two shapes that break a reassembler. The framer must never hand out a
//! message longer than what it was given, never keep more than its bound, and
//! never panic on either.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::msg::{ParseMode, StreamFramer};

const MAX: u32 = 8192;

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(first).max(1);

    let mut framer = StreamFramer::new(MAX);
    for piece in rest.chunks(chunk) {
        if framer.push(piece).is_err() {
            // the bound was hit: a stream cannot be resynchronised, so the
            // caller closes the connection and this input is done
            return;
        }
        assert!(framer.pending() <= MAX as usize);

        loop {
            match framer.next_message(ParseMode::Strict) {
                Ok(Some(message)) => {
                    assert!(message.len() <= rest.len());
                    let _ = message.validate();
                    let _ = message.to_owned();
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
        while framer.take_ping() {}
    }
});
