// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A byte stream cut at arbitrary places, through the framer.
//!
//! The first byte of the input is the size of each read, so one input covers
//! both "the whole message in one go" and "one byte at a time", which are the
//! two shapes that break a reassembler. The framer must never hand out a
//! message longer than what it was given, never keep more than its bound once
//! the messages in front of it have been taken, and never panic on either. A
//! message it refuses and passes over is salvaged the way the endpoint
//! salvages one to answer it.
//!
//! And where the reads fell must not change what was read: the same stream
//! taken in the fuzzer's pieces and taken one byte at a time gives the same
//! messages, down to each `From` display name, byte for byte. A multi-byte UTF-8
//! character split between two TCP segments is the case this is for — a
//! name decoded before reassembly comes out as two broken halves.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::msg::{Framed, ParseMode, ParseScratch, StreamFramer, salvage_request};

/// The bounds each input is framed under: one a whole message fits in, and one
/// short enough that an input of a few hundred bytes reaches it — a head that
/// ends right at the bound, a body past it — in the time a run has.
const BOUNDS: [u32; 2] = [8192, 256];

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(first).max(1);
    for bound in BOUNDS {
        // lenient is what an endpoint reads with unless told otherwise
        for mode in [ParseMode::Strict, ParseMode::Lenient] {
            let pieces = frame(rest, chunk, bound, mode);
            let bytes = frame(rest, 1, bound, mode);
            // a stream that ran into its bound ends where the reads put it,
            // so only two readings that both reached the end are compared
            if let (Some(pieces), Some(bytes)) = (pieces, bytes) {
                assert_eq!(pieces, bytes, "the reads changed what was read");
            }
        }
    }
});

/// What one message said about its caller: the `From` display name, as the
/// bytes it decodes from, when it has one that parses.
type Caller = Option<Vec<u8>>;

/// Frame `rest` read `chunk` bytes at a time, and say who every message was
/// from, in order — or `None` when the stream ended early on its bound.
fn frame(rest: &[u8], chunk: usize, bound: u32, mode: ParseMode) -> Option<Vec<Caller>> {
    let mut framer = StreamFramer::new(bound);
    let mut callers = Vec::new();
    for piece in rest.chunks(chunk) {
        if framer.push(piece).is_err() {
            // a head past the bound: nothing says where the message ends, so
            // the caller closes the connection and this stream is done
            return None;
        }

        loop {
            match framer.next_message(mode) {
                Ok(Some(Framed::Message(message))) => {
                    assert!(message.len() <= rest.len());
                    let _ = message.validate();
                    let _ = message.to_owned();
                    callers.push(
                        message
                            .from()
                            .ok()
                            .and_then(|from| from.display_name().map(|name| name.into_owned())),
                    );
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
                    callers.push(None);
                }
                Ok(None) => break,
                Err(_) => return None,
            }
        }
        assert!(framer.pending() <= bound as usize);
        while framer.take_ping() {}
    }
    Some(callers)
}
