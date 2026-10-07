// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The frames a WebSocket server sends, cut at arbitrary places, through the
//! reader `sipral_ua::websocket` puts every read of a connection through.
//!
//! The first byte of the input is the size of each read, the rest is the
//! stream. The reader must never panic, never hand out a message larger than
//! its bound or a control frame over 125 bytes, never hold more than its
//! bound and one control frame, and stay broken once it
//! has said the stream broke RFC 6455. And where the reads fell must not
//! change what was read: the stream taken in the fuzzer's pieces and taken
//! one byte at a time gives the same frames, or the same error.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_ua::websocket::{Frame, FrameError, FrameReader, MAX_MESSAGE_BYTES};

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(first).max(1);
    let pieces = read(rest, chunk);
    let bytes = read(rest, 1);
    assert_eq!(pieces, bytes, "the reads changed what was read");
});

fn read(stream: &[u8], chunk: usize) -> (Vec<Frame>, Option<FrameError>) {
    let mut reader = FrameReader::new();
    let mut frames = Vec::new();
    for piece in stream.chunks(chunk) {
        reader.push(piece);
        loop {
            match reader.next_frame() {
                Ok(Some(frame)) => {
                    match &frame {
                        Frame::Text(message) | Frame::Binary(message) => {
                            assert!(message.len() <= MAX_MESSAGE_BYTES);
                            assert!(message.len() <= stream.len());
                        }
                        Frame::Ping(payload) | Frame::Pong(payload) => {
                            assert!(payload.len() <= 125);
                        }
                        Frame::Close { reason, .. } => assert!(reason.len() <= 123),
                    }
                    frames.push(frame);
                }
                Ok(None) => break,
                Err(error) => {
                    assert_eq!(
                        reader.next_frame(),
                        Err(error),
                        "a broken reader stays broken"
                    );
                    assert_eq!(reader.pending(), 0);
                    return (frames, Some(error));
                }
            }
        }
        // what is held is one frame not yet whole and the fragments before
        // it: the bound, or a control frame's 127 bytes past the fragments
        assert!(reader.pending() <= MAX_MESSAGE_BYTES + 127);
    }
    (frames, None)
}
