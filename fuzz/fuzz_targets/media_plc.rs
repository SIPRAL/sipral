// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A stream of real frames and gaps through [`sipral_media::plc::Concealer`],
//! in whatever order and of whatever length the input names.
//!
//! Each step reads a control octet — its low bit says `received` or a frame
//! that did not arrive, the bit above it `reset` after the step, and the one
//! above that `stretch` rather than `conceal` for a frame that did not
//! arrive — a length octet, and that many sample pairs, so one input can
//! walk the concealer through the sequence its own doc comment calls out as
//! the subtle part: a gap that opens cold, one that runs past
//! [`sipral_media::plc::MAX_GAP_MS`], and a real frame arriving mid-gap to
//! close it with a splice.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::plc::Concealer;

fuzz_target!(|data: &[u8]| {
    let mut concealer = Concealer::new();
    let mut cursor = data;
    while let Some((&op, tail)) = cursor.split_first() {
        let Some((&len, tail)) = tail.split_first() else {
            break;
        };
        let take = (usize::from(len) * 2).min(tail.len());
        let (bytes, tail) = tail.split_at(take);
        cursor = tail;

        let mut frame: Vec<i16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_ne_bytes(*pair))
            .collect();

        if op & 1 == 0 {
            concealer.received(&mut frame);
        } else {
            let _ = if op & 4 == 0 {
                concealer.conceal(&mut frame)
            } else {
                concealer.stretch(&mut frame)
            };
            let _ = concealer.pitch_period();
            let _ = concealer.gap_samples();
        }
        if op & 2 != 0 {
            concealer.reset();
        }
    }
});
