// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A stream of frames through [`sipral_media::vad::Vad`], at whatever sample
//! rate and whatever cadence the input names.
//!
//! What can go wrong here is not a panic in the arithmetic -- there is no
//! division or table lookup that a frame's content can drive out of range --
//! but the adaptive noise floor walking somewhere its own rules forbid, so
//! every call checks the floor stays at or above the minimum the module
//! documents once it has seen one frame.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::vad::Vad;

fuzz_target!(|data: &[u8]| {
    let Some((&rate_byte, rest)) = data.split_first() else {
        return;
    };
    let sample_rate = 1_000_u32.saturating_add(u32::from(rate_byte) * 400);
    let mut vad = Vad::new(sample_rate);
    let mut primed = false;

    let mut cursor = rest;
    while let Some((&len, tail)) = cursor.split_first() {
        let take = (usize::from(len) * 2).min(tail.len());
        let (bytes, tail) = tail.split_at(take);
        cursor = tail;

        let frame: Vec<i16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_ne_bytes(*pair))
            .collect();
        let _ = vad.process(&frame);
        if frame.len() >= 2 {
            if primed {
                assert!(vad.noise_floor() >= 25, "the floor fell under MIN_FLOOR");
            }
            primed = true;
        }
    }
});
