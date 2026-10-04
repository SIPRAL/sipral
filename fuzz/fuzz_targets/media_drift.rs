// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A stream of frames through [`sipral_media::drift::Drift`], at whatever
//! sample rate and whatever cadence the input names.
//!
//! Every call sizes its own output slice at exactly one sample more than the
//! frame it offers, which is the one size [`Drift::process`] promises to fill
//! rather than refuse, so what is fuzzed is the warp itself: the window
//! [`sipral_media::drift::quietest`] finds, and the Catmull-Rom interpolation
//! that compresses or stretches it, across frame lengths and contents the
//! seed corpus did not write by hand.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::drift::Drift;

fuzz_target!(|data: &[u8]| {
    let Some((&rate_byte, rest)) = data.split_first() else {
        return;
    };
    let sample_rate = 1_000_u32.saturating_add(u32::from(rate_byte) * 400);
    let mut drift = Drift::new(sample_rate);

    let mut cursor = rest;
    while let Some((&len, tail)) = cursor.split_first() {
        let take = (usize::from(len) * 2).min(tail.len());
        let (bytes, tail) = tail.split_at(take);
        cursor = tail;

        let samples: Vec<i16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_ne_bytes(*pair))
            .collect();
        let mut output = vec![0_i16; samples.len() + 1];
        let written = drift.process(&samples, &mut output);
        assert!(written <= output.len());
        drift.consumed(samples.len());
        let _ = drift.excess();
        let _ = drift.drift_ppm();
    }
});
