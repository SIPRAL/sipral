// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Arbitrary sources and gains through [`sipral_media::mix`]'s summing
//! functions.
//!
//! The first byte picks a gain, the rest is cut into two sources of samples,
//! and both [`sipral_media::mix::add_scaled_into`] and
//! [`sipral_media::mix::sum_scaled_into`] run over them: what has to hold,
//! whatever the samples and whatever the gain, is that nothing they write
//! ever leaves the range a sample has -- the property the whole module
//! exists to guarantee in place of the wrap plain addition would give.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::mix::{Gain, add_scaled_into, sum_scaled_into};

fuzz_target!(|data: &[u8]| {
    let Some((&gain_byte, rest)) = data.split_first() else {
        return;
    };
    let gain = Gain::from_q15(i32::from(gain_byte) * 512);

    let samples: Vec<i16> = rest
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| i16::from_ne_bytes(*pair))
        .collect();
    if samples.is_empty() {
        return;
    }
    let mid = samples.len() / 2;
    let (a, b) = samples.split_at(mid);

    let mut mix = a.to_vec();
    let report = add_scaled_into(&mut mix, b, gain);
    let _ = report.gain_to_fit();

    let sources: [&[i16]; 2] = [a, b];
    let gains = [gain, Gain::UNITY];
    let mut summed = vec![0_i16; mid];
    let _ = sum_scaled_into(&mut summed, &sources, &gains);
});
