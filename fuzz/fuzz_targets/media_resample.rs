// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A stream through [`sipral_media::resample::Resampler`], at whatever rate
//! pair and whatever cadence of frames the input names.
//!
//! The first two bytes choose a rate pair from the six rates the pipeline
//! actually meets; every rate pair after that is refused by [`Resampler::new`]
//! before anything is built. What is left is fed to a single resampler across
//! several calls, each one's length named by the byte in front of it, so a
//! run exercises the same buffered-history path a real call does rather than
//! one call in isolation. Nothing here checks the audio is good, only that
//! `process` never panics and never reports more samples than the output slice
//! it was sized against, which is the property `output_capacity` promises.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::resample::Resampler;

const RATES: [u32; 6] = [8_000, 16_000, 24_000, 32_000, 44_100, 48_000];

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let Some((&second, rest)) = rest.split_first() else {
        return;
    };
    let input_rate = RATES[usize::from(first) % RATES.len()];
    let output_rate = RATES[usize::from(second) % RATES.len()];
    let Ok(mut resampler) = Resampler::new(input_rate, output_rate) else {
        return;
    };

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
        let needed = resampler.output_capacity(samples.len());
        let mut output = vec![0_i16; needed];
        let Ok(produced) = resampler.process(&samples, &mut output) else {
            // the slice was sized by `output_capacity` itself
            unreachable!("a slice sized by output_capacity was refused");
        };
        assert!(produced <= output.len());

        // an odd byte out of step with the resampler's own idea of a reset
        // point exercises forgetting the stream mid-run
        if len % 5 == 0 {
            resampler.reset();
        }
    }
});
