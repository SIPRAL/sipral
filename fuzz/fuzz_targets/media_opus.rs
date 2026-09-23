// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Packets nobody's encoder produced, through
//! [`sipral_media::opus::Decoder`] at each rate and frame duration this
//! module supports.
//!
//! Everything from the bindings is folded into [`sipral_media::opus::CodecError`]
//! before it reaches a caller (the module's own doc comment says so), and the
//! four checked arguments this target can drive -- the rate, the frame
//! duration and the two buffer lengths -- are exactly the ones checked before
//! libopus ever sees them. What this target exercises is everything after
//! that check: libopus's own packet parser, run on bytes nothing built.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::opus::{Decoder, FrameDuration, SampleRate};

const RATES: [SampleRate; 5] = [
    SampleRate::Narrowband,
    SampleRate::Mediumband,
    SampleRate::Wideband,
    SampleRate::SuperWideband,
    SampleRate::Fullband,
];

const DURATIONS: [FrameDuration; 6] = [
    FrameDuration::Micros2500,
    FrameDuration::Micros5000,
    FrameDuration::Micros10000,
    FrameDuration::Micros20000,
    FrameDuration::Micros40000,
    FrameDuration::Micros60000,
];

fuzz_target!(|data: &[u8]| {
    let Some((&rate_byte, rest)) = data.split_first() else {
        return;
    };
    let Some((&duration_byte, rest)) = rest.split_first() else {
        return;
    };
    let rate = RATES[usize::from(rate_byte) % RATES.len()];
    let frame = DURATIONS[usize::from(duration_byte) % DURATIONS.len()];
    let Ok(mut decoder) = Decoder::new(rate, frame) else {
        return;
    };

    let mut samples = vec![0_i16; frame.samples(rate)];
    let _ = decoder.decode(rest, &mut samples);
    let _ = decoder.recover(rest, &mut samples);
    let _ = decoder.samples_in(rest);

    let mut concealed = vec![0_i16; frame.samples(rate)];
    let _ = decoder.conceal(&mut concealed);
});
