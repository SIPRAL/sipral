// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Any bytes at all, through [`sipral_media::comfort_noise::ComfortNoise`]'s
//! wire decoder and back out through its encoder, and through
//! [`sipral_media::comfort_noise::Generator`] once decoded.
//!
//! RFC 3389 puts nothing past a level byte and some reflection coefficients
//! on the wire, and this module's own decoder never refuses a payload past
//! the level byte -- an index it does not recognise decodes as no tilt, an
//! order past what it holds is truncated rather than rejected -- so almost
//! everything this target is given decodes to something, and what that
//! something has to do is round-trip and never make the generator panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::comfort_noise::{ComfortNoise, Generator};

fuzz_target!(|data: &[u8]| {
    let Ok(noise) = ComfortNoise::decode(data) else {
        return;
    };

    let mut wire = vec![0_u8; 1 + noise.order()];
    let Ok(written) = noise.encode_into(&mut wire) else {
        unreachable!("a buffer sized for exactly 1 + order was refused");
    };
    assert_eq!(written, wire.len());
    let back = ComfortNoise::decode(&wire).expect("what was just encoded decodes");
    assert_eq!(back, noise);

    let mut generator = Generator::new();
    generator.received(noise);
    let mut frame = [0_i16; 160];
    generator.fill(&mut frame);
});
