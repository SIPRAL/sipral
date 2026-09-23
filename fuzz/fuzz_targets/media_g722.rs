// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Octets nobody's encoder produced, through
//! [`sipral_media::g722::Decoder::decode_into`] at each of the three modes,
//! and samples nobody's microphone produced through
//! [`sipral_media::g722::Encoder::encode_into`] and back through a decoder.
//!
//! Every bit pattern is a legal G.722 codeword -- there is no reserved value
//! either band's quantizer refuses -- so decoding never has an input to
//! reject, only one to turn into a reconstructed sample, and ITU-T G.722
//! S5.1 bounds every one of them the same way whatever produced the octet.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::g722::{Decoder, Encoder, Mode};

fuzz_target!(|data: &[u8]| {
    let Some((&mode_byte, rest)) = data.split_first() else {
        return;
    };
    let mode = match mode_byte % 3 {
        0 => Mode::Rate64,
        1 => Mode::Rate56,
        _ => Mode::Rate48,
    };

    let mut decoder = Decoder::new(mode);
    let mut samples = vec![0_i16; rest.len() * 2];
    let written = decoder.decode_into(rest, &mut samples);
    assert_eq!(written, rest.len() * 2);
    for sample in &samples[..written] {
        assert!((-16_384..=16_383).contains(sample), "S5.1's range");
    }

    let mut encoder = Encoder::new();
    let mut octets = vec![0_u8; samples.len() / 2];
    let re_encoded = encoder.encode_into(&samples[..written], &mut octets);
    assert_eq!(re_encoded, written / 2);

    let mut back = vec![0_i16; re_encoded * 2];
    let mut fresh = Decoder::new(mode);
    let round_tripped = fresh.decode_into(&octets[..re_encoded], &mut back);
    assert_eq!(round_tripped, re_encoded * 2);
    for sample in &back[..round_tripped] {
        assert!((-16_384..=16_383).contains(sample));
    }
});
