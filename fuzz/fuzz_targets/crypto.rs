// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! An `a=crypto` line's value, through the parser and the policy reader.
//!
//! `Crypto::parse` runs on whatever text sat after `a=crypto:` in an offer or
//! an answer, and `policy()` goes further and decodes the base64 key material
//! inside it — both on bytes a peer chose, both never reached by the `sdp`
//! target since `sipral_core::sdp::parse` does not itself call into this
//! module. No input reaches a panic, and a line that parses and is written
//! back reads the same way again.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::sdp::Crypto;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Some(line) = Crypto::parse(text) else {
        return;
    };

    // the policy reader is the one that decodes key material and session
    // parameters; it must never panic on a line the syntax parser accepted
    let _ = line.policy();

    let written = line.to_value();
    let again = Crypto::parse(&written).expect("what this parser wrote has to read back in");
    assert_eq!(line, again, "writing a crypto line changed it");
});
