// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the replay reader.
//!
//! A recording file is a text format a person can hand-edit, mail as an
//! attachment or paste into a ticket, and `Recording::parse` is the only door
//! into it. Nothing upstream of this crate checks the bytes first, so the
//! reader has to survive whatever comes back the same way every other parser
//! of external input does: no panic, on anything.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::replay::Recording;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(recording) = Recording::parse(text) else {
        return;
    };

    let _ = recording.note();
    let _ = recording.duration();
    for frame in recording.frames() {
        let _ = frame.at;
        let _ = &frame.step;
    }

    // a recording that reads has to write back out and read the same again
    let written = recording.to_text();
    let again = Recording::parse(&written).expect("what was written out has to read back in");
    assert_eq!(recording, again, "writing a recording changed it");
});
