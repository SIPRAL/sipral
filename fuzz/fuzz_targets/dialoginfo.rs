// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the `application/dialog-info+xml` reader.
//!
//! The body arrives over UDP from whatever answered a SUBSCRIBE (§4 of RFC
//! 4235), and `DialogInfo::parse` is the one door into it -- a hand-rolled
//! reader that deliberately refuses everything a general XML parser would
//! accept, per the module's own doc comment. The guarantee under test is the
//! usual one: no panic, on anything, including the bounds this reader places
//! on nesting, element count, attribute count and value length.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_ua::DialogInfo;

fuzz_target!(|data: &[u8]| {
    if let Ok(document) = DialogInfo::parse(data) {
        let _ = document.version;
        let _ = document.full;
        let _ = &document.entity;
        for dialog in &document.dialogs {
            let _ = dialog.phase;
            let _ = dialog.id.clone();
        }
    }
});
