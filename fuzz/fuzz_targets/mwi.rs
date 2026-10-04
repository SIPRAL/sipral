// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the `application/simple-message-summary` reader.
//!
//! The body arrives over UDP from whatever answered a SUBSCRIBE to
//! `message-summary` (RFC 3842 §3.9), and `MessageSummary::parse` is the one
//! door into it. The guarantee under test is the usual one: no panic, on
//! anything, including the bounds this reader places on the document, the
//! line, the class name, the account and the message counts — see the
//! module's own doc comment for what each one is for.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_ua::MessageSummary;

fuzz_target!(|data: &[u8]| {
    if let Ok(summary) = MessageSummary::parse(data) {
        let _ = summary.waiting;
        let _ = &summary.account;
        for class in &summary.classes {
            let _ = class.name.clone();
            let _ = (class.new, class.old, class.new_urgent, class.old_urgent);
        }
        let _ = summary.voice_message();
    }
});
