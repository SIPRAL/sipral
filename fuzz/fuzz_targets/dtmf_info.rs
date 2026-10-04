// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The `Content-Type` and body of an incoming INFO, through the DTMF parser
//! that answers a real one.
//!
//! `sipral_ua::dtmf::parse_info` is what an incoming INFO in a dialog is
//! read with (RFC 3261 §21.4.13 and §21.4.1 answer what it does not name a
//! digit for): a hostile peer controls both the header value and the body
//! whole, so both come from the fuzzed input rather than one of them being
//! fixed. The first byte is how many of the rest name the `Content-Type`,
//! capped at what is left; everything after that is the body. A byte count
//! of zero is `None` — no header at all — which is one of the ways a real
//! INFO can arrive malformed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_ua::dtmf::parse_info;

fuzz_target!(|data: &[u8]| {
    let Some((&len, rest)) = data.split_first() else {
        let _ = parse_info(None, &[]);
        return;
    };
    let take = usize::from(len).min(rest.len());
    let (content_type, body) = rest.split_at(take);
    let named = if content_type.is_empty() {
        None
    } else {
        Some(content_type)
    };
    let _ = parse_info(named, body);
});
