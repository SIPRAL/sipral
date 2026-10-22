// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the `application/trickle-ice-sdpfrag` reader.
//!
//! The body arrives in an INFO request from whoever holds the call's dialog
//! (RFC 8840 §9), so in practice from anybody a proxy lets through, and
//! `SdpFrag::parse` is the one door into it. Beyond the usual guarantee — no
//! panic, on anything, including the bounds on body size, sections and
//! candidate lines — a body that reads is written back the way this end
//! writes its own, and that has to read as the same body: the writer is what
//! every trickled candidate of this end goes through, and a body it cannot
//! read back is one the far end's reader may not either.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_nat::ice::{MAX_SDPFRAG, SdpFrag};

fuzz_target!(|data: &[u8]| {
    let Ok(frag) = SdpFrag::parse(data) else {
        return;
    };
    let mids: Vec<Option<String>> = frag
        .sections
        .iter()
        .map(|section| section.mid.clone())
        .chain([None])
        .collect();
    for mid in &mids {
        let mid = mid.as_deref();
        let _ = frag.credentials_for(mid);
        let _ = frag.ended(mid);
        let known = frag.section(mid).map(|section| section.candidates.clone());
        let fresh = frag.new_candidates(mid, known.as_deref().unwrap_or_default());
        assert!(fresh.is_empty(), "a section's own candidates are new to it");
    }
    let written = frag.write();
    if written.len() > MAX_SDPFRAG {
        // short candidate lines written out in full can outgrow the bound
        return;
    }
    let again = SdpFrag::parse(written.as_bytes()).expect("a body this end wrote reads");
    assert_eq!(again, frag, "a body written back reads as itself");
});
