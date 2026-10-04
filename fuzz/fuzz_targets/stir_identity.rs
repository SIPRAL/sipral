// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A hostile Identity header field and a hostile certificate chain, through
//! the whole of STIR verification.
//!
//! Both halves come from outside: the header field arrives in a request from
//! anyone who can reach the SIP port, and the chain from whatever server its
//! `info` parameter names, which the same sender chose. So everything
//! `sipral-stir` reads is under test here and none of it may panic: the
//! header field's grammar, base64url, the PASSporT's JSON, PEM, DER, X.509,
//! the TNAuthList extension and the path built from the chain.
//!
//! The input is the header field, a zero octet, then the chain. The chain is
//! also offered as the trust anchors, so a run that finds a certificate
//! issuing itself or another gets past path building and into the checks
//! beyond it, which an empty set of anchors would never reach. A compact
//! form is rebuilt from fixed claims, so the signature check is reached for
//! it too.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_stir::{
    Attest, Claims, Dest, Identity, OrigId, Shaken, Tn, TnAuthList, TrustAnchors, Verifier,
};

/// The time every chain is checked at: 2026-09-21.
const NOW: u64 = 1_790_000_000;

fn from_request() -> Option<Claims> {
    Some(Claims {
        orig: Tn::new("12155551212").ok()?,
        dest: Dest::tn(Tn::new("12125551213").ok()?),
        iat: NOW,
        shaken: Some(Shaken {
            attest: Attest::A,
            origid: OrigId::from_bytes([0x5a; 16]),
        }),
    })
}

fuzz_target!(|data: &[u8]| {
    let (header, chain) = match data.iter().position(|&b| b == 0) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &[][..]),
    };
    let header = String::from_utf8_lossy(header);

    let _ = Identity::parse(&header);
    let _ = TnAuthList::from_der(chain);
    let mut anchors = TrustAnchors::new();
    let _ = anchors.add(chain);

    let claims = from_request();
    if let Ok(pending) = Verifier::default().start(&header, claims.as_ref()) {
        let _ = pending.certificate_url();
        let verdict = pending.verify(chain, &anchors, NOW);
        let _ = verdict.verstat();
        let _ = verdict.sip_response();
        let _ = pending.verify(chain, &TrustAnchors::new(), NOW);
    }
});
