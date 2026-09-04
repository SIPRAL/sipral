// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Arbitrary bytes as header values, through the builder.
//!
//! The guarantee under test is that a caller's data cannot become structure.
//! Whatever goes in, the builder either refuses it or produces bytes that
//! parse back into the same fields — never a message with an extra header in
//! it, and never one the far end would reject.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::msg::{
    HeaderName, Method, ParseMode, ParseScratch, RequestBuilder, ResponseBuilder, StatusCode, parse,
};

fuzz_target!(|data: &[u8]| {
    // five slices of the input, used as the values a caller controls
    let step = data.len() / 5 + 1;
    let mut parts = data.chunks(step);
    let mut next = || parts.next().unwrap_or_default();
    let (uri, from, to, call_id, extra) = (next(), next(), next(), next(), next());

    let built = RequestBuilder::new(Method::Invite, uri)
        .via(b"SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1")
        .max_forwards(70)
        .from(from)
        .to(to)
        .call_id(call_id)
        .cseq(1)
        .header(HeaderName::Subject, extra)
        .body(b"application/sdp", data)
        .build();

    if let Ok(message) = built {
        let bytes = message.as_raw().as_bytes().to_vec();
        let mut scratch = ParseScratch::new();
        let reparsed = parse(&bytes, &mut scratch, ParseMode::Strict)
            .expect("the builder checks this itself before returning");

        // nothing the caller passed became a header of its own
        assert_eq!(reparsed.header_slots().len(), 9);
        assert_eq!(reparsed.method(), Some(Method::Invite));
        assert_eq!(reparsed.request_uri_bytes(), Some(uri));
        assert_eq!(reparsed.body(), data);

        let response = ResponseBuilder::for_request(&reparsed, StatusCode::OK)
            .to_tag(b"a6c85cf")
            .build();
        if let Ok(response) = response {
            let mut scratch = ParseScratch::new();
            parse(
                response.as_raw().as_bytes(),
                &mut scratch,
                ParseMode::Strict,
            )
            .expect("a response the builder accepted parses");
        }
    }
});
