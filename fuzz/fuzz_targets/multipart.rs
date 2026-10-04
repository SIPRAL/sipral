// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the multipart body reader (RFC 5621, RFC 2046
//! §5.1).
//!
//! The first line of the input is the `Content-Type` value and the rest is
//! the body, so the boundary is fuzzed along with what it has to split; a
//! first line that is not a media type falls back to a fixed
//! `multipart/mixed` one, so the body is still read. Beyond "no panic, on
//! anything", two things are checked on every body that reads: every part
//! lies inside the input, and the leaf parts, written again with the builder,
//! read back with the same content, since the builder's boundary is chosen
//! to occur in none of them. A part that claims to be recording metadata is
//! read too, as a recording session's INVITE would read it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::msg::{
    BodyPart, MediaTypeRef, Multipart, MultipartBuilder, MultipartKind, MultipartLimits, Part,
};
use sipral_ua::siprec::RecordingMetadata;

const FALLBACK: &[u8] = b"multipart/mixed;boundary=b";

fuzz_target!(|data: &[u8]| {
    let (first, body) = match data.iter().position(|byte| *byte == b'\n') {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (FALLBACK, data),
    };
    let content_type = match MediaTypeRef::parse(first) {
        Ok(media) => media,
        Err(_) => match MediaTypeRef::parse(FALLBACK) {
            Ok(media) => media,
            Err(_) => return,
        },
    };
    let Ok(multipart) = Multipart::parse(&content_type, body) else {
        return;
    };
    let range = body.as_ptr_range();
    let mut leaves: Vec<&BodyPart<'_>> = Vec::new();
    walk(&multipart, &mut leaves);
    for part in &leaves {
        let inside = part.body().as_ptr_range();
        assert!(range.start <= inside.start && inside.end <= range.end);
        let _ = part.header("content-type");
        if part.is("application", "rs-metadata+xml") {
            let _ = RecordingMetadata::parse(part.body());
        }
    }
    let _ = multipart.check(|part| part.is("application", "sdp"));
    let _ = multipart.preferred(|part| part.is("text", "plain"));
    let _ = multipart.find("application", "sdp");
    let _ = multipart.by_content_id(b"x");
    if matches!(multipart.kind(), MultipartKind::Other(_)) {
        return;
    }

    let types: Vec<String> = leaves
        .iter()
        .map(|part| {
            part.content_type()
                .map_or_else(|| "text/plain".to_owned(), |media| media.to_string())
        })
        .collect();
    let mut builder = MultipartBuilder::mixed();
    for (part, kind) in leaves.iter().zip(&types) {
        builder = builder.part(Part::new(kind, part.body()));
    }
    // a type the reader took may still be one the builder will not write,
    // and that is a refusal, not a finding
    let Ok(built) = builder.build() else {
        return;
    };
    let rebuilt_type =
        MediaTypeRef::parse(built.content_type().as_bytes()).expect("the builder's own type");
    // the rewrite gives every part a Content-Type line and a longer boundary,
    // so a body read just under the byte bound can come back over it
    let rebuilt_limits = MultipartLimits {
        max_bytes: usize::MAX,
        ..MultipartLimits::DEFAULT
    };
    let reread = Multipart::parse_with_limits(&rebuilt_type, built.body(), rebuilt_limits)
        .expect("the builder's own body");
    assert_eq!(reread.parts().len(), leaves.len());
    for (again, part) in reread.parts().iter().zip(&leaves) {
        assert_eq!(again.body(), part.body());
    }
});

fn walk<'s, 'a>(multipart: &'s Multipart<'a>, leaves: &mut Vec<&'s BodyPart<'a>>) {
    for part in multipart.parts() {
        match part.nested() {
            Some(nested) => walk(nested, leaves),
            None => leaves.push(part),
        }
    }
}
