// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The ITU's Annex A conformance streams, decoded and compared sample for
//! sample with the reference output.
//!
//! The streams are not in this repository (the module above says why, and
//! how to run these). Each `.BIT` file is the ITU's serial test format, whose
//! layout the files themselves show: per frame, a synchronisation word
//! `0x6B21`, a length word of 80, then one sixteen-bit little-endian word per
//! bit, in the order of Table 8 and most significant bit first — `0x0081`
//! for a one and `0x007F` for a zero. A frame whose bit words are zero is a
//! frame that never arrived. Each `.PST` file is the decoder's expected
//! output, sixteen-bit little-endian samples.

use super::{Decoder, FRAME_OCTETS, FRAME_SAMPLES};
use std::path::PathBuf;

const SYNC: u16 = 0x6b21;
const ONE: u16 = 0x0081;
const ZERO: u16 = 0x007f;
const WORDS_PER_FRAME: usize = 2 + 8 * FRAME_OCTETS;

fn directory() -> PathBuf {
    std::env::var_os("SIPRAL_G729_VECTORS").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../intern/itu/g729-vectors/Software/G729_Release3")
        },
        PathBuf::from,
    )
}

fn words(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect()
}

/// A frame of the serial format as the ten octets RFC 3551 would carry, or
/// `None` for an erased frame.
fn frames(stream: &[u16]) -> Vec<Option<[u8; FRAME_OCTETS]>> {
    assert_eq!(
        stream.len() % WORDS_PER_FRAME,
        0,
        "a stream of whole frames"
    );
    stream
        .chunks_exact(WORDS_PER_FRAME)
        .map(|frame| {
            assert_eq!(frame[0], SYNC, "a frame without its synchronisation word");
            assert_eq!(
                usize::from(frame[1]),
                8 * FRAME_OCTETS,
                "a frame of eighty bits"
            );
            let bits = &frame[2..];
            if bits.iter().any(|word| *word != ONE && *word != ZERO) {
                assert!(bits.iter().all(|word| *word == 0), "a frame half erased");
                return None;
            }
            let mut octets = [0_u8; FRAME_OCTETS];
            for (position, word) in bits.iter().enumerate() {
                if *word == ONE {
                    octets[position / 8] |= 0x80 >> (position % 8);
                }
            }
            Some(octets)
        })
        .collect()
}

/// Decode `name` from the Annex A directory and compare it with its
/// reference output, saying where the first difference is.
fn check(name: &str, reference: &str) {
    let base = directory().join("g729AnnexA/test_vectors");
    let bitstream = std::fs::read(base.join(format!("{name}.BIT"))).unwrap_or_else(|error| {
        panic!(
            "{name}.BIT not found under {} ({error}); set SIPRAL_G729_VECTORS to the \
             G729_Release3 directory of the ITU's archive",
            base.display()
        )
    });
    let expected: Vec<i16> = words(&std::fs::read(base.join(reference)).unwrap())
        .into_iter()
        .map(|word| i16::from_ne_bytes(word.to_ne_bytes()))
        .collect();
    let stream = frames(&words(&bitstream));

    let mut decoder = Decoder::new();
    let mut ours = Vec::with_capacity(stream.len() * FRAME_SAMPLES);
    for frame in &stream {
        let samples = match frame {
            Some(octets) => decoder.decode(octets),
            None => decoder.conceal(),
        };
        ours.extend_from_slice(&samples);
    }
    assert_eq!(ours.len(), expected.len(), "{name}: length");

    let differing = ours.iter().zip(&expected).filter(|(a, b)| a != b).count();
    if let Some(first) = ours.iter().zip(&expected).position(|(a, b)| a != b) {
        let window: Vec<(i16, i16)> = ours
            .iter()
            .zip(&expected)
            .skip(first)
            .take(8)
            .map(|(a, b)| (*a, *b))
            .collect();
        panic!(
            "{name}: {differing} of {} samples differ, the first at frame {}, sample {}; \
             from there (ours, reference): {window:?}",
            expected.len(),
            first / FRAME_SAMPLES,
            first % FRAME_SAMPLES,
        );
    }
}

/// Every stream's frames read back as the file holds them: the reader
/// itself, checked on the one stream that carries erasures.
#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn the_erasure_stream_loses_the_frames_it_says() {
    let base = directory().join("g729AnnexA/test_vectors");
    let stream = frames(&words(&std::fs::read(base.join("ERASURE.BIT")).unwrap()));
    assert_eq!(stream.len(), 300);
    assert_eq!(stream.iter().filter(|frame| frame.is_none()).count(), 60);
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn algthm() {
    check("ALGTHM", "ALGTHM.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn erasure() {
    check("ERASURE", "ERASURE.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn fixed() {
    check("FIXED", "FIXED.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn lsp() {
    check("LSP", "LSP.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn overflow() {
    check("OVERFLOW", "OVERFLOW.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn parity() {
    check("PARITY", "PARITY.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn pitch() {
    check("PITCH", "PITCH.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn speech() {
    check("SPEECH", "SPEECH.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn tame() {
    check("TAME", "TAME.PST");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn test() {
    check("TEST", "TEST.pst");
}
