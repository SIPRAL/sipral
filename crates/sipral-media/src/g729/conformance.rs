// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The ITU's Annex A conformance streams: each input encoded and compared
//! bit for bit with the reference stream, and each stream decoded and
//! compared sample for sample with the reference output.
//!
//! The streams are not in this repository (the module above says why, and
//! how to run these). Each `.BIT` file is the ITU's serial test format, whose
//! layout the files themselves show: per frame, a synchronisation word
//! `0x6B21`, a length word of 80, then one sixteen-bit little-endian word per
//! bit, in the order of Table 8 and most significant bit first — `0x0081`
//! for a one and `0x007F` for a zero. A frame whose bit words are zero is a
//! frame that never arrived. Each `.IN` file is the encoder's input and each
//! `.PST` file the decoder's expected output, sixteen-bit little-endian
//! samples. Three streams — `ERASURE`, `OVERFLOW` and `PARITY` — come
//! without an input, so they test the decoder only.

use super::bits::Frame;
use super::{Decoder, Encoder, FRAME_OCTETS, FRAME_SAMPLES};
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

/// A file of sixteen-bit little-endian samples.
fn samples(bytes: &[u8]) -> Vec<i16> {
    bytes
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
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
    let expected = samples(&std::fs::read(base.join(reference)).unwrap());
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

/// Encode `name.IN` from the Annex A directory and compare every frame with
/// `name.BIT`, saying which frames and which of Table 8's fields differ.
fn check_encoder(name: &str) {
    let base = directory().join("g729AnnexA/test_vectors");
    let input = std::fs::read(base.join(format!("{name}.IN"))).unwrap_or_else(|error| {
        panic!(
            "{name}.IN not found under {} ({error}); set SIPRAL_G729_VECTORS to the \
             G729_Release3 directory of the ITU's archive",
            base.display()
        )
    });
    let input = samples(&input);
    let expected = frames(&words(
        &std::fs::read(base.join(format!("{name}.BIT"))).unwrap(),
    ));
    assert_eq!(
        input.len() / FRAME_SAMPLES,
        expected.len(),
        "{name}: one frame of bits for each whole frame of samples"
    );

    let mut encoder = Encoder::new();
    let mut differing = Vec::new();
    for (index, (chunk, reference)) in input.chunks_exact(FRAME_SAMPLES).zip(&expected).enumerate()
    {
        let frame: [i16; FRAME_SAMPLES] = chunk.try_into().unwrap();
        let ours = encoder.encode(&frame);
        let reference = reference.expect("an encoder's stream has no erasures");
        if ours != reference {
            differing.push((index, Frame::unpack(&ours), Frame::unpack(&reference)));
        }
    }
    if let Some((index, ours, reference)) = differing.first() {
        panic!(
            "{name}: {} of {} frames differ, the first at frame {index}:\n ours      {ours:?}\n \
             reference {reference:?}",
            differing.len(),
            expected.len(),
        );
    }
}

/// Both halves in a row: `SPEECH.IN` encoded, and what comes out decoded,
/// is the reference decoder's output for the reference encoder's stream.
#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn speech_through_encoder_and_decoder() {
    let base = directory().join("g729AnnexA/test_vectors");
    let input = samples(&std::fs::read(base.join("SPEECH.IN")).unwrap());
    let expected = samples(&std::fs::read(base.join("SPEECH.PST")).unwrap());
    let mut encoder = Encoder::new();
    let mut decoder = Decoder::new();
    let mut ours = Vec::with_capacity(expected.len());
    for chunk in input.chunks_exact(FRAME_SAMPLES) {
        let frame: [i16; FRAME_SAMPLES] = chunk.try_into().unwrap();
        ours.extend_from_slice(&decoder.decode(&encoder.encode(&frame)));
    }
    assert_eq!(ours.len(), expected.len());
    let differing = ours.iter().zip(&expected).filter(|(a, b)| a != b).count();
    assert_eq!(
        differing,
        0,
        "{differing} of {} samples differ",
        expected.len()
    );
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

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn encode_algthm() {
    check_encoder("ALGTHM");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn encode_fixed() {
    check_encoder("FIXED");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn encode_lsp() {
    check_encoder("LSP");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn encode_pitch() {
    check_encoder("PITCH");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn encode_speech() {
    check_encoder("SPEECH");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn encode_tame() {
    check_encoder("TAME");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn encode_test() {
    check_encoder("TEST");
}
