// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
use super::{Decoder, Encoded, Encoder, FRAME_OCTETS, FRAME_SAMPLES, Sid};
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
        let ours = encoder.encode(&frame).speech().expect("no DTX, so speech");
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

/// One frame of an Annex B stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Received {
    Speech([u8; FRAME_OCTETS]),
    Sid(Sid),
    Untransmitted,
    Lost,
}

/// Annex B's serial format, which the streams themselves show: after the
/// synchronisation word — `0x6B21`, or `0x6B20` for a frame lost on the
/// way — the length word says how many bit words follow: eighty for speech,
/// sixteen for a SID frame (its fifteen bits and the reserved one), none
/// for a frame not sent. As in the Annex A streams, a frame whose bit words
/// are all zero was lost too.
fn annex_b_frames(stream: &[u16]) -> Vec<Received> {
    const LOST: u16 = 0x6b20;
    let mut frames = Vec::new();
    let mut rest = stream;
    while let [sync, length, tail @ ..] = rest {
        let length = usize::from(*length);
        let (bits, after) = tail.split_at(length);
        rest = after;
        assert!(
            *sync == SYNC || *sync == LOST,
            "a frame without its sync word"
        );
        if *sync == LOST || (length > 0 && bits.iter().all(|word| *word == 0)) {
            frames.push(Received::Lost);
            continue;
        }
        let mut octets = [0_u8; FRAME_OCTETS];
        for (position, word) in bits.iter().enumerate() {
            assert!(*word == ONE || *word == ZERO, "a bit word");
            if *word == ONE {
                octets[position / 8] |= 0x80 >> (position % 8);
            }
        }
        frames.push(match length {
            80 => Received::Speech(octets),
            16 => Received::Sid(Sid::from_octets([octets[0], octets[1]])),
            0 => Received::Untransmitted,
            other => panic!("a frame of {other} bits"),
        });
    }
    frames
}

fn annex_b_directory() -> PathBuf {
    directory().join("g729AnnexB/test_vectors")
}

fn read(name: &str) -> Vec<u8> {
    let path = annex_b_directory().join(name);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{} not found ({error}); set SIPRAL_G729_VECTORS to the G729_Release3 directory \
             of the ITU's archive",
            path.display()
        )
    })
}

/// Decode an Annex B stream and compare it with its reference output.
fn check_annex_b(bitstream: &str, reference: &str) {
    let stream = annex_b_frames(&words(&read(bitstream)));
    let expected = samples(&read(reference));
    let mut decoder = Decoder::new();
    let mut ours = Vec::with_capacity(expected.len());
    for frame in &stream {
        let samples = match frame {
            Received::Speech(octets) => decoder.decode(octets),
            Received::Sid(sid) => decoder.decode_sid(*sid),
            Received::Untransmitted => decoder.untransmitted(),
            Received::Lost => decoder.conceal(),
        };
        ours.extend_from_slice(&samples);
    }
    assert_eq!(ours.len(), expected.len(), "{bitstream}: length");
    let differing = ours.iter().zip(&expected).filter(|(a, b)| a != b).count();
    if let Some(first) = ours.iter().zip(&expected).position(|(a, b)| a != b) {
        let frame = first / FRAME_SAMPLES;
        let kinds: Vec<_> = stream
            .iter()
            .skip(frame.saturating_sub(3))
            .take(5)
            .collect();
        let window: Vec<(i16, i16)> = ours
            .iter()
            .zip(&expected)
            .skip(first)
            .take(8)
            .map(|(a, b)| (*a, *b))
            .collect();
        panic!(
            "{bitstream}: {differing} of {} samples differ, the first at frame {frame}, sample \
             {}; frames around it {kinds:?}; from there (ours, reference): {window:?}",
            expected.len(),
            first % FRAME_SAMPLES,
        );
    }
}

/// Encode an Annex B input with DTX on and compare every frame — its type
/// and its bits — with the reference stream.
fn check_annex_b_encoder(input: &str, reference: &str) {
    let input = samples(&read(input));
    let expected = annex_b_frames(&words(&read(reference)));
    assert_eq!(
        input.len() / FRAME_SAMPLES,
        expected.len(),
        "{reference}: one frame for each whole frame of samples"
    );
    let mut encoder = Encoder::with_dtx();
    let mut differing = Vec::new();
    for (index, (chunk, reference)) in input.chunks_exact(FRAME_SAMPLES).zip(&expected).enumerate()
    {
        let frame: [i16; FRAME_SAMPLES] = chunk.try_into().unwrap();
        let ours = match encoder.encode(&frame) {
            Encoded::Speech(octets) => Received::Speech(octets),
            Encoded::Sid(sid) => Received::Sid(sid),
            Encoded::Nothing => Received::Untransmitted,
        };
        if ours != *reference {
            differing.push((index, ours, *reference));
        }
    }
    if let Some((index, ours, reference)) = differing.first() {
        panic!(
            "{input:?}: {} of {} frames differ, the first at frame {index}:\n ours      \
             {ours:?}\n reference {reference:?}",
            differing.len(),
            expected.len(),
            input = reference,
        );
    }
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_decode_1() {
    check_annex_b("tstseq1a.bit", "tstseq1a.out");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_decode_2() {
    check_annex_b("tstseq2a.bit", "tstseq2a.out");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_decode_3() {
    check_annex_b("tstseq3a.bit", "tstseq3a.out");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_decode_4() {
    check_annex_b("tstseq4a.bit", "tstseq4a.out");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_decode_5() {
    check_annex_b("tstseq5.bit", "tstseq5a.out");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_decode_6() {
    check_annex_b("tstseq6.bit", "tstseq6a.out");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_encode_1() {
    check_annex_b_encoder("tstseq1.bin", "tstseq1a.bit");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_encode_2() {
    check_annex_b_encoder("tstseq2.bin", "tstseq2a.bit");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_encode_3() {
    check_annex_b_encoder("tstseq3.bin", "tstseq3a.bit");
}

#[test]
#[ignore = "needs the ITU conformance streams; see the module documentation"]
fn annex_b_encode_4() {
    check_annex_b_encoder("tstseq4.bin", "tstseq4a.bit");
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
        let octets = encoder.encode(&frame).speech().expect("no DTX, so speech");
        ours.extend_from_slice(&decoder.decode(&octets));
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
