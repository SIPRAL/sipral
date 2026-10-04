// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A-law, the PCMA of RFC 3551 §4.5.14.
//!
//! Same sign, chord and step as mu-law, with two differences that matter.
//!
//! The first two chords share one step of 16, so the curve runs straight
//! through the origin instead of bending there, and there is no code for zero
//! at all: the quietest sample either way is 8. That is why A-law needs no
//! bias — nothing has to be pushed up into chord 0, because chord 0 already
//! starts at the bottom.
//!
//! And every other bit of the octet is inverted with 0x55 before it goes on
//! the wire. A quiet line would otherwise send 0x80 over and over, and a
//! receiver recovering its clock out of the signal has almost no transitions
//! to lock onto in that. Inverted it becomes 0xD5, which is full of them.

use super::{chord_of, step_of};

/// The loudest magnitude the law carries. As loud as an i16 goes, so the only
/// sample the clip touches is -32768, which has no positive twin.
const CLIP: u16 = 32_767;

/// One linear sample as one A-law octet.
#[must_use]
pub fn encode(sample: i16) -> u8 {
    let magnitude = sample.unsigned_abs().min(CLIP);
    let chord = chord_of(magnitude);
    // chords 0 and 1 step by the same 16, so the first one reads its step four
    // bits up like the second rather than three
    let step = step_of(magnitude, if chord == 0 { 4 } else { chord + 3 });
    let sign = if sample < 0 { 0x00 } else { 0x80 };
    (sign | (chord << 4) | step) ^ 0x55
}

/// One A-law octet as one linear sample.
#[must_use]
pub fn decode(octet: u8) -> i16 {
    let code = octet ^ 0x55;
    let chord = (code >> 4) & 0x07;
    let step = i16::from(code & 0x0F);
    let magnitude = if chord == 0 {
        // sixteen steps of 16 up from nothing, read back at the middle of each
        (step << 4) + 8
    } else {
        // 0x108 is the chord's floor of 0x100 plus half a step, both of which
        // the chord number then doubles
        ((step << 4) + 0x108) << (chord - 1)
    };
    if code & 0x80 == 0 {
        -magnitude
    } else {
        magnitude
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    /// 0xD5, the idle code: positive, chord 0, step 0. The quietest thing the
    /// law can say, which is 8 and not 0.
    const SILENCE: u8 = 0xD5;

    #[test]
    fn every_octet_survives_a_decode_and_encode() {
        for octet in 0..=u8::MAX {
            let sample = decode(octet);
            assert_eq!(encode(sample), octet, "{octet:#04x} decoded to {sample}");
        }
    }

    #[test]
    fn the_law_has_no_code_for_zero() {
        // mid-riser: the two quietest codes straddle the origin instead of
        // sitting on it, so silence is carried as the smallest positive step
        for octet in 0..=u8::MAX {
            assert_ne!(decode(octet), 0, "{octet:#04x}");
        }
        assert_eq!(decode(SILENCE), 8);
        assert_eq!(decode(0x55), -8);
        assert_eq!(encode(0), SILENCE);
        assert_eq!(encode(-1), 0x55);
    }

    #[test]
    fn the_octets_worked_out_by_hand() {
        // decode inverts the alternate bits, then reads sign, chord and step
        // and evaluates (step << 4) + 8 in chord 0 and
        // ((step << 4) + 0x108) << (chord - 1) above it
        //
        // 0xD4 ^ 0x55 -> 0x81: positive, chord 0, step 1
        //                (1 << 4) + 8 = 24
        assert_eq!(decode(0xD4), 24);
        // 0xFF ^ 0x55 -> 0xAA: positive, chord 2, step 10
        //                ((10 << 4) + 264) << 1 = 424 * 2 = 848
        assert_eq!(decode(0xFF), 848);
        // 0x00 ^ 0x55 -> 0x55: negative, chord 5, step 5
        //                -(((5 << 4) + 264) << 4) = -(344 * 16) = -5504
        assert_eq!(decode(0x00), -5_504);
        // 0xC5 ^ 0x55 -> 0x90: positive, chord 1, step 0
        //                ((0 << 4) + 264) << 0 = 264
        assert_eq!(decode(0xC5), 264);
    }

    #[test]
    fn the_full_scale_at_each_end() {
        // chord 7, step 15: (504 << 6), the loudest either way
        assert_eq!(decode(0xAA), 32_256);
        assert_eq!(decode(0x2A), -32_256);
        assert_eq!(encode(32_256), 0xAA);
        assert_eq!(encode(-32_256), 0x2A);
        assert_eq!(encode(i16::MAX), 0xAA);
        for octet in 0..=u8::MAX {
            assert!(decode(octet).abs() <= 32_256, "{octet:#04x}");
        }
    }

    #[test]
    fn the_clip_only_bites_the_sample_with_no_positive_twin() {
        // |-32768| is 32769 wide and the law stops at 32767, so it saturates
        // onto the same code as the loudest negative sample that does fit
        assert_eq!(encode(i16::MIN), encode(-i16::MAX));
        assert_eq!(encode(i16::MIN), 0x2A);
        // and every other sample is inside the law, so the two sides mirror
        for sample in [1_i16, 8, 255, 256, 1_000, 16_383, 16_384, i16::MAX] {
            assert_eq!(decode(encode(sample)), -decode(encode(-sample)), "{sample}");
        }
    }

    #[test]
    fn the_first_two_chords_share_one_step() {
        // the positive codes of chords 0 and 1 are 0x80..=0x9F before the
        // inversion, and they decode to one straight ladder of 16 from 8 to 504
        for n in 0..32_u8 {
            let octet = (0x80 + n) ^ 0x55;
            assert_eq!(decode(octet), 8 + 16 * i16::from(n), "step {n}");
        }
        // chord 2 is where the doubling starts: 528, 560, and 32 apart after
        assert_eq!(decode(0xA0 ^ 0x55), 528);
        assert_eq!(decode(0xA1 ^ 0x55), 560);
    }

    #[test]
    fn the_chord_boundaries_land_where_the_segmentation_says() {
        // chord 0 holds everything below 256, chord n from 2^(n+7) up
        assert_eq!(encode(255), 0xDA);
        assert_eq!(decode(0xDA), 248);
        assert_eq!(encode(256), 0xC5);
        assert_eq!(decode(0xC5), 264);
        // and the top chord opens at 16384
        assert_eq!(encode(16_383), encode(16_000));
        assert_ne!(encode(16_384), encode(16_383));
    }
}
