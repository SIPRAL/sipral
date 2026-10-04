// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! mu-law, the PCMU of RFC 3551 §4.5.14.
//!
//! The bias is what turns the law into arithmetic instead of a table. Adding
//! 0x84 to the magnitude before anything else puts every value at 128 or
//! above, so the top set bit is never below bit 7 and the chord is nothing but
//! the position of that bit. The same constant is chord 0's floor plus half of
//! its step, which is what the decoder has to put back, so it comes off again
//! at the end of a decode.
//!
//! The octet is complemented on its way out. That is why silence travels as
//! 0xFF and the loudest negative sample as 0x00, and why the sign bit reads as
//! 1 for positive on the wire.

use super::{chord_of, step_of};

/// Added to the magnitude before the chord is read off it, and taken back off
/// once the decoder has rebuilt one. 0x80 of it is the floor of chord 0 and 4
/// of it is half of that chord's step.
const BIAS: i16 = 0x84;

/// The loudest magnitude the law carries. One louder would bias past 0x7FFF
/// and need a ninth chord, so everything above this shares the loudest code.
const CLIP: i16 = 32_635;

/// One linear sample as one mu-law octet.
#[must_use]
pub fn encode(sample: i16) -> u8 {
    // saturating, because -32768 has no positive twin; the clip then takes it
    // down to something the bias can be added to. The sum is positive by
    // construction, so unsigned_abs only reinterprets it.
    let magnitude = (sample.saturating_abs().min(CLIP) + BIAS).unsigned_abs();
    let chord = chord_of(magnitude);
    let step = step_of(magnitude, chord + 3);
    // set here for a negative sample and complemented away below, which leaves
    // the wire octet with its top bit set for positive
    let sign = if sample < 0 { 0x80 } else { 0x00 };
    !(sign | (chord << 4) | step)
}

/// One mu-law octet as one linear sample.
#[must_use]
pub fn decode(octet: u8) -> i16 {
    let code = !octet;
    let chord = (code >> 4) & 0x07;
    let step = i16::from(code & 0x0F);
    // the chord's floor, the step within it and half a step to land in the
    // middle of the interval rather than at its edge, all of which scale with
    // the chord and all of which the bias already carries
    let magnitude = (((step << 3) + BIAS) << chord) - BIAS;
    if code & 0x80 == 0 {
        magnitude
    } else {
        -magnitude
    }
}

#[cfg(test)]
mod tests {
    use super::{BIAS, CLIP, decode, encode};

    /// 0xFF, the idle code: positive, chord 0, step 0, which is the one value
    /// the law reads as no signal at all.
    const SILENCE: u8 = 0xFF;

    /// 0x7F: negative, chord 0, step 0. mu-law is mid-tread and has a code for
    /// zero on each side of it, so this decodes to the same zero as [`SILENCE`].
    const NEGATIVE_ZERO: u8 = 0x7F;

    #[test]
    fn every_octet_but_negative_zero_survives_a_decode_and_encode() {
        for octet in 0..=u8::MAX {
            let sample = decode(octet);
            // an i16 has one zero, so an encoder can only hand back one of the
            // two codes for it; every other octet is the only code its value has
            let expected = if octet == NEGATIVE_ZERO {
                SILENCE
            } else {
                octet
            };
            assert_eq!(encode(sample), expected, "{octet:#04x} decoded to {sample}");
        }
    }

    #[test]
    fn both_codes_for_zero_decode_to_zero() {
        assert_eq!(decode(SILENCE), 0);
        assert_eq!(decode(NEGATIVE_ZERO), 0);
        // and a zero sample takes the positive one, so a silent frame is 0xFF
        // repeated, which is what a carrier sends when there is nothing to say
        assert_eq!(encode(0), SILENCE);
    }

    #[test]
    fn the_octets_worked_out_by_hand() {
        // decode complements the octet, then reads sign, chord and step out of
        // it and evaluates (((step << 3) + 132) << chord) - 132
        //
        // 0xFE -> 0x01: positive, chord 0, step 1
        //         ((1 << 3) + 132) - 132 = 8
        assert_eq!(decode(0xFE), 8);
        // 0xFD -> 0x02: positive, chord 0, step 2
        //         ((2 << 3) + 132) - 132 = 16
        assert_eq!(decode(0xFD), 16);
        // 0xAB -> 0x54: positive, chord 5, step 4
        //         (164 << 5) - 132 = 5248 - 132 = 5116
        assert_eq!(decode(0xAB), 5_116);
        // 0x54 -> 0xAB: negative, chord 2, step 11
        //         -((220 << 2) - 132) = -(880 - 132) = -748
        assert_eq!(decode(0x54), -748);
        // 0x81 -> 0x7E: positive, chord 7, step 14
        //         (244 << 7) - 132 = 31232 - 132 = 31100
        assert_eq!(decode(0x81), 31_100);
    }

    #[test]
    fn the_full_scale_at_each_end() {
        // chord 7, step 15: (252 << 7) - 132, the loudest either way
        assert_eq!(decode(0x80), 32_124);
        assert_eq!(decode(0x00), -32_124);
        assert_eq!(encode(32_124), 0x80);
        assert_eq!(encode(-32_124), 0x00);
        assert_eq!(encode(i16::MAX), 0x80);
        assert_eq!(encode(i16::MIN), 0x00);
        // nothing the law can produce is louder than that
        for octet in 0..=u8::MAX {
            assert!(decode(octet).abs() <= 32_124, "{octet:#04x}");
        }
    }

    #[test]
    fn the_clip_and_the_boundary_before_it() {
        // 32635 + 0x84 is exactly 0x7FFF; one more would want a ninth chord
        assert_eq!(CLIP + BIAS, i16::MAX);
        for sample in [CLIP, CLIP + 1, 32_700, i16::MAX] {
            assert_eq!(encode(sample), 0x80, "{sample}");
            assert_eq!(encode(-sample), 0x00, "{sample}");
        }
        // the last step boundary the law actually resolves: biased 31744 is
        // 31 * 1024, the first value whose step field reads 15 in chord 7
        assert_eq!(encode(31_744 - BIAS), 0x80);
        assert_eq!(encode(31_744 - BIAS - 1), 0x81);
    }

    #[test]
    fn the_quiet_end_is_where_the_steps_are_smallest() {
        // chord 0 steps by 8, so the first four samples share a code and the
        // fifth starts the next one
        for sample in 0..=3 {
            assert_eq!(encode(sample), SILENCE, "{sample}");
        }
        assert_eq!(encode(4), 0xFE);
        assert_eq!(encode(11), 0xFE);
        assert_eq!(encode(12), 0xFD);
        // and the negatives mirror them onto the other side of the sign bit
        for sample in -3..=-1 {
            assert_eq!(encode(sample), NEGATIVE_ZERO, "{sample}");
        }
        assert_eq!(encode(-4), 0x7E);
    }
}
