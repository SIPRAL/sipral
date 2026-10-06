// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! MD5 (RFC 1321).
//!
//! Not a choice: RFC 8489 §9.2.2 derives the long-term credential key as
//! `MD5(username ":" realm ":" password)`, and that key is the same H(A1) a
//! SIP registrar already stores, which is the whole reason STUN kept it. It
//! hashes a credential, never a message, and the SHA-256 password algorithm of
//! §18.5.1.2 replaces it wherever a server offers that instead.

use super::{Blocks, Digest};

/// The per-round additive constants, `floor(2^32 * abs(sin(i + 1)))` with the
/// angle in radians (§3.4).
const T: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// How far each round rotates left (§3.4).
const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// The state and the bytes not yet in a block.
pub(crate) struct Md5 {
    state: [u32; 4],
    blocks: Blocks,
}

impl Digest for Md5 {
    type Output = [u8; 16];

    fn start() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            blocks: Blocks::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let Self { state, blocks } = self;
        blocks.update(data, |block| compress(state, block));
    }

    fn finish(self) -> [u8; 16] {
        let Self {
            mut state,
            mut blocks,
        } = self;
        // MD5 writes its words and its length field low byte first, which is
        // the one place it parts company with the SHA family
        blocks.finish(|block| compress(&mut state, block), true);

        let mut digest = [0_u8; 16];
        for (chunk, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        digest
    }
}

#[expect(
    clippy::many_single_char_names,
    reason = "a through d and x are the specification's own names for the state and the block"
)]
fn compress(state: &mut [u32; 4], block: &[u8]) {
    let mut x = [0_u32; 16];
    for (word, chunk) in x.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }

    let [mut a, mut b, mut c, mut d] = *state;
    for (round, (constant, shift)) in T.iter().zip(SHIFTS).enumerate() {
        // each quarter has its own mixing function and its own way of walking
        // the sixteen words of the block
        let (mixed, index) = match round / 16 {
            0 => ((b & c) | (!b & d), round),
            1 => ((b & d) | (c & !d), (5 * round + 1) % 16),
            2 => (b ^ c ^ d, (3 * round + 5) % 16),
            _ => (c ^ (b | !d), (7 * round) % 16),
        };
        let sum = a
            .wrapping_add(mixed)
            .wrapping_add(*constant)
            .wrapping_add(*x.get(index).unwrap_or(&0));
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(sum.rotate_left(shift));
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::Md5;
    use crate::crypto::{Digest, hex};

    #[test]
    fn the_test_suite_from_the_specification_passes() {
        assert_eq!(hex(Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(Md5::digest(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(Md5::digest(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn the_long_term_key_example_from_rfc_8489_comes_out() {
        // "if the username is 'user', the realm is 'realm', and the password
        // is 'pass', then the 16-byte HMAC key would be [...]" (RFC 8489 9.2.2)
        assert_eq!(
            hex(Md5::digest(b"user:realm:pass")),
            "8493fbc53ba582fb4c044c456bdc40eb"
        );
    }

    #[test]
    fn the_lengths_around_the_padding_boundary_are_right() {
        for (length, expected) in [
            (55, "04364420e25c512fd958a70738aa8f72"),
            (56, "668a72d5ba17f08e62dabcafad6db14b"),
            (63, "7dc2ca208106a2f703567bdff99d8981"),
            (64, "c1bb4f81d892b2d57947682aeb252456"),
            (65, "1bc932052302d074bdec39795fe00cf6"),
        ] {
            assert_eq!(hex(Md5::digest(&vec![b'x'; length])), expected, "{length}");
        }
    }
}
