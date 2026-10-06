// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! SHA-256 (FIPS 180-4 §6.2), for MESSAGE-INTEGRITY-SHA256 and for the SHA-256
//! password algorithm of RFC 8489 §18.5.1.2.
//!
//! `sipral-core` also hashes with SHA-256, for RFC 8760 digest. That copy is
//! private to the crate that owns it and this crate depends on nothing, so the
//! algorithm is written out a second time rather than a dependency edge being
//! drawn between signalling and media for sixty lines of arithmetic.

use super::{Blocks, Digest};

/// The first thirty-two bits of the fractional part of the cube roots of the
/// first sixty-four primes (§4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The state and the bytes not yet in a block.
pub(crate) struct Sha256 {
    state: [u32; 8],
    blocks: Blocks,
}

impl Digest for Sha256 {
    type Output = [u8; 32];

    fn start() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            blocks: Blocks::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let Self { state, blocks } = self;
        blocks.update(data, |block| compress(state, block));
    }

    fn finish(self) -> [u8; 32] {
        let Self {
            mut state,
            mut blocks,
        } = self;
        blocks.finish(|block| compress(&mut state, block), false);

        let mut digest = [0_u8; 32];
        for (chunk, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

#[expect(
    clippy::many_single_char_names,
    reason = "a through h and w are the standard's own names, and this has to be readable against it"
)]
fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0_u32; 64];
    for (word, chunk) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*chunk);
    }
    for i in 16..64 {
        let near = *w.get(i - 15).unwrap_or(&0);
        let far = *w.get(i - 2).unwrap_or(&0);
        let low = near.rotate_right(7) ^ near.rotate_right(18) ^ (near >> 3);
        let high = far.rotate_right(17) ^ far.rotate_right(19) ^ (far >> 10);
        let next = w
            .get(i - 16)
            .unwrap_or(&0)
            .wrapping_add(low)
            .wrapping_add(*w.get(i - 7).unwrap_or(&0))
            .wrapping_add(high);
        if let Some(word) = w.get_mut(i) {
            *word = next;
        }
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (word, constant) in w.iter().zip(K) {
        let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ (!e & g);
        let first = h
            .wrapping_add(sigma1)
            .wrapping_add(choice)
            .wrapping_add(constant)
            .wrapping_add(*word);
        let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let second = sigma0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256;
    use crate::crypto::{Digest, hex};

    #[test]
    fn the_published_digests_come_out() {
        assert_eq!(
            hex(Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(Sha256::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn the_lengths_around_the_padding_boundary_are_right() {
        for (length, expected) in [
            (
                55,
                "d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072",
            ),
            (
                56,
                "04c26261370ee7541549d16dee320c723e3fd14671e66a099afe0a377c16888e",
            ),
            (
                64,
                "7ce100971f64e7001e8fe5a51973ecdfe1ced42befe7ee8d5fd6219506b5393c",
            ),
            (
                65,
                "9537c5fdf120482f7d58d25e9ed583f52c02b4e304ea814db1633ad565aed7e9",
            ),
        ] {
            assert_eq!(
                hex(Sha256::digest(&vec![b'x'; length])),
                expected,
                "{length}"
            );
        }
    }

    #[test]
    fn feeding_it_in_pieces_changes_nothing() {
        let message: Vec<u8> = (0..=255_u8).cycle().take(700).collect();
        let whole = Sha256::digest(&message);

        for split in [0, 1, 55, 56, 64, 65, 128, 699, 700] {
            let mut hash = Sha256::start();
            hash.update(&message[..split]);
            hash.update(&message[split..]);
            assert_eq!(hash.finish(), whole, "split at {split}");
        }
    }
}
