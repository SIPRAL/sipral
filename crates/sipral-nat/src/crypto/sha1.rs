// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! SHA-1 (FIPS 180-4 §6.1; RFC 3174 states the same algorithm).
//!
//! It is here for one reason: MESSAGE-INTEGRITY is an HMAC-SHA1 and every STUN
//! server in the field speaks it. RFC 8489 added MESSAGE-INTEGRITY-SHA256
//! precisely because SHA-1 is no longer a hash anyone would choose, and this
//! stack prefers that attribute wherever the server offers a way to say so.

use super::{Blocks, Digest};

/// The state, the schedule and the bytes not yet in a block.
pub(crate) struct Sha1 {
    state: [u32; 5],
    blocks: Blocks,
}

impl Digest for Sha1 {
    type Output = [u8; 20];

    fn start() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            blocks: Blocks::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let Self { state, blocks } = self;
        blocks.update(data, |block| compress(state, block));
    }

    fn finish(self) -> [u8; 20] {
        let Self {
            mut state,
            mut blocks,
        } = self;
        blocks.finish(|block| compress(&mut state, block), false);

        let mut digest = [0_u8; 20];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

#[expect(
    clippy::many_single_char_names,
    reason = "a through e and w are the standard's own names, and this has to be readable against it"
)]
fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0_u32; 80];
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([
            *chunk.first().unwrap_or(&0),
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
            *chunk.get(3).unwrap_or(&0),
        ]);
    }
    for i in 16..80 {
        let mixed = w.get(i - 3).unwrap_or(&0)
            ^ w.get(i - 8).unwrap_or(&0)
            ^ w.get(i - 14).unwrap_or(&0)
            ^ w.get(i - 16).unwrap_or(&0);
        if let Some(word) = w.get_mut(i) {
            *word = mixed.rotate_left(1);
        }
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (round, word) in w.iter().enumerate() {
        // the four twenty-round stretches, each with its own function and constant
        let (mixed, constant) = match round / 20 {
            0 => ((b & c) | (!b & d), 0x5a82_7999),
            1 => (b ^ c ^ d, 0x6ed9_eba1),
            2 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(mixed)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::Sha1;
    use crate::crypto::{Digest, hex};

    #[test]
    fn the_published_digests_come_out() {
        assert_eq!(
            hex(Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex(Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn a_million_bytes_hash_the_same_as_the_standard_says() {
        assert_eq!(
            hex(Sha1::digest(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn feeding_it_in_pieces_changes_nothing() {
        let message: Vec<u8> = (0..=255_u8).cycle().take(1000).collect();
        let whole = Sha1::digest(&message);

        for split in [0, 1, 55, 56, 63, 64, 65, 128, 999, 1000] {
            let mut hash = Sha1::start();
            hash.update(&message[..split]);
            hash.update(&message[split..]);
            assert_eq!(hash.finish(), whole, "split at {split}");
        }
    }

    #[test]
    fn the_lengths_around_the_padding_boundary_are_right() {
        // 55 bytes leaves room for the terminator and the length, 56 does not
        // and spills into a second block
        for (length, expected) in [
            (55, "cef734ba81a024479e09eb5a75b6ddae62e6abf1"),
            (56, "901305367c259952f4e7af8323f480d59f81335b"),
            (63, "0ddc4e0cccd9a12850deb5abb0853a4425559fec"),
            (64, "bb2fa3ee7afb9f54c6dfb5d021f14b1ffe40c163"),
            (65, "78c741ddc482e4cdf8c474a0876347a0905b6233"),
        ] {
            assert_eq!(hex(Sha1::digest(&vec![b'x'; length])), expected, "{length}");
        }
    }
}
