// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! SHA-1 (FIPS 180-4 §6.1), for reading a `sha-1` certificate fingerprint.
//!
//! Only ever applied to a certificate the peer has already sent in the clear,
//! so it handles nothing secret and has no reason to be constant-time; and
//! RFC 8122 §5 still names it, so a peer that offers only a SHA-1 fingerprint
//! is not refused for it. Written here rather than taken as one more
//! dependency, like the copies in `sipral-rtp` and `sipral-nat`, which are
//! private to crates this one does not depend on.

/// Octets in a SHA-1 digest.
pub(crate) const DIGEST_LEN: usize = 20;

const INITIAL: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// The SHA-1 digest of `message`.
pub(crate) fn digest(message: &[u8]) -> [u8; DIGEST_LEN] {
    // pad with a one bit, zeros up to 56 octets past a multiple of 64, and
    // the message length in bits as a 64-bit big-endian integer (§5.1.1)
    let bits = (message.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(message.len() + 72);
    padded.extend_from_slice(message);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bits.to_be_bytes());

    let mut state = INITIAL;
    let (blocks, _) = padded.as_chunks::<64>();
    for block in blocks {
        compress(&mut state, block);
    }

    let mut out = [0u8; DIGEST_LEN];
    for (slot, byte) in out
        .iter_mut()
        .zip(state.iter().flat_map(|word| word.to_be_bytes()))
    {
        *slot = byte;
    }
    out
}

/// One block of §6.1.2.
///
/// The message schedule is kept sixteen words at a time rather than as all
/// eighty: `window` always holds W(t) through W(t+15), so round t reads
/// `window[0]` and appends W(t+16) = ROTL1(W(t+13) ^ W(t+8) ^ W(t+2) ^ W(t)).
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut window = [0u32; 16];
    let (words, _) = block.as_chunks::<4>();
    for (slot, word) in window.iter_mut().zip(words) {
        *slot = u32::from_be_bytes(*word);
    }

    // the five working variables §6.1.2 calls a, b, c, d and e
    let [mut va, mut vb, mut vc, mut vd, mut ve] = *state;
    for t in 0..80 {
        // Ch, Parity, Maj, Parity (§4.1.1), and the round constant K(t)
        let (mixed, constant) = match t {
            0..=19 => ((vb & vc) | (!vb & vd), 0x5A82_7999),
            20..=39 => (vb ^ vc ^ vd, 0x6ED9_EBA1),
            40..=59 => ((vb & vc) | (vb & vd) | (vc & vd), 0x8F1B_BCDC),
            _ => (vb ^ vc ^ vd, 0xCA62_C1D6),
        };
        let temp = va
            .rotate_left(5)
            .wrapping_add(mixed)
            .wrapping_add(ve)
            .wrapping_add(constant)
            .wrapping_add(window[0]);
        ve = vd;
        vd = vc;
        vc = vb.rotate_left(30);
        vb = va;
        va = temp;

        let next = (window[13] ^ window[8] ^ window[2] ^ window[0]).rotate_left(1);
        window.rotate_left(1);
        window[15] = next;
    }

    for (word, add) in state.iter_mut().zip([va, vb, vc, vd, ve]) {
        *word = word.wrapping_add(add);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").unwrap();
            out
        })
    }

    #[test]
    fn the_fips_180_examples() {
        assert_eq!(
            hex(&digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(&digest(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn lengths_on_either_side_of_the_padding_boundary() {
        // each checked against `shasum -a 1`
        let cases = [
            (0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
            (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
            (63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
            (64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
            (65, "11655326c708d70319be2610e8a57d9a5b959d3b"),
        ];
        for (len, expected) in cases {
            assert_eq!(hex(&digest(&vec![b'a'; len])), expected, "{len} octets");
        }
    }
}
