// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! SHA-1 (RFC 3174) and HMAC-SHA-1 (RFC 2104), which is the authentication
//! transform RFC 3711 §4.2 makes mandatory.
//!
//! Written here: a page of arithmetic with published test vectors, and
//! constant-time as written (no data-dependent branch or table). SHA-1's
//! collision weakness does not carry over to HMAC-SHA-1, which RFC 3711 §4.2
//! still mandates.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The block size in bytes, and so the key length HMAC pads to.
const BLOCK: usize = 64;

/// The digest length in bytes.
pub(crate) const DIGEST: usize = 20;

/// SHA-1 over a message given in pieces, so a caller that authenticates a
/// packet followed by a rollover counter does not have to join them first.
pub(crate) struct Sha1 {
    state: [u32; 5],
    buffer: [u8; BLOCK],
    buffered: usize,
    length: u64,
}

impl Sha1 {
    pub(crate) fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            buffer: [0; BLOCK],
            buffered: 0,
            length: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);

        if self.buffered > 0 {
            let want = BLOCK - self.buffered;
            let take = want.min(data.len());
            if let (Some(slot), Some(head)) = (
                self.buffer.get_mut(self.buffered..self.buffered + take),
                data.get(..take),
            ) {
                slot.copy_from_slice(head);
            }
            self.buffered += take;
            data = data.get(take..).unwrap_or_default();
            if self.buffered < BLOCK {
                return;
            }
            let block = self.buffer;
            compress(&mut self.state, &block);
            self.buffered = 0;
        }

        let (blocks, rest) = data.as_chunks::<BLOCK>();
        for block in blocks {
            compress(&mut self.state, block);
        }

        if let Some(slot) = self.buffer.get_mut(..rest.len()) {
            slot.copy_from_slice(rest);
        }
        self.buffered = rest.len();
    }

    pub(crate) fn finish(mut self) -> [u8; DIGEST] {
        let bits = self.length.wrapping_mul(8);

        // §4: append a 1 bit, then zeros, then the length in 64 big-endian
        // bits. One or two blocks, depending on how much room is left
        let mut tail = [0_u8; BLOCK * 2];
        if let Some(slot) = tail.get_mut(..self.buffered) {
            slot.copy_from_slice(self.buffer.get(..self.buffered).unwrap_or_default());
        }
        if let Some(byte) = tail.get_mut(self.buffered) {
            *byte = 0x80;
        }
        let padded = if self.buffered < BLOCK - 8 {
            BLOCK
        } else {
            BLOCK * 2
        };
        if let Some(field) = tail.get_mut(padded - 8..padded) {
            field.copy_from_slice(&bits.to_be_bytes());
        }
        for start in (0..padded).step_by(BLOCK) {
            if let Some(block) = tail.get(start..start + BLOCK) {
                compress(&mut self.state, block);
            }
        }

        let mut out = [0_u8; DIGEST];
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *chunk = word.to_be_bytes();
        }
        out
    }
}

/// Once a key is in it — HMAC's pads — the state is as good as that key, so
/// it is wiped when the hash goes.
impl Drop for Sha1 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
    }
}

impl ZeroizeOnDrop for Sha1 {}

#[expect(
    clippy::many_single_char_names,
    reason = "a through e and w are RFC 3174's own names, and this has to be readable against it"
)]
fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0_u32; 80];
    for (word, chunk) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*chunk);
    }
    for t in 16..80 {
        let value = (w.get(t - 3).unwrap_or(&0)
            ^ w.get(t - 8).unwrap_or(&0)
            ^ w.get(t - 14).unwrap_or(&0)
            ^ w.get(t - 16).unwrap_or(&0))
        .rotate_left(1);
        if let Some(slot) = w.get_mut(t) {
            *slot = value;
        }
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for t in 0..80 {
        // §5: four rounds of twenty, each with its own function and constant
        let (f, k) = match t / 20 {
            0 => ((b & c) | (!b & d), 0x5a82_7999),
            1 => (b ^ c ^ d, 0x6ed9_eba1),
            2 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(*w.get(t).unwrap_or(&0))
            .wrapping_add(k);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
        *slot = slot.wrapping_add(value);
    }
}

/// HMAC-SHA-1 over a message given in pieces.
///
/// RFC 2104: `H((K ^ opad) || H((K ^ ipad) || text))`, with a key longer than
/// the block replaced by its own digest and a shorter one zero-padded.
///
/// The padded key and both pads are the key under another name, and so is the
/// state of either hash once its pad is in: each is wiped when it goes.
pub(crate) fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; DIGEST] {
    let mut padded = Zeroizing::new([0_u8; BLOCK]);
    if key.len() > BLOCK {
        let mut hash = Sha1::new();
        hash.update(key);
        if let Some(slot) = padded.get_mut(..DIGEST) {
            slot.copy_from_slice(&hash.finish());
        }
    } else if let Some(slot) = padded.get_mut(..key.len()) {
        slot.copy_from_slice(key);
    }

    let mut inner = Sha1::new();
    inner.update(&*pad(&padded, 0x36));
    for part in parts {
        inner.update(part);
    }
    let digest = inner.finish();

    let mut outer = Sha1::new();
    outer.update(&*pad(&padded, 0x5c));
    outer.update(&digest);
    outer.finish()
}

/// The padded key with every octet exclusive-ORed with `with`: RFC 2104's
/// `ipad` for 0x36, `opad` for 0x5c.
fn pad(padded: &[u8; BLOCK], with: u8) -> Zeroizing<[u8; BLOCK]> {
    let mut pad = Zeroizing::new(*padded);
    for byte in pad.iter_mut() {
        *byte ^= with;
    }
    pad
}

#[cfg(test)]
mod tests {
    use zeroize::{ZeroizeOnDrop, Zeroizing};

    use super::super::testing::hex;
    use super::{BLOCK, Sha1, hmac, pad};

    #[test]
    fn the_pads_and_the_hash_state_are_wiped_when_they_go() {
        fn wiped_on_drop<T: ZeroizeOnDrop>() {}
        wiped_on_drop::<Sha1>();
        let padded = [0x0b_u8; BLOCK];
        let inner: Zeroizing<[u8; BLOCK]> = pad(&padded, 0x36);
        let outer: Zeroizing<[u8; BLOCK]> = pad(&padded, 0x5c);
        assert!(inner.iter().all(|&byte| byte == 0x0b ^ 0x36));
        assert!(outer.iter().all(|&byte| byte == 0x0b ^ 0x5c));
    }

    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut hash = Sha1::new();
        hash.update(data);
        hash.finish()
    }

    // RFC 3174 §7.3, the four patterns with their repeat counts
    #[test]
    fn rfc3174_vectors() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(&sha1(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
        assert_eq!(
            hex(&sha1(
                &b"0123456701234567012345670123456701234567012345670123456701234567".repeat(10)
            )),
            "dea356a2cddd90c7a7ecedc5ebb563934f460452"
        );
    }

    #[test]
    fn empty_message() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    // the length field lands differently on either side of 56 bytes in the
    // last block, which is the padding bug nobody's first attempt survives
    #[test]
    fn every_length_across_a_block_boundary() {
        let message = [b'x'; 200];
        for len in 0..200 {
            let head = message.get(..len).unwrap_or_default();
            let mut split = Sha1::new();
            let (a, b) = head.split_at(len / 2);
            split.update(a);
            split.update(b);
            assert_eq!(split.finish(), sha1(head), "length {len}");
        }
    }

    #[test]
    fn one_byte_at_a_time_matches_one_call() {
        let message: Vec<u8> = (0..300_u32).map(|i| (i % 251) as u8).collect();
        let mut drip = Sha1::new();
        for byte in &message {
            drip.update(&[*byte]);
        }
        assert_eq!(drip.finish(), sha1(&message));
    }

    // RFC 2202 §3
    #[test]
    fn rfc2202_vectors() {
        assert_eq!(
            hex(&hmac(&[0x0b; 20], &[b"Hi There"])),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac(b"Jefe", &[b"what do ya want for nothing?"])),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&hmac(&[0xaa; 20], &[&[0xdd; 50][..]])),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
        let key: Vec<u8> = (1..=25).collect();
        assert_eq!(
            hex(&hmac(&key, &[&[0xcd; 50][..]])),
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        );
        assert_eq!(
            hex(&hmac(&[0x0c; 20], &[b"Test With Truncation"])),
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
        );
        assert_eq!(
            hex(&hmac(
                &[0xaa; 80],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
        assert_eq!(
            hex(&hmac(
                &[0xaa; 80],
                &[
                    b"Test Using Larger Than Block-Size Key and Larger Than One \
                      Block-Size Data"
                ]
            )),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        );
    }

    #[test]
    fn pieces_are_the_same_message() {
        let key = [0x2b; 20];
        let whole = hmac(&key, &[b"one message in two halves"]);
        let split = hmac(&key, &[b"one message ", b"in two halves"]);
        assert_eq!(whole, split);
    }

    #[test]
    fn a_key_exactly_one_block_long_is_not_hashed() {
        // the boundary in RFC 2104 is "longer than", not "at least"
        let key = [0x41; 64];
        let mut hashed = Sha1::new();
        hashed.update(&key);
        let digest = hashed.finish();
        assert_ne!(hmac(&key, &[b"x"]), hmac(&digest, &[b"x"]));
    }
}
