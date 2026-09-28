// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The two keystream generators RFC 3711 §4.1 defines over AES: counter mode
//! (§4.1.1, mandatory) and f8 (§4.1.2, optional, and what 3GPP asks for).
//!
//! Both produce a keystream that is exclusive-ORed with the payload, so
//! encryption and decryption are the same call. AES itself comes from the
//! `aes` crate; everything above the block function is here.

use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::{Aes128Enc, Aes256Enc};
use zeroize::Zeroize;

/// The AES block size, `n_b` in the RFC's notation.
pub(crate) const BLOCK: usize = 16;

/// The AES-128 key length: every suite RFC 4568 defines, and the RTP side of
/// RFC 7714's `AEAD_AES_128_GCM`.
pub(crate) const KEY_128: usize = 16;

/// The AES-256 key length: RFC 6188's `AES_256_CM` suites and RFC 7714's
/// `AEAD_AES_256_GCM`.
pub(crate) const KEY_256: usize = 32;

/// The master and session key length of the suite every implementation has.
/// Kept for the callers that only ever spoke of the one suite; a caller that
/// cares which suite it is reads the length off [`super::Suite`] instead.
pub(crate) const KEY: usize = KEY_128;

/// A keystream long enough to have exhausted the counter.
///
/// §4.1.1: the number of blocks generated for a fixed IV "MUST NOT exceed
/// 2^16", because the IV reserves exactly sixteen bits for the counter and a
/// seventeenth block would repeat a keystream that has already been used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exhausted;

/// AES in counter mode, keyed once per session, over either key width RFC
/// 6188 adds to RFC 3711's AES-128: both are "AES_CM" with a different block
/// cipher underneath, and every other bit of arithmetic here is the same.
// the encrypt-only types: SRTP never runs AES backwards, since both
// directions are a keystream exclusive-ORed over the payload, and asking for
// the decryption schedule would double the state for nothing
#[expect(
    clippy::large_enum_variant,
    reason = "the difference is one AES key schedule, and there is one of these per session, not per packet"
)]
pub(crate) enum Counter {
    Aes128(Aes128Enc),
    Aes256(Aes256Enc),
}

impl Counter {
    /// A key of sixteen or thirty-two octets. Nothing else reaches this
    /// module: every caller sizes the key from a [`super::Suite`] first.
    pub(crate) fn new(key: &[u8]) -> Self {
        if key.len() == KEY_256 {
            let mut array = Array([0_u8; KEY_256]);
            array.copy_from_slice(key);
            let cipher = Self::Aes256(Aes256Enc::new(&array));
            array.zeroize();
            cipher
        } else {
            let mut array = Array([0_u8; KEY_128]);
            array.copy_from_slice(key.get(..KEY_128).unwrap_or(&[0; KEY_128]));
            let cipher = Self::Aes128(Aes128Enc::new(&array));
            array.zeroize();
            cipher
        }
    }

    /// Exclusive-OR the keystream for `iv` over `data`.
    ///
    /// §4.1.1 defines the keystream as `E(k, IV) || E(k, IV + 1) || ...`.
    /// Every IV the RFC constructs — the packet IV and the PRF's `x * 2^16` —
    /// has its low sixteen bits zero, so "add one" is "increment the last two
    /// bytes", and running out of them is the condition above rather than a
    /// silent wrap.
    pub(crate) fn apply(&self, iv: &[u8; BLOCK], data: &mut [u8]) -> Result<(), Exhausted> {
        let blocks = data.len().div_ceil(BLOCK);
        if blocks > usize::from(u16::MAX) + 1 {
            return Err(Exhausted);
        }

        let mut counter = *iv;
        let base = u16::from_be_bytes([
            *iv.get(BLOCK - 2).unwrap_or(&0),
            *iv.get(BLOCK - 1).unwrap_or(&0),
        ]);
        for (index, chunk) in data.chunks_mut(BLOCK).enumerate() {
            let step = u16::try_from(index).map_err(|_| Exhausted)?;
            if let Some(field) = counter.get_mut(BLOCK - 2..) {
                field.copy_from_slice(&base.wrapping_add(step).to_be_bytes());
            }
            let mut block = Array(counter);
            self.encrypt(&mut block);
            for (byte, key) in chunk.iter_mut().zip(block.0) {
                *byte ^= key;
            }
            block.0.zeroize();
        }
        Ok(())
    }

    fn encrypt(&self, block: &mut Array<u8, aes::cipher::consts::U16>) {
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(block),
            Self::Aes256(cipher) => cipher.encrypt_block(block),
        }
    }

    /// One raw block encryption, which is what the f8 mask needs.
    fn block(&self, block: &mut [u8; BLOCK]) {
        let mut value = Array(*block);
        self.encrypt(&mut value);
        *block = value.0;
        value.0.zeroize();
    }
}

/// AES in f8 mode: output feedback with a masked IV and a block counter.
pub(crate) struct F8 {
    cipher: Counter,
    masked: Counter,
}

impl F8 {
    /// §4.1.2.1: the mask is `m = k_s || 0x55..5`, filled out to the key
    /// length, and the second key is `k_e XOR m`. `F8_128_HMAC_SHA1_80` is
    /// the only f8 suite this stack implements, so `key` is always sixteen
    /// octets, but it arrives as a slice because the session key it is cut
    /// from is one too.
    pub(crate) fn new(key: &[u8], salt: &[u8]) -> Self {
        let mut mask = [0x55_u8; KEY];
        if let Some(head) = mask.get_mut(..salt.len().min(KEY)) {
            head.copy_from_slice(salt.get(..salt.len().min(KEY)).unwrap_or_default());
        }
        let mut key_mask = [0_u8; KEY];
        if let Some(head) = key_mask.get_mut(..key.len().min(KEY)) {
            head.copy_from_slice(key.get(..key.len().min(KEY)).unwrap_or_default());
        }
        for (byte, m) in key_mask.iter_mut().zip(mask) {
            *byte ^= m;
        }
        let f8 = Self {
            cipher: Counter::new(key),
            masked: Counter::new(&key_mask),
        };
        key_mask.zeroize();
        f8
    }

    /// Exclusive-OR the f8 keystream for `iv` over `data`.
    ///
    /// `IV' = E(k_e XOR m, IV)`, `S(-1) = 0`, and
    /// `S(j) = E(k_e, IV' XOR j XOR S(j-1))`.
    pub(crate) fn apply(&self, iv: &[u8; BLOCK], data: &mut [u8]) -> Result<(), Exhausted> {
        let mut masked_iv = *iv;
        self.masked.block(&mut masked_iv);

        let mut previous = [0_u8; BLOCK];
        for (index, chunk) in data.chunks_mut(BLOCK).enumerate() {
            let step = u32::try_from(index).map_err(|_| Exhausted)?;
            let mut input = masked_iv;
            for (byte, feedback) in input.iter_mut().zip(previous) {
                *byte ^= feedback;
            }
            // j is a full block wide but only ever small enough to matter in
            // its last four bytes, since the sender stops well before 2^32
            if let Some(field) = input.get_mut(BLOCK - 4..) {
                for (byte, count) in field.iter_mut().zip(step.to_be_bytes()) {
                    *byte ^= count;
                }
            }
            self.cipher.block(&mut input);
            for (byte, key) in chunk.iter_mut().zip(input) {
                *byte ^= key;
            }
            previous = input;
        }
        previous.zeroize();
        masked_iv.zeroize();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{hex, unhex, unhex16 as key16, unhexn};
    use super::{BLOCK, Counter, Exhausted, F8};

    // RFC 3711 Appendix B.2. The session salt is given already shifted, so it
    // is the IV as written; the vector lists the keystream at three counter
    // values near the start and three near the end of a very long segment
    #[test]
    fn appendix_b2_counter_keystream() {
        let cipher = Counter::new(&key16("2b7e151628aed2a6abf7158809cf4f3c"));
        let iv = key16("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000");

        let mut stream = vec![0_u8; BLOCK * 3];
        cipher.apply(&iv, &mut stream).expect("within one segment");
        assert_eq!(
            hex(&stream),
            "e03ead0935c95e80e166b16dd92b4eb4\
             d23513162b02d0f72a43a2fe4a5f97ab\
             41e95b3bb0a2e8dd477901e4fca894c0"
        );
    }

    #[test]
    fn appendix_b2_end_of_the_segment() {
        let cipher = Counter::new(&key16("2b7e151628aed2a6abf7158809cf4f3c"));
        let iv = key16("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000");

        // the last three counter values the vector names: 0xfeff, 0xff00,
        // 0xff01, so the keystream has to run that far to reach them
        let mut stream = vec![0_u8; BLOCK * 0x_ff02];
        cipher
            .apply(&iv, &mut stream)
            .expect("exactly at the limit");
        assert_eq!(
            hex(stream
                .get(BLOCK * 0x_feff..BLOCK * 0x_ff02)
                .unwrap_or_default()),
            "ec8cdf7398607cb0f2d21675ea9ea1e4\
             362b7c3c6773516318a077d7fc5073ae\
             6a2cc3787889374fbeb4c81b17ba6c44"
        );
    }

    #[test]
    fn the_counter_refuses_to_wrap() {
        let cipher = Counter::new(&key16("2b7e151628aed2a6abf7158809cf4f3c"));
        let iv = key16("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000");

        let mut just_fits = vec![0_u8; BLOCK * 65536];
        assert_eq!(cipher.apply(&iv, &mut just_fits), Ok(()));
        let mut one_too_many = vec![0_u8; BLOCK * 65536 + 1];
        assert_eq!(cipher.apply(&iv, &mut one_too_many), Err(Exhausted));
    }

    #[test]
    fn counter_mode_is_its_own_inverse() {
        let cipher = Counter::new(&key16("00112233445566778899aabbccddeeff"));
        let iv = key16("0102030405060708090a0b0c0d0e0000");
        let plain = b"the same call encrypts and decrypts".to_vec();
        let mut buffer = plain.clone();
        cipher.apply(&iv, &mut buffer).expect("short");
        assert_ne!(buffer, plain);
        cipher.apply(&iv, &mut buffer).expect("short");
        assert_eq!(buffer, plain);
    }

    // RFC 3711 Appendix B.1
    #[test]
    fn appendix_b1_f8_keystream() {
        let cipher = F8::new(
            &key16("234829008467be186c3de14aae72d62c"),
            &unhex("32f2870d"),
        );
        let iv = key16("006e5cba50681de55c621599d462564a");

        let mut payload = unhex(
            "70736575646f72616e646f6d6e657373\
             20697320746865206e65787420626573\
             74207468696e67",
        );
        cipher.apply(&iv, &mut payload).expect("short");
        assert_eq!(
            hex(&payload),
            "019ce7a26e7854014a6366aa95d4eefd\
             1ad4172a14f9faf455b7f1d4b62bd08f\
             562c0eef7c4802"
        );
    }

    #[test]
    fn f8_is_its_own_inverse() {
        let cipher = F8::new(
            &key16("234829008467be186c3de14aae72d62c"),
            &unhex("32f2870d"),
        );
        let iv = key16("006e5cba50681de55c621599d462564a");
        let plain = b"f8 is output feedback with a counter folded in".to_vec();
        let mut buffer = plain.clone();
        cipher.apply(&iv, &mut buffer).expect("short");
        assert_ne!(buffer, plain);
        cipher.apply(&iv, &mut buffer).expect("short");
        assert_eq!(buffer, plain);
    }

    // the feedback makes every block depend on the one before it, so a
    // keystream produced in one call and one produced block by block only
    // agree if the chaining is right
    #[test]
    fn f8_chains_across_blocks() {
        let cipher = F8::new(
            &key16("234829008467be186c3de14aae72d62c"),
            &unhex("32f2870d"),
        );
        let iv = key16("006e5cba50681de55c621599d462564a");
        let mut whole = vec![0_u8; BLOCK * 4];
        cipher.apply(&iv, &mut whole).expect("short");

        let mut second = vec![0_u8; BLOCK];
        cipher.apply(&iv, &mut second).expect("short");
        assert_ne!(
            second.as_slice(),
            whole.get(BLOCK..BLOCK * 2).unwrap_or_default(),
            "the second block must not repeat the first"
        );
        assert_eq!(second.as_slice(), whole.get(..BLOCK).unwrap_or_default());
    }

    // RFC 6188 §7.1: the AES-256-CM keystream, at the same counter values
    // Appendix B.2 of RFC 3711 checks for AES-128-CM.
    #[test]
    fn rfc_6188_aes_256_cm_keystream() {
        let key: [u8; 32] =
            unhexn("57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98");
        let cipher = Counter::new(&key);
        let iv = key16("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000");

        let mut stream = vec![0_u8; BLOCK * 3];
        cipher.apply(&iv, &mut stream).expect("within one segment");
        assert_eq!(
            hex(&stream),
            "92bdd28a93c3f52511c677d08b5515a4\
             9da71b2378a854f67050756ded165bac\
             63c4868b7096d88421b563b8c94c9a31"
        );

        let mut just_fits = vec![0_u8; BLOCK * 0x_ff02];
        cipher
            .apply(&iv, &mut just_fits)
            .expect("exactly at the limit");
        assert_eq!(
            hex(just_fits
                .get(BLOCK * 0x_feff..BLOCK * 0x_ff02)
                .unwrap_or_default()),
            "cea518c90fd91ced9cbb18c078a54711\
             3dbc4814f4da5f00a08772b63c6a046d\
             6eb246913062a16891433e97dd01a57f"
        );
    }

    #[test]
    fn aes_256_cm_is_a_different_cipher_from_aes_128_cm_under_the_same_bytes() {
        let key128 = key16("00112233445566778899aabbccddeeff");
        let mut key256 = [0_u8; 32];
        key256[..16].copy_from_slice(&key128);
        let iv = key16("0102030405060708090a0b0c0d0e0000");

        let mut under128 = vec![0_u8; BLOCK];
        Counter::new(&key128).apply(&iv, &mut under128).unwrap();
        let mut under256 = vec![0_u8; BLOCK];
        Counter::new(&key256).apply(&iv, &mut under256).unwrap();
        assert_ne!(
            under128, under256,
            "a wider key must not collapse to the narrow one"
        );
    }
}
