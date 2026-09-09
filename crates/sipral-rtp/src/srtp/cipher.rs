// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The two keystream generators RFC 3711 §4.1 defines over AES: counter mode
//! (§4.1.1, mandatory) and f8 (§4.1.2, optional, and what 3GPP asks for).
//!
//! Both produce a keystream that is exclusive-ORed with the payload, so
//! encryption and decryption are the same call. AES itself comes from the
//! `aes` crate; everything above the block function is here.

use aes::Aes128Enc;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use zeroize::Zeroize;

/// The AES block size, `n_b` in the RFC's notation.
pub(crate) const BLOCK: usize = 16;

/// The master and session key length for every suite RFC 4568 defines.
pub(crate) const KEY: usize = 16;

/// A keystream long enough to have exhausted the counter.
///
/// §4.1.1: the number of blocks generated for a fixed IV "MUST NOT exceed
/// 2^16", because the IV reserves exactly sixteen bits for the counter and a
/// seventeenth block would repeat a keystream that has already been used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exhausted;

/// AES in counter mode, keyed once per session.
pub(crate) struct Counter {
    // the encrypt-only type: SRTP never runs AES backwards, since both
    // directions are a keystream exclusive-ORed over the payload, and asking
    // for the decryption schedule would double the state for nothing
    cipher: Aes128Enc,
}

impl Counter {
    pub(crate) fn new(key: &[u8; KEY]) -> Self {
        Self {
            cipher: Aes128Enc::new(&Array(*key)),
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
            self.cipher.encrypt_block(&mut block);
            for (byte, key) in chunk.iter_mut().zip(block.0) {
                *byte ^= key;
            }
            block.0.zeroize();
        }
        Ok(())
    }

    /// One raw block encryption, which is what the f8 mask needs.
    fn block(&self, block: &mut [u8; BLOCK]) {
        let mut value = Array(*block);
        self.cipher.encrypt_block(&mut value);
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
    /// length, and the second key is `k_e XOR m`.
    pub(crate) fn new(key: &[u8; KEY], salt: &[u8]) -> Self {
        let mut mask = [0x55_u8; KEY];
        if let Some(head) = mask.get_mut(..salt.len().min(KEY)) {
            head.copy_from_slice(salt.get(..salt.len().min(KEY)).unwrap_or_default());
        }
        let mut key_mask = *key;
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
    use super::super::testing::{hex, unhex, unhex16 as key16};
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
}
