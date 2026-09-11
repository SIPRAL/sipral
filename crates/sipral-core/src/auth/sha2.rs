// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! SHA-256 and SHA-512/256 (FIPS 180-4), the two algorithms RFC 8760 adds to
//! SIP digest.
//!
//! Two functions rather than one generic one: the 32-bit and 64-bit families
//! differ in block size, in the rotation amounts, in the length field and in
//! the tables, which leaves almost nothing to share but the shape.
//!
//! SHA-512/256 is SHA-512 with a different starting state and the result cut
//! to 32 bytes. The starting state is not arbitrary — FIPS 180-4 §5.3.6
//! derives it by running SHA-512 over the string "SHA-512/256" with each word
//! of the standard state exclusive-ORed with `a5a5a5a5a5a5a5a5` — and the
//! known-answer tests are what prove it was transcribed correctly.
//!
//! What goes through here is a password — [`super::digest`] hashes an A1 that
//! holds one — so the buffers the message is copied into are overwritten
//! before the digest returns, the same best effort [`super::secret`] makes for
//! the A1 itself.

use super::secret::wipe;

/// Where one SHA-256 writes the message it is reading.
///
/// Named for the reason [`super::md5::Scratch`] is: the A1 of RFC 3261 §22.4
/// is `user:realm:password` and ends up in `tail` whole, and the schedule
/// below starts as that same block read back as sixteen words.
pub(super) struct Scratch256 {
    /// The last part-block, its padding, and the length field.
    tail: [u8; 128],
    /// FIPS 180-4 §6.2.2's `W`, whose first sixteen words are the message.
    words: [u32; 64],
}

impl Scratch256 {
    pub(super) const fn new() -> Self {
        Self {
            tail: [0_u8; 128],
            words: [0_u32; 64],
        }
    }

    /// Overwrite everything the message was read into.
    fn wipe(&mut self) {
        wipe(&mut self.tail);
        wipe(&mut self.words);
    }

    /// Whether nothing of the message is left in it.
    #[cfg(test)]
    fn is_clear(&self) -> bool {
        self.tail.iter().all(|byte| *byte == 0) && self.words.iter().all(|word| *word == 0)
    }
}

/// The SHA-256 digest of `data`.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_in(data, &mut Scratch256::new())
}

/// The same, in a buffer the caller owns and can read back.
fn sha256_in(data: &[u8], scratch: &mut Scratch256) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let mut chunks = data.chunks_exact(64);
    for chunk in &mut chunks {
        compress256(&mut state, chunk, &mut scratch.words);
    }

    let rest = chunks.remainder();
    scratch
        .tail
        .get_mut(..rest.len())
        .unwrap_or_default()
        .copy_from_slice(rest);
    if let Some(byte) = scratch.tail.get_mut(rest.len()) {
        *byte = 0x80;
    }
    let padded = if rest.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    if let Some(field) = scratch.tail.get_mut(padded - 8..padded) {
        field.copy_from_slice(&bits.to_be_bytes());
    }
    for start in (0..padded).step_by(64) {
        if let Some(chunk) = scratch.tail.get(start..start + 64) {
            compress256(&mut state, chunk, &mut scratch.words);
        }
    }
    // the message has been read; what is left of it here is a copy nobody
    // needs and the digest below does not come from
    scratch.wipe();

    let mut out = [0_u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[expect(
    clippy::many_single_char_names,
    reason = "a through h and w are FIPS 180-4's own names, and this has to be readable against it"
)]
fn compress256(state: &mut [u32; 8], block: &[u8], w: &mut [u32; 64]) {
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([
            *chunk.first().unwrap_or(&0),
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
            *chunk.get(3).unwrap_or(&0),
        ]);
    }
    for i in 16..64 {
        let a = *w.get(i - 15).unwrap_or(&0);
        let b = *w.get(i - 2).unwrap_or(&0);
        let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
        let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
        let value = w
            .get(i - 16)
            .unwrap_or(&0)
            .wrapping_add(s0)
            .wrapping_add(*w.get(i - 7).unwrap_or(&0))
            .wrapping_add(s1);
        if let Some(slot) = w.get_mut(i) {
            *slot = value;
        }
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(*K256.get(i).unwrap_or(&0))
            .wrapping_add(*w.get(i).unwrap_or(&0));
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

/// Where one SHA-512/256 writes the message it is reading.
pub(super) struct Scratch512 {
    /// The last part-block, its padding, and the length field.
    tail: [u8; 256],
    /// FIPS 180-4 §6.4.2's `W`, whose first sixteen words are the message.
    words: [u64; 80],
}

impl Scratch512 {
    pub(super) const fn new() -> Self {
        Self {
            tail: [0_u8; 256],
            words: [0_u64; 80],
        }
    }

    /// Overwrite everything the message was read into.
    fn wipe(&mut self) {
        wipe(&mut self.tail);
        wipe(&mut self.words);
    }

    /// Whether nothing of the message is left in it.
    #[cfg(test)]
    fn is_clear(&self) -> bool {
        self.tail.iter().all(|byte| *byte == 0) && self.words.iter().all(|word| *word == 0)
    }
}

/// The SHA-512/256 digest of `data`.
pub(super) fn sha512_256(data: &[u8]) -> [u8; 32] {
    sha512_256_in(data, &mut Scratch512::new())
}

/// The same, in a buffer the caller owns and can read back.
fn sha512_256_in(data: &[u8], scratch: &mut Scratch512) -> [u8; 32] {
    let mut state: [u64; 8] = [
        0x2231_2194_fc2b_f72c,
        0x9f55_5fa3_c84c_64c2,
        0x2393_b86b_6f53_b151,
        0x9638_7719_5940_eabd,
        0x9628_3ee2_a88e_ffe3,
        0xbe5e_1e25_5386_3992,
        0x2b01_99fc_2c85_b8aa,
        0x0eb7_2ddc_81c5_2ca2,
    ];

    let mut chunks = data.chunks_exact(128);
    for chunk in &mut chunks {
        compress512(&mut state, chunk, &mut scratch.words);
    }

    let rest = chunks.remainder();
    scratch
        .tail
        .get_mut(..rest.len())
        .unwrap_or_default()
        .copy_from_slice(rest);
    if let Some(byte) = scratch.tail.get_mut(rest.len()) {
        *byte = 0x80;
    }
    let padded = if rest.len() < 112 { 128 } else { 256 };
    let bits = (data.len() as u128).wrapping_mul(8);
    if let Some(field) = scratch.tail.get_mut(padded - 16..padded) {
        field.copy_from_slice(&bits.to_be_bytes());
    }
    for start in (0..padded).step_by(128) {
        if let Some(chunk) = scratch.tail.get(start..start + 128) {
            compress512(&mut state, chunk, &mut scratch.words);
        }
    }
    // the message has been read; what is left of it here is a copy nobody
    // needs and the digest below does not come from
    scratch.wipe();

    // "the result cut to 32 bytes": the leftmost 256 bits
    let mut out = [0_u8; 32];
    for (chunk, word) in out.chunks_exact_mut(8).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[expect(
    clippy::many_single_char_names,
    reason = "a through h and w are FIPS 180-4's own names, and this has to be readable against it"
)]
fn compress512(state: &mut [u64; 8], block: &[u8], w: &mut [u64; 80]) {
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(8)) {
        // read out a byte at a time, as `compress256` does: a buffer copied
        // into and left behind is one more place the message lives
        *word = u64::from_be_bytes([
            *chunk.first().unwrap_or(&0),
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
            *chunk.get(3).unwrap_or(&0),
            *chunk.get(4).unwrap_or(&0),
            *chunk.get(5).unwrap_or(&0),
            *chunk.get(6).unwrap_or(&0),
            *chunk.get(7).unwrap_or(&0),
        ]);
    }
    for i in 16..80 {
        let a = *w.get(i - 15).unwrap_or(&0);
        let b = *w.get(i - 2).unwrap_or(&0);
        let s0 = a.rotate_right(1) ^ a.rotate_right(8) ^ (a >> 7);
        let s1 = b.rotate_right(19) ^ b.rotate_right(61) ^ (b >> 6);
        let value = w
            .get(i - 16)
            .unwrap_or(&0)
            .wrapping_add(s0)
            .wrapping_add(*w.get(i - 7).unwrap_or(&0))
            .wrapping_add(s1);
        if let Some(slot) = w.get_mut(i) {
            *slot = value;
        }
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let choice = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(*K512.get(i).unwrap_or(&0))
            .wrapping_add(*w.get(i).unwrap_or(&0));
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

const K256: [u32; 64] = [
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

const K512: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

#[cfg(test)]
mod tests {
    use super::{Scratch256, Scratch512, sha256, sha256_in, sha512_256, sha512_256_in};
    use crate::auth::digest::hex as to_hex;

    fn hex(digest: [u8; 32]) -> String {
        to_hex(&digest)
    }

    #[test]
    fn the_message_is_not_left_behind_in_the_buffers_it_was_read_into() {
        // as in `md5`: the level below the buffer that wipes itself, where
        // the last block of an A1 is copied in the clear. Both lengths, so
        // that the block loop is walked as well as the tail, and against
        // known answers so that a wipe which broke the hash could not pass
        for (message, sha256_expected, sha512_256_expected) in [
            (
                &b"alice:example.com:hunter2"[..],
                "7df05889d19129502fdda853d6b0a23e61e0959ce4b1fef496b80d626a313150",
                "85b4481926cd9f9ccaa7c06a6a3fc2a117554a908861004b69193fe671eeda60",
            ),
            (
                &[b'p'; 400][..],
                "c96581d49e6983f4a5810fa681168c6d0ec8a58b65eab40b9063c6ca7b333790",
                "90624de533b8e7ef05dee022f924ec37d45f07bef94f0140f46aea51f7b778e2",
            ),
        ] {
            let mut scratch = Scratch256::new();
            let digest = sha256_in(message, &mut scratch);
            assert_eq!(hex(digest), sha256_expected);
            assert!(
                scratch.is_clear(),
                "SHA-256 left the message in its own buffers"
            );

            let mut scratch = Scratch512::new();
            let digest = sha512_256_in(message, &mut scratch);
            assert_eq!(hex(digest), sha512_256_expected);
            assert!(
                scratch.is_clear(),
                "SHA-512/256 left the message in its own buffers"
            );
        }
    }

    #[test]
    fn the_published_sha256_digests() {
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "the one RFC 8760 prints in section 2.6"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(b"The quick brown fox jumps over the lazy dog")),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn the_published_sha512_256_digests() {
        assert_eq!(
            hex(sha512_256(b"")),
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        );
        assert_eq!(
            hex(sha512_256(b"abc")),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
        assert_eq!(
            hex(sha512_256(b"The quick brown fox jumps over the lazy dog")),
            "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d"
        );
    }

    #[test]
    fn the_lengths_where_the_padding_changes_its_mind() {
        // 55 and 111 are the last inputs whose length field still fits
        assert_eq!(
            hex(sha256(&[b'a'; 55])),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            hex(sha256(&[b'a'; 56])),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
        assert_eq!(
            hex(sha256(&[b'a'; 64])),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
        assert_eq!(
            hex(sha256(&[b'a'; 1000])),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );

        assert_eq!(
            hex(sha512_256(&[b'a'; 111])),
            "0239e429f98d0ed61ee8e2a7c30afe98c1c3a80ce5dff62a107e9c538f7632ce"
        );
        assert_eq!(
            hex(sha512_256(&[b'a'; 112])),
            "9216b5303edb66504570bee90e48ea5beaa5e9fe9f760bbd3e0460559fc005f6"
        );
        assert_eq!(
            hex(sha512_256(&[b'a'; 128])),
            "b88f97e274f9c1d49f181c8cbd01a9c74930ad055a46ac4499a1d601f1c80bf2"
        );
        assert_eq!(
            hex(sha512_256(&[b'a'; 1000])),
            "40eb4a70d4d69815407a9e272f0101cd67e3d11262a4a0bfc087712749c7fb53"
        );
    }
}
