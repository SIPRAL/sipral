// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! MD5 (RFC 1321), because SIP digest was built on it.
//!
//! It is broken for signatures and has been for twenty years, and it is still
//! what every SIP registrar on the planet challenges with. RFC 8760 adds the
//! SHA-2 algorithms next to it, and this stack prefers those wherever the peer
//! offers them — but a client that cannot answer an MD5 challenge cannot
//! register anywhere.
//!
//! The table is `floor(2^32 * abs(sin(i + 1)))`, which is the definition in
//! §3.4 rather than a magic list; the known-answer tests are what prove it was
//! transcribed correctly.

/// The digest of `data`.
pub(super) fn md5(data: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    let mut block = [0_u8; 64];
    let mut chunks = data.chunks_exact(64);
    for chunk in &mut chunks {
        block.copy_from_slice(chunk);
        compress(&mut state, &block);
    }

    // the tail: 0x80, zeros, and the length in bits as 64 little-endian bits
    let rest = chunks.remainder();
    let mut tail = [0_u8; 128];
    let mut len = rest.len();
    tail.get_mut(..len)
        .unwrap_or_default()
        .copy_from_slice(rest);
    if let Some(byte) = tail.get_mut(len) {
        *byte = 0x80;
    }
    len += 1;
    let padded = if len <= 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    if let Some(field) = tail.get_mut(padded - 8..padded) {
        field.copy_from_slice(&bits.to_le_bytes());
    }
    for start in (0..padded).step_by(64) {
        if let Some(chunk) = tail.get(start..start + 64) {
            block.copy_from_slice(chunk);
            compress(&mut state, &block);
        }
    }

    let mut out = [0_u8; 16];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[expect(
    clippy::many_single_char_names,
    reason = "a, b, c, d and m are RFC 1321's own names, and this has to be readable against it"
)]
fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut m = [0_u32; 16];
    for (word, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes([
            *chunk.first().unwrap_or(&0),
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
            *chunk.get(3).unwrap_or(&0),
        ]);
    }

    let [mut a, mut b, mut c, mut d] = *state;
    for i in 0..64_usize {
        let (mixed, index) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let sum = a
            .wrapping_add(mixed)
            .wrapping_add(*K.get(i).unwrap_or(&0))
            .wrapping_add(*m.get(index).unwrap_or(&0));
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(sum.rotate_left(u32::from(*SHIFTS.get(i).unwrap_or(&0))));
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

const SHIFTS: [u8; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
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

#[cfg(test)]
mod tests {
    use super::md5;
    use crate::auth::digest::hex as to_hex;

    fn hex(data: &[u8]) -> String {
        to_hex(&md5(data))
    }

    #[test]
    fn the_published_digests() {
        assert_eq!(hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn the_lengths_where_the_padding_changes_its_mind() {
        // 55 fits with the length field, 56 does not and costs a second block
        assert_eq!(
            hex(&[b'a'; 55]),
            "ef1772b6dff9a122358552954ad0df65",
            "55 bytes"
        );
        assert_eq!(
            hex(&[b'a'; 56]),
            "3b0c8ac703f828b04c6c197006d17218",
            "56 bytes"
        );
        assert_eq!(
            hex(&[b'a'; 64]),
            "014842d480b571495a4a0363793f7367",
            "one whole block"
        );
        assert_eq!(hex(&[b'a'; 1000]), "cabe45dcc9ae5b66ba86600cca6b8ba8");
    }
}
