// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! CRC-32 as ITU V.42 defines it, which is the one FINGERPRINT carries
//! (RFC 8489 §14.7, pointing at the sample code in RFC 1952 §8).
//!
//! Reflected input and output, initial and final complement: the ordinary
//! variant, the same one gzip and Ethernet use.

/// The generator polynomial, bit-reversed the way a table-driven CRC wants it.
const POLYNOMIAL: u32 = 0xedb8_8320;

/// One entry per byte value, folded eight bits at a time.
const TABLE: [u32; 256] = table();

#[expect(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "a const fn has neither get_mut nor try_from, and the loop stops at 256"
)]
const fn table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut byte = 0;
    while byte < 256 {
        let mut value = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 0 {
                value >> 1
            } else {
                POLYNOMIAL ^ (value >> 1)
            };
            bit += 1;
        }
        table[byte] = value;
        byte += 1;
    }
    table
}

/// A checksum being accumulated.
///
/// In pieces, because FINGERPRINT covers the message with its length field
/// rewritten to include the attribute, and rewriting it in place would mean
/// copying the message to check it.
pub(crate) struct Crc32(u32);

impl Crc32 {
    /// A checksum over nothing yet.
    pub(crate) const fn new() -> Self {
        Self(0xffff_ffff)
    }

    /// Fold more bytes in.
    pub(crate) fn update(&mut self, data: &[u8]) {
        for byte in data {
            let low = u8::try_from(self.0 & 0xff).unwrap_or_default();
            let index = usize::from(low ^ byte);
            self.0 = TABLE.get(index).unwrap_or(&0) ^ (self.0 >> 8);
        }
    }

    /// The checksum.
    pub(crate) const fn finish(self) -> u32 {
        self.0 ^ 0xffff_ffff
    }
}

#[cfg(test)]
mod tests {
    use super::Crc32;

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = Crc32::new();
        crc.update(data);
        crc.finish()
    }

    #[test]
    fn the_check_value_for_the_standard_string_comes_out() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn nothing_checksums_to_zero() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_known_short_string_matches() {
        assert_eq!(crc32(b"abc"), 0x3524_41c2);
    }

    #[test]
    fn feeding_it_in_pieces_changes_nothing() {
        let data: Vec<u8> = (0..=255_u8).cycle().take(600).collect();
        let whole = crc32(&data);

        for split in [0, 1, 255, 256, 599, 600] {
            let mut crc = Crc32::new();
            crc.update(&data[..split]);
            crc.update(&data[split..]);
            assert_eq!(crc.finish(), whole, "split at {split}");
        }
    }
}
