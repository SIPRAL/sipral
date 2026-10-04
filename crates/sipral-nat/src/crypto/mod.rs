// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The hashes STUN asks for, written out because the tree has no dependencies.
//!
//! SHA-1 for MESSAGE-INTEGRITY, SHA-256 for MESSAGE-INTEGRITY-SHA256, MD5 for
//! the long-term credential key, HMAC over the first two, and the CRC-32 that
//! FINGERPRINT carries. Each is checked against the digests published with its
//! own specification before anything here relies on it.
//!
//! All three hashes compress 64-byte blocks and differ only in the state, the
//! round function and which end the length field is written from, so the
//! buffering that turns a stream of writes into blocks lives here once.

pub(crate) mod crc32;
pub(crate) mod hmac;
pub(crate) mod md5;
pub(crate) mod sha1;
pub(crate) mod sha256;

use core::sync::atomic::{Ordering, compiler_fence};

/// Octets every hash here consumes at a time.
pub(crate) const BLOCK: usize = 64;

/// A hash that can be fed in pieces.
///
/// Pieces rather than one slice because the HMAC over a STUN message runs over
/// the message with its length field rewritten, and rewriting it in place
/// would mean copying the message to hash it.
pub(crate) trait Digest: Sized {
    /// The digest.
    type Output: AsRef<[u8]> + Copy;

    /// A hash of nothing yet.
    fn start() -> Self;

    /// Add to what is being hashed.
    fn update(&mut self, data: &[u8]);

    /// Pad and produce the digest.
    fn finish(self) -> Self::Output;

    /// The digest of one slice.
    fn digest(data: &[u8]) -> Self::Output {
        let mut hash = Self::start();
        hash.update(data);
        hash.finish()
    }
}

/// Whether two byte strings are equal, without letting the time taken say
/// where they first differ.
///
/// Best effort, and said plainly: only a volatile read is guaranteed to
/// survive an optimiser, and a volatile read needs `unsafe`, which this crate
/// denies outside the FFI. A compiler fence is what is available without it.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    compiler_fence(Ordering::SeqCst);
    difference == 0
}

/// The block buffer shared by the three hashes.
///
/// It counts the bytes it has been given and hands whole blocks to whatever
/// compression function the hash supplies.
pub(crate) struct Blocks {
    buffer: [u8; BLOCK],
    filled: usize,
    length: u64,
}

impl Blocks {
    /// An empty buffer.
    pub(crate) const fn new() -> Self {
        Self {
            buffer: [0; BLOCK],
            filled: 0,
            length: 0,
        }
    }

    /// Take data, compressing every block it completes.
    pub(crate) fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8])) {
        self.length = self.length.wrapping_add(data.len() as u64);

        if self.filled != 0 {
            let take = (BLOCK - self.filled).min(data.len());
            if let (Some(room), Some(head)) = (
                self.buffer.get_mut(self.filled..self.filled + take),
                data.get(..take),
            ) {
                room.copy_from_slice(head);
            }
            self.filled += take;
            data = data.get(take..).unwrap_or_default();
            if self.filled < BLOCK {
                return;
            }
            compress(&self.buffer);
            self.filled = 0;
        }

        let mut whole = data.chunks_exact(BLOCK);
        for block in &mut whole {
            compress(block);
        }
        let rest = whole.remainder();
        if let Some(room) = self.buffer.get_mut(..rest.len()) {
            room.copy_from_slice(rest);
        }
        self.filled = rest.len();
    }

    /// Append the terminator, the zeros and the bit count, which leaves the
    /// buffer empty and every block compressed.
    ///
    /// `little_endian` is the one place MD5 parts company with the SHA family.
    pub(crate) fn finish(&mut self, mut compress: impl FnMut(&[u8]), little_endian: bool) {
        let bits = self.length.wrapping_mul(8);
        let count = if little_endian {
            bits.to_le_bytes()
        } else {
            bits.to_be_bytes()
        };
        self.update(&[0x80], &mut compress);
        while self.filled != BLOCK - 8 {
            self.update(&[0], &mut compress);
        }
        self.update(&count, &mut compress);
    }
}

/// A digest as lower-case hex, so a test can be read against the digest its
/// specification prints.
#[cfg(test)]
pub(crate) fn hex(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from(nibble(byte >> 4)));
        out.push(char::from(nibble(byte & 0x0f)));
    }
    out
}

#[cfg(test)]
const fn nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn equal_strings_compare_equal() {
        assert!(constant_time_eq(b"sipral", b"sipral"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn a_difference_anywhere_is_a_difference() {
        assert!(!constant_time_eq(b"sipral", b"sipraL"));
        assert!(!constant_time_eq(b"sipral", b"Sipral"));
    }

    #[test]
    fn a_prefix_is_not_the_whole_string() {
        assert!(!constant_time_eq(b"sipral", b"sipra"));
        assert!(!constant_time_eq(b"", b"\0"));
    }
}
