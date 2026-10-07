// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Comparison that takes the same time wherever the inputs differ.

use core::hint::black_box;

/// Whether `a` and `b` hold the same octets, without returning early at the
/// first difference.
///
/// Lengths are compared openly (they are public for every caller). The loop
/// folds all differences into one octet so the matching prefix length does
/// not leak; `black_box` keeps the optimiser from reintroducing early exit.
pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff = black_box(diff | (x ^ y));
    }
    black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::equal;

    #[test]
    fn differences_anywhere_are_found() {
        let base = [7u8; 32];
        assert!(equal(&base, &base));
        for position in 0..base.len() {
            for bit in 0..8 {
                let mut other = base;
                if let Some(byte) = other.get_mut(position) {
                    *byte ^= 1 << bit;
                }
                assert!(!equal(&base, &other), "octet {position} bit {bit}");
            }
        }
        assert!(!equal(&base, &base[..31]));
        assert!(equal(&[], &[]));
    }
}
