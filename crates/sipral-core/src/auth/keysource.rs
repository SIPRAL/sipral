// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A stream of unguessable blocks from one seed.
//!
//! `SHA-256(seed || counter)`, and the counter never repeats. Nothing here
//! reads a clock, opens a device or asks the operating system for anything:
//! the caller supplies the thirty-two bytes once, which is what lets the same
//! code run in a test with a fixed seed and on a phone with a real one.
//!
//! Two of these exist in a running stack and they are deliberately separate.
//! The endpoint's drives everything that goes on the wire in clear — branches,
//! tags, `Call-ID`s, the client nonce — and a replay recording carries the
//! seed it runs on while it records, one derived for the recording
//! ([`KeySource::derived`]), so that a recorded session can be replayed byte
//! for byte without the file holding the seed the stack was built with. The media
//! engine's derives SRTP master keys, and is written nowhere. Sharing one
//! between them would put every key this stack will ever offer into every
//! recording it makes.

use core::fmt;

use super::secret::wipe;
use super::sha2::sha256;

/// A seed, and the blocks drawn from it.
///
/// Neither `Clone` nor `Copy`: two copies of a stream hand out the same
/// blocks twice, and for key material that is the end of the encryption.
pub struct KeySource {
    seed: [u8; 32],
    counter: u64,
}

impl KeySource {
    /// Start from the caller's seed.
    ///
    /// Two of these must never be given the same thirty-two bytes, and a
    /// stack's media seed must not be its endpoint seed.
    #[must_use]
    pub const fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    /// `SHA-256(seed || counter)`, and the counter moves on.
    ///
    /// The counter is read before it is incremented, so the first block is
    /// drawn at zero. That ordering is load-bearing: every branch, tag,
    /// `Call-ID` and client nonce this stack has ever produced follows from
    /// it, and a recorded session replays byte for byte only while it holds.
    pub fn block(&mut self) -> [u8; 32] {
        let counter = self.counter.to_be_bytes();
        self.counter = self.counter.wrapping_add(1);
        let mut input = [0_u8; 40];
        for (slot, byte) in input.iter_mut().zip(self.seed.iter().chain(counter.iter())) {
            *slot = *byte;
        }
        let digest = sha256(&input);
        wipe(&mut input);
        digest
    }

    /// A stream of its own, seeded with `SHA-256(label || seed)`.
    ///
    /// One way: neither stream's blocks say anything about the other's, and
    /// a different `label` gives an unrelated stream. What the endpoint
    /// draws the seed of each replay recording from, so that a recording
    /// carries a seed of its own and never this one.
    pub(crate) fn derived(&self, label: &[u8]) -> Self {
        let mut input = Vec::with_capacity(label.len() + self.seed.len());
        input.extend_from_slice(label);
        input.extend_from_slice(&self.seed);
        let seed = sha256(&input);
        wipe(&mut input);
        Self::new(seed)
    }
}

/// Written by hand, because the seed must not reach a log.
///
/// Everything that holds one of these derives `Debug` — the media engine, the
/// endpoint, and the user agent above both — so a derived implementation here
/// would put thirty-two bytes of entropy into any `{:?}` of a live stack.
impl fmt::Debug for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeySource(<redacted>)")
    }
}

impl Drop for KeySource {
    fn drop(&mut self) {
        wipe(&mut self.seed);
    }
}

#[cfg(test)]
mod tests {
    use super::KeySource;

    #[test]
    fn the_same_seed_gives_the_same_blocks_and_a_different_one_does_not() {
        let mut one = KeySource::new([7; 32]);
        let mut again = KeySource::new([7; 32]);
        let mut other = KeySource::new([8; 32]);
        for _ in 0..4 {
            let block = one.block();
            assert_eq!(block, again.block(), "a seed is a stream, not a draw");
            assert_ne!(block, other.block());
        }
    }

    #[test]
    fn no_block_repeats() {
        let mut source = KeySource::new([0; 32]);
        let mut seen = Vec::new();
        for _ in 0..256 {
            let block = source.block();
            assert!(!seen.contains(&block), "the counter repeated");
            seen.push(block);
        }
    }

    #[test]
    fn the_seed_does_not_reach_a_log() {
        // the one thing a derived Debug would get wrong, and it would get it
        // wrong everywhere at once: this type is held by the media engine,
        // which is held by the facade, which an application prints
        let source = KeySource::new([0xab; 32]);
        let printed = format!("{source:?}");
        assert!(!printed.contains("ab"), "{printed}");
        assert!(!printed.contains("171"), "{printed}");
        assert_eq!(printed, "KeySource(<redacted>)");
    }
}
