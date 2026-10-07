// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A stream of unguessable blocks from one seed: `SHA-256(seed || counter)`.
//!
//! No clock, no device: the caller supplies the 32 bytes once, so a test can
//! use a fixed seed.
//!
//! A stack holds two of these, kept separate on purpose. The endpoint's drives
//! everything sent in clear (branches, tags, `Call-ID`s, the client nonce),
//! and a replay recording carries a seed derived for it
//! ([`KeySource::derived`]) so it replays byte for byte without exposing the
//! stack's seed. The media engine's derives SRTP master keys and is written
//! nowhere. Sharing one would put every key into every recording.

use core::fmt;

use super::secret::wipe;
use super::sha2::sha256;

/// A seed, and the blocks drawn from it.
///
/// Not `Clone`: two copies hand out the same blocks twice.
pub struct KeySource {
    seed: [u8; 32],
    counter: u64,
    /// Whether each block also replaces the seed ([`KeySource::forward_secure`]).
    ratchet: bool,
}

impl KeySource {
    /// Start from the caller's seed.
    ///
    /// No two sources may get the same 32 bytes, and the media seed must not
    /// be the endpoint seed.
    #[must_use]
    pub const fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            ratchet: false,
        }
    }

    /// Start from the caller's seed, with forward secrecy.
    ///
    /// Each block is `SHA-256(0x00 || seed || counter)`, then the seed is
    /// replaced by `SHA-256(0x01 || seed || counter)`. Reading this source's
    /// memory reveals future blocks but none already handed out (RFC 4086
    /// §6.2), so not the SRTP keys of earlier calls. Used by the media engine;
    /// the endpoint stream stays on [`KeySource::new`] because replays
    /// reproduce it from its seed.
    #[must_use]
    pub const fn forward_secure(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            ratchet: true,
        }
    }

    /// `SHA-256(seed || counter)`, then the counter moves on (or, made
    /// [`KeySource::forward_secure`], the ratchet turns).
    ///
    /// The first block is drawn at counter zero. Every branch, tag and
    /// `Call-ID` depends on that order, and recordings replay only while it
    /// holds.
    pub fn block(&mut self) -> [u8; 32] {
        let counter = self.counter.to_be_bytes();
        self.counter = self.counter.wrapping_add(1);
        if self.ratchet {
            return self.turn(counter);
        }
        let mut input = [0_u8; 40];
        for (slot, byte) in input.iter_mut().zip(self.seed.iter().chain(counter.iter())) {
            *slot = *byte;
        }
        let digest = sha256(&input);
        wipe(&mut input);
        digest
    }

    fn turn(&mut self, counter: [u8; 8]) -> [u8; 32] {
        let mut input = [0_u8; 41];
        for (slot, byte) in input
            .iter_mut()
            .skip(1)
            .zip(self.seed.iter().chain(counter.iter()))
        {
            *slot = *byte;
        }
        let block = sha256(&input);
        if let Some(label) = input.first_mut() {
            *label = 1;
        }
        let mut next = sha256(&input);
        wipe(&mut input);
        self.seed.copy_from_slice(&next);
        wipe(&mut next);
        block
    }

    #[cfg(test)]
    pub(crate) const fn state(&self) -> [u8; 32] {
        self.seed
    }

    /// A separate stream seeded with `SHA-256(label || seed)`. One way: neither
    /// stream reveals the other. Each replay recording gets its seed from
    /// here, never the endpoint's own.
    pub(crate) fn derived(&self, label: &[u8]) -> Self {
        let mut input = Vec::with_capacity(label.len() + self.seed.len());
        input.extend_from_slice(label);
        input.extend_from_slice(&self.seed);
        let seed = sha256(&input);
        wipe(&mut input);
        Self::new(seed)
    }
}

/// Written by hand so the seed never reaches a log: the media engine, the
/// endpoint and the user agent all derive `Debug`.
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

    /// G2: a forward-secure source is still a stream, but the state left after
    /// a draw cannot draw any block already handed out.
    #[test]
    fn a_forward_secure_source_keeps_nothing_that_draws_its_past_blocks() {
        let mut one = KeySource::forward_secure([7; 32]);
        let mut again = KeySource::forward_secure([7; 32]);
        let mut drawn = Vec::new();
        for _ in 0..64 {
            let block = one.block();
            assert_eq!(block, again.block());
            assert!(!drawn.contains(&block), "a block repeated");
            drawn.push(block);
        }
        let left = one.state();
        assert_ne!(left, [7; 32], "the seed it started from is still there");
        let mut plain = KeySource::new(left);
        let mut turned = KeySource::forward_secure(left);
        for _ in 0..64 {
            assert!(!drawn.contains(&plain.block()));
            assert!(!drawn.contains(&turned.block()));
        }
        assert_ne!(
            KeySource::forward_secure([7; 32]).block(),
            KeySource::new([7; 32]).block(),
            "the two kinds of stream share a block"
        );
    }

    #[test]
    fn the_seed_does_not_reach_a_log() {
        // this type sits inside the facade an application prints
        let source = KeySource::new([0xab; 32]);
        let printed = format!("{source:?}");
        assert!(!printed.contains("ab"), "{printed}");
        assert!(!printed.contains("171"), "{printed}");
        assert_eq!(printed, "KeySource(<redacted>)");
    }
}
