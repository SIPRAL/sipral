// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Unguessable strings (branch §8.1.1.7, `Call-ID` §8.1.1.4, tag §19.3,
//! `cnonce`) from entropy the caller gives.
//!
//! The caller supplies 32 bytes once; each value is `SHA-256(seed ||
//! counter)`. Unique, unpredictable without the seed, and reproducible in
//! tests. The library never opens `/dev/urandom` itself.

use std::time::Duration;

use crate::auth::KeySource;
use crate::auth::digest::hex;

/// A stream of tokens derived from one seed. The seed sits in a
/// [`KeySource`], which does not print it: `{:?}` on an `Endpoint` reaches here.
#[derive(Debug)]
pub(crate) struct Tokens {
    keys: KeySource,
    /// Source of the seeds after the caller's ([`Tokens::reseed`]). Never drawn
    /// for the wire, so a handed-out seed does not predict later ones.
    ratchet: KeySource,
}

/// The label [`Tokens::reseed`]'s stream is derived under.
const RATCHET: &[u8] = b"sipral endpoint seeds after the first";

impl Tokens {
    /// Start from the caller's seed.
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        let keys = KeySource::new(seed);
        let ratchet = keys.derived(RATCHET);
        Self { keys, ratchet }
    }

    /// Restart from the next ratchet block and return the new seed. Replay
    /// recordings carry this, never the caller's seed.
    pub(crate) fn reseed(&mut self) -> [u8; 32] {
        let seed = self.ratchet.block();
        self.keys = KeySource::new(seed);
        seed
    }

    /// A fresh token: 32 hex characters (128 bits of a SHA-256 digest).
    pub(crate) fn token(&mut self) -> Box<[u8]> {
        let digest = self.draw();
        hex(digest.get(..16).unwrap_or_default())
            .into_bytes()
            .into_boxed_slice()
    }

    /// A `Via` branch: the magic cookie of §8.1.1.7 and a fresh token.
    pub(crate) fn branch(&mut self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(39);
        out.extend_from_slice(crate::msg::MAGIC_COOKIE);
        out.extend_from_slice(&self.token());
        out.into_boxed_slice()
    }

    /// A number in `1..=upper`. RFC 3262 §3 wants the first `RSeq` "chosen
    /// uniformly", so it does not leak a call count.
    pub(crate) fn number(&mut self, upper: u32) -> u32 {
        if upper == 0 {
            return 0;
        }
        let digest = self.draw();
        let mut value = 0_u32;
        for byte in digest.iter().take(4) {
            value = (value << 8) | u32::from(*byte);
        }
        value % upper + 1
    }

    /// An interval in `low..=high`, in 10 ms steps: the 491 back-off (§14.1)
    /// and random `Retry-After` (§14.2). Fixed back-offs collide again.
    pub(crate) fn interval(&mut self, low: Duration, high: Duration) -> Duration {
        const STEP: Duration = Duration::from_millis(10);
        let steps = |span: Duration| u32::try_from(span.as_millis() / 10).unwrap_or(u32::MAX);
        let (low, high) = (steps(low), steps(high));
        let span = high.saturating_sub(low);
        STEP * (low + self.number(span.saturating_add(1)).saturating_sub(1))
    }

    /// An interval in the top fifth below `upper`. RFC 5626 §4.4.1 requires
    /// this so clients registered together do not ping in lockstep.
    pub(crate) fn jitter(&mut self, upper: Duration) -> Duration {
        let digest = self.draw();
        let mut fraction = 0_u32;
        for byte in digest.iter().take(4) {
            fraction = (fraction << 8) | u32::from(*byte);
        }
        let nanos = u64::try_from(upper.as_nanos()).unwrap_or(u64::MAX);
        let span = nanos / 5;
        let taken = u128::from(span) * u128::from(fraction) / u128::from(u32::MAX);
        Duration::from_nanos(nanos.saturating_sub(u64::try_from(taken).unwrap_or(span)))
    }

    /// The next block of the stream.
    fn draw(&mut self) -> [u8; 32] {
        self.keys.block()
    }
}

#[cfg(test)]
mod tests {
    use super::Tokens;
    use crate::msg::MAGIC_COOKIE;
    use std::collections::HashSet;
    use std::time::Duration;

    fn tokens(seed: u8) -> Tokens {
        Tokens::new([seed; 32])
    }

    #[test]
    fn a_token_is_thirty_two_hex_characters() {
        let token = tokens(1).token();
        assert_eq!(token.len(), 32);
        assert!(
            token.iter().all(u8::is_ascii_hexdigit),
            "not hexadecimal: {token:?}"
        );
    }

    #[test]
    fn no_token_repeats() {
        let mut source = tokens(7);
        let mut seen = HashSet::new();
        for _ in 0..1_000 {
            assert!(seen.insert(source.token()), "a token came round twice");
        }
    }

    #[test]
    fn two_endpoints_with_different_seeds_share_nothing() {
        // two softphones behind one NAT must not share a branch
        let mut left = tokens(1);
        let mut right = tokens(2);
        let mine: HashSet<_> = (0..100).map(|_| left.token()).collect();
        for _ in 0..100 {
            assert!(!mine.contains(&right.token()));
        }
    }

    #[test]
    fn the_same_seed_replays_the_same_stream() {
        let first: Vec<_> = (0..5).map(|_| tokens(3).token()).collect();
        let mut source = tokens(3);
        assert_eq!(first.first().map(AsRef::as_ref), Some(&*source.token()));
    }

    #[test]
    fn a_branch_wears_the_magic_cookie() {
        let branch = tokens(4).branch();
        assert!(branch.starts_with(MAGIC_COOKIE));
        assert_eq!(branch.len(), MAGIC_COOKIE.len() + 32);
    }

    #[test]
    fn a_number_lands_inside_its_range_and_moves_about_in_it() {
        let mut source = tokens(8);
        let mut distinct = HashSet::new();
        for _ in 0..500 {
            let value = source.number(2_147_483_647);
            assert!(value >= 1, "zero is not in 1..=upper");
            assert!(value <= 2_147_483_647);
            distinct.insert(value);
        }
        assert!(distinct.len() > 400, "the draw is barely moving");
        assert_eq!(source.number(1), 1);
        assert_eq!(source.number(0), 0, "an empty range has no answer");
    }

    #[test]
    fn a_jittered_interval_lands_in_the_top_fifth_below_the_bound() {
        let mut source = tokens(5);
        let upper = Duration::from_secs(25);
        let lower = Duration::from_secs(20);
        let mut distinct = HashSet::new();
        for _ in 0..200 {
            let interval = source.jitter(upper);
            assert!(interval <= upper, "{interval:?} is above the bound");
            assert!(interval >= lower, "{interval:?} is more than 20% below");
            distinct.insert(interval);
        }
        assert!(distinct.len() > 100, "the interval is barely moving");
    }

    #[test]
    fn a_zero_bound_stays_zero() {
        assert_eq!(tokens(6).jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn an_interval_lands_inside_its_range_on_a_ten_millisecond_step() {
        // §14.1's first case: 2.1 to 4 seconds, in units of 10 ms
        let mut source = tokens(9);
        let (low, high) = (Duration::from_millis(2_100), Duration::from_secs(4));
        let mut distinct = HashSet::new();
        for _ in 0..500 {
            let interval = source.interval(low, high);
            assert!(interval >= low, "{interval:?} is below the range");
            assert!(interval <= high, "{interval:?} is above the range");
            assert_eq!(interval.as_millis() % 10, 0, "not a ten millisecond step");
            distinct.insert(interval);
        }
        assert!(distinct.len() > 100, "the draw is barely moving");
    }

    #[test]
    fn an_interval_with_no_room_is_the_bound_itself() {
        let mut source = tokens(10);
        let fixed = Duration::from_millis(2_100);
        assert_eq!(source.interval(fixed, fixed), fixed);
        // §14.2's range starts at zero, and zero is a legitimate draw
        let low = source.interval(Duration::ZERO, Duration::ZERO);
        assert_eq!(low, Duration::ZERO);
    }
}
