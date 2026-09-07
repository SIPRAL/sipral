// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The unguessable strings a SIP stack has to produce, from entropy it is
//! given rather than entropy it goes looking for.
//!
//! A `branch` has to be unique across space and time (RFC 3261 §8.1.1.7), a
//! `Call-ID` "cryptographically random" (§8.1.1.4), a tag likewise (§19.3),
//! and a `cnonce` unpredictable or the digest exchange loses the protection
//! the counter gives it. That is four kinds of value with one requirement
//! between them, and none of it can be met by reading a clock or counting.
//!
//! Nothing here draws a random number. The caller supplies thirty-two bytes
//! once, and every value after that is `SHA-256(seed || counter)`: unique
//! because the counter never repeats, unpredictable to anyone who does not
//! have the seed, and reproducible in a test that supplies a fixed one. The
//! seed is the caller's problem for the same reason the clock and the socket
//! are — a library that opens `/dev/urandom` behind the caller's back is a
//! library that cannot run where the caller needs it to.

use std::time::Duration;

use crate::auth::digest::hex;
use crate::auth::sha2::sha256;

/// A stream of tokens derived from one seed.
#[derive(Debug)]
pub(crate) struct Tokens {
    seed: [u8; 32],
    counter: u64,
}

impl Tokens {
    /// Start from the caller's seed.
    pub(crate) const fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    /// A fresh token: 32 hexadecimal characters.
    ///
    /// Half a SHA-256 digest, which is 128 bits — more than enough that no
    /// two ever collide, and short enough that putting one in every `Via` of
    /// every retransmitted request does not cost a fragment.
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

    /// A number in `1..=upper`, drawn evenly.
    ///
    /// RFC 3262 §3 asks for the first `RSeq` of a transaction to be "chosen
    /// uniformly" in a range, so that a number on the wire says nothing about
    /// how many calls this endpoint has taken.
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

    /// An interval drawn evenly from `low..=high`, in steps of ten
    /// milliseconds.
    ///
    /// RFC 3261 §14.1 asks for the 491 back-off "in units of 10 ms", and
    /// §14.2 for a `Retry-After` "randomly chosen ... between 0 and 10
    /// seconds". Two implementations that back off by the same amount collide
    /// again, which is the whole reason the interval is drawn rather than
    /// fixed.
    pub(crate) fn interval(&mut self, low: Duration, high: Duration) -> Duration {
        const STEP: Duration = Duration::from_millis(10);
        let steps = |span: Duration| u32::try_from(span.as_millis() / 10).unwrap_or(u32::MAX);
        let (low, high) = (steps(low), steps(high));
        let span = high.saturating_sub(low);
        STEP * (low + self.number(span.saturating_add(1)).saturating_sub(1))
    }

    /// An interval at or just under `upper`.
    ///
    /// RFC 5626 §4.4.1: "The UA MUST select a random number between a fixed
    /// or configurable upper bound and a lower bound, where the lower bound
    /// is 20% less then the upper bound." Without it every client that
    /// registered during the same outage pings the server in the same
    /// millisecond for as long as they all stay up.
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

    /// `SHA-256(seed || counter)`, and the counter moves on.
    fn draw(&mut self) -> [u8; 32] {
        let counter = self.counter.to_be_bytes();
        self.counter = self.counter.wrapping_add(1);
        let mut input = [0_u8; 40];
        for (slot, byte) in input.iter_mut().zip(self.seed.iter().chain(counter.iter())) {
            *slot = *byte;
        }
        sha256(&input)
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
        // the whole point of the seed: two softphones behind one NAT must not
        // put the same branch on the wire
        let mut left = tokens(1);
        let mut right = tokens(2);
        let mine: HashSet<_> = (0..100).map(|_| left.token()).collect();
        for _ in 0..100 {
            assert!(!mine.contains(&right.token()));
        }
    }

    #[test]
    fn the_same_seed_replays_the_same_stream() {
        // which is what makes a test that asserts on bytes possible at all
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
