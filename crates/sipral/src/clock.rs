// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The one number a sans-I/O stack cannot work out for itself.
//!
//! Everything in this tree takes `now: Instant` and reads no clock. An RTCP
//! sender report is the exception that proves the rule: RFC 3550 §6.4.1 has it
//! carry "the wall clock time when this report was sent", in NTP form, and a
//! monotonic instant is not a wall clock and cannot be turned into one.
//!
//! So the caller says, once, what the wall clock read at some instant it also
//! names, and every timestamp after that is derived from the monotonic
//! distance. That is better than reading the clock per report as well as
//! cheaper: a report interval measured against a wall clock that a time
//! service has just stepped back would be a report interval that went
//! backwards, and the far end computes a round-trip time from these.

use std::time::{Duration, Instant};

/// Seconds between the NTP epoch of 1 January 1900 and the Unix epoch of
/// 1 January 1970 — seventy years with seventeen leap days in them.
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// What the wall clock read at a known instant, so that the reports which
/// need one can have it without anybody reading a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallClock {
    origin: Instant,
    ntp: u64,
}

impl WallClock {
    /// The wall clock read `ntp` at the instant `at`, in the 64-bit form
    /// RFC 3550 §4 describes: seconds since 1900 in the upper half, a binary
    /// fraction of a second in the lower.
    #[must_use]
    pub const fn new(at: Instant, ntp: u64) -> Self {
        Self { origin: at, ntp }
    }

    /// The same, from the epoch a caller is more likely to have: seconds and
    /// nanoseconds since 1 January 1970, which is what
    /// `SystemTime::duration_since(UNIX_EPOCH)` yields.
    #[must_use]
    pub fn from_unix(at: Instant, seconds: u64, nanos: u32) -> Self {
        Self::new(at, ntp_from_unix(seconds, nanos))
    }

    /// The wall clock at `now`, for a report that has to carry one.
    ///
    /// Time before the origin cannot happen with a monotonic instant, and if a
    /// caller contrives it the answer is the origin rather than a timestamp
    /// from the last century.
    #[must_use]
    pub fn at(&self, now: Instant) -> u64 {
        self.ntp
            .saturating_add(ntp_ticks(now.saturating_duration_since(self.origin)))
    }

    /// The wall clock at `now` as whole seconds since 1 January 1970, for the
    /// one thing in this tree that needs a date rather than a timestamp: the
    /// validity period RFC 5280 §4.1.2.5 makes a certificate carry.
    ///
    /// The same clock the reports read, and the same rule about time before
    /// the origin. Seconds and not the fraction, because a period measured in
    /// months has no use for one.
    #[must_use]
    pub fn unix_at(&self, now: Instant) -> u64 {
        (self.at(now) >> 32).saturating_sub(NTP_EPOCH_OFFSET)
    }
}

/// A duration as a 64-bit NTP timestamp difference: seconds in the upper half,
/// the fraction scaled by 2^32 in the lower.
fn ntp_ticks(span: Duration) -> u64 {
    (span.as_secs() << 32) | fraction(span.subsec_nanos())
}

/// The NTP form of a Unix time.
fn ntp_from_unix(seconds: u64, nanos: u32) -> u64 {
    (seconds.wrapping_add(NTP_EPOCH_OFFSET) << 32) | fraction(nanos)
}

/// Nanoseconds as a binary fraction of a second, exactly and without floating
/// point: a nanosecond count is below 10^9, so shifting it up by 32 stays
/// inside 64 bits and the division is the whole of the conversion.
fn fraction(nanos: u32) -> u64 {
    (u64::from(nanos) << 32) / 1_000_000_000
}

#[cfg(test)]
mod tests {
    use super::{NTP_EPOCH_OFFSET, WallClock, ntp_ticks};
    use std::time::{Duration, Instant};

    #[test]
    fn the_unix_epoch_is_where_the_ntp_epoch_says_it_is() {
        let origin = Instant::now();
        let clock = WallClock::from_unix(origin, 0, 0);
        assert_eq!(clock.at(origin) >> 32, NTP_EPOCH_OFFSET);
        assert_eq!(clock.at(origin) & 0xFFFF_FFFF, 0);
    }

    #[test]
    fn the_two_epochs_come_back_to_the_same_second() {
        // the certificate half reads seconds since 1970 and the reports read
        // ticks since 1900; a difference between them would date a
        // certificate seventy years out
        let origin = Instant::now();
        for seconds in [0_u64, 1, 1_790_000_000] {
            let clock = WallClock::from_unix(origin, seconds, 500_000_000);
            assert_eq!(clock.unix_at(origin), seconds);
            assert_eq!(
                clock.unix_at(origin + Duration::from_secs(90)),
                seconds + 90
            );
        }
    }

    #[test]
    fn a_second_of_monotonic_time_is_a_second_of_wall_clock() {
        let origin = Instant::now();
        let clock = WallClock::from_unix(origin, 1_000_000_000, 0);
        let later = clock.at(origin + Duration::from_secs(1));
        assert_eq!(later >> 32, (1_000_000_000 + NTP_EPOCH_OFFSET) + 1);
    }

    /// Half a second has to land on the top bit of the fraction, or the far
    /// end's round-trip arithmetic is out by however much this is wrong.
    #[test]
    fn the_fraction_is_a_binary_fraction() {
        assert_eq!(ntp_ticks(Duration::from_millis(500)), 0x8000_0000);
        assert_eq!(ntp_ticks(Duration::from_millis(250)), 0x4000_0000);
        assert_eq!(ntp_ticks(Duration::from_secs(1)), 0x1_0000_0000);
    }

    #[test]
    fn an_instant_before_the_origin_does_not_go_back_a_century() {
        let before = Instant::now();
        let origin = before + Duration::from_secs(60);
        let clock = WallClock::from_unix(origin, 1_000, 0);
        assert_eq!(clock.at(before), clock.at(origin));
    }
}
