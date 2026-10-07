// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The one number a sans-I/O stack cannot work out itself.
//!
//! Nothing in this tree reads a clock, but an RTCP sender report must carry "the wall clock time
//! when this report was sent" in NTP form (RFC 3550 §6.4.1). So the caller states once what the
//! wall clock read at a given instant, and later timestamps follow from the monotonic distance.
//! That also keeps report times from going backwards when a time service steps the clock, which
//! would corrupt the far end's round-trip calculation.

use std::time::{Duration, Instant};

/// Seconds from the NTP epoch (1900) to the Unix epoch (1970): seventy years with seventeen leap
/// days.
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// The wall clock at a known instant, so reports can carry it without reading a clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallClock {
    origin: Instant,
    ntp: u64,
}

impl WallClock {
    /// The wall clock read `ntp` at instant `at`, in RFC 3550 §4's 64-bit form: seconds since 1900
    /// above, a binary fraction below.
    #[must_use]
    pub const fn new(at: Instant, ntp: u64) -> Self {
        Self { origin: at, ntp }
    }

    /// The same from Unix seconds and nanoseconds, as `SystemTime::duration_since(UNIX_EPOCH)`
    /// gives.
    #[must_use]
    pub fn from_unix(at: Instant, seconds: u64, nanos: u32) -> Self {
        Self::new(at, ntp_from_unix(seconds, nanos))
    }

    /// The wall clock at `now`, for a report. A `now` before the origin cannot happen with
    /// monotonic instants; if forced, the origin is returned.
    #[must_use]
    pub fn at(&self, now: Instant) -> u64 {
        self.ntp
            .saturating_add(ntp_ticks(now.saturating_duration_since(self.origin)))
    }

    /// The wall clock at `now` in whole Unix seconds, for certificate validity periods (RFC 5280
    /// §4.1.2.5). Same clock and origin rule as the reports.
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

/// Nanoseconds as a binary fraction of a second, exactly: below 10^9, so shifting by 32 fits in 64
/// bits.
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
        // certificates use Unix seconds and reports NTP ticks; a mismatch would date a certificate
        // seventy years off
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

    /// Half a second must be exactly the top bit of the fraction, or the far end's round-trip time
    /// is off.
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
