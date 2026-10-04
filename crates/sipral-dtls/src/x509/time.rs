// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Validity dates as RFC 5280 §4.1.2.5 writes them.
//!
//! "CAs conforming to this profile MUST always encode certificate validity
//! dates through the year 2049 as UTCTime; certificate validity dates in 2050
//! or later MUST be encoded as GeneralizedTime." Both in UTC, to the second,
//! with a `Z` (§4.1.2.5.1 and §4.1.2.5.2).

use core::fmt::Write as _;

use super::der;
use crate::Error;

const SECONDS_PER_DAY: u64 = 86_400;
/// GeneralizedTime has four digits for the year, so 9999 is the last one
/// that can be written — and RFC 5280's value for "no expiry" is its final
/// second.
const LAST_YEAR: u64 = 9999;

/// Write the `Time` for `unix_seconds` past 1970-01-01T00:00:00Z.
pub(crate) fn write(out: &mut Vec<u8>, unix_seconds: u64) -> Result<(), Error> {
    let (year, month, day) = civil_date(unix_seconds / SECONDS_PER_DAY)?;
    let seconds = unix_seconds % SECONDS_PER_DAY;
    let (hour, minute, second) = (seconds / 3600, seconds / 60 % 60, seconds % 60);

    let mut text = String::with_capacity(15);
    let tag = if year < 2050 {
        // two digits of year; a date before 1970 cannot be given here, so
        // the 1950-1999 half of UTCTime's range is never ambiguous
        write!(text, "{:02}", year % 100).map_err(|_| Error::InvalidTime)?;
        der::UTC_TIME
    } else {
        write!(text, "{year:04}").map_err(|_| Error::InvalidTime)?;
        der::GENERALIZED_TIME
    };
    write!(text, "{month:02}{day:02}{hour:02}{minute:02}{second:02}Z")
        .map_err(|_| Error::InvalidTime)?;
    der::write(out, tag, text.as_bytes())
}

const fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Year, month and day of the day `days` after 1970-01-01, counted out year
/// by year and month by month.
fn civil_date(mut days: u64) -> Result<(u64, u64, u64), Error> {
    let mut year = 1970;
    loop {
        let length = if is_leap(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        year += 1;
        if year > LAST_YEAR {
            return Err(Error::InvalidTime);
        }
    }
    let february = if is_leap(year) { 29 } else { 28 };
    let lengths = [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (month, length) in (1..).zip(lengths) {
        if days < length {
            return Ok((year, month, days + 1));
        }
        days -= length;
    }
    Err(Error::InvalidTime)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(unix_seconds: u64) -> Result<(u8, String), Error> {
        let mut out = Vec::new();
        write(&mut out, unix_seconds)?;
        Ok((out[0], String::from_utf8(out[2..].to_vec()).unwrap()))
    }

    #[test]
    fn dates_through_2049_are_utc_time_and_later_ones_generalized_time() {
        // each instant checked against `date -u -r`
        let cases = [
            (0, der::UTC_TIME, "700101000000Z"),
            (951_782_400, der::UTC_TIME, "000229000000Z"),
            (1_785_542_400, der::UTC_TIME, "260801000000Z"),
            (2_524_607_999, der::UTC_TIME, "491231235959Z"),
            (2_524_608_000, der::GENERALIZED_TIME, "20500101000000Z"),
            (253_402_300_799, der::GENERALIZED_TIME, "99991231235959Z"),
        ];
        for (seconds, tag, expected) in cases {
            assert_eq!(text(seconds), Ok((tag, expected.to_owned())), "{seconds}");
        }
    }

    #[test]
    fn a_date_past_9999_cannot_be_written() {
        assert_eq!(text(253_402_300_800), Err(Error::InvalidTime));
        assert_eq!(text(u64::MAX), Err(Error::InvalidTime));
    }

    #[test]
    fn leap_years_follow_the_gregorian_rule() {
        assert!(is_leap(2000));
        assert!(is_leap(2024));
        assert!(!is_leap(2100));
        assert!(!is_leap(2026));
        // 2100-02-28 is followed by 2100-03-01
        assert_eq!(civil_date(47_540), Ok((2100, 2, 28)));
        assert_eq!(civil_date(47_541), Ok((2100, 3, 1)));
    }
}
