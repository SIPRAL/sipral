// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The header fields that carry a number, and CSeq, which carries one and a
//! method.
//!
//! Two things here are not obvious.
//!
//! The separator inside `CSeq` and `RAck` is `LWS = [*WSP CRLF] 1*WSP`
//! (RFC 3261 §25.1), not a space. RFC 4475's `wsinv` sends
//! `cseq: 0009\r\n  INVITE`, with the fold sitting between the digits and the
//! method, and it is a *valid* message.
//!
//! And overflow is not one rule. A `CSeq` sequence number that does not fit in
//! 32 bits has to be refused, because RFC 3261 §8.1.1.5 requires the value to
//! be expressible in 32 bits and RFC 4475 §3.1.2.4 says such a message draws a
//! 400. An over-large `Expires` is a range problem the application can recover
//! from — the same RFC section says an element "could treat them as if they
//! contained the default values" — so it parses, and says the value did not
//! fit rather than pretending it did.

use super::error::HeaderError;
use super::lex::{fields, trim};
use super::method::Method;

/// A `1*DIGIT` run, and whether it fits.
///
/// `value` is `None` when every byte was a digit but the number is larger than
/// `u32::MAX`. Nothing is wrapped or saturated: RFC 4475 `scalar02` carries an
/// `Expires` over a hundred digits long and a `CSeq` of about 2^65, and a
/// truncating conversion turns both into a plausible small number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digits {
    /// The number, if it fits in 32 bits.
    pub value: Option<u32>,
    /// How many digits were written, leading zeroes included.
    pub written: usize,
}

impl Digits {
    /// The number, refusing one that does not fit.
    ///
    /// # Errors
    /// [`HeaderError::OutOfRange`] when the digits are legal but too large.
    pub const fn require(self) -> Result<u32, HeaderError> {
        match self.value {
            Some(v) => Ok(v),
            None => Err(HeaderError::OutOfRange),
        }
    }
}

/// Read a `1*DIGIT` run. No sign, no whitespace, no other byte.
///
/// A leading `-` is a grammar mismatch at the first byte, not a negative
/// number: `1*DIGIT` has no sign, and RFC 4475 `ncl` exists to catch a parser
/// that reaches for a signed conversion.
///
/// # Errors
/// [`HeaderError::Malformed`] when the value is empty or holds a non-digit.
pub fn digits(value: &[u8]) -> Result<Digits, HeaderError> {
    let v = trim(value);
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return Err(HeaderError::Malformed("expected digits"));
    }
    let mut acc: Option<u32> = Some(0);
    for &d in v {
        acc = acc
            .and_then(|a| a.checked_mul(10))
            .and_then(|a| a.checked_add(u32::from(d - b'0')));
    }
    Ok(Digits {
        value: acc,
        written: v.len(),
    })
}

/// `CSeq: 1*DIGIT LWS Method` (RFC 3261 §20.16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CSeq<'a> {
    /// The sequence number. Always fits: a larger one is refused.
    pub seq: u32,
    /// The method, compared case-sensitively, and deliberately not checked
    /// against the request line — RFC 4475 `mismatch01` and `mismatch02` are
    /// about a disagreement the transaction layer notices, not the grammar.
    pub method: Method<'a>,
}

impl<'a> CSeq<'a> {
    /// Read a `CSeq` value.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] on a grammar mismatch, or
    /// [`HeaderError::OutOfRange`] when the sequence number needs more than 32
    /// bits, which RFC 3261 §8.1.1.5 does not allow.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let mut parts = fields(value);
        let (Some(num), Some(method), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(HeaderError::Malformed("CSeq is a number and a method"));
        };
        let seq = digits(num)?.require()?;
        let method = Method::from_bytes(method)
            .ok_or(HeaderError::Malformed("CSeq method is not a token"))?;
        Ok(Self { seq, method })
    }
}

/// `RAck: response-num LWS CSeq-num LWS Method` (RFC 3262 §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RAck<'a> {
    /// The `RSeq` of the provisional response being acknowledged.
    pub response_num: u32,
    /// The sequence number of the request it belonged to.
    pub cseq_num: u32,
    /// That request's method.
    pub method: Method<'a>,
}

impl<'a> RAck<'a> {
    /// Read an `RAck` value.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] or [`HeaderError::OutOfRange`].
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let mut parts = fields(value);
        let (Some(rseq), Some(cseq), Some(method), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(HeaderError::Malformed("RAck is two numbers and a method"));
        };
        Ok(Self {
            response_num: digits(rseq)?.require()?,
            cseq_num: digits(cseq)?.require()?,
            method: Method::from_bytes(method)
                .ok_or(HeaderError::Malformed("RAck method is not a token"))?,
        })
    }
}

/// Read an `RSeq` value (RFC 3262 §7.1).
///
/// The range is 1 to 2^32-1, not 0 to 2^32-1: "It contains a single numeric
/// value from 1 to 2**32 - 1." Zero is a legal digit run and not a legal RSeq.
///
/// # Errors
/// [`HeaderError::Malformed`], or [`HeaderError::OutOfRange`] for zero or for
/// a number that does not fit.
pub fn rseq(value: &[u8]) -> Result<u32, HeaderError> {
    match digits(value)?.require()? {
        0 => Err(HeaderError::OutOfRange),
        n => Ok(n),
    }
}

/// `Date: Fri, 01 Jan 2010 16:00:00 GMT` (RFC 3261 §20.17).
///
/// ```text
/// rfc1123-date  =  wkday "," SP date1 SP time SP "GMT"
/// date1         =  2DIGIT SP month SP 4DIGIT
/// time          =  2DIGIT ":" 2DIGIT ":" 2DIGIT
/// ```
///
/// Only GMT, and only this one format — §20.17 narrows RFC 1123, which allows
/// any zone, down to the one that needs no table to interpret. The names are
/// case-sensitive, which the same section says outright: `EST` is not a zone
/// this can read, and neither is `UT`, `UTC` or `GMt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SipDate {
    /// Monday is 0. Not checked against the date, which is the sender's
    /// business.
    pub weekday: u8,
    /// 1 to 31.
    pub day: u8,
    /// January is 1.
    pub month: u8,
    /// Four digits, as written.
    pub year: u16,
    /// 0 to 23.
    pub hour: u8,
    /// 0 to 59.
    pub minute: u8,
    /// 0 to 60, the last for a leap second.
    pub second: u8,
}

const WEEKDAYS: [&[u8]; 7] = [b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];
const MONTHS: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

impl SipDate {
    /// Read a `Date` value.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] for anything that is not exactly an RFC 1123
    /// date in GMT. RFC 4475 §3.1.2.9 is an INVITE whose only fault is the
    /// zone.
    pub fn parse(value: &[u8]) -> Result<Self, HeaderError> {
        let mut parts = fields(value);
        let mut next = || {
            parts
                .next()
                .ok_or(HeaderError::Malformed("Date is too short"))
        };
        let wkday = next()?;
        let day = next()?;
        let month = next()?;
        let year = next()?;
        let time = next()?;
        let zone = next()?;
        if parts.next().is_some() {
            return Err(HeaderError::Malformed("Date has trailing text"));
        }
        if zone != b"GMT" {
            return Err(HeaderError::Malformed("Date is GMT or nothing"));
        }

        let wkday = wkday
            .strip_suffix(b",")
            .ok_or(HeaderError::Malformed("Date has no comma after the day"))?;
        let weekday = index_of(&WEEKDAYS, wkday)
            .ok_or(HeaderError::Malformed("Date has an unknown weekday"))?;
        let month =
            index_of(&MONTHS, month).ok_or(HeaderError::Malformed("Date has an unknown month"))?;

        let (hour, rest) = split_at_colon(time)?;
        let (minute, second) = split_at_colon(rest)?;

        Ok(Self {
            weekday,
            day: small(day, 1, 31)?,
            month: month + 1,
            year: fixed(year, 4)?,
            hour: small(hour, 0, 23)?,
            minute: small(minute, 0, 59)?,
            // 60 is a leap second, which is a real value on a real wire
            second: small(second, 0, 60)?,
        })
    }
}

fn index_of(table: &[&[u8]], name: &[u8]) -> Option<u8> {
    // case-sensitive: 20.17 says an RFC 1123 date is
    let at = table.iter().position(|n| *n == name)?;
    u8::try_from(at).ok()
}

fn split_at_colon(v: &[u8]) -> Result<(&[u8], &[u8]), HeaderError> {
    let at = v
        .iter()
        .position(|&b| b == b':')
        .ok_or(HeaderError::Malformed("Date has no time"))?;
    Ok((
        v.get(..at).unwrap_or_default(),
        v.get(at + 1..).unwrap_or_default(),
    ))
}

/// A run of exactly `width` digits. The grammar counts them, so `1 Jan` and
/// `001 Jan` are both wrong.
fn fixed(v: &[u8], width: usize) -> Result<u16, HeaderError> {
    if v.len() != width || !v.iter().all(u8::is_ascii_digit) {
        return Err(HeaderError::Malformed("Date has a malformed number"));
    }
    Ok(v.iter().fold(0_u16, |a, &d| a * 10 + u16::from(d - b'0')))
}

/// Two digits, in range.
fn small(v: &[u8], low: u16, high: u16) -> Result<u8, HeaderError> {
    let n = fixed(v, 2)?;
    if n < low || n > high {
        return Err(HeaderError::Malformed("Date is out of range"));
    }
    u8::try_from(n).map_err(|_| HeaderError::Malformed("Date is out of range"))
}

#[cfg(test)]
mod tests {
    use super::{CSeq, Digits, RAck, SipDate, digits, rseq};
    use crate::msg::{HeaderError, Method};

    #[test]
    fn a_plain_cseq() {
        let c = CSeq::parse(b"314159 INVITE").expect("a CSeq");
        assert_eq!(c.seq, 314_159);
        assert_eq!(c.method, Method::Invite);
    }

    #[test]
    fn the_separator_inside_cseq_may_be_a_fold() {
        // RFC 4475 3.1.1.1 wsinv sends exactly this, and it is a valid message
        let c = CSeq::parse(b"0009\r\n  INVITE").expect("a CSeq");
        assert_eq!(c.seq, 9);
        assert_eq!(c.method, Method::Invite);
    }

    #[test]
    fn the_separator_may_also_be_several_spaces_or_a_tab() {
        assert_eq!(CSeq::parse(b"1 \t  BYE").expect("a CSeq").seq, 1);
        assert_eq!(
            CSeq::parse(b"  2\tACK  ").expect("a CSeq").method,
            Method::Ack
        );
    }

    #[test]
    fn leading_zeroes_are_kept_in_the_count_but_not_the_value() {
        let d = digits(b"0009").expect("digits");
        assert_eq!(d.value, Some(9));
        assert_eq!(d.written, 4);
    }

    #[test]
    fn a_cseq_method_is_not_checked_against_the_request_line() {
        // RFC 4475 3.1.2.17 and 3.1.2.18: the disagreement is real, but it is
        // the transaction layer's to notice, not this grammar's
        let c = CSeq::parse(b"8 INVITE").expect("a CSeq");
        assert_eq!(c.method, Method::Invite);
        let c = CSeq::parse(b"8 NEWMETHOD").expect("a CSeq");
        assert_eq!(c.method, Method::Extension("NEWMETHOD"));
    }

    #[test]
    fn a_cseq_that_needs_more_than_32_bits_is_refused() {
        // RFC 4475 3.1.2.4 scalar02: this one draws a 400
        assert_eq!(
            CSeq::parse(b"36893488147419103232 INVITE"),
            Err(HeaderError::OutOfRange)
        );
    }

    #[test]
    fn an_overlarge_expires_parses_and_says_it_did_not_fit() {
        // the same RFC section calls this recoverable, so it is not a refusal
        let d = digits(b"4294967296").expect("digits");
        assert_eq!(d.value, None);
        assert_eq!(d.require(), Err(HeaderError::OutOfRange));

        let hundred = vec![b'9'; 101];
        let d = digits(&hundred).expect("digits");
        assert_eq!(d.value, None);
        assert_eq!(d.written, 101);
    }

    #[test]
    fn u32_max_still_fits() {
        assert_eq!(digits(b"4294967295").expect("digits").value, Some(u32::MAX));
    }

    #[test]
    fn a_negative_number_is_a_grammar_mismatch_not_a_negative_number() {
        // RFC 4475 3.1.2.3 ncl
        assert!(matches!(digits(b"-999"), Err(HeaderError::Malformed(_))));
        assert!(matches!(digits(b"+1"), Err(HeaderError::Malformed(_))));
        assert!(matches!(digits(b""), Err(HeaderError::Malformed(_))));
        assert!(matches!(digits(b"12a"), Err(HeaderError::Malformed(_))));
        assert!(matches!(digits(b"1 2"), Err(HeaderError::Malformed(_))));
    }

    #[test]
    fn a_malformed_cseq_is_refused() {
        assert!(matches!(
            CSeq::parse(b"INVITE"),
            Err(HeaderError::Malformed(_))
        ));
        assert!(matches!(CSeq::parse(b"1"), Err(HeaderError::Malformed(_))));
        assert!(matches!(
            CSeq::parse(b"1 INVITE extra"),
            Err(HeaderError::Malformed(_))
        ));
        assert!(matches!(CSeq::parse(b""), Err(HeaderError::Malformed(_))));
    }

    #[test]
    fn rseq_starts_at_one_unlike_every_other_counter_here() {
        assert_eq!(rseq(b"1"), Ok(1));
        assert_eq!(rseq(b"4294967295"), Ok(u32::MAX));
        assert_eq!(rseq(b"0"), Err(HeaderError::OutOfRange));
    }

    #[test]
    fn rack_carries_two_numbers_and_a_method() {
        let r = RAck::parse(b"776656 1 INVITE").expect("an RAck");
        assert_eq!(r.response_num, 776_656);
        assert_eq!(r.cseq_num, 1);
        assert_eq!(r.method, Method::Invite);

        // folded, like CSeq can be
        let r = RAck::parse(b"1\r\n\t2\r\n PRACK").expect("an RAck");
        assert_eq!(r.method, Method::Prack);

        assert!(matches!(
            RAck::parse(b"1 INVITE"),
            Err(HeaderError::Malformed(_))
        ));
    }

    #[test]
    fn nothing_makes_the_scalar_parsers_panic() {
        for len in 0..10_usize {
            for seed in 0..96_u8 {
                let v: Vec<u8> = (0..len)
                    .map(|i| {
                        let b = seed
                            .wrapping_mul(41)
                            .wrapping_add(u8::try_from(i).unwrap_or(0));
                        match b % 6 {
                            0 => b' ',
                            1 => b'\r',
                            2 => b'\n',
                            3 => b'0' + b % 10,
                            _ => b,
                        }
                    })
                    .collect();
                let _ = digits(&v);
                let _ = CSeq::parse(&v);
                let _ = RAck::parse(&v);
                let _ = rseq(&v);
            }
        }
    }

    #[test]
    fn digits_is_copy_and_comparable() {
        let a = Digits {
            value: Some(1),
            written: 1,
        };
        assert_eq!(a, digits(b"1").expect("digits"));
    }

    #[test]
    fn a_date_in_gmt() {
        // RFC 3261 20.17's own example
        let d = SipDate::parse(b"Sat, 13 Nov 2010 23:29:00 GMT").expect("a date");
        assert_eq!(d.weekday, 5);
        assert_eq!((d.day, d.month, d.year), (13, 11, 2010));
        assert_eq!((d.hour, d.minute, d.second), (23, 29, 0));
    }

    #[test]
    fn a_date_folded_between_its_pieces_still_reads() {
        let d = SipDate::parse(b"Fri,\r\n 01 Jan 2010\r\n\t16:00:00 GMT").expect("a date");
        assert_eq!((d.day, d.month, d.year), (1, 1, 2010));
    }

    #[test]
    fn only_gmt_and_only_this_spelling() {
        // RFC 4475 3.1.2.9 baddate: the zone is the whole fault
        for bad in [
            &b"Fri, 01 Jan 2010 16:00:00 EST"[..],
            b"Fri, 01 Jan 2010 16:00:00 UT",
            b"Fri, 01 Jan 2010 16:00:00 UTC",
            b"Fri, 01 Jan 2010 16:00:00 gmt",
            b"Fri, 01 Jan 2010 16:00:00",
        ] {
            assert!(matches!(
                SipDate::parse(bad),
                Err(HeaderError::Malformed(_))
            ));
        }
    }

    #[test]
    fn the_names_and_the_digit_counts_are_exact() {
        // 20.17: an RFC 1123 date is case-sensitive
        for bad in [
            &b"fri, 01 Jan 2010 16:00:00 GMT"[..],
            b"Fri, 01 JAN 2010 16:00:00 GMT",
            b"Fri 01 Jan 2010 16:00:00 GMT",
            b"Xyz, 01 Jan 2010 16:00:00 GMT",
            b"Fri, 1 Jan 2010 16:00:00 GMT",
            b"Fri, 01 Jan 10 16:00:00 GMT",
            b"Fri, 01 Jan 2010 16:00 GMT",
            b"Fri, 32 Jan 2010 16:00:00 GMT",
            b"Fri, 01 Jan 2010 24:00:00 GMT",
            b"Fri, 01 Jan 2010 16:60:00 GMT",
            b"Fri, 01 Jan 2010 16:00:00 GMT extra",
            b"",
        ] {
            assert!(
                matches!(SipDate::parse(bad), Err(HeaderError::Malformed(_))),
                "{} was accepted",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_leap_second_is_a_real_value() {
        assert_eq!(
            SipDate::parse(b"Sat, 31 Dec 2016 23:59:60 GMT")
                .expect("a date")
                .second,
            60
        );
    }

    #[test]
    fn nothing_makes_the_date_parser_panic() {
        for len in 0..12_usize {
            for seed in 0..80_u8 {
                let v: Vec<u8> = (0..len)
                    .map(|i| {
                        let b = seed
                            .wrapping_mul(19)
                            .wrapping_add(u8::try_from(i).unwrap_or(0));
                        match b % 5 {
                            0 => b',',
                            1 => b':',
                            2 => b' ',
                            _ => b,
                        }
                    })
                    .collect();
                let _ = SipDate::parse(&v);
            }
        }
    }
}
