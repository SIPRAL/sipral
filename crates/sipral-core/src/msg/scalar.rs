// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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

#[cfg(test)]
mod tests {
    use super::{CSeq, Digits, RAck, digits, rseq};
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
}
