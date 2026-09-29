// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The TNAuthList certificate extension of RFC 8226 §9, which says which
//! telephone numbers a STIR certificate speaks for.
//!
//! ```text
//! id-pe-TNAuthList OBJECT IDENTIFIER ::= { id-pe 26 }
//!
//! TNAuthorizationList ::= SEQUENCE SIZE (1..MAX) OF TNEntry
//!
//! TNEntry ::= CHOICE {
//!   spc   [0] ServiceProviderCode,
//!   range [1] TelephoneNumberRange,
//!   one   [2] TelephoneNumber
//!   }
//!
//! ServiceProviderCode ::= IA5String
//!
//! TelephoneNumberRange ::= SEQUENCE {
//!   start TelephoneNumber,
//!   count INTEGER (2..MAX),
//!   ...
//!   }
//!
//! TelephoneNumber ::= IA5String (SIZE (1..15)) (FROM ("0123456789#*"))
//! ```
//!
//! The module that defines it uses explicit tags, so each `TNEntry` is a
//! constructed context-specific element around the universal one.

use std::fmt;

use crate::der::{self, IA5_STRING, INTEGER, SEQUENCE};
use crate::passport::{Tn, is_tn};

/// The extension's object identifier, `id-pe 26`.
pub const OID: &str = "1.3.6.1.5.5.7.1.26";

const SPC: u8 = 0xa0;
const RANGE: u8 = 0xa1;
const ONE: u8 = 0xa2;

/// One entry of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TnEntry {
    /// A service provider code: every number the provider it names serves.
    Spc(String),
    /// `count` numbers from `start` on, all as long as `start` is: `start`
    /// holds digits only, and RFC 8226 §9 has `start + count` less than
    /// `10^D` for a `start` of `D` digits.
    Range {
        /// The first number.
        start: String,
        /// How many, at least two.
        count: u64,
    },
    /// One number.
    One(String),
}

/// A TNAuthList.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TnAuthList {
    entries: Vec<TnEntry>,
}

/// The extension's value is not a TNAuthList.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTnAuthList;

impl fmt::Display for InvalidTnAuthList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a TNAuthList")
    }
}

impl std::error::Error for InvalidTnAuthList {}

/// Which entry gave a certificate authority over a number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    /// An entry naming exactly that number.
    Number,
    /// A range the number falls in.
    Range,
    /// A service provider code, which covers whatever numbers that provider
    /// serves. Which numbers those are is known to the provider's directory,
    /// not to the certificate, so accepting it is a matter of policy: see
    /// [`crate::Config::accept_service_provider_codes`].
    ServiceProvider(String),
}

impl TnAuthList {
    /// A list of these entries.
    ///
    /// # Errors
    ///
    /// [`InvalidTnAuthList`] for an empty list, a service provider code that
    /// is empty or not printable ASCII, a number that is not one to fifteen
    /// of `0123456789#*`, or a range RFC 8226 §9 calls invalid: fewer than
    /// two, a start holding `*` or `#` ("The count field is only applicable
    /// to start fields whose values do not include "*" or "#""), or one that
    /// runs into numbers longer than its start ("TelephoneNumber + count
    /// MUST be less than 10^D").
    pub fn new(entries: Vec<TnEntry>) -> Result<Self, InvalidTnAuthList> {
        let valid = !entries.is_empty()
            && entries.iter().all(|entry| match entry {
                TnEntry::Spc(code) => is_spc(code.as_bytes()),
                TnEntry::Range { start, count } => is_range(start, *count),
                TnEntry::One(number) => is_tn(number),
            });
        if valid {
            Ok(TnAuthList { entries })
        } else {
            Err(InvalidTnAuthList)
        }
    }

    /// Read the extension's value: the DER the extension's OCTET STRING
    /// holds.
    ///
    /// # Errors
    ///
    /// [`InvalidTnAuthList`] for anything that is not DER in the shape above
    /// or breaks one of the constraints [`TnAuthList::new`] checks.
    pub fn from_der(value: &[u8]) -> Result<Self, InvalidTnAuthList> {
        let list = der::only(value, SEQUENCE).map_err(|_| InvalidTnAuthList)?;
        let mut rest = list.contents;
        let mut entries = Vec::new();
        while !rest.is_empty() {
            let (entry, tail) = der::read(rest).map_err(|_| InvalidTnAuthList)?;
            rest = tail;
            entries.push(read_entry(entry.tag, entry.contents).ok_or(InvalidTnAuthList)?);
        }
        TnAuthList::new(entries)
    }

    /// The extension's value in DER.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        let mut contents = Vec::new();
        for entry in &self.entries {
            let inner = match entry {
                TnEntry::Spc(code) => der::write(SPC, &der::write(IA5_STRING, code.as_bytes())),
                TnEntry::Range { start, count } => {
                    let mut range = der::write(IA5_STRING, start.as_bytes());
                    range.extend(der::write(INTEGER, &der::unsigned_contents(*count)));
                    der::write(RANGE, &der::write(SEQUENCE, &range))
                }
                TnEntry::One(number) => der::write(ONE, &der::write(IA5_STRING, number.as_bytes())),
            };
            contents.extend(inner);
        }
        der::write(SEQUENCE, &contents)
    }

    /// The entries, in the order the certificate lists them.
    #[must_use]
    pub fn entries(&self) -> &[TnEntry] {
        &self.entries
    }

    /// Whether the list gives authority over `tn`, and through which entry:
    /// an exact number first, then a range, then — only when
    /// `accept_spc` — the first service provider code.
    #[must_use]
    pub fn covers(&self, tn: &Tn, accept_spc: bool) -> Option<Coverage> {
        let tn = tn.as_str();
        if self
            .entries
            .iter()
            .any(|entry| matches!(entry, TnEntry::One(number) if number == tn))
        {
            return Some(Coverage::Number);
        }
        if self.entries.iter().any(|entry| match entry {
            TnEntry::Range { start, count } => in_range(tn, start, *count),
            _ => false,
        }) {
            return Some(Coverage::Range);
        }
        if accept_spc {
            return self.entries.iter().find_map(|entry| match entry {
                TnEntry::Spc(code) => Some(Coverage::ServiceProvider(code.clone())),
                _ => None,
            });
        }
        None
    }
}

fn is_range(start: &str, count: u64) -> bool {
    let Some(first) = digits(start).filter(|_| is_tn(start)) else {
        return false;
    };
    // at most fifteen digits, so 10^D fits
    let limit = u32::try_from(start.len())
        .ok()
        .and_then(|d| 10_u64.checked_pow(d));
    count >= 2 && limit.is_some_and(|limit| first.checked_add(count).is_some_and(|end| end < limit))
}

fn is_spc(code: &[u8]) -> bool {
    !code.is_empty() && code.iter().all(u8::is_ascii_graphic)
}

fn ia5(input: &[u8]) -> Option<(&str, &[u8])> {
    let (string, rest) = der::expect(input, IA5_STRING).ok()?;
    let text = std::str::from_utf8(string.contents).ok()?;
    text.is_ascii().then_some((text, rest))
}

fn read_entry(tag: u8, contents: &[u8]) -> Option<TnEntry> {
    match tag {
        SPC => {
            let (code, rest) = ia5(contents)?;
            rest.is_empty().then(|| TnEntry::Spc(code.to_owned()))
        }
        ONE => {
            let (number, rest) = ia5(contents)?;
            rest.is_empty().then(|| TnEntry::One(number.to_owned()))
        }
        RANGE => {
            let range = der::only(contents, SEQUENCE).ok()?;
            let (start, rest) = ia5(range.contents)?;
            let (count, rest) = der::expect(rest, INTEGER).ok()?;
            let count = der::unsigned(count.contents).ok()?;
            // the `...` in the type admits later additions, each still an
            // element of its own: they have to parse, and are not read
            let mut rest = rest;
            while !rest.is_empty() {
                rest = der::read(rest).ok()?.1;
            }
            Some(TnEntry::Range {
                start: start.to_owned(),
                count,
            })
        }
        _ => None,
    }
}

/// Whether `tn` is one of the `count` numbers from `start` on. A range is a
/// run of numbers of one length, so a number of any other length, or one
/// holding `*` or `#`, is outside it.
fn in_range(tn: &str, start: &str, count: u64) -> bool {
    if tn.len() != start.len() {
        return false;
    }
    let (Some(tn), Some(start)) = (digits(tn), digits(start)) else {
        return false;
    };
    tn >= start && tn - start < count
}

fn digits(number: &str) -> Option<u64> {
    if number.bytes().all(|b| b.is_ascii_digit()) {
        number.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tn(number: &str) -> Tn {
        Tn::new(number).unwrap()
    }

    #[test]
    fn a_service_provider_code() {
        // SEQUENCE { [0] { IA5String "709J" } }
        let der = [0x30, 0x08, 0xa0, 0x06, 0x16, 0x04, b'7', b'0', b'9', b'J'];
        let list = TnAuthList::from_der(&der).unwrap();
        assert_eq!(list.entries(), &[TnEntry::Spc("709J".to_owned())]);
        assert_eq!(list.to_der(), der);
    }

    #[test]
    fn numbers_and_ranges_round_trip() {
        let list = TnAuthList::new(vec![
            TnEntry::One("12155551212".to_owned()),
            TnEntry::Range {
                start: "12155550000".to_owned(),
                count: 1000,
            },
            TnEntry::Spc("709J".to_owned()),
        ])
        .unwrap();
        let der = list.to_der();
        assert_eq!(TnAuthList::from_der(&der), Ok(list));
        // the range is explicitly tagged around its SEQUENCE
        let one = [0xa2, 0x0d, 0x16, 0x0b];
        assert_eq!(der.get(2..6), Some(&one[..]));
    }

    #[test]
    fn coverage_by_number_range_and_code() {
        let list = TnAuthList::new(vec![
            TnEntry::Spc("709J".to_owned()),
            TnEntry::Range {
                start: "12155550100".to_owned(),
                count: 100,
            },
            TnEntry::One("12155551212".to_owned()),
        ])
        .unwrap();
        assert_eq!(
            list.covers(&tn("12155551212"), false),
            Some(Coverage::Number)
        );
        assert_eq!(
            list.covers(&tn("12155550100"), false),
            Some(Coverage::Range)
        );
        assert_eq!(
            list.covers(&tn("12155550199"), false),
            Some(Coverage::Range)
        );
        assert_eq!(list.covers(&tn("12155550200"), false), None);
        assert_eq!(list.covers(&tn("12155550099"), false), None);
        assert_eq!(list.covers(&tn("112155550150"), false), None);
        assert_eq!(list.covers(&tn("2155550150"), false), None);
        assert_eq!(
            list.covers(&tn("12155550200"), true),
            Some(Coverage::ServiceProvider("709J".to_owned()))
        );
        assert_eq!(
            list.covers(&tn("12155551212"), true),
            Some(Coverage::Number)
        );
    }

    #[test]
    fn ranges_hold_only_digits() {
        // RFC 8226 §9: a count applies only to a start without "*" or "#"
        assert_eq!(
            TnAuthList::new(vec![TnEntry::Range {
                start: "1215555*100".to_owned(),
                count: 100,
            }]),
            Err(InvalidTnAuthList)
        );
        let plain = TnAuthList::new(vec![TnEntry::Range {
            start: "12155550100".to_owned(),
            count: 2,
        }])
        .unwrap();
        assert_eq!(plain.covers(&tn("1215555010#"), false), None);
        assert_eq!(
            plain.covers(&tn("12155550101"), false),
            Some(Coverage::Range)
        );
    }

    #[test]
    fn a_range_holds_numbers_of_its_start_length_only() {
        // 0100 to 0199: 150 and 00150 have the value of one of them, and
        // are other numbers
        let list = TnAuthList::new(vec![TnEntry::Range {
            start: "0100".to_owned(),
            count: 100,
        }])
        .unwrap();
        assert_eq!(list.covers(&tn("0150"), false), Some(Coverage::Range));
        assert_eq!(list.covers(&tn("150"), false), None);
        assert_eq!(list.covers(&tn("00150"), false), None);
    }

    #[test]
    fn a_range_may_not_run_into_longer_numbers() {
        let range = |start: &str, count: u64| {
            TnAuthList::new(vec![TnEntry::Range {
                start: start.to_owned(),
                count,
            }])
        };
        // RFC 8226 §9's own example: "a TelephoneNumberRange with
        // TelephoneNumber=10 and count=91 is invalid"
        assert_eq!(range("10", 91), Err(InvalidTnAuthList));
        // and its formal rule, TelephoneNumber + count < 10^D
        assert_eq!(range("10", 90), Err(InvalidTnAuthList));
        let widest = range("10", 89).unwrap();
        assert_eq!(widest.covers(&tn("98"), false), Some(Coverage::Range));
        assert_eq!(widest.covers(&tn("99"), false), None);
        // counts too large for any number of fifteen digits, without overflow
        assert_eq!(range("999999999999998", u64::MAX), Err(InvalidTnAuthList));
        assert_eq!(range("0", u64::MAX), Err(InvalidTnAuthList));
        let fifteen = range("999999999999990", 9).unwrap();
        assert_eq!(
            fifteen.covers(&tn("999999999999998"), false),
            Some(Coverage::Range)
        );
    }

    #[test]
    fn construction_constraints() {
        let invalid = Err(InvalidTnAuthList);
        assert_eq!(TnAuthList::new(vec![]), invalid);
        assert_eq!(TnAuthList::new(vec![TnEntry::Spc(String::new())]), invalid);
        assert_eq!(
            TnAuthList::new(vec![TnEntry::Spc("70 9J".to_owned())]),
            invalid
        );
        assert_eq!(TnAuthList::new(vec![TnEntry::One("1".repeat(16))]), invalid);
        assert_eq!(
            TnAuthList::new(vec![TnEntry::One("1-2".to_owned())]),
            invalid
        );
        let one = TnEntry::Range {
            start: "1".to_owned(),
            count: 1,
        };
        assert_eq!(TnAuthList::new(vec![one]), invalid);
    }

    #[test]
    fn range_extensions_are_skipped() {
        // SEQUENCE { [1] { SEQUENCE { "100", 5, NULL } } }
        let der = [
            0x30, 0x0e, 0xa1, 0x0c, 0x30, 0x0a, 0x16, 0x03, b'1', b'0', b'0', 0x02, 0x01, 0x05,
            0x05, 0x00,
        ];
        let list = TnAuthList::from_der(&der).unwrap();
        assert_eq!(
            list.entries(),
            &[TnEntry::Range {
                start: "100".to_owned(),
                count: 5
            }]
        );
    }

    #[test]
    fn malformed_values_are_refused() {
        let invalid = Err(InvalidTnAuthList);
        for der in [
            &[][..],
            &[0x30, 0x00],
            // implicit rather than explicit tagging
            &[0x30, 0x06, 0x80, 0x04, b'7', b'0', b'9', b'J'],
            // an unknown choice
            &[0x30, 0x08, 0xa3, 0x06, 0x16, 0x04, b'7', b'0', b'9', b'J'],
            // a UTF8String where an IA5String belongs
            &[0x30, 0x08, 0xa0, 0x06, 0x0c, 0x04, b'7', b'0', b'9', b'J'],
            // trailing octets inside the entry, and after the list
            &[
                0x30, 0x0a, 0xa0, 0x08, 0x16, 0x04, b'7', b'0', b'9', b'J', 0x05, 0x00,
            ],
            &[
                0x30, 0x08, 0xa0, 0x06, 0x16, 0x04, b'7', b'0', b'9', b'J', 0x00,
            ],
            // a number with a letter in it
            &[0x30, 0x07, 0xa2, 0x05, 0x16, 0x03, b'1', b'x', b'2'],
            // non-ASCII in an IA5String
            &[0x30, 0x06, 0xa0, 0x04, 0x16, 0x02, 0xc3, 0xa9],
            // a range of one, a negative count, a missing count
            &[
                0x30, 0x0c, 0xa1, 0x0a, 0x30, 0x08, 0x16, 0x03, b'1', b'0', b'0', 0x02, 0x01, 0x01,
            ],
            &[
                0x30, 0x0c, 0xa1, 0x0a, 0x30, 0x08, 0x16, 0x03, b'1', b'0', b'0', 0x02, 0x01, 0xff,
            ],
            &[
                0x30, 0x09, 0xa1, 0x07, 0x30, 0x05, 0x16, 0x03, b'1', b'0', b'0',
            ],
            // a range extension that is not an element
            &[
                0x30, 0x0d, 0xa1, 0x0b, 0x30, 0x09, 0x16, 0x03, b'1', b'0', b'0', 0x02, 0x01, 0x05,
                0x05,
            ],
            // truncated
            &[0x30, 0x08, 0xa0, 0x06, 0x16, 0x04, b'7', b'0', b'9'],
        ] {
            assert_eq!(TnAuthList::from_der(der), invalid, "{der:02x?}");
        }
    }
}
