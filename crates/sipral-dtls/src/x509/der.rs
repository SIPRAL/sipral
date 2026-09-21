// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The part of DER (ITU-T X.690) a certificate needs.
//!
//! Writing: the handful of types a self-signed certificate is made of, every
//! length definite and in its shortest form. Reading: element boundaries,
//! strictly enough that a hostile certificate cannot steer the reader —
//! definite lengths only, each in its shortest form, single-octet tags,
//! nothing read past the enclosing element. What an element holds is the
//! caller's to interpret.

use crate::Error;
use crate::wire::{self, Reader};

pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const NULL: u8 = 0x05;
pub(crate) const OBJECT_IDENTIFIER: u8 = 0x06;
pub(crate) const UTF8_STRING: u8 = 0x0C;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;

/// `[n] EXPLICIT`: context-specific and constructed.
pub(crate) const fn explicit(n: u8) -> u8 {
    0xA0 | n
}

/// `[n] IMPLICIT` over a primitive type: context-specific and primitive.
pub(crate) const fn implicit(n: u8) -> u8 {
    0x80 | n
}

/// Length octets beyond the first. Four describe 4 GiB, far past anything a
/// certificate is.
const MAX_LENGTH_OCTETS: usize = 4;

/// Write one element: tag, length, content.
pub(crate) fn write(out: &mut Vec<u8>, tag: u8, content: &[u8]) -> Result<(), Error> {
    wire::all_or_nothing(out, |out| {
        out.push(tag);
        match u8::try_from(content.len()) {
            Ok(short) if short < 0x80 => out.push(short),
            _ => {
                let bytes = u32::try_from(content.len())
                    .map_err(|_| Error::TooLarge)?
                    .to_be_bytes();
                let significant: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
                out.push(0x80 | u8::try_from(significant.len()).map_err(|_| Error::TooLarge)?);
                out.extend_from_slice(&significant);
            }
        }
        out.extend_from_slice(content);
        Ok(())
    })
}

/// Write a constructed element whose content `body` produces.
pub(crate) fn constructed<F>(out: &mut Vec<u8>, tag: u8, body: F) -> Result<(), Error>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), Error>,
{
    let mut content = Vec::new();
    body(&mut content)?;
    write(out, tag, &content)
}

/// A non-negative INTEGER from its big-endian magnitude: leading zero octets
/// removed, one put back when the top bit would otherwise read as a sign.
pub(crate) fn unsigned_integer(out: &mut Vec<u8>, magnitude: &[u8]) -> Result<(), Error> {
    let start = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len());
    let trimmed = magnitude.get(start..).unwrap_or_default();
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_none_or(|&b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    write(out, INTEGER, &content)
}

/// The big-endian magnitude of an INTEGER's content octets, for a number that
/// has to be positive: the one leading zero that keeps the top bit from
/// reading as a sign is dropped, and everything X.690 §8.3 does not allow a
/// positive number is refused — no octets at all (§8.3.1), a zero octet that
/// was not needed (§8.3.2: the first nine bits "shall not all be zero"), and
/// the top bit set with none, which is a negative number. Zero itself is
/// refused too, since no key this reads for may be zero.
pub(crate) fn positive_integer(content: &[u8]) -> Result<&[u8], Error> {
    match content {
        [] => Err(Error::Length),
        [first, ..] if first & 0x80 != 0 => Err(Error::IllegalValue),
        [0, rest @ ..] if rest.first().is_some_and(|next| next & 0x80 != 0) => Ok(rest),
        [0, ..] => Err(Error::IllegalValue),
        _ => Ok(content),
    }
}

/// A BIT STRING of whole octets: no unused bits.
pub(crate) fn bit_string(out: &mut Vec<u8>, octets: &[u8]) -> Result<(), Error> {
    let mut content = Vec::with_capacity(octets.len() + 1);
    content.push(0);
    content.extend_from_slice(octets);
    write(out, BIT_STRING, &content)
}

/// One element as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Element<'a> {
    pub(crate) tag: u8,
    /// The content octets.
    pub(crate) content: &'a [u8],
    /// Tag, length and content together, as they appeared.
    pub(crate) encoded: &'a [u8],
}

/// Elements read one after another from a stretch of DER.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Der<'a> {
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next element, whatever it is.
    pub(crate) fn next(&mut self) -> Result<Element<'a>, Error> {
        let start = self.rest;
        let mut r = Reader::new(start);
        let tag = r.u8()?;
        // tag number 31 announces the multi-octet form, which nothing a
        // certificate is read for uses
        if tag & 0x1F == 0x1F {
            return Err(Error::IllegalValue);
        }
        let first = r.u8()?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let octets = usize::from(first & 0x7F);
            // 0x80 is BER's indefinite length, which DER forbids
            if octets == 0 {
                return Err(Error::IllegalValue);
            }
            if octets > MAX_LENGTH_OCTETS {
                return Err(Error::TooLarge);
            }
            let bytes = r.take(octets)?;
            // DER's shortest form: no leading zero octet, and no long form
            // for a length the short form could carry
            if bytes.first() == Some(&0) {
                return Err(Error::IllegalValue);
            }
            let value = bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            if value < 0x80 {
                return Err(Error::IllegalValue);
            }
            value
        };
        let header = start.len() - r.rest().len();
        let content = r.take(len)?;
        let encoded = start.get(..header + len).ok_or(Error::Truncated)?;
        self.rest = r.rest();
        Ok(Element {
            tag,
            content,
            encoded,
        })
    }

    /// The next element, which must carry `tag`.
    pub(crate) fn expect(&mut self, tag: u8) -> Result<Element<'a>, Error> {
        let element = self.next()?;
        if element.tag != tag {
            return Err(Error::IllegalValue);
        }
        Ok(element)
    }

    /// The next element if it carries `tag`, and nothing consumed otherwise.
    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<Element<'a>>, Error> {
        if self.rest.first() == Some(&tag) {
            self.next().map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) const fn finish(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(content_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut out, SEQUENCE, &vec![7; content_len]).unwrap();
        out
    }

    #[test]
    fn a_positive_integer_is_read_as_its_magnitude_and_nothing_else_is() {
        assert_eq!(positive_integer(&[0x01]), Ok(&[0x01][..]));
        assert_eq!(positive_integer(&[0x7F, 0xFF]), Ok(&[0x7F, 0xFF][..]));
        // the zero that keeps the sign bit clear is not part of the number
        assert_eq!(positive_integer(&[0x00, 0x80]), Ok(&[0x80][..]));
        assert_eq!(positive_integer(&[0x00, 0xFF, 0x01]), Ok(&[0xFF, 0x01][..]));
        assert_eq!(positive_integer(&[]), Err(Error::Length));
        // negative
        assert_eq!(positive_integer(&[0x80]), Err(Error::IllegalValue));
        assert_eq!(positive_integer(&[0xFF, 0x00]), Err(Error::IllegalValue));
        // a zero octet X.690 §8.3.2 does not allow
        assert_eq!(positive_integer(&[0x00, 0x7F]), Err(Error::IllegalValue));
        assert_eq!(
            positive_integer(&[0x00, 0x00, 0x80]),
            Err(Error::IllegalValue)
        );
        // zero
        assert_eq!(positive_integer(&[0x00]), Err(Error::IllegalValue));
    }

    #[test]
    fn what_the_writer_prints_the_reader_takes_back() {
        for magnitude in [&[0x01][..], &[0x80], &[0x00, 0x00, 0x9A, 0x01], &[0x7F; 40]] {
            let mut out = Vec::new();
            unsigned_integer(&mut out, magnitude).unwrap();
            let element = Der::new(&out).expect(INTEGER).unwrap();
            let start = magnitude.iter().position(|&b| b != 0).unwrap();
            assert_eq!(positive_integer(element.content), Ok(&magnitude[start..]));
        }
    }

    #[test]
    fn lengths_are_written_in_their_shortest_form() {
        assert_eq!(written(0), [0x30, 0x00]);
        assert_eq!(written(0x7F)[..2], [0x30, 0x7F]);
        assert_eq!(written(0x80)[..3], [0x30, 0x81, 0x80]);
        assert_eq!(written(0xFF)[..3], [0x30, 0x81, 0xFF]);
        assert_eq!(written(0x100)[..4], [0x30, 0x82, 0x01, 0x00]);
        assert_eq!(written(0x1_0000)[..5], [0x30, 0x83, 0x01, 0x00, 0x00]);
        for len in [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1_0000] {
            let bytes = written(len);
            let mut der = Der::new(&bytes);
            let element = der.next().unwrap();
            assert_eq!(
                (element.tag, element.content.len(), element.encoded.len()),
                (SEQUENCE, len, bytes.len())
            );
            assert!(der.is_empty());
        }
    }

    #[test]
    fn integers_are_minimal_and_never_negative() {
        let cases: [(&[u8], &[u8]); 6] = [
            (&[], &[0x02, 0x01, 0x00]),
            (&[0, 0], &[0x02, 0x01, 0x00]),
            (&[5], &[0x02, 0x01, 0x05]),
            (&[0, 0, 5], &[0x02, 0x01, 0x05]),
            (&[0x80], &[0x02, 0x02, 0x00, 0x80]),
            (&[0, 0x7F, 0xFF], &[0x02, 0x02, 0x7F, 0xFF]),
        ];
        for (magnitude, expected) in cases {
            let mut out = Vec::new();
            unsigned_integer(&mut out, magnitude).unwrap();
            assert_eq!(out, expected, "{magnitude:?}");
        }
        let mut out = Vec::new();
        bit_string(&mut out, &[4, 5]).unwrap();
        assert_eq!(out, [0x03, 0x03, 0x00, 4, 5]);
    }

    #[test]
    fn what_der_forbids_is_refused_on_the_way_in() {
        let cases: [(&str, &[u8], Error); 8] = [
            (
                "indefinite length",
                &[0x30, 0x80, 0x00, 0x00],
                Error::IllegalValue,
            ),
            (
                "long form for a short length",
                &[0x30, 0x81, 0x05, 1, 2, 3, 4, 5],
                Error::IllegalValue,
            ),
            (
                "leading zero length octet",
                &[0x30, 0x82, 0x00, 0x80],
                Error::IllegalValue,
            ),
            (
                "five length octets",
                &[0x30, 0x85, 1, 0, 0, 0, 0],
                Error::TooLarge,
            ),
            (
                "multi-octet tag",
                &[0x1F, 0x81, 0x01, 0x00],
                Error::IllegalValue,
            ),
            (
                "content past the end",
                &[0x30, 0x03, 1, 2],
                Error::Truncated,
            ),
            (
                "length octets past the end",
                &[0x30, 0x82, 0x01],
                Error::Truncated,
            ),
            ("no length", &[0x30], Error::Truncated),
        ];
        for (what, bytes, error) in cases {
            assert_eq!(Der::new(bytes).next(), Err(error), "{what}");
        }
    }

    #[test]
    fn expect_and_optional_look_at_the_tag() {
        let bytes = [0x02, 0x01, 0x05, 0x30, 0x00];
        let mut der = Der::new(&bytes);
        assert_eq!(der.optional(SEQUENCE), Ok(None));
        assert_eq!(der.optional(INTEGER).unwrap().unwrap().content, [5]);
        assert_eq!(der.finish(), Err(Error::TrailingData));
        assert_eq!(der.expect(INTEGER), Err(Error::IllegalValue));
        assert_eq!(der.finish(), Ok(()));
        assert_eq!(explicit(3), 0xA3);
        assert_eq!(implicit(1), 0x81);
    }
}
