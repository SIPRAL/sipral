// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The few DER reads this crate makes by itself: one tag-length-value at a
//! time (X.690 §8.1, restricted as §10.1 restricts it), for the TNAuthList
//! extension and for cutting the exact `tbsCertificate` octets a certificate
//! signature covers out of the certificate that carries them.
//!
//! Only what DER allows is accepted: a low tag number in one octet, a
//! definite length in the fewest octets that can hold it, and never the
//! indefinite form.

/// SEQUENCE, constructed (X.690 §8.9).
pub(crate) const SEQUENCE: u8 = 0x30;
/// INTEGER (X.690 §8.3).
pub(crate) const INTEGER: u8 = 0x02;
/// IA5String (X.680 §41).
pub(crate) const IA5_STRING: u8 = 0x16;

/// Not DER, or not the shape asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Invalid;

/// One element: its tag octet, its contents, and all of it as encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) contents: &'a [u8],
    pub(crate) encoded: &'a [u8],
}

/// Read the element at the start of `input`, and what follows it.
pub(crate) fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), Invalid> {
    let (&tag, rest) = input.split_first().ok_or(Invalid)?;
    // the high-tag-number form: nothing read here uses it
    if tag & 0x1f == 0x1f {
        return Err(Invalid);
    }
    let (&first, rest) = rest.split_first().ok_or(Invalid)?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        // more than two octets of length is more than anything this crate
        // reads can hold; 0x80, the indefinite form DER forbids, reads as a
        // long form of no octets, which the fewest-octets rule below refuses
        if count > 2 {
            return Err(Invalid);
        }
        let (octets, rest) = rest.split_at_checked(count).ok_or(Invalid)?;
        let length = octets
            .iter()
            .fold(0usize, |acc, &octet| (acc << 8) | usize::from(octet));
        // X.690 §10.1: the fewest octets, so a long form must be needed
        if length < 0x80 || (count == 2 && length < 0x100) {
            return Err(Invalid);
        }
        (length, rest)
    };
    let (contents, after) = rest.split_at_checked(length).ok_or(Invalid)?;
    let header = input.len() - rest.len();
    let encoded = input.get(..header + length).ok_or(Invalid)?;
    Ok((
        Tlv {
            tag,
            contents,
            encoded,
        },
        after,
    ))
}

/// Read one element carrying `tag`, and what follows it.
pub(crate) fn expect(input: &[u8], tag: u8) -> Result<(Tlv<'_>, &[u8]), Invalid> {
    let (tlv, rest) = read(input)?;
    if tlv.tag == tag {
        Ok((tlv, rest))
    } else {
        Err(Invalid)
    }
}

/// Read the whole of `input` as exactly one element carrying `tag`.
pub(crate) fn only(input: &[u8], tag: u8) -> Result<Tlv<'_>, Invalid> {
    let (tlv, rest) = expect(input, tag)?;
    if rest.is_empty() {
        Ok(tlv)
    } else {
        Err(Invalid)
    }
}

/// A non-negative INTEGER's contents (X.690 §8.3) as a `u64`, refusing a
/// negative value, a padding octet §8.3.2 forbids, and anything wider.
pub(crate) fn unsigned(contents: &[u8]) -> Result<u64, Invalid> {
    match contents {
        [] => Err(Invalid),
        [first, ..] if first & 0x80 != 0 => Err(Invalid),
        [0, second, ..] if second & 0x80 == 0 => Err(Invalid),
        _ => {
            let digits = match contents {
                [0, rest @ ..] if !rest.is_empty() => rest,
                all => all,
            };
            if digits.len() > 8 {
                return Err(Invalid);
            }
            Ok(digits
                .iter()
                .fold(0u64, |acc, &octet| (acc << 8) | u64::from(octet)))
        }
    }
}

/// One element, `tag` around `contents`, with its length in the fewest
/// octets (X.690 §10.1).
pub(crate) fn write(tag: u8, contents: &[u8]) -> Vec<u8> {
    let length = contents.len();
    let mut out = Vec::with_capacity(contents.len() + 6);
    out.push(tag);
    if length < 0x80 {
        out.push(length.to_be_bytes().last().copied().unwrap_or(0));
    } else {
        let octets = length.to_be_bytes();
        let significant: Vec<u8> = octets.iter().copied().skip_while(|&b| b == 0).collect();
        out.push(0x80 | significant.len().to_be_bytes().last().copied().unwrap_or(0));
        out.extend_from_slice(&significant);
    }
    out.extend_from_slice(contents);
    out
}

/// The contents of an INTEGER holding `value` (X.690 §8.3): the fewest
/// octets, with a leading zero where the top bit would read as a sign.
pub(crate) fn unsigned_contents(value: u64) -> Vec<u8> {
    let octets = value.to_be_bytes();
    let mut out: Vec<u8> = octets.iter().copied().skip_while(|&b| b == 0).collect();
    if out.first().is_none_or(|&b| b & 0x80 != 0) {
        out.insert(0, 0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_elements_read_back() {
        for length in [0usize, 1, 0x7f, 0x80, 0xff, 0x100, 0x1234] {
            let contents = vec![0xa5; length];
            let encoded = write(0x04, &contents);
            let (tlv, rest) = read(&encoded).unwrap();
            assert_eq!(tlv.contents, &contents[..], "{length}");
            assert!(rest.is_empty());
        }
        assert_eq!(write(0x04, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(write(0x04, &[0; 0x100])[..4], [0x04, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn written_integers_read_back() {
        assert_eq!(unsigned_contents(0), [0]);
        assert_eq!(unsigned_contents(5), [5]);
        assert_eq!(unsigned_contents(0x80), [0, 0x80]);
        assert_eq!(unsigned_contents(0x100), [1, 0]);
        for value in [0, 1, 0x7f, 0x80, 0xffff, u64::MAX] {
            assert_eq!(unsigned(&unsigned_contents(value)), Ok(value));
        }
    }

    #[test]
    fn short_and_long_lengths() {
        let (tlv, rest) = read(&[0x04, 0x02, 0xaa, 0xbb, 0xcc]).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.contents, &[0xaa, 0xbb]);
        assert_eq!(tlv.encoded, &[0x04, 0x02, 0xaa, 0xbb]);
        assert_eq!(rest, &[0xcc]);

        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([0u8; 0x80]);
        assert_eq!(read(&long).unwrap().0.contents.len(), 0x80);

        let mut longer = vec![0x04, 0x82, 0x01, 0x00];
        longer.extend([0u8; 0x100]);
        assert_eq!(read(&longer).unwrap().0.contents.len(), 0x100);
    }

    #[test]
    fn non_minimal_lengths_are_refused() {
        let mut padded = vec![0x04, 0x81, 0x05];
        padded.extend([0u8; 5]);
        assert_eq!(read(&padded), Err(Invalid));

        let mut two = vec![0x04, 0x82, 0x00, 0x90];
        two.extend([0u8; 0x90]);
        assert_eq!(read(&two), Err(Invalid));
    }

    #[test]
    fn indefinite_and_oversized_lengths_are_refused() {
        assert_eq!(read(&[0x30, 0x80, 0x00, 0x00]), Err(Invalid));
        assert_eq!(read(&[0x04, 0x83, 0x01, 0x00, 0x00]), Err(Invalid));
    }

    #[test]
    fn truncation_is_refused() {
        assert_eq!(read(&[]), Err(Invalid));
        assert_eq!(read(&[0x04]), Err(Invalid));
        assert_eq!(read(&[0x04, 0x03, 0x00]), Err(Invalid));
        assert_eq!(read(&[0x04, 0x81]), Err(Invalid));
    }

    #[test]
    fn high_tag_numbers_are_refused() {
        // read as a one-octet tag, this would be an element of length one
        assert_eq!(read(&[0x1f, 0x01, 0x00]), Err(Invalid));
    }

    #[test]
    fn expect_and_only_check_the_tag_and_the_end() {
        assert!(expect(&[0x02, 0x01, 0x05], INTEGER).is_ok());
        assert_eq!(expect(&[0x02, 0x01, 0x05], SEQUENCE), Err(Invalid));
        assert!(only(&[0x02, 0x01, 0x05], INTEGER).is_ok());
        assert_eq!(only(&[0x02, 0x01, 0x05, 0x00], INTEGER), Err(Invalid));
    }

    #[test]
    fn unsigned_integers() {
        assert_eq!(unsigned(&[0x05]), Ok(5));
        assert_eq!(unsigned(&[0x00, 0x80]), Ok(0x80));
        assert_eq!(unsigned(&[0x01, 0x00]), Ok(0x100));
        assert_eq!(
            unsigned(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Ok(u64::MAX)
        );
        assert_eq!(unsigned(&[]), Err(Invalid));
        assert_eq!(unsigned(&[0x80]), Err(Invalid), "negative");
        assert_eq!(unsigned(&[0x00, 0x05]), Err(Invalid), "padded");
        assert_eq!(unsigned(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Invalid));
    }
}
