// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The presentation language of RFC 5246 §4, read and written with every
//! length checked.
//!
//! Every codec in the crate goes through these two halves, so the rules that
//! keep a hostile datagram from reading past its end or smuggling in a length
//! the field does not allow are written once. A vector `T x<min..max>` is a
//! length prefix as wide as `max` needs, then that many octets; the bounds are
//! octet counts, which is how RFC 5246 §4.3 counts them.

use crate::Error;

/// A cursor over received bytes that refuses to read past its end.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// What has not been read yet.
    pub(crate) const fn rest(&self) -> &'a [u8] {
        self.rest
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(Error::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (head, tail) = self.rest.split_first_chunk::<N>().ok_or(Error::Truncated)?;
        self.rest = tail;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        self.array::<1>().map(|[byte]| byte)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn u24(&mut self) -> Result<u32, Error> {
        let [a, b, c] = self.array()?;
        Ok(u32::from_be_bytes([0, a, b, c]))
    }

    pub(crate) fn u48(&mut self) -> Result<u64, Error> {
        let [b0, b1, b2, b3, b4, b5] = self.array()?;
        Ok(u64::from_be_bytes([0, 0, b0, b1, b2, b3, b4, b5]))
    }

    /// `opaque x<min..max>` behind a one-octet length.
    pub(crate) fn vec8(&mut self, min: usize, max: usize) -> Result<&'a [u8], Error> {
        let len = usize::from(self.u8()?);
        self.bounded(len, min, max)
    }

    /// `opaque x<min..max>` behind a two-octet length.
    pub(crate) fn vec16(&mut self, min: usize, max: usize) -> Result<&'a [u8], Error> {
        let len = usize::from(self.u16()?);
        self.bounded(len, min, max)
    }

    /// `opaque x<min..max>` behind a three-octet length.
    pub(crate) fn vec24(&mut self, min: usize, max: usize) -> Result<&'a [u8], Error> {
        let len = usize::try_from(self.u24()?).map_err(|_| Error::Length)?;
        self.bounded(len, min, max)
    }

    fn bounded(&mut self, len: usize, min: usize, max: usize) -> Result<&'a [u8], Error> {
        if len < min || len > max {
            return Err(Error::Length);
        }
        self.take(len)
    }

    /// Succeeds only when everything has been read.
    pub(crate) const fn finish(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }
}

/// Split a vector of fixed-width elements, refusing a length that is not a
/// whole number of them.
pub(crate) fn elements<const N: usize>(bytes: &[u8]) -> Result<Vec<[u8; N]>, Error> {
    let (whole, partial) = bytes.as_chunks::<N>();
    if !partial.is_empty() {
        return Err(Error::Length);
    }
    Ok(whole.to_vec())
}

pub(crate) fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u24(out: &mut Vec<u8>, value: u32) -> Result<(), Error> {
    let [top, a, b, c] = value.to_be_bytes();
    if top != 0 {
        return Err(Error::TooLarge);
    }
    out.extend_from_slice(&[a, b, c]);
    Ok(())
}

pub(crate) fn put_u48(out: &mut Vec<u8>, value: u64) -> Result<(), Error> {
    let [t0, t1, b0, b1, b2, b3, b4, b5] = value.to_be_bytes();
    if t0 != 0 || t1 != 0 {
        return Err(Error::SequenceExhausted);
    }
    out.extend_from_slice(&[b0, b1, b2, b3, b4, b5]);
    Ok(())
}

/// Write `opaque x<min..max>` behind a one-octet length.
pub(crate) fn put_vec8(
    out: &mut Vec<u8>,
    bytes: &[u8],
    min: usize,
    max: usize,
) -> Result<(), Error> {
    block(out, 1, min, max, |out| {
        out.extend_from_slice(bytes);
        Ok(())
    })
}

/// Write `opaque x<min..max>` behind a two-octet length.
pub(crate) fn put_vec16(
    out: &mut Vec<u8>,
    bytes: &[u8],
    min: usize,
    max: usize,
) -> Result<(), Error> {
    block(out, 2, min, max, |out| {
        out.extend_from_slice(bytes);
        Ok(())
    })
}

/// Write `opaque x<min..max>` behind a three-octet length.
pub(crate) fn put_vec24(
    out: &mut Vec<u8>,
    bytes: &[u8],
    min: usize,
    max: usize,
) -> Result<(), Error> {
    block(out, 3, min, max, |out| {
        out.extend_from_slice(bytes);
        Ok(())
    })
}

/// Run an encoder, and take back everything it wrote if it fails, so a
/// refused structure never leaves half of itself in `out`.
pub(crate) fn all_or_nothing<F>(out: &mut Vec<u8>, encode: F) -> Result<(), Error>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), Error>,
{
    let start = out.len();
    let result = encode(out);
    if result.is_err() {
        out.truncate(start);
    }
    result
}

/// Write a vector whose contents `body` produces, behind a length prefix
/// `width` octets wide that is filled in once the contents are known.
///
/// On any error `out` is left exactly as it was found, so a refused field
/// never leaves half a structure behind.
pub(crate) fn block<F>(
    out: &mut Vec<u8>,
    width: usize,
    min: usize,
    max: usize,
    body: F,
) -> Result<(), Error>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), Error>,
{
    let start = out.len();
    out.resize(start + width, 0);
    let result = body(out).and_then(|()| {
        let len = out.len() - start - width;
        if len < min || len > max {
            return Err(Error::Length);
        }
        let prefix = u32::try_from(len).map_err(|_| Error::Length)?.to_be_bytes();
        let wide = prefix.get(4 - width..).ok_or(Error::Length)?;
        if prefix.iter().take(4 - width).any(|&b| b != 0) {
            return Err(Error::Length);
        }
        let slot = out.get_mut(start..start + width).ok_or(Error::Length)?;
        slot.copy_from_slice(wide);
        Ok(())
    });
    if result.is_err() {
        out.truncate(start);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_read_big_endian_and_refused_past_the_end() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.u16(), Ok(0x0203));
        assert_eq!(r.u24(), Ok(0x04_0506));
        // five octets left, six wanted
        assert_eq!(r.u48(), Err(Error::Truncated));
        // a refused read consumes nothing
        assert_eq!(r.rest(), &[7, 8, 9, 10, 11]);
        assert_eq!(r.take(5), Ok(&[7u8, 8, 9, 10, 11][..]));
        assert!(r.is_empty());
        assert_eq!(r.u8(), Err(Error::Truncated));

        assert_eq!(
            Reader::new(&[7, 8, 9, 10, 11, 12]).u48(),
            Ok(0x0708_090a_0b0c)
        );
        assert_eq!(Reader::new(&[0xFE, 0xFD]).array::<2>(), Ok([0xFE, 0xFD]));
    }

    #[test]
    fn a_vector_is_held_to_its_bounds_before_its_bytes_are_looked_for() {
        // two octets announced, bounds say at least three
        assert_eq!(Reader::new(&[2, 9, 9]).vec8(3, 10), Err(Error::Length));
        // bounds allow it, input is short
        assert_eq!(Reader::new(&[4, 9, 9]).vec8(0, 10), Err(Error::Truncated));
        assert_eq!(
            Reader::new(&[0, 3, 1, 2, 3]).vec16(1, 3),
            Ok(&[1u8, 2, 3][..])
        );
        assert_eq!(
            Reader::new(&[0, 0, 4, 1, 2, 3]).vec24(0, 9),
            Err(Error::Truncated)
        );
        // five octets announced and present, bounds say at most three: the
        // upper bound is enforced even when every announced octet is there
        assert_eq!(
            Reader::new(&[5, 1, 2, 3, 4, 5]).vec8(0, 3),
            Err(Error::Length)
        );
    }

    #[test]
    fn finish_refuses_what_is_left() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.finish(), Err(Error::TrailingData));
        assert_eq!(r.u8(), Ok(2));
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn elements_refuse_a_partial_one() {
        assert_eq!(elements::<2>(&[0, 1, 0, 2]), Ok(vec![[0, 1], [0, 2]]));
        assert_eq!(elements::<2>(&[0, 1, 0]), Err(Error::Length));
    }

    #[test]
    fn a_block_writes_its_length_and_leaves_nothing_behind_when_refused() {
        let mut out = vec![0xAA];
        put_vec16(&mut out, &[1, 2, 3], 1, 10).unwrap();
        assert_eq!(out, [0xAA, 0, 3, 1, 2, 3]);

        assert_eq!(put_vec8(&mut out, &[1, 2, 3], 4, 10), Err(Error::Length));
        assert_eq!(put_vec8(&mut out, &[0; 256], 0, 255), Err(Error::Length));
        // five octets, comfortably inside what one length octet can hold, but
        // over a bound narrower than that: the upper bound is its own check,
        // not a side effect of the length field overflowing
        assert_eq!(put_vec8(&mut out, &[9; 5], 0, 3), Err(Error::Length));
        assert_eq!(out, [0xAA, 0, 3, 1, 2, 3]);

        put_vec24(&mut out, &[7; 300], 1, 0xFF_FFFF).unwrap();
        assert_eq!(out.get(6..9), Some(&[0, 1, 44][..]));
        assert_eq!(out.len(), 9 + 300);
    }

    #[test]
    fn wide_integers_refuse_values_their_width_cannot_hold() {
        let mut out = Vec::new();
        assert_eq!(put_u24(&mut out, 0x0100_0000), Err(Error::TooLarge));
        assert_eq!(put_u48(&mut out, 1 << 48), Err(Error::SequenceExhausted));
        assert!(out.is_empty());
        put_u48(&mut out, (1 << 48) - 1).unwrap();
        assert_eq!(out, [0xFF; 6]);
    }
}
