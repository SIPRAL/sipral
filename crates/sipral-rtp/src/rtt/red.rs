// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The RFC 2198 redundancy payload, "red", as RFC 4103 §4 uses it to carry
//! a new T140block together with copies of the ones sent before it.
//!
//! RFC 2198 §3 lays the payload out as a run of block headers followed by
//! the blocks themselves, in the same order. Every header but the last is
//! four octets: the F bit set to say another header follows, the block's
//! payload type in seven bits, a fourteen-bit timestamp offset back from the
//! packet's own RTP timestamp, and a ten-bit block length. The last header
//! is a single octet, F clear and the payload type, and belongs to the
//! primary block, whose length is whatever of the payload is left once the
//! redundant blocks are accounted for.

use core::fmt;

/// The longest block a ten-bit length field can describe (RFC 2198 §3).
pub const MAX_BLOCK_LEN: usize = 0x3FF;

/// The largest offset a fourteen-bit timestamp offset field can hold (RFC
/// 2198 §3); at the 1000 Hz clock text uses, a little over sixteen seconds.
pub const MAX_TIMESTAMP_OFFSET: u16 = 0x3FFF;

/// The largest payload type the seven-bit field has room for.
const MAX_PAYLOAD_TYPE: u8 = 0x7F;

/// Octets a redundant block's header takes; the primary's takes one.
const REDUNDANT_HEADER_LEN: usize = 4;

/// One redundant block: a copy of data sent earlier, and how much earlier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedundantBlock<'a> {
    /// The payload type the block's data is in.
    pub payload_type: u8,
    /// How many timestamp units before the packet's own RTP timestamp this
    /// block was first sent.
    pub timestamp_offset: u16,
    /// The block itself.
    pub data: &'a [u8],
}

/// A "red" payload, as a view over the octets it arrived in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedPayload<'a> {
    /// The four-octet headers of the redundant blocks, in order.
    headers: &'a [u8],
    /// Everything after the primary's one-octet header: the redundant
    /// blocks back to back, then the primary.
    blocks: &'a [u8],
    primary_payload_type: u8,
}

impl<'a> RedPayload<'a> {
    /// Read a "red" payload.
    ///
    /// # Errors
    /// [`RedError::Truncated`] when the headers never reach the one-octet
    /// primary header, or when the lengths they claim run past the end of
    /// the payload.
    pub fn parse(payload: &'a [u8]) -> Result<Self, RedError> {
        let mut at = 0;
        let mut claimed = 0_usize;
        loop {
            let Some(&first) = payload.get(at) else {
                return Err(RedError::Truncated);
            };
            if first & 0x80 == 0 {
                break;
            }
            let Some(&[_, _, high, low]) = payload.get(at..at + REDUNDANT_HEADER_LEN) else {
                return Err(RedError::Truncated);
            };
            claimed += usize::from(u16::from_be_bytes([high, low]) & 0x3FF);
            at += REDUNDANT_HEADER_LEN;
        }
        let (headers, rest) = payload.split_at(at);
        let Some((&primary, blocks)) = rest.split_first() else {
            return Err(RedError::Truncated);
        };
        if claimed > blocks.len() {
            return Err(RedError::Truncated);
        }
        Ok(Self {
            headers,
            blocks,
            primary_payload_type: primary & MAX_PAYLOAD_TYPE,
        })
    }

    /// How many redundant blocks the payload carries.
    #[must_use]
    pub const fn redundant_count(&self) -> usize {
        self.headers.len() / REDUNDANT_HEADER_LEN
    }

    /// The redundant blocks, in the order they were written: RFC 4103 §4
    /// has the oldest first.
    pub fn redundant(&self) -> impl Iterator<Item = RedundantBlock<'a>> + use<'a> {
        let mut data = self.blocks;
        self.headers
            .as_chunks::<REDUNDANT_HEADER_LEN>()
            .0
            .iter()
            .map(move |&[first, offset_high, middle, low]| {
                let length = usize::from(u16::from_be_bytes([middle, low]) & 0x3FF);
                let offset = (u16::from(offset_high) << 6) | u16::from(middle >> 2);
                let (block, rest) = data.split_at(length.min(data.len()));
                data = rest;
                RedundantBlock {
                    payload_type: first & MAX_PAYLOAD_TYPE,
                    timestamp_offset: offset,
                    data: block,
                }
            })
    }

    /// The primary block's payload type.
    #[must_use]
    pub const fn primary_payload_type(&self) -> u8 {
        self.primary_payload_type
    }

    /// The primary block: what is left once every redundant block is taken.
    #[must_use]
    pub fn primary(&self) -> &'a [u8] {
        let claimed: usize = self.redundant().map(|block| block.data.len()).sum();
        self.blocks.get(claimed..).unwrap_or_default()
    }
}

/// Append a "red" payload to `out`: the redundant blocks in the order given,
/// then the primary.
///
/// # Errors
/// [`RedError::PayloadType`] for a payload type wider than seven bits,
/// [`RedError::BlockTooLong`] for a redundant block longer than
/// [`MAX_BLOCK_LEN`], [`RedError::OffsetTooLarge`] for an offset wider than
/// fourteen bits. Nothing is appended when any of them is returned.
pub fn write_red(
    redundant: &[RedundantBlock<'_>],
    primary_payload_type: u8,
    primary: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), RedError> {
    if primary_payload_type > MAX_PAYLOAD_TYPE {
        return Err(RedError::PayloadType(primary_payload_type));
    }
    for block in redundant {
        if block.payload_type > MAX_PAYLOAD_TYPE {
            return Err(RedError::PayloadType(block.payload_type));
        }
        if block.data.len() > MAX_BLOCK_LEN {
            return Err(RedError::BlockTooLong(block.data.len()));
        }
        if block.timestamp_offset > MAX_TIMESTAMP_OFFSET {
            return Err(RedError::OffsetTooLarge(block.timestamp_offset));
        }
    }
    out.reserve(
        redundant.len() * REDUNDANT_HEADER_LEN
            + 1
            + redundant.iter().map(|b| b.data.len()).sum::<usize>()
            + primary.len(),
    );
    for block in redundant {
        // checked above to fit ten bits
        let length = u16::try_from(block.data.len()).unwrap_or(0);
        let [middle_high, low] = length.to_be_bytes();
        let offset = block.timestamp_offset;
        let offset_high = u8::try_from(offset >> 6).unwrap_or(0);
        let offset_low = u8::try_from(offset & 0x3F).unwrap_or(0);
        out.extend_from_slice(&[
            0x80 | block.payload_type,
            offset_high,
            (offset_low << 2) | (middle_high & 0x03),
            low,
        ]);
    }
    out.push(primary_payload_type);
    for block in redundant {
        out.extend_from_slice(block.data);
    }
    out.extend_from_slice(primary);
    Ok(())
}

/// Why a "red" payload could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedError {
    /// The headers or the lengths they claim run past the end of the
    /// payload.
    Truncated,
    /// A redundant block longer than the ten-bit length field can say.
    BlockTooLong(usize),
    /// A timestamp offset wider than its fourteen-bit field.
    OffsetTooLarge(u16),
    /// A payload type wider than its seven-bit field.
    PayloadType(u8),
}

impl fmt::Display for RedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Truncated => f.write_str("redundancy headers run past the payload"),
            Self::BlockTooLong(len) => {
                write!(f, "a {len}-octet block does not fit {MAX_BLOCK_LEN} octets")
            }
            Self::OffsetTooLarge(offset) => {
                write!(f, "timestamp offset {offset} does not fit fourteen bits")
            }
            Self::PayloadType(pt) => write!(f, "payload type {pt} does not fit seven bits"),
        }
    }
}

impl core::error::Error for RedError {}

#[cfg(test)]
mod tests {
    use super::{
        MAX_BLOCK_LEN, MAX_TIMESTAMP_OFFSET, RedError, RedPayload, RedundantBlock, write_red,
    };

    #[test]
    fn headers_are_laid_out_as_rfc_2198_section_3_draws_them() {
        let redundant = [RedundantBlock {
            payload_type: 98,
            timestamp_offset: 600,
            data: b"abc",
        }];
        let mut out = Vec::new();
        write_red(&redundant, 98, b"de", &mut out).unwrap();
        // F=1 and PT 98; offset 600 in fourteen bits then length 3 in ten:
        // 00001001 011000|00 00000011
        assert_eq!(
            out,
            [0xE2, 0x09, 0x60, 0x03, 98, b'a', b'b', b'c', b'd', b'e']
        );
    }

    #[test]
    fn what_is_written_reads_back() {
        let redundant = [
            RedundantBlock {
                payload_type: 98,
                timestamp_offset: MAX_TIMESTAMP_OFFSET,
                data: &[],
            },
            RedundantBlock {
                payload_type: 97,
                timestamp_offset: 300,
                data: &[0x55; MAX_BLOCK_LEN],
            },
        ];
        let mut out = Vec::new();
        write_red(&redundant, 98, "new".as_bytes(), &mut out).unwrap();
        let red = RedPayload::parse(&out).unwrap();
        assert_eq!(red.redundant_count(), 2);
        assert_eq!(red.redundant().collect::<Vec<_>>(), redundant);
        assert_eq!(red.primary_payload_type(), 98);
        assert_eq!(red.primary(), b"new");
    }

    #[test]
    fn a_primary_alone_takes_one_octet_of_header() {
        let mut out = Vec::new();
        write_red(&[], 98, b"x", &mut out).unwrap();
        assert_eq!(out, [98, b'x']);
        let red = RedPayload::parse(&out).unwrap();
        assert_eq!(red.redundant_count(), 0);
        assert_eq!(red.primary(), b"x");
        // and an empty primary is still a primary
        assert_eq!(RedPayload::parse(&[98]).unwrap().primary(), b"");
    }

    #[test]
    fn a_payload_that_does_not_add_up_is_refused() {
        // nothing at all
        assert_eq!(RedPayload::parse(&[]), Err(RedError::Truncated));
        // a redundant header cut short
        assert_eq!(RedPayload::parse(&[0xE2, 0x09]), Err(RedError::Truncated));
        // redundant headers and no primary header after them
        assert_eq!(
            RedPayload::parse(&[0xE2, 0x00, 0x00, 0x00]),
            Err(RedError::Truncated)
        );
        // a block claiming three octets with two there
        assert_eq!(
            RedPayload::parse(&[0xE2, 0x00, 0x00, 0x03, 98, b'a', b'b']),
            Err(RedError::Truncated)
        );
        // exactly three is fine, with an empty primary
        let red = RedPayload::parse(&[0xE2, 0x00, 0x00, 0x03, 98, b'a', b'b', b'c']).unwrap();
        assert_eq!(red.primary(), b"");
    }

    #[test]
    fn fields_too_wide_for_the_header_are_refused_and_nothing_is_written() {
        let block = |payload_type, timestamp_offset, data| RedundantBlock {
            payload_type,
            timestamp_offset,
            data,
        };
        let long = [0; MAX_BLOCK_LEN + 1];
        let mut out = vec![7];
        assert_eq!(
            write_red(&[block(98, 0, &long)], 98, b"", &mut out),
            Err(RedError::BlockTooLong(MAX_BLOCK_LEN + 1))
        );
        assert_eq!(
            write_red(
                &[block(98, MAX_TIMESTAMP_OFFSET + 1, b"")],
                98,
                b"",
                &mut out
            ),
            Err(RedError::OffsetTooLarge(MAX_TIMESTAMP_OFFSET + 1))
        );
        assert_eq!(
            write_red(&[block(128, 0, b"")], 98, b"", &mut out),
            Err(RedError::PayloadType(128))
        );
        assert_eq!(
            write_red(&[], 200, b"", &mut out),
            Err(RedError::PayloadType(200))
        );
        assert_eq!(out, [7]);
    }
}
