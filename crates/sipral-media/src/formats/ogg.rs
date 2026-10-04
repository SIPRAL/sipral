// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The Ogg encapsulation format, RFC 3533.
//!
//! An Ogg logical bitstream is a sequence of packets cut into pages. Each
//! page carries a 27-octet header (§6), a segment table of up to 255 lacing
//! values, and the segments themselves. A packet is laced as a run of 255s
//! followed by one value below 255, so a packet whose length is a multiple of
//! 255 ends with a zero; a page whose last lacing value is 255 leaves its
//! packet unfinished, and the next page says it continues one (§5).
//!
//! [`PageWriter`] does the cutting for one logical bitstream: packets go in
//! with the granule position they end at, and pages come out onto any
//! [`Write`] whenever the segment table fills, the caller flushes, or the
//! stream ends. [`Page::parse`] and [`read_packets`] go the other way, and
//! refuse anything whose checksum, sequence or continuation does not hold:
//! they exist to prove what the writer wrote, not to recover what somebody
//! else damaged.
//!
//! Multiplexing several logical bitstreams into one physical one (§4) is not
//! done here: a call recording is one stream.

use core::fmt;
use std::io::{self, Write};

/// The four octets every page starts with, "OggS" (§6).
pub const CAPTURE_PATTERN: [u8; 4] = *b"OggS";

/// The only stream structure version RFC 3533 defines (§6).
pub const VERSION: u8 = 0;

/// Header type flag: the page starts with the rest of a packet begun on the
/// page before (§6).
pub const FLAG_CONTINUED: u8 = 0x01;

/// Header type flag: first page of the logical bitstream (§6).
pub const FLAG_BOS: u8 = 0x02;

/// Header type flag: last page of the logical bitstream (§6).
pub const FLAG_EOS: u8 = 0x04;

/// The fixed part of a page header, up to and including the segment count.
pub const HEADER_LEN: usize = 27;

/// The most lacing values one segment table holds (§6: the count is a byte).
pub const MAX_SEGMENTS: usize = 255;

/// The most octets one page can carry: 255 segments of 255 octets.
pub const MAX_BODY_LEN: usize = MAX_SEGMENTS * 255;

/// The granule position of a page on which no packet finishes: -1 as a
/// two's complement 64-bit value (§6).
pub const NO_GRANULE: u64 = u64::MAX;

/// The CRC generator polynomial of §6, without its x^32 term.
pub const CRC_POLYNOMIAL: u32 = 0x04C1_1DB7;

const CRC_OFFSET: usize = 22;

const CRC_TABLE: [u32; 256] = crc_table();

/// The remainder of every octet value divided by the generator, one entry
/// per value, MSB first.
#[expect(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "a const fn has neither get_mut nor try_from, and the loop stops at 256"
)]
const fn crc_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut value = 0;
    while value < 256 {
        let mut remainder = (value as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            remainder = if remainder & 0x8000_0000 == 0 {
                remainder << 1
            } else {
                (remainder << 1) ^ CRC_POLYNOMIAL
            };
            bit += 1;
        }
        table[value] = remainder;
        value += 1;
    }
    table
}

/// Continue a checksum over `bytes`.
///
/// §6 gives the generator and leaves the rest to the reader of the
/// polynomial: the register starts at zero, the bits go in most significant
/// first, nothing is reflected and nothing is inverted at the end. Start with
/// `0` for a fresh checksum.
#[must_use]
pub fn crc_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        let index = usize::from(crc.to_be_bytes()[0] ^ byte);
        crc = (crc << 8) ^ CRC_TABLE.get(index).copied().unwrap_or(0);
    }
    crc
}

/// The checksum of `bytes` as §6 defines it.
#[must_use]
pub fn crc(bytes: &[u8]) -> u32 {
    crc_update(0, bytes)
}

/// Why a [`PageWriter`] refused.
#[derive(Debug)]
pub enum WriteError {
    /// The sink failed.
    Io(io::Error),
    /// The stream already ended: nothing more can be written to it.
    Finished,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "writing an Ogg page failed: {error}"),
            Self::Finished => f.write_str("the Ogg stream has already ended"),
        }
    }
}

impl core::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Finished => None,
        }
    }
}

impl From<io::Error> for WriteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Cuts the packets of one logical bitstream into pages.
///
/// The first page written is marked BOS, and [`finish`](Self::finish) writes
/// the last one marked EOS. A page goes out when its segment table is full,
/// when [`flush`](Self::flush) says so, or at the end; the granule position
/// on it is that of the last packet that finishes on it, or [`NO_GRANULE`]
/// when none does.
///
/// The buffers are allocated once, at construction, at the size of the
/// largest page; writing does not allocate.
#[derive(Debug)]
pub struct PageWriter {
    serial: u32,
    sequence: u32,
    started: bool,
    finished: bool,
    continued: bool,
    granule: u64,
    lacing: Vec<u8>,
    body: Vec<u8>,
    page: Vec<u8>,
}

impl PageWriter {
    /// A writer for the logical bitstream with this serial number.
    ///
    /// §4 asks for serial numbers chosen at random so that streams from
    /// different sources can be multiplexed without clashing; drawing one is
    /// left to the caller.
    #[must_use]
    pub fn new(serial: u32) -> Self {
        Self {
            serial,
            sequence: 0,
            started: false,
            finished: false,
            continued: false,
            granule: NO_GRANULE,
            lacing: Vec::with_capacity(MAX_SEGMENTS),
            body: Vec::with_capacity(MAX_BODY_LEN),
            page: Vec::with_capacity(HEADER_LEN + MAX_SEGMENTS + MAX_BODY_LEN),
        }
    }

    /// The serial number every page carries.
    #[must_use]
    pub const fn serial(&self) -> u32 {
        self.serial
    }

    /// How many pages have been written so far, which is also the sequence
    /// number the next one will carry.
    #[must_use]
    pub const fn pages_written(&self) -> u32 {
        self.sequence
    }

    /// Whether anything is waiting for a page.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lacing.is_empty()
    }

    /// Whether a packet of `length` octets would finish on the page being
    /// filled, rather than send it out first because the segment table
    /// fills.
    #[must_use]
    pub fn fits(&self, length: usize) -> bool {
        let needed = length / 255 + 1;
        self.lacing.len().saturating_add(needed) <= MAX_SEGMENTS
    }

    /// Add one packet that ends at `granule`, writing out every page it
    /// fills on the way.
    ///
    /// What the granule position means is the codec's business (§6); this
    /// only puts it on the page the packet finishes on.
    ///
    /// # Errors
    ///
    /// [`WriteError::Finished`] after [`finish`](Self::finish), and
    /// [`WriteError::Io`] when a page could not be written.
    pub fn write_packet<W: Write>(
        &mut self,
        out: &mut W,
        packet: &[u8],
        granule: u64,
    ) -> Result<(), WriteError> {
        if self.finished {
            return Err(WriteError::Finished);
        }
        let mut rest = packet;
        loop {
            if self.lacing.len() == MAX_SEGMENTS {
                self.write_page(out, false)?;
            }
            let (segment, after) = rest.split_at(rest.len().min(255));
            let value = u8::try_from(segment.len()).unwrap_or(u8::MAX);
            self.lacing.push(value);
            self.body.extend_from_slice(segment);
            rest = after;
            if value < 255 {
                self.granule = granule;
                return Ok(());
            }
        }
    }

    /// Write whatever is buffered as a page now, if anything is.
    ///
    /// A packet laced only partly stays unfinished: the page ends with a 255
    /// and the next one is marked as continuing it.
    ///
    /// # Errors
    ///
    /// [`WriteError::Finished`] after [`finish`](Self::finish), and
    /// [`WriteError::Io`] when the page could not be written.
    pub fn flush<W: Write>(&mut self, out: &mut W) -> Result<(), WriteError> {
        if self.finished {
            return Err(WriteError::Finished);
        }
        if self.lacing.is_empty() {
            return Ok(());
        }
        self.write_page(out, false)
    }

    /// End the stream: write what is buffered as a page marked EOS.
    ///
    /// With nothing buffered the EOS page has no segments. That is legal
    /// Ogg, but a codec mapping that wants its last packet on the EOS page
    /// should hold that packet back until it knows it is the last.
    ///
    /// # Errors
    ///
    /// [`WriteError::Finished`] when called twice, and [`WriteError::Io`]
    /// when the page could not be written.
    pub fn finish<W: Write>(&mut self, out: &mut W) -> Result<(), WriteError> {
        if self.finished {
            return Err(WriteError::Finished);
        }
        self.write_page(out, true)?;
        self.finished = true;
        Ok(())
    }

    fn write_page<W: Write>(&mut self, out: &mut W, eos: bool) -> Result<(), WriteError> {
        let mut flags = 0;
        if self.continued {
            flags |= FLAG_CONTINUED;
        }
        if !self.started {
            flags |= FLAG_BOS;
        }
        if eos {
            flags |= FLAG_EOS;
        }
        let segments = u8::try_from(self.lacing.len()).unwrap_or(u8::MAX);

        self.page.clear();
        self.page.extend_from_slice(&CAPTURE_PATTERN);
        self.page.push(VERSION);
        self.page.push(flags);
        self.page.extend_from_slice(&self.granule.to_le_bytes());
        self.page.extend_from_slice(&self.serial.to_le_bytes());
        self.page.extend_from_slice(&self.sequence.to_le_bytes());
        self.page.extend_from_slice(&[0; 4]);
        self.page.push(segments);
        self.page.extend_from_slice(&self.lacing);
        self.page.extend_from_slice(&self.body);
        let checksum = crc(&self.page);
        if let Some(field) = self.page.get_mut(CRC_OFFSET..CRC_OFFSET + 4) {
            field.copy_from_slice(&checksum.to_le_bytes());
        }
        out.write_all(&self.page)?;

        self.continued = self.lacing.last() == Some(&255);
        self.started = true;
        // four thousand million pages: more than a century of one-second pages
        self.sequence = self.sequence.wrapping_add(1);
        self.granule = NO_GRANULE;
        self.lacing.clear();
        self.body.clear();
        Ok(())
    }
}

/// Why a page or a stream of them was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// Fewer octets than the header, the segment table or the body needs.
    Truncated,
    /// The page does not start with [`CAPTURE_PATTERN`].
    CapturePattern,
    /// A stream structure version other than [`VERSION`].
    Version(u8),
    /// Header type bits set that §6 does not define.
    ReservedFlags(u8),
    /// The checksum on the page is not the checksum of the page.
    Checksum {
        /// What the page says.
        stored: u32,
        /// What its bytes come to.
        computed: u32,
    },
    /// A page from another logical bitstream.
    Serial {
        /// The serial of the stream's first page.
        expected: u32,
        /// What this page carries.
        found: u32,
    },
    /// A page sequence number out of order, which is a lost page.
    Sequence {
        /// The number that should have come next.
        expected: u32,
        /// What this page carries.
        found: u32,
    },
    /// The first page is not marked BOS, or a later one is.
    BeginningOfStream,
    /// A page after the one marked EOS, or no page marked EOS at all.
    EndOfStream,
    /// A page marked as continuing a packet when none was left open, or not
    /// marked when one was.
    Continuation,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Truncated => f.write_str("the Ogg page is truncated"),
            Self::CapturePattern => f.write_str("no Ogg capture pattern"),
            Self::Version(version) => write!(f, "Ogg stream structure version {version}"),
            Self::ReservedFlags(flags) => write!(f, "undefined Ogg header type bits {flags:#04x}"),
            Self::Checksum { stored, computed } => write!(
                f,
                "the Ogg page says CRC {stored:#010x} and its bytes come to {computed:#010x}"
            ),
            Self::Serial { expected, found } => {
                write!(f, "an Ogg page of stream {found} inside stream {expected}")
            }
            Self::Sequence { expected, found } => {
                write!(f, "Ogg page {found} where page {expected} was due")
            }
            Self::BeginningOfStream => f.write_str("the BOS flag is not on the first page alone"),
            Self::EndOfStream => f.write_str("the EOS flag is not on the last page alone"),
            Self::Continuation => {
                f.write_str("the continuation flag disagrees with the page before")
            }
        }
    }
}

impl core::error::Error for ReadError {}

/// One page, parsed and checked, borrowing the bytes it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page<'a> {
    flags: u8,
    granule: u64,
    serial: u32,
    sequence: u32,
    checksum: u32,
    lacing: &'a [u8],
    body: &'a [u8],
}

impl<'a> Page<'a> {
    /// Parse the page at the start of `bytes`, returning it and how many
    /// octets it took.
    ///
    /// # Errors
    ///
    /// A [`ReadError`] when the capture pattern, the version, the header type
    /// or the checksum is wrong, or the bytes stop before the page does.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, usize), ReadError> {
        let header = bytes.get(..HEADER_LEN).ok_or(ReadError::Truncated)?;
        if header.get(..4) != Some(&CAPTURE_PATTERN[..]) {
            return Err(ReadError::CapturePattern);
        }
        let version = byte_at(header, 4);
        if version != VERSION {
            return Err(ReadError::Version(version));
        }
        let flags = byte_at(header, 5);
        let reserved = flags & !(FLAG_CONTINUED | FLAG_BOS | FLAG_EOS);
        if reserved != 0 {
            return Err(ReadError::ReservedFlags(reserved));
        }
        let granule = u64::from_le_bytes(array_at(header, 6));
        let serial = u32::from_le_bytes(array_at(header, 14));
        let sequence = u32::from_le_bytes(array_at(header, 18));
        let stored = u32::from_le_bytes(array_at(header, CRC_OFFSET));
        let segments = usize::from(byte_at(header, 26));

        let lacing = bytes
            .get(HEADER_LEN..HEADER_LEN + segments)
            .ok_or(ReadError::Truncated)?;
        let body_len: usize = lacing.iter().map(|value| usize::from(*value)).sum();
        let total = HEADER_LEN + segments + body_len;
        let page = bytes.get(..total).ok_or(ReadError::Truncated)?;
        let body = page
            .get(HEADER_LEN + segments..)
            .ok_or(ReadError::Truncated)?;

        let computed = crc_update(
            crc_update(crc(page.get(..CRC_OFFSET).unwrap_or_default()), &[0; 4]),
            page.get(CRC_OFFSET + 4..).unwrap_or_default(),
        );
        if computed != stored {
            return Err(ReadError::Checksum { stored, computed });
        }

        Ok((
            Self {
                flags,
                granule,
                serial,
                sequence,
                checksum: stored,
                lacing,
                body,
            },
            total,
        ))
    }

    /// The header type octet.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether the page begins with the rest of a packet.
    #[must_use]
    pub const fn is_continued(&self) -> bool {
        self.flags & FLAG_CONTINUED != 0
    }

    /// Whether this is the first page of its logical bitstream.
    #[must_use]
    pub const fn is_bos(&self) -> bool {
        self.flags & FLAG_BOS != 0
    }

    /// Whether this is the last page of its logical bitstream.
    #[must_use]
    pub const fn is_eos(&self) -> bool {
        self.flags & FLAG_EOS != 0
    }

    /// The granule position, [`NO_GRANULE`] when no packet finishes here.
    #[must_use]
    pub const fn granule(&self) -> u64 {
        self.granule
    }

    /// The logical bitstream's serial number.
    #[must_use]
    pub const fn serial(&self) -> u32 {
        self.serial
    }

    /// The page sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// The checksum the page carries, already found to be right.
    #[must_use]
    pub const fn checksum(&self) -> u32 {
        self.checksum
    }

    /// The segment table.
    #[must_use]
    pub const fn lacing(&self) -> &'a [u8] {
        self.lacing
    }

    /// The segments, end to end.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }
}

fn byte_at(bytes: &[u8], at: usize) -> u8 {
    bytes.get(at).copied().unwrap_or(0)
}

fn array_at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut array = [0; N];
    if let Some(slice) = bytes.get(at..at + N) {
        array.copy_from_slice(slice);
    }
    array
}

/// One packet taken back out of a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Its octets, reassembled across pages.
    pub data: Vec<u8>,
    /// The granule position of the page it finished on, when it was the last
    /// packet to finish there; `None` for the packets before it on the page.
    pub granule: Option<u64>,
    /// The sequence number of the page it finished on.
    pub page: u32,
    /// Whether that page was the last of the stream.
    pub eos: bool,
}

/// Every page of one logical bitstream, parsed and checked, and every packet
/// reassembled from them.
///
/// Checks, beyond each page's own: one serial throughout, sequence numbers
/// counting up from the first page without a gap, BOS on the first page
/// only, EOS on the last page only, and continuation flags that agree with
/// the lacing of the page before. A packet left open on the last page is an
/// error too.
///
/// # Errors
///
/// The first [`ReadError`] found.
pub fn read_packets(mut bytes: &[u8]) -> Result<Vec<Packet>, ReadError> {
    let mut packets = Vec::new();
    let mut partial: Option<Vec<u8>> = None;
    let mut stream: Option<(u32, u32)> = None;
    let mut ended = false;

    while !bytes.is_empty() {
        let (page, used) = Page::parse(bytes)?;
        bytes = bytes.get(used..).unwrap_or_default();

        if ended {
            return Err(ReadError::EndOfStream);
        }
        match stream {
            None if !page.is_bos() => return Err(ReadError::BeginningOfStream),
            Some(_) if page.is_bos() => return Err(ReadError::BeginningOfStream),
            Some((serial, _)) if page.serial() != serial => {
                return Err(ReadError::Serial {
                    expected: serial,
                    found: page.serial(),
                });
            }
            Some((_, due)) if page.sequence() != due => {
                return Err(ReadError::Sequence {
                    expected: due,
                    found: page.sequence(),
                });
            }
            None | Some(_) => {}
        }
        stream = Some((page.serial(), page.sequence().wrapping_add(1)));
        if page.is_continued() != partial.is_some() {
            return Err(ReadError::Continuation);
        }

        let mut offset = 0;
        let mut current = partial.take().unwrap_or_default();
        let mut finished_here = Vec::new();
        for value in page.lacing() {
            let length = usize::from(*value);
            current.extend_from_slice(page.body().get(offset..offset + length).unwrap_or_default());
            offset += length;
            if *value < 255 {
                finished_here.push(core::mem::take(&mut current));
            }
        }
        // a page ending in 255 leaves its last packet open, and a page with
        // no segments at all leaves open whatever it continued
        let open = match page.lacing().last() {
            Some(value) => *value == 255,
            None => page.is_continued(),
        };
        if open {
            partial = Some(current);
        }
        let count = finished_here.len();
        for (index, data) in finished_here.into_iter().enumerate() {
            packets.push(Packet {
                data,
                granule: (index + 1 == count).then_some(page.granule()),
                page: page.sequence(),
                eos: page.is_eos(),
            });
        }
        ended = page.is_eos();
    }

    if partial.is_some() || !ended {
        return Err(ReadError::EndOfStream);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::{
        CAPTURE_PATTERN, CRC_POLYNOMIAL, FLAG_BOS, FLAG_CONTINUED, FLAG_EOS, HEADER_LEN,
        MAX_SEGMENTS, NO_GRANULE, Page, PageWriter, ReadError, WriteError, crc, crc_update,
        read_packets,
    };

    /// The checksum worked one bit at a time straight from the definition in
    /// §6, as an independent reference for the table-driven one.
    fn crc_by_bits(bytes: &[u8]) -> u32 {
        let mut register: u32 = 0;
        for byte in bytes {
            register ^= u32::from(*byte) << 24;
            for _ in 0..8 {
                register = if register & 0x8000_0000 == 0 {
                    register << 1
                } else {
                    (register << 1) ^ CRC_POLYNOMIAL
                };
            }
        }
        register
    }

    fn pages(bytes: &[u8]) -> Vec<Page<'_>> {
        let mut rest = bytes;
        let mut out = Vec::new();
        while !rest.is_empty() {
            let (page, used) = Page::parse(rest).unwrap();
            out.push(page);
            rest = &rest[used..];
        }
        out
    }

    #[test]
    fn the_checksum_has_the_known_answers_of_the_unreflected_zero_initialised_crc() {
        // the CRC-32 with generator 04C11DB7, register initialised to zero,
        // no reflection and no final inversion; its check value over the
        // ASCII digits one to nine is 89A1897F (CRC-32/POSIX without the
        // final inversion, 765E7680 ^ FFFFFFFF)
        assert_eq!(crc(b"123456789"), 0x89A1_897F);
        assert_eq!(crc(b""), 0);
        // a single octet with only its top bit set is the generator itself,
        // shifted through the other seven bits
        assert_eq!(crc(&[0x01]), CRC_POLYNOMIAL);
        assert_eq!(crc(&[0x00; 16]), 0);
    }

    #[test]
    fn the_table_agrees_with_the_bitwise_definition() {
        let bytes: Vec<u8> = (0..2_000_u32)
            .map(|n| (n * 7919 % 251).to_le_bytes()[0])
            .collect();
        assert_eq!(crc(&bytes), crc_by_bits(&bytes));
        for value in 0..=u8::MAX {
            assert_eq!(crc(&[value]), crc_by_bits(&[value]));
        }
        // and continuing a checksum is the same as taking it in one go
        let (head, tail) = bytes.split_at(777);
        assert_eq!(crc_update(crc(head), tail), crc(&bytes));
    }

    #[test]
    fn a_page_is_laid_out_as_section_6_says() {
        let mut writer = PageWriter::new(0x1234_5678);
        let mut out = Vec::new();
        writer.write_packet(&mut out, b"hello", 42).unwrap();
        writer.finish(&mut out).unwrap();

        assert_eq!(out.len(), HEADER_LEN + 1 + 5);
        assert_eq!(&out[0..4], &CAPTURE_PATTERN);
        assert_eq!(out[4], 0, "stream structure version");
        assert_eq!(out[5], FLAG_BOS | FLAG_EOS);
        assert_eq!(&out[6..14], &42_u64.to_le_bytes());
        assert_eq!(&out[14..18], &0x1234_5678_u32.to_le_bytes());
        assert_eq!(&out[18..22], &0_u32.to_le_bytes());
        assert_eq!(out[26], 1, "one segment");
        assert_eq!(out[27], 5, "its lacing value");
        assert_eq!(&out[28..], b"hello");

        // the stored CRC is the checksum of the page with the field zeroed,
        // least significant octet first
        let stored = u32::from_le_bytes(out[22..26].try_into().unwrap());
        let mut zeroed = out.clone();
        zeroed[22..26].fill(0);
        assert_eq!(stored, crc_by_bits(&zeroed));
    }

    #[test]
    fn a_packet_is_laced_as_255s_and_a_remainder_with_a_zero_after_an_exact_multiple() {
        for (length, lacing) in [
            (0, vec![0]),
            (254, vec![254]),
            (255, vec![255, 0]),
            (256, vec![255, 1]),
            (510, vec![255, 255, 0]),
            (600, vec![255, 255, 90]),
        ] {
            let mut writer = PageWriter::new(1);
            let mut out = Vec::new();
            writer
                .write_packet(&mut out, &vec![0xA5; length], 7)
                .unwrap();
            writer.finish(&mut out).unwrap();
            let page = pages(&out)[0];
            assert_eq!(page.lacing(), &lacing[..], "a packet of {length}");
            assert_eq!(page.body().len(), length);
        }
    }

    #[test]
    fn a_full_segment_table_starts_a_new_page_that_continues_the_packet() {
        // 300 segments' worth in one packet: 255 fit, the rest spill over
        let packet: Vec<u8> = (0..300 * 255 + 10_u32)
            .map(|n| n.to_le_bytes()[0])
            .collect();
        let mut writer = PageWriter::new(9);
        let mut out = Vec::new();
        writer.write_packet(&mut out, &packet, 1_000).unwrap();
        assert_eq!(
            writer.pages_written(),
            1,
            "the first page went out when it filled"
        );
        writer.finish(&mut out).unwrap();

        let pages = pages(&out);
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].lacing().len(), MAX_SEGMENTS);
        assert_eq!(pages[0].flags(), FLAG_BOS);
        assert_eq!(pages[0].granule(), NO_GRANULE, "no packet finishes on it");
        assert_eq!(pages[1].flags(), FLAG_CONTINUED | FLAG_EOS);
        assert_eq!(pages[1].granule(), 1_000);
        assert_eq!(pages[1].sequence(), 1);

        let packets = read_packets(&out).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data, packet);
        assert_eq!(packets[0].granule, Some(1_000));
    }

    #[test]
    fn a_packet_ending_exactly_at_a_full_table_takes_its_zero_onto_the_next_page() {
        let packet = vec![3_u8; 255 * 255];
        let mut writer = PageWriter::new(9);
        let mut out = Vec::new();
        writer.write_packet(&mut out, &packet, 5).unwrap();
        writer.finish(&mut out).unwrap();

        let pages = pages(&out);
        assert_eq!(pages[1].lacing(), &[0]);
        assert!(pages[1].is_continued());
        assert_eq!(read_packets(&out).unwrap()[0].data, packet);
    }

    #[test]
    fn a_packet_fits_while_its_lacing_values_fit_the_table_left() {
        let mut writer = PageWriter::new(9);
        let mut out = Vec::new();
        assert!(
            writer.fits(254 * 255 + 254),
            "255 lacing values on a new page"
        );
        assert!(
            !writer.fits(255 * 255),
            "the terminating zero is one too many"
        );
        // 252 lacing values taken, three left
        for _ in 0..63 {
            writer.write_packet(&mut out, &[0; 1_000], 1).unwrap();
        }
        assert!(writer.fits(2 * 255 + 254));
        assert!(!writer.fits(3 * 255));
        assert!(!writer.fits(usize::MAX));
        assert!(out.is_empty(), "nothing went out");
    }

    #[test]
    fn flush_cuts_a_page_and_the_granule_is_that_of_the_last_packet_on_it() {
        let mut writer = PageWriter::new(77);
        let mut out = Vec::new();
        writer.write_packet(&mut out, b"head", 0).unwrap();
        writer.flush(&mut out).unwrap();
        writer.flush(&mut out).unwrap();
        assert_eq!(writer.pages_written(), 1, "an empty flush writes nothing");
        writer.write_packet(&mut out, b"one", 960).unwrap();
        writer.write_packet(&mut out, b"two", 1_920).unwrap();
        assert!(!writer.is_empty());
        writer.finish(&mut out).unwrap();

        let pages = pages(&out);
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].granule(), 0);
        assert_eq!(pages[1].granule(), 1_920);
        assert_eq!(pages[1].flags(), FLAG_EOS);

        let packets = read_packets(&out).unwrap();
        let data: Vec<&[u8]> = packets.iter().map(|p| &p.data[..]).collect();
        assert_eq!(data, [&b"head"[..], b"one", b"two"]);
        assert_eq!(packets[1].granule, None);
        assert_eq!(packets[2].granule, Some(1_920));
        assert!(packets[2].eos);
    }

    #[test]
    fn nothing_is_written_after_the_end() {
        let mut writer = PageWriter::new(1);
        let mut out = Vec::new();
        writer.finish(&mut out).unwrap();
        assert!(matches!(
            writer.write_packet(&mut out, b"late", 1),
            Err(WriteError::Finished)
        ));
        assert!(matches!(writer.flush(&mut out), Err(WriteError::Finished)));
        assert!(matches!(writer.finish(&mut out), Err(WriteError::Finished)));
        // the one page there is: BOS and EOS together, no segments
        let page = pages(&out)[0];
        assert_eq!(page.flags(), FLAG_BOS | FLAG_EOS);
        assert!(page.lacing().is_empty());
    }

    fn two_pages() -> Vec<u8> {
        let mut writer = PageWriter::new(5);
        let mut out = Vec::new();
        writer.write_packet(&mut out, b"first", 1).unwrap();
        writer.flush(&mut out).unwrap();
        writer.write_packet(&mut out, b"second", 2).unwrap();
        writer.finish(&mut out).unwrap();
        out
    }

    /// Rewrite the CRC of the page starting at `at` after tampering with it.
    fn reseal(bytes: &mut [u8], at: usize) {
        let segments = usize::from(bytes[at + 26]);
        let body: usize = bytes[at + 27..at + 27 + segments]
            .iter()
            .map(|v| usize::from(*v))
            .sum();
        let end = at + 27 + segments + body;
        bytes[at + 22..at + 26].fill(0);
        let sum = crc(&bytes[at..end]);
        bytes[at + 22..at + 26].copy_from_slice(&sum.to_le_bytes());
    }

    #[test]
    fn a_damaged_page_fails_its_checksum() {
        let mut bytes = two_pages();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(matches!(
            read_packets(&bytes),
            Err(ReadError::Checksum { .. })
        ));
    }

    #[test]
    fn the_header_fields_are_checked() {
        let good = two_pages();
        let second = Page::parse(&good).unwrap().1;

        let mut bytes = good.clone();
        bytes[0] = b'o';
        assert_eq!(Page::parse(&bytes), Err(ReadError::CapturePattern));

        let mut bytes = good.clone();
        bytes[4] = 1;
        assert_eq!(Page::parse(&bytes), Err(ReadError::Version(1)));

        let mut bytes = good.clone();
        bytes[5] |= 0x08;
        assert_eq!(Page::parse(&bytes), Err(ReadError::ReservedFlags(0x08)));

        assert_eq!(Page::parse(&good[..20]), Err(ReadError::Truncated));
        assert_eq!(Page::parse(&good[..second - 1]), Err(ReadError::Truncated));

        // a lost page: the second page says 2 where 1 is due
        let mut bytes = good.clone();
        bytes[second + 18] = 2;
        reseal(&mut bytes, second);
        assert_eq!(
            read_packets(&bytes),
            Err(ReadError::Sequence {
                expected: 1,
                found: 2
            })
        );

        // a page from another stream
        let mut bytes = good.clone();
        bytes[second + 14] = 6;
        reseal(&mut bytes, second);
        assert_eq!(
            read_packets(&bytes),
            Err(ReadError::Serial {
                expected: 5,
                found: 6
            })
        );

        // a continuation where nothing was left open
        let mut bytes = good.clone();
        bytes[second + 5] |= FLAG_CONTINUED;
        reseal(&mut bytes, second);
        assert_eq!(read_packets(&bytes), Err(ReadError::Continuation));

        // BOS twice, and no BOS at all
        let mut bytes = good.clone();
        bytes[second + 5] |= FLAG_BOS;
        reseal(&mut bytes, second);
        assert_eq!(read_packets(&bytes), Err(ReadError::BeginningOfStream));
        assert_eq!(
            read_packets(&good[second..]),
            Err(ReadError::BeginningOfStream)
        );

        // a stream cut before its EOS page, and a page after it
        assert_eq!(read_packets(&good[..second]), Err(ReadError::EndOfStream));
        let mut bytes = good.clone();
        bytes[5] |= FLAG_EOS;
        reseal(&mut bytes, 0);
        assert_eq!(read_packets(&bytes), Err(ReadError::EndOfStream));

        assert_eq!(read_packets(&good).unwrap().len(), 2);
    }

    #[test]
    fn a_page_left_open_at_the_end_is_refused() {
        let mut writer = PageWriter::new(3);
        let mut out = Vec::new();
        writer
            .write_packet(&mut out, &vec![1; 255 * 255], 1)
            .unwrap();
        // the first page went out full and ends in 255; drop the rest
        assert_eq!(writer.pages_written(), 1);
        let mut bytes = out.clone();
        bytes[5] |= FLAG_EOS;
        reseal(&mut bytes, 0);
        assert_eq!(read_packets(&bytes), Err(ReadError::EndOfStream));
    }

    /// A sealed page with no segments.
    fn empty_page(flags: u8, serial: u32, sequence: u32) -> Vec<u8> {
        let mut page = CAPTURE_PATTERN.to_vec();
        page.extend_from_slice(&[0, flags]);
        page.extend_from_slice(&NO_GRANULE.to_le_bytes());
        page.extend_from_slice(&serial.to_le_bytes());
        page.extend_from_slice(&sequence.to_le_bytes());
        page.extend_from_slice(&[0; 5]);
        reseal(&mut page, 0);
        page
    }

    #[test]
    fn a_page_without_segments_leaves_the_open_packet_open() {
        // a first page that is full and ends in 255, its packet still open
        let mut writer = PageWriter::new(3);
        let mut first = Vec::new();
        writer
            .write_packet(&mut first, &vec![1; 255 * 255], 1)
            .unwrap();
        assert_eq!(writer.pages_written(), 1);

        // an EOS page that continues the packet with nothing: it never ends
        let mut bytes = first.clone();
        bytes.extend_from_slice(&empty_page(FLAG_CONTINUED | FLAG_EOS, 3, 1));
        assert_eq!(read_packets(&bytes), Err(ReadError::EndOfStream));

        // a page after the empty one that says it starts afresh
        let mut bytes = first.clone();
        bytes.extend_from_slice(&empty_page(FLAG_CONTINUED, 3, 1));
        let mut fresh = PageWriter::new(3);
        let mut rest = Vec::new();
        fresh.write_packet(&mut rest, b"new", 2).unwrap();
        fresh.finish(&mut rest).unwrap();
        rest[5] = FLAG_EOS;
        rest[18] = 2;
        reseal(&mut rest, 0);
        bytes.extend_from_slice(&rest);
        assert_eq!(read_packets(&bytes), Err(ReadError::Continuation));
    }

    #[test]
    fn a_page_that_does_not_continue_the_open_packet_is_refused() {
        let mut writer = PageWriter::new(3);
        let mut out = Vec::new();
        writer
            .write_packet(&mut out, &vec![1; 255 * 255 + 4], 1)
            .unwrap();
        writer.finish(&mut out).unwrap();
        let second = Page::parse(&out).unwrap().1;
        assert!(read_packets(&out).is_ok());
        let mut bytes = out.clone();
        bytes[second + 5] &= !FLAG_CONTINUED;
        reseal(&mut bytes, second);
        assert_eq!(read_packets(&bytes), Err(ReadError::Continuation));
    }
}
