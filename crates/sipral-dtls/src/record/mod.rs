// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The DTLS record layer (RFC 6347 §4.1).
//!
//! The record header with its epoch and 48-bit sequence number, the
//! unprotected records of epoch 0, AES-128-GCM protection for the records
//! after ChangeCipherSpec (RFC 5288), and the anti-replay window. Records are
//! read out of a datagram and written into one; which epoch a record belongs
//! to, which keys open it, and what to do with one that fails is the
//! handshake's business.

mod protection;
mod replay;

pub use protection::{EXPLICIT_NONCE_LEN, GCM_OVERHEAD, GcmProtection, TAG_LEN};
pub use replay::ReplayWindow;

use crate::Error;
use crate::wire::{self, Reader};

/// Octets in the record header: type, version, epoch, sequence number, length.
pub const HEADER_LEN: usize = 13;
/// RFC 5246 §6.2.1: a plaintext fragment "MUST NOT exceed 2^14".
pub const MAX_PLAINTEXT_LEN: usize = 1 << 14;
/// RFC 5246 §6.2.3: a ciphertext fragment "MUST NOT exceed 2^14 + 2048".
pub const MAX_CIPHERTEXT_LEN: usize = MAX_PLAINTEXT_LEN + 2048;
/// The highest 48-bit sequence number. RFC 6347 §4.1 forbids wrapping past it.
pub const MAX_SEQUENCE: u64 = (1 << 48) - 1;

/// `ContentType` (RFC 5246 §6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentType(pub u8);

impl ContentType {
    /// `change_cipher_spec(20)`.
    pub const CHANGE_CIPHER_SPEC: Self = Self(20);
    /// `alert(21)`.
    pub const ALERT: Self = Self(21);
    /// `handshake(22)`.
    pub const HANDSHAKE: Self = Self(22);
    /// `application_data(23)`.
    pub const APPLICATION_DATA: Self = Self(23);
}

/// `ProtocolVersion`, as DTLS writes it: the one's complement of the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    /// The first octet.
    pub major: u8,
    /// The second octet.
    pub minor: u8,
}

impl ProtocolVersion {
    /// `{254, 255}`. RFC 6347 §4.2.1 has a server put it in HelloVerifyRequest
    /// whatever version it goes on to negotiate.
    pub const DTLS_1_0: Self = Self {
        major: 254,
        minor: 255,
    };
    /// `{254, 253}` (RFC 6347 §4.1).
    pub const DTLS_1_2: Self = Self {
        major: 254,
        minor: 253,
    };

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let [major, minor] = r.array()?;
        Ok(Self { major, minor })
    }

    pub(crate) fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[self.major, self.minor]);
    }
}

/// The fields of `DTLSPlaintext` and `DTLSCiphertext` in front of the fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordHeader {
    /// What the fragment carries.
    pub content_type: ContentType,
    /// The version on the record.
    pub version: ProtocolVersion,
    /// Incremented on every cipher state change.
    pub epoch: u16,
    /// The record's sequence number within its epoch, 48 bits.
    pub sequence: u64,
    /// Octets in the fragment.
    pub length: u16,
}

impl RecordHeader {
    /// Write the thirteen header octets.
    ///
    /// # Errors
    ///
    /// [`Error::SequenceExhausted`] for a sequence number wider than 48 bits.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.sequence > MAX_SEQUENCE {
            return Err(Error::SequenceExhausted);
        }
        wire::put_u8(out, self.content_type.0);
        self.version.write(out);
        wire::put_u16(out, self.epoch);
        wire::put_u48(out, self.sequence)?;
        wire::put_u16(out, self.length);
        Ok(())
    }

    /// The epoch and the sequence number as the one 64-bit value RFC 6347
    /// §4.1.2.1 authenticates in place of TLS's implicit sequence number.
    #[must_use]
    pub const fn epoch_and_sequence(&self) -> [u8; 8] {
        epoch_and_sequence(self.epoch, self.sequence)
    }
}

pub(crate) const fn epoch_and_sequence(epoch: u16, sequence: u64) -> [u8; 8] {
    ((epoch as u64) << 48 | (sequence & MAX_SEQUENCE)).to_be_bytes()
}

/// One record as it arrived: its header and its fragment, protected or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// The header.
    pub header: RecordHeader,
    /// `DTLSPlaintext.fragment` or `DTLSCiphertext.fragment`, exactly
    /// `header.length` octets.
    pub fragment: &'a [u8],
}

impl<'a> Record<'a> {
    /// Read the record at the front of `datagram`, and return it with what
    /// follows it.
    ///
    /// RFC 6347 §4.1.1: records are "simply encoded consecutively" and "may not
    /// span datagrams", so a length that runs past the datagram is an invalid
    /// record, not the start of one that continues elsewhere.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] for a header or fragment cut short;
    /// [`Error::TooLarge`] for a length over 2^14 + 2048.
    pub fn parse(datagram: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let mut r = Reader::new(datagram);
        let content_type = ContentType(r.u8()?);
        let version = ProtocolVersion::read(&mut r)?;
        let epoch = r.u16()?;
        let sequence = r.u48()?;
        let length = r.u16()?;
        if usize::from(length) > MAX_CIPHERTEXT_LEN {
            return Err(Error::TooLarge);
        }
        let fragment = r.take(usize::from(length))?;
        let header = RecordHeader {
            content_type,
            version,
            epoch,
            sequence,
            length,
        };
        Ok((Self { header, fragment }, r.rest()))
    }

    /// The fragment of an unprotected record, held to the plaintext limit.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] when it is longer than 2^14 octets.
    pub const fn plaintext(&self) -> Result<&'a [u8], Error> {
        if self.fragment.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::TooLarge);
        }
        Ok(self.fragment)
    }
}

/// The records of one datagram, front to back.
///
/// Iteration stops after the first record that cannot be read: its length is
/// what says where the next one begins, and a record that cannot be read has
/// no length to believe.
#[derive(Debug, Clone)]
pub struct Records<'a> {
    rest: &'a [u8],
}

/// Read every record in `datagram`.
#[must_use]
pub const fn records(datagram: &[u8]) -> Records<'_> {
    Records { rest: datagram }
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match Record::parse(self.rest) {
            Ok((record, rest)) => {
                self.rest = rest;
                Some(Ok(record))
            }
            Err(error) => {
                self.rest = &[];
                Some(Err(error))
            }
        }
    }
}

/// Refuse a fragment RFC 5246 §6.2.1 forbids sending: longer than 2^14, or
/// empty for anything but application data.
pub(crate) const fn check_fragment(content_type: ContentType, len: usize) -> Result<(), Error> {
    if len > MAX_PLAINTEXT_LEN {
        return Err(Error::TooLarge);
    }
    // "Implementations MUST NOT send zero-length fragments of Handshake,
    // Alert, or ChangeCipherSpec content types."
    if len == 0 && content_type.0 != ContentType::APPLICATION_DATA.0 {
        return Err(Error::Length);
    }
    Ok(())
}

/// Write one unprotected record, as sent in epoch 0.
///
/// # Errors
///
/// [`Error::TooLarge`] for a fragment over 2^14 octets; [`Error::Length`] for
/// an empty one of any type but application data; [`Error::SequenceExhausted`]
/// for a sequence number wider than 48 bits. Nothing is written on error.
pub fn encode_plaintext(
    content_type: ContentType,
    version: ProtocolVersion,
    epoch: u16,
    sequence: u64,
    fragment: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    check_fragment(content_type, fragment.len())?;
    let length = u16::try_from(fragment.len()).map_err(|_| Error::TooLarge)?;
    let header = RecordHeader {
        content_type,
        version,
        epoch,
        sequence,
        length,
    };
    let start = out.len();
    if let Err(error) = header.encode(out) {
        out.truncate(start);
        return Err(error);
    }
    out.extend_from_slice(fragment);
    Ok(())
}

/// The sending side of one epoch: which epoch, and the sequence number the
/// next record takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteEpoch {
    epoch: u16,
    next: u64,
}

impl WriteEpoch {
    /// Epoch 0, sequence number 0: where every handshake starts.
    #[must_use]
    pub const fn initial() -> Self {
        Self { epoch: 0, next: 0 }
    }

    /// Epoch 0, its next record taking `sequence`.
    ///
    /// For a server that kept no state across a cookie exchange: RFC 6347
    /// §4.2.1 has it "use the record sequence number in the ClientHello as
    /// the record sequence number in its initial ServerHello", and count on
    /// from there.
    ///
    /// # Errors
    ///
    /// [`Error::SequenceExhausted`] for a sequence number wider than 48 bits.
    pub const fn starting_at(sequence: u64) -> Result<Self, Error> {
        if sequence > MAX_SEQUENCE {
            return Err(Error::SequenceExhausted);
        }
        Ok(Self {
            epoch: 0,
            next: sequence,
        })
    }

    /// The epoch records are sent in.
    #[must_use]
    pub const fn epoch(&self) -> u16 {
        self.epoch
    }

    /// Take the sequence number for the next record.
    ///
    /// # Errors
    ///
    /// [`Error::SequenceExhausted`] once 2^48 - 1 has been handed out: RFC 6347
    /// §4.1 requires abandoning the association rather than wrapping.
    pub const fn next_sequence(&mut self) -> Result<u64, Error> {
        if self.next > MAX_SEQUENCE {
            return Err(Error::SequenceExhausted);
        }
        let sequence = self.next;
        self.next += 1;
        Ok(sequence)
    }

    /// The epoch after this one, its sequence numbers starting again at 0
    /// ("maintained separately for each epoch", §4.1).
    ///
    /// # Errors
    ///
    /// [`Error::SequenceExhausted`] from epoch 65535, since "implementations
    /// MUST NOT allow the epoch to wrap".
    pub const fn advance(&self) -> Result<Self, Error> {
        match self.epoch.checked_add(1) {
            Some(epoch) => Ok(Self { epoch, next: 0 }),
            None => Err(Error::SequenceExhausted),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: [u8; 16] = [
        22, // handshake
        254, 253, // DTLS 1.2
        0x00, 0x01, // epoch 1
        0x00, 0x00, 0x01, 0x02, 0x03, 0x04, // sequence number
        0x00, 0x03, // three octets follow
        0xAA, 0xBB, 0xCC,
    ];

    #[test]
    fn a_record_reads_in_the_field_order_of_rfc_6347() {
        let (record, rest) = Record::parse(&RECORD).unwrap();
        assert_eq!(
            record.header,
            RecordHeader {
                content_type: ContentType::HANDSHAKE,
                version: ProtocolVersion::DTLS_1_2,
                epoch: 1,
                sequence: 0x0102_0304,
                length: 3,
            }
        );
        assert_eq!(record.fragment, [0xAA, 0xBB, 0xCC]);
        assert!(rest.is_empty());
        assert_eq!(record.header.epoch_and_sequence(), [0, 1, 0, 0, 1, 2, 3, 4]);

        let mut out = Vec::new();
        encode_plaintext(
            record.header.content_type,
            record.header.version,
            record.header.epoch,
            record.header.sequence,
            record.fragment,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, RECORD);
    }

    #[test]
    fn every_truncation_of_a_record_is_refused() {
        for cut in 0..RECORD.len() {
            assert_eq!(
                Record::parse(&RECORD[..cut]),
                Err(Error::Truncated),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn records_packed_into_one_datagram_come_out_in_order_until_one_is_broken() {
        let mut datagram = RECORD.to_vec();
        datagram.extend_from_slice(&[20, 254, 253, 0, 1, 0, 0, 0, 0, 0, 9, 0, 1, 1]);
        // a third whose length runs past the end of the datagram
        datagram.extend_from_slice(&[23, 254, 253, 0, 1, 0, 0, 0, 0, 0, 10, 0, 5, 1]);

        let mut it = records(&datagram);
        assert_eq!(it.next().unwrap().unwrap().fragment, [0xAA, 0xBB, 0xCC]);
        let ccs = it.next().unwrap().unwrap();
        assert_eq!(ccs.header.content_type, ContentType::CHANGE_CIPHER_SPEC);
        assert_eq!(ccs.header.sequence, 9);
        assert_eq!(ccs.fragment, [1]);
        assert_eq!(it.next(), Some(Err(Error::Truncated)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn nothing_after_an_unreadable_record_is_read() {
        // a header announcing more than the ciphertext limit, followed by
        // octets that would read as a perfectly good record
        let mut datagram = vec![23, 254, 253, 0, 1, 0, 0, 0, 0, 0, 10, 0xFF, 0xFF];
        datagram.extend_from_slice(&RECORD);
        let mut it = records(&datagram);
        assert_eq!(it.next(), Some(Err(Error::TooLarge)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn record_lengths_are_held_to_rfc_5246() {
        let mut header = vec![23, 254, 253, 0, 1, 0, 0, 0, 0, 0, 0];
        let over = u16::try_from(MAX_CIPHERTEXT_LEN + 1).unwrap();
        header.extend_from_slice(&over.to_be_bytes());
        header.resize(HEADER_LEN + MAX_CIPHERTEXT_LEN + 1, 0);
        assert_eq!(Record::parse(&header), Err(Error::TooLarge));

        // the ciphertext limit is also the most an unprotected record may
        // arrive with, but its fragment is then held to 2^14
        let mut plain = vec![22, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0];
        let len = u16::try_from(MAX_PLAINTEXT_LEN + 1).unwrap();
        plain.extend_from_slice(&len.to_be_bytes());
        plain.resize(HEADER_LEN + MAX_PLAINTEXT_LEN + 1, 0);
        let (record, _) = Record::parse(&plain).unwrap();
        assert_eq!(record.plaintext(), Err(Error::TooLarge));
    }

    #[test]
    fn what_rfc_5246_forbids_sending_is_not_written() {
        let mut out = vec![0xEE];
        let v = ProtocolVersion::DTLS_1_2;
        assert_eq!(
            encode_plaintext(ContentType::HANDSHAKE, v, 0, 0, &[], &mut out),
            Err(Error::Length)
        );
        assert_eq!(
            encode_plaintext(ContentType::ALERT, v, 0, 0, &[], &mut out),
            Err(Error::Length)
        );
        assert_eq!(
            encode_plaintext(
                ContentType::HANDSHAKE,
                v,
                0,
                0,
                &vec![0; MAX_PLAINTEXT_LEN + 1],
                &mut out
            ),
            Err(Error::TooLarge)
        );
        assert_eq!(
            encode_plaintext(
                ContentType::HANDSHAKE,
                v,
                0,
                MAX_SEQUENCE + 1,
                &[1],
                &mut out
            ),
            Err(Error::SequenceExhausted)
        );
        assert_eq!(out, [0xEE]);
        encode_plaintext(
            ContentType::APPLICATION_DATA,
            v,
            0,
            MAX_SEQUENCE,
            &[],
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 1 + HEADER_LEN);
    }

    #[test]
    fn sequence_numbers_run_to_forty_eight_bits_and_stop() {
        let mut epoch = WriteEpoch::initial();
        assert_eq!(epoch.next_sequence(), Ok(0));
        assert_eq!(epoch.next_sequence(), Ok(1));

        let mut near = WriteEpoch {
            epoch: 3,
            next: MAX_SEQUENCE,
        };
        assert_eq!(near.next_sequence(), Ok(MAX_SEQUENCE));
        assert_eq!(near.next_sequence(), Err(Error::SequenceExhausted));
        assert_eq!(near.next_sequence(), Err(Error::SequenceExhausted));

        let mut next = near.advance().unwrap();
        assert_eq!(next.epoch(), 4);
        assert_eq!(next.next_sequence(), Ok(0));

        let last = WriteEpoch {
            epoch: u16::MAX,
            next: 7,
        };
        assert_eq!(last.advance(), Err(Error::SequenceExhausted));
    }

    #[test]
    fn a_stateless_server_counts_on_from_the_client_hellos_sequence_number() {
        let mut epoch = WriteEpoch::starting_at(41).unwrap();
        assert_eq!(epoch.epoch(), 0);
        assert_eq!(epoch.next_sequence(), Ok(41));
        assert_eq!(epoch.next_sequence(), Ok(42));
        let mut last = WriteEpoch::starting_at(MAX_SEQUENCE).unwrap();
        assert_eq!(last.next_sequence(), Ok(MAX_SEQUENCE));
        assert_eq!(last.next_sequence(), Err(Error::SequenceExhausted));
        assert_eq!(
            WriteEpoch::starting_at(MAX_SEQUENCE + 1),
            Err(Error::SequenceExhausted)
        );
    }
}
