// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The DTLS handshake protocol: its framing, its messages, and the cookie
//! exchange (RFC 6347 §4.2).
//!
//! Framing first. A DTLS handshake message carries a twelve-octet header
//! where TLS carries four: beside the type and length, the message's sequence
//! number and the offset and length of the piece this record holds (§4.2.2).
//! [`fragment_message`] cuts a message to fit a path MTU, [`Reassembler`]
//! puts the pieces back together with a bound on everything a peer can make
//! it hold, and [`Transcript`] hashes each message the way §4.2.6 requires:
//! as if it had been sent whole.
//!
//! Then the messages of an `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` handshake,
//! each read strictly — every length checked against its field's bounds,
//! nothing left over — and written back to the same octets.

mod cookie;
mod extensions;
mod hello;
mod messages;
mod reassembly;

pub use cookie::{COOKIE_LEN, CookieSecret};
pub use extensions::{
    EcPointFormat, Extension, ExtensionType, Extensions, NamedGroup, SignatureAndHash,
    SrtpProtectionProfile, UseSrtp,
};
pub use hello::{
    COMPRESSION_NULL, CipherSuite, ClientHello, HelloVerifyRequest, MAX_COOKIE_LEN,
    MAX_SESSION_ID_LEN, ServerHello,
};
pub use messages::{
    Certificate, CertificateRequest, CertificateVerify, ChangeCipherSpec, ClientKeyExchange,
    DigitallySigned, Finished, HandshakeMessage, NAMED_CURVE, ServerKeyExchange,
};
pub use reassembly::{Limits, Message, Offered, Reassembler};

use core::fmt;

use sha2::{Digest, Sha256};

use crate::Error;
use crate::prf::HASH_LEN;
use crate::record;
use crate::wire::{self, Reader};

/// Octets in the DTLS handshake header.
pub const HEADER_LEN: usize = 12;
/// The longest message a 24-bit length can announce.
pub const MAX_MESSAGE_LEN: usize = (1 << 24) - 1;
const MAX_LENGTH_FIELD: u32 = (1 << 24) - 1;

/// `HandshakeType` (RFC 6347 §4.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandshakeType(pub u8);

impl HandshakeType {
    /// `hello_request(0)`, which asks for a renegotiation this crate refuses.
    pub const HELLO_REQUEST: Self = Self(0);
    /// `client_hello(1)`.
    pub const CLIENT_HELLO: Self = Self(1);
    /// `server_hello(2)`.
    pub const SERVER_HELLO: Self = Self(2);
    /// `hello_verify_request(3)`.
    pub const HELLO_VERIFY_REQUEST: Self = Self(3);
    /// `certificate(11)`.
    pub const CERTIFICATE: Self = Self(11);
    /// `server_key_exchange(12)`.
    pub const SERVER_KEY_EXCHANGE: Self = Self(12);
    /// `certificate_request(13)`.
    pub const CERTIFICATE_REQUEST: Self = Self(13);
    /// `server_hello_done(14)`.
    pub const SERVER_HELLO_DONE: Self = Self(14);
    /// `certificate_verify(15)`.
    pub const CERTIFICATE_VERIFY: Self = Self(15);
    /// `client_key_exchange(16)`.
    pub const CLIENT_KEY_EXCHANGE: Self = Self(16);
    /// `finished(20)`.
    pub const FINISHED: Self = Self(20);
}

/// The DTLS handshake header (RFC 6347 §4.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentHeader {
    /// The message's type.
    pub msg_type: HandshakeType,
    /// The whole message's body length, the same in every fragment of it.
    pub length: u32,
    /// The message's place in the sender's sequence of handshake messages.
    pub message_seq: u16,
    /// Octets of the body in front of this fragment.
    pub fragment_offset: u32,
    /// Octets of the body in this fragment.
    pub fragment_length: u32,
}

impl FragmentHeader {
    /// The header of a message sent in one piece, which is also the header
    /// every message is hashed under (RFC 6347 §4.2.6).
    #[must_use]
    pub const fn whole(msg_type: HandshakeType, message_seq: u16, length: u32) -> Self {
        Self {
            msg_type,
            length,
            message_seq,
            fragment_offset: 0,
            fragment_length: length,
        }
    }

    /// Refuse a header whose fragment does not lie inside its message, or
    /// that carries nothing of a message that has something.
    const fn check(&self) -> Result<(), Error> {
        if self.length > MAX_LENGTH_FIELD {
            return Err(Error::TooLarge);
        }
        match self.fragment_offset.checked_add(self.fragment_length) {
            Some(end) if end <= self.length => {}
            _ => return Err(Error::IllegalValue),
        }
        // an empty fragment of a message that has a body moves nothing
        // forward, and no sender has a reason to write one
        if self.fragment_length == 0 && self.length != 0 {
            return Err(Error::IllegalValue);
        }
        Ok(())
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::put_u8(out, self.msg_type.0);
        wire::put_u24(out, self.length)?;
        wire::put_u16(out, self.message_seq);
        wire::put_u24(out, self.fragment_offset)?;
        wire::put_u24(out, self.fragment_length)
    }
}

/// One handshake fragment as it arrived in a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment<'a> {
    /// The header.
    pub header: FragmentHeader,
    /// `header.fragment_length` octets of the message body.
    pub body: &'a [u8],
}

impl<'a> Fragment<'a> {
    /// Read the fragment at the front of a handshake record's payload, and
    /// return it with what follows it — RFC 6347 §4.2.3 lets several share a
    /// record.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when the header or body is cut short;
    /// [`Error::IllegalValue`] when the fragment reaches past the end of its
    /// message, or is empty and its message is not.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let mut r = Reader::new(bytes);
        let header = FragmentHeader {
            msg_type: HandshakeType(r.u8()?),
            length: r.u24()?,
            message_seq: r.u16()?,
            fragment_offset: r.u24()?,
            fragment_length: r.u24()?,
        };
        header.check()?;
        let body = r.take(usize::try_from(header.fragment_length).map_err(|_| Error::Length)?)?;
        Ok((Self { header, body }, r.rest()))
    }

    /// Write the fragment, header then body.
    ///
    /// # Errors
    ///
    /// The errors [`Fragment::parse`] would report for the same fragment, and
    /// [`Error::Length`] when the body is not `fragment_length` octets.
    /// Nothing is written on error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.header.check()?;
        if usize::try_from(self.header.fragment_length) != Ok(self.body.len()) {
            return Err(Error::Length);
        }
        let start = out.len();
        if let Err(error) = self.header.write(out) {
            out.truncate(start);
            return Err(error);
        }
        out.extend_from_slice(self.body);
        Ok(())
    }
}

/// The handshake fragments of one record's payload, front to back, stopping
/// after the first that cannot be read.
#[derive(Debug, Clone)]
pub struct Fragments<'a> {
    rest: &'a [u8],
}

/// Read every handshake fragment in a record's payload.
#[must_use]
pub const fn fragments(payload: &[u8]) -> Fragments<'_> {
    Fragments { rest: payload }
}

impl<'a> Iterator for Fragments<'a> {
    type Item = Result<Fragment<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match Fragment::parse(self.rest) {
            Ok((fragment, rest)) => {
                self.rest = rest;
                Some(Ok(fragment))
            }
            Err(error) => {
                self.rest = &[];
                Some(Err(error))
            }
        }
    }
}

fn message_len(body: &[u8]) -> Result<u32, Error> {
    if body.len() > MAX_MESSAGE_LEN {
        return Err(Error::TooLarge);
    }
    u32::try_from(body.len()).map_err(|_| Error::TooLarge)
}

/// Write a whole message as a single fragment.
///
/// # Errors
///
/// [`Error::TooLarge`] for a body longer than 2^24 - 1 octets.
pub fn encode_message(
    msg_type: HandshakeType,
    message_seq: u16,
    body: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let header = FragmentHeader::whole(msg_type, message_seq, message_len(body)?);
    Fragment { header, body }.encode(out)
}

/// Cut a message into fragments of at most `max_fragment` octets each, header
/// included, in order and without overlap — the "N contiguous data ranges" of
/// RFC 6347 §4.2.3. Each fragment is ready to be the payload of a record, or
/// to share one with others that fit, so none is longer than the 2^14 octets
/// RFC 5246 §6.2.1 allows a record's fragment, whatever `max_fragment` says.
///
/// A message whose body is empty still goes out as one fragment.
///
/// # Errors
///
/// [`Error::MtuTooSmall`] when `max_fragment` leaves no room for a body
/// octet; [`Error::TooLarge`] for a body longer than 2^24 - 1 octets.
pub fn fragment_message(
    msg_type: HandshakeType,
    message_seq: u16,
    body: &[u8],
    max_fragment: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    let length = message_len(body)?;
    let per_fragment = max_fragment
        .min(record::MAX_PLAINTEXT_LEN)
        .checked_sub(HEADER_LEN)
        .filter(|&n| n > 0)
        .ok_or(Error::MtuTooSmall)?;
    if body.is_empty() {
        let mut out = Vec::with_capacity(HEADER_LEN);
        encode_message(msg_type, message_seq, body, &mut out)?;
        return Ok(vec![out]);
    }
    let mut fragments = Vec::with_capacity(body.len().div_ceil(per_fragment));
    let mut offset = 0u32;
    for piece in body.chunks(per_fragment) {
        let fragment_length = u32::try_from(piece.len()).map_err(|_| Error::TooLarge)?;
        let header = FragmentHeader {
            msg_type,
            length,
            message_seq,
            fragment_offset: offset,
            fragment_length,
        };
        let mut out = Vec::with_capacity(HEADER_LEN + piece.len());
        Fragment {
            header,
            body: piece,
        }
        .encode(&mut out)?;
        fragments.push(out);
        offset += fragment_length;
    }
    Ok(fragments)
}

/// The octets of handshake data one record can carry inside a datagram whose
/// UDP payload may be `datagram_len` octets, when the epoch's protection adds
/// `protection_overhead` (0 in epoch 0, [`record::GCM_OVERHEAD`] after). A
/// path wider than a record still gets no more than the 2^14 octets RFC 5246
/// §6.2.1 allows a record's fragment.
///
/// The caller subtracts the IP and UDP headers from the path MTU first,
/// because only it knows the address family. RFC 6347 §4.1.1.1 has a sender
/// back off to a smaller size after repeated retransmissions go unanswered;
/// that means calling this again with a smaller `datagram_len`.
///
/// # Errors
///
/// [`Error::MtuTooSmall`] when no handshake header and body octet fit.
pub const fn record_payload_budget(
    datagram_len: usize,
    protection_overhead: usize,
) -> Result<usize, Error> {
    match datagram_len.checked_sub(record::HEADER_LEN + protection_overhead) {
        Some(budget) if budget > record::MAX_PLAINTEXT_LEN => Ok(record::MAX_PLAINTEXT_LEN),
        Some(budget) if budget > HEADER_LEN => Ok(budget),
        _ => Err(Error::MtuTooSmall),
    }
}

/// The running hash over a handshake's messages, for CertificateVerify, the
/// Finished messages and the extended master secret's session hash.
///
/// RFC 6347 §4.2.6: "the Finished MAC MUST be computed as if each handshake
/// message had been sent as a single fragment", so each message goes in with
/// the header of [`FragmentHeader::whole`], never with the headers of the
/// fragments it actually travelled in. The ClientHello a HelloVerifyRequest
/// answered, and the HelloVerifyRequest itself, are not added at all.
#[derive(Clone, Default)]
pub struct Transcript {
    hash: Sha256,
}

impl Transcript {
    /// A transcript of nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one message.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] for a body longer than 2^24 - 1 octets, in which
    /// case nothing is added.
    pub fn add(
        &mut self,
        msg_type: HandshakeType,
        message_seq: u16,
        body: &[u8],
    ) -> Result<(), Error> {
        let header = FragmentHeader::whole(msg_type, message_seq, message_len(body)?);
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        header.write(&mut bytes)?;
        self.hash.update(&bytes);
        self.hash.update(body);
        Ok(())
    }

    /// The hash of every message added so far. The transcript keeps running.
    #[must_use]
    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.hash.clone().finalize().into()
    }
}

impl fmt::Debug for Transcript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transcript").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAGMENT: [u8; 15] = [
        2, // server_hello
        0x00, 0x01, 0x00, // 256-octet message
        0x00, 0x05, // message_seq 5
        0x00, 0x00, 0xFD, // offset 253
        0x00, 0x00, 0x03, // three octets
        0xAA, 0xBB, 0xCC,
    ];

    #[test]
    fn a_fragment_reads_in_the_field_order_of_rfc_6347() {
        let (fragment, rest) = Fragment::parse(&FRAGMENT).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            fragment.header,
            FragmentHeader {
                msg_type: HandshakeType::SERVER_HELLO,
                length: 256,
                message_seq: 5,
                fragment_offset: 253,
                fragment_length: 3,
            }
        );
        assert_eq!(fragment.body, [0xAA, 0xBB, 0xCC]);
        let mut out = Vec::new();
        fragment.encode(&mut out).unwrap();
        assert_eq!(out, FRAGMENT);
    }

    #[test]
    fn every_truncation_of_a_fragment_is_refused() {
        for cut in 0..FRAGMENT.len() {
            assert_eq!(
                Fragment::parse(&FRAGMENT[..cut]),
                Err(Error::Truncated),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn a_fragment_must_lie_inside_its_message() {
        // offset 254 + 3 octets passes the end of a 256-octet message
        let mut past = FRAGMENT;
        past[8] = 0xFE;
        assert_eq!(Fragment::parse(&past), Err(Error::IllegalValue));
        // offset and length that would overflow if added carelessly
        let huge = [
            2, 0xFF, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        assert_eq!(Fragment::parse(&huge), Err(Error::IllegalValue));
        // nothing of a message that has a body
        let empty = [2, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(Fragment::parse(&empty), Err(Error::IllegalValue));
        // nothing of a message that has nothing: ServerHelloDone
        let done = [14, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0];
        let (fragment, _) = Fragment::parse(&done).unwrap();
        assert!(fragment.body.is_empty());
    }

    #[test]
    fn encode_refuses_what_parse_would() {
        let mut out = vec![0xEE];
        let header = FragmentHeader {
            msg_type: HandshakeType::FINISHED,
            length: 12,
            message_seq: 0,
            fragment_offset: 10,
            fragment_length: 3,
        };
        assert_eq!(
            Fragment {
                header,
                body: &[1, 2, 3]
            }
            .encode(&mut out),
            Err(Error::IllegalValue)
        );
        let header = FragmentHeader::whole(HandshakeType::FINISHED, 0, 12);
        assert_eq!(
            Fragment {
                header,
                body: &[1, 2, 3]
            }
            .encode(&mut out),
            Err(Error::Length)
        );
        assert_eq!(out, [0xEE]);
    }

    #[test]
    fn several_fragments_share_a_record() {
        let mut payload = Vec::new();
        encode_message(HandshakeType::SERVER_HELLO_DONE, 3, &[], &mut payload).unwrap();
        encode_message(HandshakeType::FINISHED, 4, &[9; 12], &mut payload).unwrap();
        let read: Vec<_> = fragments(&payload).collect::<Result<_, _>>().unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(
            read[0].header,
            FragmentHeader::whole(HandshakeType::SERVER_HELLO_DONE, 3, 0)
        );
        assert_eq!(
            read[1].header,
            FragmentHeader::whole(HandshakeType::FINISHED, 4, 12)
        );
        assert_eq!(read[1].body, [9; 12]);

        payload.push(20);
        let mut it = fragments(&payload);
        assert!(it.next().unwrap().is_ok());
        assert!(it.next().unwrap().is_ok());
        assert_eq!(it.next(), Some(Err(Error::Truncated)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn a_message_is_cut_into_contiguous_ranges_that_each_fit() {
        let body: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let pieces = fragment_message(HandshakeType::CERTIFICATE, 2, &body, 212).unwrap();
        assert_eq!(pieces.len(), 5);
        let mut joined = Vec::new();
        for (i, piece) in pieces.iter().enumerate() {
            assert!(piece.len() <= 212);
            let (fragment, rest) = Fragment::parse(piece).unwrap();
            assert!(rest.is_empty());
            assert_eq!(fragment.header.msg_type, HandshakeType::CERTIFICATE);
            assert_eq!(fragment.header.length, 1000);
            assert_eq!(fragment.header.message_seq, 2);
            assert_eq!(
                fragment.header.fragment_offset as usize,
                joined.len(),
                "fragment {i}"
            );
            joined.extend_from_slice(fragment.body);
        }
        assert_eq!(joined, body);

        // a budget that fits exactly one body octet per fragment
        assert_eq!(
            fragment_message(HandshakeType::FINISHED, 0, &[1, 2], HEADER_LEN + 1)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            fragment_message(HandshakeType::FINISHED, 0, &[1], HEADER_LEN),
            Err(Error::MtuTooSmall)
        );
        assert_eq!(
            fragment_message(HandshakeType::FINISHED, 0, &[1], 3),
            Err(Error::MtuTooSmall)
        );

        let done = fragment_message(HandshakeType::SERVER_HELLO_DONE, 4, &[], 100).unwrap();
        assert_eq!(done, vec![vec![14, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0]]);
    }

    #[test]
    fn the_budget_takes_off_the_record_header_and_the_protection() {
        assert_eq!(record_payload_budget(1200, 0), Ok(1187));
        assert_eq!(record_payload_budget(1200, record::GCM_OVERHEAD), Ok(1163));
        assert_eq!(record_payload_budget(13 + 24 + 13, 24), Ok(13));
        assert_eq!(
            record_payload_budget(13 + 24 + 12, 24),
            Err(Error::MtuTooSmall)
        );
        assert_eq!(record_payload_budget(5, 0), Err(Error::MtuTooSmall));
    }

    #[test]
    fn no_budget_or_fragment_is_more_than_a_record_carries() {
        // RFC 5246 §6.2.1: a record's fragment "MUST NOT exceed 2^14". A path
        // can carry more — a Linux loopback's 65535 leaves a UDP payload of
        // 65507 — and a record still cannot.
        assert_eq!(
            record_payload_budget(65_507, 0),
            Ok(record::MAX_PLAINTEXT_LEN)
        );
        assert_eq!(
            record_payload_budget(65_507, record::GCM_OVERHEAD),
            Ok(record::MAX_PLAINTEXT_LEN)
        );

        let body: Vec<u8> = (0..40_000u32).map(|i| (i % 253) as u8).collect();
        let pieces = fragment_message(HandshakeType::CERTIFICATE, 1, &body, 65_494).unwrap();
        assert_eq!(pieces.len(), 3);
        let mut joined = Vec::new();
        for piece in &pieces {
            let mut record = Vec::new();
            record::encode_plaintext(
                record::ContentType::HANDSHAKE,
                record::ProtocolVersion::DTLS_1_2,
                0,
                0,
                piece,
                &mut record,
            )
            .unwrap();
            joined.extend_from_slice(Fragment::parse(piece).unwrap().0.body);
        }
        assert_eq!(joined, body);
    }

    #[test]
    fn the_transcript_hashes_each_message_as_one_fragment() {
        let hello = [7u8; 300];
        let done: [u8; 0] = [];
        let mut transcript = Transcript::new();
        transcript
            .add(HandshakeType::SERVER_HELLO, 1, &hello)
            .unwrap();
        let after_hello = transcript.hash();
        transcript
            .add(HandshakeType::SERVER_HELLO_DONE, 2, &done)
            .unwrap();

        let mut expected = Sha256::new();
        // msg_type, length, message_seq, fragment_offset 0, fragment_length = length
        expected.update([2, 0, 1, 44, 0, 1, 0, 0, 0, 0, 1, 44]);
        expected.update(hello);
        assert_eq!(after_hello, <[u8; 32]>::from(expected.clone().finalize()));
        expected.update([14, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(transcript.hash(), <[u8; 32]>::from(expected.finalize()));
    }
}
