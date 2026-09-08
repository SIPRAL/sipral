// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Writing a message.
//!
//! The header's length field is kept correct after every attribute, so the
//! buffer is a valid message at all times and the two checks that read that
//! field mid-computation cannot see a stale one.
//!
//! The order the closing attributes go in is not a style: MESSAGE-INTEGRITY
//! covers everything before it, MESSAGE-INTEGRITY-SHA256 covers that too, and
//! FINGERPRINT covers both (§14.5 to §14.7). The builder refuses to put them
//! in any other order rather than producing a message that a server will
//! quietly drop.

use core::fmt;
use std::net::SocketAddr;

use super::address;
use super::attribute::AttributeType;
use super::message::{
    Class, FINGERPRINT_XOR, HEADER_LEN, MAGIC_COOKIE, Method, TransactionId, encode_type,
};
use crate::crypto::BLOCK;
use crate::crypto::crc32::Crc32;
use crate::crypto::hmac::Hmac;
use crate::crypto::sha1::Sha1;
use crate::crypto::sha256::Sha256;

/// The largest a message can be, because the length field is sixteen bits.
const MAX_BODY: usize = u16::MAX as usize;

/// How far through the closing sequence a message is.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    /// Anything may still be added.
    Open,
    /// MESSAGE-INTEGRITY is in; only MESSAGE-INTEGRITY-SHA256 and FINGERPRINT
    /// may follow.
    Integrity,
    /// MESSAGE-INTEGRITY-SHA256 is in; only FINGERPRINT may follow.
    IntegritySha256,
    /// FINGERPRINT is in and the message is finished.
    Fingerprint,
}

/// A message being written.
pub struct MessageBuilder {
    buffer: Vec<u8>,
    transaction: TransactionId,
    stage: Stage,
}

impl MessageBuilder {
    /// Start a message of this class and method.
    #[must_use]
    pub fn new(class: Class, method: Method, transaction: TransactionId) -> Self {
        let mut buffer = Vec::with_capacity(HEADER_LEN + BLOCK);
        buffer.extend_from_slice(&encode_type(class, method).to_be_bytes());
        buffer.extend_from_slice(&0_u16.to_be_bytes());
        buffer.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buffer.extend_from_slice(&transaction.as_bytes());
        Self {
            buffer,
            transaction,
            stage: Stage::Open,
        }
    }

    /// Add an attribute with a value given verbatim.
    ///
    /// # Errors
    ///
    /// A value longer than the length field can count, a message that would
    /// pass the same limit, or an attribute that has no business following the
    /// ones already written.
    pub fn add(&mut self, kind: AttributeType, value: &[u8]) -> Result<(), BuildError> {
        self.check_order(kind)?;
        self.write(kind, value)
    }

    /// Add an attribute that is a flag, USE-CANDIDATE being the only one.
    ///
    /// # Errors
    ///
    /// As `add`.
    pub fn add_flag(&mut self, kind: AttributeType) -> Result<(), BuildError> {
        self.add(kind, &[])
    }

    /// Add a thirty-two bit attribute, PRIORITY being the one that matters
    /// here.
    ///
    /// # Errors
    ///
    /// As `add`.
    pub fn add_u32(&mut self, kind: AttributeType, value: u32) -> Result<(), BuildError> {
        self.add(kind, &value.to_be_bytes())
    }

    /// Add a sixty-four bit attribute, the ICE tiebreakers being the ones that
    /// matter here.
    ///
    /// # Errors
    ///
    /// As `add`.
    pub fn add_u64(&mut self, kind: AttributeType, value: u64) -> Result<(), BuildError> {
        self.add(kind, &value.to_be_bytes())
    }

    /// Add an address in the clear, as MAPPED-ADDRESS and ALTERNATE-SERVER
    /// carry one.
    ///
    /// # Errors
    ///
    /// As `add`.
    pub fn add_address(
        &mut self,
        kind: AttributeType,
        address: SocketAddr,
    ) -> Result<(), BuildError> {
        self.check_order(kind)?;
        let mut value = Vec::new();
        address::encode(address, &mut value);
        self.write(kind, &value)
    }

    /// Add an address obfuscated with the cookie and the transaction id, as
    /// XOR-MAPPED-ADDRESS carries one.
    ///
    /// # Errors
    ///
    /// As `add`.
    pub fn add_xor_address(
        &mut self,
        kind: AttributeType,
        address: SocketAddr,
    ) -> Result<(), BuildError> {
        self.check_order(kind)?;
        let mut value = Vec::new();
        address::encode_xor(address, self.transaction, &mut value);
        self.write(kind, &value)
    }

    /// Add an ERROR-CODE with its reason phrase (§14.8).
    ///
    /// # Errors
    ///
    /// A code outside 300 to 699, or as `add`.
    pub fn add_error_code(&mut self, code: u16, reason: &[u8]) -> Result<(), BuildError> {
        let (class, number) = (code / 100, code % 100);
        if !(3..=6).contains(&class) {
            return Err(BuildError::ErrorCode(code));
        }
        self.check_order(AttributeType::ERROR_CODE)?;
        let mut value = Vec::with_capacity(4 + reason.len());
        value.extend_from_slice(&[0, 0]);
        value.push(u8::try_from(class).unwrap_or_default());
        value.push(u8::try_from(number).unwrap_or_default());
        value.extend_from_slice(reason);
        self.write(AttributeType::ERROR_CODE, &value)
    }

    /// Add the UNKNOWN-ATTRIBUTES list a 420 owes the sender (§14.13).
    ///
    /// # Errors
    ///
    /// As `add`.
    pub fn add_unknown_attributes(&mut self, types: &[AttributeType]) -> Result<(), BuildError> {
        self.check_order(AttributeType::UNKNOWN_ATTRIBUTES)?;
        let mut value = Vec::with_capacity(types.len() * 2);
        for kind in types {
            value.extend_from_slice(&kind.code().to_be_bytes());
        }
        self.write(AttributeType::UNKNOWN_ATTRIBUTES, &value)
    }

    /// Close the message with a MESSAGE-INTEGRITY over everything so far
    /// (§14.5).
    ///
    /// # Errors
    ///
    /// A message that already has one, or that has moved past the point where
    /// one can be added.
    pub fn add_message_integrity(&mut self, key: &[u8]) -> Result<(), BuildError> {
        self.check_order(AttributeType::MESSAGE_INTEGRITY)?;
        let mut mac = Hmac::<Sha1>::new(key);
        self.close_with(AttributeType::MESSAGE_INTEGRITY, 20, |part| {
            mac.update(part);
        })?;
        let digest = mac.finish();
        self.fill_in(&digest);
        self.stage = Stage::Integrity;
        Ok(())
    }

    /// Close the message with a MESSAGE-INTEGRITY-SHA256 over everything so
    /// far (§14.6).
    ///
    /// The full thirty-two bytes: truncation is only allowed where a usage
    /// says so, and no usage this stack implements says so.
    ///
    /// # Errors
    ///
    /// As `add_message_integrity`.
    pub fn add_message_integrity_sha256(&mut self, key: &[u8]) -> Result<(), BuildError> {
        self.check_order(AttributeType::MESSAGE_INTEGRITY_SHA256)?;
        let mut mac = Hmac::<Sha256>::new(key);
        self.close_with(AttributeType::MESSAGE_INTEGRITY_SHA256, 32, |part| {
            mac.update(part);
        })?;
        let digest = mac.finish();
        self.fill_in(&digest);
        self.stage = Stage::IntegritySha256;
        Ok(())
    }

    /// Close the message with a FINGERPRINT (§14.7).
    ///
    /// # Errors
    ///
    /// A message that already has one.
    pub fn add_fingerprint(&mut self) -> Result<(), BuildError> {
        self.check_order(AttributeType::FINGERPRINT)?;
        let mut crc = Crc32::new();
        self.close_with(AttributeType::FINGERPRINT, 4, |part| crc.update(part))?;
        let value = crc.finish() ^ FINGERPRINT_XOR;
        self.fill_in(&value.to_be_bytes());
        self.stage = Stage::Fingerprint;
        Ok(())
    }

    /// The message as it stands, which is a valid one after every call above.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// The finished message.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// Whether this attribute may still be added.
    fn check_order(&self, kind: AttributeType) -> Result<(), BuildError> {
        let allowed = match self.stage {
            Stage::Open => true,
            Stage::Integrity => matches!(
                kind,
                AttributeType::MESSAGE_INTEGRITY_SHA256 | AttributeType::FINGERPRINT
            ),
            Stage::IntegritySha256 => kind == AttributeType::FINGERPRINT,
            Stage::Fingerprint => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(BuildError::OutOfOrder(kind))
        }
    }

    fn write(&mut self, kind: AttributeType, value: &[u8]) -> Result<(), BuildError> {
        if value.len() > MAX_BODY {
            return Err(BuildError::AttributeTooLong {
                kind,
                length: value.len(),
            });
        }
        let padding = value.len().div_ceil(4) * 4 - value.len();
        let body = self.buffer.len() - HEADER_LEN + 4 + value.len() + padding;
        let Ok(length) = u16::try_from(body) else {
            return Err(BuildError::MessageTooLong(body));
        };

        self.buffer.extend_from_slice(&kind.code().to_be_bytes());
        let value_length = u16::try_from(value.len()).unwrap_or_default();
        self.buffer.extend_from_slice(&value_length.to_be_bytes());
        self.buffer.extend_from_slice(value);
        self.buffer.resize(self.buffer.len() + padding, 0);
        self.set_length(length);
        Ok(())
    }

    /// Write the header and a value of zeros for one of the closing
    /// attributes, then hand the bytes it is computed over to `feed`.
    ///
    /// The length field is set to include the attribute before anything is
    /// hashed, which is the whole trick: what the check covers is the message
    /// as it will be once the attribute is filled in, not the message as it is
    /// while it is being computed.
    fn close_with(
        &mut self,
        kind: AttributeType,
        value_len: usize,
        mut feed: impl FnMut(&[u8]),
    ) -> Result<(), BuildError> {
        let body = self.buffer.len() - HEADER_LEN + 4 + value_len;
        let Ok(length) = u16::try_from(body) else {
            return Err(BuildError::MessageTooLong(body));
        };
        self.set_length(length);
        feed(&self.buffer);

        let value_length = u16::try_from(value_len).unwrap_or_default();
        self.buffer.extend_from_slice(&kind.code().to_be_bytes());
        self.buffer.extend_from_slice(&value_length.to_be_bytes());
        self.buffer.resize(self.buffer.len() + value_len, 0);
        Ok(())
    }

    /// Put the computed check into the space `close_with` left for it.
    fn fill_in(&mut self, digest: &[u8]) {
        let start = self.buffer.len() - digest.len();
        if let Some(room) = self.buffer.get_mut(start..) {
            room.copy_from_slice(digest);
        }
    }

    fn set_length(&mut self, length: u16) {
        if let Some(field) = self.buffer.get_mut(2..4) {
            field.copy_from_slice(&length.to_be_bytes());
        }
    }
}

impl fmt::Debug for MessageBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageBuilder")
            .field("length", &self.buffer.len())
            .field("transaction", &self.transaction)
            .finish_non_exhaustive()
    }
}

/// Why a message could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// An attribute after one that closes the message (§9, §14.7).
    OutOfOrder(AttributeType),
    /// A value longer than the sixteen-bit length field can count.
    AttributeTooLong {
        /// Which attribute.
        kind: AttributeType,
        /// How long its value would have been.
        length: usize,
    },
    /// A message longer than the sixteen-bit length field can count.
    MessageTooLong(usize),
    /// An error code outside the range the attribute can hold (§14.8).
    ErrorCode(u16),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OutOfOrder(kind) => write!(f, "{kind} cannot follow what is already written"),
            Self::AttributeTooLong { kind, length } => {
                write!(f, "{kind} of {length} octets does not fit the length field")
            }
            Self::MessageTooLong(length) => {
                write!(
                    f,
                    "message of {length} octets does not fit the length field"
                )
            }
            Self::ErrorCode(code) => write!(f, "error code {code} is not between 300 and 699"),
        }
    }
}

impl core::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{BuildError, MessageBuilder};
    use crate::crypto::crc32::Crc32;
    use crate::crypto::hmac::Hmac;
    use crate::crypto::sha1::Sha1;
    use crate::stun::attribute::AttributeType;
    use crate::stun::message::{
        Class, FINGERPRINT_XOR, HEADER_LEN, Integrity, Message, Method, TransactionId,
    };

    fn transaction() -> TransactionId {
        TransactionId::new([
            0x21, 0x0f, 0x77, 0x1e, 0x63, 0xa9, 0x0c, 0x5b, 0x44, 0x8d, 0x2f, 0x93,
        ])
    }

    fn request() -> MessageBuilder {
        MessageBuilder::new(Class::Request, Method::BINDING, transaction())
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_empty_request_is_a_header_and_nothing_else() {
        let bytes = request().finish();
        assert_eq!(bytes.len(), HEADER_LEN);

        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.class(), Class::Request);
        assert_eq!(message.method(), Method::BINDING);
        assert_eq!(message.transaction_id(), transaction());
    }

    #[test]
    fn a_value_that_is_not_whole_words_is_padded_and_the_padding_is_zero() {
        let mut builder = request();
        builder.add(AttributeType::SOFTWARE, b"si").unwrap();
        let bytes = builder.finish();

        assert_eq!(bytes.len(), HEADER_LEN + 8);
        assert_eq!(&bytes[HEADER_LEN + 6..], &[0, 0]);
        assert_eq!(
            Message::parse(&bytes).unwrap().software().unwrap(),
            b"si".as_slice()
        );
    }

    #[test]
    fn every_value_length_up_to_a_word_pads_to_the_next_boundary() {
        for length in 0..=8_usize {
            let mut builder = request();
            builder
                .add(AttributeType::SOFTWARE, &vec![b'x'; length])
                .unwrap();
            let bytes = builder.finish();
            assert_eq!(bytes.len() % 4, 0, "{length}");
            let message = Message::parse(&bytes).unwrap();
            assert_eq!(message.software().unwrap().len(), length);
        }
    }

    #[test]
    fn an_address_round_trips_through_the_builder_and_the_parser() {
        for text in ["198.51.100.7:53412", "[2001:db8:aa:bb::1]:5060"] {
            let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, transaction());
            builder
                .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(text))
                .unwrap();
            builder
                .add_address(AttributeType::MAPPED_ADDRESS, address(text))
                .unwrap();
            let bytes = builder.finish();

            let message = Message::parse(&bytes).unwrap();
            assert_eq!(message.xor_mapped_address(), Some(address(text)));
            assert_eq!(message.mapped_address(), Some(address(text)));
        }
    }

    #[test]
    fn a_message_integrity_written_here_verifies_where_it_is_read() {
        let mut builder = request();
        builder.add(AttributeType::USERNAME, b"user").unwrap();
        builder.add_message_integrity(b"secret").unwrap();
        let bytes = builder.finish();

        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.verify_integrity(b"secret"), Integrity::Valid);
        assert_eq!(message.verify_integrity(b"wrong"), Integrity::Invalid);
    }

    #[test]
    fn a_fingerprint_after_an_integrity_leaves_the_integrity_valid() {
        let mut builder = request();
        builder.add(AttributeType::USERNAME, b"user").unwrap();
        builder.add_message_integrity(b"secret").unwrap();
        builder.add_message_integrity_sha256(b"secret").unwrap();
        builder.add_fingerprint().unwrap();
        let bytes = builder.finish();

        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.verify_fingerprint(), Integrity::Valid);
        assert_eq!(message.verify_integrity(b"secret"), Integrity::Valid);
        assert_eq!(message.verify_integrity_sha256(b"secret"), Integrity::Valid);
    }

    #[test]
    fn the_length_field_the_integrity_covers_is_not_the_final_one() {
        // an integrity over a message that gains a fingerprint afterwards must
        // still verify, which only works if the length hashed was the one that
        // ended at the integrity attribute
        let mut short = request();
        short.add_message_integrity(b"secret").unwrap();
        let without = short.finish();

        let mut long = request();
        long.add_message_integrity(b"secret").unwrap();
        long.add_fingerprint().unwrap();
        let with = long.finish();

        assert_eq!(&without[HEADER_LEN..], &with[HEADER_LEN..without.len()]);
        assert_ne!(without[3], with[3]);
        assert_eq!(
            Message::parse(&with).unwrap().verify_integrity(b"secret"),
            Integrity::Valid
        );
    }

    #[test]
    fn the_integrity_is_an_hmac_over_exactly_the_bytes_the_rfc_names() {
        let mut builder = request();
        builder.add(AttributeType::USERNAME, b"user").unwrap();
        let before = builder.as_bytes().to_vec();
        builder.add_message_integrity(b"secret").unwrap();
        builder.add_fingerprint().unwrap();
        let bytes = builder.finish();

        // assembled here rather than taken from the builder: the header with
        // the length field pointing past the integrity attribute, followed by
        // every attribute that precedes it and nothing else
        let mut input = before.clone();
        let adjusted = u16::try_from(before.len() - HEADER_LEN + 24).unwrap();
        input[2..4].copy_from_slice(&adjusted.to_be_bytes());

        let mut mac = Hmac::<Sha1>::new(b"secret");
        mac.update(&input);
        let expected = mac.finish();

        assert_eq!(&bytes[before.len()..before.len() + 2], &[0x00, 0x08]);
        assert_eq!(&bytes[before.len() + 2..before.len() + 4], &[0x00, 0x14]);
        assert_eq!(&bytes[before.len() + 4..before.len() + 24], &expected);
    }

    #[test]
    fn the_fingerprint_covers_the_integrity_that_precedes_it() {
        let mut builder = request();
        builder.add_message_integrity(b"secret").unwrap();
        let before = builder.as_bytes().to_vec();
        builder.add_fingerprint().unwrap();
        let bytes = builder.finish();

        let mut input = before.clone();
        let adjusted = u16::try_from(before.len() - HEADER_LEN + 8).unwrap();
        input[2..4].copy_from_slice(&adjusted.to_be_bytes());

        let mut crc = Crc32::new();
        crc.update(&input);
        let expected = crc.finish() ^ FINGERPRINT_XOR;

        let value = &bytes[before.len() + 4..];
        assert_eq!(value, expected.to_be_bytes());
        assert_eq!(usize::from(bytes[3]), before.len() - HEADER_LEN + 8);
    }

    #[test]
    fn nothing_may_follow_the_fingerprint() {
        let mut builder = request();
        builder.add_fingerprint().unwrap();
        assert_eq!(
            builder.add(AttributeType::SOFTWARE, b"late"),
            Err(BuildError::OutOfOrder(AttributeType::SOFTWARE))
        );
        assert_eq!(
            builder.add_fingerprint(),
            Err(BuildError::OutOfOrder(AttributeType::FINGERPRINT))
        );
    }

    #[test]
    fn only_the_two_closing_attributes_may_follow_a_message_integrity() {
        let mut builder = request();
        builder.add_message_integrity(b"secret").unwrap();
        assert_eq!(
            builder.add(AttributeType::USERNAME, b"late"),
            Err(BuildError::OutOfOrder(AttributeType::USERNAME))
        );
        assert!(builder.add_message_integrity_sha256(b"secret").is_ok());
        assert!(builder.add_fingerprint().is_ok());
    }

    #[test]
    fn a_sha256_integrity_cannot_be_followed_by_a_sha1_one() {
        let mut builder = request();
        builder.add_message_integrity_sha256(b"secret").unwrap();
        assert_eq!(
            builder.add_message_integrity(b"secret"),
            Err(BuildError::OutOfOrder(AttributeType::MESSAGE_INTEGRITY))
        );
    }

    #[test]
    fn an_error_code_outside_the_range_is_refused() {
        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, transaction());
        assert_eq!(
            builder.add_error_code(200, b"OK"),
            Err(BuildError::ErrorCode(200))
        );
        assert_eq!(
            builder.add_error_code(700, b"nonsense"),
            Err(BuildError::ErrorCode(700))
        );
        assert!(builder.add_error_code(401, b"Unauthenticated").is_ok());

        let bytes = builder.finish();
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.error_code().unwrap().code(), 401);
    }

    #[test]
    fn an_unknown_attributes_list_round_trips() {
        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, transaction());
        let listed = [AttributeType::new(0x0002), AttributeType::new(0x4321)];
        builder.add_error_code(420, b"Unknown Attribute").unwrap();
        builder.add_unknown_attributes(&listed).unwrap();
        let bytes = builder.finish();

        let message = Message::parse(&bytes).unwrap();
        let read: Vec<AttributeType> = message.unknown_attributes().collect();
        assert_eq!(read, listed);
    }

    #[test]
    fn an_attribute_longer_than_the_length_field_is_refused() {
        let mut builder = request();
        let huge = vec![0_u8; 65_536];
        assert_eq!(
            builder.add(AttributeType::SOFTWARE, &huge),
            Err(BuildError::AttributeTooLong {
                kind: AttributeType::SOFTWARE,
                length: 65_536
            })
        );
    }

    #[test]
    fn a_message_that_would_overflow_the_length_field_is_refused() {
        let mut builder = request();
        let large = vec![0_u8; 60_000];
        builder.add(AttributeType::SOFTWARE, &large).unwrap();
        assert!(matches!(
            builder.add(AttributeType::SOFTWARE, &large),
            Err(BuildError::MessageTooLong(_))
        ));
    }

    #[test]
    fn the_ice_attributes_round_trip() {
        let mut builder = request();
        builder
            .add_u32(AttributeType::PRIORITY, 0x7e00_00ff)
            .unwrap();
        builder.add_flag(AttributeType::USE_CANDIDATE).unwrap();
        builder
            .add_u64(AttributeType::ICE_CONTROLLING, 0x0123_4567_89ab_cdef)
            .unwrap();
        let bytes = builder.finish();

        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.priority(), Some(0x7e00_00ff));
        assert!(message.use_candidate());
        assert_eq!(message.ice_controlling(), Some(0x0123_4567_89ab_cdef));
        assert_eq!(message.ice_controlled(), None);
    }
}
