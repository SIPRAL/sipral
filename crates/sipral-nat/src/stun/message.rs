// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The message on the wire: the header, the type field with its interleaved
//! class and method bits, and the attributes after it (RFC 8489 §5 and §14).
//!
//! Reading borrows. A parsed message is a view over the datagram the caller
//! already owns, which is what lets the integrity check run over the original
//! bytes instead of over a reconstruction of them — and a reconstruction is
//! exactly what an attacker would want it to run over.
//!
//! Parsing is strict. Every length is checked against what is actually there,
//! every known attribute is checked against the shape its section gives it,
//! and anything that does not add up comes back as an error rather than as a
//! message with a plausible guess in it.

use core::fmt;

use super::address;
use super::attribute::{AttributeType, ErrorCode, UnknownRequired};
use crate::crypto::constant_time_eq;
use crate::crypto::crc32::Crc32;
use crate::crypto::hmac::Hmac;
use crate::crypto::sha1::Sha1;
use crate::crypto::sha256::Sha256;
use std::net::SocketAddr;

/// Octets of header before the first attribute (§5).
pub const HEADER_LEN: usize = 20;

/// The value that says a message was written after RFC 3489 (§5).
pub const MAGIC_COOKIE: u32 = 0x2112_a442;

/// What FINGERPRINT exclusive-ORs its CRC with, so that a checksum belonging
/// to some other protocol cannot pass for one of ours (§14.7).
pub const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// Octets an HMAC-SHA1 takes.
const INTEGRITY_LEN: usize = 20;

/// The shortest MESSAGE-INTEGRITY-SHA256 a usage may truncate to, and the full
/// length (§14.6).
const INTEGRITY_SHA256_MIN: usize = 16;
const INTEGRITY_SHA256_MAX: usize = 32;

/// What a message is for: the two bits that say request, response or
/// indication (§5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Asks for a response.
    Request,
    /// Asks for nothing; nobody answers it and nobody retransmits it.
    Indication,
    /// The answer, and the answer worked.
    Success,
    /// The answer, and it carries an ERROR-CODE.
    Error,
}

impl Class {
    const fn bits(self) -> u16 {
        match self {
            Self::Request => 0b00,
            Self::Indication => 0b01,
            Self::Success => 0b10,
            Self::Error => 0b11,
        }
    }

    const fn from_bits(bits: u16) -> Self {
        match bits & 0b11 {
            0b00 => Self::Request,
            0b01 => Self::Indication,
            0b10 => Self::Success,
            _ => Self::Error,
        }
    }

    /// Whether this class answers a request.
    #[must_use]
    pub const fn is_response(self) -> bool {
        matches!(self, Self::Success | Self::Error)
    }
}

/// What a message asks for (§18.2).
///
/// Twelve bits, and this document defines one of them. TURN and any other
/// usage adds its own without this file changing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Method(u16);

impl Method {
    /// The one method RFC 8489 defines: tell me where I appear from.
    pub const BINDING: Self = Self(0x001);

    /// The method with this number, if it fits the twelve bits the type field
    /// has for it.
    #[must_use]
    pub const fn new(code: u16) -> Option<Self> {
        if code > 0x0fff {
            return None;
        }
        Some(Self(code))
    }

    /// The number.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BINDING => f.write_str("Binding"),
            Self(code) => write!(f, "0x{code:03x}"),
        }
    }
}

/// The sixteen bits of the type field, which interleaves the method with the
/// class instead of putting them side by side.
///
/// RFC 8489 calls this "unfortunate" and blames RFC 3489 for assigning the
/// values before anyone thought about encoding the class in them (§5).
pub(crate) const fn encode_type(class: Class, method: Method) -> u16 {
    let method = method.0;
    let class = class.bits();
    ((method & 0x0f80) << 2)
        | ((method & 0x0070) << 1)
        | (method & 0x000f)
        | ((class & 0b10) << 7)
        | ((class & 0b01) << 4)
}

const fn decode_type(bits: u16) -> (Class, Method) {
    let method = ((bits & 0x3e00) >> 2) | ((bits & 0x00e0) >> 1) | (bits & 0x000f);
    let class = ((bits & 0x0100) >> 7) | ((bits & 0x0010) >> 4);
    (Class::from_bits(class), Method(method))
}

/// The ninety-six bits that tie a response to the request that asked for it
/// (§5).
///
/// It has to be cryptographically random, and nothing here draws it: the
/// caller supplies the bytes, which is what keeps this crate free of a random
/// number generator and every state machine in it reproducible in a test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    /// The identifier made of these twelve bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// The twelve bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 12] {
        self.0
    }
}

/// One attribute, as a view over the message it arrived in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribute<'a> {
    kind: AttributeType,
    value: &'a [u8],
    offset: usize,
}

impl<'a> Attribute<'a> {
    /// What kind of attribute it is.
    #[must_use]
    pub const fn kind(&self) -> AttributeType {
        self.kind
    }

    /// The value, without the padding that follows it.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// The attributes of a message, in the order they appear.
///
/// All of them, including the ones a receiver has to ignore: the integrity
/// check runs over the message as it stands, so the raw walk has to see
/// everything. `Message::find` is the one that applies the ignore rule.
#[derive(Clone, Debug)]
pub struct Attributes<'a> {
    message: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Attribute<'a>;

    fn next(&mut self) -> Option<Attribute<'a>> {
        let header = self.message.get(self.offset..self.offset + 4)?;
        let kind = AttributeType::new(u16::from_be_bytes([*header.first()?, *header.get(1)?]));
        let length = usize::from(u16::from_be_bytes([*header.get(2)?, *header.get(3)?]));
        let start = self.offset + 4;
        let value = self.message.get(start..start + length)?;
        let attribute = Attribute {
            kind,
            value,
            offset: self.offset,
        };
        self.offset = start + padded(length);
        Some(attribute)
    }
}

/// A value of this many bytes occupies this many, because attributes start on
/// a four-byte boundary (§14).
const fn padded(length: usize) -> usize {
    length.div_ceil(4) * 4
}

/// Whether the attribute of this type at this offset is one a receiver may act
/// on, given where the message was closed.
const fn visible(gate: Option<Gate>, offset: usize, kind: AttributeType) -> bool {
    match gate {
        None => true,
        Some(gate) if offset < gate.end => true,
        Some(gate) => {
            matches!(kind, AttributeType::FINGERPRINT)
                || (gate.integrity && matches!(kind, AttributeType::MESSAGE_INTEGRITY_SHA256))
        }
    }
}

/// What a message-integrity or fingerprint check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integrity {
    /// The attribute is not in the message.
    Absent,
    /// It is there and it matches.
    Valid,
    /// It is there and it does not match. On an unreliable transport this
    /// means discard the datagram, not fail the transaction (§9.2.5).
    Invalid,
}

/// Where the attributes a receiver must ignore begin.
///
/// "Agents MUST ignore all attributes that follow MESSAGE-INTEGRITY, with the
/// exception of the MESSAGE-INTEGRITY-SHA256 and FINGERPRINT attributes"
/// (§9). Without that rule anyone on the path could append whatever they liked
/// to an authenticated message, since the integrity check deliberately stops
/// at its own attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Gate {
    /// The offset just past the attribute that closes the message.
    end: usize,
    /// Whether that attribute was MESSAGE-INTEGRITY rather than
    /// MESSAGE-INTEGRITY-SHA256, which decides what is still allowed after it.
    integrity: bool,
}

/// A parsed message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    class: Class,
    method: Method,
    transaction: TransactionId,
    raw: &'a [u8],
    gate: Option<Gate>,
}

impl<'a> Message<'a> {
    /// Read a datagram that holds one message and nothing else.
    ///
    /// # Errors
    ///
    /// Anything that does not obey §5: the leading bits, the cookie, a length
    /// that disagrees with what arrived, an attribute that runs off the end,
    /// or a known attribute whose value is the wrong shape.
    pub fn parse(datagram: &'a [u8]) -> Result<Self, ParseError> {
        let message = Self::parse_prefix(datagram)?;
        if message.raw.len() != datagram.len() {
            return Err(ParseError::Length {
                declared: message.raw.len(),
                got: datagram.len(),
            });
        }
        Ok(message)
    }

    /// Read the message at the front of a buffer and leave the rest alone.
    ///
    /// This is for a stream, where the length field is the only frame there
    /// is; on a datagram use `parse`, which refuses trailing bytes.
    ///
    /// # Errors
    ///
    /// As `parse`, minus the complaint about trailing bytes.
    pub fn parse_prefix(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let header = bytes
            .get(..HEADER_LEN)
            .ok_or(ParseError::TooShort { got: bytes.len() })?;

        let type_bits =
            u16::from_be_bytes([*header.first().unwrap_or(&0), *header.get(1).unwrap_or(&0)]);
        if type_bits & 0xc000 != 0 {
            return Err(ParseError::NotStun);
        }

        let cookie = u32::from_be_bytes([
            *header.get(4).unwrap_or(&0),
            *header.get(5).unwrap_or(&0),
            *header.get(6).unwrap_or(&0),
            *header.get(7).unwrap_or(&0),
        ]);
        if cookie != MAGIC_COOKIE {
            return Err(ParseError::Cookie(cookie));
        }

        let length =
            u16::from_be_bytes([*header.get(2).unwrap_or(&0), *header.get(3).unwrap_or(&0)]);
        if length % 4 != 0 {
            return Err(ParseError::Unaligned(length));
        }
        let raw = bytes
            .get(..HEADER_LEN + usize::from(length))
            .ok_or(ParseError::Length {
                declared: HEADER_LEN + usize::from(length),
                got: bytes.len(),
            })?;

        let mut transaction = [0_u8; 12];
        if let Some(bytes) = header.get(8..HEADER_LEN) {
            transaction.copy_from_slice(bytes);
        }

        let (class, method) = decode_type(type_bits);
        let mut message = Self {
            class,
            method,
            transaction: TransactionId::new(transaction),
            raw,
            gate: None,
        };
        message.gate = message.walk()?;
        message.check_known_attributes()?;
        Ok(message)
    }

    /// Walk every attribute once, checking that each one fits, and find where
    /// the ignore rule of §9 starts applying.
    fn walk(&self) -> Result<Option<Gate>, ParseError> {
        let mut offset = HEADER_LEN;
        let mut integrity = None;
        let mut integrity_sha256 = None;

        while offset < self.raw.len() {
            let available = self.raw.len() - offset;
            let Some(header) = self.raw.get(offset..offset + 4) else {
                return Err(ParseError::TruncatedAttribute {
                    at: offset,
                    want: 4,
                    available,
                });
            };
            let length = usize::from(u16::from_be_bytes([
                *header.get(2).unwrap_or(&0),
                *header.get(3).unwrap_or(&0),
            ]));
            let want = 4 + padded(length);
            if want > available {
                return Err(ParseError::TruncatedAttribute {
                    at: offset,
                    want,
                    available,
                });
            }

            let kind = AttributeType::new(u16::from_be_bytes([
                *header.first().unwrap_or(&0),
                *header.get(1).unwrap_or(&0),
            ]));
            if kind == AttributeType::MESSAGE_INTEGRITY && integrity.is_none() {
                integrity = Some(offset + want);
            }
            if kind == AttributeType::MESSAGE_INTEGRITY_SHA256 && integrity_sha256.is_none() {
                integrity_sha256 = Some(offset + want);
            }

            offset += want;
        }

        Ok(match (integrity, integrity_sha256) {
            (Some(end), _) => Some(Gate {
                end,
                integrity: true,
            }),
            (None, Some(end)) => Some(Gate {
                end,
                integrity: false,
            }),
            (None, None) => None,
        })
    }

    /// Check the attributes this implementation claims to understand against
    /// the shape their sections give them.
    ///
    /// Only the ones a receiver is allowed to look at: junk appended after
    /// MESSAGE-INTEGRITY is junk the specification says to ignore, and
    /// refusing the whole message over it would hand an on-path attacker a way
    /// to break an authenticated exchange.
    fn check_known_attributes(&self) -> Result<(), ParseError> {
        for attribute in self.attributes() {
            if !self.is_visible(attribute.offset, attribute.kind) {
                continue;
            }
            let length = attribute.value.len();
            let ok = match attribute.kind {
                AttributeType::MAPPED_ADDRESS
                | AttributeType::XOR_MAPPED_ADDRESS
                | AttributeType::ALTERNATE_SERVER
                | AttributeType::XOR_PEER_ADDRESS
                | AttributeType::XOR_RELAYED_ADDRESS => {
                    if !address::is_valid(attribute.value) {
                        return Err(ParseError::Address {
                            kind: attribute.kind,
                        });
                    }
                    true
                }
                AttributeType::MESSAGE_INTEGRITY => length == INTEGRITY_LEN,
                AttributeType::MESSAGE_INTEGRITY_SHA256 => {
                    (INTEGRITY_SHA256_MIN..=INTEGRITY_SHA256_MAX).contains(&length)
                        && length % 4 == 0
                }
                AttributeType::FINGERPRINT
                | AttributeType::PRIORITY
                | AttributeType::CHANNEL_NUMBER
                | AttributeType::LIFETIME
                | AttributeType::REQUESTED_ADDRESS_FAMILY
                | AttributeType::REQUESTED_TRANSPORT
                | AttributeType::ADDITIONAL_ADDRESS_FAMILY => length == 4,
                AttributeType::USE_CANDIDATE | AttributeType::DONT_FRAGMENT => length == 0,
                AttributeType::EVEN_PORT => length == 1,
                AttributeType::RESERVATION_TOKEN
                | AttributeType::ICMP
                | AttributeType::ICE_CONTROLLED
                | AttributeType::ICE_CONTROLLING => length == 8,
                AttributeType::ADDRESS_ERROR_CODE | AttributeType::PASSWORD_ALGORITHM => {
                    length >= 4
                }
                AttributeType::UNKNOWN_ATTRIBUTES => length % 2 == 0,
                AttributeType::ERROR_CODE => {
                    if length < 4 {
                        false
                    } else {
                        let class = attribute.value.get(2).copied().unwrap_or_default();
                        let number = attribute.value.get(3).copied().unwrap_or_default();
                        if !(3..=6).contains(&class) || number > 99 {
                            return Err(ParseError::ErrorCode { class, number });
                        }
                        true
                    }
                }
                _ => true,
            };
            if !ok {
                return Err(ParseError::AttributeLength {
                    kind: attribute.kind,
                    length,
                });
            }
        }
        Ok(())
    }

    /// What the message asks for or answers.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Request, indication, success or error.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// The transaction this message belongs to.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction
    }

    /// The message as it was on the wire, header included and trailing bytes
    /// of the buffer excluded.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// Every attribute, in order, including the ones §9 says to ignore.
    #[must_use]
    pub const fn attributes(&self) -> Attributes<'a> {
        Attributes {
            message: self.raw,
            offset: HEADER_LEN,
        }
    }

    /// The first attribute of this type a receiver is allowed to act on.
    ///
    /// "Only the first occurrence needs to be processed by a receiver" (§14),
    /// and anything past MESSAGE-INTEGRITY is not there as far as a receiver
    /// is concerned (§9).
    #[must_use]
    pub fn find(&self, kind: AttributeType) -> Option<&'a [u8]> {
        self.attributes()
            .find(|attribute| attribute.kind == kind && self.is_visible(attribute.offset, kind))
            .map(|attribute| attribute.value)
    }

    /// Every occurrence of this type a receiver is allowed to act on.
    ///
    /// One occurrence is the rule (§14). The exception this exists for is the
    /// dual TURN allocation, whose success response carries one
    /// XOR-RELAYED-ADDRESS per address family (RFC 8656 §7.2).
    pub fn find_all(&self, kind: AttributeType) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let gate = self.gate;
        self.attributes()
            .filter(move |attribute| {
                attribute.kind == kind && visible(gate, attribute.offset, kind)
            })
            .map(|attribute| attribute.value)
    }

    fn is_visible(&self, offset: usize, kind: AttributeType) -> bool {
        visible(self.gate, offset, kind)
    }

    /// The comprehension-required attributes this implementation does not
    /// understand.
    ///
    /// # Errors
    ///
    /// The list itself, which is what an UNKNOWN-ATTRIBUTES attribute in a 420
    /// response is made of.
    pub fn check_comprehension(&self) -> Result<(), UnknownRequired> {
        let mut unknown = UnknownRequired::empty();
        for attribute in self.attributes() {
            let kind = attribute.kind;
            if kind.is_comprehension_required()
                && !kind.is_known()
                && self.is_visible(attribute.offset, kind)
            {
                unknown.push(kind);
            }
        }
        if unknown.is_empty() {
            return Ok(());
        }
        Err(unknown)
    }

    /// The reflexive address in XOR-MAPPED-ADDRESS.
    #[must_use]
    pub fn xor_mapped_address(&self) -> Option<SocketAddr> {
        address::decode_xor(
            self.find(AttributeType::XOR_MAPPED_ADDRESS)?,
            self.transaction,
        )
    }

    /// The reflexive address in MAPPED-ADDRESS, which only a server talking to
    /// an RFC 3489 client has any business sending (§14.1).
    #[must_use]
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        address::decode(self.find(AttributeType::MAPPED_ADDRESS)?)
    }

    /// Where a 300 (Try Alternate) points instead (§14.15).
    #[must_use]
    pub fn alternate_server(&self) -> Option<SocketAddr> {
        address::decode(self.find(AttributeType::ALTERNATE_SERVER)?)
    }

    /// The USERNAME, as it was on the wire.
    ///
    /// Bytes rather than text throughout: a realm goes into an MD5 as the
    /// octets that arrived, and decoding it to a string first would only add a
    /// way to get it wrong.
    #[must_use]
    pub fn username(&self) -> Option<&'a [u8]> {
        self.find(AttributeType::USERNAME)
    }

    /// The REALM.
    #[must_use]
    pub fn realm(&self) -> Option<&'a [u8]> {
        self.find(AttributeType::REALM)
    }

    /// The NONCE.
    #[must_use]
    pub fn nonce(&self) -> Option<&'a [u8]> {
        self.find(AttributeType::NONCE)
    }

    /// The SOFTWARE string, which is diagnostic and nothing else.
    #[must_use]
    pub fn software(&self) -> Option<&'a [u8]> {
        self.find(AttributeType::SOFTWARE)
    }

    /// The PASSWORD-ALGORITHMS attribute as it stands, which is what a retry
    /// has to echo back unchanged (§9.2.5).
    #[must_use]
    pub fn password_algorithms(&self) -> Option<&'a [u8]> {
        self.find(AttributeType::PASSWORD_ALGORITHMS)
    }

    /// The algorithm numbers PASSWORD-ALGORITHMS offers, in the order offered.
    #[must_use]
    pub fn offered_password_algorithms(&self) -> OfferedAlgorithms<'a> {
        OfferedAlgorithms {
            rest: self.password_algorithms().unwrap_or_default(),
        }
    }

    /// The error code and reason phrase of an error response.
    #[must_use]
    pub fn error_code(&self) -> Option<ErrorCode<'a>> {
        let value = self.find(AttributeType::ERROR_CODE)?;
        let class = u16::from(*value.get(2)?);
        let number = u16::from(*value.get(3)?);
        Some(ErrorCode::new(class * 100 + number, value.get(4..)?))
    }

    /// The types listed in an UNKNOWN-ATTRIBUTES attribute (§14.13).
    pub fn unknown_attributes(&self) -> impl Iterator<Item = AttributeType> + use<'a> {
        self.find(AttributeType::UNKNOWN_ATTRIBUTES)
            .unwrap_or_default()
            .chunks_exact(2)
            .map(|pair| {
                AttributeType::new(u16::from_be_bytes([
                    *pair.first().unwrap_or(&0),
                    *pair.get(1).unwrap_or(&0),
                ]))
            })
    }

    /// The PRIORITY a connectivity check carries (RFC 8445 §16.1).
    #[must_use]
    pub fn priority(&self) -> Option<u32> {
        Some(u32::from_be_bytes(
            self.find(AttributeType::PRIORITY)?.try_into().ok()?,
        ))
    }

    /// Whether the check nominates the pair it is running on.
    #[must_use]
    pub fn use_candidate(&self) -> bool {
        self.find(AttributeType::USE_CANDIDATE).is_some()
    }

    /// The tiebreaker of a peer that says it is controlled.
    #[must_use]
    pub fn ice_controlled(&self) -> Option<u64> {
        Some(u64::from_be_bytes(
            self.find(AttributeType::ICE_CONTROLLED)?.try_into().ok()?,
        ))
    }

    /// The tiebreaker of a peer that says it is controlling.
    #[must_use]
    pub fn ice_controlling(&self) -> Option<u64> {
        Some(u64::from_be_bytes(
            self.find(AttributeType::ICE_CONTROLLING)?.try_into().ok()?,
        ))
    }

    /// Whether the message carries either message-integrity attribute.
    #[must_use]
    pub fn has_integrity(&self) -> bool {
        self.find(AttributeType::MESSAGE_INTEGRITY).is_some()
            || self.find(AttributeType::MESSAGE_INTEGRITY_SHA256).is_some()
    }

    /// Check MESSAGE-INTEGRITY against a key (§14.5).
    #[must_use]
    pub fn verify_integrity(&self, key: &[u8]) -> Integrity {
        let Some(found) = self.locate(AttributeType::MESSAGE_INTEGRITY) else {
            return Integrity::Absent;
        };
        let mut mac = Hmac::<Sha1>::new(key);
        if !self.feed_prefix(found.offset, found.value.len(), |part| mac.update(part)) {
            return Integrity::Invalid;
        }
        if constant_time_eq(&mac.finish(), found.value) {
            Integrity::Valid
        } else {
            Integrity::Invalid
        }
    }

    /// Check MESSAGE-INTEGRITY-SHA256 against a key (§14.6).
    ///
    /// A usage may truncate the value; whatever length arrived is the length
    /// compared, having already been checked to be a legal one.
    #[must_use]
    pub fn verify_integrity_sha256(&self, key: &[u8]) -> Integrity {
        let Some(found) = self.locate(AttributeType::MESSAGE_INTEGRITY_SHA256) else {
            return Integrity::Absent;
        };
        let mut mac = Hmac::<Sha256>::new(key);
        if !self.feed_prefix(found.offset, found.value.len(), |part| mac.update(part)) {
            return Integrity::Invalid;
        }
        let full = mac.finish();
        let Some(expected) = full.get(..found.value.len()) else {
            return Integrity::Invalid;
        };
        if constant_time_eq(expected, found.value) {
            Integrity::Valid
        } else {
            Integrity::Invalid
        }
    }

    /// Check FINGERPRINT (§14.7).
    #[must_use]
    pub fn verify_fingerprint(&self) -> Integrity {
        let Some(found) = self.locate(AttributeType::FINGERPRINT) else {
            return Integrity::Absent;
        };
        let Ok(claimed) = <[u8; 4]>::try_from(found.value) else {
            return Integrity::Invalid;
        };
        let mut crc = Crc32::new();
        if !self.feed_prefix(found.offset, found.value.len(), |part| crc.update(part)) {
            return Integrity::Invalid;
        }
        if crc.finish() ^ FINGERPRINT_XOR == u32::from_be_bytes(claimed) {
            Integrity::Valid
        } else {
            Integrity::Invalid
        }
    }

    fn locate(&self, kind: AttributeType) -> Option<Attribute<'a>> {
        self.attributes()
            .find(|attribute| attribute.kind == kind && self.is_visible(attribute.offset, kind))
    }

    /// Feed everything before the attribute at `offset` to a hash, with the
    /// header's length field replaced by one that ends at that attribute.
    ///
    /// This is the step people get wrong. The length in the header is not the
    /// length of the message when the check is computed: it is the length the
    /// message would have if it ended right after the attribute being checked,
    /// which is what makes a FINGERPRINT appended afterwards harmless to a
    /// MESSAGE-INTEGRITY computed before it (§14.5).
    fn feed_prefix(&self, offset: usize, value_len: usize, mut feed: impl FnMut(&[u8])) -> bool {
        let end = offset + 4 + padded(value_len);
        let Ok(adjusted) = u16::try_from(end - HEADER_LEN) else {
            return false;
        };
        let (Some(head), Some(rest)) = (self.raw.get(..2), self.raw.get(4..offset)) else {
            return false;
        };
        feed(head);
        feed(&adjusted.to_be_bytes());
        feed(rest);
        true
    }
}

/// The algorithm numbers a PASSWORD-ALGORITHMS attribute offers (§14.11).
///
/// Each entry is a number, a parameter length and the parameters padded to a
/// four-byte boundary. An entry that does not fit ends the walk: the attribute
/// is comprehension-optional, so a malformed one is a reason to stop reading
/// it, not a reason to refuse the message.
#[derive(Clone, Debug)]
pub struct OfferedAlgorithms<'a> {
    rest: &'a [u8],
}

impl Iterator for OfferedAlgorithms<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        let header = self.rest.get(..4)?;
        let number = u16::from_be_bytes([*header.first()?, *header.get(1)?]);
        let parameters = usize::from(u16::from_be_bytes([*header.get(2)?, *header.get(3)?]));
        self.rest = self.rest.get(4 + padded(parameters)..)?;
        Some(number)
    }
}

/// Why a datagram is not a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Shorter than the header.
    TooShort {
        /// What arrived.
        got: usize,
    },
    /// The two leading bits are not zero, so whatever this is, it is not STUN
    /// (§5).
    NotStun,
    /// The magic cookie is missing. An RFC 3489 message looks like this, and
    /// so does anything else that happens to start with two zero bits.
    Cookie(u32),
    /// The length field does not agree with the datagram.
    Length {
        /// What the header asks for, header included.
        declared: usize,
        /// What arrived.
        got: usize,
    },
    /// The length field is not a multiple of four, which it must be because
    /// every attribute is padded to one (§5).
    Unaligned(u16),
    /// An attribute claims more than the message holds.
    TruncatedAttribute {
        /// Where it starts.
        at: usize,
        /// Octets it wants, padding included.
        want: usize,
        /// Octets left in the message.
        available: usize,
    },
    /// A known attribute of the wrong size.
    AttributeLength {
        /// Which one.
        kind: AttributeType,
        /// The size it came with.
        length: usize,
    },
    /// An address attribute with a family nobody defined, or a length that
    /// does not match the family it declares.
    Address {
        /// Which one.
        kind: AttributeType,
    },
    /// An ERROR-CODE outside the range the field can mean (§14.8).
    ErrorCode {
        /// The hundreds digit, which must be 3 to 6.
        class: u8,
        /// The rest, which must be under 100.
        number: u8,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => {
                write!(f, "{got} octets, {HEADER_LEN} needed for a header")
            }
            Self::NotStun => f.write_str("the two leading bits are not zero"),
            Self::Cookie(cookie) => write!(f, "magic cookie {cookie:#010x}"),
            Self::Length { declared, got } => {
                write!(f, "message of {declared} octets in a datagram of {got}")
            }
            Self::Unaligned(length) => write!(f, "length {length} is not a multiple of four"),
            Self::TruncatedAttribute {
                at,
                want,
                available,
            } => write!(
                f,
                "attribute at {at} wants {want} octets, {available} there"
            ),
            Self::AttributeLength { kind, length } => {
                write!(f, "{kind} of {length} octets")
            }
            Self::Address { kind } => write!(f, "{kind} is not an address"),
            Self::ErrorCode { class, number } => write!(f, "error code {class}{number:02}"),
        }
    }
}

impl core::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::{
        Class, HEADER_LEN, Integrity, MAGIC_COOKIE, Message, Method, ParseError, TransactionId,
        decode_type, encode_type,
    };
    use crate::crypto::hmac::Hmac;
    use crate::crypto::sha256::Sha256;
    use crate::stun::attribute::AttributeType;

    fn transaction() -> TransactionId {
        TransactionId::new([
            0x21, 0x0f, 0x77, 0x1e, 0x63, 0xa9, 0x0c, 0x5b, 0x44, 0x8d, 0x2f, 0x93,
        ])
    }

    /// A message with the header filled in and the attributes given verbatim.
    fn assemble(type_bits: u16, attributes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&type_bits.to_be_bytes());
        out.extend_from_slice(&u16::try_from(attributes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&transaction().as_bytes());
        out.extend_from_slice(attributes);
        out
    }

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn the_class_and_method_bits_interleave_the_way_the_figure_says() {
        assert_eq!(encode_type(Class::Request, Method::BINDING), 0x0001);
        assert_eq!(encode_type(Class::Indication, Method::BINDING), 0x0011);
        assert_eq!(encode_type(Class::Success, Method::BINDING), 0x0101);
        assert_eq!(encode_type(Class::Error, Method::BINDING), 0x0111);
    }

    #[test]
    fn every_class_and_method_round_trips_through_the_type_field() {
        for code in 0..0x1000_u16 {
            let method = Method::new(code).unwrap();
            for class in [
                Class::Request,
                Class::Indication,
                Class::Success,
                Class::Error,
            ] {
                let bits = encode_type(class, method);
                assert_eq!(bits & 0xc000, 0, "{class:?} {method}");
                assert_eq!(decode_type(bits), (class, method));
            }
        }
    }

    #[test]
    fn a_method_wider_than_twelve_bits_does_not_exist() {
        assert_eq!(Method::new(0x0fff).map(Method::code), Some(0x0fff));
        assert_eq!(Method::new(0x1000), None);
    }

    #[test]
    fn a_binding_request_reads_back() {
        let bytes = assemble(0x0001, &[]);
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.class(), Class::Request);
        assert_eq!(message.method(), Method::BINDING);
        assert_eq!(message.transaction_id(), transaction());
        assert_eq!(message.attributes().count(), 0);
    }

    #[test]
    fn a_datagram_shorter_than_the_header_is_refused() {
        for length in 0..HEADER_LEN {
            let bytes = assemble(0x0001, &[]);
            assert_eq!(
                Message::parse(&bytes[..length]),
                Err(ParseError::TooShort { got: length })
            );
        }
    }

    #[test]
    fn the_leading_bits_have_to_be_zero() {
        let mut bytes = assemble(0x0001, &[]);
        bytes[0] |= 0x80;
        assert_eq!(Message::parse(&bytes), Err(ParseError::NotStun));

        let mut bytes = assemble(0x0001, &[]);
        bytes[0] |= 0x40;
        assert_eq!(Message::parse(&bytes), Err(ParseError::NotStun));
    }

    #[test]
    fn a_message_without_the_cookie_is_not_ours() {
        let mut bytes = assemble(0x0001, &[]);
        bytes[4] = 0;
        assert!(matches!(Message::parse(&bytes), Err(ParseError::Cookie(_))));
    }

    #[test]
    fn a_length_that_is_not_a_multiple_of_four_is_refused() {
        let mut bytes = assemble(0x0001, &attribute(0x8022, b"si"));
        bytes[3] = 5;
        assert_eq!(Message::parse(&bytes), Err(ParseError::Unaligned(5)));
    }

    #[test]
    fn a_length_longer_than_the_datagram_is_refused() {
        let mut bytes = assemble(0x0001, &[]);
        bytes[3] = 8;
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::Length {
                declared: 28,
                got: 20
            })
        );
    }

    #[test]
    fn trailing_bytes_are_refused_on_a_datagram_and_left_alone_on_a_stream() {
        let mut bytes = assemble(0x0001, &[]);
        bytes.extend_from_slice(b"more");
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::Length {
                declared: 20,
                got: 24
            })
        );
        let message = Message::parse_prefix(&bytes).unwrap();
        assert_eq!(message.as_bytes().len(), 20);
    }

    #[test]
    fn an_attribute_that_runs_off_the_end_is_refused() {
        // a four-byte header claiming eight bytes of value, with the message
        // length saying the attribute area is only eight bytes long
        let mut attributes = attribute(0x8022, b"sipral");
        attributes[3] = 12;
        let bytes = assemble(0x0001, &attributes);
        assert!(matches!(
            Message::parse(&bytes),
            Err(ParseError::TruncatedAttribute { .. })
        ));
    }

    #[test]
    fn a_last_attribute_with_its_padding_left_off_is_refused() {
        // six bytes of value and no padding: the sender saved two bytes and
        // made the message length something the specification says it can
        // never be
        let mut attributes = Vec::from([0x80, 0x22, 0x00, 0x06]);
        attributes.extend_from_slice(b"sipral");
        let bytes = assemble(0x0001, &attributes);
        assert_eq!(Message::parse(&bytes), Err(ParseError::Unaligned(10)));
    }

    #[test]
    fn padding_is_counted_but_not_returned() {
        let bytes = assemble(0x0001, &attribute(0x8022, b"si"));
        let message = Message::parse(&bytes).unwrap();
        let software = message.software().unwrap();
        assert_eq!(software, b"si");
        assert_eq!(message.as_bytes().len(), HEADER_LEN + 8);
    }

    #[test]
    fn a_known_attribute_of_the_wrong_size_is_refused() {
        for (kind, value) in [
            (0x0008_u16, vec![0; 19]),
            (0x001c, vec![0; 12]),
            (0x001c, vec![0; 36]),
            (0x8028, vec![0; 3]),
            (0x0024, vec![0; 8]),
            (0x0025, vec![0; 4]),
            (0x8029, vec![0; 4]),
        ] {
            let bytes = assemble(0x0001, &attribute(kind, &value));
            assert!(
                matches!(
                    Message::parse(&bytes),
                    Err(ParseError::AttributeLength { .. })
                ),
                "{kind:#06x} of {} octets was accepted",
                value.len()
            );
        }
    }

    #[test]
    fn a_sha256_integrity_that_is_a_legal_truncation_is_accepted() {
        for length in [16_usize, 20, 24, 28, 32] {
            let bytes = assemble(0x0101, &attribute(0x001c, &vec![0; length]));
            assert!(Message::parse(&bytes).is_ok(), "{length}");
        }
    }

    #[test]
    fn an_address_of_the_wrong_shape_is_refused() {
        let bytes = assemble(0x0101, &attribute(0x0020, &[0, 1, 0, 0, 1, 2, 3]));
        assert!(matches!(
            Message::parse(&bytes),
            Err(ParseError::Address { .. })
        ));
    }

    #[test]
    fn an_error_code_outside_the_range_is_refused() {
        let bytes = assemble(0x0111, &attribute(0x0009, &[0, 0, 7, 0]));
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::ErrorCode {
                class: 7,
                number: 0
            })
        );
        let bytes = assemble(0x0111, &attribute(0x0009, &[0, 0, 4, 100]));
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::ErrorCode {
                class: 4,
                number: 100
            })
        );
    }

    #[test]
    fn an_error_code_reads_class_and_number_back_as_one_number() {
        let bytes = assemble(0x0111, &attribute(0x0009, b"\0\0\x04\x01Unauthenticated"));
        let message = Message::parse(&bytes).unwrap();
        let error = message.error_code().unwrap();
        assert_eq!(error.code(), 401);
        assert_eq!(error.reason_text(), Some("Unauthenticated"));
    }

    #[test]
    fn an_unknown_comprehension_optional_attribute_is_kept_and_ignored() {
        let mut attributes = attribute(0xc000, b"whatever");
        attributes.extend_from_slice(&attribute(0x8022, b"sipral"));
        let bytes = assemble(0x0101, &attributes);
        let message = Message::parse(&bytes).unwrap();

        assert!(message.check_comprehension().is_ok());
        assert_eq!(message.software().unwrap(), b"sipral");
        assert_eq!(
            message.find(AttributeType::new(0xc000)).unwrap(),
            b"whatever"
        );
    }

    #[test]
    fn an_unknown_comprehension_required_attribute_is_a_420() {
        let mut attributes = attribute(0x4000, b"no idea");
        attributes.extend_from_slice(&attribute(0x0002, b"reserved"));
        let bytes = assemble(0x0001, &attributes);
        let message = Message::parse(&bytes).unwrap();

        let unknown = message.check_comprehension().unwrap_err();
        assert_eq!(
            unknown.types(),
            [AttributeType::new(0x4000), AttributeType::new(0x0002)]
        );
        assert!(!unknown.is_truncated());
    }

    #[test]
    fn attributes_after_message_integrity_are_not_there() {
        let mut attributes = attribute(0x0008, &[0; 20]);
        attributes.extend_from_slice(&attribute(0x8022, b"appended"));
        attributes.extend_from_slice(&attribute(0x4000, b"required"));
        attributes.extend_from_slice(&attribute(0x8028, &[0; 4]));
        let bytes = assemble(0x0101, &attributes);
        let message = Message::parse(&bytes).unwrap();

        assert_eq!(message.software(), None);
        assert!(message.check_comprehension().is_ok());
        assert!(message.find(AttributeType::FINGERPRINT).is_some());
        assert_eq!(message.attributes().count(), 4);
    }

    #[test]
    fn only_the_fingerprint_survives_a_sha256_integrity_on_its_own() {
        let mut attributes = attribute(0x001c, &[0; 32]);
        attributes.extend_from_slice(&attribute(0x8022, b"appended"));
        attributes.extend_from_slice(&attribute(0x8028, &[0; 4]));
        let bytes = assemble(0x0101, &attributes);
        let message = Message::parse(&bytes).unwrap();

        assert_eq!(message.software(), None);
        assert!(message.find(AttributeType::FINGERPRINT).is_some());
    }

    #[test]
    fn a_sha256_integrity_after_a_sha1_one_is_still_visible() {
        let mut attributes = attribute(0x0008, &[0; 20]);
        attributes.extend_from_slice(&attribute(0x001c, &[0; 32]));
        let bytes = assemble(0x0101, &attributes);
        let message = Message::parse(&bytes).unwrap();

        assert!(
            message
                .find(AttributeType::MESSAGE_INTEGRITY_SHA256)
                .is_some()
        );
        assert!(message.has_integrity());
    }

    #[test]
    fn the_first_occurrence_is_the_one_that_counts() {
        let mut attributes = attribute(0x8022, b"first");
        attributes.extend_from_slice(&attribute(0x8022, b"second"));
        let bytes = assemble(0x0101, &attributes);
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.software().unwrap(), b"first");
    }

    #[test]
    fn a_fingerprint_that_does_not_match_is_invalid_rather_than_absent() {
        let bytes = assemble(0x0001, &attribute(0x8028, &[0; 4]));
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.verify_fingerprint(), Integrity::Invalid);

        let bytes = assemble(0x0001, &[]);
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.verify_fingerprint(), Integrity::Absent);
        assert_eq!(message.verify_integrity(b"key"), Integrity::Absent);
        assert_eq!(message.verify_integrity_sha256(b"key"), Integrity::Absent);
    }

    #[test]
    fn the_offered_password_algorithms_walk_their_parameters() {
        // MD5 with no parameters, then SHA-256 with two bytes of them padded
        // to four, then a truncated entry that ends the walk
        let value = [0, 1, 0, 0, 0, 2, 0, 2, 0xaa, 0xbb, 0, 0, 0, 3];
        let bytes = assemble(0x0111, &attribute(0x8002, &value));
        let message = Message::parse(&bytes).unwrap();
        let offered: Vec<u16> = message.offered_password_algorithms().collect();
        assert_eq!(offered, [1, 2]);
    }

    #[test]
    fn a_truncated_sha256_integrity_is_checked_against_its_own_length() {
        // a usage may cut the value to sixteen bytes, and what the HMAC covers
        // is then a message that is sixteen bytes shorter
        let mut bytes = assemble(0x0101, &attribute(0x8022, b"si"));
        let adjusted = u16::try_from(bytes.len() - HEADER_LEN + 4 + 16).unwrap();

        let mut input = bytes.clone();
        input[2..4].copy_from_slice(&adjusted.to_be_bytes());
        let mut mac = Hmac::<Sha256>::new(b"key");
        mac.update(&input);
        let full = mac.finish();

        bytes[2..4].copy_from_slice(&adjusted.to_be_bytes());
        bytes.extend_from_slice(&[0x00, 0x1c, 0x00, 0x10]);
        bytes.extend_from_slice(&full[..16]);

        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.verify_integrity_sha256(b"key"), Integrity::Valid);
        assert_eq!(
            message.verify_integrity_sha256(b"other"),
            Integrity::Invalid
        );
    }

    #[test]
    fn an_unknown_attributes_list_reads_back_as_types() {
        let bytes = assemble(0x0111, &attribute(0x000a, &[0x00, 0x02, 0x40, 0x00]));
        let message = Message::parse(&bytes).unwrap();
        let listed: Vec<AttributeType> = message.unknown_attributes().collect();
        assert_eq!(
            listed,
            [AttributeType::new(0x0002), AttributeType::new(0x4000)]
        );
    }
}
