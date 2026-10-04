// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The attributes this stack understands, and the codepoints that name them.
//!
//! The registry is open, so the type is a newtype over the sixteen bits rather
//! than an enum: a codepoint nobody here has heard of still round-trips
//! through a message unharmed.
//!
//! The TURN and ICE codepoints sit here with the base ones because the answer
//! to "does this receiver understand the attribute" is a property of the whole
//! crate, not of one layer of it: a TURN response carries XOR-RELAYED-ADDRESS,
//! which is comprehension-required, so a list that left it out would make the
//! stack refuse every allocation it ever got.

use core::fmt;

/// A STUN attribute type (RFC 8489 §18.3).
///
/// The top bit of the range decides what happens to an attribute the receiver
/// does not understand, which is the only thing an unknown codepoint tells you
/// and the reason the split is in the numbering rather than in a table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttributeType(u16);

impl AttributeType {
    /// The reflexive transport address, in the clear. Servers send it only for
    /// RFC 3489 clients (§14.1).
    pub const MAPPED_ADDRESS: Self = Self(0x0001);
    /// The name that goes with the password used for the integrity check
    /// (§14.3).
    pub const USERNAME: Self = Self(0x0006);
    /// Which channel a ChannelBind is about (RFC 8656 §18.1).
    pub const CHANNEL_NUMBER: Self = Self(0x000C);
    /// Seconds an allocation has left, asked for or granted
    /// (RFC 8656 §18.2).
    pub const LIFETIME: Self = Self(0x000D);
    /// HMAC-SHA1 over the message (§14.5).
    pub const MESSAGE_INTEGRITY: Self = Self(0x0008);
    /// The code and reason phrase of an error response (§14.8).
    pub const ERROR_CODE: Self = Self(0x0009);
    /// What a 420 could not understand (§14.13).
    pub const UNKNOWN_ATTRIBUTES: Self = Self(0x000A);
    /// A peer's transport address as the relay sees it (RFC 8656 §18.3).
    pub const XOR_PEER_ADDRESS: Self = Self(0x0012);
    /// Application data on its way through the relay (RFC 8656 §18.4).
    pub const DATA: Self = Self(0x0013);
    /// The realm the credentials belong to (§14.9).
    pub const REALM: Self = Self(0x0014);
    /// The server's replay cookie (§14.10).
    pub const NONCE: Self = Self(0x0015);
    /// The address the relay allocated to us (RFC 8656 §18.5).
    pub const XOR_RELAYED_ADDRESS: Self = Self(0x0016);
    /// The family of relayed address we want (RFC 8656 §18.6).
    pub const REQUESTED_ADDRESS_FAMILY: Self = Self(0x0017);
    /// A relayed port that is even, and optionally a hold on the next one up
    /// (RFC 8656 §18.7).
    pub const EVEN_PORT: Self = Self(0x0018);
    /// What the relay speaks to the peer, which this specification fixes at
    /// UDP (RFC 8656 §18.8).
    pub const REQUESTED_TRANSPORT: Self = Self(0x0019);
    /// Set the DF bit on the datagram the relay sends onward
    /// (RFC 8656 §18.9).
    pub const DONT_FRAGMENT: Self = Self(0x001A);
    /// HMAC-SHA256 over the message (§14.6).
    pub const MESSAGE_INTEGRITY_SHA256: Self = Self(0x001C);
    /// The algorithm the client chose from what the server offered (§14.12).
    pub const PASSWORD_ALGORITHM: Self = Self(0x001D);
    /// The reflexive transport address, obfuscated against address-rewriting
    /// middleboxes (§14.2).
    pub const XOR_MAPPED_ADDRESS: Self = Self(0x0020);
    /// What a peer-reflexive candidate found by this check would be worth
    /// (RFC 8445 §16.1).
    pub const PRIORITY: Self = Self(0x0024);
    /// The controlling agent nominating this pair (RFC 8445 §16.1).
    pub const USE_CANDIDATE: Self = Self(0x0025);
    /// A relayed address the server is holding for us (RFC 8656 §18.10).
    pub const RESERVATION_TOKEN: Self = Self(0x0022);
    /// Ask for one relayed address of each family in a single Allocate
    /// (RFC 8656 §18.11).
    pub const ADDITIONAL_ADDRESS_FAMILY: Self = Self(0x8000);
    /// Why one family of a dual allocation could not be served
    /// (RFC 8656 §18.12).
    pub const ADDRESS_ERROR_CODE: Self = Self(0x8001);
    /// The algorithms the server can derive a password with (§14.11).
    pub const PASSWORD_ALGORITHMS: Self = Self(0x8002);
    /// An ICMP error the relay saw on its way to a peer (RFC 8656 §18.13).
    pub const ICMP: Self = Self(0x8004);
    /// What the sender is running (§14.14).
    pub const SOFTWARE: Self = Self(0x8022);
    /// Where a 300 wants the client to go instead (§14.15).
    pub const ALTERNATE_SERVER: Self = Self(0x8023);
    /// CRC-32 over the message, which is what tells STUN from RTP when the two
    /// share a port (§14.7).
    pub const FINGERPRINT: Self = Self(0x8028);
    /// The tiebreaker of an agent that believes it is controlled
    /// (RFC 8445 §16.1).
    pub const ICE_CONTROLLED: Self = Self(0x8029);
    /// The tiebreaker of an agent that believes it is controlling
    /// (RFC 8445 §16.1).
    pub const ICE_CONTROLLING: Self = Self(0x802A);

    /// The type with this codepoint.
    #[must_use]
    pub const fn new(code: u16) -> Self {
        Self(code)
    }

    /// The codepoint.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }

    /// Whether a receiver that does not know this attribute has to refuse the
    /// message rather than skip the attribute.
    #[must_use]
    pub const fn is_comprehension_required(self) -> bool {
        self.0 < 0x8000
    }

    /// Whether this implementation knows what the attribute means.
    pub(crate) const fn is_known(self) -> bool {
        matches!(
            self,
            Self::MAPPED_ADDRESS
                | Self::USERNAME
                | Self::CHANNEL_NUMBER
                | Self::LIFETIME
                | Self::MESSAGE_INTEGRITY
                | Self::ERROR_CODE
                | Self::UNKNOWN_ATTRIBUTES
                | Self::XOR_PEER_ADDRESS
                | Self::DATA
                | Self::REALM
                | Self::NONCE
                | Self::XOR_RELAYED_ADDRESS
                | Self::REQUESTED_ADDRESS_FAMILY
                | Self::EVEN_PORT
                | Self::REQUESTED_TRANSPORT
                | Self::DONT_FRAGMENT
                | Self::MESSAGE_INTEGRITY_SHA256
                | Self::PASSWORD_ALGORITHM
                | Self::XOR_MAPPED_ADDRESS
                | Self::RESERVATION_TOKEN
                | Self::PRIORITY
                | Self::USE_CANDIDATE
                | Self::ADDITIONAL_ADDRESS_FAMILY
                | Self::ADDRESS_ERROR_CODE
                | Self::PASSWORD_ALGORITHMS
                | Self::ICMP
                | Self::SOFTWARE
                | Self::ALTERNATE_SERVER
                | Self::FINGERPRINT
                | Self::ICE_CONTROLLED
                | Self::ICE_CONTROLLING
        )
    }
}

impl fmt::Display for AttributeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::MAPPED_ADDRESS => "MAPPED-ADDRESS",
            Self::USERNAME => "USERNAME",
            Self::CHANNEL_NUMBER => "CHANNEL-NUMBER",
            Self::LIFETIME => "LIFETIME",
            Self::MESSAGE_INTEGRITY => "MESSAGE-INTEGRITY",
            Self::ERROR_CODE => "ERROR-CODE",
            Self::UNKNOWN_ATTRIBUTES => "UNKNOWN-ATTRIBUTES",
            Self::XOR_PEER_ADDRESS => "XOR-PEER-ADDRESS",
            Self::DATA => "DATA",
            Self::REALM => "REALM",
            Self::NONCE => "NONCE",
            Self::XOR_RELAYED_ADDRESS => "XOR-RELAYED-ADDRESS",
            Self::REQUESTED_ADDRESS_FAMILY => "REQUESTED-ADDRESS-FAMILY",
            Self::EVEN_PORT => "EVEN-PORT",
            Self::REQUESTED_TRANSPORT => "REQUESTED-TRANSPORT",
            Self::DONT_FRAGMENT => "DONT-FRAGMENT",
            Self::MESSAGE_INTEGRITY_SHA256 => "MESSAGE-INTEGRITY-SHA256",
            Self::PASSWORD_ALGORITHM => "PASSWORD-ALGORITHM",
            Self::XOR_MAPPED_ADDRESS => "XOR-MAPPED-ADDRESS",
            Self::RESERVATION_TOKEN => "RESERVATION-TOKEN",
            Self::PRIORITY => "PRIORITY",
            Self::USE_CANDIDATE => "USE-CANDIDATE",
            Self::ADDITIONAL_ADDRESS_FAMILY => "ADDITIONAL-ADDRESS-FAMILY",
            Self::ADDRESS_ERROR_CODE => "ADDRESS-ERROR-CODE",
            Self::PASSWORD_ALGORITHMS => "PASSWORD-ALGORITHMS",
            Self::ICMP => "ICMP",
            Self::SOFTWARE => "SOFTWARE",
            Self::ALTERNATE_SERVER => "ALTERNATE-SERVER",
            Self::FINGERPRINT => "FINGERPRINT",
            Self::ICE_CONTROLLED => "ICE-CONTROLLED",
            Self::ICE_CONTROLLING => "ICE-CONTROLLING",
            Self(code) => return write!(f, "0x{code:04x}"),
        };
        f.write_str(name)
    }
}

/// The error codes this stack acts on.
///
/// The registry has more; a code that is not here still reaches the caller as
/// a number, because the class alone decides what a client does with it
/// (§6.3.4).
pub mod error_code {
    /// Go ask the server in ALTERNATE-SERVER instead.
    pub const TRY_ALTERNATE: u16 = 300;
    /// The request was malformed.
    pub const BAD_REQUEST: u16 = 400;
    /// Credentials are needed, or the ones offered were wrong.
    pub const UNAUTHENTICATED: u16 = 401;
    /// The request is fine and the server will not do it anyway
    /// (RFC 8656 §19).
    pub const FORBIDDEN: u16 = 403;
    /// A comprehension-required attribute the receiver did not understand.
    pub const UNKNOWN_ATTRIBUTE: u16 = 420;
    /// A request that needs an allocation arrived without one, or one that
    /// needs none arrived with one (RFC 8656 §19).
    pub const ALLOCATION_MISMATCH: u16 = 437;
    /// The nonce has expired; retry with the one in this response.
    pub const STALE_NONCE: u16 = 438;
    /// The relay will not hand out an address of the family asked for
    /// (RFC 8656 §19).
    pub const ADDRESS_FAMILY_NOT_SUPPORTED: u16 = 440;
    /// The credentials are valid but belong to somebody else's allocation
    /// (RFC 8656 §19).
    pub const WRONG_CREDENTIALS: u16 = 441;
    /// The relay does not speak the protocol asked for towards the peer
    /// (RFC 8656 §19).
    pub const UNSUPPORTED_TRANSPORT: u16 = 442;
    /// A peer address of a family the allocation does not relay
    /// (RFC 8656 §19).
    pub const PEER_ADDRESS_FAMILY_MISMATCH: u16 = 443;
    /// This user already has as many allocations as the server allows
    /// (RFC 8656 §19).
    pub const ALLOCATION_QUOTA_REACHED: u16 = 486;
    /// Both agents claimed the same ICE role (RFC 8445 §16.2).
    pub const ROLE_CONFLICT: u16 = 487;
    /// The server is having a bad day.
    pub const SERVER_ERROR: u16 = 500;
    /// The relay has run out of whatever the request needed
    /// (RFC 8656 §19).
    pub const INSUFFICIENT_CAPACITY: u16 = 508;
}

/// The contents of an ERROR-CODE attribute (§14.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorCode<'a> {
    code: u16,
    reason: &'a [u8],
}

impl<'a> ErrorCode<'a> {
    pub(crate) const fn new(code: u16, reason: &'a [u8]) -> Self {
        Self { code, reason }
    }

    /// The three-digit code, class and number put back together.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// The reason phrase as it arrived.
    ///
    /// Bytes rather than text: the phrase is meant to be UTF-8 and is meant
    /// for a human, and neither of those is a reason to refuse a 401 whose
    /// diagnostic string is mangled.
    #[must_use]
    pub const fn reason(&self) -> &'a [u8] {
        self.reason
    }

    /// The reason phrase, when it is the UTF-8 the specification asks for.
    #[must_use]
    pub fn reason_text(&self) -> Option<&'a str> {
        core::str::from_utf8(self.reason).ok()
    }
}

/// A way of turning a long-term credential into an HMAC key (§18.5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordAlgorithm {
    /// `MD5(username ":" realm ":" password)`, the default and the one that
    /// matches what a SIP registrar already stores.
    Md5,
    /// `SHA-256(username ":" realm ":" password)`.
    Sha256,
}

impl PasswordAlgorithm {
    /// The registry number.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Md5 => 0x0001,
            Self::Sha256 => 0x0002,
        }
    }

    /// The algorithm with this number, if it is one of the two that exist.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0001 => Some(Self::Md5),
            0x0002 => Some(Self::Sha256),
            _ => None,
        }
    }
}

impl fmt::Display for PasswordAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Md5 => "MD5",
            Self::Sha256 => "SHA-256",
        })
    }
}

/// How many unknown types a `UnknownRequired` will carry.
///
/// A message with more comprehension-required attributes than this that the
/// receiver has never heard of is not a message worth describing precisely.
const UNKNOWN_CAPACITY: usize = 8;

/// The comprehension-required attributes a message carries that this
/// implementation does not understand.
///
/// Their presence is the 420 (Unknown Attribute) case: a server answering a
/// request puts exactly this list in the UNKNOWN-ATTRIBUTES attribute of the
/// error response (§6.3.1), and a client that gets them in a response gives
/// the transaction up (§6.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownRequired {
    types: [AttributeType; UNKNOWN_CAPACITY],
    count: usize,
    overflowed: bool,
}

impl UnknownRequired {
    /// The error code this condition is answered with.
    pub const CODE: u16 = error_code::UNKNOWN_ATTRIBUTE;

    pub(crate) const fn empty() -> Self {
        Self {
            types: [AttributeType::new(0); UNKNOWN_CAPACITY],
            count: 0,
            overflowed: false,
        }
    }

    pub(crate) fn push(&mut self, kind: AttributeType) {
        if let Some(slot) = self.types.get_mut(self.count) {
            *slot = kind;
            self.count += 1;
        } else {
            self.overflowed = true;
        }
    }

    /// The types, in the order they appeared.
    #[must_use]
    pub fn types(&self) -> &[AttributeType] {
        self.types.get(..self.count).unwrap_or_default()
    }

    /// Whether there was nothing the receiver failed to understand.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether the message held more of them than this list can name.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.overflowed
    }
}

impl fmt::Display for UnknownRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown comprehension-required attribute")?;
        for (position, kind) in self.types().iter().enumerate() {
            let separator = if position == 0 { " " } else { ", " };
            write!(f, "{separator}{kind}")?;
        }
        if self.overflowed {
            f.write_str(", and more")?;
        }
        Ok(())
    }
}

impl core::error::Error for UnknownRequired {}

#[cfg(test)]
mod tests {
    use super::{AttributeType, PasswordAlgorithm, UnknownRequired};

    #[test]
    fn the_range_decides_whether_an_unknown_attribute_is_fatal() {
        assert!(AttributeType::new(0x0000).is_comprehension_required());
        assert!(AttributeType::new(0x7fff).is_comprehension_required());
        assert!(!AttributeType::new(0x8000).is_comprehension_required());
        assert!(!AttributeType::new(0xffff).is_comprehension_required());
    }

    #[test]
    fn the_codepoints_the_registry_assigns_are_the_ones_written_down() {
        assert_eq!(AttributeType::MAPPED_ADDRESS.code(), 0x0001);
        assert_eq!(AttributeType::MESSAGE_INTEGRITY.code(), 0x0008);
        assert_eq!(AttributeType::MESSAGE_INTEGRITY_SHA256.code(), 0x001c);
        assert_eq!(AttributeType::XOR_MAPPED_ADDRESS.code(), 0x0020);
        assert_eq!(AttributeType::PRIORITY.code(), 0x0024);
        assert_eq!(AttributeType::USE_CANDIDATE.code(), 0x0025);
        assert_eq!(AttributeType::FINGERPRINT.code(), 0x8028);
        assert_eq!(AttributeType::ICE_CONTROLLED.code(), 0x8029);
        assert_eq!(AttributeType::ICE_CONTROLLING.code(), 0x802a);
    }

    #[test]
    fn the_turn_codepoints_are_the_ones_written_down() {
        assert_eq!(AttributeType::CHANNEL_NUMBER.code(), 0x000c);
        assert_eq!(AttributeType::LIFETIME.code(), 0x000d);
        assert_eq!(AttributeType::XOR_PEER_ADDRESS.code(), 0x0012);
        assert_eq!(AttributeType::DATA.code(), 0x0013);
        assert_eq!(AttributeType::XOR_RELAYED_ADDRESS.code(), 0x0016);
        assert_eq!(AttributeType::REQUESTED_ADDRESS_FAMILY.code(), 0x0017);
        assert_eq!(AttributeType::EVEN_PORT.code(), 0x0018);
        assert_eq!(AttributeType::REQUESTED_TRANSPORT.code(), 0x0019);
        assert_eq!(AttributeType::DONT_FRAGMENT.code(), 0x001a);
        assert_eq!(AttributeType::RESERVATION_TOKEN.code(), 0x0022);
        assert_eq!(AttributeType::ADDITIONAL_ADDRESS_FAMILY.code(), 0x8000);
        assert_eq!(AttributeType::ADDRESS_ERROR_CODE.code(), 0x8001);
        assert_eq!(AttributeType::ICMP.code(), 0x8004);
    }

    #[test]
    fn the_relayed_address_must_be_understood_or_no_allocation_ever_works() {
        // 0x0010 and 0x0021 are the two codepoints RFC 8656 §18 lists as
        // reserved, and they stay unknown so that a server still using them
        // gets a 420 rather than a guess
        for reserved in [0x0010_u16, 0x0021] {
            assert!(!AttributeType::new(reserved).is_known());
        }
        for required in [
            AttributeType::XOR_RELAYED_ADDRESS,
            AttributeType::LIFETIME,
            AttributeType::XOR_PEER_ADDRESS,
            AttributeType::DATA,
            AttributeType::RESERVATION_TOKEN,
        ] {
            assert!(required.is_comprehension_required(), "{required}");
            assert!(required.is_known(), "{required}");
        }
    }

    #[test]
    fn a_codepoint_nobody_assigned_prints_as_a_number() {
        assert_eq!(AttributeType::new(0x4242).to_string(), "0x4242");
        assert_eq!(
            AttributeType::XOR_MAPPED_ADDRESS.to_string(),
            "XOR-MAPPED-ADDRESS"
        );
    }

    #[test]
    fn reserved_codepoints_are_not_known() {
        // 0x0002 through 0x000b were RFC 3489 attributes and are reserved now,
        // so they are exactly the comprehension-required attributes a modern
        // receiver must answer with a 420
        for reserved in [0x0002_u16, 0x0003, 0x0004, 0x0005, 0x0007, 0x000b] {
            let kind = AttributeType::new(reserved);
            assert!(kind.is_comprehension_required());
            assert!(!kind.is_known(), "{kind}");
        }
    }

    #[test]
    fn the_unknown_list_stops_growing_and_says_so() {
        let mut unknown = UnknownRequired::empty();
        assert!(unknown.is_empty());
        for code in 0..12_u16 {
            unknown.push(AttributeType::new(code));
        }
        assert_eq!(unknown.types().len(), 8);
        assert!(unknown.is_truncated());
        assert!(!unknown.is_empty());
    }

    #[test]
    fn password_algorithm_numbers_round_trip() {
        for algorithm in [PasswordAlgorithm::Md5, PasswordAlgorithm::Sha256] {
            assert_eq!(
                PasswordAlgorithm::from_code(algorithm.code()),
                Some(algorithm)
            );
        }
        assert_eq!(PasswordAlgorithm::from_code(0x0000), None);
        assert_eq!(PasswordAlgorithm::from_code(0x0003), None);
    }
}
