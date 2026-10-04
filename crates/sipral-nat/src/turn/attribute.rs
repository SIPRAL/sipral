// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The methods and attribute values TURN adds to STUN (RFC 8656 §17, §18).
//!
//! The codepoints for the attributes live with the rest of the registry in the
//! STUN layer, because whether a receiver understands an attribute is a fact
//! about the whole stack. What lives here is the meaning of the four bytes
//! inside each one.

use core::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::stun::address;
use crate::stun::{AttributeType, Message};

/// The methods TURN defines (§17).
pub mod method {
    use crate::stun::Method;

    /// A method whose number fits the twelve bits, falling back to Binding for
    /// one that does not. Every number below is a three-digit hex constant
    /// from Table 4, so the fallback is unreachable; it exists because the
    /// twelve-bit check belongs to the STUN layer and returns an option.
    const fn method(code: u16) -> Method {
        match Method::new(code) {
            Some(method) => method,
            None => Method::BINDING,
        }
    }

    /// Ask for a relayed transport address.
    pub const ALLOCATE: Method = method(0x003);
    /// Keep one, or throw it away.
    pub const REFRESH: Method = method(0x004);
    /// Client to server, wrapping data for a peer.
    pub const SEND: Method = method(0x006);
    /// Server to client, wrapping data from a peer.
    pub const DATA: Method = method(0x007);
    /// Let a peer's address reach the relay.
    pub const CREATE_PERMISSION: Method = method(0x008);
    /// Give a peer a four-byte header instead of a thirty-six byte one.
    pub const CHANNEL_BIND: Method = method(0x009);
}

/// What REQUESTED-TRANSPORT asks the relay to speak towards the peer.
///
/// "This specification only allows the use of code point 17" (§18.8), so this
/// is a constant rather than a choice.
pub const PROTOCOL_UDP: u8 = 17;

/// What the server keeps an allocation for when nobody refreshes it (§6).
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);

/// How long a permission lasts. "The Permission Lifetime MUST be 300 seconds"
/// (§9) — not a default, a constant, and the server will not tell you
/// otherwise.
pub const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);

/// How long a channel binding lasts (§12).
pub const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);

/// Which IP version an address belongs to (§18.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// 0x01.
    V4,
    /// 0x02.
    V6,
}

impl AddressFamily {
    /// The byte the family occupies in an attribute.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::V4 => 0x01,
            Self::V6 => 0x02,
        }
    }

    /// The family with this byte, if it is one of the two that exist.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::V4),
            0x02 => Some(Self::V6),
            _ => None,
        }
    }

    /// The family an address belongs to.
    #[must_use]
    pub const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    /// The four bytes REQUESTED-ADDRESS-FAMILY and ADDITIONAL-ADDRESS-FAMILY
    /// carry: the family and twenty-four reserved bits.
    #[must_use]
    pub const fn encode(self) -> [u8; 4] {
        [self.code(), 0, 0, 0]
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// What EVEN-PORT asks for (§18.7).
///
/// Both forms exist for RTP as it was specified before RFC 3550 allowed an
/// arbitrary pair of ports, and a modern offer that says `a=rtcp-mux` needs
/// neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvenPort {
    /// An even port, with nothing held after it.
    Even,
    /// An even port, and the next one up held for a later allocation. The
    /// server hands back a RESERVATION-TOKEN for it.
    EvenAndReserveNext,
}

impl EvenPort {
    /// The single byte the attribute carries: the R bit and seven reserved
    /// ones.
    #[must_use]
    pub const fn encode(self) -> [u8; 1] {
        match self {
            Self::Even => [0x00],
            Self::EvenAndReserveNext => [0x80],
        }
    }
}

/// The eight bytes that name a relayed address the server is holding for a
/// later Allocate (§18.10).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReservationToken([u8; 8]);

impl ReservationToken {
    /// The token made of these eight bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// The eight bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for ReservationToken {
    /// Hex, because the token is opaque and printing it as a byte array tells
    /// a reader nothing they can compare against a capture.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReservationToken(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// Why the server served only one family of a dual allocation (§18.12).
///
/// It arrives in a *success* response: the allocation exists, and one of the
/// two addresses asked for is not in it. What reaches the caller is the family
/// and the code, which is everything §7.3 says to act on; the reason phrase is
/// a human sentence borrowed from the datagram, and copying it into an owned
/// event to be logged once is not worth the allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AddressErrorCode {
    family: AddressFamily,
    code: u16,
}

impl AddressErrorCode {
    /// The family that was refused.
    pub(crate) const fn family(self) -> AddressFamily {
        self.family
    }

    /// The code, which the section limits to 440 or 508.
    pub(crate) const fn code(self) -> u16 {
        self.code
    }

    fn parse(value: &[u8]) -> Option<Self> {
        let family = AddressFamily::from_code(*value.first()?)?;
        // the thirteen reserved bits and the three class bits share the third
        // byte; only the bottom three are the class
        let class = u16::from(*value.get(2)? & 0x07);
        let number = u16::from(*value.get(3)?);
        if !(3..=6).contains(&class) || number > 99 {
            return None;
        }
        Some(Self {
            family,
            code: class * 100 + number,
        })
    }
}

/// An ICMP error the relay met on its way to a peer (§18.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Icmp {
    kind: u8,
    code: u8,
    data: u32,
}

impl Icmp {
    /// The ICMP type. What it means depends on whether the relay reached the
    /// peer over IPv4 or IPv6, which the accompanying peer address says.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// The ICMP code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        self.code
    }

    /// The four bytes of error data, which carry the next hop's MTU for the
    /// two "too big" conditions and are zero otherwise.
    #[must_use]
    pub const fn data(&self) -> u32 {
        self.data
    }

    /// The next-hop MTU, when this is the ICMP error that carries one:
    /// ICMPv4 type 3 code 4, or ICMPv6 type 2.
    #[must_use]
    pub const fn path_mtu(&self, family: AddressFamily) -> Option<u32> {
        match family {
            AddressFamily::V4 if self.kind == 3 && self.code == 4 => Some(self.data),
            AddressFamily::V6 if self.kind == 2 => Some(self.data),
            _ => None,
        }
    }

    fn parse(value: &[u8]) -> Option<Self> {
        Some(Self {
            kind: *value.get(2)?,
            code: *value.get(3)?,
            data: u32::from_be_bytes([
                *value.get(4)?,
                *value.get(5)?,
                *value.get(6)?,
                *value.get(7)?,
            ]),
        })
    }
}

/// The seconds in a LIFETIME attribute (§18.2).
pub(crate) fn lifetime(message: &Message<'_>) -> Option<Duration> {
    let value = message.find(AttributeType::LIFETIME)?;
    let seconds = u32::from_be_bytes(value.try_into().ok()?);
    Some(Duration::from_secs(u64::from(seconds)))
}

/// The relayed transport addresses of an allocation, one per family (§18.5).
pub(crate) fn relayed_addresses(message: &Message<'_>) -> Vec<SocketAddr> {
    let transaction = message.transaction_id();
    message
        .find_all(AttributeType::XOR_RELAYED_ADDRESS)
        .filter_map(|value| address::decode_xor(value, transaction))
        .collect()
}

/// The peer an indication is about (§18.3).
pub(crate) fn peer_address(message: &Message<'_>) -> Option<SocketAddr> {
    address::decode_xor(
        message.find(AttributeType::XOR_PEER_ADDRESS)?,
        message.transaction_id(),
    )
}

/// The token a server hands back when it held a port for us (§18.10).
pub(crate) fn reservation_token(message: &Message<'_>) -> Option<ReservationToken> {
    let value = message.find(AttributeType::RESERVATION_TOKEN)?;
    Some(ReservationToken::new(value.try_into().ok()?))
}

/// The partial-failure notice a dual allocation can come back with (§18.12).
pub(crate) fn address_error_code(message: &Message<'_>) -> Option<AddressErrorCode> {
    AddressErrorCode::parse(message.find(AttributeType::ADDRESS_ERROR_CODE)?)
}

/// The ICMP error a Data indication can carry instead of data (§18.13).
pub(crate) fn icmp(message: &Message<'_>) -> Option<Icmp> {
    Icmp::parse(message.find(AttributeType::ICMP)?)
}

#[cfg(test)]
mod tests {
    use super::{
        AddressErrorCode, AddressFamily, EvenPort, Icmp, PROTOCOL_UDP, ReservationToken, method,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn the_method_numbers_are_the_ones_in_table_four() {
        assert_eq!(method::ALLOCATE.code(), 0x003);
        assert_eq!(method::REFRESH.code(), 0x004);
        assert_eq!(method::SEND.code(), 0x006);
        assert_eq!(method::DATA.code(), 0x007);
        assert_eq!(method::CREATE_PERMISSION.code(), 0x008);
        assert_eq!(method::CHANNEL_BIND.code(), 0x009);
    }

    #[test]
    fn the_only_transport_towards_a_peer_is_udp() {
        assert_eq!(PROTOCOL_UDP, 17);
    }

    #[test]
    fn families_round_trip_and_nothing_else_is_one() {
        for family in [AddressFamily::V4, AddressFamily::V6] {
            assert_eq!(AddressFamily::from_code(family.code()), Some(family));
            assert_eq!(family.encode(), [family.code(), 0, 0, 0]);
        }
        for stranger in [0x00_u8, 0x03, 0xff] {
            assert_eq!(AddressFamily::from_code(stranger), None);
        }
        assert_eq!(
            AddressFamily::of(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            AddressFamily::V4
        );
        assert_eq!(
            AddressFamily::of(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            AddressFamily::V6
        );
    }

    #[test]
    fn the_even_port_r_bit_is_the_top_one() {
        assert_eq!(EvenPort::Even.encode(), [0x00]);
        assert_eq!(EvenPort::EvenAndReserveNext.encode(), [0x80]);
    }

    #[test]
    fn an_address_error_code_splits_the_class_off_the_reserved_bits() {
        // family IPv6, thirteen reserved bits set to zero, class 5, number 8
        let value = [0x02, 0x00, 0x05, 0x08, b'o', b'u', b't'];
        let error = AddressErrorCode::parse(&value).expect("well formed");
        assert_eq!(error.family(), AddressFamily::V6);
        assert_eq!(error.code(), 508);
    }

    #[test]
    fn a_server_that_leaves_the_reserved_bits_set_still_parses() {
        // every reserved bit set: the class must come from the bottom three
        // bits of the third byte and nothing else
        let value = [0x01, 0xff, 0xf4, 0x28];
        let error = AddressErrorCode::parse(&value).expect("well formed");
        assert_eq!(error.family(), AddressFamily::V4);
        assert_eq!(error.code(), 440);
    }

    #[test]
    fn an_address_error_code_outside_the_range_is_not_one() {
        assert_eq!(AddressErrorCode::parse(&[0x01, 0, 0, 40]), None);
        assert_eq!(AddressErrorCode::parse(&[0x01, 0, 7, 40]), None);
        assert_eq!(AddressErrorCode::parse(&[0x03, 0, 5, 8]), None);
        assert_eq!(AddressErrorCode::parse(&[0x01, 0, 4, 100]), None);
        assert_eq!(AddressErrorCode::parse(&[0x01, 0, 4]), None);
    }

    #[test]
    fn the_two_icmp_errors_that_carry_an_mtu_are_the_only_ones_that_do() {
        let too_big_v4 = Icmp::parse(&[0, 0, 3, 4, 0, 0, 0x05, 0x00]).expect("well formed");
        assert_eq!(too_big_v4.kind(), 3);
        assert_eq!(too_big_v4.code(), 4);
        assert_eq!(too_big_v4.path_mtu(AddressFamily::V4), Some(1280));
        assert_eq!(too_big_v4.path_mtu(AddressFamily::V6), None);

        let too_big_v6 = Icmp::parse(&[0, 0, 2, 0, 0, 0, 0x05, 0xdc]).expect("well formed");
        assert_eq!(too_big_v6.path_mtu(AddressFamily::V6), Some(1500));

        let unreachable = Icmp::parse(&[0, 0, 3, 1, 0, 0, 0, 0]).expect("well formed");
        assert_eq!(unreachable.path_mtu(AddressFamily::V4), None);

        assert_eq!(Icmp::parse(&[0, 0, 3, 4, 0, 0, 0]), None);
    }

    #[test]
    fn a_reservation_token_prints_as_the_hex_a_capture_shows() {
        let token = ReservationToken::new([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert_eq!(format!("{token:?}"), "ReservationToken(0123456789abcdef)");
        assert_eq!(
            token.as_bytes(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }
}
