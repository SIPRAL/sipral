// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Transport addresses in an attribute value, plain and obfuscated
//! (RFC 8489 §14.1 and §14.2).
//!
//! The obfuscation exists because middleboxes rewrite what looks like an
//! address in a payload: a NAT that "helpfully" replaces its own public
//! address inside a STUN attribute breaks both the answer and the integrity
//! check over it. Exclusive-ORing the address with the magic cookie makes it
//! stop looking like an address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::message::{MAGIC_COOKIE, TransactionId};

/// The address families the attribute can carry (§14.1).
const IPV4: u8 = 0x01;
const IPV6: u8 = 0x02;

/// The family byte, the port and four or sixteen bytes of address.
const V4_LEN: usize = 8;
const V6_LEN: usize = 20;

/// The address in a MAPPED-ADDRESS-shaped value.
pub(crate) fn decode(value: &[u8]) -> Option<SocketAddr> {
    let (family, port, bytes) = split(value)?;
    let address = build(family, bytes)?;
    Some(SocketAddr::new(address, port))
}

/// The address in an XOR-MAPPED-ADDRESS-shaped value.
pub(crate) fn decode_xor(value: &[u8], transaction: TransactionId) -> Option<SocketAddr> {
    let (family, port, bytes) = split(value)?;
    let mask = mask(transaction);

    let port = port ^ u16::from_be_bytes([*mask.first()?, *mask.get(1)?]);

    let mut plain = [0_u8; 16];
    for ((slot, byte), key) in plain.iter_mut().zip(bytes).zip(mask) {
        *slot = byte ^ key;
    }
    let address = build(family, plain.get(..bytes.len())?)?;
    Some(SocketAddr::new(address, port))
}

/// Write a MAPPED-ADDRESS-shaped value.
pub(crate) fn encode(address: SocketAddr, out: &mut Vec<u8>) {
    out.push(0);
    match address.ip() {
        IpAddr::V4(v4) => {
            out.push(IPV4);
            out.extend_from_slice(&address.port().to_be_bytes());
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(IPV6);
            out.extend_from_slice(&address.port().to_be_bytes());
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Write an XOR-MAPPED-ADDRESS-shaped value.
pub(crate) fn encode_xor(address: SocketAddr, transaction: TransactionId, out: &mut Vec<u8>) {
    let start = out.len();
    encode(address, out);

    let mask = mask(transaction);
    // the port and the address are masked separately, both starting at the
    // top of the cookie: the port takes its first two bytes and the address
    // takes as many as it has, running from the cookie straight into the
    // transaction id where the address is a v6 one
    for (byte, key) in out.iter_mut().skip(start + 2).take(2).zip(mask) {
        *byte ^= key;
    }
    for (byte, key) in out.iter_mut().skip(start + 4).zip(mask) {
        *byte ^= key;
    }
}

/// Whether a value is a well-formed address of a family this stack handles.
pub(crate) fn is_valid(value: &[u8]) -> bool {
    split(value).is_some()
}

/// The family byte, the port and the address bytes, with the length agreeing
/// with the family.
fn split(value: &[u8]) -> Option<(u8, u16, &[u8])> {
    let family = *value.get(1)?;
    let expected = match family {
        IPV4 => V4_LEN,
        IPV6 => V6_LEN,
        _ => return None,
    };
    if value.len() != expected {
        return None;
    }
    let port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]);
    Some((family, port, value.get(4..)?))
}

fn build(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family {
        IPV4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
        IPV6 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).ok()?,
        ))),
        _ => None,
    }
}

/// The cookie followed by the transaction id, which is what an IPv6 address is
/// masked with and whose first four bytes serve for IPv4 and for the port.
fn mask(transaction: TransactionId) -> [u8; 16] {
    let mut mask = [0_u8; 16];
    if let Some(head) = mask.get_mut(..4) {
        head.copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    }
    if let Some(tail) = mask.get_mut(4..) {
        tail.copy_from_slice(&transaction.as_bytes());
    }
    mask
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{decode, decode_xor, encode, encode_xor, is_valid};
    use crate::stun::message::TransactionId;

    fn transaction() -> TransactionId {
        TransactionId::new([
            0x21, 0x0f, 0x77, 0x1e, 0x63, 0xa9, 0x0c, 0x5b, 0x44, 0x8d, 0x2f, 0x93,
        ])
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_v4_address_survives_being_written_and_read_back() {
        let mut out = Vec::new();
        encode(address("198.51.100.7:53412"), &mut out);
        assert_eq!(out.len(), 8);
        assert_eq!(out[1], 0x01);
        assert_eq!(decode(&out), Some(address("198.51.100.7:53412")));
    }

    #[test]
    fn a_v6_address_survives_being_written_and_read_back() {
        let peer = address("[2001:db8:aa:bb::1]:53412");
        let mut out = Vec::new();
        encode(peer, &mut out);
        assert_eq!(out.len(), 20);
        assert_eq!(out[1], 0x02);
        assert_eq!(decode(&out), Some(peer));
    }

    #[test]
    fn the_v4_obfuscation_is_the_cookie_and_nothing_else() {
        let peer = address("198.51.100.7:53412");
        let mut out = Vec::new();
        encode_xor(peer, transaction(), &mut out);

        // c6336407 xor 2112a442, and d0a4 xor 2112
        assert_eq!(&out[4..], &[0xe7, 0x21, 0xc0, 0x45]);
        assert_eq!(&out[2..4], &[0xf1, 0xb6]);
        assert_eq!(decode_xor(&out, transaction()), Some(peer));
    }

    #[test]
    fn the_v6_obfuscation_runs_into_the_transaction_id() {
        let peer = address("[2001:db8:aa:bb::1]:53412");
        let mut out = Vec::new();
        encode_xor(peer, transaction(), &mut out);
        assert_eq!(decode_xor(&out, transaction()), Some(peer));

        // the last twelve bytes are masked with the transaction id, so a
        // different transaction reads a different address out of the same
        // bytes
        let other = TransactionId::new([0; 12]);
        assert_ne!(decode_xor(&out, other), Some(peer));
    }

    #[test]
    fn the_family_byte_stays_in_the_clear() {
        let mut plain = Vec::new();
        let mut masked = Vec::new();
        encode(address("198.51.100.7:1"), &mut plain);
        encode_xor(address("198.51.100.7:1"), transaction(), &mut masked);
        assert_eq!(plain[..2], masked[..2]);
    }

    #[test]
    fn a_length_that_disagrees_with_the_family_is_refused() {
        assert!(!is_valid(&[0, 1, 0, 0, 1, 2, 3]));
        assert!(!is_valid(&[0, 1, 0, 0, 1, 2, 3, 4, 5]));
        assert!(!is_valid(&[0, 2, 0, 0, 1, 2, 3, 4]));
        assert!(is_valid(&[0, 1, 0, 0, 1, 2, 3, 4]));
    }

    #[test]
    fn a_family_nobody_defined_is_refused() {
        assert!(!is_valid(&[0, 0, 0, 0, 1, 2, 3, 4]));
        assert!(!is_valid(&[0, 3, 0, 0, 1, 2, 3, 4]));
        assert_eq!(decode(&[0, 3, 0, 0, 1, 2, 3, 4]), None);
        assert_eq!(decode_xor(&[0, 3, 0, 0, 1, 2, 3, 4], transaction()), None);
    }

    #[test]
    fn nothing_at_all_is_refused() {
        assert!(!is_valid(&[]));
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0]), None);
    }

    #[test]
    fn the_zero_port_and_the_broadcast_address_still_round_trip() {
        for text in ["0.0.0.0:0", "255.255.255.255:65535", "[::]:0"] {
            let peer = address(text);
            let mut out = Vec::new();
            encode_xor(peer, transaction(), &mut out);
            assert_eq!(decode_xor(&out, transaction()), Some(peer), "{text}");
        }
    }
}
