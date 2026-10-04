// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A synthetic Ethernet frame around one UDP or TCP segment, for a pcapng
//! packet that Wireshark's transport and SIP dissectors will both read.
//!
//! Two made-up MAC addresses are all the link layer is here for — nothing
//! reads them — and the checksums are real ones, computed the way RFC 791
//! §3.1 and RFC 793/RFC 768 say to, so a reader that checks them finds
//! nothing wrong with the packet.
//!
//! Every header is built by appending fields in order rather than indexing
//! into a fixed buffer: the workspace denies `clippy::indexing_slicing`, and
//! a checksum that has to be written back into the middle of what it was
//! computed over is instead computed once with the checksum field at zero —
//! which is what the algorithm asks for anyway — and the header built a
//! second time with the real value already in place.

use std::net::{Ipv4Addr, Ipv6Addr};

/// `ETHERTYPE_IP`.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// `ETHERTYPE_IPV6`.
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// UDP's IP protocol number.
const PROTO_UDP: u8 = 17;
/// TCP's IP protocol number.
const PROTO_TCP: u8 = 6;

fn ethernet_header(ethertype: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(14);
    header.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // destination
    header.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // source
    header.extend_from_slice(&ethertype.to_be_bytes());
    header
}

/// The Internet checksum (RFC 1071): the one's complement of the one's
/// complement sum of 16-bit words, used unchanged for an IPv4 header and,
/// over a different span of bytes, for a UDP or TCP segment.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        if let [a, b] = *chunk {
            sum += u32::from(u16::from_be_bytes([a, b]));
        }
    }
    if let [last] = *chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

fn ipv4_header_fields(
    total_len: u16,
    ident: u16,
    protocol: u8,
    checksum: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Vec<u8> {
    let mut ip = Vec::with_capacity(20);
    ip.push(0x45); // version 4, 5 32-bit words, no options
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&ident.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    ip.push(64); // TTL
    ip.push(protocol);
    ip.extend_from_slice(&checksum.to_be_bytes());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip
}

fn ipv4_header(total_len: u16, ident: u16, protocol: u8, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let probe = ipv4_header_fields(total_len, ident, protocol, 0, src, dst);
    let checksum = internet_checksum(&probe);
    ipv4_header_fields(total_len, ident, protocol, checksum, src, dst)
}

fn ipv4_pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, upper_len: u16) -> Vec<u8> {
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&upper_len.to_be_bytes());
    pseudo
}

fn ipv6_header(payload_len: u16, next_header: u8, src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    let mut ip = Vec::with_capacity(40);
    ip.push(0x60); // version 6, traffic class and flow label left zero
    ip.push(0x00);
    ip.push(0x00);
    ip.push(0x00);
    ip.extend_from_slice(&payload_len.to_be_bytes());
    ip.push(next_header);
    ip.push(64); // hop limit
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip
}

fn ipv6_pseudo_header(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, upper_len: u32) -> Vec<u8> {
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&upper_len.to_be_bytes());
    pseudo.push(0);
    pseudo.push(0);
    pseudo.push(0);
    pseudo.push(next_header);
    pseudo
}

fn udp_fields(sport: u16, dport: u16, checksum: u16, payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&len.to_be_bytes());
    udp.extend_from_slice(&checksum.to_be_bytes());
    udp.extend_from_slice(payload);
    udp
}

fn tcp_fields(sport: u16, dport: u16, seq: u32, checksum: u16, payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack: this side is never modelled
    tcp.push(0x50); // data offset: 5 32-bit words, no options
    tcp.push(0x18); // PSH | ACK
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&checksum.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    tcp.extend_from_slice(payload);
    tcp
}

/// RFC 768: a UDP checksum that comes out to exactly zero is sent as
/// all-ones, because zero already means "no checksum was computed" on the
/// wire.
fn udp_checksum_on_wire(computed: u16) -> u16 {
    if computed == 0 { 0xFFFF } else { computed }
}

/// An Ethernet frame carrying one IPv4 UDP datagram from `src` to `dst`.
#[must_use]
pub fn ipv4_udp(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    payload: &[u8],
    ident: u16,
) -> Vec<u8> {
    let probe = udp_fields(sport, dport, 0, payload);
    let pseudo = ipv4_pseudo_header(
        src,
        dst,
        PROTO_UDP,
        u16::try_from(probe.len()).unwrap_or(u16::MAX),
    );
    let mut for_checksum = pseudo;
    for_checksum.extend_from_slice(&probe);
    let checksum = udp_checksum_on_wire(internet_checksum(&for_checksum));
    let udp = udp_fields(sport, dport, checksum, payload);

    let total_len = u16::try_from(20 + udp.len()).unwrap_or(u16::MAX);
    let ip = ipv4_header(total_len, ident, PROTO_UDP, src, dst);
    frame(ETHERTYPE_IPV4, &ip, &udp)
}

/// An Ethernet frame carrying one IPv6 UDP datagram from `src` to `dst`.
#[must_use]
pub fn ipv6_udp(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let probe = udp_fields(sport, dport, 0, payload);
    let pseudo = ipv6_pseudo_header(
        src,
        dst,
        PROTO_UDP,
        u32::try_from(probe.len()).unwrap_or(u32::MAX),
    );
    let mut for_checksum = pseudo;
    for_checksum.extend_from_slice(&probe);
    // RFC 8200 §8.1: a UDP checksum over IPv6 is mandatory and is never
    // transmitted as zero, unlike RFC 768's IPv4 allowance
    let checksum = udp_checksum_on_wire(internet_checksum(&for_checksum));
    let udp = udp_fields(sport, dport, checksum, payload);

    let payload_len = u16::try_from(udp.len()).unwrap_or(u16::MAX);
    let ip = ipv6_header(payload_len, PROTO_UDP, src, dst);
    frame(ETHERTYPE_IPV6, &ip, &udp)
}

/// An Ethernet frame carrying one IPv4 TCP segment from `src` to `dst`,
/// starting at sequence number `seq`.
#[must_use]
pub fn ipv4_tcp(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    payload: &[u8],
    ident: u16,
    seq: u32,
) -> Vec<u8> {
    let probe = tcp_fields(sport, dport, seq, 0, payload);
    let pseudo = ipv4_pseudo_header(
        src,
        dst,
        PROTO_TCP,
        u16::try_from(probe.len()).unwrap_or(u16::MAX),
    );
    let mut for_checksum = pseudo;
    for_checksum.extend_from_slice(&probe);
    let checksum = internet_checksum(&for_checksum);
    let tcp = tcp_fields(sport, dport, seq, checksum, payload);

    let total_len = u16::try_from(20 + tcp.len()).unwrap_or(u16::MAX);
    let ip = ipv4_header(total_len, ident, PROTO_TCP, src, dst);
    frame(ETHERTYPE_IPV4, &ip, &tcp)
}

/// An Ethernet frame carrying one IPv6 TCP segment from `src` to `dst`,
/// starting at sequence number `seq`.
#[must_use]
pub fn ipv6_tcp(
    src: Ipv6Addr,
    sport: u16,
    dst: Ipv6Addr,
    dport: u16,
    payload: &[u8],
    seq: u32,
) -> Vec<u8> {
    let probe = tcp_fields(sport, dport, seq, 0, payload);
    let pseudo = ipv6_pseudo_header(
        src,
        dst,
        PROTO_TCP,
        u32::try_from(probe.len()).unwrap_or(u32::MAX),
    );
    let mut for_checksum = pseudo;
    for_checksum.extend_from_slice(&probe);
    let checksum = internet_checksum(&for_checksum);
    let tcp = tcp_fields(sport, dport, seq, checksum, payload);

    let payload_len = u16::try_from(tcp.len()).unwrap_or(u16::MAX);
    let ip = ipv6_header(payload_len, PROTO_TCP, src, dst);
    frame(ETHERTYPE_IPV6, &ip, &tcp)
}

fn frame(ethertype: u16, ip: &[u8], upper: &[u8]) -> Vec<u8> {
    let mut out = ethernet_header(ethertype);
    out.extend_from_slice(ip);
    out.extend_from_slice(upper);
    out
}

#[cfg(test)]
mod tests {
    use super::{internet_checksum, ipv4_tcp, ipv4_udp, ipv6_udp};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn an_ipv4_udp_frame_has_the_right_shape_and_a_valid_header_checksum() {
        let payload = b"REGISTER sip:example.com SIP/2.0\r\n";
        let frame = ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 9),
            5060,
            Ipv4Addr::new(192, 0, 2, 1),
            5060,
            payload,
            7,
        );
        assert_eq!(frame.len(), 14 + 20 + 8 + payload.len());
        assert_eq!(frame.get(12..14), Some(0x0800u16.to_be_bytes().as_slice()));
        let ip = frame.get(14..34).expect("an IPv4 header");
        // a correct IPv4 header checksum makes the whole header sum to zero
        assert_eq!(internet_checksum(ip), 0);
        assert_eq!(ip.get(16..20), Some([192, 0, 2, 1].as_slice()));
        let udp = frame.get(34..).expect("a UDP segment");
        assert_eq!(udp.get(0..2), Some(5060u16.to_be_bytes().as_slice()));
        assert_eq!(udp.get(8..), Some(payload.as_slice()));
    }

    #[test]
    fn an_ipv6_udp_frame_never_carries_a_zero_checksum() {
        let frame = ipv6_udp(
            "2001:db8::1".parse().unwrap_or(Ipv6Addr::UNSPECIFIED),
            5060,
            "2001:db8::2".parse().unwrap_or(Ipv6Addr::UNSPECIFIED),
            5060,
            b"x",
        );
        let udp_checksum = frame.get(14 + 40 + 6..14 + 40 + 8);
        assert_ne!(udp_checksum, Some([0, 0].as_slice()));
    }

    #[test]
    fn a_tcp_frame_carries_the_sequence_number_it_was_given() {
        let frame = ipv4_tcp(
            Ipv4Addr::new(192, 0, 2, 9),
            5060,
            Ipv4Addr::new(192, 0, 2, 1),
            5060,
            b"y",
            1,
            1000,
        );
        let tcp = frame.get(34..).expect("a TCP segment");
        assert_eq!(tcp.get(4..8), Some(1000u32.to_be_bytes().as_slice()));
    }
}
