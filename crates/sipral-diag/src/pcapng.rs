// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A minimal pcapng writer: one section, one Ethernet interface, and one
//! Enhanced Packet Block per packet, optionally with a direction.

const SECTION_HEADER_BLOCK: u32 = 0x0A0D_0D0A;
const INTERFACE_DESCRIPTION_BLOCK: u32 = 0x0000_0001;
const ENHANCED_PACKET_BLOCK: u32 = 0x0000_0006;
const EPB_FLAGS: u16 = 2;
/// Says the file is little-endian.
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const LINKTYPE_ETHERNET: u16 = 1;

/// Which way a packet went, as `epb_flags` spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Received by the end the capture is made at.
    Inbound = 1,
    /// Sent by it.
    Outbound = 2,
}

/// Builds a pcapng byte stream, one packet at a time.
///
/// Timestamps are microseconds since an arbitrary origin (pcapng's default
/// resolution), not wall-clock time.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A writer with its section and interface blocks already in place.
    #[must_use]
    pub fn new() -> Self {
        let mut writer = Self { buf: Vec::new() };
        writer.section_header();
        writer.interface_description();
        writer
    }

    /// One packet, captured whole, at `timestamp_us` microseconds since the
    /// writer's origin.
    pub fn packet(&mut self, timestamp_us: u64, data: &[u8]) {
        let body = Self::packet_body(timestamp_us, data);
        self.block(ENHANCED_PACKET_BLOCK, &body);
    }

    /// The same, with the direction in `epb_flags` (pcapng §4.3.1), which
    /// Wireshark filters on as `frame.packet_flags_direction`.
    pub fn packet_in(&mut self, timestamp_us: u64, data: &[u8], direction: Direction) {
        let mut body = Self::packet_body(timestamp_us, data);
        // options start on a 32-bit boundary after the padded packet data
        body.resize(body.len() + (4 - data.len() % 4) % 4, 0);
        body.extend_from_slice(&EPB_FLAGS.to_le_bytes());
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&(direction as u32).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt
        body.extend_from_slice(&0u16.to_le_bytes());
        self.block(ENHANCED_PACKET_BLOCK, &body);
    }

    fn packet_body(timestamp_us: u64, data: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(20 + data.len() + 16);
        body.extend_from_slice(&0u32.to_le_bytes()); // interface id: the one IDB above
        let high = u32::try_from(timestamp_us >> 32).unwrap_or(u32::MAX);
        let low = u32::try_from(timestamp_us & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        body.extend_from_slice(&high.to_le_bytes());
        body.extend_from_slice(&low.to_le_bytes());
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        body.extend_from_slice(&len.to_le_bytes()); // captured length
        body.extend_from_slice(&len.to_le_bytes()); // original length
        body.extend_from_slice(data);
        body
    }

    /// The finished file.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn section_header(&mut self) {
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // major version
        body.extend_from_slice(&0u16.to_le_bytes()); // minor version
        body.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
        self.block(SECTION_HEADER_BLOCK, &body);
    }

    fn interface_description(&mut self) {
        let mut body = Vec::with_capacity(8);
        body.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // snaplen: unlimited
        self.block(INTERFACE_DESCRIPTION_BLOCK, &body);
    }

    /// Type, total length, padded body, total length again (RFC 9199 §3.1).
    fn block(&mut self, block_type: u32, body: &[u8]) {
        let pad = (4 - body.len() % 4) % 4;
        let total_len = 12 + body.len() + pad;
        let total_len_field = u32::try_from(total_len).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&block_type.to_le_bytes());
        self.buf.extend_from_slice(&total_len_field.to_le_bytes());
        self.buf.extend_from_slice(body);
        self.buf.resize(self.buf.len() + pad, 0);
        self.buf.extend_from_slice(&total_len_field.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::Writer;

    #[test]
    fn a_fresh_writer_holds_the_section_and_interface_blocks_and_nothing_else() {
        let bytes = Writer::new().finish();
        // SHB 12 + 16, IDB 12 + 8
        assert_eq!(bytes.len(), 28 + 20);
        assert_eq!(
            bytes.get(0..4),
            Some(0x0A0D_0D0Au32.to_le_bytes().as_slice())
        );
        assert_eq!(
            bytes.get(28..32),
            Some(0x0000_0001u32.to_le_bytes().as_slice())
        );
    }

    #[test]
    fn a_packet_block_pads_its_body_to_four_bytes_and_repeats_its_length() {
        let mut writer = Writer::new();
        let before = writer.buf.len();
        writer.packet(0, b"abc"); // 20-byte header + 3-byte payload = 23, padded to 24
        let block = writer.buf.get(before..).expect("the block just written");
        let total = 12 + 24;
        assert_eq!(block.len(), total);
        let total32 = u32::try_from(total).expect("small enough for a test fixture");
        assert_eq!(
            block.get(0..4),
            Some(0x0000_0006u32.to_le_bytes().as_slice())
        );
        assert_eq!(block.get(4..8), Some(total32.to_le_bytes().as_slice()));
        assert_eq!(
            block.get(block.len() - 4..),
            Some(total32.to_le_bytes().as_slice())
        );
    }

    #[test]
    fn timestamps_split_across_the_high_and_low_halves() {
        let mut writer = Writer::new();
        let before = writer.buf.len();
        let ts: u64 = 0x0001_0203_0405_0607;
        writer.packet(ts, b"x");
        // type, total length, interface id
        let body = writer.buf.get(before + 12..).expect("the timestamp fields");
        let high_bytes: [u8; 4] = body
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .expect("4 bytes");
        let low_bytes: [u8; 4] = body
            .get(4..8)
            .and_then(|s| s.try_into().ok())
            .expect("4 bytes");
        let high = u32::from_le_bytes(high_bytes);
        let low = u32::from_le_bytes(low_bytes);
        assert_eq!(u64::from(high) << 32 | u64::from(low), ts);
    }
}
