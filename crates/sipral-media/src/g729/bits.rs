// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The eighty bits of a frame (§4, Table 8).
//!
//! Fifteen indices in a fixed order, each sent most significant bit first
//! (Table 8's note), which fills ten octets exactly. RFC 3551 §4.5.6 carries
//! them in an RTP payload in the same order, first bit in the top of the
//! first octet, so the octets here are the octets on the wire.

/// The widths of Table 8's fifteen fields, in the order they are sent.
const WIDTHS: [u32; 15] = [1, 7, 5, 5, 8, 1, 13, 4, 3, 4, 5, 13, 4, 3, 4];

/// One subframe's share of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Subframe {
    /// `P1` or `P2`: the adaptive-codebook delay, eight bits absolute in the
    /// first subframe and five relative in the second.
    pub(super) delay: u16,
    /// `C1` or `C2`: the four pulse positions, thirteen bits (equation 62).
    pub(super) positions: u16,
    /// `S1` or `S2`: the four pulse signs (equation 61).
    pub(super) signs: u16,
    /// `GA1` or `GA2`.
    pub(super) ga: u16,
    /// `GB1` or `GB2`.
    pub(super) gb: u16,
}

/// Every index of Table 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Frame {
    /// `L0`: which MA predictor.
    pub(super) predictor: u16,
    /// `L1`, `L2`, `L3`: the rows of the three LSP codebooks.
    pub(super) first_stage: u16,
    pub(super) second_low: u16,
    pub(super) second_high: u16,
    /// `P0`: the parity bit over `P1`.
    pub(super) parity: u16,
    pub(super) subframes: [Subframe; 2],
}

impl Frame {
    /// Read the indices out of ten octets.
    pub(super) fn unpack(octets: &[u8; 10]) -> Self {
        let mut reader = Reader {
            octets,
            position: 0,
        };
        let mut fields = [0_u16; 15];
        for (field, width) in fields.iter_mut().zip(WIDTHS) {
            *field = reader.take(width);
        }
        let [
            predictor,
            first_stage,
            second_low,
            second_high,
            delay1,
            parity,
            positions1,
            signs1,
            ga1,
            gb1,
            delay2,
            positions2,
            signs2,
            ga2,
            gb2,
        ] = fields;
        Self {
            predictor,
            first_stage,
            second_low,
            second_high,
            parity,
            subframes: [
                Subframe {
                    delay: delay1,
                    positions: positions1,
                    signs: signs1,
                    ga: ga1,
                    gb: gb1,
                },
                Subframe {
                    delay: delay2,
                    positions: positions2,
                    signs: signs2,
                    ga: ga2,
                    gb: gb2,
                },
            ],
        }
    }

    /// Write the indices into ten octets, each field masked to its width.
    pub(super) fn pack(&self) -> [u8; 10] {
        let [a, b] = self.subframes;
        let fields = [
            self.predictor,
            self.first_stage,
            self.second_low,
            self.second_high,
            a.delay,
            self.parity,
            a.positions,
            a.signs,
            a.ga,
            a.gb,
            b.delay,
            b.positions,
            b.signs,
            b.ga,
            b.gb,
        ];
        let mut octets = [0_u8; 10];
        let mut position = 0_u32;
        for (field, width) in fields.into_iter().zip(WIDTHS) {
            for bit in (0..width).rev() {
                if (field >> bit) & 1 == 1 {
                    let octet = usize::try_from(position / 8).unwrap_or(0);
                    if let Some(slot) = octets.get_mut(octet) {
                        *slot |= 0x80 >> (position % 8);
                    }
                }
                position += 1;
            }
        }
        octets
    }

    /// Whether `P0` agrees with `P1` (§3.7.2, §4.1.2).
    ///
    /// The text says the parity bit is "generated through an XOR operation
    /// on the six most significant bits of P1", without saying what the XOR
    /// starts from. The conformance streams settle it: read as a plain XOR,
    /// every frame of every stream fails, bar four in five of the one made to
    /// test the check; read as an XOR that starts from one, no frame fails
    /// except exactly every fifth frame of that stream. So a frame passes
    /// when `P0` and the six bits together hold an odd number of ones.
    pub(super) fn parity_holds(&self) -> bool {
        let [first, _] = self.subframes;
        let ones = ((first.delay >> 2) & 0x3f).count_ones() + u32::from(self.parity & 1);
        ones % 2 == 1
    }

    /// `P0` for a first subframe's delay codeword `P1`: the bit that makes
    /// the ones among it and `P1`'s six most significant bits odd, as
    /// [`Frame::parity_holds`] checks.
    pub(super) fn parity_of(delay: u16) -> u16 {
        u16::from(((delay >> 2) & 0x3f).count_ones().is_multiple_of(2))
    }
}

/// Bits read most significant first across octet boundaries.
struct Reader<'a> {
    octets: &'a [u8; 10],
    position: u32,
}

impl Reader<'_> {
    fn take(&mut self, width: u32) -> u16 {
        let mut value = 0_u16;
        for _ in 0..width {
            let octet = usize::try_from(self.position / 8).unwrap_or(0);
            let byte = self.octets.get(octet).copied().unwrap_or(0);
            let bit = (byte >> (7 - self.position % 8)) & 1;
            value = (value << 1) | u16::from(bit);
            self.position += 1;
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, Subframe, WIDTHS};

    #[test]
    fn the_fields_fill_eighty_bits() {
        assert_eq!(WIDTHS.iter().sum::<u32>(), 80);
    }

    #[test]
    fn a_frame_survives_packing_and_unpacking() {
        let frame = Frame {
            predictor: 1,
            first_stage: 0x55,
            second_low: 0x13,
            second_high: 0x0a,
            parity: 1,
            subframes: [
                Subframe {
                    delay: 0xa7,
                    positions: 0x1abc,
                    signs: 0x9,
                    ga: 0x5,
                    gb: 0xc,
                },
                Subframe {
                    delay: 0x11,
                    positions: 0x0123,
                    signs: 0x6,
                    ga: 0x2,
                    gb: 0x3,
                },
            ],
        };
        assert_eq!(Frame::unpack(&frame.pack()), frame);
    }

    #[test]
    fn the_first_bit_sent_is_the_top_of_the_first_octet() {
        let mut octets = [0_u8; 10];
        octets[0] = 0x80;
        let frame = Frame::unpack(&octets);
        assert_eq!(frame.predictor, 1);
        assert_eq!(frame.first_stage, 0);

        // and the last is the bottom of the tenth: GB2's least significant bit
        let mut octets = [0_u8; 10];
        octets[9] = 0x01;
        assert_eq!(Frame::unpack(&octets).subframes[1].gb, 1);
    }

    #[test]
    fn every_field_lands_where_table_8_puts_it() {
        let octets = [0xff_u8; 10];
        let frame = Frame::unpack(&octets);
        assert_eq!(frame.first_stage, 0x7f);
        assert_eq!(frame.subframes[0].delay, 0xff);
        assert_eq!(frame.subframes[0].positions, 0x1fff);
        assert_eq!(frame.subframes[1].delay, 0x1f);
        assert_eq!(frame.subframes[1].gb, 0xf);
    }

    #[test]
    fn parity_is_odd_over_the_six_top_bits_of_p1_and_p0() {
        let mut frame = Frame::default();
        // no ones among the six bits: the parity bit must be one
        frame.subframes[0].delay = 0b0000_0011;
        frame.parity = 1;
        assert!(frame.parity_holds());
        frame.parity = 0;
        assert!(!frame.parity_holds());
        // one one among them: the parity bit must be zero
        frame.subframes[0].delay = 0b1000_0000;
        assert!(frame.parity_holds());
    }
}
