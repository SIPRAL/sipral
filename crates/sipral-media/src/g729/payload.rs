// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What one RTP payload of G.729 holds, read from its length.
//!
//! RFC 3551 §4.5.6: "A G729 RTP packet may consist of zero or more G.729 or
//! G.729 Annex A frames, followed by zero or one G.729 Annex B frames. The
//! presence of a comfort noise frame can be deduced from the length of the
//! RTP payload." A speech frame is ten octets and an Annex B frame — the
//! silence insertion descriptor, SID — is two, so a payload is ten octets a
//! frame and, at the end, two more or none. Any other length is not a
//! payload of this codec.
//!
//! The SID frame is read here as far as Annex B's bit stream describes it
//! (Table B.2, and RFC 3551's figure 5 for where the bits sit): a switched
//! predictor bit, a first-stage index of five bits and a second-stage index
//! of four for the noise's spectrum, then five bits for its energy, and a
//! reserved bit. What the energy index means is B.4.2.1's quantizer, which
//! the text states in full, so that much is decoded; the spectrum and the
//! comfort-noise generator of B.4.4 are not, and a caller that meets a SID
//! frame decides for itself what to play in the pause it announces.

use super::FRAME_OCTETS;

/// Octets in an Annex B SID frame.
pub const SID_OCTETS: usize = 2;

/// One RTP payload, cut into its speech frames and its SID frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payload<'a> {
    frames: &'a [u8],
    sid: Option<Sid>,
}

impl<'a> Payload<'a> {
    /// Cut `octets` into ten-octet frames and, if two octets are left, a
    /// SID frame. `None` when anything else is left over: a payload of
    /// thirteen octets is no arrangement RFC 3551 allows, and decoding the
    /// frame in it would be decoding a guess.
    #[must_use]
    pub fn parse(octets: &'a [u8]) -> Option<Self> {
        let whole = octets.len() / FRAME_OCTETS * FRAME_OCTETS;
        let (frames, rest) = octets.split_at_checked(whole)?;
        let sid = match *rest {
            [] => None,
            [first, second] => Some(Sid::from_octets([first, second])),
            _ => return None,
        };
        Some(Self { frames, sid })
    }

    /// The speech frames, in order: the octets
    /// [`Decoder::decode_into`](super::Decoder::decode_into) takes.
    #[must_use]
    pub const fn speech(&self) -> &'a [u8] {
        self.frames
    }

    /// How many speech frames there are.
    #[must_use]
    pub const fn frame_count(&self) -> usize {
        self.frames.len() / FRAME_OCTETS
    }

    /// The SID frame at the end, if the payload carries one.
    #[must_use]
    pub const fn sid(&self) -> Option<Sid> {
        self.sid
    }
}

/// An Annex B SID frame: the far end has gone quiet, and this describes the
/// noise it would have heard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sid([u8; SID_OCTETS]);

impl Sid {
    /// The frame, as the two octets it arrived in.
    #[must_use]
    pub const fn from_octets(octets: [u8; SID_OCTETS]) -> Self {
        Self(octets)
    }

    /// The two octets.
    #[must_use]
    pub const fn octets(self) -> [u8; SID_OCTETS] {
        self.0
    }

    /// The energy index, `0..=31`: the last five of the fifteen bits Table
    /// B.2 lays out, before the reserved bit.
    #[must_use]
    pub const fn energy_index(self) -> u8 {
        (self.0[1] >> 1) & 0x1f
    }

    /// What the energy index quantizes, in decibels (B.4.2.1): a single
    /// level of −12 below −4, steps of four from −4 up to 16, and steps of
    /// two from 16 up to 66. Every level is an even number of decibels.
    #[must_use]
    pub const fn energy_db(self) -> i8 {
        // three index ranges, the last two starting where the one before
        // stopped; `index` is at most 31, so none of the arithmetic is near
        // the end of an i8
        let index = self.energy_index().cast_signed();
        match index {
            0 => -12,
            1..=6 => -4 + 4 * (index - 1),
            _ => 16 + 2 * (index - 6),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Payload, SID_OCTETS, Sid};

    #[test]
    fn a_payload_is_whole_frames_and_perhaps_one_sid() {
        let two = [7_u8; 20];
        let parsed = Payload::parse(&two).expect("two frames");
        assert_eq!(parsed.frame_count(), 2);
        assert_eq!(parsed.speech().len(), 20);
        assert_eq!(parsed.sid(), None);

        let with_sid: Vec<u8> = [7_u8; 10].into_iter().chain([0x12, 0x34]).collect();
        let parsed = Payload::parse(&with_sid).expect("a frame and a SID");
        assert_eq!(parsed.frame_count(), 1);
        assert_eq!(parsed.sid().map(Sid::octets), Some([0x12, 0x34]));

        let alone = Payload::parse(&[0x12, 0x34]).expect("a SID alone");
        assert_eq!(alone.frame_count(), 0);
        assert!(alone.sid().is_some());

        assert_eq!(Payload::parse(&[]).map(|p| p.frame_count()), Some(0));
    }

    #[test]
    fn any_other_length_is_refused() {
        for length in [1, 3, 9, 11, 13, 19, 21, 25] {
            assert!(
                Payload::parse(&vec![0_u8; length]).is_none(),
                "{length} octets"
            );
        }
        assert_eq!(SID_OCTETS, 2);
    }

    /// B.4.2.1's levels, end to end: thirty-two of them, rising, from −12 to
    /// 66, four apart up to 16 and two apart after it.
    #[test]
    fn the_energy_levels_are_b_4_2_1s() {
        let levels: Vec<i8> = (0..32_u8)
            .map(|index| Sid::from_octets([0, index << 1]).energy_db())
            .collect();
        assert_eq!(levels.first(), Some(&-12));
        assert_eq!(levels.get(1), Some(&-4));
        assert_eq!(levels.get(6), Some(&16));
        assert_eq!(levels.get(7), Some(&18));
        assert_eq!(levels.last(), Some(&66));
        for pair in levels.windows(2) {
            let step = pair.get(1).zip(pair.first()).map(|(b, a)| b - a);
            assert!(matches!(step, Some(2 | 4 | 8)), "{pair:?}");
        }
        assert!(levels.iter().all(|db| db % 2 == 0));
    }

    /// The reserved bit and the spectrum's ten bits do not reach the energy.
    #[test]
    fn the_energy_is_the_five_bits_before_the_reserved_one() {
        let sid = Sid::from_octets([0xff, 0b1100_0001]);
        assert_eq!(sid.energy_index(), 0b0_0000);
        let sid = Sid::from_octets([0x00, 0b0011_1110]);
        assert_eq!(sid.energy_index(), 0b1_1111);
    }
}
