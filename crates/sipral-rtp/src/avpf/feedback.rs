// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Feedback messages on the wire (RFC 4585 §6): the common packet format
//! every one of them shares (§6.1) and the one an audio stream has a use
//! for, the Generic NACK (§6.2.1).
//!
//! Reading borrows from the datagram, the same as [`crate::CompoundPacket`];
//! building writes into a buffer the caller supplies.

use core::fmt;

use crate::wire::{VERSION, put};

/// The packet type of a transport layer feedback message (RFC 4585 §6.1).
pub const RTPFB: u8 = 205;
/// The packet type of a payload-specific feedback message (RFC 4585 §6.1).
/// Every format defined for it concerns pictures, so it is only ever walked
/// past here.
pub const PSFB: u8 = 206;
/// The FMT value of a Generic NACK inside an [`RTPFB`] packet (§6.2.1).
pub const FMT_GENERIC_NACK: u8 = 1;

/// Octets in the fixed part every feedback message starts with: the RTCP
/// header, the SSRC of the packet sender and the SSRC of the media source
/// (§6.1).
pub(super) const COMMON_LEN: usize = 12;
/// Octets in one Generic NACK entry: PID and BLP (§6.2.1).
const NACK_ENTRY_LEN: usize = 4;
/// Octets in the RTCP header proper.
pub(super) const HEADER_LEN: usize = 4;
/// A 32-bit word, what the RTCP length field counts in.
const WORD_LEN: usize = 4;
/// The most words the 16-bit length field can describe, header included.
const MAX_WORDS: usize = 1 << 16;
/// Bits in a BLP: the sixteen sequence numbers after the PID (§6.2.1).
const BLP_BITS: u16 = 16;

/// One Generic NACK entry (RFC 4585 §6.2.1): a lost packet and a bitmask of
/// the sixteen that follow it.
///
/// "If bit i of BLP is set to 1, the receiver has not received RTP packet
/// number (PID+i) (modulo 2^16)", where the least significant bit is bit
/// one. A clear bit says nothing: the sender "MUST NOT assume that a
/// receiver has received a packet because its bit was set to 0".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NackEntry {
    /// The sequence number of a lost packet.
    pub pid: u16,
    /// Which of the sixteen packets after `pid` were lost as well.
    pub blp: u16,
}

impl NackEntry {
    /// An entry naming `pid` alone.
    #[must_use]
    pub const fn new(pid: u16) -> Self {
        Self { pid, blp: 0 }
    }

    /// Every sequence number this entry reports lost: the PID, then those
    /// the BLP marks, in increasing order modulo 2^16.
    pub fn lost(&self) -> impl Iterator<Item = u16> + use<> {
        let Self { pid, blp } = *self;
        core::iter::once(pid).chain(
            (1..=BLP_BITS)
                .filter(move |bit| blp & (1 << (bit - 1)) != 0)
                .map(move |bit| pid.wrapping_add(bit)),
        )
    }

    /// Mark `seq` lost too, when it is one of the sixteen after the PID;
    /// `false` when it is not and so needs an entry of its own. The PID
    /// itself is already covered.
    fn cover(&mut self, seq: u16) -> bool {
        let distance = seq.wrapping_sub(self.pid);
        if distance == 0 {
            return true;
        }
        if distance > BLP_BITS {
            return false;
        }
        self.blp |= 1 << (distance - 1);
        true
    }

    /// Pack lost sequence numbers into as few entries as the order they
    /// arrive in allows.
    ///
    /// Each number either falls within the sixteen after the current
    /// entry's PID, and sets its bit there, or starts a new entry. Numbers in
    /// increasing order modulo 2^16 — which is the order a receiver finds
    /// gaps in, including across the wrap from 65535 to 0 — pack as tightly
    /// as §6.2.1 permits; any other order still reports every number, only
    /// in more entries. A repeat of a number already reported adds nothing.
    #[must_use]
    pub fn pack(lost: impl IntoIterator<Item = u16>) -> Vec<Self> {
        let mut entries: Vec<Self> = Vec::new();
        for seq in lost {
            if entries.iter().any(|entry| entry.lost().any(|s| s == seq)) {
                continue;
            }
            let covered = entries.last_mut().is_some_and(|entry| entry.cover(seq));
            if !covered {
                entries.push(Self::new(seq));
            }
        }
        entries
    }
}

/// A Generic NACK as read off the wire (RFC 4585 §6.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericNack<'a> {
    sender_ssrc: u32,
    media_ssrc: u32,
    fci: &'a [u8],
}

impl<'a> GenericNack<'a> {
    /// Whoever sent the feedback.
    #[must_use]
    pub const fn sender_ssrc(&self) -> u32 {
        self.sender_ssrc
    }

    /// The source whose packets it reports lost.
    #[must_use]
    pub const fn media_ssrc(&self) -> u32 {
        self.media_ssrc
    }

    /// The entries, in the order they were written. There is at least one:
    /// the FCI "MUST contain at least one" (§6.2.1), and parsing refuses a
    /// NACK without.
    #[must_use]
    pub fn entries(&self) -> NackEntries<'a> {
        NackEntries { rest: self.fci }
    }

    /// Every sequence number reported lost, entry by entry.
    pub fn lost(&self) -> impl Iterator<Item = u16> + use<'a> {
        self.entries().flat_map(|entry| entry.lost())
    }
}

/// The entries of a [`GenericNack`].
#[derive(Clone, Debug)]
pub struct NackEntries<'a> {
    rest: &'a [u8],
}

impl Iterator for NackEntries<'_> {
    type Item = NackEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let (&[p0, p1, b0, b1], rest) = self.rest.split_first_chunk::<NACK_ENTRY_LEN>()?;
        self.rest = rest;
        Some(NackEntry {
            pid: u16::from_be_bytes([p0, p1]),
            blp: u16::from_be_bytes([b0, b1]),
        })
    }
}

/// One feedback message (RFC 4585 §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackPacket<'a> {
    /// A Generic NACK (§6.2.1).
    GenericNack(GenericNack<'a>),
    /// Any other transport layer or payload-specific message: none of them
    /// concerns audio, and "an implementation SHOULD ignore incoming RTCP
    /// packets with types unknown to it" (RFC 3550 §6.1), so only what
    /// identifies it is kept.
    Other {
        /// [`RTPFB`] or [`PSFB`].
        packet_type: u8,
        /// The feedback message type.
        fmt: u8,
        /// Whoever sent the feedback.
        sender_ssrc: u32,
        /// The source it is about.
        media_ssrc: u32,
    },
}

impl<'a> FeedbackPacket<'a> {
    /// Whether an individual RTCP packet of this type is a feedback message.
    #[must_use]
    pub const fn is_feedback(packet_type: u8) -> bool {
        packet_type == RTPFB || packet_type == PSFB
    }

    /// Parse one individual feedback packet, header included, exactly as
    /// long as its length field says.
    ///
    /// # Errors
    /// [`FeedbackError`], naming what is missing or inconsistent.
    pub fn parse(packet: &'a [u8]) -> Result<Self, FeedbackError> {
        let Some((head, rest)) = packet.split_first_chunk::<HEADER_LEN>() else {
            return Err(FeedbackError::TooShort { got: packet.len() });
        };
        let [flags, packet_type, _, _] = *head;
        let version = flags >> 6;
        if version != VERSION {
            return Err(FeedbackError::Version(version));
        }
        if !Self::is_feedback(packet_type) {
            return Err(FeedbackError::NotFeedback(packet_type));
        }
        let fmt = flags & 0b0001_1111;
        let body = strip_padding(rest, flags & 0b0010_0000 != 0)?;
        let Some((sender, rest)) = body.split_first_chunk::<4>() else {
            return Err(FeedbackError::TooShort { got: packet.len() });
        };
        let Some((media, fci)) = rest.split_first_chunk::<4>() else {
            return Err(FeedbackError::TooShort { got: packet.len() });
        };
        let sender_ssrc = u32::from_be_bytes(*sender);
        let media_ssrc = u32::from_be_bytes(*media);
        if packet_type == RTPFB && fmt == FMT_GENERIC_NACK {
            if fci.is_empty() || !fci.len().is_multiple_of(NACK_ENTRY_LEN) {
                return Err(FeedbackError::NackLength(fci.len()));
            }
            return Ok(Self::GenericNack(GenericNack {
                sender_ssrc,
                media_ssrc,
                fci,
            }));
        }
        Ok(Self::Other {
            packet_type,
            fmt,
            sender_ssrc,
            media_ssrc,
        })
    }
}

/// Strip the padding a P-bit packet carries at its tail (RFC 3550 §6.1).
fn strip_padding(body: &[u8], padded: bool) -> Result<&[u8], FeedbackError> {
    if !padded {
        return Ok(body);
    }
    let count = body.last().copied().map_or(0, usize::from);
    if count == 0 || count > body.len() {
        return Err(FeedbackError::Padding {
            declared: count,
            available: body.len(),
        });
    }
    Ok(body
        .get(..body.len().saturating_sub(count))
        .unwrap_or_default())
}

/// Writes one Generic NACK (RFC 4585 §6.2.1).
#[derive(Clone, Copy, Debug)]
pub struct GenericNackBuilder<'a> {
    /// Whoever sends the feedback: this participant's own SSRC.
    pub sender_ssrc: u32,
    /// The source whose packets were lost.
    pub media_ssrc: u32,
    /// The entries, at least one; [`NackEntry::pack`] makes them from a
    /// list of sequence numbers.
    pub entries: &'a [NackEntry],
}

impl GenericNackBuilder<'_> {
    /// How many octets [`GenericNackBuilder::write`] needs.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.entries
            .len()
            .saturating_mul(NACK_ENTRY_LEN)
            .saturating_add(COMMON_LEN)
    }

    /// Write the packet into `out`, returning how many octets it took.
    ///
    /// # Errors
    /// [`FeedbackBuildError`]: no entries, more than the length field can
    /// count, or a buffer too small.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, FeedbackBuildError> {
        if self.entries.is_empty() {
            return Err(FeedbackBuildError::NoEntries);
        }
        let need = self.encoded_len();
        let words = need / WORD_LEN;
        if words > MAX_WORDS {
            return Err(FeedbackBuildError::TooManyEntries(self.entries.len()));
        }
        let Some(out) = out.get_mut(..need) else {
            return Err(FeedbackBuildError::Short {
                need,
                got: out.len(),
            });
        };
        let length = u16::try_from(words.saturating_sub(1)).unwrap_or(u16::MAX);
        let flags = (VERSION << 6) | FMT_GENERIC_NACK;
        let mut at = put(out, 0, &[flags, RTPFB]);
        at = put(out, at, &length.to_be_bytes());
        at = put(out, at, &self.sender_ssrc.to_be_bytes());
        at = put(out, at, &self.media_ssrc.to_be_bytes());
        for entry in self.entries {
            at = put(out, at, &entry.pid.to_be_bytes());
            at = put(out, at, &entry.blp.to_be_bytes());
        }
        Ok(at)
    }
}

/// Why an individual feedback packet was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackError {
    /// Shorter than the twelve octets every feedback message starts with.
    TooShort {
        /// What arrived.
        got: usize,
    },
    /// Not version 2 (RFC 3550 A.2).
    Version(u8),
    /// The packet type is neither [`RTPFB`] nor [`PSFB`].
    NotFeedback(u8),
    /// The padding count is zero, or larger than what it claims to pad.
    Padding {
        /// The count in the last octet.
        declared: usize,
        /// Octets available to be padding.
        available: usize,
    },
    /// A Generic NACK whose FCI is empty or not a whole number of entries:
    /// it "MUST contain at least one" (§6.2.1).
    NackLength(usize),
}

impl fmt::Display for FeedbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => {
                write!(
                    f,
                    "{got} octets, {COMMON_LEN} needed for a feedback message"
                )
            }
            Self::Version(v) => write!(f, "version {v}, not {VERSION}"),
            Self::NotFeedback(pt) => write!(f, "packet type {pt} is not feedback"),
            Self::Padding {
                declared,
                available,
            } => write!(f, "padding of {declared} octets in {available}"),
            Self::NackLength(len) => write!(f, "Generic NACK FCI of {len} octets"),
        }
    }
}

impl core::error::Error for FeedbackError {}

/// Why a feedback packet could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackBuildError {
    /// The buffer is smaller than the packet.
    Short {
        /// Octets the packet takes.
        need: usize,
        /// Octets offered.
        got: usize,
    },
    /// A Generic NACK with no entry to carry.
    NoEntries,
    /// More entries than the 16-bit length field can count.
    TooManyEntries(usize),
    /// A reduced-size packet with no feedback in it.
    Empty,
    /// The compound part of the packet could not be written.
    Compound(crate::RtcpBuildError),
}

impl fmt::Display for FeedbackBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Short { need, got } => write!(f, "packet needs {need} octets, {got} offered"),
            Self::NoEntries => f.write_str("a Generic NACK with no entries"),
            Self::TooManyEntries(n) => write!(f, "{n} NACK entries do not fit one packet"),
            Self::Empty => f.write_str("a reduced-size packet with nothing in it"),
            Self::Compound(error) => write!(f, "compound packet: {error}"),
        }
    }
}

impl core::error::Error for FeedbackBuildError {}

#[cfg(test)]
mod tests {
    use super::{
        FeedbackBuildError, FeedbackError, FeedbackPacket, GenericNackBuilder, NackEntry, PSFB,
        RTPFB,
    };

    fn build(entries: &[NackEntry]) -> Vec<u8> {
        let builder = GenericNackBuilder {
            sender_ssrc: 0x1122_3344,
            media_ssrc: 0x5566_7788,
            entries,
        };
        let mut out = vec![0; builder.encoded_len()];
        let n = builder.write(&mut out).unwrap();
        assert_eq!(n, out.len());
        out
    }

    fn nack(packet: &[u8]) -> super::GenericNack<'_> {
        match FeedbackPacket::parse(packet).unwrap() {
            FeedbackPacket::GenericNack(nack) => nack,
            other @ FeedbackPacket::Other { .. } => panic!("not a NACK: {other:?}"),
        }
    }

    #[test]
    fn a_nack_is_laid_out_as_section_6_1_and_6_2_1_draw_it() {
        let bytes = build(&[NackEntry {
            pid: 0x0102,
            blp: 0x8001,
        }]);
        assert_eq!(
            bytes,
            [
                0x81, 205, 0x00, 0x03, // V=2, FMT=1, RTPFB, length 3
                0x11, 0x22, 0x33, 0x44, // packet sender
                0x55, 0x66, 0x77, 0x88, // media source
                0x01, 0x02, 0x80, 0x01, // PID, BLP
            ]
        );
    }

    #[test]
    fn the_least_significant_blp_bit_is_the_packet_after_the_pid() {
        let entry = NackEntry { pid: 100, blp: 1 };
        assert_eq!(entry.lost().collect::<Vec<_>>(), [100, 101]);
    }

    #[test]
    fn the_most_significant_blp_bit_is_sixteen_after_the_pid() {
        let entry = NackEntry {
            pid: 100,
            blp: 0x8000,
        };
        assert_eq!(entry.lost().collect::<Vec<_>>(), [100, 116]);
    }

    #[test]
    fn a_blp_wraps_modulo_two_to_the_sixteen() {
        let entry = NackEntry {
            pid: 65534,
            blp: 0b111,
        };
        assert_eq!(entry.lost().collect::<Vec<_>>(), [65534, 65535, 0, 1]);
    }

    #[test]
    fn seventeen_in_a_row_fill_one_entry_and_the_eighteenth_starts_another() {
        let seventeen = NackEntry::pack(1000..1017);
        assert_eq!(
            seventeen,
            [NackEntry {
                pid: 1000,
                blp: 0xFFFF
            }]
        );
        let eighteen = NackEntry::pack(1000..1018);
        assert_eq!(
            eighteen,
            [
                NackEntry {
                    pid: 1000,
                    blp: 0xFFFF
                },
                NackEntry::new(1017)
            ]
        );
    }

    #[test]
    fn packing_follows_the_wrap() {
        assert_eq!(
            NackEntry::pack([65535, 0, 15]),
            [NackEntry {
                pid: 65535,
                blp: 0b1 | 1 << 15
            }]
        );
    }

    #[test]
    fn packing_skips_repeats_and_keeps_out_of_order_numbers() {
        let entries = NackEntry::pack([10, 12, 10, 12, 5]);
        let lost: Vec<u16> = entries.iter().flat_map(NackEntry::lost).collect();
        assert_eq!(lost, [10, 12, 5]);
        assert_eq!(NackEntry::pack([7, 7, 7]), [NackEntry::new(7)]);
        assert_eq!(
            NackEntry::pack([1, 30, 1]),
            [NackEntry::new(1), NackEntry::new(30)]
        );
        assert!(NackEntry::pack([]).is_empty());
    }

    #[test]
    fn packed_entries_round_trip_through_the_wire() {
        let lost: Vec<u16> = vec![65530, 65531, 65535, 3, 9, 40, 41, 56, 57];
        let entries = NackEntry::pack(lost.iter().copied());
        let bytes = build(&entries);
        let parsed = nack(&bytes);
        assert_eq!(parsed.sender_ssrc(), 0x1122_3344);
        assert_eq!(parsed.media_ssrc(), 0x5566_7788);
        assert_eq!(parsed.entries().collect::<Vec<_>>(), entries);
        assert_eq!(parsed.lost().collect::<Vec<_>>(), lost);
    }

    #[test]
    fn a_nack_without_entries_is_neither_built_nor_accepted() {
        let builder = GenericNackBuilder {
            sender_ssrc: 1,
            media_ssrc: 2,
            entries: &[],
        };
        assert_eq!(
            builder.write(&mut [0; 64]),
            Err(FeedbackBuildError::NoEntries)
        );
        let empty = [0x81, RTPFB, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(
            FeedbackPacket::parse(&empty),
            Err(FeedbackError::NackLength(0))
        );
    }

    #[test]
    fn a_short_buffer_is_refused_rather_than_overrun() {
        let builder = GenericNackBuilder {
            sender_ssrc: 1,
            media_ssrc: 2,
            entries: &[NackEntry::new(1)],
        };
        assert_eq!(
            builder.write(&mut [0; 15]),
            Err(FeedbackBuildError::Short { need: 16, got: 15 })
        );
    }

    #[test]
    fn padding_that_leaves_a_partial_entry_is_refused() {
        let mut bytes = build(&[NackEntry::new(1)]);
        bytes[0] |= 0b0010_0000;
        bytes[15] = 2;
        assert_eq!(
            FeedbackPacket::parse(&bytes),
            Err(FeedbackError::NackLength(2))
        );
        bytes[15] = 0;
        assert!(matches!(
            FeedbackPacket::parse(&bytes),
            Err(FeedbackError::Padding { .. })
        ));
    }

    #[test]
    fn other_feedback_is_identified_and_walked_past() {
        let pli = [0x81, PSFB, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(
            FeedbackPacket::parse(&pli),
            Ok(FeedbackPacket::Other {
                packet_type: PSFB,
                fmt: 1,
                sender_ssrc: 1,
                media_ssrc: 2
            })
        );
        let tmmbr = [0x83, RTPFB, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
        assert!(matches!(
            FeedbackPacket::parse(&tmmbr),
            Ok(FeedbackPacket::Other { fmt: 3, .. })
        ));
    }

    #[test]
    fn wrong_version_type_or_length_is_refused() {
        let good = build(&[NackEntry::new(1)]);
        let mut v1 = good.clone();
        v1[0] = 0x41;
        assert_eq!(FeedbackPacket::parse(&v1), Err(FeedbackError::Version(1)));
        let mut rr = good.clone();
        rr[1] = 201;
        assert_eq!(
            FeedbackPacket::parse(&rr),
            Err(FeedbackError::NotFeedback(201))
        );
        for cut in 0..12 {
            assert!(matches!(
                FeedbackPacket::parse(&good[..cut]),
                Err(FeedbackError::TooShort { .. })
            ));
        }
    }
}
