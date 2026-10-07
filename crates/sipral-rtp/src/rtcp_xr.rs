// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! RTCP Extended Reports (RFC 3611): the XR packet header (§2), the generic
//! per-block framework every block type shares (§3), and the one block this
//! crate builds and reads, the VoIP Metrics Report Block, block type 7
//! (§4.7).
//!
//! Other block types are skipped by their length field: "An implementation
//! SHOULD ignore incoming blocks with types not relevant or unknown to it"
//! (§4).

use core::fmt;

use crate::wire::put;

/// §2: the XR packet type in the RTCP compound.
pub const XR: u8 = 207;

/// Octets in the XR packet's own header: V/P/reserved, PT, length, then the
/// reporter's SSRC (§2).
const HEADER_LEN: usize = 8;
/// Octets in a report block's own header: block type, type-specific, length
/// (§3).
const BLOCK_HEADER_LEN: usize = 4;
/// A 32-bit word: what every length field in this module counts in.
const WORD_LEN: usize = 4;
/// §4.7's block, eight words wide after its own header word: the SSRC of
/// source plus the seven words of metrics fields.
const VOIP_METRICS_CONTENT_LEN: usize = 32;

/// §4.7: the VoIP Metrics Report Block's block type.
pub const BT_VOIP_METRICS: u8 = 7;

/// §4.7.4 and §4.7.5: the sentinel an eight-bit signal or quality metric in
/// this block carries to mean "not available", in place of a number the
/// reporting end does not have.
pub const UNAVAILABLE: u8 = 127;

/// §4.7.6: how the receiving end is concealing lost packets, the top two
/// bits of the RX config byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PacketLossConcealment {
    /// `00`: "no information is available concerning the use of PLC".
    #[default]
    Unspecified,
    /// `01`: silence is inserted in place of a lost packet.
    Disabled,
    /// `10`: an interpolation algorithm able to conceal high loss rates.
    Enhanced,
    /// `11`: a simple replay or interpolation algorithm.
    Standard,
}

impl PacketLossConcealment {
    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b01 => Self::Disabled,
            0b10 => Self::Enhanced,
            0b11 => Self::Standard,
            _ => Self::Unspecified,
        }
    }

    const fn bits(self) -> u8 {
        match self {
            Self::Unspecified => 0b00,
            Self::Disabled => 0b01,
            Self::Enhanced => 0b10,
            Self::Standard => 0b11,
        }
    }
}

/// §4.7.6: whether the jitter buffer is resizing itself, the next two bits
/// of the RX config byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JitterBufferAdaptive {
    /// `00`: not specified.
    #[default]
    Unknown,
    /// `01`: reserved by the RFC; kept so a peer's value round-trips rather
    /// than being folded into `Unknown`.
    Reserved,
    /// `10`: held at a fixed size.
    NonAdaptive,
    /// `11`: resized to track jitter.
    Adaptive,
}

impl JitterBufferAdaptive {
    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b01 => Self::Reserved,
            0b10 => Self::NonAdaptive,
            0b11 => Self::Adaptive,
            _ => Self::Unknown,
        }
    }

    const fn bits(self) -> u8 {
        match self {
            Self::Unknown => 0b00,
            Self::Reserved => 0b01,
            Self::NonAdaptive => 0b10,
            Self::Adaptive => 0b11,
        }
    }
}

/// §4.7.6: the receiver configuration byte, packed as `PLC(2) | JBA(2) |
/// JB rate(4)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxConfig {
    /// How lost packets are concealed.
    pub plc: PacketLossConcealment,
    /// Whether the jitter buffer adapts its size.
    pub jba: JitterBufferAdaptive,
    /// The adaptive jitter buffer's adjustment rate, `0..=15`; `0` means
    /// unknown. Meaningless, and left at `0`, when `jba` is not adaptive.
    pub jb_rate: u8,
}

impl RxConfig {
    const fn from_byte(byte: u8) -> Self {
        Self {
            plc: PacketLossConcealment::from_bits(byte >> 6),
            jba: JitterBufferAdaptive::from_bits(byte >> 4),
            jb_rate: byte & 0b1111,
        }
    }

    const fn to_byte(self) -> u8 {
        (self.plc.bits() << 6) | (self.jba.bits() << 4) | (self.jb_rate & 0b1111)
    }
}

/// §4.7: one VoIP Metrics Report Block, decoded field by field. Every
/// eight-bit metric this stack cannot measure is written as
/// [`UNAVAILABLE`] rather than a guess (§4.7.4, §4.7.5: "A value of 127
/// indicates that this parameter is unavailable").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoipMetricsBlock {
    /// Whose reception this describes.
    pub ssrc: u32,
    /// §4.7.1: packets lost since the beginning of reception, as 256ths.
    pub loss_rate: u8,
    /// §4.7.1: packets discarded by the jitter buffer, as 256ths.
    pub discard_rate: u8,
    /// §4.7.2: the loss-or-discard density inside burst periods, as 256ths.
    pub burst_density: u8,
    /// §4.7.2: the loss-or-discard density inside gap periods, as 256ths.
    pub gap_density: u8,
    /// §4.7.2: the mean burst period length, in milliseconds.
    pub burst_duration_ms: u16,
    /// §4.7.2: the mean gap period length, in milliseconds.
    pub gap_duration_ms: u16,
    /// §4.7.3: the most recently measured round-trip time, in milliseconds.
    pub round_trip_delay_ms: u16,
    /// §4.7.3: sender and receiver end-system delay, in milliseconds; `0`
    /// when it cannot be estimated.
    pub end_system_delay_ms: u16,
    /// §4.7.4: talkspurt signal level relative to 0 dBm0, or
    /// [`UNAVAILABLE`] cast to a signed octet.
    pub signal_level_dbm0: i8,
    /// §4.7.4: silence-period noise level relative to 0 dBm0, or
    /// [`UNAVAILABLE`] cast to a signed octet.
    pub noise_level_dbm0: i8,
    /// §4.7.4: residual echo return loss, in dB, or [`UNAVAILABLE`].
    pub rerl_db: u8,
    /// §4.7.2, §4.7.6: the Gmin threshold this block's burst and gap
    /// figures were measured against. Never zero, and constant for the
    /// life of the session.
    pub gmin: u8,
    /// §4.7.5: the RTP-segment R factor, `0..=100`, or [`UNAVAILABLE`].
    pub r_factor: u8,
    /// §4.7.5: the R factor of a network segment external to this RTP
    /// session, or [`UNAVAILABLE`]. This stack has no such segment to
    /// report on and always writes [`UNAVAILABLE`] here.
    pub ext_r_factor: u8,
    /// §4.7.5: estimated listening-quality MOS x 10, `10..=50`, or
    /// [`UNAVAILABLE`].
    pub mos_lq: u8,
    /// §4.7.5: estimated conversational-quality MOS x 10, `10..=50`, or
    /// [`UNAVAILABLE`].
    pub mos_cq: u8,
    /// §4.7.6: how this end is concealing loss and sizing its jitter
    /// buffer.
    pub rx_config: RxConfig,
    /// §4.7.7: the jitter buffer's nominal delay, in milliseconds.
    pub jb_nominal_ms: u16,
    /// §4.7.7: the jitter buffer's current maximum delay, in milliseconds.
    pub jb_maximum_ms: u16,
    /// §4.7.7: the jitter buffer's absolute maximum delay, in milliseconds;
    /// equal to `jb_maximum_ms` for a fixed jitter buffer (§4.7.7).
    pub jb_abs_max_ms: u16,
}

impl VoipMetricsBlock {
    fn write(&self, out: &mut [u8]) -> Option<usize> {
        let need = BLOCK_HEADER_LEN + VOIP_METRICS_CONTENT_LEN;
        let out = out.get_mut(..need)?;
        // §3: "the length of this report block, including the header, in
        // 32-bit words minus one" -- one header word plus the content
        // words, minus one, is exactly the content word count.
        let length_words = u16::try_from(VOIP_METRICS_CONTENT_LEN / WORD_LEN).unwrap_or(8);
        let mut at = put(out, 0, &[BT_VOIP_METRICS, 0]);
        at = put(out, at, &length_words.to_be_bytes());
        at = put(out, at, &self.ssrc.to_be_bytes());
        at = put(
            out,
            at,
            &[
                self.loss_rate,
                self.discard_rate,
                self.burst_density,
                self.gap_density,
            ],
        );
        at = put(out, at, &self.burst_duration_ms.to_be_bytes());
        at = put(out, at, &self.gap_duration_ms.to_be_bytes());
        at = put(out, at, &self.round_trip_delay_ms.to_be_bytes());
        at = put(out, at, &self.end_system_delay_ms.to_be_bytes());
        at = put(
            out,
            at,
            &[
                self.signal_level_dbm0.cast_unsigned(),
                self.noise_level_dbm0.cast_unsigned(),
                self.rerl_db,
                self.gmin,
            ],
        );
        at = put(
            out,
            at,
            &[self.r_factor, self.ext_r_factor, self.mos_lq, self.mos_cq],
        );
        at = put(out, at, &[self.rx_config.to_byte(), 0]);
        at = put(out, at, &self.jb_nominal_ms.to_be_bytes());
        at = put(out, at, &self.jb_maximum_ms.to_be_bytes());
        at = put(out, at, &self.jb_abs_max_ms.to_be_bytes());
        Some(at)
    }

    /// Decode a VoIP Metrics block's content, everything after the shared
    /// three-octet block header (§4.7's seven-word layout, minus the
    /// SSRC-of-source word already folded into the fixed fields here).
    fn parse(content: &[u8]) -> Option<Self> {
        let bytes: &[u8; VOIP_METRICS_CONTENT_LEN] = content.first_chunk()?;
        let [
            s0,
            s1,
            s2,
            s3,
            loss_rate,
            discard_rate,
            burst_density,
            gap_density,
            bd0,
            bd1,
            gd0,
            gd1,
            rtt0,
            rtt1,
            esd0,
            esd1,
            signal,
            noise,
            rerl_db,
            gmin,
            r_factor,
            ext_r_factor,
            mos_listening,
            mos_conversational,
            rx_config,
            _reserved,
            jb_nom_lo,
            jb_nom_hi,
            jb_max_lo,
            jb_max_hi,
            jb_abs_lo,
            jb_abs_hi,
        ] = *bytes;
        Some(Self {
            ssrc: u32::from_be_bytes([s0, s1, s2, s3]),
            loss_rate,
            discard_rate,
            burst_density,
            gap_density,
            burst_duration_ms: u16::from_be_bytes([bd0, bd1]),
            gap_duration_ms: u16::from_be_bytes([gd0, gd1]),
            round_trip_delay_ms: u16::from_be_bytes([rtt0, rtt1]),
            end_system_delay_ms: u16::from_be_bytes([esd0, esd1]),
            signal_level_dbm0: signal.cast_signed(),
            noise_level_dbm0: noise.cast_signed(),
            rerl_db,
            gmin,
            r_factor,
            ext_r_factor,
            mos_lq: mos_listening,
            mos_cq: mos_conversational,
            rx_config: RxConfig::from_byte(rx_config),
            jb_nominal_ms: u16::from_be_bytes([jb_nom_lo, jb_nom_hi]),
            jb_maximum_ms: u16::from_be_bytes([jb_max_lo, jb_max_hi]),
            jb_abs_max_ms: u16::from_be_bytes([jb_abs_lo, jb_abs_hi]),
        })
    }
}

/// One parsed XR packet: who sent it, and the report blocks it stacked
/// (§2). Blocks other than [`BT_VOIP_METRICS`] are walked past, never
/// interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XrPacket<'a> {
    ssrc: u32,
    blocks: &'a [u8],
}

impl<'a> XrPacket<'a> {
    /// Parse an XR packet's body, as sliced off a compound packet by
    /// [`crate::rtcp::CompoundPacket`]: the four-octet RTCP header already
    /// stripped, so this starts at the SSRC word (§2).
    ///
    /// # Errors
    /// [`RtcpXrError`], naming what did not add up. Every block's length is
    /// walked and checked up front, so a caller that only wants one block
    /// type never has to trust an unvalidated one it skips past.
    pub fn parse(body: &'a [u8]) -> Result<Self, RtcpXrError> {
        let Some((ssrc, blocks)) = body.split_first_chunk::<4>() else {
            return Err(RtcpXrError::TooShort { got: body.len() });
        };
        let mut rest = blocks;
        while !rest.is_empty() {
            let Some(head) = rest.first_chunk::<BLOCK_HEADER_LEN>() else {
                return Err(RtcpXrError::TruncatedBlockHeader { got: rest.len() });
            };
            let [_bt, _type_specific, len_hi, len_lo] = *head;
            let words = usize::from(u16::from_be_bytes([len_hi, len_lo]));
            let total = BLOCK_HEADER_LEN + words * WORD_LEN;
            let Some((_, next)) = rest.split_at_checked(total) else {
                return Err(RtcpXrError::TruncatedBlock {
                    declared: total,
                    available: rest.len(),
                });
            };
            rest = next;
        }
        Ok(Self {
            ssrc: u32::from_be_bytes(*ssrc),
            blocks,
        })
    }

    /// Who this packet reports on itself as (§2's SSRC field — the XR
    /// packet's own originator, not necessarily the source each block
    /// describes).
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The VoIP Metrics block in this packet, if it carried one. A packet
    /// with more than one is not something this stack builds; the first
    /// one found is returned.
    #[must_use]
    pub fn voip_metrics(&self) -> Option<VoipMetricsBlock> {
        let mut rest = self.blocks;
        while !rest.is_empty() {
            let (head, after_head) = rest.split_first_chunk::<BLOCK_HEADER_LEN>()?;
            let [bt, _type_specific, len_hi, len_lo] = *head;
            let words = usize::from(u16::from_be_bytes([len_hi, len_lo]));
            let content_len = words * WORD_LEN;
            let (content, next) = after_head.split_at_checked(content_len)?;
            if bt == BT_VOIP_METRICS {
                return VoipMetricsBlock::parse(content);
            }
            rest = next;
        }
        None
    }
}

/// Writes an XR packet carrying exactly the one block type this stack
/// generates.
#[derive(Clone, Copy, Debug)]
pub struct XrPacketBuilder {
    /// This end's own SSRC (§2).
    pub ssrc: u32,
    /// The VoIP Metrics block to report, if this call has one to send yet.
    /// `None` writes an XR packet with no report blocks at all, which §2
    /// allows ("report blocks: variable length. Zero or more").
    pub voip_metrics: Option<VoipMetricsBlock>,
}

impl XrPacketBuilder {
    pub(crate) fn encoded_len(&self) -> usize {
        HEADER_LEN
            + self
                .voip_metrics
                .map_or(0, |_| BLOCK_HEADER_LEN + VOIP_METRICS_CONTENT_LEN)
    }

    pub(crate) fn write(&self, out: &mut [u8]) -> Option<usize> {
        let need = self.encoded_len();
        let out = out.get_mut(..need)?;
        let length_words = u16::try_from(need / WORD_LEN)
            .unwrap_or(0)
            .saturating_sub(1);
        let mut at = put(out, 0, &[0b1000_0000, XR]);
        at = put(out, at, &length_words.to_be_bytes());
        at = put(out, at, &self.ssrc.to_be_bytes());
        if let Some(block) = &self.voip_metrics {
            at += block.write(out.get_mut(at..)?)?;
        }
        Some(at)
    }
}

/// Why an XR packet was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpXrError {
    /// Shorter than the SSRC word every XR body has (§2).
    TooShort {
        /// What arrived.
        got: usize,
    },
    /// A report block's own four-octet header did not fit.
    TruncatedBlockHeader {
        /// What was left.
        got: usize,
    },
    /// A report block's declared length runs past what arrived.
    TruncatedBlock {
        /// Octets the block's length field asks for, header included.
        declared: usize,
        /// Octets actually there.
        available: usize,
    },
}

impl fmt::Display for RtcpXrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => write!(f, "{got} octets, 4 needed for the SSRC word"),
            Self::TruncatedBlockHeader { got } => {
                write!(f, "{got} octets, 4 needed for a block header")
            }
            Self::TruncatedBlock {
                declared,
                available,
            } => write!(f, "block wants {declared} octets, {available} there"),
        }
    }
}

impl core::error::Error for RtcpXrError {}

#[cfg(test)]
mod tests {
    use super::{
        BLOCK_HEADER_LEN, JitterBufferAdaptive, PacketLossConcealment, RtcpXrError, RxConfig,
        UNAVAILABLE, VOIP_METRICS_CONTENT_LEN, VoipMetricsBlock, XrPacket, XrPacketBuilder,
    };

    fn sample() -> VoipMetricsBlock {
        VoipMetricsBlock {
            ssrc: 0xCAFE_BABE,
            loss_rate: 12,
            discard_rate: 3,
            burst_density: 84,
            gap_density: 10,
            burst_duration_ms: 120,
            gap_duration_ms: 520,
            round_trip_delay_ms: 45,
            end_system_delay_ms: 60,
            signal_level_dbm0: -18,
            noise_level_dbm0: -62,
            rerl_db: 40,
            gmin: 16,
            r_factor: 82,
            ext_r_factor: UNAVAILABLE,
            mos_lq: 38,
            mos_cq: 36,
            rx_config: RxConfig {
                plc: PacketLossConcealment::Standard,
                jba: JitterBufferAdaptive::Adaptive,
                jb_rate: 5,
            },
            jb_nominal_ms: 20,
            jb_maximum_ms: 60,
            jb_abs_max_ms: 200,
        }
    }

    #[test]
    fn a_voip_metrics_block_survives_being_written_and_read_back() {
        let metrics = sample();
        let builder = XrPacketBuilder {
            ssrc: 0x1111_2222,
            voip_metrics: Some(metrics),
        };
        let mut out = [0_u8; 64];
        let n = builder.write(&mut out).expect("room");
        assert_eq!(n, builder.encoded_len());
        assert_eq!(n % 4, 0, "every RTCP packet ends on a 32-bit boundary");
        // XR header word + XR-packet SSRC word + block header word + eight
        // content words (the block's own SSRC-of-source plus seven metrics
        // words)
        assert_eq!(n, 4 + 4 + 4 + 32);

        let parsed = XrPacket::parse(&out[4..n]).expect("a parseable XR body");
        assert_eq!(parsed.ssrc(), 0x1111_2222);
        assert_eq!(parsed.voip_metrics(), Some(metrics));
    }

    #[test]
    fn an_xr_packet_with_no_blocks_is_still_valid() {
        // §2: "report blocks: variable length. Zero or more."
        let builder = XrPacketBuilder {
            ssrc: 7,
            voip_metrics: None,
        };
        let mut out = [0_u8; 16];
        let n = builder.write(&mut out).expect("room");
        assert_eq!(n, 8);
        let parsed = XrPacket::parse(&out[4..n]).expect("a parseable XR body");
        assert_eq!(parsed.ssrc(), 7);
        assert_eq!(parsed.voip_metrics(), None);
    }

    #[test]
    fn an_unknown_block_type_ahead_of_voip_metrics_is_walked_past_by_its_length() {
        // §4: "An implementation SHOULD ignore incoming blocks with types
        // not relevant or unknown to it" — a block this crate does not
        // define must not stop it from finding the one it does.
        let metrics = sample();
        let mut block_bytes = [0_u8; BLOCK_HEADER_LEN + VOIP_METRICS_CONTENT_LEN];
        let block_len = metrics.write(&mut block_bytes).expect("room");

        let mut body = Vec::new();
        body.extend_from_slice(&9_u32.to_be_bytes()); // XR packet SSRC
        // an unrecognised block: BT=99, type-specific=0, length=1 word,
        // one word of content
        body.extend_from_slice(&[99, 0, 0, 1]);
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        body.extend_from_slice(&block_bytes[..block_len]);

        let parsed = XrPacket::parse(&body).expect("a parseable XR body");
        assert_eq!(parsed.voip_metrics(), Some(metrics));
    }

    #[test]
    fn a_body_shorter_than_the_ssrc_word_is_refused() {
        assert_eq!(
            XrPacket::parse(&[0, 0, 0]),
            Err(RtcpXrError::TooShort { got: 3 })
        );
    }

    #[test]
    fn a_block_whose_declared_length_runs_past_the_packet_is_refused() {
        let mut body = Vec::new();
        body.extend_from_slice(&1_u32.to_be_bytes());
        body.extend_from_slice(&[7, 0, 0, 100]); // claims 400 octets of content
        assert_eq!(
            XrPacket::parse(&body),
            Err(RtcpXrError::TruncatedBlock {
                declared: 404,
                available: 4,
            })
        );
    }

    #[test]
    fn rx_config_round_trips_every_combination_of_its_packed_fields() {
        for plc in [
            PacketLossConcealment::Unspecified,
            PacketLossConcealment::Disabled,
            PacketLossConcealment::Enhanced,
            PacketLossConcealment::Standard,
        ] {
            for jba in [
                JitterBufferAdaptive::Unknown,
                JitterBufferAdaptive::Reserved,
                JitterBufferAdaptive::NonAdaptive,
                JitterBufferAdaptive::Adaptive,
            ] {
                let config = RxConfig {
                    plc,
                    jba,
                    jb_rate: 9,
                };
                assert_eq!(RxConfig::from_byte(config.to_byte()), config);
            }
        }
    }

    #[test]
    fn the_unavailable_sentinel_round_trips_through_the_signed_signal_fields() {
        let mut metrics = sample();
        metrics.signal_level_dbm0 = UNAVAILABLE.cast_signed();
        metrics.noise_level_dbm0 = UNAVAILABLE.cast_signed();
        let mut out = [0_u8; BLOCK_HEADER_LEN + VOIP_METRICS_CONTENT_LEN];
        let n = metrics.write(&mut out).expect("room");
        let parsed = VoipMetricsBlock::parse(&out[4..n]).expect("content parses");
        assert_eq!(parsed.signal_level_dbm0.cast_unsigned(), UNAVAILABLE);
        assert_eq!(parsed.noise_level_dbm0.cast_unsigned(), UNAVAILABLE);
    }
}
