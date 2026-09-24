// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RTCP as it appears on the wire: sender and receiver reports, source
//! description, and goodbye (RFC 3550 §6), stacked into the compound
//! packets §6.1 requires, plus telling RTCP apart from RTP on one socket
//! (RFC 5761 §4).
//!
//! Reading borrows, the same as [`crate::wire`]: report blocks, SDES items
//! and BYE reasons stay in the datagram the caller already owns. Building
//! writes into a buffer the caller supplies. Nothing here reads a clock or
//! sends anything — the wall-clock and RTP timestamps in a sender report
//! are exactly what the caller passes in.

use core::fmt;

use crate::rtcp_xr::{RtcpXrError, XR, XrPacket, XrPacketBuilder};
use crate::wire::{VERSION, put};

const SR: u8 = 200;
const RR: u8 = 201;
const SDES: u8 = 202;
const BYE: u8 = 203;

/// Octets in the header every individual RTCP packet starts with: the
/// V/P/count byte, the packet type, and the length (§6.1).
const HEADER_LEN: usize = 4;
/// Octets in one SSRC or CSRC field.
const SSRC_LEN: usize = 4;
/// Octets in the sender-information section unique to SR (§6.4.1).
const SENDER_INFO_LEN: usize = 20;
/// Octets in one reception report block (§6.4.1).
const REPORT_BLOCK_LEN: usize = 24;
/// The reception report count, source count and SDES chunk count fields
/// are all five bits wide (§6.1), so this is what "too many" means for all
/// three.
const MAX_COUNT: usize = 31;
/// A 32-bit word: what the length field counts in, and what chunks and BYE
/// reasons are padded to.
const WORD_LEN: usize = 4;
/// The largest length an SDES item or a BYE reason can declare, being an
/// eight-bit count (§6.5, §6.6).
const MAX_TEXT_LEN: usize = 255;

/// The canonical end-point identifier item type (§6.5.1): the one SDES item
/// every compound packet built here carries.
pub const CNAME: u8 = 1;

/// The span RFC 5761 §4 hands to RTCP on a multiplexed socket. Future RTCP
/// types "SHOULD be made after the current assignments in the range 209-223,
/// then in the range 194-199", which together with the obsolete 192-193 and
/// everything assigned since puts the whole of 192-223 on the RTCP side —
/// the same span as the RTP marker bit set over payload types 64-95, which
/// is exactly what §4 blocks in return.
const MUX_FIRST: u8 = 192;
const MUX_LAST: u8 = 223;

/// Whether `datagram` is RTCP rather than RTP, for a socket carrying both
/// (RFC 5761 §4). The RTCP packet type sits where the RTP marker bit and
/// payload type would be, and every value in the span §4 reserves for RTCP
/// reads as RTCP — not only what is assigned today, since a peer sending a
/// packet type registered after this was written must still not have it
/// parsed as audio. Keeping payload types out of that window is the other
/// half of the bargain, and this crate does not police it.
#[must_use]
pub fn is_rtcp(datagram: &[u8]) -> bool {
    matches!(datagram.get(1), Some(&byte) if (MUX_FIRST..=MUX_LAST).contains(&byte))
}

/// The RTCP port for an RTP port allocated as the classic even/odd pair
/// (RFC 3550 §11): one higher. An odd port was never such a pair to begin
/// with, so it is returned unchanged rather than guessed at.
#[must_use]
pub const fn paired_rtcp_port(rtp_port: u16) -> u16 {
    if rtp_port.is_multiple_of(2) {
        rtp_port.saturating_add(1)
    } else {
        rtp_port
    }
}

/// The sender-information section unique to an SR (§6.4.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SenderInfo {
    /// The wallclock instant this report was sent, as a 64-bit NTP
    /// timestamp. This crate reads no clock, so it is exactly what the
    /// caller passed in.
    pub ntp: u64,
    /// The RTP timestamp for that same instant, on the data packets' own
    /// clock.
    pub rtp_timestamp: u32,
    /// RTP data packets sent since this source started.
    pub packet_count: u32,
    /// Payload octets sent since this source started, header and padding
    /// excluded.
    pub octet_count: u32,
}

/// One source's entry in a reception report (§6.4.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReportBlock {
    /// Whose reception this describes.
    pub ssrc: u32,
    /// Packets lost in the interval since the previous report, as 256ths
    /// (§6.4.1, A.3).
    pub fraction_lost: u8,
    /// Packets lost since reception of this source began. Negative when
    /// duplicates have pushed the count below zero (A.3).
    pub cumulative_lost: i32,
    /// The highest sequence number received, extended by the cycle count.
    pub extended_highest_sequence: u32,
    /// The interarrival jitter estimate, in the source's own clock units
    /// (§6.4.1).
    pub jitter: u32,
    /// The middle 32 bits of the last SR received from this source, or
    /// zero if none has been.
    pub last_sr: u32,
    /// Delay since that SR, in units of 1/65536 second, or zero if none has
    /// been received.
    pub delay_since_last_sr: u32,
}

/// One SDES item: its type and its UTF-8 text (§6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SdesItem<'a> {
    /// Which item this is; [`CNAME`] is the only one this crate requires.
    pub kind: u8,
    /// The text, without the type and length octets that precede it.
    pub text: &'a [u8],
}

fn decode_sender_info(bytes: &[u8; SENDER_INFO_LEN]) -> SenderInfo {
    let [
        n0,
        n1,
        n2,
        n3,
        n4,
        n5,
        n6,
        n7,
        t0,
        t1,
        t2,
        t3,
        p0,
        p1,
        p2,
        p3,
        o0,
        o1,
        o2,
        o3,
    ] = *bytes;
    SenderInfo {
        ntp: u64::from_be_bytes([n0, n1, n2, n3, n4, n5, n6, n7]),
        rtp_timestamp: u32::from_be_bytes([t0, t1, t2, t3]),
        packet_count: u32::from_be_bytes([p0, p1, p2, p3]),
        octet_count: u32::from_be_bytes([o0, o1, o2, o3]),
    }
}

fn decode_report_block(bytes: &[u8; REPORT_BLOCK_LEN]) -> ReportBlock {
    let [
        s0,
        s1,
        s2,
        s3,
        frac,
        c0,
        c1,
        c2,
        e0,
        e1,
        e2,
        e3,
        j0,
        j1,
        j2,
        j3,
        l0,
        l1,
        l2,
        l3,
        d0,
        d1,
        d2,
        d3,
    ] = *bytes;
    ReportBlock {
        ssrc: u32::from_be_bytes([s0, s1, s2, s3]),
        fraction_lost: frac,
        cumulative_lost: sign_extend_24(u32::from_be_bytes([0, c0, c1, c2])),
        extended_highest_sequence: u32::from_be_bytes([e0, e1, e2, e3]),
        jitter: u32::from_be_bytes([j0, j1, j2, j3]),
        last_sr: u32::from_be_bytes([l0, l1, l2, l3]),
        delay_since_last_sr: u32::from_be_bytes([d0, d1, d2, d3]),
    }
}

/// Read a 24-bit two's complement quantity, already right-aligned in a
/// 32-bit word, as the signed value it represents.
fn sign_extend_24(raw: u32) -> i32 {
    (raw << 8).cast_signed() >> 8
}

/// A.3's saturation: "clamped at 0x7fffff for positive loss or 0x800000 for
/// negative loss rather than wrapping", written as the 24-bit two's
/// complement pattern §6.4.1's field is.
fn encode_cumulative_lost(value: i32) -> [u8; 3] {
    let clamped = value.clamp(-0x0080_0000, 0x007F_FFFF);
    let [_, b1, b2, b3] = clamped.cast_unsigned().to_be_bytes();
    [b1, b2, b3]
}

fn write_report_block(out: &mut [u8], at: usize, block: &ReportBlock) -> usize {
    let mut at = put(out, at, &block.ssrc.to_be_bytes());
    at = put(out, at, &[block.fraction_lost]);
    at = put(out, at, &encode_cumulative_lost(block.cumulative_lost));
    at = put(out, at, &block.extended_highest_sequence.to_be_bytes());
    at = put(out, at, &block.jitter.to_be_bytes());
    at = put(out, at, &block.last_sr.to_be_bytes());
    put(out, at, &block.delay_since_last_sr.to_be_bytes())
}

/// The common four-octet header: version, padding, the five-bit count, the
/// packet type, and the length in words minus one. This crate never writes
/// padding, so the padding bit is always clear.
fn write_header(out: &mut [u8], count: u8, packet_type: u8, length_words: u16) -> usize {
    let flags = (VERSION << 6) | (count & 0b0001_1111);
    let at = put(out, 0, &[flags, packet_type]);
    put(out, at, &length_words.to_be_bytes())
}

/// `total` octets as a words-minus-one length field, or the largest value
/// the field can hold if `total` somehow overflows it — which a caller
/// respecting the count limits above never reaches.
fn length_words(total: usize) -> u16 {
    u16::try_from(total / WORD_LEN)
        .unwrap_or(u16::MAX)
        .saturating_sub(1)
}

/// Strip the padding a P-bit packet carries at its tail (§6.1, same rule as
/// the RTP payload's own padding in [`crate::wire`]).
fn strip_padding(body: &[u8], padded: bool) -> Result<&[u8], RtcpError> {
    if !padded {
        return Ok(body);
    }
    let count = body.last().copied().map_or(0, usize::from);
    if count == 0 || count > body.len() {
        return Err(RtcpError::Padding {
            declared: count,
            available: body.len(),
        });
    }
    Ok(body
        .get(..body.len().saturating_sub(count))
        .unwrap_or_default())
}

/// Split one RTCP packet, header and all, off the front of `datagram`,
/// using its own length field, and hand back what follows.
fn split_packet(datagram: &[u8]) -> Result<(&[u8], &[u8]), RtcpError> {
    let Some(head) = datagram.first_chunk::<HEADER_LEN>() else {
        return Err(RtcpError::TooShort {
            got: datagram.len(),
        });
    };
    let [flags, _packet_type, len_hi, len_lo] = *head;
    let version = flags >> 6;
    if version != VERSION {
        return Err(RtcpError::Version(version));
    }
    let words = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    let total = words.saturating_add(1).saturating_mul(WORD_LEN);
    datagram
        .split_at_checked(total)
        .ok_or(RtcpError::Truncated {
            declared: total,
            available: datagram.len(),
        })
}

/// A sender report: transmission statistics for an active sender, plus
/// whatever it has heard back about its own reception (§6.4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SenderReport<'a> {
    ssrc: u32,
    info: SenderInfo,
    reports: &'a [u8],
}

impl<'a> SenderReport<'a> {
    /// The originator of this report.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// What it has sent.
    #[must_use]
    pub const fn info(&self) -> SenderInfo {
        self.info
    }

    /// How many reception report blocks it included.
    #[must_use]
    pub fn report_count(&self) -> usize {
        self.reports.len() / REPORT_BLOCK_LEN
    }

    /// What it has heard, one block per source.
    #[must_use]
    pub fn reports(&self) -> Reports<'a> {
        Reports { rest: self.reports }
    }
}

/// A receiver report: the same reception statistics as an SR, from a
/// participant that has nothing of its own to report sending (§6.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiverReport<'a> {
    ssrc: u32,
    reports: &'a [u8],
}

impl<'a> ReceiverReport<'a> {
    /// Whoever is reporting.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// How many reception report blocks it included.
    #[must_use]
    pub fn report_count(&self) -> usize {
        self.reports.len() / REPORT_BLOCK_LEN
    }

    /// What it has heard, one block per source.
    #[must_use]
    pub fn reports(&self) -> Reports<'a> {
        Reports { rest: self.reports }
    }
}

/// The reception report blocks of an SR or RR, in the order they arrived.
#[derive(Clone, Debug)]
pub struct Reports<'a> {
    rest: &'a [u8],
}

impl Iterator for Reports<'_> {
    type Item = ReportBlock;

    fn next(&mut self) -> Option<Self::Item> {
        let (block, rest) = self.rest.split_first_chunk::<REPORT_BLOCK_LEN>()?;
        self.rest = rest;
        Some(decode_report_block(block))
    }
}

fn parse_sr(body: &[u8], count: u8) -> Result<SenderReport<'_>, RtcpError> {
    let Some((ssrc, rest)) = body.split_first_chunk::<SSRC_LEN>() else {
        return Err(RtcpError::TooShort { got: body.len() });
    };
    let Some((info, rest)) = rest.split_first_chunk::<SENDER_INFO_LEN>() else {
        return Err(RtcpError::TooShort { got: rest.len() });
    };
    let need = usize::from(count) * REPORT_BLOCK_LEN;
    let Some(reports) = rest.get(..need) else {
        return Err(RtcpError::TruncatedReports {
            declared: need,
            available: rest.len(),
        });
    };
    Ok(SenderReport {
        ssrc: u32::from_be_bytes(*ssrc),
        info: decode_sender_info(info),
        reports,
    })
}

fn parse_rr(body: &[u8], count: u8) -> Result<ReceiverReport<'_>, RtcpError> {
    let Some((ssrc, rest)) = body.split_first_chunk::<SSRC_LEN>() else {
        return Err(RtcpError::TooShort { got: body.len() });
    };
    let need = usize::from(count) * REPORT_BLOCK_LEN;
    let Some(reports) = rest.get(..need) else {
        return Err(RtcpError::TruncatedReports {
            declared: need,
            available: rest.len(),
        });
    };
    Ok(ReceiverReport {
        ssrc: u32::from_be_bytes(*ssrc),
        reports,
    })
}

/// One SSRC/CSRC's chunk of an SDES packet: the source it describes and
/// the items about it (§6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk<'a> {
    ssrc: u32,
    items: &'a [u8],
}

impl<'a> Chunk<'a> {
    /// Which source this chunk describes.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The items in this chunk, in the order they were sent.
    #[must_use]
    pub fn items(&self) -> Items<'a> {
        Items { rest: self.items }
    }

    /// This chunk's [`CNAME`] text, if it has one.
    #[must_use]
    pub fn cname(&self) -> Option<&'a [u8]> {
        self.items()
            .find(|item| item.kind == CNAME)
            .map(|item| item.text)
    }
}

/// The items of one SDES chunk.
#[derive(Clone, Debug)]
pub struct Items<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Items<'a> {
    type Item = SdesItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&kind, rest) = self.rest.split_first()?;
        let (&len, rest) = rest.split_first()?;
        let (text, rest) = rest.split_at_checked(usize::from(len))?;
        self.rest = rest;
        Some(SdesItem { kind, text })
    }
}

/// Walk one chunk off the front of `bytes`: its SSRC, its items up to and
/// including the null terminator, and the padding that rounds it out to a
/// 32-bit boundary (§6.5: "each chunk starts on a 32-bit boundary").
fn split_chunk(bytes: &[u8]) -> Option<(Chunk<'_>, &[u8])> {
    let (ssrc, rest) = bytes.split_first_chunk::<SSRC_LEN>()?;
    let mut at = 0_usize;
    loop {
        let &kind = rest.get(at)?;
        if kind == 0 {
            break;
        }
        let &len = rest.get(at.checked_add(1)?)?;
        at = at.checked_add(2)?.checked_add(usize::from(len))?;
    }
    let items = rest.get(..at)?;
    let chunk_len = SSRC_LEN.checked_add(at)?.checked_add(1)?;
    let padded = chunk_len.next_multiple_of(WORD_LEN);
    let after_terminator = rest.get(at.checked_add(1)?..)?;
    let after = after_terminator.get(padded.checked_sub(chunk_len)?..)?;
    Some((
        Chunk {
            ssrc: u32::from_be_bytes(*ssrc),
            items,
        },
        after,
    ))
}

/// A source description packet: who is talking, named by CNAME and
/// whatever else a profile chose to include (§6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceDescription<'a> {
    body: &'a [u8],
    count: u8,
}

impl<'a> SourceDescription<'a> {
    fn parse(body: &'a [u8], count: u8) -> Result<Self, RtcpError> {
        let mut rest = body;
        for _ in 0..count {
            let Some((_, next)) = split_chunk(rest) else {
                return Err(RtcpError::UnterminatedChunk);
            };
            rest = next;
        }
        Ok(Self { body, count })
    }

    /// How many chunks this packet holds.
    #[must_use]
    pub const fn chunk_count(&self) -> usize {
        self.count as usize
    }

    /// The chunks, in the order they were sent.
    #[must_use]
    pub fn chunks(&self) -> Chunks<'a> {
        Chunks {
            rest: self.body,
            remaining: self.count,
        }
    }

    /// The first chunk's CNAME, which every compound packet this crate
    /// builds carries (§6.1).
    #[must_use]
    pub fn cname(&self) -> Option<&'a [u8]> {
        self.chunks().next().and_then(|chunk| chunk.cname())
    }
}

/// The chunks of an SDES packet.
#[derive(Clone, Debug)]
pub struct Chunks<'a> {
    rest: &'a [u8],
    remaining: u8,
}

impl<'a> Iterator for Chunks<'a> {
    type Item = Chunk<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (chunk, rest) = split_chunk(self.rest)?;
        self.rest = rest;
        self.remaining -= 1;
        Some(chunk)
    }
}

/// A goodbye: one or more sources that are no longer active, with an
/// optional reason (§6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Goodbye<'a> {
    sources: &'a [u8],
    reason: Option<&'a [u8]>,
}

impl<'a> Goodbye<'a> {
    /// The sources that are leaving, in the order they were listed.
    pub fn sources(&self) -> impl Iterator<Item = u32> + use<'a> {
        self.sources
            .chunks_exact(SSRC_LEN)
            .filter_map(|id| <[u8; SSRC_LEN]>::try_from(id).ok())
            .map(u32::from_be_bytes)
    }

    /// Why, if it said.
    #[must_use]
    pub const fn reason(&self) -> Option<&'a [u8]> {
        self.reason
    }
}

fn parse_bye(body: &[u8], count: u8) -> Result<Goodbye<'_>, RtcpError> {
    let need = usize::from(count) * SSRC_LEN;
    let Some((sources, rest)) = body.split_at_checked(need) else {
        return Err(RtcpError::Truncated {
            declared: need,
            available: body.len(),
        });
    };
    let reason = if let Some((&len, after_len)) = rest.split_first() {
        let Some(text) = after_len.get(..usize::from(len)) else {
            return Err(RtcpError::TruncatedReason {
                declared: usize::from(len),
                available: after_len.len(),
            });
        };
        Some(text)
    } else {
        None
    };
    Ok(Goodbye { sources, reason })
}

/// One packet out of a compound RTCP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpPacket<'a> {
    /// §6.4.1.
    SenderReport(SenderReport<'a>),
    /// §6.4.2.
    ReceiverReport(ReceiverReport<'a>),
    /// §6.5.
    SourceDescription(SourceDescription<'a>),
    /// §6.6.
    Goodbye(Goodbye<'a>),
    /// RFC 3611 §2: an Extended Report packet, carrying zero or more of the
    /// report blocks that RFC defines. Kept as its own variant, rather than
    /// folded into `Other`, so a peer's VoIP Metrics block (§4.7) can be
    /// read back out of a compound packet.
    ExtendedReport(XrPacket<'a>),
    /// APP, or any packet type this crate does not define. Kept only so a
    /// compound packet can be walked past it: "an implementation SHOULD
    /// ignore incoming RTCP packets with types unknown to it" (§6.1).
    Other {
        /// The packet type this crate does not know.
        packet_type: u8,
    },
}

impl<'a> RtcpPacket<'a> {
    /// Parse one packet, header and body, as sliced off a compound packet
    /// by [`split_packet`].
    fn parse(packet: &'a [u8]) -> Result<Self, RtcpError> {
        let Some(head) = packet.first_chunk::<HEADER_LEN>() else {
            return Err(RtcpError::TooShort { got: packet.len() });
        };
        let [flags, packet_type, _, _] = *head;
        let padded = flags & 0b0010_0000 != 0;
        let count = flags & 0b0001_1111;
        let body = strip_padding(packet.get(HEADER_LEN..).unwrap_or_default(), padded)?;
        match packet_type {
            SR => parse_sr(body, count).map(Self::SenderReport),
            RR => parse_rr(body, count).map(Self::ReceiverReport),
            SDES => SourceDescription::parse(body, count).map(Self::SourceDescription),
            BYE => parse_bye(body, count).map(Self::Goodbye),
            XR => XrPacket::parse(body)
                .map(Self::ExtendedReport)
                .map_err(RtcpError::ExtendedReport),
            other => Ok(Self::Other { packet_type: other }),
        }
    }
}

/// A compound RTCP packet, validated against §6.1's rules: version 2
/// throughout, the first packet is SR or RR, an SDES CNAME is present, and
/// the individual lengths add up to exactly what arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompoundPacket<'a> {
    datagram: &'a [u8],
}

impl<'a> CompoundPacket<'a> {
    /// # Errors
    /// [`RtcpError`], naming what did not add up.
    pub fn parse(datagram: &'a [u8]) -> Result<Self, RtcpError> {
        let (first, _) = split_packet(datagram)?;
        let Some(&first_type) = first.get(1) else {
            return Err(RtcpError::TooShort { got: first.len() });
        };
        if first_type != SR && first_type != RR {
            return Err(RtcpError::FirstPacketType(first_type));
        }

        let mut rest = datagram;
        let mut consumed = 0_usize;
        let mut saw_cname = false;
        while !rest.is_empty() {
            let (packet, next) = split_packet(rest)?;
            let padded = packet
                .first()
                .is_some_and(|&flags| flags & 0b0010_0000 != 0);
            if padded && !next.is_empty() {
                return Err(RtcpError::PaddingNotLast);
            }
            let parsed = RtcpPacket::parse(packet)?;
            if let RtcpPacket::SourceDescription(sdes) = &parsed
                && sdes.cname().is_some()
            {
                saw_cname = true;
            }
            consumed = consumed.saturating_add(packet.len());
            rest = next;
        }
        if consumed != datagram.len() {
            return Err(RtcpError::LengthMismatch {
                total: datagram.len(),
                consumed,
            });
        }
        if !saw_cname {
            return Err(RtcpError::MissingCname);
        }
        Ok(Self { datagram })
    }

    /// The individual packets, in the order they were stacked.
    #[must_use]
    pub fn packets(&self) -> Packets<'a> {
        Packets {
            rest: self.datagram,
        }
    }
}

/// The individual packets of a [`CompoundPacket`].
#[derive(Clone, Debug)]
pub struct Packets<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Packets<'a> {
    type Item = RtcpPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        // `CompoundPacket::parse` already walked and parsed every packet
        // here successfully, so this cannot fail; the `?` is cheaper than
        // re-proving that to the type system.
        let (packet, next) = split_packet(self.rest).ok()?;
        self.rest = next;
        RtcpPacket::parse(packet).ok()
    }
}

/// Writes one sender report (§6.4.1).
#[derive(Clone, Copy, Debug)]
pub struct SenderReportBuilder<'a> {
    /// The originator of this report.
    pub ssrc: u32,
    /// What it has sent.
    pub info: SenderInfo,
    /// What it has heard, one block per source; at most 31, the most a
    /// report count can name.
    pub reports: &'a [ReportBlock],
}

impl SenderReportBuilder<'_> {
    fn encoded_len(&self) -> usize {
        HEADER_LEN + SSRC_LEN + SENDER_INFO_LEN + self.reports.len() * REPORT_BLOCK_LEN
    }

    fn write(&self, out: &mut [u8]) -> Result<usize, RtcpBuildError> {
        if self.reports.len() > MAX_COUNT {
            return Err(RtcpBuildError::TooManyReports(self.reports.len()));
        }
        let need = self.encoded_len();
        let Some(out) = out.get_mut(..need) else {
            return Err(RtcpBuildError::Short {
                need,
                got: out.len(),
            });
        };
        let count = u8::try_from(self.reports.len()).unwrap_or(0);
        let mut at = write_header(out, count, SR, length_words(need));
        at = put(out, at, &self.ssrc.to_be_bytes());
        at = put(out, at, &self.info.ntp.to_be_bytes());
        at = put(out, at, &self.info.rtp_timestamp.to_be_bytes());
        at = put(out, at, &self.info.packet_count.to_be_bytes());
        at = put(out, at, &self.info.octet_count.to_be_bytes());
        for block in self.reports {
            at = write_report_block(out, at, block);
        }
        Ok(at)
    }
}

/// Writes one receiver report (§6.4.2).
#[derive(Clone, Copy, Debug)]
pub struct ReceiverReportBuilder<'a> {
    /// Whoever is reporting.
    pub ssrc: u32,
    /// What it has heard, one block per source; at most 31.
    pub reports: &'a [ReportBlock],
}

impl ReceiverReportBuilder<'_> {
    fn encoded_len(&self) -> usize {
        HEADER_LEN + SSRC_LEN + self.reports.len() * REPORT_BLOCK_LEN
    }

    fn write(&self, out: &mut [u8]) -> Result<usize, RtcpBuildError> {
        if self.reports.len() > MAX_COUNT {
            return Err(RtcpBuildError::TooManyReports(self.reports.len()));
        }
        let need = self.encoded_len();
        let Some(out) = out.get_mut(..need) else {
            return Err(RtcpBuildError::Short {
                need,
                got: out.len(),
            });
        };
        let count = u8::try_from(self.reports.len()).unwrap_or(0);
        let mut at = write_header(out, count, RR, length_words(need));
        at = put(out, at, &self.ssrc.to_be_bytes());
        for block in self.reports {
            at = write_report_block(out, at, block);
        }
        Ok(at)
    }
}

fn chunk_encoded_len(chunk: &[SdesItem<'_>]) -> usize {
    let items: usize = chunk.iter().map(|item| 2 + item.text.len()).sum();
    (SSRC_LEN + items + 1).next_multiple_of(WORD_LEN)
}

fn write_chunk(ssrc: u32, items: &[SdesItem<'_>], out: &mut [u8]) -> Result<usize, RtcpBuildError> {
    for item in items {
        if item.text.len() > MAX_TEXT_LEN {
            return Err(RtcpBuildError::ItemTooLong(item.text.len()));
        }
    }
    let need = chunk_encoded_len(items);
    let Some(out) = out.get_mut(..need) else {
        return Err(RtcpBuildError::Short {
            need,
            got: out.len(),
        });
    };
    let mut at = put(out, 0, &ssrc.to_be_bytes());
    for item in items {
        let len = u8::try_from(item.text.len()).unwrap_or(u8::MAX);
        at = put(out, at, &[item.kind, len]);
        at = put(out, at, item.text);
    }
    // the null terminator, then zero padding out to the word boundary
    // `chunk_encoded_len` already reserved
    if let Some(tail) = out.get_mut(at..) {
        tail.fill(0);
    }
    Ok(need)
}

/// One chunk to write into an SDES packet: the source it describes and the
/// items about it.
#[derive(Clone, Copy, Debug)]
pub struct ChunkBuilder<'a> {
    /// Which source this chunk describes.
    pub ssrc: u32,
    /// The items about it. At most 255 octets of text each.
    pub items: &'a [SdesItem<'a>],
}

/// Writes one source description packet (§6.5).
#[derive(Clone, Copy, Debug)]
pub struct SourceDescriptionBuilder<'a> {
    /// The chunks to write, in order; at most 31, the most a source count
    /// can name.
    pub chunks: &'a [ChunkBuilder<'a>],
}

impl SourceDescriptionBuilder<'_> {
    fn has_cname(&self) -> bool {
        self.chunks
            .iter()
            .any(|chunk| chunk.items.iter().any(|item| item.kind == CNAME))
    }

    fn encoded_len(&self) -> usize {
        HEADER_LEN
            + self
                .chunks
                .iter()
                .map(|chunk| chunk_encoded_len(chunk.items))
                .sum::<usize>()
    }

    fn write(&self, out: &mut [u8]) -> Result<usize, RtcpBuildError> {
        if self.chunks.len() > MAX_COUNT {
            return Err(RtcpBuildError::TooManyChunks(self.chunks.len()));
        }
        let need = self.encoded_len();
        let Some(out) = out.get_mut(..need) else {
            return Err(RtcpBuildError::Short {
                need,
                got: out.len(),
            });
        };
        let count = u8::try_from(self.chunks.len()).unwrap_or(0);
        let mut at = write_header(out, count, SDES, length_words(need));
        for chunk in self.chunks {
            let Some(slice) = out.get_mut(at..) else {
                break;
            };
            at += write_chunk(chunk.ssrc, chunk.items, slice)?;
        }
        Ok(at)
    }
}

/// Writes one goodbye (§6.6).
#[derive(Clone, Copy, Debug)]
pub struct GoodbyeBuilder<'a> {
    /// The sources that are leaving; at most 31, the most a source count
    /// can name.
    pub sources: &'a [u32],
    /// Why, or empty to say nothing.
    pub reason: &'a [u8],
}

impl GoodbyeBuilder<'_> {
    fn encoded_len(&self) -> usize {
        let reason = if self.reason.is_empty() {
            0
        } else {
            1 + self.reason.len()
        };
        (HEADER_LEN + self.sources.len() * SSRC_LEN + reason).next_multiple_of(WORD_LEN)
    }

    fn write(&self, out: &mut [u8]) -> Result<usize, RtcpBuildError> {
        if self.sources.len() > MAX_COUNT {
            return Err(RtcpBuildError::TooManySources(self.sources.len()));
        }
        if self.reason.len() > MAX_TEXT_LEN {
            return Err(RtcpBuildError::ReasonTooLong(self.reason.len()));
        }
        let need = self.encoded_len();
        let Some(out) = out.get_mut(..need) else {
            return Err(RtcpBuildError::Short {
                need,
                got: out.len(),
            });
        };
        let count = u8::try_from(self.sources.len()).unwrap_or(0);
        let mut at = write_header(out, count, BYE, length_words(need));
        for ssrc in self.sources {
            at = put(out, at, &ssrc.to_be_bytes());
        }
        if !self.reason.is_empty() {
            let len = u8::try_from(self.reason.len()).unwrap_or(u8::MAX);
            at = put(out, at, &[len]);
            at = put(out, at, self.reason);
        }
        if let Some(tail) = out.get_mut(at..) {
            tail.fill(0);
        }
        Ok(need)
    }
}

/// Which report leads a compound packet: an active sender includes its own
/// transmission statistics, everyone else sends only reception statistics
/// (§6.4).
#[derive(Clone, Copy, Debug)]
pub enum SenderOrReceiver<'a> {
    /// This participant has sent data since its last report (§6.4).
    Sender(SenderReportBuilder<'a>),
    /// It has not.
    Receiver(ReceiverReportBuilder<'a>),
}

/// Assembles a compound RTCP packet in the order §6.1 requires: SR or RR
/// first, an SDES with a CNAME next, then a goodbye if one is leaving.
/// Padding is never written, the same choice [`crate::wire::PacketBuilder`]
/// makes, so there is nothing here to place last.
#[derive(Clone, Copy, Debug)]
pub struct CompoundBuilder<'a> {
    report: SenderOrReceiver<'a>,
    sdes: SourceDescriptionBuilder<'a>,
    xr: Option<XrPacketBuilder>,
    bye: Option<GoodbyeBuilder<'a>>,
}

impl<'a> CompoundBuilder<'a> {
    /// A report and the CNAME §6.1 requires next to it. Nothing is
    /// buildable without both, which is what keeps a caller from producing
    /// a compound packet that parsing here would then refuse.
    #[must_use]
    pub const fn new(report: SenderOrReceiver<'a>, sdes: SourceDescriptionBuilder<'a>) -> Self {
        Self {
            report,
            sdes,
            xr: None,
            bye: None,
        }
    }

    /// Append an Extended Report (RFC 3611 §2), for a peer that negotiated
    /// it (§5). Nothing here decides whether that negotiation happened;
    /// the caller includes this only once it has.
    #[must_use]
    pub const fn with_xr(mut self, xr: XrPacketBuilder) -> Self {
        self.xr = Some(xr);
        self
    }

    /// Append a goodbye, for a compound packet sent on hangup.
    #[must_use]
    pub const fn with_bye(mut self, bye: GoodbyeBuilder<'a>) -> Self {
        self.bye = Some(bye);
        self
    }

    /// How many octets [`CompoundBuilder::write`] needs.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let report = match &self.report {
            SenderOrReceiver::Sender(sr) => sr.encoded_len(),
            SenderOrReceiver::Receiver(rr) => rr.encoded_len(),
        };
        report
            + self.sdes.encoded_len()
            + self.xr.as_ref().map_or(0, XrPacketBuilder::encoded_len)
            + self.bye.as_ref().map_or(0, GoodbyeBuilder::encoded_len)
    }

    /// Write the compound packet into `out`, returning how many octets it
    /// took.
    ///
    /// # Errors
    /// [`RtcpBuildError`], for a buffer too small, too many entries in one
    /// of the individual packets, or an SDES built without a CNAME.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, RtcpBuildError> {
        if !self.sdes.has_cname() {
            return Err(RtcpBuildError::MissingCname);
        }
        let need = self.encoded_len();
        let Some(out) = out.get_mut(..need) else {
            return Err(RtcpBuildError::Short {
                need,
                got: out.len(),
            });
        };
        let mut at = match &self.report {
            SenderOrReceiver::Sender(sr) => sr.write(out)?,
            SenderOrReceiver::Receiver(rr) => rr.write(out)?,
        };
        at += self.sdes.write(out.get_mut(at..).unwrap_or_default())?;
        if let Some(xr) = &self.xr {
            at += xr
                .write(out.get_mut(at..).unwrap_or_default())
                .ok_or(RtcpBuildError::Short { need, got: at })?;
        }
        if let Some(bye) = &self.bye {
            at += bye.write(out.get_mut(at..).unwrap_or_default())?;
        }
        Ok(at)
    }
}

/// Why a datagram, or one packet inside a compound one, was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpError {
    /// Shorter than one packet's fixed header.
    TooShort {
        /// What arrived.
        got: usize,
    },
    /// "RTP version field must equal 2" (A.2), and RTCP shares the field.
    Version(u8),
    /// The length field claims more than the datagram holds.
    Truncated {
        /// Octets the length field asks for.
        declared: usize,
        /// Octets actually there.
        available: usize,
    },
    /// The individual packets' lengths did not add up to the compound
    /// packet's own length (A.2).
    LengthMismatch {
        /// What arrived.
        total: usize,
        /// What the individual packets' lengths summed to.
        consumed: usize,
    },
    /// The first packet in a compound packet was not SR or RR (A.2).
    FirstPacketType(u8),
    /// A padding bit set on a packet that is not the last one: "padding
    /// MUST only be added to the last individual packet" (§6.1).
    PaddingNotLast,
    /// The padding count is zero, or larger than what it claims to pad.
    Padding {
        /// The count in the last octet.
        declared: usize,
        /// Octets available to be padding.
        available: usize,
    },
    /// The report count claims more report blocks than the packet holds.
    TruncatedReports {
        /// Octets of report blocks the count asks for.
        declared: usize,
        /// Octets available for them.
        available: usize,
    },
    /// An SDES chunk's item list ran past the packet without reaching its
    /// null terminator.
    UnterminatedChunk,
    /// A BYE's reason length claims more than the packet holds.
    TruncatedReason {
        /// Octets the length octet asks for.
        declared: usize,
        /// Octets available for it.
        available: usize,
    },
    /// A compound packet did not include an SDES CNAME (§6.1).
    MissingCname,
    /// An Extended Report packet (RFC 3611) did not parse.
    ExtendedReport(RtcpXrError),
}

impl fmt::Display for RtcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => write!(f, "{got} octets, {HEADER_LEN} needed for a header"),
            Self::Version(v) => write!(f, "version {v}, not {VERSION}"),
            Self::Truncated {
                declared,
                available,
            } => write!(f, "packet wants {declared} octets, {available} there"),
            Self::LengthMismatch { total, consumed } => {
                write!(
                    f,
                    "{total} octets arrived, individual lengths sum to {consumed}"
                )
            }
            Self::FirstPacketType(pt) => write!(f, "first packet type {pt}, not SR or RR"),
            Self::PaddingNotLast => write!(f, "padding on a packet that is not the last one"),
            Self::Padding {
                declared,
                available,
            } => write!(f, "padding of {declared} octets in {available}"),
            Self::TruncatedReports {
                declared,
                available,
            } => write!(f, "report blocks want {declared} octets, {available} there"),
            Self::UnterminatedChunk => write!(f, "an SDES chunk without a null terminator"),
            Self::TruncatedReason {
                declared,
                available,
            } => write!(f, "BYE reason wants {declared} octets, {available} there"),
            Self::MissingCname => write!(f, "no SDES CNAME in the compound packet"),
            Self::ExtendedReport(error) => write!(f, "extended report: {error}"),
        }
    }
}

impl core::error::Error for RtcpError {}

/// Why a packet could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpBuildError {
    /// The buffer is smaller than the packet.
    Short {
        /// Octets the packet takes.
        need: usize,
        /// Octets offered.
        got: usize,
    },
    /// More reception report blocks than a report count can name.
    TooManyReports(usize),
    /// More SDES chunks than a source count can name.
    TooManyChunks(usize),
    /// More BYE sources than a source count can name.
    TooManySources(usize),
    /// An SDES item's text longer than the eight-bit length field.
    ItemTooLong(usize),
    /// The packet was built and then refused by SRTP.
    Secured(crate::srtp::SrtpError),
    /// A BYE reason longer than the eight-bit length field.
    ReasonTooLong(usize),
    /// The SDES packet being built has no CNAME item in any chunk.
    MissingCname,
    /// The stream agreed to be secured and its keys have not arrived, so
    /// there is nothing to protect the report with. A report goes out in the
    /// clear no more readily than audio does: RFC 3550 §6.5.1 puts the
    /// canonical name in every one of them.
    NotKeyed,
}

impl fmt::Display for RtcpBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Short { need, got } => write!(f, "packet needs {need} octets, {got} offered"),
            Self::TooManyReports(n) => write!(f, "{n} report blocks, {MAX_COUNT} is the most"),
            Self::TooManyChunks(n) => write!(f, "{n} SDES chunks, {MAX_COUNT} is the most"),
            Self::TooManySources(n) => write!(f, "{n} BYE sources, {MAX_COUNT} is the most"),
            Self::ItemTooLong(n) => {
                write!(f, "SDES item of {n} octets, {MAX_TEXT_LEN} is the most")
            }
            Self::ReasonTooLong(n) => {
                write!(f, "BYE reason of {n} octets, {MAX_TEXT_LEN} is the most")
            }
            Self::MissingCname => write!(f, "no SDES CNAME item in any chunk"),
            Self::Secured(error) => write!(f, "the packet could not be protected: {error}"),
            Self::NotKeyed => f.write_str("the stream has no keys yet"),
        }
    }
}

impl core::error::Error for RtcpBuildError {}

#[cfg(test)]
mod tests {
    use super::{
        CNAME, ChunkBuilder, CompoundBuilder, CompoundPacket, GoodbyeBuilder,
        ReceiverReportBuilder, ReportBlock, RtcpBuildError, RtcpError, RtcpPacket, SdesItem,
        SenderInfo, SenderOrReceiver, SenderReportBuilder, SourceDescriptionBuilder, is_rtcp,
        paired_rtcp_port,
    };

    fn cname_chunk<'a>(ssrc: u32, items: &'a [SdesItem<'a>]) -> ChunkBuilder<'a> {
        ChunkBuilder { ssrc, items }
    }

    #[test]
    fn a_sender_report_survives_being_written_and_read_back() {
        let info = SenderInfo {
            ntp: 0x0102_0304_0506_0708,
            rtp_timestamp: 160_000,
            packet_count: 42,
            octet_count: 42 * 160,
        };
        let reports = [ReportBlock {
            ssrc: 0xAAAA_AAAA,
            fraction_lost: 12,
            cumulative_lost: -3,
            extended_highest_sequence: 70_000,
            jitter: 55,
            last_sr: 0x1111_2222,
            delay_since_last_sr: 0x3333_4444,
        }];
        let sr = SenderReportBuilder {
            ssrc: 0xCAFE_BABE,
            info,
            reports: &reports,
        };
        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"doe@192.0.2.10",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(0xCAFE_BABE, cname)],
        };
        let compound = CompoundBuilder::new(SenderOrReceiver::Sender(sr), sdes);

        let mut out = [0_u8; 256];
        let n = compound.write(&mut out).expect("room");
        assert_eq!(n, compound.encoded_len());
        assert_eq!(n % 4, 0, "every RTCP packet ends on a 32-bit boundary");

        let parsed = CompoundPacket::parse(&out[..n]).expect("a compound packet");
        let mut packets = parsed.packets();

        let Some(RtcpPacket::SenderReport(got)) = packets.next() else {
            panic!("a sender report first");
        };
        assert_eq!(got.ssrc(), 0xCAFE_BABE);
        assert_eq!(got.info(), info);
        assert_eq!(got.report_count(), 1);
        assert_eq!(got.reports().collect::<Vec<_>>(), reports);

        let Some(RtcpPacket::SourceDescription(got)) = packets.next() else {
            panic!("an SDES packet second");
        };
        assert_eq!(got.cname(), Some(&b"doe@192.0.2.10"[..]));
        assert!(packets.next().is_none());
    }

    #[test]
    fn a_sender_report_is_laid_out_the_way_section_6_4_1_draws_it() {
        // The round trip above passes whatever order the writer and the
        // reader agree on between themselves. These octets are assembled by
        // hand from the figures of §6.4.1 and §6.5, field by field, so a
        // layout both sides got wrong the same way fails here.
        #[rustfmt::skip]
        let wire: [u8; 80] = [
            // SR: V=2 P=0 RC=1, PT=200, length 12 (13 words: 52 octets)
            0x81, 0xc8, 0x00, 0x0c,
            0xca, 0xfe, 0xba, 0xbe, // SSRC of sender
            0x01, 0x02, 0x03, 0x04, // NTP timestamp, most significant word
            0x05, 0x06, 0x07, 0x08, // NTP timestamp, least significant word
            0x00, 0x02, 0x71, 0x00, // RTP timestamp 160 000
            0x00, 0x00, 0x00, 0x2a, // sender's packet count 42
            0x00, 0x00, 0x1a, 0x40, // sender's octet count 6 720
            0xaa, 0xaa, 0xaa, 0xaa, // SSRC_1
            0x0c, 0xff, 0xff, 0xfd, // fraction lost 12, cumulative lost -3 in 24 bits
            0x00, 0x01, 0x11, 0x70, // extended highest sequence number 70 000
            0x00, 0x00, 0x00, 0x37, // interarrival jitter 55
            0x11, 0x11, 0x22, 0x22, // last SR
            0x33, 0x33, 0x44, 0x44, // delay since last SR
            // SDES: V=2 P=0 SC=1, PT=202, length 6 (7 words: 28 octets)
            0x81, 0xca, 0x00, 0x06,
            0xca, 0xfe, 0xba, 0xbe, // SSRC of the chunk
            0x01, 0x0e,             // CNAME, 14 octets
            b'd', b'o', b'e', b'@', b'1', b'9', b'2', b'.', b'0', b'.', b'2', b'.', b'1', b'0',
            0x00, 0x00, 0x00, 0x00, // the terminating null item and padding to a word
        ];
        let info = SenderInfo {
            ntp: 0x0102_0304_0506_0708,
            rtp_timestamp: 160_000,
            packet_count: 42,
            octet_count: 6_720,
        };
        let reports = [ReportBlock {
            ssrc: 0xAAAA_AAAA,
            fraction_lost: 12,
            cumulative_lost: -3,
            extended_highest_sequence: 70_000,
            jitter: 55,
            last_sr: 0x1111_2222,
            delay_since_last_sr: 0x3333_4444,
        }];
        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"doe@192.0.2.10",
        }];
        let chunks = [cname_chunk(0xCAFE_BABE, cname)];
        let compound = CompoundBuilder::new(
            SenderOrReceiver::Sender(SenderReportBuilder {
                ssrc: 0xCAFE_BABE,
                info,
                reports: &reports,
            }),
            SourceDescriptionBuilder { chunks: &chunks },
        );
        let mut out = [0_u8; 128];
        let n = compound.write(&mut out).expect("room");
        assert_eq!(out.get(..n), Some(&wire[..]));

        // and the reader takes the same octets to the same fields
        let parsed = CompoundPacket::parse(&wire).expect("a compound packet");
        let Some(RtcpPacket::SenderReport(got)) = parsed.packets().next() else {
            panic!("a sender report first");
        };
        assert_eq!(got.ssrc(), 0xCAFE_BABE);
        assert_eq!(got.info(), info);
        assert_eq!(got.reports().collect::<Vec<_>>(), reports);
    }

    #[test]
    fn a_receiver_report_and_a_bye_round_trip_together() {
        let rr = ReceiverReportBuilder {
            ssrc: 7,
            reports: &[],
        };
        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"7@203.0.113.4",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(7, cname)],
        };
        let bye = GoodbyeBuilder {
            sources: &[7],
            reason: b"call ended",
        };
        let compound = CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes).with_bye(bye);

        let mut out = [0_u8; 256];
        let n = compound.write(&mut out).expect("room");
        let parsed = CompoundPacket::parse(&out[..n]).expect("a compound packet");
        let mut packets = parsed.packets();

        assert!(matches!(
            packets.next(),
            Some(RtcpPacket::ReceiverReport(_))
        ));
        assert!(matches!(
            packets.next(),
            Some(RtcpPacket::SourceDescription(_))
        ));
        let Some(RtcpPacket::Goodbye(got)) = packets.next() else {
            panic!("a goodbye third");
        };
        assert_eq!(got.sources().collect::<Vec<_>>(), [7]);
        assert_eq!(got.reason(), Some(&b"call ended"[..]));
    }

    #[test]
    fn an_empty_receiver_report_is_still_a_valid_report_block_count() {
        // §6.4.2: "An empty RR packet (RC = 0) MUST be put at the head of a
        // compound RTCP packet when there is no data transmission or
        // reception to report"
        let rr = ReceiverReportBuilder {
            ssrc: 1,
            reports: &[],
        };
        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"1@203.0.113.4",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(1, cname)],
        };
        let compound = CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes);
        let mut out = [0_u8; 128];
        let n = compound.write(&mut out).expect("room");
        let parsed = CompoundPacket::parse(&out[..n]).expect("a compound packet");
        let Some(RtcpPacket::ReceiverReport(got)) = parsed.packets().next() else {
            panic!("a receiver report");
        };
        assert_eq!(got.report_count(), 0);
    }

    #[test]
    fn an_unrecognised_packet_type_is_skipped_not_refused() {
        // §6.1: "An implementation SHOULD ignore incoming RTCP packets with
        // types unknown to it" — an APP packet (or anything else) between
        // the mandatory pieces must not stop the rest from being read.
        let rr = ReceiverReportBuilder {
            ssrc: 9,
            reports: &[],
        };
        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"9",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(9, cname)],
        };
        let compound = CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes);
        let mut out = [0_u8; 256];
        let n = compound.write(&mut out).expect("room");

        // splice in a four-word APP-shaped packet ahead of the SDES: PT=204,
        // an SSRC, a name, and one word of data
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&out[..8]); // RR header + SSRC
        spliced.extend_from_slice(&[
            0x80, 204, 0, 3, 0, 0, 0, 1, b'n', b'a', b'm', b'e', 1, 2, 3, 4,
        ]);
        spliced.extend_from_slice(&out[8..n]);

        let parsed = CompoundPacket::parse(&spliced).expect("a compound packet");
        let mut packets = parsed.packets();
        assert!(matches!(
            packets.next(),
            Some(RtcpPacket::ReceiverReport(_))
        ));
        assert!(matches!(
            packets.next(),
            Some(RtcpPacket::Other { packet_type: 204 })
        ));
        assert!(matches!(
            packets.next(),
            Some(RtcpPacket::SourceDescription(_))
        ));
    }

    #[test]
    fn the_first_packet_must_be_sr_or_rr() {
        // A.2: "The payload type field of the first RTCP packet in a
        // compound packet must be equal to SR or RR"
        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"x",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(1, cname)],
        };
        let mut out = [0_u8; 64];
        let n = sdes.write(&mut out).expect("room");
        assert_eq!(
            CompoundPacket::parse(&out[..n]),
            Err(RtcpError::FirstPacketType(202))
        );
    }

    #[test]
    fn a_compound_packet_without_a_cname_is_refused() {
        // §6.1: "each compound RTCP packet MUST also include the SDES
        // CNAME"
        let rr = ReceiverReportBuilder {
            ssrc: 1,
            reports: &[],
        };
        let name: &[SdesItem<'_>] = &[SdesItem {
            kind: 2, // NAME, not CNAME
            text: b"someone",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(1, name)],
        };
        assert_eq!(
            CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes).write(&mut [0_u8; 64]),
            Err(RtcpBuildError::MissingCname)
        );

        // and the same packet, built by hand without going through the
        // builder's own check, is refused on the way back in too
        let mut out = [0_u8; 64];
        let mut at = rr.write(&mut out).expect("room");
        at += sdes.write(out.get_mut(at..).expect("room")).unwrap_or(0);
        assert_eq!(
            CompoundPacket::parse(&out[..at]),
            Err(RtcpError::MissingCname)
        );
    }

    #[test]
    fn padding_is_only_allowed_on_the_last_packet() {
        let mut out = [0_u8; 8];
        out[0] = 0b1010_0000; // V=2, P=1, RC=0
        out[1] = 201; // RR
        out[3] = 1; // length: one word beyond the header, i.e. 8 octets total
        // ssrc word doubles as the padding word; last octet says "pad 4"
        out[7] = 4;

        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"x",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(1, cname)],
        };
        let mut sdes_bytes = [0_u8; 32];
        let n = sdes.write(&mut sdes_bytes).expect("room");

        let mut spliced = Vec::new();
        spliced.extend_from_slice(&out);
        spliced.extend_from_slice(&sdes_bytes[..n]);
        assert_eq!(
            CompoundPacket::parse(&spliced),
            Err(RtcpError::PaddingNotLast)
        );
    }

    #[test]
    fn the_padding_count_must_fit_and_must_not_be_zero() {
        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"x",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(1, cname)],
        };
        let mut sdes_bytes = [0_u8; 32];
        let sdes_n = sdes.write(&mut sdes_bytes).expect("room");

        let mut rr = [0_u8; 8];
        rr[0] = 0b1000_0000;
        rr[1] = 201;
        rr[3] = 1;

        let mut padded = [0_u8; 8];
        padded[0] = 0b1010_0000;
        padded[1] = 201;
        padded[3] = 1;
        padded[7] = 200; // more padding than the packet holds

        let mut spliced = Vec::new();
        spliced.extend_from_slice(&rr);
        spliced.extend_from_slice(&sdes_bytes[..sdes_n]);
        spliced.extend_from_slice(&padded);
        assert!(matches!(
            CompoundPacket::parse(&spliced),
            Err(RtcpError::Padding { .. })
        ));
    }

    #[test]
    fn cumulative_lost_saturates_at_the_24_bit_signed_bounds() {
        // A.3: "clamped at 0x7fffff for positive loss or 0x800000 for
        // negative loss rather than wrapping"
        let reports = [
            ReportBlock {
                cumulative_lost: i32::MAX,
                ..ReportBlock::default()
            },
            ReportBlock {
                cumulative_lost: i32::MIN,
                ..ReportBlock::default()
            },
        ];
        let rr = ReceiverReportBuilder {
            ssrc: 1,
            reports: &reports,
        };
        let mut out = [0_u8; 128];
        rr.write(&mut out).expect("room");

        let cname: &[SdesItem<'_>] = &[SdesItem {
            kind: CNAME,
            text: b"x",
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(1, cname)],
        };
        let compound = CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes);
        let mut out = [0_u8; 256];
        let n = compound.write(&mut out).expect("room");
        let parsed = CompoundPacket::parse(&out[..n]).expect("a compound packet");
        let Some(RtcpPacket::ReceiverReport(got)) = parsed.packets().next() else {
            panic!("a receiver report");
        };
        let blocks: Vec<_> = got.reports().collect();
        assert_eq!(blocks.first().map(|b| b.cumulative_lost), Some(0x007F_FFFF));
        assert_eq!(blocks.get(1).map(|b| b.cumulative_lost), Some(-0x0080_0000));
    }

    #[test]
    fn a_datagram_shorter_than_a_header_is_not_a_packet() {
        assert_eq!(
            CompoundPacket::parse(&[0x80, 200, 0]),
            Err(RtcpError::TooShort { got: 3 })
        );
    }

    #[test]
    fn the_version_must_be_two() {
        let mut packet = [0_u8; 8];
        packet[0] = 0b0000_0000;
        packet[1] = 200;
        assert_eq!(CompoundPacket::parse(&packet), Err(RtcpError::Version(0)));
    }

    #[test]
    fn the_declared_length_must_fit_and_must_add_up() {
        let mut packet = [0_u8; 8];
        packet[0] = 0b1000_0000;
        packet[1] = 200;
        packet[3] = 5; // claims 24 octets, only 8 are there
        assert_eq!(
            CompoundPacket::parse(&packet),
            Err(RtcpError::Truncated {
                declared: 24,
                available: 8,
            })
        );
    }

    #[test]
    fn writing_refuses_more_entries_than_a_five_bit_count_can_name() {
        let reports = [ReportBlock::default(); 32];
        let rr = ReceiverReportBuilder {
            ssrc: 1,
            reports: &reports,
        };
        assert_eq!(
            rr.write(&mut [0_u8; 4096]),
            Err(RtcpBuildError::TooManyReports(32))
        );
    }

    #[test]
    fn writing_into_a_buffer_that_is_too_small_writes_nothing_useful() {
        let rr = ReceiverReportBuilder {
            ssrc: 1,
            reports: &[],
        };
        let mut small = [0xFF_u8; 4];
        assert_eq!(
            rr.write(&mut small),
            Err(RtcpBuildError::Short { need: 8, got: 4 })
        );
    }

    #[test]
    fn an_sdes_item_reads_back_exactly_what_was_written_including_a_zero_length_one() {
        let items: &[SdesItem<'_>] = &[
            SdesItem {
                kind: CNAME,
                text: b"a@b",
            },
            SdesItem {
                kind: 7, // NOTE
                text: b"",
            },
        ];
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(1, items)],
        };
        let mut out = [0_u8; 64];
        let n = sdes.write(&mut out).expect("room");
        assert_eq!(n % 4, 0);

        let rr = ReceiverReportBuilder {
            ssrc: 1,
            reports: &[],
        };
        let mut compound_out = [0_u8; 128];
        let mut at = rr.write(&mut compound_out).expect("room");
        at += sdes
            .write(compound_out.get_mut(at..).expect("room"))
            .unwrap_or(0);

        let parsed = CompoundPacket::parse(&compound_out[..at]).expect("a compound packet");
        let Some(RtcpPacket::SourceDescription(got)) = parsed
            .packets()
            .find(|p| matches!(p, RtcpPacket::SourceDescription(_)))
        else {
            panic!("an SDES packet");
        };
        let chunk = got.chunks().next().expect("one chunk");
        let read: Vec<_> = chunk.items().collect();
        assert_eq!(read, items);
    }

    #[test]
    fn is_rtcp_reads_the_mux_range_from_the_second_octet_rfc5761_s4() {
        // §4 reserves 209-223 and then 194-199 for RTCP types not yet
        // assigned, and blocks RTP payload types 64-95 -- 192-223 with the
        // marker bit -- to pay for it. The whole span belongs to RTCP, so a
        // type registered after this was written still does not reach the
        // audio path.
        assert!(!is_rtcp(&[0x80, 191]));
        assert!(is_rtcp(&[0x80, 192])); // the obsolete FIR
        assert!(is_rtcp(&[0x80, 195])); // second range offered to new types
        assert!(is_rtcp(&[0x80, 200])); // SR
        assert!(is_rtcp(&[0x80, 208])); // RSI, the last one assigned
        assert!(is_rtcp(&[0x80, 220])); // first range offered to new types
        assert!(is_rtcp(&[0x80, 223]));
        assert!(!is_rtcp(&[0x80, 224]));
        assert!(!is_rtcp(&[0x80])); // no second octet at all
        assert!(!is_rtcp(&[]));
    }

    #[test]
    fn the_rtcp_port_is_one_higher_than_an_even_rtp_port() {
        assert_eq!(paired_rtcp_port(5004), 5005);
        assert_eq!(paired_rtcp_port(5005), 5005, "already odd, left alone");
        assert_eq!(paired_rtcp_port(u16::MAX - 1), u16::MAX);
    }
}
