// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Reduced-size RTCP (RFC 5506): feedback sent without the report and the
//! CNAME that RFC 3550 §6.1 puts in front of every compound packet, and
//! the rules for when that is allowed.
//!
//! A reduced-size packet is told apart from a compound one by its first
//! individual packet: a compound packet starts with SR or RR, a reduced-size
//! one need not (RFC 5506 §3.4.2, §4.1). Everything else A.2 of RFC 3550
//! checks still applies — version 2 throughout, padding only on the last
//! packet, lengths that add up to the datagram — and so does the rule that
//! only a session which negotiated `a=rtcp-rsize` sees one at all.

use core::fmt;

use super::feedback::{
    FeedbackBuildError, FeedbackError, FeedbackPacket, GenericNackBuilder, HEADER_LEN,
};
use crate::rtcp::{CompoundBuilder, CompoundPacket, RtcpError};
use crate::wire::VERSION;

/// The packet types that open a compound packet (RFC 3550 §6.1).
const SR: u8 = 200;
const RR: u8 = 201;
/// A 32-bit word, what the RTCP length field counts in.
const WORD_LEN: usize = 4;

/// The two shapes an RTCP datagram can take in an RFC 5506 session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpForm {
    /// SR or RR first, then SDES with a CNAME (RFC 3550 §6.1).
    Compound,
    /// Anything else first: feedback on its own (RFC 5506 §4.1).
    ReducedSize,
}

/// Which kind of transmission slot a packet is about to fill (RFC 4585
/// §3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// A Regular RTCP packet, at the interval RFC 3550 §6.3 schedules.
    Regular,
    /// An Early RTCP packet, sent ahead of that interval to carry feedback.
    Early,
}

/// When reduced-size RTCP may be sent (RFC 5506 §4 and §5).
///
/// Reduced size is only ever a choice for an Early packet: every Regular
/// packet stays compound, so the reports and the CNAME keep flowing at the
/// interval RFC 3550 sets. Nor is it a choice before this participant's
/// first compound packet has gone out, since that is what tells the peer
/// who it is. And none of it applies unless both ends said `a=rtcp-rsize`:
/// without the attribute in the answer as well as the offer, the session
/// falls back to compound RTCP throughout (§5), and a renegotiation that
/// drops the attribute falls back the same way from that moment on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReducedSize {
    negotiated: bool,
    compound_sent: bool,
}

impl ReducedSize {
    /// The policy for a session whose offer and answer did — or did not —
    /// both carry `a=rtcp-rsize`; see
    /// [`rsize_negotiated`](super::rsize_negotiated).
    #[must_use]
    pub const fn new(negotiated: bool) -> Self {
        Self {
            negotiated,
            compound_sent: false,
        }
    }

    /// Whether the last offer/answer exchange negotiated reduced size.
    #[must_use]
    pub const fn negotiated(&self) -> bool {
        self.negotiated
    }

    /// A later offer/answer exchange settled the question again. Dropping
    /// the attribute takes effect for the very next packet.
    pub const fn renegotiated(&mut self, negotiated: bool) {
        self.negotiated = negotiated;
    }

    /// The form the next packet in `slot` must take.
    #[must_use]
    pub const fn form(&self, slot: Slot) -> RtcpForm {
        match slot {
            Slot::Early if self.negotiated && self.compound_sent => RtcpForm::ReducedSize,
            Slot::Early | Slot::Regular => RtcpForm::Compound,
        }
    }

    /// A packet of `form` went out.
    pub const fn sent(&mut self, form: RtcpForm) {
        if matches!(form, RtcpForm::Compound) {
            self.compound_sent = true;
        }
    }

    /// Whether a received datagram of `form` is acceptable: a compound one
    /// always, a reduced-size one only once negotiated.
    #[must_use]
    pub const fn accepts(&self, form: RtcpForm) -> bool {
        matches!(form, RtcpForm::Compound) || self.negotiated
    }
}

/// One individual packet out of an RTCP datagram, sliced by its own length
/// field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawPacket<'a> {
    bytes: &'a [u8],
}

impl<'a> RawPacket<'a> {
    /// The packet type.
    #[must_use]
    pub fn packet_type(&self) -> u8 {
        self.bytes.get(1).copied().unwrap_or_default()
    }

    /// The five-bit count, or FMT for a feedback message.
    #[must_use]
    pub fn count(&self) -> u8 {
        self.bytes.first().map_or(0, |flags| flags & 0b0001_1111)
    }

    /// The whole packet, header and any padding included.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The packet as a feedback message, when it is one.
    #[must_use]
    pub fn feedback(&self) -> Option<FeedbackPacket<'a>> {
        FeedbackPacket::parse(self.bytes).ok()
    }
}

/// Split one individual packet off the front of `datagram` by its length
/// field.
fn split(datagram: &[u8]) -> Result<(&[u8], &[u8]), ReceiveError> {
    let Some(&[flags, _, hi, lo]) = datagram.first_chunk::<HEADER_LEN>() else {
        return Err(ReceiveError::TooShort {
            got: datagram.len(),
        });
    };
    let version = flags >> 6;
    if version != VERSION {
        return Err(ReceiveError::Version(version));
    }
    let words = usize::from(u16::from_be_bytes([hi, lo]));
    let total = words.saturating_add(1).saturating_mul(WORD_LEN);
    datagram
        .split_at_checked(total)
        .ok_or(ReceiveError::Truncated {
            declared: total,
            available: datagram.len(),
        })
}

/// The individual packets of a [`ReceivedRtcp`], in order.
#[derive(Clone, Debug)]
pub struct RawPackets<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for RawPackets<'a> {
    type Item = RawPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (bytes, rest) = split(self.rest).ok()?;
        self.rest = rest;
        Some(RawPacket { bytes })
    }
}

/// An RTCP datagram, compound or reduced-size, that passed the checks its
/// form calls for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedRtcp<'a> {
    datagram: &'a [u8],
    form: RtcpForm,
}

impl<'a> ReceivedRtcp<'a> {
    /// Read a datagram under `policy`.
    ///
    /// SR or RR first means compound, and the whole of RFC 3550's
    /// validation applies through [`CompoundPacket::parse`]. Anything else
    /// is reduced size, refused unless the session negotiated it; accepted,
    /// it gets the checks RFC 5506 §3.4.2 keeps — version 2 in every packet,
    /// padding only on the last, lengths adding up exactly. Either way,
    /// every feedback message inside must itself parse.
    ///
    /// # Errors
    /// [`ReceiveError`], naming what did not hold.
    pub fn parse(datagram: &'a [u8], policy: &ReducedSize) -> Result<Self, ReceiveError> {
        let (first, _) = split(datagram)?;
        let form = match first.get(1) {
            Some(&SR | &RR) => RtcpForm::Compound,
            _ => RtcpForm::ReducedSize,
        };
        if !policy.accepts(form) {
            return Err(ReceiveError::NotNegotiated);
        }
        if form == RtcpForm::Compound {
            CompoundPacket::parse(datagram).map_err(ReceiveError::Compound)?;
        }
        let mut rest = datagram;
        while !rest.is_empty() {
            let (packet, next) = split(rest)?;
            let padded = packet
                .first()
                .is_some_and(|&flags| flags & 0b0010_0000 != 0);
            if padded && !next.is_empty() {
                return Err(ReceiveError::PaddingNotLast);
            }
            if packet
                .get(1)
                .is_some_and(|&pt| FeedbackPacket::is_feedback(pt))
            {
                FeedbackPacket::parse(packet).map_err(ReceiveError::Feedback)?;
            }
            rest = next;
        }
        Ok(Self { datagram, form })
    }

    /// Which form the datagram took.
    #[must_use]
    pub const fn form(&self) -> RtcpForm {
        self.form
    }

    /// The compound packet, for the reports and descriptions a compound
    /// datagram carries; `None` for a reduced-size one.
    #[must_use]
    pub fn compound(&self) -> Option<CompoundPacket<'a>> {
        match self.form {
            RtcpForm::Compound => CompoundPacket::parse(self.datagram).ok(),
            RtcpForm::ReducedSize => None,
        }
    }

    /// Every individual packet, in order.
    #[must_use]
    pub fn packets(&self) -> RawPackets<'a> {
        RawPackets {
            rest: self.datagram,
        }
    }

    /// The feedback messages, in order.
    pub fn feedback(&self) -> impl Iterator<Item = FeedbackPacket<'a>> + use<'a> {
        self.packets().filter_map(|packet| packet.feedback())
    }
}

/// Writes a reduced-size RTCP packet: Generic NACKs and nothing else, the
/// first of them where a compound packet's report would be (RFC 5506 §4.1).
#[derive(Clone, Copy, Debug)]
pub struct ReducedSizeBuilder<'a> {
    /// The NACKs to send, at least one.
    pub nacks: &'a [GenericNackBuilder<'a>],
}

impl ReducedSizeBuilder<'_> {
    /// How many octets [`ReducedSizeBuilder::write`] needs.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.nacks
            .iter()
            .map(GenericNackBuilder::encoded_len)
            .fold(0, usize::saturating_add)
    }

    /// Write the packet, returning how many octets it took. Whether reduced
    /// size is allowed right now is [`ReducedSize::form`]'s to say; this
    /// only writes.
    ///
    /// # Errors
    /// [`FeedbackBuildError`]: nothing to send, or one NACK that cannot be
    /// written.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, FeedbackBuildError> {
        if self.nacks.is_empty() {
            return Err(FeedbackBuildError::Empty);
        }
        write_all(self.nacks, out, 0)
    }
}

/// Write a compound packet with Generic NACKs after it (RFC 4585 §3.1):
/// the report and the CNAME first as always, the feedback following. A
/// compound built with a goodbye puts the goodbye before the feedback, so
/// feedback belongs in a packet that is not also the last one.
///
/// # Errors
/// [`FeedbackBuildError`], from either half.
pub fn write_compound_with_feedback(
    compound: &CompoundBuilder<'_>,
    nacks: &[GenericNackBuilder<'_>],
    out: &mut [u8],
) -> Result<usize, FeedbackBuildError> {
    let need = nacks
        .iter()
        .map(GenericNackBuilder::encoded_len)
        .fold(compound.encoded_len(), usize::saturating_add);
    if out.len() < need {
        return Err(FeedbackBuildError::Short {
            need,
            got: out.len(),
        });
    }
    let at = compound.write(out).map_err(FeedbackBuildError::Compound)?;
    write_all(nacks, out, at)
}

fn write_all(
    nacks: &[GenericNackBuilder<'_>],
    out: &mut [u8],
    mut at: usize,
) -> Result<usize, FeedbackBuildError> {
    for nack in nacks {
        let room = out.get_mut(at..).unwrap_or_default();
        at = at.saturating_add(nack.write(room)?);
    }
    Ok(at)
}

/// Why an RTCP datagram was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveError {
    /// Shorter than one packet's header.
    TooShort {
        /// What arrived.
        got: usize,
    },
    /// Not version 2 (RFC 3550 A.2).
    Version(u8),
    /// A length field claims more than the datagram holds.
    Truncated {
        /// Octets the length field asks for.
        declared: usize,
        /// Octets actually there.
        available: usize,
    },
    /// Padding on a packet that is not the last one (RFC 3550 §6.1).
    PaddingNotLast,
    /// A reduced-size datagram in a session that did not negotiate
    /// `a=rtcp-rsize`.
    NotNegotiated,
    /// The compound datagram failed RFC 3550's own validation.
    Compound(RtcpError),
    /// A feedback message inside did not parse.
    Feedback(FeedbackError),
}

impl fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => write!(f, "{got} octets, {HEADER_LEN} needed for a header"),
            Self::Version(v) => write!(f, "version {v}, not {VERSION}"),
            Self::Truncated {
                declared,
                available,
            } => write!(f, "packet wants {declared} octets, {available} there"),
            Self::PaddingNotLast => f.write_str("padding on a packet that is not the last one"),
            Self::NotNegotiated => f.write_str("reduced-size RTCP was not negotiated"),
            Self::Compound(error) => write!(f, "compound packet: {error}"),
            Self::Feedback(error) => write!(f, "feedback: {error}"),
        }
    }
}

impl core::error::Error for ReceiveError {}

#[cfg(test)]
mod tests {
    use super::{
        ReceiveError, ReceivedRtcp, ReducedSize, ReducedSizeBuilder, RtcpForm, Slot,
        write_compound_with_feedback,
    };
    use crate::avpf::feedback::{
        FeedbackBuildError, FeedbackPacket, GenericNackBuilder, NackEntry,
    };
    use crate::{
        CNAME, ChunkBuilder, CompoundBuilder, GoodbyeBuilder, ReceiverReportBuilder, SdesItem,
        SenderOrReceiver, SourceDescriptionBuilder,
    };

    const LOCAL: u32 = 0x0A0B_0C0D;
    const REMOTE: u32 = 0x0102_0304;

    fn reduced(entries: &[&[NackEntry]]) -> Vec<u8> {
        let nacks: Vec<GenericNackBuilder<'_>> = entries
            .iter()
            .map(|entries| GenericNackBuilder {
                sender_ssrc: LOCAL,
                media_ssrc: REMOTE,
                entries,
            })
            .collect();
        let builder = ReducedSizeBuilder { nacks: &nacks };
        let mut out = vec![0; builder.encoded_len()];
        assert_eq!(builder.write(&mut out), Ok(out.len()));
        out
    }

    fn compound(entries: &[NackEntry], bye: bool) -> Vec<u8> {
        let items = [SdesItem {
            kind: CNAME,
            text: b"alice@example.com",
        }];
        let chunks = [ChunkBuilder {
            ssrc: LOCAL,
            items: &items,
        }];
        let mut builder = CompoundBuilder::new(
            SenderOrReceiver::Receiver(ReceiverReportBuilder {
                ssrc: LOCAL,
                reports: &[],
            }),
            SourceDescriptionBuilder { chunks: &chunks },
        );
        if bye {
            builder = builder.with_bye(GoodbyeBuilder {
                sources: &[LOCAL],
                reason: b"",
            });
        }
        let nacks = [GenericNackBuilder {
            sender_ssrc: LOCAL,
            media_ssrc: REMOTE,
            entries,
        }];
        let mut out = vec![0; 256];
        let n = write_compound_with_feedback(&builder, &nacks, &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn lost(received: &ReceivedRtcp<'_>) -> Vec<u16> {
        received
            .feedback()
            .flat_map(|packet| match packet {
                FeedbackPacket::GenericNack(nack) => nack.lost().collect::<Vec<_>>(),
                FeedbackPacket::Other { .. } => Vec::new(),
            })
            .collect()
    }

    #[test]
    fn a_reduced_size_packet_round_trips_when_negotiated() {
        let bytes = reduced(&[&NackEntry::pack([10, 11, 26]), &NackEntry::pack([65535, 0])]);
        assert_eq!(bytes[1], 205, "feedback first, no report in front");
        let received = ReceivedRtcp::parse(&bytes, &ReducedSize::new(true)).unwrap();
        assert_eq!(received.form(), RtcpForm::ReducedSize);
        assert!(received.compound().is_none());
        assert_eq!(received.packets().count(), 2);
        assert_eq!(lost(&received), [10, 11, 26, 65535, 0]);
    }

    #[test]
    fn a_reduced_size_packet_is_refused_when_not_negotiated() {
        let bytes = reduced(&[&[NackEntry::new(1)]]);
        assert_eq!(
            ReceivedRtcp::parse(&bytes, &ReducedSize::new(false)),
            Err(ReceiveError::NotNegotiated)
        );
    }

    #[test]
    fn a_compound_packet_carries_feedback_after_the_cname() {
        let bytes = compound(&NackEntry::pack([7, 9]), false);
        for policy in [ReducedSize::new(false), ReducedSize::new(true)] {
            let received = ReceivedRtcp::parse(&bytes, &policy).unwrap();
            assert_eq!(received.form(), RtcpForm::Compound);
            assert!(received.compound().is_some());
            let types: Vec<u8> = received.packets().map(|p| p.packet_type()).collect();
            assert_eq!(types, [201, 202, 205]);
            assert_eq!(lost(&received), [7, 9]);
        }
    }

    #[test]
    fn a_compound_packet_keeps_rfc_3550_validation() {
        let mut bytes = compound(&[NackEntry::new(1)], false);
        // turn the SDES into an APP packet: no CNAME left
        bytes[8] = (bytes[8] & 0b1110_0000) | 1;
        bytes[9] = 204;
        assert!(matches!(
            ReceivedRtcp::parse(&bytes, &ReducedSize::new(true)),
            Err(ReceiveError::Compound(crate::RtcpError::MissingCname))
        ));
    }

    #[test]
    fn a_goodbye_comes_before_feedback_written_with_it() {
        let bytes = compound(&[NackEntry::new(1)], true);
        let received = ReceivedRtcp::parse(&bytes, &ReducedSize::new(false)).unwrap();
        let types: Vec<u8> = received.packets().map(|p| p.packet_type()).collect();
        assert_eq!(types, [201, 202, 203, 205]);
    }

    #[test]
    fn a_malformed_nack_inside_either_form_is_refused() {
        let mut bytes = reduced(&[&[NackEntry::new(1)]]);
        bytes[2..4].copy_from_slice(&2_u16.to_be_bytes());
        bytes.truncate(12);
        assert!(matches!(
            ReceivedRtcp::parse(&bytes, &ReducedSize::new(true)),
            Err(ReceiveError::Feedback(_))
        ));
    }

    #[test]
    fn padding_is_allowed_only_on_the_last_packet() {
        let mut bytes = reduced(&[&[NackEntry::new(1)], &[NackEntry::new(2)]]);
        let policy = ReducedSize::new(true);
        bytes[0] |= 0b0010_0000;
        assert_eq!(
            ReceivedRtcp::parse(&bytes, &policy),
            Err(ReceiveError::PaddingNotLast)
        );
        bytes[0] &= !0b0010_0000;
        // pad the last packet by one word
        bytes[16] |= 0b0010_0000;
        bytes[18..20].copy_from_slice(&4_u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 4]);
        let received = ReceivedRtcp::parse(&bytes, &policy).unwrap();
        assert_eq!(lost(&received), [1, 2]);
    }

    #[test]
    fn lengths_must_add_up() {
        let bytes = reduced(&[&[NackEntry::new(1)]]);
        let policy = ReducedSize::new(true);
        assert!(matches!(
            ReceivedRtcp::parse(&bytes[..bytes.len() - 1], &policy),
            Err(ReceiveError::Truncated { .. })
        ));
        let mut longer = bytes.clone();
        longer.extend_from_slice(&[0x80]);
        assert!(matches!(
            ReceivedRtcp::parse(&longer, &policy),
            Err(ReceiveError::TooShort { got: 1 })
        ));
        let mut version = bytes;
        version[0] = 0x01;
        assert_eq!(
            ReceivedRtcp::parse(&version, &policy),
            Err(ReceiveError::Version(0))
        );
    }

    #[test]
    fn an_empty_reduced_size_packet_is_not_written() {
        let builder = ReducedSizeBuilder { nacks: &[] };
        assert_eq!(builder.write(&mut [0; 16]), Err(FeedbackBuildError::Empty));
    }

    #[test]
    fn a_short_buffer_is_refused_before_anything_is_written() {
        let items = [SdesItem {
            kind: CNAME,
            text: b"a",
        }];
        let chunks = [ChunkBuilder {
            ssrc: LOCAL,
            items: &items,
        }];
        let builder = CompoundBuilder::new(
            SenderOrReceiver::Receiver(ReceiverReportBuilder {
                ssrc: LOCAL,
                reports: &[],
            }),
            SourceDescriptionBuilder { chunks: &chunks },
        );
        let entries = [NackEntry::new(1)];
        let nacks = [GenericNackBuilder {
            sender_ssrc: LOCAL,
            media_ssrc: REMOTE,
            entries: &entries,
        }];
        let need = builder.encoded_len() + 16;
        let mut out = vec![0; need - 1];
        assert_eq!(
            write_compound_with_feedback(&builder, &nacks, &mut out),
            Err(FeedbackBuildError::Short {
                need,
                got: need - 1
            })
        );
    }

    #[test]
    fn regular_packets_stay_compound_and_the_first_packet_is_compound() {
        let mut policy = ReducedSize::new(true);
        assert_eq!(policy.form(Slot::Early), RtcpForm::Compound);
        assert_eq!(policy.form(Slot::Regular), RtcpForm::Compound);
        policy.sent(RtcpForm::Compound);
        assert_eq!(policy.form(Slot::Early), RtcpForm::ReducedSize);
        assert_eq!(policy.form(Slot::Regular), RtcpForm::Compound);
    }

    #[test]
    fn without_negotiation_everything_falls_back_to_compound() {
        let mut policy = ReducedSize::new(false);
        policy.sent(RtcpForm::Compound);
        assert_eq!(policy.form(Slot::Early), RtcpForm::Compound);
        let mut dropped = ReducedSize::new(true);
        dropped.sent(RtcpForm::Compound);
        dropped.renegotiated(false);
        assert!(!dropped.negotiated());
        assert_eq!(dropped.form(Slot::Early), RtcpForm::Compound);
        assert!(!dropped.accepts(RtcpForm::ReducedSize));
        dropped.renegotiated(true);
        assert_eq!(dropped.form(Slot::Early), RtcpForm::ReducedSize);
    }

    #[test]
    fn a_reduced_size_packet_sent_does_not_count_as_the_first_compound() {
        let mut policy = ReducedSize::new(true);
        policy.sent(RtcpForm::ReducedSize);
        assert_eq!(policy.form(Slot::Early), RtcpForm::Compound);
    }

    /// A small deterministic generator, so the corpus is the same on every
    /// run without a dependency.
    fn next(state: &mut u64) -> u8 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (*state >> 56) as u8
    }

    #[test]
    fn malformed_datagrams_never_panic() {
        let seeds = [
            reduced(&[&NackEntry::pack([1, 2, 30])]),
            compound(&NackEntry::pack([5]), true),
        ];
        let policies = [ReducedSize::new(true), ReducedSize::new(false)];
        let walk = |bytes: &[u8]| {
            for policy in &policies {
                if let Ok(received) = ReceivedRtcp::parse(bytes, policy) {
                    let _ = received.compound();
                    for packet in received.packets() {
                        let _ = (packet.count(), packet.bytes(), packet.feedback());
                    }
                    let _ = lost(&received);
                }
            }
        };
        for seed in &seeds {
            for cut in 0..=seed.len() {
                walk(&seed[..cut]);
            }
            for at in 0..seed.len() {
                for value in [0x00, 0x20, 0x7F, 0x80, 0xA0, 0xFF] {
                    let mut mutated = seed.clone();
                    mutated[at] = value;
                    walk(&mutated);
                }
            }
        }
        let mut state = 7;
        for len in 0..512 {
            let mut bytes: Vec<u8> = (0..len % 64).map(|_| next(&mut state)).collect();
            if let Some(first) = bytes.first_mut() {
                *first = 0x80 | (*first & 0x3F);
            }
            walk(&bytes);
        }
    }
}
