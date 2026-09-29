// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RTP/AVPF in a running stream: which packets to report lost, in which kind
//! of RTCP packet and when, and what the far end reported.
//!
//! [`crate::RtpSession::use_feedback`] turns it on for a stream whose offer
//! and answer both named a feedback profile; from then on the session's RTCP
//! is scheduled by [`AvpfTimer`] rather than by RFC 3550 alone. A packet that
//! arrives more than one ahead of the highest one seen leaves the ones in
//! between missing, and when Generic NACKs were negotiated those are the
//! feedback: an Early RTCP packet at once while `allow_early` holds (RFC 4585
//! §3.5.2, and in a two-party call `T_dither_max` is zero), otherwise the
//! next Regular one. A missing packet that turns up before its NACK goes is
//! taken off the list, since it is no longer missing.
//!
//! **Nothing is sent again in answer to a NACK.** Retransmission belongs to a
//! payload format of its own (RFC 4588), which a voice call does not
//! negotiate, and resending a packet under its own sequence number in the
//! same stream is not something RFC 4585 asks of a sender. What the far end
//! asked for is counted, which is what a quality monitor reads.

use std::time::Duration;

use super::feedback::NackEntry;
use super::rsize::{ReducedSize, RtcpForm, Slot};
use super::timing::{AvpfConfig, AvpfTimer, FeedbackTiming, RegularPacket};
use crate::rtcp_timer::Due;

/// The most sequence numbers held as missing at once. A burst longer than
/// this is an outage, not a loss a NACK can help with.
const MAX_PENDING: usize = 64;

/// The widest jump in sequence numbers read as loss rather than as the far
/// end starting again: a second and a quarter of twenty-millisecond packets.
const MAX_GAP: u16 = 64;

/// What the offer and the answer settled about feedback on one stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Negotiated {
    /// Both ends listed `a=rtcp-fb` with `nack` for the stream's payload
    /// type or for `*` (RFC 4585 §4.2).
    pub generic_nack: bool,
    /// `T_rr_interval`: the least time between two full Regular RTCP
    /// packets (`trr-int`, §3.4 m). Zero leaves the Regular interval as
    /// RFC 3550 computes it.
    pub trr_interval: Duration,
    /// Both ends said `a=rtcp-rsize` (RFC 5506 §5).
    pub reduced_size: bool,
}

/// What a stream's feedback has done so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedbackCounts {
    /// Generic NACK messages sent.
    pub nacks_sent: u64,
    /// Sequence numbers those reported lost.
    pub packets_nacked: u64,
    /// Generic NACK messages received about this stream.
    pub nacks_received: u64,
    /// Sequence numbers the far end reported lost in them.
    pub packets_asked_for: u64,
    /// Early RTCP packets sent (RFC 4585 §3.5.2).
    pub early_packets: u64,
    /// Of every RTCP packet sent, those in reduced size (RFC 5506).
    pub reduced_size_packets: u64,
    /// Regular RTCP packets `T_rr_interval` suppressed (§3.5.3).
    pub suppressed: u64,
}

/// What the next RTCP packet of a feedback stream is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Send {
    /// Nothing: an Early packet whose loss turned up after all, or a
    /// Regular one `T_rr_interval` suppressed.
    Nothing,
    /// A compound packet: the report, the CNAME, and `nacks`. `full` is
    /// whether it carries everything a Regular packet does (the extended
    /// reports), or is the minimal compound packet of RFC 4585 §3.1.
    Compound {
        /// A full compound packet.
        full: bool,
        /// Whether it is Regular, which moves RFC 3550's own schedule.
        regular: bool,
        /// The NACKs it carries.
        nacks: Vec<NackEntry>,
    },
    /// A reduced-size packet: the NACKs alone.
    ReducedSize(Vec<NackEntry>),
}

/// The feedback half of a stream (RFC 4585 §3.5).
#[derive(Clone, Debug)]
pub(crate) struct FeedbackState {
    negotiated: Negotiated,
    timer: AvpfTimer,
    rsize: ReducedSize,
    /// The highest sequence number accepted, in RFC 3550 §A.1's modulo
    /// order.
    highest: Option<u16>,
    /// Missing, and not yet reported.
    pending: Vec<u16>,
    /// The slot [`FeedbackState::due`] said is due.
    due: Option<Slot>,
    counts: FeedbackCounts,
}

impl FeedbackState {
    /// A stream turning feedback on at `now`, with RFC 3550's first
    /// interval (under AVPF's own minimum) `first_interval` from now.
    pub(crate) fn new(negotiated: Negotiated, now: Duration, first_interval: Duration) -> Self {
        Self {
            negotiated,
            timer: AvpfTimer::new(
                AvpfConfig {
                    trr_interval: negotiated.trr_interval,
                    // a call is two members, and this stack runs calls
                    point_to_point: true,
                },
                now,
                first_interval,
            ),
            rsize: ReducedSize::new(negotiated.reduced_size),
            highest: None,
            pending: Vec::new(),
            due: None,
            counts: FeedbackCounts::default(),
        }
    }

    pub(crate) const fn negotiated(&self) -> Negotiated {
        self.negotiated
    }

    pub(crate) const fn counts(&self) -> FeedbackCounts {
        self.counts
    }

    /// A later offer and answer settled it again. What was pending stays
    /// pending only while NACKs are still agreed.
    pub(crate) fn renegotiated(&mut self, negotiated: Negotiated) {
        self.negotiated = negotiated;
        self.rsize.renegotiated(negotiated.reduced_size);
        if !negotiated.generic_nack {
            self.pending = Vec::new();
        }
    }

    /// The far end started its stream again: nothing before it is missing.
    pub(crate) fn restarted(&mut self) {
        self.highest = None;
        self.pending.clear();
    }

    /// A packet numbered `sequence` was accepted at `now`.
    pub(crate) fn arrived(&mut self, sequence: u16, now: Duration) {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            return;
        };
        let ahead = sequence.wrapping_sub(highest);
        if ahead == 0 {
            return;
        }
        if ahead >= 0x8000 {
            // behind the highest: a packet late or out of order, which is no
            // longer missing
            self.pending.retain(|missing| *missing != sequence);
            return;
        }
        self.highest = Some(sequence);
        if ahead == 1 || ahead > MAX_GAP || !self.negotiated.generic_nack {
            return;
        }
        let before = self.pending.len();
        for step in 1..ahead {
            let missing = highest.wrapping_add(step);
            if self.pending.len() >= MAX_PENDING {
                break;
            }
            if !self.pending.contains(&missing) {
                self.pending.push(missing);
            }
        }
        if self.pending.len() == before {
            return;
        }
        // T_max_fb_delay is the application's to say (§3.4 h); a NACK for
        // audio is worth sending for as long as it is sent, so none is
        // given and nothing is discarded for lateness. The draw only ever
        // scales T_dither_max, which is zero for the two members of a call
        // (§3.4 g), so any value in [0, 1] schedules the same instant
        if self.timer.feedback(now, None, 0.0) == FeedbackTiming::Discard {
            self.pending.clear();
        }
    }

    /// Whether an RTCP packet is due at `now`, and which.
    pub(crate) fn due(&mut self, now: Duration) -> Due {
        if self.timer.next_early().is_some_and(|at| at <= now) {
            self.due = Some(Slot::Early);
            return Due::Send;
        }
        if self.timer.next_regular() <= now {
            self.due = Some(Slot::Regular);
            return Due::Send;
        }
        Due::Wait(self.next_deadline())
    }

    /// The soonest RTCP packet: an Early one waiting, or the next Regular.
    pub(crate) fn next_deadline(&self) -> Duration {
        let regular = self.timer.next_regular();
        self.timer
            .next_early()
            .map_or(regular, |early| early.min(regular))
    }

    /// What the packet [`FeedbackState::due`] said is due is to be.
    ///
    /// `regular_interval` is RFC 3550's calculated interval at this moment,
    /// what the Regular packet after this one is scheduled by.
    pub(crate) fn next_packet(&mut self, regular_interval: Duration, unit_interval: f64) -> Send {
        match self.due.take().unwrap_or(Slot::Regular) {
            Slot::Early => {
                self.timer.early_sent();
                let nacks = self.take_nacks();
                if nacks.is_empty() {
                    return Send::Nothing;
                }
                self.counts.early_packets = self.counts.early_packets.saturating_add(1);
                match self.rsize.form(Slot::Early) {
                    RtcpForm::ReducedSize => Send::ReducedSize(nacks),
                    RtcpForm::Compound => Send::Compound {
                        full: false,
                        regular: false,
                        nacks,
                    },
                }
            }
            Slot::Regular => {
                let feedback_pending = !self.pending.is_empty();
                match self
                    .timer
                    .regular(feedback_pending, regular_interval, unit_interval)
                {
                    RegularPacket::Full => Send::Compound {
                        full: true,
                        regular: true,
                        nacks: self.take_nacks(),
                    },
                    RegularPacket::Minimal => Send::Compound {
                        full: false,
                        regular: true,
                        nacks: self.take_nacks(),
                    },
                    RegularPacket::Suppressed => {
                        self.counts.suppressed = self.counts.suppressed.saturating_add(1);
                        Send::Nothing
                    }
                }
            }
        }
    }

    /// A packet of `form` carrying `nacks` NACK entries went out.
    pub(crate) fn sent(&mut self, form: RtcpForm, nacks: &[NackEntry]) {
        self.rsize.sent(form);
        if form == RtcpForm::ReducedSize {
            self.counts.reduced_size_packets = self.counts.reduced_size_packets.saturating_add(1);
        }
        if !nacks.is_empty() {
            self.counts.nacks_sent = self.counts.nacks_sent.saturating_add(1);
            let lost = nacks
                .iter()
                .map(|entry| entry.lost().count())
                .sum::<usize>();
            self.counts.packets_nacked = self
                .counts
                .packets_nacked
                .saturating_add(u64::try_from(lost).unwrap_or(u64::MAX));
        }
    }

    /// The far end sent a Generic NACK naming `lost` of this stream's
    /// packets.
    pub(crate) fn nack_received(&mut self, lost: usize) {
        self.counts.nacks_received = self.counts.nacks_received.saturating_add(1);
        self.counts.packets_asked_for = self
            .counts
            .packets_asked_for
            .saturating_add(u64::try_from(lost).unwrap_or(u64::MAX));
    }

    /// The policy a received datagram is read under.
    pub(crate) const fn reduced_size(&self) -> &ReducedSize {
        &self.rsize
    }

    fn take_nacks(&mut self) -> Vec<NackEntry> {
        NackEntry::pack(core::mem::take(&mut self.pending))
    }
}
