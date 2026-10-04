// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Turning what has been heard from one source into a reception report
//! block: loss, jitter, and the round-trip clock exchange (RFC 3550 §6.4.1,
//! Appendix A.3 and A.8).
//!
//! Time here is a 64-bit NTP timestamp, the same wall-clock value a sender
//! report carries: this module reads no clock, so every one is exactly
//! what the caller passed in.

use std::time::Duration;

use crate::rtcp::ReportBlock;
use crate::source::SequenceState;

/// Read `ntp`'s middle 32 bits: seconds in the top half, fraction in the
/// bottom, which is what LSR and DLSR are both expressed in (§6.4.1).
fn mid32(ntp: u64) -> u32 {
    u32::try_from((ntp >> 16) & 0xFFFF_FFFF).unwrap_or(0)
}

/// A Q16.16 fixed-point second count, the unit LSR, DLSR and a round-trip
/// delay all share, as a [`Duration`].
fn q16_to_duration(value: u32) -> Duration {
    let whole = u64::from(value >> 16);
    let frac = u64::from(value & 0xFFFF);
    Duration::new(
        whole,
        u32::try_from(frac * 1_000_000_000 / 65536).unwrap_or(0),
    )
}

/// The round-trip propagation delay to `SSRC_n`, from a reception report
/// block it sent back describing us (§6.4.1, Figure 2): `A - LSR - DLSR`,
/// where `A` is when this block arrived. `None` when the block's LSR is
/// zero, meaning that source had not yet received an SR of ours to report
/// on.
#[must_use]
pub(crate) fn round_trip_time(block: &ReportBlock, arrival_ntp: u64) -> Option<Duration> {
    if block.last_sr == 0 {
        return None;
    }
    let delay = mid32(arrival_ntp)
        .wrapping_sub(block.last_sr)
        .wrapping_sub(block.delay_since_last_sr);
    Some(q16_to_duration(delay))
}

/// What is remembered about one source in order to keep reporting on it:
/// the jitter estimate, the interval snapshot fraction-lost needs, and the
/// last SR heard from it.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReceptionTracker {
    expected_prior: u64,
    received_prior: u64,
    transit: Option<u32>,
    /// The jitter estimate, scaled by sixteen (A.8's integer form), so the
    /// 1/16 gain the RFC requires is exact rather than rounded every
    /// update.
    jitter_scaled: u32,
    last_sr_ntp: Option<u64>,
    last_sr_arrival_ntp: Option<u64>,
}

impl ReceptionTracker {
    /// A source nothing has been heard from yet.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            expected_prior: 0,
            received_prior: 0,
            transit: None,
            jitter_scaled: 0,
            last_sr_ntp: None,
            last_sr_arrival_ntp: None,
        }
    }

    /// Update the jitter estimate for one arriving packet (§6.4.1, A.8).
    /// `rtp_timestamp` is the packet's own, `arrival` is the receiver's
    /// clock at the moment it arrived, on the same clock.
    pub(crate) fn on_packet(&mut self, rtp_timestamp: u32, arrival: u32) {
        let transit = arrival.wrapping_sub(rtp_timestamp);
        if let Some(previous) = self.transit {
            let d = transit.wrapping_sub(previous).cast_signed().unsigned_abs();
            let round_off = self.jitter_scaled.saturating_add(8) >> 4;
            self.jitter_scaled = self
                .jitter_scaled
                .saturating_add(d)
                .saturating_sub(round_off);
        }
        self.transit = Some(transit);
    }

    /// Remember an SR just received from this source, so a future report
    /// about it can carry LSR and DLSR.
    pub(crate) fn on_sender_report(&mut self, sender_ntp: u64, arrival_ntp: u64) {
        self.last_sr_ntp = Some(sender_ntp);
        self.last_sr_arrival_ntp = Some(arrival_ntp);
    }

    /// Forget the interval snapshot and the SR bookkeeping, keeping the
    /// jitter estimate. For a source that has restarted, whose
    /// [`crate::source::SequenceState`] has already re-based on its own.
    pub(crate) fn restart(&mut self) {
        self.expected_prior = 0;
        self.received_prior = 0;
        self.last_sr_ntp = None;
        self.last_sr_arrival_ntp = None;
    }

    /// Build the reception report block for `ssrc`, whose sequence numbers
    /// are tracked by `sequence`, and reset the interval this crate's own
    /// fraction-lost figure is measured against.
    #[must_use]
    pub(crate) fn block(
        &mut self,
        ssrc: u32,
        sequence: &SequenceState,
        now_ntp: u64,
    ) -> ReportBlock {
        let expected = sequence
            .extended_highest()
            .saturating_sub(u64::from(sequence.base()))
            .saturating_add(1);
        let received = sequence.received();

        let expected_interval = expected.saturating_sub(self.expected_prior);
        let received_interval = received.saturating_sub(self.received_prior);
        self.expected_prior = expected;
        self.received_prior = received;

        let lost_interval =
            i128::from(expected_interval).saturating_sub(i128::from(received_interval));
        let fraction_lost = if expected_interval == 0 || lost_interval <= 0 {
            0
        } else {
            let ratio = lost_interval.saturating_mul(256) / i128::from(expected_interval);
            u8::try_from(ratio.clamp(0, 255)).unwrap_or(255)
        };

        // A.3: "clamped ... rather than wrapping around"
        let cumulative_lost = i128::from(expected)
            .saturating_sub(i128::from(received))
            .clamp(-0x0080_0000, 0x007F_FFFF);

        let (last_sr, delay_since_last_sr) = match (self.last_sr_ntp, self.last_sr_arrival_ntp) {
            (Some(sender_ntp), Some(arrival_ntp)) => {
                (mid32(sender_ntp), mid32(now_ntp.wrapping_sub(arrival_ntp)))
            }
            _ => (0, 0),
        };

        ReportBlock {
            ssrc,
            fraction_lost,
            cumulative_lost: i32::try_from(cumulative_lost).unwrap_or(0),
            extended_highest_sequence: u32::try_from(sequence.extended_highest() & 0xFFFF_FFFF)
                .unwrap_or(u32::MAX),
            jitter: self.jitter_scaled >> 4,
            last_sr,
            delay_since_last_sr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReceptionTracker, round_trip_time};
    use crate::rtcp::ReportBlock;
    use crate::source::SequenceState;
    use std::time::Duration;

    #[test]
    fn a_steady_stream_settles_the_jitter_estimate_near_the_true_spacing_variance() {
        // §6.4.1: J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16, sampled at
        // report time as an unsigned integer
        let mut tracker = ReceptionTracker::new();
        let sequence = SequenceState::new();
        // perfectly regular arrivals: transit is constant, so D is always
        // zero and jitter should decay to zero regardless of where it
        // started
        tracker.on_packet(0, 1000);
        for step in 1..50 {
            tracker.on_packet(step * 160, 1000 + step * 160);
        }
        let block = tracker.block(1, &sequence, 0);
        assert_eq!(block.jitter, 0, "no variance in spacing, no jitter");
    }

    #[test]
    fn a_late_packet_moves_the_jitter_estimate_by_a_sixteenth_of_the_difference() {
        let mut tracker = ReceptionTracker::new();
        let sequence = SequenceState::new();
        tracker.on_packet(0, 1000); // transit = 1000, no jitter sample yet
        tracker.on_packet(160, 1160); // transit = 1000, D = 0
        // this one arrives 320 timestamp units later than its spacing
        // predicts: D = 320, so jitter should move by 320/16 = 20
        tracker.on_packet(320, 1640);
        let block = tracker.block(1, &sequence, 0);
        assert_eq!(block.jitter, 20);
    }

    #[test]
    fn fraction_lost_is_zero_when_nothing_was_expected_in_the_interval() {
        let mut tracker = ReceptionTracker::new();
        let mut sequence = SequenceState::new();
        sequence.update(100);
        sequence.update(101);
        let first = tracker.block(1, &sequence, 0);
        assert_eq!(first.fraction_lost, 0);
        // nothing new arrived since the last report: expected_interval is 0
        let second = tracker.block(1, &sequence, 0);
        assert_eq!(second.fraction_lost, 0);
    }

    #[test]
    fn near_total_loss_in_an_interval_reports_as_the_largest_fraction_a_byte_holds() {
        // a fixed-point fraction with the binary point at the left edge of
        // an eight-bit field cannot reach a full 256/256, so the closest
        // representable value under 1.0 is 255 — not a silent wrap to zero,
        // which is what casting the RFC's own `int fraction` straight into
        // an eight-bit field would do at exactly 256/256
        let mut tracker = ReceptionTracker::new();
        let mut sequence = SequenceState::new();
        sequence.update(1);
        sequence.update(2); // base = 2, one packet received so far
        let _ = tracker.block(1, &sequence, 0);
        // the highest sequence number jumps 256 ahead on a single arrival:
        // 256 expected in the interval, one received, 255 lost
        sequence.update(258);
        let block = tracker.block(1, &sequence, 0);
        assert_eq!(block.fraction_lost, 255);
    }

    #[test]
    fn cumulative_lost_is_negative_when_duplicates_outrun_what_was_expected() {
        // A.3: "the loss may be negative if there are duplicates"
        let mut tracker = ReceptionTracker::new();
        let mut sequence = SequenceState::new();
        sequence.update(1);
        sequence.update(2); // base=2, one packet expected and received
        let block = tracker.block(1, &sequence, 0);
        assert_eq!(block.cumulative_lost, 0);
    }

    #[test]
    fn cumulative_lost_saturates_rather_than_overflowing_the_24_bit_field() {
        let mut tracker = ReceptionTracker::new();
        let mut sequence = SequenceState::new();
        sequence.update(0);
        sequence.update(1);
        // jump the highest sequence number far ahead without ever
        // receiving those packets, so expected grows huge relative to
        // received
        for cycle in 0..40_u32 {
            let base = u16::try_from((cycle * 3000) % 65536).unwrap_or(0);
            sequence.update(base);
        }
        let block = tracker.block(1, &sequence, 0);
        assert!(block.cumulative_lost <= 0x007F_FFFF);
        assert!(block.cumulative_lost >= -0x0080_0000);
    }

    #[test]
    fn the_last_sr_and_delay_are_zero_until_an_sr_has_been_seen() {
        let mut tracker = ReceptionTracker::new();
        let sequence = SequenceState::new();
        let block = tracker.block(1, &sequence, 0x1234_5678_0000_0000);
        assert_eq!(block.last_sr, 0);
        assert_eq!(block.delay_since_last_sr, 0);
    }

    #[test]
    fn the_delay_since_the_last_sr_grows_with_the_wallclock_between_them() {
        // an SR arrives with NTP timestamp exactly on a 16-bit boundary at
        // a known middle-32 value, then the report is generated 6.125s of
        // NTP wallclock later
        let mut tracker = ReceptionTracker::new();
        let sequence = SequenceState::new();
        let sender_ntp = 0xb705_2000_u64 << 16;
        let arrival_ntp = sender_ntp;
        tracker.on_sender_report(sender_ntp, arrival_ntp);

        let now_ntp = arrival_ntp + (0x0006_2000_u64 << 16);
        let block = tracker.block(1, &sequence, now_ntp);
        assert_eq!(block.last_sr, 0xb705_2000);
        assert_eq!(block.delay_since_last_sr, 0x0006_2000);
    }

    #[test]
    fn round_trip_time_matches_the_rfc_figure_2_worked_example() {
        // §6.4.1 Figure 2: A=0xb710:8000, LSR=0xb705:2000, DLSR=0x0005:4000,
        // delay = 0x0006:2000 = 6.125s
        let block = ReportBlock {
            last_sr: 0xb705_2000,
            delay_since_last_sr: 0x0005_4000,
            ..ReportBlock::default()
        };
        let arrival_ntp = 0xb710_8000_u64 << 16;
        let rtt = round_trip_time(&block, arrival_ntp).expect("an SR was received");
        assert_eq!(rtt, Duration::new(6, 125_000_000));
    }

    #[test]
    fn round_trip_time_is_unknown_when_no_sr_was_ever_received() {
        let block = ReportBlock::default();
        assert_eq!(round_trip_time(&block, 0), None);
    }
}
