// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! When feedback may go out (RFC 4585 §3): Early RTCP packets, the
//! `allow_early` flag that rations them, and the `T_rr_interval` that
//! thins out Regular RTCP packets.
//!
//! The Regular RTCP interval itself is RFC 3550's to compute (§6.3, with
//! the minimum that RFC 4585 §3.4 sets for AVPF), and the caller hands it
//! in each time; this module decides only what AVPF adds on top. Like
//! [`crate::RtpSession`] it reads no clock and draws no random number: time
//! is a [`Duration`] from the caller's own epoch, and each random draw
//! arrives as a `unit_interval` in `[0, 1)`.

use std::time::Duration;

/// `l` in `T_dither_max = l * T_rr` (RFC 4585 §3.5.2, step 2b) for a
/// session with more than two members.
const DITHER_FRACTION: f64 = 0.5;

/// A `unit_interval` sanitized into `[0, 1]`, so a hostile draw never
/// reaches a floating-point computation.
fn unit(unit_interval: f64) -> f64 {
    if unit_interval.is_finite() {
        unit_interval.clamp(0.0, 1.0)
    } else {
        0.5
    }
}

/// `interval` scaled by `factor`, saturating rather than panicking on a
/// result [`Duration`] cannot hold.
fn scale(interval: Duration, factor: f64) -> Duration {
    Duration::try_from_secs_f64(interval.as_secs_f64() * factor.max(0.0)).unwrap_or(Duration::MAX)
}

/// What RFC 4585 fixes for a session before its first packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AvpfConfig {
    /// `T_rr_interval`, the `trr-int` of `a=rtcp-fb` (§4.2): the least time
    /// between two full Regular RTCP packets. Zero, the default, leaves the
    /// Regular interval as RFC 3550 computes it.
    pub trr_interval: Duration,
    /// A session of exactly two members, which is every two-party call:
    /// `T_dither_max` is then zero and an Early packet goes out the moment
    /// feedback is wanted (§3.4).
    pub point_to_point: bool,
}

/// Where a piece of feedback ended up (RFC 4585 §3.5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackTiming {
    /// In an Early RTCP packet, to be sent at this point on the caller's
    /// clock — freshly scheduled, or one already waiting that the feedback
    /// joins.
    Early(Duration),
    /// In the next Regular RTCP packet, due at this point.
    Regular(Duration),
    /// Nowhere: by the next packet it would be later than the caller said
    /// the feedback is worth.
    Discard,
}

/// What to send when the Regular RTCP deadline arrives (RFC 4585 §3.5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegularPacket {
    /// A full compound packet, every report included.
    Full,
    /// A minimal compound packet carrying the pending feedback: `T_rr_interval`
    /// has not yet elapsed since the last full one.
    Minimal,
    /// Nothing: `T_rr_interval` has not elapsed and there is no feedback to
    /// carry.
    Suppressed,
}

/// The per-session state of RFC 4585 §3.5: `tp`, `tn`, `T_rr`,
/// `allow_early` and `T_rr_last`, plus the time an Early packet is waiting
/// for, if one is.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AvpfTimer {
    config: AvpfConfig,
    tp: Duration,
    tn: Duration,
    t_rr: Duration,
    allow_early: bool,
    t_rr_last: Option<Duration>,
    early_at: Option<Duration>,
}

impl AvpfTimer {
    /// Start a session at `now` (§3.5.1): `allow_early` set, no Regular
    /// packet sent yet, the first one due after `first_interval` — which the
    /// caller computes by RFC 3550 §6.3.
    #[must_use]
    pub fn new(config: AvpfConfig, now: Duration, first_interval: Duration) -> Self {
        Self {
            config,
            tp: now,
            tn: now.saturating_add(first_interval),
            t_rr: first_interval,
            allow_early: true,
            t_rr_last: None,
            early_at: None,
        }
    }

    /// When the next Regular RTCP packet is due: `tn`.
    #[must_use]
    pub const fn next_regular(&self) -> Duration {
        self.tn
    }

    /// When a scheduled Early RTCP packet is due, if one is waiting.
    #[must_use]
    pub const fn next_early(&self) -> Option<Duration> {
        self.early_at
    }

    /// Whether the next feedback may still go in an Early packet.
    #[must_use]
    pub const fn allow_early(&self) -> bool {
        self.allow_early
    }

    /// `T_dither_max` (§3.5.2, step 2b): zero point to point, half of
    /// `T_rr` otherwise.
    #[must_use]
    pub fn dither_max(&self) -> Duration {
        if self.config.point_to_point {
            Duration::ZERO
        } else {
            scale(self.t_rr, DITHER_FRACTION)
        }
    }

    /// Feedback became worth sending at `t0` (§3.5.2), and is worth nothing
    /// once `max_delay` has passed — `T_max_fb_delay`, the application's to
    /// set, or `None` for feedback that stays useful.
    ///
    /// In order: feedback joins an Early packet already waiting; rides the
    /// Regular packet if that is due within `T_dither_max` anyway; when
    /// `allow_early` is clear, waits for the Regular packet if `tn - t0` is
    /// less than `T_max_fb_delay` and is discarded otherwise (step 4a); and
    /// otherwise gets an Early packet of its own at
    /// `t0 + RND * T_dither_max`, which clears `allow_early`, pushes the
    /// next Regular packet out to `tp + 2 * T_rr` and moves `tp` to the
    /// previous `tn` (step 6), so the Early packet costs no more bandwidth
    /// than the Regular one it displaces.
    pub fn feedback(
        &mut self,
        t0: Duration,
        max_delay: Option<Duration>,
        unit_interval: f64,
    ) -> FeedbackTiming {
        // step 4a: useful while "tn - t0 < T_max_fb_delay"
        let useful_at = |at: Duration| max_delay.is_none_or(|max| at.saturating_sub(t0) < max);
        if let Some(te) = self.early_at {
            let te = te.max(t0);
            return if useful_at(te) {
                FeedbackTiming::Early(te)
            } else {
                FeedbackTiming::Discard
            };
        }
        let dither = self.dither_max();
        if self.tn.saturating_sub(t0) < dither || !self.allow_early {
            return if useful_at(self.tn) {
                FeedbackTiming::Regular(self.tn)
            } else {
                FeedbackTiming::Discard
            };
        }
        let te = t0.saturating_add(scale(dither, unit(unit_interval)));
        self.early_at = Some(te);
        self.allow_early = false;
        let previous = self.tn;
        self.tn = self.tp.saturating_add(self.t_rr.saturating_mul(2));
        self.tp = previous;
        FeedbackTiming::Early(te)
    }

    /// The Early packet went out. `allow_early` stays clear until the next
    /// Regular packet.
    pub const fn early_sent(&mut self) {
        self.early_at = None;
    }

    /// The Regular deadline `tn` arrived (§3.5.3). `feedback_pending` says
    /// whether feedback is waiting for this packet; `next_interval` is the
    /// Regular interval RFC 3550 computes for the one after it, and
    /// `unit_interval` the draw for this deadline's `T_rr_current_interval`,
    /// which §3.5.3 computes afresh at every deadline.
    ///
    /// With `T_rr_interval` zero, before any full packet, or once
    /// `T_rr_last + T_rr_current_interval` has passed, a full packet goes
    /// out and `T_rr_last` moves to `tn`.
    /// Otherwise the packet is minimal when feedback is pending and
    /// suppressed when not. Whatever was decided, `tp` moves to `tn`, the
    /// next deadline is `tn + next_interval`, `allow_early` is set again,
    /// and any Early packet still waiting is overtaken by this one.
    pub fn regular(
        &mut self,
        feedback_pending: bool,
        next_interval: Duration,
        unit_interval: f64,
    ) -> RegularPacket {
        let current = current_interval(self.config.trr_interval, unit_interval);
        let full = self.config.trr_interval.is_zero()
            || self
                .t_rr_last
                .is_none_or(|last| last.saturating_add(current) <= self.tn);
        let packet = if full {
            self.t_rr_last = Some(self.tn);
            RegularPacket::Full
        } else if feedback_pending {
            RegularPacket::Minimal
        } else {
            RegularPacket::Suppressed
        };
        self.tp = self.tn;
        self.t_rr = next_interval;
        self.tn = self.tp.saturating_add(next_interval);
        self.allow_early = true;
        self.early_at = None;
        packet
    }
}

/// `T_rr_current_interval = RND * T_rr_interval`, `RND` uniform in
/// `[0.5, 1.5]` (§3.5.3), so participants sharing a `trr-int` do not fall
/// into step.
fn current_interval(trr_interval: Duration, unit_interval: f64) -> Duration {
    scale(trr_interval, 0.5 + unit(unit_interval))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{AvpfConfig, AvpfTimer, FeedbackTiming, RegularPacket};

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn two_party(trr_interval: Duration) -> AvpfTimer {
        AvpfTimer::new(
            AvpfConfig {
                trr_interval,
                point_to_point: true,
            },
            Duration::ZERO,
            ms(1000),
        )
    }

    fn group() -> AvpfTimer {
        AvpfTimer::new(
            AvpfConfig {
                trr_interval: Duration::ZERO,
                point_to_point: false,
            },
            Duration::ZERO,
            ms(1000),
        )
    }

    #[test]
    fn point_to_point_feedback_goes_out_at_once() {
        let mut timer = two_party(Duration::ZERO);
        assert_eq!(timer.dither_max(), Duration::ZERO);
        assert_eq!(
            timer.feedback(ms(300), None, 0.9),
            FeedbackTiming::Early(ms(300))
        );
        assert!(!timer.allow_early());
    }

    #[test]
    fn an_early_packet_pushes_the_regular_one_to_twice_the_interval() {
        let mut timer = two_party(Duration::ZERO);
        assert_eq!(timer.next_regular(), ms(1000));
        let _ = timer.feedback(ms(300), None, 0.0);
        assert_eq!(timer.next_regular(), ms(2000));
    }

    #[test]
    fn after_an_early_packet_feedback_waits_for_the_regular_one() {
        let mut timer = two_party(Duration::ZERO);
        let _ = timer.feedback(ms(300), None, 0.0);
        timer.early_sent();
        assert_eq!(
            timer.feedback(ms(400), None, 0.0),
            FeedbackTiming::Regular(ms(2000))
        );
        assert_eq!(timer.regular(true, ms(1000), 0.5), RegularPacket::Full);
        assert!(timer.allow_early());
        assert_eq!(timer.next_regular(), ms(3000));
        assert_eq!(
            timer.feedback(ms(2100), None, 0.0),
            FeedbackTiming::Early(ms(2100))
        );
    }

    #[test]
    fn feedback_too_late_for_the_regular_packet_is_discarded() {
        let mut timer = two_party(Duration::ZERO);
        let _ = timer.feedback(ms(300), None, 0.0);
        timer.early_sent();
        // RFC 4585 §3.5.2 step 4a: still useful while tn - t0 is less than
        // T_max_fb_delay, discarded once it is not
        assert_eq!(
            timer.feedback(ms(400), Some(ms(1601)), 0.0),
            FeedbackTiming::Regular(ms(2000))
        );
        assert_eq!(
            timer.feedback(ms(400), Some(ms(1600)), 0.0),
            FeedbackTiming::Discard
        );
    }

    #[test]
    fn feedback_joins_an_early_packet_still_waiting() {
        let mut timer = group();
        assert_eq!(timer.dither_max(), ms(500));
        assert_eq!(
            timer.feedback(ms(100), None, 0.5),
            FeedbackTiming::Early(ms(350))
        );
        assert_eq!(timer.next_early(), Some(ms(350)));
        assert_eq!(
            timer.feedback(ms(200), None, 0.0),
            FeedbackTiming::Early(ms(350))
        );
        assert_eq!(
            timer.feedback(ms(200), Some(ms(100)), 0.0),
            FeedbackTiming::Discard
        );
    }

    #[test]
    fn a_regular_packet_within_the_dither_carries_the_feedback() {
        let mut timer = group();
        assert_eq!(
            timer.feedback(ms(600), None, 0.0),
            FeedbackTiming::Regular(ms(1000))
        );
        assert!(timer.allow_early(), "no Early packet was used");
        assert_eq!(
            timer.feedback(ms(500), None, 0.0),
            FeedbackTiming::Early(ms(500))
        );
    }

    #[test]
    fn a_regular_packet_overtakes_an_early_one_still_waiting() {
        let mut timer = group();
        let _ = timer.feedback(ms(100), None, 1.0);
        assert!(timer.next_early().is_some());
        let _ = timer.regular(true, ms(1000), 0.5);
        assert_eq!(timer.next_early(), None);
    }

    #[test]
    fn without_trr_int_every_regular_packet_is_full() {
        let mut timer = two_party(Duration::ZERO);
        for _ in 0..5 {
            assert_eq!(timer.regular(false, ms(100), 0.5), RegularPacket::Full);
        }
    }

    #[test]
    fn trr_int_suppresses_regular_packets_between_full_ones() {
        // T_rr_interval 1 s and draws of 0.5, so T_rr_current_interval
        // is exactly 1 s at every deadline; Regular deadlines every 400 ms
        let mut timer = AvpfTimer::new(
            AvpfConfig {
                trr_interval: ms(1000),
                point_to_point: true,
            },
            Duration::ZERO,
            ms(400),
        );
        let mut seen = Vec::new();
        for pending in [false, false, true, false, false, false] {
            seen.push((timer.next_regular(), timer.regular(pending, ms(400), 0.5)));
        }
        assert_eq!(
            seen,
            [
                (ms(400), RegularPacket::Full),
                (ms(800), RegularPacket::Suppressed),
                (ms(1200), RegularPacket::Minimal),
                (ms(1600), RegularPacket::Full),
                (ms(2000), RegularPacket::Suppressed),
                (ms(2400), RegularPacket::Suppressed),
            ]
        );
        assert_eq!(timer.regular(false, ms(400), 0.5), RegularPacket::Full);
    }

    #[test]
    fn trr_int_is_randomized_between_half_and_one_and_a_half() {
        let config = AvpfConfig {
            trr_interval: ms(1000),
            point_to_point: true,
        };
        // the first full packet at 100 ms, then deadlines 500 ms apart
        let mut timer = AvpfTimer::new(config, Duration::ZERO, ms(100));
        assert_eq!(timer.regular(false, ms(500), 0.5), RegularPacket::Full);
        // 500 ms on: a draw of 0 makes T_rr_current_interval 500 ms, due
        assert_eq!(timer.regular(false, ms(500), 0.0), RegularPacket::Full);
        // 500 ms on again: a draw of 1 makes it 1.5 s, not yet
        assert_eq!(
            timer.regular(false, ms(500), 1.0),
            RegularPacket::Suppressed
        );
        // §3.5.3 draws afresh at each deadline: 1 s since the last full
        // packet, and a draw of 0.25 (750 ms) sends one where the 1.5 s drawn
        // a deadline ago would not have
        assert_eq!(timer.regular(false, ms(500), 0.25), RegularPacket::Full);
    }

    #[test]
    fn hostile_draws_and_huge_intervals_do_not_panic() {
        let config = AvpfConfig {
            trr_interval: Duration::MAX,
            point_to_point: false,
        };
        let mut timer = AvpfTimer::new(config, Duration::MAX, Duration::MAX);
        let _ = timer.regular(false, Duration::MAX, f64::NAN);
        let _ = timer.feedback(Duration::MAX, Some(Duration::ZERO), f64::INFINITY);
        let _ = timer.regular(true, Duration::MAX, -1.0);
        let _ = timer.feedback(Duration::ZERO, None, f64::NEG_INFINITY);
        let _ = timer.regular(false, Duration::ZERO, 2.0);
    }
}
