// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! When to send the next compound RTCP packet (RFC 3550 §6.2, §6.3, and the
//! worked algorithm in Appendix A.7).
//!
//! Time is a [`Duration`] measured from whatever epoch the caller anchors
//! its clock to — this module reads none itself. Nor does it draw the
//! random numbers §6.2 asks for to keep participants from synchronizing:
//! every method that needs one takes a `unit_interval` in `[0, 1)` from the
//! caller.

use std::time::Duration;

/// "It is RECOMMENDED that the fraction of the session bandwidth added for
/// RTCP be fixed at 5%" (§6.2). The caller applies it to get `rtcp_bandwidth`.
///
/// "RECOMMENDED that 1/4 of the RTCP bandwidth be dedicated to
/// participants that are sending data" (§6.2, A.7 `RTCP_SENDER_BW_FRACTION`).
const SENDER_SHARE: f64 = 0.25;
const RECEIVER_SHARE: f64 = 1.0 - SENDER_SHARE;

/// "The RECOMMENDED value for a fixed minimum interval is 5 seconds"
/// (§6.2, A.7 `RTCP_MIN_TIME`).
const MIN_INTERVAL_SECS: f64 = 5.0;

/// RTP/AVPF's minimum before the first report: "the initial Tmin is set to 1
/// second" (RFC 4585 §3.4 d). After it, AVPF's minimum is zero.
const FEEDBACK_INITIAL_MIN_SECS: f64 = 1.0;

/// §6.3.1 point 5: "the resulting value of T is divided by e-3/2=1.21828 to
/// compensate for the fact that the timer reconsideration algorithm
/// converges to a value of the RTCP bandwidth below the intended average".
const REDRAW_COMPENSATION: f64 = std::f64::consts::E - 1.5;

/// More members than this and a participant leaving MUST back off its BYE
/// rather than send it immediately (§6.3.7).
const BYE_BACKOFF_THRESHOLD: u32 = 50;

fn as_f64(count: u32) -> f64 {
    f64::from(count)
}

/// A non-negative, finite number of seconds as a [`Duration`], with a
/// hostile or nonsensical input turned into zero rather than a panic —
/// [`Duration::from_secs_f64`] would abort on exactly the kind of input a
/// caller-supplied bandwidth or random draw could produce.
fn duration_from_secs(seconds: f64) -> Duration {
    if seconds <= 0.0 {
        return Duration::ZERO;
    }
    Duration::try_from_secs_f64(seconds).unwrap_or(Duration::ZERO)
}

/// A `unit_interval` sanitized into `[0, 1]`; the same fallback either way
/// keeps a hostile draw from ever reaching a floating-point computation.
fn unit(unit_interval: f64) -> f64 {
    if unit_interval.is_finite() {
        unit_interval.clamp(0.0, 1.0)
    } else {
        0.5
    }
}

/// What §6.3.6 decides at the transmission timer's expiry: send now, or
/// wait for the deadline it computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Due {
    /// A report is due; build it with
    /// [`RtpSession::build_report`](crate::RtpSession::build_report), which
    /// records that it went out and schedules the next one.
    Send,
    /// Not yet; call [`RtpSession::rtcp_due`](crate::RtpSession::rtcp_due)
    /// again no earlier than this point on the caller's clock.
    Wait(Duration),
}

/// The state §6.3 asks a participant to keep in order to schedule compound
/// RTCP packets: `tp`, `tn`, `pmembers`, `members`, `senders`, `we_sent`,
/// `avg_rtcp_size` and `initial`, one field each. `rtcp_bw` is fixed for
/// the life of a session, so it lives outside those six.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IntervalTimer {
    tp: Duration,
    tn: Duration,
    pmembers: u32,
    members: u32,
    senders: u32,
    rtcp_bandwidth: f64,
    we_sent: bool,
    avg_packet_size: f64,
    initial: bool,
    /// Whether this participant has itself sent (or, backing off, begun
    /// scheduling) its own BYE, by either branch of §6.3.7. Not an RFC state
    /// variable: it selects the rule for a received BYE (§6.3.4).
    departing: bool,
    /// Which profile's minimum applies.
    minimum: Minimum,
}

/// Whose `Tmin` the calculated interval is held to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Minimum {
    /// RFC 3550 §6.2's five seconds, halved before the first report.
    Rfc3550,
    /// RTP/AVPF's: one second before the first report and none after it
    /// (RFC 4585 §3.4 d).
    Avpf,
}

impl IntervalTimer {
    /// Join a session (§6.3.2): one member, the caller itself, nothing sent
    /// yet, and a first deadline drawn from `unit_interval` using half the
    /// minimum interval, "for quicker notification while still allowing
    /// some time ... to learn about other sources".
    #[must_use]
    pub(crate) fn new(rtcp_bandwidth: f64, first_packet_size: usize, unit_interval: f64) -> Self {
        let mut timer = Self {
            tp: Duration::ZERO,
            tn: Duration::ZERO,
            pmembers: 1,
            members: 1,
            senders: 0,
            rtcp_bandwidth: rtcp_bandwidth.max(0.0),
            we_sent: false,
            avg_packet_size: as_size(first_packet_size),
            initial: true,
            departing: false,
            minimum: Minimum::Rfc3550,
        };
        timer.tn = timer.interval(unit_interval);
        timer
    }

    /// Run the session under RTP/AVPF's minimum from here on (RFC 4585
    /// §3.4 d): "Unlike in [RFC 3550], the initial Tmin is set to 1 second
    /// to allow for some group size sampling before sending the first RTCP
    /// packet. After the first RTCP packet is sent, Tmin is set to 0."
    ///
    /// The first deadline is drawn again when no report has gone out yet,
    /// since it was drawn under the other minimum. Returns the calculated
    /// interval that deadline is `tp` plus.
    pub(crate) fn use_feedback_minimum(&mut self, unit_interval: f64) -> Duration {
        self.minimum = Minimum::Avpf;
        let interval = self.interval(unit_interval);
        if self.initial {
            self.tn = self.tp.saturating_add(interval);
        }
        interval
    }

    /// §6.3.1's calculated interval T for the report after the one about to
    /// go, drawn with `unit_interval`, without moving anything: what RFC
    /// 4585 §3.4 e calls `T_rr`, the Regular RTCP interval AVPF schedules
    /// against. Worked out as it will stand once a report has gone, which is
    /// when §3.4 d drops AVPF's minimum to zero.
    pub(crate) fn calculated_after_report(&self, unit_interval: f64) -> Duration {
        Self {
            initial: false,
            ..*self
        }
        .interval(unit_interval)
    }

    /// A new participant was heard from, by RTP or RTCP (§6.3.3).
    pub(crate) fn note_member(&mut self) {
        self.members = self.members.saturating_add(1);
    }

    /// A participant — local or remote — sent its first RTP packet
    /// (§6.3.3, §6.3.8).
    pub(crate) fn note_sender(&mut self) {
        self.senders = self.senders.saturating_add(1);
    }

    /// This participant itself started sending; also counts as
    /// [`IntervalTimer::note_sender`] (§6.3.8).
    pub(crate) fn note_local_sender(&mut self) {
        self.we_sent = true;
        self.note_sender();
    }

    /// A source left by BYE and was a sender too, so both counts fall
    /// (§6.3.4).
    pub(crate) fn remove_sender(&mut self) {
        self.senders = self.senders.saturating_sub(1);
    }

    /// A BYE was received for a source (§6.3.4): the membership count
    /// falls, and if that leaves it below what it was when the current
    /// deadline was last set, "reverse reconsideration" pulls `tp` and
    /// `tn` forward so the group learns of the departure without waiting
    /// out an interval sized for the larger group.
    ///
    /// The count never falls below one: this participant is in its own
    /// member table for the life of the session (§6.3.2), and a BYE from
    /// someone else cannot remove it — including one that arrives after
    /// [`IntervalTimer::leaving`] has already reset the count to that one.
    pub(crate) fn remove_member(&mut self, now: Duration) {
        if self.members <= 1 {
            return;
        }
        self.members = self.members.saturating_sub(1);
        if self.members >= self.pmembers || self.pmembers == 0 {
            return;
        }
        let ratio = as_f64(self.members) / as_f64(self.pmembers);
        let until_tn = self.tn.saturating_sub(now).as_secs_f64() * ratio;
        let since_tp = now.saturating_sub(self.tp).as_secs_f64() * ratio;
        self.tn = now.saturating_add(duration_from_secs(until_tn));
        self.tp = now.saturating_sub(duration_from_secs(since_tp));
        self.pmembers = self.members;
    }

    /// Fold in the size of one compound RTCP packet, sent or received
    /// (§6.3.3, §6.3.6): `avg_rtcp_size = size/16 + avg_rtcp_size*15/16`.
    pub(crate) fn observe(&mut self, packet_size: usize) {
        self.avg_packet_size = as_size(packet_size) / 16.0 + self.avg_packet_size * 15.0 / 16.0;
    }

    /// §6.3.1's deterministic-then-randomized calculated interval T, ending
    /// with A.7's compensation for reconsideration's own bias.
    fn interval(&self, unit_interval: f64) -> Duration {
        let minimum = match (self.minimum, self.initial) {
            (Minimum::Avpf, true) => FEEDBACK_INITIAL_MIN_SECS,
            (Minimum::Avpf, false) => 0.0,
            (Minimum::Rfc3550, true) => MIN_INTERVAL_SECS / 2.0,
            (Minimum::Rfc3550, false) => MIN_INTERVAL_SECS,
        };

        let (n, share) = if as_f64(self.senders) <= as_f64(self.members) * SENDER_SHARE {
            if self.we_sent {
                (self.senders, SENDER_SHARE)
            } else {
                (self.members.saturating_sub(self.senders), RECEIVER_SHARE)
            }
        } else {
            (self.members, 1.0)
        };

        let bandwidth = self.rtcp_bandwidth * share;
        let deterministic = if bandwidth > 0.0 {
            (self.avg_packet_size * as_f64(n) / bandwidth).max(minimum)
        } else {
            minimum
        };

        let t = deterministic * (unit(unit_interval) + 0.5) / REDRAW_COMPENSATION;
        duration_from_secs(t)
    }

    /// Whether it is time to send, at `now` (§6.3.6). Either way,
    /// `pmembers` is set to the current membership, as the RFC's own
    /// `OnExpire` does unconditionally.
    pub(crate) fn due(&mut self, now: Duration, unit_interval: f64) -> Due {
        let deadline = self.tp.saturating_add(self.interval(unit_interval));
        self.pmembers = self.members;
        if deadline <= now {
            Due::Send
        } else {
            self.tn = deadline;
            Due::Wait(deadline)
        }
    }

    /// Record that a report of `packet_size` octets went out at `now`, and
    /// compute the next deadline with a fresh draw — "we must redraw the
    /// interval", since the one behind [`IntervalTimer::due`]'s decision to
    /// send is not distributed the same way (§6.3.6, A.7). Returns that
    /// deadline.
    pub(crate) fn sent(
        &mut self,
        now: Duration,
        packet_size: usize,
        unit_interval: f64,
    ) -> Duration {
        self.observe(packet_size);
        self.tp = now;
        self.initial = false;
        self.tn = now.saturating_add(self.interval(unit_interval));
        self.tn
    }

    /// Reset state for leaving the session (§6.3.7 bullet one) and compute
    /// when the BYE should go out, for a participant past the fifty-member
    /// threshold ([`IntervalTimer::should_back_off_bye`]) — "the
    /// participant MUST execute the following algorithm". A session at or
    /// below it sends its BYE immediately through
    /// [`IntervalTimer::sent_bye`] instead, which does not reset anything
    /// the way this does.
    pub(crate) fn leaving(
        &mut self,
        now: Duration,
        bye_size: usize,
        unit_interval: f64,
    ) -> Duration {
        self.tp = now;
        self.pmembers = 1;
        self.members = 1;
        self.initial = true;
        self.we_sent = false;
        self.senders = 0;
        self.avg_packet_size = as_size(bye_size);
        self.tn = now.saturating_add(self.interval(unit_interval));
        self.departing = true;
        self.tn
    }

    /// Send this participant's own BYE the way §6.3.7 allows at or below
    /// the fifty-member threshold: "the participant MAY send a BYE packet
    /// immediately", read as bullet three alone: like a regular RTCP packet,
    /// without bullet one's reset. Membership counts are left as they were.
    pub(crate) fn sent_bye(
        &mut self,
        now: Duration,
        bye_size: usize,
        unit_interval: f64,
    ) -> Duration {
        let next = self.sent(now, bye_size, unit_interval);
        self.departing = true;
        next
    }

    /// Whether this participant has itself sent a BYE, by either branch of
    /// §6.3.7. §6.3.4's rule for a *received* BYE excludes "the case when
    /// an RTCP BYE is to be transmitted" from the removal it otherwise
    /// describes regardless of group size, so a caller checks this, not
    /// [`IntervalTimer::should_back_off_bye`], for a received BYE.
    #[must_use]
    pub(crate) const fn is_departing(&self) -> bool {
        self.departing
    }

    /// §6.3.7 bullet two, once this participant is itself leaving: "every
    /// time a BYE packet from another participant is received, members is
    /// incremented by 1 ... regardless of whether that participant exists
    /// in the member table or not." This "usurps the normal role of the
    /// members variable to count BYE packets instead" of removing
    /// departures, for as long as this participant's own goodbye is being
    /// scheduled or has already gone out.
    pub(crate) fn note_bye_while_departing(&mut self) {
        self.members = self.members.saturating_add(1);
    }

    /// Whether §6.3.7's BYE backoff applies: "a participant MUST execute
    /// the following algorithm if the number of members is more than 50
    /// when the participant chooses to leave."
    #[must_use]
    pub(crate) fn should_back_off_bye(&self) -> bool {
        self.members > BYE_BACKOFF_THRESHOLD
    }

    /// The next scheduled deadline, for a caller that wants to know
    /// without also advancing `pmembers` the way
    /// [`IntervalTimer::due`] does.
    #[must_use]
    pub(crate) const fn next_deadline(&self) -> Duration {
        self.tn
    }
}

fn as_size(size: usize) -> f64 {
    as_f64(u32::try_from(size).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::{Due, IntervalTimer};
    use std::time::Duration;

    const BANDWIDTH: f64 = 800.0; // octets/second
    const PACKET: usize = 100;

    #[test]
    fn a_new_session_schedules_its_first_report_at_half_the_minimum_interval() {
        // §6.2: "This delay MAY be set to half the minimum interval to
        // allow quicker notification that the new participant is present"
        let timer = IntervalTimer::new(BANDWIDTH, PACKET, 0.0);
        // draw=0.0 -> multiplier 0.5, initial halves Tmin to 2.5s, so the
        // deterministic interval floors at 1.25s before compensation
        let expected = 1.25 / super::REDRAW_COMPENSATION;
        assert!((timer.next_deadline().as_secs_f64() - expected).abs() < 1e-9);
    }

    #[test]
    fn the_draw_scales_the_interval_between_half_and_one_and_a_half_of_deterministic() {
        let low = IntervalTimer::new(BANDWIDTH, PACKET, 0.0).next_deadline();
        let mid = IntervalTimer::new(BANDWIDTH, PACKET, 0.5).next_deadline();
        let high = IntervalTimer::new(BANDWIDTH, PACKET, 1.0).next_deadline();
        assert!(low < mid);
        assert!(mid < high);
        // 1.0 draws 1.5x what 0.0 draws (0.5x), so the ratio is exactly 3
        let ratio = high.as_secs_f64() / low.as_secs_f64();
        assert!((ratio - 3.0).abs() < 1e-9);
    }

    #[test]
    fn a_hostile_draw_is_sanitized_rather_than_producing_nonsense() {
        let nan = IntervalTimer::new(BANDWIDTH, PACKET, f64::NAN).next_deadline();
        let mid = IntervalTimer::new(BANDWIDTH, PACKET, 0.5).next_deadline();
        assert_eq!(nan, mid, "NaN falls back to the midpoint draw");

        let too_high = IntervalTimer::new(BANDWIDTH, PACKET, 5.0).next_deadline();
        let one = IntervalTimer::new(BANDWIDTH, PACKET, 1.0).next_deadline();
        assert_eq!(too_high, one, "out-of-range draws clamp");
    }

    #[test]
    fn the_five_second_minimum_holds_once_the_session_is_no_longer_initial() {
        let mut timer = IntervalTimer::new(BANDWIDTH, PACKET, 0.5);
        // `sent` is what flips `initial` to false; calling it directly
        // isolates that transition from whether `due` happened to agree
        // the interval had elapsed
        let next = timer.sent(Duration::ZERO, PACKET, 0.5);
        // deterministic interval floors at 5s now that initial is false;
        // draw 0.5 gives exactly 1.0x, so next == 5s / compensation
        let expected = 5.0 / super::REDRAW_COMPENSATION;
        assert!((next.as_secs_f64() - expected).abs() < 1e-6);
    }

    #[test]
    fn a_larger_group_stretches_the_interval_linearly() {
        // a bandwidth low enough that the 5s floor is not what is binding,
        // so scaling the membership is the only thing moving the interval
        const TINY_BANDWIDTH: f64 = 1.0;
        let mut small = IntervalTimer::new(TINY_BANDWIDTH, PACKET, 0.5);
        small.sent(Duration::ZERO, PACKET, 0.5); // clear `initial`
        let Due::Wait(small_deadline) = small.due(Duration::from_secs(1), 0.5) else {
            panic!("not yet due");
        };

        let mut large = IntervalTimer::new(TINY_BANDWIDTH, PACKET, 0.5);
        large.sent(Duration::ZERO, PACKET, 0.5);
        for _ in 0..9 {
            large.note_member();
        }
        let Due::Wait(large_deadline) = large.due(Duration::from_secs(1), 0.5) else {
            panic!("not yet due");
        };
        // ten times the members, and the interval scales by the same
        // factor
        let ratio = large_deadline.as_secs_f64() / small_deadline.as_secs_f64();
        assert!((ratio - 10.0).abs() < 1e-6, "ratio was {ratio}");
    }

    #[test]
    fn due_sends_once_the_previous_interval_has_actually_elapsed() {
        let mut timer = IntervalTimer::new(BANDWIDTH, PACKET, 0.5);
        let deadline = timer.next_deadline();
        assert_eq!(
            timer.due(Duration::ZERO, 0.5),
            Due::Wait(deadline),
            "nothing has elapsed yet"
        );
        assert_eq!(timer.due(deadline, 0.5), Due::Send);
    }

    #[test]
    fn a_zero_bandwidth_falls_back_to_the_minimum_interval_rather_than_dividing_by_zero() {
        let timer = IntervalTimer::new(0.0, PACKET, 0.5);
        assert!(timer.next_deadline().is_finite_and_positive());
    }

    trait FiniteAndPositive {
        fn is_finite_and_positive(&self) -> bool;
    }
    impl FiniteAndPositive for Duration {
        fn is_finite_and_positive(&self) -> bool {
            self.as_secs_f64() > 0.0 && self.as_secs_f64().is_finite()
        }
    }

    #[test]
    fn reverse_reconsideration_pulls_the_deadline_forward_when_membership_falls() {
        // §6.3.4: tn = tc + (members/pmembers)*(tn-tc)
        let mut timer = IntervalTimer::new(BANDWIDTH, PACKET, 0.5);
        timer.note_member(); // members = 2, matching pmembers after `due`
        let now = Duration::from_secs(1);
        let _ = timer.due(now, 0.5); // pmembers := members == 2
        let before = timer.next_deadline();

        timer.remove_member(now); // members falls to 1
        let after = timer.next_deadline();
        assert!(after < before, "losing half the group halves what is left");
        let expected = now + (before.saturating_sub(now)) / 2;
        // both sides round to Duration's nanosecond resolution independently
        assert!((after.as_secs_f64() - expected.as_secs_f64()).abs() < 1e-6);
    }

    #[test]
    fn reverse_reconsideration_does_nothing_when_membership_has_not_shrunk() {
        let mut timer = IntervalTimer::new(BANDWIDTH, PACKET, 0.5);
        let before = timer.next_deadline();
        timer.note_member(); // members grows, not shrinks
        timer.remove_member(Duration::ZERO); // back to 1, still == pmembers
        assert_eq!(timer.next_deadline(), before);
    }

    #[test]
    fn small_sessions_never_need_the_bye_backoff() {
        let mut timer = IntervalTimer::new(BANDWIDTH, PACKET, 0.5);
        assert!(!timer.should_back_off_bye());
        for _ in 0..49 {
            timer.note_member();
        }
        assert!(
            !timer.should_back_off_bye(),
            "exactly fifty is not more than fifty"
        );
        timer.note_member();
        assert!(timer.should_back_off_bye());
    }

    #[test]
    fn leaving_resets_membership_to_just_the_departing_participant() {
        let mut timer = IntervalTimer::new(BANDWIDTH, PACKET, 0.5);
        for _ in 0..5 {
            timer.note_member();
        }
        timer.note_local_sender();
        let deadline = timer.leaving(Duration::from_secs(10), 40, 0.5);
        assert!(deadline > Duration::from_secs(10));
        // a fresh `due` at that deadline should send: the reset put
        // `initial` back to true, so the interval is the smaller one again
        assert_eq!(timer.due(deadline, 0.5), Due::Send);
        assert!(timer.is_departing());
    }

    #[test]
    fn sent_bye_does_not_reset_membership_the_way_leaving_does() {
        // §6.3.7 lets a participant at or below the fifty-member threshold
        // "send a BYE packet immediately", without bullet one's reset. The
        // large bandwidth pins the interval at its floor, so only a reset
        // `initial` could move the schedule.
        const HUGE_BANDWIDTH: f64 = 1e9;
        let mut timer = IntervalTimer::new(HUGE_BANDWIDTH, PACKET, 0.5);
        timer.note_member();
        // clears `initial`, as a session's first real report would before
        // anyone hangs up
        let _ = timer.sent(Duration::ZERO, PACKET, 0.5);

        let deadline = timer.sent_bye(Duration::from_secs(1), 40, 0.5);
        let floor =
            Duration::try_from_secs_f64(super::MIN_INTERVAL_SECS / super::REDRAW_COMPENSATION)
                .expect("a positive, finite duration");
        assert!(
            (deadline.as_secs_f64() - (Duration::from_secs(1) + floor).as_secs_f64()).abs() < 1e-6,
            "sent_bye moved the schedule as if `initial` had been reset to true"
        );
        assert!(timer.is_departing());
    }

    #[test]
    fn note_bye_while_departing_counts_a_departure_up_not_down() {
        // §6.3.7 bullet two: while leaving, each received BYE increments
        // members, the opposite of §6.3.4's usual decrement.
        let mut timer = IntervalTimer::new(BANDWIDTH, PACKET, 0.5);
        timer.note_member();
        timer.sent_bye(Duration::ZERO, 40, 0.5);
        assert!(timer.is_departing());

        let members_before = timer.members;
        timer.note_bye_while_departing();
        assert_eq!(timer.members, members_before + 1);
    }
}
