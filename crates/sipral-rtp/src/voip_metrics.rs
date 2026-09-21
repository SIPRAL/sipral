// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Burst/gap loss classification for the VoIP Metrics Report Block (RFC
//! 3611 §4.7.2), by the event-driven algorithm RFC 3611 Appendix A.2
//! reproduces from ETSI TS 101 329-5: "this algorithm ... takes precedence
//! over any change that might eventually be made to the algorithm in
//! future ETSI documents", which is why the state names and transition
//! counters below (`c11`, `c13`, ...) keep the appendix's own names rather
//! than renaming them into something more descriptive — a reviewer
//! checking this against the RFC text should be able to match variable for
//! variable.
//!
//! §4.7.2 defines a burst as the longest run that starts and ends with a
//! lost or discarded packet and contains no run of `Gmin` or more
//! consecutively-received packets inside it; a gap is everything between
//! bursts. `Gmin` itself is a threshold the caller chooses once per session
//! and never changes (§4.7.2: "Gmin MUST not be zero ... and MUST remain
//! constant across VoIP Metrics report blocks for the duration of the RTP
//! session").

/// What happened to one RTP packet, as the appendix's `packet_lost` and
/// `packet_discarded` booleans distinguish it. A received-and-kept packet
/// is neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketOutcome {
    /// Arrived and was handed to the application.
    Received,
    /// Never arrived (or arrived so late it is counted as loss rather than
    /// a discard, §4.7.1's "MAY categorize late-arriving packets as
    /// lost").
    Lost,
    /// Arrived but the jitter buffer dropped it (too late, too early,
    /// under-run or overflow, §4.7.1).
    Discarded,
}

/// The four §4.7.2 fields this module computes, plus the loss/discard
/// rates of §4.7.1 that share the same running counts. Values are already
/// the field's own units: loss/discard/burst/gap density as 256ths
/// (§4.7.1, §4.7.2), duration in whole milliseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BurstGapMetrics {
    pub(crate) loss_rate: u8,
    pub(crate) discard_rate: u8,
    pub(crate) burst_density: u8,
    pub(crate) gap_density: u8,
    pub(crate) burst_duration_ms: u16,
    pub(crate) gap_duration_ms: u16,
}

/// The running state Appendix A.2's algorithm keeps between packets: which
/// of its four states the stream is currently in (tracked implicitly, the
/// same way the appendix's pseudocode does, through `pkt` and `lost`
/// rather than an explicit enum), and the eight transition counters it
/// accumulates.
///
/// `Gmin` is fixed at construction and never changes, per §4.7.2.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GminTracker {
    /// `Gmin`: the received-run length that ends a burst. Never zero
    /// (§4.7.2).
    gmin: u8,
    /// `pkt`: consecutively-received packets since the last loss or
    /// discard.
    pkt: u64,
    /// `lost`: packets lost or discarded since the current burst began;
    /// zero while the stream is in a gap.
    lost: u64,
    /// `c11`: total packets received while in a gap.
    c11: u64,
    /// `c13`: gap-to-burst transitions, i.e. the number of bursts.
    c13: u64,
    /// `c14`: isolated losses inside a gap (a run shorter than `gmin`
    /// wrapped in received packets on both sides never grows past this).
    c14: u64,
    /// `c22`: packets received inside a burst, beyond the one that starts
    /// each losing run there.
    c22: u64,
    /// `c23`: burst-received-run-followed-by-another-loss transitions.
    c23: u64,
    /// `c33`: back-to-back losses inside a burst.
    c33: u64,
    /// Packets lost (not discarded) since construction, for §4.7.1's loss
    /// rate.
    loss_count: u64,
    /// Packets discarded since construction, for §4.7.1's discard rate.
    discard_count: u64,
    /// Every packet slot observed since construction — received, lost or
    /// discarded — §4.7.1's "total number of packets expected". Kept
    /// separately from the burst algorithm's own `ctotal` (computed in
    /// [`Self::metrics`]): that count only reflects packets the appendix's
    /// state machine has flushed into a classified gap or burst, and a
    /// trailing run of received packets not yet followed by another loss
    /// stays outside it, which would understate loss and discard rate.
    total: u64,
}

impl GminTracker {
    /// A tracker for one reception, with no packets observed yet. `gmin`
    /// is clamped to at least 1: the appendix's `pkt >= gmin` test would
    /// otherwise classify every single loss as ending a burst on its own.
    ///
    /// `lost` starts at 1 rather than 0. §4.7.2 states the convention the
    /// appendix's pseudocode itself relies on but never restates: "it is
    /// assumed that the RTP session is preceded ... by at least Gmin
    /// received packets" — so the first loss or discard the session ever
    /// sees should be classified exactly as if it followed a burst that
    /// had already ended with a single loss, which is what `lost == 1`
    /// means at every later flush. Starting at 0 instead would make that
    /// first flush always take the pseudocode's `else` branch (since `0
    /// != 1`) and count a clean session's very first isolated loss as the
    /// start of a real burst, which is exactly the "at least Gmin
    /// received packets" assumption's job to prevent.
    #[must_use]
    pub(crate) const fn new(gmin: u8) -> Self {
        Self {
            gmin: if gmin == 0 { 1 } else { gmin },
            pkt: 0,
            lost: 1,
            c11: 0,
            c13: 0,
            c14: 0,
            c22: 0,
            c23: 0,
            c33: 0,
            loss_count: 0,
            discard_count: 0,
            total: 0,
        }
    }

    /// `Gmin`, as constructed.
    #[must_use]
    pub(crate) const fn gmin(&self) -> u8 {
        self.gmin
    }

    /// Fold in the outcome of the next packet in sequence order, exactly
    /// the state transition Appendix A.2's pseudocode performs per event.
    pub(crate) fn observe(&mut self, outcome: PacketOutcome) {
        let (packet_lost, packet_discarded) = match outcome {
            PacketOutcome::Received => (false, false),
            PacketOutcome::Lost => (true, false),
            PacketOutcome::Discarded => (false, true),
        };
        self.total += 1;
        if packet_lost {
            self.loss_count += 1;
        }
        if packet_discarded {
            self.discard_count += 1;
        }
        if !packet_lost && !packet_discarded {
            self.pkt += 1;
            return;
        }
        if self.pkt >= u64::from(self.gmin) {
            if self.lost == 1 {
                self.c14 += 1;
            } else {
                self.c13 += 1;
            }
            self.lost = 1;
            self.c11 += self.pkt;
        } else {
            self.lost += 1;
            if self.pkt == 0 {
                self.c33 += 1;
            } else {
                self.c23 += 1;
                self.c22 += self.pkt - 1;
            }
        }
        self.pkt = 0;
    }

    /// §4.7.1's loss and discard rates, and §4.7.2's burst/gap densities
    /// and mean durations, from the counts accumulated so far.
    /// `packet_duration_ms` is the appendix's `m`, the nominal duration one
    /// RTP packet's payload spans — the per-packet time unit its `c11`,
    /// `ctotal` and the rest are converted through to get milliseconds.
    /// Reported at the field's own resolution: densities as 256ths
    /// clamped to 255 (§4.7.1, §4.7.2's "limiting the maximum value to 255
    /// to avoid overflow"), durations in whole milliseconds saturated to
    /// `u16::MAX`.
    #[must_use]
    pub(crate) fn metrics(&self, packet_duration_ms: u32) -> BurstGapMetrics {
        // c31 = c13, c32 = c23: the appendix counts each burst-adjacent
        // transition once under the name of its forward direction and
        // reuses it, since a gap-burst boundary is crossed the same
        // number of times each way.
        let c31 = self.c13;
        let c32 = self.c23;
        let ctotal = self.c11 + self.c14 + self.c13 + self.c22 + self.c23 + c31 + c32 + self.c33;

        // §4.7.1: "dividing the total number of packets lost ... by the
        // total number of packets expected" -- every slot this tracker
        // has seen, not the appendix's `ctotal`, which only reflects
        // packets the state machine has classified into a finished gap or
        // burst so far and understates the true total whenever the
        // stream's tail is still a clean, unflushed run of receives.
        let loss_rate = scale_256(self.loss_count, self.total);
        let discard_rate = scale_256(self.discard_count, self.total);

        // §4.7.2: "MUST be set to zero if no packets have been received",
        // extended here to "if no burst has ever occurred": p32 and p23
        // are burst-relative quantities the appendix defines only in
        // terms of a burst's own transitions, and with none of those
        // ever recorded (c13 == 0), its `p23 = 1` fallback below would
        // otherwise still produce a nonzero, meaningless density out of
        // a stream that has never had a burst to measure one in.
        let burst_density = if self.c13 == 0 {
            0
        } else {
            // p32: the fraction of burst-received runs that end the
            // burst rather than continue it.
            let p32_den = c31 + c32 + self.c33;
            let p32 = ratio(c32, p32_den);
            // p23: the fraction of burst losses that are followed by a
            // burst-ending receive run rather than another immediate
            // loss. "if (c22 + c23) < 1, p23 = 1": every loss in the
            // burst was back-to-back, i.e. certain to be followed by
            // another loss.
            let p23 = if self.c22 + self.c23 < 1 {
                1.0
            } else {
                1.0 - ratio(self.c22, self.c22 + self.c23)
            };
            if p23 + p32 <= 0.0 {
                0
            } else {
                scale_256_f64(256.0 * p23 / (p23 + p32))
            }
        };
        let gap_density = scale_256(self.c14, self.c11 + self.c14);

        let (burst_duration_ms, gap_duration_ms) = if self.c13 == 0 {
            // §4.7.2: "If there have been no burst periods, the burst
            // duration value MUST be zero". Whether the trailing,
            // not-yet-flushed run of packets counts as one long gap
            // depends on what it trails: `self.lost == 1` is this
            // tracker's own signal for "currently between confirmed
            // bursts, not partway through an unresolved one" (see
            // `observe`'s reset to 1 on every gap-ending flush), which is
            // exactly §4.7.2(b)'s "period from ... the last burst to ...
            // the time of the report" -- read as "session start" when, as
            // here, no burst has confirmed yet either. `self.total`, not
            // the appendix's own `ctotal`, is the right count for it: the
            // whole point of this branch is that nothing has been
            // flushed into `ctotal` yet. A `lost != 1` tail instead means
            // the session ends partway through a loss run that never
            // reached `gmin` clean packets to close it, which is neither
            // a confirmed gap nor a confirmed burst, so this falls back
            // to the RFC's own "if there have been no gap periods, the
            // gap duration value MUST be zero".
            let gap_ms = if self.lost == 1 {
                u64::from(packet_duration_ms) * self.total
            } else {
                0
            };
            (0, ms_to_field(gap_ms))
        } else {
            let m = u64::from(packet_duration_ms);
            // `self.c13 != 0` here, this branch's own condition, but the
            // divisor is still routed through `checked_div` rather than a
            // bare `/`: a value proven nonzero by a branch two lines away
            // is exactly the case a future edit could silently break.
            let gap_length_ms = ((self.c11 + self.c14 + self.c13) * m)
                .checked_div(self.c13)
                .unwrap_or(0);
            let cycle_ms = (ctotal * m).checked_div(self.c13).unwrap_or(0);
            let burst_length_ms = cycle_ms.saturating_sub(gap_length_ms);
            (ms_to_field(burst_length_ms), ms_to_field(gap_length_ms))
        };

        BurstGapMetrics {
            loss_rate,
            discard_rate,
            burst_density,
            gap_density,
            burst_duration_ms,
            gap_duration_ms,
        }
    }
}

/// `256 * numerator / denominator`, taking the integer part and clamping
/// to 255, the shared recipe behind every 256ths field in §4.7.1/§4.7.2.
/// Zero when `denominator` is zero, matching those sections' "MUST be set
/// to zero if no packets have been received".
fn scale_256(numerator: u64, denominator: u64) -> u8 {
    if denominator == 0 {
        return 0;
    }
    let scaled = numerator.saturating_mul(256) / denominator;
    u8::try_from(scaled.min(255)).unwrap_or(255)
}

/// `numerator / denominator` as a float, `0.0` when `denominator` is zero
/// (used inside `burst_density`'s two-ratio formula, which the plain
/// integer `scale_256` above cannot express).
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        #[allow(
            clippy::cast_precision_loss,
            reason = "packet counts over a call never approach f64's 53-bit mantissa"
        )]
        {
            numerator as f64 / denominator as f64
        }
    }
}

/// A value already computed as `256 * ...`, clamped into the field's
/// `0..=255` range and truncated to its integer part.
fn scale_256_f64(value: f64) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped into 0.0..=255.0 immediately above"
    )]
    let clamped = value.clamp(0.0, 255.0) as u8;
    clamped
}

/// A millisecond count into the field's sixteen-bit range, saturating
/// rather than wrapping a session long or bursty enough to overflow it.
fn ms_to_field(ms: u64) -> u16 {
    u16::try_from(ms).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::{BurstGapMetrics, GminTracker, PacketOutcome};

    /// RFC 3611 §4.7.2's own worked example: 64 packets, Gmin = 16, 10 ms
    /// packets, laid out as
    /// `11110111111111111111111X111X1011110111111111111111111X111111111`
    /// (`1` received, `0` lost, `X` discarded) plus one trailing `1`. The
    /// pattern as transcribed in the RFC's plain-text rendering is 63
    /// characters, one short of the "64 packets" the prose says it
    /// covers and of the "290 ms" it states for the final gap (28 of the
    /// stated 29 packets at 10 ms each); the trailing receive lost to
    /// text reflow is restored here so the packet count and every
    /// duration figure this test does not check are internally
    /// consistent with the RFC's own prose.
    fn rfc_example_pattern() -> &'static str {
        "11110111111111111111111X111X1011110111111111111111111X1111111111"
    }

    fn run_pattern(pattern: &str, gmin: u8, packet_duration_ms: u32) -> BurstGapMetrics {
        let mut tracker = GminTracker::new(gmin);
        for ch in pattern.chars() {
            let outcome = match ch {
                '1' => PacketOutcome::Received,
                '0' => PacketOutcome::Lost,
                'X' => PacketOutcome::Discarded,
                other => panic!("unexpected symbol {other} in test pattern"),
            };
            tracker.observe(outcome);
        }
        tracker.metrics(packet_duration_ms)
    }

    #[test]
    fn the_rfc_3611_worked_example_reproduces_its_stated_loss_and_discard_rate() {
        // §4.7.1's rate is lost-or-discarded over every packet the
        // session expected, 3 of each out of 64: 256*3/64 = 12 exactly,
        // which is what RFC 3611 SS4.7.2 states ("loss rate 12 ...
        // discard rate 12").
        let metrics = run_pattern(rfc_example_pattern(), 16, 10);
        assert_eq!(metrics.loss_rate, 12);
        assert_eq!(metrics.discard_rate, 12);
    }

    /// A pattern small enough to trace by hand against Appendix A.2's own
    /// pseudocode, exercising every one of its eight counters: `Gmin = 2`,
    /// 10 ms packets, "1" received / "0" lost / "X" discarded:
    ///
    /// ```text
    /// 111 0 111 0 0 0 11 X
    /// ```
    ///
    /// Walking the appendix's state machine event by event (each row is
    /// one loss/discard flush; `pkt` is the receive run immediately
    /// before it; `lost` starts at 1, not 0 -- see [`GminTracker::new`]):
    ///
    /// | event | pkt | branch | effect |
    /// |---|---|---|---|
    /// | loss #1 | 3 (>= Gmin) | outer | `lost == 1` (construction default) -> `c14 += 1` (an isolated gap loss); `c11 += 3`; `lost = 1` |
    /// | loss #2 | 3 (>= Gmin) | outer | `lost == 1` -> `c14 += 1` (c14 = 2, loss #2 isolated too); `c11 += 3` (c11 = 6); `lost = 1` |
    /// | loss #3 | 0 (< Gmin) | inner | `lost += 1` (= 2); `pkt == 0` -> `c33 += 1` |
    /// | loss #4 | 0 (< Gmin) | inner | `lost += 1` (= 3); `pkt == 0` -> `c33 += 1` (c33 = 2) |
    /// | discard #1 | 2 (>= Gmin) | outer | `lost == 3` -> `c13 += 1` (c13 = 1, the #3-#4 run classified as the pattern's one real burst); `c11 += 2` (c11 = 8) |
    ///
    /// which leaves `c11=8, c13=1, c14=2, c22=0, c23=0, c33=2`,
    /// `ctotal = 8+2+1+0+0+1+0+2 = 14`, `total = 13` packets observed (4
    /// lost, 1 discarded, 8 received).
    #[test]
    fn a_hand_traced_pattern_matches_appendix_a2s_pseudocode_exactly() {
        let metrics = run_pattern("111011100011X", 2, 10);

        // SS4.7.1: 256 * lost / total = 256 * 4 / 13 = 78.77 -> 78; same
        // for discard, 256 * 1 / 13 = 19.69 -> 19.
        assert_eq!(metrics.loss_rate, 78);
        assert_eq!(metrics.discard_rate, 19);

        // p32 = c32/(c31+c32+c33) = 0/(1+0+2) = 0; c22+c23 = 0, so
        // p23 = 1; burst_density = 256*1/(1+0) = 256, saturating at the
        // field's 255 maximum (SS4.7.2's "limiting the maximum value to
        // 255 to avoid overflow") -- consistent with the one burst here
        // (c33=2, c22=c23=0) never having a single received packet
        // inside it.
        assert_eq!(metrics.burst_density, 255);
        // gap_density = 256*c14/(c11+c14) = 256*2/10 = 51.2 -> 51.
        assert_eq!(metrics.gap_density, 51);

        // gap_length = (c11+c14+c13)*m/c13 = (8+2+1)*10/1 = 110 ms;
        // cycle = ctotal*m/c13 = 14*10/1 = 140 ms;
        // burst_length = cycle - gap_length = 30 ms.
        assert_eq!(metrics.burst_duration_ms, 30);
        assert_eq!(metrics.gap_duration_ms, 110);
    }

    #[test]
    fn a_stream_with_nothing_observed_yet_reports_every_field_as_zero() {
        let tracker = GminTracker::new(16);
        let metrics = tracker.metrics(20);
        assert_eq!(metrics, BurstGapMetrics::default());
    }

    #[test]
    fn a_perfect_stream_has_no_loss_and_no_burst() {
        let mut tracker = GminTracker::new(16);
        for _ in 0..100 {
            tracker.observe(PacketOutcome::Received);
        }
        let metrics = tracker.metrics(20);
        assert_eq!(metrics.loss_rate, 0);
        assert_eq!(metrics.discard_rate, 0);
        assert_eq!(metrics.burst_density, 0);
        assert_eq!(metrics.burst_duration_ms, 0, "no burst has ever occurred");
        // the whole 2000 ms session observed so far is a single gap
        assert_eq!(metrics.gap_duration_ms, 2000);
    }

    #[test]
    fn an_isolated_loss_inside_a_long_gap_never_starts_a_burst() {
        let mut tracker = GminTracker::new(4);
        for _ in 0..20 {
            tracker.observe(PacketOutcome::Received);
        }
        tracker.observe(PacketOutcome::Lost);
        for _ in 0..20 {
            tracker.observe(PacketOutcome::Received);
        }
        let metrics = tracker.metrics(20);
        assert_eq!(
            metrics.burst_duration_ms, 0,
            "one loss preceded and followed by >= gmin receives is a gap loss, not a burst"
        );
        assert!(metrics.loss_rate > 0);
    }

    #[test]
    fn gmin_of_zero_is_treated_as_one_rather_than_dividing_by_it() {
        let mut tracker = GminTracker::new(0);
        assert_eq!(tracker.gmin(), 1);
        tracker.observe(PacketOutcome::Received);
        tracker.observe(PacketOutcome::Lost);
        let metrics = tracker.metrics(20);
        assert_eq!(metrics.burst_duration_ms, 0);
    }

    #[test]
    fn a_run_of_losses_at_the_very_start_is_one_burst_not_isolated_losses() {
        // pkt starts at 0, which is < any gmin >= 1, so the first loss and
        // every immediately-following one accumulate as c33/c23 inside a
        // single burst, exactly like a burst anywhere else in the stream.
        // A burst is only classified once a later flush event closes it
        // (Appendix A.2's `lost == 1` test runs at the *next* loss or
        // discard, not the one that starts the run), so this pattern ends
        // with one more loss after the qualifying receive run: without
        // it, `c13` would still be zero and `burst_duration_ms` would
        // correctly read zero for a burst that has not been seen to end.
        let mut tracker = GminTracker::new(16);
        tracker.observe(PacketOutcome::Lost);
        tracker.observe(PacketOutcome::Lost);
        tracker.observe(PacketOutcome::Lost);
        for _ in 0..20 {
            tracker.observe(PacketOutcome::Received);
        }
        tracker.observe(PacketOutcome::Lost);
        let metrics = tracker.metrics(10);
        assert!(
            metrics.burst_duration_ms > 0,
            "three consecutive losses at stream start must count as a burst, once a later flush classifies it"
        );
    }
}
