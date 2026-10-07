// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the call cost, for two kinds of reader.
//!
//! A live indicator polls at UI frame rate and needs it cheap: no allocation, lock or history walk.
//! An end-of-call record is written once and must be complete, since people ask why a call sounded
//! bad after it ended. Both are the same value here: the jitter buffer's copyable [`Quality`] plus
//! the RTCP round-trip time, the one number the receiver cannot measure itself.

use std::time::Duration;

use sipral_rtp::{Quality, VoipMetricsBlock};

use crate::codec::Codec;

/// Loss above which a call is unusable rather than merely bad, as a
/// percentage. Past this the score is zero however good everything else is.
const HOPELESS_LOSS: f32 = 20.0;

/// Round-trip time where conversation breaks down: ITU-T G.114's 400 ms one-way limit, both ways.
/// The score reaches zero here.
const HOPELESS_ROUND_TRIP: Duration = Duration::from_millis(800);

/// Jitter buffer delay at which the same holds: the buffer may go this far, but people then talk
/// over each other.
const HOPELESS_DELAY: Duration = Duration::from_millis(500);

/// What one call's media has done, and is doing.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct StreamStatistics {
    /// The negotiated codec, the first thing anyone checks on a bad call.
    pub codec: Codec,
    /// Everything the jitter buffer counted: packets, loss, chosen delay, measured jitter.
    pub quality: Quality,
    /// Round trip from RTCP. `None` until a report returns, which on a short call may never happen
    /// (the first is delayed, RFC 3550 §6.2) and never does with a peer that sends no RTCP.
    pub round_trip: Option<Duration>,
    /// Packets this end has put on the wire.
    pub packets_sent: u64,
    /// Payload octets in them, not counting headers.
    pub octets_sent: u64,
    /// Lost frames rebuilt from the FEC copy in the next packet instead of concealed (Opus, RFC
    /// 7587 §3.3). Included in [`Quality::lost`], which counts network losses; the difference is
    /// what reached the earpiece as concealment. Zero for other codecs.
    ///
    /// [`Quality::lost`]: sipral_rtp::Quality::lost
    pub fec_recovered: u64,
    /// Time since the last packet. One frame on a live call; more is the start of a
    /// [`MediaEvent::Stalled`].
    ///
    /// [`MediaEvent::Stalled`]: crate::MediaEvent::Stalled
    pub silent_for: Duration,
    /// The RFC 3611 §4.7 VoIP Metrics for this stream: burst and gap loss, delay, jitter buffer
    /// sizing, and the R factor and MOS from the simplified E-model
    /// (`sipral_rtp::evaluate_e_model`). `Some` once a source is identified, whether or not RTCP XR
    /// was negotiated; negotiation only decides whether they are also sent
    /// ([`sipral_rtp::RtpSession::build_report`]). RFC 6035 reports and these statistics both read
    /// this field.
    pub voip_metrics: Option<VoipMetricsBlock>,
    /// The negotiated RTP/AVPF feedback (RFC 4585, RFC 5506): Generic NACK, `trr-int`, reduced
    /// size. `None` unless both offer and answer named a feedback profile.
    pub feedback: Option<sipral_rtp::avpf::Negotiated>,
    /// What the feedback did: NACKs sent and received, Early and reduced-size packets, Regular ones
    /// suppressed by `trr-int`. Zero without feedback.
    pub feedback_counts: sipral_rtp::avpf::FeedbackCounts,
}

impl StreamStatistics {
    /// A single 0 to 100 number for a bar on screen: 100 is a clean call, 0 an unusable one.
    ///
    /// Not an ITU-T G.107 rating or MOS, which need codec impairment factors and listener
    /// assumptions; a fake MOS would mislead. It takes the three impairments that vary during a
    /// call (loss, round trip, buffer delay), scales each to the point where it alone ruins the
    /// call, and uses the worst. Impairments do not add meaningfully, and heavy loss is not
    /// improved by low jitter.
    ///
    /// Only the round-trip limit comes from a standard; the others were chosen for the behaviour
    /// wanted. Measure before retuning.
    #[must_use]
    pub fn score(&self) -> f32 {
        let loss = fraction(self.quality.loss_rate * 100.0, HOPELESS_LOSS);
        let round_trip = self
            .round_trip
            .map_or(0.0, |rtt| span(rtt, HOPELESS_ROUND_TRIP));
        let delay = span(self.quality.delay, HOPELESS_DELAY);
        let worst = loss.max(round_trip).max(delay).clamp(0.0, 1.0);
        (1.0 - worst) * 100.0
    }

    /// Whether the call is in trouble now, as opposed to its total cost. 5% concealed frames is
    /// where listeners start asking for repeats, and the same threshold the codec uses for
    /// redundancy.
    #[must_use]
    pub fn is_suffering(&self) -> bool {
        self.quality.loss_rate >= 0.05
    }
}

/// One impairment as a fraction of the point at which it alone ruins a call.
fn fraction(value: f32, hopeless: f32) -> f32 {
    if hopeless <= 0.0 {
        0.0
    } else {
        value / hopeless
    }
}

/// The same for a duration.
fn span(value: Duration, hopeless: Duration) -> f32 {
    fraction(value.as_secs_f32(), hopeless.as_secs_f32())
}

#[cfg(test)]
mod tests {
    use super::StreamStatistics;
    use crate::codec::Codec;
    use sipral_rtp::Quality;
    use std::time::Duration;

    fn statistics() -> StreamStatistics {
        StreamStatistics {
            codec: Codec::G722,
            quality: Quality::default(),
            round_trip: None,
            packets_sent: 0,
            octets_sent: 0,
            fec_recovered: 0,
            silent_for: Duration::ZERO,
            voip_metrics: None,
            feedback: None,
            feedback_counts: sipral_rtp::avpf::FeedbackCounts::default(),
        }
    }

    /// Scores are compared to a tenth of a point: the arithmetic is single precision.
    #[track_caller]
    fn assert_score(stats: &StreamStatistics, expected: f32) {
        let score = stats.score();
        assert!(
            (score - expected).abs() < 0.1,
            "expected {expected}, read {score}"
        );
    }

    #[test]
    fn a_call_with_nothing_wrong_with_it_reads_a_hundred() {
        assert_score(&statistics(), 100.0);
    }

    #[test]
    fn loss_alone_can_take_the_score_to_zero() {
        let mut stats = statistics();
        stats.quality.loss_rate = 0.20;
        assert_score(&stats, 0.0);
        stats.quality.loss_rate = 0.10;
        assert_score(&stats, 50.0);
    }

    #[test]
    fn distance_alone_can_take_the_score_to_zero() {
        let mut stats = statistics();
        stats.round_trip = Some(Duration::from_millis(800));
        assert_score(&stats, 0.0);
        stats.round_trip = Some(Duration::from_millis(200));
        assert_score(&stats, 75.0);
    }

    /// The worst impairment decides. A call with heavy loss does not read
    /// better because its round-trip time is good.
    #[test]
    fn the_worst_impairment_decides_rather_than_the_sum() {
        let mut stats = statistics();
        stats.quality.loss_rate = 0.10;
        stats.round_trip = Some(Duration::from_millis(400));
        stats.quality.delay = Duration::from_millis(100);
        // each is half its limit: a sum would give zero, the worst gives fifty
        assert_score(&stats, 50.0);
    }

    #[test]
    fn an_impairment_past_its_limit_does_not_drive_the_score_below_zero() {
        let mut stats = statistics();
        stats.quality.loss_rate = 1.0;
        stats.round_trip = Some(Duration::from_secs(30));
        assert_score(&stats, 0.0);
    }

    /// No RTCP back means no round-trip time, not an infinite one.
    #[test]
    fn a_missing_round_trip_time_does_not_count_against_the_call() {
        let mut stats = statistics();
        stats.round_trip = None;
        assert_score(&stats, 100.0);
    }

    #[test]
    fn suffering_is_about_now_rather_than_about_the_whole_call() {
        let mut stats = statistics();
        stats.quality.lost = 10_000;
        assert!(!stats.is_suffering(), "the cumulative counter is history");
        stats.quality.loss_rate = 0.06;
        assert!(stats.is_suffering());
    }
}
