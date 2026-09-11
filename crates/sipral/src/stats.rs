// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the call cost, for the two people who ask.
//!
//! There are two consumers and they want different things. A live indicator is
//! polled at the frame rate of a user interface and must therefore be cheap:
//! no allocation, no lock, nothing that walks a history. An end-of-call record
//! is written once and must be complete, because the moment anybody asks why a
//! call sounded bad is after it has ended.
//!
//! Both are the same value here. The jitter buffer already keeps everything
//! either of them needs — [`Quality`] is a plain copyable struct it hands back
//! on demand — and RTCP contributes the round-trip time, which is the one
//! number the receiving side cannot work out for itself. The requirement was
//! never to compute any of this. It was that it reaches the application, which
//! until this crate existed it could not, because nothing joined the two
//! halves of the stack.

use std::time::Duration;

use sipral_rtp::Quality;

use crate::codec::Codec;

/// Loss above which a call is unusable rather than merely bad, as a
/// percentage. Past this the score is zero however good everything else is.
const HOPELESS_LOSS: f32 = 20.0;

/// Round-trip time at which conversation stops working: ITU-T G.114 puts the
/// limit of an acceptable one-way delay at 400 ms, and this is that, both
/// ways, as the point where the score reaches zero.
const HOPELESS_ROUND_TRIP: Duration = Duration::from_millis(800);

/// Jitter buffer delay at which the same is true. The buffer will go this far
/// to keep audio in sequence, and by the time it has, the two people are
/// talking over each other.
const HOPELESS_DELAY: Duration = Duration::from_millis(500);

/// What one call's media has done, and is doing.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct StreamStatistics {
    /// What the negotiation settled on, which is the first thing anybody
    /// looking at a bad call wants to know.
    pub codec: Codec,
    /// Everything the de-jitter buffer counted: packets, loss, the delay it
    /// chose, and the jitter it measured.
    pub quality: Quality,
    /// The round trip, from RTCP. `None` until a report has come back, which
    /// on a short call may be never — the first one is deliberately delayed
    /// (RFC 3550 §6.2), and a peer that sends no RTCP never provides one.
    pub round_trip: Option<Duration>,
    /// Packets this end has put on the wire.
    pub packets_sent: u64,
    /// Payload octets in them, not counting headers.
    pub octets_sent: u64,
    /// How long since a packet last arrived. A live call sits at one frame;
    /// anything larger is the beginning of [`MediaEvent::Stalled`].
    ///
    /// [`MediaEvent::Stalled`]: crate::MediaEvent::Stalled
    pub silent_for: Duration,
}

impl StreamStatistics {
    /// One number for a bar on a screen: a hundred for a call with nothing
    /// wrong with it, zero for one nobody can hold.
    ///
    /// Not an ITU-T G.107 rating and not a mean opinion score. Those need the
    /// codec's own impairment factors and an assumption about the listener,
    /// and a number that looks like a MOS but is not one is worse than a
    /// number that does not. This is the smallest honest thing: the three
    /// impairments that actually vary during a call — how much was lost, how
    /// far apart the ends are, and how much delay the buffer had to add to
    /// keep the audio in order — each scaled to the point at which it alone
    /// ruins the call, and the worst of the three deciding.
    ///
    /// The worst rather than the sum, deliberately. Impairments do not add up
    /// in any way that survives being written down, and a call with twenty
    /// percent loss is not made worse by also having low jitter.
    ///
    /// The three limits were chosen here, from the behaviour wanted, with only
    /// the round-trip one taken from anywhere authoritative. A reader who
    /// wants to retune them should measure rather than assume they came from a
    /// table.
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

    /// Whether the numbers say this call is in trouble now, which is a
    /// different question from what it has cost so far.
    ///
    /// Five percent concealed frames is where a listener starts asking the
    /// other person to repeat themselves, and it is the same threshold the
    /// codec is told to expect when it decides how much redundancy to send.
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
            silent_for: Duration::ZERO,
        }
    }

    /// Scores are compared to a tenth of a point: the arithmetic is in single
    /// precision and the question is never whether a bar is one part in a
    /// million taller.
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
        // each of those is exactly half of its own limit, so a sum would read
        // zero and the worst reads fifty
        assert_score(&stats, 50.0);
    }

    #[test]
    fn an_impairment_past_its_limit_does_not_drive_the_score_below_zero() {
        let mut stats = statistics();
        stats.quality.loss_rate = 1.0;
        stats.round_trip = Some(Duration::from_secs(30));
        assert_score(&stats, 0.0);
    }

    /// A call with no RTCP back from it has no round-trip time, and that is
    /// not the same as an infinite one.
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
