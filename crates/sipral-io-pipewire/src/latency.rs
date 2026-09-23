// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! How long a sample takes to get out of the machine and back into it.
//!
//! An echo canceller is handed the frame that was leaving the loudspeaker
//! while the microphone was open, and this is how far back that frame is.
//! Unlike CoreAudio, which answers with four independently-optional
//! properties per direction (see `sipral-io-coreaudio::Latency`), PipeWire
//! keeps one structure, `struct pw_time`, that a stream reads whole with
//! `pw_stream_get_time_n`. Its own header is explicit about the three parts
//! that make it up and are summed here:
//!
//! - `delay`, in the graph driver's own rate: everything between this
//!   stream and the hardware edge of the graph — the resamplers and filters
//!   other nodes add, and the device's own latency. Stable while the graph's
//!   topology, quantum and sample rate are, and the number that changes when
//!   a headset with a different buffer size is plugged in.
//! - `queued`, in this stream's own configured rate: frames this crate has
//!   handed to PipeWire (playback) or PipeWire has handed to this crate
//!   (capture) that the graph has not processed yet.
//! - `buffered`, in the same rate: frames held inside PipeWire's own
//!   resampler, converting between this stream's rate and the graph's.
//!
//! `pw_time` also carries `now` and `ticks`, meant for extrapolating `delay`
//! forward to the instant of a later read. This crate does not: the
//! realtime thread reads `pw_time` at the end of every quantum and keeps the
//! last one, so what a caller reads is at most one graph cycle old, a few
//! milliseconds, and extrapolating it would spend more code than the error
//! it removes.
//!
//! Until a stream has run its first quantum there is nothing kept, and every
//! field reads zero. Unlike CoreAudio's `Latency`, which reports what a
//! device answered and leaves the rest `None`, this one holds either what
//! PipeWire returned or nothing at all.

use core::fmt;
use core::time::Duration;

/// Nanoseconds in a second, which is what turns frames at a rate into a time.
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// A rational sample rate, as `pw_time.rate` carries it: `num` ticks per
/// `denom` of a second. PipeWire usually reports this as `1/<samplerate>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rate {
    /// `pw_time.rate.num`.
    pub num: u32,
    /// `pw_time.rate.denom`.
    pub denom: u32,
}

impl Rate {
    /// How many whole seconds one tick of `frames` covers, as nanoseconds.
    fn nanos(self, frames: u64) -> u64 {
        if self.denom == 0 {
            return 0;
        }
        // frames * num / denom seconds, in nanoseconds: the multiply happens
        // before the divide so a fractional tick is not truncated to zero
        // first, and it is done in u128 because frames and NANOS_PER_SECOND
        // both being large is exactly the case this exists to get right.
        let nanos = u128::from(frames) * u128::from(self.num) * u128::from(NANOS_PER_SECOND)
            / u128::from(self.denom);
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }
}

/// What one direction of one stream reported about itself, read from one
/// `pw_time`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Latency {
    /// `pw_time.delay`, in `rate` units: the graph's own latency to or from
    /// the hardware edge.
    pub delay_ticks: u64,
    /// `pw_time.rate`, the unit `delay_ticks` is counted in.
    pub rate: Rate,
    /// `pw_time.queued`, in this stream's own sample rate.
    pub queued_frames: u64,
    /// `pw_time.buffered`, in this stream's own sample rate.
    pub buffered_frames: u64,
    /// This stream's own configured sample rate, which `queued_frames` and
    /// `buffered_frames` are counted at.
    pub stream_rate_hz: u32,
}

impl Latency {
    /// The three parts added into one duration.
    #[must_use]
    pub fn duration(&self) -> Duration {
        let graph = self.rate.nanos(self.delay_ticks);
        let stream = if self.stream_rate_hz == 0 {
            0
        } else {
            let frames = self.queued_frames.saturating_add(self.buffered_frames);
            u64::try_from(
                u128::from(frames) * u128::from(NANOS_PER_SECOND) / u128::from(self.stream_rate_hz),
            )
            .unwrap_or(u64::MAX)
        };
        Duration::from_nanos(graph.saturating_add(stream))
    }
}

impl fmt::Display for Latency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} ({} graph ticks at {}/{}, {} queued + {} buffered at {} Hz)",
            self.duration(),
            self.delay_ticks,
            self.rate.num,
            self.rate.denom,
            self.queued_frames,
            self.buffered_frames,
            self.stream_rate_hz
        )
    }
}

/// The whole loop: down to the loudspeaker, through the room, and back up
/// from the microphone.
///
/// This is the number an echo canceller wants, and the two halves are kept
/// apart because they can be different nodes and because a delay that is
/// wrong is usually wrong on one side.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenderDelay {
    /// From this crate to the loudspeaker.
    pub playback: Latency,
    /// From the microphone to this crate.
    pub capture: Latency,
}

impl RenderDelay {
    /// Both halves as one time, which is what an echo canceller is told to
    /// look back by.
    #[must_use]
    pub fn total(&self) -> Duration {
        self.playback
            .duration()
            .saturating_add(self.capture.duration())
    }
}

impl fmt::Display for RenderDelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} to the loudspeaker and back: playback {}, capture {}",
            self.total(),
            self.playback,
            self.capture
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Latency, Rate, RenderDelay};
    use core::time::Duration;

    /// What a stream running at 8 kHz on a 48 kHz graph, one quantum behind,
    /// looks like.
    fn playback() -> Latency {
        Latency {
            delay_ticks: 480,
            rate: Rate {
                num: 1,
                denom: 48_000,
            },
            queued_frames: 160,
            buffered_frames: 40,
            stream_rate_hz: 8_000,
        }
    }

    #[test]
    fn the_graph_and_the_stream_parts_add_up() {
        let leg = playback();
        // 480 ticks at 1/48000 s each is 10 ms
        // 200 frames (160 + 40) at 8 kHz is 25 ms
        assert_eq!(leg.duration(), Duration::from_millis(35));
    }

    #[test]
    fn a_rate_of_zero_denominator_contributes_nothing_rather_than_dividing_by_zero() {
        let leg = Latency {
            rate: Rate { num: 1, denom: 0 },
            ..playback()
        };
        // only the stream-side 25 ms is left
        assert_eq!(leg.duration(), Duration::from_millis(25));
    }

    #[test]
    fn a_stream_rate_of_zero_leaves_only_the_graph_part() {
        let leg = Latency {
            stream_rate_hz: 0,
            ..playback()
        };
        assert_eq!(leg.duration(), Duration::from_millis(10));
    }

    #[test]
    fn a_fresh_latency_is_silence_and_costs_nothing() {
        assert_eq!(Latency::default().duration(), Duration::ZERO);
        assert_eq!(RenderDelay::default().total(), Duration::ZERO);
    }

    #[test]
    fn the_loop_is_both_directions_summed() {
        let delay = RenderDelay {
            playback: playback(),
            capture: Latency {
                delay_ticks: 480,
                rate: Rate {
                    num: 1,
                    denom: 48_000,
                },
                queued_frames: 160,
                buffered_frames: 0,
                stream_rate_hz: 8_000,
            },
        };
        assert_eq!(
            delay.total(),
            delay.playback.duration() + delay.capture.duration()
        );
        assert!(delay.to_string().contains("to the loudspeaker and back"));
    }

    #[test]
    fn huge_frame_counts_do_not_wrap_round() {
        let absurd = Latency {
            delay_ticks: u64::MAX,
            rate: Rate { num: 1, denom: 1 },
            queued_frames: 0,
            buffered_frames: 0,
            stream_rate_hz: 8_000,
        };
        // saturates rather than panicking on the multiply or wrapping round
        assert_eq!(absurd.duration(), Duration::from_nanos(u64::MAX));
    }
}
