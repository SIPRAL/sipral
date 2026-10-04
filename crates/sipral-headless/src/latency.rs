// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The arithmetic `docs/07-headless.md`'s Latency section names: buffer depth
//! plus decode plus one frame from the wire to the agent, encode plus one
//! frame back.
//!
//! Buffer depth, decode and encode all happen upstream of this crate — the
//! jitter buffer and the codec belong to `sipral-rtp`, not here — so they are
//! numbers a caller supplies as conditions change rather than anything this
//! module measures. The one frame this crate does own is the duration every
//! session agreed to at open, which is why it is added on both sides rather
//! than asked for.

use crate::audio::AudioConfig;

/// The document's latency formula, held as frame counts and read back either
/// way.
///
/// Frame counts rather than milliseconds because that is what a caller
/// upstream of RTP actually has to report — "two frames are sitting in the
/// jitter buffer" — and because this crate reads no clock to turn that into
/// a duration on its own. [`LatencyBudget::capture_latency_ms`] and
/// [`LatencyBudget::playback_latency_ms`] do the one multiplication that
/// needs the session's frame duration to answer in milliseconds at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatencyBudget {
    audio: AudioConfig,
    buffer_depth_frames: u32,
    decode_frames: u32,
    encode_frames: u32,
}

impl LatencyBudget {
    /// A budget for `audio`'s frame duration, every upstream component at
    /// zero until the caller reports one.
    #[must_use]
    pub const fn new(audio: AudioConfig) -> Self {
        Self {
            audio,
            buffer_depth_frames: 0,
            decode_frames: 0,
            encode_frames: 0,
        }
    }

    /// How many frames are sitting in the jitter buffer right now.
    #[must_use]
    pub const fn buffer_depth_frames(&self) -> u32 {
        self.buffer_depth_frames
    }

    /// Report the current jitter buffer depth, in frames.
    pub fn set_buffer_depth_frames(&mut self, frames: u32) {
        self.buffer_depth_frames = frames;
    }

    /// How long decode costs, in whole frames.
    #[must_use]
    pub const fn decode_frames(&self) -> u32 {
        self.decode_frames
    }

    /// Report how long decode costs, in whole frames.
    pub fn set_decode_frames(&mut self, frames: u32) {
        self.decode_frames = frames;
    }

    /// How long encode costs, in whole frames.
    #[must_use]
    pub const fn encode_frames(&self) -> u32 {
        self.encode_frames
    }

    /// Report how long encode costs, in whole frames.
    pub fn set_encode_frames(&mut self, frames: u32) {
        self.encode_frames = frames;
    }

    /// Buffer depth plus decode plus one frame: the last RTP packet of the
    /// caller's speech to the first frame delivered on the socket.
    #[must_use]
    pub const fn capture_latency_frames(&self) -> u32 {
        self.buffer_depth_frames
            .saturating_add(self.decode_frames)
            .saturating_add(1)
    }

    /// Encode plus one frame: a frame written on the socket to it leaving as
    /// RTP.
    #[must_use]
    pub const fn playback_latency_frames(&self) -> u32 {
        self.encode_frames.saturating_add(1)
    }

    /// [`LatencyBudget::capture_latency_frames`], converted at the session's
    /// frame duration.
    #[must_use]
    pub const fn capture_latency_ms(&self) -> u32 {
        self.capture_latency_frames()
            .saturating_mul(self.audio.frame_duration_ms())
    }

    /// [`LatencyBudget::playback_latency_frames`], converted at the
    /// session's frame duration.
    #[must_use]
    pub const fn playback_latency_ms(&self) -> u32 {
        self.playback_latency_frames()
            .saturating_mul(self.audio.frame_duration_ms())
    }
}

#[cfg(test)]
mod tests {
    use super::LatencyBudget;
    use crate::audio::{AudioConfig, SampleRate};

    fn budget() -> LatencyBudget {
        LatencyBudget::new(AudioConfig::new(SampleRate::Hz8000)) // 20 ms frames
    }

    #[test]
    fn a_fresh_budget_is_exactly_one_frame_each_way() {
        let budget = budget();
        assert_eq!(budget.capture_latency_frames(), 1);
        assert_eq!(budget.playback_latency_frames(), 1);
        assert_eq!(budget.capture_latency_ms(), 20);
        assert_eq!(budget.playback_latency_ms(), 20);
    }

    #[test]
    fn capture_latency_sums_buffer_depth_decode_and_one_frame() {
        let mut budget = budget();
        budget.set_buffer_depth_frames(3);
        budget.set_decode_frames(2);
        assert_eq!(budget.buffer_depth_frames(), 3);
        assert_eq!(budget.decode_frames(), 2);
        assert_eq!(budget.capture_latency_frames(), 6);
        assert_eq!(budget.capture_latency_ms(), 120);
    }

    #[test]
    fn playback_latency_sums_encode_and_one_frame_with_no_buffer_term() {
        // the document's playback formula has no buffer-depth term at all:
        // only capture crosses a jitter buffer, so setting one here must not
        // leak into the playback side
        let mut budget = budget();
        budget.set_buffer_depth_frames(9);
        budget.set_encode_frames(4);
        assert_eq!(budget.encode_frames(), 4);
        assert_eq!(budget.playback_latency_frames(), 5);
        assert_eq!(budget.playback_latency_ms(), 100);
    }

    #[test]
    fn a_hundred_millisecond_budget_is_reachable_at_twenty_millisecond_frames() {
        // four frames of encode plus one frame lands exactly on the
        // document's hundred-millisecond barge-in target
        let mut budget = budget();
        budget.set_encode_frames(4);
        assert_eq!(budget.playback_latency_ms(), 100);
    }

    #[test]
    fn upstream_components_saturate_instead_of_wrapping_on_overflow() {
        let mut budget = budget();
        budget.set_buffer_depth_frames(u32::MAX);
        budget.set_decode_frames(u32::MAX);
        assert_eq!(budget.capture_latency_frames(), u32::MAX);
        assert_eq!(budget.capture_latency_ms(), u32::MAX);
    }

    #[test]
    fn the_millisecond_conversion_saturates_rather_than_overflowing_too() {
        let mut budget = budget();
        budget.set_encode_frames(u32::MAX - 1);
        assert_eq!(budget.playback_latency_frames(), u32::MAX);
        assert_eq!(budget.playback_latency_ms(), u32::MAX);
    }
}
