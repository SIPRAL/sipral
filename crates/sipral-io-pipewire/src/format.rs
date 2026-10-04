// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The shape of what crosses the boundary: mono sixteen-bit samples, a fixed
//! number of them per frame, at a stated rate.
//!
//! Anything else — resampling to the codec's rate, mixing, drift correction —
//! is `sipral-media`'s. This crate only says how big a frame is and how often
//! one goes by. PipeWire's own converter is what turns this into whatever the
//! graph is actually running, which `stream.rs` explains.

use core::fmt;

/// The lowest rate a telephony device runs at.
const MIN_RATE_HZ: u32 = 8_000;

/// Above this, nothing that carries a voice call exists.
const MAX_RATE_HZ: u32 = 384_000;

/// A frame longer than this is not a frame, it is a recording.
const MAX_FRAME_MILLIS: u32 = 1_000;

/// How many samples go past, how fast, in one direction.
///
/// Mono and sixteen-bit are not parameters. A softphone sends one channel, and
/// the codecs downstream take signed sixteen-bit; a graph running at another
/// format or channel count is converted by PipeWire's own adapter before this
/// crate sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamFormat {
    sample_rate_hz: u32,
    frame_samples: u32,
}

impl StreamFormat {
    /// Eight kilohertz in twenty-millisecond frames: what a call is until
    /// something better is negotiated.
    #[must_use]
    pub const fn narrowband() -> Self {
        Self {
            sample_rate_hz: 8_000,
            frame_samples: 160,
        }
    }

    /// A rate and a frame length in samples.
    ///
    /// `None` for a rate no audio device runs at, for an empty frame, or for a
    /// frame longer than a second.
    #[must_use]
    pub const fn new(sample_rate_hz: u32, frame_samples: u32) -> Option<Self> {
        if sample_rate_hz < MIN_RATE_HZ || sample_rate_hz > MAX_RATE_HZ {
            return None;
        }
        if frame_samples == 0 || frame_samples > sample_rate_hz {
            return None;
        }
        Some(Self {
            sample_rate_hz,
            frame_samples,
        })
    }

    /// The same, said in milliseconds.
    ///
    /// `None` when the two do not divide — 8000 Hz has no 3-millisecond frame,
    /// and rounding one silently is how a stack ends up a sample short every
    /// frame and a click a second.
    #[must_use]
    pub const fn with_frame_millis(sample_rate_hz: u32, millis: u32) -> Option<Self> {
        if millis == 0 || millis > MAX_FRAME_MILLIS {
            return None;
        }
        let Some(samples) = sample_rate_hz.checked_mul(millis) else {
            return None;
        };
        if samples % 1_000 != 0 {
            return None;
        }
        Self::new(sample_rate_hz, samples / 1_000)
    }

    /// Samples per second.
    #[must_use]
    pub const fn sample_rate_hz(self) -> u32 {
        self.sample_rate_hz
    }

    /// Samples in one frame.
    #[must_use]
    pub const fn frame_samples(self) -> usize {
        self.frame_samples as usize
    }

    /// Octets in one frame.
    #[must_use]
    pub const fn frame_bytes(self) -> usize {
        self.frame_samples() * 2
    }
}

impl Default for StreamFormat {
    fn default() -> Self {
        Self::narrowband()
    }
}

impl fmt::Display for StreamFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} Hz mono, {} samples per frame",
            self.sample_rate_hz, self.frame_samples
        )
    }
}

#[cfg(test)]
mod tests {
    use super::StreamFormat;

    #[test]
    fn narrowband_is_twenty_milliseconds_of_eight_kilohertz() {
        let format = StreamFormat::narrowband();
        assert_eq!(format, StreamFormat::default());
        assert_eq!(format.sample_rate_hz(), 8_000);
        assert_eq!(format.frame_samples(), 160);
        assert_eq!(format.frame_bytes(), 320);
        assert_eq!(
            format.to_string(),
            "8000 Hz mono, 160 samples per frame".to_string()
        );
    }

    #[test]
    fn milliseconds_that_divide_are_accepted() {
        assert_eq!(
            StreamFormat::with_frame_millis(8_000, 20),
            StreamFormat::new(8_000, 160)
        );
        assert_eq!(
            StreamFormat::with_frame_millis(48_000, 10).map(StreamFormat::frame_samples),
            Some(480)
        );
        assert_eq!(
            StreamFormat::with_frame_millis(44_100, 20).map(StreamFormat::frame_samples),
            Some(882)
        );
    }

    #[test]
    fn milliseconds_that_do_not_divide_are_refused() {
        assert_eq!(StreamFormat::with_frame_millis(44_100, 3), None);
        assert_eq!(StreamFormat::with_frame_millis(8_000, 0), None);
        assert_eq!(StreamFormat::with_frame_millis(8_000, 1_001), None);
        assert_eq!(StreamFormat::with_frame_millis(u32::MAX, 20), None);
    }

    #[test]
    fn rates_no_device_runs_at_are_refused() {
        assert_eq!(StreamFormat::new(7_999, 160), None);
        assert_eq!(StreamFormat::new(384_001, 160), None);
        assert!(StreamFormat::new(8_000, 160).is_some());
        assert!(StreamFormat::new(384_000, 160).is_some());
    }

    #[test]
    fn a_frame_is_neither_empty_nor_longer_than_a_second() {
        assert_eq!(StreamFormat::new(8_000, 0), None);
        assert_eq!(StreamFormat::new(8_000, 8_001), None);
        assert!(StreamFormat::new(8_000, 8_000).is_some());
    }
}
