// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The shape of what crosses the boundary, and the shape of what the endpoint
//! runs — which on Windows are almost never the same thing.
//!
//! What crosses the boundary is mono sixteen-bit samples, a fixed number of
//! them per frame, at a stated rate: [`StreamFormat`]. What the endpoint runs
//! is whatever the audio engine mixes at, which is float and multi-channel on
//! most machines: [`DeviceFormat`].
//!
//! Between the two this crate does exactly one thing — it folds channels and
//! converts sample type. It does not resample. Resampling belongs to
//! `sipral-media`, which owns the drift correction that goes with it
//! (`docs/05-media.md`), and a resampler hidden down here would be a second
//! one nobody knew about. So when the endpoint runs at 48 kHz and the caller
//! asked for 8 kHz, the caller is handed 48 kHz and told so, rather than
//! handed something that has quietly been through a filter.

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
/// the codecs downstream take signed sixteen-bit; a device that offers neither
/// is folded and converted before this crate hands anything over.
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

    /// The same frame duration, at a rate the caller did not choose.
    ///
    /// This is what an open returns when the endpoint would not run at the
    /// rate that was asked for. The frame length is rounded to the nearest
    /// whole sample, once, at open time — which is a different thing from the
    /// rounding [`StreamFormat::with_frame_millis`] refuses, where the error
    /// would recur on every frame for the life of the call.
    ///
    /// `None` for a rate outside what a device runs at.
    #[must_use]
    pub fn at_rate(self, sample_rate_hz: u32) -> Option<Self> {
        if sample_rate_hz == self.sample_rate_hz {
            return Some(self);
        }
        let scaled = u64::from(self.frame_samples) * u64::from(sample_rate_hz)
            + u64::from(self.sample_rate_hz) / 2;
        let frame = u32::try_from(scaled / u64::from(self.sample_rate_hz)).ok()?;
        Self::new(sample_rate_hz, frame.max(1))
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

/// What one sample of one channel looks like on the wire between the engine
/// and the endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SampleFormat {
    /// Signed sixteen-bit. What this crate deals in, and what a device
    /// occasionally runs at.
    I16,
    /// A signed thirty-two-bit container holding `valid_bits` bits,
    /// left-justified. Twenty-four in thirty-two is the usual spelling.
    I32 {
        /// Bits that mean anything. The rest are at the bottom and are zero.
        valid_bits: u16,
    },
    /// Thirty-two-bit float, nominally between minus one and one. This is what
    /// the Windows audio engine mixes in, and therefore what shared mode
    /// almost always offers.
    F32,
}

impl SampleFormat {
    /// Octets one sample of one channel takes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::I16 => 2,
            Self::I32 { .. } | Self::F32 => 4,
        }
    }
}

impl fmt::Display for SampleFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::I16 => f.write_str("16-bit integer"),
            Self::I32 { valid_bits } => write!(f, "{valid_bits}-bit integer in 32"),
            Self::F32 => f.write_str("32-bit float"),
        }
    }
}

/// What the endpoint settled on, reported rather than hidden.
///
/// The rate here is the one the caller will actually be handed samples at. If
/// it is not the rate that was asked for, something above this crate has to
/// resample, and this is where it finds out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceFormat {
    /// Samples per second, per channel.
    pub sample_rate_hz: u32,
    /// Channels the endpoint carries. Folded to one on the way in, spread
    /// across all of them on the way out.
    pub channels: u16,
    /// What one sample looks like.
    pub sample: SampleFormat,
}

impl DeviceFormat {
    /// Octets in one frame of all channels — `nBlockAlign`, as the endpoint
    /// counts it.
    #[must_use]
    pub const fn block_align(self) -> usize {
        self.channels as usize * self.sample.bytes()
    }

    /// Whether an endpoint at this format hands over exactly what was asked
    /// for, with nothing above this crate left to do.
    #[must_use]
    pub const fn is(self, wanted: StreamFormat) -> bool {
        self.sample_rate_hz == wanted.sample_rate_hz()
            && self.channels == 1
            && matches!(self.sample, SampleFormat::I16)
    }
}

impl fmt::Display for DeviceFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} Hz, {} channel{}, {}",
            self.sample_rate_hz,
            self.channels,
            if self.channels == 1 { "" } else { "s" },
            self.sample
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceFormat, SampleFormat, StreamFormat};

    #[test]
    fn narrowband_is_twenty_milliseconds_of_eight_kilohertz() {
        let format = StreamFormat::narrowband();
        assert_eq!(format, StreamFormat::default());
        assert_eq!(format.sample_rate_hz(), 8_000);
        assert_eq!(format.frame_samples(), 160);
        assert_eq!(format.frame_bytes(), 320);
        assert_eq!(format.to_string(), "8000 Hz mono, 160 samples per frame");
    }

    #[test]
    fn milliseconds_that_divide_are_accepted_and_the_rest_refused() {
        assert_eq!(
            StreamFormat::with_frame_millis(8_000, 20),
            StreamFormat::new(8_000, 160)
        );
        assert_eq!(
            StreamFormat::with_frame_millis(48_000, 10).map(StreamFormat::frame_samples),
            Some(480)
        );
        assert_eq!(StreamFormat::with_frame_millis(44_100, 3), None);
        assert_eq!(StreamFormat::with_frame_millis(8_000, 0), None);
        assert_eq!(StreamFormat::with_frame_millis(8_000, 1_001), None);
        assert_eq!(StreamFormat::with_frame_millis(u32::MAX, 20), None);
    }

    #[test]
    fn rates_and_frames_outside_what_a_device_does_are_refused() {
        assert_eq!(StreamFormat::new(7_999, 160), None);
        assert_eq!(StreamFormat::new(384_001, 160), None);
        assert_eq!(StreamFormat::new(8_000, 0), None);
        assert_eq!(StreamFormat::new(8_000, 8_001), None);
        assert!(StreamFormat::new(8_000, 8_000).is_some());
        assert!(StreamFormat::new(384_000, 160).is_some());
    }

    #[test]
    fn a_frame_keeps_its_duration_when_the_rate_is_not_ours() {
        let asked = StreamFormat::with_frame_millis(8_000, 20).unwrap();
        // the case this exists for: asked for narrowband, given the engine's
        // rate, and twenty milliseconds is still twenty milliseconds
        assert_eq!(
            asked.at_rate(48_000),
            StreamFormat::with_frame_millis(48_000, 20)
        );
        assert_eq!(
            asked.at_rate(44_100),
            StreamFormat::with_frame_millis(44_100, 20)
        );
        assert_eq!(asked.at_rate(8_000), Some(asked));
        // 160 samples at 8 kHz is 20 ms; at 11025 Hz that is 220.5, rounded
        assert_eq!(
            asked.at_rate(11_025).map(StreamFormat::frame_samples),
            Some(221)
        );
        assert_eq!(asked.at_rate(0), None);
        assert_eq!(asked.at_rate(u32::MAX), None);
    }

    #[test]
    fn a_sample_is_as_wide_as_its_container() {
        assert_eq!(SampleFormat::I16.bytes(), 2);
        assert_eq!(SampleFormat::I32 { valid_bits: 24 }.bytes(), 4);
        assert_eq!(SampleFormat::F32.bytes(), 4);
        assert_eq!(SampleFormat::I16.to_string(), "16-bit integer");
        assert_eq!(
            SampleFormat::I32 { valid_bits: 24 }.to_string(),
            "24-bit integer in 32"
        );
        assert_eq!(SampleFormat::F32.to_string(), "32-bit float");
    }

    #[test]
    fn an_endpoint_that_matches_the_request_says_so() {
        let exact = DeviceFormat {
            sample_rate_hz: 8_000,
            channels: 1,
            sample: SampleFormat::I16,
        };
        assert!(exact.is(StreamFormat::narrowband()));
        assert_eq!(exact.to_string(), "8000 Hz, 1 channel, 16-bit integer");
        assert_eq!(exact.block_align(), 2);

        // one channel too many, one rate too high, one sample too wide: each
        // on its own means something above this crate has work to do
        assert!(
            !DeviceFormat {
                channels: 2,
                ..exact
            }
            .is(StreamFormat::narrowband())
        );
        assert!(
            !DeviceFormat {
                sample_rate_hz: 16_000,
                ..exact
            }
            .is(StreamFormat::narrowband())
        );
        assert!(
            !DeviceFormat {
                sample: SampleFormat::F32,
                ..exact
            }
            .is(StreamFormat::narrowband())
        );
    }

    #[test]
    fn a_multi_channel_endpoint_counts_its_octets_the_way_windows_does() {
        let cable = DeviceFormat {
            sample_rate_hz: 48_000,
            channels: 16,
            sample: SampleFormat::F32,
        };
        assert_eq!(cable.block_align(), 64);
        assert_eq!(cable.to_string(), "48000 Hz, 16 channels, 32-bit float");
    }
}
