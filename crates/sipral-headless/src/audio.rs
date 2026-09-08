// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The PCM carried in an audio frame (`docs/07-headless.md`): signed 16-bit
//! little-endian, mono, at one of four sample rates, in frames of a fixed
//! duration agreed once when the session opens and never varied afterward.
//!
//! Raw PCM rather than an encoded format is the document's whole point — the
//! codec work happens once, at the RTP edge — so what lives here is only the
//! arithmetic of frame sizing and the one check that matters: a frame is
//! exactly one frame, or it is refused.

use core::fmt;

/// The frame duration a session opens with unless it asks for another.
pub const DEFAULT_FRAME_DURATION_MS: u32 = 20;

/// A sample rate the document allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SampleRate {
    /// 8 kHz.
    Hz8000,
    /// 16 kHz.
    Hz16000,
    /// 24 kHz.
    Hz24000,
    /// 48 kHz.
    Hz48000,
}

impl SampleRate {
    /// The rate in hertz.
    #[must_use]
    pub const fn hz(self) -> u32 {
        match self {
            Self::Hz8000 => 8_000,
            Self::Hz16000 => 16_000,
            Self::Hz24000 => 24_000,
            Self::Hz48000 => 48_000,
        }
    }
}

impl TryFrom<u32> for SampleRate {
    type Error = AudioError;

    fn try_from(hz: u32) -> Result<Self, Self::Error> {
        match hz {
            8_000 => Ok(Self::Hz8000),
            16_000 => Ok(Self::Hz16000),
            24_000 => Ok(Self::Hz24000),
            48_000 => Ok(Self::Hz48000),
            other => Err(AudioError::UnsupportedSampleRate(other)),
        }
    }
}

/// What one session agreed: a rate, and how much audio one frame carries.
///
/// Fixed for the life of the session and the same in both directions, per the
/// document — there is no per-frame negotiation, so this is built once and
/// handed to whatever reads or writes audio frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioConfig {
    sample_rate: SampleRate,
    frame_duration_ms: u32,
}

impl AudioConfig {
    /// `sample_rate` at the document's default of twenty milliseconds a
    /// frame.
    #[must_use]
    pub const fn new(sample_rate: SampleRate) -> Self {
        Self {
            sample_rate,
            frame_duration_ms: DEFAULT_FRAME_DURATION_MS,
        }
    }

    /// `sample_rate` at a frame duration other than the default.
    ///
    /// # Errors
    /// [`AudioError::FrameTooLarge`] if a frame of that duration at that rate
    /// would not fit the sixteen-bit payload length every frame is written
    /// in.
    pub fn with_frame_duration_ms(
        sample_rate: SampleRate,
        frame_duration_ms: u32,
    ) -> Result<Self, AudioError> {
        let config = Self {
            sample_rate,
            frame_duration_ms,
        };
        config.frame_bytes()?;
        Ok(config)
    }

    /// The session's sample rate.
    #[must_use]
    pub const fn sample_rate(self) -> SampleRate {
        self.sample_rate
    }

    /// The session's frame duration, in milliseconds.
    #[must_use]
    pub const fn frame_duration_ms(self) -> u32 {
        self.frame_duration_ms
    }

    /// Samples in one frame.
    ///
    /// # Errors
    /// [`AudioError::FrameTooLarge`] on overflow — only reachable with a
    /// frame duration no real session would ask for.
    pub fn frame_samples(self) -> Result<u32, AudioError> {
        (self.sample_rate.hz() / 1000)
            .checked_mul(self.frame_duration_ms)
            .ok_or(AudioError::FrameTooLarge)
    }

    /// Bytes one frame of PCM takes: two per sample, mono.
    ///
    /// # Errors
    /// [`AudioError::FrameTooLarge`] if that many bytes will not fit the
    /// frame format's sixteen-bit length field.
    pub fn frame_bytes(self) -> Result<u16, AudioError> {
        let samples = self.frame_samples()?;
        let bytes = samples.checked_mul(2).ok_or(AudioError::FrameTooLarge)?;
        u16::try_from(bytes).map_err(|_| AudioError::FrameTooLarge)
    }

    /// Check that `payload` is exactly one frame at this rate and duration.
    ///
    /// A half frame is a bug on the agent's side. Padding it out would hide
    /// that bug behind a click or a shortened word instead of surfacing it.
    ///
    /// # Errors
    /// [`AudioError::WrongFrameSize`] when the lengths disagree.
    pub fn validate_frame(self, payload: &[u8]) -> Result<(), AudioError> {
        let expected = usize::from(self.frame_bytes()?);
        if payload.len() == expected {
            Ok(())
        } else {
            Err(AudioError::WrongFrameSize {
                expected,
                got: payload.len(),
            })
        }
    }
}

/// Read a PCM payload as signed 16-bit little-endian samples.
///
/// A trailing odd byte — which a payload that passed
/// [`AudioConfig::validate_frame`] never has — is dropped rather than treated
/// as half a sample.
pub fn read_samples(payload: &[u8]) -> impl Iterator<Item = i16> + '_ {
    payload
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes(<[u8; 2]>::try_from(pair).unwrap_or_default()))
}

/// Write samples as a signed 16-bit little-endian PCM payload.
pub fn write_samples(samples: &[i16], out: &mut Vec<u8>) {
    out.reserve(samples.len() * 2);
    for sample in samples {
        out.extend_from_slice(&sample.to_le_bytes());
    }
}

/// Why an audio frame was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudioError {
    /// A rate that is not one of the four the document allows.
    UnsupportedSampleRate(u32),
    /// A frame duration whose byte length overflows or does not fit sixteen
    /// bits.
    FrameTooLarge,
    /// A payload that is not exactly one frame.
    WrongFrameSize {
        /// What one frame at the session's rate and duration takes.
        expected: usize,
        /// What arrived.
        got: usize,
    },
}

impl fmt::Display for AudioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnsupportedSampleRate(hz) => {
                write!(f, "{hz} Hz is not 8000, 16000, 24000 or 48000")
            }
            Self::FrameTooLarge => f.write_str("frame duration does not fit the wire format"),
            Self::WrongFrameSize { expected, got } => {
                write!(f, "frame of {got} bytes, session expects {expected}")
            }
        }
    }
}

impl core::error::Error for AudioError {}

#[cfg(test)]
mod tests {
    use super::{AudioConfig, AudioError, SampleRate, read_samples, write_samples};

    #[test]
    fn the_default_frame_at_every_allowed_rate_is_twenty_milliseconds_of_samples() {
        let cases = [
            (SampleRate::Hz8000, 160, 320),
            (SampleRate::Hz16000, 320, 640),
            (SampleRate::Hz24000, 480, 960),
            (SampleRate::Hz48000, 960, 1920),
        ];
        for (rate, samples, bytes) in cases {
            let config = AudioConfig::new(rate);
            assert_eq!(config.frame_samples(), Ok(samples));
            assert_eq!(config.frame_bytes(), Ok(bytes));
        }
    }

    #[test]
    fn a_sample_rate_outside_the_four_is_refused() {
        assert_eq!(
            SampleRate::try_from(44_100),
            Err(AudioError::UnsupportedSampleRate(44_100))
        );
        assert_eq!(SampleRate::try_from(8_000), Ok(SampleRate::Hz8000));
    }

    #[test]
    fn a_frame_of_the_right_size_is_accepted() {
        let config = AudioConfig::new(SampleRate::Hz8000);
        let payload = vec![0_u8; 320];
        assert_eq!(config.validate_frame(&payload), Ok(()));
    }

    #[test]
    fn a_half_frame_is_refused_rather_than_padded() {
        let config = AudioConfig::new(SampleRate::Hz8000);
        let payload = vec![0_u8; 160];
        assert_eq!(
            config.validate_frame(&payload),
            Err(AudioError::WrongFrameSize {
                expected: 320,
                got: 160,
            })
        );
    }

    #[test]
    fn an_empty_frame_is_refused_when_the_session_expects_samples() {
        let config = AudioConfig::new(SampleRate::Hz48000);
        assert_eq!(
            config.validate_frame(&[]),
            Err(AudioError::WrongFrameSize {
                expected: 1920,
                got: 0,
            })
        );
    }

    #[test]
    fn a_custom_frame_duration_scales_the_frame_size() {
        let config = AudioConfig::with_frame_duration_ms(SampleRate::Hz16000, 10)
            .expect("10ms fits sixteen bits");
        assert_eq!(config.frame_duration_ms(), 10);
        assert_eq!(config.frame_bytes(), Ok(320));
    }

    #[test]
    fn a_frame_duration_that_cannot_fit_sixteen_bits_is_refused_up_front() {
        // 48000 Hz * 1000 ms = 48,000,000 samples, far past what a u16 byte
        // count can hold, so the session cannot be opened this way at all
        assert_eq!(
            AudioConfig::with_frame_duration_ms(SampleRate::Hz48000, 1_000),
            Err(AudioError::FrameTooLarge)
        );
    }

    #[test]
    fn samples_round_trip_through_the_wire_bytes() {
        let samples: Vec<i16> = vec![0, 1, -1, i16::MIN, i16::MAX, -12345];
        let mut wire = Vec::new();
        write_samples(&samples, &mut wire);
        assert_eq!(wire.len(), samples.len() * 2);
        assert_eq!(read_samples(&wire).collect::<Vec<_>>(), samples);
    }

    #[test]
    fn a_trailing_odd_byte_is_dropped_rather_than_read_as_a_sample() {
        let wire = [0_u8, 0, 1, 0, 0xFF];
        assert_eq!(read_samples(&wire).collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test]
    fn little_endian_is_what_the_document_specifies_not_native_order() {
        // 0x0102 as bytes [0x02, 0x01], not [0x01, 0x02]
        let mut wire = Vec::new();
        write_samples(&[0x0102], &mut wire);
        assert_eq!(wire, [0x02, 0x01]);
    }
}
