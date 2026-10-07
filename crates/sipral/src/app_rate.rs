// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The rate at which an application exchanges frames with a call, when it differs from the codec's.
//!
//! Speech services want their own rate (16 or 24 kHz) whatever was negotiated (8 kHz G.711, 48 kHz
//! Opus). This converts with the same filter the local conference and recorder use, so applications
//! need no resampler. Codec, processor, recording and in-band detectors stay at the codec rate;
//! only [`MediaSession::playback_at_application_rate`] and
//! [`MediaSession::capture_at_application_rate`] convert.
//!
//! [`MediaSession::playback_at_application_rate`]: crate::MediaSession::playback_at_application_rate
//! [`MediaSession::capture_at_application_rate`]: crate::MediaSession::capture_at_application_rate

use sipral_media::nway::Converter;

/// Rates an application may ask for, in hertz: narrowband and wideband telephony, the 24 kHz of
/// speech services, and the 48 kHz of Opus and sound cards.
pub const APPLICATION_RATES: [u32; 4] = [8_000, 16_000, 24_000, 48_000];

/// One call's application rate, and the two filters that serve it.
#[derive(Debug)]
pub(crate) struct ApplicationRate {
    hertz: u32,
    /// Built for the codec rate and frame they name, rebuilt when a renegotiation changes either.
    built: Option<Bridge>,
}

/// Both directions of one call at one pair of rates.
#[derive(Debug)]
pub(crate) struct Bridge {
    codec_rate: u32,
    codec_frame: usize,
    application_frame: usize,
    /// What the far end sent, from the codec's rate to the application's.
    pub(crate) heard: Converter,
    /// What the application sends, from its rate to the codec's.
    pub(crate) said: Converter,
    /// One reusable frame at the codec rate, shared by both directions in turn.
    pub(crate) codec: Vec<i16>,
}

impl ApplicationRate {
    /// The rate asked for, already checked against [`APPLICATION_RATES`].
    pub(crate) const fn new(hertz: u32) -> Self {
        Self { hertz, built: None }
    }

    pub(crate) const fn hertz(&self) -> u32 {
        self.hertz
    }

    /// The filters for a call at `codec_rate` with `codec_frame` samples per frame, built on first
    /// use and rebuilt when either changes; `None` when no conversion is needed.
    pub(crate) fn bridge(&mut self, codec_rate: u32, codec_frame: usize) -> Option<&mut Bridge> {
        if codec_rate == self.hertz {
            self.built = None;
            return None;
        }
        let current = self.built.as_ref().is_some_and(|built| {
            built.codec_rate == codec_rate && built.codec_frame == codec_frame
        });
        if !current {
            let application_frame = frame_at(codec_frame, codec_rate, self.hertz);
            // all supported rate pairs are buildable, so a refusal means a codec rate nothing
            // negotiates; then frames pass unconverted rather than losing the audio
            let heard = Converter::new(codec_rate, self.hertz, codec_frame).ok()?;
            let said = Converter::new(self.hertz, codec_rate, application_frame).ok()?;
            self.built = Some(Bridge {
                codec_rate,
                codec_frame,
                application_frame,
                heard,
                said,
                codec: vec![0; codec_frame],
            });
        }
        self.built.as_mut()
    }
}

impl Bridge {
    /// Samples in one frame at the application's rate.
    pub(crate) const fn application_frame(&self) -> usize {
        self.application_frame
    }
}

/// A frame of `samples` at `from` hertz, counted at `to`.
pub(crate) fn frame_at(samples: usize, from: u32, to: u32) -> usize {
    if from == 0 {
        return samples;
    }
    let scaled = u64::try_from(samples)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::from(to))
        / u64::from(from);
    usize::try_from(scaled).unwrap_or(usize::MAX)
}
