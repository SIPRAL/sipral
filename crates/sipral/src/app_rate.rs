// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The rate an application hands a call its frames at and takes them back
//! at, when that is not the codec's.
//!
//! A speech service wants its own rate whatever the far end negotiated —
//! 16 kHz for one, 24 kHz for another — and a call settles on 8 kHz for
//! G.711 or 48 kHz for Opus. Without this every application carries a
//! resampler of its own, in whatever language it is written in. With it the
//! call converts each way with the same filter the local conference and the
//! recorder use, and the codec, the processor, the recording and the in-band
//! detectors go on working at the codec's rate as before: only what crosses
//! [`MediaSession::playback_at_application_rate`] and
//! [`MediaSession::capture_at_application_rate`] moves.
//!
//! [`MediaSession::playback_at_application_rate`]: crate::MediaSession::playback_at_application_rate
//! [`MediaSession::capture_at_application_rate`]: crate::MediaSession::capture_at_application_rate

use sipral_media::nway::Converter;

/// The rates an application may ask for, in hertz: the narrowband and
/// wideband telephone rates, the 24 kHz speech services settle on, and the
/// rate Opus and every sound card run at.
pub const APPLICATION_RATES: [u32; 4] = [8_000, 16_000, 24_000, 48_000];

/// One call's application rate, and the two filters that serve it.
#[derive(Debug)]
pub(crate) struct ApplicationRate {
    hertz: u32,
    /// Built for the codec rate and frame they name, and built again when a
    /// re-negotiation moves either.
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
    /// One frame at the codec's rate, which each direction borrows in turn.
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

    /// The filters for a call now at `codec_rate`, `codec_frame` samples a
    /// frame, built on first use and again whenever either has moved, or
    /// `None` when the codec already runs at the application's rate.
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
            // every pair of the four rates and the codecs' own is within
            // what the resampler builds, so a refusal here is a codec rate
            // nothing in this build negotiates; the frames then pass as they
            // are rather than the call losing its audio
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
