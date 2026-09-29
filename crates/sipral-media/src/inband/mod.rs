// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Signals carried inside the audio itself: keypad digits, the tones a
//! network plays to a caller, and whether a person or a machine answered.
//!
//! RFC 4733 moves a digit out of the audio and into its own payload, and
//! most of the time that is where a digit arrives. Not always: a gateway
//! that never negotiated `telephone-event`, an old private exchange behind
//! it, or an interactive voice system on the far side of a transcoding hop
//! all leave the digit where Q.23 put it, as two tones in the voice band.
//! The same audio carries what the network says about a call it could not
//! complete — busy, congestion, a special information tone — and, once an
//! outbound call is answered, the only evidence of who or what picked up.
//!
//! - [`dtmf`] finds keypad digits in decoded audio, to the acceptance limits
//!   of ITU-T Q.24, and reports each one as a start and an end on the
//!   stream's own sample clock, so that a caller receiving the same key as an
//!   RFC 4733 event as well can tell the two apart from one press.
//! - [`generate`] writes digits and call-progress tones into a buffer.
//! - [`progress`] holds the call-progress tones of three networks as data —
//!   frequencies and cadences from ITU-T E.180 Supplement 2 — and detects
//!   them, and the three-tone special information sequence, on a call's
//!   inbound audio.
//! - [`amd`] decides, from the pattern of speech and silence after answer,
//!   whether a person or an answering machine is on the line, and
//!   [`beep`] finds the tone a machine plays before it starts recording.
//!
//! Everything here works on 16-bit linear PCM at 8 or 16 kHz, in plain
//! floating-point arithmetic with no platform-specific instructions. Each
//! detector allocates once, when it is built, and never again; each takes
//! samples in slices of any length and reports what it found through a
//! callback, stamped with the index of the sample it happened at, counted
//! from the first sample the detector was given.
//!
//! # Levels
//!
//! Levels are in dBm0, the unit every telephony specification states them
//! in. The mapping to linear samples is G.711's: a sine whose peak reaches
//! full scale is +3.14 dBm0, the A-law overload point, so a 0 dBm0 sine peaks
//! at about 22 827 on the 16-bit scale.

pub mod amd;
mod analysis;
pub mod beep;
pub mod dtmf;
pub mod generate;
pub mod progress;
#[cfg(test)]
mod signals;
#[cfg(test)]
mod tests;

/// The sample rates the detectors and generators here accept.
///
/// Narrowband and wideband telephony, the two rates G.711 and G.722 decode
/// to. A stream at another rate is resampled first, with
/// [`resample`](crate::resample).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SampleRate {
    /// 8 kHz, what G.711 and G.729 decode to.
    Hz8000,
    /// 16 kHz, what G.722 decodes to.
    Hz16000,
}

impl SampleRate {
    /// Samples per second.
    #[must_use]
    pub const fn hz(self) -> u32 {
        match self {
            Self::Hz8000 => 8_000,
            Self::Hz16000 => 16_000,
        }
    }

    /// The rate for `hz`, if it is one of the two supported.
    #[must_use]
    pub const fn from_hz(hz: u32) -> Option<Self> {
        match hz {
            8_000 => Some(Self::Hz8000),
            16_000 => Some(Self::Hz16000),
            _ => None,
        }
    }

    /// Samples in `ms` milliseconds at this rate.
    #[must_use]
    pub const fn samples(self, ms: u32) -> usize {
        // at most 16 * u32::MAX, which fits a usize on every target this
        // crate builds for; the saturating form keeps the arithmetic total
        let per_ms = self.hz() / 1_000;
        (per_ms as usize).saturating_mul(ms as usize)
    }

    pub(crate) fn as_f64(self) -> f64 {
        f64::from(self.hz())
    }
}

/// The level of a sine, in dBm0, whose peak just reaches full scale on the
/// 16-bit linear scale: the overload point of G.711's A-law.
// G.711's figure, not an approximation of π that happens to share its digits
#[allow(clippy::approx_constant)]
pub const FULL_SCALE_DBM0: f64 = 3.14;

/// Peak amplitude, on the 16-bit scale, of a sine at `dbm0`.
#[must_use]
pub fn dbm0_to_peak(dbm0: f64) -> f64 {
    32_768.0 * 10f64.powf((dbm0 - FULL_SCALE_DBM0) / 20.0)
}

/// Mean-square power, in 16-bit sample units squared, of a sine at `dbm0`.
#[must_use]
pub fn dbm0_to_power(dbm0: f64) -> f64 {
    let peak = dbm0_to_peak(dbm0);
    peak * peak / 2.0
}

/// The level, in dBm0, of a sine with mean-square power `power`. Zero power
/// is minus infinity, which compares below every threshold.
#[must_use]
pub fn power_to_dbm0(power: f64) -> f64 {
    10.0 * (power / dbm0_to_power(0.0)).log10()
}

/// A count as a float. Every count converted here is a buffer length or a
/// number of samples, far below the 2^53 where the conversion would lose a
/// unit.
#[allow(clippy::cast_precision_loss)]
pub(crate) const fn count_f64(count: usize) -> f64 {
    count as f64
}

/// A sample position as a float, for the same reason as [`count_f64`]: a
/// stream would have to run for eighteen thousand years at 16 kHz to reach
/// 2^53 samples.
#[allow(clippy::cast_precision_loss)]
pub(crate) const fn position_f64(position: u64) -> f64 {
    position as f64
}

/// A non-negative float rounded to the nearest sample position. Negative
/// values and NaN become zero; values past `u64::MAX` saturate, which is
/// what the float-to-integer conversion does.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn round_position(value: f64) -> u64 {
    if value.is_nan() || value <= 0.0 {
        0
    } else {
        value.round() as u64
    }
}

/// A float clamped to the 16-bit sample range and rounded.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn to_sample(value: f64) -> i16 {
    if value.is_nan() {
        0
    } else {
        value.round().clamp(-32_768.0, 32_767.0) as i16
    }
}
