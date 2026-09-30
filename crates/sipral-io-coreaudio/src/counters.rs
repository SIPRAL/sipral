// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the device did while nobody was watching.
//!
//! The realtime callback cannot log, cannot return an error to anyone and
//! cannot wait, so everything that goes wrong there is counted and read later.
//! A call that sounds wrong is nearly always explained by two of these numbers.

use core::fmt;

/// A reading of one stream's counters, taken at a moment.
///
/// Counted in samples rather than frames, because the device delivers in
/// slices of its own choosing and a frame boundary means nothing to it. All of
/// them only ever grow, so two readings subtract into a rate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Samples the microphone side handed over.
    pub captured: u64,
    /// Samples the microphone side threw away because the ring was full, which
    /// means the reader is not keeping up or has stopped reading.
    pub capture_dropped: u64,
    /// Samples the speaker side took.
    pub played: u64,
    /// Samples the speaker side had to invent, because the ring was empty when
    /// the device asked. Silence went out instead.
    pub playback_starved: u64,
    /// Times `AudioUnitRender` refused inside the capture callback. The status
    /// is not kept: it cannot be reported from there, and the count is what
    /// says whether it happened once or is happening constantly.
    pub render_failures: u64,
    /// Times the capture callback was told of more frames than its buffer
    /// holds, and let that slice go rather than render into a buffer too
    /// small for it. Above zero means a device ran a longer slice than the
    /// unit was allowed; the microphone missed those samples.
    pub capture_oversized: u64,
    /// Times a panic was caught at the callback boundary and turned into
    /// silence. Any number above zero is a bug in this crate.
    pub panics: u64,
}

impl fmt::Display for Counters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "captured {} (-{}), played {} (-{}), render failures {}, oversized slices {}, panics {}",
            self.captured,
            self.capture_dropped,
            self.played,
            self.playback_starved,
            self.render_failures,
            self.capture_oversized,
            self.panics
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Counters;

    #[test]
    fn a_clean_run_reads_as_zeroes() {
        let counters = Counters::default();
        assert_eq!(
            counters.to_string(),
            "captured 0 (-0), played 0 (-0), render failures 0, oversized slices 0, panics 0"
        );
    }

    #[test]
    fn two_readings_subtract() {
        let first = Counters {
            captured: 50,
            ..Counters::default()
        };
        let second = Counters {
            captured: 150,
            capture_dropped: 3,
            ..Counters::default()
        };
        assert_eq!(second.captured - first.captured, 100);
        assert_eq!(second.capture_dropped, 3);
    }
}
