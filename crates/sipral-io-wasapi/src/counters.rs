// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the device did while nobody was watching.
//!
//! The audio thread cannot log, cannot return an error to anyone and cannot
//! wait, so everything that goes wrong there is counted and read later. A call
//! that sounds wrong is nearly always explained by two of these numbers.

use core::fmt;

/// A reading of one stream's counters, taken at a moment.
///
/// Counted in mono samples at the endpoint's rate, rather than in frames,
/// because the engine delivers in packets of its own choosing and a frame
/// boundary means nothing to it. All of them only ever grow, so two readings
/// subtract into a rate.
///
/// A stream runs in one direction, so half of these stay at zero for its whole
/// life. That is cheaper than two types that are read the same way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Samples the capture side handed over.
    pub captured: u64,
    /// Samples the capture side threw away because the ring was full, which
    /// means the reader is not keeping up or has stopped reading.
    pub capture_dropped: u64,
    /// Samples the render side took.
    pub played: u64,
    /// Samples the render side had to invent, because the ring was empty when
    /// the engine asked. Silence went out instead.
    pub playback_starved: u64,
    /// Times the engine said the capture stream had a gap in it —
    /// `AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY`. Somebody else's thread was
    /// late, not ours, and the far end will hear it either way.
    pub discontinuities: u64,
    /// Times `GetBuffer` or `ReleaseBuffer` refused. The code is not kept: it
    /// cannot be reported from the audio thread, and the count is what says
    /// whether it happened once or is happening constantly.
    pub buffer_failures: u64,
    /// Times the buffer-ready event did not arrive before the deadline. One is
    /// a hiccup; a number that keeps climbing is an endpoint that has stopped
    /// running while still claiming to exist.
    pub stalls: u64,
    /// Times a panic was caught at the audio thread's boundary and turned into
    /// silence. Any number above zero is a bug in this crate.
    pub panics: u64,
}

impl fmt::Display for Counters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "captured {} (-{}), played {} (-{}), gaps {}, buffer failures {}, stalls {}, panics {}",
            self.captured,
            self.capture_dropped,
            self.played,
            self.playback_starved,
            self.discontinuities,
            self.buffer_failures,
            self.stalls,
            self.panics
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Counters;

    #[test]
    fn a_clean_run_reads_as_zeroes() {
        assert_eq!(
            Counters::default().to_string(),
            "captured 0 (-0), played 0 (-0), gaps 0, buffer failures 0, stalls 0, panics 0"
        );
    }

    #[test]
    fn two_readings_subtract() {
        let first = Counters {
            played: 480,
            ..Counters::default()
        };
        let second = Counters {
            played: 48_480,
            playback_starved: 12,
            ..Counters::default()
        };
        assert_eq!(second.played - first.played, 48_000);
        assert_eq!(second.playback_starved, 12);
    }
}
