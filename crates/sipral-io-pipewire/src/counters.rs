// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the stream did while nobody was watching.
//!
//! `process()` runs on PipeWire's own realtime data thread, which cannot log,
//! cannot return an error to anyone, and cannot wait for a lock a non-realtime
//! thread might hold. Everything that goes wrong there is counted and read
//! later. A call that sounds wrong is nearly always explained by two of these
//! numbers.

use core::fmt;

/// A reading of one stream's counters, taken at a moment.
///
/// Counted in samples rather than frames, because PipeWire hands over
/// whatever the graph's quantum happens to be for that cycle, and a frame
/// boundary means nothing to it. All of them only ever grow, so two readings
/// subtract into a rate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Samples the capture side handed over.
    pub captured: u64,
    /// Samples the capture side threw away because the ring was full, which
    /// means the reader is not keeping up or has stopped reading.
    pub capture_dropped: u64,
    /// Samples the playback side took.
    pub played: u64,
    /// Samples the playback side had to invent, because the ring was empty
    /// when PipeWire asked. Silence went out instead.
    pub playback_starved: u64,
    /// Times `process()` found no buffer to dequeue. `pw_stream_dequeue_buffer`
    /// returning null is ordinary during start-up and teardown; the count is
    /// what says whether it happened once or is happening constantly.
    pub buffer_misses: u64,
    /// Times a panic was caught at the callback boundary and turned into
    /// silence. Any number above zero is a bug in this crate.
    pub panics: u64,
}

impl fmt::Display for Counters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "captured {} (-{}), played {} (-{}), buffer misses {}, panics {}",
            self.captured,
            self.capture_dropped,
            self.played,
            self.playback_starved,
            self.buffer_misses,
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
            "captured 0 (-0), played 0 (-0), buffer misses 0, panics 0"
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
