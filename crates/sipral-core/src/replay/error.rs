// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a recording refuses to hold, and what a reader refuses to believe.

use core::fmt;

use super::Recording;

/// Why a session could not be written down.
///
/// Reported by [`Recorder::finish`](super::Recorder::finish). A recording
/// holds every byte the stack was fed or it does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Bytes arrived that the format cannot spell, such as a binary body
    /// (`docs/18-replay.md`).
    NotText {
        /// Which frame, counting from zero.
        frame: usize,
    },
    /// A note or a cue label that is not one line of text.
    NotOneLine,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotText { frame } => {
                write!(f, "frame {frame} is not text, and a recording is text")
            }
            Self::NotOneLine => f.write_str("a note and a cue label are one line of text"),
        }
    }
}

impl core::error::Error for RecordError {}

/// Why a file is not a recording this reader will replay.
///
/// Every one stops the read: guessing would replay a session nobody recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The first line does not name the format.
    NotARecording,
    /// A later format version, which may have changed what known lines mean.
    Version {
        /// The version the file says it is.
        found: u32,
        /// The latest version this reader knows.
        supported: u32,
    },
    /// A line this reader cannot make sense of.
    Syntax {
        /// Which line of the file, counting from one.
        line: usize,
    },
    /// A byte the format has no way to write, so a recorder did not write it.
    NotText {
        /// Which line of the file, counting from one.
        line: usize,
    },
    /// A frame stamped earlier than the one before it.
    Backwards {
        /// Which line of the file, counting from one.
        line: usize,
    },
    /// Payload lines under a frame that carries none.
    StrayPayload {
        /// Which line of the file, counting from one.
        line: usize,
    },
    /// No seed, so nothing the stack draws comes back the same.
    NoSeed,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotARecording => write!(
                f,
                "not a recording: the first line has to read `{} 1`",
                Recording::MAGIC
            ),
            Self::Version { found, supported } => write!(
                f,
                "recording is version {found} and this reader knows {supported}"
            ),
            Self::Syntax { line } => write!(f, "line {line} is not a line of a recording"),
            Self::NotText { line } => write!(f, "line {line} holds something that is not text"),
            Self::Backwards { line } => write!(f, "line {line} is stamped before the frame above"),
            Self::StrayPayload { line } => write!(f, "line {line} is a payload with no frame"),
            Self::NoSeed => f.write_str("no seed, so nothing drawn would come back the same"),
        }
    }
}

impl core::error::Error for ReadError {}
