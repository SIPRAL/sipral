// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a recording refuses to hold, and what a reader refuses to believe.

use core::fmt;

use super::Recording;

/// Why a session could not be written down.
///
/// Both of these are refusals rather than faults, and both are reported by
/// [`Recorder::finish`](super::Recorder::finish) rather than at the call that
/// caused them. A recording holds every byte the stack was fed or it does not
/// exist: one that quietly lost a message would replay into a different
/// session and say nothing about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Bytes arrived that the format cannot spell.
    ///
    /// The transcript is text and has no binary form, so a payload that is
    /// not text has nowhere to go. This is the rule that keeps audio out
    /// (`docs/18-replay.md`), and it is also the boundary: a SIP message with
    /// a binary body cannot be recorded either, and the recorder says so
    /// instead of dropping the body.
    NotText {
        /// Which frame, counting from zero, so that a driver can say what it
        /// was doing at the time.
        frame: usize,
    },
    /// A note or a cue label that is not one line of text.
    ///
    /// Both are prose written by the application into a line-oriented file,
    /// so neither may carry a line ending or a control character.
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
/// Every one of these stops the read. A recording is fed back into a state
/// machine, so a reader that guessed at a line it did not understand would
/// replay a session nobody recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The first line does not name the format.
    NotARecording,
    /// Written by a later version of the format than this reader knows.
    ///
    /// The reader stops here rather than reading what it recognises and
    /// ignoring the rest: a later version may have changed what a line it
    /// does recognise means.
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
    /// No seed, and without one nothing that the stack draws comes back the
    /// same.
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
