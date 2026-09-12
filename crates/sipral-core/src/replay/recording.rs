// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The artefact, and the thing that makes one.

use core::fmt::Write as _;
use std::time::{Duration, Instant};

use super::error::RecordError;
use super::frame::{Arrival, Frame, Step, failure_token};
use super::text::{one_line, write_payload};
use crate::endpoint::Input;

/// A session, written down.
///
/// What is in it is the seed the stack was given and every frame that entered
/// it, in order, each with how far into the session it was. What is not in it
/// is anything the stack produced: a recording is the question, and the
/// answer is whatever the code being tested says today.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recording {
    seed: [u8; 32],
    note: Option<Box<str>>,
    frames: Vec<Frame>,
}

impl Recording {
    /// The word the first line of a recording starts with.
    pub const MAGIC: &'static str = "sipral-recording";

    /// The version this build writes, and the latest it reads.
    ///
    /// A reader refuses a recording that says a higher number rather than
    /// reading the lines it recognises: a later version may have changed what
    /// one of those lines means, and a replay that quietly took a wrong turn
    /// is worse than one that would not start.
    pub const VERSION: u32 = 1;

    /// The signalling seed the recorded stack was built with.
    ///
    /// Every branch, tag, `Call-ID` and `cnonce` is derived from it
    /// ([`Endpoint::new`](crate::endpoint::Endpoint::new)), so a replay built
    /// with a different one writes different messages and the answers in the
    /// recording no longer belong to them.
    ///
    /// **And nothing else is derived from it.** Media keys come from a second
    /// seed this format has no field for, which is why a recording can be
    /// handed to somebody to reproduce a session without handing them the
    /// means to decrypt the media that went with it.
    #[must_use]
    pub const fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// What the application said it was doing, if it said anything.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// Every frame, in order.
    #[must_use]
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }

    /// How long the session lasted: the offset of its last frame.
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.frames.last().map_or(Duration::ZERO, |frame| frame.at)
    }

    /// Build one from parts, for a reader.
    pub(super) const fn new(seed: [u8; 32], note: Option<Box<str>>, frames: Vec<Frame>) -> Self {
        Self { seed, note, frames }
    }

    /// The recording as the text that goes in a file.
    ///
    /// Round trips: reading this back gives the same recording, and writing
    /// that gives the same text.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{} {}", Self::MAGIC, Self::VERSION);
        out.push_str("seed ");
        for byte in self.seed {
            let _ = write!(out, "{byte:02x}");
        }
        out.push('\n');
        if let Some(note) = self.note() {
            let _ = writeln!(out, "note {note}");
        }
        for frame in &self.frames {
            let _ = write!(
                out,
                "+{}.{:09} ",
                frame.at.as_secs(),
                frame.at.subsec_nanos()
            );
            match frame.step {
                Step::Woke => out.push_str("wake\n"),
                Step::Cue(ref label) => {
                    let _ = writeln!(out, "cue {label}");
                }
                Step::Arrived(ref arrival) => write_arrival(&mut out, arrival),
            }
        }
        out
    }
}

/// One arrival: its line, and the payload lines under it.
///
/// Nothing can be refused here. A [`Payload`](super::Payload) exists only if
/// the alphabet accepted it, so by the time a frame is being written out the
/// question has already been settled.
fn write_arrival(out: &mut String, arrival: &Arrival) {
    match *arrival {
        Arrival::Datagram {
            transport,
            remote,
            local,
            ref data,
        } => {
            let _ = writeln!(out, "datagram {} {remote} {local}", transport.0);
            write_payload(out, data.as_bytes());
        }
        Arrival::StreamData {
            transport,
            ref data,
        } => {
            let _ = writeln!(out, "stream {}", transport.0);
            write_payload(out, data.as_bytes());
        }
        Arrival::StreamClosed { transport } => {
            let _ = writeln!(out, "closed {}", transport.0);
        }
        Arrival::TransportBound {
            transport,
            protocol,
            local,
            remote,
        } => {
            let _ = write!(out, "bound {} {protocol} {local} ", transport.0);
            match remote {
                Some(remote) => {
                    let _ = writeln!(out, "{remote}");
                }
                None => out.push_str("-\n"),
            }
        }
        Arrival::TransportFailed { transport, error } => {
            let _ = writeln!(out, "failed {} {}", transport.0, failure_token(error));
        }
    }
}

/// Writes a session down while it runs.
///
/// The driver that owns the sockets calls one of these beside every call it
/// makes into the stack, and gets a [`Recording`] at the end. Nothing here
/// reads a clock either: the instant comes from the same variable the stack
/// was given, which is what makes the offsets exact rather than approximate.
///
/// Every method that takes a frame is infallible at the call site, and the
/// one that refuses is [`Recorder::finish`]. That is deliberate. A refusal
/// mid-session means the recording is no longer the session, and a driver
/// that had to handle each one separately would end up with a recording that
/// is missing a message and does not say so.
#[derive(Clone, Debug)]
pub struct Recorder {
    seed: [u8; 32],
    note: Option<Box<str>>,
    origin: Option<Instant>,
    frames: Vec<Frame>,
    spoiled: Option<RecordError>,
}

impl Recorder {
    /// A recorder for a stack built with `seed`.
    #[must_use]
    pub const fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            note: None,
            origin: None,
            frames: Vec::new(),
            spoiled: None,
        }
    }

    /// One line of prose for whoever opens the file: what was being done,
    /// against what, on which build.
    ///
    /// Not read by anything here. It is there because a recording arrives
    /// from somebody who cannot be asked a follow-up question.
    #[must_use]
    pub fn about(mut self, note: &str) -> Self {
        if one_line(note) {
            self.note = Some(Box::from(note));
        } else {
            self.spoil(RecordError::NotOneLine);
        }
        self
    }

    /// Something arrived. Called beside `receive`, with the same `now`.
    pub fn arrived(&mut self, input: &Input<'_>, now: Instant) {
        match Arrival::of(input) {
            Some(arrival) => self.push(Step::Arrived(arrival), now),
            None => self.spoil(RecordError::NotText {
                frame: self.frames.len(),
            }),
        }
    }

    /// A deadline passed. Called beside `handle_timeout`, with the same `now`.
    pub fn woke(&mut self, now: Instant) {
        self.push(Step::Woke, now);
    }

    /// The application did something of its own, under a name it chose.
    ///
    /// The name is the application's and means nothing here. What matters is
    /// that it is the same name on the way back, so that a replay knows which
    /// of its own actions to repeat.
    pub fn cue(&mut self, label: &str, now: Instant) {
        if one_line(label) {
            self.push(Step::Cue(Box::from(label)), now);
        } else {
            self.spoil(RecordError::NotOneLine);
        }
    }

    /// What the recorder has refused so far, if anything.
    ///
    /// A long-running driver reads this to stop early rather than finding out
    /// at the end that the last hour is not a recording.
    #[must_use]
    pub const fn spoiled(&self) -> Option<RecordError> {
        self.spoiled
    }

    /// The recording, or the first thing that could not go in it.
    ///
    /// # Errors
    /// [`RecordError`] when anything was refused. A recording holds all of a
    /// session or none of it.
    pub fn finish(self) -> Result<Recording, RecordError> {
        match self.spoiled {
            Some(error) => Err(error),
            None => Ok(Recording::new(self.seed, self.note, self.frames)),
        }
    }

    /// The first refusal is the one reported; a spoiled recorder keeps taking
    /// frames rather than making the driver check.
    const fn spoil(&mut self, error: RecordError) {
        if self.spoiled.is_none() {
            self.spoiled = Some(error);
        }
    }

    fn push(&mut self, step: Step, now: Instant) {
        let origin = *self.origin.get_or_insert(now);
        self.frames.push(Frame {
            at: now.saturating_duration_since(origin),
            step,
        });
    }
}
