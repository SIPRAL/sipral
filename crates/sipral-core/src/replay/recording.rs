// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The artefact, and the thing that makes one.

use core::fmt::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::error::RecordError;
use super::frame::{Arrival, Frame, Step, failure_token};
use super::text::{one_line, write_payload};
use crate::endpoint::{Input, TransportProtocol};
use crate::transaction::DialogId;

/// A session, written down.
///
/// The seed and every frame that entered the stack, with offsets. Nothing
/// the stack produced: a recording is the question, today's code the answer.
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
    /// A higher number is refused. Raised to `2` for [`Step::Resolved`], and to
    /// `3` when `resolved` gained the protocol of RFC 3263 §4.1: an older reader
    /// would misparse that token as an address.
    pub const VERSION: u32 = 3;

    /// The signalling seed the recorded stack drew from while it recorded.
    ///
    /// Every branch, tag, `Call-ID` and `cnonce` derives from it
    /// ([`Endpoint::new`](crate::endpoint::Endpoint::new)). A user agent draws a
    /// fresh one per recording ([`Endpoint::reseed`](crate::endpoint::Endpoint::reseed)).
    /// Media keys come from a second seed with no field here, so sharing a
    /// recording does not share the means to decrypt its media.
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
    /// Round trips with [`Recording::parse`].
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
                Step::Resolved {
                    dialog,
                    ref addresses,
                    protocol,
                } => write_resolved(&mut out, dialog, addresses, protocol),
                Step::Cue(ref label) => {
                    let _ = writeln!(out, "cue {label}");
                }
                Step::Arrived(ref arrival) => write_arrival(&mut out, arrival),
            }
        }
        out
    }
}

/// One `resolved` line: dialog, protocol or `-`, then the addresses.
fn write_resolved(
    out: &mut String,
    dialog: DialogId,
    addresses: &[SocketAddr],
    protocol: Option<TransportProtocol>,
) {
    let _ = write!(
        out,
        "resolved {}.{}",
        dialog.raw.slot, dialog.raw.generation
    );
    match protocol {
        Some(protocol) => {
            let _ = write!(out, " {protocol}");
        }
        None => out.push_str(" -"),
    }
    for address in addresses {
        let _ = write!(out, " {address}");
    }
    out.push('\n');
}

/// One arrival: its line, and the payload lines under it.
///
/// Cannot fail: a [`Payload`](super::Payload) was already accepted.
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
/// Called beside every call into the stack, with the same instant, so the
/// offsets are exact. Frames are infallible at the call site; refusals surface
/// in [`Recorder::finish`], so a recording never silently misses a message.
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
    /// Not read by anything; a recording comes from someone you cannot ask.
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

    /// A dialog's next hop was answered from outside. Called beside
    /// [`Endpoint::resolved`](crate::endpoint::Endpoint::resolved), which is
    /// untimed; `now` only places the frame, as for [`Recorder::cue`].
    pub fn resolved(
        &mut self,
        dialog: DialogId,
        addresses: &[SocketAddr],
        protocol: Option<TransportProtocol>,
        now: Instant,
    ) {
        self.push(
            Step::Resolved {
                dialog,
                addresses: Box::from(addresses),
                protocol,
            },
            now,
        );
    }

    /// The application did something of its own, under a name it chose.
    ///
    /// The name must be the same on the way back, so a replay knows what to
    /// repeat.
    pub fn cue(&mut self, label: &str, now: Instant) {
        if one_line(label) {
            self.push(Step::Cue(Box::from(label)), now);
        } else {
            self.spoil(RecordError::NotOneLine);
        }
    }

    /// What the recorder has refused so far, if anything.
    ///
    /// Lets a long-running driver stop early.
    #[must_use]
    pub const fn spoiled(&self) -> Option<RecordError> {
        self.spoiled
    }

    /// The recording, or the first thing that could not go in it.
    ///
    /// # Errors
    /// [`RecordError`] when anything was refused: all of a session or none.
    pub fn finish(self) -> Result<Recording, RecordError> {
        match self.spoiled {
            Some(error) => Err(error),
            None => Ok(Recording::new(self.seed, self.note, self.frames)),
        }
    }

    /// The first refusal wins; later frames are still taken.
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
