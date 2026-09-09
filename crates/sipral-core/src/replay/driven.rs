// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Feeding a recording back.
//!
//! The replay is the smaller half of this feature, and that is the point of
//! having built the stack sans-I/O: there is nothing to simulate. The two
//! calls that a session enters through are the two calls a replay makes, in
//! the order and at the offsets the recording holds.

use std::time::Instant;

use super::frame::{Frame, Step};
use super::recording::Recording;
use crate::endpoint::{Endpoint, Input, ReceiveError};

/// Something a recording can be fed into.
///
/// The two entry points every layer of this stack shares. A replay does not
/// know or care whether it is driving the endpoint, the user agent above it
/// or an application's own wrapper around either, which is what lets a
/// recording taken from a phone in the field be replayed into whichever layer
/// the bug is thought to be in.
pub trait Driven {
    /// Bytes, or news about a transport.
    ///
    /// # Errors
    /// Whatever the layer says about bytes it could not read.
    fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError>;

    /// Time has passed.
    fn handle_timeout(&mut self, now: Instant);
}

impl Driven for Endpoint {
    fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        Self::receive(self, input, now)
    }

    fn handle_timeout(&mut self, now: Instant) {
        Self::handle_timeout(self, now);
    }
}

/// What one step of a replay did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Played<'a> {
    /// The frame went into the stack and nothing is asked of the caller.
    Fed,
    /// The application did something of its own here, under this name.
    ///
    /// The caller does it again — places the call, answers it, registers the
    /// account — before stepping on. A replay that ignores its cues is a
    /// replay of a different session, and will usually show it by having
    /// nothing to answer the next message with.
    Cue(&'a str),
}

/// A recording, being fed back.
///
/// Pull rather than push, because between two frames the caller has work to
/// do: draining what the stack wants written, reading the events, and acting
/// on a cue. [`Replay::next_at`] gives the instant the next frame happens at,
/// which is the `now` everything in between is done with.
#[derive(Clone, Copy, Debug)]
pub struct Replay<'a> {
    frames: &'a [Frame],
    origin: Instant,
    next: usize,
}

impl<'a> Replay<'a> {
    /// A replay of `recording`, with its first frame at `origin`.
    ///
    /// The origin is the caller's: a recording holds offsets and no absolute
    /// time, so the session can be replayed at any instant and the schedule
    /// between the frames is the one that was recorded.
    #[must_use]
    pub fn new(recording: &'a Recording, origin: Instant) -> Self {
        Self {
            frames: recording.frames(),
            origin,
            next: 0,
        }
    }

    /// When the next frame happens, or `None` when the session is over.
    #[must_use]
    pub fn next_at(&self) -> Option<Instant> {
        self.frames
            .get(self.next)
            .map(|frame| self.origin + frame.at)
    }

    /// Feed the next frame.
    ///
    /// `Ok(None)` is the end of the session.
    ///
    /// # Errors
    /// Whatever the stack says about the bytes: a recording holds what
    /// arrived, malformed messages included, and a replay that hid the
    /// refusal would hide the bug.
    pub fn step<T: Driven>(&mut self, target: &mut T) -> Result<Option<Played<'a>>, ReceiveError> {
        let Some(frame) = self.frames.get(self.next) else {
            return Ok(None);
        };
        self.next += 1;
        let now = self.origin + frame.at;
        match frame.step {
            Step::Arrived(ref arrival) => target.receive(arrival.as_input(), now)?,
            Step::Woke => target.handle_timeout(now),
            Step::Cue(ref label) => return Ok(Some(Played::Cue(label))),
        }
        Ok(Some(Played::Fed))
    }
}
