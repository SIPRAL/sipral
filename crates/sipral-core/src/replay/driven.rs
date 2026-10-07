// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Feeding a recording back.
//!
//! Sans-I/O leaves nothing to simulate: a replay makes the same calls at the
//! recorded offsets.

use std::net::SocketAddr;
use std::time::Instant;

use super::frame::{Frame, Step};
use super::recording::Recording;
use crate::endpoint::{Endpoint, Input, ReceiveError, TransportProtocol};
use crate::transaction::DialogId;

/// Something a recording can be fed into.
///
/// Shared by every layer, so a field recording can be replayed into the
/// endpoint, the user agent or an application wrapper.
pub trait Driven {
    /// Bytes, or news about a transport.
    ///
    /// # Errors
    /// Whatever the layer says about bytes it could not read.
    fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError>;

    /// Time has passed.
    fn handle_timeout(&mut self, now: Instant);

    /// A dialog's next hop was answered from outside
    /// ([`Endpoint::resolved`](crate::endpoint::Endpoint::resolved)).
    fn resolved(
        &mut self,
        dialog: DialogId,
        addresses: &[SocketAddr],
        protocol: Option<TransportProtocol>,
    );
}

impl Driven for Endpoint {
    fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        Self::receive(self, input, now)
    }

    fn handle_timeout(&mut self, now: Instant) {
        Self::handle_timeout(self, now);
    }

    fn resolved(
        &mut self,
        dialog: DialogId,
        addresses: &[SocketAddr],
        protocol: Option<TransportProtocol>,
    ) {
        Self::resolved(self, dialog, addresses, protocol);
    }
}

/// What one step of a replay did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Played<'a> {
    /// The frame went into the stack and nothing is asked of the caller.
    Fed,
    /// The application did something of its own here, under this name.
    ///
    /// The caller repeats it before stepping on; ignoring cues replays a
    /// different session.
    Cue(&'a str),
}

/// A recording, being fed back.
///
/// Pull, not push: between frames the caller drains output, reads events and
/// acts on cues, at [`Replay::next_at`].
#[derive(Clone, Copy, Debug)]
pub struct Replay<'a> {
    frames: &'a [Frame],
    origin: Instant,
    next: usize,
}

impl<'a> Replay<'a> {
    /// A replay of `recording`, with its first frame at `origin`.
    ///
    /// A recording holds only offsets, so any origin works.
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
    /// Whatever the stack says: malformed messages are replayed too, and
    /// hiding the refusal would hide the bug.
    pub fn step<T: Driven>(&mut self, target: &mut T) -> Result<Option<Played<'a>>, ReceiveError> {
        let Some(frame) = self.frames.get(self.next) else {
            return Ok(None);
        };
        self.next += 1;
        let now = self.origin + frame.at;
        match frame.step {
            Step::Arrived(ref arrival) => target.receive(arrival.as_input(), now)?,
            Step::Woke => target.handle_timeout(now),
            Step::Resolved {
                dialog,
                ref addresses,
                protocol,
            } => target.resolved(dialog, addresses, protocol),
            Step::Cue(ref label) => return Ok(Some(Played::Cue(label))),
        }
        Ok(Some(Played::Fed))
    }
}
