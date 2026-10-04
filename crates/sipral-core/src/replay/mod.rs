// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A session written down, and fed back.
//!
//! The failures that cost the most happen on one PBX, on one carrier, behind
//! one NAT, and do not happen in a laboratory. They are diagnosed today by
//! reasoning about a capture, shipping a guess, and waiting a week to find
//! out. A recording ends that: the session that failed comes back as a file,
//! the fix is proved against the conditions that produced the bug, and the
//! file stays in the tree afterwards as a test that the bug does not come
//! back.
//!
//! This is nearly free here, and that is an argument for the architecture
//! rather than for this module. Everything that enters the stack enters
//! through [`Endpoint::receive`](crate::endpoint::Endpoint::receive) and
//! [`Endpoint::handle_timeout`](crate::endpoint::Endpoint::handle_timeout),
//! and the time those are given is the caller's rather than the clock's
//! (`docs/13-client-requirements.md`, D9). So a recording is the sequence of
//! those calls with the offsets they were made at, and a replay is making
//! them again.
//!
//! # What is in one, and what cannot be
//!
//! The seed, because everything the stack draws — every branch, tag,
//! `Call-ID` and `cnonce` — is derived from it, and a replay under a
//! different seed writes different requests that the recorded answers no
//! longer belong to. Then the frames: what arrived, when a deadline was
//! taken, and the names of the things the application did on its own
//! ([`Step::Cue`]).
//!
//! What cannot be in one is audio, and it is the format that makes it so
//! rather than the code that writes it. The transcript is text — one line of
//! a message to a line of the file, four escapes and no others — so there is
//! no binary frame, no length-prefixed blob and no base64 to smuggle a media
//! frame through. [`Payload`] is the whole of that rule: it is the only way
//! to put bytes in a frame, and it refuses anything that is not text. Media
//! never reaches this layer in the first place — RTP arrives at another crate
//! on another socket — so the format does not omit a media frame, it has none
//! to define.
//!
//! # Driving one
//!
//! The instants are parameters here for the same reason they are parameters
//! everywhere else in these crates: whoever owns the sockets owns the clock,
//! and a recorder that read one of its own would be recording a session
//! slightly different from the one the stack saw.
//!
//! ```
//! use sipral_core::endpoint::{Endpoint, EndpointConfig, Input, TransportId, TransportProtocol};
//! use sipral_core::replay::{Played, Recorder, Recording, Replay};
//! use std::time::Instant;
//!
//! fn record(seed: [u8; 32], now: Instant) -> Result<Recording, Box<dyn core::error::Error>> {
//!     let mut endpoint = Endpoint::new(EndpointConfig::default(), seed)?;
//!     let mut recorder = Recorder::new(seed).about("a registrar that challenges");
//!
//!     let bound = Input::TransportBound {
//!         transport: TransportId(1),
//!         protocol: TransportProtocol::Udp,
//!         local: "192.0.2.1:5060".parse()?,
//!         remote: None,
//!     };
//!     recorder.arrived(&bound, now);
//!     endpoint.receive(bound, now)?;
//!
//!     let recording = recorder.finish()?;
//!     assert_eq!(Recording::parse(&recording.to_text())?, recording);
//!     Ok(recording)
//! }
//!
//! fn play(recording: &Recording, origin: Instant) -> Result<(), Box<dyn core::error::Error>> {
//!     let mut endpoint = Endpoint::new(EndpointConfig::default(), recording.seed())?;
//!     let mut replay = Replay::new(recording, origin);
//!     while let Some(played) = replay.step(&mut endpoint)? {
//!         assert_eq!(played, Played::Fed);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! What replay reproduces and what it does not is in `docs/18-replay.md`, and
//! the short of it is that a recording is a script rather than a peer: the
//! answers in it were written for the requests the recorded build sent, so a
//! change to what this end writes can leave them answering nothing.

mod driven;
mod error;
mod frame;
mod read;
mod recording;
#[cfg(test)]
mod tests;
mod text;

pub use driven::{Driven, Played, Replay};
pub use error::{ReadError, RecordError};
pub use frame::{Arrival, Frame, Payload, Step};
pub use recording::{Recorder, Recording};

impl Recording {
    /// Read one back.
    ///
    /// # Errors
    /// [`ReadError`], and a recording written by a later version of the
    /// format is one of them: the reader refuses it rather than reading the
    /// lines it recognises.
    pub fn parse(text: &str) -> Result<Self, ReadError> {
        read::read(text)
    }
}
