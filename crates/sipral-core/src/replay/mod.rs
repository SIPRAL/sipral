// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A session written down, and fed back.
//!
//! A failure seen on one PBX comes back as a file, the fix is proved against
//! it, and the file stays as a regression test.
//!
//! Everything enters the stack through
//! [`Endpoint::receive`](crate::endpoint::Endpoint::receive) and
//! [`Endpoint::handle_timeout`](crate::endpoint::Endpoint::handle_timeout),
//! with the caller's time (`docs/13-client-requirements.md`, D9). A recording
//! is those calls with their offsets; a replay makes them again.
//!
//! # What is in one, and what cannot be
//!
//! The seed, since every branch, tag, `Call-ID` and `cnonce` derives from it.
//! Then the frames: arrivals, deadlines, and [`Step::Cue`] names.
//!
//! Audio cannot be in one. The format is text with four escapes and no
//! binary form, and [`Payload`] refuses anything else.
//!
//! # Driving one
//!
//! Instants are parameters: whoever owns the sockets owns the clock.
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
//! A recording is a script, not a peer (`docs/18-replay.md`): change what
//! this end writes and the recorded answers may match nothing.

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
    /// [`ReadError`], including a later format version.
    pub fn parse(text: &str) -> Result<Self, ReadError> {
        read::read(text)
    }
}
