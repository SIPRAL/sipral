// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Session descriptions (RFC 4566) and the offer/answer model (RFC 3264).
//!
//! SIP does not negotiate media. It carries a body that does, and this is that
//! body: a list of lines saying where to send audio, in what format, and which
//! way it may flow. The negotiation is two messages — an offer and an answer —
//! and the second is built from the first, which is why [`SessionDescription`]
//! carries [`SessionDescription::answer`] rather than there being a separate
//! negotiator.
//!
//! A description that is read and written back comes out as it went in, down
//! to the lines this stack has no use for. That is not tidiness: an SDP body
//! travels through a call in a message that may be forwarded, and a stack that
//! quietly drops what it does not understand is a stack that breaks the next
//! extension somebody adds.
//!
//! No policy lives here. Which codecs to offer, which to keep, whether to put
//! a call on hold — all of it arrives as arguments and none of it is decided
//! here.

mod answer;
mod error;
mod media;
mod parse;
mod session;

pub use answer::{AcceptedStream, StreamAnswer};
pub use error::SdpError;
pub use media::{Direction, MediaDescription, RtpMap};
pub use parse::parse;
pub use session::{Attribute, Connection, Origin, SessionDescription, Timing};
