// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
//!
//! [`MediaCapabilities`] and [`MediaPlan`] also live here rather than in a
//! media crate, because they are the two ends of this negotiation seen from
//! outside: what to write into an offer, and what the answer settled on.

mod answer;
mod crypto;
mod error;
mod media;
mod parse;
mod plan;
mod session;

pub use answer::{AcceptedStream, StreamAnswer};
pub use crypto::{
    CryptoPolicy, CryptoSuite, Inline, KeyIdentifier, KeySalt, MASTER_KEY, MASTER_SALT,
    SessionParams,
};
pub use error::SdpError;
pub use media::{Direction, MediaDescription, RtpMap};
pub use parse::{Limits, parse, parse_with_limits};
pub use plan::{
    Crypto, Keying, MediaCapabilities, MediaPlan, NegotiatedCodec, RtcpPlan, SrtpSupport,
    static_rtpmap,
};
pub use session::{Attribute, Connection, KeyLine, Origin, SessionDescription, Timing};
