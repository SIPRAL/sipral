// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Session descriptions (RFC 4566) and the offer/answer model (RFC 3264).
//!
//! The answer is built from the offer, so [`SessionDescription`] carries
//! [`SessionDescription::answer`] instead of a separate negotiator.
//!
//! A description read and written back comes out byte for byte, including
//! lines this stack ignores: a forwarded body must not lose extensions.
//! No policy lives here; codecs and hold arrive as arguments.
//! [`MediaCapabilities`] and [`MediaPlan`] are the two ends of the
//! negotiation: what goes into an offer, and what the answer settled on.

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
