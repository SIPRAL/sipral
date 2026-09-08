// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RTP for a two-party call.
//!
//! The fixed header read and written (RFC 3550 §5.1), the validity checks a
//! receiver makes before it believes a source (Appendix A.1), symmetric RTP
//! with latching, and a fixed-depth de-jitter buffer that hands frames to a
//! consumer in sequence order.
//!
//! Sans-I/O, like the rest of the tree. Nothing here opens a socket, reads a
//! clock or draws a random number: the caller supplies datagrams and the
//! address each arrived from, supplies the SSRC and the starting sequence
//! number and timestamp, and takes back bytes to send and the address to send
//! them to.
//!
//! Written from RFC 3550 and RFC 3551; see `docs/02-clean-room.md` for why
//! that matters here.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
// tests say what they mean; the no-panic discipline is for the library
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

mod endpoint;
mod playout;
mod source;
mod wire;

pub use endpoint::{Discard, Received, RtpSession, StreamConfig};
pub use playout::{Frame, Insert, JitterBuffer, MAX_DEPTH, Pull, StreamStats};
pub use source::{SeqUpdate, SequenceState};
pub use wire::{
    BuildError, FIXED_HEADER_LEN, HeaderExtension, MAX_PAYLOAD_TYPE, PacketBuilder, PacketError,
    PayloadTypes, RtpHeader, RtpPacket, VERSION,
};
