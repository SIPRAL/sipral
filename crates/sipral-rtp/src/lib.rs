// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RTP and RTCP for a two-party call.
//!
//! The fixed header read and written (RFC 3550 §5.1), the validity checks a
//! receiver makes before it believes a source (Appendix A.1), symmetric RTP
//! with latching, an adaptive de-jitter buffer that hands frames to a
//! consumer in sequence order and sets its own delay from the arrival times
//! it sees, and RTCP's sender and receiver reports, source description and
//! goodbye (§6), scheduled the way §6.2 and §6.3 describe.
//!
//! DTMF and the other named telephone events ride in that same stream and are
//! sent from the same session, since RFC 4733 §2.1 gives them its SSRC, its
//! sequence numbers and its timestamp base.
//!
//! Sans-I/O, like the rest of the tree. Nothing here opens a socket, reads a
//! clock or draws a random number: the caller supplies datagrams and the
//! address each arrived from, supplies the SSRC and the starting sequence
//! number and timestamp, supplies the wall clock as an NTP timestamp and the
//! random draw RTCP's own scheduling needs, and takes back bytes to send,
//! the address to send them to, and when to be called again.
//!
//! Written from RFC 3550, RFC 3551, RFC 4733 and RFC 5761; see
//! `docs/02-clean-room.md` for why that matters here.

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

mod dtmf;
mod endpoint;
mod playout;
mod rtcp;
mod rtcp_stats;
mod rtcp_timer;
mod source;
pub mod srtp;
mod wire;

pub use dtmf::{
    EVENT_LEN, EventError, EventReceiver, EventReport, EventSender, MAX_DURATION, MAX_VOLUME,
    Outcome, Outgoing, Reported, dtmf_digit,
};
pub use endpoint::{Discard, Received, RtcpReceived, RtpSession, StreamConfig};
pub use playout::{Activity, BufferConfig, Frame, Insert, JitterBuffer, MAX_DEPTH, Pull, Quality};
pub use rtcp::{
    CNAME, Chunk, ChunkBuilder, Chunks, CompoundBuilder, CompoundPacket, Goodbye, GoodbyeBuilder,
    Items, Packets, ReceiverReport, ReceiverReportBuilder, ReportBlock, Reports, RtcpBuildError,
    RtcpError, RtcpPacket, SdesItem, SenderInfo, SenderOrReceiver, SenderReport,
    SenderReportBuilder, SourceDescription, SourceDescriptionBuilder, is_rtcp, paired_rtcp_port,
};
pub use rtcp_timer::Due;
pub use source::{SeqUpdate, SequenceState};
pub use wire::{
    BuildError, FIXED_HEADER_LEN, HeaderExtension, MAX_PAYLOAD_TYPE, PacketBuilder, PacketError,
    PayloadTypes, RtpHeader, RtpPacket, VERSION,
};
