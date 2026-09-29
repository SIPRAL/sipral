// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RTCP feedback for audio: the parts of RTP/AVPF (RFC 4585) and of
//! reduced-size RTCP (RFC 5506) a voice call has a use for.
//!
//! - [`feedback`]: the feedback message format and the Generic NACK, the
//!   one message that asks for audio packets again (RFC 4585 §6).
//! - [`timing`]: when feedback may go out — Early RTCP packets rationed by
//!   `allow_early`, Regular ones thinned by `T_rr_interval` (RFC 4585 §3).
//! - [`rsize`]: sending and receiving feedback without the compound
//!   packet's report and CNAME in front of it, and when that is allowed
//!   (RFC 5506).
//! - [`sdp`]: the profile names, `a=rtcp-fb` and `a=rtcp-rsize`.
//!
//! Sans-I/O like the rest of the crate: no clock, no socket, no random
//! number drawn here. Written from RFC 4585 and RFC 5506 alone.

pub mod feedback;
pub mod sdp;

pub use feedback::{
    FMT_GENERIC_NACK, FeedbackBuildError, FeedbackError, FeedbackPacket, GenericNack,
    GenericNackBuilder, NackEntries, NackEntry, PSFB, RTPFB,
};
pub use sdp::{
    Feedback, FeedbackPayload, FeedbackValue, RTCP_FB, RTCP_RSIZE, RtcpFb, RtpProfile,
    answer_attributes, offers_rsize, rsize_negotiated, rtcp_fb,
};
