// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Headless media endpoint.
//!
//! Bidirectional PCM with no audio device and no media server in the path:
//! raw frames in, raw frames out, and barge-in that does not wait on a room
//! abstraction. This is what an AI voice agent answers a phone call through.
//!
//! The socket is the caller's, as everywhere else in this workspace. This
//! crate has no dependencies and opens nothing; it frames and parses, and the
//! bytes are carried by whatever the application binds — a local socket, a
//! WebSocket, a pipe.
//!
//! Protocol in `docs/07-headless.md`.

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

mod audio;
mod codec;
mod control;
mod frame;
mod json;
mod latency;
mod registry;
mod session;

pub use audio::{
    AudioConfig, AudioError, DEFAULT_FRAME_DURATION_MS, SampleRate, read_samples, write_samples,
};
pub use codec::{
    DecodeError, Decoded, Decoder, EncodeError, MAX_CONTROL_PAYLOAD, encode_audio, encode_control,
};
pub use control::{
    Answer, BargeIn, CallState, CallStateKind, ControlError, ControlMessage, DtmfDigit,
    DtmfReceived, DtmfSend, ErrorCode, ErrorMessage, FrameKind, Hangup, IncomingCall,
    OtherErrorCode, Reject, SessionOpen, Transfer,
};
pub use frame::{Frame, FrameDecoder, FrameError, HEADER_LEN, write_frame};
pub use json::{JsonError, Value, parse as parse_json};
pub use latency::LatencyBudget;
pub use registry::{RegistryError, SessionRegistry};
pub use session::{Session, SessionError, SessionState};
