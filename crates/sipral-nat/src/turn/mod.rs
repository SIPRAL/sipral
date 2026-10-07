// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! TURN: the relay of last resort (RFC 8656, which obsoletes RFC 5766 and
//! RFC 6156).
//!
//! A public server relays for us when no direct path exists; it costs a
//! round trip and bandwidth, so it is tried last.
//!
//! Channels (4-byte header) replace Send indications (36 octets) once
//! bound. TCP and TLS cover networks that only allow 443; the TLS session
//! is the caller's (see [`framing`]).
//!
//! Sans-I/O: the caller supplies time, random transaction ids and input,
//! and takes back output and the next deadline.

mod attribute;
mod channel;
mod client;
pub mod framing;

pub use attribute::{
    AddressFamily, CHANNEL_LIFETIME, DEFAULT_LIFETIME, EvenPort, Icmp, PERMISSION_LIFETIME,
    PROTOCOL_UDP, ReservationToken, method,
};
pub use channel::HEADER_LEN as CHANNEL_HEADER_LEN;
pub use channel::{ChannelData, ChannelError, ChannelNumber, FIRST_CHANNEL, LAST_CHANNEL};
pub use client::{
    DEFAULT_TI, Event, FamilyRequest, Input, SendError, StartError, TurnClient, TurnConfig,
    TurnError,
};
pub use framing::{FrameError, MAX_FRAME, StreamFraming, Transport};
