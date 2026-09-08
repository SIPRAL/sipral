// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! TURN: the relay of last resort (RFC 8656, which obsoletes RFC 5766 and
//! RFC 6156).
//!
//! Everything else in this crate tries to find a path between two endpoints.
//! This is what happens when there is none: a server on the public Internet
//! holds an address on our behalf, peers send to it, and it forwards. It costs
//! a round trip and somebody's bandwidth, so it is the last thing tried and
//! the first thing that works when nothing else does.
//!
//! Two things shape the code here more than the rest of the specification. The
//! first is the four-byte channel header: a Send indication wraps every packet
//! in thirty-six octets of STUN, which on a voice frame is more overhead than
//! payload, so the client binds a channel and uses indications only until the
//! binding is confirmed. The second is TCP and TLS, which exist for the
//! corporate network that lets nothing out but 443 — the case this whole
//! component was written for. The TLS handshake is the caller's; see
//! [`framing`] for exactly where the seam is.
//!
//! Sans-I/O, like the binding client: the caller supplies the time, supplies
//! transaction ids drawn from a real random source, feeds in what arrived, and
//! takes back what to send and when to be called again.

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
