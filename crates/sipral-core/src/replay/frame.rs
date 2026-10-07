// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One thing that happened to the stack, and when.
//!
//! A session is mostly calls to
//! [`Endpoint::receive`](crate::endpoint::Endpoint::receive) and
//! [`Endpoint::handle_timeout`](crate::endpoint::Endpoint::handle_timeout).
//! [`Endpoint::resolved`](crate::endpoint::Endpoint::resolved) carries data,
//! so [`Step::Resolved`] replays it exactly. The application acting on its
//! own cannot be replayed, so it is only named.

use std::net::SocketAddr;
use std::time::Duration;

use super::text::writable;
use crate::endpoint::{Input, TransportErrorKind, TransportId, TransportProtocol};
use crate::transaction::DialogId;

/// Bytes a recording can hold: text, or nothing.
///
/// The only constructor is [`Payload::new`], which refuses what the alphabet
/// cannot spell. Media and binary bodies cannot become one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload(Box<[u8]>);

impl Payload {
    /// Take bytes, if the format can hold them.
    ///
    /// UTF-8 with no control characters except CR, LF and tab.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self> {
        writable(bytes).then(|| Self(Box::from(bytes)))
    }

    /// The bytes, to hand back to the stack.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// What arrived, kept rather than borrowed.
///
/// [`Input`] borrows the caller's buffer; a recording outlives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// One message in one packet.
    Datagram {
        /// Which transport it came in on.
        transport: TransportId,
        /// Where it came from.
        remote: SocketAddr,
        /// Where it arrived.
        local: SocketAddr,
        /// The packet, whole.
        data: Payload,
    },
    /// Bytes off a stream transport, in the sizes the reads came in.
    StreamData {
        /// Which connection they came in on.
        transport: TransportId,
        /// The bytes, not necessarily a whole message.
        data: Payload,
    },
    /// The far end closed, or the connection broke.
    StreamClosed {
        /// Which connection.
        transport: TransportId,
    },
    /// A transport is open and may be written to.
    TransportBound {
        /// The name the caller uses for it.
        transport: TransportId,
        /// What it speaks.
        protocol: TransportProtocol,
        /// The address advertised as `sent-by`.
        local: SocketAddr,
        /// The far end, for a connection.
        remote: Option<SocketAddr>,
    },
    /// A transport failed, and what was written to it did not arrive.
    TransportFailed {
        /// Which transport.
        transport: TransportId,
        /// What went wrong.
        error: TransportErrorKind,
    },
}

impl Arrival {
    /// Keep what the caller is about to hand to the stack, when the format
    /// can hold it.
    ///
    /// `None` for non-text bytes, so no half-recorded arrival is ever built.
    #[must_use]
    pub fn of(input: &Input<'_>) -> Option<Self> {
        Some(match *input {
            Input::Datagram {
                transport,
                remote,
                local,
                data,
            } => Self::Datagram {
                transport,
                remote,
                local,
                data: Payload::new(data)?,
            },
            Input::StreamData { transport, data } => Self::StreamData {
                transport,
                data: Payload::new(data)?,
            },
            Input::StreamClosed { transport } => Self::StreamClosed { transport },
            Input::TransportBound {
                transport,
                protocol,
                local,
                remote,
            } => Self::TransportBound {
                transport,
                protocol,
                local,
                remote,
            },
            Input::TransportFailed { transport, error } => {
                Self::TransportFailed { transport, error }
            }
        })
    }

    /// Hand it back, borrowing the bytes the recording holds.
    #[must_use]
    pub fn as_input(&self) -> Input<'_> {
        match *self {
            Self::Datagram {
                transport,
                remote,
                local,
                ref data,
            } => Input::Datagram {
                transport,
                remote,
                local,
                data: data.as_bytes(),
            },
            Self::StreamData {
                transport,
                ref data,
            } => Input::StreamData {
                transport,
                data: data.as_bytes(),
            },
            Self::StreamClosed { transport } => Input::StreamClosed { transport },
            Self::TransportBound {
                transport,
                protocol,
                local,
                remote,
            } => Input::TransportBound {
                transport,
                protocol,
                local,
                remote,
            },
            Self::TransportFailed { transport, error } => {
                Input::TransportFailed { transport, error }
            }
        }
    }

    /// The bytes, where there are any.
    #[must_use]
    pub const fn payload(&self) -> Option<&Payload> {
        match *self {
            Self::Datagram { ref data, .. } | Self::StreamData { ref data, .. } => Some(data),
            Self::StreamClosed { .. }
            | Self::TransportBound { .. }
            | Self::TransportFailed { .. } => None,
        }
    }
}

/// What one frame of a recording says happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Something arrived and was handed to `receive`.
    Arrived(Arrival),
    /// A deadline passed and `handle_timeout` was called.
    Woke,
    /// A dialog's next hop was answered from outside
    /// ([`Endpoint::resolved`](crate::endpoint::Endpoint::resolved)).
    ///
    /// Data, not a name like [`Step::Cue`], so a replay makes the call itself.
    Resolved {
        /// Which dialog the answer was for.
        dialog: DialogId,
        /// The addresses in the order given. The first with a transport is
        /// taken; the rest stay for failover, so none is deduplicated.
        addresses: Box<[SocketAddr]>,
        /// The transport the lookup named, when it named one (RFC 3263
        /// §4.1). `None` replays as whatever the dialog's flow already spoke.
        protocol: Option<TransportProtocol>,
    },
    /// The application did something of its own here, under a name it chose.
    ///
    /// Placing, answering or registering arrives from nowhere, so a replay
    /// hands the name back at the same instant for the caller to repeat.
    Cue(Box<str>),
}

/// One frame: what happened, and how far into the session it was.
///
/// The offset is from the first frame: this stack never reads absolute time
/// (`docs/14-diagnostics.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// How far into the session, from the first frame.
    pub at: Duration,
    /// What happened.
    pub step: Step,
}

/// The token a transport failure is written as.
///
/// Not the `Display` of [`TransportErrorKind`], which is prose with spaces.
pub(super) const fn failure_token(error: TransportErrorKind) -> &'static str {
    match error {
        TransportErrorKind::ConnectionRefused => "refused",
        TransportErrorKind::ConnectionReset => "reset",
        TransportErrorKind::Unreachable => "unreachable",
        TransportErrorKind::TimedOut => "timed-out",
        TransportErrorKind::Closed => "closed",
        TransportErrorKind::Other => "other",
    }
}

/// The reverse, for a reader.
pub(super) fn failure_kind(token: &str) -> Option<TransportErrorKind> {
    match token {
        "refused" => Some(TransportErrorKind::ConnectionRefused),
        "reset" => Some(TransportErrorKind::ConnectionReset),
        "unreachable" => Some(TransportErrorKind::Unreachable),
        "timed-out" => Some(TransportErrorKind::TimedOut),
        "closed" => Some(TransportErrorKind::Closed),
        "other" => Some(TransportErrorKind::Other),
        _ => None,
    }
}
