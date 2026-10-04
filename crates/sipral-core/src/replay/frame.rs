// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One thing that happened to the stack, and when.
//!
//! Most of what drives a sans-I/O stack enters through two calls —
//! [`Endpoint::receive`](crate::endpoint::Endpoint::receive) and
//! [`Endpoint::handle_timeout`](crate::endpoint::Endpoint::handle_timeout) —
//! so most of a session is the sequence of those calls and the instants they
//! were made at. [`Endpoint::resolved`](crate::endpoint::Endpoint::resolved) is
//! a third way in: an answer from outside — a resolver, today — to a question
//! the stack asked. It carries data rather than a decision, so unlike the
//! fourth kind below it can be written down and fed back exactly, and
//! [`Step::Resolved`] is where it goes. What is left over, and cannot be any
//! of the three, is the application acting on its own, which a recording
//! cannot repeat for it and therefore names instead.

use std::net::SocketAddr;
use std::time::Duration;

use super::text::writable;
use crate::endpoint::{Input, TransportErrorKind, TransportId, TransportProtocol};
use crate::transaction::DialogId;

/// Bytes a recording can hold: text, or nothing.
///
/// This is where the format's promise about audio stops being a habit and
/// becomes a type. There is one way to make a payload, it is
/// [`Payload::new`], and it refuses anything the transcript's alphabet cannot
/// spell. A frame of media, a codec's output, a binary body — none of them can
/// be put in a frame, at the writing end or the reading end, because none of
/// them can be made into one of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload(Box<[u8]>);

impl Payload {
    /// Take bytes, if the format can hold them.
    ///
    /// It can hold text: UTF-8 with no control characters in it other than
    /// the carriage return, line feed and horizontal tab that SIP itself is
    /// made of. Everything else is refused here and nowhere else.
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
/// The mirror of [`Input`], which borrows the bytes it carries because the
/// caller owns the buffer they were read into. A recording outlives that
/// buffer.
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
    /// `None` for bytes that are not text, which is the same refusal
    /// [`Payload::new`] makes and the reason it is made here: the frame is
    /// never built, so there is no half-recorded arrival to notice later.
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
    /// Unlike [`Step::Cue`] this is data, not a name: the addresses and the
    /// protocol a resolver returned are everything `resolved` needs, so a
    /// replay can make the same call again itself rather than asking the
    /// caller to.
    Resolved {
        /// Which dialog the answer was for.
        dialog: DialogId,
        /// The addresses that were resolved, in the order they were handed
        /// to `resolved`. The first one this endpoint has a transport for is
        /// taken; the rest are kept for a later failure to fall back to, so
        /// none of them is folded away the way a retransmitted datagram is.
        addresses: Box<[SocketAddr]>,
        /// The transport the lookup named, when it named one (RFC 3263
        /// §4.1). `None` replays as whatever the dialog's flow already spoke.
        protocol: Option<TransportProtocol>,
    },
    /// The application did something of its own here, under a name it chose.
    ///
    /// Placing a call, answering one, registering an account: none of those
    /// arrive from anywhere, so none of them can be replayed by feeding bytes
    /// back. What a recording can do is say when they happened and what the
    /// application called them, and hand that back at the same instant so the
    /// replay does the same thing again in the same order.
    Cue(Box<str>),
}

/// One frame: what happened, and how far into the session it was.
///
/// The offset is from the first frame, not from an instant, for the reason
/// `docs/14-diagnostics.md` gives about the diagnostic record: an absolute
/// time is a thing this stack never reads, and a session that is replayed
/// starts whenever the replay says it does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// How far into the session, from the first frame.
    pub at: Duration,
    /// What happened.
    pub step: Step,
}

/// The token a transport failure is written as.
///
/// Its own vocabulary rather than the `Display` of
/// [`TransportErrorKind`], which is prose with spaces in it and is meant for
/// a person reading a log.
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
