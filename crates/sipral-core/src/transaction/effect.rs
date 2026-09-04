// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a state machine asks for after something is fed into it.
//!
//! Shared by all four machines rather than written out per machine: the shape
//! is the same everywhere, and a second copy would drift from the first.

use super::super::msg::OwnedMessage;

/// What the layer above has to do after feeding something in.
///
/// At most one message goes out per input, so this is one `Option` rather
/// than a queue: the request, or the ACK, or nothing.
#[derive(Clone, Debug, Default)]
pub(crate) struct Effects {
    /// Hand these bytes to the transport.
    pub send: Option<OwnedMessage>,
    /// Tell the transaction user.
    pub notify: Option<Notify>,
    /// The machine is finished and can be dropped.
    pub terminated: bool,
}

/// What the transaction user is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Notify {
    /// The response just fed in is for the user to see.
    Response,
    /// An ACK arrived that the user has to see. RFC 6026 §8.1 keeps these out
    /// of the machine's hands while it is in `Accepted`.
    Ack,
    /// Nothing came back: timer B or F on a client, timer H on an INVITE
    /// server, which means the ACK never arrived.
    TimedOut,
    /// The transport gave up on the message.
    TransportFailed,
}

impl Effects {
    /// Nothing to send; the user is told this and nothing else.
    pub(crate) fn notify(notify: Notify) -> Self {
        Self {
            notify: Some(notify),
            ..Self::default()
        }
    }

    /// The machine is done and asks for nothing else.
    pub(crate) fn terminated() -> Self {
        Self {
            terminated: true,
            ..Self::default()
        }
    }
}
