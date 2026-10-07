// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a state machine asks for after an input. Shared by all four machines.

use super::super::msg::OwnedMessage;

/// What the layer above has to do after feeding something in.
///
/// At most one message goes out per input, hence an `Option`, not a queue.
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
    /// An ACK the user has to see. RFC 6026 §8.1 keeps these out of the
    /// machine's hands while it is in `Accepted`.
    Ack,
    /// Nothing came back: timer B or F on a client, timer H (no ACK) on an
    /// INVITE server.
    TimedOut,
    /// The transport gave up on the message.
    TransportFailed,
}

impl Effects {
    pub(crate) fn notify(notify: Notify) -> Self {
        Self {
            notify: Some(notify),
            ..Self::default()
        }
    }

    pub(crate) fn terminated() -> Self {
        Self {
            terminated: true,
            ..Self::default()
        }
    }
}
