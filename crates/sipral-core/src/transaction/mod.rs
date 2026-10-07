// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The four state machines of RFC 3261 §17, and the handles they are held by.
//!
//! A transaction retransmits a request until an answer comes, absorbs the
//! peer's retransmissions, and decides when there will be no more. All timing
//! comes from the caller, so a timer diagram is an ordinary test.
//!
//! RFC 6026 corrects §17: a 2xx does not end an INVITE transaction outright.
//! The `Accepted` state on both INVITE machines is that correction.

mod ack;
mod cancel;
mod effect;
mod handle;
mod invite_client;
mod invite_server;
mod matching;
mod non_invite_client;
mod non_invite_server;
pub(crate) mod slab;
mod store;
mod timer;

pub(crate) use cancel::{CancelDisposition, cancel_for_request};
pub(crate) use effect::{Effects, Notify};
pub(crate) use handle::Raw;
pub use handle::{
    AnyTransactionId, DialogId, InviteClient, InviteClientState, InviteServer, InviteServerState,
    NonInviteClient, NonInviteClientState, NonInviteServer, NonInviteServerState,
    ProvisionalResponseId, Role, TransactionId, TransactionKind,
};
pub(crate) use store::{Client, Server, Transactions};
pub use timer::{TimerConfig, TimerConfigError, TimerName};
pub(crate) use timer::{TimerHandle, Timers};
