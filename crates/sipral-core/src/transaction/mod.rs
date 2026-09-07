// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The four state machines of RFC 3261 §17, and the names things are held by.
//!
//! A transaction is what makes SIP reliable over an unreliable transport: it
//! retransmits a request until an answer comes, absorbs the retransmissions
//! the other end sends, and decides when there will be no more. Everything
//! here runs on time the caller supplies, so a timer diagram is an ordinary
//! test rather than a wait.
//!
//! Written from RFC 3261 §17 and RFC 6026, which corrects it: a 2xx does not
//! end an INVITE transaction outright, and the `Accepted` state on both INVITE
//! machines is where that correction lives.

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
pub(crate) use matching::ServerKey;
pub(crate) use store::{Client, Server, Transactions};
pub use timer::{TimerConfig, TimerName};
pub(crate) use timer::{TimerHandle, Timers};
