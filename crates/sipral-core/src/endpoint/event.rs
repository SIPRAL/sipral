// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the endpoint has to tell the layer above.
//!
//! An event is never an error return from an unrelated call. A transaction
//! that times out does so while the caller is asking about something else, or
//! about nothing at all, so it is reported here and nowhere else.
//!
//! Messages ride in events as whole `OwnedMessage`s rather than as a struct of
//! the fields the core happens to care about. The layer above reads whatever
//! header it likes, including ones this crate has no opinion about, and the
//! core does not grow a field every time somebody needs one more.

use std::sync::Arc;

use super::transport::TransportProtocol;
use crate::msg::{OwnedMessage, StatusCode};
use crate::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteClient, NonInviteServer,
    TransactionId,
};

/// Why something the caller asked for did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureReason {
    /// Nothing came back within 64·T1: timer B on an INVITE, timer F on
    /// anything else.
    Timeout,
    /// The transport could not deliver.
    TransportFailed,
    /// The far end refused it with a final response of 300 or above.
    Refused,
}

impl core::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Timeout => "no response",
            Self::TransportFailed => "transport failed",
            Self::Refused => "refused",
        })
    }
}

/// Why a transaction is over.
///
/// Reported for every transaction, including the ones that ended the way they
/// were supposed to, so that a layer above can free what it hung on the
/// handle without having to guess when the handle went stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TerminationReason {
    /// It finished: the answer arrived, or was sent and acknowledged, and the
    /// timer that absorbs retransmissions has run out.
    Completed,
    /// Nothing came back within 64·T1.
    TimedOut,
    /// The transport could not deliver.
    TransportFailed,
}

impl core::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Completed => "completed",
            Self::TimedOut => "timed out",
            Self::TransportFailed => "transport failed",
        })
    }
}

/// Why a dialog is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DialogEndReason {
    /// This end sent a BYE.
    LocalBye,
    /// The far end sent one.
    RemoteBye,
    /// The INVITE that would have opened it was refused, or another branch of
    /// the fork won and this one was told so (§13.2.2.3).
    Refused,
    /// The answer window closed with this branch still early (§13.2.2.4).
    Abandoned,
    /// Nothing came back, or the transport died.
    Failed,
}

impl core::fmt::Display for DialogEndReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::LocalBye => "hung up here",
            Self::RemoteBye => "hung up there",
            Self::Refused => "refused",
            Self::Abandoned => "abandoned",
            Self::Failed => "failed",
        })
    }
}

/// Something the layer above has to know about.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Event {
    /// A provisional response opened or advanced an early dialog.
    ///
    /// One INVITE can produce several of these with different dialogs: a
    /// proxy that forked the call is ringing more than one phone.
    Provisional {
        /// The transaction that sent the INVITE.
        invite: TransactionId<InviteClient>,
        /// The early dialog it opened, if it carried a tag to name one by.
        dialog: Option<DialogId>,
        /// The status.
        status: StatusCode,
        /// The response, whole.
        response: OwnedMessage,
    },
    /// A 2xx for this dialog. The caller must call
    /// [`super::Endpoint::ack_2xx`].
    ///
    /// Several of these may follow one INVITE, and the endpoint does not pick
    /// a winner: §13.2.2.4 requires every one of them to be acknowledged, and
    /// which call to keep is policy that does not belong in the core.
    Established {
        /// The transaction that sent the INVITE.
        invite: TransactionId<InviteClient>,
        /// The dialog that is now confirmed.
        dialog: DialogId,
        /// The status.
        status: StatusCode,
        /// The response, whole.
        response: OwnedMessage,
    },
    /// A call this end placed will not connect.
    Failed {
        /// The transaction that sent the INVITE.
        invite: TransactionId<InviteClient>,
        /// The status, when one arrived.
        status: Option<StatusCode>,
        /// Why.
        reason: FailureReason,
    },
    /// A CANCEL that was asked for has gone out.
    ///
    /// It may have been held since before the first provisional response
    /// arrived (§9.1), so this is the first moment the caller can know it is
    /// on the wire.
    CancelSent {
        /// The INVITE being cancelled.
        invite: TransactionId<InviteClient>,
        /// The transaction the CANCEL runs on.
        cancel: TransactionId<NonInviteClient>,
    },
    /// The call was given up on in time: a 487 arrived.
    Cancelled {
        /// The INVITE that was cancelled.
        invite: TransactionId<InviteClient>,
    },
    /// The CANCEL lost the race and the call connected anyway.
    ///
    /// This is a live dialog. The caller acknowledges it and, if it still
    /// wants out, sends a BYE; the endpoint does neither on its own.
    CancelLostRace {
        /// The INVITE that was being cancelled.
        invite: TransactionId<InviteClient>,
        /// The dialog that connected.
        dialog: DialogId,
    },
    /// Somebody is calling.
    ///
    /// The early dialog and the transaction are minted together, so a
    /// provisional response can be sent into a dialog that already exists.
    IncomingInvite {
        /// The transaction to answer on.
        transaction: TransactionId<InviteServer>,
        /// The request, whole.
        request: OwnedMessage,
    },
    /// A re-INVITE inside a dialog: hold, resume, a codec change.
    IncomingReinvite {
        /// The transaction to answer on.
        transaction: TransactionId<InviteServer>,
        /// The dialog it is in.
        dialog: DialogId,
        /// The request, whole.
        request: OwnedMessage,
    },
    /// The caller gave up before we answered.
    ///
    /// The endpoint has already answered the CANCEL with a 200 and the INVITE
    /// with a 487, both of which §9.2 makes unconditional. What is left is to
    /// stop ringing.
    IncomingCancel {
        /// The INVITE that was cancelled.
        invite: TransactionId<InviteServer>,
    },
    /// The ACK for a 2xx we sent (§13.2.2.4). The call is up.
    IncomingAck {
        /// The dialog it confirms.
        dialog: DialogId,
        /// The request, whole; the answer to an offer may be in it.
        request: OwnedMessage,
    },
    /// The far end hung up.
    ///
    /// Answer it on the transaction. The dialog is already terminated here.
    IncomingBye {
        /// The transaction to answer on.
        transaction: TransactionId<NonInviteServer>,
        /// The dialog that has ended.
        dialog: DialogId,
    },
    /// A request inside a dialog that is none of the above: INFO, NOTIFY,
    /// UPDATE, REFER, MESSAGE.
    IncomingInDialog {
        /// The transaction to answer on.
        transaction: TransactionId<NonInviteServer>,
        /// The dialog it is in.
        dialog: DialogId,
        /// The request, whole.
        request: OwnedMessage,
    },
    /// A dialog is over and its handle is about to go stale.
    DialogTerminated {
        /// Which one.
        dialog: DialogId,
        /// Why.
        reason: DialogEndReason,
    },
    /// A final response to a request this endpoint sent.
    ///
    /// Provisional responses are reported too: a 1xx to a non-INVITE request
    /// means the far end is working on it, and a registrar that sends one is
    /// saying the registration is not refused, only slow.
    Response {
        /// The transaction that sent the request.
        transaction: TransactionId<NonInviteClient>,
        /// The status of the response.
        status: StatusCode,
        /// The response, whole.
        response: OwnedMessage,
    },
    /// A request this endpoint sent will not be answered.
    RequestFailed {
        /// The transaction that sent it.
        transaction: TransactionId<NonInviteClient>,
        /// Why.
        reason: FailureReason,
    },
    /// A request arrived that belongs to no dialog: OPTIONS, MESSAGE, a
    /// NOTIFY that starts a subscription, anything else the far end sends
    /// out of the blue. Answer it with [`super::Endpoint::respond`].
    IncomingOutOfDialog {
        /// The server transaction it created.
        transaction: TransactionId<NonInviteServer>,
        /// The request, whole.
        request: OwnedMessage,
    },
    /// A transaction is over and its handle is about to go stale.
    TransactionTerminated {
        /// Which one.
        transaction: AnyTransactionId,
        /// How it ended.
        reason: TerminationReason,
    },
    /// A message is too large for any datagram transport that is open, and
    /// there is no stream transport to move it to.
    ///
    /// RFC 3261 §18.1.1 makes the switch a MUST, so the endpoint cannot send
    /// it as it is; opening a connection is the caller's to do, and once it
    /// is bound the request goes out on it.
    TransportWanted {
        /// What to open.
        protocol: TransportProtocol,
        /// Where to.
        destination: std::net::SocketAddr,
    },
}

impl Event {
    /// The body carried by an event that has one, for a caller that only
    /// wants the SDP.
    #[must_use]
    pub fn body(&self) -> Option<Arc<[u8]>> {
        match *self {
            Self::Response { ref response, .. } => {
                let body = response.as_raw().body();
                (!body.is_empty()).then(|| Arc::from(body))
            }
            Self::Provisional { ref response, .. } | Self::Established { ref response, .. } => {
                let body = response.as_raw().body();
                (!body.is_empty()).then(|| Arc::from(body))
            }
            Self::IncomingOutOfDialog { ref request, .. }
            | Self::IncomingInvite { ref request, .. }
            | Self::IncomingReinvite { ref request, .. }
            | Self::IncomingAck { ref request, .. }
            | Self::IncomingInDialog { ref request, .. } => {
                let body = request.as_raw().body();
                (!body.is_empty()).then(|| Arc::from(body))
            }
            _ => None,
        }
    }
}
