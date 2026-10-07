// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the endpoint has to tell the layer above.
//!
//! A transaction times out while the caller is busy with something else, so
//! that is reported here, never as an error from an unrelated call. Messages
//! ride whole, so the layer above can read any header it likes.

use std::sync::Arc;

use super::transport::{Host, TransportProtocol};
use crate::auth::DigestAlgorithm;
use crate::msg::{OwnedMessage, StatusCode};
use crate::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteClient, NonInviteServer,
    ProvisionalResponseId, TransactionId,
};

/// Why something the caller asked for did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureReason {
    /// Nothing came back within 64·T1 (timer B or F).
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
/// Reported for every transaction, so the layer above knows when a handle
/// goes stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TerminationReason {
    /// It finished and the retransmission timer has run out.
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
    /// The INVITE was refused, or another fork branch won (§13.2.2.3).
    Refused,
    /// The answer window closed with this branch still early (§13.2.2.4).
    Abandoned,
    /// Nothing came back, or the transport died.
    Failed,
    /// The far end no longer has it: a 481, a 408 or no answer to a request
    /// inside it (§12.2.1.2). No BYE goes out; it would earn the same 481.
    Gone,
    /// What the dialog was carrying is over, and no request says so.
    ///
    /// A subscription ends its dialog without a BYE (RFC 6665 §4.4.1).
    Closed,
}

impl core::fmt::Display for DialogEndReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::LocalBye => "hung up here",
            Self::RemoteBye => "hung up there",
            Self::Refused => "refused",
            Self::Abandoned => "abandoned",
            Self::Failed => "failed",
            Self::Gone => "gone at the far end",
            Self::Closed => "closed",
        })
    }
}

/// Something the layer above has to know about.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Event {
    /// A provisional response opened or advanced an early dialog.
    ///
    /// A forked INVITE produces several, with different dialogs.
    Provisional {
        /// The transaction that sent the INVITE.
        invite: TransactionId<InviteClient>,
        /// The early dialog, if the response had a tag and there was room
        /// ([`super::EndpointConfig::max_dialogs`]).
        dialog: Option<DialogId>,
        /// The status.
        status: StatusCode,
        /// The response, whole.
        response: OwnedMessage,
    },
    /// A provisional response that was sent reliably (RFC 3262).
    ///
    /// Acknowledge it with [`super::Endpoint::prack`]; it may carry an offer.
    /// Retransmissions and out-of-order ones are not reported.
    ReliableProvisional {
        /// The transaction that sent the INVITE.
        invite: TransactionId<InviteClient>,
        /// The dialog it opened or advanced.
        dialog: DialogId,
        /// The handle to acknowledge it by.
        provisional: ProvisionalResponseId,
        /// The status.
        status: StatusCode,
        /// The response, whole.
        response: OwnedMessage,
    },
    /// A 2xx for this dialog. The caller must call
    /// [`super::Endpoint::ack_2xx`].
    ///
    /// Several may follow one INVITE. §13.2.2.4 wants each acknowledged;
    /// which call to keep is the caller's policy.
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
        /// The refusal, whole, when there was one. The core does not follow
        /// a 3xx itself.
        response: Option<OwnedMessage>,
    },
    /// A re-INVITE this end sent got a provisional response (§14.1).
    ///
    /// Rare (§14.2), but a 183 can carry an early answer.
    ReinviteProgress {
        /// The transaction that sent it.
        invite: TransactionId<InviteClient>,
        /// The dialog it is in.
        dialog: DialogId,
        /// The status.
        status: StatusCode,
        /// The handle to acknowledge it by, when it was sent reliably
        /// (RFC 3262 §3).
        provisional: Option<ProvisionalResponseId>,
        /// The response, whole.
        response: OwnedMessage,
    },
    /// A re-INVITE this end sent was accepted. The caller must call
    /// [`super::Endpoint::ack_reinvite`].
    ///
    /// A re-INVITE never forks (§14.1). The remote target is already
    /// refreshed from this response's `Contact`.
    ReinviteAnswered {
        /// The transaction that sent it.
        invite: TransactionId<InviteClient>,
        /// The dialog it renegotiated.
        dialog: DialogId,
        /// The status.
        status: StatusCode,
        /// The response, whole; the offer may be in it.
        response: OwnedMessage,
    },
    /// A re-INVITE this end sent was refused, or will not be answered.
    ///
    /// The session stays as it was (§14.1). The dialog stands unless a
    /// [`Event::DialogTerminated`] follows: a 481, a 408 or no answer
    /// (§12.2.1.2).
    ReinviteFailed {
        /// The transaction that sent it.
        invite: TransactionId<InviteClient>,
        /// The dialog it was sent in.
        dialog: DialogId,
        /// The status, when one arrived.
        status: Option<StatusCode>,
        /// Why.
        reason: FailureReason,
        /// The refusal, whole, when there was one.
        response: Option<OwnedMessage>,
    },
    /// Two re-INVITEs crossed: the far end answered 491 Request Pending
    /// (§14.2), because it had one of its own outstanding when ours arrived.
    ///
    /// Both ends back off from ranges that do not overlap; `retry_in` is
    /// this end's draw. Whether to send again is the caller's (§14.1).
    ReinviteGlare {
        /// The transaction that was refused.
        invite: TransactionId<InviteClient>,
        /// The dialog both INVITEs are in.
        dialog: DialogId,
        /// How long to wait before offering the same change again.
        retry_in: core::time::Duration,
        /// The 491, whole.
        response: OwnedMessage,
    },
    /// A CANCEL that was asked for has gone out.
    ///
    /// It may have waited for the first provisional response (§9.1).
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
    /// A live dialog: the caller acknowledges it and sends a BYE if it
    /// still wants out.
    CancelLostRace {
        /// The INVITE that was being cancelled.
        invite: TransactionId<InviteClient>,
        /// The dialog that connected.
        dialog: DialogId,
    },
    /// Somebody is calling.
    ///
    /// The early dialog already exists, so provisionals can go into it.
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
    /// Only reported when the CANCEL ended the call (§9.2). The 200 and the
    /// 487 are already sent; what is left is to stop ringing. An early
    /// dialog then ends with [`DialogEndReason::Refused`] (§12.3), after the
    /// INVITE transaction if a reliable provisional is still unacknowledged
    /// (RFC 3262 §3).
    IncomingCancel {
        /// The INVITE that was cancelled.
        invite: TransactionId<InviteServer>,
        /// The CANCEL, whole. Its `Reason` (RFC 3326) can say the call was
        /// completed elsewhere, which is not a missed call.
        request: OwnedMessage,
    },
    /// The ACK for a 2xx we sent (§13.2.2.4). The call is up.
    IncomingAck {
        /// The dialog it confirms.
        dialog: DialogId,
        /// The request, whole; the answer to an offer may be in it.
        request: OwnedMessage,
    },
    /// A PRACK acknowledging a reliable provisional response we sent.
    ///
    /// Retransmissions have stopped. The caller answers it, since it may
    /// carry an offer (§3). A refusal under RFC 3261 §8.2 goes through
    /// [`super::Endpoint::refuse_prack`], which keeps the response
    /// unacknowledged.
    IncomingPrack {
        /// The transaction to answer on.
        transaction: TransactionId<NonInviteServer>,
        /// The response it acknowledges.
        provisional: ProvisionalResponseId,
        /// The request, whole.
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
        /// The BYE, whole: a `Reason` in it (RFC 3326) says why.
        request: OwnedMessage,
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
    /// A request was refused with a challenge this stack can answer
    /// (RFC 3261 §22, RFC 8760).
    ///
    /// One per challenge; a request may have to answer both a 401 and a 407.
    /// Answering is the caller's: a wrong password can lock the account.
    Challenged {
        /// The transaction that was refused, and the handle
        /// [`super::Endpoint::retry_with_credentials`] takes.
        transaction: AnyTransactionId,
        /// The protection domain the credentials belong to.
        realm: Arc<str>,
        /// Whether a proxy asked (407) rather than the far end (401).
        proxy: bool,
        /// Which hash it asked for.
        algorithm: DigestAlgorithm,
        /// The nonce was only old; the same credentials are worth resending.
        stale: bool,
    },
    /// A request was refused with a `Bearer` challenge: the server takes an
    /// OAuth 2.0 access token (RFC 8898).
    ///
    /// Answer with [`super::Endpoint::retry_with_credentials`] and
    /// [`crate::auth::Credentials::with_access_token`]. Getting the token is
    /// the caller's; RFC 8898 §2.1.1 has it check the authorization server
    /// first. [`super::Endpoint::token_wanted`] says if a new token is needed.
    TokenChallenged {
        /// The transaction that was refused, and the handle
        /// [`super::Endpoint::retry_with_credentials`] takes.
        transaction: AnyTransactionId,
        /// The challenge: realm, scope, authorization server and error.
        challenge: crate::auth::BearerChallenge,
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
    /// Provisional responses are reported too: a slow registrar sends them.
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
    /// The next hop a dialog names is not the address its requests are going
    /// to (RFC 3261 §12.2.1.1, RFC 3263).
    ///
    /// A dialog keeps its first flow (§8.1.2), which survives a NAT. A caller
    /// with a resolver may answer with [`super::Endpoint::resolved`] to
    /// retarget the dialog; ignoring it is the common choice.
    ResolveNeeded {
        /// The dialog whose next hop this is, and the handle the answer takes.
        dialog: DialogId,
        /// The host to resolve.
        host: Host,
        /// The port, when the URI gave one (else RFC 3263 §4.2).
        port: Option<u16>,
        /// The transport, when the URI or the scheme named one.
        protocol: Option<TransportProtocol>,
    },
    /// A keep-alive went unanswered for ten seconds on a flow that had answered
    /// one before, so RFC 5626 §4.4.1 calls the flow dead and this end has
    /// taken it down.
    ///
    /// Everything on it has failed and the transport is forgotten. The caller
    /// closes the socket and, for a registration, binds a new flow under the
    /// same [`super::TransportId`] (§4.5).
    FlowFailed {
        /// The transport that is gone.
        transport: super::TransportId,
    },
    /// A request was refused because this endpoint is already holding as many
    /// server transactions or dialogs as it is configured to
    /// ([`super::EndpointConfig::max_server_transactions`],
    /// [`super::EndpointConfig::max_dialogs`]).
    ///
    /// A stateless 503 went back (§21.5.4), which beats being retransmitted
    /// at for 32 seconds. The count is cumulative.
    Overloaded {
        /// Requests refused this way since creation.
        refused: u64,
    },
    /// A message is too large for any datagram transport that is open, and
    /// there is no stream transport to move it to.
    ///
    /// RFC 3261 §18.1.1 makes the switch a MUST. The caller opens the
    /// connection and the request goes out once it is bound. The sizes make
    /// a silently dropped fragment explainable.
    TransportWanted {
        /// What to open.
        protocol: TransportProtocol,
        /// Where to.
        destination: std::net::SocketAddr,
        /// The request size on the wire, in bytes.
        request_bytes: usize,
        /// The largest that fits: MTU less the §18.1.1 headroom, 1300 when the
        /// MTU is unknown, zero when it leaves no room
        /// ([`super::DatagramLimit::largest_datagram_request`]).
        limit_bytes: u32,
    },
}

impl Event {
    /// The event's body, if any.
    #[must_use]
    pub fn body(&self) -> Option<Arc<[u8]>> {
        match *self {
            Self::Response { ref response, .. } => {
                let body = response.as_raw().body();
                (!body.is_empty()).then(|| Arc::from(body))
            }
            Self::Provisional { ref response, .. }
            | Self::Established { ref response, .. }
            | Self::ReliableProvisional { ref response, .. }
            | Self::ReinviteProgress { ref response, .. }
            | Self::ReinviteAnswered { ref response, .. } => {
                let body = response.as_raw().body();
                (!body.is_empty()).then(|| Arc::from(body))
            }
            Self::Failed {
                response: Some(ref response),
                ..
            }
            | Self::ReinviteFailed {
                response: Some(ref response),
                ..
            } => {
                let body = response.as_raw().body();
                (!body.is_empty()).then(|| Arc::from(body))
            }
            Self::IncomingOutOfDialog { ref request, .. }
            | Self::IncomingInvite { ref request, .. }
            | Self::IncomingReinvite { ref request, .. }
            | Self::IncomingAck { ref request, .. }
            | Self::IncomingPrack { ref request, .. }
            | Self::IncomingInDialog { ref request, .. } => {
                let body = request.as_raw().body();
                (!body.is_empty()).then(|| Arc::from(body))
            }
            _ => None,
        }
    }
}
