// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
    /// The far end no longer has it: a 481 or a 408 to a request sent inside
    /// it, or no answer at all (§12.2.1.2). No BYE goes out — the peer has
    /// just said there is no such dialog, and a BYE would earn the same 481.
    Gone,
    /// What the dialog was carrying is over, and no request says so.
    ///
    /// A subscription is the case: RFC 6665 §4.4.1 makes "the destruction of a
    /// subscription result in the termination of its associated dialog", and
    /// there is no BYE for one — the closing NOTIFY has already been answered
    /// by the time this is true.
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
    /// One INVITE can produce several of these with different dialogs: a
    /// proxy that forked the call is ringing more than one phone.
    Provisional {
        /// The transaction that sent the INVITE.
        invite: TransactionId<InviteClient>,
        /// The early dialog it opened, if it carried a tag to name one by and
        /// there was room for another branch
        /// ([`super::EndpointConfig::max_dialogs`]).
        dialog: Option<DialogId>,
        /// The status.
        status: StatusCode,
        /// The response, whole.
        response: OwnedMessage,
    },
    /// A provisional response that was sent reliably (RFC 3262).
    ///
    /// It has to be acknowledged with [`super::Endpoint::prack`], and it may
    /// carry an offer that the PRACK has to answer. Retransmissions of it are
    /// discarded here rather than reported twice, and one that arrives out of
    /// order is not reported at all.
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
        /// The refusal, whole, when there was one. A 3xx names where to try
        /// instead and a 4xx may carry a `Warning` or a `Retry-After`; none of
        /// that survives being reduced to a number, and this is a core that
        /// does not follow redirects on the caller's behalf.
        response: Option<OwnedMessage>,
    },
    /// A re-INVITE this end sent got a provisional response (§14.1).
    ///
    /// Rare — §14.2 says a UAS "MAY choose not to generate 180 (Ringing)
    /// responses for a re-INVITE" — and reported rather than swallowed,
    /// because a 183 to a re-INVITE can carry an early answer.
    ReinviteProgress {
        /// The transaction that sent it.
        invite: TransactionId<InviteClient>,
        /// The dialog it is in.
        dialog: DialogId,
        /// The status.
        status: StatusCode,
        /// The handle to acknowledge it by, when the response asked to be
        /// sent reliably (RFC 3262 §3 puts a re-INVITE's provisionals in
        /// scope exactly like an initial INVITE's).
        provisional: Option<ProvisionalResponseId>,
        /// The response, whole.
        response: OwnedMessage,
    },
    /// A re-INVITE this end sent was accepted. The caller must call
    /// [`super::Endpoint::ack_reinvite`].
    ///
    /// The dialog is the one it was sent in — a re-INVITE never forks
    /// (§14.1) — and its remote target has already been refreshed from the
    /// `Contact` of this response.
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
    /// §14.1: "the session parameters MUST remain unchanged, as if no
    /// re-INVITE had been issued". The dialog stands unless a
    /// [`Event::DialogTerminated`] follows, which it does for the three cases
    /// §12.2.1.2 names: a 481, a 408, and nothing at all.
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
    /// Both ends are about to back off, from ranges that do not overlap, so
    /// that they do not collide a second time. `retry_in` is this end's draw.
    /// Sending it again is the caller's decision — the session may no longer
    /// need changing, and §14.1 says as much: "if it still desires for that
    /// session modification to take place".
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
    /// Only reported when the CANCEL ended the call. One that crosses a final
    /// response this end has already sent changes nothing (§9.2): it gets its
    /// 200, and nothing is reported.
    ///
    /// The endpoint has already answered the CANCEL with a 200 and the INVITE
    /// with a 487, both of which §9.2 makes unconditional. What is left is to
    /// stop ringing. When a provisional response had opened an early dialog,
    /// a [`Event::DialogTerminated`] with [`DialogEndReason::Refused`] follows
    /// this event: §12.3 ends that dialog with the 487. While a reliable
    /// provisional response of that INVITE is still unacknowledged it follows
    /// the end of the INVITE transaction instead, because RFC 3262 §3 still
    /// answers a PRACK for it.
    IncomingCancel {
        /// The INVITE that was cancelled.
        invite: TransactionId<InviteServer>,
        /// The CANCEL, whole: a `Reason` in it (RFC 3326) says why, and a
        /// forking proxy's "call completed elsewhere" is the one a phone
        /// should not show as a missed call.
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
    /// Retransmissions of that response have already stopped. §3 makes
    /// answering it 2xx a MUST, and the answer is the caller's because a PRACK
    /// may carry an offer that the 2xx has to answer. One the caller refuses
    /// under RFC 3261 §8.2 — a 420, a 415, a 488 to its offer — goes through
    /// [`super::Endpoint::refuse_prack`], which puts the response back on the
    /// list of unacknowledged ones for the retry to find.
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
    /// One per challenge: a 401 and a 407 are separate protection domains and
    /// a request may have to answer both. Whether to answer at all is the
    /// caller's, because it needs a password and because answering with the
    /// wrong one is how an account gets locked.
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
        /// Whether the server said only that the nonce was old, which means
        /// the same credentials are worth sending again.
        stale: bool,
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
    /// The next hop a dialog names is not the address its requests are going
    /// to (RFC 3261 §12.2.1.1, RFC 3263).
    ///
    /// A dialog keeps the flow its first message travelled on, which §8.1.2
    /// explicitly allows as "an alternate address" and which is the only thing
    /// that survives a NAT. This says what the route set and the target
    /// actually name, for a caller with a resolver; answering it with
    /// [`super::Endpoint::resolved`] retargets the dialog, and ignoring it is
    /// a legitimate choice and the common one.
    ResolveNeeded {
        /// The dialog whose next hop this is, and the handle the answer takes.
        dialog: DialogId,
        /// The host to resolve.
        host: Host,
        /// The port, when the URI gave one. `None` leaves the choice to
        /// RFC 3263 §4.2, which is the caller's to make.
        port: Option<u16>,
        /// The transport, when the URI or the scheme named one.
        protocol: Option<TransportProtocol>,
    },
    /// A keep-alive went unanswered for ten seconds on a flow that had answered
    /// one before, so RFC 5626 §4.4.1 calls the flow dead and this end has
    /// taken it down.
    ///
    /// Everything running on it has already been failed, and the endpoint has
    /// forgotten the transport. What is left is the caller's: close the socket,
    /// and open a replacement if the flow was carrying a registration — §4.5
    /// wants a new flow rather than a retry on the old one. Binding the
    /// replacement under the same [`super::TransportId`] is what puts the
    /// account back where it was.
    FlowFailed {
        /// The transport that is gone.
        transport: super::TransportId,
    },
    /// A request was refused because this endpoint is already holding as many
    /// server transactions or dialogs as it is configured to
    /// ([`super::EndpointConfig::max_server_transactions`],
    /// [`super::EndpointConfig::max_dialogs`]).
    ///
    /// A 503 has gone back statelessly — §21.5.4 is the code for "temporarily
    /// unable to process the request due to a temporary overloading" — because
    /// refusing where the far end can see it beats dropping the request and
    /// being retransmitted at for thirty-two seconds. The count is cumulative,
    /// so an operator watching it climb is watching either a flood or a ceiling
    /// set too low.
    Overloaded {
        /// How many requests this endpoint has refused this way since it was
        /// created.
        refused: u64,
    },
    /// A message is too large for any datagram transport that is open, and
    /// there is no stream transport to move it to.
    ///
    /// RFC 3261 §18.1.1 makes the switch a MUST, so the endpoint cannot send
    /// it as it is; opening a connection is the caller's to do, and once it
    /// is bound the request goes out on it.
    ///
    /// Both sizes are here because a request that fragments and is dropped by
    /// a NAT looks from above like nothing happening at all: six
    /// retransmissions, thirty-two seconds, no error. The two numbers are what
    /// turn that into a sentence — "request 1785 bytes, limit 1299" — and
    /// nothing else in the stack says them.
    TransportWanted {
        /// What to open.
        protocol: TransportProtocol,
        /// Where to.
        destination: std::net::SocketAddr,
        /// How large the request came out, in bytes as they would have gone on
        /// the wire.
        request_bytes: usize,
        /// The largest it could have been and still fitted: the path MTU less
        /// the §18.1.1 headroom where the MTU is known, 1300 where it is not,
        /// and zero where the configured MTU leaves room for nothing
        /// ([`super::DatagramLimit::largest_datagram_request`]).
        limit_bytes: u32,
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
