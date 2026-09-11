// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A call, which is not the same thing as a `Call-ID` and not the same thing
//! as a dialog.
//!
//! One INVITE can be forked by a proxy to a desk phone, a mobile and a
//! voicemail box. Three phones ring, three early dialogs open, and every one
//! that answers has to be acknowledged — §13.2.2.4 makes that a MUST, and a
//! stack that acknowledges only the first leaves a call standing at the other
//! end for as long as the far side keeps retransmitting.
//!
//! So a [`CallHandle`] names one dialog rather than one attempt. Placing a
//! call mints one, the first early dialog adopts it, and each further one
//! arrives as a sibling under [`crate::UaEvent::CallForked`]. What happens to
//! the siblings is [`ForkPolicy`], and the default is what a telephone does:
//! keep the first that answers, acknowledge the rest and hang them up.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::dialog::CallId;
use sipral_core::endpoint::TransportId;
use sipral_core::msg::{HeaderName, Method, OwnedMessage, StatusCode, Uri};
use sipral_core::sdp::SessionDescription;
use sipral_core::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, ProvisionalResponseId, TransactionId,
};

use crate::account::{AccountId, Extra};
use crate::reliable::Unacknowledged;
use crate::session::Session;
use crate::timers::SessionTimer;
use crate::transfer::{ReferSubscription, ReferTo, Referred};

/// One call the application is talking to.
///
/// Minted when a call is placed or arrives, and again for every branch of a
/// fork. Never reused, so a handle to a call that has ended names nothing
/// rather than naming somebody else's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallHandle(pub(crate) u32);

/// Which end placed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// This end dialled.
    Outgoing,
    /// The far end dialled.
    Incoming,
}

/// Where a call is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CallState {
    /// The INVITE has gone and nothing has come back.
    Calling,
    /// Somebody is calling and this end has not answered.
    Incoming,
    /// The far end is ringing, or this end said it is.
    Ringing,
    /// A provisional response carried a session description: there is audio
    /// before anybody answers, which is how a network announcement reaches a
    /// caller.
    EarlyMedia,
    /// Up.
    Confirmed,
    /// Up, and up in order to be transferred: the second leg of an attended
    /// transfer, placed with [`crate::UserAgent::consult`] from a call that is
    /// waiting for it.
    ///
    /// A confirmed dialog in every protocol sense — it is held, hung up and
    /// renegotiated like any other — and a separate state because the
    /// difference is what the call is for. An attended transfer needs a
    /// consultation call and a call to hand over, and a stack that does not
    /// name which is which leaves the application to remember, in the middle of
    /// a three-party operation where getting it the wrong way round hands the
    /// wrong person to the wrong person.
    Consulting,
    /// A CANCEL or a BYE has gone and the call is not over until it is
    /// answered.
    Terminating,
    /// Over. The handle is about to go stale.
    Terminated,
}

impl CallState {
    /// Whether the call is up, whatever it is up for.
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        matches!(self, Self::Confirmed | Self::Consulting)
    }

    /// Whether it is still being set up, in either direction.
    #[must_use]
    pub const fn is_early(self) -> bool {
        matches!(
            self,
            Self::Calling | Self::Incoming | Self::Ringing | Self::EarlyMedia
        )
    }
}

impl core::fmt::Display for CallState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Calling => "calling",
            Self::Incoming => "incoming",
            Self::Ringing => "ringing",
            Self::EarlyMedia => "early media",
            Self::Confirmed => "confirmed",
            Self::Consulting => "consulting",
            Self::Terminating => "terminating",
            Self::Terminated => "terminated",
        })
    }
}

/// What to do with the branches of a fork that this end is not keeping.
///
/// Both of them acknowledge every 2xx, because §13.2.2.4 does not make that
/// optional. The choice is only about what happens next.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ForkPolicy {
    /// Keep the first branch that answers and hang up every later one with a
    /// BYE. What a telephone does, and the default.
    #[default]
    KeepFirst,
    /// Keep all of them. A conference bridge, a recorder, or anything that
    /// wants both legs of a fork has to say so, because hanging one up is not
    /// something that can be undone.
    KeepAll,
}

/// Why a call is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CallEndReason {
    /// This end hung up.
    LocalHangup,
    /// The far end hung up.
    RemoteHangup,
    /// The far end refused it: busy, declined, not found.
    Refused,
    /// Given up before it was answered, from either end.
    Cancelled,
    /// Nothing came back, or the transport died.
    Unreachable,
    /// Another branch of the same fork was kept and this one was not
    /// ([`ForkPolicy::KeepFirst`]).
    ForkLost,
    /// The branch was still ringing when the answer window closed
    /// (§13.2.2.4), or the proxy told it another branch had won.
    Abandoned,
    /// The session timer ran out and no refresh arrived (RFC 4028 §10). The
    /// far end is not there any more, whatever it thinks.
    Expired,
}

/// A refusal that arrived with a challenge, kept until the drain is over.
///
/// The core reports that the request failed before it reports that the failure
/// is answerable, and both arrive in the same drain. Acting on the first would
/// tear the call down and leave nothing for the second to retry, which is what
/// a PBX challenging an INVITE used to get. Registrations park a 401 the same
/// way and for the same reason.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) reason: CallEndReason,
    pub(crate) status: Option<StatusCode>,
    pub(crate) response: Option<OwnedMessage>,
    /// The retry is built and the endpoint is holding it until there is a
    /// connection to send it over (RFC 3261 §18.1.1). Until then this is not
    /// a refusal, and the settle pass leaves it alone.
    pub(crate) waiting_for_stream: bool,
}

/// The same, for a request sent inside a call rather than the INVITE that
/// opened it.
///
/// A separate record because what it has to know is different: which call,
/// and which method — a BYE that never goes and a REFER that never goes
/// leave different things behind. Both are kept here rather than looked up
/// when the time comes, because the maps that hold them are swept when the
/// transaction retires and that happens first.
#[derive(Debug)]
pub(crate) struct RequestRefusal {
    pub(crate) call: CallHandle,
    pub(crate) method: Method<'static>,
    pub(crate) status: Option<StatusCode>,
    pub(crate) waiting_for_stream: bool,
}

impl core::fmt::Display for CallEndReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::LocalHangup => "hung up here",
            Self::RemoteHangup => "hung up there",
            Self::Refused => "refused",
            Self::Cancelled => "cancelled",
            Self::Unreachable => "unreachable",
            Self::ForkLost => "another branch was kept",
            Self::Abandoned => "abandoned",
            Self::Expired => "the session expired",
        })
    }
}

/// A call the application wants placed.
#[derive(Clone, Debug)]
pub struct OutgoingCall {
    pub(crate) target: Uri,
    pub(crate) offer: Option<Arc<[u8]>>,
    pub(crate) destination: Option<(TransportId, SocketAddr)>,
    pub(crate) forks: ForkPolicy,
    pub(crate) extra: Vec<Extra>,
}

impl OutgoingCall {
    /// A call to `target`.
    ///
    /// It leaves on the account's transport, for the address the account
    /// registers with — which is the outbound proxy for a registered line, and
    /// the reason a softphone behind a NAT works at all. Somewhere else needs
    /// [`OutgoingCall::to_address`].
    #[must_use]
    pub const fn new(target: Uri) -> Self {
        Self {
            target,
            offer: None,
            destination: None,
            forks: ForkPolicy::KeepFirst,
            extra: Vec::new(),
        }
    }

    /// The session description to offer.
    ///
    /// Left out, the INVITE carries none and the offer arrives in the 2xx
    /// instead (§14.1). The answer to it then has to travel in the ACK, which
    /// is why a call placed that way is not acknowledged until
    /// [`crate::UserAgent::acknowledge`] is called.
    #[must_use]
    pub fn offer(mut self, sdp: Arc<[u8]>) -> Self {
        self.offer = Some(sdp);
        self
    }

    /// Send it somewhere other than where the account registers.
    ///
    /// Resolving a name is the caller's, here as everywhere: this takes the
    /// answer, not the question.
    #[must_use]
    pub const fn to_address(mut self, transport: TransportId, remote: SocketAddr) -> Self {
        self.destination = Some((transport, remote));
        self
    }

    /// What to do with the branches of a fork that are not kept.
    #[must_use]
    pub const fn forks(mut self, policy: ForkPolicy) -> Self {
        self.forks = policy;
        self
    }

    /// A header field on the INVITE.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'_>, value: &[u8]) -> Self {
        self.extra.push(Extra {
            name: Box::from(name.canonical().as_bytes()),
            value: Box::from(value),
        });
        self
    }
}

/// Everything one call is doing.
#[derive(Debug)]
pub(crate) struct Call {
    pub(crate) account: Option<AccountId>,
    pub(crate) direction: Direction,
    pub(crate) state: CallState,
    /// The INVITE this end sent, while its transaction is running.
    pub(crate) invite: Option<TransactionId<InviteClient>>,
    /// The INVITE the far end sent, while this end has not finally answered.
    pub(crate) server: Option<TransactionId<InviteServer>>,
    /// The dialog, once there is one.
    pub(crate) dialog: Option<DialogId>,
    /// What to do with the siblings this branch may acquire.
    pub(crate) forks: ForkPolicy,
    /// Whether the 2xx has been acknowledged.
    pub(crate) acknowledged: bool,
    /// A hangup was asked for and could not go yet: a CANCEL may not leave
    /// before the first provisional response (§9.1), and the endpoint holds it
    /// for us, but a call that has not even opened a dialog has nothing to
    /// cancel.
    pub(crate) hangup_wanted: bool,
    /// `Contact`, kept because every request inside the dialog needs it and a
    /// re-INVITE carries it again to refresh the target.
    pub(crate) contact: Box<[u8]>,
    /// Where this call's signalling travels: the far end, or the proxy that
    /// carries the line. It is what an INVITE naming this call in a
    /// `Replaces` is measured against (RFC 3891 §3).
    ///
    /// Written once, when the call is placed or arrives, and not refreshed
    /// afterwards. A far end that moves leaves it stale, which refuses a
    /// replacement rather than admitting one. `None` when the transport
    /// never said where the bytes came from, which is a byte stream bound
    /// without naming its far end.
    pub(crate) peer: Option<SocketAddr>,
    /// The branch this one was forked from, for the events that say so.
    pub(crate) forked_from: Option<CallHandle>,
    /// What each end has described, and which way it is held.
    pub(crate) session: Session,
    /// Whether the far end listed UPDATE in an `Allow` (RFC 3311 §4).
    pub(crate) update_allowed: bool,
    /// The session change this end has in flight, or is waiting to try again.
    pub(crate) offering: Option<Offer>,
    /// One the far end offered that only the application can answer.
    pub(crate) answering: Option<Answering>,
    /// A 2xx this end sent whose ACK has not arrived. §13.3.1.4 has the dialog
    /// ended with a BYE when it never does, and the transaction running out is
    /// the only moment that can be known.
    pub(crate) awaiting_ack: Option<TransactionId<InviteServer>>,
    /// When to offer the change again after a 491 (§14.1, RFC 3311 §5.3).
    pub(crate) retry_at: Option<Instant>,
    /// The session timer, once one has been negotiated (RFC 4028).
    pub(crate) timer: Option<SessionTimer>,
    /// A reliable provisional response this end sent and is still owed a
    /// PRACK for (RFC 3262 §3).
    pub(crate) unacknowledged: Option<Unacknowledged>,
    /// One that arrived carrying an offer, whose answer §5 puts in the PRACK
    /// and which only the application has.
    pub(crate) owed_prack: Option<ProvisionalResponseId>,
    /// The REFER this end sent, while its transaction is unanswered: the
    /// call's one seat for asking, given back when the far end has said yes
    /// or no.
    pub(crate) referring: Option<AnyTransactionId>,
    /// The implicit subscription that REFER opened (RFC 3515 §2, §2.4.4),
    /// which outlives the transaction and is the only thing that makes a
    /// NOTIFY of the `refer` package in this dialog ours to act on.
    pub(crate) refer_subscription: Option<ReferSubscription>,
    /// One this end received.
    pub(crate) referred: Option<Referred>,
    /// What that REFER asked for, until the application says yes or no.
    pub(crate) asked_to_refer: Option<ReferTo>,
    /// The call whose transfer this one is reporting on, for a call placed
    /// because of a REFER.
    pub(crate) reporting_to: Option<CallHandle>,
    /// The call this one replaces, once it is answered (RFC 3891 §3).
    pub(crate) replaces: Option<CallHandle>,
    /// The call this one was placed to consult about, for the second leg of an
    /// attended transfer. It is what makes the state `Consulting` when the
    /// answer arrives, and what `transfer_to` reads to know the two legs
    /// belong together.
    pub(crate) consulting_for: Option<CallHandle>,
    /// And the other way round: the consultation call placed from this one,
    /// while it is live.
    pub(crate) consulting: Option<CallHandle>,
    /// What was dialled, kept so that a 422 can be answered by asking again
    /// with the interval the far end demanded (RFC 4028 §7.3).
    pub(crate) placed: Option<OutgoingCall>,
    /// And what arrived, for a call that came in: the answer to it has to
    /// know what the INVITE asked for, and it is written later than this.
    pub(crate) invited: Option<OwnedMessage>,
    /// The `Call-ID` of this end's INVITE, and the number it used. §7.3 has
    /// the retry keep the first and move the second.
    pub(crate) id: Option<CallId>,
    pub(crate) cseq: u32,
    /// The interval this end asked for, which is what §7.2 falls back to when
    /// the far end answers without saying anything about timers.
    pub(crate) asked: Option<Duration>,
}

/// A session change this end has offered.
#[derive(Debug)]
pub(crate) struct Offer {
    /// The transaction carrying it — a re-INVITE or an UPDATE — while there
    /// is one. Absent between a 491 and the retry it asks for.
    pub(crate) transaction: Option<AnyTransactionId>,
    /// What was offered, kept for that retry and for the moment it is taken.
    /// Absent for a session-timer refresh over UPDATE, which carries none.
    pub(crate) description: Option<SessionDescription>,
    /// The hold this change asks for.
    pub(crate) held: bool,
    /// §14.1 says to attempt it once more, not to keep attempting it.
    pub(crate) retried: bool,
    /// Whether this is a session-timer refresh rather than a change: the
    /// session stays exactly as it is, and only the clock moves.
    pub(crate) refresh: bool,
}

/// One the far end offered, waiting for the application to answer it.
#[derive(Debug)]
pub(crate) struct Answering {
    /// The transaction to answer on.
    pub(crate) transaction: AnyTransactionId,
    /// The offer, when it was a session description this stack could read.
    pub(crate) offer: Option<SessionDescription>,
}

impl Call {
    /// What "up" means for this one: an ordinary call, or the leg an attended
    /// transfer was placed to build.
    pub(crate) const fn up(&self) -> CallState {
        if self.consulting_for.is_some() {
            CallState::Consulting
        } else {
            CallState::Confirmed
        }
    }

    pub(crate) fn outgoing(account: AccountId, forks: ForkPolicy, contact: Box<[u8]>) -> Self {
        Self {
            account: Some(account),
            direction: Direction::Outgoing,
            state: CallState::Calling,
            invite: None,
            server: None,
            dialog: None,
            forks,
            acknowledged: false,
            hangup_wanted: false,
            contact,
            peer: None,
            forked_from: None,
            session: Session::default(),
            update_allowed: false,
            offering: None,
            answering: None,
            awaiting_ack: None,
            retry_at: None,
            timer: None,
            unacknowledged: None,
            owed_prack: None,
            referring: None,
            refer_subscription: None,
            referred: None,
            asked_to_refer: None,
            reporting_to: None,
            replaces: None,
            consulting_for: None,
            consulting: None,
            placed: None,
            invited: None,
            id: None,
            cseq: 1,
            asked: None,
        }
    }

    pub(crate) fn incoming(
        account: Option<AccountId>,
        server: TransactionId<InviteServer>,
        contact: Box<[u8]>,
    ) -> Self {
        Self {
            account,
            direction: Direction::Incoming,
            state: CallState::Incoming,
            invite: None,
            server: Some(server),
            dialog: None,
            forks: ForkPolicy::KeepFirst,
            acknowledged: false,
            hangup_wanted: false,
            contact,
            peer: None,
            forked_from: None,
            session: Session::default(),
            update_allowed: false,
            offering: None,
            answering: None,
            awaiting_ack: None,
            retry_at: None,
            timer: None,
            unacknowledged: None,
            owed_prack: None,
            referring: None,
            refer_subscription: None,
            referred: None,
            asked_to_refer: None,
            reporting_to: None,
            replaces: None,
            consulting_for: None,
            consulting: None,
            placed: None,
            invited: None,
            id: None,
            cseq: 1,
            asked: None,
        }
    }

    /// A branch of the same fork, sharing everything but its dialog.
    pub(crate) fn sibling_of(other: &Self, forked_from: CallHandle) -> Self {
        Self {
            account: other.account,
            direction: other.direction,
            state: CallState::Calling,
            invite: other.invite,
            server: None,
            dialog: None,
            forks: other.forks,
            acknowledged: false,
            hangup_wanted: false,
            contact: other.contact.clone(),
            // the branches of one fork all answer the same far end
            peer: other.peer,
            forked_from: Some(forked_from),
            // the branches of one fork were all offered the same thing
            session: other.session.clone(),
            update_allowed: other.update_allowed,
            offering: None,
            answering: None,
            awaiting_ack: None,
            retry_at: None,
            timer: None,
            unacknowledged: None,
            owed_prack: None,
            referring: None,
            refer_subscription: None,
            referred: None,
            asked_to_refer: None,
            reporting_to: None,
            replaces: None,
            consulting_for: None,
            consulting: None,
            placed: None,
            invited: None,
            id: None,
            cseq: 1,
            asked: None,
        }
    }
}
