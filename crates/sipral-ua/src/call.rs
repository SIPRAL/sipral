// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call: one dialog, not one `Call-ID`.
//!
//! A forked INVITE opens several early dialogs, and every 2xx must be
//! acknowledged (§13.2.2.4). So a [`CallHandle`] names one dialog: the first
//! early dialog adopts the placed call's handle, and each further one arrives
//! as a sibling under [`crate::UaEvent::CallForked`]. [`ForkPolicy`] decides
//! what happens to the siblings; the default keeps the first that answers.

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
use crate::redirect::Redirection;
use crate::reliable::Unacknowledged;
use crate::session::Session;
use crate::timers::SessionTimer;
use crate::transfer::{ReferSubscription, ReferTo, Referred};

/// One call the application is talking to.
///
/// Minted when a call is placed or arrives, and for every fork branch. Never
/// reused: a handle to an ended call names nothing.
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
    /// A provisional response carried a session description: audio before
    /// the answer.
    EarlyMedia,
    /// Up.
    Confirmed,
    /// Up, as the second leg of an attended transfer placed with
    /// [`crate::UserAgent::consult`]. Behaves like `Confirmed` in every
    /// protocol sense; the state only says which leg is which.
    Consulting,
    /// A CANCEL or a BYE has gone and awaits its answer.
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
/// Both acknowledge every 2xx (§13.2.2.4); they differ in what happens next.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ForkPolicy {
    /// Keep the first branch that answers, the placed call or a sibling. The
    /// branches still ringing end with [`CallEndReason::ForkLost`] after the
    /// kept one's [`crate::UaEvent::CallConfirmed`]; a later 2xx from any
    /// branch is acknowledged and hung up with no event. A kept sibling
    /// inherits the placed call's transfer or consultation. The default.
    #[default]
    KeepFirst,
    /// Keep all of them, for a bridge or recorder that wants every leg.
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
    /// Another branch answered first and was kept ([`ForkPolicy::KeepFirst`]);
    /// the call carries on under that branch's handle.
    ForkLost,
    /// Still ringing when the answer window closed (§13.2.2.4), or the proxy
    /// said another branch won.
    Abandoned,
    /// The session timer ran out with no refresh (RFC 4028 §10).
    Expired,
}

/// A refusal that arrived with a challenge, kept until the drain is over.
///
/// The core reports the failure before the challenge, in the same drain;
/// acting on the first would leave nothing to retry.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) reason: CallEndReason,
    pub(crate) status: Option<StatusCode>,
    pub(crate) response: Option<OwnedMessage>,
    /// The endpoint holds the retry until a connection exists (RFC 3261
    /// §18.1.1); the settle pass leaves it alone.
    pub(crate) waiting_for_stream: bool,
}

/// The same, for a request inside a call. Call and method are kept here
/// because the maps holding them are swept when the transaction retires.
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
    pub(crate) focus: bool,
    /// Written recording metadata ([`OutgoingCall::recording_session`]).
    pub(crate) metadata: Option<Arc<str>>,
    pub(crate) follow_redirects: bool,
}

impl OutgoingCall {
    /// A call to `target`.
    ///
    /// It goes on the account's transport to the account's address: the
    /// registrar or outbound proxy, or for an unregistered account its given
    /// proxy ([`crate::Account::unregistered`]). Use
    /// [`OutgoingCall::to_address`] for anywhere else.
    #[must_use]
    pub const fn new(target: Uri) -> Self {
        Self {
            target,
            offer: None,
            destination: None,
            forks: ForkPolicy::KeepFirst,
            extra: Vec::new(),
            focus: false,
            metadata: None,
            follow_redirects: false,
        }
    }

    /// Place it as a conference's focus: every `Contact` of the call carries
    /// `isfocus` (RFC 4579 §4.2).
    #[must_use]
    pub const fn focus(mut self) -> Self {
        self.focus = true;
        self
    }

    /// Place it as a recording session (RFC 7866 §6.1) to the recording
    /// server at the target, with `metadata` describing what is recorded.
    ///
    /// The INVITE carries `Require: siprec` and a `Contact` with `+sip.src`,
    /// and its body is `multipart/mixed`: the offer (which must be set with
    /// [`OutgoingCall::offer`], sendonly, one `a=label` per recorded stream)
    /// and the metadata, `Content-Disposition: recording-session` (§9.1).
    ///
    /// # Errors
    /// [`UaError::Recording`](crate::UaError::Recording) for metadata that cannot be written.
    pub fn recording_session(
        mut self,
        metadata: &crate::siprec::RecordingMetadata,
    ) -> Result<Self, crate::UaError> {
        let written = metadata.to_xml().map_err(crate::UaError::Recording)?;
        self.metadata = Some(Arc::from(written));
        Ok(self)
    }

    /// The feature parameters the call's `Contact` carries (RFC 3840 §9).
    pub(crate) fn contact_features(&self) -> Box<[u8]> {
        let mut features = Vec::new();
        if self.focus {
            features.extend_from_slice(b";isfocus");
        }
        if self.metadata.is_some() {
            features.extend_from_slice(b";");
            features.extend_from_slice(crate::siprec::SRC_FEATURE_TAG.as_bytes());
        }
        features.into_boxed_slice()
    }

    /// The session description to offer.
    ///
    /// Left out, the offer arrives in the 2xx (§14.1) and the answer goes in
    /// the ACK, sent by [`crate::UserAgent::acknowledge`].
    #[must_use]
    pub fn offer(mut self, sdp: Arc<[u8]>) -> Self {
        self.offer = Some(sdp);
        self
    }

    /// Send it to an already resolved address other than the account's.
    #[must_use]
    pub const fn to_address(mut self, transport: TransportId, remote: SocketAddr) -> Self {
        self.destination = Some((transport, remote));
        self
    }

    /// Follow a 3xx to the targets it names (RFC 3261 §8.1.3.4): each as a
    /// new INVITE of the same call, most preferred first, the next one tried
    /// when one refuses.
    ///
    /// Off by default: a 3xx then ends the call, reported with its status and
    /// `Contact` addresses for the application to handle.
    #[must_use]
    pub const fn follow_redirects(mut self) -> Self {
        self.follow_redirects = true;
        self
    }

    /// What to do with the branches of a fork that are not kept.
    #[must_use]
    pub const fn forks(mut self, policy: ForkPolicy) -> Self {
        self.forks = policy;
        self
    }

    /// A header field on the INVITE, checked when the call is placed
    /// ([`crate::HeadersFor::Call`]).
    #[must_use]
    pub fn header(mut self, name: HeaderName<'_>, value: &[u8]) -> Self {
        self.extra.push(Extra {
            name: Box::from(name.canonical().as_bytes()),
            value: Box::from(value),
        });
        self
    }
}

/// [`OutgoingCall`] without target and offer: destination, fork policy and
/// header fields.
///
/// [`UserAgent::accept_transfer`](crate::UserAgent::accept_transfer) takes
/// this because the REFER already names the target.
#[derive(Clone, Copy, Debug, Default)]
pub struct OutgoingExtras<'a> {
    /// As [`OutgoingCall::to_address`].
    pub destination: Option<(TransportId, SocketAddr)>,
    /// As [`OutgoingCall::forks`].
    pub forks: ForkPolicy,
    /// As [`OutgoingCall::header`], already parsed into fields.
    pub headers: &'a [(HeaderName<'a>, &'a [u8])],
}

/// Everything one call is doing.
#[derive(Debug)]
pub(crate) struct Call {
    pub(crate) account: Option<AccountId>,
    pub(crate) direction: Direction,
    pub(crate) state: CallState,
    /// The INVITE this end sent, while its transaction is running.
    pub(crate) invite: Option<TransactionId<InviteClient>>,
    /// The INVITE the far end sent, until this end answers finally.
    pub(crate) server: Option<TransactionId<InviteServer>>,
    pub(crate) dialog: Option<DialogId>,
    pub(crate) forks: ForkPolicy,
    /// The 2xx is acknowledged, or its ACK is ours and waits for a stream
    /// (RFC 3261 §18.1.1); either way the application owes nothing.
    pub(crate) acknowledged: bool,
    /// A hangup was asked for before there was anything to cancel (§9.1).
    pub(crate) hangup_wanted: bool,
    pub(crate) contact_context: ContactContext,
    /// The `From` this call presents: the account's address when placed, the
    /// INVITE's `To` when answered (RFC 3261 §12.1.1). Fixed, for a later
    /// `Referred-By` (RFC 3892 §2.2).
    pub(crate) from: Box<[u8]>,
    /// Where the signalling goes, checked against a `Replaces` (RFC 3891 §3).
    /// Written once; a far end that moves gets its replacement refused.
    /// `None` when the transport never named the far end.
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) forked_from: Option<CallHandle>,
    pub(crate) session: Session,
    /// The far end listed UPDATE in `Allow` (RFC 3311 §4).
    pub(crate) update_allowed: bool,
    /// Our session change in flight or waiting to retry.
    pub(crate) offering: Option<Offer>,
    /// Their change, waiting for the application's answer.
    pub(crate) answering: Option<Answering>,
    /// A 2xx we sent whose ACK has not arrived (§13.3.1.4).
    pub(crate) awaiting_ack: Option<TransactionId<InviteServer>>,
    /// When to retry after a 491 (§14.1, RFC 3311 §5.3).
    pub(crate) retry_at: Option<Instant>,
    pub(crate) timer: Option<SessionTimer>,
    /// A reliable provisional we sent, still owed a PRACK (RFC 3262 §3).
    pub(crate) unacknowledged: Option<Unacknowledged>,
    /// One we received with an offer; the application's answer goes in the
    /// PRACK (§5).
    pub(crate) owed_prack: Option<ProvisionalResponseId>,
    /// The REFER we sent: the call's single seat for transfers, freed when
    /// it is answered.
    pub(crate) referring: Option<AnyTransactionId>,
    /// The implicit subscription that REFER opened (RFC 3515 §2.4.4); only it
    /// makes a `refer` NOTIFY ours.
    pub(crate) refer_subscription: Option<ReferSubscription>,
    /// A REFER we received.
    pub(crate) referred: Option<Referred>,
    /// What it asked for, until the application decides.
    pub(crate) asked_to_refer: Option<ReferTo>,
    /// For a call placed because of a REFER: the call to report to.
    pub(crate) reporting_to: Option<CallHandle>,
    /// The call this one replaces once answered (RFC 3891 §3).
    pub(crate) replaces: Option<CallHandle>,
    /// The call this consultation leg is for; makes the state `Consulting`.
    pub(crate) consulting_for: Option<CallHandle>,
    /// The live consultation placed from this call.
    pub(crate) consulting: Option<CallHandle>,
    /// Kept to ask again after a 422 (RFC 4028 §7.3).
    pub(crate) placed: Option<OutgoingCall>,
    /// 3xx targets and what was tried (RFC 3261 §8.1.3.4).
    pub(crate) redirection: Redirection,
    /// The INVITE of an incoming call.
    pub(crate) invited: Option<OwnedMessage>,
    /// `Call-ID` and CSeq of our INVITE; a 422 retry keeps the first and
    /// moves the second (§7.3).
    pub(crate) id: Option<CallId>,
    pub(crate) cseq: u32,
    /// The interval we asked for, the fallback of §7.2.
    pub(crate) asked: Option<Duration>,
    /// See [`UserAgent::respond_with_headers`](crate::UserAgent::respond_with_headers).
    pub(crate) headers: Vec<Extra>,
    /// `Reason` values (RFC 3326) of the BYE or CANCEL that ended the call.
    pub(crate) ended_by: Box<[crate::Reason]>,
    /// That BYE or CANCEL.
    pub(crate) ended_with: Option<OwnedMessage>,
    /// The caller of an incoming call, read behind the trust gate.
    pub(crate) identity: Option<Arc<CallIdentity>>,
    /// `Identity` and `Date`, signed once (RFC 8224 §6.1) and repeated on
    /// every INVITE of the call.
    pub(crate) signed: Option<SignedHeaders>,
    /// The far end's `Contact` URI when it carried `isfocus` (RFC 4579 §4.2).
    pub(crate) remote_focus: Option<Uri>,
    /// Recording metadata (RFC 7866 §9.1) sent with every offer of a
    /// recording session.
    pub(crate) recording: Option<Arc<str>>,
}

/// `Identity` (RFC 8224 §4), or `y` in its compact form (§13.1).
pub(crate) const IDENTITY: sipral_core::msg::HeaderName<'static> =
    sipral_core::msg::HeaderName::Identity;

/// The two header fields a signed INVITE carries (RFC 8224 §6.1).
#[derive(Clone, Debug)]
pub(crate) struct SignedHeaders {
    pub(crate) identity: Box<[u8]>,
    /// §6.1 Step 3; `None` when the application wrote its own.
    pub(crate) date: Option<Box<[u8]>>,
}

/// A session change this end has offered.
#[derive(Debug)]
pub(crate) struct Offer {
    /// The re-INVITE or UPDATE; absent between a 491 and its retry.
    pub(crate) transaction: Option<AnyTransactionId>,
    /// Absent for a session-timer UPDATE, which carries none.
    pub(crate) description: Option<SessionDescription>,
    pub(crate) held: bool,
    /// §14.1 allows one retry.
    pub(crate) retried: bool,
    pub(crate) author: Author,
    /// The far end's change was answered while this one waited out a 491,
    /// so its description is out of date.
    pub(crate) overtaken: bool,
}

/// Who wrote the description an offer of ours carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Author {
    /// `reoffer` or `change_formats`: not ours to rewrite.
    Application,
    /// A hold or resume, rewritable from the current session.
    Session,
    /// A session-timer refresh: same session, only the clock moves.
    Refresh,
}

/// One the far end offered, waiting for the application to answer it.
#[derive(Debug)]
pub(crate) struct Answering {
    pub(crate) transaction: AnyTransactionId,
    /// Always readable SDP: other bodies are refused 415 or ignored earlier.
    pub(crate) offer: SessionDescription,
    /// When the request is a PRACK (RFC 3262 §5), the provisional it
    /// acknowledges. A refusal leaves it unacknowledged for the far end's
    /// next PRACK.
    pub(crate) prack: Option<ProvisionalResponseId>,
}

/// What `current_contact` needs besides the account.
#[derive(Clone, Debug)]
pub(crate) struct ContactContext {
    /// Anonymous call (RFC 3323): picks the temporary GRUU (RFC 5627 §3.3).
    pub(crate) anonymous: bool,
    /// A destination other than the account's, so no GRUU from a registrar
    /// the call never used.
    pub(crate) destination: Option<(TransportId, SocketAddr)>,
    /// The plain contact, used if the account is removed mid-call (an empty
    /// `Contact` is no address, RFC 3261 §12.2.1.1).
    pub(crate) plain: Box<[u8]>,
    /// Feature parameters (RFC 3840 §9): `;isfocus` (RFC 4579 §4.2),
    /// `;+sip.src` (RFC 7866 §6.1).
    pub(crate) features: Box<[u8]>,
}

/// The branch [`ForkPolicy::KeepFirst`] kept, or the first to answer a call
/// already hung up; `dialog: None` once every call of the INVITE is over.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeptBranch {
    /// A 2xx in any other dialog is acknowledged and hung up; with `None`,
    /// every 2xx.
    pub(crate) dialog: Option<DialogId>,
    /// Whether the INVITE carried an offer. If not, the late 2xx would need
    /// the application's answer in the ACK.
    pub(crate) offered: bool,
}

/// Who is on a call: the `From` and `To` of the request that opened it.
///
/// Fixed for the call's life; a fork's branches share one.
#[derive(Clone, Debug)]
pub struct CallIdentity {
    /// The `From` URI, as written in the header: no angle brackets, no
    /// header parameters such as `tag`.
    pub from_uri: Box<[u8]>,
    /// The `From` display name, quotes and backslash escapes resolved (RFC
    /// 3261 §25.1). Empty when the header named none.
    pub from_display: Box<[u8]>,
    /// The `To` URI, as written in the header.
    pub to_uri: Box<[u8]>,
    /// The `Call-ID`.
    pub call_id: Box<[u8]>,
    /// Who an incoming INVITE says is calling beyond `From`, behind the
    /// account's trust gate (RFC 3325 §8). Empty for a placed call.
    pub caller: crate::CallerIdentity,
    /// How that INVITE asked to be answered and rung (RFC 5373, `Alert-Info`).
    /// Empty for a call this end placed.
    pub answering: crate::Answering,
}

impl Call {
    pub(crate) const fn up(&self) -> CallState {
        if self.consulting_for.is_some() {
            CallState::Consulting
        } else {
            CallState::Confirmed
        }
    }

    /// Whether a session change is running in either direction (RFC 3261
    /// §14.1), including an offer in our 2xx still waiting for the ACK's
    /// answer (RFC 3264 §4).
    pub(crate) const fn changing(&self) -> bool {
        self.offering.is_some() || self.answering.is_some() || self.session.answer_owed
    }

    /// The far end's change has just been answered, and an offer of ours
    /// still waiting to go again was written before it.
    pub(crate) const fn overtake(&mut self) {
        if let Some(offer) = self.offering.as_mut() {
            offer.overtaken = true;
        }
    }

    pub(crate) fn outgoing(
        account: AccountId,
        forks: ForkPolicy,
        destination: Option<(TransportId, SocketAddr)>,
        anonymous: bool,
        from: Box<[u8]>,
        plain: Box<[u8]>,
    ) -> Self {
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
            contact_context: ContactContext {
                anonymous,
                destination,
                plain,
                features: Box::default(),
            },
            from,
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
            redirection: Redirection::default(),
            invited: None,
            id: None,
            cseq: 1,
            asked: None,
            headers: Vec::new(),
            ended_by: Box::default(),
            ended_with: None,
            identity: None,
            signed: None,
            remote_focus: None,
            recording: None,
        }
    }

    pub(crate) fn incoming(
        account: Option<AccountId>,
        server: TransactionId<InviteServer>,
        from: Box<[u8]>,
        plain: Box<[u8]>,
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
            contact_context: ContactContext {
                anonymous: false,
                destination: None,
                plain,
                features: Box::default(),
            },
            from,
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
            redirection: Redirection::default(),
            invited: None,
            id: None,
            cseq: 1,
            asked: None,
            headers: Vec::new(),
            ended_by: Box::default(),
            ended_with: None,
            identity: None,
            signed: None,
            remote_focus: None,
            recording: None,
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
            contact_context: other.contact_context.clone(),
            from: other.from.clone(),
            peer: other.peer,
            forked_from: Some(forked_from),
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
            // the one request that opened every branch
            placed: other.placed.clone(),
            redirection: Redirection::default(),
            invited: None,
            id: other.id.clone(),
            cseq: other.cseq,
            asked: other.asked,
            headers: other.headers.clone(),
            ended_by: Box::default(),
            ended_with: None,
            identity: None,
            signed: None,
            remote_focus: None,
            recording: None,
        }
    }
}
