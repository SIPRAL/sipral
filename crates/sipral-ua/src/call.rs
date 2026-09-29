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
    /// Keep the first branch that answers, whichever one it is — the call
    /// placed or a sibling [`crate::UaEvent::CallForked`] announced — and
    /// hang up every later one with a BYE. The branches still ringing when
    /// one is kept end there and then with [`CallEndReason::ForkLost`], after
    /// the kept one's [`crate::UaEvent::CallConfirmed`]; a 2xx from any of
    /// them afterwards, or from a branch never heard of before, is
    /// acknowledged and hung up without another event. A branch kept that is
    /// not the call placed carries on as the call: a transfer it was placed
    /// for, or the consultation it is, go with it. What a telephone does,
    /// and the default.
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
    /// Another branch of the same fork answered first and was kept, and this
    /// one had not answered ([`ForkPolicy::KeepFirst`]). The call carries on
    /// under the handle of the branch that was kept.
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
    /// Whether this end is the conference's focus ([`OutgoingCall::focus`]).
    pub(crate) focus: bool,
    /// The recording metadata of a recording session, written
    /// ([`OutgoingCall::recording_session`]).
    pub(crate) metadata: Option<Arc<str>>,
}

impl OutgoingCall {
    /// A call to `target`.
    ///
    /// It leaves on the account's transport, for the account's address: the
    /// one it registers with — which is the outbound proxy for a registered
    /// line, and the reason a softphone behind a NAT works at all — or, for an
    /// account that never registers, the outbound proxy it was given
    /// ([`crate::Account::unregistered`]). Somewhere else needs
    /// [`OutgoingCall::to_address`].
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
        }
    }

    /// Place it as a conference's focus: the `Contact` of the INVITE and of
    /// every later request and response of the call carries `isfocus`, which
    /// RFC 4579 §4.2 has a focus include ("unless the focus wishes to hide
    /// the fact that it is a focus"), so that a conference-aware far end
    /// knows the dialog belongs to a conference whose URI is that `Contact`.
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
    /// [`UaError::Recording`] for metadata that cannot be written.
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
    /// Left out, the INVITE carries none and the offer arrives in the 2xx
    /// instead (§14.1). The answer to it then has to travel in the ACK, which
    /// is why a call placed that way is not acknowledged until
    /// [`crate::UserAgent::acknowledge`] is called.
    #[must_use]
    pub fn offer(mut self, sdp: Arc<[u8]>) -> Self {
        self.offer = Some(sdp);
        self
    }

    /// Send it somewhere other than the account's address.
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
    ///
    /// Checked when the call is placed, before anything is built:
    /// [`crate::HeadersFor::Call`] says which fields are refused and why.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'_>, value: &[u8]) -> Self {
        self.extra.push(Extra {
            name: Box::from(name.canonical().as_bytes()),
            value: Box::from(value),
        });
        self
    }
}

/// Everything [`OutgoingCall`] carries beside a target and an offer: a
/// destination other than the account's, which forks to keep, and header
/// fields of the application's own, already checked at whatever boundary
/// read them.
///
/// [`UserAgent::accept_transfer`](crate::UserAgent::accept_transfer) takes
/// this instead of an [`OutgoingCall`] because its target is never the
/// caller's to give — the REFER that was accepted already names it — and a
/// mandatory field the caller has no legitimate value for is worse than a
/// second, smaller type.
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
    /// The INVITE the far end sent, while this end has not finally answered.
    pub(crate) server: Option<TransactionId<InviteServer>>,
    /// The dialog, once there is one.
    pub(crate) dialog: Option<DialogId>,
    /// What to do with the siblings this branch may acquire.
    pub(crate) forks: ForkPolicy,
    /// Whether the 2xx has been acknowledged, or its ACK is this layer's and
    /// waiting for the stream RFC 3261 §18.1.1 asked for. Either way the
    /// application owes it nothing.
    pub(crate) acknowledged: bool,
    /// A hangup was asked for and could not go yet: a CANCEL may not leave
    /// before the first provisional response (§9.1), and the endpoint holds it
    /// for us, but a call that has not even opened a dialog has nothing to
    /// cancel.
    pub(crate) hangup_wanted: bool,
    /// What `current_contact` needs to answer for this call besides its
    /// account, decided once when the call was placed or arrived and read
    /// again every time a request or response is built.
    pub(crate) contact_context: ContactContext,
    /// The `From` this call presented to the peer: the account's own address
    /// on a call this end placed, and the `To` the INVITE arrived with on one
    /// it answered, which is the dialog's local URI (RFC 3261 §12.1.1). Read
    /// once because RFC 3892 §2.2 wants it in a `Referred-By` this call writes
    /// later — unlike `Contact`, which RFC 5627 §4.4 keeps current rather than
    /// fixed for the life of the dialog.
    pub(crate) from: Box<[u8]>,
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
    /// The header fields the application wants on what it sends for this
    /// call, kept until it replaces them
    /// ([`UserAgent::respond_with_headers`](crate::UserAgent::respond_with_headers)).
    pub(crate) headers: Vec<Extra>,
    /// The `Reason` values (RFC 3326) of the BYE or the CANCEL that ended
    /// this call, kept from the moment it arrives until the call's end is
    /// reported with them.
    pub(crate) ended_by: Box<[crate::Reason]>,
    /// Who the INVITE of a call this end answered said was calling, read
    /// once, as it arrived, behind the account's trust gate.
    pub(crate) identity: Option<Arc<CallIdentity>>,
    /// The URI of the far end's `Contact` — the dialog's remote target — when
    /// it last carried `isfocus` (RFC 4579 §4.2): the call is part of a
    /// conference, and that is its URI. Read again from every message that
    /// can move the remote target.
    pub(crate) remote_focus: Option<Uri>,
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
    /// Who wrote it, which decides what goes when it is offered once more.
    pub(crate) author: Author,
    /// Whether the far end's own change was answered while this one waited
    /// out a 491, leaving its description written against a session that
    /// has moved since.
    pub(crate) overtaken: bool,
}

/// Who wrote the description an offer of ours carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Author {
    /// The application, through `reoffer` or `change_formats`: written
    /// against the session as it stood, and not this layer's to rewrite.
    Application,
    /// This layer, from the session — a hold or a resume — so it can be
    /// written again from the session as it stands.
    Session,
    /// This layer, as a session-timer refresh: the session stays exactly as
    /// it is, and only the clock moves.
    Refresh,
}

/// One the far end offered, waiting for the application to answer it.
#[derive(Debug)]
pub(crate) struct Answering {
    /// The transaction to answer on.
    pub(crate) transaction: AnyTransactionId,
    /// The offer: a session description this stack could read, since a
    /// body of any other type is refused 415 or ignored before a change is
    /// handed over.
    pub(crate) offer: SessionDescription,
    /// The reliable provisional response the request acknowledges, when it
    /// is a PRACK (RFC 3262 §5). Its 2xx carries only the answer, and it
    /// lets go of whatever that response was holding back; a refusal
    /// leaves the response unacknowledged, for the PRACK the far end sends
    /// again without the offer.
    pub(crate) prack: Option<ProvisionalResponseId>,
}

/// What `current_contact` (`crate::calls`) needs to answer for a call besides
/// its account, grouped so the three do not turn into more bare fields beside
/// the `bool`s [`Call`] already has.
#[derive(Clone, Debug)]
pub(crate) struct ContactContext {
    /// Whether this call was placed, or is being answered, as an anonymous
    /// request (RFC 3323 §4.2's `Privacy`). Decides between the public and
    /// the temporary GRUU (RFC 5627 §3.3) every time the account's
    /// registration state is read fresh.
    pub(crate) anonymous: bool,
    /// Where this call's own request was sent, when it named somewhere other
    /// than the account's own address. Read on every request and response
    /// this call builds, so a call placed off the account's registrar does
    /// not start naming a GRUU it never registered through just because a
    /// later request recomputes its `Contact`.
    pub(crate) destination: Option<(TransportId, SocketAddr)>,
    /// The account's plain contact when the call was placed or arrived, which
    /// is what the call still names if the account is removed while it is up:
    /// the registration goes with the account, so no GRUU is left to name,
    /// and an empty `Contact` is no address at all (RFC 3261 §12.2.1.1).
    pub(crate) plain: Box<[u8]>,
    /// Feature parameters this call's `Contact` carries after the address
    /// (RFC 3840 §9): `;isfocus` for a call this end hosts a conference on
    /// (RFC 4579 §4.2), `;+sip.src` for a recording session this end sends
    /// (RFC 7866 §6.1). Empty for every other call.
    pub(crate) features: Box<[u8]>,
}

/// The branch [`ForkPolicy::KeepFirst`] kept out of one INVITE's fork, or the
/// first to answer an INVITE the user had already put down, which is hung up
/// like every branch after it — or none at all, once every call the INVITE
/// made is over while its transaction can still pass up a 2xx.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeptBranch {
    /// Its dialog. A 2xx in any other dialog of the same INVITE is one this
    /// end acknowledges and hangs up, and with `None` that is every 2xx.
    pub(crate) dialog: Option<DialogId>,
    /// Whether the INVITE carried an offer. When it did not, a 2xx carries
    /// the offer and its ACK has to carry an answer that only the
    /// application could write, for a branch it is no longer told about.
    pub(crate) offered: bool,
}

/// Who is on a call: the `From` and `To` of the request that opened it.
///
/// Fixed for the call's whole life, whichever end placed it: the `From` and
/// the `To` of the INVITE this end sent, or of the one it answered. A fork's
/// branches share one, since one INVITE is what opened every early dialog
/// among them.
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
    /// What the INVITE that opened a call this end answered said about who
    /// is calling beyond its `From`, behind the account's trust gate (RFC
    /// 3325 §8). Empty for a call this end placed.
    pub caller: crate::CallerIdentity,
    /// How that INVITE asked to be answered and rung (RFC 5373, `Alert-Info`).
    /// Empty for a call this end placed.
    pub answering: crate::Answering,
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

    /// Whether a session change is running in either direction, which a new
    /// one has to wait for.
    ///
    /// RFC 3261 §14.1: "a UAC MUST NOT initiate a new INVITE transaction
    /// within a dialog while another INVITE transaction is in progress in
    /// either direction". Ours runs from the moment it is sent until it is
    /// answered, through the wait a 491 asks for; theirs until the
    /// application answers it. And an offer this end put in a 2xx is only
    /// answered by the ACK (§13.2.2.4) — RFC 3264 §4 lets no new offer go
    /// before that answer has arrived.
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
            invited: None,
            id: None,
            cseq: 1,
            asked: None,
            headers: Vec::new(),
            ended_by: Box::default(),
            identity: None,
            remote_focus: None,
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
            // an incoming call answers as itself, never anonymously, and its
            // own request travels nowhere `current_contact` has to be told
            // apart from the account's registrar
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
            invited: None,
            id: None,
            cseq: 1,
            asked: None,
            headers: Vec::new(),
            ended_by: Box::default(),
            identity: None,
            remote_focus: None,
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
            // the request that opened every branch, which is the call the
            // application placed whichever branch ends up being kept: its
            // parties and `Call-ID`, and the session interval it asked for
            placed: other.placed.clone(),
            invited: None,
            id: other.id.clone(),
            cseq: other.cseq,
            asked: other.asked,
            // the application labelled the call, and a branch of it is the call
            headers: other.headers.clone(),
            ended_by: Box::default(),
            identity: None,
            remote_focus: None,
        }
    }
}
