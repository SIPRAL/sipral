// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the user agent tells the application.
//!
//! One vocabulary, and it is about accounts and calls rather than about
//! transactions. What the layer below says is not hidden — an event this layer
//! has no policy for is passed through whole — but everything it does have a
//! policy for arrives already decided: a registration that is live, one that
//! is being retried and when, one that will never succeed and why.

use std::sync::Arc;
use std::time::Duration;

use sipral_core::endpoint::Event;
use sipral_core::msg::{OwnedMessage, StatusCode};

use crate::account::AccountId;
use crate::announce::Announcement;
use crate::call::{CallEndReason, CallHandle, CallState};
use crate::dialoginfo::DialogInfo;
use crate::lifecycle::{LifecycleState, RecoveryFailure, Rung};
use crate::message::MessageHandle;
use crate::registration::RegistrarInfo;
use crate::session::Hold;
use crate::subscription::{SubscriptionEnd, SubscriptionHandle, SubscriptionState};

/// Where a registration is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistrationState {
    /// Configured and not registered. Nothing has been sent.
    Idle,
    /// A REGISTER is in flight and there is no binding yet.
    Registering,
    /// The registrar holds a binding.
    Registered,
    /// A refresh is in flight. The binding stands until it is answered.
    Refreshing,
    /// A binding the registrar really did grant, over a transport this process
    /// has since suspended or lost, that nothing has proved since.
    ///
    /// Not evidence, and that is the whole point of it existing: the worst
    /// failure of a softphone is a refresh going out on a timer after a wake,
    /// over a transport that died while nobody was watching, and the reason no
    /// amount of checking prevents it is that "are we registered?" answers yes.
    /// See `docs/16-lifecycle.md`.
    Unverified,
    /// Something recoverable went wrong and the next attempt is scheduled.
    Retrying,
    /// The binding was given up on purpose.
    Unregistered,
    /// The registrar refused in a way that trying again cannot fix.
    Failed,
    /// A snapshot was restored, and nothing has spoken to the registrar since
    /// (see [`UserAgent::thaw_registration`](crate::UserAgent::thaw_registration)).
    ///
    /// There is a binding on paper. It is deliberately not `Registered`: what
    /// was restored is what a registrar said before the device slept, and a
    /// cached registration that still read as valid while name resolution had
    /// gone is a failure this project has had. Nothing may be inferred from
    /// this state except that the next REGISTER can be a refresh rather than a
    /// new registration.
    Restored,
    /// The account has no registrar
    /// ([`Account::unregistered`](crate::Account::unregistered)) and never
    /// sends a REGISTER: a trunk that knows this end by its address.
    ///
    /// Not `Idle`, which is one
    /// [`UserAgent::register`](crate::UserAgent::register) away from a binding;
    /// that call is refused here. An account starts in this state and never
    /// leaves it — nothing on the wire moves it, and a wake, a move or a push
    /// has no binding of its to doubt or refresh.
    NotRegistering,
}

impl core::fmt::Display for RegistrationState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Idle => "idle",
            Self::Registering => "registering",
            Self::Registered => "registered",
            Self::Refreshing => "refreshing",
            Self::Unverified => "unverified",
            Self::Retrying => "retrying",
            Self::Unregistered => "unregistered",
            Self::Failed => "failed",
            Self::Restored => "restored",
            Self::NotRegistering => "not registering",
        })
    }
}

/// Why an account's password did not answer a challenge
/// ([`UaEvent::ChallengeDeclined`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChallengeRefusal {
    /// The challenged request went somewhere other than the account's own
    /// server — its registrar, or the outbound proxy of an account that does
    /// not register — so whoever asked is the far end of a call, or a peer
    /// reached directly, and not the party that issued the password.
    NotTheAccountsServer,
    /// The account's server asked for a realm that is not the account's: not
    /// one of [`Account::realms`](crate::Account::realms), or, with none
    /// named, not the one its server first challenged with. A proxy passing
    /// on a far end's own challenge is what this looks like.
    NotTheAccountsRealm,
}

impl core::fmt::Display for ChallengeRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::NotTheAccountsServer => "challenged by somebody other than the account's server",
            Self::NotTheAccountsRealm => "challenged for a realm that is not the account's",
        })
    }
}

/// Why a registration is not live.
///
/// The split that matters is whether trying again can help. Everything that
/// can is retried on the RFC 5626 §4.5 schedule without the application being
/// asked; everything that cannot stops, because a client that re-sends a
/// refused password locks the account it was trying to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistrationFailure {
    /// The registrar refused, and it will refuse the same request again: a
    /// 403, a 404, or any other final response that is about the account
    /// rather than about this attempt.
    Rejected,
    /// A challenge came back that could not be answered — no credentials on
    /// the account — or the same challenge came back after it was answered,
    /// which §22.1 reads as the password being wrong.
    BadCredentials,
    /// The registrar is not answering, or says it cannot serve this now: a
    /// timeout, a dead transport, a 5xx.
    Unreachable,
    /// The registrar moved: a 3xx naming somewhere else. Following it needs an
    /// address, and resolving one is the caller's, so the redirect is reported
    /// rather than chased.
    Redirected,
    /// The account's `Contact` names an address the registrar cannot reach
    /// this end at — loopback, to a registrar that is not, or the unspecified
    /// address — and nothing was sent (see [`crate::UaError::UnreachableAddress`]).
    /// Trying again cannot help until the account is given an address the
    /// registrar can reach ([`UserAgent::rebind`](crate::UserAgent::rebind)).
    UnreachableContact,
}

impl RegistrationFailure {
    /// A note about what usually causes this, where there is one worth saying.
    ///
    /// Not a diagnosis: nothing on the wire proves it. But a registrar that
    /// refuses every binding is almost always configured to allow none — the
    /// SIP channel driver of one widely deployed PBX defaults `max_contacts`
    /// to zero, which does exactly that — and the client gets blamed for a
    /// server setting often enough that it is worth saying out loud.
    #[must_use]
    pub const fn hint(self) -> Option<&'static str> {
        match self {
            Self::Rejected => Some(
                "a registrar that refuses every binding is usually configured to allow none; \
                 check max_contacts on the address of record",
            ),
            Self::UnreachableContact => Some(
                "the Contact names a loopback address the registrar cannot reach; bind to the \
                 address of the interface that routes to the registrar",
            ),
            Self::BadCredentials | Self::Unreachable | Self::Redirected => None,
        }
    }
}

impl core::fmt::Display for RegistrationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Rejected => "refused",
            Self::BadCredentials => "credentials refused",
            Self::Unreachable => "registrar unreachable",
            Self::Redirected => "registrar moved",
            Self::UnreachableContact => "contact unreachable from the registrar",
        })
    }
}

/// Something the application has to know about.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum UaEvent {
    /// A REGISTER is on its way and there is no binding yet.
    Registering {
        /// Which account.
        account: AccountId,
    },
    /// The registrar holds a binding.
    ///
    /// `expires` is what it granted, which wins over what was asked for
    /// (§10.2.4), and `refresh_in` is when the next REGISTER goes — early
    /// enough that one lost refresh and one retransmission round still fit
    /// before the binding lapses. The 2xx rides whole, for the same reason a
    /// refusal does: the `Contact` set the registrar holds for the address of
    /// record, and whatever else it said, says more than a lifetime can.
    Registered {
        /// Which account.
        account: AccountId,
        /// The granted lifetime of the binding.
        expires: Duration,
        /// How long until the refresh.
        refresh_in: Duration,
        /// The 2xx, whole.
        response: OwnedMessage,
        /// The service route, the GRUUs and the associated identities it
        /// carried, as far as they could be read. What this account's
        /// requests use from here on, until the next 2xx replaces it.
        info: RegistrarInfo,
    },
    /// A refresh is in flight. The binding stands until it is answered.
    Refreshing {
        /// Which account.
        account: AccountId,
    },
    /// The registration is not live.
    ///
    /// `retry_in` is set when the user agent is going to try again by itself,
    /// and absent when it has stopped. Either way the response is here whole,
    /// because a reason phrase, a `Retry-After` or the `Contact` of a redirect
    /// says more than a status code can.
    RegistrationFailed {
        /// Which account.
        account: AccountId,
        /// Why.
        reason: RegistrationFailure,
        /// The status, when one arrived.
        status: Option<StatusCode>,
        /// When the next attempt goes, if there is going to be one.
        retry_in: Option<Duration>,
        /// The refusal, whole.
        response: Option<OwnedMessage>,
    },
    /// The binding has been given up on purpose.
    Unregistered {
        /// Which account.
        account: AccountId,
    },
    /// A binding the registrar granted is no longer evidence of anything:
    /// the machine slept, the network under it changed, or names stopped
    /// resolving and its registrar was one. Its state is
    /// [`RegistrationState::Unverified`](crate::RegistrationState::Unverified)
    /// from now until a 2xx proves it again; the recovery that follows says
    /// what it tries in [`UaEvent::Lifecycle`].
    Unverified {
        /// Which account.
        account: AccountId,
    },
    /// The INVITE for a call a push had already announced has arrived
    /// (RFC 8599).
    ///
    /// Queued immediately before the [`UaEvent::IncomingCall`] naming the same
    /// call, and never without one, so that an application reading the queue
    /// in order knows the call belongs to a screen it has already raised
    /// before it is told there is a call at all. That is the whole point: on a
    /// phone the ringing screen exists first, and a stack that reports the
    /// INVITE without saying which announcement it answers has made the
    /// application guess.
    ///
    /// It is a separate event rather than a field on `IncomingCall` because a
    /// variant that grows a field breaks every pattern that names its fields —
    /// here, and in the C ABI and the bindings generated from it, where
    /// `docs/13-client-requirements.md` B7 makes "adding a function cannot
    /// leave a platform behind" a requirement rather than a preference.
    CallAnnounced {
        /// The call the INVITE opened.
        call: CallHandle,
        /// What announced it.
        announcement: Announcement,
    },
    /// An announced call never arrived.
    ///
    /// Not an error. A wake-up chain has a notification service, a proxy, a
    /// bucket timer and a radio in it, and when a call does not come through
    /// it this is the only place that says which end gave up: the push was
    /// delivered, this device woke, refreshed its binding, and no INVITE
    /// followed. RFC 8599 §5.6.2 has several ways for that to be the proxy's
    /// doing — the caller hung up, the push request failed, the bucket timer
    /// ran out — and none of them reaches this device as a SIP message.
    AnnouncedCallMissing {
        /// What was expected.
        announcement: Announcement,
        /// How long it was waited for.
        waited: Duration,
    },
    /// Somebody is calling.
    ///
    /// Answer it with [`UserAgent::answer`](crate::UserAgent::answer), say it
    /// is ringing with [`UserAgent::ring`](crate::UserAgent::ring), or refuse
    /// it with [`UserAgent::reject`](crate::UserAgent::reject). A 100 Trying
    /// has already gone out; nothing else has.
    IncomingCall {
        /// The call.
        call: CallHandle,
        /// The account it came in on, when it could be told which. An INVITE
        /// addressed to somewhere this agent does not register still arrives,
        /// because refusing it silently would hide a misrouted call.
        account: Option<AccountId>,
        /// The INVITE, whole; the offer may be in it.
        request: OwnedMessage,
        /// Who is calling, read out of the INVITE as it arrived: its `From`,
        /// `To` and `Call-ID`, what the network asserted about the caller
        /// behind the account's trust gate (RFC 3325 §8), and how the call
        /// asked to be answered and rung. `None` only for an INVITE whose
        /// `From`, `To` or `Call-ID` could not be read.
        identity: Option<std::sync::Arc<crate::CallIdentity>>,
    },
    /// A call's `Identity` header field (RFC 8224) names a certificate this
    /// end has to fetch before it can say who is calling: the call is held
    /// back until [`UserAgent::stir_certificate`](crate::UserAgent::stir_certificate)
    /// hands over what `url` yielded, or says nothing could be had.
    ///
    /// The fetch is the application's — its cache, its HTTP client and their
    /// timeouts — and it is waited for only so long
    /// ([`StirConfig::certificate_wait`](crate::StirConfig::certificate_wait));
    /// after that the call is verified as one whose certificate could not be
    /// had. The handle names a call the application has not been told about
    /// yet: [`UaEvent::CallerVerified`] and then [`UaEvent::IncomingCall`]
    /// follow, or [`UaEvent::CallEnded`] if the caller gives up first.
    CertificateWanted {
        /// The call waiting.
        call: CallHandle,
        /// The `info` URL of its `Identity` header field.
        url: Box<str>,
    },
    /// A request of `account`'s was challenged by somebody its password is
    /// not for, and the challenge was not answered (RFC 3261 §22.1: "each
    /// such protection domain has its own set of usernames and passwords").
    ///
    /// Raised before the refusal settles the way any unanswered challenge
    /// does — a call ending with the 401 or 407, a registration failing
    /// with [`RegistrationFailure::BadCredentials`], a request inside a call
    /// refused — so the application reading in order knows why first. Every
    /// answer is material for an offline search of the password by whoever
    /// chose the nonce (RFC 7616 §5.10, §5.11), which is why nothing is sent.
    ChallengeDeclined {
        /// Whose password was asked for.
        account: AccountId,
        /// Where the challenged request went, and the refusal came from.
        from: std::net::SocketAddr,
        /// The realms it was challenged for.
        realms: Vec<std::sync::Arc<str>>,
        /// Why the password is not for it.
        why: ChallengeRefusal,
    },
    /// This end's verification service reached its verdict on who is
    /// calling (RFC 8224 §6.2).
    ///
    /// Queued immediately before the [`UaEvent::IncomingCall`] naming the
    /// same call, whose identity carries the same verdict
    /// ([`CallerIdentity::verification`](crate::CallerIdentity::verification)),
    /// so an application reading in order has it before the phone rings.
    /// For an account set to refuse what does not verify
    /// ([`StirVerification::Strict`](crate::StirVerification::Strict)) and a
    /// call that did not, `verification.refused` is set, the call has been
    /// answered with the response RFC 8224 §6.2.2 prescribes, and
    /// [`UaEvent::CallEnded`] follows instead.
    ///
    /// Only for an account whose verification is in force: one set to
    /// [`StirVerification::Off`](crate::StirVerification::Off), or to report
    /// on an agent given no trust anchors, never raises it.
    CallerVerified {
        /// The call.
        call: CallHandle,
        /// The account it came in on, when it could be told.
        account: Option<AccountId>,
        /// The verdict.
        verification: std::sync::Arc<crate::CallerVerification>,
        /// The INVITE, whole.
        request: OwnedMessage,
    },
    /// A response short of an answer: the far end is ringing, or is playing
    /// something before it answers.
    CallProgress {
        /// The call.
        call: CallHandle,
        /// Where it is now.
        state: CallState,
        /// The status.
        status: StatusCode,
        /// The response, whole; early media is in it when there is any.
        response: OwnedMessage,
        /// Whether this response carried an offer whose answer has to travel
        /// in the PRACK that acknowledges it (RFC 3262 §5). Only ever true for
        /// a call placed without an offer, and answered with
        /// [`UserAgent::answer_early`](crate::UserAgent::answer_early) — until
        /// it is, the response is retransmitted and the call does not proceed.
        answer_wanted: bool,
    },
    /// One INVITE opened a second dialog: a proxy forked it, and more than one
    /// phone is ringing.
    ///
    /// `sibling` is a call of its own from here on. What happens to it when
    /// another branch answers is [`ForkPolicy`](crate::ForkPolicy).
    CallForked {
        /// The branch that was already known.
        call: CallHandle,
        /// The one that has just appeared.
        sibling: CallHandle,
    },
    /// The call is up.
    ///
    /// `answer_wanted` is true only for a call placed without an offer: the
    /// offer then arrives in this 2xx, the answer to it has to travel in the
    /// ACK, and nothing has been acknowledged yet. Call
    /// [`UserAgent::acknowledge`](crate::UserAgent::acknowledge) with it.
    /// Otherwise the ACK has already gone — a 2xx left unacknowledged is
    /// retransmitted for 32 seconds and then hung up by the far end, which is
    /// not a decision worth leaving to an application.
    CallConfirmed {
        /// The call.
        call: CallHandle,
        /// The 2xx, for a call this end placed. Absent for one it answered:
        /// this end wrote that response and the ACK is what arrived.
        response: Option<OwnedMessage>,
        /// Whether the ACK is waiting for a session description.
        answer_wanted: bool,
    },
    /// The session inside a live call changed: a hold, a resume, or an offer
    /// either end made and had accepted.
    ///
    /// Both descriptions ride along because the user agent writes some of them
    /// itself — the held version of an offer is derived here, from RFC 3264
    /// §8.4, and this is the only place the application sees it.
    SessionChanged {
        /// The call.
        call: CallHandle,
        /// Which way it is now held.
        hold: Hold,
        /// What this end is describing.
        local: Option<Arc<[u8]>>,
        /// And what the far end is.
        remote: Option<Arc<[u8]>>,
    },
    /// The far end offered a change this layer has no policy for: a codec
    /// swap, a stream added. A body that is not a session description never
    /// arrives here: RFC 3261 §8.2.3 has it refused 415 first, or ignored
    /// when its sender marked it optional.
    ///
    /// The transaction is held open for it. Answer with
    /// [`UserAgent::accept_reoffer`](crate::UserAgent::accept_reoffer) or
    /// refuse with
    /// [`UserAgent::reject_reoffer`](crate::UserAgent::reject_reoffer) — a
    /// re-INVITE nobody answers is retransmitted and then ends the call.
    Reoffer {
        /// The call.
        call: CallHandle,
        /// The re-INVITE or UPDATE, whole.
        request: OwnedMessage,
    },
    /// A change this end offered was refused, or will not be answered.
    ///
    /// §14.1: the session stands exactly as it was. `retry_in` is set only for
    /// a 491, where two offers crossed and this one is going out again by
    /// itself when the wait is over.
    SessionChangeFailed {
        /// The call.
        call: CallHandle,
        /// The status, when one arrived.
        status: Option<StatusCode>,
        /// When the change goes out again, if it is going to.
        retry_in: Option<Duration>,
        /// The refusal, whole.
        response: Option<OwnedMessage>,
    },
    /// The far end asked this one to call somebody else (RFC 3515).
    ///
    /// Take it with
    /// [`UserAgent::accept_transfer`](crate::UserAgent::accept_transfer),
    /// which answers 202 and places the call, or refuse it with
    /// [`UserAgent::reject_transfer`](crate::UserAgent::reject_transfer). A
    /// REFER nobody answers is retransmitted until it gives up; 64·T1 after
    /// it arrived the stack answers it 408 itself, and the call takes the
    /// next REFER it is sent as though this one had never come.
    TransferRequested {
        /// The call it arrived in.
        call: CallHandle,
        /// Who to call.
        target: sipral_core::msg::Uri,
        /// Whether it named a dialog to replace, which makes it an attended
        /// transfer rather than a blind one (RFC 3891).
        attended: bool,
        /// The REFER, whole.
        request: OwnedMessage,
    },
    /// A transfer this end asked for is under way, as the far end reports it
    /// in a `message/sipfrag` (RFC 3515 §2.4.5).
    TransferProgress {
        /// The call that was transferred.
        call: CallHandle,
        /// What the far end's own call is doing.
        status: StatusCode,
    },
    /// And how it ended. A success hangs this call up, because this end is not
    /// in it any more; a failure leaves it exactly where it was.
    TransferDone {
        /// The call that was transferred.
        call: CallHandle,
        /// The final status the far end reported.
        status: StatusCode,
    },
    /// Somebody outside any call asked this end to place one (RFC 3515, a
    /// REFER with no dialog): click-to-dial from a switchboard or a CRM.
    ///
    /// Raised only with
    /// [`UserAgent::allow_referrals`](crate::UserAgent::allow_referrals) on,
    /// and only for a REFER the same screening an INVITE meets let through.
    /// Take it with
    /// [`UserAgent::accept_transfer`](crate::UserAgent::accept_transfer) on
    /// `referral`, which answers 202, reports on the call it places, and
    /// places it from `account`; refuse it with
    /// [`UserAgent::reject_transfer`](crate::UserAgent::reject_transfer).
    /// Taking one is the application's decision every time, because a peer
    /// that can make a phone dial is a toll-fraud vector: see
    /// [`crate::referral`]. One left unanswered for 64·T1 is
    /// [`UaEvent::ReferralLapsed`].
    ReferralRequested {
        /// The referral: a handle of the call kind that names no call, only
        /// this request, until it is answered or lapses.
        referral: CallHandle,
        /// The line it was addressed to, by its Request-URI or its `To`, and
        /// the one the call it asks for is placed from.
        account: AccountId,
        /// Who to call.
        target: sipral_core::msg::Uri,
        /// Whether its `Refer-To` named a dialog to replace (RFC 3891).
        attended: bool,
        /// Its `Referred-By`, when it carried exactly one (RFC 3892 §2.1):
        /// who the sender says is asking. Written by the sender, so it is
        /// context for a decision and never proof of anything.
        referred_by: Option<Box<[u8]>>,
        /// The REFER, whole.
        request: OwnedMessage,
    },
    /// A referral nobody took or refused before its transaction ran out
    /// (RFC 3515 §2.4.2), answered by the stack itself. Its handle names
    /// nothing from here on.
    ReferralLapsed {
        /// The referral.
        referral: CallHandle,
        /// What the REFER was answered with.
        status: StatusCode,
    },
    /// A SUBSCRIBE is on its way and nothing has answered yet (RFC 6665
    /// §4.1.2.1).
    Subscribing {
        /// Which subscription.
        subscription: SubscriptionHandle,
        /// The account it goes out on.
        account: AccountId,
    },
    /// The notifier has the subscription.
    ///
    /// `state` says whether it is granted or still being decided — §4.1.3's
    /// `pending` means "there is insufficient policy information to grant or
    /// deny the subscription yet", and nothing is known about the resource
    /// until it becomes `active`. `expires` is what the notifier granted,
    /// which wins over what was asked for (§3.1.1).
    ///
    /// Sent when the state changes and not on every refresh: a lamp does not
    /// move when a refresh is scheduled, and thirty subscriptions saying so
    /// every hour is noise.
    Subscribed {
        /// Which subscription.
        subscription: SubscriptionHandle,
        /// Where it is now.
        state: SubscriptionState,
        /// The granted lifetime.
        expires: Duration,
        /// How long until the refresh.
        refresh_in: Duration,
    },
    /// One SUBSCRIBE was answered by two notifiers, so there are now two
    /// subscriptions (RFC 6665 §4.1.4).
    ///
    /// `sibling` is a subscription of its own from here on, with its own
    /// dialog, its own refresh and its own state. RFC 4235 §3.9 makes this the
    /// normal case for dialog state: "a forked SUBSCRIBE request for dialog
    /// state can install multiple subscriptions", one per device the address
    /// of record is registered on.
    SubscriptionForked {
        /// The one that was already known.
        subscription: SubscriptionHandle,
        /// The one that has just appeared.
        sibling: SubscriptionHandle,
    },
    /// A notification arrived and has been answered (RFC 6665 §4.1.3).
    ///
    /// `info` is there when the body was an `application/dialog-info+xml`
    /// document that could be read, and it is what changed rather than the
    /// whole picture — RFC 4235 §3.8 lets a notifier send only the dialogs
    /// whose state moved. The merged picture is
    /// [`UserAgent::dialog_info`](crate::UserAgent::dialog_info). A body that
    /// could not be read leaves both alone and arrives here as `None` with the
    /// request whole, because a lamp showing what was last known beats one
    /// showing what a malformed document happened to contain.
    Notified {
        /// Which subscription.
        subscription: SubscriptionHandle,
        /// The NOTIFY, whole. Every package that is not `dialog` is read from
        /// here.
        request: OwnedMessage,
        /// The dialog state it carried, when it carried readable dialog state.
        info: Option<Arc<DialogInfo>>,
    },
    /// The subscription is not live.
    ///
    /// `retry_in` is set when the user agent is going to start a fresh one by
    /// itself — §4.1.2.2 makes that "an unrelated initial SUBSCRIBE request
    /// with a freshly generated Call-ID and a new, unique From tag", under the
    /// same handle — and absent when it has stopped, in which case the handle
    /// names nothing from here on. Either way what a `dialog` subscription had
    /// been told is no longer evidence about anything, and
    /// [`UserAgent::dialog_info`](crate::UserAgent::dialog_info) says so by
    /// answering nothing.
    SubscriptionEnded {
        /// Which subscription.
        subscription: SubscriptionHandle,
        /// Why.
        reason: SubscriptionEnd,
        /// The status, when a response said so.
        status: Option<StatusCode>,
        /// When the next attempt goes, if there is going to be one.
        retry_in: Option<Duration>,
        /// The refusal, whole, when there was one.
        response: Option<OwnedMessage>,
    },
    /// A MESSAGE arrived (RFC 3428 §7) and has already been answered: 200,
    /// because this stack delivers rather than relays.
    ///
    /// `account` is the line it was addressed to, when one could be told —
    /// absent the same way [`UaEvent::IncomingCall`]'s is for a request this
    /// agent does not register the name in. `call` is set when the MESSAGE
    /// rode inside a dialog (§4's MAY); `None` for the ordinary out-of-dialog
    /// case. The `Content-Type` and the body are read from `request`, which
    /// carries the whole MESSAGE.
    MessageReceived {
        /// The account it was addressed to, when known.
        account: Option<AccountId>,
        /// The call it arrived inside, when it did.
        call: Option<CallHandle>,
        /// The MESSAGE, whole.
        request: OwnedMessage,
    },
    /// A MESSAGE this end sent reached its final answer, or never will.
    ///
    /// `status` is 200 when the far end delivered it, 202 when it went
    /// through a relay that could not promise delivery (§4), a 415 carrying
    /// an `Accept` the far end could not read the body against, a 413 over
    /// its size policy, or the 408/503 this stack reports for one that timed
    /// out or lost its transport (RFC 3261 §8.1.3.1's reading of the same for
    /// any non-INVITE request). `response` is the answer whole, when one
    /// arrived.
    MessageSent {
        /// Which send.
        message: MessageHandle,
        /// The final status.
        status: StatusCode,
        /// The response, whole, when there was one.
        response: Option<OwnedMessage>,
    },
    /// A message-summary NOTIFY reported the state of a mailbox (RFC 3842
    /// §3.9).
    ///
    /// `new`, `old` and the urgent counts are the `voice-message` class's
    /// (RFC 3458 §6.2) — the one a phone's message-waiting light is about —
    /// read from
    /// [`UserAgent::message_summary`](crate::UserAgent::message_summary)'s
    /// full document, which keeps every class a notifier reported. `waiting`
    /// is §3.5's boolean status line alone, sent by every notifier even one
    /// with nothing more detailed to say; a body that never names
    /// `voice-message` still carries it, with the four counts at zero.
    MessagesWaiting {
        /// Which subscription.
        subscription: SubscriptionHandle,
        /// The overall status line.
        waiting: bool,
        /// `Message-Account`, when the notifier sent one.
        account: Option<Box<str>>,
        /// New voice messages.
        new: u32,
        /// Old ones.
        old: u32,
        /// New ones flagged urgent.
        urgent_new: u32,
        /// Old ones flagged urgent.
        urgent_old: u32,
    },
    /// A `conference` subscription's picture of the conference changed, or
    /// the conference ended (RFC 4575 §4.6). The picture itself is
    /// [`UserAgent::conference`](crate::UserAgent::conference).
    ///
    /// Only for a document that was merged. One that was late or repeated
    /// changes nothing and says nothing; one that could not be merged — a
    /// partial document whose predecessor never arrived — is answered here by
    /// asking for full state again, and the picture stands as it was until
    /// that arrives.
    ConferenceChanged {
        /// Which subscription.
        subscription: SubscriptionHandle,
        /// [`ConferenceUpdate::Applied`](crate::ConferenceUpdate::Applied),
        /// or [`ConferenceUpdate::Ended`](crate::ConferenceUpdate::Ended),
        /// after which the subscription is being given up (§4.6).
        update: crate::ConferenceUpdate,
    },
    /// A `presence` subscription was told about the presentity (RFC 3856
    /// §6.8), in a document this build could read.
    PresenceChanged {
        /// Which subscription.
        subscription: SubscriptionHandle,
        /// The document, whole: every notification of this package carries
        /// the presentity's full state.
        presence: Arc<crate::presence::Presence>,
    },
    /// Something happened to state this agent keeps at a compositor (RFC
    /// 3903): it was published or refreshed, it lapsed, it was removed, or
    /// the compositor refused.
    ///
    /// Never [`PublishEvent::Challenged`](crate::PublishEvent::Challenged):
    /// the account's credentials answer a challenge, and one they cannot is
    /// a [`PublishEvent::Failed`](crate::PublishEvent::Failed) with the 401
    /// or 407 in it.
    Publication {
        /// Which publication.
        publication: crate::PublicationHandle,
        /// Whose.
        account: AccountId,
        /// What happened.
        event: crate::PublishEvent,
    },
    /// A call arrived carrying a `Replaces` that named one already up, and
    /// took it over (RFC 3891). The replaced call is being hung up.
    CallReplaced {
        /// The one that arrived.
        call: CallHandle,
        /// The one it replaced.
        replaced: CallHandle,
    },
    /// The call is over and its handle is about to go stale.
    CallEnded {
        /// The call.
        call: CallHandle,
        /// Why.
        reason: CallEndReason,
        /// The status, when a response said so.
        status: Option<StatusCode>,
        /// The refusal, whole, when there was one. A 302 names where to try
        /// instead, and a 380 carries an alternative service.
        response: Option<OwnedMessage>,
        /// Why the far end said it ended the call (RFC 3326): the `Reason`
        /// of the BYE or the CANCEL that ended it, or of the refusal when a
        /// gateway put one there (RFC 6432). One value per protocol, in the
        /// order written, and empty when nothing said. A forking proxy's
        /// CANCEL of a branch that lost carries a SIP 200,
        /// [`Reason::is_completed_elsewhere`](crate::Reason::is_completed_elsewhere):
        /// answered on another phone, not missed.
        causes: Box<[crate::Reason]>,
    },
    /// An INFO sent for [`UserAgent::send_dtmf_info`](crate::UserAgent::send_dtmf_info)
    /// reached a final answer.
    ///
    /// `status` is whatever the far end gave it — a 200 from a switch that
    /// read the body, a 415 from one that does not take this `Content-Type`,
    /// or anything else a proxy in front of it chose to send instead. Either
    /// way the application learns the digit and the code together, without
    /// having to keep its own map from a fire-and-forget send back to what it
    /// was about. An INFO nobody answered is reported the way RFC 3261
    /// §8.1.3.1 says to treat one, as a 408 when it timed out and a 503 when
    /// its transport failed; one challenged on an account with nothing to
    /// answer the challenge with, as that challenge's 401 or 407. A digit
    /// that waited behind another and whose own INFO could then not be sent
    /// at all is reported too, as a 503, the status §8.1.3.1 gives a request
    /// that never went out; nothing reached the far end for that one.
    DtmfSent {
        /// The call the INFO went out on, or was to go out on.
        call: CallHandle,
        /// The digit that was sent, or could not be.
        digit: char,
        /// What the far end answered, or the status that stands for the
        /// answer that never came.
        status: StatusCode,
    },
    /// A digit arrived by SIP INFO (RFC 6086), carrying
    /// `application/dtmf-relay` or `application/dtmf` — see
    /// `docs/04-ua.md` for the two conventions, neither of which has an RFC
    /// of its own.
    ///
    /// Not an event of its own kind: the facade this layer sits under unifies
    /// this with the RFC 4733 digit its media reports into one `DigitReceived`
    /// the application reads, tagged with which of the two carried it. This
    /// variant exists only because that unification cannot happen here — this
    /// layer has no media of its own to unify with.
    DtmfReceived {
        /// The call the INFO arrived in.
        call: CallHandle,
        /// The digit.
        digit: char,
        /// `application/dtmf-relay`'s `Duration=`, when the body carried one.
        held_ms: Option<u32>,
    },
    /// The lifecycle machine moved: the machine was told it sleeps, that it
    /// woke, or that the network under it is a different one.
    ///
    /// `rung` is what was just done about it and `next_in` is when the next
    /// thing is tried. A rung of [`Rung::WantTransport`] or
    /// [`Rung::WantAddress`] is a request: nothing here opens a socket or
    /// resolves a name, so the recovery stops there until
    /// [`UserAgent::rebind`](crate::UserAgent::rebind) is called, or until the
    /// wait runs out and the ladder climbs on without it.
    Lifecycle {
        /// Where the machine is now.
        state: LifecycleState,
        /// What was just tried, when anything was.
        rung: Option<Rung>,
        /// How long until the next rung, when there is going to be one.
        next_in: Option<Duration>,
    },
    /// A DNS lookup is needed to locate an account's server by RFC 3263
    /// ([`Account::located`](crate::Account::located)).
    ///
    /// Make it with the platform's resolver and hand the answer to
    /// [`UserAgent::looked_up`](crate::UserAgent::looked_up) — every one,
    /// failures included, since the procedure waits for each answer. Several
    /// can be outstanding at once: one per SRV target's host.
    LookupWanted {
        /// The account whose server is being located.
        account: AccountId,
        /// The name and the kind of record to ask for.
        query: sipral_core::endpoint::Query,
    },
    /// An account's server was located, or located again once the last
    /// answer's time-to-live ran out: every address the answer named, first
    /// the one the account's requests now go to.
    Located {
        /// The account.
        account: AccountId,
        /// The addresses, in RFC 3263 §4.3's order from the one in use.
        targets: Vec<std::net::SocketAddr>,
    },
    /// A lookup of an account's server named no address. A REGISTER that was
    /// waiting for it is reported failed as well, and backs off; anything
    /// else is looked up again after `retry_in`. An address an earlier
    /// answer named stays in use meanwhile.
    LocateFailed {
        /// The account.
        account: AccountId,
        /// Why.
        reason: sipral_core::endpoint::LocateError,
        /// How long until the next lookup.
        retry_in: Duration,
    },
    /// The address this call's media was described at is gone: the network
    /// changed under it ([`Recovery::Rebuild`](crate::Recovery::Rebuild)),
    /// and the far end is still sending its audio to the old one.
    ///
    /// One for every call that can still be offered a new description — up,
    /// or early in a dialog that allows UPDATE — raised as the change is
    /// reported. Nothing here opens a socket: the application binds one on
    /// the new network and offers the call there, with
    /// `sipral::MediaEngine::readdress` for a call whose media the facade
    /// describes, or [`UserAgent::change_formats`](crate::UserAgent::change_formats)
    /// with a description of its own. [`UserAgent::rebind`](crate::UserAgent::rebind)
    /// goes first, so that the re-INVITE carries the new `Contact`.
    CallAddressWanted {
        /// The call.
        call: CallHandle,
    },
    /// Every rung of a recovery ladder was climbed and none of them worked.
    ///
    /// Nothing more happens by itself. Bindings whose REGISTER reached a
    /// transport are still on their own back-off; `unverified` counts the ones
    /// that never got that far, which are the ones nothing is retrying.
    RecoveryGaveUp {
        /// The last thing that was tried.
        rung: Rung,
        /// Why it stopped.
        reason: RecoveryFailure,
        /// Bindings left unproved.
        unverified: usize,
    },
    /// A protocol event this layer has no policy for.
    ///
    /// Nothing the endpoint says is dropped on the way through, and nothing
    /// that passes here has been interpreted. The one exception is a request
    /// that no handler here claims, which leaves no choice in how it is
    /// answered and would otherwise go unanswered until the far end's timer
    /// gives up: outside a dialog RFC 3261 §8.2.1 has it 405 with `Allow`,
    /// 501, or 481 when it names a dialog this agent does not have, and
    /// inside one the usage RFC 5057 §5.3 matches it to decides between the
    /// same statuses, with RFC 6086 §4.2.2's answer for an INFO. So it is
    /// answered here and never arrives as `Event::IncomingOutOfDialog` or
    /// `Event::IncomingInDialog` — except an INFO in a call that is not
    /// DTMF, once
    /// [`UserAgent::hand_over_info`](crate::UserAgent::hand_over_info) has
    /// asked for those (`docs/04-ua.md`).
    Unclaimed(Event),
}
