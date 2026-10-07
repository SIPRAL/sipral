// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the user agent tells the application.
//!
//! Events are about accounts and calls, not transactions. Whatever this layer
//! has a policy for arrives already decided; anything else passes through whole.

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
    /// A granted binding over a transport that was since suspended or lost,
    /// not proved since.
    ///
    /// It exists so that "are we registered?" does not answer yes after a
    /// wake, when a refresh would go out over a dead transport. See
    /// `docs/16-lifecycle.md`.
    Unverified,
    /// Something recoverable went wrong and the next attempt is scheduled.
    Retrying,
    /// The binding was given up on purpose.
    Unregistered,
    /// The registrar refused in a way that trying again cannot fix.
    Failed,
    /// A snapshot was restored and nothing has spoken to the registrar since
    /// (see [`UserAgent::thaw_registration`](crate::UserAgent::thaw_registration)).
    ///
    /// Deliberately not `Registered`: the binding is only what the registrar
    /// said before the device slept. The one thing it allows is that the next
    /// REGISTER can be a refresh.
    Restored,
    /// The account has no registrar
    /// ([`Account::unregistered`](crate::Account::unregistered)) and never
    /// sends a REGISTER: a trunk that knows this end by its address.
    ///
    /// Unlike `Idle`, [`UserAgent::register`](crate::UserAgent::register) is
    /// refused here. An account starts in this state and never leaves it.
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
    /// The request went somewhere other than the account's registrar or
    /// outbound proxy, so the challenger is a far end, not the party that
    /// issued the password.
    NotTheAccountsServer,
    /// The account's server asked for a realm not in
    /// [`Account::realms`](crate::Account::realms) (or, with none named, not
    /// the one it first challenged with). Typically a proxy passing on a far
    /// end's challenge.
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
/// What can be fixed by trying again is retried on the RFC 5626 §4.5 schedule.
/// The rest stops: re-sending a refused password locks the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistrationFailure {
    /// A final refusal about the account rather than this attempt (403, 404,
    /// and the like).
    Rejected,
    /// No credentials to answer the challenge, or the same challenge came back
    /// after it was answered, which §22.1 reads as a wrong password.
    BadCredentials,
    /// Timeout, dead transport, or a 5xx.
    Unreachable,
    /// A 3xx naming somewhere else. Resolving it is the caller's, so it is
    /// reported rather than followed.
    Redirected,
    /// The `Contact` names an address the registrar cannot reach (loopback to
    /// a remote registrar, or unspecified), so nothing was sent (see
    /// [`crate::UaError::UnreachableAddress`]). Fixed only by
    /// [`UserAgent::rebind`](crate::UserAgent::rebind).
    UnreachableContact,
}

impl RegistrationFailure {
    /// A note about the usual cause, where there is one worth saying.
    ///
    /// Not a diagnosis. A registrar refusing every binding is usually set to
    /// allow none (one common PBX defaults `max_contacts` to zero), and the
    /// client gets blamed for it.
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
    /// `expires` is what it granted (§10.2.4). `refresh_in` leaves room for
    /// one lost refresh and a retransmission round before the binding lapses.
    Registered {
        /// Which account.
        account: AccountId,
        /// The granted lifetime of the binding.
        expires: Duration,
        /// How long until the refresh.
        refresh_in: Duration,
        /// The 2xx, whole.
        response: OwnedMessage,
        /// Service route, GRUUs and associated identities read from it. Used
        /// by this account's requests until the next 2xx.
        info: RegistrarInfo,
    },
    /// A refresh is in flight. The binding stands until it is answered.
    Refreshing {
        /// Which account.
        account: AccountId,
    },
    /// The registration is not live.
    ///
    /// `retry_in` is set when the user agent will try again by itself, absent
    /// when it has stopped.
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
    /// A granted binding is no longer evidence: the machine slept, the
    /// network changed, or name resolution failed. It stays
    /// [`RegistrationState::Unverified`](crate::RegistrationState::Unverified)
    /// until a 2xx proves it; the recovery reports in [`UaEvent::Lifecycle`].
    Unverified {
        /// Which account.
        account: AccountId,
    },
    /// The INVITE for a call a push already announced has arrived (RFC 8599).
    ///
    /// Queued immediately before the [`UaEvent::IncomingCall`] for the same
    /// call, and never without one, so the application knows which ringing
    /// screen the call belongs to. A separate event rather than a field, since
    /// a new field would break the C ABI and its bindings
    /// (`docs/13-client-requirements.md` B7).
    CallAnnounced {
        /// The call the INVITE opened.
        call: CallHandle,
        /// What announced it.
        announcement: Announcement,
    },
    /// An announced call never arrived.
    ///
    /// Not an error: the push was delivered, the device woke and refreshed,
    /// and no INVITE followed. RFC 8599 §5.6.2 gives the proxy several ways
    /// to cause that, none of which reaches this device.
    AnnouncedCallMissing {
        /// What was expected.
        announcement: Announcement,
        /// How long it was waited for.
        waited: Duration,
    },
    /// Somebody is calling.
    ///
    /// Answer with [`UserAgent::answer`](crate::UserAgent::answer), ring with
    /// [`UserAgent::ring`](crate::UserAgent::ring), or refuse with
    /// [`UserAgent::reject`](crate::UserAgent::reject). Only a 100 Trying has
    /// gone out.
    IncomingCall {
        /// The call.
        call: CallHandle,
        /// The account it came in on, when known. A call to an address this
        /// agent does not register still arrives, so a misrouted call shows.
        account: Option<AccountId>,
        /// The INVITE, whole; the offer may be in it.
        request: OwnedMessage,
        /// Who is calling: `From`, `To`, `Call-ID`, the network-asserted
        /// identity behind the account's trust gate (RFC 3325 §8), and the
        /// answer and ring hints. `None` only when `From`, `To` or `Call-ID`
        /// could not be read.
        identity: Option<std::sync::Arc<crate::CallIdentity>>,
    },
    /// A call's `Identity` header field (RFC 8224) needs a certificate fetched
    /// before the caller can be verified. The call is held back until
    /// [`UserAgent::stir_certificate`](crate::UserAgent::stir_certificate)
    /// hands over what `url` yielded, or that nothing could be had.
    ///
    /// The fetch is the application's. After
    /// [`StirConfig::certificate_wait`](crate::StirConfig::certificate_wait)
    /// the call is verified without the certificate. The handle names a call
    /// not yet reported: [`UaEvent::CallerVerified`] and
    /// [`UaEvent::IncomingCall`] follow, or [`UaEvent::CallEnded`] if the
    /// caller gives up first.
    CertificateWanted {
        /// The call waiting.
        call: CallHandle,
        /// The `info` URL of its `Identity` header field.
        url: Box<str>,
    },
    /// A request of `account`'s was challenged by somebody its password is not
    /// for, and the challenge was not answered (RFC 3261 §22.1).
    ///
    /// Raised before the refusal settles the usual way (call ended with the
    /// 401/407, [`RegistrationFailure::BadCredentials`], in-call request
    /// refused). Nothing is sent because every answer helps an offline
    /// password search by whoever chose the nonce (RFC 7616 §5.10, §5.11).
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
    /// The account's server wants an OAuth 2.0 access token (RFC 8898) and
    /// the account has none it accepts: none supplied, or the one supplied
    /// was refused (`invalid_token`, RFC 6750 §3.1).
    ///
    /// Fetching it is the application's, from `challenge.authz_server`, which
    /// it MUST check against its trusted list (RFC 8898 §2.1.1). Hand it over
    /// with [`UserAgent::set_access_token`](crate::UserAgent::set_access_token);
    /// it is used from the next request on. Meanwhile the refusal settles as
    /// an unanswered challenge does. Only for the account's own server;
    /// anybody else's is [`UaEvent::ChallengeDeclined`].
    TokenRequired {
        /// Whose token is wanted.
        account: AccountId,
        /// Where the challenged request went, and the challenge came from.
        from: std::net::SocketAddr,
        /// The challenge: realm, scope, authorization server and error.
        challenge: sipral_core::auth::BearerChallenge,
    },
    /// The verification service's verdict on the caller (RFC 8224 §6.2).
    ///
    /// Queued immediately before the matching [`UaEvent::IncomingCall`],
    /// whose identity carries the same verdict. Under
    /// [`StirVerification::Strict`](crate::StirVerification::Strict), a call
    /// that failed has `verification.refused` set, has been answered as
    /// §6.2.2 prescribes, and [`UaEvent::CallEnded`] follows instead.
    ///
    /// Never raised with [`StirVerification::Off`](crate::StirVerification::Off)
    /// or on an agent with no trust anchors.
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
    /// A provisional response: ringing, or early media.
    CallProgress {
        /// The call.
        call: CallHandle,
        /// Where it is now.
        state: CallState,
        /// The status.
        status: StatusCode,
        /// The response, whole; early media is in it when there is any.
        response: OwnedMessage,
        /// The response carries an offer whose answer goes in the PRACK
        /// (RFC 3262 §5). Only for a call placed without an offer; until
        /// [`UserAgent::answer_early`](crate::UserAgent::answer_early) is
        /// called the response is retransmitted and the call waits.
        answer_wanted: bool,
    },
    /// A proxy forked the INVITE and a second dialog opened.
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
    /// offer is in this 2xx, and its answer goes in the ACK through
    /// [`UserAgent::acknowledge`](crate::UserAgent::acknowledge). Otherwise
    /// the ACK has already gone, since an unacknowledged 2xx gets the call
    /// hung up after 32 seconds.
    CallConfirmed {
        /// The call.
        call: CallHandle,
        /// The 2xx, for a call this end placed. Absent for one it answered:
        /// this end wrote that response and the ACK is what arrived.
        response: Option<OwnedMessage>,
        /// Whether the ACK is waiting for a session description.
        answer_wanted: bool,
    },
    /// The session changed: a hold, a resume, or an accepted offer from
    /// either end.
    ///
    /// Both descriptions are given because the held version of an offer is
    /// derived here (RFC 3264 §8.4) and this is the only place it is seen.
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
    /// The far end offered a change this layer has no policy for (codec swap,
    /// added stream). A body that is not a session description never arrives
    /// here: it is refused 415, or ignored if marked optional (RFC 3261
    /// §8.2.3).
    ///
    /// The transaction is held open. Answer with
    /// [`UserAgent::accept_reoffer`](crate::UserAgent::accept_reoffer) or
    /// [`UserAgent::reject_reoffer`](crate::UserAgent::reject_reoffer); an
    /// unanswered re-INVITE ends the call.
    Reoffer {
        /// The call.
        call: CallHandle,
        /// The re-INVITE or UPDATE, whole.
        request: OwnedMessage,
    },
    /// A change this end offered was refused, or will not be answered.
    ///
    /// The session stands as it was (§14.1). `retry_in` is set only for a
    /// 491 (crossed offers): the change goes out again by itself after it.
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
    /// [`UserAgent::accept_transfer`](crate::UserAgent::accept_transfer)
    /// answers 202 and places the call;
    /// [`UserAgent::reject_transfer`](crate::UserAgent::reject_transfer)
    /// refuses. Left unanswered for 64·T1, the stack answers 408 and the call
    /// takes the next REFER as if this one never came.
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
    /// Progress of a transfer this end asked for, from the far end's
    /// `message/sipfrag` (RFC 3515 §2.4.5).
    TransferProgress {
        /// The call that was transferred.
        call: CallHandle,
        /// What the far end's own call is doing.
        status: StatusCode,
    },
    /// How a transfer ended. Success hangs this call up; failure leaves it
    /// as it was.
    ///
    /// Also reported here: a REFER refused outright (4xx–6xx, no NOTIFY
    /// follows, §2.4.2), one unanswered (408), or one whose transport failed
    /// (503, RFC 3261 §8.1.3.1).
    TransferDone {
        /// The call that was transferred.
        call: CallHandle,
        /// The final status the far end reported.
        status: StatusCode,
    },
    /// An out-of-dialog REFER asks this end to place a call (RFC 3515):
    /// click-to-dial from a switchboard or a CRM.
    ///
    /// Raised only with
    /// [`UserAgent::allow_referrals`](crate::UserAgent::allow_referrals) on,
    /// and only after the same screening an INVITE gets.
    /// [`UserAgent::accept_transfer`](crate::UserAgent::accept_transfer) on
    /// `referral` answers 202 and places the call from `account`;
    /// [`UserAgent::reject_transfer`](crate::UserAgent::reject_transfer)
    /// refuses. Always the application's decision, because it is a toll-fraud
    /// vector (see [`crate::referral`]). Unanswered for 64·T1, it becomes
    /// [`UaEvent::ReferralLapsed`].
    ReferralRequested {
        /// A call-kind handle that names only this request until it is
        /// answered or lapses.
        referral: CallHandle,
        /// The line it was addressed to (Request-URI or `To`), and the one
        /// the call is placed from.
        account: AccountId,
        /// Who to call.
        target: sipral_core::msg::Uri,
        /// Whether its `Refer-To` named a dialog to replace (RFC 3891).
        attended: bool,
        /// Its `Referred-By`, when it carried exactly one (RFC 3892 §2.1).
        /// Written by the sender: context, never proof.
        referred_by: Option<Box<[u8]>>,
        /// The REFER, whole.
        request: OwnedMessage,
    },
    /// A referral nobody answered before its transaction ran out (RFC 3515
    /// §2.4.2); the stack answered it. Its handle names nothing from here on.
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
    /// `state` is granted or still pending (§4.1.3); nothing is known about
    /// the resource until it is `active`. `expires` is what the notifier
    /// granted (§3.1.1). Sent on state changes only, not on every refresh.
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
    /// Two notifiers answered one SUBSCRIBE, so there are now two
    /// subscriptions (RFC 6665 §4.1.4).
    ///
    /// `sibling` has its own dialog, refresh and state. For dialog state this
    /// is normal: one per registered device (RFC 4235 §3.9).
    SubscriptionForked {
        /// The one that was already known.
        subscription: SubscriptionHandle,
        /// The one that has just appeared.
        sibling: SubscriptionHandle,
    },
    /// A NOTIFY arrived and has been answered (RFC 6665 §4.1.3).
    ///
    /// `info` is set for a readable `application/dialog-info+xml` body and
    /// holds only what changed (RFC 4235 §3.8); the merged picture is
    /// [`UserAgent::dialog_info`](crate::UserAgent::dialog_info). An
    /// unreadable body changes neither and arrives as `None`, so the lamp
    /// keeps showing what was last known.
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
    /// `retry_in` is set when a fresh subscription will start by itself under
    /// the same handle (new Call-ID and From tag, §4.1.2.2); absent, the
    /// handle names nothing from here on. Either way
    /// [`UserAgent::dialog_info`](crate::UserAgent::dialog_info) answers
    /// nothing for it.
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
    /// A MESSAGE arrived (RFC 3428 §7) and was already answered 200: this
    /// stack delivers rather than relays.
    ///
    /// `account` is absent as for [`UaEvent::IncomingCall`]. `call` is set
    /// when the MESSAGE came inside a dialog (§4). Content type and body are
    /// read from `request`.
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
    /// `status`: 200 delivered, 202 accepted by a relay that cannot promise
    /// delivery (§4), 415 with the far end's `Accept`, 413 over its size
    /// limit, or 408/503 for a timeout or lost transport (RFC 3261 §8.1.3.1).
    MessageSent {
        /// Which send.
        message: MessageHandle,
        /// The final status.
        status: StatusCode,
        /// The response, whole, when there was one.
        response: Option<OwnedMessage>,
    },
    /// A probe of an account's server ([`UserAgent::probe_server`](crate::UserAgent::probe_server))
    /// was answered, or never will be.
    ServerProbed {
        /// Which probe.
        probe: crate::ProbeHandle,
        /// Whose server.
        account: AccountId,
        /// What came of it.
        outcome: crate::ProbeOutcome,
    },
    /// A message-summary NOTIFY reported a mailbox (RFC 3842 §3.9).
    ///
    /// The counts are the `voice-message` class's (RFC 3458 §6.2); every class
    /// is in [`UserAgent::message_summary`](crate::UserAgent::message_summary).
    /// `waiting` is the §3.5 status line, present even when the body names no
    /// `voice-message` (the counts are then zero).
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
    /// A `conference` subscription's picture changed, or the conference ended
    /// (RFC 4575 §4.6). The picture is
    /// [`UserAgent::conference`](crate::UserAgent::conference).
    ///
    /// Only for a merged document. A late or repeated one is silent; one that
    /// cannot be merged (its predecessor never arrived) triggers a request
    /// for full state, and the picture stands until it comes.
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
    /// State kept at a compositor (RFC 3903) was published, refreshed,
    /// lapsed, removed, or refused.
    ///
    /// Never [`PublishEvent::Challenged`](crate::PublishEvent::Challenged):
    /// the account's credentials answer it, and when they cannot it is a
    /// [`PublishEvent::Failed`](crate::PublishEvent::Failed) with the 401 or
    /// 407.
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
        /// The far end's BYE or CANCEL, whole, when that is how it ended, so
        /// its own header fields can be read.
        request: Option<OwnedMessage>,
        /// The `Reason` values (RFC 3326) of the BYE, CANCEL, or refusal
        /// (RFC 6432), one per protocol, in order; empty when none. A forking
        /// proxy's CANCEL of a losing branch carries
        /// [`Reason::is_completed_elsewhere`](crate::Reason::is_completed_elsewhere):
        /// answered on another phone, not missed.
        causes: Box<[crate::Reason]>,
    },
    /// An INFO sent for [`UserAgent::send_dtmf_info`](crate::UserAgent::send_dtmf_info)
    /// reached a final answer.
    ///
    /// `status` is whatever the far end or a proxy sent (200, 415, ...). No
    /// answer is reported per RFC 3261 §8.1.3.1: 408 on timeout, 503 on
    /// transport failure. A challenge the account cannot answer gives its
    /// 401 or 407. A queued digit whose INFO could not be sent at all is a
    /// 503, and nothing reached the far end.
    DtmfSent {
        /// The call the INFO went out on, or was to go out on.
        call: CallHandle,
        /// The digit that was sent, or could not be.
        digit: char,
        /// What the far end answered, or the status that stands for the
        /// answer that never came.
        status: StatusCode,
    },
    /// A digit arrived by SIP INFO (RFC 6086) as `application/dtmf-relay` or
    /// `application/dtmf` (see `docs/04-ua.md`; neither has an RFC).
    ///
    /// The facade above merges this with RFC 4733 digits into one
    /// `DigitReceived`; it cannot happen here because this layer has no media.
    DtmfReceived {
        /// The call the INFO arrived in.
        call: CallHandle,
        /// The digit.
        digit: char,
        /// `application/dtmf-relay`'s `Duration=`, when the body carried one.
        held_ms: Option<u32>,
    },
    /// The lifecycle machine moved: sleep, wake, or a different network.
    ///
    /// `rung` is what was just done and `next_in` when the next step goes. A
    /// [`Rung::WantTransport`] or [`Rung::WantAddress`] is a request: nothing
    /// here opens sockets or resolves names, so recovery waits for
    /// [`UserAgent::rebind`](crate::UserAgent::rebind) or for the wait to run
    /// out.
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
    /// Hand every answer, failures included, to
    /// [`UserAgent::looked_up`](crate::UserAgent::looked_up); the procedure
    /// waits for each. Several can be outstanding, one per SRV target host.
    LookupWanted {
        /// The account whose server is being located.
        account: AccountId,
        /// The name and the kind of record to ask for.
        query: sipral_core::endpoint::Query,
    },
    /// An account's server was located, or relocated after the TTL ran out.
    Located {
        /// The account.
        account: AccountId,
        /// The addresses, in RFC 3263 §4.3's order from the one in use.
        targets: Vec<std::net::SocketAddr>,
    },
    /// A lookup of an account's server named no address. A waiting REGISTER
    /// fails too and backs off; otherwise the lookup repeats after
    /// `retry_in`. An address from an earlier answer stays in use.
    LocateFailed {
        /// The account.
        account: AccountId,
        /// Why.
        reason: sipral_core::endpoint::LocateError,
        /// How long until the next lookup.
        retry_in: Duration,
    },
    /// The network changed ([`Recovery::Rebuild`](crate::Recovery::Rebuild))
    /// and the far end still sends this call's audio to the old address.
    ///
    /// One per call that can still take a new offer (up, or early with
    /// UPDATE). The application binds a socket on the new network and
    /// re-offers, with `sipral::MediaEngine::readdress` or
    /// [`UserAgent::change_formats`](crate::UserAgent::change_formats).
    /// Call [`UserAgent::rebind`](crate::UserAgent::rebind) first so the
    /// re-INVITE carries the new `Contact`.
    CallAddressWanted {
        /// The call.
        call: CallHandle,
    },
    /// Every rung of a recovery ladder failed. Nothing more happens by
    /// itself.
    ///
    /// Bindings whose REGISTER reached a transport keep their own back-off;
    /// `unverified` counts those nothing is retrying.
    RecoveryGaveUp {
        /// The last thing that was tried.
        rung: Rung,
        /// Why it stopped.
        reason: RecoveryFailure,
        /// Bindings left unproved.
        unverified: usize,
    },
    /// A protocol event this layer has no policy for, passed through
    /// uninterpreted.
    ///
    /// Exception: a request no handler claims is answered here (405 with
    /// `Allow`, 501, or 481 per RFC 3261 §8.2.1 and RFC 5057 §5.3; RFC 6086
    /// §4.2.2 for INFO) and never arrives as `Event::IncomingOutOfDialog` or
    /// `Event::IncomingInDialog`. The one exception to that is a non-DTMF INFO
    /// in a call after
    /// [`UserAgent::hand_over_info`](crate::UserAgent::hand_over_info)
    /// (`docs/04-ua.md`).
    Unclaimed(Event),
}
