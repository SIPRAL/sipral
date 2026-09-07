// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the user agent tells the application.
//!
//! One vocabulary, and it is about accounts and calls rather than about
//! transactions. What the layer below says is not hidden — an event this layer
//! has no policy for is passed through whole — but everything it does have a
//! policy for arrives already decided: a registration that is live, one that
//! is being retried and when, one that will never succeed and why.

use std::time::Duration;

use sipral_core::endpoint::Event;
use sipral_core::msg::{OwnedMessage, StatusCode};

use crate::account::AccountId;
use crate::call::{CallEndReason, CallHandle, CallState};

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
    /// Something recoverable went wrong and the next attempt is scheduled.
    Retrying,
    /// The binding was given up on purpose.
    Unregistered,
    /// The registrar refused in a way that trying again cannot fix.
    Failed,
}

impl core::fmt::Display for RegistrationState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Idle => "idle",
            Self::Registering => "registering",
            Self::Registered => "registered",
            Self::Refreshing => "refreshing",
            Self::Retrying => "retrying",
            Self::Unregistered => "unregistered",
            Self::Failed => "failed",
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
    /// before the binding lapses.
    Registered {
        /// Which account.
        account: AccountId,
        /// The granted lifetime of the binding.
        expires: Duration,
        /// How long until the refresh.
        refresh_in: Duration,
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
    },
    /// A protocol event this layer has no policy for.
    ///
    /// Registration is what `sipral-ua` owns today; calls, subscriptions and
    /// transfers arrive here whole, and an application that needs one now acts
    /// on it directly. Nothing the endpoint says is dropped on the way
    /// through, and nothing that passes here has been interpreted.
    Unclaimed(Event),
}
