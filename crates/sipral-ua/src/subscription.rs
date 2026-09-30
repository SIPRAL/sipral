// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Subscriptions: asking to be told, and staying told (RFC 6665).
//!
//! A subscription is a standing question. It is asked with a SUBSCRIBE, it is
//! answered with NOTIFY requests for as long as it lasts, and the whole of the
//! difficulty is that it lasts — an hour at a time, thirty of them at once, on
//! a phone that gets suspended, moved between networks and pointed at a PBX
//! that reboots. Everything here exists because one of those happens.
//!
//! **The dialog is opened by the NOTIFY, not by the 200.** §4.4.1 is explicit:
//! "the dialog usage is established by the NOTIFY request, the route set at
//! the subscriber is taken from the NOTIFY request itself, as opposed to the
//! route set present in the 200-class response to the SUBSCRIBE request". A
//! stack that opens the dialog on the 2xx has the wrong route set, and sends
//! its refresh past the proxy that record-routed itself. So the SUBSCRIBE goes
//! out of dialog, the first NOTIFY is what makes a dialog, and §4.1.2.4 says
//! in as many words that the NOTIFY may arrive **before** the answer to the
//! SUBSCRIBE: "Due to the potential for out-of-order messages, packet loss,
//! and forking, the subscriber MUST be prepared to receive NOTIFY requests
//! before the SUBSCRIBE transaction has completed." It does, on real
//! equipment, and a subscription that is only matched once the 2xx has landed
//! answers that first notification 481 and kills itself.
//!
//! Which is why a subscription is matched by what §4.4.1 says and by nothing
//! else: the same `Call-ID`, a `To` tag on the NOTIFY equal to the `From` tag
//! of the SUBSCRIBE, and an `Event` that matches byte for byte. All three are
//! known the instant the SUBSCRIBE is handed to a transport, which is why the
//! tag is chosen here rather than left to the endpoint to mint.
//!
//! **Timer N is the one that stops a subscription hanging.** §4.1.2.4 starts
//! it at 64·T1 when the SUBSCRIBE goes and stops it at the first NOTIFY; if it
//! fires, there is no subscription and there never was one, however cheerful
//! the 200 was. Without it a notifier that accepts and then says nothing
//! leaves a lamp dark for ever and a record that nothing will ever collect.
//!
//! **A failure is an event, and it leaves nothing behind.** The first
//! SUBSCRIBE can fail before it reaches a socket — the interface it named has
//! gone, a name no longer resolves, the transport was closed under it — and
//! that is not an error of the call the application made, because by then the
//! subscription has a name. So the handle is minted first, the failure is
//! reported under it, and the record is removed in the same breath: no timer
//! is scheduled, no map keeps an entry, and there is nothing for a later sweep
//! to trip over. The same path runs for a refresh that cannot be sent and for
//! a re-subscription that fires while the network is still down.
//!
//! **Thirty subscriptions are not thirty round trips.** Nothing here waits for
//! anything: [`UserAgent::subscribe`] hands one SUBSCRIBE to the endpoint and
//! returns, so thirty calls put thirty requests in the transmit queue and the
//! application writes them in one pass over `poll_transmit`. What
//! [`UserAgent::subscribe_many`] adds is that the whole batch is drained once
//! instead of thirty times, and that a target which cannot be sent to becomes
//! an event rather than stopping the twenty-nine after it. There is nothing
//! else the stack can do about it and it should not pretend otherwise: it owns
//! no socket, so it cannot pace, and pacing is what an application does by
//! calling this more than once.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::dialog::CallId;
use sipral_core::endpoint::{
    Event, FailureReason, OutgoingInDialogRequest, OutgoingRequest, OutgoingResponse, TransportId,
};
use sipral_core::msg::{
    EventRef, HeaderName, Method, OwnedMessage, RawMessage, StatusCode, SubscriptionStateRef,
    Substate, Uri,
};
use sipral_core::transaction::{AnyTransactionId, DialogId, NonInviteClient, TransactionId};

use crate::account::{Account, AccountId, Extra};
use crate::agent::UserAgent;
use crate::conference::{Conference, ConferenceUpdate};
use crate::dialoginfo::{Applied, DialogInfo, DialogInfoTable};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::mwi::MessageSummary;
use crate::parked::{Parked, call_needs_a_stream};
use crate::presence::Presence;
use crate::registration::{
    RegistrarInfo, anonymous, backoff_delay, dialog_contact, refresh_after, retry_after,
};

/// How long a subscription asks for when nothing says otherwise.
///
/// RFC 4235 §3.4: "In another case, a subscriber is interested in the state of
/// all dialogs for a specific user. In these cases, a shorter interval makes
/// more sense. The default is one hour for these subscriptions." Which is what
/// a busy lamp field is, and it is the same hour a registration asks for, so a
/// phone wakes up for both at about the same time rather than twice as often.
pub const DEFAULT_EXPIRES: Duration = Duration::from_hours(1);

/// One subscription the application is watching.
///
/// Minted before anything is sent, so that a SUBSCRIBE which never reaches a
/// transport still has a name to be reported under. Never reused, so a handle
/// to a subscription that has ended names nothing rather than naming somebody
/// else's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionHandle(pub(crate) u32);

/// Where a subscription is (RFC 6665 §4.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubscriptionState {
    /// A SUBSCRIBE is out and no NOTIFY has arrived. The RFC's `notify_wait`,
    /// and the only state Timer N runs in.
    Requesting,
    /// The notifier has it and has not decided whether to grant it. §4.1.3:
    /// "there is insufficient policy information to grant or deny the
    /// subscription yet". Nothing is known about the resource.
    Pending,
    /// Notifications are arriving and the state is being kept up to date.
    Active,
    /// It ended in a way worth trying again, and the next attempt is
    /// scheduled. Nothing is known about the resource until it succeeds.
    ///
    /// There is no state past this one. A subscription that has ended for good
    /// has no record left to be in a state — the handle names nothing, and
    /// [`UaEvent::SubscriptionEnded`] with no `retry_in` was the last word.
    Retrying,
}

impl SubscriptionState {
    /// Whether what the notifier last said can still be believed.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Active | Self::Pending)
    }
}

impl core::fmt::Display for SubscriptionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Requesting => "requesting",
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Retrying => "retrying",
        })
    }
}

/// Why a subscription is not live.
///
/// The first seven are §4.1.3's own reason codes, carried through as the
/// notifier sent them, because each says something different about whether to
/// ask again and the RFC spells out which. The rest are this end's, for the
/// failures that never reach a notifier at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubscriptionEnd {
    /// `reason=deactivated`: the notifier is handing the subscription on.
    /// "the subscriber SHOULD retry immediately with a new subscription".
    Deactivated,
    /// `reason=probation`: come back later, and `retry-after` says when.
    Probation,
    /// `reason=rejected`: authorisation changed. "Clients SHOULD NOT attempt
    /// to re-subscribe."
    Rejected,
    /// `reason=timeout`: it lapsed without being refreshed. Also what a poll
    /// gets (§4.4.3), which is a subscription that was never meant to last.
    Timeout,
    /// `reason=giveup`: the notifier could not get authorisation in time.
    GaveUp,
    /// `reason=noresource`: there is nothing there to watch any more.
    /// "Clients SHOULD NOT attempt to re-subscribe."
    NoResource,
    /// `reason=invariant`: the state is guaranteed not to change again.
    Invariant,
    /// The notifier said `terminated` and gave no reason, or one nothing here
    /// knows. §4.1.3 leaves retrying open, so it is retried.
    Unstated,
    /// The application asked, with an `Expires: 0` (§4.1.2.3).
    Unsubscribed,
    /// A 489: the notifier does not know the event package. Asking again with
    /// the same package gets the same answer.
    BadEvent,
    /// The notifier refused in a way that trying again cannot fix: a 403, a
    /// 404, or one of the other final responses §4.1.2.2 lists.
    Refused,
    /// A 3xx naming somewhere else. Following it needs an address, and
    /// resolving one is the caller's, so it is reported rather than chased.
    Redirected,
    /// The notifier is not answering, or says it cannot serve this now: a
    /// timeout, a dead transport, a 5xx.
    Unreachable,
    /// The SUBSCRIBE was accepted and no NOTIFY followed within 64·T1
    /// (§4.1.2.4's Timer N). There is no subscription, whatever the 200 said.
    NoNotify,
    /// The subscription reached the end of what the notifier granted and
    /// nothing refreshed it in time.
    Expired,
}

impl SubscriptionEnd {
    /// Whether asking again could give a different answer.
    ///
    /// §4.1.3 decides the notifier's half of this, and it decides it per
    /// reason code: `rejected`, `noresource` and `invariant` are the three it
    /// tells clients not to come back from. The rest is this end's, and it is
    /// the same split registration makes — a refusal about the resource will
    /// be made again, an outage will not. `Expired` sits with the refusals
    /// rather than the outages, and for a third reason that is neither: it is
    /// not the notifier answering and it is not a failure to reach one, it is
    /// this end letting the granted lifetime run out with nothing having
    /// refreshed it in time. Asking again after that is subscribing, not
    /// retrying, and `subscribe` is the call for it; the back-off this answer
    /// drives is for a subscription that ended against this end's will.
    #[must_use]
    pub const fn is_worth_retrying(self) -> bool {
        !matches!(
            self,
            Self::Rejected
                | Self::NoResource
                | Self::Invariant
                | Self::Unsubscribed
                | Self::BadEvent
                | Self::Refused
                | Self::Redirected
                | Self::Expired
        )
    }

    /// The reason code as §4.1.3 names it, or `None` for one this end minted.
    #[must_use]
    pub const fn as_reason(self) -> Option<&'static str> {
        Some(match self {
            Self::Deactivated => "deactivated",
            Self::Probation => "probation",
            Self::Rejected => "rejected",
            Self::Timeout => "timeout",
            Self::GaveUp => "giveup",
            Self::NoResource => "noresource",
            Self::Invariant => "invariant",
            _ => return None,
        })
    }

    fn read(reason: Option<&[u8]>) -> Self {
        let Some(reason) = reason else {
            return Self::Unstated;
        };
        // §8.4's event-reason-value is a token, and tokens fold case
        for (name, value) in [
            (&b"deactivated"[..], Self::Deactivated),
            (b"probation", Self::Probation),
            (b"rejected", Self::Rejected),
            (b"timeout", Self::Timeout),
            (b"giveup", Self::GaveUp),
            (b"noresource", Self::NoResource),
            (b"invariant", Self::Invariant),
        ] {
            if reason.eq_ignore_ascii_case(name) {
                return value;
            }
        }
        Self::Unstated
    }
}

impl core::fmt::Display for SubscriptionEnd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Deactivated => "moved to another notifier",
            Self::Probation => "on probation",
            Self::Rejected => "not authorised",
            Self::Timeout => "lapsed at the notifier",
            Self::GaveUp => "authorisation took too long",
            Self::NoResource => "nothing there to watch",
            Self::Invariant => "will never change again",
            Self::Unstated => "terminated without a reason",
            Self::Unsubscribed => "unsubscribed",
            Self::BadEvent => "event package not supported",
            Self::Refused => "refused",
            Self::Redirected => "notifier moved",
            Self::Unreachable => "notifier unreachable",
            Self::NoNotify => "accepted and never notified",
            Self::Expired => "expired",
        })
    }
}

/// What to subscribe to, and how.
#[derive(Clone, Debug)]
pub struct Subscribe {
    pub(crate) target: Uri,
    pub(crate) package: Box<[u8]>,
    pub(crate) accept: Option<Box<[u8]>>,
    pub(crate) expires: Duration,
    pub(crate) destination: Option<(TransportId, std::net::SocketAddr)>,
    pub(crate) extra: Vec<Extra>,
}

impl Subscribe {
    /// Subscribe to `package` at `target`.
    ///
    /// The package is the token that names it: `dialog` for a busy lamp field
    /// (RFC 4235 §3.1), `message-summary` for message waiting (RFC 3842 §3),
    /// `presence` (RFC 3856 §6.1). §8.2.1 compares it byte for byte, so it
    /// goes out exactly as written here.
    ///
    /// It leaves on the account's transport, for the account's address: the
    /// one it registers with — the outbound proxy for a registered line, which
    /// is why a softphone behind a NAT works at all — or, for an account that
    /// never registers, the outbound proxy it was given
    /// ([`crate::Account::unregistered`]).
    #[must_use]
    pub fn new(target: Uri, package: &str) -> Self {
        Self {
            target,
            package: Box::from(package.as_bytes()),
            accept: None,
            expires: DEFAULT_EXPIRES,
            destination: None,
            extra: Vec::new(),
        }
    }

    /// How long to ask for.
    ///
    /// What the notifier grants wins (§3.1.1: "The period of time in the
    /// response is the one that defines the duration of the subscription"),
    /// and the refresh is scheduled against that rather than against this.
    #[must_use]
    pub const fn expires(mut self, expires: Duration) -> Self {
        self.expires = expires;
        self
    }

    /// The `Accept` value, when the package's default body type is not the one
    /// wanted.
    ///
    /// Left out, no `Accept` goes at all, which §3.1.3 makes the package's
    /// default: `application/dialog-info+xml` for `dialog` (RFC 4235 §3.5).
    /// Sending the wrong one is worse than sending none — §4.1.2.1 has the
    /// notifier answer 406 for a type it cannot generate — so nothing is
    /// guessed on the caller's behalf.
    #[must_use]
    pub fn accept(mut self, media_type: &[u8]) -> Self {
        self.accept = Some(Box::from(media_type));
        self
    }

    /// Send it somewhere other than the account's address.
    ///
    /// Resolving a name is the caller's, here as everywhere: this takes the
    /// answer, not the question.
    #[must_use]
    pub const fn to_address(
        mut self,
        transport: TransportId,
        remote: std::net::SocketAddr,
    ) -> Self {
        self.destination = Some((transport, remote));
        self
    }

    /// A header field on every SUBSCRIBE this subscription sends.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'_>, value: &[u8]) -> Self {
        self.extra.push(Extra {
            name: Box::from(name.canonical().as_bytes()),
            value: Box::from(value),
        });
        self
    }
}

/// What the one deadline a subscription holds is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Waiting {
    /// Timer N: 64·T1 from the SUBSCRIBE to the first NOTIFY (§4.1.2.4).
    Notify,
    /// The refresh, at a fraction of what was granted.
    Refresh,
    /// The next attempt after something recoverable went wrong.
    Retry,
}

/// Everything one subscription is doing.
#[derive(Debug)]
pub(crate) struct Subscription {
    pub(crate) state: SubscriptionState,
    pub(crate) account: AccountId,
    /// What was asked for, kept because §4.1.2.2 has a re-subscription send it
    /// again from the beginning rather than repair the old one.
    wanted: Subscribe,
    /// §4.4.1 matches a NOTIFY to a SUBSCRIBE on this and the tag below.
    call_id: CallId,
    /// Ours, chosen here rather than left to the endpoint, because a
    /// notification can arrive before the answer that would have told us what
    /// the endpoint chose.
    local_tag: Box<[u8]>,
    /// The notifier's, once a NOTIFY has named it. What tells one fork from
    /// another (§4.1.4).
    remote_tag: Option<Box<[u8]>>,
    /// The number the last out-of-dialog SUBSCRIBE carried, so the dialog the
    /// NOTIFY opens continues the series instead of restarting it.
    cseq: u32,
    /// The dialog the first NOTIFY opened (§4.4.1).
    dialog: Option<DialogId>,
    /// The last duration the notifier stated, from the 2xx (§3.1.1) or from a
    /// `Subscription-State` (§4.1.3).
    granted: Duration,
    /// When the subscription is over if nothing refreshes it.
    lapses_at: Option<Instant>,
    /// The next thing this layer does about it, and what that is.
    due: Option<(Instant, Waiting)>,
    /// How long a NOTIFY may still open a *second* dialog on this attempt.
    /// §4.1.2.4: "Until Timer N expires, several NOTIFY requests may arrive
    /// from different destinations. Each of these requests establishes a new
    /// dialog usage and a new subscription."
    forks_until: Option<Instant>,
    /// Consecutive failures worth retrying, which is what the back-off counts.
    failures: u32,
    /// An `Expires: 0` is in flight and its answer is not a subscription.
    unsubscribing: bool,
    /// A challenge came back and it is not yet known whether anything could
    /// read it. The refusal is kept for the event that says so.
    pub(crate) unanswered: Option<OwnedMessage>,
    /// The challenged SUBSCRIBE whose answer §18.1.1 would not let out over a
    /// datagram, waiting for the connection the endpoint asked for. While
    /// this is set the refusal above is not a refusal yet.
    pub(crate) waiting_for_stream: Option<AnyTransactionId>,
    /// RFC 4235 §4.3's table, for the one package that has one.
    table: DialogInfoTable,
    /// The last `application/simple-message-summary` document a `NOTIFY`
    /// carried (RFC 3842 §3.5). Unlike `table`, this is a whole snapshot
    /// every time — §3.5 defines no version and no partial state — so
    /// nothing here merges; a fresh document simply replaces it.
    summary: Option<Arc<MessageSummary>>,
    /// What a `conference` subscription has been told, merged (RFC 4575
    /// §4.6). Started afresh with every attempt, because `version` numbers
    /// the documents of one subscription and not of the next.
    conference: Conference,
    /// The last `application/pidf+xml` document a `presence` subscription
    /// was told (RFC 3856 §6.8): full state every time, so replaced whole.
    presence: Option<Arc<Presence>>,
}

impl Subscription {
    fn new(account: AccountId, wanted: Subscribe, call_id: CallId, local_tag: Box<[u8]>) -> Self {
        Self {
            state: SubscriptionState::Requesting,
            account,
            wanted,
            call_id,
            local_tag,
            remote_tag: None,
            cseq: 0,
            dialog: None,
            granted: Duration::ZERO,
            lapses_at: None,
            due: None,
            forks_until: None,
            failures: 0,
            unsubscribing: false,
            unanswered: None,
            waiting_for_stream: None,
            table: DialogInfoTable::default(),
            summary: None,
            conference: Conference::new(),
            presence: None,
        }
    }

    /// The one a fork of this attempt starts from (§4.1.4).
    ///
    /// Same question, same identity, same numbering — a different notifier
    /// answered it, and §4.4.1 gives that its own dialog and its own state
    /// machine. It does not carry the fork window: a second fork is measured
    /// against the attempt that produced it, not against its siblings.
    fn fork(&self) -> Self {
        Self {
            state: SubscriptionState::Requesting,
            account: self.account,
            wanted: self.wanted.clone(),
            call_id: self.call_id.clone(),
            local_tag: self.local_tag.clone(),
            remote_tag: None,
            cseq: self.cseq,
            dialog: None,
            granted: self.granted,
            lapses_at: None,
            due: None,
            forks_until: None,
            failures: 0,
            unsubscribing: false,
            unanswered: None,
            waiting_for_stream: None,
            table: DialogInfoTable::default(),
            summary: None,
            conference: Conference::new(),
            presence: None,
        }
    }

    /// When this layer next has something to do about it.
    fn deadline(&self) -> Option<Instant> {
        match (self.due.map(|(at, _)| at), self.lapses_at) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    /// Forget every deadline this layer scheduled.
    ///
    /// Called only from `distrust`, on a subscription it is about to demote:
    /// once `dialog_info` stops being evidence, a refresh or a lapse due
    /// against a clock that stopped while the machine slept is not evidence
    /// either, and left alone it would fire against a wall-clock reading it
    /// was never measured for. `UserAgent::resubscribe` is what re-arms it.
    pub(crate) fn stop_timers(&mut self) {
        self.due = None;
        self.lapses_at = None;
        self.forks_until = None;
    }
}

// -- what the application asks for -------------------------------------------

impl UserAgent {
    /// Subscribe, and keep the subscription alive until told otherwise
    /// (RFC 6665).
    ///
    /// Refreshes, credential retries, re-subscription after an outage and the
    /// coherent state of the package all happen without another call. What
    /// stops it is [`UserAgent::unsubscribe`], or a refusal that trying again
    /// cannot fix.
    ///
    /// The handle comes back whether or not the SUBSCRIBE reached a transport.
    /// One that did not is reported as [`UaEvent::SubscriptionEnded`] with
    /// [`SubscriptionEnd::Unreachable`] and no `retry_in`, and nothing is left
    /// scheduled — the handle names nothing from that moment. It is one event
    /// rather than one error because every later failure of the same
    /// subscription arrives that way, and an application should not have two
    /// places to look.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`].
    pub fn subscribe(
        &mut self,
        account: AccountId,
        wanted: &Subscribe,
        now: Instant,
    ) -> Result<SubscriptionHandle, UaError> {
        let handle = self.mint_subscription(account, wanted)?;
        self.start_subscription(handle, now);
        self.drain(now);
        Ok(handle)
    }

    /// Subscribe to several things at once.
    ///
    /// A busy lamp field is twenty to forty of these and they all go up when
    /// the phone starts. Nothing here waits for anything, so the batch leaves
    /// as one burst of requests into the transmit queue rather than as one
    /// round trip after another; what this adds over calling
    /// [`UserAgent::subscribe`] in a loop is that the events are drained once
    /// at the end, and that a target which cannot be sent to becomes an event
    /// instead of stopping the ones behind it.
    ///
    /// Every handle comes back, in the order asked for, including the ones
    /// whose request never left. Those have already queued their
    /// [`UaEvent::SubscriptionEnded`].
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], before anything is sent.
    pub fn subscribe_many(
        &mut self,
        account: AccountId,
        wanted: &[Subscribe],
        now: Instant,
    ) -> Result<Vec<SubscriptionHandle>, UaError> {
        // asked once rather than once per target, so that a batch either mints
        // every handle or none: a partial one would leave records nothing has
        // a name for
        if !self.accounts.contains_key(&account) {
            return Err(UaError::NoSuchAccount);
        }
        let mut handles = Vec::with_capacity(wanted.len());
        for one in wanted {
            handles.push(self.mint_subscription(account, one)?);
        }
        for handle in &handles {
            self.start_subscription(*handle, now);
        }
        self.drain(now);
        Ok(handles)
    }

    /// Give the subscription up: a SUBSCRIBE with `Expires: 0` (§4.1.2.3).
    ///
    /// The subscription is not over when this returns. §4.4.1: "the
    /// subscription is not considered terminated until the NOTIFY transaction
    /// with a `Subscription-State` of `terminated` completes" — so the closing
    /// notification is still answered, and [`UaEvent::SubscriptionEnded`] with
    /// [`SubscriptionEnd::Unsubscribed`] says when it has. One that has no
    /// dialog yet has nothing to send this in, and ends at once.
    ///
    /// # Errors
    /// [`UaError::NoSuchSubscription`].
    pub fn unsubscribe(
        &mut self,
        subscription: SubscriptionHandle,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self
            .subscriptions
            .get_mut(&subscription)
            .ok_or(UaError::NoSuchSubscription)?;
        let Some(dialog) = held.dialog else {
            self.end_subscription(subscription, SubscriptionEnd::Unsubscribed, None, None);
            self.drain(now);
            return Ok(());
        };
        held.unsubscribing = true;
        if self
            .send_in_dialog(subscription, dialog, Duration::ZERO, now)
            .is_err()
        {
            self.end_subscription(subscription, SubscriptionEnd::Unsubscribed, None, None);
        }
        self.drain(now);
        Ok(())
    }

    /// Where a subscription is.
    #[must_use]
    pub fn subscription_state(
        &self,
        subscription: SubscriptionHandle,
    ) -> Option<SubscriptionState> {
        self.subscriptions.get(&subscription).map(|held| held.state)
    }

    /// What a `dialog` subscription has been told, merged into one picture
    /// (RFC 4235 §4.3).
    ///
    /// `None` while the subscription is not live, and that is the whole point
    /// of the method: a table nothing is refreshing is not evidence about
    /// anything. §4.1.2.4 puts a subscription that has not been notified yet
    /// in "a neutral state", which for this package is an empty table — and an
    /// empty table rendered as a lamp says the colleague is free, which is the
    /// one wrong answer a busy lamp field must never give. So a subscription
    /// that is requesting, retrying or over says nothing at all, and the
    /// application shows that it does not know.
    #[must_use]
    pub fn dialog_info(&self, subscription: SubscriptionHandle) -> Option<&DialogInfoTable> {
        let held = self.subscriptions.get(&subscription)?;
        held.state.is_live().then_some(&held.table)
    }

    /// The last `application/simple-message-summary` document a `message-summary`
    /// subscription was told (RFC 3842 §3.5).
    ///
    /// `None` while the subscription is not live, for the same reason
    /// [`UserAgent::dialog_info`] answers nothing then: a mailbox count
    /// nothing is refreshing is not evidence about the mailbox. Unlike
    /// `dialog_info`'s table, this is never merged — §3.5 defines no version
    /// and no partial state, so every `NOTIFY` carries the whole picture and
    /// this is simply the last one.
    #[must_use]
    pub fn message_summary(&self, subscription: SubscriptionHandle) -> Option<&MessageSummary> {
        let held = self.subscriptions.get(&subscription)?;
        held.state
            .is_live()
            .then_some(held.summary.as_deref())
            .flatten()
    }

    /// What a `conference` subscription has been told, merged into one
    /// picture (RFC 4575 §4.6).
    ///
    /// `None` while the subscription is not live, for the reason
    /// [`UserAgent::dialog_info`] gives, and while no document has named the
    /// conference yet.
    #[must_use]
    pub fn conference(&self, subscription: SubscriptionHandle) -> Option<&Conference> {
        let held = self.subscriptions.get(&subscription)?;
        (held.state.is_live() && held.conference.entity().is_some()).then_some(&held.conference)
    }

    /// The last presence document a `presence` subscription was told (RFC
    /// 3856 §6.8).
    ///
    /// `None` while the subscription is not live, for the reason
    /// [`UserAgent::dialog_info`] gives.
    #[must_use]
    pub fn presence(&self, subscription: SubscriptionHandle) -> Option<&Presence> {
        let held = self.subscriptions.get(&subscription)?;
        held.state
            .is_live()
            .then_some(held.presence.as_deref())
            .flatten()
    }
}

// -- sending -----------------------------------------------------------------

impl UserAgent {
    fn mint_subscription(
        &mut self,
        account: AccountId,
        wanted: &Subscribe,
    ) -> Result<SubscriptionHandle, UaError> {
        if !self.accounts.contains_key(&account) {
            return Err(UaError::NoSuchAccount);
        }
        let handle = SubscriptionHandle(self.next_subscription);
        self.next_subscription = self.next_subscription.wrapping_add(1);
        let call_id = CallId::new(&self.endpoint.token());
        let local_tag = self.endpoint.token();
        self.subscriptions.insert(
            handle,
            Subscription::new(account, wanted.clone(), call_id, local_tag),
        );
        Ok(handle)
    }

    /// The first SUBSCRIBE of an attempt, out of dialog (§4.1.2.1).
    fn start_subscription(&mut self, subscription: SubscriptionHandle, now: Instant) {
        let Some(held) = self.subscriptions.get(&subscription) else {
            return;
        };
        let Some(account) = self.accounts.get(&held.account) else {
            self.unsendable(subscription);
            return;
        };
        let expires = held.wanted.expires;
        let learned = self.learned_for(held.account, held.wanted.destination, now);
        let Some(request) = build_subscribe(account, held, expires, learned) else {
            self.unsendable(subscription);
            return;
        };
        let Ok(id) = self.endpoint.request(&request, now) else {
            self.unsendable(subscription);
            return;
        };
        let timer_n = self.timer_n;
        let Some(held) = self.subscriptions.get_mut(&subscription) else {
            return;
        };
        held.cseq = held.cseq.saturating_add(1);
        held.state = SubscriptionState::Requesting;
        held.dialog = None;
        held.remote_tag = None;
        held.unanswered = None;
        held.lapses_at = None;
        held.table = DialogInfoTable::default();
        held.summary = None;
        held.conference = Conference::new();
        held.presence = None;
        // §4.1.2.4: "a subscriber starts a Timer N, set to 64*T1, when it
        // sends a SUBSCRIBE request", and the same window is the one a fork
        // may still arrive in
        held.due = Some((now + timer_n, Waiting::Notify));
        held.forks_until = Some(now + timer_n);
        let account = held.account;
        self.claim_subscribe(subscription, id);
        self.events.push_back(UaEvent::Subscribing {
            subscription,
            account,
        });
    }

    /// A fresh SUBSCRIBE for every subscription `distrust` demoted and
    /// nothing has touched since.
    ///
    /// `due.is_none()` is that signature: `stop_timers` is the only thing
    /// that puts a subscription in `Retrying` without also scheduling
    /// something for it, because the sole other writer of `Retrying`,
    /// `retry_subscription`, always sets `due` in the same statement. `true`
    /// when at least one reached a transport, which mirrors `reregister` and
    /// is what decides whether the ladder has anything left to wait for.
    pub(crate) fn resubscribe(&mut self, now: Instant) -> bool {
        let waiting: Vec<SubscriptionHandle> = self
            .subscriptions
            .iter()
            .filter(|(_, held)| held.state == SubscriptionState::Retrying && held.due.is_none())
            .map(|(handle, _)| *handle)
            .collect();
        let mut sent = false;
        for subscription in waiting {
            // a new subscription, not a refresh of the old one: the dialog it
            // had is gone, and RFC 6665 §4.1.2.4 identifies a subscription by
            // the dialog its Call-ID and tags name. Re-using them would offer
            // the notifier a second subscription under a name it already has
            // one for, and leave it to decide which of the two the next
            // NOTIFY belongs to
            let call_id = CallId::new(&self.endpoint.token());
            let local_tag = self.endpoint.token();
            if let Some(held) = self.subscriptions.get_mut(&subscription) {
                held.call_id = call_id;
                held.local_tag = local_tag;
                held.cseq = 0;
            }
            self.start_subscription(subscription, now);
            // a send that fails ends the subscription outright here, the same
            // as it does for `UserAgent::subscribe` -- `start_subscription`
            // does not know it was called from the ladder rather than the
            // application, and that is not this method's to change
            sent |= self.subscriptions.contains_key(&subscription);
        }
        sent
    }

    /// A refresh or an unsubscribe, inside the dialog the NOTIFY opened
    /// (§4.1.2.2, §4.1.2.3).
    fn send_in_dialog(
        &mut self,
        subscription: SubscriptionHandle,
        dialog: DialogId,
        expires: Duration,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self
            .subscriptions
            .get(&subscription)
            .ok_or(UaError::NoSuchSubscription)?;
        let account = self
            .accounts
            .get(&held.account)
            .ok_or(UaError::NoSuchAccount)?;
        let learned = self.learned_for(held.account, held.wanted.destination, now);
        let request = build_refresh(account, held, expires, learned);
        let id = self.endpoint.request_in_dialog(dialog, &request, now)?;
        let timer_n = self.timer_n;
        if let Some(held) = self.subscriptions.get_mut(&subscription) {
            // §4.1.2.2 starts Timer N again for a refresh, and its expiry
            // means the same thing: no NOTIFY, no subscription
            held.due = Some((now + timer_n, Waiting::Notify));
            held.unanswered = None;
        }
        self.claim_subscribe(subscription, id);
        Ok(())
    }

    /// One transaction per subscription, replaced rather than accumulated.
    fn claim_subscribe(
        &mut self,
        subscription: SubscriptionHandle,
        id: TransactionId<NonInviteClient>,
    ) {
        self.by_subscribe.retain(|_, owner| *owner != subscription);
        self.by_subscribe
            .insert(AnyTransactionId::NonInviteClient(id), subscription);
    }

    /// A SUBSCRIBE that never reached a transport.
    ///
    /// The record goes with the event, so that nothing is scheduled against a
    /// subscription that does not exist and no later sweep finds one.
    fn unsendable(&mut self, subscription: SubscriptionHandle) {
        self.end_subscription(subscription, SubscriptionEnd::Unreachable, None, None);
    }

    /// Whatever this layer scheduled for a subscription.
    pub(crate) fn fire_subscription_timers(&mut self, now: Instant) {
        let lapsed: Vec<SubscriptionHandle> = self
            .subscriptions
            .iter()
            .filter(|(_, held)| held.lapses_at.is_some_and(|at| at <= now))
            .map(|(handle, _)| *handle)
            .collect();
        for subscription in lapsed {
            self.retry_or_end(
                subscription,
                SubscriptionEnd::Expired,
                None,
                None,
                None,
                now,
            );
        }

        let due: Vec<(SubscriptionHandle, Waiting)> = self
            .subscriptions
            .iter()
            .filter_map(|(handle, held)| {
                held.due
                    .filter(|(at, _)| *at <= now)
                    .map(|(_, what)| (*handle, what))
            })
            .collect();
        for (subscription, what) in due {
            if let Some(held) = self.subscriptions.get_mut(&subscription) {
                held.due = None;
                held.forks_until = None;
            }
            match what {
                // §4.1.2.4: "If this Timer N expires prior to the receipt of a
                // NOTIFY request, the subscriber considers the subscription
                // failed, and cleans up any state associated with the
                // subscription attempt."
                Waiting::Notify => self.retry_subscription(
                    subscription,
                    SubscriptionEnd::NoNotify,
                    None,
                    None,
                    None,
                    now,
                ),
                Waiting::Refresh => self.refresh_subscription(subscription, now),
                Waiting::Retry => self.start_subscription(subscription, now),
            }
        }

        // the notifier's side: the subscriptions a REFER this end took
        // opened, and the referrals nobody has answered yet
        self.fire_refer_subscriptions(now);
        self.fire_referral_timers(now);
    }

    /// When this layer next has something to do about a subscription, on
    /// either side of one.
    pub(crate) fn subscription_deadline(&self) -> Option<Instant> {
        self.subscriptions
            .values()
            .filter_map(Subscription::deadline)
            .chain(self.refer_subscription_deadline())
            .chain(self.referral_deadline())
            .min()
    }

    pub(crate) fn refresh_subscription(&mut self, subscription: SubscriptionHandle, now: Instant) {
        let Some(held) = self.subscriptions.get(&subscription) else {
            return;
        };
        let expires = held.wanted.expires;
        let Some(dialog) = held.dialog else {
            self.start_subscription(subscription, now);
            return;
        };
        // a failure here is reported the same way one on the wire is: the
        // transport can have gone since the refresh was scheduled. One that
        // §18.1.1 holds back for a stream is not a failure yet, and goes when
        // the stream is bound
        match self.send_in_dialog(subscription, dialog, expires, now) {
            Ok(()) => {}
            Err(ref error) if call_needs_a_stream(error) => {
                self.park(Parked::Refresh {
                    subscription,
                    dialog,
                });
            }
            Err(_) => self.unsendable(subscription),
        }
    }
}

/// The out-of-dialog SUBSCRIBE that starts an attempt (§4.1.2.1), with what the
/// account's registrar said when it goes where the account registers.
fn build_subscribe(
    account: &Account,
    held: &Subscription,
    expires: Duration,
    learned: Option<&RegistrarInfo>,
) -> Option<OutgoingRequest> {
    let seconds = expires.as_secs().to_string();
    let mut from = account.sender_value().to_vec();
    from.extend_from_slice(b";tag=");
    from.extend_from_slice(&held.local_tag);
    let mut to = Vec::with_capacity(held.wanted.target.as_bytes().len() + 2);
    to.push(b'<');
    to.extend_from_slice(held.wanted.target.as_bytes());
    to.push(b'>');
    let (transport, remote) = held.wanted.destination.or_else(|| account.destination())?;

    let mut request = OutgoingRequest::new(
        Method::Subscribe,
        held.wanted.target.clone(),
        transport,
        remote,
    )
    .to(&to)
    .from(&from)
    .call_id(held.call_id.clone())
    .cseq(held.cseq.saturating_add(1))
    // §8.1.1.8: a request that can establish a dialog carries one, and
    // RFC 5627 §4.4 lists the SUBSCRIBE among those that name a GRUU
    .contact(&dialog_contact(
        account,
        learned,
        anonymous(&held.wanted.extra),
    ))
    .header(HeaderName::Event, &held.wanted.package)
    .header(HeaderName::Expires, seconds.as_bytes());
    // RFC 5627 §4.4 SHOULD: "a UA SHOULD include a Supported header field
    // with the option tag gruu in requests and responses it generates"
    if account.wants_gruu() {
        request = request.header(HeaderName::Supported, b"gruu");
    }
    // RFC 3608 §6.1: the service route preloaded, in the registrar's order
    for hop in learned.into_iter().flat_map(RegistrarInfo::service_route) {
        request = request.route(hop);
    }
    if let Some(ref accept) = held.wanted.accept {
        request = request.header(HeaderName::Accept, accept);
    }
    for extra in &held.wanted.extra {
        if let Some(name) = HeaderName::from_bytes(&extra.name) {
            request = request.header(name, &extra.value);
        }
    }
    Some(request)
}

/// The in-dialog one that refreshes or ends it. A refresh is a target refresh
/// request, which RFC 5627 §4.4 gives a GRUU as well; the route is the
/// dialog's own by now, and the service route has no part in it.
fn build_refresh(
    account: &Account,
    held: &Subscription,
    expires: Duration,
    learned: Option<&RegistrarInfo>,
) -> OutgoingInDialogRequest {
    let seconds = expires.as_secs().to_string();
    let mut request = OutgoingInDialogRequest::new(Method::Subscribe)
        .contact(&dialog_contact(
            account,
            learned,
            anonymous(&held.wanted.extra),
        ))
        .header(HeaderName::Event, &held.wanted.package)
        .header(HeaderName::Expires, seconds.as_bytes());
    if account.wants_gruu() {
        request = request.header(HeaderName::Supported, b"gruu");
    }
    if let Some(ref accept) = held.wanted.accept {
        request = request.header(HeaderName::Accept, accept);
    }
    for extra in &held.wanted.extra {
        if let Some(name) = HeaderName::from_bytes(&extra.name) {
            request = request.header(name, &extra.value);
        }
    }
    request
}

// -- what comes back ---------------------------------------------------------

impl UserAgent {
    /// `None` when the event belonged to a subscription and has been dealt
    /// with; the event back when it did not.
    ///
    /// A NOTIFY that matches nothing is refused here, which is why this sits
    /// below the transfer handler rather than above it. §4.1.3 has exactly one
    /// answer for a notification nobody subscribed to — "it MUST return a 481
    /// (Subscription does not exist) response unless another 400- or 500-class
    /// response is more appropriate" — and something can only say that once
    /// everything that runs a subscription of its own has had its turn. RFC
    /// 3515 §2.4.4's is the other one: a REFER opens a subscription this
    /// machine never sees, so the transfer handler claims the `refer` package
    /// inside a call it is running, and everything it leaves is either one of
    /// these subscriptions or nobody's.
    pub(crate) fn on_subscription_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingOutOfDialog {
                transaction,
                ref request,
            } if request.as_raw().method() == Some(Method::Notify) => {
                let request = request.clone();
                self.on_fresh_notify(transaction, &request, now);
                None
            }
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Notify) => {
                let request = request.clone();
                let found = self.subscription_in(dialog);
                self.on_known_notify(found, transaction, &request, now);
                None
            }
            // the three that carry a transaction handle: an answer to a
            // request somebody else sent has to go on, or it takes somebody
            // else's news with it
            Event::Response {
                transaction,
                status,
                ref response,
            } => {
                let Some(subscription) = self.subscription_of(transaction) else {
                    return Some(event);
                };
                let response = response.clone();
                self.on_subscribe_response(subscription, status, &response, now);
                None
            }
            Event::RequestFailed {
                transaction,
                reason,
            } => {
                let Some(subscription) = self.subscription_of(transaction) else {
                    return Some(event);
                };
                self.on_subscribe_failed(subscription, reason, now);
                None
            }
            Event::Challenged { transaction, .. } => {
                let Some(subscription) = self.by_subscribe.get(&transaction).copied() else {
                    return Some(event);
                };
                self.on_subscribe_challenged(subscription, transaction, now);
                None
            }
            // the flow every subscription on this account was running over is
            // gone, and a lamp fed by a dead flow is a lamp that lies
            Event::FlowFailed { transport } => {
                self.on_flow_lost(transport, now);
                Some(event)
            }
            other => Some(other),
        }
    }

    fn subscription_of(
        &self,
        transaction: TransactionId<NonInviteClient>,
    ) -> Option<SubscriptionHandle> {
        self.by_subscribe
            .get(&AnyTransactionId::NonInviteClient(transaction))
            .copied()
    }

    fn subscription_in(&self, dialog: DialogId) -> Option<SubscriptionHandle> {
        self.subscriptions
            .iter()
            .find(|(_, held)| held.dialog == Some(dialog))
            .map(|(handle, _)| *handle)
    }

    /// A NOTIFY that arrived outside any dialog: the first of a subscription,
    /// or nobody's (§4.4.1).
    fn on_fresh_notify(
        &mut self,
        transaction: TransactionId<sipral_core::transaction::NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let raw = request.as_raw();
        let matched = self.match_notify(&raw, now);
        match matched {
            Matched::Fresh(subscription) => {
                self.on_known_notify(Some(subscription), transaction, request, now);
            }
            Matched::Forked(parent) => {
                let Some(sibling) = self.fork_subscription(parent) else {
                    self.refuse_notify(transaction, StatusCode::CALL_DOES_NOT_EXIST, now);
                    return;
                };
                self.events.push_back(UaEvent::SubscriptionForked {
                    subscription: parent,
                    sibling,
                });
                self.on_known_notify(Some(sibling), transaction, request, now);
            }
            // §4.1.3: "If, for some reason, the event package designated in
            // the Event header field of the NOTIFY request is not supported,
            // the subscriber will respond with a 489 (Bad Event) response."
            Matched::WrongPackage => self.refuse_notify(transaction, BAD_EVENT, now),
            Matched::Nobody => {
                self.refuse_notify(transaction, StatusCode::CALL_DOES_NOT_EXIST, now);
            }
        }
    }

    /// §4.4.1's rule, and nothing else: the same `Call-ID`, a `To` tag equal
    /// to the `From` tag of the SUBSCRIBE, and a matching `Event`.
    fn match_notify(&self, request: &RawMessage<'_>, now: Instant) -> Matched {
        let (Ok(call_id), Ok(Some(tag))) = (request.call_id(), request.to().map(|to| to.tag()))
        else {
            return Matched::Nobody;
        };
        let named =
            |held: &Subscription| held.call_id.as_bytes() == call_id && *held.local_tag == *tag;
        if !self.subscriptions.values().any(named) {
            return Matched::Nobody;
        }
        let Ok(theirs) = request.event() else {
            return Matched::WrongPackage;
        };
        // §8.2.1 compares the event type byte for byte, and an `Event` with an
        // id never matches one without
        let ours = |held: &Subscription| {
            named(held)
                && EventRef::parse(&held.wanted.package).is_ok_and(|ours| ours.matches(&theirs))
        };
        if !self.subscriptions.values().any(ours) {
            return Matched::WrongPackage;
        }
        // a notifier that sends the same notification again under a fresh
        // branch is not a second notifier: §4.1.4 tells forks apart by the
        // `From` tag, and one already installed names a subscription that
        // exists rather than one to mint
        if let Some(theirs) = request.from().ok().and_then(|from| from.tag())
            && let Some((known, _)) = self
                .subscriptions
                .iter()
                .find(|(_, held)| ours(held) && held.remote_tag.as_deref() == Some(&*theirs))
        {
            return Matched::Fresh(*known);
        }
        // the usual case: the attempt that has no dialog yet takes it
        if let Some((waiting, _)) = self
            .subscriptions
            .iter()
            .find(|(_, held)| ours(held) && held.dialog.is_none())
        {
            return Matched::Fresh(*waiting);
        }
        // otherwise a second notifier answered the same SUBSCRIBE, and
        // §4.1.2.4 gives it a subscription of its own until Timer N passes
        if let Some((parent, _)) = self
            .subscriptions
            .iter()
            .find(|(_, held)| ours(held) && held.forks_until.is_some_and(|until| now < until))
        {
            return Matched::Forked(*parent);
        }
        // "After the expiration of Timer N, the subscriber SHOULD reject any
        // such NOTIFY requests that would otherwise establish a new dialog
        // usage with a 481 (Subscription does not exist) response code."
        Matched::Nobody
    }

    fn fork_subscription(&mut self, parent: SubscriptionHandle) -> Option<SubscriptionHandle> {
        let forked = self.subscriptions.get(&parent)?.fork();
        let handle = SubscriptionHandle(self.next_subscription);
        self.next_subscription = self.next_subscription.wrapping_add(1);
        self.subscriptions.insert(handle, forked);
        Some(handle)
    }

    fn refuse_notify(
        &mut self,
        transaction: TransactionId<sipral_core::transaction::NonInviteServer>,
        status: StatusCode,
        now: Instant,
    ) {
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(status), now)
            .ok();
    }
}

/// Which subscription a NOTIFY belongs to.
enum Matched {
    /// One that is waiting for its first notification.
    Fresh(SubscriptionHandle),
    /// A second notifier answering the same SUBSCRIBE (§4.1.4).
    Forked(SubscriptionHandle),
    /// The `Call-ID` and the tag name a subscription, and the `Event` does
    /// not.
    WrongPackage,
    /// Nothing here asked for this.
    Nobody,
}

/// 489, which §8.3.2 adds for an event package the far end does not know.
const BAD_EVENT: StatusCode = match StatusCode::new(489) {
    Ok(status) => status,
    // 489 is in range, so this arm never runs; it exists because `new` is
    // fallible and nothing in this crate panics to say otherwise
    Err(_) => StatusCode::CALL_DOES_NOT_EXIST,
};

/// 400, for a NOTIFY without the one field §4.1.3 makes mandatory. §4.1.3
/// leaves room for it: "unless another 400- or 500-class response is more
/// appropriate".
const BAD_REQUEST: StatusCode = match StatusCode::new(400) {
    Ok(status) => status,
    Err(_) => StatusCode::CALL_DOES_NOT_EXIST,
};

// -- notifications -----------------------------------------------------------

impl UserAgent {
    /// A NOTIFY that names a subscription, or one that names nothing.
    fn on_known_notify(
        &mut self,
        found: Option<SubscriptionHandle>,
        transaction: TransactionId<sipral_core::transaction::NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let raw = request.as_raw();
        let Some(subscription) = found else {
            self.refuse_notify(transaction, StatusCode::CALL_DOES_NOT_EXIST, now);
            return;
        };
        // §4.4.1: notifications inside an existing dialog "match if they are
        // in the same dialog and the Event header fields match"
        if !self.package_of(subscription, &raw) {
            self.refuse_notify(transaction, BAD_EVENT, now);
            return;
        }
        // §4.1.3 makes the field mandatory, and a notification that does not
        // say where the subscription is says nothing that can be acted on
        let Ok(state) = raw.subscription_state() else {
            self.refuse_notify(transaction, BAD_REQUEST, now);
            return;
        };
        let over = state.state() == Substate::Terminated;
        // §4.4.1: "Dialogs usages are created upon completion of a NOTIFY
        // transaction for a new subscription, unless the NOTIFY request
        // contains a Subscription-State of terminated."
        //
        // Before the 200 rather than after it, and that is not a choice: on a
        // reliable transport §17.2.2's Timer J is zero, so the server
        // transaction is retired the instant the final response goes — and the
        // request and the flow the dialog is built from live on it.
        let fresh = self
            .subscriptions
            .get(&subscription)
            .is_some_and(|held| held.dialog.is_none());
        let opened =
            over || !fresh || self.open_subscription_dialog(subscription, transaction, &raw);
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
            .ok();
        if !opened {
            self.end_subscription(subscription, SubscriptionEnd::Unreachable, None, None);
            return;
        }
        if over {
            self.on_subscription_over(subscription, &state, now);
            return;
        }
        self.on_notified(subscription, &state, request, now);
    }

    /// Whether the `Event` of this NOTIFY is the one that subscription asked
    /// for (§8.2.1).
    fn package_of(&self, subscription: SubscriptionHandle, request: &RawMessage<'_>) -> bool {
        let Some(held) = self.subscriptions.get(&subscription) else {
            return false;
        };
        let (Ok(ours), Ok(theirs)) = (EventRef::parse(&held.wanted.package), request.event())
        else {
            return false;
        };
        ours.matches(&theirs)
    }

    /// Make the dialog the NOTIFY names (§4.4.1).
    fn open_subscription_dialog(
        &mut self,
        subscription: SubscriptionHandle,
        transaction: TransactionId<sipral_core::transaction::NonInviteServer>,
        request: &RawMessage<'_>,
    ) -> bool {
        let cseq = self
            .subscriptions
            .get(&subscription)
            .map(|held| held.cseq)
            .filter(|seq| *seq > 0);
        let Some(dialog) = self.endpoint.open_dialog(transaction, cseq) else {
            return false;
        };
        let remote_tag = request
            .from()
            .ok()
            .and_then(|from| from.tag())
            .map(|tag| Box::from(&*tag));
        if let Some(held) = self.subscriptions.get_mut(&subscription) {
            held.dialog = Some(dialog);
            held.remote_tag = remote_tag;
        }
        true
    }

    /// A notification that says the subscription is running (§4.1.3).
    fn on_notified(
        &mut self,
        subscription: SubscriptionHandle,
        state: &SubscriptionStateRef<'_>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        // §4.1.3: under `active` and `pending`, "the subscriber SHOULD take it
        // as the authoritative subscription duration and adjust accordingly"
        let stated = state
            .expires()
            .and_then(|value| value.require().ok())
            .map(|seconds| Duration::from_secs(u64::from(seconds)));
        let pending = state.state() == Substate::Pending;
        self.settle_subscription(subscription, stated, pending, now);
        let info = self.merge_dialog_info(subscription, request, now);
        self.merge_message_summary(subscription, request);
        self.events.push_back(UaEvent::Notified {
            subscription,
            request: request.clone(),
            info,
        });
        // after the notification itself, so that an application reading the
        // raw NOTIFY and the typed news in order meets them in that order
        self.merge_conference(subscription, request, now);
        self.merge_presence(subscription, request);
    }

    /// Take the granted duration and schedule the refresh against it.
    fn settle_subscription(
        &mut self,
        subscription: SubscriptionHandle,
        stated: Option<Duration>,
        pending: bool,
        now: Instant,
    ) {
        let Some(held) = self.subscriptions.get_mut(&subscription) else {
            return;
        };
        let was = held.state;
        let granted = stated.unwrap_or(held.granted);
        let granted = if granted.is_zero() {
            held.wanted.expires
        } else {
            granted
        };
        held.granted = granted;
        held.failures = 0;
        held.state = if pending {
            SubscriptionState::Pending
        } else {
            SubscriptionState::Active
        };
        let refresh_in = refresh_after(granted);
        held.lapses_at = Some(now + granted);
        held.due = Some((now + refresh_in, Waiting::Refresh));
        let state = held.state;
        // where a subscription is, is an event. Where it is inside its own
        // hour is not: a lamp does not change when a refresh is scheduled, and
        // thirty subscriptions saying so every hour is noise
        if was != state {
            self.events.push_back(UaEvent::Subscribed {
                subscription,
                state,
                expires: granted,
                refresh_in,
            });
        }
    }

    /// The notifier says it is over (§4.1.3).
    fn on_subscription_over(
        &mut self,
        subscription: SubscriptionHandle,
        state: &SubscriptionStateRef<'_>,
        now: Instant,
    ) {
        let asked_for = state
            .retry_after()
            .and_then(|value| value.require().ok())
            .map(|seconds| Duration::from_secs(u64::from(seconds)));
        let asked_us = self
            .subscriptions
            .get(&subscription)
            .is_some_and(|held| held.unsubscribing);
        let reason = if asked_us {
            SubscriptionEnd::Unsubscribed
        } else {
            SubscriptionEnd::read(state.reason().as_deref())
        };
        self.retry_or_end(subscription, reason, None, None, asked_for, now);
    }

    /// Merge an `application/dialog-info+xml` body into the table
    /// (RFC 4235 §4.3).
    fn merge_dialog_info(
        &mut self,
        subscription: SubscriptionHandle,
        request: &OwnedMessage,
        now: Instant,
    ) -> Option<Arc<DialogInfo>> {
        let raw = request.as_raw();
        let body = raw.body();
        if body.is_empty()
            || !raw
                .content_type()
                .is_ok_and(|kind| kind.is("application", "dialog-info+xml"))
        {
            return None;
        }
        // a document that will not read leaves the table exactly as it was: a
        // lamp showing what was last known beats one showing what a malformed
        // body happened to contain
        let document = DialogInfo::parse(body).ok()?;
        let applied = self
            .subscriptions
            .get_mut(&subscription)?
            .table
            .apply(&document);
        if applied == Applied::Incomplete {
            self.ask_for_full_state(subscription, now);
        }
        (applied != Applied::Stale).then(|| Arc::new(document))
    }

    /// §4.3: "If the document did not contain full state, the subscriber
    /// SHOULD generate a refresh request (SUBSCRIBE) to trigger a full state
    /// notification."
    ///
    /// Only when there is not already one in flight. §3.3 makes the answer to
    /// a SUBSCRIBE carry "the complete view of dialog state", so one round
    /// trip settles it — and asking again while the first is unanswered is how
    /// a notifier that numbers its documents badly turns into one request per
    /// notification.
    fn ask_for_full_state(&mut self, subscription: SubscriptionHandle, now: Instant) {
        let waiting = self
            .subscriptions
            .get(&subscription)
            .is_some_and(|held| matches!(held.due, Some((_, Waiting::Notify))));
        if !waiting {
            self.refresh_subscription(subscription, now);
        }
    }

    /// Read an `application/simple-message-summary` body and raise
    /// [`UaEvent::MessagesWaiting`] for it (RFC 3842 §3.9: "the subscriber
    /// SHOULD immediately render the message status and summary information
    /// to the end user").
    ///
    /// A body that will not read is left exactly as `merge_dialog_info`
    /// leaves one: nothing here changes, and the last good reading stands —
    /// a mailbox light showing what was last known beats one showing what a
    /// malformed body happened to contain. A `NOTIFY` for `message-summary`
    /// that arrives with no matching subscription at all never reaches
    /// here: `match_notify` answers it 481 before a package is even
    /// dispatched to, which is RFC 6665 §4.1.3's own answer to an
    /// unsolicited notification and applies to every package alike,
    /// `message-summary` included — a PBX that sends one without a
    /// subscription, which several do, gets the same 481 an unsolicited
    /// `dialog` `NOTIFY` gets, and `docs/04-ua.md` says so.
    fn merge_message_summary(&mut self, subscription: SubscriptionHandle, request: &OwnedMessage) {
        let raw = request.as_raw();
        let body = raw.body();
        if body.is_empty()
            || !raw
                .content_type()
                .is_ok_and(|kind| kind.is("application", "simple-message-summary"))
        {
            return;
        }
        let Ok(document) = MessageSummary::parse(body) else {
            return;
        };
        let document = Arc::new(document);
        let (waiting, account, voice) = (
            document.waiting,
            document.account.clone(),
            document.voice_message().cloned(),
        );
        if let Some(held) = self.subscriptions.get_mut(&subscription) {
            held.summary = Some(document);
        } else {
            return;
        }
        self.events.push_back(UaEvent::MessagesWaiting {
            subscription,
            waiting,
            account,
            new: voice.as_ref().map_or(0, |class| class.new),
            old: voice.as_ref().map_or(0, |class| class.old),
            urgent_new: voice.as_ref().map_or(0, |class| class.new_urgent),
            urgent_old: voice.as_ref().map_or(0, |class| class.old_urgent),
        });
    }

    /// Merge an `application/conference-info+xml` body into the
    /// subscription's picture of the conference (RFC 4575 §4.6), and act on
    /// what the merge says.
    ///
    /// A gap asks for full state with a refresh — what §4.6 has a subscriber
    /// do, and what RFC 6665 §4.2.1 makes the answer carry — and a deleted
    /// conference gives the subscription up, as §4.6 asks: "the subscriber
    /// SHOULD terminate the subscription". A body that will not read leaves
    /// the picture as it was, for the reason `merge_dialog_info` gives.
    fn merge_conference(
        &mut self,
        subscription: SubscriptionHandle,
        request: &OwnedMessage,
        now: Instant,
    ) {
        if !self.package_is(subscription, crate::conference::CONFERENCE_EVENT) {
            return;
        }
        let Some(held) = self.subscriptions.get_mut(&subscription) else {
            return;
        };
        let Ok(Some(update)) = held.conference.apply_notify(request) else {
            return;
        };
        match update {
            ConferenceUpdate::Applied => {
                self.events.push_back(UaEvent::ConferenceChanged {
                    subscription,
                    update,
                });
            }
            ConferenceUpdate::Ended => {
                self.events.push_back(UaEvent::ConferenceChanged {
                    subscription,
                    update,
                });
                // the unsubscribe answers only for a subscription that is
                // still held, which this one is: it was just notified
                self.unsubscribe(subscription, now).ok();
            }
            ConferenceUpdate::Resubscribe => self.ask_for_full_state(subscription, now),
            // late, repeated, or held off while full state is on its way
            _ => {}
        }
    }

    /// Read an `application/pidf+xml` body of a `presence` subscription and
    /// raise [`UaEvent::PresenceChanged`] for it (RFC 3856 §6.8).
    ///
    /// Every notification of this package carries the presentity's whole
    /// state, so there is nothing to merge: the last readable document is
    /// the picture, and one that will not read leaves the last one standing.
    fn merge_presence(&mut self, subscription: SubscriptionHandle, request: &OwnedMessage) {
        if !self.package_is(subscription, crate::publishing::PRESENCE_EVENT) {
            return;
        }
        let raw = request.as_raw();
        let body = raw.body();
        if body.is_empty()
            || !raw
                .content_type()
                .is_ok_and(|kind| kind.is("application", "pidf+xml"))
        {
            return;
        }
        let Ok(document) = Presence::parse(body) else {
            return;
        };
        let presence = Arc::new(document);
        let Some(held) = self.subscriptions.get_mut(&subscription) else {
            return;
        };
        held.presence = Some(Arc::clone(&presence));
        self.events.push_back(UaEvent::PresenceChanged {
            subscription,
            presence,
        });
    }

    /// Whether the subscription asked for `package`, compared as §8.2.1
    /// compares event packages.
    fn package_is(&self, subscription: SubscriptionHandle, package: &str) -> bool {
        let Some(held) = self.subscriptions.get(&subscription) else {
            return false;
        };
        let (Ok(ours), Ok(wanted)) = (
            EventRef::parse(&held.wanted.package),
            EventRef::parse(package.as_bytes()),
        ) else {
            return false;
        };
        ours.matches(&wanted)
    }
}

// -- what the notifier answers -----------------------------------------------

impl UserAgent {
    fn on_subscribe_response(
        &mut self,
        subscription: SubscriptionHandle,
        status: StatusCode,
        response: &OwnedMessage,
        now: Instant,
    ) {
        if status.is_provisional() {
            // a notifier that says it is working on it is not a result
            return;
        }
        if status.is_success() {
            self.on_subscribe_accepted(subscription, response, now);
            return;
        }
        if matches!(status.get(), 401 | 407) {
            // held until the end of the drain: whether this is answerable is
            // decided by whether a challenge follows it
            if let Some(held) = self.subscriptions.get_mut(&subscription) {
                held.unanswered = Some(response.clone());
            }
            return;
        }
        self.on_subscribe_refused(subscription, status, response, now);
    }

    /// A 200 to a SUBSCRIBE, which is not yet a subscription (§4.1.2.4).
    fn on_subscribe_accepted(
        &mut self,
        subscription: SubscriptionHandle,
        response: &OwnedMessage,
        now: Instant,
    ) {
        // §3.1.1: "200-class responses to SUBSCRIBE requests also MUST contain
        // an Expires header field ... The period of time in the response is
        // the one that defines the duration of the subscription."
        let granted = response
            .as_raw()
            .expires()
            .ok()
            .and_then(|value| value.require().ok())
            .map(|seconds| Duration::from_secs(u64::from(seconds)));
        let Some(held) = self.subscriptions.get_mut(&subscription) else {
            return;
        };
        held.failures = 0;
        held.granted = granted.unwrap_or(held.wanted.expires);
        // Timer N keeps running. §4.1.2.4 establishes the subscription with
        // the NOTIFY and not with this, and a 200 that is never followed by
        // one is exactly the case Timer N exists for
        held.lapses_at = (!held.granted.is_zero()).then(|| now + held.granted);
    }

    fn on_subscribe_refused(
        &mut self,
        subscription: SubscriptionHandle,
        status: StatusCode,
        response: &OwnedMessage,
        now: Instant,
    ) {
        let asked_for = retry_after(&response.as_raw());
        let established = self
            .subscriptions
            .get(&subscription)
            .is_some_and(|held| held.dialog.is_some());
        // §4.1.2.2: "If a SUBSCRIBE request to refresh a subscription fails
        // with any error code other than those listed above, the original
        // subscription is still considered valid for the duration of the most
        // recently known Expires value."
        if established && !ends_the_subscription(status) {
            self.try_again_before_it_lapses(subscription, asked_for, now);
            return;
        }
        self.retry_or_end(
            subscription,
            refusal(status),
            Some(status),
            Some(response.clone()),
            asked_for,
            now,
        );
    }

    fn on_subscribe_failed(
        &mut self,
        subscription: SubscriptionHandle,
        reason: FailureReason,
        now: Instant,
    ) {
        // a timeout and a dead transport say the same thing about the
        // subscription, which is nothing yet
        let _ = reason;
        let established = self
            .subscriptions
            .get(&subscription)
            .is_some_and(|held| held.dialog.is_some());
        if established {
            self.try_again_before_it_lapses(subscription, None, now);
            return;
        }
        self.retry_subscription(
            subscription,
            SubscriptionEnd::Unreachable,
            None,
            None,
            None,
            now,
        );
    }

    fn on_subscribe_challenged(
        &mut self,
        subscription: SubscriptionHandle,
        transaction: AnyTransactionId,
        now: Instant,
    ) {
        let credentials = self
            .subscriptions
            .get(&subscription)
            .and_then(|held| self.accounts.get(&held.account))
            .and_then(|account| account.credentials.clone());
        let Some(credentials) = credentials else {
            // nothing to answer with; the refusal stands, and it stands the
            // same way every time
            return;
        };
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => self.subscribe_retry_went(subscription, transaction, retried),
            // §18.1.1 wants a connection first, and the endpoint is still
            // holding the challenge. The number is not moved either: nothing
            // has gone out to move it past
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let Some(held) = self.subscriptions.get_mut(&subscription) {
                    held.waiting_for_stream = Some(transaction);
                }
            }
            Err(_) => {}
        }
    }

    /// The retry is a transaction now, so everything that named the refused
    /// one names this one.
    fn subscribe_retry_went(
        &mut self,
        subscription: SubscriptionHandle,
        transaction: AnyTransactionId,
        retried: AnyTransactionId,
    ) {
        self.by_subscribe.remove(&transaction);
        self.by_subscribe.insert(retried, subscription);
        if let Some(held) = self.subscriptions.get_mut(&subscription) {
            held.unanswered = None;
            held.waiting_for_stream = None;
            // §22.2 has the retry carry the next number, and outside a dialog
            // that is one more than the one that was refused. The dialog the
            // NOTIFY opens continues from there, so this has to move with it
            held.cseq = held.cseq.saturating_add(1);
        }
    }

    /// Send the subscription retries §18.1.1 held back, now that there is a
    /// connection.
    pub(crate) fn resume_parked_subscriptions(&mut self, now: Instant) {
        let waiting: Vec<(SubscriptionHandle, AnyTransactionId)> = self
            .subscriptions
            .iter()
            .filter_map(|(handle, held)| held.waiting_for_stream.map(|failed| (*handle, failed)))
            .collect();
        for (subscription, failed) in waiting {
            let credentials = self
                .subscriptions
                .get(&subscription)
                .and_then(|held| self.accounts.get(&held.account))
                .and_then(|account| account.credentials.clone());
            let Some(credentials) = credentials else {
                self.stop_waiting_for_subscribe(subscription);
                continue;
            };
            match self
                .endpoint
                .retry_with_credentials(failed, &credentials, now)
            {
                Ok(retried) => self.subscribe_retry_went(subscription, failed, retried),
                Err(error) if crate::agent::wants_a_stream(&error) => {}
                Err(_) => self.stop_waiting_for_subscribe(subscription),
            }
        }
    }

    /// Stop holding one back, so the next settle reports the refusal it
    /// still carries.
    fn stop_waiting_for_subscribe(&mut self, subscription: SubscriptionHandle) {
        if let Some(held) = self.subscriptions.get_mut(&subscription) {
            held.waiting_for_stream = None;
        }
    }

    /// A refusal that carried a challenge and got no retry was a refusal.
    ///
    /// The same settling registration does, for the same reason: the core
    /// answers a challenge once, and the same nonce coming back is §22.1's way
    /// of saying the password was wrong. Nothing follows the refusal in that
    /// case, and that silence is the answer.
    pub(crate) fn settle_subscription_challenges(&mut self, now: Instant) {
        let refused: Vec<(SubscriptionHandle, OwnedMessage)> = self
            .subscriptions
            .iter_mut()
            // except one the endpoint is holding until a connection exists:
            // its answer has not been sent yet, so there is no silence to read
            .filter(|(_, held)| held.waiting_for_stream.is_none())
            .filter_map(|(handle, held)| held.unanswered.take().map(|response| (*handle, response)))
            .collect();
        for (subscription, response) in refused {
            let status = response.as_raw().status();
            self.retry_or_end(
                subscription,
                SubscriptionEnd::Refused,
                status,
                Some(response),
                None,
                now,
            );
        }
    }

    /// The flow every subscription on an account was running over has died
    /// (RFC 5626 §4.4.1).
    ///
    /// A subscription does not notice by itself: its refresh is most of an
    /// hour out, and until then the table it holds is the last thing a working
    /// notifier said. That table is what a busy lamp field renders, so leaving
    /// it standing shows a colleague as free for the rest of the hour because
    /// a socket died while they were on a call.
    fn on_flow_lost(&mut self, transport: TransportId, now: Instant) {
        let lost: Vec<SubscriptionHandle> = self
            .subscriptions
            .iter()
            .filter(|(_, held)| {
                held.state.is_live()
                    && self
                        .accounts
                        .get(&held.account)
                        .is_some_and(|account| account.transport == transport)
            })
            .map(|(handle, _)| *handle)
            .collect();
        for subscription in lost {
            self.retry_subscription(
                subscription,
                SubscriptionEnd::Unreachable,
                None,
                None,
                None,
                now,
            );
        }
    }
}

// -- ending, and starting again ----------------------------------------------

impl UserAgent {
    pub(crate) fn retry_or_end(
        &mut self,
        subscription: SubscriptionHandle,
        reason: SubscriptionEnd,
        status: Option<StatusCode>,
        response: Option<OwnedMessage>,
        asked_for: Option<Duration>,
        now: Instant,
    ) {
        if reason.is_worth_retrying() {
            self.retry_subscription(subscription, reason, status, response, asked_for, now);
        } else {
            self.end_subscription(subscription, reason, status, response);
        }
    }

    /// Something recoverable: start the whole thing again, later.
    ///
    /// §4.1.2.2 is exact about what "again" means, and it is not a repair:
    /// "he does so by composing an unrelated initial SUBSCRIBE request with a
    /// freshly generated Call-ID and a new, unique From tag". So the dialog
    /// goes, the identity goes, and what is kept is the question and the handle
    /// the application is holding.
    fn retry_subscription(
        &mut self,
        subscription: SubscriptionHandle,
        reason: SubscriptionEnd,
        status: Option<StatusCode>,
        response: Option<OwnedMessage>,
        asked_for: Option<Duration>,
        now: Instant,
    ) {
        let entropy = self.endpoint.token();
        let call_id = CallId::new(&self.endpoint.token());
        let local_tag = self.endpoint.token();
        let Some(held) = self.subscriptions.get_mut(&subscription) else {
            return;
        };
        held.failures = held.failures.saturating_add(1);
        // §4.1.3: `deactivated` says "the subscriber SHOULD retry immediately
        // with a new subscription" and `timeout` says clients "MAY
        // re-subscribe immediately". Once. A notifier that answers either of
        // those to an immediate retry as well is a loop, and the back-off is
        // what a loop is worth
        let immediate = held.failures <= 1
            && matches!(
                reason,
                SubscriptionEnd::Deactivated | SubscriptionEnd::Timeout
            );
        let wait = if immediate {
            Duration::ZERO
        } else {
            backoff_delay(held.failures, &entropy)
        }
        .max(asked_for.unwrap_or(Duration::ZERO));

        let dialog = held.dialog.take();
        held.state = SubscriptionState::Retrying;
        held.unsubscribing = false;
        held.unanswered = None;
        held.remote_tag = None;
        held.lapses_at = None;
        held.forks_until = None;
        held.due = Some((now + wait, Waiting::Retry));
        held.cseq = 0;
        held.call_id = call_id;
        held.local_tag = local_tag;
        // §4.1.2.4 puts an attempt that has not been notified yet in a neutral
        // state, and for RFC 4235 that is an empty table. Nothing may be read
        // out of it while the subscription is not live, which is what
        // `dialog_info` and `message_summary` are for
        held.table = DialogInfoTable::default();
        held.summary = None;
        held.conference = Conference::new();
        held.presence = None;
        self.forget_subscription_dialog(subscription, dialog);
        self.events.push_back(UaEvent::SubscriptionEnded {
            subscription,
            reason,
            status,
            retry_in: Some(wait),
            response,
        });
    }

    /// A refresh that failed in a way §4.1.2.2 does not make fatal.
    ///
    /// The subscription stands, and no event goes out: nothing the application
    /// renders has changed, and the event that matters is the one when the
    /// subscription actually ends — which happens by itself when `lapses_at`
    /// passes with nothing having refreshed it.
    fn try_again_before_it_lapses(
        &mut self,
        subscription: SubscriptionHandle,
        asked_for: Option<Duration>,
        now: Instant,
    ) {
        let entropy = self.endpoint.token();
        let Some(held) = self.subscriptions.get_mut(&subscription) else {
            return;
        };
        held.failures = held.failures.saturating_add(1);
        let wait = backoff_delay(held.failures, &entropy).max(asked_for.unwrap_or(Duration::ZERO));
        held.due = Some((now + wait, Waiting::Refresh));
    }

    /// Something trying again cannot fix. The record goes with the event.
    fn end_subscription(
        &mut self,
        subscription: SubscriptionHandle,
        reason: SubscriptionEnd,
        status: Option<StatusCode>,
        response: Option<OwnedMessage>,
    ) {
        let Some(held) = self.subscriptions.remove(&subscription) else {
            return;
        };
        self.by_subscribe.retain(|_, owner| *owner != subscription);
        self.forget_subscription_dialog(subscription, held.dialog);
        self.events.push_back(UaEvent::SubscriptionEnded {
            subscription,
            reason,
            status,
            retry_in: None,
            response,
        });
    }

    /// §4.4.1: "the destruction of a subscription results in the termination
    /// of its associated dialog", and nothing on the wire says so.
    ///
    /// Unless a sibling of a fork is still in it, which cannot happen today —
    /// §4.4.1 gives each fork its own dialog — and costs one comparison to be
    /// sure of.
    fn forget_subscription_dialog(
        &mut self,
        subscription: SubscriptionHandle,
        dialog: Option<DialogId>,
    ) {
        let Some(dialog) = dialog else {
            return;
        };
        let shared = self
            .subscriptions
            .iter()
            .any(|(handle, held)| *handle != subscription && held.dialog == Some(dialog));
        if !shared {
            self.endpoint.close_dialog(dialog);
        }
    }
}

/// §4.1.2.2's list: the responses to a refresh that end the subscription
/// rather than the attempt.
///
/// "If a SUBSCRIBE request to refresh a subscription receives a 404, 405, 410,
/// 416, 480-485, 489, 501, or 604 response, the subscriber MUST consider the
/// subscription terminated."
const fn ends_the_subscription(status: StatusCode) -> bool {
    matches!(
        status.get(),
        404 | 405 | 410 | 416 | 480..=485 | 489 | 501 | 604
    )
}

/// What a final response that is not a 2xx says about trying again.
const fn refusal(status: StatusCode) -> SubscriptionEnd {
    match status.get() {
        // §8.3.2: "489 (Bad Event) is used to indicate that the server did not
        // understand the event package specified in a Event header field"
        489 => SubscriptionEnd::BadEvent,
        300..=399 => SubscriptionEnd::Redirected,
        500..=599 => SubscriptionEnd::Unreachable,
        _ => SubscriptionEnd::Refused,
    }
}
