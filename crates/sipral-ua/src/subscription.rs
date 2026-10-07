// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Subscriptions: asking to be told, and staying told (RFC 6665).
//!
//! **The dialog is opened by the NOTIFY, not by the 200** (§4.4.1): the route
//! set comes from the NOTIFY, and opening on the 2xx would send refreshes past
//! a record-routing proxy. The NOTIFY may also arrive before the 2xx
//! (§4.1.2.4), so a subscription is matched only on `Call-ID`, our `From` tag
//! and the `Event`, all known when the SUBSCRIBE leaves. That is why the tag
//! is chosen here, not by the endpoint.
//!
//! **Timer N** (§4.1.2.4, 64·T1 from SUBSCRIBE to the first NOTIFY): if it
//! fires there is no subscription, whatever the 200 said.
//!
//! **A failure is an event and leaves nothing behind.** The handle is minted
//! first, so a SUBSCRIBE that never reaches a socket is reported under it and
//! its record removed at once, with no timer left. Refreshes and retries that
//! cannot be sent take the same path.
//!
//! **Batches do not wait.** Each SUBSCRIBE goes straight to the transmit
//! queue; [`UserAgent::subscribe_many`] only drains once and turns a failing
//! target into an event. The stack owns no socket, so pacing is the
//! application's.

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
/// One hour, RFC 4235 §3.4's default; the same as a registration, so a phone
/// wakes once for both.
pub const DEFAULT_EXPIRES: Duration = Duration::from_hours(1);

/// One subscription the application is watching.
///
/// Minted before anything is sent, so a failed SUBSCRIBE can be reported
/// under it. Never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionHandle(pub(crate) u32);

/// Where a subscription is (RFC 6665 §4.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubscriptionState {
    /// A SUBSCRIBE is out and no NOTIFY has arrived. The RFC's `notify_wait`,
    /// and the only state Timer N runs in.
    Requesting,
    /// The notifier has not decided yet (§4.1.3). Nothing is known about the
    /// resource.
    Pending,
    /// Notifications are arriving and the state is being kept up to date.
    Active,
    /// It ended in a way worth retrying, and the next attempt is scheduled.
    ///
    /// There is no final state: a subscription ended for good has no record,
    /// and [`UaEvent::SubscriptionEnded`] with no `retry_in` was the last word.
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
/// The first seven are §4.1.3's reason codes as the notifier sent them; the
/// rest are failures this end saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubscriptionEnd {
    /// `reason=deactivated`: retry at once with a new subscription.
    Deactivated,
    /// `reason=probation`: come back after `retry-after`.
    Probation,
    /// `reason=rejected`: authorisation changed; not retried.
    Rejected,
    /// `reason=timeout`: it lapsed. Also what a poll gets (§4.4.3).
    Timeout,
    /// `reason=giveup`: authorisation took too long.
    GaveUp,
    /// `reason=noresource`: nothing left to watch; not retried.
    NoResource,
    /// `reason=invariant`: the state will never change again.
    Invariant,
    /// `terminated` with no reason or an unknown one; retried (§4.1.3).
    Unstated,
    /// The application asked, with `Expires: 0` (§4.1.2.3).
    Unsubscribed,
    /// A 489: the event package is unknown to the notifier.
    BadEvent,
    /// A final refusal retrying cannot fix, such as 403 or 404.
    Refused,
    /// A 3xx. Following it needs name resolution, which is the caller's.
    Redirected,
    /// A timeout, a dead transport or a 5xx.
    Unreachable,
    /// Accepted, but no NOTIFY before Timer N (§4.1.2.4).
    NoNotify,
    /// The granted lifetime ran out with no successful refresh.
    Expired,
}

impl SubscriptionEnd {
    /// Whether asking again could give a different answer.
    ///
    /// §4.1.3 forbids retrying after `rejected`, `noresource` and
    /// `invariant`. Of this end's reasons, refusals are not retried and
    /// outages are. `Expired` is not retried either: the lifetime ran out on
    /// this end's side, and asking again is a new `subscribe`.
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
    /// (RFC 4235 §3.1), `message-summary` (RFC 3842 §3), `presence` (RFC 3856
    /// §6.1). Compared byte for byte (§8.2.1), so it goes out as written.
    ///
    /// Sent on the account's transport to the account's address (its
    /// registrar's outbound proxy, or the one given to
    /// [`crate::Account::unregistered`]).
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
    /// What the notifier grants wins (§3.1.1); the refresh follows that.
    #[must_use]
    pub const fn expires(mut self, expires: Duration) -> Self {
        self.expires = expires;
        self
    }

    /// The `Accept` value. Left out, no `Accept` is sent and the package default applies
    /// (§3.1.3). Nothing is guessed: a wrong type gets a 406 (§4.1.2.1).
    #[must_use]
    pub fn accept(mut self, media_type: &[u8]) -> Self {
        self.accept = Some(Box::from(media_type));
        self
    }

    /// Send it somewhere other than the account's address.
    /// Name resolution is the caller's.
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
    /// Kept because a re-subscription starts over (§4.1.2.2).
    wanted: Subscribe,
    call_id: CallId,
    /// Chosen here: a NOTIFY can arrive before the 2xx (§4.4.1).
    local_tag: Box<[u8]>,
    /// The notifier's; tells one fork from another (§4.1.4).
    remote_tag: Option<Box<[u8]>>,
    /// The last out-of-dialog CSeq, continued by the dialog.
    cseq: u32,
    dialog: Option<DialogId>,
    /// From the 2xx (§3.1.1) or a `Subscription-State` (§4.1.3).
    granted: Duration,
    lapses_at: Option<Instant>,
    due: Option<(Instant, Waiting)>,
    /// Until when a NOTIFY may open another forked dialog (§4.1.2.4).
    forks_until: Option<Instant>,
    /// Consecutive retryable failures, for the back-off.
    failures: u32,
    unsubscribing: bool,
    /// A challenge nothing has answered yet, kept for the event.
    pub(crate) unanswered: Option<OwnedMessage>,
    /// A challenged SUBSCRIBE too large for a datagram (§18.1.1), waiting
    /// for a stream. While set, `unanswered` is not yet a refusal.
    pub(crate) waiting_for_stream: Option<AnyTransactionId>,
    /// RFC 4235 §4.3's table.
    table: DialogInfoTable,
    /// RFC 3842 §3.5: a whole snapshot each time, replaced, not merged.
    summary: Option<Arc<MessageSummary>>,
    /// RFC 4575 §4.6, merged. Reset per attempt: `version` is per
    /// subscription.
    conference: Conference,
    /// RFC 3856 §6.8: full state each time, replaced whole.
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
    /// Same identity and numbering, its own dialog (§4.4.1). The fork window
    /// stays with the original attempt.
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
    /// Only from `distrust`: deadlines measured before a sleep are meaningless
    /// after it. `UserAgent::resubscribe` re-arms them.
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
    /// Refreshes, credential retries and re-subscription after an outage need
    /// no further call. It stops on [`UserAgent::unsubscribe`] or a refusal
    /// retrying cannot fix.
    ///
    /// The handle comes back even if the SUBSCRIBE reached no transport; that
    /// is reported as [`UaEvent::SubscriptionEnded`] with
    /// [`SubscriptionEnd::Unreachable`] and no `retry_in`, like every later
    /// failure, and the handle then names nothing.
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
    /// Unlike [`UserAgent::subscribe`] in a loop, events are drained once and
    /// a failing target does not stop the rest.
    ///
    /// Every handle comes back in order, including those whose request never
    /// left; they have already queued [`UaEvent::SubscriptionEnded`].
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], before anything is sent.
    pub fn subscribe_many(
        &mut self,
        account: AccountId,
        wanted: &[Subscribe],
        now: Instant,
    ) -> Result<Vec<SubscriptionHandle>, UaError> {
        // checked once, so a batch mints every handle or none
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
    /// Not over on return: the closing NOTIFY is still answered (§4.4.1), then
    /// [`UaEvent::SubscriptionEnded`] with [`SubscriptionEnd::Unsubscribed`].
    /// One with no dialog yet ends at once.
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
    /// `None` while the subscription is not live. An unrefreshed or empty
    /// table would show the colleague as free, the one wrong answer a busy
    /// lamp field must never give; the application shows "unknown" instead.
    #[must_use]
    pub fn dialog_info(&self, subscription: SubscriptionHandle) -> Option<&DialogInfoTable> {
        let held = self.subscriptions.get(&subscription)?;
        held.state.is_live().then_some(&held.table)
    }

    /// The last `application/simple-message-summary` document a `message-summary`
    /// subscription was told (RFC 3842 §3.5).
    ///
    /// `None` while the subscription is not live, as in
    /// [`UserAgent::dialog_info`]. Never merged: each NOTIFY is the whole
    /// picture.
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
    /// `None` while not live (see [`UserAgent::dialog_info`]) or before any
    /// document named the conference.
    #[must_use]
    pub fn conference(&self, subscription: SubscriptionHandle) -> Option<&Conference> {
        let held = self.subscriptions.get(&subscription)?;
        (held.state.is_live() && held.conference.entity().is_some()).then_some(&held.conference)
    }

    /// The last presence document (RFC 3856 §6.8); `None` while not live.
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
        // Timer N (§4.1.2.4), also the window for forks
        held.due = Some((now + timer_n, Waiting::Notify));
        held.forks_until = Some(now + timer_n);
        let account = held.account;
        self.claim_subscribe(subscription, id);
        self.events.push_back(UaEvent::Subscribing {
            subscription,
            account,
        });
    }

    /// A fresh SUBSCRIBE for every subscription `distrust` demoted.
    /// `Retrying` with no `due` marks them: `retry_subscription` always sets
    /// `due`, only `stop_timers` clears it. `true` when at least one reached a
    /// transport, as in `reregister`.
    pub(crate) fn resubscribe(&mut self, now: Instant) -> bool {
        let waiting: Vec<SubscriptionHandle> = self
            .subscriptions
            .iter()
            .filter(|(_, held)| held.state == SubscriptionState::Retrying && held.due.is_none())
            .map(|(handle, _)| *handle)
            .collect();
        let mut sent = false;
        for subscription in waiting {
            // a new subscription needs a new Call-ID and tag (RFC 6665
            // §4.1.2.4); reusing them would collide with the dead one at the
            // notifier
            let call_id = CallId::new(&self.endpoint.token());
            let local_tag = self.endpoint.token();
            if let Some(held) = self.subscriptions.get_mut(&subscription) {
                held.call_id = call_id;
                held.local_tag = local_tag;
                held.cseq = 0;
            }
            self.start_subscription(subscription, now);
            // a failed send ends it, as for `UserAgent::subscribe`
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
            // a refresh restarts Timer N (§4.1.2.2)
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

    /// A SUBSCRIBE that never reached a transport: the record goes with the
    /// event.
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
                // Timer N expired: the attempt failed (§4.1.2.4)
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

        // the notifier side: REFER subscriptions and pending referrals
        self.fire_refer_subscriptions(now);
        self.fire_referral_timers(now);
    }

    /// The next subscription deadline, subscriber or notifier side.
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
        // the transport may have gone since scheduling; one held back for a
        // stream (§18.1.1) is parked, not failed
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

/// The out-of-dialog SUBSCRIBE that starts an attempt (§4.1.2.1).
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
    // §8.1.1.8; RFC 5627 §4.4 for the GRUU
    .contact(&dialog_contact(
        account,
        learned,
        anonymous(&held.wanted.extra),
    ))
    .header(HeaderName::Event, &held.wanted.package)
    .header(HeaderName::Expires, seconds.as_bytes());
    // RFC 5627 §4.4
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

/// The in-dialog one that refreshes or ends it, with a GRUU (RFC 5627 §4.4)
/// and the dialog's route, not the service route.
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
    /// `None` when the event was a subscription's; otherwise it comes back.
    /// An unmatched NOTIFY is refused 481 here (§4.1.3), so this runs after
    /// the transfer handler, which claims the `refer` package inside calls
    /// (RFC 3515 §2.4.4).
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
            // answers to other layers' requests must pass through
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
            Event::Challenged { transaction, .. } | Event::TokenChallenged { transaction, .. } => {
                let Some(subscription) = self.by_subscribe.get(&transaction).copied() else {
                    return Some(event);
                };
                self.on_subscribe_challenged(subscription, transaction, now);
                None
            }
            // a lamp fed by a dead flow lies
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
            // §4.1.3: 489 for an unsupported package
            Matched::WrongPackage => self.refuse_notify(transaction, BAD_EVENT, now),
            Matched::Nobody => {
                self.refuse_notify(transaction, StatusCode::CALL_DOES_NOT_EXIST, now);
            }
        }
    }

    /// §4.4.1: same `Call-ID`, `To` tag equal to our `From` tag, same `Event`.
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
        // §8.2.1: byte for byte, and the id must match too
        let ours = |held: &Subscription| {
            named(held)
                && EventRef::parse(&held.wanted.package).is_ok_and(|ours| ours.matches(&theirs))
        };
        if !self.subscriptions.values().any(ours) {
            return Matched::WrongPackage;
        }
        // a known `From` tag is a retransmission, not a fork (§4.1.4)
        if let Some(theirs) = request.from().ok().and_then(|from| from.tag())
            && let Some((known, _)) = self
                .subscriptions
                .iter()
                .find(|(_, held)| ours(held) && held.remote_tag.as_deref() == Some(&*theirs))
        {
            return Matched::Fresh(*known);
        }
        if let Some((waiting, _)) = self
            .subscriptions
            .iter()
            .find(|(_, held)| ours(held) && held.dialog.is_none())
        {
            return Matched::Fresh(*waiting);
        }
        // a second notifier before Timer N gets its own subscription
        // (§4.1.2.4)
        if let Some((parent, _)) = self
            .subscriptions
            .iter()
            .find(|(_, held)| ours(held) && held.forks_until.is_some_and(|until| now < until))
        {
            return Matched::Forked(*parent);
        }
        // after Timer N, a new fork gets 481 (§4.1.2.4)
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
    /// `Call-ID` and tag match, the `Event` does not.
    WrongPackage,
    /// Nothing here asked for this.
    Nobody,
}

/// 489, which §8.3.2 adds for an event package the far end does not know.
const BAD_EVENT: StatusCode = match StatusCode::new(489) {
    Ok(status) => status,
    // unreachable; avoids a panic
    Err(_) => StatusCode::CALL_DOES_NOT_EXIST,
};

/// 400, for a NOTIFY without `Subscription-State` (§4.1.3).
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
        // §4.4.1: same dialog and matching Event
        if !self.package_of(subscription, &raw) {
            self.refuse_notify(transaction, BAD_EVENT, now);
            return;
        }
        // mandatory (§4.1.3)
        let Ok(state) = raw.subscription_state() else {
            self.refuse_notify(transaction, BAD_REQUEST, now);
            return;
        };
        let over = state.state() == Substate::Terminated;
        // §4.4.1: no dialog for a `terminated` NOTIFY. Opened before the 200:
        // on a reliable transport Timer J is zero (§17.2.2), and the
        // transaction the dialog is built from dies with the response.
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

    /// Whether the NOTIFY's `Event` is the one asked for (§8.2.1).
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
        // §4.1.3: the stated `expires` is authoritative
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
        // typed events follow the raw NOTIFY
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
        // only a state change is an event, not every refresh
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
        // a malformed body leaves the last known table standing
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

    /// A refresh to get full state after a gap (RFC 4235 §4.3), unless one is
    /// already in flight; otherwise a badly numbering notifier would cause one
    /// request per notification.
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
    /// [`UaEvent::MessagesWaiting`] for it (RFC 3842 §3.9).
    ///
    /// A malformed body leaves the last good reading standing. An unsolicited
    /// `message-summary` NOTIFY, which several PBXs send, never gets here:
    /// `match_notify` answers it 481 like any other (RFC 6665 §4.1.3).
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
    /// subscription's picture of the conference (RFC 4575 §4.6).
    ///
    /// A gap asks for full state with a refresh; a deleted conference ends
    /// the subscription (§4.6). A malformed body changes nothing.
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
                self.unsubscribe(subscription, now).ok();
            }
            ConferenceUpdate::Resubscribe => self.ask_for_full_state(subscription, now),
            // late, repeated, or held off while full state is on its way
            _ => {}
        }
    }

    /// Read an `application/pidf+xml` body of a `presence` subscription and
    /// raise [`UaEvent::PresenceChanged`] for it (RFC 3856 §6.8).
    /// Full state each time; a malformed body leaves the last one standing.
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

    /// Whether the subscription asked for `package` (§8.2.1).
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
            return;
        }
        if status.is_success() {
            self.on_subscribe_accepted(subscription, response, now);
            return;
        }
        if matches!(status.get(), 401 | 407) {
            // held until the drain ends: a challenge may still follow
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
        // §3.1.1: the 2xx `Expires` defines the duration
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
        // Timer N keeps running until the NOTIFY (§4.1.2.4)
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
        // §4.1.2.2: other refresh failures leave the subscription valid
        // until its last known expiry
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
        // timeout and dead transport are treated alike
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
        let account = self
            .subscriptions
            .get(&subscription)
            .map(|held| held.account);
        let Some(credentials) = self.credentials_for_challenge(account, transaction) else {
            // no credentials: the refusal stands
            return;
        };
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => self.subscribe_retry_went(subscription, transaction, retried),
            // §18.1.1 wants a connection first; CSeq stays, nothing went out
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let Some(held) = self.subscriptions.get_mut(&subscription) {
                    held.waiting_for_stream = Some(transaction);
                }
            }
            Err(_) => {}
        }
    }

    /// Point everything at the retry's transaction.
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
            // the retry took the next CSeq (§22.2); the dialog continues it
            held.cseq = held.cseq.saturating_add(1);
        }
    }

    /// Send the retries §18.1.1 held back, now that a stream exists.
    pub(crate) fn resume_parked_subscriptions(&mut self, now: Instant) {
        let waiting: Vec<(SubscriptionHandle, AnyTransactionId)> = self
            .subscriptions
            .iter()
            .filter_map(|(handle, held)| held.waiting_for_stream.map(|failed| (*handle, failed)))
            .collect();
        for (subscription, failed) in waiting {
            let account = self
                .subscriptions
                .get(&subscription)
                .map(|held| held.account);
            let Some(credentials) = self.credentials_for_challenge(account, failed) else {
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

    /// Stop holding one back; the next settle reports its refusal.
    fn stop_waiting_for_subscribe(&mut self, subscription: SubscriptionHandle) {
        if let Some(held) = self.subscriptions.get_mut(&subscription) {
            held.waiting_for_stream = None;
        }
    }

    /// A challenge that got no retry was a refusal, as in registration: the
    /// core answers once, so silence means wrong credentials (§22.1).
    pub(crate) fn settle_subscription_challenges(&mut self, now: Instant) {
        let refused: Vec<(SubscriptionHandle, OwnedMessage)> = self
            .subscriptions
            .iter_mut()
            // not one still waiting for a stream: its retry has not gone
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
    /// Otherwise the stale table would show a colleague as free until the
    /// next refresh, up to an hour away.
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
    /// §4.1.2.2: a new Call-ID and `From` tag; only the request and the handle
    /// are kept.
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
        // §4.1.3: `deactivated` and `timeout` allow an immediate retry, but
        // only once, or a notifier could loop us
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
        // neutral state (§4.1.2.4), hidden by the accessors until live
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
    /// No event: the subscription stands, and ends by itself at `lapses_at`
    /// if no refresh succeeds.
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

    /// Close the dialog with the subscription (§4.4.1), unless another
    /// subscription still uses it.
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

/// §4.1.2.2's list: refresh responses that end the subscription, not just
/// the attempt.
const fn ends_the_subscription(status: StatusCode) -> bool {
    matches!(
        status.get(),
        404 | 405 | 410 | 416 | 480..=485 | 489 | 501 | 604
    )
}

/// What a final response that is not a 2xx says about trying again.
const fn refusal(status: StatusCode) -> SubscriptionEnd {
    match status.get() {
        // §8.3.2
        489 => SubscriptionEnd::BadEvent,
        300..=399 => SubscriptionEnd::Redirected,
        500..=599 => SubscriptionEnd::Unreachable,
        _ => SubscriptionEnd::Refused,
    }
}
