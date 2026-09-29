// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Watching something at the far end: SUBSCRIBE, NOTIFY, and the busy lamp
//! field on top of them.
//!
//! `crates/sipral-ua/src/subscription.rs` already does all of it — the
//! transaction, the dialog, timer N, the refresh at a fraction of what the
//! notifier granted, the fork that turns one SUBSCRIBE into two subscriptions
//! (RFC 6665 §4.1.4), and the retry with a fresh `Call-ID` after something
//! recoverable. What was missing was any way to reach it from C, which is why
//! `sipral_capabilities` reported [`SIPRAL_FEATURE_SUBSCRIPTIONS`] off while
//! the feature was sitting there compiled in.
//!
//! [`SIPRAL_FEATURE_SUBSCRIPTIONS`]: crate::capabilities::SIPRAL_FEATURE_SUBSCRIPTIONS
//!
//! # A subscription is a handle of its own
//!
//! Not an account's and not a call's: one account holds thirty of them on a
//! desk phone, each with its own dialog, its own refresh and its own state.
//! [`sipral_account_subscribe`] mints one, and the handle is dead once
//! `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` says the subscription ended with
//! nothing more coming.
//!
//! A sibling from a fork appears by itself, in an event, the way an incoming
//! call does: RFC 4235 §3.9 makes that the normal case for dialog state, one
//! subscription per device the watched address is registered on, and each is
//! answerable on its own.
//!
//! # What a NOTIFY brings
//!
//! Two events rather than one, because they answer different questions. The
//! state changing — requesting, pending, active, ended — is
//! `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED`, and it is what a lamp goes grey
//! on. A notification arriving is
//! `SIPRAL_EVENT_KIND_NOTIFIED`, and it is what a lamp changes colour on: the
//! NOTIFY is in `sipral_event_t::message`, whole and unparsed, for a package
//! this ABI has no reader for, and for `dialog` the parsed picture is behind
//! [`sipral_subscription_dialog_count`] and [`sipral_subscription_dialog_at`].
//! A state change is not sent on every refresh: a lamp does not move because a
//! refresh was scheduled.
//!
//! # What does not cross, and why
//!
//! Application header fields on a SUBSCRIBE. `sipral_ua::Subscribe::header`
//! takes them in Rust, but the list of fields the stack writes itself is kept
//! per kind of message (`HeadersFor`), and a SUBSCRIBE has no entry in it: a
//! subscription writes `Event`, `Expires`, `Accept` and the dialog's own
//! fields, and deciding which of those an application may overwrite is a
//! policy for `sipral-ua` rather than something this boundary should invent.
//!
//! Subscribing to many things in one call. `sipral_ua::UserAgent::subscribe_many`
//! exists so that a phone's thirty lamps leave as one burst rather than thirty
//! round trips — but nothing in it waits, so a C caller doing thirty
//! `sipral_account_subscribe` calls before its next poll gets the same burst.
//! What the batch adds over the loop is that its events are drained once, and
//! this ABI drains on the poll either way. An array of configs going in would
//! also cost the config struct its `size` member, which is what lets it grow
//! later, and a permanent shape is a high price for a loop.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::time::Duration;

use sipral_core::msg::Uri;
use sipral_ua::{
    DialogEnded, DialogInfoTable, DialogPhase, Initiated, Subscribe, SubscriptionEnd,
    SubscriptionHandle, SubscriptionState, WatchedDialog,
};

use crate::abi::{codes, record};
use crate::call::ua_failed;
use crate::diagnostics::copy_out;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{required_text, text};
use crate::versioned::{Versioned, declared_size, read_versioned, write_versioned};

codes! {
    /// Where a subscription is. Names for
    /// `sipral_subscription_event_t::state` and for
    /// [`sipral_subscription_state`]'s `out_state`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralSubscriptionState: u32 {
        /// The handle names nothing: never minted here, or ended and let go.
        Unknown = 0,
        /// A SUBSCRIBE is on its way and nothing has answered it yet.
        Requesting = 1,
        /// The notifier has it and has not decided. RFC 6665 §4.1.3's
        /// `pending` is "insufficient policy information to grant or deny the
        /// subscription yet", and nothing is known about the watched thing
        /// until this becomes [`SipralSubscriptionState::Active`].
        Pending = 2,
        /// Granted, and notifications are arriving.
        Active = 3,
        /// Not live, and a fresh attempt is scheduled. The handle stays
        /// valid: §4.1.2.2's new attempt is "an unrelated initial SUBSCRIBE
        /// request with a freshly generated Call-ID and a new, unique From
        /// tag", and this ABI keeps one name over both of them.
        Retrying = 4,
        /// Over, with nothing more coming. The handle names nothing from
        /// here on.
        Ended = 5,
    }
}

codes! {
    /// Why a subscription is not live. Names for
    /// `sipral_subscription_event_t::reason`.
    ///
    /// Zero unless the state is [`SipralSubscriptionState::Retrying`] or
    /// [`SipralSubscriptionState::Ended`]. The first nine are what a
    /// `Subscription-State: terminated` said in its `reason` parameter (RFC
    /// 6665 §4.1.3), and the rest are what happened here instead.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralSubscriptionEnd: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// `deactivated`: the notifier wants this subscription started again
        /// at once.
        Deactivated = 1,
        /// `probation`: started again, but not immediately.
        Probation = 2,
        /// `rejected`: the notifier will not serve it, and asking again is
        /// pointless.
        Rejected = 3,
        /// `timeout`: it ran out rather than being refreshed.
        Timeout = 4,
        /// `giveup`: the notifier could not decide and stopped trying.
        GaveUp = 5,
        /// `noresource`: what was being watched does not exist any more.
        NoResource = 6,
        /// `invariant`: the watched thing cannot change, so there is nothing
        /// to notify about.
        Invariant = 7,
        /// `terminated` with no reason parameter at all.
        Unstated = 8,
        /// This end gave it up: [`sipral_subscription_end`]. It wins over
        /// whatever the notifier's closing notification said its own reason
        /// was, because the application asked for this one to stop and that
        /// is the answer to why it is not live.
        Unsubscribed = 9,
        /// The notifier answered 489: it does not know this event package.
        BadEvent = 10,
        /// The notifier refused the SUBSCRIBE with a status trying again
        /// cannot fix.
        Refused = 11,
        /// The SUBSCRIBE was redirected, and following a redirect for one is
        /// not something this stack does by itself.
        Redirected = 12,
        /// Nothing answered: the notifier could not be reached at all.
        Unreachable = 13,
        /// The SUBSCRIBE was answered and the first NOTIFY never arrived
        /// (§4.1.2.4's timer N, 64·T1).
        NoNotify = 14,
        /// What the notifier granted ran out with no refresh answered.
        Expired = 15,
    }
}

record! {
    /// What to watch, and how. Handed to [`sipral_account_subscribe`].
    ///
    /// Set `size` to `sizeof(sipral_subscribe_config_t)` before the call.
    /// Everything but `target` and `package` may be left zero.
    #[derive(Clone, Copy)]
    pub struct SipralSubscribeConfig {
        /// How long this struct is, as the caller's header declares it.
        pub size: usize,
        /// What to watch, as a SIP URI: `sip:2001@pbx.example.com`.
        pub target: *const c_char,
        /// How many bytes of it.
        pub target_len: usize,
        /// The event package, as the token that names it: `dialog` for a busy
        /// lamp field (RFC 4235 §3.1), `message-summary` for message waiting
        /// (RFC 3842 §3), `presence` (RFC 3856 §6.1).
        ///
        /// It goes out exactly as written here, because §8.2.1 compares it
        /// byte for byte.
        pub package: *const c_char,
        /// How many bytes of it.
        pub package_len: usize,
        /// The `Accept` value, when the package's default body type is not
        /// the one wanted. Null sends no `Accept` at all, which §3.1.3 makes
        /// the package's default — `application/dialog-info+xml` for
        /// `dialog`.
        ///
        /// Sending the wrong one is worse than sending none: §4.1.2.1 has the
        /// notifier answer 406 for a type it cannot generate, so nothing is
        /// guessed on a caller's behalf.
        pub accept: *const c_char,
        /// How many bytes of it.
        pub accept_len: usize,
        /// How long to ask for, in seconds, or zero for this build's default
        /// of one hour.
        ///
        /// What the notifier grants wins (§3.1.1: "The period of time in the
        /// response is the one that defines the duration of the
        /// subscription"), and the refresh is scheduled against that rather
        /// than against this.
        pub expires_seconds: u32,
        /// Where to send the SUBSCRIBE, as `host:port`, or null to send it
        /// where the account registers — which is the outbound proxy for a
        /// registered line, and the reason a phone behind a NAT is reachable
        /// at all.
        pub destination: *const c_char,
        /// How many bytes of it.
        pub destination_len: usize,
        /// Which transport it goes out on, read only together with
        /// `destination`, exactly as `sipral_call_config_t::transport` is.
        /// Nonzero with `destination` null is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub transport: u32,
    }
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and all-zero is valid: every pointer is null beside a length of
// zero, and a zero `expires_seconds` is the default.
unsafe impl Versioned for SipralSubscribeConfig {
    const NAME: &'static str = "sipral_subscribe_config";
    const MIN_SIZE: usize = crate::versioned::min_size::SUBSCRIBE_CONFIG;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// The C name for one of the states the layer below reports.
pub(crate) const fn named_state(state: SubscriptionState) -> SipralSubscriptionState {
    match state {
        SubscriptionState::Requesting => SipralSubscriptionState::Requesting,
        SubscriptionState::Pending => SipralSubscriptionState::Pending,
        SubscriptionState::Active => SipralSubscriptionState::Active,
        SubscriptionState::Retrying => SipralSubscriptionState::Retrying,
        // the layer below marks it `non_exhaustive`, and a state this build
        // has no number for is reported as no state rather than as the wrong
        // one: a lamp that goes grey is right about not knowing
        _ => SipralSubscriptionState::Unknown,
    }
}

/// The C name for why one ended.
pub(crate) const fn named_end(reason: SubscriptionEnd) -> SipralSubscriptionEnd {
    match reason {
        SubscriptionEnd::Deactivated => SipralSubscriptionEnd::Deactivated,
        SubscriptionEnd::Probation => SipralSubscriptionEnd::Probation,
        SubscriptionEnd::Rejected => SipralSubscriptionEnd::Rejected,
        SubscriptionEnd::Timeout => SipralSubscriptionEnd::Timeout,
        SubscriptionEnd::GaveUp => SipralSubscriptionEnd::GaveUp,
        SubscriptionEnd::NoResource => SipralSubscriptionEnd::NoResource,
        SubscriptionEnd::Invariant => SipralSubscriptionEnd::Invariant,
        SubscriptionEnd::Unstated => SipralSubscriptionEnd::Unstated,
        SubscriptionEnd::Unsubscribed => SipralSubscriptionEnd::Unsubscribed,
        SubscriptionEnd::BadEvent => SipralSubscriptionEnd::BadEvent,
        SubscriptionEnd::Refused => SipralSubscriptionEnd::Refused,
        SubscriptionEnd::Redirected => SipralSubscriptionEnd::Redirected,
        SubscriptionEnd::Unreachable => SipralSubscriptionEnd::Unreachable,
        SubscriptionEnd::NoNotify => SipralSubscriptionEnd::NoNotify,
        SubscriptionEnd::Expired => SipralSubscriptionEnd::Expired,
        // as above: a reason this build has no number for is no reason
        _ => SipralSubscriptionEnd::Unknown,
    }
}

/// The subscription a handle names, or why it names nothing.
pub(crate) fn subscription_of(
    state: &StackState,
    subscription: SipralHandle,
) -> Result<SubscriptionHandle, Fail> {
    state.subscriptions.get(subscription).map_err(handle_failed)
}

/// Turn what crossed the boundary into a [`Subscribe`], or say what was wrong.
///
/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn subscribe_from(
    state: &StackState,
    config: &SipralSubscribeConfig,
) -> Result<Subscribe, Fail> {
    let target = unsafe { required_text(config.target, config.target_len, "target") }?;
    let Ok(uri) = Uri::parse(target.as_bytes()) else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("target is {target:?}, which is not a URI"),
        ));
    };
    let package = unsafe { required_text(config.package, config.package_len, "package") }?;
    if package.bytes().any(|byte| byte <= b' ' || byte >= 0x7f) {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("package is {package:?}, and an event package is one token"),
        ));
    }
    let mut wanted = Subscribe::new(uri, package);
    if config.expires_seconds != 0 {
        wanted = wanted.expires(Duration::from_secs(u64::from(config.expires_seconds)));
    }
    if let Some(accept) = unsafe { text(config.accept, config.accept_len, "accept") }? {
        wanted = wanted.accept(accept.as_bytes());
    }
    if let Some(elsewhere) =
        unsafe { text(config.destination, config.destination_len, "destination") }?
    {
        let Ok(address) = elsewhere.parse::<SocketAddr>() else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("destination is {elsewhere:?}, which is not an address and a port"),
            ));
        };
        wanted = wanted.to_address(crate::transport::named(state, config.transport)?, address);
    } else if config.transport != 0 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "transport is read together with destination; a subscription with no destination \
             override already goes out on its account's own transport",
        ));
    }
    Ok(wanted)
}

entry! {
    /// Watch something at the far end (A1).
    ///
    /// One SUBSCRIBE goes out on `account`'s transport, to `account`'s
    /// address, and the handle written back names the subscription from now
    /// until it ends. Nothing has happened yet when this returns: the request
    /// is in the transmit queue, and
    /// `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step of what
    /// becomes of it.
    ///
    /// A subscription refreshes itself for as long as it is live, at a
    /// fraction of what the notifier granted, and starts a fresh one by itself
    /// after something recoverable — both under this same handle. What ends
    /// it for good is [`sipral_subscription_end`], or an event saying it
    /// ended with no retry, and the handle names nothing after that.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_subscribe_config_t` whose `size`
    /// member says how long it is, with every pointer in it readable for the
    /// length beside it. `out_subscription` must point at one
    /// `sipral_handle_t`.
    fn sipral_account_subscribe(
        stack: SipralHandle,
        account: SipralHandle,
        config: *const SipralSubscribeConfig,
        out_subscription: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_subscription.is_null() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "out_subscription is null",
            ));
        }
        let config = unsafe { read_versioned(config) }?;
        with_stack_at(stack, now_ms, |state, now| {
            let named = state.accounts.get(account).map_err(handle_failed)?;
            let wanted = unsafe { subscribe_from(state, &config) }?;
            let made = state
                .agent
                .subscribe(named, &wanted, now)
                .map_err(|error| ua_failed(&error))?;
            let handle = state.subscriptions.insert(made).map_err(|status| {
                fail(
                    status,
                    "this stack has handed out every subscription handle it has room for",
                )
            })?;
            unsafe { out_subscription.write(handle) };
            Ok(())
        })
    }
}

entry! {
    /// Give a subscription up.
    ///
    /// A SUBSCRIBE with `Expires: 0` (§4.1.2.3), and the subscription is not
    /// over when this returns: §4.4.1 makes it live "until the NOTIFY
    /// transaction with a `Subscription-State` of `terminated` completes", so
    /// the closing notification is still answered and
    /// `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
    /// `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when it has. One that has
    /// no dialog yet has nothing to send this in and ends at once.
    ///
    /// The handle stays usable until that event arrives, and names nothing
    /// after it.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_subscription_end(stack: SipralHandle, subscription: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let named = subscription_of(state, subscription)?;
            state
                .agent
                .unsubscribe(named, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Where a subscription is, without waiting for its next event.
    ///
    /// [`SipralSubscriptionState::Unknown`] for a handle that names nothing,
    /// which is what a subscription that has ended leaves behind — and a
    /// status of `SIPRAL_STATUS_OK` all the same, because "it is over" is an
    /// answer to this question rather than a failure of it.
    ///
    /// # Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    fn sipral_subscription_state(
        stack: SipralHandle,
        subscription: SipralHandle,
        out_state: *mut u32,
    ) {
        if out_state.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_state is null"));
        }
        with_stack(stack, |state| {
            let found = state
                .subscriptions
                .get(subscription)
                .ok()
                .and_then(|named| state.agent.subscription_state(named))
                .map_or(SipralSubscriptionState::Unknown, named_state);
            unsafe { out_state.write(found as u32) };
            Ok(())
        })
    }
}

codes! {
    /// What one watched dialog is doing, and what a lamp is lit from. Names
    /// for `sipral_watched_dialog_t::phase` and for
    /// [`sipral_subscription_lamp`]'s `out_phase`.
    ///
    /// RFC 4235 §3.7.1's states, with the order they rank in for a lamp:
    /// anything ringing beats anything settled, which is §3.7.2's virtual
    /// state machine over every dialog of one resource.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDialogPhase: u32 {
        /// Nothing is going on: no dialog, or every one of them terminated.
        /// This is what an idle lamp shows.
        Idle = 0,
        /// A request went out and nothing has answered.
        Trying = 1,
        /// Something answered without ringing yet.
        Proceeding = 2,
        /// Ringing.
        Early = 3,
        /// A call is up.
        Confirmed = 4,
        /// This dialog is over. Never [`sipral_subscription_lamp`]'s answer,
        /// which is [`SipralDialogPhase::Idle`] when every dialog has ended.
        Terminated = 5,
        /// The notifier named a state this build has no number for.
        Unknown = 6,
    }
}

codes! {
    /// Which end started a watched dialog. Names for
    /// `sipral_watched_dialog_t::direction`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDialogDirection: u32 {
        /// The notifier did not say.
        Unknown = 0,
        /// The watched end placed the call.
        Locally = 1,
        /// The watched end was called.
        Remotely = 2,
    }
}

codes! {
    /// How a watched dialog ended. Names for
    /// `sipral_watched_dialog_t::ended`, and zero while it has not.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDialogEnded: u32 {
        /// It has not ended, or the notifier did not say how.
        Unknown = 0,
        /// The caller gave up before it was answered.
        Cancelled = 1,
        /// The called end refused it.
        Rejected = 2,
        /// A `Replaces` took it over.
        Replaced = 3,
        /// The watched end hung up.
        LocalBye = 4,
        /// The far end hung up.
        RemoteBye = 5,
        /// Something went wrong with it.
        Error = 6,
        /// Nothing answered in time.
        Timeout = 7,
    }
}

codes! {
    /// Which piece of text [`sipral_subscription_dialog_text`] is being asked
    /// for.
    ///
    /// Every one of them is what the notifier wrote, unparsed: a display name
    /// is whatever it put there, and an identity is a URI in the form it sent
    /// it in.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDialogText: u32 {
        /// Never asked for.
        Unknown = 0,
        /// The notifier's own name for this dialog, which is what it will
        /// keep using for it.
        Id = 1,
        /// The dialog's `Call-ID`, when the notifier sent one.
        CallId = 2,
        /// Who the watched end is, as a URI.
        LocalIdentity = 3,
        /// And the display name beside it.
        LocalDisplay = 4,
        /// Who the other end is, as a URI. This is the one a lamp shows
        /// beside a ringing extension.
        RemoteIdentity = 5,
        /// And the display name beside it.
        RemoteDisplay = 6,
        /// Where requests for the watched end would be sent.
        LocalTarget = 7,
        /// And for the other end.
        RemoteTarget = 8,
    }
}

record! {
    /// One dialog a `dialog` subscription has been told about, with the text
    /// left behind: [`sipral_subscription_dialog_text`] reads that, because a
    /// pointer into this library's own memory would be a pointer a caller
    /// could outlive.
    #[derive(Clone, Copy)]
    pub struct SipralWatchedDialog {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralDialogPhase`].
        pub phase: u32,
        /// A [`SipralDialogDirection`].
        pub direction: u32,
        /// A [`SipralDialogEnded`], and zero while the dialog has not.
        pub ended: u32,
        /// The SIP status behind how it ended, when the notifier sent one.
        /// Zero otherwise.
        pub status_code: u32,
        /// How long it has been up, in milliseconds, when the notifier sent a
        /// duration. Zero otherwise.
        pub duration_ms: u64,
    }
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and the library is the only one that fills it in.
unsafe impl Versioned for SipralWatchedDialog {
    const NAME: &'static str = "sipral_watched_dialog";
    const MIN_SIZE: usize = crate::versioned::min_size::WATCHED_DIALOG;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// The C name for a phase.
const fn named_phase(phase: DialogPhase) -> SipralDialogPhase {
    match phase {
        DialogPhase::Trying => SipralDialogPhase::Trying,
        DialogPhase::Proceeding => SipralDialogPhase::Proceeding,
        DialogPhase::Early => SipralDialogPhase::Early,
        DialogPhase::Confirmed => SipralDialogPhase::Confirmed,
        DialogPhase::Terminated => SipralDialogPhase::Terminated,
        // `Unknown` is what the layer below calls a state the notifier named
        // that RFC 4235 does not, and `non_exhaustive` covers a state a later
        // build of it might add: neither is a phase this one can light a lamp
        // from
        _ => SipralDialogPhase::Unknown,
    }
}

/// The table one subscription has been told about, or the failure to say why
/// there is none.
fn table_of(state: &StackState, subscription: SipralHandle) -> Result<&DialogInfoTable, Fail> {
    let named = subscription_of(state, subscription)?;
    state.agent.dialog_info(named).ok_or_else(|| {
        fail(
            SipralStatus::NotSupported,
            "this subscription has no dialog state: either it is not a `dialog` subscription, or \
             it is not live and what it had been told is no longer evidence about anything",
        )
    })
}

/// One row of it.
fn row_of(
    state: &StackState,
    subscription: SipralHandle,
    index: usize,
) -> Result<&WatchedDialog, Fail> {
    let table = table_of(state, subscription)?;
    table.dialogs().get(index).ok_or_else(|| {
        fail(
            SipralStatus::InvalidArgument,
            format!(
                "there is no dialog {index}; this subscription has been told about {}",
                table.dialogs().len()
            ),
        )
    })
}

entry! {
    /// What a lamp for this subscription should show (A1).
    ///
    /// RFC 4235 §3.7.2's virtual state machine over every dialog the notifier
    /// has told this subscription about: anything ringing beats anything
    /// settled, and [`SipralDialogPhase::Idle`] is what is left once they
    /// have all ended. One call and one number, which is what a busy lamp
    /// field is; [`sipral_subscription_dialog_count`] and the two after it
    /// are for an application that wants to show who is on the call as well.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription that has no dialog
    /// state at all — one to another package, or one that is not live, whose
    /// last notification stopped being evidence the moment it stopped being
    /// refreshed.
    ///
    /// # Safety
    ///
    /// `out_phase` must point at one `uint32_t`.
    fn sipral_subscription_lamp(
        stack: SipralHandle,
        subscription: SipralHandle,
        out_phase: *mut u32,
    ) {
        if out_phase.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_phase is null"));
        }
        with_stack(stack, |state| {
            let table = table_of(state, subscription)?;
            let phase = table
                .phase()
                .map_or(SipralDialogPhase::Idle, named_phase);
            unsafe { out_phase.write(phase as u32) };
            Ok(())
        })
    }
}

entry! {
    /// How many dialogs this subscription has been told about.
    ///
    /// They are in the order they were first heard of, and the index one has
    /// here is stable only until the next notification arrives: a dialog that
    /// ended is dropped from the table, and the numbering closes up behind
    /// it. Read a dialog out in the same breath as the count, and read them
    /// both again on the next
    /// [`SIPRAL_EVENT_KIND_NOTIFIED`](crate::event::SipralEventKind::Notified).
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_subscription_dialog_count(
        stack: SipralHandle,
        subscription: SipralHandle,
        out_count: *mut usize,
    ) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        with_stack(stack, |state| {
            let table = table_of(state, subscription)?;
            unsafe { out_count.write(table.dialogs().len()) };
            Ok(())
        })
    }
}

entry! {
    /// One of them, by index.
    ///
    /// # Safety
    ///
    /// `out_dialog` must point at a `sipral_watched_dialog_t` whose `size`
    /// member says how long it is.
    fn sipral_subscription_dialog_at(
        stack: SipralHandle,
        subscription: SipralHandle,
        index: usize,
        out_dialog: *mut SipralWatchedDialog,
    ) {
        unsafe { declared_size(out_dialog.cast_const()) }?;
        with_stack(stack, |state| {
            let row = row_of(state, subscription, index)?;
            let out = SipralWatchedDialog {
                size: size_of::<SipralWatchedDialog>(),
                phase: named_phase(row.phase) as u32,
                direction: match row.direction {
                    Some(Initiated::Locally) => SipralDialogDirection::Locally,
                    Some(Initiated::Remotely) => SipralDialogDirection::Remotely,
                    _ => SipralDialogDirection::Unknown,
                } as u32,
                ended: match row.ended {
                    Some(DialogEnded::Cancelled) => SipralDialogEnded::Cancelled,
                    Some(DialogEnded::Rejected) => SipralDialogEnded::Rejected,
                    Some(DialogEnded::Replaced) => SipralDialogEnded::Replaced,
                    Some(DialogEnded::LocalBye) => SipralDialogEnded::LocalBye,
                    Some(DialogEnded::RemoteBye) => SipralDialogEnded::RemoteBye,
                    Some(DialogEnded::Error) => SipralDialogEnded::Error,
                    Some(DialogEnded::Timeout) => SipralDialogEnded::Timeout,
                    _ => SipralDialogEnded::Unknown,
                } as u32,
                status_code: u32::from(row.code.unwrap_or(0)),
                duration_ms: row
                    .duration
                    .map_or(0, |held| u64::try_from(held.as_millis()).unwrap_or(u64::MAX)),
            };
            unsafe { write_versioned(out_dialog, out) }
        })
    }
}

entry! {
    /// A piece of text about one of them, copied into the caller's buffer.
    ///
    /// The same shape `sipral_last_error_message` has, and for the same
    /// reason: the text belongs to the library and a pointer to it would be
    /// one a caller could outlive. `out_needed` always receives the number of
    /// bytes the text needs including the trailing NUL, so a caller that
    /// brought nothing can ask with `capacity` zero and then ask again with
    /// room. A buffer too small for the whole of it is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written to it.
    ///
    /// A piece the notifier did not send is one byte: the NUL.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes, and `out_needed` must
    /// point at one `size_t`.
    fn sipral_subscription_dialog_text(
        stack: SipralHandle,
        subscription: SipralHandle,
        index: usize,
        which: u32,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        if out_needed.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_needed is null"));
        }
        let wanted = match which {
            1 => SipralDialogText::Id,
            2 => SipralDialogText::CallId,
            3 => SipralDialogText::LocalIdentity,
            4 => SipralDialogText::LocalDisplay,
            5 => SipralDialogText::RemoteIdentity,
            6 => SipralDialogText::RemoteDisplay,
            7 => SipralDialogText::LocalTarget,
            8 => SipralDialogText::RemoteTarget,
            other => {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("{other} is not a piece of text a watched dialog has"),
                ));
            }
        };
        with_stack(stack, |state| {
            let row = row_of(state, subscription, index)?;
            let text = match wanted {
                SipralDialogText::Id => Some(&*row.id),
                SipralDialogText::CallId => row.call_id.as_deref(),
                SipralDialogText::LocalIdentity => row.local.identity.as_deref(),
                SipralDialogText::LocalDisplay => row.local.display.as_deref(),
                SipralDialogText::RemoteIdentity => row.remote.identity.as_deref(),
                SipralDialogText::RemoteDisplay => row.remote.display.as_deref(),
                SipralDialogText::LocalTarget => row.local.target.as_deref(),
                SipralDialogText::RemoteTarget => row.remote.target.as_deref(),
                SipralDialogText::Unknown => None,
            }
            .unwrap_or("");
            unsafe { copy_out(text, buffer, capacity, out_needed) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralDialogEnded, SipralDialogPhase, SipralDialogText, SipralSubscribeConfig,
        SipralSubscriptionEnd, SipralSubscriptionState, SipralWatchedDialog,
        sipral_account_subscribe, sipral_subscription_dialog_at, sipral_subscription_dialog_count,
        sipral_subscription_dialog_text, sipral_subscription_end, sipral_subscription_lamp,
        sipral_subscription_state,
    };
    use crate::call::tests::{account_on, deliver, one, sent};
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::{Observed, Watched, poll, stack};
    use crate::status::SipralStatus;
    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};
    use std::ffi::c_char;
    use std::ptr;

    /// A pointer and a length, as a caller hands text over.
    fn as_text(text: &str) -> (*const c_char, usize) {
        (text.as_ptr().cast::<c_char>(), text.len())
    }

    /// One header field of a message, for building the answer to it.
    fn field(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message");
        message.header(name).unwrap_or_default().to_vec()
    }

    /// The config a test subscribes with: the busy lamp field on one
    /// extension, which is what A1 is for.
    fn watch(target: &str) -> SipralSubscribeConfig {
        let mut config = SipralSubscribeConfig {
            size: size_of::<SipralSubscribeConfig>(),
            target: ptr::null(),
            target_len: 0,
            package: ptr::null(),
            package_len: 0,
            accept: ptr::null(),
            accept_len: 0,
            expires_seconds: 0,
            destination: ptr::null(),
            destination_len: 0,
            transport: 0,
        };
        (config.target, config.target_len) = as_text(target);
        (config.package, config.package_len) = as_text("dialog");
        config
    }

    /// Subscribe, and hand back the stack, the account and the subscription.
    fn watching(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        let account = account_on(handle);
        let config = watch("sip:2001@example.com");
        let mut subscription = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_account_subscribe(
                handle,
                account,
                ptr::from_ref(&config),
                &raw mut subscription,
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(subscription, SIPRAL_HANDLE_NONE);
        (handle, subscription)
    }

    /// The notifier's 200, granting what it chose rather than what was asked.
    fn granted(subscribe: &[u8], seconds: u32) -> Vec<u8> {
        let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
        for (name, value) in [
            ("Via", field(subscribe, HeaderName::Via)),
            ("From", field(subscribe, HeaderName::From)),
            ("To", {
                let mut to = field(subscribe, HeaderName::To);
                to.extend_from_slice(b";tag=notifier");
                to
            }),
            ("Call-ID", field(subscribe, HeaderName::CallId)),
            ("CSeq", field(subscribe, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("Expires: {seconds}\r\n").as_bytes());
        out.extend_from_slice(b"Contact: <sip:pbx@203.0.113.9:5060>\r\n");
        out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        out
    }

    /// A notification in the dialog the SUBSCRIBE opened.
    fn notification(subscribe: &[u8], state: &str, body: &[u8], with_body_type: bool) -> Vec<u8> {
        let mut out = b"NOTIFY sip:alice@192.0.2.10:5060 SIP/2.0\r\n".to_vec();
        out.extend_from_slice(b"Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK-notify-one\r\n");
        out.extend_from_slice(b"Max-Forwards: 70\r\n");
        for (name, value) in [
            ("From", {
                let mut to = field(subscribe, HeaderName::To);
                to.extend_from_slice(b";tag=notifier");
                to
            }),
            ("To", field(subscribe, HeaderName::From)),
            ("Call-ID", field(subscribe, HeaderName::CallId)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"CSeq: 1 NOTIFY\r\n");
        out.extend_from_slice(b"Contact: <sip:pbx@203.0.113.9:5060>\r\n");
        out.extend_from_slice(b"Event: dialog\r\n");
        out.extend_from_slice(format!("Subscription-State: {state}\r\n").as_bytes());
        if with_body_type {
            out.extend_from_slice(b"Content-Type: application/dialog-info+xml\r\n");
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out
    }

    /// The notifier's last word, in a second transaction of its own so that
    /// it does not read as a retransmission of the first notification.
    fn closing(subscribe: &[u8], state: &str) -> Vec<u8> {
        let mut out = notification(subscribe, state, b"", false);
        out = String::from_utf8_lossy(&out)
            .replace("z9hG4bK-notify-one", "z9hG4bK-notify-two")
            .replace("CSeq: 1 NOTIFY", "CSeq: 2 NOTIFY")
            .into_bytes();
        out
    }

    /// One extension, ringing.
    const RINGING: &[u8] = br#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info" version="1" state="full" entity="sip:2001@example.com">
  <dialog id="d1"><state>early</state></dialog>
</dialog-info>"#;

    /// And the same dialog, over.
    const ENDED: &[u8] = br#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info" version="2" state="full" entity="sip:2001@example.com">
  <dialog id="d1"><state>terminated</state></dialog>
</dialog-info>"#;

    fn what_was_watched(observed: &Observed) -> Vec<Watched> {
        observed.subscriptions.clone()
    }

    #[test]
    fn a_subscribe_goes_out_naming_the_package_and_the_target() {
        let mut observed = Observed::default();
        let (handle, _) = watching(&mut observed);

        let subscribe = one(handle);
        let text = String::from_utf8_lossy(&subscribe).into_owned();
        assert!(
            text.starts_with("SUBSCRIBE sip:2001@example.com SIP/2.0\r\n"),
            "{text}"
        );
        assert_eq!(field(&subscribe, HeaderName::Event), b"dialog");
        // asked for, not granted: the notifier's answer is what wins
        assert_eq!(field(&subscribe, HeaderName::Expires), b"3600");

        poll(handle, 1_000);
        let seen = what_was_watched(&observed);
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].kind, SipralEventKind::SubscriptionChanged);
        assert_eq!(seen[0].state, SipralSubscriptionState::Requesting as u32);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// RFC 6665 §4.1.2.2: the 200 to a SUBSCRIBE does not establish the
    /// subscription -- "the subscription is not established until the first
    /// NOTIFY" -- so nothing moves on it, and what the notifier granted is
    /// reported when the subscription actually starts.
    #[test]
    fn what_the_notifier_granted_is_what_the_event_reports() {
        let mut observed = Observed::default();
        let (handle, subscription) = watching(&mut observed);
        let subscribe = one(handle);

        deliver(handle, &granted(&subscribe, 600), 1_000);
        poll(handle, 1_000);

        let seen = what_was_watched(&observed);
        let last = seen.last().copied().expect("an event");
        assert_eq!(
            last.state,
            SipralSubscriptionState::Requesting as u32,
            "a 200 with no notification behind it moved the subscription: {seen:?}"
        );

        deliver(
            handle,
            &notification(&subscribe, "active;expires=600", RINGING, true),
            2_000,
        );
        poll(handle, 2_000);

        let seen = what_was_watched(&observed);
        let granted_event = seen
            .iter()
            .rev()
            .find(|one| {
                one.kind == SipralEventKind::SubscriptionChanged
                    && one.state == SipralSubscriptionState::Active as u32
            })
            .copied()
            .unwrap_or_else(|| panic!("nothing became active in {seen:?}"));
        assert_eq!(granted_event.subscription, subscription);
        assert_eq!(
            granted_event.expires_ms, 600_000,
            "the notifier granted ten minutes and the event says otherwise: {seen:?}"
        );
        assert!(
            granted_event.refresh_in_ms > 0 && granted_event.refresh_in_ms < 600_000,
            "the refresh is not scheduled inside what was granted: {granted_event:?}"
        );

        let mut state = 0_u32;
        assert_eq!(
            unsafe { sipral_subscription_state(handle, subscription, &raw mut state) },
            SipralStatus::Ok
        );
        assert_eq!(state, SipralSubscriptionState::Active as u32);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_notification_arrives_as_its_own_event_with_the_request_whole() {
        let mut observed = Observed::default();
        let (handle, subscription) = watching(&mut observed);
        let subscribe = one(handle);
        deliver(handle, &granted(&subscribe, 600), 1_000);
        poll(handle, 1_000);
        let _ = sent(handle);

        deliver(
            handle,
            &notification(&subscribe, "active;expires=600", RINGING, true),
            2_000,
        );
        poll(handle, 2_000);

        let seen = what_was_watched(&observed);
        let notified = seen
            .iter()
            .find(|one| one.kind == SipralEventKind::Notified)
            .copied()
            .unwrap_or_else(|| panic!("no notification in {seen:?}"));
        assert_eq!(notified.subscription, subscription);
        assert_eq!(
            notified.has_dialog_info, 1,
            "the body was dialog state and the event says it was not"
        );
        assert!(
            notified.message_len > 0,
            "the NOTIFY itself did not come with the event"
        );
        // and the subscription is live now that a notification has arrived
        let mut state = 0_u32;
        assert_eq!(
            unsafe { sipral_subscription_state(handle, subscription, &raw mut state) },
            SipralStatus::Ok
        );
        assert_eq!(state, SipralSubscriptionState::Active as u32);
        // the NOTIFY is answered, which is what keeps the notifier sending
        let answer = one(handle);
        assert!(
            answer.starts_with(b"SIP/2.0 200"),
            "{}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_body_that_could_not_be_read_still_arrives_and_says_it_carried_nothing() {
        let mut observed = Observed::default();
        let (handle, _) = watching(&mut observed);
        let subscribe = one(handle);
        deliver(handle, &granted(&subscribe, 600), 1_000);
        poll(handle, 1_000);
        let _ = sent(handle);

        deliver(
            handle,
            &notification(&subscribe, "active;expires=600", b"<not-a-document", true),
            2_000,
        );
        poll(handle, 2_000);

        let seen = what_was_watched(&observed);
        let notified = seen
            .iter()
            .find(|one| one.kind == SipralEventKind::Notified)
            .copied()
            .unwrap_or_else(|| panic!("no notification in {seen:?}"));
        assert_eq!(
            notified.has_dialog_info, 0,
            "a body that could not be read was reported as dialog state"
        );
        assert!(notified.message_len > 0, "the request did not come with it");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn giving_a_subscription_up_sends_expires_zero_and_ends_it() {
        let mut observed = Observed::default();
        let (handle, subscription) = watching(&mut observed);
        let subscribe = one(handle);
        deliver(handle, &granted(&subscribe, 600), 1_000);
        poll(handle, 1_000);
        // a subscription with no dialog has nothing to send a closing
        // SUBSCRIBE in, so this one is established first
        deliver(
            handle,
            &notification(&subscribe, "active;expires=600", RINGING, true),
            2_000,
        );
        poll(handle, 2_000);
        let _ = sent(handle);

        assert_eq!(
            unsafe { sipral_subscription_end(handle, subscription, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let given_up = one(handle);
        assert!(
            given_up.starts_with(b"SUBSCRIBE "),
            "{}",
            String::from_utf8_lossy(&given_up)
        );
        assert_eq!(field(&given_up, HeaderName::Expires), b"0");

        // §4.4.1: over when the closing NOTIFY says so, not when the request
        // was sent
        deliver(
            handle,
            &closing(&subscribe, "terminated;reason=noresource"),
            3_000,
        );
        poll(handle, 3_000);

        let seen = what_was_watched(&observed);
        let ended = seen
            .iter()
            .rev()
            .find(|one| one.state == SipralSubscriptionState::Ended as u32)
            .copied()
            .unwrap_or_else(|| panic!("nothing ended in {seen:?}"));
        assert_eq!(ended.subscription, subscription);
        // what this end did, not what the notifier's closing parameter said:
        // the application asked for this one to stop, and that is the answer
        // to "why is it not live"
        assert_eq!(ended.reason, SipralSubscriptionEnd::Unsubscribed as u32);
        assert_eq!(ended.retry_in_ms, 0, "ended for good, and a retry is named");

        let mut state = 0_u32;
        assert_eq!(
            unsafe { sipral_subscription_state(handle, subscription, &raw mut state) },
            SipralStatus::Ok
        );
        assert_eq!(
            state,
            SipralSubscriptionState::Unknown as u32,
            "the handle still names a live subscription after it ended"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// The other way one ends: the notifier stops it, and says why in the
    /// `Subscription-State` it stopped it with. That reason is the one thing
    /// telling a lamp apart from an extension that was deleted.
    #[test]
    fn a_notifier_that_ends_it_says_why_and_the_reason_crosses() {
        let mut observed = Observed::default();
        let (handle, subscription) = watching(&mut observed);
        let subscribe = one(handle);
        deliver(handle, &granted(&subscribe, 600), 1_000);
        poll(handle, 1_000);
        deliver(
            handle,
            &notification(&subscribe, "active;expires=600", RINGING, true),
            2_000,
        );
        poll(handle, 2_000);
        let _ = sent(handle);

        deliver(
            handle,
            &closing(&subscribe, "terminated;reason=noresource"),
            3_000,
        );
        poll(handle, 3_000);

        let seen = what_was_watched(&observed);
        let ended = seen
            .iter()
            .rev()
            .find(|one| one.state == SipralSubscriptionState::Ended as u32)
            .copied()
            .unwrap_or_else(|| panic!("nothing ended in {seen:?}"));
        assert_eq!(ended.subscription, subscription);
        assert_eq!(ended.reason, SipralSubscriptionEnd::NoResource as u32);
        assert_eq!(
            ended.retry_in_ms, 0,
            "nothing is coming back for a resource that is gone"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// What the whole feature is for: a lamp that goes on when the watched
    /// extension rings, and off when the call is over.
    #[test]
    fn the_lamp_follows_the_dialog_the_notifier_describes() {
        let mut observed = Observed::default();
        let (handle, subscription) = watching(&mut observed);
        let subscribe = one(handle);
        deliver(handle, &granted(&subscribe, 600), 1_000);
        poll(handle, 1_000);

        // nothing has been said about it yet
        deliver(
            handle,
            &notification(&subscribe, "active;expires=600", RINGING, true),
            2_000,
        );
        poll(handle, 2_000);

        let mut phase = 0_u32;
        assert_eq!(
            unsafe { sipral_subscription_lamp(handle, subscription, &raw mut phase) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            phase,
            SipralDialogPhase::Early as u32,
            "the extension is ringing and the lamp says otherwise"
        );

        let mut count = 0_usize;
        assert_eq!(
            unsafe { sipral_subscription_dialog_count(handle, subscription, &raw mut count) },
            SipralStatus::Ok
        );
        assert_eq!(
            count, 1,
            "one dialog was described and the table holds {count}"
        );

        let mut dialog = SipralWatchedDialog {
            size: size_of::<SipralWatchedDialog>(),
            phase: 0,
            direction: 0,
            ended: 0,
            status_code: 0,
            duration_ms: 0,
        };
        assert_eq!(
            unsafe { sipral_subscription_dialog_at(handle, subscription, 0, &raw mut dialog) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(dialog.phase, SipralDialogPhase::Early as u32);
        assert_eq!(dialog.ended, SipralDialogEnded::Unknown as u32);

        // and it goes out again when the call is over
        let mut done = notification(&subscribe, "active;expires=600", ENDED, true);
        done = String::from_utf8_lossy(&done)
            .replace("z9hG4bK-notify-one", "z9hG4bK-notify-three")
            .replace("CSeq: 1 NOTIFY", "CSeq: 3 NOTIFY")
            .into_bytes();
        deliver(handle, &done, 3_000);
        poll(handle, 3_000);

        assert_eq!(
            unsafe { sipral_subscription_lamp(handle, subscription, &raw mut phase) },
            SipralStatus::Ok
        );
        assert_eq!(
            phase,
            SipralDialogPhase::Idle as u32,
            "the call ended and the lamp is still on"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// The text about one of them, which is what a lamp shows beside itself:
    /// copied into the caller's buffer, because a pointer into the library's
    /// own memory would be one a caller could outlive.
    #[test]
    fn the_text_about_a_watched_dialog_is_copied_out_and_says_how_much_room_it_needs() {
        let mut observed = Observed::default();
        let (handle, subscription) = watching(&mut observed);
        let subscribe = one(handle);
        deliver(handle, &granted(&subscribe, 600), 1_000);
        poll(handle, 1_000);
        deliver(
            handle,
            &notification(&subscribe, "active;expires=600", RINGING, true),
            2_000,
        );
        poll(handle, 2_000);

        let mut needed = 0_usize;
        assert_eq!(
            unsafe {
                sipral_subscription_dialog_text(
                    handle,
                    subscription,
                    0,
                    SipralDialogText::Id as u32,
                    ptr::null_mut(),
                    0,
                    &raw mut needed,
                )
            },
            SipralStatus::BufferTooSmall,
            "asking with no room did not say how much was needed"
        );
        assert_eq!(needed, 3, "`d1` and a NUL");
        let mut room = [0_i8; 8];
        assert_eq!(
            unsafe {
                sipral_subscription_dialog_text(
                    handle,
                    subscription,
                    0,
                    SipralDialogText::Id as u32,
                    room.as_mut_ptr(),
                    room.len(),
                    &raw mut needed,
                )
            },
            SipralStatus::Ok
        );
        assert_eq!(&room[..3], &[b'd'.cast_signed(), b'1'.cast_signed(), 0]);

        // a piece the notifier did not send is one byte, the NUL, rather
        // than a failure: nothing is wrong with a dialog that carries no
        // display name
        assert_eq!(
            unsafe {
                sipral_subscription_dialog_text(
                    handle,
                    subscription,
                    0,
                    SipralDialogText::RemoteDisplay as u32,
                    room.as_mut_ptr(),
                    room.len(),
                    &raw mut needed,
                )
            },
            SipralStatus::Ok
        );
        assert_eq!(needed, 1);
        assert_eq!(room[0], 0);

        // and a piece of text nothing names is refused rather than read as
        // one of the ones that do
        assert_eq!(
            unsafe {
                sipral_subscription_dialog_text(
                    handle,
                    subscription,
                    0,
                    99,
                    room.as_mut_ptr(),
                    room.len(),
                    &raw mut needed,
                )
            },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// Asking a subscription that has no dialog state says so rather than
    /// answering an empty table, which reads as "nothing is going on".
    #[test]
    fn a_subscription_with_no_dialog_state_says_so() {
        let mut observed = Observed::default();
        let (handle, subscription) = watching(&mut observed);
        let mut phase = 0_u32;
        assert_eq!(
            unsafe { sipral_subscription_lamp(handle, subscription, &raw mut phase) },
            SipralStatus::NotSupported
        );
        let mut count = 0_usize;
        assert_eq!(
            unsafe { sipral_subscription_dialog_count(handle, subscription, &raw mut count) },
            SipralStatus::NotSupported
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// A dialog-info document about `entity`, in `state`, at `version`.
    fn about(entity: &str, version: u32, state: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?>\n<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" \
             version=\"{version}\" state=\"full\" entity=\"{entity}\">\n  \
             <dialog id=\"d-{version}\"><state>{state}</state></dialog>\n</dialog-info>"
        )
        .into_bytes()
    }

    /// `notification` in a transaction of its own: the `n`th in the
    /// subscription `who` names.
    fn numbered(subscribe: &[u8], who: &str, n: u32, body: &[u8]) -> Vec<u8> {
        String::from_utf8_lossy(&notification(subscribe, "active;expires=600", body, true))
            .replace("z9hG4bK-notify-one", &format!("z9hG4bK-notify-{who}-{n}"))
            .replace("CSeq: 1 NOTIFY", &format!("CSeq: {n} NOTIFY"))
            .into_bytes()
    }

    fn lamp(handle: SipralHandle, subscription: SipralHandle) -> u32 {
        let mut phase = u32::MAX;
        assert_eq!(
            unsafe { sipral_subscription_lamp(handle, subscription, &raw mut phase) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        phase
    }

    /// Extension 10 and extension 100 on one account, the pair a PBX with
    /// two- and three-digit numbers always has: a lamp is the subscription's
    /// own, found by its dialog, and one number being the start of the
    /// other mixes nothing up — not the lamps, not the notifications, not
    /// the refreshes.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn extensions_ten_and_a_hundred_keep_their_lamps_apart() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        let subscribe = |target: &str| {
            let config = watch(target);
            let mut subscription = SIPRAL_HANDLE_NONE;
            let status = unsafe {
                sipral_account_subscribe(
                    handle,
                    account,
                    ptr::from_ref(&config),
                    &raw mut subscription,
                    1_000,
                )
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            (subscription, one(handle))
        };
        let (ten, to_ten) = subscribe("sip:10@example.com");
        let (hundred, to_hundred) = subscribe("sip:100@example.com");
        assert_ne!(ten, hundred);
        assert!(to_ten.starts_with(b"SUBSCRIBE sip:10@example.com SIP/2.0\r\n"));
        assert!(to_hundred.starts_with(b"SUBSCRIBE sip:100@example.com SIP/2.0\r\n"));
        for request in [&to_ten, &to_hundred] {
            deliver(handle, &granted(request, 600), 1_000);
        }
        poll(handle, 1_000);

        // a hundred rings; ten is on a call
        deliver(
            handle,
            &numbered(
                &to_hundred,
                "hundred",
                1,
                &about("sip:100@example.com", 1, "early"),
            ),
            2_000,
        );
        deliver(
            handle,
            &numbered(
                &to_ten,
                "ten",
                1,
                &about("sip:10@example.com", 1, "confirmed"),
            ),
            2_000,
        );
        poll(handle, 2_000);
        assert_eq!(lamp(handle, hundred), SipralDialogPhase::Early as u32);
        assert_eq!(lamp(handle, ten), SipralDialogPhase::Confirmed as u32);
        let notified: Vec<SipralHandle> = what_was_watched(&observed)
            .iter()
            .filter(|one| one.kind == SipralEventKind::Notified)
            .map(|one| one.subscription)
            .collect();
        assert_eq!(notified, vec![hundred, ten], "each notification is its own");

        // a hundred's call is over, and ten's lamp does not go out with it
        deliver(
            handle,
            &numbered(
                &to_hundred,
                "hundred",
                2,
                &about("sip:100@example.com", 2, "terminated"),
            ),
            3_000,
        );
        poll(handle, 3_000);
        assert_eq!(lamp(handle, hundred), SipralDialogPhase::Idle as u32);
        assert_eq!(lamp(handle, ten), SipralDialogPhase::Confirmed as u32);

        // and each refresh stays in its own dialog, naming its own number
        poll(handle, 600_000);
        let mut refreshed: Vec<(Vec<u8>, Vec<u8>)> = sent(handle)
            .iter()
            .filter(|message| message.starts_with(b"SUBSCRIBE "))
            .map(|message| {
                (
                    field(message, HeaderName::CallId),
                    field(message, HeaderName::To),
                )
            })
            .collect();
        refreshed.sort();
        let mut expected: Vec<(Vec<u8>, &[u8])> = vec![
            (field(&to_ten, HeaderName::CallId), b"sip:10@example.com"),
            (
                field(&to_hundred, HeaderName::CallId),
                b"sip:100@example.com",
            ),
        ];
        expected.sort();
        assert_eq!(refreshed.len(), 2, "{refreshed:?}");
        for ((call_id, to), (wanted_id, number)) in refreshed.iter().zip(&expected) {
            assert_eq!(call_id, wanted_id);
            let to = String::from_utf8_lossy(to);
            let number = String::from_utf8_lossy(number);
            assert!(
                to.contains(&format!("<{number}>")),
                "{to} is not {number}'s"
            );
        }
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_target_that_is_not_a_uri_is_refused_before_anything_is_sent() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        for (target, package, why) in [
            ("not a uri", "dialog", "a target that is not a URI"),
            (
                "sip:2001@example.com",
                "two words",
                "a package that is not a token",
            ),
        ] {
            let mut config = watch(target);
            (config.package, config.package_len) = as_text(package);
            let mut subscription = SIPRAL_HANDLE_NONE;
            assert_eq!(
                unsafe {
                    sipral_account_subscribe(
                        handle,
                        account,
                        ptr::from_ref(&config),
                        &raw mut subscription,
                        1_000,
                    )
                },
                SipralStatus::InvalidArgument,
                "{why} was accepted"
            );
            assert_eq!(subscription, SIPRAL_HANDLE_NONE, "{why}");
        }
        assert!(sent(handle).is_empty(), "something went out anyway");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_stale_subscription_handle_is_refused_rather_than_read() {
        let mut observed = Observed::default();
        let (handle, subscription) = watching(&mut observed);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
        let mut state = 0_u32;
        assert_eq!(
            unsafe { sipral_subscription_state(handle, subscription, &raw mut state) },
            SipralStatus::StaleHandle
        );
        assert_eq!(
            unsafe { sipral_subscription_end(handle, subscription, 2_000) },
            SipralStatus::StaleHandle
        );
    }
}
