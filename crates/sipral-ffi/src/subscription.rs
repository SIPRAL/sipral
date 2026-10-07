// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Watching something at the far end: SUBSCRIBE, NOTIFY, and the busy lamp
//! field on top of them.
//!
//! `sipral-ua` does the protocol work: the dialog, timer N, the refresh, forks
//! (RFC 6665 §4.1.4), and the retry with a fresh `Call-ID`. This module exposes
//! it to C, behind [`SIPRAL_FEATURE_SUBSCRIPTIONS`].
//!
//! [`SIPRAL_FEATURE_SUBSCRIPTIONS`]: crate::capabilities::SIPRAL_FEATURE_SUBSCRIPTIONS
//!
//! A subscription is a handle of its own, minted by
//! [`sipral_account_subscribe`] and dead once
//! `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` says it ended for good. A fork
//! sibling appears in an event, like an incoming call (RFC 4235 §3.9: one per
//! registered device).
//!
//! A NOTIFY raises `SIPRAL_EVENT_KIND_NOTIFIED`, with the request whole in
//! `sipral_event_t::message`; for `dialog` the parsed table is behind
//! [`sipral_subscription_dialog_count`] and [`sipral_subscription_dialog_at`].
//! State changes are a separate event, not raised on refresh.
//!
//! Not exposed: application header fields on a SUBSCRIBE (which of the
//! stack's fields may be overwritten is `sipral-ua`'s policy, not yet set),
//! and batch subscribe (a loop before the next poll sends the same burst, and
//! an array would cost the config its `size` member).

use std::ffi::c_char;
use std::net::SocketAddr;
use std::time::Duration;

use sipral_core::msg::Uri;
use sipral_ua::{
    DialogEnded, DialogInfoTable, DialogPhase, Initiated, Subscribe, SubscriptionEnd,
    SubscriptionHandle, SubscriptionState, WatchedDialog,
};

use crate::abi::{Number, codes, record};
use crate::call::ua_failed;
use crate::diagnostics::copy_out;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{required_text, text};
use crate::versioned::{Versioned, declared_size, read_versioned, write_versioned};

codes! {
    /// Where a subscription is: `sipral_subscription_event_t::state` and
    /// [`sipral_subscription_state`]'s `out_state`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralSubscriptionState: u32 {
        /// The handle names nothing: never minted here, or ended and let go.
        Unknown = 0,
        /// A SUBSCRIBE is on its way and nothing has answered it yet.
        Requesting = 1,
        /// The notifier has not decided (RFC 6665 §4.1.3 `pending`); nothing
        /// is known until [`SipralSubscriptionState::Active`].
        Pending = 2,
        /// Granted, and notifications are arriving.
        Active = 3,
        /// Not live, and a fresh attempt is scheduled (§4.1.2.2: new
        /// `Call-ID` and `From` tag). The handle stays valid across both.
        Retrying = 4,
        /// Over, nothing more coming. The handle names nothing from here on.
        Ended = 5,
    }
}

codes! {
    /// Why a subscription is not live: `sipral_subscription_event_t::reason`.
    ///
    /// Zero unless [`SipralSubscriptionState::Retrying`] or
    /// [`SipralSubscriptionState::Ended`]. The first eight are the `reason` of
    /// `Subscription-State: terminated` (RFC 6665 §4.1.3); the rest happened
    /// here.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralSubscriptionEnd: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// `deactivated`: the notifier wants it started again at once.
        Deactivated = 1,
        /// `probation`: started again, but not immediately.
        Probation = 2,
        /// `rejected`: the notifier will not serve it; do not ask again.
        Rejected = 3,
        /// `timeout`: it ran out rather than being refreshed.
        Timeout = 4,
        /// `giveup`: the notifier could not decide and stopped trying.
        GaveUp = 5,
        /// `noresource`: what was being watched does not exist any more.
        NoResource = 6,
        /// `invariant`: the watched thing cannot change.
        Invariant = 7,
        /// `terminated` with no reason parameter at all.
        Unstated = 8,
        /// This end gave it up with [`sipral_subscription_end`]. Wins over
        /// the notifier's closing reason.
        Unsubscribed = 9,
        /// The notifier answered 489: it does not know this event package.
        BadEvent = 10,
        /// Refused with a status a retry cannot fix.
        Refused = 11,
        /// Redirected; this stack does not follow redirects for SUBSCRIBE.
        Redirected = 12,
        /// Nothing answered: the notifier could not be reached at all.
        Unreachable = 13,
        /// Answered, but the first NOTIFY never came (§4.1.2.4's timer N,
        /// 64·T1).
        NoNotify = 14,
        /// What the notifier granted ran out with no refresh answered.
        Expired = 15,
    }
}

record! {
    /// What to watch, and how. Handed to [`sipral_account_subscribe`]. Set
    /// `size` to `sizeof(sipral_subscribe_config_t)`; all but `target` and
    /// `package` may be zero.
    #[derive(Clone, Copy)]
    pub struct SipralSubscribeConfig {
        /// How long this struct is, as the caller's header declares it.
        pub size: usize,
        /// What to watch, as a SIP URI: `sip:2001@pbx.example.com`.
        pub target: *const c_char,
        /// How many bytes of it.
        pub target_len: usize,
        /// The event package token: `dialog` for a busy lamp field (RFC 4235
        /// §3.1), `message-summary` (RFC 3842 §3), `presence` (RFC 3856 §6.1).
        /// Sent exactly as written, since §8.2.1 compares it byte for byte.
        pub package: *const c_char,
        /// How many bytes of it.
        pub package_len: usize,
        /// The `Accept` value, when the package's default body type is not
        /// wanted. Null sends none, which means the default (§3.1.3); a wrong
        /// one gets 406 (§4.1.2.1), so nothing is guessed.
        pub accept: *const c_char,
        /// How many bytes of it.
        pub accept_len: usize,
        /// Seconds to ask for, or zero for one hour. The notifier's grant wins
        /// (§3.1.1), and the refresh follows the grant.
        pub expires_seconds: u32,
        /// Where to send the SUBSCRIBE, as `host:port`, or null for where the
        /// account registers (the outbound proxy, which keeps NAT working).
        pub destination: *const c_char,
        /// How many bytes of it.
        pub destination_len: usize,
        /// The transport, read only with `destination`, as
        /// `sipral_call_config_t::transport` is. Nonzero without `destination`
        /// is `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub transport: u32,
        /// Zero. Pads the struct to a multiple of its alignment, so a member
        /// appended later never lands in padding. Never read.
        pub reserved: u32,
    }
}

// Safety: plain data, and all-zero is valid: null pointers with zero lengths,
// and zero `expires_seconds` is the default.
unsafe impl Versioned for SipralSubscribeConfig {
    const NAME: &'static str = "sipral_subscribe_config";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralSubscribeConfig, reserved);

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
        // `non_exhaustive` below: an unnumbered state reads as unknown, never
        // as a wrong one
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

/// Turn a C config into a [`Subscribe`], or say what was wrong.
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
    /// Watch something at the far end.
    ///
    /// One SUBSCRIBE is queued on `account`'s transport and address, and the
    /// handle names the subscription until it ends.
    /// `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step. It
    /// refreshes and retries recoverable failures under the same handle;
    /// [`sipral_subscription_end`] or an end with no retry finishes it.
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
    /// Give a subscription up with `Expires: 0` (§4.1.2.3).
    ///
    /// It stays live until the closing NOTIFY completes (§4.4.1);
    /// `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
    /// `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when. Without a dialog yet
    /// it ends at once. The handle is usable until that event.
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
    /// [`SipralSubscriptionState::Unknown`], with `SIPRAL_STATUS_OK`, for a
    /// handle that names nothing, as an ended one does.
    ///
    /// # Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    fn sipral_subscription_state(
        stack: SipralHandle,
        subscription: SipralHandle,
        out_state: *mut Number<SipralSubscriptionState>,
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
    /// What one watched dialog is doing, and what a lamp shows:
    /// `sipral_watched_dialog_t::phase` and [`sipral_subscription_lamp`]'s
    /// `out_phase`. RFC 4235 §3.7.1's states, ranked as §3.7.2 ranks them.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDialogPhase: u32 {
        /// No dialog, or all terminated: an idle lamp.
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
        /// which is [`SipralDialogPhase::Idle`] then.
        Terminated = 5,
        /// The notifier named a state this build has no number for.
        Unknown = 6,
    }
}

codes! {
    /// Which end started a watched dialog: `sipral_watched_dialog_t::direction`.
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
    /// How a watched dialog ended: `sipral_watched_dialog_t::ended`, zero
    /// while it has not.
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
    /// Which text [`sipral_subscription_dialog_text`] reads. Each is what the
    /// notifier wrote, unparsed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDialogText: u32 {
        /// Never asked for.
        Unknown = 0,
        /// The notifier's own id for this dialog.
        Id = 1,
        /// The dialog's `Call-ID`, when the notifier sent one.
        CallId = 2,
        /// Who the watched end is, as a URI.
        LocalIdentity = 3,
        /// And the display name beside it.
        LocalDisplay = 4,
        /// Who the other end is, as a URI: what a lamp shows when ringing.
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
    /// One dialog a `dialog` subscription was told about. Its text is read
    /// with [`sipral_subscription_dialog_text`], so no pointer can dangle.
    #[derive(Clone, Copy)]
    pub struct SipralWatchedDialog {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralDialogPhase`].
        pub phase: Number<SipralDialogPhase>,
        /// A [`SipralDialogDirection`].
        pub direction: Number<SipralDialogDirection>,
        /// A [`SipralDialogEnded`], and zero while the dialog has not.
        pub ended: Number<SipralDialogEnded>,
        /// The SIP status behind how it ended, or zero.
        pub status_code: u32,
        /// How long it has been up, in milliseconds, or zero.
        pub duration_ms: u64,
    }
}

// Safety: plain data, filled only by the library.
unsafe impl Versioned for SipralWatchedDialog {
    const NAME: &'static str = "sipral_watched_dialog";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralWatchedDialog, duration_ms);

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
        // the notifier's non-RFC 4235 states, and states added later
        _ => SipralDialogPhase::Unknown,
    }
}

/// The dialog table of one subscription, or why there is none.
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
    /// What a lamp for this subscription should show: RFC 4235 §3.7.2's
    /// virtual state machine over every known dialog, ringing beating
    /// settled, [`SipralDialogPhase::Idle`] once all ended. The dialog
    /// functions below give the detail.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription with no dialog state:
    /// another package, or not live (its last notification is stale).
    ///
    /// # Safety
    ///
    /// `out_phase` must point at one `uint32_t`.
    fn sipral_subscription_lamp(
        stack: SipralHandle,
        subscription: SipralHandle,
        out_phase: *mut Number<SipralDialogPhase>,
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
    /// How many dialogs this subscription has been told about, in order first
    /// heard. Indexes hold only until the next notification, which drops
    /// ended dialogs; read again on each
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
    /// `out_needed` always receives the size with the trailing NUL; ask with
    /// `capacity` zero, then with room. Too small a buffer is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`, nothing written. A piece the notifier
    /// did not send is just the NUL.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be
    /// null.
    fn sipral_subscription_dialog_text(
        stack: SipralHandle,
        subscription: SipralHandle,
        index: usize,
        which: Number<SipralDialogText>,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
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
pub(crate) mod tests {
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
    pub(crate) fn as_text(text: &str) -> (*const c_char, usize) {
        (text.as_ptr().cast::<c_char>(), text.len())
    }

    /// One header field of a message, for building the answer to it.
    pub(crate) fn field(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message");
        message.header(name).unwrap_or_default().to_vec()
    }

    /// A busy-lamp config for one extension.
    pub(crate) fn watch(target: &str) -> SipralSubscribeConfig {
        let mut config = SipralSubscribeConfig {
            reserved: 0,
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

    /// Subscribe; returns the stack and the subscription.
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
    pub(crate) fn granted(subscribe: &[u8], seconds: u32) -> Vec<u8> {
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

    /// The notifier's last word, in its own transaction so it is not a
    /// retransmission.
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
        // asked for, not granted
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

    /// RFC 6665 §4.1.2.2: the 200 does not establish the subscription; the
    /// first NOTIFY does, and reports the grant.
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
        let mut state = 0_u32;
        assert_eq!(
            unsafe { sipral_subscription_state(handle, subscription, &raw mut state) },
            SipralStatus::Ok
        );
        assert_eq!(state, SipralSubscriptionState::Active as u32);
        // answering the NOTIFY keeps the notifier sending
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
        // established first: without a dialog there is nothing to close in
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

        // §4.4.1: over when the closing NOTIFY says so
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
        // this end's reason wins over the notifier's
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

    /// The notifier ends it, and its reason crosses.
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

    /// The lamp goes on when the extension rings and off when the call ends.
    #[test]
    fn the_lamp_follows_the_dialog_the_notifier_describes() {
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

    /// A watched dialog's text is copied out and says how much room it needs.
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

        // a piece not sent is just the NUL, not a failure
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

        // an unknown piece is refused
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

    /// No dialog state is reported as such, not as an empty table.
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

    /// `notification` as the `n`th transaction of subscription `who`.
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

    /// Extensions 10 and 100 on one account: prefix numbers mix up no lamps,
    /// notifications or refreshes.
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

        // a hundred's call ends; ten's lamp stays
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

        // each refresh stays in its own dialog
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
