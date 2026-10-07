// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Transfer: REFER, the subscription it opens, and `Replaces` (RFC 3515,
//! RFC 3891).
//!
//! The transferor asks the far end (the transferee) to call a target; the
//! target knows nothing of it unless a `Replaces` names which of its calls
//! is being taken over.
//!
//! **REFER opens a subscription** (§2.4.4). The transferee reports with
//! NOTIFYs carrying a `message/sipfrag` status line: `100` while trying,
//! then the final answer, so a phone can show "transferring" and then hang
//! up or take the call back. The last NOTIFY is
//! `terminated;reason=noresource` (§2.4.7).
//!
//! **Blind and attended differ by one URI parameter.** Blind sends
//! `Refer-To: <sip:carol@example.com>`; attended sends the target's contact
//! with a `Replaces` naming the dialog the transferee already has with it,
//! so the target replaces that call instead of getting a second one.
//!
//! **Attended needs a consultation call first**, placed with
//! [`UserAgent::consult`] and shown as [`CallState::Consulting`], so the
//! application does not have to remember why that call exists.
//!
//! **What `Replaces` matches.** RFC 3891 §3, each branch its own status: no
//! match is 481, an ended dialog is 603, an early dialog this end did not
//! originate is 481; only a confirmed dialog or our own early one is
//! replaced.
//!
//! **Matching is not permission.** §3 and §8 require the replacer to be
//! authorised. The dialog identifiers travel in every packet, and `From` or
//! `Referred-By` are written by the sender. This stack issues no challenges,
//! so by default a `Replaces` is honoured only when its INVITE arrives from
//! the same place as the named call's signalling; anything else is 403 and
//! the call is untouched. That refuses a transferee that reaches this end
//! directly rather than through the proxy, so
//! [`Screen::on_replaces`](crate::Screen::on_replaces) can widen or tighten
//! the rule; its default is the one above.
//!
//! **A NOTIFY is not a transfer.** Only a REFER opens this package (§2.4.4),
//! so a NOTIFY is acted on only where a REFER of ours opened a subscription;
//! anything else gets 481. The INVITE placed for a REFER carries its
//! `Referred-By` because RFC 3892 §2.2 requires it, not because it proves
//! anything.
//!
//! **The subscription is a real one** (§2.4.4). It runs for [`SUBSCRIPTION`]
//! (the `expires` RFC 6665 §4.2.2 requires on `active`), may be refreshed or
//! ended early by a SUBSCRIBE, and lapses with `terminated;reason=timeout`
//! (RFC 6665 §4.2.1.4). Ending it does not withdraw the call it placed.
//! RFC 4488's `Refer-Sub: false` is granted: echoed, and no subscription.
//!
//! A REFER outside any dialog uses the same machinery; [`crate::referral`]
//! says why it is off by default.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Event, OutgoingInDialogRequest, OutgoingResponse};
use sipral_core::msg::{
    HeaderName, Method, OwnedMessage, Params, RawMessage, StatusCode, Uri, unfold,
};
use sipral_core::transaction::{
    AnyTransactionId, DialogId, InviteServer, NonInviteServer, TransactionId,
};

use crate::agent::UserAgent;
use crate::call::{CallHandle, CallState, Direction, OutgoingCall, OutgoingExtras};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::headers::{HeaderRefused, HeadersFor};
use crate::screening::{Replacing, Screening};

/// Fields the transfer INVITE takes only from the REFER: two `Replaces` get
/// a 400 (RFC 3891 §3), `Referred-By` has one referrer (RFC 3892 §3), and an
/// application `Replaces` on a blind transfer would take over a dialog the
/// REFER never named.
const FROM_THE_REFER: &[HeaderName<'static>] = &[HeaderName::Replaces, HeaderName::ReferredBy];

/// The event package a REFER subscribes to (§3.1).
pub(crate) const REFER: &[u8] = b"refer";
/// §2.4.7: the last NOTIFY.
const FINISHED: &[u8] = b"terminated;reason=noresource";
/// RFC 6665 §4.2.1.4: lapsed, or ended by the subscriber with `Expires: 0`.
const TIMED_OUT: &[u8] = b"terminated;reason=timeout";
/// §2.4.5: the body of a NOTIFY while pending.
pub(crate) const TRYING: &[u8] = b"SIP/2.0 100 Trying\r\n";

/// How long a taken REFER's subscription runs before it needs a refresh,
/// stated in the first NOTIFY's `expires`.
///
/// §3.4 wants it longer than the referenced request takes; the INVITE has no
/// `Expires`, and an hour is past any ringing. The subscription ends with the
/// call's answer anyway (§2.4.7), so this is only a ceiling.
pub(crate) const SUBSCRIPTION: Duration = Duration::from_hours(1);

/// RFC 4488 §4: asks for no subscription, and is echoed by the 2xx granting it.
pub(crate) const REFER_SUB: HeaderName<'static> = HeaderName::Extension("Refer-Sub");

/// What the subscription ends with when the referred call could not be sent
/// (§2.4.5's example).
const UNSENDABLE: StatusCode = StatusCode::SERVICE_UNAVAILABLE;
/// For a `Replaces` naming a live call it may not replace (RFC 3891 §3, RFC
/// 3261 §21.4.4).
pub(crate) const FORBIDDEN: StatusCode = match StatusCode::new(403) {
    Ok(status) => status,
    // unreachable, but `new` is fallible and this crate does not panic
    Err(_) => StatusCode::CALL_DOES_NOT_EXIST,
};

/// One this end received, and the notifier's half of the subscription it
/// opens once taken (§2.4.4).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Referred {
    /// The transaction to answer, until it is answered.
    pub(crate) transaction: Option<TransactionId<NonInviteServer>>,
    pub(crate) placed: Option<CallHandle>,
    /// The closing NOTIFY has gone, or there was never one to send.
    pub(crate) finished: bool,
    /// The REFER's `CSeq`, sent on every NOTIFY as `Event: refer;id=<n>`
    /// (§2.4.6). Required only from the second REFER on; always sending it
    /// is legal and simpler.
    pub(crate) id: Option<u32>,
    /// When the subscription lapses without a refresh (RFC 6665 §4.2.1.4).
    pub(crate) lapses: Option<Instant>,
    /// The last NOTIFY's status, repeated by an early close, since each body
    /// is a complete statement (§2.4.5).
    pub(crate) last: StatusCode,
}

impl Referred {
    /// A REFER that has just arrived, answered by nothing yet.
    pub(crate) const fn asked(
        transaction: TransactionId<NonInviteServer>,
        id: Option<u32>,
    ) -> Self {
        Self {
            transaction: Some(transaction),
            placed: None,
            finished: false,
            id,
            lapses: None,
            last: StatusCode::TRYING,
        }
    }
}

/// The implicit subscription a REFER of ours opened (RFC 3515 §2).
///
/// It exists from the moment the REFER is sent, since a NOTIFY may beat the
/// 202 (§2.4.4), until the last NOTIFY or a refusal of the REFER (§2.4.2).
/// [`Call::referring`](crate::call::Call) cannot serve: it is cleared when
/// the REFER is answered, before notifications arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReferSubscription {
    /// The REFER's `CSeq`, which §2.4.6 makes the event `id`: a NOTIFY with
    /// an `id` is ours only if it matches. `None` when the dialog could not
    /// tell; then an `id` refuses nothing.
    pub(crate) id: Option<u32>,
}

/// What a `Refer-To` asks for.
#[derive(Clone, Debug)]
pub(crate) struct ReferTo {
    /// Where to call.
    pub(crate) target: Uri,
    /// The `Replaces` it carried, as it should go on the new INVITE.
    pub(crate) replaces: Option<Box<[u8]>>,
    /// Copied onto the INVITE (RFC 3892 §2.2).
    pub(crate) referred_by: Option<Box<[u8]>>,
    /// `Refer-Sub: false` (RFC 4488 §4): granted, the 202 echoes it and no
    /// NOTIFY follows.
    pub(crate) quiet: bool,
}

// -- what the application asks for -------------------------------------------

impl UserAgent {
    /// Ask the far end to call somebody else, and hang up when it has
    /// (RFC 3515).
    ///
    /// The far end reports progress, which arrives as
    /// [`UaEvent::TransferProgress`] and then [`UaEvent::TransferDone`]. This
    /// end hangs up only once the transfer succeeded, so a failed transfer
    /// leaves the call in place.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] for a call that is not
    /// up or is already transferring, or [`UaError::Send`].
    pub fn transfer(
        &mut self,
        call: CallHandle,
        target: &Uri,
        now: Instant,
    ) -> Result<(), UaError> {
        let mut value = Vec::with_capacity(target.as_bytes().len() + 2);
        value.push(b'<');
        value.extend_from_slice(target.as_bytes());
        value.push(b'>');
        self.refer(call, &value, now)
    }

    /// Call the transfer target, so that there is somebody to hand the call to.
    ///
    /// The consultation leg of an attended transfer, placed here rather than
    /// with [`call`](crate::UserAgent::call) so the two legs know each other.
    /// While up its state is [`CallState::Consulting`];
    /// [`UserAgent::transfer_to`] follows.
    ///
    /// Putting `call` on hold first is the application's. Hanging up the
    /// consultation without a transfer leaves `call` as it was.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when `call` is not up,
    /// is already consulting somebody, or is itself a consultation,
    /// [`UaError::NoSuchAccount`], or [`UaError::Send`].
    pub fn consult(
        &mut self,
        call: CallHandle,
        outgoing: &OutgoingCall,
        now: Instant,
    ) -> Result<CallHandle, UaError> {
        let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
        let state = held.state;
        // one consultation at a time, and no consulting from a consultation
        if !state.is_confirmed() || held.consulting.is_some() || held.consulting_for.is_some() {
            return Err(UaError::WrongState(state));
        }
        let account = held.account.ok_or(UaError::NoSuchAccount)?;
        let placed = self.call(account, outgoing, now)?;
        if let Some(second) = self.calls.get_mut(&placed) {
            second.consulting_for = Some(call);
        }
        if let Some(first) = self.calls.get_mut(&call) {
            first.consulting = Some(placed);
        }
        Ok(placed)
    }

    /// Hand this call to the far end of another one (RFC 3891).
    ///
    /// The `Replaces` names `other`'s dialog, so its far end replaces that
    /// call rather than answering a second. `other` is usually the
    /// [`UserAgent::consult`] call, but any confirmed call works.
    ///
    /// # Errors
    /// As [`UserAgent::transfer`], and [`UaError::WrongState`] when `other` is
    /// not up or has no dialog to name.
    pub fn transfer_to(
        &mut self,
        call: CallHandle,
        other: CallHandle,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self.calls.get(&other).ok_or(UaError::NoSuchCall)?;
        let state = held.state;
        // §3: the far end refuses a Replaces naming an early dialog it did
        // not originate
        if !state.is_confirmed() {
            return Err(UaError::WrongState(state));
        }
        let dialog = held.dialog.ok_or(UaError::WrongState(state))?;
        let snapshot = self
            .endpoint
            .dialog(dialog)
            .ok_or(UaError::WrongState(state))?;
        let remote_tag = snapshot
            .remote_tag
            .as_ref()
            .ok_or(UaError::WrongState(state))?;

        // §6.1: tags as seen by the end being replaced, so swapped
        let mut replaces = Vec::new();
        replaces.extend_from_slice(snapshot.call_id.as_bytes());
        replaces.extend_from_slice(b";to-tag=");
        replaces.extend_from_slice(remote_tag.as_bytes());
        replaces.extend_from_slice(b";from-tag=");
        replaces.extend_from_slice(snapshot.local_tag.as_bytes());

        // as a Request-URI (§19.1.5): stray URI headers in the Contact would
        // swallow the `?Replaces=` below
        let target = snapshot.remote_target.as_request_uri();
        let mut value = Vec::new();
        value.push(b'<');
        value.extend_from_slice(target.as_bytes());
        value.extend_from_slice(b"?Replaces=");
        escape(&replaces, &mut value);
        value.push(b'>');
        self.refer(call, &value, now)
    }

    /// Take a transfer that was asked for, and place the call it names.
    ///
    /// The target, `Replaces` and `Referred-By` come from the REFER, never
    /// the caller, hence [`OutgoingExtras`] rather than [`OutgoingCall`].
    /// `offer` is as on [`UserAgent::call`]: with none, the INVITE carries no
    /// offer and the answer comes in the 2xx (§14.1). `extra` fields are as
    /// on [`UserAgent::call`]; headers are refused as [`HeadersFor::Call`]
    /// refuses them, and also when they are `Replaces` or `Referred-By`. All
    /// is checked before the REFER is touched: a refusal sends nothing and
    /// leaves the transfer waiting.
    ///
    /// `call` may also be a
    /// [`UaEvent::ReferralRequested`](crate::UaEvent::ReferralRequested)
    /// handle, taken the same way from the account it arrived for
    /// ([`crate::referral`]).
    ///
    /// The 202 goes first, then the call. If the call cannot be sent, the
    /// subscription ends at once with a 503 (§2.4.5) and the error is
    /// returned.
    ///
    /// # Errors
    /// [`UaError::Header`] for a refused field in `extra.headers`,
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when nothing was
    /// asked, or it went unanswered for 64·T1 and the stack sent 408,
    /// [`UaError::NoSuchAccount`], or [`UaError::Send`].
    pub fn accept_transfer(
        &mut self,
        call: CallHandle,
        offer: Option<Arc<[u8]>>,
        extra: OutgoingExtras<'_>,
        now: Instant,
    ) -> Result<CallHandle, UaError> {
        for &(name, value) in extra.headers {
            let field = HeadersFor::Call
                .check(name.canonical().as_bytes(), value)
                .map_err(UaError::Header)?;
            if let Some(written) = FROM_THE_REFER.iter().find(|own| **own == field) {
                return Err(UaError::Header(HeaderRefused::WrittenByTheStack(
                    written.canonical(),
                )));
            }
        }
        if !self.calls.contains_key(&call) && self.referrals.held.contains_key(&call) {
            return self.accept_referral(call, offer, extra, now);
        }
        let (transaction, wanted, account) = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            let asked = held
                .asked_to_refer
                .take()
                .ok_or(UaError::WrongState(state))?;
            let account = held.account.ok_or(UaError::NoSuchAccount)?;
            let referred = held.referred.as_mut().ok_or(UaError::WrongState(state))?;
            (
                referred
                    .transaction
                    .take()
                    .ok_or(UaError::WrongState(state))?,
                asked,
                account,
            )
        };
        // §2.4.2's 202, echoing `Refer-Sub: false` (RFC 4488 §4). No
        // `Contact`: the dialog is the call's
        let mut response = OutgoingResponse::new(StatusCode::ACCEPTED);
        if wanted.quiet {
            response = response.header(REFER_SUB, b"false");
        }
        self.endpoint.respond(transaction, &response, now)?;
        self.subscribed(call, wanted.quiet, now);
        self.place_referred(call, account, &wanted, offer, &extra, now)
    }

    /// Take a transfer that was asked for with a call the application placed
    /// itself, and report that call's progress to the far end as though the
    /// REFER had placed it.
    ///
    /// For a bridge that reaches the target on its own line and joins the
    /// calls. The REFER is answered 202 (§2.4.2), echoing `Refer-Sub: false`
    /// if asked, and `placed` then reports as an
    /// [`UserAgent::accept_transfer`] call does: a NOTIFY per provisional
    /// (§2.4.5), the final one ending the subscription (§2.4.7). A `placed`
    /// already answered is reported at once with a 200.
    ///
    /// Only for a REFER inside a call; a referral ([`crate::referral`]) goes
    /// through [`UserAgent::accept_transfer`].
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`] when either handle names nothing (a
    /// referral's included), [`UaError::WrongState`] when nothing was asked
    /// on `call`, or `placed` is `call`, is over, or already reports to a
    /// REFER; or [`UaError::Send`]. A refusal leaves the REFER waiting.
    pub fn accept_transfer_placed(
        &mut self,
        call: CallHandle,
        placed: CallHandle,
        now: Instant,
    ) -> Result<(), UaError> {
        let answered = {
            let other = self.calls.get(&placed).ok_or(UaError::NoSuchCall)?;
            if placed == call
                || other.state == CallState::Terminated
                || other.reporting_to.is_some()
            {
                return Err(UaError::WrongState(other.state));
            }
            other.state.is_confirmed()
        };
        let (transaction, wanted) = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            let waiting = held
                .referred
                .is_some_and(|referred| referred.transaction.is_some());
            if !waiting || held.asked_to_refer.is_none() {
                return Err(UaError::WrongState(state));
            }
            let wanted = held
                .asked_to_refer
                .take()
                .ok_or(UaError::WrongState(state))?;
            let transaction = held
                .referred
                .as_mut()
                .and_then(|referred| referred.transaction.take())
                .ok_or(UaError::WrongState(state))?;
            (transaction, wanted)
        };
        let mut response = OutgoingResponse::new(StatusCode::ACCEPTED);
        if wanted.quiet {
            response = response.header(REFER_SUB, b"false");
        }
        self.endpoint.respond(transaction, &response, now)?;
        self.subscribed(call, wanted.quiet, now);
        let reporting = if let Some(referred) = self.referred_mut(call) {
            referred.placed = Some(placed);
            !referred.finished
        } else {
            false
        };
        if reporting {
            if let Some(held) = self.calls.get_mut(&placed) {
                held.reporting_to = Some(call);
            }
            if answered {
                self.report_transfer(placed, StatusCode::OK, now);
            }
        }
        self.drain(now);
        Ok(())
    }

    /// A REFER was just answered 202: its subscription starts with a 100
    /// (§2.4.5), or not at all with `Refer-Sub: false` (RFC 4488 §4).
    pub(crate) fn subscribed(&mut self, owner: CallHandle, quiet: bool, now: Instant) {
        if let Some(referred) = self.referred_mut(owner) {
            referred.transaction = None;
            referred.finished = quiet;
            referred.lapses = (!quiet).then(|| now + SUBSCRIPTION);
        }
        if !quiet {
            let state = running(now + SUBSCRIPTION, now);
            self.notify(owner, TRYING, &state, now);
        }
    }

    /// Place the call a taken REFER asked for, from `account`, and have it
    /// report to `owner` — the call the REFER arrived in, or the referral
    /// that was one of its own.
    pub(crate) fn place_referred(
        &mut self,
        owner: CallHandle,
        account: crate::account::AccountId,
        wanted: &ReferTo,
        offer: Option<Arc<[u8]>>,
        extra: &OutgoingExtras<'_>,
        now: Instant,
    ) -> Result<CallHandle, UaError> {
        let mut placed = OutgoingCall::new(wanted.target.clone());
        if let Some(offer) = offer {
            placed = placed.offer(offer);
        }
        if let Some((transport, remote)) = extra.destination {
            placed = placed.to_address(transport, remote);
        }
        placed = placed.forks(extra.forks);
        for &(name, value) in extra.headers {
            placed = placed.header(name, value);
        }
        if let Some(ref replaces) = wanted.replaces {
            placed = placed.header(HeaderName::Replaces, replaces);
        }
        // RFC 3892 §2.2 requires copying it. It proves nothing here (no §3
        // token), but the far end may have a policy that reads it
        if let Some(ref referred_by) = wanted.referred_by {
            placed = placed.header(HeaderName::ReferredBy, referred_by);
        }
        let new = match self.call(account, &placed, now) {
            Ok(new) => new,
            Err(error) => {
                // the 202 and 100 have gone: close the subscription
                self.close_subscription(owner, UNSENDABLE, FINISHED, now);
                self.drain(now);
                return Err(error);
            }
        };
        let reporting = if let Some(referred) = self.referred_mut(owner) {
            referred.placed = Some(new);
            !referred.finished
        } else {
            false
        };
        // without a subscription, reporting would land on the dialog's next
        // REFER
        if reporting && let Some(held) = self.calls.get_mut(&new) {
            held.reporting_to = Some(owner);
        }
        self.release_finished_referral(owner);
        self.drain(now);
        Ok(new)
    }

    /// Refuse one with any 4xx-6xx (§2.4.2). A referral
    /// ([`crate::referral`]) is refused the same way.
    ///
    /// # Errors
    /// As [`UserAgent::accept_transfer`].
    pub fn reject_transfer(
        &mut self,
        call: CallHandle,
        status: StatusCode,
        now: Instant,
    ) -> Result<(), UaError> {
        if !self.calls.contains_key(&call) && self.referrals.held.contains_key(&call) {
            return self.reject_referral(call, status, now);
        }
        let transaction = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            held.asked_to_refer = None;
            let referred = held.referred.as_mut().ok_or(UaError::WrongState(state))?;
            referred
                .transaction
                .take()
                .ok_or(UaError::WrongState(state))?
        };
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(status), now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.referred = None;
        }
        self.drain(now);
        Ok(())
    }
}

// -- sending -----------------------------------------------------------------

impl UserAgent {
    fn refer(&mut self, call: CallHandle, refer_to: &[u8], now: Instant) -> Result<(), UaError> {
        let (dialog, state, from) = {
            let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            if held.referring.is_some() {
                return Err(UaError::WrongState(held.state));
            }
            (
                held.dialog.ok_or(UaError::WrongState(held.state))?,
                held.state,
                held.from.clone(),
            )
        };
        if !state.is_confirmed() {
            return Err(UaError::WrongState(state));
        }
        let contact = self.current_contact(call, now);
        // §2: one Contact. `Referred-By` is the call's `From` (RFC 3892 §1),
        // not the Contact, which may be a GRUU (RFC 5627 §4.4) the far end
        // has no need for
        let request = OutgoingInDialogRequest::new(Method::Refer)
            .contact(&contact)
            .header(HeaderName::ReferTo, refer_to)
            .header(HeaderName::ReferredBy, &from);
        let transaction = self.endpoint.request_in_dialog(dialog, &request, now)?;
        // recorded now, not on the 202: a NOTIFY may beat it (§2.4.4)
        let id = self
            .endpoint
            .dialog(dialog)
            .and_then(|snapshot| snapshot.local_seq);
        if let Some(held) = self.calls.get_mut(&call) {
            held.referring = Some(AnyTransactionId::NonInviteClient(transaction));
            held.refer_subscription = Some(ReferSubscription { id });
        }
        self.remember_request(
            call,
            AnyTransactionId::NonInviteClient(transaction),
            Method::Refer,
        );
        self.drain(now);
        Ok(())
    }

    /// The notifier state of a REFER this end received, wherever it lives: on
    /// the call it arrived in, or on the referral that arrived outside one.
    pub(crate) fn referred_of(&self, owner: CallHandle) -> Option<Referred> {
        match self.calls.get(&owner) {
            Some(held) => held.referred,
            None => self
                .referrals
                .held
                .get(&owner)
                .map(|referral| referral.notifier),
        }
    }

    /// An in-call REFER nobody answered within 64·T1; the endpoint sent 408
    /// (§2.4.2). It opened no subscription, and kept it would hold the call's
    /// one seat, so every later REFER would get 491.
    pub(crate) fn forget_unanswered_refer(&mut self, transaction: TransactionId<NonInviteServer>) {
        for held in self.calls.values_mut() {
            if held
                .referred
                .is_some_and(|referred| referred.transaction == Some(transaction))
            {
                held.referred = None;
                held.asked_to_refer = None;
            }
        }
    }

    /// The same, to change.
    pub(crate) fn referred_mut(&mut self, owner: CallHandle) -> Option<&mut Referred> {
        match self.calls.get_mut(&owner) {
            Some(held) => held.referred.as_mut(),
            None => self
                .referrals
                .held
                .get_mut(&owner)
                .map(|referral| &mut referral.notifier),
        }
    }

    /// The dialog a REFER this end took reports in, and the `Contact` that
    /// goes on what this end sends there.
    fn notifier_of(&self, owner: CallHandle, now: Instant) -> Option<(DialogId, Box<[u8]>)> {
        if let Some(held) = self.calls.get(&owner) {
            return Some((held.dialog?, self.current_contact(owner, now)));
        }
        let referral = self.referrals.held.get(&owner)?;
        Some((
            referral.dialog?,
            self.referral_contact(referral.account, now),
        ))
    }

    /// Say how the referred call is going (§2.4.4, §2.4.5).
    fn notify(&mut self, owner: CallHandle, sipfrag: &[u8], state: &[u8], now: Instant) {
        let Some((dialog, contact)) = self.notifier_of(owner, now) else {
            return;
        };
        // §2.4.6: always sent, so no count of REFERs is needed
        let event = match self.referred_of(owner).and_then(|referred| referred.id) {
            Some(id) => format!("refer;id={id}").into_bytes(),
            None => REFER.to_vec(),
        };
        let request = OutgoingInDialogRequest::new(Method::Notify)
            .contact(&contact)
            .header(HeaderName::Event, &event)
            .header(HeaderName::SubscriptionState, state)
            .body(b"message/sipfrag;version=2.0", Arc::from(sipfrag.to_vec()));
        self.notify_by_itself(owner, dialog, event, request, now);
        // a referral is no call: tie the NOTIFY to its account, for
        // challenges
        if let Some(account) = self.referrals.held.get(&owner).map(|held| held.account) {
            let unowned: Vec<AnyTransactionId> = self
                .by_request
                .iter()
                .filter(|(id, (whose, method))| {
                    *whose == owner
                        && *method == Method::Notify
                        && !self.account_of.contains_key(id)
                })
                .map(|(id, _)| *id)
                .collect();
            for id in unowned {
                self.account_of.insert(id, account);
            }
        }
    }

    /// How the referred call is going, or how it ended, which ends the
    /// subscription (§2.4.7).
    pub(crate) fn report_transfer(&mut self, placed: CallHandle, status: StatusCode, now: Instant) {
        let Some(reporting_to) = self.calls.get(&placed).and_then(|held| held.reporting_to) else {
            return;
        };
        let Some(referred) = self.referred_of(reporting_to) else {
            return;
        };
        if referred.finished {
            return;
        }
        if status.is_final() {
            self.close_subscription(reporting_to, status, FINISHED, now);
            return;
        }
        if let Some(referred) = self.referred_mut(reporting_to) {
            referred.last = status;
        }
        let state = running(referred.lapses.unwrap_or(now + SUBSCRIPTION), now);
        self.notify(reporting_to, &status_line(status), &state, now);
    }

    /// End a taken REFER's subscription with a final NOTIFY (`status` in the
    /// body, `state` in `Subscription-State`). The placed call goes on but
    /// stops reporting.
    fn close_subscription(
        &mut self,
        owner: CallHandle,
        status: StatusCode,
        state: &[u8],
        now: Instant,
    ) {
        let Some(referred) = self.referred_of(owner) else {
            return;
        };
        if !referred.finished {
            self.notify(owner, &status_line(status), state, now);
        }
        if let Some(referred) = self.referred_mut(owner) {
            referred.finished = true;
            referred.last = status;
            referred.lapses = None;
        }
        if let Some(placed) = referred.placed
            && let Some(held) = self.calls.get_mut(&placed)
            && held.reporting_to == Some(owner)
        {
            held.reporting_to = None;
        }
        self.release_finished_referral(owner);
    }
}

/// `active` with the `expires` RFC 6665 §4.2.2 requires. Never zero, which
/// would read as over.
pub(crate) fn running(lapses: Instant, now: Instant) -> Vec<u8> {
    let left = lapses.saturating_duration_since(now).as_secs().max(1);
    format!("active;expires={left}").into_bytes()
}

// -- what comes back ---------------------------------------------------------

impl UserAgent {
    /// `None` when the event was about a transfer.
    pub(crate) fn on_transfer_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Refer) => {
                // not a call's dialog: pass it on, or the far end retransmits
                // into silence
                let Some(call) = self.by_dialog.get(&dialog).copied() else {
                    return Some(event);
                };
                let request = request.clone();
                self.on_refer(call, transaction, &request, now);
                None
            }
            // The `Event` decides, not the method (RFC 6665 §8.2.1): a dialog
            // may also carry `dialog` or `message-summary` NOTIFYs, which
            // must not be eaten as transfer reports.
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Notify)
                && package_is(&request.as_raw(), REFER) =>
            {
                // not a call: the subscription machine answers 481
                let Some(call) = self.by_dialog.get(&dialog).copied() else {
                    return Some(event);
                };
                // §2.4.4: only our REFER opens this package. An unmatched
                // NOTIFY would let the far end hang up the call with a fake
                // final report; the subscription machine answers it
                // (RFC 6665 §4.1.3).
                if !self.reports_on_our_refer(call, &request.as_raw()) {
                    return Some(event);
                }
                let request = request.clone();
                self.on_notify(call, transaction, &request, now);
                None
            }
            // a REFER outside a dialog, only when allowed; otherwise
            // `admission` refuses it further down
            Event::IncomingOutOfDialog {
                transaction,
                ref request,
            } if request.as_raw().method() == Some(Method::Refer)
                && self.referrals.allowed
                && !names_a_dialog(&request.as_raw()) =>
            {
                let request = request.clone();
                self.on_referral(transaction, &request, now);
                None
            }
            // §2.4.4: a `refer` SUBSCRIBE for no subscription gets 403, and
            // outside a dialog none exists. One with a To tag gets §12.2.2's
            // 481 elsewhere
            Event::IncomingOutOfDialog {
                transaction,
                ref request,
            } if request.as_raw().method() == Some(Method::Subscribe)
                && package_is(&request.as_raw(), REFER)
                && !names_a_dialog(&request.as_raw()) =>
            {
                self.endpoint
                    .respond(transaction, &OutgoingResponse::new(FORBIDDEN), now)
                    .ok();
                None
            }
            // inside one: a refresh or early end of a taken REFER's
            // subscription (§2.4.4)
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Subscribe)
                && package_is(&request.as_raw(), REFER) =>
            {
                let owner = self
                    .by_dialog
                    .get(&dialog)
                    .copied()
                    .or_else(|| self.referral_in(dialog));
                let request = request.clone();
                self.on_refer_subscribe(owner, transaction, &request, now);
                None
            }
            // the 481 for an unknown subscription (RFC 6665 §4.1.3) is the
            // subscription machine's; this handler sees only one package
            other => Some(other),
        }
    }

    /// A REFER arrived (§2.4.2).
    fn on_refer(
        &mut self,
        call: CallHandle,
        transaction: TransactionId<sipral_core::transaction::NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let raw = request.as_raw();
        // §2.4.1, §2.4.2: exactly one Refer-To, else 400
        let Some(wanted) = refer_to(&raw) else {
            let Ok(bad) = StatusCode::new(400) else {
                return;
            };
            self.endpoint
                .respond(transaction, &OutgoingResponse::new(bad), now)
                .ok();
            return;
        };
        // One at a time: a call keeps one `Referred`, and a second REFER
        // (allowed by §2.4.6) would overwrite the first. 491: pending behind
        // another, not refused on its merits.
        let outstanding = self
            .calls
            .get(&call)
            .and_then(|held| held.referred.as_ref())
            .is_some_and(|referred| !referred.finished);
        if outstanding {
            if let Ok(pending) = StatusCode::new(491) {
                self.endpoint
                    .respond(transaction, &OutgoingResponse::new(pending), now)
                    .ok();
            }
            return;
        }
        // §2.4.6: the `id` a NOTIFY about this REFER carries is its own
        // `CSeq`, not the dialog's next outgoing one
        let id = raw.cseq().ok().map(|cseq| cseq.seq);
        if let Some(held) = self.calls.get_mut(&call) {
            held.referred = Some(Referred::asked(transaction, id));
            held.asked_to_refer = Some(wanted.clone());
        }
        self.events.push_back(UaEvent::TransferRequested {
            call,
            target: wanted.target,
            attended: wanted.replaces.is_some(),
            request: request.clone(),
        });
    }

    /// Whether this NOTIFY reports on a subscription a REFER of this end's
    /// opened (§2, §2.4.4).
    fn reports_on_our_refer(&self, call: CallHandle, request: &RawMessage<'_>) -> bool {
        let Some(subscription) = self
            .calls
            .get(&call)
            .and_then(|held| held.refer_subscription)
        else {
            return false;
        };
        // §2.4.6: an `id` must match our REFER's CSeq; no `id` is fine (only
        // one is open here), and an unknown own number refuses nothing
        let Some(named) = event_id(request) else {
            return true;
        };
        subscription.id.is_none_or(|ours| ours == named)
    }

    /// One of the NOTIFYs a REFER of ours asked for (§2.4.4).
    fn on_notify(
        &mut self,
        call: CallHandle,
        transaction: TransactionId<sipral_core::transaction::NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        // answered at once (RFC 6665 §4.1.3)
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
            .ok();
        let raw = request.as_raw();
        let over = raw
            .header(HeaderName::SubscriptionState)
            .is_some_and(|value| Params::split(value).0.eq_ignore_ascii_case(b"terminated"));
        // terminated frees the seat whatever the body says, even on a first
        // NOTIFY carrying 100 (§2.4.4): nothing comes after it
        if over && let Some(held) = self.calls.get_mut(&call) {
            held.referring = None;
            held.refer_subscription = None;
        }
        let Some(status) = sipfrag_status(raw.body()) else {
            return;
        };

        if status.is_provisional() {
            self.events
                .push_back(UaEvent::TransferProgress { call, status });
            return;
        }
        self.events
            .push_back(UaEvent::TransferDone { call, status });
        if let Some(held) = self.calls.get_mut(&call) {
            held.referring = None;
        }
        // hang up only on success; a failed transfer keeps the call
        if status.is_success() && over {
            self.hang_up_by_itself(call, now);
        }
    }
}

// -- the subscription a taken REFER opened -----------------------------------

impl UserAgent {
    /// A SUBSCRIBE for the `refer` package inside a dialog: the far end
    /// refreshing the subscription a REFER it sent here opened, or ending it
    /// early (§2.4.4, RFC 6665 §4.2.1.4).
    fn on_refer_subscribe(
        &mut self,
        owner: Option<CallHandle>,
        transaction: TransactionId<NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let raw = request.as_raw();
        let named = event_id(&raw);
        let live = owner
            .and_then(|owner| Some((owner, self.referred_of(owner)?)))
            .filter(|(_, referred)| referred.lapses.is_some() && !referred.finished)
            // §2.4.6: an `id` naming another REFER is not about this one
            .filter(|(_, referred)| {
                named.is_none_or(|named| referred.id.is_none_or(|ours| ours == named))
            });
        let Some((owner, referred)) = live else {
            // §2.4.4: 403 for a subscription that does not exist
            self.endpoint
                .respond(transaction, &OutgoingResponse::new(FORBIDDEN), now)
                .ok();
            return;
        };
        // RFC 6665 §4.2.1.4: may shorten, never lengthen; no `Expires`
        // means the first NOTIFY's value
        let asked = raw
            .expires()
            .ok()
            .and_then(|digits| digits.value)
            .map_or(SUBSCRIPTION, |seconds| {
                Duration::from_secs(u64::from(seconds))
            });
        let granted = asked.min(SUBSCRIPTION);
        let Some((_, contact)) = self.notifier_of(owner, now) else {
            return;
        };
        let seconds = granted.as_secs().to_string();
        let response = OutgoingResponse::new(StatusCode::OK)
            .contact(&contact)
            .header(HeaderName::Expires, seconds.as_bytes());
        if self.endpoint.respond(transaction, &response, now).is_err() {
            return;
        }
        if granted.is_zero() {
            // a final NOTIFY with reason=timeout (RFC 6665 §4.1.2.3,
            // §4.2.1.4); the placed call is not withdrawn (RFC 3515 §2.4.4)
            self.close_subscription(owner, referred.last, TIMED_OUT, now);
            return;
        }
        // a NOTIFY at once with the full state (RFC 6665 §4.2.1.2, §2.4.5)
        let lapses = now + granted;
        if let Some(referred) = self.referred_mut(owner) {
            referred.lapses = Some(lapses);
        }
        self.notify(
            owner,
            &status_line(referred.last),
            &running(lapses, now),
            now,
        );
    }

    /// When the next subscription a taken REFER opened lapses.
    pub(crate) fn refer_subscription_deadline(&self) -> Option<Instant> {
        let on_calls = self
            .calls
            .values()
            .filter_map(|held| held.referred)
            .filter(|referred| !referred.finished)
            .filter_map(|referred| referred.lapses);
        let on_referrals = self
            .referrals
            .held
            .values()
            .filter(|referral| !referral.notifier.finished)
            .filter_map(|referral| referral.notifier.lapses);
        on_calls.chain(on_referrals).min()
    }

    /// End the ones nobody refreshed in time, with RFC 6665 §4.2.1.4's
    /// "terminated" and "reason=timeout".
    pub(crate) fn fire_refer_subscriptions(&mut self, now: Instant) {
        let on_calls = self.calls.iter().filter_map(|(handle, held)| {
            held.referred
                .filter(|referred| !referred.finished)
                .and_then(|referred| referred.lapses)
                .filter(|at| *at <= now)
                .map(|_| *handle)
        });
        let on_referrals = self.referrals.held.iter().filter_map(|(handle, held)| {
            (!held.notifier.finished && held.notifier.lapses.is_some_and(|at| at <= now))
                .then_some(*handle)
        });
        let lapsed: Vec<CallHandle> = on_calls.chain(on_referrals).collect();
        for owner in lapsed {
            let last = self
                .referred_of(owner)
                .map_or(StatusCode::TRYING, |referred| referred.last);
            self.close_subscription(owner, last, TIMED_OUT, now);
        }
    }
}

// -- Replaces ----------------------------------------------------------------

impl UserAgent {
    /// Which of this end's calls an incoming `Replaces` names, and what §3
    /// says to do about it.
    ///
    /// `Ok(None)` when the request carries no `Replaces` at all.
    pub(crate) fn replaced_by(
        &mut self,
        invite: &OwnedMessage,
    ) -> Result<Option<CallHandle>, StatusCode> {
        let request = &invite.as_raw();
        // §6.1, §3: more than one Replaces is 400; a proxy may have read the
        // other one
        match request.field_values(HeaderName::Replaces).count() {
            0 => return Ok(None),
            1 => (),
            _ => return Err(StatusCode::new(400).unwrap_or(StatusCode::SERVER_ERROR)),
        }
        let Some(value) = request.header(HeaderName::Replaces) else {
            return Ok(None);
        };
        let (call_id, params) = Params::split(value);
        // §6.1: both tags are required
        let (Some(to_tag), Some(from_tag)) = (params.get("to-tag"), params.get("from-tag")) else {
            return Err(StatusCode::new(400).unwrap_or(StatusCode::SERVER_ERROR));
        };
        let early_only = params.get("early-only").is_some();

        let mut found = None;
        for (handle, held) in &self.calls {
            let Some(dialog) = held.dialog else {
                continue;
            };
            let Some(snapshot) = self.endpoint.dialog(dialog) else {
                continue;
            };
            let ours = snapshot.local_tag.as_bytes() == &*to_tag
                && snapshot
                    .remote_tag
                    .as_ref()
                    .is_some_and(|tag| tag.as_bytes() == &*from_tag)
                && snapshot.call_id.as_bytes() == call_id;
            if !ours {
                continue;
            }
            // §3: "If the Replaces header field matches more than one dialog,
            // the UA MUST act as if no match is found."
            if found.is_some() {
                return Err(StatusCode::CALL_DOES_NOT_EXIST);
            }
            found = Some((*handle, held.state, held.direction, held.peer));
        }

        let Some((handle, state, direction, peer)) = found else {
            return Err(StatusCode::CALL_DOES_NOT_EXIST);
        };
        // §3, §8: the replacer must be authorised. With no authenticated
        // identity, the default compares where the INVITE came from with the
        // named call's peer; `on_replaces` lets the application change that
        // (see the module docs).
        //
        // It runs before the state arms so a stranger who guessed the
        // identifiers cannot read the call's state off the status code.
        let named = Replacing::new(handle, self.guard.source() == peer);
        match self.guard.screen_replaces(invite, named) {
            Screening::Take => (),
            Screening::Refuse(status) => return Err(status),
        }
        match state {
            CallState::Terminating | CallState::Terminated => {
                // §3
                Err(StatusCode::new(603).unwrap_or(StatusCode::BUSY_HERE))
            }
            CallState::Confirmed | CallState::Consulting if early_only => {
                // §3: early-only on a confirmed call
                Err(StatusCode::BUSY_HERE)
            }
            CallState::Confirmed | CallState::Consulting => Ok(Some(handle)),
            // §3: only our own early dialog can be replaced
            _ if direction == Direction::Outgoing => Ok(Some(handle)),
            _ => Err(StatusCode::CALL_DOES_NOT_EXIST),
        }
    }

    /// The call that was replaced is over, now that the one replacing it is
    /// answered (§3).
    pub(crate) fn shut_down_replaced(&mut self, call: CallHandle, now: Instant) {
        let replaced = self.calls.get(&call).and_then(|held| held.replaces);
        let Some(replaced) = replaced else {
            return;
        };
        if let Some(held) = self.calls.get_mut(&call) {
            held.replaces = None;
        }
        self.events
            .push_back(UaEvent::CallReplaced { call, replaced });
        // BYE or CANCEL, whichever fits
        self.hang_up_by_itself(replaced, now);
    }

    /// Refuse an INVITE whose `Replaces` names nothing this end can give up,
    /// or names a call the sender is not the peer of.
    pub(crate) fn refuse_replaces(
        &mut self,
        transaction: TransactionId<InviteServer>,
        status: StatusCode,
        now: Instant,
    ) {
        if status == FORBIDDEN {
            self.guard.refused_replaces();
        }
        self.endpoint
            .respond_invite(transaction, &OutgoingResponse::new(status), now)
            .ok();
    }
}

/// The `Refer-To` of a REFER, when it has exactly one that can be read.
pub(crate) fn refer_to(request: &RawMessage<'_>) -> Option<ReferTo> {
    if request.field_values(HeaderName::ReferTo).count() != 1 {
        return None;
    }
    let value = request.header(HeaderName::ReferTo)?;
    let inside = between_angles(value).unwrap_or(value);
    let (uri, replaces) = split_replaces(inside);
    // The unescaped Replaces goes onto an INVITE header line, so an escaped
    // CRLF would inject a header (RFC 3891 §6.1 allows no control bytes).
    // The whole Refer-To is refused: dropping only the Replaces would turn
    // an attended transfer into a blind one.
    if replaces.as_deref().is_some_and(holds_a_control_byte) {
        return None;
    }
    Some(ReferTo {
        target: Uri::parse(uri).ok()?,
        replaces,
        referred_by: referred_by(request),
        quiet: asks_for_no_subscription(request),
    })
}

/// Whether a REFER carries RFC 4488's `Refer-Sub: false`.
///
/// Only a single field with value `false` counts; anything unreadable is the
/// default case (§4).
fn asks_for_no_subscription(request: &RawMessage<'_>) -> bool {
    let mut values = request.field_values(REFER_SUB);
    let (Some(only), None) = (values.next(), values.next()) else {
        return false;
    };
    Params::split(only).0.eq_ignore_ascii_case(b"false")
}

/// Whether a request outside any dialog has a `To` tag anyway; it gets 481
/// (RFC 3261 §12.2.2).
pub(crate) fn names_a_dialog(request: &RawMessage<'_>) -> bool {
    request.to().is_ok_and(|to| to.tag().is_some())
}

/// The `Referred-By` to carry on to the INVITE this REFER asks for (RFC 3892
/// §2.2).
///
/// None when there are two (§2.1): no guessing which one to pass on. The
/// REFER itself is not refused over it.
fn referred_by(request: &RawMessage<'_>) -> Option<Box<[u8]>> {
    let mut values = request.field_values(HeaderName::ReferredBy);
    let only = values.next()?;
    if values.next().is_some() {
        return None;
    }
    // the parser keeps a fold's CRLF, which copied out would start a new
    // header
    Some(Box::from(unfold(only).as_ref()))
}

/// Whether a NOTIFY reports on the named event package (RFC 6665 §8.2.1).
///
/// The name compares case-insensitively. A NOTIFY with no `Event` is not
/// claimed: guessing would eat somebody else's notification.
fn package_is(request: &RawMessage<'_>, package: &[u8]) -> bool {
    request
        .header(HeaderName::Event)
        .is_some_and(|value| Params::split(value).0.eq_ignore_ascii_case(package))
}

/// The `id` of the event a NOTIFY reports on (RFC 6665 §8.2.1, RFC 3515
/// §2.4.6), when it names one this end can read as a number.
fn event_id(request: &RawMessage<'_>) -> Option<u32> {
    let value = request.header(HeaderName::Event)?;
    let named = Params::split(value).1.get("id")?;
    core::str::from_utf8(&named).ok()?.parse().ok()
}

/// `<...>`, when the value has them.
fn between_angles(value: &[u8]) -> Option<&[u8]> {
    let start = value.iter().position(|byte| *byte == b'<')? + 1;
    let end = value.iter().rposition(|byte| *byte == b'>')?;
    value.get(start..end)
}

/// A URI and the `Replaces` header it carries in its own header part, unescaped
/// so that it can go straight into the new INVITE.
fn split_replaces(uri: &[u8]) -> (&[u8], Option<Box<[u8]>>) {
    let Some(at) = uri.iter().position(|byte| *byte == b'?') else {
        return (uri, None);
    };
    let head = uri.get(..at).unwrap_or_default();
    let query = uri.get(at + 1..).unwrap_or_default();
    for field in query.split(|byte| *byte == b'&') {
        let Some(split) = field.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let name = field.get(..split).unwrap_or_default();
        if !name.eq_ignore_ascii_case(b"Replaces") {
            continue;
        }
        let value = field.get(split + 1..).unwrap_or_default();
        return (head, Some(unescape(value)));
    }
    (head, None)
}

/// Percent-encode what a URI header value may not carry literally.
fn escape(value: &[u8], out: &mut Vec<u8>) {
    for byte in value {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(*byte),
            other => {
                out.push(b'%');
                out.extend_from_slice(format!("{other:02X}").as_bytes());
            }
        }
    }
}

/// A byte no header value may hold outside a quoted pair: the C0 controls but
/// the tab LWS allows, and DEL.
fn holds_a_control_byte(value: &[u8]) -> bool {
    value
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
}

/// And back.
fn unescape(value: &[u8]) -> Box<[u8]> {
    let mut out = Vec::with_capacity(value.len());
    let mut rest = value;
    while let Some(&byte) = rest.first() {
        if byte == b'%'
            && let Some(pair) = rest.get(1..3)
            && let Ok(text) = core::str::from_utf8(pair)
            && let Ok(decoded) = u8::from_str_radix(text, 16)
        {
            out.push(decoded);
            rest = rest.get(3..).unwrap_or_default();
            continue;
        }
        out.push(byte);
        rest = rest.get(1..).unwrap_or_default();
    }
    out.into_boxed_slice()
}

/// The status a `message/sipfrag` reports (§2.4.5).
fn sipfrag_status(body: &[u8]) -> Option<StatusCode> {
    let line = body.split(|byte| *byte == b'\n').next()?;
    let mut fields = line.split(|byte| *byte == b' ').filter(|f| !f.is_empty());
    let version = fields.next()?;
    if !version.starts_with(b"SIP/") {
        return None;
    }
    let code = core::str::from_utf8(fields.next()?).ok()?;
    StatusCode::new(code.parse().ok()?).ok()
}

/// A status line to put in one.
fn status_line(status: StatusCode) -> Vec<u8> {
    let reason = status.reason().unwrap_or("Unknown");
    format!("SIP/2.0 {} {reason}\r\n", status.get()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::{escape, sipfrag_status, split_replaces, status_line, unescape};
    use sipral_core::msg::StatusCode;

    #[test]
    fn a_replaces_survives_being_put_in_a_uri_and_taken_out_again() {
        let original = b"a84b4c76e66710;to-tag=abc;from-tag=def";
        let mut escaped = Vec::new();
        escape(original, &mut escaped);
        assert!(
            !escaped.contains(&b';'),
            "a semicolon in a URI header would end the header: {}",
            String::from_utf8_lossy(&escaped)
        );
        assert_eq!(&*unescape(&escaped), original);
    }

    #[test]
    fn a_refer_to_with_a_replaces_gives_back_both_halves() {
        let uri = b"sip:bob@192.0.2.9?Replaces=call%3Bto-tag%3Dx%3Bfrom-tag%3Dy";
        let (target, replaces) = split_replaces(uri);
        assert_eq!(target, b"sip:bob@192.0.2.9");
        assert_eq!(
            replaces.as_deref(),
            Some(&b"call;to-tag=x;from-tag=y"[..]),
            "and it is unescaped, ready for the new INVITE"
        );
    }

    #[test]
    fn a_refer_to_without_one_is_a_plain_target() {
        let (target, replaces) = split_replaces(b"sip:carol@example.com");
        assert_eq!(target, b"sip:carol@example.com");
        assert!(replaces.is_none());
    }

    #[test]
    fn a_sipfrag_says_what_happened_and_nothing_else_does() {
        // 2.4.5: the body begins with a status line
        assert_eq!(
            sipfrag_status(b"SIP/2.0 100 Trying\r\n"),
            Some(StatusCode::TRYING)
        );
        assert_eq!(sipfrag_status(b"SIP/2.0 200 OK\r\n"), Some(StatusCode::OK));
        assert_eq!(
            sipfrag_status(b"SIP/2.0 486 Busy Here\r\n\r\n"),
            Some(StatusCode::BUSY_HERE)
        );
        assert_eq!(sipfrag_status(b"INVITE sip:x SIP/2.0\r\n"), None);
        assert_eq!(sipfrag_status(b""), None);
    }

    #[test]
    fn a_status_line_reads_back_as_the_status_it_was_written_from() {
        for status in [StatusCode::TRYING, StatusCode::RINGING, StatusCode::OK] {
            assert_eq!(sipfrag_status(&status_line(status)), Some(status));
        }
    }
}
