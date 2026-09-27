// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Transfer: REFER, the subscription it opens, and `Replaces` (RFC 3515,
//! RFC 3891).
//!
//! A transfer is three parties and two of them never speak to each other. The
//! transferor is in a call and asks the other end to call somebody else; the
//! transferee does, and reports back; the target knows nothing about any of it
//! unless a `Replaces` tells it which of its own calls is being taken over.
//!
//! **REFER is not fire and forget.** §2.4.4 makes it open a subscription, and
//! the transferee has to say what happened: a NOTIFY carrying a
//! `message/sipfrag` whose first line is a SIP status line, `100` while it is
//! trying and the real answer when there is one. That is what lets a phone
//! show "transferring" and then either hang up or take the call back. The
//! subscription ends with a NOTIFY marked `terminated;reason=noresource`,
//! which §2.4.7 makes the last word.
//!
//! **Blind and attended differ by one URI parameter.** A blind transfer sends
//! `Refer-To: <sip:carol@example.com>`. An attended one sends the target's own
//! contact with a `Replaces` in it, naming a dialog the transferee already has
//! with the target — so the target replaces a call it is already in rather
//! than getting a second one. Everything else is the same code.
//!
//! **The attended one needs a second call first**, to the target, and that call
//! is not an ordinary one: it exists so that the transferor can speak to the
//! target before handing the caller over, and it is the dialog the `Replaces`
//! will name. So it is placed with [`UserAgent::consult`] and it says what it
//! is — [`CallState::Consulting`] — rather than being an ordinary confirmed
//! call the application has to remember the purpose of.
//!
//! **What `Replaces` matches, and what it does not.** §3 is exact about it,
//! and every branch is a different status code: no match is 481, a dialog that
//! has already ended is 603, an early dialog this end did not originate is
//! 481, and only a confirmed dialog or an early one of our own is replaced.
//! Getting that wrong hands somebody else's call to whoever asks.
//!
//! **Matching is not permission.** §3 also asks the UA to "verify that the
//! initiator of the new INVITE is authorized to replace the matched dialog",
//! and §8 will only have one accepted "if the peer requesting replacement has
//! been properly authenticated". Three strings out of a dialog are not an
//! identity: they travel in every packet of the call, and a `From` or a
//! `Referred-By` naming the far end is written by whoever sent the INVITE.
//! This stack answers challenges and issues none, so it has no authenticated
//! peer to compare and compares the one thing the sender did not write:
//! a `Replaces` is honoured only when the INVITE carrying it arrives from the
//! same place the named call's own signalling does. Anything else is 403 and
//! the named call is left exactly as it was.
//!
//! **And that is the default, not the whole rule.** It refuses a legitimate
//! attended transfer whose transferee reaches this end directly rather than
//! through the line's proxy, which is a deployment rather than a corner case,
//! so the application has the last word:
//! [`Screen::on_replaces`](crate::Screen::on_replaces) is handed the INVITE
//! and which call it names, and can widen the rule or tighten it. Its default
//! body is the paragraph above, so nothing that does not override it changes.
//!
//! **A notification is not a transfer either.** §2.4.4 makes REFER the only
//! thing that can open a subscription to this package, so a NOTIFY of it is
//! acted on only where a REFER of this end's opened one, and anything else is
//! left for the subscription machine to answer 481. And §2.2 of RFC 3892 has
//! the INVITE this end places for a REFER carry that REFER's `Referred-By`
//! onward — because the RFC requires it, not because an incoming one proves
//! anything here.
//!
//! **The subscription a taken REFER opens is a real one.** §2.4.4 makes it
//! "the same as a subscription created with a SUBSCRIBE request", so it runs
//! for as long as its first NOTIFY said ([`SUBSCRIPTION`], in the `expires`
//! RFC 6665 §4.2.2 makes compulsory on an `active` one), the far end may
//! refresh it or end it early with a SUBSCRIBE of its own, and one that
//! lapses is ended with `terminated;reason=timeout` (RFC 6665 §4.2.1.4). None
//! of that touches the call the REFER placed: §2.4.4 says an unsubscription
//! "is not an indication that the referenced request should be withdrawn".
//! And a REFER carrying RFC 4488's `Refer-Sub: false` is answered with the
//! same field and opens no subscription at all — this end has no reason to
//! refuse to keep less state.
//!
//! A REFER outside any dialog — somebody asking this end to place a call it
//! is not already in — is the same machinery reached another way, and
//! [`crate::referral`] says how and why it is off by default.

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

/// The fields the INVITE an accepted transfer places takes from the REFER and
/// from nowhere else. RFC 3891 §3 has an INVITE with more than one `Replaces`
/// refused with a 400, RFC 3892 §3 gives `Referred-By` one referrer, and on a
/// blind transfer a `Replaces` of the application's own would take over a
/// dialog the REFER never named.
const FROM_THE_REFER: &[HeaderName<'static>] = &[HeaderName::Replaces, HeaderName::ReferredBy];

/// The event package a REFER subscribes to (§3.1).
pub(crate) const REFER: &[u8] = b"refer";
/// §2.4.7: the last NOTIFY says the subscription is over and why.
const FINISHED: &[u8] = b"terminated;reason=noresource";
/// RFC 6665 §4.2.1.4: a subscription that lapsed, or that the subscriber
/// ended with a SUBSCRIBE of `Expires: 0`, is ended "with a reason code of
/// timeout".
const TIMED_OUT: &[u8] = b"terminated;reason=timeout";
/// §2.4.5: "If a NOTIFY is generated when the subscription state is pending,
/// its body should consist of a status line containing a response code of 100."
pub(crate) const TRYING: &[u8] = b"SIP/2.0 100 Trying\r\n";

/// How long the implicit subscription of a REFER this end took runs before
/// it has to be refreshed, which the first NOTIFY says in its `expires`.
///
/// §3.4: "The duration SHOULD be chosen to be longer than the time the
/// referenced request will be given to complete", and the INVITE this end
/// places for one carries no `Expires` — it rings for as long as the far end
/// lets it. An hour is past any ringing a person waits through, and the
/// subscription is over the moment the call has its answer anyway (§2.4.7),
/// so this is a ceiling rather than a cost.
pub(crate) const SUBSCRIPTION: Duration = Duration::from_hours(1);

/// RFC 4488 §4: the field a REFER asks for no subscription with, and the one
/// the 2xx that grants it has to carry back.
pub(crate) const REFER_SUB: HeaderName<'static> = HeaderName::Extension("Refer-Sub");

/// §2.4.5's own minimal example of the NOTIFY for "the reference failed":
/// what the subscription ends with when the call a taken REFER asked for
/// could not even be sent.
const UNSENDABLE: StatusCode = StatusCode::SERVICE_UNAVAILABLE;
/// What an INVITE gets when its `Replaces` names a live call it has no
/// standing to replace (RFC 3891 §3, RFC 3261 §21.4.4).
pub(crate) const FORBIDDEN: StatusCode = match StatusCode::new(403) {
    Ok(status) => status,
    // 403 is in range, so this arm never runs; it exists because `new` is
    // fallible and nothing in this crate panics to say otherwise
    Err(_) => StatusCode::CALL_DOES_NOT_EXIST,
};

/// One this end received, and the notifier's half of the subscription it
/// opens once taken (§2.4.4).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Referred {
    /// The transaction to answer, until it is answered.
    pub(crate) transaction: Option<TransactionId<NonInviteServer>>,
    /// The call placed because of it, once there is one.
    pub(crate) placed: Option<CallHandle>,
    /// Whether the subscription is over: the closing NOTIFY has gone, or
    /// there never was one to send.
    pub(crate) finished: bool,
    /// The `CSeq` of the REFER that asked for this, put on every NOTIFY this
    /// end sends about it as `Event: refer;id=<n>` (§2.4.6). Required from
    /// the second REFER a dialog carries onward; carrying it from the first
    /// too is legal and one fewer thing to get right per dialog.
    pub(crate) id: Option<u32>,
    /// When the subscription lapses unless the far end refreshes it (RFC
    /// 6665 §4.2.1.4). `None` until the REFER is taken.
    pub(crate) lapses: Option<Instant>,
    /// What the last NOTIFY said, for the one a subscription that ends early
    /// closes with: §2.4.5 has every body be "a complete statement of the
    /// status of the referred action".
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

/// The implicit subscription a REFER of this end's opened (RFC 3515 §2:
/// "A REFER request implicitly establishes a subscription to the refer
/// event").
///
/// It exists from the moment the REFER is written — §2.4.4 warns that "the
/// agent that issued the REFER MUST be prepared to receive a NOTIFY before
/// the REFER transaction completes", so waiting for the 202 would leave a
/// legitimate first notification matching nothing — until the last NOTIFY
/// says the subscription is over, or until the REFER is refused, which is the
/// one answer that creates no subscription at all (§2.4.2).
///
/// Without it there is nothing to check a NOTIFY against. The seat in
/// [`Call::referring`](crate::call::Call) cannot be that thing: it is given
/// back when the REFER is answered, which is before any notification can
/// arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReferSubscription {
    /// The `CSeq` of the REFER that created it.
    ///
    /// §2.4.6 makes this the `id` of the event: from the second REFER in a
    /// dialog on, every NOTIFY "MUST include an id parameter in the Event
    /// header field containing the sequence number of the REFER", and the
    /// first one MAY carry it. So a notification that names an `id` names one
    /// REFER, and this is what says whether it is ours. `None` when the
    /// dialog could not say what number went out, in which case an `id` is
    /// not used to refuse anything.
    ///
    /// It is also the number 8.3.5 has to put on the wire — `Event:
    /// refer;id=<cseq>` on the REFER and on the NOTIFYs this end sends — and
    /// that work belongs here rather than in a second record of the same
    /// thing.
    pub(crate) id: Option<u32>,
}

/// What a `Refer-To` asks for.
#[derive(Clone, Debug)]
pub(crate) struct ReferTo {
    /// Where to call.
    pub(crate) target: Uri,
    /// The `Replaces` it carried, as it should go on the new INVITE.
    pub(crate) replaces: Option<Box<[u8]>>,
    /// The `Referred-By` of the REFER that asked for this, to be copied onto
    /// the INVITE it triggers (RFC 3892 §2.2).
    pub(crate) referred_by: Option<Box<[u8]>>,
    /// Whether the REFER asked for no subscription (RFC 4488 §4's
    /// `Refer-Sub: false`), which taking it grants: the 202 says so, and no
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
    /// end does not hang up until the transfer has succeeded: §2.4.4 leaves
    /// that open, and hanging up first turns a transfer that failed into a
    /// call that vanished.
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
    /// This is the second leg of an attended transfer — the consultation call —
    /// and it is placed here rather than with
    /// [`call`](crate::UserAgent::call) so that the two legs know about each
    /// other. It is answered like any other call, and while it is up its state
    /// is [`CallState::Consulting`]: a confirmed dialog whose reason for
    /// existing is the transfer that follows. [`UserAgent::transfer_to`] is
    /// what follows.
    ///
    /// Putting `call` on hold first is the application's, because it is a
    /// session change and this layer does not make those uninvited. If the
    /// consultation ends without a transfer, hanging it up leaves `call`
    /// exactly where it was.
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
        // one consultation at a time, and a consultation is not a call to
        // consult from: a chain of them names no transfer at all
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
    /// The `Replaces` names the dialog `other` is in, so the party at its far
    /// end replaces the call it already has rather than answering a second.
    /// `other` is normally the consultation call [`UserAgent::consult`] placed,
    /// and any other call that is up may be named instead — RFC 3891 replaces a
    /// dialog, not a role.
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
        // an early dialog is not something to hand over: §3 has the far end
        // refuse a Replaces naming one it did not originate, and this end
        // would have hung up a call that was never taken
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

        // §6.1: exactly one to-tag and one from-tag, and they name the dialog
        // from the point of view of the end that is being replaced — so ours
        // is its remote and its local is ours
        let mut replaces = Vec::new();
        replaces.extend_from_slice(snapshot.call_id.as_bytes());
        replaces.extend_from_slice(b";to-tag=");
        replaces.extend_from_slice(remote_tag.as_bytes());
        replaces.extend_from_slice(b";from-tag=");
        replaces.extend_from_slice(snapshot.local_tag.as_bytes());

        // the target as a Request-URI (§19.1.5), which is what the transferee
        // will make of it: no URI headers and no method. A dialog's Contact
        // may carry neither (RFC 3261 Table 1), and one that does anyway would
        // otherwise swallow the `?Replaces=` below into its last header value
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
    /// The target, `Replaces` and `Referred-By` on the INVITE this places are
    /// never the caller's to give — they come from the REFER that was
    /// accepted, which is why `extra` is an [`OutgoingExtras`] rather than an
    /// [`OutgoingCall`]: there is no legitimate target for the caller to put
    /// in one. `offer` means what it does on [`UserAgent::call`] — the
    /// session description to put in the INVITE, with none it carries no
    /// offer and the answer travels in the 2xx instead (§14.1) — and so does
    /// every field of `extra`: a destination other than the account's, which
    /// forks to keep, and header fields of the caller's own, refused for
    /// everything [`HeadersFor::Call`] refuses them for on
    /// [`UserAgent::call`], and refused as well when they are `Replaces` or
    /// `Referred-By`, which the REFER supplies. Every field is checked
    /// before the REFER is touched: a refusal leaves the transfer waiting,
    /// still to be taken or refused, with nothing sent.
    ///
    /// `call` may also be the handle of a
    /// [`UaEvent::ReferralRequested`](crate::UaEvent::ReferralRequested) — a
    /// REFER outside any dialog — which is taken exactly the same way and
    /// places its call from the account it arrived for ([`crate::referral`]).
    ///
    /// The 202 goes first and then the call. A call that cannot even be sent
    /// ends the subscription at once with §2.4.5's own 503, so the far end is
    /// told rather than left with a 100 that nothing follows, and the error
    /// comes back here.
    ///
    /// # Errors
    /// [`UaError::Header`] for a field in `extra.headers` refused as above,
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when nothing was
    /// asked, [`UaError::NoSuchAccount`], or [`UaError::Send`].
    pub fn accept_transfer(
        &mut self,
        call: CallHandle,
        offer: Option<Arc<[u8]>>,
        extra: OutgoingExtras<'_>,
        now: Instant,
    ) -> Result<CallHandle, UaError> {
        // every refusal `call` would give these fields, and the two fields
        // the REFER alone supplies, checked before the REFER is touched: a
        // field refused here leaves the transfer waiting, still to be taken
        // or refused, with nothing sent
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
        // §2.4.2: "the UA MUST return a 202 Accepted response before the REFER
        // transaction expires", and RFC 4488 §4 has the 2xx that grants
        // `Refer-Sub: false` say so. No `Contact` here: the dialog is the
        // call's, and its remote target was set by the INVITE
        let mut response = OutgoingResponse::new(StatusCode::ACCEPTED);
        if wanted.quiet {
            response = response.header(REFER_SUB, b"false");
        }
        self.endpoint.respond(transaction, &response, now)?;
        self.subscribed(call, wanted.quiet, now);
        self.place_referred(call, account, &wanted, offer, &extra, now)
    }

    /// A REFER was just answered 202: its subscription starts, with §2.4.5's
    /// 100 while it is only trying, or — granted `Refer-Sub: false` — does not
    /// start at all (RFC 4488 §4: "no implicit subscription is created").
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
        // RFC 3892 §2.2: "A UA accepting a REFER request (a referee) to a SIP
        // URI ... MUST copy any Referred-By header field" onto the request it
        // triggers. It is not authorisation here and this stack does not read
        // an incoming one as proof of anything — §3's signed token is not
        // implemented — but the far end may have a policy that reads it, and
        // dropping it silently is deciding on its behalf.
        if let Some(ref referred_by) = wanted.referred_by {
            placed = placed.header(HeaderName::ReferredBy, referred_by);
        }
        let new = match self.call(account, &placed, now) {
            Ok(new) => new,
            Err(error) => {
                // the 202 has gone and so, unless it was declined, has a
                // 100: the subscription is not left open on a call that was
                // never placed
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
        // a REFER granted no subscription has nobody to report to, and a
        // call that reported to it anyway would be read as reporting on
        // whichever REFER that dialog takes next
        if reporting && let Some(held) = self.calls.get_mut(&new) {
            held.reporting_to = Some(owner);
        }
        self.release_finished_referral(owner);
        self.drain(now);
        Ok(new)
    }

    /// Refuse one, with a final status of the application's choosing: §2.4.2
    /// allows "any appropriate 4xx-6xx class response". A referral
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
        // §2: "REFER creates a dialog, and MAY be Record-Routed, hence MUST
        // contain a single Contact header field value." `Referred-By` is not
        // that Contact: RFC 3892 §1 has it identify the referrer, and this
        // call's own `From` already did that to the peer it is now asking to
        // refer -- a GRUU in Contact (RFC 5627 §4.4, or a temporary one on an
        // anonymous call, §3.3) would otherwise hand out a routable address
        // the far end never needed just to say who is asking.
        let request = OutgoingInDialogRequest::new(Method::Refer)
            .contact(&contact)
            .header(HeaderName::ReferTo, refer_to)
            .header(HeaderName::ReferredBy, &from);
        let transaction = self.endpoint.request_in_dialog(dialog, &request, now)?;
        // §2: the REFER is what creates the subscription, so it is recorded
        // now rather than when the 202 comes back — §2.4.4 allows a NOTIFY to
        // beat that answer, and one that arrives before there is a record of
        // what asked for it is a notification against nothing
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
        // §2.4.6: the `id` names which REFER this reports on. Carrying it on
        // every NOTIFY rather than only the second REFER onward is legal --
        // the section MAYs it for the first -- and needs no counter of how
        // many REFERs this dialog has seen.
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
        // a referral is no call, so what remembered the NOTIFY could not say
        // whose password answers a challenge to it; the account it arrived
        // for can
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

    /// End the subscription of a REFER this end took, with the NOTIFY that
    /// says so: `status` in its body and `state` — terminated, and why — in
    /// its `Subscription-State`. The call the REFER placed goes on, and stops
    /// reporting here.
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

/// `active`, with the `expires` RFC 6665 §4.2.2 makes compulsory on it: "the
/// notifier MUST also include ... an "expires" parameter that indicates the
/// time remaining on the subscription". Never zero, which would read as over.
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
                // a dialog that is not a call is not one this handler has
                // anything to say about, and swallowing the request here would
                // leave the far end retransmitting into silence for
                // thirty-two seconds. Subscriptions have dialogs too now
                let Some(call) = self.by_dialog.get(&dialog).copied() else {
                    return Some(event);
                };
                let request = request.clone();
                self.on_refer(call, transaction, &request, now);
                None
            }
            // The `Event` decides this, not the method. RFC 6665 §8.2.1 makes
            // the header mandatory on every NOTIFY, and a dialog carries as
            // many event packages as anybody subscribed to: a phone with a
            // busy lamp on this line sends `dialog`, a mailbox sends
            // `message-summary`, and answering either as though it reported a
            // transfer swallows it whole -- 200 already sent, body dropped,
            // and the subscriber none the wiser.
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Notify)
                && package_is(&request.as_raw(), REFER) =>
            {
                // and likewise: a `refer` notification in a dialog that is not
                // a call belongs to nobody here, and the subscription machine
                // below is what says so with a 481
                let Some(call) = self.by_dialog.get(&dialog).copied() else {
                    return Some(event);
                };
                // §2.4.4: "REFER is the only mechanism that can create a
                // subscription to event refer". So one exists here only if a
                // REFER of this end's made it, and a notification that
                // matches none of those is not a report on anything — it is
                // the far end of an ordinary call driving a transfer nobody
                // asked for, and the last NOTIFY of one hangs the call up.
                // Left for the subscription machine below, which gives RFC
                // 6665 §4.1.3's answer to a notification against nothing.
                if !self.reports_on_our_refer(call, &request.as_raw()) {
                    return Some(event);
                }
                let request = request.clone();
                self.on_notify(call, transaction, &request, now);
                None
            }
            // A REFER outside any dialog, which nothing here takes unless the
            // application said it would: left alone, it is refused further
            // down with what `admission` answers it
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
            // §2.4.4: "If a SUBSCRIBE request for event refer is received
            // for a subscription that does not already exist, it MUST be
            // rejected with a 403." Outside a dialog none can exist, since
            // only a REFER opens one. One whose `To` names a dialog this end
            // no longer has is §12.2.2's 481 like any other request
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
            // And inside one, the subscriber refreshing or ending the one a
            // REFER this end took opened (§2.4.4: it "may extend its
            // subscription using the subscription refresh mechanisms")
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
            // Everything else goes on. RFC 6665 §4.1.3's answer for a
            // notification nobody subscribed to -- "it MUST return a 481
            // (Subscription does not exist) response" -- used to be given
            // here, because this was the only thing in the crate that knew
            // what a subscription was. It belongs to the subscription machine
            // now: this handler knows about one event package inside a call,
            // and a 481 written from here would be refusing on behalf of every
            // subscription it cannot see.
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
        // §2.4.1: "A REFER request MUST contain exactly one Refer-To header
        // field value", and §2.4.2 answers anything else with a 400
        let Some(wanted) = refer_to(&raw) else {
            let Ok(bad) = StatusCode::new(400) else {
                return;
            };
            self.endpoint
                .respond(transaction, &OutgoingResponse::new(bad), now)
                .ok();
            return;
        };
        // One at a time. A dialog may carry a second REFER before the first
        // has finished — §2.4.6's whole reason for the `id` parameter is that
        // it can — but this end keeps one `Referred` per call, so taking the
        // second would throw away the first's transaction, the call it placed
        // and the `id` its own NOTIFYs are tagged with, and the transferor
        // would be told about the wrong one. 491 is the honest answer: the
        // request is not refused on its merits, it is pending behind another.
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
        // §2.4.6: a NOTIFY that carries an `id` is reporting on the REFER
        // whose `CSeq` that is, so one naming another REFER is not this
        // subscription's news. One with no `id` at all is: §2.4.6 makes the
        // parameter optional for the first REFER in a dialog, and there is
        // never more than one open here. An `id` is not read as a refusal
        // when this end does not know its own number to compare.
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
        // §4.1.3 of RFC 6665 has an answer go out before anything else, and
        // never after asking a person
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
            .ok();
        let raw = request.as_raw();
        let over = raw
            .header(HeaderName::SubscriptionState)
            .is_some_and(|value| Params::split(value).0.eq_ignore_ascii_case(b"terminated"));
        // a terminated subscription is over whatever its body says: §2.4.4
        // lets the far end end it with the very first NOTIFY, which §2.4.5
        // has carry a 100 while the reference is pending, and RFC 6665
        // §4.1.3 leaves nothing after it to free the seat later
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
        // the transfer worked, so this end is not in the call any more. A
        // failed one leaves it exactly where it was, which is the point of
        // waiting for the answer rather than hanging up when the REFER went
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
            // §2.4.6: "A SUBSCRIBE sent to refresh or terminate this
            // subscription MUST contain this id parameter", so one naming
            // another REFER is not about this one
            .filter(|(_, referred)| {
                named.is_none_or(|named| referred.id.is_none_or(|ours| ours == named))
            });
        let Some((owner, referred)) = live else {
            // §2.4.4's 403, for a subscription that does not exist: "REFER
            // is the only mechanism that can create a subscription to event
            // refer"
            self.endpoint
                .respond(transaction, &OutgoingResponse::new(FORBIDDEN), now)
                .ok();
            return;
        };
        // RFC 6665 §4.2.1.4: "the server MAY shorten the amount of time until
        // expiration but MUST NOT increase it". With no `Expires` at all the
        // package's default applies, and `refer` defines none but the one
        // the first NOTIFY named
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
            // §4.1.2.3: "a successful unsubscription will also trigger a
            // final NOTIFY request", and §4.2.1.4 gives it "a reason code of
            // timeout". The call the REFER placed is not touched: RFC 3515
            // §2.4.4 says ending the subscription "is not an indication that
            // the referenced request should be withdrawn"
            self.close_subscription(owner, referred.last, TIMED_OUT, now);
            return;
        }
        // §4.2.1.2: on "accepting or refreshing a subscription, notifiers
        // MUST send a NOTIFY request immediately", with the whole state,
        // since §2.4.5 has the package carry no deltas
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
        // §6.1: "Only a single Replaces header field value may be present in
        // a SIP request", and §3 answers more than one with "the UAS MUST
        // reject the request with a 400 Bad Request response". Which of two
        // values the check below reads is not the sender's to choose, and an
        // upstream proxy may well have read the other one.
        match request.field_values(HeaderName::Replaces).count() {
            0 => return Ok(None),
            1 => (),
            _ => return Err(StatusCode::new(400).unwrap_or(StatusCode::SERVER_ERROR)),
        }
        let Some(value) = request.header(HeaderName::Replaces) else {
            return Ok(None);
        };
        let (call_id, params) = Params::split(value);
        // §6.1: "A Replaces header field MUST contain exactly one to-tag and
        // exactly one from-tag, as they are required for unique dialog
        // matching"
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
        // §3: "the UA MUST verify that the initiator of the new INVITE is
        // authorized to replace the matched dialog", and §8: "invitations
        // with the Replaces header MUST only be accepted if the peer
        // requesting replacement has been properly authenticated". This
        // stack answers challenges and issues none, so there is no
        // authenticated identity to compare and `From` or `Referred-By`
        // would only be comparing strings the sender wrote. What is left is
        // the one thing the sender did not write: where the bytes came from.
        //
        // That is the default and not the whole rule, because it is wrong in
        // a deployment that exists: an attended transfer whose transferee
        // reaches this end directly rather than through the line's proxy
        // arrives from an address no call here was placed to. `on_replaces`
        // is where an application that knows its own deployment says so, and
        // where one that knows the flow is not enough says that instead. With
        // no policy set, and with one that does not override it, this is
        // byte-for-byte the comparison above.
        //
        // It runs above the state arms on purpose. What state one of this
        // end's calls is in is not something a stranger who guessed three
        // identifiers gets to read off the status code.
        let named = Replacing::new(handle, self.guard.source() == peer);
        match self.guard.screen_replaces(invite, named) {
            Screening::Take => (),
            Screening::Refuse(status) => return Err(status),
        }
        match state {
            CallState::Terminating | CallState::Terminated => {
                // §3: "the UA SHOULD decline the request with a 603 Declined"
                Err(StatusCode::new(603).unwrap_or(StatusCode::BUSY_HERE))
            }
            CallState::Confirmed | CallState::Consulting if early_only => {
                // §3: "If the flag is present, the UA rejects the request with
                // a 486 Busy response."
                Err(StatusCode::BUSY_HERE)
            }
            CallState::Confirmed | CallState::Consulting => Ok(Some(handle)),
            // §3: an early dialog this end did not originate cannot be
            // replaced by this end at all
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
        // a confirmed dialog goes with a BYE and an early one of ours with a
        // CANCEL; hanging up is the one call that already knows which
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
    // The Replaces is unescaped to go onto a header line of the INVITE, so an
    // escape is how a control byte would get there: a NUL, or a CRLF and a
    // header of the sender's choosing. RFC 3891 §6.1 makes the value a Call-ID
    // and token parameters, which hold none, and RFC 3261 §19.1.5 treats a
    // URI that forms an invalid request as invalid. The whole Refer-To is
    // refused rather than just the Replaces, which would quietly turn an
    // attended transfer into a blind one.
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
/// `refer-sub-value = "true" / "false"`, with `*(SEMI exten)` after it. Only
/// one field, and only the value `false`, asks for anything: §4 has a REFER
/// that did not ask handled "as in the default case", and a field this end
/// cannot read is the same as one that did not ask.
fn asks_for_no_subscription(request: &RawMessage<'_>) -> bool {
    let mut values = request.field_values(REFER_SUB);
    let (Some(only), None) = (values.next(), values.next()) else {
        return false;
    };
    Params::split(only).0.eq_ignore_ascii_case(b"false")
}

/// Whether a request outside any dialog names one anyway, with a tag in its
/// `To` (RFC 3261 §12.2.2): one that does is a dialog this end does not have,
/// and is answered 481 whatever its method.
pub(crate) fn names_a_dialog(request: &RawMessage<'_>) -> bool {
    request.to().is_ok_and(|to| to.tag().is_some())
}

/// The `Referred-By` to carry on to the INVITE this REFER asks for (RFC 3892
/// §2.2).
///
/// Exactly one or none: §2.1 is "A REFER request MUST NOT contain more than
/// one Referred-By header field value", and which of two to pass on is not
/// something to guess at — a second value is how a sender would try to make
/// the far end read one field while this end acted on the other. The REFER
/// itself is not refused over it, because the field is not what the transfer
/// turns on here.
fn referred_by(request: &RawMessage<'_>) -> Option<Box<[u8]>> {
    let mut values = request.field_values(HeaderName::ReferredBy);
    let only = values.next()?;
    if values.next().is_some() {
        return None;
    }
    // Unfolded here, because the parser keeps a fold's interior CRLF on
    // purpose and unfolding belongs to whoever consumes the value. This one
    // is copied onto a request we then send, and a bare CRLF in the middle of
    // a header value is a second header field to whatever reads it next.
    Some(Box::from(unfold(only).as_ref()))
}

/// Whether a NOTIFY reports on the named event package (RFC 6665 §8.2.1).
///
/// The value is a package name followed by parameters, and the name is
/// case-insensitive; `id` in particular rides on it wherever one dialog holds
/// two subscriptions to the same package. A NOTIFY with no `Event` at all is
/// not one this layer will claim: §8.2.1 requires it, and guessing on behalf
/// of a peer that omitted it is how somebody else's notification gets eaten.
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
        // 2.4.5: "The body of a NOTIFY MUST begin with a SIP Response
        // Status-Line"
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
