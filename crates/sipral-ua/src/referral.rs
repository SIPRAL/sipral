// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A REFER outside any dialog: somebody asking this end to place a call it is
//! not already in (RFC 3515).
//!
//! RFC 3515 §4.1 is written around exactly this case — "this particular
//! REFER occurs outside a session (there is no To tag in the REFER
//! request)" — and it is what click-to-dial is: a CRM, a switchboard or an
//! operator console tells a phone to ring somebody, and the phone does it
//! from its own line. §2.4.2 asks the UA to "request approval from the user
//! to proceed (this request could be satisfied with an interactive query or
//! through accessing configured policy)", so every one is the application's
//! to take or refuse, and none is taken on its behalf.
//!
//! **Off unless the application turns it on, and a decision per request when
//! it does.** A peer that can make a phone dial is a peer that can make it
//! dial a premium-rate number at three in the morning, which is toll fraud
//! with this stack's name on the call records. This stack issues no
//! challenges, so it has no authenticated peer to hold the request to, and
//! `Referred-By` is a header field the sender wrote. With
//! [`UserAgent::allow_referrals`] left alone a REFER outside a dialog is
//! refused 403 before anything reads it — "the server understood the
//! request, but is refusing to fulfill it" (RFC 3261 §21.4.4), which is this
//! end's answer rather than 405's claim that it does not do REFER (it does,
//! inside a call), 481's that it names a dialog (it names none) or 603's
//! that a person declined. Turned on, it meets the same screening an INVITE
//! does before anybody hears of it ([`crate::Screen`] and the rate limit
//! per source, [`crate::screening`]), and what survives is
//! [`UaEvent::ReferralRequested`], answered with
//! [`UserAgent::accept_transfer`] or [`UserAgent::reject_transfer`].
//!
//! **The referral is a [`CallHandle`] of its own, and not a call.** It is
//! drawn from the same count every call's handle is, so it never names a
//! call and a call never names it, and it is taken and refused through the
//! two methods an in-dialog REFER already is — which is what lets a layer
//! above place the call it asks for with media of its own exactly as it does
//! for a transfer. What it is not is a call: [`UserAgent::call_state`] knows
//! nothing of it, and nothing but those two methods takes it. It names
//! something from [`UaEvent::ReferralRequested`] until it is answered, or
//! until [`UaEvent::ReferralLapsed`] says nobody answered it in time.
//!
//! **Taking one is taking a transfer.** The 202 carries the tag that makes
//! the dialog of the implicit subscription (§2.4.4: the NOTIFYs match the
//! REFER "as they would if the REFER had been a SUBSCRIBE request"), and
//! from there it is [`crate::transfer`]'s machinery unchanged: a NOTIFY
//! with §2.4.5's 100 at once, the call placed with the REFER's own
//! `Replaces` and `Referred-By` and never the caller's, one NOTIFY per
//! provisional and the last one `terminated` with the final answer. RFC
//! 4488's `Refer-Sub: false` is granted here too: no dialog, no NOTIFY.
//!
//! **Nothing waits past the transaction.** §2.4.2 has the answer go "before
//! the REFER transaction expires", so one the application leaves alone for
//! 64·T1 is given up: the endpoint has answered it 408 by then, and
//! [`UaEvent::ReferralLapsed`] tells the application its handle is spent.
//! And there is a ceiling on how many are held at once, since the table is
//! one anybody on the internet can write to.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use sipral_core::endpoint::OutgoingResponse;
use sipral_core::msg::{HeaderName, OwnedMessage, StatusCode, UriScheme};
use sipral_core::transaction::{DialogId, NonInviteServer, TransactionId};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::call::{CallHandle, OutgoingExtras};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::registration::dialog_contact;
use crate::transfer::{FORBIDDEN, REFER_SUB, ReferTo, Referred, refer_to};

/// How many referrals are held at once, waiting or running.
///
/// A person is asked about one at a time, and a switchboard that has sixteen
/// of its own clicks outstanding at one phone has lost track of them. It is a
/// fixed cost for the reason [`crate::screening`]'s table of sources is: past
/// it the next is refused, rather than a table a stranger can grow.
const HELD: usize = 16;

/// What one past [`HELD`] is refused with: RFC 3261 §21.4.24's "the callee's
/// end system was contacted successfully but the callee is currently not
/// willing or able to take additional calls".
const BUSY: StatusCode = StatusCode::BUSY_HERE;

/// RFC 3261 §8.2.2.1: "If the Request-URI does not identify an address that
/// the UAS is willing to accept requests for, it SHOULD reject the request
/// with a 404 (Not Found) response." A referral that names no account here
/// has no line to place its call from.
const NOT_FOUND: StatusCode = match StatusCode::new(404) {
    Ok(status) => status,
    // 404 is in range, so this arm never runs; it exists because `new` is
    // fallible and nothing in this crate panics to say otherwise
    Err(_) => StatusCode::BAD_REQUEST,
};

/// The referrals this agent holds, and whether it takes any at all.
#[derive(Debug, Default)]
pub(crate) struct Referrals {
    /// Whether a REFER outside a dialog reaches the application. Off by
    /// default: see the note at the top of this module.
    pub(crate) allowed: bool,
    /// Every one waiting for the application or reporting on the call it
    /// placed, by its handle.
    pub(crate) held: HashMap<CallHandle, Referral>,
}

/// One REFER outside a dialog.
#[derive(Debug)]
pub(crate) struct Referral {
    /// The line it arrived for, which the call it asks for is placed from.
    pub(crate) account: AccountId,
    /// What it asked for, until the application answers.
    pub(crate) asked: Option<ReferTo>,
    /// The notifier's half of the subscription, as a transfer has it.
    pub(crate) notifier: Referred,
    /// The dialog the 202 made, once it has gone and unless `Refer-Sub:
    /// false` was granted.
    pub(crate) dialog: Option<DialogId>,
    /// When one nobody answered is given up: the REFER's own transaction
    /// is answered 408 by the endpoint at the same moment.
    pub(crate) answer_by: Instant,
}

impl UserAgent {
    /// Whether a REFER outside any dialog is handed to the application
    /// ([`UaEvent::ReferralRequested`]) rather than refused 403.
    ///
    /// Off by default, and on only when the application says so, because a
    /// peer that can make a phone dial is a toll-fraud vector: see
    /// [`crate::referral`]. Turned on, each one is still screened as an
    /// INVITE is and is still the application's to take or refuse.
    /// Turning it off again refuses what arrives from then on and leaves
    /// alone the ones already handed over.
    pub const fn allow_referrals(&mut self, allowed: bool) {
        self.referrals.allowed = allowed;
    }

    /// Whether [`UserAgent::allow_referrals`] is on.
    #[must_use]
    pub const fn allows_referrals(&self) -> bool {
        self.referrals.allowed
    }

    /// Whether `referral` names a REFER outside a dialog that is still
    /// waiting to be taken or refused.
    ///
    /// `false` once either has been done, once it lapsed, and for a handle
    /// that names a call or nothing.
    #[must_use]
    pub fn referral_waiting(&self, referral: CallHandle) -> bool {
        self.referrals
            .held
            .get(&referral)
            .is_some_and(|held| held.notifier.transaction.is_some())
    }
}

// -- what arrives -------------------------------------------------------------

impl UserAgent {
    /// A REFER outside any dialog, with [`UserAgent::allow_referrals`] on.
    pub(crate) fn on_referral(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        // the same floor and the same policy an INVITE meets, and before
        // anything else reads it: a REFER here is a call this end would
        // place, which is what both of them exist to ration
        if let Some(refused) = self.guard.decide(request, now) {
            self.refuse_referral(transaction, refused, now);
            return;
        }
        let raw = request.as_raw();
        // §2.4.2: "An agent responding to a REFER method MUST return a 400
        // (Bad Request) if the request contained zero or more than one
        // Refer-To header field values"; and §2: "REFER creates a dialog ...
        // hence MUST contain a single Contact header field value", without
        // which there is nowhere to send the NOTIFYs
        let wanted = refer_to(&raw);
        let Some(wanted) = wanted.filter(|_| raw.header_count(HeaderName::Contact) == 1) else {
            self.refuse_referral(transaction, StatusCode::BAD_REQUEST, now);
            return;
        };
        // §2.4.2: "A UA not capable of accessing non-SIP URIs SHOULD NOT
        // accept REFER requests to them", and a call is all this end can
        // place
        if matches!(wanted.target.scheme(), UriScheme::Other(_)) {
            self.refuse_referral(transaction, FORBIDDEN, now);
            return;
        }
        let Some(account) = self.line_for(&raw) else {
            self.refuse_referral(transaction, NOT_FOUND, now);
            return;
        };
        if self.referrals.held.len() >= HELD {
            self.refuse_referral(transaction, BUSY, now);
            return;
        }
        let referral = CallHandle(self.next_call);
        self.next_call = self.next_call.wrapping_add(1);
        let id = raw.cseq().ok().map(|cseq| cseq.seq);
        self.referrals.held.insert(
            referral,
            Referral {
                account,
                asked: Some(wanted.clone()),
                notifier: Referred::asked(transaction, id),
                dialog: None,
                answer_by: now + self.timer_n,
            },
        );
        self.events.push_back(UaEvent::ReferralRequested {
            referral,
            account,
            target: wanted.target,
            attended: wanted.replaces.is_some(),
            referred_by: wanted.referred_by,
            request: request.clone(),
        });
    }

    fn refuse_referral(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        status: StatusCode,
        now: Instant,
    ) {
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(status), now)
            .ok();
    }

    /// The referral whose subscription lives in `dialog`, if one does.
    pub(crate) fn referral_in(&self, dialog: DialogId) -> Option<CallHandle> {
        self.referrals
            .held
            .iter()
            .find(|(_, held)| held.dialog == Some(dialog))
            .map(|(handle, _)| *handle)
    }

    /// The `Contact` a referral's 202 and NOTIFYs carry: the account's, as
    /// every request of its line names it (RFC 5627 §4.4 where it has a
    /// GRUU).
    pub(crate) fn referral_contact(&self, account: AccountId, now: Instant) -> Box<[u8]> {
        self.accounts
            .get(&account)
            .map(|config| dialog_contact(config, self.learned_for(account, None, now), false))
            .unwrap_or_default()
    }
}

// -- what the application says ------------------------------------------------

impl UserAgent {
    /// [`UserAgent::accept_transfer`], for a referral: the header fields in
    /// `extra` have already been checked there.
    pub(crate) fn accept_referral(
        &mut self,
        referral: CallHandle,
        offer: Option<Arc<[u8]>>,
        extra: OutgoingExtras<'_>,
        now: Instant,
    ) -> Result<CallHandle, UaError> {
        let (transaction, wanted, account) = {
            let held = self
                .referrals
                .held
                .get(&referral)
                .ok_or(UaError::NoSuchCall)?;
            let transaction = held.notifier.transaction.ok_or(UaError::NoSuchCall)?;
            let wanted = held.asked.clone().ok_or(UaError::NoSuchCall)?;
            (transaction, wanted, held.account)
        };
        // the line it arrived for is the one it calls from, and one removed
        // since has no `Contact` to answer with: refused before anything is
        // sent, so the referral is still there to refuse
        if !self.accounts.contains_key(&account) {
            return Err(UaError::NoSuchAccount);
        }
        // RFC 4488 §4: granting `Refer-Sub: false` means "no new dialog is
        // created if this REFER was issued outside any existing dialog".
        // Otherwise the dialog is opened before the answer, whose tag it is
        // built around, goes: on a reliable transport the answer retires the
        // transaction the dialog is read from
        let dialog = if wanted.quiet {
            None
        } else {
            self.endpoint.open_dialog_answering(transaction)
        };
        if dialog.is_none() && !wanted.quiet {
            // a REFER whose dialog cannot be made, from a `Contact` that
            // arrived and would not parse, has nowhere for its NOTIFYs to go
            self.refuse_referral(transaction, StatusCode::BAD_REQUEST, now);
            self.referrals.held.remove(&referral);
            return Err(UaError::NoSuchCall);
        }
        // §2.4.2's 202, with the `Contact` §12.1.1 has a response that makes
        // a dialog carry, and RFC 4488 §4's `Refer-Sub: false` back when that
        // was asked for: "it MUST insert the "Refer-Sub" header field set to
        // "false" in the 2xx response"
        let contact = self.referral_contact(account, now);
        let mut response = OutgoingResponse::new(StatusCode::ACCEPTED).contact(&contact);
        if wanted.quiet {
            response = response.header(REFER_SUB, b"false");
        }
        if let Err(error) = self.endpoint.respond(transaction, &response, now) {
            // the transaction is gone -- the endpoint answered it already, or
            // its transport went -- so there is no referral left to take
            if let Some(dialog) = dialog {
                self.endpoint.close_dialog(dialog);
            }
            self.referrals.held.remove(&referral);
            return Err(error.into());
        }
        if let Some(held) = self.referrals.held.get_mut(&referral) {
            held.asked = None;
            held.dialog = dialog;
        }
        self.subscribed(referral, wanted.quiet, now);
        self.place_referred(referral, account, &wanted, offer, &extra, now)
    }

    /// [`UserAgent::reject_transfer`], for a referral.
    pub(crate) fn reject_referral(
        &mut self,
        referral: CallHandle,
        status: StatusCode,
        now: Instant,
    ) -> Result<(), UaError> {
        let transaction = self
            .referrals
            .held
            .get(&referral)
            .and_then(|held| held.notifier.transaction)
            .ok_or(UaError::NoSuchCall)?;
        self.referrals.held.remove(&referral);
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(status), now)?;
        self.drain(now);
        Ok(())
    }

    /// Let a referral go once there is nothing left for it to say: its
    /// subscription is over, or was never opened.
    pub(crate) fn release_finished_referral(&mut self, owner: CallHandle) {
        let over = self
            .referrals
            .held
            .get(&owner)
            .is_some_and(|held| held.notifier.transaction.is_none() && held.notifier.finished);
        if !over {
            return;
        }
        if let Some(held) = self.referrals.held.remove(&owner)
            && let Some(dialog) = held.dialog
        {
            // RFC 6665 §4.4.1: "the destruction of a subscription results in
            // the termination of its associated dialog", and nothing on the
            // wire says so
            self.endpoint.close_dialog(dialog);
        }
    }
}

// -- time ---------------------------------------------------------------------

impl UserAgent {
    /// When the next referral nobody answered is given up.
    pub(crate) fn referral_deadline(&self) -> Option<Instant> {
        self.referrals
            .held
            .values()
            .filter(|held| held.notifier.transaction.is_some())
            .map(|held| held.answer_by)
            .min()
    }

    /// Give up the ones nobody answered before their transaction ran out
    /// (§2.4.2), and say so.
    pub(crate) fn fire_referral_timers(&mut self, now: Instant) {
        let lapsed: Vec<(CallHandle, TransactionId<NonInviteServer>)> = self
            .referrals
            .held
            .iter()
            .filter(|(_, held)| held.answer_by <= now)
            .filter_map(|(handle, held)| Some((*handle, held.notifier.transaction?)))
            .collect();
        for (referral, transaction) in lapsed {
            self.referrals.held.remove(&referral);
            // the endpoint's own 408 went at this same instant, since its
            // deadline and this one are the same 64·T1 from the same
            // arrival; this one is for the rare transaction it missed
            self.refuse_referral(transaction, StatusCode::REQUEST_TIMEOUT, now);
            self.events.push_back(UaEvent::ReferralLapsed {
                referral,
                status: StatusCode::REQUEST_TIMEOUT,
            });
        }
    }
}
