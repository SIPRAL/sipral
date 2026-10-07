// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A REFER outside any dialog: somebody asking this end to place a call it is
//! not already in (RFC 3515).
//!
//! This is click-to-dial: a CRM or operator console tells a phone to ring
//! somebody from its own line (RFC 3515 §4.1, a REFER with no To tag).
//! §2.4.2 asks the UA to get the user's approval, so each one is the
//! application's to take or refuse.
//!
//! **Off unless the application turns it on.** A peer that can make a phone
//! dial can make it dial a premium-rate number at 3 a.m.: toll fraud. This
//! stack issues no challenges, and `Referred-By` is whatever the sender
//! wrote. With [`UserAgent::allow_referrals`] off, the REFER is refused 403
//! before anything reads it (RFC 3261 §21.4.4; not 405, since REFER works in
//! a call, not 481, since it names no dialog). On, it meets the same
//! screening as an INVITE ([`crate::Screen`] and the per-source rate limit),
//! and what passes becomes [`UaEvent::ReferralRequested`], answered with
//! [`UserAgent::accept_transfer`] or [`UserAgent::reject_transfer`].
//!
//! **The referral is a [`CallHandle`], not a call.** It comes from the same
//! counter as call handles, so the two never collide, and the transfer
//! methods take it, so a layer above places the call with its own media as
//! for a transfer. [`UserAgent::call_state`] knows nothing of it. It is
//! valid from [`UaEvent::ReferralRequested`] until answered, or until
//! [`UaEvent::ReferralLapsed`].
//!
//! **Taking one is taking a transfer.** The 202 carries the tag of the
//! implicit subscription's dialog (§2.4.4), and from there the in-dialog
//! transfer machinery runs unchanged: a NOTIFY with 100 at once (§2.4.5),
//! the call placed with the REFER's `Replaces` and `Referred-By`, one NOTIFY
//! per provisional, the last one `terminated`. RFC 4488's `Refer-Sub: false`
//! is granted: no dialog, no NOTIFY.
//!
//! **Nothing waits past the transaction.** One left unanswered for 64·T1 is
//! given up (§2.4.2): the endpoint has sent 408, and
//! [`UaEvent::ReferralLapsed`] says the handle is spent. The number held at
//! once is capped, since anybody on the internet can fill the table.

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

/// How many referrals are held at once, waiting or running. Past it the
/// next is refused, so a stranger cannot grow the table.
const HELD: usize = 16;

/// What one past [`HELD`] is refused with (RFC 3261 §21.4.24).
const BUSY: StatusCode = StatusCode::BUSY_HERE;

/// A referral naming no account here has no line to call from (RFC 3261
/// §8.2.2.1).
const NOT_FOUND: StatusCode = match StatusCode::new(404) {
    Ok(status) => status,
    // unreachable, but `new` is fallible and this crate does not panic
    Err(_) => StatusCode::BAD_REQUEST,
};

/// The referrals this agent holds, and whether it takes any at all.
#[derive(Debug, Default)]
pub(crate) struct Referrals {
    /// Whether a REFER outside a dialog reaches the application.
    pub(crate) allowed: bool,
    /// Every one waiting or reporting on its call, by handle.
    pub(crate) held: HashMap<CallHandle, Referral>,
}

/// One REFER outside a dialog.
#[derive(Debug)]
pub(crate) struct Referral {
    /// The line it arrived for, and calls from.
    pub(crate) account: AccountId,
    /// What it asked for, until the application answers.
    pub(crate) asked: Option<ReferTo>,
    pub(crate) notifier: Referred,
    /// The dialog the 202 made, unless `Refer-Sub: false` was granted.
    pub(crate) dialog: Option<DialogId>,
    /// When an unanswered one is given up; the endpoint sends 408 then.
    pub(crate) answer_by: Instant,
}

impl UserAgent {
    /// Whether a REFER outside any dialog is handed to the application
    /// ([`UaEvent::ReferralRequested`]) rather than refused 403.
    ///
    /// Off by default: a peer that can make a phone dial is a toll-fraud
    /// vector (see [`crate::referral`]). On, each one is still screened as
    /// an INVITE is. Turning it off refuses new ones and leaves alone those
    /// already handed over.
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
        // screened like an INVITE: it is a call this end would place
        if let Some(refused) = self.guard.decide(request, now) {
            self.refuse_referral(transaction, refused, now);
            return;
        }
        let raw = request.as_raw();
        // §2.4.2: exactly one Refer-To or 400; §2: exactly one Contact,
        // where the NOTIFYs go
        let wanted = refer_to(&raw);
        let Some(wanted) = wanted.filter(|_| raw.header_count(HeaderName::Contact) == 1) else {
            self.refuse_referral(transaction, StatusCode::BAD_REQUEST, now);
            return;
        };
        // §2.4.2: no REFER to a non-SIP URI
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
        // a removed line has no `Contact`; fail before sending anything so
        // the referral can still be refused
        if !self.accounts.contains_key(&account) {
            return Err(UaError::NoSuchAccount);
        }
        // RFC 4488 §4: `Refer-Sub: false` makes no dialog. Otherwise open it
        // before the 202: on a reliable transport the answer retires the
        // transaction the dialog is read from
        let dialog = if wanted.quiet {
            None
        } else {
            self.endpoint.open_dialog_answering(transaction)
        };
        if dialog.is_none() && !wanted.quiet {
            // unparsable `Contact`: nowhere for the NOTIFYs to go
            self.refuse_referral(transaction, StatusCode::BAD_REQUEST, now);
            self.referrals.held.remove(&referral);
            return Err(UaError::NoSuchCall);
        }
        // §2.4.2's 202 with a `Contact` (§12.1.1), and `Refer-Sub: false`
        // echoed when granted (RFC 4488 §4)
        let contact = self.referral_contact(account, now);
        let mut response = OutgoingResponse::new(StatusCode::ACCEPTED).contact(&contact);
        if wanted.quiet {
            response = response.header(REFER_SUB, b"false");
        }
        if let Err(error) = self.endpoint.respond(transaction, &response, now) {
            // the transaction is gone: nothing left to take
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
            // RFC 6665 §4.4.1: the dialog ends with the subscription,
            // silently
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
            // the endpoint's 408 normally went at the same 64·T1; this
            // covers a transaction it missed
            self.refuse_referral(transaction, StatusCode::REQUEST_TIMEOUT, now);
            self.events.push_back(UaEvent::ReferralLapsed {
                referral,
                status: StatusCode::REQUEST_TIMEOUT,
            });
        }
    }
}
