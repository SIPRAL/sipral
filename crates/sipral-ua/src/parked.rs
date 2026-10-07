// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What this layer sends inside a dialog by itself, when RFC 3261 §18.1.1
//! will not let it out over a datagram.
//!
//! An application request gets [`UaError::Send`] with `NeedsStreamTransport`
//! and can retry once the stream is bound. What this layer sends on its own
//! (ACK, PRACK, transfer NOTIFY, BYE, hangup, 491 retry, subscription
//! refresh) has nobody to retry it, so it waits here and goes when a
//! transport is bound. A dialog that ends drops what waits in it.
//!
//! The session timer retries its own refresh.

use std::time::Instant;

use sipral_core::endpoint::{AckError, OutgoingInDialogRequest, PrackError, SendError};
use sipral_core::msg::Method;
use sipral_core::transaction::{
    AnyTransactionId, DialogId, InviteClient, ProvisionalResponseId, TransactionId,
};

use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::error::UaError;
use crate::subscription::SubscriptionHandle;

/// One request held back for want of a stream.
#[derive(Debug)]
pub(crate) enum Parked {
    /// The ACK to the 2xx that confirmed a call placed with an offer.
    Ack { dialog: DialogId },
    /// The ACK to the 2xx that took a session change this end offered.
    ReinviteAck {
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
    },
    /// A PRACK with nothing to carry (RFC 3262 §4). The handle names the
    /// dialog.
    Prack {
        call: CallHandle,
        provisional: ProvisionalResponseId,
    },
    /// A NOTIFY about a transfer (RFC 3515 §2.4.4), whole, with the `Event`
    /// value that says which REFER it reports on (§2.4.6).
    Notify {
        call: CallHandle,
        dialog: DialogId,
        event: Vec<u8>,
        request: OutgoingInDialogRequest,
    },
    /// A BYE in a dialog whose call this layer has already reported over.
    Bye { dialog: DialogId },
    /// The hangup of a call this layer decided to end.
    Hangup { call: CallHandle, dialog: DialogId },
    /// A session change offered again after a 491 (§14.1).
    Offer { call: CallHandle, dialog: DialogId },
    /// A subscription's refresh (RFC 6665 §4.1.2.2).
    Refresh {
        subscription: SubscriptionHandle,
        dialog: DialogId,
    },
}

impl Parked {
    /// The dialog it would be sent in.
    const fn dialog(&self) -> DialogId {
        match *self {
            Self::Ack { dialog }
            | Self::ReinviteAck { dialog, .. }
            | Self::Notify { dialog, .. }
            | Self::Bye { dialog }
            | Self::Hangup { dialog, .. }
            | Self::Offer { dialog, .. }
            | Self::Refresh { dialog, .. } => dialog,
            Self::Prack { provisional, .. } => provisional.dialog(),
        }
    }

    /// Whether the two are the same request, so it waits once. Two NOTIFYs
    /// for one REFER count as one: each body is a complete status (RFC 3515
    /// §2.4.5). Another REFER is another subscription (§2.4.6).
    fn repeats(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Notify {
                    dialog: one,
                    event: this,
                    ..
                },
                Self::Notify {
                    dialog: two,
                    event: that,
                    ..
                },
            ) => one == two && this == that,
            (Self::Ack { dialog: one }, Self::Ack { dialog: two })
            | (Self::Bye { dialog: one }, Self::Bye { dialog: two }) => one == two,
            (Self::ReinviteAck { invite: one, .. }, Self::ReinviteAck { invite: two, .. }) => {
                one == two
            }
            (
                Self::Prack {
                    provisional: one, ..
                },
                Self::Prack {
                    provisional: two, ..
                },
            ) => one == two,
            (Self::Hangup { call: one, .. }, Self::Hangup { call: two, .. })
            | (Self::Offer { call: one, .. }, Self::Offer { call: two, .. }) => one == two,
            (
                Self::Refresh {
                    subscription: one, ..
                },
                Self::Refresh {
                    subscription: two, ..
                },
            ) => one == two,
            _ => false,
        }
    }
}

/// Whether a send was refused only because §18.1.1 wants a stream, which the
/// endpoint has already asked the application for.
pub(crate) const fn needs_a_stream(error: &SendError) -> bool {
    matches!(*error, SendError::NeedsStreamTransport)
}

/// The same, for what this layer's own calls return.
pub(crate) const fn call_needs_a_stream(error: &UaError) -> bool {
    matches!(*error, UaError::Send(SendError::NeedsStreamTransport))
}

const fn ack_needs_a_stream(error: &AckError) -> bool {
    matches!(*error, AckError::Build(SendError::NeedsStreamTransport))
}

const fn prack_needs_a_stream(error: &PrackError) -> bool {
    matches!(*error, PrackError::Send(SendError::NeedsStreamTransport))
}

impl UserAgent {
    /// Hold one back until a transport is bound, once.
    ///
    /// A newer transfer report replaces the waiting one.
    pub(crate) fn park(&mut self, parked: Parked) {
        if let Some(held) = self.parked.iter_mut().find(|held| held.repeats(&parked)) {
            if matches!(*held, Parked::Notify { .. }) {
                *held = parked;
            }
            return;
        }
        self.parked.push(parked);
    }

    /// Whether the ACK in this dialog is waiting for a stream.
    pub(crate) fn ack_parked_in(&self, dialog: DialogId) -> bool {
        self.parked.iter().any(|held| {
            matches!(
                *held,
                Parked::Ack { dialog: waiting } if waiting == dialog
            )
        })
    }

    /// A dialog has ended, and nothing waiting to be sent in it will be.
    pub(crate) fn forget_parked_in(&mut self, dialog: DialogId) {
        self.parked.retain(|held| held.dialog() != dialog);
    }

    /// Send what §18.1.1 held back, now that a transport has been bound.
    ///
    /// Everything is tried; the endpoint decides which stream each needs.
    /// What still needs a stream waits again; any other refusal drops it.
    pub(crate) fn resume_parked_sends(&mut self, now: Instant) {
        for parked in core::mem::take(&mut self.parked) {
            match parked {
                Parked::Ack { dialog } => {
                    self.ack_by_itself(dialog, now);
                }
                Parked::ReinviteAck { invite, dialog } => {
                    self.ack_reinvite_by_itself(invite, dialog, now);
                }
                Parked::Prack { call, provisional } => {
                    self.prack_by_itself(call, provisional, now);
                }
                Parked::Notify {
                    call,
                    dialog,
                    event,
                    request,
                } => self.notify_by_itself(call, dialog, event, request, now),
                Parked::Bye { dialog } => self.bye_by_itself(dialog, now),
                Parked::Hangup { call, .. } => self.hang_up_by_itself(call, now),
                Parked::Offer { call, .. } => self.retry_offer(call, now),
                Parked::Refresh { subscription, .. } => {
                    self.refresh_subscription(subscription, now);
                }
            }
        }
    }

    /// Acknowledge a 2xx to a call placed with an offer (§13.2.2.4).
    ///
    /// `true` when the ACK went or is waiting for a stream.
    pub(crate) fn ack_by_itself(&mut self, dialog: DialogId, now: Instant) -> bool {
        match self.endpoint.ack_2xx(dialog, None, now) {
            Ok(()) => true,
            Err(ref error) if ack_needs_a_stream(error) => {
                self.park(Parked::Ack { dialog });
                true
            }
            Err(_) => false,
        }
    }

    /// Acknowledge the 2xx to a session change this end offered.
    pub(crate) fn ack_reinvite_by_itself(
        &mut self,
        invite: TransactionId<InviteClient>,
        dialog: DialogId,
        now: Instant,
    ) {
        if let Err(error) = self.endpoint.ack_reinvite(invite, None, now)
            && ack_needs_a_stream(&error)
        {
            self.park(Parked::ReinviteAck { invite, dialog });
        }
    }

    /// Acknowledge a reliable provisional response with nothing to answer
    /// (RFC 3262 §4).
    pub(crate) fn prack_by_itself(
        &mut self,
        call: CallHandle,
        provisional: ProvisionalResponseId,
        now: Instant,
    ) {
        match self.endpoint.prack(provisional, None, now) {
            Ok(prack) => self.remember_request(
                call,
                AnyTransactionId::NonInviteClient(prack),
                Method::Prack,
            ),
            Err(ref error) if prack_needs_a_stream(error) => {
                self.park(Parked::Prack { call, provisional });
            }
            Err(_) => {}
        }
    }

    /// Tell a referrer how the transfer is going (RFC 3515 §2.4.4). `event`
    /// is the `Event` value the request carries, which names the REFER.
    pub(crate) fn notify_by_itself(
        &mut self,
        call: CallHandle,
        dialog: DialogId,
        event: Vec<u8>,
        request: OutgoingInDialogRequest,
        now: Instant,
    ) {
        let sent = self.endpoint.request_in_dialog(dialog, &request, now);
        match sent {
            Ok(id) => {
                self.remember_request(call, AnyTransactionId::NonInviteClient(id), Method::Notify);
            }
            Err(ref error) if needs_a_stream(error) => {
                self.park(Parked::Notify {
                    call,
                    dialog,
                    event,
                    request,
                });
            }
            Err(_) => {}
        }
    }

    /// End a dialog whose call this layer has already reported over.
    pub(crate) fn bye_by_itself(&mut self, dialog: DialogId, now: Instant) {
        self.bye_by_itself_for(dialog, None, now);
    }

    /// [`UserAgent::bye_by_itself`], with a `Reason` (RFC 3326) on the BYE
    /// when this layer knows why it is sending it.
    pub(crate) fn bye_by_itself_for(
        &mut self,
        dialog: DialogId,
        reason: Option<&crate::Reason>,
        now: Instant,
    ) {
        let mut bye = OutgoingInDialogRequest::new(Method::Bye);
        if let Some(reason) = reason {
            bye = bye.header(crate::reason::REASON, &reason.to_value());
        }
        if let Err(error) = self.endpoint.bye_with(dialog, &bye, now)
            && needs_a_stream(&error)
        {
            self.park(Parked::Bye { dialog });
        }
    }

    /// Hang up a call this layer has decided to end.
    pub(crate) fn hang_up_by_itself(&mut self, call: CallHandle, now: Instant) {
        if let Err(error) = self.end_call(call, &[], &[], now)
            && call_needs_a_stream(&error)
            && let Some(dialog) = self.calls.get(&call).and_then(|held| held.dialog)
        {
            self.park(Parked::Hangup { call, dialog });
        }
    }
}
