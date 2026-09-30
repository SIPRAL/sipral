// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A request RFC 3261 §18.1.1 took off the datagram, and no stream to put it
//! on.
//!
//! "If a request is within 200 bytes of the path MTU, or if it is larger than
//! 1300 bytes and the path MTU is unknown, the request MUST be sent using an
//! RFC 2914 congestion controlled transport protocol, such as TCP." The
//! request that crosses the line is nearly always a retry: a call offering
//! two SDES suites is a thousand bytes, and the `Authorization` a PBX's
//! challenge asks for is the few hundred more. The endpoint then holds the
//! retry and raises `TransportWanted`, and every path here that answers a
//! challenge waits for the stream it asked for ([`crate::parked`] is the same
//! for what this layer sends by itself).
//!
//! Waiting is right when a stream is coming and a hang when it is not: a
//! registrar that listens on UDP alone, a firewall that lets no TCP out, or
//! an application that never answers the event. So the wait is bounded —
//! [`STREAM_WAIT`], or at once when the application says the stream cannot be
//! had ([`UserAgent::stream_unavailable`]) — and what is still waiting at the
//! end of it stops:
//!
//! - an INVITE that opens a call gets one last try over the datagram with a
//!   smaller offer, every media section keeping only the first `a=crypto`
//!   line of its SDES offer (RFC 4568 §6.1). The first is the suite this end
//!   prefers, a far end can only answer with a suite it was offered, and the
//!   suites dropped are the ones it would have chosen only instead of that
//!   one. When that fits, the call goes on; when it does not, or there was
//!   only one suite to begin with, the call ends as
//!   [`CallEndReason::Unreachable`] with a status of 513 and a `Reason`
//!   whose text names the size and the limit;
//! - a REGISTER fails for good with [`RegistrationFailure::Unreachable`] and
//!   a 513: sending it again would build the same retry and meet the same
//!   line;
//! - a re-INVITE or an UPDATE is a session change that failed, with a 513,
//!   and the call carries on as it was (§14.1);
//! - a BYE, a REFER, an INFO and the rest a call sends settle as refused
//!   with a 513, and a SUBSCRIBE ends its subscription the same way;
//! - what this layer was holding back by itself goes nowhere, once the
//!   application has said no stream is coming: a hangup it had decided on
//!   ends the call here, a session change it was offering again fails, and
//!   an ACK, a PRACK, a NOTIFY or a BYE after the call was over is dropped.
//!   The wait running out leaves these alone: each is something the far
//!   end is owed rather than an answer this end is waiting for, and a stream
//!   the application opens later — after a network change, say — still
//!   delivers it.
//!
//! 513 is the status RFC 3261 §21.5.6 gives a message too large to be
//! processed. No response carried it: it stands for this end's own verdict
//! the way §8.1.3.1's 408 and 503 stand for a request nobody answered.

use std::time::{Duration, Instant};

use sipral_core::msg::StatusCode;
use sipral_core::transaction::{AnyTransactionId, InviteClient, TransactionId};

use crate::agent::UserAgent;
use crate::call::CallEndReason;
use crate::event::{RegistrationFailure, UaEvent};
use crate::parked::Parked;
use crate::reason::Reason;
use crate::subscription::{SubscriptionEnd, SubscriptionHandle};

/// How long a request waits for the stream RFC 3261 §18.1.1 asked for.
///
/// Long enough for a TCP handshake and a TLS one after it across a slow
/// mobile path, which is what the application is opening while this runs.
/// Short enough that a phone whose application never answers the event is
/// told inside the time a caller waits for a ring.
pub const STREAM_WAIT: Duration = Duration::from_secs(10);

/// RFC 3261 §21.5.6's Message Too Large.
const TOO_LARGE: u16 = 513;

impl UserAgent {
    /// The stream a `TransportWanted` asked for cannot be had.
    ///
    /// For an application that tried and failed to open it — the far end
    /// refused the connection, or it timed out — or that does not open
    /// streams at all. Everything waiting for one stops now rather than at
    /// the end of [`STREAM_WAIT`], as the module documentation says: a call's
    /// INVITE is tried once more with a smaller offer, and what still does
    /// not fit a datagram ends with a 513 naming the limit.
    ///
    /// Nothing is waiting when no `TransportWanted` is outstanding, and this
    /// does nothing then.
    pub fn stream_unavailable(&mut self, now: Instant) {
        self.give_up_on_a_stream(now);
        self.give_up_parked(now);
        self.drain(now);
    }

    /// Whether anything is held back until a stream is bound: an answer to a
    /// challenge, or something this layer sends by itself.
    ///
    /// What makes a connection that could not be opened news to this agent:
    /// while this is `false`, no `TransportWanted` is waiting on an answer.
    #[must_use]
    pub fn wants_a_stream(&self) -> bool {
        self.waiting_for_a_stream() || !self.parked.is_empty()
    }

    /// Whether an answer to a challenge is held back until a stream is
    /// bound. What this layer sends by itself ([`crate::parked`]) is not
    /// counted: the wait is not for that.
    pub(crate) fn waiting_for_a_stream(&self) -> bool {
        self.registrations
            .values()
            .any(|reg| reg.waiting_for_stream.is_some())
            || self
                .challenged
                .values()
                .any(|refusal| refusal.waiting_for_stream)
            || self
                .challenged_requests
                .values()
                .any(|refusal| refusal.waiting_for_stream)
            || self
                .challenged_offers
                .values()
                .any(|offer| offer.waiting_for_stream)
            || self
                .subscriptions
                .values()
                .any(|held| held.waiting_for_stream.is_some())
    }

    /// Start the wait when the first request starts waiting, and stop it when
    /// the last one has gone.
    ///
    /// Run at the end of every drain, which is where a request starts or
    /// stops waiting. One deadline for all of them: a stream is asked for
    /// per destination, and a request that starts waiting while another
    /// already is has been waiting for the same connection.
    pub(crate) fn watch_the_stream_wait(&mut self, now: Instant) {
        if !self.waiting_for_a_stream() {
            self.stream_deadline = None;
        } else if self.stream_deadline.is_none() {
            self.stream_deadline = Some(now + STREAM_WAIT);
        }
    }

    /// Give up once the wait has run out.
    pub(crate) fn fire_stream_wait(&mut self, now: Instant) {
        if self.stream_deadline.is_some_and(|due| due <= now) {
            self.give_up_on_a_stream(now);
        }
    }

    /// The size, the limit and the rule, for a person to read.
    fn too_large_text(&self) -> String {
        match self.oversize {
            Some((request_bytes, limit_bytes)) => format!(
                "request of {request_bytes} bytes is over the {limit_bytes}-byte datagram \
                 limit of RFC 3261 section 18.1.1, and no stream transport carried it"
            ),
            None => String::from(
                "request is over the datagram limit of RFC 3261 section 18.1.1, and no \
                 stream transport carried it",
            ),
        }
    }

    /// Stop waiting, for every answer to a challenge.
    fn give_up_on_a_stream(&mut self, now: Instant) {
        self.stream_deadline = None;
        let text = self.too_large_text();
        let status = StatusCode::new(TOO_LARGE).ok();
        self.give_up_calls(&text, status, now);
        self.give_up_registrations(status);
        self.give_up_requests(status);
        self.give_up_offers(status);
        self.give_up_subscriptions(status, now);
    }

    fn give_up_calls(&mut self, text: &str, status: Option<StatusCode>, now: Instant) {
        let waiting: Vec<TransactionId<InviteClient>> = self
            .challenged
            .iter()
            .filter(|(_, refusal)| refusal.waiting_for_stream)
            .map(|(invite, _)| *invite)
            .collect();
        for invite in waiting {
            let old = AnyTransactionId::InviteClient(invite);
            if self.retry_with_one_suite(invite, now) {
                continue;
            }
            self.endpoint.abandon_challenge(old);
            if let Some(refusal) = self.challenged.get_mut(&invite) {
                refusal.waiting_for_stream = false;
                refusal.reason = CallEndReason::Unreachable;
                refusal.status = status;
                refusal.response = None;
            }
            if let Some(held) = self
                .by_invite
                .get(&invite)
                .copied()
                .and_then(|call| self.calls.get_mut(&call))
            {
                held.ended_by = Box::from([Reason::sip(TOO_LARGE, text)]);
            }
        }
    }

    /// The last resort for an INVITE: the same offer with one SDES suite per
    /// media section, over the datagram if it now fits. `true` when it went.
    fn retry_with_one_suite(&mut self, invite: TransactionId<InviteClient>, now: Instant) -> bool {
        let old = AnyTransactionId::InviteClient(invite);
        let Some(call) = self.by_invite.get(&invite).copied() else {
            return false;
        };
        let credentials = self
            .calls
            .get(&call)
            .and_then(|held| held.account)
            .and_then(|id| self.accounts.get(&id))
            .and_then(|config| config.credentials.clone());
        let Some(credentials) = credentials else {
            return false;
        };
        if !self.endpoint.reshape_challenged_body(old, one_suite_each) {
            return false;
        }
        match self.endpoint.retry_with_credentials(old, &credentials, now) {
            Ok(AnyTransactionId::InviteClient(retried)) => {
                self.call_retry_went(call, old, retried);
                true
            }
            Ok(_) | Err(_) => false,
        }
    }

    fn give_up_registrations(&mut self, status: Option<StatusCode>) {
        let waiting: Vec<(crate::AccountId, AnyTransactionId)> = self
            .registrations
            .iter()
            .filter_map(|(account, reg)| reg.waiting_for_stream.map(|failed| (*account, failed)))
            .collect();
        for (account, failed) in waiting {
            self.endpoint.abandon_challenge(failed);
            if let Some(reg) = self.registrations.get_mut(&account) {
                reg.waiting_for_stream = None;
                // the challenge was answered, so it is not the refusal the
                // settle pass would otherwise report as wrong credentials
                reg.unanswered = None;
            }
            self.give_up(account, RegistrationFailure::Unreachable, status, None);
        }
    }

    fn give_up_requests(&mut self, status: Option<StatusCode>) {
        let waiting: Vec<AnyTransactionId> = self
            .challenged_requests
            .iter()
            .filter(|(_, refusal)| refusal.waiting_for_stream)
            .map(|(id, _)| *id)
            .collect();
        for id in waiting {
            self.endpoint.abandon_challenge(id);
            if let Some(refusal) = self.challenged_requests.get_mut(&id) {
                refusal.waiting_for_stream = false;
                refusal.status = status;
            }
        }
    }

    fn give_up_offers(&mut self, status: Option<StatusCode>) {
        let waiting: Vec<AnyTransactionId> = self
            .challenged_offers
            .iter()
            .filter(|(_, offer)| offer.waiting_for_stream)
            .map(|(id, _)| *id)
            .collect();
        for id in waiting {
            self.endpoint.abandon_challenge(id);
            if let Some(offer) = self.challenged_offers.get_mut(&id) {
                offer.waiting_for_stream = false;
                offer.status = status;
                offer.response = None;
            }
        }
    }

    fn give_up_subscriptions(&mut self, status: Option<StatusCode>, now: Instant) {
        let waiting: Vec<(SubscriptionHandle, AnyTransactionId)> = self
            .subscriptions
            .iter()
            .filter_map(|(handle, held)| held.waiting_for_stream.map(|failed| (*handle, failed)))
            .collect();
        for (subscription, failed) in waiting {
            self.endpoint.abandon_challenge(failed);
            if let Some(held) = self.subscriptions.get_mut(&subscription) {
                held.waiting_for_stream = None;
                held.unanswered = None;
            }
            self.retry_or_end(
                subscription,
                SubscriptionEnd::Refused,
                status,
                None,
                None,
                now,
            );
        }
    }

    fn give_up_parked(&mut self, now: Instant) {
        let text = self.too_large_text();
        let status = StatusCode::new(TOO_LARGE).ok();
        for parked in core::mem::take(&mut self.parked) {
            match parked {
                Parked::Hangup { call, .. } => {
                    if let Some(held) = self.calls.get_mut(&call) {
                        held.ended_by = Box::from([Reason::sip(TOO_LARGE, &text)]);
                    }
                    self.finish(call, CallEndReason::LocalHangup, status, None, now);
                }
                Parked::Offer { call, .. } => {
                    if let Some(held) = self.calls.get_mut(&call) {
                        held.offering = None;
                        held.retry_at = None;
                    }
                    self.events.push_back(UaEvent::SessionChangeFailed {
                        call,
                        status,
                        retry_in: None,
                        response: None,
                    });
                }
                Parked::Ack { .. }
                | Parked::ReinviteAck { .. }
                | Parked::Prack { .. }
                | Parked::Notify { .. }
                | Parked::Bye { .. }
                | Parked::Refresh { .. } => {}
            }
        }
    }
}

/// An SDES offer with only the first `a=crypto` line of each media section,
/// or `None` when no section had more than one.
///
/// Lines are kept byte for byte, the line ending included, so that nothing
/// but the suites dropped differs from the offer the application was told
/// about.
pub(crate) fn one_suite_each(body: &[u8]) -> Option<Vec<u8>> {
    let mut kept = Vec::with_capacity(body.len());
    let mut seen_in_section = false;
    let mut dropped = false;
    for line in body.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"m=") {
            seen_in_section = false;
        } else if line.starts_with(b"a=crypto:") {
            if seen_in_section {
                dropped = true;
                continue;
            }
            seen_in_section = true;
        }
        kept.extend_from_slice(line);
    }
    dropped.then_some(kept)
}

#[cfg(test)]
mod tests {
    use super::one_suite_each;

    #[test]
    fn every_media_section_keeps_its_first_suite_and_nothing_else_moves() {
        let offer = b"v=0\r\n\
            o=- 1 1 IN IP4 192.0.2.1\r\n\
            s=-\r\n\
            c=IN IP4 192.0.2.1\r\n\
            t=0 0\r\n\
            m=audio 4000 RTP/SAVP 0\r\n\
            a=crypto:1 AEAD_AES_256_GCM inline:AAAA\r\n\
            a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:BBBB\r\n\
            a=sendrecv\r\n\
            m=text 4002 RTP/SAVP 98\r\n\
            a=crypto:1 AEAD_AES_256_GCM inline:CCCC\r\n\
            a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:DDDD\r\n";
        let trimmed = one_suite_each(offer).expect("two suites to drop");
        let text = String::from_utf8(trimmed).expect("text");
        assert_eq!(
            text,
            "v=0\r\n\
             o=- 1 1 IN IP4 192.0.2.1\r\n\
             s=-\r\n\
             c=IN IP4 192.0.2.1\r\n\
             t=0 0\r\n\
             m=audio 4000 RTP/SAVP 0\r\n\
             a=crypto:1 AEAD_AES_256_GCM inline:AAAA\r\n\
             a=sendrecv\r\n\
             m=text 4002 RTP/SAVP 98\r\n\
             a=crypto:1 AEAD_AES_256_GCM inline:CCCC\r\n"
        );
    }

    #[test]
    fn an_offer_with_one_suite_or_none_has_nothing_to_give() {
        assert_eq!(
            one_suite_each(b"v=0\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:1 X inline:A\r\n"),
            None
        );
        assert_eq!(one_suite_each(b"v=0\r\nm=audio 4000 RTP/AVP 0\r\n"), None);
        assert_eq!(one_suite_each(b""), None);
    }
}
