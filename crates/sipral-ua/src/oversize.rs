// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Requests too large for a datagram (RFC 3261 §18.1.1) when no stream comes.
//!
//! Over 1300 bytes with an unknown MTU, a request must go over a stream. It
//! is nearly always a retry: two SDES suites plus a PBX's `Authorization`.
//! The endpoint holds it and raises `TransportWanted`; [`crate::parked`]
//! does the same for what this layer sends by itself.
//!
//! The wait is bounded by [`STREAM_WAIT`], or ends at once on
//! [`UserAgent::stream_unavailable`]. Then:
//!
//! - an initial INVITE is retried once over the datagram with one `a=crypto`
//!   per media section ([`one_suite_each`]), preferring
//!   `AES_CM_128_HMAC_SHA1_80`, the suite every SDES peer takes (RFC 3711
//!   §5). If it still does not fit, the call ends as
//!   [`CallEndReason::Unreachable`] with 513 and a `Reason` naming size and
//!   limit;
//! - a REGISTER fails for good with [`RegistrationFailure::Unreachable`] and
//!   513, since a retry would hit the same limit;
//! - a re-INVITE or UPDATE fails as a session change with 513; the call goes
//!   on (§14.1);
//! - BYE, REFER, INFO and other in-call requests settle as refused with 513;
//!   a SUBSCRIBE ends its subscription;
//! - a MESSAGE is reported sent with 513 and a PUBLISH fails as unreachable
//!   with 513, not as the 401/407 they never answered;
//! - what this layer parked itself is dropped only on `stream_unavailable`:
//!   a pending hangup ends the call, a re-offer fails, and ACK, PRACK,
//!   NOTIFY or a late BYE are dropped. The timeout leaves them, since a
//!   stream opened later (after a network change) still delivers them.
//!
//! 513 is §21.5.6's Message Too Large, a local verdict like §8.1.3.1's 408.

use std::time::{Duration, Instant};

use sipral_core::msg::StatusCode;
use sipral_core::transaction::{AnyTransactionId, InviteClient, TransactionId};

use crate::agent::UserAgent;
use crate::call::CallEndReason;
use crate::event::{RegistrationFailure, UaEvent};
use crate::parked::Parked;
use crate::reason::Reason;
use crate::subscription::{SubscriptionEnd, SubscriptionHandle};

/// How long a request waits for the stream §18.1.1 asked for: room for TCP
/// plus TLS on a slow mobile path, short of how long a caller waits to ring.
pub const STREAM_WAIT: Duration = Duration::from_secs(10);

/// RFC 3261 §21.5.6's Message Too Large.
const TOO_LARGE: u16 = 513;

impl UserAgent {
    /// The stream a `TransportWanted` asked for cannot be had.
    ///
    /// Call when opening it failed, or when the application opens no streams.
    /// Everything waiting gives up now instead of after [`STREAM_WAIT`], as
    /// the module docs describe. A no-op when nothing is waiting.
    pub fn stream_unavailable(&mut self, now: Instant) {
        self.give_up_on_a_stream(now);
        self.give_up_parked(now);
        self.drain(now);
    }

    /// Whether anything is held until a stream is bound. While `false`, a
    /// failed connection is no news to this agent.
    #[must_use]
    pub fn wants_a_stream(&self) -> bool {
        self.waiting_for_a_stream() || !self.parked.is_empty()
    }

    /// Like [`Self::wants_a_stream`], without [`crate::parked`]: the
    /// timeout does not apply to those.
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
            || self.messages_wait_for_a_stream()
            || self.publications_wait_for_a_stream()
    }

    /// Arms the deadline with the first waiting request and clears it with
    /// the last. Run after every drain. One deadline for all: later
    /// requests wait for the same connection.
    pub(crate) fn watch_the_stream_wait(&mut self, now: Instant) {
        if !self.waiting_for_a_stream() {
            self.stream_deadline = None;
        } else if self.stream_deadline.is_none() {
            self.stream_deadline = Some(now + STREAM_WAIT);
        }
    }

    pub(crate) fn fire_stream_wait(&mut self, now: Instant) {
        if self.stream_deadline.is_some_and(|due| due <= now) {
            self.give_up_on_a_stream(now);
        }
    }

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

    /// With `DatagramLimit::without_stream_bytes` set, everything held is
    /// first resent under that limit; only what still does not fit fails.
    fn give_up_on_a_stream(&mut self, now: Instant) {
        self.stream_deadline = None;
        if self.endpoint.no_stream_coming() {
            self.resume_what_waited_for_a_stream(now);
        }
        let text = self.too_large_text();
        let status = StatusCode::new(TOO_LARGE).ok();
        self.give_up_calls(&text, status, now);
        self.give_up_registrations(status);
        self.give_up_requests(status);
        self.give_up_offers(status);
        self.give_up_subscriptions(status, now);
        if let Some(status) = status {
            self.give_up_messages(status);
            self.give_up_publications(status, now);
        }
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

    /// Resends with one SDES suite per section; `true` when it went.
    fn retry_with_one_suite(&mut self, invite: TransactionId<InviteClient>, now: Instant) -> bool {
        let old = AnyTransactionId::InviteClient(invite);
        let Some(call) = self.by_invite.get(&invite).copied() else {
            return false;
        };
        let account = self.calls.get(&call).and_then(|held| held.account);
        let Some(credentials) = self.credentials_for_challenge(account, old) else {
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
                // answered, so not to be reported as wrong credentials
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

/// RFC 3711 §5's mandatory suite, named as in RFC 4568 §6.2.1.
const EVERYONE_TAKES: &[u8] = b" AES_CM_128_HMAC_SHA1_80 ";

/// An SDES offer with one `a=crypto` line in each media section, or `None`
/// when no section had more than one.
///
/// Keeps `AES_CM_128_HMAC_SHA1_80` if offered, else the first: this retry
/// must be answerable, and Asterisk answers 488 to `AEAD_AES_256_GCM` alone.
///
/// Kept lines are byte-exact, tag included, so the answer names a tag this
/// end keyed.
pub(crate) fn one_suite_each(body: &[u8]) -> Option<Vec<u8>> {
    let is_crypto = |line: &&[u8]| line.starts_with(b"a=crypto:");
    let everyone_takes = |line: &&[u8]| {
        line.windows(EVERYONE_TAKES.len())
            .any(|window| window == EVERYONE_TAKES)
    };
    // the session part, then one group per `m=` line and what follows it
    let mut sections: Vec<Vec<&[u8]>> = vec![Vec::new()];
    for line in body.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"m=") {
            sections.push(Vec::new());
        }
        if let Some(section) = sections.last_mut() {
            section.push(line);
        }
    }
    let mut kept = Vec::with_capacity(body.len());
    let mut dropped = false;
    for section in &sections {
        let offered: Vec<&[u8]> = section.iter().copied().filter(is_crypto).collect();
        let chosen =
            (offered.len() > 1).then(|| offered.iter().position(everyone_takes).unwrap_or(0));
        let mut crypto_seen = 0_usize;
        for line in section {
            if is_crypto(line) {
                let at = crypto_seen;
                crypto_seen += 1;
                if chosen.is_some_and(|chosen| chosen != at) {
                    dropped = true;
                    continue;
                }
            }
            kept.extend_from_slice(line);
        }
    }
    dropped.then_some(kept)
}

#[cfg(test)]
mod tests {
    use super::one_suite_each;

    #[test]
    fn every_media_section_keeps_the_suite_everyone_takes_and_nothing_else_moves() {
        let offer = b"v=0\r\n\
            o=- 1 1 IN IP4 192.0.2.1\r\n\
            s=-\r\n\
            c=IN IP4 192.0.2.1\r\n\
            t=0 0\r\n\
            m=audio 4000 RTP/SAVP 0\r\n\
            a=crypto:1 AEAD_AES_256_GCM inline:AAAA\r\n\
            a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:BBBB\r\n\
            a=crypto:3 AEAD_AES_128_GCM inline:EEEE\r\n\
            a=sendrecv\r\n\
            m=text 4002 RTP/SAVP 98\r\n\
            a=crypto:1 AEAD_AES_256_GCM inline:CCCC\r\n\
            a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:DDDD\r\n";
        let trimmed = one_suite_each(offer).expect("three suites to drop");
        let text = String::from_utf8(trimmed).expect("text");
        assert_eq!(
            text,
            "v=0\r\n\
             o=- 1 1 IN IP4 192.0.2.1\r\n\
             s=-\r\n\
             c=IN IP4 192.0.2.1\r\n\
             t=0 0\r\n\
             m=audio 4000 RTP/SAVP 0\r\n\
             a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:BBBB\r\n\
             a=sendrecv\r\n\
             m=text 4002 RTP/SAVP 98\r\n\
             a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:DDDD\r\n"
        );
    }

    #[test]
    fn a_section_without_the_suite_everyone_takes_keeps_its_first() {
        let offer = b"v=0\r\nm=audio 4000 RTP/SAVP 0\r\n\
            a=crypto:1 AEAD_AES_256_GCM inline:AAAA\r\n\
            a=crypto:2 AES_256_CM_HMAC_SHA1_80 inline:BBBB\r\n\
            a=rtcp-mux\r\n";
        assert_eq!(
            one_suite_each(offer).as_deref(),
            Some(
                &b"v=0\r\nm=audio 4000 RTP/SAVP 0\r\n\
                   a=crypto:1 AEAD_AES_256_GCM inline:AAAA\r\n\
                   a=rtcp-mux\r\n"[..]
            )
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
