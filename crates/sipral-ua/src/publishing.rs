// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Keeping an account's event state at a compositor (RFC 3903), over this
//! agent's own endpoint.
//!
//! [`Publication`] decides what each PUBLISH says and when; this module gives
//! it transactions and a clock, and reports everything as
//! [`UaEvent::Publication`].
//!
//! A 401/407 is answered with the account's credentials (RFC 3903 §13), never
//! reported. Only an unanswerable one becomes a refusal, decided at the end of
//! the drain, because the core reports the refusal before the retry.
//!
//! A publication ends only when a removal is confirmed. A failed refresh, a
//! 412 with nothing to publish, or an expired lifetime keep the handle, and
//! the next [`UserAgent::republish`] starts it afresh.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Event, OutgoingRequest};
use sipral_core::msg::{Method, OwnedMessage, StatusCode, Uri};
use sipral_core::transaction::AnyTransactionId;

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::error::UaError;
use crate::event::UaEvent;
use crate::presence::Presence;
use crate::publish::{Publication, PublishEvent, PublishRequest};
use crate::subscription::DEFAULT_EXPIRES;

/// RFC 3856's event package for presence (RFC 3903 §4.1).
pub const PRESENCE_EVENT: &str = "presence";

/// One piece of event state this agent keeps at a compositor.
///
/// Minted before sending, so even an unsent PUBLISH can be reported. Never
/// reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicationHandle(pub(crate) u32);

/// What to publish, where, and for how long.
#[derive(Clone, Debug)]
pub struct Publish {
    event: Box<str>,
    target: Option<Uri>,
    expires: Duration,
}

impl Publish {
    /// State of package `event` for the account's own address of record
    /// (RFC 3903 §4), for [`DEFAULT_EXPIRES`].
    #[must_use]
    pub fn new(event: &str) -> Self {
        Self {
            event: Box::from(event),
            target: None,
            expires: DEFAULT_EXPIRES,
        }
    }

    /// A presence document ([`PRESENCE_EVENT`]).
    #[must_use]
    pub fn presence() -> Self {
        Self::new(PRESENCE_EVENT)
    }

    /// Publish for another resource (Request-URI and `To`).
    #[must_use]
    pub fn target(mut self, target: Uri) -> Self {
        self.target = Some(target);
        self
    }

    /// Lifetime to ask for instead of an hour ([`Publication::expires`]).
    #[must_use]
    pub const fn expires(mut self, expires: Duration) -> Self {
        self.expires = expires;
        self
    }

    /// The event package it publishes.
    #[must_use]
    pub fn event(&self) -> &str {
        &self.event
    }
}

/// One publication, and whose it is.
#[derive(Debug)]
struct Held {
    account: AccountId,
    target: Uri,
    machine: Publication,
    /// The account's presence, which [`UserAgent::publish_presence`]
    /// modifies rather than duplicates.
    presence: bool,
    /// A 401/407 not yet known to be retried; settled at the drain's end.
    unanswered: Option<StatusCode>,
    /// A challenged transaction whose retry needs a stream (§18.1.1,
    /// [`crate::oversize`]).
    waiting_for_stream: Option<AnyTransactionId>,
}

#[derive(Debug, Default)]
pub(crate) struct Publications {
    held: HashMap<PublicationHandle, Held>,
    by_transaction: HashMap<AnyTransactionId, PublicationHandle>,
    next: u32,
}

impl UserAgent {
    /// Publish `body` as state of `wanted`'s event package for `account`
    /// (RFC 3903 §4), and keep it published until
    /// [`UserAgent::unpublish`].
    ///
    /// Refreshes, challenges, a 412's fresh PUBLISH and a 423's longer
    /// lifetime are handled automatically and reported as
    /// [`UaEvent::Publication`].
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`].
    pub fn publish(
        &mut self,
        account: AccountId,
        wanted: &Publish,
        content_type: &str,
        body: Arc<[u8]>,
        now: Instant,
    ) -> Result<PublicationHandle, UaError> {
        let handle = self.mint_publication(account, wanted, false)?;
        if let Some(held) = self.publications.held.get_mut(&handle) {
            held.machine.publish(content_type, body);
        }
        self.pump_publication(handle, now);
        self.drain(now);
        Ok(handle)
    }

    /// Publish this account's presence (RFC 3856 §6.2's `presence` package,
    /// as `application/pidf+xml`).
    ///
    /// One per account: later calls modify it under the same handle (RFC
    /// 3903 §4.4).
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], or [`UaError::Publish`] with
    /// [`crate::PublishError::Unwritable`]; nothing is sent then.
    pub fn publish_presence(
        &mut self,
        account: AccountId,
        presence: &Presence,
        now: Instant,
    ) -> Result<PublicationHandle, UaError> {
        if !self.accounts.contains_key(&account) {
            return Err(UaError::NoSuchAccount);
        }
        let body = presence
            .to_xml()
            .map_err(|error| UaError::Publish(crate::PublishError::Unwritable(error)))?;
        let existing = self
            .publications
            .held
            .iter()
            .find(|(_, held)| held.account == account && held.presence)
            .map(|(handle, _)| *handle);
        let handle = match existing {
            Some(handle) => handle,
            None => self.mint_publication(account, &Publish::presence(), true)?,
        };
        if let Some(held) = self.publications.held.get_mut(&handle) {
            held.machine
                .publish(crate::presence::PIDF_TYPE, Arc::from(body));
        }
        self.pump_publication(handle, now);
        self.drain(now);
        Ok(handle)
    }

    /// Replace the published state (RFC 3903 §4.4), or publish afresh if the
    /// compositor holds nothing.
    ///
    /// # Errors
    /// [`UaError::NoSuchPublication`].
    pub fn republish(
        &mut self,
        publication: PublicationHandle,
        content_type: &str,
        body: Arc<[u8]>,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self
            .publications
            .held
            .get_mut(&publication)
            .ok_or(UaError::NoSuchPublication)?;
        held.machine.publish(content_type, body);
        self.pump_publication(publication, now);
        self.drain(now);
        Ok(())
    }

    /// Refresh now (RFC 3903 §4.3), e.g. after a failed refresh.
    ///
    /// # Errors
    /// [`UaError::NoSuchPublication`], or [`UaError::Publish`] with
    /// [`crate::PublishError::NothingPublished`].
    pub fn refresh_publication(
        &mut self,
        publication: PublicationHandle,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self
            .publications
            .held
            .get_mut(&publication)
            .ok_or(UaError::NoSuchPublication)?;
        held.machine.refresh().map_err(UaError::Publish)?;
        self.pump_publication(publication, now);
        self.drain(now);
        Ok(())
    }

    /// Remove the state (RFC 3903 §4.5): `SIP-If-Match` and `Expires: 0`.
    /// [`UaEvent::Publication`] with [`PublishEvent::Removed`] says it is
    /// gone, and the handle names nothing from then on.
    ///
    /// One never published is dropped at once, with the same event.
    ///
    /// # Errors
    /// [`UaError::NoSuchPublication`].
    pub fn unpublish(
        &mut self,
        publication: PublicationHandle,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self
            .publications
            .held
            .get_mut(&publication)
            .ok_or(UaError::NoSuchPublication)?;
        let account = held.account;
        if held.machine.remove().is_err() {
            self.forget_publication(publication);
            self.events.push_back(UaEvent::Publication {
                publication,
                account,
                event: PublishEvent::Removed,
            });
            self.drain(now);
            return Ok(());
        }
        self.pump_publication(publication, now);
        self.drain(now);
        Ok(())
    }

    /// The entity tag from the compositor's last 2xx.
    #[must_use]
    pub fn publication_etag(&self, publication: PublicationHandle) -> Option<&str> {
        self.publications
            .held
            .get(&publication)
            .and_then(|held| held.machine.etag())
    }

    /// The account's live [`UserAgent::publish_presence`] publication.
    #[must_use]
    pub fn presence_publication(&self, account: AccountId) -> Option<PublicationHandle> {
        self.publications
            .held
            .iter()
            .find(|(_, held)| held.account == account && held.presence)
            .map(|(handle, _)| *handle)
    }

    fn mint_publication(
        &mut self,
        account: AccountId,
        wanted: &Publish,
        presence: bool,
    ) -> Result<PublicationHandle, UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        let target = wanted.target.clone().unwrap_or_else(|| config.aor.clone());
        let handle = PublicationHandle(self.publications.next);
        self.publications.next = self.publications.next.wrapping_add(1);
        self.publications.held.insert(
            handle,
            Held {
                account,
                target,
                machine: Publication::new(&wanted.event).expires(wanted.expires),
                presence,
                unanswered: None,
                waiting_for_stream: None,
            },
        );
        Ok(handle)
    }

    fn pump_publication(&mut self, publication: PublicationHandle, now: Instant) {
        loop {
            let Some(held) = self.publications.held.get_mut(&publication) else {
                return;
            };
            let Some(request) = held.machine.poll_transmit() else {
                break;
            };
            let (account, target) = (held.account, held.target.clone());
            let sent = self.send_publish(account, target, &request, now);
            match sent {
                Some(transaction) => {
                    self.publications
                        .by_transaction
                        .insert(transaction, publication);
                }
                None => {
                    if let Some(held) = self.publications.held.get_mut(&publication) {
                        held.machine.handle_failure();
                    }
                }
            }
        }
        self.report_publication(publication);
    }

    fn send_publish(
        &mut self,
        account: AccountId,
        target: Uri,
        publish: &PublishRequest,
        now: Instant,
    ) -> Option<AnyTransactionId> {
        let config = self.accounts.get(&account)?;
        let (transport, remote) = config.destination()?;
        let mut to = Vec::with_capacity(target.as_bytes().len() + 2);
        to.push(b'<');
        to.extend_from_slice(target.as_bytes());
        to.push(b'>');
        let request = publish.apply(
            OutgoingRequest::new(Method::Publish, target, transport, remote)
                .to(&to)
                .from(&config.sender_value()),
        );
        // §22.2 caching: credentials go only where challenged before, so an
        // hourly refresh does not cost a 401 each time
        let sent = match config.credentials.clone() {
            Some(credentials) => {
                self.endpoint
                    .request_with_credentials(&request, &credentials, now)
            }
            None => self.endpoint.request(&request, now),
        };
        sent.ok().map(AnyTransactionId::NonInviteClient)
    }

    fn report_publication(&mut self, publication: PublicationHandle) {
        let Some(held) = self.publications.held.get_mut(&publication) else {
            return;
        };
        let account = held.account;
        let mut removed = false;
        let mut said = Vec::new();
        while let Some(event) = held.machine.poll_event() {
            // challenges are retried by the endpoint, not reported
            if matches!(event, PublishEvent::Challenged { .. }) {
                continue;
            }
            removed |= event == PublishEvent::Removed;
            said.push(event);
        }
        if removed {
            self.forget_publication(publication);
        }
        for event in said {
            self.events.push_back(UaEvent::Publication {
                publication,
                account,
                event,
            });
        }
    }

    fn forget_publication(&mut self, publication: PublicationHandle) {
        self.publications.held.remove(&publication);
        self.publications
            .by_transaction
            .retain(|_, owner| *owner != publication);
    }

    /// Drops an account's publications without sending: the state lapses at
    /// the compositor (RFC 3903 §4), and a removal needs the credentials.
    pub(crate) fn forget_publications(&mut self, account: AccountId) {
        let gone: Vec<PublicationHandle> = self
            .publications
            .held
            .iter()
            .filter(|(_, held)| held.account == account)
            .map(|(handle, _)| *handle)
            .collect();
        for publication in gone {
            self.forget_publication(publication);
        }
    }

    /// `None` when the event was about a PUBLISH of ours and has been dealt
    /// with; the event back otherwise.
    pub(crate) fn on_publication_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::Response {
                transaction,
                status,
                ref response,
            } => {
                let key = AnyTransactionId::NonInviteClient(transaction);
                let Some(publication) = self.publications.by_transaction.get(&key).copied() else {
                    return Some(event);
                };
                let response = response.clone();
                self.on_publish_response(publication, key, status, &response, now);
                None
            }
            Event::RequestFailed { transaction, .. } => {
                let key = AnyTransactionId::NonInviteClient(transaction);
                let publication = self.publications.by_transaction.remove(&key)?;
                if let Some(held) = self.publications.held.get_mut(&publication) {
                    held.unanswered = None;
                    held.machine.handle_failure();
                }
                self.pump_publication(publication, now);
                None
            }
            Event::Challenged { transaction, .. } | Event::TokenChallenged { transaction, .. } => {
                let Some(publication) = self.publications.by_transaction.get(&transaction).copied()
                else {
                    return Some(event);
                };
                self.on_publish_challenged(publication, transaction, now);
                None
            }
            Event::TransactionTerminated { transaction, .. }
                if self.publications.by_transaction.contains_key(&transaction) =>
            {
                None
            }
            other => Some(other),
        }
    }

    fn on_publish_response(
        &mut self,
        publication: PublicationHandle,
        transaction: AnyTransactionId,
        status: StatusCode,
        response: &OwnedMessage,
        now: Instant,
    ) {
        if status.is_provisional() {
            return;
        }
        let Some(held) = self.publications.held.get_mut(&publication) else {
            return;
        };
        if matches!(status.get(), 401 | 407) {
            // settled at the end of the drain, once a retry may have gone
            held.unanswered = Some(status);
            return;
        }
        self.publications.by_transaction.remove(&transaction);
        held.unanswered = None;
        held.machine.handle_response(&response.as_raw(), now);
        self.pump_publication(publication, now);
    }

    fn on_publish_challenged(
        &mut self,
        publication: PublicationHandle,
        transaction: AnyTransactionId,
        now: Instant,
    ) {
        let account = self
            .publications
            .held
            .get(&publication)
            .map(|held| held.account);
        let Some(credentials) = self.credentials_for_challenge(account, transaction) else {
            return;
        };
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => self.publish_retry_went(publication, transaction, retried),
            // §18.1.1: needs a stream; the endpoint holds the challenge
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let Some(held) = self.publications.held.get_mut(&publication) {
                    held.waiting_for_stream = Some(transaction);
                }
            }
            Err(_) => {}
        }
    }

    /// Follows a PUBLISH failed over to the next server (RFC 3263 §4.3).
    pub(crate) fn publish_retry_went_if_held(
        &mut self,
        failed: AnyTransactionId,
        sent: AnyTransactionId,
    ) {
        if let Some(publication) = self.publications.by_transaction.get(&failed).copied() {
            self.publish_retry_went(publication, failed, sent);
        }
    }

    fn publish_retry_went(
        &mut self,
        publication: PublicationHandle,
        transaction: AnyTransactionId,
        retried: AnyTransactionId,
    ) {
        self.publications.by_transaction.remove(&transaction);
        self.publications
            .by_transaction
            .insert(retried, publication);
        if let Some(held) = self.publications.held.get_mut(&publication) {
            held.unanswered = None;
            held.waiting_for_stream = None;
        }
    }

    fn publications_waiting(&self) -> Vec<(PublicationHandle, AnyTransactionId)> {
        self.publications
            .held
            .iter()
            .filter_map(|(handle, held)| held.waiting_for_stream.map(|failed| (*handle, failed)))
            .collect()
    }

    /// Sends the retries §18.1.1 held, now that a stream exists.
    pub(crate) fn resume_parked_publications(&mut self, now: Instant) {
        for (publication, failed) in self.publications_waiting() {
            let account = self
                .publications
                .held
                .get(&publication)
                .map(|held| held.account);
            let credentials = self.credentials_for_challenge(account, failed);
            let outcome = credentials.map(|credentials| {
                self.endpoint
                    .retry_with_credentials(failed, &credentials, now)
            });
            match outcome {
                Some(Ok(retried)) => self.publish_retry_went(publication, failed, retried),
                Some(Err(error)) if crate::agent::wants_a_stream(&error) => {}
                // the next settle reports the refusal it still carries
                _ => {
                    if let Some(held) = self.publications.held.get_mut(&publication) {
                        held.waiting_for_stream = None;
                    }
                }
            }
        }
    }

    /// No stream is coming: each held PUBLISH fails as unreachable with
    /// `status`, not as the 401/407 it never answered.
    pub(crate) fn give_up_publications(&mut self, status: StatusCode, now: Instant) {
        for (publication, failed) in self.publications_waiting() {
            self.endpoint.abandon_challenge(failed);
            self.publications
                .by_transaction
                .retain(|_, owner| *owner != publication);
            if let Some(held) = self.publications.held.get_mut(&publication) {
                held.waiting_for_stream = None;
                held.unanswered = None;
                held.machine.too_large(status);
            }
            self.pump_publication(publication, now);
        }
    }

    pub(crate) fn publications_wait_for_a_stream(&self) -> bool {
        self.publications
            .held
            .values()
            .any(|held| held.waiting_for_stream.is_some())
    }

    /// A challenge that got no retry was a refusal. Called at the end of
    /// every drain, as `settle_message_challenges` is.
    pub(crate) fn settle_publication_challenges(&mut self, now: Instant) {
        let refused: Vec<(PublicationHandle, StatusCode)> = self
            .publications
            .held
            .iter_mut()
            // a retry held for a stream is not a refusal yet
            .filter(|(_, held)| held.waiting_for_stream.is_none())
            .filter_map(|(handle, held)| held.unanswered.take().map(|status| (*handle, status)))
            .collect();
        for (publication, status) in refused {
            self.publications
                .by_transaction
                .retain(|_, owner| *owner != publication);
            if let Some(held) = self.publications.held.get_mut(&publication) {
                held.machine.challenge_unanswered(status);
            }
            self.pump_publication(publication, now);
        }
    }

    pub(crate) fn fire_publication_timers(&mut self, now: Instant) {
        let due: Vec<PublicationHandle> = self
            .publications
            .held
            .iter()
            .filter(|(_, held)| held.machine.poll_timeout().is_some_and(|at| at <= now))
            .map(|(handle, _)| *handle)
            .collect();
        for publication in due {
            if let Some(held) = self.publications.held.get_mut(&publication) {
                held.machine.handle_timeout(now);
            }
            self.pump_publication(publication, now);
        }
    }

    pub(crate) fn publication_deadline(&self) -> Option<Instant> {
        self.publications
            .held
            .values()
            .filter_map(|held| held.machine.poll_timeout())
            .min()
    }
}
