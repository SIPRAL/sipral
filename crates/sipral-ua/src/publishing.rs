// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Keeping an account's event state at a compositor (RFC 3903), over this
//! agent's own endpoint.
//!
//! [`Publication`] decides what each PUBLISH says and when the next one is
//! due; it owns no transaction and no clock. This is what gives it both: it
//! addresses each request for the account it belongs to, answers the
//! compositor's challenges with that account's credentials, wakes the
//! machine for its refresh from [`UserAgent::handle_timeout`], and says what
//! became of the state as [`UaEvent::Publication`] — the one place an
//! application looks, whether the news is a refresh that went through or
//! a compositor that forgot the state.
//!
//! **A challenge is answered here, never reported.** A 401 or 407 is the
//! compositor asking who is publishing, and the account's credentials are
//! the answer (RFC 3903 §13 has the compositor authenticate the publisher).
//! Only a challenge nothing here can answer — an account with no credentials,
//! or a retry the endpoint could not send — becomes a refusal, decided at the
//! end of the drain the way a MESSAGE's is, because the core reports the
//! refusal before it reports that the refusal is answerable.
//!
//! **A publication ends only when its state is removed.** A refresh that
//! failed, a compositor that answered 412 with nothing left to publish, or a
//! lifetime that ran out leaves the handle naming the same piece of state,
//! and the next [`UserAgent::republish`] starts it afresh; a removal the
//! compositor confirmed is what lets the handle go.

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

/// The event package RFC 3856 names, which is the one a presence document
/// is published under (RFC 3903 §4.1).
pub const PRESENCE_EVENT: &str = "presence";

/// One piece of event state this agent keeps at a compositor.
///
/// Minted before anything is sent, so that a PUBLISH which never reaches a
/// transport still has a name to be reported under. Never reused.
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
    /// State of the event package `event`, published for the account's own
    /// address of record — the resource RFC 3903 §4 has a PUBLISH name in
    /// its Request-URI — for [`DEFAULT_EXPIRES`].
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

    /// Publish the state of another resource than the account's own address
    /// of record: a Request-URI, and the `To` the request carries.
    #[must_use]
    pub fn target(mut self, target: Uri) -> Self {
        self.target = Some(target);
        self
    }

    /// Ask for `expires` rather than an hour, as [`Publication::expires`]
    /// takes it.
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
    /// Whether this is the account's presence, which
    /// [`UserAgent::publish_presence`] modifies rather than duplicates.
    presence: bool,
    /// A 401 or 407 to the request in flight, until the drain ends and it is
    /// known whether a retry followed.
    unanswered: Option<StatusCode>,
    /// The refused transaction whose answer RFC 3261 §18.1.1 took off the
    /// datagram, held by the endpoint until a stream is bound or the wait for
    /// one ends ([`crate::oversize`]).
    waiting_for_stream: Option<AnyTransactionId>,
}

/// Every publication an agent keeps, and the transactions they have in
/// flight.
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
    /// The refresh, the answer to a challenge, the fresh initial PUBLISH a
    /// 412 asks for and the longer lifetime a 423 asks for all happen without
    /// another call. What happens is [`UaEvent::Publication`].
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
    /// One per account: the first call creates the publication, and every
    /// later one modifies it under the same handle, which is what RFC 3903
    /// §4.4 expects of a publisher whose state changed.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], or [`UaError::Publish`] with
    /// [`crate::PublishError::Unwritable`] for a document that cannot be
    /// written, in which case nothing is sent.
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

    /// Replace what a publication holds at the compositor: a modification
    /// (RFC 3903 §4.4), or an initial PUBLISH again when nothing is held
    /// there any more.
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

    /// Refresh now rather than when the lifetime says (RFC 3903 §4.3): after
    /// a refresh that failed, say.
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
    /// A publication that never got as far as the compositor has nothing to
    /// remove, and is let go here and now, with the same event.
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

    /// The entity tag the compositor holds a publication's state under, once
    /// a 2xx has named one.
    #[must_use]
    pub fn publication_etag(&self, publication: PublicationHandle) -> Option<&str> {
        self.publications
            .held
            .get(&publication)
            .and_then(|held| held.machine.etag())
    }

    /// The account's presence publication, when [`UserAgent::publish_presence`]
    /// has made one and it has not been removed.
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

    /// Send whatever the machine has to send, and report whatever it has to
    /// say.
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

    /// One PUBLISH on the wire, addressed for `account`: the transaction, or
    /// `None` when it could not be sent.
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
        // §22.2's caching, as a MESSAGE does: nothing goes on unless this
        // destination has challenged this account before, and a refresh an
        // hour does not cost a fresh 401 every time
        let sent = match config.credentials.clone() {
            Some(credentials) => {
                self.endpoint
                    .request_with_credentials(&request, &credentials, now)
            }
            None => self.endpoint.request(&request, now),
        };
        sent.ok().map(AnyTransactionId::NonInviteClient)
    }

    /// Everything the machine has to say, as events, and the record let go
    /// once the state is removed.
    fn report_publication(&mut self, publication: PublicationHandle) {
        let Some(held) = self.publications.held.get_mut(&publication) else {
            return;
        };
        let account = held.account;
        let mut removed = false;
        let mut said = Vec::new();
        while let Some(event) = held.machine.poll_event() {
            // a challenge is answered by the endpoint's retry, and the
            // machine is only ever told about one nothing could answer
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

    /// Drop every publication of an account being removed. Nothing is sent:
    /// the state lapses at the compositor by itself (RFC 3903 §4), and a
    /// removal that needs an account's credentials cannot outlive it.
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
            Event::Challenged { transaction, .. } => {
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
            // whether this is a refusal is decided at the end of the drain,
            // once it is known whether a retry followed
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
        let credentials = self
            .publications
            .held
            .get(&publication)
            .and_then(|held| self.accounts.get(&held.account))
            .and_then(|config| config.credentials.clone());
        let Some(credentials) = credentials else {
            return;
        };
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => self.publish_retry_went(publication, transaction, retried),
            // §18.1.1 wants a connection first, and the endpoint is still
            // holding the challenge
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let Some(held) = self.publications.held.get_mut(&publication) {
                    held.waiting_for_stream = Some(transaction);
                }
            }
            Err(_) => {}
        }
    }

    /// A PUBLISH that went to the next server (RFC 3263 §4.3): the
    /// publication names the new transaction, when it held the old one.
    pub(crate) fn publish_retry_went_if_held(
        &mut self,
        failed: AnyTransactionId,
        sent: AnyTransactionId,
    ) {
        if let Some(publication) = self.publications.by_transaction.get(&failed).copied() {
            self.publish_retry_went(publication, failed, sent);
        }
    }

    /// The retry is a transaction now, and the publication names it.
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

    /// Send the PUBLISH retries §18.1.1 held back, now that there is a
    /// connection.
    pub(crate) fn resume_parked_publications(&mut self, now: Instant) {
        for (publication, failed) in self.publications_waiting() {
            let credentials = self
                .publications
                .held
                .get(&publication)
                .and_then(|held| self.accounts.get(&held.account))
                .and_then(|config| config.credentials.clone());
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

    /// No stream is coming for the PUBLISHes whose answer to a challenge
    /// outgrew the datagram: each fails as unreachable with `status`, rather
    /// than as the 401 or 407 its credentials never got to answer.
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

    /// Whether a PUBLISH's answer to a challenge waits for a stream.
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
            // except one the endpoint is holding until a connection exists:
            // its answer has not been sent yet
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

    /// Refresh what is due, and notice what has lapsed.
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

    /// The soonest a publication has something to do.
    pub(crate) fn publication_deadline(&self) -> Option<Instant> {
        self.publications
            .held
            .values()
            .filter_map(|held| held.machine.poll_timeout())
            .min()
    }
}
