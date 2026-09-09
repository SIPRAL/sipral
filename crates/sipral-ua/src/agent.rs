// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The user agent: one endpoint, and the policy it refuses to have.
//!
//! The shape is the endpoint's, deliberately. Bytes and a time go in, bytes
//! and events come out, and a deadline says when to come back — so anything
//! that could drive a [`sipral_core::endpoint::Endpoint`] can drive this
//! without learning a second way to be driven, and a test can run a week of
//! registration refreshes in a millisecond.
//!
//! What is added is the deciding. The core reports a 401 and stops, because
//! answering one needs a password and answering it wrongly locks an account;
//! here the account holds the password, so the retry happens without asking.
//! The core reports a 200 to a REGISTER and has no opinion about `Expires`;
//! here the binding is refreshed before it lapses, for as long as the process
//! runs. The core reports a timeout; here it becomes a back-off with a drawn
//! interval, so that a thousand phones that lost the same server do not all
//! come back in the same second.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use sipral_core::dialog::CallId;
use sipral_core::endpoint::{
    Endpoint, EndpointConfig, Event, FailureReason, Input, OutgoingRequest, ReceiveError, Transmit,
    TransportId,
};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, StatusCode};
use sipral_core::replay::Driven;
use sipral_core::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteClient, TransactionId,
};

use crate::account::{Account, AccountId};
use crate::announce::{Announcement, Arrival, WINDOW};
use crate::call::{Call, CallHandle, Refusal};
use crate::error::UaError;
use crate::event::{RegistrationFailure, RegistrationState, UaEvent};
use crate::lifecycle::Machine;
use crate::registration::{
    ANSWERS, Registration, backoff_delay, echoed, granted_expiry, min_expires, retry_after,
};
use crate::renegotiate::ParkedOffer;
use crate::screening::Guard;
use crate::subscription::{Subscription, SubscriptionHandle};

/// One user agent: several accounts over one endpoint.
#[derive(Debug)]
pub struct UserAgent {
    pub(crate) endpoint: Endpoint,
    pub(crate) accounts: HashMap<AccountId, Account>,
    pub(crate) registrations: HashMap<AccountId, Registration>,
    /// Which account a transaction belongs to. A challenge answered gives a
    /// new transaction, so this moves rather than being written once.
    owners: HashMap<AnyTransactionId, AccountId>,
    pub(crate) calls: HashMap<CallHandle, Call>,
    /// The three ways a call is reached from an event: by the INVITE this end
    /// sent, by the one the far end sent, and by the dialog either opened.
    pub(crate) by_invite: HashMap<TransactionId<InviteClient>, CallHandle>,
    pub(crate) by_server: HashMap<TransactionId<InviteServer>, CallHandle>,
    pub(crate) by_dialog: HashMap<DialogId, CallHandle>,
    /// The BYEs, CANCELs, PRACKs, REFERs and NOTIFYs a call has in flight, so
    /// that their answers are this layer's news rather than the application's.
    pub(crate) by_request: HashMap<AnyTransactionId, CallHandle>,
    /// The account behind each of those, kept beside rather than inside the
    /// call: a BYE outlives the call it ended, and a challenge to it can only
    /// be answered by whoever still knows the password.
    pub(crate) account_of: HashMap<AnyTransactionId, AccountId>,
    /// The re-INVITEs and UPDATEs offering a session change.
    pub(crate) by_offer: HashMap<AnyTransactionId, CallHandle>,
    /// Refusals of an INVITE that carried a challenge, held until the drain
    /// ends. Whether one was a refusal or the first half of a retry is decided
    /// by whether a challenge follows it.
    pub(crate) challenged: HashMap<TransactionId<InviteClient>, Refusal>,
    /// The same, for a session change: an offer refused with a challenge is
    /// not refused until the drain ends without a retry.
    pub(crate) challenged_offers: HashMap<AnyTransactionId, ParkedOffer>,
    /// The subscriptions this layer is keeping alive (RFC 6665), by the handle
    /// the application holds. A subscription that has ended is removed rather
    /// than kept in a terminated state: nothing else names it, and a record
    /// left behind is one a later sweep would visit for ever.
    pub(crate) subscriptions: HashMap<SubscriptionHandle, Subscription>,
    /// The SUBSCRIBE each one has in flight. One entry per subscription,
    /// replaced when it sends the next, so a refresh an hour does not grow it.
    pub(crate) by_subscribe: HashMap<AnyTransactionId, SubscriptionHandle>,
    pub(crate) events: VecDeque<UaEvent>,
    /// What an incoming INVITE meets before anything else here does, and the
    /// count of what it turned away.
    pub(crate) guard: Guard,
    /// 64·T1, read off the configuration once. RFC 6665 §4.1.2.4's Timer N is
    /// the only deadline this layer takes from the transaction timings, and
    /// the endpoint does not hand its configuration back out.
    pub(crate) timer_n: Duration,
    /// What the operating system last said about sleeping, moving and losing a
    /// network, and how far up the recovery ladder that left this.
    pub(crate) life: Machine,
    /// Calls a push said were coming and whose INVITE has not arrived yet.
    /// A handful at most, and each one leaves within the window.
    pub(crate) announcements: Vec<Announcement>,
    /// And what each incoming call looked like when it arrived, so that a push
    /// which lost the race to its own INVITE can still find it.
    pub(crate) arrivals: HashMap<CallHandle, Arrival>,
    pub(crate) announce_window: Duration,
    /// When the application said this process was launched or woken, for the
    /// time-to-ready measurement. Nothing here reads a clock.
    pub(crate) cold: Option<Instant>,
    next_account: u32,
    pub(crate) next_call: u32,
    pub(crate) next_subscription: u32,
    pub(crate) next_announcement: u32,
}

impl UserAgent {
    /// A user agent with no accounts.
    ///
    /// `seed` is the endpoint's: thirty-two bytes of entropy from which every
    /// branch, tag, `Call-ID` and back-off interval is derived. Two agents must
    /// never be given the same one.
    #[must_use]
    pub fn new(config: EndpointConfig, seed: [u8; 32]) -> Self {
        let timer_n = config.timers.sixty_four_t1();
        Self {
            endpoint: Endpoint::new(config, seed),
            accounts: HashMap::new(),
            registrations: HashMap::new(),
            owners: HashMap::new(),
            calls: HashMap::new(),
            by_invite: HashMap::new(),
            by_server: HashMap::new(),
            by_dialog: HashMap::new(),
            by_request: HashMap::new(),
            account_of: HashMap::new(),
            by_offer: HashMap::new(),
            challenged: HashMap::new(),
            challenged_offers: HashMap::new(),
            subscriptions: HashMap::new(),
            by_subscribe: HashMap::new(),
            events: VecDeque::new(),
            guard: Guard::default(),
            timer_n,
            life: Machine::default(),
            announcements: Vec::new(),
            arrivals: HashMap::new(),
            announce_window: WINDOW,
            cold: None,
            next_account: 0,
            next_call: 0,
            next_subscription: 0,
            next_announcement: 0,
        }
    }

    /// Bytes, or news about a transport.
    ///
    /// # Errors
    /// As [`Endpoint::receive`].
    pub fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        // where the bytes came from is on the input and nowhere else by the
        // time an event names them, and screening an INVITE needs it
        self.guard.arrived(&input);
        let bound = crate::announce::bound_transport(&input);
        let outcome = self.endpoint.receive(input, now);
        if let Some(transport) = bound {
            self.on_transport_bound(transport, now);
        }
        self.drain(now);
        outcome
    }

    /// Time has passed: the endpoint's timers, and this layer's own.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.endpoint.handle_timeout(now);
        self.fire_due(now);
        self.fire_call_timers(now);
        self.fire_subscription_timers(now);
        self.fire_lifecycle_timers(now);
        self.fire_announce_timers(now);
        self.drain(now);
    }

    /// Bytes to put on a transport. Drain to empty.
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.endpoint.poll_transmit()
    }

    /// Something the application has to know. Drain to empty.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<UaEvent> {
        self.events.pop_front()
    }

    /// When to call [`UserAgent::handle_timeout`], if nothing arrives first.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mine = self
            .registrations
            .values()
            .filter_map(|reg| reg.due)
            .chain(self.call_deadline())
            .chain(self.subscription_deadline())
            .chain(self.lifecycle_deadline())
            .chain(self.announce_deadline())
            .min();
        match (self.endpoint.poll_timeout(), mine) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    /// The endpoint underneath, for what this layer has no policy for yet.
    ///
    /// What this layer has no policy for arrives as [`UaEvent::Unclaimed`] and
    /// is answered through here. Registration, calls, transfers and
    /// subscriptions are not among them: a REGISTER or a SUBSCRIBE sent from
    /// here would be one this layer does not know it owns, and would neither
    /// be refreshed nor retried.
    #[must_use]
    pub const fn endpoint(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }
}

/// A recorded session is fed back into whichever layer the bug is thought to
/// be in (`docs/18-replay.md`), and registration, back-off and call policy are
/// decided here rather than below. So the same two calls again, under the
/// trait a replay drives.
impl Driven for UserAgent {
    fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        Self::receive(self, input, now)
    }

    fn handle_timeout(&mut self, now: Instant) {
        Self::handle_timeout(self, now);
    }
}

// -- accounts ----------------------------------------------------------------

impl UserAgent {
    /// Take an account. Nothing is sent until [`UserAgent::register`].
    pub fn add_account(&mut self, account: Account) -> AccountId {
        let id = AccountId(self.next_account);
        self.next_account = self.next_account.wrapping_add(1);
        // §10.2.4: one Call-ID for every registration of a boot cycle, so the
        // registrar reads a refresh as a refresh rather than as a second device
        let call_id = CallId::new(&self.endpoint.token());
        let asking = account.expires;
        self.registrations
            .insert(id, Registration::new(call_id, asking));
        self.accounts.insert(id, account);
        id
    }

    /// Forget an account, and everything scheduled for it.
    ///
    /// No de-registration goes out: an account being removed may be one whose
    /// registrar is unreachable, and blocking on that is not this call's job.
    /// Call [`UserAgent::unregister`] first when the binding should be given
    /// up politely.
    pub fn remove_account(&mut self, account: AccountId) {
        self.accounts.remove(&account);
        self.registrations.remove(&account);
        self.owners.retain(|_, owner| *owner != account);
    }

    /// What was configured, read back.
    #[must_use]
    pub fn account(&self, account: AccountId) -> Option<&Account> {
        self.accounts.get(&account)
    }

    /// Where an account's registration is.
    #[must_use]
    pub fn registration_state(&self, account: AccountId) -> Option<RegistrationState> {
        self.registrations.get(&account).map(|reg| reg.state)
    }

    /// Register, and keep the binding alive until told otherwise.
    ///
    /// Refreshes, credential retries and back-off after a failure all happen
    /// without another call. What stops it is [`UserAgent::unregister`], or a
    /// refusal that trying again cannot fix.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], or [`UaError::Send`] when the REGISTER
    /// cannot be built or the transport is unknown.
    pub fn register(&mut self, account: AccountId, now: Instant) -> Result<(), UaError> {
        self.send_register(account, false, now)?;
        self.drain(now);
        Ok(())
    }

    /// Give up the binding: a REGISTER with `Expires: 0` (§10.2.5).
    ///
    /// Only this device's binding. A `Contact: *` would remove every binding
    /// the address of record has, including the ones belonging to the desk
    /// phone somebody else is holding.
    ///
    /// # Errors
    /// As [`UserAgent::register`].
    pub fn unregister(&mut self, account: AccountId, now: Instant) -> Result<(), UaError> {
        self.send_register(account, true, now)?;
        self.drain(now);
        Ok(())
    }
}

// -- sending -----------------------------------------------------------------

impl UserAgent {
    pub(crate) fn send_register(
        &mut self,
        account: AccountId,
        unregistering: bool,
        now: Instant,
    ) -> Result<(), UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        let reg = self
            .registrations
            .get(&account)
            .ok_or(UaError::NoSuchAccount)?;
        let refreshing = reg.is_bound() && !unregistering;
        let expires = if unregistering {
            Duration::ZERO
        } else {
            reg.asking
        };

        let request = build_register(config, reg, expires);
        // §22.2: a registrar that has challenged this account before gets the
        // credentials on the way in, rather than a REGISTER it has to refuse
        // first. Nothing is added unless it has, so the first one of the boot
        // is unchanged; what this saves is the 401 and the round trip after it
        // on every refresh for the life of the process
        let id = match config.credentials.clone() {
            Some(credentials) => {
                self.endpoint
                    .request_with_credentials(&request, &credentials, now)?
            }
            None => self.endpoint.request(&request, now)?,
        };

        let Some(reg) = self.registrations.get_mut(&account) else {
            return Err(UaError::NoSuchAccount);
        };
        reg.cseq = reg.cseq.saturating_add(1);
        reg.transaction = Some(id);
        reg.unregistering = unregistering;
        reg.unanswered = None;
        reg.due = None;
        reg.owed = false;
        // a fresh attempt gets the whole allowance again: a password can be
        // corrected while the process runs, and a refresh an hour later is not
        // the attempt that was refused
        reg.answered = 0;
        reg.state = if unregistering {
            RegistrationState::Unregistered
        } else if refreshing {
            RegistrationState::Refreshing
        } else {
            RegistrationState::Registering
        };
        // one entry per account: the previous attempt is over, and keeping its
        // handle would only grow the map by one per refresh for ever
        self.owners.retain(|_, owner| *owner != account);
        self.owners
            .insert(AnyTransactionId::NonInviteClient(id), account);

        // an in-flight de-registration says nothing until it is answered; the
        // other two are worth reporting the moment they leave
        if !unregistering {
            let event = if refreshing {
                UaEvent::Refreshing { account }
            } else {
                UaEvent::Registering { account }
            };
            self.events.push_back(event);
        }
        Ok(())
    }

    /// Whatever this layer scheduled for itself: a refresh, or a retry.
    fn fire_due(&mut self, now: Instant) {
        let due: Vec<AccountId> = self
            .registrations
            .iter()
            .filter(|(_, reg)| reg.due.is_some_and(|at| at <= now))
            .map(|(id, _)| *id)
            .collect();
        for account in due {
            if let Some(reg) = self.registrations.get_mut(&account) {
                reg.due = None;
            }
            // A failure here is a refresh that could not leave, which is not
            // the same thing as a registrar that refused. The transport can
            // have gone since the refresh was scheduled -- which is the normal
            // case on a machine that slept: the deadline falls due before the
            // socket has been rebuilt -- so it backs off and tries again
            // rather than declaring the account dead for the life of the
            // process. Nothing on the wire said otherwise.
            if let Err(error) = self.send_register(account, false, now) {
                self.retry_later(account, None, None, None, now);
                let _ = error;
            }
        }
    }
}

/// The REGISTER for one account (§10.2.1).
fn build_register(account: &Account, reg: &Registration, expires: Duration) -> OutgoingRequest {
    let seconds = expires.as_secs().to_string();
    let mut request = OutgoingRequest::new(
        Method::Register,
        account.registrar.clone(),
        account.transport,
        account.remote,
    )
    .to(&account.to_value())
    .from(&account.sender_value())
    .call_id(reg.call_id.clone())
    .cseq(reg.cseq.saturating_add(1))
    // the one request the RFC 8599 push parameters belong in, and a
    // de-registration leaves the identifier out of them (§4.1.2)
    .contact(&account.register_contact_value(expires.is_zero()))
    .header(HeaderName::Expires, seconds.as_bytes());
    for extra in &account.extra {
        if let Some(name) = HeaderName::from_bytes(&extra.name) {
            request = request.header(name, &extra.value);
        }
    }
    request
}

// -- what comes back ---------------------------------------------------------

impl UserAgent {
    /// Turn everything the endpoint has to say into what the application does.
    pub(crate) fn drain(&mut self, now: Instant) {
        while let Some(event) = self.endpoint.poll_event() {
            if let Some(event) = self.on_core_event(event, now) {
                self.events.push_back(UaEvent::Unclaimed(event));
            }
        }
        self.settle_challenges();
        self.settle_call_challenges(now);
        self.settle_offer_challenges();
        self.settle_subscription_challenges(now);
        self.settle_announcements(now);
    }

    /// `None` when this layer claimed the event; the event back when nothing
    /// here has a policy for it, in which case it reaches the application
    /// unchanged.
    ///
    /// The chain is ordered, and the order is part of what each link means. A
    /// handler added here goes where its subject is first touched, not at the
    /// end: screening decides whether an INVITE becomes anything at all, so it
    /// runs above the call handler that would otherwise mint the call and
    /// queue the event, and a policy consulted after that has been asked about
    /// something the application has already seen.
    fn on_core_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let event = self.on_screening_event(event, now)?;
        // Screening first, so a scanner that writes a Require header still
        // meets the rate limiter. Then this, before every handler that acts on
        // a request -- OPTIONS included, which used to answer 200 to anything
        // it was handed and so answered 200 to a Require it could not honour.
        // §8.2.2.3 refuses the request; it does not undo what honouring it did.
        let event = self.on_require_event(event, now)?;
        let event = self.on_options_event(event, now)?;
        let event = self.on_registration_event(event, now)?;
        let event = self.on_call_event(event, now)?;
        let event = self.on_reliable_event(event, now)?;
        let event = self.on_transfer_event(event, now)?;
        // Below transfer, and it has to be: both claim NOTIFYs, and they
        // divide them by the `Event` header. Transfer claims the `refer`
        // package inside a call it is running -- a subscription this machine
        // never opened, because RFC 3515 §2.4.4 opens it with a REFER rather
        // than with a SUBSCRIBE -- and everything it leaves is either one of
        // these subscriptions or nobody's. This one is what says which, and
        // RFC 6665 §4.1.3 leaves exactly one answer for nobody's: a 481. That
        // answer can only be given once everything holding a subscription of
        // its own has had its turn, which is what puts the general case under
        // the special one rather than over it.
        let event = self.on_subscription_event(event, now)?;
        self.on_session_event(event, now)
    }

    /// `None` when the event belonged to a registration and has been dealt
    /// with; the event back when it did not.
    fn on_registration_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::Response {
                transaction,
                status,
                ref response,
            } => {
                // a REGISTER and an UPDATE are both non-INVITE transactions,
                // and dropping the ones that are not ours would take the
                // answer to somebody else's request with them
                let Some(account) = self.owner_of(transaction) else {
                    return Some(event);
                };
                let response = response.clone();
                self.on_response(account, status, &response, now);
                None
            }
            Event::RequestFailed {
                transaction,
                reason,
            } => {
                let Some(account) = self.owner_of(transaction) else {
                    return Some(event);
                };
                self.on_request_failed(account, reason, now);
                None
            }
            Event::Challenged { transaction, .. } => {
                let Some(account) = self.owners.get(&transaction).copied() else {
                    return Some(event);
                };
                self.on_challenged(account, transaction, now);
                None
            }
            // the flow a binding lives on is dead (RFC 5626 §4.4.1), and the
            // application still has to hear it: it owns the socket
            Event::FlowFailed { transport } => {
                self.on_flow_failed(transport, now);
                Some(event)
            }
            Event::TransactionTerminated { transaction, .. } => {
                // plumbing this layer owns: a registration transaction ends
                // after every registration, and the application is told about
                // the binding rather than about the transaction
                if self.owners.contains_key(&transaction) {
                    self.forget_transaction(transaction);
                    return None;
                }
                Some(event)
            }
            other => Some(other),
        }
    }

    fn owner_of(&self, transaction: TransactionId<NonInviteClient>) -> Option<AccountId> {
        self.owners
            .get(&AnyTransactionId::NonInviteClient(transaction))
            .copied()
    }

    /// A registration transaction has ended.
    ///
    /// The mapping stays. A transaction that times out is retired *before* the
    /// failure it caused is reported — the core sends the news about the
    /// machine first and the news about the request second — so forgetting who
    /// owned it here would make the failure that follows look like somebody
    /// else's. It is replaced when the account sends its next REGISTER, which
    /// keeps one entry per account rather than one per attempt.
    fn forget_transaction(&mut self, transaction: AnyTransactionId) {
        let Some(account) = self.owners.get(&transaction).copied() else {
            return;
        };
        if let (Some(reg), AnyTransactionId::NonInviteClient(id)) =
            (self.registrations.get_mut(&account), transaction)
            && reg.transaction == Some(id)
        {
            reg.transaction = None;
        }
    }

    fn on_response(
        &mut self,
        account: AccountId,
        status: StatusCode,
        response: &OwnedMessage,
        now: Instant,
    ) {
        if status.is_provisional() {
            // a registrar that says it is working on it is not a result
            return;
        }
        if status.is_success() {
            self.on_registered(account, response, now);
            return;
        }
        match status.get() {
            // held until the end of the drain: whether this is answerable is
            // decided by whether a challenge follows it
            401 | 407 => {
                if let Some(reg) = self.registrations.get_mut(&account) {
                    reg.unanswered = Some(response.clone());
                }
            }
            // §10.2.8: ask for what the registrar demands, once
            423 => self.on_interval_too_brief(account, response, now),
            300..=399 => self.give_up(
                account,
                RegistrationFailure::Redirected,
                Some(status),
                Some(response.clone()),
            ),
            500..=599 => self.retry_later(
                account,
                Some(status),
                Some(response.clone()),
                retry_after(&response.as_raw()),
                now,
            ),
            _ => self.give_up(
                account,
                RegistrationFailure::Rejected,
                Some(status),
                Some(response.clone()),
            ),
        }
    }

    fn on_registered(&mut self, account: AccountId, response: &OwnedMessage, now: Instant) {
        let Some(config) = self.accounts.get(&account) else {
            return;
        };
        let Some(reg) = self.registrations.get(&account) else {
            return;
        };
        if reg.unregistering {
            let Some(reg) = self.registrations.get_mut(&account) else {
                return;
            };
            reg.state = RegistrationState::Unregistered;
            reg.unregistering = false;
            reg.failures = 0;
            reg.due = None;
            self.events.push_back(UaEvent::Unregistered { account });
            return;
        }

        let granted =
            granted_expiry(&response.as_raw(), &config.contact, reg.asking).unwrap_or(reg.asking);
        let echo = echoed(&response.as_raw(), config);
        // a granted zero is a binding the registrar did not keep; there is
        // nothing to refresh and nothing to celebrate
        if granted.is_zero() {
            self.give_up(
                account,
                RegistrationFailure::Rejected,
                Some(StatusCode::OK),
                Some(response.clone()),
            );
            return;
        }

        let cold = self.cold;
        let Some(reg) = self.registrations.get_mut(&account) else {
            return;
        };
        reg.echo = echo;
        let refresh_in = reg.bound(granted, cold, now);
        reg.state = RegistrationState::Registered;
        reg.failures = 0;
        reg.raised = false;
        reg.due = Some(now + refresh_in);
        self.events.push_back(UaEvent::Registered {
            account,
            expires: granted,
            refresh_in,
        });
        self.registration_proved();
    }

    /// §10.2.8: "a UA receives a 423 ... it MAY retry the registration after
    /// making the expiration interval ... equal to or greater than the
    /// expiration interval within the Min-Expires header field".
    fn on_interval_too_brief(&mut self, account: AccountId, response: &OwnedMessage, now: Instant) {
        let demanded = min_expires(&response.as_raw());
        let already_raised = self
            .registrations
            .get(&account)
            .is_some_and(|reg| reg.raised);
        let Some(demanded) = demanded.filter(|_| !already_raised) else {
            // no Min-Expires to obey, or a second 423 after we already met the
            // first: the registrar is contradicting itself, and asking again
            // with the same number would loop
            self.give_up(
                account,
                RegistrationFailure::Rejected,
                StatusCode::new(423).ok(),
                Some(response.clone()),
            );
            return;
        };
        if let Some(reg) = self.registrations.get_mut(&account) {
            reg.asking = demanded;
            reg.raised = true;
        }
        if self.send_register(account, false, now).is_err() {
            self.give_up(account, RegistrationFailure::Unreachable, None, None);
        }
    }

    /// A keep-alive went unanswered and the flow is gone (RFC 5626 §4.4.1).
    ///
    /// §4.4: "If a flow with a registration has failed, the UA follows the
    /// procedures in Section 4.2 to form a new flow to replace the failed one."
    /// Forming it is the application's — nothing here opens a socket — and what
    /// this layer owes is the rest: the binding is not live any more, and the
    /// REGISTER that says so again goes on the §4.5 back-off rather than at
    /// once, because a server that has just lost a thousand flows does not want
    /// them all back in the same second.
    ///
    /// Only a settled binding is touched. One with a REGISTER in flight loses
    /// its transaction with the transport and is retried by the failure that
    /// follows, and counting the same outage twice would double the wait.
    fn on_flow_failed(&mut self, transport: TransportId, now: Instant) {
        let lost: Vec<AccountId> = self
            .accounts
            .iter()
            .filter(|(id, account)| {
                account.transport == transport
                    && self
                        .registrations
                        .get(id)
                        .is_some_and(|reg| reg.state == RegistrationState::Registered)
            })
            .map(|(id, _)| *id)
            .collect();
        for account in lost {
            self.retry_later(account, None, None, None, now);
        }
    }

    fn on_request_failed(&mut self, account: AccountId, reason: FailureReason, now: Instant) {
        // §10.2.7: "the UAC SHOULD NOT immediately re-attempt a registration to
        // the same registrar" after a timeout. Neither is a dead transport a
        // reason to stop for good
        let _ = reason;
        self.retry_later(account, None, None, None, now);
    }

    fn on_challenged(&mut self, account: AccountId, transaction: AnyTransactionId, now: Instant) {
        let Some(credentials) = self
            .accounts
            .get(&account)
            .and_then(|config| config.credentials.clone())
        else {
            // nothing to answer with; the refusal stands, and it stands the
            // same way every time, so there is no point trying again
            return;
        };
        // A registrar that draws a fresh nonce for every refusal and never
        // marks it stale walks straight past the same-nonce guard below, and
        // the exchange then runs one wrong password per round trip until the
        // account is locked. Nothing on the wire tells that apart from a
        // server ageing its nonces honestly, so the count is the defence.
        if let Some(reg) = self.registrations.get_mut(&account) {
            if reg.answered >= ANSWERS {
                return;
            }
            reg.answered = reg.answered.saturating_add(1);
        }
        let Ok(retried) = self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        else {
            return;
        };
        self.owners.remove(&transaction);
        self.owners.insert(retried, account);
        if let (Some(reg), AnyTransactionId::NonInviteClient(id)) =
            (self.registrations.get_mut(&account), retried)
        {
            reg.transaction = Some(id);
            reg.unanswered = None;
        }
    }

    /// A refusal that carried a challenge and got no retry was a refusal.
    ///
    /// The core answers a challenge once; the same nonce coming back without
    /// `stale` is §22.1's way of saying the password was wrong, and it stops
    /// reporting it rather than let a client lock the account by repeating it.
    /// Nothing follows the refusal in that case, and that silence is the
    /// answer.
    fn settle_challenges(&mut self) {
        let refused: Vec<(AccountId, Option<OwnedMessage>)> = self
            .registrations
            .iter_mut()
            .filter_map(|(id, reg)| reg.unanswered.take().map(|response| (*id, Some(response))))
            .collect();
        for (account, response) in refused {
            let status = response
                .as_ref()
                .and_then(|message| message.as_raw().status());
            self.give_up(
                account,
                RegistrationFailure::BadCredentials,
                status,
                response,
            );
        }
    }

    /// Something recoverable: schedule the next attempt (RFC 5626 §4.5).
    fn retry_later(
        &mut self,
        account: AccountId,
        status: Option<StatusCode>,
        response: Option<OwnedMessage>,
        asked_for: Option<Duration>,
        now: Instant,
    ) {
        let entropy = self.endpoint.token();
        let Some(reg) = self.registrations.get_mut(&account) else {
            return;
        };
        reg.failures = reg.failures.saturating_add(1);
        // "a 503 response to an earlier failed registration attempt with a
        // Retry-After header field value may cause the UA to wait longer"
        let wait = backoff_delay(reg.failures, &entropy).max(asked_for.unwrap_or(Duration::ZERO));
        reg.state = RegistrationState::Retrying;
        reg.transaction = None;
        reg.unregistering = false;
        reg.due = Some(now + wait);
        self.events.push_back(UaEvent::RegistrationFailed {
            account,
            reason: RegistrationFailure::Unreachable,
            status,
            retry_in: Some(wait),
            response,
        });
    }

    /// Something that trying again cannot fix.
    fn give_up(
        &mut self,
        account: AccountId,
        reason: RegistrationFailure,
        status: Option<StatusCode>,
        response: Option<OwnedMessage>,
    ) {
        if let Some(reg) = self.registrations.get_mut(&account) {
            reg.state = RegistrationState::Failed;
            reg.transaction = None;
            reg.unregistering = false;
            reg.due = None;
        }
        self.events.push_back(UaEvent::RegistrationFailed {
            account,
            reason,
            status,
            retry_in: None,
            response,
        });
    }
}
