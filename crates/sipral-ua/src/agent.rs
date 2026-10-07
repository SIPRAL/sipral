// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The user agent: one endpoint, and the policy it refuses to have.
//!
//! Driven exactly like a [`sipral_core::endpoint::Endpoint`]: bytes and time
//! in, bytes and events out, a deadline for the next call.
//!
//! What it adds is the deciding: answering a 401 with the account's password,
//! refreshing a binding before it lapses, and turning a timeout into a
//! randomised back-off.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::auth::Credentials;
use sipral_core::dialog::CallId;
use sipral_core::endpoint::{
    AuthRetryError, Endpoint, EndpointConfig, Event, FailureReason, Input, OutgoingRequest,
    ReceiveError, SendError, Transmit, TransportId, TransportProtocol,
};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, StatusCode, Uri};
use sipral_core::replay::{Driven, RecordError, Recorder, Recording};
use sipral_core::sdp;
use sipral_core::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteClient, TimerConfigError,
    TransactionId,
};

use crate::account::{Account, AccountId};
use crate::announce::{Announcement, Arrival, WINDOW};
use crate::call::{Call, CallHandle, KeptBranch, Refusal, RequestRefusal};
use crate::error::UaError;
use crate::event::{RegistrationFailure, RegistrationState, UaEvent};
use crate::headers::HeadersFor;
use crate::lifecycle::Machine;
use crate::message::{MessageHandle, SentMessage};
use crate::parked::Parked;
use crate::referral::Referrals;
use crate::registration::{
    Registration, backoff_delay, echoed, granted_expiry, min_expires, read_registrar_info,
    retry_after,
};
use crate::renegotiate::ParkedOffer;
use crate::screening::Guard;
use crate::subscription::{Subscription, SubscriptionHandle};

/// Whether a retry failed because RFC 3261 §18.1.1 wants a connection.
///
/// Not a verdict: the endpoint still holds the challenge and the retry works
/// once a stream transport is bound. Treating it as a failure would report
/// the password as wrong.
pub(crate) fn wants_a_stream(error: &AuthRetryError) -> bool {
    matches!(
        error,
        AuthRetryError::Unsendable(SendError::NeedsStreamTransport)
    )
}

/// One user agent: several accounts over one endpoint.
#[derive(Debug)]
pub struct UserAgent {
    pub(crate) endpoint: Endpoint,
    pub(crate) accounts: HashMap<AccountId, Account>,
    pub(crate) registrations: HashMap<AccountId, Registration>,
    /// Which account a transaction belongs to. Moves when a challenge answer
    /// opens a new transaction.
    owners: HashMap<AnyTransactionId, AccountId>,
    pub(crate) calls: HashMap<CallHandle, Call>,
    pub(crate) by_invite: HashMap<TransactionId<InviteClient>, CallHandle>,
    pub(crate) by_server: HashMap<TransactionId<InviteServer>, CallHandle>,
    pub(crate) by_dialog: HashMap<DialogId, CallHandle>,
    /// The branch [`crate::ForkPolicy::KeepFirst`] kept (or the first to
    /// answer an INVITE already put down), until the INVITE transaction is
    /// retired: a later branch's 2xx must still be acknowledged and hung up
    /// (§13.2.2.4). Kept apart from the calls, which may be over by then.
    pub(crate) kept_branches: HashMap<TransactionId<InviteClient>, KeptBranch>,
    /// In-dialog requests a call has in flight (BYE, CANCEL, PRACK, REFER,
    /// NOTIFY). The method decides what an unsent request leaves behind.
    pub(crate) by_request: HashMap<AnyTransactionId, (CallHandle, Method<'static>)>,
    /// The account behind each of those, kept outside the call: a BYE
    /// outlives its call and a challenge to it still needs the password.
    pub(crate) account_of: HashMap<AnyTransactionId, AccountId>,
    /// The digit an INFO in `by_request` carries, for [`UaEvent::DtmfSent`].
    pub(crate) by_dtmf_info: HashMap<AnyTransactionId, char>,
    /// Digits queued behind the INFO in flight: a 2xx sends the next, anything
    /// else drops the rest. Removed once the last one is answered.
    pub(crate) dtmf_queue: HashMap<CallHandle, crate::dtmf::DtmfQueue>,
    /// The re-INVITEs and UPDATEs offering a session change.
    pub(crate) by_offer: HashMap<AnyTransactionId, CallHandle>,
    /// A hold (`true`) or resume asked for during another session change,
    /// sent once it is over (RFC 3261 §14.1). The last press wins.
    pub(crate) holds_waiting: HashMap<CallHandle, bool>,
    /// INVITE refusals carrying a challenge, held until the drain ends: only
    /// then is it known whether a retry followed.
    pub(crate) challenged: HashMap<TransactionId<InviteClient>, Refusal>,
    /// The same for in-dialog requests. Without it an unretried BYE left the
    /// call `Terminating` for ever, and a REFER blocked later transfers.
    pub(crate) challenged_requests: HashMap<AnyTransactionId, RequestRefusal>,
    /// The same for session changes.
    pub(crate) challenged_offers: HashMap<AnyTransactionId, ParkedOffer>,
    /// Live subscriptions (RFC 6665). Ended ones are removed, not kept.
    pub(crate) subscriptions: HashMap<SubscriptionHandle, Subscription>,
    /// The SUBSCRIBE each one has in flight, one entry per subscription.
    pub(crate) by_subscribe: HashMap<AnyTransactionId, SubscriptionHandle>,
    /// MESSAGEs sent and not yet reported (RFC 3428). Removed when
    /// `UaEvent::MessageSent` goes out.
    pub(crate) messages: HashMap<MessageHandle, SentMessage>,
    /// The MESSAGE transaction each one has in flight.
    pub(crate) by_message: HashMap<AnyTransactionId, MessageHandle>,
    /// The `OPTIONS` probes of an account's server not yet reported.
    pub(crate) probes: crate::probe::Probes,
    /// The event state this agent keeps at a compositor (RFC 3903).
    pub(crate) publications: crate::publishing::Publications,
    /// In-dialog requests too large for a datagram (RFC 3261 §18.1.1),
    /// waiting for a stream.
    pub(crate) parked: Vec<Parked>,
    /// When the wait for a stream ends ([`crate::oversize`]).
    pub(crate) stream_deadline: Option<Instant>,
    /// Size and limit from the latest `TransportWanted`, for the 513 text.
    pub(crate) oversize: Option<(usize, u32)>,
    pub(crate) events: VecDeque<UaEvent>,
    /// Screening for incoming INVITEs, and its refusal counts.
    pub(crate) guard: Guard,
    /// Out-of-dialog REFERs held, and whether any are taken
    /// ([`crate::referral`]).
    pub(crate) referrals: Referrals,
    /// Non-DTMF INFO goes to the application unanswered
    /// ([`UserAgent::hand_over_info`]).
    pub(crate) info_handed_over: bool,
    /// Recording sessions are taken, so `siprec` is understood
    /// ([`UserAgent::accept_recording_sessions`]).
    pub(crate) recording_server: bool,
    /// The registrar flows kept open through a NAT ([`crate::keepalive`]).
    pub(crate) keepalives: crate::keepalive::Keepalives,
    /// The WebSocket connections this agent runs ([`crate::websocket`]).
    pub(crate) websockets: crate::websocket::WebSockets,
    /// The addresses of the accounts that find their server by name.
    pub(crate) locations: crate::locate::Locations,
    /// Accounts on their own connection that asked for one, and when
    /// (`crate::flow`).
    pub(crate) flows_wanted: HashMap<AccountId, Instant>,
    /// Non-registering accounts whose connection was already asked for.
    pub(crate) flows_asked: std::collections::HashSet<AccountId>,
    /// Accounts whose connection was lost since the last round.
    pub(crate) flows_lost: Vec<AccountId>,
    /// 64·T1 for RFC 6665 §4.1.2.4's Timer N, copied once because the
    /// endpoint does not hand its configuration back.
    pub(crate) timer_n: Duration,
    /// Bounds for incoming session descriptions, copied for the same reason.
    pub(crate) sdp_limits: sdp::Limits,
    /// Sleep, move and network-loss state, and the recovery ladder.
    pub(crate) life: Machine,
    /// Push-announced calls whose INVITE has not arrived yet.
    pub(crate) announcements: Vec<Announcement>,
    /// Incoming calls as they arrived, so a push that lost the race to its
    /// INVITE can still find its call.
    pub(crate) arrivals: HashMap<CallHandle, Arrival>,
    pub(crate) announce_window: Duration,
    /// When the process was launched or woken, for time-to-ready.
    pub(crate) cold: Option<Instant>,
    next_account: u32,
    pub(crate) next_call: u32,
    pub(crate) next_subscription: u32,
    pub(crate) next_announcement: u32,
    pub(crate) next_message: u32,
    /// The recording in progress. Only input (`receive`, `handle_timeout`) is
    /// recorded, never what this end sent, so negotiated keys stay out
    /// (`docs/18-replay.md`).
    recorder: Option<Recorder>,
    /// What [`UserAgent::stop_recording`] produced, until
    /// [`UserAgent::clear_stopped_recording`]. Separate from `recorder` so a
    /// caller can ask twice (size, then text) without stopping twice.
    stopped_recording: Option<Result<Recording, RecordError>>,
    /// What [`UserAgent::send_quality_report`] needs (RFC 6035) about a call
    /// already forgotten: the facade sends the report on `CallEnded`, after
    /// the call is gone. Bounded; see `crate::quality_report`.
    pub(crate) quality_report_snapshots: HashMap<CallHandle, crate::quality_report::EndedCall>,
    /// Insertion order for the snapshots, so the oldest is evicted at the
    /// cap. Calls that never had media would otherwise stay for ever.
    pub(crate) quality_report_order: VecDeque<CallHandle>,
    /// Wall clock at a known instant ([`UserAgent::set_wall_clock`]), for
    /// PASSporT signing and verification.
    pub(crate) wall_clock: Option<(Instant, u64)>,
    /// The verification service and the calls waiting on it
    /// ([`crate::stir`]).
    #[cfg(feature = "stir")]
    pub(crate) stir: crate::stir::Service,
}

impl UserAgent {
    /// A user agent with no accounts.
    ///
    /// `seed` is 32 bytes of entropy for every branch, tag, `Call-ID` and
    /// back-off interval. Two agents must never share one.
    ///
    /// # Errors
    /// [`TimerConfigError`] for a zero `timers.t1`, `timers.t2` or
    /// `keepalive_interval`, which would hang `handle_timeout`.
    pub fn new(config: EndpointConfig, seed: [u8; 32]) -> Result<Self, TimerConfigError> {
        let timer_n = config.timers.sixty_four_t1();
        let sdp_limits = config.sdp_limits;
        Ok(Self {
            endpoint: Endpoint::new(config, seed)?,
            recorder: None,
            stopped_recording: None,
            accounts: HashMap::new(),
            registrations: HashMap::new(),
            owners: HashMap::new(),
            calls: HashMap::new(),
            by_invite: HashMap::new(),
            by_server: HashMap::new(),
            by_dialog: HashMap::new(),
            kept_branches: HashMap::new(),
            by_request: HashMap::new(),
            account_of: HashMap::new(),
            by_dtmf_info: HashMap::new(),
            dtmf_queue: HashMap::new(),
            by_offer: HashMap::new(),
            holds_waiting: HashMap::new(),
            challenged: HashMap::new(),
            challenged_requests: HashMap::new(),
            challenged_offers: HashMap::new(),
            subscriptions: HashMap::new(),
            by_subscribe: HashMap::new(),
            messages: HashMap::new(),
            by_message: HashMap::new(),
            probes: crate::probe::Probes::default(),
            publications: crate::publishing::Publications::default(),
            parked: Vec::new(),
            stream_deadline: None,
            oversize: None,
            events: VecDeque::new(),
            guard: Guard::default(),
            referrals: Referrals::default(),
            info_handed_over: false,
            recording_server: false,
            keepalives: crate::keepalive::Keepalives::default(),
            websockets: crate::websocket::WebSockets::default(),
            locations: crate::locate::Locations::default(),
            flows_wanted: HashMap::new(),
            flows_asked: std::collections::HashSet::new(),
            flows_lost: Vec::new(),
            timer_n,
            sdp_limits,
            life: Machine::default(),
            announcements: Vec::new(),
            arrivals: HashMap::new(),
            announce_window: WINDOW,
            cold: None,
            next_account: 0,
            next_call: 0,
            next_subscription: 0,
            next_announcement: 0,
            next_message: 0,
            quality_report_snapshots: HashMap::new(),
            quality_report_order: VecDeque::new(),
            wall_clock: None,
            #[cfg(feature = "stir")]
            stir: crate::stir::Service::default(),
        })
    }

    /// What the wall clock read at the instant `at`, as Unix seconds.
    ///
    /// PASSporT signing and verification need real time (RFC 8225 §5.1.1)
    /// and nothing here reads a clock; later times are `at` plus monotonic
    /// distance. Set it again whenever the platform clock is stepped.
    pub fn set_wall_clock(&mut self, at: Instant, unix_seconds: u64) {
        self.wall_clock = Some((at, unix_seconds));
    }

    /// Whether [`UserAgent::set_wall_clock`] has been called.
    #[must_use]
    pub const fn knows_the_time(&self) -> bool {
        self.wall_clock.is_some()
    }

    /// The wall clock at `now`, in whole seconds since 1970, once it has
    /// been set. An instant before the one it was set at reads as that one.
    #[cfg_attr(not(feature = "stir"), allow(dead_code))]
    pub(crate) fn unix_at(&self, now: Instant) -> Option<u64> {
        self.wall_clock
            .map(|(at, unix)| unix.saturating_add(now.saturating_duration_since(at).as_secs()))
    }

    /// Bytes, or news about a transport.
    ///
    /// # Errors
    /// As [`Endpoint::receive`].
    pub fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        // recorded first; WebSocket bytes are recorded raw and re-framed on
        // replay
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.arrived(&input, now);
        }
        let outcome = match self.websocket_input(input, now) {
            Some(outcome) => outcome,
            None => self.take(input, now),
        };
        self.drain(now);
        outcome
    }

    /// [`UserAgent::receive`] without the recording and the drain.
    pub(crate) fn take(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        // the source address is lost by the time an event arrives, and
        // screening needs it
        self.guard.arrived(&input);
        let bound = crate::announce::bound_transport(&input);
        let lost = match input {
            Input::TransportFailed { transport, .. } | Input::StreamClosed { transport } => {
                Some(transport)
            }
            _ => None,
        };
        let outcome = self.endpoint.receive(input, now);
        if let Some(transport) = lost {
            self.flow_lost(transport);
        }
        if let Some(transport) = bound {
            // a WebSocket this agent runs names itself before anything is
            // written on it (RFC 7118 Appendix B.1)
            if let Some(name) = self.websockets.name_of(transport) {
                let name = name.to_owned();
                self.endpoint.advertise_name(transport, &name);
            }
            self.on_transport_bound(transport, now);
        }
        outcome
    }

    /// Time has passed: the endpoint's timers, and this layer's own.
    pub fn handle_timeout(&mut self, now: Instant) {
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.woke(now);
        }
        self.endpoint.handle_timeout(now);
        self.fire_due(now);
        self.fire_call_timers(now);
        self.fire_subscription_timers(now);
        self.fire_lifecycle_timers(now);
        self.fire_announce_timers(now);
        self.fire_keepalives(now);
        self.fire_locations(now);
        #[cfg(feature = "stir")]
        self.fire_stir_timers(now);
        self.fire_publication_timers(now);
        self.fire_stream_wait(now);
        self.fire_websockets(now);
        self.drain(now);
    }

    /// Starts recording every [`UserAgent::receive`] and
    /// [`UserAgent::handle_timeout`] from here on (`docs/18-replay.md`).
    ///
    /// Starting and stopping reseed the endpoint one way
    /// ([`Endpoint::reseed`]) and the recording carries the fresh seed, so it
    /// predicts no identifier drawn outside it. A recording already running
    /// is discarded.
    ///
    /// `note` is one line for whoever opens the file. A multi-line note is
    /// accepted here and becomes [`RecordError::NotOneLine`] at
    /// [`UserAgent::stop_recording`].
    pub fn start_recording(&mut self, note: Option<&str>) {
        let seed = self.endpoint.reseed();
        let recorder = match note {
            Some(note) => Recorder::new(seed).about(note),
            None => Recorder::new(seed),
        };
        self.recorder = Some(recorder);
        self.stopped_recording = None;
    }

    /// Stops the recording and holds the result until
    /// [`UserAgent::clear_stopped_recording`].
    ///
    /// `None` when nothing was running or waiting. Calling again before
    /// clearing returns the same result, so a caller can ask once for the
    /// size and once for the text.
    ///
    /// `Some(Err(_))` when something fed could not be recorded (a non-text
    /// body, `docs/18-replay.md`); no partial recording is produced.
    pub fn stop_recording(&mut self) -> Option<Result<&Recording, RecordError>> {
        if self.stopped_recording.is_none() {
            self.stopped_recording = Some(self.recorder.take()?.finish());
            let _ = self.endpoint.reseed();
        }
        self.stopped_recording
            .as_ref()
            .map(|result| result.as_ref().map_err(|error| *error))
    }

    /// Discards the result [`UserAgent::stop_recording`] is holding, if any.
    pub fn clear_stopped_recording(&mut self) {
        self.stopped_recording = None;
    }

    /// Whether a recording is running. `false` from the first
    /// [`UserAgent::stop_recording`], collected or not.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recorder.is_some()
    }

    /// Bytes to put on a transport. Drain to empty.
    ///
    /// The endpoint's output, then NAT keep-alives ([`crate::keepalive`]). On
    /// a WebSocket this agent runs ([`crate::websocket`]) these are frames:
    /// handshake, masked messages, and control frames.
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        loop {
            if let Some(own) = self.poll_websocket() {
                return Some(own);
            }
            let transmit = self
                .endpoint
                .poll_transmit()
                .or_else(|| self.poll_keepalive())?;
            if let Some(framed) = self.websocket_frame(transmit) {
                return Some(framed);
            }
        }
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
            .chain(self.keepalive_deadline())
            .chain(self.location_deadline())
            .chain(self.verification_deadline())
            .chain(self.publication_deadline())
            .chain(self.stream_deadline)
            .chain(self.websockets.deadline())
            .min();
        match (self.endpoint.poll_timeout(), mine) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    /// When the next call waiting for its certificate stops waiting.
    #[cfg(feature = "stir")]
    fn verification_deadline(&self) -> Option<Instant> {
        self.stir_deadline()
    }

    /// Without the feature no call ever waits for one.
    #[cfg(not(feature = "stir"))]
    #[allow(clippy::unused_self)]
    const fn verification_deadline(&self) -> Option<Instant> {
        None
    }

    /// The endpoint underneath, for what this layer has no policy for yet.
    ///
    /// Used to answer a non-DTMF INFO after [`UserAgent::hand_over_info`];
    /// every other unclaimed request is answered by this layer (§8.2.1, RFC
    /// 5057 §5.3). Do not send REGISTER or SUBSCRIBE through it: this layer
    /// would not know it owns them and would neither refresh nor retry them.
    #[must_use]
    pub const fn endpoint(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }

    /// The endpoint underneath, shared, to read counters such as
    /// [`Endpoint::retransmissions`] and [`Endpoint::refused`].
    #[must_use]
    pub const fn endpoint_ref(&self) -> &Endpoint {
        &self.endpoint
    }
}

/// Lets a replay drive this layer, where registration and call policy live
/// (`docs/18-replay.md`).
impl Driven for UserAgent {
    fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError> {
        Self::receive(self, input, now)
    }

    fn handle_timeout(&mut self, now: Instant) {
        Self::handle_timeout(self, now);
    }

    fn resolved(
        &mut self,
        dialog: DialogId,
        addresses: &[SocketAddr],
        protocol: Option<TransportProtocol>,
    ) {
        self.endpoint.resolved(dialog, addresses, protocol);
    }
}

// -- accounts ----------------------------------------------------------------

impl UserAgent {
    /// Take an account. Nothing is sent until [`UserAgent::register`], and
    /// nothing ever is for an account that has no registrar.
    pub fn add_account(&mut self, account: Account) -> AccountId {
        // RFC 8588 §5 origid, drawn once so every call of the account shares it
        #[cfg(feature = "stir")]
        let account = {
            let mut account = account;
            if account
                .stir_signing
                .as_ref()
                .is_some_and(|signing| signing.origid.is_none())
            {
                let drawn = self.draw_origid();
                if let Some(signing) = account.stir_signing.as_mut() {
                    signing.origid = Some(drawn);
                }
            }
            account
        };
        let id = AccountId(self.next_account);
        self.next_account = self.next_account.wrapping_add(1);
        // §10.2.4: one Call-ID per boot cycle, so a refresh is not read as a
        // second device
        let call_id = CallId::new(&self.endpoint.token());
        let asking = account.expires;
        let mut registration = Registration::new(call_id, asking);
        // set once and never changed
        if account.registrar.is_none() {
            registration.state = RegistrationState::NotRegistering;
        }
        self.registrations.insert(id, registration);
        self.accounts.insert(id, account);
        id
    }

    /// Forget an account, and everything scheduled for it.
    ///
    /// No de-registration goes out, since the registrar may be unreachable.
    /// Call [`UserAgent::unregister`] first to give the binding up.
    pub fn remove_account(&mut self, account: AccountId) {
        self.accounts.remove(&account);
        self.registrations.remove(&account);
        self.owners.retain(|_, owner| *owner != account);
        self.forget_keepalive(account);
        self.forget_location(account);
        self.flows_wanted.remove(&account);
        self.flows_asked.remove(&account);
        self.forget_publications(account);
    }

    /// What was configured, read back.
    #[must_use]
    pub fn account(&self, account: AccountId) -> Option<&Account> {
        self.accounts.get(&account)
    }

    /// Every account this agent holds, oldest first.
    #[must_use]
    pub fn accounts(&self) -> Vec<AccountId> {
        let mut held: Vec<AccountId> = self.accounts.keys().copied().collect();
        held.sort_unstable();
        held
    }

    /// Give an account the OAuth 2.0 access token its server asked for
    /// (RFC 8898), in place of any it had; `None` takes it away. The
    /// password, if the account has one, stays.
    ///
    /// The answer to [`UaEvent::TokenRequired`], and the way to renew a token
    /// early. Used from the next request on; nothing is sent here. A
    /// registration that failed for want of a token restarts with
    /// [`UserAgent::register`].
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], or [`UaError::InvalidAccessToken`] for a
    /// token that is not RFC 6750 §2.1's `b64token`, with nothing changed.
    pub fn set_access_token(
        &mut self,
        account: AccountId,
        token: Option<&str>,
    ) -> Result<(), UaError> {
        let config = self
            .accounts
            .get_mut(&account)
            .ok_or(UaError::NoSuchAccount)?;
        let renewed = match (config.credentials.as_deref(), token) {
            (Some(credentials), token) => credentials.renewed(token),
            (None, Some(token)) => Credentials::bearer(token),
            (None, None) => return Ok(()),
        }
        .map_err(|_| UaError::InvalidAccessToken)?;
        config.credentials =
            (renewed.has_password() || renewed.has_access_token()).then(|| Arc::new(renewed));
        Ok(())
    }

    /// Where an account's registration is.
    #[must_use]
    pub fn registration_state(&self, account: AccountId) -> Option<RegistrationState> {
        self.registrations.get(&account).map(|reg| reg.state)
    }

    /// Register, and keep the binding alive until told otherwise.
    ///
    /// Refreshes, credential retries and back-off happen by themselves until
    /// [`UserAgent::unregister`] or a refusal that retrying cannot fix.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], [`UaError::NoRegistrar`] for an account
    /// that never registers, or [`UaError::Send`] when the REGISTER cannot be
    /// built or the transport is unknown.
    pub fn register(&mut self, account: AccountId, now: Instant) -> Result<(), UaError> {
        self.send_register(account, false, now)?;
        self.drain(now);
        Ok(())
    }

    /// Give up the binding: a REGISTER with `Expires: 0` (§10.2.5).
    ///
    /// Only this device's binding; `Contact: *` would remove every device's.
    ///
    /// # Errors
    /// As [`UserAgent::register`].
    pub fn unregister(&mut self, account: AccountId, now: Instant) -> Result<(), UaError> {
        self.send_register(account, true, now)?;
        self.drain(now);
        Ok(())
    }

    /// Point an account at a different registrar address (an SRV target
    /// resolved by the application, a failover, a migration).
    ///
    /// Only the address moves: same transport, `Call-ID`, CSeq sequence and
    /// credentials. Contrast [`UserAgent::rebind`], where this end's own
    /// address moves.
    ///
    /// If a REGISTER is in flight or scheduled (refresh, challenge retry,
    /// back-off), a new one goes to the new address now and the old one's
    /// answer is ignored; waiting could mean up to the 30-minute RFC 5626
    /// §4.5 back-off on a wrong address. An `Idle` account sends nothing.
    /// The same address as before is a no-op.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`], [`UaError::NoRegistrar`] for a trunk that
    /// never registers, or [`UaError::Send`] as [`UserAgent::register`]'s,
    /// when the superseding REGISTER cannot be built or sent.
    pub fn retarget(
        &mut self,
        account: AccountId,
        remote: SocketAddr,
        now: Instant,
    ) -> Result<(), UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        if config.registrar.is_none() {
            return Err(UaError::NoRegistrar);
        }
        if config.remote == remote {
            return Ok(());
        }
        let config = self
            .accounts
            .get_mut(&account)
            .ok_or(UaError::NoSuchAccount)?;
        config.remote = remote;

        let reg = self
            .registrations
            .get(&account)
            .ok_or(UaError::NoSuchAccount)?;
        if reg.transaction.is_some() || reg.due.is_some() {
            let unregistering = reg.unregistering;
            self.send_register(account, unregistering, now)?;
            self.drain(now);
        }
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
        // every REGISTER passes here, so these checks live here
        if config.registrar.is_none() {
            return Err(UaError::NoRegistrar);
        }
        HeadersFor::Registration.check_each(&config.extra)?;
        // RFC 3263: wait for a lookup to name an address
        if self.register_waits_for_location(account, unregistering, now) {
            if let Some(reg) = self.registrations.get_mut(&account)
                && reg.transaction.is_none()
            {
                reg.due = None;
                if !unregistering {
                    reg.state = RegistrationState::Registering;
                }
            }
            return Ok(());
        }
        if self.register_waits_for_flow(account, unregistering, now)? {
            return Ok(());
        }
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        let Some(registrar) = config.registrar.as_ref() else {
            return Err(UaError::NoRegistrar);
        };
        crate::advertise::check_contact(&config.contact, config.remote)?;
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

        let request = build_register(config, registrar, reg, expires);
        // §22.2: once challenged, send credentials up front and save the 401
        // round trip on every refresh
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
        reg.state = if unregistering {
            RegistrationState::Unregistered
        } else if refreshing {
            RegistrationState::Refreshing
        } else {
            RegistrationState::Registering
        };
        // one entry per account; this also makes the previous attempt's
        // answer unclaimed
        self.owners.retain(|_, owner| *owner != account);
        self.owners
            .insert(AnyTransactionId::NonInviteClient(id), account);

        // a de-registration is reported only when answered
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

    /// Records what a REGISTER waiting for a lookup or a connection will be.
    ///
    /// A de-registration reads `Unregistered` at once, supersedes any running
    /// REGISTER, and whatever is sent later is the `Expires: 0`. A
    /// registration asked for while nothing is in flight replaces a waiting
    /// de-registration.
    pub(crate) fn hold_register(&mut self, account: AccountId, unregistering: bool) {
        let Some(reg) = self.registrations.get_mut(&account) else {
            return;
        };
        if !unregistering {
            if reg.transaction.is_none() {
                reg.unregistering = false;
            }
            return;
        }
        reg.unregistering = true;
        reg.state = RegistrationState::Unregistered;
        if reg.transaction.take().is_some() {
            self.owners.retain(|_, owner| *owner != account);
        }
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
            let mut unregistering = false;
            if let Some(reg) = self.registrations.get_mut(&account) {
                reg.due = None;
                unregistering = reg.unregistering;
            }
            // A send failure is not a refusal: after sleep the deadline often
            // fires before the socket is rebuilt, so back off and retry.
            if let Err(error) = self.send_register(account, unregistering, now) {
                self.register_unsent(account, &error, now);
            }
        }
    }
}

/// The REGISTER for one account (§10.2.1), addressed to `registrar`.
fn build_register(
    account: &Account,
    registrar: &Uri,
    reg: &Registration,
    expires: Duration,
) -> OutgoingRequest {
    let seconds = expires.as_secs().to_string();
    // §10.2.2: old addresses go in the same field with expires=0
    let mut contact = account.register_contact_value(expires.is_zero()).into_vec();
    for old in &reg.retired {
        contact.extend_from_slice(b", ");
        contact.extend_from_slice(old);
        contact.extend_from_slice(b";expires=0");
    }
    let mut request = OutgoingRequest::new(
        Method::Register,
        registrar.clone(),
        account.transport,
        account.remote,
    )
    .to(&account.to_value())
    .from(&account.sender_value())
    .call_id(reg.call_id.clone())
    .cseq(reg.cseq.saturating_add(1))
    // RFC 8599 push parameters ride here; de-registration drops the
    // identifier (§4.1.2)
    .contact(&contact)
    .header(HeaderName::Expires, seconds.as_bytes());
    // RFC 5627 §4.1, §5.2: `Supported: gruu` only with an instance id. The
    // application's own `Supported` is merged into the same field.
    let wants_gruu = account.wants_gruu();
    let mut supported: Vec<u8> = Vec::new();
    for extra in &account.extra {
        let Some(name) = HeaderName::from_bytes(&extra.name) else {
            continue;
        };
        if wants_gruu && name == HeaderName::Supported {
            if !supported.is_empty() {
                supported.extend_from_slice(b", ");
            }
            supported.extend_from_slice(&extra.value);
            continue;
        }
        request = request.header(name, &extra.value);
    }
    if wants_gruu {
        let listed = supported
            .split(|byte| *byte == b',')
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"gruu"));
        if !listed {
            if !supported.is_empty() {
                supported.extend_from_slice(b", ");
            }
            supported.extend_from_slice(b"gruu");
        }
        request = request.header(HeaderName::Supported, &supported);
    }
    request
}

// -- what comes back ---------------------------------------------------------

impl UserAgent {
    /// Turn everything the endpoint has to say into what the application does.
    pub(crate) fn drain(&mut self, now: Instant) {
        while let Some(event) = self.endpoint.poll_event() {
            if let Event::TransportWanted {
                request_bytes,
                limit_bytes,
                ..
            } = event
            {
                self.oversize = Some((request_bytes, limit_bytes));
            }
            if let Some(event) = self.on_core_event(event, now) {
                self.events.push_back(UaEvent::Unclaimed(event));
            }
        }
        self.settle_challenges();
        self.settle_call_challenges(now);
        self.settle_request_challenges(now);
        self.settle_offer_challenges();
        self.settle_subscription_challenges(now);
        self.settle_message_challenges();
        self.settle_probe_challenges();
        self.settle_publication_challenges(now);
        self.settle_announcements(now);
        self.settle_unanswered_changes(now);
        // after every change this round has released its call
        self.send_waiting_holds(now);
        self.settle_locations(now);
        self.settle_flows(now);
        self.settle_keepalives(now);
        // last: the wait covers whatever this round parked
        self.watch_the_stream_wait(now);
    }

    /// `None` when this layer claimed the event; otherwise the event, which
    /// reaches the application unchanged.
    ///
    /// Order matters: a handler goes where its subject is first touched.
    /// Screening runs before the call handler would create the call.
    fn on_core_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let event = self.on_screening_event(event, now)?;
        // §8.2: method and Request-URI (§8.2.1, §8.2.2.1) before Require
        let event = self.on_admission_event(event, now)?;
        // §8.2.2.3 before any handler acts on the request, OPTIONS included;
        // after screening, so a scanner still meets the rate limiter
        let event = self.on_require_event(event, now)?;
        let event = self.on_options_event(event, now)?;
        // RFC 3263 §4.3: fail over to the next address before anyone sees
        // the failure
        let event = self.on_unreached_event(event, now)?;
        // before anything that would answer the probe's challenge
        let event = self.on_probe_event(event, now)?;
        let event = self.on_registration_event(event, now)?;
        let event = self.on_call_event(event, now)?;
        let event = self.on_reliable_event(event, now)?;
        let event = self.on_transfer_event(event, now)?;
        let event = self.on_dtmf_event(event, now)?;
        // Below transfer: transfer takes `refer` NOTIFYs (RFC 3515 §2.4.4),
        // and this one answers 481 to any NOTIFY nobody owns (RFC 6665
        // §4.1.3), which is only safe after every owner had its turn.
        let event = self.on_subscription_event(event, now)?;
        let event = self.on_message_event(event, now)?;
        let event = self.on_publication_event(event, now)?;
        let event = self.on_session_event(event, now)?;
        // last: whatever nobody claimed is answered per §8.2.1
        self.on_unclaimed_request(event, now)
    }

    /// `None` when the event belonged to a registration.
    fn on_registration_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::Response {
                transaction,
                status,
                ref response,
            } => {
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
            Event::Challenged { transaction, .. } | Event::TokenChallenged { transaction, .. } => {
                let Some(account) = self.owners.get(&transaction).copied() else {
                    return Some(event);
                };
                self.on_challenged(account, transaction, now);
                None
            }
            // RFC 5626 §4.4.1; passed on too, since the application owns the
            // socket
            Event::FlowFailed { transport } => {
                self.on_flow_failed(transport, now);
                Some(event)
            }
            Event::TransactionTerminated { transaction, .. } => {
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
    /// The owner mapping stays: the core retires a timed-out transaction
    /// before reporting its failure, which must still find the account. The
    /// next REGISTER replaces it.
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
            return;
        }
        if status.is_success() {
            // the retired contacts were removed with it
            if let Some(reg) = self.registrations.get_mut(&account) {
                reg.retired.clear();
            }
            self.on_registered(account, response, now);
            return;
        }
        match status.get() {
            // held until the drain ends: a challenge may follow
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
            // RFC 3263 §4.3: a 503 fails over to the next address first
            503 if self.fail_over_registration(account, now) => {}
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
            // GRUUs (RFC 5627 §5.3) and service route (RFC 3608 §6.1) go too
            reg.learned = None;
            self.events.push_back(UaEvent::Unregistered { account });
            return;
        }

        let raw = response.as_raw();
        let granted = granted_expiry(&raw, &config.contact, reg.asking).unwrap_or(reg.asking);
        let echo = echoed(&raw, config);
        // a granted zero is a binding the registrar did not keep
        if granted.is_zero() {
            if let Some(reg) = self.registrations.get_mut(&account) {
                reg.learned = None;
            }
            self.give_up(
                account,
                RegistrationFailure::Rejected,
                Some(StatusCode::OK),
                Some(response.clone()),
            );
            return;
        }
        let (info, ignored) = read_registrar_info(&raw, config);
        for reason in ignored {
            self.endpoint.note_arrival(&raw, reason, now);
        }

        let cold = self.cold;
        let Some(reg) = self.registrations.get_mut(&account) else {
            return;
        };
        reg.echo = echo;
        let refresh_in = reg.bound(granted, cold, now);
        // replaced whole, never merged: RFC 3608 §6.1 (a 2xx without
        // Service-Route clears it), RFC 5627 §4.2 (new temporary GRUU each 2xx)
        reg.learned = Some(info.clone());
        reg.state = RegistrationState::Registered;
        reg.failures = 0;
        reg.raised = false;
        reg.due = Some(now + refresh_in);
        self.events.push_back(UaEvent::Registered {
            account,
            expires: granted,
            refresh_in,
            response: response.clone(),
            info,
        });
        self.registration_proved();
    }

    /// §10.2.8: a 423 is retried once with the `Min-Expires` interval.
    fn on_interval_too_brief(&mut self, account: AccountId, response: &OwnedMessage, now: Instant) {
        let demanded = min_expires(&response.as_raw());
        let already_raised = self
            .registrations
            .get(&account)
            .is_some_and(|reg| reg.raised);
        let Some(demanded) = demanded.filter(|_| !already_raised) else {
            // no Min-Expires, or a second 423: retrying would loop
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
    /// The application opens the new flow (§4.4); here the binding goes on
    /// the §4.5 back-off, so a server that lost many flows is not flooded.
    ///
    /// Only settled bindings: one with a REGISTER in flight is retried by
    /// the failure that follows, and counting it twice would double the wait.
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
        // §10.2.7: no immediate retry to the same registrar, but RFC 3263
        // §4.3 may try the next address at once
        let _ = reason;
        if self.fail_over_registration(account, now) {
            return;
        }
        self.retry_later(account, None, None, None, now);
    }

    /// `account`'s credentials for the challenge under `transaction`, or
    /// `None` when it has none or they are not for whoever asked (RFC 3261
    /// §22.1).
    ///
    /// Every challenge path comes here. The request must have gone to the
    /// account's server (same host, any port, IPv4-mapped counts as IPv4) and
    /// every realm must be the account's: [`Account::realms`](crate::Account::realms),
    /// or, with none named, the realms first seen plus any its own REGISTER
    /// is challenged for. Otherwise the challenge is declined at the endpoint
    /// and reported as [`UaEvent::ChallengeDeclined`].
    ///
    /// With no challenge held, the credentials are returned and the
    /// endpoint's retry reports there is nothing to answer.
    pub(crate) fn credentials_for_challenge(
        &mut self,
        account: Option<AccountId>,
        transaction: AnyTransactionId,
    ) -> Option<Arc<Credentials>> {
        let account = account?;
        let config = self.accounts.get(&account)?;
        let credentials = config.credentials.clone();
        let Some(origin) = self.endpoint.challenge_origin(transaction) else {
            return credentials;
        };
        // nothing to answer with, unless a token can be fetched
        if credentials.is_none() && self.endpoint.token_wanted(transaction, None).is_none() {
            return None;
        }
        // a REGISTER is never relayed to a far end, so its realms are the
        // account's
        let registering = match transaction {
            AnyTransactionId::NonInviteClient(id) => self
                .registrations
                .get(&account)
                .is_some_and(|reg| reg.transaction == Some(id)),
            _ => false,
        };
        // host only: a PBX may take TCP on another port (§18.1.1); canonical
        // so IPv4-mapped addresses from dual-stack sockets match
        let why = if origin.destination.ip().to_canonical() == config.remote.ip().to_canonical() {
            let foreign = if !config.realms.is_empty() {
                origin
                    .realms
                    .iter()
                    .any(|realm| !config.realms.contains(realm))
            } else if registering {
                false
            } else {
                let known = &config.pinned_realms;
                !known.is_empty() && origin.realms.iter().any(|realm| !known.contains(realm))
            };
            foreign.then_some(crate::event::ChallengeRefusal::NotTheAccountsRealm)
        } else {
            Some(crate::event::ChallengeRefusal::NotTheAccountsServer)
        };
        let Some(why) = why else {
            if let Some(config) = self.accounts.get_mut(&account)
                && config.realms.is_empty()
                && (registering || config.pinned_realms.is_empty())
            {
                for realm in &origin.realms {
                    if !config.pinned_realms.contains(realm) {
                        config.pinned_realms.push(Arc::clone(realm));
                    }
                }
            }
            // RFC 8898: own server wants a token we lack or had refused
            if let Some(challenge) = self
                .endpoint
                .token_wanted(transaction, credentials.as_deref())
            {
                self.events.push_back(UaEvent::TokenRequired {
                    account,
                    from: origin.destination,
                    challenge,
                });
            }
            return credentials;
        };
        self.endpoint.decline_challenge(transaction);
        self.events.push_back(UaEvent::ChallengeDeclined {
            account,
            from: origin.destination,
            realms: origin.realms,
            why,
        });
        None
    }

    fn on_challenged(&mut self, account: AccountId, transaction: AnyTransactionId, now: Instant) {
        let Some(credentials) = self.credentials_for_challenge(Some(account), transaction) else {
            return;
        };
        // the endpoint caps retries against a registrar that draws a fresh
        // nonce every time; past the cap no challenge is reported
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => {
                self.owners.remove(&transaction);
                self.owners.insert(retried, account);
                if let (Some(reg), AnyTransactionId::NonInviteClient(id)) =
                    (self.registrations.get_mut(&account), retried)
                {
                    reg.transaction = Some(id);
                    reg.unanswered = None;
                    reg.waiting_for_stream = None;
                    // §22.2, §10.2: the retry used the next CSeq
                    reg.cseq = reg.cseq.saturating_add(1);
                }
            }
            // §18.1.1: too big for a datagram; the retry waits for a stream
            // and is not a refusal yet
            Err(error) if wants_a_stream(&error) => {
                if let Some(reg) = self.registrations.get_mut(&account) {
                    reg.waiting_for_stream = Some(transaction);
                }
            }
            Err(_) => {}
        }
    }

    /// Send the registration retries §18.1.1 held back, now that a
    /// connection exists.
    ///
    /// The failed id lives on the registration, not in `owners`, which a
    /// refresh between park and bind would clear.
    pub(crate) fn resume_parked_registrations(&mut self, now: Instant) {
        let waiting: Vec<(AccountId, AnyTransactionId)> = self
            .registrations
            .iter()
            .filter_map(|(account, reg)| reg.waiting_for_stream.map(|failed| (*account, failed)))
            .collect();
        for (account, failed) in waiting {
            let credentials = self.credentials_for_challenge(Some(account), failed);
            let Some(credentials) = credentials else {
                self.stop_waiting(account);
                continue;
            };
            match self
                .endpoint
                .retry_with_credentials(failed, &credentials, now)
            {
                Ok(retried) => {
                    self.owners.remove(&failed);
                    self.owners.insert(retried, account);
                    if let (Some(reg), AnyTransactionId::NonInviteClient(id)) =
                        (self.registrations.get_mut(&account), retried)
                    {
                        reg.transaction = Some(id);
                        reg.unanswered = None;
                        reg.waiting_for_stream = None;
                        reg.cseq = reg.cseq.saturating_add(1);
                    }
                }
                // not a usable connection; stays parked
                Err(error) if wants_a_stream(&error) => {}
                Err(_) => self.stop_waiting(account),
            }
        }
    }

    /// Stop holding a registration's retry back, so the next settle reports
    /// the refusal it is still carrying.
    fn stop_waiting(&mut self, account: AccountId) {
        if let Some(reg) = self.registrations.get_mut(&account) {
            reg.waiting_for_stream = None;
        }
    }

    /// A refusal that carried a challenge and got no retry was a refusal.
    ///
    /// A repeated challenge without `stale` means a wrong password (§22.1);
    /// the core stops reporting it so the account is not locked. A retry
    /// waiting for a connection is left alone.
    fn settle_challenges(&mut self) {
        let refused: Vec<(AccountId, Option<OwnedMessage>)> = self
            .registrations
            .iter_mut()
            .filter(|(_, reg)| reg.waiting_for_stream.is_none())
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

    /// A REGISTER this layer sent on its own could not leave. One whose
    /// `Contact` the registrar cannot reach stops there, since no retry can
    /// change the address; anything else backs off and tries again.
    pub(crate) fn register_unsent(&mut self, account: AccountId, error: &UaError, now: Instant) {
        if matches!(error, UaError::UnreachableAddress { .. }) {
            self.give_up(account, RegistrationFailure::UnreachableContact, None, None);
        } else {
            self.retry_later(account, None, None, None, now);
        }
    }

    /// Something recoverable: schedule the next attempt (RFC 5626 §4.5).
    pub(crate) fn retry_later(
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
        // only a response refuses; a timeout says nothing about the route
        if status.is_some() {
            reg.refused();
        }
        // RFC 5626 §4.5: Retry-After may lengthen the wait
        let wait = backoff_delay(reg.failures, &entropy).max(asked_for.unwrap_or(Duration::ZERO));
        // a de-registration is retried as a de-registration
        if !reg.unregistering {
            reg.state = RegistrationState::Retrying;
        }
        reg.transaction = None;
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
    pub(crate) fn give_up(
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
            reg.refused();
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
