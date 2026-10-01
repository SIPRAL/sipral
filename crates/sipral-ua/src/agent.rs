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
/// The one error out of `retry_with_credentials` that is a request rather
/// than a verdict: the endpoint is still holding the challenge, and the same
/// handle works again once the application binds a stream transport. Every
/// path that answers a challenge has to tell it apart from a real failure, or
/// it reports a password as wrong in the same breath as asking for a socket
/// nobody has been given time to open.
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
    /// Which account a transaction belongs to. A challenge answered gives a
    /// new transaction, so this moves rather than being written once.
    owners: HashMap<AnyTransactionId, AccountId>,
    pub(crate) calls: HashMap<CallHandle, Call>,
    /// The three ways a call is reached from an event: by the INVITE this end
    /// sent, by the one the far end sent, and by the dialog either opened.
    pub(crate) by_invite: HashMap<TransactionId<InviteClient>, CallHandle>,
    pub(crate) by_server: HashMap<TransactionId<InviteServer>, CallHandle>,
    pub(crate) by_dialog: HashMap<DialogId, CallHandle>,
    /// The branch [`crate::ForkPolicy::KeepFirst`] kept, or the first to
    /// answer an INVITE the user had already put down, for each INVITE of
    /// ours a branch has answered, until the INVITE's transaction is retired:
    /// the window in which another branch's 2xx can still arrive (§13.2.2.4)
    /// and has to be acknowledged and hung up. Kept apart from the calls,
    /// because every other branch is over by then and the one kept may be too.
    pub(crate) kept_branches: HashMap<TransactionId<InviteClient>, KeptBranch>,
    /// The BYEs, CANCELs, PRACKs, REFERs and NOTIFYs a call has in flight, so
    /// that their answers are this layer's news rather than the application's.
    ///
    /// The method is kept beside the call because what a request leaves
    /// behind when it never goes depends on which one it was, and by the time
    /// that has to be decided the bytes are long gone.
    pub(crate) by_request: HashMap<AnyTransactionId, (CallHandle, Method<'static>)>,
    /// The account behind each of those, kept beside rather than inside the
    /// call: a BYE outlives the call it ended, and a challenge to it can only
    /// be answered by whoever still knows the password.
    pub(crate) account_of: HashMap<AnyTransactionId, AccountId>,
    /// The digit an INFO in `by_request` is carrying, so that its final
    /// answer can be reported as [`UaEvent::DtmfSent`] naming the digit it
    /// was about. Kept beside `by_request` rather than inside it because
    /// every other method that map holds — BYE, CANCEL, PRACK, REFER, NOTIFY —
    /// has nothing to put here.
    pub(crate) by_dtmf_info: HashMap<AnyTransactionId, char>,
    /// The digits still waiting behind the one [`UserAgent::send_dtmf_info`]
    /// has in flight: a 2xx to the one just answered sends the next, and
    /// anything else drops the rest (8.3.11-bis). One entry per call, present
    /// while any of its digits is in flight and gone once the last has its
    /// final answer.
    pub(crate) dtmf_queue: HashMap<CallHandle, crate::dtmf::DtmfQueue>,
    /// The re-INVITEs and UPDATEs offering a session change.
    pub(crate) by_offer: HashMap<AnyTransactionId, CallHandle>,
    /// A hold (`true`) or a resume asked for while another session change was
    /// running in the call, sent once it is over (RFC 3261 §14.1). One per
    /// call: what waits is the state last asked for, so a second press
    /// replaces the first.
    pub(crate) holds_waiting: HashMap<CallHandle, bool>,
    /// Refusals of an INVITE that carried a challenge, held until the drain
    /// ends. Whether one was a refusal or the first half of a retry is decided
    /// by whether a challenge follows it.
    pub(crate) challenged: HashMap<TransactionId<InviteClient>, Refusal>,
    /// The same, for the BYEs, REFERs and the rest a call sends inside its
    /// dialog. These used to be reported nowhere at all: a BYE whose retry
    /// never went left the call in `Terminating` for ever with nothing said,
    /// and a REFER left the transfer seat taken so no later transfer could
    /// be asked for.
    pub(crate) challenged_requests: HashMap<AnyTransactionId, RequestRefusal>,
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
    /// The MESSAGEs this layer sent and has not yet reported a final answer
    /// for (RFC 3428). Removed the moment `UaEvent::MessageSent` goes out:
    /// unlike a subscription, one of these has nothing left to do once it is
    /// answered.
    pub(crate) messages: HashMap<MessageHandle, SentMessage>,
    /// The MESSAGE transaction each one has in flight.
    pub(crate) by_message: HashMap<AnyTransactionId, MessageHandle>,
    /// The event state this agent keeps at a compositor (RFC 3903).
    pub(crate) publications: crate::publishing::Publications,
    /// What this layer sends inside a dialog by itself and RFC 3261 §18.1.1
    /// would not let out over a datagram, waiting for a stream.
    pub(crate) parked: Vec<Parked>,
    /// When whatever is waiting for a stream stops waiting
    /// ([`crate::oversize`]). `None` while nothing is.
    pub(crate) stream_deadline: Option<Instant>,
    /// The request size and the limit the latest `TransportWanted` carried,
    /// for the text of the 513 a request that never got its stream ends
    /// with.
    pub(crate) oversize: Option<(usize, u32)>,
    pub(crate) events: VecDeque<UaEvent>,
    /// What an incoming INVITE meets before anything else here does, and the
    /// count of what it turned away.
    pub(crate) guard: Guard,
    /// The REFERs outside any dialog this agent holds, and whether it takes
    /// any ([`crate::referral`]).
    pub(crate) referrals: Referrals,
    /// Whether an INFO in a call that is not DTMF reaches the application
    /// unanswered ([`UserAgent::hand_over_info`]) rather than being answered
    /// here.
    pub(crate) info_handed_over: bool,
    /// Whether this agent takes recording sessions, which is what makes the
    /// `siprec` option tag one it understands
    /// ([`UserAgent::accept_recording_sessions`]).
    pub(crate) recording_server: bool,
    /// The registrar flows kept open through a NAT ([`crate::keepalive`]).
    pub(crate) keepalives: crate::keepalive::Keepalives,
    /// The addresses of the accounts that find their server by name.
    pub(crate) locations: crate::locate::Locations,
    /// The accounts on a connection of their own that asked for one, and
    /// when (`crate::flow`).
    pub(crate) flows_wanted: HashMap<AccountId, Instant>,
    /// The accounts that never register whose connection has been asked for
    /// once already.
    pub(crate) flows_asked: std::collections::HashSet<AccountId>,
    /// The accounts whose connection was lost since the last round of work.
    pub(crate) flows_lost: Vec<AccountId>,
    /// 64·T1, read off the configuration once. RFC 6665 §4.1.2.4's Timer N is
    /// the only deadline this layer takes from the transaction timings, and
    /// the endpoint does not hand its configuration back out.
    pub(crate) timer_n: Duration,
    /// The bounds a session description read off the wire is held to, read
    /// off the configuration once for the same reason `timer_n` is.
    pub(crate) sdp_limits: sdp::Limits,
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
    pub(crate) next_message: u32,
    /// The recording in progress, if the application asked for one.
    ///
    /// `None` for the whole life of an agent nobody records. Everything that
    /// enters through [`UserAgent::receive`] and [`UserAgent::handle_timeout`]
    /// is offered to it first, and nothing else here ever is: what this end
    /// sent is never handed to it, which is the reason a caller's own
    /// negotiated key never rides along in its own recording (8.2.4,
    /// `docs/18-replay.md`).
    recorder: Option<Recorder>,
    /// What [`UserAgent::stop_recording`] last produced, held until
    /// [`UserAgent::clear_stopped_recording`] releases it. Kept apart from
    /// [`UserAgent::recorder`] rather than folded into one `enum` because a
    /// caller working out how large a buffer to bring for the finished text
    /// asks [`UserAgent::stop_recording`] more than once, and the second ask
    /// must not stop a recording that is no longer running.
    stopped_recording: Option<Result<Recording, RecordError>>,
    /// What [`UserAgent::send_quality_report`] needs about a call whose
    /// account asked for one (RFC 6035), kept past the moment `finish`
    /// forgets the call itself: the `CallEnded` event that call queues is
    /// what tells the facade above this crate to send the report, and by
    /// the time that event is drained the call is already gone from
    /// [`UserAgent::calls`]. See `crate::quality_report` for what stashes
    /// and consumes this, and why it is bounded.
    pub(crate) quality_report_snapshots: HashMap<CallHandle, crate::quality_report::EndedCall>,
    /// Insertion order for [`UserAgent::quality_report_snapshots`], so the
    /// oldest entry can be evicted first when the cap is reached: a call
    /// whose account asked for a report but that never got a media session
    /// for [`send_quality_report`](UserAgent::send_quality_report) to be
    /// asked about (rejected before answer, cancelled) would otherwise sit
    /// here for the rest of the process's life.
    pub(crate) quality_report_order: VecDeque<CallHandle>,
    /// What the wall clock read at a known instant ([`UserAgent::set_wall_clock`]):
    /// the one number signing and verifying a PASSporT need that a monotonic
    /// instant cannot give.
    pub(crate) wall_clock: Option<(Instant, u64)>,
    /// The verification service and the calls waiting on it
    /// ([`crate::stir`]).
    #[cfg(feature = "stir")]
    pub(crate) stir: crate::stir::Service,
}

impl UserAgent {
    /// A user agent with no accounts.
    ///
    /// `seed` is the endpoint's: thirty-two bytes of entropy from which every
    /// branch, tag, `Call-ID` and back-off interval is derived. Two agents must
    /// never be given the same one.
    ///
    /// # Errors
    /// [`TimerConfigError`] when a timer in `config` cannot be armed at all:
    /// `timers.t1` or `timers.t2` zero, which
    /// [`sipral_core::transaction::TimerConfig::validate`] refuses, or a
    /// `keepalive_interval` of zero. Either would make a timer re-arm at the
    /// instant it just fired and hang `handle_timeout` forever.
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

    /// What the wall clock read at the instant `at`, as seconds since 1
    /// January 1970.
    ///
    /// Nothing here reads a clock, and a PASSporT carries the time it was
    /// signed (RFC 8225 §5.1.1) and is judged against the time it is
    /// verified at, so signing and verifying one take the time from here:
    /// `unix_seconds` at `at`, and the monotonic distance from `at` after
    /// it. Set it again whenever the platform says its clock was stepped.
    pub fn set_wall_clock(&mut self, at: Instant, unix_seconds: u64) {
        self.wall_clock = Some((at, unix_seconds));
    }

    /// Whether [`UserAgent::set_wall_clock`] has been called: what an
    /// account that signs its calls, and a verifier, need.
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
        // where the bytes came from is on the input and nowhere else by the
        // time an event names them, and screening an INVITE needs it
        self.guard.arrived(&input);
        // recorded before anything else touches it: what arrived is the only
        // thing a recording ever holds of the wire, never what this end sent
        // (`docs/18-replay.md`)
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.arrived(&input, now);
        }
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
            self.on_transport_bound(transport, now);
        }
        self.drain(now);
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
        self.drain(now);
    }

    /// Starts a recording of everything this agent is fed from here on
    /// (`docs/18-replay.md`): every [`UserAgent::receive`] and
    /// [`UserAgent::handle_timeout`], with the seed the agent's identifiers
    /// are drawn from from here on, since a replay needs that same seed to
    /// write the branches and tags the recorded answers belong to.
    ///
    /// That seed is not the one the agent was built with. Starting moves the
    /// endpoint onto a fresh seed derived one way from that one
    /// ([`Endpoint::reseed`]) and the recording carries the fresh one, and
    /// stopping moves it on again, so a recording handed to somebody predicts
    /// no `Call-ID`, tag, branch or SSRC drawn before it started or after it
    /// stopped.
    ///
    /// A recording already running is discarded rather than extended: the
    /// two would disagree about where their own clock starts, and a caller
    /// that meant to keep the first one would not have asked to start a
    /// second.
    ///
    /// `note` is one line of prose for whoever opens the file later. A note
    /// that is not one line is accepted here — nothing here has an error to
    /// give back — and turns into [`RecordError::NotOneLine`] the first time
    /// [`UserAgent::stop_recording`] is called, the same as any other reason
    /// a recording could not be produced.
    pub fn start_recording(&mut self, note: Option<&str>) {
        // the recording carries a seed of its own, never the one this agent
        // was built with: a replay of it draws what this agent draws from
        // here on, and nothing about the seed it was built with
        let seed = self.endpoint.reseed();
        let recorder = match note {
            Some(note) => Recorder::new(seed).about(note),
            None => Recorder::new(seed),
        };
        self.recorder = Some(recorder);
        // an answer nobody came back for is abandoned rather than kept: a
        // caller starting over has already said it does not want it
        self.stopped_recording = None;
    }

    /// Stops the recording started by [`UserAgent::start_recording`], and
    /// holds the answer until [`UserAgent::clear_stopped_recording`] says it
    /// has been delivered.
    ///
    /// `None` when nothing was running and nothing already stopped is
    /// waiting to be collected. Calling this again before the answer is
    /// cleared hands back the same one rather than stopping a second time —
    /// there is nothing left running to stop — which is what lets a caller
    /// that does not yet know how big a buffer to bring ask twice: once to
    /// be told, and once to be handed the text, both against one recording
    /// rather than two.
    ///
    /// `Some(Err(_))` when something this session was fed could not go in
    /// the recording — a message with a body that is not text is the one
    /// way that happens (`docs/18-replay.md`) — in which case the recording
    /// is not produced at all rather than handed back with a gap in it.
    pub fn stop_recording(&mut self) -> Option<Result<&Recording, RecordError>> {
        if self.stopped_recording.is_none() {
            self.stopped_recording = Some(self.recorder.take()?.finish());
            // the seed the recording carries stops here: whoever is handed
            // the file can work out every identifier it covers, which the
            // file already shows, and none drawn after this
            let _ = self.endpoint.reseed();
        }
        self.stopped_recording
            .as_ref()
            .map(|result| result.as_ref().map_err(|error| *error))
    }

    /// Discards the answer [`UserAgent::stop_recording`] is holding, once it
    /// has been collected in full. Safe to call whether or not there is one.
    pub fn clear_stopped_recording(&mut self) {
        self.stopped_recording = None;
    }

    /// Whether a recording is running. `false` again from the moment
    /// [`UserAgent::stop_recording`] is first called, whether or not its
    /// answer has been collected yet.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recorder.is_some()
    }

    /// Bytes to put on a transport. Drain to empty.
    ///
    /// What the endpoint wrote, and then the keep-alives this layer sends to
    /// a registrar behind a NAT ([`crate::keepalive`]).
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.endpoint
            .poll_transmit()
            .or_else(|| self.poll_keepalive())
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
    /// What this layer has no policy for arrives as [`UaEvent::Unclaimed`] and
    /// is answered through here — an INFO in a call that is not DTMF, and
    /// only once [`UserAgent::hand_over_info`] asked for it, since every
    /// other request nothing here claims, inside a dialog or outside one, is
    /// answered by this layer (§8.2.1, RFC 5057 §5.3). Registration, calls,
    /// transfers and
    /// subscriptions are not among them: a REGISTER or a SUBSCRIBE sent from
    /// here would be one this layer does not know it owns, and would neither
    /// be refreshed nor retried.
    #[must_use]
    pub const fn endpoint(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }

    /// The endpoint underneath, to read what it counts —
    /// [`Endpoint::retransmissions`], [`Endpoint::refused`] — where only a
    /// shared borrow of this agent is at hand.
    #[must_use]
    pub const fn endpoint_ref(&self) -> &Endpoint {
        &self.endpoint
    }
}

/// A recorded session is fed back into whichever layer the bug is thought to
/// be in (`docs/18-replay.md`), and registration, back-off and call policy are
/// decided here rather than below. So the same calls again, under the trait a
/// replay drives.
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
        // RFC 8588 §5's origination identifier, drawn once for an account
        // that signs and named none, so every call it places names the same
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
        // §10.2.4: one Call-ID for every registration of a boot cycle, so the
        // registrar reads a refresh as a refresh rather than as a second device
        let call_id = CallId::new(&self.endpoint.token());
        let asking = account.expires;
        let mut registration = Registration::new(call_id, asking);
        // said once, here, and never moved: nothing that changes a
        // registration's state can reach an account no REGISTER leaves for
        if account.registrar.is_none() {
            registration.state = RegistrationState::NotRegistering;
        }
        self.registrations.insert(id, registration);
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

    /// Every account this agent holds, oldest first — for a report of the
    /// whole agent, such as a crash report's state snapshot.
    #[must_use]
    pub fn accounts(&self) -> Vec<AccountId> {
        let mut held: Vec<AccountId> = self.accounts.keys().copied().collect();
        held.sort_unstable();
        held
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

    /// Point an account at a different registrar address: a second SRV
    /// target this application resolved on its own, a failover a proxy
    /// pushed in-band, an operator's migration.
    ///
    /// Only the address moves. The transport is not asked for again — a
    /// registrar migration names a new place, not a new way of reaching it —
    /// and nothing about the binding this account already holds or is
    /// getting restarts: the `Call-ID` stands, the sequence number keeps
    /// growing from wherever it was, and the credentials are the ones this
    /// account always had. What changes is only where the *next* REGISTER
    /// this account sends is addressed, and nothing else — contrast
    /// [`UserAgent::rebind`], which is this end's own
    /// address moving and has a `Contact` to update because of it.
    ///
    /// A REGISTER already in flight is not cancelled — there is no way to
    /// unsend one — but it is superseded the same way a second call to
    /// [`UserAgent::register`] already supersedes one still running: this
    /// account's next attempt goes to the new address, and whatever the old
    /// one still in the network does with the old one no longer reaches this
    /// account (`send_register`'s "one entry per account" rule). That
    /// supersession happens *now*, inside this call, rather than waiting for
    /// the attempt already running to time out or the next scheduled refresh
    /// to fall due, whenever this account has a REGISTER in flight or one
    /// scheduled — a refresh, a challenge answered and about to be retried,
    /// or a back-off after a failure. Waiting there would mean believing an
    /// address this call was just told is wrong for up to the RFC 5626 §4.5
    /// back-off ceiling of thirty minutes. An account that was never told to
    /// register (`RegistrationState::Idle`) sends nothing: retargeting picks
    /// where its next `register` goes, it does not call `register` for it.
    ///
    /// Retargeting to the address an account is already on changes nothing
    /// and sends nothing: this call answers `Ok(())` at once, the same
    /// binding standing exactly as it did before it was asked.
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
        // every REGISTER goes through here -- the application's, a refresh, a
        // retry, a wake's, a push's -- so this is the one place an account
        // with no registrar is turned away, before anything is built
        if config.registrar.is_none() {
            return Err(UaError::NoRegistrar);
        }
        // and the one place the fields the account was configured with are
        // checked, for the same reason
        HeadersFor::Registration.check_each(&config.extra)?;
        // an account that finds its registrar by name and holds no address
        // for it sends nothing until a lookup has named one (RFC 3263)
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
        // and one on a connection of its own waits for the connection
        if self.register_waits_for_flow(account, unregistering, now)? {
            return Ok(());
        }
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        let Some(registrar) = config.registrar.as_ref() else {
            return Err(UaError::NoRegistrar);
        };
        // a Contact the registrar would store and never reach this end at
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
    // the addresses this account moved away from go in the same field, each
    // with a zero that removes that binding and no other (§10.2.2)
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
    // the one request the RFC 8599 push parameters belong in, and a
    // de-registration leaves the identifier out of them (§4.1.2)
    .contact(&contact)
    .header(HeaderName::Expires, seconds.as_bytes());
    // RFC 5627 §4.1: a UA that wants GRUUs "MUST include the Supported header
    // field in the request", with `gruu` in it, and §5.2 hands them out only
    // for a contact that names its instance — so the tag goes with the
    // instance identifier and never without it. A `Supported` the application
    // added is folded into the same field rather than written beside it.
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
        self.settle_publication_challenges(now);
        self.settle_announcements(now);
        self.settle_unanswered_changes(now);
        // last, so that every change this round finished — answered, refused,
        // or given up on after a challenge — has let go of its call first
        self.send_waiting_holds(now);
        // a trunk that finds its proxy by name starts looking once it can
        self.settle_locations(now);
        // and one on a connection of its own asks for it once it has an
        // address to connect to
        self.settle_flows(now);
        // and after every registration this round won or lost
        self.settle_keepalives(now);
        // last of all: whatever this round left waiting for a stream is
        // what the wait covers
        self.watch_the_stream_wait(now);
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
        // §8.2.1 and §8.2.2.1 come before §8.2.2.3 in the order §8.2 asks
        // them: a method this agent does not implement, or a Request-URI it
        // can never be, is refused before its Require is read
        let event = self.on_admission_event(event, now)?;
        // Screening first, so a scanner that writes a Require header still
        // meets the rate limiter. Then this, before every handler that acts on
        // a request -- OPTIONS included, which used to answer 200 to anything
        // it was handed and so answered 200 to a Require it could not honour.
        // §8.2.2.3 refuses the request; it does not undo what honouring it did.
        let event = self.on_require_event(event, now)?;
        let event = self.on_options_event(event, now)?;
        // RFC 3263 §4.3, before any handler takes the failure for a verdict:
        // a request to a located server that found nobody there goes to the
        // next address the name gave, and its owner never hears of the first
        let event = self.on_unreached_event(event, now)?;
        let event = self.on_registration_event(event, now)?;
        let event = self.on_call_event(event, now)?;
        let event = self.on_reliable_event(event, now)?;
        let event = self.on_transfer_event(event, now)?;
        // A digit by INFO, claimed by method rather than by dialog state, so
        // it runs wherever in this run it does not collide with the two
        // handlers either side of it — neither reads an INFO.
        let event = self.on_dtmf_event(event, now)?;
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
        // MESSAGE opens no dialog and carries no subscription, so it has
        // nothing to compete with here: it is claimed by its own method,
        // in or out of any dialog, and everything above has already taken
        // what is its own
        let event = self.on_message_event(event, now)?;
        // a PUBLISH of ours is claimed by its transaction, like a MESSAGE's
        // answer, and nothing else sends one that is kept
        let event = self.on_publication_event(event, now)?;
        let event = self.on_session_event(event, now)?;
        // last: a request outside a dialog that every handler above passed
        // over is one this agent does not implement there, and §8.2.1 says
        // what it is answered with rather than leaving it to the application
        self.on_unclaimed_request(event, now)
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
            // the registrar has read every `Contact` the request carried,
            // the ones it was asked to drop included
            if let Some(reg) = self.registrations.get_mut(&account) {
                reg.retired.clear();
            }
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
            // RFC 3263 §4.3 treats a 503 like a server that did not answer:
            // the next address a located registrar's name gave is tried at
            // once, and only when none is left does the account back off
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
            // the binding is gone, and what the registrar said about it went
            // with it: RFC 5627 §5.3 removes the GRUUs, and RFC 3608 §6.1's
            // service route belongs to a registration there no longer is
            reg.learned = None;
            self.events.push_back(UaEvent::Unregistered { account });
            return;
        }

        let raw = response.as_raw();
        let granted = granted_expiry(&raw, &config.contact, reg.asking).unwrap_or(reg.asking);
        let echo = echoed(&raw, config);
        // a granted zero is a binding the registrar did not keep; there is
        // nothing to refresh and nothing to celebrate, and nothing it said
        // about that binding is worth keeping either
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
        // Replaced whole, never merged. RFC 3608 §6.1: the stored service
        // route "is updated according to the Service-Route header field of
        // the latest 200 class response", and one without the field clears
        // it; RFC 5627 §4.2 hands out a new temporary GRUU with every 2xx.
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
        // reason to stop for good. A different server is another matter: RFC
        // 3263 §4.3 tries the next address a located registrar's name gave
        let _ = reason;
        if self.fail_over_registration(account, now) {
            return;
        }
        self.retry_later(account, None, None, None, now);
    }

    /// `account`'s password for the challenge held under `transaction`, when
    /// the password is for it — and `None` when the account has none, or
    /// when it is not for whoever asked (RFC 3261 §22.1).
    ///
    /// Every path that answers a challenge comes through here, so that the
    /// rule holds for all of them: the challenged request went to the
    /// account's own server — its address, on whatever port — and every
    /// realm it was challenged for is the
    /// account's — the ones [`Account::realms`](crate::Account::realms)
    /// names, or with none named, the ones the server first challenged with,
    /// taken here the first time and kept. A challenge that fails either is
    /// declined at the endpoint, so that nothing is answered ahead of the
    /// next one either, and reported as [`UaEvent::ChallengeDeclined`]; the
    /// caller then treats it as a challenge with nothing to answer it, which
    /// is what it is.
    ///
    /// No challenge held under `transaction` hands the password back: the
    /// endpoint's own retry then says there is nothing to answer.
    pub(crate) fn credentials_for_challenge(
        &mut self,
        account: Option<AccountId>,
        transaction: AnyTransactionId,
    ) -> Option<Arc<Credentials>> {
        let account = account?;
        let config = self.accounts.get(&account)?;
        let credentials = config.credentials.clone()?;
        let Some(origin) = self.endpoint.challenge_origin(transaction) else {
            return Some(credentials);
        };
        // the host, not the port: a PBX that takes TCP on another port than
        // UDP is the same server over the stream §18.1.1 moved a request to
        let why = if origin.destination.ip() == config.remote.ip() {
            let known = if config.realms.is_empty() {
                &config.pinned_realms
            } else {
                &config.realms
            };
            let foreign =
                !known.is_empty() && origin.realms.iter().any(|realm| !known.contains(realm));
            foreign.then_some(crate::event::ChallengeRefusal::NotTheAccountsRealm)
        } else {
            Some(crate::event::ChallengeRefusal::NotTheAccountsServer)
        };
        let Some(why) = why else {
            if let Some(config) = self.accounts.get_mut(&account)
                && config.realms.is_empty()
                && config.pinned_realms.is_empty()
            {
                config.pinned_realms.clone_from(&origin.realms);
            }
            return Some(credentials);
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
            // nothing to answer with; the refusal stands, and it stands the
            // same way every time, so there is no point trying again
            return;
        };
        // The count that stops a registrar which draws a fresh nonce for every
        // refusal is the endpoint's now, not this layer's: it has to cover
        // every path that answers a challenge, and only the endpoint sees all
        // of them. Past the allowance no challenge is reported at all, so this
        // is never reached and the refusal settles below.
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
                }
            }
            // §18.1.1: the credentials made it too big for a datagram and the
            // endpoint has asked for a connection. It is still holding the
            // challenge, so this is not a refusal yet — it is a retry waiting
            // for something the application has not had a chance to open.
            // Reporting it now, which is what dropping the error did, told
            // the application its password was wrong in the same breath as
            // asking it for a socket.
            Err(error) if wants_a_stream(&error) => {
                if let Some(reg) = self.registrations.get_mut(&account) {
                    reg.waiting_for_stream = Some(transaction);
                }
            }
            Err(_) => {}
        }
    }

    /// Send the registration retries §18.1.1 held back, now that there is a
    /// connection to send them over.
    ///
    /// The failed transaction id is kept on the registration rather than read
    /// back out of `owners`, because `send_register` clears that account's
    /// entries on every new attempt and a refresh can fall between the park
    /// and the bind.
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
                    }
                }
                // the connection that was opened is not one this can go over;
                // it stays parked for the next
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
    /// The core answers a challenge once; the same nonce coming back without
    /// `stale` is §22.1's way of saying the password was wrong, and it stops
    /// reporting it rather than let a client lock the account by repeating it.
    /// Nothing follows the refusal in that case, and that silence is the
    /// answer.
    /// One thing is not that silence: a retry the endpoint is holding until a
    /// connection exists. That one is left where it is, because the answer to
    /// it has not been sent yet.
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
        // a 5xx is the registrar refusing; a timeout or a dead transport is
        // no answer at all, and says nothing about the route it handed out
        if status.is_some() {
            reg.refused();
        }
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
