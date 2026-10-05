// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call from the PBX, bridged to a voice agent that answers SIP itself:
//! the logic `agent-bridge.rs` runs over its sockets and
//! `tests/agent_bridge.rs` runs over loopback, written once.
//!
//! Each caller gets a second call, to the agent, and the two are joined in a
//! local conference without this end in it — two members, each on its own
//! codec and rate, one audio stream each. The caller hears the PBX ring
//! until the agent answers, and is answered only then. A digit is forwarded
//! from the events rather than through the mix, because the conference
//! mixes audio and a telephone event is not audio. Either side hanging up
//! ends the other.
//!
//! **What the call came to.** The PBX hears how the agent's part ended as
//! an [`Outcome`]: on the BYE that ends the caller's call, in an
//! `X-Sipral-Outcome` field ([`OutcomeMode::Header`]), or — for a PBX that
//! reads no field off a BYE — as a REFER of the caller's call to an address
//! configured for that outcome ([`OutcomeMode::Refer`]). The outcome is
//! the one a REFER from the agent named, `expired` when the agent's call
//! outlived [`Policy::max_agent`], one named in the `Reason` text of the
//! agent's BYE, and `resolved` otherwise.
//!
//! **A REFER from the agent** goes to [`Policy::decide`], which answers
//! with an [`Action`]. [`decide`] is the default: a user part that names an
//! outcome other than `human` ends the call with that outcome, and any
//! other target is a transfer to that user at the PBX. A transfer is a
//! REFER of the caller's call to the PBX ([`TransferMode::Refer`]), so that
//! the PBX places the new call and owns all of it; or, with
//! [`TransferMode::Bridge`], a call this bridge places on the line itself
//! and bridges in the agent's place.
//!
//! The agent's REFER is not taken with `accept_transfer`: that places a call
//! from the account the agent's call belongs to, whose `Contact` and
//! transport point at the agent. It is left open while the transfer runs,
//! refused with the transfer's own failure if it fails, and ends with the
//! agent's call once it succeeds.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    AccountId, CallHandle, CallIdentity, Codec, DEFAULT_DIGIT, Digit, DigitSource, Event,
    LONGEST_DIGIT, LocalConference, LocalConferenceConfig, MediaEvent, OutgoingCall, Reason,
    SHORTEST_DIGIT, StatusCode, TransportId, UaEvent, Uri,
};
use sipral_core::msg::{HeaderName, OwnedMessage, UriRef, UriScheme};

use crate::udp_endpoint::{self, Endpoint};

/// How often the conferences are ticked: the twenty milliseconds
/// `LocalConference::tick` is.
pub(crate) const TICK: Duration = Duration::from_millis(20);

/// The most ticks one turn makes up after a stall: 100 ms.
const CATCH_UP: u32 = 5;

/// How long a REFER of the caller's call may go without a word from the
/// PBX. A REFER refused outright is not reported by the stack — only the
/// NOTIFYs of one it took are — so silence this long is read as a refusal.
pub(crate) const REFER_PATIENCE: Duration = Duration::from_secs(10);

/// The field an outcome rides in on the BYE to the PBX.
pub(crate) const OUTCOME_HEADER: &str = "X-Sipral-Outcome";

/// How the agent's part of a call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The caller wants a person.
    Human,
    /// The caller is to be called back.
    Callback,
    /// The agent dealt with it.
    Resolved,
    /// The agent could not, or never answered.
    Unresolved,
    /// The agent's call ran past [`Policy::max_agent`].
    Expired,
}

impl Outcome {
    pub(crate) const ALL: [Self; 5] = [
        Self::Human,
        Self::Callback,
        Self::Resolved,
        Self::Unresolved,
        Self::Expired,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Callback => "callback",
            Self::Resolved => "resolved",
            Self::Unresolved => "unresolved",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.name().eq_ignore_ascii_case(name.trim()))
    }
}

/// What a REFER from the agent is answered with.
#[derive(Clone, Debug)]
pub(crate) enum Action {
    /// Put the caller through to this address.
    Transfer(Uri),
    /// End the caller's call with this outcome, playing nothing first.
    End(Outcome),
    /// Refuse the REFER; the caller stays with the agent.
    Refuse,
}

/// How a transfer reaches the person it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransferMode {
    /// The caller's call is REFERred to the PBX, which places the new call.
    Refer,
    /// This bridge places the new call on the line and bridges it.
    Bridge,
}

/// How an outcome reaches the PBX.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutcomeMode {
    /// In an `X-Sipral-Outcome` field on the BYE.
    Header,
    /// As a REFER of the caller's call to the outcome's address in
    /// [`Policy::outcome_uris`]; an outcome with none is ended as `Header`.
    Refer,
}

/// Where the bridge sends what.
pub(crate) struct Routes {
    /// The PBX line: calls arrive on it, and a bridged transfer's call
    /// leaves on it.
    pub(crate) line: AccountId,
    /// The host a transfer's target is called at: the PBX's domain, in
    /// place of whatever host the agent named.
    pub(crate) line_domain: String,
    /// The account the agent's call is placed from, on the agent's
    /// transport and with its own `Contact`.
    pub(crate) agent_account: AccountId,
    /// The agent's SIP address.
    pub(crate) agent: Uri,
    /// The transport and the address the agent's INVITE goes to.
    pub(crate) agent_route: (TransportId, SocketAddr),
}

/// What the bridge does on the application's behalf.
pub(crate) struct Policy {
    pub(crate) transfer: TransferMode,
    pub(crate) outcomes: OutcomeMode,
    /// Where each outcome sends the caller, in [`OutcomeMode::Refer`].
    pub(crate) outcome_uris: Vec<(Outcome, Uri)>,
    /// The longest the agent's call may last.
    pub(crate) max_agent: Option<Duration>,
    /// The fields of the PBX's INVITE copied onto the agent's, by name; a
    /// name ending in `*` is a prefix. Matched without regard to case.
    pub(crate) copy_headers: Vec<String>,
    /// What a REFER from the agent does, given its target and the PBX's
    /// domain.
    pub(crate) decide: fn(&Uri, &str) -> Action,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            transfer: TransferMode::Refer,
            outcomes: OutcomeMode::Header,
            outcome_uris: Vec::new(),
            max_agent: None,
            copy_headers: vec!["X-*".to_owned()],
            decide,
        }
    }
}

/// The default answer to a REFER from the agent: a user part naming an
/// outcome other than `human` ends the call with it; anything else — a
/// person's extension, a queue, `human` — is a transfer to that user at the
/// PBX. An application that wants other rules gives [`Policy::decide`] a
/// function of its own.
pub(crate) fn decide(target: &Uri, line_domain: &str) -> Action {
    let named = user_of(target).as_deref().and_then(Outcome::named);
    match named {
        Some(outcome) if outcome != Outcome::Human => Action::End(outcome),
        _ => on_the_line(target, line_domain).map_or(Action::Refuse, Action::Transfer),
    }
}

/// One caller and whoever it is bridged to.
struct Pair {
    caller: CallHandle,
    /// The call to the agent, while it lasts.
    agent: Option<CallHandle>,
    /// The call a bridged transfer placed, while it rings or talks.
    person: Option<CallHandle>,
    /// Whether that call has answered.
    person_up: bool,
    /// Whether the caller has been answered.
    answered: bool,
    /// Whether the caller's call has been REFERred to the PBX and the PBX
    /// has not said how that went.
    referred: bool,
    /// When that REFER is given up on, until the PBX says anything at all.
    refer_until: Option<Instant>,
    /// What the agent's part came to, once something said.
    outcome: Option<Outcome>,
    /// When the agent's call has to end.
    agent_until: Option<Instant>,
    /// What each leg negotiated.
    caller_codec: Option<Codec>,
    agent_codec: Option<Codec>,
    /// The two calls' bridge, once both have media.
    conference: Option<LocalConference>,
}

impl Pair {
    /// Who the caller talks to: the person once that call answered, the
    /// agent until then.
    fn far(&self) -> Option<CallHandle> {
        if self.person_up {
            self.person
        } else {
            self.agent
        }
    }

    fn holds(&self, call: CallHandle) -> bool {
        self.caller == call || self.agent == Some(call) || self.person == Some(call)
    }
}

/// The codec each leg of one bridged call negotiated, for the application
/// to read.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Legs {
    pub(crate) caller: CallHandle,
    pub(crate) agent: Option<CallHandle>,
    pub(crate) caller_codec: Option<Codec>,
    pub(crate) agent_codec: Option<Codec>,
}

/// Every bridged call this process holds.
pub(crate) struct Bridge {
    routes: Routes,
    policy: Policy,
    pairs: Vec<Pair>,
    next_tick: Option<Instant>,
}

impl Bridge {
    pub(crate) const fn new(routes: Routes, policy: Policy) -> Self {
        Self {
            routes,
            policy,
            pairs: Vec::new(),
            next_tick: None,
        }
    }

    /// How many callers are bridged or waiting for the agent.
    pub(crate) fn len(&self) -> usize {
        self.pairs.len()
    }

    /// What every bridged call's legs negotiated.
    pub(crate) fn legs(&self) -> Vec<Legs> {
        self.pairs
            .iter()
            .map(|pair| Legs {
                caller: pair.caller,
                agent: pair.agent,
                caller_codec: pair.caller_codec,
                agent_codec: pair.agent_codec,
            })
            .collect()
    }

    /// Act on one event the endpoint drained.
    pub(crate) fn on_event(&mut self, endpoint: &mut Endpoint, event: &Event, now: Instant) {
        match event {
            Event::Signalling(UaEvent::IncomingCall {
                call,
                identity,
                request,
                ..
            }) => {
                self.incoming(endpoint, *call, identity.as_deref(), request, now);
            }
            Event::Signalling(UaEvent::CallConfirmed { call, .. }) => {
                self.confirmed(endpoint, *call, now);
            }
            Event::Signalling(UaEvent::TransferRequested { call, target, .. }) => {
                self.transfer_asked(endpoint, *call, target, now);
            }
            Event::Signalling(UaEvent::TransferProgress { call, status }) => {
                if let Some(pair) = self.pairs.iter_mut().find(|pair| pair.caller == *call) {
                    println!("the PBX is transferring {call:?}: {status}");
                    pair.refer_until = None;
                }
            }
            Event::Signalling(UaEvent::TransferDone { call, status }) => {
                self.transfer_done(endpoint, *call, *status, now);
            }
            Event::Signalling(UaEvent::CallEnded {
                call,
                status,
                causes,
                ..
            }) => {
                self.ended(endpoint, *call, *status, causes, now);
            }
            // a digit heard in the audio is already in the mix the other
            // side hears; sending it again would play it twice
            Event::Media {
                call,
                event:
                    MediaEvent::DigitReceived {
                        digit: Some(key),
                        held,
                        source,
                        ..
                    },
            } if *source != DigitSource::InBand => {
                self.forward_digit(endpoint, *call, *key, *held);
            }
            Event::Media {
                call,
                event: MediaEvent::Started { codec, .. } | MediaEvent::Changed { codec, .. },
            } => self.negotiated(*call, *codec),
            Event::Media {
                call,
                event: MediaEvent::Ended(stats),
            } => println!(
                "stats {call:?} codec={} sent={} received={} lost={}",
                stats.codec.encoding_name(),
                stats.packets_sent,
                stats.quality.received,
                stats.quality.lost
            ),
            _ => {}
        }
    }

    /// A caller: ring it, and call the agent with what the PBX said about
    /// it.
    fn incoming(
        &mut self,
        endpoint: &mut Endpoint,
        caller: CallHandle,
        identity: Option<&CallIdentity>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let (transport, address) = self.routes.agent_route;
        let bare = OutgoingCall::new(self.routes.agent.clone()).to_address(transport, address);
        let mut outgoing = bare.clone();
        let mut context = context_of(identity, request, &self.policy.copy_headers);
        for (name, value) in &context {
            outgoing = outgoing.header(HeaderName::Extension(name), value.as_bytes());
        }
        let from = identity.map_or_else(String::new, |who| {
            String::from_utf8_lossy(&who.from_uri).into_owned()
        });
        let account = self.routes.agent_account;
        let placed = udp_endpoint::place(endpoint, account, outgoing, now).or_else(|error| {
            // a field the stack will not send is not worth the call
            eprintln!("calling the agent without the caller's context: {error}");
            context.clear();
            udp_endpoint::place(endpoint, account, bare, now)
        });
        match placed {
            Ok(agent) => {
                // a plain 180: the PBX plays its own ringback to the caller
                if let Err(error) = endpoint.agent.ring(caller, None, now) {
                    eprintln!("cannot ring {caller:?}: {error}");
                }
                println!(
                    "incoming {caller:?} from {from}: calling the agent as {agent:?} with {} context fields",
                    context.len()
                );
                self.pairs.push(Pair {
                    caller,
                    agent: Some(agent),
                    person: None,
                    person_up: false,
                    answered: false,
                    referred: false,
                    refer_until: None,
                    outcome: None,
                    agent_until: None,
                    caller_codec: None,
                    agent_codec: None,
                    conference: None,
                });
            }
            Err(error) => {
                eprintln!("cannot call the agent for {caller:?}: {error}");
                let _ = endpoint
                    .agent
                    .reject(caller, StatusCode::SERVICE_UNAVAILABLE, now);
            }
        }
    }

    fn pair_of(&mut self, call: CallHandle) -> Option<&mut Pair> {
        self.pairs.iter_mut().find(|pair| pair.holds(call))
    }

    /// The agent answered — answer the caller — or a bridged transfer's
    /// person did.
    fn confirmed(&mut self, endpoint: &mut Endpoint, call: CallHandle, now: Instant) {
        let max_agent = self.policy.max_agent;
        let Some(pair) = self.pair_of(call) else {
            return;
        };
        if pair.agent == Some(call) && !pair.answered {
            pair.answered = true;
            pair.agent_until = max_agent.map(|longest| now + longest);
            let caller = pair.caller;
            println!("agent answered {call:?}: answering {caller:?}");
            let answered = endpoint
                .open_media(caller, now)
                .map_err(|error| error.to_string())
                .and_then(|local| {
                    endpoint
                        .engine
                        .answer(&mut endpoint.agent, caller, local, now)
                        .map_err(|error| error.to_string())
                });
            if let Err(error) = answered {
                eprintln!("cannot answer {caller:?}: {error}");
                let _ = endpoint.agent.hangup(caller, now);
                let _ = endpoint.agent.hangup(call, now);
            }
        } else if pair.person == Some(call) {
            pair.person_up = true;
            println!("transfer target answered {call:?}");
        }
    }

    /// Say what a leg negotiated, and keep it for [`Bridge::legs`].
    fn negotiated(&mut self, call: CallHandle, codec: Codec) {
        let Some(pair) = self.pair_of(call) else {
            return;
        };
        let leg = if pair.caller == call {
            pair.caller_codec = Some(codec);
            "caller"
        } else if pair.agent == Some(call) {
            pair.agent_codec = Some(codec);
            "agent"
        } else {
            "transfer"
        };
        println!(
            "codec {call:?} {leg} {}/{}",
            codec.encoding_name(),
            codec.sample_rate()
        );
    }

    /// The agent sent a REFER: ask the policy what it means.
    fn transfer_asked(
        &mut self,
        endpoint: &mut Endpoint,
        call: CallHandle,
        target: &Uri,
        now: Instant,
    ) {
        let action = (self.policy.decide)(target, &self.routes.line_domain);
        let mode = self.policy.transfer;
        let line = self.routes.line;
        let Some(pair) = self.pairs.iter_mut().find(|pair| pair.agent == Some(call)) else {
            return;
        };
        if pair.referred || pair.person.is_some() {
            let _ = endpoint
                .agent
                .reject_transfer(call, StatusCode::REQUEST_PENDING, now);
            return;
        }
        println!("agent asked for {target}: {action:?}");
        match action {
            Action::Refuse => {
                let _ = endpoint.agent.reject_transfer(call, decline(), now);
            }
            Action::End(outcome) => {
                // the agent's call ends first; its end ends the caller's
                pair.outcome = Some(outcome);
                let _ = endpoint.agent.hangup(call, now);
            }
            Action::Transfer(uri) if mode == TransferMode::Refer => {
                match endpoint.agent.transfer(pair.caller, &uri, now) {
                    Ok(()) => {
                        println!("referred {:?} to {uri}", pair.caller);
                        pair.referred = true;
                        pair.refer_until = Some(now + REFER_PATIENCE);
                        pair.outcome = Some(Outcome::Human);
                    }
                    Err(error) => {
                        eprintln!("cannot refer {:?} to {uri}: {error}", pair.caller);
                        let _ = endpoint.agent.reject_transfer(
                            call,
                            StatusCode::SERVICE_UNAVAILABLE,
                            now,
                        );
                    }
                }
            }
            Action::Transfer(uri) => {
                match udp_endpoint::place(endpoint, line, OutgoingCall::new(uri.clone()), now) {
                    Ok(person) => {
                        println!("calling {uri} as {person:?}");
                        pair.person = Some(person);
                        pair.outcome = Some(Outcome::Human);
                    }
                    Err(error) => {
                        eprintln!("cannot call {uri}: {error}");
                        let _ = endpoint.agent.reject_transfer(
                            call,
                            StatusCode::SERVICE_UNAVAILABLE,
                            now,
                        );
                    }
                }
            }
        }
    }

    /// The PBX said how a REFER of the caller's call went. A success has
    /// the stack hang that call up, and its end ends the rest.
    fn transfer_done(
        &mut self,
        endpoint: &mut Endpoint,
        call: CallHandle,
        status: StatusCode,
        now: Instant,
    ) {
        let Some(pair) = self.pairs.iter_mut().find(|pair| pair.caller == call) else {
            return;
        };
        if status.is_success() {
            println!("the PBX took {call:?}: {status}");
            pair.referred = false;
            pair.refer_until = None;
            return;
        }
        refused(endpoint, pair, status, now);
    }

    /// One call ended: end what depended on it.
    fn ended(
        &mut self,
        endpoint: &mut Endpoint,
        call: CallHandle,
        status: Option<StatusCode>,
        causes: &[Reason],
        now: Instant,
    ) {
        endpoint.close_media(call);
        let Some(at) = self.pairs.iter().position(|pair| pair.holds(call)) else {
            return;
        };
        let Some(pair) = self.pairs.get_mut(at) else {
            return;
        };
        if pair.caller == call {
            println!("ended {call:?}: the caller's call is over");
            for other in [pair.agent, pair.person].into_iter().flatten() {
                let _ = endpoint.agent.hangup(other, now);
            }
            self.pairs.remove(at);
            return;
        }
        let caller = pair.caller;
        if pair.agent == Some(call) {
            pair.agent = None;
            if pair.person.is_some() || pair.referred {
                println!("ended {call:?}: the agent left during its transfer");
                return;
            }
            if !pair.answered {
                println!("ended {call:?}: the agent did not answer");
                // the agent's own refusal, when it is one a caller can act on
                let code = status
                    .filter(|code| matches!(code.get(), 486 | 600 | 603))
                    .unwrap_or_else(unavailable);
                let _ = endpoint.agent.respond_with_headers(
                    caller,
                    &[(
                        HeaderName::Extension(OUTCOME_HEADER),
                        Outcome::Unresolved.name().as_bytes(),
                    )],
                );
                let _ = endpoint.agent.reject(caller, code, now);
                self.pairs.remove(at);
                return;
            }
            let outcome = pair
                .outcome
                .or_else(|| {
                    causes
                        .iter()
                        .find_map(|cause| cause.text.as_deref().and_then(Outcome::named))
                })
                .unwrap_or(Outcome::Resolved);
            println!(
                "ended {call:?}: the agent hung up, outcome {}",
                outcome.name()
            );
            if !end_with(
                endpoint,
                pair,
                outcome,
                self.policy.outcomes,
                &self.policy.outcome_uris,
                now,
            ) {
                self.pairs.remove(at);
            }
            return;
        }
        // a bridged transfer's call
        pair.person = None;
        if pair.person_up {
            println!("ended {call:?}: the transfer target hung up");
            let _ = endpoint.agent.hangup(caller, now);
            self.pairs.remove(at);
        } else if let Some(agent) = pair.agent {
            let code = status
                .filter(|code| code.get() >= 300)
                .unwrap_or_else(unavailable);
            println!("transfer failed with {code}: {caller:?} stays with the agent");
            pair.outcome = None;
            let _ = endpoint.agent.reject_transfer(agent, code, now);
        } else {
            println!("transfer failed and the agent has gone: ending {caller:?}");
            end_with(
                endpoint,
                pair,
                Outcome::Unresolved,
                OutcomeMode::Header,
                &[],
                now,
            );
            self.pairs.remove(at);
        }
    }

    /// A digit from one side, sent on the other.
    fn forward_digit(
        &mut self,
        endpoint: &mut Endpoint,
        call: CallHandle,
        key: char,
        held: Option<Duration>,
    ) {
        let Some(pair) = self.pair_of(call) else {
            return;
        };
        let to = if pair.caller == call {
            pair.far()
        } else {
            Some(pair.caller)
        };
        let (Some(to), Some(digit)) = (to, Digit::from_char(key)) else {
            return;
        };
        let length = held
            .unwrap_or(DEFAULT_DIGIT)
            .clamp(SHORTEST_DIGIT, LONGEST_DIGIT);
        let Some(mut session) = endpoint.engine.session(to) else {
            return;
        };
        match session.send_dtmf(digit, length) {
            Ok(()) => println!("dtmf {key} from {call:?} to {to:?}"),
            Err(error) => eprintln!("cannot send {key} to {to:?}: {error}"),
        }
    }

    /// Read every call's media, join what is ready to be joined, end an
    /// agent's call that has run too long, and tick the conferences once
    /// each twenty milliseconds. A call in a conference is only read here:
    /// the conference captures and plays it.
    pub(crate) fn run_media(&mut self, endpoint: &mut Endpoint, now: Instant) {
        for call in endpoint.engine.active().collect::<Vec<_>>() {
            let Some(mut session) = endpoint.engine.session(call) else {
                continue;
            };
            if let Some(media) = endpoint.media.get_mut(&call) {
                media.receive(&mut session, now);
            }
        }
        for pair in &mut self.pairs {
            join(endpoint, pair, now);
            if pair.refer_until.is_some_and(|until| now >= until) {
                refused(endpoint, pair, unavailable(), now);
            }
            if let (Some(until), Some(agent)) = (pair.agent_until, pair.agent)
                && now >= until
                && !pair.referred
                && pair.person.is_none()
            {
                println!("the agent's call {agent:?} ran its time: hanging it up");
                pair.agent_until = None;
                pair.outcome = Some(Outcome::Expired);
                let _ = endpoint.agent.hangup(agent, now);
            }
        }
        let mut due = *self.next_tick.get_or_insert(now);
        let mut ticks = 0;
        while now >= due {
            // a short stall is made up, so the far ends hear no gap; a long
            // one starts again from now rather than sending its backlog at
            // once
            if ticks == CATCH_UP {
                due = now + TICK;
                break;
            }
            ticks += 1;
            due += TICK;
            for pair in &mut self.pairs {
                let Some(conference) = pair.conference.as_mut() else {
                    continue;
                };
                if let Err(error) = conference.tick(&[], now) {
                    eprintln!("cannot tick the bridge of {:?}: {error}", pair.caller);
                }
                while let Some(packet) = conference.poll_transmit() {
                    if let Some(media) = endpoint.media.get(&packet.call) {
                        media.send(packet.destination, &packet.payload);
                    }
                }
                while conference.poll_change().is_some() {}
            }
        }
        self.next_tick = Some(due);
        while let Some((call, destination, payload)) = endpoint.engine.poll_rtcp(now) {
            if let Some(media) = endpoint.media.get(&call) {
                media.send_rtcp(destination, &payload);
            }
        }
        while let Some((call, destination, payload)) = endpoint.engine.poll_farewell() {
            if let Some(media) = endpoint.media.get(&call) {
                media.send_rtcp(destination, &payload);
            }
        }
        #[cfg(any(feature = "dtls", feature = "ice"))]
        while let Some((call, destination, payload)) = endpoint.engine.poll_transmit(now) {
            if let Some(media) = endpoint.media.get(&call) {
                media.send(destination, &payload);
            }
        }
    }

    /// When the bridge next wants to run.
    pub(crate) fn next_tick(&self) -> Option<Instant> {
        if self.pairs.iter().any(|pair| pair.conference.is_some()) {
            self.next_tick
        } else {
            None
        }
    }
}

/// The PBX did not take a REFER of the caller's call: the caller stays with
/// the agent, which hears its own REFER failed, or — the agent gone — ends.
fn refused(endpoint: &mut Endpoint, pair: &mut Pair, status: StatusCode, now: Instant) {
    println!(
        "the PBX did not take the REFER of {:?}: {status}",
        pair.caller
    );
    pair.referred = false;
    pair.refer_until = None;
    if let Some(agent) = pair.agent {
        pair.outcome = None;
        let _ = endpoint.agent.reject_transfer(agent, status, now);
    } else {
        let outcome = pair.outcome.unwrap_or(Outcome::Unresolved);
        end_with(endpoint, pair, outcome, OutcomeMode::Header, &[], now);
    }
}

/// End the caller's call with `outcome`: a REFER to the outcome's address
/// in [`OutcomeMode::Refer`] when it has one, a BYE carrying it otherwise.
/// `true` while the caller's call goes on, to be ended by the PBX's REFER.
fn end_with(
    endpoint: &mut Endpoint,
    pair: &mut Pair,
    outcome: Outcome,
    mode: OutcomeMode,
    uris: &[(Outcome, Uri)],
    now: Instant,
) -> bool {
    let caller = pair.caller;
    let to = uris
        .iter()
        .find(|(named, _)| *named == outcome)
        .map(|(_, uri)| uri);
    if mode == OutcomeMode::Refer
        && let Some(uri) = to
    {
        match endpoint.agent.transfer(caller, uri, now) {
            Ok(()) => {
                println!(
                    "returning {caller:?} to the PBX at {uri}: {}",
                    outcome.name()
                );
                pair.referred = true;
                pair.refer_until = Some(now + REFER_PATIENCE);
                pair.outcome = Some(outcome);
                return true;
            }
            Err(error) => eprintln!("cannot refer {caller:?} to {uri}: {error}"),
        }
    }
    println!(
        "ending {caller:?} with {OUTCOME_HEADER}: {}",
        outcome.name()
    );
    let _ = endpoint.agent.respond_with_headers(
        caller,
        &[(
            HeaderName::Extension(OUTCOME_HEADER),
            outcome.name().as_bytes(),
        )],
    );
    let _ = endpoint.agent.hangup(caller, now);
    false
}

/// Bridge the caller to whoever it should be talking to, once both calls
/// have media; and once the person a bridged transfer called is bridged in
/// the agent's place, hang the agent up.
fn join(endpoint: &mut Endpoint, pair: &mut Pair, now: Instant) {
    let Some(far) = pair.far() else {
        return;
    };
    if let Some(conference) = pair.conference.as_ref()
        && conference.contains(far)
    {
        return;
    }
    let (Some(caller_share), Some(far_share)) = (
        endpoint.engine.share(pair.caller),
        endpoint.engine.share(far),
    ) else {
        return;
    };
    // a new conference for the new pair: the agent's call leaves with the
    // old one
    pair.conference = None;
    let made = endpoint.engine.local_conference(LocalConferenceConfig {
        max_members: 2,
        local: None,
    });
    let mut conference = match made {
        Ok(conference) => conference,
        Err(error) => {
            eprintln!("cannot make a bridge for {:?}: {error}", pair.caller);
            return;
        }
    };
    let added = conference
        .add(pair.caller, caller_share)
        .and_then(|()| conference.add(far, far_share));
    if let Err(error) = added {
        eprintln!("cannot bridge {:?} with {far:?}: {error}", pair.caller);
        return;
    }
    pair.conference = Some(conference);
    println!("bridged {:?} with {far:?}", pair.caller);
    if pair.person_up
        && let Some(agent) = pair.agent
    {
        println!(
            "transferred {:?} to {far:?}: hanging the agent up",
            pair.caller
        );
        let _ = endpoint.agent.hangup(agent, now);
    }
}

/// What the agent is told about the caller: its number and display name,
/// what it called, and the PBX INVITE's own fields `copy` names.
fn context_of(
    identity: Option<&CallIdentity>,
    request: &OwnedMessage,
    copy: &[String],
) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    if let Some(who) = identity {
        if let Some(number) = Uri::parse(&who.from_uri).ok().as_ref().and_then(user_of) {
            fields.push(("X-Sipral-Caller-Number".to_owned(), number));
        }
        if !who.from_display.is_empty() {
            fields.push((
                "X-Sipral-Caller-Name".to_owned(),
                String::from_utf8_lossy(&who.from_display).into_owned(),
            ));
        }
        fields.push((
            "X-Sipral-Called".to_owned(),
            String::from_utf8_lossy(&who.to_uri).into_owned(),
        ));
    }
    for (name, value) in request.as_raw().raw_headers() {
        let (Ok(name), Ok(value)) = (std::str::from_utf8(name), std::str::from_utf8(value)) else {
            continue;
        };
        // a folded value is left behind rather than written back folded
        if value.contains(['\r', '\n']) || !copy.iter().any(|wanted| matches_name(wanted, name)) {
            continue;
        }
        fields.push((name.to_owned(), value.trim().to_owned()));
    }
    fields
}

fn matches_name(wanted: &str, name: &str) -> bool {
    match wanted.strip_suffix('*') {
        Some(prefix) => name
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix)),
        None => wanted.eq_ignore_ascii_case(name),
    }
}

/// A URI's user part, or a `tel:` URI's number.
fn user_of(uri: &Uri) -> Option<String> {
    let user = match uri.as_uri_ref() {
        UriRef::Sip(sip) => sip.user?.to_owned(),
        UriRef::Other {
            scheme: UriScheme::Tel,
            opaque,
        } => opaque.split(';').next()?.to_owned(),
        UriRef::Other { .. } => return None,
    };
    (!user.is_empty()).then_some(user)
}

/// The address a transfer's target is called at on the PBX: its user at
/// the PBX's own domain, whatever host the agent named. `None` for a target
/// with no user to call.
pub(crate) fn on_the_line(target: &Uri, domain: &str) -> Option<Uri> {
    let user = user_of(target)?;
    Uri::parse_str(&format!("sip:{user}@{domain}")).ok()
}

fn decline() -> StatusCode {
    StatusCode::new(603).unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
}

fn unavailable() -> StatusCode {
    StatusCode::new(480).unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
}
