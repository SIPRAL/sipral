// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! In-process proof that `examples/agent-bridge.rs`'s bridge carries a call
//! from a PBX to a voice agent and back: three stacks on loopback, each on a
//! real UDP socket.
//!
//! - the PBX: places the caller's call at the bridge, takes a REFER of it,
//!   and answers the call to a person a transfer asks for;
//! - the bridge: `examples/common/agent_bridge.rs`, the very code the
//!   example runs;
//! - the agent: answers on PCMA where the PBX's call is PCMU, so the
//!   bridge's two legs are on two codecs.
//!
//! Every party sends a tone of its own pitch, and what each one hears is
//! measured at every pitch: the far side's, and not its own. What only a
//! message carries — the caller's context on the agent's INVITE, the
//! outcome on the PBX's BYE — is read off the datagrams the parties received.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[path = "../examples/common/agent_bridge.rs"]
mod agent_bridge;
#[path = "../examples/common/media_socket.rs"]
mod media_socket;
#[path = "../examples/common/udp_endpoint.rs"]
mod udp_endpoint;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use sipral::{
    Account, AccountId, CallHandle, CodecCatalog, DEFAULT_DIGIT, Digit, EndpointConfig, Event,
    ForkPolicy, MediaConfig, MediaEngine, MediaEvent, OutgoingCall, OutgoingExtras, UaEvent, Uri,
    UserAgent, WallClock,
};
use sipral_core::msg::HeaderName;

use agent_bridge::{Action, Bridge, Outcome, OutcomeMode, Policy, Routes, TransferMode};
use udp_endpoint::Endpoint;

/// The pitches: the caller, the agent, and the person a transfer reaches.
const CALLER_HZ: f64 = 500.0;
const AGENT_HZ: f64 = 1_100.0;
const PERSON_HZ: f64 = 1_700.0;

const AMPLITUDE: f64 = 8_000.0;

/// How much of what a call heard is measured, from the first frame the far
/// end's tone is loud in. When that frame comes is up to the jitter buffers
/// on the way, a bridge's and the listener's, which wait longer the more
/// unevenly packets arrive: on a busy machine half a second each. So the
/// moment is found in the audio, not on the clock.
const LISTEN: Duration = Duration::from_millis(1_000);

/// The longest any one step may take.
const STEP: Duration = Duration::from_secs(10);

/// One tone a call sends, and everything it heard.
struct Tone {
    hz: f64,
    phase: usize,
    rate: u32,
    heard: Vec<i16>,
}

impl Tone {
    const fn new(hz: f64) -> Self {
        Self {
            hz,
            phase: 0,
            rate: 8_000,
            heard: Vec::new(),
        }
    }
}

/// The PBX or the agent: a stack that places and answers calls with a tone
/// of its own, and remembers what happened to them.
struct Party {
    endpoint: Endpoint,
    /// Set by [`Party::point_at`].
    account: Option<AccountId>,
    /// The tone a call answered here sends.
    answers_with: f64,
    tones: HashMap<CallHandle, Tone>,
    incoming: Vec<CallHandle>,
    confirmed: Vec<CallHandle>,
    ended: Vec<CallHandle>,
    digits: Vec<(CallHandle, char)>,
    /// The REFERs this end was sent, by call: never taken unless a test
    /// takes one.
    referred: Vec<(CallHandle, String)>,
}

impl Party {
    fn new(codecs: &[&str], seed: u8, answers_with: f64, now: Instant) -> Self {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut endpoint = Endpoint::bind(
            loopback,
            UserAgent::new(EndpointConfig::default(), [seed; 32]).unwrap(),
            MediaEngine::new(
                CodecCatalog::with_order(codecs).unwrap(),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [seed.wrapping_add(1); 32],
            ),
            now,
        )
        .unwrap();
        endpoint.tap = Some(Vec::new());
        Self {
            endpoint,
            account: None,
            answers_with,
            tones: HashMap::new(),
            incoming: Vec::new(),
            confirmed: Vec::new(),
            ended: Vec::new(),
            digits: Vec::new(),
            referred: Vec::new(),
        }
    }

    /// An account that never registers, whose requests go to `server`.
    fn point_at(&mut self, name: &str, server: SocketAddr) {
        let me = Uri::parse_str(&format!("sip:{name}@{}", self.endpoint.local)).unwrap();
        self.account = Some(self.endpoint.add_account(Account::unregistered(
            me.clone(),
            me,
            self.endpoint.transport,
            server,
        )));
    }

    fn turn(&mut self, now: Instant) -> bool {
        for event in self.endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
                    self.incoming.push(call);
                    let local = self.endpoint.open_media(call, now).unwrap();
                    self.endpoint
                        .engine
                        .answer(&mut self.endpoint.agent, call, local, now)
                        .unwrap();
                    self.tones.insert(call, Tone::new(self.answers_with));
                }
                Event::Signalling(UaEvent::CallConfirmed { call, .. }) => {
                    self.confirmed.push(call);
                }
                Event::Signalling(UaEvent::CallEnded { call, .. }) => {
                    self.ended.push(call);
                    self.endpoint.close_media(call);
                }
                Event::Signalling(UaEvent::TransferRequested { call, target, .. }) => {
                    self.referred.push((call, target.as_str().to_owned()));
                }
                Event::Media {
                    call,
                    event:
                        MediaEvent::DigitReceived {
                            digit: Some(key), ..
                        },
                } => self.digits.push((call, key)),
                _ => {}
            }
        }
        let tones = &mut self.tones;
        self.endpoint.run_media(now, |call, media, session, now| {
            let Some(tone) = tones.get_mut(&call) else {
                return;
            };
            tone.rate = session.sample_rate();
            let Tone {
                hz,
                phase,
                rate,
                heard,
            } = tone;
            media.turn(
                session,
                now,
                |room| {
                    let step = core::f64::consts::TAU * *hz / f64::from(*rate);
                    for sample in room.iter_mut() {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
                        let value = (AMPLITUDE * (step * *phase as f64).sin()) as i16;
                        *sample = value;
                        *phase += 1;
                    }
                },
                |room| heard.extend_from_slice(room),
            );
        });
        self.endpoint.timers(now);
        self.endpoint.read_sip(Instant::now())
    }

    fn place(&mut self, outgoing: OutgoingCall, hz: f64, now: Instant) -> CallHandle {
        let account = self.account.expect("pointed at the bridge");
        let call = udp_endpoint::place(&mut self.endpoint, account, outgoing, now).unwrap();
        self.tones.insert(call, Tone::new(hz));
        call
    }

    fn send_digit(&mut self, call: CallHandle, key: char) {
        let mut session = self.endpoint.engine.session(call).expect("media");
        session
            .send_dtmf(Digit::from_char(key).unwrap(), DEFAULT_DIGIT)
            .expect("named events were negotiated");
    }

    fn forget(&mut self) {
        for tone in self.tones.values_mut() {
            tone.heard.clear();
        }
    }

    /// Whether a request this end received starts with `method` and
    /// carries `line` among its header lines.
    fn received(&self, method: &str, line: &str) -> bool {
        self.endpoint.tap.as_ref().is_some_and(|kept| {
            kept.iter().any(|datagram| {
                let text = String::from_utf8_lossy(datagram);
                text.starts_with(method) && text.lines().any(|seen| seen.trim_end() == line)
            })
        })
    }
}

/// Which of the two parties.
#[derive(Clone, Copy)]
enum Side {
    Pbx,
    Agent,
}

/// The three stacks, and the bridge between them.
struct World {
    pbx: Party,
    agent: Party,
    bridge_endpoint: Endpoint,
    bridge: Bridge,
}

impl World {
    fn new(policy: Policy) -> Self {
        let now = Instant::now();
        let mut pbx = Party::new(&["PCMU"], 0x51, PERSON_HZ, now);
        let mut agent = Party::new(&["PCMA"], 0x61, AGENT_HZ, now);
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut bridge_endpoint = Endpoint::bind(
            loopback,
            UserAgent::new(EndpointConfig::default(), [0x71; 32]).unwrap(),
            MediaEngine::new(
                CodecCatalog::with_order(&["PCMU", "PCMA"]).unwrap(),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [0x72; 32],
            ),
            now,
        )
        .unwrap();
        let me = Uri::parse_str(&format!("sip:bridge@{}", bridge_endpoint.local)).unwrap();
        let line = bridge_endpoint.add_account(Account::unregistered(
            me.clone(),
            me.clone(),
            bridge_endpoint.transport,
            pbx.endpoint.local,
        ));
        let agent_account = bridge_endpoint.add_account(Account::unregistered(
            me.clone(),
            me,
            bridge_endpoint.transport,
            agent.endpoint.local,
        ));
        let bridge = Bridge::new(
            Routes {
                line,
                line_domain: pbx.endpoint.local.to_string(),
                agent_account,
                agent: Uri::parse_str(&format!("sip:agent@{}", agent.endpoint.local)).unwrap(),
                agent_route: (bridge_endpoint.transport, agent.endpoint.local),
            },
            policy,
        );
        pbx.point_at("pbx", bridge_endpoint.local);
        agent.point_at("agent", bridge_endpoint.local);
        Self {
            pbx,
            agent,
            bridge_endpoint,
            bridge,
        }
    }

    fn turn(&mut self) {
        let now = Instant::now();
        let pbx = self.pbx.turn(now);
        let agent = self.agent.turn(now);
        for event in self.bridge_endpoint.pump(now) {
            self.bridge.on_event(&mut self.bridge_endpoint, &event, now);
        }
        self.bridge.run_media(&mut self.bridge_endpoint, now);
        self.bridge_endpoint.timers(now);
        let bridge = self.bridge_endpoint.read_sip(Instant::now());
        if !pbx && !agent && !bridge {
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Turn until `done` holds, or fail naming `what`.
    fn until(&mut self, what: &str, done: impl Fn(&Self) -> bool) -> Result<(), String> {
        let deadline = Instant::now() + STEP;
        while Instant::now() < deadline {
            self.turn();
            if done(self) {
                return Ok(());
            }
        }
        Err(format!("timed out waiting until {what}"))
    }

    /// Listen afresh: what either end heard so far is forgotten.
    fn listen(&mut self) {
        self.pbx.forget();
        self.agent.forget();
    }

    fn party(&mut self, side: Side) -> &mut Party {
        match side {
            Side::Pbx => &mut self.pbx,
            Side::Agent => &mut self.agent,
        }
    }

    /// Turn until `call` has heard [`LISTEN`] of audio since `hears` was
    /// first loud in it, after [`World::listen`]; in that audio, `hears` is
    /// loud and `not` is not.
    ///
    /// Only the frames that carried something count. A machine too busy to
    /// turn the three stacks in real time starves the bridge, which drops
    /// what it cannot catch up on, and the listener's buffer waits out the
    /// gaps: what is measured here is whose voice each end hears, so the
    /// silence between is left out rather than counted against it.
    fn hears(
        &mut self,
        side: Side,
        who: &str,
        call: CallHandle,
        hears: f64,
        not: f64,
    ) -> Result<(), String> {
        let deadline = Instant::now() + STEP;
        loop {
            let tone = &self.party(side).tones[&call];
            let frame = usize::try_from(tone.rate / 50).unwrap();
            let wanted = usize::try_from(LISTEN.as_millis() / 20).unwrap();
            let audible: Vec<&[i16]> = tone
                .heard
                .chunks_exact(frame)
                .skip_while(|chunk| level_at(chunk, tone.rate, hears) <= AMPLITUDE / 8.0)
                .filter(|chunk| chunk.iter().any(|sample| sample.unsigned_abs() > 64))
                .collect();
            if audible.len() >= wanted {
                let mean = |hz: f64| {
                    audible
                        .iter()
                        .take(wanted)
                        .map(|chunk| level_at(chunk, tone.rate, hz))
                        .sum::<f64>()
                        / f64::from(u32::try_from(wanted).unwrap())
                };
                let (loud, quiet) = (mean(hears), mean(not));
                if loud > AMPLITUDE / 8.0 && loud > quiet * 4.0 {
                    return Ok(());
                }
                return Err(format!(
                    "{who} heard {hears} Hz at {loud:.0} and {not} Hz at {quiet:.0}"
                ));
            }
            if Instant::now() >= deadline {
                let frames = audible.len();
                let buffer = self
                    .party(side)
                    .endpoint
                    .engine
                    .session(call)
                    .map(|session| format!("{:?}", session.statistics(Instant::now()).quality));
                return Err(format!(
                    "{who} heard {frames} frames of {wanted} from {hears} Hz on; \
                     its buffer: {buffer:?}"
                ));
            }
            self.turn();
        }
    }

    /// The caller's call placed at the bridge with a field of the PBX's
    /// own, the agent's answered, and both carrying audio.
    fn connect(&mut self) -> Result<(CallHandle, CallHandle), String> {
        let bridge = Uri::parse_str(&format!("sip:bridge@{}", self.bridge_endpoint.local)).unwrap();
        let outgoing = OutgoingCall::new(bridge).header(HeaderName::Extension("X-Ticket"), b"42");
        let caller = self.pbx.place(outgoing, CALLER_HZ, Instant::now());
        self.until("the agent is called", |world| {
            !world.agent.incoming.is_empty()
        })?;
        let agent_call = self.agent.incoming[0];
        self.until("the caller is answered", |world| {
            world.pbx.confirmed.contains(&caller)
        })?;
        Ok((caller, agent_call))
    }

    /// The PBX's REFER of the caller's call, once it arrives.
    fn pbx_referred(&mut self, caller: CallHandle) -> Result<String, String> {
        self.until("the PBX is sent a REFER", |world| {
            world.pbx.referred.iter().any(|(call, _)| *call == caller)
        })?;
        Ok(self
            .pbx
            .referred
            .iter()
            .find(|(call, _)| *call == caller)
            .map(|(_, target)| target.clone())
            .unwrap_or_default())
    }
}

/// The amplitude of `hz` in `samples`, by Goertzel's recurrence.
fn level_at(samples: &[i16], rate: u32, hz: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let coefficient = 2.0 * (core::f64::consts::TAU * hz / f64::from(rate)).cos();
    let (mut previous, mut before) = (0.0_f64, 0.0_f64);
    for &sample in samples {
        let next = f64::from(sample) + coefficient * previous - before;
        before = previous;
        previous = next;
    }
    let power = previous * previous + before * before - coefficient * previous * before;
    #[allow(clippy::cast_precision_loss)]
    let length = samples.len() as f64;
    power.max(0.0).sqrt() * 2.0 / length
}

/// Run `attempt` up to three times: a real UDP send can sit long enough in
/// a busy machine's queue that a stream is read as lost
/// (`tests/headless_bridge.rs` says more).
fn retried(attempt: fn() -> Result<(), String>) {
    let mut last = String::new();
    for _ in 0..3 {
        match attempt() {
            Ok(()) => return,
            Err(reason) => {
                eprintln!("attempt failed: {reason}");
                last = reason;
            }
        }
    }
    panic!("{last}");
}

fn outcome_line(outcome: Outcome) -> String {
    format!("{}: {}", agent_bridge::OUTCOME_HEADER, outcome.name())
}

#[test]
fn the_bridge_carries_audio_both_ways_forwards_digits_and_ends_with_the_agent() {
    retried(|| {
        let mut world = World::new(Policy::default());
        let (caller, agent_call) = world.connect()?;

        if !world.agent.received("INVITE ", "X-Ticket: 42")
            || !world
                .agent
                .received("INVITE ", "X-Sipral-Caller-Number: pbx")
        {
            return Err("the agent's INVITE carried no caller context".to_owned());
        }
        world.listen();
        world.hears(Side::Pbx, "the caller", caller, AGENT_HZ, CALLER_HZ)?;
        world.hears(Side::Agent, "the agent", agent_call, CALLER_HZ, AGENT_HZ)?;
        let legs = world.bridge.legs();
        let named =
            |codec: Option<sipral::Codec>| codec.map(|codec| codec.encoding_name().to_owned());
        if legs.len() != 1
            || named(legs[0].caller_codec).as_deref() != Some("PCMU")
            || named(legs[0].agent_codec).as_deref() != Some("PCMA")
        {
            return Err(format!("the legs' codecs read {legs:?}"));
        }

        world.pbx.send_digit(caller, '5');
        world.until("the agent hears the caller's 5", |world| {
            world.agent.digits.contains(&(agent_call, '5'))
        })?;
        world.agent.send_digit(agent_call, '7');
        world.until("the caller hears the agent's 7", |world| {
            world.pbx.digits.contains(&(caller, '7'))
        })?;

        world
            .agent
            .endpoint
            .agent
            .hangup(agent_call, Instant::now())
            .unwrap();
        world.until("the caller's call ends with the agent's", |world| {
            world.pbx.ended.contains(&caller) && world.bridge.len() == 0
        })?;
        if world.pbx.received("BYE ", &outcome_line(Outcome::Resolved)) {
            Ok(())
        } else {
            Err("the PBX's BYE did not say resolved".to_owned())
        }
    });
}

#[test]
fn a_refer_from_the_agent_is_a_refer_of_the_callers_call_to_the_pbx() {
    retried(|| {
        let mut world = World::new(Policy::default());
        let (caller, agent_call) = world.connect()?;

        // a host the PBX does not answer for: the PBX is asked for the user
        // at its own domain
        let person = Uri::parse_str("sip:200@agents.example.invalid").unwrap();
        world
            .agent
            .endpoint
            .agent
            .transfer(agent_call, &person, Instant::now())
            .unwrap();
        let target = world.pbx_referred(caller)?;
        let expected = format!("sip:200@{}", world.pbx.endpoint.local);
        if target != expected {
            return Err(format!("the PBX was asked for {target}, not {expected}"));
        }

        // the PBX takes it, and calls the person itself (here, itself)
        let now = Instant::now();
        let media = media_socket::MediaSocket::bind(now).unwrap();
        let pbx = &mut world.pbx.endpoint;
        let local = SocketAddr::new(pbx.local.ip(), media.port().unwrap());
        let destination = Some((pbx.transport, pbx.local));
        let placed = pbx
            .engine
            .accept_transfer(
                &mut pbx.agent,
                caller,
                local,
                OutgoingExtras {
                    destination,
                    forks: ForkPolicy::default(),
                    headers: &[],
                },
                now,
            )
            .unwrap();
        pbx.media.insert(placed, media);
        world.pbx.tones.insert(placed, Tone::new(CALLER_HZ));
        world.until("the bridge leaves the call to the PBX", |world| {
            world.pbx.ended.contains(&caller)
                && world.agent.ended.contains(&agent_call)
                && world.bridge.len() == 0
        })?;
        world.until("the PBX's own call to the person is up", |world| {
            world.pbx.confirmed.contains(&placed)
        })
    });
}

#[test]
fn a_named_outcome_ends_the_callers_call_with_it() {
    retried(|| {
        let mut world = World::new(Policy::default());
        let (caller, agent_call) = world.connect()?;
        let callback = Uri::parse_str("sip:callback@agents.example.invalid").unwrap();
        world
            .agent
            .endpoint
            .agent
            .transfer(agent_call, &callback, Instant::now())
            .unwrap();
        world.until("both calls end", |world| {
            world.pbx.ended.contains(&caller)
                && world.agent.ended.contains(&agent_call)
                && world.bridge.len() == 0
        })?;
        if world.pbx.received("BYE ", &outcome_line(Outcome::Callback)) {
            Ok(())
        } else {
            Err("the PBX's BYE did not say callback".to_owned())
        }
    });
}

#[test]
fn an_outcome_with_an_address_returns_the_caller_to_the_pbx_by_refer() {
    retried(|| {
        let queue = Uri::parse_str("sip:800@pbx.example.invalid").unwrap();
        let mut world = World::new(Policy {
            outcomes: OutcomeMode::Refer,
            outcome_uris: vec![(Outcome::Callback, queue.clone())],
            ..Policy::default()
        });
        let (caller, agent_call) = world.connect()?;
        let callback = Uri::parse_str("sip:callback@agents.example.invalid").unwrap();
        world
            .agent
            .endpoint
            .agent
            .transfer(agent_call, &callback, Instant::now())
            .unwrap();
        let target = world.pbx_referred(caller)?;
        if target != queue.as_str() {
            return Err(format!("the PBX was asked for {target}, not {queue}"));
        }
        world.until("the agent's call ends", |world| {
            world.agent.ended.contains(&agent_call)
        })
    });
}

#[test]
fn an_agent_call_past_its_time_ends_as_expired() {
    retried(|| {
        let mut world = World::new(Policy {
            max_agent: Some(Duration::from_secs(1)),
            ..Policy::default()
        });
        let (caller, agent_call) = world.connect()?;
        world.until("both calls end", |world| {
            world.pbx.ended.contains(&caller)
                && world.agent.ended.contains(&agent_call)
                && world.bridge.len() == 0
        })?;
        if world.pbx.received("BYE ", &outcome_line(Outcome::Expired)) {
            Ok(())
        } else {
            Err("the PBX's BYE did not say expired".to_owned())
        }
    });
}

#[test]
fn a_bridged_transfer_puts_the_caller_through_to_the_person_it_names() {
    retried(|| {
        let mut world = World::new(Policy {
            transfer: TransferMode::Bridge,
            ..Policy::default()
        });
        let (caller, agent_call) = world.connect()?;
        world.listen();
        world.hears(Side::Pbx, "the caller", caller, AGENT_HZ, CALLER_HZ)?;

        let person = Uri::parse_str("sip:person@agents.example.invalid").unwrap();
        world
            .agent
            .endpoint
            .agent
            .transfer(agent_call, &person, Instant::now())
            .unwrap();
        world.until("the person is called on the PBX", |world| {
            world.pbx.incoming.len() == 1
        })?;
        let person_call = world.pbx.incoming[0];
        world.until("the agent is hung up once the person answers", |world| {
            world.agent.ended.contains(&agent_call)
        })?;

        world.listen();
        world.hears(Side::Pbx, "the caller", caller, PERSON_HZ, AGENT_HZ)?;
        world.hears(Side::Pbx, "the person", person_call, CALLER_HZ, AGENT_HZ)?;

        world.pbx.send_digit(caller, '9');
        world.until("the person hears the caller's 9", |world| {
            world.pbx.digits.contains(&(person_call, '9'))
        })?;

        world
            .pbx
            .endpoint
            .agent
            .hangup(caller, Instant::now())
            .unwrap();
        world.until("the person's call ends with the caller's", |world| {
            world.pbx.ended.contains(&person_call) && world.bridge.len() == 0
        })
    });
}

#[test]
fn a_refer_target_is_a_user_at_the_pbx_or_an_outcome() {
    let decided =
        |target: &str| agent_bridge::decide(&Uri::parse_str(target).unwrap(), "pbx.example");
    let transfer = |target: &str| match decided(target) {
        Action::Transfer(uri) => Some(uri.as_str().to_owned()),
        _ => None,
    };
    assert_eq!(
        transfer("sip:200@agents.example").as_deref(),
        Some("sip:200@pbx.example")
    );
    assert_eq!(
        transfer("tel:+15551234567").as_deref(),
        Some("sip:+15551234567@pbx.example")
    );
    assert_eq!(
        transfer("sip:human@agents.example").as_deref(),
        Some("sip:human@pbx.example")
    );
    assert!(matches!(
        decided("sip:callback@x.example"),
        Action::End(Outcome::Callback)
    ));
    assert!(matches!(
        decided("sip:Resolved@x.example"),
        Action::End(Outcome::Resolved)
    ));
    assert!(matches!(decided("sip:agents.example"), Action::Refuse));
}
