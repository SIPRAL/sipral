// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A phone's registration, recorded and fed back.
//!
//! The layer a recording is replayed into is the layer the bug is in, and a
//! registration that is challenged, granted and then refreshed forty-five
//! minutes later is decided here rather than in the endpoint: the password,
//! the refresh, the back-off. So the same recording that proves the format
//! also proves that this layer is driven by nothing but its two calls.
//!
//! One of these recordings is in the tree, under `fixtures/replay/`. That is
//! the whole feature in one file: a session that happened once, kept, and
//! replayed on every build afterwards.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};

use crate::account::{Account, AccountId};
use crate::agent::UserAgent;
use crate::event::RegistrationState;
use crate::{
    Credentials, EndpointConfig, Input, Played, Recorder, Recording, Replay, TransportId,
    TransportProtocol, Uri,
};

const UDP: TransportId = TransportId(1);
const SEED: [u8; 32] = [11; 32];
/// What the application calls the one thing it does on its own here.
const ASK: &str = "register";
/// The challenge a registrar answers the first REGISTER with.
const CHALLENGE: &str =
    "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", qop=\"auth\"\r\n";
/// The session in the tree.
const FIXTURE: &str = include_str!("../../../fixtures/replay/registration-challenged.sipralrec");

fn local() -> SocketAddr {
    "192.0.2.1:5060".parse().expect("a local address")
}

fn registrar() -> SocketAddr {
    "192.0.2.9:5060".parse().expect("the registrar's address")
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

fn bound() -> Input<'static> {
    Input::TransportBound {
        transport: UDP,
        protocol: TransportProtocol::Udp,
        local: local(),
        remote: None,
    }
}

fn arriving(data: &[u8]) -> Input<'_> {
    Input::Datagram {
        transport: UDP,
        remote: registrar(),
        local: local(),
        data,
    }
}

/// The one thing the application does that no recording can feed back for it.
fn ask(agent: &mut UserAgent, now: Instant) -> AccountId {
    let account = agent.add_account(
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1"),
            UDP,
            registrar(),
        )
        .credentials(Credentials::new("alice", "open sesame")),
    );
    agent.register(account, now).expect("the REGISTER goes");
    account
}

fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
    let mut scratch = ParseScratch::new();
    parse(bytes, &mut scratch, ParseMode::Lenient)
        .expect("a message")
        .header(name)
        .unwrap_or_default()
        .to_vec()
}

/// A response to a request the agent wrote, echoing what §8.2.6.2 requires.
fn reply(request: &[u8], status: u16, reason: &str, extra: &str) -> Vec<u8> {
    let mut out = format!("SIP/2.0 {status} {reason}\r\n").into_bytes();
    for name in [
        HeaderName::Via,
        HeaderName::From,
        HeaderName::To,
        HeaderName::CallId,
        HeaderName::CSeq,
    ] {
        out.extend_from_slice(name.canonical().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&header(request, name));
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(extra.as_bytes());
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

/// Everything the agent did, in a shape two runs can be compared in.
#[derive(Debug, Default, PartialEq, Eq)]
struct Trace {
    out: Vec<(Duration, Vec<u8>)>,
    events: Vec<String>,
    decisions: String,
}

impl Trace {
    fn drain(&mut self, agent: &mut UserAgent, at: Duration) {
        while let Some(transmit) = agent.poll_transmit() {
            self.out.push((at, transmit.payload.to_vec()));
        }
        while let Some(event) = agent.poll_event() {
            self.events.push(format!("{event:?}"));
        }
    }

    fn close(&mut self, agent: &mut UserAgent) {
        self.decisions = agent.endpoint().diagnostics_json();
    }

    fn last(&self) -> Vec<u8> {
        self.out
            .last()
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_default()
    }
}

/// A registration challenged, granted, and refreshed once the binding is
/// three quarters spent.
fn record() -> (Recording, Trace) {
    let t0 = Instant::now();
    let mut agent = UserAgent::new(EndpointConfig::default(), SEED);
    let mut recorder = Recorder::new(SEED)
        .about("a registrar that challenges, a binding granted for an hour, one refresh");
    let mut trace = Trace::default();

    recorder.arrived(&bound(), t0);
    agent.receive(bound(), t0).expect("binding a transport");
    trace.drain(&mut agent, Duration::ZERO);

    recorder.cue(ASK, t0);
    let account = ask(&mut agent, t0);
    trace.drain(&mut agent, Duration::ZERO);

    for (at, status, reason, extra) in [
        (
            Duration::from_millis(40),
            401,
            "Unauthorized",
            CHALLENGE.to_owned(),
        ),
        (
            Duration::from_millis(95),
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n".to_owned(),
        ),
    ] {
        let answer = reply(&trace.last(), status, reason, &extra);
        recorder.arrived(&arriving(&answer), t0 + at);
        agent
            .receive(arriving(&answer), t0 + at)
            .expect("a well formed datagram");
        trace.drain(&mut agent, at);
    }

    // and then the loop an application runs: come back when the stack says
    // to, until the refresh this layer scheduled for itself has gone. The
    // deadlines are part of the session, which is why a recording holds them
    while trace.out.len() < 3 {
        let due = agent.poll_timeout().expect("a deadline to come back at");
        recorder.woke(due);
        agent.handle_timeout(due);
        trace.drain(&mut agent, due.saturating_duration_since(t0));
    }

    assert_eq!(
        agent.registration_state(account),
        Some(RegistrationState::Refreshing),
        "the binding stands and the refresh is in flight"
    );
    trace.close(&mut agent);
    (recorder.finish().expect("a recording of it"), trace)
}

/// The same session, fed back into an agent that has never seen it.
fn replay(recording: &Recording) -> (Trace, UserAgent) {
    let origin = Instant::now();
    let mut agent = UserAgent::new(EndpointConfig::default(), recording.seed());
    let mut trace = Trace::default();
    let mut replay = Replay::new(recording, origin);

    while let Some(now) = replay.next_at() {
        let at = now.saturating_duration_since(origin);
        let played = replay
            .step(&mut agent)
            .expect("the recorded bytes read as they did the first time");
        if let Some(Played::Cue(label)) = played {
            assert_eq!(label, ASK, "the recording names what the application did");
            ask(&mut agent, now);
        }
        trace.drain(&mut agent, at);
    }

    trace.close(&mut agent);
    (trace, agent)
}

#[test]
fn a_recorded_registration_replays_to_the_same_bytes_events_and_decisions() {
    let (recording, live) = record();
    let (replayed, _) = replay(&recording);

    assert_eq!(live.out.len(), 3, "a REGISTER, a retry, and a refresh");
    assert_eq!(replayed.out, live.out, "the same bytes at the same offsets");
    assert_eq!(replayed.events, live.events);
    assert_eq!(
        replayed.decisions, live.decisions,
        "the endpoint decided the same things in the same order, at the same offsets"
    );
}

#[test]
fn the_recording_in_the_tree_is_the_session_it_says_it_is() {
    let recording = Recording::parse(FIXTURE).expect("the recording in fixtures/replay");
    let (trace, mut agent) = replay(&recording);

    assert_eq!(trace.out.len(), 3, "a REGISTER, a retry, and a refresh");
    let sent: Vec<Vec<u8>> = trace
        .out
        .iter()
        .map(|(_, bytes)| header(bytes, HeaderName::Authorization))
        .collect();
    assert!(
        sent.first().is_some_and(Vec::is_empty),
        "the first REGISTER asks without credentials"
    );
    let answered = String::from_utf8_lossy(sent.get(1).map_or(b"".as_slice(), Vec::as_slice));
    assert!(
        answered.contains("nonce=\"abc123\""),
        "the retry answers the challenge that is in the recording: {answered}"
    );
    assert!(
        !answered.contains("open sesame"),
        "and the password does not travel: {answered}"
    );
    // and the refresh fifty-one minutes later carries the answer on the way
    // out rather than paying for a second 401 (RFC 3261 §22.2). This assertion
    // used to say the opposite, and the recording is what caught the change:
    // a fixture that replays a session is a fixture that notices when the
    // session stops being the one it recorded
    let refreshed = String::from_utf8_lossy(sent.get(2).map_or(b"".as_slice(), Vec::as_slice));
    assert!(
        refreshed.contains("nonce=\"abc123\""),
        "the refresh asks to be challenged all over again: {refreshed:?}"
    );
    assert!(
        !refreshed.contains("open sesame"),
        "and the password still does not travel: {refreshed}"
    );
    for (_, bytes) in &trace.out {
        assert!(bytes.starts_with(b"REGISTER sip:example.com SIP/2.0\r\n"));
    }

    assert!(
        trace
            .events
            .iter()
            .any(|event| event.starts_with("Registered")),
        "{:?}",
        trace.events
    );
    assert_eq!(
        agent.registration_state(AccountId(0)),
        Some(RegistrationState::Refreshing),
        "the binding was granted and the refresh is on its way"
    );
    assert!(
        agent.endpoint().diagnostics_json().contains("challenge"),
        "the challenge is where the field failure would be read"
    );
}

#[test]
fn replaying_the_recording_in_the_tree_twice_gives_the_same_run_twice() {
    // determinism is the property, so it is tested as one: two replays of the
    // same file into two agents that share nothing
    let recording = Recording::parse(FIXTURE).expect("the recording in fixtures/replay");
    let (first, _) = replay(&recording);
    let (second, _) = replay(&recording);
    assert_eq!(first, second);
}

#[test]
fn the_recording_in_the_tree_is_what_a_run_of_this_session_writes() {
    // the fixture is a capture rather than a document: it is regenerated by
    // running the session again, and this is what says so
    let (recording, _) = record();
    let text = recording.to_text();
    assert_eq!(
        text, FIXTURE,
        "fixtures/replay/registration-challenged.sipralrec is no longer what this session \
         records, and what it records now is:\n{text}"
    );
}

#[test]
fn a_recording_of_one_layer_replays_into_the_layer_below_it() {
    // the trait is on both layers and the file says nothing about which one
    // it came from, so the same recording fed to the endpoint gets the
    // endpoint's answer to it: none, because a REGISTER is the layer above
    let recording = Recording::parse(FIXTURE).expect("the recording in fixtures/replay");
    let mut endpoint =
        sipral_core::endpoint::Endpoint::new(EndpointConfig::default(), recording.seed());
    let mut replay = Replay::new(&recording, Instant::now());
    let mut cues = 0;
    while let Some(played) = replay.step(&mut endpoint).expect("the bytes read") {
        if matches!(played, Played::Cue(_)) {
            cues += 1;
        }
    }
    assert_eq!(cues, 1, "the one thing the application did");
    assert!(
        endpoint.poll_transmit().is_none(),
        "and without a layer that knows how to do it, nothing was sent"
    );
}
