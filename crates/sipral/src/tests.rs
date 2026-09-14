// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Two stacks calling each other, with no network under either of them.
//!
//! The point of the whole tree being sans-I/O is that this is possible: two
//! user agents, two media engines, and a function that hands what one of them
//! wanted to write to the other as something that arrived. A call is placed,
//! answered, spoken through, held, resumed and hung up, and the clock only
//! moves because the test moves it.
//!
//! What is being tested here is the join, so the assertions are about the
//! things that only exist because the two halves have been connected: that a
//! call which was answered has audio on it, that the codec it settled on is
//! the one the offer preferred, that a tone put in one end comes out of the
//! other, that the recording has both directions in it, and that a stream
//! which stops is reported rather than sat on.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sipral_core::sdp::{Crypto, Direction, MediaDescription, SessionDescription, parse};
use sipral_rtp::srtp::SrtpError;

use crate::codec::tests::UNMATCHED;
use crate::codec::{Codec, CodecCandidate, CodecCatalog, CodecOutcome};
use crate::dtmf::{DEFAULT_DIGIT, Digit};
use crate::error::MediaError;
use crate::event::{Event, MediaEvent};
use crate::keying::SrtpPolicy;
use crate::record::tests::Buffer;
use crate::session::{Arrival, MediaConfig, MediaSession, Playback, StreamIdentity};
use crate::{
    Account, AccountId, CallHandle, CallMedia, EndpointConfig, Input, MediaEngine, OutgoingCall,
    TransportId, TransportProtocol, UaEvent, Uri, UserAgent, WallClock,
};

const UDP: TransportId = TransportId(1);

/// The codec at the top of the default catalogue, which is what a call
/// between two default stacks settles on: Opus where the feature is on, and
/// G.722 where it is off. Read off `Codec::ALL` rather than written down, so
/// that these tests say "the one the offer preferred" in either build.
const PREFERRED: Codec = Codec::ALL[0];

/// A tick of the fake clock, and the length of one frame.
const TICK: Duration = Duration::from_millis(20);

/// Where the two stacks are.
fn caller_sip() -> SocketAddr {
    "192.0.2.1:5060".parse().expect("an address")
}

fn callee_sip() -> SocketAddr {
    "192.0.2.2:5060".parse().expect("an address")
}

fn caller_media() -> SocketAddr {
    "192.0.2.1:40000".parse().expect("an address")
}

fn callee_media() -> SocketAddr {
    "192.0.2.2:40002".parse().expect("an address")
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

/// One side: a user agent, its media engine, and everything the test has heard
/// from it.
struct Stack {
    agent: UserAgent,
    engine: MediaEngine,
    local: SocketAddr,
    media: SocketAddr,
    heard: Vec<Event>,
}

impl Stack {
    fn new(
        seed: u8,
        local: SocketAddr,
        media: SocketAddr,
        catalog: CodecCatalog,
        now: Instant,
    ) -> Self {
        let mut agent =
            UserAgent::new(EndpointConfig::default(), [seed; 32]).expect("a user agent");
        agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local,
                    remote: None,
                },
                now,
            )
            .expect("binding a transport");
        let engine = MediaEngine::new(
            catalog,
            MediaConfig::default(),
            WallClock::from_unix(now, 1_700_000_000, 0),
            // neither this stack's signalling seed nor the other stack's
            [seed ^ 0xa5; 32],
        );
        Self {
            agent,
            engine,
            local,
            media,
            heard: Vec::new(),
        }
    }

    fn account(&mut self, user: &str, registrar: SocketAddr) -> AccountId {
        let account = Account::new(
            uri(&format!("sip:{user}@example.com")),
            uri("sip:example.com"),
            uri(&format!("sip:{user}@{}", self.local.ip())),
            UDP,
            registrar,
        );
        self.agent.add_account(account)
    }

    /// Drain the engine, keeping everything for the assertions and answering
    /// anything that has to be answered to keep the call moving.
    fn drain(&mut self, now: Instant, answer: bool) {
        while let Some(event) = self.engine.poll_event(&mut self.agent, now) {
            if answer && let Event::Signalling(UaEvent::IncomingCall { call, .. }) = &event {
                let call = *call;
                self.engine
                    .answer(&mut self.agent, call, self.media, now)
                    .expect("the answer goes");
            }
            self.heard.push(event);
        }
    }

    /// Everything the agent wanted to write.
    fn outbound(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(transmit) = self.agent.poll_transmit() {
            out.push(transmit.payload.to_vec());
        }
        out
    }

    fn deliver(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) {
        self.agent
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: from,
                    local: self.local,
                    data: datagram,
                },
                now,
            )
            .expect("a datagram");
    }

    /// The description of the INVITE this side was handed, as it arrived.
    ///
    /// Read out of the message rather than off the engine, because what is
    /// being asserted about is what went on the wire.
    fn offer_received(&self) -> Option<SessionDescription> {
        self.heard.iter().rev().find_map(|event| match event {
            Event::Signalling(UaEvent::IncomingCall { request, .. }) => {
                parse(request.as_raw().body()).ok()
            }
            _ => None,
        })
    }

    /// The same for the description in the response that confirmed the call.
    fn answer_received(&self) -> Option<SessionDescription> {
        self.heard.iter().rev().find_map(|event| match event {
            Event::Signalling(UaEvent::CallConfirmed {
                response: Some(response),
                ..
            }) => parse(response.as_raw().body()).ok(),
            _ => None,
        })
    }

    fn media_events(&self) -> Vec<&MediaEvent> {
        self.heard
            .iter()
            .filter_map(|event| match event {
                Event::Media { event, .. } => Some(event),
                Event::Signalling(_) => None,
            })
            .collect()
    }

    fn call(&self) -> Option<CallHandle> {
        self.heard.iter().find_map(|event| match event {
            Event::Signalling(
                UaEvent::IncomingCall { call, .. } | UaEvent::CallConfirmed { call, .. },
            ) => Some(*call),
            _ => None,
        })
    }

    /// Every call this side has heard about, first-seen order. What
    /// [`Stack::call`] cannot answer once there is more than one — an
    /// attended transfer's consultation leg among them.
    fn calls(&self) -> Vec<CallHandle> {
        let mut found = Vec::new();
        for event in &self.heard {
            if let Event::Signalling(
                UaEvent::IncomingCall { call, .. } | UaEvent::CallConfirmed { call, .. },
            ) = event
                && !found.contains(call)
            {
                found.push(*call);
            }
        }
        found
    }
}

/// The two stacks, wired to each other.
struct Pair {
    caller: Stack,
    callee: Stack,
    now: Instant,
}

impl Pair {
    fn new(catalog: CodecCatalog) -> Self {
        let now = Instant::now();
        Self {
            caller: Stack::new(11, caller_sip(), caller_media(), catalog.clone(), now),
            callee: Stack::new(22, callee_sip(), callee_media(), catalog, now),
            now,
        }
    }

    /// The same, with a different catalogue on each side — D5's three
    /// outcomes only all show up when the two ends do not agree on
    /// everything.
    fn asymmetric(placing: CodecCatalog, answering: CodecCatalog) -> Self {
        let now = Instant::now();
        Self {
            caller: Stack::new(11, caller_sip(), caller_media(), placing, now),
            callee: Stack::new(22, callee_sip(), callee_media(), answering, now),
            now,
        }
    }

    /// Move everything one side wants to write to the other, drain both, and
    /// keep going until nothing more happens.
    fn settle(&mut self) {
        for _ in 0..12 {
            let dialled = self.caller.outbound();
            let answered = self.callee.outbound();
            if dialled.is_empty() && answered.is_empty() {
                break;
            }
            for datagram in dialled {
                self.callee.deliver(&datagram, caller_sip(), self.now);
            }
            for datagram in answered {
                self.caller.deliver(&datagram, callee_sip(), self.now);
            }
            self.caller.drain(self.now, false);
            self.callee.drain(self.now, true);
        }
    }

    /// Place a call and take it all the way to confirmed.
    fn connect(&mut self) -> CallHandle {
        let account = self.caller.account("alice", callee_sip());
        let _ = self.callee.account("bob", caller_sip());
        let placed = self
            .caller
            .engine
            .place(
                &mut self.caller.agent,
                account,
                OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
                caller_media(),
                self.now,
            )
            .expect("the INVITE goes");
        self.caller.drain(self.now, false);
        self.settle();
        placed
    }

    /// Place a call and take it as far as the callee hearing about it,
    /// without answering — what a test about the answer itself needs.
    fn ring(&mut self) -> CallHandle {
        let account = self.caller.account("alice", callee_sip());
        let _ = self.callee.account("bob", caller_sip());
        self.caller
            .engine
            .place(
                &mut self.caller.agent,
                account,
                OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
                caller_media(),
                self.now,
            )
            .expect("the INVITE goes");
        self.caller.drain(self.now, false);
        for datagram in self.caller.outbound() {
            self.callee.deliver(&datagram, caller_sip(), self.now);
        }
        self.callee.drain(self.now, false);
        self.callee.call().expect("the callee heard the INVITE")
    }

    /// One frame from the caller to the callee, keeping the datagram that
    /// crossed as well as the frame that came out of it.
    ///
    /// The copy is not tidiness: an arriving datagram is verified and
    /// decrypted where it lies, so delivering the buffer that was captured
    /// would hand a test back the plaintext it is trying to prove is not on
    /// the wire.
    fn speak(&mut self, call: CallHandle, remote: CallHandle, tone: &[i16]) -> (Vec<u8>, Vec<i16>) {
        let sent = self
            .caller
            .engine
            .session(call)
            .expect("the caller's media")
            .capture(tone)
            .expect("the frame encodes")
            .map(|datagram| datagram.payload.to_vec())
            .expect("a frame that is neither held nor suppressed goes out");
        let mut session = self
            .callee
            .engine
            .session(remote)
            .expect("the callee's media");
        let mut arriving = sent.clone();
        session.receive(&mut arriving, caller_media(), self.now);
        let mut played = vec![0_i16; session.frame_samples()];
        session.playback(&mut played);
        (sent, played)
    }

    /// One frame of audio each way, and the frame the far end played.
    fn exchange(&mut self, call: CallHandle, remote: CallHandle, tone: &[i16]) -> Vec<i16> {
        let outbound = {
            let mut session = self
                .caller
                .engine
                .session(call)
                .expect("the caller's media");
            session
                .capture(tone)
                .expect("the frame encodes")
                .map(|datagram| datagram.payload.to_vec())
        };
        if let Some(mut datagram) = outbound {
            let mut session = self
                .callee
                .engine
                .session(remote)
                .expect("the callee's media");
            // the first packet of a stream is refused: RFC 3550 A.1 wants two
            // in a row before a source is believed, and the latch has already
            // closed on this one either way
            let arrival = session.receive(&mut datagram, caller_media(), self.now);
            assert!(
                matches!(
                    arrival,
                    Arrival::Queued | Arrival::Dropped(crate::Discard::Probation)
                ),
                "the far end refused a packet: {arrival:?}"
            );
        }
        let mut session = self
            .callee
            .engine
            .session(remote)
            .expect("the callee's media");
        let mut played = vec![0_i16; session.frame_samples()];
        session.playback(&mut played);
        played
    }

    fn advance(&mut self) {
        self.now += TICK;
    }

    /// Every control packet either side has due, delivered to the other.
    /// Returns how many crossed and how many were believed.
    fn exchange_control(&mut self, call: CallHandle, remote: CallHandle) -> (usize, usize) {
        let mut sent = 0;
        let mut believed = 0;
        let mut pending = Vec::new();
        while let Some((_, _, payload)) = self.caller.engine.poll_rtcp(self.now) {
            pending.push((payload, true));
        }
        while let Some((_, _, payload)) = self.callee.engine.poll_rtcp(self.now) {
            pending.push((payload, false));
        }
        for (mut datagram, from_caller) in pending {
            sent += 1;
            let (mut session, from) = if from_caller {
                (
                    self.callee.engine.session(remote).expect("media"),
                    "192.0.2.1:40001".parse().expect("an address"),
                )
            } else {
                (
                    self.caller.engine.session(call).expect("media"),
                    "192.0.2.2:40003".parse().expect("an address"),
                )
            };
            if session.receive(&mut datagram, from, self.now) == Arrival::Control {
                believed += 1;
            }
        }
        (sent, believed)
    }
}

/// Roughly 440 Hz at any rate, square so that nothing about the signal itself
/// can be blamed for what comes back.
fn tone(samples: &mut [i16], rate: u32, phase: &mut u32) {
    let period = (rate / 444).max(2);
    for slot in samples.iter_mut() {
        *slot = if *phase % period < period / 2 {
            8_000
        } else {
            -8_000
        };
        *phase = phase.wrapping_add(1);
    }
}

fn loudness(samples: &[i16]) -> i64 {
    if samples.is_empty() {
        return 0;
    }
    let total: i64 = samples.iter().map(|s| i64::from(s.saturating_abs())).sum();
    total / i64::try_from(samples.len()).unwrap_or(1).max(1)
}

// -- the join ----------------------------------------------------------------

/// The whole point of the crate in one test: a call that is answered has audio
/// on it, and neither application wrote a line of SDP.
#[test]
fn a_call_that_is_answered_has_media_on_it() {
    let mut pair = Pair::new(CodecCatalog::new());
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    assert!(
        pair.caller.engine.session(call).is_some(),
        "the caller has no media on a call that is up"
    );
    assert!(
        pair.callee.engine.session(remote).is_some(),
        "the callee has no media on a call that is up"
    );

    for side in [pair.caller.media_events(), pair.callee.media_events()] {
        assert!(
            side.iter().any(|event| matches!(
                event,
                MediaEvent::Started {
                    direction: Direction::SendRecv,
                    ..
                }
            )),
            "no side reported that its media started: {side:?}"
        );
    }
}

/// The raw bytes of a message's body, straight off the wire — what a test
/// needs for a datagram captured from [`Stack::outbound`] rather than read
/// out of a [`UaEvent`].
fn wire_message_body(datagram: &[u8]) -> Vec<u8> {
    let mut scratch = sipral_core::msg::ParseScratch::new();
    let message =
        sipral_core::msg::parse(datagram, &mut scratch, sipral_core::msg::ParseMode::Lenient)
            .expect("a well-formed message");
    message.body().to_vec()
}

/// 8.4.9: an incoming call may be rung with media before it is answered, and
/// [`MediaEngine::answer`] on one that was must not negotiate a second time —
/// same session, same `o=` id and version.
///
/// Every INVITE this build sends carries `Supported: 100rel`
/// (`sipral-core`'s endpoint adds it unconditionally), so a call this
/// harness's own caller places always makes the callee's 183 a reliable one —
/// [`Pair::ring`] cannot produce the other half of RFC 3262 §5 / RFC 6337
/// §3.1.1's rule, an early answer sent unreliably; a hand-written INVITE can,
/// and `crates/sipral-ffi/src/call.rs`'s tests cover it. What this proves
/// instead is the reliable half from both sides of one exchange: the far end
/// PRACKs the 183 the way this stack's own caller always would, and the 200
/// OK that follows carries nothing, because RFC 6337 §3.1.1's UAS rule #2 is
/// that nothing sent reliably is repeated.
#[test]
fn ringing_with_media_then_answering_reuses_the_session_and_the_description() {
    let mut pair = Pair::new(CodecCatalog::new());
    let remote = pair.ring();
    // whatever provisional response the core sent on its own before the
    // application had a chance to
    let _ = pair.callee.outbound();

    pair.callee
        .engine
        .ring(&mut pair.callee.agent, remote, callee_media(), pair.now)
        .expect("the 183 goes");
    pair.callee.drain(pair.now, false);
    assert_eq!(
        pair.callee
            .media_events()
            .iter()
            .filter(|event| matches!(event, MediaEvent::Started { .. }))
            .count(),
        1,
        "ringing with media should start the session once: {:?}",
        pair.callee.media_events()
    );
    assert!(
        pair.callee.engine.session(remote).is_some(),
        "the far end should hear something before anybody answers"
    );

    let progress = pair.callee.outbound();
    assert_eq!(progress.len(), 1, "one 183 goes out");
    assert!(progress[0].starts_with(b"SIP/2.0 183"));
    assert!(
        !wire_message_body(&progress[0]).is_empty(),
        "the 183 carries the description this stack wrote"
    );

    // the far end's own stack already placed this call with an offer, so
    // RFC 3262 §5's "MAY generate an additional offer in the PRACK" is
    // declined and `on_reliable_progress` PRACKs the answer by itself, the
    // same way an application-driven far end would once told the 183 arrived
    for datagram in &progress {
        pair.caller.deliver(datagram, callee_sip(), pair.now);
    }
    pair.settle();

    pair.callee
        .engine
        .answer(&mut pair.callee.agent, remote, callee_media(), pair.now)
        .expect("the 200 OK goes");
    pair.callee.drain(pair.now, false);
    let confirmed = pair.callee.outbound();
    assert_eq!(confirmed.len(), 1, "one 200 OK goes out");
    assert!(confirmed[0].starts_with(b"SIP/2.0 200"));
    assert!(
        wire_message_body(&confirmed[0]).is_empty(),
        "the answer already went out reliably in the 183; RFC 6337 §3.1.1 \
         forbids repeating it in the 200 OK"
    );
    assert_eq!(
        pair.callee
            .media_events()
            .iter()
            .filter(|event| matches!(event, MediaEvent::Started { .. }))
            .count(),
        1,
        "answering a call already rung with media must not start a second session"
    );
}

/// Ringing with media twice on one call is refused, with the error
/// [`MediaEngine::answer`] itself uses for a call in the wrong state.
#[test]
fn ringing_with_media_twice_is_refused() {
    let mut pair = Pair::new(CodecCatalog::new());
    let remote = pair.ring();
    let _ = pair.callee.outbound();

    pair.callee
        .engine
        .ring(&mut pair.callee.agent, remote, callee_media(), pair.now)
        .expect("the first 183 goes");
    let _ = pair.callee.outbound();

    let refused = pair
        .callee
        .engine
        .ring(&mut pair.callee.agent, remote, callee_media(), pair.now);
    assert!(
        matches!(
            refused,
            Err(MediaError::Signalling(sipral_ua::UaError::WrongState(_)))
        ),
        "ringing with media twice should be refused the way answering twice is: {refused:?}"
    );
    assert!(
        pair.callee.outbound().is_empty(),
        "nothing goes out for a refused second 183"
    );
}

/// A4's reporting half. Both ends have the same catalogue, so both should land
/// on the codec at the top of it — and the top of it is not the one a stack
/// falls back to by accident, which is what makes this test say something.
#[test]
fn both_ends_settle_on_the_codec_the_offer_preferred() {
    let mut pair = Pair::new(CodecCatalog::new());
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    assert_eq!(
        pair.caller
            .engine
            .session(call)
            .map(|session| session.codec()),
        Some(PREFERRED)
    );
    assert_eq!(
        pair.callee
            .engine
            .session(remote)
            .map(|session| session.codec()),
        Some(PREFERRED)
    );
}

/// The same call with the catalogue reordered has to land somewhere else, or
/// the order is not doing anything.
#[test]
fn reordering_the_catalogue_changes_what_the_call_uses() {
    let catalog = CodecCatalog::with_order(&["PCMA", "PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();

    let session = pair.caller.engine.session(call).expect("media");
    assert_eq!(session.codec(), Codec::Pcma);
    assert_eq!(session.sample_rate(), 8_000);
    assert_eq!(session.frame_samples(), 160);
}

/// D5: "PCMU was chosen" is a fact; this is the diagnosis. Three candidates,
/// three different reasons, on a real pair of stacks rather than on the
/// negotiation code in isolation.
#[test]
fn a_live_call_says_why_every_other_candidate_was_not_chosen() {
    let mut pair = Pair::asymmetric(
        CodecCatalog::with_order(&[UNMATCHED.0, "PCMA", "PCMU"]).expect("an order"),
        CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order"),
    );
    let call = pair.connect();

    // the callee cannot do the caller's first choice, so the offer of it goes
    // nowhere; both ends do PCMA and PCMU, and the callee's answer names PCMA
    // first
    let session = pair.caller.engine.session(call).expect("media");
    assert_eq!(
        session.codec_candidates(),
        [
            CodecCandidate {
                codec: UNMATCHED.1,
                outcome: CodecOutcome::NotNamed,
            },
            CodecCandidate {
                codec: Codec::Pcma,
                outcome: CodecOutcome::Chosen,
            },
            CodecCandidate {
                codec: Codec::Pcmu,
                outcome: CodecOutcome::Outranked(Codec::Pcma),
            },
        ]
    );
    assert_eq!(
        session.codec(),
        Codec::Pcma,
        "the chosen entry has to agree with what the call actually settled on"
    );
}

/// D6: a second call on the same engine, placed with its own catalogue and
/// its own device, does not move what the first call is using or what the
/// engine's own default is — the shape an attended transfer needs, since
/// `UserAgent::consult` is exactly two live calls on one engine.
#[test]
fn two_calls_on_one_engine_keep_their_own_catalogue_and_device() {
    let default_catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(default_catalog.clone());
    let primary = pair.connect();

    let account = pair.caller.account("alice-consult", callee_sip());
    let consult_catalog = CodecCatalog::with_order(&["PCMA"]).expect("an order");
    let consult_config = MediaConfig {
        device: Some("bluetooth-headset-2".to_owned()),
        ..MediaConfig::default()
    };
    let consult = pair
        .caller
        .engine
        .place_with(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            "192.0.2.1:40010".parse().expect("an address"),
            CallMedia::new(consult_catalog.clone(), consult_config),
            pair.now,
        )
        .expect("the second INVITE goes");
    pair.caller.drain(pair.now, false);
    pair.settle();

    let consult_remote = *pair
        .callee
        .calls()
        .last()
        .expect("the callee has heard about two calls by now");

    // the consult leg landed on what it was told to, not on the engine's
    // default
    assert_eq!(
        pair.caller.engine.session(consult).expect("media").codec(),
        Codec::Pcma
    );
    assert_eq!(
        pair.caller.engine.session(consult).expect("media").device(),
        Some("bluetooth-headset-2")
    );
    assert_eq!(
        pair.caller.engine.call_catalog(consult),
        Some(&consult_catalog)
    );

    // the primary call is untouched: still the engine's default catalogue,
    // still no device recorded on it, still PCMU
    assert_eq!(
        pair.caller.engine.session(primary).expect("media").codec(),
        Codec::Pcmu
    );
    assert_eq!(
        pair.caller.engine.session(primary).expect("media").device(),
        None
    );
    assert_eq!(
        pair.caller.engine.call_catalog(primary),
        Some(&default_catalog)
    );

    // and the engine's own default was never touched by placing the second
    // call with a catalogue of its own
    assert_eq!(pair.caller.engine.catalog(), &default_catalog);

    // both calls really are up, on both ends, at once
    assert!(pair.callee.engine.session(consult_remote).is_some());
    assert!(pair.caller.engine.session(primary).is_some());
}

/// Audio put in one end comes out of the other, at the right length and loud
/// enough to be the tone rather than the concealment.
#[test]
fn a_tone_crosses_the_call() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let frame = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .frame_samples();
    let mut samples = vec![0_i16; frame];
    let mut phase = 0_u32;
    let mut heard = Vec::new();

    for _ in 0..20 {
        tone(&mut samples, 8_000, &mut phase);
        heard = pair.exchange(call, remote, &samples);
        pair.advance();
    }

    assert_eq!(heard.len(), frame);
    assert!(
        loudness(&heard) > 4_000,
        "the tone came back at {} rather than crossing the call",
        loudness(&heard)
    );
}

// -- SDES ---------------------------------------------------------------------

/// One call's worth of a caller talking: the last datagram that crossed, the
/// frame it turned into at the far end, and what the two descriptions said.
struct Spoken {
    offer: MediaDescription,
    answer: MediaDescription,
    /// The first datagram of the stream, which is the only one whose sequence
    /// number is the one the stream started from.
    first: Vec<u8>,
    datagram: Vec<u8>,
    played: Vec<i16>,
    encrypted: bool,
}

fn one_stream(description: &SessionDescription) -> MediaDescription {
    description
        .media
        .first()
        .cloned()
        .expect("one audio stream")
}

fn crypto_line(stream: &MediaDescription) -> Option<Crypto> {
    Crypto::parse(stream.attribute("crypto")?.value.as_deref()?)
}

/// Place a call from `catalog` on both ends, talk for twenty frames, and keep
/// everything a test could want to look at.
fn spoken(catalog: CodecCatalog) -> Spoken {
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    let (frame, rate) = {
        let session = pair.caller.engine.session(call).expect("media");
        (session.frame_samples(), session.sample_rate())
    };
    let mut samples = vec![0_i16; frame];
    let mut phase = 0_u32;
    let mut first = Vec::new();
    let mut datagram = Vec::new();
    let mut played = Vec::new();

    for index in 0..20 {
        tone(&mut samples, rate, &mut phase);
        let (sent, heard) = pair.speak(call, remote, &samples);
        if index == 0 {
            first.clone_from(&sent);
        }
        datagram = sent;
        played = heard;
        pair.advance();
    }

    Spoken {
        offer: one_stream(
            &pair
                .callee
                .offer_received()
                .expect("the callee saw an offer"),
        ),
        answer: one_stream(
            &pair
                .caller
                .answer_received()
                .expect("the caller saw an answer"),
        ),
        encrypted: pair
            .caller
            .engine
            .session(call)
            .expect("media")
            .is_encrypted()
            && pair
                .callee
                .engine
                .session(remote)
                .expect("media")
                .is_encrypted(),
        first,
        datagram,
        played,
    }
}

/// The one that would pass with the encryption never attached is the one that
/// only reads the SDP, so this reads the octets.
///
/// The same call is placed twice, plain and with SDES, from the same seed.
/// Both draw their stream identity from the same first token — the key comes
/// out of the tokens after it — so the two runs put the same SSRC, the same
/// sequence number and the same timestamp on the wire, and every difference
/// past the header is the transform.
#[test]
fn a_call_that_offered_sdes_carries_none_of_the_plaintext_on_the_wire() {
    let plain = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let secure = plain.clone().with_srtp(SrtpPolicy::Offered);
    let open = spoken(plain);
    let closed = spoken(secure);

    // what the descriptions said
    assert_eq!(open.offer.proto, "RTP/AVP");
    assert!(
        crypto_line(&open.offer).is_none(),
        "the default put keys in an offer nobody asked for"
    );
    assert_eq!(closed.offer.proto, "RTP/SAVP");
    assert_eq!(closed.answer.proto, "RTP/SAVP");
    let offered = crypto_line(&closed.offer).expect("the offer carries a crypto line");
    let answered = crypto_line(&closed.answer).expect("the answer carries one too");
    // RFC 4568 §5.1.2: "the tag and crypto-suite from the accepted crypto
    // attribute in the offer"
    assert_eq!(answered.tag, offered.tag);
    assert_eq!(answered.suite, offered.suite);
    // §7.1.2: "the master key(s) included in the answer MUST be different
    // from those in the offer"
    assert_ne!(answered.key_params, offered.key_params);

    // what the two sessions think they are
    assert!(closed.encrypted, "neither end reports an encrypted stream");
    assert!(!open.encrypted);

    // the tone crossed, which is the far end having decrypted it
    assert!(
        loudness(&closed.played) > 4_000,
        "the tone came back at {} through the secured call",
        loudness(&closed.played)
    );

    // and the octets: an eighty-bit tag longer, the header still readable
    // because RFC 3711 §3.1 leaves it in the clear, and nothing of the
    // payload anywhere in it
    assert_eq!(
        closed.datagram.len(),
        open.datagram.len() + 10,
        "the packet did not grow by the tag of AES_CM_128_HMAC_SHA1_80"
    );
    assert_eq!(
        &closed.datagram[..12],
        &open.datagram[..12],
        "the two runs should have put the same RTP header on the wire"
    );
    assert_ne!(
        &closed.datagram[12..open.datagram.len()],
        &open.datagram[12..],
        "the payload went out in the clear"
    );
    let plaintext = &open.datagram[12..];
    assert!(
        !closed
            .datagram
            .windows(plaintext.len())
            .any(|window| window == plaintext),
        "the plaintext payload is still somewhere in the protected datagram"
    );

    // RFC 4568 §6.4: a stream that may be secured starts below 2^15, so that
    // losses at the very beginning cannot leave the two ends disagreeing
    // about the rollover counter
    let started_at = u16::from_be_bytes([closed.first[2], closed.first[3]]);
    assert!(
        started_at < 0x8000,
        "the stream started at sequence number {started_at}"
    );
    assert_eq!(
        started_at,
        u16::from_be_bytes([open.first[2], open.first[3]]),
        "the two runs should have drawn the same stream identity"
    );
}

/// The default does not offer SDES and does answer it, which are two
/// different decisions: the first is about a `RTP/SAVP` offer to a PBX that
/// would refuse the stream, and the second is about a peer that has already
/// asked for encryption and would get silence instead.
#[test]
fn the_default_offers_no_keys_and_still_answers_a_peer_that_asks_for_them() {
    let mut pair = Pair::asymmetric(
        CodecCatalog::new().with_srtp(SrtpPolicy::Offered),
        CodecCatalog::new(),
    );
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    assert_eq!(
        pair.callee.engine.catalog().srtp(),
        SrtpPolicy::NotOffered,
        "the answering side is on the default"
    );
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .is_encrypted(),
        "the caller offered SDES and did not get a keyed stream back"
    );
    assert!(
        pair.callee
            .engine
            .session(remote)
            .expect("media")
            .is_encrypted()
    );
    // and it is the codec at the top of the catalogue through the protected
    // path, not only the narrowband one
    assert_eq!(
        pair.caller.engine.session(call).expect("media").codec(),
        PREFERRED
    );

    let frame = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .frame_samples();
    let rate = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .sample_rate();
    let mut samples = vec![0_i16; frame];
    let mut phase = 0_u32;
    let mut heard = Vec::new();
    for _ in 0..20 {
        tone(&mut samples, rate, &mut phase);
        heard = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(
        loudness(&heard) > 2_000,
        "the tone came back at {} through a secured {PREFERRED} call",
        loudness(&heard)
    );
}

/// A call that requires SRTP does not answer a plain INVITE at all. The
/// refusal comes back where the answer was asked for, so the call is still
/// ringing and the application chooses the status code.
#[test]
fn a_call_that_requires_srtp_refuses_to_answer_a_plain_invite() {
    let mut pair = Pair::asymmetric(
        CodecCatalog::with_order(&["PCMU"]).expect("an order"),
        CodecCatalog::with_order(&["PCMU"])
            .expect("an order")
            .with_srtp(SrtpPolicy::Required),
    );
    let call = pair.ring();
    // whatever provisional response the user agent sent on its own
    let _ = pair.callee.outbound();

    let refused = pair
        .callee
        .engine
        .answer(&mut pair.callee.agent, call, callee_media(), pair.now);
    assert_eq!(refused, Err(MediaError::SrtpRequired));
    assert!(
        pair.callee.outbound().is_empty(),
        "a refused answer must not have gone out anyway"
    );
    assert!(
        pair.callee.engine.session(call).is_none(),
        "no media was opened for a call that was never answered"
    );
}

/// The re-offer is where a silent downgrade would happen: a live encrypted
/// call, and a far end that asks to carry on in the clear.
#[test]
fn a_plain_re_offer_inside_a_call_that_requires_srtp_is_refused() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::Required);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .is_encrypted()
    );

    // written by hand rather than offered through the engine, because the
    // engine will not write this: a plain profile, and a format list that
    // differs so that the user agent hands the offer up instead of answering
    // it on the application's behalf
    let downgrade = "v=0\r\no=- 9 9 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
                     m=audio 40002 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n";
    pair.callee
        .agent
        .reoffer(remote, downgrade.as_bytes(), pair.now)
        .expect("the re-INVITE goes");
    pair.settle();

    assert!(
        pair.caller
            .media_events()
            .iter()
            .any(|event| matches!(event, MediaEvent::Failed(MediaError::SrtpRequired))),
        "a plain re-offer was taken without a word: {:?}",
        pair.caller.media_events()
    );
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .is_encrypted(),
        "the stream that was already running must not have been re-keyed downwards"
    );
}

/// Thirty octets of key and salt as an `inline:` parameter carries them, and
/// two of them that are not the same — §7.1.2 refuses a stream whose two
/// directions share a master key.
const OURS: &str = "inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const THEIRS: &str = "inline:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

/// Plain RTP arriving on a secured stream is dropped rather than played.
///
/// The other half of what makes the encryption worth having: a stream that
/// accepted an unprotected packet as a fallback would be one an attacker
/// downgrades by sending one.
#[test]
fn an_unprotected_packet_on_a_secured_stream_is_refused_rather_than_played() {
    let now = Instant::now();
    let (ours, theirs) = plan_pair(
        &format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
             m=audio 40000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 {OURS}\r\n"
        ),
        &format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
             m=audio 40002 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 {THEIRS}\r\n"
        ),
    );
    let mut receiver = session(&ours, &theirs, now);
    assert!(receiver.is_encrypted());

    // a well-formed plain RTP packet carrying the negotiated payload type
    let mut datagram = vec![0x80, 0, 0, 1, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
    datagram.extend_from_slice(&[0x55; 160]);
    let arrival = receiver.receive(
        &mut datagram,
        "192.0.2.2:40002".parse().expect("an address"),
        now,
    );
    assert!(
        matches!(arrival, Arrival::Dropped(crate::Discard::Insecure(_))),
        "an unprotected packet was taken on a secured stream: {arrival:?}"
    );
}

/// Keeps every reference frame it is handed, so a test can assert on what the
/// seam delivered rather than on a canceller's arithmetic.
struct Heard(Arc<Mutex<Vec<Vec<i16>>>>);

impl crate::Processor for Heard {
    fn process(&mut self, near_end: &mut [i16], reference: &[i16]) {
        if let Ok(mut frames) = self.0.lock() {
            frames.push(reference.to_vec());
        }
        near_end.fill(0);
    }

    fn reset(&mut self) {}
}

/// The whole point of the seam: a processor attached to a live call is handed
/// the far end's audio as this end played it, rather than silence or the frame
/// that has not been played yet. A canceller given the wrong frame does not
/// cancel less, it diverges.
#[test]
fn a_processor_is_handed_the_audio_the_call_played() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let frames = Arc::new(Mutex::new(Vec::new()));
    let frame = {
        let mut session = pair
            .callee
            .engine
            .session(remote)
            .expect("the callee's media");
        session.attach_processor(Box::new(Heard(Arc::clone(&frames))));
        assert!(session.has_processor());
        session.frame_samples()
    };

    let mut samples = vec![0_i16; frame];
    let silence = vec![0_i16; frame];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..20 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.callee
            .engine
            .session(remote)
            .expect("the callee's media")
            .capture(&silence)
            .expect("the frame encodes");
        pair.advance();
    }

    let seen = frames.lock().expect("the frames").clone();
    assert_eq!(seen.len(), 20, "the processor did not see every frame");
    let loudest = seen.iter().map(|frame| loudness(frame)).max().unwrap_or(0);
    assert!(
        loudest > 4_000,
        "the processor was handed audio at {loudest}, not the call's own"
    );
    // sample for sample, and in the order it left the loudspeaker: a
    // reference that is merely the right audio backwards correlates against
    // nothing
    assert_eq!(
        seen.last().map(Vec::as_slice),
        Some(played.as_slice()),
        "the reference was not the frame the call had just played"
    );
}

/// Attaching and detaching are answers rather than silence: an application
/// that asks to stop something that was never running has to be able to tell.
#[test]
fn detaching_says_whether_there_was_anything_to_detach() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();

    let mut session = pair
        .caller
        .engine
        .session(call)
        .expect("the caller's media");
    assert!(!session.has_processor());
    assert!(!session.detach_processor());
    assert!(!session.reset_processor());

    let frames = Arc::new(Mutex::new(Vec::new()));
    session.attach_processor(Box::new(Heard(frames)));
    assert!(session.reset_processor());
    assert!(session.detach_processor());
    assert!(!session.has_processor());
}

/// A delay no loudspeaker and microphone in one room can have is refused where
/// it is set. B2 in `docs/13-client-requirements.md`: a setting is applied,
/// rejected with a reason, or unsupported — never accepted and ignored.
#[test]
fn a_render_delay_longer_than_any_device_is_refused_rather_than_kept() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let mut session = pair
        .caller
        .engine
        .session(call)
        .expect("the caller's media");

    assert_eq!(session.render_delay(), Duration::ZERO);
    session
        .set_render_delay(Duration::from_millis(40))
        .expect("a delay a Bluetooth headset really has");
    assert_eq!(session.render_delay(), Duration::from_millis(40));

    let refused = session.set_render_delay(crate::MAX_RENDER_DELAY + Duration::from_millis(1));
    assert!(matches!(
        refused,
        Err(MediaError::RenderDelayTooLong { .. })
    ));
    assert_eq!(
        session.render_delay(),
        Duration::from_millis(40),
        "a refused delay was kept anyway"
    );
}

/// A key pressed on one end reaches the other as exactly one keypress. RFC
/// 4733 sends a digit as a run of updates and then repeats its closing packet
/// three times, so the bug this guards against is an application being told
/// five times that somebody pressed 7.
#[test]
fn a_digit_dialled_on_one_end_is_heard_once_on_the_other() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let frame = {
        let mut session = pair
            .caller
            .engine
            .session(call)
            .expect("the caller's media");
        session
            .send_dtmf(Digit::from_char('7').expect("a key"), DEFAULT_DIGIT)
            .expect("the digit is queued");
        assert!(session.is_dialling());
        session.frame_samples()
    };

    let mut samples = vec![0_i16; frame];
    let mut phase = 0_u32;
    for _ in 0..20 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        pair.advance();
    }
    pair.callee.drain(pair.now, false);

    let heard: Vec<_> = pair
        .callee
        .media_events()
        .into_iter()
        .filter_map(|event| match event {
            MediaEvent::DigitReceived { digit, held, .. } => Some((*digit, *held)),
            _ => None,
        })
        .collect();
    assert_eq!(
        heard.len(),
        1,
        "one keypress arrived as {} events: {heard:?}",
        heard.len()
    );
    assert_eq!(heard.first().and_then(|(digit, _)| *digit), Some('7'));
    assert!(
        heard
            .first()
            .is_some_and(|(_, held)| *held >= Duration::from_millis(80)),
        "the digit was reported as lasting {:?}",
        heard.first().map(|(_, held)| *held)
    );
    assert!(
        !pair
            .caller
            .engine
            .session(call)
            .expect("the caller's media")
            .is_dialling()
    );
}

/// A call whose far end offered no telephone event type is told so, rather
/// than swallowing the digit. B2: applied, rejected with a reason, or not
/// supported — never accepted and ignored.
#[test]
fn a_call_with_no_event_type_refuses_a_digit_instead_of_dropping_it() {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_dtmf(false);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let mut session = pair
        .caller
        .engine
        .session(call)
        .expect("the caller's media");

    assert!(matches!(
        session.send_dtmf(Digit::Hash, DEFAULT_DIGIT),
        Err(MediaError::NoDtmf)
    ));
    assert!(!session.is_dialling());
}

/// Half an extension is worse than none, because it reaches somebody.
#[test]
fn a_dial_string_with_a_bad_character_queues_nothing_at_all() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let mut session = pair
        .caller
        .engine
        .session(call)
        .expect("the caller's media");

    assert!(matches!(
        session.dial("12X4", DEFAULT_DIGIT),
        Err(MediaError::UnknownDigit { key: 'X' })
    ));
    assert_eq!(session.digits_waiting(), 0);
    assert_eq!(session.dial("1234", DEFAULT_DIGIT).expect("four keys"), 4);
    assert_eq!(session.digits_waiting(), 4);

    assert!(matches!(
        session.send_dtmf(Digit::Number(1), Duration::from_millis(20)),
        Err(MediaError::DigitTooShort { .. })
    ));
    session.stop_dialling();
    assert!(!session.is_dialling());
}

/// A call that ends gives its media up, and the last word on it is what it
/// cost — which is the only moment an end-of-call record can be written.
#[test]
fn a_call_that_ends_gives_up_its_media_and_says_what_it_cost() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    for _ in 0..10 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        pair.advance();
    }

    pair.caller.agent.hangup(call, pair.now).expect("the BYE");
    pair.caller.drain(pair.now, false);
    pair.settle();

    assert!(
        pair.caller.engine.session(call).is_none(),
        "the media outlived the call"
    );
    let ended = pair
        .caller
        .media_events()
        .into_iter()
        .find_map(|event| match event {
            MediaEvent::Ended(statistics) => Some(*statistics),
            _ => None,
        })
        .expect("the call said what it cost");
    assert_eq!(ended.codec, Codec::Pcmu);
    assert_eq!(ended.packets_sent, 10);
    assert_eq!(ended.octets_sent, 10 * 160);

    let callee = pair
        .callee
        .media_events()
        .into_iter()
        .find_map(|event| match event {
            MediaEvent::Ended(statistics) => Some(*statistics),
            _ => None,
        })
        .expect("the far end said what it cost");
    // nine of the ten: RFC 3550 A.1 puts the first packet of a source on
    // probation, and a stack that counted it would be counting audio it did
    // not play
    assert_eq!(callee.quality.received, 9);
}

/// Hold is a session change, and what it has to reach is the media: a stream
/// that keeps sending into a held call is a stream the far end has said it is
/// not listening to.
#[test]
fn hold_reaches_the_media_and_resume_gives_it_back() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    pair.caller.agent.hold(call, pair.now).expect("the hold");
    pair.caller.drain(pair.now, false);
    pair.settle();

    let mut held = pair.callee.engine.session(remote).expect("media");
    assert_eq!(held.direction(), Direction::RecvOnly);
    assert!(!held.is_sending(), "the held end is still sending");
    assert!(held.is_receiving(), "the held end has stopped listening");
    assert!(
        held.capture(&[100; 160]).expect("no error").is_none(),
        "a held stream put a packet on the wire"
    );
    drop(held);

    pair.caller
        .agent
        .resume(call, pair.now)
        .expect("the resume");
    pair.caller.drain(pair.now, false);
    pair.settle();

    let mut resumed = pair.callee.engine.session(remote).expect("media");
    assert_eq!(resumed.direction(), Direction::SendRecv);
    assert!(resumed.capture(&[100; 160]).expect("no error").is_some());
}

/// A6's other half: loss and jitter the receiver works out for itself, but the
/// round-trip time only exists because reports went both ways, and it only
/// reaches the application because this crate carries it.
#[test]
fn the_round_trip_time_comes_back_from_rtcp() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut crossed = 0;

    // reports are scheduled rather than sent per packet (RFC 3550 §6.2), so
    // this runs long enough for the schedule to come round twice
    for tick in 0..800 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        let back = pair
            .callee
            .engine
            .session(remote)
            .expect("media")
            .capture(&samples)
            .expect("it encodes")
            .map(|out| out.payload.to_vec());
        let mut session = pair.caller.engine.session(call).expect("media");
        if let Some(mut datagram) = back {
            session.receive(&mut datagram, callee_media(), pair.now);
        }
        // and the caller plays what arrived. A side that receives and never
        // pulls is a side whose buffer fills up, which is a real fault and
        // would be measured as one here
        let mut played = vec![0_i16; session.frame_samples()];
        session.playback(&mut played);
        drop(session);
        let (sent, believed) = pair.exchange_control(call, remote);
        assert_eq!(sent, believed, "a report was refused at tick {tick}");
        crossed += sent;
        pair.advance();
    }

    assert!(
        crossed >= 2,
        "only {crossed} reports crossed in sixteen seconds"
    );
    let caller = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .statistics(pair.now);
    assert!(
        caller.round_trip.is_some(),
        "reports went both ways and no round-trip time came out of them"
    );
    assert!(
        caller
            .round_trip
            .is_some_and(|rtt| rtt < Duration::from_secs(1)),
        "the round-trip time is not a plausible one: {:?}",
        caller.round_trip
    );
    // and the score reflects it rather than staying at its default
    assert!(
        caller.score() > 90.0,
        "a clean call scored {}",
        caller.score()
    );
}

/// RFC 3550 §6.6: a stream that is ending says so, and the far end stops
/// expecting audio at once rather than waiting for its own timeout.
#[test]
fn a_stream_that_is_ending_says_goodbye() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    // some audio first, so that the far end knows which synchronization source
    // is leaving: RFC 3550 §6.6 names one, and a BYE for a source nobody has
    // heard from is a BYE about somebody else's stream
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    for _ in 0..4 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        pair.advance();
    }

    let farewell = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .goodbye(pair.now)
        .expect("a BYE is built")
        .payload
        .to_vec();

    let mut datagram = farewell;
    let arrival = pair.callee.engine.session(remote).expect("media").receive(
        &mut datagram,
        "192.0.2.1:40001".parse().expect("an address"),
        pair.now,
    );
    assert_eq!(arrival, Arrival::Goodbye);
}

/// RFC 3550 §6.2: "The first RTCP packet sent after joining a session is
/// also delayed by a random variation of half the minimum RTCP interval" —
/// the same random factor every later report draws, not a fixed point in
/// it. Two sessions opened from the same plan and clock, differing only in
/// the caller's seed, have to schedule their first report differently, or
/// that factor never came from the seed at all.
#[test]
fn the_first_rtcp_report_is_scheduled_from_this_calls_own_seed() {
    let now = Instant::now();
    let (ours, theirs) = plan_pair(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
    );
    let plan = ours
        .media_plan(&theirs, 0)
        .expect("a plan")
        .expect("a stream");

    let scheduled = |seed: u64| {
        MediaSession::open(
            &plan,
            20,
            &MediaConfig::default(),
            StreamIdentity {
                ssrc: 1,
                sequence: 1,
                timestamp: 0,
                seed,
            },
            WallClock::from_unix(now, 1_700_000_000, 0),
            Vec::new(),
            now,
        )
        .expect("the session opens")
        .poll_timeout()
        .expect("RTCP was negotiated, so a first report is scheduled")
    };

    assert_ne!(
        scheduled(7),
        scheduled(0xC0FF_EE00_1234_5678),
        "two different seeds scheduled the same first report"
    );
}

// -- the watchdog ------------------------------------------------------------

/// B5: inbound audio that stops while signalling stays perfectly happy is the
/// failure this whole watchdog exists for.
#[test]
fn a_stream_that_stops_is_reported_and_the_call_is_not_touched() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    for _ in 0..5 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        pair.advance();
    }

    // and now the far end goes quiet while every SIP timer carries on
    let quiet = pair.now;
    pair.now += Duration::from_secs(11);
    pair.callee.engine.handle_timeout(pair.now);
    pair.callee.drain(pair.now, false);

    let stalled = pair
        .callee
        .media_events()
        .into_iter()
        .find_map(|event| match event {
            MediaEvent::Stalled { silent_for } => Some(*silent_for),
            _ => None,
        })
        .expect("nothing said the stream had stopped");
    assert!(stalled >= Duration::from_secs(10));
    assert!(
        pair.callee
            .engine
            .session(remote)
            .is_some_and(|session| session.is_stalled())
    );

    // the call itself is untouched: hanging one up over silence is a decision
    // with a person on the other end of it
    assert!(matches!(
        pair.callee.agent.call_state(remote),
        Some(crate::CallState::Confirmed)
    ));

    // and when audio comes back, so does the report
    let _ = quiet;
    tone(&mut samples, 8_000, &mut phase);
    pair.exchange(call, remote, &samples);
    pair.callee.drain(pair.now, false);
    assert!(
        pair.callee
            .media_events()
            .into_iter()
            .any(|event| matches!(event, MediaEvent::Resumed { .. })),
        "the stream came back and nothing said so"
    );
    assert!(
        pair.callee
            .engine
            .session(remote)
            .is_some_and(|session| !session.is_stalled())
    );
}

/// The watchdog must not fire on a stream this end asked not to receive, or
/// every hold turns into a fault report.
///
/// The end that presses hold is the end that stops receiving — RFC 3264 §8.4
/// marks its own stream `sendonly`, so it goes on sending music and expects
/// nothing back. Its own watchdog therefore has to go quiet, and the far end's
/// must not, because the far end is still meant to be hearing something.
#[test]
fn a_held_stream_is_not_a_stalled_one() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let _ = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    pair.callee.agent.hold(remote, pair.now).expect("the hold");
    pair.callee.drain(pair.now, false);
    pair.settle();

    assert!(
        pair.callee
            .engine
            .session(remote)
            .is_some_and(|session| !session.is_receiving()),
        "the end that pressed hold is still expecting audio"
    );

    pair.now += Duration::from_secs(60);
    pair.callee.engine.handle_timeout(pair.now);
    pair.callee.drain(pair.now, false);

    assert!(
        !pair
            .callee
            .media_events()
            .into_iter()
            .any(|event| matches!(event, MediaEvent::Stalled { .. })),
        "a stream that was told to stop was reported as having failed"
    );
}

// -- recording ---------------------------------------------------------------

/// A5: both directions, one file, started and stopped in the middle of a live
/// call.
#[test]
fn a_recording_takes_both_directions_of_a_live_call() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let file = Buffer::new();

    // ten frames before the recording starts, so that the de-jitter buffer is
    // past its start-up delay and every frame that follows is real audio
    for _ in 0..10 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        pair.advance();
    }
    pair.callee
        .engine
        .session(remote)
        .expect("media")
        .start_recording(Box::new(file.clone()))
        .expect("the recording starts");
    // the two directions carry deliberately different signals: the caller
    // sends a tone that swings either side of zero, and the callee's own
    // microphone holds a constant. Mixed, that is a file whose samples are
    // either near zero or near full scale — and a file with only one direction
    // in it cannot be either, because one of them never leaves half scale and
    // the other never reaches it.
    let level = vec![8_000_i16; 160];
    for _ in 0..10 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        pair.callee
            .engine
            .session(remote)
            .expect("media")
            .capture(&level)
            .expect("the far end speaks too");
        pair.advance();
    }
    let mut session = pair.callee.engine.session(remote).expect("media");
    assert!(session.is_recording());
    assert_eq!(session.recorded(), Some(Duration::from_millis(200)));
    session.stop_recording().expect("the recording stops");
    assert!(!session.is_recording());

    let wav = file.contents();
    assert_eq!(&wav[0..4], b"RIFF");
    // ten frames of a hundred and sixty samples, two octets each, behind the
    // forty-four octet header
    assert_eq!(wav.len(), 44 + 10 * 160 * 2);

    let audio: Vec<i16> = wav[44..]
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    assert!(
        audio.iter().any(|sample| *sample > 7_000),
        "nothing in the recording is loud enough to be the two directions added"
    );
    assert!(
        audio.iter().any(|sample| sample.abs() < 1_000),
        "nothing in the recording is quiet enough to be the two directions \
         cancelling, so only one of them is in it"
    );
}

#[test]
fn a_recording_cannot_be_started_twice_on_one_call() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();

    let mut session = pair.caller.engine.session(call).expect("media");
    session
        .start_recording(Box::new(Buffer::new()))
        .expect("the first one starts");
    assert_eq!(
        session.start_recording(Box::new(Buffer::new())),
        Err(MediaError::AlreadyRecording)
    );
    drop(session);
    // two statements rather than one expression: a guard lives to the end of
    // the statement that took it, and a second one taken inside it on the same
    // thread is refused rather than left waiting for the first
    let first = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .stop_recording();
    let second = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .stop_recording();
    assert_eq!(first.and(second), Err(MediaError::NotRecording));
}

/// A recording that is still running when the call ends has to be closed, or
/// the file has zeroes where its two lengths should be and no player will open
/// it.
#[test]
fn a_call_that_ends_closes_the_recording_it_was_making() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let file = Buffer::new();
    pair.caller
        .engine
        .session(call)
        .expect("media")
        .start_recording(Box::new(file.clone()))
        .expect("the recording starts");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    for _ in 0..4 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        pair.advance();
    }

    pair.caller.agent.hangup(call, pair.now).expect("the BYE");
    pair.caller.drain(pair.now, false);
    pair.settle();

    let wav = file.contents();
    let length = u32::from_le_bytes([wav[40], wav[41], wav[42], wav[43]]);
    assert_eq!(
        usize::try_from(length).expect("a length"),
        wav.len() - 44,
        "the data chunk length was never patched"
    );
    assert!(length > 0, "nothing was recorded at all");
}

// -- the session on its own --------------------------------------------------

/// Two descriptions, one plan, two sessions: the same wiring the engine does,
/// without a user agent, so that a failure here is about the media and nothing
/// else.
fn plan_pair(offer: &str, answer: &str) -> (SessionDescription, SessionDescription) {
    (
        parse(offer.as_bytes()).expect("the offer parses"),
        parse(answer.as_bytes()).expect("the answer parses"),
    )
}

fn session(local: &SessionDescription, remote: &SessionDescription, now: Instant) -> MediaSession {
    let plan = local
        .media_plan(remote, 0)
        .expect("a plan")
        .expect("a stream");
    MediaSession::open(
        &plan,
        20,
        &MediaConfig::default(),
        StreamIdentity {
            ssrc: 0x5149_5241,
            sequence: 1,
            timestamp: 0,
            seed: 7,
        },
        WallClock::from_unix(now, 1_700_000_000, 0),
        Vec::new(),
        now,
    )
    .expect("the session opens")
}

/// A packet that never arrives has to come out as a frame of concealment
/// rather than as nothing at all, or the device plays whatever was in its
/// buffer last.
#[test]
fn a_lost_packet_is_played_as_concealment_rather_than_as_a_gap() {
    let now = Instant::now();
    let (ours, theirs) = plan_pair(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
    );
    let mut sender = session(&theirs, &ours, now);
    let mut receiver = session(&ours, &theirs, now);

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut at = now;
    let mut played = vec![0_i16; 160];
    let mut concealed = 0;

    for index in 0..30 {
        tone(&mut samples, 8_000, &mut phase);
        let datagram = sender
            .capture(&samples)
            .expect("it encodes")
            .map(|out| out.payload.to_vec());
        // every seventh packet is lost on the way
        if let Some(mut datagram) = datagram
            && index % 7 != 3
        {
            receiver.receive(
                &mut datagram,
                "192.0.2.2:40002".parse().expect("an address"),
                at,
            );
        }
        if receiver.playback(&mut played) == Playback::Concealed {
            concealed += 1;
            assert!(
                loudness(&played) > 500,
                "a concealed frame came out silent, which is a click"
            );
        }
        at += TICK;
    }

    assert!(concealed > 0, "nothing was ever concealed");
    let quality = receiver.statistics(at).quality;
    assert!(quality.received > 0);
    assert!(quality.lost > 0, "the loss was not counted");
}

/// A payload type nobody negotiated is dropped rather than decoded through the
/// wrong table, which is loud distortion rather than quiet.
#[test]
fn a_payload_type_that_was_not_negotiated_is_refused() {
    let now = Instant::now();
    let (ours, theirs) = plan_pair(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
    );
    let mut receiver = session(&ours, &theirs, now);

    // a well-formed RTP packet carrying A-law, which was never offered
    let mut datagram = vec![0x80, 8, 0, 1, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
    datagram.extend_from_slice(&[0x55; 160]);
    let arrival = receiver.receive(
        &mut datagram,
        "192.0.2.2:40002".parse().expect("an address"),
        now,
    );
    assert_eq!(arrival, Arrival::Dropped(crate::Discard::PayloadType(8)));
}

/// An answer naming a codec this build has no decoder for is a reported
/// failure, not a call that stands up with noise on it.
#[test]
fn an_answer_this_build_cannot_decode_is_refused_by_name() {
    let now = Instant::now();
    let (ours, theirs) = plan_pair(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 97\r\na=rtpmap:97 SPEEX/8000\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP 97\r\na=rtpmap:97 SPEEX/8000\r\n",
    );
    let plan = ours
        .media_plan(&theirs, 0)
        .expect("a plan")
        .expect("a stream");
    let opened = MediaSession::open(
        &plan,
        20,
        &MediaConfig::default(),
        StreamIdentity {
            ssrc: 1,
            sequence: 1,
            timestamp: 0,
            seed: 7,
        },
        WallClock::from_unix(now, 1_700_000_000, 0),
        Vec::new(),
        now,
    );
    assert_eq!(
        opened.err(),
        Some(MediaError::UnknownPayload {
            payload: 97,
            encoding: "SPEEX".to_owned()
        })
    );
}

// -- a re-negotiation that moves the keys ------------------------------------

/// An `RTP/SAVP` description with one PCMU stream, the suite and the key
/// given.
fn savp(host: &str, port: u16, suite: &str, key: &str) -> String {
    savp_of(host, port, 0, "PCMU/8000", suite, key)
}

fn savp_of(host: &str, port: u16, payload: u8, rtpmap: &str, suite: &str, key: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {host}\r\ns=-\r\nc=IN IP4 {host}\r\nt=0 0\r\n\
         m=audio {port} RTP/SAVP {payload}\r\na=rtpmap:{payload} {rtpmap}\r\n\
         a=crypto:1 {suite} {key}\r\na=sendrecv\r\n"
    )
}

const SHA1_80: &str = "AES_CM_128_HMAC_SHA1_80";
const OURS_AGAIN: &str = "inline:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
const THEIRS_AGAIN: &str = "inline:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";

/// The two descriptions of a secured PCMU call, with the keys given.
fn savp_pair(ours: &str, theirs: &str) -> (SessionDescription, SessionDescription) {
    savp_pair_of(SHA1_80, ours, theirs)
}

fn savp_pair_of(suite: &str, ours: &str, theirs: &str) -> (SessionDescription, SessionDescription) {
    plan_pair(
        &savp("192.0.2.1", 40_000, suite, ours),
        &savp("192.0.2.2", 40_002, suite, theirs),
    )
}

fn plan_of(local: &SessionDescription, remote: &SessionDescription) -> crate::MediaPlan {
    local
        .media_plan(remote, 0)
        .expect("a plan")
        .expect("a stream")
}

/// One packet's worth of audio, as it goes on the wire.
fn one_packet(from: &mut MediaSession) -> Vec<u8> {
    from.capture(&[1_000_i16; 160])
        .expect("the frame encodes")
        .expect("a frame goes out")
        .payload
        .to_vec()
}

fn theirs_address() -> SocketAddr {
    "192.0.2.2:40002".parse().expect("an address")
}

fn ours_address() -> SocketAddr {
    "192.0.2.1:40000".parse().expect("an address")
}

/// RFC 4568 §7.1.4: a re-offer is an opportunity to re-key, and both ends put
/// a fresh master key in the new descriptions. Whatever the negotiation
/// settles on is what has to be on the wire from then on.
#[test]
fn a_stream_re_keyed_by_a_re_negotiation_sends_under_the_new_key() {
    let now = Instant::now();
    let (ours, theirs) = savp_pair(OURS, THEIRS);
    let mut sender = session(&ours, &theirs, now);
    assert!(sender.is_encrypted());

    // the same two ends, same codec, same addresses, fresh keys
    let (ours_2, theirs_2) = savp_pair(OURS_AGAIN, THEIRS_AGAIN);
    sender
        .adopt(&plan_of(&ours_2, &theirs_2), Vec::new(), now)
        .expect("the fresh keys are ones this build can open a stream with");

    // the far end, keyed the way the fresh pair of descriptions says
    let mut receiver = session(&theirs_2, &ours_2, now);
    let mut datagram = one_packet(&mut sender);
    let arrival = receiver.receive(&mut datagram, ours_address(), now);
    assert!(
        matches!(
            arrival,
            Arrival::Queued | Arrival::Dropped(crate::Discard::Probation)
        ),
        "the stream is still sending under the key the previous negotiation \
         settled on: {arrival:?}"
    );
}

/// The other direction, and the one that decides whether a call stays audible
/// through a re-key: the far end's answer reaches us before the far end's
/// first packet under the key it names.
#[test]
fn a_stream_re_keyed_by_a_re_negotiation_reads_the_peers_new_key() {
    let now = Instant::now();
    let (ours, theirs) = savp_pair(OURS, THEIRS);
    let mut receiver = session(&ours, &theirs, now);

    let (ours_2, theirs_2) = savp_pair(OURS_AGAIN, THEIRS_AGAIN);
    receiver
        .adopt(&plan_of(&ours_2, &theirs_2), Vec::new(), now)
        .expect("the fresh keys open");

    let mut peer = session(&theirs_2, &ours_2, now);
    let mut datagram = one_packet(&mut peer);
    let arrival = receiver.receive(&mut datagram, theirs_address(), now);
    assert!(
        matches!(
            arrival,
            Arrival::Queued | Arrival::Dropped(crate::Discard::Probation)
        ),
        "the far end has switched to the key it named and is not being \
         heard: {arrival:?}"
    );
}

/// The far end has not switched yet, which is the ordinary case for as long
/// as the answer and the packets are crossing.
#[test]
fn a_peer_that_has_not_switched_to_its_new_key_yet_is_still_heard() {
    let now = Instant::now();
    let (ours, theirs) = savp_pair(OURS, THEIRS);
    let mut receiver = session(&ours, &theirs, now);
    let mut peer = session(&theirs, &ours, now);

    let (ours_2, theirs_2) = savp_pair(OURS_AGAIN, THEIRS_AGAIN);
    receiver
        .adopt(&plan_of(&ours_2, &theirs_2), Vec::new(), now)
        .expect("the fresh keys open");

    // still protected with the key the far end is replacing
    let mut in_flight = one_packet(&mut peer);
    let arrival = receiver.receive(&mut in_flight, theirs_address(), now);
    assert!(
        matches!(
            arrival,
            Arrival::Queued | Arrival::Dropped(crate::Discard::Probation)
        ),
        "a packet the far end sent before it saw our answer: {arrival:?}"
    );
}

/// A re-negotiation that moves nothing about the keys must not touch the
/// contexts. The harm is not theoretical: a fresh receive context brings a
/// fresh replay window, and a fresh window accepts a packet this stream has
/// already taken.
#[test]
fn a_re_offer_that_keeps_the_keys_does_not_re_open_the_replay_window() {
    let now = Instant::now();
    let (ours, theirs) = savp_pair(OURS, THEIRS);
    let mut receiver = session(&ours, &theirs, now);
    let mut peer = session(&theirs, &ours, now);

    let datagram = one_packet(&mut peer);
    receiver.receive(&mut datagram.clone(), theirs_address(), now);

    // a session timer refresh, or a hold that changed only the direction:
    // the same two crypto lines, to the octet
    receiver
        .adopt(&plan_of(&ours, &theirs), Vec::new(), now)
        .expect("the keys it already holds open");

    let arrival = receiver.receive(&mut datagram.clone(), theirs_address(), now);
    assert!(
        matches!(
            arrival,
            Arrival::Dropped(crate::Discard::Insecure(SrtpError::Replayed))
        ),
        "the replay window was re-opened by a re-negotiation that changed no \
         key: {arrival:?}"
    );
}

/// The halves move one at a time. Each end keys what it sends, so a
/// negotiation in which only our own key moved leaves the far end's context —
/// and its replay window — exactly where they were.
#[test]
fn a_re_offer_that_moves_only_our_own_key_leaves_the_peers_context_alone() {
    let now = Instant::now();
    let (ours, theirs) = savp_pair(OURS, THEIRS);
    let mut receiver = session(&ours, &theirs, now);
    let mut peer = session(&theirs, &ours, now);

    let datagram = one_packet(&mut peer);
    receiver.receive(&mut datagram.clone(), theirs_address(), now);

    // our key moved; theirs did not
    let (ours_2, _) = savp_pair(OURS_AGAIN, THEIRS);
    receiver
        .adopt(&plan_of(&ours_2, &theirs), Vec::new(), now)
        .expect("the fresh key opens");

    let arrival = receiver.receive(&mut datagram.clone(), theirs_address(), now);
    assert!(
        matches!(
            arrival,
            Arrival::Dropped(crate::Discard::Insecure(SrtpError::Replayed))
        ),
        "our own key moving re-opened the far end's replay window: {arrival:?}"
    );
}

/// Only the key and salt decide whether a direction was re-keyed. RFC 4568
/// §6.1 lets an `inline:` carry a lifetime and a master key identifier beside
/// them, and a re-offer that adds a lifetime has not changed the key the far
/// end is counting under. Read as a new key, it opened a fresh receive
/// context, and a fresh replay window accepts what the stream already took.
#[test]
fn a_re_offer_that_only_adds_a_key_lifetime_does_not_re_open_the_replay_window() {
    let now = Instant::now();
    let (ours, theirs) = savp_pair(OURS, THEIRS);
    let mut receiver = session(&ours, &theirs, now);
    let mut peer = session(&theirs, &ours, now);

    let datagram = one_packet(&mut peer);
    receiver.receive(&mut datagram.clone(), theirs_address(), now);

    // the same thirty octets, with a lifetime written beside them
    let with_lifetime = format!("{THEIRS}|2^31");
    let (_, theirs_2) = savp_pair(OURS, &with_lifetime);
    receiver
        .adopt(&plan_of(&ours, &theirs_2), Vec::new(), now)
        .expect("the key it already holds opens");

    let arrival = receiver.receive(&mut datagram.clone(), theirs_address(), now);
    assert!(
        matches!(
            arrival,
            Arrival::Dropped(crate::Discard::Insecure(SrtpError::Replayed))
        ),
        "a lifetime beside an unchanged key re-opened the far end's replay \
         window: {arrival:?}"
    );
}

/// §6.1 lets a re-offer keep the `inline:` and change the terms around it.
/// `AES_CM_128_HMAC_SHA1_32` keeps all thirty octets of the key and salt and
/// shortens only the tag, so the transform has to follow — while the packet
/// index, which is all that stops the unchanged keystream from being spent
/// twice, must not restart. The index half is
/// `terms_that_move_under_the_same_key_do_not_restart_the_packet_index`, in
/// the crate that owns the counters; this is the half a peer can see.
#[test]
fn a_re_offer_that_shortens_the_tag_is_followed_without_a_new_key() {
    let now = Instant::now();
    let (ours, theirs) = savp_pair(OURS, THEIRS);
    let mut sender = session(&ours, &theirs, now);

    let (ours_32, theirs_32) = savp_pair_of("AES_CM_128_HMAC_SHA1_32", OURS, THEIRS);
    sender
        .adopt(&plan_of(&ours_32, &theirs_32), Vec::new(), now)
        .expect("the same keys under a shorter tag open");

    let mut receiver = session(&theirs_32, &ours_32, now);
    let mut datagram = one_packet(&mut sender);
    let arrival = receiver.receive(&mut datagram, ours_address(), now);
    assert!(
        matches!(
            arrival,
            Arrival::Queued | Arrival::Dropped(crate::Discard::Probation)
        ),
        "the stream is still stamping the tag length the previous \
         negotiation settled on: {arrival:?}"
    );
}

// -- a re-negotiation that moves the codec -----------------------------------

fn re_offer_onto(pair: &mut Pair, remote: CallHandle, payload: u8, rtpmap: &str) {
    let offer = format!(
        "v=0\r\no=- 9 9 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP {payload}\r\na=rtpmap:{payload} {rtpmap}\r\na=sendrecv\r\n"
    );
    pair.callee
        .agent
        .reoffer(remote, offer.as_bytes(), pair.now)
        .expect("the re-INVITE goes");
    pair.settle();
}

fn re_offer_onto_pcma(pair: &mut Pair, remote: CallHandle) {
    re_offer_onto(pair, remote, 8, "PCMA/8000");
}

fn re_offer_onto_g722(pair: &mut Pair, remote: CallHandle) {
    re_offer_onto(pair, remote, 9, "G722/8000");
}

fn sequence_of(datagram: &[u8]) -> u16 {
    u16::from_be_bytes([
        *datagram.get(2).unwrap_or(&0),
        *datagram.get(3).unwrap_or(&0),
    ])
}

fn ssrc_of(datagram: &[u8]) -> u32 {
    u32::from_be_bytes([
        *datagram.get(8).unwrap_or(&0),
        *datagram.get(9).unwrap_or(&0),
        *datagram.get(10).unwrap_or(&0),
        *datagram.get(11).unwrap_or(&0),
    ])
}

/// Forty packets of tone out of one end, and the last one as it went.
fn talk(pair: &mut Pair, call: CallHandle, packets: usize) -> Vec<u8> {
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut last = Vec::new();
    for _ in 0..packets {
        tone(&mut samples, 8_000, &mut phase);
        let mut session = pair.caller.engine.session(call).expect("media");
        let frame = vec![0_i16; session.frame_samples()];
        let audio = if samples.len() == frame.len() {
            samples.clone()
        } else {
            frame
        };
        if let Some(out) = session.capture(&audio).expect("it encodes") {
            last = out.payload.to_vec();
        }
        drop(session);
        pair.advance();
    }
    last
}

/// A re-INVITE that moves the call onto another codec keeps the same
/// synchronization source, so RFC 3550 §5.1 has the sequence number carry on
/// from where it was. A stream that rewound it by forty packets is one the far
/// end drops as ancient duplicates — and, on a secured call, one that hands a
/// second packet a keystream already spent.
#[test]
fn a_codec_change_carries_the_sequence_number_on_rather_than_rewinding_it() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let last = talk(&mut pair, call, 40);
    let before = sequence_of(&last);
    let source = ssrc_of(&last);

    re_offer_onto_pcma(&mut pair, remote);
    assert_eq!(
        pair.caller.engine.session(call).expect("media").codec(),
        Codec::Pcma,
        "the re-offer never reached the media"
    );

    let after = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .capture(&[100_i16; 160])
        .expect("it encodes")
        .expect("a frame goes out")
        .payload
        .to_vec();
    assert_eq!(
        ssrc_of(&after),
        source,
        "the synchronization source moved without an RTCP BYE for the old one"
    );
    let moved = sequence_of(&after).wrapping_sub(before);
    assert!(
        moved > 0 && moved < 0x8000,
        "the stream rewound from {before} to {}",
        sequence_of(&after)
    );
}

/// The call's own totals belong to the call. A re-negotiation that set them
/// back to zero would tell the application the call had just started, and
/// would tell the far end, through RTCP, that nothing had been lost since a
/// beginning that never happened.
#[test]
fn a_codec_change_carries_the_statistics_the_call_has_accumulated() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    talk(&mut pair, call, 40);
    let at = pair.now;
    let before = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .statistics(at);
    assert!(before.packets_sent >= 40, "{before:?}");

    re_offer_onto_pcma(&mut pair, remote);
    let at = pair.now;

    let after = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .statistics(at);
    assert!(
        after.packets_sent >= before.packets_sent,
        "the call's totals went backwards across the re-negotiation: {} then {}",
        before.packets_sent,
        after.packets_sent
    );
}

/// A codec change that keeps the rate and the frame length keeps the
/// recording: the three eight-kilohertz codecs are interchangeable under one
/// WAVE header, and a file that stopped here would stop for no reason the
/// application could have predicted.
#[test]
fn a_codec_change_at_the_same_rate_does_not_lose_the_recording_that_was_running() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let file = Buffer::new();
    pair.caller
        .engine
        .session(call)
        .expect("media")
        .start_recording(Box::new(file.clone()))
        .expect("the recording starts");
    talk(&mut pair, call, 8);
    let before = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .recorded()
        .expect("something was taken");

    re_offer_onto_pcma(&mut pair, remote);

    let session = pair.caller.engine.session(call).expect("media");
    assert!(
        session.is_recording(),
        "the recording was dropped with the session that was replaced"
    );
    assert_eq!(
        session.recorded(),
        Some(before),
        "the recording restarted its own clock"
    );
}

/// A codec change that moves the rate cannot keep it: a WAVE header names the
/// playback rate once, at the front of the file. So the recording is closed
/// properly rather than dropped, and the application is told, because it is
/// the only one that can decide whether to open a second file.
#[test]
fn a_codec_change_that_moves_the_rate_closes_the_recording_and_says_so() {
    let catalog = CodecCatalog::with_order(&["PCMU", "G722"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let file = Buffer::new();
    pair.caller
        .engine
        .session(call)
        .expect("media")
        .start_recording(Box::new(file.clone()))
        .expect("the recording starts");
    talk(&mut pair, call, 8);

    re_offer_onto_g722(&mut pair, remote);
    assert_eq!(
        pair.caller.engine.session(call).expect("media").codec(),
        Codec::G722,
        "the re-offer never reached the media"
    );

    let wav = file.contents();
    let data_len = u32::from_le_bytes([
        *wav.get(40).unwrap_or(&0),
        *wav.get(41).unwrap_or(&0),
        *wav.get(42).unwrap_or(&0),
        *wav.get(43).unwrap_or(&0),
    ]);
    assert!(
        data_len > 0,
        "the file was left with zeroes where its lengths should be"
    );
    assert!(
        !pair
            .caller
            .engine
            .session(call)
            .expect("media")
            .is_recording()
    );
    pair.caller.drain(pair.now, false);
    assert!(
        pair.caller.media_events().into_iter().any(|event| matches!(
            event,
            MediaEvent::RecordingStopped {
                reason: MediaError::CodecChanged,
                ..
            }
        )),
        "the recording ended and nobody was told"
    );
}

/// The echo canceller and the render delay a device reported are properties of
/// the call, not of one negotiation. A re-INVITE onto another codec must not
/// silently take them away — and the application has no second chance to hand
/// its processor over, because nothing tells it a re-negotiation happened
/// until after it has.
#[test]
fn a_codec_change_keeps_the_processor_and_the_render_delay_the_device_reported() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    {
        let mut session = pair.caller.engine.session(call).expect("media");
        session.attach_processor(Box::new(Heard(Arc::new(Mutex::new(Vec::new())))));
        session
            .set_render_delay(Duration::from_millis(40))
            .expect("a delay a headset really has");
        session.set_device(Some("bluetooth-headset".to_owned()));
    }

    re_offer_onto_pcma(&mut pair, remote);

    let session = pair.caller.engine.session(call).expect("media");
    assert_eq!(session.codec(), Codec::Pcma);
    assert_eq!(
        session.render_delay(),
        Duration::from_millis(40),
        "the render delay went back to zero across the re-negotiation"
    );
    assert_eq!(
        session.device(),
        Some("bluetooth-headset"),
        "the device the call is on was forgotten across the re-negotiation"
    );
    assert!(
        session.has_processor(),
        "the echo canceller was dropped across the re-negotiation"
    );
}

/// The same, across a codec change that moves the rate: the rings around the
/// processor have to be rebuilt at the new size, and the application's own
/// object has to survive that rebuild.
#[test]
fn a_codec_change_that_moves_the_rate_keeps_the_processor_too() {
    let catalog = CodecCatalog::with_order(&["PCMU", "G722"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    pair.caller
        .engine
        .session(call)
        .expect("media")
        .attach_processor(Box::new(Heard(Arc::new(Mutex::new(Vec::new())))));

    re_offer_onto_g722(&mut pair, remote);

    let mut session = pair.caller.engine.session(call).expect("media");
    assert_eq!(session.codec(), Codec::G722);
    assert!(
        session.has_processor(),
        "the processor was dropped by the rebuild that resized its rings"
    );
    // and it is fed frames of the new size rather than the old
    let frame = vec![100_i16; session.frame_samples()];
    session.capture(&frame).expect("it encodes");
}

/// A guard rather than a proof, and worth saying which: audio crossed a codec
/// change before this repair too, because both ends restarted together and
/// neither noticed. That is exactly why the defect survived — the damage was
/// to the packet index under an unchanged key, which nothing audible reports.
/// This is here so that carrying the stream on does not break what replacing
/// it happened to get right.
#[test]
fn audio_still_crosses_after_a_codec_change() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    for _ in 0..40 {
        tone(&mut samples, 8_000, &mut phase);
        pair.exchange(call, remote, &samples);
        pair.advance();
    }

    re_offer_onto_pcma(&mut pair, remote);
    assert_eq!(
        pair.caller.engine.session(call).expect("media").codec(),
        Codec::Pcma
    );
    assert_eq!(
        pair.callee.engine.session(remote).expect("media").codec(),
        Codec::Pcma
    );

    let mut heard = Vec::new();
    let mut queued = 0;
    for _ in 0..40 {
        tone(&mut samples, 8_000, &mut phase);
        let outbound = pair
            .caller
            .engine
            .session(call)
            .expect("media")
            .capture(&samples)
            .expect("it encodes")
            .map(|out| out.payload.to_vec());
        if let Some(mut datagram) = outbound {
            let mut session = pair.callee.engine.session(remote).expect("media");
            if session.receive(&mut datagram, caller_media(), pair.now) == Arrival::Queued {
                queued += 1;
            }
        }
        let mut session = pair.callee.engine.session(remote).expect("media");
        heard = vec![0_i16; session.frame_samples()];
        session.playback(&mut heard);
        drop(session);
        pair.advance();
    }

    assert!(
        queued > 20,
        "only {queued} of forty packets were taken after the codec change"
    );
    assert!(
        loudness(&heard) > 4_000,
        "the tone came back at {} after the codec change",
        loudness(&heard)
    );
}

/// The defect this whole change exists for, stated where it can be seen.
///
/// A codec change used to open a session on the identity the *call* opened
/// with, so the sequence number rewound to where it started while the master
/// key stayed exactly as it was. The SRTP packet index is `2^16 · ROC + SEQ`,
/// so every packet after the change re-used a keystream already spent — the
/// two-time pad RFC 3711 §9.1 calls catastrophic, and invisible in a capture.
///
/// The live assertion is the sequence number: break the carry and this test
/// goes red. The replay assertion after it is a guard rather than a proof —
/// nothing touches the receive context when the keys have not moved, and it
/// is there so that a later `reformat` which rebuilt that context would be
/// caught here rather than in a capture.
#[test]
fn a_codec_change_on_a_secured_call_does_not_re_open_the_packet_index() {
    let now = Instant::now();
    let config = MediaConfig::default();
    let (ours, theirs) = savp_pair(OURS, THEIRS);
    let mut sender = session(&ours, &theirs, now);
    let mut receiver = session(&theirs, &ours, now);

    let mut already_taken = Vec::new();
    for _ in 0..40 {
        already_taken = one_packet(&mut sender);
        receiver.receive(&mut already_taken.clone(), ours_address(), now);
    }
    let before = sequence_of(&already_taken);

    // the same two ends, the same keys, PCMA instead of PCMU
    let ours_2 = parse(savp_of("192.0.2.1", 40_000, 8, "PCMA/8000", SHA1_80, OURS).as_bytes())
        .expect("the offer parses");
    let theirs_2 = parse(savp_of("192.0.2.2", 40_002, 8, "PCMA/8000", SHA1_80, THEIRS).as_bytes())
        .expect("the answer parses");
    sender
        .reformat(&plan_of(&ours_2, &theirs_2), 20, &config, Vec::new(), now)
        .expect("the codec is one this build has");
    receiver
        .reformat(&plan_of(&theirs_2, &ours_2), 20, &config, Vec::new(), now)
        .expect("the codec is one this build has");
    assert_eq!(sender.codec(), Codec::Pcma, "the plan never reached it");

    let moved = sequence_of(&one_packet(&mut sender)).wrapping_sub(before);
    assert!(
        moved > 0 && moved < 0x8000,
        "the stream rewound its sequence number under a key that has sent \
         forty packets already"
    );

    let arrival = receiver.receive(&mut already_taken.clone(), ours_address(), now);
    assert!(
        matches!(
            arrival,
            Arrival::Dropped(crate::Discard::Insecure(SrtpError::Replayed))
        ),
        "the codec change re-opened the replay window on an unchanged master \
         key: {arrival:?}"
    );
}

/// `SrtpPolicy::Required` promises that "a plain re-offer inside a live call
/// is refused rather than accepted", because "a stack that offers SDES and
/// then answers a mid-call plain re-offer in the clear has fallen back
/// silently, which is the worst of the outcomes available".
///
/// The re-offer here keeps every format the first negotiation settled and
/// changes only the profile and the key — which is what a downgrade looks
/// like, and what a B2BUA that has lost its own SRTP does.
#[test]
fn a_plain_re_offer_that_keeps_the_formats_is_refused_too() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::Required);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .is_encrypted()
    );

    // the callee's own last description, with the profile taken down to
    // RTP/AVP and the key removed. Every format stays exactly where it was
    let mut downgrade = pair
        .caller
        .answer_received()
        .expect("the caller saw the answer");
    downgrade.origin.version += 5;
    for stream in &mut downgrade.media {
        stream.proto = "RTP/AVP".to_owned();
        stream.attributes.retain(|a| a.name != "crypto");
    }
    let bytes = downgrade.to_bytes();
    pair.callee
        .agent
        .reoffer(remote, &bytes, pair.now)
        .expect("the re-INVITE goes");

    // the re-INVITE reaches the caller, and whatever the caller answers goes
    // on the wire before anything else happens
    for datagram in pair.callee.outbound() {
        pair.caller.deliver(&datagram, callee_sip(), pair.now);
    }
    pair.caller.drain(pair.now, false);
    let answered: Vec<String> = pair
        .caller
        .outbound()
        .iter()
        .map(|datagram| String::from_utf8_lossy(datagram).into_owned())
        .collect();

    assert!(
        !answered
            .iter()
            .any(|response| response.starts_with("SIP/2.0 2")),
        "a call that requires SRTP accepted a re-offer that took the keys \
         away: {answered:?}"
    );
}

/// RFC 4568 §9.2: "the SDP MUST be protected". A `{:?}` on a live stack is
/// not protection, and it reaches every call at once — so the test is on the
/// whole thing, not on the one type that happens to hold the key today.
#[test]
fn printing_a_live_secured_stack_prints_no_key_material() {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_srtp(SrtpPolicy::Required);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .is_encrypted()
    );

    let printed = format!("{:?} {:?}", pair.caller.engine, pair.caller.agent);
    // the offer and the answer both carried a key, and both are held
    assert!(
        printed.contains("crypto"),
        "the crypto line itself is worth seeing: {printed}"
    );
    for line in pair
        .caller
        .answer_received()
        .expect("the caller saw the answer")
        .media
        .iter()
        .flat_map(|stream| stream.attributes.iter())
        .filter(|attribute| attribute.name == "crypto")
    {
        let value = line.value.as_deref().expect("a crypto line has a value");
        let inline = value
            .split_ascii_whitespace()
            .find(|word| word.starts_with("inline:"))
            .expect("a crypto line names a key");
        assert!(
            !printed.contains(inline),
            "the master key reached a debug print: {inline}"
        );
    }
}

/// And the way back out, which is the half that was missing. The watchdog
/// measures from the last packet that arrived; during a hold none do. A
/// resume keeps the media address — only the direction attribute moves — so
/// the mark stayed where the hold began, and the first timer tick after
/// resuming read the whole length of the hold as silence.
#[test]
fn a_resume_after_a_long_hold_is_not_reported_as_a_stalled_stream() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let _ = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    pair.callee.agent.hold(remote, pair.now).expect("the hold");
    pair.callee.drain(pair.now, false);
    pair.settle();

    // a hold long enough that the whole of it is silence by any measure
    pair.now += Duration::from_secs(600);
    pair.callee
        .agent
        .resume(remote, pair.now)
        .expect("the resume");
    pair.callee.drain(pair.now, false);
    pair.settle();
    assert!(
        pair.callee
            .engine
            .session(remote)
            .is_some_and(|session| session.is_receiving()),
        "the resume never reached the media"
    );
    pair.callee.media_events();

    // the first tick after resuming, before any packet could have arrived
    pair.callee.engine.handle_timeout(pair.now);
    pair.callee.drain(pair.now, false);
    let stalled: Vec<Duration> = pair
        .callee
        .media_events()
        .into_iter()
        .filter_map(|event| match event {
            MediaEvent::Stalled { silent_for } => Some(*silent_for),
            _ => None,
        })
        .collect();
    assert!(
        stalled.is_empty(),
        "the hold itself was reported as silence the moment it ended: {stalled:?}"
    );
}

/// RFC 3550 §6.6: a participant that leaves says so. It is the last thing a
/// stream owes the far end and the only moment it can be said — the session
/// is out of the engine in the same breath as the event that reports the end,
/// so a packet still inside it is one nobody can reach.
#[test]
fn a_call_that_ends_leaves_an_rtcp_goodbye_behind_it() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    // one packet each way, so the control destination is latched
    let tone = vec![100_i16; 160];
    pair.exchange(call, remote, &tone);
    pair.advance();

    pair.caller
        .agent
        .hangup(call, pair.now)
        .expect("the hangup");
    pair.settle();
    pair.caller.drain(pair.now, false);

    let farewells: Vec<(CallHandle, Vec<u8>)> = std::iter::from_fn(|| {
        pair.caller
            .engine
            .poll_farewell()
            .map(|(call, _, payload)| (call, payload))
    })
    .collect();
    assert_eq!(farewells.len(), 1, "{farewells:?}");
    let (named, payload) = farewells.into_iter().next().expect("one goodbye");
    assert_eq!(named, call, "the goodbye named another call");
    assert!(
        carries_bye(&payload),
        "the datagram carries no BYE: {:?}",
        payload.get(..8)
    );
}

/// Whether a compound RTCP packet carries a BYE (§6.6, packet type 203).
///
/// Walked rather than searched: §6.1 requires a compound packet to begin with
/// a report, so the BYE is never the first header, and the length field of
/// each packet is what says where the next one starts — "the length of this
/// RTCP packet in 32-bit words minus one".
fn carries_bye(compound: &[u8]) -> bool {
    let mut at = 0;
    while let (Some(&kind), Some(&high), Some(&low)) = (
        compound.get(at + 1),
        compound.get(at + 2),
        compound.get(at + 3),
    ) {
        if kind == 203 {
            return true;
        }
        let words = usize::from(u16::from_be_bytes([high, low]));
        at += words.saturating_add(1) * 4;
    }
    false
}
