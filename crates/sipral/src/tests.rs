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

use sipral_core::sdp::{Direction, SessionDescription, parse};

use crate::codec::{Codec, CodecCatalog};
use crate::error::MediaError;
use crate::event::{Event, MediaEvent};
use crate::record::tests::Buffer;
use crate::session::{Arrival, MediaConfig, MediaSession, Playback, StreamIdentity};
use crate::{
    Account, AccountId, CallHandle, EndpointConfig, Input, MediaEngine, OutgoingCall, TransportId,
    TransportProtocol, UaEvent, Uri, UserAgent, WallClock,
};

const UDP: TransportId = TransportId(1);

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
        let mut agent = UserAgent::new(EndpointConfig::default(), [seed; 32]);
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

    /// One frame of audio each way, and the frame the far end played.
    fn exchange(&mut self, call: CallHandle, remote: CallHandle, tone: &[i16]) -> Vec<i16> {
        let outbound = {
            let session = self
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
            let session = self
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
        let session = self
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
        while let Some((_, datagram)) = self.caller.engine.poll_rtcp(self.now) {
            pending.push((datagram.payload.to_vec(), true));
        }
        while let Some((_, datagram)) = self.callee.engine.poll_rtcp(self.now) {
            pending.push((datagram.payload.to_vec(), false));
        }
        for (mut datagram, from_caller) in pending {
            sent += 1;
            let (session, from) = if from_caller {
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
        Some(Codec::Opus)
    );
    assert_eq!(
        pair.callee
            .engine
            .session(remote)
            .map(|session| session.codec()),
        Some(Codec::Opus)
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
        let session = pair
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

    let session = pair
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
    let session = pair
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

    let held = pair.callee.engine.session(remote).expect("media");
    assert_eq!(held.direction(), Direction::RecvOnly);
    assert!(!held.is_sending(), "the held end is still sending");
    assert!(held.is_receiving(), "the held end has stopped listening");
    assert!(
        held.capture(&[100; 160]).expect("no error").is_none(),
        "a held stream put a packet on the wire"
    );

    pair.caller
        .agent
        .resume(call, pair.now)
        .expect("the resume");
    pair.caller.drain(pair.now, false);
    pair.settle();

    let resumed = pair.callee.engine.session(remote).expect("media");
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
        let session = pair.caller.engine.session(call).expect("media");
        if let Some(mut datagram) = back {
            session.receive(&mut datagram, callee_media(), pair.now);
        }
        // and the caller plays what arrived. A side that receives and never
        // pulls is a side whose buffer fills up, which is a real fault and
        // would be measured as one here
        let mut played = vec![0_i16; session.frame_samples()];
        session.playback(&mut played);
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
    let session = pair.callee.engine.session(remote).expect("media");
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

    let session = pair.caller.engine.session(call).expect("media");
    session
        .start_recording(Box::new(Buffer::new()))
        .expect("the first one starts");
    assert_eq!(
        session.start_recording(Box::new(Buffer::new())),
        Err(MediaError::AlreadyRecording)
    );
    assert_eq!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .stop_recording()
            .and_then(|()| pair
                .caller
                .engine
                .session(call)
                .expect("media")
                .stop_recording()),
        Err(MediaError::NotRecording)
    );
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
