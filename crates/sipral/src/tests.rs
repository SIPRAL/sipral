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

use sipral_core::msg::{ParseMode, ParseScratch};
use sipral_core::replay::Recorder;
use sipral_core::sdp::{Crypto, Direction, MediaDescription, SessionDescription, parse};
use sipral_rtp::srtp::SrtpError;

use crate::codec::tests::UNMATCHED;
use crate::codec::{Codec, CodecCandidate, CodecCatalog, CodecOutcome};
use crate::dtmf::{DEFAULT_DIGIT, Digit};
use crate::error::MediaError;
use crate::event::{Event, MediaEvent};
use crate::keying::SrtpPolicy;
use crate::record::tests::Buffer;
use crate::session::{Arrival, MediaConfig, MediaSession, Playback, Start, StreamIdentity};
use crate::{
    Account, AccountId, CallHandle, CallMedia, EndpointConfig, Input, MediaEngine, OutgoingCall,
    OutgoingExtras, TransportId, TransportProtocol, UaEvent, Uri, UserAgent, WallClock,
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
            .capture(tone, self.now)
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
                .capture(tone, self.now)
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

    /// One frame from the caller to the callee: the datagram that went, if
    /// one did, and what the callee then played and how.
    fn one_way(
        &mut self,
        call: CallHandle,
        remote: CallHandle,
        samples: &[i16],
    ) -> (Option<Vec<u8>>, Playback, Vec<i16>) {
        let sent = self
            .caller
            .engine
            .session(call)
            .expect("the caller's media")
            .capture(samples, self.now)
            .expect("the frame encodes")
            .map(|datagram| datagram.payload.to_vec());
        let mut session = self
            .callee
            .engine
            .session(remote)
            .expect("the callee's media");
        if let Some(datagram) = &sent {
            let mut arriving = datagram.clone();
            session.receive(&mut arriving, caller_media(), self.now);
        }
        let mut played = vec![0_i16; session.frame_samples()];
        let outcome = session.playback(&mut played);
        drop(session);
        self.advance();
        (sent, outcome, played)
    }

    fn advance(&mut self) {
        self.now += TICK;
    }

    /// Run the DTLS-SRTP handshake between the two ends, over the media path
    /// and over nothing else, and say how many records crossed.
    ///
    /// The shape a real driver has to have: drain `poll_transmit` to empty,
    /// deliver, drive the clock to whatever `poll_timeout` asked for, drain
    /// again. A driver that skips any of those three is a driver whose calls
    /// come up silent, which is what this reproduces if it is got wrong.
    #[cfg(feature = "dtls")]
    fn shake_hands(&mut self, call: CallHandle, remote: CallHandle) -> usize {
        let mut crossed = 0;
        for _ in 0..64 {
            let mut moved = false;
            let mut pending = Vec::new();
            while let Some((_, _, record)) = self.caller.engine.poll_transmit(self.now) {
                pending.push((record, true));
            }
            while let Some((_, _, record)) = self.callee.engine.poll_transmit(self.now) {
                pending.push((record, false));
            }
            for (mut record, from_caller) in pending {
                crossed += 1;
                moved = true;
                let (mut session, from) = if from_caller {
                    (
                        self.callee.engine.session(remote).expect("media"),
                        caller_media(),
                    )
                } else {
                    (
                        self.caller.engine.session(call).expect("media"),
                        callee_media(),
                    )
                };
                session.receive(&mut record, from, self.now);
            }
            let keyed = self
                .caller
                .engine
                .session(call)
                .expect("media")
                .is_encrypted()
                && self
                    .callee
                    .engine
                    .session(remote)
                    .expect("media")
                    .is_encrypted();
            // the events the handshake raised are the session's until the
            // engine is drained, and an application learns of them there
            self.caller.drain(self.now, false);
            self.callee.drain(self.now, false);
            if keyed {
                break;
            }
            if !moved {
                // nothing crossed, so only the retransmission timer can move
                // either end
                self.now += Duration::from_millis(1100);
                self.caller.engine.handle_timeout(self.now);
                self.callee.engine.handle_timeout(self.now);
            }
        }
        crossed
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

/// The ACK that confirms a call rung with media carries no description of its
/// own — the ordinary case, since RFC 6337 §3.1.1 already forbids repeating
/// one sent reliably — and `settle` used to read that as a change anyway,
/// because it compared nothing before deciding the running session had moved.
/// Neither side's plan has moved: the far end's `CallConfirmed` and this
/// end's `IncomingAck` both settle on exactly the same local and remote
/// descriptions the 183 already wrote. A hold placed afterward is a real
/// change and must still be reported.
#[test]
fn the_ack_after_ringing_with_media_reports_no_change_but_a_real_one_still_is() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let remote = pair.ring();
    // whatever provisional response the core sent on its own before the
    // application had a chance to
    let _ = pair.callee.outbound();

    pair.callee
        .engine
        .ring(&mut pair.callee.agent, remote, callee_media(), pair.now)
        .expect("the 183 goes");
    pair.callee.drain(pair.now, false);
    for datagram in pair.callee.outbound() {
        pair.caller.deliver(&datagram, callee_sip(), pair.now);
    }
    pair.settle();

    pair.callee
        .engine
        .answer(&mut pair.callee.agent, remote, callee_media(), pair.now)
        .expect("the 200 OK goes");
    pair.callee.drain(pair.now, false);
    // carries the 200 OK to the caller, the caller's ACK back to the callee,
    // and drains both sides — the exchange that used to manufacture a change
    pair.settle();

    let call = pair.caller.call().expect("the caller knows the call");
    for side in [
        ("caller", pair.caller.media_events()),
        ("callee", pair.callee.media_events()),
    ] {
        let (name, events) = side;
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, MediaEvent::Started { .. }))
                .count(),
            1,
            "{name} should have started media exactly once: {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, MediaEvent::Changed { .. })),
            "{name} reported a change nothing about the session made: {events:?}"
        );
    }

    // a real change — a hold — is still reported once it actually happens
    pair.caller.agent.hold(call, pair.now).expect("the hold");
    pair.caller.drain(pair.now, false);
    pair.settle();
    assert!(
        pair.callee
            .media_events()
            .iter()
            .any(|event| matches!(event, MediaEvent::Changed { .. })),
        "a hold placed after settling should still be reported: {:?}",
        pair.callee.media_events()
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

/// The lesson the interop harness's own media join used to encode by hand: a
/// real PBX that answers with one G.711 law and sends the other. Dropping the
/// far end's audio at the RTP layer would look like silence rather than like
/// a fault, so the sibling law is accepted and decoded with the law it
/// actually names.
#[test]
fn a_peer_that_negotiated_one_g711_law_and_sends_the_other_is_still_heard() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    // past RFC 3550 A.1's probation, on the law this call actually negotiated
    for _ in 0..4 {
        tone(&mut samples, 8_000, &mut phase);
        let _ = pair.exchange(call, remote, &samples);
        pair.advance();
    }

    // one more frame, mislabelled the way that PBX mislabelled it: the octets
    // this end sends are still mu-law, but the RTP header now claims A-law
    tone(&mut samples, 8_000, &mut phase);
    let mut sent = pair
        .caller
        .engine
        .session(call)
        .expect("the caller's media")
        .capture(&samples, Instant::now())
        .expect("the frame encodes")
        .map(|datagram| datagram.payload.to_vec())
        .expect("a frame that is neither held nor suppressed goes out");
    let byte = sent.get_mut(1).expect("an RTP header has a second octet");
    *byte = (*byte & 0x80) | 8; // keep the marker bit, claim PCMA (8)

    let mut session = pair
        .callee
        .engine
        .session(remote)
        .expect("the callee's media");
    let arrival = session.receive(&mut sent, caller_media(), pair.now);
    assert_eq!(
        arrival,
        Arrival::Queued,
        "the far end's own law was refused at the RTP layer: {arrival:?}"
    );
    let mut played = vec![0_i16; session.frame_samples()];
    let outcome = session.playback(&mut played);
    assert_eq!(
        outcome,
        Playback::Packet,
        "a mislabelled frame was concealed instead of played"
    );
    assert!(
        loudness(&played) > 4_000,
        "the mislabelled frame came back at {} rather than as the tone",
        loudness(&played)
    );
}

/// Frames of the tone, of silence, or of the tone again, through a G.729
/// call, and what each came to: its payload's length (`None` for a frame
/// not sent), whether its RTP header carried the marker bit, and what the
/// far end played and how loud.
fn g729_through(
    pair: &mut Pair,
    call: CallHandle,
    remote: CallHandle,
    shape: &[(bool, usize)],
) -> Vec<(Option<usize>, bool, Playback, i64)> {
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut out = Vec::new();
    for (talking, frames) in shape {
        for _ in 0..*frames {
            if *talking {
                tone(&mut samples, 8_000, &mut phase);
            } else {
                samples.fill(0);
            }
            let (sent, outcome, played) = pair.one_way(call, remote, &samples);
            let length = sent.as_ref().map(|datagram| datagram.len() - 12);
            let marker = sent
                .as_ref()
                .and_then(|datagram| datagram.get(1))
                .is_some_and(|octet| octet & 0x80 != 0);
            out.push((length, marker, outcome, loudness(&played)));
        }
    }
    out
}

/// G.729 end to end with Annex B, which a catalogue naming G.729 allows
/// unless told otherwise: `annexb=yes` in the offer and in the answer, the
/// tone as twenty octets a packet, a pause as a SID frame and then nothing
/// on the wire while the far end plays the codec's own comfort noise, and
/// the tone again, its first packet marked as a talk spurt's.
#[test]
fn a_g729_call_with_annex_b_both_ways_sends_a_pause_as_a_sid_and_silence() {
    let catalog = CodecCatalog::with_order(&["G729"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let offer = one_stream(&pair.callee.offer_received().expect("an offer"));
    let answer = one_stream(&pair.caller.answer_received().expect("an answer"));
    for (stream, which) in [(&offer, "offer"), (&answer, "answer")] {
        assert_eq!(
            stream.formats.first().map(String::as_str),
            Some("18"),
            "{which}"
        );
        assert_eq!(stream.fmtp(18), Some("annexb=yes"), "{which}");
    }

    let heard = g729_through(
        &mut pair,
        call,
        remote,
        &[(true, 40), (false, 60), (true, 40)],
    );
    let talking = &heard[20..40];
    assert!(
        talking
            .iter()
            .all(|(length, _, outcome, loud)| *length == Some(20)
                && *outcome == Playback::Packet
                && *loud > 2_000),
        "the tone before the pause: {talking:?}"
    );
    let pause = &heard[40..100];
    let first_quiet = pause
        .iter()
        .position(|(length, ..)| *length != Some(20))
        .expect("the pause changed what went out");
    assert!(
        matches!(pause[first_quiet].0, Some(2 | 12)),
        "a pause starts with a SID frame: {pause:?}"
    );
    let not_sent = pause.iter().filter(|(length, ..)| length.is_none()).count();
    assert!(not_sent > 40, "{not_sent} of 60 frames not sent: {pause:?}");
    assert!(
        pause[30..]
            .iter()
            .all(|(_, _, outcome, _)| *outcome == Playback::ComfortNoise),
        "the far end played the pause as comfort noise: {pause:?}"
    );
    let again = &heard[100..];
    let resumed = again
        .iter()
        .position(|(length, ..)| *length == Some(20))
        .expect("the tone goes out again");
    assert!(again[resumed].1, "a talk spurt's first packet is marked");
    assert!(
        again[20..].iter().all(|(_, marker, outcome, loud)| !*marker
            && *outcome == Playback::Packet
            && *loud > 2_000),
        "the tone after the pause: {again:?}"
    );
}

/// With Annex B off at either end, neither end uses it: an offer with it
/// off says `annexb=no` and the answer follows; an answer that refuses the
/// offer's `yes` stops the offerer using it too; and a pause then goes out
/// frame by frame, twenty octets each, as speech.
#[test]
fn a_g729_call_with_annex_b_off_at_either_end_sends_every_frame() {
    let on = CodecCatalog::with_order(&["G729"]).expect("an order");
    let off = on.clone().with_g729_annex_b(false);
    for (placing, answering, offered, answered) in [
        (off.clone(), on.clone(), "annexb=no", "annexb=no"),
        (on, off, "annexb=yes", "annexb=no"),
    ] {
        let mut pair = Pair::asymmetric(placing, answering);
        let call = pair.connect();
        let remote = pair.callee.call().expect("the callee knows the call");
        let offer = one_stream(&pair.callee.offer_received().expect("an offer"));
        let answer = one_stream(&pair.caller.answer_received().expect("an answer"));
        assert_eq!(offer.fmtp(18), Some(offered));
        assert_eq!(answer.fmtp(18), Some(answered));

        let heard = g729_through(&mut pair, call, remote, &[(true, 20), (false, 40)]);
        assert!(
            heard
                .iter()
                .all(|(length, marker, ..)| *length == Some(20) && !*marker),
            "{offered} / {answered}: {heard:?}"
        );
    }
}

/// G.729 end to end: offered only because the order names it, on its static
/// type, twenty octets a packet, and the tone through this stack's own
/// encoder and decoder.
#[test]
fn a_call_on_g729_carries_the_tone() {
    let catalog = CodecCatalog::with_order(&["G729"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let offer = one_stream(&pair.callee.offer_received().expect("an offer"));
    let answer = one_stream(&pair.caller.answer_received().expect("an answer"));
    for (stream, which) in [(&offer, "offer"), (&answer, "answer")] {
        assert_eq!(
            stream.formats.first().map(String::as_str),
            Some("18"),
            "{which}"
        );
    }
    let session = pair.caller.engine.session(call).expect("media");
    assert_eq!(session.codec(), Codec::G729);
    assert_eq!(session.frame_samples(), 160);
    drop(session);

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut heard = Vec::new();
    for _ in 0..25 {
        tone(&mut samples, 8_000, &mut phase);
        heard = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert_eq!(heard.len(), 160);
    assert!(
        loudness(&heard) > 2_000,
        "the tone came back at {} rather than crossing the call",
        loudness(&heard)
    );

    tone(&mut samples, 8_000, &mut phase);
    let (sent, _) = pair.speak(call, remote, &samples);
    assert_eq!(
        sent.len(),
        12 + 20,
        "two ten-octet frames behind the header"
    );
}

/// A peer that sends Annex B even though this end said `annexb=no`: a
/// payload of nothing but a SID frame starts the codec's comfort noise, and
/// the silence the far end then keeps is filled with the same noise rather
/// than with nothing.
#[test]
fn a_g729_sid_frame_from_the_far_end_is_played_as_comfort_noise() {
    let catalog = CodecCatalog::with_order(&["G729"])
        .expect("an order")
        .with_g729_annex_b(false);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    for _ in 0..25 {
        tone(&mut samples, 8_000, &mut phase);
        let _ = pair.exchange(call, remote, &samples);
        pair.advance();
    }

    // the next packet, cut down to its header and two octets of SID, whose
    // energy is the top of Annex B's scale
    tone(&mut samples, 8_000, &mut phase);
    let mut datagram = pair
        .caller
        .engine
        .session(call)
        .expect("the caller's media")
        .capture(&samples, pair.now)
        .expect("the frame encodes")
        .map(|datagram| datagram.payload.to_vec())
        .expect("a frame goes out");
    datagram.truncate(12);
    datagram.extend_from_slice(&[0x00, 0x3e]);

    let mut session = pair
        .callee
        .engine
        .session(remote)
        .expect("the callee's media");
    assert_eq!(
        session.receive(&mut datagram, caller_media(), pair.now),
        Arrival::Queued
    );
    // the buffer still holds the speech ahead of the SID for a frame or
    // two; after it, nothing more arrives, since the far end is in its pause
    let mut played = vec![0_i16; 160];
    let mut outcomes = Vec::new();
    for _ in 0..6 {
        let outcome = session.playback(&mut played);
        outcomes.push((outcome, loudness(&played)));
    }
    let paused = outcomes
        .iter()
        .position(|(outcome, _)| *outcome != Playback::Packet)
        .expect("something other than a packet was played");
    let pause = &outcomes[paused..];
    assert!(pause.len() >= 3, "{outcomes:?}");
    assert!(
        pause
            .iter()
            .all(|(outcome, loud)| *outcome == Playback::ComfortNoise && *loud > 100),
        "the pause was not filled with noise: {outcomes:?}"
    );
}

/// The other lesson: offering only mu-law is not what a client does, because
/// the first real PBX the interop harness met allows A-law only. The default
/// catalogue offers both, so a peer that keeps only A-law still gets a call
/// with audio on it.
#[test]
fn a_call_still_connects_against_a_peer_that_keeps_only_a_law() {
    let mut pair = Pair::asymmetric(
        CodecCatalog::new(),
        CodecCatalog::with_order(&["PCMA"]).expect("an order"),
    );
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    assert_eq!(
        pair.caller
            .engine
            .session(call)
            .map(|session| session.codec()),
        Some(Codec::Pcma),
        "the default catalogue did not offer A-law at all"
    );

    let frame = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .frame_samples();
    let mut samples = vec![0_i16; frame];
    let mut phase = 0_u32;
    let mut heard = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        heard = pair.exchange(call, remote, &samples);
        pair.advance();
    }
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

// -- DTLS-SRTP ----------------------------------------------------------------

/// One frame of the same tone every other test here uses.
#[cfg(feature = "dtls")]
fn one_frame() -> Vec<i16> {
    let mut samples = vec![0_i16; 160];
    let mut phase = 0;
    tone(&mut samples, 8_000, &mut phase);
    samples
}

/// A call placed under a DTLS policy, taken to the point where the two ends
/// have described each other and the handshake has not run yet.
#[cfg(feature = "dtls")]
fn dtls_call() -> (Pair, CallHandle, CallHandle) {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_srtp(SrtpPolicy::DtlsOffered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side of the call");
    (pair, call, remote)
}

#[cfg(feature = "dtls")]
#[test]
fn the_offer_a_dtls_call_writes_names_a_fingerprint_and_asks_to_multiplex() {
    let (pair, _, _) = dtls_call();
    let offer = one_stream(
        &pair
            .callee
            .offer_received()
            .expect("the callee saw an offer"),
    );
    assert_eq!(offer.proto, "UDP/TLS/RTP/SAVP");
    let fingerprint = offer
        .attribute("fingerprint")
        .and_then(|line| line.value.as_deref())
        .expect("the offer carries a fingerprint");
    assert!(fingerprint.starts_with("sha-256 "), "{fingerprint}");
    // RFC 5763 §5: "The endpoint that is the offerer MUST use the setup
    // attribute value of setup:actpass"
    assert_eq!(
        offer
            .attribute("setup")
            .and_then(|line| line.value.as_deref()),
        Some("actpass")
    );
    // RFC 5764 §4.2 would put a second handshake on a separate RTCP port, and
    // this stack runs one, so the offer asks for the attribute whatever the
    // catalogue says about it
    assert!(offer.has_rtcp_mux(), "the offer did not ask to multiplex");
    assert!(
        crypto_line(&offer).is_none(),
        "a description keyed by a handshake also put a key in the body"
    );

    let answer = one_stream(
        &pair
            .caller
            .answer_received()
            .expect("the caller saw an answer"),
    );
    assert_eq!(answer.proto, "UDP/TLS/RTP/SAVP");
    // §4.1's table: the answer to actpass is active, and RFC 5763 §5
    // recommends it so the answerer's ClientHello leaves with the answer
    assert_eq!(
        answer
            .attribute("setup")
            .and_then(|line| line.value.as_deref()),
        Some("active")
    );
    let theirs = answer
        .attribute("fingerprint")
        .and_then(|line| line.value.as_deref())
        .expect("the answer carries one too");
    assert_ne!(
        theirs, fingerprint,
        "both ends offered the same certificate, so neither authenticates anything"
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_call_that_agreed_dtls_srtp_sends_nothing_until_the_handshake_has_keyed_it() {
    let (mut pair, call, remote) = dtls_call();
    let tone = one_frame();

    // the session exists, has a codec and an address, and reports itself as
    // not encrypted: the padlock is drawn from the keys, not from the SDP
    {
        let session = pair.caller.engine.session(call).expect("media");
        assert!(!session.is_encrypted());
        assert!(session.is_awaiting_keys());
    }

    // and it carries nothing. Not one octet, in fifty frames — a second of a
    // call, which is longer than the handshake it is waiting for
    for frame in 0..50 {
        let mut session = pair.caller.engine.session(call).expect("media");
        let sent = session
            .capture(&tone, Instant::now())
            .expect("the frame encodes")
            .is_some();
        drop(session);
        assert!(
            !sent,
            "frame {frame} went out in the clear on a stream that agreed to be encrypted"
        );
    }
    // nor any report, which would have carried this end's canonical name
    assert!(
        pair.caller.engine.poll_rtcp(pair.now).is_none(),
        "a report went out unprotected"
    );

    // the handshake, and then it does
    let crossed = pair.shake_hands(call, remote);
    assert!(crossed >= 4, "only {crossed} records crossed");
    {
        let session = pair.caller.engine.session(call).expect("media");
        assert!(session.is_encrypted());
        assert!(!session.is_awaiting_keys());
    }
    let mut session = pair.caller.engine.session(call).expect("media");
    let went = session
        .capture(&tone, Instant::now())
        .expect("the frame encodes")
        .is_some();
    drop(session);
    assert!(went, "the call stayed silent after it was keyed");
}

#[cfg(feature = "dtls")]
#[test]
fn two_stacks_complete_a_dtls_handshake_on_the_media_path_and_the_tone_crosses_afterwards() {
    let (mut pair, call, remote) = dtls_call();
    pair.shake_hands(call, remote);

    // both ends say the same thing about the same call
    assert!(
        pair.caller
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
        "one end thinks the call is encrypted and the other does not"
    );

    // each end was told, once, with the transform the handshake chose
    let secured: Vec<_> = pair
        .caller
        .heard
        .iter()
        .filter_map(|event| match event {
            Event::Media {
                event: MediaEvent::Secured { suite, peer },
                ..
            } => Some((*suite, *peer)),
            _ => None,
        })
        .collect();
    assert_eq!(
        secured.len(),
        1,
        "the caller was told {} times",
        secured.len()
    );
    // RFC 5764 §4.1.2, and sipral-dtls now offers RFC 7714's AEAD_AES_256_GCM
    // first: the strongest profile both ends here support
    assert_eq!(secured[0].0, sipral_rtp::srtp::Suite::AeadAes256Gcm);
    assert_eq!(secured[0].1, Some(callee_media()));

    // and the audio crosses, which is the far end having decrypted it
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(
        loudness(&played) > 4_000,
        "the tone came back at {} through the handshaken call",
        loudness(&played)
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_dtls_call_carries_none_of_the_plaintext_on_the_wire() {
    let (mut pair, call, remote) = dtls_call();
    pair.shake_hands(call, remote);
    let tone = one_frame();
    let (datagram, _) = pair.speak(call, remote, &tone);

    // the same shape the SDES test proves, reached the other way: the RFC
    // 3711 §3.1 header is readable and nothing past it is
    assert!(datagram.len() > 12);
    let payload = &datagram[12..];
    let plain: Vec<u8> = tone
        .iter()
        .map(|sample| sipral_media::g711::Law::Mu.encode(*sample))
        .collect();
    assert!(
        !payload
            .windows(plain.len().min(payload.len()))
            .any(|window| window == &plain[..window.len()]),
        "the encoded tone is on the wire in the clear"
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_forged_alert_from_a_stranger_does_not_end_a_call_that_is_being_keyed() {
    // the attack this latch exists for. A DTLS connection ends on any fatal
    // alert; an alert arriving before the keys exist cannot be authenticated,
    // because there is nothing yet to authenticate it with. Without the latch
    // one fifteen-octet datagram from anywhere on the path would end every
    // encrypted call this stack places, and the call would look like a call
    // with a network fault.
    //
    // RFC 6347 §4.1: content type 21 is an alert, and this one says
    // handshake_failure (40) at the fatal level (2).
    let forged = || vec![21_u8, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 40];
    let stranger: SocketAddr = "203.0.113.9:40000".parse().expect("an address");

    let (mut pair, call, remote) = dtls_call();
    // before any record has arrived there is no latch, and an alert is
    // refused because it is not the kind of record a latch closes on
    let refused = {
        let mut session = pair.caller.engine.session(call).expect("media");
        session.receive(&mut forged(), stranger, pair.now)
    };
    assert_eq!(refused, Arrival::Dropped(crate::Discard::ForeignAddress));

    // the handshake runs anyway, which is the point
    pair.shake_hands(call, remote);
    assert!(
        pair.caller
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
        "the forged alert killed the call"
    );

    // and once the latch has closed it refuses the same datagram for the
    // other reason
    let refused = {
        let mut session = pair.caller.engine.session(call).expect("media");
        session.receive(&mut forged(), stranger, pair.now)
    };
    assert_eq!(refused, Arrival::Dropped(crate::Discard::ForeignAddress));
}

#[cfg(feature = "dtls")]
#[test]
fn a_re_negotiation_that_names_a_different_certificate_is_refused_by_name() {
    // RFC 5763 §6.6 asks for a new DTLS association there. This stack does
    // not start one, so the honest answer is a refusal the application can
    // read — not a session that carries on under keys the far end has
    // already moved away from
    let (mut pair, call, remote) = dtls_call();
    pair.shake_hands(call, remote);

    let mut moved = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .plan()
        .clone();
    let Some(sipral_core::sdp::Keying::Dtls { fingerprints, .. }) = moved.keying.as_mut() else {
        panic!("the call was not keyed by a handshake");
    };
    fingerprints[0] = "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        .to_owned();

    let candidates = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .codec_candidates()
        .to_vec();
    let mut session = pair.caller.engine.session(call).expect("media");
    let adopted = session.adopt(&moved, candidates, false, pair.now);
    let still_encrypted = session.is_encrypted();
    drop(session);

    assert_eq!(adopted.err(), Some(MediaError::DtlsFingerprintChanged));
    assert!(
        still_encrypted,
        "the session threw away keys both ends still agree on"
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_call_waiting_for_its_keys_asks_to_be_woken_for_the_handshake_and_not_for_a_report() {
    // the deadline a report would have named never moves while the stream is
    // unkeyed, because no report is ever built; a driver told to wake for one
    // would be told to wake immediately, for ever
    let (mut pair, call, _) = dtls_call();
    let now = pair.now;
    let session = pair.caller.engine.session(call).expect("media");
    let deadline = session.poll_timeout().expect("a deadline");
    assert!(
        deadline > now,
        "the session asked to be woken at a moment already passed"
    );
    assert!(!session.rtcp_deadline_passed(now));
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

    // and the octets: the accepted suite's tag longer -- AEAD_AES_256_GCM,
    // the strongest this end offers and the first line the answering side
    // understands, so its sixteen-octet tag rather than AES_CM_128's ten --
    // the header still readable because RFC 3711 §3.1 leaves it in the
    // clear, and nothing of the payload anywhere in it
    assert_eq!(
        closed.datagram.len(),
        open.datagram.len() + 16,
        "the packet did not grow by AEAD_AES_256_GCM's own tag"
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

/// An INVITE carrying an SDES offer still fits a datagram once a server's
/// digest challenge is answered in it.
///
/// Over 1300 octets, with the path MTU unknown, RFC 3261 §18.1.1 moves a
/// request to a congestion-controlled transport, and a phone registered over
/// UDP alone has none: the answered INVITE never leaves, and the call is never
/// placed. Every `a=crypto` line of the offer is in that INVITE, so the offer
/// is kept to what leaves room for an `Authorization` field the shape of the
/// one the lab's Asterisk asks for, with the lab's own digest values in it.
#[test]
fn an_sdes_offer_leaves_an_answered_invite_room_in_a_datagram() {
    const AUTHORIZATION: &str = "Authorization: Digest username=\"labuser-srtp\", \
        realm=\"asterisk\", nonce=\"1790633099/25f6972d5eee33b81b72468670c2b3e3\", \
        uri=\"sip:bob@example.com\", response=\"0817df17685071240abceef36b2be782\", \
        algorithm=MD5, qop=auth, nc=00000001, cnonce=\"d32af035a347eb032cf6229e22b7b6bf\", \
        opaque=\"7defcb0c4fbb9048\"\r\n";

    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::Offered);
    let mut pair = Pair::new(catalog);
    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());
    pair.caller
        .engine
        .place(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    let invite = pair
        .caller
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .expect("the INVITE");
    assert!(
        String::from_utf8_lossy(&invite).contains("a=crypto:"),
        "the offer carries SDES"
    );
    let answered = invite.len() + AUTHORIZATION.len();
    assert!(
        answered <= 1_300,
        "the INVITE is {} octets, {answered} once the challenge is answered",
        invite.len()
    );
}

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
            .capture(&silence, Instant::now())
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
            .is_some_and(|(_, held)| held.is_some_and(|held| held >= Duration::from_millis(80))),
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

/// 8.3.11-bis(d): an RFC 4733 digit sent at the default lasts the same
/// hundred milliseconds an INFO sent without a length carries. The far end
/// reads the length off the closing packet's duration, 800 ticks at eight
/// kilohertz.
#[test]
fn a_digit_dialled_at_the_default_length_lasts_a_hundred_milliseconds() {
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
            .dial("5", DEFAULT_DIGIT)
            .expect("the digit is queued");
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
        heard,
        vec![(Some('5'), Some(Duration::from_millis(100)))],
        "the default digit as the far end heard it"
    );
}

/// 8.3.11: an INFO's digit is the same [`Event::Media`] an RFC 4733 one is,
/// told apart only by [`crate::DigitSource`] — not a signalling event of its
/// own on the way through the facade.
#[test]
fn a_digit_sent_by_info_is_heard_as_the_same_event_rfc_4733_uses() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();

    pair.caller
        .agent
        .send_dtmf_info(call, "7", crate::DtmfInfoForm::Relay, 0, pair.now)
        .expect("the INFO goes");
    pair.settle();

    let heard: Vec<_> = pair
        .callee
        .media_events()
        .into_iter()
        .filter_map(|event| match event {
            MediaEvent::DigitReceived { digit, source, .. } => Some((*digit, *source)),
            _ => None,
        })
        .collect();
    assert_eq!(heard, vec![(Some('7'), crate::DigitSource::Info)]);
    assert!(
        pair.callee
            .heard
            .iter()
            .all(|event| !matches!(event, Event::Signalling(UaEvent::DtmfReceived { .. }))),
        "the INFO's own event does not also reach the application: {:?}",
        pair.callee.heard
    );

    assert!(
        pair.caller.heard.iter().any(|event| matches!(
            event,
            Event::Signalling(UaEvent::DtmfSent { status, digit: '7', .. })
                if status.get() == 200
        )),
        "{:?}",
        pair.caller.heard
    );
}

/// The same datagram this stack wrote, with its body replaced and
/// `Content-Type`/`Content-Length` corrected to match — the only way to put a
/// literal `Duration=0` on the wire, since sending it through
/// [`UserAgent::send_dtmf_info`](sipral_ua::UserAgent::send_dtmf_info) itself
/// reads zero as "say nothing" and sends the hundred-millisecond default
/// instead (8.3.11-ter(d)).
fn with_body(datagram: &[u8], content_type: &str, body: &str) -> Vec<u8> {
    let boundary = datagram
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a header/body boundary");
    let mut out = Vec::new();
    for line in datagram[..boundary].split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let lower = line.to_ascii_lowercase();
        if lower.starts_with(b"content-type") || lower.starts_with(b"content-length") {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

/// 8.3.11-ter(d): a peer that said `Duration=0` held the key for no time at
/// all, and a peer sending `application/dtmf` never says how long it held one
/// — two different facts the layer below this one keeps apart
/// (`sipral_ua::dtmf::DtmfInfo::held_ms` is `Some(0)` for one and `None` for
/// the other), and this facade used to fold back into one zero.
#[test]
fn a_duration_of_zero_and_no_duration_at_all_report_different_held_values() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();

    pair.caller
        .agent
        .send_dtmf_info(call, "6", crate::DtmfInfoForm::Relay, 40, pair.now)
        .expect("the INFO goes");
    let relay_template = pair.caller.outbound();
    assert_eq!(relay_template.len(), 1, "{relay_template:?}");
    let zero_duration = with_body(
        &relay_template[0],
        "application/dtmf-relay",
        "Signal=6\r\nDuration=0\r\n",
    );
    pair.callee.deliver(&zero_duration, caller_sip(), pair.now);
    pair.callee.drain(pair.now, false);
    // the caller's own queue has to see this digit answered before it will
    // send the next one at all (8.3.11-bis(b))
    let answered = pair.callee.outbound();
    assert_eq!(answered.len(), 1, "{answered:?}");
    pair.caller.deliver(&answered[0], callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);

    pair.caller
        .agent
        .send_dtmf_info(call, "7", crate::DtmfInfoForm::Relay, 40, pair.now)
        .expect("the INFO goes");
    let plain_template = pair.caller.outbound();
    assert_eq!(plain_template.len(), 1, "{plain_template:?}");
    let no_duration_at_all = with_body(&plain_template[0], "application/dtmf", "7");
    pair.callee
        .deliver(&no_duration_at_all, caller_sip(), pair.now);
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
        heard,
        vec![(Some('6'), Some(Duration::ZERO)), (Some('7'), None)],
        "{heard:?}"
    );
}

/// 8.3.11(c) held RFC 4733 sending, INFO sending and INFO receiving to the
/// same tone lengths. 8.3.11-bis(c) revises the receiving half of that: a
/// `Duration=` a peer sent reports a tone that peer already generated, not
/// one this end is about to, so only the ceiling every sending form also
/// refuses still binds it — the floor below, 40 ms, is where sending and
/// receiving now part ways. Zero is still left out of this loop, for the
/// same reason it always was (where a length is a number of milliseconds it
/// asks for the default, and where it is a `Duration` it is simply too
/// short); `sipral_ua::dtmf`'s own tests cover a received `Duration=0`.
#[test]
fn every_form_a_digit_takes_refuses_the_same_tone_lengths() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();

    for held_ms in [1_u32, 20, 39, 40, 160, 10_000, 10_001, 60_000] {
        let in_media = {
            let mut session = pair
                .caller
                .engine
                .session(call)
                .expect("the caller's media");
            let dialled = session
                .dial("5", Duration::from_millis(u64::from(held_ms)))
                .is_ok();
            session.stop_dialling();
            dialled
        };
        let by_info = pair
            .caller
            .agent
            .send_dtmf_info(call, "5", crate::DtmfInfoForm::Relay, held_ms, pair.now)
            .is_ok();
        let body = format!("Signal=5\r\nDuration={held_ms}\r\n");
        let received =
            sipral_ua::dtmf::parse_info(Some(b"application/dtmf-relay"), body.as_bytes()).is_ok();
        let sent_taken = (40..=10_000).contains(&held_ms);
        let received_taken = held_ms <= 10_000;
        assert_eq!(
            (in_media, by_info, received),
            (sent_taken, sent_taken, received_taken),
            "{held_ms} ms, as (RFC 4733 sending, INFO sending, INFO receiving)"
        );
    }
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
        held.capture(&[100; 160], Instant::now())
            .expect("no error")
            .is_none(),
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
    assert!(
        resumed
            .capture(&[100; 160], Instant::now())
            .expect("no error")
            .is_some()
    );
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
            .capture(&samples, Instant::now())
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

/// RFC 3611 §5.2: the offerer's `a=rtcp-xr` asks the answerer to send the
/// named blocks, and only the answer's own line asks the offerer to send
/// them back. An answer that left it out had the offerer send no VoIP
/// Metrics block at all, so a call this end answered never learned what the
/// far end measured of its audio.
#[test]
fn an_answer_asks_the_offerer_for_its_voip_metrics_too() {
    let mut pair = Pair::new(CodecCatalog::with_order(&["PCMU"]).expect("an order"));
    let _ = pair.connect();
    let offer = one_stream(&pair.callee.offer_received().expect("an offer"));
    let answer = one_stream(&pair.caller.answer_received().expect("an answer"));
    for (side, stream) in [("offer", &offer), ("answer", &answer)] {
        assert_eq!(
            stream
                .attribute("rtcp-xr")
                .and_then(|line| line.value.as_deref()),
            Some("voip-metrics"),
            "the {side} does not ask for the other end's blocks"
        );
    }
}

/// What RFC 6035's `RemoteMetrics` set must say for `block`, the far end's
/// own RFC 3611 §4.7 block: each figure as the block carries it, and each
/// field §4.7.4 and §4.7.5 let a block leave "unavailable" (127) left out
/// rather than written as a reading.
fn assert_remote_metrics_are(
    remote: &sipral_ua::RemoteQualityMetrics,
    block: &crate::VoipMetricsBlock,
) {
    let known = |value: u8| (value != crate::UNAVAILABLE).then_some(value);
    let level = |value: i8| (value.cast_unsigned() != crate::UNAVAILABLE).then_some(value);
    assert_eq!(remote.loss_rate, block.loss_rate, "loss rate");
    assert_eq!(remote.discard_rate, block.discard_rate, "discard rate");
    assert_eq!(remote.burst_density, block.burst_density, "burst density");
    assert_eq!(
        remote.burst_duration_ms, block.burst_duration_ms,
        "burst duration"
    );
    assert_eq!(remote.gap_density, block.gap_density, "gap density");
    assert_eq!(
        remote.gap_duration_ms, block.gap_duration_ms,
        "gap duration"
    );
    assert_eq!(remote.gmin, block.gmin, "Gmin");
    assert_eq!(
        remote.round_trip_delay_ms, block.round_trip_delay_ms,
        "round trip"
    );
    assert_eq!(
        remote.end_system_delay_ms, block.end_system_delay_ms,
        "end system delay"
    );
    assert_eq!(
        remote.signal_level_dbm0,
        level(block.signal_level_dbm0),
        "signal level"
    );
    assert_eq!(
        remote.noise_level_dbm0,
        level(block.noise_level_dbm0),
        "noise level"
    );
    assert_eq!(remote.rerl_db, known(block.rerl_db), "RERL");
    assert_eq!(
        remote.jitter_buffer_adaptive, block.rx_config.jba as u8,
        "JBA"
    );
    assert_eq!(
        remote.jitter_buffer_rate, block.rx_config.jb_rate,
        "JB rate"
    );
    assert_eq!(
        remote.jitter_buffer_nominal_ms, block.jb_nominal_ms,
        "JB nominal"
    );
    assert_eq!(
        remote.jitter_buffer_maximum_ms, block.jb_maximum_ms,
        "JB maximum"
    );
    assert_eq!(
        remote.jitter_buffer_abs_max_ms, block.jb_abs_max_ms,
        "JB abs max"
    );
    assert_eq!(remote.r_factor, known(block.r_factor), "R factor");
    assert_eq!(
        remote.ext_r_factor,
        known(block.ext_r_factor),
        "external R factor"
    );
    assert_eq!(remote.mos_lq_x10, known(block.mos_lq), "MOS-LQ");
    assert_eq!(remote.mos_cq_x10, known(block.mos_cq), "MOS-CQ");
}

/// One tick of a call whose caller's audio loses one packet in ten on the
/// way: a frame each way, each played, and every report either side has due
/// delivered to the other. Returns the VoIP Metrics block each end put in a
/// report it sent this tick, the caller's first: the one its sender would
/// read of itself at that moment, since both are built from the same state.
fn lossy_tick(
    pair: &mut Pair,
    call: CallHandle,
    remote: CallHandle,
    samples: &[i16],
    tick: u32,
) -> (
    Option<crate::VoipMetricsBlock>,
    Option<crate::VoipMetricsBlock>,
) {
    let outbound = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .capture(samples, pair.now)
        .expect("it encodes")
        .map(|out| out.payload.to_vec());
    {
        let mut session = pair.callee.engine.session(remote).expect("media");
        if let Some(mut datagram) = outbound
            && tick % 10 != 5
        {
            session.receive(&mut datagram, caller_media(), pair.now);
        }
        let mut played = vec![0_i16; session.frame_samples()];
        session.playback(&mut played);
    }
    let back = pair
        .callee
        .engine
        .session(remote)
        .expect("media")
        .capture(samples, pair.now)
        .expect("it encodes")
        .map(|out| out.payload.to_vec());
    {
        let mut session = pair.caller.engine.session(call).expect("media");
        if let Some(mut datagram) = back {
            session.receive(&mut datagram, callee_media(), pair.now);
        }
        let mut played = vec![0_i16; session.frame_samples()];
        session.playback(&mut played);
    }

    let mut pending = Vec::new();
    let mut sent = (None, None);
    {
        let mut session = pair.caller.engine.session(call).expect("media");
        let block = session.statistics(pair.now).voip_metrics;
        while let Some(datagram) = session.poll_rtcp(pair.now) {
            pending.push((datagram.payload.to_vec(), true));
            sent.0 = block;
        }
    }
    {
        let mut session = pair.callee.engine.session(remote).expect("media");
        let block = session.statistics(pair.now).voip_metrics;
        while let Some(datagram) = session.poll_rtcp(pair.now) {
            pending.push((datagram.payload.to_vec(), false));
            sent.1 = block;
        }
    }
    for (mut datagram, from_caller) in pending {
        let (mut session, from) = if from_caller {
            (
                pair.callee.engine.session(remote).expect("media"),
                "192.0.2.1:40001".parse().expect("an address"),
            )
        } else {
            (
                pair.caller.engine.session(call).expect("media"),
                "192.0.2.2:40003".parse().expect("an address"),
            )
        };
        assert_eq!(
            session.receive(&mut datagram, from, pair.now),
            Arrival::Control,
            "a report was refused at tick {tick}"
        );
    }
    pair.advance();
    sent
}

/// Two sessions on one call, each sending the other RTCP XR VoIP Metrics
/// (RFC 3611 §4.7, which both ask for by default), and each end's quality
/// report carrying as its `RemoteMetrics` set (RFC 6035 §4.7) exactly what
/// the other measured of the stream it sent: the last block the far end
/// built about this end's source, figure for figure. The caller's audio
/// loses one packet in ten on the way, so the callee's block has loss,
/// bursts and a rating off its best to carry, and the two ends' blocks
/// differ; the caller has no set before the callee's block has crossed.
#[test]
fn each_end_reports_as_remote_what_the_other_measured_of_its_stream() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    // what each end last sent the other, in the report that carried it
    let (mut from_alice, mut from_bob) = (None, None);
    let mut early = None;
    for tick in 0..1_000_u32 {
        if from_bob.is_none() {
            early = early.or(pair
                .caller
                .engine
                .session(call)
                .expect("media")
                .quality_report_metrics(pair.now)
                .and_then(|metrics| metrics.remote));
        }
        tone(&mut samples, 8_000, &mut phase);
        let (alice, bob) = lossy_tick(&mut pair, call, remote, &samples, tick);
        from_alice = alice.or(from_alice);
        from_bob = bob.or(from_bob);
    }
    assert!(
        early.is_none(),
        "a remote set appeared before any block crossed"
    );

    let bobs: crate::VoipMetricsBlock = from_bob.expect("the callee sent a VoIP Metrics block");
    let alices: crate::VoipMetricsBlock = from_alice.expect("the caller sent one too");
    assert!(bobs.loss_rate > 0, "the callee saw none of the loss");
    assert_eq!(alices.loss_rate, 0, "the caller's audio arrived whole");
    assert_ne!(
        bobs.r_factor, alices.r_factor,
        "the two blocks cannot be told apart"
    );

    for (end, handle, far) in [("caller", call, &bobs), ("callee", remote, &alices)] {
        let engine = if end == "caller" {
            &mut pair.caller.engine
        } else {
            &mut pair.callee.engine
        };
        let report = engine
            .session(handle)
            .expect("media")
            .quality_report_metrics(pair.now)
            .expect("a source to report on");
        let set = report
            .remote
            .unwrap_or_else(|| panic!("the {end} heard no block about its own stream"));
        assert_remote_metrics_are(&set, far);
        // and its own figures are its own, not the other's
        let own = if end == "caller" { &alices } else { &bobs };
        assert_eq!(report.loss_rate, own.loss_rate, "the {end}'s own loss rate");
    }
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
            Vec::new(),
            Start {
                identity: StreamIdentity {
                    ssrc: 1,
                    sequence: 1,
                    timestamp: 0,
                    seed,
                },
                clock: WallClock::from_unix(now, 1_700_000_000, 0),
                #[cfg(feature = "dtls")]
                handshake: None,
                #[cfg(feature = "ice")]
                ice: None,
                annex_b: false,
                now,
            },
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

/// A G.729 far end in an Annex B pause sends nothing on purpose, for as long
/// as the pause lasts and its background does not change — a muted
/// microphone sends one SID frame and then nothing at all. That is not a
/// stream that stopped: while its RTCP keeps arriving the watchdog stays
/// quiet, and once the RTCP stops too it reports the stall as ever.
#[test]
fn a_g729_pause_is_not_a_stall_while_the_far_ends_rtcp_arrives() {
    let catalog = CodecCatalog::with_order(&["G729"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    let heard = g729_through(&mut pair, call, remote, &[(true, 20), (false, 40)]);
    assert!(
        heard[30..]
            .iter()
            .all(|(length, _, outcome, _)| length.is_none() && *outcome == Playback::ComfortNoise),
        "a pause, played as comfort noise: {heard:?}"
    );

    let stalled = |pair: &Pair| {
        pair.callee
            .media_events()
            .into_iter()
            .any(|event| matches!(event, MediaEvent::Stalled { .. }))
    };
    let mut believed = 0;
    for _ in 0..30 {
        pair.now += Duration::from_secs(1);
        believed += pair.exchange_control(call, remote).1;
        pair.callee.engine.handle_timeout(pair.now);
        pair.callee.drain(pair.now, false);
    }
    assert!(
        believed >= 4,
        "{believed} reports crossed in thirty seconds"
    );
    assert!(
        !stalled(&pair),
        "thirty seconds of a pause with its RTCP arriving was reported as a stall"
    );

    // the far end's reports stop as well: that is a stream that stopped
    pair.now += Duration::from_secs(11);
    pair.callee.engine.handle_timeout(pair.now);
    pair.callee.drain(pair.now, false);
    assert!(
        stalled(&pair),
        "nothing arrived at all, and nothing said so"
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
            .capture(&level, Instant::now())
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
        Vec::new(),
        Start {
            identity: StreamIdentity {
                ssrc: 0x5149_5241,
                sequence: 1,
                timestamp: 0,
                seed: 7,
            },
            clock: WallClock::from_unix(now, 1_700_000_000, 0),
            #[cfg(feature = "dtls")]
            handshake: None,
            #[cfg(feature = "ice")]
            ice: None,
            annex_b: false,
            now,
        },
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
            .capture(&samples, Instant::now())
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

/// A burst of loss longer than the jitter buffer's delay is played as
/// silence, not concealment: the buffer runs dry and waits to fill again.
/// The concealer never saw those frames go by, and kept the audio from
/// before them as if the frame after them came straight on. On the lab's
/// 350 + 440 Hz tone, whose period is five frames, a hole of four made the
/// two sides of the join match exactly one frame apart, and the next packet
/// lost was concealed by repeating the frame before it as a one-frame
/// period: it opened on that frame's first sample instead of continuing
/// from its last, a jump the lab's audio gate measured at 7 992 on a tone
/// whose steepest step is 2 998. Every splice into concealment here, over
/// holes of three to six frames and ten phases of the tone, must step no
/// further than the tone itself does.
#[test]
fn a_loss_after_the_buffer_ran_dry_continues_the_audio_and_not_what_came_before_it() {
    concealment_after_a_hole(Playback::Silence);
}

/// The same hole, sent: an RFC 3389 far end fills a pause with comfort
/// noise packets, one per frame here, and the concealer sees none of them
/// either. Its history from before the pause is no nearer the frame after
/// it than it is across a buffer run dry.
#[test]
fn a_loss_after_comfort_noise_continues_the_audio_and_not_what_came_before_it() {
    concealment_after_a_hole(Playback::ComfortNoise);
}

/// A hole of three to six frames in a G.711 tone, played as `hole` — the
/// buffer running dry, or comfort noise the far end sent in the tone's
/// place — then one packet, then one lost: every splice into concealment,
/// over ten phases of the tone, may step no further than the tone does.
fn concealment_after_a_hole(hole_played_as: Playback) {
    let rate = 8_000.0;
    let (low, high) = (
        2.0 * core::f64::consts::PI * 350.0 / rate,
        2.0 * core::f64::consts::PI * 440.0 / rate,
    );
    let amplitude = 4_900.0;
    let steepest = 2.0 * amplitude * ((low / 2.0).sin() + (high / 2.0).sin());
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
    let answer = "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

    let mut splices = 0;
    for hole in 3..=6_usize {
        for step in 0..10_u32 {
            let phase = f64::from(step) * core::f64::consts::TAU / 10.0;
            let now = Instant::now();
            let (ours, theirs) = plan_pair(offer, answer);
            let mut sender = session(&theirs, &ours, now);
            let mut receiver = session(&ours, &theirs, now);
            let mut at = now;
            let mut played = vec![0_i16; 160];
            let mut previous: Option<(Playback, i16)> = None;
            let mut filled = 0;

            for index in 0..60_usize {
                #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
                let samples: Vec<i16> = (index * 160..(index + 1) * 160)
                    .map(|n| {
                        let n = n as f64;
                        (amplitude * ((low * n + phase).sin() + (high * n + 2.0 * phase).sin()))
                            .round() as i16
                    })
                    .collect();
                let datagram = sender
                    .capture(&samples, at)
                    .expect("it encodes")
                    .map(|out| out.payload.to_vec());
                // a hole of `hole` packets, then one packet, then one more lost
                let in_hole = (20..20 + hole).contains(&index);
                let lost = (in_hole && hole_played_as == Playback::Silence) || index == 21 + hole;
                if let Some(mut datagram) = datagram
                    && !lost
                {
                    if in_hole {
                        // the same header, a comfort noise payload type and
                        // a noise level of -70 dBov (RFC 3389 section 3)
                        assert_eq!(datagram[0], 0x80, "a bare twelve-byte header");
                        datagram[1] =
                            (datagram[1] & 0x80) | sipral_media::comfort_noise::PAYLOAD_TYPE;
                        datagram.truncate(12);
                        datagram.push(70);
                    }
                    receiver.receive(
                        &mut datagram,
                        "192.0.2.2:40002".parse().expect("an address"),
                        at,
                    );
                }
                let outcome = receiver.playback(&mut played);
                if outcome == hole_played_as && index > 10 {
                    filled += 1;
                }
                if outcome == Playback::Concealed
                    && let Some((Playback::Packet, last)) = previous
                {
                    splices += 1;
                    let jump = (f64::from(played[0]) - f64::from(last)).abs();
                    assert!(
                        jump <= steepest + 400.0,
                        "a hole of {hole} and phase {phase:.2}: the concealment opened \
                         {jump:.0} away from the last sample played, against a steepest \
                         step of {steepest:.0}"
                    );
                }
                previous = Some((outcome, played[159]));
                at += TICK;
            }
            assert!(
                filled > 0,
                "a hole of {hole} was never played as {hole_played_as:?}"
            );
        }
    }
    assert!(
        splices >= 40,
        "only {splices} splices into concealment were checked"
    );
}

/// A far end that is not this stack answers an offer of G.729 on its static
/// number alone, with no `a=rtpmap`, and says `annexb=yes` although the
/// offer said no: the call still runs on G.729, the tone crosses, and each
/// packet it loses is filled by the codec's own concealment rather than by
/// silence. (A run of losses longer than the buffer's delay reads as the far
/// end having stopped, for every codec alike; that is the jitter buffer's
/// business, not this test's.)
#[test]
fn a_g729_answer_that_says_annexb_yes_still_carries_the_call_through_losses() {
    let now = Instant::now();
    let (ours, theirs) = plan_pair(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\na=fmtp:18 annexb=no\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP 18\r\na=fmtp:18 annexb=yes\r\n",
    );
    let mut sender = session(&theirs, &ours, now);
    let mut receiver = session(&ours, &theirs, now);
    assert_eq!(sender.codec(), Codec::G729);
    assert_eq!(receiver.codec(), Codec::G729);

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut at = now;
    let mut played = vec![0_i16; 160];
    let mut heard = 0;
    let mut concealed = 0;

    for index in 0..60 {
        tone(&mut samples, 8_000, &mut phase);
        let datagram = sender
            .capture(&samples, Instant::now())
            .expect("it encodes")
            .map(|out| out.payload.to_vec());
        let lost = matches!(index, 30 | 38 | 45 | 52);
        if let Some(mut datagram) = datagram
            && !lost
        {
            assert_eq!(datagram.len(), 12 + 20, "two frames behind the header");
            receiver.receive(
                &mut datagram,
                "192.0.2.2:40002".parse().expect("an address"),
                at,
            );
        }
        match receiver.playback(&mut played) {
            Playback::Packet if index > 20 && loudness(&played) > 1_000 => heard += 1,
            Playback::Concealed => {
                concealed += 1;
                assert!(
                    loudness(&played) > 100,
                    "a concealed G.729 frame came out silent, which is a click"
                );
            }
            _ => {}
        }
        at += TICK;
    }

    assert!(heard > 20, "the tone was heard in only {heard} frames");
    assert_eq!(concealed, 4, "each of the four lost packets is concealed");
}

/// A payload type nobody negotiated, and that is not the sibling G.711 law
/// either, is dropped rather than decoded through the wrong table, which is
/// loud distortion rather than quiet. The sibling law itself is
/// `a_peer_that_negotiated_one_g711_law_and_sends_the_other_is_still_heard`,
/// which this test used to cover before that lesson was learned: an offer of
/// nothing but A-law's payload type, 8, is exactly what a peer answering with
/// mu-law and sending A-law would put on the wire, and that is now accepted.
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

    // a well-formed RTP packet carrying a dynamic type that names nothing
    // this call agreed to and is not G.711's other law either
    let mut datagram = vec![0x80, 97, 0, 1, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
    datagram.extend_from_slice(&[0x55; 160]);
    let arrival = receiver.receive(
        &mut datagram,
        "192.0.2.2:40002".parse().expect("an address"),
        now,
    );
    assert_eq!(arrival, Arrival::Dropped(crate::Discard::PayloadType(97)));
}

/// G.711's other law is let through on a G.711 call, but only as the law its
/// static payload type names when nothing in this call's own negotiation
/// names that number otherwise. A far end whose description maps 8 to
/// `telephone-event` beside PCMU is breaking RFC 3551's static table, and
/// its digits still have to arrive as digits rather than be decoded through
/// the A-law table as a burst of noise, with the key never reported.
#[test]
fn a_telephone_event_on_the_other_laws_number_is_still_a_digit() {
    let now = Instant::now();
    let (ours, theirs) = plan_pair(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 telephone-event/8000\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 telephone-event/8000\r\n",
    );
    let mut receiver = session(&ours, &theirs, now);
    assert_eq!(receiver.codec(), Codec::Pcmu);
    assert_eq!(
        receiver.plan().dtmf,
        Some(8),
        "the negotiation put named events on 8"
    );
    let from: SocketAddr = "192.0.2.2:40002".parse().expect("an address");

    // six frames of audio, then a digit's closing packet three times over
    // (RFC 4733 §2.5.1.4): event 5, end bit, volume 10, 800 ticks held
    let packet = |sequence: u16, timestamp: u32, payload_type: u8, payload: &[u8]| {
        let mut datagram = vec![0x80, payload_type];
        datagram.extend_from_slice(&sequence.to_be_bytes());
        datagram.extend_from_slice(&timestamp.to_be_bytes());
        datagram.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        datagram.extend_from_slice(payload);
        datagram
    };
    // the first of them are RFC 3550 A.1's probation, and refused as such
    for index in 0..6_u16 {
        let mut audio = packet(index + 1, u32::from(index) * 160, 0, &[0xff; 160]);
        let _ = receiver.receive(&mut audio, from, now);
    }
    for sequence in 7..=9_u16 {
        let mut event = packet(sequence, 960, 8, &[5, 0x8a, 0x03, 0x20]);
        assert_eq!(receiver.receive(&mut event, from, now), Arrival::Queued);
    }

    let mut played = vec![0_i16; receiver.frame_samples()];
    let mut heard = Vec::new();
    for _ in 0..20 {
        let _ = receiver.playback(&mut played);
        while let Some(event) = receiver.poll_event() {
            if let MediaEvent::DigitReceived { digit, .. } = event {
                heard.push(digit);
            }
        }
    }
    assert_eq!(
        heard,
        vec![Some('5')],
        "the key sent on the negotiated telephone-event number was not heard as one"
    );
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
        Vec::new(),
        Start {
            identity: StreamIdentity {
                ssrc: 1,
                sequence: 1,
                timestamp: 0,
                seed: 7,
            },
            clock: WallClock::from_unix(now, 1_700_000_000, 0),
            #[cfg(feature = "dtls")]
            handshake: None,
            #[cfg(feature = "ice")]
            ice: None,
            annex_b: false,
            now,
        },
    );
    assert_eq!(
        opened.err(),
        Some(MediaError::UnknownPayload {
            payload: 97,
            encoding: "SPEEX".to_owned()
        })
    );
}

/// A G.729 stream opened without Annex B sends every frame of a pause; a
/// re-negotiation that allows it turns the encoder's DTX on, the pause then
/// going out as a SID frame and silence with the next talk spurt marked; and
/// one that refuses it again turns it off.
#[test]
fn a_renegotiation_turns_g729_annex_b_on_and_off() {
    let now = Instant::now();
    let (ours, theirs) = plan_pair(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 40002 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n",
    );
    let plan = plan_of(&ours, &theirs);
    let mut session = MediaSession::open(
        &plan,
        20,
        &MediaConfig::default(),
        Vec::new(),
        Start {
            identity: StreamIdentity {
                ssrc: 1,
                sequence: 1,
                timestamp: 0,
                seed: 7,
            },
            clock: WallClock::from_unix(now, 1_700_000_000, 0),
            #[cfg(feature = "dtls")]
            handshake: None,
            #[cfg(feature = "ice")]
            ice: None,
            annex_b: false,
            now,
        },
    )
    .expect("G.729 is in every build");
    // what each of a run of frames sent: its payload's length and marker
    let mut phase = 0_u32;
    let mut run = |session: &mut MediaSession, talking: bool, frames: usize| {
        let mut samples = [0_i16; 160];
        (0..frames)
            .map(|_| {
                if talking {
                    tone(&mut samples, 8_000, &mut phase);
                } else {
                    samples.fill(0);
                }
                session
                    .capture(&samples, now)
                    .expect("the frame encodes")
                    .map(|datagram| {
                        let payload = datagram.payload;
                        (
                            payload.len() - 12,
                            payload.get(1).is_some_and(|octet| octet & 0x80 != 0),
                        )
                    })
            })
            .collect::<Vec<_>>()
    };
    run(&mut session, true, 20);
    assert!(
        run(&mut session, false, 40)
            .iter()
            .all(|sent| *sent == Some((20, false)))
    );

    session
        .adopt(&plan, Vec::new(), true, now)
        .expect("the same stream");
    run(&mut session, true, 20);
    let pause = run(&mut session, false, 40);
    assert!(
        pause.iter().filter(|sent| sent.is_none()).count() > 30,
        "{pause:?}"
    );
    let again = run(&mut session, true, 10);
    let first = again
        .iter()
        .flatten()
        .next()
        .expect("the tone goes out again");
    assert!(first.1, "and its first packet is marked: {again:?}");

    session
        .adopt(&plan, Vec::new(), false, now)
        .expect("the same stream");
    assert!(
        run(&mut session, false, 40)
            .iter()
            .all(|sent| *sent == Some((20, false)))
    );
}

/// The plan of a call on one codec, `payload` with `rtpmap`, between two
/// hand-written descriptions.
fn one_codec_plan(payload: u8, rtpmap: &str) -> crate::MediaPlan {
    let (ours, theirs) = plan_pair(
        &format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
             m=audio 40000 RTP/AVP {payload}\r\na=rtpmap:{payload} {rtpmap}\r\n"
        ),
        &format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
             m=audio 40002 RTP/AVP {payload}\r\na=rtpmap:{payload} {rtpmap}\r\n"
        ),
    );
    plan_of(&ours, &theirs)
}

/// A stream opened on `plan` with twenty-millisecond frames, Annex B as
/// `annex_b` says.
fn opened(
    plan: &crate::MediaPlan,
    config: &MediaConfig,
    annex_b: bool,
    now: Instant,
) -> MediaSession {
    MediaSession::open(
        plan,
        20,
        config,
        Vec::new(),
        Start {
            identity: StreamIdentity {
                ssrc: 1,
                sequence: 1,
                timestamp: 0,
                seed: 7,
            },
            clock: WallClock::from_unix(now, 1_700_000_000, 0),
            #[cfg(feature = "dtls")]
            handshake: None,
            #[cfg(feature = "ice")]
            ice: None,
            annex_b,
            now,
        },
    )
    .expect("G.729 and PCMU are in every build")
}

/// The facade's own silence suppression stands aside on a G.729 stream whose
/// encoder does Annex B, since the detector has to hear the pause to send
/// its SID frame: with suppression asked for, a pause still starts with a
/// SID frame when Annex B is on — from the start, from a re-negotiation or
/// from a change of codec onto G.729 — and with Annex B off the suppression
/// is what stops the frames, and no SID frame goes out.
#[test]
fn silence_suppression_stands_aside_for_g729_annex_b() {
    let now = Instant::now();
    let plan = one_codec_plan(18, "G729/8000");
    let pcmu = one_codec_plan(0, "PCMU/8000");
    let config = MediaConfig {
        silence_suppression: true,
        ..MediaConfig::default()
    };
    let open = |annex_b: bool| opened(&plan, &config, annex_b, now);
    // the payload lengths a talk spurt and then a pause sent, `None` for a
    // frame that sent nothing
    let spurt_and_pause = |session: &mut MediaSession| {
        let mut samples = [0_i16; 160];
        let mut phase = 0_u32;
        (0..60)
            .map(|frame| {
                if frame < 20 {
                    tone(&mut samples, 8_000, &mut phase);
                } else {
                    samples.fill(0);
                }
                session
                    .capture(&samples, now)
                    .expect("the frame encodes")
                    .map(|datagram| datagram.payload.len() - 12)
            })
            .collect::<Vec<_>>()
    };
    let sid = |sent: &Option<usize>| matches!(sent, Some(2 | 12));

    let mut with_annex_b = open(true);
    let sent = spurt_and_pause(&mut with_annex_b);
    assert!(sent[20..].iter().any(sid), "{sent:?}");

    let suppressed = |sent: &[Option<usize>]| {
        !sent.iter().any(sid)
            && sent
                .get(30..)
                .is_some_and(|rest| rest.iter().all(Option::is_none))
    };
    let sent = spurt_and_pause(&mut open(false));
    assert!(
        suppressed(&sent),
        "the facade suppressed the pause: {sent:?}"
    );

    // a re-negotiation either way, before anything is sent
    let mut turned_on = open(false);
    turned_on
        .adopt(&plan, Vec::new(), true, now)
        .expect("the same stream");
    let sent = spurt_and_pause(&mut turned_on);
    assert!(sent[20..].iter().any(sid), "{sent:?}");
    let mut turned_off = open(true);
    turned_off
        .adopt(&plan, Vec::new(), false, now)
        .expect("the same stream");
    let sent = spurt_and_pause(&mut turned_off);
    assert!(suppressed(&sent), "{sent:?}");

    // and a stream that moves onto G.729 from another codec
    for annex_b in [true, false] {
        let mut moved = opened(&pcmu, &config, false, now);
        moved
            .reformat(&plan, 20, &config, Vec::new(), annex_b, now)
            .expect("onto G.729");
        let sent = spurt_and_pause(&mut moved);
        if annex_b {
            assert!(sent[20..].iter().any(sid), "{sent:?}");
        } else {
            assert!(suppressed(&sent), "{sent:?}");
        }
    }
}

/// A G.729 pause that ends ten milliseconds into a packet's twenty: the
/// packet carries the one frame of speech, stamped ten milliseconds into its
/// time and marked as a talk spurt's first, and the next packet is stamped
/// where it always would have been.
#[test]
fn a_g729_pause_that_ends_inside_a_packet_moves_its_timestamp() {
    let now = Instant::now();
    let mut stream = opened(
        &one_codec_plan(18, "G729/8000"),
        &MediaConfig::default(),
        true,
        now,
    );
    let mut samples = [0_i16; 160];
    let mut phase = 0_u32;
    let mut stamped = Vec::new();
    for frame in 0..80_u32 {
        match frame {
            20..70 => samples.fill(0),
            70 => {
                samples.fill(0);
                let mut late = [0_i16; 80];
                tone(&mut late, 8_000, &mut phase);
                samples[80..].copy_from_slice(&late);
            }
            _ => tone(&mut samples, 8_000, &mut phase),
        }
        if let Some(datagram) = stream.capture(&samples, now).expect("the frame encodes") {
            let packet = datagram.payload;
            let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
            stamped.push((frame, packet.len() - 12, timestamp, packet[1] & 0x80 != 0));
        }
    }
    let first = stamped[0].2;
    let onset = stamped
        .iter()
        .find(|(frame, ..)| *frame == 70)
        .expect("the frame the voice comes back in is sent");
    assert_eq!(
        (onset.1, onset.2.wrapping_sub(first), onset.3),
        (10, 70 * 160 + 80, true),
        "{stamped:?}"
    );
    let next = stamped
        .iter()
        .find(|(frame, ..)| *frame == 71)
        .expect("and the one after it");
    assert_eq!(
        (next.1, next.2.wrapping_sub(first), next.3),
        (20, 71 * 160, false),
        "{stamped:?}"
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
    from.capture(&[1_000_i16; 160], Instant::now())
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
        .adopt(&plan_of(&ours_2, &theirs_2), Vec::new(), false, now)
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
        .adopt(&plan_of(&ours_2, &theirs_2), Vec::new(), false, now)
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
        .adopt(&plan_of(&ours_2, &theirs_2), Vec::new(), false, now)
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
        .adopt(&plan_of(&ours, &theirs), Vec::new(), false, now)
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
        .adopt(&plan_of(&ours_2, &theirs), Vec::new(), false, now)
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
        .adopt(&plan_of(&ours, &theirs_2), Vec::new(), false, now)
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
        .adopt(&plan_of(&ours_32, &theirs_32), Vec::new(), false, now)
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
        if let Some(out) = session.capture(&audio, Instant::now()).expect("it encodes") {
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
        .capture(&[100_i16; 160], Instant::now())
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
    session.capture(&frame, Instant::now()).expect("it encodes");
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
            .capture(&samples, Instant::now())
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
        .reformat(
            &plan_of(&ours_2, &theirs_2),
            20,
            &config,
            Vec::new(),
            false,
            now,
        )
        .expect("the codec is one this build has");
    receiver
        .reformat(
            &plan_of(&theirs_2, &ours_2),
            20,
            &config,
            Vec::new(),
            false,
            now,
        )
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

/// Run both ends' clocks forward a step at a time, moving what each writes to
/// the other, for as long as `span` says.
fn run_for(pair: &mut Pair, span: Duration) {
    let end = pair.now + span;
    while pair.now < end {
        pair.now += Duration::from_millis(10);
        pair.caller.agent.handle_timeout(pair.now);
        pair.callee.agent.handle_timeout(pair.now);
        pair.caller.drain(pair.now, false);
        pair.callee.drain(pair.now, false);
        pair.settle();
    }
}

/// RFC 3261 §14.1's two ranges exist so that two ends whose offers crossed
/// both get their change through: the end that did not generate the Call-ID
/// tries again within two seconds, while the one that did is still waiting.
#[test]
fn two_holds_that_cross_both_go_through() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    pair.caller
        .agent
        .hold(call, pair.now)
        .expect("the caller's hold");
    pair.callee
        .agent
        .hold(remote, pair.now)
        .expect("the callee's hold");
    pair.caller.drain(pair.now, false);
    pair.callee.drain(pair.now, false);
    pair.settle();
    run_for(&mut pair, Duration::from_secs(6));

    let both = crate::Hold {
        local: true,
        remote: true,
    };
    assert_eq!(pair.caller.agent.hold_state(call), Some(both));
    assert_eq!(pair.callee.agent.hold_state(remote), Some(both));
}

/// And a resume pressed at one end while the far end's hold of its own is
/// crossing it: whatever collides, both ends settle where they were asked.
#[test]
fn a_resume_behind_a_crossed_hold_still_arrives() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");

    pair.caller
        .agent
        .hold(call, pair.now)
        .expect("the caller's hold");
    pair.callee
        .agent
        .hold(remote, pair.now)
        .expect("the callee's hold");
    pair.caller.agent.resume(call, pair.now).expect("waits");
    pair.caller.drain(pair.now, false);
    pair.callee.drain(pair.now, false);
    pair.settle();
    run_for(&mut pair, Duration::from_secs(12));

    assert_eq!(
        pair.caller.agent.hold_state(call),
        Some(crate::Hold {
            local: false,
            remote: true
        })
    );
    assert_eq!(
        pair.callee.agent.hold_state(remote),
        Some(crate::Hold {
            local: true,
            remote: false
        })
    );
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

/// 8.4.4: the call a transfer becomes is a call this engine can put audio on,
/// the same way one placed with [`MediaEngine::place`] is — an offer from
/// this engine's own catalogue, and a call the engine now manages.
#[test]
fn a_transfer_taken_through_the_facade_places_a_call_with_media_on_it() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let transferor = pair.connect();
    let transferee = *pair
        .callee
        .calls()
        .first()
        .expect("the callee is in a call");

    // the caller hands the callee to somebody else (RFC 3515)
    pair.caller
        .agent
        .transfer(transferor, &uri("sip:carol@example.com"), pair.now)
        .expect("the REFER goes");
    pair.settle();
    assert!(
        pair.callee
            .heard
            .iter()
            .any(|event| matches!(event, Event::Signalling(UaEvent::TransferRequested { .. }))),
        "the transferee was asked"
    );

    let placed = pair
        .callee
        .engine
        .accept_transfer(
            &mut pair.callee.agent,
            transferee,
            callee_media(),
            OutgoingExtras::default(),
            pair.now,
        )
        .expect("the transfer is taken");
    let written = pair.callee.outbound();
    let invite = written
        .iter()
        .find(|bytes| bytes.starts_with(b"INVITE sip:carol@example.com"))
        .expect("the call the REFER asked for is placed");

    assert!(
        String::from_utf8_lossy(invite).contains("m=audio"),
        "the INVITE a transfer places carries no offer: {}",
        String::from_utf8_lossy(invite)
    );
    assert!(
        pair.callee.engine.call_catalog(placed).is_some(),
        "the engine has never heard of the call the transfer became"
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

// -- 8.2.4: a recording carries no key ---------------------------------------

/// The base64 an `a=crypto` line in a SIP message's body carries, however
/// many session parameters trail it.
///
/// Read with `sipral_core::msg::parse`, the same as the stack's own body
/// lookup, rather than a manual search for the blank line — and then with
/// [`crypto_line`], the same as every other test here that reads one.
fn offered_key(datagram: &[u8]) -> String {
    let mut scratch = ParseScratch::new();
    let message = sipral_core::msg::parse(datagram, &mut scratch, ParseMode::Lenient)
        .expect("a well formed SIP message");
    let description = parse(message.body()).expect("the SDP parses");
    let crypto = crypto_line(&one_stream(&description)).expect("a crypto line");
    crypto
        .key_params
        .strip_prefix("inline:")
        .expect("the key method is inline")
        .split('|')
        .next()
        .expect("a key value")
        .to_owned()
}

/// 8.2.4's whole point, proved rather than read off the code: a recording of
/// a live SRTP call, taken from the caller's own side, does not carry the key
/// the caller's own engine negotiated for it.
///
/// The recorder only ever hears two things — what arrived at `receive`, and
/// the name of what the application did on its own — and the caller's own
/// offer is neither of those: it is written out, not read in. What does
/// arrive is the callee's answer, carrying the callee's own key from the
/// callee's own engine, a different value from a different seed; the second
/// pair of assertions below is there so that a future change collapsing the
/// two seeds back together fails a call in progress, not only a unit test of
/// `draw_key` on its own.
#[test]
fn a_recorded_srtp_call_does_not_carry_the_key_it_negotiated() {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_srtp(SrtpPolicy::Offered);
    let mut pair = Pair::new(catalog);
    let mut recorder =
        Recorder::new([11; 32]).about("an SRTP call, recorded from the caller's side only");

    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());

    recorder.cue("place", pair.now);
    let call = pair
        .caller
        .engine
        .place(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);

    // the same loop `Pair::settle` runs, with the caller's own half of it
    // beside a recorder: what the caller sends is never handed to it, only
    // what arrives at the caller is
    let mut own_key = None;
    for _ in 0..12 {
        let dialled = pair.caller.outbound();
        let answered = pair.callee.outbound();
        if dialled.is_empty() && answered.is_empty() {
            break;
        }
        for datagram in &dialled {
            if own_key.is_none() {
                own_key = Some(offered_key(datagram));
            }
            pair.callee.deliver(datagram, caller_sip(), pair.now);
        }
        for datagram in &answered {
            let input = Input::Datagram {
                transport: UDP,
                remote: callee_sip(),
                local: pair.caller.local,
                data: datagram.as_slice(),
            };
            recorder.arrived(&input, pair.now);
            pair.caller
                .agent
                .receive(input, pair.now)
                .expect("a datagram");
        }
        pair.caller.drain(pair.now, false);
        pair.callee.drain(pair.now, true);
    }

    let own_key = own_key.expect("the caller's own INVITE carried a crypto line");
    let remote = pair.callee.call().expect("the callee knows the call");
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("the caller's media")
            .is_encrypted(),
        "the call this test records was never actually secured"
    );
    assert!(
        pair.callee
            .engine
            .session(remote)
            .expect("the callee's media")
            .is_encrypted()
    );

    let text = recorder.finish().expect("a recording of it").to_text();
    assert!(
        !text.contains(&own_key),
        "the caller's own negotiated key rode along in its own recording: {text}"
    );
}

/// One offer, from a user agent and a media engine built fresh from the two
/// seeds given, and the base64 its `a=crypto` line carries.
fn offered_with_seeds(
    endpoint_seed: [u8; 32],
    media_seed: [u8; 32],
    catalog: CodecCatalog,
    clock: WallClock,
    now: Instant,
) -> String {
    let mut agent = UserAgent::new(EndpointConfig::default(), endpoint_seed).expect("a user agent");
    let mut engine = MediaEngine::new(catalog, MediaConfig::default(), clock, media_seed);
    agent
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: caller_sip(),
                remote: None,
            },
            now,
        )
        .expect("binding a transport");
    let account = agent.add_account(Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri(&format!("sip:alice@{}", caller_sip().ip())),
        UDP,
        callee_sip(),
    ));
    engine
        .place(
            &mut agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            now,
        )
        .expect("the INVITE goes");
    let invite = agent
        .poll_transmit()
        .expect("the INVITE was written")
        .payload
        .to_vec();
    offered_key(&invite)
}

/// The other half of 8.2.4: the media seed, not the endpoint seed, is what a
/// negotiated key follows. Two calls placed from user agents that share one
/// endpoint seed — which is what a replay recording carries in clear — offer
/// two different keys as long as their media seeds differ.
///
/// `key_source_tests::the_media_key_follows_the_media_seed_and_nothing_else`
/// in `engine.rs` already proves this fact at `draw_key`'s own level, with
/// two bare `KeySource`s and no endpoint anywhere; this is the same fact one
/// layer up, through an actual offer and with the endpoint seed literally
/// shared between the two, which is the specific case the plan calls out and
/// that lower-level test does not touch.
#[test]
fn two_engines_sharing_an_endpoint_seed_still_negotiate_different_keys() {
    let now = Instant::now();
    let clock = WallClock::from_unix(now, 1_700_000_000, 0);
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_srtp(SrtpPolicy::Offered);
    let shared_endpoint_seed = [77; 32];

    let first = offered_with_seeds(shared_endpoint_seed, [1; 32], catalog.clone(), clock, now);
    let second = offered_with_seeds(shared_endpoint_seed, [2; 32], catalog, clock, now);

    assert_ne!(
        first, second,
        "the same endpoint seed must not make two different media seeds \
         negotiate the same key"
    );
}

// -- ICE ---------------------------------------------------------------------

/// A pair whose two ends both offer ICE, connected.
#[cfg(feature = "ice")]
fn ice_call() -> (Pair, CallHandle, CallHandle) {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side of the call");
    (pair, call, remote)
}

/// A pair that offers ICE to a peer that does not do it at all — an Asterisk
/// with `ice_support=no`, which is its default.
#[cfg(feature = "ice")]
fn one_sided_ice_call(ours: crate::IcePolicy) -> (Pair, CallHandle, CallHandle) {
    let mine = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(ours);
    let theirs = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::asymmetric(mine, theirs);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side of the call");
    (pair, call, remote)
}

#[cfg(feature = "ice")]
impl Pair {
    /// Run the connectivity checks between the two ends, over the media path
    /// and over nothing else, and say how many datagrams crossed.
    ///
    /// The same three-step shape a real driver needs and `shake_hands`
    /// describes: drain `poll_transmit` to empty, deliver, move the clock,
    /// drain again. A driver that skips the clock is a driver whose calls
    /// never pace a second check, which is what this reproduces if it is got
    /// wrong.
    fn check_paths(&mut self, call: CallHandle, remote: CallHandle) -> usize {
        let mut crossed = 0;
        for _ in 0..64 {
            let mut pending = Vec::new();
            while let Some((_, _, probe)) = self.caller.engine.poll_transmit(self.now) {
                pending.push((probe, true));
            }
            while let Some((_, _, probe)) = self.callee.engine.poll_transmit(self.now) {
                pending.push((probe, false));
            }
            let moved = !pending.is_empty();
            for (mut probe, from_caller) in pending {
                crossed += 1;
                let (mut session, from) = if from_caller {
                    (
                        self.callee.engine.session(remote).expect("media"),
                        caller_media(),
                    )
                } else {
                    (
                        self.caller.engine.session(call).expect("media"),
                        callee_media(),
                    )
                };
                session.receive(&mut probe, from, self.now);
            }
            let chosen = self
                .caller
                .engine
                .session(call)
                .is_some_and(|session| session.ice_path().is_some())
                && self
                    .callee
                    .engine
                    .session(remote)
                    .is_some_and(|session| session.ice_path().is_some());
            if chosen && !moved {
                break;
            }
            self.advance();
            self.caller.engine.handle_timeout(self.now);
            self.callee.engine.handle_timeout(self.now);
            // and drained, because a session's events reach the application
            // through the engine and a test that never asks sees none
            self.caller.drain(self.now, false);
            self.callee.drain(self.now, true);
        }
        crossed
    }
}

#[cfg(feature = "ice")]
#[test]
fn an_offer_that_carries_ice_names_a_candidate_and_asks_to_multiplex() {
    let (pair, _, _) = ice_call();
    let described = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer");
    let offer = one_stream(&described);
    let ufrag = offer
        .attribute("ice-ufrag")
        .and_then(|line| line.value.as_deref())
        .expect("the offer carries a username fragment");
    let pwd = offer
        .attribute("ice-pwd")
        .and_then(|line| line.value.as_deref())
        .expect("the offer carries a password");
    // RFC 8839 §5.4's shape, which is what the peer's agent will check
    assert!((4..=32).contains(&ufrag.len()), "ufrag is {}", ufrag.len());
    assert!((22..=256).contains(&pwd.len()), "pwd is {}", pwd.len());
    let candidates: Vec<&str> = offer
        .attributes
        .iter()
        .filter(|attribute| attribute.name == "candidate")
        .filter_map(|attribute| attribute.value.as_deref())
        .collect();
    assert_eq!(candidates.len(), 1, "one address, one component, one host");
    assert!(
        candidates[0].contains("typ host") && candidates[0].contains("192.0.2.1"),
        "{}",
        candidates[0]
    );
    // N4's consequence: an ICE stream has one component, and asking for
    // multiplexing is what makes that true. The catalogue never said so
    assert!(
        offer.attribute("rtcp-mux").is_some(),
        "an ICE offer has to ask for one port"
    );
    // RFC 8839 §5.5, session-level, and written after `answer()` built the
    // description rather than into the vocabulary that builds it
    assert_eq!(
        described
            .attributes
            .iter()
            .find(|attribute| attribute.name == "ice-pacing")
            .and_then(|attribute| attribute.value.as_deref()),
        Some("50")
    );
}

#[cfg(feature = "ice")]
#[test]
fn two_stacks_check_each_other_and_the_tone_crosses_on_the_pair_they_chose() {
    let (mut pair, call, remote) = ice_call();
    let crossed = pair.check_paths(call, remote);
    assert!(crossed > 0, "nothing was checked");

    // both ends chose, and each chose the other's address
    let ours = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .ice_path()
        .expect("the caller chose a path");
    let theirs = pair
        .callee
        .engine
        .session(remote)
        .expect("media")
        .ice_path()
        .expect("the callee chose a path");
    assert_eq!(ours, (caller_media(), callee_media()));
    assert_eq!(theirs, (callee_media(), caller_media()));

    // and each was told once, which is what an application draws on
    let chosen = pair
        .caller
        .heard
        .iter()
        .filter(|event| {
            matches!(
                event,
                Event::Media {
                    event: MediaEvent::PathChosen { .. },
                    ..
                }
            )
        })
        .count();
    assert_eq!(chosen, 1, "the caller was told {chosen} times");

    // and the audio crosses, which is the whole point of having checked
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(
        loudness(&played) > 4_000,
        "the tone came back at {} through the checked call",
        loudness(&played)
    );
}

/// One PCMU packet as the far end puts it on the wire: RFC 3550 §5.1's
/// header, version 2, payload type 0, and twenty milliseconds of silence.
#[cfg(feature = "ice")]
fn far_end_packet(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0x5eed_0001_u32.to_be_bytes());
    packet.extend_from_slice(&[0xff; 160]);
    packet
}

/// Before either end has chosen a pair, the far end sends on whichever pair
/// its own checks found valid first and moves to a better one as they find
/// it (RFC 8445 §12.1): through this end's relay, say — where every packet
/// arrives from the TURN server — and then straight from its own relayed
/// address. This end receives on any pair (§12.2). RTP's latch closed on the
/// first of the two used to refuse every packet from the second as foreign
/// until the selection reopened it, up to `nomination_wait` later: the lab's
/// relayed call through the C ABI lost a second of the callee's audio that
/// way, every call.
#[cfg(feature = "ice")]
#[test]
fn before_a_pair_is_chosen_the_far_end_is_heard_on_whichever_pair_it_moves_to() {
    let (mut pair, call, _) = ice_call();
    let now = pair.now;
    let mut session = pair.caller.engine.session(call).expect("media");
    assert!(session.ice_path().is_none(), "no pair is chosen yet");
    let through_the_relay: SocketAddr = "198.51.100.9:3478".parse().expect("an address");
    let straight: SocketAddr = "198.51.100.9:49207".parse().expect("an address");

    for sequence in 0..3 {
        let mut packet = far_end_packet(sequence);
        let _ = session.receive(&mut packet, through_the_relay, now);
    }
    let heard: Vec<Arrival> = (3..10)
        .map(|sequence| {
            let mut packet = far_end_packet(sequence);
            session.receive(&mut packet, straight, now)
        })
        .collect();
    assert!(
        heard
            .iter()
            .all(|arrival| matches!(arrival, Arrival::Queued)),
        "the far end's audio on the pair it moved to: {heard:?}"
    );
}

/// From the selection on the latch holds again: once the far end's audio has
/// arrived on the chosen path, a packet from anywhere else is refused as
/// foreign, the same as on a call not using ICE.
#[cfg(feature = "ice")]
#[test]
fn once_a_pair_is_chosen_the_latch_holds_on_it() {
    let (mut pair, call, remote) = ice_call();
    let _ = pair.check_paths(call, remote);
    let now = pair.now;
    let mut session = pair.caller.engine.session(call).expect("media");
    let (_, chosen) = session.ice_path().expect("the caller chose a path");
    for sequence in 0..3 {
        let _ = session.receive(&mut far_end_packet(sequence), chosen, now);
    }
    let elsewhere: SocketAddr = "198.51.100.9:49207".parse().expect("an address");
    assert_eq!(
        session.receive(&mut far_end_packet(3), elsewhere, now),
        Arrival::Dropped(crate::Discard::ForeignAddress)
    );
    assert_eq!(
        session.receive(&mut far_end_packet(4), chosen, now),
        Arrival::Queued
    );
}

/// The lite role keeps what arrives early as the full one does. A full peer
/// answering a lite offer is the controlling end (RFC 8445 §6.1.1) and checks
/// the moment it answers; a check that reaches the lite caller's socket
/// before the 200 does, handed to `MediaEngine::receive_early`, is kept and
/// answered as the caller's session opens, and a copy signed with anything
/// but the caller's password is refused.
#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn a_lite_caller_answers_a_check_that_arrived_before_the_answer() {
    let mine = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Lite);
    let theirs = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::asymmetric(mine, theirs);
    let remote = pair.ring();
    let offer = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer");
    let stream = one_stream(&offer);
    let credential = |name: &str| {
        stream
            .attribute(name)
            .and_then(|line| line.value.clone())
            .expect("the lite offer's credentials")
    };
    let (ufrag, pwd) = (credential("ice-ufrag"), credential("ice-pwd"));
    let check = check_to_lite(&ufrag, &pwd, 3, true);
    let forged = check_to_lite(&ufrag, "notthepasswordthelitecallergaveout", 4, true);
    assert!(
        !pair
            .caller
            .engine
            .receive_early(caller_media(), callee_media(), &forged, pair.now),
        "a check with a broken signature was kept"
    );
    assert!(
        pair.caller
            .engine
            .receive_early(caller_media(), callee_media(), &check, pair.now),
        "the callee's check was not kept for the lite caller"
    );

    pair.callee
        .engine
        .answer(&mut pair.callee.agent, remote, callee_media(), pair.now)
        .expect("the answer goes");
    pair.callee.drain(pair.now, false);
    pair.settle();
    let call = pair.caller.call().expect("the caller's call");
    let mut answers = 0;
    while let Some((from_call, to, datagram)) = pair.caller.engine.poll_transmit(pair.now) {
        if from_call == call
            && to == callee_media()
            && datagram.get(..2) == Some(&[0x01, 0x01][..])
            && datagram.get(8..20) == check.get(8..20)
        {
            answers += 1;
        }
    }
    assert_eq!(answers, 1, "the lite caller's answers to the kept check");
}

#[cfg(feature = "ice")]
#[test]
fn a_peer_that_does_not_do_ice_still_gets_its_audio() {
    // the regression the whole fallback exists to prevent: an Asterisk with
    // `ice_support=no` — its default — used to be a call that worked, and
    // turning ICE on must not turn it into a call with no audio
    let (mut pair, call, remote) = one_sided_ice_call(crate::IcePolicy::Offered);
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .ice_path()
            .is_none(),
        "there is no pair to choose against a peer that described none"
    );
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(
        loudness(&played) > 4_000,
        "the tone came back at {} on a call that fell back",
        loudness(&played)
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_call_that_requires_ice_refuses_the_peer_that_has_none_rather_than_falling_back() {
    let (mut pair, call, _) = one_sided_ice_call(crate::IcePolicy::Required);
    // the media is refused; the call itself is untouched, which is what every
    // other media failure here does too
    assert!(
        pair.caller.engine.session(call).is_none(),
        "a required policy opened a stream on a path nothing checked"
    );
    let failed: Vec<&MediaError> = pair
        .caller
        .heard
        .iter()
        .filter_map(|event| match event {
            Event::Media {
                event: MediaEvent::Failed(error),
                ..
            } => Some(error),
            _ => None,
        })
        .collect();
    assert_eq!(failed, vec![&MediaError::IceRequired]);
}

/// A relay allocated for the caller's media socket, against a TURN server
/// that asks for no credential (`crate::relay::tests::answer`).
#[cfg(feature = "ice")]
fn relay_for_the_caller(pair: &mut Pair) -> crate::Relay {
    use crate::relay::tests::{SERVER, answer};

    let server: SocketAddr = SERVER.parse().expect("an address");
    let mut relays = pair.caller.engine.relays(server, "alice", "correct horse");
    relays.allocate(caller_media(), pair.now);
    while let Some(request) = relays.poll_transmit() {
        let reply = answer(&request.payload).expect("an answer");
        assert!(relays.receive(request.local, request.destination, &reply, pair.now));
    }
    relays.take(caller_media()).expect("the relay")
}

/// A relay allocated for the caller's media socket over a TCP connection to
/// the same server, every answer handed in three octets at a time, as a
/// stream may deliver it.
#[cfg(feature = "ice")]
fn relay_over_tcp_for_the_caller(pair: &mut Pair) -> crate::Relay {
    use crate::relay::tests::{SERVER, answer};

    let server: SocketAddr = SERVER.parse().expect("an address");
    let mut relays = pair
        .caller
        .engine
        .relays(server, "alice", "correct horse")
        .over(crate::TurnTransport::Tcp);
    relays.allocate(caller_media(), pair.now);
    while let Some(request) = relays.poll_transmit() {
        assert_eq!(request.transport, crate::TurnTransport::Tcp);
        let reply = answer(&request.payload).expect("an answer");
        for piece in reply.chunks(3) {
            assert_eq!(
                relays.receive_stream(request.local, piece, pair.now),
                Ok(true)
            );
        }
    }
    let relay = relays.take(caller_media()).expect("the relay");
    assert_eq!(relay.transport(), crate::TurnTransport::Tcp);
    relay
}

/// Place the caller's call with a relay for its media socket, and take it all
/// the way to confirmed.
#[cfg(feature = "ice")]
fn place_with_a_relay(pair: &mut Pair, catalog: CodecCatalog) -> CallHandle {
    let relay = relay_for_the_caller(pair);
    place_with_this_relay(pair, catalog, relay)
}

/// Place the caller's call with `relay` for its media socket, and take it all
/// the way to confirmed.
#[cfg(feature = "ice")]
fn place_with_this_relay(
    pair: &mut Pair,
    catalog: CodecCatalog,
    relay: crate::Relay,
) -> CallHandle {
    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());
    let media = CallMedia::new(catalog, MediaConfig::default()).relay(relay);
    let placed = pair
        .caller
        .engine
        .place_with(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            media,
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    pair.settle();
    placed
}

/// Every Refresh of lifetime zero among a stack's farewells, and the call and
/// address each one went for.
#[cfg(feature = "ice")]
fn relays_given_back(stack: &mut Stack) -> Vec<(CallHandle, SocketAddr)> {
    std::iter::from_fn(|| stack.engine.poll_farewell())
        .filter(|(_, _, payload)| crate::relay::tests::refresh_lifetime(payload) == Some(0))
        .map(|(call, destination, _)| (call, destination))
        .collect()
}

#[cfg(feature = "ice")]
#[test]
fn a_relay_is_offered_beside_the_host_candidate_and_given_back_when_the_call_ends() {
    use crate::relay::tests::{MAPPED, RELAYED, SERVER};

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let call = place_with_a_relay(&mut pair, catalog);
    let remote = pair.callee.call().expect("the callee's side of the call");

    let offer = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer")
        .to_string();
    // RFC 8839 §5.1: a relayed candidate names the mapped address the
    // Allocate returned as its related address
    assert!(
        offer.contains("198.51.100.9 50000 typ relay raddr 203.0.113.7 rport 41002"),
        "{offer}"
    );
    assert!(offer.contains("192.0.2.1 40000 typ host"), "{offer}");
    assert!(offer.contains("typ srflx"), "{offer}");
    // and what the server saw is what a peer without ICE is told, as
    // `CallMedia::public_address` would have put it
    assert!(offer.contains("c=IN IP4 203.0.113.7\r\n"), "{offer}");
    assert!(offer.contains("m=audio 41002 "), "{offer}");
    assert_eq!(MAPPED, "203.0.113.7:41002");
    assert_eq!(RELAYED, "198.51.100.9:50000");

    // the two ends reach each other directly here, so ICE settles on the
    // host pair and the relay carries nothing
    pair.check_paths(call, remote);
    let path = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .ice_path()
        .expect("a path");
    assert_eq!(path, (caller_media(), callee_media()));

    pair.caller
        .agent
        .hangup(call, pair.now)
        .expect("the hangup");
    pair.settle();
    pair.caller.drain(pair.now, false);
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(
        relays_given_back(&mut pair.caller),
        vec![(call, server)],
        "the allocation goes back with the call rather than lapsing"
    );
}

/// Everything the caller wrote for its relay's TCP connection, from the
/// socket it was allocated on to the server it was allocated on.
#[cfg(feature = "ice")]
fn written_on_the_connection(stack: &mut Stack) -> Vec<(CallHandle, Vec<u8>)> {
    let server: SocketAddr = crate::relay::tests::SERVER.parse().expect("an address");
    std::iter::from_fn(|| stack.engine.poll_turn_stream())
        .map(|(call, bytes)| {
            assert_eq!(bytes.transport, crate::TurnTransport::Tcp);
            assert_eq!(bytes.local, caller_media());
            assert_eq!(bytes.destination, server);
            (call, bytes.payload)
        })
        .collect()
}

#[cfg(feature = "ice")]
#[test]
fn a_relay_over_tcp_offers_no_mapping_of_the_connection_and_goes_back_on_it() {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let relay = relay_over_tcp_for_the_caller(&mut pair);
    // what the server saw is where the connection comes from, not the socket
    assert_eq!(relay.mapped(), None);
    let call = place_with_this_relay(&mut pair, catalog, relay);
    let remote = pair.callee.call().expect("the callee's side of the call");
    let offer = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer")
        .to_string();
    assert!(offer.contains("198.51.100.9 50000 typ relay"), "{offer}");
    assert!(!offer.contains("typ srflx"), "{offer}");
    assert!(offer.contains("c=IN IP4 192.0.2.1\r\n"), "{offer}");
    assert!(offer.contains("m=audio 40000 "), "{offer}");

    pair.check_paths(call, remote);
    // the permissions and the channel went on the connection, not as
    // datagrams to the server
    assert!(!written_on_the_connection(&mut pair.caller).is_empty());

    pair.caller
        .agent
        .hangup(call, pair.now)
        .expect("the hangup");
    pair.settle();
    pair.caller.drain(pair.now, false);
    assert_eq!(
        relays_given_back(&mut pair.caller),
        vec![],
        "no datagram gives back an allocation made on a connection"
    );
    let given_back: Vec<_> = written_on_the_connection(&mut pair.caller)
        .into_iter()
        .filter(|(_, bytes)| crate::relay::tests::refresh_lifetime(bytes) == Some(0))
        .map(|(handle, _)| handle)
        .collect();
    assert_eq!(given_back, vec![call]);
}

/// A TURN server the caller reaches over TCP and nothing else, in front of a
/// network that carries no datagram between the two ends: what the caller's
/// connection carries is framed here, the callee is reached from the relayed
/// address, and what the callee sends there goes back on the connection.
#[cfg(feature = "ice")]
#[derive(Default)]
struct TcpTurn {
    from_caller: sipral_nat::turn::StreamFraming,
    channels: Vec<(sipral_nat::turn::ChannelNumber, SocketAddr)>,
    to_caller: Vec<u8>,
    to_callee: Vec<Vec<u8>>,
}

#[cfg(feature = "ice")]
impl TcpTurn {
    fn caller_wrote(&mut self, bytes: &[u8]) {
        self.from_caller.push(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = self.from_caller.next_frame().expect("a well-formed stream") {
            frames.push(frame.to_vec());
        }
        for frame in frames {
            self.frame(&frame);
        }
    }

    fn frame(&mut self, frame: &[u8]) {
        use sipral_nat::stun::{AttributeType, Class, Message};
        use sipral_nat::turn::{ChannelData, ChannelNumber, method};

        if let Ok(channel) = ChannelData::parse_frame(frame) {
            if self
                .channels
                .iter()
                .any(|(number, _)| *number == channel.channel())
            {
                self.to_callee.push(channel.data().to_vec());
            }
            return;
        }
        let message = Message::parse(frame).expect("STUN");
        match (message.class(), message.method()) {
            (Class::Indication, method::SEND) => {
                if let Some(data) = message.find(AttributeType::DATA) {
                    self.to_callee.push(data.to_vec());
                }
            }
            (Class::Request, method::CHANNEL_BIND) => {
                let number = message
                    .find(AttributeType::CHANNEL_NUMBER)
                    .and_then(|value| value.get(..2))
                    .and_then(|bytes| ChannelNumber::new(u16::from_be_bytes([bytes[0], bytes[1]])))
                    .expect("a channel number");
                let peer = message
                    .find(AttributeType::XOR_PEER_ADDRESS)
                    .map(xor_v4)
                    .expect("a peer");
                self.channels.push((number, peer));
                self.answer(frame);
            }
            (Class::Request, _) => self.answer(frame),
            _ => {}
        }
    }

    fn answer(&mut self, request: &[u8]) {
        let reply = crate::relay::tests::answer(request).expect("an answer");
        self.to_caller.extend_from_slice(&reply);
    }

    /// A datagram the callee sent to the relayed address: a channel message
    /// once one is bound to the callee, padded for the stream (RFC 8656
    /// §12.5), and a Data indication before.
    fn callee_sent(&mut self, datagram: &[u8]) {
        use sipral_nat::stun::{AttributeType, Class, MessageBuilder, TransactionId};
        use sipral_nat::turn::{ChannelData, Transport, method};

        if let Some((number, _)) = self
            .channels
            .iter()
            .find(|(_, peer)| *peer == callee_media())
        {
            ChannelData::encode(*number, datagram, Transport::Tcp, &mut self.to_caller)
                .expect("fits");
            return;
        }
        let mut builder =
            MessageBuilder::new(Class::Indication, method::DATA, TransactionId::new([7; 12]));
        builder
            .add_xor_address(AttributeType::XOR_PEER_ADDRESS, callee_media())
            .expect("fits");
        builder.add(AttributeType::DATA, datagram).expect("fits");
        self.to_caller.extend_from_slice(&builder.finish());
    }
}

/// An IPv4 XOR-PEER-ADDRESS (RFC 8489 §14.2).
#[cfg(feature = "ice")]
fn xor_v4(value: &[u8]) -> SocketAddr {
    let cookie = sipral_nat::stun::MAGIC_COOKIE.to_be_bytes();
    let port = u16::from_be_bytes([value[2] ^ cookie[0], value[3] ^ cookie[1]]);
    let ip = std::net::Ipv4Addr::new(
        value[4] ^ cookie[0],
        value[5] ^ cookie[1],
        value[6] ^ cookie[2],
        value[7] ^ cookie[3],
    );
    SocketAddr::from((ip, port))
}

#[cfg(feature = "ice")]
impl Pair {
    /// Run the connectivity checks with no datagram crossing between the
    /// two ends, the caller's relay over TCP the only path: the caller's
    /// connection carried to `turn` and back, and what the callee sends to
    /// the relayed address carried there.
    fn check_paths_through(&mut self, turn: &mut TcpTurn, call: CallHandle, remote: CallHandle) {
        let relayed: SocketAddr = crate::relay::tests::RELAYED.parse().expect("an address");
        for _ in 0..400 {
            let mut moved = false;
            let server: SocketAddr = crate::relay::tests::SERVER.parse().expect("an address");
            while let Some((_, destination, _)) = self.caller.engine.poll_transmit(self.now) {
                assert_ne!(
                    destination, server,
                    "a datagram to a server reached over TCP"
                );
                moved = true;
            }
            for (_, bytes) in written_on_the_connection(&mut self.caller) {
                turn.caller_wrote(&bytes);
                moved = true;
            }
            while let Some((_, destination, datagram)) = self.callee.engine.poll_transmit(self.now)
            {
                if destination == relayed {
                    turn.callee_sent(&datagram);
                }
                moved = true;
            }
            for mut datagram in std::mem::take(&mut turn.to_callee) {
                let mut session = self.callee.engine.session(remote).expect("media");
                session.receive(&mut datagram, relayed, self.now);
                moved = true;
            }
            let bytes = std::mem::take(&mut turn.to_caller);
            if !bytes.is_empty() {
                // cut where no message ends, as a read off a socket may be
                let (first, second) = bytes.split_at(bytes.len() / 2 + 1);
                for piece in [first, second] {
                    assert_eq!(
                        self.caller
                            .engine
                            .receive_stream(caller_media(), piece, self.now),
                        Ok(true)
                    );
                }
                moved = true;
            }
            let chosen = self
                .caller
                .engine
                .session(call)
                .is_some_and(|session| session.ice_path().is_some())
                && self
                    .callee
                    .engine
                    .session(remote)
                    .is_some_and(|session| session.ice_path().is_some());
            if chosen && !moved {
                return;
            }
            self.advance();
            self.caller.engine.handle_timeout(self.now);
            self.callee.engine.handle_timeout(self.now);
            self.caller.drain(self.now, false);
            self.callee.drain(self.now, true);
        }
        panic!("no path through the relay");
    }
}

#[cfg(feature = "ice")]
#[test]
fn a_call_whose_only_path_is_a_relay_over_tcp_carries_audio_both_ways() {
    use crate::relay::tests::{RELAYED, SERVER};

    let server: SocketAddr = SERVER.parse().expect("an address");
    let relayed: SocketAddr = RELAYED.parse().expect("an address");
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let relay = relay_over_tcp_for_the_caller(&mut pair);
    let call = place_with_this_relay(&mut pair, catalog, relay);
    let remote = pair.callee.call().expect("the callee's side of the call");
    let mut turn = TcpTurn::default();
    pair.check_paths_through(&mut turn, call, remote);
    let path = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .ice_path()
        .expect("a path");
    assert_eq!(path, (relayed, callee_media()));

    // the caller's audio leaves on the connection, and the callee hears it
    // from the relayed address: three frames, since a new source is on
    // probation for its first (RFC 3550 §6.2.1)
    let silence = [0_i16; 160];
    let mut arrivals = Vec::new();
    for _ in 0..3 {
        pair.advance();
        let sent = {
            let mut session = pair.caller.engine.session(call).expect("media");
            let datagram = session
                .capture(&silence, pair.now)
                .expect("a frame")
                .expect("a route");
            assert_eq!(datagram.transport, crate::TurnTransport::Tcp);
            assert_eq!(datagram.destination, server);
            datagram.payload.to_vec()
        };
        turn.caller_wrote(&sent);
        let mut heard = turn.to_callee.pop().expect("relayed to the callee");
        arrivals.push(
            pair.callee
                .engine
                .session(remote)
                .expect("media")
                .receive(&mut heard, relayed, pair.now),
        );
    }
    assert_eq!(
        arrivals.last(),
        Some(&crate::Arrival::Queued),
        "{arrivals:?}"
    );

    // and the callee's comes back on it, padded, every read cut short of a
    // whole message
    let before = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .statistics(pair.now)
        .quality
        .received;
    for _ in 0..3 {
        pair.advance();
        let answered = {
            let mut session = pair.callee.engine.session(remote).expect("media");
            let datagram = session
                .capture(&silence, pair.now)
                .expect("a frame")
                .expect("a route");
            assert_eq!(datagram.destination, relayed);
            datagram.payload.to_vec()
        };
        turn.callee_sent(&answered);
    }
    let bytes = std::mem::take(&mut turn.to_caller);
    assert_eq!(bytes.len() % 4, 0, "padded to whole words");
    for piece in bytes.chunks(5) {
        assert_eq!(
            pair.caller
                .engine
                .receive_stream(caller_media(), piece, pair.now),
            Ok(true)
        );
    }
    let after = pair
        .caller
        .engine
        .session(call)
        .expect("media")
        .statistics(pair.now)
        .quality
        .received;
    assert!(
        after > before,
        "the caller heard the callee: {before} then {after}"
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_closed_connection_takes_the_relay_and_the_path_through_it() {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let relay = relay_over_tcp_for_the_caller(&mut pair);
    let call = place_with_this_relay(&mut pair, catalog, relay);
    let remote = pair.callee.call().expect("the callee's side of the call");
    let mut turn = TcpTurn::default();
    pair.check_paths_through(&mut turn, call, remote);

    pair.caller.engine.stream_closed(caller_media(), pair.now);
    assert_eq!(
        pair.caller
            .engine
            .receive_stream(caller_media(), &[0x40, 0, 0, 0], pair.now),
        Ok(false),
        "nothing runs over a connection that closed"
    );
    // consent on the pair through it runs out, and the call hears so
    let mut lost = false;
    for _ in 0..(40_000 / TICK.as_millis()) {
        pair.advance();
        pair.caller.engine.handle_timeout(pair.now);
        pair.caller.drain(pair.now, false);
        while pair.caller.engine.poll_transmit(pair.now).is_some() {}
        assert!(
            written_on_the_connection(&mut pair.caller).is_empty(),
            "written on a connection that closed"
        );
        lost = pair.caller.heard.iter().any(|event| {
            matches!(
                event,
                Event::Media {
                    event: MediaEvent::Failed(MediaError::IcePathLost),
                    ..
                }
            )
        });
        if lost {
            break;
        }
    }
    assert!(lost, "the path through the lost relay was reported gone");
}

/// Place the caller's call with every codec the default catalogue offers,
/// SRTP keyed under `srtp`, and ICE with every candidate the facade gathers
/// (host, server-reflexive and relayed), and say what became of the INVITE
/// on the datagram transport: `Ok` with its bytes when it went, `Err` with
/// the size §18.1.1 refused it at when it did not.
#[cfg(all(feature = "ice", feature = "dtls", feature = "opus"))]
fn invite_with_every_candidate(srtp: SrtpPolicy) -> Result<Vec<u8>, usize> {
    use sipral_core::diag::Reason;
    use sipral_core::endpoint::SendError;

    let catalog = CodecCatalog::new()
        .with_srtp(srtp)
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let account = pair.caller.account("alice", callee_sip());
    let relay = relay_for_the_caller(&mut pair);
    let media = CallMedia::new(catalog, MediaConfig::default()).relay(relay);
    let placed = pair.caller.engine.place_with(
        &mut pair.caller.agent,
        account,
        OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
        caller_media(),
        media,
        pair.now,
    );
    let invite = pair
        .caller
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "));
    match placed {
        Ok(_) => Ok(invite.expect("an INVITE on the datagram transport")),
        Err(MediaError::Signalling(crate::UaError::Send(SendError::NeedsStreamTransport))) => {
            assert!(invite.is_none(), "refused, and sent anyway");
            let endpoint = pair.caller.agent.endpoint();
            let calls: Vec<_> = endpoint.recorded_calls().cloned().collect();
            let measure = calls
                .iter()
                .filter_map(|call| endpoint.call_record(call))
                .flat_map(sipral_core::diag::Record::decisions)
                .find(|decision| decision.reason == Reason::TransportRefusedBySize)
                .and_then(|decision| decision.measure)
                .expect("the refusal is in the record, with its size");
            assert_eq!(measure.limit, 1300);
            Err(measure.size)
        }
        Err(other) => panic!("the call was not placed: {other:?}"),
    }
}

/// `docs/06-nat.md`'s budget, measured on the INVITE this stack actually
/// writes rather than argued: every codec the default catalogue offers,
/// SRTP, ICE with every candidate the facade gathers, and the headers every
/// INVITE carries, against the 1300 bytes RFC 3261 §18.1.1 lets a request
/// take over a datagram. Neither keying fits: SDES offers two `a=crypto`
/// lines and DTLS-SRTP a fingerprint, and with three candidates either
/// INVITE is past the floor, so the endpoint refuses it the datagram and
/// asks for a stream rather than send something the path would fragment.
/// The sizes are the ones the endpoint wrote in the call's record when it
/// refused. The page quotes both numbers, and the bounds here keep either
/// from moving far without the page being read again.
#[cfg(all(feature = "ice", feature = "dtls", feature = "opus"))]
#[test]
fn an_invite_with_every_candidate_is_measured_against_the_datagram_floor() {
    let sdes = invite_with_every_candidate(SrtpPolicy::Offered)
        .expect_err("SDES with every candidate needs a stream");
    assert!((1301..=1400).contains(&sdes), "{sdes} bytes with SDES");

    let dtls = invite_with_every_candidate(SrtpPolicy::DtlsOffered)
        .expect_err("DTLS-SRTP with every candidate needs a stream");
    assert!((1301..=1400).contains(&dtls), "{dtls} bytes with DTLS-SRTP");
}

#[cfg(feature = "ice")]
#[test]
fn a_relay_goes_back_when_the_call_ends_before_it_was_answered() {
    use crate::relay::tests::SERVER;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());
    let relay = relay_for_the_caller(&mut pair);
    let call = pair
        .caller
        .engine
        .place_with(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            CallMedia::new(catalog, MediaConfig::default()).relay(relay),
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    for datagram in pair.caller.outbound() {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, false);
    assert!(pair.callee.call().is_some(), "the callee is ringing");
    let server: SocketAddr = SERVER.parse().expect("an address");
    // the agent waiting with the allocation holds the credential, and a
    // `Debug` of the engine around it prints none of it
    let printed = format!("{:?}", pair.caller.engine);
    assert!(!printed.contains("correct horse"), "{printed}");

    // a phone that rings on: the agent holding the relay keeps the NAT
    // binding towards the server alive though no session has opened
    let due = pair
        .caller
        .engine
        .poll_timeout()
        .expect("the waiting agent has a deadline");
    pair.now = due;
    pair.caller.engine.handle_timeout(pair.now);
    let sent: Vec<_> = std::iter::from_fn(|| pair.caller.engine.poll_transmit(pair.now)).collect();
    assert!(
        sent.iter()
            .any(|(from, to, _)| *from == call && *to == server),
        "{sent:?}"
    );

    // and the caller gives up before anyone answers
    pair.caller
        .agent
        .hangup(call, pair.now)
        .expect("the CANCEL");
    pair.caller.drain(pair.now, false);
    pair.settle();
    pair.caller.drain(pair.now, false);
    assert_eq!(
        relays_given_back(&mut pair.caller),
        vec![(call, server)],
        "a call that never opened its session still gives its relay back"
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_relay_a_call_without_ice_cannot_use_goes_back_at_once() {
    use crate::relay::tests::SERVER;

    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog.clone());
    let call = place_with_a_relay(&mut pair, catalog);
    let offer = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer")
        .to_string();
    assert!(!offer.contains("a=candidate"), "{offer}");
    assert!(offer.contains("c=IN IP4 203.0.113.7\r\n"), "{offer}");
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(relays_given_back(&mut pair.caller), vec![(call, server)]);
}

/// A lite end has host candidates only (RFC 8445 §5.2) and runs no agent
/// that could hold an allocation: the relay goes back as the call is placed.
#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn a_relay_a_lite_end_cannot_use_goes_back_at_once() {
    use crate::relay::tests::SERVER;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Lite);
    let mut pair = Pair::new(catalog.clone());
    let call = place_with_a_relay(&mut pair, catalog);
    let offer = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer")
        .to_string();
    assert!(offer.contains("a=ice-lite"), "{offer}");
    assert!(!offer.contains("typ relay"), "{offer}");
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(relays_given_back(&mut pair.caller), vec![(call, server)]);
}

#[cfg(feature = "ice")]
#[test]
fn a_relay_goes_back_when_the_peer_answers_without_ice() {
    use crate::relay::tests::SERVER;

    let mine = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let theirs = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::asymmetric(mine.clone(), theirs);
    let call = place_with_a_relay(&mut pair, mine);
    // the fallback: a session on `c=`/`m=` and symmetric RTP, and no agent
    // to keep the allocation for
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .ice_path()
            .is_none()
    );
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(relays_given_back(&mut pair.caller), vec![(call, server)]);
}

/// Relays on the test's TURN server with an allocation for `media`, already
/// answered, waiting to be taken.
#[cfg(feature = "ice")]
fn relays_with_one_for(stack: &mut Stack, media: SocketAddr, now: Instant) -> crate::Relays {
    use crate::relay::tests::{SERVER, answer};

    let server: SocketAddr = SERVER.parse().expect("an address");
    let mut relays = stack.engine.relays(server, "alice", "correct horse");
    relays.allocate(media, now);
    while let Some(request) = relays.poll_transmit() {
        let reply = answer(&request.payload).expect("an answer");
        assert!(relays.receive(request.local, request.destination, &reply, now));
    }
    while relays.poll_event().is_some() {}
    relays
}

#[cfg(feature = "ice")]
#[test]
fn a_relay_handed_to_a_call_the_user_agent_refuses_comes_back_whole() {
    use crate::relay::tests::RELAYED;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    // an account of the other stack's, which this one's user agent has
    // never heard of
    let unknown = pair.callee.account("bob", caller_sip());
    let mut relays = relays_with_one_for(&mut pair.caller, caller_media(), pair.now);
    let relay = relays.take(caller_media()).expect("the relay");
    let refused = pair.caller.engine.place_with(
        &mut pair.caller.agent,
        unknown,
        OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
        caller_media(),
        CallMedia::new(catalog.clone(), MediaConfig::default()).relay(relay),
        pair.now,
    );
    assert!(refused.is_err(), "{refused:?}");
    assert!(pair.caller.outbound().is_empty(), "no INVITE left");
    assert!(
        pair.caller.engine.poll_farewell().is_none(),
        "nothing to give back to the server: the relay is still good"
    );
    let back = pair
        .caller
        .engine
        .poll_returned_relay()
        .expect("the relay comes back from the refusal");
    assert!(pair.caller.engine.poll_returned_relay().is_none());
    assert_eq!(back.local(), caller_media());
    assert_eq!(back.relayed(), Some(RELAYED.parse().expect("an address")));

    // put back on its socket, it is the next call's there
    relays.put_back(back, pair.now);
    assert!(relays.poll_transmit().is_none(), "nothing deleted it");
    let account = pair.caller.account("alice", callee_sip());
    let relay = relays.take(caller_media()).expect("kept for the socket");
    pair.caller
        .engine
        .place_with(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            CallMedia::new(catalog, MediaConfig::default()).relay(relay),
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    for datagram in pair.caller.outbound() {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, false);
    let offer = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer")
        .to_string();
    assert!(
        offer.contains("198.51.100.9 50000 typ relay"),
        "the relay was lost to the refusal: {offer}"
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_relay_handed_to_a_ring_refused_before_it_describes_anything_comes_back() {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let incoming = pair.ring();
    let mut relays = relays_with_one_for(&mut pair.callee, callee_media(), pair.now);
    // a call of the callee's own user agent the engine never described
    let carol = pair.callee.account("carol", caller_sip());
    let stranger = pair
        .callee
        .agent
        .call(
            carol,
            &OutgoingCall::new(uri("sip:alice@example.com")).to_address(UDP, caller_sip()),
            pair.now,
        )
        .expect("a call the engine knows nothing of");
    let relay = relays.take(callee_media()).expect("the relay");
    let refused = pair.callee.engine.ring_with(
        &mut pair.callee.agent,
        stranger,
        callee_media(),
        CallMedia::new(catalog.clone(), MediaConfig::default()).relay(relay),
        pair.now,
    );
    assert_eq!(refused, Err(MediaError::NoSuchCall));
    let back = pair
        .callee
        .engine
        .poll_returned_relay()
        .expect("the relay comes back from the refusal");
    assert_eq!(back.local(), callee_media());

    // and a second ring on a call already rung refuses the same way
    relays.put_back(back, pair.now);
    let relay = relays.take(callee_media()).expect("kept for the socket");
    pair.callee
        .engine
        .ring_with(
            &mut pair.callee.agent,
            incoming,
            callee_media(),
            CallMedia::new(catalog.clone(), MediaConfig::default()).relay(relay),
            pair.now,
        )
        .expect("the 183 goes");
    let other: SocketAddr = "192.0.2.2:40010".parse().expect("an address");
    let mut others = relays_with_one_for(&mut pair.callee, other, pair.now);
    let second = others.take(other).expect("a second relay");
    let refused = pair.callee.engine.ring_with(
        &mut pair.callee.agent,
        incoming,
        other,
        CallMedia::new(catalog, MediaConfig::default()).relay(second),
        pair.now,
    );
    assert!(refused.is_err(), "{refused:?}");
    let back = pair
        .callee
        .engine
        .poll_returned_relay()
        .expect("the second relay comes back");
    assert_eq!(back.local(), other);
    assert!(
        relays_given_back(&mut pair.callee).is_empty(),
        "the call's own relay is still its own, and the refused one was not deleted"
    );
}

/// The 200 OK of a call rung with media carries the 183's description, so a
/// relay handed to the answer was named by nothing that left: it comes back
/// whole, as a refused description's does, rather than being deleted.
#[cfg(feature = "ice")]
#[test]
fn a_relay_handed_to_the_answer_of_a_call_rung_with_media_comes_back_whole() {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let incoming = pair.ring();
    let mut relays = relays_with_one_for(&mut pair.callee, callee_media(), pair.now);
    let relay = relays.take(callee_media()).expect("the relay");
    pair.callee
        .engine
        .ring_with(
            &mut pair.callee.agent,
            incoming,
            callee_media(),
            CallMedia::new(catalog.clone(), MediaConfig::default()).relay(relay),
            pair.now,
        )
        .expect("the 183 goes");
    pair.callee.drain(pair.now, false);
    let other: SocketAddr = "192.0.2.2:40010".parse().expect("an address");
    let mut others = relays_with_one_for(&mut pair.callee, other, pair.now);
    let second = others.take(other).expect("a second relay");
    pair.callee
        .engine
        .answer_with(
            &mut pair.callee.agent,
            incoming,
            other,
            CallMedia::new(catalog, MediaConfig::default()).relay(second),
            pair.now,
        )
        .expect("the 200 goes");
    pair.callee.drain(pair.now, false);
    assert!(
        relays_given_back(&mut pair.callee).is_empty(),
        "a relay nothing named was deleted rather than handed back"
    );
    let back = pair
        .callee
        .engine
        .poll_returned_relay()
        .expect("the second relay comes back from the answer");
    assert_eq!(back.local(), other);
    assert!(pair.callee.engine.poll_returned_relay().is_none());

    // still live: kept for its socket, nothing deleted it
    others.put_back(back, pair.now);
    assert!(others.poll_transmit().is_none());
    assert!(others.take(other).is_some(), "kept for the socket");
}

/// A phone that rings for longer than the allocation's lifetime less a
/// minute: the agent waiting with the relay refreshes it, and the answer to
/// that refresh has a way in before the session opens.
#[cfg(feature = "ice")]
#[test]
fn a_relay_outlives_a_ring_longer_than_its_lifetime() {
    use crate::relay::tests::{SERVER, answer};
    use sipral_nat::stun::{Class, Message};
    use sipral_nat::turn::method;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());
    let mut relays = relays_with_one_for(&mut pair.caller, caller_media(), pair.now);
    let relay = relays.take(caller_media()).expect("the relay");
    let call = pair
        .caller
        .engine
        .place_with(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            CallMedia::new(catalog, MediaConfig::default()).relay(relay),
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    for datagram in pair.caller.outbound() {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, false);

    let server: SocketAddr = SERVER.parse().expect("an address");
    let start = pair.now;
    let mut refreshed = 0;
    while pair.now < start + Duration::from_secs(700) {
        let due = pair
            .caller
            .engine
            .poll_timeout()
            .expect("the waiting agent has a deadline");
        pair.now = due.max(pair.now);
        pair.caller.engine.handle_timeout(pair.now);
        while let Some((from, datagram)) = pair.caller.engine.poll_waiting_transmit() {
            assert_eq!(from, call);
            assert_eq!(datagram.local, caller_media());
            assert_eq!(datagram.destination, server);
            let Some(reply) = answer(&datagram.payload) else {
                continue;
            };
            let request = Message::parse(&datagram.payload).expect("STUN");
            if request.class() == Class::Request && request.method() == method::REFRESH {
                refreshed += 1;
            }
            assert!(
                pair.caller
                    .engine
                    .receive_waiting(caller_media(), server, &reply, pair.now),
                "the server's answer reaches the waiting agent"
            );
        }
    }
    assert!(refreshed >= 1, "the allocation was refreshed while it rang");

    // the relay is alive eleven minutes in, and goes back with the call
    pair.caller
        .agent
        .hangup(call, pair.now)
        .expect("the CANCEL");
    pair.caller.drain(pair.now, false);
    pair.settle();
    pair.caller.drain(pair.now, false);
    assert_eq!(
        relays_given_back(&mut pair.caller),
        vec![(call, server)],
        "a relay lost to an unanswered refresh has nothing to give back"
    );
}

/// The 2xx of the callee, as a second phone a proxy forked the INVITE to
/// would have sent it: the same answer, from a dialog of its own.
fn from_another_branch(response: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(response.to_vec()).expect("text");
    let mut lines: Vec<String> = Vec::new();
    for line in text.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if (lower.starts_with("to:") || lower.starts_with("t:"))
            && let Some(at) = lower.find(";tag=")
        {
            lines.push(format!("{};tag=secondphone", &line[..at]));
        } else {
            lines.push(line.to_owned());
        }
    }
    lines.join("\r\n").into_bytes()
}

/// A call placed with a relay, rung plainly by the callee (a 180 with no
/// description, naming the first dialog), and the callee's 2xx held back.
#[cfg(feature = "ice")]
fn rung_with_a_relay(pair: &mut Pair, forks: crate::ForkPolicy) -> (CallHandle, Vec<u8>) {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());
    let relay = relay_for_the_caller(pair);
    let call = pair
        .caller
        .engine
        .place_with(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com"))
                .to_address(UDP, callee_sip())
                .forks(forks),
            caller_media(),
            CallMedia::new(catalog, MediaConfig::default()).relay(relay),
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    for datagram in pair.caller.outbound() {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, false);
    let incoming = pair.callee.call().expect("the callee heard the INVITE");
    pair.callee
        .agent
        .ring(incoming, None, pair.now)
        .expect("a 180");
    for datagram in pair.callee.outbound() {
        pair.caller.deliver(&datagram, callee_sip(), pair.now);
    }
    pair.caller.drain(pair.now, false);
    pair.callee
        .engine
        .answer(&mut pair.callee.agent, incoming, callee_media(), pair.now)
        .expect("the 200 goes");
    let answered = pair
        .callee
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"SIP/2.0 200"))
        .expect("the 2xx");
    (call, answered)
}

/// What left for the TURN server from a call's session, as the engine
/// hands it out.
#[cfg(feature = "ice")]
fn sent_to_the_server(stack: &mut Stack, now: Instant) -> Vec<CallHandle> {
    let server: SocketAddr = crate::relay::tests::SERVER.parse().expect("an address");
    std::iter::from_fn(|| stack.engine.poll_transmit(now))
        .filter(|(_, destination, _)| *destination == server)
        .map(|(call, _, _)| call)
        .collect()
}

/// What left for the TURN server from the caller's sessions over the next
/// two seconds — checks from the relayed candidate, and permissions and
/// their retransmissions — with the clock moved as a driver moves it.
#[cfg(feature = "ice")]
fn sent_to_the_server_over(pair: &mut Pair) -> Vec<CallHandle> {
    let mut sent = Vec::new();
    for _ in 0..100 {
        pair.advance();
        pair.caller.engine.handle_timeout(pair.now);
        sent.extend(sent_to_the_server(&mut pair.caller, pair.now));
    }
    sent
}

#[cfg(feature = "ice")]
#[test]
fn a_forked_branch_answered_and_kept_takes_the_relay_its_offer_named() {
    use crate::relay::tests::SERVER;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog);
    let (call, answered) = rung_with_a_relay(&mut pair, crate::ForkPolicy::KeepAll);
    // the second phone picks up while the first still rings
    pair.caller
        .deliver(&from_another_branch(&answered), callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    let sibling = pair
        .caller
        .heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::CallForked { sibling, .. }) => Some(*sibling),
            _ => None,
        })
        .expect("the 2xx came from a second dialog");
    assert!(pair.caller.engine.session(sibling).is_some(), "media");
    // its agent holds the allocation: the permission for the peer's
    // candidates goes to the TURN server, for that branch
    let sent = sent_to_the_server(&mut pair.caller, pair.now);
    assert!(
        sent.contains(&sibling),
        "the branch that was answered has no relay: {sent:?}"
    );
    assert!(!sent.contains(&call), "{sent:?}");

    // when it ends, the relay does not go back to the server: the first
    // branch, still ringing, holds it too — under KeepAll it may yet
    // answer, and its session will open on the relay the offer named
    pair.caller
        .agent
        .hangup(sibling, pair.now)
        .expect("the BYE");
    pair.caller.drain(pair.now, false);
    assert!(
        relays_given_back(&mut pair.caller).is_empty(),
        "the relay went back while a branch that can use it still rings"
    );
    // it waits with the first branch, keeping the NAT binding towards the
    // server open while that phone rings on
    let server: SocketAddr = SERVER.parse().expect("an address");
    let start = pair.now;
    let mut kept_alive = Vec::new();
    while pair.now < start + Duration::from_secs(20) {
        pair.advance();
        pair.caller.engine.handle_timeout(pair.now);
        while let Some((holder, datagram)) = pair.caller.engine.poll_waiting_transmit() {
            if datagram.destination == server {
                kept_alive.push(holder);
            }
        }
    }
    assert!(
        kept_alive.contains(&call),
        "the ringing branch does not hold the relay: {kept_alive:?}"
    );
}

/// A 2xx rewritten as the 183 the same phone would have sent before it: the
/// same dialog and the same description, as early media.
#[cfg(feature = "ice")]
fn as_early_media(response: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(response.to_vec()).expect("text");
    text.replacen("SIP/2.0 200 OK", "SIP/2.0 183 Session Progress", 1)
        .into_bytes()
}

#[cfg(feature = "ice")]
#[test]
fn the_branch_kept_after_early_media_on_another_keeps_the_relay_the_other_lets_go_of() {
    use crate::relay::tests::SERVER;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog);
    let (call, answered) = rung_with_a_relay(&mut pair, crate::ForkPolicy::KeepFirst);
    // the first phone plays early media, and its session runs on the relay
    pair.caller
        .deliver(&as_early_media(&answered), callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    assert!(pair.caller.engine.session(call).is_some(), "early media");
    assert!(
        sent_to_the_server(&mut pair.caller, pair.now).contains(&call),
        "the early session has no relay"
    );

    // a second phone answers: kept, and the first ends with ForkLost
    pair.caller
        .deliver(&from_another_branch(&answered), callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    let sibling = pair
        .caller
        .heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::CallForked { sibling, .. }) => Some(*sibling),
            _ => None,
        })
        .expect("the 2xx came from a second dialog");
    assert!(
        pair.caller.heard.iter().any(|event| matches!(
            event,
            Event::Signalling(UaEvent::CallEnded {
                call: ended,
                reason: crate::CallEndReason::ForkLost,
                ..
            }) if *ended == call
        )),
        "the first branch was not let go"
    );
    assert!(pair.caller.engine.session(sibling).is_some(), "media");
    assert!(
        relays_given_back(&mut pair.caller).is_empty(),
        "the relay went back with the branch that lost"
    );
    // the kept branch's agent held it beside the other's from its session
    // on, and holds it alone now: what it checks and asks for on the relay
    // goes to the TURN server
    let sent = sent_to_the_server_over(&mut pair);
    assert!(
        sent.contains(&sibling),
        "the branch kept has no relay: {sent:?}"
    );

    pair.caller
        .agent
        .hangup(sibling, pair.now)
        .expect("the BYE");
    pair.caller.drain(pair.now, false);
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(relays_given_back(&mut pair.caller), vec![(sibling, server)]);
}

#[cfg(feature = "ice")]
#[test]
fn when_one_answered_branch_ends_the_other_still_holds_the_relay() {
    use crate::relay::tests::SERVER;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog);
    let (call, answered) = rung_with_a_relay(&mut pair, crate::ForkPolicy::KeepAll);
    // both phones answer, and both are kept: one allocation, one socket, and
    // both branches' agents hold it, each for its own peer (RFC 8839 §7)
    pair.caller.deliver(&answered, callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    pair.caller
        .deliver(&from_another_branch(&answered), callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    let sibling = pair
        .caller
        .heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::CallForked { sibling, .. }) => Some(*sibling),
            _ => None,
        })
        .expect("the 2xx came from a second dialog");
    let held = |pair: &mut Pair, branch: CallHandle| {
        pair.caller
            .engine
            .session(branch)
            .expect("media")
            .path_candidates()
            .iter()
            .filter(|path| path.kind == crate::PathKind::Relay)
            .map(|path| path.outcome)
            .collect::<Vec<_>>()
    };
    assert_eq!(held(&mut pair, call), vec![crate::PathOutcome::Held]);
    assert_eq!(held(&mut pair, sibling), vec![crate::PathOutcome::Held]);

    // the first leg hangs up: the second still holds the relay, so the
    // server does not get it back
    pair.caller.agent.hangup(call, pair.now).expect("the BYE");
    pair.caller.drain(pair.now, false);
    assert!(
        relays_given_back(&mut pair.caller).is_empty(),
        "the relay went back while the other leg could use it"
    );
    let sent = sent_to_the_server_over(&mut pair);
    assert!(
        sent.contains(&sibling),
        "the leg left has no relay: {sent:?}"
    );
    assert!(pair.caller.engine.session(sibling).is_some(), "media");

    pair.caller
        .agent
        .hangup(sibling, pair.now)
        .expect("the BYE");
    pair.caller.drain(pair.now, false);
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(relays_given_back(&mut pair.caller), vec![(sibling, server)]);
}

#[cfg(feature = "ice")]
#[test]
fn a_second_branch_kept_because_it_answered_first_takes_the_relay() {
    use crate::relay::tests::SERVER;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog);
    let (call, answered) = rung_with_a_relay(&mut pair, crate::ForkPolicy::KeepFirst);
    // the second phone picks up while the first still rings: KeepFirst keeps
    // it, and the first branch ends without giving the relay back
    pair.caller
        .deliver(&from_another_branch(&answered), callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    let sibling = pair
        .caller
        .heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::CallForked { sibling, .. }) => Some(*sibling),
            _ => None,
        })
        .expect("the 2xx came from a second dialog");
    assert!(
        pair.caller.heard.iter().any(|event| matches!(
            event,
            Event::Signalling(UaEvent::CallEnded {
                call: ended,
                reason: crate::CallEndReason::ForkLost,
                ..
            }) if *ended == call
        )),
        "the first branch was not let go"
    );
    assert!(pair.caller.engine.session(sibling).is_some(), "media");
    let sent = sent_to_the_server(&mut pair.caller, pair.now);
    assert!(
        sent.contains(&sibling),
        "the branch kept has no relay: {sent:?}"
    );
    assert!(
        relays_given_back(&mut pair.caller).is_empty(),
        "the relay went back with the branch that was let go"
    );

    // the first phone answers after all: acknowledged and hung up, and the
    // relay stays where it is
    pair.caller.deliver(&answered, callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    let out = pair.caller.outbound();
    assert!(out.iter().any(|datagram| datagram.starts_with(b"BYE ")));
    assert!(pair.caller.engine.session(call).is_none());
    assert!(relays_given_back(&mut pair.caller).is_empty());

    pair.caller
        .agent
        .hangup(sibling, pair.now)
        .expect("the BYE");
    pair.caller.drain(pair.now, false);
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(relays_given_back(&mut pair.caller), vec![(sibling, server)]);
}

#[cfg(feature = "ice")]
#[test]
fn a_branch_that_answers_after_one_was_kept_leaves_the_relay_where_it_is() {
    use crate::relay::tests::SERVER;

    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog);
    let (call, answered) = rung_with_a_relay(&mut pair, crate::ForkPolicy::KeepFirst);
    // the first phone answers, and its session runs on the relay
    pair.caller.deliver(&answered, callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    assert!(pair.caller.engine.session(call).is_some(), "media");
    assert!(
        sent_to_the_server(&mut pair.caller, pair.now).contains(&call),
        "the branch kept has no relay"
    );

    // a second phone answers too late: hung up, and never a call here
    pair.caller
        .deliver(&from_another_branch(&answered), callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    let out = pair.caller.outbound();
    assert!(out.iter().any(|datagram| datagram.starts_with(b"BYE ")));
    assert!(
        !pair
            .caller
            .heard
            .iter()
            .any(|event| matches!(event, Event::Signalling(UaEvent::CallForked { .. }))),
        "a branch that answered too late became a call"
    );
    assert!(relays_given_back(&mut pair.caller).is_empty());

    pair.caller.agent.hangup(call, pair.now).expect("the BYE");
    pair.caller.drain(pair.now, false);
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(relays_given_back(&mut pair.caller), vec![(call, server)]);
}

/// The TURN server of the forked-call tests: it answers every request with
/// success (`crate::relay::tests::answer`), keeps the permissions and
/// channels it is asked for, and relays — which the other tests here never
/// need, since their two ends reach each other directly. Over a connection
/// it pads a channel message to whole words (RFC 8656 §12.5).
#[cfg(feature = "ice")]
#[derive(Default)]
struct Relaying {
    permitted: Vec<std::net::IpAddr>,
    channels: Vec<(u16, SocketAddr)>,
    transport: crate::TurnTransport,
}

/// What the TURN server does with a datagram from the client.
#[cfg(feature = "ice")]
enum FromClient {
    /// Answer it.
    Reply(Vec<u8>),
    /// Relay its payload to this peer, from the relayed address.
    Relay(SocketAddr, Vec<u8>),
    /// Drop it.
    Nothing,
}

/// An XOR-PEER-ADDRESS's IPv4 address (RFC 8489 §14.2).
#[cfg(feature = "ice")]
fn xor_peer(value: &[u8]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]) ^ 0x2112;
    let ip = value.get(4..8)?;
    let cookie = [0x21_u8, 0x12, 0xa4, 0x42];
    let octets: Vec<u8> = ip.iter().zip(cookie).map(|(a, b)| a ^ b).collect();
    Some(SocketAddr::new(
        std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).into(),
        port,
    ))
}

#[cfg(feature = "ice")]
impl Relaying {
    fn on_client(&mut self, data: &[u8]) -> FromClient {
        use sipral_nat::stun::{AttributeType, Class, Message};
        use sipral_nat::turn::{ChannelData, method};

        if data
            .first()
            .is_some_and(|byte| (0x40..=0x4f).contains(byte))
        {
            let Ok(frame) = ChannelData::parse_frame(data) else {
                return FromClient::Nothing;
            };
            return self
                .channels
                .iter()
                .find(|(number, _)| *number == frame.channel().get())
                .map_or(FromClient::Nothing, |(_, peer)| {
                    FromClient::Relay(*peer, frame.data().to_vec())
                });
        }
        let Ok(message) = Message::parse(data) else {
            return FromClient::Nothing;
        };
        if message.class() == Class::Indication && message.method() == method::SEND {
            let peer = message
                .find(AttributeType::XOR_PEER_ADDRESS)
                .and_then(xor_peer);
            let payload = message.find(AttributeType::DATA);
            return match (peer, payload) {
                (Some(peer), Some(payload)) if self.permitted.contains(&peer.ip()) => {
                    FromClient::Relay(peer, payload.to_vec())
                }
                _ => FromClient::Nothing,
            };
        }
        if message.method() == method::CREATE_PERMISSION || message.method() == method::CHANNEL_BIND
        {
            for peer in message
                .find_all(AttributeType::XOR_PEER_ADDRESS)
                .filter_map(xor_peer)
            {
                if !self.permitted.contains(&peer.ip()) {
                    self.permitted.push(peer.ip());
                }
                if let Some(number) = message.find(AttributeType::CHANNEL_NUMBER) {
                    let number = u16::from_be_bytes([number[0], number[1]]);
                    self.channels.retain(|(_, bound)| *bound != peer);
                    self.channels.push((number, peer));
                }
            }
        }
        crate::relay::tests::answer(data).map_or(FromClient::Nothing, FromClient::Reply)
    }

    /// What the server hands the client for a datagram `peer` sent to the
    /// relayed address, if its permission lets it through.
    fn for_client(&self, peer: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
        use sipral_nat::stun::{AttributeType, Class, MessageBuilder, TransactionId};
        use sipral_nat::turn::{ChannelData, ChannelNumber, method};

        if !self.permitted.contains(&peer.ip()) {
            return None;
        }
        if let Some((number, _)) = self.channels.iter().find(|(_, bound)| *bound == peer) {
            let mut frame = Vec::new();
            ChannelData::encode(
                ChannelNumber::new(*number)?,
                data,
                self.transport,
                &mut frame,
            )
            .ok()?;
            return Some(frame);
        }
        let mut builder = MessageBuilder::new(
            Class::Indication,
            method::DATA,
            TransactionId::new([0xd1; 12]),
        );
        builder
            .add_xor_address(AttributeType::XOR_PEER_ADDRESS, peer)
            .ok()?;
        builder.add(AttributeType::DATA, data).ok()?;
        Some(builder.finish())
    }
}

/// The mobile of the forked-call tests: a second phone the proxy rang, at
/// an address of its own.
#[cfg(feature = "ice")]
fn mobile_sip() -> SocketAddr {
    "192.0.2.3:5060".parse().expect("an address")
}

#[cfg(feature = "ice")]
fn mobile_media() -> SocketAddr {
    "192.0.2.3:40004".parse().expect("an address")
}

/// A call placed with a relay and forked by a proxy to a desk phone and a
/// mobile, both of which answer and are kept ([`ForkPolicy::KeepAll`]).
/// The caller sits behind a NAT neither phone can cross, so the relay the
/// one offer named is the only path to either; the phones reach the relay
/// directly.
#[cfg(feature = "ice")]
struct Fork {
    caller: Stack,
    phones: [Stack; 2],
    /// The caller's branch for each phone.
    branches: [CallHandle; 2],
    /// Each phone's side of its call.
    answered: [CallHandle; 2],
    turn: Relaying,
    /// What the server has read off the caller's connection to it, when the
    /// relay runs over one, and not yet taken whole.
    at_server: sipral_nat::turn::StreamFraming,
    now: Instant,
}

/// A relay allocated for `media` over a TCP connection to the forked-call
/// tests' TURN server, as [`relays_with_one_for`] allocates one over UDP.
#[cfg(feature = "ice")]
fn relays_over_tcp_with_one_for(
    stack: &mut Stack,
    media: SocketAddr,
    now: Instant,
) -> crate::Relays {
    use crate::relay::tests::{SERVER, answer};

    let server: SocketAddr = SERVER.parse().expect("an address");
    let mut relays = stack
        .engine
        .relays(server, "alice", "correct horse")
        .over(crate::TurnTransport::Tcp);
    relays.allocate(media, now);
    while let Some(request) = relays.poll_transmit() {
        let reply = answer(&request.payload).expect("an answer");
        assert_eq!(relays.receive_stream(request.local, &reply, now), Ok(true));
    }
    while relays.poll_event().is_some() {}
    relays
}

#[cfg(feature = "ice")]
impl Fork {
    fn new() -> Self {
        Self::placed(crate::TurnTransport::Udp, false)
    }

    /// [`Fork::new`], with the caller's relay reached over `transport`.
    fn over(transport: crate::TurnTransport) -> Self {
        Self::placed(transport, false)
    }

    /// The same call, both phones ringing with media — a 183 carrying the
    /// answer, the session open on it — and neither picking up: the
    /// branches run early.
    fn ringing() -> Self {
        Self::placed(crate::TurnTransport::Udp, true)
    }

    fn placed(transport: crate::TurnTransport, early: bool) -> Self {
        let now = Instant::now();
        let catalog = CodecCatalog::with_order(&["PCMU"])
            .expect("an order")
            .with_ice(crate::IcePolicy::Offered);
        let mut caller = Stack::new(11, caller_sip(), caller_media(), catalog.clone(), now);
        let mut phones = [
            Stack::new(22, callee_sip(), callee_media(), catalog.clone(), now),
            Stack::new(33, mobile_sip(), mobile_media(), catalog, now),
        ];
        let account = caller.account("alice", callee_sip());
        for phone in &mut phones {
            let _ = phone.account("bob", caller_sip());
        }
        let mut relays = if transport.is_stream() {
            relays_over_tcp_with_one_for(&mut caller, caller_media(), now)
        } else {
            relays_with_one_for(&mut caller, caller_media(), now)
        };
        let relay = relays.take(caller_media()).expect("the relay");
        let catalog = CodecCatalog::with_order(&["PCMU"])
            .expect("an order")
            .with_ice(crate::IcePolicy::Offered);
        let root = caller
            .engine
            .place_with(
                &mut caller.agent,
                account,
                OutgoingCall::new(uri("sip:bob@example.com"))
                    .to_address(UDP, callee_sip())
                    .forks(crate::ForkPolicy::KeepAll),
                caller_media(),
                CallMedia::new(catalog, MediaConfig::default()).relay(relay),
                now,
            )
            .expect("the INVITE goes");
        caller.drain(now, false);
        // the proxy hands the one INVITE to both phones, and both pick up,
        // or both ring with media
        let invite = caller.outbound();
        let mut answers = Vec::new();
        for phone in &mut phones {
            for datagram in &invite {
                phone.deliver(datagram, caller_sip(), now);
            }
            phone.drain(now, !early);
            if early {
                let incoming = phone.call().expect("the INVITE");
                let media = phone.media;
                phone
                    .engine
                    .ring(&mut phone.agent, incoming, media, now)
                    .expect("the 183 goes");
            }
            let wanted: &[u8] = if early {
                b"SIP/2.0 183"
            } else {
                b"SIP/2.0 200"
            };
            answers.extend(
                phone
                    .outbound()
                    .into_iter()
                    .filter(|datagram| datagram.starts_with(wanted)),
            );
        }
        for answer in &answers {
            caller.deliver(answer, callee_sip(), now);
        }
        caller.drain(now, false);
        let sibling = caller
            .heard
            .iter()
            .find_map(|event| match event {
                Event::Signalling(UaEvent::CallForked { sibling, .. }) => Some(*sibling),
                _ => None,
            })
            .expect("the mobile's response came from a second dialog");
        for ack in caller.outbound() {
            let to_mobile = String::from_utf8_lossy(&ack).contains("192.0.2.3");
            phones[usize::from(to_mobile)].deliver(&ack, caller_sip(), now);
        }
        let answered = [
            phones[0].call().expect("the desk's call"),
            phones[1].call().expect("the mobile's call"),
        ];
        for phone in &mut phones {
            phone.drain(now, false);
        }
        Self {
            caller,
            phones,
            branches: [root, sibling],
            answered,
            turn: Relaying {
                transport,
                ..Relaying::default()
            },
            at_server: sipral_nat::turn::StreamFraming::new(),
            now,
        }
    }

    /// What the TURN server sends the caller: a datagram to its socket, or
    /// bytes on its connection, each through the engine, which finds the
    /// branch.
    fn server_sends(&mut self, bytes: &[u8]) {
        let server: SocketAddr = crate::relay::tests::SERVER.parse().expect("an address");
        if self.turn.transport.is_stream() {
            assert_eq!(
                self.caller
                    .engine
                    .receive_stream(caller_media(), bytes, self.now),
                Ok(true),
                "a call's relay runs over the connection"
            );
        } else {
            self.caller
                .engine
                .receive_early(caller_media(), server, bytes, self.now);
        }
    }

    /// Everything the caller has for its TURN server, as whole messages:
    /// its datagrams to the server, or what it wrote on the connection, put
    /// back together as the server reads it.
    fn caller_sends(&mut self) -> Vec<Vec<u8>> {
        let server: SocketAddr = crate::relay::tests::SERVER.parse().expect("an address");
        let mut messages = Vec::new();
        while let Some((_, destination, payload)) = self.caller.engine.poll_transmit(self.now) {
            if destination == server {
                messages.push(payload);
            }
        }
        while let Some((_, written)) = self.caller.engine.poll_turn_stream() {
            assert_eq!(written.local, caller_media());
            assert_eq!(written.destination, server);
            self.at_server.push(&written.payload);
        }
        while let Some(frame) = self
            .at_server
            .next_frame()
            .expect("the caller writes whole messages")
        {
            messages.push(frame.to_vec());
        }
        messages
    }

    /// Which phone, by the address it sends from.
    fn phone_at(address: SocketAddr) -> Option<usize> {
        [callee_media(), mobile_media()]
            .iter()
            .position(|media| media.ip() == address.ip())
    }

    /// Move everything every end has queued one hop, and say whether
    /// anything moved. What the caller sends anywhere but its TURN server is
    /// lost at its NAT, and so is what reaches its own addresses from
    /// outside; everything the TURN server passes on reaches the caller
    /// through `MediaEngine::receive_early`, which finds the branch.
    fn step(&mut self) -> bool {
        let relayed: SocketAddr = crate::relay::tests::RELAYED.parse().expect("an address");
        let mut moved = false;
        for payload in self.caller_sends() {
            moved = true;
            match self.turn.on_client(&payload) {
                FromClient::Reply(reply) => self.server_sends(&reply),
                FromClient::Relay(peer, mut data) => {
                    if let Some(phone) = Self::phone_at(peer) {
                        let answered = self.answered[phone];
                        if let Some(mut session) = self.phones[phone].engine.session(answered) {
                            session.receive(&mut data, relayed, self.now);
                        }
                    }
                }
                FromClient::Nothing => {}
            }
        }
        for phone in 0..2 {
            let source = [callee_media(), mobile_media()][phone];
            while let Some((_, destination, payload)) =
                self.phones[phone].engine.poll_transmit(self.now)
            {
                moved = true;
                if destination == relayed
                    && let Some(wrapped) = self.turn.for_client(source, &payload)
                {
                    self.server_sends(&wrapped);
                }
            }
        }
        moved
    }

    fn advance(&mut self) {
        self.now += TICK;
        self.caller.engine.handle_timeout(self.now);
        self.caller.drain(self.now, false);
        for phone in &mut self.phones {
            phone.engine.handle_timeout(self.now);
            phone.drain(self.now, false);
        }
    }

    /// Run until both branches, and both phones, have a path.
    fn connect(&mut self) {
        for _ in 0..500 {
            while self.step() {}
            let chosen = self.branches.iter().all(|branch| {
                self.caller
                    .engine
                    .session(*branch)
                    .is_some_and(|session| session.ice_path().is_some())
            }) && (0..2).all(|phone| {
                self.phones[phone]
                    .engine
                    .session(self.answered[phone])
                    .is_some_and(|session| session.ice_path().is_some())
            });
            if chosen {
                return;
            }
            self.advance();
        }
        panic!("the forked call found no path through the relay");
    }

    /// One frame of `samples` from `phone` to its branch through the relay,
    /// and what each of the caller's branches played after it.
    fn heard_from(&mut self, phone: usize, samples: &[i16]) -> [i64; 2] {
        let source = [callee_media(), mobile_media()][phone];
        let sent = self.phones[phone]
            .engine
            .session(self.answered[phone])
            .expect("the phone's media")
            .capture(samples, self.now)
            .expect("the frame encodes")
            .map(|datagram| datagram.payload.to_vec());
        if let Some(sent) = sent
            && let Some(wrapped) = self.turn.for_client(source, &sent)
        {
            self.server_sends(&wrapped);
        }
        let mut loudness_of = [0; 2];
        for (index, branch) in self.branches.into_iter().enumerate() {
            if let Some(mut session) = self.caller.engine.session(branch) {
                let mut played = vec![0_i16; session.frame_samples()];
                session.playback(&mut played);
                loudness_of[index] = loudness(&played);
            }
        }
        loudness_of
    }

    /// Eight frames of a tone from `phone`, and how loud each branch played
    /// the last of them.
    fn tone_from(&mut self, phone: usize) -> [i64; 2] {
        let mut samples = vec![0_i16; 160];
        let mut phase = 0_u32;
        let mut heard = [0; 2];
        for _ in 0..8 {
            tone(&mut samples, 8_000, &mut phase);
            heard = self.heard_from(phone, &samples);
            self.advance();
            while self.step() {}
        }
        heard
    }
}

/// Both phones ring with media before either answers: each branch runs its
/// own ICE over the one relay and chooses a path to its own phone, and each
/// carries that phone's audio, before anybody picks up.
#[cfg(feature = "ice")]
#[test]
fn two_branches_ringing_with_media_each_find_their_phone_over_the_one_relay() {
    use crate::relay::tests::RELAYED;

    let mut fork = Fork::ringing();
    let [desk_branch, mobile_branch] = fork.branches;
    fork.connect();
    let relayed: SocketAddr = RELAYED.parse().expect("an address");
    for (branch, phone) in [
        (desk_branch, callee_media()),
        (mobile_branch, mobile_media()),
    ] {
        let path = fork
            .caller
            .engine
            .session(branch)
            .expect("the branch's early media")
            .ice_path()
            .expect("a path");
        assert_eq!(path, (relayed, phone), "{branch:?}");
    }
    let [desk_heard, _] = fork.tone_from(0);
    assert!(desk_heard > 4_000, "the desk's branch heard {desk_heard}");
    let [_, mobile_heard] = fork.tone_from(1);
    assert!(
        mobile_heard > 4_000,
        "the mobile's branch heard {mobile_heard}"
    );
}

#[cfg(feature = "ice")]
#[test]
fn two_answered_branches_of_a_fork_both_run_on_the_one_relay_until_one_hangs_up() {
    use crate::relay::tests::{RELAYED, SERVER};

    let mut fork = Fork::new();
    let [desk_branch, mobile_branch] = fork.branches;
    fork.connect();
    let relayed: SocketAddr = RELAYED.parse().expect("an address");
    // both branches' agents checked their own phone over the one relay
    for (branch, phone) in [
        (desk_branch, callee_media()),
        (mobile_branch, mobile_media()),
    ] {
        let path = fork
            .caller
            .engine
            .session(branch)
            .expect("the branch's media")
            .ice_path()
            .expect("a path");
        assert_eq!(path, (relayed, phone), "{branch:?}");
    }
    // one allocation, with both phones let through
    for phone in [callee_media(), mobile_media()] {
        assert!(fork.turn.permitted.contains(&phone.ip()), "{phone}");
    }

    // media on both, each phone heard on its own branch and on no other
    let [desk_heard, mobile_heard] = fork.tone_from(0);
    assert!(desk_heard > 4_000, "the desk's branch heard {desk_heard}");
    assert!(
        mobile_heard < 500,
        "the mobile's branch heard the desk: {mobile_heard}"
    );
    let [desk_heard, mobile_heard] = fork.tone_from(1);
    assert!(
        mobile_heard > 4_000,
        "the mobile's branch heard {mobile_heard}"
    );
    assert!(
        desk_heard < 500,
        "the desk's branch heard the mobile: {desk_heard}"
    );

    // the desk hangs up: its branch lets go of the relay, which the mobile's
    // branch still holds, so nothing goes back to the server yet
    fork.caller
        .agent
        .hangup(desk_branch, fork.now)
        .expect("the BYE");
    fork.caller.drain(fork.now, false);
    assert!(
        relays_given_back(&mut fork.caller).is_empty(),
        "the relay went back while the mobile's branch runs on it"
    );
    let [_, mobile_heard] = fork.tone_from(1);
    assert!(
        mobile_heard > 4_000,
        "the mobile's branch heard {mobile_heard} after"
    );

    // and the mobile's branch, the last to hold it, gives it back
    fork.caller
        .agent
        .hangup(mobile_branch, fork.now)
        .expect("the BYE");
    fork.caller.drain(fork.now, false);
    let server: SocketAddr = SERVER.parse().expect("an address");
    assert_eq!(
        relays_given_back(&mut fork.caller),
        vec![(mobile_branch, server)]
    );
}

/// The same fork with the relay reached over TCP: one connection carries
/// both branches' peers, and each message on it still reaches the branch it
/// is for, as a datagram from the server does.
#[cfg(feature = "ice")]
#[test]
fn two_branches_of_a_fork_share_the_one_relay_over_tcp_each_hearing_its_own_phone() {
    use crate::relay::tests::RELAYED;

    let mut fork = Fork::over(crate::TurnTransport::Tcp);
    let [desk_branch, mobile_branch] = fork.branches;
    fork.connect();
    let relayed: SocketAddr = RELAYED.parse().expect("an address");
    for (branch, phone) in [
        (desk_branch, callee_media()),
        (mobile_branch, mobile_media()),
    ] {
        let path = fork
            .caller
            .engine
            .session(branch)
            .expect("the branch's media")
            .ice_path()
            .expect("a path");
        assert_eq!(path, (relayed, phone), "{branch:?}");
    }
    let [desk_heard, mobile_heard] = fork.tone_from(0);
    assert!(desk_heard > 4_000, "the desk's branch heard {desk_heard}");
    assert!(
        mobile_heard < 500,
        "the mobile's branch heard the desk: {mobile_heard}"
    );
    let [desk_heard, mobile_heard] = fork.tone_from(1);
    assert!(
        mobile_heard > 4_000,
        "the mobile's branch heard {mobile_heard}"
    );
    assert!(
        desk_heard < 500,
        "the desk's branch heard the mobile: {desk_heard}"
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_call_behind_a_nat_says_which_paths_it_tried_and_why_each_lost() {
    use crate::relay::tests::{RELAYED, SERVER};
    use crate::{CandidateKind, PathKind, PathOutcome};

    let mut fork = Fork::new();
    fork.connect();
    let paths = fork
        .caller
        .engine
        .session(fork.branches[0])
        .expect("the desk's branch")
        .path_candidates();
    let relayed: SocketAddr = RELAYED.parse().expect("an address");
    let server: SocketAddr = SERVER.parse().expect("an address");
    // the pair the media runs on: from the relayed candidate, to the desk
    let selected: Vec<_> = paths
        .iter()
        .filter(|path| path.kind == PathKind::Pair && path.outcome == PathOutcome::Selected)
        .collect();
    assert_eq!(selected.len(), 1, "{paths:#?}");
    assert_eq!(selected[0].local, Some(relayed));
    assert_eq!(selected[0].local_kind, CandidateKind::Relayed);
    assert_eq!(selected[0].remote, callee_media());
    // the direct pair lost: its checks crossed no NAT, and the relayed pair
    // was nominated before they could run out (RFC 8445 §8.1.2)
    let direct = paths
        .iter()
        .find(|path| {
            path.kind == PathKind::Pair
                && path.local == Some(caller_media())
                && path.remote == callee_media()
        })
        .expect("the host pair was formed");
    assert_eq!(direct.local_kind, CandidateKind::Host);
    assert_eq!(
        direct.outcome,
        PathOutcome::NominatedElsewhere,
        "{paths:#?}"
    );
    assert!(
        paths
            .iter()
            .all(|path| path.outcome != PathOutcome::Waiting),
        "a pair was left undecided once the path was chosen: {paths:#?}"
    );
    // and the relay, which carries it
    let relays: Vec<_> = paths
        .iter()
        .filter(|path| path.kind == PathKind::Relay)
        .map(|path| (path.local, path.remote, path.outcome))
        .collect();
    assert_eq!(
        relays,
        vec![(Some(relayed), server, PathOutcome::Selected)],
        "{paths:#?}"
    );
}

/// Early media from the desk phone a proxy rang, at an address of its own.
const DESK_EARLY_MEDIA: &str = "v=0\r\no=- 5 5 IN IP4 192.0.2.50\r\ns=-\r\n\
c=IN IP4 192.0.2.50\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

#[test]
fn a_second_branch_kept_plays_the_session_its_own_answer_described() {
    // the desk rang with early media and the mobile answered first: the audio
    // goes where the mobile's 2xx says, and the desk's early session is gone
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());
    let call = pair
        .caller
        .engine
        .place(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    for datagram in pair.caller.outbound() {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, false);
    let incoming = pair.callee.call().expect("the callee heard the INVITE");
    pair.callee
        .agent
        .ring(incoming, None, pair.now)
        .expect("a 180");
    let ringing = pair
        .callee
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"SIP/2.0 180"))
        .expect("the 180");
    let progress = String::from_utf8(ringing).expect("text").replacen(
        "SIP/2.0 180 Ringing",
        "SIP/2.0 183 Session Progress",
        1,
    );
    let desk = with_body(progress.as_bytes(), "application/sdp", DESK_EARLY_MEDIA);
    pair.caller.deliver(&desk, callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    let early: SocketAddr = "192.0.2.50:6000".parse().expect("an address");
    assert_eq!(
        pair.caller
            .engine
            .session(call)
            .map(|session| session.destination()),
        Some(early),
        "the desk's early media plays"
    );

    pair.callee
        .engine
        .answer(&mut pair.callee.agent, incoming, callee_media(), pair.now)
        .expect("the 200 goes");
    let answered = pair
        .callee
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"SIP/2.0 200"))
        .expect("the 2xx");
    let described = String::from_utf8(wire_message_body(&answered))
        .expect("text")
        .replace("192.0.2.2", "192.0.2.77")
        .replace(" 40002 ", " 7000 ");
    let mobile = with_body(
        &from_another_branch(&answered),
        "application/sdp",
        &described,
    );
    pair.caller.deliver(&mobile, callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);

    let sibling = pair
        .caller
        .heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::CallForked { sibling, .. }) => Some(*sibling),
            _ => None,
        })
        .expect("the 2xx came from a second dialog");
    assert!(pair.caller.heard.iter().any(|event| matches!(
        event,
        Event::Signalling(UaEvent::CallEnded {
            call: ended,
            reason: crate::CallEndReason::ForkLost,
            ..
        }) if *ended == call
    )));
    assert!(
        pair.caller.engine.session(call).is_none(),
        "the desk's early media outlived its branch"
    );
    let mobile_media: SocketAddr = "192.0.2.77:7000".parse().expect("an address");
    assert_eq!(
        pair.caller
            .engine
            .session(sibling)
            .map(|session| session.destination()),
        Some(mobile_media),
        "the audio does not go where the branch kept said"
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_hold_does_not_withdraw_ice_from_a_call_that_had_it() {
    // RFC 8839 §4.4: the attributes go on every description of a session. The
    // user agent writes both of these itself — the facade never sees either —
    // so what keeps them there is the copy of this end's last description the
    // hold is made from, and `carried` in `sipral-ua` for the answer, and
    // this is their test from the outside. Read off the session change: the
    // INVITE that opened the call has them too, and a test that read that
    // one would pass whatever the hold did
    let (mut pair, call, _) = ice_call();
    pair.caller
        .agent
        .hold(call, pair.now)
        .expect("a confirmed call can be held");
    pair.caller.drain(pair.now, false);
    pair.settle();
    let (answer, held) = last_described(&pair.callee).expect("the callee saw the hold");
    assert_eq!(
        held.direction_of(&one_stream(&held)),
        Direction::SendOnly,
        "that was not the hold: {held}"
    );
    for (what, description) in [("re-offer", &held), ("answer", &answer)] {
        let stream = one_stream(description);
        assert!(
            stream.attribute("ice-ufrag").is_some() && stream.attribute("ice-pwd").is_some(),
            "the hold's {what} withdrew ICE from a call that had it"
        );
        assert_eq!(
            stream
                .attributes
                .iter()
                .filter(|attribute| attribute.name == "candidate")
                .count(),
            1,
            "and the {what} withdrew the candidate"
        );
    }
}

/// The USERNAME of every connectivity check one end has queued for the
/// other, drained.
#[cfg(feature = "ice")]
fn checks_sent(stack: &mut Stack, now: Instant) -> Vec<(Vec<u8>, String)> {
    use sipral_nat::stun::{Class, Message, Method};

    std::iter::from_fn(|| stack.engine.poll_transmit(now))
        .filter_map(|(_, _, datagram)| {
            let message = Message::parse(&datagram).ok()?;
            let username = (message.class() == Class::Request
                && message.method() == Method::BINDING)
                .then(|| message.username())
                .flatten()?;
            Some((
                datagram.clone(),
                String::from_utf8_lossy(username).into_owned(),
            ))
        })
        .collect()
}

#[cfg(feature = "ice")]
#[test]
fn an_ice_restart_between_two_full_agents_checks_again_on_new_credentials_and_keeps_the_audio() {
    let (mut pair, call, remote) = ice_call();
    pair.check_paths(call, remote);
    let first = pair.callee.offer_received().expect("the first offer");
    let answer = pair.caller.answer_received().expect("the first answer");
    let (offered_before, answered_before) = (
        ice_value(&first, "ice-ufrag").expect("a fragment"),
        ice_value(&answer, "ice-ufrag").expect("a fragment"),
    );
    let old_pwd = ice_value(&answer, "ice-pwd").expect("a password");

    // RFC 8445 §9, from this end: the caller offers the call again with new
    // credentials, and nothing else of the description moves
    pair.caller
        .engine
        .restart_ice(&mut pair.caller.agent, call, pair.now)
        .expect("a call running ICE restarts");
    pair.caller.drain(pair.now, false);
    pair.settle();

    let (restart_answer, restart_offer) =
        last_described(&pair.callee).expect("the callee answered the restart");
    let offering = ice_value(&restart_offer, "ice-ufrag").expect("a fragment");
    let answering = ice_value(&restart_answer, "ice-ufrag").expect("a fragment");
    let new_pwd = ice_value(&restart_answer, "ice-pwd").expect("a password");
    // RFC 8839 §4.4.1.1.1 has the offer change both, §4.4.2.1 the answer
    for (now, before) in [
        (Some(offering.clone()), Some(offered_before)),
        (
            ice_value(&restart_offer, "ice-pwd"),
            ice_value(&first, "ice-pwd"),
        ),
        (Some(answering.clone()), Some(answered_before)),
        (Some(new_pwd), Some(old_pwd)),
    ] {
        assert_ne!(now, before, "a restart kept a credential");
    }
    for (what, description, before) in [
        ("offer", &restart_offer, &first),
        ("answer", &restart_answer, &answer),
    ] {
        assert_eq!(
            attribute_values(&one_stream(description), "candidate"),
            attribute_values(&one_stream(before), "candidate"),
            "the restart's {what} named candidates its agent does not hold"
        );
    }
    assert!(failures(&pair).is_empty(), "{:?}", failures(&pair));

    // both agents flushed and check again, under the new credentials: the
    // caller's USERNAME is the callee's new fragment and then its own
    // (RFC 8445 §7.2.2)
    pair.advance();
    pair.caller.engine.handle_timeout(pair.now);
    pair.callee.engine.handle_timeout(pair.now);
    let checked_by_alice = checks_sent(&mut pair.caller, pair.now);
    let checked_by_bob = checks_sent(&mut pair.callee, pair.now);
    assert!(
        checked_by_alice
            .iter()
            .any(|(_, username)| *username == format!("{answering}:{offering}")),
        "the caller does not check under the new credentials: {checked_by_alice:?}"
    );
    assert!(
        checked_by_bob
            .iter()
            .any(|(_, username)| *username == format!("{offering}:{answering}")),
        "the callee does not check under the new credentials: {checked_by_bob:?}"
    );
    for (datagram, _) in checked_by_alice {
        let mut datagram = datagram;
        let _ = pair.callee.engine.session(remote).expect("media").receive(
            &mut datagram,
            caller_media(),
            pair.now,
        );
    }
    for (datagram, _) in checked_by_bob {
        let mut datagram = datagram;
        let _ = pair.caller.engine.session(call).expect("media").receive(
            &mut datagram,
            callee_media(),
            pair.now,
        );
    }

    // RFC 8839 §4.4.3.1.1: the audio stays on the pair selected before,
    // while the new session has selected nothing
    assert_eq!(
        pair.caller.engine.session(call).expect("media").ice_path(),
        None,
        "the restart did not reach the caller's agent"
    );
    let heard = tone_after(&mut pair, call, remote);
    assert!(heard > 4_000, "the tone came back at {heard} mid-restart");

    // and the checks run to a new selection on both ends
    pair.check_paths(call, remote);
    assert_eq!(
        paths_chosen(&pair.caller),
        vec![(caller_media(), callee_media()); 2],
        "the caller's new session selected nothing"
    );
    assert_eq!(
        paths_chosen(&pair.callee),
        vec![(callee_media(), caller_media()); 2],
        "the callee's new session selected nothing"
    );
    let heard = tone_after(&mut pair, call, remote);
    assert!(heard > 4_000, "the tone came back at {heard} after it");
    assert!(failures(&pair).is_empty(), "{:?}", failures(&pair));
}

#[cfg(feature = "ice")]
#[test]
fn a_restart_the_far_end_refuses_leaves_ice_as_it_was() {
    let ice = |order: &[&str]| {
        CodecCatalog::with_order(order)
            .expect("an order")
            .with_ice(crate::IcePolicy::Offered)
    };
    let mut pair = Pair::asymmetric(ice(&["PCMU", "PCMA"]), ice(&["PCMU"]));
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side of the call");
    pair.check_paths(call, remote);
    let first = pair.callee.offer_received().expect("the first offer");
    let old_ufrag = ice_value(&first, "ice-ufrag").expect("a fragment");

    pair.caller
        .engine
        .restart_ice(&mut pair.caller.agent, call, pair.now)
        .expect("a call running ICE restarts");
    pair.caller.drain(pair.now, false);
    // the far end is offered a codec it does not have, and refuses the
    // whole offer with a 488 (RFC 3261 §14.2)
    for datagram in pair.caller.outbound() {
        let body = wire_message_body(&datagram);
        let datagram = if body.starts_with(b"v=0") {
            let mut offer = parse(&body).expect("the restart offer");
            let stream = offer
                .media
                .iter_mut()
                .find(|stream| !stream.is_rejected())
                .expect("a stream");
            stream.formats = vec!["8".to_owned()];
            stream
                .attributes
                .retain(|attribute| attribute.name != "rtpmap" && attribute.name != "fmtp");
            with_body(&datagram, "application/sdp", &offer.to_string())
        } else {
            datagram
        };
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, true);
    pair.settle();
    assert!(
        pair.caller.heard.iter().any(|event| matches!(
            event,
            Event::Signalling(UaEvent::SessionChangeFailed { call: failed, .. }) if *failed == call
        )),
        "the far end accepted the restart"
    );

    // RFC 8839 §4.4: "as if the subsequent offer had never been made" — the
    // agent kept its pair and its credentials, and a later offer names them
    assert_eq!(
        pair.caller.engine.session(call).expect("media").ice_path(),
        Some((caller_media(), callee_media())),
        "a refused restart reached the running agent"
    );
    assert_eq!(paths_chosen(&pair.caller).len(), 1);
    pair.caller
        .agent
        .hold(call, pair.now)
        .expect("a confirmed call can be held");
    pair.caller.drain(pair.now, false);
    pair.settle();
    let (_, held) = last_described(&pair.callee).expect("the callee saw the hold");
    assert_eq!(ice_value(&held, "ice-ufrag"), Some(old_ufrag));
    assert!(failures(&pair).is_empty(), "{:?}", failures(&pair));
}

#[cfg(feature = "ice")]
#[test]
fn a_restart_asked_of_a_call_without_ice_is_refused_and_sends_nothing() {
    let (mut pair, call, _) = one_sided_ice_call(crate::IcePolicy::Offered);
    let refused = pair
        .caller
        .engine
        .restart_ice(&mut pair.caller.agent, call, pair.now);
    assert_eq!(refused, Err(MediaError::NoIce));
    assert!(pair.caller.outbound().is_empty(), "an offer went out");
}

/// The class of every STUN answer among `sent` to the request `id`.
#[cfg(feature = "ice")]
fn answers_to(sent: &[(CallHandle, SocketAddr, Vec<u8>)], id: &[u8]) -> Vec<String> {
    use sipral_nat::stun::{Class, Message};

    sent.iter()
        .filter_map(|(_, _, datagram)| Message::parse(datagram).ok())
        .filter(|message| {
            message.class() != Class::Request && message.transaction_id().as_bytes() == id
        })
        .map(|message| format!("{:?} {:?}", message.class(), message.error_code()))
        .collect()
}

#[cfg(feature = "ice")]
#[test]
fn checks_under_a_restart_this_end_offered_are_answered_once_its_answer_arrives() {
    use sipral_nat::stun::Message;

    let (mut pair, call, remote) = ice_call();
    pair.check_paths(call, remote);
    pair.caller
        .engine
        .restart_ice(&mut pair.caller.agent, call, pair.now)
        .expect("a call running ICE restarts");
    pair.caller.drain(pair.now, false);
    // the far end takes the restart and answers it, and its 200 is still on
    // the way when its first checks under the new credentials arrive
    for datagram in pair.caller.outbound() {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, true);
    let held_back: Vec<Vec<u8>> = pair.callee.outbound();
    assert!(
        held_back
            .iter()
            .any(|datagram| datagram.starts_with(b"SIP/2.0 200")),
        "the far end did not answer the restart"
    );
    let (restart_answer, restart_offer) =
        last_described(&pair.callee).expect("the callee answered the restart");
    let new_names = format!(
        "{}:{}",
        ice_value(&restart_offer, "ice-ufrag").expect("a fragment"),
        ice_value(&restart_answer, "ice-ufrag").expect("a fragment")
    );
    pair.advance();
    pair.callee.engine.handle_timeout(pair.now);
    let early: Vec<Vec<u8>> = checks_sent(&mut pair.callee, pair.now)
        .into_iter()
        .filter(|(_, username)| *username == new_names)
        .map(|(datagram, _)| datagram)
        .collect();
    assert!(
        !early.is_empty(),
        "the far end sent no check under the restart"
    );
    let ids: Vec<Vec<u8>> = early
        .iter()
        .map(|datagram| {
            Message::parse(datagram)
                .expect("STUN")
                .transaction_id()
                .as_bytes()
                .to_vec()
        })
        .collect();
    for datagram in &early {
        let mut datagram = datagram.clone();
        let _ = pair.caller.engine.session(call).expect("media").receive(
            &mut datagram,
            callee_media(),
            pair.now,
        );
    }
    let before: Vec<_> =
        std::iter::from_fn(|| pair.caller.engine.poll_transmit(pair.now)).collect();
    for id in &ids {
        assert_eq!(
            answers_to(&before, id),
            Vec::<String>::new(),
            "answered before the restart was taken up: an unsigned 401"
        );
    }

    // the 200 arrives: the restart is taken up, and the checks that came
    // first are answered then, well inside the far end's transactions
    for datagram in held_back {
        pair.caller.deliver(&datagram, callee_sip(), pair.now);
    }
    pair.caller.drain(pair.now, false);
    let after: Vec<_> = std::iter::from_fn(|| pair.caller.engine.poll_transmit(pair.now)).collect();
    for id in &ids {
        assert_eq!(
            answers_to(&after, id),
            vec!["Success None".to_owned()],
            "a check kept for the restart was not answered when it came"
        );
    }
}

/// A caller that will carry no audio on a path ICE did not check, and a
/// headless agent answering it as a lite endpoint.
#[cfg(all(feature = "ice", feature = "headless"))]
fn lite_call() -> (Pair, CallHandle, CallHandle) {
    let full = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Required);
    let lite = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Lite);
    let mut pair = Pair::asymmetric(full, lite);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side of the call");
    (pair, call, remote)
}

/// Every `PathChosen` a stack has reported.
#[cfg(feature = "ice")]
fn paths_chosen(stack: &Stack) -> Vec<(SocketAddr, SocketAddr)> {
    stack
        .media_events()
        .into_iter()
        .filter_map(|event| match event {
            MediaEvent::PathChosen { local, remote } => Some((*local, *remote)),
            _ => None,
        })
        .collect()
}

/// A connectivity check to a lite agent, as a full one signs it (RFC 8445
/// §7.2.2): USERNAME is the lite end's fragment and then the checker's, and
/// the lite end's password is the key.
#[cfg(all(feature = "ice", feature = "headless"))]
fn check_to_lite(ufrag: &str, pwd: &str, id: u8, nominate: bool) -> Vec<u8> {
    use sipral_nat::stun::{AttributeType, Class, MessageBuilder, Method, TransactionId};
    let mut builder = MessageBuilder::new(
        Class::Request,
        Method::BINDING,
        TransactionId::new([id; 12]),
    );
    builder
        .add(AttributeType::USERNAME, format!("{ufrag}:full").as_bytes())
        .expect("a username");
    builder
        .add_u64(AttributeType::ICE_CONTROLLING, 7)
        .expect("the role");
    if nominate {
        builder
            .add_flag(AttributeType::USE_CANDIDATE)
            .expect("a nomination");
    }
    builder
        .add_message_integrity(pwd.as_bytes())
        .expect("a key");
    builder.add_fingerprint().expect("a fingerprint");
    builder.finish()
}

/// Hand a check to the lite end of `pair` and read back what it answered.
#[cfg(all(feature = "ice", feature = "headless"))]
fn ask_lite(pair: &mut Pair, remote: CallHandle, from: SocketAddr, check: &[u8]) -> Vec<u8> {
    let mut datagram = check.to_vec();
    let arrival =
        pair.callee
            .engine
            .session(remote)
            .expect("media")
            .receive(&mut datagram, from, pair.now);
    assert_eq!(arrival, Arrival::Check, "a check is the agent's, not RTP");
    let (_, destination, answer) = pair
        .callee
        .engine
        .poll_transmit(pair.now)
        .expect("the lite end answers a check");
    assert_eq!(
        destination, from,
        "an answer goes back where its check came from"
    );
    pair.callee.drain(pair.now, true);
    answer
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn a_lite_end_that_restarts_keeps_the_checks_that_beat_the_answer_back() {
    use sipral_nat::stun::{Class, Integrity, Message};

    let (mut pair, call, remote) = lite_call();
    pair.check_paths(call, remote);
    pair.callee
        .engine
        .restart_ice(&mut pair.callee.agent, remote, pair.now)
        .expect("a lite end restarts too");
    pair.callee.drain(pair.now, false);
    let offer = pair
        .callee
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .expect("the re-offer");
    let described = parse(&wire_message_body(&offer)).expect("a description");
    let ufrag = ice_value(&described, "ice-ufrag").expect("a fragment");
    let pwd = ice_value(&described, "ice-pwd").expect("a password");
    pair.caller.deliver(&offer, callee_sip(), pair.now);
    pair.caller.drain(pair.now, false);
    let answer = pair.caller.outbound();

    // the full end checks under the new credentials before its 200 is in
    let mut early = check_to_lite(&ufrag, &pwd, 41, false);
    let arrival = pair.callee.engine.session(remote).expect("media").receive(
        &mut early,
        caller_media(),
        pair.now,
    );
    assert_eq!(arrival, Arrival::Check);
    assert!(
        pair.callee.engine.poll_transmit(pair.now).is_none(),
        "answered before the restart was taken up: an unsigned 401"
    );

    // the 200 arrives, and the check is answered, signed with the new key
    for datagram in answer {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, false);
    let (_, destination, reply) = pair
        .callee
        .engine
        .poll_transmit(pair.now)
        .expect("the kept check is answered");
    assert_eq!(destination, caller_media());
    let reply = Message::parse(&reply).expect("STUN");
    assert_eq!(reply.class(), Class::Success);
    assert_eq!(reply.transaction_id().as_bytes(), [41; 12]);
    assert_eq!(reply.verify_integrity(pwd.as_bytes()), Integrity::Valid);
}

/// An ICE attribute's value on a description's one stream.
#[cfg(feature = "ice")]
fn ice_value(description: &SessionDescription, name: &str) -> Option<String> {
    one_stream(description)
        .attribute(name)
        .and_then(|attribute| attribute.value.clone())
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn a_full_caller_checks_a_lite_agent_and_the_audio_crosses_on_the_pair_it_nominated() {
    let (mut pair, call, remote) = lite_call();

    // what makes the far end lite on the wire: `a=ice-lite` at session
    // level, credentials and one host candidate on the stream, and no
    // pacing, which RFC 8839 §4.3.1 forbids a lite end
    let answer = pair
        .caller
        .answer_received()
        .expect("the caller saw the answer");
    assert!(answer.attribute("ice-lite").is_some(), "{answer}");
    assert!(answer.attribute("ice-pacing").is_none(), "{answer}");
    let stream = one_stream(&answer);
    assert!(stream.attribute("ice-ufrag").is_some() && stream.attribute("ice-pwd").is_some());
    let candidates: Vec<&str> = stream
        .attributes
        .iter()
        .filter(|attribute| attribute.name == "candidate")
        .filter_map(|attribute| attribute.value.as_deref())
        .collect();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert!(
        candidates[0].contains("typ host") && candidates[0].contains("192.0.2.2 40002"),
        "{}",
        candidates[0]
    );

    // the caller requires ICE, so the lite answer is what let it open a
    // stream at all; and the lite end sends nothing before it is nominated
    let mut lite = pair
        .callee
        .engine
        .session(remote)
        .expect("the lite end's media");
    assert!(lite.ice_path().is_none());
    let frame = vec![100_i16; lite.frame_samples()];
    assert!(
        lite.capture(&frame, pair.now)
            .expect("refused, not broken")
            .is_none(),
        "a lite end sent audio before a pair was nominated"
    );
    drop(lite);

    let crossed = pair.check_paths(call, remote);
    assert!(crossed > 0, "nothing was checked");
    assert_eq!(
        pair.caller.engine.session(call).expect("media").ice_path(),
        Some((caller_media(), callee_media()))
    );
    assert_eq!(
        pair.callee
            .engine
            .session(remote)
            .expect("media")
            .ice_path(),
        Some((callee_media(), caller_media())),
        "the lite end took the pair the caller nominated"
    );
    assert_eq!(
        paths_chosen(&pair.callee),
        vec![(callee_media(), caller_media())]
    );

    // and audio both ways, the lite end's on the nominated pair
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(
        loudness(&played) > 4_000,
        "the tone reached the lite end at {}",
        loudness(&played)
    );
    let mut lite = pair.callee.engine.session(remote).expect("media");
    let sent = lite
        .capture(&samples, pair.now)
        .expect("the frame encodes")
        .expect("a nominated lite end sends");
    assert_eq!(sent.destination, caller_media());
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn a_lite_agent_answers_a_peer_without_ice_without_any_and_still_gets_its_audio() {
    // RFC 8839 §4.3.2: "the answerer MUST NOT include any ICE-related SDP
    // attributes in the answer" to an offer that had none — a PBX that does
    // no ICE is the commonest peer a headless agent has
    let plain = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let lite = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Lite);
    let mut pair = Pair::asymmetric(plain, lite);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side of the call");
    let answer = pair
        .caller
        .answer_received()
        .expect("the caller saw the answer");
    assert!(answer.attribute("ice-lite").is_none(), "{answer}");
    assert!(ice_value(&answer, "ice-ufrag").is_none(), "{answer}");
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(
        loudness(&played) > 4_000,
        "the tone came back at {}",
        loudness(&played)
    );
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn an_ice_restart_gives_the_lite_agent_new_credentials_and_the_old_pair_holds_until_the_new_nomination()
 {
    let (mut pair, call, remote) = lite_call();
    pair.check_paths(call, remote);
    let answer = pair.caller.answer_received().expect("the first answer");
    let (old_ufrag, old_pwd) = (
        ice_value(&answer, "ice-ufrag").expect("a fragment"),
        ice_value(&answer, "ice-pwd").expect("a password"),
    );

    // the caller restarts: the same description with both of its
    // credentials changed (RFC 8839 §4.4.1.1.1)
    let mut offer = pair
        .callee
        .offer_received()
        .expect("the caller's own description, as it arrived");
    offer.origin.version += 1;
    let stream = offer
        .media
        .iter_mut()
        .find(|media| !media.is_rejected())
        .expect("a stream");
    for attribute in &mut stream.attributes {
        match attribute.name.as_str() {
            "ice-ufrag" => attribute.value = Some("rstr".to_owned()),
            "ice-pwd" => attribute.value = Some("restartrestartrestart12".to_owned()),
            _ => {}
        }
    }
    pair.caller
        .agent
        .reoffer(call, &offer.to_bytes(), pair.now)
        .expect("a confirmed call can be re-offered");
    pair.caller.drain(pair.now, false);
    pair.settle();

    // read off the session change, not off the INVITE that opened the call
    let (restarted, offered) = last_described(&pair.callee).expect("the callee answered");
    assert_eq!(ice_value(&offered, "ice-ufrag").as_deref(), Some("rstr"));
    let new_ufrag = ice_value(&restarted, "ice-ufrag").expect("a fragment");
    let new_pwd = ice_value(&restarted, "ice-pwd").expect("a password");
    assert_ne!(
        new_ufrag, old_ufrag,
        "RFC 8839 §4.4.2.1: the answerer changes both"
    );
    assert_ne!(
        new_pwd, old_pwd,
        "RFC 8839 §4.4.2.1: the answerer changes both"
    );
    assert!(restarted.attribute("ice-lite").is_some(), "{restarted}");

    // RFC 8445 §9: the old pair carries the media until the new session
    // selects, and its consent check under the old credentials is answered
    assert_eq!(
        pair.callee
            .engine
            .session(remote)
            .expect("media")
            .ice_path(),
        Some((callee_media(), caller_media()))
    );
    let consent = ask_lite(
        &mut pair,
        remote,
        caller_media(),
        &check_to_lite(&old_ufrag, &old_pwd, 1, false),
    );
    let consent = sipral_nat::stun::Message::parse(&consent).expect("a STUN answer");
    assert_eq!(consent.class(), sipral_nat::stun::Class::Success);
    assert_eq!(
        consent.verify_integrity(old_pwd.as_bytes()),
        sipral_nat::stun::Integrity::Valid
    );

    // the new session nominates another path, and the audio moves to it
    let moved: SocketAddr = "192.0.2.1:40010".parse().expect("an address");
    let nominated = ask_lite(
        &mut pair,
        remote,
        moved,
        &check_to_lite(&new_ufrag, &new_pwd, 2, true),
    );
    let nominated = sipral_nat::stun::Message::parse(&nominated).expect("a STUN answer");
    assert_eq!(nominated.class(), sipral_nat::stun::Class::Success);
    assert_eq!(
        nominated.verify_integrity(new_pwd.as_bytes()),
        sipral_nat::stun::Integrity::Valid
    );
    assert_eq!(
        pair.callee
            .engine
            .session(remote)
            .expect("media")
            .ice_path(),
        Some((callee_media(), moved))
    );
    assert_eq!(
        paths_chosen(&pair.callee),
        vec![(callee_media(), caller_media()), (callee_media(), moved)]
    );
    let mut lite = pair.callee.engine.session(remote).expect("media");
    let frame = vec![100_i16; lite.frame_samples()];
    let sent = lite
        .capture(&frame, pair.now)
        .expect("the frame encodes")
        .expect("a nominated lite end sends");
    assert_eq!(sent.destination, moved);
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn a_nomination_the_lite_agent_cannot_authenticate_moves_no_audio() {
    let (mut pair, call, remote) = lite_call();
    let answer = pair.caller.answer_received().expect("the answer");
    let (ufrag, pwd) = (
        ice_value(&answer, "ice-ufrag").expect("a fragment"),
        ice_value(&answer, "ice-pwd").expect("a password"),
    );
    // a nominating check with a username but nothing signing it
    let unsigned = {
        use sipral_nat::stun::{AttributeType, Class, MessageBuilder, Method, TransactionId};
        let mut builder =
            MessageBuilder::new(Class::Request, Method::BINDING, TransactionId::new([9; 12]));
        builder
            .add(AttributeType::USERNAME, format!("{ufrag}:full").as_bytes())
            .expect("a username");
        builder
            .add_u64(AttributeType::ICE_CONTROLLING, 7)
            .expect("the role");
        builder
            .add_flag(AttributeType::USE_CANDIDATE)
            .expect("a nomination");
        builder.add_fingerprint().expect("a fingerprint");
        builder.finish()
    };
    let forged = [
        check_to_lite(&ufrag, "notthepasswordnotthepass", 1, true),
        check_to_lite("nope", &pwd, 2, true),
        unsigned,
    ];
    let elsewhere: SocketAddr = "198.51.100.66:40066".parse().expect("an address");

    // before any nomination: each is refused, and the lite end still has
    // nowhere to send
    for check in &forged {
        let refused = ask_lite(&mut pair, remote, elsewhere, check);
        let refused = sipral_nat::stun::Message::parse(&refused).expect("a STUN answer");
        assert_eq!(refused.class(), sipral_nat::stun::Class::Error);
        let mut lite = pair.callee.engine.session(remote).expect("media");
        assert!(lite.ice_path().is_none());
        let frame = vec![100_i16; lite.frame_samples()];
        assert!(
            lite.capture(&frame, pair.now)
                .expect("refused, not broken")
                .is_none(),
            "audio left for a pair nobody authenticated"
        );
    }

    // after the real one: the same checks do not move the path off it
    pair.check_paths(call, remote);
    for check in &forged {
        let refused = ask_lite(&mut pair, remote, elsewhere, check);
        let refused = sipral_nat::stun::Message::parse(&refused).expect("a STUN answer");
        assert_eq!(refused.class(), sipral_nat::stun::Class::Error);
    }
    assert_eq!(
        paths_chosen(&pair.callee),
        vec![(callee_media(), caller_media())]
    );
    let mut lite = pair.callee.engine.session(remote).expect("media");
    let frame = vec![100_i16; lite.frame_samples()];
    let sent = lite
        .capture(&frame, pair.now)
        .expect("the frame encodes")
        .expect("a nominated lite end sends");
    assert_eq!(sent.destination, caller_media());
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn two_lite_ends_carry_the_call_on_their_default_candidates() {
    // RFC 8445 §6.1.1 gives two lite ends roles but neither sends a check,
    // and each has one host candidate, which is its `c=`/`m=`: the pair
    // there is to select is the default one
    let lite = || {
        CodecCatalog::with_order(&["PCMU"])
            .expect("an order")
            .with_ice(crate::IcePolicy::Lite)
    };
    let mut pair = Pair::asymmetric(lite(), lite());
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's side of the call");
    let offer = pair.callee.offer_received().expect("the offer");
    let answer = pair.caller.answer_received().expect("the answer");
    assert!(offer.attribute("ice-lite").is_some(), "{offer}");
    assert!(answer.attribute("ice-lite").is_some(), "{answer}");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert!(
        loudness(&played) > 4_000,
        "the tone reached the answering lite end at {}",
        loudness(&played)
    );
    let mut answering = pair.callee.engine.session(remote).expect("media");
    let sent = answering
        .capture(&samples, pair.now)
        .expect("the frame encodes")
        .expect("the answering end sends on its default candidate");
    assert_eq!(sent.destination, caller_media());
}

/// Where [`flood_media_port`]'s requests come from.
#[cfg(feature = "ice")]
fn stranger() -> SocketAddr {
    "203.0.113.66:40066".parse().expect("an address")
}

/// Send `count` unsigned Binding requests, from a stranger, to one call's
/// media port without taking anything back, then `behind` if there is one,
/// then drain the session: what it had queued, and how many it dropped.
#[cfg(feature = "ice")]
fn flood_media_port(
    pair: &mut Pair,
    remote: CallHandle,
    count: u32,
    behind: Option<(SocketAddr, &[u8])>,
) -> (Vec<(SocketAddr, Vec<u8>)>, u64) {
    use sipral_nat::stun::{Class, MessageBuilder, Method, TransactionId};
    let mut session = pair.callee.engine.session(remote).expect("media");
    while session.poll_transmit(pair.now).is_some() {}
    for index in 0..count {
        let mut id = [0x5a_u8; 12];
        id[..4].copy_from_slice(&index.to_be_bytes());
        let mut builder =
            MessageBuilder::new(Class::Request, Method::BINDING, TransactionId::new(id));
        builder.add_fingerprint().expect("a fingerprint");
        let mut datagram = builder.finish();
        assert_eq!(
            session.receive(&mut datagram, stranger(), pair.now),
            Arrival::Check
        );
    }
    if let Some((from, check)) = behind {
        let mut datagram = check.to_vec();
        assert_eq!(
            session.receive(&mut datagram, from, pair.now),
            Arrival::Check
        );
    }
    let mut queued = Vec::new();
    while let Some(datagram) = session.poll_transmit(pair.now) {
        queued.push((datagram.destination, datagram.payload.to_vec()));
    }
    (queued, session.ice_transmits_dropped())
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn a_flood_of_checks_nobody_drains_holds_the_lite_end_to_its_ceiling() {
    let (mut pair, call, remote) = lite_call();
    let (queued, dropped) = flood_media_port(&mut pair, remote, 5_000, None);
    assert_eq!(queued.len(), sipral_nat::ice::REFUSAL_CEILING);
    assert!(queued.iter().all(|(to, _)| *to == stranger()));
    assert_eq!(
        dropped,
        5_000 - u64::try_from(sipral_nat::ice::REFUSAL_CEILING).expect("fits")
    );
    // and the real peer, checking once the queue is drained, is answered and
    // gets its path
    pair.check_paths(call, remote);
    assert_eq!(
        paths_chosen(&pair.callee),
        vec![(callee_media(), caller_media())]
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_flood_of_checks_nobody_drains_holds_the_full_agent_to_its_ceiling() {
    let (mut pair, call, remote) = ice_call();
    let (queued, dropped) = flood_media_port(&mut pair, remote, 5_000, None);
    assert_eq!(queued.len(), sipral_nat::ice::REFUSAL_CEILING);
    assert!(queued.iter().all(|(to, _)| *to == stranger()));
    assert_eq!(
        dropped,
        5_000 - u64::try_from(sipral_nat::ice::REFUSAL_CEILING).expect("fits")
    );
    pair.check_paths(call, remote);
    let session = pair.callee.engine.session(remote).expect("media");
    assert_eq!(session.ice_path(), Some((callee_media(), caller_media())));
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn a_consent_check_behind_a_strangers_flood_is_still_answered_by_the_lite_end() {
    let (mut pair, call, remote) = lite_call();
    pair.check_paths(call, remote);
    let answer = pair.caller.answer_received().expect("the answer");
    let (ufrag, pwd) = (
        ice_value(&answer, "ice-ufrag").expect("a fragment"),
        ice_value(&answer, "ice-pwd").expect("a password"),
    );
    // the peer's consent check lands behind the flood, with nothing
    // drained: a stranger's refusals must not have taken its answer's room,
    // or thirty seconds of that ends the peer's consent (RFC 7675 §5.1)
    let consent = check_to_lite(&ufrag, &pwd, 9, false);
    let (queued, _) = flood_media_port(
        &mut pair,
        remote,
        5_000,
        Some((caller_media(), consent.as_slice())),
    );
    let answered = queued.iter().any(|(to, bytes)| {
        *to == caller_media()
            && sipral_nat::stun::Message::parse(bytes)
                .is_ok_and(|message| message.class() == sipral_nat::stun::Class::Success)
    });
    assert!(answered, "the peer's consent check went unanswered");
}

#[cfg(all(feature = "ice", feature = "headless"))]
#[test]
fn signed_checks_nobody_drains_hold_the_lite_end_to_the_whole_ceiling() {
    let (mut pair, call, remote) = lite_call();
    pair.check_paths(call, remote);
    let answer = pair.caller.answer_received().expect("the answer");
    let (ufrag, pwd) = (
        ice_value(&answer, "ice-ufrag").expect("a fragment"),
        ice_value(&answer, "ice-pwd").expect("a password"),
    );
    let mut session = pair.callee.engine.session(remote).expect("media");
    while session.poll_transmit(pair.now).is_some() {}
    for index in 0..1_000_u32 {
        let id = u8::try_from(index % 256).expect("fits");
        let mut datagram = check_to_lite(&ufrag, &pwd, id, false);
        assert_eq!(
            session.receive(&mut datagram, caller_media(), pair.now),
            Arrival::Check
        );
    }
    let mut queued = 0;
    while session.poll_transmit(pair.now).is_some() {
        queued += 1;
    }
    assert_eq!(queued, sipral_nat::ice::TRANSMIT_CEILING);
    assert_eq!(
        session.ice_transmits_dropped(),
        1_000 - u64::try_from(sipral_nat::ice::TRANSMIT_CEILING).expect("fits")
    );
}

#[cfg(feature = "ice")]
#[test]
fn nothing_goes_out_on_a_call_whose_checks_have_not_finished() {
    // N5's precondition, from the outside: a producer that had no route and
    // sent anyway would be sending to the signalled address, which is exactly
    // the path ICE exists not to trust
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let mut session = pair.caller.engine.session(call).expect("media");
    assert!(session.ice_path().is_none(), "nothing has been checked yet");
    let frame = vec![100_i16; session.frame_samples()];
    assert!(
        session
            .capture(&frame, pair.now)
            .expect("the frame is refused, not broken")
            .is_none(),
        "audio went out before a path was chosen"
    );
    assert!(
        session.poll_rtcp(pair.now).is_none(),
        "a report went out before a path was chosen"
    );
    // and the clock does not wake a caller for a report it will refuse. The
    // deadline `poll_rtcp` would have moved stays where it is when the report
    // is refused, so publishing it would spin the caller's loop for the whole
    // of the checks — the same failure the keying guard one line up avoids,
    // and the reason both are asked before the schedule rather than after
    assert!(
        !session.rtcp_deadline_passed(pair.now + Duration::from_secs(30)),
        "the clock says a report is due on a call with nowhere to send it"
    );
    // it does ask to be woken, and soon — but for the agent's own pacing,
    // which is what makes a path exist at all, rather than for the report
    let waking = session
        .poll_timeout()
        .expect("the agent has work and says when");
    assert!(
        waking <= pair.now + Duration::from_secs(1),
        "the only deadline left is the report's, which is five seconds out"
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_call_that_lost_consent_stops_sending_rather_than_falling_back() {
    // RFC 7675 §5.1: "the endpoint MUST cease transmission on that 5-tuple".
    // The failure this guards is the quiet one in the other direction — a
    // session that answered a lost path by forgetting it had an agent would
    // put the audio straight back on the address the signalling named, which
    // is the unchecked path the call chose not to trust
    let (mut pair, call, remote) = ice_call();
    pair.check_paths(call, remote);
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .ice_path()
            .is_some(),
        "the call has a checked path to lose"
    );

    // thirty seconds with no authenticated response on the selected pair,
    // which is what the far end going away looks like from here
    for _ in 0..40 {
        pair.now += Duration::from_secs(1);
        pair.caller.engine.handle_timeout(pair.now);
        // drained but never delivered: the far end is gone
        while pair.caller.engine.poll_transmit(pair.now).is_some() {}
        pair.caller.drain(pair.now, false);
    }

    let lost = pair.caller.heard.iter().any(|event| {
        matches!(
            event,
            Event::Media {
                event: MediaEvent::Failed(MediaError::IcePathLost),
                ..
            }
        )
    });
    assert!(lost, "consent ran out and the call was not told");

    let mut session = pair.caller.engine.session(call).expect("media");
    let frame = vec![100_i16; session.frame_samples()];
    assert!(
        session
            .capture(&frame, pair.now)
            .expect("the frame is refused, not broken")
            .is_none(),
        "audio went out after consent was withdrawn"
    );
    assert!(
        session.poll_rtcp(pair.now).is_none(),
        "a report went out after consent was withdrawn"
    );
}

// -- a codec change this end asks for ----------------------------------------

/// Ask the caller's engine to move `call` onto `codecs`, and hand back the
/// re-offer exactly as it went on the wire, once both ends have finished the
/// exchange it started.
fn change_codecs(pair: &mut Pair, call: CallHandle, codecs: &[&str]) -> SessionDescription {
    pair.caller
        .engine
        .change_codecs(&mut pair.caller.agent, call, codecs, pair.now)
        .expect("the re-offer goes");
    let written = pair.caller.outbound();
    let offer = written
        .iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .map(|datagram| parse(&wire_message_body(datagram)).expect("an offer that reads"))
        .expect("a re-INVITE went out");
    for datagram in written {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, true);
    pair.caller.drain(pair.now, false);
    pair.settle();
    offer
}

/// The `a=` lines a stream carries under one name, in order.
#[cfg(any(feature = "opus", feature = "dtls", feature = "ice"))]
fn attribute_values(stream: &MediaDescription, name: &str) -> Vec<String> {
    stream
        .attributes
        .iter()
        .filter(|attribute| attribute.name == name)
        .map(|attribute| attribute.value.clone().unwrap_or_default())
        .collect()
}

/// Everything a description says about a stream but its codecs: the lines a
/// codec change must leave exactly as they were.
fn all_but_the_codecs(stream: &MediaDescription) -> Vec<(String, Option<String>)> {
    stream
        .attributes
        .iter()
        .filter(|attribute| attribute.name != "rtpmap" && attribute.name != "fmtp")
        .map(|attribute| (attribute.name.clone(), attribute.value.clone()))
        .collect()
}

#[test]
fn asking_for_another_codec_moves_the_call_and_nothing_else() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    let first = pair.callee.offer_received().expect("the first offer");
    assert_eq!(
        pair.caller.engine.session(call).expect("media").codec(),
        Codec::Pcmu
    );

    let offer = change_codecs(&mut pair, call, &["PCMA"]);

    let (was, now) = (one_stream(&first), one_stream(&offer));
    assert_eq!(
        now.formats.first().map(String::as_str),
        Some("8"),
        "{offer}"
    );
    assert!(!now.formats.iter().any(|format| format == "0"), "{offer}");
    // RFC 3264 §8: the same session, one version on, from the same place
    assert_eq!(offer.origin.session_id, first.origin.session_id);
    assert_eq!(offer.origin.version, first.origin.version + 1);
    assert_eq!(offer.connection, first.connection);
    assert_eq!((now.port, &now.proto), (was.port, &was.proto));
    assert_eq!(all_but_the_codecs(&now), all_but_the_codecs(&was));

    for session in [
        pair.caller.engine.session(call).expect("media"),
        pair.callee.engine.session(remote).expect("media"),
    ] {
        assert_eq!(session.codec(), Codec::Pcma, "one end never moved");
    }
    assert!(
        pair.caller.media_events().iter().any(|event| matches!(
            event,
            MediaEvent::Changed {
                codec: Codec::Pcma,
                direction: Direction::SendRecv
            }
        )),
        "the change was never reported"
    );
    assert_eq!(
        pair.caller
            .engine
            .call_catalog(call)
            .map(CodecCatalog::codecs),
        Some(&[Codec::Pcma][..]),
        "the list the far end accepted is not the call's own"
    );
}

#[test]
fn a_codec_change_on_a_held_call_leaves_it_held_and_the_resume_brings_the_new_codec() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.caller.agent.hold(call, pair.now).expect("the hold");
    pair.caller.drain(pair.now, false);
    pair.settle();

    let offer = change_codecs(&mut pair, call, &["PCMA"]);
    assert_eq!(
        offer.direction_of(&one_stream(&offer)),
        Direction::SendOnly,
        "a codec change took the call off hold: {offer}"
    );
    {
        let held = pair.callee.engine.session(remote).expect("media");
        assert_eq!(held.codec(), Codec::Pcma);
        assert_eq!(held.direction(), Direction::RecvOnly);
    }
    assert_eq!(
        pair.caller.agent.hold_state(call).map(|hold| hold.local),
        Some(true)
    );

    pair.caller
        .agent
        .resume(call, pair.now)
        .expect("the resume");
    pair.caller.drain(pair.now, false);
    pair.settle();
    let resumed = pair.callee.engine.session(remote).expect("media");
    assert_eq!(resumed.codec(), Codec::Pcma, "the resume went back to PCMU");
    assert_eq!(resumed.direction(), Direction::SendRecv);
}

#[test]
fn a_refused_codec_change_leaves_the_call_on_the_list_it_had() {
    // the far end keeps only PCMU, so an offer of PCMA alone is one it
    // cannot answer — and §14.1 leaves the session exactly as it was
    let mut pair = Pair::asymmetric(
        CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order"),
        CodecCatalog::with_order(&["PCMU"]).expect("an order"),
    );
    let call = pair.connect();

    let _ = change_codecs(&mut pair, call, &["PCMA"]);
    assert!(
        pair.caller.heard.iter().any(|event| matches!(
            event,
            Event::Signalling(UaEvent::SessionChangeFailed { .. })
        )),
        "the far end accepted what it cannot decode"
    );
    let remote = pair.callee.call().expect("the callee knows the call");
    for session in [
        pair.caller.engine.session(call).expect("media"),
        pair.callee
            .engine
            .session(remote)
            .expect("the refusal kept the stream"),
    ] {
        assert_eq!(session.codec(), Codec::Pcmu);
        assert_eq!(session.direction(), Direction::SendRecv);
    }
    assert_eq!(
        pair.caller
            .engine
            .call_catalog(call)
            .map(CodecCatalog::codecs),
        Some(&[Codec::Pcmu, Codec::Pcma][..]),
        "a refused list became the call's own"
    );

    // and nothing is left waiting on it: the next change goes
    let offer = change_codecs(&mut pair, call, &["PCMU"]);
    assert_eq!(
        one_stream(&offer).formats.first().map(String::as_str),
        Some("0")
    );
}

#[cfg(feature = "opus")]
#[test]
fn a_codec_change_does_not_move_the_number_a_dynamic_format_has() {
    // the call opened on Opus at 96 with its events at 97, on Opus's clock.
    // Numbered from the catalogue alone, the same two codecs the other way
    // round give Opus 96 again but put PCMU's own events — a different
    // format, on another clock — at 97, which RFC 3264 §8.3.2 keeps for the
    // forty-eight kilohertz ones for the whole session
    let catalog = CodecCatalog::with_order(&["opus", "PCMU"])
        .expect("an order")
        .with_dtmf(true);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let first = one_stream(&pair.callee.offer_received().expect("the first offer"));
    let number_of = |stream: &MediaDescription, encoding: &str| {
        attribute_values(stream, "rtpmap")
            .into_iter()
            .find(|map| map.contains(encoding))
            .and_then(|map| map.split_once(' ').map(|(number, _)| number.to_owned()))
    };
    assert_eq!(number_of(&first, "opus/").as_deref(), Some("96"));
    assert_eq!(
        number_of(&first, "telephone-event/48000").as_deref(),
        Some("97")
    );

    let offer = one_stream(&change_codecs(&mut pair, call, &["PCMU", "opus"]));
    assert_eq!(
        number_of(&offer, "opus/").as_deref(),
        Some("96"),
        "Opus moved"
    );
    let events = number_of(&offer, "telephone-event/8000").expect("events are offered");
    assert!(
        events != "96" && events != "97",
        "telephone-event/8000 took {events}, a number this call already gave \
         something else: {:?}",
        attribute_values(&offer, "rtpmap")
    );
    assert_eq!(
        pair.caller.engine.session(call).expect("media").codec(),
        Codec::Pcmu
    );
}

#[test]
fn a_codec_change_on_a_call_keyed_by_sdes_offers_the_key_it_already_has() {
    // a key drawn afresh would be a re-key nobody asked for, in the middle of
    // a change that is about something else
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::Offered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    let first = one_stream(&pair.callee.offer_received().expect("the first offer"));

    let offer = one_stream(&change_codecs(&mut pair, call, &["PCMA"]));
    assert_eq!(crypto_line(&offer), crypto_line(&first));
    assert!(crypto_line(&offer).is_some(), "the key was dropped");

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    let session = pair.caller.engine.session(call).expect("media");
    assert_eq!(session.codec(), Codec::Pcma);
    assert!(
        session.is_encrypted(),
        "the change took the encryption away"
    );
    drop(session);
    assert!(
        loudness(&played) > 4_000,
        "the tone came back at {} after the change",
        loudness(&played)
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_codec_change_on_a_dtls_call_keeps_the_association_it_has() {
    // RFC 8842 §3.1: a fingerprint or a role that moved asks for a new DTLS
    // association, which this stack does not start — so the change carries
    // both exactly as the call already has them
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::DtlsOffered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.shake_hands(call, remote);
    let first = one_stream(&pair.callee.offer_received().expect("the first offer"));

    let offer = one_stream(&change_codecs(&mut pair, call, &["PCMA"]));
    for name in ["fingerprint", "setup"] {
        assert_eq!(
            attribute_values(&offer, name),
            attribute_values(&first, name),
            "a={name} moved"
        );
    }
    assert!(
        !pair.caller.media_events().iter().any(|event| matches!(
            event,
            MediaEvent::Failed(MediaError::DtlsFingerprintChanged)
        )),
        "the change was read as a new certificate"
    );

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    assert_eq!(
        pair.caller.engine.session(call).expect("media").codec(),
        Codec::Pcma
    );
    assert!(
        loudness(&played) > 4_000,
        "the tone came back at {} after the change",
        loudness(&played)
    );
}

/// The same from the end that answered, whose last description carries the
/// role it answered with. RFC 8842 §5.5 has the re-offer say `actpass`
/// anyway, and §5.3 has the far end answer it with the roles already in
/// force — so the association stays as it was and nothing is re-keyed.
#[cfg(feature = "dtls")]
#[test]
fn a_codec_change_from_the_end_that_answered_keeps_the_dtls_roles() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::DtlsOffered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.shake_hands(call, remote);
    let answered = one_stream(&pair.caller.answer_received().expect("the answer"));
    let role = attribute_values(&answered, "setup");
    assert!(
        role == ["active"] || role == ["passive"],
        "the answer took no role: {role:?}"
    );

    pair.callee
        .engine
        .change_codecs(&mut pair.callee.agent, remote, &["PCMA"], pair.now)
        .expect("the re-offer goes");
    let written = pair.callee.outbound();
    let offer = written
        .iter()
        .find(|datagram| datagram.starts_with(b"INVITE "))
        .map(|datagram| parse(&wire_message_body(datagram)).expect("an offer that reads"))
        .expect("a re-INVITE went out");
    for datagram in written {
        pair.caller.deliver(&datagram, callee_sip(), pair.now);
    }
    pair.caller.drain(pair.now, false);
    pair.callee.drain(pair.now, true);
    pair.settle();

    let stream = one_stream(&offer);
    assert_eq!(
        attribute_values(&stream, "setup"),
        ["actpass"],
        "RFC 8842 §5.5: a re-offer hands the roles back"
    );
    assert_eq!(
        attribute_values(&stream, "fingerprint"),
        attribute_values(&answered, "fingerprint"),
        "the certificate moved"
    );
    // and the far end answered it with the role it has, which is the other
    // one to this end's: RFC 4145 §4.1 leaves this end its own
    let (_, reanswered) = last_described(&pair.callee).expect("the change settled");
    let kept = attribute_values(&one_stream(&reanswered), "setup");
    let theirs = if role == ["active"] {
        "passive"
    } else {
        "active"
    };
    assert_eq!(kept, [theirs], "the far end took another role");
    for (side, heard) in [("caller", &pair.caller), ("callee", &pair.callee)] {
        assert!(
            !heard
                .media_events()
                .iter()
                .any(|event| matches!(event, MediaEvent::Failed(_))),
            "the {side} refused the change: {:?}",
            heard.media_events()
        );
    }

    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    for session in [
        pair.caller.engine.session(call).expect("media"),
        pair.callee.engine.session(remote).expect("media"),
    ] {
        assert_eq!(session.codec(), Codec::Pcma);
        assert!(session.is_encrypted());
    }
    assert!(
        loudness(&played) > 4_000,
        "the tone came back at {} after the change",
        loudness(&played)
    );
}

#[cfg(feature = "ice")]
#[test]
fn a_codec_change_on_an_ice_call_does_not_restart_it() {
    // RFC 8445 §9: new credentials in an offer are an ICE restart
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let first = one_stream(&pair.callee.offer_received().expect("the first offer"));

    let offer = change_codecs(&mut pair, call, &["PCMA"]);
    let stream = one_stream(&offer);
    for name in ["ice-ufrag", "ice-pwd", "candidate"] {
        assert_eq!(
            attribute_values(&stream, name),
            attribute_values(&first, name),
            "a={name} moved"
        );
    }
    assert!(offer.attribute("ice-pacing").is_some(), "{offer}");
}

#[test]
fn a_codec_change_names_a_codec_this_build_has_or_goes_nowhere() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();

    let refused =
        pair.caller
            .engine
            .change_codecs(&mut pair.caller.agent, call, &["G723"], pair.now);
    assert!(
        matches!(refused, Err(MediaError::UnsupportedCodec { .. })),
        "{refused:?}"
    );
    assert!(
        pair.caller.outbound().is_empty(),
        "an offer went out for a codec that is not here"
    );

    pair.caller
        .agent
        .hangup(call, pair.now)
        .expect("the BYE goes");
    pair.caller.drain(pair.now, false);
    pair.settle();
    let ended = pair
        .caller
        .engine
        .change_codecs(&mut pair.caller.agent, call, &["PCMA"], pair.now);
    assert_eq!(ended, Err(MediaError::NoSuchCall));
}

// -- re-offers on a call that is held or secured ---------------------------------

/// What the two ends last described, as the latest session change reported
/// it — this end's half first.
fn last_described(stack: &Stack) -> Option<(SessionDescription, SessionDescription)> {
    stack.heard.iter().rev().find_map(|event| match event {
        Event::Signalling(UaEvent::SessionChanged {
            local: Some(local),
            remote: Some(remote),
            ..
        }) => Some((parse(local.as_ref()).ok()?, parse(remote.as_ref()).ok()?)),
        _ => None,
    })
}

/// Settle as [`Pair::settle`] does, with every description one side sends
/// passed through `edit` on its way: a far end writing what this stack
/// never would.
#[cfg(feature = "dtls")]
fn settle_editing(pair: &mut Pair, caller_writes: bool, edit: &dyn Fn(&str) -> String) {
    for _ in 0..12 {
        let mut dialled = pair.caller.outbound();
        let mut answered = pair.callee.outbound();
        if dialled.is_empty() && answered.is_empty() {
            break;
        }
        let edited = if caller_writes {
            &mut dialled
        } else {
            &mut answered
        };
        for datagram in edited.iter_mut() {
            let body = wire_message_body(datagram);
            if body.starts_with(b"v=0") {
                let rewritten = edit(&String::from_utf8_lossy(&body));
                *datagram = with_body(datagram, "application/sdp", &rewritten);
            }
        }
        for datagram in dialled {
            pair.callee.deliver(&datagram, caller_sip(), pair.now);
        }
        for datagram in answered {
            pair.caller.deliver(&datagram, callee_sip(), pair.now);
        }
        pair.caller.drain(pair.now, false);
        pair.callee.drain(pair.now, true);
    }
}

/// Whether either end reported media failing, and what.
fn failures(pair: &Pair) -> Vec<(&'static str, MediaError)> {
    let mut found = Vec::new();
    for (side, heard) in [("caller", &pair.caller), ("callee", &pair.callee)] {
        for event in heard.media_events() {
            if let MediaEvent::Failed(error) = event {
                found.push((side, error.clone()));
            }
        }
    }
    found
}

/// Talk for eight frames and say how loud what came out was.
fn tone_after(pair: &mut Pair, call: CallHandle, remote: CallHandle) -> i64 {
    let mut samples = vec![0_i16; 160];
    let mut phase = 0_u32;
    let mut played = Vec::new();
    for _ in 0..8 {
        tone(&mut samples, 8_000, &mut phase);
        played = pair.exchange(call, remote, &samples);
        pair.advance();
    }
    loudness(&played)
}

#[cfg(feature = "dtls")]
#[test]
fn a_hold_from_either_end_of_a_dtls_call_is_answered_and_keeps_the_association() {
    // the answer used to be the user agent's, and it carried neither the
    // certificate nor the role: the end that asked for the hold read a
    // secured stream with no key on it, and the hold never reached its media
    for caller_holds in [true, false] {
        let label = if caller_holds { "caller" } else { "callee" };
        let (mut pair, call, remote) = dtls_call();
        pair.shake_hands(call, remote);
        let offered = one_stream(&pair.callee.offer_received().expect("the first offer"));
        let answered = one_stream(&pair.caller.answer_received().expect("the answer"));
        if caller_holds {
            pair.caller.agent.hold(call, pair.now).expect("the hold");
            pair.caller.drain(pair.now, false);
        } else {
            pair.callee.agent.hold(remote, pair.now).expect("the hold");
            pair.callee.drain(pair.now, false);
        }
        pair.settle();
        assert_eq!(failures(&pair), [], "{label} held");

        let holder = if caller_holds {
            &pair.caller
        } else {
            &pair.callee
        };
        let (offer, answer) = last_described(holder).expect("the hold settled");
        let (offer, answer) = (one_stream(&offer), one_stream(&answer));
        assert_eq!(attribute_values(&offer, "setup"), ["actpass"], "{label}");
        // the answering end's own certificate, and the role it already has:
        // the caller offered actpass and the callee took active
        let (theirs, role) = if caller_holds {
            (&answered, "active")
        } else {
            (&offered, "passive")
        };
        assert_eq!(
            attribute_values(&answer, "fingerprint"),
            attribute_values(theirs, "fingerprint"),
            "{label} held: the answer withdrew or moved the certificate"
        );
        assert_eq!(attribute_values(&answer, "setup"), [role], "{label} held");

        let directions = (
            pair.caller.engine.session(call).expect("media").direction(),
            pair.callee
                .engine
                .session(remote)
                .expect("media")
                .direction(),
        );
        let expected = if caller_holds {
            (Direction::SendOnly, Direction::RecvOnly)
        } else {
            (Direction::RecvOnly, Direction::SendOnly)
        };
        assert_eq!(directions, expected, "{label}: the hold missed the media");

        if caller_holds {
            pair.caller
                .agent
                .resume(call, pair.now)
                .expect("the resume");
            pair.caller.drain(pair.now, false);
        } else {
            pair.callee
                .agent
                .resume(remote, pair.now)
                .expect("the resume");
            pair.callee.drain(pair.now, false);
        }
        pair.settle();
        assert_eq!(failures(&pair), [], "{label} resumed");
        let loud = tone_after(&mut pair, call, remote);
        assert!(loud > 4_000, "{label}: the tone came back at {loud}");
        for session in [
            pair.caller.engine.session(call).expect("media"),
            pair.callee.engine.session(remote).expect("media"),
        ] {
            assert_eq!(session.direction(), Direction::SendRecv, "{label}");
            assert!(session.is_encrypted(), "{label}: the keys went");
        }
    }
}

#[test]
fn a_hold_from_the_far_end_of_an_sdes_call_is_answered_with_the_key_in_use() {
    // RFC 4568 §7.1.4: an answerer that changes its key leaves the offerer
    // unable to read it until the answer arrives, and a hold is no reason to
    // open that window
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_srtp(SrtpPolicy::Offered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    let first = one_stream(&pair.callee.offer_received().expect("the first offer"));

    pair.callee.agent.hold(remote, pair.now).expect("the hold");
    pair.callee.drain(pair.now, false);
    pair.settle();
    assert_eq!(failures(&pair), []);
    let (_, answer) = last_described(&pair.callee).expect("the hold settled");
    let answer = one_stream(&answer);
    assert_eq!(
        crypto_line(&answer).map(|line| line.key_params),
        crypto_line(&first).map(|line| line.key_params),
        "the answer to a hold re-keyed"
    );
    {
        let held = pair.caller.engine.session(call).expect("media");
        assert_eq!(held.direction(), Direction::RecvOnly);
        assert!(held.is_encrypted());
    }

    pair.callee
        .agent
        .resume(remote, pair.now)
        .expect("the resume");
    pair.callee.drain(pair.now, false);
    pair.settle();
    assert_eq!(failures(&pair), []);
    let loud = tone_after(&mut pair, call, remote);
    assert!(loud > 4_000, "the tone came back at {loud}");
}

#[test]
fn a_codec_change_from_the_far_end_leaves_a_call_held_here_on_hold() {
    // the engine answers every offer sendrecv; sent as written, that took the
    // call off hold on the wire and started this end's stream sending into a
    // call its user believed was on hold
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.caller.agent.hold(call, pair.now).expect("the hold");
    pair.caller.drain(pair.now, false);
    pair.settle();

    pair.callee
        .engine
        .change_codecs(&mut pair.callee.agent, remote, &["PCMA"], pair.now)
        .expect("the re-offer goes");
    pair.callee.drain(pair.now, false);
    pair.settle();

    let (answer, _) = last_described(&pair.caller).expect("the change settled");
    assert_eq!(
        answer.direction_of(&one_stream(&answer)),
        Direction::SendOnly,
        "{answer}"
    );
    assert_eq!(
        pair.caller.agent.hold_state(call).map(|hold| hold.local),
        Some(true)
    );
    let held = pair.caller.engine.session(call).expect("media");
    assert_eq!(held.codec(), Codec::Pcma);
    assert_eq!(held.direction(), Direction::SendOnly);
    drop(held);
    let other = pair.callee.engine.session(remote).expect("media");
    assert_eq!(other.codec(), Codec::Pcma);
    assert_eq!(other.direction(), Direction::RecvOnly);
}

#[cfg(feature = "dtls")]
#[test]
fn an_answer_that_takes_the_other_dtls_role_is_refused_by_name() {
    // the callee is the client; its hold hands the roles back, and a far end
    // that answers by taking the client's role for itself is asking for an
    // association this end does not start
    let (mut pair, call, remote) = dtls_call();
    pair.shake_hands(call, remote);
    pair.callee.agent.hold(remote, pair.now).expect("the hold");
    pair.callee.drain(pair.now, false);
    settle_editing(&mut pair, true, &|body| {
        body.replace("a=setup:passive", "a=setup:active")
    });

    assert!(
        failures(&pair).contains(&("callee", MediaError::DtlsRoleChanged)),
        "{:?}",
        failures(&pair)
    );
    let session = pair.callee.engine.session(remote).expect("media");
    assert!(session.is_encrypted(), "the refusal threw the keys away");
    assert_eq!(
        session.direction(),
        Direction::SendRecv,
        "a refused plan was adopted"
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_re_offer_that_asks_for_the_other_dtls_role_is_refused_with_488() {
    // an older peer's concrete value: the callee, the client, re-offering
    // `passive` asks this end to become the client in its place
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::DtlsOffered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.shake_hands(call, remote);
    pair.callee
        .engine
        .change_codecs(&mut pair.callee.agent, remote, &["PCMA"], pair.now)
        .expect("the re-offer goes");
    settle_editing(&mut pair, false, &|body| {
        body.replace("a=setup:actpass", "a=setup:passive")
    });

    assert!(
        failures(&pair).contains(&("caller", MediaError::DtlsRoleChanged)),
        "{:?}",
        failures(&pair)
    );
    assert!(
        pair.callee.heard.iter().any(|event| matches!(
            event,
            Event::Signalling(UaEvent::SessionChangeFailed { .. })
        )),
        "the re-offer was answered"
    );
    for session in [
        pair.caller.engine.session(call).expect("media"),
        pair.callee.engine.session(remote).expect("media"),
    ] {
        assert_eq!(session.codec(), Codec::Pcmu, "the session did not stand");
        assert!(session.is_encrypted());
    }
}

#[cfg(feature = "dtls")]
#[test]
fn a_re_offer_that_names_another_certificate_is_refused_with_488() {
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::DtlsOffered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.shake_hands(call, remote);
    pair.callee
        .engine
        .change_codecs(&mut pair.callee.agent, remote, &["PCMA"], pair.now)
        .expect("the re-offer goes");
    settle_editing(&mut pair, false, &|body| {
        let mut moved = String::new();
        for line in body.lines() {
            if line.starts_with("a=fingerprint:") {
                moved.push_str(
                    "a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
                );
            } else {
                moved.push_str(line);
            }
            moved.push_str("\r\n");
        }
        moved
    });

    assert!(
        failures(&pair).contains(&("caller", MediaError::DtlsFingerprintChanged)),
        "{:?}",
        failures(&pair)
    );
    assert!(
        pair.callee.heard.iter().any(|event| matches!(
            event,
            Event::Signalling(UaEvent::SessionChangeFailed { .. })
        )),
        "the re-offer was answered"
    );
    let session = pair.caller.engine.session(call).expect("media");
    assert_eq!(session.codec(), Codec::Pcmu, "the session did not stand");
    assert!(session.is_encrypted());
}

#[cfg(feature = "dtls")]
#[test]
fn a_re_offer_that_writes_the_same_certificate_differently_is_not_a_new_one() {
    // RFC 8842 §3.1 counts fingerprints "modified, added, or removed"; the
    // same lines in lower case and one of them twice are none of those
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])
        .expect("an order")
        .with_srtp(SrtpPolicy::DtlsOffered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.shake_hands(call, remote);
    pair.callee
        .engine
        .change_codecs(&mut pair.callee.agent, remote, &["PCMA"], pair.now)
        .expect("the re-offer goes");
    settle_editing(&mut pair, false, &|body| {
        let mut rewritten = String::new();
        for line in body.lines() {
            if line.starts_with("a=fingerprint:") {
                let lower = line.to_ascii_lowercase();
                rewritten.push_str(&lower);
                rewritten.push_str("\r\n");
                rewritten.push_str(&lower);
            } else {
                rewritten.push_str(line);
            }
            rewritten.push_str("\r\n");
        }
        rewritten
    });

    assert_eq!(failures(&pair), []);
    for session in [
        pair.caller.engine.session(call).expect("media"),
        pair.callee.engine.session(remote).expect("media"),
    ] {
        assert_eq!(session.codec(), Codec::Pcma, "the change was refused");
        assert!(session.is_encrypted());
    }
}

#[test]
fn a_call_the_application_describes_answers_its_own_re_offers() {
    // the application answered with a description of its own, so it is the
    // only one that can answer a re-offer on the call: the engine used to
    // refuse every one of them 488 first — every hold, once holds on a
    // secured call were handed up — and to open a stream of its own on the
    // call after a plain one
    for secured in [false, true] {
        let mut catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
        if secured {
            catalog = catalog.with_srtp(SrtpPolicy::Offered);
        }
        let mut pair = Pair::new(catalog);
        let remote = pair.ring();
        let (proto, crypto) = if secured {
            (
                "RTP/SAVP",
                "a=crypto:1 AES_CM_128_HMAC_SHA1_80 \
inline:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\r\n",
            )
        } else {
            ("RTP/AVP", "")
        };
        let described = |version: u32, direction: &str| {
            format!(
                "v=0\r\no=- 5 {version} IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\n\
t=0 0\r\nm=audio 40002 {proto} 0\r\na=rtpmap:0 PCMU/8000\r\n{crypto}a={direction}\r\n"
            )
        };
        pair.callee
            .agent
            .answer(
                remote,
                Some(Arc::from(described(5, "sendrecv").as_bytes())),
                pair.now,
            )
            .expect("the 200 goes");
        pair.settle();
        let call = pair.caller.call().expect("the caller knows the call");

        pair.caller.agent.hold(call, pair.now).expect("the hold");
        pair.caller.drain(pair.now, false);
        pair.settle();
        let refused = |pair: &Pair| {
            pair.caller.heard.iter().any(|event| {
                matches!(
                    event,
                    Event::Signalling(UaEvent::SessionChangeFailed { .. })
                )
            })
        };
        assert!(
            !refused(&pair),
            "secured={secured}: the engine refused a hold on a call it does not describe"
        );
        if secured {
            assert!(
                pair.callee
                    .heard
                    .iter()
                    .any(|event| matches!(event, Event::Signalling(UaEvent::Reoffer { .. }))),
                "the hold never reached the application"
            );
            pair.callee
                .agent
                .accept_reoffer(remote, described(6, "recvonly").as_bytes(), pair.now)
                .expect("the application answers it");
            pair.settle();
            assert!(!refused(&pair));
        }
        assert_eq!(
            pair.caller.agent.hold_state(call).map(|hold| hold.local),
            Some(true),
            "secured={secured}"
        );
        assert!(
            pair.callee.engine.session(remote).is_none(),
            "secured={secured}: the engine opened a stream on the application's call"
        );
        assert!(
            pair.callee.media_events().is_empty(),
            "secured={secured}: {:?}",
            pair.callee.media_events()
        );
    }
}

// -- the DTLS latch, and what a running stream may not change -------------------

#[cfg(feature = "dtls")]
#[test]
fn one_octet_from_a_stranger_does_not_take_a_calls_handshake() {
    // the latch used to close on the first datagram whose first octet was 22,
    // from anywhere: one packet from somebody who read the port out of the
    // description, and the real far end's records were dropped until the
    // handshake gave up
    let (mut pair, call, remote) = dtls_call();
    let stranger: SocketAddr = "203.0.113.9:40000".parse().expect("an address");
    let taken = {
        let mut session = pair.caller.engine.session(call).expect("media");
        session.receive(&mut [22_u8], stranger, pair.now)
    };
    assert_eq!(taken, Arrival::Dropped(crate::Discard::ForeignAddress));

    pair.shake_hands(call, remote);
    for session in [
        pair.caller.engine.session(call).expect("media"),
        pair.callee.engine.session(remote).expect("media"),
    ] {
        assert!(
            session.is_encrypted(),
            "the stranger kept the call from keying"
        );
    }
}

#[cfg(feature = "dtls")]
#[test]
fn a_far_end_whose_port_the_path_moved_is_answered_where_its_records_come_from() {
    // no RTP latch can close before there are keys, so the answer to a
    // ClientHello used to go to the signalled port whatever port it came from
    let (mut pair, call, remote) = dtls_call();
    let moved: SocketAddr = "192.0.2.2:50002".parse().expect("an address");
    let mut destinations = Vec::new();
    for _ in 0..16 {
        let mut crossed = false;
        while let Some((_, _, mut record)) = pair.callee.engine.poll_transmit(pair.now) {
            crossed = true;
            let mut session = pair.caller.engine.session(call).expect("media");
            session.receive(&mut record, moved, pair.now);
        }
        while let Some((_, destination, mut record)) = pair.caller.engine.poll_transmit(pair.now) {
            crossed = true;
            destinations.push(destination);
            let mut session = pair.callee.engine.session(remote).expect("media");
            session.receive(&mut record, caller_media(), pair.now);
        }
        pair.caller.drain(pair.now, false);
        pair.callee.drain(pair.now, false);
        if !crossed {
            break;
        }
    }
    assert!(!destinations.is_empty(), "this end never answered");
    assert!(
        destinations.iter().all(|destination| *destination == moved),
        "the flight went to the signalled port: {destinations:?}"
    );
    assert!(
        pair.caller
            .engine
            .session(call)
            .expect("media")
            .is_encrypted()
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_far_end_that_moves_its_media_address_is_heard_from_the_new_one() {
    // the handshake's latch stayed on the old address, so a far end that
    // moved and still had a flight to retransmit was dropped as a stranger
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_srtp(SrtpPolicy::DtlsOffered);
    let mut pair = Pair::new(catalog);
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.shake_hands(call, remote);

    // the callee's own description is the answer the caller received
    let mut moved = pair.caller.answer_received().expect("the answer");
    moved.origin.version += 5;
    for stream in &mut moved.media {
        stream.port = 50_002;
    }
    pair.callee
        .agent
        .reoffer(remote, &moved.to_bytes(), pair.now)
        .expect("the re-INVITE goes");
    pair.callee.drain(pair.now, false);
    pair.settle();
    assert_eq!(failures(&pair), []);

    let new: SocketAddr = "192.0.2.2:50002".parse().expect("an address");
    let heard = {
        let mut session = pair.caller.engine.session(call).expect("media");
        session.receive(&mut [22_u8, 254, 253, 0, 0], new, pair.now)
    };
    assert_eq!(
        heard,
        Arrival::Handshake,
        "the new address was taken for a stranger"
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_re_offer_that_takes_the_encryption_off_a_running_call_is_refused_by_name() {
    // under an offered policy the plain answer was allowed, and adopted: the
    // stream went on sending SRTP to a far end now expecting RTP, and the
    // plan it compares later certificates against had none left in it
    for keyed in [SrtpPolicy::DtlsOffered, SrtpPolicy::Offered] {
        let catalog = CodecCatalog::with_order(&["PCMU"])
            .expect("an order")
            .with_srtp(keyed);
        let mut pair = Pair::new(catalog);
        let call = pair.connect();
        let remote = pair.callee.call().expect("the callee knows the call");
        if keyed == SrtpPolicy::DtlsOffered {
            pair.shake_hands(call, remote);
        }
        let mut plain = pair.caller.answer_received().expect("the answer");
        plain.origin.version += 5;
        for stream in &mut plain.media {
            stream.proto = "RTP/AVP".to_owned();
            stream
                .attributes
                .retain(|a| !matches!(a.name.as_str(), "crypto" | "fingerprint" | "setup"));
        }
        pair.callee
            .agent
            .reoffer(remote, &plain.to_bytes(), pair.now)
            .expect("the re-INVITE goes");
        pair.callee.drain(pair.now, false);
        pair.settle();

        assert!(
            failures(&pair).contains(&("caller", MediaError::KeyingChanged)),
            "{keyed:?}: {:?}",
            failures(&pair)
        );
        assert!(
            pair.callee.heard.iter().any(|event| matches!(
                event,
                Event::Signalling(UaEvent::SessionChangeFailed { .. })
            )),
            "{keyed:?}: the re-offer was answered"
        );
        assert!(
            pair.caller
                .engine
                .session(call)
                .expect("media")
                .is_encrypted(),
            "{keyed:?}"
        );
    }
}

#[cfg(feature = "dtls")]
#[test]
fn a_clear_call_re_offered_under_dtls_is_refused_rather_than_left_in_the_clear() {
    // the plain call this policy took was answered DTLS-SRTP when re-offered
    // it, and no handshake ever started: this end said it would be the client
    // and went on sending RTP in the clear
    let mut pair = Pair::asymmetric(
        CodecCatalog::with_order(&["PCMU"]).expect("an order"),
        CodecCatalog::with_order(&["PCMU"])
            .expect("an order")
            .with_srtp(SrtpPolicy::DtlsOffered),
    );
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    assert!(
        !pair
            .callee
            .engine
            .session(remote)
            .expect("media")
            .is_encrypted()
    );

    let mut keyed = pair.callee.offer_received().expect("the offer");
    keyed.origin.version += 5;
    for stream in &mut keyed.media {
        stream.proto = "UDP/TLS/RTP/SAVP".to_owned();
        stream
            .attributes
            .push(sipral_core::sdp::Attribute::with_value(
                "fingerprint",
                "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
            ));
        stream
            .attributes
            .push(sipral_core::sdp::Attribute::with_value("setup", "actpass"));
        stream
            .attributes
            .push(sipral_core::sdp::Attribute::flag("rtcp-mux"));
    }
    pair.caller
        .agent
        .reoffer(call, &keyed.to_bytes(), pair.now)
        .expect("the re-INVITE goes");
    pair.caller.drain(pair.now, false);
    pair.settle();

    assert!(
        failures(&pair).contains(&("callee", MediaError::KeyingChanged)),
        "{:?}",
        failures(&pair)
    );
    assert!(
        pair.caller.heard.iter().any(|event| matches!(
            event,
            Event::Signalling(UaEvent::SessionChangeFailed { .. })
        )),
        "the re-offer was answered"
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_certificate_renewed_while_a_call_rings_is_not_the_one_its_handshake_presents() {
    // the engine renews its certificate a day before it runs out. One renewed
    // between a call's offer and its answer used to hand the handshake the new
    // certificate, whose hash was not the fingerprint the far end was given
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_srtp(SrtpPolicy::DtlsOffered);
    let mut pair = Pair::new(catalog);
    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());
    let call = pair
        .caller
        .engine
        .place(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    let offered = pair.caller.outbound();

    // a month on, as far as this engine's clock can tell, another call is
    // placed, and the certificate is renewed under the first one
    let month = pair.now + Duration::from_secs(29 * 24 * 60 * 60 + 60 * 60);
    let other = pair.caller.account("carol", callee_sip());
    pair.caller
        .engine
        .place(
            &mut pair.caller.agent,
            other,
            OutgoingCall::new(uri("sip:carol@example.com")).to_address(UDP, callee_sip()),
            "192.0.2.1:41000".parse().expect("an address"),
            month,
        )
        .expect("the second INVITE goes");
    let _ = pair.caller.outbound();

    for datagram in offered {
        pair.callee.deliver(&datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, true);
    pair.settle();
    let remote = pair.callee.call().expect("the callee knows the call");
    pair.shake_hands(call, remote);
    for session in [
        pair.caller.engine.session(call).expect("media"),
        pair.callee.engine.session(remote).expect("media"),
    ] {
        assert!(
            session.is_encrypted(),
            "the handshake presented a certificate the offer never named"
        );
    }
    assert_eq!(failures(&pair), []);
}

/// Carry every handshake record either end owes the other, both ways, until
/// nothing more moves.
#[cfg(feature = "dtls")]
fn cross_records(pair: &mut Pair, call: CallHandle, remote: CallHandle) {
    for _ in 0..32 {
        let mut crossed = false;
        while let Some((_, _, mut record)) = pair.callee.engine.poll_transmit(pair.now) {
            crossed = true;
            let mut session = pair.caller.engine.session(call).expect("media");
            session.receive(&mut record, callee_media(), pair.now);
        }
        while let Some((_, _, mut record)) = pair.caller.engine.poll_transmit(pair.now) {
            crossed = true;
            let mut session = pair.callee.engine.session(remote).expect("media");
            session.receive(&mut record, caller_media(), pair.now);
        }
        pair.caller.drain(pair.now, false);
        pair.callee.drain(pair.now, false);
        if !crossed {
            return;
        }
    }
}

#[cfg(feature = "dtls")]
#[test]
fn a_far_end_that_starts_its_handshake_over_is_answered_and_the_call_moves_to_the_new_keys() {
    // RFC 6347 §4.2.8. Asterisk starts a new association on a hold and on the
    // resume; the running connection took its ClientHello and ignored it, the
    // far end waited for a handshake that never came, and the call went silent
    let (mut pair, call, remote) = dtls_call();
    pair.shake_hands(call, remote);
    let before = tone_after(&mut pair, call, remote);
    assert!(
        before > 4_000,
        "the tone came through at {before} to begin with"
    );

    // the callee is the client here, which is the end that starts over
    assert!(
        pair.callee
            .engine
            .session(remote)
            .expect("media")
            .start_the_handshake_over(pair.now)
    );
    cross_records(&mut pair, call, remote);

    let secured = |stack: &Stack| {
        stack
            .media_events()
            .iter()
            .filter(|event| matches!(event, MediaEvent::Secured { .. }))
            .count()
    };
    assert_eq!(
        secured(&pair.caller),
        2,
        "this end never took the new association"
    );
    assert_eq!(secured(&pair.callee), 2, "the far end never finished it");
    assert_eq!(failures(&pair), []);
    let after = tone_after(&mut pair, call, remote);
    assert!(
        after > 4_000,
        "the two ends came out of the new association on different keys: {after}"
    );
}

#[cfg(feature = "dtls")]
#[test]
fn a_new_association_that_is_never_finished_leaves_the_call_on_the_one_it_had() {
    // the prompt for one arrives in the clear, so anybody who can send from
    // the far end's address can make one begin: it must neither interrupt the
    // call nor be reported as the call failing when it comes to nothing
    let (mut pair, call, remote) = dtls_call();
    pair.shake_hands(call, remote);
    assert!(
        pair.callee
            .engine
            .session(remote)
            .expect("media")
            .start_the_handshake_over(pair.now)
    );
    // the ClientHello arrives, and nothing after it ever does
    let (_, _, mut hello) = pair
        .callee
        .engine
        .poll_transmit(pair.now)
        .expect("a ClientHello");
    {
        let mut session = pair.caller.engine.session(call).expect("media");
        assert_eq!(
            session.receive(&mut hello, callee_media(), pair.now),
            Arrival::Handshake
        );
    }
    while pair.caller.engine.poll_transmit(pair.now).is_some() {}
    while pair.callee.engine.poll_transmit(pair.now).is_some() {}

    let during = tone_after(&mut pair, call, remote);
    assert!(
        during > 4_000,
        "the half-begun association cut the call: {during}"
    );

    // long past any handshake's budget
    for _ in 0..40 {
        pair.now += Duration::from_secs(5);
        pair.caller.engine.handle_timeout(pair.now);
        pair.callee.engine.handle_timeout(pair.now);
        while pair.caller.engine.poll_transmit(pair.now).is_some() {}
        while pair.callee.engine.poll_transmit(pair.now).is_some() {}
    }
    pair.caller.drain(pair.now, false);
    pair.callee.drain(pair.now, false);
    assert!(
        !failures(&pair)
            .iter()
            .any(|(_, error)| matches!(error, MediaError::DtlsHandshake)),
        "an association nobody finished was reported as the call failing: {:?}",
        failures(&pair)
    );
    let after = tone_after(&mut pair, call, remote);
    assert!(after > 4_000, "the call did not stay on its keys: {after}");
}

// -- a local conference of two calls -----------------------------------------

fn carol_sip() -> SocketAddr {
    "192.0.2.3:5060".parse().expect("an address")
}

fn carol_media() -> SocketAddr {
    "192.0.2.3:40004".parse().expect("an address")
}

/// Move everything one stack wants to write to the other, drain both, and
/// keep going until nothing more happens — [`Pair::settle`], generalised to
/// whichever two stacks a local-conference test needs settled: a call joined
/// to another still has to be placed against, and torn down against, a third
/// stack `Pair` itself never carries.
fn settle_two(a: &mut Stack, b: &mut Stack, answer_b: bool, now: Instant) {
    for _ in 0..12 {
        let from_a = a.outbound();
        let from_b = b.outbound();
        if from_a.is_empty() && from_b.is_empty() {
            break;
        }
        for datagram in from_a {
            b.deliver(&datagram, a.local, now);
        }
        for datagram in from_b {
            a.deliver(&datagram, b.local, now);
        }
        a.drain(now, false);
        b.drain(now, answer_b);
    }
}

/// Place a call from `caller` to `callee` and take it all the way to
/// confirmed — [`Pair::connect`], generalised the same way [`settle_two`] is:
/// a local conference joins two calls this end placed to two different
/// stacks, and `Pair` only ever knows about one.
fn connect_two(
    from: &mut Stack,
    to: &mut Stack,
    to_user: &str,
    now: Instant,
) -> (CallHandle, CallHandle) {
    let account = from.account("alice", to.local);
    let _ = to.account(to_user, from.local);
    let near = from
        .engine
        .place(
            &mut from.agent,
            account,
            OutgoingCall::new(uri(&format!("sip:{to_user}@example.com"))).to_address(UDP, to.local),
            from.media,
            now,
        )
        .expect("the INVITE goes");
    from.drain(now, false);
    settle_two(from, to, true, now);
    let far = to.call().expect("the far end heard the INVITE");
    (near, far)
}

/// This end, with two active calls to two other stacks — what
/// [`MediaEngine::join`] needs something to join.
struct Trio {
    me: Stack,
    call_a: CallHandle,
    bob: Stack,
    bob_call: CallHandle,
    carol: Stack,
    call_b: CallHandle,
    carol_call: CallHandle,
    now: Instant,
}

impl Trio {
    /// Two calls placed and confirmed, on PCMU so that every session in this
    /// trio shares a sample rate and a frame length without asking for it —
    /// [`MediaEngine::join`] would refuse the pair otherwise.
    fn connected() -> Self {
        let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
        let now = Instant::now();
        let mut me = Stack::new(11, caller_sip(), caller_media(), catalog.clone(), now);
        let mut bob = Stack::new(22, callee_sip(), callee_media(), catalog.clone(), now);
        let mut carol = Stack::new(33, carol_sip(), carol_media(), catalog, now);
        let (call_a, bob_call) = connect_two(&mut me, &mut bob, "bob", now);
        let (call_b, carol_call) = connect_two(&mut me, &mut carol, "carol", now);
        Self {
            me,
            call_a,
            bob,
            bob_call,
            carol,
            call_b,
            carol_call,
            now,
        }
    }

    /// The same, already joined.
    fn joined(mut self) -> Self {
        self.me
            .engine
            .join(self.call_a, self.call_b)
            .expect("two calls on the same catalogue join");
        self
    }

    /// One frame each way: `bob_tone`/`carol_tone` into their own legs
    /// (silence where `None`), mixed through the pair with this end's
    /// microphone silent, delivered back to whichever far end
    /// [`MediaEngine::mix`] said was owed one, and what each of them played
    /// once it arrived.
    fn frame(
        &mut self,
        bob_tone: Option<&[i16]>,
        carol_tone: Option<&[i16]>,
    ) -> (Vec<i16>, Vec<i16>) {
        let frame = self
            .me
            .engine
            .session(self.call_a)
            .expect("call a has media")
            .frame_samples();
        let silence = vec![0_i16; frame];
        let bob_samples = bob_tone.unwrap_or(&silence);
        let carol_samples = carol_tone.unwrap_or(&silence);

        if let Some(mut datagram) = self
            .bob
            .engine
            .session(self.bob_call)
            .expect("bob's media")
            .capture(bob_samples, self.now)
            .expect("bob's frame encodes")
            .map(|datagram| datagram.payload.to_vec())
        {
            self.me
                .engine
                .session(self.call_a)
                .expect("call a's media")
                .receive(&mut datagram, callee_media(), self.now);
        }
        if let Some(mut datagram) = self
            .carol
            .engine
            .session(self.carol_call)
            .expect("carol's media")
            .capture(carol_samples, self.now)
            .expect("carol's frame encodes")
            .map(|datagram| datagram.payload.to_vec())
        {
            self.me
                .engine
                .session(self.call_b)
                .expect("call b's media")
                .receive(&mut datagram, carol_media(), self.now);
        }

        let mut local_out = vec![0_i16; frame];
        let outcome = self
            .me
            .engine
            .mix(self.call_a, &silence, &mut local_out, self.now)
            .expect("the pair mixes");

        let mut heard_by_bob = vec![0_i16; frame];
        if let Some((_, mut payload)) = outcome.to_a {
            let mut session = self.bob.engine.session(self.bob_call).expect("bob's media");
            session.receive(&mut payload, caller_media(), self.now);
            session.playback(&mut heard_by_bob);
        }
        let mut heard_by_carol = vec![0_i16; frame];
        if let Some((_, mut payload)) = outcome.to_b {
            let mut session = self
                .carol
                .engine
                .session(self.carol_call)
                .expect("carol's media");
            session.receive(&mut payload, caller_media(), self.now);
            session.playback(&mut heard_by_carol);
        }
        self.now += TICK;
        (heard_by_bob, heard_by_carol)
    }
}

/// The whole point of [`crate::join`]: a tone put into one leg of a joined
/// pair comes out of the other's wire, and the reverse holds at the same
/// time — two different tones, out of step with each other, so a mix that
/// silently swapped the two legs would still be caught.
#[test]
fn a_tone_into_one_leg_of_a_joined_pair_comes_out_the_other_and_the_reverse_too() {
    let mut trio = Trio::connected().joined();
    let frame = trio
        .me
        .engine
        .session(trio.call_a)
        .expect("call a has media")
        .frame_samples();
    let mut bob_phase = 0_u32;
    let mut carol_phase = 500_u32;
    let (mut heard_by_bob, mut heard_by_carol) = (Vec::new(), Vec::new());
    for _ in 0..6 {
        let mut bob_tone = vec![0_i16; frame];
        tone(&mut bob_tone, 8_000, &mut bob_phase);
        let mut carol_tone = vec![0_i16; frame];
        tone(&mut carol_tone, 8_000, &mut carol_phase);
        (heard_by_bob, heard_by_carol) = trio.frame(Some(&bob_tone), Some(&carol_tone));
    }

    assert!(
        loudness(&heard_by_carol) > 1_000,
        "the tone sent into call a did not come out of call b's wire: {heard_by_carol:?}"
    );
    assert!(
        loudness(&heard_by_bob) > 1_000,
        "the tone sent into call b did not come out of call a's wire: {heard_by_bob:?}"
    );
}

/// [`MediaEngine::leave`] un-pairs both calls, whichever one it was asked
/// about, and [`MediaEngine::mix`] refuses a pair that no longer exists
/// rather than mixing one leg against itself.
#[test]
fn leave_un_pairs_both_calls_and_mix_then_refuses_them() {
    let mut trio = Trio::connected().joined();
    assert_eq!(trio.me.engine.joined_with(trio.call_a), Some(trio.call_b));
    assert_eq!(trio.me.engine.joined_with(trio.call_b), Some(trio.call_a));

    let partner = trio
        .me
        .engine
        .leave(trio.call_a)
        .expect("call a was joined");
    assert_eq!(partner, trio.call_b);
    assert_eq!(trio.me.engine.joined_with(trio.call_a), None);
    assert_eq!(
        trio.me.engine.joined_with(trio.call_b),
        None,
        "leave un-pairs both calls, not only the one it was asked about"
    );
    assert_eq!(
        trio.me.engine.leave(trio.call_a).unwrap_err(),
        MediaError::NotJoined,
        "a call already left has nothing more to leave"
    );

    let frame = trio
        .me
        .engine
        .session(trio.call_a)
        .expect("call a kept its media")
        .frame_samples();
    let mut local_out = vec![0_i16; frame];
    let refused = trio
        .me
        .engine
        .mix(trio.call_a, &vec![0_i16; frame], &mut local_out, trio.now);
    assert_eq!(refused.unwrap_err(), MediaError::NotJoined);

    // each call still carries its own audio directly, exactly as an unjoined
    // call always has
    let mut played = vec![0_i16; frame];
    trio.me
        .engine
        .session(trio.call_a)
        .expect("call a's media")
        .playback(&mut played);
}

/// A call that hangs up while it is joined takes the pairing down with it —
/// not the partner's own call, and not the partner's own media, which keeps
/// running exactly as an unjoined call's always has.
#[test]
fn a_call_that_hangs_up_while_joined_leaves_the_mix_cleanly() {
    let mut trio = Trio::connected().joined();

    trio.carol
        .agent
        .hangup(trio.carol_call, trio.now)
        .expect("the BYE");
    trio.carol.drain(trio.now, false);
    settle_two(&mut trio.carol, &mut trio.me, false, trio.now);

    assert!(
        trio.me.engine.session(trio.call_b).is_none(),
        "call b's media outlived the call it belonged to"
    );
    assert_eq!(
        trio.me.engine.joined_with(trio.call_a),
        None,
        "a hung-up partner leaves the pair, not only its own call"
    );
    assert!(
        trio.me
            .media_events()
            .into_iter()
            .any(|event| matches!(event, MediaEvent::Unjoined)),
        "call a was never told its partner was gone"
    );

    // call a's own session outlived its partner and still carries audio
    // directly, exactly as an unjoined call always has
    let frame = trio
        .me
        .engine
        .session(trio.call_a)
        .expect("call a's media outlived its partner")
        .frame_samples();
    let mut played = vec![0_i16; frame];
    trio.me
        .engine
        .session(trio.call_a)
        .expect("call a's media")
        .playback(&mut played);

    let refused = trio.me.engine.mix(
        trio.call_a,
        &vec![0_i16; frame],
        &mut vec![0_i16; frame],
        trio.now,
    );
    assert_eq!(refused.unwrap_err(), MediaError::NotJoined);
}

/// [`MediaEngine::join`] refuses a pair whose two sessions decode at
/// different sample rates, proven against a real codec mismatch rather than
/// only against the same-call and already-joined refusals above — so that a
/// broken check in [`MediaEngine::join`] (the `&&` turned into an `||`, say,
/// or the check dropped outright) fails a test rather than passing silently
/// straight through to [`mix_two`] reading the shorter session's buffer past
/// its own end.
#[test]
fn join_refuses_two_calls_that_do_not_share_a_sample_rate() {
    let now = Instant::now();
    let mut me = Stack::new(
        51,
        caller_sip(),
        caller_media(),
        CodecCatalog::with_order(&["PCMU", "G722"]).expect("an order"),
        now,
    );
    let mut bob = Stack::new(
        52,
        callee_sip(),
        callee_media(),
        CodecCatalog::with_order(&["PCMU"]).expect("an order"),
        now,
    );
    let mut carol = Stack::new(
        53,
        carol_sip(),
        carol_media(),
        CodecCatalog::with_order(&["G722"]).expect("an order"),
        now,
    );
    // bob and carol each support only one of the two codecs `me` offers, so
    // the codec each call settles on is forced by the intersection alone,
    // whatever order `me`'s own catalogue prefers them in
    let (call_a, _bob_call) = connect_two(&mut me, &mut bob, "bob", now);
    let (call_b, _carol_call) = connect_two(&mut me, &mut carol, "carol", now);

    assert_eq!(
        me.engine
            .session(call_a)
            .expect("call a has media")
            .sample_rate(),
        8_000,
        "bob's own leg did not settle on PCMU"
    );
    assert_eq!(
        me.engine
            .session(call_b)
            .expect("call b has media")
            .sample_rate(),
        16_000,
        "carol's own leg did not settle on G722"
    );

    assert_eq!(
        me.engine.join(call_a, call_b).unwrap_err(),
        MediaError::JoinIncompatible
    );
    assert_eq!(
        me.engine.joined_with(call_a),
        None,
        "a refused join must not leave either call believing it is paired"
    );
}

/// A5: a joined call's own recording keeps the conference it was actually
/// in, not only the two legs it would have carried alone — proven by a far
/// end this call never dialled (carol, joined onto call a through call b)
/// showing up in call a's own file, while call a's direct far end (bob) and
/// this end's own microphone both stay silent throughout.
#[test]
fn a_joined_calls_recording_keeps_a_far_end_it_never_dialled() {
    let mut trio = Trio::connected().joined();
    let frame = trio
        .me
        .engine
        .session(trio.call_a)
        .expect("call a has media")
        .frame_samples();

    // ten frames before the recording starts, so the de-jitter buffer is
    // past its start-up delay before anything that follows is measured
    for _ in 0..10 {
        trio.frame(None, None);
    }

    let file = Buffer::new();
    trio.me
        .engine
        .session(trio.call_a)
        .expect("call a has media")
        .start_recording(Box::new(file.clone()))
        .expect("the recording starts");

    let mut carol_phase = 0_u32;
    for _ in 0..10 {
        let mut carol_tone = vec![0_i16; frame];
        tone(&mut carol_tone, 8_000, &mut carol_phase);
        // bob stays silent (`None`) and so does this end's own microphone
        // (`Trio::frame`'s own `mic`, always silent) — anything loud enough
        // to find in call a's recording had to cross from carol by way of
        // the pair `MediaEngine::mix` is driving
        trio.frame(None, Some(&carol_tone));
    }

    let mut session = trio.me.engine.session(trio.call_a).expect("call a's media");
    assert!(session.is_recording());
    session.stop_recording().expect("the recording stops");
    drop(session);

    let wav = file.contents();
    let audio: Vec<i16> = wav
        .get(44..)
        .unwrap_or_default()
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    assert!(
        loudness(&audio) > 1_000,
        "call a's own recording is not loud enough to hold carol's audio, \
         which reaches it only by way of the joined pair: {audio:?}"
    );
}

// -- behind a NAT: what a STUN server said, in the Contact and the offer ------

/// Where the lab's STUN server is, as far as these tests are concerned.
#[cfg(feature = "stun")]
fn stun_server() -> SocketAddr {
    "198.51.100.1:3478".parse().expect("an address")
}

/// What a NAT in front of the caller shows the world for each of its two
/// sockets: another host, and another port for each.
#[cfg(feature = "stun")]
fn behind_the_nat(local: SocketAddr) -> SocketAddr {
    let port = if local == caller_sip() {
        41_000
    } else {
        41_002
    };
    SocketAddr::new("203.0.113.7".parse().expect("an address"), port)
}

/// Map the caller's two sockets against a STUN server that answers every
/// request with [`behind_the_nat`], and hand each answer to where it goes:
/// the signalling socket's to the user agent, which moves the accounts onto
/// it, and the media socket's back to the test, for the call it places.
#[cfg(feature = "stun")]
fn map_the_caller(pair: &mut Pair) -> SocketAddr {
    use crate::nat::tests::answer;
    use crate::{Keep, MappingEvent, MappingState};

    let mut mappings = pair.caller.engine.mappings(stun_server());
    mappings.map(caller_sip(), Keep::Refreshed, pair.now);
    mappings.map(caller_media(), Keep::Once, pair.now);
    while let Some(request) = mappings.poll_transmit() {
        assert_eq!(request.destination, stun_server());
        let reply = answer(&request.payload, behind_the_nat(request.local));
        assert!(mappings.receive(request.local, stun_server(), &reply, pair.now));
    }
    let mut media = None;
    while let Some(event) = mappings.poll_event() {
        match event {
            MappingEvent::Learned { local, public } if local == caller_sip() => {
                assert_eq!(
                    pair.caller.agent.readdress(UDP, local, public, pair.now),
                    1,
                    "the account moves"
                );
            }
            MappingEvent::Learned { local, public } if local == caller_media() => {
                media = Some(public);
            }
            other => panic!("nothing else was asked: {other:?}"),
        }
    }
    assert_eq!(
        mappings.state(caller_media()),
        Some(MappingState::Mapped(behind_the_nat(caller_media())))
    );
    media.expect("the media socket was answered")
}

/// The `Contact` of the first request in `datagrams` whose method is `method`.
#[cfg(feature = "stun")]
fn contact_of_request(datagrams: &[Vec<u8>], method: &str) -> Option<String> {
    datagrams.iter().find_map(|datagram| {
        if !datagram.starts_with(method.as_bytes()) {
            return None;
        }
        let mut scratch = ParseScratch::new();
        let message = sipral_core::msg::parse(datagram, &mut scratch, ParseMode::Lenient).ok()?;
        message
            .header(sipral_core::msg::HeaderName::Contact)
            .map(|value| String::from_utf8_lossy(value).into_owned())
    })
}

/// Place the caller's call on the public address its media socket was given,
/// capturing the INVITE on its way, and take the call all the way to
/// confirmed.
#[cfg(feature = "stun")]
fn place_from_behind_the_nat(pair: &mut Pair, catalog: CodecCatalog) -> (CallHandle, Vec<Vec<u8>>) {
    let account = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("bob", caller_sip());
    let public = map_the_caller(pair);
    let media = CallMedia::new(catalog, MediaConfig::default()).public_address(public);
    let placed = pair
        .caller
        .engine
        .place_with(
            &mut pair.caller.agent,
            account,
            OutgoingCall::new(uri("sip:bob@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            media,
            pair.now,
        )
        .expect("the INVITE goes");
    pair.caller.drain(pair.now, false);
    let invite = pair.caller.outbound();
    for datagram in &invite {
        pair.callee.deliver(datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, true);
    pair.settle();
    (placed, invite)
}

#[cfg(feature = "stun")]
#[test]
fn what_the_stun_server_said_is_the_contact_and_the_media_address_the_far_end_is_given() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog.clone());
    let (call, invite) = place_from_behind_the_nat(&mut pair, catalog);
    let remote = pair.callee.call().expect("the callee's side of the call");

    // the signalling socket's answer, in the Contact of the INVITE: what the
    // far end sends its BYE and its re-INVITEs to
    assert_eq!(
        contact_of_request(&invite, "INVITE").as_deref(),
        Some("<sip:alice@203.0.113.7:41000>")
    );

    // the media socket's, in `c=` and `m=`: what the far end sends its audio
    // to. Read off the INVITE the callee was handed, since that is what a far
    // end with no NAT helper acts on
    let offer = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer")
        .to_string();
    assert!(offer.contains("c=IN IP4 203.0.113.7\r\n"), "{offer}");
    assert!(offer.contains("m=audio 41002 "), "{offer}");
    assert!(
        !offer.contains("192.0.2.1"),
        "the private address leaked into the offer: {offer}"
    );
    // one mapping describes one port, so the call asks for one
    assert!(offer.contains("a=rtcp-mux\r\n"), "{offer}");

    // and the far end's session sends there. This one's catalogue does not
    // multiplex, so it declined the offer's `a=rtcp-mux` and sends its reports
    // to the public port plus one — which a NAT that keeps ports in step maps
    // and another does not, and what is lost then is the reports and never
    // the audio (`CallMedia::public_address`)
    let theirs = pair
        .callee
        .engine
        .session(remote)
        .expect("the callee's media");
    assert_eq!(theirs.destination(), behind_the_nat(caller_media()));
    assert_eq!(
        theirs.control_destination(),
        Some(SocketAddr::new(
            behind_the_nat(caller_media()).ip(),
            behind_the_nat(caller_media()).port() + 1
        ))
    );
    drop(theirs);

    // while this end's own session stays on the socket it is bound to: the
    // public address is what it is called, not where it listens
    let ours = pair
        .caller
        .engine
        .session(call)
        .expect("the caller's media");
    assert_eq!(ours.destination(), callee_media());
}

#[cfg(feature = "stun")]
#[test]
fn a_hold_after_the_mapping_moved_carries_the_new_contact_and_keeps_the_public_media() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog.clone());
    let (call, _) = place_from_behind_the_nat(&mut pair, catalog);

    // the NAT let the signalling mapping go and made another: the next
    // re-INVITE is the target refresh (RFC 3261 §12.2) that tells the far end
    let moved: SocketAddr = "203.0.113.7:52000".parse().expect("an address");
    assert_eq!(
        pair.caller
            .agent
            .readdress(UDP, behind_the_nat(caller_sip()), moved, pair.now),
        1,
        "the account moves"
    );
    let _ = pair.caller.outbound();
    pair.caller
        .agent
        .hold(call, pair.now)
        .expect("a confirmed call can be held");
    pair.caller.drain(pair.now, false);
    let reinvite = pair.caller.outbound();
    assert_eq!(
        contact_of_request(&reinvite, "INVITE").as_deref(),
        Some("<sip:alice@203.0.113.7:52000>")
    );
    for datagram in &reinvite {
        pair.callee.deliver(datagram, caller_sip(), pair.now);
    }
    pair.callee.drain(pair.now, true);
    pair.settle();

    // the hold is a re-offer, so it is read off the session change and not
    // off the INVITE that opened the call
    let (_, held) = last_described(&pair.callee).expect("the callee saw the hold");
    let held = held.to_string();
    assert!(held.contains("a=sendonly"), "that was not the hold: {held}");
    assert!(held.contains("c=IN IP4 203.0.113.7\r\n"), "{held}");
    assert!(held.contains("m=audio 41002 "), "{held}");
}

#[cfg(all(feature = "stun", feature = "ice"))]
#[test]
fn a_public_address_is_the_reflexive_candidate_and_the_default_one() {
    let catalog = CodecCatalog::with_order(&["PCMU"])
        .expect("an order")
        .with_ice(crate::IcePolicy::Offered);
    let mut pair = Pair::new(catalog.clone());
    let _ = place_from_behind_the_nat(&mut pair, catalog);
    let described = pair
        .callee
        .offer_received()
        .expect("the callee saw an offer");
    let offer = one_stream(&described);
    let candidates: Vec<&str> = offer
        .attributes
        .iter()
        .filter(|attribute| attribute.name == "candidate")
        .filter_map(|attribute| attribute.value.as_deref())
        .collect();
    assert_eq!(
        candidates.len(),
        2,
        "a host and a reflexive: {candidates:?}"
    );
    assert!(
        candidates[0].contains("192.0.2.1 40000 typ host"),
        "{}",
        candidates[0]
    );
    assert!(
        candidates[1].contains("203.0.113.7 41002 typ srflx raddr 192.0.2.1 rport 40000"),
        "{}",
        candidates[1]
    );
    // RFC 8839 §4.2.1.2 puts the reflexive one in `c=` and `m=`, and a peer
    // running RFC 8839 §4.2.5's mismatch check finds it among the candidates
    let text = described.to_string();
    assert!(text.contains("c=IN IP4 203.0.113.7\r\n"), "{text}");
    assert!(text.contains("m=audio 41002 "), "{text}");
    let remote = sipral_nat::ice::parse_remote(&described, &offer).expect("ICE attributes");
    assert!(
        !sipral_nat::ice::ice_mismatch(&described, &offer, &remote, true),
        "the default destination is one of the candidates"
    );
}

#[cfg(feature = "stun")]
#[test]
fn an_answer_from_behind_the_nat_and_its_answer_to_a_later_offer_name_the_public_address() {
    // the other side of the call: the end behind the NAT is the one called,
    // so the public address goes into the answer, and into the answer this
    // engine writes itself when the far end offers again
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("an order");
    let mut pair = Pair::new(catalog.clone());
    let incoming = pair.ring();
    let public: SocketAddr = "203.0.113.9:41010".parse().expect("an address");
    let media = CallMedia::new(catalog, MediaConfig::default()).public_address(public);
    pair.callee
        .engine
        .answer_with(
            &mut pair.callee.agent,
            incoming,
            callee_media(),
            media,
            pair.now,
        )
        .expect("the answer goes");
    pair.callee.drain(pair.now, false);
    pair.settle();

    let answer = pair
        .caller
        .answer_received()
        .expect("the caller saw the answer")
        .to_string();
    assert!(answer.contains("c=IN IP4 203.0.113.9\r\n"), "{answer}");
    assert!(answer.contains("m=audio 41010 "), "{answer}");
    assert!(
        !answer.contains("192.0.2.2"),
        "the private address leaked: {answer}"
    );
    let call = pair.caller.call().expect("the caller's side of the call");
    assert_eq!(
        pair.caller
            .engine
            .session(call)
            .expect("the caller's media")
            .destination(),
        public
    );

    // a codec change is a re-offer the user agent has no answer of its own
    // for, so the callee's engine writes that answer, and it must not fall
    // back to the address the socket is bound to
    let _ = change_codecs(&mut pair, call, &["PCMA"]);
    let (_, answered) = last_described(&pair.caller).expect("the caller saw the change");
    let answered = answered.to_string();
    assert!(
        answered.contains("a=rtpmap:8 PCMA"),
        "not that answer: {answered}"
    );
    assert!(answered.contains("c=IN IP4 203.0.113.9\r\n"), "{answered}");
    assert!(answered.contains("m=audio 41010 "), "{answered}");
}

/// The signalling side of the same story: an account whose `Contact` has
/// already moved to the address a STUN answer gave (`UserAgent::readdress`,
/// what a mapping learned before the call arrived writes) is called, and the
/// 2xx it answers with has to carry that address too, not the one the socket
/// is bound to underneath it — the far end's ACK, and everything else built
/// from this dialog's `Contact`, goes exactly where this header says.
#[test]
fn a_call_answered_after_the_account_moved_behind_a_nat_writes_the_public_contact() {
    let catalog = CodecCatalog::with_order(&["PCMU"]).expect("an order");
    let mut pair = Pair::new(catalog);
    let incoming = pair.ring();
    let public: SocketAddr = "203.0.113.9:41010".parse().expect("an address");
    assert_eq!(
        pair.callee
            .agent
            .readdress(UDP, callee_sip(), public, pair.now),
        1,
        "the account moves before the call is answered"
    );
    pair.callee
        .engine
        .answer(&mut pair.callee.agent, incoming, callee_media(), pair.now)
        .expect("the answer goes");
    let response = pair
        .callee
        .outbound()
        .into_iter()
        .find(|datagram| datagram.starts_with(b"SIP/2.0 200"))
        .expect("the 200 OK went out");
    let mut scratch = ParseScratch::new();
    let message = sipral_core::msg::parse(&response, &mut scratch, ParseMode::Lenient)
        .expect("a well-formed response");
    let contact = message
        .header(sipral_core::msg::HeaderName::Contact)
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .expect("a Contact on the 2xx");
    assert!(
        contact.contains("203.0.113.9:41010"),
        "the 200 OK's Contact still names the address behind the NAT: {contact}"
    );
}

// -- an earpiece on a clock of its own ----------------------------------------

/// What an earpiece heard of the lab's cadenced tone through the facade, as
/// `interop/harness` counts it.
#[derive(Debug, Default)]
struct Earpiece {
    /// Frames taken.
    played: u32,
    /// Frames played as silence because the buffer had nothing, once
    /// playout had begun.
    dry: u32,
    /// Of those, the frames of runs that neither began straight after the
    /// tone nor ended straight into it: silence heard in the far end's
    /// own pause.
    dry_in_pauses: u32,
    /// Runs of that silence that cut the tone off.
    cuts: u32,
    /// The deepest the buffer was after any frame.
    deepest: Duration,
}

/// Sixty frames of the lab's tone and thirty of silence, over and over,
/// captured by the caller on the network's clock and played by the callee
/// on an earpiece `skew_ppm` fast (or slow), `per_callback` frames at a
/// time, each callback up to three milliseconds either side of its tick —
/// `sipral-rtp`'s own simulation of `scripts/lab.sh drift`, carried through
/// the codec, the concealment and the facade's own detector of speech,
/// whose verdicts are the ones the buffer is actually given.
fn earpiece_against(skew_ppm: i64, pulls: u32, per_callback: u32) -> (crate::Quality, Earpiece) {
    const FRAME_US: i64 = 20_000;
    let mut pair = Pair::new(CodecCatalog::with_order(&["PCMU"]).expect("an order"));
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee knows the call");
    let start = pair.now;
    let at = |us: i64| start + Duration::from_micros(u64::try_from(us).unwrap_or(0));

    let pull_every = FRAME_US * 1_000_000 / (1_000_000 + skew_ppm);
    let mut next_capture = 0_i64;
    let mut tick = pull_every * i64::from(per_callback);
    let (mut sent, mut pulled) = (0_u32, 0_u32);
    let mut phase = 0_u32;
    let mut samples = vec![0_i16; 160];
    let mut heard = Earpiece::default();
    // whether playout has begun, whether the frame before the dry run going
    // on now was the tone, and how long that run is
    let (mut started, mut before_was_tone, mut run) = (false, false, 0_u32);
    while pulled < pulls {
        let wobble = (i64::from(pulled) * 7_919 % 7 - 3) * 1_000;
        if next_capture + FRAME_US / 2 < tick + wobble {
            if sent % 90 < 60 {
                tone(&mut samples, 8_000, &mut phase);
            } else {
                samples.fill(0);
            }
            let datagram = pair
                .caller
                .engine
                .session(call)
                .expect("media")
                .capture(&samples, at(next_capture))
                .expect("it encodes")
                .map(|out| out.payload.to_vec());
            if let Some(mut datagram) = datagram {
                pair.callee.engine.session(remote).expect("media").receive(
                    &mut datagram,
                    caller_media(),
                    at(next_capture + FRAME_US / 2),
                );
            }
            sent += 1;
            next_capture += FRAME_US;
            continue;
        }
        let mut session = pair.callee.engine.session(remote).expect("media");
        for _ in 0..per_callback {
            let mut played = vec![0_i16; session.frame_samples()];
            let outcome = session.playback(&mut played);
            let tone_heard = outcome == Playback::Packet && loudness(&played) >= 500;
            heard.played += 1;
            if outcome == Playback::Silence && started {
                heard.dry += 1;
                run += 1;
            } else {
                if run > 0 {
                    if before_was_tone || tone_heard {
                        heard.cuts += 1;
                    } else {
                        heard.dry_in_pauses += run;
                    }
                    run = 0;
                }
                started |= outcome == Playback::Packet;
                before_was_tone = tone_heard;
            }
            heard.deepest = heard
                .deepest
                .max(session.statistics(at(next_capture)).quality.delay);
            pulled += 1;
        }
        drop(session);
        tick += pull_every * i64::from(per_callback);
    }
    let quality = pair
        .callee
        .engine
        .session(remote)
        .expect("media")
        .statistics(at(next_capture))
        .quality;
    (quality, heard)
}

/// Every clock a real device runs on, and twice the widest any may run at
/// and meet its bus's specification (USB 2.0 §7.1.11, ±0.25 %), and twice
/// that again: an earpiece fast or slow by any of them, taking one frame a
/// callback or two, never plays a frame of silence where the far end was
/// sending, in the tone or in its pauses, once the facade's own detector
/// is the one telling the buffer which is which.
#[test]
fn an_earpiece_on_any_clock_a_device_runs_never_runs_dry() {
    for per_callback in [1, 2] {
        for skew in [-10_000, -5_000, 500, 2_500, 5_000, 10_000] {
            let (quality, heard) = earpiece_against(skew, 6_000, per_callback);
            assert_eq!(
                (heard.dry, heard.cuts),
                (0, 0),
                "{skew} ppm, {per_callback} a callback: {heard:?}"
            );
            assert_eq!(
                quality.underruns, 0,
                "{skew} ppm, {per_callback} a callback"
            );
            assert!(
                heard.deepest <= Duration::from_millis(100),
                "{skew} ppm, {per_callback} a callback: {:?} held",
                heard.deepest
            );
        }
    }
}

/// An earpiece half as fast again as the far end is no device's clock but
/// a stream opened at the wrong rate. Through the facade it plays what it
/// can with no more than a tenth of a second in hand, and every frame it
/// played as nothing is counted, frame for frame, as an under-run the
/// call's loss rate takes in: the call says it is in trouble, where it
/// used to hold a third of a second of delay and say nothing.
#[test]
fn an_earpiece_past_any_real_clock_is_held_to_its_budget_and_says_so() {
    for per_callback in [1, 2] {
        let (quality, heard) = earpiece_against(500_000, 6_000, per_callback);
        assert!(
            heard.deepest <= Duration::from_millis(100),
            "{per_callback} a callback: {:?} held",
            heard.deepest
        );
        assert!(heard.dry > 1_000, "{per_callback} a callback: {heard:?}");
        assert_eq!(
            quality.underruns,
            u64::from(heard.dry),
            "{per_callback} a callback"
        );
        assert!(
            quality.loss_rate >= 0.05,
            "{per_callback} a callback: a loss rate of {}",
            quality.loss_rate
        );
    }
}

/// A call's two diagnostic artefacts leave redacted: the D1 record without
/// the address the far end signalled from, and the D2 recording without the
/// caller's user part or that address, while the same recording exported
/// plainly still has both — which is what makes the absence mean anything.
#[cfg(feature = "redaction")]
#[test]
fn a_calls_record_and_recording_are_handed_over_redacted() {
    let mut pair = Pair::new(CodecCatalog::new());
    pair.callee.agent.start_recording(None);
    let _ = pair.connect();
    let call = pair.callee.call().expect("the callee has the call");
    let caller_address = caller_sip().ip().to_string();

    let mut redactor = crate::Redactor::new(crate::RedactionMode::Hash(b"org key".to_vec()));
    let record = crate::redacted_call_record(&mut pair.callee.agent, call, &mut redactor)
        .expect("the call has a record");
    assert!(record.contains("\"decisions\":[{"), "{record}");
    assert!(!record.contains(&caller_address), "{record}");
    let identity = pair
        .callee
        .agent
        .call_identity(call)
        .expect("the call is known");
    let plain_record = pair
        .callee
        .agent
        .endpoint()
        .call_record(&sipral_core::dialog::CallId::new(&identity.call_id))
        .map(sipral_core::diag::Record::to_json)
        .expect("the record, plain");
    assert!(plain_record.contains(&caller_address), "{plain_record}");

    let recording = pair
        .callee
        .agent
        .stop_recording()
        .expect("a recording was running")
        .expect("it finished")
        .clone();
    let contains = |haystack: &[u8], needle: &[u8]| {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    };
    let plain = sipral_diag::export(&recording, None).expect("the plain export");
    assert!(contains(&plain, b"alice"));
    assert!(contains(&plain, caller_address.as_bytes()));
    let redacted = crate::redacted_recording(&recording, redactor).expect("the redacted export");
    assert!(
        contains(&redacted, b"INVITE sip:"),
        "the messages are still there"
    );
    assert!(!contains(&redacted, b"alice"));
    assert!(!contains(&redacted, caller_address.as_bytes()));
}
