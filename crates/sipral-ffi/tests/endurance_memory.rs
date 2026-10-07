// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Whether a stack that keeps taking calls and renewing its registration
//! holds on to anything once each call is over.
//!
//! The endurance soak (`scripts/soak.sh endurance`) runs one call after
//! another for a day against the lab's Asterisk and reads the process's
//! resident memory. Resident memory cannot tell a leak from an allocator that
//! keeps freed pages, so this replays the same work compressed: an answering
//! stack registered with a two-minute expiry (challenged with a fresh nonce
//! every time, as Asterisk does), a far end that calls it, a second of tone
//! each way, the far end's "#" as an RFC 4733 event, the answering stack's own
//! BYE, and three minutes of simulated time before the next call, in which
//! the registration renews. It counts the bytes and blocks the library holds
//! between calls, from this file's counting allocator, at three call counts.
//!
//! A leak grows with the calls; a plateau does not. The test fails when the
//! bytes still held after the last stretch of calls exceed what the first
//! stretch settled at by more than a few hash-table resizes' worth.
//!
//! `SIPRAL_ENDURANCE_CALLS` sets the calls per stretch (default 100), so the
//! release run behind `docs/19-numbers.md` can go to thousands.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sipral::{
    Account, AccountId, CallHandle, CodecCatalog, Credentials, Digit, EndpointConfig, Event, Input,
    MediaConfig, MediaEngine, MediaEvent, OutgoingCall, TransportId, TransportProtocol, UaEvent,
    Uri, UserAgent, WallClock,
};

// the allocator

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);
static BLOCKS: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);

/// The system's own allocator, counting bytes and blocks as it goes.
struct Counting;

// SAFETY: every method forwards to `System` unchanged and only then updates
// atomic counters, so the allocator stays safe to share across threads.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is `System`'s contract.
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
            BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        block
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let block = unsafe { System.alloc_zeroed(layout) };
        if !block.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
            BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        block
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: `block` came from this allocator, which is `System`'s.
        unsafe { System.dealloc(block, layout) };
        FREED.fetch_add(layout.size(), Ordering::Relaxed);
        RELEASED.fetch_add(1, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as for `dealloc`, with the new size the caller vouches for.
        let moved = unsafe { System.realloc(block, layout, new_size) };
        if !moved.is_null() {
            ALLOCATED.fetch_add(new_size, Ordering::Relaxed);
            FREED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Bytes and blocks held right now by the whole process. Valid only because
/// this file has a single test.
fn live() -> (usize, usize) {
    (
        ALLOCATED
            .load(Ordering::Relaxed)
            .saturating_sub(FREED.load(Ordering::Relaxed)),
        BLOCKS
            .load(Ordering::Relaxed)
            .saturating_sub(RELEASED.load(Ordering::Relaxed)),
    )
}

// the two stacks

const UDP: TransportId = TransportId(1);
const DOMAIN: &str = "lab.sipral.test";
const USER: &str = "agent";
const PASSWORD: &str = "a lab password";

/// The registration lifetime the soak holds the account to.
const EXPIRES: u32 = 120;
/// Simulated time between one call's end and the next call.
const BETWEEN_CALLS: Duration = Duration::from_secs(180);
/// Twenty-millisecond frames of tone before the far end presses "#", and the
/// most frames a call may run before the test calls it stuck.
const FRAMES_BEFORE_DIGIT: usize = 50;
const MOST_FRAMES: usize = 200;
const FRAME: Duration = Duration::from_millis(20);

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a written address")
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a written URI")
}

struct Side {
    agent: UserAgent,
    engine: MediaEngine,
    sip: SocketAddr,
    media: SocketAddr,
    /// Whether this side asks for ended calls' RTCP goodbyes, as an
    /// application writing them to its socket does.
    polls_farewells: bool,
}

impl Side {
    fn new(seed: u8, host: &str, polls_farewells: bool, now: Instant) -> Self {
        let sip = address(&format!("{host}:5060"));
        let mut agent = UserAgent::new(EndpointConfig::default(), [seed; 32]).expect("an agent");
        agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local: sip,
                    remote: None,
                },
                now,
            )
            .expect("a transport");
        let engine = MediaEngine::new(
            CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("a catalogue"),
            MediaConfig::default(),
            WallClock::from_unix(now, 1_790_000_000, 0),
            [seed ^ 0x5a; 32],
        );
        Self {
            agent,
            engine,
            sip,
            media: address(&format!("{host}:30000")),
            polls_farewells,
        }
    }

    fn tick(&mut self, now: Instant) {
        self.agent.handle_timeout(now);
        self.engine.handle_timeout(now);
        while self.engine.poll_rtcp(now).is_some() {}
        if self.polls_farewells {
            while self.engine.poll_farewell().is_some() {}
        }
    }

    fn due(&self) -> Option<Instant> {
        [self.agent.poll_timeout(), self.engine.poll_timeout()]
            .into_iter()
            .flatten()
            .min()
    }

    fn deliver(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) {
        let local = self.sip;
        self.agent
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: from,
                    local,
                    data: datagram,
                },
                now,
            )
            .expect("a datagram the other side wrote");
    }
}

// the registrar: Asterisk's part, written by hand

/// One header's value, by name, from a request this test's stack wrote.
fn header<'a>(message: &'a str, name: &str) -> Option<&'a str> {
    message
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (field, value) = line.split_once(':')?;
            field
                .trim()
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
}

/// A 401 with a nonce never used before, or a 200 that keeps the binding for
/// [`EXPIRES`] seconds once credentials come.
fn registrar_answer(request: &[u8], nonces: &mut u64) -> Vec<u8> {
    let request = std::str::from_utf8(request).expect("a text REGISTER");
    let echoed = ["Via", "From", "To", "Call-ID", "CSeq"]
        .into_iter()
        .map(|name| {
            let value = header(request, name).unwrap_or_else(|| panic!("no {name}"));
            if name == "To" {
                format!("To: {value};tag=registrar\r\n")
            } else {
                format!("{name}: {value}\r\n")
            }
        })
        .collect::<String>();
    if header(request, "Authorization").is_some() {
        let contact = header(request, "Contact").expect("a Contact");
        format!(
            "SIP/2.0 200 OK\r\n{echoed}Contact: {contact};expires={EXPIRES}\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes()
    } else {
        *nonces += 1;
        format!(
            "SIP/2.0 401 Unauthorized\r\n{echoed}WWW-Authenticate: Digest realm=\"{DOMAIN}\", \
             nonce=\"{:016x}\", algorithm=MD5, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n",
            *nonces
        )
        .into_bytes()
    }
}

// the run

struct Run {
    pbx: Side,
    app: Side,
    pbx_account: AccountId,
    now: Instant,
    nonces: u64,
    registrations: usize,
    /// The answering stack's current call, and whether it has ended.
    answered: Option<CallHandle>,
    ended: bool,
}

impl Run {
    fn new(polls_farewells: bool) -> Self {
        let now = Instant::now();
        let mut pbx = Side::new(0x11, "192.0.2.1", true, now);
        let mut app = Side::new(0x22, "192.0.2.2", polls_farewells, now);
        let pbx_identity = uri(&format!("sip:pbx@{}", pbx.sip));
        let pbx_account = pbx.agent.add_account(Account::unregistered(
            pbx_identity.clone(),
            pbx_identity,
            UDP,
            app.sip,
        ));
        let account = app.agent.add_account(
            Account::new(
                uri(&format!("sip:{USER}@{DOMAIN}")),
                uri(&format!("sip:{DOMAIN}")),
                uri(&format!("sip:{USER}@{}", app.sip)),
                UDP,
                pbx.sip,
            )
            .credentials(Credentials::new(USER, PASSWORD)),
        );
        app.agent.register(account, now).expect("the REGISTER goes");
        let mut run = Self {
            pbx,
            app,
            pbx_account,
            now,
            nonces: 0,
            registrations: 0,
            answered: None,
            ended: false,
        };
        run.settle();
        assert_eq!(run.registrations, 1, "the first registration did not take");
        run
    }

    /// Relay everything between the stacks, the registrar answering the
    /// REGISTERs, until both are quiet.
    fn settle(&mut self) {
        loop {
            self.drain();
            let mut moved = false;
            while let Some(transmit) = self.app.agent.poll_transmit() {
                moved = true;
                if transmit.payload.starts_with(b"REGISTER ") {
                    let answer = registrar_answer(&transmit.payload, &mut self.nonces);
                    self.app.deliver(&answer, self.pbx.sip, self.now);
                } else {
                    self.pbx.deliver(&transmit.payload, self.app.sip, self.now);
                }
            }
            while let Some(transmit) = self.pbx.agent.poll_transmit() {
                moved = true;
                self.app.deliver(&transmit.payload, self.pbx.sip, self.now);
            }
            if !moved {
                break;
            }
        }
    }

    fn drain(&mut self) {
        while self
            .pbx
            .engine
            .poll_event(&mut self.pbx.agent, self.now)
            .is_some()
        {}
        while let Some(event) = self.app.engine.poll_event(&mut self.app.agent, self.now) {
            match event {
                Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
                    self.app
                        .engine
                        .answer(&mut self.app.agent, call, self.app.media, self.now)
                        .expect("the 200 goes");
                    self.answered = Some(call);
                    self.ended = false;
                }
                Event::Signalling(UaEvent::Registered { .. }) => self.registrations += 1,
                Event::Signalling(UaEvent::RegistrationFailed { reason, .. }) => {
                    panic!("the registration failed: {reason}")
                }
                Event::Signalling(UaEvent::CallEnded { call, .. })
                    if self.answered == Some(call) =>
                {
                    self.ended = true;
                }
                Event::Media {
                    call,
                    event:
                        MediaEvent::DigitReceived {
                            digit: Some('#'), ..
                        },
                } => {
                    self.app.agent.hangup(call, self.now).expect("the BYE goes");
                }
                _ => {}
            }
        }
    }

    /// One frame each way: tone from the far end, silence back.
    fn frame(&mut self, pbx_call: CallHandle, app_call: CallHandle, phase: &mut u32) {
        let mut tone = [0_i16; 160];
        for sample in &mut tone {
            *sample = if *phase % 18 < 9 { 8_000 } else { -8_000 };
            *phase = phase.wrapping_add(1);
        }
        let silence = [0_i16; 160];
        let now = self.now;
        let sent = self.pbx.engine.session(pbx_call).and_then(|mut session| {
            session
                .capture(&tone, now)
                .ok()
                .flatten()
                .map(|d| d.payload.to_vec())
        });
        if let (Some(mut datagram), Some(mut session)) = (sent, self.app.engine.session(app_call)) {
            session.receive(&mut datagram, self.pbx.media, now);
            let mut played = [0_i16; 160];
            session.playback(&mut played);
        }
        let back = self.app.engine.session(app_call).and_then(|mut session| {
            session
                .capture(&silence, now)
                .ok()
                .flatten()
                .map(|d| d.payload.to_vec())
        });
        if let (Some(mut datagram), Some(mut session)) = (back, self.pbx.engine.session(pbx_call)) {
            session.receive(&mut datagram, self.app.media, now);
            let mut played = [0_i16; 160];
            session.playback(&mut played);
        }
        self.now += FRAME;
        self.pbx.tick(self.now);
        self.app.tick(self.now);
        self.settle();
    }

    /// One call: placed by the far end, answered, a second of tone, "#",
    /// and the answering stack's BYE.
    fn call(&mut self) {
        let account = self.pbx_account;
        let target = uri(&format!("sip:{USER}@{}", self.app.sip));
        let placed = self
            .pbx
            .engine
            .place(
                &mut self.pbx.agent,
                account,
                OutgoingCall::new(target).to_address(UDP, self.app.sip),
                self.pbx.media,
                self.now,
            )
            .expect("the INVITE goes");
        self.answered = None;
        self.settle();
        let answered = self.answered.expect("the call was answered");
        let mut phase = 0;
        for n in 0..MOST_FRAMES {
            if self.ended {
                return;
            }
            if n == FRAMES_BEFORE_DIGIT {
                self.pbx
                    .engine
                    .session(placed)
                    .expect("the far end's media")
                    .send_dtmf(Digit::Hash, sipral::DEFAULT_DIGIT)
                    .expect("the digit queues");
            }
            self.frame(placed, answered, &mut phase);
        }
        panic!("the call was never hung up");
    }

    /// Run the clock on for `span`, timer to timer.
    fn wait(&mut self, span: Duration) {
        let until = self.now + span;
        loop {
            let next = [self.pbx.due(), self.app.due()].into_iter().flatten().min();
            let Some(next) = next.filter(|next| *next <= until) else {
                self.now = until;
                self.pbx.tick(until);
                self.app.tick(until);
                self.settle();
                return;
            };
            self.now = next.max(self.now);
            let now = self.now;
            self.pbx.tick(now);
            self.app.tick(now);
            self.settle();
        }
    }
}

/// Calls per stretch: [`STRETCH`], or more from the environment.
const STRETCH: usize = 100;

/// The engine's ceiling on goodbyes nobody asked for; the run that never
/// asks must pass it within the first stretch.
const FAREWELLS_KEPT: usize = 256;

fn stretch() -> usize {
    std::env::var("SIPRAL_ENDURANCE_CALLS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|calls| *calls > 0)
        .unwrap_or(STRETCH)
}

/// Bytes and blocks held after `stretch`, 3 × `stretch` and 7 × `stretch`
/// calls, checked for growth over the last two stretches.
fn endure(stretch: usize, polls_farewells: bool) {
    let mut run = Run::new(polls_farewells);
    let mut readings = Vec::with_capacity(4);
    readings.push((0, run.registrations, live()));
    let mut done = 0;
    for factor in [1, 2, 4] {
        for _ in 0..stretch * factor {
            run.call();
            run.wait(BETWEEN_CALLS);
            done += 1;
        }
        readings.push((done, run.registrations, live()));
    }
    let asking = if polls_farewells {
        "asks for"
    } else {
        "never asks for"
    };
    for (calls, registrations, (bytes, blocks)) in &readings {
        println!(
            "endurance ({asking} goodbyes): after {calls} calls and {registrations} \
             registrations: {bytes} B in {blocks} blocks held"
        );
    }
    let app_engine = {
        let before = live().0;
        drop(run.app.engine);
        before.saturating_sub(live().0)
    };
    let app_agent = {
        let before = live().0;
        drop(run.app.agent);
        before.saturating_sub(live().0)
    };
    println!(
        "endurance ({asking} goodbyes): the answering stack gave back {app_agent} B \
         (signalling) and {app_engine} B (media) when dropped"
    );
    assert!(
        run.registrations > done,
        "the registration did not renew between calls: {} for {done} calls",
        run.registrations
    );
    let (_, _, (settled, settled_blocks)) = readings[1];
    let (_, _, (last, last_blocks)) = readings[3];
    // a table that doubles once more is allowed; a few bytes a call over
    // 4 × `stretch` calls is not
    assert!(
        last <= settled + 16 * 1024 && last_blocks <= settled_blocks + 16,
        "held memory grew with the calls ({asking} goodbyes): {settled} B in \
         {settled_blocks} blocks after {} calls, {last} B in {last_blocks} blocks after {done}",
        readings[1].0
    );
}

// one test, so the counting allocator sees nothing but these runs
#[test]
fn calls_and_registrations_one_after_another_hold_nothing_once_each_is_over() {
    let stretch = stretch();
    endure(stretch, true);
    // an application that never asks for ended calls' goodbyes, as the soak's
    // own did: past the queue's ceiling the oldest go
    endure(stretch.max(FAREWELLS_KEPT), false);
}
