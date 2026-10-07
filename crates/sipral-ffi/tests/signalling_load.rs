// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a hundred calls' worth of signalling costs one stack.
//!
//! `src/load.rs` measures an audio frame; this measures the signalling. Two
//! stacks (a user agent and a media engine each) call each other with no
//! network between them. Every call runs a PBX-style exchange: INVITE, 401
//! challenge, INVITE with digest credentials, 100, reliable 180 and PRACK,
//! 200 and ACK, a hold re-INVITE, a resume re-INVITE, BYE and 200. Calls are
//! concurrent: all are placed before the first answer, and likewise for
//! hold, resume and hangup.
//!
//! Printed (and collected by `scripts/bench.sh` into `docs/19-numbers.md`):
//! time inside the library per call set-up and per transaction, messages per
//! second, and memory per live call at each end, dialog apart from media.
//! Time is wall clock around each library call on one thread, so a busy
//! machine reads slower. Memory comes from this file's counting allocator
//! (bytes the library asked for); its `unsafe impl` is why the test lives in
//! this crate.
//!
//! It is also a test: every call must end as it was ended, every message is
//! counted against the expected tally (a lost or doubled transaction fails),
//! and after the calls the clock runs past every RFC 3261 timer with nothing
//! sent (a retransmission means an unfinished transaction).
//!
//! The server half of digest is the test's own: the answering stack's
//! `reject` sends the 401, and the test checks the credentials as RFC 7616
//! §3.4.1 has a server do, outside the measured time.

// panics are fine in a test harness; `caller` and `callee` are the names
// used everywhere
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sipral::{
    Account, AccountId, CallEndReason, CallHandle, CallState, CodecCatalog, Credentials,
    EndpointConfig, Event, Input, MediaConfig, MediaEngine, OutgoingCall, Rate, StatusCode,
    TransportId, TransportProtocol, UaEvent, Uri, UserAgent, WallClock,
};
use sipral_core::auth::DigestAlgorithm;
use sipral_core::msg::HeaderName;

// the processor time

/// `struct timespec` on the 64-bit targets the floor is held on.
#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64"
))]
#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64"
))]
unsafe extern "C" {
    fn clock_gettime(clock: i32, now: *mut Timespec) -> i32;
}

/// `CLOCK_THREAD_CPUTIME_ID`: the processor time the calling thread has had.
#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
const THREAD_CPU: i32 = 16;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const THREAD_CPU: i32 = 3;

/// This thread's processor time so far, where the platform provides it.
fn thread_cpu() -> Option<Duration> {
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64"
    ))]
    {
        let mut now = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        // SAFETY: a clock both platforms define, and a live struct of the
        // layout their C library writes.
        let status = unsafe { clock_gettime(THREAD_CPU, &raw mut now) };
        if status != 0 {
            return None;
        }
        Some(
            Duration::from_secs(u64::try_from(now.seconds).ok()?)
                + Duration::from_nanos(u64::try_from(now.nanoseconds).ok()?),
        )
    }
    #[cfg(not(all(
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64"
    )))]
    {
        None
    }
}

// the allocator

/// Every byte asked for, and every byte given back, since the process began.
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);

/// The system's own allocator, counting as it goes.
struct Counting;

// SAFETY: every method forwards to `System` unchanged and only then updates
// two atomic counters, so the allocator stays safe to share across threads.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is `System`'s contract.
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        block
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let block = unsafe { System.alloc_zeroed(layout) };
        if !block.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        block
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: `block` came from this allocator, which is `System`'s.
        unsafe { System.dealloc(block, layout) };
        FREED.fetch_add(layout.size(), Ordering::Relaxed);
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

/// Bytes held right now by the whole process. Valid only because this file
/// has a single test; the harness would count a second one too.
fn live() -> usize {
    ALLOCATED
        .load(Ordering::Relaxed)
        .saturating_sub(FREED.load(Ordering::Relaxed))
}

// the two stacks

/// How many calls each stack holds at once.
const CALLS: usize = 100;

const UDP: TransportId = TransportId(1);

/// Past the last RFC 3261 transaction timer (64 × T1 = 32 s).
const TRANSACTIONS_OVER: Duration = Duration::from_secs(40);

/// The challenge realm, and the password known to the caller's account and
/// this test's check.
const REALM: &str = "sipral.test";
const USER: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";

/// Where the far end's calls go.
const TARGET: &str = "sip:bob@sipral.test";

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a written address")
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a written URI")
}

/// A media address per call `n`: a stack refuses two sessions on one port.
fn media_address(host: &str, n: usize) -> SocketAddr {
    address(&format!("{host}:{}", 20_000 + 2 * n))
}

/// One stack and its cost: wall time inside the library, processor time
/// meanwhile, and messages in and out.
struct Side {
    agent: UserAgent,
    engine: MediaEngine,
    sip: SocketAddr,
    host: &'static str,
    spent: Duration,
    /// Processor time inside those calls, where available; unaffected by
    /// other load, so the regression floor uses it.
    worked: Option<Duration>,
    sent: BTreeMap<String, usize>,
    received: BTreeMap<String, usize>,
}

impl Side {
    fn new(seed: u8, host: &'static str, calls: usize, now: Instant) -> Self {
        let sip = address(&format!("{host}:5060"));
        // defaults are 128 dialogs and 256 server transactions; each call has
        // two INVITE server transactions during set-up, so larger runs raise
        // both, as a media server would
        let mut config = EndpointConfig::default();
        config.max_dialogs = config.max_dialogs.max(calls);
        config.max_server_transactions = config.max_server_transactions.max(2 * calls);
        let mut agent = UserAgent::new(config, [seed; 32]).expect("an agent");
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
        // mu-law only: an Opus codec's state would be counted as call memory
        let catalog = CodecCatalog::with_order(&["PCMU"]).expect("a catalogue");
        let engine = MediaEngine::new(
            catalog,
            MediaConfig::default(),
            WallClock::from_unix(now, 1_700_000_000, 0),
            [seed ^ 0x5a; 32],
        );
        Self {
            agent,
            engine,
            sip,
            host,
            spent: Duration::ZERO,
            worked: thread_cpu().map(|_| Duration::ZERO),
            sent: BTreeMap::new(),
            received: BTreeMap::new(),
        }
    }

    /// Run `work` against this stack, charging the time it took.
    fn timed<T>(&mut self, work: impl FnOnce(&mut UserAgent, &mut MediaEngine) -> T) -> T {
        let began = Instant::now();
        let cpu = thread_cpu();
        let out = work(&mut self.agent, &mut self.engine);
        self.spent += began.elapsed();
        if let (Some(worked), Some(from), Some(to)) = (self.worked.as_mut(), cpu, thread_cpu()) {
            *worked += to.saturating_sub(from);
        }
        out
    }

    /// Everything this stack wants written, as it wrote it.
    fn outbound(&mut self) -> Vec<Arc<[u8]>> {
        let mut out = Vec::new();
        while let Some(transmit) = self.timed(|agent, _| agent.poll_transmit()) {
            *self.sent.entry(kind(&transmit.payload)).or_default() += 1;
            out.push(transmit.payload);
        }
        out
    }

    fn deliver(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) {
        *self.received.entry(kind(datagram)).or_default() += 1;
        let local = self.sip;
        self.timed(|agent, _| {
            agent.receive(
                Input::Datagram {
                    transport: UDP,
                    remote: from,
                    local,
                    data: datagram,
                },
                now,
            )
        })
        .expect("a datagram the other stack wrote");
    }

    fn event(&mut self, now: Instant) -> Option<Event> {
        self.timed(|agent, engine| engine.poll_event(agent, now))
    }

    /// Advance this stack's time: transaction timers and session watchdogs
    /// run, and due RTCP reports are written and dropped (no audio here).
    fn tick(&mut self, now: Instant) {
        self.timed(|agent, engine| {
            agent.handle_timeout(now);
            engine.handle_timeout(now);
            while engine.poll_rtcp(now).is_some() {}
        });
    }

    /// The earliest either half of this stack wants to be woken.
    fn due(&mut self) -> Option<Instant> {
        self.timed(|agent, engine| {
            [agent.poll_timeout(), engine.poll_timeout()]
                .into_iter()
                .flatten()
                .min()
        })
    }
}

/// A message by method or status; the key of a run's tally.
fn kind(datagram: &[u8]) -> String {
    let line = datagram
        .split(|byte| *byte == b'\r')
        .next()
        .unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    match line.strip_prefix("SIP/2.0 ") {
        Some(status) => status.split(' ').next().unwrap_or_default().to_owned(),
        None => line.split(' ').next().unwrap_or_default().to_owned(),
    }
}

// the far end's half of digest

/// The parameters of a `Digest` credentials value, unquoted.
fn digest_parameters(value: &str) -> BTreeMap<String, String> {
    let rest = value.strip_prefix("Digest ").expect("Digest credentials");
    let mut out = BTreeMap::new();
    let mut quoted = false;
    let mut start = 0;
    let mut pieces = Vec::new();
    for (at, character) in rest.char_indices() {
        match character {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                pieces.push(&rest[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    pieces.push(&rest[start..]);
    for piece in pieces {
        let (name, value) = piece.trim().split_once('=').expect("name=value");
        out.insert(
            name.trim().to_ascii_lowercase(),
            value.trim().trim_matches('"').to_owned(),
        );
    }
    out
}

/// Nonces issued and their highest count; a count that does not rise is a
/// replay (RFC 7616 §3.4).
#[derive(Default)]
struct Nonces {
    issued: usize,
    counts: BTreeMap<String, u32>,
}

impl Nonces {
    fn challenge(&mut self) -> String {
        self.issued += 1;
        let nonce = format!("n{:08x}", self.issued);
        self.counts.insert(nonce.clone(), 0);
        format!("Digest realm=\"{REALM}\", nonce=\"{nonce}\", qop=\"auth\", algorithm=MD5")
    }

    /// Whether `value` answers one of our INVITE challenges with our password.
    fn verify(&mut self, value: &str) {
        let fields = digest_parameters(value);
        let get = |name: &str| {
            fields
                .get(name)
                .unwrap_or_else(|| panic!("no {name} in {value}"))
                .as_str()
        };
        assert_eq!(get("username"), USER);
        assert_eq!(get("realm"), REALM);
        assert_eq!(get("qop"), "auth");
        let nonce = get("nonce");
        let count = u32::from_str_radix(get("nc"), 16).expect("a hex nonce count");
        let last = self
            .counts
            .get_mut(nonce)
            .unwrap_or_else(|| panic!("a nonce this end never issued: {nonce}"));
        assert!(count > *last, "nonce {nonce} counted {count} after {last}");
        *last = count;
        let md5 = DigestAlgorithm::Md5;
        let ha1 = md5.hash(format!("{USER}:{REALM}:{PASSWORD}").as_bytes());
        let ha2 = md5.hash(format!("INVITE:{}", get("uri")).as_bytes());
        let expected = md5
            .hash(format!("{ha1}:{nonce}:{}:{}:auth:{ha2}", get("nc"), get("cnonce")).as_bytes());
        assert_eq!(get("response"), expected, "credentials that do not verify");
    }
}

// the run

/// Both stacks, the calls between them, and what each end has seen of them.
struct Run {
    caller: Side,
    callee: Side,
    now: Instant,
    account: AccountId,
    nonces: Nonces,
    /// The calls the caller placed, in order.
    placed: Vec<CallHandle>,
    /// The callee's calls it answered, and the ones it challenged.
    answered: BTreeSet<CallHandle>,
    challenged: BTreeSet<CallHandle>,
    /// Calls each end has seen confirmed, and seen change.
    confirmed: [BTreeSet<CallHandle>; 2],
    changed: [BTreeMap<CallHandle, usize>; 2],
    /// Why each end's calls ended, by call.
    ended: [BTreeMap<CallHandle, CallEndReason>; 2],
    /// Anything that should not happen, kept to be reported together.
    unexpected: Vec<String>,
}

impl Run {
    /// Two stacks configured to hold `capacity` calls at once.
    fn new(capacity: usize) -> Self {
        let now = Instant::now();
        let mut caller = Side::new(0x11, "192.0.2.1", capacity, now);
        let mut callee = Side::new(0x22, "192.0.2.2", capacity, now);
        // all calls come from one address, like a proxy; the default limit is
        // for a phone, and `limit_invites` is how a deployment says so
        callee.agent.limit_invites(Rate::unlimited());
        let account = caller.agent.add_account(
            Account::new(
                uri(&format!("sip:{USER}@{REALM}")),
                uri(&format!("sip:{REALM}")),
                uri(&format!("sip:{USER}@192.0.2.1")),
                UDP,
                callee.sip,
            )
            .credentials(Credentials::new(USER, PASSWORD)),
        );
        Self {
            caller,
            callee,
            now,
            account,
            nonces: Nonces::default(),
            placed: Vec::new(),
            answered: BTreeSet::new(),
            challenged: BTreeSet::new(),
            confirmed: [BTreeSet::new(), BTreeSet::new()],
            changed: [BTreeMap::new(), BTreeMap::new()],
            ended: [BTreeMap::new(), BTreeMap::new()],
            unexpected: Vec::new(),
        }
    }

    /// Place `calls` calls before any answer, and confirm them at both ends.
    fn set_up(&mut self, calls: usize) {
        for n in 0..calls {
            let local = media_address(self.caller.host, n);
            let account = self.account;
            let call = self
                .caller
                .timed(|agent, engine| {
                    engine.place(
                        agent,
                        account,
                        OutgoingCall::new(uri(TARGET)).to_address(UDP, address("192.0.2.2:5060")),
                        local,
                        self.now,
                    )
                })
                .expect("the INVITE goes");
            self.placed.push(call);
        }
        self.settle();
    }

    /// Relay everything between the stacks until both are quiet.
    fn settle(&mut self) {
        loop {
            self.drain_caller();
            self.drain_callee();
            let dialled = self.caller.outbound();
            let answered = self.callee.outbound();
            if dialled.is_empty() && answered.is_empty() {
                break;
            }
            for datagram in dialled {
                self.callee.deliver(&datagram, self.caller.sip, self.now);
            }
            for datagram in answered {
                self.caller.deliver(&datagram, self.callee.sip, self.now);
            }
        }
    }

    fn drain_caller(&mut self) {
        while let Some(event) = self.caller.event(self.now) {
            let Event::Signalling(event) = event else {
                continue;
            };
            self.observe(0, &event);
        }
    }

    fn drain_callee(&mut self) {
        while let Some(event) = self.callee.event(self.now) {
            let Event::Signalling(event) = event else {
                continue;
            };
            if let UaEvent::IncomingCall { call, request, .. } = &event {
                let call = *call;
                let credentials = request
                    .as_raw()
                    .header(HeaderName::Authorization)
                    .map(|value| String::from_utf8_lossy(value).into_owned());
                self.incoming(call, credentials);
            } else {
                self.observe(1, &event);
            }
        }
    }

    /// An arriving call: challenged without credentials, answered when they
    /// verify.
    fn incoming(&mut self, call: CallHandle, credentials: Option<String>) {
        let now = self.now;
        if let Some(credentials) = credentials {
            self.nonces.verify(&credentials);
            let local = media_address(self.callee.host, self.answered.len());
            self.callee
                .timed(|agent, _| agent.ring(call, None, now))
                .expect("the 180 goes");
            self.callee
                .timed(|agent, engine| engine.answer(agent, call, local, now))
                .expect("the 200 goes");
            self.answered.insert(call);
        } else {
            let challenge = self.nonces.challenge();
            self.callee
                .timed(|agent, _| {
                    agent.respond_with_headers(
                        call,
                        &[(HeaderName::WwwAuthenticate, challenge.as_bytes())],
                    )?;
                    agent.reject(call, StatusCode::UNAUTHORIZED, now)
                })
                .expect("the 401 goes");
            self.challenged.insert(call);
        }
    }

    fn observe(&mut self, side: usize, event: &UaEvent) {
        match event {
            UaEvent::CallConfirmed { call, .. } => {
                if !self.confirmed[side].insert(*call) {
                    self.unexpected
                        .push(format!("side {side}: {call:?} confirmed twice"));
                }
            }
            UaEvent::SessionChanged { call, .. } => {
                *self.changed[side].entry(*call).or_default() += 1;
            }
            UaEvent::CallEnded { call, reason, .. } => {
                if self.ended[side].insert(*call, *reason).is_some() {
                    self.unexpected
                        .push(format!("side {side}: {call:?} ended twice"));
                }
            }
            UaEvent::CallProgress { .. } => {}
            other => self
                .unexpected
                .push(format!("side {side}: {}", short(&format!("{other:?}")))),
        }
    }

    /// Hold every call, then resume every call, all at once each time.
    fn hold_and_resume(&mut self) {
        for hold in [true, false] {
            for call in self.placed.clone() {
                let now = self.now;
                self.caller
                    .timed(|agent, _| {
                        if hold {
                            agent.hold(call, now)
                        } else {
                            agent.resume(call, now)
                        }
                    })
                    .expect("the re-INVITE goes");
            }
            self.settle();
        }
    }

    fn hang_up(&mut self) {
        for call in self.placed.clone() {
            let now = self.now;
            self.caller
                .timed(|agent, _| agent.hangup(call, now))
                .expect("the BYE goes");
        }
        self.settle();
    }

    /// Run the clock on for `span`, timer to timer, delivering what goes out;
    /// returns it, since after finished exchanges it should be empty.
    fn wait(&mut self, span: Duration) -> usize {
        let before = total(&self.caller.sent) + total(&self.callee.sent);
        let until = self.now + span;
        for _ in 0..1_000_000 {
            let next = [self.caller.due(), self.callee.due()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next.filter(|next| *next <= until) else {
                self.now = until;
                return total(&self.caller.sent) + total(&self.callee.sent) - before;
            };
            // a timer still due after running would loop; the bound ends it
            self.now = next.max(self.now);
            let now = self.now;
            self.caller.tick(now);
            self.callee.tick(now);
            self.settle();
        }
        panic!("a timer that never stops being due");
    }
}

fn total(tally: &BTreeMap<String, usize>) -> usize {
    tally.values().sum()
}

/// The first line or so of an event's debug form, for a failure message.
fn short(text: &str) -> String {
    text.chars().take(160).collect()
}

/// The call count: `CALLS`, or more from the environment
/// (`scripts/bench.sh`).
fn sized() -> usize {
    std::env::var("SIPRAL_SIGNALLING_CALLS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(CALLS)
}

/// The expected messages per call, per end; a run's tally is this times the
/// calls.
///
/// Caller: INVITE, ACK for the 401, INVITE with credentials, PRACK for the
/// 180, ACK for the 200, two re-INVITEs with ACKs, BYE. Callee: 100 for each
/// of the four INVITEs, 401, 180, 200 for the three it takes, 200 for PRACK
/// and for BYE. PRACK appears because both ends advertise RFC 3262.
const CALLER_WRITES: &[(&str, usize)] = &[("ACK", 4), ("BYE", 1), ("INVITE", 4), ("PRACK", 1)];
const CALLEE_WRITES: &[(&str, usize)] = &[("100", 4), ("180", 1), ("200", 5), ("401", 1)];

fn expected(per_call: &[(&str, usize)], calls: usize) -> BTreeMap<String, usize> {
    per_call
        .iter()
        .map(|(kind, count)| ((*kind).to_owned(), count * calls))
        .collect()
}

/// Bytes freed by dropping each half of a pair with `calls` confirmed calls:
/// caller's user agent and media engine, then the callee's.
///
/// Each media engine is dropped before its user agent, with nothing in
/// flight. `later` first runs the clock past every set-up timer, so what is
/// left is the dialogs, not the exchange.
fn footprint(capacity: usize, calls: usize, later: Option<Duration>) -> [usize; 4] {
    let mut run = Run::new(capacity);
    run.set_up(calls);
    if let Some(span) = later {
        run.wait(span);
    }
    let Run { caller, callee, .. } = run;
    let callee_media = freed(callee.engine);
    let callee_dialog = freed(callee.agent);
    let caller_media = freed(caller.engine);
    let caller_dialog = freed(caller.agent);
    [caller_dialog, caller_media, callee_dialog, callee_media]
}

/// What dropping `piece` gave back to the allocator.
fn freed<T>(piece: T) -> usize {
    let before = live();
    drop(piece);
    before.saturating_sub(live())
}

/// Nanoseconds as microseconds with one decimal.
#[allow(clippy::cast_precision_loss)]
fn micros(duration: Duration, per: usize) -> f64 {
    duration.as_secs_f64() * 1e6 / per as f64
}

// the test: one scenario read top to bottom, matching the line it prints
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
#[test]
fn a_hundred_calls_are_challenged_answered_held_resumed_and_hung_up_with_nothing_lost() {
    let calls = sized();

    // time: the whole exchange on one pair of stacks
    let mut run = Run::new(calls);
    run.set_up(calls);
    let setup = [run.caller.spent, run.callee.spent];
    // processor time where available, so a busy machine is not a
    // regression; wall time elsewhere
    let floor_measure = [
        run.caller.worked.unwrap_or(run.caller.spent),
        run.callee.worked.unwrap_or(run.callee.spent),
    ];
    assert_eq!(run.challenged.len(), calls, "every INVITE was challenged");
    assert_eq!(run.answered.len(), calls, "every retry was answered");
    for call in &run.placed {
        assert_eq!(
            run.caller.agent.call_state(*call),
            Some(CallState::Confirmed),
            "{call:?} did not come up"
        );
    }
    assert_eq!(run.confirmed[0].len(), calls);
    assert_eq!(run.confirmed[1].len(), calls);
    assert_eq!(run.caller.engine.active().count(), calls);
    assert_eq!(run.callee.engine.active().count(), calls);

    run.hold_and_resume();
    for call in &run.placed {
        assert_eq!(
            run.changed[0].get(call),
            Some(&2),
            "{call:?} was not held and resumed"
        );
        assert!(
            !run.caller
                .agent
                .hold_state(*call)
                .expect("a live call")
                .is_held(),
            "{call:?} is still held"
        );
    }
    for call in &run.answered {
        assert_eq!(
            run.changed[1].get(call),
            Some(&2),
            "the far end of {call:?} did not see the hold and the resume"
        );
    }

    run.hang_up();
    // anything written while transactions run out was never finished
    let late = run.wait(TRANSACTIONS_OVER);
    for side in [&mut run.caller, &mut run.callee] {
        assert_eq!(side.due(), None, "a timer outlived every call");
    }

    assert!(run.unexpected.is_empty(), "{:#?}", run.unexpected);
    assert_eq!(late, 0, "messages went out after every exchange was over");
    for call in &run.placed {
        assert_eq!(
            run.ended[0].get(call),
            Some(&CallEndReason::LocalHangup),
            "{call:?} ended the wrong way at the end that hung up"
        );
    }
    for call in &run.answered {
        assert_eq!(
            run.ended[1].get(call),
            Some(&CallEndReason::RemoteHangup),
            "{call:?} ended the wrong way at the end that was hung up on"
        );
    }
    for call in &run.challenged {
        assert!(
            run.ended[1].contains_key(call),
            "the challenged {call:?} was never ended"
        );
    }
    assert_eq!(run.caller.sent, expected(CALLER_WRITES, calls));
    assert_eq!(run.callee.sent, expected(CALLEE_WRITES, calls));
    assert_eq!(
        run.caller.received, run.callee.sent,
        "a message went missing"
    );
    assert_eq!(
        run.callee.received, run.caller.sent,
        "a message went missing"
    );
    assert_eq!(run.caller.engine.active().count(), 0);
    assert_eq!(run.callee.engine.active().count(), 0);

    // six transactions per call per end: two INVITEs, PRACK, two re-INVITEs,
    // BYE (an ACK for a 2xx is not a transaction)
    let transactions = 6 * calls;
    let caller_messages = total(&run.caller.sent) + total(&run.caller.received);
    let callee_messages = total(&run.callee.sent) + total(&run.callee.received);
    let caller_rate = caller_messages as f64 / run.caller.spent.as_secs_f64();
    let callee_rate = callee_messages as f64 / run.callee.spent.as_secs_f64();

    // memory: the same calls again, measured against an empty pair so an
    // empty stack is not charged to a call
    let bare = footprint(calls, 0, None);
    let per_call = |loaded: [usize; 4]| {
        let mut out = [0; 4];
        for (part, bytes) in out.iter_mut().enumerate() {
            *bytes = loaded[part].saturating_sub(bare[part]) / calls;
        }
        out
    };
    let [caller_dialog, caller_media, callee_dialog, callee_media] =
        per_call(footprint(calls, calls, Some(TRANSACTIONS_OVER)));
    let [caller_fresh, _, callee_fresh, _] = per_call(footprint(calls, calls, None));

    println!(
        "signalling: {calls} calls, {} messages per call ({caller_messages} through the caller, \
         {callee_messages} through the callee): call setup {:.1} us caller, {:.1} us callee; \
         per transaction {:.1} us caller, {:.1} us callee; {:.0} messages/s caller, {:.0} \
         messages/s callee; per live call {caller_dialog} B signalling + {caller_media} B media \
         caller, {callee_dialog} B signalling + {callee_media} B media callee, \
         {caller_fresh} B and {callee_fresh} B signalling while its transactions last",
        (total(&run.caller.sent) + total(&run.callee.sent)) / calls,
        micros(setup[0], calls),
        micros(setup[1], calls),
        micros(run.caller.spent, transactions),
        micros(run.callee.spent, transactions),
        caller_rate,
        callee_rate,
    );

    // the values `scripts/check.sh --only numbers` checks against
    // docs/numbers.toml: per-call signalling and media at the heavier end,
    // their sum, and the calling stack with no call
    println!(
        "numbers: memory.call.signalling={} memory.call.media={} memory.call.total={} \
         memory.idle={}",
        caller_dialog.max(callee_dialog),
        caller_media.max(callee_media),
        (caller_dialog + caller_media).max(callee_dialog + callee_media),
        bare[0] + bare[1],
    );

    // a floor under a regression, not the number: near 10 ms of one core
    // per set-up would put a dialler's 100 calls a second past a core.
    // Processor time, because a busy machine's wall clock read 13 ms.
    for spent in floor_measure {
        assert!(
            spent < Duration::from_millis(10) * u32::try_from(calls).unwrap_or(u32::MAX),
            "a call cost {spent:?} / {calls} to set up"
        );
    }
}
