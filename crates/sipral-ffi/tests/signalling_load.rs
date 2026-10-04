// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a hundred calls' worth of signalling costs one stack.
//!
//! The media load test beside the library (`src/load.rs`) measures a frame of
//! audio; this measures everything around it that is not audio. Two stacks —
//! a user agent and a media engine each, exactly what one `sipral_stack_new`
//! holds — call each other with no network between them, and every call goes
//! the whole way a call on a PBX goes: an INVITE the far end challenges, the
//! same INVITE again with digest credentials, a 100, a reliable 180 and its
//! PRACK, a 200 and the ACK, a re-INVITE that holds it and another that
//! resumes it, and a BYE and its 200. The calls are concurrent: every one of
//! them is placed before the first answer is delivered, so each stack holds
//! all of them at once, and the same is true of the hold, the resume and the
//! hangup after it.
//!
//! What it prints, and `scripts/bench.sh` collects into
//! `docs/19-numbers.md`: the time each stack spent inside the library
//! bringing one call up and on one transaction, how many messages one stack
//! gets through in a second of that time, and what a live call holds in
//! memory on each end — the dialog and its transactions apart from the media
//! session that is opened beside them. The time is the wall clock read
//! around every call into the library, on the one thread making them, not
//! the processor time the operating system charged that thread: a machine
//! busy with other work reads slower. Memory is counted by this file's own
//! allocator rather than read off the operating system, so it is the bytes
//! the library asked for and nothing the process did around it; that
//! allocator's one `unsafe impl` is why the test lives in this crate, the one
//! whose lints allow it.
//!
//! And it is a test before it is a measurement. Every call has to end the
//! way it was ended — hung up here, hung up there — every message that
//! crossed is counted against the number the exchange above makes, so a
//! transaction lost or answered twice is a failure, and once the calls are
//! over the clock is run on past every timer RFC 3261 has, and nothing may go
//! out: a retransmission then is a transaction that was never finished.
//!
//! The one thing not taken from the library is the far end's half of digest
//! authentication. A user agent answers challenges; it does not issue them.
//! The challenge is the 401 a PBX answers with, written by the answering
//! stack's own `reject` with the field on it, and the credentials that come
//! back are checked here, by the test, the way RFC 7616 §3.4.1 has a server
//! check them — outside the time either stack is charged with.

// the test says what it means; the library's no-panic discipline is not for
// a test harness. And the two ends of a call are the caller and the callee,
// which is what they are called everywhere else too, one letter apart or not
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

// -- the processor time --------------------------------------------------------

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

/// The processor time this thread has been given so far, where the platform
/// says; `None` elsewhere.
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
        // SAFETY: a clock both platforms define, and a live structure of
        // the layout their C library writes into.
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

// -- the allocator ------------------------------------------------------------

/// Every byte asked for, and every byte given back, since the process began.
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);

/// The system's own allocator, counting as it goes.
struct Counting;

// SAFETY: every method hands the call to `System` unchanged, with the layout
// and pointer it was given, and only adds to two counters afterwards; the
// counters are atomics, so the allocator stays safe to share across threads.
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

/// The bytes held right now, by everything in the process.
///
/// Only meaningful because this file has one test in it: the harness runs
/// tests on threads of their own, and a second test would be counted too.
fn live() -> usize {
    ALLOCATED
        .load(Ordering::Relaxed)
        .saturating_sub(FREED.load(Ordering::Relaxed))
}

// -- the two stacks -----------------------------------------------------------

/// How many calls each stack holds at once.
const CALLS: usize = 100;

const UDP: TransportId = TransportId(1);

/// Past the last timer any RFC 3261 transaction runs: 64 × T1 is thirty-two
/// seconds, and nothing an exchange started is still alive after it.
const TRANSACTIONS_OVER: Duration = Duration::from_secs(40);

/// The realm the answering end challenges in, and the password only the
/// calling end's account and this test's check know.
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

/// A media address of its own for call `n`: two sessions on one port is what
/// a stack refuses, and it is the application that owns the port.
fn media_address(host: &str, n: usize) -> SocketAddr {
    address(&format!("{host}:{}", 20_000 + 2 * n))
}

/// One stack, and what it cost: the wall time spent inside the library on
/// its behalf, the processor time the thread was given meanwhile, and the
/// messages that crossed its edge either way.
struct Side {
    agent: UserAgent,
    engine: MediaEngine,
    sip: SocketAddr,
    host: &'static str,
    spent: Duration,
    /// The processor time inside those same calls, where the platform says,
    /// which other work on the machine does not inflate: what the floor
    /// under a regression is held to.
    worked: Option<Duration>,
    sent: BTreeMap<String, usize>,
    received: BTreeMap<String, usize>,
}

impl Side {
    fn new(seed: u8, host: &'static str, calls: usize, now: Instant) -> Self {
        let sip = address(&format!("{host}:5060"));
        // the defaults hold 128 dialogs and 256 server transactions, which
        // is a softphone's ceiling and a flood's, and every call here has
        // two INVITE server transactions live at once while it is set up. A
        // run of more calls than that raises both, the way a media server
        // built on this stack would; a run within them measures the stack
        // as it ships
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
        // mu-law and nothing else, the codec the media numbers are taken on:
        // what is measured here is the signalling, and an Opus session's own
        // encoder and decoder would be counted as a call's memory
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

    /// Time passes for this stack: its transactions' timers and its
    /// sessions' watchdogs both get a look, and the RTCP reports that fall
    /// due are written — and dropped, since they go to a media address and
    /// no audio is running on these calls.
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

/// A message by what it is: the method of a request, the status of a
/// response. What the tally of a run is kept in.
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

// -- the far end's half of digest --------------------------------------------

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

/// The nonces this end has handed out, and the highest count each has been
/// answered with: a count that does not rise is a replay (RFC 7616 §3.4).
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

    /// Whether `value` answers one of this end's challenges for an INVITE,
    /// with the password this end knows.
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

// -- the run ------------------------------------------------------------------

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
        // every call arrives from one address, which is a switchboard's
        // shape and not a phone's: the default limit, ten at once from one
        // source, is for a phone that faces the internet, and
        // `limit_invites` is how a deployment that answers a proxy says so
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

    /// Place `calls` calls, all before any answer is delivered, and carry
    /// them to confirmed at both ends.
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

    /// Move everything either stack wrote to the other, and act on what each
    /// then says, until neither has anything left to say.
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

    /// A call arrived at the answering end: challenged when it carries no
    /// credentials, and rung and answered when the ones it carries verify.
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

    /// Hold every call, then resume every call, each round all at once.
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

    /// Run the clock on for `span`, from one timer either stack asked for to
    /// the next, the way an application's loop does, delivering whatever
    /// goes out; what went out is returned, since after a finished exchange
    /// the answer should be nothing.
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
            // a timer already due is run now, and one that stays due after
            // it has run would be a loop, which the bound above ends
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

/// What a run was asked for: `CALLS`, unless the environment raises it.
/// `scripts/bench.sh` runs the same test at a larger count.
fn sized() -> usize {
    std::env::var("SIPRAL_SIGNALLING_CALLS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(CALLS)
}

/// The exchange above, message by message, for one call, as each end writes
/// it: the tally a run has to come to, times the number of calls.
///
/// The caller writes an INVITE, the ACK for its 401, the INVITE again with
/// credentials, the PRACK for the 180, the ACK for the 200, then a re-INVITE
/// and its ACK twice, and a BYE. The callee writes a 100 for each of the four
/// INVITEs, the 401, the 180, the 200 for each of the three it takes, the 200
/// for the PRACK and the 200 for the BYE.
///
/// The PRACK is there because both ends are this stack: each INVITE says it
/// supports RFC 3262, so the answering end sends its 180 reliably and the
/// calling end acknowledges it, the way it would against any PBX that does
/// the same.
const CALLER_WRITES: &[(&str, usize)] = &[("ACK", 4), ("BYE", 1), ("INVITE", 4), ("PRACK", 1)];
const CALLEE_WRITES: &[(&str, usize)] = &[("100", 4), ("180", 1), ("200", 5), ("401", 1)];

fn expected(per_call: &[(&str, usize)], calls: usize) -> BTreeMap<String, usize> {
    per_call
        .iter()
        .map(|(kind, count)| ((*kind).to_owned(), count * calls))
        .collect()
}

/// What each half of a pair configured for `capacity` calls and holding
/// `calls` confirmed ones gives back when it is dropped: the caller's user
/// agent and media engine, then the callee's, in bytes.
///
/// Taken apart one piece at a time, each media engine before its user agent,
/// with nothing in flight between them: what is freed is what that piece
/// held, and nothing the harness was carrying. `later` runs the clock on
/// first, past the last timer of every transaction that brought the calls
/// up, so that what is left is the dialogs and not the exchange that made
/// them.
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

/// Nanoseconds as microseconds with one decimal, for the printed line.
#[allow(clippy::cast_precision_loss)]
fn micros(duration: Duration, per: usize) -> f64 {
    duration.as_secs_f64() * 1e6 / per as f64
}

// -- the test -----------------------------------------------------------------

// one scenario read top to bottom: the calls brought up, changed and hung up,
// then judged, then measured for memory. Cut into pieces it would be harder
// to read against the line it prints.
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
#[test]
fn a_hundred_calls_are_challenged_answered_held_resumed_and_hung_up_with_nothing_lost() {
    let calls = sized();

    // -- time: the whole exchange, on one pair of stacks ---------------------
    let mut run = Run::new(calls);
    run.set_up(calls);
    let setup = [run.caller.spent, run.callee.spent];
    // the floor's measure: the processor time where the platform gives it,
    // so that a machine running three test suites at once does not read as
    // a regression, and the wall time elsewhere
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
    // anything written while every transaction runs out is a transaction
    // that was never finished
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

    // six transactions a call at each end: the two INVITEs, the PRACK, the
    // two re-INVITEs and the BYE, client side at one end and server side at
    // the other (an ACK for a 2xx is a transaction of its own to nobody)
    let transactions = 6 * calls;
    let caller_messages = total(&run.caller.sent) + total(&run.caller.received);
    let callee_messages = total(&run.callee.sent) + total(&run.callee.received);
    let caller_rate = caller_messages as f64 / run.caller.spent.as_secs_f64();
    let callee_rate = callee_messages as f64 / run.callee.spent.as_secs_f64();

    // -- memory: the same calls brought up again, and taken apart -----------
    // a pair with no calls on it is what a pair with all of them is measured
    // against, so that what an empty stack holds is not charged to a call
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

    // The same memory as `scripts/check.sh --only numbers` reads it against
    // docs/numbers.toml: a live call's signalling and media at whichever end
    // holds more of each, the two together at the end that holds more, and
    // what the calling stack holds with no call at all -- its user agent,
    // its transport and its account, and its media engine.
    println!(
        "numbers: memory.call.signalling={} memory.call.media={} memory.call.total={} \
         memory.idle={}",
        caller_dialog.max(callee_dialog),
        caller_media.max(callee_media),
        (caller_dialog + caller_media).max(callee_dialog + callee_media),
        bare[0] + bare[1],
    );

    // A call is brought up once and held for minutes. Anything near ten
    // milliseconds of one core to set one up would put a dialler's burst of
    // a hundred calls a second past a core of its own; this is a floor under
    // a regression, not the number. Held to the processor time the thread
    // was given, not to the wall clock: in a debug build a call costs a few
    // milliseconds, and on a machine busy enough the wall clock alone went
    // past ten (a gate beside two other workspace test runs read 13 ms).
    for spent in floor_measure {
        assert!(
            spent < Duration::from_millis(10) * u32::try_from(calls).unwrap_or(u32::MAX),
            "a call cost {spent:?} / {calls} to set up"
        );
    }
}
