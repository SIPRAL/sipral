// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Thousands of calls at once between two of this stack's own endpoints on
//! one machine, each carrying audio both ways for as long as it is held.
//!
//! `volume` asks what a real PBX makes of a hundred calls; this asks what the
//! stack itself costs holding five or ten thousand, which no PBX in the lab
//! is sized to answer. So the far end is this binary again, in a second
//! process started with the flow `scale-answer`: it answers every INVITE it
//! is sent and plays audio back into it. The two processes share a machine
//! and nothing else, and each reads its own processor time and memory from
//! `/proc/self`, so the calling end's cost is read apart from the answering
//! end's. `scripts/bench.sh scale` starts the pair.
//!
//! Each end is laid out the way a server built on this stack would be: one
//! thread owns the user agent and the media engine and runs all of the
//! signalling, and `SIPRAL_SCALE_THREADS` others carry the audio, each for its
//! share of the calls, reaching a call's session through
//! [`sipral::SessionShare`] — the call's own lock, never the engine's — once
//! every twenty milliseconds: whatever arrived on the call's socket in, one
//! frame of tone out, one frame played. The signalling thread times every
//! call it makes into the stack that grows with the number of calls held:
//! [`MediaEngine::poll_event`], which is meant not to, and the two timer
//! sweeps, which do.
//!
//! What is reported, at the calling end: how many calls came up and how
//! fast — calls a second from the first INVITE to the last answer, and each
//! call's own time from its INVITE to the 2xx — then, over the hold, this
//! process's processor time and resident memory, the packets a second both
//! ways, the mean cost of each of those calls into the stack, the frames the
//! audio threads played dry and the ticks they ran late, and the SIP
//! retransmissions and timeouts `Endpoint::retransmissions` counted. A run
//! that breaks says where: a call that never came up and why, a thread that
//! could not keep its twenty milliseconds, a path the SIP messages started
//! being retransmitted on.

use std::collections::HashMap;
use std::env;
use std::hash::Hash;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sipral::{
    Account, AccountId, Arrival, CallHandle, CallMedia, CodecCatalog, EndpointConfig, Event, Input,
    MediaConfig, MediaEngine, MediaEvent, OutgoingCall, Playback, Rate, SessionShare, TransportId,
    TransportProtocol, UaEvent, UserAgent, WallClock,
};

use crate::{run_folded, uri};

/// The calling end's identity. Listed in `main.rs`'s
/// `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const CALLER_SEED: u8 = 91;
pub(crate) const CALLER_MEDIA_SEED: u8 = 92;
/// The answering end's.
pub(crate) const ANSWER_SEED: u8 = 93;
pub(crate) const ANSWER_MEDIA_SEED: u8 = 94;

/// A frame, twenty milliseconds apart, on every call.
const TICK: Duration = Duration::from_millis(20);

/// The largest frame the tone is written for: twenty milliseconds at 16 kHz.
const MAX_SAMPLES: usize = 320;

/// How often the signalling thread runs the timer sweeps: once a frame.
/// Each visits every call or every session, so a loop that ran them on every
/// turn would measure the loop rather than the calls, and nothing they drive
/// — SIP's timers from T1's half second up, RTCP every few seconds, the stall
/// watchdog — needs a finer step than twenty milliseconds.
const SWEEP: Duration = Duration::from_millis(20);

/// How long the hangups are waited for.
const ENDING: Duration = Duration::from_secs(40);

/// How long after the last BYE the calling end stays to repeat one that was
/// lost: past T1 + 2·T1 + 4·T1 at the default T1 of half a second.
const DRAIN: Duration = Duration::from_secs(5);

/// What a run is asked for, from the environment.
struct Settings {
    calls: usize,
    /// Calls placed a second.
    rate: u64,
    hold: Duration,
    threads: usize,
    /// How long every call is given to come up.
    patience: Duration,
}

fn number(name: &str, fallback: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|text| text.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

impl Settings {
    fn read() -> Self {
        Self {
            calls: usize::try_from(number("SIPRAL_SCALE_CALLS", 1_000)).unwrap_or(1_000),
            rate: number("SIPRAL_SCALE_RATE", 500),
            hold: Duration::from_millis(number("SIPRAL_SCALE_HOLD_MS", 60_000)),
            threads: usize::try_from(number("SIPRAL_SCALE_THREADS", 8)).unwrap_or(8),
            patience: Duration::from_millis(number("SIPRAL_SCALE_PATIENCE_MS", 120_000)),
        }
    }

    /// The limits a stack that holds this many calls is created with: room
    /// for every one of them, and for the transactions of the busiest moment
    /// — each call's INVITE and its BYE may be open at once.
    fn endpoint(&self) -> EndpointConfig {
        let mut config = EndpointConfig::default();
        config.max_dialogs = self.calls.saturating_add(64);
        config.max_server_transactions = self.calls.saturating_mul(2).saturating_add(256);
        config
    }
}

/// What the audio threads have done, all of them together.
#[derive(Default)]
struct Totals {
    sent: AtomicU64,
    received: AtomicU64,
    played: AtomicU64,
    dry: AtomicU64,
    /// Ticks a thread started later than a whole frame after it was due.
    late: AtomicU64,
    /// The longest one tick of one thread took, in microseconds.
    worst_tick_us: AtomicU64,
}

/// One call, as an audio thread carries it.
struct Leg {
    share: SessionShare,
    socket: UdpSocket,
}

/// The audio threads, and how to hand them a call.
struct Carriers {
    to: Vec<Sender<Leg>>,
    threads: Vec<JoinHandle<()>>,
    next: usize,
    totals: Arc<Totals>,
    stop: Arc<AtomicBool>,
}

impl Carriers {
    fn start(count: usize) -> Self {
        let totals = Arc::new(Totals::default());
        let stop = Arc::new(AtomicBool::new(false));
        let mut to = Vec::new();
        let mut threads = Vec::new();
        for _ in 0..count.max(1) {
            let (sender, receiver) = channel();
            let totals = Arc::clone(&totals);
            let stop = Arc::clone(&stop);
            to.push(sender);
            threads.push(std::thread::spawn(move || carry(&receiver, &totals, &stop)));
        }
        Self {
            to,
            threads,
            next: 0,
            totals,
            stop,
        }
    }

    /// Give a call whose media has started to the next thread in turn.
    fn hand(&mut self, leg: Leg) {
        if let Some(sender) = self.to.get(self.next % self.to.len().max(1)) {
            let _ = sender.send(leg);
        }
        self.next = self.next.wrapping_add(1);
    }

    fn finish(self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// The most datagrams one call's socket is read for in one tick: one is
/// due, and a few more is a burst after a scheduling delay.
const SLOTS: usize = 8;

/// A datagram's room: RTP carrying twenty milliseconds of G.711 is 172
/// octets, and nothing this flow sends is larger than an Ethernet frame.
const SLOT: usize = 1_500;

/// What one call's socket held at the start of a tick, read before the
/// call's lock is taken: a system call made under the lock is a wait for
/// every other thread that wants the call, the signalling thread's timer
/// sweep among them.
struct Arrived {
    slots: Vec<[u8; SLOT]>,
    got: Vec<(usize, SocketAddr)>,
}

impl Arrived {
    fn new() -> Self {
        Self {
            slots: vec![[0_u8; SLOT]; SLOTS],
            got: Vec::with_capacity(SLOTS),
        }
    }

    fn read(&mut self, socket: &UdpSocket) {
        self.got.clear();
        for slot in &mut self.slots {
            match socket.recv_from(slot) {
                Ok((length, from)) => self.got.push((length, from)),
                Err(_) => break,
            }
        }
    }
}

/// One audio thread: every twenty milliseconds, every call it carries.
fn carry(calls: &Receiver<Leg>, totals: &Totals, stop: &AtomicBool) {
    let mut legs: Vec<Leg> = Vec::new();
    let mut inbox = Arrived::new();
    let mut outbox: Vec<u8> = Vec::with_capacity(SLOT);
    let tone = tone();
    let mut room = [0_i16; MAX_SAMPLES];
    let mut due = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        while let Ok(leg) = calls.try_recv() {
            legs.push(leg);
        }
        let began = Instant::now();
        if began > due + TICK {
            totals.late.fetch_add(1, Ordering::Relaxed);
            due = began;
        }
        legs.retain(|leg| {
            turn(
                leg,
                (&mut inbox, &mut outbox),
                &tone,
                &mut room,
                totals,
                began,
            )
        });
        let took = u64::try_from(began.elapsed().as_micros()).unwrap_or(u64::MAX);
        totals.worst_tick_us.fetch_max(took, Ordering::Relaxed);
        due += TICK;
        if let Some(wait) = due.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
    }
}

/// One call's twenty milliseconds: its socket read, then its session worked
/// under the call's lock, then what the session wrote sent. `false` once the
/// call has ended and its session is gone.
fn turn(
    leg: &Leg,
    (inbox, outbox): (&mut Arrived, &mut Vec<u8>),
    tone: &[i16; MAX_SAMPLES],
    room: &mut [i16; MAX_SAMPLES],
    totals: &Totals,
    now: Instant,
) -> bool {
    inbox.read(&leg.socket);
    let mut destination = None;
    let alive = leg
        .share
        .with(|session| {
            for ((length, from), slot) in inbox.got.iter().zip(inbox.slots.iter_mut()) {
                let datagram = slot.get_mut(..*length).unwrap_or_default();
                if matches!(session.receive(datagram, *from, now), Arrival::Queued) {
                    totals.received.fetch_add(1, Ordering::Relaxed);
                }
            }
            let frame = session.frame_samples().min(MAX_SAMPLES);
            if let Ok(Some(datagram)) = session.capture(tone.get(..frame).unwrap_or_default(), now)
            {
                outbox.clear();
                outbox.extend_from_slice(datagram.payload);
                destination = Some(datagram.destination);
            }
            let played = session.playback(room.get_mut(..frame).unwrap_or_default());
            if matches!(played, Playback::Packet) {
                totals.played.fetch_add(1, Ordering::Relaxed);
            } else {
                totals.dry.fetch_add(1, Ordering::Relaxed);
            }
        })
        .is_ok();
    if let Some(destination) = destination
        && leg.socket.send_to(outbox, destination).is_ok()
    {
        totals.sent.fetch_add(1, Ordering::Relaxed);
    }
    alive
}

/// A 400 Hz tone at a quarter of full scale, as many samples as the largest
/// frame: every call sends the same frame, which is all a codec that keeps
/// no state between frames needs, and G.711 keeps none.
fn tone() -> [i16; MAX_SAMPLES] {
    let mut out = [0_i16; MAX_SAMPLES];
    for (at, sample) in out.iter_mut().enumerate() {
        let phase = f64::from(u32::try_from(at).unwrap_or(0)) * 400.0 / 8_000.0;
        #[allow(clippy::cast_possible_truncation)]
        let value = ((phase * std::f64::consts::TAU).sin() * 8_000.0) as i16;
        *sample = value;
    }
    out
}

/// Time spent in one kind of call into the stack.
#[derive(Clone, Copy, Default)]
struct Spent {
    calls: u64,
    total: Duration,
}

impl Spent {
    fn add(&mut self, took: Duration) {
        self.calls = self.calls.saturating_add(1);
        self.total += took;
    }

    fn since(self, before: Self) -> Self {
        Self {
            calls: self.calls.saturating_sub(before.calls),
            total: self.total.saturating_sub(before.total),
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn mean_us(self) -> f64 {
        if self.calls == 0 {
            return 0.0;
        }
        self.total.as_secs_f64() * 1e6 / self.calls as f64
    }
}

/// One end: the agent and the engine on the signalling thread, and the
/// sockets of the calls it has, kept here as well for what the engine sends
/// on a call's behalf (RTCP).
struct Side {
    agent: UserAgent,
    engine: MediaEngine,
    sip: UdpSocket,
    local: SocketAddr,
    transport: TransportId,
    sockets: HashMap<CallHandle, UdpSocket>,
    inbox: Vec<u8>,
    polls: Spent,
    events: u64,
    engine_sweeps: Spent,
    agent_sweeps: Spent,
    /// Every drain of [`MediaEngine::poll_rtcp`], and the packets it gave.
    rtcp_drains: Spent,
    rtcp: u64,
    swept: Instant,
}

impl Side {
    fn bind(
        seed: u8,
        media_seed: u8,
        bind: SocketAddr,
        settings: &Settings,
        now: Instant,
    ) -> Result<Self, String> {
        let sip = UdpSocket::bind(bind).map_err(|error| format!("cannot bind {bind}: {error}"))?;
        sip.set_nonblocking(true)
            .map_err(|error| format!("cannot make the SIP socket non-blocking: {error}"))?;
        let local = sip
            .local_addr()
            .map_err(|error| format!("the SIP socket has no address: {error}"))?;
        let transport = TransportId(1);
        let mut agent = UserAgent::new(settings.endpoint(), run_folded([seed; 32]))
            .map_err(|error| format!("cannot start a user agent: {error}"))?;
        agent
            .receive(
                Input::TransportBound {
                    transport,
                    protocol: TransportProtocol::Udp,
                    local,
                    remote: None,
                },
                now,
            )
            .map_err(|error| format!("cannot bind the transport: {error}"))?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let engine = MediaEngine::new(
            catalog(),
            MediaConfig::default(),
            WallClock::from_unix(now, unix_seconds, 0),
            run_folded([media_seed; 32]),
        );
        Ok(Self {
            agent,
            engine,
            sip,
            local,
            transport,
            sockets: HashMap::new(),
            inbox: vec![0_u8; 65_535],
            polls: Spent::default(),
            events: 0,
            engine_sweeps: Spent::default(),
            agent_sweeps: Spent::default(),
            rtcp_drains: Spent::default(),
            rtcp: 0,
            swept: now,
        })
    }

    /// A socket for a call's media, on the same address as the signalling.
    fn media_socket(&self) -> Result<(UdpSocket, SocketAddr), String> {
        let socket = UdpSocket::bind(SocketAddr::new(self.local.ip(), 0))
            .map_err(|error| format!("cannot bind an RTP socket: {error}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| format!("cannot make the RTP socket non-blocking: {error}"))?;
        let local = socket
            .local_addr()
            .map_err(|error| format!("the RTP socket has no address: {error}"))?;
        Ok((socket, local))
    }

    /// Read whatever SIP arrived. `true` when something did.
    fn read_sip(&mut self, now: Instant) -> bool {
        let mut arrived = false;
        loop {
            match self.sip.recv_from(&mut self.inbox) {
                Ok((length, from)) => {
                    arrived = true;
                    let data = self.inbox.get(..length).unwrap_or_default();
                    let _ = self.agent.receive(
                        Input::Datagram {
                            transport: self.transport,
                            remote: from,
                            local: self.local,
                            data,
                        },
                        now,
                    );
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        arrived
    }

    /// Every event there is, each [`MediaEngine::poll_event`] timed.
    fn drain(&mut self, now: Instant) -> Vec<Event> {
        let mut out = Vec::new();
        loop {
            let began = Instant::now();
            let event = self.engine.poll_event(&mut self.agent, now);
            self.polls.add(began.elapsed());
            let Some(event) = event else {
                break;
            };
            self.events = self.events.saturating_add(1);
            out.push(event);
        }
        out
    }

    /// Write what the agent queued, and the goodbyes of calls that ended.
    fn flush(&mut self) {
        while let Some(transmit) = self.agent.poll_transmit() {
            let _ = self.sip.send_to(&transmit.payload, transmit.destination);
        }
        while let Some((call, destination, payload)) = self.engine.poll_farewell() {
            if let Some(socket) = self.sockets.get(&call) {
                let _ = socket.send_to(&payload, destination);
            }
        }
    }

    /// The two timer sweeps, and the RTCP that came due, no more often than
    /// [`SWEEP`]: RTCP is due every few seconds a call, and each
    /// [`MediaEngine::poll_rtcp`] looks at every session, so asking on every
    /// turn of the loop would cost a sweep a turn.
    fn sweep(&mut self, now: Instant) {
        if now < self.swept + SWEEP {
            return;
        }
        self.swept = now;
        let began = Instant::now();
        self.engine.handle_timeout(now);
        self.engine_sweeps.add(began.elapsed());
        let began = Instant::now();
        self.agent.handle_timeout(now);
        self.agent_sweeps.add(began.elapsed());
        let began = Instant::now();
        while let Some((call, destination, payload)) = self.engine.poll_rtcp(now) {
            self.rtcp = self.rtcp.saturating_add(1);
            if let Some(socket) = self.sockets.get(&call) {
                let _ = socket.send_to(&payload, destination);
            }
        }
        self.rtcp_drains.add(began.elapsed());
    }

    /// The call's media has started: an audio thread carries it from now on.
    fn carried(&mut self, call: CallHandle, carriers: &mut Carriers) {
        let (Some(share), Some(socket)) = (
            self.engine.share(call),
            self.sockets
                .get(&call)
                .and_then(|socket| socket.try_clone().ok()),
        ) else {
            return;
        };
        carriers.hand(Leg { share, socket });
    }
}

fn catalog() -> CodecCatalog {
    CodecCatalog::with_order(&["PCMU"])
        .unwrap_or_else(|_| CodecCatalog::new())
        .with_rtcp_mux(true)
}

/// This process's processor time and resident memory, from `/proc`: user
/// and system seconds, and the resident and peak resident set in kilobytes.
/// Zero where there is no `/proc` to read.
fn usage() -> (f64, f64, u64, u64) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // the fields after the command name, which is the one field that may
    // hold a space and is closed by the last parenthesis
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest.split_whitespace().collect())
        .unwrap_or_default();
    // utime and stime are the 14th and 15th fields of the whole line, the
    // 12th and 13th after the name; in clock ticks, which Linux reports at
    // USER_HZ, a hundred a second on every architecture this runs on
    let ticks = |at: usize| {
        fields
            .get(at)
            .and_then(|text| text.parse::<u32>().ok())
            .map_or(0.0, |ticks| f64::from(ticks) / 100.0)
    };
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let kilobytes = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|text| text.parse().ok())
            .unwrap_or(0)
    };
    (
        ticks(11),
        ticks(12),
        kilobytes("VmRSS:"),
        kilobytes("VmHWM:"),
    )
}

/// A call placed, as the calling end follows it.
#[derive(Clone, Copy)]
struct Placed {
    at: Instant,
    confirmed: Option<Instant>,
    ended: bool,
    /// Already counted among the failures: whatever else goes wrong with it
    /// later is the same call failing, not another one.
    failed: bool,
}

/// The calling end's count of what it asked for and what came of it, kept
/// apart from the sockets and the stack so that what is counted can be
/// checked on its own. Each call asked for is attempted once, placed or not,
/// and each counts at most one failure, however many things then go wrong
/// with it.
struct Tally<K> {
    calls: usize,
    attempts: usize,
    legs: HashMap<K, Placed>,
    failures: Vec<String>,
}

impl<K: Copy + Eq + Hash> Tally<K> {
    fn new(calls: usize) -> Self {
        Self {
            calls,
            attempts: 0,
            legs: HashMap::new(),
            failures: Vec::new(),
        }
    }

    /// Whether a call asked for is still to be attempted. A failure of a
    /// call already placed is not an attempt, so it does not cut the placing
    /// short.
    fn wants_more(&self) -> bool {
        self.attempts < self.calls
    }

    fn placed(&mut self, call: K, at: Instant) {
        self.attempts += 1;
        self.legs.insert(
            call,
            Placed {
                at,
                confirmed: None,
                ended: false,
                failed: false,
            },
        );
    }

    fn not_placed(&mut self, why: &str) {
        self.attempts += 1;
        self.failures.push(format!("not placed: {why}"));
    }

    fn confirmed(&mut self, call: K, at: Instant) {
        if let Some(leg) = self.legs.get_mut(&call) {
            leg.confirmed = Some(at);
        }
    }

    /// A call of ours ended; `early` says why that is a failure, when it is
    /// one. Whether the call was ours at all is the answer.
    fn ended(&mut self, call: K, early: Option<String>) -> bool {
        let Some(leg) = self.legs.get_mut(&call) else {
            return false;
        };
        leg.ended = true;
        if let Some(why) = early {
            self.fail(call, why);
        }
        true
    }

    /// Counts `why` against `call`, unless the call has already failed.
    fn fail(&mut self, call: K, why: String) {
        if let Some(leg) = self.legs.get_mut(&call)
            && !leg.failed
        {
            leg.failed = true;
            self.failures.push(why);
        }
    }

    /// Every call up or gone.
    fn settled(&self) -> bool {
        self.legs
            .values()
            .all(|leg| leg.confirmed.is_some() || leg.ended)
    }

    /// Counts every call neither up nor gone as never answered.
    fn write_off_unanswered(&mut self) {
        let unanswered: Vec<K> = self
            .legs
            .iter()
            .filter(|(_, leg)| leg.confirmed.is_none() && !leg.ended)
            .map(|(call, _)| *call)
            .collect();
        for call in unanswered {
            self.fail(call, "never answered".to_owned());
        }
    }

    fn unended(&self) -> Vec<K> {
        self.legs
            .iter()
            .filter(|(_, leg)| !leg.ended)
            .map(|(call, _)| *call)
            .collect()
    }

    fn all_ended(&self) -> bool {
        self.legs.values().all(|leg| leg.ended)
    }

    /// Counts every call still up as never ended — one already counted,
    /// never answered among them, stays counted once.
    fn write_off_unended(&mut self) {
        for call in self.unended() {
            self.fail(call, "never ended".to_owned());
        }
    }

    fn answered(&self) -> usize {
        self.legs
            .values()
            .filter(|leg| leg.confirmed.is_some())
            .count()
    }
}

/// The answering end: answer everything, carry its audio, and stop once
/// `SIPRAL_SCALE_CALLS` calls have come and gone, or after the patience, the
/// hold and the hangups have all run out with no call left.
///
/// # Errors
/// When it cannot bind.
pub(crate) fn answer(bind: SocketAddr) -> Result<String, String> {
    answer_with(bind, &Settings::read())
}

fn answer_with(bind: SocketAddr, settings: &Settings) -> Result<String, String> {
    let now = Instant::now();
    let mut side = Side::bind(ANSWER_SEED, ANSWER_MEDIA_SEED, bind, settings, now)?;
    // every call comes from the one address, as a switchboard's do: the
    // per-source rate a phone facing the internet keeps would refuse them
    side.agent.limit_invites(Rate::unlimited());
    let mut carriers = Carriers::start(settings.threads);
    println!(
        "  scale-answer: at {}, for {} calls, {} audio threads",
        side.local, settings.calls, settings.threads
    );
    let mut answered = 0_usize;
    let mut ended = 0_usize;
    let mut failed = 0_usize;
    let mut last_seen = now;
    let give_up = settings.patience + settings.hold + ENDING * 2;
    loop {
        let now = Instant::now();
        let arrived = side.read_sip(now);
        for event in side.drain(now) {
            match event {
                Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
                    last_seen = now;
                    let placed = side.media_socket().and_then(|(socket, local)| {
                        side.engine
                            .answer(&mut side.agent, call, local, now)
                            .map_err(|error| error.to_string())?;
                        side.sockets.insert(call, socket);
                        Ok(())
                    });
                    match placed {
                        Ok(()) => answered += 1,
                        Err(_) => failed += 1,
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::Started { .. },
                } => side.carried(call, &mut carriers),
                Event::Signalling(UaEvent::CallEnded { call, .. }) => {
                    last_seen = now;
                    ended += 1;
                    side.sockets.remove(&call);
                }
                _ => {}
            }
        }
        side.flush();
        side.sweep(now);
        let done = answered + failed >= settings.calls && ended >= answered;
        if (done && now > last_seen + Duration::from_secs(2)) || now > last_seen + give_up {
            break;
        }
        if !arrived {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let counted = side.agent.endpoint().retransmissions();
    carriers.finish();
    let (user, system, _, peak) = usage();
    Ok(format!(
        "   ({answered} answered, {failed} could not be, {ended} ended; {user:.1} s user + \
         {system:.1} s system, peak {peak} KB; SIP sent again {} requests, {} responses, {} \
         timed out)",
        counted.requests, counted.responses, counted.timeouts
    ))
}

/// The calling end: place `SIPRAL_SCALE_CALLS` calls at `SIPRAL_SCALE_RATE`
/// a second to `peer`, hold them all for `SIPRAL_SCALE_HOLD_MS` once every
/// one has come up or failed, hang up, and report.
///
/// # Errors
/// When it cannot bind, when nothing came up at all, or when any call failed
/// to come up or ended before it was hung up — with the report beside it.
pub(crate) fn call(peer: SocketAddr) -> Result<String, String> {
    call_with(peer, &Settings::read())
}

#[allow(clippy::too_many_lines)]
fn call_with(peer: SocketAddr, settings: &Settings) -> Result<String, String> {
    let now = Instant::now();
    let bind = SocketAddr::new(local_towards(peer), 0);
    let mut side = Side::bind(CALLER_SEED, CALLER_MEDIA_SEED, bind, settings, now)?;
    let account = caller_account(&mut side, peer)?;
    let target = uri(&format!("sip:scale@{peer}"))?;
    let mut carriers = Carriers::start(settings.threads);
    println!(
        "  scale: {} calls to {peer} at {} a second, held {:?}, {} audio threads",
        settings.calls, settings.rate, settings.hold, settings.threads
    );

    let gap = Duration::from_secs(1) / u32::try_from(settings.rate).unwrap_or(u32::MAX).max(1);
    let mut tally: Tally<CallHandle> = Tally::new(settings.calls);
    let mut next_at = now;
    let began = now;
    let mut hold_began: Option<(Instant, Snapshot)> = None;
    let mut held: Option<(Snapshot, Snapshot)> = None;
    let mut hung_up: Option<Instant> = None;
    let mut hanging: Vec<CallHandle> = Vec::new();
    let mut last_hangup = now;

    loop {
        let now = Instant::now();
        let arrived = side.read_sip(now);
        for event in side.drain(now) {
            match event {
                Event::Signalling(UaEvent::CallConfirmed { call, .. }) => {
                    tally.confirmed(call, now);
                }
                Event::Media {
                    call,
                    event: MediaEvent::Started { .. },
                } => side.carried(call, &mut carriers),
                Event::Signalling(UaEvent::CallEnded {
                    call,
                    reason,
                    status,
                    ..
                }) => {
                    side.sockets.remove(&call);
                    let early = hung_up.is_none().then(|| {
                        format!(
                            "ended before it was hung up: {reason:?}{}",
                            status.map(|code| format!(" ({code})")).unwrap_or_default()
                        )
                    });
                    tally.ended(call, early);
                }
                _ => {}
            }
        }

        let mut placing = 0;
        while tally.wants_more() && now >= next_at && placing < 64 {
            match place(&mut side, account, &target, peer, now) {
                Ok(call) => tally.placed(call, now),
                Err(why) => tally.not_placed(&why),
            }
            next_at += gap;
            placing += 1;
        }
        side.flush();
        side.sweep(now);

        if hold_began.is_none()
            && !tally.wants_more()
            && (tally.settled() || now > began + settings.patience)
        {
            tally.write_off_unanswered();
            hold_began = Some((now, Snapshot::take(&side, &carriers.totals, now)));
        }
        if let Some((at, before)) = hold_began
            && hung_up.is_none()
            && now >= at + settings.hold
        {
            held = Some((before, Snapshot::take(&side, &carriers.totals, now)));
            hanging = tally.unended();
            next_at = now;
            hung_up = Some(now);
        }
        // the BYEs go at the rate the INVITEs did: all of them in one burst
        // would be more datagrams than the far end's socket buffers, and
        // what a burst loses is the network's doing, not the stack's
        let mut ending = 0;
        while now >= next_at && ending < 64 {
            let Some(call) = hanging.pop() else {
                break;
            };
            if let Err(error) = side.agent.hangup(call, now) {
                tally.fail(call, format!("could not hang up: {error}"));
            }
            next_at += gap;
            ending += 1;
        }
        if ending > 0 {
            last_hangup = now;
        }
        // a call is reported ended as its BYE leaves, so that alone says
        // nothing about the BYE: stay until no transaction is left, or for
        // long enough that one lost BYE has gone again three times (T1, 2·T1
        // and 4·T1 after it) — an INVITE's own transaction stands for 64·T1
        // after its 2xx, which a short hold would otherwise wait out
        let drained = side.agent.endpoint().in_flight().0 == 0 || now > last_hangup + DRAIN;
        if let Some(at) = hung_up
            && hanging.is_empty()
            && ((tally.all_ended() && drained) || now > at + ENDING)
        {
            tally.write_off_unended();
            break;
        }
        if !arrived {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let counted = side.agent.endpoint().retransmissions();
    let worst_tick_us = carriers.totals.worst_tick_us.load(Ordering::Relaxed);
    carriers.finish();
    let setups = setup_times(&tally.legs);
    let report = Report {
        settings,
        placed: &tally.legs,
        setups: &setups,
        held,
        retransmitted: (counted.requests, counted.responses, counted.timeouts),
        worst_tick_us,
    }
    .render();
    if tally.answered() == 0 {
        return Err(format!("nothing answered{report}"));
    }
    if let Some(first) = tally.failures.first() {
        return Err(format!(
            "{} of {} failed, the first: {first}{report}",
            tally.failures.len(),
            settings.calls
        ));
    }
    Ok(report)
}

/// The address on this machine that reaches `peer`.
fn local_towards(peer: SocketAddr) -> IpAddr {
    if peer.ip().is_loopback() {
        return peer.ip();
    }
    crate::route_to(peer)
}

fn caller_account(side: &mut Side, peer: SocketAddr) -> Result<AccountId, String> {
    let here = side.local;
    let aor = uri(&format!("sip:scale-caller@{here}"))?;
    let registrar = uri(&format!("sip:{peer}"))?;
    let contact = uri(&format!("sip:scale-caller@{here}"))?;
    Ok(side
        .agent
        .add_account(Account::new(aor, registrar, contact, side.transport, peer)))
}

fn place(
    side: &mut Side,
    account: AccountId,
    target: &sipral::Uri,
    peer: SocketAddr,
    now: Instant,
) -> Result<CallHandle, String> {
    let (socket, local) = side.media_socket()?;
    let outgoing = OutgoingCall::new(target.clone()).to_address(side.transport, peer);
    let media = CallMedia::new(catalog(), MediaConfig::default());
    let call = side
        .engine
        .place_with(&mut side.agent, account, outgoing, local, media, now)
        .map_err(|error| error.to_string())?;
    side.sockets.insert(call, socket);
    Ok(call)
}

/// Every answered call's time from its INVITE to its 2xx, sorted.
fn setup_times(placed: &HashMap<CallHandle, Placed>) -> Vec<Duration> {
    let mut setups: Vec<Duration> = placed
        .values()
        .filter_map(|leg| Some(leg.confirmed?.saturating_duration_since(leg.at)))
        .collect();
    setups.sort();
    setups
}

/// What the calling end had counted at one moment.
#[derive(Clone, Copy)]
struct Snapshot {
    at: Instant,
    user: f64,
    system: f64,
    resident_kb: u64,
    sent: u64,
    received: u64,
    played: u64,
    dry: u64,
    late: u64,
    polls: Spent,
    events: u64,
    engine_sweeps: Spent,
    agent_sweeps: Spent,
    rtcp_drains: Spent,
    rtcp: u64,
    calls: usize,
}

impl Snapshot {
    fn take(side: &Side, totals: &Totals, now: Instant) -> Self {
        let (user, system, resident_kb, _) = usage();
        Self {
            at: now,
            user,
            system,
            resident_kb,
            sent: totals.sent.load(Ordering::Relaxed),
            received: totals.received.load(Ordering::Relaxed),
            played: totals.played.load(Ordering::Relaxed),
            dry: totals.dry.load(Ordering::Relaxed),
            late: totals.late.load(Ordering::Relaxed),
            polls: side.polls,
            events: side.events,
            engine_sweeps: side.engine_sweeps,
            agent_sweeps: side.agent_sweeps,
            rtcp_drains: side.rtcp_drains,
            rtcp: side.rtcp,
            calls: side.engine.active().count(),
        }
    }
}

struct Report<'a> {
    settings: &'a Settings,
    placed: &'a HashMap<CallHandle, Placed>,
    setups: &'a [Duration],
    held: Option<(Snapshot, Snapshot)>,
    retransmitted: (u64, u64, u64),
    worst_tick_us: u64,
}

impl Report<'_> {
    #[allow(clippy::cast_precision_loss)]
    fn render(&self) -> String {
        use std::fmt::Write as _;
        let answered = self.setups.len();
        let first = self.placed.values().map(|leg| leg.at).min();
        let last = self.placed.values().filter_map(|leg| leg.confirmed).max();
        let rate = match (first, last) {
            (Some(first), Some(last)) if last > first => {
                answered as f64 / last.duration_since(first).as_secs_f64()
            }
            _ => 0.0,
        };
        let ms = |at: f64| percentile(self.setups, at).as_secs_f64() * 1e3;
        let mut out = format!(
            "   ({answered} of {} answered, {rate:.0} a second; setup p50 {:.1} ms, p90 {:.1} \
             ms, max {:.1} ms",
            self.settings.calls,
            ms(50.0),
            ms(90.0),
            ms(100.0),
        );
        if let Some((before, after)) = self.held {
            let seconds = after.at.duration_since(before.at).as_secs_f64().max(1e-9);
            let busy = (after.user - before.user) + (after.system - before.system);
            let _ = write!(
                out,
                "; held {} calls {seconds:.0} s: {:.2} cores ({:.1} s user + {:.1} s system), \
                 resident {} KB, {:.0} packets a second out and {:.0} in, {} frames played dry \
                 of {}, {} ticks late, the slowest tick {} µs; poll_event {:.2} µs over {} polls \
                 ({} events), engine sweep {:.0} µs, agent sweep {:.0} µs, RTCP drain {:.0} µs \
                 ({} packets)",
                after.calls,
                busy / seconds,
                after.user - before.user,
                after.system - before.system,
                after.resident_kb,
                (after.sent - before.sent) as f64 / seconds,
                (after.received - before.received) as f64 / seconds,
                after.dry - before.dry,
                (after.played - before.played) + (after.dry - before.dry),
                after.late - before.late,
                self.worst_tick_us,
                after.polls.since(before.polls).mean_us(),
                after.polls.since(before.polls).calls,
                after.events - before.events,
                after.engine_sweeps.since(before.engine_sweeps).mean_us(),
                after.agent_sweeps.since(before.agent_sweeps).mean_us(),
                after.rtcp_drains.since(before.rtcp_drains).mean_us(),
                after.rtcp - before.rtcp,
            );
        }
        let (requests, responses, timeouts) = self.retransmitted;
        let (_, _, _, peak) = usage();
        let _ = write!(
            out,
            "; peak {peak} KB; SIP sent again {requests} requests, {responses} responses, \
             {timeouts} timed out)"
        );
        out
    }
}

/// `p` in `[0, 100]` of a sorted list.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let last = sorted.len() - 1;
    let rank = (last as f64 * p / 100.0).round() as usize;
    sorted.get(rank.min(last)).copied().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use super::{Settings, Tally, answer_with, call_with, percentile};

    #[test]
    fn an_early_failure_does_not_cut_the_placing_short() {
        let now = Instant::now();
        let mut tally = Tally::new(3);
        tally.placed(1, now);
        tally.ended(1, Some("ended before it was hung up".to_owned()));
        assert!(tally.wants_more());
        tally.placed(2, now);
        assert!(tally.wants_more());
        tally.placed(3, now);
        assert!(!tally.wants_more());
        assert_eq!(tally.legs.len(), 3);
        assert_eq!(tally.failures.len(), 1);
    }

    #[test]
    fn a_call_that_could_not_be_placed_is_still_an_attempt() {
        let mut tally: Tally<u32> = Tally::new(2);
        tally.not_placed("no socket");
        assert!(tally.wants_more());
        tally.placed(1, Instant::now());
        assert!(!tally.wants_more());
        assert_eq!(tally.failures, ["not placed: no socket"]);
    }

    #[test]
    fn a_call_never_answered_is_not_also_counted_never_ended() {
        let now = Instant::now();
        let mut tally = Tally::new(2);
        tally.placed(1, now);
        tally.placed(2, now);
        tally.confirmed(1, now);
        tally.write_off_unanswered();
        assert_eq!(tally.failures, ["never answered"]);
        let mut hanging = tally.unended();
        hanging.sort_unstable();
        assert_eq!(hanging, [1, 2]);
        assert!(tally.ended(1, None));
        tally.write_off_unended();
        assert_eq!(tally.failures, ["never answered"]);
        assert_eq!(tally.answered(), 1);
    }

    #[test]
    fn a_call_never_answered_that_then_ends_early_counts_once() {
        let now = Instant::now();
        let mut tally = Tally::new(1);
        tally.placed(7, now);
        tally.write_off_unanswered();
        assert!(tally.ended(7, Some("ended before it was hung up: Timeout".to_owned())));
        tally.fail(7, "could not hang up: gone".to_owned());
        assert_eq!(tally.failures, ["never answered"]);
    }

    #[test]
    fn an_answered_call_that_never_ends_counts_once() {
        let now = Instant::now();
        let mut tally = Tally::new(2);
        tally.placed(1, now);
        tally.placed(2, now);
        tally.confirmed(1, now);
        tally.confirmed(2, now);
        tally.write_off_unanswered();
        assert!(tally.failures.is_empty());
        assert!(tally.ended(2, None));
        assert!(!tally.all_ended());
        tally.write_off_unended();
        assert_eq!(tally.failures, ["never ended"]);
        assert!(!tally.ended(9, None));
    }

    #[test]
    fn percentile_reads_off_the_sorted_list() {
        let sorted: Vec<Duration> = [5, 10, 20, 40]
            .iter()
            .map(|ms| Duration::from_millis(*ms))
            .collect();
        assert_eq!(percentile(&sorted, 0.0), Duration::from_millis(5));
        assert_eq!(percentile(&sorted, 100.0), Duration::from_millis(40));
        assert_eq!(percentile(&[], 50.0), Duration::ZERO);
    }

    /// The two ends of the flow in one process, on loopback, with a handful
    /// of calls held for a second: every call comes up, carries audio both
    /// ways, and is hung up, and the report says so.
    #[test]
    fn a_few_calls_come_up_carry_audio_and_are_hung_up() {
        let settings = || Settings {
            calls: 20,
            rate: 200,
            hold: Duration::from_secs(1),
            threads: 2,
            patience: Duration::from_secs(10),
        };
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer: SocketAddr = probe.local_addr().unwrap();
        drop(probe);
        let answering = std::thread::spawn(move || answer_with(peer, &settings()));
        std::thread::sleep(Duration::from_millis(200));
        let said = call_with(peer, &settings()).unwrap();
        assert!(said.contains("20 of 20 answered"), "{said}");
        assert!(said.contains("held 20 calls"), "{said}");
        assert!(!said.contains(" 0 packets a second in"), "{said}");
        let heard = answering.join().unwrap().unwrap();
        assert!(heard.contains("20 answered"), "{heard}");
    }
}
