// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A network test before a call, from C (ABI 1.2).
//!
//! [`sipral_stack_network_test`] asks, at once and without placing a call of
//! its own, the questions whose answers decide whether a call will work:
//!
//! - **STUN.** With `probe_socket` set, the socket is named exactly as
//!   `sipral_stack_nat_map` names one — the application binds it and sends
//!   and receives for it through `sipral_stack_poll_stun` and
//!   `sipral_stack_receive_stun` as it does for a call's — and its answer says
//!   where this end appears from and, approximately, what the NAT in front of
//!   it does. Without one, the answer the signalling socket was last given
//!   stands in. On a stack that asks no STUN server, not tested.
//! - **TURN.** On a stack with a TURN server, the probe socket is given a
//!   relay over the configured `turn_transport` (a connection to open for
//!   TCP or TLS, as `SIPRAL_EVENT_KIND_TURN_STREAM` asks for any socket), and
//!   it is given back when the test ends.
//! - **The account's server.** With `account` set, an `OPTIONS` on the
//!   account's own transport, timed; any answer is the server.
//! - **Echo.** With `echo_call` set — a call the application placed to an
//!   echo service, an extension that plays back what it hears — the audio
//!   that comes back is measured for `echo_ms` from the moment the call's
//!   media starts, rated with the E-model, and the call is hung up.
//!
//! What the test came to arrives as one
//! [`SipralEventKind::NetworkTest`](crate::event::SipralEventKind::NetworkTest),
//! once every part has answered or `timeout_ms` has passed, with a verdict:
//! good, acceptable or poor, the worst of the parts that were tested. The
//! thresholds are `sipral::network_test`'s and `docs/08-ffi.md` lists them.
//! The parts' own events — `SIPRAL_EVENT_KIND_NAT_MAPPING` and
//! `SIPRAL_EVENT_KIND_NAT_RELAY` about the probe socket, the echo call's —
//! arrive as they would for anything else.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::network_test::{
    EchoMeasurement, EchoQuality, Findings, NatKind, Probe, ServerReach, Verdict,
};
use sipral_ua::{AccountId, CallHandle, ProbeHandle, ProbeOutcome};

use crate::abi::{Number, codes, record};
use crate::error::{Fail, entry, fail};
use crate::event::SipralEvent;
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::nat::{Asked, Nat, Raised};
use crate::stack::{SipralTransport, StackState, handle_failed, with_stack_at};
use crate::status::SipralStatus;
use crate::versioned::{Versioned, read_versioned};

/// How long a test waits for its parts when the configuration says nothing.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an echo call is listened to when the configuration says nothing:
/// long enough for the first RTCP report, which RFC 3550 §6.2 has wait up to
/// about five seconds, to have brought a round trip back.
const DEFAULT_ECHO: Duration = Duration::from_secs(8);

codes! {
    /// What a network test, or one part of it, comes to. Names for
    /// `sipral_network_test_event_t::verdict` and `echo_verdict`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralNetworkVerdict: u32 {
        /// Nothing was tested.
        Unknown = 0,
        /// Calls should work and sound right.
        Good = 1,
        /// Calls should work, and may not everywhere or may not sound their
        /// best.
        Acceptable = 2,
        /// Calls are likely to fail or to sound bad.
        Poor = 3,
    }
}

codes! {
    /// Whether a part of a network test was tried, and how it went. Names
    /// for `sipral_network_test_event_t::stun`, `turn` and `echo`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralNetworkProbe: u32 {
        /// Not part of this test.
        NotTested = 0,
        /// The server answered as hoped; for the echo, audio came back and
        /// was measured.
        Succeeded = 1,
        /// It did not.
        Failed = 2,
    }
}

codes! {
    /// What a STUN answer says about the NAT in front of this end. Names for
    /// `sipral_network_test_event_t::nat`. Approximate: one answer shows
    /// whether the address and the port were translated, and nothing about
    /// how the NAT filters what arrives (RFC 4787).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralNatKind: u32 {
        /// No answer to read.
        Unknown = 0,
        /// No translation: the server saw the socket's own address.
        Open = 1,
        /// The address was translated and the port kept.
        PortPreserved = 2,
        /// The port was changed too.
        PortChanged = 3,
    }
}

codes! {
    /// What the account's server did with the test's `OPTIONS`. Names for
    /// `sipral_network_test_event_t::server`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralServerReach: u32 {
        /// Not part of this test.
        NotTested = 0,
        /// It answered: `server_status` with what, `server_round_trip_ms`
        /// after how long. Any final answer is a server that is there.
        Answered = 1,
        /// No answer before the request, or the test, timed out.
        TimedOut = 2,
        /// The transport refused the request or failed under it.
        TransportFailed = 3,
    }
}

record! {
    /// What [`sipral_stack_network_test`] tests. Zero in any member but
    /// `size` leaves that part out or takes its default.
    ///
    /// Set `size` to `sizeof(sipral_network_test_config_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralNetworkTestConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// The account whose server to probe, on the account's own
        /// transport, or `SIPRAL_HANDLE_NONE` to leave it out.
        pub account: SipralHandle,
        /// A UDP socket the application bound for the test, `host:port`,
        /// asked about as `sipral_stack_nat_map` asks about a media socket;
        /// null to ask about the signalling socket only, and to test no
        /// relay. Not NUL-terminated.
        pub probe_socket: *const c_char,
        /// How many bytes of it.
        pub probe_socket_len: usize,
        /// A call the application placed to an echo service, measured once
        /// its media starts and hung up by the test, or `SIPRAL_HANDLE_NONE`.
        pub echo_call: SipralHandle,
        /// How long the echo is measured. 8000 by default.
        pub echo_ms: u32,
        /// How long the whole test may take. 30000 by default; a part that
        /// has not answered by then counts as failed.
        pub timeout_ms: u32,
    }
}

// Safety: the trait's contract. Integers, a handle and a pointer with its
// length, and all-zero is a valid value of each: it leaves every part out.
unsafe impl Versioned for SipralNetworkTestConfig {
    const NAME: &'static str = "sipral_network_test_config";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralNetworkTestConfig, timeout_ms);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What a [`SipralEventKind::NetworkTest`](crate::event::SipralEventKind::NetworkTest)
    /// carries: every part of one test, and the verdict (ABI 1.2). The
    /// event's `account` is the account probed and its `call` the echo call,
    /// when there were any. The two addresses are `host:port`, not
    /// NUL-terminated, and the library's: valid for as long as the callback
    /// runs.
    #[derive(Clone, Copy)]
    pub struct SipralNetworkTestEvent {
        /// The number [`sipral_stack_network_test`] gave the test.
        pub test: u32,
        /// A [`SipralNetworkVerdict`]: the worst of the parts tested.
        pub verdict: Number<SipralNetworkVerdict>,
        /// A [`SipralNetworkProbe`]: whether a STUN server answered.
        pub stun: Number<SipralNetworkProbe>,
        /// A [`SipralNatKind`], from that answer.
        pub nat: Number<SipralNatKind>,
        /// A [`SipralNetworkProbe`]: whether the TURN server allocated a
        /// relay for the probe socket.
        pub turn: Number<SipralNetworkProbe>,
        /// A `SipralTransport`: what the TURN server was reached over, or
        /// zero when it was not tested.
        pub turn_protocol: Number<SipralTransport>,
        /// A [`SipralServerReach`].
        pub server: Number<SipralServerReach>,
        /// The status the server answered with, or zero.
        pub server_status: u32,
        /// From sending the `OPTIONS` to its answer, in milliseconds.
        pub server_round_trip_ms: u32,
        /// A [`SipralNetworkProbe`]: whether audio came back on the echo call
        /// and was measured. Failed for a call whose media never started, or
        /// that brought nothing back.
        pub echo: Number<SipralNetworkProbe>,
        /// A [`SipralNetworkVerdict`] for the echo alone.
        pub echo_verdict: Number<SipralNetworkVerdict>,
        /// Packets lost or too late to play, as a percentage of those due.
        pub loss_percent: f32,
        /// Interarrival jitter (RFC 3550 §6.4.1), in milliseconds.
        pub jitter_ms: f32,
        /// Nonzero when RTCP brought a round trip back in time.
        pub has_round_trip: u32,
        /// That round trip, in milliseconds.
        pub round_trip_ms: u32,
        /// The one-way delay the rating assumed: half the round trip and the
        /// jitter buffer's delay, in milliseconds.
        pub one_way_delay_ms: u32,
        /// G.107's transmission rating R, 0 to 100, for concealed G.711.
        pub r_factor: u32,
        /// The conversational mean opinion score estimated from it, 1.0 to
        /// 4.5.
        pub mos: f32,
        /// The socket the STUN answer was about: the probe socket, or the
        /// signalling socket.
        pub local: *const c_char,
        /// How many bytes of it.
        pub local_len: usize,
        /// Where the STUN server saw it. Empty without an answer.
        pub mapped: *const c_char,
        /// How many bytes of it.
        pub mapped_len: usize,
    }
}

/// Where an echo call stands.
#[derive(Clone, Copy, Debug)]
enum Echo {
    /// No echo in this test.
    None,
    /// Waiting for the call's media to start.
    Waiting(CallHandle),
    /// Measuring since the instant named, with the last figures read.
    Measuring(CallHandle, Instant, EchoMeasurement),
    /// Rated.
    Done(Option<EchoQuality>),
}

/// One test under way.
struct Running {
    id: u32,
    account: SipralHandle,
    echo_handle: SipralHandle,
    probe: Option<ProbeHandle>,
    server: Option<ServerReach>,
    /// The probe socket, which the test named and gives back.
    socket: Option<SocketAddr>,
    /// The socket the STUN part reads.
    asked: Option<SocketAddr>,
    echo: Echo,
    echo_for: Duration,
    deadline: Instant,
}

/// Every test a stack has under way.
#[derive(Default)]
pub(crate) struct Tests {
    next: u32,
    running: Vec<Running>,
}

impl Tests {
    /// The account's server answered a test's `OPTIONS`, or never will. A
    /// probe no test is waiting on any more — one whose test already timed
    /// out — is nothing anybody else wants either.
    pub(crate) fn server_probed(&mut self, probe: ProbeHandle, outcome: ProbeOutcome) {
        let reach = match outcome {
            ProbeOutcome::Answered { status, round_trip } => ServerReach::Answered {
                status: status.get(),
                round_trip,
            },
            ProbeOutcome::TransportFailed => ServerReach::TransportFailed,
            ProbeOutcome::TimedOut => ServerReach::TimedOut,
        };
        if let Some(test) = self
            .running
            .iter_mut()
            .find(|test| test.probe == Some(probe) && test.server.is_none())
        {
            test.server = Some(reach);
        }
    }

    /// When a test next has to be looked at: its deadline, or the end of its
    /// echo window.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.running
            .iter()
            .flat_map(|test| {
                let window = match test.echo {
                    Echo::Measuring(_, since, _) => Some(since + test.echo_for),
                    _ => None,
                };
                [Some(test.deadline), window]
            })
            .flatten()
            .min()
    }
}

/// Look at every test: measure the echo calls, and raise each test that has
/// every answer it is going to get.
pub(crate) fn service(state: &mut StackState, stack: SipralHandle, now: Instant) -> Vec<Raised> {
    let mut raised = Vec::new();
    let mut kept = Vec::new();
    for mut test in std::mem::take(&mut state.tests.running) {
        listen_to_echo(state, &mut test, now);
        let tested = test.asked.map(|local| Nat::tested(state, local));
        let waiting = now < test.deadline
            && (matches!(test.echo, Echo::Waiting(_) | Echo::Measuring(..))
                || (test.probe.is_some() && test.server.is_none())
                || tested.is_some_and(|tested| {
                    tested.mapping == Asked::Waiting
                        || (test.socket.is_some() && tested.relay == Asked::Waiting)
                }));
        if waiting {
            kept.push(test);
            continue;
        }
        if let Some(socket) = test.socket {
            // the relay goes back to the server, and the mapping is no
            // longer kept; a socket the application unmapped itself
            // meanwhile is nothing to give back
            let _ = Nat::unmap(state, socket, now);
        }
        raised.push(finish(stack, &test, tested.unwrap_or_default()));
    }
    state.tests.running = kept;
    raised
}

/// The echo call's figures, read while it runs, and the call hung up once
/// its window is over.
fn listen_to_echo(state: &mut StackState, test: &mut Running, now: Instant) {
    let (call, since, last) = match test.echo {
        Echo::Waiting(call) => (call, None, EchoMeasurement::default()),
        Echo::Measuring(call, since, last) => (call, Some(since), last),
        Echo::None | Echo::Done(_) => return,
    };
    let read = state.engine.share(call).and_then(|share| {
        share
            .with(|session| {
                let figures = session.statistics(now);
                EchoMeasurement {
                    received: figures.quality.received,
                    lost: figures
                        .quality
                        .lost
                        .saturating_add(figures.quality.discarded_late),
                    jitter: figures.quality.jitter,
                    round_trip: figures.round_trip,
                    buffer_delay: figures.quality.delay,
                }
            })
            .ok()
    });
    test.echo = match (read, since) {
        // the media has not started, and there is still time for it to
        (None, None) if now < test.deadline => Echo::Waiting(call),
        // it never started, or the call is gone
        (None, None) => Echo::Done(None),
        // gone while it was being measured: what was read last is the call
        (None, Some(_)) => Echo::Done(Some(last.rate())),
        (Some(read), None) => Echo::Measuring(call, now, read),
        (Some(read), Some(since)) if now < since + test.echo_for && now < test.deadline => {
            Echo::Measuring(call, since, read)
        }
        (Some(read), Some(_)) => {
            // the test's own call, and its last use: a call already ending
            // refuses, which is the same thing
            let _ = state.agent.hangup(call, now);
            Echo::Done(Some(read.rate()))
        }
    };
}

/// What one finished test found, and whether audio came back on its echo
/// call: a call that never had media, or brought nothing back, is rated as
/// everything lost.
fn findings_of(test: &Running, tested: crate::nat::Tested) -> (Findings, bool) {
    let mut findings = Findings::new();
    if let Some(local) = test.asked {
        match tested.mapping {
            Asked::Unasked => {}
            Asked::Waiting | Asked::Answered(None) => findings.stun = Probe::Failed,
            Asked::Answered(Some(public)) => {
                findings.stun = Probe::Succeeded;
                findings.public = Some(public);
                findings.nat = NatKind::of(local, Some(public));
            }
        }
        if test.socket.is_some() {
            findings.turn = match tested.relay {
                Asked::Unasked => Probe::NotTested,
                Asked::Answered(true) => Probe::Succeeded,
                Asked::Waiting | Asked::Answered(false) => Probe::Failed,
            };
        }
    }
    if test.probe.is_some() {
        findings.server = Some(test.server.unwrap_or(ServerReach::TimedOut));
    }
    let echo = match test.echo {
        Echo::None => None,
        Echo::Done(rated) => Some(rated),
        // the deadline came first
        Echo::Waiting(_) => Some(None),
        Echo::Measuring(_, _, last) => Some(Some(last.rate())),
    };
    let heard = echo
        .flatten()
        .is_some_and(|rated| rated.loss_percent < 100.0);
    findings.echo = echo.map(|rated| rated.unwrap_or_else(|| EchoMeasurement::default().rate()));
    (findings, heard)
}

/// The event one finished test raises, and the text its addresses point
/// into.
fn finish(stack: SipralHandle, test: &Running, tested: crate::nat::Tested) -> Raised {
    let (findings, heard) = findings_of(test, tested);
    let local = test
        .asked
        .map(|local| local.to_string())
        .unwrap_or_default();
    let mapped = findings
        .public
        .map(|public| public.to_string())
        .unwrap_or_default();
    let addresses = format!("{local}{mapped}");
    let base = addresses.as_ptr().cast::<c_char>();
    let piece = |offset: usize, len: usize| -> *const c_char {
        if len == 0 {
            std::ptr::null()
        } else {
            base.wrapping_add(offset)
        }
    };
    let (server, server_status, server_round_trip_ms) = match findings.server {
        None => (SipralServerReach::NotTested, 0, 0),
        Some(ServerReach::Answered { status, round_trip }) => (
            SipralServerReach::Answered,
            u32::from(status),
            millis(round_trip),
        ),
        Some(ServerReach::TimedOut) => (SipralServerReach::TimedOut, 0, 0),
        Some(ServerReach::TransportFailed) => (SipralServerReach::TransportFailed, 0, 0),
    };
    let echo = match (findings.echo, heard) {
        (None, _) => SipralNetworkProbe::NotTested,
        (Some(_), true) => SipralNetworkProbe::Succeeded,
        (Some(_), false) => SipralNetworkProbe::Failed,
    };
    let mut payload = SipralNetworkTestEvent {
        test: test.id,
        verdict: verdict(findings.verdict()) as u32,
        stun: probe(findings.stun) as u32,
        nat: nat_kind(findings.nat) as u32,
        turn: probe(findings.turn) as u32,
        turn_protocol: if findings.turn == Probe::NotTested {
            0
        } else {
            tested.relay_protocol
        },
        server: server as u32,
        server_status,
        server_round_trip_ms,
        echo: echo as u32,
        echo_verdict: SipralNetworkVerdict::Unknown as u32,
        loss_percent: 0.0,
        jitter_ms: 0.0,
        has_round_trip: 0,
        round_trip_ms: 0,
        one_way_delay_ms: 0,
        r_factor: 0,
        mos: 0.0,
        local: piece(0, local.len()),
        local_len: local.len(),
        mapped: piece(local.len(), mapped.len()),
        mapped_len: mapped.len(),
    };
    if let Some(quality) = findings.echo {
        rated_echo(&mut payload, &quality);
    }
    let mut event: SipralEvent = crate::event::network_tested(stack, payload);
    event.account = test.account;
    event.call = test.echo_handle;
    (event, addresses)
}

/// An echo call's rating, into the event.
#[allow(
    clippy::cast_possible_truncation,
    reason = "a percentage and milliseconds of jitter, both far inside an f32"
)]
fn rated_echo(payload: &mut SipralNetworkTestEvent, quality: &EchoQuality) {
    payload.echo_verdict = verdict(quality.verdict) as u32;
    payload.loss_percent = quality.loss_percent as f32;
    payload.jitter_ms = (quality.jitter.as_secs_f64() * 1000.0) as f32;
    payload.has_round_trip = u32::from(quality.round_trip.is_some());
    payload.round_trip_ms = quality.round_trip.map_or(0, millis);
    payload.one_way_delay_ms = millis(quality.one_way_delay);
    payload.r_factor = u32::from(quality.r_factor);
    payload.mos = quality.mos;
}

const fn nat_kind(said: NatKind) -> SipralNatKind {
    match said {
        NatKind::Unknown => SipralNatKind::Unknown,
        NatKind::Open => SipralNatKind::Open,
        NatKind::PortPreserved => SipralNatKind::PortPreserved,
        NatKind::PortChanged => SipralNatKind::PortChanged,
    }
}

fn millis(span: Duration) -> u32 {
    u32::try_from(span.as_millis()).unwrap_or(u32::MAX)
}

const fn verdict(said: Verdict) -> SipralNetworkVerdict {
    match said {
        Verdict::Unknown => SipralNetworkVerdict::Unknown,
        Verdict::Good => SipralNetworkVerdict::Good,
        Verdict::Acceptable => SipralNetworkVerdict::Acceptable,
        Verdict::Poor => SipralNetworkVerdict::Poor,
    }
}

const fn probe(said: Probe) -> SipralNetworkProbe {
    match said {
        Probe::NotTested => SipralNetworkProbe::NotTested,
        Probe::Succeeded => SipralNetworkProbe::Succeeded,
        Probe::Failed => SipralNetworkProbe::Failed,
    }
}

/// Start a test as `config` says.
fn start(
    state: &mut StackState,
    config: &SipralNetworkTestConfig,
    socket: Option<SocketAddr>,
    now: Instant,
) -> Result<u32, Fail> {
    let account: Option<AccountId> = if config.account == SIPRAL_HANDLE_NONE {
        None
    } else {
        Some(state.accounts.get(config.account).map_err(handle_failed)?)
    };
    let echo_call: Option<CallHandle> = if config.echo_call == SIPRAL_HANDLE_NONE {
        None
    } else {
        Some(state.calls.get(config.echo_call).map_err(handle_failed)?)
    };
    if let Some(socket) = socket {
        Nat::map_media(state, socket, now)?;
    }
    let probe = match account {
        Some(account) => match state.agent.probe_server(account, now) {
            Ok(probe) => Some(probe),
            Err(error) => {
                if let Some(socket) = socket {
                    let _ = Nat::unmap(state, socket, now);
                }
                return Err(crate::call::ua_failed(&error));
            }
        },
        None => None,
    };
    let asked = socket.or_else(|| {
        (Nat::tested(state, state.local).mapping != Asked::Unasked).then_some(state.local)
    });
    let id = state.tests.next;
    state.tests.next = state.tests.next.wrapping_add(1);
    let timeout = if config.timeout_ms == 0 {
        DEFAULT_TIMEOUT
    } else {
        Duration::from_millis(u64::from(config.timeout_ms))
    };
    state.tests.running.push(Running {
        id,
        account: config.account,
        echo_handle: config.echo_call,
        probe,
        server: None,
        socket,
        asked,
        echo: echo_call.map_or(Echo::None, Echo::Waiting),
        echo_for: if config.echo_ms == 0 {
            DEFAULT_ECHO
        } else {
            Duration::from_millis(u64::from(config.echo_ms))
        },
        deadline: now + timeout,
    });
    Ok(id)
}

entry! {
    /// Test the network before a call: STUN, TURN, the account's server and,
    /// with an echo call, the audio path, as `config` says (ABI 1.2). The
    /// answer arrives from a later `sipral_stack_poll` as one
    /// `SIPRAL_EVENT_KIND_NETWORK_TEST` carrying `*out_test`, once every part
    /// has answered or `timeout_ms` has passed. Tests may run side by side.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a `probe_socket` on a stack that asks
    /// no STUN server, and for an account whose server has not been located
    /// yet; `SIPRAL_STATUS_INVALID_ARGUMENT` for a `probe_socket` that is not
    /// an address or is a signalling socket of the stack's own; a handle
    /// that names no account or call of this stack is refused as handles are.
    /// Nothing is started when anything is refused.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_network_test_config_t` whose `size`
    /// member says how long it is, with `probe_socket` readable for
    /// `probe_socket_len` bytes; `out_test` must point at one `uint32_t`.
    fn sipral_stack_network_test(
        stack: SipralHandle,
        config: *const SipralNetworkTestConfig,
        now_ms: u64,
        out_test: *mut u32,
    ) {
        if out_test.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_test is null"));
        }
        let config = unsafe { read_versioned(config) }?;
        let socket = if config.probe_socket.is_null() && config.probe_socket_len == 0 {
            None
        } else {
            Some(unsafe {
                crate::media::address(config.probe_socket, config.probe_socket_len, "probe_socket")
            }?)
        };
        let id = with_stack_at(stack, now_ms, |state, now| start(state, &config, socket, now))?;
        unsafe { out_test.write(id) };
        Ok(())
    }
}
