// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! An agent with no audio device: it answers every call and echoes back what it hears, one 20 ms
//! frame later.
//!
//! Without a registrar, call it directly at the address it prints. It still holds one unregistered
//! account so the `Contact` in its answers is a real address (RFC 3261 §12.1.1); with an empty one
//! the caller could not continue the dialog.
//!
//! ```text
//! cargo run --example headless-agent -- --host 127.0.0.1 --port 5070
//! ```
//!
//! `--host` must be a routable address, not a wildcard: it is advertised in every offer and answer,
//! and a peer told `0.0.0.0` cannot reply (see `crates/sipral/examples/common/udp_endpoint.rs`).
//!
//! Behind a PBX it registers instead:
//!
//! ```text
//! cargo run --example headless-agent -- --register agent@pbx.example \
//!     --registrar 192.0.2.10:5060 --pass secret [--call sip:9000@pbx.example] [--ice] \
//!     [--codecs PCMU,PCMA] [--max-calls 1000] [--invite-burst 200]
//! ```
//!
//! Registered, `--host` defaults to the local address the registrar is reached from, and the agent
//! follows it: if the route moves to another address (a container or laptop changing networks) it
//! rebinds its SIP socket there, reports it (`UserAgent::network_changed`), repoints the account
//! and re-offers every call. `--call` places one call after registration, `--ice` uses
//! `sipral::IcePolicy::Offered`, `--codecs` sets the codecs in order (default: the whole
//! catalogue), and `--invite-burst` lets that many INVITEs from one address arrive at once instead
//! of the scanner guard's ten (`sipral::Rate`), for an agent that only its PBX calls.
//!
//! **Concurrent calls.** 128 by default (`EndpointConfig::max_dialogs`); beyond that an incoming
//! call gets `503 Service Unavailable` with `Retry-After: 2` before ringing, so a proxy can try
//! another agent. `--max-calls N` raises the ceiling (ten thousand on one machine are measured in
//! `docs/19-numbers.md`) and the server transaction limit with it, to three per call plus the
//! default 256: an answered INVITE keeps its transaction 32 s (RFC 6026 timer L) and a BYE over UDP
//! as long (timer J). Without `--invite-burst`, the scanner guard then allows 2N INVITEs at once
//! and N per second after, so a full ceiling, ended and refilled, meets the ceiling and not the
//! guard; sub-second calls faster than N per second still hit the guard. An explicit
//! `--invite-burst` is used as given, and excess INVITEs get 480. Each call uses two UDP sockets
//! (RTP, and RTCP until the far end muxes), so `ulimit -n` must allow 2N plus a few; a call that
//! cannot get a socket is refused 503 and logged to stderr.
//!
//! **Commands on stdin.** `netchange`: the network changed. The route is re-read within 50 ms (the
//! loop's longest wait between stdin checks), the stack is told (`UserAgent::network_changed`) even
//! if the address is unchanged, since the path behind it may have moved and the stack then
//! re-registers, and everything moves if the address changed. One line reports what was done.
//! `quit`: hang up all calls, unregister, and exit when both are answered or after five seconds.
//! End of stdin is not a command, so under a service manager with stdin closed the agent keeps
//! answering. Started with `&` in an interactive shell, give it `< /dev/null`, or `SIGTTIN` stops
//! it.
//!
//! A request too big for UDP (RFC 3261 §18.1.1: over 1300 bytes without a known path MTU) prints
//! `transport wanted`, since this agent opens no stream transports. Each call's end prints what its
//! receiving side measured, including the E-model R factor and MOS and, as `recovered`, frames Opus
//! rebuilt from FEC; `scripts/lab.sh compare` reads these lines.
//!
//! This is the shape a voice agent embeds: a socket, a [`sipral::UserAgent`], a
//! [`sipral::MediaEngine`], and `i16` PCM frames for anything to read and write, such as a model
//! instead of an echo.

// no-panic rules are for shipped code; the test at the bottom may take shortcuts
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

#[path = "common/entropy.rs"]
mod entropy;
#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/udp_endpoint.rs"]
mod udp_endpoint;
#[path = "common/wall_clock.rs"]
mod wall_clock;

use std::collections::HashMap;
use std::env;
use std::io::BufRead;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sipral::{
    Account, AccountId, CallHandle, CodecCatalog, Credentials, EndpointConfig, Event, Link,
    MediaConfig, MediaEngine, MediaEvent, Network, OutgoingCall, Quality, Rate, Recovery,
    StatusCode, StreamStatistics, UaEvent, Uri, UserAgent,
};

use sipral_core::endpoint::Event as CoreEvent;
use udp_endpoint::Endpoint;

/// One call's worth of what it said last turn, played back this turn.
type Echoes = HashMap<CallHandle, Vec<i16>>;

/// How often to check which address the route to the registrar uses. Containers are not told about
/// network changes, so it polls twice a second.
const ROUTE_CHECK: Duration = Duration::from_millis(500);

/// After `--invite-burst` is spent, one more INVITE per source is allowed this often: the stack's
/// default, so the flag only changes the burst size.
const INVITE_REFILL: Duration = Duration::from_secs(2);

/// How long `quit` waits for answers to its BYEs and de-registration before exiting; otherwise an
/// unanswered one would hold the process for RFC 3261's 32 s timer F.
const QUIT_GRACE: Duration = Duration::from_secs(5);

/// While a call has an audio socket, the loop turns at least this often, on a fixed [`Grid`].
/// Packet arrival times (and so reported jitter and delay) are those turns. A 20 ms frame is two of
/// these, so frames fall on the grid.
///
/// Every turn reads every call's socket, the main per-call cost. On the lab's Linux host the old
/// waits ended on scheduler ticks (~8 ms). For a hundred loopback calls: 11.7 to 12.4 % of a core
/// before, 16.3 to 16.7 % with a 5 ms grid, 13.3 to 13.9 % with this one (`docs/19-numbers.md`):
/// nearly as fine-grained for a third of the cost.
const MEDIA_LOOK: Duration = Duration::from_millis(10);

/// The longest a stdin command waits while nothing else turns the loop: the reader thread cannot
/// wake a loop waiting for SIP, so the loop checks.
const COMMAND_LOOK: Duration = Duration::from_millis(50);

/// The instants audio moves at: every [`MEDIA_LOOK`] since start.
///
/// Frames are due on grid instants 20 ms apart. A turn runs media at the last grid instant it has
/// reached, not when it began, so a turn woken early by SIP sends nothing early and a late wake
/// sends the frame it owed. The far end then gets one frame per 20 ms plus wake-up lateness,
/// instead of whatever the turn spacing was; before the grid, frames left the lab host 16, 24 or 28
/// ms apart (`docs/19-numbers.md`).
#[derive(Clone, Copy, Debug)]
struct Grid {
    epoch: Instant,
}

impl Grid {
    /// The last instant of the grid at or before `now`.
    fn at_or_before(self, now: Instant) -> Instant {
        let since = now.saturating_duration_since(self.epoch);
        let look = MEDIA_LOOK.as_nanos().max(1);
        let whole = since.as_nanos() / look * look;
        self.epoch + Duration::from_nanos(u64::try_from(whole).unwrap_or(u64::MAX))
    }

    /// The first instant of the grid after `now`.
    fn after(self, now: Instant) -> Instant {
        self.at_or_before(now) + MEDIA_LOOK
    }
}

/// Server transactions per call `--max-calls` reserves: the INVITE's (kept 32 s after answer, RFC
/// 6026 timer L), the BYE's (as long over UDP, RFC 3261 timer J), and the next call's INVITE within
/// that half minute.
const TRANSACTIONS_PER_CALL: usize = 3;

/// Registration: `--register user@domain --registrar ip:port --pass secret`.
#[derive(Debug, PartialEq, Eq)]
struct Registration {
    user: String,
    domain: String,
    registrar: SocketAddr,
    pass: String,
}

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    /// `--host`; with a registrar and no `--host`, the address the registrar is reached from.
    host: Option<IpAddr>,
    port: u16,
    registration: Option<Registration>,
    /// `--call`, placed through the registrar once registration is accepted.
    call: Option<String>,
    /// `--ice`.
    ice: bool,
    /// `--codecs`, comma-separated; this build's whole catalogue when absent.
    codecs: Option<Vec<String>>,
    /// `--invite-burst`: INVITEs one source may send at once before the rest get 480; the stack
    /// default when absent.
    invite_rate: Option<Rate>,
    /// `--max-calls`: the most concurrent calls; the stack's 128 when absent.
    max_calls: Option<u32>,
}

impl Args {
    /// The endpoint's configuration: the stack's defaults, with the
    /// ceilings `--max-calls` raises raised.
    fn endpoint_config(&self) -> EndpointConfig {
        let mut config = EndpointConfig::default();
        if let Some(calls) = self.max_calls {
            let calls = usize::try_from(calls).unwrap_or(usize::MAX);
            config.max_dialogs = calls;
            config.max_server_transactions = calls
                .saturating_mul(TRANSACTIONS_PER_CALL)
                .saturating_add(EndpointConfig::DEFAULT.max_server_transactions);
        }
        config
    }

    /// The scanner guard, when not the stack default: `--invite-burst` as given, or with
    /// `--max-calls N`, 2N at once and N per second after.
    fn invite_guard(&self) -> Option<Rate> {
        if self.invite_rate.is_some() {
            return self.invite_rate;
        }
        let calls = self.max_calls?;
        let every = Duration::from_nanos((1_000_000_000 / u64::from(calls)).max(1));
        Rate::new(calls.saturating_mul(2), every).ok()
    }
}

fn parse_args(raw: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut host = None;
    let mut port = 5070_u16;
    let mut register = None;
    let mut registrar = None;
    let mut pass = None;
    let mut call = None;
    let mut ice = false;
    let mut codecs = None;
    let mut invite_rate = None;
    let mut max_calls = None;
    let mut raw = raw.into_iter();
    while let Some(flag) = raw.next() {
        let mut value = || raw.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--host" => {
                host = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--host takes an IP address".to_owned())?,
                );
            }
            "--port" => {
                port = value()?
                    .parse()
                    .map_err(|_| "--port takes a port number".to_owned())?;
            }
            "--register" => {
                let text = value()?;
                let (user, domain) = text
                    .split_once('@')
                    .ok_or_else(|| "--register takes user@domain".to_owned())?;
                register = Some((user.to_owned(), domain.to_owned()));
            }
            "--registrar" => {
                registrar = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--registrar takes ip:port".to_owned())?,
                );
            }
            "--pass" => pass = Some(value()?),
            "--call" => call = Some(value()?),
            "--codecs" => {
                let names: Vec<String> = value()?
                    .split(',')
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
                    .collect();
                let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                CodecCatalog::with_order(&refs).map_err(|error| format!("--codecs: {error}"))?;
                codecs = Some(names);
            }
            "--invite-burst" => {
                let burst = value()?
                    .parse()
                    .map_err(|_| "--invite-burst takes a count".to_owned())?;
                invite_rate = Some(
                    Rate::new(burst, INVITE_REFILL)
                        .map_err(|error| format!("--invite-burst: {error}"))?,
                );
            }
            "--max-calls" => {
                let calls: u32 = value()?
                    .parse()
                    .map_err(|_| "--max-calls takes a count".to_owned())?;
                if calls == 0 {
                    return Err("--max-calls 0 would refuse every call".to_owned());
                }
                max_calls = Some(calls);
            }
            "--ice" if cfg!(feature = "ice") => ice = true,
            "--ice" => return Err("--ice needs a build with the `ice` feature".to_owned()),
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    let registration = match (register, registrar) {
        (Some((user, domain)), Some(registrar)) => Some(Registration {
            user,
            domain,
            registrar,
            pass: pass.unwrap_or_default(),
        }),
        (None, None) if pass.is_none() => None,
        _ => return Err("--register, --registrar and --pass go together".to_owned()),
    };
    if call.is_some() && registration.is_none() {
        return Err("--call places its call through the registrar, so it needs one".to_owned());
    }
    Ok(Args {
        host,
        port,
        registration,
        call,
        ice,
        codecs,
        invite_rate,
        max_calls,
    })
}

/// A line on standard input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    /// `netchange`: the platform says the network changed.
    NetChange,
    /// `quit`: hang up, give the registration up, exit.
    Quit,
}

impl Command {
    /// `None` for a blank line; `Some(Err)` names a line that is no command.
    fn parse(line: &str) -> Option<Result<Self, String>> {
        match line.trim() {
            "" => None,
            "netchange" => Some(Ok(Self::NetChange)),
            "quit" => Some(Ok(Self::Quit)),
            other => Some(Err(format!(
                "unknown command {other:?}: the commands are netchange and quit"
            ))),
        }
    }
}

/// Read commands on their own thread so the call loop never waits. End of input only ends that
/// thread: under a service manager stdin is closed from the start and the agent must keep
/// answering.
fn commands(input: impl BufRead + Send + 'static) -> mpsc::Receiver<Command> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in input.lines() {
            let Ok(line) = line else {
                return;
            };
            let command = match Command::parse(&line) {
                Some(Ok(command)) => command,
                Some(Err(message)) => {
                    eprintln!("{message}");
                    continue;
                }
                None => continue,
            };
            // the loop is gone, which only happens on exit
            if sender.send(command).is_err() {
                return;
            }
        }
    });
    receiver
}

/// The catalogue for every call: the build default or `--codecs` (already validated by
/// [`parse_args`]), plus ICE if `--ice` (allowed only in builds with ICE).
fn catalog(codecs: Option<&[String]>, ice: bool) -> CodecCatalog {
    let refs: Vec<&str> = codecs
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    let catalog = if refs.is_empty() {
        CodecCatalog::new()
    } else {
        CodecCatalog::with_order(&refs).unwrap_or_default()
    };
    #[cfg(feature = "ice")]
    if ice {
        return catalog.with_ice(sipral::IcePolicy::Offered);
    }
    #[cfg(not(feature = "ice"))]
    let _ = ice;
    catalog
}

/// The address this host reaches the registrar from, watched for a change.
struct Route {
    registrar: SocketAddr,
    current: IpAddr,
    next_check: Instant,
}

impl Route {
    fn new(registrar: SocketAddr, current: IpAddr, now: Instant) -> Self {
        Self {
            registrar,
            current,
            next_check: now + ROUTE_CHECK,
        }
    }

    /// `Some((from, to))` once `probe` (the local address toward the registrar) changes, checked at
    /// most every [`ROUTE_CHECK`]. A loopback or unspecified answer means no route right now and is
    /// waited out.
    fn moved(
        &mut self,
        now: Instant,
        probe: impl FnOnce(SocketAddr) -> IpAddr,
    ) -> Option<(IpAddr, IpAddr)> {
        if now < self.next_check {
            return None;
        }
        self.reread(now, probe)
    }

    /// [`Route::moved`] without waiting, for `netchange`. The next scheduled check is pushed back a
    /// full interval.
    fn reread(
        &mut self,
        now: Instant,
        probe: impl FnOnce(SocketAddr) -> IpAddr,
    ) -> Option<(IpAddr, IpAddr)> {
        self.next_check = now + ROUTE_CHECK;
        let here = probe(self.registrar);
        if here == self.current || here.is_loopback() || here.is_unspecified() {
            return None;
        }
        let from = self.current;
        self.current = here;
        Some((from, here))
    }
}

/// What one call's receiving side counted by its end, and the E-model rating if it got that far:
/// the figures [`Ending::line`] prints.
struct Ending {
    codec: String,
    sent: u64,
    quality: Quality,
    /// Lost frames rebuilt from Opus FEC rather than concealed.
    recovered: u64,
    round_trip: Option<Duration>,
    r_factor: Option<u8>,
    mos_x10: Option<u8>,
}

impl Ending {
    fn of(stats: &StreamStatistics) -> Self {
        let known = |value: u8| (value != sipral::UNAVAILABLE).then_some(value);
        Self {
            codec: stats.codec.to_string(),
            sent: stats.packets_sent,
            quality: stats.quality,
            recovered: stats.fec_recovered,
            round_trip: stats.round_trip,
            r_factor: stats.voip_metrics.and_then(|block| known(block.r_factor)),
            mos_x10: stats.voip_metrics.and_then(|block| known(block.mos_lq)),
        }
    }

    /// One line of `name=value` pairs: loss as a share of packets sent per sequence numbers, jitter
    /// and buffer delay in ms, `-` for anything not measured.
    fn line(&self) -> String {
        let quality = &self.quality;
        let expected = quality.received + quality.lost;
        // packet counts of one call are exact in f64
        #[allow(clippy::cast_precision_loss)]
        let loss_pct = if expected == 0 {
            0.0
        } else {
            quality.lost as f64 * 100.0 / expected as f64
        };
        let unknown = || "-".to_owned();
        let rtt = self
            .round_trip
            .map_or_else(unknown, |rtt| format!("{:.1}", rtt.as_secs_f64() * 1e3));
        let r = self.r_factor.map_or_else(unknown, |r| r.to_string());
        let mos = self
            .mos_x10
            .map_or_else(unknown, |mos| format!("{:.1}", f64::from(mos) / 10.0));
        format!(
            "codec={} sent={} received={} lost={} recovered={} loss_pct={loss_pct:.2} late={} \
             reordered={} jitter_ms={:.2} delay_ms={:.1} rtt_ms={rtt} r={r} mos={mos}",
            self.codec,
            self.sent,
            quality.received,
            quality.lost,
            self.recovered,
            quality.discarded_late,
            quality.reordered,
            quality.jitter.as_secs_f64() * 1e3,
            quality.delay.as_secs_f64() * 1e3,
        )
    }
}

/// What the agent is holding besides its endpoint.
struct Agent {
    endpoint: Endpoint,
    account: AccountId,
    registration: Option<Registration>,
    route: Option<Route>,
    call: Option<String>,
    echoes: Echoes,
    /// When the calls' audio moves.
    grid: Grid,
    /// Set by `quit`: when the process exits regardless of pending answers.
    leaving: Option<Instant>,
    /// `quit` gave the registration up and the registrar has not answered.
    unregistering: bool,
}

impl Agent {
    /// A command read off standard input.
    fn obey(&mut self, command: Command, now: Instant) {
        match command {
            Command::NetChange => self.told(now, udp_endpoint::route_to),
            Command::Quit => self.quit(now),
        }
    }

    /// `netchange`: re-read the route now and tell the stack the network changed, whether or not
    /// the address did. `probe` is [`udp_endpoint::route_to`] outside tests.
    fn told(&mut self, now: Instant, probe: impl FnOnce(SocketAddr) -> IpAddr) {
        if let Some(route) = self.route.as_mut()
            && let Some((from, to)) = route.reread(now, probe)
        {
            let recovery = self.move_to(from, to, now);
            println!("told the network changed: moved from {from} to {to}: {recovery}");
            return;
        }
        // same address, so the agent cannot see what changed (path, NAT, link type). It trusts the
        // platform, and `Recovery::choose` re-proves the registration
        let here = self.endpoint.local.ip();
        let recovery = self.endpoint.agent.network_changed(
            &Network::new(Link::Down).address(here).resolves(true),
            &Network::new(Link::Wired).address(here).resolves(true),
            now,
        );
        let registration = if self.registration.is_some() {
            ""
        } else {
            " (no registration to prove)"
        };
        println!("told the network changed: still at {here}: {recovery}{registration}");
    }

    /// `quit`: every call hung up, the registration given up, and the
    /// process gone once both are answered or [`QUIT_GRACE`] has passed.
    fn quit(&mut self, now: Instant) {
        if self.leaving.is_some() {
            return;
        }
        self.leaving = Some(now + QUIT_GRACE);
        let calls = self.endpoint.agent.calls();
        for call in &calls {
            if let Err(error) = self.endpoint.agent.hangup(*call, now) {
                eprintln!("cannot hang {call:?} up: {error}");
            }
        }
        if self.registration.is_some() {
            match self.endpoint.agent.unregister(self.account, now) {
                Ok(()) => self.unregistering = true,
                Err(error) => eprintln!("cannot give the registration up: {error}"),
            }
        }
        println!(
            "quitting: {} calls hung up{}",
            calls.len(),
            if self.unregistering {
                ", the registration given up"
            } else {
                ""
            }
        );
    }

    /// Whether `quit` has finished: nothing left to be answered, or no more
    /// time to wait for it.
    fn finished(&self, now: Instant) -> bool {
        self.leaving.is_some_and(|deadline| {
            now >= deadline || (self.endpoint.agent.calls().is_empty() && !self.unregistering)
        })
    }

    /// When the loop must turn if no SIP datagram arrives first ([`run`] waits for SIP until then):
    /// the earliest stack timer, route check, `quit` deadline, next [`Grid`] instant while any call
    /// has audio, and next stdin check while stdin is open (`listening`). `None` means wait for a
    /// datagram.
    ///
    /// Only SIP is waited on. Every call socket is read every turn, and turns follow the grid while
    /// calls have audio, so waking on any readable media socket would just spin with a thousand
    /// calls.
    fn next_turn(&self, now: Instant, listening: bool) -> Option<Instant> {
        [
            (!self.endpoint.media.is_empty()).then(|| self.grid.after(now)),
            listening.then(|| now + COMMAND_LOOK),
            self.route.as_ref().map(|route| route.next_check),
            self.leaving,
            self.endpoint.agent.poll_timeout(),
            self.endpoint.engine.poll_timeout(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Place `--call`, once.
    fn place(&mut self, now: Instant) {
        let Some(target) = self.call.take() else {
            return;
        };
        match Uri::parse_str(&target) {
            Ok(uri) => {
                match udp_endpoint::place(
                    &mut self.endpoint,
                    self.account,
                    OutgoingCall::new(uri),
                    now,
                ) {
                    Ok(call) => println!("calling {target} as {call:?}"),
                    Err(error) => eprintln!("cannot call {target}: {error}"),
                }
            }
            Err(error) => eprintln!("cannot call {target}: {error}"),
        }
    }

    /// Follow a changed registrar route: rebind SIP there, report the change, repoint the account.
    /// Calls the stack then names in `CallAddressWanted` are re-offered by [`tick`].
    fn follow(&mut self, now: Instant) {
        let Some(route) = self.route.as_mut() else {
            return;
        };
        let Some((from, to)) = route.moved(now, udp_endpoint::route_to) else {
            return;
        };
        let recovery = self.move_to(from, to, now);
        println!("moved from {from} to {to}: {recovery}");
    }

    /// The route to the registrar moved from `from` to `to`: rebind SIP, report, repoint the
    /// account. Returns the stack's decision, or `Nothing` if binding failed and nothing was
    /// reported.
    fn move_to(&mut self, from: IpAddr, to: IpAddr, now: Instant) -> Recovery {
        let Some(registration) = self.registration.as_ref() else {
            return Recovery::Nothing;
        };
        let local = match self.endpoint.rebind_sip(to, now) {
            Ok(local) => local,
            Err(error) => {
                eprintln!("cannot bind at {to}: {error}");
                return Recovery::Nothing;
            }
        };
        let recovery = self.endpoint.agent.network_changed(
            &Network::new(Link::Wired).address(from).resolves(true),
            &Network::new(Link::Wired).address(to).resolves(true),
            now,
        );
        if recovery == Recovery::Rebuild {
            let rebound = Uri::parse_str(&format!("sip:{}@{local}", registration.user))
                .map_err(|error| error.to_string())
                .and_then(|contact| {
                    self.endpoint
                        .agent
                        .rebind(
                            self.account,
                            self.endpoint.transport,
                            registration.registrar,
                            &contact,
                            now,
                        )
                        .map_err(|error| error.to_string())
                });
            if let Err(error) = rebound {
                eprintln!("cannot point the account at {local}: {error}");
            }
        }
        recovery
    }
}

/// Handle what arrived and move each session's frames due by the last [`Grid`] instant: what was
/// heard goes back out, and what is heard now is kept for the next frame. `true` when a SIP
/// datagram arrived.
///
/// Anything the turn queued is sent before it ends, by the drain that finds no more events.
fn tick(agent: &mut Agent, now: Instant) -> bool {
    agent.follow(now);
    let arrived = agent.endpoint.read_sip(now);
    agent.endpoint.timers(now);
    settle(agent, now);
    let echoes = &mut agent.echoes;
    // frames move on the grid; reports and other engine output are polled at the real time. Polling
    // at the grid instant left reports due between instants overdue, so the loop spun until the
    // next instant and a hundred calls cost twice the CPU
    let beat = agent.grid.at_or_before(now);
    agent.endpoint.run_media(now, |call, media, session, _| {
        // one closure reads last frame's audio, the other stores this frame's: two `Vec`s, since
        // both closures exist at once
        let heard_before = echoes.remove(&call).unwrap_or_default();
        let mut heard_now = Vec::with_capacity(heard_before.len());
        let mut said = false;
        media.turn(
            session,
            beat,
            |room| {
                let filled = room.len().min(heard_before.len());
                if let Some(dst) = room.get_mut(..filled) {
                    dst.copy_from_slice(heard_before.get(..filled).unwrap_or(&[]));
                }
                if let Some(rest) = room.get_mut(filled..) {
                    rest.fill(0);
                }
                said = true;
            },
            |room| heard_now.extend_from_slice(room),
        );
        // a turn that moved no frame keeps what it heard for the turn that does; the loop turns
        // several times per frame, and dropping it sent silence
        let kept = if !heard_now.is_empty() {
            heard_now
        } else if said {
            Vec::new()
        } else {
            heard_before
        };
        echoes.insert(call, kept);
    });
    settle(agent, now);
    arrived
}

/// Drain and handle events until none are left: handling one can raise another, and the empty drain
/// flushes what the answers queued.
fn settle(agent: &mut Agent, now: Instant) {
    loop {
        let events = agent.endpoint.pump(now);
        if events.is_empty() {
            return;
        }
        for event in events {
            handle(agent, &event, now);
        }
    }
}

/// Answer one event.
fn handle(agent: &mut Agent, event: &Event, now: Instant) {
    match event {
        Event::Signalling(UaEvent::Registered { .. }) => {
            println!("registered");
            agent.place(now);
        }
        Event::Signalling(UaEvent::RegistrationFailed { reason, status, .. }) => {
            println!("registration failed: {reason} ({status:?})");
            agent.unregistering = false;
        }
        Event::Signalling(UaEvent::Unregistered { .. }) => {
            println!("unregistered");
            agent.unregistering = false;
        }
        Event::Signalling(UaEvent::IncomingCall { call, .. }) if agent.leaving.is_some() => {
            let _ = agent
                .endpoint
                .agent
                .reject(*call, StatusCode::SERVICE_UNAVAILABLE, now);
        }
        Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
            match agent.endpoint.open_media(*call, now) {
                Ok(local) => {
                    match agent
                        .endpoint
                        .engine
                        .answer(&mut agent.endpoint.agent, *call, local, now)
                    {
                        Ok(()) => println!("answered {call:?}"),
                        Err(error) => eprintln!("cannot answer {call:?}: {error}"),
                    }
                }
                // usually the open-file limit: two sockets per call until the far end muxes RTP and
                // RTCP
                Err(error) => {
                    eprintln!("cannot open a media socket for {call:?}, refused 503: {error}");
                    let _ =
                        agent
                            .endpoint
                            .agent
                            .reject(*call, StatusCode::SERVICE_UNAVAILABLE, now);
                }
            }
        }
        Event::Signalling(UaEvent::Unclaimed(CoreEvent::TransportWanted {
            protocol,
            destination,
            request_bytes,
            limit_bytes,
        })) => println!(
            "transport wanted: {protocol:?} to {destination} for a request of \
                 {request_bytes} bytes, over the {limit_bytes} a datagram may carry"
        ),
        Event::Signalling(UaEvent::CallConfirmed { call, .. }) => {
            println!("connected {call:?}");
        }
        Event::Signalling(UaEvent::CallAddressWanted { call }) => {
            agent.endpoint.readdress(*call, now);
        }
        Event::Media {
            call,
            event: MediaEvent::Ended(stats),
        } => println!("ended {call:?} {}", Ending::of(stats).line()),
        Event::Signalling(UaEvent::CallEnded { call, .. }) => {
            agent.echoes.remove(call);
            // otherwise every answered call's RTP socket stays in `endpoint.media` forever, which
            // matters for this long-running agent (see `Endpoint::close_media`)
            agent.endpoint.close_media(*call);
        }
        _ => {}
    }
}

fn main() -> ExitCode {
    let args = match parse_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: headless-agent [--host IP] [--port N] [--register USER@DOMAIN \
                 --registrar IP:PORT --pass SECRET] [--call SIP-URI] [--ice] \
                 [--codecs NAME,NAME] [--max-calls N (128)] [--invite-burst N]\n\
                 standard input: netchange, quit"
            );
            return ExitCode::FAILURE;
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let host = args.host.unwrap_or_else(|| {
        args.registration
            .as_ref()
            .map_or(IpAddr::from([127, 0, 0, 1]), |registration| {
                udp_endpoint::route_to(registration.registrar)
            })
    });
    let mut agent = UserAgent::new(args.endpoint_config(), entropy::seed()?)?;
    if let Some(rate) = args.invite_guard() {
        agent.limit_invites(rate);
    }
    let engine = MediaEngine::new(
        catalog(args.codecs.as_deref(), args.ice),
        MediaConfig::default(),
        wall_clock::at(now),
        entropy::seed()?,
    );
    // a real address, not a wildcard: it is advertised in every offer and answer (see
    // `Endpoint::bind`)
    let mut endpoint = Endpoint::bind(SocketAddr::new(host, args.port), agent, engine, now)?;
    let (account, route) = if let Some(registration) = &args.registration {
        let aor = Uri::parse_str(&format!(
            "sip:{}@{}",
            registration.user, registration.domain
        ))?;
        let registrar = Uri::parse_str(&format!("sip:{}", registration.domain))?;
        let contact = Uri::parse_str(&format!("sip:{}@{}", registration.user, endpoint.local))?;
        let account = endpoint.add_account(
            Account::new(
                aor,
                registrar,
                contact,
                endpoint.transport,
                registration.registrar,
            )
            .credentials(Credentials::new(&registration.user, &registration.pass)),
        );
        endpoint.agent.register(account, now)?;
        println!(
            "listening on {}; registering {}@{} at {}",
            endpoint.local, registration.user, registration.domain, registration.registrar
        );
        // `--host` pins the address; only a route-derived one is followed
        let route = args
            .host
            .is_none()
            .then(|| Route::new(registration.registrar, host, now));
        (account, route)
    } else {
        let identity = Uri::parse_str(&format!("sip:agent@{}", endpoint.local))?;
        let account = endpoint.add_account(Account::unregistered(
            identity.clone(),
            identity,
            endpoint.transport,
            endpoint.local,
        ));
        println!(
            "listening on {}; dial sip:agent@{}",
            endpoint.local, endpoint.local
        );
        (account, None)
    };

    // from here on SIP arrives on a channel, whose wait ends on time
    endpoint.read_in_background()?;
    let mut agent = Agent {
        endpoint,
        account,
        registration: args.registration,
        route,
        call: args.call,
        echoes: Echoes::new(),
        grid: Grid { epoch: now },
        leaving: None,
        unregistering: false,
    };
    let told = commands(std::io::BufReader::new(std::io::stdin()));
    let mut listening = true;
    loop {
        let now = Instant::now();
        loop {
            match told.try_recv() {
                Ok(command) => agent.obey(command, now),
                Err(mpsc::TryRecvError::Empty) => break,
                // stdin has ended; stop checking it
                Err(mpsc::TryRecvError::Disconnected) => {
                    listening = false;
                    break;
                }
            }
        }
        tick(&mut agent, now);
        if agent.finished(now) {
            println!("bye");
            return Ok(());
        }
        agent.endpoint.wait_sip(agent.next_turn(now, listening));
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use sipral::{Account, OutgoingCall, RegistrationState, Uri};

    use super::*;
    use sipral::WallClock;

    /// Two stacks on loopback: the agent answers, a second endpoint calls it, speaks, and hears
    /// itself back.
    ///
    /// Retried a few times: on a heavily loaded machine a UDP send can be delayed enough that the
    /// jitter buffer treats it as a new source and restarts RFC 3550 probation on the very packet
    /// meant to prove the round trip. Each attempt is an independent call, so only repeated failure
    /// fails the test.
    #[test]
    fn echoes_what_it_hears() {
        let mut last_failure = String::new();
        for _ in 0..3 {
            match one_call(true) {
                Ok(()) => return,
                Err(reason) => last_failure = reason,
            }
        }
        panic!("{last_failure}");
    }

    /// The same with a caller that keeps RTCP on its own port, as Asterisk does by default: the
    /// agent's answer promises RTCP on RTP port + 1 (RFC 3550 §11) and must listen there, or no
    /// round trip is ever measured.
    #[test]
    fn a_caller_that_does_not_multiplex_rtcp_finds_it_on_the_next_port() {
        let mut last_failure = String::new();
        for _ in 0..3 {
            match one_call(false) {
                Ok(()) => return,
                Err(reason) => last_failure = reason,
            }
        }
        panic!("{last_failure}");
    }

    /// `rtcp_mux`: whether both ends ask for RTCP on the RTP port.
    fn one_call(rtcp_mux: bool) -> Result<(), String> {
        let now = Instant::now();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        // G.711, not the default catalogue: it encodes sample by sample, so a steady tone survives
        // the round trip recognisably
        let codecs = || CodecCatalog::with_order(&["PCMU", "PCMA"]).unwrap();

        let mut agent_endpoint = Endpoint::bind(
            loopback,
            UserAgent::new(EndpointConfig::default(), [0x11; 32]).unwrap(),
            MediaEngine::new(
                codecs().with_rtcp_mux(rtcp_mux),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [0x12; 32],
            ),
            now,
        )
        .unwrap();
        let agent_address = agent_endpoint.local;
        let agent_identity = Uri::parse_str(&format!("sip:agent@{agent_address}")).unwrap();
        let agent_account = agent_endpoint.add_account(Account::unregistered(
            agent_identity.clone(),
            agent_identity,
            agent_endpoint.transport,
            agent_address,
        ));
        // read as `run` does, on its own thread
        agent_endpoint.read_in_background().unwrap();
        let mut agent = Agent {
            endpoint: agent_endpoint,
            account: agent_account,
            registration: None,
            route: None,
            call: None,
            echoes: Echoes::new(),
            grid: Grid { epoch: now },
            leaving: None,
            unregistering: false,
        };

        let mut caller_endpoint = Endpoint::bind(
            loopback,
            UserAgent::new(EndpointConfig::default(), [0x21; 32]).unwrap(),
            MediaEngine::new(
                codecs().with_rtcp_mux(rtcp_mux),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [0x22; 32],
            ),
            now,
        )
        .unwrap();

        let aor = Uri::parse_str("sip:caller@invalid.example").unwrap();
        let contact = Uri::parse_str(&format!("sip:caller@{}", caller_endpoint.local)).unwrap();
        let account = caller_endpoint.add_account(Account::unregistered(
            aor,
            contact,
            caller_endpoint.transport,
            agent_address,
        ));
        let target = Uri::parse_str(&format!("sip:agent@{agent_address}")).unwrap();
        let outgoing =
            OutgoingCall::new(target).to_address(caller_endpoint.transport, agent_address);
        let call = udp_endpoint::place(&mut caller_endpoint, account, outgoing, now).unwrap();

        // What the caller says once the call is up, and what it hears back. A few silent frames go
        // first, because RFC 3550 appendix A.1 source validation drops the first packets of a new
        // SSRC (`MIN_SEQUENTIAL`)
        let mut frames_sent = 0_u32;
        let mut heard: Vec<i16> = Vec::new();
        let mut up = false;
        const TONE: i16 = 8_000;
        const WARM_UP_FRAMES: u32 = 5;
        // 20 ms of G.711, and how many frames are checked once the tone is heard
        const FRAME: usize = 160;
        const LISTENED: usize = 25;
        let loud = |frame: &[i16]| frame.iter().any(|sample| sample.abs() > 1_000);
        let after_first_loud = |heard: &[i16]| {
            heard
                .chunks(FRAME)
                .position(|frame| loud(frame))
                .map_or(0, |first| heard.len() / FRAME - first)
        };

        // run until the tone has clearly and repeatedly come back, or the deadline passes; the
        // first echoed frames are the agent's own silence
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline && !(up && after_first_loud(&heard) > LISTENED) {
            let turn = Instant::now();
            for event in caller_endpoint.pump(turn) {
                if matches!(
                    event,
                    Event::Signalling(sipral::UaEvent::CallConfirmed { call: this, .. })
                        if this == call
                ) {
                    up = true;
                }
            }
            tick(&mut agent, turn);
            if up {
                caller_endpoint.run_media(turn, |this, media, session, now| {
                    if this != call {
                        return;
                    }
                    media.turn(
                        session,
                        now,
                        |room| {
                            frames_sent += 1;
                            if frames_sent >= WARM_UP_FRAMES {
                                room.fill(TONE);
                            } else {
                                room.fill(0);
                            }
                        },
                        |room| heard.extend_from_slice(room),
                    );
                });
            }
            caller_endpoint.timers(turn);
            agent.endpoint.timers(turn);
            let caller_read = caller_endpoint.read_sip(turn);
            let agent_read = agent.endpoint.read_sip(turn);
            if !caller_read && !agent_read {
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        if !up {
            return Err("the call never reached CallConfirmed".to_owned());
        }
        if !heard.iter().any(|sample| sample.abs() > 1_000) {
            return Err(format!(
                "nothing came back louder than silence in {} samples — the agent did not echo it",
                heard.len()
            ));
        }
        // continuous tone in, continuous tone back: an agent echoing only what each turn heard sent
        // back mostly silence
        let frames: Vec<&[i16]> = heard.chunks(FRAME).collect();
        let first = frames.iter().position(|frame| loud(frame)).unwrap_or(0);
        let listened = frames.iter().skip(first).take(LISTENED);
        let quiet = listened.filter(|frame| !loud(frame)).count();
        if quiet > LISTENED / 4 {
            return Err(format!(
                "{quiet} of the {LISTENED} frames after the tone first came back were silent"
            ));
        }
        let media = agent
            .endpoint
            .media
            .values()
            .next()
            .ok_or("the agent kept no media socket for the call")?;
        let rtp = media.port().map_err(|error| error.to_string())?;
        let wanted = (!rtcp_mux).then(|| rtp + 1);
        if media.rtcp_port() != wanted {
            return Err(format!(
                "RTCP is received on {:?} beside RTP on {rtp}, not on {wanted:?}",
                media.rtcp_port()
            ));
        }
        Ok(())
    }

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_registration_takes_its_three_flags_together() {
        let args = parse_args(words(
            "--register agent@pbx --registrar 192.0.2.10:5060 --pass secret \
             --call sip:9000@pbx --ice --port 5071 --codecs PCMU,PCMA --invite-burst 200",
        ))
        .unwrap();
        assert_eq!(
            args,
            Args {
                host: None,
                port: 5071,
                registration: Some(Registration {
                    user: "agent".to_owned(),
                    domain: "pbx".to_owned(),
                    registrar: "192.0.2.10:5060".parse().unwrap(),
                    pass: "secret".to_owned(),
                }),
                call: Some("sip:9000@pbx".to_owned()),
                ice: true,
                codecs: Some(vec!["PCMU".to_owned(), "PCMA".to_owned()]),
                invite_rate: Some(Rate::new(200, Duration::from_secs(2)).unwrap()),
                max_calls: None,
            }
        );
        assert!(parse_args(words("--register agent@pbx --pass secret")).is_err());
        assert!(parse_args(words("--registrar 192.0.2.10:5060")).is_err());
        assert!(parse_args(words("--pass secret")).is_err());
    }

    #[test]
    fn a_call_needs_a_registrar_and_an_unknown_flag_is_refused() {
        assert!(parse_args(words("--call sip:9000@pbx")).is_err());
        assert!(parse_args(words("--hots 127.0.0.1")).is_err());
        assert!(parse_args(words("--port")).is_err());
        assert!(parse_args(words("--codecs PCMU,NOPE")).is_err());
        assert!(parse_args(words("--invite-burst 0")).is_err());
        assert!(parse_args(words("--invite-burst many")).is_err());
        let plain = parse_args(words("--host 127.0.0.1")).unwrap();
        assert_eq!(plain.host, Some(IpAddr::from([127, 0, 0, 1])));
        assert_eq!(plain.port, 5070);
        assert_eq!(plain.registration, None);
        assert_eq!(plain.codecs, None);
        assert_eq!(plain.invite_rate, None);
        assert_eq!(plain.max_calls, None);
    }

    #[test]
    fn max_calls_raises_the_ceiling_what_grows_with_it_and_the_guard() {
        let plain = parse_args(words("--host 127.0.0.1")).unwrap();
        let config = plain.endpoint_config();
        assert_eq!(config.max_dialogs, 128);
        assert_eq!(config.max_server_transactions, 256);
        assert_eq!(plain.invite_guard(), None, "the stack's own guard");

        let raised = parse_args(words("--max-calls 1000")).unwrap();
        assert_eq!(raised.max_calls, Some(1000));
        let config = raised.endpoint_config();
        assert_eq!(config.max_dialogs, 1000);
        assert_eq!(config.max_server_transactions, 3 * 1000 + 256);
        assert_eq!(
            raised.invite_guard(),
            Some(Rate::new(2000, Duration::from_millis(1)).unwrap()),
            "two ceilings' worth at once, and a ceiling's worth a second after"
        );

        // --invite-burst given as well is taken as it is
        let both = parse_args(words("--max-calls 1000 --invite-burst 50")).unwrap();
        assert_eq!(both.endpoint_config().max_dialogs, 1000);
        assert_eq!(
            both.invite_guard(),
            Some(Rate::new(50, INVITE_REFILL).unwrap())
        );

        // below the default it lowers the ceiling; transactions keep the default room for non-call
        // use
        let small = parse_args(words("--max-calls 4")).unwrap();
        assert_eq!(small.endpoint_config().max_dialogs, 4);
        assert_eq!(small.endpoint_config().max_server_transactions, 3 * 4 + 256);

        assert!(parse_args(words("--max-calls 0")).is_err());
        assert!(parse_args(words("--max-calls many")).is_err());
        assert!(parse_args(words("--max-calls")).is_err());
        let huge = parse_args(words("--max-calls 4294967295")).unwrap();
        assert_eq!(
            huge.invite_guard(),
            Some(Rate::new(u32::MAX, Duration::from_nanos(1)).unwrap()),
            "an interval too short to count rounds up to a nanosecond, not to no limit"
        );
    }

    #[test]
    fn standard_input_says_netchange_and_quit_and_its_end_says_nothing() {
        assert_eq!(Command::parse("netchange"), Some(Ok(Command::NetChange)));
        assert_eq!(Command::parse("  quit \r"), Some(Ok(Command::Quit)));
        assert_eq!(Command::parse(""), None);
        assert!(matches!(Command::parse("reboot"), Some(Err(_))));

        let told = commands(std::io::Cursor::new(
            b"netchange\n\nnonsense\nquit\n".to_vec(),
        ));
        let wait = Duration::from_secs(5);
        assert_eq!(told.recv_timeout(wait), Ok(Command::NetChange));
        assert_eq!(told.recv_timeout(wait), Ok(Command::Quit));
        // end of input ends the reader thread and is not a command
        assert_eq!(
            told.recv_timeout(wait),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }

    /// The agent `run` builds from `args`, on loopback: registered with the named registrar, if
    /// any, and following its route.
    fn agent_on_loopback(args: &Args, seed: u8) -> Agent {
        let now = Instant::now();
        let mut user_agent = UserAgent::new(args.endpoint_config(), [seed; 32]).unwrap();
        if let Some(rate) = args.invite_guard() {
            user_agent.limit_invites(rate);
        }
        let mut endpoint = Endpoint::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            user_agent,
            MediaEngine::new(
                CodecCatalog::with_order(&["PCMU"]).unwrap(),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [seed.wrapping_add(1); 32],
            ),
            now,
        )
        .unwrap();
        let local = endpoint.local;
        let (account, route) = if let Some(registration) = &args.registration {
            let account = endpoint.add_account(
                Account::new(
                    Uri::parse_str(&format!(
                        "sip:{}@{}",
                        registration.user, registration.domain
                    ))
                    .unwrap(),
                    Uri::parse_str(&format!("sip:{}", registration.domain)).unwrap(),
                    Uri::parse_str(&format!("sip:{}@{local}", registration.user)).unwrap(),
                    endpoint.transport,
                    registration.registrar,
                )
                .credentials(Credentials::new(&registration.user, &registration.pass)),
            );
            endpoint.agent.register(account, now).unwrap();
            (
                account,
                Some(Route::new(registration.registrar, local.ip(), now)),
            )
        } else {
            let identity = Uri::parse_str(&format!("sip:agent@{local}")).unwrap();
            let account = endpoint.add_account(Account::unregistered(
                identity.clone(),
                identity,
                endpoint.transport,
                local,
            ));
            (account, None)
        };
        Agent {
            endpoint,
            account,
            registration: args.registration.as_ref().map(|registration| Registration {
                user: registration.user.clone(),
                domain: registration.domain.clone(),
                registrar: registration.registrar,
                pass: registration.pass.clone(),
            }),
            route,
            call: None,
            echoes: Echoes::new(),
            grid: Grid { epoch: now },
            leaving: None,
            unregistering: false,
        }
    }

    /// What the calling end of a test has seen of its calls.
    #[derive(Default)]
    struct Tally {
        confirmed: std::collections::HashSet<CallHandle>,
        /// Each ended call's status and, for a refusal, the response whole.
        ended: HashMap<CallHandle, (Option<u16>, String)>,
    }

    /// Turn caller and agent until `done` is true or 20 s pass; returns whether `done` became true.
    fn drive(
        caller: &mut Endpoint,
        agent: &mut Agent,
        tally: &mut Tally,
        mut done: impl FnMut(&Agent, &Tally) -> bool,
    ) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let turn = Instant::now();
            for event in caller.pump(turn) {
                match event {
                    Event::Signalling(UaEvent::CallConfirmed { call, .. }) => {
                        tally.confirmed.insert(call);
                    }
                    Event::Signalling(UaEvent::CallEnded {
                        call,
                        status,
                        response,
                        ..
                    }) => {
                        let text = response.map_or_else(String::new, |response| {
                            String::from_utf8_lossy(&response.bytes()).into_owned()
                        });
                        tally
                            .ended
                            .insert(call, (status.map(StatusCode::get), text));
                    }
                    _ => {}
                }
            }
            let agent_read = tick(agent, turn);
            caller.timers(turn);
            let caller_read = caller.read_sip(turn);
            if done(agent, tally) {
                return true;
            }
            if !agent_read && !caller_read {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        false
    }

    /// A ceiling's worth of calls, ended and immediately placed again, plus one more: all of both
    /// rounds get in (neither the scanner guard nor transactions still held from round one refuse
    /// any), and the extra one gets 503 with `Retry-After`. 150 exceeds both stack defaults: 128
    /// calls, and 256 transactions while round two meets 300 still held.
    #[test]
    fn two_full_bursts_back_to_back_meet_neither_the_guard_nor_the_ceiling() {
        const CALLS: usize = 150;
        let args = parse_args(words(&format!("--max-calls {CALLS}"))).unwrap();
        let mut agent = agent_on_loopback(&args, 0x31);
        let agent_address = agent.endpoint.local;
        let now = Instant::now();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // the caller's audio destination, never read: the caller sends no audio
        let sink = std::net::UdpSocket::bind(loopback).unwrap();
        let sink_address = sink.local_addr().unwrap();
        let mut roomy = EndpointConfig::default();
        roomy.max_dialogs = 4 * CALLS;
        roomy.max_server_transactions = 8 * CALLS;
        let mut caller = Endpoint::bind(
            loopback,
            UserAgent::new(roomy, [0x41; 32]).unwrap(),
            MediaEngine::new(
                CodecCatalog::with_order(&["PCMU"]).unwrap(),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [0x42; 32],
            ),
            now,
        )
        .unwrap();
        let contact = Uri::parse_str(&format!("sip:caller@{}", caller.local)).unwrap();
        let account = caller.add_account(Account::unregistered(
            Uri::parse_str("sip:caller@invalid.example").unwrap(),
            contact,
            caller.transport,
            agent_address,
        ));
        let place = |caller: &mut Endpoint| {
            let target = Uri::parse_str(&format!("sip:agent@{agent_address}")).unwrap();
            let transport = caller.transport;
            caller
                .engine
                .place(
                    &mut caller.agent,
                    account,
                    OutgoingCall::new(target).to_address(transport, agent_address),
                    sink_address,
                    Instant::now(),
                )
                .unwrap()
        };
        let mut tally = Tally::default();

        let first: Vec<CallHandle> = (0..CALLS).map(|_| place(&mut caller)).collect();
        assert!(
            drive(&mut caller, &mut agent, &mut tally, |_, tally| {
                tally.confirmed.len() == CALLS || !tally.ended.is_empty()
            }),
            "the first round did not come up"
        );
        assert_eq!(tally.confirmed.len(), CALLS, "refused: {:?}", tally.ended);

        let one_more = place(&mut caller);
        assert!(drive(&mut caller, &mut agent, &mut tally, |_, tally| {
            tally.ended.contains_key(&one_more)
        }));
        let (status, refusal) = tally.ended.get(&one_more).cloned().unwrap();
        assert_eq!(status, Some(503), "{refusal}");
        assert!(refusal.contains("\r\nRetry-After: 2\r\n"), "{refusal}");

        for call in &first {
            caller.agent.hangup(*call, Instant::now()).unwrap();
        }
        assert!(
            drive(&mut caller, &mut agent, &mut tally, |agent, tally| {
                tally.ended.len() == CALLS + 1 && agent.endpoint.agent.calls().is_empty()
            }),
            "the first round did not end"
        );

        let second: Vec<CallHandle> = (0..CALLS).map(|_| place(&mut caller)).collect();
        assert!(
            drive(&mut caller, &mut agent, &mut tally, |_, tally| {
                tally.confirmed.len() == 2 * CALLS || tally.ended.len() > CALLS + 1
            }),
            "the second round did not come up"
        );
        let refused: Vec<_> = second
            .iter()
            .filter_map(|call| tally.ended.get(call))
            .collect();
        assert!(refused.is_empty(), "refused: {refused:?}");
        assert_eq!(tally.confirmed.len(), 2 * CALLS);
        assert_eq!(
            agent.endpoint.agent.refusals(),
            sipral::Refusals::default(),
            "the guard turned nothing away"
        );
    }

    /// Answer one REGISTER on `registrar` with 200: five minutes, or removal for `expires` zero.
    /// Returns the request, if any.
    fn answer_register(registrar: &std::net::UdpSocket) -> Option<String> {
        let mut inbox = [0_u8; 4_096];
        let (length, from) = registrar.recv_from(&mut inbox).ok()?;
        let request = String::from_utf8_lossy(inbox.get(..length)?).into_owned();
        if !request.starts_with("REGISTER ") {
            return None;
        }
        let lower = request.to_ascii_lowercase();
        let removing = lower.contains("\r\nexpires: 0\r\n") || lower.contains("expires=0");
        let mut reply = String::from("SIP/2.0 200 OK\r\n");
        for line in request.split("\r\n").skip(1) {
            let name = line
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            match name.as_str() {
                "via" | "v" | "from" | "f" | "call-id" | "i" | "cseq" => {
                    reply.push_str(line);
                    reply.push_str("\r\n");
                }
                "to" | "t" => {
                    reply.push_str(line);
                    if !line.contains(";tag=") {
                        reply.push_str(";tag=registrar");
                    }
                    reply.push_str("\r\n");
                }
                "contact" | "m" if !removing => {
                    reply.push_str(line);
                    reply.push_str(";expires=300\r\n");
                }
                _ => {}
            }
        }
        reply.push_str("Content-Length: 0\r\n\r\n");
        registrar.send_to(reply.as_bytes(), from).ok()?;
        Some(request)
    }

    /// Turn the agent, answering and counting REGISTERs in `registers`, until `done` or 10 s;
    /// returns whether `done` became true.
    fn turn_until(
        agent: &mut Agent,
        registrar: &std::net::UdpSocket,
        registers: &mut usize,
        done: impl Fn(&Agent) -> bool,
    ) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !done(agent) {
            tick(agent, Instant::now());
            if answer_register(registrar).is_some() {
                *registers += 1;
            }
        }
        done(agent)
    }

    #[test]
    fn told_the_network_changed_it_registers_again_and_quit_gives_everything_up() {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let registrar = std::net::UdpSocket::bind(loopback).unwrap();
        registrar
            .set_read_timeout(Some(Duration::from_millis(2)))
            .unwrap();
        let args = parse_args(words(&format!(
            "--register agent@registrar.invalid --registrar {} --pass secret",
            registrar.local_addr().unwrap()
        )))
        .unwrap();
        let mut agent = agent_on_loopback(&args, 0x51);
        let account = agent.account;
        let mut registers = 0;
        let registered = |agent: &Agent| {
            agent.endpoint.agent.registration_state(account) == Some(RegistrationState::Registered)
        };
        assert!(
            turn_until(&mut agent, &registrar, &mut registers, registered),
            "never registered"
        );
        assert_eq!(registers, 1);

        // route unchanged: the stack re-proves the registration and the agent continues
        let here = agent.endpoint.local.ip();
        agent.told(Instant::now(), |_| here);
        assert_ne!(
            agent.endpoint.agent.registration_state(account),
            Some(RegistrationState::Registered),
            "the binding stopped being evidence the moment the change was told"
        );
        assert!(
            turn_until(&mut agent, &registrar, &mut registers, registered),
            "never registered again"
        );
        assert_eq!(registers, 2, "one REGISTER for being told");
        assert_eq!(agent.endpoint.local.ip(), here);
        assert!(!agent.finished(Instant::now()), "being told is not leaving");

        // nothing to hang up; unregisters and finishes once the registrar answers
        agent.quit(Instant::now());
        assert!(agent.unregistering);
        assert!(!agent.finished(Instant::now()));
        assert!(turn_until(
            &mut agent,
            &registrar,
            &mut registers,
            |agent| { agent.finished(Instant::now()) }
        ));
        assert_eq!(registers, 3, "one REGISTER giving the binding up");
        assert!(!agent.unregistering);
    }

    #[test]
    fn the_route_is_asked_twice_a_second_and_a_new_address_is_a_move() {
        let now = Instant::now();
        let old = IpAddr::from([192, 0, 2, 20]);
        let new = IpAddr::from([198, 51, 100, 20]);
        let mut route = Route::new("192.0.2.10:5060".parse().unwrap(), old, now);

        assert_eq!(route.moved(now, |_| new), None, "asked before its interval");
        let later = now + ROUTE_CHECK;
        assert_eq!(route.moved(later, |_| old), None, "the same address");
        let later = later + ROUTE_CHECK;
        assert_eq!(
            route.moved(later, |_| IpAddr::from([127, 0, 0, 1])),
            None,
            "no route out is waited out"
        );
        let later = later + ROUTE_CHECK;
        assert_eq!(route.moved(later, |_| new), Some((old, new)));
        let later = later + ROUTE_CHECK;
        assert_eq!(route.moved(later, |_| new), None, "moved once, not again");
    }

    #[test]
    fn the_audio_moves_on_a_grid_every_frame_falls_on() {
        let epoch = Instant::now();
        let grid = Grid { epoch };
        let look = MEDIA_LOOK;
        assert_eq!(grid.at_or_before(epoch), epoch);
        assert_eq!(grid.after(epoch), epoch + look);
        // any point inside a look maps to its start, and the next look follows
        for inside in [1, look.as_micros() / 2, look.as_micros() - 1] {
            let now = epoch + 7 * look + Duration::from_micros(u64::try_from(inside).unwrap());
            assert_eq!(grid.at_or_before(now), epoch + 7 * look);
            assert_eq!(grid.after(now), epoch + 8 * look);
        }
        // a frame is a whole number of looks, so frames 20 ms apart from a grid instant stay on the
        // grid
        let frame = media_socket::PACE;
        assert_eq!(frame.as_nanos() % look.as_nanos(), 0);
        let first = epoch + 3 * look;
        for n in 0..1_000_u32 {
            let due = first + frame * n;
            assert_eq!(grid.at_or_before(due), due);
        }
        // still correct a day in
        let later = epoch + Duration::from_secs(86_400) + Duration::from_micros(2_500);
        assert_eq!(
            grid.at_or_before(later),
            epoch + Duration::from_secs(86_400)
        );
    }

    /// The loop waits for SIP on the reader's channel: the wait ends at its deadline, never before
    /// (a socket timeout counts in scheduler ticks), and immediately on a datagram.
    #[test]
    fn a_wait_for_sip_ends_at_its_deadline_or_when_a_datagram_arrives() {
        let now = Instant::now();
        let mut endpoint = Endpoint::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            UserAgent::new(EndpointConfig::default(), [0x31; 32]).unwrap(),
            MediaEngine::new(
                CodecCatalog::with_order(&["PCMU"]).unwrap(),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [0x32; 32],
            ),
            now,
        )
        .unwrap();
        endpoint.read_in_background().unwrap();
        for _ in 0..20 {
            let deadline = Instant::now() + Duration::from_millis(2);
            endpoint.wait_sip(Some(deadline));
            assert!(Instant::now() >= deadline, "the wait ended early");
        }

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let waiting = Instant::now();
        let target = endpoint.local;
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            peer.send_to(b"OPTIONS sip:x SIP/2.0\r\n\r\n", target)
                .unwrap();
        });
        endpoint.wait_sip(Some(waiting + Duration::from_secs(5)));
        assert!(
            waiting.elapsed() < Duration::from_secs(4),
            "the datagram did not end the wait"
        );
        assert!(
            endpoint.read_sip(Instant::now()),
            "the datagram was not handed over"
        );
        sender.join().unwrap();

        // when the endpoint is dropped its reader wakes and frees the port at once
        let port = endpoint.local;
        drop(endpoint);
        let gone = Instant::now();
        while std::net::UdpSocket::bind(port).is_err() {
            assert!(
                gone.elapsed() < Duration::from_secs(2),
                "the reader still holds {port}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_call_ends_on_one_line_of_what_it_measured() {
        let quality = Quality {
            received: 990,
            lost: 10,
            discarded_late: 2,
            reordered: 3,
            jitter: Duration::from_micros(4_250),
            delay: Duration::from_millis(60),
            ..Quality::default()
        };
        let rated = Ending {
            codec: "opus".to_owned(),
            sent: 1_000,
            quality,
            recovered: 4,
            round_trip: Some(Duration::from_micros(12_340)),
            r_factor: Some(88),
            mos_x10: Some(42),
        };
        assert_eq!(
            rated.line(),
            "codec=opus sent=1000 received=990 lost=10 recovered=4 loss_pct=1.00 late=2 \
             reordered=3 jitter_ms=4.25 delay_ms=60.0 rtt_ms=12.3 r=88 mos=4.2"
        );
        let unrated = Ending {
            codec: "PCMA".to_owned(),
            sent: 0,
            quality: Quality::default(),
            recovered: 0,
            round_trip: None,
            r_factor: None,
            mos_x10: None,
        };
        assert_eq!(
            unrated.line(),
            "codec=PCMA sent=0 received=0 lost=0 recovered=0 loss_pct=0.00 late=0 reordered=0 \
             jitter_ms=0.00 delay_ms=0.0 rtt_ms=- r=- mos=-"
        );
    }
}
