// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! An agent with no device anywhere near it: it answers whatever calls it,
//! and repeats back whatever it hears, one twenty-millisecond frame later.
//!
//! With no registrar named, dial it directly at the address it prints. It
//! still holds one account, never registered, purely so the `Contact` on a
//! call it answers is a real address rather than an empty one (RFC 3261
//! §12.1.1); a caller that got an empty `Contact` back would have nowhere to
//! send the rest of the dialog and would drop the call rather than complete
//! it.
//!
//! ```text
//! cargo run --example headless-agent -- --host 127.0.0.1 --port 5070
//! ```
//!
//! `--host` names a real, routable address rather than defaulting to a
//! wildcard one: that address is what every call's offer or answer
//! advertises, and a peer handed `0.0.0.0` has nowhere to send anything
//! back to (`crates/sipral/examples/common/udp_endpoint.rs`'s own doc). On a
//! machine reachable from elsewhere, name the interface that is.
//!
//! Behind a PBX it registers instead, the way an agent sits behind one:
//!
//! ```text
//! cargo run --example headless-agent -- --register agent@pbx.example \
//!     --registrar 192.0.2.10:5060 --pass secret [--call sip:9000@pbx.example] [--ice] \
//!     [--codecs PCMU,PCMA] [--max-calls 1000] [--invite-burst 200]
//! ```
//!
//! Registered, `--host` defaults to whichever of this host's addresses the
//! registrar is reached from, and the agent follows that address: when the
//! route to the registrar leaves from a different one — a container moved
//! between networks, a laptop between two — it binds its SIP socket there,
//! reports the change (`UserAgent::network_changed`), points the account at
//! the new address and offers every call again at it. `--call` places one
//! call once the registration is accepted, `--ice` offers and answers with
//! ICE (`sipral::IcePolicy::Offered`), `--codecs` names the codecs offered
//! and accepted, in order, where this build's whole catalogue is the
//! default, and `--invite-burst` lets that many INVITEs from one address
//! arrive at once where the stack's own guard against scanners lets ten
//! (`sipral::Rate`): an agent whose PBX is the only thing that calls it, and
//! calls it a hundred times at once, is the switchboard that guard names.
//!
//! **How many calls at once.** The agent holds 128 calls at once unless
//! `--max-calls` says otherwise: the stack's default ceiling
//! (`EndpointConfig::max_dialogs`), past which an incoming call is answered
//! `503 Service Unavailable` with `Retry-After: 2` before it rings, so that a
//! proxy in front of several agents sends it to another and comes back once a
//! call here has ended. `--max-calls N` raises the ceiling to `N` (ten
//! thousand calls on one machine are measured in `docs/19-numbers.md`), and
//! with it what has to grow for `N` calls to stand: the server transactions
//! the stack may hold, to three a call and the default 256 besides, since an
//! answered INVITE keeps its transaction for 32 seconds (RFC 6026's timer
//! L) and a BYE over UDP keeps its own as long (timer J), so a ceiling's
//! worth of calls set up, ended and set up again inside that half minute
//! holds three each. With `--max-calls` and no `--invite-burst`, the guard
//! against scanners follows the ceiling too: twice `N` INVITEs from one
//! address at once — a full ceiling, ended, and a second full one straight
//! after it — and `N` more a second after that, so a rush up to the ceiling,
//! and a second one as soon as the first has ended, meets the ceiling and
//! not the guard. Calls shorter than a second, offered faster than `N` a
//! second for longer than that, still meet the guard: past its burst it
//! lets `N` a second in, whatever room the ceiling has.
//! `--invite-burst` given as well is taken as it is, and the guard then
//! refuses with 480 whatever it would refuse at that rate. Each call holds
//! two UDP sockets for its audio, its RTP port and the one after it for
//! RTCP, and lets the second go only once the far end keeps the two on one
//! port, so the process's open-file limit (`ulimit -n`) has to allow twice
//! `N` and a few more; a call the agent cannot open a socket for is refused 503 and
//! said on standard error.
//!
//! **What it is told.** A line on standard input is a command: `netchange`
//! says the network changed. The agent reads the route to the registrar
//! again as soon as it reads the line — within a twentieth of a second,
//! the longest its loop waits without looking at standard input — rather
//! than at its next half-second look, and tells the
//! stack (`UserAgent::network_changed`) even when the address is where it
//! was — the platform knows of a change the address does not show, such as
//! a new path behind the same one, so the stack registers again — and moves
//! everything when the address did change. It prints one line of what it
//! did. `quit` hangs every call up, gives the registration up and exits
//! once both are done or five seconds have passed. The end of standard
//! input is not a command: under a service manager with standard input
//! closed, the agent goes on answering. Started in the background of an
//! interactive shell (`&`), it is given `< /dev/null`: a background job
//! that reads the terminal is stopped (`SIGTTIN`) until it is brought to
//! the foreground.
//!
//! A request the stack will not put in a UDP datagram (RFC 3261
//! §18.1.1: over 1300 bytes with no known path MTU) is said on one line,
//! `transport wanted`, since this agent opens no stream transport to carry
//! it. Every call's end prints one line of
//! what its receiving side measured, the E-model's R factor and MOS among
//! it, so a run is compared by reading its output rather than a capture —
//! `scripts/lab.sh compare` reads it that way.
//!
//! This is the shape a voice agent embeds: a socket, a
//! [`sipral::UserAgent`], a [`sipral::MediaEngine`], and PCM in `i16` frames
//! that something other than an earpiece is free to read and write —
//! whatever answers here could as well be a model instead of an echo.

// the no-panic discipline is for what ships; the test at the bottom is
// allowed the shortcuts a test is for
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

/// How often the route to the registrar is asked which address it leaves
/// from. A platform that says when its network changed saves the asking; a
/// process in a container is told nothing, so it asks, twice a second.
const ROUTE_CHECK: Duration = Duration::from_millis(500);

/// Once `--invite-burst` is spent, one more INVITE from the same source is
/// let through every this often: the stack's own default interval, so the
/// flag changes how many calls may arrive together and nothing else.
const INVITE_REFILL: Duration = Duration::from_secs(2);

/// How long `quit` waits for the calls it hung up and the registration it
/// gave up to be answered before the process exits regardless: a BYE or a
/// REGISTER nobody answers would otherwise hold it for the 32 seconds of
/// RFC 3261's timer F.
const QUIT_GRACE: Duration = Duration::from_secs(5);

/// While a call has a socket for its audio, the loop turns at least this
/// often to read it: what a packet's arrival is timed at is the turn that
/// read it, and the jitter and delay every call's last line reports are
/// measured from those times.
const MEDIA_LOOK: Duration = Duration::from_millis(5);

/// While standard input is open, the longest a command waits to be read
/// when nothing else turns the loop: the thread reading it cannot wake a
/// loop waiting on a socket, so the loop looks.
const COMMAND_LOOK: Duration = Duration::from_millis(50);

/// Server transactions per call that `--max-calls` makes room for: the
/// INVITE's own, kept 32 seconds after it is answered (RFC 6026's timer L),
/// the BYE's, kept as long over UDP (RFC 3261's timer J), and the next
/// call's INVITE arriving inside that half minute.
const TRANSACTIONS_PER_CALL: usize = 3;

/// Where to register: `--register user@domain --registrar ip:port --pass
/// secret`.
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
    /// `--host`; with a registrar and no `--host`, the address the
    /// registrar is reached from.
    host: Option<IpAddr>,
    port: u16,
    registration: Option<Registration>,
    /// `--call`, placed through the registrar once it accepted the
    /// registration.
    call: Option<String>,
    /// `--ice`.
    ice: bool,
    /// `--codecs`, comma-separated; this build's whole catalogue when absent.
    codecs: Option<Vec<String>>,
    /// `--invite-burst`: how many INVITEs one source may offer at once
    /// before the stack's rate limit answers the rest 480; the stack's own
    /// default when absent.
    invite_rate: Option<Rate>,
    /// `--max-calls`: the most calls held at once; the stack's own ceiling,
    /// 128, when absent.
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

    /// The guard against one source offering calls too fast, when it is not
    /// the stack's own default: `--invite-burst` as given, or else, with
    /// `--max-calls N`, twice `N` at once and `N` a second after that.
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

/// Read commands off `input` on a thread of their own, so that the loop
/// carrying the calls never waits on it. The end of `input` ends the thread
/// and nothing else: an agent under a service manager has standard input
/// closed from the start, and must go on answering.
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
            // the loop it was for has gone, which only happens on the way out
            if sender.send(command).is_err() {
                return;
            }
        }
    });
    receiver
}

/// The catalogue every call is offered and answered from: this build's
/// default or the codecs `--codecs` named — which [`parse_args`] has already
/// checked this build has — with ICE on it when `--ice` asked for it, which
/// [`parse_args`] allows only in a build that has it.
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

    /// `Some((from, to))` once `probe` — which address a datagram to the
    /// registrar would leave from — names a different one than before; at
    /// most once every [`ROUTE_CHECK`]. A loopback or unspecified answer
    /// is a host with no route out at this moment, not a new address, and
    /// is waited out rather than moved to.
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

    /// [`Route::moved`] without waiting for its interval: what being told
    /// the network changed asks for. The next scheduled look is put back by
    /// a whole interval, since this one has just been taken.
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

/// What one call's receiving side counted by the time it ended, and the
/// E-model's rating of it when the stream got as far as rating: the figures
/// [`Ending::line`] prints.
struct Ending {
    codec: String,
    sent: u64,
    quality: Quality,
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
            round_trip: stats.round_trip,
            r_factor: stats.voip_metrics.and_then(|block| known(block.r_factor)),
            mos_x10: stats.voip_metrics.and_then(|block| known(block.mos_lq)),
        }
    }

    /// One line, `name=value` apart: loss as a share of the packets the
    /// sequence numbers say were sent, jitter and the buffer's delay in
    /// milliseconds, and `-` for what was never measured.
    fn line(&self) -> String {
        let quality = &self.quality;
        let expected = quality.received + quality.lost;
        // counts of packets in one call, far inside f64's exact range
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
            "codec={} sent={} received={} lost={} loss_pct={loss_pct:.2} late={} reordered={} \
             jitter_ms={:.2} delay_ms={:.1} rtt_ms={rtt} r={r} mos={mos}",
            self.codec,
            self.sent,
            quality.received,
            quality.lost,
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
    /// Set by `quit`: when the process exits whether or not everything it
    /// hung up and gave up has been answered by then.
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

    /// `netchange`: read the route again now, and tell the stack the network
    /// changed whether or not the address did. `probe` is
    /// [`udp_endpoint::route_to`] outside a test.
    fn told(&mut self, now: Instant, probe: impl FnOnce(SocketAddr) -> IpAddr) {
        if let Some(route) = self.route.as_mut()
            && let Some((from, to)) = route.reread(now, probe)
        {
            let recovery = self.move_to(from, to, now);
            println!("told the network changed: moved from {from} to {to}: {recovery}");
            return;
        }
        // Told, and finding the address where it was, the agent cannot see
        // what changed: the path behind the address, a NAT in front of it, a
        // link of another kind. It takes the platform at its word — the
        // network it was on is gone and this one came up at the same
        // address — and `Recovery::choose` answers that with a registration
        // proved again: the transports stand, and what is upstream of them
        // may not.
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

    /// When the loop has to turn again if no SIP datagram arrives first —
    /// [`run`] waits on the SIP socket until then: the earliest of the
    /// stack's own timers, the next look at the route, the end of `quit`'s
    /// grace, the next look at the calls' audio while there are any, and
    /// the next look at standard input while it is open (`listening`).
    /// `None` is nothing to do until a datagram arrives.
    ///
    /// Only the SIP socket is waited on. Every call's socket is read on
    /// every turn, and the turns come at least every [`MEDIA_LOOK`] while a
    /// call has one, so a call's audio sitting unread in its socket never
    /// wakes the loop by itself: with a thousand calls, a wait that woke
    /// for any readable socket would wake at once, every time, for audio
    /// that is read on the next turn anyway.
    fn next_turn(&self, now: Instant, listening: bool) -> Option<Instant> {
        [
            (!self.endpoint.media.is_empty()).then(|| now + MEDIA_LOOK),
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

    /// Follow the address the registrar is reached from, when it changed:
    /// the SIP socket bound there, the change reported, the account pointed
    /// at it. Every call the stack then names in `CallAddressWanted` is
    /// offered again from there by [`tick`].
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

    /// The address the registrar is reached from is `to` now, where it was
    /// `from`: the SIP socket bound there, the change reported, the account
    /// pointed at it. What the stack decided is the answer, or `Nothing`
    /// when the socket could not be bound and nothing was reported.
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

/// Read what arrived and answer it, and let every call's session move one
/// frame: what it said comes back out, and what it says now is kept for the
/// next turn. `true` when a SIP datagram arrived.
///
/// What the turn decided goes out before it ends: an answer queued while
/// the events are handled is written by the drain that finds no more of
/// them, not left for the next turn, which may be a wait away.
fn tick(agent: &mut Agent, now: Instant) -> bool {
    agent.follow(now);
    let arrived = agent.endpoint.read_sip(now);
    agent.endpoint.timers(now);
    settle(agent, now);
    let echoes = &mut agent.echoes;
    agent.endpoint.run_media(now, |call, media, session, now| {
        // one closure plays what was captured last turn, the other captures
        // what is heard this turn — two different `Vec`s, since both
        // closures exist at once and neither may borrow the same one
        let said_last_turn = echoes.remove(&call).unwrap_or_default();
        let mut said_this_turn = Vec::with_capacity(said_last_turn.len());
        media.turn(
            session,
            now,
            |room| {
                let filled = room.len().min(said_last_turn.len());
                if let Some(dst) = room.get_mut(..filled) {
                    dst.copy_from_slice(said_last_turn.get(..filled).unwrap_or(&[]));
                }
                if let Some(rest) = room.get_mut(filled..) {
                    rest.fill(0);
                }
            },
            |room| said_this_turn.extend_from_slice(room),
        );
        echoes.insert(call, said_this_turn);
    });
    settle(agent, now);
    arrived
}

/// Drain every event the stack has and answer each, until a drain finds
/// none: answering one can raise another (a call refused ends), and the
/// drain that comes back empty has written whatever the answers queued.
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
                // most often the open-file limit: two sockets a call until
                // the far end keeps RTP and RTCP on one port
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
            // Without this, every call this agent has ever answered
            // keeps its bound RTP socket alive in `endpoint.media` for
            // the rest of the process's life — harmless for the examples
            // that place one call and exit, real for the one that keeps
            // answering (`Endpoint::close_media`'s own doc).
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
    // A real address, not a wildcard: `Endpoint::bind`'s own documentation
    // says why — it becomes what every call's offer or answer advertises,
    // and a peer handed `0.0.0.0` has nowhere to send anything back to.
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
        // `--host` pins the address; only the one found by asking the
        // route is followed when the route changes
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

    let mut agent = Agent {
        endpoint,
        account,
        registration: args.registration,
        route,
        call: args.call,
        echoes: Echoes::new(),
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
                // standard input has ended, and with it any need to look
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

    /// Two stacks on loopback: this crate's own agent answers, and a second
    /// endpoint places a call at it, says something, and hears it again.
    ///
    /// Run more than once before giving up: on a machine doing other heavy
    /// work at the same time (this workspace's own build is run four ways at
    /// once), a real UDP send can sit long enough in the kernel's queue that
    /// the jitter buffer reads the gap as a lost source and reopens RFC
    /// 3550's probation on the very packet meant to prove the round trip.
    /// Each attempt is a full, independent call on its own pair of sockets,
    /// so only a repeated failure to hear anything back fails the test.
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

    /// The same call from a caller that keeps RTCP on a port of its own, as
    /// Asterisk does unless told otherwise: the agent's answer then promises
    /// RTCP on the port after its RTP one (RFC 3550 §11), and it has to be
    /// listening there, or the caller's reports go nowhere and neither end
    /// ever measures a round trip.
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

        // G.711 rather than this crate's own default catalogue: it encodes
        // each sample on its own rather than perceptually, so a steady tone
        // survives the round trip recognisably, which is all this test reads.
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
        let mut agent = Agent {
            endpoint: agent_endpoint,
            account: agent_account,
            registration: None,
            route: None,
            call: None,
            echoes: Echoes::new(),
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

        // What the caller says once the call is up, and what it heard back —
        // filled and read by the run_media closures below, once the call
        // moves past `CallConfirmed`. The tone starts only once a few silent
        // frames have gone first: RFC 3550 appendix A.1's own source
        // validation drops the very first packet or two of a new SSRC on
        // probation (`MIN_SEQUENTIAL`), and a tone sent only in that first
        // packet would prove nothing but the drop.
        let mut frames_sent = 0_u32;
        let mut heard: Vec<i16> = Vec::new();
        let mut up = false;
        const TONE: i16 = 8_000;
        const WARM_UP_FRAMES: u32 = 5;

        // Runs until the tone has plainly come back, or the deadline says it
        // never will — not until `heard` reaches some fixed length, since the
        // early frames the agent echoes are its own opening silence and only
        // a loud one proves anything.
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline && !(up && heard.iter().any(|sample| sample.abs() > 1_000))
        {
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

        // below the default it lowers the ceiling, and the transactions keep
        // the default's room for everything that is not a call
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
        // the end of the input ends the reading thread, and is no command
        assert_eq!(
            told.recv_timeout(wait),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }

    /// The agent `run` makes from `args`, on loopback: registered at the
    /// registrar `args` names, if it names one, and following the route to it.
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

    /// Turn the caller and the agent until `done` says so, or twenty seconds
    /// pass; whether `done` did.
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

    /// A ceiling's worth of calls, ended and placed again at once, with one
    /// more in between: every one of the two ceilings' worth is let in —
    /// neither the guard against scanners, nor the server transactions the
    /// first round still holds, turn any away — and the one past the
    /// ceiling is refused 503 with a `Retry-After`. 150 is past both of the
    /// stack's defaults: 128 calls, and 256 transactions where the second
    /// round meets 300 still held from the first.
    #[test]
    fn two_full_bursts_back_to_back_meet_neither_the_guard_nor_the_ceiling() {
        const CALLS: usize = 150;
        let args = parse_args(words(&format!("--max-calls {CALLS}"))).unwrap();
        let mut agent = agent_on_loopback(&args, 0x31);
        let agent_address = agent.endpoint.local;
        let now = Instant::now();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        // where the caller says its audio goes, read by nobody: the caller
        // carries no audio, so it needs no socket a call of its own
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

    /// Answer one REGISTER waiting on `registrar` with a 200, the binding
    /// granted for five minutes or, for one with `expires` of zero, given
    /// up; the request, when there was one.
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

    /// Turn the agent, answering every REGISTER it sends and counting them
    /// in `registers`, until `done` says so or ten seconds pass; whether
    /// `done` did.
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

        // told, with the route where it was: the stack proves the
        // registration again, and the agent goes on
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

        // quit: nothing to hang up, the registration given up, and finished
        // once the registrar says so
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
            codec: "PCMU".to_owned(),
            sent: 1_000,
            quality,
            round_trip: Some(Duration::from_micros(12_340)),
            r_factor: Some(88),
            mos_x10: Some(42),
        };
        assert_eq!(
            rated.line(),
            "codec=PCMU sent=1000 received=990 lost=10 loss_pct=1.00 late=2 reordered=3 \
             jitter_ms=4.25 delay_ms=60.0 rtt_ms=12.3 r=88 mos=4.2"
        );
        let unrated = Ending {
            codec: "PCMA".to_owned(),
            sent: 0,
            quality: Quality::default(),
            round_trip: None,
            r_factor: None,
            mos_x10: None,
        };
        assert_eq!(
            unrated.line(),
            "codec=PCMA sent=0 received=0 lost=0 loss_pct=0.00 late=0 reordered=0 \
             jitter_ms=0.00 delay_ms=0.0 rtt_ms=- r=- mos=-"
        );
    }
}
