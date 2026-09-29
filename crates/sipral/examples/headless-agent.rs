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
//!     [--codecs PCMU,PCMA] [--invite-burst 200]
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
//! calls it a hundred times at once, is the switchboard that guard names. A
//! request the stack will not put in a UDP datagram (RFC 3261
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
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use sipral::{
    Account, AccountId, CallHandle, CodecCatalog, Credentials, EndpointConfig, Event, Link,
    MediaConfig, MediaEngine, MediaEvent, Network, OutgoingCall, Quality, Rate, Recovery,
    StreamStatistics, UaEvent, Uri, UserAgent,
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
    })
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
}

impl Agent {
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
        let (Some(route), Some(registration)) = (self.route.as_mut(), self.registration.as_ref())
        else {
            return;
        };
        let Some((from, to)) = route.moved(now, udp_endpoint::route_to) else {
            return;
        };
        let local = match self.endpoint.rebind_sip(to, now) {
            Ok(local) => local,
            Err(error) => {
                eprintln!("cannot bind at {to}: {error}");
                return;
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
        println!("moved from {from} to {to}: {recovery}");
    }
}

/// Answer whatever just arrived, and let every call's session move one frame:
/// what it said comes back out, and what it says now is kept for the next
/// turn.
fn tick(agent: &mut Agent, now: Instant) -> bool {
    agent.follow(now);
    for event in agent.endpoint.pump(now) {
        match event {
            Event::Signalling(UaEvent::Registered { .. }) => {
                println!("registered");
                agent.place(now);
            }
            Event::Signalling(UaEvent::RegistrationFailed { reason, status, .. }) => {
                println!("registration failed: {reason} ({status:?})");
            }
            Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
                if let Ok(local) = agent.endpoint.open_media(call, now) {
                    match agent
                        .endpoint
                        .engine
                        .answer(&mut agent.endpoint.agent, call, local, now)
                    {
                        Ok(()) => println!("answered {call:?}"),
                        Err(error) => eprintln!("cannot answer {call:?}: {error}"),
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
                agent.endpoint.readdress(call, now);
            }
            Event::Media {
                call,
                event: MediaEvent::Ended(stats),
            } => println!("ended {call:?} {}", Ending::of(&stats).line()),
            Event::Signalling(UaEvent::CallEnded { call, .. }) => {
                agent.echoes.remove(&call);
                // Without this, every call this agent has ever answered
                // keeps its bound RTP socket alive in `endpoint.media` for
                // the rest of the process's life — harmless for the examples
                // that place one call and exit, real for the one that keeps
                // answering (`Endpoint::close_media`'s own doc).
                agent.endpoint.close_media(call);
            }
            _ => {}
        }
    }
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
    agent.endpoint.timers(now);
    agent.endpoint.read_sip(now)
}

fn main() -> ExitCode {
    let args = match parse_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: headless-agent [--host IP] [--port N] [--register USER@DOMAIN \
                 --registrar IP:PORT --pass SECRET] [--call SIP-URI] [--ice] \
                 [--codecs NAME,NAME] [--invite-burst N]"
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
    let mut agent = UserAgent::new(EndpointConfig::default(), entropy::seed()?)?;
    if let Some(rate) = args.invite_rate {
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
    };
    loop {
        if !tick(&mut agent, Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use sipral::{Account, OutgoingCall, Uri};

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
