// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A bridge from a PBX to a voice agent that answers SIP itself — a hosted
//! realtime model, an agent platform's SIP trunk — with no vendor protocol
//! anywhere in it: the agent is a SIP address, and this is a phone line that
//! forwards its calls there.
//!
//! It registers on the PBX as an extension (or, with no `--register`, takes
//! what a trunk sends it), answers nothing at first, and calls the agent
//! with the caller's number, display name and the PBX INVITE's `X-` fields.
//! The caller hears the PBX ring until the agent answers; then it is
//! answered and the two calls are joined in a local conference without this
//! end, each on its own codec and rate. A digit either side sends is sent on
//! to the other, and either side hanging up ends the other — the PBX's end
//! carrying the call's outcome. A REFER from the agent goes to one function,
//! `agent_bridge::decide`: a person to transfer to, or an outcome to end on.
//! `common/agent_bridge.rs` is all of that; this file is the sockets and the
//! command line.
//!
//! ```text
//! cargo run --example agent-bridge -- --pbx 192.0.2.10:5060 \
//!     --register bridge@pbx.example --pass secret \
//!     --agent 'sip:agent@203.0.113.7:5060' [--agent-address host:port] \
//!     [--host ip] [--port n] [--transfer refer|bridge] \
//!     [--outcomes header|refer] [--outcome-uri callback=sip:800@pbx.example] \
//!     [--max-agent-seconds n] [--copy-headers 'X-*,User-to-User'] \
//!     [--invite-burst n]
//! ```
//!
//! `--transfer refer` (the default) answers a transfer by REFERring the
//! caller's call to the PBX, which places the new call and owns it;
//! `--transfer bridge` places it from here and bridges it in the agent's
//! place. `--outcomes header` (the default) ends the caller's call with a
//! BYE carrying `X-Sipral-Outcome: human|callback|resolved|unresolved|expired`;
//! `--outcomes refer` REFERs it to the `--outcome-uri` given for that
//! outcome instead, for a PBX that reads no field off a BYE.
//! `--max-agent-seconds` hangs the agent up after that long, as `expired`.
//! `--copy-headers` names the INVITE fields passed on, `*` ending a prefix;
//! an empty list passes only the caller's number and name.
//! `--invite-burst` lets that many calls arrive from the PBX at once, where
//! the stack's own guard against scanners lets ten.
//!
//! An agent address that asks for TLS — `sips:`, or `;transport=tls` — is
//! called over a TLS connection of its own, which this example opens with
//! `rustls` when built with `--features example-tls`, and trusts by the
//! platform's roots or, with `--pin <sha-256>`, by one certificate's
//! fingerprint. Without the feature such an address is refused at start.
//! `--agent-address` names where to connect when the address's host is not
//! where its SIP server is; otherwise a name is looked up by its SRV record
//! (`_sips._tcp` or `_sip._udp`) and then as a host.
//!
//! `--host` is the address advertised to both the PBX and the agent, the
//! route toward the PBX when left out: an agent on the Internet has to be
//! able to send audio back to it.

#[path = "common/agent_bridge.rs"]
mod agent_bridge;
#[path = "common/entropy.rs"]
mod entropy;
#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/srv.rs"]
mod srv;
#[cfg(feature = "example-tls")]
#[path = "common/tls_transport.rs"]
mod tls_transport;
#[path = "common/udp_endpoint.rs"]
mod udp_endpoint;
#[path = "common/wall_clock.rs"]
mod wall_clock;

use std::env;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use sipral::{
    Account, CodecCatalog, Credentials, EndpointConfig, Event, MediaConfig, MediaEngine, Rate,
    TransportId, UaEvent, Uri, UserAgent,
};
use sipral_core::msg::{HostRef, UriScheme};

use agent_bridge::{Bridge, Outcome, OutcomeMode, Policy, Routes, TransferMode};
use udp_endpoint::Endpoint;

/// The longest the loop waits for SIP before it looks at everything else.
const LOOK: Duration = Duration::from_millis(5);

/// The transport number the TLS connection to the agent is bound at; the
/// UDP socket is the endpoint's own, 1.
const AGENT_STREAM: TransportId = TransportId(2);

/// Once `--invite-burst` is spent, one more INVITE from one source every
/// this often: the stack's own interval.
const INVITE_REFILL: Duration = Duration::from_secs(2);

/// What the command line asked for.
struct Args {
    pbx: String,
    register: Option<(String, String)>,
    pass: Option<String>,
    agent: String,
    agent_address: Option<String>,
    host: Option<IpAddr>,
    port: Option<u16>,
    pin: Option<String>,
    invite_burst: Option<u32>,
    policy: Policy,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: agent-bridge --pbx host:port --agent sip:... \
                 [--register user@domain --pass secret] [--agent-address host:port] \
                 [--host ip] [--port n] [--pin sha-256] [--transfer refer|bridge] \
                 [--outcomes header|refer] [--outcome-uri name=uri]... \
                 [--max-agent-seconds n] [--copy-headers list] [--invite-burst n]"
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

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        pbx: String::new(),
        register: None,
        pass: None,
        agent: String::new(),
        agent_address: None,
        host: None,
        port: None,
        pin: None,
        invite_burst: None,
        policy: Policy::default(),
    };
    let mut raw = env::args().skip(1);
    while let Some(flag) = raw.next() {
        match flag.as_str() {
            "--pbx" => args.pbx = next_value(&mut raw, "--pbx")?,
            "--register" => {
                let value = next_value(&mut raw, "--register")?;
                let (user, domain) = value
                    .split_once('@')
                    .ok_or("--register takes user@domain")?;
                args.register = Some((user.to_owned(), domain.to_owned()));
            }
            "--pass" => args.pass = Some(next_value(&mut raw, "--pass")?),
            "--agent" => args.agent = next_value(&mut raw, "--agent")?,
            "--agent-address" => {
                args.agent_address = Some(next_value(&mut raw, "--agent-address")?);
            }
            "--host" => {
                let value = next_value(&mut raw, "--host")?;
                args.host = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--host {value}: not an address"))?,
                );
            }
            "--port" => {
                let value = next_value(&mut raw, "--port")?;
                args.port = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--port {value}: not a port"))?,
                );
            }
            "--pin" => args.pin = Some(next_value(&mut raw, "--pin")?),
            "--invite-burst" => {
                let value = next_value(&mut raw, "--invite-burst")?;
                args.invite_burst = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--invite-burst {value}: not a count"))?,
                );
            }
            other => {
                if !policy_flag(other, &mut raw, &mut args.policy)? {
                    return Err(format!("unrecognised argument: {other}"));
                }
            }
        }
    }
    if args.pbx.is_empty() {
        return Err("--pbx is required".to_owned());
    }
    if args.agent.is_empty() {
        return Err("--agent is required".to_owned());
    }
    if args.register.is_some() && args.pass.is_none() {
        return Err("--register needs --pass".to_owned());
    }
    Ok(args)
}

/// One of the flags that say what the bridge does on the application's
/// behalf; `false` for a flag that is not one of them.
fn policy_flag(
    flag: &str,
    raw: &mut impl Iterator<Item = String>,
    policy: &mut Policy,
) -> Result<bool, String> {
    match flag {
        "--transfer" => {
            policy.transfer = match next_value(raw, flag)?.as_str() {
                "refer" => TransferMode::Refer,
                "bridge" => TransferMode::Bridge,
                other => return Err(format!("--transfer {other}: refer or bridge")),
            };
        }
        "--outcomes" => {
            policy.outcomes = match next_value(raw, flag)?.as_str() {
                "header" => OutcomeMode::Header,
                "refer" => OutcomeMode::Refer,
                other => return Err(format!("--outcomes {other}: header or refer")),
            };
        }
        "--outcome-uri" => {
            let value = next_value(raw, flag)?;
            let (name, uri) = value
                .split_once('=')
                .ok_or("--outcome-uri takes name=uri")?;
            let outcome =
                Outcome::named(name).ok_or_else(|| format!("--outcome-uri: no outcome {name}"))?;
            let uri =
                Uri::parse_str(uri).map_err(|error| format!("--outcome-uri {uri}: {error}"))?;
            policy.outcome_uris.push((outcome, uri));
        }
        "--max-agent-seconds" => {
            let value = next_value(raw, flag)?;
            let seconds: u64 = value
                .parse()
                .map_err(|_| format!("--max-agent-seconds {value}: not a number"))?;
            policy.max_agent = Some(Duration::from_secs(seconds));
        }
        "--copy-headers" => {
            policy.copy_headers = next_value(raw, flag)?
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect();
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

/// Where the agent is, and whether its address asks for TLS.
struct AgentTarget {
    uri: Uri,
    address: SocketAddr,
    tls: bool,
    /// The name its certificate is checked against.
    #[cfg_attr(not(feature = "example-tls"), allow(dead_code))]
    host: String,
}

fn agent_target(args: &Args) -> Result<AgentTarget, Box<dyn std::error::Error>> {
    let uri = Uri::parse_str(&args.agent)?;
    let sip = uri.sip().ok_or("--agent is not a sip: or sips: address")?;
    let transport = sip
        .param("transport")
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let tls = sip.scheme == UriScheme::Sips || transport == "tls";
    if !tls && !transport.is_empty() && transport != "udp" {
        return Err(format!("--agent: transport={transport} is not one this example opens").into());
    }
    let host = match sip.host {
        HostRef::Name(name) => name.to_owned(),
        HostRef::Ipv4(ip) => ip.to_string(),
        HostRef::Ipv6(ip) => ip.to_string(),
    };
    let address = if let Some(given) = &args.agent_address {
        given
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| format!("cannot resolve {given}"))?
    } else if let (HostRef::Name(name), None) = (sip.host, sip.port) {
        if tls {
            srv::resolve(name, "_sips._tcp", 5061)?
        } else {
            srv::resolve(name, "_sip._udp", 5060)?
        }
    } else {
        let port = sip.port.unwrap_or(if tls { 5061 } else { 5060 });
        (host.as_str(), port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| format!("cannot resolve {host}"))?
    };
    Ok(AgentTarget {
        uri: uri.clone(),
        address,
        tls,
        host,
    })
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let pbx = args
        .pbx
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("cannot resolve {}", args.pbx))?;
    let target = agent_target(&args)?;
    let now = Instant::now();
    let mut agent = UserAgent::new(EndpointConfig::default(), entropy::seed()?)?;
    if let Some(burst) = args.invite_burst {
        agent.limit_invites(Rate::new(burst, INVITE_REFILL)?);
    }
    let engine = MediaEngine::new(
        CodecCatalog::new(),
        MediaConfig::default(),
        wall_clock::at(now),
        entropy::seed()?,
    );
    let host = args.host.unwrap_or_else(|| udp_endpoint::route_to(pbx));
    let port = args
        .port
        .unwrap_or(if args.register.is_some() { 0 } else { 5060 });
    let mut endpoint = Endpoint::bind(SocketAddr::new(host, port), agent, engine, now)?;
    endpoint.read_in_background()?;

    let (user, domain) = args
        .register
        .clone()
        .unwrap_or_else(|| ("bridge".to_owned(), pbx.ip().to_string()));
    let aor = Uri::parse_str(&format!("sip:{user}@{domain}"))?;
    let contact = Uri::parse_str(&format!("sip:{user}@{}", endpoint.local))?;
    let line = if let Some(pass) = &args.pass {
        let registrar = Uri::parse_str(&format!("sip:{domain}"))?;
        let line = endpoint.add_account(
            Account::new(
                aor.clone(),
                registrar,
                contact.clone(),
                endpoint.transport,
                pbx,
            )
            .credentials(Credentials::new(&user, pass)),
        );
        println!("registering {user} at {pbx} ...");
        endpoint.agent.register(line, now)?;
        line
    } else {
        endpoint.add_account(Account::unregistered(
            aor.clone(),
            contact.clone(),
            endpoint.transport,
            pbx,
        ))
    };

    let agent_link = AgentLink::open(&args, &target, &mut endpoint, now)?;
    let (agent_contact, agent_route) = match agent_link.local() {
        Some(local) => (
            Uri::parse_str(&format!("sip:{user}@{local};transport=tls"))?,
            (AGENT_STREAM, target.address),
        ),
        None => (contact, (endpoint.transport, target.address)),
    };
    let agent_account = endpoint.add_account(Account::unregistered(
        aor,
        agent_contact,
        agent_route.0,
        target.address,
    ));
    let policy = Policy {
        // what a REFER from the agent does: replace this function to map
        // other targets to other actions
        decide: agent_bridge::decide,
        ..args.policy
    };
    let bridge = Bridge::new(
        Routes {
            line,
            line_domain: domain,
            agent_account,
            agent: target.uri.clone(),
            agent_route,
        },
        policy,
    );
    println!(
        "listening on {}; calls go to {} at {}{}",
        endpoint.local,
        target.uri,
        target.address,
        if target.tls { " over TLS" } else { "" }
    );
    serve(endpoint, bridge, agent_link)
}

/// The loop, for as long as the process runs.
fn serve(
    mut endpoint: Endpoint,
    mut bridge: Bridge,
    mut agent_link: AgentLink,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            report(&event);
            bridge.on_event(&mut endpoint, &event, now);
        }
        agent_link.carry(&mut endpoint, now);
        bridge.run_media(&mut endpoint, now);
        endpoint.timers(now);
        let look = Instant::now() + LOOK;
        let until = bridge.next_tick().map_or(look, |tick| tick.min(look));
        endpoint.wait_sip(Some(until));
        endpoint.read_sip(Instant::now());
    }
}

/// What the line's registration does, said on standard output.
fn report(event: &Event) {
    match event {
        Event::Signalling(UaEvent::Registered { .. }) => println!("registered"),
        Event::Signalling(UaEvent::RegistrationFailed { reason, status, .. }) => {
            println!("registration failed: {reason} ({status:?})");
        }
        _ => {}
    }
}

/// The TLS connection to the agent, when its address asks for one.
#[cfg(feature = "example-tls")]
struct AgentLink {
    open: Option<tls_transport::TlsTransport>,
    remote: SocketAddr,
    name: String,
    pin: Option<sipral::CertificatePin>,
}

#[cfg(feature = "example-tls")]
impl AgentLink {
    fn open(
        args: &Args,
        target: &AgentTarget,
        endpoint: &mut Endpoint,
        now: Instant,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut link = Self {
            open: None,
            remote: target.address,
            name: target.host.clone(),
            pin: args
                .pin
                .as_deref()
                .map(sipral::CertificatePin::parse)
                .transpose()?,
        };
        if target.tls {
            link.connect(endpoint, now)?;
        }
        Ok(link)
    }

    fn connect(
        &mut self,
        endpoint: &mut Endpoint,
        now: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use tls_transport::{TlsTransport, Trust};
        let trust = self.pin.map_or_else(
            || Trust::Roots(TlsTransport::platform_roots()),
            Trust::Pinned,
        );
        let open = TlsTransport::connect(self.remote, &self.name, trust)?;
        let local = open.tcp.local_addr()?;
        endpoint.agent.receive(
            sipral::Input::TransportBound {
                transport: AGENT_STREAM,
                protocol: sipral::TransportProtocol::Tls,
                local,
                remote: Some(self.remote),
            },
            now,
        )?;
        self.open = Some(open);
        Ok(())
    }

    fn local(&self) -> Option<SocketAddr> {
        self.open
            .as_ref()
            .and_then(|open| open.tcp.local_addr().ok())
    }

    /// Send what the agent wrote for the connection, and hand it what
    /// arrived. A connection the agent's server closed is told to the stack
    /// and opened again.
    fn carry(&mut self, endpoint: &mut Endpoint, now: Instant) {
        let Some(open) = self.open.as_mut() else {
            endpoint.elsewhere.clear();
            return;
        };
        while let Some(transmit) = endpoint.elsewhere.pop_front() {
            if transmit.transport == AGENT_STREAM
                && let Err(error) = open.send(&transmit.payload)
            {
                eprintln!("cannot write to the agent: {error}");
            }
        }
        let agent = &mut endpoint.agent;
        let polled = open.poll(|data| {
            let _ = agent.receive(
                sipral::Input::StreamData {
                    transport: AGENT_STREAM,
                    data,
                },
                now,
            );
        });
        let lost = match polled {
            Ok(outcome) => outcome.closed,
            Err(error) => {
                eprintln!("the connection to the agent failed: {error}");
                true
            }
        };
        if lost {
            let _ = endpoint.agent.receive(
                sipral::Input::StreamClosed {
                    transport: AGENT_STREAM,
                },
                now,
            );
            self.open = None;
            if let Err(error) = self.connect(endpoint, now) {
                eprintln!("cannot connect to the agent again: {error}");
            }
        }
    }
}

/// Without `example-tls` there is no TLS to open: an agent address that
/// asks for it is refused before anything starts.
#[cfg(not(feature = "example-tls"))]
struct AgentLink;

// the same calls as the TLS link's, which do need `self`
#[cfg(not(feature = "example-tls"))]
#[allow(clippy::unused_self)]
impl AgentLink {
    fn open(
        _args: &Args,
        target: &AgentTarget,
        _endpoint: &mut Endpoint,
        _now: Instant,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if target.tls {
            return Err("the agent's address asks for TLS: run with --features example-tls".into());
        }
        Ok(Self)
    }

    const fn local(&self) -> Option<SocketAddr> {
        None
    }

    fn carry(&mut self, endpoint: &mut Endpoint, _now: Instant) {
        endpoint.elsewhere.clear();
    }
}
