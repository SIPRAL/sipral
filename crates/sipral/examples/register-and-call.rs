// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A softphone's shape: register an account, place a call, hold and resume it, and blind-transfer
//! it, all of which `call.rs` skips.
//!
//! A registrar needs a real account, so pass one:
//!
//! ```text
//! cargo run --example register-and-call -- \
//!     --user alice --pass secret --domain sip.example.com \
//!     --target sip:bob@sip.example.com
//! ```
//!
//! `--hold` holds the call for two seconds and resumes it; `--transfer sip:carol@sip.example.com`
//! blind-transfers it (RFC 3515) instead of hanging up. With neither, the call stays up a couple of
//! seconds and is hung up. The account unregisters before exit, as a softphone does, rather than
//! leaving the binding to time out.

// `udp_endpoint` needs `media_socket` at `crate::media_socket`, as in `call.rs`, though this file
// never names it
#[path = "common/entropy.rs"]
mod entropy;
#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/srv.rs"]
mod srv;
#[path = "common/udp_endpoint.rs"]
mod udp_endpoint;
#[path = "common/wall_clock.rs"]
mod wall_clock;

use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CodecCatalog, Credentials, EndpointConfig, Event, MediaConfig,
    MediaEngine, OutgoingCall, UaEvent, Uri, UserAgent,
};

use udp_endpoint::Endpoint;

/// Time spent in each step (up, held, transferring), long enough to watch it happen on the far
/// phone.
const PAUSE: Duration = Duration::from_secs(2);

/// Overall time limit before exiting non-zero, so an unresponsive registrar or target cannot hang
/// the example.
const CEILING: Duration = Duration::from_secs(30);

/// What the command line asked for.
struct Args {
    user: String,
    pass: String,
    domain: String,
    /// `host:port` for the registrar, when it is not `domain:5060`.
    server: Option<String>,
    target: String,
    hold: bool,
    transfer: Option<String>,
}

/// The run's steps, in order. `Holding` and `Resuming` are skipped without [`Args::hold`],
/// `Transferring` without [`Args::transfer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Registering,
    Calling,
    Talking,
    Holding,
    Resuming,
    Transferring,
    Ending,
    Unregistering,
    Done,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: register-and-call --user U --pass P --domain D --target sip:... \
                 [--server host:port] [--hold] [--transfer sip:...]"
            );
            return ExitCode::FAILURE;
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args() -> Result<Args, String> {
    let mut user = None;
    let mut pass = None;
    let mut domain = None;
    let mut server = None;
    let mut target = None;
    let mut hold = false;
    let mut transfer = None;

    let mut raw = env::args().skip(1);
    while let Some(flag) = raw.next() {
        match flag.as_str() {
            "--user" => user = Some(next_value(&mut raw, "--user")?),
            "--pass" => pass = Some(next_value(&mut raw, "--pass")?),
            "--domain" => domain = Some(next_value(&mut raw, "--domain")?),
            "--server" => server = Some(next_value(&mut raw, "--server")?),
            "--target" => target = Some(next_value(&mut raw, "--target")?),
            "--transfer" => transfer = Some(next_value(&mut raw, "--transfer")?),
            "--hold" => hold = true,
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    Ok(Args {
        user: user.ok_or("--user is required")?,
        pass: pass.ok_or("--pass is required")?,
        domain: domain.ok_or("--domain is required")?,
        server,
        target: target.ok_or("--target is required")?,
        hold,
        transfer,
    })
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let server = args.server.as_deref().unwrap_or(&args.domain);
    let remote = resolve(server)?;
    let now = Instant::now();
    let agent = UserAgent::new(EndpointConfig::default(), entropy::seed()?)?;
    let engine = MediaEngine::new(
        CodecCatalog::new(),
        MediaConfig::default(),
        wall_clock::at(now),
        entropy::seed()?,
    );
    let mut endpoint = Endpoint::bind(
        SocketAddr::new(udp_endpoint::route_to(remote), 0),
        agent,
        engine,
        now,
    )?;

    let aor = Uri::parse_str(&format!("sip:{}@{}", args.user, args.domain))?;
    let registrar = Uri::parse_str(&format!("sip:{}", args.domain))?;
    let contact = Uri::parse_str(&format!("sip:{}@{}", args.user, endpoint.local))?;
    let account = endpoint.add_account(
        Account::new(aor, registrar, contact, endpoint.transport, remote)
            .credentials(Credentials::new(&args.user, &args.pass)),
    );

    println!("registering {} at {server} ...", args.user);
    endpoint.agent.register(account, now)?;

    let mut step = Step::Registering;
    let mut call: Option<CallHandle> = None;
    let mut step_at: Option<Instant> = None;
    let deadline = now + CEILING;

    while step != Step::Done && Instant::now() < deadline {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            let Event::Signalling(event) = event else {
                continue;
            };
            match event {
                UaEvent::Registered { .. } if step == Step::Registering => {
                    println!("registered");
                    let outgoing = OutgoingCall::new(Uri::parse_str(&args.target)?);
                    let placed = udp_endpoint::place(&mut endpoint, account, outgoing, now)?;
                    println!("calling {} ...", args.target);
                    call = Some(placed);
                    step = Step::Calling;
                }
                UaEvent::RegistrationFailed { reason, status, .. } => {
                    return Err(format!("registration failed: {reason} ({status:?})").into());
                }
                UaEvent::CallConfirmed { call: this, .. } if Some(this) == call => {
                    println!("connected");
                    step = Step::Talking;
                    step_at = Some(now + PAUSE);
                }
                UaEvent::SessionChanged { hold, .. } if step == Step::Holding => {
                    println!("{hold}");
                }
                UaEvent::SessionChanged { hold, .. } if step == Step::Resuming => {
                    println!("{hold}");
                }
                UaEvent::TransferProgress { status, .. } => {
                    println!("transfer progress: {status}");
                }
                UaEvent::TransferDone { status, .. } => {
                    println!("transfer done: {status}");
                }
                UaEvent::CallEnded { reason, .. } => {
                    println!("call ended: {reason}");
                    step = Step::Unregistering;
                    step_at = None;
                    endpoint.agent.unregister(account, now)?;
                }
                UaEvent::Unregistered { .. } if step == Step::Unregistering => {
                    println!("unregistered");
                    step = Step::Done;
                }
                _ => {}
            }
        }

        // media must still be pumped: silence out, replies discarded. A real softphone passes a
        // microphone and speaker; see `call.rs`
        endpoint.run_media(now, |_call, media, session, now| {
            media.turn(session, now, |room| room.fill(0), |_room| {});
        });

        if let Some(due) = step_at
            && now >= due
            && let Some(call) = call
        {
            step = advance(&mut endpoint, args, call, step, now)?;
            // only `Holding` and `Resuming` wait on a timer; other steps advance on events
            step_at = matches!(step, Step::Holding | Step::Resuming).then(|| now + PAUSE);
        }

        endpoint.timers(now);
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    if step != Step::Done {
        return Err("timed out before the flow finished".into());
    }
    Ok(())
}

/// What happens once a step's own pause is over, and which step follows it.
fn advance(
    endpoint: &mut Endpoint,
    args: &Args,
    call: CallHandle,
    step: Step,
    now: Instant,
) -> Result<Step, Box<dyn std::error::Error>> {
    match step {
        Step::Talking if args.hold => {
            endpoint.agent.hold(call, now)?;
            Ok(Step::Holding)
        }
        Step::Holding => {
            endpoint.agent.resume(call, now)?;
            Ok(Step::Resuming)
        }
        Step::Talking | Step::Resuming => {
            if let Some(target) = &args.transfer {
                endpoint
                    .agent
                    .transfer(call, &Uri::parse_str(target)?, now)?;
                Ok(Step::Transferring)
            } else {
                endpoint.agent.hangup(call, now)?;
                Ok(Step::Ending)
            }
        }
        other => Ok(other),
    }
}

/// A server with a port is used as is; a bare domain is looked up per RFC 3263 §4.2, `_sip._udp`
/// record first.
fn resolve(server: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    if server.contains(':') {
        return server
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| format!("cannot resolve {server}").into());
    }
    Ok(srv::resolve(server, "_sip._udp", 5060)?)
}
