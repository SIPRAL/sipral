// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A softphone's own shape: register with a real account, place a call, put
//! it on hold and take it off again, and hand it to somebody else with a
//! blind transfer — everything `call.rs` skips by dialling an address that
//! needs none of it.
//!
//! Nothing here is runnable with no configuration, because a registrar wants
//! a real account: name one on the command line.
//!
//! ```text
//! cargo run --example register-and-call -- \
//!     --user alice --pass secret --domain sip.example.com \
//!     --target sip:bob@sip.example.com
//! ```
//!
//! `--hold` puts the call on hold for two seconds and takes it off again
//! before it ends; `--transfer sip:carol@sip.example.com` hands it to a third
//! party with a blind transfer (RFC 3515) instead of hanging it up. With
//! neither, the call stays up for a couple of seconds and is hung up from
//! here. The account unregisters before the process exits, the same way a
//! softphone gives its binding back when it quits rather than leaving the
//! registrar to time it out.

// `udp_endpoint` needs `media_socket` at `crate::media_socket`, the same way
// `call.rs` provides it, even though this file never names it itself.
#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/udp_endpoint.rs"]
mod udp_endpoint;

use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CodecCatalog, Credentials, EndpointConfig, Event, MediaConfig,
    MediaEngine, OutgoingCall, UaEvent, Uri, UserAgent, WallClock,
};

use udp_endpoint::Endpoint;

/// How long a call sits in each step — up, held, transferring — before the
/// next one starts. Long enough that a person watching the far end's phone
/// sees each change happen.
const PAUSE: Duration = Duration::from_secs(2);

/// How long the whole run may take before this gives up and exits non-zero,
/// so a registrar or a target that never answers does not hang the example
/// forever.
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

/// Where this run is, in the order it moves through them. `Holding` and
/// `Resuming` are skipped entirely when [`Args::hold`] is not asked for, and
/// `Transferring` is skipped when [`Args::transfer`] names nobody.
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
    let agent = UserAgent::new(EndpointConfig::default(), [0x4a; 32])?;
    let engine = MediaEngine::new(
        CodecCatalog::new(),
        MediaConfig::default(),
        WallClock::from_unix(now, 0, 0),
        [0x4b; 32],
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

        // Every call still needs its media pumped, even one this example
        // never plays or records: silence out, and whatever comes back is
        // simply discarded. A real softphone hands the closures below a
        // microphone and a speaker instead — see `call.rs` for exactly that.
        endpoint.run_media(now, |_call, media, session, now| {
            media.turn(session, now, |room| room.fill(0), |_room| {});
        });

        if let Some(due) = step_at
            && now >= due
            && let Some(call) = call
        {
            step = advance(&mut endpoint, args, call, step, now)?;
            // `Holding` and `Resuming` each need the same pause before the
            // next thing happens to them; every other step is driven by an
            // event instead, so nothing schedules a further wake-up for it.
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

fn resolve(server: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let with_port = if server.contains(':') {
        server.to_owned()
    } else {
        format!("{server}:5060")
    };
    with_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("cannot resolve {server}").into())
}
