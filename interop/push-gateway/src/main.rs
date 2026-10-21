// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A push gateway for the lab: the proxy half of RFC 8599, placed in front of
//! a PBX that has none, so that a call to a device that is asleep wakes it.
//!
//! The device side of RFC 8599 is the stack's (docs/15-mobile.md, "RFC 8599
//! push parameters" and "C2"); this is the other side, built to prove the two
//! meet. It is a test tool: one PBX, UDP, state in memory, and pushes sent
//! one at a time. `proxy.rs` says what it does on the wire and why.
//!
//! ```text
//! sipral-push-gateway run --pbx HOST:PORT [--listen ADDR] [--advertise ADDR]
//!     [--fake-pns HOST:PORT]
//!     [--apns-key FILE --apns-key-id ID --apns-team TEAM [--apns-production]]
//!     [--fcm-service-account FILE]
//!     [--invite-bucket-ms N] [--other-bucket-ms N] [--min-expires S]
//!     [--only-push-proxy]
//! sipral-push-gateway fake-pns [--listen ADDR]
//! sipral-push-gateway probe apns [--apns-key FILE --apns-key-id ID
//!     --apns-team TEAM] [--apns-production] [--topic BUNDLE.voip]
//!     [--device-token HEX]
//! sipral-push-gateway probe fcm [--fcm-service-account FILE]
//!     [--device-token TOKEN]
//! ```
//!
//! `--fake-pns` sends every push to the lab's own notification service
//! (`fake.rs`) instead of Apple or Google. The key and the service account are
//! read from files named on the command line or in `SIPRAL_APNS_KEY_FILE`,
//! `SIPRAL_APNS_KEY_ID`, `SIPRAL_APNS_TEAM` and `SIPRAL_FCM_SERVICE_ACCOUNT`,
//! never from the repository, and nothing of them is printed.
//!
//! `probe` sends one push the way `run` would and prints what the service
//! answered: with no key, signed by one made up on the spot, which shows the
//! request reaches Apple or Google and is read by them; with a real key and
//! a device token that does not exist, which shows the key is accepted
//! before any phone is in the room.

// tests say what they mean; the no-panic discipline is for what ships
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::unreadable_literal
    )
)]

mod apns;
mod fake;
mod fcm;
mod h2;
mod hpack;
mod json;
mod jwt;
mod proxy;
mod push;
mod sip;

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom as _, SystemRandom};

use crate::proxy::{Action, Config, Gateway, ParamRule, Service};
use crate::push::{PushKind, PushOutcome, PushRequest};

/// The command line, as flags and their values.
struct Args {
    words: Vec<String>,
}

impl Args {
    /// A flag's value, or the environment's when the flag is not given.
    fn value(&self, flag: &str, env: Option<&str>) -> Option<String> {
        self.words
            .iter()
            .position(|word| word == flag)
            .and_then(|at| self.words.get(at + 1).cloned())
            .or_else(|| env.and_then(|name| std::env::var(name).ok()))
            .filter(|value| !value.is_empty())
    }

    fn has(&self, flag: &str) -> bool {
        self.words.iter().any(|word| word == flag)
    }

    fn number(&self, flag: &str, default: u64) -> Result<u64, String> {
        self.value(flag, None).map_or(Ok(default), |value| {
            value.parse().map_err(|_| format!("{flag} takes a number"))
        })
    }
}

fn address(text: &str) -> Result<SocketAddr, String> {
    text.to_socket_addrs()
        .map_err(|error| format!("{text}: {error}"))?
        .next()
        .ok_or_else(|| format!("{text} has no address"))
}

/// The local address the route to `peer` leaves from.
fn route_to(peer: SocketAddr) -> Result<std::net::IpAddr, String> {
    let socket = UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|error| format!("a socket: {error}"))?;
    socket
        .connect(peer)
        .map_err(|error| format!("no route to {peer}: {error}"))?;
    socket
        .local_addr()
        .map(|local| local.ip())
        .map_err(|error| format!("{error}"))
}

/// Whatever sends pushes, chosen once at start.
struct Senders {
    fake: Option<SocketAddr>,
    apns: Option<apns::Apns>,
    fcm: Option<fcm::Fcm>,
    tls: Option<h2::Tls>,
}

impl Senders {
    fn send(&mut self, push: &PushRequest) -> PushOutcome {
        if let Some(service) = self.fake {
            return fake::send(service, push);
        }
        let Some(tls) = &self.tls else {
            return PushOutcome::Failed("no TLS".to_owned());
        };
        match (push.provider.as_str(), &mut self.apns, &mut self.fcm) {
            ("apns", Some(apns), _) => apns.send(tls, push),
            ("fcm", _, Some(fcm)) => fcm.send(tls, push),
            (other, _, _) => PushOutcome::Failed(format!("no sender for {other}")),
        }
    }
}

fn apns_from(args: &Args) -> Result<Option<(apns::Apns, String)>, String> {
    let Some(key) = args.value("--apns-key", Some("SIPRAL_APNS_KEY_FILE")) else {
        return Ok(None);
    };
    let key_id = args
        .value("--apns-key-id", Some("SIPRAL_APNS_KEY_ID"))
        .ok_or("--apns-key needs --apns-key-id")?;
    let team = args
        .value("--apns-team", Some("SIPRAL_APNS_TEAM"))
        .ok_or("--apns-key needs --apns-team")?;
    let signer = jwt::Signer::es256_file(&PathBuf::from(key))?;
    let sender = apns::Apns::new(signer, &key_id, &team, !args.has("--apns-production"));
    Ok(Some((sender, team)))
}

fn fcm_from(args: &Args, ttl: Duration) -> Result<Option<(fcm::Fcm, String)>, String> {
    let Some(file) = args.value("--fcm-service-account", Some("SIPRAL_FCM_SERVICE_ACCOUNT")) else {
        return Ok(None);
    };
    let account = fcm::ServiceAccount::from_file(&PathBuf::from(file))?;
    let project = account.project_id.clone();
    Ok(Some((fcm::Fcm::new(account, ttl), project)))
}

// the setup read top to bottom, then the loop it sets up
#[allow(clippy::too_many_lines)]
fn run(args: &Args) -> Result<(), String> {
    let pbx = address(
        &args
            .value("--pbx", None)
            .ok_or("run needs --pbx HOST:PORT")?,
    )?;
    let listen = address(
        &args
            .value("--listen", None)
            .unwrap_or_else(|| "0.0.0.0:5060".to_owned()),
    )?;
    let own = match args.value("--advertise", None) {
        Some(text) => address(&text)?,
        None => SocketAddr::new(route_to(pbx)?, listen.port()),
    };
    let invite_bucket = Duration::from_millis(args.number("--invite-bucket-ms", 20_000)?);
    let other_bucket = Duration::from_millis(args.number("--other-bucket-ms", 10_000)?);
    let min_expires = u32::try_from(args.number("--min-expires", 180)?)
        .map_err(|_| "--min-expires is too large")?;

    let mut senders = Senders {
        fake: None,
        apns: None,
        fcm: None,
        tls: None,
    };
    let mut services = Vec::new();
    let mut said = Vec::new();
    if let Some(service) = args.value("--fake-pns", None) {
        let service = address(&service)?;
        senders.fake = Some(service);
        services.push(Service {
            provider: "apns".into(),
            param: ParamRule::Apns { team: None },
        });
        services.push(Service {
            provider: "fcm".into(),
            param: ParamRule::Fcm { project: None },
        });
        said.push(format!(
            "the lab's notification service at {service}, for apns and fcm"
        ));
    } else {
        if let Some((sender, team)) = apns_from(args)? {
            said.push(format!("APNs at {} for team {team}", sender.host()));
            senders.apns = Some(sender);
            services.push(Service {
                provider: "apns".into(),
                param: ParamRule::Apns { team: Some(team) },
            });
        }
        if let Some((sender, project)) = fcm_from(args, invite_bucket)? {
            said.push(format!("FCM for project {project}"));
            senders.fcm = Some(sender);
            services.push(Service {
                provider: "fcm".into(),
                param: ParamRule::Fcm {
                    project: Some(project),
                },
            });
        }
        if services.is_empty() {
            return Err(
                "nothing to push through: name --fake-pns, an APNs key or a service account"
                    .to_owned(),
            );
        }
        senders.tls = Some(h2::Tls::new()?);
    }

    let mut secret = [0u8; 32];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| "no random source")?;
    let mut gateway = Gateway::new(Config {
        own,
        pbx,
        services,
        invite_bucket,
        other_bucket,
        min_expires,
        only_push_proxy: args.has("--only-push-proxy"),
        secret,
    });
    let socket = UdpSocket::bind(listen).map_err(|error| format!("binding {listen}: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|error| format!("{error}"))?;
    println!(
        "  gw    in front of the PBX at {pbx}, reached at {own}, pushing through {}",
        said.join(" and ")
    );

    let (to_senders, pushes) = mpsc::channel::<PushRequest>();
    let (outcomes, from_senders) = mpsc::channel::<(u64, PushOutcome)>();
    std::thread::spawn(move || {
        for push in pushes {
            let outcome = senders.send(&push);
            if outcomes.send((push.id, outcome)).is_err() {
                break;
            }
        }
    });

    let perform = |actions: Vec<Action>| {
        for action in actions {
            match action {
                Action::Send { to, bytes } => {
                    let _ = socket.send_to(&bytes, to);
                }
                Action::Push(push) => {
                    let _ = to_senders.send(push);
                }
                Action::Note(line) => println!("  gw    {line}"),
            }
        }
    };
    let mut buffer = vec![0u8; 65_535];
    loop {
        if let Ok((length, from)) = socket.recv_from(&mut buffer) {
            let data = buffer.get(..length).unwrap_or_default();
            perform(gateway.on_datagram(from, data, Instant::now()));
        }
        while let Ok((id, outcome)) = from_senders.try_recv() {
            perform(gateway.on_push(id, &outcome, Instant::now()));
        }
        perform(gateway.on_tick(Instant::now()));
    }
}

fn describe(outcome: &PushOutcome) -> String {
    match outcome {
        PushOutcome::Accepted(what) => format!("accepted: {what}"),
        PushOutcome::Failed(why) => format!("refused: {why}"),
    }
}

fn probe(args: &Args, service: &str) -> Result<(), String> {
    let tls = h2::Tls::new()?;
    match service {
        "apns" => {
            let (mut sender, team, which) = if let Some((sender, team)) = apns_from(args)? {
                (sender, team, "the key named")
            } else {
                let team = "SIPRALPRB0".to_owned();
                let sender = apns::Apns::new(
                    jwt::Signer::es256_throwaway()?,
                    "SIPRALPRB0",
                    &team,
                    !args.has("--apns-production"),
                );
                (sender, team, "a key made up for this probe")
            };
            let topic = args
                .value("--topic", None)
                .unwrap_or_else(|| "org.sipral.probe.voip".to_owned());
            let push = PushRequest {
                id: 0,
                provider: "apns".into(),
                prid: args
                    .value("--device-token", None)
                    .unwrap_or_else(|| "0".repeat(64)),
                param: Some(format!("{team}.{topic}")),
                kind: PushKind::Call,
                caller: Some("sip:probe@sipral.invalid".into()),
                name: None,
                call_id: Some("probe@sipral.invalid".into()),
            };
            println!(
                "apns probe: {} with {which}, topic {topic}: {}",
                sender.host(),
                describe(&sender.send(&tls, &push))
            );
        }
        "fcm" => {
            let token = args
                .value("--device-token", None)
                .unwrap_or_else(|| "sipral-probe-not-a-registration-token".to_owned());
            let mut push = PushRequest {
                id: 0,
                provider: "fcm".into(),
                prid: token,
                param: None,
                kind: PushKind::Call,
                caller: Some("sip:probe@sipral.invalid".into()),
                name: None,
                call_id: Some("probe@sipral.invalid".into()),
            };
            if let Some((mut sender, project)) = fcm_from(args, Duration::from_secs(20))? {
                push.param = Some(project.clone());
                println!(
                    "fcm probe: project {project} with the service account named: {}",
                    describe(&sender.send(&tls, &push))
                );
            } else {
                let (host, port, request) = fcm::token_request(
                    "https://oauth2.googleapis.com/token",
                    "sipral.probe.assertion",
                )?;
                let answer = tls.send(&host, port, &request).and_then(|response| {
                    fcm::token_answer(&response).map(|_| "an access token".to_owned())
                });
                println!(
                    "fcm probe: {host} with an assertion nobody signed: {}",
                    answer.unwrap_or_else(|why| format!("refused: {why}"))
                );
                let request = fcm::message_request(
                    "sipral-probe",
                    Duration::from_secs(20),
                    &push,
                    "sipral-probe",
                );
                let outcome = tls
                    .send(fcm::HOST, 443, &request)
                    .map_or_else(PushOutcome::Failed, |response| fcm::describe(&response));
                println!(
                    "fcm probe: {} with an access token nobody issued: {}",
                    fcm::HOST,
                    describe(&outcome)
                );
            }
        }
        other => return Err(format!("probe apns or probe fcm, not {other}")),
    }
    Ok(())
}

fn main() {
    let words: Vec<String> = std::env::args().skip(1).collect();
    let args = Args {
        words: words.clone(),
    };
    let outcome = match words.first().map(String::as_str) {
        Some("run") => run(&args),
        Some("fake-pns") => args
            .value("--listen", None)
            .map_or_else(|| address("0.0.0.0:5099"), |text| address(&text))
            .and_then(fake::serve),
        Some("probe") => probe(&args, words.get(1).map_or("", String::as_str)),
        _ => Err("usage: sipral-push-gateway run|fake-pns|probe ... (see src/main.rs)".to_owned()),
    };
    if let Err(why) = outcome {
        eprintln!("sipral-push-gateway: {why}");
        std::process::exit(2);
    }
}
