// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Two agents on one server, so that one of them receives a call.
//!
//! Every other flow places the call, which means the offer is always ours and
//! the answer is always somebody else's. The narrowing half of RFC 3264 §6.1 —
//! given a list of formats, keep the ones we have and refuse the rest — has
//! therefore only ever been asked to narrow offers written in this repository.
//!
//! Here the far end offers. Registering a second account whose codec list the
//! server was told to leave wide makes the PBX send an INVITE carrying
//! everything it knows, and what comes back has to be exactly the G.711 in it
//! and nothing else.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::msg::OwnedMessage;
use sipral_core::sdp::{self, AcceptedStream, Connection, Direction, Origin};
use sipral_ua::{
    Account, AccountId, CallHandle, Control, Credentials, EndpointConfig, Handler, OutgoingCall,
    Runtime, UaEvent, Uri, UserAgent,
};

use crate::media::Media;

/// How long the pair may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long the call stays up once it is answered.
const DWELL: Duration = Duration::from_secs(2);

/// What the callee saw, which is what this flow exists to check.
#[derive(Debug, Default)]
struct Narrowing {
    /// The formats the server offered us.
    offered: Vec<String>,
    /// The ones our answer kept.
    kept: Vec<String>,
    /// Whether the call was answered and confirmed.
    up: bool,
}

/// The end that waits to be called.
struct Callee {
    account: AccountId,
    local: SocketAddr,
    media: Media,
    narrowing: Narrowing,
    registered: bool,
    asked: bool,
    done: bool,
}

impl Handler for Callee {
    fn on_event(&mut self, agent: &mut UserAgent, event: UaEvent, now: Instant) {
        match event {
            UaEvent::Registered { .. } => self.registered = true,
            UaEvent::IncomingCall { call, request, .. } => self.answer(agent, call, &request, now),
            UaEvent::CallConfirmed { .. } => self.narrowing.up = true,
            UaEvent::CallEnded { .. } => self.done = true,
            _ => (),
        }
    }

    fn on_tick(&mut self, agent: &mut UserAgent, now: Instant) -> Control {
        if !self.asked {
            self.asked = true;
            let _ = agent.register(self.account, now);
        }
        self.media.turn(now);
        if self.done {
            return Control::Stop;
        }
        Control::Continue
    }
}

impl Callee {
    /// Answer with what is left after keeping only the formats we have.
    fn answer(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let Ok(theirs) = sdp::parse(request.as_raw().body()) else {
            let _ = agent.answer(call, None, now);
            return;
        };
        let Some(stream) = theirs.media.first() else {
            return;
        };
        self.narrowing.offered.clone_from(&stream.formats);
        // G.711 and nothing else. §6.1 allows an answer to add formats it
        // cannot send yet; adding what we cannot decode would be a lie
        let kept: Vec<String> = stream
            .formats
            .iter()
            .filter(|format| matches!(format.as_str(), "0" | "8"))
            .cloned()
            .collect();
        if kept.is_empty() {
            let _ = agent.reject(call, sipral_core::msg::StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        }
        self.narrowing.kept.clone_from(&kept);
        let port = self.media.port().unwrap_or(0);
        let answer = theirs.answer(
            Origin::new(1, 1, self.local.ip()),
            Connection::new(self.local.ip()),
            &[sipral_core::sdp::StreamAnswer::Accept(AcceptedStream {
                port,
                connection: None,
                formats: kept,
                direction: Direction::SendRecv,
                attributes: Vec::new(),
            })],
        );
        let Ok(answer) = answer else {
            return;
        };
        let body = answer.to_string().into_bytes();
        if agent.answer(call, Some(body.into()), now).is_ok()
            && let Ok(ours) = sdp::parse(&answer.to_string().into_bytes())
            && let Ok(Some(plan)) = ours.media_plan(&theirs, 0)
        {
            self.media.start(&plan, 0x4341_4c4c, now);
        }
    }
}

/// The end that places it.
struct Caller {
    account: AccountId,
    target: Uri,
    call: Option<CallHandle>,
    hang_up_at: Option<Instant>,
    /// Every event this end saw, in order. A pair that stalls says nothing
    /// about why unless somebody wrote down what did happen.
    saw: Vec<String>,
    asked: bool,
    placed: bool,
    done: bool,
}

impl Handler for Caller {
    fn on_event(&mut self, _agent: &mut UserAgent, event: UaEvent, now: Instant) {
        match event {
            UaEvent::Registered { .. } => self.saw.push("registered".to_owned()),
            UaEvent::CallProgress { state, .. } => self.saw.push(format!("progress {state:?}")),
            UaEvent::CallConfirmed { .. } => {
                self.saw.push("confirmed".to_owned());
                self.hang_up_at = Some(now + DWELL);
            }
            UaEvent::CallEnded { reason, status, .. } => {
                self.saw.push(match status {
                    Some(status) => format!("ended {reason} ({})", status.get()),
                    None => format!("ended {reason}"),
                });
                self.done = true;
            }
            other => self.saw.push(short(&other).to_owned()),
        }
    }

    fn on_tick(&mut self, agent: &mut UserAgent, now: Instant) -> Control {
        if !self.asked {
            self.asked = true;
            let _ = agent.register(self.account, now);
        }
        if self.hang_up_at.is_some_and(|due| now >= due)
            && let Some(call) = self.call
        {
            self.hang_up_at = None;
            let _ = agent.hangup(call, now);
        }
        if self.done {
            return Control::Stop;
        }
        Control::Continue
    }
}

impl Caller {
    /// Place the call, once the callee has had time to register.
    fn place(&mut self, agent: &mut UserAgent, now: Instant) {
        if self.placed {
            return;
        }
        self.placed = true;
        let placing = OutgoingCall::new(self.target.clone());
        if let Ok(call) = agent.call(self.account, &placing, now) {
            self.call = Some(call);
        }
    }
}

/// Register two accounts, have one call the other, and report what the answer
/// kept of what was offered.
///
/// # Errors
/// Anything that stops the pair from getting as far as an answer.
pub(crate) fn run(
    server: &str,
    remote: SocketAddr,
    answering_user: &str,
    answering_pass: &str,
    dialling_user: &str,
    dialling_pass: &str,
) -> Result<String, String> {
    // the address that reaches the server, for the reason given in `run` in
    // main.rs: a wildcard here becomes a `Via` naming nowhere
    let bind = SocketAddr::new(crate::route_to(remote), 0);

    let mut answering_rt = Runtime::bind(EndpointConfig::default(), [71; 32], bind)
        .map_err(|error| format!("cannot bind the callee: {error}"))?;
    let mut dialling_rt = Runtime::bind(EndpointConfig::default(), [73; 32], bind)
        .map_err(|error| format!("cannot bind the caller: {error}"))?;

    let answering_id = account(
        &mut answering_rt,
        server,
        remote,
        answering_user,
        answering_pass,
    )?;
    let dialling_id = account(
        &mut dialling_rt,
        server,
        remote,
        dialling_user,
        dialling_pass,
    )?;

    let mut answering = Callee {
        account: answering_id,
        local: crate::advertised(answering_rt.local(), remote),
        media: Media::bind(Instant::now())?,
        narrowing: Narrowing::default(),
        registered: false,
        asked: false,
        done: false,
    };
    let mut dialling = Caller {
        account: dialling_id,
        target: crate::uri(&format!("sip:{answering_user}@{server}"))?,
        call: None,
        hang_up_at: None,
        saw: Vec::new(),
        asked: false,
        placed: false,
        done: false,
    };

    let started = Instant::now();
    loop {
        let now = Instant::now();
        if now > started + PATIENCE {
            return Err(format!(
                "the pair never got as far as an answer: callee registered {}, \
                 caller saw [{}], call placed {}, offer seen {}, answered {}",
                answering.registered,
                dialling.saw.join(", "),
                dialling.call.is_some(),
                !answering.narrowing.offered.is_empty(),
                answering.narrowing.up
            ));
        }
        let a = answering_rt
            .turn(&mut answering, now)
            .map_err(|error| format!("the callee's loop stopped: {error}"))?;
        // only once the callee is registered, or the server has nowhere to
        // send the INVITE and answers 404 instead of ringing anybody
        if answering.registered {
            dialling.place(dialling_rt.agent(), Instant::now());
        }
        let b = dialling_rt
            .turn(&mut dialling, Instant::now())
            .map_err(|error| format!("the caller's loop stopped: {error}"))?;
        if a == Control::Stop && b == Control::Stop {
            break;
        }
        if answering.done && dialling.done {
            break;
        }
    }

    verdict(&answering)
}

/// What the flow proved, or the first thing it did not.
fn verdict(seen: &Callee) -> Result<String, String> {
    if seen.narrowing.offered.is_empty() {
        return Err("no offer arrived: the server never sent us an INVITE with one".to_owned());
    }
    if !seen.narrowing.up {
        return Err("the call we answered was never confirmed".to_owned());
    }
    if seen.narrowing.kept.is_empty() {
        return Err("the answer kept no format at all".to_owned());
    }
    if seen.narrowing.offered.len() <= seen.narrowing.kept.len() {
        return Err(format!(
            "nothing was narrowed: {} offered, {} kept — the server's list was not wide",
            seen.narrowing.offered.len(),
            seen.narrowing.kept.len()
        ));
    }
    if let Some(invented) = seen
        .narrowing
        .kept
        .iter()
        .find(|format| !seen.narrowing.offered.contains(format))
    {
        return Err(format!(
            "the answer kept {invented}, which was never offered"
        ));
    }
    let heard = seen.media.heard();
    Ok(format!(
        "   ({} offered, kept {}; {} sent, {} back, {} audible)",
        seen.narrowing.offered.len(),
        seen.narrowing.kept.join(" and "),
        heard.sent,
        heard.received,
        heard.audible
    ))
}

fn account(
    runtime: &mut Runtime,
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<AccountId, String> {
    let local = runtime.local();
    let transport = runtime.transport();
    let aor = crate::uri(&format!("sip:{user}@{server}"))?;
    let registrar = crate::uri(&format!("sip:{server}"))?;
    let contact = crate::uri(&format!("sip:{user}@{}", crate::advertised(local, remote)))?;
    Ok(runtime.agent().add_account(
        Account::new(aor, registrar, contact, transport, remote)
            .credentials(Credentials::new(user, pass))
            .expires(Duration::from_secs(300)),
    ))
}

/// A one-word name for an event, for the diagnosis line.
fn short(event: &UaEvent) -> &'static str {
    match *event {
        UaEvent::Registered { .. } => "registered",
        UaEvent::Unregistered { .. } => "unregistered",
        UaEvent::RegistrationFailed { .. } => "registration failed",
        UaEvent::IncomingCall { .. } => "incoming",
        UaEvent::CallProgress { .. } => "progress",
        UaEvent::CallConfirmed { .. } => "confirmed",
        UaEvent::CallEnded { .. } => "ended",
        UaEvent::SessionChanged { .. } => "session changed",
        _ => "something else",
    }
}
