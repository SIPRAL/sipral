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
//!
//! Both roles are driven by [`Endpoint`], the same pump `main`'s flow script
//! uses: `sipral::MediaEngine::answer` is what narrows the offer now, kept to
//! the catalogue this side opened with, and the diagnosis is
//! `sipral::MediaSession::codec_candidates` rather than a hand-rolled filter
//! on the offer's own format list.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    Account, AccountId, CallHandle, CallMedia, CodecOutcome, Credentials, Event, MediaConfig,
    OutgoingCall, UaEvent, Uri,
};
use sipral_core::sdp;

use crate::audio::Media;
use crate::{Endpoint, advertised, catalog, place_call, run_folded, uri};

/// How long the pair may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long the call stays up once it is answered.
const DWELL: Duration = Duration::from_secs(2);

/// This flow's own endpoint identity constants, each folded with the run's
/// own entropy before anything binds with it (`run_folded`, `main.rs`).
/// Listed in `main.rs`'s `tests::endpoint_identity_constants_are_distinct`
/// alongside every other step's, so a value reused here or added later fails
/// that test rather than a live run.
pub(crate) const ANSWERING_SEED: u8 = 71;
pub(crate) const ANSWERING_MEDIA_SEED: u8 = 171;
pub(crate) const DIALLING_SEED: u8 = 73;
pub(crate) const DIALLING_MEDIA_SEED: u8 = 173;

/// What the callee saw, which is what this flow exists to check.
#[derive(Debug, Default)]
struct Narrowing {
    /// The formats the server offered us, read from the INVITE itself.
    offered: Vec<String>,
    /// Every codec in this end's own catalogue that the offer also named —
    /// D5's diagnosis, filtered to drop what the far end never listed.
    kept: Vec<sipral::Codec>,
    /// Whether the call was answered and confirmed.
    up: bool,
}

/// The end that waits to be called.
struct Callee {
    endpoint: Endpoint,
    account: AccountId,
    remote: SocketAddr,
    registered: bool,
    asked: bool,
    narrowing: Narrowing,
    done: bool,
}

impl Callee {
    fn turn(&mut self, now: Instant) {
        if !self.asked {
            self.asked = true;
            let _ = self.endpoint.agent.register(self.account, now);
        }
        for event in self.endpoint.pump(now) {
            self.on_event(event, now);
        }
        self.endpoint.run_media(now);
        self.endpoint.timers(now);
    }

    fn on_event(&mut self, event: Event, now: Instant) {
        match event {
            Event::Signalling(UaEvent::Registered { .. }) => self.registered = true,
            Event::Signalling(UaEvent::IncomingCall { call, request, .. }) => {
                self.narrowing.offered = offered_formats(request.as_raw().body());
                if let Ok(local) = self.endpoint.open_media(call, self.remote, now) {
                    let _ = self
                        .endpoint
                        .engine
                        .answer(&mut self.endpoint.agent, call, local, now);
                }
            }
            Event::Signalling(UaEvent::CallConfirmed { call, .. }) => {
                self.narrowing.up = true;
                if let Some(session) = self.endpoint.engine.session(call) {
                    self.narrowing.kept = session
                        .codec_candidates()
                        .iter()
                        .filter(|candidate| !matches!(candidate.outcome, CodecOutcome::NotNamed))
                        .map(|candidate| candidate.codec)
                        .collect();
                }
            }
            Event::Signalling(UaEvent::CallEnded { .. }) => self.done = true,
            _ => (),
        }
    }
}

/// The `m=audio` line's own format list, read straight off the request this
/// end was handed — the offer as it actually arrived, not as this end would
/// have written it.
fn offered_formats(body: &[u8]) -> Vec<String> {
    sdp::parse(body)
        .ok()
        .and_then(|description| {
            description
                .media
                .first()
                .map(|stream| stream.formats.clone())
        })
        .unwrap_or_default()
}

/// The end that places it.
struct Caller {
    endpoint: Endpoint,
    account: AccountId,
    target: Uri,
    remote: SocketAddr,
    call: Option<CallHandle>,
    hang_up_at: Option<Instant>,
    /// Every event this end saw, in order. A pair that stalls says nothing
    /// about why unless somebody wrote down what did happen.
    saw: Vec<String>,
    asked: bool,
    placed: bool,
    done: bool,
}

impl Caller {
    fn turn(&mut self, callee_registered: bool, now: Instant) {
        if !self.asked {
            self.asked = true;
            let _ = self.endpoint.agent.register(self.account, now);
        }
        for event in self.endpoint.pump(now) {
            self.on_event(event, now);
        }
        self.endpoint.run_media(now);
        self.endpoint.timers(now);
        // only once the callee is registered, or the server has nowhere to
        // send the INVITE and answers 404 instead of ringing anybody
        if callee_registered {
            self.place(now);
        }
        if self.hang_up_at.is_some_and(|due| now >= due)
            && let Some(call) = self.call
        {
            self.hang_up_at = None;
            let _ = self.endpoint.agent.hangup(call, now);
        }
    }

    fn place(&mut self, now: Instant) {
        if self.placed {
            return;
        }
        self.placed = true;
        let media = CallMedia::new(catalog(), MediaConfig::default());
        let outgoing =
            OutgoingCall::new(self.target.clone()).to_address(self.endpoint.transport, self.remote);
        if let Ok(call) = place_call(
            &mut self.endpoint,
            self.account,
            outgoing,
            media,
            self.remote,
            now,
        ) {
            self.call = Some(call);
        }
    }

    fn on_event(&mut self, event: Event, now: Instant) {
        match event {
            Event::Signalling(UaEvent::Registered { .. }) => self.saw.push("registered".to_owned()),
            Event::Signalling(UaEvent::CallProgress { state, .. }) => {
                self.saw.push(format!("progress {state:?}"));
            }
            Event::Signalling(UaEvent::CallConfirmed { .. }) => {
                self.saw.push("confirmed".to_owned());
                self.hang_up_at = Some(now + DWELL);
            }
            Event::Signalling(UaEvent::CallEnded { reason, status, .. }) => {
                self.saw.push(match status {
                    Some(status) => format!("ended {reason} ({})", status.get()),
                    None => format!("ended {reason}"),
                });
                self.done = true;
            }
            Event::Signalling(other) => self.saw.push(short(&other).to_owned()),
            // `Event::Media`, and anything `sipral::Event` (which is
            // `#[non_exhaustive]`) grows later
            _ => {}
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
    // the address that reaches the server, for the reason given in `main.rs`:
    // a wildcard here becomes a `Via` naming nowhere
    let bind = SocketAddr::new(crate::route_to(remote), 0);
    let now = Instant::now();

    let mut answering_endpoint = Endpoint::bind(
        run_folded([ANSWERING_SEED; 32]),
        run_folded([ANSWERING_MEDIA_SEED; 32]),
        bind,
        catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind the callee: {error}"))?;
    let mut dialling_endpoint = Endpoint::bind(
        run_folded([DIALLING_SEED; 32]),
        run_folded([DIALLING_MEDIA_SEED; 32]),
        bind,
        catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind the caller: {error}"))?;

    let answering_id = account(
        &mut answering_endpoint,
        server,
        remote,
        answering_user,
        answering_pass,
    )?;
    let dialling_id = account(
        &mut dialling_endpoint,
        server,
        remote,
        dialling_user,
        dialling_pass,
    )?;

    let mut answering = Callee {
        endpoint: answering_endpoint,
        account: answering_id,
        remote,
        registered: false,
        asked: false,
        narrowing: Narrowing::default(),
        done: false,
    };
    let mut dialling = Caller {
        endpoint: dialling_endpoint,
        account: dialling_id,
        target: crate::uri(&format!("sip:{answering_user}@{server}"))?,
        remote,
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
        answering.turn(now);
        dialling.turn(answering.registered, now);
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
        return Err("the answer kept no codec at all".to_owned());
    }
    if seen.narrowing.offered.len() <= seen.narrowing.kept.len() {
        return Err(format!(
            "nothing was narrowed: {} offered, {} kept — the server's list was not wide",
            seen.narrowing.offered.len(),
            seen.narrowing.kept.len()
        ));
    }
    let kept_names: Vec<String> = seen
        .narrowing
        .kept
        .iter()
        .map(sipral::Codec::to_string)
        .collect();
    let heard = seen
        .endpoint
        .media
        .values()
        .next()
        .map(Media::heard)
        .unwrap_or_default();
    Ok(format!(
        "   ({} offered, kept {}; {} sent, {} back, {} audible)",
        seen.narrowing.offered.len(),
        kept_names.join(" and "),
        heard.sent,
        heard.received,
        heard.audible
    ))
}

fn account(
    endpoint: &mut Endpoint,
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<AccountId, String> {
    let aor = uri(&format!("sip:{user}@{server}"))?;
    let registrar = uri(&format!("sip:{server}"))?;
    let contact = uri(&format!(
        "sip:{user}@{}",
        advertised(endpoint.local, remote)
    ))?;
    Ok(endpoint.agent.add_account(
        Account::new(aor, registrar, contact, endpoint.transport, remote)
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
        UaEvent::CallConfirmed { .. } => "confirmed",
        UaEvent::CallEnded { .. } => "ended",
        UaEvent::SessionChanged { .. } => "session changed",
        _ => "something else",
    }
}
