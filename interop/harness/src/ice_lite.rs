// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A call that requires ICE, placed straight at an ICE-lite peer, and the
//! audio carried on the pair the checks chose.
//!
//! `scripts/lab.sh`'s ICE-lite step runs `headless-socket-agent --ice-lite`
//! on the lab network and points this flow at it, unregistered and with no
//! server in between: a PBX in the middle would terminate the media, and ICE
//! with it. This end is the full agent, as a WebRTC gateway would be, and
//! places the call under `IcePolicy::Required`, which is what makes the flow
//! mean something — a peer that answered without `a=ice-lite`, candidates
//! and credentials, or that never answered a check, leaves this end with
//! `MediaError::IceRequired` or no path at all, never with audio on a path
//! nobody checked. The reference agent behind the socket echoes, so the tone
//! this end sends is what comes back.
//!
//! The same flow runs between two stacks behind the lab's NAT
//! (`scripts/lab.sh ice`), where the far end is full as well and the pair
//! found is a server-reflexive one; what differs there is the far end, not
//! anything here. In both, the time from placing the call to
//! `MediaEvent::PathChosen` is printed: it is the start-up cost ICE adds,
//! which `docs/06-nat.md` quotes.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CallMedia, Event, IcePolicy, MediaConfig, MediaEvent, OutgoingCall,
    UaEvent,
};

use crate::{Endpoint, catalog, place_call, route_to, uri};

/// How long the flow may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long the call stays up once a path is chosen: long enough for the
/// tone to go out and come back through the far end's echo many times over.
const DWELL: Duration = Duration::from_secs(3);

/// Frames of the tone that have to come back before the path counts as
/// carrying audio: a fifth of a second, which neither a stray frame nor
/// concealment reaches.
const AUDIBLE_FRAMES: u32 = 10;

/// What the call told this end, in the order it matters to the verdict.
#[derive(Debug, Default)]
struct Seen {
    confirmed: bool,
    started: bool,
    chosen: Option<(SocketAddr, SocketAddr, Duration)>,
    failed: Option<String>,
    ended: bool,
}

/// Place the call at `target` (the far end's own SIP address), require ICE of
/// it, and judge the path and the audio.
///
/// # Errors
/// The first condition that did not hold, named.
pub(crate) fn run(target: &str, remote: SocketAddr) -> Result<String, String> {
    let now = Instant::now();
    let required = catalog().with_ice(IcePolicy::Required);
    let mut endpoint = Endpoint::bind(
        [173; 32],
        [179; 32],
        SocketAddr::new(route_to(remote), 0),
        required.clone(),
        now,
    )?;
    let identity = uri(&format!("sip:harness@{}", endpoint.local))?;
    let account = endpoint.agent.add_account(Account::unregistered(
        identity.clone(),
        identity,
        endpoint.transport,
        remote,
    ));
    let outgoing = OutgoingCall::new(uri(&format!("sip:{target}@{remote}"))?)
        .to_address(endpoint.transport, remote);
    let offered = Instant::now();
    let call = place_call(
        &mut endpoint,
        account,
        outgoing,
        CallMedia::new(required, MediaConfig::default()),
        remote,
        offered,
    )?;

    let mut seen = Seen::default();
    let mut hung_up = false;
    loop {
        let now = Instant::now();
        if now > offered + PATIENCE {
            break;
        }
        for event in endpoint.pump(now) {
            note(&mut seen, call, &event, offered, now);
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        if let Some((_, _, after)) = seen.chosen
            && !hung_up
            && now >= offered + after + DWELL
        {
            hung_up = true;
            let _ = endpoint.agent.hangup(call, now);
        }
        if seen.ended || (seen.failed.is_some() && !hung_up) {
            if !seen.ended {
                let _ = endpoint.agent.hangup(call, now);
            }
            endpoint.flush();
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let heard = endpoint
        .media
        .get(&call)
        .map(crate::audio::Media::heard)
        .unwrap_or_default();
    verdict(&seen, heard)
}

fn note(seen: &mut Seen, call: CallHandle, event: &Event, offered: Instant, now: Instant) {
    match event {
        Event::Signalling(UaEvent::CallConfirmed { call: which, .. }) if *which == call => {
            seen.confirmed = true;
        }
        Event::Signalling(UaEvent::CallEnded { call: which, .. }) if *which == call => {
            seen.ended = true;
        }
        Event::Media {
            call: which,
            event: MediaEvent::Started { .. },
        } if *which == call => seen.started = true,
        Event::Media {
            call: which,
            event: MediaEvent::PathChosen { local, remote },
        } if *which == call && seen.chosen.is_none() => {
            seen.chosen = Some((*local, *remote, now.saturating_duration_since(offered)));
        }
        Event::Media {
            call: which,
            event: MediaEvent::Failed(error),
        } if *which == call => seen.failed = Some(error.to_string()),
        _ => {}
    }
}

fn verdict(seen: &Seen, heard: crate::audio::Heard) -> Result<String, String> {
    if let Some(why) = &seen.failed {
        return Err(format!("the media failed: {why}"));
    }
    if !seen.confirmed {
        return Err("the call was never answered".to_owned());
    }
    if !seen.started {
        return Err("the call never got media".to_owned());
    }
    let Some((local, remote, after)) = seen.chosen else {
        return Err(format!(
            "no path was ever chosen ({} sent, {} back): the far end answered no check",
            heard.sent, heard.received
        ));
    };
    if heard.audible < AUDIBLE_FRAMES {
        return Err(format!(
            "a path was chosen, {local} -> {remote}, but only {} frame(s) of the tone came back \
             ({} sent, {} back, {} refused)",
            heard.audible, heard.sent, heard.received, heard.refused
        ));
    }
    Ok(format!(
        "   (path {local} -> {remote}, chosen {} ms after the offer; {} sent, {} back, {} audible)",
        after.as_millis(),
        heard.sent,
        heard.received,
        heard.audible
    ))
}
