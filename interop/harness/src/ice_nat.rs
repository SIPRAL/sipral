// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Two stacks, each behind a NAT of its own, finding each other with full ICE
//! on the addresses STUN gave them.
//!
//! `scripts/lab.sh ice` puts one harness behind `interop/nat`'s NAT on
//! `inside` and another behind a second one on `inside2`, with coturn on the
//! lab network between them. Neither can reach the other's host candidate:
//! the two inside networks have no route to each other, and each NAT lets in
//! only what answers a flow its own side opened (address- and port-dependent
//! filtering, conntrack's). What reaches is the server-reflexive candidate
//! each learned for its media socket from coturn before the call — and only
//! once both ends have sent a check towards the other's, which is the hole
//! punching ICE's paced, retransmitted checks are built for.
//!
//! Signalling is not what is being proven, so it takes the short way: the
//! callee's NAT forwards its one SIP port, the way a phone with a port
//! forward is reached, and the callee advertises that forward as its
//! `Contact`. The media has no forward. Both ends require ICE, so a call that
//! found no path through the two NATs has no audio and fails, and the caller
//! fails a path that reached the callee anywhere but at its NAT.
//!
//! The caller prints how long ICE took: from the offer to
//! `MediaEvent::PathChosen`, and from the answer to it. The second is what
//! ICE adds to a call's start; the first includes the INVITE's own round
//! trip. `docs/06-nat.md` quotes both.

use std::env;
use std::io::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallMedia, Event, IcePolicy, Keep, MappingEvent, Mappings, MediaConfig, OutgoingCall,
    UaEvent,
};

use crate::audio::Media;
use crate::ice_lite::{drive, verdict};
use crate::{Endpoint, catalog, route_to, uri};

/// How long a mapping is waited for: longer than `Mappings`' own five and a
/// half seconds, so that it is the one that gives up and says why.
const MAPPING_PATIENCE: Duration = Duration::from_secs(8);

/// How long the callee waits for the call to arrive.
const CALLEE_PATIENCE: Duration = Duration::from_secs(60);

/// The STUN server both ends ask, from `SIPRAL_STUN_SERVER`.
fn stun_server() -> Result<SocketAddr, String> {
    env::var("SIPRAL_STUN_SERVER")
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| "SIPRAL_STUN_SERVER does not name an address".to_owned())
}

/// Where `media`'s socket, known to the call as `local`, appears from
/// outside, asked of `server`.
///
/// # Errors
/// When the server does not answer, or answers with the socket's own address
/// — a call from there would prove nothing about a NAT.
fn map(
    media: &mut Media,
    server: SocketAddr,
    local: SocketAddr,
    seed: [u8; 32],
) -> Result<SocketAddr, String> {
    let started = Instant::now();
    let mut mappings = Mappings::new(server, seed);
    mappings.map(local, Keep::Once, started);
    loop {
        let now = Instant::now();
        while let Some(datagram) = mappings.poll_transmit() {
            media.send(datagram.destination, &datagram.payload);
        }
        media.receive_stun(&mut mappings, local, now);
        while let Some(event) = mappings.poll_event() {
            match event {
                MappingEvent::Learned { public, .. } if public == local => {
                    return Err(format!(
                        "{server} saw the media socket at its own address, {local}: \
                         there is no NAT in the way"
                    ));
                }
                MappingEvent::Learned { public, .. } => return Ok(public),
                MappingEvent::Unanswered { failure, .. } => {
                    return Err(format!(
                        "{server} never said where the media socket appears: {failure:?}"
                    ));
                }
                MappingEvent::Moved { .. } => {}
            }
        }
        if now > started + MAPPING_PATIENCE {
            return Err(format!("{server} never answered for the media socket"));
        }
        if mappings.poll_timeout().is_some_and(|due| due <= now) {
            mappings.handle_timeout(now);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A media socket bound, and where it appears from outside: its address for
/// the call, and its server-reflexive one.
fn mapped_media(
    toward: SocketAddr,
    stun: SocketAddr,
    seed: [u8; 32],
) -> Result<(Media, SocketAddr, SocketAddr), String> {
    let mut media = Media::bind(Instant::now())?;
    let local = SocketAddr::new(route_to(toward), media.port()?);
    let public = map(&mut media, stun, local, seed)?;
    Ok((media, local, public))
}

/// The calling side: map the media socket, place a call that requires ICE at
/// `target` on `remote` (the callee's NAT, which forwards its SIP port), and
/// judge the path, which has to end at the callee's NAT, and the audio.
///
/// # Errors
/// The first condition that did not hold, named.
pub(crate) fn call(target: &str, remote: SocketAddr) -> Result<String, String> {
    let stun = stun_server()?;
    let required = catalog().with_ice(IcePolicy::Required);
    let mut endpoint = Endpoint::bind(
        [181; 32],
        [191; 32],
        SocketAddr::new(route_to(remote), 0),
        required.clone(),
        Instant::now(),
    )?;
    let identity = uri(&format!("sip:caller@{}", endpoint.local))?;
    let account = endpoint.agent.add_account(Account::unregistered(
        identity.clone(),
        identity,
        endpoint.transport,
        remote,
    ));
    let (media, local, public) = mapped_media(remote, stun, [193; 32])?;
    let outgoing = OutgoingCall::new(uri(&format!("sip:{target}@{remote}"))?)
        .to_address(endpoint.transport, remote);
    let offered = Instant::now();
    let call = endpoint
        .engine
        .place_with(
            &mut endpoint.agent,
            account,
            outgoing,
            local,
            CallMedia::new(required, MediaConfig::default()).public_address(public),
            offered,
        )
        .map_err(|error| error.to_string())?;
    endpoint.media.insert(call, media);
    let seen = drive(&mut endpoint, call, offered, true);
    let heard = endpoint
        .media
        .get(&call)
        .map(Media::heard)
        .unwrap_or_default();
    let said = verdict(&seen, heard)?;
    // the one address on the callee's side this end can reach is its NAT's:
    // a path anywhere else went round the NAT rather than through it
    if let Some((_, far, _)) = seen.chosen
        && far.ip() != remote.ip()
    {
        return Err(format!(
            "the path ends at {far}, which is not the callee's NAT at {}",
            remote.ip()
        ));
    }
    Ok(format!("{said}; this end at {local}, mapped to {public}"))
}

/// The answering side: bind SIP where the NAT in front of it forwards
/// (`SIPRAL_CONTACT`, which is also what it advertises), map the media
/// socket, answer the first call under `IcePolicy::Required` with the mapped
/// address, and judge the path and the caller's tone.
///
/// # Errors
/// The first condition that did not hold, named.
pub(crate) fn answer(stun_hint: SocketAddr) -> Result<String, String> {
    let stun = stun_server()?;
    let contact = env::var("SIPRAL_CONTACT")
        .map_err(|_| "SIPRAL_CONTACT does not name the forwarded address".to_owned())?;
    let required = catalog().with_ice(IcePolicy::Required);
    let mut endpoint = Endpoint::bind(
        [197; 32],
        [199; 32],
        SocketAddr::new(route_to(stun_hint), 5060),
        required.clone(),
        Instant::now(),
    )?;
    let identity = uri(&format!("sip:callee@{contact}"))?;
    endpoint.agent.add_account(Account::unregistered(
        identity.clone(),
        identity,
        endpoint.transport,
        stun,
    ));
    let (media, local, public) = mapped_media(stun, stun, [211; 32])?;
    println!(
        "waiting for the call on {}, media at {local}, mapped to {public}",
        endpoint.local
    );
    let _ = std::io::stdout().flush();

    let started = Instant::now();
    let (call, answered) = loop {
        let now = Instant::now();
        if now > started + CALLEE_PATIENCE {
            return Err("no call arrived".to_owned());
        }
        let incoming = endpoint
            .pump(now)
            .into_iter()
            .find_map(|event| match event {
                Event::Signalling(UaEvent::IncomingCall { call, .. }) => Some(call),
                _ => None,
            });
        if let Some(call) = incoming {
            break (call, now);
        }
        endpoint.timers(now);
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    endpoint.media.insert(call, media);
    endpoint
        .engine
        .answer_with(
            &mut endpoint.agent,
            call,
            local,
            CallMedia::new(required, MediaConfig::default()).public_address(public),
            answered,
        )
        .map_err(|error| format!("could not answer: {error}"))?;
    let seen = drive(&mut endpoint, call, answered, false);
    let heard = endpoint
        .media
        .get(&call)
        .map(Media::heard)
        .unwrap_or_default();
    let said = verdict(&seen, heard)?;
    Ok(format!("{said}; this end at {local}, mapped to {public}"))
}
