// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
//!
//! # Through a relay
//!
//! With `SIPRAL_TURN_SERVER`, `SIPRAL_TURN_USER` and `SIPRAL_TURN_PASSWORD`
//! set, each end also allocates a relay on that TURN server for its media
//! socket before the call (`sipral::Relays`) and hands it to the call
//! (`CallMedia::relay`). `scripts/lab.sh ice` runs that with the two NATs
//! told to drop everything between them but SIP, so the server-reflexive
//! pair the step above found is gone and the relay is the one path left: the
//! caller then fails a path that does not go through the TURN server, and
//! prints how long the allocation took, which is what TURN adds to a call's
//! start before the offer can be written.

use std::env;
use std::io::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallMedia, Event, IcePolicy, Keep, MappingEvent, Mappings, MediaConfig, OutgoingCall,
    Relay, RelayEvent, Relays, UaEvent,
};

use crate::audio::Media;
use crate::ice_lite::{drive, verdict};
use crate::{Endpoint, catalog, route_to, run_folded, uri};

/// How long a mapping is waited for: longer than `Mappings`' own five and a
/// half seconds, so that it is the one that gives up and says why.
const MAPPING_PATIENCE: Duration = Duration::from_secs(8);

/// How long the callee waits for the call to arrive.
const CALLEE_PATIENCE: Duration = Duration::from_secs(60);

/// This flow's own endpoint identity constants, each folded with the run's
/// own entropy before anything binds with it (`run_folded`, `main.rs`).
/// Listed in `main.rs`'s `tests::endpoint_identity_constants_are_distinct`
/// alongside every other step's, so a value reused here or added later fails
/// that test rather than a live run.
pub(crate) const CALLER_SEED: u8 = 8;
pub(crate) const CALLER_MEDIA_SEED: u8 = 9;
pub(crate) const CALLER_RELAY_SEED: u8 = 10;
pub(crate) const ANSWER_SEED: u8 = 11;
pub(crate) const ANSWER_MEDIA_SEED: u8 = 12;
pub(crate) const ANSWER_RELAY_SEED: u8 = 13;

/// The STUN server both ends ask, from `SIPRAL_STUN_SERVER`.
pub(crate) fn stun_server() -> Result<SocketAddr, String> {
    env::var("SIPRAL_STUN_SERVER")
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| "SIPRAL_STUN_SERVER does not name an address".to_owned())
}

/// The STUN servers to turn to when the first fails, from
/// `SIPRAL_STUN_FALLBACKS`: `host:port` addresses separated by commas, none
/// when it is unset.
///
/// # Errors
/// An entry that is not an address.
pub(crate) fn stun_fallbacks() -> Result<Vec<SocketAddr>, String> {
    let Ok(list) = env::var("SIPRAL_STUN_FALLBACKS") else {
        return Ok(Vec::new());
    };
    list.split(',')
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| {
            entry.trim().parse().map_err(|_| {
                format!("SIPRAL_STUN_FALLBACKS names {entry:?}, which is not an address")
            })
        })
        .collect()
}

/// Whether the run says the first STUN server is dead on purpose, so that a
/// mapping learned without the server in use moving is a failure:
/// `SIPRAL_STUN_EXPECT_FAILOVER=1`, which only `scripts/lab.sh robust` sets.
fn failover_expected() -> bool {
    env::var("SIPRAL_STUN_EXPECT_FAILOVER").is_ok_and(|value| value == "1")
}

/// Where `media`'s socket, known to the call as `local`, appears from
/// outside, asked of `server` and, when it fails, of the servers
/// `SIPRAL_STUN_FALLBACKS` names.
///
/// # Errors
/// When no server answers, or one answers with the socket's own address — a
/// call from there would prove nothing about a NAT — or when the run
/// expected the first server to fail and it did not.
fn map(
    media: &mut Media,
    server: SocketAddr,
    local: SocketAddr,
    seed: [u8; 32],
) -> Result<SocketAddr, String> {
    let started = Instant::now();
    let fallbacks = stun_fallbacks()?;
    // five and a half seconds for each server that may stay silent before
    // the one that answers
    let patience = MAPPING_PATIENCE
        + Duration::from_millis(5_500)
            .saturating_mul(u32::try_from(fallbacks.len()).unwrap_or(u32::MAX));
    let mut mappings = Mappings::new(server, seed).fallbacks(fallbacks);
    let mut moved = false;
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
                MappingEvent::Learned { .. } if failover_expected() && !moved => {
                    return Err(format!(
                        "{server} was to be dead and answered: the failover was never exercised"
                    ));
                }
                MappingEvent::Learned { public, .. } => return Ok(public),
                MappingEvent::ServerChanged { previous, server } => {
                    println!("  stun  {previous} did not answer; asking {server}");
                    moved = true;
                }
                MappingEvent::ServersFailed { last } => {
                    println!("  stun  every server failed, {last} last");
                }
                MappingEvent::Unanswered { failure, .. } => {
                    return Err(format!(
                        "{server} never said where the media socket appears: {failure:?}"
                    ));
                }
                MappingEvent::Moved { .. } => {}
            }
        }
        if now > started + patience {
            return Err(format!("{server} never answered for the media socket"));
        }
        if mappings.poll_timeout().is_some_and(|due| due <= now) {
            mappings.handle_timeout(now);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The TURN server both ends allocate on, and the credential it knows them
/// by, when `SIPRAL_TURN_SERVER` names one.
///
/// # Errors
/// A server that is not an address, or one named without a credential.
pub(crate) fn turn_server() -> Result<Option<(SocketAddr, String, String)>, String> {
    let Ok(server) = env::var("SIPRAL_TURN_SERVER") else {
        return Ok(None);
    };
    let server = server
        .parse()
        .map_err(|_| "SIPRAL_TURN_SERVER does not name an address".to_owned())?;
    let (Ok(user), Ok(password)) = (
        env::var("SIPRAL_TURN_USER"),
        env::var("SIPRAL_TURN_PASSWORD"),
    ) else {
        return Err(
            "SIPRAL_TURN_SERVER needs SIPRAL_TURN_USER and SIPRAL_TURN_PASSWORD".to_owned(),
        );
    };
    Ok(Some((server, user, password)))
}

/// A relay for `media`'s socket, known to the call as `local`, allocated on
/// the TURN server `turn` names, and how long the allocation took.
///
/// # Errors
/// When the server refuses or does not answer.
fn relay(
    media: &mut Media,
    (server, user, password): &(SocketAddr, String, String),
    local: SocketAddr,
    seed: [u8; 32],
) -> Result<(Relay, Duration), String> {
    let started = Instant::now();
    let mut relays = Relays::new(*server, user, password, seed);
    relays.allocate(local, started);
    loop {
        let now = Instant::now();
        while let Some(datagram) = relays.poll_transmit() {
            media.send(datagram.destination, &datagram.payload);
        }
        media.receive_relay(&mut relays, local, now);
        // one socket, so the first event is the only one there will be
        match relays.poll_event() {
            Some(RelayEvent::Allocated { .. }) => {
                let took = now.saturating_duration_since(started);
                let relay = relays
                    .take(local)
                    .ok_or_else(|| "an allocation reported and not there".to_owned())?;
                return Ok((relay, took));
            }
            Some(RelayEvent::Failed { failure, .. }) => {
                return Err(format!("{server} gave no relay: {failure}"));
            }
            None => {}
        }
        if now > started + MAPPING_PATIENCE {
            return Err(format!("{server} never answered the Allocate"));
        }
        if relays.poll_timeout().is_some_and(|due| due <= now) {
            relays.handle_timeout(now);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A relay handed to a call, and how long its allocation took.
pub(crate) type Allocated = Option<(Relay, Duration)>;

/// A media socket bound, where it appears from outside — its address for the
/// call and its server-reflexive one — and, with a TURN server named, a relay
/// for it and how long that took.
pub(crate) fn mapped_media(
    toward: SocketAddr,
    stun: SocketAddr,
    seed: [u8; 32],
) -> Result<(Media, SocketAddr, SocketAddr, Allocated), String> {
    let mut media = Media::bind(Instant::now())?;
    let local = SocketAddr::new(route_to(toward), media.port()?);
    let public = map(&mut media, stun, local, seed)?;
    let relayed = match turn_server()? {
        Some(turn) => {
            let mut other = seed;
            other[0] ^= 0x5a;
            Some(relay(&mut media, &turn, local, other)?)
        }
        None => None,
    };
    Ok((media, local, public, relayed))
}

/// `media` with the relay, when there is one, and what to say about it.
pub(crate) fn with_relay(media: CallMedia, relayed: Allocated) -> (CallMedia, String) {
    match relayed {
        Some((relay, took)) => {
            let said = format!(
                ", relay {} allocated in {} ms",
                relay
                    .relayed()
                    .map_or_else(|| "?".to_owned(), |address| address.to_string()),
                took.as_millis()
            );
            (media.relay(relay), said)
        }
        None => (media, String::new()),
    }
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
        run_folded([CALLER_SEED; 32]),
        run_folded([CALLER_MEDIA_SEED; 32]),
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
    let (media, local, public, relayed) =
        mapped_media(remote, stun, run_folded([CALLER_RELAY_SEED; 32]))?;
    let turn = turn_server()?.map(|(server, ..)| server);
    let (described, allocated) = with_relay(
        CallMedia::new(required, MediaConfig::default()).public_address(public),
        relayed,
    );
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
            described,
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
    match (turn, seen.chosen) {
        // with the direct path blocked, a path that does not go through the
        // TURN server at one end or the other is one the block let through,
        // and proves nothing about the relay
        (Some(server), Some((near, far, _)))
            if near.ip() != server.ip() && far.ip() != server.ip() =>
        {
            return Err(format!(
                "the path {near} -> {far} does not go through the TURN server at {}",
                server.ip()
            ));
        }
        // the one address on the callee's side this end can reach is its
        // NAT's: a path anywhere else went round the NAT rather than
        // through it
        (None, Some((_, far, _))) if far.ip() != remote.ip() => {
            return Err(format!(
                "the path ends at {far}, which is not the callee's NAT at {}",
                remote.ip()
            ));
        }
        // no path at all is `verdict`'s to refuse, and it already has
        _ => {}
    }
    Ok(format!(
        "{said}; this end at {local}, mapped to {public}{allocated}"
    ))
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
        run_folded([ANSWER_SEED; 32]),
        run_folded([ANSWER_MEDIA_SEED; 32]),
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
    let (media, local, public, relayed) =
        mapped_media(stun, stun, run_folded([ANSWER_RELAY_SEED; 32]))?;
    let (described, allocated) = with_relay(
        CallMedia::new(required, MediaConfig::default()).public_address(public),
        relayed,
    );
    println!(
        "waiting for the call on {}, media at {local}, mapped to {public}{allocated}",
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
        .answer_with(&mut endpoint.agent, call, local, described, answered)
        .map_err(|error| format!("could not answer: {error}"))?;
    let seen = drive(&mut endpoint, call, answered, false);
    let heard = endpoint
        .media
        .get(&call)
        .map(Media::heard)
        .unwrap_or_default();
    let said = verdict(&seen, heard)?;
    Ok(format!(
        "{said}; this end at {local}, mapped to {public}{allocated}"
    ))
}
