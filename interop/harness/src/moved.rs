// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call that outlives the address it was placed from.
//!
//! One call to Asterisk's echo, no ICE, and audio heard back for a few
//! seconds. Then the network under it changes: `scripts/lab.sh` takes this
//! container off the lab network and puts it back at another address, which
//! is what a laptop moving between two networks looks like to the stack
//! running on it. The old address is gone, and with it every socket bound to
//! it; Asterisk goes on sending the echo to the `c=` it was given, which
//! names nothing any more.
//!
//! What has to happen is what an application does on the platform's own
//! notification: bind the SIP socket at the new address and say so, report
//! the change (`UserAgent::network_changed`), which answers
//! `Recovery::Rebuild` and names the call in `UaEvent::CallAddressWanted`;
//! point the account at the new address (`UserAgent::rebind`), bind the
//! call's media socket there, and hand that to `MediaEngine::readdress`. The
//! re-INVITE carries the new `Contact`, `c=` and port, Asterisk answers it,
//! and the echo comes back to the new socket.
//!
//! # What fails it
//!
//! The call never coming up, no audio before the move, the address never
//! changing within [`MOVE_PATIENCE`], the stack not naming the call, the
//! re-INVITE not being answered, or no audio heard back after it — which is
//! the defect this exists to keep fixed: a stack that only registered again
//! kept its call up with the audio going to an address that was gone.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sipral::{
    CallHandle, CallMedia, Event, Link, MediaConfig, MediaEvent, Network, OutgoingCall, Recovery,
    UaEvent,
};

use crate::{Endpoint, catalog, place_call, route_to, run_folded, uri};

/// `interop/asterisk/extensions.conf`'s echo, the same one `crate::latency`
/// uses.
const ECHO_EXTENSION: &str = "9008";

/// This flow's own endpoint identity, folded with the run's own entropy the
/// way every other step's is (`run_folded`, `main.rs`). Listed in
/// `main.rs`'s `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const SEED: u8 = 18;
pub(crate) const MEDIA_SEED: u8 = 19;

/// How long registering and the call coming up may take.
const PATIENCE: Duration = Duration::from_secs(20);

/// How long the echo is listened to before the address may move.
const BEFORE: Duration = Duration::from_secs(3);

/// How long `scripts/lab.sh` has to move the address once told the call is
/// up.
const MOVE_PATIENCE: Duration = Duration::from_secs(60);

/// How long the echo is listened to once the re-INVITE has been answered.
const AFTER: Duration = Duration::from_secs(4);

/// How long the BYE may take.
const ENDING: Duration = Duration::from_secs(5);

/// Audible frames wanted on each side of the move: half a second of them.
const AUDIBLE_WANTED: u32 = 25;

/// The line `scripts/lab.sh` waits for before it moves the address.
pub(crate) const READY: &str = "  move  the call is up at";

/// Where the call is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    Registering,
    Calling,
    Listening,
    Waiting,
    Moved,
    Ending,
}

/// Place the call, hear the echo, wait for the address to move, move the
/// call with it, and hear the echo again.
///
/// # Errors
/// The first thing that was not as it has to be.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    let old_ip = route_to(remote);
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(
        run_folded([SEED; 32]),
        run_folded([MEDIA_SEED; 32]),
        SocketAddr::new(old_ip, 0),
        catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind: {error}"))?;
    let account = endpoint.account(user, pass, server, remote)?;
    let target = uri(&format!("sip:{ECHO_EXTENSION}@{server}"))?;
    let _ = endpoint.agent.register(account, now);

    let mut stage = Stage::Registering;
    let mut call: Option<CallHandle> = None;
    let mut since = now;
    let mut heard_before = 0_u32;
    let mut wanted: Vec<CallHandle> = Vec::new();
    let mut answered_after_move = false;
    let mut refused: Option<String> = None;
    let mut ended = false;
    let mut new_ip: Option<IpAddr> = None;
    let mut story: Vec<String> = Vec::new();

    loop {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) if stage == Stage::Registering => {
                    stage = Stage::Calling;
                    let media = CallMedia::new(catalog(), MediaConfig::default());
                    let outgoing =
                        OutgoingCall::new(target.clone()).to_address(endpoint.transport, remote);
                    call = Some(place_call(
                        &mut endpoint,
                        account,
                        outgoing,
                        media,
                        remote,
                        now,
                    )?);
                    since = now;
                }
                Event::Media {
                    event: MediaEvent::Started { .. },
                    ..
                } if stage == Stage::Calling => {
                    stage = Stage::Listening;
                    since = now;
                }
                Event::Signalling(UaEvent::CallAddressWanted { call: named }) => {
                    story.push("the call was named".to_owned());
                    wanted.push(named);
                }
                Event::Signalling(UaEvent::SessionChanged { .. }) if stage == Stage::Moved => {
                    story.push("the re-INVITE was answered".to_owned());
                    answered_after_move = true;
                    since = now;
                }
                Event::Signalling(UaEvent::SessionChangeFailed { status, .. }) => {
                    refused = Some(format!("the re-INVITE was refused {status:?}"));
                }
                Event::Signalling(UaEvent::CallEnded { reason, .. }) => {
                    story.push(format!("the call ended {reason}"));
                    ended = true;
                }
                _ => {}
            }
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        endpoint.flush();

        let audible = call
            .and_then(|handle| endpoint.media.get(&handle))
            .map_or(0, |media| media.heard().audible);
        match stage {
            Stage::Registering | Stage::Calling if now > since + PATIENCE => {
                return Err(format!("the call never came up ({stage:?})"));
            }
            Stage::Listening if now >= since + BEFORE => {
                heard_before = audible;
                if heard_before < AUDIBLE_WANTED {
                    return Err(format!(
                        "only {heard_before} audible frames came back before the move"
                    ));
                }
                println!("{READY} {old_ip}");
                stage = Stage::Waiting;
                since = now;
            }
            Stage::Waiting => {
                let here = route_to(remote);
                if here != old_ip && !here.is_loopback() {
                    let handle = call.ok_or("no call to move")?;
                    move_the_call(
                        &mut endpoint,
                        account,
                        handle,
                        (old_ip, here),
                        (user, remote),
                        now,
                    )?;
                    story.push(format!("moved from {old_ip} to {here}"));
                    new_ip = Some(here);
                    heard_before = audible;
                    stage = Stage::Moved;
                    since = now;
                } else if now > since + MOVE_PATIENCE {
                    return Err(format!(
                        "the address never moved from {old_ip} within {} s",
                        MOVE_PATIENCE.as_secs()
                    ));
                }
            }
            Stage::Moved if answered_after_move && now >= since + AFTER => {
                if let Some(handle) = call {
                    let _ = endpoint.agent.hangup(handle, now);
                }
                stage = Stage::Ending;
                since = now;
            }
            Stage::Moved if now > since + PATIENCE => {
                return Err(format!(
                    "the re-INVITE was never answered [{}]{}",
                    story.join(", "),
                    refused
                        .as_deref()
                        .map_or(String::new(), |why| format!(": {why}"))
                ));
            }
            Stage::Ending if ended || now > since + ENDING => break,
            _ => {}
        }
        if ended && stage != Stage::Ending {
            return Err(format!(
                "the call ended part-way through ({stage:?}) [{}]",
                story.join(", ")
            ));
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    let heard_after = call
        .and_then(|handle| endpoint.media.get(&handle))
        .map_or(0, |media| media.heard().audible)
        .saturating_sub(heard_before);
    crate::join::give_back(&mut endpoint, account);
    if wanted != call.into_iter().collect::<Vec<_>>() {
        return Err(format!(
            "the stack named {wanted:?} to move, not the one call up [{}]",
            story.join(", ")
        ));
    }
    if heard_after < AUDIBLE_WANTED {
        return Err(format!(
            "only {heard_after} audible frames came back after the move [{}]",
            story.join(", ")
        ));
    }
    Ok(format!(
        "   (from {old_ip} to {}; {heard_before} audible frames before the move, {heard_after} \
         after)",
        new_ip.map_or_else(String::new, |ip| ip.to_string())
    ))
}

/// What the application does when the platform says the address changed:
/// the SIP socket bound at the new one and the change reported, the account
/// pointed there, the call's media socket bound there, and the call offered
/// at it.
fn move_the_call(
    endpoint: &mut Endpoint,
    account: sipral::AccountId,
    call: CallHandle,
    (from, to): (IpAddr, IpAddr),
    (user, remote): (&str, SocketAddr),
    now: Instant,
) -> Result<(), String> {
    let sip = endpoint.rebind_sip(to, now)?;
    let recovery = endpoint.agent.network_changed(
        &Network::new(Link::Wired).address(from).resolves(true),
        &Network::new(Link::Wired).address(to).resolves(true),
        now,
    );
    if recovery != Recovery::Rebuild {
        return Err(format!("a new address was taken as {recovery}"));
    }
    let contact = uri(&format!("sip:{user}@{sip}"))?;
    endpoint
        .agent
        .rebind(account, endpoint.transport, remote, &contact, now)
        .map_err(|error| format!("cannot point the account at {sip}: {error}"))?;
    let media = endpoint
        .media
        .get_mut(&call)
        .ok_or("the call has no media socket")?
        .rebind(to)?;
    endpoint
        .engine
        .readdress(&mut endpoint.agent, call, media, None, now)
        .map_err(|error| format!("cannot offer the call at {media}: {error}"))?;
    endpoint.flush();
    Ok(())
}
