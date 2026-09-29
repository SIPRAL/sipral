// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One call, forked by a proxy to two phones behind a NAT, every end on a
//! relay.
//!
//! `scripts/lab.sh turn` runs this in the NAT pair its relay step sets up:
//! the path between the two NATs blocked but for SIP, and coturn a TURN
//! server. Two phones, the desk and the mobile, run in one container behind
//! the second NAT, each with a SIP socket of its own the NAT forwards
//! (`PHONE_PORTS`), registered at Kamailio as the one user
//! `interop/kamailio/kamailio.cfg` forks. The caller runs behind the first
//! NAT and calls that user through the proxy, which relays the INVITE to
//! both phones at once. Every end asks coturn where its media socket
//! appears from and allocates a relay there before the call
//! (`crate::ice_nat`), and every end requires ICE: with the NATs dropping
//! everything between them, a path has to go through the relay at one end
//! or the other.
//!
//! Both phones ring with media — a 183 carrying the answer, the session
//! open on it — so both branches run ICE and carry the tone both ways
//! before anybody answers. The caller's one offer named one relayed
//! candidate, and the two branches hold it together (RFC 8656 §1 lets one
//! relayed address serve many peers, and RFC 8839 §7 runs each answer as an
//! ICE session of its own). Once both branches have chosen a path and each
//! phone has heard the caller on its own, the mobile answers; the proxy cancels the desk, and the caller
//! keeps the mobile's branch and hangs up after a while. Every relay goes
//! back to coturn when the last branch holding it ends, which the lab reads
//! off coturn's own log.

use std::env;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sipral::{
    Account, CallEndReason, CallHandle, CallMedia, Credentials, Event, IcePolicy, MediaConfig,
    MediaEvent, OutgoingCall, UaEvent,
};

use crate::audio::Media;
use crate::fork::{FORK_PASS, FORK_USER};
use crate::ice_nat::{Allocated, mapped_media, stun_server, turn_server, with_relay};
use crate::join::give_back;
use crate::{Endpoint, catalog, route_to, run_folded, uri};

/// How long the phones wait for the proxy to take both registrations: it
/// answers a REGISTER within a round trip or two, and a challenge doubles
/// that.
const REGISTER_PATIENCE: Duration = Duration::from_secs(15);

/// How long the phones wait for the call, from the moment both are
/// registered.
const CALL_PATIENCE: Duration = Duration::from_secs(60);

/// How long the call may take from the INVITE to the end of the kept
/// branch: ICE on two branches, the early media, the answer and the dwell.
const PATIENCE: Duration = Duration::from_secs(40);

/// How long the phones wait for each other to have heard the caller before
/// the mobile answers anyway, so that a branch without media is reported
/// rather than waited on forever.
const ANSWER_BY: Duration = Duration::from_secs(20);

/// How long the kept call stays up once it is answered.
const DWELL: Duration = Duration::from_secs(3);

/// Audible frames of the tone each end of each branch has to hear before
/// the answer: a fifth of a second.
const EARLY_WANTED: u32 = 10;

/// The two phones' SIP ports, each forwarded by the NAT in front of them
/// from the same port on its outside address (`SIPRAL_CONTACT`), which is
/// what each registers as its contact.
pub(crate) const PHONE_PORTS: [u16; 2] = [5060, 5062];

/// This flow's own endpoint identity constants, each folded with the run's
/// own entropy before anything binds with it (`run_folded`, `main.rs`).
/// Listed in `main.rs`'s `tests::endpoint_identity_constants_are_distinct`
/// alongside every other step's.
pub(crate) const CALLER_SEED: u8 = 30;
pub(crate) const CALLER_MEDIA_SEED: u8 = 31;
pub(crate) const CALLER_RELAY_SEED: u8 = 32;
pub(crate) const DESK_SEED: u8 = 33;
pub(crate) const DESK_MEDIA_SEED: u8 = 34;
pub(crate) const DESK_RELAY_SEED: u8 = 35;
pub(crate) const MOBILE_SEED: u8 = 36;
pub(crate) const MOBILE_MEDIA_SEED: u8 = 37;
pub(crate) const MOBILE_RELAY_SEED: u8 = 38;

/// Every path a call's agent tried and what became of it, on one line.
fn paths_of(session: &sipral::MediaSession) -> String {
    let tried: Vec<String> = session
        .path_candidates()
        .iter()
        .map(|path| {
            let local = path
                .local
                .map_or_else(|| "?".to_owned(), |address| address.to_string());
            format!(
                "{:?} {local} -> {} {:?}",
                path.kind, path.remote, path.outcome
            )
        })
        .collect();
    if tried.is_empty() {
        "no path was tried".to_owned()
    } else {
        format!("paths tried: {}", tried.join(", "))
    }
}

/// Whether a path chosen as `local` -> `remote` goes through the TURN server
/// at `server`: from this end's relayed address, or to the far end's.
fn through(server: IpAddr, (local, remote): (SocketAddr, SocketAddr)) -> bool {
    local.ip() == server || remote.ip() == server
}

/// The TURN server's address, which every path has to go through.
///
/// # Errors
/// When none is named: without a relay the flow proves nothing.
fn relay_server() -> Result<IpAddr, String> {
    turn_server()?
        .map(|(server, ..)| server.ip())
        .ok_or_else(|| {
            "SIPRAL_TURN_SERVER names no TURN server, and every end needs one".to_owned()
        })
}

/// One of the two phones.
struct Phone {
    name: &'static str,
    endpoint: Endpoint,
    account: sipral::AccountId,
    registered: bool,
    /// The media socket, its address for the call, its mapped one and the
    /// relay allocated for it, until the call arrives and they are handed
    /// to it.
    waiting: Option<(Media, SocketAddr, SocketAddr, Allocated)>,
    local: Option<SocketAddr>,
    call: Option<CallHandle>,
    chosen: Option<(SocketAddr, SocketAddr)>,
    /// What became of every path the branch's agent tried, as of the last
    /// turn: what a branch that chose none is reported with.
    paths: String,
    failed: Option<String>,
    /// The caller's tone heard on this branch when the mobile answered.
    early: Option<u32>,
    confirmed: bool,
    ended: Option<CallEndReason>,
}

impl Phone {
    fn heard(&self) -> u32 {
        self.call
            .and_then(|call| self.endpoint.media.get(&call))
            .map_or(0, |media| media.heard().audible)
    }

    fn turn(&mut self, now: Instant) {
        for event in self.endpoint.pump(now) {
            self.on_event(&event, now);
        }
        self.endpoint.run_media(now);
        if let Some(call) = self.call
            && let Some(session) = self.endpoint.engine.session(call)
        {
            self.paths = paths_of(&session);
        }
        self.endpoint.timers(now);
        self.endpoint.flush();
    }

    fn on_event(&mut self, event: &Event, now: Instant) {
        match event {
            Event::Signalling(UaEvent::Registered { .. }) => self.registered = true,
            Event::Signalling(UaEvent::IncomingCall { call, .. }) if self.call.is_none() => {
                self.call = Some(*call);
                self.ring(*call, now);
            }
            Event::Signalling(UaEvent::CallConfirmed { call, .. }) if Some(*call) == self.call => {
                self.confirmed = true;
            }
            Event::Signalling(UaEvent::CallEnded { call, reason, .. })
                if Some(*call) == self.call =>
            {
                self.ended = Some(*reason);
            }
            Event::Media {
                call,
                event: MediaEvent::PathChosen { local, remote },
            } if Some(*call) == self.call && self.chosen.is_none() => {
                self.chosen = Some((*local, *remote));
            }
            Event::Media {
                call,
                event: MediaEvent::Failed(error),
            } if Some(*call) == self.call => self.failed = Some(error.to_string()),
            _ => {}
        }
    }

    /// Ring with media: the answer in a 183, and the session open on it.
    fn ring(&mut self, call: CallHandle, now: Instant) {
        let Some((media, local, public, relayed)) = self.waiting.take() else {
            return;
        };
        let required = catalog().with_ice(IcePolicy::Required);
        let (described, _) = with_relay(
            CallMedia::new(required, MediaConfig::default()).public_address(public),
            relayed,
        );
        self.endpoint.media.insert(call, media);
        self.local = Some(local);
        if let Err(error) =
            self.endpoint
                .engine
                .ring_with(&mut self.endpoint.agent, call, local, described, now)
        {
            self.failed = Some(format!("could not ring with media: {error}"));
        }
    }

    fn answer(&mut self, now: Instant) {
        let (Some(call), Some(local)) = (self.call, self.local) else {
            return;
        };
        if let Err(error) = self
            .endpoint
            .engine
            .answer(&mut self.endpoint.agent, call, local, now)
        {
            self.failed = Some(format!("could not answer: {error}"));
        }
    }
}

/// The phones' side: register both at the proxy, ring both with media when
/// the forked call arrives, have the mobile answer once both have heard the
/// caller, and judge what each saw.
///
/// # Errors
/// The first condition that did not hold, named.
#[allow(clippy::too_many_lines)]
pub(crate) fn answer(proxy: SocketAddr) -> Result<String, String> {
    let stun = stun_server()?;
    let server = relay_server()?;
    let contact = env::var("SIPRAL_CONTACT")
        .map_err(|_| "SIPRAL_CONTACT does not name the NAT's outside address".to_owned())?;
    let now = Instant::now();
    let phone = |name, port: u16, seeds: [u8; 3]| -> Result<Phone, String> {
        let mut endpoint = Endpoint::bind(
            run_folded([seeds[0]; 32]),
            run_folded([seeds[1]; 32]),
            SocketAddr::new(route_to(proxy), port),
            catalog().with_ice(IcePolicy::Required),
            now,
        )
        .map_err(|error| format!("cannot bind the {name}: {error}"))?;
        let aor = uri(&format!("sip:{FORK_USER}@kamailio"))?;
        let account = endpoint.agent.add_account(
            Account::new(
                aor,
                uri("sip:kamailio")?,
                uri(&format!("sip:{FORK_USER}@{contact}:{port}"))?,
                endpoint.transport,
                proxy,
            )
            .credentials(Credentials::new(FORK_USER, FORK_PASS))
            .expires(Duration::from_secs(300)),
        );
        let waiting = mapped_media(stun, stun, run_folded([seeds[2]; 32]))
            .map_err(|error| format!("the {name}: {error}"))?;
        Ok(Phone {
            name,
            endpoint,
            account,
            registered: false,
            waiting: Some(waiting),
            local: None,
            call: None,
            chosen: None,
            paths: String::new(),
            failed: None,
            early: None,
            confirmed: false,
            ended: None,
        })
    };
    let [desk_port, mobile_port] = PHONE_PORTS;
    // the desk never answers, and the mobile does: the second of the two.
    // Each boxed: a phone holds a whole engine, and two side by side are more
    // than a stack frame should carry
    let mut phones = [
        Box::new(phone(
            "desk",
            desk_port,
            [DESK_SEED, DESK_MEDIA_SEED, DESK_RELAY_SEED],
        )?),
        Box::new(phone(
            "mobile",
            mobile_port,
            [MOBILE_SEED, MOBILE_MEDIA_SEED, MOBILE_RELAY_SEED],
        )?),
    ];
    for phone in &mut phones {
        let _ = phone.endpoint.agent.register(phone.account, Instant::now());
    }

    let started = Instant::now();
    let mut announced = None;
    let mut rang = None;
    let mut answered = false;
    loop {
        let now = Instant::now();
        for phone in &mut phones {
            phone.turn(now);
        }
        if announced.is_none() && phones.iter().all(|phone| phone.registered) {
            announced = Some(now);
            println!(
                "waiting for the call: the desk at {contact}:{desk_port}, the mobile at \
                 {contact}:{mobile_port}"
            );
            let _ = std::io::stdout().flush();
        }
        if rang.is_none() && phones.iter().any(|phone| phone.call.is_some()) {
            rang = Some(now);
        }
        // the mobile picks up once both branches have settled on a path and
        // the caller has been heard on each, or once waiting for that is no
        // longer worth it. Early media flows on a valid pair before one is
        // nominated (RFC 8445 §12.1), so hearing the caller alone would let
        // the desk's branch end before its agent had chosen anything
        let settled = phones
            .iter()
            .all(|phone| phone.chosen.is_some() && phone.heard() >= EARLY_WANTED);
        let late = rang.is_some_and(|at| now > at + ANSWER_BY);
        if !answered && phones.iter().all(|phone| phone.call.is_some()) && (settled || late) {
            answered = true;
            for phone in &mut phones {
                phone.early = Some(phone.heard());
            }
            phones[1].answer(now);
        }
        if phones.iter().all(|phone| phone.ended.is_some()) {
            break;
        }
        match (announced, rang) {
            (None, _) if now > started + REGISTER_PATIENCE => {
                return Err(phones_unregistered(&phones));
            }
            (Some(at), None) if now > at + CALL_PATIENCE => {
                return Err("no call arrived at either phone".to_owned());
            }
            (_, Some(at)) if now > at + PATIENCE => break,
            _ => {}
        }
        let read = [
            phones[0].endpoint.read_sip(Instant::now()),
            phones[1].endpoint.read_sip(Instant::now()),
        ];
        if !read.contains(&true) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    // the farewells, the relay's own deletion among them, before the
    // bindings are given back
    for phone in &mut phones {
        phone.turn(Instant::now());
    }
    let verdict = phones_verdict(&phones, server);
    for phone in &mut phones {
        let account = phone.account;
        give_back(&mut phone.endpoint, account);
    }
    verdict
}

fn phones_unregistered(phones: &[Box<Phone>; 2]) -> String {
    let names: Vec<&str> = phones
        .iter()
        .filter(|phone| !phone.registered)
        .map(|phone| phone.name)
        .collect();
    format!(
        "the proxy never took the {}'s registration",
        names.join(" and the ")
    )
}

/// What the phones proved, or the first thing they did not.
fn phones_verdict(phones: &[Box<Phone>; 2], server: IpAddr) -> Result<String, String> {
    let mut said = Vec::new();
    for phone in phones {
        if let Some(why) = &phone.failed {
            return Err(format!("the {}: {why}", phone.name));
        }
        if phone.call.is_none() {
            return Err(format!(
                "the proxy never forked the call to the {}",
                phone.name
            ));
        }
        let Some(chosen) = phone.chosen else {
            return Err(format!(
                "the {}'s branch never chose a path; {}",
                phone.name, phone.paths
            ));
        };
        if !through(server, chosen) {
            return Err(format!(
                "the {}'s path {} -> {} does not go through the TURN server at {server}",
                phone.name, chosen.0, chosen.1
            ));
        }
        let early = phone.early.unwrap_or(0);
        if early < EARLY_WANTED {
            return Err(format!(
                "the {} heard {early} audible frames of the caller before the answer",
                phone.name
            ));
        }
        said.push(format!(
            "the {} on {} -> {}, {early} audible before the answer",
            phone.name, chosen.0, chosen.1
        ));
    }
    let [desk, mobile] = phones;
    if desk.ended != Some(CallEndReason::Cancelled) {
        return Err(format!(
            "the desk never saw the proxy's CANCEL: it ended {:?}",
            desk.ended
        ));
    }
    if !mobile.confirmed {
        return Err("the mobile's answer was never acknowledged".to_owned());
    }
    if mobile.ended != Some(CallEndReason::RemoteHangup) {
        return Err(format!(
            "the call did not last until the caller hung up: the mobile's ended {:?}",
            mobile.ended
        ));
    }
    Ok(format!("   ({}; the desk cancelled)", said.join("; ")))
}

/// One branch of the forked call, as the caller sees it.
#[derive(Default)]
struct Branch {
    chosen: Option<(SocketAddr, SocketAddr)>,
    /// What became of every path the branch's agent tried, as of the last
    /// turn.
    paths: String,
    failed: Option<String>,
    /// The phone's tone heard on this branch when the call was answered.
    early: Option<u32>,
    ended: Option<CallEndReason>,
}

/// The caller's side: map and relay the media socket, call the forked user
/// through the proxy, carry both branches' early media on the one socket,
/// keep the branch that answers, and judge both.
///
/// # Errors
/// The first condition that did not hold, named.
#[allow(clippy::too_many_lines)]
pub(crate) fn call(proxy: SocketAddr) -> Result<String, String> {
    let stun = stun_server()?;
    let server = relay_server()?;
    let required = catalog().with_ice(IcePolicy::Required);
    let mut endpoint = Endpoint::bind(
        run_folded([CALLER_SEED; 32]),
        run_folded([CALLER_MEDIA_SEED; 32]),
        SocketAddr::new(route_to(proxy), 0),
        required.clone(),
        Instant::now(),
    )?;
    let identity = uri(&format!("sip:caller@{}", endpoint.local))?;
    let account = endpoint.agent.add_account(Account::unregistered(
        identity.clone(),
        identity,
        endpoint.transport,
        proxy,
    ));
    let (media, local, public, relayed) =
        mapped_media(proxy, stun, run_folded([CALLER_RELAY_SEED; 32]))?;
    let (described, allocated) = with_relay(
        CallMedia::new(required, MediaConfig::default()).public_address(public),
        relayed,
    );
    let outgoing = OutgoingCall::new(uri(&format!("sip:{FORK_USER}@kamailio"))?)
        .to_address(endpoint.transport, proxy);
    let offered = Instant::now();
    let placed = endpoint
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
    endpoint.media.insert(placed, media);
    let mut branches: Vec<(CallHandle, Branch)> = vec![(placed, Branch::default())];
    let mut kept: Option<CallHandle> = None;
    let mut hang_up_at: Option<Instant> = None;
    let mut story = Vec::new();

    loop {
        let now = Instant::now();
        let at = now.saturating_duration_since(offered).as_millis();
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::CallProgress { call, state, .. }) => {
                    story.push(format!("{at} ms {call:?} {state:?}"));
                }
                Event::Media {
                    call,
                    event: MediaEvent::Started { .. },
                } => story.push(format!("{at} ms {call:?} media")),
                Event::Signalling(UaEvent::CallForked { sibling, .. }) => {
                    story.push(format!("{at} ms forked to {sibling:?}"));
                    let shared = endpoint
                        .media
                        .get_mut(&placed)
                        .map(|media| media.share(now));
                    match shared {
                        Some(Ok(media)) => {
                            endpoint.media.insert(sibling, media);
                            branches.push((sibling, Branch::default()));
                        }
                        Some(Err(why)) => return Err(why),
                        None => return Err("the call placed has no media socket".to_owned()),
                    }
                }
                Event::Signalling(UaEvent::CallConfirmed { call, .. }) if kept.is_none() => {
                    story.push(format!("{at} ms {call:?} confirmed"));
                    kept = Some(call);
                    hang_up_at = Some(now + DWELL);
                    for (branch, seen) in &mut branches {
                        seen.early = Some(
                            endpoint
                                .media
                                .get(branch)
                                .map_or(0, |media| media.heard().audible),
                        );
                    }
                }
                Event::Signalling(UaEvent::CallEnded { call, reason, .. }) => {
                    story.push(format!("{at} ms {call:?} ended {reason}"));
                    if let Some((_, seen)) = branches.iter_mut().find(|(ours, _)| *ours == call) {
                        seen.ended = Some(reason);
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::PathChosen { local, remote },
                } => {
                    story.push(format!("{at} ms {call:?} path {local} -> {remote}"));
                    if let Some((_, seen)) = branches
                        .iter_mut()
                        .find(|(ours, seen)| *ours == call && seen.chosen.is_none())
                    {
                        seen.chosen = Some((local, remote));
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::Failed(error),
                } => {
                    if let Some((_, seen)) = branches.iter_mut().find(|(ours, _)| *ours == call) {
                        seen.failed = Some(error.to_string());
                    }
                }
                _ => {}
            }
        }
        // each branch's own capture and earpiece; the socket they share is
        // read once below, and the engine says whose each datagram is
        for call in endpoint.engine.active().collect::<Vec<_>>() {
            let Some(mut session) = endpoint.engine.session(call) else {
                continue;
            };
            if let Some(media) = endpoint.media.get_mut(&call) {
                media.turn(&mut session, now);
            }
            if let Some((_, seen)) = branches.iter_mut().find(|(ours, _)| *ours == call) {
                seen.paths = paths_of(&session);
            }
        }
        if let Some(media) = endpoint.media.get_mut(&placed) {
            media.receive_early(&mut endpoint.engine, local, now);
        }
        send_queued(&mut endpoint, placed, now);
        if let Some(due) = hang_up_at
            && now >= due
            && let Some(call) = kept
        {
            hang_up_at = None;
            let _ = endpoint.agent.hangup(call, now);
        }
        endpoint.timers(now);
        let over = branches.iter().all(|(_, seen)| seen.ended.is_some());
        if over || now > offered + PATIENCE {
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    // the farewells, the relay's own deletion among them
    let now = Instant::now();
    let _ = endpoint.pump(now);
    send_queued(&mut endpoint, placed, now);
    endpoint.flush();
    let judged: Vec<(bool, &Branch)> = branches
        .iter()
        .map(|(call, seen)| (Some(*call) == kept, seen))
        .collect();
    caller_verdict(&judged, server, &story.join(", "))
        .map(|said| format!("{said}; this end at {local}, mapped to {public}{allocated}"))
}

/// Send everything the engine queued for the socket the branches share:
/// what their sessions and agents wrote, and the farewells.
fn send_queued(endpoint: &mut Endpoint, placed: CallHandle, now: Instant) {
    let mut out = Vec::new();
    while let Some((_, destination, payload)) = endpoint.engine.poll_rtcp(now) {
        out.push((destination, payload));
    }
    while let Some((_, destination, payload)) = endpoint.engine.poll_farewell() {
        out.push((destination, payload));
    }
    while let Some((_, destination, payload)) = endpoint.engine.poll_transmit(now) {
        out.push((destination, payload));
    }
    while let Some((_, datagram)) = endpoint.engine.poll_waiting_transmit() {
        out.push((datagram.destination, datagram.payload));
    }
    if let Some(media) = endpoint.media.get(&placed) {
        for (destination, payload) in out {
            media.send(destination, &payload);
        }
    }
}

/// What the caller proved, or the first thing it did not: `branches` is
/// every branch it saw, each with whether it is the one kept.
fn caller_verdict(
    branches: &[(bool, &Branch)],
    server: IpAddr,
    story: &str,
) -> Result<String, String> {
    if branches.len() < 2 {
        return Err(format!("the caller saw one branch, not a fork [{story}]"));
    }
    if !branches.iter().any(|(kept, _)| *kept) {
        return Err(format!("no branch was answered [{story}]"));
    }
    let mut said = Vec::new();
    for (kept, seen) in branches {
        let name = if *kept {
            "the branch kept"
        } else {
            "the branch lost"
        };
        if let Some(why) = &seen.failed {
            return Err(format!("{name}'s media failed: {why} [{story}]"));
        }
        let Some(chosen) = seen.chosen else {
            return Err(format!(
                "{name} never chose a path; {} [{story}]",
                seen.paths
            ));
        };
        if !through(server, chosen) {
            return Err(format!(
                "{name}'s path {} -> {} does not go through the TURN server at {server}",
                chosen.0, chosen.1
            ));
        }
        let early = seen.early.unwrap_or(0);
        if early < EARLY_WANTED {
            return Err(format!(
                "{name} carried {early} audible frames before the answer [{story}]"
            ));
        }
        if !*kept && seen.ended != Some(CallEndReason::ForkLost) {
            return Err(format!(
                "{name} did not end as a fork lost: {:?} [{story}]",
                seen.ended
            ));
        }
        said.push(format!(
            "{name} on {} -> {}, {early} audible before the answer",
            chosen.0, chosen.1
        ));
    }
    Ok(format!("   ({})", said.join("; ")))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use sipral::CallEndReason;

    use super::{Branch, EARLY_WANTED, caller_verdict, through};

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    fn server() -> IpAddr {
        "172.30.0.9".parse().expect("an address")
    }

    /// A branch that chose a path from this end's relay, heard the phone
    /// before the answer, and ended as `ended`.
    fn relayed(ended: CallEndReason) -> Branch {
        Branch {
            chosen: Some((address("172.30.0.9:49160"), address("172.30.0.3:40000"))),
            paths: String::new(),
            failed: None,
            early: Some(EARLY_WANTED),
            ended: Some(ended),
        }
    }

    #[test]
    fn a_path_goes_through_the_relay_at_either_end_or_not_at_all() {
        let near = (address("172.30.0.9:49160"), address("172.30.0.3:40000"));
        let far = (address("172.30.0.2:40000"), address("172.30.0.9:49170"));
        let neither = (address("172.30.0.2:40000"), address("172.30.0.3:40000"));
        assert!(through(server(), near));
        assert!(through(server(), far));
        assert!(!through(server(), neither));
    }

    /// Both branches relayed and heard before the answer, the one not kept
    /// lost to the fork: the flow holds.
    #[test]
    fn both_branches_relayed_and_heard_before_the_answer_pass() {
        let kept = relayed(CallEndReason::LocalHangup);
        let lost = relayed(CallEndReason::ForkLost);
        let said =
            caller_verdict(&[(false, &lost), (true, &kept)], server(), "").expect("the fork held");
        assert!(
            said.contains("the branch kept") && said.contains("the branch lost"),
            "{said}"
        );
    }

    /// Every way a branch falls short fails the flow, and says which branch.
    #[test]
    fn a_branch_that_falls_short_fails_and_is_named() {
        let kept = relayed(CallEndReason::LocalHangup);
        let judge =
            |branch: &Branch| caller_verdict(&[(false, branch), (true, &kept)], server(), "");

        let mut quiet = relayed(CallEndReason::ForkLost);
        quiet.early = Some(EARLY_WANTED - 1);
        let why = judge(&quiet).expect_err("no early media on it");
        assert!(
            why.contains("the branch lost") && why.contains("before the answer"),
            "{why}"
        );

        let mut direct = relayed(CallEndReason::ForkLost);
        direct.chosen = Some((address("172.30.0.2:40000"), address("172.30.0.3:40000")));
        let why = judge(&direct).expect_err("the path went round the relay");
        assert!(why.contains("does not go through the TURN server"), "{why}");

        let mut unpathed = relayed(CallEndReason::ForkLost);
        unpathed.chosen = None;
        let why = judge(&unpathed).expect_err("no path");
        assert!(why.contains("never chose a path"), "{why}");

        let cancelled = relayed(CallEndReason::Cancelled);
        let why = judge(&cancelled).expect_err("not lost to the fork");
        assert!(why.contains("did not end as a fork lost"), "{why}");

        let why = caller_verdict(&[(true, &kept)], server(), "").expect_err("one branch");
        assert!(why.contains("not a fork"), "{why}");
        let lost = relayed(CallEndReason::ForkLost);
        let why = caller_verdict(&[(false, &lost), (false, &lost)], server(), "")
            .expect_err("nobody answered");
        assert!(why.contains("no branch was answered"), "{why}");
    }
}
