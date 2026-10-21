// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Trickle ICE (RFC 8838) between two stacks through the lab's proxy, each
//! behind a NAT of its own, and half trickle against an Asterisk that does
//! not trickle.
//!
//! `scripts/lab.sh trickle` reuses the NAT pair of the full-ICE step
//! (`crate::ice_nat`): the caller behind `interop/nat`'s NAT on `inside`,
//! the callee behind the second one on `inside2`, coturn on the lab network
//! between them, and Kamailio there too. The callee registers at Kamailio as
//! `trickle` through its NAT, which forwards its SIP port; the caller calls
//! that user through the proxy, which record-routes, so the INFO requests
//! that carry the candidates (RFC 8840 §4.4) cross it inside the dialog the
//! way the ACK and the BYE do.
//!
//! What makes trickle worth measuring is a slow server, and every end here
//! has one: it asks coturn and a second STUN server that never answers at
//! once, as a phone with a backup server does — RFC 8838 Appendix A's own
//! example. Gathering is over only when the silent one has been given up on,
//! five and a half seconds in (`sipral::Mappings`). Under `SIPRAL_TRICKLE`:
//!
//! - **`off`**, each end waits for its gathering to finish before it writes
//!   its description, the reflexive address coturn gave in it.
//! - **`half`**, the same wait and the same description, which also says
//!   `trickle`; a far end that trickles may then send its own later.
//! - **`full`**, each end writes its description at once, with its host
//!   candidate alone, and trickles the reflexive one in an INFO the moment
//!   coturn answers, and the end of its candidates once the silent server is
//!   given up on.
//!
//! Neither host candidate reaches the other end, so the call has a path only
//! once both reflexive candidates are known at both ends. Each end prints
//! when its description went, when the call was answered, when a path was
//! chosen and when its own gathering finished, all from the moment it was
//! dialled or rang; under `full` the path has to be chosen before gathering
//! finishes, which is the whole claim, and the tone has to cross it both
//! ways.
//!
//! The Asterisk step (`asterisk`) is half trickle against a peer that does
//! not trickle: an offer that says `trickle` and is whole, from the account
//! `interop/ice/pjsip_local.conf` gives ICE, to the echo; Asterisk answers
//! regular ICE, no INFO goes, and the echo of the tone comes back on the pair
//! its checks and this end's chose.

use std::env;
use std::io::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CallMedia, Credentials, Event, IcePolicy, IceTrickle, Keep, MappingEvent,
    Mappings, MediaConfig, MediaEvent, OutgoingCall, UaEvent,
};

use crate::audio::Media;
use crate::ice_lite::{Seen, verdict};
use crate::ice_nat::stun_server;
use crate::{Endpoint, catalog, route_to, run_folded, uri};

/// How long a call may take from the moment it was dialled: the silent
/// server's five and a half seconds twice over for regular ICE, ICE itself,
/// and the dwell.
const PATIENCE: Duration = Duration::from_secs(40);

/// How long the call stays up once a path is chosen.
const DWELL: Duration = Duration::from_secs(3);

/// How long the callee waits for its registration, and then for the call.
const REGISTER_PATIENCE: Duration = Duration::from_secs(15);
const CALL_PATIENCE: Duration = Duration::from_secs(90);

/// The user the callee registers as, which `interop/kamailio/kamailio.cfg`
/// looks up.
const TRICKLE_USER: &str = "trickle";
const TRICKLE_PASS: &str = "tricklepass";

/// The account Asterisk gives ICE, and the extension that echoes.
const ASTERISK_USER: &str = "labuser-agent-ice";
const ECHO: &str = "9008";

/// This flow's own endpoint identity constants, each folded with the run's
/// own entropy before anything binds with it (`run_folded`, `main.rs`).
/// Listed in `main.rs`'s `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const CALLER_SEED: u8 = 44;
pub(crate) const CALLER_MEDIA_SEED: u8 = 45;
pub(crate) const ANSWER_SEED: u8 = 46;
pub(crate) const ANSWER_MEDIA_SEED: u8 = 50;
pub(crate) const ASTERISK_SEED: u8 = 48;
pub(crate) const ASTERISK_MEDIA_SEED: u8 = 49;

/// The stance both ends take, from `SIPRAL_TRICKLE`.
///
/// # Errors
/// Anything but `off`, `half` and `full`.
fn stance() -> Result<IceTrickle, String> {
    match env::var("SIPRAL_TRICKLE").as_deref() {
        Ok("off") => Ok(IceTrickle::Off),
        Ok("half") => Ok(IceTrickle::Half),
        Ok("full") => Ok(IceTrickle::Full),
        Ok(other) => Err(format!(
            "SIPRAL_TRICKLE is {other:?}, and it is off, half or full"
        )),
        Err(_) => Err("SIPRAL_TRICKLE names no stance".to_owned()),
    }
}

/// The STUN server nobody answers from, from `SIPRAL_STUN_SILENT`.
///
/// # Errors
/// When it names no address.
fn silent_server() -> Result<SocketAddr, String> {
    env::var("SIPRAL_STUN_SILENT")
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| "SIPRAL_STUN_SILENT does not name an address".to_owned())
}

/// Whether a stance writes the description before gathering is over.
const fn at_once(trickle: IceTrickle) -> bool {
    matches!(trickle, IceTrickle::Full)
}

/// What gathering on a media socket came to.
enum Gathered {
    /// A server said where the socket appears from outside.
    Learned(SocketAddr),
    /// Every server has answered or been given up on.
    Finished,
}

/// Gathering on one media socket from several STUN servers at once.
struct Gathering {
    asked: Vec<(SocketAddr, Mappings)>,
    local: SocketAddr,
    open: usize,
    public: Option<SocketAddr>,
    started: Instant,
    learned_at: Option<Duration>,
    finished_at: Option<Duration>,
}

impl Gathering {
    fn start(local: SocketAddr, servers: &[SocketAddr], seed: [u8; 32], now: Instant) -> Self {
        let asked = servers
            .iter()
            .enumerate()
            .map(|(index, server)| {
                let mut own = seed;
                own[0] ^= u8::try_from(index).unwrap_or(0).wrapping_add(1);
                let mut mappings = Mappings::new(*server, own);
                mappings.map(local, Keep::Once, now);
                (*server, mappings)
            })
            .collect::<Vec<_>>();
        Self {
            open: asked.len(),
            asked,
            local,
            public: None,
            started: now,
            learned_at: None,
            finished_at: None,
        }
    }

    const fn finished(&self) -> bool {
        self.finished_at.is_some()
    }

    /// Send what is due from `media`, take what the servers sent it, and
    /// say what came of it.
    fn turn(&mut self, media: &mut Media, now: Instant) -> Vec<Gathered> {
        for (from, data) in media.take_intercepted() {
            if let Some((_, mappings)) = self.asked.iter_mut().find(|(server, _)| *server == from) {
                let _ = mappings.receive(self.local, from, &data, now);
            }
        }
        let mut said = Vec::new();
        for (_, mappings) in &mut self.asked {
            if mappings.poll_timeout().is_some_and(|due| due <= now) {
                mappings.handle_timeout(now);
            }
            while let Some(datagram) = mappings.poll_transmit() {
                media.send(datagram.destination, &datagram.payload);
            }
            while let Some(event) = mappings.poll_event() {
                match event {
                    MappingEvent::Learned { public, .. } => {
                        self.open = self.open.saturating_sub(1);
                        if self.public.is_none() {
                            self.public = Some(public);
                            self.learned_at = Some(now.saturating_duration_since(self.started));
                            said.push(Gathered::Learned(public));
                        }
                    }
                    MappingEvent::Unanswered { .. } => self.open = self.open.saturating_sub(1),
                    _ => {}
                }
            }
        }
        if self.open == 0 && self.finished_at.is_none() {
            self.finished_at = Some(now.saturating_duration_since(self.started));
            said.push(Gathered::Finished);
        }
        said
    }
}

/// One end of the call, as it drives it.
struct End {
    endpoint: Endpoint,
    trickle: IceTrickle,
    catalog: sipral::CodecCatalog,
    gathering: Gathering,
    /// The media socket, until the call it is for exists.
    waiting: Option<Media>,
    local: SocketAddr,
    call: Option<CallHandle>,
    /// When the description went, from the moment the end was dialled or
    /// rang.
    described_at: Option<Duration>,
    seen: Seen,
    /// Bodies of trickled candidates the far end sent.
    trickled_in: u32,
    /// Candidates and ends of candidates this end handed its call to send.
    trickled_out: u32,
    hung_up: bool,
    story: Vec<String>,
}

impl End {
    fn new(
        endpoint: Endpoint,
        trickle: IceTrickle,
        servers: &[SocketAddr],
        seed: [u8; 32],
        toward: SocketAddr,
        now: Instant,
    ) -> Result<Self, String> {
        let mut media = Media::bind(now)?;
        media.intercept(servers);
        let local = SocketAddr::new(route_to(toward), media.port()?);
        Ok(Self {
            endpoint,
            trickle,
            catalog: catalog()
                .with_ice(IcePolicy::Required)
                .with_ice_trickle(trickle),
            gathering: Gathering::start(local, servers, seed, now),
            waiting: Some(media),
            local,
            call: None,
            described_at: None,
            seen: Seen::default(),
            trickled_in: 0,
            trickled_out: 0,
            hung_up: false,
            story: Vec::new(),
        })
    }

    /// The description this end writes, now: what gathering has learned so
    /// far, which under a stance that waits is all of it.
    fn media(&self) -> CallMedia {
        let media = CallMedia::new(self.catalog.clone(), MediaConfig::default());
        match self.gathering.public {
            Some(public) => media.public_address(public),
            None => media,
        }
    }

    /// Whether this end may write its description now.
    const fn may_describe(&self) -> bool {
        at_once(self.trickle) || self.gathering.finished()
    }

    fn since(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.gathering.started)
    }

    /// One turn: gathering, signalling, media, and the trickling that joins
    /// them.
    fn turn(&mut self, now: Instant, ends_it: bool) {
        let gathered = match (self.call, self.waiting.as_mut()) {
            (_, Some(media)) => {
                media.receive_waiting(&mut self.endpoint.engine, self.local, now);
                self.gathering.turn(media, now)
            }
            (Some(call), None) => match self.endpoint.media.get_mut(&call) {
                Some(media) => {
                    // a call whose session is not open yet reads its socket here
                    if self.endpoint.engine.session(call).is_none() {
                        media.receive_waiting(&mut self.endpoint.engine, self.local, now);
                    }
                    self.gathering.turn(media, now)
                }
                None => Vec::new(),
            },
            (None, None) => Vec::new(),
        };
        for what in gathered {
            self.gathered(&what, now);
        }
        for event in self.endpoint.pump(now) {
            self.note(&event, now);
        }
        self.endpoint.run_media(now);
        self.endpoint.timers(now);
        if let Some((_, _, after)) = self.seen.chosen
            && ends_it
            && !self.hung_up
            && now >= self.gathering.started + after + DWELL
            && let Some(call) = self.call
        {
            self.hung_up = true;
            let _ = self.endpoint.agent.hangup(call, now);
        }
        self.endpoint.flush();
    }

    /// Hand the call what gathering learned after its description went.
    fn gathered(&mut self, what: &Gathered, now: Instant) {
        let at = self.since(now).as_millis();
        let (Some(call), true) = (self.call, at_once(self.trickle)) else {
            if let Gathered::Learned(public) = what {
                self.story.push(format!("{at} ms mapped to {public}"));
            }
            return;
        };
        let handed = match what {
            Gathered::Learned(public) => {
                self.story
                    .push(format!("{at} ms mapped to {public}, trickled"));
                self.endpoint.engine.trickle_public_address(
                    &mut self.endpoint.agent,
                    call,
                    *public,
                    now,
                )
            }
            Gathered::Finished => {
                self.story
                    .push(format!("{at} ms gathering over, end of candidates"));
                self.endpoint
                    .engine
                    .end_of_candidates(&mut self.endpoint.agent, call, now)
            }
        };
        match handed {
            Ok(()) => self.trickled_out += 1,
            // a pair already nominated: nothing more is trickled (RFC 8838
            // §13), which is a call that no longer needs it
            Err(error) => self.story.push(format!("{at} ms not trickled: {error}")),
        }
    }

    fn note(&mut self, event: &Event, now: Instant) {
        let since = self.since(now);
        let Some(call) = self.call else {
            return;
        };
        match event {
            Event::Signalling(UaEvent::CallConfirmed { call: which, .. })
                if *which == call && self.seen.confirmed.is_none() =>
            {
                self.seen.confirmed = Some(since);
            }
            Event::Signalling(UaEvent::CallEnded { call: which, .. }) if *which == call => {
                self.seen.ended = true;
            }
            Event::Signalling(UaEvent::TrickleIce { call: which, .. }) if *which == call => {
                self.trickled_in += 1;
                self.story
                    .push(format!("{} ms candidates trickled in", since.as_millis()));
            }
            Event::Media {
                call: which,
                event: MediaEvent::Started { .. },
            } if *which == call => self.seen.started = true,
            Event::Media {
                call: which,
                event: MediaEvent::PathChosen { local, remote },
            } if *which == call && self.seen.chosen.is_none() => {
                self.seen.chosen = Some((*local, *remote, since));
            }
            Event::Media {
                call: which,
                event: MediaEvent::Failed(error),
            } if *which == call => self.seen.failed = Some(error.to_string()),
            _ => {}
        }
    }

    /// The media socket, handed to the call once it exists.
    fn adopt(&mut self, call: CallHandle) {
        self.call = Some(call);
        if let Some(media) = self.waiting.take() {
            self.endpoint.media.insert(call, media);
        }
    }

    /// What this end proved, or the first thing it did not.
    fn verdict(&self, peer_nat: Option<std::net::IpAddr>) -> Result<String, String> {
        let heard = self
            .call
            .and_then(|call| self.endpoint.media.get(&call))
            .map(Media::heard)
            .unwrap_or_default();
        let said = verdict(&self.seen, heard)
            .map_err(|why| format!("{why}; {}", self.story.join(", ")))?;
        let Some((_, remote, chosen)) = self.seen.chosen else {
            return Err("no path was chosen".to_owned());
        };
        if let Some(nat) = peer_nat
            && remote.ip() != nat
        {
            return Err(format!(
                "the path ends at {remote}, which is not the far end's NAT at {nat}"
            ));
        }
        let finished = self.gathering.finished_at;
        if at_once(self.trickle) {
            match finished {
                Some(over) if chosen >= over => {
                    return Err(format!(
                        "trickling, the path was chosen {} ms in, after gathering finished at {} ms",
                        chosen.as_millis(),
                        over.as_millis()
                    ));
                }
                _ => {}
            }
            if self.trickled_in == 0 {
                return Err("trickling, and the far end trickled nothing".to_owned());
            }
        }
        let millis = |at: Option<Duration>| {
            at.map_or_else(|| "never".to_owned(), |at| format!("{} ms", at.as_millis()))
        };
        Ok(format!(
            "{said}; trickle {:?}: described {}, answered {}, path {} ms, gathering over {}, \
             mapped {}; {} trickled out, {} in",
            self.trickle,
            millis(self.described_at),
            millis(self.seen.confirmed),
            chosen.as_millis(),
            millis(finished),
            millis(self.gathering.learned_at),
            self.trickled_out,
            self.trickled_in
        ))
    }
}

/// The calling side: dial the trickle user through the proxy, describe the
/// call when the stance says, trickle what follows, and judge the path, the
/// audio and when each happened.
///
/// # Errors
/// The first condition that did not hold, named.
pub(crate) fn call(proxy: SocketAddr) -> Result<String, String> {
    let trickle = stance()?;
    let servers = [stun_server()?, silent_server()?];
    let peer_nat = env::var("SIPRAL_PEER_NAT")
        .ok()
        .and_then(|text| text.parse().ok());
    let now = Instant::now();
    let endpoint = Endpoint::bind(
        run_folded([CALLER_SEED; 32]),
        run_folded([CALLER_MEDIA_SEED; 32]),
        SocketAddr::new(route_to(proxy), 0),
        catalog(),
        now,
    )?;
    let mut end = End::new(
        endpoint,
        trickle,
        &servers,
        run_folded([CALLER_SEED ^ 0x5a; 32]),
        proxy,
        now,
    )?;
    let identity = uri(&format!("sip:caller@{}", end.endpoint.local))?;
    let account = end.endpoint.agent.add_account(Account::unregistered(
        identity.clone(),
        identity,
        end.endpoint.transport,
        proxy,
    ));
    loop {
        let now = Instant::now();
        if end.call.is_none() && end.may_describe() {
            let outgoing = OutgoingCall::new(uri(&format!("sip:{TRICKLE_USER}@kamailio"))?)
                .to_address(end.endpoint.transport, proxy);
            let media = end.media();
            let local = end.local;
            let placed = end
                .endpoint
                .engine
                .place_with(
                    &mut end.endpoint.agent,
                    account,
                    outgoing,
                    local,
                    media,
                    now,
                )
                .map_err(|error| format!("could not place the call: {error}"))?;
            end.adopt(placed);
            end.described_at = Some(end.since(now));
        }
        end.turn(now, true);
        if end.seen.ended || end.seen.failed.is_some() || now > end.gathering.started + PATIENCE {
            if !end.seen.ended
                && let Some(call) = end.call
            {
                let _ = end.endpoint.agent.hangup(call, now);
                end.endpoint.flush();
            }
            break;
        }
        if !end.endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    end.verdict(peer_nat)
}

/// The answering side: register as the trickle user at the proxy through
/// the NAT, which forwards `SIPRAL_CONTACT`'s port; gather when the call
/// rings; answer when the stance says; trickle what follows.
///
/// # Errors
/// The first condition that did not hold, named.
pub(crate) fn answer(proxy: SocketAddr) -> Result<String, String> {
    let trickle = stance()?;
    let servers = [stun_server()?, silent_server()?];
    let contact = env::var("SIPRAL_CONTACT")
        .map_err(|_| "SIPRAL_CONTACT does not name the NAT's outside address".to_owned())?;
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(
        run_folded([ANSWER_SEED; 32]),
        run_folded([ANSWER_MEDIA_SEED; 32]),
        SocketAddr::new(route_to(proxy), 5060),
        catalog(),
        now,
    )?;
    // an INVITE that requires trickle (RFC 8840 §5.1) is taken rather than
    // refused 420
    endpoint
        .agent
        .accept_trickle_ice(trickle != IceTrickle::Off);
    let account = endpoint.agent.add_account(
        Account::new(
            uri(&format!("sip:{TRICKLE_USER}@kamailio"))?,
            uri("sip:kamailio")?,
            uri(&format!("sip:{TRICKLE_USER}@{contact}:5060"))?,
            endpoint.transport,
            proxy,
        )
        .credentials(Credentials::new(TRICKLE_USER, TRICKLE_PASS))
        .expires(Duration::from_secs(300)),
    );
    let _ = endpoint.agent.register(account, now);
    let started = Instant::now();
    let mut registered = None;
    let incoming = loop {
        let now = Instant::now();
        let mut arrived = None;
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) if registered.is_none() => {
                    registered = Some(now);
                    println!("waiting for the call as {TRICKLE_USER}, at {contact}:5060");
                    let _ = std::io::stdout().flush();
                }
                Event::Signalling(UaEvent::IncomingCall { call, .. }) => arrived = Some(call),
                _ => {}
            }
        }
        if let Some(call) = arrived {
            break call;
        }
        match registered {
            None if now > started + REGISTER_PATIENCE => {
                return Err("the proxy never took the registration".to_owned());
            }
            Some(at) if now > at + CALL_PATIENCE => return Err("no call arrived".to_owned()),
            _ => {}
        }
        endpoint.timers(now);
        endpoint.flush();
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    // gathering starts as the phone rings, as a responder's does (RFC 8838
    // §5)
    let now = Instant::now();
    let mut end = End::new(
        endpoint,
        trickle,
        &servers,
        run_folded([ANSWER_SEED ^ 0x5a; 32]),
        proxy,
        now,
    )?;
    end.call = Some(incoming);
    let mut answered = false;
    loop {
        let now = Instant::now();
        if !answered && end.may_describe() {
            answered = true;
            let media = end.media();
            let local = end.local;
            end.endpoint
                .engine
                .answer_with(&mut end.endpoint.agent, incoming, local, media, now)
                .map_err(|error| format!("could not answer: {error}"))?;
            end.adopt(incoming);
            end.described_at = Some(end.since(now));
        }
        end.turn(now, false);
        if end.seen.ended || now > end.gathering.started + PATIENCE {
            break;
        }
        if !end.endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let said = end.verdict(None);
    crate::join::give_back(&mut end.endpoint, account);
    said
}

/// Half trickle against Asterisk, which does not trickle: the account
/// `interop/ice/pjsip_local.conf` gives ICE calls the echo with an offer that
/// is whole and says `trickle`; the answer has to be regular ICE, nothing may
/// be trickled to it, and the tone has to come back on the pair ICE chose.
///
/// # Errors
/// The first condition that did not hold, named.
pub(crate) fn asterisk(remote: SocketAddr, pass: &str) -> Result<String, String> {
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(
        run_folded([ASTERISK_SEED; 32]),
        run_folded([ASTERISK_MEDIA_SEED; 32]),
        SocketAddr::new(route_to(remote), 0),
        catalog(),
        now,
    )?;
    let account = endpoint.account(ASTERISK_USER, pass, "asterisk", remote)?;
    let half = catalog()
        .with_ice(IcePolicy::Required)
        .with_ice_trickle(IceTrickle::Half);
    let outgoing = OutgoingCall::new(uri(&format!("sip:{ECHO}@asterisk"))?)
        .to_address(endpoint.transport, remote);
    let offered = Instant::now();
    let call = crate::place_call(
        &mut endpoint,
        account,
        outgoing,
        CallMedia::new(half, MediaConfig::default()),
        remote,
        offered,
    )?;
    let seen = crate::ice_lite::drive(&mut endpoint, call, offered, true);
    let heard = endpoint
        .media
        .get(&call)
        .map(Media::heard)
        .unwrap_or_default();
    let said = verdict(&seen, heard)?;
    if endpoint.agent.takes_trickle_ice(call) {
        return Err("Asterisk listed the trickle-ice package it does not implement".to_owned());
    }
    if endpoint
        .engine
        .trickle_public_address(&mut endpoint.agent, call, remote, Instant::now())
        != Err(sipral::MediaError::NotTrickling)
    {
        return Err(
            "the call took a trickled candidate although Asterisk answered without trickle"
                .to_owned(),
        );
    }
    Ok(format!(
        "{said}; half trickle offered, regular ICE answered, nothing trickled"
    ))
}
