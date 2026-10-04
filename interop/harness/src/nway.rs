// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Three calls through the proxy, one local conference, and every member
//! hearing the other two.
//!
//! Three stacks register at Kamailio as `conf-a`, `conf-b` and `conf-c`,
//! each offering one codec of its own — G.711 at 8 kHz, G.722 at 16 kHz and
//! L16 at 16 kHz — and a fourth, the host, calls each of them through the
//! proxy and puts the three calls in one `sipral::LocalConference`, taking
//! no part itself. Each member sends a tone of a pitch of its own, and what
//! each one plays is measured at every pitch: a member has to hear the other
//! two and not itself. Then `conf-c` hangs up, the conference lets it go on
//! the next tick and says so, and the two left have to go on hearing each
//! other and nothing of `conf-c`.
//!
//! What `crates/sipral/src/local_conference_tests.rs` already proves with
//! four stacks and no network, this proves over real sockets, through a
//! real proxy's routing, at the pace of real time: every member's jitter
//! buffer fed by the conference's own tick rather than by a test's loop.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    AccountId, CallHandle, CallMedia, CodecCatalog, ConferenceChange, Departure, Event,
    LocalConference, LocalConferenceConfig, MediaConfig, Member, OutgoingCall, UaEvent,
};

use crate::{Endpoint, place_call, run_folded, uri};

/// How long the flow may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(40);

/// The conference's tick, and each member's frame.
const TICK: Duration = Duration::from_millis(20);

/// How long the conference runs before anything is measured: the jitter
/// buffers settle and the resamplers fill.
const WARM: Duration = Duration::from_millis(1_500);

/// How long each measurement listens.
const LISTEN: Duration = Duration::from_secs(2);

/// The password the three members register with, `interop/kamailio/kamailio.cfg`'s
/// own `CONF_PASS`.
const MEMBER_PASS: &str = "confpass";

/// Loud enough to be a member's tone through a codec and two resamplers.
const HEARD: f64 = 1_000.0;

/// Quiet enough that it is only what a codec's own distortion leaves at
/// another pitch.
const SILENT: f64 = 300.0;

/// This flow's own endpoint identity constants, each folded with the run's
/// own entropy before anything binds with it (`run_folded`, `main.rs`), and
/// listed in `main.rs`'s `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const HOST_SEED: u8 = 20;
pub(crate) const HOST_MEDIA_SEED: u8 = 21;
pub(crate) const MEMBER_SEEDS: [u8; 3] = [22, 23, 24];
pub(crate) const MEMBER_MEDIA_SEEDS: [u8; 3] = [25, 26, 27];

/// Who the members are: the user each registers as, the one codec it offers
/// and the pitch it sends.
const MEMBERS: [(&str, &str, f64); 3] = [
    ("conf-a", "PCMU", 500.0),
    ("conf-b", "G722", 900.0),
    ("conf-c", "L16/16000", 1_300.0),
];

/// A sine at `hz`, carried on from `phase` samples in.
fn sine(len: usize, rate: u32, hz: f64, phase: &mut usize) -> Vec<i16> {
    let step = core::f64::consts::TAU * hz / f64::from(rate);
    (0..len)
        .map(|_| {
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let sample = (5_000.0 * (step * *phase as f64).sin()).round() as i16;
            *phase += 1;
            sample
        })
        .collect()
}

/// The amplitude of the component at `hz`, by Goertzel.
fn level_at(samples: &[i16], rate: u32, hz: f64) -> f64 {
    let coefficient = 2.0 * (core::f64::consts::TAU * hz / f64::from(rate)).cos();
    let (mut before, mut last) = (0.0_f64, 0.0_f64);
    for sample in samples {
        let next = f64::from(*sample) + coefficient * last - before;
        before = last;
        last = next;
    }
    let power = before.mul_add(before, last * last) - coefficient * before * last;
    #[allow(clippy::cast_precision_loss)]
    let length = samples.len().max(1) as f64;
    2.0 * power.max(0.0).sqrt() / length
}

/// One of the three far ends.
struct Party {
    name: &'static str,
    hz: f64,
    endpoint: Endpoint,
    remote: SocketAddr,
    registered: bool,
    call: Option<CallHandle>,
    ended: bool,
    phase: usize,
    listening: bool,
    heard: Vec<i16>,
    rate: u32,
}

impl Party {
    fn signalling(&mut self, now: Instant) -> bool {
        for event in self.endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) => self.registered = true,
                Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
                    if let Ok(local) = self.endpoint.open_media(call, self.remote, now) {
                        let _ =
                            self.endpoint
                                .engine
                                .answer(&mut self.endpoint.agent, call, local, now);
                    }
                }
                Event::Signalling(UaEvent::CallConfirmed { call, .. }) => self.call = Some(call),
                Event::Signalling(UaEvent::CallEnded { .. }) => self.ended = true,
                _ => {}
            }
        }
        self.endpoint.timers(now);
        self.endpoint.read_sip(now)
    }

    /// One frame of this member's tone out, whatever arrived in, and one
    /// frame played.
    fn frame(&mut self, now: Instant) {
        let Some(call) = self.call.filter(|_| !self.ended) else {
            return;
        };
        let Some(media) = self.endpoint.media.get_mut(&call) else {
            return;
        };
        let Some(mut session) = self.endpoint.engine.session(call) else {
            return;
        };
        media.receive_into(&mut session, now);
        self.rate = session.sample_rate();
        let tone = sine(session.frame_samples(), self.rate, self.hz, &mut self.phase);
        if let Ok(Some(datagram)) = session.capture(&tone, now) {
            media.send(datagram.destination, datagram.payload);
        }
        let mut played = vec![0_i16; session.frame_samples()];
        session.playback(&mut played);
        if self.listening {
            self.heard.extend_from_slice(&played);
        }
        drop(session);
        carry_control(&mut self.endpoint, now);
    }

    /// What this member heard at every member's pitch.
    fn levels(&self) -> [f64; 3] {
        MEMBERS.map(|(_, _, hz)| level_at(&self.heard, self.rate, hz))
    }
}

/// What the engine queued beside the audio: reports, handshakes and
/// goodbyes, each from its own call's socket.
fn carry_control(endpoint: &mut Endpoint, now: Instant) {
    while let Some((call, destination, payload)) = endpoint.engine.poll_rtcp(now) {
        if let Some(media) = endpoint.media.get(&call) {
            media.send(destination, &payload);
        }
    }
    while let Some((call, destination, payload)) = endpoint.engine.poll_farewell() {
        if let Some(media) = endpoint.media.get(&call) {
            media.send(destination, &payload);
        }
    }
    while let Some((call, destination, payload)) = endpoint.engine.poll_transmit(now) {
        if let Some(media) = endpoint.media.get(&call) {
            media.send(destination, &payload);
        }
    }
}

/// The end that calls the three and bridges them.
struct Host {
    endpoint: Endpoint,
    account: AccountId,
    remote: SocketAddr,
    server: String,
    calls: Vec<CallHandle>,
    confirmed: Vec<CallHandle>,
    conference: Option<LocalConference>,
    changes: Vec<ConferenceChange>,
}

impl Host {
    fn signalling(&mut self, now: Instant) -> bool {
        for event in self.endpoint.pump(now) {
            if let Event::Signalling(UaEvent::CallConfirmed { call, .. }) = event {
                self.confirmed.push(call);
            }
        }
        self.endpoint.timers(now);
        self.endpoint.read_sip(now)
    }

    fn place(&mut self, now: Instant) -> Result<(), String> {
        let catalog = CodecCatalog::with_order(&["PCMU", "G722", "L16/16000"])
            .map_err(|error| error.to_string())?;
        for (user, _, _) in MEMBERS {
            let outgoing = OutgoingCall::new(uri(&format!("sip:{user}@{}", self.server))?)
                .to_address(self.endpoint.transport, self.remote);
            let media = CallMedia::new(catalog.clone(), MediaConfig::default());
            let call = place_call(
                &mut self.endpoint,
                self.account,
                outgoing,
                media,
                self.remote,
                now,
            )?;
            self.calls.push(call);
        }
        Ok(())
    }

    /// Every call confirmed and with a session: the conference is made and
    /// the three put in it.
    fn bridge(&mut self) -> Result<(), String> {
        let mut conference = self
            .endpoint
            .engine
            .local_conference(LocalConferenceConfig {
                max_members: 3,
                local: None,
            })
            .map_err(|error| error.to_string())?;
        for call in &self.calls {
            let share = self
                .endpoint
                .engine
                .share(*call)
                .ok_or_else(|| "a call confirmed without media".to_owned())?;
            conference
                .add(*call, share)
                .map_err(|error| format!("a call was refused by the conference: {error}"))?;
        }
        self.conference = Some(conference);
        Ok(())
    }

    /// One tick of the conference: what arrived on each call's socket in,
    /// the mix, and every packet out from its own call's socket.
    fn frame(&mut self, now: Instant) {
        for call in &self.calls {
            if let (Some(media), Some(mut session)) = (
                self.endpoint.media.get_mut(call),
                self.endpoint.engine.session(*call),
            ) {
                media.receive_into(&mut session, now);
            }
        }
        if let Some(conference) = self.conference.as_mut() {
            let _ = conference.tick(&[], now);
            while let Some(packet) = conference.poll_transmit() {
                if let Some(media) = self.endpoint.media.get(&packet.call) {
                    media.send(packet.destination, &packet.payload);
                }
            }
            while let Some(change) = conference.poll_change() {
                self.changes.push(change);
            }
        }
        carry_control(&mut self.endpoint, now);
    }
}

/// Where the flow is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Registering,
    Calling,
    Warming(Instant),
    Listening(Instant),
    Leaving(Instant),
    ListeningAgain(Instant),
    HangingUp,
}

/// The host and the three members, and what was measured.
struct Lab {
    host: Host,
    a: Party,
    b: Party,
    c: Party,
    /// What each member heard at every pitch with all three in.
    first: Option<[[f64; 3]; 3]>,
    /// What `a` and `b` heard once `c` had left.
    second: Option<[[f64; 3]; 2]>,
}

impl Lab {
    fn parties(&mut self) -> [&mut Party; 3] {
        [&mut self.a, &mut self.b, &mut self.c]
    }

    /// One turn of the loop: everybody's signalling, and on a tick
    /// everybody's audio. `true` when a SIP datagram arrived.
    fn turn(&mut self, tick: bool, now: Instant) -> bool {
        let mut read = self.host.signalling(now);
        for party in self.parties() {
            read |= party.signalling(now);
        }
        if tick {
            self.host.frame(now);
            for party in self.parties() {
                party.frame(now);
            }
        }
        read
    }

    /// The stage after `stage`, doing what moving on to it takes.
    fn advance(&mut self, stage: Stage, now: Instant) -> Result<Stage, String> {
        Ok(match stage {
            Stage::Registering if self.parties().iter().all(|party| party.registered) => {
                self.host.place(now)?;
                Stage::Calling
            }
            Stage::Calling
                if self
                    .host
                    .calls
                    .iter()
                    .all(|call| self.host.confirmed.contains(call))
                    && self.parties().iter().all(|party| party.call.is_some()) =>
            {
                self.host.bridge()?;
                Stage::Warming(now)
            }
            Stage::Warming(since) if now >= since + WARM => {
                for party in self.parties() {
                    party.listening = true;
                }
                Stage::Listening(now)
            }
            Stage::Listening(since) if now >= since + LISTEN => {
                self.first = Some([self.a.levels(), self.b.levels(), self.c.levels()]);
                for party in self.parties() {
                    party.listening = false;
                    party.heard.clear();
                }
                self.c.hang_up(now);
                Stage::Leaving(now)
            }
            Stage::Leaving(since) if now >= since + WARM => {
                self.a.listening = true;
                self.b.listening = true;
                Stage::ListeningAgain(now)
            }
            Stage::ListeningAgain(since) if now >= since + LISTEN => {
                self.second = Some([self.a.levels(), self.b.levels()]);
                self.a.hang_up(now);
                self.b.hang_up(now);
                Stage::HangingUp
            }
            other => other,
        })
    }

    fn finished(&mut self, stage: Stage) -> bool {
        stage == Stage::HangingUp && self.parties().iter().all(|party| party.ended)
    }
}

impl Party {
    fn hang_up(&mut self, now: Instant) {
        if let Some(call) = self.call {
            let _ = self.endpoint.agent.hangup(call, now);
        }
    }
}

/// The host and the three members, bound and registering.
fn lab(server: &str, remote: SocketAddr, user: &str, pass: &str) -> Result<Lab, String> {
    let bind = SocketAddr::new(crate::route_to(remote), 0);
    let now = Instant::now();
    let mut host_endpoint = Endpoint::bind(
        run_folded([HOST_SEED; 32]),
        run_folded([HOST_MEDIA_SEED; 32]),
        bind,
        crate::catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind the host: {error}"))?;
    let host_account = host_endpoint.account(user, pass, server, remote)?;
    let _ = host_endpoint.agent.register(host_account, now);
    let host = Host {
        endpoint: host_endpoint,
        account: host_account,
        remote,
        server: server.to_owned(),
        calls: Vec::new(),
        confirmed: Vec::new(),
        conference: None,
        changes: Vec::new(),
    };
    let mut parties = Vec::new();
    for (((name, codec, hz), seed), media_seed) in MEMBERS
        .into_iter()
        .zip(MEMBER_SEEDS)
        .zip(MEMBER_MEDIA_SEEDS)
    {
        let catalog = CodecCatalog::with_order(&[codec]).map_err(|error| error.to_string())?;
        let mut endpoint = Endpoint::bind(
            run_folded([seed; 32]),
            run_folded([media_seed; 32]),
            bind,
            catalog,
            now,
        )
        .map_err(|error| format!("cannot bind {name}: {error}"))?;
        let account = endpoint.account(name, MEMBER_PASS, server, remote)?;
        let _ = endpoint.agent.register(account, now);
        parties.push(Party {
            name,
            hz,
            endpoint,
            remote,
            registered: false,
            call: None,
            ended: false,
            phase: 0,
            listening: false,
            heard: Vec::new(),
            rate: 8_000,
        });
    }
    let [a, b, c]: [Party; 3] = parties
        .try_into()
        .map_err(|_| "three members were not made".to_owned())?;
    Ok(Lab {
        host,
        a,
        b,
        c,
        first: None,
        second: None,
    })
}

/// Run the flow at `server`, reached at `remote`, the host registering as
/// `user`.
///
/// # Errors
/// The first thing that did not happen, or a member that heard the wrong
/// thing.
pub(crate) fn run(
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    let mut lab = lab(server, remote, user, pass)?;
    let started = Instant::now();
    let mut next_tick = started;
    let mut stage = Stage::Registering;
    while !lab.finished(stage) {
        let now = Instant::now();
        if now > started + PATIENCE {
            return Err(format!(
                "the flow never finished: {} of 3 registered, {} of 3 calls confirmed, \
                 conference made {}",
                lab.parties()
                    .iter()
                    .filter(|party| party.registered)
                    .count(),
                lab.host.confirmed.len(),
                lab.host.conference.is_some()
            ));
        }
        let tick = now >= next_tick;
        if tick {
            next_tick += TICK;
        }
        let read = lab.turn(tick, now);
        stage = lab.advance(stage, now)?;
        if !read {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    verdict(&lab)
}

/// Whether `levels` has every pitch in `heard` and none of the others.
fn hears(who: &str, levels: [f64; 3], heard: [bool; 3]) -> Result<(), String> {
    for ((level, wanted), name) in levels
        .iter()
        .zip(heard)
        .zip(MEMBERS.map(|(name, _, _)| name))
    {
        if wanted && *level < HEARD {
            return Err(format!(
                "{who} did not hear {name} ({level:.0} at its pitch): {levels:.0?}"
            ));
        }
        if !wanted && *level > SILENT {
            return Err(format!(
                "{who} heard {name}, which it should not have ({level:.0} at its pitch): \
                 {levels:.0?}"
            ));
        }
    }
    Ok(())
}

/// What the flow proved, or the first thing it did not.
fn verdict(lab: &Lab) -> Result<String, String> {
    let (Some([a, b, c]), Some([a_after, b_after])) = (lab.first, lab.second) else {
        return Err("the flow ended before it measured anything".to_owned());
    };
    hears("conf-a", a, [false, true, true])?;
    hears("conf-b", b, [true, false, true])?;
    hears("conf-c", c, [true, true, false])?;
    // the host placed the three calls in the members' order
    let told = lab.host.calls.last().is_some_and(|near| {
        lab.host.changes.contains(&ConferenceChange::Left {
            member: Member::Call(*near),
            why: Departure::Ended,
        })
    });
    if !told {
        return Err("conf-c hung up and the conference never said it left".to_owned());
    }
    hears(
        "conf-a, once conf-c had left,",
        a_after,
        [false, true, false],
    )?;
    hears(
        "conf-b, once conf-c had left,",
        b_after,
        [true, false, false],
    )?;
    let [[_, a_b, a_c], [b_a, _, b_c], [c_a, c_b, _]] = [a, b, c];
    let [_, a_b_after, _] = a_after;
    let [b_a_after, _, _] = b_after;
    Ok(format!(
        "   ({} at {} Hz, {} at {} Hz, {} at {} Hz; each heard the other two: a {a_b:.0}/{a_c:.0}, \
         b {b_a:.0}/{b_c:.0}, c {c_a:.0}/{c_b:.0}; conf-c left and a and b still heard each \
         other at {a_b_after:.0} and {b_a_after:.0})",
        lab.a.name, lab.a.rate, lab.b.name, lab.b.rate, lab.c.name, lab.c.rate
    ))
}
