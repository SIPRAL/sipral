// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A call's own mute, heard through a real echo.
//!
//! Two calls on one account to an extension that sends back whatever it is
//! sent (`interop/asterisk/extensions.conf`'s 9008, or the echo feature code
//! of the PBX `SIPRAL_ECHO_EXTENSION` names), both carried by
//! `sipral-audio`'s engine the way a softphone's are: one microphone into
//! both, both into one loudspeaker. The devices are the engine's fakes,
//! since the containers this runs in have no sound card; everything between
//! them and the wire — the pump, the resampling, each call's own gain, mute
//! and meter, the codec, the jitter buffer — is the engine's own.
//!
//! The microphone carries a tone from the start. The first call's input is
//! muted with the engine's own per-call mute (`Engine::set_call_muted`, what
//! `sipral_audio_call_set_muted` calls), so its far end is sent silence and
//! its echo brings silence back, while the second call's echo brings the
//! tone back. Each call's meter on the way to the loudspeaker
//! (`Engine::call_level`, `Direction::Output`) says what came back on that
//! call alone. Then the mute comes off, and the first call's echo has to
//! bring the tone back too, so a far end that sent nothing at all on that
//! call cannot pass for a mute that worked.
//!
//! A PBX whose echo plays a prompt first and starts echoing on a key (the
//! FreePBX echo test does) is given that key on each call before the engine
//! takes them over: `SIPRAL_ECHO_KEY`, sent as a named event.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sipral::{CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, UaEvent};
use sipral_audio::fake::FakeControl;
use sipral_audio::{Activation, CallId, Config, Direction, Engine, Level, Outgoing};

use crate::join::give_back;
use crate::{Endpoint, catalog, place_call, run_folded, uri};

/// How long the flow may take, the two phases included, before it is a
/// failure.
const PATIENCE: Duration = Duration::from_secs(40);

/// How long the first call stays muted once the engine carries both, and
/// how long it then runs unmuted.
const MUTED: Duration = Duration::from_secs(5);
const UNMUTED: Duration = Duration::from_secs(4);

/// How long into each phase the meters are left to settle before they are
/// read: the echo's round trip, the jitter buffer filling, and a meter
/// window holding what came before.
const SETTLE: Duration = Duration::from_millis(1_500);

/// How often the meters are read.
const READ_EVERY: Duration = Duration::from_millis(100);

/// The pace the microphone is fed at.
const PACE: Duration = Duration::from_millis(20);

/// The fake devices' rate, and a microphone frame at it.
const DEVICE_HZ: u32 = 48_000;
const MIC_FRAME: usize = 960;

/// The tone into the microphone: 440 Hz at a quarter of full scale.
const TONE_HZ: f64 = 440.0;
const TONE_AMPLITUDE: f64 = 8_000.0;

/// A meter reading at or above this is the tone come back; at or under
/// [`SILENT`], nothing did. The tone peaks near 8000 after the codec.
const AUDIBLE: u16 = 2_000;
const SILENT: u16 = 200;

/// The share of a phase's half seconds that have to carry the tone come back
/// for the call to count as hearing it. Judged by the half second, not by
/// the reading: the fake loudspeaker queues nothing, so the engine pulls
/// each call at twice the frame rate and every other frame it plays is the
/// jitter buffer's, and a far end that sends in bursts leaves a tenth of a
/// second of that at a time.
const HEARD_SHARE: f64 = 0.8;

/// Readings in one of those half seconds.
const PER_STRETCH: u32 = 5;

/// How long after both calls have media the key `SIPRAL_ECHO_KEY` names is
/// sent: a PBX that answers, waits and then plays its prompt drops a key
/// that comes before the prompt has begun.
const KEY_DELAY: Duration = Duration::from_millis(2_500);

/// How long after the key the engine takes the calls over: a prompt the key
/// cut short has stopped by then, and the echo behind it started.
const KEY_WAIT: Duration = Duration::from_secs(3);

/// The engine's names for the call muted first and the one left alone.
const MUTED_ID: CallId = 1;
const OPEN_ID: CallId = 2;

/// `interop/asterisk/extensions.conf`'s echo, unless another is named.
const ECHO_EXTENSION: &str = "9008";

/// This flow's own endpoint identity, folded with the run's own entropy
/// before anything binds with it (`run_folded`, `main.rs`), and listed in
/// `main.rs`'s `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const SEED: u8 = 39;
pub(crate) const MEDIA_SEED: u8 = 40;

/// One of the two calls.
#[derive(Debug, Default)]
struct Leg {
    attempted: bool,
    call: Option<CallHandle>,
    media_started: bool,
    ended: bool,
}

/// What the meters said in one phase, for one call.
#[derive(Debug, Default)]
struct Readings {
    taken: u32,
    audible: u32,
    loudest: u16,
    /// Half seconds read, and those with a reading of the tone in them.
    stretches: u32,
    heard_stretches: u32,
    /// Whether the half second being read has had one yet.
    stretch_heard: bool,
}

impl Readings {
    fn note(&mut self, peak: u16) {
        self.taken += 1;
        if peak >= AUDIBLE {
            self.audible += 1;
            self.stretch_heard = true;
        }
        self.loudest = self.loudest.max(peak);
        if self.taken.is_multiple_of(PER_STRETCH) {
            self.stretches += 1;
            self.heard_stretches += u32::from(self.stretch_heard);
            self.stretch_heard = false;
        }
    }

    fn heard(&self) -> bool {
        self.stretches > 0
            && f64::from(self.heard_stretches) >= HEARD_SHARE * f64::from(self.stretches)
    }

    fn silent(&self) -> bool {
        self.taken > 0 && self.loudest <= SILENT
    }
}

impl std::fmt::Display for Readings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} of {} readings audible, in {} of {} half seconds, loudest {}",
            self.audible, self.taken, self.heard_stretches, self.stretches, self.loudest
        )
    }
}

/// The engine over its fake devices, and how each call's packets leave.
struct Carried {
    engine: Engine,
    fake: FakeControl,
    sent: Arc<Mutex<HashMap<CallId, u32>>>,
    started: Instant,
    next_frame: Instant,
    next_read: Instant,
    unmuted: bool,
    phase: f64,
}

impl Carried {
    /// An engine whose microphone and loudspeaker are fakes, sending each
    /// call's packets on that call's own socket.
    fn new(sockets: HashMap<CallId, UdpSocket>, now: Instant) -> Result<Self, String> {
        let fake = FakeControl::new(DEVICE_HZ);
        fake.plug("speaker", "Speaker", 0, 2);
        fake.plug("microphone", "Microphone", 1, 0);
        fake.make_default("speaker", sipral_audio::Direction::Output);
        fake.make_default("microphone", sipral_audio::Direction::Input);
        fake.forget_notices();
        let sent: Arc<Mutex<HashMap<CallId, u32>>> = Arc::default();
        let counted = Arc::clone(&sent);
        let transmit = Box::new(move |call: CallId, packet: &Outgoing| {
            if let Some(socket) = sockets.get(&call)
                && socket.send_to(&packet.payload, packet.destination).is_ok()
            {
                *counted
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .entry(call)
                    .or_default() += 1;
            }
        });
        let mut engine = Engine::new(
            fake.backend(),
            Config {
                activation: Activation::Automatic,
                device_rate_hz: DEVICE_HZ,
                ..Config::default()
            },
            transmit,
            Arc::new(Instant::now),
        );
        engine
            .refresh()
            .map_err(|error| format!("the engine could not list its devices: {error}"))?;
        Ok(Self {
            engine,
            fake,
            sent,
            started: now,
            next_frame: now,
            next_read: now + SETTLE,
            unmuted: false,
            phase: 0.0,
        })
    }

    /// The microphone's frames that are due by `now`.
    fn speak(&mut self, now: Instant) {
        while now >= self.next_frame {
            let step = std::f64::consts::TAU * TONE_HZ / f64::from(DEVICE_HZ);
            let frame: Vec<i16> = (0..MIC_FRAME)
                .map(|_| {
                    self.phase = (self.phase + step) % std::f64::consts::TAU;
                    #[allow(clippy::cast_possible_truncation)]
                    let sample = (TONE_AMPLITUDE * self.phase.sin()).round() as i16;
                    sample
                })
                .collect();
            self.fake.speak_into("microphone", &frame);
            self.next_frame += PACE;
        }
    }

    fn level(&self, call: CallId) -> u16 {
        self.engine
            .call_level(call, Direction::Output)
            .map_or(0, Level::peak)
    }

    fn sent(&self, call: CallId) -> u32 {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&call)
            .copied()
            .unwrap_or(0)
    }
}

/// Register, place both calls to the echo, carry them in the engine with the
/// first one's input muted, then unmuted, and judge what came back on each.
///
/// # Errors
/// The first thing that did not hold: a call not placed or never given
/// media, the engine refusing a call, or an echo that did not come back the
/// way the mute says it should.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    let bind_addr = SocketAddr::new(crate::route_to(remote), 0);
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(
        run_folded([SEED; 32]),
        run_folded([MEDIA_SEED; 32]),
        bind_addr,
        catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind: {error}"))?;
    let account = endpoint.account(user, pass, server, remote)?;
    let extension =
        std::env::var("SIPRAL_ECHO_EXTENSION").unwrap_or_else(|_| ECHO_EXTENSION.to_owned());
    let target = uri(&format!("sip:{extension}@{server}"))?;

    let mut muted_leg = Leg::default();
    let mut open_leg = Leg::default();
    let mut asked_to_register = false;
    let mut registered = false;
    let mut carried: Option<Carried> = None;
    let mut keyed: Option<Instant> = None;
    let mut key_sent = false;
    let mut muted_phase = (Readings::default(), Readings::default());
    let mut unmuted_phase = (Readings::default(), Readings::default());
    let mut verdict: Option<Result<String, String>> = None;

    let started = Instant::now();
    loop {
        let now = Instant::now();
        if now > started + PATIENCE {
            verdict.get_or_insert_with(|| {
                Err(format!(
                    "the two calls never finished: registered {registered}, placed {} and {}, \
                     media {} and {}, carried {}",
                    muted_leg.call.is_some(),
                    open_leg.call.is_some(),
                    muted_leg.media_started,
                    open_leg.media_started,
                    carried.is_some()
                ))
            });
            break;
        }
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) => registered = true,
                Event::Signalling(UaEvent::CallEnded { call, .. }) => {
                    for leg in [&mut muted_leg, &mut open_leg] {
                        if leg.call == Some(call) {
                            leg.ended = true;
                        }
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::Started { .. },
                } => {
                    for leg in [&mut muted_leg, &mut open_leg] {
                        if leg.call == Some(call) {
                            leg.media_started = true;
                        }
                    }
                }
                _ => {}
            }
        }
        if !asked_to_register {
            asked_to_register = true;
            let _ = endpoint.agent.register(account, now);
        }
        for leg in [&mut muted_leg, &mut open_leg] {
            if registered && !leg.attempted {
                leg.attempted = true;
                let media = CallMedia::new(catalog(), MediaConfig::default());
                let outgoing =
                    OutgoingCall::new(target.clone()).to_address(endpoint.transport, remote);
                leg.call = place_call(&mut endpoint, account, outgoing, media, remote, now).ok();
            }
        }

        // an echo behind a prompt starts on a key: sent on each call while
        // the harness still drives it, once the prompt has begun, and the
        // prompt given time to stop before the engine takes over
        let key = std::env::var("SIPRAL_ECHO_KEY").ok();
        if keyed.is_none() && muted_leg.media_started && open_leg.media_started {
            keyed = Some(match key {
                Some(_) => now + KEY_DELAY + KEY_WAIT,
                None => now,
            });
        }
        if let (Some(key), Some(at), Some(muted), Some(open)) =
            (key, keyed, muted_leg.call, open_leg.call)
            && !key_sent
            && now + KEY_WAIT >= at
        {
            key_sent = true;
            for call in [muted, open] {
                if let Some(mut session) = endpoint.engine.session(call) {
                    let _ = session.dial(&key, sipral::DEFAULT_DIGIT);
                }
            }
        }

        if carried.is_none()
            && verdict.is_none()
            && keyed.is_some_and(|at| now >= at)
            && let (Some(muted), Some(open)) = (muted_leg.call, open_leg.call)
        {
            match carry(&mut endpoint, [muted, open], now) {
                Ok(engine) => carried = Some(engine),
                Err(why) => {
                    verdict = Some(Err(why));
                    let _ = endpoint.agent.hangup(muted, now);
                    let _ = endpoint.agent.hangup(open, now);
                }
            }
        }

        if let (Some(engine), Some(muted), Some(open)) =
            (carried.as_mut(), muted_leg.call, open_leg.call)
        {
            for call in [muted, open] {
                if let Some(mut session) = endpoint.engine.session(call)
                    && let Some(media) = endpoint.media.get_mut(&call)
                {
                    media.receive_into(&mut session, now);
                }
            }
            engine.speak(now);
            let elapsed = now.saturating_duration_since(engine.started);
            if !engine.unmuted && elapsed >= MUTED {
                engine.unmuted = true;
                let _ = engine
                    .engine
                    .set_call_muted(MUTED_ID, Direction::Input, false);
                engine.next_read = now + SETTLE;
            }
            while now >= engine.next_read {
                if engine.unmuted {
                    unmuted_phase.0.note(engine.level(MUTED_ID));
                    unmuted_phase.1.note(engine.level(OPEN_ID));
                } else {
                    muted_phase.0.note(engine.level(MUTED_ID));
                    muted_phase.1.note(engine.level(OPEN_ID));
                }
                engine.next_read += READ_EVERY;
            }
            if verdict.is_none() && elapsed >= MUTED + UNMUTED {
                let said = format!(
                    "   (muted: its echo {} while the other's {}; unmuted: its echo {} while the other's {}; \
                     packets sent {} and {}, received {} and {})",
                    muted_phase.0,
                    muted_phase.1,
                    unmuted_phase.0,
                    unmuted_phase.1,
                    engine.sent(MUTED_ID),
                    engine.sent(OPEN_ID),
                    endpoint.media.get(&muted).map_or(0, |m| m.heard().received),
                    endpoint.media.get(&open).map_or(0, |m| m.heard().received),
                );
                verdict = Some(judge(&muted_phase, &unmuted_phase.0, said));
                engine.engine.detach(MUTED_ID);
                engine.engine.detach(OPEN_ID);
                let _ = endpoint.agent.hangup(muted, now);
                let _ = endpoint.agent.hangup(open, now);
            }
        } else {
            endpoint.run_media(now);
        }
        endpoint.timers(now);

        let over = |leg: &Leg| leg.ended || (leg.attempted && leg.call.is_none());
        if over(&muted_leg) && over(&open_leg) {
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    drop(carried);
    give_back(&mut endpoint, account);
    if muted_leg.call.is_none() || open_leg.call.is_none() {
        return Err("one of the two calls was never placed".to_owned());
    }
    verdict.unwrap_or_else(|| Err("the two calls ended before they were judged".to_owned()))
}

/// The engine over its fakes, carrying both calls, the first one's input
/// muted.
fn carry(endpoint: &mut Endpoint, calls: [CallHandle; 2], now: Instant) -> Result<Carried, String> {
    let mut sockets = HashMap::new();
    for (call, id) in calls.into_iter().zip([MUTED_ID, OPEN_ID]) {
        let media = endpoint
            .media
            .get(&call)
            .ok_or("a call with no socket of its own")?;
        sockets.insert(id, media.sender()?);
    }
    let mut carried = Carried::new(sockets, now)?;
    for (call, id) in calls.into_iter().zip([MUTED_ID, OPEN_ID]) {
        let share = endpoint
            .engine
            .share(call)
            .ok_or("a call whose media is gone")?;
        // the devices are fakes, so opening them cannot fail for a reason
        // worth more than the verdict below
        let _ = carried.engine.attach(id, Box::new(share));
    }
    if !carried
        .engine
        .set_call_muted(MUTED_ID, Direction::Input, true)
    {
        return Err("the engine would not mute a call it carries".to_owned());
    }
    Ok(carried)
}

fn judge(
    (muted, open): &(Readings, Readings),
    unmuted: &Readings,
    said: String,
) -> Result<String, String> {
    if !open.heard() {
        return Err(format!("the call left alone did not hear its echo{said}"));
    }
    if !muted.silent() {
        return Err(format!(
            "the call muted on the way in heard something come back{said}"
        ));
    }
    if !unmuted.heard() {
        return Err(format!(
            "the call unmuted did not hear its echo come back{said}"
        ));
    }
    Ok(said)
}
