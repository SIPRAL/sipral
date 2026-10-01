// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A call hung up while its devices are still opening.
//!
//! A softphone in device mode hands each call to `sipral-audio`'s engine,
//! which opens the microphone and the loudspeaker on a thread of its own: a
//! USB headset under the platform's voice unit has been measured taking a
//! second and a half to open. A call that ends inside that second and a half
//! — answered and hung up at once, or ended by the far end — has to leave
//! as any other does: the engine lets go of it without waiting for the open,
//! the BYE goes on the wire as soon as it is asked for, and the devices the
//! open brings back later are let go of on a thread of their own. Before
//! the engine opened in the background, the stack's poll held its own lock
//! through the open, and the BYE waited behind it.
//!
//! The devices are the engine's fakes, with every stream taking
//! [`OPEN_DELAY`] to open and one duplex unit for both directions, the way
//! the voice unit on macOS and iOS is; the call is a real one, to the
//! echo of Asterisk's or of the PBX `SIPRAL_ECHO_EXTENSION` names. The
//! engine takes the call as soon as its media starts, and the hangup is
//! asked for straight after, in the order a stack does it: the engine
//! lets go of the call, then the BYE is queued and written.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral::{CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, UaEvent};
use sipral_audio::fake::FakeControl;
use sipral_audio::{Activation, CallId, Config, Direction, Engine, Outgoing};

use crate::join::give_back;
use crate::{Endpoint, catalog, place_call, run_folded, uri};

/// How long the flow may take, the open that outlives the call included.
const PATIENCE: Duration = Duration::from_secs(20);

/// How long each stream takes to open: the USB headset's second and a half,
/// near enough, for each half of the duplex unit.
const OPEN_DELAY: Duration = Duration::from_millis(1_000);

/// The most the engine's attach, its detach and the BYE after the hangup
/// may each take: well under one [`OPEN_DELAY`], so that none of them can
/// have waited for the open.
const PROMPT: Duration = Duration::from_millis(250);

/// The fake devices' rate.
const DEVICE_HZ: u32 = 48_000;

/// The engine's name for the call.
const CALL_ID: CallId = 1;

/// `interop/asterisk/extensions.conf`'s echo, unless another is named.
const ECHO_EXTENSION: &str = "9008";

/// This flow's own endpoint identity, folded with the run's own entropy
/// before anything binds with it (`run_folded`, `main.rs`), and listed in
/// `main.rs`'s `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const SEED: u8 = 191;
pub(crate) const MEDIA_SEED: u8 = 193;

/// What was measured, each from the moment the step began.
#[derive(Debug, Default)]
struct Timings {
    attach: Option<Duration>,
    detach: Option<Duration>,
    hangup_asked: Option<Instant>,
    ended: Option<Instant>,
    /// When the open, outliving the call, had brought its unit back and
    /// had it let go of.
    open_settled: Option<Instant>,
}

/// Register, call the echo, hand the call to an engine whose devices take
/// [`OPEN_DELAY`] to open, hang up at once, and judge how long each step of
/// the hangup took and what became of the open.
///
/// # Errors
/// The first thing that did not hold: the call never placed or never given
/// media, a step of the hangup that waited for the open, a call that did not
/// end, or devices left open.
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

    endpoint
        .agent
        .register(account, now)
        .map_err(|error| format!("register: {error}"))?;
    let mut registered = false;
    let mut call: Option<CallHandle> = None;
    let mut placed = false;
    let mut media_started = false;
    let mut carried: Option<(Engine, FakeControl)> = None;
    let mut timings = Timings::default();
    let mut refused: Option<String> = None;

    let started = Instant::now();
    loop {
        let now = Instant::now();
        if now > started + PATIENCE {
            break;
        }
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) => registered = true,
                Event::Signalling(UaEvent::CallEnded {
                    call: ended,
                    reason,
                    ..
                }) if Some(ended) == call => {
                    timings.ended = Some(Instant::now());
                    if timings.hangup_asked.is_none() {
                        refused = Some(format!("the call ended before the hangup: {reason}"));
                    }
                }
                Event::Media {
                    call: started_call,
                    event: MediaEvent::Started { .. },
                } if Some(started_call) == call => media_started = true,
                _ => {}
            }
        }
        if registered && !placed {
            placed = true;
            let media = CallMedia::new(catalog(), MediaConfig::default());
            let outgoing = OutgoingCall::new(target.clone()).to_address(endpoint.transport, remote);
            match place_call(&mut endpoint, account, outgoing, media, remote, now) {
                Ok(placed_call) => call = Some(placed_call),
                Err(error) => {
                    refused = Some(format!("call: {error}"));
                    break;
                }
            }
        }
        if media_started
            && carried.is_none()
            && let Some(handle) = call
        {
            match carry_and_hang_up(&mut endpoint, handle, &mut timings) {
                Ok(engine) => carried = Some(engine),
                Err(why) => {
                    refused = Some(why);
                    let _ = endpoint.agent.hangup(handle, now);
                }
            }
        }
        if let Some((engine, fake)) = carried.as_mut() {
            note_settled(engine, fake, &mut timings);
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        if timings.ended.is_some() && (timings.open_settled.is_some() || carried.is_none()) {
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let opened = carried.as_ref().map_or(0, |(_, fake)| fake.units_opened());
    let alive = carried.as_ref().map_or(0, |(_, fake)| fake.units_alive());
    drop(carried);
    give_back(&mut endpoint, account);
    if let Some(why) = refused {
        return Err(why);
    }
    judge(&timings, endpoint.written.first_bye, opened, alive)
}

/// Hand `call` to an engine over fakes that open slowly, and hang it up at
/// once, in the order a stack does: the engine lets go of the call, then
/// the BYE is queued and written. Returns the engine and its fakes, for the
/// open that outlives the call to be watched.
fn carry_and_hang_up(
    endpoint: &mut Endpoint,
    call: CallHandle,
    timings: &mut Timings,
) -> Result<(Engine, FakeControl), String> {
    let socket = endpoint
        .media
        .get(&call)
        .ok_or("a call with no socket of its own")?
        .sender()?;
    let share = endpoint
        .engine
        .share(call)
        .ok_or("a call whose media is gone")?;
    let fake = FakeControl::new(DEVICE_HZ);
    fake.plug("speaker", "Speaker", 0, 2);
    fake.plug("microphone", "Microphone", 1, 0);
    fake.make_default("speaker", Direction::Output);
    fake.make_default("microphone", Direction::Input);
    fake.set_duplex_only(true);
    fake.forget_notices();
    fake.set_open_delay(Some(OPEN_DELAY));
    let sockets = HashMap::from([(CALL_ID, socket)]);
    let transmit = Box::new(move |id: CallId, packet: &Outgoing| {
        if let Some(socket) = sockets.get(&id) {
            let _ = socket.send_to(&packet.payload, packet.destination);
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

    let step = Instant::now();
    engine
        .attach(CALL_ID, Box::new(share))
        .map_err(|error| format!("the engine would not take the call: {error}"))?;
    timings.attach = Some(step.elapsed());
    if !engine.is_opening() {
        return Err("the engine took the call with no open under way".to_owned());
    }

    let asked = Instant::now();
    timings.hangup_asked = Some(asked);
    engine.detach(CALL_ID);
    timings.detach = Some(asked.elapsed());
    endpoint
        .agent
        .hangup(call, Instant::now())
        .map_err(|error| format!("hangup: {error}"))?;
    endpoint.flush();
    Ok((engine, fake))
}

/// Note the moment the open that outlived the call has brought its unit
/// back and had it let go of, with nothing left opening or closing.
fn note_settled(engine: &mut Engine, fake: &FakeControl, timings: &mut Timings) {
    if timings.open_settled.is_none()
        && fake.units_opened() > 0
        && fake.units_alive() == 0
        && !engine.is_opening()
        && !engine.is_closing()
    {
        timings.open_settled = Some(Instant::now());
    }
}

/// What the hangup has to have been: each step prompt, the call ended, and
/// the open that outlived it settled with nothing left open.
fn judge(
    timings: &Timings,
    first_bye: Option<Instant>,
    opened: usize,
    alive: usize,
) -> Result<String, String> {
    let (Some(attach), Some(detach), Some(asked)) =
        (timings.attach, timings.detach, timings.hangup_asked)
    else {
        return Err("the call never reached the engine".to_owned());
    };
    let bye = first_bye
        .map(|at| at.saturating_duration_since(asked))
        .ok_or("no BYE was written")?;
    let ended = timings
        .ended
        .map(|at| at.saturating_duration_since(asked))
        .ok_or("the call did not end")?;
    let settled = timings
        .open_settled
        .map(|at| at.saturating_duration_since(asked))
        .ok_or(format!(
            "the open that outlived the call never settled: {opened} units opened, {alive} still open"
        ))?;
    let said = format!(
        "   (attach {} ms, detach {} ms, the BYE on the wire {} ms after the hangup was asked, \
         the call ended {} ms after it; the open finished {} ms after it and its unit was let \
         go of, {opened} opened, {alive} open)",
        attach.as_millis(),
        detach.as_millis(),
        bye.as_millis(),
        ended.as_millis(),
        settled.as_millis()
    );
    for (step, took) in [
        ("the attach", attach),
        ("the detach", detach),
        ("the BYE", bye),
    ] {
        if took >= PROMPT {
            return Err(format!("{step} waited for the open{said}"));
        }
    }
    if settled < OPEN_DELAY / 2 {
        return Err(format!(
            "the open settled before the devices could have opened{said}"
        ));
    }
    Ok(said)
}
