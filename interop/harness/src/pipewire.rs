// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A call whose microphone and earpiece are a Linux desktop's: PipeWire
//! nodes, reached through `sipral-io-pipewire`, the way a softphone on Linux
//! would reach them.
//!
//! Every other flow in this table plays the part of the device itself — a
//! tone written straight into `MediaSession::capture`, frames taken out of
//! `MediaSession::playback` and counted. This one hands both ends to real
//! device streams on a real graph and lets the graph's clock pace the call,
//! which is the half of an application no other flow here exercises: frames
//! arriving when a source has them rather than when a timer says, and an
//! earpiece that takes a frame when it has room for one.
//!
//! # The room
//!
//! `interop/pipewire/run.sh` builds the graph this needs, in a container with
//! no sound card: two mono virtual cables, each a sink whose samples come
//! straight out of a source. This flow is both the phone and the room around
//! it:
//!
//! - the room speaks into the phone: a cadenced tone (`crate::audio::tone`,
//!   the same one every other flow sends) is played into [`MOUTH`], and the
//!   phone's microphone is a capture stream on [`MIC`], the other end of
//!   that cable;
//! - the call goes to the lab's echo extension, which sends back what it is
//!   sent;
//! - the phone's earpiece is a playback stream on [`EAR`], and the room
//!   listens at [`EAR_MONITOR`], the other end of that cable.
//!
//! The only way the tone reaches [`EAR_MONITOR`] is the whole path: into
//! PipeWire, out of it through the microphone stream, encoded, across the
//! network to Asterisk and back, decoded, into PipeWire again through the
//! earpiece stream, and out. The two cables are not connected to each other.
//! So the verdict is read where a person would read it — at the ear — and it
//! asks for the tone's own pitch there, not merely for sound.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, UaEvent};
use sipral_io_pipewire::{
    CaptureStream, DeviceId, PlaybackStream, RenderDelay, StreamConfig, StreamFormat,
};

use crate::audio::{AUDIBLE, in_spurt, loudness, tone};
use crate::join::give_back;
use crate::{Endpoint, catalog, place_call, uri};

/// The room's mouth: the sink the tone is played into.
const MOUTH: &str = "sipral-mouth";
/// The phone's microphone: the source at the other end of [`MOUTH`]'s cable.
const MIC: &str = "sipral-mic";
/// The phone's earpiece: the sink the call's audio is played into.
const EAR: &str = "sipral-ear";
/// The room's ear: the source at the other end of [`EAR`]'s cable.
const EAR_MONITOR: &str = "sipral-ear-monitor";

/// `interop/asterisk/extensions.conf`'s `Answer(); Echo();`.
const ECHO_EXTENSION: &str = "9008";

/// How long the flow may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(40);

/// How long the call runs once its devices are open: several turns of the
/// tone's cadence, there and back.
const DWELL: Duration = Duration::from_secs(8);

/// How often the room speaks a frame into [`MOUTH`].
const PACE: Duration = Duration::from_millis(20);

/// Frames of slack in the phone's own two streams. A device-paced earpiece
/// takes a frame from the jitter buffer whenever its ring has room, so this
/// is also how far ahead of the sink the call's playback runs: kept short, a
/// real softphone's number rather than a test's.
const PHONE_DEPTH_FRAMES: usize = 4;

/// Frames loud enough to be the tone, heard at [`EAR_MONITOR`], below which
/// the crossing is not proven: half a second's worth.
const HEARD_THRESHOLD: u32 = 25;

/// The tone is about 444 Hz (`crate::audio`), a square wave, so it crosses
/// zero about 888 times a second. What comes back has been through G.711 or
/// G.722, a resampler or two and an echo, and is allowed a wide margin
/// around that — but not so wide that noise or a stuck level passes.
const CROSSINGS_PER_SECOND: std::ops::RangeInclusive<u64> = 700..=1_100;

/// The four streams: the phone's two, and the room's two.
struct Devices {
    mouth: PlaybackStream,
    mic: CaptureStream,
    ear: PlaybackStream,
    monitor: CaptureStream,
    format: StreamFormat,
}

impl Devices {
    fn open(format: StreamFormat) -> Result<Self, String> {
        let phone = |node: &str| StreamConfig {
            depth_frames: PHONE_DEPTH_FRAMES,
            ..StreamConfig::on(DeviceId::new(node), format)
        };
        let room = |node: &str| StreamConfig::on(DeviceId::new(node), format);
        let open = |what: &str, error: sipral_io_pipewire::Error| format!("{what}: {error}");
        let mut devices = Self {
            mouth: PlaybackStream::open(&room(MOUTH)).map_err(|error| open(MOUTH, error))?,
            mic: CaptureStream::open(&phone(MIC)).map_err(|error| open(MIC, error))?,
            ear: PlaybackStream::open(&phone(EAR)).map_err(|error| open(EAR, error))?,
            monitor: CaptureStream::open(&room(EAR_MONITOR))
                .map_err(|error| open(EAR_MONITOR, error))?,
            format,
        };
        devices.mouth.start().map_err(|error| open(MOUTH, error))?;
        devices.mic.start().map_err(|error| open(MIC, error))?;
        devices.ear.start().map_err(|error| open(EAR, error))?;
        devices
            .monitor
            .start()
            .map_err(|error| open(EAR_MONITOR, error))?;
        Ok(devices)
    }
}

/// What crossed each stream.
#[derive(Debug, Default)]
struct Tally {
    /// Frames the room played into [`MOUTH`].
    spoken: u32,
    /// Frames the phone's microphone delivered, and how many were the tone.
    captured: u32,
    captured_audible: u32,
    /// Packets the call sent.
    sent: u32,
    /// Frames the phone's earpiece took.
    played: u32,
    /// Frames the room heard at [`EAR_MONITOR`], how many were the tone, and
    /// over those, how many samples and zero crossings.
    heard: u32,
    heard_audible: u32,
    audible_samples: u64,
    crossings: u64,
}

/// Run the flow if `wanted` names it and the server is the one with the
/// echo extension, print its verdict the way every other flow's is printed,
/// and say whether it passed. A run that did not ask for it passes.
///
/// Only when named, unlike the flows `main` runs when nothing is named: it
/// needs the virtual cables `interop/pipewire/run.sh` makes, which no other
/// run of this harness has.
pub(crate) fn flow(server: &str, remote: SocketAddr, user: &str, pass: &str, wanted: &str) -> bool {
    if server != "asterisk" || !wanted.split(',').any(|name| name.trim() == "pipewire") {
        return true;
    }
    match run(server, remote, user, pass) {
        Ok(said) => {
            println!("  pass  a call on PipeWire's devices{said}");
            true
        }
        Err(why) => {
            println!("  FAIL  a call on PipeWire's devices — {why}");
            false
        }
    }
}

/// Register, call the echo extension, and carry the call on PipeWire's
/// devices until the tone has had time to go round.
///
/// # Errors
/// The first condition that did not hold, the same shape every other flow in
/// this table reports.
fn run(server: &str, remote: SocketAddr, user: &str, pass: &str) -> Result<String, String> {
    let bind_addr = SocketAddr::new(crate::route_to(remote), 0);
    let now = Instant::now();
    // distinct from every seed the other flows use, so no two of them mint
    // the same branch
    let mut endpoint = Endpoint::bind([191; 32], [197; 32], bind_addr, catalog(), now)
        .map_err(|error| format!("cannot bind: {error}"))?;
    let account = endpoint.account(user, pass, server, remote)?;
    let target = uri(&format!("sip:{ECHO_EXTENSION}@{server}"))?;

    let mut asked_to_register = false;
    let mut registered = false;
    let mut call: Option<CallHandle> = None;
    let mut placed = false;
    let mut ended = false;
    let mut hung_up = false;
    let mut devices: Option<Devices> = None;
    let mut opened_at = now;
    let mut next_spoken = now;
    let mut phase = 0_u32;
    let mut tally = Tally::default();
    let mut failure = None;

    let started = Instant::now();
    loop {
        let now = Instant::now();
        if now > started + PATIENCE {
            failure = Some(format!(
                "the call never finished: registered {registered}, placed {placed}, \
                 devices open {}",
                devices.is_some()
            ));
            break;
        }
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) => registered = true,
                Event::Signalling(UaEvent::CallEnded {
                    call: ended_call, ..
                }) if Some(ended_call) == call => {
                    ended = true;
                }
                Event::Media {
                    call: started_call,
                    event: MediaEvent::Started { .. },
                } if Some(started_call) == call && devices.is_none() && failure.is_none() => {
                    match devices_for(&mut endpoint, started_call) {
                        Ok(opened) => {
                            devices = Some(opened);
                            opened_at = now;
                            next_spoken = now;
                        }
                        Err(why) => failure = Some(format!("the devices would not open: {why}")),
                    }
                }
                _ => {}
            }
        }
        if !asked_to_register {
            asked_to_register = true;
            let _ = endpoint.agent.register(account, now);
        }
        if registered && !placed {
            placed = true;
            let media = CallMedia::new(catalog(), MediaConfig::default());
            let outgoing = OutgoingCall::new(target.clone()).to_address(endpoint.transport, remote);
            call = place_call(&mut endpoint, account, outgoing, media, remote, now).ok();
            if call.is_none() {
                failure = Some("the call could not be placed".to_owned());
            }
        }

        if let (Some(handle), Some(open)) = (call, devices.as_mut()) {
            let elapsed = now.saturating_duration_since(opened_at);
            while now >= next_spoken {
                speak(open, &mut phase, elapsed, &mut tally);
                next_spoken += PACE;
            }
            carry(&mut endpoint, handle, open, &mut tally, now);
            listen(open, &mut tally);
        }
        drain(&mut endpoint, now);

        let done = failure.is_some()
            || devices.is_some() && now.saturating_duration_since(opened_at) >= DWELL;
        if done && !hung_up {
            hung_up = true;
            if let Some(handle) = call {
                let _ = endpoint.agent.hangup(handle, now);
            }
        }
        endpoint.timers(now);
        if ended || (hung_up && call.is_none()) {
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    give_back(&mut endpoint, account);
    if let Some(why) = failure {
        return Err(why);
    }
    verdict(&tally, devices.as_ref())
}

/// The call's own format, once its session has one, and the four streams
/// opened at it.
fn devices_for(endpoint: &mut Endpoint, call: CallHandle) -> Result<Devices, String> {
    endpoint
        .engine
        .session(call)
        .and_then(|session| {
            let frame = u32::try_from(session.frame_samples()).ok()?;
            StreamFormat::new(session.sample_rate(), frame)
        })
        .ok_or_else(|| "the call's session has no usable format".to_owned())
        .and_then(Devices::open)
}

/// The room speaks one frame into [`MOUTH`]: the tone while its cadence says
/// so, silence between.
fn speak(devices: &mut Devices, phase: &mut u32, elapsed: Duration, tally: &mut Tally) {
    let mut frame = vec![0_i16; devices.format.frame_samples()];
    if in_spurt(elapsed) {
        tone(&mut frame, phase, devices.format.sample_rate_hz());
    }
    if devices.mouth.write(&frame) {
        tally.spoken = tally.spoken.saturating_add(1);
    }
}

/// The phone: what the microphone has goes out on the call, what the call
/// brought in goes to the earpiece — each at its device's own pace.
fn carry(
    endpoint: &mut Endpoint,
    call: CallHandle,
    devices: &mut Devices,
    tally: &mut Tally,
    now: Instant,
) {
    let (Some(mut session), Some(media)) =
        (endpoint.engine.session(call), endpoint.media.get_mut(&call))
    else {
        return;
    };
    media.receive_into(&mut session, now);
    let mut frame = vec![0_i16; devices.format.frame_samples()];
    while devices.mic.read(&mut frame) {
        tally.captured = tally.captured.saturating_add(1);
        if loudness(&frame) >= AUDIBLE {
            tally.captured_audible = tally.captured_audible.saturating_add(1);
        }
        if let Ok(Some(datagram)) = session.capture(&frame, now) {
            media.send(datagram.destination, datagram.payload);
            tally.sent = tally.sent.saturating_add(1);
        }
    }
    while devices.ear.room() >= frame.len() {
        session.playback(&mut frame);
        if !devices.ear.write(&frame) {
            break;
        }
        tally.played = tally.played.saturating_add(1);
    }
}

/// The room listens at [`EAR_MONITOR`] to what the earpiece played.
fn listen(devices: &mut Devices, tally: &mut Tally) {
    let mut frame = vec![0_i16; devices.format.frame_samples()];
    while devices.monitor.read(&mut frame) {
        tally.heard = tally.heard.saturating_add(1);
        if loudness(&frame) >= AUDIBLE {
            tally.heard_audible = tally.heard_audible.saturating_add(1);
            tally.audible_samples = tally
                .audible_samples
                .saturating_add(u64::try_from(frame.len()).unwrap_or(0));
            let crossings = frame
                .windows(2)
                .filter(|pair| matches!(pair, [a, b] if (*a >= 0) != (*b >= 0)))
                .count();
            tally.crossings = tally
                .crossings
                .saturating_add(u64::try_from(crossings).unwrap_or(0));
        }
    }
}

/// Carry whatever the engine queued on the call's behalf that is not a
/// frame: reports, the goodbye, handshake records. `Endpoint::run_media`
/// does this too, but it also drives every call's audio from a timer, which
/// is the one thing this flow hands to the devices instead.
fn drain(endpoint: &mut Endpoint, now: Instant) {
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

fn verdict(tally: &Tally, devices: Option<&Devices>) -> Result<String, String> {
    let rate = devices.map_or(8_000, |open| open.format.sample_rate_hz());
    let delay: Option<RenderDelay> = devices.map(|open| open.mic.render_delay(&open.ear));
    let counters = devices.map(|open| (open.mic.counters(), open.ear.counters()));
    let pitch = (tally.crossings * u64::from(rate))
        .checked_div(tally.audible_samples)
        .unwrap_or(0);
    let numbers = format!(
        "{} frame(s) into the room, {} out of the microphone ({} the tone), {} packet(s) sent; \
         {} frame(s) to the earpiece, {} heard back in the room ({} the tone, {pitch} zero \
         crossings a second){}{}",
        tally.spoken,
        tally.captured,
        tally.captured_audible,
        tally.sent,
        tally.played,
        tally.heard,
        tally.heard_audible,
        delay.map_or_else(String::new, |delay| format!(
            "; render delay {:?}",
            delay.total()
        )),
        counters.map_or_else(String::new, |(mic, ear)| format!(
            "; microphone {mic}; earpiece {ear}"
        )),
    );
    if tally.captured_audible == 0 {
        return Err(format!(
            "the microphone never heard the room's tone: {numbers}"
        ));
    }
    if tally.sent == 0 {
        return Err(format!("nothing was sent: {numbers}"));
    }
    if tally.heard_audible < HEARD_THRESHOLD {
        return Err(format!(
            "the tone did not come back to the room through the earpiece: {numbers}"
        ));
    }
    if !CROSSINGS_PER_SECOND.contains(&pitch) {
        return Err(format!(
            "what came back to the room is not the tone's pitch: {numbers}"
        ));
    }
    Ok(format!("   ({numbers})"))
}
