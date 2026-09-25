// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A call whose microphone and earpiece are a Windows desktop's:
//! `sipral-io-wasapi` streams on real endpoints, the way a softphone on
//! Windows would reach them.
//!
//! This is `pipewire.rs`'s sibling, for the platform where the lab has no
//! containerised sound card at all — the room around the phone is a single
//! VB-CABLE, run on real hardware (`docs/11-testing.md` says which machine),
//! not a pair of virtual cables built fresh in a container.
//!
//! # One cable, not two
//!
//! `pipewire.rs`'s room has two cables: a mouth feeding a microphone, and an
//! earpiece feeding a monitor the room listens at. VB-CABLE's free edition
//! is one: "CABLE Input" is the render endpoint, "CABLE Output" the capture
//! side of the very same cable. Wiring the phone's earpiece to CABLE Input
//! and its microphone to CABLE Output, as this flow does, does not give the
//! room a mouth and an ear — it gives the phone's own earpiece and
//! microphone a direct physical loop, through the cable, back to each other.
//!
//! Against the echo extension that loop is the whole point rather than a
//! problem: nothing needs to inject anything into it round after round for
//! the call to keep carrying audio, because the cable is doing that. What it
//! cannot do on its own is start — until the earpiece has played something,
//! the capture side of the cable has nothing on it either. So this flow
//! seeds the loop the way the task that added it says to: for
//! [`SEED_FRAMES`] at the start of the call, a tone goes out on the call's
//! own send path directly (`MediaSession::capture`, the same call
//! `crate::audio::Media` makes from a real device's frame everywhere else in
//! this crate), not through the microphone. Once that seed has had time to
//! reach Asterisk and come back, the flow stops feeding the call synthetic
//! audio and reads the microphone instead, for the rest of the call. From
//! there the loop is
//! self-sustaining if and only if the whole path is real: call → decode →
//! [`Devices::earpiece`] → the physical cable → [`Devices::mic`] → encode →
//! call, round and round. A device layer that quietly did nothing would let
//! the seed itself be sent once and would then have nothing more to say —
//! this flow's verdict is read entirely from what the microphone captures
//! *after* the seed stops, which is exactly the part a no-op cannot fake.
//!
//! # A device runs at its own rate, not the call's
//!
//! Shared-mode WASAPI runs at whatever the audio engine mixes at — commonly
//! 48 kHz — never at the call's own 8 kHz (G.711) or 16 kHz (G.722), and
//! `sipral-io-wasapi` says so rather than hiding it: `PlaybackStream::format`
//! and `CaptureStream::format` report what a stream actually delivers, which
//! is not what [`Devices::open`] asked for. [`Devices::to_device`] and
//! [`Devices::from_device`] are `sipral-media`'s own resampler, one each way,
//! doing at this boundary exactly what a real softphone's audio layer does
//! at its own.

use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, UaEvent};
use sipral_io_wasapi::{
    CaptureStream, Device, DeviceId, Direction, PlaybackStream, StreamConfig, StreamFormat,
};
use sipral_media::resample::Resampler;

use crate::audio::{AUDIBLE, loudness, tone};
use crate::join::give_back;
use crate::{Endpoint, catalog, place_call, run_folded, uri};

/// `interop/asterisk/extensions.conf`'s `Answer(); Echo();`, the same
/// extension `pipewire.rs` calls.
const ECHO_EXTENSION: &str = "9008";

/// How long the flow may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(40);

/// How long the call runs once its devices are open.
const DWELL: Duration = Duration::from_secs(8);

/// How many frames, at the start of the call, the tone is written straight
/// onto the call's own send path rather than read from the microphone — a
/// count rather than a wall-clock window, because the first few turns of the
/// loop are whatever real device start-up and a real network round trip take
/// on the machine this actually runs on, not a fixed number of milliseconds;
/// gating on time let that first turn alone swallow the whole seed on a slow
/// start. One second's worth at twenty milliseconds a frame: comfortably
/// past both the echo extension's own answer and the earpiece's first
/// buffers filling, and past the transient a codec and two resample stages
/// need to settle into their steady state, without so long a seed that the
/// dwell has little left to prove the loop keeps carrying it unaided.
const SEED_FRAMES: u32 = 50;

/// This flow's own endpoint identity, folded with the run's own entropy
/// before anything binds with it (`run_folded`, `main.rs`). Listed in
/// `main.rs`'s `tests::endpoint_identity_constants_are_distinct` alongside
/// every other step's, so a value reused here or added later fails that
/// test rather than a live run.
pub(crate) const SEED: u8 = 14;
pub(crate) const MEDIA_SEED: u8 = 187;

/// Environment variable naming the earpiece endpoint's id exactly, when
/// [`is_vb_cable_endpoint`] below is not enough — two cables installed, say.
const EARPIECE_ID_ENV: &str = "SIPRAL_WASAPI_EARPIECE_ID";
/// Same, for the microphone endpoint.
const MIC_ID_ENV: &str = "SIPRAL_WASAPI_MIC_ID";
/// Environment variable naming the substring an output endpoint's name is
/// matched against, overriding [`is_vb_cable_endpoint`] entirely — a second,
/// unrelated cable installed, say, where the default rule would find two.
const EARPIECE_NAME_ENV: &str = "SIPRAL_WASAPI_EARPIECE_NAME";
/// Same, for the input endpoint.
const MIC_NAME_ENV: &str = "SIPRAL_WASAPI_MIC_NAME";

/// Frames loud enough to be the tone, captured from the microphone once the
/// seed has stopped, below which the loop is not proven: half a second's
/// worth at the twenty-millisecond frames this lab negotiates.
const HEARD_THRESHOLD: u32 = 25;

/// The tone is about 444 Hz (`crate::audio`), a square wave, so it crosses
/// zero about 888 times a second. What comes back has been through G.711 or
/// G.722, two resample stages each way (`Devices::to_device` and
/// `Devices::from_device`, on top of whatever `sipral-media` does for the
/// codec itself), an echo, and a real cable, and is allowed a wide margin
/// around that — measured on real hardware at 600 to 1500 a second across
/// several runs — but not so wide that noise or a stuck level passes.
const CROSSINGS_PER_SECOND: std::ops::RangeInclusive<u64> = 600..=1_500;

/// The phone's two streams, and what moves samples between the call's own
/// rate and whatever rate each of them actually runs at.
struct Devices {
    earpiece: PlaybackStream,
    mic: CaptureStream,
    /// The call's own format: what `session.playback`/`session.capture` give
    /// and expect, and what the seed tone is generated at.
    session_format: StreamFormat,
    /// A call frame, resampled to the earpiece's own delivered rate.
    to_device: Resampler,
    /// One microphone read, resampled to the call's own rate.
    from_device: Resampler,
    /// Session-rate samples `from_device` has produced but that do not yet
    /// add up to one whole call frame — carried over to the next read,
    /// because a microphone read and a call frame are different lengths at
    /// almost every ratio.
    mic_pending: Vec<i16>,
}

impl Devices {
    fn open(session_format: StreamFormat) -> Result<Self, String> {
        let earpiece_id = find_endpoint(Direction::Output, EARPIECE_ID_ENV, EARPIECE_NAME_ENV)?;
        let mic_id = find_endpoint(Direction::Input, MIC_ID_ENV, MIC_NAME_ENV)?;
        let open = |what: &str, error: sipral_io_wasapi::Error| format!("{what}: {error}");
        let mut earpiece = PlaybackStream::open(&StreamConfig::on(earpiece_id, session_format))
            .map_err(|error| open("earpiece", error))?;
        let mut mic = CaptureStream::open(&StreamConfig::on(mic_id, session_format))
            .map_err(|error| open("microphone", error))?;
        earpiece.start().map_err(|error| open("earpiece", error))?;
        mic.start().map_err(|error| open("microphone", error))?;

        let earpiece_rate = earpiece.format().sample_rate_hz();
        let mic_rate = mic.format().sample_rate_hz();
        let resample = |what: &str, from: u32, to: u32| {
            Resampler::new(from, to)
                .map_err(|error| format!("cannot resample {what} ({from} Hz to {to} Hz): {error}"))
        };
        let to_device = resample(
            "to the earpiece",
            session_format.sample_rate_hz(),
            earpiece_rate,
        )?;
        let from_device = resample(
            "from the microphone",
            mic_rate,
            session_format.sample_rate_hz(),
        )?;

        Ok(Self {
            earpiece,
            mic,
            session_format,
            to_device,
            from_device,
            mic_pending: Vec::new(),
        })
    }
}

/// True when an endpoint's own friendly name says it is one of VB-Audio's
/// cable endpoints, under either naming variant the driver ships under —
/// specific enough that a real speaker or a real microphone never matches
/// it by accident:
///
/// - the classic naming VB-CABLE's installer gives its own device
///   description: "CABLE Input" for the render side, "CABLE Output" for the
///   capture side of the same cable;
/// - the generic port class Windows falls back to when that description is
///   absent, with the audio interface's own friendly name in parentheses
///   instead — "Speakers (VB-Audio Virtual Cable)" and "Microphone
///   (VB-Audio Virtual Cable)" on the lab's own test machine, which is why
///   `SIPRAL_WASAPI_EARPIECE_ID` had to be set before this rule existed.
///
/// Direction is not decided here: [`find_endpoint`] already asks Windows for
/// the render or the capture list separately, so telling the two ends of the
/// cable apart is its job, not this predicate's — a real "Speakers" or
/// "Microphone" endpoint never carries "vb-audio", "cable input" or
/// "cable output" in its own name, so none of the three substrings needs the
/// direction to stay safe.
fn is_vb_cable_endpoint(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("vb-audio") || lower.contains("cable input") || lower.contains("cable output")
}

/// The one endpoint, in the given direction, that `name_env` singles out by
/// substring when it names one, or else the one [`is_vb_cable_endpoint`]
/// recognises — or, when `id_env` names one, exactly that endpoint,
/// unchecked against the machine's own list.
///
/// More than one endpoint can match the rule at once — this lab's own test
/// machine has both the free edition's cable and an unused paid edition's
/// extra render endpoint installed side by side, "CABLE In 16 Ch" among
/// them, and both carry "vb-audio" in their name — so a tie among them is
/// broken by which one, if only one, Windows' own "default communications"
/// setting already names for this direction: the same choice a person
/// setting this machine up by hand would reach for, and already recorded
/// for [`Device::is_default`] to read rather than guessed at here.
///
/// # Errors
/// No endpoint matches, more than one matches and no single one of those is
/// the communications default either, or the list itself could not be read;
/// every error names every endpoint this machine actually has in that
/// direction, so the fix is legible from the failure alone, without a
/// separate `-ListDevices` run.
fn find_endpoint(direction: Direction, id_env: &str, name_env: &str) -> Result<DeviceId, String> {
    if let Ok(id) = env::var(id_env)
        && !id.is_empty()
    {
        return Ok(DeviceId::new(id));
    }
    let all =
        sipral_io_wasapi::devices().map_err(|error| format!("cannot list endpoints: {error}"))?;
    let wanted = env::var(name_env).ok().filter(|name| !name.is_empty());
    let rule = |device: &&Device| {
        device.direction == direction
            && match &wanted {
                Some(substring) => device
                    .name
                    .to_lowercase()
                    .contains(&substring.to_lowercase()),
                None => is_vb_cable_endpoint(&device.name),
            }
    };
    let matching: Vec<&Device> = all.iter().filter(rule).collect();
    let chosen = match matching.as_slice() {
        [] => None,
        [only] => Some(*only),
        several => {
            let mut defaults = several.iter().copied().filter(|device| device.is_default);
            match (defaults.next(), defaults.next()) {
                (Some(only_default), None) => Some(only_default),
                _ => None,
            }
        }
    };
    let Some(chosen) = chosen else {
        return Err(format!(
            "no single {direction} endpoint {} — set {id_env} (or {name_env}) to the one to \
             use; this machine's {direction} endpoints:\n{}",
            rule_description(wanted.as_deref()),
            list_endpoints(&all, direction),
        ));
    };
    Ok(chosen.id.clone())
}

/// The clause an error names for why an endpoint was or was not picked.
fn rule_description(wanted: Option<&str>) -> String {
    match wanted {
        Some(substring) => format!("has \"{substring}\" in its name"),
        None => "is one of VB-Audio's cable endpoints".to_owned(),
    }
}

/// Every endpoint this machine has in the given direction, one per line.
fn list_endpoints(all: &[Device], direction: Direction) -> String {
    let mut lines: Vec<String> = all
        .iter()
        .filter(|device| device.direction == direction)
        .map(|device| format!("  {device}"))
        .collect();
    if lines.is_empty() {
        lines.push("  (none)".to_owned());
    }
    lines.join("\n")
}

/// What crossed each stream.
#[derive(Debug, Default)]
struct Tally {
    /// Frames written onto the call's send path directly, while
    /// [`SEED_FRAMES`] was still being sent.
    seeded: u32,
    /// Frames the earpiece took, seed or looped audio alike.
    played: u32,
    /// Frames the microphone delivered, seed window included.
    captured: u32,
    /// Packets sent on the call from a frame the microphone actually
    /// delivered — never counts a seed frame.
    sent: u32,
    /// Call frames built from resampled microphone audio once the seed had
    /// stopped, and how many were loud enough to be the tone. This, and the
    /// samples and zero crossings below it, is the whole of what proves the
    /// cable: nothing feeds the call after [`SEED_FRAMES`] except what came
    /// out of a real [`CaptureStream::read`].
    looped: u32,
    looped_audible: u32,
    audible_samples: u64,
    crossings: u64,
    /// The call's own sample rate, once its session has one — needed only to
    /// turn [`Tally::crossings`] into a per-second rate in [`verdict`].
    rate: u32,
}

/// Run the flow if `wanted` names it and the server is the one with the
/// echo extension, print its verdict the way every other flow's is printed,
/// and say whether it passed. A run that did not ask for it passes.
///
/// Unlike `pipewire::flow`, this does not also require `server == "asterisk"`:
/// `interop/wasapi/run.ps1` runs from a Windows machine outside the lab's own
/// Docker network, which cannot resolve that hostname, so it gives `server`
/// as the lab host's own LAN address instead. [`ECHO_EXTENSION`] is dialled
/// regardless of what `server` says, and nothing else here reads it as
/// anything but where to send the SIP messages, so the address is enough —
/// `wanted` naming this flow is what makes it opt-in.
pub(crate) fn flow(server: &str, remote: SocketAddr, user: &str, pass: &str, wanted: &str) -> bool {
    if !wanted.split(',').any(|name| name.trim() == "wasapi") {
        return true;
    }
    match run(server, remote, user, pass) {
        Ok(said) => {
            println!("  pass  a call on WASAPI's devices{said}");
            true
        }
        Err(why) => {
            println!("  FAIL  a call on WASAPI's devices — {why}");
            false
        }
    }
}

/// Register, call the echo extension, and carry the call on WASAPI's
/// devices until the loop has had time to prove itself.
///
/// # Errors
/// The first condition that did not hold, the same shape every other flow in
/// this table reports.
fn run(server: &str, remote: SocketAddr, user: &str, pass: &str) -> Result<String, String> {
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
    let target = uri(&format!("sip:{ECHO_EXTENSION}@{server}"))?;

    let mut asked_to_register = false;
    let mut registered = false;
    let mut call: Option<CallHandle> = None;
    let mut placed = false;
    let mut ended = false;
    let mut hung_up = false;
    let mut devices: Option<Devices> = None;
    let mut opened_at = now;
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
                            tally.rate = opened.session_format.sample_rate_hz();
                            devices = Some(opened);
                            opened_at = now;
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
            carry(&mut endpoint, handle, open, &mut tally, &mut phase, now);
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
    verdict(&tally)
}

/// The call's own format, once its session has one, and the two streams
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

/// The phone, one tick: the earpiece always plays what the call brought in;
/// what feeds the call is a seed tone written straight onto the send path
/// for [`SEED_FRAMES`], and the real microphone once that many have gone
/// out.
fn carry(
    endpoint: &mut Endpoint,
    call: CallHandle,
    devices: &mut Devices,
    tally: &mut Tally,
    phase: &mut u32,
    now: Instant,
) {
    let (Some(mut session), Some(media)) =
        (endpoint.engine.session(call), endpoint.media.get_mut(&call))
    else {
        return;
    };
    media.receive_into(&mut session, now);

    let session_len = devices.session_format.frame_samples();
    let seeding = tally.seeded < SEED_FRAMES;

    // Earpiece: one call frame at a time, resampled up (or down) to
    // whatever rate the endpoint actually delivers at, before it goes to a
    // device that never asked for the call's own rate.
    let device_len = devices.to_device.output_capacity(session_len);
    let mut device_frame = vec![0_i16; device_len];
    while devices.earpiece.room() >= device_len {
        let mut session_frame = vec![0_i16; session_len];
        session.playback(&mut session_frame);
        let Ok(produced) = devices.to_device.process(&session_frame, &mut device_frame) else {
            break;
        };
        let Some(written) = device_frame.get(..produced) else {
            break;
        };
        if !devices.earpiece.write(written) {
            break;
        }
        tally.played = tally.played.saturating_add(1);
    }

    if seeding {
        let mut seed_frame = vec![0_i16; session_len];
        tone(
            &mut seed_frame,
            phase,
            devices.session_format.sample_rate_hz(),
        );
        if let Ok(Some(datagram)) = session.capture(&seed_frame, now) {
            media.send(datagram.destination, datagram.payload);
            tally.seeded = tally.seeded.saturating_add(1);
        }
    }

    // Microphone: one endpoint period at a time, at whatever rate it
    // actually delivers, resampled down (or up) to the call's own rate and
    // chunked into call-frame-sized pieces — a device period and a call
    // frame are different lengths at almost every ratio, so what
    // `from_device` produces from one read almost never lands on a call
    // frame's own boundary.
    //
    // Read every tick, seed window included, so the ring never overflows
    // and `tally.captured` always says what the real device actually saw;
    // while seeding, what comes out is resampled and then thrown away
    // rather than queued, so the backlog a seed window's worth of reads
    // would otherwise leave never arrives as a sudden burst once it ends.
    let mic_len = devices.mic.format().frame_samples();
    let mut mic_frame = vec![0_i16; mic_len];
    while devices.mic.read(&mut mic_frame) {
        tally.captured = tally.captured.saturating_add(1);
        if seeding {
            continue;
        }
        let resampled_len = devices.from_device.output_capacity(mic_frame.len());
        let mut resampled = vec![0_i16; resampled_len];
        let Ok(produced) = devices.from_device.process(&mic_frame, &mut resampled) else {
            continue;
        };
        let Some(fresh) = resampled.get(..produced) else {
            continue;
        };
        devices.mic_pending.extend_from_slice(fresh);
        while devices.mic_pending.len() >= session_len {
            let chunk: Vec<i16> = devices.mic_pending.drain(..session_len).collect();
            tally.looped = tally.looped.saturating_add(1);
            if loudness(&chunk) >= AUDIBLE {
                tally.looped_audible = tally.looped_audible.saturating_add(1);
                tally.audible_samples = tally
                    .audible_samples
                    .saturating_add(u64::try_from(chunk.len()).unwrap_or(0));
                let crossings = chunk
                    .windows(2)
                    .filter(|pair| matches!(pair, [a, b] if (*a >= 0) != (*b >= 0)))
                    .count();
                tally.crossings = tally
                    .crossings
                    .saturating_add(u64::try_from(crossings).unwrap_or(0));
            }
            if let Ok(Some(datagram)) = session.capture(&chunk, now) {
                media.send(datagram.destination, datagram.payload);
                tally.sent = tally.sent.saturating_add(1);
            }
        }
    }
}

/// Carry whatever the engine queued on the call's behalf that is not a
/// frame: reports, the goodbye, handshake records — `pipewire.rs`'s own
/// `drain` does the same thing, for the same reason.
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

fn verdict(tally: &Tally) -> Result<String, String> {
    let rate = if tally.rate == 0 { 8_000 } else { tally.rate };
    let pitch = (tally.crossings * u64::from(rate))
        .checked_div(tally.audible_samples)
        .unwrap_or(0);
    let numbers = format!(
        "{} seed frame(s) sent, {} frame(s) to the earpiece, {} out of the microphone; once the \
         seed stopped: {} frame(s) sent from it, {} out of the microphone ({} the tone, {pitch} \
         zero crossings a second)",
        tally.seeded, tally.played, tally.captured, tally.sent, tally.looped, tally.looped_audible,
    );
    if tally.seeded == 0 {
        return Err(format!("the seed was never sent: {numbers}"));
    }
    if tally.played == 0 {
        return Err(format!("the earpiece never played anything: {numbers}"));
    }
    if tally.looped_audible < HEARD_THRESHOLD {
        return Err(format!(
            "the tone never came back around the cable once the seed itself stopped: {numbers}"
        ));
    }
    if !CROSSINGS_PER_SECOND.contains(&pitch) {
        return Err(format!(
            "what the microphone heard once the seed stopped is not the tone's pitch: {numbers}"
        ));
    }
    Ok(format!("   ({numbers})"))
}
