// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The engine's rules, each against the fake platform.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::backend::BackendError;
use crate::device::{Change, DeviceHandle, Direction, Origin, Role, SelectError, Selection};
use crate::engine::{Activation, Config, Engine};
use crate::fake::{FakeCallControl, FakeControl};
use crate::{CallId, Gain, Outgoing};

const RATE: u32 = 48_000;

fn destination() -> SocketAddr {
    "203.0.113.5:41000".parse().unwrap()
}

/// What the pump sent, gathered from its thread.
type Sent = Arc<Mutex<Vec<(CallId, Outgoing)>>>;

fn engine_with(activation: Activation, fake: &FakeControl) -> (Engine, Sent) {
    let sent: Sent = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&sent);
    let engine = Engine::new(
        fake.backend(),
        Config {
            activation,
            probe_wait: Duration::from_millis(200),
            device_rate_hz: RATE,
        },
        Box::new(move |id, packet| recorded.lock().unwrap().push((id, packet))),
        Arc::new(Instant::now),
    );
    (engine, sent)
}

/// A platform with a headset (in and out), the machine's own speaker (out
/// only) and a webcam microphone (in only), the built-in ones the defaults.
fn a_desk() -> FakeControl {
    let fake = FakeControl::new(RATE);
    fake.plug("builtin-out", "Built-in Output", 0, 2);
    fake.plug("builtin-mic", "Built-in Microphone", 1, 0);
    fake.plug("headset", "USB Headset", 1, 2);
    fake.plug("webcam", "Webcam", 2, 0);
    fake.make_default("builtin-out", Direction::Output);
    fake.make_default("builtin-mic", Direction::Input);
    fake.forget_notices();
    fake
}

fn handle_of(engine: &Engine, identity: &str) -> DeviceHandle {
    engine
        .devices()
        .iter()
        .find(|device| device.identity == identity)
        .map_or_else(
            || panic!("{identity} is not listed"),
            |device| device.handle,
        )
}

fn drain(engine: &mut Engine) -> Vec<Change> {
    let mut changes = Vec::new();
    while let Some(event) = engine.poll_event() {
        changes.push(event.change);
    }
    changes
}

fn wait_ticks(engine: &Engine, ticks: u64) {
    let from = engine.ticks();
    let started = Instant::now();
    while engine.ticks() < from + ticks {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the pump stopped ticking"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

// -- the list ---------------------------------------------------------------

#[test]
fn a_refresh_lists_every_device_with_its_channels_and_defaults() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    let listed = engine.refresh().unwrap().to_vec();
    assert_eq!(listed.len(), 4);
    let headset = listed.iter().find(|d| d.identity == "headset").unwrap();
    assert_eq!((headset.input_channels, headset.output_channels), (1, 2));
    assert!(headset.present && !headset.default_output && !headset.default_input);
    let out = listed.iter().find(|d| d.identity == "builtin-out").unwrap();
    assert!(out.default_output);
    let mic = listed.iter().find(|d| d.identity == "builtin-mic").unwrap();
    assert!(mic.default_input);
}

/// B1: the handle a device was given is the handle it keeps, through any
/// number of refreshes and through being unplugged and plugged back.
#[test]
fn a_refresh_keeps_every_handle_and_a_replugged_device_gets_its_old_one_back() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    let webcam = handle_of(&engine, "webcam");

    fake.unplug("headset");
    engine.refresh().unwrap();
    let gone = engine.device(headset).expect("the row stays");
    assert!(
        !gone.present,
        "an unplugged device is marked absent, not dropped"
    );
    assert_eq!(
        handle_of(&engine, "webcam"),
        webcam,
        "the others did not move"
    );

    fake.plug("headset", "USB Headset", 1, 2);
    fake.plug("second", "Second Headset", 1, 2);
    engine.refresh().unwrap();
    assert_eq!(
        handle_of(&engine, "headset"),
        headset,
        "the same identity, the same handle"
    );
    assert!(engine.device(headset).unwrap().present);
    let second = handle_of(&engine, "second");
    assert!(
        second > webcam && second > headset,
        "a new device gets a new number"
    );
}

/// B1, the half about a running stream: rebuilding the list under a role
/// that is running does not touch what it is running on.
#[test]
fn a_refresh_does_not_reopen_a_role_that_is_running() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    engine.activate().unwrap();
    let opened = fake.opens();
    drain(&mut engine);
    fake.plug("late", "Late Arrival", 0, 2);
    engine.refresh().unwrap();
    engine.service();
    assert_eq!(fake.opens(), opened, "nothing was reopened by a refresh");
    assert_eq!(engine.running_on(Role::Speaker), Some(headset));
    assert!(drain(&mut engine).contains(&Change::ListChanged));
}

/// B2: a device with no channels in a direction is in the list, says so, and
/// cannot be chosen for that direction.
#[test]
fn a_device_with_no_channels_in_a_direction_is_listed_and_refused_for_it() {
    let fake = a_desk();
    fake.plug("orphan", "Orphaned Device", 0, 0);
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let out = handle_of(&engine, "builtin-out");
    let orphan = handle_of(&engine, "orphan");
    assert_eq!(
        engine.select(Role::Microphone, Selection::Device(out)),
        Err(SelectError::NoChannels)
    );
    assert_eq!(
        engine.select(Role::Speaker, Selection::Device(orphan)),
        Err(SelectError::NoChannels)
    );
    assert_eq!(
        engine.select(Role::Microphone, Selection::Device(orphan)),
        Err(SelectError::NoChannels)
    );
    assert_eq!(
        engine.selection(Role::Microphone),
        Selection::System,
        "a refused selection changes nothing"
    );
    assert_eq!(engine.select(Role::Speaker, Selection::Device(out)), Ok(()));
}

/// B3: a handle the engine never issued is refused before the platform is
/// asked anything.
#[test]
fn an_unknown_handle_is_refused_without_a_platform_call() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    fake.hang();
    let bogus = DeviceHandle::new(999).unwrap();
    let started = Instant::now();
    assert_eq!(
        engine.select(Role::Speaker, Selection::Device(bogus)),
        Err(SelectError::NoSuchDevice)
    );
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "the platform was not asked"
    );
    fake.release();
}

/// An unplugged device is refused rather than opened and lost.
#[test]
fn an_absent_device_is_refused() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    fake.unplug("headset");
    engine.refresh().unwrap();
    assert_eq!(
        engine.select(Role::Speaker, Selection::Device(headset)),
        Err(SelectError::Absent)
    );
}

// -- selection and what the system does ------------------------------------

/// B4: the engine's own change and the system's are told apart, and a role
/// the application put on a device does not follow the default.
#[test]
fn a_selection_is_the_engines_change_and_the_default_moving_is_the_systems() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    engine.activate().unwrap();
    drain(&mut engine);
    let headset = handle_of(&engine, "headset");

    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    let selected = engine.poll_event().unwrap();
    assert_eq!(selected.change, Change::Selected(Role::Speaker));
    assert_eq!(selected.origin, Origin::Engine);
    assert_eq!(selected.device, Some(headset));
    assert_eq!(engine.running_on(Role::Speaker), Some(headset));

    // the system moves its default output: the speaker, put on the headset
    // by the application, stays there; the microphone, which follows the
    // system, moves with it
    fake.plug("dock", "Docking Station", 1, 2);
    fake.make_default("dock", Direction::Output);
    fake.make_default("dock", Direction::Input);
    let opens_before = fake.opens();
    engine.service();
    let changes: Vec<_> = {
        let mut all = Vec::new();
        while let Some(event) = engine.poll_event() {
            all.push(event);
        }
        all
    };
    assert!(changes.iter().any(
        |e| e.change == Change::DefaultChanged(Direction::Output) && e.origin == Origin::System
    ));
    assert!(
        changes
            .iter()
            .any(|e| e.change == Change::Reopened(Role::Microphone) && e.origin == Origin::System)
    );
    assert!(
        !changes
            .iter()
            .any(|e| e.change == Change::Reopened(Role::Speaker)),
        "the speaker was not moved: {changes:?}"
    );
    assert_eq!(engine.running_on(Role::Speaker), Some(headset));
    assert_eq!(
        engine.running_on(Role::Microphone),
        Some(handle_of(&engine, "dock"))
    );
    assert_eq!(
        fake.opens(),
        opens_before + 1,
        "one stream reopened, the microphone's"
    );
}

/// B5: gain and mute belong to the direction, not to the stream, and are
/// still set after the device changes under it.
#[test]
fn gain_and_mute_survive_a_device_change() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    engine.set_gain(Direction::Output, Gain::from_ratio(0.5));
    engine.set_muted(Direction::Input, true);
    engine.activate().unwrap();
    let call = FakeCallControl::new(8_000, 8_000, destination());
    engine.attach(1, call.call()).unwrap();
    let headset = handle_of(&engine, "headset");
    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    engine
        .select(Role::Microphone, Selection::Device(headset))
        .unwrap();
    wait_ticks(&engine, 3);
    for _ in 0..5 {
        fake.speak_into("headset", &[10_000; 960]);
    }
    wait_ticks(&engine, 3);

    assert_eq!(engine.gain(Direction::Output), Gain::from_ratio(0.5));
    assert!(engine.is_muted(Direction::Input));
    let played = fake.played_by("headset");
    assert!(played.len() >= 960 * 2, "the headset played something");
    // past the resampler's settling, which is the first few samples of a
    // step from silence
    let tail = &played[played.len() - 480..];
    assert!(
        tail.iter().all(|s| (*s - 4_000).abs() < 100),
        "the call's 8000 was halved on the new device: {:?}",
        &tail[..4]
    );
    let captured = call.captured();
    assert!(
        !captured.is_empty(),
        "the microphone frame reached the call"
    );
    assert!(
        captured.iter().flatten().all(|s| *s == 0),
        "the muted microphone gave silence"
    );
}

/// B6: the ring goes to the ringer's device, which is another output than
/// the call's.
#[test]
fn the_ring_plays_on_the_ringer_and_not_on_the_call_speaker() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    let builtin = handle_of(&engine, "builtin-out");
    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    engine
        .select(Role::Ringer, Selection::Device(builtin))
        .unwrap();
    assert!(!engine.is_active(), "nothing to do yet");
    engine.ring(vec![1_000; 800], 8_000, true).unwrap();
    assert!(engine.is_active() && engine.is_ringing());
    assert_eq!(
        fake.ringer_opens(),
        1,
        "the ringer's stream was opened as a ring, not as a second call output"
    );
    wait_ticks(&engine, 4);
    let room = fake.played_by("builtin-out");
    assert!(room.iter().any(|s| *s != 0), "the room speaker rang");
    assert!(
        fake.played_by("headset").iter().all(|s| *s == 0),
        "the headset did not"
    );
    engine.stop_ringing();
    assert!(
        !engine.is_active(),
        "with no call and no ring the devices are closed"
    );
}

/// The ring with no ringer of its own goes through the call's speaker.
#[test]
fn the_ring_without_a_ringer_of_its_own_goes_to_the_speaker() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    engine.ring(vec![500; 160], 8_000, false).unwrap();
    wait_ticks(&engine, 4);
    let played = fake.played_by("builtin-out");
    assert!(played.iter().any(|s| *s != 0));
    // a ring that was not looped ends by itself, and the devices with it
    let started = Instant::now();
    while engine.is_ringing() && started.elapsed() < Duration::from_secs(2) {
        engine.service();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!engine.is_ringing());
    assert!(!engine.is_active());
}

/// B7: under manual activation the calls do not open or close anything.
#[test]
fn manual_activation_is_decoupled_from_the_calls() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let call = FakeCallControl::new(8_000, 0, destination());
    engine.attach(1, call.call()).unwrap();
    assert!(
        !engine.is_active(),
        "a call attached does not open the devices"
    );
    assert_eq!(fake.opens(), 0);
    engine.activate().unwrap();
    assert!(engine.is_active());
    engine.detach(1);
    assert!(
        engine.is_active(),
        "the last call leaving does not close them"
    );
    engine.deactivate();
    assert!(!engine.is_active());
}

/// B7, the other half: a call whose media started before the platform said
/// the audio was ours — CallKit answering, then activating the session — is
/// carried from the moment the devices open, and again after a deactivation
/// and a second activation.
#[test]
fn a_call_attached_before_a_manual_activation_is_carried_once_active() {
    let fake = a_desk();
    let (mut engine, sent) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let call = FakeCallControl::new(8_000, 1_111, destination());
    engine.attach(1, call.call()).unwrap();
    engine.activate().unwrap();
    wait_ticks(&engine, 2);
    // a few frames, past the resampler's own delay
    for _ in 0..3 {
        fake.speak_into("builtin-mic", &[2_000; 960]);
    }
    wait_ticks(&engine, 3);
    assert!(
        !call.captured().is_empty(),
        "the microphone reached the call"
    );
    assert!(
        fake.played_by("builtin-out").contains(&1_111),
        "the call reached the loudspeaker"
    );
    assert!(!sent.lock().unwrap().is_empty());
    engine.deactivate();
    let captured = call.captured().len();
    engine.activate().unwrap();
    wait_ticks(&engine, 2);
    for _ in 0..3 {
        fake.speak_into("builtin-mic", &[2_000; 960]);
    }
    wait_ticks(&engine, 3);
    assert!(
        call.captured().len() > captured,
        "and again after the second activation"
    );
    engine.detach(1);
    engine.deactivate();
    engine.activate().unwrap();
    wait_ticks(&engine, 3);
    let pulls = call.pulls();
    wait_ticks(&engine, 3);
    assert_eq!(call.pulls(), pulls, "a detached call stays detached");
}

/// A direction with no device from the start is still carried at the
/// call's own pace: one frame a tick each way, not a device frame's worth of
/// call frames, which would send packets several times faster than real
/// time and drain the far end's audio as fast.
#[test]
fn a_direction_with_no_device_is_carried_at_the_calls_own_pace() {
    let fake = FakeControl::new(RATE);
    let (mut engine, sent) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    assert_eq!(engine.activate(), Err(BackendError::NoDevice));
    let call = FakeCallControl::new(8_000, 0, destination());
    engine.attach(1, call.call()).unwrap();
    wait_ticks(&engine, 2);
    let (ticks, captured, pulls) = (engine.ticks(), call.captured().len(), call.pulls());
    wait_ticks(&engine, 10);
    let ran = usize::try_from(engine.ticks() - ticks).unwrap();
    let captured = call.captured().len() - captured;
    let pulls = call.pulls() - pulls;
    assert!(captured <= ran + 1, "{captured} frames in {ran} ticks");
    assert!(pulls <= ran + 1, "{pulls} pulls in {ran} ticks");
    assert!(captured >= ran.saturating_sub(1) && pulls >= ran.saturating_sub(1));
    assert!(!sent.lock().unwrap().is_empty());
}

/// A call re-negotiated onto a codec at another rate under a live call is
/// pumped at its new rate from then on.
#[test]
fn a_call_that_changes_rate_midway_is_pumped_at_its_new_rate() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let call = FakeCallControl::new(8_000, 0, destination());
    engine.attach(1, call.call()).unwrap();
    fake.speak_into("builtin-mic", &[1_000; 960]);
    wait_ticks(&engine, 2);
    assert!(call.captured().iter().all(|frame| frame.len() == 160));
    call.set_rate(16_000);
    wait_ticks(&engine, 1);
    let before = call.captured().len();
    for _ in 0..4 {
        fake.speak_into("builtin-mic", &[1_000; 960]);
    }
    wait_ticks(&engine, 3);
    let after = call.captured();
    assert!(after.len() > before);
    assert!(
        after.iter().skip(before).all(|frame| frame.len() == 320),
        "{:?}",
        after.iter().skip(before).map(Vec::len).collect::<Vec<_>>()
    );
}

/// A driver stuck inside a probe the engine walked away from does not hold
/// up the servicing the application's loop does a few times a second.
#[test]
fn a_stuck_driver_does_not_hold_up_servicing() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    fake.hang();
    assert_eq!(engine.refresh().map(|_| ()), Err(BackendError::TimedOut));
    let releaser = {
        let fake = fake.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            fake.release();
        })
    };
    let started = Instant::now();
    engine.service();
    let took = started.elapsed();
    releaser.join().unwrap();
    assert!(took < Duration::from_secs(1), "service waited {took:?}");
}

/// And under automatic activation they do.
#[test]
fn automatic_activation_follows_the_calls() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let one = FakeCallControl::new(8_000, 0, destination());
    let two = FakeCallControl::new(16_000, 0, destination());
    engine.attach(1, one.call()).unwrap();
    assert!(engine.is_active());
    engine.attach(2, two.call()).unwrap();
    engine.detach(1);
    assert!(engine.is_active(), "one call is still up");
    engine.detach(2);
    assert!(!engine.is_active());
}

/// B10: a driver that does not answer is reported as stuck within the
/// probe wait, and the engine is still usable afterwards.
#[test]
fn a_hung_driver_is_a_timeout_and_not_a_hang() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    fake.hang();
    let started = Instant::now();
    assert_eq!(engine.refresh().map(|_| ()), Err(BackendError::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(2));
    // the driver is still stuck: asking again does not wait on it again
    let started = Instant::now();
    assert_eq!(engine.activate(), Err(BackendError::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(2));
    fake.release();
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        engine.refresh().is_ok(),
        "once the driver answers, so does the engine"
    );
}

// -- losing a device ----------------------------------------------------------

/// A device pulled out from under a role: the loss is the system's, the
/// reopening on the fallback is the engine's, and the selection is kept as a
/// preference that is honoured when the device comes back.
#[test]
fn a_lost_device_is_reopened_on_the_system_route_and_reclaimed_when_it_returns() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    let builtin = handle_of(&engine, "builtin-out");
    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    engine.activate().unwrap();
    wait_ticks(&engine, 2);
    drain(&mut engine);

    fake.unplug("headset");
    wait_ticks(&engine, 2);
    engine.service();
    let events: Vec<_> = std::iter::from_fn(|| engine.poll_event()).collect();
    let lost = events
        .iter()
        .find(|e| e.change == Change::Lost(Role::Speaker))
        .expect("the loss is reported");
    assert_eq!(lost.origin, Origin::System);
    assert_eq!(lost.device, Some(headset));
    let reopened = events
        .iter()
        .find(|e| e.change == Change::Reopened(Role::Speaker))
        .expect("the fallback is reported");
    assert_eq!(reopened.origin, Origin::Engine);
    assert_eq!(reopened.device, Some(builtin));
    assert_eq!(engine.running_on(Role::Speaker), Some(builtin));
    assert_eq!(
        engine.selection(Role::Speaker),
        Selection::Device(headset),
        "the preference is kept"
    );

    fake.plug("headset", "USB Headset", 1, 2);
    engine.service();
    assert_eq!(
        engine.running_on(Role::Speaker),
        Some(headset),
        "and honoured when the device is back"
    );
    let events: Vec<_> = std::iter::from_fn(|| engine.poll_event()).collect();
    assert!(
        events
            .iter()
            .any(|e| e.change == Change::Reopened(Role::Speaker) && e.origin == Origin::Engine)
    );
}

/// A direction with nothing to open is silence, reported, and not an error
/// that stops the other direction.
#[test]
fn a_missing_microphone_leaves_the_speaker_running_and_says_so() {
    let fake = FakeControl::new(RATE);
    fake.plug("builtin-out", "Built-in Output", 0, 2);
    fake.make_default("builtin-out", Direction::Output);
    let (mut engine, sent) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    assert_eq!(engine.activate(), Err(BackendError::NoDevice));
    assert!(engine.is_active());
    let changes = drain(&mut engine);
    assert!(changes.contains(&Change::Unavailable(Role::Microphone)));
    assert!(changes.contains(&Change::Reopened(Role::Speaker)));
    let call = FakeCallControl::new(8_000, 1_234, destination());
    engine.attach(7, call.call()).unwrap();
    wait_ticks(&engine, 4);
    assert!(
        fake.played_by("builtin-out").contains(&1_234),
        "playback runs"
    );
    assert!(
        !sent.lock().unwrap().is_empty(),
        "silence is still sent, so the far end hears a stream"
    );
    assert!(call.captured().iter().flatten().all(|s| *s == 0));
}

// -- the audio itself -----------------------------------------------------------

/// The microphone's frames reach every call at that call's own rate, and
/// what a call captured leaves through the transmit function.
#[test]
fn the_microphone_reaches_every_call_at_its_own_rate_and_the_packets_go_out() {
    let fake = a_desk();
    let (mut engine, sent) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let narrow = FakeCallControl::new(8_000, 0, destination());
    let wide = FakeCallControl::new(16_000, 0, destination());
    engine.attach(1, narrow.call()).unwrap();
    engine.attach(2, wide.call()).unwrap();
    wait_ticks(&engine, 1);
    for _ in 0..10 {
        fake.speak_into("builtin-mic", &[3_000; 960]);
    }
    wait_ticks(&engine, 4);
    let narrow_frames = narrow.captured();
    let wide_frames = wide.captured();
    assert!(
        narrow_frames.len() >= 8,
        "{} narrowband frames",
        narrow_frames.len()
    );
    assert!(
        wide_frames.len() >= 8,
        "{} wideband frames",
        wide_frames.len()
    );
    assert!(narrow_frames.iter().all(|f| f.len() == 160));
    assert!(wide_frames.iter().all(|f| f.len() == 320));
    // a constant resampled is the same constant, once the filter has settled
    let settled = narrow_frames.last().unwrap();
    assert!(
        settled.iter().all(|s| (*s - 3_000).abs() < 100),
        "{:?}",
        &settled[..8]
    );
    let sent = sent.lock().unwrap();
    assert!(sent.iter().any(|(id, _)| *id == 1) && sent.iter().any(|(id, _)| *id == 2));
    assert!(
        sent.iter()
            .all(|(_, packet)| packet.destination == destination())
    );
}

/// Several streams carried as one entry — a local conference — each
/// name their packets after a call of their own, and every packet reaches
/// the transmit function under the name it was given rather than the
/// entry's.
#[test]
fn an_entry_that_carries_several_calls_names_each_packet_after_its_own() {
    struct Bridge;

    impl crate::CallAudio for Bridge {
        fn sample_rate(&self) -> Result<u32, crate::CallGone> {
            Ok(16_000)
        }

        fn frame_samples(&self) -> Result<usize, crate::CallGone> {
            Ok(320)
        }

        fn capture(
            &mut self,
            _frame: &[i16],
            _now: Instant,
        ) -> Result<Option<Outgoing>, crate::CallGone> {
            Ok(None)
        }

        fn capture_each(
            &mut self,
            _own: CallId,
            frame: &[i16],
            _now: Instant,
            send: &mut dyn FnMut(CallId, Outgoing),
        ) -> Result<(), crate::CallGone> {
            for member in [11, 12] {
                send(
                    member,
                    Outgoing {
                        destination: destination(),
                        payload: vec![u8::try_from(frame.len() / 16).unwrap_or(0)],
                        transport: crate::Transport::Udp,
                    },
                );
            }
            Ok(())
        }

        fn playback(&mut self, out: &mut [i16]) -> Result<(), crate::CallGone> {
            out.fill(0);
            Ok(())
        }
    }

    let fake = a_desk();
    let (mut engine, sent) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    engine.attach(7, Box::new(Bridge)).unwrap();
    wait_ticks(&engine, 1);
    for _ in 0..4 {
        fake.speak_into("builtin-mic", &[1_000; 960]);
    }
    wait_ticks(&engine, 4);
    let sent = sent.lock().unwrap();
    assert!(
        sent.iter().any(|(id, _)| *id == 11) && sent.iter().any(|(id, _)| *id == 12),
        "{sent:?}"
    );
    assert!(sent.iter().all(|(id, _)| *id != 7), "{sent:?}");
    assert!(sent.iter().all(|(_, packet)| packet.payload == [20]));
}

/// Two calls' playback are summed into the loudspeaker.
#[test]
fn every_call_is_heard_on_the_speaker_at_once() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let one = FakeCallControl::new(8_000, 1_000, destination());
    let two = FakeCallControl::new(48_000, 2_000, destination());
    engine.attach(1, one.call()).unwrap();
    engine.attach(2, two.call()).unwrap();
    wait_ticks(&engine, 6);
    let played = fake.played_by("builtin-out");
    assert!(played.len() >= 960 * 4);
    let tail = &played[played.len() - 480..];
    assert!(
        tail.iter().all(|s| (*s - 3_000).abs() < 100),
        "{:?}",
        &tail[..8]
    );
}

/// The meter reads the loudest thing that went past, per direction.
#[test]
fn the_level_meter_reads_per_direction() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    assert_eq!(engine.level(Direction::Input).peak(), 0);
    let call = FakeCallControl::new(8_000, 9_000, destination());
    engine.attach(1, call.call()).unwrap();
    // the resampler overshoots the step from silence to the call's
    // constant, and the meter holds a peak for up to two windows of five
    // frames: wait until the step has left both
    wait_ticks(&engine, 8);
    fake.speak_into("builtin-mic", &[-12_000; 960]);
    wait_ticks(&engine, 3);
    assert_eq!(engine.level(Direction::Input).peak(), 12_000);
    // the call's constant is resampled on its way to the loudspeaker, and a
    // resampled constant ripples by a few steps
    let output = i32::from(engine.level(Direction::Output).peak());
    assert!((output - 9_000).abs() < 100, "{output}");
}

/// A call whose media ends under the pump is let go of, and under automatic
/// activation the devices close with the last one.
#[test]
fn a_call_that_ends_is_let_go_of() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let call = FakeCallControl::new(8_000, 0, destination());
    engine.attach(1, call.call()).unwrap();
    wait_ticks(&engine, 2);
    call.end();
    wait_ticks(&engine, 2);
    engine.service();
    assert!(engine.attached().is_empty());
    assert!(!engine.is_active());
}

/// A call is told the devices' loudspeaker-to-microphone delay when it is
/// attached, and again when a device changes under it: what a canceller
/// attached to the call looks back by.
#[test]
fn a_call_is_told_the_render_delay_of_the_devices_it_is_on() {
    let fake = a_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let call = FakeCallControl::new(8_000, 0, destination());
    assert_eq!(call.render_delay(), None);
    engine.attach(1, call.call()).unwrap();
    wait_ticks(&engine, 2);
    assert_eq!(
        call.render_delay(),
        Some(Duration::from_millis(30)),
        "fifteen each way"
    );
    let headset = handle_of(&engine, "headset");
    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    wait_ticks(&engine, 2);
    assert_eq!(
        call.render_delay(),
        Some(Duration::from_millis(30)),
        "told again on the change"
    );
}

/// The engine reports what the platform does about echo and what the
/// devices add in delay.
#[test]
fn the_info_says_whether_the_platform_cancels_echo_and_what_the_delay_is() {
    let fake = a_desk();
    fake.set_system_echo_cancellation(true);
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    assert!(!engine.info().active);
    engine.activate().unwrap();
    let info = engine.info();
    assert!(info.active && info.system_echo_cancellation);
    assert_eq!(info.render_delay, Duration::from_millis(30));
    assert_eq!(info.microphone_rate_hz, Some(RATE));
}

/// On a platform that runs one duplex unit, the microphone and the ringer
/// cannot be put on devices of their own, and say so.
#[test]
fn a_duplex_only_platform_refuses_a_microphone_or_ringer_of_its_own() {
    let fake = a_desk();
    fake.set_duplex_only(true);
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    assert_eq!(
        engine.select(Role::Microphone, Selection::Device(headset)),
        Err(SelectError::NotSupported)
    );
    assert_eq!(
        engine.select(Role::Ringer, Selection::Device(headset)),
        Err(SelectError::NotSupported)
    );
    assert_eq!(
        engine.select(Role::Speaker, Selection::Device(headset)),
        Ok(())
    );
    assert_eq!(engine.select(Role::Microphone, Selection::System), Ok(()));
}

/// A duplex platform like the Mac's: the call's microphone and loudspeaker
/// one unit, each on a device of its own, and every role chosen.
fn a_duplex_desk() -> FakeControl {
    let fake = a_desk();
    fake.set_duplex_only(true);
    fake.set_chooses_every_role(true);
    fake
}

/// On a duplex platform that names every device, the microphone goes on a
/// device apart from the loudspeaker's — opened as the other half of the
/// same unit — and survives the loudspeaker moving and the microphone's
/// device being unplugged and plugged back.
#[test]
fn a_duplex_platform_puts_the_microphone_on_a_device_of_its_own() {
    let fake = a_duplex_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let webcam = handle_of(&engine, "webcam");
    let headset = handle_of(&engine, "headset");
    engine
        .select(Role::Microphone, Selection::Device(webcam))
        .unwrap();
    engine.activate().unwrap();
    assert_eq!(engine.running_on(Role::Microphone), Some(webcam));
    assert_eq!(
        engine.running_on(Role::Speaker),
        Some(handle_of(&engine, "builtin-out"))
    );
    assert_eq!(fake.units_opened(), 1, "one unit for the two halves");

    // the loudspeaker moves: the unit is reopened, the microphone with it
    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    assert_eq!(engine.running_on(Role::Speaker), Some(headset));
    assert_eq!(engine.running_on(Role::Microphone), Some(webcam));

    // the webcam goes and comes back: the microphone follows it home
    fake.unplug("webcam");
    for _ in 0..3 {
        engine.service();
        std::thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(
        engine.running_on(Role::Microphone),
        Some(handle_of(&engine, "builtin-mic"))
    );
    fake.plug("webcam", "Webcam", 2, 0);
    engine.service();
    assert_eq!(engine.running_on(Role::Microphone), Some(webcam));
    assert_eq!(fake.units_at_most(), 1);
    engine.deactivate();
    assert_eq!(fake.units_alive(), 0);
}

/// The ring on a device of its own, on a duplex platform, is an output of
/// its own beside the call's unit — never a second duplex unit.
#[test]
fn a_duplex_platform_rings_on_a_device_of_its_own_without_a_second_unit() {
    let fake = a_duplex_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    let builtin = handle_of(&engine, "builtin-out");
    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    engine
        .select(Role::Ringer, Selection::Device(builtin))
        .unwrap();
    engine.ring(vec![1_000; 800], 8_000, true).unwrap();
    assert_eq!(fake.ringer_opens(), 1);
    assert_eq!(fake.units_opened(), 1, "the call's unit, and only that");
    wait_ticks(&engine, 4);
    assert!(fake.played_by("builtin-out").iter().any(|s| *s != 0));
    assert!(fake.played_by("headset").iter().all(|s| *s == 0));
    engine.stop_ringing();
    assert_eq!(fake.units_alive(), 0);
}

/// What an application in device mode does around a call, three times
/// over, with every role on a device of its own part of the way: at no
/// point are two of the platform's one duplex unit open at once.
#[test]
fn the_call_sequence_never_has_two_duplex_units_open() {
    let fake = a_duplex_desk();
    let (mut engine, _) = engine_with(Activation::Automatic, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    let builtin = handle_of(&engine, "builtin-out");
    let webcam = handle_of(&engine, "webcam");
    for round in 0..3 {
        engine.activate().unwrap();
        engine.ring(vec![700; 160], 8_000, true).unwrap();
        wait_ticks(&engine, 2);
        engine.service();
        engine.stop_ringing();
        engine.activate().unwrap();
        engine
            .select(Role::Speaker, Selection::Device(builtin))
            .unwrap();
        if round == 1 {
            engine
                .select(Role::Microphone, Selection::Device(webcam))
                .unwrap();
            engine
                .select(Role::Ringer, Selection::Device(headset))
                .unwrap();
            engine.ring(vec![700; 160], 8_000, true).unwrap();
            engine
                .select(Role::Speaker, Selection::Device(headset))
                .unwrap();
            engine.stop_ringing();
        }
        engine.service();
        engine.deactivate();
        assert_eq!(fake.units_alive(), 0, "round {round} left a unit open");
    }
    assert_eq!(fake.units_at_most(), 1);
    assert!(fake.units_opened() >= 3);
}

/// A reopen of the duplex unit waits for the pump to have let the old one
/// go, however long the pump is held up in a device: the new unit is not
/// opened beside the old.
#[test]
fn a_duplex_reopen_waits_for_the_old_unit_even_behind_a_slow_pump() {
    let fake = a_duplex_desk();
    let (mut engine, _) = engine_with(Activation::Manual, &fake);
    engine.refresh().unwrap();
    let headset = handle_of(&engine, "headset");
    engine.activate().unwrap();
    // the pump is inside a write that takes longer than a tick or two
    fake.stall_next_write("builtin-out", Duration::from_millis(400));
    let started = Instant::now();
    while !fake.stalled("builtin-out") {
        assert!(started.elapsed() < Duration::from_secs(5), "never stalled");
        std::thread::sleep(Duration::from_millis(2));
    }
    engine
        .select(Role::Speaker, Selection::Device(headset))
        .unwrap();
    assert_eq!(engine.running_on(Role::Speaker), Some(headset));
    assert_eq!(
        fake.units_at_most(),
        1,
        "the new unit opened beside the old"
    );
}
