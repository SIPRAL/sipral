// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The engine on the machine's real devices.
//!
//! Ignored by default, because they open whatever the machine has and a
//! machine with no devices — the lab's containers, most CI — has nothing to
//! open. Run them on a desk:
//!
//! ```text
//! cargo test -p sipral-audio --test real_device -- --ignored --nocapture
//! ```
//!
//! On macOS the first run asks the person for the microphone once.

// a test says what it means; the no-panic discipline is for the library
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sipral_audio::{
    Activation, CallAudio, CallGone, Config, Direction, Engine, Outgoing, Role, Selection,
    Transport,
};

/// A call that plays a tone and keeps what the microphone gave it.
struct ToneCall {
    rate_hz: u32,
    phase: f32,
    frequency_hz: f32,
    amplitude: f32,
    captured: Arc<Mutex<Vec<i16>>>,
    played: Arc<Mutex<Vec<i16>>>,
}

impl CallAudio for ToneCall {
    fn sample_rate(&self) -> Result<u32, CallGone> {
        Ok(self.rate_hz)
    }

    fn frame_samples(&self) -> Result<usize, CallGone> {
        Ok((self.rate_hz / 50) as usize)
    }

    fn capture(&mut self, frame: &[i16], _now: Instant) -> Result<Option<Outgoing>, CallGone> {
        self.captured.lock().unwrap().extend_from_slice(frame);
        Ok(Some(Outgoing {
            destination: "203.0.113.5:41000".parse::<SocketAddr>().unwrap(),
            payload: vec![0; 172],
            transport: Transport::Udp,
        }))
    }

    fn playback(&mut self, out: &mut [i16]) -> Result<(), CallGone> {
        let step = self.frequency_hz / self.rate_hz as f32;
        for slot in out.iter_mut() {
            self.phase = (self.phase + step) % 1.0;
            let value = (self.phase * core::f32::consts::TAU).sin() * self.amplitude * 32_767.0;
            *slot = value as i16;
        }
        self.played.lock().unwrap().extend_from_slice(out);
        Ok(())
    }
}

fn rms(samples: &[i16]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: f64 = samples
        .iter()
        .map(|sample| f64::from(*sample) * f64::from(*sample))
        .sum();
    (sum / samples.len() as f64).sqrt() as f32
}

fn engine() -> (Engine, Arc<Mutex<usize>>) {
    let backend = sipral_audio::platform_backend().expect("this platform has a backend");
    let packets = Arc::new(Mutex::new(0_usize));
    let counted = Arc::clone(&packets);
    let engine = Engine::on_system_clock(
        backend,
        Config {
            activation: Activation::Manual,
            ..Config::default()
        },
        Box::new(move |_, _| *counted.lock().unwrap() += 1),
    );
    (engine, packets)
}

#[test]
#[ignore = "opens the machine's real devices"]
fn the_devices_are_listed_and_a_call_is_pumped_through_them() {
    let (mut engine, packets) = engine();
    let listed = engine
        .refresh()
        .expect("the platform lists its devices")
        .to_vec();
    for device in &listed {
        println!(
            "{}: {:?} in={} out={} default_in={} default_out={} present={} [{}]",
            device.handle,
            device.name,
            device.input_channels,
            device.output_channels,
            device.default_input,
            device.default_output,
            device.present,
            device.identity
        );
    }
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        assert!(!listed.is_empty(), "a desktop has at least one device");
    }

    let opened = engine.activate();
    println!("activate: {opened:?}");
    let info = engine.info();
    println!("info: {info:?}");
    assert!(info.active);

    let captured = Arc::new(Mutex::new(Vec::new()));
    let played = Arc::new(Mutex::new(Vec::new()));
    engine
        .attach(
            1,
            Box::new(ToneCall {
                rate_hz: 8_000,
                phase: 0.0,
                frequency_hz: 440.0,
                amplitude: 0.1,
                captured: Arc::clone(&captured),
                played: Arc::clone(&played),
            }),
        )
        .expect("the call attaches");
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(1_500) {
        engine.service();
        std::thread::sleep(Duration::from_millis(50));
    }
    println!(
        "microphone level {} / speaker level {}, running on {:?} / {:?}",
        engine.level(Direction::Input),
        engine.level(Direction::Output),
        engine.running_on(Role::Microphone),
        engine.running_on(Role::Speaker)
    );
    let heard = captured.lock().unwrap().len();
    let sent = *packets.lock().unwrap();
    println!("captured {heard} samples at 8 kHz, {sent} packets out");
    if info.microphone_rate_hz.is_some() {
        assert!(
            heard >= 8_000,
            "a second of microphone reached the call: {heard}"
        );
        assert!(sent >= 50, "and left as packets: {sent}");
    }
    assert!(
        played.lock().unwrap().len() >= 8_000,
        "a second of the call was played"
    );
    assert!(
        engine.level(Direction::Output).peak() > 0,
        "the meter saw the tone"
    );

    // the ring, through whatever the ringer is on, half a second
    let tone: Vec<i16> = (0..4_000)
        .map(|n| ((n as f32 * 0.35).sin() * 6_000.0) as i16)
        .collect();
    engine.ring(tone, 8_000, false).expect("the ring plays");
    std::thread::sleep(Duration::from_millis(600));
    engine.service();

    // the loudspeaker put back where it is, explicitly: the engine's own
    // change, reported as such
    if let Some(speaker) = engine.running_on(Role::Speaker) {
        engine
            .select(Role::Speaker, Selection::Device(speaker))
            .expect("the device it runs on can be chosen");
        std::thread::sleep(Duration::from_millis(300));
        engine.service();
        let events: Vec<_> = std::iter::from_fn(|| engine.poll_event()).collect();
        println!("events: {events:?}");
        assert!(events.iter().any(|event| {
            event.change == sipral_audio::Change::Selected(Role::Speaker)
                && event.origin == sipral_audio::Origin::Engine
        }));
    }

    engine.detach(1);
    engine.deactivate();
    assert!(!engine.is_active());
}

/// What an application in device mode does around a call, three times over:
/// open, ring a looped tone, stop it, put the loudspeaker on a device
/// explicitly, close. On macOS this is the sequence that once had the
/// voice-processing unit write past the end of a buffer; run it under the
/// system's guard allocator to see that it does not:
///
/// ```text
/// DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib MallocScribble=1 \
///   cargo test -p sipral-audio --test real_device -- --ignored --nocapture sequence
/// ```
///
/// `SIPRAL_AUDIO_SPEAKER`, `SIPRAL_AUDIO_MIC` and `SIPRAL_AUDIO_RINGER` put
/// each role on a device named like that; the loudspeaker goes on the
/// system's default output otherwise.
#[test]
#[ignore = "opens the machine's real devices and plays a tone"]
fn the_device_mode_sequence_runs_three_times() {
    let (mut engine, _) = engine();
    let listed = engine
        .refresh()
        .expect("the platform lists its devices")
        .to_vec();
    let named = |role: Role, variable: &str| {
        let wanted = std::env::var(variable).ok()?;
        listed
            .iter()
            .find(|device| device.serves(role) && device.name.contains(&wanted))
            .map(|device| device.handle)
    };
    for (role, variable) in [
        (Role::Microphone, "SIPRAL_AUDIO_MIC"),
        (Role::Ringer, "SIPRAL_AUDIO_RINGER"),
    ] {
        if let Some(handle) = named(role, variable) {
            engine
                .select(role, Selection::Device(handle))
                .unwrap_or_else(|error| panic!("{role}: {error}"));
        }
    }
    let speaker = named(Role::Speaker, "SIPRAL_AUDIO_SPEAKER").or_else(|| {
        listed
            .iter()
            .find(|device| device.default_output)
            .map(|device| device.handle)
    });
    if let Some(handle) = speaker {
        engine
            .select(Role::Speaker, Selection::Device(handle))
            .expect("the loudspeaker");
    }
    let tone: Vec<i16> = (0..8_000)
        .map(|n| ((n as f32 * core::f32::consts::TAU * 440.0 / 8_000.0).sin() * 3_000.0) as i16)
        .collect();
    for round in 1..=3 {
        engine.activate().expect("the devices open");
        engine.ring(tone.clone(), 8_000, true).expect("the ring");
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(1_500) {
            engine.service();
            std::thread::sleep(Duration::from_millis(50));
        }
        let info = engine.info();
        println!(
            "round {round}: {info:?}, microphone on {:?}, speaker on {:?}, ringer on {:?}",
            engine.running_on(Role::Microphone),
            engine.running_on(Role::Speaker),
            engine.running_on(Role::Ringer)
        );
        assert!(info.active && info.speaker_rate_hz.is_some());
        engine.stop_ringing();
        if let Some(handle) = named(Role::Speaker, "SIPRAL_AUDIO_SPEAKER") {
            engine
                .select(Role::Speaker, Selection::Device(handle))
                .expect("the loudspeaker again");
        }
        std::thread::sleep(Duration::from_millis(500));
        engine.service();
        engine.deactivate();
        assert!(!engine.is_active());
    }
}

/// The echo return loss of the machine's loudspeaker-to-microphone path:
/// how much quieter the tone the call plays comes back through the
/// microphone. On a machine whose microphone and loudspeaker are one
/// loopback cable — the Windows lab's VB-CABLE — this is the path with no
/// room in it, and what the platform's own processing takes off it.
///
/// `SIPRAL_AUDIO_MIC` and `SIPRAL_AUDIO_SPEAKER` name the devices by a
/// fragment of their names; without them the system's route is measured.
#[test]
#[ignore = "opens the machine's real devices and plays a tone"]
fn echo_return_loss_through_the_loudspeaker_to_microphone_path() {
    let (mut engine, _) = engine();
    let listed = engine
        .refresh()
        .expect("the platform lists its devices")
        .to_vec();
    for (role, variable) in [
        (Role::Microphone, "SIPRAL_AUDIO_MIC"),
        (Role::Speaker, "SIPRAL_AUDIO_SPEAKER"),
    ] {
        let Ok(wanted) = std::env::var(variable) else {
            continue;
        };
        let device = listed
            .iter()
            .find(|device| device.serves(role) && device.name.contains(&wanted))
            .unwrap_or_else(|| panic!("no {role} named like {wanted:?}: {listed:?}"));
        engine
            .select(role, Selection::Device(device.handle))
            .unwrap_or_else(|error| panic!("{role} on {:?}: {error}", device.name));
    }
    let opened = engine.activate();
    println!("activate: {opened:?}");
    let info = engine.info();
    println!("info: {info:?}");
    assert!(info.microphone_rate_hz.is_some() && info.speaker_rate_hz.is_some());

    let captured = Arc::new(Mutex::new(Vec::new()));
    let played = Arc::new(Mutex::new(Vec::new()));
    engine
        .attach(
            1,
            Box::new(ToneCall {
                rate_hz: 16_000,
                phase: 0.0,
                frequency_hz: 1_000.0,
                amplitude: 0.25,
                captured: Arc::clone(&captured),
                played: Arc::clone(&played),
            }),
        )
        .expect("the call attaches");
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(4) {
        engine.service();
        std::thread::sleep(Duration::from_millis(50));
    }
    engine.detach(1);
    engine.deactivate();

    let played = played.lock().unwrap();
    let captured = captured.lock().unwrap();
    // the last two seconds of each, past whatever the path took to settle
    let window = 32_000_usize;
    assert!(
        played.len() > window && captured.len() > window,
        "played {} captured {}",
        played.len(),
        captured.len()
    );
    let out = rms(&played[played.len() - window..]);
    let back = rms(&captured[captured.len() - window..]);
    let erl_db = if back > 0.0 {
        20.0 * (out / back).log10()
    } else {
        f32::INFINITY
    };
    println!(
        "played rms {out:.0}, captured rms {back:.0}, echo return loss {erl_db:.1} dB, system \
         echo cancellation {}, render delay {:?}",
        info.system_echo_cancellation, info.render_delay
    );
    assert!(
        out > 1_000.0,
        "the tone was played at a level worth measuring"
    );
}
