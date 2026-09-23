// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Against a real PipeWire: the claims the unit tests can only make about
//! layouts and arithmetic, checked on a running graph.
//!
//! Every test here is ignored by default, because it needs a daemon, a
//! session manager and the cables `interop/pipewire/run.sh` makes — mono
//! virtual cables whose sink's samples come straight out of a source,
//! `sipral-mouth` into `sipral-mic` and `sipral-ear` into
//! `sipral-ear-monitor` — and PipeWire's own `pw-loopback`, `pw-metadata`
//! and `pw-cli`. That script starts all of it inside
//! `interop/pipewire/Dockerfile`'s image and runs these with `--ignored`; on
//! a desktop with the same cables loaded they run the same way, except that
//! two of them move the session's defaults while they run and then hand the
//! choice back to the session manager.
//!
//! What is measured is printed as well as asserted, because the numbers —
//! how many frames crossed, how loud, how late — are the part worth reading
//! when one of them moves.

#![cfg(target_os = "linux")]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stdout
)]

use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use sipral_io_pipewire::{
    CaptureStream, DeviceChoice, DeviceEvent, DeviceId, DeviceMonitor, Direction, Error,
    PlaybackStream, StreamConfig, StreamEvent, StreamFormat, default_device, devices,
};

/// The cable's sink, which the tests play into.
const MOUTH: &str = "sipral-mouth";
/// The cable's source, which the tests read back from.
const MIC: &str = "sipral-mic";
/// The other cable's sink, which only the default-changing test uses.
const EAR: &str = "sipral-ear";

/// How long anything waits for the graph before the test is a failure.
const PATIENCE: Duration = Duration::from_secs(10);

/// Forty-eight kilohertz, which is what the graph runs: no resampler between
/// the stream and the cable, so sixteen-bit samples converted to the graph's
/// float and back are the same samples, and "the same samples back" can be
/// asserted exactly rather than approximately.
fn graph_rate() -> StreamFormat {
    StreamFormat::with_frame_millis(48_000, 10).expect("48 kHz divides into 10 ms")
}

/// A signal nothing else in the graph could produce by accident: a
/// pseudo-random sequence, never repeating over the length of a test, at a
/// level well inside the sixteen-bit range.
fn signal(length: usize) -> Vec<i16> {
    let mut state: u32 = 0x2545_f491;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            // the top sixteen bits, halved: at most half of full scale
            i16::try_from(i32::try_from(state >> 16).unwrap() - 32_768).unwrap() / 2
        })
        .collect()
}

#[test]
#[ignore = "needs a running PipeWire with the cable interop/pipewire/run.sh makes"]
fn the_graph_lists_the_cable_and_a_default() {
    let listed = devices().expect("the registry answers");
    for device in &listed {
        println!("  {device}");
    }
    assert!(
        listed
            .iter()
            .any(|device| device.id.as_str() == MOUTH && device.direction == Direction::Output),
        "{MOUTH} is not listed as a sink"
    );
    assert!(
        listed
            .iter()
            .any(|device| device.id.as_str() == MIC && device.direction == Direction::Input),
        "{MIC} is not listed as a source"
    );
    let sink = default_device(Direction::Output).expect("the registry answers");
    println!("  default sink: {sink:?}");
    assert!(sink.is_some(), "the session manager named no default sink");
    // the listing marks the one it named, and only that one
    let marked: Vec<_> = listed
        .iter()
        .filter(|device| device.direction == Direction::Output && device.is_default)
        .map(|device| device.id.clone())
        .collect();
    assert_eq!(marked, sink.into_iter().collect::<Vec<_>>());
}

#[test]
#[ignore = "needs a running PipeWire with the cable interop/pipewire/run.sh makes"]
fn samples_played_into_the_sink_come_back_out_of_the_source() {
    let format = graph_rate();
    let frame = format.frame_samples();
    let played = signal(format.sample_rate_hz() as usize * 2);

    let mut microphone = CaptureStream::open(&StreamConfig::on(DeviceId::new(MIC), format))
        .expect("the capture stream opens");
    let mut speaker = PlaybackStream::open(&StreamConfig::on(DeviceId::new(MOUTH), format))
        .expect("the playback stream opens");
    assert_eq!(microphone.device().map(DeviceId::as_str), Some(MIC));
    microphone.start().expect("the capture stream starts");
    speaker.start().expect("the playback stream starts");

    // Paced by the speaker's own demand: a frame goes in whenever there is
    // room for one, so the graph's clock sets the rate and the ring stays
    // near full rather than running dry between writes.
    let mut heard = Vec::with_capacity(played.len() * 2);
    let mut next = 0;
    let mut buffer = vec![0_i16; frame];
    let mut loudest = 0_u16;
    let started = Instant::now();
    while started.elapsed() < PATIENCE
        && heard.len() < played.len() + format.sample_rate_hz() as usize
    {
        while next < played.len() && speaker.room() >= frame {
            assert!(speaker.write(&played[next..next + frame]));
            next += frame;
        }
        while microphone.read(&mut buffer) {
            heard.extend_from_slice(&buffer);
            loudest = loudest.max(microphone.controls().level().peak());
        }
        thread::sleep(Duration::from_millis(2));
    }
    let delay = microphone.render_delay(&speaker);
    let (captured, sent) = (microphone.counters(), speaker.counters());
    microphone.close().expect("the capture stream closes");
    speaker.close().expect("the playback stream closes");

    // The first stretch of the signal, found in what came back, says where
    // the two line up; everything after that has to be the same samples.
    let probe = &played[..64];
    let offset = heard
        .windows(probe.len())
        .position(|window| window == probe)
        .expect("the signal played into the sink never came out of the source");
    let compared = (heard.len() - offset).min(played.len());
    let equal = heard[offset..offset + compared]
        .iter()
        .zip(&played[..compared])
        .filter(|(a, b)| a == b)
        .count();

    println!(
        "  {} frames written, {} frames read, first sample back after {} samples \
         ({:.1} ms of silence ahead of it)",
        next / frame,
        heard.len() / frame,
        offset,
        f64::from(u32::try_from(offset).unwrap()) * 1_000.0 / f64::from(format.sample_rate_hz())
    );
    println!("  {equal} of {compared} samples identical, loudest {loudest}");
    println!("  capture: {captured}");
    println!("  playback: {sent}");
    println!("  {delay}");

    assert!(
        compared >= played.len() / 2,
        "only {compared} samples came back"
    );
    assert_eq!(equal, compared, "samples changed on the way through");
    assert!(
        loudest > 8_000,
        "the meter read {loudest} for a half-scale signal"
    );
    assert_eq!(captured.panics + sent.panics, 0);
    // the graph reported a clock, and it is the graph's own rate
    assert_eq!(delay.capture.rate.denom, 48_000);
    assert_eq!(delay.playback.rate.denom, 48_000);
}

/// A virtual cable of its own, which the test can take away.
struct Cable {
    child: Child,
}

impl Cable {
    fn plug(sink: &str, source: &str) -> Self {
        let child = Command::new("pw-loopback")
            .arg("-m")
            .arg("[ MONO ]")
            .arg(format!(
                "--capture-props=media.class=Audio/Sink node.name={sink}"
            ))
            .arg(format!(
                "--playback-props=media.class=Audio/Source node.name={source}"
            ))
            .spawn()
            .expect("pw-loopback runs");
        Self { child }
    }

    fn unplug(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Cable {
    fn drop(&mut self) {
        self.unplug();
    }
}

/// Wait until `ready` says yes, or fail the test after [`PATIENCE`].
fn until(what: &str, mut ready: impl FnMut() -> bool) {
    let started = Instant::now();
    while !ready() {
        assert!(started.elapsed() < PATIENCE, "{what} never happened");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "needs a running PipeWire with pw-loopback on the path"]
fn a_node_that_goes_is_reported_once_and_recovered_from() {
    const SINK: &str = "sipral-transient-sink";
    const SOURCE: &str = "sipral-transient-source";

    let monitor = DeviceMonitor::new().expect("the registry answers");
    while monitor.poll().is_some() {}

    let mut cable = Cable::plug(SINK, SOURCE);
    until("the new source appearing", || {
        monitor
            .devices()
            .iter()
            .any(|device| device.id.as_str() == SOURCE)
    });
    assert_eq!(monitor.poll(), Some(DeviceEvent::ListChanged));

    let format = StreamFormat::narrowband();
    let named = StreamConfig::on(DeviceId::new(SOURCE), format);
    let preferred = StreamConfig::preferring(DeviceId::new(SOURCE), format);
    let mut strict = CaptureStream::open(&named).expect("the named source opens");
    let mut lenient = CaptureStream::open(&preferred).expect("the preferred source opens");
    strict.start().expect("starts");
    lenient.start().expect("starts");
    until("the streams running", || {
        strict.is_running() && lenient.is_running()
    });

    cable.unplug();
    until("the loss being reported", || {
        strict.poll() == Some(StreamEvent::DeviceLost)
    });
    // said once, not on every poll
    assert_eq!(strict.poll(), None);
    until("the other stream's loss", || {
        lenient.poll() == Some(StreamEvent::DeviceLost)
    });
    assert!(!strict.is_running());
    until("the node leaving the list", || {
        !monitor
            .devices()
            .iter()
            .any(|device| device.id.as_str() == SOURCE)
    });
    println!("  lost after: {}", strict.counters());

    // "that node and nothing else" has nowhere to go back to
    match strict.recover() {
        Err(Error::NoDevice) => {}
        Err(other) => panic!("recovering a named node that is gone said {other}"),
        Ok(_) => panic!("recovered onto a node that is gone"),
    }
    // a preference falls back to the session's route, and is running again
    let recovered = lenient.recover().expect("a preference recovers");
    let fallback = monitor
        .default_device(Direction::Input)
        .expect("the session names a default source");
    assert_eq!(recovered.device(), Some(&fallback));
    until("the recovered stream running", || recovered.is_running());
    println!(
        "  recovered onto the session's route, a {} config",
        DeviceChoice::Preferred(DeviceId::new(SOURCE))
    );
    recovered.close().expect("closes");
}

/// `pw-metadata` on the `"default"` object, which is how a desktop's mixer
/// changes the session's choices.
fn pw_metadata(arguments: &[&str]) {
    let status = Command::new("pw-metadata")
        .args(arguments)
        .output()
        .expect("pw-metadata runs")
        .status;
    assert!(status.success(), "pw-metadata {arguments:?} said {status}");
}

/// The key a person's choice of default is kept under, which the session
/// manager turns into the `default.audio.*` keys the crate reads.
fn configured_key(direction: Direction) -> &'static str {
    match direction {
        Direction::Output => "default.configured.audio.sink",
        Direction::Input => "default.configured.audio.source",
    }
}

/// Choose a direction's default node the way a mixer does.
fn configure(direction: Direction, node: &str) {
    let value = format!("{{ \"name\": \"{node}\" }}");
    pw_metadata(&["0", configured_key(direction), &value, "Spa:String:JSON"]);
}

/// Leaves the session's own choice of default in place once a test that
/// made one ends, however it ends.
struct Configured(Direction);

impl Drop for Configured {
    fn drop(&mut self) {
        let _ = Command::new("pw-metadata")
            .args(["-d", "0", configured_key(self.0)])
            .output();
    }
}

/// A node's registry id, which `pw-metadata` names a subject by and this
/// crate never hands out.
fn node_id(name: &str) -> String {
    let listing = Command::new("pw-cli")
        .args(["ls", "Node"])
        .output()
        .expect("pw-cli runs");
    let listing = String::from_utf8_lossy(&listing.stdout);
    let mut id = None;
    for line in listing.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("id ") {
            id = rest.split(',').next().map(str::to_owned);
        } else if line.contains(&format!("node.name = \"{name}\"")) {
            return id.expect("an id before the properties");
        }
    }
    panic!("no node is called {name}");
}

#[test]
#[ignore = "needs a running PipeWire with the cables interop/pipewire/run.sh makes"]
fn a_default_that_changes_is_reported_and_nothing_else_passes_for_one() {
    let monitor = DeviceMonitor::new().expect("the registry answers");
    let _restore = Configured(Direction::Output);
    let source = monitor
        .default_device(Direction::Input)
        .expect("the session names a default source");

    while monitor.poll().is_some() {}
    configure(Direction::Output, EAR);
    until("the default sink moving to the ear", || {
        monitor.default_device(Direction::Output) == Some(DeviceId::new(EAR))
    });
    let heard: Vec<_> = std::iter::from_fn(|| monitor.poll()).collect();
    assert!(
        heard.contains(&DeviceEvent::DefaultChanged(Direction::Output)),
        "the change was never reported: {heard:?}"
    );

    // The same metadata object keeps keys under other nodes' ids, and clears
    // them all when the node goes: what happens to any stream a mixer moved,
    // done here to a node that stays.
    let ear = node_id(EAR);
    pw_metadata(&[&ear, "sipral.test", "yes"]);
    pw_metadata(&["-d", &ear]);
    // A change of the session's own after it, so that once it has arrived
    // everything before it has too.
    configure(Direction::Output, MOUTH);
    until("the default sink moving back", || {
        monitor.default_device(Direction::Output) == Some(DeviceId::new(MOUTH))
    });
    let heard: Vec<_> = std::iter::from_fn(|| monitor.poll()).collect();
    println!("  after another node's keys were cleared: {heard:?}");
    assert_eq!(monitor.default_device(Direction::Input), Some(source));
    assert!(!heard.contains(&DeviceEvent::DefaultChanged(Direction::Input)));
}

/// Play `signal` into `mouth` for as long as `window` lasts, a frame at a
/// time whenever there is room, while reading `phone`; say the loudest
/// sample heard.
fn loudest_heard(
    mouth: &mut PlaybackStream,
    phone: &mut CaptureStream,
    signal: &[i16],
    window: Duration,
) -> u16 {
    let mut buffer = vec![0_i16; signal.len()];
    let mut loudest = 0_u16;
    let started = Instant::now();
    while started.elapsed() < window {
        while mouth.room() >= signal.len() {
            assert!(mouth.write(signal));
        }
        while phone.read(&mut buffer) {
            let peak = buffer.iter().map(|sample| sample.unsigned_abs()).max();
            loudest = loudest.max(peak.unwrap_or(0));
        }
        thread::sleep(Duration::from_millis(2));
    }
    loudest
}

#[test]
#[ignore = "needs a running PipeWire with the cables interop/pipewire/run.sh makes"]
fn a_stream_on_the_session_route_stays_on_the_node_it_opened_on() {
    const SINK: &str = "sipral-route-sink";
    const SOURCE: &str = "sipral-route-source";

    let monitor = DeviceMonitor::new().expect("the registry answers");
    let mut cable = Cable::plug(SINK, SOURCE);
    until("the new source appearing", || {
        monitor
            .devices()
            .iter()
            .any(|device| device.id.as_str() == SOURCE)
    });
    let _restore = Configured(Direction::Input);
    configure(Direction::Input, SOURCE);
    until("the new source becoming the default", || {
        monitor.default_device(Direction::Input) == Some(DeviceId::new(SOURCE))
    });

    // The room talks into the cable the old default is not: whatever the
    // phone hears, it hears from a node it was never opened on.
    let format = graph_rate();
    let spoken = signal(format.frame_samples());
    let mut mouth = PlaybackStream::open(&StreamConfig::on(DeviceId::new(MOUTH), format))
        .expect("the room's stream opens");
    mouth.start().expect("starts");
    let mut phone =
        CaptureStream::open(&StreamConfig::new(format)).expect("the session's route opens");
    phone.start().expect("starts");
    until("the phone running", || phone.is_running());
    let before = loudest_heard(&mut mouth, &mut phone, &spoken, Duration::from_millis(500));
    assert_eq!(before, 0, "the silent cable was not silent");

    configure(Direction::Input, MIC);
    until("the default moving to the room's cable", || {
        monitor.default_device(Direction::Input) == Some(DeviceId::new(MIC))
    });
    let after = loudest_heard(&mut mouth, &mut phone, &spoken, Duration::from_secs(2));
    println!("  loudest heard after the default moved: {after}");
    assert_eq!(
        after, 0,
        "a stream on the session's route was linked to the new default"
    );
    assert_eq!(phone.device().map(DeviceId::as_str), Some(SOURCE));
    assert_eq!(phone.poll(), None);

    // pinned, so losing the node is said rather than papered over, and a
    // recover lands on the default of the moment
    cable.unplug();
    until("the loss being reported", || {
        phone.poll() == Some(StreamEvent::DeviceLost)
    });
    let mut phone = phone.recover().expect("the session's route recovers");
    assert_eq!(phone.device().map(DeviceId::as_str), Some(MIC));
    let recovered = loudest_heard(&mut mouth, &mut phone, &spoken, Duration::from_secs(1));
    println!("  loudest heard after recovering: {recovered}");
    assert!(recovered > 8_000, "the recovered stream heard {recovered}");
    phone.close().expect("closes");
    mouth.close().expect("closes");
}

#[test]
#[ignore = "needs a running PipeWire with the cable interop/pipewire/run.sh makes"]
fn a_rate_the_graph_does_not_run_is_converted_both_ways() {
    let format = StreamFormat::with_frame_millis(16_000, 20).expect("16 kHz, 20 ms");
    let rate = format.sample_rate_hz();
    // a 500 Hz triangle at 16 kHz, 32 samples a period and ten to a frame: a
    // thousand zero crossings a second, which a resampler that got either
    // rate wrong would move
    let tone: Vec<i16> = (0..format.frame_samples())
        .map(|n| {
            let step = i16::try_from(n % 32).unwrap();
            let rise = if step < 16 { step } else { 32 - step };
            (rise - 8) * 1_000
        })
        .collect();

    let mut speaker = PlaybackStream::open(&StreamConfig::on(DeviceId::new(MOUTH), format))
        .expect("the playback stream opens");
    let mut microphone = CaptureStream::open(&StreamConfig::on(DeviceId::new(MIC), format))
        .expect("the capture stream opens");
    speaker.start().expect("starts");
    microphone.start().expect("starts");

    let mut heard: Vec<i16> = Vec::new();
    let mut buffer = vec![0_i16; format.frame_samples()];
    let mut first_read = None;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(3) {
        while speaker.room() >= tone.len() {
            assert!(speaker.write(&tone));
        }
        while microphone.read(&mut buffer) {
            first_read.get_or_insert_with(Instant::now);
            heard.extend_from_slice(&buffer);
        }
        thread::sleep(Duration::from_millis(2));
    }
    let elapsed = first_read.expect("something was read").elapsed();
    let latency = microphone.latency();
    microphone.close().expect("closes");
    speaker.close().expect("closes");

    let count = |length: usize| f64::from(u32::try_from(length).unwrap());
    let delivered = count(heard.len()) / elapsed.as_secs_f64();
    let loud: Vec<i16> = heard
        .iter()
        .copied()
        .skip_while(|sample| sample.unsigned_abs() < 4_000)
        .collect();
    let crossings = loud
        .windows(2)
        .filter(|pair| (pair[0] >= 0) != (pair[1] >= 0))
        .count();
    let per_second = count(crossings) * f64::from(rate) / count(loud.len());
    println!(
        "  {delivered:.0} samples a second delivered, {per_second:.0} zero crossings a second, \
         graph clock 1/{}",
        latency.rate.denom
    );
    assert!(
        (15_200.0..=16_800.0).contains(&delivered),
        "{delivered:.0} samples a second at 16 kHz"
    );
    assert!(
        (950.0..=1_050.0).contains(&per_second),
        "the tone came back at {per_second:.0} crossings a second"
    );
    // the graph ran at its own rate, and the stream at the one asked for
    assert_ne!(latency.rate.denom, rate);
    assert_eq!(latency.stream_rate_hz, rate);
}

/// PipeWire's own threads and this crate's, in this process.
fn pipewire_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("procfs")
        .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .filter(|name| name.starts_with("data-loop") || name.starts_with("sipral-pw"))
        .count()
}

#[test]
#[ignore = "needs a running PipeWire with the cable interop/pipewire/run.sh makes"]
fn closing_a_stream_leaves_no_thread_behind() {
    let before = pipewire_threads();
    let format = StreamFormat::narrowband();
    let mut speaker = PlaybackStream::open(&StreamConfig::on(DeviceId::new(MOUTH), format))
        .expect("the playback stream opens");
    let mut microphone = CaptureStream::open(&StreamConfig::on(DeviceId::new(MIC), format))
        .expect("the capture stream opens");
    speaker.start().expect("starts");
    microphone.start().expect("starts");
    until("both running", || {
        speaker.is_running() && microphone.is_running()
    });
    // a loop thread and a realtime data thread for each
    let open = pipewire_threads();
    println!("  PipeWire threads: {before} before, {open} open");
    assert!(open >= before + 4);
    speaker.close().expect("closes");
    microphone.close().expect("closes");
    // the data thread belongs to the context `pw_stream_new_simple` made,
    // and goes with the stream: nothing is left to call into freed memory
    assert_eq!(pipewire_threads(), before);
}
