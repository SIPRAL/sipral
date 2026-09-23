// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Against a real PipeWire: the claims the unit tests can only make about
//! layouts and arithmetic, checked on a running graph.
//!
//! Every test here is ignored by default, because it needs a daemon, a
//! session manager and the two nodes `interop/pipewire/run.sh` makes — a
//! virtual cable whose sink is `sipral-mouth` and whose source is
//! `sipral-mic`, mono, so that what is played into the one comes straight
//! out of the other. That script starts all of it inside
//! `interop/pipewire/Dockerfile`'s image and runs these with `--ignored`; on
//! a desktop with the same cable loaded they run the same way.
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
    assert_eq!(recovered.device(), None);
    until("the recovered stream running", || recovered.is_running());
    println!(
        "  recovered onto the session's route, a {} config",
        DeviceChoice::Preferred(DeviceId::new(SOURCE))
    );
    recovered.close().expect("closes");
}
