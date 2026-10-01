// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Windows, over `sipral-io-wasapi`.
//!
//! An endpoint is one direction, so a microphone and a loudspeaker are two
//! streams on two endpoints with two clocks, and a ringer on a third is a
//! third stream: everything the engine can ask for, this platform can open.
//! Every stream is opened as a communications stream, and whether Windows
//! took it as one — which is what puts the endpoint's own echo cancellation
//! behind the microphone — is what the capture stream reports as its
//! system echo cancellation. Where it did not, the engine's info says so
//! and the application attaches a canceller of its own to each call, with
//! the delay the two streams report as its reference.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use sipral_io_common::level::Controls;
use sipral_io_wasapi::{
    CaptureStream as WasapiCapture, DeviceEvent, DeviceId, DeviceMonitor, Direction,
    PlaybackStream as WasapiPlayback, StreamConfig, StreamEvent, StreamFormat,
};

use crate::backend::{
    Backend, BackendError, CaptureStream, Format, Notice, PlaybackStream, RawDevice, StreamCommon,
};

/// How often the watcher asks the monitor what changed.
const WATCH_EVERY: Duration = Duration::from_millis(200);

/// The platform's backend.
pub(crate) struct WasapiBackend {
    /// What the watcher's thread has seen, in order.
    notices: Arc<Mutex<VecDeque<Notice>>>,
    /// Set to stop the watcher.
    stop: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
    /// Whether streams ask for the endpoint's voice processing, or open raw.
    processing: bool,
}

impl WasapiBackend {
    pub(crate) fn new() -> Self {
        let notices = Arc::new(Mutex::new(VecDeque::new()));
        let stop = Arc::new(AtomicBool::new(false));
        // the monitor is a COM object registered in the apartment of the
        // thread that made it, and stays on that thread: a thread of its
        // own, which polls it and leaves what it saw where any thread can
        // read it. The engine's own thread affinity is nobody's business
        // that way, and the backend is Send because it holds no COM object.
        let watcher = {
            let notices = Arc::clone(&notices);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("sipral-audio-watch".to_owned())
                .spawn(move || watch(&notices, &stop))
                .ok()
        };
        Self {
            notices,
            stop,
            watcher,
            processing: true,
        }
    }
}

impl Drop for WasapiBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

/// The watcher's thread: the monitor, polled until told to stop.
fn watch(notices: &Mutex<VecDeque<Notice>>, stop: &AtomicBool) {
    let Ok(monitor) = DeviceMonitor::new() else {
        return;
    };
    while !stop.load(Ordering::Acquire) {
        while let Some(event) = monitor.poll() {
            let notice = match event {
                DeviceEvent::ListChanged => Notice::ListChanged,
                DeviceEvent::DefaultChanged(Direction::Input) => {
                    Notice::DefaultChanged(crate::device::Direction::Input)
                }
                DeviceEvent::DefaultChanged(Direction::Output) => {
                    Notice::DefaultChanged(crate::device::Direction::Output)
                }
                _ => continue,
            };
            notices
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(notice);
        }
        std::thread::sleep(WATCH_EVERY);
    }
    let _ = monitor.close();
}

fn refused(error: &sipral_io_wasapi::Error) -> BackendError {
    match *error {
        sipral_io_wasapi::Error::NoDevice => BackendError::NoDevice,
        _ => BackendError::Refused(error.to_string()),
    }
}

fn config_for(
    identity: Option<&str>,
    wanted: Format,
    processing: bool,
) -> Result<StreamConfig, BackendError> {
    let frame = u32::try_from(wanted.frame_samples).unwrap_or(960);
    let format = StreamFormat::new(wanted.sample_rate_hz, frame).ok_or_else(|| {
        BackendError::Refused(format!(
            "{} Hz in frames of {} is not a format a stream takes",
            wanted.sample_rate_hz, wanted.frame_samples
        ))
    })?;
    let config = match identity {
        Some(identity) => StreamConfig::on(DeviceId::new(identity), format),
        None => StreamConfig::new(format),
    };
    Ok(StreamConfig {
        processing,
        ..config
    })
}

const fn format_of(format: StreamFormat) -> Format {
    Format {
        sample_rate_hz: format.sample_rate_hz(),
        frame_samples: format.frame_samples(),
    }
}

impl Backend for WasapiBackend {
    fn devices(&mut self) -> Result<Vec<RawDevice>, BackendError> {
        let mut found: Vec<RawDevice> = Vec::new();
        for device in sipral_io_wasapi::devices().map_err(|error| refused(&error))? {
            // an endpoint that will not say how many channels it has is
            // still an endpoint, in that direction, with one at least
            let channels = u32::from(
                sipral_io_wasapi::channels(&device.id, device.direction)
                    .unwrap_or(1)
                    .max(1),
            );
            let (input_channels, output_channels) = match device.direction {
                Direction::Input => (channels, 0),
                Direction::Output => (0, channels),
            };
            found.push(RawDevice {
                identity: device.id.as_str().to_owned(),
                name: device.name,
                input_channels,
                output_channels,
                default_input: device.is_default && device.direction == Direction::Input,
                default_output: device.is_default && device.direction == Direction::Output,
            });
        }
        Ok(found)
    }

    fn set_system_echo_cancellation(&mut self, on: bool) {
        self.processing = on;
    }

    fn poll_notice(&mut self) -> Option<Notice> {
        self.notices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    fn open_capture(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn CaptureStream>, BackendError> {
        let config = config_for(identity, wanted, self.processing)?;
        let mut stream = WasapiCapture::open(&config).map_err(|error| refused(&error))?;
        stream.start().map_err(|error| refused(&error))?;
        Ok(Box::new(Capture {
            identity: stream.device().id.as_str().to_owned(),
            lost: false,
            stream,
        }))
    }

    fn open_playback(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError> {
        let config = config_for(identity, wanted, self.processing)?;
        let mut stream = WasapiPlayback::open(&config).map_err(|error| refused(&error))?;
        stream.start().map_err(|error| refused(&error))?;
        Ok(Box::new(Playback {
            identity: stream.device().id.as_str().to_owned(),
            depth: config
                .depth_frames
                .saturating_mul(stream.format().frame_samples()),
            lost: false,
            stream,
        }))
    }
}

struct Capture {
    stream: WasapiCapture,
    identity: String,
    lost: bool,
}

impl StreamCommon for Capture {
    fn format(&self) -> Format {
        format_of(self.stream.format())
    }

    fn identity(&self) -> &str {
        &self.identity
    }

    fn lost(&mut self) -> bool {
        if !self.lost && self.stream.poll() == Some(StreamEvent::DeviceLost) {
            self.lost = true;
        }
        self.lost
    }

    fn controls(&self) -> Controls {
        self.stream.controls()
    }

    fn latency(&self) -> Duration {
        self.stream.latency()
    }
}

impl CaptureStream for Capture {
    fn read(&mut self, frame: &mut [i16]) -> bool {
        self.stream.read(frame)
    }

    fn system_echo_cancellation(&self) -> bool {
        self.stream.category().is_communications()
    }
}

struct Playback {
    stream: WasapiPlayback,
    identity: String,
    depth: usize,
    lost: bool,
}

impl StreamCommon for Playback {
    fn format(&self) -> Format {
        format_of(self.stream.format())
    }

    fn identity(&self) -> &str {
        &self.identity
    }

    fn lost(&mut self) -> bool {
        if !self.lost && self.stream.poll() == Some(StreamEvent::DeviceLost) {
            self.lost = true;
        }
        self.lost
    }

    fn controls(&self) -> Controls {
        self.stream.controls()
    }

    fn latency(&self) -> Duration {
        self.stream.latency()
    }
}

impl PlaybackStream for Playback {
    fn write(&mut self, frame: &[i16]) -> bool {
        self.stream.write(frame)
    }

    fn queued(&self) -> usize {
        self.depth.saturating_sub(self.stream.room())
    }
}
