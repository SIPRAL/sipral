// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! macOS and iOS, over `sipral-io-coreaudio`'s voice-processing unit.
//!
//! The unit is duplex and there is one per process, so the microphone and
//! the loudspeaker are the two halves of one stream, opened together on the
//! loudspeaker's device: the engine asks for the loudspeaker first and the
//! microphone second, and the second answer is the other half of the first.
//! Naming a microphone of its own is refused ([`Backend::duplex_only`]);
//! which device the microphone actually landed on is read back from the
//! unit and reported. On iOS there is no device list at all — the route is
//! the audio session's and the application's — so the list is empty and
//! the unit follows the session.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use sipral_io_common::level::Controls;
use sipral_io_coreaudio::{Stream, StreamConfig, StreamEvent, StreamFormat};

use crate::backend::{
    Backend, BackendError, CaptureStream, Format, Notice, PlaybackStream, RawDevice, StreamCommon,
};

/// The platform's backend.
pub(crate) struct CoreAudioBackend {
    #[cfg(target_os = "macos")]
    monitor: Option<sipral_io_coreaudio::DeviceMonitor>,
    /// The unit the last `open_playback` opened, waiting for its
    /// microphone half to be asked for.
    pending: Option<Arc<Unit>>,
}

/// One voice-processing unit, shared by its two halves.
struct Unit {
    stream: Mutex<Option<Stream>>,
    lost: AtomicBool,
    format: Format,
    output: String,
    input: String,
    latency: Duration,
}

impl Unit {
    fn stream(&self) -> MutexGuard<'_, Option<Stream>> {
        self.stream.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lost(&self) -> bool {
        if self.lost.load(Ordering::Acquire) {
            return true;
        }
        let gone = self
            .stream()
            .as_mut()
            .is_some_and(|stream| stream.poll() == Some(StreamEvent::DeviceLost));
        if gone {
            self.lost.store(true, Ordering::Release);
        }
        gone
    }
}

impl CoreAudioBackend {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            monitor: sipral_io_coreaudio::DeviceMonitor::new().ok(),
            pending: None,
        }
    }

    fn open_unit(identity: Option<&str>, wanted: Format) -> Result<Arc<Unit>, BackendError> {
        let frame = u32::try_from(wanted.frame_samples).unwrap_or(960);
        let format = StreamFormat::new(wanted.sample_rate_hz, frame).ok_or_else(|| {
            BackendError::Refused(format!(
                "{} Hz in frames of {} is not a format the unit takes",
                wanted.sample_rate_hz, wanted.frame_samples
            ))
        })?;
        let config = match identity {
            #[cfg(target_os = "macos")]
            Some(uid) => StreamConfig::preferring(uid, format),
            // iOS has no device to name: the route is the session's
            #[cfg(not(target_os = "macos"))]
            Some(_) => StreamConfig::new(format),
            None => StreamConfig::new(format),
        };
        let mut stream = Stream::open(config).map_err(|error| refused(&error))?;
        stream.start().map_err(|error| refused(&error))?;
        let (output, input) = landed(&stream);
        let latency = stream.latency();
        Ok(Arc::new(Unit {
            stream: Mutex::new(Some(stream)),
            lost: AtomicBool::new(false),
            format: wanted,
            output,
            input,
            latency,
        }))
    }
}

fn refused(error: &sipral_io_coreaudio::Error) -> BackendError {
    BackendError::Refused(error.to_string())
}

/// The identities of the devices each half landed on, on macOS; on iOS the
/// session's route, unnamed.
#[cfg(target_os = "macos")]
fn landed(stream: &Stream) -> (String, String) {
    let identity = |device: Result<sipral_io_coreaudio::DeviceId, _>| {
        device
            .ok()
            .and_then(|id| {
                sipral_io_coreaudio::devices()
                    .ok()?
                    .into_iter()
                    .find(|device| device.id == id)
            })
            .map(identity_of)
            .unwrap_or_default()
    };
    (identity(stream.device()), identity(stream.capture_device()))
}

#[cfg(not(target_os = "macos"))]
fn landed(_: &Stream) -> (String, String) {
    (String::new(), String::new())
}

#[cfg(target_os = "macos")]
fn identity_of(device: sipral_io_coreaudio::Device) -> String {
    device
        .uid
        .unwrap_or_else(|| format!("coreaudio:{}", device.id.get()))
}

impl Backend for CoreAudioBackend {
    fn devices(&mut self) -> Result<Vec<RawDevice>, BackendError> {
        #[cfg(target_os = "macos")]
        {
            use sipral_io_coreaudio::Direction;
            let default_input = sipral_io_coreaudio::default_device(Direction::Input)
                .map_err(|error| refused(&error))?;
            let default_output = sipral_io_coreaudio::default_device(Direction::Output)
                .map_err(|error| refused(&error))?;
            Ok(sipral_io_coreaudio::devices()
                .map_err(|error| refused(&error))?
                .into_iter()
                .map(|device| RawDevice {
                    default_input: default_input == Some(device.id),
                    default_output: default_output == Some(device.id),
                    name: device.name.clone(),
                    input_channels: device.input_channels,
                    output_channels: device.output_channels,
                    identity: identity_of(device),
                })
                .collect())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(Vec::new())
        }
    }

    fn poll_notice(&mut self) -> Option<Notice> {
        #[cfg(target_os = "macos")]
        {
            use sipral_io_coreaudio::{DeviceEvent, Direction};
            match self.monitor.as_ref()?.poll()? {
                DeviceEvent::ListChanged => Some(Notice::ListChanged),
                DeviceEvent::DefaultChanged(Direction::Input) => {
                    Some(Notice::DefaultChanged(crate::device::Direction::Input))
                }
                DeviceEvent::DefaultChanged(Direction::Output) => {
                    Some(Notice::DefaultChanged(crate::device::Direction::Output))
                }
                _ => None,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    fn open_capture(
        &mut self,
        _identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn CaptureStream>, BackendError> {
        // the other half of the unit the loudspeaker just opened, or a unit
        // on the system's route when the loudspeaker was not asked for first
        let unit = match self.pending.take() {
            Some(unit) => unit,
            None => Self::open_unit(None, wanted)?,
        };
        Ok(Box::new(Half {
            unit,
            capture: true,
        }))
    }

    fn open_playback(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError> {
        let unit = Self::open_unit(identity, wanted)?;
        self.pending = Some(Arc::clone(&unit));
        Ok(Box::new(Half {
            unit,
            capture: false,
        }))
    }

    fn duplex_only(&self) -> bool {
        true
    }
}

/// One half of the unit.
struct Half {
    unit: Arc<Unit>,
    capture: bool,
}

impl Drop for Half {
    fn drop(&mut self) {
        // the unit closes when its last half goes, and closes cleanly: a
        // stream dropped inside a lock is still a stream dropped
        if Arc::strong_count(&self.unit) == 1
            && let Some(stream) = self.unit.stream().take()
        {
            let _ = stream.close();
        }
    }
}

impl StreamCommon for Half {
    fn format(&self) -> Format {
        self.unit.format
    }

    fn identity(&self) -> &str {
        if self.capture {
            &self.unit.input
        } else {
            &self.unit.output
        }
    }

    fn lost(&mut self) -> bool {
        self.unit.lost()
    }

    fn controls(&self) -> Controls {
        let stream = self.unit.stream();
        match stream.as_ref() {
            Some(stream) if self.capture => stream.capture_controls(),
            Some(stream) => stream.playback_controls(),
            None => Controls::new(&Arc::new(sipral_io_common::level::Channel::new(1))),
        }
    }

    fn latency(&self) -> Duration {
        // the unit reports the loop once; the capture half carries it so
        // that the sum of the two halves is the loop and not twice it
        if self.capture {
            self.unit.latency
        } else {
            Duration::ZERO
        }
    }
}

impl CaptureStream for Half {
    fn read(&mut self, frame: &mut [i16]) -> bool {
        self.unit
            .stream()
            .as_mut()
            .is_some_and(|stream| stream.read(frame))
    }

    fn system_echo_cancellation(&self) -> bool {
        true
    }
}

impl PlaybackStream for Half {
    fn write(&mut self, frame: &[i16]) -> bool {
        self.unit
            .stream()
            .as_mut()
            .is_some_and(|stream| stream.write(frame))
    }

    fn queued(&self) -> usize {
        self.unit.stream().as_mut().map_or(0, |stream| {
            let (_, playback) = stream.split();
            // the ring's depth is a frame count; what is queued is what is
            // not free
            let depth = self.unit.format.frame_samples.saturating_mul(16);
            depth.saturating_sub(playback.room())
        })
    }
}
