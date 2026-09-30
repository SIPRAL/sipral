// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! macOS and iOS, over `sipral-io-coreaudio`'s units.
//!
//! A call's microphone and loudspeaker are the two halves of one
//! voice-processing unit, the one a process may have: the engine asks for
//! both at once ([`Backend::open_duplex`]) and the unit opens with each half
//! on its own device — on macOS the microphone is named apart from the
//! loudspeaker, without moving the system's default input. Which device each
//! half actually landed on is read back from the unit and reported.
//!
//! A ringer on a device of its own is not a second voice-processing unit.
//! It only plays, needs no echo canceller and no microphone, and a second
//! voice unit beside the call's is what the framework does not support; so
//! it is a plain output unit ([`StreamKind::Playback`]), which opens on any
//! output device beside the call's. A ringer on the loudspeaker's device is
//! mixed into the call's unit by the engine and opens nothing.
//!
//! On iOS there is no device list at all — the route is the audio session's
//! and the application's — so the list is empty, the unit follows the
//! session, and only the loudspeaker role is offered for choosing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sipral_io_common::level::Controls;
use sipral_io_coreaudio::{Stream, StreamConfig, StreamEvent, StreamFormat, StreamKind};

use crate::backend::{
    Backend, BackendError, CaptureStream, Duplex, Format, Notice, PlaybackStream, RawDevice,
    StreamCommon,
};
use crate::device::Role;

/// How long an open waits for the process's voice unit to be given back by
/// the halves the engine has just let go of, which the pump drops on its
/// own thread. Within the engine's probe wait, so that a unit held for good
/// — by another stack in the same process — is a refusal and not a hang.
const ROOM_WAIT: Duration = Duration::from_secs(2);

/// The platform's backend.
pub(crate) struct CoreAudioBackend {
    #[cfg(target_os = "macos")]
    monitor: Option<sipral_io_coreaudio::DeviceMonitor>,
}

/// One unit, shared by its halves: two for the voice unit, one for a unit
/// that only plays.
struct Unit {
    stream: Mutex<Option<Stream>>,
    lost: AtomicBool,
    format: Format,
    output: String,
    input: String,
    latency: Duration,
    voice: bool,
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
        }
    }

    /// Open a unit of `kind`, the loudspeaker's half on `speaker` and — for
    /// the voice unit — the microphone's on `microphone`.
    fn open_unit(
        kind: StreamKind,
        speaker: Option<&str>,
        microphone: Option<&str>,
        wanted: Format,
    ) -> Result<Arc<Unit>, BackendError> {
        let frame = u32::try_from(wanted.frame_samples).unwrap_or(960);
        let format = StreamFormat::new(wanted.sample_rate_hz, frame).ok_or_else(|| {
            BackendError::Refused(format!(
                "{} Hz in frames of {} is not a format the unit takes",
                wanted.sample_rate_hz, wanted.frame_samples
            ))
        })?;
        let mut config = StreamConfig::new(format);
        config.kind = kind;
        #[cfg(target_os = "macos")]
        {
            use sipral_io_coreaudio::DeviceChoice;
            let preferred = |identity: Option<&str>| {
                identity.map_or(DeviceChoice::System, |uid| {
                    DeviceChoice::Preferred(uid.to_owned())
                })
            };
            config.device = preferred(speaker);
            config.capture_device = preferred(microphone);
        }
        // iOS has no device to name: the route is the session's
        #[cfg(not(target_os = "macos"))]
        let _ = (speaker, microphone);
        let voice = kind == StreamKind::Voice;
        if voice {
            wait_for_room();
        }
        let mut stream = Stream::open(config).map_err(|error| refused(&error))?;
        stream.start().map_err(|error| refused(&error))?;
        let (output, input) = landed(&stream, voice);
        let latency = stream.latency();
        Ok(Arc::new(Unit {
            stream: Mutex::new(Some(stream)),
            lost: AtomicBool::new(false),
            format: wanted,
            output,
            input,
            latency,
            voice,
        }))
    }
}

/// Wait, a bounded time, for the process's voice unit to be free: the
/// engine reopens a call's pair by letting go of the old halves first, and
/// the pump drops them on its own thread. Past the wait the open goes ahead
/// and is refused by the unit itself if the room is still taken.
fn wait_for_room() {
    let started = Instant::now();
    while sipral_io_coreaudio::voice_units_open() > 0 && started.elapsed() < ROOM_WAIT {
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn refused(error: &sipral_io_coreaudio::Error) -> BackendError {
    BackendError::Refused(error.to_string())
}

/// The identities of the devices each half landed on, on macOS; on iOS the
/// session's route, unnamed. A unit that only plays has no microphone half.
#[cfg(target_os = "macos")]
fn landed(stream: &Stream, voice: bool) -> (String, String) {
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
    let input = if voice {
        identity(stream.capture_device())
    } else {
        String::new()
    };
    (identity(stream.device()), input)
}

#[cfg(not(target_os = "macos"))]
fn landed(_: &Stream, _: bool) -> (String, String) {
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

    fn open_duplex(
        &mut self,
        microphone: Option<&str>,
        speaker: Option<&str>,
        wanted: Format,
    ) -> Duplex {
        match Self::open_unit(StreamKind::Voice, speaker, microphone, wanted) {
            Ok(unit) => (
                Ok(Box::new(Half {
                    unit: Arc::clone(&unit),
                    capture: true,
                })),
                Ok(Box::new(Half {
                    unit,
                    capture: false,
                })),
            ),
            Err(error) => (Err(error.clone()), Err(error)),
        }
    }

    fn open_capture(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn CaptureStream>, BackendError> {
        // a microphone is only ever the voice unit's, whose loudspeaker half
        // is let go of here and plays nothing
        self.open_duplex(identity, None, wanted).0
    }

    fn open_playback(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError> {
        // an output on its own — the ringer's — is a unit that only plays,
        // beside the call's voice unit rather than a second one of those
        let unit = Self::open_unit(StreamKind::Playback, identity, None, wanted)?;
        Ok(Box::new(Half {
            unit,
            capture: false,
        }))
    }

    fn duplex_only(&self) -> bool {
        true
    }

    fn chooses(&self, role: Role) -> bool {
        // iOS routes by the audio session, and a ringer there is the
        // application's to play; a Mac names every device
        cfg!(target_os = "macos") || role == Role::Speaker
    }
}

/// One half of a unit.
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
        // the voice unit reports the loop once; its capture half carries it
        // so that the sum of the two halves is the loop and not twice it. A
        // unit that only plays has the one half, which carries its own.
        if self.capture || !self.unit.voice {
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
