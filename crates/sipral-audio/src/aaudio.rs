// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Android, over `sipral-io-aaudio`.
//!
//! Every stream is AAudio's and runs on a thread AAudio owns; the list, the
//! defaults and the route are `AudioManager`'s, reached through the Kotlin
//! binding's shim once the application has handed it a `Context`
//! (`sipral_io_aaudio::route`). Three things set this platform apart from
//! the desktop ones, and each is carried here:
//!
//! - **A call's output is routed, not opened on a device.** The platform
//!   puts every voice-communication stream on the communication device, so
//!   putting the loudspeaker role on a device is setting that route, and
//!   the stream is opened on the route rather than on the device; handing
//!   the role back to the system gives the route back. The microphone is
//!   opened on the device named, and follows the route when none is.
//! - **The ring is not a call.** It is opened as a ringtone stream, which
//!   the platform plays where a ring goes, on the device named if one is.
//! - **Changes are looked for.** The platform announces them to Java, so a
//!   watcher thread reads the list and the route a few times a second and
//!   reports what moved, leaving out what the engine moved itself.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sipral_io_aaudio::route::{self, Routes};
use sipral_io_aaudio::{Controls, JniPlatform, Stream, StreamConfig, Usage};

use crate::backend::{
    Backend, BackendError, CaptureStream, Format, Notice, PlaybackStream, RawDevice, StreamCommon,
};
use crate::device::Direction;

/// How often the watcher asks whether anything changed. The platform is
/// only read again once `route::POLL_INTERVAL` has passed.
const WATCH_EVERY: Duration = Duration::from_millis(100);

type Shared = Arc<Mutex<Routes<JniPlatform>>>;

fn lock(routes: &Shared) -> MutexGuard<'_, Routes<JniPlatform>> {
    routes.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The platform's backend.
pub(crate) struct AAudioBackend {
    routes: Shared,
    notices: Arc<Mutex<VecDeque<Notice>>>,
    stop: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
    /// Whether the microphone opens behind the platform's echo canceller.
    echo_cancellation: bool,
}

impl AAudioBackend {
    pub(crate) fn new() -> Self {
        let routes = Arc::new(Mutex::new(Routes::new(JniPlatform::find())));
        let notices = Arc::new(Mutex::new(VecDeque::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let watcher = {
            let routes = Arc::clone(&routes);
            let notices = Arc::clone(&notices);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("sipral-audio-watch".to_owned())
                .spawn(move || watch(&routes, &notices, &stop))
                .ok()
        };
        Self {
            routes,
            notices,
            stop,
            watcher,
            echo_cancellation: true,
        }
    }
}

impl Drop for AAudioBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
        lock(&self.routes).release(Instant::now());
    }
}

fn watch(routes: &Shared, notices: &Mutex<VecDeque<Notice>>, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        let seen = {
            let mut routes = lock(routes);
            let mut seen = Vec::new();
            while let Some(notice) = routes.poll_notice(Instant::now()) {
                seen.push(match notice {
                    route::Notice::ListChanged => Notice::ListChanged,
                    route::Notice::DefaultOutputChanged => {
                        Notice::DefaultChanged(Direction::Output)
                    }
                    route::Notice::DefaultInputChanged => Notice::DefaultChanged(Direction::Input),
                });
            }
            seen
        };
        if !seen.is_empty() {
            notices
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(seen);
        }
        std::thread::sleep(WATCH_EVERY);
    }
}

fn refused(error: &sipral_io_aaudio::Error) -> BackendError {
    BackendError::Refused(error.to_string())
}

impl AAudioBackend {
    fn open(
        &self,
        usage: Usage,
        device: Option<i32>,
        wanted: Format,
    ) -> Result<Opened, BackendError> {
        let stream = Stream::open(StreamConfig {
            usage,
            device,
            sample_rate_hz: wanted.sample_rate_hz,
            echo_cancellation: self.echo_cancellation,
        })
        .map_err(|error| refused(&error))?;
        // where it landed, by the identity the list gives it; the route's
        // default for a stream that does not say
        let mut routes = lock(&self.routes);
        let landed = Some(stream.device_id())
            .filter(|&id| id > 0)
            .and_then(|id| routes.identity_of(id))
            .or_else(|| {
                if usage == Usage::Microphone {
                    routes.default_input_identity()
                } else {
                    routes.default_output_identity()
                }
            })
            .unwrap_or_default();
        Ok(Opened {
            format: Format {
                sample_rate_hz: stream.sample_rate(),
                frame_samples: stream.frame_samples(),
            },
            controls: stream.controls(),
            stream,
            identity: landed,
            echo_cancellation: self.echo_cancellation,
        })
    }
}

impl Backend for AAudioBackend {
    fn devices(&mut self) -> Result<Vec<RawDevice>, BackendError> {
        Ok(lock(&self.routes)
            .devices()
            .into_iter()
            .map(|device| RawDevice {
                identity: device.identity,
                name: device.name,
                input_channels: device.input_channels,
                output_channels: device.output_channels,
                default_input: device.default_input,
                default_output: device.default_output,
            })
            .collect())
    }

    fn set_system_echo_cancellation(&mut self, on: bool) {
        self.echo_cancellation = on;
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
        let device = match identity {
            Some(identity) => Some(
                lock(&self.routes)
                    .source_of(identity)
                    .ok_or(BackendError::NoDevice)?,
            ),
            None => None,
        };
        Ok(Box::new(self.open(Usage::Microphone, device, wanted)?))
    }

    fn open_playback(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError> {
        {
            let mut routes = lock(&self.routes);
            match identity {
                Some(identity) => {
                    routes
                        .route_to(identity, Instant::now())
                        .map_err(|error| match error {
                            route::RouteError::Absent(_) => BackendError::NoDevice,
                            other => BackendError::Refused(other.to_string()),
                        })?;
                }
                None => routes.release(Instant::now()),
            }
        }
        // on the route just set: a voice-communication stream that names a
        // device of its own is one the platform may keep off the call's
        let mut opened = self.open(Usage::Call, None, wanted)?;
        if let Some(identity) = identity {
            identity.clone_into(&mut opened.identity);
        }
        Ok(Box::new(opened))
    }

    fn open_ringer(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError> {
        let device = match identity {
            Some(identity) => Some(
                lock(&self.routes)
                    .sink_of(identity)
                    .ok_or(BackendError::NoDevice)?,
            ),
            None => None,
        };
        let mut opened = self.open(Usage::Ring, device, wanted)?;
        if let Some(identity) = identity {
            identity.clone_into(&mut opened.identity);
        }
        Ok(Box::new(opened))
    }
}

/// One stream, in whichever direction it runs.
struct Opened {
    stream: Stream,
    identity: String,
    format: Format,
    controls: Controls,
    /// Whether it was opened behind the platform's echo canceller.
    echo_cancellation: bool,
}

impl StreamCommon for Opened {
    fn format(&self) -> Format {
        self.format
    }

    fn identity(&self) -> &str {
        &self.identity
    }

    fn lost(&mut self) -> bool {
        self.stream.lost()
    }

    fn controls(&self) -> Controls {
        self.controls.clone()
    }

    fn latency(&self) -> Duration {
        self.stream.latency()
    }
}

impl CaptureStream for Opened {
    fn read(&mut self, frame: &mut [i16]) -> bool {
        self.stream.read(frame)
    }

    fn system_echo_cancellation(&self) -> bool {
        // the voice-communication preset is the platform's own canceller,
        // on every phone that has one; the recognition preset has none
        self.echo_cancellation
    }
}

impl PlaybackStream for Opened {
    fn write(&mut self, frame: &[i16]) -> bool {
        self.stream.write(frame)
    }

    fn queued(&self) -> usize {
        self.stream.queued()
    }
}
