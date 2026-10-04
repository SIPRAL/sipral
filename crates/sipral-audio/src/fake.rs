// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A platform made of fakes, for testing the engine's rules without a
//! device in the room.
//!
//! The test holds a [`FakeControl`] and plugs devices in, pulls them out,
//! moves the default, hangs the driver and feeds the microphone; the engine
//! holds the [`FakeBackend`] and sees exactly what a platform would show it.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sipral_io_common::level::{Channel, Controls, window_samples};

use crate::backend::{
    Backend, BackendError, CaptureStream, Duplex, Format, Notice, PlaybackStream, Promote,
    Promoted, RawDevice, StreamCommon,
};
use crate::call::{CallAudio, CallGone, Outgoing};

/// One fake device's state, shared between the control and any stream open
/// on it.
#[derive(Default)]
struct FakeDevice {
    /// Frames the microphone will deliver next, at the device's rate.
    microphone: VecDeque<Vec<i16>>,
    /// Everything the loudspeaker was written, after gain and mute.
    played: Vec<i16>,
    /// Set when the device is pulled out from under its streams.
    lost: bool,
    /// How long the next write to it takes, once.
    stall: Option<Duration>,
    /// Set when a write has started taking that long.
    stalled: bool,
}

// each flag is one independent way a test bends the fake platform
#[allow(clippy::struct_excessive_bools)]
struct State {
    devices: Vec<RawDevice>,
    plugged: Vec<Arc<Mutex<FakeDevice>>>,
    notices: VecDeque<Notice>,
    refuse: Option<BackendError>,
    hung: bool,
    rate_hz: u32,
    system_echo_cancellation: bool,
    /// Whether the engine asked for the platform's echo cancellation; a
    /// stream claims it only when the platform has it and it was asked for.
    echo_asked: bool,
    opens: usize,
    ringer_opens: usize,
    duplex_only: bool,
    chooses_every_role: bool,
    units: Arc<Units>,
    /// How long each stream takes to open, as a USB headset's does.
    open_delay: Option<Duration>,
    teardown: Arc<Teardown>,
    /// Whether the fake has a scheduling class to grant, and whether it
    /// grants it: `None` for a platform with none.
    scheduling: Option<bool>,
    /// The names of the threads that asked for it.
    scheduled: Arc<Mutex<Vec<String>>>,
}

/// Whether a stream being let go of is held there, as a platform whose
/// teardown waits for another thread holds it, and how many have gone.
#[derive(Default)]
struct Teardown {
    held: Mutex<bool>,
    released: Condvar,
    finished: AtomicUsize,
}

impl Teardown {
    fn pass(&self) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        while *held {
            held = self
                .released
                .wait(held)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(held);
        self.finished.fetch_add(1, Ordering::AcqRel);
    }
}

/// The duplex units a duplex fake has open, counted the way a platform with
/// room for one would have to count them: each pair of halves is one unit,
/// alive until both halves are gone.
#[derive(Default)]
struct Units {
    alive: AtomicUsize,
    most: AtomicUsize,
    opened: AtomicUsize,
}

/// One duplex unit, shared by its two halves.
struct UnitHeld(Arc<Units>);

impl UnitHeld {
    fn open(units: &Arc<Units>) -> Arc<Self> {
        let alive = units.alive.fetch_add(1, Ordering::AcqRel) + 1;
        units.most.fetch_max(alive, Ordering::AcqRel);
        units.opened.fetch_add(1, Ordering::AcqRel);
        Arc::new(Self(Arc::clone(units)))
    }
}

impl Drop for UnitHeld {
    fn drop(&mut self) {
        self.0.alive.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The test's side of the fake platform.
#[derive(Clone)]
pub struct FakeControl {
    state: Arc<(Mutex<State>, Condvar)>,
}

fn lock(state: &(Mutex<State>, Condvar)) -> MutexGuard<'_, State> {
    state.0.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeControl {
    /// A platform with nothing plugged in, delivering at `rate_hz`.
    #[must_use]
    pub fn new(rate_hz: u32) -> Self {
        Self {
            state: Arc::new((
                Mutex::new(State {
                    devices: Vec::new(),
                    plugged: Vec::new(),
                    notices: VecDeque::new(),
                    refuse: None,
                    hung: false,
                    rate_hz,
                    system_echo_cancellation: false,
                    echo_asked: true,
                    opens: 0,
                    ringer_opens: 0,
                    duplex_only: false,
                    chooses_every_role: false,
                    units: Arc::new(Units::default()),
                    open_delay: None,
                    teardown: Arc::new(Teardown::default()),
                    scheduling: None,
                    scheduled: Arc::new(Mutex::new(Vec::new())),
                }),
                Condvar::new(),
            )),
        }
    }

    /// The backend the engine is given.
    #[must_use]
    pub fn backend(&self) -> Box<dyn Backend> {
        Box::new(FakeBackend {
            state: Arc::clone(&self.state),
        })
    }

    /// Plug a device in and announce it.
    pub fn plug(&self, identity: &str, name: &str, inputs: u32, outputs: u32) {
        let mut state = lock(&self.state);
        state.devices.push(RawDevice {
            identity: identity.to_owned(),
            name: name.to_owned(),
            input_channels: inputs,
            output_channels: outputs,
            default_input: false,
            default_output: false,
        });
        state
            .plugged
            .push(Arc::new(Mutex::new(FakeDevice::default())));
        state.notices.push_back(Notice::ListChanged);
    }

    /// Pull a device out: it leaves the list, any stream on it reports the
    /// loss, and the platform announces the change. A default that went
    /// moves to the first device left that can take it, and that is
    /// announced too, as an operating system does.
    pub fn unplug(&self, identity: &str) {
        let mut state = lock(&self.state);
        let Some(at) = state
            .devices
            .iter()
            .position(|device| device.identity == identity)
        else {
            return;
        };
        let gone = state.devices.remove(at);
        let plugged = state.plugged.remove(at);
        plugged.lock().unwrap_or_else(PoisonError::into_inner).lost = true;
        state.notices.push_back(Notice::ListChanged);
        if gone.default_input
            && let Some(next) = state
                .devices
                .iter_mut()
                .find(|device| device.input_channels > 0)
        {
            next.default_input = true;
            state
                .notices
                .push_back(Notice::DefaultChanged(crate::device::Direction::Input));
        }
        if gone.default_output
            && let Some(next) = state
                .devices
                .iter_mut()
                .find(|device| device.output_channels > 0)
        {
            next.default_output = true;
            state
                .notices
                .push_back(Notice::DefaultChanged(crate::device::Direction::Output));
        }
    }

    /// Make a device the system's default for one direction and announce it.
    pub fn make_default(&self, identity: &str, direction: crate::device::Direction) {
        let mut state = lock(&self.state);
        for device in &mut state.devices {
            let this = device.identity == identity;
            match direction {
                crate::device::Direction::Input => device.default_input = this,
                crate::device::Direction::Output => device.default_output = this,
            }
        }
        state.notices.push_back(Notice::DefaultChanged(direction));
    }

    /// Forget what the platform announced so far: what a test's setup
    /// plugged in is not news the engine should hear about.
    pub fn forget_notices(&self) {
        lock(&self.state).notices.clear();
    }

    /// Refuse every open from now on with `error`, or none for `None`.
    pub fn refuse_opens(&self, error: Option<BackendError>) {
        lock(&self.state).refuse = error;
    }

    /// Whether the fake's microphone claims the platform cancels echo.
    pub fn set_system_echo_cancellation(&self, on: bool) {
        lock(&self.state).system_echo_cancellation = on;
    }

    /// Whether the engine asked the platform for its echo cancellation.
    #[must_use]
    pub fn echo_cancellation_asked(&self) -> bool {
        lock(&self.state).echo_asked
    }

    /// Whether the fake behaves like a duplex-only platform: the microphone
    /// and the loudspeaker opened together as one unit.
    pub fn set_duplex_only(&self, on: bool) {
        lock(&self.state).duplex_only = on;
    }

    /// Whether a duplex fake lets every role be chosen, as macOS does —
    /// the microphone named apart from the loudspeaker, a ringer opened as
    /// an output of its own — rather than only the loudspeaker.
    pub fn set_chooses_every_role(&self, on: bool) {
        lock(&self.state).chooses_every_role = on;
    }

    /// How many duplex units are open right now.
    #[must_use]
    pub fn units_alive(&self) -> usize {
        lock(&self.state).units.alive.load(Ordering::Acquire)
    }

    /// The most duplex units that were ever open at once.
    #[must_use]
    pub fn units_at_most(&self) -> usize {
        lock(&self.state).units.most.load(Ordering::Acquire)
    }

    /// How many duplex units were opened so far.
    #[must_use]
    pub fn units_opened(&self) -> usize {
        lock(&self.state).units.opened.load(Ordering::Acquire)
    }

    /// Make every stream take `delay` to open from now on, or none for
    /// `None`: what a USB headset under the voice unit takes.
    pub fn set_open_delay(&self, delay: Option<Duration>) {
        lock(&self.state).open_delay = delay;
    }

    /// Hold every stream being let go of until
    /// [`FakeControl::release_teardown`], as a platform whose teardown
    /// waits for a thread that is busy elsewhere does.
    pub fn hold_teardown(&self) {
        let teardown = Arc::clone(&lock(&self.state).teardown);
        *teardown.held.lock().unwrap_or_else(PoisonError::into_inner) = true;
    }

    /// Let the streams held by [`FakeControl::hold_teardown`] go.
    pub fn release_teardown(&self) {
        let teardown = Arc::clone(&lock(&self.state).teardown);
        *teardown.held.lock().unwrap_or_else(PoisonError::into_inner) = false;
        teardown.released.notify_all();
    }

    /// How many streams have been let go of so far.
    #[must_use]
    pub fn teardowns(&self) -> usize {
        lock(&self.state).teardown.finished.load(Ordering::Acquire)
    }

    /// Give the fake a scheduling class for the pump's thread, granted or
    /// refused, or take it away for `None`.
    pub fn set_scheduling(&self, granted: Option<bool>) {
        lock(&self.state).scheduling = granted;
    }

    /// The names of the threads that asked for the scheduling class.
    #[must_use]
    pub fn scheduled(&self) -> Vec<String> {
        let scheduled = Arc::clone(&lock(&self.state).scheduled);
        scheduled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Make every platform call block until [`FakeControl::release`].
    pub fn hang(&self) {
        lock(&self.state).hung = true;
    }

    /// Let a hung platform answer again.
    pub fn release(&self) {
        lock(&self.state).hung = false;
        self.state.1.notify_all();
    }

    /// How many streams were opened so far.
    #[must_use]
    pub fn opens(&self) -> usize {
        lock(&self.state).opens
    }

    /// How many of those were opened as a ringer.
    #[must_use]
    pub fn ringer_opens(&self) -> usize {
        lock(&self.state).ringer_opens
    }

    /// Queue one microphone frame on a device, at the platform's rate.
    pub fn speak_into(&self, identity: &str, frame: &[i16]) {
        if let Some(device) = self.device(identity) {
            device
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .microphone
                .push_back(frame.to_vec());
        }
    }

    /// Make the next write to a device take `how_long`, as a driver that
    /// holds the pump's thread does.
    pub fn stall_next_write(&self, identity: &str, how_long: Duration) {
        if let Some(device) = self.device(identity) {
            let mut device = device.lock().unwrap_or_else(PoisonError::into_inner);
            device.stall = Some(how_long);
            device.stalled = false;
        }
    }

    /// Whether the write [`FakeControl::stall_next_write`] set up has begun.
    #[must_use]
    pub fn stalled(&self, identity: &str) -> bool {
        self.device(identity).is_some_and(|device| {
            device
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .stalled
        })
    }

    /// Everything a device has played so far.
    #[must_use]
    pub fn played_by(&self, identity: &str) -> Vec<i16> {
        self.device(identity).map_or_else(Vec::new, |device| {
            device
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .played
                .clone()
        })
    }

    fn device(&self, identity: &str) -> Option<Arc<Mutex<FakeDevice>>> {
        let state = lock(&self.state);
        let at = state
            .devices
            .iter()
            .position(|device| device.identity == identity)?;
        state.plugged.get(at).cloned()
    }
}

/// What opening a fake device answers: its identity, its state, the format
/// it delivers, whether it claims to cancel echo, and what holds its
/// teardown.
type OpenedFake = (String, Arc<Mutex<FakeDevice>>, Format, bool, Arc<Teardown>);

/// The engine's side of the fake platform.
pub struct FakeBackend {
    state: Arc<(Mutex<State>, Condvar)>,
}

impl FakeBackend {
    /// Wait out a hang, then take the state.
    fn ready(&self) -> MutexGuard<'_, State> {
        let mut state = lock(&self.state);
        while state.hung {
            state = self
                .state
                .1
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state
    }

    fn open(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
        input: bool,
    ) -> Result<OpenedFake, BackendError> {
        let delay = lock(&self.state).open_delay;
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        let mut state = self.ready();
        if let Some(error) = state.refuse.clone() {
            return Err(error);
        }
        let at = match identity {
            Some(identity) => state
                .devices
                .iter()
                .position(|device| device.identity == identity),
            None => state.devices.iter().position(|device| {
                if input {
                    device.default_input
                } else {
                    device.default_output
                }
            }),
        }
        .ok_or(BackendError::NoDevice)?;
        let device = state.devices.get(at).ok_or(BackendError::NoDevice)?;
        let channels = if input {
            device.input_channels
        } else {
            device.output_channels
        };
        if channels == 0 {
            return Err(BackendError::Refused(format!(
                "{} has no {} channels",
                device.identity,
                if input { "input" } else { "output" }
            )));
        }
        let identity = device.identity.clone();
        let plugged = state
            .plugged
            .get(at)
            .cloned()
            .ok_or(BackendError::NoDevice)?;
        // the platform's own rate wins, as it does on Windows
        let rate = state.rate_hz;
        let format = Format {
            sample_rate_hz: rate,
            frame_samples: wanted.frame_samples * rate as usize
                / wanted.sample_rate_hz.max(1) as usize,
        };
        state.opens += 1;
        let cancels = state.system_echo_cancellation && state.echo_asked;
        Ok((
            identity,
            plugged,
            format,
            cancels,
            Arc::clone(&state.teardown),
        ))
    }
}

impl Backend for FakeBackend {
    fn devices(&mut self) -> Result<Vec<RawDevice>, BackendError> {
        Ok(self.ready().devices.clone())
    }

    fn poll_notice(&mut self) -> Option<Notice> {
        lock(&self.state).notices.pop_front()
    }

    fn set_system_echo_cancellation(&mut self, on: bool) {
        lock(&self.state).echo_asked = on;
    }

    fn open_capture(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn CaptureStream>, BackendError> {
        Ok(Box::new(FakeStream::new(
            self.open(identity, wanted, true)?,
            None,
        )))
    }

    fn open_duplex(
        &mut self,
        microphone: Option<&str>,
        speaker: Option<&str>,
        wanted: Format,
    ) -> Duplex {
        let playback = self.open(speaker, wanted, false);
        let capture = self.open(microphone, wanted, true);
        // a duplex fake's two halves are one unit, alive until the second
        // half goes; any other fake's are two streams
        let unit = if capture.is_ok() && playback.is_ok() {
            let state = lock(&self.state);
            state.duplex_only.then(|| UnitHeld::open(&state.units))
        } else {
            None
        };
        (
            capture.map(|opened| -> Box<dyn CaptureStream> {
                Box::new(FakeStream::new(opened, unit.clone()))
            }),
            playback.map(|opened| -> Box<dyn PlaybackStream> {
                Box::new(FakeStream::new(opened, unit))
            }),
        )
    }

    fn chooses(&self, role: crate::device::Role) -> bool {
        let state = lock(&self.state);
        state.chooses_every_role || role == crate::device::Role::Speaker || !state.duplex_only
    }

    fn open_playback(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError> {
        Ok(Box::new(FakeStream::new(
            self.open(identity, wanted, false)?,
            None,
        )))
    }

    fn open_ringer(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError> {
        let opened = self.open_playback(identity, wanted)?;
        lock(&self.state).ringer_opens += 1;
        Ok(opened)
    }

    fn duplex_only(&self) -> bool {
        lock(&self.state).duplex_only
    }

    fn pump_scheduling(&self) -> Option<Promote> {
        let state = lock(&self.state);
        let granted = state.scheduling?;
        let scheduled = Arc::clone(&state.scheduled);
        Some(Arc::new(move || -> Option<Promoted> {
            let name = std::thread::current().name().unwrap_or_default().to_owned();
            scheduled
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(name);
            granted.then(|| Box::new(()) as Promoted)
        }))
    }
}

struct FakeStream {
    identity: String,
    device: Arc<Mutex<FakeDevice>>,
    format: Format,
    channel: Arc<Channel>,
    aec: bool,
    /// The duplex unit this stream is half of, where it is half of one:
    /// held, never read, so that the unit goes when its last half does.
    _unit: Option<Arc<UnitHeld>>,
    teardown: Arc<Teardown>,
}

impl FakeStream {
    fn new(
        (identity, device, format, aec, teardown): OpenedFake,
        unit: Option<Arc<UnitHeld>>,
    ) -> Self {
        Self {
            identity,
            device,
            format,
            channel: Arc::new(Channel::new(window_samples(format.sample_rate_hz))),
            aec,
            _unit: unit,
            teardown,
        }
    }
}

impl Drop for FakeStream {
    fn drop(&mut self) {
        self.teardown.pass();
    }
}

impl StreamCommon for FakeStream {
    fn format(&self) -> Format {
        self.format
    }

    fn identity(&self) -> &str {
        &self.identity
    }

    fn lost(&mut self) -> bool {
        self.device
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .lost
    }

    fn controls(&self) -> Controls {
        Controls::new(&self.channel)
    }

    fn latency(&self) -> Duration {
        Duration::from_millis(15)
    }
}

impl CaptureStream for FakeStream {
    fn read(&mut self, frame: &mut [i16]) -> bool {
        let mut device = self.device.lock().unwrap_or_else(PoisonError::into_inner);
        if device.lost {
            return false;
        }
        let Some(next) = device.microphone.pop_front() else {
            return false;
        };
        for (slot, sample) in frame
            .iter_mut()
            .zip(next.iter().chain(std::iter::repeat(&0)))
        {
            *slot = *sample;
        }
        self.channel.apply(frame, frame.len());
        true
    }

    fn system_echo_cancellation(&self) -> bool {
        self.aec
    }
}

impl PlaybackStream for FakeStream {
    fn write(&mut self, frame: &[i16]) -> bool {
        let stall = self
            .device
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stall
            .take();
        if let Some(stall) = stall {
            self.device
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .stalled = true;
            std::thread::sleep(stall);
        }
        let mut device = self.device.lock().unwrap_or_else(PoisonError::into_inner);
        if device.lost {
            return false;
        }
        let mut copy = frame.to_vec();
        let covered = copy.len();
        self.channel.apply(&mut copy, covered);
        device.played.extend_from_slice(&copy);
        true
    }

    fn queued(&self) -> usize {
        // a loudspeaker that plays what it is given at once
        0
    }
}

/// A call made of fakes: it records what the microphone gave it and plays
/// a constant it was told to.
pub struct FakeCall {
    shared: Arc<Mutex<FakeCallState>>,
}

#[derive(Default)]
struct FakeCallState {
    rate_hz: u32,
    frame_samples: usize,
    captured: Vec<Vec<i16>>,
    plays: i16,
    ended: bool,
    destination: Option<std::net::SocketAddr>,
    render_delay: Option<Duration>,
    pulls: usize,
}

/// The test's side of a [`FakeCall`].
#[derive(Clone)]
pub struct FakeCallControl {
    shared: Arc<Mutex<FakeCallState>>,
}

impl FakeCallControl {
    /// A call at `rate_hz`, twenty-millisecond frames, playing `plays` in
    /// every sample and sending every captured frame to `destination`.
    #[must_use]
    pub fn new(rate_hz: u32, plays: i16, destination: std::net::SocketAddr) -> Self {
        Self {
            shared: Arc::new(Mutex::new(FakeCallState {
                rate_hz,
                frame_samples: (rate_hz / 50) as usize,
                captured: Vec::new(),
                plays,
                ended: false,
                destination: Some(destination),
                render_delay: None,
                pulls: 0,
            })),
        }
    }

    /// The call the engine is given.
    #[must_use]
    pub fn call(&self) -> Box<dyn CallAudio> {
        Box::new(FakeCall {
            shared: Arc::clone(&self.shared),
        })
    }

    /// Every frame the microphone gave the call, at the call's rate.
    #[must_use]
    pub fn captured(&self) -> Vec<Vec<i16>> {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .captured
            .clone()
    }

    /// The delay the pump last told the call, if it has told it one.
    #[must_use]
    pub fn render_delay(&self) -> Option<Duration> {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .render_delay
    }

    /// How many frames the loudspeaker side has pulled from the call.
    #[must_use]
    pub fn pulls(&self) -> usize {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pulls
    }

    /// Move the call to another rate, twenty-millisecond frames, as a
    /// re-negotiation onto another codec does under a live call.
    pub fn set_rate(&self, rate_hz: u32) {
        let mut state = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        state.rate_hz = rate_hz;
        state.frame_samples = (rate_hz / 50) as usize;
    }

    /// End the call's media.
    pub fn end(&self) {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ended = true;
    }
}

impl CallAudio for FakeCall {
    fn sample_rate(&self) -> Result<u32, CallGone> {
        let state = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        if state.ended {
            return Err(CallGone::Ended);
        }
        Ok(state.rate_hz)
    }

    fn frame_samples(&self) -> Result<usize, CallGone> {
        let state = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        if state.ended {
            return Err(CallGone::Ended);
        }
        Ok(state.frame_samples)
    }

    fn capture(&mut self, frame: &[i16], _now: Instant) -> Result<Option<Outgoing>, CallGone> {
        let mut state = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        if state.ended {
            return Err(CallGone::Ended);
        }
        state.captured.push(frame.to_vec());
        Ok(state.destination.map(|destination| Outgoing {
            destination,
            payload: frame
                .iter()
                .flat_map(|sample| sample.to_be_bytes())
                .collect(),
            transport: crate::call::Transport::Udp,
        }))
    }

    fn playback(&mut self, out: &mut [i16]) -> Result<(), CallGone> {
        let mut state = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        if state.ended {
            return Err(CallGone::Ended);
        }
        state.pulls += 1;
        out.fill(state.plays);
        Ok(())
    }

    fn set_render_delay(&mut self, delay: Duration) {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .render_delay = Some(delay);
    }
}
