// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The engine: the devices named, chosen, opened and kept open.

use std::collections::VecDeque;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sipral_io_common::level::{Controls, Gain, Level};

use crate::backend::{
    Backend, BackendError, CaptureStream, Duplex, Format, Notice, PlaybackStream,
};
use crate::call::{CallAudio, CallId, Outgoing};
use crate::device::{
    AudioEvent, Change, DeviceHandle, DeviceInfo, Direction, Origin, Role, SelectError, Selection,
};
use crate::probe::{DEFAULT_PROBE_WAIT, probe};
use crate::pump::{Carried, Command, Finished, Pump, Report, Ring, Stream};

/// When the devices are opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Activation {
    /// When the first call's audio is attached, or a ring starts; closed
    /// again when the last is detached and the ring has stopped. What a
    /// desktop softphone wants.
    #[default]
    Automatic,
    /// Only when [`Engine::activate`] says so, whatever the calls do, until
    /// [`Engine::deactivate`]. What a phone wants: CallKit and the telecom
    /// framework say when the audio session is this application's, and a
    /// device opened before they do is a device that does not work.
    Manual,
}

/// How the engine is set up.
#[derive(Clone, Debug)]
pub struct Config {
    /// When the devices are opened.
    pub activation: Activation,
    /// How long a platform call may block before it is reported as stuck.
    pub probe_wait: Duration,
    /// The rate the devices are asked to run at. Every call is resampled
    /// between its own rate and this one; a platform that answers with
    /// another rate is taken at its word.
    pub device_rate_hz: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            activation: Activation::Automatic,
            probe_wait: DEFAULT_PROBE_WAIT,
            device_rate_hz: 48_000,
        }
    }
}

/// Where a role is running, and what it reports.
#[derive(Clone)]
struct Running {
    identity: String,
    controls: Controls,
    latency: Duration,
    system_echo_cancellation: bool,
    format: Format,
}

/// What the engine is doing right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// Whether the devices are open and the pump is running.
    pub active: bool,
    /// Whether the platform's own processing sits behind the microphone:
    /// the voice-processing unit on macOS and iOS, which cancels the
    /// loudspeaker's echo itself; on Windows, a stream the engine accepted
    /// as a communications stream, which puts the endpoint's own processing
    /// — where the endpoint has any; a virtual cable has none — behind it.
    /// An application that wants the echo gone regardless attaches a
    /// processor to each call, and the engine tells the call the
    /// loudspeaker-to-microphone delay for it ([`CallAudio::set_render_delay`]).
    pub system_echo_cancellation: bool,
    /// The loudspeaker-to-microphone delay the devices report, which is the
    /// reference an attached canceller needs.
    pub render_delay: Duration,
    /// The rate the microphone runs at, when open.
    pub microphone_rate_hz: Option<u32>,
    /// The rate the loudspeaker runs at, when open.
    pub speaker_rate_hz: Option<u32>,
}

/// A gain and a mute, per direction, kept here so that they outlive any one
/// device.
#[derive(Clone, Copy, Debug)]
struct Setting {
    gain: Gain,
    muted: bool,
}

impl Default for Setting {
    fn default() -> Self {
        Self {
            gain: Gain::UNITY,
            muted: false,
        }
    }
}

/// The pump's thread and the way to it.
struct PumpHandle {
    sender: Sender<Command>,
    thread: Option<PumpThread>,
    report: Arc<Report>,
}

impl PumpHandle {
    /// Wait for the pump to have acted on every command sent before this one
    /// — a stream dropped, in particular — or give up after a bounded wait
    /// on a pump that is not turning.
    ///
    /// The pump answers in the order it takes commands, so the answer is
    /// proof rather than a guess from a tick count: a tick already under way
    /// when a command was sent counts itself without having seen it.
    fn settle(&self) {
        let (done, answer) = mpsc::channel();
        if self.sender.send(Command::Settled(done)).is_ok() {
            let _ = answer.recv_timeout(Duration::from_secs(1));
        }
    }
}

/// The built-in audio engine.
///
/// One per stack. Everything here is called from the application's thread,
/// and nothing here waits on a device: a platform call is made from a thread
/// the engine can walk away from ([`Config::probe_wait`]), and the audio
/// itself runs on the pump's thread.
pub struct Engine {
    backend: Arc<Mutex<Box<dyn Backend>>>,
    duplex_only: bool,
    /// Which roles the platform lets the application put on a device.
    chooses: PerRole<bool>,
    config: Config,
    devices: Vec<DeviceInfo>,
    /// Whether the platform has answered a listing yet. Until it has, the
    /// list holds only what an activation happened to open, and a first read
    /// asks the platform rather than handing that partial list out.
    listed: bool,
    next_handle: u32,
    selection: PerRole<Selection>,
    running: PerRole<Option<Running>>,
    settings: PerDirection<Setting>,
    pump: Option<PumpHandle>,
    transmit: Option<Box<dyn FnMut(CallId, Outgoing) + Send>>,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
    attached: Vec<CallId>,
    /// The attached calls' audio while no pump runs to carry it: a call
    /// attached before a manual activation, and every call across a
    /// deactivation, handed to the next pump when it starts.
    parked: Carried,
    ringing: bool,
    events: VecDeque<AudioEvent>,
}

/// One of something per role.
#[derive(Clone, Copy, Debug, Default)]
struct PerRole<T> {
    microphone: T,
    speaker: T,
    ringer: T,
}

impl<T> PerRole<T> {
    const fn get(&self, role: Role) -> &T {
        match role {
            Role::Microphone => &self.microphone,
            Role::Speaker => &self.speaker,
            Role::Ringer => &self.ringer,
        }
    }

    const fn get_mut(&mut self, role: Role) -> &mut T {
        match role {
            Role::Microphone => &mut self.microphone,
            Role::Speaker => &mut self.speaker,
            Role::Ringer => &mut self.ringer,
        }
    }
}

/// One of something per direction.
#[derive(Clone, Copy, Debug, Default)]
struct PerDirection<T> {
    input: T,
    output: T,
}

impl<T> PerDirection<T> {
    const fn get(&self, direction: Direction) -> &T {
        match direction {
            Direction::Input => &self.input,
            Direction::Output => &self.output,
        }
    }

    const fn get_mut(&mut self, direction: Direction) -> &mut T {
        match direction {
            Direction::Input => &mut self.input,
            Direction::Output => &mut self.output,
        }
    }
}

/// The pump's thread, returning the transmit function it was given and the
/// calls it was carrying.
type PumpThread = JoinHandle<Finished>;

impl Engine {
    /// An engine over `backend`.
    ///
    /// `transmit` is handed every packet the pump produces, on the pump's
    /// thread: send it and return. `now` is the clock the calls are driven
    /// on, so that what the pump tells a call about time agrees with what
    /// the stack polling it says.
    pub fn new(
        backend: Box<dyn Backend>,
        config: Config,
        transmit: Box<dyn FnMut(CallId, Outgoing) + Send>,
        now: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        let duplex_only = backend.duplex_only();
        let chooses = PerRole {
            microphone: backend.chooses(Role::Microphone),
            speaker: backend.chooses(Role::Speaker),
            ringer: backend.chooses(Role::Ringer),
        };
        Self {
            backend: Arc::new(Mutex::new(backend)),
            duplex_only,
            chooses,
            config,
            devices: Vec::new(),
            listed: false,
            next_handle: 1,
            selection: PerRole::default(),
            running: PerRole::default(),
            settings: PerDirection::default(),
            pump: None,
            transmit: Some(transmit),
            now,
            attached: Vec::new(),
            parked: Vec::new(),
            ringing: false,
            events: VecDeque::new(),
        }
    }

    /// The same, on the system's own clock.
    pub fn on_system_clock(
        backend: Box<dyn Backend>,
        config: Config,
        transmit: Box<dyn FnMut(CallId, Outgoing) + Send>,
    ) -> Self {
        Self::new(backend, config, transmit, Arc::new(Instant::now))
    }

    // -- the list -----------------------------------------------------------

    /// Ask the platform what is there, and bring the list up to date.
    ///
    /// A device seen before keeps its handle; one that has gone keeps its
    /// row, marked absent; one that is new gets the next handle. A role
    /// whose chosen device has come back is reopened on it.
    ///
    /// # Errors
    /// [`BackendError::TimedOut`] when the platform did not answer in
    /// [`Config::probe_wait`], and the list is left as it was.
    pub fn refresh(&mut self) -> Result<&[DeviceInfo], BackendError> {
        let backend = Arc::clone(&self.backend);
        let found = probe(self.config.probe_wait, move || {
            let mut backend = match backend.try_lock() {
                Ok(backend) => backend,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                // a probe that timed out earlier is still inside the
                // platform, which is the same answer again
                Err(TryLockError::WouldBlock) => return Err(BackendError::TimedOut),
            };
            backend.devices()
        })?;
        self.absorb(found);
        self.listed = true;
        self.follow_preferences();
        Ok(&self.devices)
    }

    /// The list, asked of the platform first if it never has been.
    ///
    /// A new engine knows no device until something asks the platform: a
    /// refresh, a change the platform announced, or an activation that opened
    /// a device the list had not met. Without one of those its list is empty,
    /// or holds what an earlier failed listing left. Every read the
    /// application makes goes through here, so the first is complete without
    /// a [`Engine::refresh`].
    ///
    /// # Errors
    /// [`BackendError::TimedOut`] when the platform did not answer in
    /// [`Config::probe_wait`]; the next read asks again.
    pub fn listing(&mut self) -> Result<&[DeviceInfo], BackendError> {
        if self.listed {
            return Ok(&self.devices);
        }
        self.refresh()
    }

    fn absorb(&mut self, found: Vec<crate::backend::RawDevice>) {
        for device in &mut self.devices {
            device.present = false;
            device.default_input = false;
            device.default_output = false;
        }
        for raw in found {
            if let Some(known) = self
                .devices
                .iter_mut()
                .find(|device| device.identity == raw.identity)
            {
                known.name = raw.name;
                known.input_channels = raw.input_channels;
                known.output_channels = raw.output_channels;
                known.default_input = raw.default_input;
                known.default_output = raw.default_output;
                known.present = true;
                continue;
            }
            let Some(handle) = DeviceHandle::new(self.next_handle) else {
                continue;
            };
            self.next_handle = self.next_handle.saturating_add(1);
            self.devices.push(DeviceInfo {
                handle,
                identity: raw.identity,
                name: raw.name,
                input_channels: raw.input_channels,
                output_channels: raw.output_channels,
                default_input: raw.default_input,
                default_output: raw.default_output,
                present: true,
            });
        }
    }

    /// Every device this engine has ever listed, present or not.
    #[must_use]
    pub fn devices(&self) -> &[DeviceInfo] {
        &self.devices
    }

    /// One device, by handle.
    #[must_use]
    pub fn device(&self, handle: DeviceHandle) -> Option<&DeviceInfo> {
        self.devices.iter().find(|device| device.handle == handle)
    }

    fn handle_of(&self, identity: &str) -> Option<DeviceHandle> {
        self.devices
            .iter()
            .find(|device| device.identity == identity)
            .map(|device| device.handle)
    }

    // -- selection ----------------------------------------------------------

    /// Put a role on a device, or back on the system's route.
    ///
    /// Refused before any platform call is made, for a handle this engine
    /// never listed, a device with no channels in that direction, or one
    /// that is not plugged in; a selection that is refused changes nothing.
    /// While the engine is active the role is reopened at once, and the
    /// gain and the mute of that direction carry over.
    ///
    /// # Errors
    /// [`SelectError`] says which.
    pub fn select(&mut self, role: Role, selection: Selection) -> Result<(), SelectError> {
        if let Selection::Device(handle) = selection {
            let device = self.device(handle).ok_or(SelectError::NoSuchDevice)?;
            if !device.serves(role) {
                return Err(SelectError::NoChannels);
            }
            if !device.present {
                return Err(SelectError::Absent);
            }
            if !*self.chooses.get(role) {
                return Err(SelectError::NotSupported);
            }
        }
        if *self.selection.get(role) == selection {
            return Ok(());
        }
        *self.selection.get_mut(role) = selection;
        if self.is_active() {
            self.reopen(role, Origin::Engine, Change::Selected(role));
        } else {
            self.events.push_back(AudioEvent {
                change: Change::Selected(role),
                origin: Origin::Engine,
                device: match selection {
                    Selection::System => None,
                    Selection::Device(handle) => Some(handle),
                },
            });
        }
        Ok(())
    }

    /// What a role was asked to be on.
    #[must_use]
    pub fn selection(&self, role: Role) -> Selection {
        *self.selection.get(role)
    }

    /// The device a role is running on right now, when it is running and the
    /// device is one the list knows.
    #[must_use]
    pub fn running_on(&self, role: Role) -> Option<DeviceHandle> {
        self.running
            .get(role)
            .as_ref()
            .and_then(|running| self.handle_of(&running.identity))
    }

    // -- gain, mute, level --------------------------------------------------

    /// Set the gain of one direction, kept across every device change.
    pub fn set_gain(&mut self, direction: Direction, gain: Gain) {
        self.settings.get_mut(direction).gain = gain;
        self.apply_settings(direction);
    }

    /// The gain of one direction.
    #[must_use]
    pub fn gain(&self, direction: Direction) -> Gain {
        self.settings.get(direction).gain
    }

    /// Mute or unmute one direction, kept across every device change.
    pub fn set_muted(&mut self, direction: Direction, muted: bool) {
        self.settings.get_mut(direction).muted = muted;
        self.apply_settings(direction);
    }

    /// Whether one direction is muted.
    #[must_use]
    pub fn is_muted(&self, direction: Direction) -> bool {
        self.settings.get(direction).muted
    }

    /// The meter of one direction: the loudest sample of the last tenth of
    /// a second, silent when nothing is open.
    #[must_use]
    pub fn level(&self, direction: Direction) -> Level {
        let role = match direction {
            Direction::Input => Role::Microphone,
            Direction::Output => Role::Speaker,
        };
        self.running
            .get(role)
            .as_ref()
            .map_or(Level::SILENT, |running| running.controls.level())
    }

    fn apply_settings(&self, direction: Direction) {
        let setting = *self.settings.get(direction);
        for role in Role::ALL {
            if role.direction() != direction {
                continue;
            }
            if let Some(running) = self.running.get(role).as_ref() {
                running.controls.set_gain(setting.gain);
                running.controls.set_muted(setting.muted);
            }
        }
    }

    // -- calls --------------------------------------------------------------

    /// Carry this call's audio: its playback to the loudspeaker, the
    /// microphone into it. Under [`Activation::Automatic`] the first one
    /// opens the devices; under [`Activation::Manual`] a call attached
    /// before [`Engine::activate`] is carried from the activation on.
    ///
    /// # Errors
    /// What opening the devices said, under automatic activation; the call
    /// is attached all the same and gets audio when a device arrives.
    pub fn attach(&mut self, id: CallId, audio: Box<dyn CallAudio>) -> Result<(), BackendError> {
        if !self.attached.contains(&id) {
            self.attached.push(id);
        }
        self.parked.retain(|(parked, _)| *parked != id);
        let opened = if self.config.activation == Activation::Automatic && !self.is_active() {
            self.start()
        } else {
            Ok(())
        };
        match self.pump.as_ref() {
            Some(pump) => {
                let _ = pump.sender.send(Command::Attach(id, audio));
            }
            None => self.parked.push((id, audio)),
        }
        opened
    }

    /// Stop carrying it. Under [`Activation::Automatic`] the last one closes
    /// the devices, unless a ring is playing.
    pub fn detach(&mut self, id: CallId) {
        self.attached.retain(|attached| *attached != id);
        self.parked.retain(|(parked, _)| *parked != id);
        if let Some(pump) = self.pump.as_ref() {
            let _ = pump.sender.send(Command::Detach(id));
        }
        self.settle();
    }

    /// The calls being carried.
    #[must_use]
    pub fn attached(&self) -> &[CallId] {
        &self.attached
    }

    fn settle(&mut self) {
        if self.config.activation == Activation::Automatic
            && self.attached.is_empty()
            && !self.ringing
        {
            self.stop();
        }
    }

    // -- the ring -----------------------------------------------------------

    /// Play `tone` to the ringer, looped or once, until [`Engine::stop_ringing`].
    ///
    /// # Errors
    /// What opening the devices said, under automatic activation.
    pub fn ring(
        &mut self,
        tone: Vec<i16>,
        sample_rate_hz: u32,
        looped: bool,
    ) -> Result<(), BackendError> {
        self.ringing = true;
        let opened = if self.config.activation == Activation::Automatic && !self.is_active() {
            self.start()
        } else {
            Ok(())
        };
        if let Some(pump) = self.pump.as_ref() {
            let _ = pump.sender.send(Command::Ring(Ring {
                tone: Arc::new(tone),
                sample_rate_hz,
                looped,
            }));
        }
        opened
    }

    /// Stop the ring.
    pub fn stop_ringing(&mut self) {
        self.ringing = false;
        if let Some(pump) = self.pump.as_ref() {
            let _ = pump.sender.send(Command::StopRing);
        }
        self.settle();
    }

    /// Whether a ring is playing.
    #[must_use]
    pub const fn is_ringing(&self) -> bool {
        self.ringing
    }

    // -- activation ---------------------------------------------------------

    /// Open the devices and start the pump, whatever the calls are doing.
    ///
    /// # Errors
    /// What the platform said about the microphone or the loudspeaker; the
    /// engine is active all the same, with silence in whichever direction
    /// has no device, and a refresh or a device arriving fills it in.
    pub fn activate(&mut self) -> Result<(), BackendError> {
        if self.is_active() {
            return Ok(());
        }
        self.start()
    }

    /// Close the devices and stop the pump. Calls stay attached and get
    /// their audio back on the next activation.
    pub fn deactivate(&mut self) {
        self.stop();
    }

    /// Whether the devices are open.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.pump.is_some()
    }

    fn start(&mut self) -> Result<(), BackendError> {
        let Some(transmit) = self.transmit.take() else {
            return Ok(());
        };
        let (sender, receiver) = mpsc::channel();
        let report = Arc::new(Report::default());
        let pump = Pump::new(
            receiver,
            Arc::clone(&report),
            transmit,
            Arc::clone(&self.now),
            self.config.device_rate_hz,
        );
        let thread = std::thread::Builder::new()
            .name("sipral-audio".to_owned())
            .spawn(move || pump.run())
            .map_err(|_| BackendError::Refused("the pump's thread could not start".to_owned()))?;
        self.pump = Some(PumpHandle {
            sender,
            thread: Some(thread),
            report,
        });
        let (microphone, speaker) = self.open_pair();
        let microphone = self.install(
            Role::Microphone,
            microphone,
            Origin::Engine,
            Change::Reopened(Role::Microphone),
        );
        let speaker = self.install(
            Role::Speaker,
            speaker,
            Origin::Engine,
            Change::Reopened(Role::Speaker),
        );
        if self.wants_own_ringer() {
            let ringer = self.open_one(Role::Ringer);
            let _ = self.install(
                Role::Ringer,
                ringer,
                Origin::Engine,
                Change::Reopened(Role::Ringer),
            );
        }
        if let Some(pump) = self.pump.as_ref() {
            for (id, audio) in self.parked.drain(..) {
                let _ = pump.sender.send(Command::Attach(id, audio));
            }
        }
        microphone.and(speaker)
    }

    fn stop(&mut self) {
        let Some(mut pump) = self.pump.take() else {
            return;
        };
        let _ = pump.sender.send(Command::Quit);
        if let Some(thread) = pump.thread.take()
            && let Ok((transmit, carried)) = thread.join()
        {
            self.transmit = Some(transmit);
            self.parked = carried;
        }
        self.running = PerRole::default();
    }

    /// Whether the ringer runs on a stream of its own: only when it was put
    /// on a device other than the loudspeaker's, and only where a second
    /// output can be opened beside the first.
    fn wants_own_ringer(&self) -> bool {
        *self.chooses.get(Role::Ringer)
            && self.selection(Role::Ringer) != Selection::System
            && self.selection(Role::Ringer) != self.selection(Role::Speaker)
    }

    // -- opening ------------------------------------------------------------

    fn identity_for(&self, role: Role) -> Option<String> {
        match self.selection(role) {
            Selection::System => None,
            Selection::Device(handle) => self
                .device(handle)
                .filter(|device| device.present)
                .map(|device| device.identity.clone()),
        }
    }

    fn open_pair(&mut self) -> Duplex {
        let microphone = self.identity_for(Role::Microphone);
        let speaker = self.identity_for(Role::Speaker);
        let wanted = Format::twenty_ms(self.config.device_rate_hz);
        let backend = Arc::clone(&self.backend);
        let opened = probe(self.config.probe_wait, move || {
            let mut backend = match backend.try_lock() {
                Ok(backend) => backend,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => return Err(BackendError::TimedOut),
            };
            // both devices at once: a duplex platform opens its one unit
            // with each half on its own device and answers with the two
            Ok(backend.open_duplex(microphone.as_deref(), speaker.as_deref(), wanted))
        });
        match opened {
            Ok(pair) => pair,
            Err(error) => (Err(error.clone()), Err(error)),
        }
    }

    fn open_one(&mut self, role: Role) -> Result<Box<dyn PlaybackStream>, BackendError> {
        let identity = self.identity_for(role);
        let wanted = Format::twenty_ms(self.config.device_rate_hz);
        let backend = Arc::clone(&self.backend);
        probe(self.config.probe_wait, move || {
            let mut backend = match backend.try_lock() {
                Ok(backend) => backend,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => return Err(BackendError::TimedOut),
            };
            if role == Role::Ringer {
                backend.open_ringer(identity.as_deref(), wanted)
            } else {
                backend.open_playback(identity.as_deref(), wanted)
            }
        })
    }

    fn open_capture_one(&mut self, role: Role) -> Result<Box<dyn CaptureStream>, BackendError> {
        let identity = self.identity_for(role);
        let wanted = Format::twenty_ms(self.config.device_rate_hz);
        let backend = Arc::clone(&self.backend);
        probe(self.config.probe_wait, move || {
            let mut backend = match backend.try_lock() {
                Ok(backend) => backend,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => return Err(BackendError::TimedOut),
            };
            backend.open_capture(identity.as_deref(), wanted)
        })
    }

    /// Hand an opened stream to the pump, note where it landed and apply the
    /// direction's gain and mute to it; or note that the role has nothing.
    fn install<S>(
        &mut self,
        role: Role,
        opened: Result<S, BackendError>,
        origin: Origin,
        change: Change,
    ) -> Result<(), BackendError>
    where
        S: Into<Opened>,
    {
        let setting = *self.settings.get(role.direction());
        match opened {
            Ok(stream) => {
                let opened: Opened = stream.into();
                let running = Running {
                    identity: opened.identity().to_owned(),
                    controls: opened.controls(),
                    latency: opened.latency(),
                    system_echo_cancellation: opened.system_echo_cancellation(),
                    format: opened.format(),
                };
                running.controls.set_gain(setting.gain);
                running.controls.set_muted(setting.muted);
                if self.handle_of(&running.identity).is_none() {
                    // a device the list has not met yet: the system's
                    // default, opened before the first refresh
                    let _ = self.refresh();
                }
                let device = self.handle_of(&running.identity);
                *self.running.get_mut(role) = Some(running);
                if let Some(pump) = self.pump.as_ref() {
                    let _ = pump
                        .sender
                        .send(Command::Replace(role, Some(opened.into_stream())));
                }
                self.events.push_back(AudioEvent {
                    change,
                    origin,
                    device,
                });
                Ok(())
            }
            Err(error) => {
                *self.running.get_mut(role) = None;
                if let Some(pump) = self.pump.as_ref() {
                    let _ = pump.sender.send(Command::Replace(role, None));
                }
                self.events.push_back(AudioEvent {
                    change: Change::Unavailable(role),
                    origin,
                    device: None,
                });
                Err(error)
            }
        }
    }

    /// Open a role again on whatever its selection resolves to now.
    fn reopen(&mut self, role: Role, origin: Origin, change: Change) {
        if !self.is_active() {
            return;
        }
        if self.duplex_only && matches!(role, Role::Microphone | Role::Speaker) {
            // the one unit has to be closed before another is opened: two
            // voice-processing units alive at once is what blocks inside
            // the framework, so the pump drops the old halves first
            if let Some(pump) = self.pump.as_ref() {
                let _ = pump.sender.send(Command::Replace(Role::Microphone, None));
                let _ = pump.sender.send(Command::Replace(Role::Speaker, None));
                pump.settle();
            }
            *self.running.get_mut(Role::Microphone) = None;
            *self.running.get_mut(Role::Speaker) = None;
            let (microphone, speaker) = self.open_pair();
            let _ = self.install(
                Role::Microphone,
                microphone,
                origin,
                Change::Reopened(Role::Microphone),
            );
            let _ = self.install(Role::Speaker, speaker, origin, change);
            if role == Role::Speaker {
                // a ringer on its own device may now be on the loudspeaker's,
                // or the other way round
                self.settle_ringer(origin);
            }
            return;
        }
        match role {
            Role::Microphone => {
                let opened = self.open_capture_one(role);
                let _ = self.install(role, opened, origin, change);
            }
            Role::Speaker => {
                let opened = self.open_one(role);
                let _ = self.install(role, opened, origin, change);
                // a ringer that shares the loudspeaker's device is the
                // loudspeaker's stream; one that no longer does needs its own
                self.settle_ringer(origin);
            }
            Role::Ringer => self.settle_ringer(origin),
        }
    }

    fn settle_ringer(&mut self, origin: Origin) {
        if self.wants_own_ringer() {
            let opened = self.open_one(Role::Ringer);
            let _ = self.install(Role::Ringer, opened, origin, Change::Reopened(Role::Ringer));
        } else {
            *self.running.get_mut(Role::Ringer) = None;
            if let Some(pump) = self.pump.as_ref() {
                let _ = pump.sender.send(Command::Replace(Role::Ringer, None));
            }
        }
    }

    /// A role whose chosen device is present again and is not what it is
    /// running on goes back to it.
    fn follow_preferences(&mut self) {
        if !self.is_active() {
            return;
        }
        for role in Role::ALL {
            let Selection::Device(handle) = self.selection(role) else {
                continue;
            };
            let Some(wanted) = self.device(handle).filter(|device| device.present) else {
                continue;
            };
            let on = self
                .running
                .get(role)
                .as_ref()
                .map(|running| running.identity.clone());
            if on.as_deref() != Some(wanted.identity.as_str()) {
                self.reopen(role, Origin::Engine, Change::Reopened(role));
            }
        }
    }

    // -- servicing ----------------------------------------------------------

    /// Take in what the platform and the pump reported since last time, and
    /// act on it: a device gone is reopened on the fallback, a default that
    /// moved is followed by a role that follows it, a list that changed is
    /// refreshed. Called from the application's own loop, a few times a
    /// second; every consequence comes out of [`Engine::poll_event`].
    pub fn service(&mut self) {
        let notices = match self.backend.try_lock() {
            Ok(mut backend) => drain_notices(&mut **backend),
            Err(TryLockError::Poisoned(poisoned)) => drain_notices(&mut **poisoned.into_inner()),
            // a probe the engine walked away from is still inside the
            // platform: what it announced waits for a later service, and
            // the application's loop does not wait on the driver
            Err(TryLockError::WouldBlock) => Vec::new(),
        };
        for notice in notices {
            match notice {
                Notice::ListChanged => {
                    let _ = self.refresh();
                    self.events.push_back(AudioEvent {
                        change: Change::ListChanged,
                        origin: Origin::System,
                        device: None,
                    });
                }
                Notice::DefaultChanged(direction) => {
                    let _ = self.refresh();
                    self.events.push_back(AudioEvent {
                        change: Change::DefaultChanged(direction),
                        origin: Origin::System,
                        device: None,
                    });
                    // only a role that follows the system moves with it: one
                    // the application put somewhere stays there, which is
                    // what keeps the application's own choice from being
                    // re-applied in a loop
                    for role in Role::ALL {
                        if role.direction() == direction
                            && self.selection(role) == Selection::System
                            && self.running.get(role).is_some()
                        {
                            self.reopen(role, Origin::System, Change::Reopened(role));
                        }
                    }
                }
            }
        }
        let Some(pump) = self.pump.as_ref() else {
            return;
        };
        let report = Arc::clone(&pump.report);
        for id in report.take_ended() {
            self.attached.retain(|attached| *attached != id);
            self.parked.retain(|(parked, _)| *parked != id);
        }
        if report.take_ring_done() {
            self.ringing = false;
        }
        for role in Role::ALL {
            if report.take_lost(role) {
                let device = self.running_on(role);
                *self.running.get_mut(role) = None;
                self.events.push_back(AudioEvent {
                    change: Change::Lost(role),
                    origin: Origin::System,
                    device,
                });
                let _ = self.refresh();
                self.reopen(role, Origin::Engine, Change::Reopened(role));
            }
        }
        self.settle();
    }

    /// The next thing the engine has to say.
    pub fn poll_event(&mut self) -> Option<AudioEvent> {
        self.events.pop_front()
    }

    /// What the engine is doing.
    #[must_use]
    pub fn info(&self) -> Info {
        let microphone = self.running.get(Role::Microphone).as_ref();
        let speaker = self.running.get(Role::Speaker).as_ref();
        Info {
            active: self.is_active(),
            system_echo_cancellation: microphone
                .is_some_and(|running| running.system_echo_cancellation),
            render_delay: microphone.map_or(Duration::ZERO, |running| running.latency)
                + speaker.map_or(Duration::ZERO, |running| running.latency),
            microphone_rate_hz: microphone.map(|running| running.format.sample_rate_hz),
            speaker_rate_hz: speaker.map(|running| running.format.sample_rate_hz),
        }
    }

    /// How many ticks the pump has run, for a test that waits on it.
    #[must_use]
    pub fn ticks(&self) -> u64 {
        self.pump.as_ref().map_or(0, |pump| pump.report.ticks())
    }
}

/// Everything a platform announced since it was last asked.
fn drain_notices(backend: &mut dyn Backend) -> Vec<Notice> {
    let mut notices = Vec::new();
    while let Some(notice) = backend.poll_notice() {
        notices.push(notice);
    }
    notices
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A stream of either direction, just opened, before the pump has it.
pub(crate) enum Opened {
    Capture(Box<dyn CaptureStream>),
    Playback(Box<dyn PlaybackStream>),
}

impl Opened {
    fn identity(&self) -> &str {
        match self {
            Self::Capture(stream) => stream.identity(),
            Self::Playback(stream) => stream.identity(),
        }
    }

    fn controls(&self) -> Controls {
        match self {
            Self::Capture(stream) => stream.controls(),
            Self::Playback(stream) => stream.controls(),
        }
    }

    fn latency(&self) -> Duration {
        match self {
            Self::Capture(stream) => stream.latency(),
            Self::Playback(stream) => stream.latency(),
        }
    }

    fn format(&self) -> Format {
        match self {
            Self::Capture(stream) => stream.format(),
            Self::Playback(stream) => stream.format(),
        }
    }

    fn system_echo_cancellation(&self) -> bool {
        match self {
            Self::Capture(stream) => stream.system_echo_cancellation(),
            Self::Playback(_) => false,
        }
    }

    fn into_stream(self) -> Stream {
        match self {
            Self::Capture(stream) => Stream::Capture(stream),
            Self::Playback(stream) => Stream::Playback(stream),
        }
    }
}

impl From<Box<dyn CaptureStream>> for Opened {
    fn from(stream: Box<dyn CaptureStream>) -> Self {
        Self::Capture(stream)
    }
}

impl From<Box<dyn PlaybackStream>> for Opened {
    fn from(stream: Box<dyn PlaybackStream>) -> Self {
        Self::Playback(stream)
    }
}
