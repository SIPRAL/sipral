// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The engine: the devices named, chosen, opened and kept open.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use sipral_io_common::level::{Channel, Controls, Gain, Level};

use crate::backend::{
    Backend, BackendError, CaptureStream, Duplex, Format, Notice, PlaybackStream, Promote,
    RawDevice, Scheduling,
};
use crate::call::{CallAudio, CallId, Outgoing};
use crate::device::{
    AudioEvent, Change, DeviceHandle, DeviceInfo, Direction, Origin, Role, SelectError, Selection,
};
use crate::probe::{DEFAULT_PROBE_WAIT, probe};
use crate::pump::{CallChannels, Carried, Command, Done, Finished, Pump, Report, Ring, Stream};

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
    /// Whether the platform's own echo cancellation runs behind the
    /// microphone, where the platform lets it be turned off: on by default.
    /// Off, the devices open without it — the voice-processing unit
    /// bypassed on macOS and iOS, a raw stream rather than a communications
    /// one on Windows, the plain recognition preset rather than the
    /// voice-communication one on Android — for a headset, which has no
    /// echo to cancel and whose speech the processing only colours, or for
    /// an application that runs a canceller of its own on each call.
    /// [`Info::system_echo_cancellation`] says what the platform did.
    pub system_echo_cancellation: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            activation: Activation::Automatic,
            probe_wait: DEFAULT_PROBE_WAIT,
            device_rate_hz: 48_000,
            system_echo_cancellation: true,
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
    /// What the pump hands back when it finishes, before its devices go.
    finished: Receiver<Finished>,
    /// Set once the pump has let go of its devices.
    closed: Arc<Done>,
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
    /// Each call's own gain, mute and meter, from its first attach until
    /// [`Engine::forget_call`].
    call_channels: HashMap<CallId, CallChannels>,
    ringing: bool,
    events: VecDeque<AudioEvent>,
    /// How the pump's thread asks for the scheduling class audio runs in.
    promote: Option<Promote>,
    /// Devices being let go of on a thread of their own — a finished
    /// pump's, or ones an open in the background brought back for a pump
    /// that had already stopped — which every open waits for, a bounded
    /// time, before it asks the platform for the next.
    closing: Vec<Arc<Done>>,
    /// Which pump is running, counted, so that devices opened in the
    /// background for one that has since stopped are not handed to the next.
    generation: u64,
    /// The open running in the background, for a caller that does not wait
    /// for it.
    opening: Option<Opening>,
    /// What is to be opened in the background once that one has landed.
    wanted: Vec<Want>,
}

/// One role to open in the background, and what to say when it lands.
#[derive(Clone, Copy, Debug)]
struct Want {
    role: Role,
    origin: Origin,
    change: Change,
}

/// What an open in the background hands back: each role's stream, or why
/// there is none, and the platform's list as it stood just after.
struct Landing {
    streams: Vec<(Role, Result<Opened, BackendError>)>,
    devices: Option<Vec<RawDevice>>,
}

/// An open running in the background.
struct Opening {
    /// The pump it was asked for.
    generation: u64,
    wants: Vec<Want>,
    answer: Receiver<Landing>,
    since: Instant,
    /// Whether its roles have already been reported unavailable for taking
    /// longer than the probe wait.
    overdue: bool,
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

impl Engine {
    /// An engine over `backend`.
    ///
    /// `transmit` is handed every packet the pump produces, on the pump's
    /// thread: send it and return. `now` is the clock the calls are driven
    /// on, so that what the pump tells a call about time agrees with what
    /// the stack polling it says.
    pub fn new(
        mut backend: Box<dyn Backend>,
        config: Config,
        transmit: Box<dyn FnMut(CallId, Outgoing) + Send>,
        now: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        backend.set_system_echo_cancellation(config.system_echo_cancellation);
        let duplex_only = backend.duplex_only();
        let promote = backend.pump_scheduling();
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
            call_channels: HashMap::new(),
            ringing: false,
            events: VecDeque::new(),
            promote,
            closing: Vec::new(),
            generation: 0,
            opening: None,
            wanted: Vec::new(),
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
        // an open still running in the background has the platform: what it
        // brings back is put to work first, rather than this listing being
        // refused as a stuck driver
        self.finish_opening();
        self.refresh_now(false)
    }

    /// The listing itself; a role whose chosen device is back is reopened
    /// in the background when `later`, as the stack's own servicing wants,
    /// and at once otherwise.
    fn refresh_now(&mut self, later: bool) -> Result<&[DeviceInfo], BackendError> {
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
        self.follow_preferences(later);
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
            self.finish_opening();
            self.reopen(role, Origin::Engine, Change::Selected(role), false);
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
    /// Nothing here waits on a device. The stack attaches a call from the
    /// poll that saw its media start, and opening a headset has been seen to
    /// take a second and a half: a poll held that long stalls every other
    /// call's signalling, and the far end's packets pile up behind it and
    /// reach the call in one burst. So the pump starts at once and carries
    /// the call on no device — silence to the far end, and the far end's
    /// audio pulled at its own pace and let go of, each frame counted
    /// ([`Engine::frames_without_device`]) — while the devices are opened on
    /// a thread of their own, and put under the call by the next
    /// [`Engine::service`] after they answer, with a `Reopened` event for
    /// each role, or `Unavailable` for one the platform refused or did not
    /// answer for within [`Config::probe_wait`].
    ///
    /// # Errors
    /// [`BackendError::Refused`] when the pump's thread could not start; the
    /// call is attached all the same and is carried once a pump runs.
    pub fn attach(&mut self, id: CallId, audio: Box<dyn CallAudio>) -> Result<(), BackendError> {
        if !self.attached.contains(&id) {
            self.attached.push(id);
        }
        self.parked.retain(|(parked, _)| *parked != id);
        let opened = if self.config.activation == Activation::Automatic && !self.is_active() {
            self.start_later()
        } else {
            Ok(())
        };
        let channels = self.channels_of(id);
        match self.pump.as_ref() {
            Some(pump) => {
                let _ = pump.sender.send(Command::Attach(id, audio, channels));
            }
            None => self.parked.push((id, audio)),
        }
        opened
    }

    /// A call's own controls, made at its first attach.
    fn channels_of(&mut self, id: CallId) -> CallChannels {
        let rate = self.config.device_rate_hz;
        self.call_channels
            .entry(id)
            .or_insert_with(|| CallChannels::new(rate))
            .clone()
    }

    /// Forget a call's own controls, once its media has ended for good. A
    /// detach keeps them, so that a call moved out of the mix and back —
    /// into a conference, say — keeps its gain and its mute.
    pub fn forget_call(&mut self, id: CallId) {
        self.call_channels.remove(&id);
    }

    /// One direction of one call's own controls: `Input` is what the
    /// microphone sends it, `Output` what it plays into the loudspeaker.
    fn call_channel(&self, id: CallId, direction: Direction) -> Option<&Channel> {
        self.call_channels.get(&id).map(|channels| match direction {
            Direction::Input => &*channels.up,
            Direction::Output => &*channels.down,
        })
    }

    /// Set one call's own gain in one direction, on top of the stack's, from
    /// the next frame on: what the microphone sends that call alone, or how
    /// loud that call is in the loudspeaker beside the others. `false` for a
    /// call this engine has never carried, or has forgotten.
    #[must_use]
    pub fn set_call_gain(&self, id: CallId, direction: Direction, gain: Gain) -> bool {
        self.call_channel(id, direction)
            .map(|channel| channel.set_gain(gain))
            .is_some()
    }

    /// One call's own gain in one direction.
    #[must_use]
    pub fn call_gain(&self, id: CallId, direction: Direction) -> Option<Gain> {
        self.call_channel(id, direction).map(Channel::gain)
    }

    /// Mute or unmute one call in one direction: the far end of that call
    /// alone hears silence, or that call alone is silent in the
    /// loudspeaker, while every other call goes on. The muted direction
    /// still runs, so the far end hears a stream rather than a gap.
    #[must_use]
    pub fn set_call_muted(&self, id: CallId, direction: Direction, muted: bool) -> bool {
        self.call_channel(id, direction)
            .map(|channel| channel.set_muted(muted))
            .is_some()
    }

    /// Whether one call is muted in one direction.
    #[must_use]
    pub fn call_muted(&self, id: CallId, direction: Direction) -> Option<bool> {
        self.call_channel(id, direction).map(Channel::is_muted)
    }

    /// One call's meter in one direction: the loudest sample of the last
    /// tenth of a second of what went to it, or of what it played, after its
    /// own gain and mute.
    #[must_use]
    pub fn call_level(&self, id: CallId, direction: Direction) -> Option<Level> {
        self.call_channel(id, direction).map(Channel::level)
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
            // reached from the stack's own poll, through a call's media
            // ending: the devices go on the pump's thread and nothing here
            // waits for them
            self.stop(None);
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
    ///
    /// The devices are let go of on the pump's thread, and this waits for
    /// that at most [`Config::probe_wait`]: a teardown that waits on the
    /// thread this was called from — the voice unit's, on macOS, has been
    /// seen to wait for the main thread — finishes after this returns
    /// rather than never.
    pub fn deactivate(&mut self) {
        self.finish_opening();
        self.stop(Some(self.config.probe_wait));
    }

    /// Whether the devices are open.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.pump.is_some()
    }

    /// Whether devices are still being let go of, on a thread of their own,
    /// after the pump that ran them stopped or an open nobody wanted any
    /// more answered.
    #[must_use]
    pub fn is_closing(&mut self) -> bool {
        self.closing.retain(|closed| !closed.is_set());
        !self.closing.is_empty()
    }

    /// Start the pump on no device at all.
    fn spawn_pump(&mut self) -> Result<bool, BackendError> {
        let Some(transmit) = self.transmit.take() else {
            return Ok(false);
        };
        let (sender, receiver) = mpsc::channel();
        let (handback, finished) = mpsc::channel();
        let report = Arc::new(Report::default());
        let closed = Arc::new(Done::default());
        let pump = Pump::new(
            receiver,
            Arc::clone(&report),
            transmit,
            Arc::clone(&self.now),
            self.config.device_rate_hz,
            self.promote.clone(),
        );
        let done = Arc::clone(&closed);
        std::thread::Builder::new()
            .name("sipral-audio".to_owned())
            .spawn(move || pump.run(&handback, &done))
            .map_err(|_| BackendError::Refused("the pump's thread could not start".to_owned()))?;
        self.generation = self.generation.wrapping_add(1);
        self.pump = Some(PumpHandle {
            sender,
            finished,
            closed,
            report,
        });
        Ok(true)
    }

    /// Hand every parked call to the pump just started.
    fn unpark(&mut self) {
        let parked: Vec<_> = self.parked.drain(..).collect();
        for (id, audio) in parked {
            let channels = self.channels_of(id);
            if let Some(pump) = self.pump.as_ref() {
                let _ = pump.sender.send(Command::Attach(id, audio, channels));
            }
        }
    }

    /// Start the pump and open the devices under it, waiting for them.
    fn start(&mut self) -> Result<(), BackendError> {
        self.finish_opening();
        if !self.spawn_pump()? {
            return Ok(());
        }
        let (microphone, speaker) = self.open_pair();
        let microphone = self.install(
            Role::Microphone,
            microphone.map(Opened::from),
            Origin::Engine,
            Change::Reopened(Role::Microphone),
            false,
        );
        let speaker = self.install(
            Role::Speaker,
            speaker.map(Opened::from),
            Origin::Engine,
            Change::Reopened(Role::Speaker),
            false,
        );
        if self.wants_own_ringer() {
            let ringer = self.open_one(Role::Ringer).map(Opened::from);
            let _ = self.install(
                Role::Ringer,
                ringer,
                Origin::Engine,
                Change::Reopened(Role::Ringer),
                false,
            );
        }
        self.unpark();
        microphone.and(speaker)
    }

    /// Start the pump now, and open the devices under it in the background.
    fn start_later(&mut self) -> Result<(), BackendError> {
        if !self.spawn_pump()? {
            return Ok(());
        }
        let mut wants = vec![
            Want {
                role: Role::Microphone,
                origin: Origin::Engine,
                change: Change::Reopened(Role::Microphone),
            },
            Want {
                role: Role::Speaker,
                origin: Origin::Engine,
                change: Change::Reopened(Role::Speaker),
            },
        ];
        if self.wants_own_ringer() {
            wants.push(Want {
                role: Role::Ringer,
                origin: Origin::Engine,
                change: Change::Reopened(Role::Ringer),
            });
        }
        self.unpark();
        self.want(wants);
        Ok(())
    }

    /// Stop the pump, take back what the next one needs, and leave its
    /// devices to be let go of on its own thread: waiting for that at most
    /// `wait`, and not at all for `None`.
    fn stop(&mut self, wait: Option<Duration>) {
        let Some(pump) = self.pump.take() else {
            return;
        };
        let _ = pump.sender.send(Command::Quit);
        // the pump answers as soon as the tick it is in is over: what it
        // hands back comes before its devices go
        if let Ok((transmit, carried)) = pump.finished.recv() {
            self.transmit = Some(transmit);
            self.parked = carried;
        }
        self.running = PerRole::default();
        // an open still under way was for this pump: what it brings back
        // goes on its own thread, and what was still to be opened is not
        if let Some(opening) = self.opening.take() {
            drop(opening.answer);
        }
        self.wanted.clear();
        if let Some(within) = wait {
            pump.closed.wait(within);
        }
        self.closing.retain(|closed| !closed.is_set());
        self.closing.push(pump.closed);
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

    /// Wait, at most [`Config::probe_wait`] in all, for devices still being
    /// let go of on a thread of their own: a platform with room for one
    /// voice unit has none for the next until the last one is gone.
    fn wait_closed(&mut self) {
        let deadline = Instant::now() + self.config.probe_wait;
        for closed in &self.closing {
            closed.wait(deadline.saturating_duration_since(Instant::now()));
        }
        self.closing.retain(|closed| !closed.is_set());
    }

    fn open_pair(&mut self) -> Duplex {
        self.wait_closed();
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
        self.wait_closed();
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
        self.wait_closed();
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

    // -- opening in the background -------------------------------------------

    /// Ask for roles to be opened in the background: at once when nothing
    /// else is being opened, and once that has landed otherwise, so that two
    /// opens never race for the platform's one voice unit.
    fn want(&mut self, wants: Vec<Want>) {
        for want in wants {
            self.wanted.retain(|queued| queued.role != want.role);
            self.wanted.push(want);
        }
        if self.opening.is_none() {
            self.submit();
        }
    }

    /// Open what is wanted on a thread of its own.
    fn submit(&mut self) {
        if !self.is_active() {
            self.wanted.clear();
        }
        if self.wanted.is_empty() {
            return;
        }
        let mut wants = std::mem::take(&mut self.wanted);
        let wants_role = |wants: &[Want], role: Role| wants.iter().any(|want| want.role == role);
        let duplex = self.duplex_only
            && (wants_role(&wants, Role::Microphone) || wants_role(&wants, Role::Speaker));
        let pair =
            duplex || (wants_role(&wants, Role::Microphone) && wants_role(&wants, Role::Speaker));
        let mut settled = None;
        if duplex {
            // the one unit is reopened whole, and the old one closed first:
            // the pump drops its halves, and it is the open's own thread,
            // not this caller, that waits for the pump to have done so
            let origin = wants.first().map_or(Origin::Engine, |want| want.origin);
            for role in [Role::Microphone, Role::Speaker] {
                if !wants_role(&wants, role) {
                    wants.push(Want {
                        role,
                        origin,
                        change: Change::Reopened(role),
                    });
                }
                *self.running.get_mut(role) = None;
            }
            if let Some(pump) = self.pump.as_ref() {
                let _ = pump.sender.send(Command::Replace(Role::Microphone, None));
                let _ = pump.sender.send(Command::Replace(Role::Speaker, None));
                let (done, answer) = mpsc::channel();
                let _ = pump.sender.send(Command::Settled(done));
                settled = Some(answer);
            }
        }
        let asked: Vec<(Role, Option<String>)> = wants
            .iter()
            .map(|want| (want.role, self.identity_for(want.role)))
            .collect();
        self.closing.retain(|closed| !closed.is_set());
        let closing = self.closing.clone();
        let backend = Arc::clone(&self.backend);
        let format = Format::twenty_ms(self.config.device_rate_hz);
        let wait = self.config.probe_wait;
        let (reply, answer) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("sipral-audio-open".to_owned())
            .spawn(move || {
                let deadline = Instant::now() + wait;
                for closed in &closing {
                    closed.wait(deadline.saturating_duration_since(Instant::now()));
                }
                if let Some(settled) = settled {
                    let _ = settled.recv_timeout(Duration::from_secs(1));
                }
                let landing = open_in_background(&backend, &asked, pair, format);
                // nobody is waiting for it any more: the devices are let go
                // of here, on this thread, rather than on whoever asked
                let _ = reply.send(landing);
            });
        if spawned.is_err() {
            let refused = BackendError::Refused(
                "the thread that opens the devices could not start".to_owned(),
            );
            self.unanswered(&wants, &refused);
            return;
        }
        self.opening = Some(Opening {
            generation: self.generation,
            wants,
            answer,
            since: Instant::now(),
            overdue: false,
        });
    }

    /// Put what an open in the background brought back under the pump it
    /// was asked for, or let it go when that pump has stopped since.
    fn land(&mut self, opening: &Opening, landing: Landing) {
        if opening.generation != self.generation || !self.is_active() {
            self.let_go(landing);
            return;
        }
        if let Some(found) = landing.devices {
            self.absorb(found);
            self.listed = true;
        }
        for (role, opened) in landing.streams {
            let want = opening
                .wants
                .iter()
                .find(|want| want.role == role)
                .copied()
                .unwrap_or(Want {
                    role,
                    origin: Origin::Engine,
                    change: Change::Reopened(role),
                });
            let _ = self.install(role, opened, want.origin, want.change, true);
        }
    }

    /// Let devices nobody wants any more go, on a thread of their own.
    fn let_go(&mut self, landing: Landing) {
        let closed = Arc::new(Done::default());
        let done = Arc::clone(&closed);
        let spawned = std::thread::Builder::new()
            .name("sipral-audio-close".to_owned())
            .spawn(move || {
                drop(landing);
                done.set();
            });
        if spawned.is_ok() {
            self.closing.push(closed);
        }
    }

    /// An open that ended with no answer, or has not answered within the
    /// probe wait: every role it was for is reported unavailable.
    fn unanswered(&mut self, wants: &[Want], error: &BackendError) {
        for want in wants {
            let _ = self.install(
                want.role,
                Err(error.clone()),
                want.origin,
                want.change,
                true,
            );
        }
    }

    /// Land an open in the background that has answered, without waiting
    /// for one that has not.
    fn poll_opening(&mut self) {
        let Some(mut opening) = self.opening.take() else {
            return;
        };
        match opening.answer.try_recv() {
            Ok(landing) => {
                self.land(&opening, landing);
                self.submit();
            }
            Err(TryRecvError::Empty) => {
                if !opening.overdue && opening.since.elapsed() >= self.config.probe_wait {
                    // said once; what it brings back later is still put to
                    // work, with a reopened event of its own
                    opening.overdue = true;
                    self.unanswered(&opening.wants, &BackendError::TimedOut);
                }
                self.opening = Some(opening);
            }
            Err(TryRecvError::Disconnected) => {
                self.unanswered(&opening.wants, &gone_without_answer());
                self.submit();
            }
        }
    }

    /// Wait, at most [`Config::probe_wait`] for each, for the devices being
    /// opened in the background, and put them under the calls; `true` once
    /// nothing is left being opened.
    ///
    /// The stack never calls this: its poll lands an open in
    /// [`Engine::service`] once it has answered. It is for a caller on its
    /// own thread that wants the devices before it goes on, and the engine
    /// calls it itself before anything that asks the platform while it
    /// waits.
    pub fn finish_opening(&mut self) -> bool {
        while let Some(opening) = self.opening.take() {
            match opening.answer.recv_timeout(self.config.probe_wait) {
                Ok(landing) => {
                    self.land(&opening, landing);
                    self.submit();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.opening = Some(opening);
                    return false;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.unanswered(&opening.wants, &gone_without_answer());
                    self.submit();
                }
            }
        }
        true
    }

    /// Whether devices are being opened in the background, which the next
    /// [`Engine::service`] after they answer puts to work: a caller that
    /// services the engine from a loop of its own comes back soon while
    /// this holds.
    #[must_use]
    pub fn is_opening(&self) -> bool {
        self.opening.is_some() || !self.wanted.is_empty()
    }

    /// Hand an opened stream to the pump, note where it landed and apply the
    /// direction's gain and mute to it; or note that the role has nothing.
    ///
    /// A device the list has not met is listed first, unless `later` says
    /// the caller is the stack's own poll, which does not wait on the
    /// platform: an open in the background lists the devices itself.
    fn install(
        &mut self,
        role: Role,
        opened: Result<Opened, BackendError>,
        origin: Origin,
        change: Change,
        later: bool,
    ) -> Result<(), BackendError> {
        let setting = *self.settings.get(role.direction());
        match opened {
            Ok(opened) => {
                let running = Running {
                    identity: opened.identity().to_owned(),
                    controls: opened.controls(),
                    latency: opened.latency(),
                    system_echo_cancellation: opened.system_echo_cancellation(),
                    format: opened.format(),
                };
                running.controls.set_gain(setting.gain);
                running.controls.set_muted(setting.muted);
                if !later && self.handle_of(&running.identity).is_none() {
                    // a device the list has not met yet: the system's
                    // default, opened before the first refresh
                    let _ = self.refresh_now(false);
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

    /// Open a role again on whatever its selection resolves to now: in the
    /// background when `later`, as the stack's own poll wants it, and at
    /// once otherwise.
    fn reopen(&mut self, role: Role, origin: Origin, change: Change, later: bool) {
        if !self.is_active() {
            return;
        }
        if later {
            let mut wants = Vec::new();
            if role != Role::Ringer {
                wants.push(Want {
                    role,
                    origin,
                    change,
                });
            }
            if matches!(role, Role::Speaker | Role::Ringer) {
                // a ringer that shares the loudspeaker's device is the
                // loudspeaker's stream; one that no longer does needs its own
                if self.wants_own_ringer() {
                    wants.push(Want {
                        role: Role::Ringer,
                        origin,
                        change: if role == Role::Ringer {
                            change
                        } else {
                            Change::Reopened(Role::Ringer)
                        },
                    });
                } else {
                    self.drop_ringer();
                }
            }
            self.want(wants);
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
                microphone.map(Opened::from),
                origin,
                Change::Reopened(Role::Microphone),
                false,
            );
            let _ = self.install(
                Role::Speaker,
                speaker.map(Opened::from),
                origin,
                change,
                false,
            );
            if role == Role::Speaker {
                // a ringer on its own device may now be on the loudspeaker's,
                // or the other way round
                self.settle_ringer(origin);
            }
            return;
        }
        match role {
            Role::Microphone => {
                let opened = self.open_capture_one(role).map(Opened::from);
                let _ = self.install(role, opened, origin, change, false);
            }
            Role::Speaker => {
                let opened = self.open_one(role).map(Opened::from);
                let _ = self.install(role, opened, origin, change, false);
                // a ringer that shares the loudspeaker's device is the
                // loudspeaker's stream; one that no longer does needs its own
                self.settle_ringer(origin);
            }
            Role::Ringer => self.settle_ringer(origin),
        }
    }

    fn settle_ringer(&mut self, origin: Origin) {
        if self.wants_own_ringer() {
            let opened = self.open_one(Role::Ringer).map(Opened::from);
            let _ = self.install(
                Role::Ringer,
                opened,
                origin,
                Change::Reopened(Role::Ringer),
                false,
            );
        } else {
            self.drop_ringer();
        }
    }

    /// The ringer back on the loudspeaker's stream.
    fn drop_ringer(&mut self) {
        *self.running.get_mut(Role::Ringer) = None;
        if let Some(pump) = self.pump.as_ref() {
            let _ = pump.sender.send(Command::Replace(Role::Ringer, None));
        }
    }

    /// A role whose chosen device is present again and is not what it is
    /// running on goes back to it, in the background when `later`.
    fn follow_preferences(&mut self, later: bool) {
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
            // a role already being opened in the background lands on what
            // its selection resolved to when it was asked
            let pending = self
                .opening
                .as_ref()
                .is_some_and(|opening| opening.wants.iter().any(|want| want.role == role))
                || self.wanted.iter().any(|want| want.role == role);
            if on.as_deref() != Some(wanted.identity.as_str()) && !(later && pending) {
                self.reopen(role, Origin::Engine, Change::Reopened(role), later);
            }
        }
    }

    // -- servicing ----------------------------------------------------------

    /// Take in what the platform and the pump reported since last time, and
    /// act on it: devices opened in the background are put to work, a
    /// device gone is reopened on the fallback, a default that moved is
    /// followed by a role that follows it, a list that changed is
    /// refreshed. Called from the application's own loop, a few times a
    /// second; every consequence comes out of [`Engine::poll_event`].
    ///
    /// Nothing here waits for a device to open or to close: what has to be
    /// reopened is opened in the background, and put to work by a later
    /// call once it has answered ([`Engine::is_opening`]).
    pub fn service(&mut self) {
        self.poll_opening();
        let notices = match self.backend.try_lock() {
            Ok(mut backend) => drain_notices(&mut **backend),
            Err(TryLockError::Poisoned(poisoned)) => drain_notices(&mut **poisoned.into_inner()),
            // a probe the engine walked away from, or an open in the
            // background, is still inside the platform: what it announced
            // waits for a later service, and the application's loop does
            // not wait on the driver
            Err(TryLockError::WouldBlock) => Vec::new(),
        };
        for notice in notices {
            match notice {
                Notice::ListChanged => {
                    let _ = self.refresh_now(true);
                    self.events.push_back(AudioEvent {
                        change: Change::ListChanged,
                        origin: Origin::System,
                        device: None,
                    });
                }
                Notice::DefaultChanged(direction) => {
                    let _ = self.refresh_now(true);
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
                            self.reopen(role, Origin::System, Change::Reopened(role), true);
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
                let _ = self.refresh_now(true);
                self.reopen(role, Origin::Engine, Change::Reopened(role), true);
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

    /// Frames the running pump has carried with no device under them while
    /// calls were up — a microphone or a loudspeaker still being opened, or
    /// one the platform refused: for `Input`, the silence sent to the far
    /// end in place of the microphone; for `Output`, the far end's audio
    /// pulled at its own pace and let go of. Zero while no pump runs.
    #[must_use]
    pub fn frames_without_device(&self, direction: Direction) -> u64 {
        self.pump.as_ref().map_or(0, |pump| {
            pump.report.stand_in(direction == Direction::Input)
        })
    }

    /// What the running pump's thread got when it asked the platform's
    /// scheduler for the class audio runs in: `None` while no pump runs, or
    /// before it has asked.
    #[must_use]
    pub fn pump_scheduling(&self) -> Option<Scheduling> {
        self.pump.as_ref().and_then(|pump| pump.report.scheduling())
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

/// Open `asked`, on the calling thread, which is an open's own: a probe the
/// engine walked away from that is still inside the platform is waited for
/// here, where nobody else is waiting. The microphone and the loudspeaker
/// together as one `pair` where they are opened as one unit, or both are
/// wanted; each on its own otherwise. The list is taken afterwards, so that
/// whoever puts the streams to work knows the devices they landed on
/// without asking the platform itself.
fn open_in_background(
    backend: &Mutex<Box<dyn Backend>>,
    asked: &[(Role, Option<String>)],
    pair: bool,
    wanted: Format,
) -> Landing {
    let mut backend = backend.lock().unwrap_or_else(PoisonError::into_inner);
    let wants = |role: Role| asked.iter().any(|(asked, _)| *asked == role);
    let identity = |role: Role| {
        asked
            .iter()
            .find(|(asked, _)| *asked == role)
            .and_then(|(_, identity)| identity.as_deref())
    };
    let mut streams = Vec::new();
    if pair {
        let (microphone, speaker) =
            backend.open_duplex(identity(Role::Microphone), identity(Role::Speaker), wanted);
        streams.push((Role::Microphone, microphone.map(Opened::from)));
        streams.push((Role::Speaker, speaker.map(Opened::from)));
    } else {
        if wants(Role::Microphone) {
            let opened = backend.open_capture(identity(Role::Microphone), wanted);
            streams.push((Role::Microphone, opened.map(Opened::from)));
        }
        if wants(Role::Speaker) {
            let opened = backend.open_playback(identity(Role::Speaker), wanted);
            streams.push((Role::Speaker, opened.map(Opened::from)));
        }
    }
    if wants(Role::Ringer) {
        let opened = backend.open_ringer(identity(Role::Ringer), wanted);
        streams.push((Role::Ringer, opened.map(Opened::from)));
    }
    Landing {
        streams,
        devices: backend.devices().ok(),
    }
}

/// What an open in the background that ended without answering is
/// reported as.
fn gone_without_answer() -> BackendError {
    BackendError::Refused("the thread opening the devices ended without an answer".to_owned())
}

impl Drop for Engine {
    fn drop(&mut self) {
        // the stack is going: what is being opened is let go of where it
        // lands, and the devices in use go on the pump's thread, waited for
        // a bounded time rather than for ever
        self.opening = None;
        self.stop(Some(self.config.probe_wait));
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
