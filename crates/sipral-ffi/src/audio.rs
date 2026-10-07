// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The built-in audio engine across the boundary: the library lists, opens
//! and pumps the platform's devices.
//!
//! In application mode (`sipral_stack_config_t::audio` zero) the application
//! pumps frames through `sipral_media_capture` and `sipral_media_playback`. In
//! device mode the library opens the devices, carries every managed call's
//! audio, and hands encoded packets to `audio_transmit_callback` for the
//! application's socket. Received packets still go in through
//! `sipral_media_receive`.
//!
//! These entry points take the engine's lock, not the stack's, so they never
//! answer `SIPRAL_STATUS_BUSY` because signalling is busy. That lock is held
//! for a table lookup or a platform call bounded by `audio_probe_ms`, never
//! for a frame.
//!
//! Engine changes arrive as `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` with an
//! origin, so an application can tell its own change from the system's and
//! does not loop re-applying its choice.

use std::cell::Cell;
use std::ffi::{c_char, c_void};
use std::fmt::Write as _;
use std::slice;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sipral_audio::{
    Activation, AudioEvent, Change, Config, DeviceHandle, Direction, Engine, Gain, Origin,
    Outgoing, Role, SelectError, Selection, Transport,
};

use crate::abi::{Number, alias, codes, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::SipralToggle;
use crate::stack::{SipralStackConfig, SipralTransport, audio_of};
use crate::status::SipralStatus;
use crate::versioned::{Versioned, write_versioned};

codes! {
    /// Who pumps a stack's audio: `sipral_stack_config_t::audio`.
    ///
    /// Zero is application mode, so a configuration written against an
    /// earlier header keeps pumping its own frames.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudio: u32 {
        /// The application opens the devices and pumps frames through
        /// `sipral_media_capture` and `sipral_media_playback`.
        Application = 0,
        /// The library opens the devices and pumps every managed call; the
        /// packets reach the application through `audio_transmit_callback`.
        /// `SIPRAL_STATUS_NOT_SUPPORTED` without a backend for the platform,
        /// as `SIPRAL_FEATURE_AUDIO_DEVICE` says.
        Device = 1,
    }
}

codes! {
    /// When the devices are opened, in device mode:
    /// `sipral_stack_config_t::audio_activation`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudioActivation: u32 {
        /// With the first managed call's media or ring; closed with the last.
        Automatic = 0,
        /// Only between `sipral_audio_activate` and `sipral_audio_deactivate`:
        /// for CallKit and the telecom framework, which own the audio session.
        Manual = 1,
    }
}

codes! {
    /// What a device is used for.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudioRole: u32 {
        /// The call's microphone.
        Microphone = 1,
        /// The call's loudspeaker or earpiece.
        Speaker = 2,
        /// Where an incoming call is announced, which may differ from where
        /// it is answered.
        Ringer = 3,
    }
}

codes! {
    /// Which way audio flows, for gain, mute and the meter.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudioDirection: u32 {
        /// From the microphone. Its gain is the microphone gain.
        Input = 1,
        /// To the loudspeaker. Its gain is the volume.
        Output = 2,
    }
}

codes! {
    /// What changed, on `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudioChange: u32 {
        /// A device arrived or left. Every valid id stays valid: a device
        /// that left keeps its row, marked absent.
        ListChanged = 1,
        /// The system's default for `direction` moved. A role on a chosen
        /// device stays; one on the system's route follows with
        /// `SIPRAL_AUDIO_CHANGE_REOPENED`.
        DefaultChanged = 2,
        /// `role` is on `device` because `sipral_audio_select` said so.
        Selected = 3,
        /// The device `role` ran on went away; the reopen is reported apart.
        Lost = 4,
        /// `role` is running on `device` again.
        Reopened = 5,
        /// `role` could not be opened on anything; that direction is
        /// silence until a device arrives.
        Unavailable = 6,
    }
}

codes! {
    /// Who made a change. An application must not answer either by
    /// re-applying its own choice.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudioOrigin: u32 {
        /// The operating system, or a person at a socket.
        System = 1,
        /// The engine.
        Engine = 2,
    }
}

record! {
    /// One device, as `sipral_audio_device_at` fills it in. Set `size` to
    /// `sizeof(sipral_audio_device_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralAudioDevice {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The engine's name for the device: stable across refreshes, never
        /// reused, never zero. What `sipral_audio_select` takes.
        pub id: u32,
        /// Channels it captures; zero for a device that is no microphone.
        pub input_channels: u32,
        /// How many channels it plays; zero likewise.
        pub output_channels: u32,
        /// One when the system records from it by default.
        pub default_input: u32,
        /// One when the system plays to it by default.
        pub default_output: u32,
        /// One when the last refresh found it. An absent device keeps its row
        /// and id, so a saved selection still names something.
        pub present: u32,
    }
}

// Safety: integers only, and zero is valid for each.
unsafe impl Versioned for SipralAudioDevice {
    const NAME: &'static str = "sipral_audio_device";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralAudioDevice, present);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What the engine is doing, as `sipral_audio_info` fills it in. Set
    /// `size` to `sizeof(sipral_audio_info_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralAudioInfo {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// One while the devices are open and the pump is running.
        pub active: u32,
        /// One when the platform's own processing sits behind the microphone:
        /// the voice-processing unit on macOS and iOS, a communications stream
        /// on Windows (a virtual cable cancels nothing). For echo removal
        /// regardless, attach a processor per call; the engine tells each
        /// managed call `render_delay_ms` itself, after every device change.
        pub system_echo_cancellation: u32,
        /// The loudspeaker-to-microphone delay the devices report, in
        /// milliseconds.
        pub render_delay_ms: u64,
        /// The rate the microphone runs at, or zero when it is not open.
        pub microphone_rate_hz: u32,
        /// The rate the loudspeaker runs at, or zero when it is not open.
        pub speaker_rate_hz: u32,
        /// The device the microphone is running on, or zero.
        pub microphone: u32,
        /// The device the loudspeaker is running on, or zero.
        pub speaker: u32,
        /// The device the ringer is running on, or zero when the ring goes
        /// through the loudspeaker.
        pub ringer: u32,
        /// Zero. Pads the struct to a multiple of its alignment, so a member
        /// appended later never lands in padding. Written zero, never read.
        pub reserved: u32,
    }
}

// Safety: integers only, and zero is valid for each.
unsafe impl Versioned for SipralAudioInfo {
    const NAME: &'static str = "sipral_audio_info";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralAudioInfo, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One packet the engine encoded, handed to
    /// `sipral_stack_config_t::audio_transmit_callback`: send it from the
    /// call's media socket and return.
    ///
    /// Read `size` before anything past it, and nothing once the callback
    /// returns. The callback runs on the engine's thread, once per frame per
    /// call; it may call the media entry points and must not destroy the stack.
    #[derive(Clone, Copy)]
    pub struct SipralAudioTransmit {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The call whose socket this leaves from.
        pub call: SipralHandle,
        /// A `SipralTransport`: UDP is a datagram from the media socket; TCP
        /// and TLS are bytes to write in order on the socket's TURN connection.
        pub protocol: Number<SipralTransport>,
        /// Zero. Keeps later members at the same offsets on 32- and 64-bit
        /// targets. Written zero, never read.
        pub reserved: u32,
        /// Where to send it, `host:port`, UTF-8 and not NUL-terminated.
        pub destination: *const c_char,
        /// How many bytes of it.
        pub destination_len: usize,
        /// The octets.
        pub payload: *const u8,
        /// How many of them.
        pub payload_len: usize,
    }
}

alias! {
    /// Where the packets the engine encodes go: the application's, called
    /// on the engine's thread with one `sipral_audio_transmit_t` per packet.
    pub type SipralAudioTransmitCallback = fn(
        transmit: *const SipralAudioTransmit,
        user_data: *mut c_void,
    );
}

record! {
    /// What `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` carries.
    #[derive(Clone, Copy)]
    pub struct SipralAudioEvent {
        /// A `SipralAudioChange`.
        pub change: Number<SipralAudioChange>,
        /// A `SipralAudioOrigin`.
        pub origin: Number<SipralAudioOrigin>,
        /// A `SipralAudioRole`, for a change about one role; zero otherwise.
        pub role: Number<SipralAudioRole>,
        /// A `SipralAudioDirection`, for `SIPRAL_AUDIO_CHANGE_DEFAULT_CHANGED`;
        /// zero otherwise.
        pub direction: Number<SipralAudioDirection>,
        /// The device the change is about, or zero.
        pub device: u32,
    }
}

/// The engine of one stack in device mode, behind its own lock.
pub(crate) type Shared = Arc<Mutex<Engine>>;

/// The clock the pump drives the calls on: the stack's last poll time,
/// carried forward by the time since. The pump has no caller to take
/// `now_ms` from, and its own reading would put call timers out of step.
pub(crate) struct Clock {
    origin: Instant,
    last: Mutex<(u64, Instant)>,
}

impl Clock {
    pub(crate) fn new(origin: Instant) -> Arc<Self> {
        Arc::new(Self {
            origin,
            last: Mutex::new((0, origin)),
        })
    }

    /// The stack was polled at `now_ms`.
    pub(crate) fn polled(&self, now_ms: u64) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = (now_ms, Instant::now());
    }

    fn now(&self) -> Instant {
        let (now_ms, read_at) = *self.last.lock().unwrap_or_else(PoisonError::into_inner);
        self.origin
            .checked_add(Duration::from_millis(now_ms))
            .unwrap_or(self.origin)
            + read_at.elapsed()
    }
}

/// The transmit callback, as the engine calls it.
struct CTransmit {
    callback: unsafe extern "C" fn(*const SipralAudioTransmit, *mut c_void),
    user_data: usize,
    destination: String,
}

impl CTransmit {
    fn send(&mut self, call: SipralHandle, packet: &Outgoing) {
        self.destination.clear();
        let _ = write!(self.destination, "{}", packet.destination);
        let transmit = SipralAudioTransmit {
            reserved: 0,
            size: size_of::<SipralAudioTransmit>(),
            call,
            protocol: match packet.transport {
                Transport::Udp => SipralTransport::Udp as u32,
                Transport::Tcp => SipralTransport::Tcp as u32,
                Transport::Tls => SipralTransport::Tls as u32,
            },
            destination: self.destination.as_ptr().cast::<c_char>(),
            destination_len: self.destination.len(),
            payload: packet.payload.as_ptr(),
            payload_len: packet.payload.len(),
        };
        IN_TRANSMIT.set(IN_TRANSMIT.get().saturating_add(1));
        // SAFETY: the callback is the caller's, given with the user pointer
        // it expects, and the record points into buffers that outlive the
        // call.
        unsafe { (self.callback)(&raw const transmit, self.user_data as *mut c_void) };
        IN_TRANSMIT.set(IN_TRANSMIT.get().saturating_sub(1));
    }
}

thread_local! {
    /// How deep this thread is inside the audio transmit callback.
    static IN_TRANSMIT: Cell<u32> = const { Cell::new(0) };
}

/// Whether this thread is the engine's pump, inside the transmit callback.
///
/// Destroying the stack from there would join the pump from itself, so that
/// call is refused with `SIPRAL_STATUS_BUSY`.
pub(crate) fn inside_transmit() -> bool {
    IN_TRANSMIT.get() != 0
}

#[cfg(test)]
thread_local! {
    /// A fake platform for the stack this thread creates next.
    pub(crate) static FAKE_PLATFORM: std::cell::RefCell<Option<sipral_audio::fake::FakeControl>> =
        const { std::cell::RefCell::new(None) };
}

fn backend() -> Option<Box<dyn sipral_audio::backend::Backend>> {
    #[cfg(test)]
    if let Some(fake) = FAKE_PLATFORM.with_borrow(Clone::clone) {
        return Some(fake.backend());
    }
    sipral_audio::platform_backend()
}

/// Whether this build has a backend for the platform it runs on: the answer
/// `SIPRAL_FEATURE_AUDIO_DEVICE` gives.
pub(crate) fn available() -> bool {
    sipral_audio::platform_has_backend()
}

/// The engine a configuration asks for, or `None` for application mode.
///
/// # Safety
///
/// `config` as `sipral_stack_create` takes it.
pub(crate) unsafe fn configured(
    config: &SipralStackConfig,
    clock: &Arc<Clock>,
) -> Result<Option<Shared>, Fail> {
    match config.audio {
        0 => return Ok(None),
        1 => {}
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "audio is {other}, and a stack is SIPRAL_AUDIO_APPLICATION or SIPRAL_AUDIO_DEVICE"
                ),
            ));
        }
    }
    let activation = match config.audio_activation {
        0 => Activation::Automatic,
        1 => Activation::Manual,
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("audio_activation is {other}, which names no activation"),
            ));
        }
    };
    let Some(callback) = config.audio_transmit_callback else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "a stack in device mode needs an audio_transmit_callback: the packets the engine \
             encodes have to leave from the application's socket",
        ));
    };
    let Some(platform) = backend() else {
        return Err(fail(
            SipralStatus::NotSupported,
            "this build has no audio backend for this platform: pump the frames from the \
             application, as SIPRAL_FEATURE_AUDIO_DEVICE says",
        ));
    };
    let mut settings = Config {
        activation,
        ..Config::default()
    };
    if config.audio_probe_ms != 0 {
        settings.probe_wait = Duration::from_millis(config.audio_probe_ms);
    }
    if config.audio_device_rate_hz != 0 {
        settings.device_rate_hz = config.audio_device_rate_hz;
    }
    settings.system_echo_cancellation = crate::media::toggled(
        config.system_echo_cancellation,
        "system_echo_cancellation",
        true,
    )?;
    let mut transmit = CTransmit {
        callback,
        user_data: config.audio_transmit_user_data as usize,
        destination: String::new(),
    };
    let clock = Arc::clone(clock);
    let engine = Engine::new(
        platform,
        settings,
        Box::new(move |call, packet: &Outgoing| transmit.send(call, packet)),
        Arc::new(move || clock.now()),
    );
    Ok(Some(Arc::new(Mutex::new(engine))))
}

/// What an engine event is, as C reads it.
pub(crate) fn event_of(event: AudioEvent) -> SipralAudioEvent {
    let (change, role, direction) = match event.change {
        Change::DefaultChanged(direction) => {
            (SipralAudioChange::DefaultChanged, None, Some(direction))
        }
        Change::Selected(role) => (SipralAudioChange::Selected, Some(role), None),
        Change::Lost(role) => (SipralAudioChange::Lost, Some(role), None),
        Change::Reopened(role) => (SipralAudioChange::Reopened, Some(role), None),
        Change::Unavailable(role) => (SipralAudioChange::Unavailable, Some(role), None),
        // the list changing, or an engine change this ABI has no word for
        Change::ListChanged | _ => (SipralAudioChange::ListChanged, None, None),
    };
    SipralAudioEvent {
        change: change as u32,
        origin: match event.origin {
            Origin::System => SipralAudioOrigin::System as u32,
            Origin::Engine => SipralAudioOrigin::Engine as u32,
        },
        role: role.map_or(0, |role| role_code(role) as u32),
        direction: direction.map_or(0, |direction| direction_code(direction) as u32),
        device: event.device.map_or(0, DeviceHandle::get),
    }
}

const fn role_code(role: Role) -> SipralAudioRole {
    match role {
        Role::Microphone => SipralAudioRole::Microphone,
        Role::Speaker => SipralAudioRole::Speaker,
        Role::Ringer => SipralAudioRole::Ringer,
    }
}

const fn direction_code(direction: Direction) -> SipralAudioDirection {
    match direction {
        Direction::Input => SipralAudioDirection::Input,
        Direction::Output => SipralAudioDirection::Output,
    }
}

fn role_of(role: u32) -> Result<Role, Fail> {
    match role {
        1 => Ok(Role::Microphone),
        2 => Ok(Role::Speaker),
        3 => Ok(Role::Ringer),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("role is {other}, which names no role"),
        )),
    }
}

fn direction_of(direction: u32) -> Result<Direction, Fail> {
    match direction {
        1 => Ok(Direction::Input),
        2 => Ok(Direction::Output),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("direction is {other}, which names no direction"),
        )),
    }
}

fn platform_failed(error: &sipral_audio::backend::BackendError) -> Fail {
    use sipral_audio::backend::BackendError;
    match *error {
        BackendError::TimedOut => fail(
            SipralStatus::DeviceTimedOut,
            "the platform did not answer within audio_probe_ms: a driver is stuck, and the \
             engine is not waiting on it",
        ),
        BackendError::NoDevice => fail(
            SipralStatus::DeviceUnusable,
            "there is no device to open in that direction",
        ),
        BackendError::Refused(ref why) => fail(
            SipralStatus::DeviceUnusable,
            format!("the platform refused the device: {why}"),
        ),
        _ => fail(SipralStatus::DeviceUnusable, error.to_string()),
    }
}

/// Do something with the stack's engine, or say why not.
fn with_engine<R>(
    stack: SipralHandle,
    act: impl FnOnce(&mut Engine) -> Result<R, Fail>,
) -> Result<R, Fail> {
    let shared = audio_of(stack)?.ok_or_else(|| {
        fail(
            SipralStatus::WrongState,
            "this stack runs its audio in application mode: it was created with audio left at \
             SIPRAL_AUDIO_APPLICATION, and pumps its own frames",
        )
    })?;
    let mut engine = shared.lock().unwrap_or_else(PoisonError::into_inner);
    act(&mut engine)
}

entry! {
    /// Ask the platform for its devices and say how many the list holds.
    ///
    /// Known devices keep their ids; gone ones keep their rows, marked absent.
    /// For a settings screen, not polling: the engine refreshes on platform
    /// notices. `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`, with
    /// the list unchanged.
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t` or be null.
    fn sipral_audio_refresh(stack: SipralHandle, out_count: *mut usize) {
        let count = with_engine(stack, |engine| {
            engine
                .refresh()
                .map(<[_]>::len)
                .map_err(|error| platform_failed(&error))
        })?;
        if !out_count.is_null() {
            unsafe { out_count.write(count) };
        }
        Ok(())
    }
}

entry! {
    /// How many devices the list holds, present or not.
    ///
    /// The first read of a list asks the platform, so no refresh is needed.
    /// `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`; the next read
    /// asks again.
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_audio_device_count(stack: SipralHandle, out_count: *mut usize) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let count = with_engine(stack, |engine| {
            engine
                .listing()
                .map(<[_]>::len)
                .map_err(|error| platform_failed(&error))
        })?;
        unsafe { out_count.write(count) };
        Ok(())
    }
}

entry! {
    /// The device at `index` in the list, and its name into `buffer`.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` past the end. The name is UTF-8 with a
    /// trailing NUL; `out_needed`, when not null, receives its length with the
    /// NUL. `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes neither `buffer` nor
    /// `out_device`.
    ///
    /// # Safety
    ///
    /// `out_device` must point at a `sipral_audio_device_t` whose `size`
    /// member says how long it is; `buffer` must be writable for `capacity`
    /// bytes or null with a capacity of zero; `out_needed` must point at one
    /// `size_t` or be null.
    fn sipral_audio_device_at(
        stack: SipralHandle,
        index: usize,
        out_device: *mut SipralAudioDevice,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        unsafe { crate::versioned::declared_size(out_device.cast_const()) }?;
        let (device, text) = with_engine(stack, |engine| {
            let listed = engine.listing().map_err(|error| platform_failed(&error))?;
            let count = listed.len();
            let found = listed.get(index).ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("index is {index} and the list holds {count}"),
                )
            })?;
            Ok((
                SipralAudioDevice {
                    size: size_of::<SipralAudioDevice>(),
                    id: found.handle.get(),
                    input_channels: found.input_channels,
                    output_channels: found.output_channels,
                    default_input: u32::from(found.default_input),
                    default_output: u32::from(found.default_output),
                    present: u32::from(found.present),
                },
                found.name.clone(),
            ))
        })?;
        unsafe { crate::diagnostics::copy_out(&text, buffer, capacity, out_needed) }?;
        unsafe { write_versioned(out_device, device) }
    }
}

entry! {
    /// Put a role on a device, or back on the system's route with a
    /// `device` of zero.
    ///
    /// Refused before any platform call, changing nothing:
    /// `SIPRAL_STATUS_NO_SUCH_DEVICE` for an unknown id,
    /// `SIPRAL_STATUS_DEVICE_UNUSABLE` for a device absent or without channels
    /// in the role's direction, `SIPRAL_STATUS_NOT_SUPPORTED` where the
    /// platform cannot separate the role (on macOS the microphone follows the
    /// system's input).
    ///
    /// While active the role reopens at once, keeping gain and mute, and
    /// `SIPRAL_AUDIO_CHANGE_SELECTED` follows. A chosen device that is
    /// unplugged stays the preference and is used again when it returns.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_select(stack: SipralHandle, role: Number<SipralAudioRole>, device: u32) {
        let role = role_of(role)?;
        let selection = match DeviceHandle::new(device) {
            Some(handle) => Selection::Device(handle),
            None => Selection::System,
        };
        with_engine(stack, |engine| {
            engine.select(role, selection).map_err(|error| match error {
                SelectError::NoSuchDevice => fail(
                    SipralStatus::NoSuchDevice,
                    format!("no device has the id {device}: sipral_audio_device_at lists them"),
                ),
                SelectError::NoChannels => fail(
                    SipralStatus::DeviceUnusable,
                    format!("device {device} has no channels in the {role}'s direction"),
                ),
                SelectError::Absent => fail(
                    SipralStatus::DeviceUnusable,
                    format!("device {device} is not plugged in"),
                ),
                SelectError::NotSupported => fail(
                    SipralStatus::NotSupported,
                    format!("this platform cannot put the {role} on a device of its own"),
                ),
                _ => fail(SipralStatus::DeviceUnusable, error.to_string()),
            })
        })
    }
}

entry! {
    /// What a role was asked to be on (zero: the system's route) and what it
    /// runs on (zero: not open). They differ while a chosen device is absent.
    ///
    /// # Safety
    ///
    /// Each out parameter must point at one `uint32_t` or be null.
    fn sipral_audio_selection(
        stack: SipralHandle,
        role: Number<SipralAudioRole>,
        out_selected: *mut u32,
        out_running: *mut u32,
    ) {
        let role = role_of(role)?;
        let (selected, running) = with_engine(stack, |engine| {
            let selected = match engine.selection(role) {
                Selection::System => 0,
                Selection::Device(handle) => handle.get(),
            };
            Ok((selected, engine.running_on(role).map_or(0, DeviceHandle::get)))
        })?;
        if !out_selected.is_null() {
            unsafe { out_selected.write(selected) };
        }
        if !out_running.is_null() {
            unsafe { out_running.write(running) };
        }
        Ok(())
    }
}

/// Unity gain, in the fixed-point steps `sipral_audio_set_gain` takes.
const GAIN_UNITY: u16 = 256;

/// The most the steps go up to: four times unity.
const GAIN_MOST: u16 = 4 * GAIN_UNITY;

entry! {
    /// Set the gain of one direction, fixed-point with 256 for unity, capped
    /// at 1024. Input is the microphone gain, output the volume. Applied to
    /// the frames, not the OS control, and kept across device changes.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_set_gain(stack: SipralHandle, direction: Number<SipralAudioDirection>, gain: u32) {
        let direction = direction_of(direction)?;
        with_engine(stack, |engine| {
            engine.set_gain(direction, gain_of(gain));
            Ok(())
        })
    }
}

entry! {
    /// The gain of one direction, in the steps `sipral_audio_set_gain` takes.
    ///
    /// # Safety
    ///
    /// `out_gain` must point at one `uint32_t`.
    fn sipral_audio_gain(stack: SipralHandle, direction: Number<SipralAudioDirection>, out_gain: *mut u32) {
        if out_gain.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_gain is null"));
        }
        let direction = direction_of(direction)?;
        let gain = with_engine(stack, |engine| Ok(engine.gain(direction)))?;
        unsafe { out_gain.write(steps_of(gain)) };
        Ok(())
    }
}

entry! {
    /// Mute or unmute one direction, kept across device changes. A muted
    /// microphone sends silence, so the far end hears a stream, not a gap.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_set_muted(stack: SipralHandle, direction: Number<SipralAudioDirection>, muted: u32) {
        let direction = direction_of(direction)?;
        with_engine(stack, |engine| {
            engine.set_muted(direction, muted != 0);
            Ok(())
        })
    }
}

entry! {
    /// Whether one direction is muted: one or zero into `out_muted`.
    ///
    /// # Safety
    ///
    /// `out_muted` must point at one `uint32_t`.
    fn sipral_audio_muted(stack: SipralHandle, direction: Number<SipralAudioDirection>, out_muted: *mut u32) {
        if out_muted.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_muted is null"));
        }
        let direction = direction_of(direction)?;
        let muted = with_engine(stack, |engine| Ok(engine.is_muted(direction)))?;
        unsafe { out_muted.write(u32::from(muted)) };
        Ok(())
    }
}

entry! {
    /// The meter of one direction: the peak sample of the last 100 ms, 0 to
    /// 32767, held one to two windows. Cheap to poll per frame; zero while
    /// nothing is open.
    ///
    /// # Safety
    ///
    /// `out_peak` must point at one `uint32_t`.
    fn sipral_audio_level(stack: SipralHandle, direction: Number<SipralAudioDirection>, out_peak: *mut u32) {
        if out_peak.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_peak is null"));
        }
        let direction = direction_of(direction)?;
        let peak = with_engine(stack, |engine| Ok(engine.level(direction).peak()))?;
        unsafe { out_peak.write(u32::from(peak)) };
        Ok(())
    }
}

/// `sipral_audio_set_gain` steps as a gain, capped at four times unity.
fn gain_of(steps: u32) -> Gain {
    let steps = u16::try_from(steps).unwrap_or(GAIN_MOST).min(GAIN_MOST);
    Gain::from_ratio(f32::from(steps) / f32::from(GAIN_UNITY))
}

/// A gain, as the steps `sipral_audio_gain` hands back.
fn steps_of(gain: Gain) -> u32 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a ratio is between 0 and 4, so its steps are between 0 and 1024"
    )]
    let steps = (gain.ratio() * f32::from(GAIN_UNITY)).round() as u32;
    steps
}

/// The engine is not carrying `call`.
fn not_carried(call: SipralHandle) -> Fail {
    fail(
        SipralStatus::WrongState,
        format!(
            "the engine is not carrying call {call}: a call's own gain, mute and meter exist \
             from the moment its media starts until it ends"
        ),
    )
}

entry! {
    /// Set one call's own gain in one direction, on top of the stack's, in
    /// `sipral_audio_set_gain` steps. Input is what the microphone sends that
    /// call; output is how loud it plays. Kept through hold and conference,
    /// gone when the call ends.
    ///
    /// In a local conference it acts on the call's path, on top of the
    /// conference's member controls: input on what its far end hears, output
    /// on what it says into the conference.
    /// `SIPRAL_STATUS_WRONG_STATE` when the engine is not carrying the call's
    /// media: before it starts, after it ends, or in application mode.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_call_set_gain(
        stack: SipralHandle,
        call: SipralHandle,
        direction: Number<SipralAudioDirection>,
        gain: u32,
    ) {
        let direction = direction_of(direction)?;
        with_engine(stack, |engine| {
            if engine.set_call_gain(call, direction, gain_of(gain)) {
                Ok(())
            } else {
                Err(not_carried(call))
            }
        })
    }
}

entry! {
    /// One call's own gain in one direction, in `sipral_audio_set_gain` steps.
    ///
    /// # Safety
    ///
    /// `out_gain` must point at one `uint32_t`.
    fn sipral_audio_call_gain(
        stack: SipralHandle,
        call: SipralHandle,
        direction: Number<SipralAudioDirection>,
        out_gain: *mut u32,
    ) {
        if out_gain.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_gain is null"));
        }
        let direction = direction_of(direction)?;
        let gain = with_engine(stack, |engine| {
            engine
                .call_gain(call, direction)
                .ok_or_else(|| not_carried(call))
        })?;
        unsafe { out_gain.write(steps_of(gain)) };
        Ok(())
    }
}

entry! {
    /// Mute or unmute one call in one direction while other calls go on (a
    /// consultation). A muted direction sends silence. Kept, dropped and
    /// refused as `sipral_audio_call_set_gain` is, conference included.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_call_set_muted(
        stack: SipralHandle,
        call: SipralHandle,
        direction: Number<SipralAudioDirection>,
        muted: u32,
    ) {
        let direction = direction_of(direction)?;
        with_engine(stack, |engine| {
            if engine.set_call_muted(call, direction, muted != 0) {
                Ok(())
            } else {
                Err(not_carried(call))
            }
        })
    }
}

entry! {
    /// Whether one call is muted in one direction: one or zero.
    ///
    /// # Safety
    ///
    /// `out_muted` must point at one `uint32_t`.
    fn sipral_audio_call_muted(
        stack: SipralHandle,
        call: SipralHandle,
        direction: Number<SipralAudioDirection>,
        out_muted: *mut u32,
    ) {
        if out_muted.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_muted is null"));
        }
        let direction = direction_of(direction)?;
        let muted = with_engine(stack, |engine| {
            engine
                .call_muted(call, direction)
                .ok_or_else(|| not_carried(call))
        })?;
        unsafe { out_muted.write(u32::from(muted)) };
        Ok(())
    }
}

entry! {
    /// One call's meter in one direction, after its own gain and mute: what
    /// `sipral_audio_level` reads, for one call of several.
    ///
    /// # Safety
    ///
    /// `out_peak` must point at one `uint32_t`.
    fn sipral_audio_call_level(
        stack: SipralHandle,
        call: SipralHandle,
        direction: Number<SipralAudioDirection>,
        out_peak: *mut u32,
    ) {
        if out_peak.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_peak is null"));
        }
        let direction = direction_of(direction)?;
        let peak = with_engine(stack, |engine| {
            engine
                .call_level(call, direction)
                .map(sipral_audio::Level::peak)
                .ok_or_else(|| not_carried(call))
        })?;
        unsafe { out_peak.write(u32::from(peak)) };
        Ok(())
    }
}

entry! {
    /// Open the devices and start the pump now. The only way under
    /// `SIPRAL_AUDIO_ACTIVATION_MANUAL`; early under automatic activation.
    /// `SIPRAL_STATUS_DEVICE_UNUSABLE` or `SIPRAL_STATUS_DEVICE_TIMED_OUT` for
    /// a direction that failed: the engine is still active, silent there.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_activate(stack: SipralHandle) {
        with_engine(stack, |engine| {
            engine.activate().map_err(|error| platform_failed(&error))
        })
    }
}

entry! {
    /// Close the devices and stop the pump. The calls stay attached and get
    /// their audio back on the next activation.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_deactivate(stack: SipralHandle) {
        with_engine(stack, |engine| {
            engine.deactivate();
            Ok(())
        })
    }
}

entry! {
    /// Ring on the ringer's device (or the loudspeaker) until
    /// `sipral_audio_stop_ringing`, or once when `looped` is zero. Mono 16-bit
    /// samples at `sample_rate_hz`, copied before return. Under automatic
    /// activation a ring opens the devices.
    ///
    /// # Safety
    ///
    /// `samples` must be readable for `sample_count` `int16_t`.
    fn sipral_audio_ring(
        stack: SipralHandle,
        samples: *const i16,
        sample_count: usize,
        sample_rate_hz: u32,
        looped: u32,
    ) {
        if samples.is_null() || sample_count == 0 {
            return Err(fail(SipralStatus::InvalidArgument, "the tone is empty"));
        }
        if sample_rate_hz == 0 {
            return Err(fail(SipralStatus::InvalidArgument, "sample_rate_hz is zero"));
        }
        let tone = unsafe { slice::from_raw_parts(samples, sample_count) }.to_vec();
        with_engine(stack, |engine| {
            engine
                .ring(tone, sample_rate_hz, looped != 0)
                .map_err(|error| platform_failed(&error))
        })
    }
}

entry! {
    /// Stop the ring. Under automatic activation, with no call up, the
    /// devices close with it.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_stop_ringing(stack: SipralHandle) {
        with_engine(stack, |engine| {
            engine.stop_ringing();
            Ok(())
        })
    }
}

entry! {
    /// Turn the platform's echo cancellation on or off on a running stack:
    /// `on` is a `SipralToggle`, and zero leaves it.
    ///
    /// Open devices are reopened at once with or without the platform
    /// processing, on the same devices with gain and mute, each reported as
    /// `SIPRAL_AUDIO_CHANGE_REOPENED`. A call hears a short gap; a refused
    /// direction is `SIPRAL_AUDIO_CHANGE_UNAVAILABLE`. Closed devices use it
    /// on the next open. `sipral_audio_info_t` says what the platform did.
    /// `SIPRAL_STATUS_WRONG_STATE` in application mode.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_set_system_echo_cancellation(stack: SipralHandle, on: Number<SipralToggle>) {
        let on = match on {
            0 => None,
            1 => Some(true),
            2 => Some(false),
            other => {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("on is {other}, and a toggle is 0 to leave it, 1 for on or 2 for off"),
                ));
            }
        };
        with_engine(stack, |engine| {
            if let Some(on) = on {
                engine.set_system_echo_cancellation(on);
            }
            Ok(())
        })
    }
}

entry! {
    /// What the engine is doing: whether it is active, whether the platform
    /// cancels echo, the delay a canceller needs, and where each role runs.
    ///
    /// # Safety
    ///
    /// `out_info` must point at a `sipral_audio_info_t` whose `size` member
    /// says how long it is.
    fn sipral_audio_info(stack: SipralHandle, out_info: *mut SipralAudioInfo) {
        unsafe { crate::versioned::declared_size(out_info.cast_const()) }?;
        let info = with_engine(stack, |engine| {
            let info = engine.info();
            Ok(SipralAudioInfo {
                reserved: 0,
                size: size_of::<SipralAudioInfo>(),
                active: u32::from(info.active),
                system_echo_cancellation: u32::from(info.system_echo_cancellation),
                render_delay_ms: u64::try_from(info.render_delay.as_millis()).unwrap_or(u64::MAX),
                microphone_rate_hz: info.microphone_rate_hz.unwrap_or(0),
                speaker_rate_hz: info.speaker_rate_hz.unwrap_or(0),
                microphone: engine.running_on(Role::Microphone).map_or(0, DeviceHandle::get),
                speaker: engine.running_on(Role::Speaker).map_or(0, DeviceHandle::get),
                ringer: engine.running_on(Role::Ringer).map_or(0, DeviceHandle::get),
            })
        })?;
        unsafe { write_versioned(out_info, info) }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        CTransmit, FAKE_PLATFORM, GAIN_UNITY, Outgoing, SipralAudio, SipralAudioActivation,
        SipralAudioChange, SipralAudioDevice, SipralAudioDirection, SipralAudioInfo,
        SipralAudioOrigin, SipralAudioRole, SipralAudioTransmit, Transport, sipral_audio_activate,
        sipral_audio_deactivate, sipral_audio_device_at, sipral_audio_device_count,
        sipral_audio_gain, sipral_audio_info, sipral_audio_level, sipral_audio_muted,
        sipral_audio_refresh, sipral_audio_ring, sipral_audio_select, sipral_audio_selection,
        sipral_audio_set_gain, sipral_audio_set_muted, sipral_audio_set_system_echo_cancellation,
        sipral_audio_stop_ringing,
    };
    use super::{
        sipral_audio_call_gain, sipral_audio_call_level, sipral_audio_call_muted,
        sipral_audio_call_set_gain, sipral_audio_call_set_muted,
    };
    use crate::call::tests::{hangup, media_call_tuned};
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::SipralHandle;
    use crate::media::SipralToggle;
    use crate::stack::tests::{Observed, config, create, poll, record};
    use crate::stack::{SipralStackSettings, sipral_stack_settings};
    use crate::status::SipralStatus;
    use sipral_audio::Direction;
    use sipral_audio::fake::FakeControl;
    use std::ffi::{c_char, c_void};
    use std::ptr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Packets handed to the transmit callback: call, destination, length.
    pub(crate) type Packets = Arc<Mutex<Vec<(SipralHandle, String, usize)>>>;

    pub(crate) unsafe extern "C" fn transmit(
        event: *const SipralAudioTransmit,
        user_data: *mut c_void,
    ) {
        let transmit = unsafe { &*event };
        let destination = unsafe {
            std::slice::from_raw_parts(transmit.destination.cast::<u8>(), transmit.destination_len)
        };
        let packets = unsafe { &*user_data.cast::<Packets>() };
        packets.lock().unwrap().push((
            transmit.call,
            String::from_utf8_lossy(destination).into_owned(),
            transmit.payload_len,
        ));
    }

    /// A headset beside the built-in defaults, at 48 kHz.
    pub(crate) fn a_desk() -> FakeControl {
        let fake = FakeControl::new(48_000);
        fake.plug("builtin-out", "Built-in Output", 0, 2);
        fake.plug("builtin-mic", "Built-in Microphone", 1, 0);
        fake.plug("headset", "USB Headset", 1, 2);
        fake.make_default("builtin-out", Direction::Output);
        fake.make_default("builtin-mic", Direction::Input);
        fake.forget_notices();
        fake
    }

    /// A stack in device mode over `fake`, with a managed call up on it.
    pub(crate) fn device_call(
        observed: &mut Observed,
        fake: &FakeControl,
        activation: SipralAudioActivation,
    ) -> (SipralHandle, SipralHandle, Packets) {
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = Some(fake.clone()));
        let packets: Packets = Arc::new(Mutex::new(Vec::new()));
        let leaked: &'static Packets = Box::leak(Box::new(Arc::clone(&packets)));
        let (stack, call) = media_call_tuned(observed, |config| {
            config.audio = SipralAudio::Device as u32;
            config.audio_activation = activation as u32;
            config.audio_transmit_callback = Some(transmit);
            config.audio_transmit_user_data = ptr::from_ref(leaked).cast_mut().cast::<c_void>();
            config.audio_probe_ms = 500;
        });
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = None);
        (stack, call, packets)
    }

    fn refresh(stack: SipralHandle) -> usize {
        let mut count = usize::MAX;
        let status = unsafe { sipral_audio_refresh(stack, &raw mut count) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        count
    }

    fn device_at(stack: SipralHandle, index: usize) -> (SipralAudioDevice, String) {
        let mut device = SipralAudioDevice {
            size: size_of::<SipralAudioDevice>(),
            id: u32::MAX,
            input_channels: u32::MAX,
            output_channels: u32::MAX,
            default_input: u32::MAX,
            default_output: u32::MAX,
            present: u32::MAX,
        };
        let mut name = [0_u8; 128];
        let mut len = 0_usize;
        let status = unsafe {
            sipral_audio_device_at(
                stack,
                index,
                &raw mut device,
                name.as_mut_ptr().cast::<c_char>(),
                name.len(),
                &raw mut len,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(name[len - 1], 0, "the name ends in the NUL it counts");
        (
            device,
            String::from_utf8_lossy(&name[..len - 1]).into_owned(),
        )
    }

    fn id_of(stack: SipralHandle, name: &str) -> u32 {
        let mut count = 0;
        assert_eq!(
            unsafe { sipral_audio_device_count(stack, &raw mut count) },
            SipralStatus::Ok
        );
        (0..count)
            .map(|index| device_at(stack, index))
            .find(|(_, listed)| listed == name)
            .map_or_else(|| panic!("{name} is not listed"), |(device, _)| device.id)
    }

    fn info(stack: SipralHandle) -> SipralAudioInfo {
        let mut info = SipralAudioInfo {
            reserved: 0,
            size: size_of::<SipralAudioInfo>(),
            active: u32::MAX,
            system_echo_cancellation: u32::MAX,
            render_delay_ms: u64::MAX,
            microphone_rate_hz: u32::MAX,
            speaker_rate_hz: u32::MAX,
            microphone: u32::MAX,
            speaker: u32::MAX,
            ringer: u32::MAX,
        };
        let status = unsafe { sipral_audio_info(stack, &raw mut info) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        info
    }

    fn audio_events(observed: &Observed) -> Vec<(u32, u32, u32, u32)> {
        observed.audio.clone()
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let started = Instant::now();
        while !done() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "waited five seconds for {what}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Poll until the devices opening in the background are under the calls.
    pub(crate) fn landed(stack: SipralHandle, now_ms: u64) {
        let engine = crate::stack::audio_of(stack)
            .expect("the stack")
            .expect("device mode has an engine");
        wait_until("the devices to open", || {
            poll(stack, now_ms);
            !engine.lock().unwrap().is_opening()
        });
    }

    /// A call's own controls work while carried and are refused otherwise.
    #[test]
    fn a_calls_own_gain_mute_and_meter_cross_by_its_handle() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, call, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        let input = SipralAudioDirection::Input as u32;
        let output = SipralAudioDirection::Output as u32;
        assert_eq!(
            unsafe { sipral_audio_call_set_muted(stack, call, input, 1) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { sipral_audio_call_set_gain(stack, call, output, u32::from(GAIN_UNITY / 2)) },
            SipralStatus::Ok
        );
        let (mut muted, mut gain, mut peak) = (u32::MAX, u32::MAX, u32::MAX);
        assert_eq!(
            unsafe { sipral_audio_call_muted(stack, call, input, &raw mut muted) },
            SipralStatus::Ok
        );
        assert_eq!(muted, 1);
        assert_eq!(
            unsafe { sipral_audio_call_muted(stack, call, output, &raw mut muted) },
            SipralStatus::Ok
        );
        assert_eq!(muted, 0, "each direction its own");
        assert_eq!(
            unsafe { sipral_audio_call_gain(stack, call, output, &raw mut gain) },
            SipralStatus::Ok
        );
        assert_eq!(gain, u32::from(GAIN_UNITY / 2));
        assert_eq!(
            unsafe { sipral_audio_call_level(stack, call, input, &raw mut peak) },
            SipralStatus::Ok
        );
        assert_eq!(peak, 0, "nothing has gone past yet");
        // the stack-wide mute is another switch, and was not touched
        assert_eq!(
            unsafe { sipral_audio_muted(stack, input, &raw mut muted) },
            SipralStatus::Ok
        );
        assert_eq!(muted, 0);
        assert_eq!(
            unsafe { sipral_audio_call_level(stack, call, 3, &raw mut peak) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_audio_call_level(stack, call, input, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        let stranger = call ^ 0x5555;
        assert_eq!(
            unsafe { sipral_audio_call_set_muted(stack, stranger, input, 1) },
            SipralStatus::WrongState,
            "a handle the engine never carried"
        );
        hangup(stack, call, 3_000);
        assert_eq!(
            unsafe { sipral_audio_call_muted(stack, call, input, &raw mut muted) },
            SipralStatus::WrongState,
            "gone with the call's media"
        );

        let mut observed = Observed::default();
        let (status, plain) = create(&config(record, &mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_audio_call_set_muted(plain, call, input, 1) },
            SipralStatus::WrongState
        );
        assert!(last_error_text().contains("application mode"));
    }

    /// Echo cancellation off at creation is not asked of the platform.
    #[test]
    fn the_echo_cancellation_switch_reaches_the_platform() {
        let mut observed = Observed::default();
        let fake = a_desk();
        fake.set_system_echo_cancellation(true);
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = Some(fake.clone()));
        let packets: Packets = Arc::new(Mutex::new(Vec::new()));
        let leaked: &'static Packets = Box::leak(Box::new(packets));
        let (stack, _) = media_call_tuned(&mut observed, |config| {
            config.audio = SipralAudio::Device as u32;
            config.audio_activation = SipralAudioActivation::Manual as u32;
            config.audio_transmit_callback = Some(transmit);
            config.audio_transmit_user_data = ptr::from_ref(leaked).cast_mut().cast::<c_void>();
            config.audio_probe_ms = 500;
            config.system_echo_cancellation = crate::media::SipralToggle::Off as u32;
        });
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = None);
        assert!(!fake.echo_cancellation_asked());
        assert_eq!(unsafe { sipral_audio_activate(stack) }, SipralStatus::Ok);
        assert_eq!(info(stack).system_echo_cancellation, 0);
    }

    fn asked_echo_cancellation(stack: SipralHandle) -> u32 {
        let mut settings = SipralStackSettings {
            size: size_of::<SipralStackSettings>(),
            ..unsafe { std::mem::zeroed() }
        };
        let status = unsafe { sipral_stack_settings(stack, &raw mut settings) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        settings.system_echo_cancellation
    }

    /// Switching echo cancellation on a running stack reopens the devices in
    /// place, keeping gain, mute and the call.
    #[test]
    fn the_echo_cancellation_switches_on_a_running_stack() {
        let mut observed = Observed::default();
        let fake = a_desk();
        fake.set_system_echo_cancellation(true);
        let (stack, call, packets) =
            device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        let headset = id_of(stack, "USB Headset");
        let speaker = SipralAudioRole::Speaker as u32;
        let input = SipralAudioDirection::Input as u32;
        let output = SipralAudioDirection::Output as u32;
        assert_eq!(
            unsafe { sipral_audio_select(stack, speaker, headset) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_audio_set_gain(stack, output, u32::from(GAIN_UNITY / 2)) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_audio_set_muted(stack, input, 1) },
            SipralStatus::Ok
        );
        assert_eq!(unsafe { sipral_audio_activate(stack) }, SipralStatus::Ok);
        assert_eq!(info(stack).system_echo_cancellation, 1);
        assert_eq!(asked_echo_cancellation(stack), SipralToggle::On as u32);
        poll(stack, 2_500);
        observed.audio.clear();
        let opens = fake.opens();

        assert_eq!(
            unsafe { sipral_audio_set_system_echo_cancellation(stack, SipralToggle::Off as u32) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(fake.opens(), opens + 2, "both directions reopened at once");
        assert!(!fake.echo_cancellation_asked());
        let now = info(stack);
        assert_eq!((now.active, now.system_echo_cancellation), (1, 0));
        assert_eq!(now.speaker, headset, "the loudspeaker stayed on its device");
        assert_eq!(asked_echo_cancellation(stack), SipralToggle::Off as u32);
        let (mut gain, mut muted) = (u32::MAX, u32::MAX);
        assert_eq!(
            unsafe { sipral_audio_gain(stack, output, &raw mut gain) },
            SipralStatus::Ok
        );
        assert_eq!(gain, u32::from(GAIN_UNITY / 2));
        assert_eq!(
            unsafe { sipral_audio_muted(stack, input, &raw mut muted) },
            SipralStatus::Ok
        );
        assert_eq!(muted, 1);
        poll(stack, 2_600);
        let reopened = SipralAudioChange::Reopened as u32;
        let engine_said = SipralAudioOrigin::Engine as u32;
        assert!(
            audio_events(&observed).contains(&(reopened, engine_said, speaker, headset)),
            "{:?}",
            audio_events(&observed)
        );
        let sent = packets.lock().unwrap().len();
        for _ in 0..12 {
            fake.speak_into("builtin-mic", &[4_000; 960]);
        }
        wait_until("the call to go on being carried", || {
            packets
                .lock()
                .unwrap()
                .iter()
                .skip(sent)
                .any(|(on, _, _)| *on == call)
        });

        assert_eq!(
            unsafe {
                sipral_audio_set_system_echo_cancellation(stack, SipralToggle::Default as u32)
            },
            SipralStatus::Ok
        );
        assert_eq!(fake.opens(), opens + 2, "zero leaves it as it is");
        assert_eq!(
            unsafe { sipral_audio_set_system_echo_cancellation(stack, 3) },
            SipralStatus::InvalidArgument
        );
        assert!(last_error_text().contains("on is 3"));
        assert_eq!(
            info(stack).system_echo_cancellation,
            0,
            "a refusal changes nothing"
        );
        assert_eq!(
            unsafe { sipral_audio_set_system_echo_cancellation(stack, SipralToggle::On as u32) },
            SipralStatus::Ok
        );
        assert_eq!(info(stack).system_echo_cancellation, 1);
        hangup(stack, call, 3_000);
    }

    /// In application mode there is nothing to switch.
    #[test]
    fn the_echo_cancellation_switch_is_refused_in_application_mode() {
        let mut observed = Observed::default();
        let (status, stack) = create(&config(record, &mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_audio_set_system_echo_cancellation(stack, SipralToggle::Off as u32) },
            SipralStatus::WrongState
        );
        assert!(last_error_text().contains("application mode"));
        assert_eq!(
            unsafe { sipral_audio_set_system_echo_cancellation(stack, 7) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(asked_echo_cancellation(stack), SipralToggle::On as u32);
    }

    #[test]
    fn a_stack_in_application_mode_has_no_engine_to_ask() {
        let mut observed = Observed::default();
        let config = config(record, &mut observed);
        let (status, stack) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let mut count = 0;
        assert_eq!(
            unsafe { sipral_audio_device_count(stack, &raw mut count) },
            SipralStatus::WrongState
        );
        assert!(last_error_text().contains("application mode"));
    }

    /// A hangup's BYE leaves while the platform's teardown is blocked (the
    /// macOS voice unit can wait on the main thread): no poll waits for it.
    #[test]
    fn a_hangup_leaves_while_the_devices_are_still_being_let_go_of() {
        use crate::call::sipral_call_hangup;
        use crate::call::tests::{accepted, deliver, sent, start_line};
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, call, _) = device_call(&mut observed, &fake, SipralAudioActivation::Automatic);
        landed(stack, 2_500);
        fake.hold_teardown();
        let releaser = {
            let fake = fake.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(3));
                fake.release_teardown();
            })
        };
        let timed_poll = |now_ms: u64| {
            let started = Instant::now();
            poll(stack, now_ms);
            let took = started.elapsed();
            assert!(
                took < Duration::from_millis(500),
                "the poll at {now_ms} waited {took:?} for the devices"
            );
        };
        assert_eq!(
            unsafe { sipral_call_hangup(stack, call, 3_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        timed_poll(3_000);
        let out = sent(stack);
        let bye = out
            .iter()
            .find(|message| start_line(message).starts_with("BYE"))
            .expect("the BYE is queued");
        deliver(stack, &accepted(bye, b"", false), 3_010);
        timed_poll(3_010);
        assert_eq!(info(stack).active, 0, "the devices still run the call");
        releaser.join().unwrap();
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A slow device open does not hold the poll that starts the call.
    #[test]
    fn a_slow_device_does_not_hold_the_poll_that_starts_the_call() {
        let mut observed = Observed::default();
        let fake = a_desk();
        fake.set_open_delay(Some(Duration::from_millis(1_500)));
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = Some(fake.clone()));
        let packets: Packets = Arc::new(Mutex::new(Vec::new()));
        let leaked: &'static Packets = Box::leak(Box::new(packets));
        let started = Instant::now();
        let (stack, _) = media_call_tuned(&mut observed, |config| {
            config.audio = SipralAudio::Device as u32;
            config.audio_activation = SipralAudioActivation::Automatic as u32;
            config.audio_transmit_callback = Some(transmit);
            config.audio_transmit_user_data = ptr::from_ref(leaked).cast_mut().cast::<c_void>();
        });
        let took = started.elapsed();
        FAKE_PLATFORM.with_borrow_mut(|slot| *slot = None);
        assert!(
            took < Duration::from_millis(800),
            "bringing the call up waited {took:?} for its devices"
        );
        assert_eq!(info(stack).active, 1);
        assert_eq!(info(stack).speaker, 0, "the loudspeaker answered too soon");
        let mut result = crate::stack::tests::poll_result();
        let status = unsafe { crate::stack::sipral_stack_poll(stack, 2_500, &raw mut result) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(result.has_deadline, 1);
        assert!(
            result.next_poll_in_ms <= 20,
            "the poll is not asked back while the devices open: {}",
            result.next_poll_in_ms
        );
        landed(stack, 2_500);
        assert_ne!(info(stack).speaker, 0);
        assert_eq!(info(stack).microphone_rate_hz, 48_000);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A poll does not wait for an engine another thread holds; it asks to
    /// be called back soon, so signalling never answers BUSY meanwhile.
    #[test]
    fn a_poll_does_not_wait_for_an_engine_another_thread_holds() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, _, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        let shared = crate::stack::audio_of(stack)
            .expect("the stack")
            .expect("device mode has an engine");
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _engine = shared.lock().unwrap();
            held_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(1_500));
        });
        held_rx.recv().unwrap();
        let started = Instant::now();
        let mut result = crate::stack::tests::poll_result();
        let status = unsafe { crate::stack::sipral_stack_poll(stack, 5_000, &raw mut result) };
        let waited = started.elapsed();
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(
            waited < Duration::from_secs(1),
            "the poll waited {waited:?} for the engine"
        );
        assert_eq!(result.has_deadline, 1);
        assert!(result.next_poll_in_ms <= 20, "{}", result.next_poll_in_ms);
        holder.join().unwrap();
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// What `sipral_stack_destroy` answered inside the callback below.
    static DESTROYED_FROM_THE_PUMP: std::sync::atomic::AtomicI32 =
        std::sync::atomic::AtomicI32::new(i32::MIN);

    /// A transmit callback that destroys the stack whose handle it was given.
    unsafe extern "C" fn destroys_its_stack(
        _transmit: *const SipralAudioTransmit,
        user_data: *mut c_void,
    ) {
        let stack = unsafe { *user_data.cast::<SipralHandle>() };
        let status = unsafe { crate::stack::sipral_stack_destroy(stack) };
        DESTROYED_FROM_THE_PUMP.store(status as i32, std::sync::atomic::Ordering::SeqCst);
    }

    /// A destroy from the transmit callback would join the pump from itself;
    /// it is refused, and the stack can still be destroyed elsewhere.
    #[test]
    fn a_stack_is_not_destroyed_from_inside_its_transmit_callback() {
        let mut observed = Observed::default();
        let config = config(record, &mut observed);
        let (status, stack) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let mut handle = stack;
        let mut transmit = CTransmit {
            callback: destroys_its_stack,
            user_data: ptr::from_mut(&mut handle) as usize,
            destination: String::new(),
        };
        let packet = Outgoing {
            destination: "192.0.2.1:4000".parse().unwrap(),
            payload: vec![0; 12],
            transport: Transport::Udp,
        };
        transmit.send(stack, &packet);
        assert_eq!(
            DESTROYED_FROM_THE_PUMP.load(std::sync::atomic::Ordering::SeqCst),
            SipralStatus::Busy as i32
        );
        assert!(!super::inside_transmit(), "the mark goes with the callback");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn device_mode_needs_a_transmit_callback() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.audio = SipralAudio::Device as u32;
        let (status, _) = create(&config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("audio_transmit_callback"));
        config.audio = 7;
        let (status, _) = create(&config);
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    /// Every device with its channels, under ids that survive an unplug.
    #[test]
    fn the_list_is_read_with_stable_ids() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, call, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        assert_eq!(refresh(stack), 3);
        let (headset, name) = device_at(stack, 2);
        assert_eq!(name, "USB Headset");
        assert_eq!((headset.input_channels, headset.output_channels), (1, 2));
        assert_eq!(headset.present, 1);
        assert_eq!(headset.default_output, 0);
        let (builtin, _) = device_at(stack, 0);
        assert_eq!(builtin.default_output, 1);

        fake.unplug("headset");
        assert_eq!(refresh(stack), 3, "the row stays");
        let (gone, _) = device_at(stack, 2);
        assert_eq!(gone.id, headset.id);
        assert_eq!(gone.present, 0);
        fake.plug("headset", "USB Headset", 1, 2);
        refresh(stack);
        let (back, _) = device_at(stack, 2);
        assert_eq!(back.id, headset.id, "the same identity gets the same id");
        assert_eq!(back.present, 1);

        let mut device = SipralAudioDevice {
            size: size_of::<SipralAudioDevice>(),
            id: 0,
            input_channels: 0,
            output_channels: 0,
            default_input: 0,
            default_output: 0,
            present: 0,
        };
        let status = unsafe {
            sipral_audio_device_at(
                stack,
                9,
                &raw mut device,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        // a name that does not fit: length with NUL, nothing written
        let mut short = [0_u8; 11];
        let mut needed = 0;
        let status = unsafe {
            sipral_audio_device_at(
                stack,
                2,
                &raw mut device,
                short.as_mut_ptr().cast::<c_char>(),
                short.len(),
                &raw mut needed,
            )
        };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(needed, "USB Headset".len() + 1);
        assert_eq!(short, [0; 11], "nothing of the name was written");
        assert_eq!(device.id, 0, "nothing of the struct was written");
        hangup(stack, call, 3_000);
    }

    /// A new stack lists every device on its first read, without a refresh.
    #[test]
    fn a_new_stack_lists_every_device_on_its_first_read() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (first, _, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        assert_eq!(refresh(first), 3);
        fake.plug("dock", "Dock Speakers", 0, 2);
        fake.forget_notices();

        let mut second_observed = Observed::default();
        let (second, _, _) =
            device_call(&mut second_observed, &fake, SipralAudioActivation::Manual);
        let mut count = 0;
        assert_eq!(
            unsafe { sipral_audio_device_count(second, &raw mut count) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(count, 4, "the first read asks the platform");
        assert_ne!(id_of(second, "Dock Speakers"), 0);

        let mut third_observed = Observed::default();
        let (third, _, _) = device_call(&mut third_observed, &fake, SipralAudioActivation::Manual);
        let (dock, name) = device_at(third, 3);
        assert_eq!(name, "Dock Speakers");
        assert_eq!(dock.output_channels, 2);
    }

    /// Each refusal has its own status, and the selection reads back.
    #[test]
    fn a_selection_is_refused_by_status_and_read_back() {
        let mut observed = Observed::default();
        let fake = a_desk();
        fake.plug("orphan", "Orphaned Device", 0, 0);
        let (stack, _, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        refresh(stack);
        let headset = id_of(stack, "USB Headset");
        let builtin_out = id_of(stack, "Built-in Output");
        let orphan = id_of(stack, "Orphaned Device");
        let select = |role: SipralAudioRole, device: u32| unsafe {
            sipral_audio_select(stack, role as u32, device)
        };
        assert_eq!(
            select(SipralAudioRole::Speaker, 999),
            SipralStatus::NoSuchDevice
        );
        assert_eq!(
            select(SipralAudioRole::Microphone, builtin_out),
            SipralStatus::DeviceUnusable
        );
        assert_eq!(
            select(SipralAudioRole::Speaker, orphan),
            SipralStatus::DeviceUnusable
        );
        assert_eq!(
            unsafe { sipral_audio_select(stack, 9, headset) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(select(SipralAudioRole::Speaker, headset), SipralStatus::Ok);
        let (mut selected, mut running) = (u32::MAX, u32::MAX);
        let status = unsafe {
            sipral_audio_selection(
                stack,
                SipralAudioRole::Speaker as u32,
                &raw mut selected,
                &raw mut running,
            )
        };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(selected, headset);
        assert_eq!(running, 0, "not active, so on nothing yet");
        fake.unplug("headset");
        refresh(stack);
        assert_eq!(
            select(SipralAudioRole::Ringer, headset),
            SipralStatus::DeviceUnusable
        );
        assert!(last_error_text().contains("not plugged in"));
    }

    /// Gain, mute and the meter, per direction.
    #[test]
    fn gain_mute_and_level_are_per_direction() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, _, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        let input = SipralAudioDirection::Input as u32;
        let output = SipralAudioDirection::Output as u32;
        assert_eq!(
            unsafe { sipral_audio_set_gain(stack, output, u32::from(GAIN_UNITY / 2)) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_audio_set_muted(stack, input, 1) },
            SipralStatus::Ok
        );
        let mut gain = 0;
        assert_eq!(
            unsafe { sipral_audio_gain(stack, output, &raw mut gain) },
            SipralStatus::Ok
        );
        assert_eq!(gain, u32::from(GAIN_UNITY / 2));
        assert_eq!(
            unsafe { sipral_audio_gain(stack, input, &raw mut gain) },
            SipralStatus::Ok
        );
        assert_eq!(gain, u32::from(GAIN_UNITY));
        let mut muted = 0;
        assert_eq!(
            unsafe { sipral_audio_muted(stack, input, &raw mut muted) },
            SipralStatus::Ok
        );
        assert_eq!(muted, 1);
        assert_eq!(
            unsafe { sipral_audio_muted(stack, output, &raw mut muted) },
            SipralStatus::Ok
        );
        assert_eq!(muted, 0);
        let mut peak = u32::MAX;
        assert_eq!(
            unsafe { sipral_audio_level(stack, input, &raw mut peak) },
            SipralStatus::Ok
        );
        assert_eq!(peak, 0, "nothing is open");
        assert_eq!(
            unsafe { sipral_audio_level(stack, 3, &raw mut peak) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_audio_level(stack, input, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
    }

    /// A managed call's audio goes from the fake microphone to the callback
    /// and from the call to the loudspeaker.
    #[test]
    fn a_managed_call_is_pumped_and_its_packets_reach_the_callback() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, call, packets) =
            device_call(&mut observed, &fake, SipralAudioActivation::Automatic);
        // the call's media activated the engine; the devices land later
        assert_eq!(info(stack).active, 1);
        landed(stack, 2_500);
        let now = info(stack);
        assert_eq!(now.active, 1);
        assert_eq!(now.microphone_rate_hz, 48_000);
        assert_eq!(now.render_delay_ms, 30);
        assert_eq!(now.system_echo_cancellation, 0);
        for _ in 0..12 {
            fake.speak_into("builtin-mic", &[4_000; 960]);
        }
        wait_until("packets from the callback", || {
            packets.lock().unwrap().len() >= 8
        });
        let sent = packets.lock().unwrap().clone();
        assert!(sent.iter().all(|(handle, _, _)| *handle == call));
        assert!(
            sent.iter()
                .all(|(_, destination, _)| destination == crate::call::tests::PEER_MEDIA)
        );
        assert!(
            sent.iter().all(|(_, _, len)| *len == 12 + 160),
            "mu-law, twenty milliseconds, and a header"
        );
        // silence, but written at the loudspeaker's rate
        wait_until("the loudspeaker to be written", || {
            fake.played_by("builtin-out").len() >= 960 * 4
        });
        let mut peak = 0;
        assert_eq!(
            unsafe { sipral_audio_level(stack, SipralAudioDirection::Input as u32, &raw mut peak) },
            SipralStatus::Ok
        );
        assert_eq!(peak, 4_000);
        hangup(stack, call, 3_000);
        poll(stack, 3_100);
        wait_until("the devices to close with the last call", || {
            info(stack).active == 0
        });
    }

    /// Device changes say who made them, and a moved default leaves a chosen
    /// role in place.
    #[test]
    fn device_changes_arrive_as_events_that_say_who_made_them() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, call, _) = device_call(&mut observed, &fake, SipralAudioActivation::Automatic);
        refresh(stack);
        let headset = id_of(stack, "USB Headset");
        let builtin = id_of(stack, "Built-in Output");
        assert_eq!(
            unsafe { sipral_audio_select(stack, SipralAudioRole::Speaker as u32, headset) },
            SipralStatus::Ok
        );
        poll(stack, 3_000);
        let selected = (
            SipralAudioChange::Selected as u32,
            SipralAudioOrigin::Engine as u32,
            SipralAudioRole::Speaker as u32,
            headset,
        );
        assert!(
            audio_events(&observed).contains(&selected),
            "{:?}",
            audio_events(&observed)
        );
        assert_eq!(info(stack).speaker, headset);

        let speaker_reopened = |events: &[(u32, u32, u32, u32)]| {
            events
                .iter()
                .filter(|(change, _, role, _)| {
                    *change == SipralAudioChange::Reopened as u32
                        && *role == SipralAudioRole::Speaker as u32
                })
                .count()
        };
        let before = speaker_reopened(&audio_events(&observed));
        fake.make_default("headset", Direction::Output);
        poll(stack, 3_100);
        let events = audio_events(&observed);
        assert!(events.contains(&(
            SipralAudioChange::DefaultChanged as u32,
            SipralAudioOrigin::System as u32,
            0,
            0
        )));
        assert_eq!(
            speaker_reopened(&events),
            before,
            "the speaker was not moved: {events:?}"
        );

        fake.unplug("headset");
        std::thread::sleep(Duration::from_millis(60));
        poll(stack, 3_200);
        landed(stack, 3_200);
        let events = audio_events(&observed);
        assert!(
            events.contains(&(
                SipralAudioChange::Lost as u32,
                SipralAudioOrigin::System as u32,
                SipralAudioRole::Speaker as u32,
                headset
            )),
            "{events:?}"
        );
        assert!(
            events.contains(&(
                SipralAudioChange::Reopened as u32,
                SipralAudioOrigin::Engine as u32,
                SipralAudioRole::Speaker as u32,
                builtin
            )),
            "{events:?}"
        );
        let (mut selected, mut running) = (0, 0);
        unsafe {
            sipral_audio_selection(
                stack,
                SipralAudioRole::Speaker as u32,
                &raw mut selected,
                &raw mut running,
            )
        };
        assert_eq!(
            (selected, running),
            (headset, builtin),
            "the preference is kept, the fallback runs"
        );
        hangup(stack, call, 3_300);
    }

    /// Manual activation: the call does not open the devices; activate and
    /// deactivate do.
    #[test]
    fn manual_activation_is_the_applications_alone() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, call, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        assert_eq!(info(stack).active, 0, "a call up did not open anything");
        assert_eq!(fake.opens(), 0);
        assert_eq!(
            unsafe { sipral_audio_activate(stack) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(info(stack).active, 1);
        assert_eq!(fake.opens(), 2);
        hangup(stack, call, 3_000);
        poll(stack, 3_100);
        assert_eq!(info(stack).active, 1, "the call ending did not close them");
        assert_eq!(unsafe { sipral_audio_deactivate(stack) }, SipralStatus::Ok);
        assert_eq!(info(stack).active, 0);
    }

    /// A ring goes to the ringer's device, and stopping it with no call up
    /// closes the devices under automatic activation.
    #[test]
    fn a_ring_goes_to_the_ringer_device() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, call, _) = device_call(&mut observed, &fake, SipralAudioActivation::Automatic);
        refresh(stack);
        let headset = id_of(stack, "USB Headset");
        let builtin = id_of(stack, "Built-in Output");
        assert_eq!(
            unsafe { sipral_audio_select(stack, SipralAudioRole::Speaker as u32, headset) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_audio_select(stack, SipralAudioRole::Ringer as u32, builtin) },
            SipralStatus::Ok
        );
        let tone = [2_000_i16; 800];
        assert_eq!(
            unsafe { sipral_audio_ring(stack, tone.as_ptr(), tone.len(), 8_000, 1) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(info(stack).ringer, builtin);
        wait_until("the room to ring", || {
            fake.played_by("builtin-out").iter().any(|s| *s != 0)
        });
        assert_eq!(
            unsafe { sipral_audio_ring(stack, ptr::null(), 0, 8_000, 1) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_audio_stop_ringing(stack) },
            SipralStatus::Ok
        );
        hangup(stack, call, 3_000);
        poll(stack, 3_100);
        wait_until("the devices to close", || info(stack).active == 0);
    }

    /// A platform that does not answer is a status, within the probe wait.
    #[test]
    fn a_stuck_platform_is_a_timeout_status() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, _, _) = device_call(&mut observed, &fake, SipralAudioActivation::Manual);
        fake.hang();
        let started = Instant::now();
        let mut count = 0;
        assert_eq!(
            unsafe { sipral_audio_refresh(stack, &raw mut count) },
            SipralStatus::DeviceTimedOut
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        fake.release();
    }

    /// Literal numbers, so a moved declaration fails here.
    #[test]
    fn the_numbers_are_where_they_were_published() {
        assert_eq!(SipralAudio::Application as u32, 0);
        assert_eq!(SipralAudio::Device as u32, 1);
        assert_eq!(SipralAudioActivation::Automatic as u32, 0);
        assert_eq!(SipralAudioActivation::Manual as u32, 1);
        assert_eq!(SipralAudioRole::Microphone as u32, 1);
        assert_eq!(SipralAudioRole::Speaker as u32, 2);
        assert_eq!(SipralAudioRole::Ringer as u32, 3);
        assert_eq!(SipralAudioDirection::Input as u32, 1);
        assert_eq!(SipralAudioDirection::Output as u32, 2);
        assert_eq!(SipralAudioChange::ListChanged as u32, 1);
        assert_eq!(SipralAudioChange::Unavailable as u32, 6);
        assert_eq!(SipralAudioOrigin::System as u32, 1);
        assert_eq!(SipralAudioOrigin::Engine as u32, 2);
        assert_eq!(SipralEventKind::AudioDevicesChanged as u32, 43);
        assert_eq!(SipralStatus::NoSuchDevice as i32, 13);
        assert_eq!(SipralStatus::DeviceUnusable as i32, 14);
        assert_eq!(SipralStatus::DeviceTimedOut as i32, 15);
    }

    /// An engine event becomes the record C reads.
    #[test]
    fn an_engine_event_becomes_the_record_c_reads() {
        let event = super::event_of(sipral_audio::AudioEvent {
            change: sipral_audio::Change::Lost(sipral_audio::Role::Ringer),
            origin: sipral_audio::Origin::System,
            device: sipral_audio::DeviceHandle::new(5),
        });
        assert_eq!(event.change, SipralAudioChange::Lost as u32);
        assert_eq!(event.origin, SipralAudioOrigin::System as u32);
        assert_eq!(event.role, SipralAudioRole::Ringer as u32);
        assert_eq!(event.direction, 0);
        assert_eq!(event.device, 5);
        let event = super::event_of(sipral_audio::AudioEvent {
            change: sipral_audio::Change::DefaultChanged(Direction::Output),
            origin: sipral_audio::Origin::System,
            device: None,
        });
        assert_eq!(event.direction, SipralAudioDirection::Output as u32);
        assert_eq!(event.role, 0);
    }
}
