// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The built-in audio engine across the boundary: the platform's devices
//! listed, chosen, opened and pumped by the library — A2 and A3, and the
//! mode a softphone migrating from a stack that opened the devices for it
//! expects.
//!
//! A stack is created in one of two modes, `sipral_stack_config_t::audio`.
//! In application mode, which is what a zeroed configuration says and what
//! every stack before this module was, the application pumps its own
//! frames through `sipral_media_capture` and `sipral_media_playback` and
//! nothing here does anything. In device mode the library opens the
//! microphone and the loudspeaker itself, carries every managed call's
//! audio between them, and hands the packets it encodes to the
//! application's `audio_transmit_callback` for the application's socket —
//! the socket is still the application's, as it is for everything else
//! this ABI sends. Received packets go in through `sipral_media_receive`
//! as before, from whichever thread reads the socket.
//!
//! The entry points here take the stack's handle and not its lock: a level
//! meter polled from a window's timer, or a device list rebuilt from a
//! settings screen, never answers `SIPRAL_STATUS_BUSY` because signalling
//! is busy. What they take is the engine's own lock, which is held for a
//! table lookup or a platform call bounded by `audio_probe_ms`, never for
//! a frame.
//!
//! What the engine does on its own — a device pulled out, the default
//! moved, a role reopened on its fallback — arrives as
//! `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`, from the poll, with
//! `payload.audio` saying what changed and who changed it: a change the
//! application asked for and one the operating system made are told
//! apart, because an application that re-applies its own choice on hearing
//! itself announced is a loop.

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

use crate::abi::{alias, codes, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{SipralStackConfig, SipralTransport, audio_of};
use crate::status::SipralStatus;
use crate::versioned::{Versioned, write_versioned};

codes! {
    /// Who pumps a stack's audio: `sipral_stack_config_t::audio`.
    ///
    /// Zero is application mode because zero is what a configuration
    /// written against any earlier header says, and a caller that pumps its
    /// own frames must go on pumping them when the library underneath it is
    /// updated. The idiomatic layers each choose their own default.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudio: u32 {
        /// The application opens the devices and pumps the frames through
        /// `sipral_media_capture` and `sipral_media_playback`. What every
        /// stack was before device mode existed.
        Application = 0,
        /// The library opens the platform's devices and pumps every
        /// managed call itself; the packets it encodes reach the
        /// application's socket through `audio_transmit_callback`.
        /// `SIPRAL_STATUS_NOT_SUPPORTED` on a platform this build has no
        /// backend for, which `SIPRAL_FEATURE_AUDIO_DEVICE` says first.
        Device = 1,
    }
}

codes! {
    /// When the devices are opened, in device mode:
    /// `sipral_stack_config_t::audio_activation`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudioActivation: u32 {
        /// With the first managed call's media, or the first ring; closed
        /// with the last. What a desktop softphone wants.
        Automatic = 0,
        /// Only between `sipral_audio_activate` and `sipral_audio_deactivate`,
        /// whatever the calls do. What CallKit and the telecom framework
        /// want: they say when the audio session is this application's,
        /// and a device opened before they do is a device that does not work.
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
        /// Where an incoming call is announced, which need not be where it
        /// is answered: the room's speaker for the ring, the headset for
        /// the call.
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
        /// A device arrived or left; the list has been refreshed, and
        /// `sipral_audio_device_at` reads the new one. Every id that was
        /// valid still is: a device that left keeps its row, marked absent.
        ListChanged = 1,
        /// The system's default for `direction` moved. A role the
        /// application put on a device stays there; one on the system's
        /// route follows, and says so with `SIPRAL_AUDIO_CHANGE_REOPENED`.
        DefaultChanged = 2,
        /// `role` is on `device` because `sipral_audio_select` said so.
        Selected = 3,
        /// The device `role` was running on went away. The engine reopens
        /// the role on its fallback and reports that separately.
        Lost = 4,
        /// `role` is running on `device` again.
        Reopened = 5,
        /// `role` could not be opened on anything; that direction is
        /// silence until a device arrives.
        Unavailable = 6,
    }
}

codes! {
    /// Who made a change: the operating system, or this library doing what
    /// the application asked or what a loss made it do. An application
    /// notes the first and acts on neither by re-applying its own choice.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAudioOrigin: u32 {
        /// The operating system, or a person at a socket.
        System = 1,
        /// The engine.
        Engine = 2,
    }
}

record! {
    /// One device, as `sipral_audio_device_at` fills it in. The name is
    /// written beside it, into the caller's buffer.
    ///
    /// Set `size` to `sizeof(sipral_audio_device_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralAudioDevice {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The engine's name for the device: stable across refreshes, never
        /// reused, never zero. What `sipral_audio_select` takes.
        pub id: u32,
        /// How many channels it captures; zero for a device that is no
        /// microphone.
        pub input_channels: u32,
        /// How many channels it plays; zero likewise.
        pub output_channels: u32,
        /// One when the system records from it by default.
        pub default_input: u32,
        /// One when the system plays to it by default.
        pub default_output: u32,
        /// One when the last refresh still found it. A device that went
        /// keeps its row and its id, so that a selection saved against it
        /// still names something.
        pub present: u32,
    }
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each.
unsafe impl Versioned for SipralAudioDevice {
    const NAME: &'static str = "sipral_audio_device";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralAudioDevice, present);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What the engine is doing, as `sipral_audio_info` fills it in.
    ///
    /// Set `size` to `sizeof(sipral_audio_info_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralAudioInfo {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// One while the devices are open and the pump is running.
        pub active: u32,
        /// One when the platform's own processing sits behind the
        /// microphone: the voice-processing unit on macOS and iOS, which
        /// cancels the loudspeaker's echo itself; on Windows, a stream
        /// accepted as a communications stream, which puts the endpoint's
        /// own processing behind it where the endpoint has any — a virtual
        /// cable has none, and cancels nothing. An application that wants
        /// the echo gone regardless attaches a processor to each call with
        /// `sipral_media_attach_processor`; the delay it needs is
        /// `render_delay_ms`, and the engine tells each managed call that
        /// number itself, again after every device change.
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
        /// Zero. Rounds the struct up to a whole multiple of its alignment on
        /// every target, so that a member a later version appends starts at or
        /// past the length a caller built against this header declares, never
        /// in padding inside it. The library writes zero here and reads nothing
        /// from it.
        pub reserved: u32,
    }
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each.
unsafe impl Versioned for SipralAudioInfo {
    const NAME: &'static str = "sipral_audio_info";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralAudioInfo, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One packet the engine encoded from the microphone, handed to
    /// `sipral_stack_config_t::audio_transmit_callback`: send it from the
    /// call's media socket and return.
    ///
    /// Filled by the library and handed to the callback as a `const`
    /// pointer, the shape `sipral_processor_frame_t` is: read `size` before
    /// anything past it, and read nothing once the callback has returned.
    /// The callback runs on the engine's own thread, once per frame per
    /// call; it may call `sipral_media_receive` and the other media entry
    /// points, and must not destroy the stack.
    #[derive(Clone, Copy)]
    pub struct SipralAudioTransmit {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The call whose socket this leaves from.
        pub call: SipralHandle,
        /// How it leaves, as a `SipralTransport`: `SIPRAL_TRANSPORT_UDP` is
        /// a datagram from the media socket; `SIPRAL_TRANSPORT_TCP` and
        /// `SIPRAL_TRANSPORT_TLS` are bytes to write, in order, on the
        /// socket's connection to its TURN server, as `sipral_media_capture`
        /// marks them.
        pub protocol: u32,
        /// Zero. Keeps the members after it where a 32-bit and a 64-bit target
        /// both put them without padding at the end of the struct, so that a
        /// member a later version appends starts past the length a caller built
        /// against this header declares. The library writes zero here and reads
        /// nothing from it.
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
        pub change: u32,
        /// A `SipralAudioOrigin`.
        pub origin: u32,
        /// A `SipralAudioRole`, for a change about one role; zero otherwise.
        pub role: u32,
        /// A `SipralAudioDirection`, for `SIPRAL_AUDIO_CHANGE_DEFAULT_CHANGED`;
        /// zero otherwise.
        pub direction: u32,
        /// The device the change is about — the one a role landed on, or
        /// the one that went — or zero.
        pub device: u32,
    }
}

// -- the engine behind a stack --------------------------------------------

/// The engine of one stack in device mode, behind its own lock.
pub(crate) type Shared = Arc<Mutex<Engine>>;

/// The clock the pump drives the calls on: the caller's, as the stack last
/// read it, carried forward by the time since.
///
/// A media entry point takes `now_ms` from the caller; the pump has no
/// caller to take it from, and a reading that disagreed with the stack's
/// would put the calls' timers out of step with the signalling that owns
/// them.
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
    /// How deep this thread is inside the audio transmit callback: the
    /// engine's pump, handing the application a packet.
    static IN_TRANSMIT: Cell<u32> = const { Cell::new(0) };
}

/// Whether this thread is the engine's pump, inside the transmit callback.
///
/// The pump holds no lock of the library's while it calls out, so nothing
/// stops a `sipral_stack_destroy` made from there — and destroying the stack
/// drops the engine, which joins the pump: the thread waiting for itself to
/// finish. That call is refused with `SIPRAL_STATUS_BUSY` instead, the way a
/// processor's call into its own stack is.
pub(crate) fn inside_transmit() -> bool {
    IN_TRANSMIT.get() != 0
}

#[cfg(test)]
thread_local! {
    /// A fake platform for the stack the calling thread creates next, so a
    /// test of device mode runs without a device in the room.
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
    let mut transmit = CTransmit {
        callback,
        user_data: config.audio_transmit_user_data as usize,
        destination: String::new(),
    };
    let clock = Arc::clone(clock);
    let engine = Engine::new(
        platform,
        settings,
        Box::new(move |call, packet| transmit.send(call, &packet)),
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
        // the list changing, and a change the engine grows later that this
        // ABI has no word for: the list is what every one of them ends up
        // changing
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

// -- entry points -----------------------------------------------------------

entry! {
    /// Ask the platform what devices there are, and say how many the list
    /// holds now.
    ///
    /// A device seen before keeps its id; one that has gone keeps its row,
    /// marked absent; a new one gets the next id. The engine refreshes by
    /// itself when the platform announces a change, so this is for a
    /// settings screen opening, not for polling.
    /// `SIPRAL_STATUS_DEVICE_TIMED_OUT` when the platform did not answer
    /// within `audio_probe_ms`, with the list left as it was.
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
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_audio_device_count(stack: SipralHandle, out_count: *mut usize) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let count = with_engine(stack, |engine| Ok(engine.devices().len()))?;
        unsafe { out_count.write(count) };
        Ok(())
    }
}

entry! {
    /// The device at `index` in the list, and its name into `buffer`.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the end. The name
    /// is written the way every other text this ABI hands out is: UTF-8 with
    /// a trailing NUL, and `out_needed`, when it is not null, receives the
    /// bytes it needs with that NUL counted. When the name does not fit, the
    /// answer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` and nothing is written,
    /// neither to `buffer` nor to `out_device`: ask with a capacity of zero
    /// to learn the length, then again with room.
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
            let count = engine.devices().len();
            let found = engine.devices().get(index).ok_or_else(|| {
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
    /// Refused before any platform call is made: `SIPRAL_STATUS_NO_SUCH_DEVICE`
    /// for an id the list never held, `SIPRAL_STATUS_DEVICE_UNUSABLE` for a
    /// device with no channels in the role's direction or one that is not
    /// plugged in, `SIPRAL_STATUS_NOT_SUPPORTED` where the platform cannot
    /// put that role on a device of its own — macOS runs the call's
    /// microphone and loudspeaker as one unit, and the microphone follows
    /// the system's input. A refused selection changes nothing.
    ///
    /// While the engine is active the role is reopened at once, the gain and
    /// the mute of its direction carried over, and
    /// `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` says `SIPRAL_AUDIO_CHANGE_SELECTED`
    /// from the engine. A device chosen and later unplugged is a preference:
    /// the role runs on the system's route meanwhile and goes back to the
    /// device when it returns.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_select(stack: SipralHandle, role: u32, device: u32) {
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
    /// What a role was asked to be on, and what it is running on: the id
    /// chosen with `sipral_audio_select` or zero for the system's route, and
    /// the id of the device the role is actually open on or zero when it is
    /// not open. The two differ while a chosen device is unplugged.
    ///
    /// # Safety
    ///
    /// Each out parameter must point at one `uint32_t` or be null.
    fn sipral_audio_selection(
        stack: SipralHandle,
        role: u32,
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
    /// Set the gain of one direction, as a fixed-point ratio with 256 for
    /// unity: 128 halves, 512 doubles, 0 is silence, and anything above 1024
    /// is taken as 1024. The input direction's gain is the microphone gain;
    /// the output's is the volume. Applied to the frames rather than to the
    /// operating system's own control, so a film playing beside the call is
    /// not turned down with it, and kept across every device change.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_set_gain(stack: SipralHandle, direction: u32, gain: u32) {
        let direction = direction_of(direction)?;
        let steps = u16::try_from(gain).unwrap_or(GAIN_MOST).min(GAIN_MOST);
        let ratio = f32::from(steps) / f32::from(GAIN_UNITY);
        with_engine(stack, |engine| {
            engine.set_gain(direction, Gain::from_ratio(ratio));
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
    fn sipral_audio_gain(stack: SipralHandle, direction: u32, out_gain: *mut u32) {
        if out_gain.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_gain is null"));
        }
        let direction = direction_of(direction)?;
        let gain = with_engine(stack, |engine| Ok(engine.gain(direction)))?;
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a ratio is between 0 and 4, so its steps are between 0 and 1024"
        )]
        let steps = (gain.ratio() * f32::from(GAIN_UNITY)).round() as u32;
        unsafe { out_gain.write(steps) };
        Ok(())
    }
}

entry! {
    /// Mute one direction, or unmute it, kept across every device change. A
    /// muted microphone still runs and sends silence, so the far end hears a
    /// stream rather than a gap.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_audio_set_muted(stack: SipralHandle, direction: u32, muted: u32) {
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
    fn sipral_audio_muted(stack: SipralHandle, direction: u32, out_muted: *mut u32) {
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
    /// The meter of one direction: the loudest sample of the last tenth of a
    /// second, 0 to 32767, held for between one window and two so that a
    /// bar drawn from it neither flickers nor sticks. Cheap enough to poll
    /// at a window's frame rate; zero while nothing is open.
    ///
    /// # Safety
    ///
    /// `out_peak` must point at one `uint32_t`.
    fn sipral_audio_level(stack: SipralHandle, direction: u32, out_peak: *mut u32) {
        if out_peak.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_peak is null"));
        }
        let direction = direction_of(direction)?;
        let peak = with_engine(stack, |engine| Ok(engine.level(direction).peak()))?;
        unsafe { out_peak.write(u32::from(peak)) };
        Ok(())
    }
}

entry! {
    /// Open the devices and start the pump now, whatever the calls are
    /// doing. Under `SIPRAL_AUDIO_ACTIVATION_MANUAL` this is the only thing
    /// that does; under automatic activation it opens them early.
    ///
    /// `SIPRAL_STATUS_DEVICE_UNUSABLE` or `SIPRAL_STATUS_DEVICE_TIMED_OUT`
    /// when a direction could not be opened: the engine is active all the
    /// same, silent in that direction, and `sipral_audio_info` says which.
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
    /// Play a ring tone on the ringer — the device `SIPRAL_AUDIO_ROLE_RINGER`
    /// is on, or the loudspeaker when it is on none of its own — until
    /// `sipral_audio_stop_ringing`, or once through when `looped` is zero.
    /// The tone is mono sixteen-bit samples at `sample_rate_hz`, copied, so
    /// the caller's buffer is its own again when this returns. Under
    /// automatic activation a ring opens the devices.
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
        sipral_audio_set_gain, sipral_audio_set_muted, sipral_audio_stop_ringing,
    };
    use crate::call::tests::{hangup, media_call_tuned};
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::SipralHandle;
    use crate::stack::tests::{Observed, config, create, poll, record};
    use crate::status::SipralStatus;
    use sipral_audio::Direction;
    use sipral_audio::fake::FakeControl;
    use std::ffi::{c_char, c_void};
    use std::ptr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// The packets the transmit callback was handed: which call, where to,
    /// and how many bytes.
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

    /// A platform with a headset and the machine's own devices, the
    /// built-in ones the defaults, delivering at 48 kHz.
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
    fn device_call(
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

    /// An audio call on another thread holds the engine for as long as the
    /// platform takes to answer about its devices. A poll that waited for it
    /// held the stack's lock all that while, so every signalling call on
    /// every other thread answered BUSY until the platform did; now the poll
    /// leaves the engine for the next one and says to come back soon.
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

    /// What `sipral_stack_destroy` answered from inside the transmit
    /// callback below.
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

    /// The pump holds no lock of the library's while it hands a packet over,
    /// so a destroy made from the transmit callback went through: it dropped
    /// the engine, and dropping the engine joins the pump, which is the thread
    /// making the call. It is refused now, like a processor's call into its
    /// own stack, and the stack is still there to destroy from elsewhere.
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

    /// The list: every device with its channels, and an id that survives a
    /// refresh and an unplug.
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

        // past the end is an argument that was wrong, and says how many
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
        // a name that does not fit is said so, and the length given with its
        // NUL counted, as every other text-out call counts it; nothing is
        // written, the struct included
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

    /// Selection: the three refusals, each with its own status, and the
    /// selection read back.
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

    /// The whole path: a managed call in device mode has its microphone fed
    /// from the fake platform, its packets handed to the transmit callback
    /// for the call's socket, and its playback on the loudspeaker.
    #[test]
    fn a_managed_call_is_pumped_and_its_packets_reach_the_callback() {
        let mut observed = Observed::default();
        let fake = a_desk();
        let (stack, call, packets) =
            device_call(&mut observed, &fake, SipralAudioActivation::Automatic);
        // the call came up with its media, so the engine is active already
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
        // the loudspeaker is written what the call plays, which with nothing
        // arriving is silence — but written, at the loudspeaker's rate
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

    /// A device pulled out from under a role reaches the application as an
    /// event from the system, and the engine's own reopening as one from
    /// the engine; the default moving under a role the application chose
    /// leaves it where it is.
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

    /// The numbers are written out rather than walked, because a test that
    /// derived them from the declaration would move with a declaration that
    /// moved.
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

    /// The event the poll raises carries the record the engine's event
    /// became, and nothing else.
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
