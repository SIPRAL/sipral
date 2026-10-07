// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One duplex voice-processing unit: samples in from the microphone, samples
//! out to the speaker, and nothing else.
//!
//! `kAudioUnitSubType_VoiceProcessingIO` brings the system echo canceller
//! (`docs/05-media.md`: attach one, do not write one), and on iOS it makes
//! the audio session behave like a call.
//!
//! One unit is not one device: on a Mac the built-in speaker and microphone
//! are separate objects with their own rates and delays, so the stream asks
//! the unit about each half.
//!
//! The realtime thread runs [`play`] and [`record`]; they share only the
//! rings and counters with the caller's thread, and neither waits.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::cell::UnsafeCell;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::{Arc, Mutex, PoisonError};

use crate::abi;
use crate::counters::Counters;
// choosing a device is a macOS notion; on iOS the route is the session's
#[cfg(target_os = "macos")]
use crate::device::{DeviceChoice, Direction};
use crate::device::{DeviceId, StreamEvent};
use crate::format::StreamFormat;
use crate::gate::{Gate, TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS};
#[cfg(target_os = "macos")]
use crate::latency::Latency;
use crate::latency::RenderDelay;
use crate::level::{Channel, Controls, window_samples};
use crate::ring::Ring;
use crate::status::{Error, OsStatus};
use crate::sys;

/// The most frames the unit is allowed to ask for at once.
///
/// It sizes the input buffer, so it is fixed up front. Apple advises this
/// value on iOS, where smaller ones fail with the screen locked.
///
/// On macOS VPIO adopts it as the microphone IO buffer (512 to 4,096 frames
/// on an Intel MacBook Pro, +81 ms at 44.1 kHz); [`Stream::render_delay`]
/// includes it.
const MAX_FRAMES_PER_SLICE: u32 = 4096;

/// A narrowband Bluetooth headset.
const SLOWEST_DEVICE_RATE_HZ: u32 = 8_000;

/// How many samples the input callback's buffer holds at `format`'s rate.
///
/// Not [`MAX_FRAMES_PER_SLICE`]: the limit is at the device rate and the
/// callback sees it converted (4,096 at 44.1 kHz became 4,458 at 48 kHz). So
/// this holds one slice of the slowest device at the stream rate; larger
/// requests are refused (see `Shared::record`).
fn capture_capacity(format: StreamFormat) -> usize {
    let slice = usize::try_from(MAX_FRAMES_PER_SLICE).unwrap_or(0);
    let ratio = format
        .sample_rate_hz()
        .div_ceil(SLOWEST_DEVICE_RATE_HZ)
        .max(1);
    slice.saturating_mul(usize::try_from(ratio).unwrap_or(1))
}

/// Enough for a scheduling hiccup; short enough that a stalled reader is a
/// gap, not a permanent delay.
const DEFAULT_DEPTH_FRAMES: usize = 16;

/// Which unit a stream is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamKind {
    /// The voice-processing unit: microphone and speaker with the system echo
    /// canceller. At most one per process ([`voice_units_open`]), created once
    /// and reused, because a new unit after a torn-down one was seen to read
    /// freed memory inside the framework.
    #[default]
    Voice,
    /// A plain output unit (HAL output on macOS, remote I/O on iOS): playback
    /// only, no claim on the voice unit, so it opens beside a call. Used for a
    /// ring on its own device. Reading delivers nothing.
    Playback,
}

/// What to open, and how much slack to leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// Rate and frame length. Both directions use it.
    pub format: StreamFormat,
    /// Which unit.
    pub kind: StreamKind,
    /// Which device the speaker is on, and what to do when it is not there.
    ///
    /// macOS only: on iOS the route is the audio session's, so the field is
    /// absent rather than silently ignored.
    #[cfg(target_os = "macos")]
    pub device: DeviceChoice,
    /// Which device the microphone is on, chosen apart from the speaker's
    /// and without touching the system's default input. macOS only, as
    /// `device`; ignored by a [`StreamKind::Playback`] stream.
    #[cfg(target_os = "macos")]
    pub capture_device: DeviceChoice,
    /// Frames of buffering between the device and the caller, per direction.
    pub depth_frames: usize,
    /// Whether the voice unit's processing (AEC, AGC, noise suppression)
    /// runs or is bypassed; on by default. [`StreamKind::Voice`] only; the
    /// unit and its process-wide claim are the same either way.
    pub voice_processing: bool,
}

impl StreamConfig {
    /// The system's current route, at the given format.
    #[must_use]
    pub const fn new(format: StreamFormat) -> Self {
        Self {
            format,
            kind: StreamKind::Voice,
            #[cfg(target_os = "macos")]
            device: DeviceChoice::System,
            #[cfg(target_os = "macos")]
            capture_device: DeviceChoice::System,
            depth_frames: DEFAULT_DEPTH_FRAMES,
            voice_processing: true,
        }
    }

    /// A stream that only plays, on the system's current output.
    #[must_use]
    pub fn playback(format: StreamFormat) -> Self {
        Self {
            kind: StreamKind::Playback,
            ..Self::new(format)
        }
    }

    /// The microphone on the device with this UID, or the default input
    /// when absent.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn capturing_from(self, uid: impl Into<String>) -> Self {
        Self {
            capture_device: DeviceChoice::Preferred(uid.into()),
            ..self
        }
    }

    /// The speaker on the device with this UID, or the system route when
    /// absent. The UID is [`Device::uid`](crate::Device::uid), the value to save.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn preferring(uid: impl Into<String>, format: StreamFormat) -> Self {
        Self {
            device: DeviceChoice::Preferred(uid.into()),
            ..Self::new(format)
        }
    }
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self::new(StreamFormat::narrowband())
    }
}

/// Room for one voice-processing unit.
///
/// One per process: a second unit was seen to block inside the framework,
/// and two microphones confuse the canceller. Taken before a unit is created
/// or taken from [`SPARE`], released once it is disposed of or spared; a
/// deliberately leaked stream keeps it.
struct Slot(AtomicBool);

/// The room held, for as long as this lives.
struct Claim(&'static Slot);

impl Slot {
    const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    fn take(&'static self) -> Option<Claim> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Claim(self))
    }

    fn held(&self) -> usize {
        usize::from(self.0.load(Ordering::Acquire))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.0.0.store(false, Ordering::Release);
    }
}

static VOICE_UNIT: Slot = Slot::new();

/// The voice-processing unit a closed voice stream left behind, uninitialised,
/// for the next one to configure again rather than create.
///
/// Creating a voice unit after an earlier one was torn down faulted on
/// macOS (guard allocator, `0xaaaaaaaaaaaaaaaa`) inside the framework's own
/// property listener, within ten rounds in half the runs. Teardown order and
/// delays made no difference; reusing one unit for a hundred rounds never
/// faulted. So a closing voice stream parks its unit here for the next.
///
/// Only a cleanly uninitialised unit is kept; one with a lost device, or
/// under [`Stream::recover`], is disposed of.
static SPARE: Spare = Spare::new();

/// Room for one unit put aside.
struct Spare(Mutex<Option<Kept>>);

/// A unit handle with a single owner at a time.
struct Kept(sys::Unit);

// SAFETY: the handle is moved, never shared: whoever takes it out of the
// `Spare` is the only one holding it, as the `Stream` that put it there was.
unsafe impl Send for Kept {}

impl Spare {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// Put `unit` aside, and hand back whatever was there before it.
    fn keep(&self, unit: sys::Unit) -> Option<sys::Unit> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(Kept(unit))
            .map(|kept| kept.0)
    }

    /// Take the unit put aside, if there is one.
    fn take(&self) -> Option<sys::Unit> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .map(|kept| kept.0)
    }
}

/// Whether a teardown parks the unit in [`SPARE`] instead of disposing of it.
fn spares(kind: StreamKind, lost: bool, allowed: bool, uninitialized: sys::Status) -> bool {
    kind == StreamKind::Voice && !lost && allowed && uninitialized == 0
}

/// A new instance of the unit `kind` names.
fn new_unit(kind: StreamKind) -> Result<sys::Unit, Error> {
    let wanted = abi::ComponentDescription {
        component_type: abi::UNIT_TYPE_OUTPUT,
        subtype: match kind {
            StreamKind::Voice => abi::UNIT_SUBTYPE_VOICE_PROCESSING,
            StreamKind::Playback => abi::UNIT_SUBTYPE_PLAIN_OUTPUT,
        },
        manufacturer: abi::MANUFACTURER_APPLE,
        flags: 0,
        flags_mask: 0,
    };
    // SAFETY: null asks for the first match; the description is a local the
    // call only reads.
    let component = unsafe { sys::find_component(ptr::null_mut(), &raw const wanted) };
    if component.is_null() {
        return Err(Error::UnitMissing);
    }
    let mut unit: sys::Unit = ptr::null_mut();
    // SAFETY: `unit` is a live out-parameter of the right type.
    sys::check("AudioComponentInstanceNew", unsafe {
        sys::open_component(component, &raw mut unit)
    })?;
    Ok(unit)
}

/// How many voice-processing units this process has open right now: zero or
/// one. A [`StreamKind::Voice`] stream opened while it is one is refused with
/// [`Error::Busy`]; a caller reopening one that is on its way down can wait
/// for this to read zero.
#[must_use]
pub fn voice_units_open() -> usize {
    VOICE_UNIT.held()
}

/// Realtime statistics. Relaxed: nothing depends on them, and a fence in the
/// callback is not worth a statistic.
#[derive(Default)]
struct Meters {
    captured: AtomicU64,
    capture_dropped: AtomicU64,
    played: AtomicU64,
    playback_starved: AtomicU64,
    render_failures: AtomicU64,
    capture_oversized: AtomicU64,
    panics: AtomicU64,
}

impl Meters {
    fn add(counter: &AtomicU64, amount: usize) {
        counter.fetch_add(u64::try_from(amount).unwrap_or(0), Ordering::Relaxed);
    }

    fn read(&self) -> Counters {
        Counters {
            captured: self.captured.load(Ordering::Relaxed),
            capture_dropped: self.capture_dropped.load(Ordering::Relaxed),
            played: self.played.load(Ordering::Relaxed),
            playback_starved: self.playback_starved.load(Ordering::Relaxed),
            render_failures: self.render_failures.load(Ordering::Relaxed),
            capture_oversized: self.capture_oversized.load(Ordering::Relaxed),
            panics: self.panics.load(Ordering::Relaxed),
        }
    }
}

/// Everything both threads touch. Allocated once, before the unit is told
/// where to find it, and freed only once the gate says no callback is in it.
struct Shared {
    unit: sys::Unit,
    /// Closed at the start of teardown and drained before anything is freed.
    gate: Gate,
    capture: Ring,
    playback: Ring,
    /// The largest output request so far, which the writer must keep queued.
    burst: AtomicUsize,
    /// The input callback's render target. The framework never runs two
    /// input callbacks at once for a unit.
    scratch: UnsafeCell<Box<[i16]>>,
    meters: Meters,
    /// In their own `Arc` so a [`Controls`] survives a reopen.
    microphone: Arc<Channel>,
    speaker: Arc<Channel>,
}

// SAFETY: every field is either an atomic, a ring built out of atomics, or
// touched by exactly one thread. `unit` is a handle written once before the
// callbacks are installed and only read afterwards, and `scratch` is reached
// only from the input callback, which the framework never runs twice at once
// for one unit.
unsafe impl Sync for Shared {}
// SAFETY: as above; nothing in here is tied to the thread that built it.
unsafe impl Send for Shared {}

impl Shared {
    fn new(
        unit: sys::Unit,
        format: StreamFormat,
        depth_frames: usize,
        microphone: Arc<Channel>,
        speaker: Arc<Channel>,
    ) -> Self {
        // At least one slowest-device slice plus two frames: a narrowband
        // headset hands a 48 kHz stream half a second at once, and a smaller
        // ring drops or starves on every callback.
        let frame = format.frame_samples();
        let samples = frame
            .saturating_mul(depth_frames.max(2))
            .max(capture_capacity(format).saturating_add(frame.saturating_mul(2)));
        let window = window_samples(format.sample_rate_hz());
        microphone.set_window(window);
        speaker.set_window(window);
        Self {
            unit,
            gate: Gate::new(),
            capture: Ring::new(samples),
            playback: Ring::new(samples),
            burst: AtomicUsize::new(0),
            scratch: UnsafeCell::new(vec![0; capture_capacity(format)].into_boxed_slice()),
            meters: Meters::default(),
            microphone,
            speaker,
        }
    }

    /// Fill the unit's buffer from the playback ring. Realtime thread.
    ///
    /// Returns whether the silence flag may be set: only when every buffer
    /// was zeroed, as the header requires.
    ///
    /// # Safety
    /// As [`silence`].
    unsafe fn play(&self, frames: u32, buffers: *mut abi::BufferList) -> bool {
        // SAFETY: the caller's pointer, checked for null by `as_mut`.
        let Some(list) = (unsafe { buffers.as_mut() }) else {
            // SAFETY: as above; null is handled inside.
            return unsafe { silence(buffers) };
        };
        // mono interleaved: exactly one buffer, or not our format
        let Some(buffer) = list.buffers.first_mut() else {
            // SAFETY: the caller's list.
            return unsafe { silence(buffers) };
        };
        if list.count != 1 || buffer.data.is_null() {
            // SAFETY: the caller's list, walked by its own count.
            return unsafe { silence(buffers) };
        }
        let room = usize::try_from(buffer.byte_size).unwrap_or(0) / 2;
        let wanted = usize::try_from(frames).unwrap_or(0).min(room);
        if wanted == 0 {
            // SAFETY: the caller's list.
            return unsafe { silence(buffers) };
        }
        self.burst.fetch_max(wanted, Ordering::Relaxed);
        // SAFETY: `wanted` samples fit in the octets the buffer declares, and
        // the unit hands over memory aligned for the format it was given.
        let out = unsafe { core::slice::from_raw_parts_mut(buffer.data.cast::<i16>(), wanted) };
        let taken = self.playback.read(out);
        // applied here so a mute is heard at once; `wanted` so starved
        // silence still advances the meter window
        if let Some(played) = out.get_mut(..taken) {
            self.speaker.apply(played, wanted);
        }
        if let Some(tail) = out.get_mut(taken..) {
            tail.fill(0);
        }
        Meters::add(&self.meters.played, taken);
        Meters::add(&self.meters.playback_starved, wanted - taken);
        if taken > 0 {
            return false;
        }
        // the buffer may be larger than what was zeroed above
        // SAFETY: the caller's list, and `out` is not used past this point.
        unsafe { silence(buffers) }
    }

    /// Pull what the microphone heard and put it in the capture ring.
    /// Realtime thread.
    ///
    /// # Safety
    /// `flags` and `time` are the framework's, and are handed straight back to
    /// `AudioUnitRender` as it requires.
    unsafe fn record(&self, flags: *mut u32, time: *const abi::TimeStamp, bus: u32, frames: u32) {
        // SAFETY: the input callback is not re-entered for a unit, so this is
        // the only live reference to the scratch buffer.
        let scratch = unsafe { &mut *self.scratch.get() };
        let wanted = usize::try_from(frames).unwrap_or(usize::MAX);
        if wanted == 0 {
            return;
        }
        // Render exactly `frames` or nothing: asking VPIO for fewer was seen
        // to make it write past its own buffers.
        if wanted > scratch.len() {
            Meters::add(&self.meters.capture_oversized, 1);
            return;
        }
        let Ok(byte_size) = u32::try_from(wanted * 2) else {
            return;
        };
        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size,
                data: scratch.as_mut_ptr().cast::<c_void>(),
            }],
        };
        // SAFETY: the unit is open for as long as this callback can run, and
        // the buffer list points at memory owned by this crate and big enough
        // for what is being asked for.
        let status = unsafe {
            sys::render_unit(
                self.unit,
                flags,
                time,
                bus,
                u32::try_from(wanted).unwrap_or(0),
                &raw mut list,
            )
        };
        if status != 0 {
            Meters::add(&self.meters.render_failures, 1);
            return;
        }
        let delivered = list
            .buffers
            .first()
            .map_or(0, |buffer| {
                usize::try_from(buffer.byte_size).unwrap_or(0) / 2
            })
            .min(wanted);
        let Some(samples) = scratch.get_mut(..delivered) else {
            return;
        };
        self.captured(samples);
    }

    /// Gain, meter and ring for captured samples; split out so it can be
    /// tested without a device.
    fn captured(&self, samples: &mut [i16]) {
        let delivered = samples.len();
        // a muted microphone still delivers silence, so nothing piles up
        self.microphone.apply(samples, delivered);
        let stored = self.capture.write(samples);
        Meters::add(&self.meters.captured, stored);
        Meters::add(&self.meters.capture_dropped, delivered - stored);
    }
}

/// Set the silence flag on the way out of a render callback.
///
/// # Safety
/// `flags` is the framework's pointer, which may be null.
unsafe fn mark_silent(flags: *mut u32) {
    // SAFETY: checked for null; the framework owns a live `UInt32` otherwise.
    if let Some(flags) = unsafe { flags.as_mut() } {
        *flags |= abi::RENDER_ACTION_OUTPUT_IS_SILENCE;
    }
}

/// Zero every buffer and return whether all were zeroed (the condition for
/// the silence flag).
///
/// Walked by count and offset, since a multi-buffer list is longer than the
/// declared struct. Octets behind a null pointer make the answer `false`.
/// Cannot panic, so the panic path can use it.
///
/// # Safety
/// `buffers` is whatever the framework passed, so it may be null; when it is
/// not, it is an `AudioBufferList` whose `count` buffers lie end to end from
/// [`abi::BUFFERS_AT`], each describing `byte_size` octets that this callback
/// owns for the length of the call, or a null pointer.
unsafe fn silence(buffers: *mut abi::BufferList) -> bool {
    if buffers.is_null() {
        return true;
    }
    // SAFETY: not null, and the count is the list's first field.
    let count = unsafe { (*buffers).count };
    let mut zeroed = true;
    for index in 0..usize::try_from(count).unwrap_or(0) {
        let Some(offset) = index
            .checked_mul(size_of::<abi::Buffer>())
            .and_then(|at| at.checked_add(abi::BUFFERS_AT))
        else {
            return false;
        };
        // SAFETY: the list carries `count` buffers from `BUFFERS_AT` on, so
        // this one is inside it, and a list aligned for its pointer field is
        // aligned for every buffer in it.
        let buffer = unsafe { ptr::read(buffers.byte_add(offset).cast::<abi::Buffer>()) };
        if buffer.data.is_null() {
            zeroed &= buffer.byte_size == 0;
            continue;
        }
        let bytes = usize::try_from(buffer.byte_size).unwrap_or(0);
        // SAFETY: the buffer declares that many octets and nothing else is
        // reading them while this callback runs.
        unsafe { ptr::write_bytes(buffer.data.cast::<u8>(), 0, bytes) };
    }
    zeroed
}

/// The render callback the unit calls when it wants something to play.
///
/// A panic must not cross into C (`docs/08-ffi.md`): it is caught, counted
/// and played as silence.
unsafe extern "C" fn play(
    context: *mut c_void,
    flags: *mut u32,
    _time: *const abi::TimeStamp,
    _bus: u32,
    frames: u32,
    buffers: *mut abi::BufferList,
) -> sys::Status {
    // SAFETY: the context is the pointer handed to the unit at open time, and
    // teardown does not free what is behind it until the gate below is empty.
    let Some(shared) = (unsafe { context.cast::<Shared>().as_ref() }) else {
        return 0;
    };
    let Some(_inside) = shared.gate.enter() else {
        // teardown has begun: play silence and touch nothing it may be about
        // to take away
        // SAFETY: the framework's buffers, not ours; checked for null inside.
        if unsafe { silence(buffers) } {
            // SAFETY: as above.
            unsafe { mark_silent(flags) };
        }
        return 0;
    };

    let outcome = panic::catch_unwind(AssertUnwindSafe(|| unsafe { shared.play(frames, buffers) }));
    let silent = outcome.unwrap_or_else(|_| {
        Meters::add(&shared.meters.panics, 1);
        // SAFETY: as in `play`; nothing here can panic a second time.
        unsafe { silence(buffers) }
    });
    if silent {
        // SAFETY: the framework's pointer, checked inside.
        unsafe { mark_silent(flags) };
    }
    0
}

/// The callback the unit calls when the microphone has something.
unsafe extern "C" fn record(
    context: *mut c_void,
    flags: *mut u32,
    time: *const abi::TimeStamp,
    bus: u32,
    frames: u32,
    _buffers: *mut abi::BufferList,
) -> sys::Status {
    // SAFETY: as in `play`.
    let Some(shared) = (unsafe { context.cast::<Shared>().as_ref() }) else {
        return 0;
    };
    // teardown has begun: do not render from a unit being taken down
    let Some(_inside) = shared.gate.enter() else {
        return 0;
    };

    if panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        shared.record(flags, time, bus, frames);
    }))
    .is_err()
    {
        Meters::add(&shared.meters.panics, 1);
    }
    0
}

/// An open duplex stream.
///
/// Dropping it shuts the device down and waits for the callbacks to leave
/// its memory; [`Stream::close`] does the same and reports statuses.
pub struct Stream {
    unit: sys::Unit,
    shared: Arc<Shared>,
    format: StreamFormat,
    /// Re-resolved by [`Stream::recover`].
    config: StreamConfig,
    /// Also held here so a reopen keeps volume and mute.
    microphone: Arc<Channel>,
    speaker: Arc<Channel>,
    /// Read once at open: later the device may be gone, which is exactly
    /// when it is wanted. Empty on iOS.
    route: Route,
    /// Read at open, for the same reason.
    delay: RenderDelay,
    health: Health,
    closed: bool,
    /// Teardown could not prove the callbacks left; nothing is ever freed.
    leak: bool,
    /// The voice-unit slot, held until the unit is disposed of or spared.
    claim: Option<Claim>,
    /// Whether teardown may park a voice unit in [`SPARE`].
    spare: bool,
}

/// The device under each half; on a Mac usually two objects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Route {
    playback: Option<DeviceId>,
    capture: Option<DeviceId>,
}

/// `Lost` persists until [`Stream::recover`], so the loss is reported once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Health {
    /// Open, and not started.
    Stopped,
    /// Started, and the device is taking and giving frames.
    Running,
    /// The device has gone.
    Lost,
}

// SAFETY: the unit handle belongs to this `Stream` alone, every method that
// touches it takes `&mut self`, and the framework accepts its control calls
// from any thread as long as they do not overlap.
unsafe impl Send for Stream {}

impl Stream {
    /// Open the device, without starting it.
    ///
    /// One [`StreamKind::Voice`] stream per process: a second voice unit was
    /// seen to block in the framework, so it is refused instead. A
    /// [`StreamKind::Playback`] stream opens beside it.
    ///
    /// # Errors
    /// [`Error::Busy`] for a second voice-processing unit,
    /// [`Error::UnitMissing`] when the system has no unit of the kind asked
    /// for, and [`Error::Call`] naming whichever framework call refused: a
    /// device that is gone, a format it will not take, a microphone the user
    /// has not granted.
    pub fn open(config: StreamConfig) -> Result<Self, Error> {
        let window = window_samples(config.format.sample_rate_hz());
        Self::open_with(
            config,
            Arc::new(Channel::new(window)),
            Arc::new(Channel::new(window)),
        )
    }

    /// The same, on existing controls, so a reopen keeps volume and mute.
    fn open_with(
        config: StreamConfig,
        microphone: Arc<Channel>,
        speaker: Arc<Channel>,
    ) -> Result<Self, Error> {
        // claimed before the unit exists, so concurrent opens cannot both win
        let claim = match config.kind {
            StreamKind::Voice => Some(VOICE_UNIT.take().ok_or(Error::Busy)?),
            StreamKind::Playback => None,
        };
        let spare = match config.kind {
            StreamKind::Voice => SPARE.take(),
            StreamKind::Playback => None,
        };
        let unit = match spare {
            Some(unit) => unit,
            None => new_unit(config.kind)?,
        };

        // Owned by a `Stream` before configuring: configuration can fail after
        // the callbacks are installed, and then the normal teardown (shut,
        // stop, drain, dispose) must run.
        let mut stream = Self {
            unit,
            shared: Arc::new(Shared::new(
                unit,
                config.format,
                config.depth_frames,
                Arc::clone(&microphone),
                Arc::clone(&speaker),
            )),
            format: config.format,
            config,
            microphone,
            speaker,
            route: Route::default(),
            delay: RenderDelay::default(),
            health: Health::Stopped,
            closed: false,
            leak: false,
            claim,
            spare: true,
        };
        if let Err(error) = configure(unit, &stream.config, &stream.shared) {
            if spare.is_none() {
                return Err(error);
            }
            // a spared unit may have gone bad (media services reset): retry
            // once on a fresh unit
            let config = stream.config.clone();
            let (microphone, speaker) =
                (Arc::clone(&stream.microphone), Arc::clone(&stream.speaker));
            stream.spare = false;
            if let Err(error @ Error::Draining { .. }) = stream.teardown() {
                return Err(error);
            }
            drop(stream);
            return Self::open_with(config, microphone, speaker);
        }
        stream.route = route_of(unit);
        if stream.config.kind == StreamKind::Playback {
            stream.route.capture = None;
        }
        stream.delay = stream.current_delay();
        Ok(stream)
    }

    /// Each half's delay, at its own device's rate.
    #[cfg(target_os = "macos")]
    fn current_delay(&self) -> RenderDelay {
        let leg = |device: Option<DeviceId>, direction| {
            device.map_or_else(Latency::default, |device| {
                crate::hal::latency(device, direction)
            })
        };
        RenderDelay {
            playback: leg(self.route.playback, Direction::Output),
            capture: leg(self.route.capture, Direction::Input),
        }
    }

    /// On iOS the figures are `AVAudioSession`'s, for the application to read.
    #[cfg(target_os = "ios")]
    #[expect(
        clippy::unused_self,
        reason = "the answer is the platform's rather than this stream's, and staying a method keeps the caller free of a cfg"
    )]
    fn current_delay(&self) -> RenderDelay {
        RenderDelay::default()
    }

    /// Whether both devices the stream opened on are still attached.
    ///
    /// Losing either half is losing the stream; on a Mac they are usually
    /// different objects.
    #[cfg(target_os = "macos")]
    fn device_present(&self) -> bool {
        [self.route.playback, self.route.capture]
            .into_iter()
            .flatten()
            .all(crate::hal::is_alive)
    }

    /// Whether the unit still runs. Interruptions stop it and a media
    /// services reset leaves it unresponsive; the session events themselves
    /// go to the application.
    #[cfg(target_os = "ios")]
    fn device_present(&self) -> bool {
        unit_still_running(get::<u32>(
            self.unit,
            "AudioUnitGetProperty",
            abi::PROPERTY_IS_RUNNING,
            abi::SCOPE_GLOBAL,
            0,
        ))
    }

    /// What the stream was opened at.
    #[must_use]
    pub const fn format(&self) -> StreamFormat {
        self.format
    }

    /// Time from [`Playback::write`] through the room back to
    /// [`Capture::read`]: what an echo canceller looks back by. Covers both
    /// halves (the WASAPI equivalent is per endpoint), each at its device's
    /// rate.
    ///
    /// Read once at open; [`Stream::recover`] reads it again. Zero on iOS
    /// and for a device that reports nothing; [`Stream::render_delay`] gives
    /// the parts.
    #[must_use]
    pub fn latency(&self) -> Duration {
        self.delay.total()
    }

    /// The same delay, part by part and direction by direction.
    ///
    /// If a part is missing the total is only a floor; see
    /// [`RenderDelay::is_complete`].
    #[must_use]
    pub const fn render_delay(&self) -> RenderDelay {
        self.delay
    }

    /// Whether the device is running.
    ///
    /// Goes false on its own when the device is lost; [`Stream::poll`] is what
    /// says that is why.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self.health, Health::Running)
    }

    /// Start the device. Frames begin arriving immediately, so whatever is
    /// going to read them should be ready.
    ///
    /// # Errors
    /// [`Error::Call`] from `AudioOutputUnitStart`.
    pub fn start(&mut self) -> Result<(), Error> {
        if self.is_running() {
            return Ok(());
        }
        // SAFETY: the unit is open and initialised.
        sys::check("AudioOutputUnitStart", unsafe {
            sys::start_unit(self.unit)
        })?;
        self.health = Health::Running;
        Ok(())
    }

    /// Stop the device. What is already in the rings stays there.
    ///
    /// # Errors
    /// [`Error::Call`] from `AudioOutputUnitStop`.
    pub fn stop(&mut self) -> Result<(), Error> {
        if !self.is_running() {
            return Ok(());
        }
        // SAFETY: the unit is open and running.
        sys::check("AudioOutputUnitStop", unsafe { sys::stop_unit(self.unit) })?;
        self.health = Health::Stopped;
        // stop is synchronous here; reset meters so they do not look live
        self.microphone.quiet();
        self.speaker.quiet();
        Ok(())
    }

    /// What the device has been doing since it opened.
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.shared.meters.read()
    }

    /// The microphone's volume, mute and meter.
    ///
    /// A handle for the UI thread, independent of [`Stream::split`]'s
    /// borrow. It survives [`Stream::recover`].
    #[must_use]
    pub fn capture_controls(&self) -> Controls {
        Controls::new(&self.microphone)
    }

    /// The speaker's, as [`Stream::capture_controls`].
    #[must_use]
    pub fn playback_controls(&self) -> Controls {
        Controls::new(&self.speaker)
    }

    /// Ask whether the device underneath is still there, and say so once when
    /// it is not.
    ///
    /// On macOS each half's device is checked for being alive, so an unplug
    /// is caught even when idle. On iOS the unit is checked for running: an
    /// `AVAudioSession` interruption or a media services reset reads as a
    /// loss, while a route change is not one. [`Stream::recover`] builds a new
    /// unit; during an interruption it fails until the session is active.
    ///
    /// After [`StreamEvent::DeviceLost`] the stream is stopped: captured
    /// samples can still be read, nothing more arrives.
    ///
    /// Costs one or two property reads; poll a few times a second, not per
    /// UI frame. After the loss it returns `None` cheaply.
    pub fn poll(&mut self) -> Option<StreamEvent> {
        if !self.is_running() || self.device_present() {
            return None;
        }
        self.declare_lost();
        Some(StreamEvent::DeviceLost)
    }

    /// Stop, on a device that is not there to be stopped.
    fn declare_lost(&mut self) {
        // SAFETY: the unit is ours and still open. What it makes of being
        // stopped on a device that has gone is not news: the device has gone.
        let _ = unsafe { sys::stop_unit(self.unit) };
        self.health = Health::Lost;
        self.microphone.quiet();
        self.speaker.quiet();
    }

    /// Open again, on whatever the stream's [`StreamConfig`] names now.
    ///
    /// The answer to [`StreamEvent::DeviceLost`].
    /// [`DeviceChoice::Preferred`](crate::DeviceChoice::Preferred) falls back
    /// to the system route; [`DeviceChoice::Device`](crate::DeviceChoice::Device)
    /// fails if that device is gone.
    ///
    /// Gain, mute and existing [`Controls`] carry over; ring contents do not.
    /// A running stream is restarted.
    ///
    /// # Errors
    /// [`Error::Draining`] when the old stream could not be shut down; then
    /// nothing is reopened, since a second unit beside a wedged one hangs the
    /// process. Otherwise what [`Stream::open`] would say.
    pub fn recover(mut self) -> Result<Self, Error> {
        let config = self.config.clone();
        let microphone = Arc::clone(&self.microphone);
        let speaker = Arc::clone(&self.speaker);
        // `Lost` is only reached from `Running`
        let running = !matches!(self.health, Health::Stopped);
        // Teardown errors on a lost device are expected; only a failed drain
        // stops recovery. Always a fresh unit: after a media services reset
        // the old one no longer answers.
        self.spare = false;
        if let Err(error @ Error::Draining { .. }) = self.teardown() {
            return Err(error);
        }
        drop(self);

        let mut stream = Self::open_with(config, microphone, speaker)?;
        if running {
            stream.start()?;
        }
        Ok(stream)
    }

    /// Which device the speaker half of the stream actually landed on.
    ///
    /// Useful after [`DeviceEvent::DefaultChanged`] for a stream following
    /// the system route. The microphone half is [`Stream::capture_device`].
    ///
    /// [`DeviceEvent::DefaultChanged`]: crate::DeviceEvent::DefaultChanged
    ///
    /// # Errors
    /// [`Error::Call`] from `AudioUnitGetProperty`.
    #[cfg(target_os = "macos")]
    pub fn device(&self) -> Result<DeviceId, Error> {
        device_on(self.unit, abi::BUS_OUTPUT)
    }

    /// Which device the microphone half of the stream actually landed on, as
    /// [`Stream::device`] is for the speaker.
    ///
    /// # Errors
    /// [`Error::Call`] from `AudioUnitGetProperty`.
    #[cfg(target_os = "macos")]
    pub fn capture_device(&self) -> Result<DeviceId, Error> {
        device_on(self.unit, abi::BUS_INPUT)
    }

    /// The two directions, so that a capture thread and a playback thread can
    /// each have one.
    ///
    /// They borrow the stream, so no second pair can exist: the rings
    /// require one producer and one consumer.
    pub fn split(&mut self) -> (Capture<'_>, Playback<'_>) {
        let shared: &Shared = &self.shared;
        (Capture { shared }, Playback { shared })
    }

    /// Take one frame from the microphone, or say there is not a whole one
    /// yet. Convenience for a caller doing both directions on one thread.
    pub fn read(&mut self, frame: &mut [i16]) -> bool {
        self.shared.capture.read_frame(frame)
    }

    /// Queue one frame for the speaker, or say there is no room. Convenience,
    /// as [`Stream::read`].
    pub fn write(&mut self, frame: &[i16]) -> bool {
        self.shared.playback.write_frame(frame)
    }

    /// Shut the device down and say what the framework made of it.
    ///
    /// Same as dropping, but the statuses are returned.
    ///
    /// # Errors
    /// [`Error::Draining`] when the callbacks did not leave within two
    /// seconds; the memory and unit are then deliberately leaked. Otherwise
    /// [`Error::Call`] for the first of stop, uninitialise, dispose to fail;
    /// all are attempted, except that a cleanly stopped voice unit is kept
    /// for reuse (`SPARE` in the source).
    pub fn close(mut self) -> Result<(), Error> {
        self.teardown()
    }

    /// The shutdown sequence, safe to call twice.
    ///
    /// 1. close the gate, so new callbacks turn back;
    /// 2. stop the unit (synchronous off the I/O thread), so none begin;
    /// 3. drain the gate, for callbacks already inside;
    /// 4. only then uninitialise and dispose (or spare, [`SPARE`]).
    ///
    /// If step 3 fails the stream is marked to leak and nothing is freed.
    fn teardown(&mut self) -> Result<(), Error> {
        self.shut_down(TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS)
    }

    /// With an explicit deadline, for tests.
    fn shut_down(&mut self, within: Duration, millis: u64) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let lost = self.health == Health::Lost;
        self.health = Health::Stopped;

        self.shared.gate.close();
        // SAFETY: the unit is ours and still open; this call is not on the
        // I/O thread, because the I/O thread never drops a `Stream`.
        let stopped = unsafe { sys::stop_unit(self.unit) };

        if !self.shared.gate.drained(within) {
            self.leak = true;
            return Err(Error::Draining {
                waited_millis: millis,
            });
        }

        // SAFETY: no callback is inside and none can start, so nothing is
        // reading the unit or anything reachable from it.
        let uninitialized = unsafe { sys::uninitialize_unit(self.unit) };
        let disposed = if spares(self.config.kind, lost, self.spare, uninitialized) {
            // The stale callbacks point into `shared`, which is freed; the
            // next stream installs its own before initialising, and an
            // uninitialised unit calls none.
            match SPARE.keep(self.unit) {
                // SAFETY: as above, and nothing else holds it.
                Some(other) => unsafe { sys::dispose_component(other) },
                None => 0,
            }
        } else {
            // SAFETY: as above.
            unsafe { sys::dispose_component(self.unit) }
        };
        self.claim = None;

        sys::check("AudioOutputUnitStop", stopped)?;
        sys::check("AudioUnitUninitialize", uninitialized)?;
        sys::check("AudioComponentInstanceDispose", disposed)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let _ = self.teardown();
        if self.leak {
            // a realtime thread may still read this: leak rather than crash
            core::mem::forget(Arc::clone(&self.shared));
            // the undisposed unit still occupies the voice slot
            core::mem::forget(self.claim.take());
        }
    }
}

/// The microphone end of a stream.
pub struct Capture<'a> {
    shared: &'a Shared,
}

impl Capture<'_> {
    /// Fill `frame` from the microphone, or leave it untouched and say `false`
    /// because a whole frame is not there yet.
    pub fn read(&mut self, frame: &mut [i16]) -> bool {
        self.shared.capture.read_frame(frame)
    }

    /// Samples waiting. A growing number means the reader is falling behind.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.shared.capture.filled()
    }
}

/// The speaker end of a stream.
pub struct Playback<'a> {
    shared: &'a Shared,
}

impl Playback<'_> {
    /// Queue `frame` for the speaker, or say `false` because there is no room
    /// for a whole one. Nothing is queued in that case.
    pub fn write(&mut self, frame: &[i16]) -> bool {
        self.shared.playback.write_frame(frame)
    }

    /// Samples that would fit right now.
    #[must_use]
    pub fn room(&self) -> usize {
        self.shared.playback.free()
    }

    /// Samples queued and not yet taken by the device.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.shared
            .playback
            .capacity()
            .saturating_sub(self.shared.playback.free())
    }

    /// The largest single pull so far, at the stream's rate (up to half a
    /// second for a narrowband headset). Keep at least this much queued.
    #[must_use]
    pub fn burst(&self) -> usize {
        self.shared.burst.load(Ordering::Relaxed)
    }
}

/// Everything between opening the instance and initialising it.
///
/// Order matters: enable I/O, name devices, set formats, then initialise.
fn configure(unit: sys::Unit, config: &StreamConfig, shared: &Arc<Shared>) -> Result<(), Error> {
    let voice = config.kind == StreamKind::Voice;
    // input off for playback, so no microphone permission is needed
    let capture_enabled = u32::from(voice);
    let enabled: u32 = 1;
    set(
        unit,
        "AudioUnitSetProperty (EnableIO, input)",
        abi::PROPERTY_ENABLE_IO,
        abi::SCOPE_INPUT,
        abi::BUS_INPUT,
        &capture_enabled,
    )?;
    set(
        unit,
        "AudioUnitSetProperty (EnableIO, output)",
        abi::PROPERTY_ENABLE_IO,
        abi::SCOPE_OUTPUT,
        abi::BUS_OUTPUT,
        &enabled,
    )?;

    #[cfg(target_os = "macos")]
    name_devices(unit, config, voice)?;

    if voice && !config.voice_processing {
        let bypassed: u32 = 1;
        set(
            unit,
            "AudioUnitSetProperty (BypassVoiceProcessing)",
            abi::PROPERTY_BYPASS_VOICE_PROCESSING,
            abi::SCOPE_GLOBAL,
            0,
            &bypassed,
        )?;
    }

    set(
        unit,
        "AudioUnitSetProperty (MaximumFramesPerSlice)",
        abi::PROPERTY_MAXIMUM_FRAMES_PER_SLICE,
        abi::SCOPE_GLOBAL,
        0,
        &MAX_FRAMES_PER_SLICE,
    )?;
    formats_and_callbacks(unit, config, shared, voice)
}

/// Settable only while uninitialised, hence `Stream::recover` reopens.
/// Element 0 is the speaker, 1 the microphone; naming 0 leaves 1 on the
/// default input, so each is set separately and read back after init.
#[cfg(target_os = "macos")]
fn name_devices(unit: sys::Unit, config: &StreamConfig, voice: bool) -> Result<(), Error> {
    {
        let halves: &[(&DeviceChoice, u32, &'static str)] = if voice {
            &[
                (
                    &config.device,
                    abi::BUS_OUTPUT,
                    "AudioUnitSetProperty (CurrentDevice, speaker)",
                ),
                (
                    &config.capture_device,
                    abi::BUS_INPUT,
                    "AudioUnitSetProperty (CurrentDevice, microphone)",
                ),
            ]
        } else {
            &[(
                &config.device,
                abi::BUS_OUTPUT,
                "AudioUnitSetProperty (CurrentDevice, speaker)",
            )]
        };
        for &(choice, element, call) in halves {
            if let Some(device) = crate::hal::choose(choice)? {
                let id = device.get();
                set(
                    unit,
                    call,
                    abi::PROPERTY_CURRENT_DEVICE,
                    abi::SCOPE_GLOBAL,
                    element,
                    &id,
                )?;
            }
        }
    }
    Ok(())
}

/// The formats, the callbacks, the initialisation, and the format read back.
fn formats_and_callbacks(
    unit: sys::Unit,
    config: &StreamConfig,
    shared: &Arc<Shared>,
    voice: bool,
) -> Result<(), Error> {
    // The scopes read the way the unit sees them, not the way we do: what the
    // caller reads off bus 1 is that bus's output, and what the caller writes
    // to bus 0 is that bus's input.
    let description = abi::StreamDescription::mono_pcm(config.format.sample_rate_hz());
    if voice {
        set(
            unit,
            "AudioUnitSetProperty (StreamFormat, capture)",
            abi::PROPERTY_STREAM_FORMAT,
            abi::SCOPE_OUTPUT,
            abi::BUS_INPUT,
            &description,
        )?;
    }
    set(
        unit,
        "AudioUnitSetProperty (StreamFormat, playback)",
        abi::PROPERTY_STREAM_FORMAT,
        abi::SCOPE_INPUT,
        abi::BUS_OUTPUT,
        &description,
    )?;

    let context = Arc::as_ptr(shared).cast::<c_void>().cast_mut();
    set(
        unit,
        "AudioUnitSetProperty (SetRenderCallback)",
        abi::PROPERTY_SET_RENDER_CALLBACK,
        abi::SCOPE_INPUT,
        abi::BUS_OUTPUT,
        &sys::RenderCallback {
            procedure: play,
            context,
        },
    )?;
    if voice {
        set(
            unit,
            "AudioUnitSetProperty (SetInputCallback)",
            abi::PROPERTY_SET_INPUT_CALLBACK,
            abi::SCOPE_GLOBAL,
            0,
            &sys::RenderCallback {
                procedure: record,
                context,
            },
        )?;
    }

    // SAFETY: the unit is open and fully described.
    sys::check("AudioUnitInitialize", unsafe { sys::initialize_unit(unit) })?;

    // Read the format back: a unit that silently picked another one would
    // sound wrong instead of failing. `record` sizes its render by the
    // capture side; a playback unit has only the other.
    let (scope, bus) = if voice {
        (abi::SCOPE_OUTPUT, abi::BUS_INPUT)
    } else {
        (abi::SCOPE_INPUT, abi::BUS_OUTPUT)
    };
    let settled: abi::StreamDescription = get(
        unit,
        "AudioUnitGetProperty (StreamFormat)",
        abi::PROPERTY_STREAM_FORMAT,
        scope,
        bus,
    )?;
    let same_rate = (settled.sample_rate - description.sample_rate).abs() < 0.5;
    if !same_rate
        || settled.format_id != description.format_id
        || settled.channels_per_frame != description.channels_per_frame
        || settled.bits_per_channel != description.bits_per_channel
        || settled.bytes_per_frame != description.bytes_per_frame
    {
        return Err(Error::Call {
            call: "AudioUnitGetProperty (StreamFormat)",
            status: OsStatus::new(abi::FORMAT_NOT_SUPPORTED),
        });
    }
    Ok(())
}

/// The device of one element (0 speaker, 1 microphone). The header does not
/// define the elements; VPIO answers with the default output on 0 and the
/// default input on 1, which this relies on.
#[cfg(target_os = "macos")]
fn device_on(unit: sys::Unit, element: u32) -> Result<DeviceId, Error> {
    let id: u32 = get(
        unit,
        "AudioUnitGetProperty (CurrentDevice)",
        abi::PROPERTY_CURRENT_DEVICE,
        abi::SCOPE_GLOBAL,
        element,
    )?;
    Ok(DeviceId::new(id))
}

/// Both halves' devices, where the unit names one. Zero is
/// `kAudioObjectUnknown`, which names nothing and is not a device to watch.
#[cfg(target_os = "macos")]
fn route_of(unit: sys::Unit) -> Route {
    let on = |element| {
        device_on(unit, element)
            .ok()
            .filter(|device| device.get() != 0)
    };
    Route {
        playback: on(abi::BUS_OUTPUT),
        capture: on(abi::BUS_INPUT),
    }
}

/// Running only on a non-zero `IsRunning`; a failed read (media services
/// reset) counts as not running.
#[cfg(any(target_os = "ios", test))]
fn unit_still_running(answer: Result<u32, Error>) -> bool {
    matches!(answer, Ok(running) if running != 0)
}

/// On iOS the route is the audio session's, and there is no device identifier
/// to be had from the unit.
#[cfg(target_os = "ios")]
fn route_of(_unit: sys::Unit) -> Route {
    Route::default()
}

/// Read a property back, and insist it came back the size it was asked for.
fn get<T: Copy + Default>(
    unit: sys::Unit,
    call: &'static str,
    property: u32,
    scope: u32,
    element: u32,
) -> Result<T, Error> {
    let mut value = T::default();
    let mut size = u32::try_from(size_of::<T>()).unwrap_or(0);
    // SAFETY: the out-parameter is a live `T` and `size` says how big it is.
    let status = unsafe {
        sys::get_unit_property(
            unit,
            property,
            scope,
            element,
            ptr::from_mut(&mut value).cast::<c_void>(),
            &raw mut size,
        )
    };
    sys::check(call, status)?;
    if usize::try_from(size).unwrap_or(0) == size_of::<T>() {
        Ok(value)
    } else {
        Err(Error::Call {
            call,
            status: OsStatus::new(abi::BAD_PROPERTY_SIZE),
        })
    }
}

fn set<T>(
    unit: sys::Unit,
    call: &'static str,
    property: u32,
    scope: u32,
    element: u32,
    value: &T,
) -> Result<(), Error> {
    let size = u32::try_from(size_of::<T>()).unwrap_or(0);
    // SAFETY: the pointer is to a live `T` of exactly `size` octets, and the
    // unit copies what it needs before returning.
    let status = unsafe {
        sys::set_unit_property(
            unit,
            property,
            scope,
            element,
            ptr::from_ref(value).cast::<c_void>(),
            size,
        )
    };
    sys::check(call, status)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_DEPTH_FRAMES, Health, MAX_FRAMES_PER_SLICE, Route, Shared, Stream, StreamConfig,
        play, record,
    };
    use crate::abi;
    use crate::format::StreamFormat;
    use crate::level::{Channel, Controls, Gain, Level, window_samples};
    use crate::status::Error;
    use core::ffi::c_void;
    use core::time::Duration;
    use std::ptr;
    use std::sync::Arc;

    #[cfg(target_os = "macos")]
    use crate::device::{DeviceChoice, DeviceId};

    /// Held by every test that opens or closes a real voice unit: `SPARE` is
    /// process-wide, and parallel tests otherwise took each other's unit.
    static VOICE_UNITS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn voice_units() -> std::sync::MutexGuard<'static, ()> {
        VOICE_UNITS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn channels() -> (Arc<Channel>, Arc<Channel>) {
        let window = window_samples(StreamFormat::narrowband().sample_rate_hz());
        (
            Arc::new(Channel::new(window)),
            Arc::new(Channel::new(window)),
        )
    }

    fn shared() -> Arc<Shared> {
        // a null unit is fine as long as nothing calls into the framework,
        // which is true of everything but `record`
        let (microphone, speaker) = channels();
        Arc::new(Shared::new(
            ptr::null_mut(),
            StreamFormat::narrowband(),
            DEFAULT_DEPTH_FRAMES,
            microphone,
            speaker,
        ))
    }

    fn context(shared: &Arc<Shared>) -> *mut c_void {
        Arc::as_ptr(shared).cast::<c_void>().cast_mut()
    }

    #[test]
    fn a_configuration_defaults_to_the_system_route() {
        let config = StreamConfig::default();
        assert_eq!(config.format, StreamFormat::narrowband());
        assert_eq!(config.depth_frames, DEFAULT_DEPTH_FRAMES);
        #[cfg(target_os = "macos")]
        assert_eq!(config.device, DeviceChoice::System);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_saved_selection_is_a_preference_rather_than_a_demand() {
        let config = StreamConfig::preferring("AppleUSBAudioEngine:1", StreamFormat::narrowband());
        assert_eq!(
            config.device,
            DeviceChoice::Preferred("AppleUSBAudioEngine:1".to_string())
        );
        assert_eq!(config.depth_frames, DEFAULT_DEPTH_FRAMES);
        // and it resolves to nothing in particular when the machine has no
        // such device, which is what makes it a preference
        assert_eq!(crate::hal::choose(&config.device), Ok(None));
    }

    #[test]
    fn the_rings_are_never_smaller_than_one_slice() {
        let (microphone, speaker) = channels();
        let shared = Shared::new(
            ptr::null_mut(),
            StreamFormat::narrowband(),
            1,
            microphone,
            speaker,
        );
        let slice = usize::try_from(MAX_FRAMES_PER_SLICE).unwrap();
        assert!(shared.capture.free() >= slice);
        assert!(shared.playback.free() >= slice);
    }

    #[test]
    fn the_capture_buffer_holds_a_whole_slice_of_the_slowest_device_at_the_stream_rate() {
        let (microphone, speaker) = channels();
        let wideband = StreamFormat::with_frame_millis(48_000, 20).unwrap();
        let shared = Shared::new(ptr::null_mut(), wideband, 16, microphone, speaker);
        let slice = usize::try_from(MAX_FRAMES_PER_SLICE).unwrap();
        // what a MacBook Air's microphone asked a 48 kHz stream for, on a
        // 4,096-frame slice at 44.1 kHz
        let seen = 4_458;
        // and the worst there is: the same slice from a narrowband headset
        let worst = slice * 6;
        let held = unsafe { (&*shared.scratch.get()).len() };
        assert!(held >= seen, "{held} samples cannot take {seen}");
        assert!(held >= worst, "{held} samples cannot take {worst}");
        assert_eq!(super::capture_capacity(StreamFormat::narrowband()), slice);
    }

    #[test]
    fn a_slice_of_the_slowest_device_fits_in_either_ring_beside_two_frames() {
        let (microphone, speaker) = channels();
        let wideband = StreamFormat::with_frame_millis(48_000, 20).unwrap();
        let shared = Shared::new(
            ptr::null_mut(),
            wideband,
            DEFAULT_DEPTH_FRAMES,
            microphone,
            speaker,
        );
        let frame = wideband.frame_samples();
        // a narrowband headset's slice, as the unit hands it to a 48 kHz
        // stream: half a second in one callback
        let slice = super::capture_capacity(wideband);

        // two frames the reader has not come for yet, then the slice
        shared.captured(&mut vec![1; frame * 2]);
        shared.captured(&mut vec![1; slice]);
        let counters = shared.meters.read();
        assert_eq!(counters.capture_dropped, 0, "the microphone lost samples");
        assert_eq!(counters.captured, u64::try_from(slice + frame * 2).unwrap());

        let queued = vec![1; slice + frame * 2];
        assert_eq!(
            shared.playback.write(&queued),
            queued.len(),
            "the speaker cannot be kept a slice ahead"
        );
    }

    #[test]
    fn the_most_a_render_has_asked_for_is_kept() {
        let mut stream = detached();
        assert_eq!(stream.split().1.burst(), 0, "nothing was asked yet");
        let mut samples = [0i16; 4];
        rendered(&stream.shared, &mut samples);
        assert_eq!(stream.split().1.burst(), 4);
        // a shorter render after it does not make the device's slice shorter
        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size: 8,
                data: samples.as_mut_ptr().cast::<c_void>(),
            }],
        };
        let mut flags = 0u32;
        let status = unsafe {
            play(
                context(&stream.shared),
                &raw mut flags,
                ptr::null(),
                abi::BUS_OUTPUT,
                2,
                &raw mut list,
            )
        };
        assert_eq!(status, 0);
        assert_eq!(stream.split().1.burst(), 4);
    }

    #[test]
    fn what_is_queued_is_what_was_written_whatever_the_ring_holds() {
        let mut stream = detached();
        let frame = vec![1i16; stream.format().frame_samples()];
        for _ in 0..3 {
            assert!(stream.write(&frame));
        }
        assert_eq!(stream.split().1.queued(), frame.len() * 3);
        let mut samples = [0i16; 4];
        rendered(&stream.shared, &mut samples);
        assert_eq!(stream.split().1.queued(), frame.len() * 3 - 4);
    }

    #[test]
    fn a_capture_told_of_more_frames_than_its_buffer_holds_renders_nothing() {
        // the unit in this `Shared` is null: a render that was attempted
        // would come back refused and be counted as a render failure, so a
        // clean count of those is what says none was attempted
        let shared = shared();
        let held = unsafe { (&*shared.scratch.get()).len() };

        let mut flags = 0u32;
        let status = unsafe {
            record(
                context(&shared),
                &raw mut flags,
                ptr::null(),
                abi::BUS_INPUT,
                u32::try_from(held + 1).unwrap(),
                ptr::null_mut(),
            )
        };

        assert_eq!(status, 0);
        let counters = shared.meters.read();
        assert_eq!(counters.capture_oversized, 1);
        assert_eq!(counters.render_failures, 0);
        assert_eq!(counters.captured, 0);
    }

    #[test]
    fn there_is_room_for_one_voice_unit_and_it_comes_back_when_the_unit_goes() {
        // a slot of this test's own: the process's is the real streams'
        static ROOM: super::Slot = super::Slot::new();

        let first = ROOM.take().expect("the room is free");
        assert_eq!(ROOM.held(), 1);
        assert!(ROOM.take().is_none(), "a second unit beside the first");
        drop(first);
        assert_eq!(ROOM.held(), 0);
        let again = ROOM.take();
        assert!(again.is_some(), "the room came back with the unit gone");
    }

    #[test]
    fn the_meters_are_told_what_a_window_is_worth_at_the_rate_that_opened() {
        let (microphone, speaker) = channels();
        let wideband = StreamFormat::with_frame_millis(48_000, 20).unwrap();
        let shared = Shared::new(
            ptr::null_mut(),
            wideband,
            DEFAULT_DEPTH_FRAMES,
            Arc::clone(&microphone),
            Arc::clone(&speaker),
        );
        // the window must have grown from 800 to 4800 samples
        let mut loud = [6_000i16; 4_000];
        let mut quiet = [0i16; 700];
        shared.microphone.apply(&mut loud, 4_000);
        for _ in 0..3 {
            shared.microphone.apply(&mut quiet, 700);
        }
        assert_eq!(shared.microphone.level().peak(), 6_000);
        assert!(Arc::ptr_eq(&shared.speaker, &speaker));
        assert!(Arc::ptr_eq(&shared.microphone, &microphone));
    }

    #[test]
    fn a_callback_with_no_context_does_nothing_and_says_so() {
        let mut flags = 0u32;
        let status = unsafe {
            play(
                ptr::null_mut(),
                &raw mut flags,
                ptr::null(),
                abi::BUS_OUTPUT,
                160,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, 0);
        assert_eq!(flags, 0);

        let status = unsafe {
            record(
                ptr::null_mut(),
                &raw mut flags,
                ptr::null(),
                abi::BUS_INPUT,
                160,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, 0);
    }

    #[test]
    fn a_render_with_nothing_to_render_into_is_silence() {
        let shared = shared();
        let mut flags = 0u32;
        let status = unsafe {
            play(
                context(&shared),
                &raw mut flags,
                ptr::null(),
                abi::BUS_OUTPUT,
                160,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, 0);
        assert_eq!(flags, abi::RENDER_ACTION_OUTPUT_IS_SILENCE);
        assert_eq!(shared.meters.read().played, 0);
    }

    #[test]
    fn what_was_queued_goes_out_and_the_rest_is_zeroed() {
        let shared = shared();
        assert!(shared.playback.write_frame(&[11, 22, 33, 44]));

        let mut samples = [-1i16; 8];
        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size: 16,
                data: samples.as_mut_ptr().cast::<c_void>(),
            }],
        };
        let mut flags = 0u32;
        let status = unsafe {
            play(
                context(&shared),
                &raw mut flags,
                ptr::null(),
                abi::BUS_OUTPUT,
                8,
                &raw mut list,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(samples, [11, 22, 33, 44, 0, 0, 0, 0]);
        // something went out, so it is not silence
        assert_eq!(flags, 0);
        let counters = shared.meters.read();
        assert_eq!(counters.played, 4);
        assert_eq!(counters.playback_starved, 4);
        assert_eq!(counters.panics, 0);
    }

    /// Render four samples into a buffer the size of what the device would
    /// hand over, and say what came out.
    fn rendered(shared: &Arc<Shared>, samples: &mut [i16; 4]) -> u32 {
        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size: 8,
                data: samples.as_mut_ptr().cast::<c_void>(),
            }],
        };
        let mut flags = 0u32;
        let status = unsafe {
            play(
                context(shared),
                &raw mut flags,
                ptr::null(),
                abi::BUS_OUTPUT,
                4,
                &raw mut list,
            )
        };
        assert_eq!(status, 0);
        flags
    }

    #[test]
    fn the_speaker_volume_is_applied_where_the_device_takes_the_samples() {
        let shared = shared();
        assert!(shared.playback.write_frame(&[10_000, -10_000, 4, -4]));
        // set after queueing: the gain must apply on the way out
        shared.speaker.set_gain(Gain::from_ratio(0.5));

        let mut samples = [-1i16; 4];
        let flags = rendered(&shared, &mut samples);

        assert_eq!(samples, [5_000, -5_000, 2, -2]);
        assert_eq!(flags, 0);
        // and the meter is what went to the device, not what was queued
        assert_eq!(shared.speaker.level().peak(), 5_000);
    }

    #[test]
    fn a_muted_speaker_plays_silence_and_still_takes_the_frames() {
        let shared = shared();
        assert!(shared.playback.write_frame(&[9_000i16; 4]));
        shared.speaker.set_muted(true);

        let mut samples = [-1i16; 4];
        rendered(&shared, &mut samples);

        assert_eq!(samples, [0, 0, 0, 0]);
        // drained while muted, so unmuting replays nothing
        assert_eq!(shared.playback.filled(), 0);
        assert_eq!(shared.meters.read().played, 4);
        assert_eq!(shared.speaker.level(), Level::SILENT);
    }

    #[test]
    fn the_microphone_volume_is_applied_before_the_samples_reach_the_ring() {
        let shared = shared();
        shared.microphone.set_gain(Gain::from_ratio(0.5));
        let mut heard = [1_000i16, -1_000, 2_000, -2_000];
        shared.captured(&mut heard);

        let mut frame = [0i16; 4];
        assert!(shared.capture.read_frame(&mut frame));
        assert_eq!(frame, [500, -500, 1_000, -1_000]);
        assert_eq!(shared.meters.read().captured, 4);
        assert_eq!(shared.microphone.level().peak(), 1_000);
    }

    #[test]
    fn a_muted_microphone_sends_silence_and_keeps_the_frames_coming() {
        let shared = shared();
        shared.microphone.set_muted(true);
        let mut heard = [12_000i16; 160];
        shared.captured(&mut heard);

        let mut frame = [1i16; 160];
        assert!(
            shared.capture.read_frame(&mut frame),
            "a muted microphone still has to deliver frames"
        );
        assert_eq!(frame, [0i16; 160]);
        assert_eq!(shared.meters.read().captured, 160);
        assert_eq!(shared.microphone.level(), Level::SILENT);
    }

    #[test]
    fn the_controls_and_the_callbacks_are_looking_at_the_same_channels() {
        let stream = detached();
        stream.capture_controls().set_gain(Gain::from_ratio(0.25));
        stream.playback_controls().set_muted(true);

        assert_eq!(stream.shared.microphone.gain(), Gain::from_ratio(0.25));
        assert!(stream.shared.speaker.is_muted());
        // and the two directions are not one channel wearing two hats
        assert!(!stream.shared.microphone.is_muted());
        assert_eq!(stream.shared.speaker.gain(), Gain::UNITY);

        // a handle outlives the stream rather than dangling
        let controls: Controls = stream.capture_controls();
        drop(stream);
        assert_eq!(controls.gain(), Gain::from_ratio(0.25));
    }

    /// A route onto a number no machine has handed out, so the hardware layer
    /// will not say either half is alive.
    #[cfg(target_os = "macos")]
    fn gone() -> Route {
        Route {
            playback: Some(DeviceId::new(u32::MAX)),
            capture: Some(DeviceId::new(u32::MAX)),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn losing_either_half_is_losing_the_stream() {
        let Some(alive) = crate::hal::devices()
            .ok()
            .and_then(|list| list.first().map(|device| device.id))
        else {
            return;
        };
        let dead = Some(DeviceId::new(u32::MAX));
        for (route, lost) in [
            // the microphone unplugged while the speaker it was not part of
            // plays on, which is what a USB microphone on a Mac does
            (
                Route {
                    playback: Some(alive),
                    capture: dead,
                },
                true,
            ),
            (
                Route {
                    playback: dead,
                    capture: Some(alive),
                },
                true,
            ),
            (
                Route {
                    playback: Some(alive),
                    capture: Some(alive),
                },
                false,
            ),
        ] {
            let mut stream = detached();
            stream.health = Health::Running;
            stream.route = route;
            assert_eq!(
                stream.poll(),
                lost.then_some(crate::device::StreamEvent::DeviceLost),
                "{route:?}"
            );
            assert_eq!(stream.is_running(), !lost, "{route:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn each_half_of_the_delay_is_asked_of_its_own_device() {
        use crate::device::Direction;
        use crate::hal::{default_device, latency};

        let (Ok(Some(speaker)), Ok(Some(microphone))) = (
            default_device(Direction::Output),
            default_device(Direction::Input),
        ) else {
            return;
        };
        let mut stream = detached();
        stream.route = Route {
            playback: Some(speaker),
            capture: Some(microphone),
        };
        let delay = stream.current_delay();
        // asked of the microphone; the speaker would answer for an input
        // side it does not have
        assert_eq!(delay.capture, latency(microphone, Direction::Input));
        assert_eq!(delay.playback, latency(speaker, Direction::Output));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_unit_says_which_device_each_half_is_on() {
        use crate::device::Direction;
        use crate::hal::default_device;
        use crate::sys;

        let (Ok(Some(speaker)), Ok(Some(microphone))) = (
            default_device(Direction::Output),
            default_device(Direction::Input),
        ) else {
            return;
        };
        let wanted = abi::ComponentDescription {
            component_type: abi::UNIT_TYPE_OUTPUT,
            subtype: abi::UNIT_SUBTYPE_VOICE_PROCESSING,
            manufacturer: abi::MANUFACTURER_APPLE,
            flags: 0,
            flags_mask: 0,
        };
        let component = unsafe { sys::find_component(ptr::null_mut(), &raw const wanted) };
        if component.is_null() {
            return;
        }
        let mut unit: sys::Unit = ptr::null_mut();
        assert_eq!(unsafe { sys::open_component(component, &raw mut unit) }, 0);
        // What `configure` does first, and nothing after it: the unit is never
        // initialised, so no microphone is opened and nothing is played.
        let enabled: u32 = 1;
        let input = super::set(
            unit,
            "AudioUnitSetProperty (EnableIO, input)",
            abi::PROPERTY_ENABLE_IO,
            abi::SCOPE_INPUT,
            abi::BUS_INPUT,
            &enabled,
        );
        let output = super::set(
            unit,
            "AudioUnitSetProperty (EnableIO, output)",
            abi::PROPERTY_ENABLE_IO,
            abi::SCOPE_OUTPUT,
            abi::BUS_OUTPUT,
            &enabled,
        );
        let route = super::route_of(unit);
        assert_eq!(unsafe { sys::dispose_component(unit) }, 0);

        assert_eq!(input, Ok(()));
        assert_eq!(output, Ok(()));
        // the system route: the default output for one half, and the default
        // input for the other, which on a Mac is another object
        assert_eq!(
            route,
            Route {
                playback: Some(speaker),
                capture: Some(microphone),
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_device_that_has_gone_is_reported_once_and_stops_the_stream() {
        let mut stream = detached();
        stream.health = Health::Running;
        // no machine has handed this number out, so the hardware layer will
        // not say it is alive
        stream.route = gone();
        let mut loud = [20_000i16; 100];
        stream.shared.microphone.apply(&mut loud, 100);
        assert_ne!(stream.capture_controls().level(), Level::SILENT);

        assert_eq!(stream.poll(), Some(crate::device::StreamEvent::DeviceLost));
        assert!(!stream.is_running(), "a lost device is not a running one");
        // a meter left where the last frame put it reads as a live signal
        assert_eq!(stream.capture_controls().level(), Level::SILENT);
        assert_eq!(stream.playback_controls().level(), Level::SILENT);
        // and a device does not go twice
        assert_eq!(stream.poll(), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_stream_that_was_running_when_the_device_went_is_one_to_put_back() {
        let mut stream = detached();
        stream.health = Health::Running;
        stream.route = gone();
        assert_eq!(stream.poll(), Some(crate::device::StreamEvent::DeviceLost));
        // `recover` restarts a stream lost while running
        assert_ne!(stream.health, Health::Stopped);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_stream_nobody_started_has_had_nothing_taken_away() {
        let mut stream = detached();
        stream.route = gone();
        assert_eq!(stream.poll(), None);
        assert_eq!(stream.health, Health::Stopped);
    }

    #[test]
    fn a_unit_is_running_only_while_it_says_so() {
        use super::unit_still_running;
        use crate::status::OsStatus;

        assert!(unit_still_running(Ok(1)));
        // stopped by the system: an interruption began
        assert!(!unit_still_running(Ok(0)));
        // not there to answer: the media services were reset under it
        assert!(!unit_still_running(Err(Error::Call {
            call: "AudioUnitGetProperty",
            status: OsStatus::new(-50),
        })));
    }

    /// What an `AVAudioSession` interruption does to a running unit, done by
    /// hand on the iOS simulator — which cannot raise a real interruption:
    /// the unit stopped behind the stream's back is reported lost once, and
    /// `recover` puts a new unit under the stream that carries frames again.
    /// Run with `cargo test --target aarch64-apple-ios-sim --no-run` and the
    /// test binary under `xcrun simctl spawn <device> <binary> --ignored`.
    ///
    /// A voice-processing unit starts only in a session whose category
    /// records, which an application sets on `AVAudioSession` and a test
    /// binary has nobody to set: [`record_and_play`] does it the way the
    /// Objective-C runtime lets C do it.
    #[cfg(target_os = "ios")]
    #[test]
    #[ignore = "opens the real default device"]
    fn a_unit_the_system_stopped_is_reported_lost_and_recovered_onto_a_new_one() {
        use super::{Stream, StreamConfig};
        use std::thread;
        use std::time::{Duration, Instant};

        let _units = voice_units();
        record_and_play();
        let format = StreamFormat::narrowband();
        let mut stream = Stream::open(StreamConfig::new(format)).expect("open the default device");
        stream.start().expect("start");
        assert_eq!(stream.poll(), None, "a running unit reported lost");

        // SAFETY: the unit is the stream's and open; this is what the system
        // does to it when an interruption begins.
        let stopped = unsafe { crate::sys::stop_unit(stream.unit) };
        assert_eq!(stopped, 0);
        assert_eq!(stream.poll(), Some(crate::device::StreamEvent::DeviceLost));
        assert!(!stream.is_running());
        assert_eq!(stream.poll(), None, "reported twice");

        let old = stream.unit;
        let mut stream = stream.recover().expect("recover onto a new unit");
        assert!(stream.is_running());
        assert_ne!(stream.unit, old, "the stopped unit was reused");
        assert_eq!(stream.poll(), None);

        let mut frame = vec![0i16; format.frame_samples()];
        let silence = vec![0i16; format.frame_samples()];
        let until = Instant::now() + Duration::from_secs(2);
        let mut arrived = 0;
        while Instant::now() < until && arrived < 5 {
            let _ = stream.write(&silence);
            while stream.read(&mut frame) {
                arrived += 1;
            }
            thread::sleep(Duration::from_millis(10));
        }
        println!(
            "{arrived} frames from the recovered unit, {}",
            stream.counters()
        );
        assert!(arrived >= 5, "the recovered unit carried {arrived} frames");
        stream.close().expect("close");
    }

    /// `[[AVAudioSession sharedInstance] setCategory:PlayAndRecord error:nil]`
    /// and `setActive:YES error:nil`, through the Objective-C runtime's C
    /// entry points, from Apple's public `objc/message.h` and
    /// `AVFAudio/AVAudioSessionTypes.h`.
    #[cfg(target_os = "ios")]
    fn record_and_play() {
        use core::ffi::c_char;

        type Id = *mut c_void;
        #[link(name = "objc")]
        unsafe extern "C" {
            fn objc_getClass(name: *const c_char) -> Id;
            fn sel_registerName(name: *const c_char) -> Id;
            fn objc_msgSend();
        }
        #[link(name = "AVFAudio", kind = "framework")]
        unsafe extern "C" {
            static AVAudioSessionCategoryPlayAndRecord: Id;
        }

        // SAFETY: each message is sent to the object and with the argument
        // types the header declares for it, through `objc_msgSend` cast to
        // exactly that signature, which is how the runtime is called from C.
        unsafe {
            let get: unsafe extern "C" fn(Id, Id) -> Id =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let set_category: unsafe extern "C" fn(Id, Id, Id, *mut Id) -> bool =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let set_active: unsafe extern "C" fn(Id, Id, bool, *mut Id) -> bool =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let session = get(
                objc_getClass(c"AVAudioSession".as_ptr()),
                sel_registerName(c"sharedInstance".as_ptr()),
            );
            assert!(!session.is_null(), "no AVAudioSession");
            assert!(set_category(
                session,
                sel_registerName(c"setCategory:error:".as_ptr()),
                AVAudioSessionCategoryPlayAndRecord,
                ptr::null_mut(),
            ));
            assert!(set_active(
                session,
                sel_registerName(c"setActive:error:".as_ptr()),
                true,
                ptr::null_mut(),
            ));
        }
    }

    #[test]
    fn a_render_asking_for_more_than_the_buffer_holds_stops_at_the_buffer() {
        let shared = shared();
        let queued = [1i16; 64];
        assert!(shared.playback.write_frame(&queued));

        let mut samples = [-1i16; 4];
        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size: 8,
                data: samples.as_mut_ptr().cast::<c_void>(),
            }],
        };
        let mut flags = 0u32;
        let status = unsafe {
            play(
                context(&shared),
                &raw mut flags,
                ptr::null(),
                abi::BUS_OUTPUT,
                4096,
                &raw mut list,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(samples, [1, 1, 1, 1]);
        assert_eq!(shared.meters.read().played, 4);
    }

    /// What a muted microphone does: go on delivering frames, of silence.
    ///
    /// Whatever was captured before the mute is still in the ring and is not
    /// what is under test, so it is drained first.
    fn muting_leaves_the_frames_coming(
        capture: &mut super::Capture<'_>,
        controls: &Controls,
        incoming: &mut [i16],
    ) {
        use std::thread;

        controls.set_muted(true);
        thread::sleep(Duration::from_millis(100));
        while capture.read(incoming) {}

        thread::sleep(Duration::from_millis(200));
        let mut silent = 0usize;
        while capture.read(incoming) {
            silent += 1;
            assert_eq!(
                incoming.iter().map(|sample| sample.abs()).max(),
                Some(0),
                "a muted microphone sent something"
            );
        }
        println!("{silent} frames of silence while muted");
        assert!(
            silent > 0,
            "muting stopped the frames instead of emptying them"
        );
        assert_eq!(controls.level(), Level::SILENT);
    }

    /// What an initialised stream on the system route has to be on: the
    /// default output for one half and the default input for the other, with
    /// the delay theirs.
    #[cfg(target_os = "macos")]
    fn on_the_route_asked_for(stream: &Stream, quiet: Option<&crate::device::Device>) {
        use crate::device::Direction;
        use crate::hal::{default_device, render_delay};

        println!(
            "landed on {:?} for the speaker and {:?} for the microphone",
            stream.device(),
            stream.capture_device()
        );
        let (Ok(Some(speaker)), Ok(Some(microphone))) = quiet.map_or_else(
            || {
                (
                    default_device(Direction::Output),
                    default_device(Direction::Input),
                )
            },
            |quiet| (Ok(Some(quiet.id)), Ok(Some(quiet.id))),
        ) else {
            return;
        };
        assert_eq!(
            stream.route,
            Route {
                playback: Some(speaker),
                capture: Some(microphone),
            }
        );
        // the live property read agrees with what was read back at open, for
        // both halves
        assert_eq!(stream.device(), Ok(speaker));
        assert_eq!(stream.capture_device(), Ok(microphone));
        assert_eq!(
            stream.render_delay(),
            render_delay(speaker, microphone),
            "the stream is reporting a delay that is not its devices'"
        );
    }

    /// A voice stream on `route`, both halves, and a player beside it on
    /// the same device: the quiet one when the machine has it
    /// ([`crate::quiet`]), the system's route otherwise.
    #[cfg(target_os = "macos")]
    fn on(route: &DeviceChoice, mut config: StreamConfig) -> StreamConfig {
        config.device = route.clone();
        config.capture_device = route.clone();
        config
    }

    #[cfg(not(target_os = "macos"))]
    fn on<R>(_route: &R, config: StreamConfig) -> StreamConfig {
        config
    }

    /// The default route end to end (on the quiet device when present). One
    /// function, because a second voice unit is refused while one is open.
    #[test]
    #[ignore = "opens the real default device"]
    #[expect(
        clippy::too_many_lines,
        reason = "one voice unit per process: the whole sequence is one test on purpose"
    )]
    fn a_loopback_on_the_default_device_moves_frames() {
        use super::{Stream, StreamConfig};
        use std::thread;
        use std::time::{Duration, Instant};

        let _units = voice_units();
        #[cfg(target_os = "macos")]
        let (route, quiet) = crate::quiet::route().expect("the device list");
        #[cfg(target_os = "macos")]
        println!("on {route}");
        #[cfg(not(target_os = "macos"))]
        let route = ();

        for rate in [16_000, 32_000, 48_000] {
            let wanted = StreamFormat::with_frame_millis(rate, 20).expect("a twenty ms frame");
            let mut stream =
                Stream::open(on(&route, StreamConfig::new(wanted))).expect("open at that rate");
            assert_eq!(stream.format(), wanted);
            stream.start().expect("start");
            stream.stop().expect("stop");
            // explicit, so errors are not swallowed by the destructor
            stream.close().expect("close");
            println!("{wanted} opened and closed");
        }

        let format = StreamFormat::narrowband();
        let mut stream =
            Stream::open(on(&route, StreamConfig::new(format))).expect("open the default device");
        println!("opened at {format}");
        println!("{}", stream.render_delay());
        assert!(
            stream.latency() < Duration::from_millis(500),
            "the device claims a delay no room has: {:?}",
            stream.latency()
        );
        #[cfg(target_os = "macos")]
        on_the_route_asked_for(&stream, quiet.as_ref());
        stream.start().expect("start the device");

        // the process's one voice unit is this one: a second is refused
        // without going near the framework, and a unit that only plays opens
        // beside it and runs
        assert_eq!(super::voice_units_open(), 1);
        assert!(matches!(
            Stream::open(on(&route, StreamConfig::new(format))),
            Err(Error::Busy)
        ));
        let mut beside = Stream::open(on(&route, StreamConfig::playback(format)))
            .expect("a player beside the call");
        beside.start().expect("start the player");
        assert!(beside.write(&vec![0; format.frame_samples()]));
        thread::sleep(Duration::from_millis(100));
        assert!(beside.counters().played > 0, "the player took nothing");
        assert_eq!(beside.counters().captured, 0);
        beside.close().expect("close the player");

        // a quiet sawtooth, so that what goes to the speaker is not silence
        // and the counters can tell the two directions apart
        let mut outgoing = vec![0i16; format.frame_samples()];
        for (index, sample) in outgoing.iter_mut().enumerate() {
            *sample = i16::try_from((index % 64) * 64).unwrap_or(0) - 2048;
        }

        let mut incoming = vec![0i16; format.frame_samples()];
        let mut arrived = 0usize;
        let mut queued = 0usize;
        let mut loudest = 0i16;

        let microphone = stream.capture_controls();
        let speaker = stream.playback_controls();
        // half volume out, so that what the speaker is doing is audibly this
        // crate's doing rather than the machine's
        speaker.set_gain(Gain::from_db(-6.0));

        {
            let (mut capture, mut playback) = stream.split();
            let until = Instant::now() + Duration::from_millis(800);
            while Instant::now() < until {
                // two frames a pass keeps the speaker fed without filling the
                // ring and turning the test into half a second of latency
                for _ in 0..2 {
                    if playback.write(&outgoing) {
                        queued += 1;
                    }
                }
                while capture.read(&mut incoming) {
                    arrived += 1;
                    for sample in &incoming {
                        loudest = loudest.max(sample.saturating_abs());
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
            println!(
                "microphone {}, speaker {} at {}",
                microphone.level(),
                speaker.level(),
                speaker.gain()
            );
            assert!(
                speaker.level().peak() <= 1_024 + 1,
                "the sawtooth is half of ±2048 after the gain, and it came \
                 out at {}",
                speaker.level().peak()
            );

            muting_leaves_the_frames_coming(&mut capture, &microphone, &mut incoming);
        }

        stream.stop().expect("stop the device");
        let counters = stream.counters();
        println!("{arrived} frames in, {queued} frames out, loudest sample {loudest}");
        println!("{counters}");

        assert!(arrived > 0, "no frames arrived from the microphone");
        assert!(counters.played > 0, "nothing was taken for the speaker");
        assert_eq!(counters.panics, 0);

        // a reopen on a real device keeps the caller's controls working
        let mut stream = stream.recover().expect("reopen on the system route");
        assert_eq!(stream.format(), format);
        assert!(!stream.is_running(), "a stopped stream comes back stopped");
        assert!(
            stream.capture_controls().is_muted(),
            "the mute did not survive the reopen"
        );
        assert_eq!(microphone.gain(), stream.capture_controls().gain());
        assert_eq!(speaker.gain(), Gain::from_db(-6.0));
        stream.start().expect("start the reopened device");
        stream.stop().expect("stop the reopened device");

        stream.close().expect("close the device");
        assert_eq!(super::voice_units_open(), 0, "the room came back");
    }

    /// The microphone on a device of its own, apart from the speaker's and
    /// without the system's default input moving: element one of the unit
    /// named separately from element zero.
    ///
    /// Needs a second input. `SIPRAL_AUDIO_MIC` names it by a fragment of its
    /// name — a virtual loopback device will do. Run it with
    /// `--test-threads=1` beside the loopback test: each holds the process's
    /// one voice unit, and the other is refused while it does.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "opens the real devices and needs a second input named by SIPRAL_AUDIO_MIC"]
    fn the_microphone_is_chosen_apart_from_the_speaker() {
        use super::{Stream, StreamConfig};
        use crate::device::Direction;
        use crate::hal::{default_device, devices};

        let _units = voice_units();
        let wanted = std::env::var("SIPRAL_AUDIO_MIC").expect("SIPRAL_AUDIO_MIC names an input");
        let input = devices()
            .expect("the list")
            .into_iter()
            .find(|device| device.is_input() && device.name.contains(&wanted))
            .expect("an input named like that");
        let default_input = default_device(Direction::Input).expect("the default input");
        let default_output = default_device(Direction::Output).expect("the default output");
        assert_ne!(
            Some(input.id),
            default_input,
            "pick an input that is not the default"
        );

        // the speaker on the quiet device when the machine has one, so that
        // nothing sounds through its loudspeaker
        let (route, quiet) = crate::quiet::route().expect("the device list");
        let format = StreamFormat::with_frame_millis(48_000, 20).expect("a twenty ms frame");
        let config = StreamConfig {
            device: route,
            ..StreamConfig::new(format)
        }
        .capturing_from(input.uid.clone().expect("a uid to save"));
        let mut stream = Stream::open(config).expect("open with the microphone apart");
        println!(
            "speaker on {:?}, microphone on {:?}",
            stream.device(),
            stream.capture_device()
        );
        assert_eq!(stream.capture_device(), Ok(input.id));
        assert_eq!(
            stream.device().ok(),
            quiet.map_or(default_output, |quiet| Some(quiet.id))
        );
        assert_eq!(
            default_device(Direction::Input),
            Ok(default_input),
            "the system's default input moved"
        );
        stream.start().expect("start");
        std::thread::sleep(Duration::from_millis(300));
        let mut frame = vec![0i16; format.frame_samples()];
        let mut arrived = 0;
        while stream.read(&mut frame) {
            arrived += 1;
        }
        println!(
            "{arrived} frames from {}; {}",
            input.name,
            stream.counters()
        );
        assert!(arrived > 0, "nothing came from the chosen microphone");
        stream.close().expect("close");
    }

    /// The loss of a device in the middle of a call, end to end: reported,
    /// the stream stopped, and a reopen onto whatever the machine has left.
    ///
    /// A person has to do the unplugging, which is why it is ignored. Plug a
    /// USB headset in, let the system make it the default input and output,
    /// run this, and pull the headset out when it says so.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs a person to unplug a headset while it waits"]
    fn a_headset_unplugged_mid_call_is_reported_and_the_stream_recovers_onto_what_is_left() {
        use super::{Stream, StreamConfig};
        use crate::device::StreamEvent;
        use std::thread;
        use std::time::Instant;

        const WAIT: Duration = Duration::from_secs(30);

        let _units = voice_units();
        let format = StreamFormat::narrowband();
        let mut stream = Stream::open(StreamConfig::new(format)).expect("open the system route");
        stream.start().expect("start the device");
        println!(
            "speaker on {:?}, microphone on {:?}: unplug the headset within {WAIT:?}",
            stream.route.playback, stream.route.capture
        );

        // nothing is written for the speaker, so the call is silent; the
        // microphone is drained the way a call would drain it
        let mut frame = vec![0i16; format.frame_samples()];
        let until = Instant::now() + WAIT;
        let mut event = None;
        while event.is_none() && Instant::now() < until {
            while stream.read(&mut frame) {}
            event = stream.poll();
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            event,
            Some(StreamEvent::DeviceLost),
            "no loss was reported within {WAIT:?}"
        );
        assert!(!stream.is_running(), "a lost device is not a running one");

        let mut stream = stream
            .recover()
            .expect("reopen on what the machine has left");
        println!(
            "recovered: speaker on {:?}, microphone on {:?}",
            stream.route.playback, stream.route.capture
        );
        assert!(
            stream.is_running(),
            "a call that lost its device comes back running"
        );
        thread::sleep(Duration::from_millis(500));
        let mut arrived = 0usize;
        while stream.read(&mut frame) {
            arrived += 1;
        }
        assert!(
            arrived > 0,
            "nothing arrived from the microphone it recovered onto"
        );
        assert_eq!(stream.poll(), None, "what it recovered onto is there");
        stream.close().expect("close the device");
    }

    /// A stream around a null unit.
    ///
    /// The framework refuses teardown calls on it with `paramErr`, so this
    /// crate's own teardown logic is testable without a device.
    fn detached() -> Stream {
        let shared = shared();
        Stream {
            unit: ptr::null_mut(),
            format: StreamFormat::narrowband(),
            config: StreamConfig::default(),
            microphone: Arc::clone(&shared.microphone),
            speaker: Arc::clone(&shared.speaker),
            shared,
            route: Route::default(),
            delay: super::RenderDelay::default(),
            health: Health::Stopped,
            closed: false,
            leak: false,
            claim: None,
            spare: true,
        }
    }

    #[test]
    fn a_stream_that_asked_no_device_looks_back_no_further_than_the_last_frame() {
        let stream = detached();
        assert_eq!(stream.latency(), Duration::ZERO);
        assert_eq!(stream.render_delay(), super::RenderDelay::default());
        assert!(
            !stream.render_delay().is_complete(),
            "nothing was asked, so nothing was answered"
        );
    }

    #[test]
    fn a_teardown_shuts_the_gate_reports_the_first_complaint_and_repeats_nothing() {
        let mut stream = detached();

        let outcome = stream.teardown();
        assert!(
            matches!(
                outcome,
                Err(Error::Call {
                    call: "AudioOutputUnitStop",
                    ..
                })
            ),
            "the first framework call to complain should be the one reported"
        );
        assert!(!stream.leak, "an empty gate drains, so nothing is leaked");
        // shut, and shut for good: no callback gets in after this
        assert!(stream.shared.gate.enter().is_none());

        // the destructor is about to do this again, and it must be a no-op
        assert_eq!(stream.teardown(), Ok(()));
    }

    #[test]
    fn a_teardown_that_cannot_drain_leaks_rather_than_frees() {
        let mut stream = detached();
        // stand in for a callback that is inside and does not come out; the
        // clone is what keeps the borrow off `stream` itself
        let held = Arc::clone(&stream.shared);
        let inside = held.gate.enter().expect("the gate is open");

        let outcome = stream.shut_down(Duration::from_millis(20), 20);

        assert_eq!(outcome, Err(Error::Draining { waited_millis: 20 }));
        assert!(
            stream.leak,
            "a stream that could not be shown to be quiet must not be freed"
        );
        drop(inside);
        // dropping `stream` now deliberately leaks its `Shared`, which is the
        // behaviour under test
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_device_that_does_not_exist_is_refused_and_the_unit_goes_back() {
        // an unknown device fails after the unit exists; the unwind must
        // neither hang nor crash
        let config = StreamConfig {
            device: DeviceChoice::Device(DeviceId::new(u32::MAX)),
            ..StreamConfig::default()
        };
        let _units = voice_units();
        assert!(Stream::open(config).is_err(), "a device that is not there");
    }

    #[test]
    fn a_render_that_arrives_during_teardown_plays_silence_and_takes_nothing() {
        let shared = shared();
        assert!(shared.playback.write_frame(&[5, 5, 5, 5]));
        shared.gate.close();

        let mut left = [-1i16; 4];
        let mut right = [-1i16; 4];
        let mut list = two_buffers(&mut left, &mut right);
        let flags = render(&shared, 4, (&raw mut list).cast::<abi::BufferList>());

        // zeroed rather than filled, every buffer of it, and the ring was not
        // touched
        assert_eq!(left, [0, 0, 0, 0]);
        assert_eq!(right, [0, 0, 0, 0]);
        assert_eq!(flags, abi::RENDER_ACTION_OUTPUT_IS_SILENCE);
        assert_eq!(shared.playback.filled(), 4);
        assert_eq!(shared.meters.read().played, 0);
    }

    #[test]
    fn a_render_during_teardown_that_cannot_be_zeroed_is_not_called_silence() {
        // teardown never touches the ring, but the buffer itself may still be
        // one this callback cannot write into
        let shared = shared();
        shared.gate.close();

        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size: 8,
                data: ptr::null_mut(),
            }],
        };
        let flags = render(&shared, 4, &raw mut list);

        // nothing reachable was zeroed, so the flag is not teardown's to set
        assert_eq!(flags, 0);
    }

    #[test]
    fn a_capture_that_arrives_during_teardown_does_not_call_into_the_unit() {
        // the unit in this `Shared` is null, so anything that got as far as
        // `AudioUnitRender` would be handing the framework a null instance:
        // the gate is the only thing between the two
        let shared = shared();
        shared.gate.close();

        let mut flags = 0u32;
        let status = unsafe {
            record(
                context(&shared),
                &raw mut flags,
                ptr::null(),
                abi::BUS_INPUT,
                160,
                ptr::null_mut(),
            )
        };

        assert_eq!(status, 0);
        let counters = shared.meters.read();
        assert_eq!(counters.captured, 0);
        assert_eq!(counters.render_failures, 0);
    }

    /// An `AudioBufferList` of two buffers, laid out the way the framework
    /// lays out a list longer than the declared structure.
    #[repr(C)]
    struct TwoBuffers {
        count: u32,
        buffers: [abi::Buffer; 2],
    }

    fn two_buffers(left: &mut [i16; 4], right: &mut [i16; 4]) -> TwoBuffers {
        let buffer = |samples: &mut [i16; 4]| abi::Buffer {
            channels: 1,
            byte_size: 8,
            data: samples.as_mut_ptr().cast::<c_void>(),
        };
        TwoBuffers {
            count: 2,
            buffers: [buffer(left), buffer(right)],
        }
    }

    /// Call the render callback for `frames` into `list`, and say what flags
    /// came back.
    fn render(shared: &Arc<Shared>, frames: u32, list: *mut abi::BufferList) -> u32 {
        let mut flags = 0u32;
        let status = unsafe {
            play(
                context(shared),
                &raw mut flags,
                ptr::null(),
                abi::BUS_OUTPUT,
                frames,
                list,
            )
        };
        assert_eq!(status, 0);
        flags
    }

    #[test]
    fn a_buffer_list_the_format_does_not_match_is_zeroed_before_it_is_called_silence() {
        let shared = shared();
        assert!(shared.playback.write_frame(&[7, 7, 7, 7]));

        let mut left = [-1i16; 4];
        let mut right = [-1i16; 4];
        let mut list = two_buffers(&mut left, &mut right);
        let flags = render(&shared, 4, (&raw mut list).cast::<abi::BufferList>());

        // Not our format, so nothing from the ring goes into it. The flag
        // still says silence, and the header holds whoever sets it to having
        // made every buffer silent.
        assert_eq!(left, [0, 0, 0, 0]);
        assert_eq!(right, [0, 0, 0, 0]);
        assert_eq!(flags, abi::RENDER_ACTION_OUTPUT_IS_SILENCE);
        assert_eq!(shared.playback.filled(), 4);
        assert_eq!(shared.meters.read().played, 0);
    }

    #[test]
    fn a_render_asking_for_no_frames_zeroes_what_it_calls_silence() {
        let shared = shared();
        assert!(shared.playback.write_frame(&[7, 7, 7, 7]));

        let mut samples = [-1i16; 4];
        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size: 8,
                data: samples.as_mut_ptr().cast::<c_void>(),
            }],
        };
        let flags = render(&shared, 0, &raw mut list);

        assert_eq!(samples, [0, 0, 0, 0]);
        assert_eq!(flags, abi::RENDER_ACTION_OUTPUT_IS_SILENCE);
        assert_eq!(shared.playback.filled(), 4);
    }

    #[test]
    fn a_starved_render_zeroes_every_octet_it_calls_silence() {
        // nothing queued, and a buffer declaring more than the frames asked
        // for: the flag is about the buffer, not about the frames
        let shared = shared();
        let mut samples = [-1i16; 4];
        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size: 8,
                data: samples.as_mut_ptr().cast::<c_void>(),
            }],
        };
        let flags = render(&shared, 2, &raw mut list);

        assert_eq!(samples, [0, 0, 0, 0]);
        assert_eq!(flags, abi::RENDER_ACTION_OUTPUT_IS_SILENCE);
        assert_eq!(shared.meters.read().playback_starved, 2);
    }

    #[test]
    fn a_buffer_with_nowhere_to_write_is_not_called_silence() {
        let shared = shared();
        let mut list = abi::BufferList {
            count: 1,
            buffers: [abi::Buffer {
                channels: 1,
                byte_size: 8,
                data: ptr::null_mut(),
            }],
        };
        let flags = render(&shared, 4, &raw mut list);

        // eight octets declared and none of them reachable, so none of them
        // were zeroed, and the flag is not ours to set
        assert_eq!(flags, 0);
        assert_eq!(shared.meters.read().played, 0);
    }

    #[test]
    fn a_spare_holds_one_unit_and_gives_it_to_whoever_takes_it() {
        let spare = super::Spare::new();
        let (first, second) = (
            ptr::without_provenance_mut(8),
            ptr::without_provenance_mut(16),
        );
        assert_eq!(spare.take(), None);
        assert_eq!(spare.keep(first), None);
        assert_eq!(
            spare.keep(second),
            Some(first),
            "the one it displaced comes back"
        );
        assert_eq!(spare.take(), Some(second));
        assert_eq!(spare.take(), None, "and taking empties it");
    }

    #[test]
    fn only_a_voice_unit_that_came_down_cleanly_is_kept() {
        use super::{StreamKind, spares};
        assert!(spares(StreamKind::Voice, false, true, 0));
        assert!(
            !spares(StreamKind::Playback, false, true, 0),
            "a player is disposed of"
        );
        assert!(
            !spares(StreamKind::Voice, true, true, 0),
            "so is a unit whose device went"
        );
        assert!(
            !spares(StreamKind::Voice, false, false, 0),
            "and one that may not be kept"
        );
        assert!(
            !spares(StreamKind::Voice, false, true, -50),
            "and one that would not uninitialise"
        );
    }

    /// On a real, never-initialised voice unit: close spares it; a lost
    /// device or a reopen disposes of it. One test, since `SPARE` is global.
    #[test]
    fn a_closed_voice_stream_leaves_its_unit_for_the_next_and_a_lost_one_does_not() {
        use super::{SPARE, StreamKind, new_unit};
        let _units = voice_units();
        let Ok(unit) = new_unit(StreamKind::Voice) else {
            // a system with no voice-processing unit has nothing to keep
            return;
        };
        let mut stream = detached();
        stream.unit = unit;
        stream
            .close()
            .expect("a unit that was never started comes down cleanly");
        assert_eq!(SPARE.take(), Some(unit), "the unit was disposed of");

        let mut lost = detached();
        lost.unit = unit;
        lost.health = Health::Lost;
        lost.close().expect("disposed of");
        assert_eq!(SPARE.take(), None, "a unit whose device went is not kept");

        let Ok(unit) = new_unit(StreamKind::Voice) else {
            return;
        };
        let mut reopening = detached();
        reopening.unit = unit;
        reopening.spare = false;
        reopening.close().expect("disposed of");
        assert_eq!(SPARE.take(), None, "nor is one the stream may not keep");
    }

    /// Repeated open/close rounds with a mid-round microphone change, all on
    /// one unit. With a new unit each time this read freed memory within a
    /// few rounds under the guard allocator:
    ///
    ///   SIPRAL_AUDIO_ROUNDS=10 DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib \
    ///   MallocScribble=1 target/debug/deps/sipral_io_coreaudio-<hash> \
    ///   --ignored --exact stream::tests::repeated_voice_streams_run_on_one_unit
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "opens the real devices, round after round"]
    fn repeated_voice_streams_run_on_one_unit() {
        use super::{Stream, StreamConfig};
        use crate::device::Direction;
        use crate::hal::{default_device, devices};

        let _units = voice_units();
        let rounds = std::env::var("SIPRAL_AUDIO_ROUNDS")
            .ok()
            .and_then(|rounds| rounds.parse::<usize>().ok())
            .unwrap_or(5);
        let (route, _) = crate::quiet::route().expect("the device list");
        let input = default_device(Direction::Input)
            .expect("the default input")
            .expect("a machine with a microphone");
        let uid = devices()
            .expect("the list")
            .into_iter()
            .find(|device| device.id == input)
            .and_then(|device| device.uid)
            .expect("the default input has a uid");
        let format = StreamFormat::with_frame_millis(48_000, 20).expect("a twenty ms frame");
        let mut first = None;
        for round in 1..=rounds {
            for microphone in [DeviceChoice::System, DeviceChoice::Preferred(uid.clone())] {
                let config = StreamConfig {
                    device: route.clone(),
                    capture_device: microphone,
                    ..StreamConfig::new(format)
                };
                let mut stream = Stream::open(config).expect("open");
                assert_eq!(
                    *first.get_or_insert(stream.unit),
                    stream.unit,
                    "round {round}: a second voice unit was made"
                );
                stream.start().expect("start");
                std::thread::sleep(Duration::from_millis(400));
                let mut frame = vec![0i16; format.frame_samples()];
                let mut arrived = 0;
                while stream.read(&mut frame) {
                    arrived += 1;
                }
                assert!(
                    arrived > 0,
                    "round {round}: nothing came from the microphone"
                );
                stream.close().expect("close");
                assert_eq!(super::voice_units_open(), 0, "the room came back");
            }
            println!("round {round} of {rounds}");
        }
    }
}
