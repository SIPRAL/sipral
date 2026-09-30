// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One duplex voice-processing unit: samples in from the microphone, samples
//! out to the speaker, and nothing else.
//!
//! The unit is `kAudioUnitSubType_VoiceProcessingIO` on both platforms. That
//! is not a preference. It brings the system's own echo canceller, and
//! `docs/05-media.md` says in as many words that we attach an echo canceller
//! rather than write one; on iOS it is also what makes the audio session
//! behave the way a call should.
//!
//! One unit is not one device. On macOS it plays to one device object and
//! captures from another whenever the machine has them as two, which on a Mac
//! is the usual case: the built-in speakers and the built-in microphone are
//! separate objects, with separate rates, buffers and delays. The unit says
//! which object each half is on, and the stream asks it for both rather than
//! letting either stand for the other.
//!
//! Two threads meet here. The framework's realtime thread runs [`play`] and
//! [`record`]; everything else runs on whatever thread the caller is on. They
//! share nothing but the two rings and the counters, and neither waits for the
//! other.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::cell::UnsafeCell;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::Arc;

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
/// It is also how big the buffer the input callback renders into is, so it has
/// to be decided before the stream opens rather than discovered. Apple's own
/// advice for iOS is this number, because a smaller one starts failing when
/// the screen locks.
///
/// On macOS it is not free. The voice-processing unit takes it as the
/// microphone's IO buffer: on an Intel MacBook Pro the built-in microphone
/// went from 512 frames to 4,096 once a unit with this limit was initialised,
/// and stayed at 512 under a limit of 512 or none, which is 81 ms more capture
/// delay at 44.1 kHz. [`Stream::render_delay`] counts it, because the device
/// reports it.
const MAX_FRAMES_PER_SLICE: u32 = 4096;

/// The slowest rate a device delivers at: a Bluetooth headset in its
/// narrowband mode.
const SLOWEST_DEVICE_RATE_HZ: u32 = 8_000;

/// How many samples the input callback's buffer holds at `format`'s rate.
///
/// Not [`MAX_FRAMES_PER_SLICE`]. The limit is counted at the device's rate,
/// and the unit converts the device's slice to the stream's rate before the
/// callback is told how many frames there are: a MacBook Air microphone on a
/// 4,096-frame slice at 44.1 kHz asks a 48 kHz stream for 4,458. So the buffer
/// holds one whole slice of the slowest device there is, converted up to this
/// stream's rate, and a callback that still asks for more is refused rather
/// than handed a buffer that is too small (see `Shared::record`).
fn capture_capacity(format: StreamFormat) -> usize {
    let slice = usize::try_from(MAX_FRAMES_PER_SLICE).unwrap_or(0);
    let ratio = format.sample_rate_hz().div_ceil(SLOWEST_DEVICE_RATE_HZ).max(1);
    slice.saturating_mul(usize::try_from(ratio).unwrap_or(1))
}

/// Frames each ring holds unless the caller says otherwise: enough to ride out
/// a scheduling hiccup, short enough that a stalled reader is heard as a gap
/// rather than as a delay that never recovers.
const DEFAULT_DEPTH_FRAMES: usize = 16;

/// Which unit a stream is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamKind {
    /// The voice-processing unit: the microphone and the speaker together,
    /// with the system's echo canceller between them. At most one is open in
    /// a process at a time ([`voice_units_open`]).
    #[default]
    Voice,
    /// A plain output unit — the hardware output unit on macOS, the remote
    /// I/O unit on iOS — that only plays: no microphone, no echo canceller,
    /// and no claim on the voice-processing unit, so it opens beside a call's.
    /// What a ring on a device of its own is played through. Reading from
    /// one delivers nothing.
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
    /// macOS only, because naming a device is: on iOS the route is the audio
    /// session's and the application's, and there is no property to set. The
    /// field is absent there rather than ignored, so the request cannot be
    /// written down at all.
    #[cfg(target_os = "macos")]
    pub device: DeviceChoice,
    /// Which device the microphone is on, chosen apart from the speaker's
    /// and without touching the system's default input. macOS only, as
    /// `device`; ignored by a [`StreamKind::Playback`] stream.
    #[cfg(target_os = "macos")]
    pub capture_device: DeviceChoice,
    /// Frames of buffering between the device and the caller, per direction.
    pub depth_frames: usize,
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

    /// The same configuration with the microphone on a saved selection: the
    /// device carrying that identity when the stream opens, and the system's
    /// default input when the machine does not have it.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn capturing_from(self, uid: impl Into<String>) -> Self {
        Self {
            capture_device: DeviceChoice::Preferred(uid.into()),
            ..self
        }
    }

    /// A saved selection, at the given format: the device carrying that
    /// identity when the stream opens, and the system's route when the machine
    /// does not have it.
    ///
    /// The identity is [`Device::uid`](crate::Device::uid), which is the field
    /// worth writing into a configuration file.
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
/// Apple supports one such unit per process: a second one opened beside the
/// first was seen to block inside the framework, and two with their
/// microphones enabled hand the canceller two captures of one room. So the
/// room is taken before a unit is created and given back only once it has
/// been disposed of, and a stream that was deliberately leaked keeps it for
/// good, because its unit was never taken down either.
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

/// How many voice-processing units this process has open right now: zero or
/// one. A [`StreamKind::Voice`] stream opened while it is one is refused with
/// [`Error::Busy`]; a caller reopening one that is on its way down can wait
/// for this to read zero.
#[must_use]
pub fn voice_units_open() -> usize {
    VOICE_UNIT.held()
}

/// What the realtime side has to say, in numbers because it cannot speak.
///
/// Every one of these is relaxed: nothing else depends on having seen them, a
/// reader that is one increment behind is reading a number that was true a
/// moment ago, and making them ordered would put a fence in the callback for
/// the sake of a statistic.
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
    /// Shut at the top of teardown, and waited on before anything below is
    /// freed. See `gate.rs` for why this is built rather than assumed.
    gate: Gate,
    capture: Ring,
    playback: Ring,
    /// Where the input callback renders to before the samples reach the ring.
    /// The framework runs one input callback at a time for a unit, so the
    /// exclusivity given up here is handed straight back by the framework.
    scratch: UnsafeCell<Box<[i16]>>,
    meters: Meters,
    /// The gain, the mute and the meter for each direction. Held behind an
    /// `Arc` of their own rather than inline, so that a [`Controls`] handed to
    /// the thread drawing the window survives the stream being reopened on
    /// another device.
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
        let slice = usize::try_from(MAX_FRAMES_PER_SLICE).unwrap_or(0);
        // never smaller than one slice: a ring that cannot hold what the
        // device hands over in one callback would drop samples every time
        let samples = format
            .frame_samples()
            .saturating_mul(depth_frames.max(2))
            .max(slice);
        // the meters count in samples, so a stream reopened at another rate
        // has to be told what a tenth of a second is now worth
        let window = window_samples(format.sample_rate_hz());
        microphone.set_window(window);
        speaker.set_window(window);
        Self {
            unit,
            gate: Gate::new(),
            capture: Ring::new(samples),
            playback: Ring::new(samples),
            scratch: UnsafeCell::new(vec![0; capture_capacity(format)].into_boxed_slice()),
            meters: Meters::default(),
            microphone,
            speaker,
        }
    }

    /// Fill the unit's buffer from the playback ring. Realtime thread.
    ///
    /// Returns whether the silence flag may go on the way back, which is only
    /// ever when every buffer in the list has just been zeroed: the header
    /// calls the flag a hint, and holds whoever sets it to having made the
    /// buffer silent.
    ///
    /// # Safety
    /// As [`silence`].
    unsafe fn play(&self, frames: u32, buffers: *mut abi::BufferList) -> bool {
        // SAFETY: the caller's pointer, checked for null by `as_mut`.
        let Some(list) = (unsafe { buffers.as_mut() }) else {
            // SAFETY: as above; null is handled inside.
            return unsafe { silence(buffers) };
        };
        // one channel interleaved is what the stream format asks for, so the
        // unit hands back exactly one buffer; anything else is not our format
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
        // SAFETY: `wanted` samples fit in the octets the buffer declares, and
        // the unit hands over memory aligned for the format it was given.
        let out = unsafe { core::slice::from_raw_parts_mut(buffer.data.cast::<i16>(), wanted) };
        let taken = self.playback.read(out);
        // The volume goes on here rather than where the caller wrote the
        // frame, so that a mute is silent on this callback instead of on the
        // one after the ring has drained. `wanted` rather than `taken`,
        // because the silence a starved callback plays is time the meter's
        // window has to count.
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
        // Only the frames asked for were zeroed above, and a buffer can
        // declare more octets than that; the flag speaks for all of them.
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
        // The unit renders `frames` frames whatever the buffer list says:
        // asking it for fewer, into a buffer sized for fewer, was seen to have
        // the voice-processing unit copy past the end of its own buffers. So
        // the render is for exactly what the callback was told, into a buffer
        // that holds all of it at the format `configure` read back (mono,
        // sixteen bits, two octets a frame) — or it is not made at all.
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

    /// The volume, the meter and the ring, for what the microphone delivered.
    ///
    /// Split out of the callback above because everything before this point
    /// needs a live unit to call into and everything in it is arithmetic,
    /// which is the half that can be shown to be right without a device.
    fn captured(&self, samples: &mut [i16]) {
        let delivered = samples.len();
        // A muted microphone still fills the ring, with silence. Stopping the
        // frames instead would mean unmuting replayed however much audio had
        // piled up behind the mute, and would starve whatever above is pacing
        // itself on frames arriving.
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

/// Zero every buffer the unit was going to play, and say whether that left
/// nothing unzeroed — which is the only condition under which the silence flag
/// may be set.
///
/// Walked by the list's own count and by offset, not through the declared
/// structure, because a list of more than one buffer is longer than that
/// structure. A null list has no octets to zero and is silent; a buffer that
/// declares octets behind a null pointer cannot be zeroed, and the answer is
/// then no. Nothing here can panic, which is what lets the panic path use it.
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
/// A panic must not cross back into C — the same reasoning `docs/08-ffi.md`
/// gives for the C ABI, and with more force here, because the frame after this
/// one is due in a few milliseconds. So it is caught, counted, and turned into
/// silence.
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
    // teardown has begun: there is nothing to hand the samples to, and
    // `AudioUnitRender` would be a call into a unit that is being taken down
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
/// Dropping it shuts the device down and waits for the callbacks to be out of
/// its memory, so nothing here has to be closed by hand. [`Stream::close`] does
/// the same thing and says what the framework thought of it.
pub struct Stream {
    unit: sys::Unit,
    shared: Arc<Shared>,
    format: StreamFormat,
    /// Kept so that [`Stream::recover`] can ask for the same thing again and
    /// have the choice resolved against the machine as it is then.
    config: StreamConfig,
    /// The two directions' controls, held here as well as in `shared` so that
    /// a reopen carries the volume and the mute across rather than resetting
    /// them under a caller who is mid-call.
    microphone: Arc<Channel>,
    speaker: Arc<Channel>,
    /// Which device each half of the unit settled on, read once at open.
    /// Reading them later would be a call into a unit whose device may have
    /// gone, and the answer is wanted precisely when that has happened. Empty
    /// on iOS, where the route belongs to the audio session rather than to
    /// this crate.
    route: Route,
    /// What those two devices said about their own delay, read at the same
    /// moment and for the same reason.
    delay: RenderDelay,
    health: Health,
    closed: bool,
    /// Set when teardown could not prove the callbacks were out. Nothing is
    /// then freed, ever.
    leak: bool,
    /// The process's room for a voice-processing unit, held by a
    /// [`StreamKind::Voice`] stream until its unit has been disposed of.
    claim: Option<Claim>,
}

/// The device object under each half of a stream.
///
/// Two fields rather than one because the unit reports two, and on a Mac they
/// are usually different objects. Either is `None` where the unit named no
/// device for that half.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Route {
    /// The speaker's: what the unit reports on its output element.
    playback: Option<DeviceId>,
    /// The microphone's: what the unit reports on its input element.
    capture: Option<DeviceId>,
}

/// Where the device under a stream is.
///
/// Three states rather than two flags, because the third one is not "stopped
/// with a bit set": a stream that has lost its device stays here until
/// [`Stream::recover`] puts another one underneath, and that is what makes the
/// loss reported once rather than on every poll.
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
    /// A [`StreamKind::Voice`] stream is one per process. A softphone has one
    /// call's worth of audio at a time, and opening a second voice-processing
    /// unit while the first is alive was observed to block inside the
    /// framework rather than to fail, so it is refused here instead. A
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

    /// The same, on controls that already exist, which is what makes a reopen
    /// keep the volume and the mute the caller had set.
    fn open_with(
        config: StreamConfig,
        microphone: Arc<Channel>,
        speaker: Arc<Channel>,
    ) -> Result<Self, Error> {
        // the room is taken before the unit exists, so that two threads
        // opening at once cannot both get one
        let claim = match config.kind {
            StreamKind::Voice => Some(VOICE_UNIT.take().ok_or(Error::Busy)?),
            StreamKind::Playback => None,
        };
        let wanted = abi::ComponentDescription {
            component_type: abi::UNIT_TYPE_OUTPUT,
            subtype: match config.kind {
                StreamKind::Voice => abi::UNIT_SUBTYPE_VOICE_PROCESSING,
                StreamKind::Playback => abi::UNIT_SUBTYPE_PLAIN_OUTPUT,
            },
            manufacturer: abi::MANUFACTURER_APPLE,
            flags: 0,
            flags_mask: 0,
        };
        // SAFETY: null asks for the first match; the description is a local
        // the call only reads.
        let component = unsafe { sys::find_component(ptr::null_mut(), &raw const wanted) };
        if component.is_null() {
            return Err(Error::UnitMissing);
        }

        let mut unit: sys::Unit = ptr::null_mut();
        // SAFETY: `unit` is a live out-parameter of the right type.
        sys::check("AudioComponentInstanceNew", unsafe {
            sys::open_component(component, &raw mut unit)
        })?;

        // The unit belongs to a `Stream` from here on, before anything is set
        // on it. Configuration installs the callbacks partway through and can
        // fail after that — at `AudioUnitInitialize` or at the format readback
        // — so the way out of a failure has to be the same shut, stop, drain
        // and only-then-dispose that any other teardown does. Handing it to a
        // `Stream` first is what makes `?` below take that route, and means
        // there is one shutdown sequence in this file rather than two.
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
        };
        configure(unit, &stream.config, &stream.shared)?;
        stream.route = route_of(unit);
        if stream.config.kind == StreamKind::Playback {
            // no microphone half, so no device under one to watch or to
            // count the delay of
            stream.route.capture = None;
        }
        stream.delay = stream.current_delay();
        Ok(stream)
    }

    /// What the two devices the unit landed on say their halves cost: the
    /// speaker's output side at the speaker's rate, and the microphone's
    /// input side at the microphone's.
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

    /// On iOS the numbers live in `AVAudioSession` — `inputLatency`,
    /// `outputLatency` and `ioBufferDuration` — which is Objective-C and the
    /// application's to read, so this crate has nothing to report.
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
    /// Either one going is the stream's device going: a call that has lost
    /// its microphone is as broken as one that has lost its speaker, and on a
    /// Mac the two are usually different objects, so asking about one says
    /// nothing about the other.
    #[cfg(target_os = "macos")]
    fn device_present(&self) -> bool {
        [self.route.playback, self.route.capture]
            .into_iter()
            .flatten()
            .all(crate::hal::is_alive)
    }

    /// Whether the unit is still running, which is what iOS lets this crate
    /// see of the device being taken away.
    ///
    /// The route and its interruptions belong to `AVAudioSession` and are
    /// delivered to the application, not here. What does reach the unit is
    /// their effect: the system stops it when an interruption begins — a
    /// cellular call, another application's session — and one whose media
    /// services were reset no longer answers at all. Either way the unit is
    /// not running while the stream still thinks it is.
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

    /// How long a frame takes to get from [`Playback::write`] out of the
    /// loudspeaker, across the room, and back in through [`Capture::read`].
    ///
    /// This is the number an echo canceller is told to look back by, and the
    /// one line to write is the same on Windows: what
    /// `sipral_io_wasapi::CaptureStream::latency` reports for its endpoint,
    /// this reports for both halves at once, because the unit here is duplex
    /// and a WASAPI client is not. Each half is asked of the device object
    /// the unit reports for it, and converted at that device's own rate.
    ///
    /// Read once, when the stream opened. Asking the devices again later
    /// would be a property read on hardware that may have gone, and the parts
    /// that can move — the IO buffer another process resized — move by less
    /// than the delay of asking. [`Stream::recover`] reads it again for the
    /// devices it lands on.
    ///
    /// Zero on iOS, and zero from a device that answered nothing.
    /// [`Stream::render_delay`] is the same number with the parts still
    /// separate, and says which of them the device would not give.
    #[must_use]
    pub fn latency(&self) -> Duration {
        self.delay.total()
    }

    /// The same delay, part by part and direction by direction.
    ///
    /// Worth reading when a canceller is not converging: a device that
    /// answered for three parts out of four gives a delay that is a floor
    /// rather than the truth, and [`RenderDelay::is_complete`] is what says so.
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
        // The stop is synchronous off the I/O thread, so no callback is left
        // to move these. A meter left where the last frame put it would read
        // as a live signal for as long as the stream stayed stopped.
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
    /// A handle, not a borrow: the slider and the bar are on the thread that
    /// draws the window, the frames are on the thread that carries the call,
    /// and the stream is borrowed by [`Stream::split`] for the length of it.
    /// It survives [`Stream::recover`] with its settings intact.
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
    /// What it proves differs by platform, and the difference is worth
    /// knowing. On macOS the hardware layer is asked outright whether each of
    /// the two device objects the stream opened — the speaker's and the
    /// microphone's, which are often not the same object — is still alive, so
    /// an unplugged headset or microphone is reported whether or not anything
    /// was flowing through it, and losing either half is losing the stream.
    /// On iOS the unit is asked whether it is still running: the system stops
    /// it when an `AVAudioSession` interruption begins, and a unit whose media
    /// services were reset does not answer, so both are reported here as the
    /// device lost. A route change on iOS is not a loss — the unit follows the
    /// session's route — and is the application's to hear about, from
    /// `AVAudioSession`. [`Stream::recover`] builds a new unit, which is the
    /// only thing that works after a reset; while an interruption lasts it
    /// fails, and is tried again once the application's session is active.
    ///
    /// A stream that has said [`StreamEvent::DeviceLost`] is stopped. What it
    /// had already captured can still be read out; nothing further arrives,
    /// and the speaker ring fills and takes no more. [`Stream::recover`] is
    /// what puts a device back under it.
    ///
    /// The macOS answer costs two property reads and the iOS one a single
    /// read of the unit, so it belongs beside `DeviceMonitor::poll` (macOS)
    /// a few times a second rather than beside [`Controls::level`] on every
    /// drawn frame. Once the loss has been reported it costs a comparison:
    /// every answer after the first is `None`, because a device does not go
    /// twice.
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
        // a meter left where the last frame put it reads as a live signal
        self.microphone.quiet();
        self.speaker.quiet();
    }

    /// Open again, on whatever the stream's [`StreamConfig`] names now.
    ///
    /// This is the answer to [`StreamEvent::DeviceLost`], and the reason a
    /// saved selection is worth storing as
    /// [`DeviceChoice::Preferred`](crate::DeviceChoice::Preferred): that
    /// choice resolves to the saved device when it is back and to the system's
    /// route when it is not, so recovering from an unplugged headset lands on
    /// the machine's own speaker rather than failing.
    /// [`DeviceChoice::Device`](crate::DeviceChoice::Device) names one device
    /// and nothing else, so recovering onto one that has gone fails, and
    /// says so.
    ///
    /// The controls carry over: the gain and the mute a person set are still
    /// set, and a [`Controls`] handed out earlier keeps working. Whatever was
    /// in the rings does not — those samples were on their way to a device
    /// that is not there. A stream that was running is started again.
    ///
    /// # Errors
    /// [`Error::Draining`] when the old stream could not be shut down, in
    /// which case nothing is reopened: a second voice-processing unit
    /// alongside one that is wedged is how a process stops answering
    /// altogether. Otherwise whatever [`Stream::open`] would have said about
    /// the device it landed on.
    pub fn recover(mut self) -> Result<Self, Error> {
        let config = self.config.clone();
        let microphone = Arc::clone(&self.microphone);
        let speaker = Arc::clone(&self.speaker);
        // `Lost` is only ever reached from `Running`, so a stream that was
        // carrying a call when its device went is one to put back on the air.
        let running = !matches!(self.health, Health::Stopped);
        // What the framework says about taking down a unit whose device has
        // gone is not a reason to stop: that is the situation being recovered
        // from. Failing to drain is another matter entirely.
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
    /// Worth asking after a [`DeviceEvent::DefaultChanged`] arrives: a stream
    /// opened without naming a device follows the system route, and this is
    /// how to find out where that went. The microphone half is
    /// [`Stream::capture_device`], and on a Mac it is usually another device.
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
    /// They borrow the stream rather than owning it, which is what keeps a
    /// second pair from existing: one producer and one consumer per ring is
    /// the whole basis of the lock-free discipline underneath.
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
    /// Dropping a stream does exactly this and has nowhere to report to, so
    /// this exists for a caller who wants to know. Either way the device is
    /// released; the difference is only whether the statuses are seen.
    ///
    /// # Errors
    /// [`Error::Draining`] when the callbacks could not be shown to be out of
    /// the stream's memory within two seconds — in which case that memory and
    /// the audio unit are deliberately never freed. Otherwise [`Error::Call`]
    /// carrying the first of stop, uninitialise and dispose to complain; all
    /// three are attempted regardless.
    pub fn close(mut self) -> Result<(), Error> {
        self.teardown()
    }

    /// The shutdown sequence, safe to call twice.
    ///
    /// The order is the argument, and each step is here for one reason:
    ///
    /// 1. shut the gate, so a callback that has not started reading yet turns
    ///    itself around;
    /// 2. stop the unit, which is synchronous when it is not called from the
    ///    I/O thread and is therefore what rules out a callback beginning
    ///    after this point;
    /// 3. wait for anything already inside to come out, which is the only
    ///    thing that says so about a callback that was already running;
    /// 4. only then take the unit apart and let the memory go.
    ///
    /// Step 3 failing is not recoverable and not survivable by freeing
    /// anyway, so it stops the sequence and marks the stream to be leaked.
    fn teardown(&mut self) -> Result<(), Error> {
        self.shut_down(TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS)
    }

    /// The same with the wait spelled out, so a test can ask for a deadline it
    /// is willing to sit through.
    fn shut_down(&mut self, within: Duration, millis: u64) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
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
        // SAFETY: as above.
        let disposed = unsafe { sys::dispose_component(self.unit) };
        // the unit is gone, and with it the reason to keep the room
        self.claim = None;

        sys::check("AudioOutputUnitStop", stopped)?;
        sys::check("AudioUnitUninitialize", uninitialized)?;
        sys::check("AudioComponentInstanceDispose", disposed)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // nothing to report a status to from here; the record a teardown that
        // could not finish leaves behind is the leak below
        let _ = self.teardown();
        if self.leak {
            // A realtime thread may still be reading this. A buffer that is
            // never freed is a number in a memory graph; a buffer freed under
            // a callback is a crash in the middle of somebody's call.
            core::mem::forget(Arc::clone(&self.shared));
            // And a unit that was never disposed of is still the process's
            // one voice-processing unit.
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

    /// Samples waiting to be read. A number that keeps growing is a reader
    /// that is falling behind, and the drop counter is about to start moving.
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
}

/// Everything between opening the instance and initialising it.
///
/// The order is not free: enabling I/O comes before naming a device, naming a
/// device comes before the formats, and initialising comes last, because the
/// unit works out what it can do from what it has been told so far.
fn configure(unit: sys::Unit, config: &StreamConfig, shared: &Arc<Shared>) -> Result<(), Error> {
    let voice = config.kind == StreamKind::Voice;
    // the plain output unit plays and nothing else: its input stays off, so
    // it asks nothing of the microphone and needs no permission for it
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

/// The device under each half, on the global scope and before initialising:
/// the device is only settable while the unit is uninitialised, which is why
/// a device cannot be changed under a running stream and why
/// `Stream::recover` reopens. Element zero is the speaker's half and element
/// one the microphone's. Naming the speaker's device on element zero was seen
/// to leave element one on the system's default input, so the microphone's is
/// named on element one separately, and what each half is on is read back
/// from the unit once it is initialised rather than assumed from these
/// choices.
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

    // Read the format back rather than assume it took. A unit that quietly
    // settled on something else would not fail here, it would hand over
    // samples at a rate nobody expects, and that arrives as a call that sounds
    // wrong rather than as an error. The capture side is the one whose
    // octets per frame `record` sizes its render by; a unit that only plays
    // has only the other side.
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

/// The device one element of the unit is on: element zero is the speaker's
/// half and element one the microphone's, the same numbers the two buses
/// carry.
///
/// The header documents the property on the global scope without saying what
/// its elements are. The voice-processing unit answers on both, with the
/// default output on element zero and the default input on element one when
/// no device is named, which is what this relies on.
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

/// What `kAudioOutputUnitProperty_IsRunning` read back says about a unit the
/// stream started: running only on a non-zero answer. A read that failed is a
/// unit that is not there to answer — the media services were reset under it —
/// and that is not a running one either.
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
        // a tenth of a second at 48 kHz is 4800 samples, so the window has to
        // have been moved on from the 800 the narrowband channels were built
        // with — at 800 the peak below would have fallen off by now
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
        // Set after the frame was queued, which is the whole point: the ring
        // holds sixteen frames, and a volume applied on the way in would be
        // heard a third of a second after the slider moved.
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
        // the ring was drained rather than held back: unmuting has to be the
        // room, not four seconds of what was said while nobody was listening
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
        // The microphone's side of the microphone, at the microphone's rate.
        // Asked of the speaker instead, a Mac answers for an input side the
        // speaker does not have, at the speaker's rate.
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
        // what `recover` reads to decide whether to start what it opens: a
        // device that went mid-call has to come back mid-call, and `Lost` is
        // only ever reached from `Running`
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
    fn on_the_system_route(stream: &Stream) {
        use crate::device::Direction;
        use crate::hal::{default_device, render_delay};

        println!(
            "landed on {:?} for the speaker and {:?} for the microphone",
            stream.device(),
            stream.capture_device()
        );
        let (Ok(Some(speaker)), Ok(Some(microphone))) = (
            default_device(Direction::Output),
            default_device(Direction::Input),
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

    /// The default route end to end, everything in the one function on
    /// purpose: a process has room for one voice-processing unit, the test
    /// harness runs its tests on several threads, and a second unit is
    /// refused while the first is open.
    #[test]
    #[ignore = "opens the real default device"]
    fn a_loopback_on_the_default_device_moves_frames() {
        use super::{Stream, StreamConfig};
        use std::thread;
        use std::time::{Duration, Instant};

        for rate in [16_000, 32_000, 48_000] {
            let wanted = StreamFormat::with_frame_millis(rate, 20).expect("a twenty ms frame");
            let mut stream = Stream::open(StreamConfig::new(wanted)).expect("open at that rate");
            assert_eq!(stream.format(), wanted);
            stream.start().expect("start");
            stream.stop().expect("stop");
            // the explicit teardown, so that a drain that did not finish or a
            // framework call that complained shows up here rather than being
            // swallowed by a destructor
            stream.close().expect("close");
            println!("{wanted} opened and closed");
        }

        let format = StreamFormat::narrowband();
        let mut stream = Stream::open(StreamConfig::new(format)).expect("open the default device");
        println!("opened at {format}");
        println!("{}", stream.render_delay());
        assert!(
            stream.latency() < Duration::from_millis(500),
            "the device claims a delay no room has: {:?}",
            stream.latency()
        );
        #[cfg(target_os = "macos")]
        on_the_system_route(&stream);
        stream.start().expect("start the device");

        // the process's one voice unit is this one: a second is refused
        // without going near the framework, and a unit that only plays opens
        // beside it and runs
        assert_eq!(super::voice_units_open(), 1);
        assert!(matches!(
            Stream::open(StreamConfig::new(format)),
            Err(Error::Busy)
        ));
        let mut beside =
            Stream::open(StreamConfig::playback(format)).expect("a player beside the call");
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

        // Reopening is what a lost device is answered with, so it is worth
        // doing here where a device is real: the unit goes back, another one
        // comes up on the same choice, and the controls the caller is holding
        // still work and still say what they were set to.
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

        let wanted = std::env::var("SIPRAL_AUDIO_MIC").expect("SIPRAL_AUDIO_MIC names an input");
        let input = devices()
            .expect("the list")
            .into_iter()
            .find(|device| device.is_input() && device.name.contains(&wanted))
            .expect("an input named like that");
        let default_input = default_device(Direction::Input).expect("the default input");
        let default_output = default_device(Direction::Output).expect("the default output");
        assert_ne!(Some(input.id), default_input, "pick an input that is not the default");

        let format = StreamFormat::with_frame_millis(48_000, 20).expect("a twenty ms frame");
        let config =
            StreamConfig::new(format).capturing_from(input.uid.clone().expect("a uid to save"));
        let mut stream = Stream::open(config).expect("open with the microphone apart");
        println!(
            "speaker on {:?}, microphone on {:?}",
            stream.device(),
            stream.capture_device()
        );
        assert_eq!(stream.capture_device(), Ok(input.id));
        assert_eq!(stream.device().ok(), default_output);
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
        println!("{arrived} frames from {}; {}", input.name, stream.counters());
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
    /// The framework refuses all three teardown calls on one with `paramErr`
    /// and touches nothing, which is what makes the order, the idempotence and
    /// the drain testable without a device — the part of teardown that is this
    /// crate's, rather than the part that is CoreAudio's.
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
        // No device carries this identifier, so setting it fails with
        // kAudioUnitErr_InvalidPropertyValue and `open` has to unwind a unit
        // it had already created. There is one way out of that and it is the
        // teardown sequence; what this checks is that taking it neither hangs
        // nor falls over.
        let config = StreamConfig {
            device: DeviceChoice::Device(DeviceId::new(u32::MAX)),
            ..StreamConfig::default()
        };
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
}
