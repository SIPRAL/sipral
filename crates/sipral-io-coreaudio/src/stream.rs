// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One duplex voice-processing unit: samples in from the microphone, samples
//! out to the speaker, and nothing else.
//!
//! The unit is `kAudioUnitSubType_VoiceProcessingIO` on both platforms. That
//! is not a preference. It brings the system's own echo canceller, and
//! `docs/05-media.md` says in as many words that we attach an echo canceller
//! rather than write one; on iOS it is also what makes the audio session
//! behave the way a call should. The cost is that it is one unit driving one
//! device in both directions, so a caller wanting the microphone of one device
//! and the speaker of another has to build an aggregate device first, and that
//! is the operating system's business rather than ours.
//!
//! Two threads meet here. The framework's realtime thread runs [`play`] and
//! [`record`]; everything else runs on whatever thread the caller is on. They
//! share nothing but the two rings and the counters, and neither waits for the
//! other.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::cell::UnsafeCell;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::Arc;

use crate::abi;
use crate::counters::Counters;
// naming a device is a macOS notion; on iOS the route is the session's
#[cfg(target_os = "macos")]
use crate::device::DeviceId;
use crate::format::StreamFormat;
use crate::gate::{Gate, TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS};
use crate::ring::Ring;
use crate::status::{Error, OsStatus};
use crate::sys;

/// The most frames the unit is allowed to ask for at once.
///
/// It is also how big the buffer the input callback renders into is, so it has
/// to be decided before the stream opens rather than discovered. Apple's own
/// advice for iOS is this number, because a smaller one starts failing when
/// the screen locks.
const MAX_FRAMES_PER_SLICE: u32 = 4096;

/// Frames each ring holds unless the caller says otherwise: enough to ride out
/// a scheduling hiccup, short enough that a stalled reader is heard as a gap
/// rather than as a delay that never recovers.
const DEFAULT_DEPTH_FRAMES: usize = 16;

/// What to open, and how much slack to leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// Rate and frame length. Both directions use it.
    pub format: StreamFormat,
    /// Which device, or `None` for whatever the system is routing to now,
    /// which is what a softphone usually wants.
    ///
    /// macOS only, because naming a device is: on iOS the route is the audio
    /// session's and the application's, and there is no property to set. The
    /// field is absent there rather than ignored, so the request cannot be
    /// written down at all.
    #[cfg(target_os = "macos")]
    pub device: Option<DeviceId>,
    /// Frames of buffering between the device and the caller, per direction.
    pub depth_frames: usize,
}

impl StreamConfig {
    /// The system's current route, at the given format.
    #[must_use]
    pub const fn new(format: StreamFormat) -> Self {
        Self {
            format,
            #[cfg(target_os = "macos")]
            device: None,
            depth_frames: DEFAULT_DEPTH_FRAMES,
        }
    }
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self::new(StreamFormat::narrowband())
    }
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
    fn new(unit: sys::Unit, format: StreamFormat, depth_frames: usize) -> Self {
        let slice = usize::try_from(MAX_FRAMES_PER_SLICE).unwrap_or(0);
        // never smaller than one slice: a ring that cannot hold what the
        // device hands over in one callback would drop samples every time
        let samples = format
            .frame_samples()
            .saturating_mul(depth_frames.max(2))
            .max(slice);
        Self {
            unit,
            gate: Gate::new(),
            capture: Ring::new(samples),
            playback: Ring::new(samples),
            scratch: UnsafeCell::new(vec![0; slice].into_boxed_slice()),
            meters: Meters::default(),
        }
    }

    /// Fill the unit's buffer from the playback ring. Realtime thread.
    ///
    /// Returns whether what went out was silence, which is what the silence
    /// flag on the way back is for.
    ///
    /// # Safety
    /// `buffers` is whatever the framework passed, so it may be null; when it
    /// is not, its first buffer describes memory of `byte_size` octets that
    /// this callback owns for the length of the call.
    unsafe fn play(&self, frames: u32, buffers: *mut abi::BufferList) -> bool {
        // SAFETY: the caller's pointer, checked for null by `as_mut`.
        let Some(list) = (unsafe { buffers.as_mut() }) else {
            return true;
        };
        // one channel interleaved is what the stream format asks for, so the
        // unit hands back exactly one buffer; anything else is not our format
        let Some(buffer) = list.buffers.first_mut() else {
            return true;
        };
        if list.count != 1 || buffer.data.is_null() {
            return true;
        }
        let room = usize::try_from(buffer.byte_size).unwrap_or(0) / 2;
        let wanted = usize::try_from(frames).unwrap_or(0).min(room);
        if wanted == 0 {
            return true;
        }
        // SAFETY: `wanted` samples fit in the octets the buffer declares, and
        // the unit hands over memory aligned for the format it was given.
        let out = unsafe { core::slice::from_raw_parts_mut(buffer.data.cast::<i16>(), wanted) };
        let taken = self.playback.read(out);
        if let Some(tail) = out.get_mut(taken..) {
            tail.fill(0);
        }
        Meters::add(&self.meters.played, taken);
        Meters::add(&self.meters.playback_starved, wanted - taken);
        taken == 0
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
        let wanted = usize::try_from(frames).unwrap_or(0).min(scratch.len());
        if wanted == 0 {
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
        let Some(samples) = scratch.get(..delivered) else {
            return;
        };
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

/// Zero whatever the unit was going to play, without doing anything that could
/// itself go wrong. Reached only after a panic has already been caught.
///
/// # Safety
/// As [`Shared::play`].
unsafe fn blank(buffers: *mut abi::BufferList) {
    // SAFETY: checked for null.
    let Some(list) = (unsafe { buffers.as_mut() }) else {
        return;
    };
    let Some(buffer) = list.buffers.first_mut() else {
        return;
    };
    if buffer.data.is_null() {
        return;
    }
    let bytes = usize::try_from(buffer.byte_size).unwrap_or(0);
    // SAFETY: the buffer declares that many octets and nothing else is reading
    // them while this callback runs.
    unsafe { ptr::write_bytes(buffer.data.cast::<u8>(), 0, bytes) };
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
        unsafe { blank(buffers) };
        // SAFETY: as above.
        unsafe { mark_silent(flags) };
        return 0;
    };

    let outcome = panic::catch_unwind(AssertUnwindSafe(|| unsafe { shared.play(frames, buffers) }));
    let silent = outcome.unwrap_or_else(|_| {
        Meters::add(&shared.meters.panics, 1);
        // SAFETY: as in `play`; nothing here can panic a second time.
        unsafe { blank(buffers) };
        true
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
    running: bool,
    closed: bool,
    /// Set when teardown could not prove the callbacks were out. Nothing is
    /// then freed, ever.
    leak: bool,
}

// SAFETY: the unit handle belongs to this `Stream` alone, every method that
// touches it takes `&mut self`, and the framework accepts its control calls
// from any thread as long as they do not overlap.
unsafe impl Send for Stream {}

impl Stream {
    /// Open the device, without starting it.
    ///
    /// One per process. A softphone has one call's worth of audio at a time,
    /// and opening a second voice-processing unit while the first is alive was
    /// observed to block inside the framework rather than to fail.
    ///
    /// # Errors
    /// [`Error::UnitMissing`] when the system has no voice-processing unit,
    /// and [`Error::Call`] naming whichever framework call refused: a device
    /// that is gone, a format it will not take, a microphone the user has not
    /// granted.
    pub fn open(config: StreamConfig) -> Result<Self, Error> {
        let wanted = abi::ComponentDescription {
            component_type: abi::UNIT_TYPE_OUTPUT,
            subtype: abi::UNIT_SUBTYPE_VOICE_PROCESSING,
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
        let stream = Self {
            unit,
            shared: Arc::new(Shared::new(unit, config.format, config.depth_frames)),
            format: config.format,
            running: false,
            closed: false,
            leak: false,
        };
        configure(unit, &config, &stream.shared)?;
        Ok(stream)
    }

    /// What the stream was opened at.
    #[must_use]
    pub const fn format(&self) -> StreamFormat {
        self.format
    }

    /// Whether the device is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Start the device. Frames begin arriving immediately, so whatever is
    /// going to read them should be ready.
    ///
    /// # Errors
    /// [`Error::Call`] from `AudioOutputUnitStart`.
    pub fn start(&mut self) -> Result<(), Error> {
        if self.running {
            return Ok(());
        }
        // SAFETY: the unit is open and initialised.
        sys::check("AudioOutputUnitStart", unsafe {
            sys::start_unit(self.unit)
        })?;
        self.running = true;
        Ok(())
    }

    /// Stop the device. What is already in the rings stays there.
    ///
    /// # Errors
    /// [`Error::Call`] from `AudioOutputUnitStop`.
    pub fn stop(&mut self) -> Result<(), Error> {
        if !self.running {
            return Ok(());
        }
        // SAFETY: the unit is open and running.
        sys::check("AudioOutputUnitStop", unsafe { sys::stop_unit(self.unit) })?;
        self.running = false;
        Ok(())
    }

    /// What the device has been doing since it opened.
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.shared.meters.read()
    }

    /// Which device the stream actually landed on.
    ///
    /// Worth asking after a [`DeviceEvent::DefaultChanged`] arrives: a stream
    /// opened without naming a device follows the system route, and this is
    /// how to find out where that went.
    ///
    /// [`DeviceEvent::DefaultChanged`]: crate::DeviceEvent::DefaultChanged
    ///
    /// # Errors
    /// [`Error::Call`] from `AudioUnitGetProperty`.
    #[cfg(target_os = "macos")]
    pub fn device(&self) -> Result<DeviceId, Error> {
        let id: u32 = get(
            self.unit,
            "AudioUnitGetProperty (CurrentDevice)",
            abi::PROPERTY_CURRENT_DEVICE,
            abi::SCOPE_GLOBAL,
            0,
        )?;
        Ok(DeviceId::new(id))
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
        self.running = false;

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
    let enabled: u32 = 1;
    set(
        unit,
        "AudioUnitSetProperty (EnableIO, input)",
        abi::PROPERTY_ENABLE_IO,
        abi::SCOPE_INPUT,
        abi::BUS_INPUT,
        &enabled,
    )?;
    set(
        unit,
        "AudioUnitSetProperty (EnableIO, output)",
        abi::PROPERTY_ENABLE_IO,
        abi::SCOPE_OUTPUT,
        abi::BUS_OUTPUT,
        &enabled,
    )?;

    // Global scope, element zero, and before initialising: for this unit the
    // device is one property covering both directions, and it is only settable
    // while the unit is uninitialised.
    #[cfg(target_os = "macos")]
    if let Some(device) = config.device {
        let id = device.get();
        set(
            unit,
            "AudioUnitSetProperty (CurrentDevice)",
            abi::PROPERTY_CURRENT_DEVICE,
            abi::SCOPE_GLOBAL,
            0,
            &id,
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

    // The scopes read the way the unit sees them, not the way we do: what the
    // caller reads off bus 1 is that bus's output, and what the caller writes
    // to bus 0 is that bus's input.
    let description = abi::StreamDescription::mono_pcm(config.format.sample_rate_hz());
    set(
        unit,
        "AudioUnitSetProperty (StreamFormat, capture)",
        abi::PROPERTY_STREAM_FORMAT,
        abi::SCOPE_OUTPUT,
        abi::BUS_INPUT,
        &description,
    )?;
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

    // SAFETY: the unit is open and fully described.
    sys::check("AudioUnitInitialize", unsafe { sys::initialize_unit(unit) })?;

    // Read the format back rather than assume it took. A unit that quietly
    // settled on something else would not fail here, it would hand over
    // samples at a rate nobody expects, and that arrives as a call that sounds
    // wrong rather than as an error.
    let settled: abi::StreamDescription = get(
        unit,
        "AudioUnitGetProperty (StreamFormat)",
        abi::PROPERTY_STREAM_FORMAT,
        abi::SCOPE_OUTPUT,
        abi::BUS_INPUT,
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
        DEFAULT_DEPTH_FRAMES, MAX_FRAMES_PER_SLICE, Shared, Stream, StreamConfig, play, record,
    };
    use crate::abi;
    use crate::format::StreamFormat;
    use crate::status::Error;
    use core::ffi::c_void;
    use core::time::Duration;
    use std::ptr;
    use std::sync::Arc;

    #[cfg(target_os = "macos")]
    use crate::device::DeviceId;

    fn shared() -> Arc<Shared> {
        // a null unit is fine as long as nothing calls into the framework,
        // which is true of everything but `record`
        Arc::new(Shared::new(
            ptr::null_mut(),
            StreamFormat::narrowband(),
            DEFAULT_DEPTH_FRAMES,
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
        assert_eq!(config.device, None);
    }

    #[test]
    fn the_rings_are_never_smaller_than_one_slice() {
        let shared = Shared::new(ptr::null_mut(), StreamFormat::narrowband(), 1);
        let slice = usize::try_from(MAX_FRAMES_PER_SLICE).unwrap();
        assert!(shared.capture.free() >= slice);
        assert!(shared.playback.free() >= slice);
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

    /// The only test here that touches hardware, and everything it checks is
    /// in the one function on purpose: two voice-processing units open at once
    /// in one process block inside the framework, and the test harness runs
    /// its tests on several threads.
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
        #[cfg(target_os = "macos")]
        println!("landed on {:?}", stream.device());
        stream.start().expect("start the device");

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
        }

        stream.stop().expect("stop the device");
        let counters = stream.counters();
        println!("{arrived} frames in, {queued} frames out, loudest sample {loudest}");
        println!("{counters}");

        assert!(arrived > 0, "no frames arrived from the microphone");
        assert!(counters.played > 0, "nothing was taken for the speaker");
        assert_eq!(counters.panics, 0);

        stream.close().expect("close the device");
    }

    /// A stream around a null unit.
    ///
    /// The framework refuses all three teardown calls on one with `paramErr`
    /// and touches nothing, which is what makes the order, the idempotence and
    /// the drain testable without a device — the part of teardown that is this
    /// crate's, rather than the part that is CoreAudio's.
    fn detached() -> Stream {
        Stream {
            unit: ptr::null_mut(),
            shared: shared(),
            format: StreamFormat::narrowband(),
            running: false,
            closed: false,
            leak: false,
        }
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
            device: Some(DeviceId::new(u32::MAX)),
            ..StreamConfig::default()
        };
        assert!(Stream::open(config).is_err(), "a device that is not there");
    }

    #[test]
    fn a_render_that_arrives_during_teardown_plays_silence_and_takes_nothing() {
        let shared = shared();
        assert!(shared.playback.write_frame(&[5, 5, 5, 5]));
        shared.gate.close();

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
                4,
                &raw mut list,
            )
        };

        assert_eq!(status, 0);
        // zeroed rather than filled, and the ring was not touched
        assert_eq!(samples, [0, 0, 0, 0]);
        assert_eq!(flags, abi::RENDER_ACTION_OUTPUT_IS_SILENCE);
        assert_eq!(shared.playback.filled(), 4);
        assert_eq!(shared.meters.read().played, 0);
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

    #[test]
    fn a_buffer_list_the_format_does_not_match_is_left_alone() {
        let shared = shared();
        assert!(shared.playback.write_frame(&[7, 7, 7, 7]));

        let mut samples = [-1i16; 4];
        let mut list = abi::BufferList {
            count: 2,
            buffers: [abi::Buffer {
                channels: 2,
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
                4,
                &raw mut list,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(samples, [-1, -1, -1, -1]);
        assert_eq!(flags, abi::RENDER_ACTION_OUTPUT_IS_SILENCE);
        assert_eq!(shared.meters.read().played, 0);
    }
}
