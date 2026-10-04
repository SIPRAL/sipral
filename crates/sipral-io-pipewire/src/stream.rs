// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One node, in one direction: samples in from a source, or samples out to a
//! sink, and nothing else.
//!
//! One direction, because a PipeWire node is one: `media.class` is
//! `Audio/Source` or `Audio/Sink`, never both. A duplex type here would be two
//! of these in a coat, and it would hide the case a softphone most needs to
//! get right — microphone on one node, speaker on another — so there are two
//! types and the caller holds both, the same as `sipral-io-wasapi`.
//!
//! Each stream is a `pw_stream` of its own, on a `pw_thread_loop` of its own,
//! made with `pw_stream_new_simple`, which gives it its own context and its
//! own connection to the daemon. That costs a socket per direction and buys
//! a teardown that is local: closing one stream stops one loop and touches
//! nothing another stream is using.
//!
//! Three threads meet here. The caller's, which opens, starts, stops, reads
//! and writes. The thread loop's, which PipeWire runs every event on except
//! one — `state_changed` and `param_changed` arrive there, with the loop's
//! lock held. And PipeWire's realtime data thread, which runs `process`,
//! because the stream is connected with `PW_STREAM_FLAG_RT_PROCESS`: that is
//! the only way a period is never late behind whatever else the loop is
//! doing, and it is why `process` touches nothing but the ring, the level
//! channel, a handful of atomics, and the calls `pipewire/stream.h` marks RT
//! safe — `pw_stream_dequeue_buffer`, `pw_stream_queue_buffer` and
//! `pw_stream_get_time_n`. It never takes a lock and never allocates.
//!
//! The format is offered as one fixed object — mono, signed sixteen-bit, at
//! the rate asked for — and PipeWire's adapter converts between that and
//! whatever the graph runs. So unlike a WASAPI stream, what a caller asked for
//! is what a caller gets, and resampling to the graph's rate is PipeWire's
//! work rather than a number the caller has to size its frames by.

use core::ffi::{CStr, c_char, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use std::ffi::CString;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use crate::abi::{
    self, AudioFormat, FormatPod, PwBuffer, PwStreamEvents, PwTime, SPA_AUDIO_FORMAT_S16, SpaPod,
    read_audio_format,
};
use crate::counters::Counters;
use crate::device::{DeviceChoice, DeviceId, Direction, StreamEvent};
use crate::format::StreamFormat;
use crate::gate::{Gate, TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS};
use crate::latency::{Latency, Rate, RenderDelay};
use crate::level::{Channel, Controls, window_samples};
use crate::registry::{self, ensure_init, new_properties};
use crate::ring::Ring;
use crate::status::Error;
use crate::sys::{self, PwStream, PwThreadLoop};

/// Frames the ring holds unless the caller says otherwise: enough to ride out
/// a scheduling hiccup, short enough that a stalled reader is heard as a gap
/// rather than as a delay that never recovers.
const DEFAULT_DEPTH_FRAMES: usize = 16;

/// How long `open` waits for the daemon to take the stream on. Negotiation is
/// a couple of round trips on a working desktop; whole seconds are for a
/// daemon that is not answering.
const CONNECT_WAIT: Duration = Duration::from_secs(5);

/// Samples the capture side scales at a time, on the realtime thread's own
/// stack: a quantum is copied out of PipeWire's buffer through this rather
/// than scaled where it lies, because that memory is the graph's.
const SCRATCH_SAMPLES: usize = 512;

/// The stream's listener. `static` because the hook `pw_stream_new_simple`
/// registers keeps a pointer to it for the stream's whole life — see
/// [`crate::abi::SpaHook`].
static STREAM_EVENTS: PwStreamEvents = PwStreamEvents {
    version: abi::PW_VERSION_STREAM_EVENTS,
    destroy: None,
    state_changed: Some(on_state_changed),
    control_info: None,
    io_changed: None,
    param_changed: Some(on_param_changed),
    add_buffer: None,
    remove_buffer: None,
    process: Some(on_process),
    drained: None,
    command: None,
    trigger_done: None,
};

/// What to open, and how much slack to leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// Rate and frame length wanted, which is what is delivered: PipeWire's
    /// adapter converts to and from whatever the graph runs.
    pub format: StreamFormat,
    /// Which node, and what to do when it is not there. The default is the
    /// session's default node as the stream opens, which is what a softphone
    /// usually wants.
    pub device: DeviceChoice,
    /// Frames of buffering between the node and the caller.
    ///
    /// This sizes the ring in this crate and nothing else. The graph's own
    /// buffering is the quantum, which the stream asks to be one frame long
    /// with `node.latency` — a request the graph may round, never a promise.
    pub depth_frames: usize,
}

impl StreamConfig {
    /// The session's route — its default node as the stream opens — at the
    /// given format.
    #[must_use]
    pub const fn new(format: StreamFormat) -> Self {
        Self {
            format,
            device: DeviceChoice::System,
            depth_frames: DEFAULT_DEPTH_FRAMES,
        }
    }

    /// A named node, at the given format, and nothing else if it is not
    /// there.
    #[must_use]
    pub fn on(device: DeviceId, format: StreamFormat) -> Self {
        Self {
            device: DeviceChoice::Device(device),
            ..Self::new(format)
        }
    }

    /// A saved selection, at the given format: that node when the graph has
    /// it, and the session's route when it does not.
    ///
    /// This is the one to build from a [`DeviceId`] read out of a
    /// configuration file. A headset that powers off takes its node away and
    /// brings it back under the same `node.name`, and in between a call still
    /// has to have somewhere to go.
    #[must_use]
    pub fn preferring(device: DeviceId, format: StreamFormat) -> Self {
        Self {
            device: DeviceChoice::Preferred(device),
            ..Self::new(format)
        }
    }
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self::new(StreamFormat::narrowband())
    }
}

/// What the realtime thread has to say, in numbers because it cannot speak.
///
/// Relaxed throughout: nothing depends on having seen them, and a reader one
/// increment behind is reading a number that was true a moment ago.
#[derive(Default)]
struct Meters {
    captured: AtomicU64,
    capture_dropped: AtomicU64,
    played: AtomicU64,
    playback_starved: AtomicU64,
    buffer_misses: AtomicU64,
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
            buffer_misses: self.buffer_misses.load(Ordering::Relaxed),
            panics: self.panics.load(Ordering::Relaxed),
        }
    }
}

/// The last `pw_time` the realtime thread read, kept field by field.
///
/// Each field is its own relaxed atomic, so a reader can see one field from
/// one cycle and the next from the following one. That is a few samples of
/// disagreement in a figure that moves only when the graph's quantum or
/// topology does, and it keeps the realtime side to plain stores.
#[derive(Default)]
struct Timing {
    delay: AtomicU64,
    rate_num: AtomicU32,
    rate_denom: AtomicU32,
    queued: AtomicU64,
    buffered: AtomicU64,
}

impl Timing {
    fn store(&self, time: &PwTime) {
        // a negative delay is a capture stream's clock running ahead of the
        // device it reads, by less than a cycle; as a distance back in time
        // it is zero
        self.delay
            .store(u64::try_from(time.delay).unwrap_or(0), Ordering::Relaxed);
        self.rate_num.store(time.rate.num, Ordering::Relaxed);
        self.rate_denom.store(time.rate.denom, Ordering::Relaxed);
        self.queued.store(time.queued, Ordering::Relaxed);
        self.buffered.store(time.buffered, Ordering::Relaxed);
    }

    fn read(&self, stream_rate_hz: u32) -> Latency {
        Latency {
            delay_ticks: self.delay.load(Ordering::Relaxed),
            rate: Rate {
                num: self.rate_num.load(Ordering::Relaxed),
                denom: self.rate_denom.load(Ordering::Relaxed),
            },
            queued_frames: self.queued.load(Ordering::Relaxed),
            buffered_frames: self.buffered.load(Ordering::Relaxed),
            stream_rate_hz,
        }
    }
}

/// Everything the three threads touch.
///
/// The `pw_stream` is handed a pointer to this as its callbacks' `data`, and
/// PipeWire keeps that pointer for the stream's whole life without Rust
/// seeing the borrow. The `Arc` is what the owner holds, and it is dropped
/// only after the stream is destroyed and the loop's thread is joined — or,
/// when the realtime thread cannot be shown to have left, never.
struct Shared {
    direction: Direction,
    format: StreamFormat,
    gate: Gate,
    /// The gain, the mute and the meter. Behind an `Arc` of its own so that a
    /// [`Controls`] handed out survives the stream being recovered.
    channel: Arc<Channel>,
    ring: Ring,
    meters: Meters,
    timing: Timing,
    /// For `pw_thread_loop_signal`, which wakes an owner waiting in `open`.
    thread_loop: *mut PwThreadLoop,
    /// Set once, right after `pw_stream_new_simple`, before anything that
    /// could make PipeWire call `process`.
    stream: AtomicPtr<PwStream>,
    /// The last `enum pw_stream_state` PipeWire reported.
    state: AtomicI32,
    /// Whether the stream ever reached `PAUSED`: taken on by the daemon.
    connected: AtomicBool,
    /// Set by the owner before it destroys the stream, so that the state
    /// change destroying it causes is not read as the node going away.
    closing: AtomicBool,
    /// Whether the stream went down on its own after it was taken on.
    lost: AtomicBool,
    /// What PipeWire said when the stream went into its error state, or
    /// what this crate found wrong with the format it settled on. Written on
    /// the loop's thread only, read by the owner.
    error: Mutex<Option<String>>,
}

// SAFETY: `thread_loop` is only used for `pw_thread_loop_signal`, which the
// header gives callbacks for waking a waiter, and `stream` only for the RT
// safe calls `process` makes on the thread PipeWire runs it on. Everything
// else is atomics, a `Mutex`, and types that are `Sync` already.
unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

impl Shared {
    /// One quantum: take a buffer, fill or drain it, give it back, and note
    /// what the graph now says about time.
    fn process(&self) {
        let stream = self.stream.load(Ordering::Acquire);
        if stream.is_null() {
            return;
        }
        // SAFETY: a live stream, on the thread PipeWire calls `process` on;
        // RT safe per `pipewire/stream.h`.
        let buffer = unsafe { sys::stream_dequeue_buffer(stream) };
        if buffer.is_null() {
            Meters::add(&self.meters.buffer_misses, 1);
            return;
        }
        // SAFETY: `buffer` was just dequeued from this stream and is ours
        // until it is queued back below.
        unsafe {
            match self.direction {
                Direction::Input => self.capture(buffer),
                Direction::Output => self.play(buffer),
            }
            sys::stream_queue_buffer(stream, buffer);
        }
        let mut time = PwTime::default();
        // SAFETY: a live stream and a `pw_time` of the size being declared;
        // RT safe.
        if unsafe { sys::stream_get_time_n(stream, &raw mut time, size_of::<PwTime>()) } >= 0 {
            self.timing.store(&time);
        }
    }

    /// The first data block of a dequeued buffer, if it has mapped memory.
    ///
    /// # Safety
    /// `buffer` is a `pw_buffer` dequeued from this stream and not yet queued
    /// back.
    unsafe fn first_data<'a>(buffer: *mut PwBuffer) -> Option<&'a mut abi::SpaData> {
        // SAFETY: per this function's contract, `buffer` and the `spa_buffer`
        // it points to are PipeWire's and valid until queued back; every
        // stream here is mono and interleaved, one `spa_data` per buffer.
        unsafe {
            let spa = (*buffer).buffer;
            if spa.is_null() || (*spa).n_datas == 0 || (*spa).datas.is_null() {
                return None;
            }
            let data = &mut *(*spa).datas;
            (!data.data.is_null() && !data.chunk.is_null()).then_some(data)
        }
    }

    /// Copy what the source produced into the ring, through the gain.
    ///
    /// # Safety
    /// As [`Self::first_data`].
    unsafe fn capture(&self, buffer: *mut PwBuffer) {
        // SAFETY: forwarded.
        let Some(data) = (unsafe { Self::first_data(buffer) }) else {
            Meters::add(&self.meters.buffer_misses, 1);
            return;
        };
        // SAFETY: a non-null chunk of a dequeued buffer.
        let chunk = unsafe { &*data.chunk };
        // `spa/buffer/buffer.h`: the chunk's offset and size "should be
        // clamped" to the data's own size, so they are
        let offset = chunk.offset.min(data.maxsize);
        let size = chunk.size.min(data.maxsize - offset);
        let samples = usize::try_from(size / 2).unwrap_or(0);
        // SAFETY: `data.data` maps `maxsize` bytes, and offset + size is
        // within it by the clamp above.
        let start =
            unsafe { data.data.byte_add(usize::try_from(offset).unwrap_or(0)) }.cast::<i16>();
        if !start.is_aligned() {
            Meters::add(&self.meters.buffer_misses, 1);
            return;
        }
        // SAFETY: `samples` whole sixteen-bit samples from an aligned start,
        // within the mapped block, which the graph does not touch while this
        // buffer is dequeued.
        let source = unsafe { core::slice::from_raw_parts(start, samples) };
        let mut scratch = [0_i16; SCRATCH_SAMPLES];
        for piece in source.chunks(SCRATCH_SAMPLES) {
            let Some(block) = scratch.get_mut(..piece.len()) else {
                break;
            };
            block.copy_from_slice(piece);
            self.channel.apply(block, block.len());
            let taken = self.ring.write(block);
            Meters::add(&self.meters.captured, taken);
            Meters::add(&self.meters.capture_dropped, block.len() - taken);
        }
    }

    /// Fill the buffer the sink will play from the ring, through the gain,
    /// and pad with silence what the ring did not have.
    ///
    /// # Safety
    /// As [`Self::first_data`].
    unsafe fn play(&self, buffer: *mut PwBuffer) {
        // SAFETY: forwarded.
        let Some(data) = (unsafe { Self::first_data(buffer) }) else {
            Meters::add(&self.meters.buffer_misses, 1);
            return;
        };
        let room = usize::try_from(data.maxsize / 2).unwrap_or(0);
        // SAFETY: `buffer` is the dequeued buffer `data` came from.
        let requested = usize::try_from(unsafe { (*buffer).requested }).unwrap_or(usize::MAX);
        // `requested` is the resampler's own demand for this quantum, in
        // frames of this stream's rate, and zero when it has none
        let wanted = if requested == 0 {
            room
        } else {
            room.min(requested)
        };
        let start = data.data.cast::<i16>();
        if !start.is_aligned() {
            Meters::add(&self.meters.buffer_misses, 1);
            return;
        }
        // SAFETY: `wanted` samples fit in the `maxsize` bytes mapped at an
        // aligned `data.data`, which is this stream's to write while the
        // buffer is dequeued.
        let out = unsafe { core::slice::from_raw_parts_mut(start, wanted) };
        let got = self.ring.read(out);
        if let Some(missing) = out.get_mut(got..) {
            missing.fill(0);
        }
        self.channel.apply(out, wanted);
        Meters::add(&self.meters.played, got);
        Meters::add(&self.meters.playback_starved, wanted - got);

        let bytes = u32::try_from(wanted * 2).unwrap_or(0);
        // SAFETY: the chunk of the dequeued buffer, which the stream reads
        // once the buffer is queued back.
        unsafe {
            let chunk = &mut *data.chunk;
            chunk.offset = 0;
            chunk.stride = 2;
            chunk.size = bytes;
            // `pipewire/stream.h` advises the frame count here, and it is
            // what `pw_time.queued` is summed from
            (*buffer).size = u64::try_from(wanted).unwrap_or(0);
        }
    }

    /// Read the error message, if there is one.
    fn error(&self) -> Option<String> {
        self.error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Record an error, for `open` and `start` to report.
    fn fail(&self, message: String) {
        *self.error.lock().unwrap_or_else(PoisonError::into_inner) = Some(message);
    }
}

/// The state the stream's callbacks were given.
///
/// # Safety
/// `data` is the `data` pointer `Session::open` handed `pw_stream_new_simple`:
/// an `Arc<Shared>`'s pointee, kept alive by the owner until the stream is
/// destroyed and its thread loop joined, or for ever.
unsafe fn shared<'a>(data: *mut c_void) -> &'a Shared {
    // SAFETY: per this function's own contract.
    unsafe { &*data.cast::<Shared>() }
}

/// `pw_stream_events.process`, on the realtime data thread.
unsafe extern "C" fn on_process(data: *mut c_void) {
    // SAFETY: registered with a `Shared`, per `shared`'s contract.
    let shared = unsafe { shared(data) };
    let Some(_pass) = shared.gate.enter() else {
        return;
    };
    // A panic cannot be allowed to cross back into C, and a stream that
    // stopped on one would be a call that went silent with nothing said. It
    // is counted instead, and the counter above zero is the bug report.
    if panic::catch_unwind(AssertUnwindSafe(|| shared.process())).is_err() {
        Meters::add(&shared.meters.panics, 1);
    }
}

/// `pw_stream_events.state_changed`, on the loop's thread with its lock held.
unsafe extern "C" fn on_state_changed(
    data: *mut c_void,
    _old: i32,
    state: i32,
    error: *const c_char,
) {
    // SAFETY: registered with a `Shared`, per `shared`'s contract.
    let shared = unsafe { shared(data) };
    shared.state.store(state, Ordering::SeqCst);
    if state == abi::PW_STREAM_STATE_ERROR {
        let message = if error.is_null() {
            String::new()
        } else {
            // SAFETY: a non-null error is a NUL-terminated string for the
            // length of this call.
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        };
        shared.fail(message);
    }
    if state == abi::PW_STREAM_STATE_PAUSED || state == abi::PW_STREAM_STATE_STREAMING {
        shared.connected.store(true, Ordering::SeqCst);
    }
    // Taken on and then gone, without this crate asking: the session manager
    // destroyed the stream's node because its target went away, which is
    // what `node.dont-reconnect` tells it to do, or the daemon itself went.
    if (state == abi::PW_STREAM_STATE_ERROR || state == abi::PW_STREAM_STATE_UNCONNECTED)
        && shared.connected.load(Ordering::SeqCst)
        && !shared.closing.load(Ordering::SeqCst)
    {
        shared.lost.store(true, Ordering::SeqCst);
    }
    // SAFETY: the loop is running — this is its thread — and this is the
    // header's way for a callback to wake a waiter.
    unsafe { sys::thread_loop_signal(shared.thread_loop, false) };
}

/// `pw_stream_events.param_changed`, on the loop's thread.
///
/// Only the settled format is read, and only to check it. The adapter is
/// asked for one fixed format and converts everything else, so the format
/// that comes back is the one offered; one that is not would be samples of
/// the wrong shape in the ring, which is an error to report rather than a
/// signal to reinterpret.
unsafe extern "C" fn on_param_changed(data: *mut c_void, id: u32, param: *const SpaPod) {
    if id != abi::SPA_PARAM_FORMAT || param.is_null() {
        return;
    }
    // SAFETY: registered with a `Shared`, per `shared`'s contract; a
    // non-null param is a pod whose header says how long its body is, valid
    // for the length of this call.
    let (shared, bytes) = unsafe {
        let body = usize::try_from((*param).size).unwrap_or(0);
        (
            shared(data),
            core::slice::from_raw_parts(param.cast::<u8>(), size_of::<SpaPod>() + body),
        )
    };
    let wanted = AudioFormat {
        format: SPA_AUDIO_FORMAT_S16,
        rate: shared.format.sample_rate_hz(),
        channels: 1,
    };
    if let Some(settled) = read_audio_format(bytes)
        && settled != wanted
    {
        shared.fail(format!(
            "the graph settled on format {}, {} Hz, {} channel(s), not the S16 mono {} Hz offered",
            settled.format, settled.rate, settled.channels, wanted.rate
        ));
        // SAFETY: as in `on_state_changed`.
        unsafe { sys::thread_loop_signal(shared.thread_loop, false) };
    }
}

/// The flags a stream is connected with.
///
/// `PW_STREAM_FLAG_DONT_RECONNECT` only on a stream pinned to a node: that
/// is the stream whose node going is reported rather than papered over. On
/// one left to follow the session — which happens only when the session
/// named no default to pin it to — the flag does harm: WirePlumber 0.5.8
/// answers a default change for such a stream by linking the new default
/// and keeping the old link, so the stream would end up on two nodes at
/// once.
const fn connect_flags(pinned: bool) -> u32 {
    let flags = abi::PW_STREAM_FLAG_AUTOCONNECT
        | abi::PW_STREAM_FLAG_INACTIVE
        | abi::PW_STREAM_FLAG_MAP_BUFFERS
        | abi::PW_STREAM_FLAG_RT_PROCESS;
    if pinned {
        flags | abi::PW_STREAM_FLAG_DONT_RECONNECT
    } else {
        flags
    }
}

/// The half of a stream that is the same in both directions.
struct Session {
    shared: Arc<Shared>,
    thread_loop: *mut PwThreadLoop,
    /// Null only if `pw_stream_new_simple` refused.
    stream: *mut PwStream,
    /// The format offered to `pw_stream_connect`. Kept for the stream's
    /// life: the header does not say whether the call copies its params, so
    /// this does not rely on it.
    offer: Box<FormatPod>,
    /// How far `open` got, and whether teardown has run.
    phase: Phase,
    /// Kept so that a recover can ask for the same thing again and have the
    /// choice resolved against the graph as it is then.
    config: StreamConfig,
    /// The node the choice resolved to, or `None` when it fell back to a
    /// session that had named no default.
    target: Option<DeviceId>,
    /// Held here as well as in `shared` so that a recover carries the volume
    /// and the mute across.
    channel: Arc<Channel>,
    /// Whether the owner has asked for it to be running, which survives the
    /// node going away — a stream carrying a call when that happened should
    /// carry one after it is recovered.
    started: bool,
    /// Whether the loss has been handed over, so it is reported once.
    loss_reported: bool,
}

/// Where a session is in its life, which is what teardown has to know.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The loop exists and its thread was never started.
    Built,
    /// The loop's thread is running, and has to be stopped.
    Running,
    /// Torn down.
    Closed,
}

// SAFETY: the PipeWire objects are only touched with the thread loop's lock
// held, which any thread may take — that is what a thread loop is for — and
// `shared` is `Send + Sync`. A stream has to be able to move to the thread
// that carries the call.
unsafe impl Send for Session {}

impl Session {
    /// Open a stream on the node the choice names, and leave it inactive.
    fn open(
        config: &StreamConfig,
        direction: Direction,
        channel: Arc<Channel>,
    ) -> Result<Self, Error> {
        ensure_init();
        let target = registry::resolve(&config.device, direction)?;
        Self::open_on(config, direction, channel, target)
    }

    /// The rest of [`Self::open`], given a target already resolved.
    ///
    /// Split out so a test can ask `registry::resolve` for a node, make it
    /// vanish, and open on the answer regardless — the race
    /// `check_target_survived` closes, reached without having to win it: the
    /// same gap between a resolved target and `pw_stream_connect` reaching
    /// the daemon that [`Self::open`] itself leaves open, just wide enough
    /// here to always land in it.
    fn open_on(
        config: &StreamConfig,
        direction: Direction,
        channel: Arc<Channel>,
        target: Option<DeviceId>,
    ) -> Result<Self, Error> {
        let format = config.format;
        channel.set_window(window_samples(format.sample_rate_hz()));
        let ring = Ring::new(
            format
                .frame_samples()
                .saturating_mul(config.depth_frames.max(2)),
        );

        let name = match direction {
            Direction::Input => c"sipral-pw-capture",
            Direction::Output => c"sipral-pw-playback",
        };
        // SAFETY: a NUL-terminated name, and no properties.
        let thread_loop = unsafe { sys::thread_loop_new(name.as_ptr(), ptr::null()) };
        if thread_loop.is_null() {
            return Err(Error::Refused {
                call: "pw_thread_loop_new",
            });
        }
        let shared = Arc::new(Shared {
            direction,
            format,
            gate: Gate::new(),
            channel: Arc::clone(&channel),
            ring,
            meters: Meters::default(),
            timing: Timing::default(),
            thread_loop,
            stream: AtomicPtr::new(ptr::null_mut()),
            state: AtomicI32::new(abi::PW_STREAM_STATE_UNCONNECTED),
            connected: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            lost: AtomicBool::new(false),
            error: Mutex::new(None),
        });
        // From here on, dropping `session` is what undoes any of it.
        let mut session = Self {
            shared,
            thread_loop,
            stream: ptr::null_mut(),
            offer: Box::new(FormatPod::new(format.sample_rate_hz())),
            phase: Phase::Built,
            config: config.clone(),
            target,
            channel,
            started: false,
            loss_reported: false,
        };
        session.create(direction)?;
        session.connect(direction)?;
        Ok(session)
    }

    /// Make the `pw_stream`, before the loop runs, so no lock is needed yet.
    fn create(&mut self, direction: Direction) -> Result<(), Error> {
        let format = self.config.format;
        let latency = CString::new(format!(
            "{}/{}",
            format.frame_samples(),
            format.sample_rate_hz()
        ))
        .map_err(|_| Error::Refused {
            call: "pw_properties_set",
        })?;
        let target = match &self.target {
            Some(id) => Some(CString::new(id.as_str()).map_err(|_| Error::NoDevice)?),
            None => None,
        };
        let category = match direction {
            Direction::Input => c"Capture",
            Direction::Output => c"Playback",
        };
        let mut pairs: Vec<(&CStr, &CStr)> = vec![
            (abi::PW_KEY_MEDIA_TYPE, c"Audio"),
            (abi::PW_KEY_MEDIA_CATEGORY, category),
            (abi::PW_KEY_MEDIA_ROLE, c"Communication"),
            (abi::PW_KEY_NODE_LATENCY, latency.as_c_str()),
        ];
        if let Some(target) = &target {
            pairs.push((abi::PW_KEY_TARGET_OBJECT, target.as_c_str()));
            pairs.push((abi::KEY_NODE_DONT_FALLBACK, c"true"));
        }
        let props = new_properties(&pairs)?;
        // SAFETY: `thread_loop` is live and not yet started.
        let pw_loop = unsafe { sys::thread_loop_get_loop(self.thread_loop) };
        let data = ptr::from_ref(self.shared.as_ref())
            .cast_mut()
            .cast::<c_void>();
        let name = match direction {
            Direction::Input => c"Sipral microphone",
            Direction::Output => c"Sipral speaker",
        };
        // SAFETY: the loop is live and not running, so nothing races this;
        // `props` is handed over and owned by the call; the events table is
        // a `static`; `data` is the `Shared` this session keeps alive for
        // longer than the stream.
        self.stream = unsafe {
            sys::stream_new_simple(
                pw_loop,
                name.as_ptr(),
                props,
                &raw const STREAM_EVENTS,
                data,
            )
        };
        if self.stream.is_null() {
            return Err(Error::Refused {
                call: "pw_stream_new_simple",
            });
        }
        self.shared.stream.store(self.stream, Ordering::Release);
        Ok(())
    }

    /// Start the loop, connect, and wait for the daemon to take the stream on.
    fn connect(&mut self, direction: Direction) -> Result<(), Error> {
        // SAFETY: `thread_loop` is live and not yet started.
        sys::check("pw_thread_loop_start", unsafe {
            sys::thread_loop_start(self.thread_loop)
        })?;
        self.phase = Phase::Running;

        // SAFETY: the loop is running, so the stream is touched under its
        // lock; the waits below release it while they wait.
        unsafe { sys::thread_loop_lock(self.thread_loop) };
        let outcome = self.connect_locked(direction);
        // SAFETY: balances the lock above.
        unsafe { sys::thread_loop_unlock(self.thread_loop) };
        outcome?;
        self.check_target_survived()
    }

    /// Close the race `open`'s own two steps leave open: `registry::resolve`
    /// names a node from a snapshot, and everything between that and this
    /// call taking the loop's lock — building properties, starting the
    /// thread, PipeWire answering `PW_ID_CORE`'s round trip — is time enough
    /// for the node to be gone before `pw_stream_connect` ever reaches the
    /// session manager. `target.object` is a property, not a promise it is
    /// checked against anything, and `node.dont-fallback` (`abi.rs`) means a
    /// target it cannot find is left unlinked rather than rerouted — which
    /// changes nothing about the stream's own state, so `on_state_changed`
    /// never sees it and never sets [`Shared::lost`]. One look at the
    /// registry, taken the moment the stream reports itself connected,
    /// turns that silent, unlinked stream into the same
    /// [`StreamEvent::DeviceLost`] a node that goes later is reported as.
    fn check_target_survived(&self) -> Result<(), Error> {
        let Some(target) = &self.target else {
            return Ok(());
        };
        let direction = self.shared.direction;
        let present = registry::devices()?
            .iter()
            .any(|device| device.direction == direction && &device.id == target);
        if !present {
            self.shared.lost.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    fn connect_locked(&mut self, direction: Direction) -> Result<(), Error> {
        let pw_direction = match direction {
            Direction::Input => abi::PW_DIRECTION_INPUT,
            Direction::Output => abi::PW_DIRECTION_OUTPUT,
        };
        let flags = connect_flags(self.target.is_some());
        let params = [self.offer.as_ptr()];
        // SAFETY: a live stream, under the loop's lock; one param, the format
        // this session keeps alive for as long as the stream.
        sys::check("pw_stream_connect", unsafe {
            sys::stream_connect(
                self.stream,
                pw_direction,
                abi::PW_ID_ANY,
                flags,
                params.as_ptr(),
                1,
            )
        })?;
        let started = Instant::now();
        loop {
            if let Some(message) = self.shared.error() {
                return Err(Error::StreamError { message });
            }
            if self.shared.connected.load(Ordering::SeqCst) {
                return Ok(());
            }
            if started.elapsed() >= CONNECT_WAIT {
                return Err(Error::Refused {
                    call: "pw_stream_connect (never taken on)",
                });
            }
            // SAFETY: the lock is held; the wait releases it while waiting
            // and takes it back, and the state callbacks signal it.
            unsafe { sys::thread_loop_timed_wait(self.thread_loop, 1) };
        }
    }

    /// Say `active` to the stream, under the loop's lock.
    fn set_active(&self, active: bool) -> Result<(), Error> {
        // SAFETY: a live stream on a running loop, touched under its lock.
        let outcome = unsafe {
            sys::thread_loop_lock(self.thread_loop);
            let outcome = sys::stream_set_active(self.stream, active);
            sys::thread_loop_unlock(self.thread_loop);
            outcome
        };
        sys::check("pw_stream_set_active", outcome)
    }

    fn start(&mut self) -> Result<(), Error> {
        if let Some(message) = self.shared.error()
            && !self.shared.lost.load(Ordering::SeqCst)
        {
            return Err(Error::StreamError { message });
        }
        if self.shared.lost.load(Ordering::SeqCst) {
            // The owner is still asking for a running stream; the loss is
            // what `recover` answers, and it starts again only what was
            // started.
            self.started = true;
            return Err(Error::NoDevice);
        }
        self.set_active(true)?;
        self.started = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), Error> {
        self.started = false;
        if self.shared.lost.load(Ordering::SeqCst) {
            return Ok(());
        }
        let outcome = self.set_active(false);
        self.channel.quiet();
        outcome
    }

    fn is_running(&self) -> bool {
        self.shared.state.load(Ordering::SeqCst) == abi::PW_STREAM_STATE_STREAMING
            && !self.shared.lost.load(Ordering::SeqCst)
    }

    /// Whether the node has gone, said once.
    fn poll(&mut self) -> Option<StreamEvent> {
        if self.loss_reported || !self.shared.lost.load(Ordering::SeqCst) {
            return None;
        }
        self.loss_reported = true;
        Some(StreamEvent::DeviceLost)
    }

    fn latency(&self) -> Latency {
        self.shared.timing.read(self.config.format.sample_rate_hz())
    }

    /// Shut down and open again on whatever the choice names now.
    fn recovered(mut self, direction: Direction) -> Result<Self, Error> {
        let config = self.config.clone();
        let channel = Arc::clone(&self.channel);
        let started = self.started;
        self.teardown()?;
        drop(self);

        let mut session = Self::open(&config, direction, channel)?;
        if started {
            session.start()?;
        }
        Ok(session)
    }

    /// The shutdown sequence, safe to call twice.
    ///
    /// The order is the argument:
    ///
    /// 1. mark the stream as closing, so the state change destroying it
    ///    causes is not taken for the node going away;
    /// 2. shut the gate, so a `process` that has not yet reached our memory
    ///    turns itself around;
    /// 3. wait, with a deadline, for any `process` already inside to leave;
    /// 4. destroy the stream under the loop's lock, which takes its node out
    ///    of the graph and its buffers out of this process;
    /// 5. stop the loop's thread, outside the lock, which joins it — no
    ///    `state_changed` or `param_changed` is still running after that;
    /// 6. destroy the loop; `Shared` and the offered format go when `self`
    ///    does.
    ///
    /// Step 3 failing is not survivable by carrying on. The realtime thread
    /// is inside our memory and not coming out, so nothing is destroyed and
    /// nothing is freed: the stream, the loop and `Shared` are leaked,
    /// deliberately, because a buffer freed under a thread still reading it
    /// is a crash somewhere else entirely.
    fn teardown(&mut self) -> Result<(), Error> {
        let phase = core::mem::replace(&mut self.phase, Phase::Closed);
        if phase == Phase::Closed {
            return Ok(());
        }
        self.shared.closing.store(true, Ordering::SeqCst);
        self.shared.gate.close();
        if !self.shared.gate.drained(TEARDOWN_WAIT) {
            core::mem::forget(Arc::clone(&self.shared));
            core::mem::forget(core::mem::replace(
                &mut self.offer,
                Box::new(FormatPod::new(0)),
            ));
            return Err(Error::Draining {
                waited_millis: TEARDOWN_WAIT_MILLIS,
            });
        }
        if phase == Phase::Running {
            // SAFETY: the loop is running, so the stream is destroyed under
            // its lock; nothing in the realtime thread is inside `Shared`.
            unsafe {
                sys::thread_loop_lock(self.thread_loop);
                if !self.stream.is_null() {
                    sys::stream_destroy(self.stream);
                }
                sys::thread_loop_unlock(self.thread_loop);
                sys::thread_loop_stop(self.thread_loop);
            }
        } else if !self.stream.is_null() {
            // SAFETY: the loop never ran, so nothing else touches the stream.
            unsafe { sys::stream_destroy(self.stream) };
        }
        self.stream = ptr::null_mut();
        self.shared.stream.store(ptr::null_mut(), Ordering::Release);
        // SAFETY: the loop's thread is joined, or never ran, and nothing
        // references the loop any more.
        unsafe { sys::thread_loop_destroy(self.thread_loop) };
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // nothing to report a status to from here
        let _ = self.teardown();
    }
}

/// The capture end: what a source heard, as mono frames.
pub struct CaptureStream {
    session: Session,
}

/// The playback end: what goes to a sink, as mono frames.
pub struct PlaybackStream {
    session: Session,
}

/// The methods that are the same in both directions.
///
/// A macro rather than a trait, because a trait would put these in the
/// caller's namespace only after an import, and rather than two copies
/// because two copies drift.
macro_rules! session_methods {
    () => {
        /// What the caller is handed: exactly what it asked for, because
        /// PipeWire's adapter converts to and from the graph's own format.
        #[must_use]
        pub const fn format(&self) -> StreamFormat {
            self.session.config.format
        }

        /// The node the stream is on: the one named, or — for the session's
        /// route, and for a [`StreamConfig::preferring`] whose node was not
        /// there — the session's default as the stream opened. `None` only
        /// when the session had named no default, in which case the session
        /// manager places the stream wherever it routes one.
        #[must_use]
        pub const fn device(&self) -> Option<&DeviceId> {
            self.session.target.as_ref()
        }

        /// What `pw_time` said at the last quantum: the graph's delay to or
        /// from the device, and what is queued in the stream and its
        /// resampler.
        ///
        /// All zero until the stream has run a quantum. For the whole loop an
        /// echo canceller needs, see [`CaptureStream::render_delay`].
        #[must_use]
        pub fn latency(&self) -> Latency {
            self.session.latency()
        }

        /// Whether the stream is running: started, linked, and processing.
        ///
        /// This goes false on its own when the node goes away;
        /// [`Self::poll`] is what says that is why.
        #[must_use]
        pub fn is_running(&self) -> bool {
            self.session.is_running()
        }

        /// The volume, the mute and the meter for this direction.
        ///
        /// A handle, not a borrow: the slider and the bar are on the thread
        /// that draws the window and the frames are on the thread that
        /// carries the call. It survives a recover with its settings intact.
        #[must_use]
        pub fn controls(&self) -> Controls {
            Controls::new(&self.session.channel)
        }

        /// Ask whether the node under the stream has gone, and say so once.
        ///
        /// A few atomic loads and no call into PipeWire, so it can be polled
        /// beside the meter. The stream is pinned to its node — see
        /// [`Self::device`] — and connected with
        /// `PW_STREAM_FLAG_DONT_RECONNECT`, so when that node goes the
        /// session manager destroys the stream's own node rather than moving
        /// it, and what this reports is that state change arriving unasked.
        /// A stream
        /// that has said [`StreamEvent::DeviceLost`] has stopped: what it had
        /// already captured can still be read out, nothing further arrives,
        /// and the speaker ring fills and takes no more.
        /// [`Self::recover`] is what puts a node back under it.
        pub fn poll(&mut self) -> Option<StreamEvent> {
            self.session.poll()
        }

        /// What the stream has been doing since it opened.
        #[must_use]
        pub fn counters(&self) -> Counters {
            self.session.shared.meters.read()
        }

        /// Start processing.
        ///
        /// # Errors
        /// [`Error::Call`] from `pw_stream_set_active`,
        /// [`Error::StreamError`] when the stream is in PipeWire's error
        /// state, or [`Error::NoDevice`] when its node has already gone — in
        /// which case the stream counts as started for [`Self::recover`],
        /// which starts what it puts back.
        pub fn start(&mut self) -> Result<(), Error> {
            self.session.start()
        }

        /// Stop processing. What is already in the ring stays there.
        ///
        /// # Errors
        /// [`Error::Call`] from `pw_stream_set_active`.
        pub fn stop(&mut self) -> Result<(), Error> {
            self.session.stop()
        }

        /// Shut the stream down.
        ///
        /// Dropping the stream does exactly this and has nowhere to report
        /// to.
        ///
        /// # Errors
        /// [`Error::Draining`] when PipeWire's realtime thread could not be
        /// shown to have left the stream's memory within two seconds — in
        /// which case the stream and everything it shares with that thread
        /// are leaked, deliberately.
        pub fn close(mut self) -> Result<(), Error> {
            self.session.teardown()
        }
    };
}

impl CaptureStream {
    /// Open a capture stream, without starting it.
    ///
    /// # Errors
    /// [`Error::NoDevice`] when a [`DeviceChoice::Device`] names a source the
    /// graph does not have, [`Error::Refused`] when PipeWire cannot be
    /// reached or never takes the stream on, [`Error::StreamError`] with what
    /// PipeWire said when it refuses the stream, and [`Error::Call`] naming
    /// any other call that refused.
    pub fn open(config: &StreamConfig) -> Result<Self, Error> {
        let window = window_samples(config.format.sample_rate_hz());
        Ok(Self {
            session: Session::open(config, Direction::Input, Arc::new(Channel::new(window)))?,
        })
    }

    /// Open again, on whatever this stream's [`StreamConfig`] names now.
    ///
    /// This is the answer to [`StreamEvent::DeviceLost`], and the reason a
    /// saved selection is worth storing as [`StreamConfig::preferring`]:
    /// that choice resolves to the saved node when it is back and to the
    /// session's route when it is not. [`StreamConfig::on`] names one node
    /// and nothing else, so recovering onto one that has gone fails, and
    /// says so.
    ///
    /// The controls carry over, and a [`Controls`] handed out earlier keeps
    /// working. Whatever was in the ring does not — those samples came from a
    /// node that is not there. A stream that was started is started again.
    ///
    /// # Errors
    /// [`Error::Draining`] when the old stream could not be shown to be out
    /// of its memory, in which case nothing is reopened. Otherwise whatever
    /// [`Self::open`] would have said.
    pub fn recover(self) -> Result<Self, Error> {
        Ok(Self {
            session: self.session.recovered(Direction::Input)?,
        })
    }

    /// Fill `frame` from the source, or leave it untouched and say `false`
    /// because a whole frame is not there yet.
    pub fn read(&mut self, frame: &mut [i16]) -> bool {
        self.session.shared.ring.read_frame(frame)
    }

    /// Samples waiting to be read. A number that keeps growing is a reader
    /// falling behind, and the drop counter is about to start moving.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.session.shared.ring.filled()
    }

    /// The whole loop an echo canceller needs — down to the loudspeaker and
    /// back up from the microphone — for this capture stream and the
    /// playback stream carrying the same call.
    ///
    /// The two halves come from two streams because a PipeWire node is one
    /// direction; `sipral_media::MediaSession::set_render_delay` takes
    /// [`RenderDelay::total`].
    #[must_use]
    pub fn render_delay(&self, speaker: &PlaybackStream) -> RenderDelay {
        RenderDelay {
            playback: speaker.latency(),
            capture: self.latency(),
        }
    }

    session_methods!();
}

impl PlaybackStream {
    /// Open a playback stream, without starting it.
    ///
    /// # Errors
    /// As [`CaptureStream::open`].
    pub fn open(config: &StreamConfig) -> Result<Self, Error> {
        let window = window_samples(config.format.sample_rate_hz());
        Ok(Self {
            session: Session::open(config, Direction::Output, Arc::new(Channel::new(window)))?,
        })
    }

    /// Open again, on whatever this stream's [`StreamConfig`] names now. As
    /// [`CaptureStream::recover`].
    ///
    /// # Errors
    /// As [`CaptureStream::recover`].
    pub fn recover(self) -> Result<Self, Error> {
        Ok(Self {
            session: self.session.recovered(Direction::Output)?,
        })
    }

    /// Queue `frame` for the sink, or say `false` because there is no room
    /// for a whole one. Nothing is queued in that case.
    pub fn write(&mut self, frame: &[i16]) -> bool {
        self.session.shared.ring.write_frame(frame)
    }

    /// Samples that would fit right now.
    #[must_use]
    pub fn room(&self) -> usize {
        self.session.shared.ring.free()
    }

    session_methods!();
}

#[cfg(test)]
mod tests {
    use super::{CaptureStream, Meters, Session, StreamConfig, Timing, connect_flags};
    use crate::abi::{PwTime, SpaFraction};
    use crate::device::{DeviceChoice, DeviceId, Direction, StreamEvent};
    use crate::format::StreamFormat;

    #[test]
    fn a_config_says_which_node_and_how_much_slack() {
        let config = StreamConfig::default();
        assert_eq!(config.format, StreamFormat::narrowband());
        assert_eq!(config.device, DeviceChoice::System);
        assert!(config.depth_frames >= 2);

        let id = DeviceId::new("bluez_output.AA_BB_CC_DD_EE_FF.1");
        assert_eq!(
            StreamConfig::on(id.clone(), StreamFormat::narrowband()).device,
            DeviceChoice::Device(id.clone())
        );
        assert_eq!(
            StreamConfig::preferring(id.clone(), StreamFormat::narrowband()).device,
            DeviceChoice::Preferred(id)
        );
    }

    #[test]
    fn only_a_pinned_stream_asks_not_to_be_reconnected() {
        use crate::abi::PW_STREAM_FLAG_DONT_RECONNECT;
        assert_ne!(connect_flags(true) & PW_STREAM_FLAG_DONT_RECONNECT, 0);
        assert_eq!(connect_flags(false) & PW_STREAM_FLAG_DONT_RECONNECT, 0);
        // everything else is the same either way
        assert_eq!(
            connect_flags(true) & !PW_STREAM_FLAG_DONT_RECONNECT,
            connect_flags(false)
        );
    }

    #[test]
    fn the_counters_read_back_what_was_added() {
        let meters = Meters::default();
        Meters::add(&meters.captured, 160);
        Meters::add(&meters.capture_dropped, 3);
        Meters::add(&meters.buffer_misses, 1);
        let read = meters.read();
        assert_eq!(read.captured, 160);
        assert_eq!(read.capture_dropped, 3);
        assert_eq!(read.buffer_misses, 1);
        assert_eq!(read.played, 0);
    }

    /// What `pw_time` says is carried across unchanged, and a delay the
    /// graph reports as negative — a capture clock a hair ahead of its
    /// device — is no delay rather than an enormous one.
    #[test]
    fn a_time_report_becomes_a_latency() {
        let timing = Timing::default();
        timing.store(&PwTime {
            rate: SpaFraction {
                num: 1,
                denom: 48_000,
            },
            delay: 480,
            queued: 160,
            buffered: 40,
            ..PwTime::default()
        });
        let latency = timing.read(8_000);
        assert_eq!(latency.delay_ticks, 480);
        assert_eq!(latency.rate.denom, 48_000);
        assert_eq!(latency.queued_frames, 160);
        assert_eq!(latency.duration(), core::time::Duration::from_millis(35));

        timing.store(&PwTime {
            delay: -12,
            ..PwTime::default()
        });
        assert_eq!(timing.read(8_000).delay_ticks, 0);
    }

    /// Against a real PipeWire, reaching the race `check_target_survived`
    /// closes without having to win it: `registry::resolve` is asked for the
    /// node while it is still there, exactly as [`Session::open`] asks it,
    /// and only then is the node made to vanish — before [`Session::open_on`]
    /// ever builds the stream that names it. `pw_stream_connect` still
    /// succeeds, because the daemon never validates `target.object` against
    /// anything; what would have stayed a silently unlinked stream, said
    /// nothing until an unrelated `recover`, is instead
    /// [`StreamEvent::DeviceLost`] the moment `open` returns — no polling
    /// loop, because there is nothing to wait for.
    #[test]
    #[ignore = "needs a running PipeWire with pw-loopback on the path"]
    fn a_node_gone_before_connect_reaches_it_is_reported_without_waiting_for_recover() {
        use crate::level::{Channel, window_samples};
        use crate::registry::{self, DeviceMonitor};
        use std::process::Command;
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        const SINK: &str = "sipral-precheck-sink";
        const SOURCE: &str = "sipral-precheck-source";
        let patience = Duration::from_secs(10);

        let monitor = DeviceMonitor::new().expect("the registry answers");
        let mut cable = Command::new("pw-loopback")
            .arg("-m")
            .arg("[ MONO ]")
            .arg(format!(
                "--capture-props=media.class=Audio/Sink node.name={SINK}"
            ))
            .arg(format!(
                "--playback-props=media.class=Audio/Source node.name={SOURCE}"
            ))
            .spawn()
            .expect("pw-loopback runs");

        let started = Instant::now();
        while !monitor
            .devices()
            .iter()
            .any(|device| device.id.as_str() == SOURCE)
        {
            assert!(started.elapsed() < patience, "the source never appeared");
            std::thread::sleep(Duration::from_millis(20));
        }

        let id = DeviceId::new(SOURCE);
        // Resolved while the node is still there — exactly what `open`
        // itself would have named.
        let target = registry::resolve(&DeviceChoice::Device(id.clone()), Direction::Input)
            .expect("the registry answers");
        assert_eq!(target.as_ref(), Some(&id));

        // Gone before a session is even built from that answer.
        let _ = cable.kill();
        let _ = cable.wait();
        let started = Instant::now();
        while monitor
            .devices()
            .iter()
            .any(|device| device.id.as_str() == SOURCE)
        {
            assert!(started.elapsed() < patience, "the source never left");
            std::thread::sleep(Duration::from_millis(20));
        }

        let config = StreamConfig::on(id, StreamFormat::narrowband());
        let channel = Arc::new(Channel::new(window_samples(config.format.sample_rate_hz())));
        let session = Session::open_on(&config, Direction::Input, channel, target)
            .expect("a target the daemon never sees is still a stream that connects");
        let mut strict = CaptureStream { session };

        assert_eq!(strict.poll(), Some(StreamEvent::DeviceLost));
        assert_eq!(strict.poll(), None, "said once, not on every poll");
        strict.close().expect("closes");
    }
}
