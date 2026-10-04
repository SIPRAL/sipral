// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One AAudio stream, one direction, a frame at a time.
//!
//! AAudio runs the stream on a thread of its own and calls back into it for
//! every burst, a few milliseconds of audio. The callback converts the burst
//! to or from mono sixteen-bit samples, applies the gain, the mute and the
//! meter, and meets the rest of the process in a ring: the microphone's
//! callback fills one that [`Stream::read`] empties a frame at a time, and
//! the loudspeaker's empties one that [`Stream::write`] fills, sending
//! silence when it runs dry. Nothing in either callback allocates, locks or
//! waits.
//!
//! A device that goes away under a stream — a headset unplugged, the audio
//! server restarted — arrives as an error on the error callback, which only
//! notes it: the header forbids stopping or closing a stream from there.
//! [`Stream::lost`] reports it, once, and whoever holds the stream opens
//! another.
//!
//! Tearing down is where a callback can outlive its memory: the header says
//! that on the ordinary, non-MMAP path "some callbacks may still be in
//! process" after a stream is released. So both callbacks come in through a
//! [`Gate`], and what they point at is freed only once the gate is shut and
//! empty — or leaked, if it never empties.

use core::ffi::c_void;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sipral_io_common::gate::{Gate, TEARDOWN_WAIT};
use sipral_io_common::level::{Channel, Controls, window_samples};
use sipral_io_common::ring::Ring;

use crate::api::{self, Api, Code, RawStream};
use crate::samples;

/// How many frames each ring holds at [`RING_RATE_HZ`]: enough for a pump
/// that is a few ticks late. A stream at a lower rate holds more of its own
/// frames; the engine's pump keeps the loudspeaker's ring near its own
/// target and empties the microphone's every tick, so neither falls behind
/// the live edge for it.
const RING_FRAMES: usize = 16;

/// The rate a ring is sized for at least, so that a stream that opens at a
/// higher rate than it asked for still has its sixteen frames.
const RING_RATE_HZ: u32 = 48_000;

/// The most mono samples a callback converts at once, on its own stack.
const CHUNK: usize = 480;

/// What a stream is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    /// A call's microphone: the voice-communication input preset.
    Microphone,
    /// A call's loudspeaker or earpiece: voice-communication usage.
    Call,
    /// A ring tone: notification-ringtone usage.
    Ring,
}

/// How to open a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// What the stream is for.
    pub usage: Usage,
    /// The platform's id for the device to open it on, from
    /// `AudioDeviceInfo.getId`, or `None` for the platform's own route.
    pub device: Option<i32>,
    /// The rate asked for. AAudio may answer with another, which
    /// [`Stream::sample_rate`] says.
    pub sample_rate_hz: u32,
    /// For a microphone, whether it opens with the voice-communication
    /// preset, behind which the platform cancels the call's echo, or with
    /// the voice-recognition one, which has no canceller in its path. Read
    /// for nothing else.
    pub echo_cancellation: bool,
}

/// The input preset a call's microphone opens with: voice communication,
/// behind the platform's echo canceller, or voice recognition, with none.
const fn input_preset(echo_cancellation: bool) -> i32 {
    if echo_cancellation {
        api::PRESET_VOICE_COMMUNICATION
    } else {
        api::PRESET_VOICE_RECOGNITION
    }
}

/// Why a stream did not open.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// AAudio cannot carry a call on this phone: [`crate::available`] is
    /// false.
    Unavailable,
    /// An AAudio call failed; which, and what AAudio said.
    Failed {
        /// The function that failed.
        call: &'static str,
        /// `AAudio_convertResultToText` of its answer.
        detail: String,
    },
    /// The stream opened in a sample format this crate does not convert.
    Format(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Unavailable => {
                f.write_str("AAudio cannot carry a call here: it needs API level 28")
            }
            Self::Failed { call, ref detail } => write!(f, "{call}: {detail}"),
            Self::Format(format) => write!(f, "AAudio opened the stream in format {format}"),
        }
    }
}

impl std::error::Error for Error {}

/// What both callbacks reach, through the gate.
///
/// The channel count and the sample format are atomics because the
/// callbacks are registered before the stream opens and the stream says
/// what it runs only after; they are stored once, before it starts.
struct Shared {
    gate: Gate,
    ring: Ring,
    channel: Arc<Channel>,
    lost: AtomicBool,
    channels: AtomicUsize,
    float: AtomicBool,
    input: bool,
    /// Samples the microphone heard with nowhere to go, and samples of
    /// silence the loudspeaker played for want of a frame.
    dropped: AtomicU64,
}

/// One open, running AAudio stream.
pub struct Stream {
    api: &'static Api,
    raw: *mut RawStream,
    shared: *const Shared,
    sample_rate_hz: u32,
    device_id: i32,
    latency: Duration,
    reported_lost: bool,
}

// SAFETY: the stream handle is used from whichever thread holds the
// `Stream`, one at a time, and every AAudio call made through it may be made
// from any thread that is not the stream's own callback; the shared state is
// atomics and a single-producer, single-consumer ring whose non-callback
// side is only ever this handle's holder.
unsafe impl Send for Stream {}

/// Deletes a builder however the open goes.
struct BuilderGuard {
    api: &'static Api,
    builder: *mut api::Builder,
}

impl Drop for BuilderGuard {
    fn drop(&mut self) {
        // SAFETY: a builder AAudio made and nothing else deletes.
        unsafe { (self.api.delete_builder)(self.builder) };
    }
}

fn failed(api: &Api, call: &'static str, code: Code) -> Error {
    Error::Failed {
        call,
        detail: api.describe(code),
    }
}

impl Stream {
    /// Open a stream and start it.
    ///
    /// # Errors
    /// [`Error::Unavailable`] below API level 28 or without `libaaudio.so`,
    /// [`Error::Failed`] naming the call AAudio refused, and
    /// [`Error::Format`] for a sample format it cannot be read in.
    pub fn open(config: StreamConfig) -> Result<Self, Error> {
        if !crate::available() {
            return Err(Error::Unavailable);
        }
        let api = Api::get().ok_or(Error::Unavailable)?;
        let input = config.usage == Usage::Microphone;
        let ring_rate = config.sample_rate_hz.max(RING_RATE_HZ);
        let shared = Arc::into_raw(Arc::new(Shared {
            gate: Gate::new(),
            ring: Ring::new((ring_rate / 50) as usize * RING_FRAMES),
            channel: Arc::new(Channel::new(window_samples(config.sample_rate_hz))),
            lost: AtomicBool::new(false),
            channels: AtomicUsize::new(1),
            float: AtomicBool::new(false),
            input,
            dropped: AtomicU64::new(0),
        }));
        match Self::open_with(api, config, shared) {
            Ok(stream) => Ok(stream),
            Err(error) => {
                // SAFETY: the pointer `into_raw` made above; no stream that
                // could call back with it was started.
                drop(unsafe { Arc::from_raw(shared) });
                Err(error)
            }
        }
    }

    fn open_with(
        api: &'static Api,
        config: StreamConfig,
        shared: *const Shared,
    ) -> Result<Self, Error> {
        let mut builder = core::ptr::null_mut();
        // SAFETY: an out-pointer to a local.
        let code = unsafe { (api.create_builder)(&raw mut builder) };
        if code != api::OK || builder.is_null() {
            return Err(failed(api, "AAudio_createStreamBuilder", code));
        }
        let guard = BuilderGuard { api, builder };
        let rate = i32::try_from(config.sample_rate_hz).unwrap_or(48_000);
        let user = shared.cast_mut().cast::<c_void>();
        // SAFETY: every setter takes the builder AAudio made and a value;
        // the two callbacks take `user`, which stays valid until `Drop` has
        // seen the gate empty.
        unsafe {
            (api.set_direction)(
                builder,
                if config.usage == Usage::Microphone {
                    api::DIRECTION_INPUT
                } else {
                    api::DIRECTION_OUTPUT
                },
            );
            (api.set_device_id)(builder, config.device.unwrap_or(api::UNSPECIFIED));
            (api.set_sample_rate)(builder, rate);
            (api.set_channel_count)(builder, 1);
            (api.set_format)(builder, api::FORMAT_I16);
            (api.set_sharing_mode)(builder, api::SHARING_SHARED);
            match config.usage {
                Usage::Microphone => {
                    (api.set_performance_mode)(builder, api::PERFORMANCE_LOW_LATENCY);
                    (api.set_input_preset)(builder, input_preset(config.echo_cancellation));
                    (api.set_content_type)(builder, api::CONTENT_SPEECH);
                }
                Usage::Call => {
                    (api.set_performance_mode)(builder, api::PERFORMANCE_LOW_LATENCY);
                    (api.set_usage)(builder, api::USAGE_VOICE_COMMUNICATION);
                    (api.set_content_type)(builder, api::CONTENT_SPEECH);
                }
                Usage::Ring => {
                    (api.set_performance_mode)(builder, api::PERFORMANCE_NONE);
                    (api.set_usage)(builder, api::USAGE_NOTIFICATION_RINGTONE);
                    (api.set_content_type)(builder, api::CONTENT_SONIFICATION);
                }
            }
            (api.set_data_callback)(builder, on_data, user);
            (api.set_error_callback)(builder, on_error, user);
        }
        let mut raw = core::ptr::null_mut();
        // SAFETY: an out-pointer to a local, and a builder AAudio made.
        let code = unsafe { (api.open_stream)(builder, &raw mut raw) };
        drop(guard);
        if code != api::OK || raw.is_null() {
            return Err(failed(api, "AAudioStreamBuilder_openStream", code));
        }
        // SAFETY: the stream just opened, queried before it starts.
        let (opened_rate, channels, format, device_id, burst, buffer) = unsafe {
            (
                (api.sample_rate)(raw),
                (api.channel_count)(raw),
                (api.format)(raw),
                (api.device_id)(raw),
                (api.frames_per_burst)(raw),
                (api.buffer_size)(raw),
            )
        };
        let close = || {
            // SAFETY: the stream just opened, never started, so nothing
            // calls back into `shared` once it is closed.
            unsafe { (api.close)(raw) };
        };
        if format != api::FORMAT_I16 && format != api::FORMAT_FLOAT {
            close();
            return Err(Error::Format(format));
        }
        let sample_rate_hz = u32::try_from(opened_rate)
            .ok()
            .filter(|&rate| rate > 0)
            .unwrap_or(config.sample_rate_hz);
        // SAFETY: `shared` is live, and nothing calls back before the start
        // below.
        let state = unsafe { &*shared };
        state.channels.store(
            usize::try_from(channels).unwrap_or(1).max(1),
            Ordering::Release,
        );
        state
            .float
            .store(format == api::FORMAT_FLOAT, Ordering::Release);
        state.channel.set_window(window_samples(sample_rate_hz));
        if config.usage != Usage::Microphone && burst > 0 {
            // two bursts queued in the device: the least that does not
            // underrun, which is what the low-latency mode is for. A path
            // that will not go that low keeps what it has.
            // SAFETY: the stream just opened.
            let _ = unsafe { (api.set_buffer_size)(raw, burst.saturating_mul(2)) };
        }
        // SAFETY: the stream just opened.
        let code = unsafe { (api.request_start)(raw) };
        if code != api::OK {
            close();
            return Err(failed(api, "AAudioStream_requestStart", code));
        }
        let queued = if config.usage == Usage::Microphone {
            burst
        } else {
            // SAFETY: the stream is open.
            unsafe { (api.buffer_size)(raw) }.max(buffer.min(burst.saturating_mul(2)))
        };
        Ok(Self {
            api,
            raw,
            shared,
            sample_rate_hz,
            device_id,
            latency: latency_of(queued, sample_rate_hz),
            reported_lost: false,
        })
    }

    fn shared(&self) -> &Shared {
        // SAFETY: freed only in `Drop`, after which `self` is gone.
        unsafe { &*self.shared }
    }

    /// The rate the stream runs at.
    #[must_use]
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate_hz
    }

    /// Samples in one twenty-millisecond frame at that rate.
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        (self.sample_rate_hz / 50).max(1) as usize
    }

    /// The platform's id for the device the stream landed on, or zero when
    /// AAudio does not say.
    #[must_use]
    pub fn device_id(&self) -> i32 {
        self.device_id
    }

    /// What the device holds between the frame and the air, or the air and
    /// the frame.
    #[must_use]
    pub fn latency(&self) -> Duration {
        self.latency
    }

    /// Gain, mute and the meter, applied in the callback.
    #[must_use]
    pub fn controls(&self) -> Controls {
        Controls::new(&self.shared().channel)
    }

    /// Samples lost to a ring that was full (the microphone) or empty (the
    /// loudspeaker), over the life of the stream.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared().dropped.load(Ordering::Relaxed)
    }

    /// Take one whole frame the microphone heard, or say there is not one
    /// yet. Always false on a loudspeaker.
    pub fn read(&mut self, frame: &mut [i16]) -> bool {
        self.shared().input && self.shared().ring.read_frame(frame)
    }

    /// Queue one whole frame for the loudspeaker, or say there is no room
    /// for it. Always false on a microphone.
    pub fn write(&mut self, frame: &[i16]) -> bool {
        !self.shared().input && self.shared().ring.write_frame(frame)
    }

    /// Samples queued for the loudspeaker and not yet taken by the device.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.shared().ring.filled()
    }

    /// Whether the device went away under the stream. True once: after
    /// that the stream carries nothing and is only to be dropped.
    pub fn lost(&mut self) -> bool {
        if self.reported_lost {
            return false;
        }
        let gone = self.shared().lost.load(Ordering::Acquire) || {
            // SAFETY: the stream is open.
            let state = unsafe { (self.api.state)(self.raw) };
            state == api::STATE_DISCONNECTED
        };
        if gone {
            self.reported_lost = true;
        }
        gone
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: the stream is open, and this is not its callback thread.
        unsafe {
            (self.api.request_stop)(self.raw);
            (self.api.close)(self.raw);
        }
        let shared = self.shared();
        shared.gate.close();
        if shared.gate.drained(TEARDOWN_WAIT) {
            // SAFETY: the pointer `into_raw` made in `open`; the gate is
            // shut and empty, so no callback holds it.
            drop(unsafe { Arc::from_raw(self.shared) });
        }
    }
}

fn latency_of(frames: i32, sample_rate_hz: u32) -> Duration {
    let frames = u64::try_from(frames).unwrap_or(0);
    Duration::from_micros(frames * 1_000_000 / u64::from(sample_rate_hz.max(1)))
}

/// `AAudioStream_dataCallback`: one burst in or out.
unsafe extern "C" fn on_data(
    _stream: *mut RawStream,
    user: *mut c_void,
    audio: *mut c_void,
    frames: i32,
) -> i32 {
    // SAFETY: `user` is the `Shared` the stream was opened with, alive until
    // the gate below is shut and empty.
    let shared = unsafe { &*user.cast_const().cast::<Shared>() };
    let Some(_inside) = shared.gate.enter() else {
        return api::CALLBACK_STOP;
    };
    let frames = usize::try_from(frames).unwrap_or(0);
    let channels = shared.channels.load(Ordering::Acquire);
    let samples = frames.saturating_mul(channels);
    if audio.is_null() || samples == 0 {
        return api::CALLBACK_CONTINUE;
    }
    let float = shared.float.load(Ordering::Acquire);
    // SAFETY: AAudio hands `frames` frames of `channels` samples in the
    // format the stream opened in, for the length of this call.
    let buffer = unsafe {
        if float {
            Buffer::Float(core::slice::from_raw_parts_mut(
                audio.cast::<f32>(),
                samples,
            ))
        } else {
            Buffer::Short(core::slice::from_raw_parts_mut(
                audio.cast::<i16>(),
                samples,
            ))
        }
    };
    let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        if shared.input {
            capture(shared, buffer, channels);
        } else {
            play(shared, buffer, channels);
        }
    }));
    if outcome.is_err() {
        shared.lost.store(true, Ordering::Release);
        return api::CALLBACK_STOP;
    }
    api::CALLBACK_CONTINUE
}

/// `AAudioStream_errorCallback`: note it, and nothing else.
unsafe extern "C" fn on_error(_stream: *mut RawStream, user: *mut c_void, _error: Code) {
    // SAFETY: as `on_data`.
    let shared = unsafe { &*user.cast_const().cast::<Shared>() };
    let Some(_inside) = shared.gate.enter() else {
        return;
    };
    shared.lost.store(true, Ordering::Release);
}

/// A burst, in the format the stream runs in.
enum Buffer<'a> {
    Short(&'a mut [i16]),
    Float(&'a mut [f32]),
}

/// The microphone's burst into the ring, a chunk at a time.
fn capture(shared: &Shared, buffer: Buffer<'_>, channels: usize) {
    let mut mono = [0i16; CHUNK];
    let step = CHUNK * channels;
    let take = |converted: usize, mono: &mut [i16; CHUNK]| {
        let Some(chunk) = mono.get_mut(..converted) else {
            return;
        };
        shared.channel.apply(chunk, converted);
        let written = shared.ring.write(chunk);
        let lost = converted - written;
        if lost > 0 {
            shared.dropped.fetch_add(lost as u64, Ordering::Relaxed);
        }
    };
    match buffer {
        Buffer::Short(data) => {
            for part in data.chunks(step) {
                let converted = samples::mono_from_i16(part, channels, &mut mono);
                take(converted, &mut mono);
            }
        }
        Buffer::Float(data) => {
            for part in data.chunks(step) {
                let converted = samples::mono_from_f32(part, channels, &mut mono);
                take(converted, &mut mono);
            }
        }
    }
}

/// The ring into the loudspeaker's burst, silence where it runs dry.
fn play(shared: &Shared, buffer: Buffer<'_>, channels: usize) {
    let mut mono = [0i16; CHUNK];
    let step = CHUNK * channels;
    let fill = |wanted: usize, mono: &mut [i16; CHUNK]| -> usize {
        let Some(chunk) = mono.get_mut(..wanted) else {
            return 0;
        };
        let read = shared.ring.read(chunk);
        if let Some(rest) = chunk.get_mut(read..) {
            rest.fill(0);
        }
        if read < wanted {
            shared
                .dropped
                .fetch_add((wanted - read) as u64, Ordering::Relaxed);
        }
        shared.channel.apply(chunk, wanted);
        wanted
    };
    match buffer {
        Buffer::Short(data) => {
            for part in data.chunks_mut(step) {
                let wanted = part.len() / channels;
                let filled = fill(wanted, &mut mono);
                if let Some(chunk) = mono.get(..filled) {
                    samples::i16_from_mono(chunk, channels, part);
                }
            }
        }
        Buffer::Float(data) => {
            for part in data.chunks_mut(step) {
                let wanted = part.len() / channels;
                let filled = fill(wanted, &mut mono);
                if let Some(chunk) = mono.get(..filled) {
                    samples::f32_from_mono(chunk, channels, part);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Stream, StreamConfig, Usage};
    use std::time::{Duration, Instant};

    fn open(usage: Usage, sample_rate_hz: u32) -> Stream {
        Stream::open(StreamConfig {
            usage,
            device: None,
            sample_rate_hz,
            echo_cancellation: true,
        })
        .unwrap_or_else(|error| panic!("{usage:?} at {sample_rate_hz} Hz: {error}"))
    }

    /// The three streams the engine opens, at the three rates a call asks
    /// for, carried for a second: the microphone hands whole frames over at
    /// its own pace, the loudspeaker and the ring take what they are given
    /// at theirs, and each refuses the direction it does not run.
    #[test]
    #[ignore = "opens the phone's own microphone and loudspeaker"]
    fn a_microphone_a_call_and_a_ring_open_run_and_close() {
        assert!(
            crate::available(),
            "AAudio carries no call at API level {}",
            crate::sdk()
        );
        for rate in [48_000u32, 16_000, 8_000] {
            let mut microphone = open(Usage::Microphone, rate);
            let mut call = open(Usage::Call, rate);
            let mut ring = open(Usage::Ring, rate);
            let frame = call.frame_samples();
            // fifty decibels down: whoever is beside the phone hears nothing
            let tone: Vec<i16> = (0..frame)
                .map(|at| if at % 40 < 20 { 100 } else { -100 })
                .collect();
            let mut heard = vec![0i16; microphone.frame_samples()];
            let (mut read, mut played, mut ringer_frames) = (0usize, 0usize, 0usize);
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(1) {
                while microphone.read(&mut heard) {
                    read += 1;
                }
                while call.write(&tone) {
                    played += 1;
                }
                while ring.write(&tone) {
                    ringer_frames += 1;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            println!(
                "{rate} Hz asked: microphone {} Hz on device {}, {read} frames, {:?}; \
                 call {} Hz on device {}, {played} frames, {:?}, {} samples of silence; \
                 ring {} Hz, {ringer_frames} frames",
                microphone.sample_rate(),
                microphone.device_id(),
                microphone.latency(),
                call.sample_rate(),
                call.device_id(),
                call.latency(),
                call.dropped(),
                ring.sample_rate(),
            );
            // a second is fifty frames; the first few go to starting up
            assert!(read >= 25, "the microphone gave {read} frames in a second");
            assert!(played >= 40, "the call took {played} frames in a second");
            assert!(
                ringer_frames >= 40,
                "the ring took {ringer_frames} frames in a second"
            );
            assert!(!microphone.lost() && !call.lost() && !ring.lost());
            assert!(!microphone.write(&tone), "a microphone plays nothing");
            assert!(!call.read(&mut heard), "a loudspeaker hears nothing");
        }
    }
}
