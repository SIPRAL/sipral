// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One endpoint, in one direction: samples in from a microphone, or samples
//! out to a speaker, and nothing else.
//!
//! One `IAudioClient` per endpoint; a headset is two endpoints with two
//! clocks, so the caller holds two streams.
//!
//! Shared mode, because exclusive mode locks out the rest of the machine for
//! latency a jitter buffer will not notice. Event-driven, because polling on
//! a timer is late or busy.
//!
//! Our own audio thread (MTA, MMCSS Pro Audio) owns every COM object for its
//! life, so teardown is local. It shares one ring, the counters and three
//! events with the caller; only teardown waits, with a deadline.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use core::time::Duration;
use std::ffi::c_void;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::abi::{
    AudioCaptureClient, AudioCaptureClientVtable, AudioClient, AudioClient2, AudioClient2Vtable,
    AudioClientProperties, AudioClientVtable, AudioRenderClient, AudioRenderClientVtable,
    BUFFERFLAGS_DATA_DISCONTINUITY, BUFFERFLAGS_SILENT, CLSCTX_ALL, Handle, Interface,
    REFERENCE_TIMES_PER_SECOND, SHARE_MODE_SHARED, STREAMFLAGS_EVENTCALLBACK, Unknown,
    WAIT_OBJECT_0, WAIT_TIMEOUT, WaveFormat, WaveFormatExtensible,
};
use crate::category::Category;
use crate::com::{Apartment, Com, Event, Priority, TaskMemory};
use crate::convert::{fold, silence, spread};
use crate::counters::Counters;
use crate::device::{Device, DeviceChoice, DeviceId, Direction, StreamEvent};
use crate::endpoint;
use crate::format::{DeviceFormat, StreamFormat};
use crate::gate::{Gate, TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS};
use crate::level::{Channel, Controls, window_samples};
use crate::mixformat;
use crate::ring::Ring;
use crate::status::{AUDCLNT_E_DEVICE_INVALIDATED, AUDCLNT_E_UNSUPPORTED_FORMAT, Error, HResult};
use crate::sys;

/// Enough for a scheduling hiccup; short enough that a stalled reader is a
/// gap, not a permanent delay.
const DEFAULT_DEPTH_FRAMES: usize = 16;

/// How long the audio thread waits for the engine before deciding the endpoint
/// has stopped signalling.
///
/// A wake costs one atomic load; a silent endpoint is noticed, not waited on.
const STALL_AFTER_MILLIS: u32 = 200;

/// How long a caller waits for the audio thread to answer `start` or `stop`.
///
/// As for teardown: past that the thread is stuck in a driver call.
const ANSWER_WAIT: Duration = TEARDOWN_WAIT;

/// Nothing to do.
const COMMAND_NONE: u32 = 0;
/// Fill the buffer so the first period is not a gap, then start the client.
const COMMAND_START: u32 = 1;
/// Stop the client and throw away what the engine still holds.
const COMMAND_STOP: u32 = 2;
/// Leave the loop, put every interface back, and end.
const COMMAND_QUIT: u32 = 3;

/// Two thirty-two-bit halves in one word: a ticket on top, and a command or a
/// status underneath.
///
/// One word, so both halves are read from the same store.
fn ticketed(ticket: u32, low: u32) -> u64 {
    (u64::from(ticket) << 32) | u64::from(low)
}

/// The two halves of a word [`ticketed`] made: the ticket, then the rest.
fn unticket(word: u64) -> (u32, u32) {
    (
        u32::try_from(word >> 32).unwrap_or(u32::MAX),
        u32::try_from(word & u64::from(u32::MAX)).unwrap_or(u32::MAX),
    )
}

/// What to open, and how much slack to leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// Rate and frame length wanted. What is actually delivered is
    /// [`CaptureStream::format`], which carries the endpoint's rate.
    pub format: StreamFormat,
    /// Which endpoint; by default Windows' route for calls.
    pub device: DeviceChoice,
    /// Frames of buffering between the endpoint and the caller.
    ///
    /// Sizes this crate's ring only; the engine buffer stays at its period.
    pub depth_frames: usize,
    /// Whether to keep the endpoint's voice processing (AEC, NS, AGC); on by
    /// default. Off opens with `AUDCLNT_STREAMOPTIONS_RAW`, which keeps the
    /// communications routing and ducking.
    pub processing: bool,
}

impl StreamConfig {
    /// The system's current route for calls, at the given format.
    #[must_use]
    pub const fn new(format: StreamFormat) -> Self {
        Self {
            format,
            device: DeviceChoice::System,
            depth_frames: DEFAULT_DEPTH_FRAMES,
            processing: true,
        }
    }

    /// A named endpoint, at the given format, and nothing else if it is not
    /// there.
    #[must_use]
    pub fn on(device: DeviceId, format: StreamFormat) -> Self {
        Self {
            device: DeviceChoice::Device(device),
            ..Self::new(format)
        }
    }

    /// That endpoint when usable, else the system route for calls. Use this
    /// for a [`DeviceId`] from a configuration file.
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

/// Audio-thread statistics, relaxed: nothing depends on them.
#[derive(Default)]
struct Meters {
    captured: AtomicU64,
    capture_dropped: AtomicU64,
    played: AtomicU64,
    playback_starved: AtomicU64,
    discontinuities: AtomicU64,
    buffer_failures: AtomicU64,
    stalls: AtomicU64,
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
            discontinuities: self.discontinuities.load(Ordering::Relaxed),
            buffer_failures: self.buffer_failures.load(Ordering::Relaxed),
            stalls: self.stalls.load(Ordering::Relaxed),
            panics: self.panics.load(Ordering::Relaxed),
        }
    }
}

/// Everything both threads touch.
///
/// The audio thread holds an `Arc`, so no buffer can be freed under it. The
/// gate guards against closing a handle it waits on or joining a stuck
/// thread: a failed drain detaches the thread rather than hanging the caller.
struct Shared {
    gate: Gate,
    /// In its own `Arc` so a [`Controls`] survives a reopen.
    channel: Arc<Channel>,
    /// Set by the audio thread once the rate is known, before `open` returns.
    ring: OnceLock<Ring>,
    meters: Meters,
    /// Signalled by the audio engine when a buffer wants attention.
    ready: Event,
    /// Signalled by the owner to make the audio thread read `command`.
    control: Event,
    /// Signalled by the audio thread when it has carried a command out.
    answered: Event,
    /// The command the owner wants carried out, under the ticket it was sent
    /// with. See [`ticketed`].
    command: AtomicU64,
    /// The last command's result under its ticket, so a late answer to an
    /// abandoned command is not mistaken for the current one.
    outcome: AtomicU64,
    /// What the final stop returned, on the way out of the loop.
    parting: AtomicI32,
    /// Whether the client is started. Written by the audio thread only.
    running: AtomicBool,
    /// Set by the audio thread as the last thing it does.
    ended: AtomicBool,
    /// Whether the multimedia scheduler took the thread on.
    pro_audio: AtomicBool,
    /// Set by the audio thread when Windows says the endpoint is not coming
    /// back. Distinguishes a stream that stopped from one that was taken away.
    lost: AtomicBool,
}

impl Shared {
    fn new(channel: Arc<Channel>) -> Result<Self, Error> {
        Ok(Self {
            gate: Gate::new(),
            channel,
            ring: OnceLock::new(),
            meters: Meters::default(),
            ready: Event::new()?,
            control: Event::new()?,
            answered: Event::new()?,
            command: AtomicU64::new(ticketed(0, COMMAND_NONE)),
            // ticket zero is never handed out, so this answers nobody
            outcome: AtomicU64::new(ticketed(0, 0)),
            parting: AtomicI32::new(0),
            running: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            pro_audio: AtomicBool::new(false),
            lost: AtomicBool::new(false),
        })
    }

    /// Wait for the audio thread to answer, and say whether it did.
    fn answer(&self, within: Duration) -> bool {
        let handles = [self.answered.handle()];
        let millis = u32::try_from(within.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: one live handle, in an array of the length being declared.
        let outcome = unsafe { sys::wait_for_multiple_objects(1, handles.as_ptr(), 0, millis) };
        outcome == WAIT_OBJECT_0
    }

    /// Wait for the audio thread to say it has finished, within the deadline.
    ///
    /// Deliberately not `JoinHandle::join`, which has no deadline: a thread
    /// stuck inside a driver call would hang whoever dropped the stream.
    fn finished(&self, within: Duration) -> bool {
        let start = Instant::now();
        loop {
            if self.ended.load(Ordering::SeqCst) {
                return true;
            }
            if start.elapsed() >= within {
                return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// What the audio thread reports once the endpoint is open.
struct Opened {
    device: Device,
    format: DeviceFormat,
    delivered: StreamFormat,
    latency: Duration,
    buffer_frames: u32,
    category: Category,
}

/// The half of a stream that is the same in both directions.
struct Session {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
    device: Device,
    format: DeviceFormat,
    delivered: StreamFormat,
    latency: Duration,
    buffer_frames: u32,
    /// Set once, before initialisation, the only moment it can be.
    category: Category,
    /// Re-resolved on a reopen.
    config: StreamConfig,
    /// Also held here so a reopen keeps volume and mute.
    channel: Arc<Channel>,
    /// What the owner asked for, unlike `shared.running`, which drops on a
    /// loss; a recover restarts what was wanted.
    started: bool,
    /// Whether the loss has been handed over, so that it is reported once
    /// rather than on every poll.
    loss_reported: bool,
    closed: bool,
    /// The last ticket a command was sent under. Zero until the first.
    tickets: u32,
}

impl Session {
    /// Open an endpoint and leave it stopped.
    fn open(
        config: &StreamConfig,
        direction: Direction,
        channel: Arc<Channel>,
    ) -> Result<Self, Error> {
        let shared = Arc::new(Shared::new(Arc::clone(&channel))?);
        let (sender, receiver) = mpsc::channel::<Result<Opened, Error>>();
        let worker = {
            let shared = Arc::clone(&shared);
            let wanted = config.format;
            let choice = config.device.clone();
            let depth = config.depth_frames.max(2);
            let processing = config.processing;
            thread::Builder::new()
                .name("sipral-wasapi".to_string())
                .spawn(move || {
                    run(
                        &shared, &choice, direction, wanted, depth, processing, &sender,
                    );
                })
                .map_err(|_| Error::NoThread)?
        };

        // The thread reports once, either way, before it does anything else.
        let report = match receiver.recv_timeout(ANSWER_WAIT) {
            Ok(report) => report,
            Err(RecvTimeoutError::Timeout) => Err(Error::Draining {
                waited_millis: TEARDOWN_WAIT_MILLIS,
            }),
            Err(RecvTimeoutError::Disconnected) => Err(Error::NoThread),
        };

        let opened = match report {
            Ok(opened) => opened,
            Err(error) => {
                // the thread is exiting: wait, with the usual deadline
                shared.gate.close();
                shared
                    .command
                    .store(ticketed(0, COMMAND_QUIT), Ordering::SeqCst);
                shared.control.signal();
                if shared.finished(TEARDOWN_WAIT) {
                    let _ = worker.join();
                }
                return Err(error);
            }
        };

        Ok(Self {
            shared,
            worker: Some(worker),
            device: opened.device,
            format: opened.format,
            delivered: opened.delivered,
            latency: opened.latency,
            buffer_frames: opened.buffer_frames,
            category: opened.category,
            config: config.clone(),
            channel,
            started: false,
            loss_reported: false,
            closed: false,
            tickets: 0,
        })
    }

    /// Send the audio thread a command and wait for what it made of it.
    fn ask(&mut self, command: u32, call: &'static str) -> Result<(), Error> {
        self.ask_within(command, call, ANSWER_WAIT)
    }

    /// With an explicit deadline, for tests.
    ///
    /// Only the answer under this command's ticket is taken: a timed-out
    /// command still completes later, and its answer must not be read as
    /// this one's.
    fn ask_within(
        &mut self,
        command: u32,
        call: &'static str,
        within: Duration,
    ) -> Result<(), Error> {
        if self.shared.ended.load(Ordering::SeqCst) || self.shared.lost.load(Ordering::SeqCst) {
            // nobody left to answer; the loss is checked first because it is
            // recorded before the thread ends
            return Err(Error::NoDevice);
        }
        // never zero: reserved for quit and the initial outcome
        self.tickets = self.tickets.checked_add(1).unwrap_or(1);
        let ticket = self.tickets;
        self.shared
            .command
            .store(ticketed(ticket, command), Ordering::SeqCst);
        self.shared.control.signal();

        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if !self.shared.answer(left) {
                return Err(Error::Draining {
                    waited_millis: u64::try_from(within.as_millis()).unwrap_or(u64::MAX),
                });
            }
            let (answered, status) = unticket(self.shared.outcome.load(Ordering::SeqCst));
            if answered == ticket {
                return sys::check(call, status.cast_signed());
            }
        }
    }

    fn start(&mut self) -> Result<(), Error> {
        if self.shared.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        let outcome = self.ask(COMMAND_START, "IAudioClient::Start");
        // record the wish even if the endpoint is gone, so `recover` starts it
        if outcome.is_ok() || self.shared.lost.load(Ordering::SeqCst) {
            self.started = true;
        }
        outcome
    }

    fn stop(&mut self) -> Result<(), Error> {
        self.started = false;
        if !self.shared.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.ask(COMMAND_STOP, "IAudioClient::Stop")
    }

    /// Whether Windows has taken the endpoint away, said once.
    fn poll(&mut self) -> Option<StreamEvent> {
        if self.loss_reported || !self.shared.lost.load(Ordering::SeqCst) {
            return None;
        }
        self.loss_reported = true;
        Some(StreamEvent::DeviceLost)
    }

    /// Shut down and open again on whatever the choice names now.
    fn recovered(mut self, direction: Direction) -> Result<Self, Error> {
        let config = self.config.clone();
        let channel = Arc::clone(&self.channel);
        let started = self.started;
        // teardown errors on a lost endpoint are expected; a stuck thread is not
        if let Err(error @ Error::Draining { .. }) = self.teardown() {
            return Err(error);
        }
        drop(self);

        let mut session = Self::open(&config, direction, channel)?;
        if started {
            session.start()?;
        }
        Ok(session)
    }

    fn ring(&self) -> Option<&Ring> {
        self.shared.ring.get()
    }

    fn teardown(&mut self) -> Result<(), Error> {
        self.shut_down(TEARDOWN_WAIT, TEARDOWN_WAIT_MILLIS)
    }

    /// The shutdown sequence, safe to call twice.
    ///
    /// 1. close the gate, so a new pass turns back;
    /// 2. ask the thread to quit and wake it;
    /// 3. wait, with a deadline, for the gate to drain and the thread to end
    ///    (its interfaces released, its handles untouched);
    /// 4. join, which then returns at once.
    ///
    /// If step 3 fails the thread is detached, and its `Arc` keeps the
    /// handles open: closing a handle it still waits on could hit a reused
    /// handle value elsewhere.
    fn shut_down(&mut self, within: Duration, millis: u64) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        self.shared.gate.close();
        self.shared
            .command
            .store(ticketed(0, COMMAND_QUIT), Ordering::SeqCst);
        self.shared.control.signal();

        if !(self.shared.gate.drained(within) && self.shared.finished(within)) {
            // dropped without a join, which detaches it
            self.worker = None;
            return Err(Error::Draining {
                waited_millis: millis,
            });
        }

        if let Some(worker) = self.worker.take() {
            // already ended; a panic shows in the panic counter
            let _ = worker.join();
        }
        sys::check(
            "IAudioClient::Stop",
            self.shared.parting.load(Ordering::SeqCst),
        )
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // nothing to report a status to from here
        let _ = self.teardown();
    }
}

/// The capture end: what the microphone heard, as mono frames.
pub struct CaptureStream {
    session: Session,
}

/// The render end: what goes to the speaker, as mono frames.
///
/// "Render" is Windows' word for playback.
pub struct PlaybackStream {
    session: Session,
}

/// The methods that are the same in both directions.
///
/// A macro, so callers need no trait import and the copies cannot drift.
macro_rules! session_methods {
    () => {
        /// What the caller will actually be handed.
        ///
        /// The endpoint's rate (no resampling), with the requested frame
        /// duration.
        #[must_use]
        pub const fn format(&self) -> StreamFormat {
            self.session.delivered
        }

        /// What the endpoint runs, in its own terms.
        ///
        /// Explains a [`Self::format`] rate other than the one requested.
        #[must_use]
        pub const fn device_format(&self) -> DeviceFormat {
            self.session.format
        }

        /// Which endpoint it landed on.
        #[must_use]
        pub const fn device(&self) -> &Device {
            &self.session.device
        }

        /// What `IAudioClient::GetStreamLatency` says the engine adds, which is
        /// the part of the mouth-to-ear budget that belongs to Windows.
        ///
        /// One direction only: an echo canceller wants the speaker's plus the
        /// microphone's (CoreAudio's duplex `Stream::latency` gives both).
        #[must_use]
        pub const fn latency(&self) -> Duration {
            self.session.latency
        }

        /// Whether Windows took the stream as a call.
        ///
        /// Asked for in both directions, since the canceller's reference must
        /// be a communications stream too. It reports acceptance, not that
        /// anything is cancelling (see [`Category`]); anything other than
        /// [`Category::Communications`] means no system processing.
        #[must_use]
        pub const fn category(&self) -> Category {
            self.session.category
        }

        /// Frames in the engine's own buffer, which is the period it comes back
        /// for.
        #[must_use]
        pub const fn buffer_frames(&self) -> u32 {
            self.session.buffer_frames
        }

        /// Whether the multimedia class scheduler took the audio thread into
        /// the Pro Audio class.
        ///
        /// `false`: it still runs, but expect glitches.
        #[must_use]
        pub fn priority_raised(&self) -> bool {
            self.session.shared.pro_audio.load(Ordering::Relaxed)
        }

        /// Whether the endpoint is running.
        ///
        /// This goes false on its own when Windows invalidates the endpoint —
        /// unplugged, or its format changed from the control panel;
        /// [`Self::poll`] is what says that is why.
        #[must_use]
        pub fn is_running(&self) -> bool {
            self.session.shared.running.load(Ordering::SeqCst)
        }

        /// The volume, the mute and the meter for this direction.
        ///
        /// A handle for the UI thread; it survives a recover.
        #[must_use]
        pub fn controls(&self) -> Controls {
            Controls::new(&self.session.channel)
        }

        /// Ask whether Windows has taken the endpoint away, and say so once.
        ///
        /// One atomic load and no calls into Windows, so it can be polled
        /// beside the meter. Every answer after the first is `None`, because
        /// an endpoint does not go twice.
        ///
        /// What it reports is exact rather than inferred: every WASAPI call
        /// the audio thread makes answers `AUDCLNT_E_DEVICE_INVALIDATED` once
        /// the endpoint has gone, and nothing else in this crate treats that
        /// status as survivable. That includes `Start`, `Stop` and `Reset`, so
        /// an endpoint that went while the stream was stopped is reported by
        /// the next [`Self::start`], and here straight after. Not by a
        /// [`Self::stop`]: stopping a stream that is not running asks Windows
        /// nothing, so it finds nothing. A stop finds the endpoint gone only
        /// on a running stream, before a buffer pass has.
        ///
        /// A stream that has said [`StreamEvent::DeviceLost`] has stopped.
        /// What it had already captured can still be read out; nothing further
        /// arrives, and the speaker ring fills and takes no more.
        /// [`Self::recover`] is what puts an endpoint back under it.
        pub fn poll(&mut self) -> Option<StreamEvent> {
            self.session.poll()
        }

        /// What the endpoint has been doing since it opened.
        #[must_use]
        pub fn counters(&self) -> Counters {
            self.session.shared.meters.read()
        }

        /// Start the endpoint.
        ///
        /// # Errors
        /// [`Error::Call`] from `IAudioClient::Start`, [`Error::NoDevice`] when
        /// the endpoint has already gone away, or [`Error::Draining`] when the
        /// audio thread does not answer.
        ///
        /// If the endpoint went while stopped, this is an [`Error::Call`]
        /// with `AUDCLNT_E_DEVICE_INVALIDATED`, [`Self::poll`] then reports
        /// [`StreamEvent::DeviceLost`], and [`Self::recover`] treats the
        /// stream as started.
        pub fn start(&mut self) -> Result<(), Error> {
            self.session.start()
        }

        /// Stop the endpoint. What is already in the ring stays there; what the
        /// engine still held is discarded.
        ///
        /// # Errors
        /// As [`Self::start`], from `IAudioClient::Stop`.
        pub fn stop(&mut self) -> Result<(), Error> {
            self.session.stop()
        }

        /// Shut the endpoint down and say what Windows made of it.
        ///
        /// Same as dropping, but the status is returned.
        ///
        /// # Errors
        /// [`Error::Draining`] when the audio thread did not finish within two
        /// seconds; it is then detached with its handles left open on
        /// purpose. Otherwise [`Error::Call`] from the last stop.
        pub fn close(mut self) -> Result<(), Error> {
            self.session.teardown()
        }
    };
}

impl CaptureStream {
    /// Open a capture endpoint, without starting it.
    ///
    /// # Errors
    /// [`Error::NoDevice`] when there is no such endpoint, [`Error::Call`]
    /// naming whichever call refused — a microphone the user has not granted,
    /// an endpoint another application holds exclusively — or
    /// [`Error::SampleFormat`] when the endpoint runs something this crate will
    /// not read.
    pub fn open(config: &StreamConfig) -> Result<Self, Error> {
        let window = window_samples(config.format.sample_rate_hz());
        Ok(Self {
            session: Session::open(config, Direction::Input, Arc::new(Channel::new(window)))?,
        })
    }

    /// Open again, on whatever this stream's [`StreamConfig`] names now.
    ///
    /// The answer to [`StreamEvent::DeviceLost`].
    /// [`StreamConfig::preferring`] falls back to the system route;
    /// [`StreamConfig::on`] fails if its endpoint is gone.
    ///
    /// Gain, mute and existing [`Controls`] carry over; ring contents do not.
    /// A started stream is restarted. The rate may change, so re-read
    /// [`Self::format`].
    ///
    /// # Errors
    /// [`Error::Draining`] when the old audio thread did not finish; nothing
    /// is reopened then. Otherwise what [`Self::open`] would say.
    pub fn recover(self) -> Result<Self, Error> {
        Ok(Self {
            session: self.session.recovered(Direction::Input)?,
        })
    }

    /// Fill `frame` from the microphone, or leave it untouched and say `false`
    /// because a whole frame is not there yet.
    pub fn read(&mut self, frame: &mut [i16]) -> bool {
        self.session
            .ring()
            .is_some_and(|ring| ring.read_frame(frame))
    }

    /// Samples waiting. A growing number means the reader is falling behind.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.session.ring().map_or(0, Ring::filled)
    }

    session_methods!();
}

impl PlaybackStream {
    /// Open a render endpoint, without starting it.
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

    /// Queue `frame` for the speaker, or say `false` because there is no room
    /// for a whole one. Nothing is queued in that case.
    pub fn write(&mut self, frame: &[i16]) -> bool {
        self.session
            .ring()
            .is_some_and(|ring| ring.write_frame(frame))
    }

    /// Samples that would fit right now.
    #[must_use]
    pub fn room(&self) -> usize {
        self.session.ring().map_or(0, Ring::free)
    }

    /// Samples queued, from the ring's own count (depth minus
    /// [`room`](Self::room) would include power-of-two rounding).
    #[must_use]
    pub fn queued(&self) -> usize {
        self.session.ring().map_or(0, Ring::filled)
    }

    session_methods!();
}

/// Everything the audio thread owns.
struct Engine {
    client: Com<AudioClientVtable>,
    render: Option<Com<AudioRenderClientVtable>>,
    capture: Option<Com<AudioCaptureClientVtable>>,
    format: DeviceFormat,
    buffer_frames: u32,
    /// Sized once: the audio thread must not allocate.
    scratch: Box<[i16]>,
}

/// The audio thread.
///
/// Every COM object lives and dies on this thread, so once it returns every
/// reference is released and nothing the caller does can be too early.
fn run(
    shared: &Shared,
    choice: &DeviceChoice,
    direction: Direction,
    wanted: StreamFormat,
    depth: usize,
    processing: bool,
    sender: &mpsc::Sender<Result<Opened, Error>>,
) {
    let apartment = match Apartment::enter() {
        Ok(apartment) => apartment,
        Err(error) => {
            let _ = sender.send(Err(error));
            shared.ended.store(true, Ordering::SeqCst);
            return;
        }
    };

    match build(shared, choice, direction, wanted, depth, processing) {
        Ok((engine, opened)) => {
            let _ = sender.send(Ok(opened));
            serve(shared, engine, direction);
        }
        Err(error) => {
            let _ = sender.send(Err(error));
        }
    }

    drop(apartment);
    // last: tells the owner joining will not block and handles may close
    shared.ended.store(true, Ordering::SeqCst);
}

/// Open the endpoint, settle on a format, and get as far as being able to run.
fn build(
    shared: &Shared,
    choice: &DeviceChoice,
    direction: Direction,
    wanted: StreamFormat,
    depth: usize,
    processing: bool,
) -> Result<(Engine, Opened), Error> {
    let enumerator = endpoint::enumerator()?;
    let opened = endpoint::open_choice(&enumerator, choice, direction)?;
    let described = endpoint::describe(&enumerator, &opened, direction);

    // bound to a local so that what is pointed at outlives the call
    let interface = AudioClientVtable::IID;
    let mut raw: *mut c_void = ptr::null_mut();
    // SAFETY: a live identifier, a documented class context, no activation
    // parameters, and a live out-parameter of the interface named.
    let status = unsafe {
        (opened.vtable().activate)(
            opened.as_ptr(),
            &raw const interface,
            CLSCTX_ALL,
            ptr::null_mut(),
            &raw mut raw,
        )
    };
    sys::check("IMMDevice::Activate (IAudioClient)", status)?;
    // SAFETY: the call succeeded, so this is a live client.
    let client = unsafe { Com::<AudioClientVtable>::from_raw(raw.cast::<AudioClient>()) }
        .ok_or(Error::NoDevice)?;

    // first: format, period and processing may depend on the category
    let category = ask_for_communications(&client, processing);

    let settled = negotiate(&client, wanted.sample_rate_hz())?;
    let format = mixformat::describe(&settled)?;

    // zero durations: the engine's own period in event-driven shared mode
    // SAFETY: a live format that outlives the call, and no session identifier.
    let status = unsafe {
        (client.vtable().initialize)(
            client.as_ptr(),
            SHARE_MODE_SHARED,
            STREAMFLAGS_EVENTCALLBACK,
            0,
            0,
            &raw const settled.format,
            ptr::null(),
        )
    };
    sys::check("IAudioClient::Initialize", status)?;

    let mut buffer_frames: u32 = 0;
    // SAFETY: a live out-parameter on an initialised client.
    let status =
        unsafe { (client.vtable().get_buffer_size)(client.as_ptr(), &raw mut buffer_frames) };
    sys::check("IAudioClient::GetBufferSize", status)?;

    let mut latency: i64 = 0;
    // SAFETY: as above.
    let status = unsafe { (client.vtable().get_stream_latency)(client.as_ptr(), &raw mut latency) };
    sys::check("IAudioClient::GetStreamLatency", status)?;

    // only accepted between Initialize and Start
    // SAFETY: a live event handle. It outlives the client, because the client
    // is released on this thread before the reference to the shared state that
    // owns the handle is dropped.
    let status =
        unsafe { (client.vtable().set_event_handle)(client.as_ptr(), shared.ready.handle()) };
    sys::check("IAudioClient::SetEventHandle", status)?;

    let (render, capture) = service(&client, direction)?;

    let delivered = wanted
        .at_rate(format.sample_rate_hz)
        .ok_or(Error::SampleFormat {
            bits: 16,
            floating: false,
        })?;
    shared
        .channel
        .set_window(window_samples(delivered.sample_rate_hz()));
    let period = usize::try_from(buffer_frames).unwrap_or(0).max(1);
    // at least two engine periods, or every period loses samples
    let samples = delivered
        .frame_samples()
        .saturating_mul(depth)
        .max(period * 2);
    let _ = shared.ring.set(Ring::new(samples));

    Ok((
        Engine {
            client,
            render,
            capture,
            format,
            buffer_frames,
            scratch: vec![0i16; period].into_boxed_slice(),
        },
        Opened {
            device: described,
            format,
            delivered,
            latency: reference_time(latency),
            buffer_frames,
            category,
        },
    ))
}

/// Tell the client this stream is a call, before it is too late to say so.
///
/// `AudioCategory_Communications` enables the endpoint's voice processing and
/// is accepted only between activation and initialisation, and cannot be
/// queried later, so the answer is kept with the stream.
///
/// A refusal does not fail the open; [`Category`] tells the application.
fn ask_for_communications(client: &Com<AudioClientVtable>, processing: bool) -> Category {
    // bound to a local so that what is pointed at outlives the call
    let interface = AudioClient2Vtable::IID;
    let mut raw: *mut c_void = ptr::null_mut();
    // SAFETY: every vtable in `abi` begins with the three IUnknown slots, so
    // this is the same cast the C headers make; the identifier and the
    // out-parameter are live locals.
    let status = unsafe {
        (client.vtable().unknown.query_interface)(
            client.as_ptr().cast::<Unknown>(),
            &raw const interface,
            &raw mut raw,
        )
    };
    if !HResult::new(status).is_ok() {
        return Category::Unavailable;
    }
    // SAFETY: the call succeeded, so this is a live `IAudioClient2` carrying a
    // reference of its own, which this value gives back when it goes.
    let Some(client) = (unsafe { Com::<AudioClient2Vtable>::from_raw(raw.cast::<AudioClient2>()) })
    else {
        // a success that handed over nothing, which no implementation does
        return Category::Unavailable;
    };

    let asked = if processing {
        AudioClientProperties::COMMUNICATIONS
    } else {
        AudioClientProperties::COMMUNICATIONS_RAW
    };
    // SAFETY: a live client and a live structure that outlives the call, whose
    // own first field says how much of it Windows may read.
    let status =
        unsafe { (client.vtable().set_client_properties)(client.as_ptr(), &raw const asked) };
    Category::from_status(HResult::new(status), processing)
}

/// A `REFERENCE_TIME` as a duration.
///
/// Units of 100 ns. Negative values do not occur; the magnitude is taken.
fn reference_time(ticks: i64) -> Duration {
    let ticks = ticks.unsigned_abs();
    let per_second = REFERENCE_TIMES_PER_SECOND.unsigned_abs();
    let leftover = (ticks % per_second).saturating_mul(100);
    Duration::new(ticks / per_second, u32::try_from(leftover).unwrap_or(0))
}

/// Ask for mono sixteen-bit, and decide what to do with the answer.
///
/// `S_OK`: exactly as asked (rare outside virtual cables). `S_FALSE`: the
/// offered closest match (the mix format) is taken. Anything else: the mix
/// format is asked for directly.
///
/// `AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM` is deliberately not used: a hidden
/// resampler here would fight `sipral-media`'s drift correction.
fn negotiate(
    client: &Com<AudioClientVtable>,
    sample_rate_hz: u32,
) -> Result<WaveFormatExtensible, Error> {
    let asked = mixformat::request(sample_rate_hz);
    let mut closest: *mut WaveFormat = ptr::null_mut();
    // SAFETY: a live format that outlives the call, and a live out-parameter
    // for a pointer this side then owns.
    let status = unsafe {
        (client.vtable().is_format_supported)(
            client.as_ptr(),
            SHARE_MODE_SHARED,
            &raw const asked.format,
            &raw mut closest,
        )
    };
    // SAFETY: task memory when the call left any, null otherwise.
    let offered = unsafe { TaskMemory::from_raw(closest) };

    if HResult::new(status) == HResult::OK {
        return Ok(asked);
    }
    if let Some(offered) = offered {
        // SAFETY: a live WAVEFORMATEX, read header first and extension only
        // when the header says there is one.
        if let Some(format) = unsafe { read_wave(offered.as_ptr()) } {
            return Ok(format);
        }
    }

    let mut mixed: *mut WaveFormat = ptr::null_mut();
    // SAFETY: a live out-parameter for a pointer this side then owns.
    let status = unsafe { (client.vtable().get_mix_format)(client.as_ptr(), &raw mut mixed) };
    sys::check("IAudioClient::GetMixFormat", status)?;
    let unreadable = Error::Call {
        call: "IAudioClient::GetMixFormat",
        status: HResult::new(AUDCLNT_E_UNSUPPORTED_FORMAT),
    };
    // SAFETY: the call succeeded, so this is task memory holding a format.
    let mixed = unsafe { TaskMemory::from_raw(mixed) }.ok_or(unreadable)?;
    // SAFETY: as above.
    unsafe { read_wave(mixed.as_ptr()) }.ok_or(unreadable)
}

/// Copy a `WAVEFORMATEX` out of memory Windows owns, taking the extension only
/// when its own `cbSize` says it is there.
///
/// Variable length and byte-packed: with `cbSize` zero there are only 18
/// octets, so reading 40 would overrun.
///
/// # Safety
/// `pointer` is null, or a live `WAVEFORMATEX` followed by as many octets as
/// its own `cbSize` declares.
unsafe fn read_wave(pointer: *const WaveFormat) -> Option<WaveFormatExtensible> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the caller's live header, read unaligned because the structure is
    // byte-packed and Windows makes no promise about where it put it.
    let header = unsafe { ptr::read_unaligned(pointer) };
    if header.cb_size >= WaveFormatExtensible::EXTENSION_BYTES {
        // SAFETY: the header says at least twenty-two octets follow it, which
        // is exactly the extension being read here.
        let mut whole = unsafe { ptr::read_unaligned(pointer.cast::<WaveFormatExtensible>()) };
        // A larger original cbSize would make Initialize read past this copy.
        whole.format.cb_size = WaveFormatExtensible::EXTENSION_BYTES;
        return Some(whole);
    }
    let mut whole = WaveFormatExtensible::EMPTY;
    whole.format = header;
    Some(whole)
}

/// Channels in an endpoint's shared-mode mix format, for device lists.
///
/// Reads the mix format without initialising a client, leaving nothing
/// open. The count is for `direction`; endpoints are one-directional.
///
/// # Errors
/// [`Error::NoDevice`] for an identifier the machine does not have, and
/// [`Error::Call`] naming whichever call refused.
pub fn channels(id: &DeviceId, direction: Direction) -> Result<u16, Error> {
    let _apartment = Apartment::enter()?;
    let enumerator = endpoint::enumerator()?;
    let opened = endpoint::open(&enumerator, Some(id), direction)?;
    let interface = AudioClientVtable::IID;
    let mut raw: *mut c_void = ptr::null_mut();
    // SAFETY: a live endpoint, a documented interface identifier and a live
    // out-parameter.
    let status = unsafe {
        (opened.vtable().activate)(
            opened.as_ptr(),
            &raw const interface,
            CLSCTX_ALL,
            ptr::null_mut(),
            &raw mut raw,
        )
    };
    sys::check("IMMDevice::Activate (IAudioClient)", status)?;
    // SAFETY: the call succeeded, so the pointer is a live client whose
    // reference this takes over.
    let client = unsafe { Com::<AudioClientVtable>::from_raw(raw.cast::<AudioClient>()) }
        .ok_or(Error::NoDevice)?;
    let mut mixed: *mut WaveFormat = ptr::null_mut();
    // SAFETY: a live client and a live out-parameter.
    let status = unsafe { (client.vtable().get_mix_format)(client.as_ptr(), &raw mut mixed) };
    sys::check("IAudioClient::GetMixFormat", status)?;
    let unreadable = Error::Call {
        call: "IAudioClient::GetMixFormat",
        status: HResult::new(AUDCLNT_E_UNSUPPORTED_FORMAT),
    };
    // SAFETY: what the call wrote is task memory this takes over.
    let mixed = unsafe { TaskMemory::from_raw(mixed) }.ok_or(unreadable)?;
    // SAFETY: the memory holds the format the call wrote.
    let wave = unsafe { read_wave(mixed.as_ptr()) }.ok_or(unreadable)?;
    Ok(mixformat::describe(&wave)?.channels)
}

/// The render client for an output endpoint, the capture client for an input
/// one, and never both: a WASAPI client serves one direction.
type Services = (
    Option<Com<AudioRenderClientVtable>>,
    Option<Com<AudioCaptureClientVtable>>,
);

/// The one service interface a direction needs.
fn service(client: &Com<AudioClientVtable>, direction: Direction) -> Result<Services, Error> {
    let (call, iid) = match direction {
        Direction::Input => (
            "IAudioClient::GetService (IAudioCaptureClient)",
            AudioCaptureClientVtable::IID,
        ),
        Direction::Output => (
            "IAudioClient::GetService (IAudioRenderClient)",
            AudioRenderClientVtable::IID,
        ),
    };
    let mut raw: *mut c_void = ptr::null_mut();
    // SAFETY: a static identifier and a live out-parameter of the interface it
    // names.
    let status =
        unsafe { (client.vtable().get_service)(client.as_ptr(), &raw const iid, &raw mut raw) };
    sys::check(call, status)?;
    match direction {
        // SAFETY: the call succeeded, so this is a live capture client.
        Direction::Input => Ok((None, unsafe {
            Com::from_raw(raw.cast::<AudioCaptureClient>())
        })),
        // SAFETY: as above, a live render client.
        Direction::Output => Ok((
            unsafe { Com::from_raw(raw.cast::<AudioRenderClient>()) },
            None,
        )),
    }
}

/// The loop: wait for the engine or for a command, and do one or the other.
fn serve(shared: &Shared, mut engine: Engine, direction: Direction) {
    let priority = Priority::pro_audio();
    shared
        .pro_audio
        .store(priority.is_some(), Ordering::Relaxed);

    let handles: [Handle; 2] = [shared.ready.handle(), shared.control.handle()];

    loop {
        // SAFETY: two live handles, in an array of the length being declared.
        let woken =
            unsafe { sys::wait_for_multiple_objects(2, handles.as_ptr(), 0, STALL_AFTER_MILLIS) };
        if woken == WAIT_OBJECT_0 {
            if !pass(shared, &mut engine, direction) {
                break;
            }
        } else if woken == WAIT_OBJECT_0 + 1 {
            if !command(shared, &mut engine, direction) {
                break;
            }
        } else if woken == WAIT_TIMEOUT {
            if shared.running.load(Ordering::SeqCst) {
                Meters::add(&shared.meters.stalls, 1);
            }
        } else {
            // the wait itself failed, which means a handle is not what it was;
            // there is nothing to do but leave
            break;
        }
    }

    let parting = if shared.running.load(Ordering::SeqCst) {
        // SAFETY: a live client that this thread started.
        unsafe { (engine.client.vtable().stop)(engine.client.as_ptr()) }
    } else {
        0
    };
    // record a loss: the loop may have ended without the owner asking
    carry_on(shared, parting);
    shared.running.store(false, Ordering::SeqCst);
    shared.channel.quiet();
    shared.parting.store(parting, Ordering::SeqCst);
    drop(priority);
}

/// Carry out whatever the owner asked for. `false` means leave the loop.
///
/// An invalidated endpoint found by `Start`, `Stop` or `Reset` ends the loop
/// like one found by a buffer pass, and is recorded before replying so the
/// owner can poll the reason at once.
fn command(shared: &Shared, engine: &mut Engine, direction: Direction) -> bool {
    let (ticket, wanted) = unticket(
        shared
            .command
            .swap(ticketed(0, COMMAND_NONE), Ordering::SeqCst),
    );
    match wanted {
        COMMAND_START => {
            let status = start(shared, engine, direction);
            let survived = carry_on(shared, status);
            reply(shared, ticket, status);
            survived
        }
        COMMAND_STOP => {
            // SAFETY: a live client.
            let stopped = unsafe { (engine.client.vtable().stop)(engine.client.as_ptr()) };
            shared.running.store(false, Ordering::SeqCst);
            // reset (legal only while stopped) so a restart replays nothing
            // SAFETY: a live, stopped client.
            let cleared = unsafe { (engine.client.vtable().reset)(engine.client.as_ptr()) };
            shared.channel.quiet();
            let first = if HResult::new(stopped).is_ok() {
                cleared
            } else {
                stopped
            };
            // either may have found the endpoint gone
            let survived = carry_on(shared, stopped) && carry_on(shared, cleared);
            reply(shared, ticket, first);
            survived
        }
        COMMAND_QUIT => false,
        // a spurious wake, or a command already taken: nothing to do and
        // nothing to answer
        _ => true,
    }
}

/// Hand the owner what a command came to, under the ticket it was sent with.
fn reply(shared: &Shared, ticket: u32, status: i32) {
    shared
        .outcome
        .store(ticketed(ticket, status.cast_unsigned()), Ordering::SeqCst);
    shared.answered.signal();
}

/// Fill the engine's buffer and start it.
///
/// Prefill is required: the first event comes a period after `Start`, so an
/// empty buffer is a gap and on some drivers a glitch.
fn start(shared: &Shared, engine: &mut Engine, direction: Direction) -> i32 {
    if direction == Direction::Output {
        let room = engine.buffer_frames;
        if room > 0 {
            let _ = fill(shared, engine, room);
        }
    }
    // SAFETY: a live, initialised client with its event handle set.
    let status = unsafe { (engine.client.vtable().start)(engine.client.as_ptr()) };
    if HResult::new(status).is_ok() {
        shared.running.store(true, Ordering::SeqCst);
    }
    status
}

/// One pass over the endpoint's buffer. `false` means leave the loop.
///
/// Everything under here runs at Pro Audio priority with a period to meet, so
/// it allocates nothing, takes no lock and logs nothing. A panic would be a bug
/// in this crate rather than a condition, so it is caught, counted and turned
/// into silence rather than allowed to end the thread.
fn pass(shared: &Shared, engine: &mut Engine, direction: Direction) -> bool {
    let Some(_inside) = shared.gate.enter() else {
        // teardown has begun: touch nothing it may be waiting to take away
        return false;
    };
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| match direction {
        Direction::Input => capture_pass(shared, engine),
        Direction::Output => render_pass(shared, engine),
    }));
    outcome.unwrap_or_else(|_| {
        Meters::add(&shared.meters.panics, 1);
        true
    })
}

/// Whether a failed call is worth carrying on after.
///
/// Everything but an invalidated endpoint (unplugged, or format changed),
/// which never comes back: the loop ends and `is_running` goes false.
fn survivable(status: i32) -> bool {
    status != AUDCLNT_E_DEVICE_INVALIDATED
}

/// The same, and it writes down what it found.
///
/// The flag is the only record of "taken away" versus "stopped".
fn carry_on(shared: &Shared, status: i32) -> bool {
    let survived = survivable(status);
    if !survived {
        shared.lost.store(true, Ordering::SeqCst);
    }
    survived
}

/// Take what the endpoint captured and put it in the ring.
fn capture_pass(shared: &Shared, engine: &mut Engine) -> bool {
    let Some(client) = engine.capture.as_ref() else {
        return false;
    };
    loop {
        let mut packet: u32 = 0;
        // SAFETY: a live out-parameter.
        let status =
            unsafe { (client.vtable().get_next_packet_size)(client.as_ptr(), &raw mut packet) };
        if !HResult::new(status).is_ok() {
            Meters::add(&shared.meters.buffer_failures, 1);
            return carry_on(shared, status);
        }
        if packet == 0 {
            return true;
        }

        let mut data: *mut u8 = ptr::null_mut();
        let mut frames: u32 = 0;
        let mut flags: u32 = 0;
        // SAFETY: three live out-parameters. The two position ones are
        // documented as optional and are not wanted: this stack takes its clock
        // from the far end rather than from the device.
        let status = unsafe {
            (client.vtable().get_buffer)(
                client.as_ptr(),
                &raw mut data,
                &raw mut frames,
                &raw mut flags,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if !HResult::new(status).is_ok() {
            Meters::add(&shared.meters.buffer_failures, 1);
            return carry_on(shared, status);
        }

        if flags & BUFFERFLAGS_DATA_DISCONTINUITY != 0 {
            Meters::add(&shared.meters.discontinuities, 1);
        }
        let wanted = usize::try_from(frames)
            .unwrap_or(0)
            .min(engine.scratch.len());
        if let Some(mono) = engine.scratch.get_mut(..wanted) {
            if flags & BUFFERFLAGS_SILENT == 0 && !data.is_null() {
                let bytes = wanted * engine.format.block_align();
                // SAFETY: the engine declares `frames` frames at `data` and
                // `wanted` is no more than that, so the slice is inside the
                // buffer it handed over, for the length of this call.
                let source = unsafe { core::slice::from_raw_parts(data, bytes) };
                fold(source, engine.format, mono);
            } else {
                // contents undefined: nothing was recorded
                mono.fill(0);
            }
            // a muted microphone still delivers silence, so nothing piles up
            shared.channel.apply(mono, wanted);
            if let Some(ring) = shared.ring.get() {
                let stored = ring.write(mono);
                Meters::add(&shared.meters.captured, stored);
                Meters::add(&shared.meters.capture_dropped, wanted - stored);
            }
        }

        // SAFETY: releasing exactly the frames the buffer was got with, which
        // is what the interface requires and the only thing that stops the next
        // GetBuffer refusing.
        let status = unsafe { (client.vtable().release_buffer)(client.as_ptr(), frames) };
        if !HResult::new(status).is_ok() {
            Meters::add(&shared.meters.buffer_failures, 1);
            return carry_on(shared, status);
        }
    }
}

/// Fill whatever room the endpoint has from the ring.
fn render_pass(shared: &Shared, engine: &mut Engine) -> bool {
    if engine.render.is_none() {
        return false;
    }
    let mut padding: u32 = 0;
    // SAFETY: a live out-parameter on an initialised client.
    let status = unsafe {
        (engine.client.vtable().get_current_padding)(engine.client.as_ptr(), &raw mut padding)
    };
    if !HResult::new(status).is_ok() {
        Meters::add(&shared.meters.buffer_failures, 1);
        return carry_on(shared, status);
    }
    let room = engine.buffer_frames.saturating_sub(padding);
    if room == 0 {
        return true;
    }
    fill(shared, engine, room)
}

/// Put `room` frames into the endpoint's buffer, from the ring or as silence.
fn fill(shared: &Shared, engine: &mut Engine, room: u32) -> bool {
    let Some(client) = engine.render.as_ref() else {
        return false;
    };
    let mut data: *mut u8 = ptr::null_mut();
    // SAFETY: asking for no more than the buffer has room for, and a live
    // out-parameter for the pointer it hands back.
    let status = unsafe { (client.vtable().get_buffer)(client.as_ptr(), room, &raw mut data) };
    if !HResult::new(status).is_ok() {
        Meters::add(&shared.meters.buffer_failures, 1);
        return carry_on(shared, status);
    }

    let wanted = usize::try_from(room).unwrap_or(0).min(engine.scratch.len());
    let taken = match (shared.ring.get(), engine.scratch.get_mut(..wanted)) {
        (Some(ring), Some(mono)) => ring.read(mono),
        _ => 0,
    };
    // applied here so a mute is heard at once; `wanted` so starved silence
    // still advances the meter window
    if let Some(played) = engine.scratch.get_mut(..taken) {
        shared.channel.apply(played, wanted);
    }
    Meters::add(&shared.meters.played, taken);
    Meters::add(&shared.meters.playback_starved, wanted - taken);

    let mut released = 0;
    if taken == 0 || data.is_null() {
        // the silent flag is cheaper than zeroing
        released = BUFFERFLAGS_SILENT;
    } else {
        let block = engine.format.block_align();
        let bytes = usize::try_from(room).unwrap_or(0) * block;
        // SAFETY: the engine declares `room` frames at `data`, which is `bytes`
        // octets, and nothing else reads them until they are released.
        let out = unsafe { core::slice::from_raw_parts_mut(data, bytes) };
        let written = engine
            .scratch
            .get(..taken)
            .map_or(0, |mono| spread(mono, engine.format, out));
        if let Some(rest) = out.get_mut(written.saturating_mul(block)..) {
            silence(rest);
        }
    }

    // SAFETY: releasing exactly the frames the buffer was got with.
    let status = unsafe { (client.vtable().release_buffer)(client.as_ptr(), room, released) };
    if !HResult::new(status).is_ok() {
        Meters::add(&shared.meters.buffer_failures, 1);
        return carry_on(shared, status);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{
        COMMAND_QUIT, COMMAND_START, COMMAND_STOP, CaptureStream, Category, DEFAULT_DEPTH_FRAMES,
        Engine, PlaybackStream, Session, Shared, StreamConfig, carry_on, command, read_wave, serve,
        survivable, ticketed, unticket,
    };
    use crate::abi::{
        AudioClient, AudioClientVtable, Guid, Handle, SUBTYPE_IEEE_FLOAT, WAVE_FORMAT_EXTENSIBLE,
        WAVE_FORMAT_PCM, WaveFormat, WaveFormatExtensible,
    };
    use crate::device::Device;
    use crate::device::{DeviceChoice, DeviceId, Direction, StreamEvent};
    use crate::endpoint::devices;
    use crate::fake::{self, Fake, NOT_IMPLEMENTED};
    use crate::format::{SampleFormat, StreamFormat};
    use crate::level::{Channel, Controls, Gain, Level, window_samples};
    use crate::status::{AUDCLNT_E_DEVICE_INVALIDATED, E_POINTER, Error, HResult};
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    /// `AUDCLNT_E_NOT_INITIALIZED`: a refusal, and not a loss.
    const NOT_INITIALIZED: i32 = 0x8889_0001_u32.cast_signed();

    #[test]
    fn a_configuration_defaults_to_the_system_route() {
        let config = StreamConfig::default();
        assert_eq!(config.format, StreamFormat::narrowband());
        assert_eq!(config.device, DeviceChoice::System);
        assert_eq!(config.depth_frames, DEFAULT_DEPTH_FRAMES);

        let id = DeviceId::new("{0.0.1.00000000}.{x}");
        let named = StreamConfig::on(id.clone(), config.format);
        assert_eq!(named.device, DeviceChoice::Device(id.clone()));
        // the same endpoint, and the other answer to it not being there
        let saved = StreamConfig::preferring(id.clone(), config.format);
        assert_eq!(saved.device, DeviceChoice::Preferred(id));
        assert_eq!(saved.depth_frames, DEFAULT_DEPTH_FRAMES);
    }

    fn channel() -> Arc<Channel> {
        Arc::new(Channel::new(window_samples(8_000)))
    }

    /// A session with no audio thread behind it.
    ///
    /// `ended` is preset so the destructor does not wait out the deadline.
    fn detached(channel: &Arc<Channel>) -> Session {
        let shared = Arc::new(Shared::new(Arc::clone(channel)).expect("three event handles"));
        shared.ended.store(true, Ordering::SeqCst);
        session(shared, None, channel)
    }

    /// The owner's half of a stream, over whatever audio thread the test has.
    fn session(
        shared: Arc<Shared>,
        worker: Option<JoinHandle<()>>,
        channel: &Arc<Channel>,
    ) -> Session {
        Session {
            shared,
            worker,
            device: Device {
                id: DeviceId::new("{0.0.1.00000000}.{gone}"),
                name: "A headset in a bag".to_string(),
                direction: Direction::Input,
                is_default: false,
            },
            format: crate::format::DeviceFormat {
                sample_rate_hz: 48_000,
                channels: 2,
                sample: SampleFormat::F32,
            },
            delivered: StreamFormat::narrowband(),
            latency: Duration::ZERO,
            buffer_frames: 480,
            category: Category::Communications,
            config: StreamConfig::default(),
            channel: Arc::clone(channel),
            started: false,
            loss_reported: false,
            closed: false,
            tickets: 0,
        }
    }

    /// What one client call comes to, and how long the driver takes over it.
    #[derive(Default)]
    struct Answer {
        status: AtomicI32,
        millis: AtomicU32,
    }

    impl Answer {
        fn set(&self, status: i32, millis: u32) {
            self.status.store(status, Ordering::SeqCst);
            self.millis.store(millis, Ordering::SeqCst);
        }

        fn give(&self) -> i32 {
            let millis = self.millis.load(Ordering::SeqCst);
            if millis > 0 {
                thread::sleep(Duration::from_millis(u64::from(millis)));
            }
            self.status.load(Ordering::SeqCst)
        }
    }

    /// The three calls a command makes of the client. Everything else the
    /// client has is never reached from a command, and answers `E_NOTIMPL`.
    #[derive(Default)]
    struct Script {
        start: Answer,
        stop: Answer,
        reset: Answer,
        /// Delay between the loop ending and the thread being gone; only the
        /// delay is read.
        leaving: Answer,
    }

    static CLIENT: AudioClientVtable = AudioClientVtable {
        unknown: fake::unknown::<AudioClientVtable, Arc<Script>>(),
        initialize: client_initialize,
        get_buffer_size: client_count,
        get_stream_latency: client_latency,
        get_current_padding: client_count,
        is_format_supported: client_format_supported,
        get_mix_format: client_mix_format,
        get_device_period: client_period,
        start: client_start,
        stop: client_stop,
        reset: client_reset,
        set_event_handle: client_event_handle,
        get_service: client_service,
    };

    unsafe extern "system" fn client_initialize(
        _this: *mut AudioClient,
        _share: u32,
        _flags: u32,
        _duration: i64,
        _periodicity: i64,
        _format: *const WaveFormat,
        _session: *const Guid,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn client_count(_this: *mut AudioClient, _out: *mut u32) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn client_latency(_this: *mut AudioClient, _out: *mut i64) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn client_format_supported(
        _this: *mut AudioClient,
        _share: u32,
        _format: *const WaveFormat,
        _closest: *mut *mut WaveFormat,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn client_mix_format(
        _this: *mut AudioClient,
        _out: *mut *mut WaveFormat,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn client_period(
        _this: *mut AudioClient,
        _default: *mut i64,
        _minimum: *mut i64,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn client_event_handle(_this: *mut AudioClient, _event: Handle) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn client_service(
        _this: *mut AudioClient,
        _interface: *const Guid,
        _out: *mut *mut c_void,
    ) -> i32 {
        NOT_IMPLEMENTED
    }

    unsafe extern "system" fn client_start(this: *mut AudioClient) -> i32 {
        // SAFETY: `this` is the address of a live `Fake` over this table.
        unsafe { fake::script::<AudioClientVtable, Arc<Script>>(this) }
            .map_or(E_POINTER, |script| script.start.give())
    }

    unsafe extern "system" fn client_stop(this: *mut AudioClient) -> i32 {
        // SAFETY: as above.
        unsafe { fake::script::<AudioClientVtable, Arc<Script>>(this) }
            .map_or(E_POINTER, |script| script.stop.give())
    }

    unsafe extern "system" fn client_reset(this: *mut AudioClient) -> i32 {
        // SAFETY: as above.
        unsafe { fake::script::<AudioClientVtable, Arc<Script>>(this) }
            .map_or(E_POINTER, |script| script.reset.give())
    }

    /// What the audio thread owns, with the fake as its client and nothing
    /// else: no service interface, so a pass would leave the loop, and no
    /// event handle given to the client, so no pass ever comes.
    fn engine(client: &Fake<AudioClientVtable, Arc<Script>>) -> Engine {
        Engine {
            client: client.com(),
            render: None,
            capture: None,
            format: crate::format::DeviceFormat {
                sample_rate_hz: 48_000,
                channels: 2,
                sample: SampleFormat::F32,
            },
            buffer_frames: 0,
            scratch: Box::default(),
        }
    }

    /// A session whose audio thread is the real loop, in front of a client
    /// the script decides for.
    fn scripted(script: &Arc<Script>, channel: &Arc<Channel>) -> Session {
        let shared = Arc::new(Shared::new(Arc::clone(channel)).expect("three event handles"));
        let worker = {
            let shared = Arc::clone(&shared);
            let script = Arc::clone(script);
            thread::spawn(move || {
                let client = Fake::new(&CLIENT, Arc::clone(&script));
                serve(&shared, engine(&client), Direction::Input);
                drop(client);
                let _ = script.leaving.give();
                shared.ended.store(true, Ordering::SeqCst);
            })
        };
        session(shared, Some(worker), channel)
    }

    #[test]
    fn a_start_refused_because_the_endpoint_went_while_stopped_is_a_loss() {
        let script = Arc::new(Script::default());
        script.start.set(AUDCLNT_E_DEVICE_INVALIDATED, 0);
        let channel = channel();
        let mut session = scripted(&script, &channel);

        assert_eq!(
            session.start(),
            Err(Error::Call {
                call: "IAudioClient::Start",
                status: HResult::new(AUDCLNT_E_DEVICE_INVALIDATED),
            })
        );
        assert_eq!(
            session.poll(),
            Some(StreamEvent::DeviceLost),
            "the owner was told the start failed, and never why"
        );
        assert!(
            session.started,
            "recover starts only what was started, and this was asked to run"
        );
        assert!(
            session.shared.finished(Duration::from_secs(2)),
            "the audio thread stayed behind, waiting on an invalidated client"
        );
        assert_eq!(session.teardown(), Ok(()));
    }

    #[test]
    fn a_start_sent_after_the_endpoint_was_found_gone_is_not_left_waiting() {
        let script = Arc::new(Script::default());
        script.start.set(AUDCLNT_E_DEVICE_INVALIDATED, 0);
        // the loop is over at once, the thread is gone a second later
        script.leaving.set(0, 1_000);
        let channel = channel();
        let mut session = scripted(&script, &channel);

        assert_eq!(
            session.start(),
            Err(Error::Call {
                call: "IAudioClient::Start",
                status: HResult::new(AUDCLNT_E_DEVICE_INVALIDATED),
            })
        );
        // a retry while the thread is still leaving: nobody answers
        let asked = Instant::now();
        assert_eq!(
            session.start(),
            Err(Error::NoDevice),
            "the second start waited out the deadline on a loop already left"
        );
        assert!(
            asked.elapsed() < Duration::from_millis(500),
            "the second start took {:?} to say the endpoint is gone",
            asked.elapsed()
        );
        assert_eq!(session.poll(), Some(StreamEvent::DeviceLost));
        assert!(
            session.started,
            "the owner still asked for a running stream"
        );
    }

    #[test]
    fn a_stop_or_a_reset_that_finds_the_endpoint_gone_is_a_loss() {
        const TICKET: u32 = 7;
        for (stop, reset) in [
            (AUDCLNT_E_DEVICE_INVALIDATED, 0),
            (0, AUDCLNT_E_DEVICE_INVALIDATED),
            (NOT_INITIALIZED, 0),
        ] {
            let script = Arc::new(Script::default());
            script.stop.set(stop, 0);
            script.reset.set(reset, 0);
            let client = Fake::new(&CLIENT, Arc::clone(&script));
            let mut engine = engine(&client);
            let shared = Shared::new(channel()).expect("three event handles");
            shared.running.store(true, Ordering::SeqCst);
            shared
                .command
                .store(ticketed(TICKET, COMMAND_STOP), Ordering::SeqCst);

            let stays = command(&shared, &mut engine, Direction::Input);

            let gone =
                stop == AUDCLNT_E_DEVICE_INVALIDATED || reset == AUDCLNT_E_DEVICE_INVALIDATED;
            assert_eq!(
                shared.lost.load(Ordering::SeqCst),
                gone,
                "stop {stop:#x}, reset {reset:#x}: the loss was not written down"
            );
            assert_eq!(
                stays, !gone,
                "stop {stop:#x}, reset {reset:#x}: the loop has to end with the endpoint"
            );
            let (ticket, status) = unticket(shared.outcome.load(Ordering::SeqCst));
            assert_eq!(ticket, TICKET, "the answer went under another ticket");
            assert_eq!(status.cast_signed(), if stop == 0 { reset } else { stop });
            drop(engine);
            assert_eq!(client.refs(), 1);
        }
    }

    #[test]
    fn the_last_stop_on_the_way_out_of_the_loop_is_looked_at_too() {
        let script = Arc::new(Script::default());
        script.stop.set(AUDCLNT_E_DEVICE_INVALIDATED, 0);
        let client = Fake::new(&CLIENT, Arc::clone(&script));
        let shared = Shared::new(channel()).expect("three event handles");
        shared.running.store(true, Ordering::SeqCst);
        shared
            .command
            .store(ticketed(0, COMMAND_QUIT), Ordering::SeqCst);
        shared.control.signal();

        serve(&shared, engine(&client), Direction::Input);

        assert_eq!(
            shared.parting.load(Ordering::SeqCst),
            AUDCLNT_E_DEVICE_INVALIDATED
        );
        assert!(
            shared.lost.load(Ordering::SeqCst),
            "the final stop found the endpoint gone and nothing wrote it down"
        );
        assert_eq!(client.refs(), 1, "the loop did not give the client back");
    }

    #[test]
    fn an_answer_nobody_waited_for_is_not_taken_for_the_next_command() {
        let script = Arc::new(Script::default());
        // slow enough that an owner who takes the first signal it sees reads
        // the outcome well before this stop has written one
        script.stop.set(NOT_INITIALIZED, 200);
        let channel = channel();
        let mut session = scripted(&script, &channel);
        assert_eq!(session.start(), Ok(()));

        // a stale, signalled success from an abandoned command
        session
            .shared
            .outcome
            .store(ticketed(session.tickets, 0), Ordering::SeqCst);
        session.shared.answered.signal();

        assert_eq!(
            session.stop(),
            Err(Error::Call {
                call: "IAudioClient::Stop",
                status: HResult::new(NOT_INITIALIZED),
            }),
            "the stop reported an answer that was not to it"
        );
    }

    #[test]
    fn an_answer_still_on_its_way_is_not_taken_for_the_command_sent_after_it() {
        let script = Arc::new(Script::default());
        script.start.set(0, 300);
        // slow stop, so a first-answer owner could not pass by luck
        script.stop.set(NOT_INITIALIZED, 200);
        let channel = channel();
        let mut session = scripted(&script, &channel);

        assert_eq!(
            session.ask_within(
                COMMAND_START,
                "IAudioClient::Start",
                Duration::from_millis(30)
            ),
            Err(Error::Draining { waited_millis: 30 })
        );
        // The start is still inside the driver. This goes while it is, and the
        // start's answer arrives while this one waits.
        assert_eq!(
            session.ask_within(COMMAND_STOP, "IAudioClient::Stop", Duration::from_secs(2)),
            Err(Error::Call {
                call: "IAudioClient::Stop",
                status: HResult::new(NOT_INITIALIZED),
            }),
            "the stop reported the start's answer"
        );
    }

    #[test]
    fn an_invalidated_endpoint_is_written_down_rather_than_only_ending_the_loop() {
        let channel = channel();
        let shared = Shared::new(Arc::clone(&channel)).expect("three event handles");

        assert!(carry_on(&shared, 0));
        // a buffer that could not be got this period may be there the next
        assert!(carry_on(&shared, 0x8889_0018_u32.cast_signed()));
        assert!(
            !shared.lost.load(Ordering::SeqCst),
            "nothing has been taken away yet"
        );

        assert!(!carry_on(&shared, AUDCLNT_E_DEVICE_INVALIDATED));
        assert!(shared.lost.load(Ordering::SeqCst));
    }

    #[test]
    fn a_lost_endpoint_is_reported_once_and_leaves_the_call_to_be_put_back() {
        let channel = channel();
        let mut session = detached(&channel);
        session.started = true;
        assert_eq!(session.poll(), None, "nothing has happened yet");

        session.shared.lost.store(true, Ordering::SeqCst);
        session.shared.running.store(false, Ordering::SeqCst);

        assert_eq!(session.poll(), Some(StreamEvent::DeviceLost));
        // and an endpoint does not go twice
        assert_eq!(session.poll(), None);
        assert!(
            session.started,
            "a stream that was carrying a call when its endpoint went is one \
             to put back on the air, whatever the client says about running"
        );
    }

    #[test]
    fn a_stream_the_owner_stopped_is_not_restarted_by_a_recover() {
        let channel = channel();
        let mut session = detached(&channel);
        session.started = true;
        assert_eq!(session.stop(), Ok(()));
        assert!(!session.started);
    }

    /// Queued must ignore the ring's power-of-two rounding.
    #[test]
    fn what_is_queued_is_what_the_ring_holds_not_the_depth_less_the_room() {
        let channel = channel();
        let session = detached(&channel);
        let depth = 1_000;
        assert!(
            session
                .shared
                .ring
                .set(crate::ring::Ring::new(depth))
                .is_ok(),
            "a detached session has no ring yet"
        );
        let mut speaker = PlaybackStream { session };
        assert_eq!(speaker.queued(), 0);
        assert!(speaker.write(&[1_000; 160]));
        assert!(speaker.write(&[1_000; 160]));
        assert_eq!(speaker.queued(), 320);
        assert_eq!(speaker.room(), 1_024 - 320);
        assert_ne!(
            depth - speaker.room(),
            speaker.queued(),
            "the depth less the room is what the rounding hides"
        );
    }

    #[test]
    fn what_windows_made_of_the_category_reaches_the_caller_in_both_directions() {
        use crate::status::HResult;

        let channel = channel();
        let speaker = PlaybackStream {
            session: detached(&channel),
        };
        assert_eq!(speaker.category(), Category::Communications);
        assert!(
            speaker.category().is_communications(),
            "the loudspeaker is asked for the category too, so a canceller's \
             reference is not a stream Windows is treating as media"
        );

        // AUDCLNT_E_ALREADY_INITIALIZED: what a client asked in the wrong
        // order would answer, and the stream still opens
        let mut session = detached(&channel);
        session.category = Category::Refused(HResult::new(0x8889_0002_u32.cast_signed()));
        let microphone = CaptureStream { session };
        assert!(!microphone.category().is_communications());
        assert!(
            microphone.category().to_string().contains("0x88890002"),
            "a refusal has to carry what Windows said: {}",
            microphone.category()
        );
    }

    #[test]
    fn the_controls_and_the_audio_thread_are_looking_at_the_same_channel() {
        let channel = channel();
        let session = detached(&channel);
        let controls = Controls::new(&session.channel);

        controls.set_gain(Gain::from_ratio(0.25));
        controls.set_muted(true);
        assert_eq!(session.shared.channel.gain(), Gain::from_ratio(0.25));
        assert!(session.shared.channel.is_muted());

        // and a handle outlives the stream rather than dangling
        drop(session);
        assert_eq!(controls.level(), Level::SILENT);
        assert_eq!(controls.gain(), Gain::from_ratio(0.25));
    }

    #[test]
    fn a_reference_time_is_hundreds_of_nanoseconds() {
        assert_eq!(super::reference_time(0), Duration::ZERO);
        // a ten-millisecond engine period, which is what most machines report
        assert_eq!(super::reference_time(100_000), Duration::from_millis(10));
        assert_eq!(super::reference_time(10_000_000), Duration::from_secs(1));
        assert_eq!(
            super::reference_time(30_000_001),
            Duration::from_secs(3) + Duration::from_nanos(100)
        );
    }

    #[test]
    fn only_an_invalidated_endpoint_ends_the_loop() {
        // a buffer that could not be got this period may be there the next
        assert!(survivable(0x8889_0018_u32.cast_signed()));
        assert!(!survivable(AUDCLNT_E_DEVICE_INVALIDATED));
    }

    #[test]
    fn a_short_header_is_read_without_reading_past_it() {
        // eighteen octets and nothing after them, which is all a `cbSize` of
        // zero promises; reading forty would be reading whatever follows
        let header = WaveFormat {
            format_tag: WAVE_FORMAT_PCM,
            channels: 1,
            samples_per_sec: 8_000,
            avg_bytes_per_sec: 16_000,
            block_align: 2,
            bits_per_sample: 16,
            cb_size: 0,
        };
        // SAFETY: a live header whose own cbSize says nothing follows it.
        let read = unsafe { read_wave(&raw const header) }.expect("a header is a format");
        let tag = read.format.format_tag;
        let rate = read.format.samples_per_sec;
        let subtype = read.sub_format;
        assert_eq!(tag, WAVE_FORMAT_PCM);
        assert_eq!(rate, 8_000);
        // the extension was not there, so it is blank rather than whatever was
        assert_eq!(subtype, crate::abi::Guid::new(0, 0, 0, [0; 8]));
    }

    #[test]
    fn an_extensible_header_is_read_whole() {
        let mut whole = WaveFormatExtensible::EMPTY;
        whole.format.format_tag = crate::abi::WAVE_FORMAT_EXTENSIBLE;
        whole.format.channels = 2;
        whole.format.samples_per_sec = 48_000;
        whole.format.bits_per_sample = 32;
        whole.format.block_align = 8;
        whole.format.cb_size = WaveFormatExtensible::EXTENSION_BYTES;
        whole.valid_bits_per_sample = 32;
        whole.sub_format = crate::abi::SUBTYPE_IEEE_FLOAT;

        // SAFETY: a live header followed by the extension its cbSize declares.
        let read = unsafe { read_wave(&raw const whole.format) }.expect("a format");
        assert_eq!(
            crate::mixformat::describe(&read)
                .expect("a readable format")
                .sample,
            SampleFormat::F32
        );
    }

    #[test]
    fn a_longer_extension_is_copied_as_the_one_that_was_read() {
        let mut whole = WaveFormatExtensible::EMPTY;
        whole.format.format_tag = WAVE_FORMAT_EXTENSIBLE;
        whole.format.channels = 2;
        whole.format.samples_per_sec = 48_000;
        whole.format.bits_per_sample = 32;
        whole.format.block_align = 8;
        // twelve octets more than the extension this crate reads, as a format
        // with fields of its own after the subtype declares
        whole.format.cb_size = WaveFormatExtensible::EXTENSION_BYTES + 12;
        whole.valid_bits_per_sample = 32;
        whole.sub_format = SUBTYPE_IEEE_FLOAT;
        let mut memory = [0u8; 52];
        // SAFETY: forty octets written into fifty-two, unaligned because the
        // structure is byte-packed.
        unsafe {
            std::ptr::write_unaligned(memory.as_mut_ptr().cast::<WaveFormatExtensible>(), whole);
        }

        // SAFETY: a live header followed by the thirty-four octets its cbSize
        // declares.
        let read = unsafe { read_wave(memory.as_ptr().cast::<WaveFormat>()) }.expect("a format");
        let size = read.format.cb_size;
        let subtype = read.sub_format;
        assert_eq!(
            size,
            WaveFormatExtensible::EXTENSION_BYTES,
            "the copy claims octets after it that were never copied"
        );
        assert_eq!(subtype, SUBTYPE_IEEE_FLOAT);
    }

    #[test]
    fn a_null_format_is_not_read_at_all() {
        // SAFETY: null is the case this is documented to answer for.
        assert!(unsafe { read_wave(std::ptr::null()) }.is_none());
    }

    #[test]
    fn an_endpoint_that_does_not_exist_is_refused_rather_than_waited_on() {
        // the thread fails at GetDevice; open must unwind it promptly
        let started = Instant::now();
        let outcome = CaptureStream::open(&StreamConfig::on(
            DeviceId::new("{0.0.1.00000000}.{no such endpoint}"),
            StreamFormat::narrowband(),
        ));
        assert!(outcome.is_err(), "an endpoint that is not there");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "it should refuse rather than sit out a deadline"
        );
    }

    /// A rate as a float, without a cast: every rate an endpoint runs at fits
    /// in sixteen bits.
    fn hertz(rate: u32) -> f32 {
        f32::from(u16::try_from(rate).unwrap_or(u16::MAX))
    }

    /// How much of `samples` is at one frequency, by the Goertzel recurrence.
    ///
    /// Not normalised: the only thing asked of it is the ratio between two
    /// frequencies over the same window, and the normalisation cancels.
    fn bin(samples: &[i16], rate: u32, frequency: f32) -> f32 {
        let omega = core::f32::consts::TAU * frequency / hertz(rate);
        let coefficient = 2.0 * omega.cos();
        let mut previous = 0.0f32;
        let mut older = 0.0f32;
        for sample in samples {
            let current = f32::from(*sample) + coefficient * previous - older;
            older = previous;
            previous = current;
        }
        (previous * previous + older * older - coefficient * previous * older)
            .max(0.0)
            .sqrt()
    }

    #[test]
    #[ignore = "opens the machine's default endpoints"]
    fn the_default_endpoints_open_start_and_close() {
        for rate in [8_000u32, 16_000, 48_000] {
            let wanted = StreamFormat::with_frame_millis(rate, 20).expect("a twenty ms frame");
            match PlaybackStream::open(&StreamConfig::new(wanted)) {
                Ok(mut stream) => {
                    println!(
                        "render at {rate}: {} on \"{}\", delivering {}, {} frames, {:?}, pro audio {}, {}",
                        stream.device_format(),
                        stream.device().name,
                        stream.format(),
                        stream.buffer_frames(),
                        stream.latency(),
                        stream.priority_raised(),
                        stream.category()
                    );
                    assert!(
                        stream.category().is_communications(),
                        "the endpoint would not take the communications category"
                    );
                    stream.start().expect("start the render endpoint");
                    thread::sleep(Duration::from_millis(120));
                    stream.stop().expect("stop the render endpoint");
                    println!("  {}", stream.counters());
                    stream.close().expect("close the render endpoint");
                }
                Err(error) => println!("render at {rate}: {error}"),
            }
            match CaptureStream::open(&StreamConfig::new(wanted)) {
                Ok(mut stream) => {
                    println!(
                        "capture at {rate}: {} on \"{}\", delivering {}, {} frames, {:?}, pro audio {}, {}",
                        stream.device_format(),
                        stream.device().name,
                        stream.format(),
                        stream.buffer_frames(),
                        stream.latency(),
                        stream.priority_raised(),
                        stream.category()
                    );
                    assert!(
                        stream.category().is_communications(),
                        "the endpoint would not take the communications category"
                    );
                    stream.start().expect("start the capture endpoint");
                    thread::sleep(Duration::from_millis(120));
                    stream.stop().expect("stop the capture endpoint");
                    println!("  {}", stream.counters());
                    stream.close().expect("close the capture endpoint");
                }
                Err(error) => println!("capture at {rate}: {error}"),
            }
        }
    }

    /// What a muted microphone does: go on delivering frames, of silence.
    ///
    /// Whatever was captured before the mute is still in the ring and is not
    /// what is under test, so it is drained first.
    fn muting_leaves_the_frames_coming(
        microphone: &mut CaptureStream,
        controls: &Controls,
        incoming: &mut [i16],
    ) {
        controls.set_muted(true);
        thread::sleep(Duration::from_millis(100));
        while microphone.read(incoming) {}

        thread::sleep(Duration::from_millis(200));
        let mut silent = 0usize;
        while microphone.read(incoming) {
            silent += 1;
            assert_eq!(
                incoming.iter().map(|sample| sample.abs()).max(),
                Some(0),
                "a muted microphone sent something"
            );
        }
        println!(
            "{silent} frames of silence while muted, meter {}",
            controls.level()
        );
        assert!(
            silent > 0,
            "muting stopped the frames instead of emptying them"
        );
        assert_eq!(controls.level(), Level::SILENT);
    }

    /// The loudest thing that came back out of the cable, having established
    /// that what came back is the tone that went in rather than noise.
    fn the_tone_came_back(captured: &[i16], in_rate: u32, sent_peak: i16) -> i16 {
        /// A kilohertz, the tone the caller renders.
        const TONE_HZ: f32 = 1_000.0;
        /// A frequency the tone has nothing at, to compare it against.
        const OFF_TONE_HZ: f32 = 1_700.0;

        // skip the first quarter second: the cable is silent until the render
        // side has been running, and that silence is not the thing under test
        let skip = usize::try_from(in_rate / 4).unwrap_or(0);
        assert!(
            captured.len() > skip * 2,
            "not enough came back out of the cable to look at"
        );
        let window = &captured[skip..(skip + 10_000).min(captured.len())];
        let peak = window
            .iter()
            .map(|sample| sample.saturating_abs())
            .max()
            .unwrap_or(0);
        let tone_bin = bin(window, in_rate, TONE_HZ);
        let off_bin = bin(window, in_rate, OFF_TONE_HZ);

        println!(
            "sent peak {sent_peak}, heard peak {peak}, {TONE_HZ} Hz {tone_bin:.1} against \
             {OFF_TONE_HZ} Hz {off_bin:.1}"
        );
        assert!(peak > 1_000, "the cable came back silent (peak {peak})");
        assert!(
            tone_bin > off_bin * 10.0,
            "what came back is not the tone that went in ({tone_bin:.1} against {off_bin:.1})"
        );
        peak
    }

    /// A tone through a virtual cable proves the whole path: negotiation,
    /// events, conversion and both rings.
    #[test]
    #[ignore = "renders a tone into the VB-Audio cable and captures it back"]
    fn a_tone_rendered_into_the_cable_comes_back_out_of_it() {
        /// 20 whole cycles per 20 ms frame, so frames repeat seamlessly.
        const CYCLES_PER_FRAME: f32 = 20.0;
        /// Loud enough to be unmistakable, quiet enough not to clip anywhere.
        const LEVEL: f32 = 0.37;

        let all = devices().expect("enumerate the endpoints");
        let sink = all.iter().find(|device| {
            device.direction == Direction::Output && device.name.starts_with("CABLE In")
        });
        let source = all.iter().find(|device| {
            device.direction == Direction::Input && device.name.starts_with("CABLE Output")
        });
        let (Some(sink), Some(source)) = (sink, source) else {
            for device in &all {
                println!("{device}");
            }
            panic!("no VB-Audio cable on this machine; the loopback needs one");
        };

        let wanted = StreamFormat::with_frame_millis(48_000, 20).expect("a twenty ms frame");
        let mut speaker = PlaybackStream::open(&StreamConfig::on(sink.id.clone(), wanted))
            .expect("open the cable's render endpoint");
        let mut microphone = CaptureStream::open(&StreamConfig::on(source.id.clone(), wanted))
            .expect("open the cable's capture endpoint");

        println!(
            "render  \"{}\"\n        endpoint {}, delivering {}, {} frames a period, {:?}, pro audio {}",
            sink.name,
            speaker.device_format(),
            speaker.format(),
            speaker.buffer_frames(),
            speaker.latency(),
            speaker.priority_raised()
        );
        println!(
            "capture \"{}\"\n        endpoint {}, delivering {}, {} frames a period, {:?}, pro audio {}",
            source.name,
            microphone.device_format(),
            microphone.format(),
            microphone.buffer_frames(),
            microphone.latency(),
            microphone.priority_raised()
        );

        let out_rate = speaker.format().sample_rate_hz();
        let in_rate = microphone.format().sample_rate_hz();
        assert_eq!(
            out_rate, in_rate,
            "the two halves of the cable are configured at different rates; \
             set both to the same one in the VB-Audio control panel"
        );

        let length = speaker.format().frame_samples();
        let span = f32::from(u16::try_from(length).unwrap_or(1));
        let mut tone = vec![0i16; length];
        for (index, sample) in tone.iter_mut().enumerate() {
            let at = f32::from(u16::try_from(index).unwrap_or(0));
            let radians = core::f32::consts::TAU * CYCLES_PER_FRAME * at / span;
            *sample = crate::convert::from_float(radians.sin() * LEVEL);
        }
        let sent_peak = tone.iter().map(|sample| sample.saturating_abs()).max();

        // half volume out, so what comes back measures the gain
        let out_volume = speaker.controls();
        let in_volume = microphone.controls();
        out_volume.set_gain(Gain::from_db(-6.02));

        // fill the ring before the endpoint starts, so the first period is the
        // tone rather than the silence the prefill would otherwise write
        while speaker.write(&tone) {}
        speaker.start().expect("start the render endpoint");
        microphone.start().expect("start the capture endpoint");

        let mut incoming = vec![0i16; microphone.format().frame_samples()];
        let mut captured: Vec<i16> = Vec::new();
        let until = Instant::now() + Duration::from_millis(1_200);
        while Instant::now() < until {
            while speaker.write(&tone) {}
            while microphone.read(&mut incoming) {
                captured.extend_from_slice(&incoming);
            }
            thread::sleep(Duration::from_millis(5));
        }

        // read before the stop, which puts both meters back to silence
        let (heard, sent) = (in_volume.level(), out_volume.level());
        println!("meters: render {sent}, capture {heard}");

        muting_leaves_the_frames_coming(&mut microphone, &in_volume, &mut incoming);

        speaker.stop().expect("stop the render endpoint");
        microphone.stop().expect("stop the capture endpoint");

        println!("{} samples captured at {in_rate} Hz", captured.len());
        println!("render  {}", speaker.counters());
        println!("capture {}", microphone.counters());

        let peak = the_tone_came_back(&captured, in_rate, sent_peak.unwrap_or(0));

        // half, within 10% for the meter window and the cable's conversion
        let half = i32::from(sent_peak.unwrap_or(0)) / 2;
        let margin = half / 10;
        assert!(
            (i32::from(peak) - half).abs() < margin,
            "the gain did not go on the frames: {peak} came back where {half} was expected"
        );
        assert!(
            (i32::from(heard.peak()) - half).abs() < margin,
            "the capture meter says {heard} where {half} was expected"
        );
        assert!(
            (i32::from(sent.peak()) - half).abs() < margin,
            "the render meter says {sent} where {half} was expected"
        );
        assert_eq!(speaker.counters().panics, 0);
        assert_eq!(microphone.counters().panics, 0);

        speaker.close().expect("close the render endpoint");
        microphone.close().expect("close the capture endpoint");
    }
}
