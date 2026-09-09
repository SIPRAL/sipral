// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One endpoint, in one direction: samples in from a microphone, or samples
//! out to a speaker, and nothing else.
//!
//! One direction, because that is what Windows has. A WASAPI client is one
//! `IAudioClient` on one endpoint, and a headset is two endpoints with two
//! identifiers and two clocks. A duplex type here would be two of these in a
//! coat, and it would hide the case a softphone most needs to get right —
//! microphone on one device, speaker on another — so there are two types and
//! the caller holds both.
//!
//! Shared mode and event-driven. Shared, because exclusive mode takes the
//! endpoint away from everything else on the machine and buys latency that a
//! jitter buffer will not notice. Event-driven, because the alternative is a
//! thread that wakes on a timer and asks whether the buffer needs anything,
//! which is either late or busy and usually both.
//!
//! Two threads meet here. The audio thread is ours: it is created by
//! [`CaptureStream::open`] or [`PlaybackStream::open`], it joins the
//! multi-threaded apartment, it registers itself as Pro Audio with the
//! multimedia class scheduler, and it owns every COM object for its whole life
//! — which is what makes teardown a local question rather than a promise read
//! out of a document. Everything else runs on whatever thread the caller is
//! on. The two share one ring, the counters and three event handles, and
//! neither waits for the other except at teardown, where the waiting has a
//! deadline.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use std::ffi::c_void;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::abi::{
    AudioCaptureClient, AudioCaptureClientVtable, AudioClient, AudioClientVtable,
    AudioRenderClient, AudioRenderClientVtable, BUFFERFLAGS_DATA_DISCONTINUITY, BUFFERFLAGS_SILENT,
    CLSCTX_ALL, Handle, Interface, REFERENCE_TIMES_PER_SECOND, SHARE_MODE_SHARED,
    STREAMFLAGS_EVENTCALLBACK, WAIT_OBJECT_0, WAIT_TIMEOUT, WaveFormat, WaveFormatExtensible,
};
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

/// Frames the ring holds unless the caller says otherwise: enough to ride out a
/// scheduling hiccup, short enough that a stalled reader is heard as a gap
/// rather than as a delay that never recovers.
const DEFAULT_DEPTH_FRAMES: usize = 16;

/// How long the audio thread waits for the engine before deciding the endpoint
/// has stopped signalling.
///
/// Long enough that a stopped stream is not woken for nothing, short enough
/// that an endpoint which has gone quiet is noticed rather than waited on for
/// ever. A wake here costs one atomic load.
const STALL_AFTER_MILLIS: u32 = 200;

/// How long a caller waits for the audio thread to answer `start` or `stop`.
///
/// The same budget teardown gets, for the same reason: past a couple of seconds
/// the thread is not slow, it is inside a driver call that is not coming back,
/// and a caller hung on that is worse than a caller told so.
const ANSWER_WAIT: Duration = TEARDOWN_WAIT;

/// Nothing to do.
const COMMAND_NONE: u32 = 0;
/// Fill the buffer so the first period is not a gap, then start the client.
const COMMAND_START: u32 = 1;
/// Stop the client and throw away what the engine still holds.
const COMMAND_STOP: u32 = 2;
/// Leave the loop, put every interface back, and end.
const COMMAND_QUIT: u32 = 3;

/// What to open, and how much slack to leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// Rate and frame length wanted. What is actually delivered is
    /// [`CaptureStream::format`], which carries the endpoint's rate.
    pub format: StreamFormat,
    /// Which endpoint, and what to do when it is not there. The default is
    /// whatever Windows is routing calls to, which is what a softphone
    /// usually wants.
    pub device: DeviceChoice,
    /// Frames of buffering between the endpoint and the caller.
    ///
    /// This sizes the ring in this crate and nothing else. The engine's own
    /// buffer is the engine's to size: shared mode with an event handle gets
    /// the audio engine's period, and asking for a longer one would add
    /// latency the caller cannot spend.
    pub depth_frames: usize,
}

impl StreamConfig {
    /// The system's current route for calls, at the given format.
    #[must_use]
    pub const fn new(format: StreamFormat) -> Self {
        Self {
            format,
            device: DeviceChoice::System,
            depth_frames: DEFAULT_DEPTH_FRAMES,
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

    /// A saved selection, at the given format: that endpoint when the machine
    /// has it, and the system's route for calls when it does not.
    ///
    /// This is the one to build from a [`DeviceId`] read out of a
    /// configuration file. A docking station or a headset that reboots itself
    /// takes its endpoint away and brings it back, and in between a call still
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

/// What the audio thread has to say, in numbers because it cannot speak.
///
/// Every one of these is relaxed: nothing else depends on having seen them, a
/// reader that is one increment behind is reading a number that was true a
/// moment ago, and making them ordered would put a fence in the audio thread
/// for the sake of a statistic.
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
/// The audio thread holds a reference to this for its whole life, so the memory
/// is alive as long as either side wants it — which is why teardown here has no
/// buffers to leak, unlike the CoreAudio sibling where the framework holds a
/// bare pointer to them. What teardown here can still get wrong is closing a
/// handle the audio thread is waiting on, or blocking for ever in `join` on a
/// thread that is not coming back. That is what the gate is for, and why
/// failing to drain costs a detached thread rather than a hung caller.
struct Shared {
    gate: Gate,
    /// The gain, the mute and the meter. Behind an `Arc` of its own rather
    /// than inline, so that a [`Controls`] handed to the thread drawing the
    /// window survives the stream being reopened on another endpoint.
    channel: Arc<Channel>,
    /// Made once the endpoint's rate is known, which is after the client is
    /// open. A caller cannot reach it before then: `open` does not return until
    /// the audio thread has put it here.
    ring: OnceLock<Ring>,
    meters: Meters,
    /// Signalled by the audio engine when a buffer wants attention.
    ready: Event,
    /// Signalled by the owner to make the audio thread read `command`.
    control: Event,
    /// Signalled by the audio thread when it has carried a command out.
    answered: Event,
    command: AtomicU32,
    /// What the last command returned.
    reply: AtomicI32,
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
            command: AtomicU32::new(COMMAND_NONE),
            reply: AtomicI32::new(0),
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
    /// Kept so that a reopen can ask for the same thing again and have the
    /// choice resolved against the machine as it is then.
    config: StreamConfig,
    /// The controls, held here as well as in `shared` so that a reopen carries
    /// the volume and the mute across rather than resetting them under a
    /// caller who is mid-call.
    channel: Arc<Channel>,
    /// Whether the owner has asked for it to be running. Not the same as
    /// `shared.running`, which goes false on its own when the endpoint is
    /// taken away — and a stream that was carrying a call when that happened
    /// is one that should be carrying a call after it is recovered.
    started: bool,
    /// Whether the loss has been handed over, so that it is reported once
    /// rather than on every poll.
    loss_reported: bool,
    closed: bool,
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
            thread::Builder::new()
                .name("sipral-wasapi".to_string())
                .spawn(move || run(&shared, &choice, direction, wanted, depth, &sender))
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
                // The thread is already on its way out, having sent that. Wait
                // for it rather than leave one behind for every endpoint that
                // refuses, but wait with the same deadline as anything else
                // here: it is a thread inside COM, not a thread we control.
                shared.gate.close();
                shared.command.store(COMMAND_QUIT, Ordering::SeqCst);
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
            config: config.clone(),
            channel,
            started: false,
            loss_reported: false,
            closed: false,
        })
    }

    /// Send the audio thread a command and wait for what it made of it.
    fn ask(&self, command: u32, call: &'static str) -> Result<(), Error> {
        if self.shared.ended.load(Ordering::SeqCst) {
            // the endpoint went away, or the thread already ended: nobody is
            // left to answer, and waiting would only cost the deadline
            return Err(Error::NoDevice);
        }
        self.shared.command.store(command, Ordering::SeqCst);
        self.shared.control.signal();
        if !self.shared.answer(ANSWER_WAIT) {
            return Err(Error::Draining {
                waited_millis: TEARDOWN_WAIT_MILLIS,
            });
        }
        sys::check(call, self.shared.reply.load(Ordering::SeqCst))
    }

    fn start(&mut self) -> Result<(), Error> {
        if self.shared.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.ask(COMMAND_START, "IAudioClient::Start")?;
        self.started = true;
        Ok(())
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
        // What Windows says about taking down a client whose endpoint has gone
        // is not a reason to stop: that is the situation being recovered from.
        // A thread that would not finish is another matter entirely.
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
    /// The order is the argument, and each step is here for one reason:
    ///
    /// 1. shut the gate, so a pass that has not started touching the shared
    ///    state turns itself around;
    /// 2. ask the thread to quit and wake it, which is what gets it out of the
    ///    wait it is almost certainly sitting in;
    /// 3. wait, with a deadline, for it to be out of the shared state and then
    ///    for it to have ended — the second is what says its interfaces are
    ///    back and its last touch of a handle is over;
    /// 4. only then join it, which by that point returns at once.
    ///
    /// Step 3 failing is not recoverable and not survivable by carrying on. The
    /// thread is inside a call that has not returned, so it is left detached
    /// rather than joined, and the reference it holds to the shared state keeps
    /// its handles open for as long as it lives. A thread that outlives its
    /// owner is a bug report; a handle closed under a thread still waiting on
    /// it is a crash somewhere else entirely, because handle values come round
    /// again.
    fn shut_down(&mut self, within: Duration, millis: u64) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        self.shared.gate.close();
        self.shared.command.store(COMMAND_QUIT, Ordering::SeqCst);
        self.shared.control.signal();

        if !(self.shared.gate.drained(within) && self.shared.finished(within)) {
            // dropped without a join, which detaches it
            self.worker = None;
            return Err(Error::Draining {
                waited_millis: millis,
            });
        }

        if let Some(worker) = self.worker.take() {
            // it has already ended, so this returns at once; a thread that
            // panicked its way out is not a status to report, it is the panic
            // counter above zero
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
/// "Render" is Windows's word for playback and it is the one every interface
/// and every error code uses, so it is the one the audio thread uses too.
pub struct PlaybackStream {
    session: Session,
}

/// The methods that are the same in both directions.
///
/// A macro rather than a trait, because a trait would put these in the caller's
/// namespace only after an import, and rather than two copies because two
/// copies drift.
macro_rules! session_methods {
    () => {
        /// What the caller will actually be handed.
        ///
        /// The rate is the endpoint's, because this crate does not resample.
        /// The frame length is the one that was asked for, rescaled to the same
        /// duration at that rate.
        #[must_use]
        pub const fn format(&self) -> StreamFormat {
            self.session.delivered
        }

        /// What the endpoint runs, in its own terms.
        ///
        /// Worth reading whenever [`Self::format`] is not the rate that was
        /// asked for: this says what it is instead, and what the samples looked
        /// like on the way through.
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
        #[must_use]
        pub const fn latency(&self) -> Duration {
            self.session.latency
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
        /// `false` means the stream still runs and will be interrupted, which
        /// is worth saying out loud rather than discovering as glitches.
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
        /// A handle, not a borrow: the slider and the bar are on the thread
        /// that draws the window and the frames are on the thread that carries
        /// the call. It survives a recover with its settings intact.
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
        /// status as survivable.
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
        /// Dropping the stream does exactly this and has nowhere to report to.
        ///
        /// # Errors
        /// [`Error::Draining`] when the audio thread could not be shown to have
        /// finished within two seconds — in which case it is left detached and
        /// its handles are left open, deliberately. Otherwise [`Error::Call`]
        /// carrying what the last stop said.
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
    /// This is the answer to [`StreamEvent::DeviceLost`], and the reason a
    /// saved selection is worth storing as
    /// [`StreamConfig::preferring`]: that choice resolves to the saved
    /// endpoint when it is back and to the system's route when it is not, so
    /// recovering from an unplugged headset lands on the machine's own
    /// microphone rather than failing. [`StreamConfig::on`] names one endpoint
    /// and nothing else, so recovering onto one that has gone fails, and says
    /// so.
    ///
    /// The controls carry over: the gain and the mute a person set are still
    /// set, and a [`Controls`] handed out earlier keeps working. Whatever was
    /// in the ring does not — those samples came from an endpoint that is not
    /// there. A stream that was started is started again.
    ///
    /// The format can come back different, because the new endpoint chooses
    /// its own rate: [`Self::format`] is worth reading again afterwards.
    ///
    /// # Errors
    /// [`Error::Draining`] when the old audio thread could not be shown to
    /// have finished, in which case nothing is reopened. Otherwise whatever
    /// [`Self::open`] would have said about the endpoint it landed on.
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

    /// Samples waiting to be read. A number that keeps growing is a reader
    /// falling behind, and the drop counter is about to start moving.
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

    session_methods!();
}

/// Everything the audio thread owns.
struct Engine {
    client: Com<AudioClientVtable>,
    render: Option<Com<AudioRenderClientVtable>>,
    capture: Option<Com<AudioCaptureClientVtable>>,
    format: DeviceFormat,
    buffer_frames: u32,
    /// Mono samples on their way between the ring and the endpoint's buffer.
    /// Sized once, here, because the audio thread must not allocate.
    scratch: Box<[i16]>,
}

/// The audio thread.
///
/// Every COM object is created and released here and nowhere else: the
/// apartment, the enumerator, the client, the one service interface. That is
/// not caution about marshalling, it is what makes teardown answerable — when
/// this function returns, every reference it took is back, and nothing the
/// caller does afterwards can be too early.
fn run(
    shared: &Shared,
    choice: &DeviceChoice,
    direction: Direction,
    wanted: StreamFormat,
    depth: usize,
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

    match build(shared, choice, direction, wanted, depth) {
        Ok((engine, opened)) => {
            let _ = sender.send(Ok(opened));
            serve(shared, engine, direction);
        }
        Err(error) => {
            let _ = sender.send(Err(error));
        }
    }

    drop(apartment);
    // last, and after every interface is back: the owner watches this to know
    // that joining will not block and that a handle can be closed
    shared.ended.store(true, Ordering::SeqCst);
}

/// Open the endpoint, settle on a format, and get as far as being able to run.
fn build(
    shared: &Shared,
    choice: &DeviceChoice,
    direction: Direction,
    wanted: StreamFormat,
    depth: usize,
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

    let settled = negotiate(&client, wanted.sample_rate_hz())?;
    let format = mixformat::describe(&settled)?;

    // Zero for both durations, which in shared mode with an event handle means
    // the engine's own period. Asking for a longer buffer here would add
    // latency the caller cannot spend, and asking for a shorter one is what
    // exclusive mode is for.
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

    // After Initialize and before Start, which is the only window the client
    // accepts it in.
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
    // the endpoint chose the rate, so the meter's window is only now worth
    // anything: at 48 kHz a tenth of a second is six times what it is at 8
    shared
        .channel
        .set_window(window_samples(delivered.sample_rate_hz()));
    let period = usize::try_from(buffer_frames).unwrap_or(0).max(1);
    // never smaller than two of the engine's buffers: a ring that cannot hold
    // what one period delivers would lose samples every single period
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
        },
    ))
}

/// A `REFERENCE_TIME` as a duration.
///
/// It counts hundreds of nanoseconds, a unit that exists nowhere else and is
/// therefore worth converting exactly once. Negative values do not arise from
/// the calls this crate makes; the magnitude is taken rather than the sign
/// being argued about.
fn reference_time(ticks: i64) -> Duration {
    let ticks = ticks.unsigned_abs();
    let per_second = REFERENCE_TIMES_PER_SECOND.unsigned_abs();
    let leftover = (ticks % per_second).saturating_mul(100);
    Duration::new(ticks / per_second, u32::try_from(leftover).unwrap_or(0))
}

/// Ask for mono sixteen-bit, and decide what to do with the answer.
///
/// Three answers are possible and all three happen. `S_OK` means the endpoint
/// will run exactly what was asked for, which a virtual cable configured that
/// way does and a sound card almost never does. `S_FALSE` comes with the
/// closest match the engine is willing to run — in shared mode that is the
/// audio engine's mix format — and it is taken, because the alternative is to
/// refuse the machine's only sound card. Anything else means the question was
/// not understood, and the mix format is asked for directly.
///
/// What is deliberately not done is to set `AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM`
/// and let the engine resample. It would make the rate come out right, and it
/// would put a resampler inside a crate whose boundary says it has none:
/// `sipral-media` owns resampling because it owns the clock drift correction
/// that has to go with it, and a second one down here that nobody knew about is
/// how a stack ends up correcting drift against itself. The rate that comes
/// back is reported instead.
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
/// The structure is variable length and byte-packed, which is two reasons not
/// to read it as a `WAVEFORMATEXTENSIBLE` and hope: an endpoint with `cbSize`
/// of zero has eighteen octets and nothing after them, and reading forty would
/// be reading somebody else's allocation.
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
        return Some(unsafe { ptr::read_unaligned(pointer.cast::<WaveFormatExtensible>()) });
    }
    let mut whole = WaveFormatExtensible::EMPTY;
    whole.format = header;
    Some(whole)
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
    shared.running.store(false, Ordering::SeqCst);
    // a meter left where the last pass put it reads as a live signal
    shared.channel.quiet();
    shared.parting.store(parting, Ordering::SeqCst);
    drop(priority);
}

/// Carry out whatever the owner asked for. `false` means leave the loop.
fn command(shared: &Shared, engine: &mut Engine, direction: Direction) -> bool {
    match shared.command.swap(COMMAND_NONE, Ordering::SeqCst) {
        COMMAND_START => {
            let status = start(shared, engine, direction);
            shared.reply.store(status, Ordering::SeqCst);
            shared.answered.signal();
            true
        }
        COMMAND_STOP => {
            // SAFETY: a live client.
            let stopped = unsafe { (engine.client.vtable().stop)(engine.client.as_ptr()) };
            shared.running.store(false, Ordering::SeqCst);
            // Reset after Stop, so a restart does not replay whatever the
            // engine was still holding. It is only legal while stopped, which
            // is exactly where this is.
            // SAFETY: a live, stopped client.
            let cleared = unsafe { (engine.client.vtable().reset)(engine.client.as_ptr()) };
            shared.channel.quiet();
            let first = if HResult::new(stopped).is_ok() {
                cleared
            } else {
                stopped
            };
            shared.reply.store(first, Ordering::SeqCst);
            shared.answered.signal();
            true
        }
        COMMAND_QUIT => false,
        // a spurious wake, or a command already taken: nothing to do and
        // nothing to answer
        _ => true,
    }
}

/// Fill the engine's buffer and start it.
///
/// The prefill is not optional in event-driven mode: the first event arrives
/// one period after `Start`, so a buffer that was empty at the start is a
/// period of silence, and on some drivers a glitch.
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
/// Everything but an invalidated endpoint is: a buffer that could not be got
/// this period may be there the next one. An invalidated endpoint never comes
/// back — the device was unplugged, or its format was changed underneath — so
/// the loop ends and `is_running` goes false, which is how the caller finds
/// out.
fn survivable(status: i32) -> bool {
    status != AUDCLNT_E_DEVICE_INVALIDATED
}

/// The same, and it writes down what it found.
///
/// The flag is the difference between a stream that stopped and one that was
/// taken away, and it is the only place that difference is known: by the time
/// the owner looks, the loop has ended either way.
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
                // the engine says the contents are undefined, which is its way
                // of saying nothing was recorded
                mono.fill(0);
            }
            // A muted microphone still fills the ring, with silence. Stopping
            // the frames instead would mean unmuting replayed however much
            // audio had piled up behind the mute, and would starve whatever
            // above is pacing itself on frames arriving.
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
    // The volume goes on here rather than where the caller wrote the frame,
    // so that a mute is silent on this period instead of on the one after the
    // ring has drained. `wanted` rather than `taken`, because the silence a
    // starved pass leaves behind is time the meter's window has to count.
    if let Some(played) = engine.scratch.get_mut(..taken) {
        shared.channel.apply(played, wanted);
    }
    Meters::add(&shared.meters.played, taken);
    Meters::add(&shared.meters.playback_starved, wanted - taken);

    let mut released = 0;
    if taken == 0 || data.is_null() {
        // Nothing to play and nothing to write. The engine has a flag for
        // exactly this, and it is cheaper than a memset the engine will ignore.
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
        CaptureStream, DEFAULT_DEPTH_FRAMES, PlaybackStream, Session, Shared, StreamConfig,
        carry_on, read_wave, survivable,
    };
    use crate::abi::{WAVE_FORMAT_PCM, WaveFormat, WaveFormatExtensible};
    use crate::device::Device;
    use crate::device::{DeviceChoice, DeviceId, Direction, StreamEvent};
    use crate::endpoint::devices;
    use crate::format::{SampleFormat, StreamFormat};
    use crate::level::{Channel, Controls, Gain, Level, window_samples};
    use crate::status::AUDCLNT_E_DEVICE_INVALIDATED;
    use core::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

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
    /// `ended` is set because that is what a thread says on its way out, and
    /// without it the destructor would sit out the whole teardown deadline
    /// waiting for a thread that was never started. What is left is the owner
    /// side, which is the half that can be shown to be right without an
    /// endpoint.
    fn detached(channel: &Arc<Channel>) -> Session {
        let shared = Arc::new(Shared::new(Arc::clone(channel)).expect("three event handles"));
        shared.ended.store(true, Ordering::SeqCst);
        Session {
            shared,
            worker: None,
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
            config: StreamConfig::default(),
            channel: Arc::clone(channel),
            started: false,
            loss_reported: false,
            closed: false,
        }
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

        // what the audio thread does on its way out of an invalidated
        // endpoint: the loop ends, the client is not running, and this is the
        // only record of why
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
    fn a_null_format_is_not_read_at_all() {
        // SAFETY: null is the case this is documented to answer for.
        assert!(unsafe { read_wave(std::ptr::null()) }.is_none());
    }

    #[test]
    fn an_endpoint_that_does_not_exist_is_refused_rather_than_waited_on() {
        // No endpoint carries this identifier, so the audio thread fails at
        // GetDevice and reports it. What this checks is that opening unwinds a
        // thread it had already started, promptly, and says why.
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
                        "render at {rate}: {} on \"{}\", delivering {}, {} frames, {:?}, pro audio {}",
                        stream.device_format(),
                        stream.device().name,
                        stream.format(),
                        stream.buffer_frames(),
                        stream.latency(),
                        stream.priority_raised()
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
                        "capture at {rate}: {} on \"{}\", delivering {}, {} frames, {:?}, pro audio {}",
                        stream.device_format(),
                        stream.device().name,
                        stream.format(),
                        stream.buffer_frames(),
                        stream.latency(),
                        stream.priority_raised()
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

    /// The reason the virtual cable is installed: what goes into it comes back
    /// out of it, so a tone rendered on one endpoint and captured on the other
    /// proves the whole path — negotiation, the event, the conversion, both
    /// rings — rather than proving that two calls returned zero.
    #[test]
    #[ignore = "renders a tone into the VB-Audio cable and captures it back"]
    fn a_tone_rendered_into_the_cable_comes_back_out_of_it() {
        /// A kilohertz, which a twenty-millisecond frame holds twenty whole
        /// cycles of at any rate — so one frame repeats without a step in the
        /// waveform, and nothing has to remember a phase.
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

        // Half volume out. What comes back through the cable is then a
        // measurement of the gain rather than of the tone: the cable does not
        // change what it carries, so anything but half is this crate.
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

        // Half of what went in, within the tenth that the meter's window and
        // the cable's own conversion are worth. This is the whole gain claim:
        // the cable does not change what it carries, so anything but half
        // would be this crate.
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
