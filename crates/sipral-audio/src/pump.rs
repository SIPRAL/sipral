// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The thread that carries audio between the devices and the calls.
//!
//! One thread, one tick every frame: whatever the microphone has captured is
//! resampled to each call's own rate and encoded, and the packet goes out
//! through the application's transmit function; each call's playback is
//! pulled at its own rate, resampled to the loudspeaker's and summed into
//! the frame the loudspeaker is written. A ring tone goes to the ringer's
//! stream, or into the loudspeaker's sum when the two are the same device.
//!
//! The pump owns the streams. The engine, on whichever thread the
//! application calls it from, opens a stream and hands it over as a command;
//! what the pump has to report — a device gone, a call whose media ended —
//! goes back through flags and a list the engine reads when it is next
//! serviced. Nothing here takes a lock the engine holds while it waits on a
//! platform, and nothing the engine does waits for a tick.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sipral_media::resample::Resampler;

use crate::backend::{CaptureStream, Format, PlaybackStream};
use crate::call::{CallAudio, CallGone, CallId, Outgoing};
use crate::device::Role;

/// One frame's worth of time, which is the tick.
pub(crate) const FRAME: Duration = Duration::from_millis(20);

/// How many frames the pump keeps queued at a loudspeaker: enough to ride
/// out a late tick, few enough that the mouth-to-ear budget does not pay for
/// buffering nobody asked for.
const TARGET_QUEUED_FRAMES: usize = 2;

/// A ring tone: the application's own samples, at their own rate, looped or
/// played once.
#[derive(Clone, Debug)]
pub(crate) struct Ring {
    /// Mono sixteen-bit samples.
    pub(crate) tone: Arc<Vec<i16>>,
    /// Their rate.
    pub(crate) sample_rate_hz: u32,
    /// Whether to start again at the end.
    pub(crate) looped: bool,
}

/// Calls' audio by the engine's name for them: what a pump that finished
/// hands back, and what the engine keeps while no pump runs.
pub(crate) type Carried = Vec<(CallId, Box<dyn CallAudio>)>;

/// What a pump's thread returns: the transmit function it was given and the
/// calls it was still carrying.
pub(crate) type Finished = (Box<dyn FnMut(CallId, Outgoing) + Send>, Carried);

/// What the engine asks the pump to do.
pub(crate) enum Command {
    /// Carry this call's audio from here on.
    Attach(CallId, Box<dyn CallAudio>),
    /// Stop carrying it.
    Detach(CallId),
    /// Run this role on this stream from here on, or on nothing.
    Replace(Role, Option<Stream>),
    /// Play this to the ringer.
    Ring(Ring),
    /// Stop playing it.
    StopRing,
    /// Say so, once every command sent before this one has been acted on.
    Settled(Sender<()>),
    /// Finish.
    Quit,
}

/// A stream of either direction, boxed.
pub(crate) enum Stream {
    /// A microphone.
    Capture(Box<dyn CaptureStream>),
    /// A loudspeaker.
    Playback(Box<dyn PlaybackStream>),
}

/// What the pump reports, readable from any thread.
#[derive(Default)]
pub(crate) struct Report {
    /// Set when the device under a role has gone; one flag per role, in
    /// [`Role::ALL`]'s order.
    lost: [AtomicBool; 3],
    /// Calls whose media ended under the pump, which it has let go of.
    ended: Mutex<Vec<CallId>>,
    /// Ticks run, so that a test can wait for the thread to have turned.
    ticks: AtomicU64,
    /// Whether the ring finished by itself.
    ring_done: AtomicBool,
}

impl Report {
    /// Whether a role's device went, cleared by asking.
    pub(crate) fn take_lost(&self, role: Role) -> bool {
        self.lost
            .get(index(role))
            .is_some_and(|flag| flag.swap(false, Ordering::AcqRel))
    }

    /// The calls whose media ended since last asked.
    pub(crate) fn take_ended(&self) -> Vec<CallId> {
        std::mem::take(&mut *self.ended.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether a ring that was not looped reached its end, cleared by asking.
    pub(crate) fn take_ring_done(&self) -> bool {
        self.ring_done.swap(false, Ordering::AcqRel)
    }

    /// How many ticks have run.
    pub(crate) fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::Acquire)
    }
}

const fn index(role: Role) -> usize {
    match role {
        Role::Microphone => 0,
        Role::Speaker => 1,
        Role::Ringer => 2,
    }
}

/// Samples on their way from one rate to another, with a queue on the far
/// side because a resampler does not produce whole frames.
struct Lane {
    resampler: Option<Resampler>,
    queue: VecDeque<i16>,
    scratch: Vec<i16>,
}

impl Lane {
    fn between(from_hz: u32, to_hz: u32) -> Self {
        Self {
            resampler: (from_hz != to_hz)
                .then(|| Resampler::new(from_hz, to_hz).ok())
                .flatten(),
            queue: VecDeque::new(),
            scratch: Vec::new(),
        }
    }

    /// Put `samples` in at the source rate.
    fn push(&mut self, samples: &[i16]) {
        match self.resampler.as_mut() {
            Some(resampler) => {
                let capacity = resampler.output_capacity(samples.len());
                self.scratch.clear();
                self.scratch.resize(capacity, 0);
                let produced = resampler.process(samples, &mut self.scratch).unwrap_or(0);
                self.queue
                    .extend(self.scratch.iter().take(produced).copied());
            }
            None => self.queue.extend(samples.iter().copied()),
        }
    }

    /// Whether a whole frame of `len` is waiting.
    fn has(&self, len: usize) -> bool {
        self.queue.len() >= len
    }

    /// Take `out.len()` samples, or say there are not that many.
    fn take(&mut self, out: &mut [i16]) -> bool {
        let wanted = out.len();
        if !self.has(wanted) {
            return false;
        }
        for (slot, sample) in out.iter_mut().zip(self.queue.drain(..wanted)) {
            *slot = sample;
        }
        true
    }

    /// Whatever is queued, and silence after it: `false` when nothing was.
    fn take_padded(&mut self, out: &mut [i16]) -> bool {
        if self.queue.is_empty() {
            return false;
        }
        for slot in out.iter_mut() {
            *slot = self.queue.pop_front().unwrap_or(0);
        }
        true
    }

    /// Everything queued, forgotten.
    fn clear(&mut self) {
        self.queue.clear();
        if let Some(resampler) = self.resampler.as_mut() {
            resampler.reset();
        }
    }
}

/// One call, with its two lanes.
struct Call {
    id: CallId,
    audio: Box<dyn CallAudio>,
    rate_hz: u32,
    /// Microphone to call.
    up: Lane,
    /// Call to loudspeaker.
    down: Lane,
    /// Which device rate each lane was built for, so that a device change
    /// rebuilds them.
    up_from_hz: u32,
    down_to_hz: u32,
    frame: Vec<i16>,
}

impl Call {
    /// A call carried between a microphone at `microphone_hz` and a
    /// loudspeaker at `speaker_hz`, or `None` for one whose media has
    /// already ended.
    fn new(
        id: CallId,
        audio: Box<dyn CallAudio>,
        microphone_hz: u32,
        speaker_hz: u32,
    ) -> Option<Self> {
        let rate_hz = audio.sample_rate().ok()?;
        let frame_samples = audio.frame_samples().ok()?;
        Some(Self {
            id,
            audio,
            rate_hz,
            up: Lane::between(microphone_hz, rate_hz),
            down: Lane::between(rate_hz, speaker_hz),
            up_from_hz: microphone_hz,
            down_to_hz: speaker_hz,
            frame: vec![0; frame_samples],
        })
    }

    fn lanes_for(&mut self, microphone_hz: u32, speaker_hz: u32) {
        if microphone_hz != self.up_from_hz {
            self.up = Lane::between(microphone_hz, self.rate_hz);
            self.up_from_hz = microphone_hz;
        }
        if speaker_hz != self.down_to_hz {
            self.down = Lane::between(self.rate_hz, speaker_hz);
            self.down_to_hz = speaker_hz;
        }
    }

    /// Follow the call's own rate and frame length, which a re-negotiation
    /// onto another codec moves under a live call.
    fn follow_format(&mut self) -> Result<(), CallGone> {
        let rate_hz = self.audio.sample_rate()?;
        let frame_samples = self.audio.frame_samples()?;
        if rate_hz != self.rate_hz {
            self.rate_hz = rate_hz;
            self.up = Lane::between(self.up_from_hz, rate_hz);
            self.down = Lane::between(rate_hz, self.down_to_hz);
        }
        if frame_samples != self.frame.len() {
            self.frame.resize(frame_samples, 0);
        }
        Ok(())
    }
}

/// The ring tone, on its way out.
struct Ringing {
    ring: Ring,
    at: usize,
    lane: Lane,
    lane_to_hz: u32,
}

impl Ringing {
    fn new(ring: Ring) -> Self {
        Self {
            lane: Lane::between(ring.sample_rate_hz, ring.sample_rate_hz),
            lane_to_hz: ring.sample_rate_hz,
            ring,
            at: 0,
        }
    }

    /// The next `out.len()` samples at `to_hz`, or `false` once a ring that
    /// is not looped has been played to the end.
    fn next(&mut self, to_hz: u32, out: &mut [i16]) -> bool {
        if to_hz != self.lane_to_hz {
            self.lane = Lane::between(self.ring.sample_rate_hz, to_hz);
            self.lane_to_hz = to_hz;
        }
        while !self.lane.has(out.len()) {
            let tone = &self.ring.tone;
            if tone.is_empty() {
                return false;
            }
            if self.at >= tone.len() {
                if !self.ring.looped {
                    // the end of a ring played once: what the lane still
                    // holds goes out, padded to the frame, and then nothing
                    return self.lane.take_padded(out);
                }
                self.at = 0;
            }
            // one source frame's worth at a time, from where the tone left off
            let want = usize::try_from(self.ring.sample_rate_hz / 50)
                .unwrap_or(160)
                .max(1);
            let end = self.at.saturating_add(want).min(tone.len());
            let Some(chunk) = tone.get(self.at..end) else {
                return false;
            };
            self.lane.push(chunk);
            self.at = end;
        }
        self.lane.take(out)
    }
}

/// The pump itself: the state the thread runs on, and what a test runs by
/// hand.
pub(crate) struct Pump {
    commands: Receiver<Command>,
    report: Arc<Report>,
    microphone: Option<Box<dyn CaptureStream>>,
    speaker: Option<Box<dyn PlaybackStream>>,
    ringer: Option<Box<dyn PlaybackStream>>,
    calls: Vec<Call>,
    ringing: Option<Ringing>,
    transmit: Box<dyn FnMut(CallId, Outgoing) + Send>,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
    device_hz: u32,
    /// The microphone's frame, at its rate.
    captured: Vec<i16>,
    /// One loudspeaker frame, summed wide and then narrowed.
    sum: Vec<i32>,
    out: Vec<i16>,
    /// The ring tone's frame.
    ring_frame: Vec<i16>,
    quit: bool,
}

impl Pump {
    pub(crate) fn new(
        commands: Receiver<Command>,
        report: Arc<Report>,
        transmit: Box<dyn FnMut(CallId, Outgoing) + Send>,
        now: Arc<dyn Fn() -> Instant + Send + Sync>,
        device_hz: u32,
    ) -> Self {
        Self {
            commands,
            report,
            microphone: None,
            speaker: None,
            ringer: None,
            calls: Vec::new(),
            ringing: None,
            transmit,
            now,
            device_hz,
            captured: Vec::new(),
            sum: Vec::new(),
            out: Vec::new(),
            ring_frame: Vec::new(),
            quit: false,
        }
    }

    /// Run until told to quit, one tick a frame; then hand back the transmit
    /// function and every call still carried, for the next pump to take up.
    pub(crate) fn run(mut self) -> Finished {
        let mut next = Instant::now();
        while !self.quit {
            self.tick();
            next += FRAME;
            let now = Instant::now();
            if next > now {
                std::thread::sleep(next - now);
            } else {
                // behind by more than a frame: do not try to catch up by
                // running ticks back to back, the rings have what they have
                next = now;
            }
        }
        let calls = self
            .calls
            .into_iter()
            .map(|call| (call.id, call.audio))
            .collect();
        (self.transmit, calls)
    }

    /// One frame's worth of work.
    pub(crate) fn tick(&mut self) {
        self.take_commands();
        self.check_lost();
        self.follow_formats();
        self.capture();
        self.play();
        self.ring();
        self.report.ticks.fetch_add(1, Ordering::AcqRel);
    }

    fn take_commands(&mut self) {
        loop {
            match self.commands.try_recv() {
                Ok(Command::Attach(id, audio)) => {
                    self.calls.retain(|call| call.id != id);
                    if let Some(mut call) =
                        Call::new(id, audio, self.microphone_hz(), self.speaker_hz())
                    {
                        call.audio.set_render_delay(self.render_delay());
                        self.calls.push(call);
                    } else {
                        self.note_ended(id);
                    }
                }
                Ok(Command::Detach(id)) => self.calls.retain(|call| call.id != id),
                Ok(Command::Replace(role, stream)) => self.replace(role, stream),
                Ok(Command::Ring(ring)) => self.ringing = Some(Ringing::new(ring)),
                Ok(Command::StopRing) => self.ringing = None,
                Ok(Command::Settled(done)) => {
                    // a caller that stopped waiting is not this pump's concern
                    let _ = done.send(());
                }
                Ok(Command::Quit) | Err(TryRecvError::Disconnected) => {
                    self.quit = true;
                    return;
                }
                Err(TryRecvError::Empty) => return,
            }
        }
    }

    fn replace(&mut self, role: Role, stream: Option<Stream>) {
        match (role, stream) {
            (Role::Microphone, Some(Stream::Capture(stream))) => {
                self.microphone = Some(stream);
            }
            (Role::Speaker, Some(Stream::Playback(stream))) => self.speaker = Some(stream),
            (Role::Ringer, Some(Stream::Playback(stream))) => self.ringer = Some(stream),
            (Role::Microphone, _) => self.microphone = None,
            (Role::Speaker, _) => self.speaker = None,
            (Role::Ringer, _) => self.ringer = None,
        }
        let (microphone_hz, speaker_hz) = (self.microphone_hz(), self.speaker_hz());
        let delay = self.render_delay();
        for call in &mut self.calls {
            call.lanes_for(microphone_hz, speaker_hz);
            // what was queued was on its way to a device that is not there
            call.up.clear();
            call.down.clear();
            // and the new device's own delay is what a canceller now needs
            call.audio.set_render_delay(delay);
        }
    }

    /// The loudspeaker-to-microphone delay the two streams report, which is
    /// what a canceller attached to a call looks back by.
    fn render_delay(&self) -> Duration {
        self.microphone
            .as_ref()
            .map_or(Duration::ZERO, |stream| stream.latency())
            + self
                .speaker
                .as_ref()
                .map_or(Duration::ZERO, |stream| stream.latency())
    }

    /// The rate the microphone side runs at: the stream's, or the device
    /// rate the silence stands in at when there is no microphone.
    fn microphone_hz(&self) -> u32 {
        self.microphone
            .as_ref()
            .map_or(self.device_hz, |stream| stream.format().sample_rate_hz)
    }

    /// The same for the loudspeaker side.
    fn speaker_hz(&self) -> u32 {
        self.speaker
            .as_ref()
            .map_or(self.device_hz, |stream| stream.format().sample_rate_hz)
    }

    /// Every call at its own current rate, and a call whose media ended let
    /// go of.
    fn follow_formats(&mut self) {
        let mut ended = Vec::new();
        for call in &mut self.calls {
            if call.follow_format().is_err() {
                ended.push(call.id);
            }
        }
        self.let_go(&ended);
    }

    fn check_lost(&mut self) {
        let lost = [
            self.microphone.as_mut().is_some_and(|stream| stream.lost()),
            self.speaker.as_mut().is_some_and(|stream| stream.lost()),
            self.ringer.as_mut().is_some_and(|stream| stream.lost()),
        ];
        for (flag, gone) in self.report.lost.iter().zip(lost) {
            if gone {
                flag.store(true, Ordering::Release);
            }
        }
    }

    fn note_ended(&self, id: CallId) {
        self.report
            .ended
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(id);
    }

    /// Everything the microphone has, into every call.
    fn capture(&mut self) {
        let format = match self.microphone.as_ref() {
            Some(stream) => stream.format(),
            // no microphone: the far end still hears a stream, of silence,
            // so that its own watchdog does not declare this end gone
            None => Format::twenty_ms(self.device_hz),
        };
        let mut ended = Vec::new();
        loop {
            self.captured.clear();
            self.captured.resize(format.frame_samples, 0);
            let got = match self.microphone.as_mut() {
                Some(stream) => stream.read(&mut self.captured),
                None => true,
            };
            if !got {
                break;
            }
            let now = (self.now)();
            let transmit = &mut self.transmit;
            for call in &mut self.calls {
                call.up.push(&self.captured);
                while call.up.take(&mut call.frame) {
                    let captured =
                        call.audio
                            .capture_each(call.id, &call.frame, now, &mut |id, packet| {
                                transmit(id, packet);
                            });
                    if captured.is_err() {
                        ended.push(call.id);
                        break;
                    }
                }
            }
            if self.microphone.is_none() {
                // one silent frame a tick, not a loop of them
                break;
            }
        }
        self.let_go(&ended);
    }

    fn let_go(&mut self, ended: &[CallId]) {
        for id in ended {
            self.calls.retain(|call| call.id != *id);
            self.note_ended(*id);
        }
    }

    /// Every call's playback, summed, into the loudspeaker — or pulled and
    /// dropped at the tick rate when there is none, so that a call keeps
    /// draining what arrives and keeps its echo reference moving.
    fn play(&mut self) {
        let format = match self.speaker.as_ref() {
            Some(stream) => stream.format(),
            None => Format::twenty_ms(self.device_hz),
        };
        let mut ended = Vec::new();
        let mut frames = 0_usize;
        loop {
            let room = match self.speaker.as_ref() {
                Some(stream) => {
                    stream.queued() < TARGET_QUEUED_FRAMES.saturating_mul(format.frame_samples)
                }
                None => frames == 0,
            };
            if !room || frames >= TARGET_QUEUED_FRAMES {
                break;
            }
            frames += 1;
            self.sum.clear();
            self.sum.resize(format.frame_samples, 0);
            self.out.clear();
            self.out.resize(format.frame_samples, 0);
            for call in &mut self.calls {
                while !call.down.has(format.frame_samples) {
                    match call.audio.playback(&mut call.frame) {
                        Ok(()) => call.down.push(&call.frame),
                        Err(CallGone::Ended) => {
                            ended.push(call.id);
                            break;
                        }
                    }
                }
                if call.down.take(&mut self.out) {
                    for (total, sample) in self.sum.iter_mut().zip(&self.out) {
                        *total += i32::from(*sample);
                    }
                }
            }
            // the ring joins the loudspeaker's own frame when the ringer is
            // that same stream, which is what "no ringer of its own" means
            if self.ringer.is_none()
                && let Some(ringing) = self.ringing.as_mut()
            {
                self.ring_frame.clear();
                self.ring_frame.resize(format.frame_samples, 0);
                if ringing.next(format.sample_rate_hz, &mut self.ring_frame) {
                    for (total, sample) in self.sum.iter_mut().zip(&self.ring_frame) {
                        *total += i32::from(*sample);
                    }
                } else {
                    self.ringing = None;
                    self.report.ring_done.store(true, Ordering::Release);
                }
            }
            for (slot, total) in self.out.iter_mut().zip(&self.sum) {
                *slot =
                    i16::try_from(*total).unwrap_or(if *total < 0 { i16::MIN } else { i16::MAX });
            }
            let Some(stream) = self.speaker.as_mut() else {
                break;
            };
            if !stream.write(&self.out) {
                break;
            }
        }
        self.let_go(&ended);
    }

    /// The ring tone into the ringer's own stream.
    fn ring(&mut self) {
        let Some(stream) = self.ringer.as_mut() else {
            return;
        };
        let format = stream.format();
        let Some(ringing) = self.ringing.as_mut() else {
            return;
        };
        let mut frames = 0_usize;
        while frames < TARGET_QUEUED_FRAMES
            && stream.queued() < TARGET_QUEUED_FRAMES.saturating_mul(format.frame_samples)
        {
            frames += 1;
            self.ring_frame.clear();
            self.ring_frame.resize(format.frame_samples, 0);
            if !ringing.next(format.sample_rate_hz, &mut self.ring_frame) {
                self.ringing = None;
                self.report.ring_done.store(true, Ordering::Release);
                return;
            }
            if !stream.write(&self.ring_frame) {
                return;
            }
        }
    }
}
