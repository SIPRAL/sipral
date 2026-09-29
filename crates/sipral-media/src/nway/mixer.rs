// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The conference itself: who is in it, what each of them sent, and what
//! each of them hears.

use core::fmt;

use super::convert::Converter;
use super::limiter::Limiter;
use super::ring::Ring;
use super::talker::Talker;
use super::{MAX_FRAME_TICKS, MAX_PARTICIPANTS, MIX_RATE, MIX_TICK, RECORDING_TICKS};
use crate::mix::Gain;
use crate::resample::RateError;

/// A rate a participant sends and hears at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rate {
    /// 8 kHz: G.711, G.729.
    Hz8000,
    /// 16 kHz: G.722, wideband Opus.
    Hz16000,
    /// 32 kHz: super-wideband.
    Hz32000,
    /// 48 kHz: fullband Opus, and the rate the mix is formed at.
    Hz48000,
}

impl Rate {
    /// The rate in hertz.
    #[must_use]
    pub const fn hz(self) -> u32 {
        match self {
            Self::Hz8000 => 8_000,
            Self::Hz16000 => 16_000,
            Self::Hz32000 => 32_000,
            Self::Hz48000 => 48_000,
        }
    }

    /// The rate that is `hz` hertz, when it is one of the four.
    #[must_use]
    pub const fn from_hz(hz: u32) -> Option<Self> {
        match hz {
            8_000 => Some(Self::Hz8000),
            16_000 => Some(Self::Hz16000),
            32_000 => Some(Self::Hz32000),
            48_000 => Some(Self::Hz48000),
            _ => None,
        }
    }

    /// Samples in one tick of the mixer, twenty milliseconds, at this rate.
    #[must_use]
    pub const fn tick_samples(self) -> usize {
        match self {
            Self::Hz8000 => 160,
            Self::Hz16000 => 320,
            Self::Hz32000 => 640,
            Self::Hz48000 => 960,
        }
    }
}

/// How a participant's audio is shaped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParticipantConfig {
    /// The rate the participant sends at, and hears at.
    pub rate: Rate,
    /// Samples in one of the participant's frames: what it pushes and pulls
    /// at a time. It either divides a tick — 5 or 10 ms, say — or is two or
    /// three whole ticks, 40 or 60 ms.
    pub frame_samples: usize,
}

impl ParticipantConfig {
    /// A participant at `rate` whose frames are one tick, 20 ms.
    #[must_use]
    pub const fn new(rate: Rate) -> Self {
        Self {
            rate,
            frame_samples: rate.tick_samples(),
        }
    }

    /// The same participant with frames of `frame_samples`.
    #[must_use]
    pub const fn with_frame(self, frame_samples: usize) -> Self {
        Self {
            frame_samples,
            ..self
        }
    }
}

/// How a conference is sized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixerConfig {
    /// The most participants the conference holds at once, from one to
    /// [`MAX_PARTICIPANTS`].
    pub max_participants: usize,
}

impl Default for MixerConfig {
    /// Sixteen participants.
    fn default() -> Self {
        Self {
            max_participants: 16,
        }
    }
}

/// A participant, for as long as it stays in the conference.
///
/// Once it has left, its id is refused everywhere, even after its place has
/// been given to somebody else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParticipantId {
    slot: u32,
    generation: u32,
}

impl ParticipantId {
    /// The participant's place in the conference, below
    /// [`MixerConfig::max_participants`]. A place is reused after its
    /// participant leaves, so it is an index for a table sized to the
    /// conference, not an identity.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.slot
    }
}

impl fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "participant {}.{}", self.slot, self.generation)
    }
}

/// Why the mixer refused something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MixError {
    /// The id names nobody in the conference: it left, or it was never here.
    UnknownParticipant(ParticipantId),
    /// Every place in the conference is taken.
    Full {
        /// How many places there are.
        capacity: usize,
    },
    /// A frame that neither divides a tick nor is up to
    /// [`MAX_FRAME_TICKS`] whole ticks.
    FrameSize {
        /// The participant's rate.
        rate: Rate,
        /// The frame asked for.
        frame_samples: usize,
    },
    /// A conference of no places, or of more than [`MAX_PARTICIPANTS`].
    Capacity {
        /// The places asked for.
        requested: usize,
    },
    /// No resampler could be built between a participant's rate and the
    /// mix's.
    Rate(RateError),
}

impl fmt::Display for MixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnknownParticipant(id) => write!(f, "{id} is not in the conference"),
            Self::Full { capacity } => write!(f, "all {capacity} places are taken"),
            Self::FrameSize {
                rate,
                frame_samples,
            } => write!(
                f,
                "a frame of {frame_samples} samples at {} Hz does not fit a {} ms tick",
                rate.hz(),
                super::TICK_MS
            ),
            Self::Capacity { requested } => write!(
                f,
                "{requested} places asked for, from 1 to {MAX_PARTICIPANTS} allowed"
            ),
            Self::Rate(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for MixError {}

impl From<RateError> for MixError {
    fn from(error: RateError) -> Self {
        Self::Rate(error)
    }
}

/// What went wrong with one participant's audio since it joined.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParticipantStats {
    /// Ticks that found less than a tick of input queued, once the
    /// participant had pushed anything at all. The missing part was mixed as
    /// silence.
    pub underruns: u64,
    /// Input samples dropped because they arrived more than a frame ahead of
    /// the mix.
    pub input_dropped: u64,
    /// Output samples dropped because they were not pulled in time.
    pub output_dropped: u64,
}

/// The levels and switches a participant is mixed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Controls {
    /// Applied to what the participant sends, before anybody hears it.
    pub gain_in: Gain,
    /// Applied to what the participant hears, before the limiter.
    pub gain_out: Gain,
    /// Nobody hears the participant.
    pub mute_in: bool,
    /// The participant hears silence.
    pub mute_out: bool,
    /// The participant only listens: what it pushes is thrown away unread.
    pub listen_only: bool,
}

impl Default for Controls {
    /// Unity both ways, nothing muted.
    fn default() -> Self {
        Self {
            gain_in: Gain::UNITY,
            gain_out: Gain::UNITY,
            mute_in: false,
            mute_out: false,
            listen_only: false,
        }
    }
}

/// One participant's queues, filters and state.
struct Participant {
    tick: usize,
    controls: Controls,
    /// Pushed and not yet mixed, at the participant's rate.
    input: Ring,
    /// Mixed and not yet pulled, at the participant's rate.
    output: Ring,
    /// The participant's rate up to the mix's.
    upstream: Converter,
    /// The mix's rate down to the participant's.
    downstream: Converter,
    /// Whether `upstream` holds history that a mute should forget.
    upstream_live: bool,
    /// Whether `downstream` and `limiter` do.
    downstream_live: bool,
    limiter: Limiter,
    talker: Talker,
    /// What this participant put into the current tick's sum, at the mix's
    /// rate, so it can be taken out again for its own ears.
    contribution: Vec<i32>,
    /// Whether anything has been pushed yet, so a participant that joined
    /// before its first packet is not counted as starving.
    started: bool,
    stats: ParticipantStats,
}

impl Participant {
    fn new(config: ParticipantConfig) -> Result<Self, RateError> {
        let tick = config.rate.tick_samples();
        let hz = config.rate.hz();
        let queue = config.frame_samples.max(tick) + tick;
        Ok(Self {
            tick,
            controls: Controls::default(),
            input: Ring::new(queue),
            output: Ring::new(queue),
            upstream: Converter::new(hz, MIX_RATE, tick)?,
            downstream: Converter::new(MIX_RATE, hz, MIX_TICK)?,
            upstream_live: false,
            downstream_live: false,
            limiter: Limiter::new(MIX_RATE),
            talker: Talker::default(),
            contribution: vec![0; MIX_TICK],
            started: false,
            stats: ParticipantStats::default(),
        })
    }

    /// Takes tick number `tick` of input, measures it for the talker
    /// detector, and adds what the others should hear of it to `sum`.
    fn take_input(&mut self, tick: u64, native: &mut [i16], wide: &mut [i16], sum: &mut [i32]) {
        let Some(frame) = native.get_mut(..self.tick) else {
            return;
        };
        let got = self.input.pop(frame);
        if let Some(missing) = frame.get_mut(got..)
            && !missing.is_empty()
        {
            missing.fill(0);
            if self.started && !self.controls.listen_only {
                self.stats.underruns += 1;
            }
        }

        if self.controls.listen_only {
            self.talker.reset();
        } else {
            // measured even while muted, so a caller can tell a participant
            // that it is talking into a mute
            self.talker
                .update(energy(frame, self.controls.gain_in), tick);
        }

        if self.controls.mute_in || self.controls.listen_only {
            self.contribution.fill(0);
            if self.upstream_live {
                self.upstream.reset();
                self.upstream_live = false;
            }
            return;
        }
        self.upstream.run(frame, wide);
        self.upstream_live = true;
        let gain = self.controls.gain_in;
        for ((own, sample), total) in self.contribution.iter_mut().zip(wide.iter()).zip(sum) {
            *own = narrow(scale(i64::from(*sample), gain));
            *total = total.saturating_add(*own);
        }
    }

    /// Queues one tick of everything in `sum` except this participant.
    fn give_output(&mut self, sum: &[i32], wide: &mut [i16], native: &mut [i16]) {
        let Some(frame) = native.get_mut(..self.tick) else {
            return;
        };
        if self.controls.mute_out {
            frame.fill(0);
            if self.downstream_live {
                self.downstream.reset();
                self.limiter.reset();
                self.downstream_live = false;
            }
        } else {
            let gain = self.controls.gain_out;
            for ((slot, total), own) in wide.iter_mut().zip(sum).zip(&self.contribution) {
                let heard = scale(i64::from(total.saturating_sub(*own)), gain);
                *slot = self.limiter.process(narrow(heard));
            }
            self.downstream.run(wide, frame);
            self.downstream_live = true;
        }
        let dropped = self.output.push(frame);
        self.stats.output_dropped += count(dropped);
    }
}

impl Participant {
    /// Whether the conference should list this participant as talking.
    const fn heard_talking(&self) -> bool {
        self.talker.talking() && !self.controls.mute_in && !self.controls.listen_only
    }
}

/// The whole mix, on its way to a recorder.
struct Recording {
    rate: Rate,
    limiter: Limiter,
    downstream: Converter,
    queue: Ring,
    dropped: u64,
}

impl Recording {
    fn new(rate: Rate) -> Result<Self, RateError> {
        Ok(Self {
            rate,
            limiter: Limiter::new(MIX_RATE),
            downstream: Converter::new(MIX_RATE, rate.hz(), MIX_TICK)?,
            queue: Ring::new(RECORDING_TICKS * rate.tick_samples()),
            dropped: 0,
        })
    }

    /// Queues one tick of the whole of `sum`.
    fn take(&mut self, sum: &[i32], wide: &mut [i16], native: &mut [i16]) {
        let Some(frame) = native.get_mut(..self.rate.tick_samples()) else {
            return;
        };
        self.limiter.process_into(sum, wide);
        self.downstream.run(wide, frame);
        self.dropped += count(self.queue.push(frame));
    }
}

/// A place in the conference, and how many participants have held it.
struct Slot {
    generation: u32,
    participant: Option<Participant>,
}

/// An N-way conference mixer.
///
/// The [module documentation](super) describes the model: push each
/// participant's audio, call [`mix`](Self::mix) once every 20 ms, pull each
/// participant's audio back.
pub struct Mixer {
    slots: Vec<Slot>,
    present: usize,
    /// Everybody's contribution to the current tick, at the mix's rate.
    sum: Vec<i32>,
    /// One tick at the mix's rate, reused for each participant in turn.
    wide: Vec<i16>,
    /// One tick at a participant's rate, reused likewise.
    native: Vec<i16>,
    /// Who is talking, loudest first, as of the last tick.
    talkers: Vec<ParticipantId>,
    recording: Option<Recording>,
    ticks: u64,
}

impl Mixer {
    /// An empty conference with room for `config.max_participants`.
    ///
    /// # Errors
    ///
    /// [`MixError::Capacity`] when that is zero or more than
    /// [`MAX_PARTICIPANTS`].
    pub fn new(config: MixerConfig) -> Result<Self, MixError> {
        let requested = config.max_participants;
        if requested == 0 || requested > MAX_PARTICIPANTS {
            return Err(MixError::Capacity { requested });
        }
        let slots = (0..requested)
            .map(|_| Slot {
                generation: 0,
                participant: None,
            })
            .collect();
        Ok(Self {
            slots,
            present: 0,
            sum: vec![0; MIX_TICK],
            wide: vec![0; MIX_TICK],
            native: vec![0; MIX_TICK],
            talkers: Vec::with_capacity(requested),
            recording: None,
            ticks: 0,
        })
    }

    /// Adds a participant, which takes part in the next tick: what it pushes
    /// before that tick is heard in it.
    ///
    /// This is where the participant's filters and queues are allocated;
    /// nothing allocates for it again until it leaves.
    ///
    /// # Errors
    ///
    /// [`MixError::FrameSize`] for a frame that does not fit the tick,
    /// [`MixError::Full`] when every place is taken.
    pub fn join(&mut self, config: ParticipantConfig) -> Result<ParticipantId, MixError> {
        let tick = config.rate.tick_samples();
        let frame = config.frame_samples;
        let fits = frame > 0
            && (tick.is_multiple_of(frame)
                || (frame.is_multiple_of(tick) && frame / tick <= MAX_FRAME_TICKS));
        if !fits {
            return Err(MixError::FrameSize {
                rate: config.rate,
                frame_samples: frame,
            });
        }
        let capacity = self.slots.len();
        let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.participant.is_none())
        else {
            return Err(MixError::Full { capacity });
        };
        let index = u32::try_from(index).map_err(|_| MixError::Full { capacity })?;
        slot.participant = Some(Participant::new(config)?);
        slot.generation = slot.generation.wrapping_add(1);
        self.present += 1;
        Ok(ParticipantId {
            slot: index,
            generation: slot.generation,
        })
    }

    /// Removes a participant. Whatever it pushed and was not yet mixed is
    /// never heard, and it is gone from the very next tick.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn leave(&mut self, id: ParticipantId) -> Result<(), MixError> {
        let slot = self.slot_mut(id).ok_or(MixError::UnknownParticipant(id))?;
        slot.participant = None;
        self.present -= 1;
        self.talkers.retain(|talker| *talker != id);
        Ok(())
    }

    /// Participants in the conference.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.present
    }

    /// Whether nobody is in the conference.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.present == 0
    }

    /// Ticks mixed so far.
    #[must_use]
    pub const fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Queues audio a participant sent, at its own rate, for the next tick.
    ///
    /// Any length is taken; a frame at a time is the usual. Audio more than
    /// one frame ahead of the mix is dropped from the oldest end and counted
    /// in [`ParticipantStats::input_dropped`], and a listen-only participant's
    /// audio is dropped unread.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn push(&mut self, id: ParticipantId, samples: &[i16]) -> Result<(), MixError> {
        let participant = self.participant_mut(id)?;
        if participant.controls.listen_only {
            return Ok(());
        }
        participant.started = true;
        let dropped = participant.input.push(samples);
        participant.stats.input_dropped += count(dropped);
        Ok(())
    }

    /// Moves what a participant should hear, at its own rate, into `output`,
    /// and returns how many samples that was.
    ///
    /// Each tick queues one tick of audio for every participant, so a
    /// participant whose frame is a tick or less can pull a whole frame
    /// after every tick, and one whose frame is several ticks after that
    /// many.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn pull(&mut self, id: ParticipantId, output: &mut [i16]) -> Result<usize, MixError> {
        Ok(self.participant_mut(id)?.output.pop(output))
    }

    /// Samples waiting to be pulled for a participant.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn available(&self, id: ParticipantId) -> Result<usize, MixError> {
        Ok(self.participant(id)?.output.len())
    }

    /// What has gone wrong with a participant's audio since it joined.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn stats(&self, id: ParticipantId) -> Result<ParticipantStats, MixError> {
        Ok(self.participant(id)?.stats)
    }

    /// The levels and switches a participant is mixed with.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn controls(&self, id: ParticipantId) -> Result<Controls, MixError> {
        Ok(self.participant(id)?.controls)
    }

    /// Sets the level of what a participant sends, from the next tick.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn set_gain_in(&mut self, id: ParticipantId, gain: Gain) -> Result<(), MixError> {
        self.participant_mut(id)?.controls.gain_in = gain;
        Ok(())
    }

    /// Sets the level of what a participant hears, from the next tick.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn set_gain_out(&mut self, id: ParticipantId, gain: Gain) -> Result<(), MixError> {
        self.participant_mut(id)?.controls.gain_out = gain;
        Ok(())
    }

    /// Mutes or unmutes what a participant sends, from the next tick.
    ///
    /// A muted participant's audio is still taken off its queue every tick,
    /// so unmuting does not play back what was said while muted.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn set_mute_in(&mut self, id: ParticipantId, muted: bool) -> Result<(), MixError> {
        self.participant_mut(id)?.controls.mute_in = muted;
        Ok(())
    }

    /// Mutes or unmutes what a participant hears, from the next tick.
    ///
    /// A participant muted this way still has a tick of silence queued every
    /// tick, so whatever clocks its playback keeps running.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn set_mute_out(&mut self, id: ParticipantId, muted: bool) -> Result<(), MixError> {
        self.participant_mut(id)?.controls.mute_out = muted;
        Ok(())
    }

    /// Makes a participant listen only, or lets it speak again.
    ///
    /// A listen-only participant hears the conference as before. What it
    /// pushes is thrown away unread, what it queued before is thrown away by
    /// the next tick, and a tick with nothing from it is not an underrun.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn set_listen_only(
        &mut self,
        id: ParticipantId,
        listen_only: bool,
    ) -> Result<(), MixError> {
        self.participant_mut(id)?.controls.listen_only = listen_only;
        Ok(())
    }

    /// Who was talking in the last tick, loudest first.
    ///
    /// A participant joins the list after [`START_TICKS`] ticks of speech and
    /// leaves it after [`STOP_TICKS`] ticks of silence, and is ranked by its
    /// level averaged over [`SMOOTHING_TICKS`] ticks; two at the same level
    /// are ranked by who started first. A muted or listen-only participant is
    /// never listed, and one that leaves is gone from the list at once. The
    /// [`talker`](super::talker) module has the levels.
    ///
    /// [`START_TICKS`]: super::talker::START_TICKS
    /// [`STOP_TICKS`]: super::talker::STOP_TICKS
    /// [`SMOOTHING_TICKS`]: super::talker::SMOOTHING_TICKS
    #[must_use]
    pub fn talkers(&self) -> &[ParticipantId] {
        &self.talkers
    }

    /// Whether a participant was talking in the last tick.
    ///
    /// Unlike [`talkers`](Self::talkers) this is true of a participant that
    /// is talking into its own mute, which is what a client needs to say so.
    /// It is never true of a listen-only participant.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    pub fn is_talking(&self, id: ParticipantId) -> Result<bool, MixError> {
        Ok(self.participant(id)?.talker.talking())
    }

    /// The level talkers are ranked by: mean-square energy after the input
    /// gain, averaged over [`SMOOTHING_TICKS`] ticks.
    ///
    /// # Errors
    ///
    /// [`MixError::UnknownParticipant`] when it is not in the conference.
    ///
    /// [`SMOOTHING_TICKS`]: super::talker::SMOOTHING_TICKS
    pub fn talk_level(&self, id: ParticipantId) -> Result<i64, MixError> {
        Ok(self.participant(id)?.talker.level())
    }

    /// Starts recording the whole mix at `rate`, from the next tick, or
    /// starts again at a new rate.
    ///
    /// The recording is everybody the conference hears — every participant
    /// that is neither muted nor listen-only, at its input gain — through a
    /// limiter of its own. Each tick queues a tick of it, and up to
    /// [`RECORDING_TICKS`] ticks wait to be read; past that the oldest are
    /// dropped and counted. This allocates the recording's filter and queue.
    ///
    /// # Errors
    ///
    /// [`MixError::Rate`] if no resampler could be built for `rate`, which
    /// does not happen for any [`Rate`].
    pub fn start_recording(&mut self, rate: Rate) -> Result<(), MixError> {
        self.recording = Some(Recording::new(rate)?);
        Ok(())
    }

    /// Stops recording, dropping whatever was not read.
    pub fn stop_recording(&mut self) {
        self.recording = None;
    }

    /// The rate the mix is being recorded at, if it is.
    #[must_use]
    pub fn recording_rate(&self) -> Option<Rate> {
        self.recording.as_ref().map(|recording| recording.rate)
    }

    /// Moves recorded audio into `output` and returns how many samples that
    /// was: none when nothing is being recorded.
    pub fn read_recording(&mut self, output: &mut [i16]) -> usize {
        self.recording
            .as_mut()
            .map_or(0, |recording| recording.queue.pop(output))
    }

    /// Recorded samples waiting to be read.
    #[must_use]
    pub fn recording_available(&self) -> usize {
        self.recording
            .as_ref()
            .map_or(0, |recording| recording.queue.len())
    }

    /// Recorded samples dropped because they were not read in time, since
    /// recording started.
    #[must_use]
    pub fn recording_dropped(&self) -> u64 {
        self.recording
            .as_ref()
            .map_or(0, |recording| recording.dropped)
    }

    /// Mixes one tick, 20 ms.
    ///
    /// Takes a tick of input from every participant — silence for whatever
    /// was not pushed in time — and queues a tick of output for every
    /// participant: everybody else, at its own rate, at its own level,
    /// through its own limiter. Nothing here allocates.
    pub fn mix(&mut self) {
        let Self {
            slots,
            sum,
            wide,
            native,
            talkers,
            recording,
            ticks,
            ..
        } = self;
        sum.fill(0);
        for participant in slots
            .iter_mut()
            .filter_map(|slot| slot.participant.as_mut())
        {
            participant.take_input(*ticks, native, wide, sum);
        }
        rank(slots, talkers);
        if let Some(recording) = recording {
            recording.take(sum, wide, native);
        }
        for participant in slots
            .iter_mut()
            .filter_map(|slot| slot.participant.as_mut())
        {
            participant.give_output(sum, wide, native);
        }
        self.ticks += 1;
    }

    fn slot_mut(&mut self, id: ParticipantId) -> Option<&mut Slot> {
        let slot = self.slots.get_mut(usize::try_from(id.slot).ok()?)?;
        (slot.generation == id.generation && slot.participant.is_some()).then_some(slot)
    }

    fn participant(&self, id: ParticipantId) -> Result<&Participant, MixError> {
        usize::try_from(id.slot)
            .ok()
            .and_then(|index| self.slots.get(index))
            .filter(|slot| slot.generation == id.generation)
            .and_then(|slot| slot.participant.as_ref())
            .ok_or(MixError::UnknownParticipant(id))
    }

    fn participant_mut(&mut self, id: ParticipantId) -> Result<&mut Participant, MixError> {
        self.slot_mut(id)
            .and_then(|slot| slot.participant.as_mut())
            .ok_or(MixError::UnknownParticipant(id))
    }
}

/// Lists the participants that are talking, loudest first, in place.
fn rank(slots: &[Slot], talkers: &mut Vec<ParticipantId>) {
    talkers.clear();
    for (index, slot) in slots.iter().enumerate() {
        if let (Some(participant), Ok(index)) = (&slot.participant, u32::try_from(index))
            && participant.heard_talking()
        {
            talkers.push(ParticipantId {
                slot: index,
                generation: slot.generation,
            });
        }
    }
    let key = |id: &ParticipantId| {
        let talker = usize::try_from(id.slot)
            .ok()
            .and_then(|index| slots.get(index))
            .and_then(|slot| slot.participant.as_ref())
            .map(|participant| participant.talker)
            .unwrap_or_default();
        (core::cmp::Reverse(talker.level()), talker.since(), *id)
    };
    talkers.sort_unstable_by_key(key);
}

/// Mean-square energy of a tick at `gain`.
fn energy(frame: &[i16], gain: Gain) -> i64 {
    let total: i64 = frame
        .iter()
        .map(|sample| {
            let scaled = scale(i64::from(*sample), gain);
            scaled * scaled
        })
        .sum();
    total / i64::try_from(frame.len()).unwrap_or(1).max(1)
}

/// Written out: the filters and queues are tens of kilobytes each.
impl fmt::Debug for Mixer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mixer")
            .field("places", &self.slots.len())
            .field("participants", &self.present)
            .field("ticks", &self.ticks)
            .finish_non_exhaustive()
    }
}

/// A sample at a Q15 level, rounded away from zero exactly as
/// [`Gain::apply`] rounds, without clipping: the sum it goes into is wider
/// than a sample.
fn scale(value: i64, gain: Gain) -> i64 {
    let scaled = value * i64::from(gain.to_q15());
    let half = 1 << 14;
    if scaled < 0 {
        -((-scaled + half) >> 15)
    } else {
        (scaled + half) >> 15
    }
}

/// A wide value down to thirty-two bits, saturating.
fn narrow(value: i64) -> i32 {
    i32::try_from(value).unwrap_or(if value < 0 { i32::MIN } else { i32::MAX })
}

/// A sample count as a counter's width.
fn count(samples: usize) -> u64 {
    u64::try_from(samples).unwrap_or(u64::MAX)
}
