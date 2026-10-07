// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a call carries inside its audio: keypad digits both ways, network call-progress tones, who
//! answered, and the recording beep.
//!
//! `sipral-media`'s `inband` module listens and writes; this connects it to a call. Detectors run
//! at 8 or 16 kHz, so far-end audio at another codec rate (Opus's 48 kHz) is converted down to 16
//! kHz first. Writing needs no conversion: digits and beeps are sines generated at the codec's
//! rate.
//!
//! # Digits in the audio
//!
//! Most far ends send digits as RFC 4733 events. One that never offered `telephone-event` can only
//! leave the tones in the audio, so by default ([`DtmfDetection::Auto`]) this end listens exactly
//! when no named events were negotiated. [`DtmfDetection::Always`] listens on every call, for
//! gateways that negotiate events and still pass the tones. A press heard both ways is reported
//! once: an in-band digit waits [`IN_BAND_DIGIT_HOLD`] after it ends, and is dropped if the same
//! press arrives as an event meanwhile.
//!
//! Outgoing, a digit on a call without telephone events replaces the microphone for its tone and
//! the pause after it.
//!
//! # Call progress and who answered
//!
//! Opt-in per call ([`ProgressDetection`]). From the first early-media frame the far-end audio is
//! checked for one network's tones (ringback, busy, congestion, special information tone), each
//! reported once. On answer, an answering-machine detector decides from the speech and silence
//! pattern while tones are still checked (catching gateways that answer to play an intercept).
//! After [`AmdVerdict::Machine`] the machine's beep is awaited, so a message starts after it rather
//! than over the greeting.
//!
//! # The consent tone
//!
//! A repeating beep while the call is recorded, mixed into what goes to the far end and, by
//! default, into local playback. It starts with the recording (first beep at once), stops with it,
//! and is in the recording's local side as evidence it was played.

use std::collections::VecDeque;
use std::time::Duration;

use sipral_media::inband::SampleRate;
use sipral_media::inband::amd::AnsweringMachineDetector;
use sipral_media::inband::beep::BeepDetector;
use sipral_media::inband::dtmf::{Digit as Key, DtmfDetector, DtmfEvent};
use sipral_media::inband::generate::{DtmfGenerator, DtmfTone, ToneGenerator};
use sipral_media::inband::progress::{ProgressDetector, ProgressEvent};
use sipral_media::mix::add_into;
use sipral_media::resample::Resampler;

pub use sipral_media::inband::amd::{AmdConfig, Reason as AmdReason, Verdict as AmdVerdict};
pub use sipral_media::inband::beep::BeepConfig;
pub use sipral_media::inband::progress::{ProgressConfig, ProgressTone, Region as ToneRegion};

use crate::dtmf::{DIGIT_GAP, WAITING};
use crate::error::MediaError;
use crate::event::{DigitSource, MediaEvent};
use crate::share::Outbox;

/// How long an in-band digit is held before reporting, on a call that also negotiated named events:
/// the time a far end sending both needs to send the event.
///
/// `KeyPress::is_same_press` in `sipral-media` treats 60 ms either side as one press, and an RFC
/// 4733 event is reported only after its end packet, so this is that plus a frame or two of jitter.
pub const IN_BAND_DIGIT_HOLD: Duration = Duration::from_millis(250);

/// How far apart an in-band digit and an event digit may be and still count as one press:
/// `sipral-media`'s allowance between a gateway's event timestamp and its tone.
const SAME_PRESS: Duration = Duration::from_millis(60);

/// How many events received by RFC 4733 are remembered for telling a press
/// heard both ways apart from two presses.
const REMEMBERED: usize = 8;

/// Detector rate when the call's rate is neither 8 nor 16 kHz: 16 kHz keeps everything tones and
/// voice need.
const LISTENING_RATE: SampleRate = SampleRate::Hz16000;

/// When to listen for keypad digits in the far end's audio.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DtmfDetection {
    /// Never. Digits arrive only as RFC 4733 events or by INFO.
    Off,
    /// On a call whose negotiation settled on no telephone event payload
    /// type: the far end then has no other way to send a digit.
    #[default]
    Auto,
    /// On every call. A press the far end sends both as an event and in the
    /// audio is reported once, as the event.
    Always,
}

/// What to listen for on a call this end placed: the tones its network
/// plays, and who answered.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProgressDetection {
    /// Whose tones to listen for.
    pub region: ToneRegion,
    /// How strict to be about them.
    pub tones: ProgressConfig,
    /// Decide who answered, with these limits; `None` stops listening at
    /// answer.
    pub answering_machine: Option<AmdConfig>,
    /// After a verdict of [`AmdVerdict::Machine`], listen for the beep with
    /// these limits; `None` does not.
    pub beep: Option<BeepConfig>,
    /// How long after the verdict to go on listening for the beep: a
    /// greeting can run on well after the detector has recognised it as one.
    pub beep_window: Duration,
}

impl Default for ProgressDetection {
    /// The European tones, and both detectors with their own defaults, the
    /// beep listened for for thirty seconds.
    fn default() -> Self {
        Self {
            region: ToneRegion::Europe,
            tones: ProgressConfig::default(),
            answering_machine: Some(AmdConfig::default()),
            beep: Some(BeepConfig::default()),
            beep_window: Duration::from_secs(30),
        }
    }
}

/// A beep that repeats while a call is being recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConsentTone {
    /// Its frequency, from 300 to 3400 Hz: inside the band every codec in
    /// this build carries. Default 1400.
    pub frequency_hz: u32,
    /// Its level, from −40 to −3 dBm0. Default −18: plainly audible under
    /// speech without drowning it.
    pub level_dbm0: i32,
    /// How long each beep lasts, from 50 ms to 2 s. Default 200 ms.
    pub length: Duration,
    /// How often it repeats, start to start: longer than a beep and at most
    /// ten minutes. Default fifteen seconds.
    pub interval: Duration,
    /// Whether this end hears it too. Default on: the person recording is
    /// told the recording is running by the same sound as the far end.
    pub local: bool,
}

impl Default for ConsentTone {
    fn default() -> Self {
        Self {
            frequency_hz: 1_400,
            level_dbm0: -18,
            length: Duration::from_millis(200),
            interval: Duration::from_secs(15),
            local: true,
        }
    }
}

impl ConsentTone {
    /// Refuse a tone no codec here carries, or one that is not a beep.
    ///
    /// # Errors
    /// [`MediaError::ConsentTone`], naming the field.
    pub fn check(&self) -> Result<(), MediaError> {
        if !(300..=3_400).contains(&self.frequency_hz) {
            return Err(MediaError::ConsentTone(
                "frequency_hz is outside 300 to 3400",
            ));
        }
        if !(-40..=-3).contains(&self.level_dbm0) {
            return Err(MediaError::ConsentTone("level_dbm0 is outside -40 to -3"));
        }
        if self.length < Duration::from_millis(50) || self.length > Duration::from_secs(2) {
            return Err(MediaError::ConsentTone("length is outside 50 ms to 2 s"));
        }
        if self.interval <= self.length || self.interval > Duration::from_secs(600) {
            return Err(MediaError::ConsentTone(
                "interval is not longer than a beep and at most ten minutes",
            ));
        }
        Ok(())
    }

    /// The beep, written at `hz`.
    fn generator(&self, hz: u32) -> ToneGenerator {
        let on = millis(self.length);
        let off = millis(self.interval).saturating_sub(on);
        ToneGenerator::beeps(
            hz,
            f64::from(self.frequency_hz),
            on,
            off,
            f64::from(self.level_dbm0),
        )
    }
}

/// What the far end's network or the far end itself said in the audio.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum CallProgress {
    /// A call-progress tone of the configured network.
    Tone {
        /// Which.
        tone: ProgressTone,
        /// When its first burst began, on the far end's audio, from the
        /// first frame listened to.
        at: Duration,
    },
    /// The special information tone: the call failed, and an announcement
    /// saying why usually follows.
    SpecialInformation {
        /// The frequency of each of the three, as measured, in hertz.
        frequencies: [f64; 3],
        /// How long each sounded, as measured.
        durations: [Duration; 3],
        /// When the first of the three began, from the first frame
        /// listened to.
        at: Duration,
    },
    /// Who answered.
    AnsweredBy {
        /// A person, a machine, or not sure.
        verdict: AmdVerdict,
        /// Which rule decided.
        reason: AmdReason,
        /// How long after answer the decision came.
        after: Duration,
        /// How long after answer the first word began, or how long the
        /// silence lasted if nobody spoke.
        initial_silence: Duration,
        /// From the first word's start to the last word's end.
        greeting: Duration,
        /// How many words were heard.
        words: u32,
    },
    /// The beep an answering machine plays before it records.
    Beep {
        /// Its frequency, as measured, in hertz.
        frequency_hz: f64,
        /// How long after answer it ended, which is when the machine starts
        /// recording.
        ended: Duration,
        /// How long it sounded.
        length: Duration,
    },
}

/// A span of the far end's audio, from the first frame listened to.
#[derive(Clone, Copy, Debug)]
struct Press {
    key: char,
    start: Duration,
    end: Duration,
}

impl Press {
    fn overlaps(&self, other: &Self) -> bool {
        self.key == other.key
            && self.start <= other.end.saturating_add(SAME_PRESS)
            && other.start <= self.end.saturating_add(SAME_PRESS)
    }
}

/// Where a detector's sample counts fall on the call's own clock.
#[derive(Clone, Copy, Debug)]
struct Clock {
    /// The rate the detectors count at.
    rate: SampleRate,
    /// The time heard before they were built: a codec change rebuilds
    /// them, and the call's clock goes on.
    before: Duration,
}

impl Clock {
    /// Where `samples` of the detectors' count falls on the call's clock.
    fn time(self, samples: u64) -> Duration {
        self.before.saturating_add(sample_span(samples, self.rate))
    }
}

/// The far end's audio at the rate the detectors take, and the count of
/// samples that is their clock.
#[derive(Debug)]
struct Listener {
    clock: Clock,
    /// The rate the call's frames arrive at.
    call_rate: u32,
    /// Converter from the call rate to the listening rate, when they differ. Built on first use,
    /// since most calls never listen. Stays `None` if no resampler fits, which never happens for
    /// supported codec rates; the detectors then hear nothing rather than audio at the wrong speed.
    convert: Option<Resampler>,
    converted: Vec<i16>,
    /// Samples at the listening rate taken since the detectors were built.
    samples: u64,
}

impl Listener {
    fn new(call_rate: u32, before: Duration) -> Self {
        let rate = SampleRate::from_hz(call_rate).unwrap_or(LISTENING_RATE);
        Self {
            clock: Clock { rate, before },
            call_rate,
            convert: None,
            converted: Vec::new(),
            samples: 0,
        }
    }

    const fn rate(&self) -> SampleRate {
        self.clock.rate
    }

    /// `frame`, at the listening rate.
    fn take<'a>(&'a mut self, frame: &'a [i16]) -> &'a [i16] {
        if self.clock.rate.hz() == self.call_rate {
            return frame;
        }
        if self.convert.is_none() {
            self.convert = Resampler::new(self.call_rate, self.clock.rate.hz()).ok();
        }
        let Some(convert) = self.convert.as_mut() else {
            return &[];
        };
        let room = convert.output_capacity(frame.len());
        if self.converted.len() < room {
            self.converted.resize(room, 0);
        }
        let written = convert.process(frame, &mut self.converted).unwrap_or(0);
        self.converted.get(..written).unwrap_or_default()
    }

    fn now(&self) -> Duration {
        self.clock.time(self.samples)
    }
}

/// Call progress on one call: the tones until answer, who answered, and
/// the beep.
#[derive(Debug)]
struct Progress {
    config: ProgressDetection,
    tones: Option<ProgressDetector>,
    amd: Option<AnsweringMachineDetector>,
    /// The beep detector, and until when it listens.
    beep: Option<(BeepDetector, Duration)>,
    /// When the call was answered, on the far end's audio.
    answered: Option<Duration>,
    /// Where the answering-machine detector's clock starts, on the
    /// listener's: it counts from answer.
    amd_from: Duration,
    /// And the beep detector's, which counts from the verdict.
    beep_from: Duration,
}

impl Progress {
    fn new(config: ProgressDetection, rate: SampleRate) -> Self {
        Self {
            tones: Some(ProgressDetector::with_config(
                rate,
                config.region.tones(),
                config.tones,
            )),
            config,
            amd: None,
            beep: None,
            answered: None,
            amd_from: Duration::ZERO,
            beep_from: Duration::ZERO,
        }
    }

    /// The detectors that are running, rebuilt at a new rate. What each has
    /// heard is lost with the rate it heard it at.
    fn rebuild(&mut self, rate: SampleRate, now: Duration) {
        if self.tones.is_some() {
            self.tones = Some(ProgressDetector::with_config(
                rate,
                self.config.region.tones(),
                self.config.tones,
            ));
        }
        if let (Some(_), Some(limits)) = (&self.amd, self.config.answering_machine) {
            self.amd = Some(AnsweringMachineDetector::with_config(rate, limits));
            self.amd_from = now;
        }
        if let (Some((_, until)), Some(limits)) = (&self.beep, self.config.beep) {
            self.beep = Some((BeepDetector::with_config(rate, limits), *until));
            self.beep_from = now;
        }
    }

    /// The call was answered at `now`.
    fn answered(&mut self, rate: SampleRate, now: Duration) {
        if self.answered.is_some() {
            return;
        }
        self.answered = Some(now);
        match self.config.answering_machine {
            Some(limits) => {
                self.amd = Some(AnsweringMachineDetector::with_config(rate, limits));
                self.amd_from = now;
            }
            None => self.tones = None,
        }
    }

    fn is_done(&self) -> bool {
        self.tones.is_none() && self.amd.is_none() && self.beep.is_none()
    }

    /// Listen to one frame, which starts at sample `start` of `clock`.
    fn hear(&mut self, samples: &[i16], clock: Clock, start: u64, events: &mut Outbox) {
        if let Some(tones) = self.tones.as_mut() {
            tones.process(samples, |heard| {
                events.push_back(MediaEvent::Progress(tone_heard(&heard, clock)));
            });
        }
        let now = clock.time(start);
        if let Some(amd) = self.amd.as_mut()
            && let Some(result) = amd.process(samples)
        {
            let after = sample_span(result.at, clock.rate);
            events.push_back(MediaEvent::Progress(CallProgress::AnsweredBy {
                verdict: result.verdict,
                reason: result.reason,
                after: self
                    .amd_from
                    .saturating_sub(self.answered.unwrap_or(self.amd_from))
                    .saturating_add(after),
                initial_silence: Duration::from_millis(u64::from(result.initial_silence_ms)),
                greeting: Duration::from_millis(u64::from(result.greeting_ms)),
                words: result.words,
            }));
            self.amd = None;
            self.tones = None;
            if result.verdict == AmdVerdict::Machine
                && let Some(limits) = self.config.beep
            {
                let decided = self.amd_from.saturating_add(after);
                self.beep = Some((
                    BeepDetector::with_config(clock.rate, limits),
                    decided.saturating_add(self.config.beep_window),
                ));
                self.beep_from = now;
            }
            return;
        }
        let answered = self.answered.unwrap_or_default();
        let beep_from = self.beep_from;
        let mut heard = None;
        if let Some((detector, until)) = self.beep.as_mut() {
            detector.process(samples, |beep| heard = Some(beep));
            if let Some(beep) = heard {
                let ended = beep_from
                    .saturating_add(sample_span(beep.end, clock.rate))
                    .saturating_sub(answered);
                events.push_back(MediaEvent::Progress(CallProgress::Beep {
                    frequency_hz: beep.frequency_hz,
                    ended,
                    length: sample_span(beep.end.saturating_sub(beep.start), clock.rate),
                }));
            }
            if heard.is_some() || now >= *until {
                self.beep = None;
            }
        }
    }
}

/// What a progress detector heard, said on the call's clock.
fn tone_heard(heard: &ProgressEvent, clock: Clock) -> CallProgress {
    let at = clock.time(heard.start);
    match heard.sit {
        Some(sit) => CallProgress::SpecialInformation {
            frequencies: sit.frequencies,
            durations: sit
                .durations_ms
                .map(|ms| Duration::from_millis(u64::from(ms))),
            at,
        },
        None => CallProgress::Tone {
            tone: heard.tone,
            at,
        },
    }
}

/// `samples` at `rate`, as a length of time.
fn sample_span(samples: u64, rate: SampleRate) -> Duration {
    Duration::from_nanos(samples.saturating_mul(1_000_000_000) / u64::from(rate.hz()).max(1))
}

/// A length of time in whole milliseconds, as the generators take it.
fn millis(span: Duration) -> u32 {
    u32::try_from(span.as_millis()).unwrap_or(u32::MAX)
}

/// Everything one call does with what its audio carries.
#[derive(Debug)]
pub(crate) struct Signals {
    /// The rate the codec hears at, which is what the generators write at.
    rate: u32,
    listener: Listener,
    detection: DtmfDetection,
    /// Whether the call negotiated named events, which is what `Auto`
    /// decides on and what makes holding a digit back worth the wait.
    events: bool,
    dtmf: Option<DtmfDetector>,
    /// Digits heard in the audio, waiting out [`IN_BAND_DIGIT_HOLD`], each with
    /// the time it may be reported at.
    held: VecDeque<(Press, Duration)>,
    /// Digits the far end sent as events, recently.
    received: VecDeque<Press>,
    progress: Option<Progress>,
    /// Digits to write into the outgoing audio, and how long each sounds.
    dialling: VecDeque<(Key, u32)>,
    writing: DtmfGenerator,
    consent: Option<ConsentTone>,
    beeps_out: Option<ToneGenerator>,
    beeps_in: Option<ToneGenerator>,
    beep_scratch: Vec<i16>,
}

impl Signals {
    pub(crate) fn new(
        rate: u32,
        events: bool,
        detection: DtmfDetection,
        progress: Option<ProgressDetection>,
        consent: Option<ConsentTone>,
    ) -> Self {
        let listener = Listener::new(rate, Duration::ZERO);
        let listening = listener.rate();
        let mut signals = Self {
            rate,
            listener,
            detection,
            events,
            dtmf: None,
            held: VecDeque::new(),
            received: VecDeque::with_capacity(REMEMBERED),
            progress: progress.map(|config| Progress::new(config, listening)),
            dialling: VecDeque::with_capacity(WAITING),
            writing: DtmfGenerator::with_tone_at(rate, DtmfTone::default()),
            consent,
            beeps_out: None,
            beeps_in: None,
            beep_scratch: Vec::new(),
        };
        signals.arm_detector();
        signals
    }

    /// The call moved to a codec at another rate, or its negotiation moved
    /// on named events. Detectors are rebuilt at the new rate; what they
    /// were in the middle of hearing is lost, and the clock carries on.
    pub(crate) fn reformat(&mut self, rate: u32, events: bool) {
        let now = self.listener.now();
        if rate != self.rate {
            self.rate = rate;
            self.listener = Listener::new(rate, now);
            self.dtmf = None;
            let listening = self.listener.rate();
            if let Some(progress) = self.progress.as_mut() {
                progress.rebuild(listening, now);
            }
            self.writing = DtmfGenerator::with_tone_at(rate, DtmfTone::default());
            self.dialling.clear();
            if let Some(tone) = self.consent {
                if self.beeps_out.is_some() {
                    self.beeps_out = Some(tone.generator(rate));
                }
                if self.beeps_in.is_some() {
                    self.beeps_in = Some(tone.generator(rate));
                }
            }
        }
        self.events = events;
        self.arm_detector();
    }

    /// Build the digit detector when the mode and the negotiation call for
    /// one, and drop it when they no longer do.
    fn arm_detector(&mut self) {
        let wanted = match self.detection {
            DtmfDetection::Off => false,
            DtmfDetection::Auto => !self.events,
            DtmfDetection::Always => true,
        };
        if !wanted {
            self.dtmf = None;
            self.held.clear();
        } else if self.dtmf.is_none() {
            self.dtmf = Some(DtmfDetector::new(self.listener.rate()));
        }
    }

    /// Listen for digits in the far end's audio, or stop.
    pub(crate) fn set_detection(&mut self, detection: DtmfDetection) {
        self.detection = detection;
        self.arm_detector();
    }

    pub(crate) const fn detection(&self) -> DtmfDetection {
        self.detection
    }

    /// Listen for call progress with this configuration, or stop.
    pub(crate) fn set_progress(&mut self, progress: Option<ProgressDetection>) {
        let rate = self.listener.rate();
        self.progress = progress.map(|config| Progress::new(config, rate));
    }

    /// Whether call progress is still being listened for.
    pub(crate) fn is_listening_for_progress(&self) -> bool {
        self.progress
            .as_ref()
            .is_some_and(|progress| !progress.is_done())
    }

    /// The call was answered: who answered is decided from here.
    pub(crate) fn answered(&mut self) {
        let now = self.listener.now();
        let rate = self.listener.rate();
        if let Some(progress) = self.progress.as_mut() {
            progress.answered(rate, now);
        }
    }

    /// One frame of the far end's audio, as it is about to be played.
    pub(crate) fn heard(&mut self, frame: &[i16], events: &mut Outbox) {
        if self.dtmf.is_none() && self.progress.is_none() && self.held.is_empty() {
            return;
        }
        let start = self.listener.samples;
        let clock = self.listener.clock;
        let Self {
            listener,
            dtmf,
            progress,
            held,
            received,
            events: negotiated,
            ..
        } = self;
        let samples = listener.take(frame);
        let count = u64::try_from(samples.len()).unwrap_or(0);
        if let Some(detector) = dtmf.as_mut() {
            let wait = if *negotiated {
                IN_BAND_DIGIT_HOLD
            } else {
                Duration::ZERO
            };
            detector.process(samples, |event| {
                if let DtmfEvent::End { digit, start, end } = event {
                    let press = Press {
                        key: digit.to_char(),
                        start: clock.time(start),
                        end: clock.time(end),
                    };
                    if !received.iter().any(|sent| sent.overlaps(&press)) {
                        held.push_back((press, press.end.saturating_add(wait)));
                    }
                }
            });
        }
        if let Some(listening) = progress.as_mut() {
            listening.hear(samples, clock, start, events);
            if listening.is_done() {
                *progress = None;
            }
        }
        listener.samples = listener.samples.saturating_add(count);
        let now = listener.now();
        while let Some((press, due)) = held.front().copied() {
            if due > now {
                break;
            }
            held.pop_front();
            events.push_back(MediaEvent::DigitReceived {
                digit: Some(press.key),
                event: Key::from_char(press.key).map_or(0, Key::event_code),
                held: Some(press.end.saturating_sub(press.start)),
                source: DigitSource::InBand,
            });
        }
    }

    /// A digit the far end sent as an RFC 4733 event, reported as it ended:
    /// a press heard in the audio as well within [`SAME_PRESS`] of it is the
    /// same press, and is not reported again.
    pub(crate) fn received_event(&mut self, key: Option<char>, held: Duration) {
        let Some(key) = key else {
            return;
        };
        let end = self.listener.now();
        let press = Press {
            key,
            start: end.saturating_sub(held),
            end,
        };
        self.held.retain(|(waiting, _)| !waiting.overlaps(&press));
        if self.received.len() == REMEMBERED {
            self.received.pop_front();
        }
        self.received.push_back(press);
    }

    /// Queue digits to be written into the outgoing audio. All of them or
    /// none.
    pub(crate) fn dial(&mut self, keys: &[char], length: Duration) -> Result<usize, MediaError> {
        if self.dialling.len().saturating_add(keys.len()) > WAITING {
            return Err(MediaError::TooManyDigits);
        }
        let mut digits = Vec::with_capacity(keys.len());
        for &key in keys {
            digits.push(Key::from_char(key).ok_or(MediaError::UnknownDigit { key })?);
        }
        let tone = millis(length);
        self.dialling
            .extend(digits.into_iter().map(|digit| (digit, tone)));
        Ok(keys.len())
    }

    /// Whether a digit is sounding in the outgoing audio or waiting to.
    pub(crate) fn is_dialling(&self) -> bool {
        !self.writing.is_idle() || !self.dialling.is_empty()
    }

    /// How many digits have not started sounding yet.
    pub(crate) fn digits_waiting(&self) -> usize {
        self.dialling.len()
    }

    /// Stop writing digits, the one sounding included.
    pub(crate) fn stop_dialling(&mut self) {
        self.dialling.clear();
        self.writing = DtmfGenerator::with_tone_at(self.rate, DtmfTone::default());
    }

    /// Use this consent tone from now on, or none.
    pub(crate) fn set_consent(&mut self, tone: Option<ConsentTone>, recording: bool) {
        self.consent = tone;
        self.beeps_out = None;
        self.beeps_in = None;
        if recording {
            self.recording_started();
        }
    }

    pub(crate) const fn consent(&self) -> Option<ConsentTone> {
        self.consent
    }

    /// A recording started: the beep sounds at once, and then at its
    /// interval.
    pub(crate) fn recording_started(&mut self) {
        if let Some(tone) = self.consent {
            self.beeps_out = Some(tone.generator(self.rate));
            self.beeps_in = tone.local.then(|| tone.generator(self.rate));
        }
    }

    /// The recording stopped, and the beep with it.
    pub(crate) fn recording_stopped(&mut self) {
        self.beeps_out = None;
        self.beeps_in = None;
    }

    /// What goes to the far end instead of `captured`, if anything changes it: a digit being
    /// written replaces the microphone for its tone and pause, and the consent beep is mixed in.
    /// `false` leaves `shaped` and the frame alone.
    ///
    /// `held_back` is a digit going out as an RFC 4733 event, which an in-band digit waits behind.
    pub(crate) fn shape(
        &mut self,
        captured: &[i16],
        shaped: &mut Vec<i16>,
        held_back: bool,
    ) -> bool {
        let digits = !held_back && self.is_dialling();
        if !digits && self.beeps_out.is_none() {
            return false;
        }
        shaped.clear();
        shaped.extend_from_slice(captured);
        if digits {
            self.write_digits(shaped);
        }
        if let Some(beeps) = self.beeps_out.as_mut() {
            mix_beep(beeps, &mut self.beep_scratch, shaped);
        }
        true
    }

    /// The consent beep into what this end is about to play, when it is to
    /// hear it too.
    pub(crate) fn beep_locally(&mut self, played: &mut [i16]) {
        if let Some(beeps) = self.beeps_in.as_mut() {
            mix_beep(beeps, &mut self.beep_scratch, played);
        }
    }

    fn write_digits(&mut self, out: &mut [i16]) {
        let mut at = 0;
        while at < out.len() {
            if self.writing.is_idle() {
                let Some((digit, tone_ms)) = self.dialling.pop_front() else {
                    break;
                };
                self.writing = DtmfGenerator::with_tone_at(
                    self.rate,
                    DtmfTone {
                        tone_ms,
                        pause_ms: millis(DIGIT_GAP),
                        ..DtmfTone::default()
                    },
                );
                self.writing.start(digit);
            }
            at += self.writing.fill(out.get_mut(at..).unwrap_or_default());
        }
    }
}

/// Add one frame of beeps to `frame`, saturating rather than wrapping, by
/// way of `scratch`, which is kept so that a frame costs no allocation.
fn mix_beep(beeps: &mut ToneGenerator, scratch: &mut Vec<i16>, frame: &mut [i16]) {
    scratch.resize(frame.len(), 0);
    beeps.fill(scratch);
    add_into(frame, scratch);
}

#[cfg(test)]
mod tests {
    use super::{
        CallProgress, ConsentTone, DtmfDetection, IN_BAND_DIGIT_HOLD, ProgressDetection, Signals,
    };
    use crate::error::MediaError;
    use crate::event::{DigitSource, MediaEvent};
    use crate::share::Outbox;
    use sipral_media::inband::dtmf::Digit as Key;
    use sipral_media::inband::generate::{DtmfGenerator, DtmfTone, ToneGenerator};
    use sipral_media::inband::progress::{ProgressTone, Region};
    use std::time::Duration;

    /// Play `pcm` through `signals` twenty milliseconds at a time, and give
    /// back what it said.
    fn hear(signals: &mut Signals, pcm: &[i16], rate: u32) -> Vec<MediaEvent> {
        let frame = usize::try_from(rate / 50).unwrap();
        let mut outbox = Outbox::default();
        for chunk in pcm.chunks(frame) {
            signals.heard(chunk, &mut outbox);
        }
        let mut events = Vec::new();
        while let Some(event) = outbox.pop_front() {
            events.push(event);
        }
        events
    }

    fn digits(keys: &str, rate: u32) -> Vec<i16> {
        let mut pcm = vec![0_i16; usize::try_from(rate / 10).unwrap()];
        for key in keys.chars() {
            let mut generator = DtmfGenerator::with_tone_at(rate, DtmfTone::default());
            generator.start(Key::from_char(key).unwrap());
            let mut out = vec![0_i16; generator.remaining()];
            generator.fill(&mut out);
            pcm.extend(out);
        }
        pcm.extend(vec![0_i16; usize::try_from(rate / 2).unwrap()]);
        pcm
    }

    fn heard_keys(events: &[MediaEvent]) -> String {
        events
            .iter()
            .filter_map(|event| match event {
                MediaEvent::DigitReceived {
                    digit: Some(key),
                    source: DigitSource::InBand,
                    ..
                } => Some(*key),
                _ => None,
            })
            .collect()
    }

    /// With no named events negotiated, `Auto` listens, and every digit in
    /// the audio is one press with its length — at every rate a codec here
    /// hears at, Opus's included.
    #[test]
    fn auto_hears_digits_on_a_call_with_no_named_events_at_every_rate() {
        for rate in [8_000, 16_000, 48_000] {
            let mut signals = Signals::new(rate, false, DtmfDetection::Auto, None, None);
            let events = hear(&mut signals, &digits("147*#0", rate), rate);
            assert_eq!(heard_keys(&events), "147*#0", "{rate} Hz");
            for event in events {
                if let MediaEvent::DigitReceived {
                    held: Some(held),
                    event,
                    digit,
                    ..
                } = event
                {
                    assert!(
                        held.as_millis().abs_diff(100) <= 5,
                        "{rate} Hz: {digit:?} held {held:?}"
                    );
                    let key = Key::from_char(digit.unwrap()).unwrap();
                    assert_eq!(event, key.event_code());
                }
            }
        }
    }

    #[test]
    fn auto_does_not_listen_where_named_events_were_negotiated_and_off_never_does() {
        let mut negotiated = Signals::new(8_000, true, DtmfDetection::Auto, None, None);
        assert!(hear(&mut negotiated, &digits("5", 8_000), 8_000).is_empty());
        let mut off = Signals::new(8_000, false, DtmfDetection::Off, None, None);
        assert!(hear(&mut off, &digits("5", 8_000), 8_000).is_empty());
        let mut always = Signals::new(8_000, true, DtmfDetection::Always, None, None);
        assert_eq!(
            heard_keys(&hear(&mut always, &digits("5", 8_000), 8_000)),
            "5"
        );
    }

    /// `Always` on a call with named events: a press the far end also sent
    /// as an event is reported once, whichever of the two came first, and a
    /// press it sent only in the audio still is.
    #[test]
    fn a_press_heard_both_ways_is_one_press() {
        let rate = 8_000;
        let pcm = digits("9", rate);
        // the event reported before the audio was heard
        let mut early = Signals::new(rate, true, DtmfDetection::Always, None, None);
        let mut outbox = Outbox::default();
        let frame = usize::try_from(rate / 50).unwrap();
        let mut chunks = pcm.chunks(frame);
        // a hundred milliseconds of silence and five of tone
        for chunk in chunks.by_ref().take(10) {
            early.heard(chunk, &mut outbox);
        }
        early.received_event(Some('9'), Duration::from_millis(60));
        for chunk in chunks {
            early.heard(chunk, &mut outbox);
        }
        assert!(outbox.pop_front().is_none(), "the press was reported twice");

        // and after: the digit is held back, and the event takes it away
        let mut late = Signals::new(rate, true, DtmfDetection::Always, None, None);
        let mut outbox = Outbox::default();
        let tone_end = frame * 5 + usize::try_from(rate / 10).unwrap();
        let mut at = 0;
        while at < tone_end + frame * 4 {
            late.heard(&pcm[at..at + frame], &mut outbox);
            at += frame;
        }
        late.received_event(Some('9'), Duration::from_millis(100));
        while at + frame <= pcm.len() {
            late.heard(&pcm[at..at + frame], &mut outbox);
            at += frame;
        }
        assert!(outbox.pop_front().is_none(), "the press was reported twice");

        // a different key sent as an event takes nothing away
        let mut other = Signals::new(rate, true, DtmfDetection::Always, None, None);
        let mut outbox = Outbox::default();
        let mut at = 0;
        while at < tone_end {
            other.heard(&pcm[at..at + frame], &mut outbox);
            at += frame;
        }
        other.received_event(Some('3'), Duration::from_millis(100));
        while at + frame <= pcm.len() {
            other.heard(&pcm[at..at + frame], &mut outbox);
            at += frame;
        }
        let mut events = Vec::new();
        while let Some(event) = outbox.pop_front() {
            events.push(event);
        }
        assert_eq!(heard_keys(&events), "9");
    }

    /// A digit heard in the audio on a call with named events waits out the
    /// window before it is reported, and not much longer.
    #[test]
    fn a_digit_heard_beside_named_events_waits_out_the_window() {
        let rate = 8_000;
        let pcm = digits("2", rate);
        let frame = usize::try_from(rate / 50).unwrap();
        let mut signals = Signals::new(rate, true, DtmfDetection::Always, None, None);
        let mut outbox = Outbox::default();
        let mut reported_at = None;
        for (index, chunk) in pcm.chunks(frame).enumerate() {
            signals.heard(chunk, &mut outbox);
            if reported_at.is_none() && outbox.pop_front().is_some() {
                reported_at = Some(index);
            }
        }
        // the tone ends at 200 ms (100 ms of lead-in and 100 of tone); the
        // report comes once the window after it has been heard
        let at_ms = u64::try_from(reported_at.expect("reported") * 20 + 20).unwrap();
        let due = 200 + u64::try_from(IN_BAND_DIGIT_HOLD.as_millis()).unwrap();
        assert!(at_ms >= due && at_ms <= due + 80, "reported at {at_ms} ms");
    }

    /// Digits written into the outgoing audio replace the microphone for
    /// their tone and pause, and are the digits a detector hears.
    #[test]
    fn digits_written_out_replace_the_microphone_and_are_heard_as_themselves() {
        for rate in [8_000, 16_000, 48_000] {
            let mut sender = Signals::new(rate, false, DtmfDetection::Off, None, None);
            assert_eq!(
                sender.dial(&['1', '#', 'd'], Duration::from_millis(80)),
                Ok(3)
            );
            assert!(sender.is_dialling());
            assert_eq!(sender.digits_waiting(), 3);
            let frame = usize::try_from(rate / 50).unwrap();
            let microphone = vec![1_000_i16; frame];
            let mut sent = Vec::new();
            let mut shaped = Vec::new();
            for _ in 0..40 {
                if sender.shape(&microphone, &mut shaped, false) {
                    sent.extend_from_slice(&shaped);
                } else {
                    sent.extend_from_slice(&microphone);
                }
            }
            assert!(!sender.is_dialling());
            // three digits of 80 ms and three pauses of 60 ms, then the
            // microphone again
            let written = 3 * 140 * usize::try_from(rate / 1_000).unwrap();
            assert!(sent[written..].iter().all(|&sample| sample == 1_000));
            let mut listener = Signals::new(rate, false, DtmfDetection::Auto, None, None);
            let quiet: Vec<i16> = sent[..written].to_vec();
            let mut padded = quiet;
            padded.extend(vec![0_i16; usize::try_from(rate / 2).unwrap()]);
            assert_eq!(
                heard_keys(&hear(&mut listener, &padded, rate)),
                "1#D",
                "{rate}"
            );
        }
    }

    #[test]
    fn a_digit_waits_behind_one_going_out_as_an_event_and_stopping_drops_them_all() {
        let mut sender = Signals::new(8_000, true, DtmfDetection::Off, None, None);
        sender.dial(&['5'], Duration::from_millis(100)).unwrap();
        let microphone = vec![7_i16; 160];
        let mut shaped = Vec::new();
        assert!(
            !sender.shape(&microphone, &mut shaped, true),
            "sounded under an event"
        );
        assert!(sender.shape(&microphone, &mut shaped, false));
        sender.stop_dialling();
        assert!(!sender.is_dialling());
        assert!(!sender.shape(&microphone, &mut shaped, false));
        assert_eq!(
            sender.dial(&['5', 'x'], Duration::from_millis(100)),
            Err(MediaError::UnknownDigit { key: 'x' })
        );
        assert_eq!(sender.digits_waiting(), 0, "half a dial string was queued");
    }

    fn tone_of(region: Region, tone: ProgressTone, rate: u32, seconds: u32) -> Vec<i16> {
        let spec = region
            .tones()
            .iter()
            .find(|spec| spec.tone == tone)
            .unwrap();
        let sample_rate = sipral_media::inband::SampleRate::from_hz(rate).unwrap();
        let mut generator = ToneGenerator::new(sample_rate, spec, -13.0);
        let mut out = vec![0_i16; usize::try_from(rate * seconds).unwrap()];
        generator.fill(&mut out);
        out
    }

    /// A voice-like sample at `t` seconds: a 180 Hz fundamental whose level
    /// a 700 Hz component moves, which the voice activity detector the
    /// answering-machine detector builds on reads as speech.
    fn voiced(t: f64) -> i16 {
        let value = 6_000.0
            * (2.0 * std::f64::consts::PI * 180.0 * t).sin()
            * (1.0 + 0.5 * (2.0 * std::f64::consts::PI * 700.0 * t).sin());
        // at most 9000 either side, well inside the sixteen-bit range
        #[allow(clippy::cast_possible_truncation)]
        let sample = value.round() as i16;
        sample
    }

    fn progress_of(events: &[MediaEvent]) -> Vec<CallProgress> {
        events
            .iter()
            .filter_map(|event| match event {
                MediaEvent::Progress(progress) => Some(*progress),
                _ => None,
            })
            .collect()
    }

    /// Before answer, the network's tones are reported, each once.
    #[test]
    fn busy_on_early_media_is_reported_once() {
        let rate = 8_000;
        let mut signals = Signals::new(
            rate,
            true,
            DtmfDetection::Off,
            Some(ProgressDetection::default()),
            None,
        );
        let busy = tone_of(Region::Europe, ProgressTone::Busy, rate, 6);
        let heard = progress_of(&hear(&mut signals, &busy, rate));
        assert_eq!(heard.len(), 1, "{heard:?}");
        let CallProgress::Tone { tone, at } = heard[0] else {
            panic!("{heard:?}");
        };
        assert_eq!(tone, ProgressTone::Busy);
        assert!(at < Duration::from_millis(50), "{at:?}");
    }

    /// Nothing is listened for unless asked, and with no answering-machine
    /// detection the listening ends at answer.
    #[test]
    fn progress_is_opt_in_and_without_amd_ends_at_answer() {
        let rate = 8_000;
        let busy = tone_of(Region::Europe, ProgressTone::Busy, rate, 4);
        let mut unasked = Signals::new(rate, true, DtmfDetection::Off, None, None);
        assert!(progress_of(&hear(&mut unasked, &busy, rate)).is_empty());

        let mut signals = Signals::new(
            rate,
            true,
            DtmfDetection::Off,
            Some(ProgressDetection {
                answering_machine: None,
                ..ProgressDetection::default()
            }),
            None,
        );
        assert!(signals.is_listening_for_progress());
        signals.answered();
        assert!(!signals.is_listening_for_progress());
        assert!(progress_of(&hear(&mut signals, &busy, rate)).is_empty());
    }

    /// A long greeting after answer is a machine, and its beep is found
    /// after it, timed from answer.
    #[test]
    fn a_long_greeting_is_a_machine_and_its_beep_is_found_after_it() {
        let rate = 8_000;
        let mut signals = Signals::new(
            rate,
            true,
            DtmfDetection::Off,
            Some(ProgressDetection::default()),
            None,
        );
        signals.answered();
        // half a second of silence, four seconds of syllables, a pause, and
        // a 1 kHz beep of 400 ms
        let mut pcm = vec![0_i16; 4_000];
        for n in 0..32_000_u32 {
            let syllable = (n / 1_600) % 2 == 0;
            let value = if syllable {
                voiced(f64::from(n) / 8_000.0)
            } else {
                0
            };
            pcm.push(value);
        }
        pcm.extend(vec![0_i16; 2_400]);
        let beep_start = pcm.len();
        let mut beep = vec![0_i16; 3_200];
        ToneGenerator::beeps(8_000, 1_000.0, 400, 0, -10.0).fill(&mut beep);
        pcm.extend(beep);
        pcm.extend(vec![0_i16; 4_000]);
        let heard = progress_of(&hear(&mut signals, &pcm, rate));
        let verdict = heard.iter().find_map(|progress| match progress {
            CallProgress::AnsweredBy { verdict, .. } => Some(*verdict),
            _ => None,
        });
        assert_eq!(verdict, Some(super::AmdVerdict::Machine), "{heard:?}");
        let beep = heard.iter().find_map(|progress| match progress {
            CallProgress::Beep {
                frequency_hz,
                ended,
                length,
            } => Some((*frequency_hz, *ended, *length)),
            _ => None,
        });
        let (frequency, ended, length) = beep.unwrap_or_else(|| panic!("{heard:?}"));
        assert!((frequency - 1_000.0).abs() < 20.0, "{frequency}");
        let expected_end = Duration::from_millis(u64::try_from((beep_start + 3_200) / 8).unwrap());
        assert!(
            ended.abs_diff(expected_end) < Duration::from_millis(40),
            "{ended:?} against {expected_end:?}"
        );
        assert!(length.abs_diff(Duration::from_millis(400)) < Duration::from_millis(40));
        assert!(!signals.is_listening_for_progress(), "still listening");
    }

    /// A short hello and a wait is a person, and nothing listens after.
    #[test]
    fn a_short_hello_is_a_person() {
        let rate = 16_000;
        let mut signals = Signals::new(
            rate,
            true,
            DtmfDetection::Off,
            Some(ProgressDetection::default()),
            None,
        );
        signals.answered();
        let mut pcm = vec![0_i16; 8_000];
        for n in 0..8_000_u32 {
            pcm.push(voiced(f64::from(n) / 16_000.0));
        }
        pcm.extend(vec![0_i16; 32_000]);
        let heard = progress_of(&hear(&mut signals, &pcm, rate));
        assert!(
            matches!(
                heard.as_slice(),
                [CallProgress::AnsweredBy {
                    verdict: super::AmdVerdict::Human,
                    ..
                }]
            ),
            "{heard:?}"
        );
        assert!(!signals.is_listening_for_progress());
    }

    /// The consent tone sounds at once when a recording starts, both ways
    /// unless told otherwise, and stops with it.
    #[test]
    fn the_consent_beep_starts_with_the_recording_and_stops_with_it() {
        let rate = 8_000;
        let tone = ConsentTone {
            interval: Duration::from_secs(1),
            ..ConsentTone::default()
        };
        assert_eq!(tone.check(), Ok(()));
        let mut signals = Signals::new(rate, true, DtmfDetection::Off, None, Some(tone));
        let silence = vec![0_i16; 160];
        let mut shaped = Vec::new();
        assert!(
            !signals.shape(&silence, &mut shaped, false),
            "beeped before recording"
        );
        signals.recording_started();
        assert!(signals.shape(&silence, &mut shaped, false));
        assert!(
            shaped.iter().any(|&sample| sample != 0),
            "the first beep is not at once"
        );
        let mut played = vec![0_i16; 160];
        signals.beep_locally(&mut played);
        assert!(
            played.iter().any(|&sample| sample != 0),
            "this end did not hear it"
        );
        // 200 ms of beep, then 800 of silence, then the next
        let mut sent = shaped.clone();
        for _ in 1..60 {
            signals.shape(&silence, &mut shaped, false);
            sent.extend_from_slice(&shaped);
        }
        let sounding = |from_ms: usize, to_ms: usize| {
            sent[from_ms * 8..to_ms * 8]
                .iter()
                .any(|&sample| sample != 0)
        };
        assert!(sounding(0, 200));
        assert!(!sounding(200, 1_000));
        assert!(sounding(1_000, 1_200));
        signals.recording_stopped();
        assert!(!signals.shape(&silence, &mut shaped, false));

        let quiet = ConsentTone {
            local: false,
            ..tone
        };
        signals.set_consent(Some(quiet), true);
        let mut played = vec![0_i16; 160];
        signals.beep_locally(&mut played);
        assert!(
            played.iter().all(|&sample| sample == 0),
            "heard where it was not to be"
        );
    }

    #[test]
    fn a_consent_tone_that_is_not_a_beep_is_refused_by_field() {
        let good = ConsentTone::default();
        for (bad, field) in [
            (
                ConsentTone {
                    frequency_hz: 4_000,
                    ..good
                },
                "frequency_hz",
            ),
            (
                ConsentTone {
                    level_dbm0: 0,
                    ..good
                },
                "level_dbm0",
            ),
            (
                ConsentTone {
                    length: Duration::from_millis(10),
                    ..good
                },
                "length",
            ),
            (
                ConsentTone {
                    interval: Duration::from_millis(100),
                    ..good
                },
                "interval",
            ),
        ] {
            let Err(MediaError::ConsentTone(said)) = bad.check() else {
                panic!("{bad:?} was taken");
            };
            assert!(said.contains(field), "{said}");
        }
    }
}
