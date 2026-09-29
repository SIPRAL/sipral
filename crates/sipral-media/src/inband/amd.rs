// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Answering-machine detection: after an outbound call is answered, is a
//! person on the line or a recording?
//!
//! Nothing in the signalling says. What differs is how each speaks first. A
//! person picking up says one or two words — "hello?", "Ann speaking" — and
//! stops, waiting to hear who called. A machine plays a greeting written to
//! be complete without an answer: many words, several seconds of them,
//! before the beep. So the decision is read from the pattern of speech and
//! silence in the first seconds after answer, and nothing else: no words
//! are recognised, and the level only matters to [`Vad`], which this
//! builds on.
//!
//! # The rules
//!
//! The audio is cut into 10 ms frames. A frame is speech when [`Vad`],
//! with no hangover of its own, reads it as speech and it also stands
//! [`AmdConfig::min_speech_above_floor_db`] above the noise floor the
//! [`Vad`] has learned (see below). A run of speech frames at least
//! [`AmdConfig::min_word_ms`] long is a word, and a word ends at a silence
//! of [`AmdConfig::min_word_gap_ms`]. Then, checked every frame, in this
//! order:
//!
//! 1. More than [`AmdConfig::max_words`] words: [`Verdict::Machine`],
//!    [`Reason::TooManyWords`].
//! 2. The greeting, from the first word's start to the latest word's last
//!    frame, longer than [`AmdConfig::max_greeting_ms`]:
//!    [`Verdict::Machine`], [`Reason::LongGreeting`].
//! 3. At least one word, then silence for
//!    [`AmdConfig::silence_after_greeting_ms`]: [`Verdict::Human`],
//!    [`Reason::ShortGreeting`].
//! 4. No word within [`AmdConfig::max_initial_silence_ms`] of answer:
//!    [`Verdict::NotSure`], [`Reason::InitialSilence`]. Some machines wait
//!    before they play, and some people wait before they speak, so silence
//!    alone decides nothing; a caller treats it as its policy says.
//! 5. No verdict within [`AmdConfig::max_decision_ms`] of answer:
//!    [`Verdict::NotSure`], [`Reason::Timeout`].
//!
//! # The defaults
//!
//! Chosen from how people and machines behave, not from a standard, since
//! none sets them. A person's first words take well under a second and a
//! half; the shortest machine greetings, a bare "please leave a message",
//! take about two, so the greeting limit sits at 1.6 s. Four words is more
//! than a person's answer and less than any greeting's. 700 ms of silence
//! is longer than the pauses between the phrases of a recorded greeting
//! and shorter than the silence a person leaves waiting for a reply. A
//! word is at least 120 ms, a syllable's length, so a click or a breath is
//! not one, and 60 ms of silence separates two, less than the pause
//! between words of normal speech. Three seconds without a word is longer
//! than a person takes to bring the phone to their ear, and six seconds
//! is about as long as anyone stays on a line that has not answered them.
//!
//! What the rules cannot see is meaning. A recording that opens with one
//! word and 700 ms of silence — "Hello … you've reached …" — is read as a
//! person, and a person who answers with a long sentence as a machine;
//! the timing is the whole of the evidence, and those two are timed like
//! the other.
//!
//! # The voice activity detector
//!
//! [`Vad`] is built to call a frame speech whenever in doubt, because the
//! jitter buffer and comfort noise it serves lose more by clipping a word
//! than by keeping a pause; so a quiet broadband frame just above its floor
//! is speech to it, which is right for a fricative. Counting words wants
//! the opposite bias — the hiss of a quiet line read as speech half the
//! time runs into one endless word — so a frame counts here only when it
//! also clears the floor by a margin, 6 dB by default. The floor is
//! [`Vad::noise_floor`], learned from the first frame heard: on a call just
//! answered that is almost always the line's silence before anyone speaks,
//! which is what it should learn, and a greeting that starts in the very
//! first frame is heard once the floor has fallen at the first pause, as
//! [`Vad`]'s own docs describe.

use crate::vad::{Activity, Vad};

use super::SampleRate;

const FRAME_MS: u32 = 10;

/// The limits of an [`AnsweringMachineDetector`], in milliseconds and
/// words. The module docs give the reasoning behind each default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmdConfig {
    /// The longest silence after answer before the verdict is
    /// [`Reason::InitialSilence`]. Default 3000.
    pub max_initial_silence_ms: u32,
    /// The longest greeting a person gives. Default 1600.
    pub max_greeting_ms: u32,
    /// The silence after a greeting that says a person is waiting for a
    /// reply. Default 700.
    pub silence_after_greeting_ms: u32,
    /// The most words a person's greeting has. Default 4.
    pub max_words: u32,
    /// The shortest run of speech that is a word. Default 120.
    pub min_word_ms: u32,
    /// The shortest silence that separates two words. Default 60.
    pub min_word_gap_ms: u32,
    /// The longest the decision may take, from answer. Default 6000.
    pub max_decision_ms: u32,
    /// How far above the voice activity detector's noise floor a frame's
    /// power must be to count as speech, in dB. Default 6.
    pub min_speech_above_floor_db: u32,
}

impl Default for AmdConfig {
    fn default() -> Self {
        Self {
            max_initial_silence_ms: 3_000,
            max_greeting_ms: 1_600,
            silence_after_greeting_ms: 700,
            max_words: 4,
            min_word_ms: 120,
            min_word_gap_ms: 60,
            max_decision_ms: 6_000,
            min_speech_above_floor_db: 6,
        }
    }
}

/// Who answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// A person.
    Human,
    /// An answering machine or a voice mailbox.
    Machine,
    /// The evidence does not say.
    NotSure,
}

/// Which rule gave the verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    /// A short greeting, then silence: somebody said hello and is waiting.
    ShortGreeting,
    /// More words than a person answers with.
    TooManyWords,
    /// A greeting longer than a person gives.
    LongGreeting,
    /// Nobody spoke.
    InitialSilence,
    /// No rule decided in the time allowed.
    Timeout,
}

/// The decision, and what it was made from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmdResult {
    /// Who answered.
    pub verdict: Verdict,
    /// Why the detector thinks so.
    pub reason: Reason,
    /// The sample, counted from answer, whose frame decided.
    pub at: u64,
    /// How long after answer the first word began, or how long the silence
    /// had lasted if none did, in milliseconds.
    pub initial_silence_ms: u32,
    /// How long the greeting was, first word's start to last word's end, in
    /// milliseconds; zero without a word.
    pub greeting_ms: u32,
    /// How many words were heard.
    pub words: u32,
}

/// Decides, for one outbound call, whether a person or a machine answered.
/// Fed the call's inbound audio from the moment of answer.
#[derive(Clone, Debug)]
pub struct AnsweringMachineDetector {
    config: AmdConfig,
    vad: Vad,
    frame: Vec<i16>,
    frame_len: usize,
    frames: u64,
    speech_run: u64,
    silence_run: u64,
    in_word: bool,
    words: u32,
    greeting_start: Option<u64>,
    last_word_frame: u64,
    result: Option<AmdResult>,
}

impl AnsweringMachineDetector {
    /// A detector at `rate` with the default limits.
    #[must_use]
    pub fn new(rate: SampleRate) -> Self {
        Self::with_config(rate, AmdConfig::default())
    }

    /// A detector with explicit limits.
    #[must_use]
    pub fn with_config(rate: SampleRate, config: AmdConfig) -> Self {
        let frame_len = rate.samples(FRAME_MS).max(2);
        Self {
            config,
            vad: Vad::with_hangover_ms(rate.hz(), 0),
            frame: Vec::with_capacity(frame_len),
            frame_len,
            frames: 0,
            speech_run: 0,
            silence_run: 0,
            in_word: false,
            words: 0,
            greeting_start: None,
            last_word_frame: 0,
            result: None,
        }
    }

    /// The limits the detector was built with.
    #[must_use]
    pub const fn config(&self) -> &AmdConfig {
        &self.config
    }

    /// The decision, once there is one.
    #[must_use]
    pub const fn result(&self) -> Option<AmdResult> {
        self.result
    }

    /// Start over for a new call.
    pub fn reset(&mut self) {
        self.vad.reset();
        self.frame.clear();
        self.frames = 0;
        self.speech_run = 0;
        self.silence_run = 0;
        self.in_word = false;
        self.words = 0;
        self.greeting_start = None;
        self.last_word_frame = 0;
        self.result = None;
    }

    /// Listen to `samples`, the next of the call's inbound audio. Returns
    /// the decision once one has been made, on this call and every later
    /// one; audio after the decision is not looked at.
    pub fn process(&mut self, samples: &[i16]) -> Option<AmdResult> {
        for &sample in samples {
            if self.result.is_some() {
                break;
            }
            self.frame.push(sample);
            if self.frame.len() == self.frame_len {
                let activity = self.vad.process(&self.frame);
                let speech = activity == Activity::Speech && self.clears_floor();
                self.frame.clear();
                self.on_frame(speech);
            }
        }
        self.result
    }

    /// Whether the frame's power clears the floor by the margin.
    fn clears_floor(&self) -> bool {
        let power: f64 = self
            .frame
            .iter()
            .map(|&s| f64::from(s) * f64::from(s))
            .sum::<f64>()
            / super::count_f64(self.frame.len().max(1));
        let floor = f64::from(i32::try_from(self.vad.noise_floor()).unwrap_or(i32::MAX));
        power >= floor * 10f64.powf(f64::from(self.config.min_speech_above_floor_db) / 10.0)
    }

    fn frames_for(ms: u32) -> u64 {
        u64::from(ms.div_ceil(FRAME_MS))
    }

    fn on_frame(&mut self, speech: bool) {
        let frame = self.frames;
        self.frames += 1;
        let gap = Self::frames_for(self.config.min_word_gap_ms);
        if speech {
            self.silence_run = 0;
            self.speech_run += 1;
            if self.in_word {
                self.last_word_frame = frame;
            } else if self.speech_run >= Self::frames_for(self.config.min_word_ms).max(1) {
                self.in_word = true;
                self.words += 1;
                self.last_word_frame = frame;
                if self.greeting_start.is_none() {
                    self.greeting_start = Some(frame + 1 - self.speech_run);
                }
            }
        } else {
            self.silence_run += 1;
            if self.silence_run >= gap {
                // a word has ended, or a click too short to be one is
                // forgotten
                self.in_word = false;
                self.speech_run = 0;
            }
        }
        self.decide();
    }

    fn decide(&mut self) {
        let config = self.config;
        let elapsed = self.frames;
        let greeting = self
            .greeting_start
            .map_or(0, |start| self.last_word_frame + 1 - start);
        let decision = if self.words > config.max_words {
            Some((Verdict::Machine, Reason::TooManyWords))
        } else if greeting > Self::frames_for(config.max_greeting_ms) {
            Some((Verdict::Machine, Reason::LongGreeting))
        } else if self.words > 0
            && self.silence_run >= Self::frames_for(config.silence_after_greeting_ms)
        {
            Some((Verdict::Human, Reason::ShortGreeting))
        } else if self.greeting_start.is_none()
            && elapsed >= Self::frames_for(config.max_initial_silence_ms)
        {
            Some((Verdict::NotSure, Reason::InitialSilence))
        } else if elapsed >= Self::frames_for(config.max_decision_ms) {
            Some((Verdict::NotSure, Reason::Timeout))
        } else {
            None
        };
        if let Some((verdict, reason)) = decision {
            let ms = |frames: u64| u32::try_from(frames * u64::from(FRAME_MS)).unwrap_or(u32::MAX);
            self.result = Some(AmdResult {
                verdict,
                reason,
                at: elapsed * u64::try_from(self.frame_len).unwrap_or(u64::MAX),
                initial_silence_ms: ms(self.greeting_start.unwrap_or(elapsed)),
                greeting_ms: ms(greeting),
                words: self.words,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AmdConfig, AmdResult, AnsweringMachineDetector, Reason, Verdict};
    use crate::inband::SampleRate;
    use crate::inband::signals::{Rng, mix, span, syllable, to_pcm, white};

    const RATES: [SampleRate; 2] = [SampleRate::Hz8000, SampleRate::Hz16000];

    /// What a stretch of the line holds.
    #[derive(Clone, Copy)]
    enum Part {
        Quiet(f64),
        Word(f64),
    }
    use Part::{Quiet, Word};

    /// The parts in order, over a line's background noise at -60 dBm0,
    /// with three seconds more of it after them.
    fn line(rate: SampleRate, parts: &[Part], seed: u64) -> Vec<i16> {
        let hz = rate.hz();
        let mut rng = Rng::new(seed);
        let mut signal = Vec::new();
        for part in parts {
            match *part {
                Quiet(ms) => signal.extend(vec![0.0; span(hz, ms)]),
                Word(ms) => {
                    let level = rng.range(-22.0, -14.0);
                    signal.extend(syllable(&mut rng, hz, ms, level));
                }
            }
        }
        signal.extend(vec![0.0; span(hz, 3_000.0)]);
        let noise = white(&mut rng, -60.0, signal.len());
        mix(&mut signal, &noise);
        to_pcm(&signal)
    }

    fn decide_with(rate: SampleRate, config: AmdConfig, parts: &[Part]) -> Vec<AmdResult> {
        (1..=3)
            .map(|seed| {
                let mut detector = AnsweringMachineDetector::with_config(rate, config);
                let pcm = line(rate, parts, seed);
                let mut result = None;
                for chunk in pcm.chunks(80) {
                    result = detector.process(chunk);
                }
                result.unwrap()
            })
            .collect()
    }

    fn decide(rate: SampleRate, parts: &[Part]) -> Vec<AmdResult> {
        decide_with(rate, AmdConfig::default(), parts)
    }

    fn assert_all(results: &[AmdResult], verdict: Verdict, reason: Reason, context: &str) {
        for result in results {
            assert_eq!(
                (result.verdict, result.reason),
                (verdict, reason),
                "{context}: {result:?}"
            );
        }
    }

    fn ms(rate: SampleRate, samples: u64) -> f64 {
        f64::from(u32::try_from(samples).unwrap()) * 1_000.0 / f64::from(rate.hz())
    }

    #[test]
    fn hello_then_silence_is_a_person() {
        for rate in RATES {
            let results = decide(rate, &[Quiet(500.0), Word(450.0)]);
            assert_all(
                &results,
                Verdict::Human,
                Reason::ShortGreeting,
                &format!("{rate:?}"),
            );
            for result in results {
                assert_eq!(result.words, 1);
                assert!(result.initial_silence_ms.abs_diff(500) <= 30, "{result:?}");
                assert!(result.greeting_ms.abs_diff(450) <= 50, "{result:?}");
                assert!((ms(rate, result.at) - 1_650.0).abs() <= 60.0, "{result:?}");
            }
        }
    }

    #[test]
    fn a_name_after_hello_is_still_a_person() {
        for rate in RATES {
            let results = decide(
                rate,
                &[Quiet(400.0), Word(250.0), Quiet(120.0), Word(350.0)],
            );
            assert_all(
                &results,
                Verdict::Human,
                Reason::ShortGreeting,
                &format!("{rate:?}"),
            );
            assert!(results.iter().all(|r| r.words == 2), "{results:?}");
        }
    }

    fn words(count: usize, word: f64, gap: f64) -> Vec<Part> {
        let mut parts = vec![Quiet(300.0)];
        for _ in 0..count {
            parts.push(Word(word));
            parts.push(Quiet(gap));
        }
        parts
    }

    #[test]
    fn a_greeting_of_many_words_is_a_machine() {
        for rate in RATES {
            let results = decide(rate, &words(8, 180.0, 100.0));
            assert_all(
                &results,
                Verdict::Machine,
                Reason::TooManyWords,
                &format!("{rate:?}"),
            );
            assert!(results.iter().all(|r| r.words == 5), "{results:?}");
        }
    }

    #[test]
    fn four_words_and_silence_are_a_person_and_five_are_a_machine() {
        for rate in RATES {
            let results = decide(rate, &words(4, 180.0, 100.0));
            assert_all(
                &results,
                Verdict::Human,
                Reason::ShortGreeting,
                &format!("{rate:?} 4"),
            );
            let results = decide(rate, &words(5, 180.0, 100.0));
            assert_all(
                &results,
                Verdict::Machine,
                Reason::TooManyWords,
                &format!("{rate:?} 5"),
            );
        }
    }

    #[test]
    fn a_long_greeting_is_a_machine_and_a_greeting_just_short_of_it_is_not() {
        for rate in RATES {
            let results = decide(
                rate,
                &[Quiet(300.0), Word(900.0), Quiet(150.0), Word(900.0)],
            );
            assert_all(
                &results,
                Verdict::Machine,
                Reason::LongGreeting,
                &format!("{rate:?}"),
            );
            assert!(results.iter().all(|r| r.words == 2), "{results:?}");
            let results = decide(rate, &[Quiet(300.0), Word(1_750.0)]);
            assert_all(
                &results,
                Verdict::Machine,
                Reason::LongGreeting,
                &format!("{rate:?} 1.75 s"),
            );
            let results = decide(rate, &[Quiet(300.0), Word(1_450.0)]);
            assert_all(
                &results,
                Verdict::Human,
                Reason::ShortGreeting,
                &format!("{rate:?} 1.45 s"),
            );
        }
    }

    #[test]
    fn a_pause_inside_a_greeting_is_not_the_silence_after_it() {
        for rate in RATES {
            // 600 ms is a pause; the greeting goes on, and is short enough
            let results = decide(
                rate,
                &[Quiet(300.0), Word(300.0), Quiet(600.0), Word(300.0)],
            );
            assert_all(
                &results,
                Verdict::Human,
                Reason::ShortGreeting,
                &format!("{rate:?} 600"),
            );
            assert!(results.iter().all(|r| r.words == 2), "{results:?}");
            // 800 ms is the silence after it; the second word comes too late
            let results = decide(
                rate,
                &[Quiet(300.0), Word(300.0), Quiet(800.0), Word(300.0)],
            );
            assert_all(
                &results,
                Verdict::Human,
                Reason::ShortGreeting,
                &format!("{rate:?} 800"),
            );
            assert!(results.iter().all(|r| r.words == 1), "{results:?}");
        }
    }

    #[test]
    fn silence_after_answer_decides_nothing_and_says_so() {
        for rate in RATES {
            let results = decide(rate, &[Quiet(3_500.0), Word(400.0)]);
            assert_all(
                &results,
                Verdict::NotSure,
                Reason::InitialSilence,
                &format!("{rate:?}"),
            );
            for result in results {
                assert!((ms(rate, result.at) - 3_000.0).abs() <= 10.0, "{result:?}");
                assert_eq!((result.words, result.greeting_ms), (0, 0));
            }
            let results = decide(rate, &[Quiet(2_700.0), Word(400.0)]);
            assert_all(
                &results,
                Verdict::Human,
                Reason::ShortGreeting,
                &format!("{rate:?} 2.7 s"),
            );
        }
    }

    #[test]
    fn a_click_is_not_a_word_and_two_bursts_close_together_are_one() {
        for rate in RATES {
            let results = decide(rate, &[Quiet(500.0), Word(60.0), Quiet(3_000.0)]);
            assert_all(
                &results,
                Verdict::NotSure,
                Reason::InitialSilence,
                &format!("{rate:?} click"),
            );
            let results = decide(rate, &[Quiet(500.0), Word(200.0), Quiet(30.0), Word(200.0)]);
            assert!(
                results.iter().all(|r| r.words == 1),
                "{rate:?} 30 ms apart: {results:?}"
            );
            let results = decide(
                rate,
                &[Quiet(500.0), Word(200.0), Quiet(150.0), Word(200.0)],
            );
            assert!(
                results.iter().all(|r| r.words == 2),
                "{rate:?} 150 ms apart: {results:?}"
            );
        }
    }

    #[test]
    fn no_verdict_in_the_time_allowed_is_a_timeout() {
        let config = AmdConfig {
            max_decision_ms: 2_000,
            ..AmdConfig::default()
        };
        for rate in RATES {
            let parts = [Quiet(1_500.0), Word(300.0), Quiet(400.0), Word(300.0)];
            let results = decide_with(rate, config, &parts);
            assert_all(
                &results,
                Verdict::NotSure,
                Reason::Timeout,
                &format!("{rate:?}"),
            );
            for result in results {
                assert!((ms(rate, result.at) - 2_000.0).abs() <= 10.0, "{result:?}");
            }
        }
    }

    #[test]
    fn the_decision_stands_and_reset_starts_a_new_call() {
        let rate = SampleRate::Hz8000;
        let mut detector = AnsweringMachineDetector::new(rate);
        let first = detector
            .process(&line(rate, &[Quiet(400.0), Word(400.0)], 1))
            .unwrap();
        assert_eq!(first.verdict, Verdict::Human);
        let again = detector.process(&line(rate, &words(8, 180.0, 100.0), 1));
        assert_eq!(
            again,
            Some(first),
            "audio after the decision is not looked at"
        );
        assert_eq!(detector.result(), Some(first));
        detector.reset();
        assert_eq!(detector.result(), None);
        let second = detector
            .process(&line(rate, &words(8, 180.0, 100.0), 1))
            .unwrap();
        assert_eq!(second.verdict, Verdict::Machine);
        assert_eq!(detector.config().max_words, 4);
    }
}
