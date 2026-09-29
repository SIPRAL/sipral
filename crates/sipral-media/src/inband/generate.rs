// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Writing tones into a buffer: keypad digits, and the call-progress tones
//! [`progress`](super::progress) describes.
//!
//! Both generators run sines by rotating a unit phasor one step per sample,
//! renormalised as it goes so that its length cannot drift over a tone
//! played for the length of a call, and both write into a caller's slice
//! without allocating once built.
//!
//! # How long a digit sounds
//!
//! RFC 4733 §2.5.2.1 takes its floor from ITU-T Q.24 Table A-1: the
//! switching equipment surveyed there expects a digit of at least 40 ms and
//! a pause between digits of at least 40 ms, so [`MIN_TONE_MS`] and
//! [`MIN_PAUSE_MS`] are those. The defaults are longer, 100 ms of tone and
//! 60 ms of pause, the same the `sipral` crate sends an RFC 4733 event
//! with, so that a digit lasts as long whichever way it leaves.

use std::f64::consts::PI;

use super::dtmf::Digit;
use super::progress::{Cadence, ToneSpec};
use super::{SampleRate, dbm0_to_peak, to_sample};

/// The shortest digit Q.24's surveyed equipment recognises, in
/// milliseconds, as RFC 4733 §2.5.2.1 quotes it.
pub const MIN_TONE_MS: u32 = 40;

/// The shortest pause between digits the same equipment expects.
pub const MIN_PAUSE_MS: u32 = 40;

/// How long a generated digit sounds unless configured otherwise.
pub const DEFAULT_TONE_MS: u32 = 100;

/// The silence held after a generated digit unless configured otherwise.
pub const DEFAULT_PAUSE_MS: u32 = 60;

/// The level of each of a digit's two tones unless configured otherwise,
/// in dBm0: the ten that RFC 4733 §2.3.3's volume field conventionally
/// carries for a generated digit, and what this stack sends.
pub const DEFAULT_DIGIT_DBM0: f64 = -10.0;

/// The level of each frequency of a call-progress tone unless configured
/// otherwise, in dBm0. E.180 Supplement 2 lists each administration's own;
/// this sits among them, and a caller who needs one network's exact level
/// passes it.
pub const DEFAULT_PROGRESS_DBM0: f64 = -13.0;

/// A sine, by rotation of a unit phasor.
#[derive(Clone, Copy, Debug)]
struct Oscillator {
    re: f64,
    im: f64,
    step_re: f64,
    step_im: f64,
    amplitude: f64,
}

impl Oscillator {
    fn new(frequency: f64, amplitude: f64, rate: SampleRate) -> Self {
        let omega = 2.0 * PI * frequency / rate.as_f64();
        Self {
            re: 1.0,
            im: 0.0,
            step_re: omega.cos(),
            step_im: omega.sin(),
            amplitude,
        }
    }

    fn silent() -> Self {
        Self {
            re: 1.0,
            im: 0.0,
            step_re: 1.0,
            step_im: 0.0,
            amplitude: 0.0,
        }
    }

    fn next(&mut self) -> f64 {
        let value = self.amplitude * self.im;
        let re = self.re * self.step_re - self.im * self.step_im;
        let im = self.re * self.step_im + self.im * self.step_re;
        // one Newton step toward unit length: the error it leaves is the
        // square of the one it found, so the phasor stays on the circle
        let fix = 1.5 - 0.5 * (re * re + im * im);
        self.re = re * fix;
        self.im = im * fix;
        value
    }
}

/// How a [`DtmfGenerator`] sounds a digit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DtmfTone {
    /// How long the tone lasts, in milliseconds.
    pub tone_ms: u32,
    /// How long the silence after it lasts, in milliseconds.
    pub pause_ms: u32,
    /// The low-group tone's level, in dBm0.
    pub low_dbm0: f64,
    /// The high-group tone's level, in dBm0.
    pub high_dbm0: f64,
}

impl Default for DtmfTone {
    fn default() -> Self {
        Self {
            tone_ms: DEFAULT_TONE_MS,
            pause_ms: DEFAULT_PAUSE_MS,
            low_dbm0: DEFAULT_DIGIT_DBM0,
            high_dbm0: DEFAULT_DIGIT_DBM0,
        }
    }
}

/// Sounds one digit at a time: its two tones, then its pause.
#[derive(Clone, Debug)]
pub struct DtmfGenerator {
    rate: SampleRate,
    tone: DtmfTone,
    tone_samples: usize,
    total_samples: usize,
    position: usize,
    low: Oscillator,
    high: Oscillator,
}

impl DtmfGenerator {
    /// A generator at `rate` with the default timing and levels.
    #[must_use]
    pub fn new(rate: SampleRate) -> Self {
        Self::with_tone(rate, DtmfTone::default())
    }

    /// A generator with explicit timing and levels.
    #[must_use]
    pub fn with_tone(rate: SampleRate, tone: DtmfTone) -> Self {
        let tone_samples = rate.samples(tone.tone_ms);
        let total_samples = tone_samples.saturating_add(rate.samples(tone.pause_ms));
        Self {
            rate,
            tone,
            tone_samples,
            total_samples,
            position: total_samples,
            low: Oscillator::silent(),
            high: Oscillator::silent(),
        }
    }

    /// Begin `digit`, abandoning whatever was still sounding.
    pub fn start(&mut self, digit: Digit) {
        let (low, high) = digit.frequencies();
        self.low = Oscillator::new(low, dbm0_to_peak(self.tone.low_dbm0), self.rate);
        self.high = Oscillator::new(high, dbm0_to_peak(self.tone.high_dbm0), self.rate);
        self.position = 0;
    }

    /// Whether the last digit, and its pause, have been written in full.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.position >= self.total_samples
    }

    /// How many samples of the current digit and its pause are still to be
    /// written.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.total_samples.saturating_sub(self.position)
    }

    /// Write the next samples of the current digit and its pause into the
    /// start of `out`. Returns how many were written: all of `out`, or
    /// fewer when the pause ends inside it, in which case the rest of `out`
    /// is left as it was.
    pub fn fill(&mut self, out: &mut [i16]) -> usize {
        let count = out.len().min(self.remaining());
        for slot in out.iter_mut().take(count) {
            *slot = if self.position < self.tone_samples {
                to_sample(self.low.next() + self.high.next())
            } else {
                0
            };
            self.position += 1;
        }
        count
    }
}

/// One stretch of a cadence: which frequencies sound, for how long, and
/// how long the silence after them lasts, in samples.
#[derive(Clone, Debug)]
struct Stretch {
    frequencies: Vec<f64>,
    on: usize,
    off: usize,
}

/// Plays a call-progress tone for as long as it is asked to: a
/// [`ToneSpec`]'s frequencies to its cadence, or the special information
/// tone's three frequencies in turn.
#[derive(Clone, Debug)]
pub struct ToneGenerator {
    rate: SampleRate,
    amplitude: f64,
    stretches: Vec<Stretch>,
    index: usize,
    position: usize,
    oscillators: Vec<Oscillator>,
}

impl ToneGenerator {
    /// A generator for `spec`, each frequency at `dbm0`.
    #[must_use]
    pub fn new(rate: SampleRate, spec: &ToneSpec, dbm0: f64) -> Self {
        let frequencies = spec.frequencies.to_vec();
        let stretches = match spec.cadence {
            // a second at a time, played back to back: the oscillators run
            // on across the seam, so a continuous tone has none
            Cadence::Continuous => vec![Stretch {
                frequencies,
                on: rate.samples(1_000),
                off: 0,
            }],
            Cadence::Repeating(bursts) => bursts
                .iter()
                .map(|b| Stretch {
                    frequencies: frequencies.clone(),
                    on: rate.samples(b.on_ms),
                    off: rate.samples(b.off_ms),
                })
                .collect(),
        };
        Self::from_stretches(rate, stretches, dbm0)
    }

    /// The special information tone: `frequencies[i]` for `durations_ms[i]`,
    /// the three back to back, then [`SIT_SILENCE_MS`] of silence, over and
    /// over. [`SIT_FREQUENCIES`] and [`SIT_DURATION_MS`] are E.180's.
    ///
    /// [`SIT_SILENCE_MS`]: super::progress::SIT_SILENCE_MS
    /// [`SIT_FREQUENCIES`]: super::progress::SIT_FREQUENCIES
    /// [`SIT_DURATION_MS`]: super::progress::SIT_DURATION_MS
    #[must_use]
    pub fn special_information(
        rate: SampleRate,
        frequencies: [f64; 3],
        durations_ms: [u32; 3],
        dbm0: f64,
    ) -> Self {
        let last = frequencies.len() - 1;
        let stretches = frequencies
            .iter()
            .zip(durations_ms)
            .enumerate()
            .map(|(i, (&frequency, ms))| Stretch {
                frequencies: vec![frequency],
                on: rate.samples(ms),
                off: if i == last {
                    rate.samples(super::progress::SIT_SILENCE_MS)
                } else {
                    0
                },
            })
            .collect();
        Self::from_stretches(rate, stretches, dbm0)
    }

    fn from_stretches(rate: SampleRate, stretches: Vec<Stretch>, dbm0: f64) -> Self {
        let most = stretches
            .iter()
            .map(|s| s.frequencies.len())
            .max()
            .unwrap_or(0);
        let mut generator = Self {
            rate,
            amplitude: dbm0_to_peak(dbm0),
            stretches,
            index: 0,
            position: 0,
            oscillators: vec![Oscillator::silent(); most],
        };
        generator.tune();
        generator
    }

    /// Start the cadence again from its first burst.
    pub fn reset(&mut self) {
        self.index = 0;
        self.position = 0;
        for oscillator in &mut self.oscillators {
            *oscillator = Oscillator::silent();
        }
        self.tune();
    }

    /// Set the oscillators to the current stretch's frequencies, leaving
    /// any whose frequency does not change running where it is.
    fn tune(&mut self) {
        let Some(stretch) = self.stretches.get(self.index) else {
            return;
        };
        for (i, oscillator) in self.oscillators.iter_mut().enumerate() {
            match stretch.frequencies.get(i) {
                Some(&f) => {
                    let wanted = Oscillator::new(f, self.amplitude, self.rate);
                    let same = (wanted.step_re - oscillator.step_re).abs() < 1e-12
                        && (wanted.step_im - oscillator.step_im).abs() < 1e-12
                        && oscillator.amplitude > 0.0;
                    if !same {
                        *oscillator = wanted;
                    }
                }
                None => *oscillator = Oscillator::silent(),
            }
        }
    }

    /// Fill all of `out` with the next samples of the tone.
    pub fn fill(&mut self, out: &mut [i16]) {
        for slot in out.iter_mut() {
            let Some(stretch) = self.stretches.get(self.index) else {
                *slot = 0;
                continue;
            };
            let (on, length) = (stretch.on, stretch.on.saturating_add(stretch.off));
            *slot = if self.position < on {
                to_sample(self.oscillators.iter_mut().map(Oscillator::next).sum())
            } else {
                0
            };
            self.position += 1;
            if self.position >= length {
                self.position = 0;
                self.index = (self.index + 1) % self.stretches.len().max(1);
                self.tune();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DtmfGenerator, DtmfTone, Oscillator, ToneGenerator};
    use crate::inband::dtmf::{Digit, DtmfDetector, DtmfEvent};
    use crate::inband::progress::{Region, SIT_DURATION_MS, SIT_FREQUENCIES, SIT_SILENCE_MS};
    use crate::inband::{SampleRate, dbm0_to_power, power_to_dbm0};

    const RATES: [SampleRate; 2] = [SampleRate::Hz8000, SampleRate::Hz16000];

    fn mean_square(samples: &[i16]) -> f64 {
        let sum: f64 = samples.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
        sum / f64::from(u32::try_from(samples.len()).unwrap())
    }

    #[test]
    fn an_oscillator_holds_its_level_over_an_hour() {
        let mut oscillator = Oscillator::new(425.0, 1.0, SampleRate::Hz8000);
        for _ in 0..(8_000 * 3_600) {
            oscillator.next();
        }
        let length = oscillator.re.hypot(oscillator.im);
        assert!((length - 1.0).abs() < 1e-9, "{length}");
    }

    #[test]
    fn an_oscillator_knocked_off_its_circle_returns_to_it() {
        let mut oscillator = Oscillator::new(1_336.0, 1.0, SampleRate::Hz8000);
        oscillator.re = 1.01;
        for _ in 0..8 {
            oscillator.next();
        }
        let length = oscillator.re.hypot(oscillator.im);
        assert!((length - 1.0).abs() < 1e-12, "{length}");
    }

    /// Amplitude of the component of `samples` at `frequency`, by
    /// correlation over a whole number of its periods or near enough.
    fn amplitude_at(samples: &[i16], frequency: f64, rate: SampleRate) -> f64 {
        let step = 2.0 * std::f64::consts::PI * frequency / f64::from(rate.hz());
        let (mut re, mut im) = (0.0, 0.0);
        for (n, &s) in samples.iter().enumerate() {
            let phase = step * f64::from(u32::try_from(n).unwrap());
            re += f64::from(s) * phase.cos();
            im += f64::from(s) * phase.sin();
        }
        2.0 * re.hypot(im) / f64::from(u32::try_from(samples.len()).unwrap())
    }

    #[test]
    fn each_tone_of_a_digit_sounds_at_its_own_level() {
        use crate::inband::dbm0_to_peak;
        for rate in RATES {
            let mut generator = DtmfGenerator::with_tone(
                rate,
                DtmfTone {
                    tone_ms: 100,
                    pause_ms: 0,
                    low_dbm0: -16.0,
                    high_dbm0: -9.0,
                },
            );
            generator.start(Digit::Nine);
            let mut out = vec![0_i16; generator.remaining()];
            generator.fill(&mut out);
            let (low, high) = Digit::Nine.frequencies();
            for (frequency, dbm0) in [(low, -16.0), (high, -9.0)] {
                let heard = amplitude_at(&out, frequency, rate);
                let error_db = 20.0 * (heard / dbm0_to_peak(dbm0)).log10();
                assert!(error_db.abs() < 0.2, "{rate:?} {frequency}: {error_db} dB");
            }
        }
    }

    #[test]
    fn a_continuous_tone_runs_on_across_the_seconds_it_is_played_in() {
        use crate::inband::dbm0_to_peak;
        use crate::inband::progress::{Cadence, ProgressTone, ToneSpec};
        // a frequency that does not end a second on a whole cycle, so that
        // an oscillator started over at the seam would jump
        static ODD: ToneSpec = ToneSpec {
            tone: ProgressTone::Dial,
            frequencies: &[437.3],
            cadence: Cadence::Continuous,
        };
        let rate = SampleRate::Hz8000;
        let mut out = vec![0_i16; 16_000];
        ToneGenerator::new(rate, &ODD, -13.0).fill(&mut out);
        let amplitude = dbm0_to_peak(-13.0);
        for (n, &s) in out.iter().enumerate() {
            let t = f64::from(u32::try_from(n).unwrap()) / 8_000.0;
            let expected = amplitude * (2.0 * std::f64::consts::PI * 437.3 * t).sin();
            assert!((f64::from(s) - expected).abs() <= 1.5, "sample {n}: {s}");
        }
    }

    #[test]
    fn a_digit_lasts_exactly_its_tone_and_pause_at_its_level() {
        for rate in RATES {
            let mut generator = DtmfGenerator::new(rate);
            assert!(generator.is_idle());
            generator.start(Digit::Five);
            let per_ms = usize::try_from(rate.hz() / 1_000).unwrap();
            assert_eq!(generator.remaining(), 160 * per_ms);
            let mut out = vec![1_i16; 200 * per_ms];
            let written = generator.fill(&mut out);
            assert_eq!(written, 160 * per_ms);
            assert!(generator.is_idle());
            assert!(
                out[100 * per_ms..160 * per_ms].iter().all(|&s| s == 0),
                "the pause"
            );
            assert!(
                out[160 * per_ms..].iter().all(|&s| s == 1),
                "left as it was"
            );
            // two tones at -10 dBm0 each are -7 dBm0 together
            let level = power_to_dbm0(mean_square(&out[..100 * per_ms]));
            assert!(
                (level - (-10.0 + 10.0 * 2f64.log10())).abs() < 0.1,
                "{level}"
            );
            assert_eq!(generator.fill(&mut out), 0);
        }
    }

    #[test]
    fn written_in_pieces_a_digit_is_the_same_digit() {
        let rate = SampleRate::Hz8000;
        let mut whole = DtmfGenerator::new(rate);
        whole.start(Digit::Hash);
        let mut one = vec![0_i16; 1_280];
        whole.fill(&mut one);
        let mut pieces = DtmfGenerator::new(rate);
        pieces.start(Digit::Hash);
        let mut other = vec![0_i16; 1_280];
        let mut at = 0;
        for size in [1, 7, 160, 333, 5, 1_000] {
            let end = (at + size).min(other.len());
            at += pieces.fill(&mut other[at..end]);
        }
        assert_eq!(one, other);
    }

    #[test]
    fn every_generated_digit_is_detected_as_itself_for_as_long_as_it_sounded() {
        for rate in RATES {
            let per_ms = u64::from(rate.hz() / 1_000);
            let mut generator = DtmfGenerator::with_tone(
                rate,
                DtmfTone {
                    tone_ms: 40,
                    pause_ms: 40,
                    low_dbm0: -12.0,
                    high_dbm0: -10.0,
                },
            );
            let mut pcm = Vec::new();
            for digit in Digit::ALL {
                generator.start(digit);
                let mut out = vec![0_i16; generator.remaining()];
                generator.fill(&mut out);
                pcm.extend(out);
            }
            let mut detector = DtmfDetector::new(rate);
            let mut ends = Vec::new();
            detector.process(&pcm, |e| {
                if let DtmfEvent::End { digit, start, end } = e {
                    ends.push((digit, start, end));
                }
            });
            detector.finish(|e| {
                if let DtmfEvent::End { digit, start, end } = e {
                    ends.push((digit, start, end));
                }
            });
            let heard: Vec<Digit> = ends.iter().map(|e| e.0).collect();
            assert_eq!(heard, Digit::ALL, "{rate:?}");
            for (i, &(_, start, end)) in ends.iter().enumerate() {
                let expected = u64::try_from(i).unwrap() * 80 * per_ms;
                assert!(start.abs_diff(expected) <= per_ms, "{rate:?} {i}: {start}");
                assert!(
                    (end - start).abs_diff(40 * per_ms) <= per_ms,
                    "{rate:?} {i}"
                );
            }
        }
    }

    /// Whether each sample is sounding, run-length encoded, in
    /// milliseconds.
    fn runs(samples: &[i16], rate: SampleRate) -> Vec<(bool, u32)> {
        let per_ms = usize::try_from(rate.hz() / 1_000).unwrap();
        let mut out: Vec<(bool, u32)> = Vec::new();
        for chunk in samples.chunks(per_ms) {
            let on = chunk.iter().any(|&s| s != 0);
            match out.last_mut() {
                Some((state, ms)) if *state == on => *ms += 1,
                _ => out.push((on, 1)),
            }
        }
        out
    }

    #[test]
    fn every_table_tone_follows_its_cadence_at_its_level() {
        use crate::inband::progress::Cadence;
        for rate in RATES {
            for region in Region::ALL {
                for spec in region.tones() {
                    let mut generator = ToneGenerator::new(rate, spec, -13.0);
                    let per_ms = usize::try_from(rate.hz() / 1_000).unwrap();
                    let mut out = vec![0_i16; 25_000 * per_ms];
                    generator.fill(&mut out);
                    let seen = runs(&out, rate);
                    match spec.cadence {
                        Cadence::Continuous => {
                            assert_eq!(seen, [(true, 25_000)], "{region:?} {spec:?}");
                        }
                        Cadence::Repeating(bursts) => {
                            let expected: Vec<(bool, u32)> = bursts
                                .iter()
                                .flat_map(|b| [(true, b.on_ms), (false, b.off_ms)])
                                .collect();
                            for (i, run) in seen.iter().take(seen.len() - 1).enumerate() {
                                assert_eq!(
                                    *run,
                                    expected[i % expected.len()],
                                    "{region:?} {spec:?} run {i}"
                                );
                            }
                        }
                    }
                    let first_on = rate.samples(match spec.cadence {
                        Cadence::Continuous => 1_000,
                        Cadence::Repeating(bursts) => bursts[0].on_ms,
                    });
                    let expected = dbm0_to_power(-13.0)
                        * f64::from(u32::try_from(spec.frequencies.len()).unwrap());
                    let level = power_to_dbm0(mean_square(&out[..first_on]));
                    assert!(
                        (level - power_to_dbm0(expected)).abs() < 0.2,
                        "{region:?} {spec:?}: {level}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_special_information_tone_is_three_tones_then_a_second_of_silence() {
        let rate = SampleRate::Hz8000;
        let mut generator =
            ToneGenerator::special_information(rate, SIT_FREQUENCIES, SIT_DURATION_MS, -13.0);
        let mut out = vec![0_i16; 8 * 2 * (3 * 330 + 1_000)];
        generator.fill(&mut out);
        let seen = runs(&out, rate);
        assert_eq!(
            seen,
            [
                (true, 990),
                (false, SIT_SILENCE_MS),
                (true, 990),
                (false, SIT_SILENCE_MS)
            ]
        );
        // and each third is its own frequency: count zero crossings
        let crossings = |part: &[i16]| part.windows(2).filter(|w| (w[0] < 0) != (w[1] < 0)).count();
        let third = 8 * 330;
        assert!(crossings(&out[..third]).abs_diff(2 * 950 * 330 / 1_000) <= 2);
        assert!(crossings(&out[third..2 * third]).abs_diff(2 * 1_400 * 330 / 1_000) <= 2);
        assert!(crossings(&out[2 * third..3 * third]).abs_diff(2 * 1_800 * 330 / 1_000) <= 2);
    }

    #[test]
    fn reset_starts_the_cadence_over() {
        let rate = SampleRate::Hz8000;
        let spec = &Region::Europe.tones()[2];
        let mut generator = ToneGenerator::new(rate, spec, -13.0);
        let mut first = vec![0_i16; 5_000];
        generator.fill(&mut first);
        generator.reset();
        let mut again = vec![0_i16; 5_000];
        generator.fill(&mut again);
        assert_eq!(first, again);
    }
}
