// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The tone an answering machine plays before it records: "leave your
//! message after the beep".
//!
//! A beep is one sine, somewhere between 400 and 2000 Hz, held steady for a
//! fraction of a second. The machine's own recording starts when it stops,
//! so the end is what a caller leaving a message waits for, and the end is
//! what [`BeepDetector`] reports.
//!
//! # A sine predicts itself
//!
//! One sine of angular frequency `ω` obeys `x[n] = 2cos(ω)·x[n-1] − x[n-2]`
//! exactly. Fitting that one coefficient to a block of audio by least
//! squares gives the frequency, from the coefficient, and how much of the
//! block the rule explains, from what it leaves over. A lone sine leaves
//! nothing but the noise under it; a voice, with a dozen harmonics and
//! formants that move, leaves most of itself. No filter bank, no search
//! over frequency: a few running sums per sample, which is why this
//! detector costs almost nothing beside the others.
//!
//! Two sines close together are the hard case: a digit's pair, 941 and
//! 1209 Hz, is so near one sine to the rule that it leaves only a fortieth
//! of itself over at 8 kHz, and less at 16 kHz, where both frequencies are
//! half as far round the circle. The same rule holds across any stride
//! `s`, `x[n] = 2cos(sω)·x[n-s] − x[n-2s]`, and a stride multiplies the
//! angle between two sines by `s`. So the rule is also fitted across the
//! stride that puts 2 kHz, the top of the band, at half the circle — two
//! samples at 8 kHz, four at 16 — where the same pair leaves a sixth of
//! itself over at either rate. A stride cannot tell a frequency from its
//! mirror images, 800 Hz from 3200 at these strides, and the fit across
//! adjacent samples can, and reads the frequency: both have to explain the
//! block.
//!
//! A block is 10 ms. A beep is a run of blocks each explained this well, at
//! a frequency inside the band, that stay within a narrow drift of where
//! the run began, lasting between [`BeepConfig::min_ms`] and
//! [`BeepConfig::max_ms`]. The last bound matters as much as the first: a
//! continuous tone — a dial tone, a fax's calling tone held — is not a beep.

use super::{SampleRate, count_f64, dbm0_to_power, round_position};

const BLOCK_MS: u32 = 10;

/// The widest stride used: four samples, at 16 kHz.
const MAX_STRIDE: usize = 4;

/// The limits of a [`BeepDetector`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BeepConfig {
    /// The lowest a beep may be, in hertz. Default 400.
    pub min_hz: f64,
    /// The highest a beep may be, in hertz. Default 2000.
    pub max_hz: f64,
    /// The shortest beep, in milliseconds. Default 120: the machines that
    /// beep briefly still hold it longer than a click or a syllable holds a
    /// single frequency.
    pub min_ms: u32,
    /// The longest beep, in milliseconds. Default 3000; anything longer is
    /// a continuous tone.
    pub max_ms: u32,
    /// The least level of a beep, in dBm0. Default −35.
    pub min_level_dbm0: f64,
    /// How much of a block the one-sine rule must explain, across adjacent
    /// samples and across the stride, as the ratio of the block's power to
    /// what the rule leaves over, in dB. Default 15: a sine 25 dB above
    /// white noise clears it, and neither speech nor a digit comes near.
    pub min_prediction_gain_db: f64,
    /// How far each block's frequency may be from the run's first, as a
    /// fraction. Default 0.02: a beep holds its pitch, and a voice gliding
    /// through the same frequency does not.
    pub max_drift: f64,
}

impl Default for BeepConfig {
    fn default() -> Self {
        Self {
            min_hz: 400.0,
            max_hz: 2_000.0,
            min_ms: 120,
            max_ms: 3_000,
            min_level_dbm0: -35.0,
            min_prediction_gain_db: 15.0,
            max_drift: 0.02,
        }
    }
}

/// A beep, reported once it has ended.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Beep {
    /// The first sample of the first block that held it.
    pub start: u64,
    /// The sample after the last block that held it: where the machine's
    /// recording starts.
    pub end: u64,
    /// Its frequency, in hertz, averaged over the beep.
    pub frequency_hz: f64,
}

/// A run of tonal blocks being heard.
#[derive(Clone, Copy, Debug)]
struct Run {
    start: u64,
    blocks: u64,
    first_hz: f64,
    sum_hz: f64,
}

/// Finds answering-machine beeps in one stream.
#[derive(Clone, Debug)]
pub struct BeepDetector {
    config: BeepConfig,
    rate: f64,
    block: usize,
    min_power: f64,
    min_gain: f64,
    /// The stride, in samples, that puts the top of the band at half the
    /// circle.
    stride: usize,
    /// The last `2 × stride` samples, newest first.
    history: [f64; 2 * MAX_STRIDE],
    filled: usize,
    /// Σ x², then for adjacent samples and for the stride in turn
    /// Σ x[n-s]², Σ x[n-s]·(x[n] + x[n-2s]), Σ (x[n] + x[n-2s])².
    sums: [f64; 7],
    blocks_seen: u64,
    run: Option<Run>,
}

impl BeepDetector {
    /// A detector at `rate` with the default limits.
    #[must_use]
    pub fn new(rate: SampleRate) -> Self {
        Self::with_config(rate, BeepConfig::default())
    }

    /// A detector with explicit limits.
    #[must_use]
    pub fn with_config(rate: SampleRate, config: BeepConfig) -> Self {
        Self {
            rate: rate.as_f64(),
            block: rate.samples(BLOCK_MS).max(1),
            stride: match rate {
                SampleRate::Hz8000 => 2,
                SampleRate::Hz16000 => MAX_STRIDE,
            },
            min_power: dbm0_to_power(config.min_level_dbm0),
            min_gain: 10f64.powf(config.min_prediction_gain_db / 10.0),
            config,
            history: [0.0; 2 * MAX_STRIDE],
            filled: 0,
            sums: [0.0; 7],
            blocks_seen: 0,
            run: None,
        }
    }

    /// The limits the detector was built with.
    #[must_use]
    pub const fn config(&self) -> &BeepConfig {
        &self.config
    }

    /// Forget the stream: the next sample is sample zero of a new one.
    pub fn reset(&mut self) {
        self.history = [0.0; 2 * MAX_STRIDE];
        self.filled = 0;
        self.sums = [0.0; 7];
        self.blocks_seen = 0;
        self.run = None;
    }

    /// Listen to `samples`, the next ones of the stream, and report every
    /// beep that ends in them.
    pub fn process(&mut self, samples: &[i16], mut on_beep: impl FnMut(Beep)) {
        for &sample in samples {
            let x = f64::from(sample);
            let back = |n: usize| self.history.get(n - 1).copied().unwrap_or(0.0);
            let (x1, x2) = (back(1), back(2));
            let (xs, x2s) = (back(self.stride), back(2 * self.stride));
            let terms = [
                x * x,
                x1 * x1,
                x1 * (x + x2),
                (x + x2) * (x + x2),
                xs * xs,
                xs * (x + x2s),
                (x + x2s) * (x + x2s),
            ];
            for (sum, term) in self.sums.iter_mut().zip(terms) {
                *sum += term;
            }
            self.history.rotate_right(1);
            if let Some(newest) = self.history.first_mut() {
                *newest = x;
            }
            self.filled += 1;
            if self.filled == self.block {
                let frequency = self.tonal_frequency();
                self.sums = [0.0; 7];
                self.filled = 0;
                self.on_block(frequency, &mut on_beep);
                self.blocks_seen += 1;
            }
        }
    }

    /// The frequency of the block just ended, if one sine explains it.
    fn tonal_frequency(&self) -> Option<f64> {
        let [energy, lagged, cross, outer, lagged_s, cross_s, outer_s] = self.sums;
        if energy / count_f64(self.block) < self.min_power || lagged <= 0.0 || lagged_s <= 0.0 {
            return None;
        }
        // the least-squares coefficient leaves `outer - cross²/lagged` over
        let coefficient = cross / lagged;
        let residual = (outer - cross * coefficient).max(0.0);
        let residual_s = (outer_s - cross_s * cross_s / lagged_s).max(0.0);
        if energy < self.min_gain * residual || energy < self.min_gain * residual_s {
            return None;
        }
        let frequency =
            (coefficient / 2.0).clamp(-1.0, 1.0).acos() * self.rate / (2.0 * std::f64::consts::PI);
        (frequency >= self.config.min_hz && frequency <= self.config.max_hz).then_some(frequency)
    }

    fn on_block(&mut self, frequency: Option<f64>, on_beep: &mut impl FnMut(Beep)) {
        let block_start = self.blocks_seen * u64::try_from(self.block).unwrap_or(u64::MAX);
        let drift = self.config.max_drift;
        match (frequency, self.run.as_mut()) {
            (Some(f), Some(run)) if (f - run.first_hz).abs() <= drift * run.first_hz => {
                run.blocks += 1;
                run.sum_hz += f;
            }
            (Some(f), _) => {
                if let Some(run) = self.run.take() {
                    self.close(run, on_beep);
                }
                self.run = Some(Run {
                    start: block_start,
                    blocks: 1,
                    first_hz: f,
                    sum_hz: f,
                });
            }
            (None, _) => {
                if let Some(run) = self.run.take() {
                    self.close(run, on_beep);
                }
            }
        }
    }

    fn close(&self, run: Run, on_beep: &mut impl FnMut(Beep)) {
        let per_ms = self.rate / 1_000.0;
        let length_ms = position_ms(run.blocks, self.block, per_ms);
        if length_ms < f64::from(self.config.min_ms) || length_ms > f64::from(self.config.max_ms) {
            return;
        }
        let blocks = count_f64(usize::try_from(run.blocks).unwrap_or(usize::MAX));
        on_beep(Beep {
            start: run.start,
            end: run.start + round_position(blocks * count_f64(self.block)),
            frequency_hz: run.sum_hz / blocks,
        });
    }
}

/// `blocks` blocks of `block` samples, in milliseconds.
fn position_ms(blocks: u64, block: usize, per_ms: f64) -> f64 {
    count_f64(usize::try_from(blocks).unwrap_or(usize::MAX)) * count_f64(block) / per_ms
}

#[cfg(test)]
mod tests {
    use super::{Beep, BeepConfig, BeepDetector};
    use crate::inband::SampleRate;
    use crate::inband::dbm0_to_peak;
    use crate::inband::signals::{Rng, mix, pair, silence, sine, span, to_pcm, white};

    const RATES: [SampleRate; 2] = [SampleRate::Hz8000, SampleRate::Hz16000];

    fn listen(rate: SampleRate, signal: &[f64]) -> Vec<Beep> {
        let mut detector = BeepDetector::new(rate);
        let mut beeps = Vec::new();
        for chunk in to_pcm(signal).chunks(100) {
            detector.process(chunk, |b| beeps.push(b));
        }
        beeps
    }

    /// 200 ms of silence, a tone, 200 ms of silence.
    fn beep(rate: SampleRate, hz: f64, ms: f64, dbm0: f64) -> Vec<f64> {
        let fs = rate.hz();
        let mut signal = silence(span(fs, 200.0));
        signal.extend(sine(hz, dbm0_to_peak(dbm0), 0.3, fs, span(fs, ms)));
        signal.extend(silence(span(fs, 200.0)));
        signal
    }

    #[test]
    fn a_beep_is_reported_at_its_end_with_its_frequency() {
        for rate in RATES {
            let per_ms = u64::from(rate.hz() / 1_000);
            for hz in [440.0, 1_000.0, 1_400.0, 1_950.0] {
                let beeps = listen(rate, &beep(rate, hz, 500.0, -15.0));
                assert_eq!(beeps.len(), 1, "{rate:?} {hz}: {beeps:?}");
                let found = beeps[0];
                assert!(
                    (found.frequency_hz - hz).abs() < 0.005 * hz,
                    "{rate:?} {hz}: {found:?}"
                );
                assert!(
                    found.start.abs_diff(200 * per_ms) <= 10 * per_ms,
                    "{rate:?} {found:?}"
                );
                assert!(
                    found.end.abs_diff(700 * per_ms) <= 10 * per_ms,
                    "{rate:?} {found:?}"
                );
            }
        }
    }

    #[test]
    fn a_tone_outside_the_band_is_not_a_beep() {
        for rate in RATES {
            for hz in [300.0, 380.0, 2_050.0, 2_600.0] {
                let beeps = listen(rate, &beep(rate, hz, 500.0, -15.0));
                assert!(beeps.is_empty(), "{rate:?} {hz}: {beeps:?}");
            }
            for hz in [420.0, 1_980.0] {
                assert_eq!(
                    listen(rate, &beep(rate, hz, 500.0, -15.0)).len(),
                    1,
                    "{rate:?} {hz}"
                );
            }
        }
    }

    #[test]
    fn a_click_is_too_short_and_a_held_tone_too_long() {
        for rate in RATES {
            assert!(
                listen(rate, &beep(rate, 1_000.0, 90.0, -15.0)).is_empty(),
                "{rate:?} 90 ms"
            );
            assert_eq!(
                listen(rate, &beep(rate, 1_000.0, 160.0, -15.0)).len(),
                1,
                "{rate:?} 160 ms"
            );
            assert_eq!(
                listen(rate, &beep(rate, 1_000.0, 2_900.0, -15.0)).len(),
                1,
                "{rate:?} 2.9 s"
            );
            assert!(
                listen(rate, &beep(rate, 1_000.0, 3_200.0, -15.0)).is_empty(),
                "{rate:?} 3.2 s"
            );
        }
    }

    #[test]
    fn a_quiet_tone_is_not_a_beep() {
        for rate in RATES {
            assert_eq!(
                listen(rate, &beep(rate, 1_000.0, 500.0, -33.0)).len(),
                1,
                "{rate:?}"
            );
            assert!(
                listen(rate, &beep(rate, 1_000.0, 500.0, -37.0)).is_empty(),
                "{rate:?}"
            );
        }
    }

    #[test]
    fn no_digit_is_a_beep() {
        use crate::inband::dtmf::Digit;
        for rate in RATES {
            let fs = rate.hz();
            for digit in Digit::ALL {
                let (low, high) = digit.frequencies();
                for twist in [0.0, -4.0, 4.0] {
                    let mut signal = silence(span(fs, 100.0));
                    signal.extend(pair(
                        (low, -10.0),
                        (high, -10.0 + twist),
                        fs,
                        span(fs, 500.0),
                    ));
                    signal.extend(silence(span(fs, 100.0)));
                    let beeps = listen(rate, &signal);
                    assert!(beeps.is_empty(), "{rate:?} {digit:?} {twist}: {beeps:?}");
                }
            }
        }
    }

    #[test]
    fn two_tones_the_stride_cannot_tell_apart_are_told_apart_by_adjacent_samples() {
        // 800 and 3200 Hz sit at the same angle across two samples at
        // 8 kHz and across four at 16: to the strided fit they are one sine,
        // and unequal, the adjacent fit alone would read them as one in the
        // band
        for rate in RATES {
            let fs = rate.hz();
            let mut signal = silence(span(fs, 100.0));
            signal.extend(pair((800.0, -12.0), (3_200.0, -18.0), fs, span(fs, 500.0)));
            signal.extend(silence(span(fs, 100.0)));
            let beeps = listen(rate, &signal);
            assert!(beeps.is_empty(), "{rate:?}: {beeps:?}");
        }
    }

    #[test]
    fn a_tone_that_glides_is_not_a_beep() {
        for rate in RATES {
            let fs = rate.hz();
            let len = span(fs, 500.0);
            // 800 to 1200 Hz over half a second: 1.6 Hz a millisecond
            let mut phase = 0.0;
            let mut signal = silence(span(fs, 100.0));
            for n in 0..len {
                let f = 800.0
                    + 400.0 * f64::from(u32::try_from(n).unwrap())
                        / f64::from(u32::try_from(len).unwrap());
                phase += 2.0 * std::f64::consts::PI * f / f64::from(fs);
                signal.push(dbm0_to_peak(-15.0) * phase.sin());
            }
            signal.extend(silence(span(fs, 100.0)));
            assert!(listen(rate, &signal).is_empty(), "{rate:?}");
        }
    }

    #[test]
    fn a_beep_is_heard_through_noise_twenty_five_db_down() {
        let mut rng = Rng::new(9);
        for rate in RATES {
            let mut signal = beep(rate, 1_000.0, 400.0, -15.0);
            let noise = white(&mut rng, -40.0, signal.len());
            mix(&mut signal, &noise);
            assert_eq!(listen(rate, &signal).len(), 1, "{rate:?}");
            let mut signal = beep(rate, 1_000.0, 400.0, -15.0);
            let noise = white(&mut rng, -22.0, signal.len());
            mix(&mut signal, &noise);
            assert!(
                listen(rate, &signal).is_empty(),
                "{rate:?}: seven dB is too little"
            );
        }
    }

    #[test]
    fn a_wider_band_is_honoured_and_reset_forgets_a_beep_half_heard() {
        let rate = SampleRate::Hz8000;
        let config = BeepConfig {
            min_hz: 250.0,
            ..BeepConfig::default()
        };
        let mut detector = BeepDetector::with_config(rate, config);
        let mut beeps = Vec::new();
        detector.process(&to_pcm(&beep(rate, 300.0, 500.0, -15.0)), |b| beeps.push(b));
        assert_eq!(beeps.len(), 1);
        assert!((detector.config().min_hz - 250.0).abs() < f64::EPSILON);
        let signal = to_pcm(&beep(rate, 1_000.0, 500.0, -15.0));
        detector.process(&signal[..4_000], |b| beeps.push(b));
        detector.reset();
        detector.process(&to_pcm(&silence(4_000)), |b| beeps.push(b));
        assert_eq!(beeps.len(), 1);
    }
}
