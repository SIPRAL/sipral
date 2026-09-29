// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Synthesised test signals: tones, noise, and something that sounds enough
//! like speech to try to fool a tone detector. Nothing here is recorded;
//! every signal is built from a seed, so every failure reproduces.

use std::f64::consts::PI;

use super::{count_f64, dbm0_to_peak, dbm0_to_power, to_sample};

/// A xorshift generator: small, fast, and the same on every machine.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform in `[0, 1)`.
    pub(crate) fn uniform(&mut self) -> f64 {
        let top = u32::try_from(self.next_u64() >> 32).unwrap_or(0);
        f64::from(top) / 4_294_967_296.0
    }

    pub(crate) fn range(&mut self, low: f64, high: f64) -> f64 {
        low + (high - low) * self.uniform()
    }

    /// Standard normal, by Box and Muller.
    pub(crate) fn gaussian(&mut self) -> f64 {
        let u1 = self.uniform().max(1e-12);
        let u2 = self.uniform();
        (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos()
    }
}

/// Samples in `ms` milliseconds at `rate`, allowing fractions.
pub(crate) fn span(rate: u32, ms: f64) -> usize {
    to_count(f64::from(rate) * ms / 1_000.0)
}

/// A non-negative float rounded to a count.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(crate) fn to_count(value: f64) -> usize {
    value.max(0.0).round() as usize
}

pub(crate) fn silence(len: usize) -> Vec<f64> {
    vec![0.0; len]
}

pub(crate) fn sine(frequency: f64, amplitude: f64, phase: f64, rate: u32, len: usize) -> Vec<f64> {
    let step = 2.0 * PI * frequency / f64::from(rate);
    (0..len)
        .map(|n| amplitude * (phase + step * count_f64(n)).sin())
        .collect()
}

/// Two sines at the given levels in dBm0.
pub(crate) fn pair(low: (f64, f64), high: (f64, f64), rate: u32, len: usize) -> Vec<f64> {
    let mut out = sine(low.0, dbm0_to_peak(low.1), 0.4, rate, len);
    mix(
        &mut out,
        &sine(high.0, dbm0_to_peak(high.1), 1.3, rate, len),
    );
    out
}

pub(crate) fn mix(into: &mut [f64], other: &[f64]) {
    for (a, b) in into.iter_mut().zip(other) {
        *a += b;
    }
}

pub(crate) fn to_pcm(signal: &[f64]) -> Vec<i16> {
    signal.iter().map(|&x| to_sample(x)).collect()
}

/// White Gaussian noise whose mean-square power is that of a sine at
/// `dbm0`.
pub(crate) fn white(rng: &mut Rng, dbm0: f64, len: usize) -> Vec<f64> {
    let rms = dbm0_to_power(dbm0).sqrt();
    (0..len).map(|_| rms * rng.gaussian()).collect()
}

/// Pink noise, by summing sixteen random rows each held for twice as long
/// as the one before and renewed on its own schedule, then scaled to the
/// mean-square power of a sine at `dbm0`.
pub(crate) fn pink(rng: &mut Rng, dbm0: f64, len: usize) -> Vec<f64> {
    let mut rows = [0.0_f64; 16];
    let mut out = Vec::with_capacity(len);
    for n in 1..=len {
        let changed = n.trailing_zeros();
        if let Some(row) = rows.get_mut(usize::try_from(changed).unwrap()) {
            *row = rng.gaussian();
        }
        let sum: f64 = rows.iter().sum::<f64>() + rng.gaussian();
        out.push(sum);
    }
    scale_to(&mut out, dbm0);
    out
}

fn scale_to(signal: &mut [f64], dbm0: f64) {
    let len = count_f64(signal.len().max(1));
    let mean = signal.iter().sum::<f64>() / len;
    for x in signal.iter_mut() {
        *x -= mean;
    }
    let power = signal.iter().map(|x| x * x).sum::<f64>() / len;
    let gain = if power > 0.0 {
        (dbm0_to_power(dbm0) / power).sqrt()
    } else {
        0.0
    };
    for x in signal.iter_mut() {
        *x *= gain;
    }
}

/// First three formants, in hertz, of a handful of vowels.
const VOWELS: [[f64; 3]; 8] = [
    [730.0, 1_090.0, 2_440.0],
    [270.0, 2_290.0, 3_010.0],
    [300.0, 870.0, 2_240.0],
    [530.0, 1_840.0, 2_480.0],
    [570.0, 840.0, 2_410.0],
    [660.0, 1_720.0, 2_410.0],
    [640.0, 1_190.0, 2_390.0],
    [490.0, 1_350.0, 1_690.0],
];

const BANDWIDTHS: [f64; 3] = [80.0, 100.0, 140.0];

fn resonance(frequency: f64, centre: f64, bandwidth: f64) -> f64 {
    let ratio = frequency / centre;
    let re = 1.0 - ratio * ratio;
    let im = frequency * bandwidth / (centre * centre);
    1.0 / re.hypot(im)
}

/// Speech-like audio: syllables of a voiced source, its pitch gliding,
/// shaped by formants that move from one vowel to another, with noisy
/// consonants before some syllables and pauses of varied length between
/// them. Levels vary by syllable around `dbm0`.
pub(crate) fn speech(rng: &mut Rng, rate: u32, seconds: f64, dbm0: f64) -> Vec<f64> {
    let total = span(rate, seconds * 1_000.0);
    let fs = f64::from(rate);
    let nyquist = fs / 2.0;
    let mut out = Vec::with_capacity(total);
    while out.len() < total {
        if rng.uniform() < 0.3 {
            let len = span(rate, rng.range(30.0, 90.0));
            let level = dbm0 - rng.range(8.0, 16.0);
            let burst = white(rng, level, len);
            out.extend(burst);
        }
        let len = span(rate, rng.range(90.0, 380.0));
        let f0_start = rng.range(85.0, 260.0);
        let f0_end = (f0_start * rng.range(0.7, 1.4)).clamp(70.0, 320.0);
        let from = VOWELS[usize::try_from(rng.next_u64() % 8).unwrap()];
        let to = VOWELS[usize::try_from(rng.next_u64() % 8).unwrap()];
        let level = dbm0 + rng.range(-6.0, 6.0);
        let mut syllable = Vec::with_capacity(len);
        let mut phase = rng.range(0.0, 2.0 * PI);
        let mut amplitudes: Vec<f64> = Vec::new();
        let block = span(rate, 5.0).max(1);
        for n in 0..len {
            let t = count_f64(n) / count_f64(len);
            let f0 = f0_start + (f0_end - f0_start) * t;
            if n % block == 0 {
                let formants: Vec<f64> = (0..3).map(|i| from[i] + (to[i] - from[i]) * t).collect();
                let count = to_count((nyquist * 0.95 / f0).floor()).max(1);
                amplitudes = (1..=count)
                    .map(|k| {
                        let f = f0 * count_f64(k);
                        let shape: f64 = formants
                            .iter()
                            .zip(BANDWIDTHS)
                            .map(|(&c, b)| resonance(f, c, b))
                            .product();
                        shape / count_f64(k)
                    })
                    .collect();
            }
            phase += 2.0 * PI * f0 / fs;
            let (s1, c1) = phase.sin_cos();
            // sin(kφ) by the recurrence sin((k+1)φ) = 2cosφ·sin(kφ) − sin((k−1)φ)
            let mut previous = 0.0;
            let mut current = s1;
            let mut value = 0.0;
            for a in &amplitudes {
                value += a * current;
                let next = 2.0 * c1 * current - previous;
                previous = current;
                current = next;
            }
            syllable.push(value);
        }
        // a rise and fall over the syllable rather than a hard gate
        let edge = span(rate, 20.0).max(1);
        let slen = syllable.len();
        for (n, x) in syllable.iter_mut().enumerate() {
            let from_start = n.min(slen - 1 - n);
            if from_start < edge {
                *x *= count_f64(from_start) / count_f64(edge);
            }
        }
        scale_to(&mut syllable, level);
        out.extend(syllable);
        let pause = if rng.uniform() < 0.15 {
            rng.range(400.0, 900.0)
        } else {
            rng.range(30.0, 250.0)
        };
        out.extend(silence(span(rate, pause)));
    }
    out.truncate(total);
    out
}
