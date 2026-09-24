// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Annex B's voice activity detector (B.3): whether a frame is speech, from
//! four features of it measured against running averages of the
//! background noise.
//!
//! The features (B.3.1) are the full-band and low-band energies in
//! `log10` units, Q11 — so 2048 is ten decibels — the ten LSFs as fractions
//! of the sampling rate, and the zero-crossing rate of the frame. The
//! averages are started from the first thirty-two frames loud enough to
//! count (B.3.2), and afterwards follow the noise wherever the frame is
//! quiet against them (B.3.7). The initial decision is a union of fourteen
//! regions in the space of the four differences (B.3.5), smoothed in four
//! stages (B.3.6).
//!
//! Where this departs from the text, it is because the conformance streams
//! are encoded that way, and §B.5 makes the software they come from
//! normative:
//!
//! - the fourteen boundaries are not Table B.1's: the Implementers' Guide
//!   (10/2017) records that the software's differ from the table, and gives
//!   the first (`a1 = −14680` against the table's 23488). The differences
//!   here are the background's average less the frame's value, so the
//!   boundaries are written in that orientation;
//! - the averages are started as the text says, but the full-band noise
//!   energy begins ten decibels and the low-band twelve below the average
//!   frame energy, not by Table B.1's three cases;
//! - the fourth smoothing stage also needs the second reflection
//!   coefficient below 0.6, and the averages are updated only when the
//!   frame is within three decibels of the noise, its second reflection
//!   coefficient is below 0.75 and its spectral distance below 83 — the
//!   conditions Appendix II quotes from the software (II.5.1, II.5.3);
//! - the long-term minimum of B.3.3 is kept over sixteen stretches of eight
//!   frames, and after the 128th frame the noise's energy is pulled down to
//!   it when it falls below the minimum with a steady spectrum, or rises
//!   more than ten decibels above it.

use super::analysis::{Autocorrelation, WINDOW};
use super::arith::{
    Split, abs, add, deposit_high, log2, long_add, long_mult, long_shift_left, long_shift_right,
    mac, mult, sub,
};
use super::lsp::Vector;
use super::tables::{LOUD_FRAMES_MANTISSA, LOUD_FRAMES_SHIFT, LOW_BAND_CORRELATION};

/// Frames the averages are started over (`Ni`).
const START_FRAMES: i16 = 32;

/// Fifteen decibels: a frame below it is not speech, and does not count
/// towards the averages' start. Q11 `log10` units.
const QUIET: i16 = 3072;

/// Three decibels.
const THREE_DB: i16 = 614;

/// Ten decibels.
const TEN_DB: i16 = 2048;

/// Where the averages' updates change speed: the first twenty, then every
/// ten.
const FIRST_UPDATES: i16 = 20;

/// `log10(2)`, Q15.
const LOG10_OF_TWO: i16 = 9864;

/// `log10(240)`, Q11: from a sum over the window to its mean.
const LOG10_OF_WINDOW: i16 = 4875;

/// A frame's crossings are counted over its own eighty samples; each is
/// worth 1/80, Q15.
const CROSSING: i16 = 410;

/// The detector's memory.
#[derive(Debug, Clone)]
pub(super) struct Detector {
    /// `LSF̄`, `ZC̄`, `Ēf`, `Ēl`, and the average frame energy `Ēn` the last
    /// two start from.
    spectrum: Vector,
    crossings: i16,
    noise: i16,
    low_noise: i16,
    mean: i16,
    /// The minima of the full-band energy over sixteen stretches of eight
    /// frames, the least of them, and the least of the current stretch so
    /// far and of the next.
    minima: [i16; 16],
    least: i16,
    current_least: i16,
    next_least: i16,
    /// The last frame's full-band energy.
    last_energy: i16,
    /// Of the first thirty-two frames, how many were too quiet to count.
    quiet_start: usize,
    /// Frames in a row decided as noise.
    quiet_run: i16,
    /// Updates of the averages since they were last pulled down.
    updates: i16,
    /// The second smoothing stage's counter and whether it may extend.
    extensions: i16,
    may_extend: bool,
}

/// What the detector reads of a frame.
pub(super) struct Features<'a> {
    /// The second reflection coefficient of the frame's LP analysis, Q15.
    pub(super) reflection: i16,
    /// The frame's LSFs as fractions of the sampling rate, Q15.
    pub(super) lsf: &'a Vector,
    pub(super) correlation: &'a Autocorrelation,
    /// The analysis window: 120 samples before the frame, its eighty, and
    /// the look-ahead.
    pub(super) window: &'a [i16; WINDOW],
    /// The frame's number, from one.
    pub(super) frame: i16,
    /// The decisions of the two frames before, the last first.
    pub(super) before: [bool; 2],
}

impl Detector {
    pub(super) const fn new() -> Self {
        Self {
            spectrum: [0; 10],
            crossings: 0,
            noise: 0,
            low_noise: 0,
            mean: 0,
            minima: [0; 16],
            least: i16::MAX,
            current_least: 0,
            next_least: 0,
            last_energy: 0,
            quiet_start: 0,
            quiet_run: 0,
            updates: 0,
            extensions: 0,
            may_extend: true,
        }
    }

    /// Whether the frame is speech.
    pub(super) fn decide(&mut self, frame: &Features<'_>) -> bool {
        let r = &frame.correlation.windowed;
        let exponent = frame.correlation.exponent;

        // B.3.1: the two energies, the spectral distance, the crossings
        let energy = log_mean(r.first().map_or(0, |value| value.join()), exponent);
        let mut low = 0_i32;
        for (value, weight) in r.iter().zip(LOW_BAND_CORRELATION).skip(1) {
            low = mac(low, value.high, weight);
        }
        low = long_shift_left(low, 1);
        low = mac(
            low,
            r.first().map_or(0, |value| value.high),
            LOW_BAND_CORRELATION.first().copied().unwrap_or(0),
        );
        let low_energy = log_mean(low, exponent);
        let mut distance = 0_i32;
        for (value, mean) in frame.lsf.iter().zip(self.spectrum) {
            let difference = sub(*value, mean);
            distance = mac(distance, difference, difference);
        }
        let distance = super::arith::high(distance);
        let current = frame.window.get(120..=200).unwrap_or_default();
        let crossings = current.windows(2).fold(0_i16, |count, pair| match pair {
            [a, b] if mult(*a, *b) < 0 => add(count, CROSSING),
            _ => count,
        });

        self.track_minimum(energy, frame.frame);

        let [previous, before] = frame.before;
        let mut speech = false;
        if frame.frame <= START_FRAMES {
            if energy < QUIET {
                self.quiet_start += 1;
            } else {
                speech = true;
                self.mean = add_share(self.mean, energy);
                self.crossings = add_share(self.crossings, crossings);
                for (slot, value) in self.spectrum.iter_mut().zip(frame.lsf) {
                    *slot = add_share(*slot, *value);
                }
            }
        }
        if frame.frame >= START_FRAMES {
            if frame.frame == START_FRAMES {
                self.start();
            }
            let energy_difference = sub(self.noise, energy);
            let low_difference = sub(self.low_noise, low_energy);
            let crossing_difference = sub(self.crossings, crossings);

            speech = energy >= QUIET
                && initial(
                    low_difference,
                    energy_difference,
                    distance,
                    crossing_difference,
                );

            // the first smoothing stage
            let mut extended = false;
            if previous && !speech && add(energy_difference, 410) < 0 && energy > QUIET {
                speech = true;
                extended = true;
            }
            // the second
            if self.may_extend {
                if before && previous && !speech && abs(sub(self.last_energy, energy)) <= THREE_DB {
                    self.extensions += 1;
                    speech = true;
                    extended = true;
                    if self.extensions > 4 {
                        self.extensions = 0;
                        self.may_extend = false;
                    }
                }
            } else {
                self.may_extend = true;
            }
            // the third
            if !speech {
                self.quiet_run = add(self.quiet_run, 1);
            }
            if speech && self.quiet_run > 10 && sub(energy, self.last_energy) <= THREE_DB {
                speech = false;
                self.quiet_run = 0;
            }
            if speech {
                self.quiet_run = 0;
            }
            // the fourth
            let near_noise = sub(energy, THREE_DB) < self.noise;
            if near_noise && frame.frame > 128 && !extended && frame.reflection < 19_661 {
                speech = false;
            }

            // B.3.7
            if near_noise && frame.reflection < 24_576 && distance < 83 {
                self.update(energy, low_energy, crossings, frame.lsf);
            }
            if frame.frame > 128
                && ((self.noise < self.least && distance < 83)
                    || sub(self.noise, self.least) > TEN_DB)
            {
                self.noise = self.least;
                self.updates = 0;
            }
        }
        self.last_energy = energy;
        speech
    }

    /// B.3.2: the averages at the thirty-second frame, from the sums of the
    /// frames loud enough to count.
    fn start(&mut self) {
        let mantissa = LOUD_FRAMES_MANTISSA
            .get(self.quiet_start)
            .copied()
            .unwrap_or(0);
        let shift = i32::from(
            LOUD_FRAMES_SHIFT
                .get(self.quiet_start)
                .copied()
                .unwrap_or(0),
        );
        let average =
            |sum: i16| super::arith::high(long_shift_left(long_mult(sum, mantissa), shift));
        self.mean = average(self.mean);
        self.crossings = average(self.crossings);
        for slot in &mut self.spectrum {
            *slot = average(*slot);
        }
        self.noise = sub(self.mean, TEN_DB);
        // twelve decibels
        self.low_noise = sub(self.mean, 2458);
    }

    /// B.3.3: the least full-band energy of each stretch of eight frames,
    /// kept for sixteen stretches, and the least of those.
    fn track_minimum(&mut self, energy: i16, frame: i16) {
        let stretch_ends = frame % 8 == 0;
        if frame < 129 {
            if energy < self.least {
                self.least = energy;
                self.current_least = energy;
            }
            if stretch_ends {
                let slot = usize::try_from((frame >> 3) - 1).unwrap_or(0);
                if let Some(minimum) = self.minima.get_mut(slot) {
                    *minimum = self.least;
                }
                self.least = i16::MAX;
            }
        }
        if stretch_ends {
            self.current_least = self.minima.iter().copied().fold(i16::MAX, i16::min);
        }
        if frame >= 129 {
            if frame % 8 == 1 {
                self.least = self.current_least;
                self.next_least = i16::MAX;
            }
            self.least = self.least.min(energy);
            self.next_least = self.next_least.min(energy);
            if stretch_ends {
                self.minima.rotate_left(1);
                if let Some(last) = self.minima.last_mut() {
                    *last = self.next_least;
                }
                self.current_least = self.minima.iter().copied().fold(i16::MAX, i16::min);
            }
        }
    }

    /// Equation B.8: move the averages towards the frame, faster in the
    /// first updates after a start or a reset.
    fn update(&mut self, energy: i16, low_energy: i16, crossings: i16, lsf: &Vector) {
        self.updates = add(self.updates, 1);
        let (energy_keep, crossing_keep, spectrum_keep) = match self.updates {
            n if n < FIRST_UPDATES => (24_576, 26_214, 19_661),
            n if n < FIRST_UPDATES + 10 => (31_130, 30_147, 21_299),
            n if n < FIRST_UPDATES + 20 => (31_785, 30_802, 22_938),
            n if n < FIRST_UPDATES + 30 => (32_440, 31_457, 24_576),
            n if n < FIRST_UPDATES + 40 => (32_604, 32_440, 24_576),
            _ => (32_604, 32_702, 24_576),
        };
        let (energy_take, crossing_take, spectrum_take) = match self.updates {
            n if n < FIRST_UPDATES => (8192, 6554, 13_017),
            n if n < FIRST_UPDATES + 10 => (1638, 2621, 11_469),
            n if n < FIRST_UPDATES + 20 => (983, 1966, 9830),
            n if n < FIRST_UPDATES + 30 => (328, 1311, 8192),
            n if n < FIRST_UPDATES + 40 => (164, 328, 8192),
            _ => (164, 66, 8192),
        };
        let blend = |mean: i16, keep: i16, value: i16, take: i16| {
            super::arith::high(mac(long_mult(keep, mean), take, value))
        };
        self.noise = blend(self.noise, energy_keep, energy, energy_take);
        self.low_noise = blend(self.low_noise, energy_keep, low_energy, energy_take);
        self.crossings = blend(self.crossings, crossing_keep, crossings, crossing_take);
        for (slot, value) in self.spectrum.iter_mut().zip(lsf) {
            *slot = blend(*slot, spectrum_keep, *value, spectrum_take);
        }
    }
}

/// `mean + value/32`, the upper half of the sum: one frame's share of an
/// average over the first thirty-two.
fn add_share(mean: i16, value: i16) -> i16 {
    super::arith::high(mac(deposit_high(mean), value, 1024))
}

/// `log10` of the mean of a sum of doubled products over the window — the
/// normalised sum and the power of two it is to be scaled by — in Q11.
fn log_mean(value: i32, exponent: i16) -> i16 {
    let (whole, fraction) = log2(value);
    let octaves = Split {
        high: whole,
        low: fraction,
    };
    let mut sum = octaves.times(LOG10_OF_TWO);
    // the exponent, less one for the doubling of every product and one to
    // bring the word's normalisation back
    sum = mac(sum, LOG10_OF_TWO, sub(exponent, 2));
    sum = long_shift_left(sum, 11);
    sub(super::arith::high(sum), LOG10_OF_WINDOW)
}

/// B.3.5: the initial decision, from the differences between the
/// background's averages and the frame's low-band energy, full-band energy,
/// spectral distance (the distance itself) and zero crossings.
fn initial(low: i16, full: i16, distance: i16, crossings: i16) -> bool {
    let above = |sum: i32| sum > 0;
    let below = |sum: i32| sum < 0;
    let with_distance = |sum: i32| long_add(sum, deposit_high(distance));
    let with_full = |sum: i32| long_add(sum, deposit_high(full));
    let with_low = |sum: i32| long_add(sum, deposit_high(low));
    let line = |slope: i16, one: i16, offset: i16, shift: i32| {
        long_shift_right(mac(long_mult(crossings, slope), one, offset), shift)
    };

    // the spectral distance against the crossings
    above(with_distance(line(-14_680, 8192, -28_521, 8)))
        || above(with_distance(line(19_065, 8192, -19_446, 7)))
        // the full-band energy against the crossings, and alone
        || below(with_full(line(20_480, 8192, 16_384, 2)))
        || below(with_full(line(-16_384, 8192, 19_660, 2)))
        || below(mac(long_mult(full, 32_767), 1024, 30_802))
        // the full-band energy against the spectral distance, and the
        // distance alone
        || below(mac(mac(long_mult(distance, -28_160), 64, 19_988), full, 512))
        || above(mac(long_mult(distance, 32_767), 32, -30_199))
        // the full-band energy against the crossings again, and alone
        || below(with_full(line(-20_480, 8192, 22_938, 2)))
        || below(with_full(line(23_831, 4096, 31_576, 2)))
        || below(mac(long_mult(full, 32_767), 2048, 17_367))
        // the low-band energy against the spectral distance
        || below(mac(mac(long_mult(distance, -22_400), 32, 25_395), low, 256))
        // the low-band energy against the full-band energy
        || above(with_low(mac(long_mult(full, -30_427), 256, -29_959)))
        || below(with_low(mac(long_mult(full, -23_406), 512, 28_087)))
        || below(mac(mac(long_mult(full, 24_576), 1024, 29_491), low, 16_384))
}

#[cfg(test)]
mod tests {
    use super::{Detector, Features, initial};
    use crate::g729::analysis::{WINDOW, autocorrelation};
    use crate::g729::lsp::Vector;

    fn features<'a>(
        window: &'a [i16; WINDOW],
        correlation: &'a crate::g729::analysis::Autocorrelation,
        lsf: &'a Vector,
        frame: i16,
        before: [bool; 2],
    ) -> Features<'a> {
        Features {
            reflection: 0,
            lsf,
            correlation,
            window,
            frame,
            before,
        }
    }

    /// Nothing different from the background is noise, and a frame much
    /// louder than it is speech.
    #[test]
    fn the_initial_decision_separates_loud_from_background() {
        assert!(!initial(0, 0, 0, 0));
        // the frame twenty decibels above the noise: the averages less the
        // frame are negative
        assert!(initial(-4096, -4096, 0, 0));
    }

    /// A steady hiss from the start, loud enough to count as speech while
    /// the averages are started, is decided as noise once the long-term
    /// minimum has caught up with it — after the 128th frame — and a loud
    /// tone in the middle of it after that as speech.
    #[test]
    fn hiss_is_noise_and_a_tone_is_speech() {
        let mut detector = Detector::new();
        let mut state = 0x1357_9bdf_u32;
        let mut decisions = Vec::new();
        let mut before = [true, true];
        for frame in 1..=260_i16 {
            let tone = (220..240).contains(&frame);
            let mut window = [0_i16; WINDOW];
            for (n, slot) in window.iter_mut().enumerate() {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let hiss = f64::from(state % 2000) - 1000.0;
                let phase = f64::from(u16::try_from(n).unwrap()) * 0.35;
                let sample = if tone {
                    hiss + 12_000.0 * phase.sin()
                } else {
                    hiss
                };
                #[expect(clippy::cast_possible_truncation, reason = "bounded above")]
                let value = sample as i16;
                *slot = value;
            }
            let correlation = autocorrelation(&window);
            let lsf: Vector = if tone {
                [
                    1500, 1700, 3000, 5000, 7000, 8000, 9000, 11000, 13000, 15000,
                ]
            } else {
                [
                    1200, 2800, 4200, 5700, 7300, 8800, 10000, 11500, 13100, 14700,
                ]
            };
            let speech = detector.decide(&features(&window, &correlation, &lsf, frame, before));
            before = [speech, before[0]];
            decisions.push(speech);
        }
        // frame n is decisions[n − 1]
        assert!(
            decisions[..32].iter().all(|speech| *speech),
            "{decisions:?}"
        );
        assert!(
            decisions[160..219].iter().all(|speech| !*speech),
            "{decisions:?}"
        );
        assert!(
            decisions[220..239].iter().all(|speech| *speech),
            "{decisions:?}"
        );
    }
}
