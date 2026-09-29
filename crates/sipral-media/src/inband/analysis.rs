// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The measurement every tone detector here stands on: a Hann-windowed
//! Goertzel filter bank evaluated on a sliding window, with the frequency of
//! each tone read from the phase it advances by between one window and the
//! next.
//!
//! # Why the phase
//!
//! A Goertzel filter says how much energy a window holds near one frequency.
//! It does not say *where* near it, and a DTMF receiver has to: Q.24 asks it
//! to accept a tone 1.5 % off its nominal frequency and to refuse one 3.5 %
//! off, and a filter wide enough to catch the first also catches most of the
//! second. What separates them is the frequency itself. The filter's complex
//! output turns, from one window to the next `hop` samples later, by `2π f
//! hop / rate` for a tone at `f`; subtracting the turn the bin's own
//! frequency would make leaves the tone's offset from it, unambiguous within
//! `± rate / (2 hop)`. That is exact for a steady tone, needs no extra
//! filter, and costs one complex multiply per bin per hop.
//!
//! # Why the window
//!
//! Knowing the offset also gives the tone's true level: the Hann window's
//! response at that offset is known in closed form, `sinc(δ) / (1 − δ²)` for
//! an offset of `δ` bins, so the magnitude a filter reports can be divided by
//! it. Levels read that way are what twist is computed from, and they do not
//! drift with a tone's frequency error. The Hann window also buries a tone
//! more than two bins from a filter under sidelobes 31 dB down and falling,
//! where a rectangular window would leave the other group's tone of a DTMF
//! pair 13 dB down in every filter.
//!
//! # Edges
//!
//! A window is long, so a window that sees a tone does not say when the tone
//! began. [`HopTracker`] does: a hop is part of a tone when the energy in
//! that hop alone reaches half of the tone's power as a window fully inside
//! it measured, which is where half the hop is covered. The fraction of the
//! first and last hop that is covered then places each edge to within a few
//! samples on a clean signal.

use std::collections::VecDeque;
use std::f64::consts::PI;

use super::{SampleRate, count_f64};

/// The response of a Hann window to a sine `delta` bins from the frequency
/// it is evaluated at, relative to its response at zero offset, with its
/// sign: real, because the window is symmetric about its middle, and
/// negative on every other sidelobe from the third bin out.
pub(crate) fn hann_shape(delta: f64) -> f64 {
    let x = delta.abs();
    if x < 1e-9 {
        return 1.0;
    }
    if (x - 1.0).abs() < 1e-9 {
        return 0.5;
    }
    let sinc = (PI * x).sin() / (PI * x);
    sinc / (1.0 - x * x)
}

/// The magnitude of [`hann_shape`].
pub(crate) fn hann_response(delta: f64) -> f64 {
    hann_shape(delta).abs()
}

/// A filter whose phase is followed from window to window.
#[derive(Clone, Debug)]
struct Bin {
    frequency: f64,
    coefficient: f64,
    cos: f64,
    sin: f64,
    /// `cos` and `sin` of the phase this bin's own frequency turns through
    /// in one hop.
    hop_cos: f64,
    hop_sin: f64,
    /// `cos` and `sin` of `ω (N - 1)`, which take the Goertzel output back
    /// to the DFT's own phase.
    end_cos: f64,
    end_sin: f64,
    previous: Option<(f64, f64)>,
}

/// What one window says about one tracked frequency.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Reading {
    /// The magnitude of the filter's output, as the window left it.
    pub(crate) magnitude: f64,
    /// Where the tone is, relative to the bin: `None` on the first window,
    /// or when the filter holds nothing to take a phase from.
    pub(crate) offset_hz: Option<f64>,
    /// Mean-square power of a sine at the bin's frequency plus the offset,
    /// corrected for the window's response there. Zero without an offset.
    pub(crate) power: f64,
    /// The windowed DFT at the bin's frequency, phase referred to the
    /// window's first sample.
    pub(crate) dft: (f64, f64),
}

/// One tone's share of a probe's DFT: see [`Analyzer::leak`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Leak {
    pub(crate) dft: (f64, f64),
    pub(crate) coupling: f64,
}

/// A sliding Hann-windowed Goertzel bank.
#[derive(Clone, Debug)]
pub(crate) struct Analyzer {
    rate: f64,
    hop: usize,
    window: Vec<f64>,
    window_sum: f64,
    window_square_sum: f64,
    /// The last `window.len()` samples, oldest first.
    buffer: Vec<f64>,
    windowed: Vec<f64>,
    /// How many samples of the current hop have arrived.
    filled: usize,
    hop_energy: f64,
    bins: Vec<Bin>,
    readings: Vec<Reading>,
    total_power: f64,
    hop_power: f64,
    /// Index of the hop the last analysed window ended with, counting the
    /// first hop of the stream as zero.
    hop_index: u64,
    started: bool,
}

impl Analyzer {
    /// A bank with a window of `window_ms` sliding by `hop_ms`, following
    /// the phase of every frequency in `frequencies`.
    pub(crate) fn new(rate: SampleRate, window_ms: u32, hop_ms: u32, frequencies: &[f64]) -> Self {
        let len = rate.samples(window_ms).max(2);
        let hop = rate.samples(hop_ms).clamp(1, len);
        let rate_hz = rate.as_f64();
        let window: Vec<f64> = (0..len)
            .map(|n| 0.5 - 0.5 * (2.0 * PI * count_f64(n) / count_f64(len)).cos())
            .collect();
        let window_sum = window.iter().sum();
        let window_square_sum = window.iter().map(|w| w * w).sum();
        let bins: Vec<Bin> = frequencies
            .iter()
            .map(|&frequency| {
                let omega = 2.0 * PI * frequency / rate_hz;
                let turn = omega * count_f64(hop);
                let end = omega * count_f64(len - 1);
                Bin {
                    frequency,
                    coefficient: 2.0 * omega.cos(),
                    cos: omega.cos(),
                    sin: omega.sin(),
                    hop_cos: turn.cos(),
                    hop_sin: turn.sin(),
                    end_cos: end.cos(),
                    end_sin: end.sin(),
                    previous: None,
                }
            })
            .collect();
        let readings = vec![
            Reading {
                magnitude: 0.0,
                offset_hz: None,
                power: 0.0,
                dft: (0.0, 0.0),
            };
            bins.len()
        ];
        Self {
            rate: rate_hz,
            hop,
            buffer: vec![0.0; len],
            windowed: vec![0.0; len],
            window,
            window_sum,
            window_square_sum,
            filled: 0,
            hop_energy: 0.0,
            bins,
            readings,
            total_power: 0.0,
            hop_power: 0.0,
            hop_index: 0,
            started: false,
        }
    }

    /// Forget everything heard: the next sample is the first of a stream.
    pub(crate) fn reset(&mut self) {
        self.buffer.iter_mut().for_each(|s| *s = 0.0);
        self.filled = 0;
        self.hop_energy = 0.0;
        self.bins.iter_mut().for_each(|b| b.previous = None);
        self.total_power = 0.0;
        self.hop_power = 0.0;
        self.hop_index = 0;
        self.started = false;
    }

    /// Samples per hop.
    pub(crate) const fn hop(&self) -> usize {
        self.hop
    }

    /// Hops per window, rounded down.
    pub(crate) fn hops_per_window(&self) -> usize {
        (self.window.len() / self.hop).max(1)
    }

    /// Index of the hop the last analysed window ended with.
    pub(crate) const fn hop_index(&self) -> u64 {
        self.hop_index
    }

    /// Mean-square power of the last window, weighted by the window so that
    /// it compares directly with [`Reading::power`].
    pub(crate) const fn total_power(&self) -> f64 {
        self.total_power
    }

    /// Mean-square power of the last hop alone, unweighted.
    pub(crate) const fn hop_power(&self) -> f64 {
        self.hop_power
    }

    /// What the last window says about the `index`th tracked frequency.
    pub(crate) fn reading(&self, index: usize) -> Option<Reading> {
        self.readings.get(index).copied()
    }

    /// Hertz per bin: the spacing of the window's own frequency grid.
    pub(crate) fn bin_width(&self) -> f64 {
        self.rate / count_f64(self.window.len())
    }

    /// Amplitude of a sine exactly at a filter's frequency that would
    /// produce `magnitude` there.
    pub(crate) fn amplitude_at_centre(&self, magnitude: f64) -> f64 {
        if self.window_sum > 0.0 {
            2.0 * magnitude / self.window_sum
        } else {
            0.0
        }
    }

    /// The windowed DFT of the last window at an arbitrary frequency, phase
    /// referred to the window's first sample, for a filter that is not
    /// tracked from window to window.
    pub(crate) fn probe(&self, frequency: f64) -> (f64, f64) {
        let omega = 2.0 * PI * frequency / self.rate;
        let y = goertzel(&self.windowed, 2.0 * omega.cos(), omega.cos(), omega.sin());
        let end = omega * count_f64(self.window.len() - 1);
        rotate(y, end.cos(), -end.sin())
    }

    /// What a steady sine at `tone_hz`, heard by the `index`th tracked
    /// filter, puts into the DFT at `probe_hz`, and how strongly the two
    /// filters are coupled.
    ///
    /// The Hann window is symmetric about sample `N / 2`, so its transform
    /// is a real shape times the phase `e^{-jΔN/2}` for an offset `Δ`. Both
    /// DFTs see the same sine through that transform; dividing one by the
    /// other leaves the ratio of the two shapes and the phase the two
    /// evaluation frequencies differ by, and neither depends on the sine's
    /// own phase or level. That is what lets a probe take a neighbouring
    /// tone's leakage off exactly, rather than only its magnitude.
    ///
    /// The tracked filter hears whatever sits at the probe's frequency too,
    /// so the leak computed from it carries a share of that back. The
    /// coupling returned is that share, a real number because the two
    /// phase turns cancel: whatever is at the probe's frequency is what is
    /// left after the leak, divided by one minus the coupling.
    pub(crate) fn leak(&self, index: usize, tone_hz: f64, probe_hz: f64) -> Leak {
        let none = Leak {
            dft: (0.0, 0.0),
            coupling: 0.0,
        };
        let (Some(bin), Some(reading)) = (self.bins.get(index), self.readings.get(index)) else {
            return none;
        };
        let width = self.bin_width();
        let own = hann_shape((bin.frequency - tone_hz) / width);
        if own.abs() < 0.05 {
            return none;
        }
        let ratio = hann_shape((probe_hz - tone_hz) / width) / own;
        let turn = PI * (bin.frequency - probe_hz) / self.rate * count_f64(self.window.len());
        let (re, im) = rotate(reading.dft, turn.cos(), turn.sin());
        Leak {
            dft: (re * ratio, im * ratio),
            coupling: ratio * hann_shape((bin.frequency - probe_hz) / width),
        }
    }

    /// Take one sample. Returns whether it completed a hop, in which case
    /// the readings describe the window that ends with it.
    pub(crate) fn push(&mut self, sample: i16) -> bool {
        let value = f64::from(sample);
        let offset = self.window.len() - self.hop + self.filled;
        if let Some(slot) = self.buffer.get_mut(offset) {
            *slot = value;
        }
        self.hop_energy += value * value;
        self.filled += 1;
        if self.filled < self.hop {
            return false;
        }
        self.filled = 0;
        self.hop_power = self.hop_energy / count_f64(self.hop);
        self.hop_energy = 0.0;
        if self.started {
            self.hop_index += 1;
        }
        self.started = true;
        self.analyse();
        self.buffer.copy_within(self.hop.., 0);
        true
    }

    fn analyse(&mut self) {
        let mut energy = 0.0;
        for ((out, sample), weight) in self.windowed.iter_mut().zip(&self.buffer).zip(&self.window)
        {
            *out = sample * weight;
            energy += *out * *out;
        }
        self.total_power = if self.window_square_sum > 0.0 {
            energy / self.window_square_sum
        } else {
            0.0
        };
        let rate = self.rate;
        let hop = count_f64(self.hop);
        let bin_width = rate / count_f64(self.window.len());
        let window_sum = self.window_sum;
        for (bin, reading) in self.bins.iter_mut().zip(self.readings.iter_mut()) {
            let (re, im) = goertzel(&self.windowed, bin.coefficient, bin.cos, bin.sin);
            let dft = rotate((re, im), bin.end_cos, -bin.end_sin);
            let magnitude = re.hypot(im);
            let offset_hz = match bin.previous {
                Some((p_re, p_im)) if magnitude > 0.0 && p_re.hypot(p_im) > 0.0 => {
                    // this window times the conjugate of the last, turned
                    // back by what the bin's own frequency accounts for
                    let turn_re = re * p_re + im * p_im;
                    let turn_im = im * p_re - re * p_im;
                    let rest_re = turn_re * bin.hop_cos + turn_im * bin.hop_sin;
                    let rest_im = turn_im * bin.hop_cos - turn_re * bin.hop_sin;
                    Some(rest_im.atan2(rest_re) * rate / (2.0 * PI * hop))
                }
                _ => None,
            };
            bin.previous = Some((re, im));
            let power = match offset_hz {
                Some(offset) => {
                    let response = hann_response(offset / bin_width);
                    if response > 0.05 && window_sum > 0.0 {
                        let amplitude = 2.0 * magnitude / (window_sum * response);
                        amplitude * amplitude / 2.0
                    } else {
                        0.0
                    }
                }
                None => 0.0,
            };
            *reading = Reading {
                magnitude,
                offset_hz,
                power,
                dft,
            };
        }
    }
}

/// `value` times `cos + j sin`.
fn rotate(value: (f64, f64), cos: f64, sin: f64) -> (f64, f64) {
    (value.0 * cos - value.1 * sin, value.0 * sin + value.1 * cos)
}

/// The Goertzel recurrence over `samples`, returning the complex output
/// `s[N-1] - e^{-jω} s[N-2]`. Its magnitude is the DFT's at `ω`; its phase
/// differs from the DFT's by a constant for a given `ω` and length, which
/// is all the phase comparison between windows needs.
fn goertzel(samples: &[f64], coefficient: f64, cos: f64, sin: f64) -> (f64, f64) {
    let mut s1 = 0.0;
    let mut s2 = 0.0;
    for &x in samples {
        let s0 = x + coefficient * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    (s1 - cos * s2, sin * s2)
}

/// The best explanation a window found for its hops: which class of tone,
/// and the power of that tone as the window measured it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Claim<C> {
    pub(crate) class: C,
    pub(crate) power: f64,
}

/// One hop, once every window that covers it has been heard.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Hop<C> {
    /// Index of the hop, the first of the stream being zero.
    pub(crate) index: u64,
    /// Mean-square power of the hop's own samples.
    pub(crate) power: f64,
    /// The strongest claim any window covering this hop made.
    pub(crate) claim: Option<Claim<C>>,
}

impl<C: Copy> Hop<C> {
    /// The class this hop belongs to: the claim, when the hop holds at least
    /// half the power the claim measured, which is where at least half of
    /// it is covered by the tone.
    pub(crate) fn on(&self) -> Option<C> {
        self.claim
            .filter(|c| c.power > 0.0 && self.power >= 0.5 * c.power)
            .map(|c| c.class)
    }

    /// The hop's power as a fraction of `plateau`, the tone's own.
    pub(crate) fn coverage(&self, plateau: f64) -> f64 {
        if plateau > 0.0 {
            self.power / plateau
        } else {
            0.0
        }
    }
}

/// Collects each window's claim onto every hop it covers, and hands a hop
/// on once the last window covering it has been heard.
#[derive(Clone, Debug)]
pub(crate) struct HopTracker<C> {
    span: usize,
    pending: VecDeque<Hop<C>>,
}

impl<C: Copy> HopTracker<C> {
    /// A tracker for windows `span` hops long.
    pub(crate) fn new(span: usize) -> Self {
        let span = span.max(1);
        Self {
            span,
            pending: VecDeque::with_capacity(span + 1),
        }
    }

    /// Forget every hop not yet handed on.
    pub(crate) fn reset(&mut self) {
        self.pending.clear();
    }

    /// Hand on the oldest hop not yet handed on, as the windows heard so
    /// far left it: for a stream that has ended, where no window will
    /// follow.
    pub(crate) fn drain_one(&mut self) -> Option<Hop<C>> {
        self.pending.pop_front()
    }

    /// Record the window ending with hop `index`, whose own samples had
    /// mean-square `power`, and the claim that window made. Returns the hop
    /// the window completed, if any: the one `span - 1` hops back.
    pub(crate) fn push(
        &mut self,
        index: u64,
        power: f64,
        claim: Option<Claim<C>>,
    ) -> Option<Hop<C>> {
        self.pending.push_back(Hop {
            index,
            power,
            claim: None,
        });
        if let Some(claim) = claim {
            for hop in &mut self.pending {
                let stronger = hop.claim.is_none_or(|held| claim.power > held.power);
                if stronger {
                    hop.claim = Some(claim);
                }
            }
        }
        if self.pending.len() >= self.span {
            self.pending.pop_front()
        } else {
            None
        }
    }
}

/// Where a tone began, given the first hop it covers at least half of.
///
/// `this` is that hop's coverage, `before` the coverage of the hop before
/// it, both as fractions of the tone's own power. A tone starting inside
/// this hop leaves it partly empty; one starting inside the hop before
/// leaves some of its power there.
pub(crate) fn start_edge(hop_start: f64, hop_len: f64, this: f64, before: f64) -> f64 {
    hop_start + (1.0 - this.clamp(0.0, 1.0)) * hop_len - before.clamp(0.0, 0.5) * hop_len
}

/// Where a tone ended, given the last hop it covers at least half of: the
/// mirror of [`start_edge`].
pub(crate) fn end_edge(hop_end: f64, hop_len: f64, this: f64, after: f64) -> f64 {
    hop_end - (1.0 - this.clamp(0.0, 1.0)) * hop_len + after.clamp(0.0, 0.5) * hop_len
}

#[cfg(test)]
mod tests {
    use super::{Analyzer, Claim, HopTracker, end_edge, hann_response, start_edge};
    use crate::inband::SampleRate;
    use crate::inband::signals::mix;
    use crate::inband::signals::{sine, to_pcm};

    #[test]
    fn the_hann_response_is_one_at_the_centre_and_half_a_bin_away_is_known() {
        assert!((hann_response(0.0) - 1.0).abs() < 1e-12);
        assert!((hann_response(1.0) - 0.5).abs() < 1e-12);
        assert!(hann_response(2.0) < 1e-12);
        let half = hann_response(0.5);
        // sinc(0.5) / 0.75 = (2 / π) / 0.75
        assert!((half - 2.0 / std::f64::consts::PI / 0.75).abs() < 1e-12);
        assert!((hann_response(-0.5) - half).abs() < 1e-12);
    }

    fn analyse(frequency: f64, amplitude: f64, rate: SampleRate) -> (f64, f64) {
        let mut bank = Analyzer::new(rate, 20, 5, &[1_000.0]);
        let pcm = to_pcm(&sine(frequency, amplitude, 0.3, rate.hz(), 4_000));
        let mut last = (0.0, 0.0);
        for &s in &pcm {
            if bank.push(s) {
                let reading = bank.reading(0).unwrap();
                if let Some(offset) = reading.offset_hz {
                    last = (offset, reading.power);
                }
            }
        }
        last
    }

    #[test]
    fn a_tone_off_the_bin_is_placed_and_measured_where_it_really_is() {
        for rate in [SampleRate::Hz8000, SampleRate::Hz16000] {
            for offset in [-80.0, -35.0, -10.0, 0.0, 12.5, 40.0, 75.0] {
                let (seen, power) = analyse(1_000.0 + offset, 10_000.0, rate);
                assert!((seen - offset).abs() < 0.5, "{rate:?} {offset}: {seen}");
                let expected = 10_000.0_f64 * 10_000.0 / 2.0;
                let error_db = 10.0 * (power / expected).log10();
                assert!(error_db.abs() < 0.2, "{rate:?} {offset}: {error_db} dB");
            }
        }
    }

    #[test]
    fn the_leak_of_a_tone_into_a_probe_is_predicted_in_phase_as_well_as_level() {
        for rate in [SampleRate::Hz8000, SampleRate::Hz16000] {
            let mut bank = Analyzer::new(rate, 20, 5, &[1_336.0]);
            for tone in [1_320.0, 1_336.0, 1_350.0] {
                for probe in [1_394.0, 1_300.0, 1_450.0] {
                    for phase in [0.0, 1.0, 2.5] {
                        bank.reset();
                        for &s in &to_pcm(&sine(tone, 9_000.0, phase, rate.hz(), 1_000)) {
                            bank.push(s);
                        }
                        let (re, im) = bank.probe(probe);
                        let leak = bank.leak(0, tone, probe).dft;
                        let left = bank.amplitude_at_centre((re - leak.0).hypot(im - leak.1));
                        // what is left is quantisation, far under the tone
                        assert!(left < 2.0, "{rate:?} {tone} {probe} {phase}: {left}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_probe_hears_a_second_sine_under_a_neighbours_leak_whatever_their_phases() {
        let rate = SampleRate::Hz8000;
        let mut bank = Analyzer::new(rate, 20, 5, &[1_336.0]);
        for phase in [0.0, 0.8, 1.6, 2.4, 3.2, 4.0, 4.8, 5.6] {
            bank.reset();
            let mut signal = sine(1_336.0, 9_000.0, 0.0, 8_000, 1_000);
            mix(&mut signal, &sine(1_394.0, 3_000.0, phase, 8_000, 1_000));
            for &s in &to_pcm(&signal) {
                bank.push(s);
            }
            let (re, im) = bank.probe(1_394.0);
            let leak = bank.leak(0, 1_336.0, 1_394.0);
            let left = (re - leak.dft.0).hypot(im - leak.dft.1) / (1.0 - leak.coupling);
            let heard = bank.amplitude_at_centre(left);
            assert!((heard / 3_000.0 - 1.0).abs() < 0.05, "{phase}: {heard}");
        }
    }

    #[test]
    fn the_window_power_of_a_sine_is_its_mean_square() {
        let mut bank = Analyzer::new(SampleRate::Hz8000, 20, 5, &[]);
        for &s in &to_pcm(&sine(700.0, 8_000.0, 0.0, 8_000, 800)) {
            bank.push(s);
        }
        let expected = 8_000.0_f64 * 8_000.0 / 2.0;
        assert!((bank.total_power() / expected - 1.0).abs() < 0.02);
        assert!((bank.hop_power() / expected - 1.0).abs() < 0.1);
    }

    #[test]
    fn a_hop_is_handed_on_once_every_window_covering_it_has_spoken() {
        let mut tracker: HopTracker<u8> = HopTracker::new(3);
        assert_eq!(tracker.push(0, 1.0, None), None);
        assert_eq!(
            tracker.push(
                1,
                1.0,
                Some(Claim {
                    class: 7,
                    power: 2.0
                })
            ),
            None
        );
        let first = tracker
            .push(
                2,
                1.0,
                Some(Claim {
                    class: 9,
                    power: 1.0,
                }),
            )
            .unwrap();
        assert_eq!(first.index, 0);
        // the window ending with hop 1 covered hop 0 and made the stronger claim
        assert_eq!(first.claim.map(|c| c.class), Some(7));
        assert_eq!(first.on(), Some(7), "power 1.0 is half of the claim's 2.0");
        let second = tracker.push(3, 0.1, None).unwrap();
        assert_eq!(second.index, 1);
        assert_eq!(second.claim.map(|c| c.class), Some(7));
    }

    #[test]
    fn a_hop_holding_less_than_half_of_the_claim_is_not_part_of_the_tone() {
        let mut tracker: HopTracker<u8> = HopTracker::new(1);
        let hop = tracker
            .push(
                0,
                0.99,
                Some(Claim {
                    class: 1,
                    power: 2.0,
                }),
            )
            .unwrap();
        assert_eq!(hop.on(), None);
        let hop = tracker
            .push(
                1,
                1.0,
                Some(Claim {
                    class: 1,
                    power: 2.0,
                }),
            )
            .unwrap();
        assert_eq!(hop.on(), Some(1));
    }

    #[test]
    fn edges_fall_inside_the_hop_by_the_fraction_left_uncovered() {
        // a tone that starts a quarter of the way into a 40-sample hop
        // covers three quarters of it
        assert!((start_edge(400.0, 40.0, 0.75, 0.0) - 410.0).abs() < 1e-9);
        // one that starts a quarter of the way before it covers it all, and
        // a quarter of the hop before
        assert!((start_edge(400.0, 40.0, 1.0, 0.25) - 390.0).abs() < 1e-9);
        assert!((end_edge(440.0, 40.0, 0.5, 0.0) - 420.0).abs() < 1e-9);
        assert!((end_edge(440.0, 40.0, 1.0, 0.25) - 450.0).abs() < 1e-9);
    }
}
