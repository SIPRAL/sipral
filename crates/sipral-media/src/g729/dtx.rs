// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Annex B's discontinuous transmission at the encoder (B.4.1, B.4.2): for
//! each frame the detector finds silent, whether to send a SID frame or
//! nothing, what the SID frame says, and the comfort noise both ends then
//! synthesise.
//!
//! The autocorrelations of every frame, speech or not, are kept (B.4.1.1),
//! as their upper halves and the power of two each is to be scaled by; so
//! are sums of them over pairs of frames, the last three pairs of which
//! make the past average filter of B.4.2.2. A silent frame's own filter is
//! the one of the sum of its and the last frame's autocorrelations (B.9),
//! and its residual energy is the one B.4.1.4 compares.
//!
//! The text's comparisons are Itakura distances against thresholds of
//! 1.20226 and 1.12202 (B.12, B.17). The comparison here is the same sum
//! with its first term halved and the threshold's scale folded into the
//! shifts, which is how the conformance streams are encoded. A SID frame is
//! allowed from the third silent frame after the last one, not the second.

use super::analysis::{Autocorrelation, Levinson, to_lsp};
use super::arith::{
    Split, abs, add, high, long_add, long_norm, long_shift_left, long_shift_right, long_sub,
    mac_checked, mult_round, round, shift_right, sub, to_word,
};
use super::comfort;
use super::lsp::{Coefficients, NoiseIndices, Quantizer, Vector};
use super::sid::{self, Level};
use super::tables::SID_GAINS;
use super::taming::Taming;
use super::{FRAME_SAMPLES, PAST};

/// B.12's threshold less one, Q15: a silent frame's filter this much
/// further from the last SID's than its own prediction error is a change.
/// The text gives 1.20226, 0.8 dB; the conformance streams are encoded with
/// 1.14816, 0.6 dB, and with the text's value they send their SID frames
/// at other frames than the streams do.
const CHANGED_FILTER: i16 = 4_855;

/// B.17's threshold less one, Q15: the frame's own filter is sent rather
/// than the past average if it is this far from the average. The text gives
/// 1.12202, 0.5 dB; the streams are encoded with 1.09647, 0.4 dB.
const OWN_FILTER: i16 = 3_161;

/// Silent frames after a SID frame before the next may be sent.
const SID_SPACING: i16 = 3;

/// A set of autocorrelations as the DTX keeps them: `r(0)` to `r(10)`, upper
/// halves, and the power of two they are to be scaled by, negated.
#[derive(Debug, Clone, Copy)]
struct Correlations {
    values: [i16; 11],
    shift: i16,
}

impl Correlations {
    /// Nothing yet: zeros, at a scale that loses them in any sum.
    const EMPTY: Self = Self {
        values: [0; 11],
        shift: 40,
    };

    /// The sum of `sets`, brought to a common scale with two bits of
    /// headroom and normalised on `r(0)`.
    fn sum(sets: &[Self]) -> Self {
        let common = add(sets.iter().map(|set| set.shift).min().unwrap_or(0), 14);
        let mut sums = [0_i32; 11];
        for set in sets {
            let shift = i32::from(sub(common, set.shift));
            for (slot, value) in sums.iter_mut().zip(set.values) {
                *slot = long_add(*slot, long_shift_left(i32::from(value), shift));
            }
        }
        let normalising = long_norm(sums.first().copied().unwrap_or(0));
        let mut values = [0_i16; 11];
        for (slot, sum) in values.iter_mut().zip(sums) {
            *slot = high(long_shift_left(
                sum,
                i32::try_from(normalising).unwrap_or(0),
            ));
        }
        Self {
            values,
            shift: add(common, sub(to_word(normalising), 16)),
        }
    }

    /// The same values in the split form the recursion reads.
    fn split(&self) -> [Split; 11] {
        self.values.map(|high| Split { high, low: 0 })
    }
}

/// `Ra` of equation B.13 for a filter, without B.13's factor of two off the
/// lag zero: the autocorrelation of its coefficients, normalised on the
/// first, and the normalising shift.
#[derive(Debug, Clone, Copy)]
struct FilterCorrelation {
    values: [i16; 11],
    shift: i16,
}

impl FilterCorrelation {
    fn of(a: &Coefficients) -> Self {
        let energy = a.iter().fold(0_i32, |sum, c| mac_checked(sum, *c, *c).0);
        let shift = long_norm(energy);
        let count = i32::try_from(shift).unwrap_or(0);
        let mut values = [0_i16; 11];
        for (lag, slot) in values.iter_mut().enumerate() {
            let later = a.get(lag..).unwrap_or_default();
            let sum = later
                .iter()
                .zip(a)
                .fold(0_i32, |sum, (x, y)| mac_checked(sum, *x, *y).0);
            *slot = round(long_shift_left(sum, count));
        }
        Self {
            values,
            shift: to_word(shift),
        }
    }

    /// Whether the filter these describe is further from the frame whose
    /// autocorrelations are `r`, and whose prediction error is `error`, than
    /// `threshold` (one plus the threshold, Q15) allows: B.12's test.
    ///
    /// The sum is taken with its first term halved. If it leaves the word,
    /// the two sets are shifted down a bit at a time, each in turn, until it
    /// does not.
    fn differs(&self, r: &Correlations, error: i16, threshold: i16) -> bool {
        let mut shifts = [0_u32; 2];
        let mut turn = 1;
        let sum = loop {
            let mut overflowed = false;
            let mut sum = 0_i32;
            for (lag, (own, frame)) in self.values.iter().zip(r.values).enumerate() {
                let a = shift_right(*own, shifts[0]);
                let b = shift_right(frame, shifts[1]);
                let (next, held) = if lag == 0 {
                    let (product, held) = mac_checked(0, a, b);
                    (long_shift_right(product, 1), held)
                } else {
                    mac_checked(sum, a, b)
                };
                sum = next;
                overflowed |= held;
            }
            if !overflowed {
                break sum;
            }
            if let Some(slot) = shifts.get_mut(turn) {
                *slot += 1;
            }
            turn = 1 - turn;
        };
        let limit = long_add(i32::from(mult_round(error, threshold)), i32::from(error));
        let scale = sub(add(self.shift, 9), to_word(shifts.iter().sum::<u32>()));
        long_sub(sum, long_shift_left(limit, i32::from(scale))) > 0
    }
}

/// What a silent frame becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Silent {
    /// A SID frame: its spectrum indices and energy index.
    Sid(NoiseIndices, u8),
    /// Nothing is sent.
    Nothing,
}

/// The encoder's side of the DTX.
#[derive(Debug, Clone)]
pub(super) struct Dtx {
    /// The last two frames' autocorrelations, newest first.
    recent: [Correlations; 2],
    /// Frames since `recent` last made a pair.
    unpaired: u8,
    /// Sums over the last three pairs, newest first.
    pairs: [Correlations; 3],
    /// The residual energies of the last two silent frames' filters, newest
    /// first, with their scales.
    energies: [(i16, i16); 2],
    /// How many of them are summed (`kE`).
    summed: usize,
    /// The last SID frame's filter, as B.13 needs it.
    reference: FilterCorrelation,
    /// The last SID frame's energy, in decibels.
    sid_decibels: i16,
    /// The gain the last SID frame's energy decodes to, and the smoothed
    /// target (B.19).
    sid_level: i16,
    gain: i16,
    /// Silent frames since the last SID frame, held at [`SID_SPACING`].
    since_sid: i16,
    /// Whether the noise has changed since the last SID frame.
    changed: bool,
    /// The quantized LSPs of the last SID frame.
    lsp: Vector,
}

impl Dtx {
    pub(super) fn new() -> Self {
        let mut flat = [0; 11];
        if let Some(first) = flat.first_mut() {
            *first = 4096;
        }
        Self {
            recent: [Correlations::EMPTY; 2],
            unpaired: 0,
            pairs: [Correlations::EMPTY; 3],
            energies: [(0, 40); 2],
            summed: 0,
            reference: FilterCorrelation::of(&flat),
            sid_decibels: 0,
            sid_level: 0,
            gain: 0,
            since_sid: 0,
            changed: false,
            lsp: super::tables::INITIAL_LSP,
        }
    }

    /// B.4.1.1: keep every frame's autocorrelations, and every second frame
    /// add the pair to the sums — at once if the frame is speech, and after
    /// the silent frame's own processing if not.
    pub(super) fn remember(&mut self, correlation: &Autocorrelation, speech: bool) {
        self.recent.rotate_right(1);
        let mut values = [0_i16; 11];
        for (slot, value) in values.iter_mut().zip(&correlation.plain) {
            *slot = value.high;
        }
        if let Some(newest) = self.recent.first_mut() {
            *newest = Correlations {
                values,
                shift: super::arith::negate(add(16, correlation.exponent)),
            };
        }
        self.unpaired += 1;
        if self.unpaired == 2 {
            self.unpaired = 0;
            if speech {
                self.pair();
            }
        }
    }

    fn pair(&mut self) {
        self.pairs.rotate_right(1);
        if let Some(newest) = self.pairs.first_mut() {
            *newest = Correlations::sum(&self.recent);
        }
    }

    /// A silent frame (B.4.1.2 to B.4.2.2 and B.4.4): decide whether it is
    /// a SID frame, quantize the SID if so, and write the comfort noise
    /// into the current frame of `excitation`. `after_speech` is whether the
    /// frame before was speech; `previous_lsp` is the last frame's quantized
    /// LSPs, which an LP filter whose LSPs cannot all be found falls back
    /// on; `generator` is the comfort noise's random generator. Returns what
    /// is sent; [`Dtx::lsp`] then gives the LSPs the frame is synthesised
    /// with.
    #[expect(
        clippy::too_many_arguments,
        reason = "the encoder's state the silent frame reads and writes, each a different part"
    )]
    pub(super) fn frame(
        &mut self,
        after_speech: bool,
        levinson: &mut Levinson,
        quantizer: &mut Quantizer,
        previous_lsp: &Vector,
        excitation: &mut [i16; PAST + FRAME_SAMPLES],
        generator: &mut i16,
        taming: &mut Taming,
    ) -> Silent {
        // B.9: the filter of the last two frames, and its residual energy;
        // the last frame's energy moves back a place and stays in the first
        // until this one's is known
        let [newest, _] = self.energies;
        self.energies = [newest, newest];
        let current = Correlations::sum(&self.recent);
        let mut own = [0_i16; 11];
        if let Some(first) = own.first_mut() {
            *first = 4096;
        }
        if current.values.first().copied().unwrap_or(0) == 0 {
            if let Some(newest) = self.energies.first_mut() {
                *newest = (0, current.shift);
            }
        } else {
            let prediction = levinson.run(&current.split());
            own = prediction.a;
            if let Some(newest) = self.energies.first_mut() {
                newest.0 = prediction.error.unwrap_or(newest.0);
                newest.1 = current.shift;
            }
        }
        let error = self.energies.first().map_or(0, |(energy, _)| *energy);

        self.summed = if after_speech {
            1
        } else {
            (self.summed + 1).min(2)
        };
        let level = sid::quantize_residuals(self.energies.get(..self.summed).unwrap_or_default());
        let due = if after_speech {
            self.since_sid = 0;
            true
        } else {
            if self.reference.differs(&current, error, CHANGED_FILTER) {
                self.changed = true;
            }
            if sub(abs(sub(self.sid_decibels, level.decibels)), 2) > 0 {
                self.changed = true;
            }
            self.since_sid = add(self.since_sid, 1);
            if self.since_sid < SID_SPACING {
                false
            } else {
                self.since_sid = SID_SPACING;
                self.changed
            }
        };

        let outcome = if due {
            self.since_sid = 0;
            self.changed = false;
            Silent::Sid(
                self.describe(
                    &own,
                    &current,
                    error,
                    level,
                    levinson,
                    quantizer,
                    previous_lsp,
                ),
                level.index,
            )
        } else {
            Silent::Nothing
        };

        self.gain = comfort::target_gain(self.gain, self.sid_level, after_speech);
        comfort::excite(self.gain, excitation, generator, Some(taming));
        if self.unpaired == 0 {
            self.pair();
        }
        outcome
    }

    /// B.4.2.2: the SID frame's filter — the past average, unless the
    /// frame's own is far from it — quantized, and the energy's level kept.
    #[expect(
        clippy::too_many_arguments,
        reason = "the silent frame's measurements and the encoder's state the SID is quantized with"
    )]
    fn describe(
        &mut self,
        own: &Coefficients,
        current: &Correlations,
        error: i16,
        level: Level,
        levinson: &mut Levinson,
        quantizer: &mut Quantizer,
        previous_lsp: &Vector,
    ) -> NoiseIndices {
        let average = Correlations::sum(&self.pairs);
        let past = if average.values.first().copied().unwrap_or(0) == 0 {
            let mut flat = [0_i16; 11];
            if let Some(first) = flat.first_mut() {
                *first = 4096;
            }
            flat
        } else {
            levinson.run(&average.split()).a
        };
        self.reference = FilterCorrelation::of(&past);
        let chosen = if self.reference.differs(current, error, OWN_FILTER) {
            self.reference = FilterCorrelation::of(own);
            *own
        } else {
            past
        };
        let lsp = to_lsp(&chosen, previous_lsp);
        let (indices, lsf) = quantizer.encode_sid(&lsp);
        self.lsp = super::lsp::to_cosines(&lsf);
        self.sid_decibels = level.decibels;
        self.sid_level = SID_GAINS
            .get(usize::from(level.index))
            .copied()
            .unwrap_or(0);
        indices
    }

    /// The quantized LSPs of the last SID frame, which a silent frame is
    /// synthesised with.
    pub(super) const fn lsp(&self) -> Vector {
        self.lsp
    }
}

#[cfg(test)]
mod tests {
    use super::{Correlations, FilterCorrelation};

    /// Two sets at different scales sum to what their values say.
    #[test]
    fn sums_meet_at_a_common_scale() {
        let a = Correlations {
            values: [16_384, 8192, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            shift: -20,
        };
        let b = Correlations {
            values: [16_384, -8192, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            shift: -21,
        };
        let sum = Correlations::sum(&[a, b]);
        // a set's values are scaled by two to the power of its shift, negated
        let whole = |set: &Correlations, lag: usize| {
            f64::from(set.values[lag]) * 2_f64.powi(-i32::from(set.shift))
        };
        for lag in 0..2 {
            let expected = whole(&a, lag) + whole(&b, lag);
            let got = whole(&sum, lag);
            assert!(
                (got - expected).abs() < whole(&sum, 0) * 1e-3,
                "lag {lag}: {got} against {expected}"
            );
        }
    }

    /// A filter compared with the spectrum it came from does not differ;
    /// with a very different spectrum it does.
    #[test]
    fn the_itakura_test_tells_near_from_far() {
        // A(z) = 1 − 0.9 z⁻¹, whose inverse's autocorrelation is 0.9^k
        let a = [4096, -3686, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let reference = FilterCorrelation::of(&a);
        let mut values = [0_i16; 11];
        let mut power = 1.0_f64;
        for slot in &mut values {
            #[expect(clippy::cast_possible_truncation, reason = "below one")]
            let value = (power * 16_000.0) as i16;
            *slot = value;
            power *= 0.9;
        }
        let near = Correlations { values, shift: -16 };
        // its prediction error is r(0)(1 − 0.81)
        #[expect(clippy::cast_possible_truncation, reason = "below one")]
        let error = (16_000.0 * 0.19) as i16;
        assert!(!reference.differs(&near, error, super::CHANGED_FILTER));
        // white noise: the same energy, no correlation
        let mut white = [0_i16; 11];
        white[0] = 16_000;
        let far = Correlations {
            values: white,
            shift: -16,
        };
        assert!(reference.differs(&far, 16_000, super::CHANGED_FILTER));
    }
}
