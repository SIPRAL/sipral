// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The short-term filter, from four indices to two sets of LP coefficients
//! (§3.2.4 to §3.2.6, §4.1.1, §4.4.1).
//!
//! The indices name a two-stage vector in the LSF domain; the vector is
//! spaced out so that no two neighbours come too close, weighed against what
//! a switched MA predictor expects from the last four frames, checked for
//! stability, and turned into cosines. The first subframe uses the midpoint
//! of these cosines and the last frame's, the second uses them as they are,
//! and each set is expanded into the ten coefficients of `A(z)`.
//!
//! Formats: LSFs are Q13 radians, so π is 25736; LSPs (the cosines) are Q15;
//! LP coefficients are Q12, so `a0 = 1` is 4096; the polynomials `F1` and
//! `F2` are Q24 in thirty-two bits.

use super::arith::{
    Split, add, at, high, long_add, long_mult, long_shift_left, long_shift_right,
    long_shift_right_round, long_sub, low, mac, msu, mult, norm, round, shift_left, shift_right,
    sub,
};
use super::tables::{
    ARCCOS_SLOPE, COSINE, COSINE_SLOPE, FIRST_STAGE, INITIAL_LSF, MA_CURRENT_WEIGHT,
    MA_CURRENT_WEIGHT_INVERSE, MA_PREDICTOR, NOISE_MA_CURRENT_WEIGHT,
    NOISE_MA_CURRENT_WEIGHT_INVERSE, NOISE_MA_PREDICTOR, SECOND_STAGE_HIGH, SECOND_STAGE_LOW,
    SID_FIRST_STAGE_ROWS, SID_FIRST_STAGE_SCALE, SID_SECOND_STAGE_ROWS,
};

/// Ten LSFs, or ten LSPs.
pub(super) type Vector = [i16; 10];

/// The coefficients of `A(z)`, `a0` first.
pub(super) type Coefficients = [i16; 11];

/// `J` for the first spacing pass, 0.0012 in Q13.
const FIRST_GAP: i16 = 10;

/// `J` for the second, 0.0006.
const SECOND_GAP: i16 = 5;

/// The stability check's floor for `ω̂1`, 0.005, as the nearest Q13 value.
/// No conformance stream reaches it, so 40 would decode them all as well.
const LOWEST: i16 = 41;

/// Its minimum distance between neighbours. The text prints 0.0391, whose
/// nearest Q13 value is 320; the conformance streams need 321, 0.03918, and
/// six of the ten decode differently with 320.
const MINIMUM_DISTANCE: i16 = 321;

/// Its ceiling for `ω̂10`, 3.135, as the nearest Q13 value. No conformance
/// stream reaches it either.
const HIGHEST: i16 = 25_682;

/// `2/π` in Q15. An LSF in Q13 radians times this is its position along the
/// sixty-four segments of [`COSINE`], in Q8.
const TO_TABLE: i16 = 20_861;

/// The LSF quantizer's memory: the last four frames' quantizer outputs, the
/// last LSFs decoded, and which predictor produced them.
#[derive(Debug, Clone)]
pub(super) struct Quantizer {
    /// `l̂(m−1)` to `l̂(m−4)`, newest first.
    history: [Vector; 4],
    /// `ω̂` of the last frame, for an erasure to repeat.
    last: Vector,
    /// `L0` of the last good frame, for an erasure to predict with.
    predictor: usize,
}

impl Quantizer {
    /// Table 9: every `l̂` of the past is `iπ/11`.
    pub(super) const fn new() -> Self {
        Self {
            history: [INITIAL_LSF; 4],
            last: INITIAL_LSF,
            predictor: 0,
        }
    }

    /// Equations 19 and 20 and the stability check: the LSFs a good frame's
    /// indices name.
    pub(super) fn decode(
        &mut self,
        predictor: u16,
        first: u16,
        second_low: u16,
        second_high: u16,
    ) -> Vector {
        let predictor = usize::from(predictor & 1);
        let first = FIRST_STAGE
            .get(usize::from(first))
            .copied()
            .unwrap_or_default();
        let lower = SECOND_STAGE_LOW
            .get(usize::from(second_low))
            .copied()
            .unwrap_or_default();
        let upper = SECOND_STAGE_HIGH
            .get(usize::from(second_high))
            .copied()
            .unwrap_or_default();

        // equation 19
        let mut output: Vector = [0; 10];
        let corrections = lower.iter().chain(upper.iter());
        for ((slot, base), correction) in output.iter_mut().zip(first).zip(corrections) {
            *slot = add(base, *correction);
        }
        space(&mut output, FIRST_GAP);
        space(&mut output, SECOND_GAP);

        let mut lsf = self.predict(&output, predictor);
        self.remember(output);
        stabilise(&mut lsf);
        self.last = lsf;
        self.predictor = predictor;
        lsf
    }

    /// §4.4.1: an erased frame repeats the last LSFs, and the quantizer
    /// output that would have produced them under the last good frame's
    /// predictor (equation 92) takes the lost one's place in the memory.
    pub(super) fn conceal(&mut self) -> Vector {
        let output = self.unpredict(&self.last, self.predictor);
        self.remember(output);
        self.last
    }

    /// §3.2.4: the four indices that quantize `lsf`. The memory is not
    /// touched; decoding the indices sent brings it up to date.
    ///
    /// For each MA predictor, the vector to quantize is `lsf` with the
    /// prediction taken out (equation 23). The first stage is the entry of
    /// `L1` nearest it, unweighted; the lower half of the second stage is the
    /// entry of `L2` nearest what is left, weighted by equation 22, and the
    /// upper half the entry of `L3`. The candidate is spaced out as the
    /// decoder would space it, and the predictor whose candidate is nearest
    /// `lsf` in the weighted error of equation 21 is sent.
    ///
    /// Where the text rearranges each second-stage candidate before its
    /// error is measured, the conformance streams are encoded with the
    /// second stage searched against the target directly, in the domain of
    /// the quantizer output rather than of `ω̂`, and the rearrangement and
    /// the predictor's weight entering only the comparison of the two
    /// predictors.
    pub(super) fn encode(&self, lsf: &Vector) -> Indices {
        let weights = weights(lsf);
        let mut choices = [Indices::default(); 2];
        let mut distances = [i32::MAX; 2];
        for (predictor, (choice, distance)) in
            choices.iter_mut().zip(distances.iter_mut()).enumerate()
        {
            let target = self.unpredict(lsf, predictor);
            let first = nearest_first(&target);
            let base = FIRST_STAGE.get(first).copied().unwrap_or_default();
            let mut residue: Vector = [0; 10];
            for ((slot, value), stage) in residue.iter_mut().zip(target).zip(base) {
                *slot = sub(value, stage);
            }
            let lower = nearest_second(&residue, &weights, &SECOND_STAGE_LOW, 0);
            let upper = nearest_second(&residue, &weights, &SECOND_STAGE_HIGH, 5);

            let mut candidate = base;
            let corrections = SECOND_STAGE_LOW
                .get(lower)
                .copied()
                .unwrap_or_default()
                .into_iter()
                .chain(SECOND_STAGE_HIGH.get(upper).copied().unwrap_or_default());
            for (slot, correction) in candidate.iter_mut().zip(corrections) {
                *slot = add(*slot, correction);
            }
            space(&mut candidate, FIRST_GAP);
            space(&mut candidate, SECOND_GAP);

            let current = MA_CURRENT_WEIGHT
                .get(predictor)
                .copied()
                .unwrap_or_default();
            *distance = weighted_distance(&candidate, &target, &weights, &current);
            *choice = Indices {
                predictor: u16::try_from(predictor).unwrap_or(0),
                first: u16::try_from(first).unwrap_or(0),
                second_low: u16::try_from(lower).unwrap_or(0),
                second_high: u16::try_from(upper).unwrap_or(0),
            };
        }
        let [first_distance, second_distance] = distances;
        let [first_choice, second_choice] = choices;
        if second_distance < first_distance {
            second_choice
        } else {
            first_choice
        }
    }

    /// Equations 23 and 92, the same arithmetic: `(ω − Σ p̂ l̂(m−k)) / (1 −
    /// Σ p̂)`, the quantizer output that `ω` would be under `predictor`. The
    /// division is a multiplication by the stored reciprocal.
    fn unpredict(&self, lsf: &Vector, predictor: usize) -> Vector {
        self.unpredict_with(&SPEECH, lsf, predictor)
    }

    fn unpredict_with(&self, set: &Predictors, lsf: &Vector, predictor: usize) -> Vector {
        let taps = set.taps.get(predictor).copied().unwrap_or_default();
        let inverse = set.inverse.get(predictor).copied().unwrap_or_default();
        let mut output: Vector = [0; 10];
        for (index, slot) in output.iter_mut().enumerate() {
            let mut sum = i32::from(lsf.get(index).copied().unwrap_or(0)) << 16;
            for (past, row) in self.history.iter().zip(taps) {
                sum = msu(
                    sum,
                    row.get(index).copied().unwrap_or(0),
                    past.get(index).copied().unwrap_or(0),
                );
            }
            // the remainder in Q13 times the Q12 reciprocal is Q26; three more
            // bits bring the upper half back to Q13
            let remainder = high(sum);
            let scaled = long_mult(remainder, inverse.get(index).copied().unwrap_or(0));
            *slot = high(long_shift_left(scaled, 3));
        }
        output
    }

    /// Equation 20: `(1 − Σ p̂) l̂(m) + Σ p̂ l̂(m−k)`, a Q13 vector times Q15
    /// weights, summed in thirty-two bits and taken back to Q13 from the
    /// upper half.
    fn predict(&self, output: &Vector, predictor: usize) -> Vector {
        self.predict_with(&SPEECH, output, predictor)
    }

    fn predict_with(&self, set: &Predictors, output: &Vector, predictor: usize) -> Vector {
        let taps = set.taps.get(predictor).copied().unwrap_or_default();
        let current = set.current.get(predictor).copied().unwrap_or_default();
        let mut lsf: Vector = [0; 10];
        for (index, slot) in lsf.iter_mut().enumerate() {
            let mut sum = long_mult(
                output.get(index).copied().unwrap_or(0),
                current.get(index).copied().unwrap_or(0),
            );
            for (past, row) in self.history.iter().zip(taps) {
                sum = mac(
                    sum,
                    row.get(index).copied().unwrap_or(0),
                    past.get(index).copied().unwrap_or(0),
                );
            }
            *slot = high(sum);
        }
        lsf
    }

    fn remember(&mut self, output: Vector) {
        self.history.rotate_right(1);
        if let Some(newest) = self.history.first_mut() {
            *newest = output;
        }
    }

    /// B.4.3 and B.4.2.2 read backwards: the LSFs a SID frame's three
    /// spectrum indices name. The same steps as a speech frame's, with the
    /// SID's subsets of the codebooks, a single spacing pass and the noise
    /// predictors; the memory takes the quantizer output as it would a
    /// speech frame's. What an erased speech frame repeats — the last LSFs
    /// and predictor of a speech frame — is left alone.
    pub(super) fn decode_sid(&mut self, indices: NoiseIndices) -> Vector {
        let mut output = sid_output(indices.first, indices.second);
        space(&mut output, FIRST_GAP);
        let mut lsf = self.predict_with(&NOISE, &output, usize::from(indices.predictor & 1));
        self.remember(output);
        stabilise(&mut lsf);
        lsf
    }

    /// B.4.2.2: the SID indices for the spectrum `lsp`, and the LSFs they
    /// decode to, which the memory is brought up to date with.
    ///
    /// The LSFs are first spaced at twice the stability check's minimum
    /// distance, and weighted as a speech frame's are. For each of the two
    /// noise predictors the target is the quantizer output that would give
    /// them; the first stage keeps the [`SID_CANDIDATES`] nearest (target,
    /// row) pairs of the two in plain squared error, the second stage tries
    /// each of its sixteen rows against each candidate in squared error
    /// weighted by the LSF weights and by the square of the predictor's
    /// current-frame weight, and the nearest wins. Ties go to the first
    /// found, the predictor before the row.
    pub(super) fn encode_sid(&mut self, lsp: &Vector) -> (NoiseIndices, Vector) {
        let mut lsf = to_frequencies(lsp);
        let wide = shift_left(MINIMUM_DISTANCE, 1);
        if let Some(first) = lsf.first_mut() {
            *first = (*first).max(LOWEST);
        }
        for upper in 1..lsf.len() {
            let below = lsf.get(upper - 1).copied().unwrap_or(0);
            if let Some(slot) = lsf.get_mut(upper)
                && sub(*slot, below) < wide
            {
                *slot = add(below, wide);
            }
        }
        if let Some(last) = lsf.last_mut() {
            *last = (*last).min(HIGHEST);
        }
        let (top, next) = (at(&lsf, 9), at(&lsf, 8));
        if top < next
            && let Some(slot) = lsf.get_mut(8)
        {
            *slot = sub(top, MINIMUM_DISTANCE);
        }
        let weights = weights(&lsf);
        let targets = [0, 1].map(|predictor| self.unpredict_with(&NOISE, &lsf, predictor));

        // the first stage: every target against every row it may use
        let mut first_errors = [[0_i16; 32]; 2];
        for ((errors, target), scale) in first_errors
            .iter_mut()
            .zip(&targets)
            .zip(SID_FIRST_STAGE_SCALE)
        {
            for (error, row) in errors.iter_mut().zip(SID_FIRST_STAGE_ROWS) {
                let entry = FIRST_STAGE
                    .get(usize::from(row))
                    .copied()
                    .unwrap_or_default();
                let sum = target.iter().zip(entry).fold(0_i32, |sum, (t, e)| {
                    let difference = sub(*t, e);
                    mac(sum, difference, difference)
                });
                *error = mult(high(sum), scale);
            }
        }
        let mut candidates = [(0_usize, 0_usize); SID_CANDIDATES];
        for candidate in &mut candidates {
            let mut least = i16::MAX;
            for (predictor, errors) in first_errors.iter().enumerate() {
                for (row, error) in errors.iter().enumerate() {
                    if *error < least {
                        least = *error;
                        *candidate = (predictor, row);
                    }
                }
            }
            let (predictor, row) = *candidate;
            if let Some(slot) = first_errors.get_mut(predictor).and_then(|e| e.get_mut(row)) {
                *slot = i16::MAX;
            }
        }

        // the second stage, over what each candidate leaves
        let mut best = (0_usize, 0_usize);
        let mut least = i16::MAX;
        for (candidate, (predictor, row)) in candidates.iter().enumerate() {
            let target = targets.get(*predictor).copied().unwrap_or_default();
            let entry = sid_first_stage(*row);
            let current = NOISE_MA_CURRENT_WEIGHT
                .get(*predictor)
                .copied()
                .unwrap_or_default();
            for second in 0..16 {
                let correction = sid_second_stage(second);
                let mut sum = 0_i32;
                for index in 0..10 {
                    let share = at(&current, index);
                    let mut weight = high(long_shift_left(long_mult(share, share), 2));
                    weight = mult(weight, at(&weights, index));
                    let difference = sub(
                        sub(at(&target, index), at(&entry, index)),
                        at(&correction, index),
                    );
                    let weighed = high(long_shift_left(long_mult(weight, difference), 3));
                    sum = mac(sum, weighed, difference);
                }
                let error = high(sum);
                if error < least {
                    least = error;
                    best = (candidate, second);
                }
            }
        }
        let (candidate, second) = best;
        let (predictor, row) = candidates.get(candidate).copied().unwrap_or((0, 0));
        let indices = NoiseIndices {
            predictor: u16::try_from(predictor).unwrap_or(0),
            first: u16::try_from(row).unwrap_or(0),
            second: u16::try_from(second).unwrap_or(0),
        };
        (indices, self.decode_sid(indices))
    }
}

/// A set of MA predictors with their current-frame weights: the speech
/// quantizer's, or a SID frame's.
struct Predictors {
    taps: &'static [[[i16; 10]; 4]; 2],
    current: &'static [[i16; 10]; 2],
    inverse: &'static [[i16; 10]; 2],
}

const SPEECH: Predictors = Predictors {
    taps: &MA_PREDICTOR,
    current: &MA_CURRENT_WEIGHT,
    inverse: &MA_CURRENT_WEIGHT_INVERSE,
};

const NOISE: Predictors = Predictors {
    taps: &NOISE_MA_PREDICTOR,
    current: &NOISE_MA_CURRENT_WEIGHT,
    inverse: &NOISE_MA_CURRENT_WEIGHT_INVERSE,
};

/// How many first-stage choices a SID frame's search carries into its
/// second stage (B.4.2.2, item 2: "a delayed decision quantization is used
/// by keeping few candidates").
const SID_CANDIDATES: usize = 4;

/// The three spectrum indices of a SID frame (Table B.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct NoiseIndices {
    pub(super) predictor: u16,
    pub(super) first: u16,
    pub(super) second: u16,
}

/// The row of `L1` a SID first-stage index names.
fn sid_first_stage(index: usize) -> Vector {
    SID_FIRST_STAGE_ROWS
        .get(index)
        .and_then(|row| FIRST_STAGE.get(usize::from(*row)))
        .copied()
        .unwrap_or_default()
}

/// The ten corrections a SID second-stage index names: five from a row of
/// `L2`, five from a row of `L3`.
fn sid_second_stage(index: usize) -> Vector {
    let [lower_rows, upper_rows] = SID_SECOND_STAGE_ROWS;
    let lower = lower_rows
        .get(index)
        .and_then(|row| SECOND_STAGE_LOW.get(usize::from(*row)))
        .copied()
        .unwrap_or_default();
    let upper = upper_rows
        .get(index)
        .and_then(|row| SECOND_STAGE_HIGH.get(usize::from(*row)))
        .copied()
        .unwrap_or_default();
    let mut out: Vector = [0; 10];
    for (slot, value) in out.iter_mut().zip(lower.iter().chain(upper.iter())) {
        *slot = *value;
    }
    out
}

/// A SID frame's quantizer output before spacing: the two stages added.
fn sid_output(first: u16, second: u16) -> Vector {
    let mut output = sid_first_stage(usize::from(first & 31));
    for (slot, correction) in output
        .iter_mut()
        .zip(sid_second_stage(usize::from(second & 15)))
    {
        *slot = add(*slot, correction);
    }
    output
}

/// The four LSP indices of a frame (Table 8's `L0` to `L3`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Indices {
    pub(super) predictor: u16,
    pub(super) first: u16,
    pub(super) second_low: u16,
    pub(super) second_high: u16,
}

/// The row of `L1` nearest `target`, in plain squared error; the first of
/// equal ones.
fn nearest_first(target: &Vector) -> usize {
    let mut best = 0;
    let mut least = i32::MAX;
    for (row, entry) in FIRST_STAGE.iter().enumerate() {
        let distance = target.iter().zip(entry).fold(0_i32, |sum, (t, e)| {
            let difference = sub(*t, *e);
            mac(sum, difference, difference)
        });
        if distance < least {
            least = distance;
            best = row;
        }
    }
    best
}

/// The row of a half of the second stage nearest the five values of
/// `residue` from `offset`, in squared error weighted by `weights`: each
/// difference is weighed once, as a Q15 product, before it is squared into
/// the sum.
fn nearest_second(
    residue: &Vector,
    weights: &Vector,
    codebook: &[[i16; 5]; 32],
    offset: usize,
) -> usize {
    let part = residue.get(offset..).unwrap_or_default();
    let part_weights = weights.get(offset..).unwrap_or_default();
    let mut best = 0;
    let mut least = i32::MAX;
    for (row, entry) in codebook.iter().enumerate() {
        let distance = part.iter().zip(part_weights).zip(entry).fold(
            0_i32,
            |sum, ((value, weight), stage)| {
                let difference = sub(*value, *stage);
                mac(sum, mult(*weight, difference), difference)
            },
        );
        if distance < least {
            least = distance;
            best = row;
        }
    }
    best
}

/// Equation 21 for a candidate quantizer output against the target, both in
/// the domain of the quantizer output: the difference scaled by the
/// predictor's `1 − Σ p̂` is the difference in `ω̂`, and it is weighed and
/// squared.
fn weighted_distance(
    candidate: &Vector,
    target: &Vector,
    weights: &Vector,
    current: &Vector,
) -> i32 {
    let mut sum = 0_i32;
    for (((value, goal), weight), share) in candidate.iter().zip(target).zip(weights).zip(current) {
        let difference = mult(sub(*value, *goal), *share);
        let weighed = high(long_shift_left(long_mult(*weight, difference), 4));
        sum = mac(sum, weighed, difference);
    }
    sum
}

/// Equation 22: the weight of each LSF by how close its neighbours are, the
/// fifth and sixth made 1.2 times heavier, and all ten scaled up together as
/// far as the largest allows.
///
/// Formats: the distances are Q13 radians, as the LSFs are; each weight is
/// formed in Q11, where one is 2048.
fn weights(lsf: &Vector) -> Vector {
    // 1 + 0.04π and 0.92π − 1, Q13
    const LOWER_EDGE: i16 = 8192 + 1029;
    const UPPER_EDGE: i16 = 23_677 - 8192;
    // ten, Q11, and 1.2, Q14
    const TEN: i16 = 20_480;
    const ONE_AND_A_FIFTH: i16 = 19_661;

    let mut spread: Vector = [0; 10];
    for (index, slot) in spread.iter_mut().enumerate() {
        *slot = match index {
            0 => sub(at(lsf, 1), LOWER_EDGE),
            9 => sub(UPPER_EDGE, at(lsf, 8)),
            _ => sub(sub(at(lsf, index + 1), at(lsf, index - 1)), 8192),
        };
    }
    let mut weights: Vector = [0; 10];
    for (slot, distance) in weights.iter_mut().zip(spread) {
        *slot = if distance > 0 {
            2048
        } else {
            let square = high(long_shift_left(long_mult(distance, distance), 2));
            add(high(long_shift_left(long_mult(square, TEN), 2)), 2048)
        };
    }
    for index in [4, 5] {
        if let Some(slot) = weights.get_mut(index) {
            *slot = high(long_shift_left(long_mult(*slot, ONE_AND_A_FIFTH), 1));
        }
    }
    let largest = weights.iter().copied().fold(0, i16::max);
    let shift = norm(largest);
    for slot in &mut weights {
        *slot = shift_left(*slot, shift);
    }
    weights
}

/// Equation 18: `ω = arccos(q)` for each LSP, by the cosine table read
/// backwards. The LSPs fall as the LSFs rise, so the search runs from the
/// last LSP down the table's segments and never back up. Each LSF is the
/// segment's start, 512 units a segment, plus the LSP's distance into it
/// times the segment's inverse slope, and the 64 segments of `[0, π]` are
/// converted to Q13 radians by a factor of `π/4`.
pub(super) fn to_frequencies(lsp: &Vector) -> Vector {
    const QUARTER_PI: i16 = 25_736;
    let mut lsf: Vector = [0; 10];
    let mut segment = COSINE.len() - 1;
    for (slot, value) in lsf.iter_mut().zip(lsp).rev() {
        while COSINE.get(segment).copied().unwrap_or(0) < *value {
            segment -= 1;
            if segment == 0 {
                break;
            }
        }
        let offset = sub(*value, COSINE.get(segment).copied().unwrap_or(0));
        let slope = ARCCOS_SLOPE.get(segment).copied().unwrap_or(0);
        let start = shift_left(i16::try_from(segment).unwrap_or(0), 9);
        let within = low(long_shift_right(long_mult(slope, offset), 12));
        *slot = mult(add(start, within), QUARTER_PI);
    }
    lsf
}

/// The LSFs of `lsp` as fractions of the sampling rate, Q15, so that π is
/// 16384: the form Annex B's detector compares spectra in (B.3.1.1). The
/// cosine table read backwards as in [`to_frequencies`], each segment 256
/// units wide, and the step into a segment rounded rather than truncated.
pub(super) fn to_normalised_frequencies(lsp: &Vector) -> Vector {
    let mut lsf: Vector = [0; 10];
    let mut segment = COSINE.len() - 1;
    for (slot, value) in lsf.iter_mut().zip(lsp).rev() {
        while COSINE.get(segment).copied().unwrap_or(0) < *value {
            if segment == 0 {
                break;
            }
            segment -= 1;
        }
        let offset = sub(*value, COSINE.get(segment).copied().unwrap_or(0));
        let slope = ARCCOS_SLOPE.get(segment).copied().unwrap_or(0);
        let step = round(long_shift_left(long_mult(offset, slope), 3));
        *slot = add(step, shift_left(i16::try_from(segment).unwrap_or(0), 8));
    }
    lsf
}

/// §3.2.4's rearrangement: wherever a coefficient comes within `gap` of the
/// one above it, the two are pushed apart about their midpoint by half of
/// the shortfall each.
fn space(lsf: &mut Vector, gap: i16) {
    for upper in 1..lsf.len() {
        let below = lsf.get(upper - 1).copied().unwrap_or(0);
        let above = lsf.get(upper).copied().unwrap_or(0);
        let shortfall = sub(add(below, gap), above);
        if shortfall > 0 {
            let half = shift_right(shortfall, 1);
            if let Some(slot) = lsf.get_mut(upper - 1) {
                *slot = sub(below, half);
            }
            if let Some(slot) = lsf.get_mut(upper) {
                *slot = add(above, half);
            }
        }
    }
}

/// §3.2.4's stability check, in its four steps: order, a floor, a minimum
/// distance between neighbours, a ceiling.
fn stabilise(lsf: &mut Vector) {
    lsf.sort_unstable();
    if let Some(first) = lsf.first_mut() {
        *first = (*first).max(LOWEST);
    }
    for upper in 1..lsf.len() {
        let below = lsf.get(upper - 1).copied().unwrap_or(0);
        if let Some(slot) = lsf.get_mut(upper)
            && sub(*slot, below) < MINIMUM_DISTANCE
        {
            *slot = add(below, MINIMUM_DISTANCE);
        }
    }
    if let Some(last) = lsf.last_mut() {
        *last = (*last).min(HIGHEST);
    }
}

/// Equation 18 read backwards, `q = cos(ω)` for each LSF: the position along
/// the table's sixty-four segments, its whole part picking the segment and
/// its eight bits of fraction scaling the segment's slope.
pub(super) fn to_cosines(lsf: &Vector) -> Vector {
    let mut lsp: Vector = [0; 10];
    for (slot, frequency) in lsp.iter_mut().zip(lsf) {
        let position = mult(*frequency, TO_TABLE);
        let segment = usize::try_from(position >> 8).unwrap_or(0).min(63);
        let offset = position & 0xff;
        let base = COSINE.get(segment).copied().unwrap_or(0);
        let slope = COSINE_SLOPE.get(segment).copied().unwrap_or(0);
        // the slope is sixteen times a segment's fall, so the Q8 offset's
        // product needs twelve bits off, and the doubling of the product one
        let step = low(long_shift_right(long_mult(slope, offset), 13));
        *slot = add(base, step);
    }
    lsp
}

/// Equation 24 for the first subframe: halfway between the last frame's
/// LSPs and this one's, each halved before the two are added.
pub(super) fn midpoint(previous: &Vector, current: &Vector) -> Vector {
    let mut out: Vector = [0; 10];
    for ((slot, a), b) in out.iter_mut().zip(previous).zip(current) {
        *slot = add(shift_right(*a, 1), shift_right(*b, 1));
    }
    out
}

/// §3.2.6: the LP coefficients from the LSPs.
///
/// `F1` and `F2` are built up one quadratic factor at a time from the odd
/// and the even LSPs, multiplied by `1 + z⁻¹` and `1 − z⁻¹` (equation 25),
/// and averaged into `A(z)` (equation 26), each coefficient rounded from Q24
/// with the halving folded into the shift.
pub(super) fn to_coefficients(lsp: &Vector) -> Coefficients {
    let mut odd = [0_i16; 5];
    let mut even = [0_i16; 5];
    for (pair, (o, e)) in lsp.chunks_exact(2).zip(odd.iter_mut().zip(even.iter_mut())) {
        if let [first, second] = pair {
            *o = *first;
            *e = *second;
        }
    }
    let mut sum = polynomial(&odd);
    let mut difference = polynomial(&even);
    for index in (1..6).rev() {
        let previous = sum.get(index - 1).copied().unwrap_or(0);
        if let Some(slot) = sum.get_mut(index) {
            *slot = long_add(*slot, previous);
        }
        let previous = difference.get(index - 1).copied().unwrap_or(0);
        if let Some(slot) = difference.get_mut(index) {
            *slot = long_sub(*slot, previous);
        }
    }

    let mut a: Coefficients = [0; 11];
    if let Some(first) = a.first_mut() {
        *first = 4096;
    }
    for index in 1..6 {
        let f1 = sum.get(index).copied().unwrap_or(0);
        let f2 = difference.get(index).copied().unwrap_or(0);
        if let Some(slot) = a.get_mut(index) {
            *slot = low(long_shift_right_round(long_add(f1, f2), 13));
        }
        if let Some(slot) = a.get_mut(11 - index) {
            *slot = low(long_shift_right_round(long_sub(f1, f2), 13));
        }
    }
    a
}

/// `F1` or `F2` of equations 13 and 14, coefficients 0 to 5, from its five
/// LSPs, by the recursion under equation 26. Each new factor
/// `1 − 2q z⁻¹ + z⁻²` updates the coefficients from the top down, so every
/// update reads the values of the order before.
fn polynomial(lsp: &[i16; 5]) -> [i32; 6] {
    let mut f = [0_i32; 6];
    if let Some(slot) = f.first_mut() {
        *slot = 1 << 24;
    }
    // −2q in Q24 is a Q15 q times −1024, and the product is doubled
    if let Some(slot) = f.get_mut(1) {
        *slot = long_mult(lsp.first().copied().unwrap_or(0), -512);
    }
    for (order, q) in (2..6).zip(lsp.iter().skip(1)) {
        // the new top coefficient starts as its mirror two below, and the
        // loop below adds the same again with the cross term
        let mirror = f.get(order - 2).copied().unwrap_or(0);
        if let Some(slot) = f.get_mut(order) {
            *slot = mirror;
        }
        for index in (2..=order).rev() {
            let cross = long_shift_left(
                Split::of(f.get(index - 1).copied().unwrap_or(0)).times(*q),
                1,
            );
            let two_below = f.get(index - 2).copied().unwrap_or(0);
            if let Some(slot) = f.get_mut(index) {
                *slot = long_sub(long_add(*slot, two_below), cross);
            }
        }
        if let Some(slot) = f.get_mut(1) {
            *slot = msu(*slot, *q, 512);
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::{
        HIGHEST, LOWEST, MINIMUM_DISTANCE, Quantizer, midpoint, space, stabilise, to_coefficients,
        to_cosines, to_frequencies, weights,
    };
    use crate::g729::tables::INITIAL_LSF;

    /// Reading the cosine table backwards undoes reading it forwards, to
    /// within the table's resolution.
    #[test]
    fn frequencies_and_cosines_are_inverses() {
        let lsf = [
            800, 1500, 3000, 5000, 7000, 9000, 12_000, 15_000, 19_000, 23_000,
        ];
        let back = to_frequencies(&to_cosines(&lsf));
        for (original, found) in lsf.iter().zip(back) {
            assert!((original - found).abs() <= 8, "{lsf:?} against {back:?}");
        }
    }

    /// Crowded neighbours weigh more than spread-out ones, and the heaviest
    /// weight fills the word's top bit.
    #[test]
    fn crowded_frequencies_weigh_more() {
        let spread = [
            2000, 4400, 6800, 9200, 11_600, 14_000, 16_400, 18_800, 21_200, 23_600,
        ];
        let mut crowded = spread;
        crowded[3] = 6900;
        crowded[4] = 7000;
        let even = weights(&spread);
        let uneven = weights(&crowded);
        assert!(uneven[3] > uneven[1], "{uneven:?}");
        assert!(even.iter().chain(uneven.iter()).all(|w| *w > 0));
        assert!(uneven.iter().any(|w| *w >= 16_384), "{uneven:?}");
    }

    /// Once the predictor's memory has caught up with a steady spectrum, the
    /// indices the encoder chooses decode to LSFs close to it; and a decoder
    /// that saw the same indices holds the same LSFs throughout.
    #[test]
    fn the_quantizer_finds_indices_that_decode_nearby() {
        let lsf = [
            1200, 2300, 4100, 6300, 8200, 10_700, 13_300, 16_800, 19_900, 22_700,
        ];
        let mut encoder = Quantizer::new();
        let mut decoder = Quantizer::new();
        let mut quantized = [0; 10];
        for _ in 0..12 {
            let indices = encoder.encode(&lsf);
            quantized = encoder.decode(
                indices.predictor,
                indices.first,
                indices.second_low,
                indices.second_high,
            );
            let again = decoder.decode(
                indices.predictor,
                indices.first,
                indices.second_low,
                indices.second_high,
            );
            assert_eq!(quantized, again);
        }
        for (wanted, got) in lsf.iter().zip(quantized) {
            // 0.05 of a radian: eighteen bits of codebook, not an identity
            assert!((wanted - got).abs() < 400, "{lsf:?} against {quantized:?}");
        }
    }

    #[test]
    fn spacing_pushes_close_neighbours_apart() {
        let mut lsf = [100, 105, 300, 900, 1500, 2000, 2500, 3000, 3500, 4000];
        space(&mut lsf, 10);
        // five short of ten apart: each moves by two, half the shortfall
        // rounded down
        assert_eq!(&lsf[..2], &[98, 107]);
        assert_eq!(&lsf[2..], &[300, 900, 1500, 2000, 2500, 3000, 3500, 4000]);
    }

    #[test]
    fn stability_orders_bounds_and_separates() {
        let mut lsf = [5000, 10, 3000, 3100, 3110, 9000, 12000, 15000, 20000, 26000];
        stabilise(&mut lsf);
        assert_eq!(lsf[0], LOWEST);
        for pair in lsf.windows(2) {
            assert!(pair[1] - pair[0] >= MINIMUM_DISTANCE, "{lsf:?}");
        }
        assert_eq!(lsf[9], HIGHEST);
    }

    /// A quarter turn in Q13 is π/2, whose cosine is 0; the table's own
    /// sample points come out exactly; and `iπ/11` comes out as its cosine
    /// to within the table's interpolation.
    #[test]
    fn cosines_come_out_of_the_table() {
        let quarter = to_cosines(&[12_868, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(quarter[0].abs() < 16, "{}", quarter[0]);
        assert_eq!(quarter[1], 32_767);
        let lsp = to_cosines(&INITIAL_LSF);
        for (index, value) in lsp.iter().enumerate() {
            let i = f64::from(u8::try_from(index + 1).unwrap());
            let exact = (i * core::f64::consts::PI / 11.0).cos() * 32768.0;
            assert!((f64::from(*value) - exact).abs() < 12.0, "{value} {exact}");
        }
    }

    #[test]
    fn the_midpoint_halves_each_side_first() {
        assert_eq!(midpoint(&[100; 10], &[300; 10]), [200; 10]);
        // −3/2 and 3/2 round down separately, to −2 and 1
        assert_eq!(midpoint(&[-3; 10], &[3; 10]), [-1; 10]);
    }

    /// Evenly spaced LSFs describe a flat spectrum, whose LP filter is nearly
    /// `A(z) = 1`: every coefficient small against `a0`.
    #[test]
    fn evenly_spaced_lsps_give_a_nearly_flat_filter() {
        let a = to_coefficients(&to_cosines(&INITIAL_LSF));
        assert_eq!(a[0], 4096);
        for value in &a[1..] {
            assert!(value.abs() < 400, "{a:?}");
        }
    }

    /// Equations 13, 14, 25 and 26 worked in floating point — multiply out
    /// the five quadratic factors of each polynomial, multiply by `1 ± z⁻¹`,
    /// average — agree with the fixed-point recursion to within the rounding
    /// of its Q12 result.
    #[test]
    fn the_coefficients_are_the_product_of_the_factors() {
        let lsp = [
            30_000, 26_000, 21_000, 15_000, 8_000, 0, -8_000, -15_000, -21_000, -26_000,
        ];
        let expand = |roots: &[i16]| -> Vec<f64> {
            let mut poly = vec![1.0_f64];
            for q in roots {
                let q = f64::from(*q) / 32_768.0;
                let mut next = vec![0.0; poly.len() + 2];
                for (i, c) in poly.iter().enumerate() {
                    next[i] += c;
                    next[i + 1] -= 2.0 * q * c;
                    next[i + 2] += c;
                }
                poly = next;
            }
            poly
        };
        let odd: Vec<i16> = lsp.iter().step_by(2).copied().collect();
        let even: Vec<i16> = lsp.iter().skip(1).step_by(2).copied().collect();
        let f1 = expand(&odd);
        let f2 = expand(&even);
        let a = to_coefficients(&lsp);
        for i in 1..=10 {
            // F1(z)(1 + z⁻¹) + F2(z)(1 − z⁻¹), halved
            let exact = 0.5 * (f1[i] + f1[i - 1] + f2[i] - f2[i - 1]);
            let ours = f64::from(a[i]) / 4096.0;
            assert!(
                (ours - exact).abs() < 2.0 / 4096.0,
                "a{i}: {ours} against {exact}"
            );
        }
    }

    #[test]
    fn an_erasure_repeats_the_last_frequencies() {
        let mut quantizer = Quantizer::new();
        let good = quantizer.decode(0, 17, 5, 9);
        assert_eq!(quantizer.conceal(), good);
        assert_eq!(quantizer.conceal(), good);
    }
}
