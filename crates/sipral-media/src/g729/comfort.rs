// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Annex B's comfort noise (B.4.4): the excitation a pause is synthesised
//! from, built the same way at both ends so that they stay in step.
//!
//! The text describes it as a random adaptive-codebook excitation at a
//! small gain plus random ACELP pulses, sized to a target energy, mixed with
//! white Gaussian noise. What the encoder and decoder that the Annex B
//! conformance streams come from compute is that, arranged differently, and
//! only that arrangement decodes the streams:
//!
//! - each subframe draws, from the generator of equation 96 (seeded with
//!   [`SEED`] rather than the concealment's value), a delay of 40 to 103 in
//!   thirds, four pulse positions and signs on Table 7's tracks, and an
//!   adaptive-codebook gain below one half;
//! - forty Gaussian samples, each the sum of twelve draws, are scaled so
//!   that their energy is a quarter of the target's, and added to the
//!   adaptive-codebook vector at that gain *before* the pulses' gain is
//!   solved for — the text mixes the Gaussian part in afterwards, at 0.6 and
//!   a solved-for weight (B.24 to B.26);
//! - the pulses' gain is the root of equation B.21 of least magnitude, with
//!   the Gaussian part inside `ea`; when the equation has no root the
//!   adaptive part is dropped and the target is asked of the Gaussian part
//!   and the pulses together at three quarters of the energy;
//! - the pulses' gain is held within ±5000.
//!
//! None of this arrangement is in the text beyond what the list says of
//! it, so what vouches for it is the conformance streams: all six Annex B
//! streams decode to their reference output sample for sample with it, and
//! all four encoded streams, whose frames after each pause depend on this
//! excitation, come out bit for bit.

use super::arith::{
    Split, abs, add, half_square_root, high, inverse_sqrt, long_add, long_mult, long_norm,
    long_shift_left, long_shift_right, long_sub, low, mac, mult_round, negate, norm, shift_left,
    shift_right, shift_right_round, sub,
};
use super::pitch::{self, Delay};
use super::taming::Taming;
use super::{FRAME_SAMPLES, PAST, SUBFRAME};

/// Where the comfort noise's generator starts, and where every speech frame
/// puts it back (B.4.5: "the pseudo-random sequence reset is performed at
/// each active frame").
pub(super) const SEED: i16 = 11_111;

/// B.19's smoothing of the target gain, `7/8` of the last and `1/8` of the
/// SID's, Q15.
const KEEP: i16 = 28_672;
const TAKE: i16 = 4_096;

/// `√40 / 4`, the step from the target gain to a quarter of the target
/// energy over a subframe, less one: the gain is added to its own product
/// with this, Q15.
const QUARTER_ROOT_FORTY_LESS_ONE: i16 = 19_043;

/// When the equation has no root: `1 − 0.5²`, the share of the target
/// energy asked of the Gaussian part and the pulses, Q15.
const WITHOUT_ADAPTIVE: i16 = 24_576;

/// The largest magnitude the pulses' gain takes.
const LARGEST_PULSE_GAIN: i16 = 5_000;

/// The target gain `G̃t` of the frame (equation B.19): the SID's own on the
/// first frame of a pause, and after that moved an eighth of the way
/// towards the latest SID's each frame.
pub(super) fn target_gain(previous: i16, sid: i16, first_of_pause: bool) -> i16 {
    if first_of_pause {
        sid
    } else {
        add(mult_round(previous, KEEP), mult_round(sid, TAKE))
    }
}

/// Equation 96, in sixteen bits: `seed = 31821 seed + 13849`.
pub(super) fn random(seed: &mut i16) -> i16 {
    *seed = seed.wrapping_mul(31_821).wrapping_add(13_849);
    *seed
}

/// A Gaussian draw: twelve uniform draws summed, down by seven bits.
fn gaussian(seed: &mut i16) -> i16 {
    let mut sum = 0_i32;
    for _ in 0..12 {
        sum = long_add(sum, i32::from(random(seed)));
    }
    low(long_shift_right(sum, 7))
}

/// The random choices of one subframe.
struct Draw {
    delay: Delay,
    positions: [usize; 4],
    positive: [bool; 4],
    /// The adaptive-codebook gain, Q14, below one half.
    pitch_gain: i16,
}

impl Draw {
    /// Three draws: the first gives the delay's fraction and whole part and
    /// the first two pulses, the second the last two pulses, the third the
    /// gain. The bits are read from the bottom up.
    fn new(seed: &mut i16) -> Self {
        let mut bits = random(seed);
        let fraction = match (bits & 3) - 1 {
            2 => 0,
            other => other,
        };
        bits = shift_right(bits, 2);
        let integer = (bits & 0x3f) + 40;
        bits = shift_right(bits, 6);
        let first = 5 * (bits & 7);
        bits = shift_right(bits, 3);
        let first_positive = bits & 1 == 1;
        bits = shift_right(bits, 1);
        let second = 5 * (bits & 7) + 1;
        bits = shift_right(bits, 3);
        let second_positive = bits & 1 == 1;

        bits = random(seed);
        let third = 5 * (bits & 7) + 2;
        bits = shift_right(bits, 3);
        let third_positive = bits & 1 == 1;
        bits = shift_right(bits, 1);
        let fourth = 5 * ((bits >> 1) & 7) + 3 + (bits & 1);
        bits = shift_right(bits, 4);
        let fourth_positive = bits & 1 == 1;

        let pitch_gain = random(seed) & 0x1fff;
        Self {
            delay: Delay { integer, fraction },
            positions: [first, second, third, fourth].map(|p| usize::try_from(p).unwrap_or(0)),
            positive: [
                first_positive,
                second_positive,
                third_positive,
                fourth_positive,
            ],
            pitch_gain,
        }
    }

    /// `Σ ±v(position)` over the four pulses, each value shifted down first.
    fn correlate(&self, values: &[i16; SUBFRAME], shift: u32) -> i16 {
        let mut sum = 0_i16;
        for (position, positive) in self.positions.iter().zip(self.positive) {
            let value = shift_right(values.get(*position).copied().unwrap_or(0), shift);
            sum = if positive {
                add(sum, value)
            } else {
                sub(sum, value)
            };
        }
        sum
    }
}

/// Fill the current frame of `excitation` — the [`PAST`] samples before it
/// are the past excitation — with comfort noise at the target gain `gain`
/// (Q3). `taming`, at the encoder, learns each subframe's delay and
/// adaptive-codebook gain as it would a speech subframe's; neither the text
/// nor any conformance stream settles that (the streams come out the same
/// without it), so it is the choice that keeps the taming procedure's view
/// of the excitation whole.
pub(super) fn excite(
    gain: i16,
    excitation: &mut [i16; PAST + FRAME_SAMPLES],
    seed: &mut i16,
    mut taming: Option<&mut Taming>,
) {
    if gain == 0 {
        if let Some(current) = excitation.get_mut(PAST..) {
            current.fill(0);
        }
        if let Some(taming) = taming.as_mut() {
            for _ in 0..2 {
                taming.update(0, 41);
            }
        }
        return;
    }
    for index in 0..2 {
        let start = PAST + SUBFRAME * index;
        let mut draw = Draw::new(seed);

        // the Gaussian part, scaled to a quarter of the target's energy
        let mut noise = [0_i16; SUBFRAME];
        let mut energy = 0_i32;
        for slot in &mut noise {
            *slot = gaussian(seed);
            energy = mac(energy, *slot, *slot);
        }
        let inverse = Split::of(inverse_sqrt(long_shift_right(energy, 1)));
        let scaled_gain = add(gain, mult_round(gain, QUARTER_ROOT_FORTY_LESS_ONE));
        let factor = inverse.times(scaled_gain);
        let shift = long_norm(factor);
        let factor_high = high(long_shift_left(factor, to_signed(shift)));
        let down = sub(super::arith::to_word(shift), 14);
        for slot in &mut noise {
            *slot = shift_right_round(mult_round(*slot, factor_high), down);
        }

        // the adaptive part at its gain, and the Gaussian part added to it
        pitch::interpolate(excitation, start, draw.delay);
        let doubled_gain = shift_left(draw.pitch_gain, 1);
        let mut largest = 0_i16;
        let mut current = [0_i16; SUBFRAME];
        for ((slot, sample), extra) in current
            .iter_mut()
            .zip(excitation.get(start..start + SUBFRAME).unwrap_or_default())
            .zip(noise)
        {
            *slot = add(mult_round(*sample, doubled_gain), extra);
            largest = largest.max(abs(*slot));
        }
        let mut shift = if largest == 0 {
            0
        } else {
            sub(3, super::arith::to_word(norm(largest))).max(0)
        };
        let mut scaled = [0_i16; SUBFRAME];
        for (slot, value) in scaled.iter_mut().zip(current) {
            *slot = shift_right(value, to_count(shift));
        }

        // equation B.21 for the pulses' gain, with the four unit pulses'
        // energy of four folded in: 4x² + 2bx + c = 0, where b is the
        // pulses' correlation with the rest and c its energy less the target
        let rest_energy = scaled.iter().fold(0_i32, |sum, v| mac(sum, *v, *v));
        let mut cross = draw.correlate(&scaled, 0);
        let per_subframe = low(long_shift_right(long_mult(gain, 40), 6));
        let target = long_mult(gain, per_subframe);
        let mut discriminant = long_shift_right(target, i32::from(add(1, shift_left(shift, 1))));
        discriminant = long_sub(discriminant, rest_energy);
        cross = shift_right(cross, 1);
        discriminant = mac(discriminant, cross, cross);
        shift = add(shift, 1);

        if discriminant < 0 {
            // no root: the Gaussian part alone, and the pulses asked for
            // three quarters of the target with it
            current = noise;
            let magnitudes = draw.positions.iter().fold(0_i16, |bits, p| {
                bits | abs(noise.get(*p).copied().unwrap_or(0))
            });
            shift = if magnitudes & 0x4000 == 0 { 1 } else { 2 };
            cross = draw.correlate(&noise, to_count(shift));
            discriminant = Split::of(target).times(WITHOUT_ADAPTIVE);
            discriminant = long_shift_right(discriminant, i32::from(sub(shift_left(shift, 1), 1)));
            discriminant = mac(discriminant, cross, cross);
            draw.pitch_gain = 0;
        }

        let root = half_square_root(discriminant);
        let mut chosen = sub(root, cross);
        let other = negate(add(cross, root));
        if abs(other) < abs(chosen) {
            chosen = other;
        }
        let pulse_gain =
            shift_right_round(chosen, sub(2, shift)).clamp(-LARGEST_PULSE_GAIN, LARGEST_PULSE_GAIN);

        for (position, positive) in draw.positions.iter().zip(draw.positive) {
            if let Some(slot) = current.get_mut(*position) {
                *slot = if positive {
                    add(*slot, pulse_gain)
                } else {
                    sub(*slot, pulse_gain)
                };
            }
        }
        if let Some(slot) = excitation.get_mut(start..start + SUBFRAME) {
            slot.copy_from_slice(&current);
        }
        if let Some(taming) = taming.as_mut() {
            taming.update(draw.pitch_gain, draw.delay.integer);
        }
    }
}

/// A shift count known to be small and not negative.
fn to_count(shift: i16) -> u32 {
    u32::try_from(shift).unwrap_or(0)
}

/// A normalising shift as a signed count.
fn to_signed(shift: u32) -> i32 {
    i32::try_from(shift).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{SEED, excite, random, target_gain};
    use crate::g729::{FRAME_SAMPLES, PAST};

    #[test]
    fn the_target_gain_moves_an_eighth_of_the_way() {
        assert_eq!(target_gain(0, 800, true), 800);
        assert_eq!(target_gain(800, 800, false), 800);
        assert_eq!(target_gain(0, 800, false), 100);
        assert_eq!(target_gain(800, 0, false), 700);
    }

    #[test]
    fn the_generator_is_equation_96() {
        let mut seed = 0;
        assert_eq!(random(&mut seed), 13_849);
        let mut seed = SEED;
        let next = random(&mut seed);
        let exact = (i64::from(SEED) * 31_821 + 13_849).rem_euclid(65_536);
        assert_eq!(i64::from(next).rem_euclid(65_536), exact);
    }

    /// The excitation's energy follows the target gain: over many frames
    /// its mean square is near `G̃²` with the gain in Q3, and a zero gain is
    /// silence.
    #[test]
    fn the_noise_has_the_energy_it_was_asked_for() {
        let mut excitation = [0_i16; PAST + FRAME_SAMPLES];
        let mut seed = SEED;
        let gain = 800; // 100 in the signal's units
        let mut total = 0.0;
        let frames = 200;
        for _ in 0..frames {
            excite(gain, &mut excitation, &mut seed, None);
            total += excitation[PAST..]
                .iter()
                .map(|s| f64::from(*s) * f64::from(*s))
                .sum::<f64>();
            excitation.copy_within(FRAME_SAMPLES.., 0);
        }
        let rms = (total / f64::from(frames * 80)).sqrt();
        assert!((60.0..160.0).contains(&rms), "{rms}");

        excite(0, &mut excitation, &mut seed, None);
        assert!(excitation[PAST..].iter().all(|s| *s == 0));
    }
}
