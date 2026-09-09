// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One sub-band's ADPCM, which is nearly all of G.722 (§6.2).
//!
//! The two bands run the same machine with different tables: a sixth-order
//! zero section and a second-order pole section predicting the next sample, a
//! quantizer whose step size is carried in a logarithmic scale factor, and an
//! adaptation that moves both from the codeword alone — so the decoder tracks
//! the encoder without being told anything beyond the bits it already has.
//!
//! Every arithmetic operation here is the Recommendation's. §6.2 defines `*`
//! as `(A times B) >> 15`, and `+` and `-` as saturating at the ends of a
//! sixteen-bit word; both are spelled out below rather than written as plain
//! Rust operators, because the saturation is part of the specification and a
//! wrapping add would decode to noise only on loud passages.

use super::tables::{
    IH_NEGATIVE, IH_POSITIVE, IH2, IL_NEGATIVE, IL_POSITIVE, IL4, IL5, IL6, ILA, Q2, Q6, QQ2, QQ4,
    QQ5, QQ6, SIH, SIL4, SIL5, SIL6, WH, WL,
};

/// §6.2: "denotes the multiplication defined by the following arithmetic
/// operation: `A * B = (A times B) >> 15`".
fn mul(a: i16, b: i16) -> i16 {
    saturate((i32::from(a) * i32::from(b)) >> 15)
}

/// §6.2: "The result is set at +32767 when overflow occurs, or at −32768 when
/// underflow occurs."
const fn saturate(value: i32) -> i16 {
    if value > i16::MAX as i32 {
        i16::MAX
    } else if value < i16::MIN as i32 {
        i16::MIN
    } else {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "both ends are checked above, so the value is inside i16 here"
        )]
        let inside = value as i16;
        inside
    }
}

fn add(a: i16, b: i16) -> i16 {
    a.saturating_add(b)
}

fn sub(a: i16, b: i16) -> i16 {
    a.saturating_sub(b)
}

/// Which band this is, and therefore which tables and limits apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Half {
    /// The lower sub-band: six bits a sample, scale factor capped at 18432.
    Lower,
    /// The higher sub-band: two bits a sample, capped at 22528.
    Higher,
}

impl Half {
    /// `DELAYL` resets `DETL` to 32; `DELAYH` resets `DETH` to 8.
    const fn initial_scale(self) -> i16 {
        match self {
            Self::Lower => 32,
            Self::Higher => 8,
        }
    }

    /// The upper limit `LOGSCL` and `LOGSCH` clamp the logarithmic scale
    /// factor to: "Upper limit of 9" and "Upper limit of 11".
    const fn scale_ceiling(self) -> i16 {
        match self {
            Self::Lower => 18_432,
            Self::Higher => 22_528,
        }
    }

    /// §6.2.1.3 adds 64 to the table address in the lower band and §6.2.2.3
    /// does not in the higher one, which is what makes the two bands cover
    /// different parts of the same 353-entry curve.
    const fn scale_offset(self) -> usize {
        match self {
            Self::Lower => 64,
            Self::Higher => 0,
        }
    }
}

/// How many bits of a lower-band codeword carry audio (§1.3, Table 2).
///
/// The encoder always writes six; a decoder told fewer treats the rest as the
/// auxiliary data channel the mode reserves, and reconstructs from what is
/// left.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Mode 1: all 64 kbit/s carry audio.
    #[default]
    Rate64,
    /// Mode 2: 56 kbit/s of audio, one bit a sample given to data.
    Rate56,
    /// Mode 3: 48 kbit/s of audio, two bits a sample given to data.
    Rate48,
}

/// One band's whole state.
///
/// Every field marked with an asterisk in Table 13 is here, and `reset` puts
/// each one back to what that table's note requires.
#[derive(Debug, Clone)]
pub(super) struct Band {
    half: Half,
    /// `SL` / `SH`: the predictor's output, what the next sample is expected
    /// to be.
    predicted: i16,
    /// `SZL` / `SZH`: the zero section's share of it, kept because `PARREC`
    /// needs it after `PREDIC` has already used it.
    zero_section: i16,
    /// `DETL` / `DETH`: the quantizer scale factor.
    scale: i16,
    /// `NBL` / `NBH`: its logarithm, which is what actually adapts.
    log_scale: i16,
    /// `AL1`, `AL2` / `AH1`, `AH2`: the pole section.
    pole: [i16; 2],
    /// `BL1` to `BL6` / `BH1` to `BH6`: the zero section.
    zero: [i16; 6],
    /// `DLT1` to `DLT6` / `DH1` to `DH6`.
    difference: [i16; 6],
    /// `PLT1`, `PLT2` / `PH1`, `PH2`.
    partial: [i16; 2],
    /// `RLT1`, `RLT2` / `RH1`, `RH2`.
    reconstructed: [i16; 2],
}

impl Band {
    pub(super) fn new(half: Half) -> Self {
        Self {
            half,
            predicted: 0,
            zero_section: 0,
            scale: half.initial_scale(),
            log_scale: 0,
            pole: [0; 2],
            zero: [0; 6],
            difference: [0; 6],
            partial: [0; 2],
            reconstructed: [0; 2],
        }
    }

    pub(super) fn reset(&mut self) {
        *self = Self::new(self.half);
    }

    /// The codeword for one input sample, and the state moved on by it.
    ///
    /// Six bits in the lower band, two in the higher, as the block diagrams
    /// in Figures 19 and 26 read from left to right.
    pub(super) fn encode(&mut self, sample: i16) -> u8 {
        let difference = sub(sample, self.predicted);
        let codeword = match self.half {
            Half::Lower => self.quantize_lower(difference),
            Half::Higher => self.quantize_higher(difference),
        };
        let quantized = self.inverse_quantize(codeword);
        self.adapt(codeword, quantized);
        codeword
    }

    /// The reconstructed sample for one codeword, and the state moved on by
    /// it.
    ///
    /// `mode` says how many of a lower-band codeword's bits are audio; it is
    /// ignored in the higher band, whose two bits are always audio.
    pub(super) fn decode(&mut self, codeword: u8, mode: Mode) -> i16 {
        // §6.2.1.5: the predictor is driven by the six-bit reconstruction
        // whatever the mode, and only the output the caller hears is built
        // from the shorter codeword. Feeding the predictor the short one
        // instead would let the two ends drift apart
        let quantized = self.inverse_quantize(codeword);
        let output = match (self.half, mode) {
            // §6.2.1.5: the predictor runs off the four-bit reconstruction in
            // every mode, and only what the caller hears is built from as
            // many bits as the mode says are audio
            (Half::Lower, Mode::Rate64) => self.inverse_quantize_short(codeword, 6),
            (Half::Lower, Mode::Rate56) => self.inverse_quantize_short(codeword >> 1, 5),
            // "DL may be substituted by output signal (DLT) of sub-block
            // INVQAL in the case of Mode 3", which is the same four bits
            (Half::Lower, Mode::Rate48) | (Half::Higher, _) => quantized,
        };
        let reconstructed = add(self.predicted, output);
        self.adapt(codeword, quantized);
        reconstructed.clamp(-16_384, 16_383)
    }

    /// `QUANTL` (§6.2.1.1): find the interval the difference falls in and
    /// look up its codeword.
    fn quantize_lower(&self, difference: i16) -> u8 {
        let negative = difference < 0;
        let magnitude = if negative {
            32_767 - (difference & 32_767)
        } else {
            difference
        };

        // §3.3: the boundaries are the table's levels scaled by the current
        // step size, and the note says a value landing exactly on a boundary
        // belongs to the interval above
        let mut interval = 30_usize;
        for level in 1..=29_usize {
            let boundary = mul(
                saturate(i32::from(*Q6.get(level).unwrap_or(&0)) << 3),
                self.scale,
            );
            if magnitude < boundary {
                interval = level;
                break;
            }
        }

        let table = if negative { &IL_NEGATIVE } else { &IL_POSITIVE };
        *table.get(interval).unwrap_or(&0)
    }

    /// `QUANTH` (§6.2.2.1): the same with one decision level.
    fn quantize_higher(&self, difference: i16) -> u8 {
        let negative = difference < 0;
        let magnitude = if negative {
            32_767 - (difference & 32_767)
        } else {
            difference
        };
        let boundary = mul(saturate(i32::from(Q2) << 3), self.scale);
        let interval = usize::from(magnitude >= boundary) + 1;
        let table = if negative { &IH_NEGATIVE } else { &IH_POSITIVE };
        *table.get(interval).unwrap_or(&0)
    }

    /// `INVQAL` and `INVQAH` (§6.2.1.2, §6.2.2.2): the quantized difference
    /// the predictor is driven by, which both ends compute the same way.
    fn inverse_quantize(&self, codeword: u8) -> i16 {
        match self.half {
            Half::Lower => self.inverse_quantize_short(codeword >> 2, 4),
            Half::Higher => {
                let index = usize::from(codeword & 0b11);
                let sign = *SIH.get(index).unwrap_or(&0);
                let level = *QQ2
                    .get(usize::from(*IH2.get(index).unwrap_or(&0)))
                    .unwrap_or(&0);
                self.scaled(sign, level)
            }
        }
    }

    /// `INVQBL` (§6.2.1.5) for a lower-band codeword of `bits` bits, and the
    /// four-bit case of `INVQAL`, which is the same lookup in a shorter
    /// table.
    fn inverse_quantize_short(&self, codeword: u8, bits: u32) -> i16 {
        let index = usize::from(codeword);
        let (sign, level) = match bits {
            6 => (
                *SIL6.get(index).unwrap_or(&0),
                *QQ6.get(usize::from(*IL6.get(index).unwrap_or(&0)))
                    .unwrap_or(&0),
            ),
            5 => (
                *SIL5.get(index).unwrap_or(&0),
                *QQ5.get(usize::from(*IL5.get(index).unwrap_or(&0)))
                    .unwrap_or(&0),
            ),
            _ => (
                *SIL4.get(index).unwrap_or(&0),
                *QQ4.get(usize::from(*IL4.get(index).unwrap_or(&0)))
                    .unwrap_or(&0),
            ),
        };
        self.scaled(sign, level)
    }

    /// The table constant shifted left by three and given the sign, then
    /// scaled by the step size — the last two lines of every inverse
    /// quantizer block.
    fn scaled(&self, sign: i16, level: i16) -> i16 {
        let shifted = saturate(i32::from(level) << 3);
        let signed = if sign == 0 { shifted } else { -shifted };
        mul(self.scale, signed)
    }

    /// The predictor and the scale factor both move on one sample, which is
    /// blocks 3 and 4 of each band run in the order the figures draw them.
    fn adapt(&mut self, codeword: u8, quantized: i16) {
        self.adapt_scale(codeword);

        let partial = add(quantized, self.zero_section);
        let reconstructed = add(self.predicted, quantized);

        self.update_zero_section(quantized);
        self.update_pole_section(partial);

        self.difference.rotate_right(1);
        if let Some(newest) = self.difference.first_mut() {
            *newest = quantized;
        }
        self.partial.rotate_right(1);
        if let Some(newest) = self.partial.first_mut() {
            *newest = partial;
        }
        self.reconstructed.rotate_right(1);
        if let Some(newest) = self.reconstructed.first_mut() {
            *newest = reconstructed;
        }

        self.zero_section = self.filter_zero();
        self.predicted = add(self.filter_pole(), self.zero_section);
    }

    /// `LOGSCL` / `LOGSCH` then `SCALEL` / `SCALEH` (§6.2.1.3, §6.2.2.3).
    fn adapt_scale(&mut self, codeword: u8) {
        let multiplier = match self.half {
            Half::Lower => {
                let index = usize::from(*IL4.get(usize::from(codeword >> 2)).unwrap_or(&0));
                *WL.get(index).unwrap_or(&0)
            }
            Half::Higher => {
                let index = usize::from(*IH2.get(usize::from(codeword & 0b11)).unwrap_or(&0));
                *WH.get(index).unwrap_or(&0)
            }
        };

        // the leak of 127/128 is what lets the scale factor forget a loud
        // passage rather than sitting at the ceiling for the rest of the call
        let leaked = mul(self.log_scale, 32_512);
        self.log_scale = add(leaked, multiplier).clamp(0, self.half.scale_ceiling());

        // Method 1 of the two the Recommendation offers: the 353-entry table,
        // which is exact where the 32-entry one is a shift away from it
        let address = (usize::from(
            #[expect(
                clippy::cast_sign_loss,
                reason = "the clamp above holds the scale factor at or above zero"
            )]
            {
                (self.log_scale >> 6) as u16
            },
        ) & 511)
            + self.half.scale_offset();
        let entry = *ILA.get(address).unwrap_or(&0);
        self.scale = saturate((i32::from(entry) + 1) << 2);
    }

    /// `UPZERO` (§6.2.1.4): each zero coefficient leaks by 255/256 and moves
    /// by a fixed step whose sign says whether this difference agreed with
    /// the one that far back.
    fn update_zero_section(&mut self, quantized: i16) {
        let step = if quantized == 0 { 0 } else { 128 };
        let sign = quantized >> 15;
        for tap in 0..6 {
            let past = *self.difference.get(tap).unwrap_or(&0);
            let agreed = sign == past >> 15;
            let moved = if agreed { step } else { -step };
            let leaked = mul(*self.zero.get(tap).unwrap_or(&0), 32_640);
            if let Some(coefficient) = self.zero.get_mut(tap) {
                *coefficient = add(moved, leaked);
            }
        }
    }

    /// `UPPOL2` then `UPPOL1` (§6.2.1.4), in that order because the first
    /// coefficient's limit is written in terms of the second's new value.
    fn update_pole_section(&mut self, partial: i16) {
        let sign = partial >> 15;
        let sign1 = self.partial.first().map_or(0, |value| value >> 15);
        let sign2 = self.partial.get(1).map_or(0, |value| value >> 15);
        let first = *self.pole.first().unwrap_or(&0);
        let second = *self.pole.get(1).unwrap_or(&0);

        let quadrupled = add(add(first, first), add(first, first));
        let toward = if sign == sign1 {
            sub(0, quadrupled)
        } else {
            quadrupled
        };
        let constant = if sign == sign2 { 128 } else { -128 };
        let updated_second =
            add(add(toward >> 7, constant), mul(second, 32_512)).clamp(-12_288, 12_288);

        let step = if sign == sign1 { 192 } else { -192 };
        let ceiling = sub(15_360, updated_second);
        let updated_first = add(step, mul(first, 32_640)).clamp(-ceiling, ceiling);

        self.pole = [updated_first, updated_second];
    }

    /// `FILTEZ` (§6.2.1.4).
    fn filter_zero(&self) -> i16 {
        let mut sum = 0_i16;
        for tap in 0..6 {
            let doubled = {
                let past = *self.difference.get(tap).unwrap_or(&0);
                add(past, past)
            };
            sum = add(sum, mul(*self.zero.get(tap).unwrap_or(&0), doubled));
        }
        sum
    }

    /// `FILTEP` (§6.2.1.4).
    fn filter_pole(&self) -> i16 {
        let mut sum = 0_i16;
        for tap in 0..2 {
            let doubled = {
                let past = *self.reconstructed.get(tap).unwrap_or(&0);
                add(past, past)
            };
            sum = add(sum, mul(*self.pole.get(tap).unwrap_or(&0), doubled));
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::{Band, Half, Mode, mul, saturate};
    use crate::g722::tables::IL_POSITIVE;

    #[test]
    fn the_multiplication_is_the_recommendations_own() {
        assert_eq!(mul(32_767, 32_767), 32_766);
        assert_eq!(mul(0, 12_345), 0);
        assert_eq!(mul(-32_768, 32_767), -32_767);
        // the one product that leaves a sixteen-bit word, and the saturation
        // §6.2 asks for rather than the wrap Rust would give
        assert_eq!(mul(-32_768, -32_768), i16::MAX);
    }

    #[test]
    fn addition_saturates_at_the_ends_of_the_word() {
        assert_eq!(saturate(40_000), i16::MAX);
        assert_eq!(saturate(-40_000), i16::MIN);
        assert_eq!(saturate(7), 7);
    }

    #[test]
    fn a_fresh_band_starts_where_the_reset_condition_says() {
        let lower = Band::new(Half::Lower);
        assert_eq!(lower.scale, 32);
        assert_eq!(lower.log_scale, 0);
        let higher = Band::new(Half::Higher);
        assert_eq!(higher.scale, 8);
    }

    /// A decoder fed what an encoder produced has to hold the same state, or
    /// the two drift apart and the call decays into noise over seconds.
    #[test]
    fn encoder_and_decoder_stay_in_step() {
        let mut encoder = Band::new(Half::Lower);
        let mut decoder = Band::new(Half::Lower);
        let mut worst = 0_i32;
        for n in 0..4_000_i32 {
            let t = f64::from(n) / 8_000.0;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the sine is bounded by the amplitude, which is inside i16"
            )]
            let sample = (6_000.0 * (core::f64::consts::TAU * 300.0 * t).sin()) as i16;
            let codeword = encoder.encode(sample);
            let heard = decoder.decode(codeword, Mode::Rate64);
            if n > 200 {
                worst = worst.max((i32::from(sample) - i32::from(heard)).abs());
            }
            assert_eq!(
                encoder.scale, decoder.scale,
                "the two step sizes parted company at sample {n}"
            );
            assert_eq!(encoder.pole, decoder.pole);
            assert_eq!(encoder.zero, decoder.zero);
        }
        assert!(
            worst < 900,
            "the worst sample was {worst} away, which is not six bits of ADPCM"
        );
    }

    /// NOTE 1 under `QUANTL`: "If WD falls exactly on a higher decision
    /// level, LDU, the larger adjacent MIL is used." A comparison written the
    /// other way round is off by one interval on exactly the values a test
    /// with a sine in it never produces.
    #[test]
    fn a_difference_landing_exactly_on_a_decision_level_takes_the_interval_above() {
        let mut band = Band::new(Half::Lower);
        // a step size large enough that the first two boundaries are whole
        // numbers: 140 and 288
        band.scale = 16_384;
        assert_eq!(band.quantize_lower(139), IL_POSITIVE[1]);
        assert_eq!(band.quantize_lower(140), IL_POSITIVE[2]);
        assert_eq!(band.quantize_lower(287), IL_POSITIVE[2]);
        assert_eq!(band.quantize_lower(288), IL_POSITIVE[3]);
    }

    /// The leak on the scale factor is what makes a decoder forget a bad
    /// packet. Without it the two ends keep whatever difference an error left
    /// them with, for the rest of the call.
    #[test]
    fn a_burst_of_errors_decays_out_of_the_scale_factor() {
        let mut encoder = Band::new(Half::Lower);
        let mut decoder = Band::new(Half::Lower);
        let sample = |n: i32| {
            let t = f64::from(n) / 8_000.0;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the sine is bounded by the amplitude, which is inside i16"
            )]
            let value = (7_000.0 * (core::f64::consts::TAU * 350.0 * t).sin()) as i16;
            value
        };

        for n in 0..500 {
            let codeword = encoder.encode(sample(n));
            decoder.decode(codeword, Mode::Rate64);
        }
        assert_eq!(
            encoder.log_scale, decoder.log_scale,
            "not in step to begin with"
        );

        // twenty packets of rubbish, which is what a burst of loss followed by
        // concealment looks like from the decoder's side
        for n in 500..520 {
            let codeword = encoder.encode(sample(n));
            decoder.decode(codeword ^ 0x2a, Mode::Rate64);
        }
        let straight_after = (i32::from(encoder.log_scale) - i32::from(decoder.log_scale)).abs();
        assert!(
            straight_after > 0,
            "the errors did not knock it out of step"
        );

        for n in 520..4_000 {
            let codeword = encoder.encode(sample(n));
            decoder.decode(codeword, Mode::Rate64);
        }
        let later = (i32::from(encoder.log_scale) - i32::from(decoder.log_scale)).abs();
        assert!(
            later * 4 < straight_after,
            "the gap was {straight_after} after the errors and {later} long afterwards"
        );
    }

    /// §6.2.1.4 holds the second pole coefficient inside ±0.75 and the first
    /// inside what is left of the stability triangle. A predictor allowed out
    /// of it rings, and the ringing is what a listener hears as a whistle on
    /// a loud vowel.
    #[test]
    fn the_pole_section_stays_inside_the_stability_limits() {
        for band_half in [Half::Lower, Half::Higher] {
            let mut band = Band::new(band_half);
            for n in 0..20_000_i32 {
                // a tone that steps in amplitude, which is what drives the
                // pole section hardest
                let t = f64::from(n) / 8_000.0;
                let amplitude = if (n / 800) % 2 == 0 { 15_500.0 } else { 400.0 };
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "the sine is bounded by the amplitude, which is inside i16"
                )]
                let sample = (amplitude * (core::f64::consts::TAU * 220.0 * t).sin()) as i16;
                band.encode(sample);

                let second = band.pole[1];
                assert!(
                    (-12_288..=12_288).contains(&second),
                    "{band_half:?}: the second coefficient reached {second} at sample {n}"
                );
                let ceiling = 15_360 - second;
                assert!(
                    band.pole[0].abs() <= ceiling,
                    "{band_half:?}: the first reached {} against a limit of {ceiling}",
                    band.pole[0]
                );
            }
        }
    }

    #[test]
    fn the_higher_band_tracks_too() {
        let mut encoder = Band::new(Half::Higher);
        let mut decoder = Band::new(Half::Higher);
        for n in 0..2_000_i32 {
            let t = f64::from(n) / 8_000.0;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the sine is bounded by the amplitude, which is inside i16"
            )]
            let sample = (3_000.0 * (core::f64::consts::TAU * 1_100.0 * t).sin()) as i16;
            let codeword = encoder.encode(sample);
            decoder.decode(codeword, Mode::Rate64);
            assert_eq!(encoder.scale, decoder.scale, "sample {n}");
        }
    }

    /// The scale factor has to climb for a loud signal and fall again for a
    /// quiet one, which is the whole point of the logarithmic adaptation.
    #[test]
    fn the_step_size_follows_the_signal() {
        let mut band = Band::new(Half::Lower);
        for n in 0..2_000_i32 {
            let t = f64::from(n) / 8_000.0;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the sine is bounded by the amplitude, which is inside i16"
            )]
            let loud = (15_000.0 * (core::f64::consts::TAU * 400.0 * t).sin()) as i16;
            band.encode(loud);
        }
        let after_loud = band.scale;
        for _ in 0..4_000 {
            band.encode(0);
        }
        let after_silence = band.scale;
        assert!(
            after_loud > after_silence * 4,
            "loud left the step at {after_loud} and silence at {after_silence}"
        );
        assert!(after_silence >= 32, "the step size fell below its floor");
    }

    /// Digital silence does not decode to exact zeros, and cannot: the
    /// quantizer has no zero interval, so the smallest thing it can say is
    /// one step. What matters is that the step falls to its floor and stays
    /// there, so the residue is inaudible rather than growing.
    #[test]
    fn silence_settles_into_the_smallest_step_the_quantizer_has() {
        let mut encoder = Band::new(Half::Lower);
        let mut decoder = Band::new(Half::Lower);
        let mut worst = 0_i32;
        for n in 0..2_000 {
            let codeword = encoder.encode(0);
            let heard = decoder.decode(codeword, Mode::Rate64);
            if n > 500 {
                worst = worst.max(i32::from(heard).abs());
            }
        }
        assert!(
            encoder.scale <= 64,
            "the step size settled at {} rather than near its floor of 32",
            encoder.scale
        );
        assert!(worst < 64, "silence left a residue of {worst}");
    }
}
