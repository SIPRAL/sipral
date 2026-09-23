// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The sixteen- and thirty-two-bit arithmetic the codec is defined in (§5.2,
//! Tables 10 and 11), and the three table-driven functions built on it.
//!
//! Table 10 gives the two data types — a signed sixteen-bit word and a signed
//! thirty-two-bit word — and Table 11 lists the operations, one line each:
//! "Short addition", "Long multiplication", "Multiply and accumulate". What
//! the lines leave out follows from the types: a result that does not fit is
//! held at the end of the word it overflowed rather than wrapped, a sixteen-bit
//! word is a fraction with fifteen bits after the point, and the product of two
//! of them is doubled so that it lands as a fraction with thirty-one. Where
//! that still leaves a choice — which way a product or a shift rounds — the
//! choice here is the one the conformance streams decode with: toward minus
//! infinity, the way a two's-complement shift goes.
//!
//! The names are ours; each operator says which line of Table 11 it is.

use super::tables::{INVERSE_SQRT, LOG2, POWER_OF_TWO};

/// "Limit to 16 bits".
pub(super) const fn saturate(value: i32) -> i16 {
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

/// The same for a thirty-two-bit word, and whether it had to.
const fn saturate_long(value: i64) -> (i32, bool) {
    if value > i32::MAX as i64 {
        (i32::MAX, true)
    } else if value < i32::MIN as i64 {
        (i32::MIN, true)
    } else {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "both ends are checked above, so the value is inside i32 here"
        )]
        let inside = value as i32;
        (inside, false)
    }
}

/// "Short addition".
pub(super) const fn add(a: i16, b: i16) -> i16 {
    saturate(a as i32 + b as i32)
}

/// "Short subtraction".
pub(super) const fn sub(a: i16, b: i16) -> i16 {
    saturate(a as i32 - b as i32)
}

/// "Short shift left": a count of zero or more, the result held at the end
/// of the word if it leaves it.
pub(super) const fn shift_left(a: i16, count: u32) -> i16 {
    if a == 0 {
        0
    } else if count > 15 {
        if a > 0 { i16::MAX } else { i16::MIN }
    } else {
        saturate((a as i32) << count)
    }
}

/// "Short shift right": arithmetic, so it rounds toward minus infinity and a
/// negative word stays negative.
pub(super) const fn shift_right(a: i16, count: u32) -> i16 {
    if count > 15 {
        if a < 0 { -1 } else { 0 }
    } else {
        a >> count
    }
}

/// "Short multiplication": two Q15 fractions to a Q15 fraction, truncated
/// toward minus infinity. Only −1 × −1 leaves the word.
pub(super) const fn mult(a: i16, b: i16) -> i16 {
    saturate((a as i32 * b as i32) >> 15)
}

/// "Long multiplication": the product doubled, two Q15 fractions to a Q31
/// one. −1 × −1 is again the one case held at the top.
pub(super) const fn long_mult(a: i16, b: i16) -> i32 {
    saturate_long((a as i64 * b as i64) << 1).0
}

/// "Long addition".
pub(super) const fn long_add(a: i32, b: i32) -> i32 {
    saturate_long(a as i64 + b as i64).0
}

/// "Long subtraction".
pub(super) const fn long_sub(a: i32, b: i32) -> i32 {
    saturate_long(a as i64 - b as i64).0
}

/// "Multiply and accumulate": the doubled product, held, then added and held
/// again — two limits, which differ from one exact sum only at the ends.
pub(super) const fn mac(acc: i32, a: i16, b: i16) -> i32 {
    long_add(acc, long_mult(a, b))
}

/// "Multiply and subtract".
pub(super) const fn msu(acc: i32, a: i16, b: i16) -> i32 {
    long_sub(acc, long_mult(a, b))
}

/// "Multiply and subtract", saying whether either step reached the end of the
/// word. The synthesis filter needs to know (see `lpc::synthesise`).
pub(super) const fn msu_checked(acc: i32, a: i16, b: i16) -> (i32, bool) {
    let (product, held) = saturate_long((a as i64 * b as i64) << 1);
    let (result, clipped) = saturate_long(acc as i64 - product as i64);
    (result, held || clipped)
}

/// "Long shift left" by a signed count: a negative count shifts right, and a
/// result that leaves the word is held at its end.
pub(super) const fn long_shift_left(a: i32, count: i32) -> i32 {
    long_shift_left_checked(a, count).0
}

/// The same, saying whether the result had to be held.
pub(super) const fn long_shift_left_checked(a: i32, count: i32) -> (i32, bool) {
    if count < 0 {
        (long_shift_right(a, -count), false)
    } else if a == 0 {
        (0, false)
    } else if count > 31 {
        if a > 0 {
            (i32::MAX, true)
        } else {
            (i32::MIN, true)
        }
    } else {
        saturate_long((a as i64) << count)
    }
}

/// "Long shift right" by a signed count, arithmetic; a negative count shifts
/// left.
pub(super) const fn long_shift_right(a: i32, count: i32) -> i32 {
    if count < 0 {
        long_shift_left(a, -count)
    } else if count > 31 {
        if a < 0 { -1 } else { 0 }
    } else {
        a >> count
    }
}

/// "Long shift right with round": the last bit shifted out is added back, so
/// a half rounds up.
pub(super) const fn long_shift_right_round(a: i32, count: u32) -> i32 {
    if count == 0 {
        a
    } else if count > 31 {
        0
    } else {
        let shifted = a >> count;
        if (a >> (count - 1)) & 1 == 1 {
            shifted + 1
        } else {
            shifted
        }
    }
}

/// "Extract high": the upper sixteen bits.
pub(super) const fn high(a: i32) -> i16 {
    saturate(a >> 16)
}

/// "Extract low": the lower sixteen bits, as they are.
pub(super) const fn low(a: i32) -> i16 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "keeping the lower sixteen bits is the whole of the operation"
    )]
    let bits = a as i16;
    bits
}

/// "Round": the upper sixteen bits after adding half of the lower ones'
/// range, held if the addition leaves the word.
pub(super) const fn round(a: i32) -> i16 {
    high(long_add(a, 0x8000))
}

/// "Round", saying whether the addition had to be held.
pub(super) const fn round_checked(a: i32) -> (i16, bool) {
    let (sum, held) = saturate_long(a as i64 + 0x8000);
    (high(sum), held)
}

/// "16-bit var1 into MSB part".
pub(super) const fn deposit_high(a: i16) -> i32 {
    (a as i32) << 16
}

/// "Long norm": how far a word can move left before its two top bits differ.
/// Zero for zero, thirty-one for −1.
pub(super) const fn long_norm(a: i32) -> u32 {
    if a == 0 {
        0
    } else if a == -1 {
        31
    } else {
        let positive = if a < 0 { !a } else { a };
        positive.leading_zeros() - 1
    }
}

/// "Short division": `numerator / denominator` as a Q15 fraction, for
/// `0 <= numerator <= denominator`, found a bit at a time and so truncated;
/// equal operands give the largest fraction the word holds. A zero numerator
/// gives zero whatever the denominator, which is how the long-term postfilter
/// reaches a gain of nothing when both of its correlations are zero. The
/// codec never divides outside that domain; if it did, zero would come back
/// rather than a panic.
pub(super) const fn divide(numerator: i16, denominator: i16) -> i16 {
    if numerator <= 0 || denominator <= 0 || numerator > denominator {
        return 0;
    }
    if numerator == denominator {
        return i16::MAX;
    }
    let mut remainder = numerator as i32;
    let divisor = denominator as i32;
    let mut quotient = 0_i32;
    let mut bit = 0;
    while bit < 15 {
        quotient <<= 1;
        remainder <<= 1;
        if remainder >= divisor {
            remainder -= divisor;
            quotient += 1;
        }
        bit += 1;
    }
    saturate(quotient)
}

/// A thirty-two-bit value split for a multiplication by a sixteen-bit one:
/// the upper sixteen bits, and the fifteen below them as a positive number,
/// the last bit dropped. Multiplying the two halves separately keeps the
/// precision a single sixteen-bit product would lose; the LP polynomial, the
/// gain predictor and the output filter's memory all need it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Split {
    pub(super) high: i16,
    pub(super) low: i16,
}

impl Split {
    pub(super) const fn of(value: i32) -> Self {
        let upper = high(value);
        let rest = msu(long_shift_right(value, 1), upper, 16_384);
        Self {
            high: upper,
            low: low(rest),
        }
    }

    /// The whole value again.
    pub(super) const fn join(self) -> i32 {
        mac(deposit_high(self.high), self.low, 1)
    }

    /// The split value times a Q15 fraction, in the value's own format.
    pub(super) const fn times(self, factor: i16) -> i32 {
        mac(long_mult(self.high, factor), mult(self.low, factor), 1)
    }
}

/// `log2(value)` for a positive value, as a whole part and a Q15 fraction,
/// from the thirty-three-entry table of `log2(1 + i/32)` (Table 12).
///
/// The value is normalised into `[2^30, 2^31)`. The six bits after the sign
/// pick one of thirty-two segments of `log2(1 + x)` on `[0, 1)`, the next
/// fifteen say how far into it the value falls, and the fraction is the
/// segment's start plus that share of its rise. Zero and below give zero.
pub(super) fn log2(value: i32) -> (i16, i16) {
    if value <= 0 {
        return (0, 0);
    }
    let shift = long_norm(value);
    let normal = long_shift_left(value, to_count(shift));
    let segment = usize::try_from((normal >> 25) - 32).unwrap_or(0);
    let within = low((normal >> 10) & 0x7fff);
    let start = LOG2.get(segment).copied().unwrap_or(0);
    let end = LOG2.get(segment + 1).copied().unwrap_or(0);
    let fraction = high(msu(deposit_high(start), sub(start, end), within));
    (sub(30, to_word(shift)), fraction)
}

/// `2^(whole + fraction/2^15)`, rounded to an integer, from the table of
/// `2^(i/32)` (Table 12): the top five bits of the fraction pick the segment,
/// the other ten how far along it, and the Q30 result is shifted down by
/// `30 − whole` with rounding.
pub(super) fn pow2(whole: i16, fraction: i16) -> i32 {
    let segment = usize::try_from(fraction >> 10).unwrap_or(0);
    let within = (fraction << 5) & 0x7fff;
    let start = POWER_OF_TWO.get(segment).copied().unwrap_or(0);
    let end = POWER_OF_TWO.get(segment + 1).copied().unwrap_or(0);
    let value = msu(deposit_high(start), sub(start, end), within);
    long_shift_right_round(value, u32::try_from(sub(30, whole)).unwrap_or(0))
}

/// `1/√value` for a positive value, in Q30 counted from an integer input,
/// from the table of `1/√(1 + i/16)` (Table 12).
///
/// The value is normalised; when the exponent left is even the mantissa is
/// halved so that the power of two taken out has a whole square root. The
/// mantissa, between one and four, picks one of forty-eight segments and is
/// interpolated within it. A value that is not positive gives the largest
/// result the format holds.
pub(super) fn inverse_sqrt(value: i32) -> i32 {
    if value <= 0 {
        return 0x3fff_ffff;
    }
    let shift = long_norm(value);
    let mut normal = long_shift_left(value, to_count(shift));
    let exponent = 30 - to_count(shift);
    if exponent & 1 == 0 {
        normal = long_shift_right(normal, 1);
    }
    let exponent = (exponent >> 1) + 1;
    let segment = usize::try_from((normal >> 25) - 16).unwrap_or(0);
    let within = low((normal >> 10) & 0x7fff);
    let start = INVERSE_SQRT.get(segment).copied().unwrap_or(0);
    let end = INVERSE_SQRT.get(segment + 1).copied().unwrap_or(0);
    let interpolated = msu(deposit_high(start), sub(start, end), within);
    long_shift_right(interpolated, exponent)
}

/// A normalising shift, at most thirty-one, as a signed shift count.
const fn to_count(shift: u32) -> i32 {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "a normalising shift is at most 31"
    )]
    let count = shift as i32;
    count
}

/// The same shift as a word.
pub(super) const fn to_word(shift: u32) -> i16 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a normalising shift is at most 31"
    )]
    let word = shift as i16;
    word
}

#[cfg(test)]
mod tests {
    use super::{
        Split, add, deposit_high, divide, high, inverse_sqrt, log2, long_add, long_mult, long_norm,
        long_shift_left, long_shift_left_checked, long_shift_right, long_shift_right_round,
        long_sub, low, mac, msu, msu_checked, mult, pow2, round, round_checked, saturate,
        shift_left, shift_right, sub,
    };

    #[test]
    fn sixteen_bit_addition_holds_at_the_ends_rather_than_wrapping() {
        assert_eq!(add(32_000, 1_000), 32_767);
        assert_eq!(add(-32_000, -1_000), -32_768);
        assert_eq!(add(100, -300), -200);
        assert_eq!(sub(-32_768, 1), -32_768);
        assert_eq!(sub(32_767, -1), 32_767);
        assert_eq!(sub(0, -32_768), 32_767);
        assert_eq!(saturate(70_000), 32_767);
        assert_eq!(saturate(-70_000), -32_768);
        assert_eq!(saturate(-32_768), -32_768);
    }

    #[test]
    fn shifts_hold_on_the_way_up_and_keep_the_sign_on_the_way_down() {
        assert_eq!(shift_left(0x4000, 1), 32_767);
        assert_eq!(shift_left(-0x4001, 1), -32_768);
        assert_eq!(shift_left(3, 2), 12);
        assert_eq!(shift_left(1, 20), 32_767);
        assert_eq!(shift_left(0, 20), 0);
        assert_eq!(shift_right(-3, 1), -2);
        assert_eq!(shift_right(-1, 2), -1, "rounding is toward minus infinity");
        assert_eq!(shift_right(-3, 20), -1);
        assert_eq!(shift_right(3, 20), 0);
        assert_eq!(long_shift_left(0x4000_0000, 1), i32::MAX);
        assert_eq!(long_shift_left(-0x4000_0001, 1), i32::MIN);
        assert_eq!(long_shift_left(12, -2), 3, "a negative count shifts right");
        assert_eq!(long_shift_right(-5, 1), -3);
        assert_eq!(long_shift_right(-5, 40), -1);
        assert_eq!(long_shift_right(3, -2), 12, "and the other way");
        assert_eq!(long_shift_left_checked(0x1000_0000, 3), (i32::MAX, true));
        assert_eq!(
            long_shift_left_checked(0x0fff_ffff, 3),
            (0x7fff_fff8, false)
        );
    }

    #[test]
    fn rounding_shifts_add_back_the_last_bit_out() {
        assert_eq!(long_shift_right_round(5, 1), 3);
        assert_eq!(long_shift_right_round(-5, 1), -2);
        assert_eq!(long_shift_right_round(4, 1), 2);
        assert_eq!(long_shift_right_round(0x1fff, 13), 1);
        assert_eq!(long_shift_right_round(0x0fff, 13), 0);
        assert_eq!(long_shift_right_round(7, 0), 7);
    }

    #[test]
    fn a_product_of_two_fractions_is_a_fraction() {
        // a half times a half is a quarter, in Q15 and in Q31
        assert_eq!(mult(16_384, 16_384), 8_192);
        assert_eq!(long_mult(16_384, 16_384), 0x2000_0000);
        // the one product that does not fit
        assert_eq!(mult(-32_768, -32_768), 32_767);
        assert_eq!(long_mult(-32_768, -32_768), i32::MAX);
        // truncation is toward minus infinity: 32767/32768 of a positive
        // integer loses a unit, of a negative one does not
        assert_eq!(mult(32_767, 5), 4);
        assert_eq!(mult(32_767, -5), -5);
        assert_eq!(mult(-1, 1), -1);
    }

    #[test]
    fn accumulation_holds_at_each_step() {
        assert_eq!(mac(i32::MAX - 1, 1, 1), i32::MAX);
        assert_eq!(msu(i32::MIN + 1, 1, 1), i32::MIN);
        assert_eq!(mac(10, 3, 4), 34);
        assert_eq!(long_add(i32::MAX, 1), i32::MAX);
        assert_eq!(long_sub(i32::MIN, 1), i32::MIN);
        // held first at the product, then added: not the exact sum
        assert_eq!(mac(-2, -32_768, -32_768), i32::MAX - 2);
        assert_eq!(msu_checked(0, 3, 4), (-24, false));
        assert_eq!(msu_checked(i32::MIN + 10, 3, 4), (i32::MIN, true));
        assert_eq!(msu_checked(0, -32_768, -32_768), (-i32::MAX, true));
    }

    #[test]
    fn rounding_takes_the_upper_half_after_adding_half_of_the_lower() {
        assert_eq!(round(0x0001_8000), 2);
        assert_eq!(round(0x0001_7fff), 1);
        assert_eq!(round(-0x0001_8000), -1);
        assert_eq!(round(i32::MAX), 32_767);
        assert_eq!(round_checked(0x7fff_8000), (32_767, true));
        assert_eq!(round_checked(0x7fff_7fff), (32_767, false));
        assert_eq!(high(0x1234_5678), 0x1234);
        assert_eq!(high(-1), -1);
        assert_eq!(low(0x1234_5678), 0x5678);
        assert_eq!(low(0x0000_8000), -32_768);
        assert_eq!(deposit_high(-2), -0x2_0000);
    }

    #[test]
    fn normalisation_counts_the_redundant_sign_bits() {
        assert_eq!(long_norm(0), 0);
        assert_eq!(long_norm(-1), 31);
        assert_eq!(long_norm(1), 30);
        assert_eq!(long_norm(i32::MIN), 0);
        assert_eq!(long_norm(i32::MAX), 0);
        assert_eq!(long_norm(0x0000_ffff), 15);
        assert_eq!(long_norm(-0x0001_0000), 15);
    }

    #[test]
    fn division_is_a_truncated_fraction() {
        assert_eq!(divide(1, 2), 16_384);
        assert_eq!(divide(1, 3), 10_922);
        assert_eq!(divide(2, 3), 21_845);
        assert_eq!(divide(7, 7), 32_767);
        assert_eq!(divide(0, 7), 0);
        assert_eq!(divide(0, 0), 0);
        assert_eq!(divide(8_000, 16_000), 16_384);
        assert_eq!(divide(32_766, 32_767), 32_766);
    }

    #[test]
    fn a_split_value_multiplies_like_the_whole() {
        let value = 0x1234_5678;
        let parts = Split::of(value);
        assert_eq!(parts.high, 0x1234);
        assert_eq!(parts.low, 0x2b3c);
        assert_eq!(parts.join(), value & !1, "only the last bit is lost");
        let halved = parts.times(16_384);
        assert!(
            (halved - value / 2).abs() <= 2,
            "{halved} against {}",
            value / 2
        );
        let negative = Split::of(-0x0123_4567);
        assert!(negative.low >= 0, "the lower half is always positive");
        assert_eq!(negative.join(), -0x0123_4568);
    }

    #[test]
    fn the_logarithm_is_the_table_interpolated() {
        assert_eq!(log2(0), (0, 0));
        assert_eq!(log2(-5), (0, 0));
        assert_eq!(log2(1), (0, 0));
        assert_eq!(log2(1 << 20), (20, 0));
        // 1.5 × 2^10 sits exactly on entry 16, log2(1 + 16/32)
        assert_eq!(log2(1536), (10, 19_167));
        for value in [3_i32, 1000, 65_537, 123_456_789, i32::MAX] {
            let (whole, fraction) = log2(value);
            let ours = f64::from(whole) + f64::from(fraction) / 32_768.0;
            let exact = f64::from(value).log2();
            assert!(
                (ours - exact).abs() < 1e-4,
                "log2({value}) = {ours}, not {exact}"
            );
        }
    }

    #[test]
    fn the_power_of_two_is_the_table_interpolated() {
        assert_eq!(pow2(0, 0), 1);
        assert_eq!(pow2(14, 0), 16_384);
        assert_eq!(pow2(14, 16_384), 23_170);
        assert_eq!(pow2(30, 0), 16_384 << 16);
        for (whole, fraction) in [(14_i16, 1_000_i16), (10, 32_000), (20, 5)] {
            let exact = 2_f64.powf(f64::from(whole) + f64::from(fraction) / 32_768.0);
            let ours = f64::from(pow2(whole, fraction));
            assert!((ours - exact).abs() <= exact * 1e-4 + 0.5, "{ours} {exact}");
        }
    }

    #[test]
    fn the_inverse_square_root_is_the_table_interpolated() {
        // one below 2^30: the table's first entry is one below 1.0
        assert_eq!(inverse_sqrt(1), 0x3fff_8000);
        assert_eq!(inverse_sqrt(4), 0x1fff_c000);
        assert_eq!(inverse_sqrt(0), 0x3fff_ffff);
        assert_eq!(inverse_sqrt(-3), 0x3fff_ffff);
        for value in [2_i32, 1000, 65_536, 1 << 22, 99_999_999] {
            let exact = f64::from(1_i32 << 30) / f64::from(value).sqrt();
            let ours = f64::from(inverse_sqrt(value));
            assert!(
                (ours - exact).abs() <= exact * 1e-3,
                "1/sqrt({value}): {ours} {exact}"
            );
        }
    }
}
