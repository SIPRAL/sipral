// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The fixed codebook: four signed unit pulses on interleaved tracks
//! (§3.8, Table 7, §4.1.4).

use super::arith::{add, mult, shift_left};

/// A pulse of `+1` and one of `−1`, in the codebook's Q13.
///
/// Not symmetric. `+1` in Q13 is 8192, which a sixteen-bit word holds, but
/// the conformance streams decode only with a positive pulse one unit
/// smaller: every stream's excitation comes out a unit off wherever a
/// positive pulse meets a gain that puts it on a rounding boundary.
const PLUS_ONE: i16 = 8191;
const MINUS_ONE: i16 = -8192;

/// Samples in a subframe.
pub(super) const SUBFRAME: usize = 40;

/// Equations 61 and 62 read backwards: three bits of position for each of
/// the first three pulses, four for the last — three of position and, below
/// them, one for which of the two tracks Table 7 gives it — and one sign bit
/// each, set for a positive pulse.
pub(super) fn decode(positions: u16, signs: u16) -> [i16; SUBFRAME] {
    let places = [
        5 * (positions & 7),
        5 * ((positions >> 3) & 7) + 1,
        5 * ((positions >> 6) & 7) + 2,
        5 * ((positions >> 10) & 7) + 3 + ((positions >> 9) & 1),
    ];
    let mut code = [0_i16; SUBFRAME];
    for (pulse, place) in places.into_iter().enumerate() {
        let positive = (signs >> pulse) & 1 == 1;
        if let Some(slot) = code.get_mut(usize::from(place)) {
            *slot = if positive { PLUS_ONE } else { MINUS_ONE };
        }
    }
    code
}

/// Equation 48: for a pitch delay shorter than the subframe, the vector is
/// passed through `1 / (1 − βz^−T)` of equation 46 within the subframe, so
/// each pulse is echoed a delay later at `β` times its height — and, for a
/// delay under half the subframe, echoed again from the echo. `beta` is the
/// last subframe's quantized pitch gain within its bounds, Q14.
pub(super) fn sharpen(code: &mut [i16; SUBFRAME], delay: i16, beta: i16) {
    let Ok(delay) = usize::try_from(delay) else {
        return;
    };
    if delay >= SUBFRAME || delay == 0 {
        return;
    }
    let factor = shift_left(beta, 1);
    for n in delay..SUBFRAME {
        let echo = mult(code.get(n - delay).copied().unwrap_or(0), factor);
        if let Some(slot) = code.get_mut(n) {
            *slot = add(*slot, echo);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MINUS_ONE, PLUS_ONE, decode, sharpen};

    #[test]
    fn the_pulses_land_on_their_tracks() {
        // every position index zero, all signs negative: pulses at 0, 1, 2, 3
        let code = decode(0, 0);
        assert_eq!(&code[..5], &[MINUS_ONE, MINUS_ONE, MINUS_ONE, MINUS_ONE, 0]);
        // the fourth pulse's extra bit moves it to the track starting at 4
        let code = decode(1 << 9, 0b1000);
        assert_eq!(code[4], PLUS_ONE);
        assert_eq!(code[3], 0);
        // the largest indices reach the end of each track
        let code = decode(0x1fff, 0b1111);
        for place in [35, 36, 37, 39] {
            assert_eq!(code[place], PLUS_ONE, "position {place}");
        }
        // equation 62's example weights: C = m0/5 + 8 m1/5 + 64 m2/5 + 512 (2 m3/5 + jx)
        let code = decode(3 + 8 * 2 + 64 * 7 + 512 * (2 * 5 + 1), 0b0101);
        assert_eq!(code[15], PLUS_ONE);
        assert_eq!(code[11], MINUS_ONE);
        assert_eq!(code[37], PLUS_ONE);
        assert_eq!(code[29], MINUS_ONE);
    }

    #[test]
    fn sharpening_echoes_each_pulse_one_delay_later() {
        let mut code = decode(0, 0b0001);
        // 0.5 in Q14
        sharpen(&mut code, 25, 8192);
        assert_eq!(code[0], PLUS_ONE);
        assert_eq!(code[25], 4095, "half of 8191, rounded down");
        // a delay of a whole subframe or more leaves the vector alone
        let mut code = decode(0, 0b0001);
        sharpen(&mut code, 40, 8192);
        assert_eq!(code.iter().filter(|value| **value != 0).count(), 4);
    }

    /// Below half the subframe the filter's recursion shows: the echo is
    /// echoed.
    #[test]
    fn a_short_delay_echoes_the_echo() {
        let mut code = [0_i16; 40];
        code[0] = PLUS_ONE;
        sharpen(&mut code, 15, 8192);
        assert_eq!(code[15], 4095);
        assert_eq!(code[30], 2047);
    }
}
