// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The three things done with a set of LP coefficients: bandwidth
//! expansion, inverse filtering through `A(z)` and synthesis through
//! `1/A(z)` (equations 2, 77, 79 and A.12).

use super::arith::{
    long_abs, long_mult, long_norm, long_shift_left, long_shift_left_checked, long_shift_right,
    low, mac, msu_checked, round, round_checked,
};
use super::lsp::Coefficients;

/// `A(z/γ)`: each coefficient `ai` scaled by `γ^i`, with `γ` in Q15 and each
/// power of it rounded before it is used.
pub(super) fn expand(a: &Coefficients, gamma: i16) -> Coefficients {
    let mut out = *a;
    let mut factor = gamma;
    for slot in out.iter_mut().skip(1) {
        *slot = round(long_mult(*slot, factor));
        factor = round(long_mult(factor, gamma));
    }
    out
}

/// Inverse filtering through `A(z)`: `signal[start..start + out.len()]`
/// becomes its residual in `out`. The ten samples before `start` are the
/// filter's memory and must be there.
pub(super) fn residual(a: &Coefficients, signal: &[i16], start: usize, out: &mut [i16]) {
    for (n, slot) in out.iter_mut().enumerate() {
        let now = start + n;
        let mut sum = 0_i32;
        for (lag, coefficient) in a.iter().enumerate() {
            let past = now
                .checked_sub(lag)
                .and_then(|at| signal.get(at))
                .copied()
                .unwrap_or(0);
            sum = mac(sum, past, *coefficient);
        }
        // Q12 coefficients, doubled products: three bits up to Q16
        *slot = round(long_shift_left(sum, 3));
    }
}

/// Synthesis through `1/A(z)` (equation 77): `output[n] = input[n] −
/// Σ ai output[n − i]`, with `memory` holding the ten outputs before the
/// first, oldest first.
///
/// Returns whether any step of the arithmetic had to be held at the end of
/// its word. The Recommendation's text does not say what a decoder does when
/// its synthesis overflows; its conformance streams have one made to find
/// out, and they decode only if the decoder, on seeing this, scales its whole
/// excitation memory down by four and synthesises the subframe again (see
/// `Decoder::subframe`).
pub(super) fn synthesise(
    a: &Coefficients,
    input: &[i16],
    memory: &[i16; 10],
    output: &mut [i16],
) -> bool {
    let mut overflowed = false;
    for n in 0..input.len().min(output.len()) {
        let mut sum = long_mult(
            input.get(n).copied().unwrap_or(0),
            a.first().copied().unwrap_or(0),
        );
        for (lag, coefficient) in a.iter().enumerate().skip(1) {
            let past = if lag <= n {
                output.get(n - lag).copied().unwrap_or(0)
            } else {
                memory.get(10 + n - lag).copied().unwrap_or(0)
            };
            let (next, held) = msu_checked(sum, *coefficient, past);
            sum = next;
            overflowed |= held;
        }
        let (scaled, held) = long_shift_left_checked(sum, 3);
        overflowed |= held;
        let (sample, held) = round_checked(scaled);
        overflowed |= held;
        if let Some(slot) = output.get_mut(n) {
            *slot = sample;
        }
    }
    overflowed
}

/// `xb(n)` of A.3.7 and `d(n)` of equation 52: the target filtered
/// backwards through the impulse response, `Σ x(i) h(i−n)`.
///
/// The forty sums are scaled together so that the largest has thirteen
/// significant bits and a sign, and at most sixteen bits are gained doing
/// it: the searches compare these sums with each other and square them, so
/// what matters is that they share a scale and have room.
pub(super) fn backward(response: &[i16; 40], target: &[i16; 40]) -> [i16; 40] {
    let mut sums = [0_i32; 40];
    let mut largest = 0_i32;
    for (n, slot) in sums.iter_mut().enumerate() {
        let later = target.get(n..).unwrap_or_default();
        *slot = later
            .iter()
            .zip(response)
            .fold(0_i32, |sum, (x, h)| mac(sum, *x, *h));
        largest = largest.max(long_abs(*slot));
    }
    let shift = 18 - i32::try_from(long_norm(largest).min(16)).unwrap_or(16);
    let mut out = [0_i16; 40];
    for (slot, sum) in out.iter_mut().zip(sums) {
        *slot = low(long_shift_right(sum, shift));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{expand, residual, synthesise};

    /// Filtering through `A(z)` and back through `1/A(z)` gives the signal
    /// back, to within the rounding of each step.
    #[test]
    fn synthesis_undoes_the_residual() {
        let a = [4096, -3000, 1200, -300, 100, 0, 0, 0, 0, 0, 0];
        let signal: Vec<i16> = (0..60)
            .map(|n| i16::try_from((n * 373) % 2000 - 1000).unwrap())
            .collect();
        let mut error = [0_i16; 50];
        residual(&a, &signal, 10, &mut error);
        let memory: [i16; 10] = signal[..10].try_into().unwrap();
        let mut back = [0_i16; 50];
        assert!(!synthesise(&a, &error, &memory, &mut back));
        for (original, rebuilt) in signal[10..].iter().zip(back) {
            assert!((original - rebuilt).abs() <= 8, "{original} {rebuilt}");
        }
    }

    /// One pole at 0.5: an impulse decays by half a sample, rounded.
    #[test]
    fn a_single_pole_decays_as_worked_by_hand() {
        let a = [4096, -2048, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut input = [0_i16; 6];
        input[0] = 1000;
        let mut out = [0_i16; 6];
        assert!(!synthesise(&a, &input, &[0; 10], &mut out));
        assert_eq!(out, [1000, 500, 250, 125, 63, 32]);
    }

    #[test]
    fn a_filter_driven_past_the_top_of_the_word_says_so() {
        let a = [4096, -8000, 4000, 0, 0, 0, 0, 0, 0, 0, 0];
        let input = [20_000_i16; 40];
        let mut out = [0_i16; 40];
        assert!(synthesise(&a, &input, &[0; 10], &mut out));
    }

    #[test]
    fn expansion_scales_by_powers_of_gamma() {
        let a = [4096; 11];
        let half = expand(&a, 16_384);
        assert_eq!(half[0], 4096);
        assert_eq!(half[1], 2048);
        assert_eq!(half[2], 1024);
        assert_eq!(half[10], 4);
    }
}
