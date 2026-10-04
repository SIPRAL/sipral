// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The quadrature mirror filters that split sixteen kilohertz into two bands
//! of eight and put them back together (ITU-T G.722 §5).
//!
//! Twenty-four taps, symmetric, and the same coefficients both ways. The
//! analysis pair takes two input samples and produces one sample of each
//! band; the synthesis pair takes one of each and produces two output
//! samples. That is the whole reason the codec's RTP clock is eight kilohertz
//! while it hears sixteen.

use super::tables::QMF;

/// Taps, and so the depth of the delay line the analysis side keeps.
const TAPS: usize = 24;

/// What each side keeps in its own delay line, which is half the taps because
/// each accumulator sees every other sample.
const HALF: usize = TAPS / 2;

/// §5.1: "limited to a range of –16384 to 16383".
const CEILING: i32 = 16_383;
const FLOOR: i32 = -16_384;

/// The coefficients are Table 11's, scaled by 2^13, and the input carries
/// fifteen fractional bits, so a product carries twenty-eight. §5.2.1 shifts
/// the analysis sum by `y - 15` and §5.2.2 shifts the synthesis sum by
/// `y - 16`: one bit less, which is the factor of two equations (4-3) and
/// (4-4) print in front of the synthesis sum and which a filter pair needs to
/// give back what it was handed.
const ANALYSIS_SHIFT: u32 = 13;
const SYNTHESIS_SHIFT: u32 = 12;

fn clamp(value: i32) -> i16 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the clamp above puts the value inside i16 before the cast"
    )]
    let limited = value.clamp(FLOOR, CEILING) as i16;
    limited
}

/// The transmit filter: sixteen kilohertz in, two bands of eight out.
#[derive(Debug, Clone)]
pub(super) struct Analysis {
    /// `XIN` at delay zero, then `XIN1` to `XIN23`.
    delay: [i16; TAPS],
}

impl Analysis {
    pub(super) const fn new() -> Self {
        Self { delay: [0; TAPS] }
    }

    pub(super) fn reset(&mut self) {
        self.delay = [0; TAPS];
    }

    /// Take the two samples of one eight-kilohertz period and return the
    /// lower and higher band values.
    ///
    /// `first` is the earlier of the two, so it is the one that ends up at an
    /// odd delay and meets the odd coefficients.
    pub(super) fn split(&mut self, first: i16, second: i16) -> (i16, i16) {
        self.push(first);
        self.push(second);

        let mut even = 0_i32;
        let mut odd = 0_i32;
        for tap in 0..HALF {
            even +=
                i32::from(*self.delay.get(tap * 2).unwrap_or(&0)) * QMF.get(tap * 2).unwrap_or(&0);
            odd += i32::from(*self.delay.get(tap * 2 + 1).unwrap_or(&0))
                * QMF.get(tap * 2 + 1).unwrap_or(&0);
        }

        (
            clamp((even + odd) >> ANALYSIS_SHIFT),
            clamp((even - odd) >> ANALYSIS_SHIFT),
        )
    }

    fn push(&mut self, sample: i16) {
        self.delay.rotate_right(1);
        if let Some(newest) = self.delay.first_mut() {
            *newest = sample;
        }
    }
}

/// The receive filter: two bands of eight kilohertz in, sixteen out.
#[derive(Debug, Clone)]
pub(super) struct Synthesis {
    /// `XD` and its eleven delays: the difference of the two bands.
    difference: [i16; HALF],
    /// `XS` and its eleven delays: their sum.
    sum: [i16; HALF],
}

impl Synthesis {
    pub(super) const fn new() -> Self {
        Self {
            difference: [0; HALF],
            sum: [0; HALF],
        }
    }

    pub(super) fn reset(&mut self) {
        self.difference = [0; HALF];
        self.sum = [0; HALF];
    }

    /// Take one sample of each band and return the two output samples of that
    /// eight-kilohertz period, earlier one first (§5.2.2, `SELECT`).
    pub(super) fn join(&mut self, lower: i16, higher: i16) -> (i16, i16) {
        self.difference.rotate_right(1);
        self.sum.rotate_right(1);
        if let Some(newest) = self.difference.first_mut() {
            *newest = lower.saturating_sub(higher);
        }
        if let Some(newest) = self.sum.first_mut() {
            *newest = lower.saturating_add(higher);
        }

        let mut even = 0_i32;
        let mut odd = 0_i32;
        for tap in 0..HALF {
            even +=
                i32::from(*self.difference.get(tap).unwrap_or(&0)) * QMF.get(tap * 2).unwrap_or(&0);
            odd += i32::from(*self.sum.get(tap).unwrap_or(&0)) * QMF.get(tap * 2 + 1).unwrap_or(&0);
        }

        (
            clamp(even >> SYNTHESIS_SHIFT),
            clamp(odd >> SYNTHESIS_SHIFT),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Analysis, Synthesis, TAPS};

    /// Analysis then synthesis with nothing in between is the filter pair's
    /// defining property: what comes out is what went in, delayed by the
    /// filter length and scaled by one.
    #[test]
    fn what_the_pair_takes_apart_it_puts_back_together() {
        let mut analysis = Analysis::new();
        let mut synthesis = Synthesis::new();

        // a chirp, so every frequency the filter has an opinion about is
        // present; a single tone would pass a filter that only handles one
        let input: Vec<i16> = (0..800)
            .map(|n| {
                let t = f64::from(n) / 16_000.0;
                let sweep = 200.0 + 6_800.0 * f64::from(n) / 800.0;
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "the sine is bounded by the amplitude, which is inside i16"
                )]
                let sample = (8_000.0 * (core::f64::consts::TAU * sweep * t).sin()) as i16;
                sample
            })
            .collect();

        let mut output = Vec::with_capacity(input.len());
        for pair in input.chunks_exact(2) {
            let (lower, higher) =
                analysis.split(*pair.first().unwrap_or(&0), *pair.get(1).unwrap_or(&0));
            let (first, second) = synthesis.join(lower, higher);
            output.push(first);
            output.push(second);
        }

        // the pair delays by two taps less than its length: the analysis
        // side reads the line after pushing both samples of the pair, which
        // is where the two go missing
        let delay = TAPS - 2;
        let (a, b) = (
            input.get(..input.len() - delay).unwrap_or_default(),
            output.get(delay..).unwrap_or_default(),
        );
        let energy: f64 = a.iter().map(|s| f64::from(*s) * f64::from(*s)).sum();
        let error: f64 = a
            .iter()
            .zip(b)
            .map(|(x, y)| {
                let e = f64::from(*x) - f64::from(*y);
                e * e
            })
            .sum();
        let ratio = 10.0 * (energy / error).log10();
        assert!(
            ratio > 55.0,
            "reconstruction is {ratio:.1} dB below the signal, which is not a filter pair"
        );
    }

    #[test]
    fn silence_in_is_silence_out() {
        let mut analysis = Analysis::new();
        let mut synthesis = Synthesis::new();
        for _ in 0..100 {
            let (lower, higher) = analysis.split(0, 0);
            assert_eq!((lower, higher), (0, 0));
            assert_eq!(synthesis.join(0, 0), (0, 0));
        }
    }

    /// A tone well inside the lower half has to come out of the lower band
    /// and not the higher one, or the two bands are swapped — which would
    /// still reconstruct, and would still be wrong on the wire.
    #[test]
    fn the_bands_are_the_way_round_they_are_named() {
        let tone = |n: i32, hertz: f64| {
            let t = f64::from(n) / 16_000.0;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the sine is bounded by the amplitude, which is inside i16"
            )]
            let sample = (8_000.0 * (core::f64::consts::TAU * hertz * t).sin()) as i16;
            sample
        };

        for (hertz, low_should_win) in [(500.0, true), (6_500.0, false)] {
            let mut analysis = Analysis::new();
            let mut low = 0_f64;
            let mut high = 0_f64;
            for pair in 0..800 {
                let (lower, higher) =
                    analysis.split(tone(pair * 2, hertz), tone(pair * 2 + 1, hertz));
                if pair > 50 {
                    low += f64::from(lower) * f64::from(lower);
                    high += f64::from(higher) * f64::from(higher);
                }
            }
            if low_should_win {
                assert!(
                    low > high * 100.0,
                    "{hertz} Hz gave low {low:.0}, high {high:.0}"
                );
            } else {
                assert!(
                    high > low * 100.0,
                    "{hertz} Hz gave low {low:.0}, high {high:.0}"
                );
            }
        }
    }
}
