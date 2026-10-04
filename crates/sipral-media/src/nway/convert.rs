// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One tick of audio at one rate, as one tick at another.

use crate::resample::{RateError, Resampler};

/// A [`Resampler`] that produces exactly one tick per tick.
///
/// Between any two of 8, 16, 32 and 48 kHz a tick of 20 ms is a whole number
/// of samples at both rates, so once the filter is full every tick in
/// produces exactly one tick out. The first tick after a reset produces less,
/// because half the filter is still waiting for input; that tick is completed
/// with silence in front of what there is, and from then on the stream
/// carries the filter's delay and no more.
pub(crate) struct Converter {
    resampler: Resampler,
    /// Where the resampler writes, as long as it can write for one tick.
    scratch: Vec<i16>,
}

impl Converter {
    /// A converter for ticks of `input_tick` samples at `input_rate` into
    /// ticks at `output_rate`.
    pub(crate) fn new(
        input_rate: u32,
        output_rate: u32,
        input_tick: usize,
    ) -> Result<Self, RateError> {
        let resampler = Resampler::new(input_rate, output_rate)?;
        let scratch = vec![0; resampler.output_capacity(input_tick)];
        Ok(Self { resampler, scratch })
    }

    /// Converts one tick, filling the whole of `output`.
    pub(crate) fn run(&mut self, input: &[i16], output: &mut [i16]) {
        let produced = self
            .resampler
            .process(input, &mut self.scratch)
            .unwrap_or(0);
        let fresh = self
            .scratch
            .get(..produced.min(output.len()))
            .unwrap_or_default();
        if let Some((silence, rest)) = output.split_at_mut_checked(output.len() - fresh.len()) {
            silence.fill(0);
            rest.copy_from_slice(fresh);
        }
    }

    /// Forgets the stream, so the next tick starts from silence.
    pub(crate) fn reset(&mut self) {
        self.resampler.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::Converter;

    #[test]
    fn every_tick_is_full_from_the_first() {
        for (input_rate, output_rate) in [
            (8_000, 48_000),
            (48_000, 8_000),
            (16_000, 48_000),
            (48_000, 16_000),
            (32_000, 48_000),
            (48_000, 32_000),
            (48_000, 48_000),
        ] {
            let input_tick = usize::try_from(input_rate / 50).unwrap();
            let output_tick = usize::try_from(output_rate / 50).unwrap();
            let mut converter = Converter::new(input_rate, output_rate, input_tick).unwrap();
            let input = vec![10_000_i16; input_tick];
            let mut output = vec![0_i16; output_tick];
            for tick in 0..5 {
                converter.run(&input, &mut output);
                if tick > 0 {
                    // a constant comes through as itself once the filter is
                    // full, with no gap anywhere in the tick
                    assert!(
                        output.iter().all(|sample| *sample == 10_000),
                        "{input_rate} to {output_rate}, tick {tick}"
                    );
                }
            }
            // and the first tick after a reset starts from silence, unless
            // there is no filter to fill
            converter.reset();
            if input_rate == output_rate {
                continue;
            }
            converter.run(&input, &mut output);
            assert_eq!(output[0], 0, "{input_rate} to {output_rate} after a reset");
            assert_eq!(output[output_tick - 1], 10_000);
        }
    }
}
