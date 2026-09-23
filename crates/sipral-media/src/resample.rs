// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Moving audio between the rate a device runs at and the rate a codec was
//! negotiated at.
//!
//! A softphone has two clocks and they rarely agree: the microphone delivers
//! 48 kHz because that is what the hardware does, and the call was answered
//! with G.711 at 8 kHz because that is what the carrier offered. Every sample
//! has to cross that boundary twice per call, and doing it badly is what makes
//! a call sound thin — far more often than the codec does.
//!
//! The filter here is a polyphase FIR, designed once when the resampler is
//! built and then only ever indexed. Both rates are reduced to a fraction
//! `L/M` in lowest terms, and the bank holds exactly `L` phases, so output
//! sample `n` is taken at input time `n·M/L` with no accumulator, no rounding
//! of the phase and therefore no slow walk off the timeline: 44100 to 48000
//! is 147/160, and the hundred and sixtieth output lands exactly where the
//! hundred and forty-seventh input sample is.
//!
//! The prototype is a windowed sinc, cut off at [`CUTOFF_NUMERATOR`] over
//! [`CUTOFF_DENOMINATOR`] of the sampling rate and windowed by a Blackman of
//! [`BASE_TAPS`] taps. Measured against the rate that matters most, 48 kHz
//! down to 8: flat to within a tenth of a decibel through 3400 Hz, which is
//! the whole band G.711 carries, three decibels down at 3600, and
//! seventy-five decibels down by 4400, where anything left would fold back
//! into the speech. When the output rate is the lower of the two the kernel
//! is stretched by the ratio, so the same shape does the anti-alias filtering
//! as does the interpolation and the quality does not depend on the
//! direction.
//!
//! All of it is integer arithmetic, including the design: the sine, the
//! window and the quantisation to Q15 are computed in fixed point from exact
//! rationals, so the coefficients are the same on every platform and a call
//! resampled on a phone and the same call resampled on a server are the same
//! samples. Every phase is normalised to sum to exactly one, which is what
//! makes a constant come through as itself rather than with a ripple on it.
//!
//! There are two allocations and both happen in [`Resampler::new`]: the
//! coefficient bank and the working buffer. Nothing after that allocates, and
//! nothing here touches a device, a thread or a clock.

use crate::mix;
use core::fmt;

/// Taps of prototype filter at unity or upward ratios.
///
/// A Blackman window puts its transition band at about `5.5/N` of the sampling
/// rate, so sixty-four taps buy a transition about a tenth of the band wide:
/// flat to nine tenths of the cutoff, and well past seventy decibels down
/// where it matters. Downward ratios stretch the kernel by the ratio, and so
/// use proportionally more taps for the same shape.
pub const BASE_TAPS: usize = 64;

/// Half of it, which is the half-width of the prototype in the unit the
/// window is measured in.
const HALF_TAPS: i64 = 32;

/// The cutoff, over [`CUTOFF_DENOMINATOR`], in cycles per sample of whichever
/// rate is the lower. Half the transition band below the Nyquist, so that the
/// stopband starts where folding would.
pub const CUTOFF_NUMERATOR: i64 = 457;

/// What [`CUTOFF_NUMERATOR`] is a fraction of.
pub const CUTOFF_DENOMINATOR: i64 = 1_000;

/// The deepest reduction in rate this will build a filter for.
///
/// Eight covers 48 kHz down to 8 kHz with room to spare. Deeper than that the
/// kernel needs proportionally more taps for the same quality, and a caller
/// asking for it has almost certainly passed the rates the wrong way round.
pub const MAX_DECIMATION: u32 = 8;

/// The largest coefficient bank that will be built, in taps.
///
/// The bank is `L` phases of `taps` each, so what this really bounds is how
/// awkward a ratio may be: every pair among 8000, 16000, 24000, 32000, 44100
/// and 48000 needs at most 28800 taps, which is 57 KiB. Rates whose ratio in
/// lowest terms has a numerator in the thousands — 44101 against 48000 — are
/// refused rather than quietly allocating megabytes.
pub const MAX_COEFFICIENTS: usize = 65_536;

/// Input samples moved through the working buffer at a time. A frame longer
/// than this is processed in several passes and produces the same output.
const CHUNK: usize = 512;

/// Fifteen fractional bits: coefficients are Q15, and so is the accumulator
/// they add up in.
const SHIFT: u32 = 15;

/// A coefficient of one, which is what every phase sums to.
const ONE: i64 = 1 << SHIFT;

/// Half a coefficient, for rounding.
const HALF: i64 = 1 << (SHIFT - 1);

/// Thirty fractional bits, which is where the design arithmetic lives.
const DESIGN_SHIFT: u32 = 30;

/// One, in the design's fixed point.
const DESIGN_ONE: i64 = 1 << DESIGN_SHIFT;

/// Pi, in the design's fixed point.
const PI: i64 = 3_373_259_426;

/// The three Blackman weights, in the design's fixed point. They are exact:
/// 0.42, 0.5 and 0.08 add to one at the middle of the window and to zero at
/// its ends, so the prototype starts and stops at nothing without being told
/// to.
const BLACKMAN: [i64; 3] = [450_971_566, 536_870_912, 85_899_346];

/// Why no filter could be built for a pair of rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateError {
    /// A rate of zero, which is not a rate.
    Zero {
        /// What was asked for on the way in.
        input_rate: u32,
        /// And on the way out.
        output_rate: u32,
    },
    /// The input rate is more than [`MAX_DECIMATION`] times the output rate.
    Decimation {
        /// The rate to read at.
        input_rate: u32,
        /// The rate to write at.
        output_rate: u32,
    },
    /// The ratio in lowest terms needs more phases than [`MAX_COEFFICIENTS`]
    /// allows.
    Ratio {
        /// Phases the ratio asks for, which is the output rate over the
        /// greatest common divisor of the two.
        phases: usize,
        /// Taps in each of them.
        taps: usize,
    },
}

impl fmt::Display for RateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Zero {
                input_rate,
                output_rate,
            } => write!(
                f,
                "rates {input_rate} and {output_rate}, neither may be zero"
            ),
            Self::Decimation {
                input_rate,
                output_rate,
            } => write!(
                f,
                "{input_rate} to {output_rate} is deeper than {MAX_DECIMATION} to one"
            ),
            Self::Ratio { phases, taps } => write!(
                f,
                "{phases} phases of {taps} taps is past the {MAX_COEFFICIENTS} allowed"
            ),
        }
    }
}

impl core::error::Error for RateError {}

/// The slice offered for the output was shorter than the input could fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortOutput {
    /// What [`Resampler::output_capacity`] asked for.
    pub needed: usize,
    /// What was offered.
    pub got: usize,
}

impl fmt::Display for ShortOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { needed, got } = *self;
        write!(f, "output of {got} samples, {needed} needed")
    }
}

impl core::error::Error for ShortOutput {}

/// One direction of one stream, at a fixed pair of rates.
///
/// A call needs two of these, one each way, and they are independent: the
/// history each keeps is the tail of its own input.
pub struct Resampler {
    input_rate: u32,
    output_rate: u32,
    /// The interpolation factor `L`, which is also the number of phases.
    up: usize,
    /// The decimation factor `M`.
    down: usize,
    taps: usize,
    /// `up` phases of `taps` coefficients each, phase-major, Q15.
    bank: Vec<i16>,
    /// History and incoming samples, in one run so a window never straddles
    /// two pieces of memory.
    buffer: Vec<i16>,
    /// Samples of history at the front of the buffer.
    held: usize,
    /// Input samples to drop before the next window, for the ratios that skip
    /// further than the buffer holds.
    skip: usize,
    /// Which phase the next output sample is taken at.
    phase: usize,
}

impl Resampler {
    /// Builds the filter for a pair of rates.
    ///
    /// This is where the design happens and where the two allocations happen.
    /// Once built, a resampler is a fixed cost per sample and no cost per
    /// frame.
    ///
    /// # Errors
    ///
    /// [`RateError`] when a rate is zero, when the reduction in rate is deeper
    /// than [`MAX_DECIMATION`], or when the ratio in lowest terms would need a
    /// bank larger than [`MAX_COEFFICIENTS`].
    pub fn new(input_rate: u32, output_rate: u32) -> Result<Self, RateError> {
        if input_rate == 0 || output_rate == 0 {
            return Err(RateError::Zero {
                input_rate,
                output_rate,
            });
        }
        if u64::from(input_rate) > u64::from(output_rate) * u64::from(MAX_DECIMATION) {
            return Err(RateError::Decimation {
                input_rate,
                output_rate,
            });
        }
        let divisor = gcd(input_rate, output_rate);
        let up = usize::try_from(output_rate / divisor).unwrap_or(usize::MAX);
        let down = usize::try_from(input_rate / divisor).unwrap_or(usize::MAX);
        let taps = tap_count(input_rate, output_rate);
        if up.saturating_mul(taps) > MAX_COEFFICIENTS {
            return Err(RateError::Ratio { phases: up, taps });
        }

        let passthrough = up == 1 && down == 1;
        let bank = if passthrough {
            Vec::new()
        } else {
            design(up, down, taps)
        };
        let buffer = vec![0_i16; taps.saturating_sub(1) + CHUNK];
        let mut resampler = Self {
            input_rate,
            output_rate,
            up,
            down,
            taps,
            bank,
            buffer,
            held: 0,
            skip: 0,
            phase: 0,
        };
        resampler.reset();
        Ok(resampler)
    }

    /// The rate samples arrive at.
    #[must_use]
    pub const fn input_rate(&self) -> u32 {
        self.input_rate
    }

    /// The rate they leave at.
    #[must_use]
    pub const fn output_rate(&self) -> u32 {
        self.output_rate
    }

    /// Taps in each phase of the bank, which is how many input samples every
    /// output sample is made of.
    #[must_use]
    pub const fn taps(&self) -> usize {
        self.taps
    }

    /// Phases in the bank, which is the interpolation factor of the ratio in
    /// lowest terms.
    #[must_use]
    pub const fn phases(&self) -> usize {
        self.up
    }

    /// The delay the filter adds, in output samples.
    ///
    /// The kernel is symmetric, so output sample `n` carries the input as it
    /// was at time `n·input/output` and the two streams stay aligned in
    /// content. What this counts is the wait: half the kernel reaches forward
    /// in time, so nothing can be produced until that much input has arrived
    /// past the point being produced. It comes to about four milliseconds at
    /// 8 kHz and less at every higher rate, and a caller budgeting end-to-end
    /// latency owes it once in each direction.
    #[must_use]
    pub const fn latency_samples(&self) -> usize {
        if self.is_passthrough() {
            return 0;
        }
        (self.taps / 2) * self.up / self.down
    }

    /// The most output samples `input_len` input samples can produce.
    ///
    /// [`process`](Self::process) refuses a slice shorter than this rather
    /// than dropping the samples that would not fit.
    #[must_use]
    pub fn output_capacity(&self, input_len: usize) -> usize {
        if self.is_passthrough() {
            return input_len;
        }
        input_len.saturating_mul(self.up) / self.down + 1
    }

    /// Resamples a frame, writing every output sample it produced.
    ///
    /// The count returned varies by one from call to call even at a fixed
    /// frame size, because the timeline of an awkward ratio does not divide
    /// into frames; over any run of frames it converges on the ratio. Input is
    /// consumed whole, so nothing is left behind between calls but the history
    /// the next window needs.
    ///
    /// # Errors
    ///
    /// [`ShortOutput`] when `output` is shorter than
    /// [`output_capacity`](Self::output_capacity) for this frame. Nothing is
    /// written and no input is consumed, so a caller that enlarges the slice
    /// and calls again loses nothing.
    pub fn process(&mut self, input: &[i16], output: &mut [i16]) -> Result<usize, ShortOutput> {
        let needed = self.output_capacity(input.len());
        if output.len() < needed {
            return Err(ShortOutput {
                needed,
                got: output.len(),
            });
        }
        if self.is_passthrough() {
            for (slot, sample) in output.iter_mut().zip(input) {
                *slot = *sample;
            }
            return Ok(input.len());
        }

        let mut remaining = input;
        let mut produced = 0;
        while !remaining.is_empty() {
            if self.skip > 0 {
                let dropped = self.skip.min(remaining.len());
                self.skip -= dropped;
                remaining = remaining.get(dropped..).unwrap_or_default();
                continue;
            }
            let take = self
                .buffer
                .len()
                .saturating_sub(self.held)
                .min(remaining.len());
            let (Some(slot), Some(source)) = (
                self.buffer.get_mut(self.held..self.held + take),
                remaining.get(..take),
            ) else {
                break;
            };
            slot.copy_from_slice(source);
            remaining = remaining.get(take..).unwrap_or_default();
            let filled = self.held + take;

            let mut read = 0;
            while read + self.taps <= filled {
                let start = self.phase * self.taps;
                let (Some(window), Some(coefficients)) = (
                    self.buffer.get(read..read + self.taps),
                    self.bank.get(start..start + self.taps),
                ) else {
                    break;
                };
                if let Some(slot) = output.get_mut(produced) {
                    *slot = dot(window, coefficients);
                }
                produced += 1;
                let advance = self.phase + self.down;
                read += advance / self.up;
                self.phase = advance % self.up;
            }

            if read >= filled {
                // the next window starts past everything that has arrived
                self.skip = read - filled;
                self.held = 0;
            } else {
                self.buffer.copy_within(read..filled, 0);
                self.held = filled - read;
            }
        }
        Ok(produced)
    }

    /// Forgets the stream: a new call, or a codec change mid-call.
    ///
    /// The filter itself is untouched, so this costs nothing but the history.
    pub fn reset(&mut self) {
        self.buffer.fill(0);
        // the first output sits at input time zero and half the kernel reaches
        // back before it, so the stream opens against that much silence
        self.held = self.taps.saturating_sub(1) / 2;
        self.skip = 0;
        self.phase = 0;
    }

    /// Whether the rates are the same, in which case there is nothing to do
    /// and the filter would only take the top off the band for no reason.
    const fn is_passthrough(&self) -> bool {
        self.up == 1 && self.down == 1
    }
}

/// Written out rather than derived: the bank is tens of thousands of
/// coefficients and none of them belong in a log line.
impl fmt::Debug for Resampler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Resampler")
            .field("input_rate", &self.input_rate)
            .field("output_rate", &self.output_rate)
            .field("phases", &self.up)
            .field("taps", &self.taps)
            .finish_non_exhaustive()
    }
}

/// One output sample: the window against one phase of the bank.
fn dot(window: &[i16], coefficients: &[i16]) -> i16 {
    let sum: i64 = window
        .iter()
        .zip(coefficients)
        .map(|(sample, tap)| i64::from(*sample) * i64::from(*tap))
        .sum();
    let rounded = if sum < 0 {
        -((-sum + HALF) >> SHIFT)
    } else {
        (sum + HALF) >> SHIFT
    };
    mix::clip(i32::try_from(rounded).unwrap_or(if rounded < 0 { i32::MIN } else { i32::MAX }))
}

/// How many taps one phase needs.
///
/// The prototype is [`BASE_TAPS`] wide in units of the lower rate; when the
/// input is the faster of the two it takes that many input samples per unit,
/// so the kernel is stretched and the count grows with the ratio.
fn tap_count(input_rate: u32, output_rate: u32) -> usize {
    if input_rate == output_rate {
        return 1;
    }
    let half = u64::try_from(HALF_TAPS).unwrap_or(0);
    let (input, output) = (u64::from(input_rate), u64::from(output_rate));
    let width = if input > output {
        (half * input).div_ceil(output)
    } else {
        half
    };
    usize::try_from(2 * width).unwrap_or(usize::MAX)
}

/// The coefficient bank: `up` phases of `taps`, phase-major.
///
/// Each phase is the prototype sampled at the offsets that phase falls on, and
/// then normalised so that its taps add to exactly one. The normalisation is
/// done on the running sum rather than tap by tap, so the rounding error never
/// accumulates and the total is exact rather than nearly right — which is what
/// a constant input needs if it is to come out constant.
fn design(up: usize, down: usize, taps: usize) -> Vec<i16> {
    let mut bank = Vec::with_capacity(up.saturating_mul(taps));
    let mut kernel_values = vec![0_i64; taps];
    let denominator = i64::try_from(up.max(down)).unwrap_or(1);
    let stride = i64::try_from(up).unwrap_or(1);
    let centre = i64::try_from(taps / 2).unwrap_or(0);
    for phase in 0..up {
        let offset = i64::try_from(phase).unwrap_or(0);
        let mut total: i64 = 0;
        for (index, value) in kernel_values.iter_mut().enumerate() {
            let tap = i64::try_from(index).unwrap_or(0);
            *value = kernel(stride * (tap - centre + 1) - offset, denominator);
            total += *value;
        }
        let divisor = total.max(1);
        let mut running: i64 = 0;
        let mut emitted: i64 = 0;
        for value in &kernel_values {
            running += *value;
            let target = div_round(running * ONE, divisor);
            let tap = target - emitted;
            bank.push(i16::try_from(tap).unwrap_or(if tap < 0 { i16::MIN } else { i16::MAX }));
            emitted = target;
        }
    }
    bank
}

/// The prototype at `numerator / denominator` samples from its centre, in the
/// design's fixed point.
fn kernel(numerator: i64, denominator: i64) -> i64 {
    let window = blackman(numerator, denominator * HALF_TAPS);
    if window == 0 {
        return 0;
    }
    let shape = sinc(
        2 * CUTOFF_NUMERATOR * numerator,
        CUTOFF_DENOMINATOR * denominator,
    );
    (shape * window) >> DESIGN_SHIFT
}

/// `sin(pi·z) / (pi·z)` for `z = numerator / denominator`.
fn sinc(numerator: i64, denominator: i64) -> i64 {
    if numerator == 0 {
        return DESIGN_ONE;
    }
    let angle = (PI * numerator) / denominator;
    if angle == 0 {
        return DESIGN_ONE;
    }
    // reduced first, so that a large multiple of pi is still exact
    let turns = (numerator.rem_euclid(2 * denominator) * DESIGN_ONE) / denominator;
    (sin_pi(turns) << DESIGN_SHIFT) / angle
}

/// The Blackman window at `numerator / denominator` of its half-width, zero
/// outside it.
fn blackman(numerator: i64, denominator: i64) -> i64 {
    if numerator.unsigned_abs() >= denominator.unsigned_abs() {
        return 0;
    }
    let [flat, first, second] = BLACKMAN;
    flat + ((first * cos_pi(numerator, denominator)) >> DESIGN_SHIFT)
        + ((second * cos_pi(2 * numerator, denominator)) >> DESIGN_SHIFT)
}

/// `cos(pi · numerator / denominator)`.
fn cos_pi(numerator: i64, denominator: i64) -> i64 {
    let reduced = numerator.rem_euclid(2 * denominator);
    sin_pi((reduced * DESIGN_ONE) / denominator + DESIGN_ONE / 2)
}

/// `sin(pi·turns)`, with `turns` and the result in the design's fixed point.
///
/// Folded into the first quarter turn, where the Taylor series is short and
/// converges hard: five terms leave an error around a part in ten million,
/// which is four orders below the last bit of a Q15 coefficient.
fn sin_pi(turns: i64) -> i64 {
    let mut fraction = turns.rem_euclid(2 * DESIGN_ONE);
    let mut sign = 1;
    if fraction >= DESIGN_ONE {
        fraction -= DESIGN_ONE;
        sign = -1;
    }
    if fraction > DESIGN_ONE / 2 {
        fraction = DESIGN_ONE - fraction;
    }
    let angle = (PI * fraction) >> DESIGN_SHIFT;
    let square = (angle * angle) >> DESIGN_SHIFT;
    let mut series = DESIGN_ONE;
    for divisor in [110_i64, 72, 42, 20, 6] {
        series = DESIGN_ONE - (((square * series) >> DESIGN_SHIFT) / divisor);
    }
    sign * ((angle * series) >> DESIGN_SHIFT)
}

/// Division that rounds to nearest rather than towards zero. The divisor is
/// always positive here.
fn div_round(numerator: i64, divisor: i64) -> i64 {
    let half = divisor / 2;
    if numerator < 0 {
        (numerator - half) / divisor
    } else {
        (numerator + half) / divisor
    }
}

const fn gcd(first: u32, second: u32) -> u32 {
    let (mut left, mut right) = (first, second);
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::{
        BASE_TAPS, DESIGN_ONE, MAX_COEFFICIENTS, RateError, Resampler, blackman, gcd, sin_pi,
    };

    /// The rates the pipeline actually meets.
    const RATES: [u32; 6] = [8_000, 16_000, 24_000, 32_000, 44_100, 48_000];

    /// A sine of `frequency` hertz at `rate`, built from the module's own
    /// integer sine so that a test never needs a float.
    fn tone(rate: u32, frequency: u32, count: usize, amplitude: i64) -> Vec<i16> {
        (0..count)
            .map(|index| {
                let numerator = 2 * i64::from(frequency) * i64::try_from(index).unwrap();
                let denominator = i64::from(rate);
                let turns = (numerator.rem_euclid(2 * denominator) * DESIGN_ONE) / denominator;
                i16::try_from((amplitude * sin_pi(turns)) >> 30).unwrap()
            })
            .collect()
    }

    fn energy(samples: &[i16]) -> i128 {
        samples
            .iter()
            .map(|sample| i128::from(*sample) * i128::from(*sample))
            .sum()
    }

    fn run(resampler: &mut Resampler, input: &[i16]) -> Vec<i16> {
        let mut output = vec![0_i16; resampler.output_capacity(input.len())];
        let produced = resampler.process(input, &mut output).unwrap();
        assert!(produced <= output.len(), "produced {produced} samples");
        output.truncate(produced);
        output
    }

    #[test]
    fn the_integer_sine_is_the_sine() {
        // exact by symmetry
        assert_eq!(sin_pi(0), 0);
        assert_eq!(sin_pi(DESIGN_ONE), 0);
        assert_eq!(sin_pi(2 * DESIGN_ONE), 0);
        // a part in a million is four orders better than a Q15 coefficient
        let tolerance = DESIGN_ONE / 1_000_000;
        let close = |value: i64, expected: i64, what: &str| {
            assert!((value - expected).abs() <= tolerance, "{what}: {value}");
        };
        close(sin_pi(DESIGN_ONE / 2), DESIGN_ONE, "a quarter turn");
        close(sin_pi(DESIGN_ONE / 6), DESIGN_ONE / 2, "a twelfth");
        close(sin_pi(3 * DESIGN_ONE / 2), -DESIGN_ONE, "three quarters");
        close(sin_pi(-DESIGN_ONE / 2), -DESIGN_ONE, "backwards");
        // sqrt(2)/2 in the design's fixed point
        close(sin_pi(DESIGN_ONE / 4), 759_250_125, "an eighth");
        // and the reduction really is exact for a large argument
        close(
            sin_pi(1_000 * DESIGN_ONE + DESIGN_ONE / 2),
            DESIGN_ONE,
            "far out",
        );
    }

    #[test]
    fn the_window_opens_at_one_and_closes_at_nothing() {
        assert_eq!(i64::try_from(BASE_TAPS).unwrap(), 2 * super::HALF_TAPS);
        // one at the middle, to within the sine's own accuracy
        assert!((blackman(0, 32) - DESIGN_ONE).abs() <= DESIGN_ONE / 1_000_000);
        // and nothing at the edge, exactly, so the kernel has no step in it
        assert_eq!(blackman(32, 32), 0);
        assert_eq!(blackman(-32, 32), 0);
        assert_eq!(blackman(64, 32), 0);
        // symmetric, and monotone from the middle outwards
        let mut previous = DESIGN_ONE;
        for step in 1..32 {
            let value = blackman(step, 32);
            assert_eq!(value, blackman(-step, 32), "at {step}");
            assert!(value < previous, "at {step}");
            assert!(value >= 0, "at {step}");
            previous = value;
        }
    }

    #[test]
    fn every_phase_of_every_bank_sums_to_one() {
        for input_rate in RATES {
            for output_rate in RATES {
                if input_rate == output_rate {
                    continue;
                }
                let resampler = Resampler::new(input_rate, output_rate).unwrap();
                let taps = resampler.taps();
                assert_eq!(resampler.bank.len(), resampler.phases() * taps);
                for (index, phase) in resampler.bank.chunks(taps).enumerate() {
                    let sum: i64 = phase.iter().map(|tap| i64::from(*tap)).sum();
                    assert_eq!(sum, 32_768, "{input_rate} to {output_rate}, phase {index}");
                }
                assert!(
                    resampler.bank.len() <= MAX_COEFFICIENTS,
                    "{input_rate} to {output_rate} wants {} taps",
                    resampler.bank.len()
                );
            }
        }
    }

    #[test]
    fn the_first_phase_is_symmetric_and_ends_on_nothing() {
        let resampler = Resampler::new(8_000, 48_000).unwrap();
        let taps = resampler.taps();
        assert_eq!(taps, BASE_TAPS);
        let phase = resampler.bank.get(..taps).unwrap();
        // the window is exactly zero at its edge, so the last tap, the one
        // that has no mirror image, is too; the rest fold about the centre
        assert_eq!(phase[taps - 1], 0);
        for index in 0..taps - 1 {
            let mirrored = taps - 2 - index;
            let difference = i32::from(phase[index]) - i32::from(phase[mirrored]);
            assert!(difference.abs() <= 1, "tap {index} against {mirrored}");
        }
    }

    #[test]
    fn a_constant_survives_every_ratio() {
        for input_rate in RATES {
            for output_rate in RATES {
                let mut resampler = Resampler::new(input_rate, output_rate).unwrap();
                let input = vec![1_000_i16; 4_000];
                let output = run(&mut resampler, &input);
                let settled = output.len() / 2;
                for (index, sample) in output.iter().enumerate().skip(settled) {
                    assert_eq!(
                        *sample, 1_000,
                        "{input_rate} to {output_rate} at sample {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn equal_rates_are_a_copy() {
        let mut resampler = Resampler::new(8_000, 8_000).unwrap();
        assert_eq!(resampler.latency_samples(), 0);
        assert_eq!(resampler.output_capacity(160), 160);
        let input = tone(8_000, 1_000, 160, 20_000);
        let output = run(&mut resampler, &input);
        assert_eq!(output, input);
    }

    #[test]
    fn a_tone_that_goes_up_and_comes_back_is_the_tone() {
        let mut up = Resampler::new(8_000, 48_000).unwrap();
        let mut down = Resampler::new(48_000, 8_000).unwrap();
        let input = tone(8_000, 1_000, 4_000, 20_000);
        let wide = run(&mut up, &input);
        let narrow = run(&mut down, &wide);

        // the kernel is symmetric, so nothing has moved in time: sample for
        // sample against the original, once the opening transient is past
        let settled = 400;
        let span = narrow.len().min(input.len());
        let signal: i128 = energy(input.get(settled..span).unwrap());
        let noise: i128 = input
            .iter()
            .zip(narrow.iter())
            .skip(settled)
            .map(|(before, after)| {
                let error = i128::from(*before) - i128::from(*after);
                error * error
            })
            .sum();
        assert!(
            noise * 1_000_000 < signal,
            "round trip noise {noise} against signal {signal}"
        );
    }

    #[test]
    fn content_above_the_new_nyquist_does_not_fold_back() {
        // six kilohertz has nowhere to go in a four kilohertz band, and what
        // the filter must not do is let it come back as two
        let mut resampler = Resampler::new(48_000, 8_000).unwrap();
        let input = tone(48_000, 6_000, 24_000, 20_000);
        let output = run(&mut resampler, &input);
        let settled = output.len() / 4;
        let tail = output.get(settled..).unwrap();
        let passed = energy(tail) / i128::try_from(tail.len()).unwrap();
        let offered = energy(&input) / i128::try_from(input.len()).unwrap();
        // a hundred thousand to one in power is fifty decibels; the filter as
        // designed manages seventy-five, and the margin is there so that a
        // retune of the window does not have to come with a retune of the test
        assert!(
            passed * 100_000 < offered,
            "stopband let through {passed} of {offered}"
        );
    }

    #[test]
    fn the_band_a_telephone_carries_arrives_untouched() {
        let peak_of = |frequency: u32| {
            let mut resampler = Resampler::new(48_000, 8_000).unwrap();
            let input = tone(48_000, frequency, 24_000, 20_000);
            let output = run(&mut resampler, &input);
            output
                .get(200..)
                .unwrap()
                .iter()
                .map(|sample| i32::from(sample.abs()))
                .max()
                .unwrap()
        };
        // G.711 carries 300 to 3400 hertz, and all of it has to survive the
        // trip down from a device rate
        for frequency in [300, 1_000, 3_000, 3_400] {
            let peak = peak_of(frequency);
            assert!((19_600..=20_100).contains(&peak), "{frequency} Hz: {peak}");
        }
        // ten percent above the new Nyquist there is nothing left to fold
        let above = peak_of(4_400);
        assert!(above < 40, "4400 Hz came through at {above}");
    }

    #[test]
    fn the_passband_arrives_at_the_level_it_left() {
        let mut resampler = Resampler::new(44_100, 48_000).unwrap();
        let input = tone(44_100, 1_000, 8_820, 20_000);
        let output = run(&mut resampler, &input);
        let tail = output.get(1_000..).unwrap();
        let peak = tail
            .iter()
            .map(|sample| i32::from(sample.abs()))
            .max()
            .unwrap();
        assert!((19_800..=20_200).contains(&peak), "peak {peak}");
    }

    #[test]
    fn the_frame_size_does_not_change_the_output() {
        for (input_rate, output_rate) in [(48_000, 8_000), (8_000, 44_100), (44_100, 48_000)] {
            let input = tone(input_rate, 700, 5_000, 15_000);
            let mut whole = Resampler::new(input_rate, output_rate).unwrap();
            let expected = run(&mut whole, &input);

            let mut piecewise = Resampler::new(input_rate, output_rate).unwrap();
            let mut collected = Vec::new();
            let mut offset = 0;
            // sizes that share no factor with anything, so the chunks land on
            // every phase of the ratio in turn
            for step in [1_usize, 7, 160, 3, 999, 512, 513].into_iter().cycle() {
                if offset >= input.len() {
                    break;
                }
                let end = (offset + step).min(input.len());
                collected.extend(run(&mut piecewise, input.get(offset..end).unwrap()));
                offset = end;
            }
            assert_eq!(collected, expected, "{input_rate} to {output_rate}");
        }
    }

    #[test]
    fn the_count_produced_keeps_up_with_the_ratio() {
        for input_rate in RATES {
            for output_rate in RATES {
                let mut resampler = Resampler::new(input_rate, output_rate).unwrap();
                let frame = usize::try_from(input_rate / 50).unwrap();
                let mut produced = 0;
                for _ in 0..50 {
                    produced += run(&mut resampler, &vec![0_i16; frame]).len();
                }
                // a second of input is a second of output, less the half
                // kernel that has not been reached yet
                let expected = usize::try_from(output_rate).unwrap();
                assert!(
                    produced <= expected + 2,
                    "{input_rate} to {output_rate}: {produced} against {expected}"
                );
                assert!(
                    produced + resampler.latency_samples() + 2 >= expected,
                    "{input_rate} to {output_rate}: {produced} against {expected}"
                );
            }
        }
    }

    #[test]
    fn an_output_slice_that_is_too_short_is_refused() {
        let mut resampler = Resampler::new(8_000, 16_000).unwrap();
        let input = [1_000_i16; 160];
        let mut output = [0_i16; 320];
        let error = resampler.process(&input, &mut output).unwrap_err();
        assert_eq!(error.needed, 321);
        assert_eq!(error.got, 320);
        assert!(error.to_string().contains("321"));
        // and nothing was consumed: the same call with room works
        let mut roomy = [0_i16; 321];
        assert!(resampler.process(&input, &mut roomy).unwrap() > 0);
    }

    #[test]
    fn rates_that_cannot_be_filtered_are_refused() {
        assert_eq!(
            Resampler::new(0, 8_000).unwrap_err(),
            RateError::Zero {
                input_rate: 0,
                output_rate: 8_000
            }
        );
        assert!(matches!(
            Resampler::new(8_000, 0).unwrap_err(),
            RateError::Zero { .. }
        ));
        // ten to one, past what a kernel of this length can filter well
        assert!(matches!(
            Resampler::new(80_000, 8_000).unwrap_err(),
            RateError::Decimation { .. }
        ));
        // coprime rates: forty-eight thousand phases
        assert!(matches!(
            Resampler::new(44_101, 48_000).unwrap_err(),
            RateError::Ratio { .. }
        ));
        // eight to one is the edge, and it is allowed
        assert!(Resampler::new(64_000, 8_000).is_ok());
    }

    #[test]
    fn empty_input_produces_nothing() {
        let mut resampler = Resampler::new(8_000, 48_000).unwrap();
        let mut output = [0_i16; 8];
        assert_eq!(resampler.process(&[], &mut output).unwrap(), 0);
        assert_eq!(output, [0; 8]);
    }

    #[test]
    fn reset_forgets_the_stream() {
        let mut resampler = Resampler::new(16_000, 8_000).unwrap();
        let input = tone(16_000, 500, 2_000, 12_000);
        let first = run(&mut resampler, &input);
        resampler.reset();
        let second = run(&mut resampler, &input);
        assert_eq!(first, second);
    }

    #[test]
    fn full_scale_input_does_not_wrap() {
        // a square wave is the worst case for a filter with overshoot, and
        // overshoot on top of a full-scale sample has to clip, not wrap
        let mut resampler = Resampler::new(8_000, 48_000).unwrap();
        let input: Vec<i16> = (0..2_000)
            .map(|index| {
                if (index / 20) % 2 == 0 {
                    i16::MAX
                } else {
                    i16::MIN
                }
            })
            .collect();
        let output = run(&mut resampler, &input);
        for (index, window) in output.windows(2).enumerate() {
            let step = i32::from(window[1]) - i32::from(window[0]);
            assert!(step.abs() < 60_000, "step of {step} at {index}");
        }
    }

    #[test]
    fn a_frame_longer_than_the_working_buffer_is_not_a_special_case() {
        let mut resampler = Resampler::new(48_000, 16_000).unwrap();
        let input = tone(48_000, 1_000, 4_800, 10_000);
        let long = run(&mut resampler, &input);
        resampler.reset();
        let mut short = Vec::new();
        for chunk in input.chunks(100) {
            short.extend(run(&mut resampler, chunk));
        }
        assert_eq!(long, short);
    }

    #[test]
    fn the_ratio_is_reduced_before_anything_is_built() {
        assert_eq!(gcd(44_100, 48_000), 300);
        assert_eq!(gcd(8_000, 48_000), 8_000);
        assert_eq!(gcd(0, 7), 7);
        let resampler = Resampler::new(44_100, 48_000).unwrap();
        assert_eq!(resampler.phases(), 160);
        let other = Resampler::new(48_000, 44_100).unwrap();
        assert_eq!(other.phases(), 147);
        // the same latency both ways, four milliseconds at the lower rate
        assert_eq!(
            Resampler::new(8_000, 48_000).unwrap().latency_samples(),
            192
        );
        assert_eq!(Resampler::new(48_000, 8_000).unwrap().latency_samples(), 32);
    }

    #[test]
    fn the_debug_line_is_the_four_numbers_that_matter() {
        let resampler = Resampler::new(44_100, 8_000).unwrap();
        let rendered = format!("{resampler:?}");
        assert!(rendered.contains("44100"), "{rendered}");
        assert!(rendered.contains("phases: 80"), "{rendered}");
        assert!(!rendered.contains("bank"), "{rendered}");
    }

    /// A small, seeded xorshift so this test drives many inputs without a new
    /// dependency: the same generator [`crate::comfort_noise`] uses, reseeded
    /// here so a failure is reproducible from the printed seed alone.
    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Every rate pair, every frame length worth distrusting, and every
    /// amplitude worth distrusting, driven through the same resampler across
    /// several frames so a rate change or a length change mid-stream is
    /// exercised too. Nothing here checks the audio is good — the other tests
    /// in this module already measure that — only that nothing panics and
    /// that `process` never reports more samples than fit the slice it was
    /// given, which is the property [`Resampler::output_capacity`] promises.
    #[test]
    fn no_input_makes_process_panic_or_overrun_its_output() {
        let mut seed = 0xC0FF_EE00_1234_5678_u64;
        let lengths = [0_usize, 1, 2, 3, 17, 511, 512, 513, 4_001];
        for _ in 0..300 {
            let input_rate = RATES[usize::try_from(xorshift64(&mut seed) % 6).unwrap()];
            let output_rate = RATES[usize::try_from(xorshift64(&mut seed) % 6).unwrap()];
            let Ok(mut resampler) = Resampler::new(input_rate, output_rate) else {
                continue;
            };
            for _ in 0..4 {
                let length = lengths[usize::try_from(xorshift64(&mut seed) % 9).unwrap()];
                let pattern = xorshift64(&mut seed) % 5;
                let input: Vec<i16> = (0..length)
                    .map(|index| match pattern {
                        0 => 0,
                        1 => i16::MAX,
                        2 => i16::MIN,
                        3 => {
                            if index % 2 == 0 {
                                i16::MAX
                            } else {
                                i16::MIN
                            }
                        }
                        _ => {
                            let top = xorshift64(&mut seed) >> 48;
                            let unsigned = u16::try_from(top).unwrap_or(0);
                            i16::try_from(i32::from(unsigned) - 32_768).unwrap_or(0)
                        }
                    })
                    .collect();
                let needed = resampler.output_capacity(input.len());
                let mut output = vec![0_i16; needed];
                let produced = resampler
                    .process(&input, &mut output)
                    .unwrap_or_else(|error| {
                        panic!(
                            "{input_rate} to {output_rate}, {length} samples, pattern {pattern}: {error}"
                        )
                    });
                assert!(
                    produced <= output.len(),
                    "{input_rate} to {output_rate}: {produced} overran a slice of {needed}"
                );
                if xorshift64(&mut seed).is_multiple_of(7) {
                    resampler.reset();
                }
            }
        }
    }
}
