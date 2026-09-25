// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Packet loss concealment for a G.711 stream.
//!
//! G.711 carries no redundancy of any kind, so a lost packet is twenty
//! milliseconds that nobody sent twice and the only material left to build
//! them from is the audio that arrived before them. Voiced speech is nearly
//! periodic over a few tens of milliseconds, which is the one property worth
//! leaning on: the concealer estimates the pitch period of the last audio it
//! saw, repeats it, attenuates it a little on every repetition, and cross-fades
//! back into the real stream when it resumes. Past [`MAX_GAP_MS`] it stops and
//! says so, because a repeated period that far from the last real sample has
//! nothing to do with what the far end said and comfort noise is the better
//! thing to play.
//!
//! Samples in and out are linear PCM at [`g711::CLOCK_RATE`], which is what
//! comes out of either companding law. The concealer does not decode anything
//! itself and holds no buffer per frame: the history is one fixed array, the
//! period being repeated is another, and a concealed frame is written straight
//! into the caller's slice. All of it is integer arithmetic, gains and
//! cross-fade weights in Q15, so a build with no floating point unit and a
//! build with one produce the same samples.
//!
//! # What is forced and what was chosen
//!
//! Forced, in the sense that any other answer would be wrong: the pitch is the
//! lag that maximises the normalised autocorrelation of the last window of
//! audio, and the splice adds the difference between the last real sample and
//! its counterpart one period earlier, which is the only correction that
//! continues a signal drifting under the periodicity — on a straight line it
//! reproduces the next sample exactly. The Q15 arithmetic is exact where it
//! matters: at the first concealed sample the gain is one and the correction
//! is whole, so that sample is determined, not approximated.
//!
//! The same constant is added again at every loop point, and what it does
//! there is worth stating exactly, because a lag is only ever the pitch to the
//! nearest sample and the arithmetic looks the same whether or not that is
//! true. With it, the step into the first sample of a repeat is the step the
//! source itself made into that sample. Without it, the step is whatever
//! separates the two ends of the lag, which is the same number only when the
//! lag is the true period exactly. The correction is re-applied, never
//! summed: an extension that kept accumulating the drift would walk away from
//! the voice it was measured on well before the sixty millisecond bound.
//!
//! Chosen here, from the behaviour wanted rather than from any published
//! table: the search range of 50 to 400 Hz, the preference for the longest lag
//! within five percent of the best score, the two and a half millisecond
//! shortest correlation window, the pitch carried across a gap to a history
//! too short to measure it again, the four millisecond cross-fade, the
//! smoothstep shape of it, the sixty millisecond bound, and the amplitude ramp
//! to zero at that bound with the gain held constant across each period and
//! the last four milliseconds faded out so the ramp lands on silence rather
//! than near it. A reader who wants to retune any of them should measure
//! rather than assume they came from somewhere authoritative.

use crate::g711;
use core::fmt;

/// The longest gap that is filled with waveform extension, in milliseconds.
///
/// Three frames at the default packetisation. Loss bursts longer than this
/// happen, and the honest answer to them is comfort noise.
pub const MAX_GAP_MS: u32 = 60;

/// The same bound counted in samples at [`g711::CLOCK_RATE`].
pub const MAX_GAP_SAMPLES: usize = g711::frame_samples(MAX_GAP_MS);

/// The shortest pitch period the search considers: 400 Hz, above any speaking
/// voice and most singing ones.
const MIN_PERIOD: usize = 20;

/// The longest: 50 Hz, below the deepest voice a telephone will carry.
const MAX_PERIOD: usize = 160;

/// How much recent audio the correlation is measured over. One maximum period
/// is enough to hold a whole cycle of the lowest pitch in range.
const WINDOW: usize = MAX_PERIOD;

/// Past audio kept per stream: a correlation window plus the furthest lag it
/// is compared against.
const HISTORY: usize = WINDOW + MAX_PERIOD;

/// The shortest correlation window worth a verdict: two and a half
/// milliseconds, a whole cycle of the highest pitch in range. A history
/// shorter than [`WINDOW`] + [`MAX_PERIOD`] — one frame after a gap started
/// it again — gives up window before lag range, down to this, so the search
/// still reaches the whole voice range as soon as there is this much audio
/// beyond one [`MAX_PERIOD`].
const MIN_WINDOW: usize = MIN_PERIOD;

/// The longest cross-fade, in samples. Four milliseconds is long enough to
/// hide a splice and short enough that two signals out of phase with each
/// other do not cancel audibly.
const OVERLAP: usize = 32;

/// Q15 one. Gains and cross-fade weights are fixed point with fifteen
/// fractional bits.
const ONE: i64 = 32_768;

/// The shift that goes with [`ONE`].
const SHIFT: u32 = 15;

/// How much better a lag must score to displace the best one: a candidate
/// within five percent of the best score wins on length instead. Expressed as
/// the square of the ratio, since the comparison is made on squared scores.
const MARGIN_NUMERATOR: i128 = 231;

/// The denominator of that ratio: 231/256 is 0.95 squared, near enough.
const MARGIN_DENOMINATOR: i128 = 256;

/// What the concealer produced for one lost frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Concealment {
    /// Waveform extension was written and can be played.
    Extended,
    /// Nothing has arrived on this stream yet, so there was nothing to extend.
    /// Silence was written.
    Cold,
    /// The gap has run past [`MAX_GAP_MS`]. Silence was written; play comfort
    /// noise until the stream resumes.
    Exhausted,
}

/// Fills the gaps a G.711 stream leaves behind, one stream per concealer.
///
/// Every frame the far end sent goes through [`received`](Self::received),
/// which keeps the history the extension is built from and repairs the splice
/// when a gap has just ended. Every frame it sent that did not arrive goes
/// through [`conceal`](Self::conceal), and every frame played to lengthen a
/// pause, which nobody sent, through [`stretch`](Self::stretch).
pub struct Concealer {
    history: History,
    gap: Option<Gap>,
    /// The pitch last measured over the whole voice range, kept across a
    /// gap: the voice that paused is the one that resumes, while the history
    /// after it is too short to measure that pitch again.
    pitch: Option<Pitch>,
}

impl Concealer {
    /// A concealer with no history, as at the start of a call.
    #[must_use]
    pub fn new() -> Self {
        Self {
            history: History {
                samples: [0; HISTORY],
                filled: 0,
            },
            gap: None,
            pitch: None,
        }
    }

    /// Take a frame that really arrived.
    ///
    /// If it is the first frame after a gap, its opening samples are
    /// cross-faded with the extension that was being played, in place, because
    /// splicing two waveforms that were never in phase clicks. The frame is
    /// remembered as the material for the next gap as it arrived, before
    /// that cross-fade: the fade's samples are partly the extension's, which
    /// is invented.
    ///
    /// The first frame after a gap starts the history again rather than
    /// joining it. What was remembered before the gap is no longer next to
    /// it in time — the gap's own samples are never remembered, below — and
    /// a history joined across one reads as periodic where it is not: after
    /// four lost frames of the lab's 350 + 440 Hz tone, whose period is five
    /// frames, the frame that ended the gap matched the one before the gap
    /// exactly, one frame back in the history, and the next gap repeated it
    /// as a one-frame period, opening on its first sample instead of the one
    /// after its last — a jump of up to the tone's whole amplitude. The pitch
    /// measured before the gap is kept, for the next gap to use while the
    /// history is still too short to measure it again.
    ///
    /// A gap made only of [`stretch`](Self::stretch)es is no hole: the frame
    /// after it is the one the far end sent next, and it joins the history.
    pub fn received(&mut self, frame: &mut [i16]) {
        let Some(mut gap) = self.gap.take() else {
            self.history.push(frame);
            return;
        };
        if gap.hole {
            self.history.filled = 0;
        }
        self.history.push(frame);
        gap.blend_into(frame);
    }

    /// Fill a frame the far end did send and this end did not get.
    ///
    /// The concealed samples are deliberately not fed back into the history:
    /// the next estimate should be made from what somebody actually said, not
    /// from what this invented.
    pub fn conceal(&mut self, frame: &mut [i16]) -> Concealment {
        self.extend(frame, true)
    }

    /// Fill a frame the far end never sent, played to lengthen the delay in
    /// a pause: the same extension as [`conceal`](Self::conceal), but nothing
    /// of the stream is missing, so the frame that follows is next to the
    /// history in time and does not start it again.
    pub fn stretch(&mut self, frame: &mut [i16]) -> Concealment {
        self.extend(frame, false)
    }

    fn extend(&mut self, frame: &mut [i16], lost: bool) -> Concealment {
        if self.gap.is_none() {
            let history = self.history.recent();
            self.gap = estimate_period(history, self.pitch).and_then(|estimate| {
                if let Some(measured) = estimate.measured {
                    self.pitch = Some(measured);
                }
                Gap::start(history, estimate.lag)
            });
        }
        let Some(gap) = self.gap.as_mut() else {
            frame.fill(0);
            return Concealment::Cold;
        };
        gap.hole |= lost;
        let spent = gap.emitted >= MAX_GAP_SAMPLES;
        for sample in frame.iter_mut() {
            *sample = gap.next_sample();
        }
        if spent {
            Concealment::Exhausted
        } else {
            Concealment::Extended
        }
    }

    /// Forget the stream: a new call, a codec change mid-call, or a hole in
    /// it this concealer was not asked to fill — silence played while a
    /// jitter buffer refilled, say — after which the history before it is no
    /// longer next to what comes, for the reason
    /// [`received`](Self::received) gives.
    pub fn reset(&mut self) {
        self.history.filled = 0;
        self.gap = None;
        self.pitch = None;
    }

    /// The period being repeated while a gap is open, in samples, for
    /// reporting.
    #[must_use]
    pub fn pitch_period(&self) -> Option<usize> {
        self.gap.as_ref().map(|gap| gap.period_len)
    }

    /// How many samples the current gap has run to, whether or not they were
    /// still within the bound.
    #[must_use]
    pub fn gap_samples(&self) -> usize {
        self.gap.as_ref().map_or(0, |gap| gap.emitted)
    }
}

impl Default for Concealer {
    fn default() -> Self {
        Self::new()
    }
}

/// Written out rather than derived: the interesting state is three numbers,
/// and the arrays behind them are five hundred samples nobody wants in a log
/// line.
impl fmt::Debug for Concealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Concealer")
            .field("history", &self.history.filled)
            .field("pitch_period", &self.pitch_period())
            .field("gap_samples", &self.gap_samples())
            .finish_non_exhaustive()
    }
}

/// The most recent [`HISTORY`] samples, oldest first.
struct History {
    samples: [i16; HISTORY],
    filled: usize,
}

impl History {
    fn push(&mut self, frame: &[i16]) {
        let start = frame.len().saturating_sub(HISTORY);
        let Some(tail) = frame.get(start..) else {
            return;
        };
        let keep = self.filled.min(HISTORY - tail.len());
        if keep < self.filled {
            self.samples.copy_within(self.filled - keep..self.filled, 0);
        }
        if let Some(slot) = self.samples.get_mut(keep..keep + tail.len()) {
            slot.copy_from_slice(tail);
        }
        self.filled = keep + tail.len();
    }

    fn recent(&self) -> &[i16] {
        self.samples.get(..self.filled).unwrap_or(&[])
    }
}

/// One gap in progress: the period being repeated and where in it we are.
struct Gap {
    period: [i16; MAX_PERIOD],
    period_len: usize,
    phase: usize,
    /// Length of the cross-fade at each loop point, never more than half a
    /// period or the fade would still be running when the next one starts.
    taper: usize,
    emitted: usize,
    /// How far the last real sample sat from its counterpart one period back:
    /// the drift the lag failed to account for.
    ///
    /// Added at the splice and at every loop point, then faded out over the
    /// taper. Adding it makes the step into `period[0]` the step the source
    /// made into that same sample; leaving it out makes the step the distance
    /// between the two ends of the lag instead.
    seam: i64,
    gain: i64,
    previous_gain: i64,
    /// Whether any of it stood in for a frame that was lost, rather than
    /// only lengthening a pause.
    hole: bool,
}

impl Gap {
    fn start(history: &[i16], period_len: usize) -> Option<Self> {
        let source = history.get(history.len().checked_sub(period_len)?..)?;
        let mut period = [0_i16; MAX_PERIOD];
        period.get_mut(..period_len)?.copy_from_slice(source);

        let last = i64::from(history.last().copied().unwrap_or(0));
        let seam = history
            .len()
            .checked_sub(period_len + 1)
            .and_then(|index| history.get(index))
            .map_or(0, |earlier| last - i64::from(*earlier));

        Some(Self {
            period,
            period_len,
            phase: 0,
            taper: OVERLAP.min(period_len / 2),
            emitted: 0,
            seam,
            gain: period_gain(0, period_len),
            // the audio before the gap was at full level, and the first period
            // fades from there down to its own gain
            previous_gain: ONE,
            hole: false,
        })
    }

    fn next_sample(&mut self) -> i16 {
        let sample = if self.emitted >= MAX_GAP_SAMPLES {
            0
        } else {
            self.extended()
        };
        self.emitted = self.emitted.saturating_add(1);
        self.phase += 1;
        if self.phase >= self.period_len {
            self.phase = 0;
            self.previous_gain = self.gain;
            self.gain = period_gain(self.emitted, self.period_len);
        }
        sample
    }

    fn extended(&self) -> i16 {
        let value = i64::from(self.period.get(self.phase).copied().unwrap_or(0));
        let level = if self.taper >= 2 && self.phase < self.taper {
            let weight = smoothstep(self.phase, self.taper);
            let gain = self.previous_gain + (((self.gain - self.previous_gain) * weight) >> SHIFT);
            let correction = self.seam * gain * (ONE - weight) / ONE;
            value * gain + correction
        } else {
            value * self.gain
        };
        to_pcm((level * closing_fade(self.emitted)) >> SHIFT)
    }

    /// Cross-fade the front of an arriving frame with the extension that would
    /// have continued, so the real stream comes back without a step.
    fn blend_into(&mut self, frame: &mut [i16]) {
        let span = OVERLAP.min(frame.len());
        if span < 2 {
            return;
        }
        for (step, sample) in frame.iter_mut().take(span).enumerate() {
            let synthetic = i64::from(self.next_sample());
            let weight = smoothstep(step, span);
            *sample = to_pcm(i64::from(*sample) * weight + synthetic * (ONE - weight));
        }
    }
}

/// The lag, in samples, whose normalised autocorrelation with the most recent
/// window is highest, preferring the longest lag that scores within
/// [`MARGIN_NUMERATOR`]/[`MARGIN_DENOMINATOR`] of it.
///
/// Longer is preferred because a lag of half the true period correlates almost
/// as well as the period itself, and repeating half a cycle buzzes where
/// repeating the whole one does not. The energy of the recent window is a
/// factor common to every lag, so it is left out of the comparison rather than
/// divided away.
///
/// The window is [`WINDOW`] long when the history allows it and shrinks,
/// down to [`MIN_WINDOW`], before the lag range does, so one short frame
/// after a gap is still searched over every voice pitch rather than only
/// the highest. A history too short even for that — one ten millisecond
/// frame holds a single cycle of a voice at 100 Hz — cannot tell a period
/// from anything else, and there the pitch last measured over the whole
/// range stands in, as the longest whole number of its cycles the history
/// holds. A cycle of it longer than the history says every lag the search
/// could reach is too short to be the voice's period, and so does less than
/// one short window beyond the shortest lag: either way what there is is
/// repeated whole. With no pitch known, the search covers the lags it can
/// reach.
fn estimate_period(history: &[i16], pitch: Option<Pitch>) -> Option<Estimate> {
    if history.is_empty() {
        return None;
    }
    let window_len = history
        .len()
        .saturating_sub(MAX_PERIOD)
        .clamp(MIN_WINDOW, WINDOW);
    let max_lag = MAX_PERIOD.min(history.len().saturating_sub(window_len));
    if max_lag == MAX_PERIOD {
        let (lag, best) = search(history, window_len, max_lag);
        let cycles = best.map_or(1, |best| cycles(history, window_len, lag, best));
        return Some(Estimate {
            lag,
            measured: Some(Pitch { lag, cycles }),
        });
    }
    if let Some(lag) = pitch.and_then(|pitch| pitch.within(history.len())) {
        return Some(Estimate {
            lag,
            measured: None,
        });
    }
    let lag = if max_lag < MIN_PERIOD || pitch.is_some() {
        history.len().min(MAX_PERIOD)
    } else {
        search(history, window_len, max_lag).0
    };
    Some(Estimate {
        lag,
        measured: None,
    })
}

/// What [`estimate_period`] settled on: the lag to repeat, and the pitch it
/// measured, when the history was long enough to search the whole range.
struct Estimate {
    lag: usize,
    measured: Option<Pitch>,
}

/// A pitch measured over the whole voice range: the lag the search chose,
/// and how many cycles of the voice it spans, since the search prefers the
/// longest of several lags that score alike and so often lands on two or
/// three periods rather than one.
#[derive(Clone, Copy)]
struct Pitch {
    lag: usize,
    cycles: usize,
}

impl Pitch {
    /// The longest whole number of cycles shorter than `available` samples,
    /// so that the sample one period before the last is still in the
    /// history, and no shorter than [`MIN_PERIOD`].
    fn within(self, available: usize) -> Option<usize> {
        (1..=self.cycles)
            .rev()
            .map(|count| (self.lag * count + self.cycles / 2) / self.cycles)
            .find(|lag| (MIN_PERIOD..available).contains(lag))
    }
}

/// The lag in `MIN_PERIOD..=max_lag` the search prefers, and the best score
/// any lag reached; `None` for the score, and the longest lag, when nothing
/// correlated positively at all.
fn search(history: &[i16], window_len: usize, max_lag: usize) -> (usize, Option<(i128, i128)>) {
    let mut best: Option<(i128, i128)> = None;
    let mut best_lag = max_lag;
    for lag in MIN_PERIOD..=max_lag {
        let Some(candidate) = score(history, window_len, lag) else {
            continue;
        };
        match best {
            None => {
                best = Some(candidate);
                best_lag = lag;
            }
            Some(incumbent) => {
                if outscores(candidate, incumbent) {
                    best = Some(candidate);
                    best_lag = lag;
                } else if scores_alike(candidate, incumbent) {
                    best_lag = lag;
                }
            }
        }
    }
    (best_lag, best)
}

/// How many cycles of the voice `lag` spans: the most it can be divided
/// into, each part still no shorter than [`MIN_PERIOD`], with a lag at one
/// part's length — to the nearest sample either way, since a part is rarely
/// a whole number of samples — scoring alike with `best`. One when no part
/// does.
fn cycles(history: &[i16], window_len: usize, lag: usize, best: (i128, i128)) -> usize {
    (2..=lag / MIN_PERIOD)
        .rev()
        .find(|&count| {
            let part = (lag + count / 2) / count;
            (part - 1..=part + 1).any(|candidate| {
                candidate >= MIN_PERIOD
                    && score(history, window_len, candidate)
                        .is_some_and(|score| scores_alike(score, best))
            })
        })
        .unwrap_or(1)
}

/// The correlation of the most recent `window_len` samples with the same
/// length `lag` samples earlier, as the product and the earlier stretch's
/// energy; `None` where the lag is no candidate at any strength.
fn score(history: &[i16], window_len: usize, lag: usize) -> Option<(i128, i128)> {
    let end = history.len().checked_sub(lag)?;
    let start = end.checked_sub(window_len)?;
    let recent = history.get(history.len() - window_len..)?;
    let past = history.get(start..end)?;
    let product: i64 = recent
        .iter()
        .zip(past)
        .map(|(near, far)| i64::from(*near) * i64::from(*far))
        .sum();
    // a negative correlation is not a candidate at any strength
    if product <= 0 {
        return None;
    }
    let power = energy(past);
    if power == 0 {
        return None;
    }
    Some((i128::from(product), i128::from(power)))
}

/// Whether one score beats another: r = product / sqrt(power), compared
/// without the square root.
fn outscores((product, power): (i128, i128), (best_product, best_power): (i128, i128)) -> bool {
    product * product * best_power > best_product * best_product * power
}

/// Whether one score is within [`MARGIN_NUMERATOR`]/[`MARGIN_DENOMINATOR`]
/// of another.
fn scores_alike((product, power): (i128, i128), (best_product, best_power): (i128, i128)) -> bool {
    product * product * best_power * MARGIN_DENOMINATOR
        >= best_product * best_product * power * MARGIN_NUMERATOR
}

fn energy(samples: &[i16]) -> i64 {
    samples
        .iter()
        .map(|sample| {
            let value = i64::from(*sample);
            value * value
        })
        .sum()
}

/// The Q15 gain for a period starting `emitted` samples into the gap.
///
/// A straight line from one at the start of the gap to zero at the bound, read
/// at the middle of the period so that neither the first period nor the last
/// is a step. Held constant across the period, which is what keeps the
/// repetition from beating against its own envelope.
fn period_gain(emitted: usize, period_len: usize) -> i64 {
    let centre = emitted.saturating_add(period_len / 2);
    let remaining = i64::try_from(MAX_GAP_SAMPLES.saturating_sub(centre)).unwrap_or(0);
    let bound = i64::try_from(MAX_GAP_SAMPLES).unwrap_or(1);
    remaining * ONE / bound
}

/// The Q15 fade applied over the last [`OVERLAP`] samples before the bound.
///
/// The per-period gain is held constant across a period and so cannot land on
/// zero exactly where the budget runs out; without this the extension would
/// stop on a step of up to half a period's worth of the ramp, which for the
/// lowest pitch in range is a sixth of the amplitude and audible as a click.
fn closing_fade(emitted: usize) -> i64 {
    let remaining = MAX_GAP_SAMPLES.saturating_sub(emitted);
    if remaining > OVERLAP {
        ONE
    } else {
        smoothstep(remaining, OVERLAP + 1)
    }
}

/// A cross-fade weight in Q15, rising from zero at `step` 0 to one at
/// `step == span - 1`.
///
/// Smoothstep rather than a straight line: it leaves the fade flat at both
/// ends, so neither end of a splice has a corner in it, and unlike a raised
/// cosine it is two multiplies and no table. `span` is at least two, which
/// every caller checks.
fn smoothstep(step: usize, span: usize) -> i64 {
    let (Ok(step), Ok(span)) = (i64::try_from(step), i64::try_from(span)) else {
        return ONE;
    };
    let fraction = ((step * ONE) / (span - 1)).clamp(0, ONE);
    let square = (fraction * fraction) >> SHIFT;
    let cube = (square * fraction) >> SHIFT;
    (3 * square - 2 * cube).clamp(0, ONE)
}

/// One Q15-scaled accumulator back to a sample, saturating rather than
/// wrapping: a seam correction on top of a full-scale sample can leave the
/// range, and a wrap there is the loudest artefact in the codebase.
fn to_pcm(scaled: i64) -> i16 {
    let value = (scaled >> SHIFT).clamp(i64::from(i16::MIN), i64::from(i16::MAX));
    i16::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        Concealer, Concealment, HISTORY, MAX_GAP_SAMPLES, MAX_PERIOD, MIN_PERIOD, ONE, OVERLAP,
        period_gain,
    };
    use crate::g711;

    /// A frame at the default packetisation, which is what a caller of this
    /// will be handing it.
    const FRAME: usize = 160;

    /// A triangle wave: exactly periodic, so its continuation past any point
    /// is known without a table, and full of steps a splice could break.
    fn triangle(index: usize, period: usize, peak: i32) -> i16 {
        let span = i32::try_from(period).unwrap();
        let phase = i32::try_from(index % period).unwrap();
        let half = span / 2;
        let value = if phase < half {
            (2 * peak * phase / half) - peak
        } else {
            peak - (2 * peak * (phase - half) / (span - half))
        };
        i16::try_from(value.clamp(-32_768, 32_767)).unwrap()
    }

    fn tone(range: std::ops::Range<usize>, period: usize, peak: i32) -> Vec<i16> {
        range.map(|n| triangle(n, period, peak)).collect()
    }

    fn energy(samples: &[i16]) -> i64 {
        samples
            .iter()
            .map(|sample| {
                let value = i64::from(*sample);
                value * value
            })
            .sum()
    }

    /// Fills a concealer with `frames` frames of a triangle and returns how
    /// many samples were fed, so a test can continue the wave from there.
    fn prime(concealer: &mut Concealer, frames: usize, period: usize, peak: i32) -> usize {
        for frame in 0..frames {
            let mut samples = tone(frame * FRAME..(frame + 1) * FRAME, period, peak);
            concealer.received(&mut samples);
        }
        frames * FRAME
    }

    #[test]
    fn the_search_range_is_the_pitch_range_of_a_voice() {
        let rate = usize::try_from(g711::CLOCK_RATE).unwrap();
        assert_eq!(rate / MIN_PERIOD, 400);
        assert_eq!(rate / MAX_PERIOD, 50);
        // the bound is three frames at the default packetisation
        assert_eq!(MAX_GAP_SAMPLES, 480);
        assert_eq!(
            MAX_GAP_SAMPLES,
            3 * g711::frame_samples(g711::DEFAULT_PTIME_MS)
        );
        // enough history to compare a whole window against the furthest lag
        assert_eq!(HISTORY, 320);
    }

    #[test]
    fn a_periodic_signal_is_extended_at_a_multiple_of_its_own_period() {
        let mut concealer = Concealer::new();
        let sent = prime(&mut concealer, 2, 40, 8_000);

        let mut patch = vec![0_i16; FRAME];
        assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);

        // the estimate has no business being anything but a whole number of
        // cycles of the wave it was measured on
        let period = concealer.pitch_period().unwrap();
        assert_eq!(period % 40, 0, "estimated {period}");
        assert!((MIN_PERIOD..=MAX_PERIOD).contains(&period));

        // with the period an exact multiple there is no drift to correct, so
        // the first concealed sample is the sample the far end would have sent
        let truth = tone(sent..sent + FRAME, 40, 8_000);
        assert_eq!(patch[0], truth[0]);

        // the rest is the same waveform, quieter
        for (extended, actual) in patch.iter().zip(truth.iter()) {
            if actual.abs() > 2_000 {
                assert_eq!(
                    extended.signum(),
                    actual.signum(),
                    "extension turned the wave over"
                );
            }
            assert!(extended.unsigned_abs() <= actual.unsigned_abs() + 1);
        }
        let ratio = energy(&patch) * 100 / energy(&truth);
        assert!((50..=100).contains(&ratio), "energy ratio {ratio}%");
    }

    #[test]
    fn the_splice_continues_a_straight_line_exactly() {
        // a ramp is periodic at no lag at all, so whatever the search picks the
        // correction has to carry the whole trend
        let mut concealer = Concealer::new();
        let ramp: Vec<i16> = (0..HISTORY)
            .map(|n| i16::try_from(-8_000 + 50 * i32::try_from(n).unwrap()).unwrap())
            .collect();
        let mut sent = ramp.clone();
        concealer.received(&mut sent);

        let mut patch = vec![0_i16; FRAME];
        assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);
        assert_eq!(patch[0], ramp[HISTORY - 1] + 50);
    }

    #[test]
    fn silence_conceals_as_silence() {
        let mut concealer = Concealer::new();
        let mut quiet = vec![0_i16; FRAME];
        concealer.received(&mut quiet);
        concealer.received(&mut quiet);

        let mut patch = vec![1_i16; FRAME];
        assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);
        assert!(patch.iter().all(|sample| *sample == 0));
    }

    #[test]
    fn a_held_level_decays_and_never_rises() {
        let mut concealer = Concealer::new();
        let mut level = vec![8_000_i16; FRAME];
        concealer.received(&mut level);
        concealer.received(&mut level);

        let mut previous = 8_000_i16;
        for _ in 0..3 {
            let mut patch = vec![0_i16; FRAME];
            concealer.conceal(&mut patch);
            for sample in patch {
                assert!(sample <= previous, "{sample} came after {previous}");
                previous = sample;
            }
        }
        // three frames is the whole bound, so the closing fade has taken it to
        // within a thousandth of the level it started from
        assert!(previous < 8, "the extension stopped on {previous}");
    }

    #[test]
    fn the_extension_fades_and_then_stops_at_the_bound() {
        let mut concealer = Concealer::new();
        prime(&mut concealer, 2, 40, 8_000);

        let mut frames = Vec::new();
        for _ in 0..3 {
            let mut patch = vec![0_i16; FRAME];
            assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);
            frames.push(patch);
        }
        assert!(energy(&frames[0]) > energy(&frames[1]));
        assert!(energy(&frames[1]) > energy(&frames[2]));
        assert!(energy(&frames[2]) * 4 < energy(&frames[0]));

        // 480 samples is the bound exactly, so the fourth frame is past it
        assert_eq!(concealer.gap_samples(), MAX_GAP_SAMPLES);
        let mut beyond = vec![7_i16; FRAME];
        assert_eq!(concealer.conceal(&mut beyond), Concealment::Exhausted);
        assert!(beyond.iter().all(|sample| *sample == 0));
        assert_eq!(concealer.gap_samples(), MAX_GAP_SAMPLES + FRAME);
    }

    #[test]
    fn a_gap_that_straddles_the_bound_is_extended_then_silent() {
        let mut concealer = Concealer::new();
        prime(&mut concealer, 2, 40, 8_000);

        // one frame twice the length of the bound: the first 480 samples are
        // extension and the rest is nothing at all
        let mut long = vec![7_i16; 2 * MAX_GAP_SAMPLES];
        assert_eq!(concealer.conceal(&mut long), Concealment::Extended);
        assert!(long.iter().take(MIN_PERIOD).any(|sample| *sample != 0));
        assert!(long.iter().skip(MAX_GAP_SAMPLES).all(|sample| *sample == 0));
    }

    #[test]
    fn a_stream_that_has_never_carried_audio_conceals_cold() {
        let mut concealer = Concealer::new();
        let mut first = vec![9_i16; FRAME];
        assert_eq!(concealer.conceal(&mut first), Concealment::Cold);
        assert!(first.iter().all(|sample| *sample == 0));
        assert_eq!(concealer.pitch_period(), None);
        assert_eq!(concealer.gap_samples(), 0);

        // and once something has arrived it has material to work with
        let mut real = vec![4_000_i16; FRAME];
        concealer.received(&mut real);
        assert!(real.iter().all(|sample| *sample == 4_000));
        let mut second = vec![0_i16; FRAME];
        assert_eq!(concealer.conceal(&mut second), Concealment::Extended);
    }

    #[test]
    fn the_stream_resumes_through_a_cross_fade() {
        let mut concealer = Concealer::new();
        prime(&mut concealer, 2, 40, 8_000);

        let mut patch = vec![0_i16; FRAME];
        concealer.conceal(&mut patch);
        let tail = *patch.last().unwrap();

        // a level far from where the extension left off, so a hard splice
        // would be plain in the numbers
        let mut resumed = vec![20_000_i16; FRAME];
        concealer.received(&mut resumed);

        let jump = i32::from(20_000_i16 - tail).abs();
        let seam = i32::from(resumed[0] - tail).abs();
        assert!(seam * 4 < jump, "seam {seam} against a jump of {jump}");
        assert_eq!(resumed[OVERLAP - 1], 20_000);
        assert!(resumed.iter().skip(OVERLAP).all(|sample| *sample == 20_000));
        assert_eq!(concealer.pitch_period(), None);
        assert_eq!(concealer.gap_samples(), 0);
    }

    /// The shape the lab's audio gate caught on a lossy link: four frames of
    /// the 350 + 440 Hz tone lost, one received, one more lost. The tone's
    /// period is five frames, so the frame that ended the first gap matched
    /// the one before it exactly, one frame back in a history joined across
    /// the gap, and the second gap repeated that frame as a one-frame period:
    /// it opened on the frame's first sample, not on the one after its last.
    /// The lab measured a jump of 6 396 against a tone whose steepest step is
    /// 3 027; every phase of the tone is tried here, and none may open further
    /// from the last sample than the tone itself ever moves in one.
    #[test]
    fn a_gap_after_a_gap_continues_the_tone_and_not_the_history() {
        let rate = f64::from(g711::CLOCK_RATE);
        let (low, high) = (
            2.0 * core::f64::consts::PI * 350.0 / rate,
            2.0 * core::f64::consts::PI * 440.0 / rate,
        );
        let amplitude = 4_900.0;
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        let lab = |n: usize, phase: f64| {
            (amplitude * ((low * n as f64 + phase).sin() + (high * n as f64 + 2.0 * phase).sin()))
                .round() as i16
        };
        let frame = |start: usize, phase: f64| -> Vec<i16> {
            (start..start + FRAME).map(|n| lab(n, phase)).collect()
        };
        let steepest = 2.0 * amplitude * ((low / 2.0).sin() + (high / 2.0).sin());

        for step in 0..40 {
            let phase = f64::from(step) * core::f64::consts::TAU / 40.0;
            let mut concealer = Concealer::new();
            let mut sent = 0;
            for _ in 0..10 {
                concealer.received(&mut frame(sent, phase));
                sent += FRAME;
            }
            for _ in 0..4 {
                concealer.conceal(&mut vec![0_i16; FRAME]);
                sent += FRAME;
            }
            let mut resumed = frame(sent, phase);
            concealer.received(&mut resumed);
            let last = f64::from(*resumed.last().unwrap());

            let mut next = vec![0_i16; FRAME];
            assert_eq!(concealer.conceal(&mut next), Concealment::Extended);
            let jump = (f64::from(next[0]) - last).abs();
            assert!(
                jump <= steepest + 100.0,
                "at phase {phase:.2} the second gap opened {jump:.0} away from the last \
                 sample, against a steepest step of {steepest:.0}"
            );
        }
    }

    /// After a gap that ran out, the frame that ends it fades in from
    /// silence; with a period of exactly one frame, a history joined across
    /// the gap handed that fade to the next gap as the period to repeat, and
    /// the extension opened on the silence the fade began with.
    #[test]
    fn a_gap_after_a_faded_resume_continues_what_was_received() {
        let period = FRAME;
        let peak = 8_000;
        let mut concealer = Concealer::new();
        let mut sent = prime(&mut concealer, 10, period, peak);

        let mut patch = vec![0_i16; FRAME];
        for _ in 0..4 {
            concealer.conceal(&mut patch);
            sent += FRAME;
        }
        assert_eq!(
            concealer.conceal(&mut vec![0_i16; FRAME]),
            Concealment::Exhausted
        );
        sent += FRAME;

        let mut resumed = tone(sent..sent + FRAME, period, peak);
        concealer.received(&mut resumed);
        let last = i32::from(*resumed.last().unwrap());

        let mut next = vec![0_i16; FRAME];
        assert_eq!(concealer.conceal(&mut next), Concealment::Extended);
        // the triangle's own step is 2 * peak * 2 / period, 200 here
        let jump = (i32::from(next[0]) - last).abs();
        assert!(
            jump <= 400,
            "the next gap opened {jump} away from the last sample"
        );
    }

    #[test]
    fn a_frame_that_follows_no_gap_is_left_alone() {
        let mut concealer = Concealer::new();
        let mut first = vec![1_234_i16; FRAME];
        concealer.received(&mut first);
        let mut second = vec![-4_321_i16; FRAME];
        concealer.received(&mut second);
        assert!(second.iter().all(|sample| *sample == -4_321));
    }

    #[test]
    fn one_short_frame_is_enough_history() {
        let mut concealer = Concealer::new();
        let mut sent = tone(0..MIN_PERIOD, 40, 8_000);
        concealer.received(&mut sent);

        let mut patch = vec![0_i16; FRAME];
        assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);
        // too little to correlate: everything there is becomes the period, and
        // the repetition starts where the frame started
        assert_eq!(concealer.pitch_period(), Some(MIN_PERIOD));
        assert_eq!(patch[0], sent[0]);
    }

    #[test]
    fn full_scale_input_does_not_wrap() {
        let mut concealer = Concealer::new();
        let mut floor = vec![i16::MIN; FRAME];
        concealer.received(&mut floor);
        concealer.received(&mut floor);

        let mut patch = vec![0_i16; FRAME];
        concealer.conceal(&mut patch);
        assert_eq!(patch[0], i16::MIN);
        assert!(
            patch.iter().all(|sample| *sample <= 0),
            "a negative extension came back positive"
        );

        // the worst case for the correlation: alternating full scale, which
        // correlates perfectly at every even lag and inversely at every odd one
        let mut concealer = Concealer::new();
        let mut nyquist: Vec<i16> = (0..HISTORY)
            .map(|n| if n % 2 == 0 { i16::MIN } else { i16::MAX })
            .collect();
        concealer.received(&mut nyquist);
        let mut patch = vec![0_i16; FRAME];
        concealer.conceal(&mut patch);
        assert_eq!(concealer.pitch_period().unwrap() % 2, 0);
        // the first sample is at full gain by construction; the second is
        // already a shade into the fade the taper starts
        assert_eq!(patch[0], i16::MIN);
        assert!(patch[1] > 32_000, "{} is not full scale", patch[1]);
        assert!(patch[2] < -32_000, "{} is not full scale", patch[2]);
    }

    #[test]
    fn a_frame_longer_than_the_history_keeps_its_tail() {
        let mut concealer = Concealer::new();
        let mut opening = vec![100_i16; 4 * HISTORY];
        let tail = 5_000_i16;
        for sample in opening.iter_mut().skip(3 * HISTORY) {
            *sample = tail;
        }
        concealer.received(&mut opening);

        let mut patch = vec![0_i16; FRAME];
        concealer.conceal(&mut patch);
        assert_eq!(patch[0], tail);
    }

    #[test]
    fn empty_frames_are_not_a_special_case() {
        let mut concealer = Concealer::new();
        assert_eq!(concealer.conceal(&mut []), Concealment::Cold);
        concealer.received(&mut []);

        prime(&mut concealer, 2, 40, 8_000);
        assert_eq!(concealer.conceal(&mut []), Concealment::Extended);
        assert_eq!(concealer.gap_samples(), 0);
        concealer.received(&mut []);
        assert_eq!(concealer.pitch_period(), None);
    }

    #[test]
    fn the_gap_counter_reports_the_whole_gap() {
        let mut concealer = Concealer::new();
        prime(&mut concealer, 2, 40, 8_000);

        let mut patch = vec![0_i16; FRAME];
        concealer.conceal(&mut patch);
        assert_eq!(concealer.gap_samples(), FRAME);
        concealer.conceal(&mut patch);
        assert_eq!(concealer.gap_samples(), 2 * FRAME);
        assert!(concealer.pitch_period().is_some());

        let mut resumed = vec![1_000_i16; FRAME];
        concealer.received(&mut resumed);
        assert_eq!(concealer.gap_samples(), 0);
    }

    /// One sample of a smooth wave whose cycle is 149.3 samples long.
    ///
    /// The three shapes above are all exactly periodic at an integer lag,
    /// which is the one case where the seam correction is zero and any
    /// arithmetic for it looks right. This one is not: whatever whole number
    /// of samples the search settles on, it is a fraction of a cycle away
    /// from the truth, so a period back from the last real sample is a long
    /// way from it and the correction is doing visible work. Integer
    /// throughout — a phase accumulator and the same smoothstep the module
    /// uses for its fades — so the wave is bit-identical everywhere.
    fn near_periodic(index: usize) -> i16 {
        let phase = (i64::try_from(index).unwrap() * 655_360 / 1_493) % 65_536;
        let rising = phase < 32_768;
        let step = if rising { phase } else { phase - 32_768 };
        let square = (step * step) >> 15;
        let cube = (square * step) >> 15;
        let shape = (3 * square - 2 * cube).clamp(0, 32_768);
        let swing = 2 * 8_000 * shape / 32_768;
        i16::try_from(if rising { swing - 8_000 } else { 8_000 - swing }).unwrap()
    }

    fn steepest(samples: &[i16]) -> i32 {
        samples
            .windows(2)
            .map(|pair| (i32::from(pair[1]) - i32::from(pair[0])).abs())
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn a_loop_point_steps_by_what_the_source_stepped_by() {
        let history: Vec<i16> = (0..HISTORY).map(near_periodic).collect();
        let mut concealer = Concealer::new();
        let mut sent = history.clone();
        concealer.received(&mut sent);

        // two whole repeats and then some, all of it before the closing fade
        let mut patch = vec![0_i16; 400];
        assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);
        let period = concealer.pitch_period().unwrap();
        assert!(2 * period < patch.len());

        // the signal has to be one that can tell the candidates apart: with an
        // exactly periodic shape every formula for the correction agrees at
        // zero and the test proves nothing
        let drift = i32::from(history[HISTORY - 1]) - i32::from(history[HISTORY - 1 - period]);
        assert!(drift.abs() > 1_000, "drift of {drift} proves nothing");

        // what the source did on its way into the sample each repeat starts
        // from is what each loop point should do, scaled by the gain that
        // period is being played at
        let source_step =
            i32::from(history[HISTORY - period]) - i32::from(history[HISTORY - period - 1]);
        for repeat in 1..=2 {
            let at = repeat * period;
            let step = i32::from(patch[at]) - i32::from(patch[at - 1]);
            let gain = period_gain((repeat - 1) * period, period);
            let expected = i32::try_from(i64::from(source_step) * gain / ONE).unwrap();
            assert!(
                (step - expected).abs() <= 2,
                "repeat {repeat} stepped {step} where the source stepped {expected}"
            );
        }

        // and nothing anywhere in the extension moves faster than the source
        // ever did, which is where an uncorrected repeat gives itself away
        assert!(
            steepest(&patch) <= steepest(&history),
            "extension moves at {} against the source's {}",
            steepest(&patch),
            steepest(&history)
        );
    }

    /// One sample of a voiced sound: eight harmonics of a cycle `period`
    /// samples long, each weaker by the reciprocal of its number, at phases
    /// chosen so that no two line up. The cycle is not a whole number of
    /// samples, as a voice's never is.
    fn voice(index: usize, period: f64) -> i16 {
        let phases = [0.3, 1.9, 4.1, 2.7, 0.8, 5.5, 3.3, 1.2];
        #[allow(clippy::cast_precision_loss)]
        let total: f64 = phases
            .iter()
            .enumerate()
            .map(|(order, phase)| {
                let harmonic = (order + 1) as f64;
                (core::f64::consts::TAU * harmonic * index as f64 / period + phase).sin() / harmonic
            })
            .sum();
        #[allow(clippy::cast_possible_truncation)]
        let sample = (total * 3_000.0).round() as i16;
        sample
    }

    fn spoken(range: std::ops::Range<usize>, period: f64) -> Vec<i16> {
        range.map(|n| voice(n, period)).collect()
    }

    /// Signal to error, in decibels, of a concealed frame against what the
    /// far end really sent in its place.
    fn snr(truth: &[i16], concealed: &[i16]) -> f64 {
        let signal: f64 = truth.iter().map(|sample| f64::from(*sample).powi(2)).sum();
        let error: f64 = truth
            .iter()
            .zip(concealed)
            .map(|(real, made)| (f64::from(*real) - f64::from(*made)).powi(2))
            .sum();
        10.0 * (signal / error.max(1.0)).log10()
    }

    /// The same ten millisecond loss pattern as
    /// [`one_ten_millisecond_frame_between_two_gaps_keeps_the_voice_pitch`],
    /// but with [`reset`](Concealer::reset) called first, so no pitch is
    /// carried across the gap and the widened window alone has to do the
    /// work: this is the shape a stretch or a silence gap leaves behind it,
    /// the far end resuming into a call the concealer has no memory of yet.
    /// A search still halved into window and lag range reaches only 133 Hz
    /// and down, scoring -5 dB worst and -3 dB mean on these voices; the
    /// window shrinking first reaches every one of them, worst -2.5, mean
    /// 8.3, even with no period carried over to help.
    #[test]
    fn a_short_history_with_no_pitch_known_still_reaches_low_voices() {
        const SHORT: usize = 80;
        let mut scores = Vec::new();
        for hertz in (110..=178).step_by(4) {
            let period = f64::from(g711::CLOCK_RATE) / f64::from(hertz);
            let mut concealer = Concealer::new();
            let mut sent = 0;
            for _ in 0..10 {
                concealer.received(&mut spoken(sent..sent + SHORT, period));
                sent += SHORT;
            }
            concealer.reset();
            concealer.received(&mut spoken(sent..sent + SHORT, period));
            sent += SHORT;
            let mut patch = vec![0_i16; SHORT];
            assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);
            let score = snr(&spoken(sent..sent + SHORT, period), &patch);
            scores.push((hertz, score));
        }
        #[allow(clippy::cast_precision_loss)]
        let mean = scores.iter().map(|(_, score)| score).sum::<f64>() / scores.len() as f64;
        let worst = scores
            .iter()
            .map(|(_, score)| *score)
            .fold(f64::INFINITY, f64::min);
        assert!(
            worst >= -3.5 && mean >= 5.0,
            "worst {worst:.1} dB, mean {mean:.1} dB: {scores:?}"
        );
    }

    /// Ten millisecond frames, which G.711 is offered at as readily as
    /// twenty: one lost, one received, one lost. The frame that ended the
    /// first gap is all the history there is when the second opens, eighty
    /// samples, and a search that halved it into a window and a lag range
    /// could only reach lags of 20 to 40 — 200 to 400 Hz, above every voice
    /// here — and repeated a period no voice had: the second gap scored -1
    /// to -5 dB against what was really said, -3 dB on average. A history
    /// joined across the gap had averaged 15 dB but fell to 1 dB at 110 Hz.
    /// Every voice from 110 to 178 Hz must now clear both floors.
    #[test]
    fn one_ten_millisecond_frame_between_two_gaps_keeps_the_voice_pitch() {
        const SHORT: usize = 80;
        let mut scores = Vec::new();
        for hertz in (110..=178).step_by(4) {
            let period = f64::from(g711::CLOCK_RATE) / f64::from(hertz);
            let mut concealer = Concealer::new();
            let mut sent = 0;
            for _ in 0..10 {
                concealer.received(&mut spoken(sent..sent + SHORT, period));
                sent += SHORT;
            }
            concealer.conceal(&mut [0_i16; SHORT]);
            sent += SHORT;
            concealer.received(&mut spoken(sent..sent + SHORT, period));
            sent += SHORT;

            let mut patch = vec![0_i16; SHORT];
            assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);
            let score = snr(&spoken(sent..sent + SHORT, period), &patch);
            scores.push((hertz, score, concealer.pitch_period()));
        }
        #[allow(clippy::cast_precision_loss)]
        let mean = scores.iter().map(|(_, score, _)| score).sum::<f64>() / scores.len() as f64;
        let worst = scores
            .iter()
            .map(|(_, score, _)| *score)
            .fold(f64::INFINITY, f64::min);
        assert!(
            worst >= 5.0 && mean >= 12.0,
            "worst {worst:.1} dB, mean {mean:.1} dB: {scores:?}"
        );
    }

    /// A stretch lengthens a pause by a frame the far end never sent, so the
    /// frame after it is the one that came next and the history goes on
    /// across it: a gap after that is concealed from exactly what it would
    /// have been without the stretch, sample for sample.
    #[test]
    fn a_stretch_is_not_a_hole() {
        for hertz in [70, 110, 150, 230] {
            let period = f64::from(g711::CLOCK_RATE) / f64::from(hertz);
            let mut stretched = Concealer::new();
            let mut straight = Concealer::new();
            let mut sent = 0;
            for _ in 0..3 {
                stretched.received(&mut spoken(sent..sent + FRAME, period));
                straight.received(&mut spoken(sent..sent + FRAME, period));
                sent += FRAME;
            }
            let mut filler = vec![0_i16; FRAME];
            assert_eq!(stretched.stretch(&mut filler), Concealment::Extended);
            stretched.received(&mut spoken(sent..sent + FRAME, period));
            straight.received(&mut spoken(sent..sent + FRAME, period));

            let (mut after_stretch, mut without) = (vec![0_i16; FRAME], vec![0_i16; FRAME]);
            stretched.conceal(&mut after_stretch);
            straight.conceal(&mut without);
            assert_eq!(
                stretched.pitch_period(),
                straight.pitch_period(),
                "{hertz} Hz"
            );
            assert_eq!(after_stretch, without, "{hertz} Hz");
        }
    }

    /// And a stretch that a loss then joins is a hole after all: the frame
    /// after both starts the history again, as after any loss.
    #[test]
    fn a_loss_inside_a_stretch_still_ends_the_history() {
        let mut concealer = Concealer::new();
        prime(&mut concealer, 2, 40, 8_000);
        let mut filler = vec![0_i16; FRAME];
        concealer.stretch(&mut filler);
        concealer.conceal(&mut filler);
        concealer.received(&mut tone(0..FRAME, 40, 8_000));
        assert_eq!(concealer.history.filled, FRAME);

        let mut concealer = Concealer::new();
        prime(&mut concealer, 2, 40, 8_000);
        concealer.stretch(&mut filler);
        concealer.received(&mut tone(0..FRAME, 40, 8_000));
        assert_eq!(concealer.history.filled, HISTORY);
    }

    #[test]
    fn reset_forgets_the_stream() {
        let mut concealer = Concealer::new();
        prime(&mut concealer, 2, 40, 8_000);
        let mut patch = vec![0_i16; FRAME];
        assert_eq!(concealer.conceal(&mut patch), Concealment::Extended);

        concealer.reset();
        assert_eq!(concealer.pitch_period(), None);
        assert_eq!(concealer.conceal(&mut patch), Concealment::Cold);
        assert!(patch.iter().all(|sample| *sample == 0));

        // the pitch measured before the reset goes with it: one short frame
        // after it is concealed as by a concealer that never heard the stream
        let period = f64::from(g711::CLOCK_RATE) / 120.0;
        let mut concealer = Concealer::new();
        for start in (0..HISTORY).step_by(FRAME) {
            concealer.received(&mut spoken(start..start + FRAME, period));
        }
        concealer.conceal(&mut patch);
        concealer.reset();
        let mut fresh = Concealer::new();
        concealer.received(&mut spoken(HISTORY..HISTORY + 80, period));
        fresh.received(&mut spoken(HISTORY..HISTORY + 80, period));
        let mut again = vec![0_i16; FRAME];
        concealer.conceal(&mut patch);
        fresh.conceal(&mut again);
        assert_eq!(patch, again);
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Arbitrary interleavings of real frames and gaps, of arbitrary length
    /// and content, never panic and never leave the reported state outside
    /// what the module promises: a pitch period inside the search range
    /// whenever there is enough history to have searched, and a gap counter
    /// that never runs backwards while a gap is open. This is the property
    /// the individual scenario tests above each check once; here the sizes,
    /// the content, and the order of `received` against `conceal` are all
    /// driven by the seed, including empty frames and frames far longer than
    /// [`HISTORY`].
    #[test]
    fn arbitrary_traffic_never_panics_and_never_breaks_its_own_invariants() {
        let mut seed = 0x5EED_F00D_1357_9BDF_u64;
        for _ in 0..200 {
            let mut concealer = Concealer::new();
            let mut last_gap_samples = 0_usize;
            let mut was_conceal = false;
            for _ in 0..40 {
                let receiving = !xorshift64(&mut seed).is_multiple_of(3);
                let bound = u64::try_from(3 * HISTORY).unwrap_or(u64::MAX);
                let length = usize::try_from(xorshift64(&mut seed) % bound).unwrap_or(0);
                let pattern = xorshift64(&mut seed) % 4;
                let mut frame: Vec<i16> = (0..length)
                    .map(|index| match pattern {
                        0 => 0,
                        1 if index % 2 == 0 => i16::MAX,
                        1 | 2 => i16::MIN,
                        _ => {
                            let top = xorshift64(&mut seed) >> 48;
                            let unsigned = u16::try_from(top).unwrap_or(0);
                            i16::try_from(i32::from(unsigned) - 32_768).unwrap_or(0)
                        }
                    })
                    .collect();

                if receiving {
                    concealer.received(&mut frame);
                    was_conceal = false;
                } else {
                    let outcome = concealer.conceal(&mut frame);
                    let samples = concealer.gap_samples();
                    if was_conceal {
                        assert!(
                            samples >= last_gap_samples,
                            "gap_samples went from {last_gap_samples} to {samples}"
                        );
                    }
                    last_gap_samples = samples;
                    was_conceal = true;
                    if let Some(period) = concealer.pitch_period() {
                        // the search itself only ever returns a lag in
                        // MIN_PERIOD..=MAX_PERIOD, but `estimate_period`'s own
                        // documented fallback for history too short to
                        // correlate anything against anything returns
                        // whatever little history there is instead, which can
                        // be shorter -- so the bound every caller can rely on
                        // is 1..=MAX_PERIOD, not the search range itself
                        assert!(
                            (1..=MAX_PERIOD).contains(&period),
                            "pitch period {period} outside 1..={MAX_PERIOD} after {outcome:?}"
                        );
                    }
                }
            }
        }
    }
}
