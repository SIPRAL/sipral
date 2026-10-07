// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Voice activity detection: is a frame of decoded PCM speech or a pause.
//!
//! Used by the jitter buffer (it adapts only in pauses) and by silence
//! suppression. Speech misread as a pause clips a word, the reverse costs
//! little, so ambiguity resolves to [`Activity::Speech`].
//!
//! Two features, either of which votes speech: energy against an adaptive
//! noise floor, and zero-crossing rate, which catches quiet broadband
//! fricatives.
//!
//! # The noise floor
//!
//! The floor moves only on pause frames: slowly up, so a door or keyboard is
//! not absorbed at once, and quickly down, so the bar for speech does not stay
//! too high. The first frame after construction or [`Vad::reset`] sets the
//! floor outright; otherwise a room louder than `MIN_FLOOR` would read as
//! speech forever. A stream opening mid-word is corrected at the first pause.
//!
//! # Hangover
//!
//! A speech verdict holds for [`DEFAULT_HANGOVER_MS`] after the score drops,
//! so stop-consonant closures do not chop words, and the floor does not adapt
//! meanwhile.
//!
//! Integer arithmetic, no allocation.

/// Whether a frame of decoded audio was speech or a pause.
///
/// The caller maps it onto `sipral-rtp`'s own `Activity`; the crates do not
/// depend on each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    /// The evidence favoured speech, or there was not enough of it to be
    /// sure — see the module docs for why an unsure frame reads as this one.
    Speech,
    /// A pause: neither feature found speech, and any hangover from the last
    /// frame that did has run out.
    Silence,
}

/// How long a hangover holds [`Activity::Speech`] after the score itself
/// stops finding it, in milliseconds.
///
/// Long enough to bridge a stop-consonant closure and the short pauses inside
/// fluent speech, short enough that a real pause between sentences still
/// reads as one. Chosen from the behaviour wanted, not from a published
/// table.
pub const DEFAULT_HANGOVER_MS: u32 = 200;

/// The ratio short-term energy must clear the noise floor by to be read as
/// speech on energy alone, expressed as `NUMERATOR`/`DENOMINATOR` so the
/// comparison stays exact integer arithmetic. Three over two is fifty
/// percent above the floor, about 1.8 dB — enough that the frame-to-frame
/// variance of stationary background noise does not cross it on its own for
/// a typical packet-length frame, small enough that a quiet voice is not
/// asked to fight the floor as hard as a loud one.
const RATIO_NUMERATOR: i64 = 3;
const RATIO_DENOMINATOR: i64 = 2;

/// The zero-crossing rate, as a fraction of the pairs in a frame, above
/// which a signal that is at least a little above the floor is read as
/// speech even though it failed the energy test. A voiced, low-pitched tone
/// crosses zero a handful of times a frame; broadband material such as a
/// fricative or noise crosses far more often. Three eighths sits well above
/// the voiced case and well below "every other sample", which is as far as
/// crossing can go.
const ZCR_NUMERATOR: usize = 3;
const ZCR_DENOMINATOR: usize = 8;

/// The least the noise floor is ever allowed to sit at, whatever the
/// background does. Without it, a stream of literal digital silence settles
/// the floor at zero and then a single bit of decoder truncation error reads
/// as speech forever after. The value is a mean-square energy corresponding
/// to an amplitude of about five, which is below anything a real microphone
/// puts out even in a quiet room.
const MIN_FLOOR: i64 = 25;

/// How many frames of a step change it takes the floor to close roughly two
/// thirds of the gap when the background is getting louder.
const RISE_DIVISOR: i64 = 32;

/// The same, for a background getting quieter. Smaller, and therefore
/// faster, for the reason in the module docs: a stale, too-high floor is the
/// expensive mistake.
const FALL_DIVISOR: i64 = 8;

/// Energy-and-zero-crossing voice activity detection with an adaptive noise
/// floor and a hangover, one instance per stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vad {
    hangover_span: usize,
    hangover_remaining: usize,
    noise_floor: i64,
    /// Whether the floor has taken its one-time seed from the first frame
    /// yet — see the module docs' "noise floor" section.
    primed: bool,
}

impl Vad {
    /// A detector for a stream at `sample_rate`, with [`DEFAULT_HANGOVER_MS`]
    /// of hangover.
    #[must_use]
    pub fn new(sample_rate: u32) -> Self {
        Self::with_hangover_ms(sample_rate, DEFAULT_HANGOVER_MS)
    }

    /// A detector with an explicit hangover instead of the default.
    #[must_use]
    pub fn with_hangover_ms(sample_rate: u32, hangover_ms: u32) -> Self {
        let span = u64::from(sample_rate) * u64::from(hangover_ms) / 1_000;
        Self {
            hangover_span: usize::try_from(span).unwrap_or(usize::MAX),
            hangover_remaining: 0,
            noise_floor: 0,
            primed: false,
        }
    }

    /// Forget the stream: a new call, or a device change that makes the
    /// current noise floor meaningless. The next frame processed re-seeds the
    /// floor exactly as the first frame after construction would.
    pub fn reset(&mut self) {
        self.hangover_remaining = 0;
        self.noise_floor = 0;
        self.primed = false;
    }

    /// The current noise floor: the same mean-square energy [`process`]
    /// compares frames against, never below `MIN_FLOOR` once a frame has
    /// primed it, and zero before that. For diagnostics; nothing in this
    /// module reads it back from the outside.
    ///
    /// [`process`]: Self::process
    #[must_use]
    pub const fn noise_floor(&self) -> i64 {
        self.noise_floor
    }

    /// Whether a hangover is currently in effect, holding the verdict at
    /// [`Activity::Speech`] regardless of what the last frame scored.
    #[must_use]
    pub const fn in_hangover(&self) -> bool {
        self.hangover_remaining > 0
    }

    /// Score one frame of linear PCM and update the detector's state.
    ///
    /// A frame too short to measure a zero crossing in — fewer than two
    /// samples — is read as speech without touching the noise floor or the
    /// hangover: there is no evidence in it either way, and an unsure frame
    /// reads as speech.
    pub fn process(&mut self, frame: &[i16]) -> Activity {
        if frame.len() < 2 {
            return Activity::Speech;
        }

        let energy = mean_energy(frame);
        let crossings = zero_crossings(frame);
        let raw_speech = self.scores_as_speech(energy, crossings, frame.len());

        if raw_speech {
            self.hangover_remaining = self.hangover_span;
        } else {
            self.hangover_remaining = self.hangover_remaining.saturating_sub(frame.len());
        }

        if self.primed {
            if !raw_speech && self.hangover_remaining == 0 {
                self.adapt_floor(energy);
            }
        } else {
            // nothing to compare the first frame against; its own level
            // becomes the starting estimate, regardless of how it scored
            self.noise_floor = energy.max(MIN_FLOOR);
            self.primed = true;
        }

        if raw_speech || self.hangover_remaining > 0 {
            Activity::Speech
        } else {
            Activity::Silence
        }
    }

    fn scores_as_speech(&self, energy: i64, crossings: usize, len: usize) -> bool {
        // the stored floor is already held at the minimum; this covers the
        // one frame that arrives before anything has primed it
        let floor = self.noise_floor.max(MIN_FLOOR);
        if energy.saturating_mul(RATIO_DENOMINATOR) >= floor.saturating_mul(RATIO_NUMERATOR) {
            return true;
        }
        // above the floor but not by the energy margin: only a broadband,
        // fast-crossing signal earns the fricative exception, not any old
        // frame that happens to sit just over a rising floor
        if energy <= floor {
            return false;
        }
        let pairs = len.saturating_sub(1);
        crossings.saturating_mul(ZCR_DENOMINATOR) >= pairs.saturating_mul(ZCR_NUMERATOR)
    }

    fn adapt_floor(&mut self, energy: i64) {
        let divisor = if energy >= self.noise_floor {
            RISE_DIVISOR
        } else {
            FALL_DIVISOR
        };
        // held at the minimum here rather than only where it is compared, so
        // that a long run of digital silence cannot walk the stored floor
        // below the value every decision is actually made against
        self.noise_floor = step_toward(self.noise_floor, energy, divisor).max(MIN_FLOOR);
    }
}

/// Move `current` toward `target` by `1/divisor` of the remaining distance,
/// but never by less than one: without the floor on the step, integer
/// division stalls a few units short of the target forever once the
/// remaining distance drops below `divisor`.
fn step_toward(current: i64, target: i64, divisor: i64) -> i64 {
    let diff = target - current;
    if diff == 0 {
        return current;
    }
    let step = diff / divisor;
    if step == 0 {
        current + diff.signum()
    } else {
        current + step
    }
}

/// Mean of the squared samples — average power, not summed power, so a
/// caller that changes frame length does not also change the scale the
/// thresholds are compared at.
fn mean_energy(frame: &[i16]) -> i64 {
    let sum: i64 = frame
        .iter()
        .map(|&sample| {
            let value = i64::from(sample);
            value * value
        })
        .sum();
    let len = i64::try_from(frame.len()).unwrap_or(i64::MAX);
    if len == 0 { 0 } else { sum / len }
}

/// How many adjacent sample pairs have strictly opposite sign. A sample of
/// exactly zero counts toward neither side of a crossing, which keeps a
/// signal that dwells at zero from being scored as crossing on every step.
fn zero_crossings(frame: &[i16]) -> usize {
    frame
        .windows(2)
        .filter(|pair| match (pair.first(), pair.get(1)) {
            (Some(&a), Some(&b)) => i64::from(a) * i64::from(b) < 0,
            _ => false,
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::{Activity, MIN_FLOOR, Vad, mean_energy, step_toward, zero_crossings};

    /// A constant-amplitude frame has an exact mean energy of `amplitude *
    /// amplitude`, which makes it easy to prime the noise floor at a known
    /// value and easy to reason about which side of a threshold a test frame
    /// falls on.
    fn flat(amplitude: i16, len: usize) -> Vec<i16> {
        vec![amplitude; len]
    }

    /// Feeds `frame` to `vad` until [`Vad::process`] stops moving the noise
    /// floor, for priming a test to a known starting point. Panics if that
    /// does not happen well within the number of frames [`step_toward`]'s own
    /// convergence guarantee promises — a test helper, so panicking on a
    /// broken precondition is exactly what should happen.
    fn converge(vad: &mut Vad, frame: &[i16]) {
        for _ in 0..10_000 {
            let before = vad.noise_floor();
            vad.process(frame);
            if vad.noise_floor() == before {
                return;
            }
        }
        panic!("noise floor did not converge");
    }

    #[test]
    fn mean_energy_of_a_flat_frame_is_the_amplitude_squared() {
        assert_eq!(mean_energy(&flat(10, 3)), 100);
        assert_eq!(mean_energy(&flat(-10, 5)), 100);
        assert_eq!(mean_energy(&[]), 0);
        assert_eq!(mean_energy(&[0, 0, 0]), 0);
    }

    #[test]
    fn zero_crossings_counts_sign_changes_and_not_touches_of_zero() {
        assert_eq!(zero_crossings(&[1, -1, 1, -1]), 3);
        assert_eq!(zero_crossings(&[1, 1, 1, 1]), 0);
        assert_eq!(zero_crossings(&[1, 0, -1]), 0);
        assert_eq!(zero_crossings(&[5]), 0);
        assert_eq!(zero_crossings(&[]), 0);
    }

    #[test]
    fn step_toward_moves_at_least_one_unit_and_lands_exactly() {
        assert_eq!(step_toward(0, 100, 32), 3);
        assert_eq!(step_toward(97, 100, 32), 98); // 3/32 truncates to 0, floor of 1 applies
        assert_eq!(step_toward(100, 100, 32), 100);
        assert_eq!(step_toward(500, 400, 8), 488); // -100/8 truncates toward zero to -12
        assert_eq!(step_toward(0, 0, 8), 0);
    }

    #[test]
    fn a_loud_tone_from_a_cold_start_is_speech() {
        let mut vad = Vad::new(8_000);
        let frame: Vec<i16> = (0..160)
            .map(|n| if n % 2 == 0 { 20_000 } else { -20_000 })
            .collect();
        assert_eq!(vad.process(&frame), Activity::Speech);
    }

    #[test]
    fn digital_silence_from_a_cold_start_is_silence() {
        let mut vad = Vad::new(8_000);
        // zero energy against a cold floor clamped to MIN_FLOOR never clears
        // the margin, so this reads as silence on the very first frame
        assert_eq!(vad.process(&flat(0, 160)), Activity::Silence);
    }

    #[test]
    fn the_first_frame_seeds_the_floor_from_its_own_energy_however_it_was_scored() {
        let mut vad = Vad::with_hangover_ms(8_000, 0);
        // loud enough that, against the cold floor, it reads as speech --
        // and it does -- but the floor still starts from what this frame
        // measured, not from the classification it happened to get
        assert_eq!(vad.process(&flat(200, 160)), Activity::Speech);
        assert_eq!(vad.noise_floor(), 40_000);
    }

    #[test]
    fn a_background_above_min_floor_still_reaches_its_true_level_from_a_cold_start() {
        // the case the bootstrap exists for: without it, an ordinary
        // background loud enough to clear MIN_FLOOR's margin would score as
        // speech against the cold floor forever and never return a pause for
        // the floor to learn from
        let mut vad = Vad::with_hangover_ms(8_000, 0);
        for _ in 0..5 {
            vad.process(&flat(30, 160)); // energy 900, well past MIN_FLOOR's margin
        }
        assert_eq!(vad.noise_floor(), 900);
    }

    #[test]
    fn the_noise_floor_converges_exactly_to_a_steady_background() {
        let mut vad = Vad::new(8_000);
        converge(&mut vad, &flat(10, 160)); // energy 100
        assert_eq!(vad.noise_floor(), 100);
    }

    #[test]
    fn the_floor_rises_slower_than_it_falls() {
        // no hangover here: a lingering hangover from the priming frame's own
        // classification would gate the single follow-up step this test
        // measures, which is not what it is testing
        let mut rising = Vad::with_hangover_ms(8_000, 0);
        converge(&mut rising, &flat(10, 160));
        assert_eq!(rising.noise_floor(), 100);
        rising.process(&flat(12, 160)); // energy 144, above the floor
        let rise = rising.noise_floor() - 100;

        let mut falling = Vad::with_hangover_ms(8_000, 0);
        converge(&mut falling, &flat(22, 160)); // energy 484
        assert_eq!(falling.noise_floor(), 484);
        falling.process(&flat(20, 160)); // energy 400, below the floor
        let fall = 484 - falling.noise_floor();

        assert_eq!(rise, 1, "44/32 truncates to a single-unit step");
        assert_eq!(fall, 10, "84/8 is an exact ten-unit step");
        assert!(fall > rise, "the floor should fall faster than it rises");
    }

    #[test]
    fn a_tie_at_the_energy_margin_is_read_as_speech() {
        let mut vad = Vad::with_hangover_ms(8_000, 0);
        converge(&mut vad, &[0, 8]); // energy (0+64)/2 = 32
        assert_eq!(vad.noise_floor(), 32);
        // floor 32, margin 3/2: tie at energy 48 exactly (32*3 == 48*2)
        assert_eq!(vad.process(&[0, 0, 12]), Activity::Speech); // energy 144/3 = 48
    }

    #[test]
    fn one_below_the_margin_is_silence() {
        let mut vad = Vad::with_hangover_ms(8_000, 0);
        converge(&mut vad, &[0, 8]); // floor 32
        assert_eq!(vad.noise_floor(), 32);
        // energy (121+16+4)/3 = 47, one short of the tie at 48
        assert_eq!(vad.process(&[11, 4, 2]), Activity::Silence);
    }

    #[test]
    fn a_quiet_fast_crossing_signal_is_read_as_speech_on_zero_crossings_alone() {
        let mut vad = Vad::with_hangover_ms(8_000, 0);
        converge(&mut vad, &flat(10, 160)); // floor 100
        assert_eq!(vad.noise_floor(), 100);
        // amplitude 11 alternating sign: energy 121, well under the 150
        // needed for the energy test, but every pair crosses
        let fricative: Vec<i16> = (0..160)
            .map(|n| if n % 2 == 0 { 11 } else { -11 })
            .collect();
        assert_eq!(mean_energy(&fricative), 121);
        assert_eq!(vad.process(&fricative), Activity::Speech);
    }

    #[test]
    fn the_same_energy_without_crossings_is_not_read_as_speech() {
        let mut vad = Vad::with_hangover_ms(8_000, 0);
        converge(&mut vad, &flat(10, 160)); // floor 100
        let steady = flat(11, 160); // energy 121, same as the fricative above
        assert_eq!(mean_energy(&steady), 121);
        assert_eq!(vad.process(&steady), Activity::Silence);
    }

    #[test]
    fn hangover_holds_speech_through_a_short_gap_and_releases_after_it() {
        let mut vad = Vad::with_hangover_ms(8_000, 200); // 1_600 samples
        let loud = flat(20_000, 160);
        assert_eq!(vad.process(&loud), Activity::Speech);
        assert!(vad.in_hangover());

        let quiet = flat(0, 160);
        for frame in 0..9 {
            assert_eq!(
                vad.process(&quiet),
                Activity::Speech,
                "frame {frame} should still be in hangover"
            );
        }
        // ten silent frames of 160 samples exhausts exactly 1_600 samples
        assert_eq!(vad.process(&quiet), Activity::Silence);
        assert!(!vad.in_hangover());
    }

    #[test]
    fn the_floor_does_not_adapt_while_a_hangover_is_running() {
        let mut vad = Vad::with_hangover_ms(8_000, 200);
        vad.process(&flat(20_000, 160));
        let seeded = vad.noise_floor();
        // strictly within the hangover window: nine frames of 160 samples
        // against a 1_600-sample hangover never brings it to zero
        for _ in 0..9 {
            vad.process(&flat(0, 160));
        }
        assert_eq!(vad.noise_floor(), seeded);
    }

    #[test]
    fn a_gap_shorter_than_the_hangover_never_reports_silence() {
        let mut vad = Vad::with_hangover_ms(8_000, 200);
        vad.process(&flat(20_000, 160));
        let seeded = vad.noise_floor();
        for _ in 0..5 {
            assert_eq!(vad.process(&flat(0, 160)), Activity::Speech);
        }
        // speech resumes before the hangover ran out
        assert_eq!(vad.process(&flat(15_000, 160)), Activity::Speech);
        assert_eq!(vad.noise_floor(), seeded, "the floor was never touched");
    }

    #[test]
    fn a_long_run_of_digital_silence_stops_the_floor_where_the_comparison_stops() {
        let mut vad = Vad::with_hangover_ms(8_000, 0);
        converge(&mut vad, &flat(30, 160)); // energy 900
        assert_eq!(vad.noise_floor(), 900);

        // a muted microphone, or a codec handing over exact zeroes: the floor
        // falls the whole way down, and it has to stop where the comparison
        // stops reading it, or what the accessor reports is not what any
        // decision was made against. `converge` cannot reach this: it stops
        // at the first frame that does not move the floor, which is the same
        // frame either way
        for _ in 0..200 {
            assert_eq!(vad.process(&flat(0, 160)), Activity::Silence);
        }
        assert_eq!(vad.noise_floor(), MIN_FLOOR);

        // and the number it reports is the one frames are judged against:
        // energy 49 clears the margin over 25, energy 25 does not
        assert_eq!(vad.process(&flat(7, 160)), Activity::Speech);
        assert_eq!(vad.process(&flat(5, 160)), Activity::Silence);
    }

    #[test]
    fn frames_too_short_to_measure_are_read_as_speech_and_leave_no_trace() {
        let mut vad = Vad::new(8_000);
        assert_eq!(vad.process(&[]), Activity::Speech);
        assert_eq!(vad.process(&[123]), Activity::Speech);
        assert_eq!(vad.noise_floor(), 0);
        assert!(!vad.in_hangover());
    }

    #[test]
    fn reset_forgets_both_the_floor_and_the_hangover() {
        let mut vad = Vad::new(8_000);
        converge(&mut vad, &flat(30, 160));
        assert_ne!(vad.noise_floor(), 0);
        vad.process(&flat(20_000, 160));
        assert!(vad.in_hangover());

        vad.reset();
        assert_eq!(vad.noise_floor(), 0);
        assert!(!vad.in_hangover());
    }

    #[test]
    fn hangover_span_scales_with_both_rate_and_duration() {
        assert_eq!(Vad::with_hangover_ms(8_000, 200).hangover_span, 1_600);
        assert_eq!(Vad::with_hangover_ms(16_000, 200).hangover_span, 3_200);
        assert_eq!(Vad::with_hangover_ms(8_000, 100).hangover_span, 800);
        assert_eq!(Vad::with_hangover_ms(8_000, 0).hangover_span, 0);
    }

    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Arbitrary sample rates, arbitrary frame lengths and content — silence,
    /// full-scale runs, a burst after a long silence, and plain noise —
    /// driven through the same detector across many frames. `process` must
    /// never panic, the floor it reports must never fall under [`MIN_FLOOR`]
    /// once it has seen a frame, and it must never move while a hangover is
    /// running, all of which the scenario tests above check once apiece.
    #[test]
    fn arbitrary_frames_never_panic_and_never_break_the_floors_own_rules() {
        let mut seed = 0xACE5_5EED_0BAD_F00D_u64;
        for _ in 0..150 {
            let rate = 1 + u32::try_from(xorshift64(&mut seed) % 96_000).unwrap_or(8_000);
            let mut vad = Vad::new(rate);
            let mut primed_floor: Option<i64> = None;
            for _ in 0..60 {
                let length = usize::try_from(xorshift64(&mut seed) % 400).unwrap_or(0);
                let pattern = xorshift64(&mut seed) % 4;
                let frame: Vec<i16> = (0..length)
                    .map(|index| match pattern {
                        0 => 0,
                        1 if index % 2 == 0 => i16::MAX,
                        1 => i16::MIN,
                        2 => i16::MAX,
                        _ => {
                            let top = xorshift64(&mut seed) >> 48;
                            let unsigned = u16::try_from(top).unwrap_or(0);
                            i16::try_from(i32::from(unsigned) - 32_768).unwrap_or(0)
                        }
                    })
                    .collect();

                let before = vad.noise_floor();
                let _ = vad.process(&frame);
                let after = vad.noise_floor();
                // a hangover still running once this frame's own decrement has
                // been applied is exactly the condition `process` itself
                // gates adaptation on, so this is the one point a test from
                // outside the module can observe it
                let still_in_hangover = vad.in_hangover();

                if frame.len() >= 2 {
                    if primed_floor.is_none() {
                        primed_floor = Some(after);
                    } else {
                        assert!(after >= MIN_FLOOR, "the floor fell under its own minimum");
                        if still_in_hangover {
                            assert_eq!(
                                before, after,
                                "the floor moved while a hangover was still running"
                            );
                        }
                    }
                }
            }
        }
    }
}
