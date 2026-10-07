// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Volume, mute, and the number a meter is drawn from.
//!
//! Gain is applied to the samples, not the system volume, which would
//! affect other apps and outlive the process. It is applied at the device
//! end of the rings so a mute is heard on the next period, not a ring later.
//! Integer arithmetic and relaxed atomics only, safe for the callback.

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Unity in 256ths, so applying a gain is a multiply and a shift.
const UNITY_SCALE: u16 = 256;

const SHIFT: u32 = 8;

/// 4x (+12 dB). Not an arithmetic limit; more only buys distortion.
const MAX_SCALE: u16 = 4 * UNITY_SCALE;

/// `|i16::MIN|`, the largest magnitude.
const FULL_SCALE: u16 = 32_768;

/// The peak hold window. A fixed window, not "since last poll", keeps the
/// meter independent of how often it is read.
const WINDOW_MILLIS: u32 = 100;

/// Samples one meter window covers at a rate.
#[must_use]
pub const fn window_samples(sample_rate_hz: u32) -> u32 {
    let per_millisecond = sample_rate_hz / 1_000;
    if per_millisecond == 0 {
        // never an empty window
        WINDOW_MILLIS
    } else {
        per_millisecond * WINDOW_MILLIS
    }
}

/// What the samples are multiplied by on their way to or from the device.
///
/// Held in 256ths. Negative or NaN ratios are [`Gain::SILENT`], above four
/// [`Gain::MAX`]. Applying it saturates, and each clipped sample is counted
/// in [`Controls::clipped`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gain(u16);

impl Gain {
    /// Nothing gets through. Distinct from mute, which keeps the gain.
    pub const SILENT: Self = Self(0);

    /// Samples unchanged.
    pub const UNITY: Self = Self(UNITY_SCALE);

    /// Four times, +12 dB.
    pub const MAX: Self = Self(MAX_SCALE);

    /// A gain from a multiplier, clamped into range; NaN is silence.
    #[must_use]
    pub fn from_ratio(ratio: f32) -> Self {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a float cast to an integer saturates and turns NaN into zero, which is exactly the behaviour documented above"
        )]
        let steps = (ratio * f32::from(UNITY_SCALE)).round() as u16;
        Self(steps.min(MAX_SCALE))
    }

    /// The multiplier it stands for.
    #[must_use]
    pub fn ratio(self) -> f32 {
        f32::from(self.0) / f32::from(UNITY_SCALE)
    }

    /// A gain from decibels (amplitude: 20·log10, so -6 dB is half).
    #[must_use]
    pub fn from_db(db: f32) -> Self {
        Self::from_ratio(10.0_f32.powf(db / 20.0))
    }

    /// In decibels; negative infinity when silent.
    #[must_use]
    pub fn db(self) -> f32 {
        20.0 * self.ratio().log10()
    }
}

impl Default for Gain {
    fn default() -> Self {
        Self::UNITY
    }
}

impl fmt::Display for Gain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::SILENT {
            f.write_str("silent")
        } else {
            write!(f, "{:+.1} dB", self.db())
        }
    }
}

/// The recent peak, measured after gain and mute, so a muted microphone
/// reads silent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Level(u16);

impl Level {
    /// Nothing went past at all.
    pub const SILENT: Self = Self(0);

    /// The magnitude itself, from zero to 32768.
    #[must_use]
    pub const fn peak(self) -> u16 {
        self.0
    }

    /// As a fraction of full scale.
    #[must_use]
    pub fn fraction(self) -> f32 {
        f32::from(self.0) / f32::from(FULL_SCALE)
    }

    /// In dBFS; negative infinity for silence.
    #[must_use]
    pub fn dbfs(self) -> f32 {
        20.0 * self.fraction().log10()
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::SILENT {
            f.write_str("silent")
        } else {
            write!(f, "{:.1} dBFS", self.dbfs())
        }
    }
}

/// The gain, the mute and the meter for one direction.
///
/// All relaxed: a control seen one callback late is inaudible, and a fence
/// in the callback is not worth it.
#[derive(Debug)]
pub struct Channel {
    scale: AtomicU16,
    muted: AtomicBool,
    clipped: AtomicU64,
    window: AtomicU32,
    /// Peaks of the current and last full window; the meter shows the larger,
    /// so a peak holds for one to two windows.
    current: AtomicU16,
    previous: AtomicU16,
    counted: AtomicU32,
}

impl Channel {
    /// Unity gain, unmuted, with a meter window of `window` samples.
    #[must_use]
    pub fn new(window: u32) -> Self {
        Self {
            scale: AtomicU16::new(UNITY_SCALE),
            muted: AtomicBool::new(false),
            clipped: AtomicU64::new(0),
            window: AtomicU32::new(window),
            current: AtomicU16::new(0),
            previous: AtomicU16::new(0),
            counted: AtomicU32::new(0),
        }
    }

    /// Resize the window once the device has chosen a rate.
    pub fn set_window(&self, window: u32) {
        self.window.store(window.max(1), Ordering::Relaxed);
    }

    /// Set the gain the audio path applies from its next sample on.
    pub fn set_gain(&self, gain: Gain) {
        self.scale.store(gain.0, Ordering::Relaxed);
    }

    /// The gain in force.
    pub fn gain(&self) -> Gain {
        Gain(self.scale.load(Ordering::Relaxed))
    }

    /// Mute or unmute, heard on the next sample the device asks for.
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    /// Whether it is muted.
    pub fn is_muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    /// Samples clipped by the gain, ever. Monotonic.
    pub fn clipped(&self) -> u64 {
        self.clipped.load(Ordering::Relaxed)
    }

    /// What a meter should show.
    pub fn level(&self) -> Level {
        Level(
            self.current
                .load(Ordering::Relaxed)
                .max(self.previous.load(Ordering::Relaxed)),
        )
    }

    /// Reset the meter when a stream stops, so it does not look live.
    pub fn quiet(&self) {
        self.current.store(0, Ordering::Relaxed);
        self.previous.store(0, Ordering::Relaxed);
        self.counted.store(0, Ordering::Relaxed);
    }

    /// Scale `samples` in place and meter them.
    ///
    /// `covered` is the device time in samples, which can exceed the block
    /// when a starved callback pads with silence; the window must advance by
    /// it anyway.
    pub fn apply(&self, samples: &mut [i16], covered: usize) {
        let scale = if self.muted.load(Ordering::Relaxed) {
            0
        } else {
            i32::from(self.scale.load(Ordering::Relaxed))
        };
        let low = i32::from(i16::MIN);
        let high = i32::from(i16::MAX);

        let mut peak: u16 = 0;
        let mut clipped: u64 = 0;
        for sample in samples.iter_mut() {
            let scaled = (i32::from(*sample) * scale) >> SHIFT;
            let bounded = scaled.clamp(low, high);
            clipped += u64::from(bounded != scaled);
            let value = i16::try_from(bounded).unwrap_or(0);
            peak = peak.max(value.unsigned_abs());
            *sample = value;
        }

        if clipped > 0 {
            self.clipped.fetch_add(clipped, Ordering::Relaxed);
        }
        self.note(peak, covered);
    }

    fn note(&self, peak: u16, covered: usize) {
        let counted = self
            .counted
            .load(Ordering::Relaxed)
            .saturating_add(u32::try_from(covered).unwrap_or(u32::MAX));
        let current = self.current.load(Ordering::Relaxed).max(peak);
        if counted >= self.window.load(Ordering::Relaxed) {
            self.previous.store(current, Ordering::Relaxed);
            self.current.store(0, Ordering::Relaxed);
            self.counted.store(0, Ordering::Relaxed);
        } else {
            self.current.store(current, Ordering::Relaxed);
            self.counted.store(counted, Ordering::Relaxed);
        }
    }
}

/// The volume, the mute and the meter for one direction of one stream.
///
/// A cloneable, `Send` handle for the UI thread; it may outlive the stream.
/// Reads are relaxed loads, cheap enough to poll every UI frame.
#[derive(Clone, Debug)]
pub struct Controls {
    channel: Arc<Channel>,
}

impl Controls {
    /// A handle onto a channel the audio path already owns.
    pub fn new(channel: &Arc<Channel>) -> Self {
        Self {
            channel: Arc::clone(channel),
        }
    }

    /// Set the gain; heard from the next device period.
    pub fn set_gain(&self, gain: Gain) {
        self.channel.set_gain(gain);
    }

    /// The gain, regardless of mute.
    #[must_use]
    pub fn gain(&self) -> Gain {
        self.channel.gain()
    }

    /// Mute or unmute without touching the gain.
    ///
    /// The stream keeps running while muted, so unmuting does not replay
    /// audio that piled up.
    pub fn set_muted(&self, muted: bool) {
        self.channel.set_muted(muted);
    }

    /// Whether it is muted.
    #[must_use]
    pub fn is_muted(&self) -> bool {
        self.channel.is_muted()
    }

    /// The peak of the last ~100 ms, after gain and mute.
    #[must_use]
    pub fn level(&self) -> Level {
        self.channel.level()
    }

    /// Samples clipped by the gain. Monotonic; a rising count means the gain
    /// is too high.
    #[must_use]
    pub fn clipped(&self) -> u64 {
        self.channel.clipped()
    }
}

#[cfg(test)]
mod tests {
    use super::{Channel, Controls, Gain, Level, MAX_SCALE, UNITY_SCALE, window_samples};
    use std::sync::Arc;

    fn channel() -> Channel {
        Channel::new(100)
    }

    #[test]
    fn a_window_is_a_tenth_of_a_second_at_any_rate() {
        assert_eq!(window_samples(8_000), 800);
        assert_eq!(window_samples(48_000), 4_800);
        // 99.8 ms is near enough
        assert_eq!(window_samples(44_100), 4_400);
        assert_eq!(window_samples(0), 100);
    }

    #[test]
    fn unity_leaves_every_sample_exactly_as_it_was() {
        let channel = channel();
        let mut samples = [i16::MIN, -1_000, -1, 0, 1, 1_000, i16::MAX];
        let wanted = samples;
        channel.apply(&mut samples, wanted.len());
        assert_eq!(samples, wanted);
        assert_eq!(channel.clipped(), 0);
        assert_eq!(channel.level().peak(), 32_768);
    }

    #[test]
    fn half_the_gain_is_half_the_sample() {
        let channel = channel();
        channel.set_gain(Gain::from_ratio(0.5));
        let mut samples = [1_000i16, -1_000, 32_766];
        channel.apply(&mut samples, 3);
        assert_eq!(samples, [500, -500, 16_383]);
        assert_eq!(channel.clipped(), 0);
    }

    #[test]
    fn a_gain_that_would_overflow_saturates_and_is_counted() {
        let channel = channel();
        channel.set_gain(Gain::from_ratio(4.0));
        let mut samples = [20_000i16, -20_000, 1_000, -1_000];
        channel.apply(&mut samples, 4);

        assert_eq!(samples, [i16::MAX, i16::MIN, 4_000, -4_000]);
        // per sample, not per block
        assert_eq!(channel.clipped(), 2);
        assert_eq!(channel.level().peak(), 32_768);

        let mut more = [30_000i16];
        channel.apply(&mut more, 1);
        assert_eq!(channel.clipped(), 3);
    }

    #[test]
    fn nothing_the_gain_does_wraps_round() {
        let channel = channel();
        channel.set_gain(Gain::MAX);
        for start in [i16::MIN, i16::MIN + 1, -1, 0, 1, i16::MAX] {
            let mut samples = [start];
            channel.apply(&mut samples, 1);
            let out = samples[0];
            assert_eq!(out.signum(), start.signum(), "{start} came back as {out}");
            assert!(out.saturating_abs() >= start.saturating_abs() - 1);
        }
    }

    #[test]
    fn a_mute_is_silence_and_gives_the_volume_back() {
        let channel = channel();
        channel.set_gain(Gain::from_ratio(0.75));
        channel.set_muted(true);

        let mut samples = [10_000i16; 8];
        channel.apply(&mut samples, 8);
        assert_eq!(samples, [0i16; 8]);
        assert_eq!(channel.gain(), Gain::from_ratio(0.75));
        assert!(channel.is_muted());

        channel.set_muted(false);
        let mut samples = [10_000i16; 4];
        channel.apply(&mut samples, 4);
        assert_eq!(samples, [7_500i16; 4]);
    }

    #[test]
    fn a_muted_direction_reads_as_silent_within_two_windows() {
        let channel = channel();
        let mut loud = [20_000i16; 60];
        channel.apply(&mut loud, 60);
        assert_eq!(channel.level().peak(), 20_000);

        channel.set_muted(true);
        for _ in 0..4 {
            let mut quiet = [20_000i16; 60];
            channel.apply(&mut quiet, 60);
        }
        assert_eq!(channel.level(), Level::SILENT);
    }

    #[test]
    fn a_peak_is_held_across_a_window_and_polling_does_not_spend_it() {
        let channel = channel();
        let mut spike = [0i16; 10];
        spike[3] = 8_000;
        channel.apply(&mut spike, 10);

        for _ in 0..10 {
            assert_eq!(channel.level().peak(), 8_000);
        }

        for _ in 0..8 {
            let mut quiet = [0i16; 10];
            channel.apply(&mut quiet, 10);
        }
        assert_eq!(channel.level().peak(), 8_000);
    }

    #[test]
    fn a_peak_falls_away_between_one_window_and_two() {
        let channel = channel();
        let mut spike = [0i16; 50];
        spike[0] = 8_000;
        channel.apply(&mut spike, 50);
        assert_eq!(channel.level().peak(), 8_000);

        let mut quiet = [0i16; 50];
        channel.apply(&mut quiet, 50);
        assert_eq!(channel.level().peak(), 8_000);
        channel.apply(&mut quiet, 50);
        assert_eq!(channel.level().peak(), 8_000);

        channel.apply(&mut quiet, 50);
        assert_eq!(channel.level(), Level::SILENT);
    }

    #[test]
    fn silence_the_caller_never_wrote_still_moves_the_window_on() {
        let channel = channel();
        let mut spike = [9_000i16; 4];
        channel.apply(&mut spike, 4);
        assert_eq!(channel.level().peak(), 9_000);

        // a starved playback callback covering two windows
        let mut nothing: [i16; 0] = [];
        channel.apply(&mut nothing, 200);
        channel.apply(&mut nothing, 200);
        assert_eq!(channel.level(), Level::SILENT);
    }

    #[test]
    fn a_reopen_at_another_rate_gets_another_window() {
        let channel = channel();
        channel.set_window(window_samples(48_000));

        let mut loud = [7_000i16; 4_000];
        channel.apply(&mut loud, 4_000);
        let mut quiet = [0i16; 700];
        // with the original 100-sample window these would clear the peak
        for _ in 0..3 {
            channel.apply(&mut quiet, 700);
        }
        assert_eq!(channel.level().peak(), 7_000);

        channel.set_window(0);
        channel.apply(&mut quiet, 1);
        assert_eq!(channel.level(), Level::SILENT);
    }

    #[test]
    fn a_stopped_stream_stops_metering() {
        let channel = channel();
        let mut loud = [12_000i16; 50];
        channel.apply(&mut loud, 50);
        assert_ne!(channel.level(), Level::SILENT);
        channel.quiet();
        assert_eq!(channel.level(), Level::SILENT);
    }

    #[test]
    fn the_ends_of_the_gain_range_are_the_ends_and_not_a_wrap() {
        assert_eq!(Gain::from_ratio(0.0), Gain::SILENT);
        assert_eq!(Gain::from_ratio(1.0), Gain::UNITY);
        assert_eq!(Gain::from_ratio(4.0), Gain::MAX);
        assert_eq!(Gain::from_ratio(-1.0), Gain::SILENT);
        assert_eq!(Gain::from_ratio(-0.5), Gain::SILENT);
        assert_eq!(Gain::from_ratio(9.0), Gain::MAX);
        assert_eq!(Gain::from_ratio(f32::INFINITY), Gain::MAX);
        assert_eq!(Gain::from_ratio(f32::NEG_INFINITY), Gain::SILENT);
        assert_eq!(Gain::from_ratio(f32::NAN), Gain::SILENT);
        assert_eq!(Gain::default(), Gain::UNITY);
    }

    #[test]
    fn decibels_are_amplitudes_rather_than_powers() {
        assert_eq!(Gain::from_db(0.0), Gain::UNITY);
        assert!((Gain::from_db(-6.02).ratio() - 0.5).abs() < 0.01);
        assert!((Gain::from_db(6.02).ratio() - 2.0).abs() < 0.02);
        assert!(Gain::UNITY.db().abs() < f32::EPSILON);
        assert_eq!(Gain::from_db(f32::NEG_INFINITY), Gain::SILENT);
        let silent = Gain::SILENT.db();
        assert!(silent.is_infinite() && silent.is_sign_negative());
        assert_eq!(Gain::from_db(100.0), Gain::MAX);
    }

    #[test]
    fn the_ratio_and_the_scale_agree() {
        assert!((Gain::UNITY.ratio() - 1.0).abs() < f32::EPSILON);
        assert!((Gain::MAX.ratio() - 4.0).abs() < f32::EPSILON);
        assert_eq!(Gain::from_ratio(1.0), Gain(UNITY_SCALE));
        assert_eq!(Gain::MAX, Gain(MAX_SCALE));
    }

    #[test]
    fn levels_and_gains_read_as_sentences() {
        assert_eq!(Gain::SILENT.to_string(), "silent");
        assert_eq!(Gain::UNITY.to_string(), "+0.0 dB");
        assert_eq!(Gain::from_ratio(0.5).to_string(), "-6.0 dB");
        assert_eq!(Level::SILENT.to_string(), "silent");
        assert_eq!(Level(32_768).to_string(), "0.0 dBFS");
        assert_eq!(Level(16_384).to_string(), "-6.0 dBFS");
        assert!((Level(16_384).fraction() - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn controls_reach_the_channel_from_another_thread() {
        fn movable<T: Send + Sync>() {}
        movable::<Controls>();

        let channel = Arc::new(channel());
        let controls = Controls::new(&channel);
        let elsewhere = controls.clone();
        std::thread::spawn(move || {
            elsewhere.set_gain(Gain::from_ratio(0.25));
            elsewhere.set_muted(true);
        })
        .join()
        .unwrap();

        assert_eq!(controls.gain(), Gain::from_ratio(0.25));
        assert!(controls.is_muted());
        assert!(channel.is_muted());

        let mut samples = [4_000i16; 4];
        channel.apply(&mut samples, 4);
        assert_eq!(controls.level(), Level::SILENT);
        assert_eq!(controls.clipped(), 0);
    }
}
