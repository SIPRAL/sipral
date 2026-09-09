// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Volume, mute, and the number a meter is drawn from.
//!
//! The gain is applied to the samples on their way past. Windows has two
//! volumes it could have been handed to instead and neither of them belongs to
//! a call: `IAudioEndpointVolume` is the endpoint's own master, shared with
//! everything else on the machine and left where the call put it, and
//! `ISimpleAudioVolume` is the process's slot in the volume mixer, which is
//! one setting for the whole process however many streams it has open and
//! which Windows remembers between runs. What is done to the frames belongs to
//! the stream and goes when the stream goes.
//!
//! It is applied at the endpoint end of the ring rather than at the caller's,
//! because a mute has to be silent on the next period. The ring holds sixteen
//! frames by default, so a gain applied on the way in would be heard a third
//! of a second after the button was pressed.
//!
//! All of it runs on the audio thread, so it is integer arithmetic over
//! samples that are being copied anyway — one multiply, one shift, one clamp
//! and one comparison each — plus six relaxed atomics per pass. Nothing here
//! allocates, takes a lock, or reads a clock.

// The half of this file the audio thread uses is only reached from the
// platform code, and the types it hangs off are the portable surface and are
// exported everywhere. So on a target with no WASAPI what is left here does
// look unused, and is, until something on that target calls it.
#![cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Unity as a whole number of 256ths.
///
/// A power of two, so that applying a gain is a multiply and a shift rather
/// than a divide.
const UNITY_SCALE: u16 = 256;

/// Bits the scale is held in, which is what applying it shifts back by.
const SHIFT: u32 = 8;

/// The loudest a gain goes: four times, a little over twelve decibels.
///
/// Not a limit of the arithmetic — the products fit in a `u32` many times over
/// — but of what is worth offering. A microphone that needs more than four
/// times is a microphone that is not plugged in, and a slider that goes there
/// only lets somebody turn a quiet call into a distorted one.
const MAX_SCALE: u16 = 4 * UNITY_SCALE;

/// The magnitude of a sample at either end of the sixteen-bit range.
///
/// The negative end reaches one further than the positive one, so this is the
/// larger of the two and a peak is held in seventeen bits' worth of `u16`.
const FULL_SCALE: u16 = 32_768;

/// How long the loudest sample is held for: a tenth of a second.
///
/// The window is the whole of what makes a meter readable. Reporting the peak
/// since the last poll would make the number depend on how often the caller
/// asks — fast polling would show a bar that flickers between a syllable and
/// the gap after it, slow polling one that never comes down. A tenth of a
/// second is long enough that sixty polls a second see the same number for six
/// of them, and short enough that the bar follows speech rather than lagging
/// behind it.
const WINDOW_MILLIS: u32 = 100;

/// Samples one meter window covers at a rate.
pub(crate) const fn window_samples(sample_rate_hz: u32) -> u32 {
    let per_millisecond = sample_rate_hz / 1_000;
    if per_millisecond == 0 {
        // no endpoint runs below a kilohertz; a window of no samples would be
        // one that ends on every pass
        WINDOW_MILLIS
    } else {
        per_millisecond * WINDOW_MILLIS
    }
}

/// What the samples are multiplied by on their way to or from the endpoint.
///
/// Held as a whole number of 256ths rather than as a float, because the
/// multiplication happens on the audio thread and integers are what the
/// samples already are by then.
///
/// Both ends of the range are defined and neither of them wraps. A ratio below
/// zero, or one that is not a number at all, is [`Gain::SILENT`]; one above
/// four is [`Gain::MAX`]. Applying a gain saturates at the loudest and
/// quietest sample sixteen bits can hold, and every sample that lands there is
/// counted by [`Controls::clipped`] — so a gain set too high is a number
/// somebody can read rather than a distortion they can only hear.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gain(u16);

impl Gain {
    /// Nothing gets through. Not the same thing as a mute, which is a separate
    /// switch precisely so that unmuting gives back the volume that was set.
    pub const SILENT: Self = Self(0);

    /// The samples as the endpoint gave them, or as the caller wrote them.
    pub const UNITY: Self = Self(UNITY_SCALE);

    /// The loudest this crate will multiply by: four times, +12 dB.
    pub const MAX: Self = Self(MAX_SCALE);

    /// A gain from a plain multiplier, clamped into the range rather than
    /// refused.
    ///
    /// A slider that has been dragged past the end is a slider at the end, and
    /// a value that is not a number at all is silence — the only answer that
    /// cannot make somebody's ears worse.
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

    /// A gain from decibels, which is what a fader is marked in.
    ///
    /// Twenty times the logarithm, not ten: these are amplitudes, and halving
    /// one is six decibels rather than three. Getting that wrong is the
    /// standard way for a volume slider to feel broken at the quiet end.
    #[must_use]
    pub fn from_db(db: f32) -> Self {
        Self::from_ratio(10.0_f32.powf(db / 20.0))
    }

    /// What it reads as on a fader. Negative infinity when it is silent.
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

/// The loudest sample that has gone past recently.
///
/// After the gain and after the mute, because what a meter is asked is "is my
/// voice getting through", and a bar that keeps moving while the microphone is
/// muted answers the wrong question.
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

    /// The same as a fraction of full scale, which is what a bar is drawn to.
    #[must_use]
    pub fn fraction(self) -> f32 {
        f32::from(self.0) / f32::from(FULL_SCALE)
    }

    /// The same in decibels below full scale, which is what a meter is
    /// labelled in. Negative infinity for silence.
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

/// The gain, the mute and the meter for one stream.
///
/// One writer and any number of readers. Everything is relaxed: the audio
/// thread is the only thing that writes the meter, a control that arrives one
/// pass late is a slider that moved a few milliseconds ago, and an ordering
/// here would put a fence in the audio thread for the sake of a volume change
/// nobody can hear the timing of.
#[derive(Debug)]
pub(crate) struct Channel {
    scale: AtomicU16,
    muted: AtomicBool,
    clipped: AtomicU64,
    /// Samples in a window, from the rate the endpoint turned out to run.
    window: AtomicU32,
    /// The loudest in the window being filled, and in the last full one. The
    /// meter is the larger, which is what holds a peak for between one window
    /// and two.
    current: AtomicU16,
    previous: AtomicU16,
    counted: AtomicU32,
}

impl Channel {
    pub(crate) fn new(window: u32) -> Self {
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

    /// Say what the rate turned out to be. The endpoint decides it, and on a
    /// reopen it can decide differently.
    pub(crate) fn set_window(&self, window: u32) {
        self.window.store(window.max(1), Ordering::Relaxed);
    }

    pub(crate) fn set_gain(&self, gain: Gain) {
        self.scale.store(gain.0, Ordering::Relaxed);
    }

    pub(crate) fn gain(&self) -> Gain {
        Gain(self.scale.load(Ordering::Relaxed))
    }

    pub(crate) fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    pub(crate) fn is_muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    pub(crate) fn clipped(&self) -> u64 {
        self.clipped.load(Ordering::Relaxed)
    }

    /// What a meter should show: the loudest of the window being filled and
    /// the last full one.
    pub(crate) fn level(&self) -> Level {
        Level(
            self.current
                .load(Ordering::Relaxed)
                .max(self.previous.load(Ordering::Relaxed)),
        )
    }

    /// Forget what was heard. For a stream that has stopped, whose meter would
    /// otherwise stay where the last pass left it and read as a live signal.
    pub(crate) fn quiet(&self) {
        self.current.store(0, Ordering::Relaxed);
        self.previous.store(0, Ordering::Relaxed);
        self.counted.store(0, Ordering::Relaxed);
    }

    /// Scale a block of samples where they lie, and note what came out.
    ///
    /// `covered` is how much endpoint time the block accounts for, which is
    /// not always its length: a starved render pass scales what there was and
    /// leaves the rest silent, and the window has to advance by the silence
    /// too, or a stream that stopped being fed would leave its meter frozen at
    /// the last thing it heard.
    pub(crate) fn apply(&self, samples: &mut [i16], covered: usize) {
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

    /// Move the meter's window on by `covered` samples, having heard `peak`.
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

/// The volume, the mute and the meter of one stream.
///
/// A handle rather than methods on the stream, because the slider and the
/// meter are on the thread that draws the window and the frames are on the
/// thread that carries the call. It can be cloned, sent and kept after the
/// stream is dropped; what it then reports is the last thing the stream heard.
///
/// Reading it is a couple of relaxed loads, so a user interface may poll
/// [`Controls::level`] on every frame it draws.
#[derive(Clone, Debug)]
pub struct Controls {
    channel: Arc<Channel>,
}

impl Controls {
    pub(crate) fn new(channel: &Arc<Channel>) -> Self {
        Self {
            channel: Arc::clone(channel),
        }
    }

    /// Set what the samples are multiplied by. Takes effect on the next period
    /// the endpoint asks for, which is one period away and not one ring away.
    pub fn set_gain(&self, gain: Gain) {
        self.channel.set_gain(gain);
    }

    /// What it is set to, mute or no mute.
    #[must_use]
    pub fn gain(&self) -> Gain {
        self.channel.gain()
    }

    /// Mute or unmute, without disturbing the gain: unmuting gives back
    /// exactly the volume that was set before.
    ///
    /// A muted stream keeps running rather than stopping. The endpoint is
    /// still read and the ring still moves, at the rate it always did, so that
    /// unmuting is heard immediately instead of replaying however much audio
    /// piled up while nobody was listening.
    pub fn set_muted(&self, muted: bool) {
        self.channel.set_muted(muted);
    }

    /// Whether it is muted.
    #[must_use]
    pub fn is_muted(&self) -> bool {
        self.channel.is_muted()
    }

    /// The loudest sample of the last tenth of a second, after the gain and
    /// the mute.
    #[must_use]
    pub fn level(&self) -> Level {
        self.channel.level()
    }

    /// Samples that came out at the end of the range because the gain put them
    /// there.
    ///
    /// Only ever grows, so two readings subtract. Anything above zero on a
    /// call means the gain is set too high for this microphone, and that is
    /// worth showing next to the slider that caused it.
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
        // a window of a hundred samples, so a test can fill one without
        // writing out a tenth of a second of audio
        Channel::new(100)
    }

    #[test]
    fn a_window_is_a_tenth_of_a_second_at_any_rate() {
        assert_eq!(window_samples(8_000), 800);
        assert_eq!(window_samples(48_000), 4_800);
        // 44100 has no whole number of samples per millisecond, and 99.8 ms is
        // near enough for a bar on a screen
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
        // the loudest magnitude, which the negative end holds
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
        // 20000 * 4 is over the end of the range, 1000 * 4 is not
        let mut samples = [20_000i16, -20_000, 1_000, -1_000];
        channel.apply(&mut samples, 4);

        assert_eq!(samples, [i16::MAX, i16::MIN, 4_000, -4_000]);
        // counted per sample, not per block: two of the four landed at an end
        assert_eq!(channel.clipped(), 2);
        assert_eq!(channel.level().peak(), 32_768);

        // and it accumulates rather than being reset by the next block
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
            // the sign is the one thing a wrap would take away
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
        // muting does not spend the setting
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
        // one window to end the one that heard the voice, one to end the one
        // after it
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

        // the same answer however often it is asked, which is what a meter
        // polled at sixty hertz depends on
        for _ in 0..10 {
            assert_eq!(channel.level().peak(), 8_000);
        }

        // quiet blocks that do not end the window leave it standing
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

        // the window it fell in ends here, so it becomes the last full one and
        // goes on showing
        let mut quiet = [0i16; 50];
        channel.apply(&mut quiet, 50);
        assert_eq!(channel.level().peak(), 8_000);
        channel.apply(&mut quiet, 50);
        assert_eq!(channel.level().peak(), 8_000);

        // and a window and a half after it happened, it is gone
        channel.apply(&mut quiet, 50);
        assert_eq!(channel.level(), Level::SILENT);
    }

    #[test]
    fn silence_the_caller_never_wrote_still_moves_the_window_on() {
        let channel = channel();
        let mut spike = [9_000i16; 4];
        channel.apply(&mut spike, 4);
        assert_eq!(channel.level().peak(), 9_000);

        // a starved render pass: four samples came out of the ring and the
        // endpoint asked for two hundred, so two windows have gone by
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
        // at the hundred samples this channel was built with, these three
        // would have taken the peak away
        for _ in 0..3 {
            channel.apply(&mut quiet, 700);
        }
        assert_eq!(channel.level().peak(), 7_000);

        // and a window of no samples at all is one that ends on every block,
        // which is not a window: it is clamped rather than divided by
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
        // past either end, and the value that is not a number at all
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
        // six decibels down is half, not a bit over two thirds
        assert!((Gain::from_db(-6.02).ratio() - 0.5).abs() < 0.01);
        assert!((Gain::from_db(6.02).ratio() - 2.0).abs() < 0.02);
        assert!(Gain::UNITY.db().abs() < f32::EPSILON);
        assert_eq!(Gain::from_db(f32::NEG_INFINITY), Gain::SILENT);
        // silence has no decibels, and saying so is better than a number
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

        // and it outlives what it was reading, rather than dangling
        let mut samples = [4_000i16; 4];
        channel.apply(&mut samples, 4);
        assert_eq!(controls.level(), Level::SILENT);
        assert_eq!(controls.clipped(), 0);
    }
}
