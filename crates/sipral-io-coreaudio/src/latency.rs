// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! How long a sample takes to get out of the machine and back into it.
//!
//! An echo canceller is handed the frame that was leaving the loudspeaker
//! while the microphone was open, and this is how far back that frame is.
//! CoreAudio does not keep the number in one property the way WASAPI does.
//! Apple's hardware layer reports four things per direction — what the device
//! itself adds, how far ahead of or behind the hardware the IO has to stay,
//! how many frames go in one IO buffer, and, on the stream object rather than
//! the device, what the stream adds — and the header is explicit that the
//! device's and the stream's are summed rather than one standing for the
//! other. The loop is both directions of that.
//!
//! Nothing here is a measurement. It is what the device says about itself, and
//! a device that will not answer for a part is reported as not having answered
//! rather than as having said zero: three parts out of four is worth more than
//! no number at all, and a caller that needs to know which it got has
//! [`Latency::is_complete`].

use core::fmt;
use core::time::Duration;

/// Nanoseconds in a second, which is what turns frames at a rate into a time.
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// What one direction of one device adds, in frames, part by part.
///
/// Each part is `None` when the device would not answer for it, which is not
/// the same as zero — a headset that reports no latency of its own has said
/// something, and one whose driver has no such property has not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Latency {
    /// `kAudioDevicePropertyLatency` on this direction's scope: the frames the
    /// device itself adds.
    pub device_frames: Option<u32>,
    /// `kAudioStreamPropertyLatency` on the first stream of this direction,
    /// which the header says is added to the device's rather than replacing
    /// it. The first stream is the one carrying channel one, and this crate is
    /// mono.
    pub stream_frames: Option<u32>,
    /// `kAudioDevicePropertySafetyOffset`: how far ahead of the hardware
    /// position, for playback, or behind it, for capture, the IO has to stay.
    pub safety_offset_frames: Option<u32>,
    /// `kAudioDevicePropertyBufferFrameSize`: the frames in one IO buffer, one
    /// of which passes between a frame being handed over and the hardware
    /// having it.
    pub buffer_frames: Option<u32>,
    /// `kAudioDevicePropertyNominalSampleRate`, rounded to whole hertz. It is
    /// what turns the frames above into a time, so without it there is no
    /// duration to give.
    pub sample_rate_hz: Option<u32>,
}

impl Latency {
    /// The parts that were answered, added up.
    #[must_use]
    pub const fn frames(&self) -> u32 {
        answered(self.device_frames)
            .saturating_add(answered(self.stream_frames))
            .saturating_add(answered(self.safety_offset_frames))
            .saturating_add(answered(self.buffer_frames))
    }

    /// The same as a time, at the rate the device said it was running.
    ///
    /// Zero when the device would not say what rate that is, because frames
    /// without a rate are not a duration and inventing one would be a guess
    /// arriving where a fact is expected.
    #[must_use]
    pub fn duration(&self) -> Duration {
        match self.sample_rate_hz {
            Some(rate) if rate > 0 => Duration::from_nanos(
                u64::from(self.frames()).saturating_mul(NANOS_PER_SECOND) / u64::from(rate),
            ),
            _ => Duration::ZERO,
        }
    }

    /// Whether every part was answered.
    ///
    /// `false` means the number is a floor rather than the delay: what is
    /// missing was left out, not estimated.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.device_frames.is_some()
            && self.stream_frames.is_some()
            && self.safety_offset_frames.is_some()
            && self.buffer_frames.is_some()
            && self.sample_rate_hz.is_some()
    }
}

impl fmt::Display for Latency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} frames", self.frames())?;
        match self.sample_rate_hz {
            Some(rate) => write!(f, " at {rate} Hz")?,
            None => f.write_str(" at an unreported rate")?,
        }
        f.write_str(" (")?;
        part(f, "device", self.device_frames)?;
        f.write_str(", ")?;
        part(f, "stream", self.stream_frames)?;
        f.write_str(", ")?;
        part(f, "safety offset", self.safety_offset_frames)?;
        f.write_str(", ")?;
        part(f, "buffer", self.buffer_frames)?;
        f.write_str(")")
    }
}

/// The whole loop: down to the loudspeaker, through the room, and back up from
/// the microphone.
///
/// This is the number an echo canceller wants, and the two halves are kept
/// apart because they can be different devices and because a delay that is
/// wrong is usually wrong on one side.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenderDelay {
    /// From this crate to the loudspeaker.
    pub playback: Latency,
    /// From the microphone to this crate.
    pub capture: Latency,
}

impl RenderDelay {
    /// Both halves as one time, which is what an echo canceller is told to
    /// look back by.
    ///
    /// A machine that answered nothing gives zero, which pairs a capture with
    /// the frame handed to the loudspeaker immediately before it. That is the
    /// same thing a caller who never asked would get, and it is the honest
    /// answer rather than a number invented to look like one.
    #[must_use]
    pub fn total(&self) -> Duration {
        self.playback
            .duration()
            .saturating_add(self.capture.duration())
    }

    /// Whether both directions answered for every part.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.playback.is_complete() && self.capture.is_complete()
    }
}

impl fmt::Display for RenderDelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} to the loudspeaker and back: playback {}, capture {}",
            self.total(),
            self.playback,
            self.capture
        )
    }
}

/// A part the device answered for, or nothing where it did not.
const fn answered(part: Option<u32>) -> u32 {
    match part {
        Some(frames) => frames,
        None => 0,
    }
}

/// One part of the breakdown, saying plainly when there was none.
fn part(f: &mut fmt::Formatter<'_>, name: &str, frames: Option<u32>) -> fmt::Result {
    match frames {
        Some(frames) => write!(f, "{name} {frames}"),
        None => write!(f, "{name} unreported"),
    }
}

#[cfg(test)]
mod tests {
    use super::{Latency, RenderDelay};
    use core::time::Duration;

    /// What a built-in output on a Mac looks like: everything answered.
    fn playback() -> Latency {
        Latency {
            device_frames: Some(371),
            stream_frames: Some(0),
            safety_offset_frames: Some(33),
            buffer_frames: Some(512),
            sample_rate_hz: Some(48_000),
        }
    }

    #[test]
    fn the_parts_of_one_direction_add_up_and_convert_at_the_devices_rate() {
        let leg = playback();
        assert_eq!(leg.frames(), 916);
        // 916 frames at 48 kHz, to the nanosecond the division leaves
        assert_eq!(leg.duration(), Duration::from_nanos(19_083_333));
        assert!(leg.is_complete());
    }

    #[test]
    fn a_part_the_device_never_answered_for_is_left_out_rather_than_guessed() {
        let leg = Latency {
            stream_frames: None,
            ..playback()
        };
        assert_eq!(leg.frames(), 916);
        assert!(!leg.is_complete(), "a floor is not the delay");
        assert!(leg.to_string().contains("stream unreported"));
    }

    #[test]
    fn frames_without_a_rate_are_not_a_duration() {
        let leg = Latency {
            sample_rate_hz: None,
            ..playback()
        };
        assert_eq!(leg.frames(), 916);
        assert_eq!(leg.duration(), Duration::ZERO);
        assert!(leg.to_string().contains("at an unreported rate"));

        // and a device claiming to run at no hertz at all is the same answer
        let stopped = Latency {
            sample_rate_hz: Some(0),
            ..playback()
        };
        assert_eq!(stopped.duration(), Duration::ZERO);
    }

    #[test]
    fn a_device_that_answered_nothing_gives_zero() {
        let nothing = RenderDelay::default();
        assert_eq!(nothing.total(), Duration::ZERO);
        assert!(!nothing.is_complete());
        assert_eq!(Latency::default().frames(), 0);
    }

    #[test]
    fn the_loop_is_both_directions_summed() {
        let delay = RenderDelay {
            playback: playback(),
            capture: Latency {
                device_frames: Some(84),
                stream_frames: Some(0),
                safety_offset_frames: Some(33),
                buffer_frames: Some(512),
                sample_rate_hz: Some(48_000),
            },
        };
        assert_eq!(
            delay.total(),
            delay.playback.duration() + delay.capture.duration()
        );
        // a bit over thirty milliseconds, which is what a Mac's own hardware
        // costs and why the number is worth asking for rather than assuming
        assert!(delay.total() > Duration::from_millis(32));
        assert!(delay.total() < Duration::from_millis(33));
        assert!(delay.is_complete());
    }

    #[test]
    fn one_direction_answering_nothing_still_leaves_the_other_countable() {
        let delay = RenderDelay {
            playback: playback(),
            capture: Latency::default(),
        };
        assert_eq!(delay.total(), delay.playback.duration());
        assert!(!delay.is_complete());
        assert!(delay.to_string().contains("capture 0 frames"));
    }

    #[test]
    fn a_device_reporting_absurd_numbers_does_not_wrap_round() {
        let absurd = Latency {
            device_frames: Some(u32::MAX),
            stream_frames: Some(u32::MAX),
            safety_offset_frames: Some(u32::MAX),
            buffer_frames: Some(u32::MAX),
            sample_rate_hz: Some(1),
        };
        assert_eq!(absurd.frames(), u32::MAX);
        assert_eq!(absurd.duration(), Duration::from_secs(u64::from(u32::MAX)));
    }
}
