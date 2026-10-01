// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The seam between the engine and a platform.
//!
//! Everything the engine knows about devices it learns through [`Backend`],
//! and everything it does to one it does through a [`CaptureStream`] or a
//! [`PlaybackStream`]. The platform crates — `sipral-io-coreaudio`,
//! `sipral-io-wasapi`, `sipral-io-aaudio` — sit behind these three traits and nothing else, so
//! that every rule the engine keeps (a handle that survives a refresh, a
//! device with no channels refused, a loss reopened on the fallback, a
//! setting carried across a change) is written once and tested against a
//! backend made of fakes, with no device in the room.

use core::fmt;
use core::time::Duration;

use sipral_io_common::level::Controls;

use crate::device::{Direction, Role};

/// One device as a platform lists it, before the engine has named it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawDevice {
    /// The platform's stable identity: a CoreAudio UID, a WASAPI endpoint
    /// identifier, a kind and an address on Android.
    pub identity: String,
    /// What it is called.
    pub name: String,
    /// How many channels it captures.
    pub input_channels: u32,
    /// How many channels it plays.
    pub output_channels: u32,
    /// Whether the system records from it by default.
    pub default_input: bool,
    /// Whether the system plays to it by default.
    pub default_output: bool,
}

/// What the platform announced since the engine last asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A device arrived or left.
    ListChanged,
    /// The system's default for one direction moved.
    DefaultChanged(Direction),
}

/// A rate and a frame length: what a stream is asked for, and what it
/// answers with, which need not be the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    /// Samples per second.
    pub sample_rate_hz: u32,
    /// Samples per frame.
    pub frame_samples: usize,
}

impl Format {
    /// Twenty milliseconds at `sample_rate_hz`.
    #[must_use]
    pub const fn twenty_ms(sample_rate_hz: u32) -> Self {
        Self {
            sample_rate_hz,
            frame_samples: (sample_rate_hz / 50) as usize,
        }
    }
}

/// Why a platform refused a device, or a list.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendError {
    /// Nothing is there to open in that direction.
    NoDevice,
    /// The platform refused, and this is what it said.
    Refused(String),
    /// The platform did not answer within the time the engine allows a
    /// driver to be stuck for.
    TimedOut,
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoDevice => f.write_str("no device"),
            Self::Refused(ref why) => f.write_str(why),
            Self::TimedOut => f.write_str("the platform did not answer in time"),
        }
    }
}

impl std::error::Error for BackendError {}

/// A platform's devices.
///
/// Every call here may block on a driver, which is why the engine makes them
/// from a thread it can abandon (`probe`) rather than from the caller's.
pub trait Backend: Send {
    /// Every device the platform has right now.
    ///
    /// # Errors
    /// Whatever the platform said.
    fn devices(&mut self) -> Result<Vec<RawDevice>, BackendError>;

    /// What the platform announced since the last call, one at a time.
    fn poll_notice(&mut self) -> Option<Notice>;

    /// Open the microphone on the device with `identity`, or on the
    /// system's default input for `None`, as close to `wanted` as the
    /// platform allows.
    ///
    /// # Errors
    /// [`BackendError::NoDevice`] when nothing is there, and
    /// [`BackendError::Refused`] naming the call that refused.
    fn open_capture(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn CaptureStream>, BackendError>;

    /// The same for a loudspeaker.
    ///
    /// # Errors
    /// As [`Backend::open_capture`].
    fn open_playback(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError>;

    /// Open the ringer on the device with `identity`, or wherever the
    /// platform plays a ring for `None`.
    ///
    /// The loudspeaker by default. A platform that tells a ring from a call
    /// — Android, whose ring is a ringtone stream that the platform plays
    /// where a ring goes, while a call's output is a voice stream it puts
    /// on the call's route — opens it as one.
    ///
    /// # Errors
    /// As [`Backend::open_capture`].
    fn open_ringer(
        &mut self,
        identity: Option<&str>,
        wanted: Format,
    ) -> Result<Box<dyn PlaybackStream>, BackendError> {
        self.open_playback(identity, wanted)
    }

    /// Open a call's microphone and loudspeaker together, each on its own
    /// device (`None` for the system's), as close to `wanted` as the platform
    /// allows.
    ///
    /// Two separate opens by default. A platform that runs the two as one
    /// unit ([`Backend::duplex_only`]) opens that unit here, once, with both
    /// devices named up front, and answers with its two halves.
    fn open_duplex(
        &mut self,
        microphone: Option<&str>,
        speaker: Option<&str>,
        wanted: Format,
    ) -> Duplex {
        // the loudspeaker first, as the engine always asked
        let playback = self.open_playback(speaker, wanted);
        let capture = self.open_capture(microphone, wanted);
        (capture, playback)
    }

    /// Whether this platform runs the microphone and the loudspeaker as one
    /// unit, so that the two halves are opened and reopened together
    /// ([`Backend::open_duplex`]).
    fn duplex_only(&self) -> bool {
        false
    }

    /// Whether a role can be put on a device of the application's choosing.
    ///
    /// Every role by default, and the loudspeaker everywhere. A duplex
    /// platform that cannot name the microphone's device apart from the
    /// loudspeaker's, or open a ringer beside the call's unit, says no for
    /// those two — iOS, whose route is the audio session's.
    fn chooses(&self, role: Role) -> bool {
        role == Role::Speaker || !self.duplex_only()
    }

    /// Whether every stream opened from now on asks for the platform's own
    /// echo cancellation behind the microphone (`on`, the default) or opens
    /// without it ([`Config::system_echo_cancellation`](crate::Config::system_echo_cancellation)).
    /// A platform with nothing to turn off ignores it, and a stream says
    /// what it got ([`CaptureStream::system_echo_cancellation`]).
    fn set_system_echo_cancellation(&mut self, _on: bool) {}

    /// How the pump's thread asks the platform's scheduler for the class
    /// audio runs in, or nothing where this backend has none to ask for.
    ///
    /// The engine calls what this returns once, on the pump's own thread,
    /// before the first tick, and keeps what it answers for as long as that
    /// thread runs: a registration that is given back when it is dropped —
    /// Windows' — is given back when the pump finishes.
    fn pump_scheduling(&self) -> Option<Promote> {
        None
    }
}

/// A real-time scheduling class the calling thread holds for as long as this
/// value lives.
pub type Promoted = Box<dyn core::any::Any>;

/// Ask the platform to run the calling thread as audio: `Some` with what it
/// granted, `None` when it refused.
pub type Promote = std::sync::Arc<dyn Fn() -> Option<Promoted> + Send + Sync>;

/// What the pump's thread asked of the scheduler, and what it got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheduling {
    /// The platform has no class to ask for: the thread runs as any other.
    Ordinary,
    /// The platform runs it as audio.
    Granted,
    /// It was asked and refused, and the thread runs as any other.
    Refused,
}

/// A call's two halves, as a platform answered for each.
pub type Duplex = (
    Result<Box<dyn CaptureStream>, BackendError>,
    Result<Box<dyn PlaybackStream>, BackendError>,
);

/// What every stream answers, whichever way it runs.
pub trait StreamCommon: Send {
    /// The rate and frame length the stream actually delivers.
    fn format(&self) -> Format;
    /// The identity of the device it landed on.
    fn identity(&self) -> &str;
    /// Whether the device under it has gone. Answered once; after that the
    /// stream is stopped and carries nothing.
    fn lost(&mut self) -> bool;
    /// Gain, mute and the meter, applied to the frames on the way past.
    fn controls(&self) -> Controls;
    /// What the device adds between the frame and the air, or the air and
    /// the frame.
    fn latency(&self) -> Duration;
}

/// A microphone, read a frame at a time.
pub trait CaptureStream: StreamCommon {
    /// Take one frame, or say there is not a whole one yet.
    fn read(&mut self, frame: &mut [i16]) -> bool;
    /// Whether the platform is cancelling the loudspeaker's echo out of
    /// these frames itself.
    fn system_echo_cancellation(&self) -> bool;
}

/// A loudspeaker, written a frame at a time.
pub trait PlaybackStream: StreamCommon {
    /// Queue one frame, or say there is no room for a whole one.
    fn write(&mut self, frame: &[i16]) -> bool;
    /// Samples queued and not yet played.
    fn queued(&self) -> usize;
    /// The most samples the device has taken in one go so far, or nothing
    /// for a device fed a frame at a time. The pump keeps this much queued
    /// on top of its own couple of frames, so that a device which takes a
    /// long slice at once — a narrowband headset under the voice unit asks
    /// for half a second — finds all of it.
    fn burst(&self) -> usize {
        0
    }
    /// Samples the device asked for and found nothing queued for, and so
    /// played silence in place of, since the stream opened: an underrun,
    /// counted where the platform counts them, and zero where it does not.
    fn starved(&self) -> u64 {
        0
    }
}
