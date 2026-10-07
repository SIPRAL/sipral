// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! CoreAudio device I/O for macOS and iOS.
//!
//! Mono 16-bit frames in and out, at a size and rate fixed at open. No
//! codec, jitter buffer or call (`docs/05-media.md`). Device enumeration,
//! default changes and unplugs are handled here; an unplug is a polled
//! [`DeviceEvent`], not an error.
//!
//! Volume, mute and metering are applied to the frames ([`Controls`]).
//! The unit is `kAudioUnitSubType_VoiceProcessingIO`, which brings the
//! system echo canceller. The render-to-capture delay is still reported
//! (`Stream::latency`, `render_delay`) for an application canceller and for
//! latency budgets; see [`Latency`].
//!
//! Off Apple platforms the portable types still compile, so code above can
//! name them; nothing that links a framework is exported.
//!
//! Written from Apple's published headers and documented ABI
//! (`docs/02-clean-room.md`).
//!
//! # Getting a call's worth of audio
//!
//! ```no_run
//! # #[cfg(any(target_os = "macos", target_os = "ios"))]
//! # fn main() -> Result<(), sipral_io_coreaudio::Error> {
//! use sipral_io_coreaudio::{Stream, StreamConfig, StreamFormat};
//!
//! let format = StreamFormat::narrowband();
//! let mut stream = Stream::open(StreamConfig::new(format))?;
//! stream.start()?;
//!
//! let mut frame = vec![0i16; format.frame_samples()];
//! let (mut capture, mut playback) = stream.split();
//! while capture.read(&mut frame) {
//!     // encode, send, and put what came back from the far end into playback
//!     playback.write(&frame);
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(any(target_os = "macos", target_os = "ios")))]
//! # fn main() {}
//! ```

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
// tests say what they mean; the no-panic discipline is for the library
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

mod counters;
mod device;
mod format;
mod latency;
mod status;

pub use counters::Counters;
pub use device::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, StreamEvent};
pub use format::StreamFormat;
pub use latency::{Latency, RenderDelay};
pub use level::{Controls, Gain, Level};
pub use status::{Error, OsStatus};

pub(crate) use sipral_io_common::level;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use sipral_io_common::{gate, ring};

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod abi;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod stream;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod sys;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use stream::{Capture, Playback, Stream, StreamConfig, StreamKind, voice_units_open};

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod realtime;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use realtime::{audio_period, run_as_audio};

// macOS only: iOS routes through `AVAudioSession`, owned by the application.
#[cfg(target_os = "macos")]
mod hal;

/// Where a test that opens the real devices plays: a virtual loopback device
/// when the machine has one.
#[cfg(test)]
mod quiet;

#[cfg(target_os = "macos")]
pub use hal::{
    DeviceMonitor, default_device, device_with_uid, devices, is_alive, latency, render_delay,
};

#[cfg(test)]
mod tests {
    use super::{
        Counters, Device, DeviceChoice, DeviceEvent, DeviceId, Direction, Error, Gain, Latency,
        Level, OsStatus, RenderDelay, StreamEvent, StreamFormat,
    };

    #[test]
    fn the_portable_surface_is_portable() {
        let format = StreamFormat::narrowband();
        assert_eq!(format.frame_bytes(), format.frame_samples() * 2);

        let device = Device {
            id: DeviceId::new(1),
            name: String::new(),
            uid: None,
            input_channels: 1,
            output_channels: 0,
        };
        assert!(device.is_input());
        assert_eq!(
            DeviceEvent::DefaultChanged(Direction::Output),
            DeviceEvent::DefaultChanged(Direction::Output)
        );
        assert_eq!(StreamEvent::DeviceLost, StreamEvent::DeviceLost);
        assert_eq!(
            DeviceChoice::Preferred("BuiltInSpeakerDevice".to_string()),
            DeviceChoice::Preferred("BuiltInSpeakerDevice".to_string())
        );
        assert_eq!(Gain::default(), Gain::UNITY);
        assert_eq!(Level::default(), Level::SILENT);
        assert_eq!(Counters::default().captured, 0);
        assert_eq!(RenderDelay::default().total(), core::time::Duration::ZERO);
        assert_eq!(RenderDelay::default().capture, Latency::default());
        assert_eq!(
            Error::Call {
                call: "AudioUnitInitialize",
                status: OsStatus::OK,
            }
            .to_string(),
            "AudioUnitInitialize returned 0"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn the_stream_types_are_there_on_apple_platforms() {
        use super::{Stream, StreamConfig};

        fn movable<T: Send>() {}
        fn shareable<T: Send + Sync>() {}

        let config = StreamConfig::new(StreamFormat::narrowband());
        assert_eq!(config.format, StreamFormat::narrowband());
        movable::<Stream>();
        shareable::<super::Controls>();
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn nothing_that_needs_a_framework_is_compiled_elsewhere() {
        assert_eq!(StreamFormat::default(), StreamFormat::narrowband());
    }
}
