// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! CoreAudio device I/O for macOS and iOS.
//!
//! Frames of mono sixteen-bit samples come out of the microphone and go into
//! the speaker, at a size and a rate fixed when the stream opens. That is the
//! whole of it. There is no codec here, no jitter buffer, no packet and no
//! call: `docs/05-media.md` draws the line and this crate stays under it.
//!
//! What is here, because the same document says it belongs here, is the
//! platform work that eats the time on this kind of project: enumerating
//! devices, noticing that the default one changed, and coping with a headset
//! being unplugged in the middle of a call. That last one is not an error and
//! is not reported as one — it arrives as a [`DeviceEvent`] the caller polls
//! for, so that nothing above this crate has to know CoreAudio exists.
//!
//! The unit is `kAudioUnitSubType_VoiceProcessingIO`, which brings the
//! system's own echo cancellation. `docs/05-media.md` says we attach an echo
//! canceller rather than write one, and on Apple's platforms the best one is
//! already in the operating system.
//!
//! On a target with no CoreAudio the crate still compiles, and still exports
//! [`StreamFormat`], [`Device`], [`DeviceEvent`], [`Counters`] and [`Error`],
//! so that portable code above can name what it will be handed. What it does
//! not export there is anything that would need a framework to link against.
//!
//! Written from Apple's published headers and documented ABI; see
//! `docs/02-clean-room.md` for why that matters.
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
mod status;

pub use counters::Counters;
pub use device::{Device, DeviceEvent, DeviceId, Direction};
pub use format::StreamFormat;
pub use status::{Error, OsStatus};

// The ring and the gate are only ever instantiated by the platform code, but
// what they are for is to be right, and that is worth compiling and testing
// everywhere the workspace builds rather than only where the frameworks are.
#[cfg(any(target_os = "macos", target_os = "ios", test))]
mod gate;
#[cfg(any(target_os = "macos", target_os = "ios", test))]
mod ring;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod abi;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod stream;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod sys;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use stream::{Capture, Playback, Stream, StreamConfig};

// The hardware abstraction layer is macOS only. iOS routes through
// `AVAudioSession`, which is Objective-C and belongs to the application.
#[cfg(target_os = "macos")]
mod hal;

#[cfg(target_os = "macos")]
pub use hal::{DeviceMonitor, default_device, devices};

#[cfg(test)]
mod tests {
    use super::{
        Counters, Device, DeviceEvent, DeviceId, Direction, Error, OsStatus, StreamFormat,
    };

    /// Everything named here has to exist on every target the workspace
    /// builds, or portable code a layer up cannot describe what it will be
    /// given.
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
        assert_eq!(Counters::default().captured, 0);
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

        let config = StreamConfig::new(StreamFormat::narrowband());
        assert_eq!(config.format, StreamFormat::narrowband());
        // a stream has to be able to live on the thread that does the media
        movable::<Stream>();
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn nothing_that_needs_a_framework_is_compiled_elsewhere() {
        // The crate builds on Linux and on Windows with the platform module
        // gated out entirely, which is what lets the workspace be built and
        // linted on a machine that has never heard of CoreAudio.
        assert_eq!(StreamFormat::default(), StreamFormat::narrowband());
    }
}
