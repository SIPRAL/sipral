// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! WASAPI device I/O for Windows.
//!
//! Frames of mono sixteen-bit samples come out of the microphone and go into
//! the speaker, at a size and a rate fixed when the stream opens. That is the
//! whole of it. There is no codec here, no jitter buffer, no packet and no
//! call: `docs/05-media.md` draws the line and this crate stays under it.
//!
//! Endpoint enumeration, default changes and unplugs are handled here; an
//! unplug is a polled [`DeviceEvent`], not an error.
//!
//! * **An endpoint is one direction.** So there is a [`CaptureStream`] and
//!   a [`PlaybackStream`], no duplex type, and microphone and speaker can be
//!   on different devices.
//! * **The rate is the endpoint's.** Shared mode runs the engine's mix
//!   format (usually 48 kHz float). Channels are folded and samples
//!   converted to mono 16-bit, but nothing is resampled: `sipral-media` owns
//!   resampling and drift. [`CaptureStream::format`] is what the caller gets;
//!   [`CaptureStream::device_format`] is what the endpoint runs.
//!
//! Every stream asks to be a communications stream
//! (`IAudioClient2::SetClientProperties`), which is what gets the endpoint's
//! echo cancellation; [`Category`] reports whether Windows agreed.
//!
//! Volume, mute and metering are applied to the frames ([`Controls`]).
//! Off Windows the portable types still compile; nothing that links a
//! Windows library is exported.
//!
//! Written from Microsoft's published headers and documented ABI
//! (`docs/02-clean-room.md`).
//!
//! # Getting a call's worth of audio
//!
//! ```no_run
//! # #[cfg(target_os = "windows")]
//! # fn main() -> Result<(), sipral_io_wasapi::Error> {
//! use sipral_io_wasapi::{CaptureStream, PlaybackStream, StreamConfig, StreamFormat};
//!
//! let wanted = StreamConfig::new(StreamFormat::narrowband());
//! let mut microphone = CaptureStream::open(&wanted)?;
//! let mut speaker = PlaybackStream::open(&wanted)?;
//! microphone.start()?;
//! speaker.start()?;
//!
//! // the endpoint decides the rate: at 48 kHz a 20 ms frame is 960 samples
//! let mut frame = vec![0i16; microphone.format().frame_samples()];
//! while microphone.read(&mut frame) {
//!     // encode, send, and put what came back from the far end into the speaker
//!     speaker.write(&frame);
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "windows"))]
//! # fn main() {}
//! ```

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
// The stream types linked above exist only on Windows. The docs are read
// built for Windows, where scripts/check.sh runs rustdoc with warnings fatal,
// so the links stay checked there.
#![cfg_attr(not(target_os = "windows"), allow(rustdoc::broken_intra_doc_links))]
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

mod category;
mod counters;
mod device;
mod format;
mod status;

pub use category::Category;
pub use counters::Counters;
pub use device::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, StreamEvent};
pub use format::{DeviceFormat, SampleFormat, StreamFormat};
pub use level::{Controls, Gain, Level};
pub use status::{Error, HResult};

pub(crate) use sipral_io_common::level;

#[cfg(target_os = "windows")]
pub(crate) use sipral_io_common::{gate, ring};

// layouts and conversions are tested on every target
#[cfg(any(target_os = "windows", test))]
mod abi;
#[cfg(any(target_os = "windows", test))]
mod convert;
#[cfg(any(target_os = "windows", test))]
mod mixformat;

#[cfg(target_os = "windows")]
mod com;
#[cfg(target_os = "windows")]
mod endpoint;
#[cfg(target_os = "windows")]
mod stream;
#[cfg(target_os = "windows")]
mod sys;

#[cfg(all(test, target_os = "windows"))]
mod fake;

#[cfg(target_os = "windows")]
pub use endpoint::{DeviceMonitor, default_device, devices};
#[cfg(target_os = "windows")]
pub use stream::{CaptureStream, PlaybackStream, StreamConfig, channels};

/// The calling thread's MMCSS Pro Audio registration, for a caller's pump
/// thread. Drop it on the same thread to release it.
#[cfg(target_os = "windows")]
pub struct ProAudio {
    _registration: com::Priority,
}

/// Register the calling thread as Pro Audio, or `None` when MMCSS refuses
/// (no audio service, or none in this session); the thread then runs normally.
#[cfg(target_os = "windows")]
#[must_use]
pub fn pro_audio_thread() -> Option<ProAudio> {
    com::Priority::pro_audio().map(|registration| ProAudio {
        _registration: registration,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Category, Counters, Device, DeviceChoice, DeviceEvent, DeviceFormat, DeviceId, Direction,
        Error, Gain, HResult, Level, SampleFormat, StreamEvent, StreamFormat,
    };

    #[test]
    fn the_portable_surface_is_portable() {
        let format = StreamFormat::narrowband();
        assert_eq!(format.frame_bytes(), format.frame_samples() * 2);

        let device = Device {
            id: DeviceId::new("{0.0.1.00000000}.{one}"),
            name: String::new(),
            direction: Direction::Input,
            is_default: true,
        };
        assert_eq!(device.direction, Direction::Input);
        assert_eq!(
            DeviceEvent::DefaultChanged(Direction::Output),
            DeviceEvent::DefaultChanged(Direction::Output)
        );
        assert_eq!(StreamEvent::DeviceLost, StreamEvent::DeviceLost);
        assert_eq!(
            DeviceChoice::Preferred(DeviceId::new("{0.0.1.00000000}.{one}")),
            DeviceChoice::Preferred(DeviceId::new("{0.0.1.00000000}.{one}"))
        );
        assert_eq!(Gain::default(), Gain::UNITY);
        assert_eq!(Level::default(), Level::SILENT);
        assert_eq!(Counters::default().captured, 0);
        assert!(Category::Communications.is_communications());
        assert_eq!(
            DeviceFormat {
                sample_rate_hz: 48_000,
                channels: 2,
                sample: SampleFormat::F32,
            }
            .block_align(),
            8
        );
        assert_eq!(
            Error::Call {
                call: "IAudioClient::Initialize",
                status: HResult::OK,
            }
            .to_string(),
            "IAudioClient::Initialize returned 0x00000000 (S_OK)"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn the_stream_types_are_there_on_windows() {
        use super::{CaptureStream, PlaybackStream, StreamConfig};

        fn movable<T: Send>() {}
        fn shareable<T: Send + Sync>() {}

        let config = StreamConfig::new(StreamFormat::narrowband());
        assert_eq!(config.format, StreamFormat::narrowband());
        assert_eq!(config.device, DeviceChoice::System);
        movable::<CaptureStream>();
        movable::<PlaybackStream>();
        shareable::<super::Controls>();
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn nothing_that_needs_a_windows_library_is_compiled_elsewhere() {
        assert_eq!(StreamFormat::default(), StreamFormat::narrowband());
    }
}
