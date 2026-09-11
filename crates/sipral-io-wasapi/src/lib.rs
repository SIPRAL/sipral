// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! WASAPI device I/O for Windows.
//!
//! Frames of mono sixteen-bit samples come out of the microphone and go into
//! the speaker, at a size and a rate fixed when the stream opens. That is the
//! whole of it. There is no codec here, no jitter buffer, no packet and no
//! call: `docs/05-media.md` draws the line and this crate stays under it.
//!
//! What is here, because the same document says it belongs here, is the
//! platform work that eats the time on this kind of project: enumerating
//! endpoints, noticing that the default one changed, and coping with a headset
//! being unplugged in the middle of a call. That last one is not an error and
//! is not reported as one — it arrives as a [`DeviceEvent`] the caller polls
//! for, so that nothing above this crate has to know WASAPI exists.
//!
//! Two things about Windows shape the interface and are worth reading before
//! the rest:
//!
//! * **An endpoint is one direction.** A headset is two of them, with two
//!   identifiers and two clocks, so there is a [`CaptureStream`] and a
//!   [`PlaybackStream`] and no duplex type. That is not a simplification, it is
//!   what lets a softphone put the microphone on one device and the speaker on
//!   another, which is what a virtual cable and most USB headsets need.
//! * **The rate is the endpoint's, not the caller's.** Shared mode runs the
//!   audio engine's mix format, which on most machines is 48 kHz float. This
//!   crate folds the channels and converts the samples, because its boundary is
//!   mono sixteen-bit, and it does not resample, because `sipral-media` owns
//!   resampling and the clock drift correction that goes with it. So
//!   [`CaptureStream::format`] reports what the caller will actually get and
//!   [`CaptureStream::device_format`] says what the endpoint is doing. A crate
//!   that quietly resampled would be easier to use and would hide the one
//!   number a media pipeline has to know.
//!
//! Every stream is opened as a communications stream, which is what Windows
//! applies the endpoint's own echo cancellation, noise suppression and gain
//! control to. It is one call — `IAudioClient2::SetClientProperties`, after
//! the client is activated and before it is initialised — and [`Category`] is
//! where the answer to it goes, because a stream that did not get it has no
//! system processing and the application above has to know that rather than
//! assume either way.
//!
//! The volume, the mute and the level meter are here too, and they are applied
//! to the frames rather than to any of the volumes Windows keeps — see
//! [`Controls`] for why neither of those belongs to a call. They are on a
//! handle that can be moved to the thread drawing the window, because that is
//! where a slider and a meter live.
//!
//! On a target that is not Windows the crate still compiles, and still exports
//! [`StreamFormat`], [`DeviceFormat`], [`SampleFormat`], [`Device`],
//! [`DeviceChoice`], [`DeviceEvent`], [`StreamEvent`], [`Controls`], [`Gain`],
//! [`Level`], [`Counters`], [`Category`], [`HResult`] and [`Error`], so that
//! portable code above can name what it will be handed. What it does not
//! export there is anything that would need a Windows library to link against.
//!
//! Written from Microsoft's published headers and documented ABI; see
//! `docs/02-clean-room.md` for why that matters.
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
//! // the endpoint decides the rate, so ask what it settled on before sizing
//! // anything: at 48 kHz a twenty-millisecond frame is 960 samples, not 160
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
// The stream types the two rules above link to are behind
// cfg(target_os = "windows"), so on any other target there is no item for
// those links to find and rustdoc is right to say so. They are not written as
// code spans for it: a link is what a reader of this crate's documentation
// needs, and the documentation a reader reads is built for Windows. It is the
// gate that keeps them honest -- scripts/check.sh runs rustdoc against
// x86_64-pc-windows-msvc with warnings fatal, where every one of them
// resolves or the step goes red.
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
mod level;
mod status;

pub use category::Category;
pub use counters::Counters;
pub use device::{Device, DeviceChoice, DeviceEvent, DeviceId, Direction, StreamEvent};
pub use format::{DeviceFormat, SampleFormat, StreamFormat};
pub use level::{Controls, Gain, Level};
pub use status::{Error, HResult};

// The ring, the gate, the structure layouts and the conversions are only ever
// reached by the platform code, but what they are for is to be right, and that
// is worth compiling and testing everywhere the workspace builds rather than
// only where the libraries are.
#[cfg(any(target_os = "windows", test))]
mod abi;
#[cfg(any(target_os = "windows", test))]
mod convert;
#[cfg(any(target_os = "windows", test))]
mod gate;
#[cfg(any(target_os = "windows", test))]
mod mixformat;
#[cfg(any(target_os = "windows", test))]
mod ring;

#[cfg(target_os = "windows")]
mod com;
#[cfg(target_os = "windows")]
mod endpoint;
#[cfg(target_os = "windows")]
mod stream;
#[cfg(target_os = "windows")]
mod sys;

#[cfg(target_os = "windows")]
pub use endpoint::{DeviceMonitor, default_device, devices};
#[cfg(target_os = "windows")]
pub use stream::{CaptureStream, PlaybackStream, StreamConfig};

#[cfg(test)]
mod tests {
    use super::{
        Category, Counters, Device, DeviceChoice, DeviceEvent, DeviceFormat, DeviceId, Direction,
        Error, Gain, HResult, Level, SampleFormat, StreamEvent, StreamFormat,
    };

    /// Everything named here has to exist on every target the workspace builds,
    /// or portable code a layer up cannot describe what it will be given.
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
        // the one answer that means the system is doing the cancelling, and
        // the one a caller has to be able to name to check for it
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
        // a stream has to be able to live on the thread that does the media,
        // which is not the thread that opened it
        movable::<CaptureStream>();
        movable::<PlaybackStream>();
        // and its controls on the one that draws the window
        shareable::<super::Controls>();
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn nothing_that_needs_a_windows_library_is_compiled_elsewhere() {
        // The crate builds on Linux and on macOS with the platform modules
        // gated out entirely, which is what lets the workspace be built and
        // linted on a machine that has never heard of WASAPI. The layout tests
        // and the ring still run there, because they are arithmetic.
        assert_eq!(StreamFormat::default(), StreamFormat::narrowband());
    }
}
