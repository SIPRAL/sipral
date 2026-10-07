// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! PipeWire device I/O for Linux desktops.
//!
//! Mono 16-bit frames in and out, at a size and rate fixed at open; no
//! codec or call (`docs/05-media.md`). Node enumeration, default changes and
//! unplugs are handled here; an unplug is a polled [`DeviceEvent`].
//!
//! * **A node is one direction** (`Audio/Sink` or `Audio/Source`), so there
//!   is a [`CaptureStream`] and a [`PlaybackStream`], no duplex type.
//! * **One fixed format is offered**: mono S16 at the requested rate, as a
//!   hand-built `SPA_TYPE_OBJECT_Format` pod (SPA's builder is `static
//!   inline`). PipeWire's adapter converts, so the caller always gets the
//!   rate it asked for.
//!
//! Streams set `media.role` `"Communication"` for routing; that is not echo
//! cancellation. PipeWire's canceller is `libpipewire-module-echo-cancel`,
//! loaded by the session, and a call is cancelled only when routed through
//! its source and sink (as defaults or named in the [`StreamConfig`]s).
//! Otherwise use the processor seam in `docs/05-media.md`.
//!
//! Volume, mute and metering are applied to the frames ([`Controls`]).
//!
//! A lost node is reported once as [`StreamEvent::DeviceLost`], never
//! silently rerouted: `PW_STREAM_FLAG_DONT_RECONNECT` pins each stream to
//! the node it opened on. A later default change is a
//! [`DeviceEvent::DefaultChanged`]; [`CaptureStream::recover`] and
//! [`PlaybackStream::recover`] move a stream.
//!
//! Off Linux the portable types still compile. On Linux, linking needs
//! `libpipewire-0.3.so` (Debian `libpipewire-0.3-dev`) and running needs a
//! PipeWire daemon; `interop/pipewire/` has an image with both.
//!
//! Written from PipeWire's and SPA's published headers
//! (`docs/02-clean-room.md`, `THIRD-PARTY-NOTICES.md`).
//!
//! # Getting a call's worth of audio
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> Result<(), sipral_io_pipewire::Error> {
//! use sipral_io_pipewire::{CaptureStream, PlaybackStream, StreamConfig, StreamFormat};
//!
//! let wanted = StreamConfig::new(StreamFormat::narrowband());
//! let mut microphone = CaptureStream::open(&wanted)?;
//! let mut speaker = PlaybackStream::open(&wanted)?;
//! microphone.start()?;
//! speaker.start()?;
//!
//! let mut frame = vec![0i16; wanted.format.frame_samples()];
//! while microphone.read(&mut frame) {
//!     // encode, send, and put what came back from the far end into the speaker
//!     speaker.write(&frame);
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
// The stream types linked above exist only on Linux, where scripts/check.sh
// runs rustdoc with warnings fatal, so the links stay checked there.
#![cfg_attr(not(target_os = "linux"), allow(rustdoc::broken_intra_doc_links))]
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
pub use latency::{Latency, Rate, RenderDelay};
pub use level::{Controls, Gain, Level};
pub use status::{Errno, Error};

pub(crate) use sipral_io_common::level;

#[cfg(target_os = "linux")]
pub(crate) use sipral_io_common::{gate, ring};

// Layouts link nothing, so their tests run everywhere; off Linux only the
// tests read them, hence `dead_code`.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod abi;

#[cfg(target_os = "linux")]
mod registry;
#[cfg(target_os = "linux")]
mod stream;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub use registry::{DeviceMonitor, default_device, devices};
#[cfg(target_os = "linux")]
pub use stream::{CaptureStream, PlaybackStream, StreamConfig};

#[cfg(test)]
mod tests {
    use super::{
        Controls, Counters, Device, DeviceChoice, DeviceEvent, DeviceId, Direction, Error, Gain,
        Latency, Level, RenderDelay, StreamEvent, StreamFormat,
    };

    #[test]
    fn the_portable_surface_is_portable() {
        fn shareable<T: Send + Sync>() {}

        let format = StreamFormat::narrowband();
        assert_eq!(format.frame_bytes(), format.frame_samples() * 2);

        let device = Device {
            id: DeviceId::new("alsa_output.pci-0000_00_1f.3.analog-stereo"),
            name: String::new(),
            direction: Direction::Output,
            is_default: true,
        };
        assert_eq!(device.direction, Direction::Output);
        assert_eq!(
            DeviceEvent::DefaultChanged(Direction::Output),
            DeviceEvent::DefaultChanged(Direction::Output)
        );
        assert_eq!(StreamEvent::DeviceLost, StreamEvent::DeviceLost);
        assert_eq!(
            DeviceChoice::Preferred(DeviceId::new("bluez_output.AA_BB_CC_DD_EE_FF.1")),
            DeviceChoice::Preferred(DeviceId::new("bluez_output.AA_BB_CC_DD_EE_FF.1"))
        );
        assert_eq!(Gain::default(), Gain::UNITY);
        assert_eq!(Level::default(), Level::SILENT);
        assert_eq!(Counters::default().captured, 0);
        assert_eq!(Latency::default().duration(), core::time::Duration::ZERO);
        assert_eq!(RenderDelay::default().total(), core::time::Duration::ZERO);
        assert_eq!(
            Error::Refused {
                call: "pw_thread_loop_new"
            }
            .to_string(),
            "pw_thread_loop_new returned null"
        );
        shareable::<Controls>();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_stream_types_are_there_on_linux() {
        use super::{CaptureStream, PlaybackStream, StreamConfig};

        fn movable<T: Send>() {}

        let config = StreamConfig::new(StreamFormat::narrowband());
        assert_eq!(config.format, StreamFormat::narrowband());
        assert_eq!(config.device, DeviceChoice::System);
        movable::<CaptureStream>();
        movable::<PlaybackStream>();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn nothing_that_needs_libpipewire_is_compiled_elsewhere() {
        assert_eq!(StreamFormat::default(), StreamFormat::narrowband());
    }
}
