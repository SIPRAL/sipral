// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! PipeWire device I/O for Linux desktops.
//!
//! Frames of mono sixteen-bit samples come out of the microphone and go into
//! the speaker, at a size and a rate fixed when the stream opens. That is the
//! whole of it. There is no codec here, no jitter buffer, no packet and no
//! call: `docs/05-media.md` draws the line and this crate stays under it.
//!
//! What is here, because the same document says it belongs here, is the
//! platform work that eats the time on this kind of project: enumerating
//! nodes, noticing that the default one changed, and coping with a headset
//! being unplugged in the middle of a call. That last one is not an error and
//! is not reported as one — it arrives as a [`DeviceEvent`] the caller polls
//! for, so that nothing above this crate has to know PipeWire exists.
//!
//! Two things about PipeWire shape the interface and are worth reading before
//! the rest:
//!
//! * **A node is one direction.** `media.class` is `"Audio/Sink"` or
//!   `"Audio/Source"` and never both, the same as a WASAPI endpoint and
//!   unlike a CoreAudio device. So there is a [`CaptureStream`] and a
//!   [`PlaybackStream`] and no duplex type, which is what lets a softphone put
//!   the microphone on one node and the speaker on another.
//! * **The format is not negotiated away from.** [`CaptureStream::open`] and
//!   [`PlaybackStream::open`] offer exactly one format — mono, signed
//!   sixteen-bit, at the rate asked for — built by hand as the
//!   `SPA_TYPE_OBJECT_Format` pod `crate::abi` declares, because SPA's own
//!   builder for it is `static inline` and this crate links no such symbol.
//!   PipeWire reads that as one fixed format rather than a set to pick
//!   from, and its own adapter converts between it and whatever the graph
//!   is actually running, so a caller never sees a rate it did not ask for
//!   the way a WASAPI client does.
//!
//! Every stream says `media.role` `"Communication"`, which is how a session
//! manager's routing rules can tell a call from music. It is not echo
//! cancellation: PipeWire's canceller is `libpipewire-module-echo-cancel`,
//! which the session loads — a `pipewire.conf.d` fragment, or
//! `pactl load-module module-echo-cancel` on a desktop running
//! `pipewire-pulse` — and which appears in the graph as one more source and
//! one more sink. A call is cancelled when its two streams are routed
//! through that pair, as the session's defaults or by naming the two nodes
//! in the [`StreamConfig`]s; nothing a stream can set on itself turns it on.
//! Where the session has not loaded it, the processor seam in
//! `docs/05-media.md` is the canceller.
//!
//! The volume, the mute and the level meter are here too, and they are
//! applied to the frames rather than to the node's own volume — see
//! [`Controls`] for why that is the only version of the feature a call can
//! own. They are on a handle that can be moved to the thread drawing the
//! window, because that is where a slider and a meter live.
//!
//! A lost node is reported once, as [`StreamEvent::DeviceLost`], and never
//! silently rerouted underneath a call. Every stream is pinned to a node as
//! it opens — the session's route to the session's default node of that
//! moment — and `PW_STREAM_FLAG_DONT_RECONNECT` is what keeps it there;
//! `crate::abi` says so where the flag is declared. A default that changes
//! later is a [`DeviceEvent::DefaultChanged`], not a stream that moved. What
//! puts a node back under a stream is [`CaptureStream::recover`] and
//! [`PlaybackStream::recover`].
//!
//! On a target that is not Linux the crate still compiles, and still exports
//! [`StreamFormat`], [`Device`], [`DeviceChoice`], [`DeviceEvent`],
//! [`StreamEvent`], [`Controls`], [`Gain`], [`Level`], [`Counters`],
//! [`Latency`], [`Rate`], [`RenderDelay`] and [`Error`], so that portable code
//! above can name what it will be handed. What it does not export there is
//! anything that would need `libpipewire` to link against.
//!
//! On Linux, linking anything that uses this crate — its own tests included —
//! needs `libpipewire-0.3.so`, which Debian ships in `libpipewire-0.3-dev`;
//! running it needs a PipeWire daemon on the session. `interop/pipewire/`
//! has an image with both, and the script that tests this crate against it.
//!
//! Written from PipeWire's and SPA's published headers; see
//! `docs/02-clean-room.md` for why that matters, and `THIRD-PARTY-NOTICES.md`
//! for the one library this crate links.
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
// The stream types the rules above link to are behind cfg(target_os =
// "linux"), so on any other target there is no item for those links to find
// and rustdoc is right to say so. They are not written as code spans for it:
// a link is what a reader of this crate's documentation needs, and the
// documentation a reader reads is built for Linux. It is the gate that keeps
// them honest -- scripts/check.sh runs rustdoc against
// x86_64-unknown-linux-gnu with warnings fatal, where every one of them
// resolves or the step goes red.
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

// Volume, mute and the meter are not about PipeWire and were never written
// here twice on purpose: `sipral-io-coreaudio` and `sipral-io-wasapi` had the
// same file, once each. They live in `sipral-io-common` now, and are
// re-exported so that a caller of this crate sees the same names the other
// two do.
pub(crate) use sipral_io_common::level;

// The ring and the gate were the same story. They are `sipral-io-common`'s
// now, which compiles and tests them everywhere unconditionally, so this is
// left naming only what actually reaches them: the one module that runs on
// Linux.
#[cfg(target_os = "linux")]
pub(crate) use sipral_io_common::{gate, ring};

// The structure layouts declared from PipeWire's and SPA's headers compile
// and test everywhere -- there is nothing in `abi.rs` that links a symbol --
// so its layout tests run on every target the workspace builds on, the same
// reasoning `sipral-io-wasapi::abi` gives for its own. Off Linux the tests
// are all that reads it, and the constants only the stream and the registry
// use are unused there by construction rather than by mistake.
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

    /// Everything named here has to exist on every target the workspace
    /// builds, or portable code a layer up cannot describe what it will be
    /// given.
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
        // a delay nobody has asked a stream for is no delay, which is what a
        // session that was never told one already assumes
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
        // a stream has to be able to live on the thread that does the media,
        // which is not the thread that opened it
        movable::<CaptureStream>();
        movable::<PlaybackStream>();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn nothing_that_needs_libpipewire_is_compiled_elsewhere() {
        // The crate builds on macOS and on Windows with the platform modules
        // gated out entirely, which is what lets the workspace be built and
        // linted on a machine that has never heard of PipeWire.
        assert_eq!(StreamFormat::default(), StreamFormat::narrowband());
    }
}
