// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The built-in audio engine: the platform's devices, opened and pumped for
//! a call, behind one API on every platform.
//!
//! It lists devices, opens the chosen ones, survives unplugs and default
//! changes, resamples each call to the device rate, mixes calls into the
//! loudspeaker, feeds the microphone to each, and plays the ring. The core
//! stays device-free; applications may still pump frames themselves.
//!
//! # Rules
//!
//! Each is tested against a fake backend:
//!
//! - a device's handle is the engine's and survives a refresh: a stream on
//!   a device, and a selection saved against one, still name it after the
//!   list has been rebuilt, and after the device has gone;
//! - a device with no channels in a direction is listed and refused for it;
//! - a handle the engine never issued is refused before any platform call;
//! - a change the engine made and one the operating system announced are
//!   told apart ([`Origin`]), and a role the application put on a device
//!   does not follow the default when the system moves it;
//! - the gain and the mute of a direction are the engine's, not a stream's,
//!   and carry across every device change;
//! - the ring has an output of its own, which may or may not be the call's;
//! - opening the devices is decoupled from the calls under
//!   [`Activation::Manual`], for the platforms that say when audio is ours;
//! - a platform call that does not answer is reported as stuck, not waited
//!   for ([`Config::probe_wait`]);
//! - nothing here needs an instruction the oldest supported machine does
//!   not have: the resampler and the mixer are plain integer arithmetic.

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

pub mod backend;
mod call;
mod device;
mod engine;
mod probe;
mod pump;

#[cfg(any(test, feature = "fake"))]
pub mod fake;

#[cfg(target_os = "android")]
mod aaudio;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod coreaudio;
#[cfg(target_os = "windows")]
mod wasapi;

#[cfg(test)]
mod realtime_tests;
#[cfg(test)]
mod tests;

pub use call::{CallAudio, CallGone, CallId, Outgoing, Transmit, Transport};
pub use device::{
    AudioEvent, Change, DeviceHandle, DeviceInfo, Direction, Origin, Role, SelectError, Selection,
};
pub use engine::{Activation, Config, Engine, Info};
pub use probe::DEFAULT_PROBE_WAIT;
pub use pump::CallControls;
pub use sipral_io_common::level::{Gain, Level};

/// Whether this platform has a backend, without constructing one.
///
/// Fixed by the build on macOS, iOS and Windows. On Android it needs API
/// level 28 (`sipral_io_aaudio::MIN_API`); older phones run their own audio.
#[must_use]
pub fn platform_has_backend() -> bool {
    #[cfg(target_os = "android")]
    {
        sipral_io_aaudio::available()
    }
    #[cfg(not(target_os = "android"))]
    {
        cfg!(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        ))
    }
}

/// The platform's own backend, where this crate has one.
///
/// `None` on Linux (the packaged `sipral-ffi` must not require PipeWire) and
/// on Android below API 28, so a caller can report device mode unavailable.
#[must_use]
pub fn platform_backend() -> Option<Box<dyn backend::Backend>> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        Some(Box::new(coreaudio::CoreAudioBackend::new()))
    }
    #[cfg(target_os = "windows")]
    {
        Some(Box::new(wasapi::WasapiBackend::new()))
    }
    #[cfg(target_os = "android")]
    {
        if sipral_io_aaudio::available() {
            Some(Box::new(aaudio::AAudioBackend::new()))
        } else {
            None
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "android"
    )))]
    {
        None
    }
}
