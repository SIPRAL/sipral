// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Audio device I/O for Android, over AAudio.
//!
//! Mono 16-bit frames to and from AAudio streams; no codec or call
//! (`sipral-audio` adds those).
//!
//! Call streams are voice-communication streams:
//!
//! - output: `AAUDIO_USAGE_VOICE_COMMUNICATION` + `CONTENT_TYPE_SPEECH`,
//!   routed to the communication device at call volume;
//! - input: `AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION`, the platform's AEC,
//!   NS and AGC where present;
//! - both low-latency and shared.
//!
//! A ring is its own `AAUDIO_USAGE_NOTIFICATION_RINGTONE` stream.
//!
//! # API level
//!
//! The usage and preset need API 28 ([`MIN_API`]); below that a stream would
//! be media. [`available`] also requires `libaaudio.so` with every function
//! used. It is loaded lazily, so the build still runs on API 21, where the
//! application uses `AudioRecord`/`AudioTrack` (see `bindings/kotlin/android`).
//!
//! # Devices and routes
//!
//! Devices and routing belong to the Java `AudioManager`. [`route`] holds
//! the non-Java part and reaches `AudioManager` via the Kotlin JNI shim once
//! given a `Context`; without one the list is empty and streams follow the
//! platform route.
//!
//! Written from the NDK's published `AAudio.h` and the Android SDK's
//! reference for `AudioManager` and `AudioDeviceInfo`; see
//! `docs/02-clean-room.md` for why that matters.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
// The stream types the documentation above links to exist only on Android,
// where scripts/check.sh reads it with warnings fatal.
#![cfg_attr(not(target_os = "android"), allow(rustdoc::broken_intra_doc_links))]
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

pub mod route;
mod samples;

#[cfg(target_os = "android")]
mod api;
#[cfg(target_os = "android")]
mod bridge;
#[cfg(target_os = "android")]
mod stream;

#[cfg(target_os = "android")]
mod priority;

#[cfg(target_os = "android")]
pub use bridge::JniPlatform;
#[cfg(target_os = "android")]
pub use priority::{URGENT_AUDIO, thread_priority, urgent_audio_thread};
#[cfg(target_os = "android")]
pub use stream::{Error, Stream, StreamConfig, Usage};

pub use sipral_io_common::level::{Controls, Gain, Level};

/// The lowest API level a call stream is opened on: the one where AAudio
/// learned the usage and the input preset that make a stream a call.
pub const MIN_API: u32 = 28;

/// Whether AAudio can carry a call here: API level [`MIN_API`] or later,
/// and `libaaudio.so` loaded with every function this crate calls. Always
/// false on a target that is not Android.
#[must_use]
pub fn available() -> bool {
    #[cfg(target_os = "android")]
    {
        api::sdk() >= MIN_API && api::Api::get().is_some()
    }
    #[cfg(not(target_os = "android"))]
    {
        false
    }
}

/// The API level this process runs on, or zero off Android.
#[must_use]
pub fn sdk() -> u32 {
    #[cfg(target_os = "android")]
    {
        api::sdk()
    }
    #[cfg(not(target_os = "android"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nothing_is_available_off_android() {
        if cfg!(not(target_os = "android")) {
            assert!(!super::available());
            assert_eq!(super::sdk(), 0);
        }
    }
}
