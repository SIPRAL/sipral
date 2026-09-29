// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Audio device I/O for Android, over AAudio.
//!
//! Frames of mono sixteen-bit samples come out of the microphone and go into
//! the loudspeaker, a frame at a time, from a stream AAudio runs on a thread
//! of its own. That is the whole of the stream half: no codec, no jitter
//! buffer, no call. `sipral-audio` puts the call on top.
//!
//! Every call stream is a voice-communication one, which is what makes a
//! phone treat it as a call:
//!
//! - the loudspeaker half says `AAUDIO_USAGE_VOICE_COMMUNICATION` and
//!   `AAUDIO_CONTENT_TYPE_SPEECH`, so the platform routes it to the
//!   communication device — the earpiece, the loudspeaker, a wired or a
//!   Bluetooth headset — and its volume is the call volume;
//! - the microphone half says `AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION`,
//!   which is the platform's own echo canceller, noise suppressor and gain
//!   control where the phone has them;
//! - both ask for `AAUDIO_PERFORMANCE_MODE_LOW_LATENCY` and share the device
//!   (`AAUDIO_SHARING_MODE_SHARED`).
//!
//! A ring tone is a stream of its own, `AAUDIO_USAGE_NOTIFICATION_RINGTONE`,
//! which the platform plays where a ring goes rather than where the call is.
//!
//! # What API level it needs
//!
//! AAudio arrived in API level 26 and the usage and input preset in 28;
//! without those two a stream is media, with no echo cancellation and on
//! the media volume, which is not a call. So [`available`] says yes from API
//! level 28 ([`MIN_API`]) and only when `libaaudio.so` loads with every
//! function this crate calls. The library is looked up when first needed
//! rather than linked, so the same build loads on the API level 21 floor the
//! Android packages keep; below 28 the application runs its own audio
//! through `AudioRecord` and `AudioTrack`, as the telecom helper in
//! `bindings/kotlin/android` does.
//!
//! # Devices and routes
//!
//! AAudio lists no devices and routes nothing: both belong to
//! `AudioManager`, a Java API. [`route`] is everything about them that is
//! not Java, and runs anywhere. On Android it reaches `AudioManager` through
//! the Kotlin binding's JNI shim, once the application has handed it a
//! `Context`; without one the list is empty and every stream follows the
//! platform's own route, which is what a phone does anyway.
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
pub use bridge::JniPlatform;
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
