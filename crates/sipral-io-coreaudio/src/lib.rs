// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! CoreAudio device I/O for macOS and iOS.
//!
//! Device enumeration and hot-plug, `AVAudioSession` handling on iOS, and
//! Bluetooth hands-free routing. Sibling crates cover WASAPI and AAudio.
//!
//! Kept apart from [`sipral_media`] so that the core stack stays free of any
//! platform dependency, and so `sipral-headless` can exist at all.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
