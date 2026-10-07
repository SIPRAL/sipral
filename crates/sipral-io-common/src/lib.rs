// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The parts of an audio device backend that are not about any device.
//!
//! - [`ring`]: the lock-free buffer between the realtime thread and an
//!   ordinary one;
//! - [`gate`]: proof that the audio thread has left our memory before it is
//!   freed;
//! - [`level`]: volume, mute and metering applied to the samples, not to the
//!   system control.
//!
//! Platform-specific counters stay in each backend, since they measure
//! different things. Nothing here allocates, locks or reads a clock on the
//! audio path; [`gate`] reads one only during teardown.

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

pub mod gate;
pub mod level;
pub mod ring;
