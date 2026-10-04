// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The parts of an audio device backend that are not about any device.
//!
//! A backend for a platform's audio API is mostly that platform: its
//! enumeration, its formats, its handles, its errors, the shape of its
//! callback. Three things in it are not, and they are the three that are hard
//! to get right:
//!
//! - [`ring`] — the lock-free buffer where the thread the system will not wait
//!   for meets an ordinary one;
//! - [`gate`] — knowing that the audio thread is out of our memory before that
//!   memory is freed, built rather than assumed;
//! - [`level`] — volume, mute and the number a meter is drawn from, applied to
//!   the samples on the way past rather than to the machine's own control.
//!
//! None of them names a platform and none of them can, because what they are
//! for is to be right. They were written twice, once in
//! `sipral-io-coreaudio` and once in `sipral-io-wasapi`, and the second copy's
//! own documentation said so. This crate is the first copy; the two backends
//! use it, and a third and a fourth will not be a third and a fourth copy.
//!
//! What stayed behind in each backend is what is genuinely its own. The
//! counters are the clearest case: both keep four of the same numbers, and
//! then one counts the times `AudioUnitRender` refused while the other counts
//! buffer gaps, refused `GetBuffer` calls and a buffer-ready event that did
//! not arrive. Those are not the same measurement with different names, so
//! they are not shared.
//!
//! Nothing here allocates on the audio path, takes a lock a realtime thread
//! could be made to wait on, or reads a clock — except [`gate`] while tearing
//! down, which by then is not on that path at all.

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
