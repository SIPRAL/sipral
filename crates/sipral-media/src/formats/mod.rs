// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Audio as bytes: what a call's audio looks like in a file, and the one
//! payload format that is nothing but samples.
//!
//! [`ogg`] is the container of RFC 3533, pages and all, with a reader strict
//! enough to check what the writer produced.
//!
//! Unlike the codecs, the writers here allocate their buffers when they are
//! built and write to any [`std::io::Write`]: they belong on a thread that
//! may block on a disk, never on the audio thread.

pub mod ogg;
