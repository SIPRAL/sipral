// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Audio as bytes: what a call's audio looks like in a file, and the one
//! payload format that is nothing but samples.
//!
//! [`ogg`] is RFC 3533, [`ogg_opus`] is RFC 7845 for already-encoded packets,
//! [`wav`] is 16-bit RIFF/WAVE growing into RF64, and [`l16`] is RFC 3551's
//! uncompressed RTP payload (re-exported at the crate root). None needs the
//! `opus` feature.
//!
//! The writers block on any [`std::io::Write`]: keep them off the audio
//! thread.

pub mod l16;
pub mod ogg;
pub mod ogg_opus;
pub mod wav;
