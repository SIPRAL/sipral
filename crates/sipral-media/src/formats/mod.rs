// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Audio as bytes: what a call's audio looks like in a file, and the one
//! payload format that is nothing but samples.
//!
//! [`ogg`] is the container of RFC 3533, pages and all, with a reader strict
//! enough to check what the writer produced. [`ogg_opus`] puts Opus packets
//! that were already encoded into it the way RFC 7845 asks, so a call
//! recording in Opus costs no second encode. [`wav`] is the other recording
//! format: sixteen-bit PCM in RIFF/WAVE, stereo with the local side on the
//! left and the remote side on the right, growing into RF64 past four
//! gibibytes. [`l16`] is RFC 3551's uncompressed payload, which is the same
//! samples in network byte order on RTP instead of in a file; it is
//! re-exported at the crate root as `l16`, beside the other codecs.
//!
//! None of it needs the `opus` feature. The Ogg Opus writer takes packets
//! and their durations; where they came from is the caller's business.
//!
//! Unlike the codecs, the writers here allocate their buffers when they are
//! built and write to any [`std::io::Write`]: they belong on a thread that
//! may block on a disk, never on the audio thread.

pub mod l16;
pub mod ogg;
pub mod ogg_opus;
pub mod wav;
