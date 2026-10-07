// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! An N-way conference: every participant hears everyone else.
//!
//! # The model
//!
//! A [`Mixer`] runs on a tick of [`TICK_MS`] milliseconds that its caller
//! drives, and does no I/O of its own: it owns no clock, no thread and no
//! socket. Between two ticks the caller [`push`](Mixer::push)es whatever
//! each participant sent and [`pull`](Mixer::pull)s whatever each
//! participant should hear; once per tick it calls [`mix`](Mixer::mix).
//!
//! Participants [`join`](Mixer::join) and [`leave`](Mixer::leave) at any
//! point, between ticks or between two pushes of the same tick. Each has its
//! own [`Rate`] — 8, 16, 32 or 48 kHz — and its own frame, which either
//! divides a tick or is up to [`MAX_FRAME_TICKS`] whole ticks.
//!
//! # What each participant hears
//!
//! The mix is formed at [`MIX_RATE`]. Every participant's tick of input is
//! resampled up to it, scaled by the participant's input gain and added into
//! one wide sum. Each participant then hears that sum minus its own
//! contribution — everybody but itself, the "minus-one" mix — scaled by its
//! output gain, held under full scale by its own [`Limiter`], and resampled
//! down to its own rate. Forming one sum and subtracting is linear in the
//! number of participants, and the sum cannot saturate at
//! [`MAX_PARTICIPANTS`] legs and maximum gain, so the subtraction is exact.
//!
//! [`Controls`] change per participant from the next tick: gain in and out,
//! mute each way, and listen-only (see [`Mixer`] for their exact effects).
//!
//! # Who is talking
//!
//! Every tick, each participant's input is measured, and
//! [`talkers`](Mixer::talkers) lists who is talking, loudest first. Starting
//! and stopping each need a run of ticks past a threshold of their own, so
//! the list does not flicker with every syllable; [`talker`] has the
//! thresholds and the spans.
//!
//! # Recording
//!
//! [`start_recording`](Mixer::start_recording) taps the whole mix —
//! everybody the conference hears — through a limiter of its own, at a rate
//! of the caller's choosing, into a queue that
//! [`read_recording`](Mixer::read_recording) drains.
//!
//! # Latency
//!
//! Audio pushed before a tick can be pulled right after it. Added delay is
//! only the resampling filters: 4 ms each way at 8 kHz, 2 at 16, 1 at 32,
//! none at 48. Queues hold one frame beyond the tick; overruns drop the oldest
//! samples and underruns mix silence, both counted in [`ParticipantStats`].
//! Legs on another clock go through [`crate::drift`] first.
//!
//! # Allocation
//!
//! Only [`Mixer::new`], [`Mixer::join`] and [`Mixer::start_recording`]
//! allocate. Integer arithmetic throughout.
//!
//! # Wiring it to calls
//!
//! One [`Mixer`] per conference, driven from one thread. Each leg joins at its
//! codec's decode rate; push what its jitter buffer releases and send what is
//! pulled to its encoder.

mod convert;
pub mod limiter;
mod mixer;
mod ring;
pub mod talker;

pub use convert::Converter;
pub use limiter::Limiter;
pub use mixer::{
    Controls, MixError, Mixer, MixerConfig, ParticipantConfig, ParticipantId, ParticipantStats,
    Rate,
};

/// How often [`Mixer::mix`] is called, in milliseconds.
pub const TICK_MS: u32 = 20;

/// The rate the mix is formed at, in hertz: the highest a participant can
/// have, so nobody's audio loses bandwidth on the way through.
pub const MIX_RATE: u32 = 48_000;

/// Samples in one tick at [`MIX_RATE`].
const MIX_TICK: usize = 960;

/// The longest frame a participant may have, in ticks.
pub const MAX_FRAME_TICKS: usize = 3;

/// Ticks of recorded mix that wait to be read before the oldest are dropped:
/// 100 ms.
pub const RECORDING_TICKS: usize = 5;

/// The most places a [`Mixer`] may have.
///
/// A contribution is at most a full-scale sample at four times, 2^17, and a
/// thousand and twenty-four of them sum to 2^27: the wide sum stays well
/// inside thirty-two bits, and the output gain's further four times still
/// fits.
pub const MAX_PARTICIPANTS: usize = 1_024;

#[cfg(test)]
mod realtime_tests;
#[cfg(test)]
mod tests;
