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
//! number of participants rather than quadratic, and the sum is wide enough
//! that it cannot saturate at [`MAX_PARTICIPANTS`] legs at the highest gain
//! a [`Gain`](crate::mix::Gain) allows, so the subtraction is exact.
//!
//! The resampling is [`crate::resample`]'s and the levels are
//! [`crate::mix`]'s [`Gain`](crate::mix::Gain), so a conference leg sounds
//! like a two-party call at the same rates.
//!
//! [`Controls`] hold what can be changed per participant, from the next
//! tick: a gain in and a gain out, a mute each way, and listen-only. A
//! muted participant's input is still read and thrown away every tick, so
//! unmuting does not play back what was said while muted; a listen-only
//! participant's input is not even queued, and missing input from it is not
//! an underrun. Muting out still queues a tick of silence every tick, so the
//! participant's playout clock keeps running.
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
//! A tick consumes one tick of queued input from every participant and queues
//! one tick of output for every participant, so audio pushed before a tick is
//! ready to pull right after it: the mixer adds no buffering beyond the tick
//! itself, plus the delay of the resampling filters between the mix and a
//! participant not at 48 kHz: 4 ms each way at 8 kHz, 2 ms at 16 kHz, 1 ms at
//! 32 kHz and none at 48 kHz, so 8 ms from one 8 kHz participant to another.
//! The queues on both sides hold one frame (at least one tick) beyond the
//! tick being mixed and no more: a writer that runs ahead loses its oldest
//! samples, and they are counted in [`ParticipantStats`], so latency cannot
//! build up behind a participant whose clock runs fast. A participant whose
//! clock runs slow underruns, and the missing samples are mixed as silence
//! and counted too. Keeping the two clocks in step is [`crate::drift`]'s job,
//! in front of the mixer.
//!
//! # Allocation
//!
//! [`Mixer::new`] allocates the places and the shared scratch,
//! [`Mixer::join`] the participant's queues and filters, and
//! [`Mixer::start_recording`] the recording's. Nothing else allocates:
//! pushing, pulling, mixing, reading the talkers and changing controls are
//! allocation-free, and every per-tick cost is bounded by the number of
//! participants. Leaving frees what joining allocated.
//!
//! All the arithmetic is integer, so the same input produces the same output
//! on every platform.
//!
//! # Wiring it to calls
//!
//! One [`Mixer`] is one conference, driven from one thread. Each call leg
//! joins at the rate its codec decodes to; what its jitter buffer releases is
//! pushed, and what is pulled goes to its encoder. The tick comes from
//! whatever clock the conference is to run on, and each leg whose far end
//! runs on another clock goes through [`crate::drift`] on the way in and on
//! the way out, or its queue slowly fills or runs dry.

mod convert;
pub mod limiter;
mod mixer;
mod ring;
pub mod talker;

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
