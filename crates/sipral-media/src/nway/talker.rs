// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Who is talking: an energy detector with hysteresis, one per participant.
//!
//! Each tick the detector is given the mean-square energy of what the
//! participant sent, after its input gain. Starting and stopping are judged
//! against two different levels and over two different spans, so a talker
//! does not flicker in and out of the list on every syllable:
//!
//! - a participant starts talking after [`START_TICKS`] consecutive ticks at
//!   or above [`START_ENERGY`], so a click or a cough does not put it in the
//!   list;
//! - a talker stops after [`STOP_TICKS`] consecutive ticks below
//!   [`STOP_ENERGY`], so the gaps between words and sentences do not take it
//!   out. A tick between the two levels keeps whichever state it finds.
//!
//! Talkers are ranked by a smoothed level, the per-tick energy averaged with
//! a time constant of [`SMOOTHING_TICKS`] ticks, loudest first.
//!
//! The levels are absolute rather than relative to a noise floor: every leg
//! of a conference arrives decoded and, in practice, with its own noise
//! suppression, and an absolute level is what lets two legs be compared at
//! all.

/// Mean-square energy a tick needs to count towards starting: an RMS of 328,
/// 40 dB below full scale.
pub const START_ENERGY: i64 = 328 * 328;

/// Mean-square energy a tick has to stay under to count towards stopping: an
/// RMS of 164, 6 dB below [`START_ENERGY`].
pub const STOP_ENERGY: i64 = 164 * 164;

/// Consecutive ticks at or above [`START_ENERGY`] before a participant is
/// talking: 40 ms.
pub const START_TICKS: u32 = 2;

/// Consecutive ticks under [`STOP_ENERGY`] before a talker has stopped:
/// 400 ms.
pub const STOP_TICKS: u32 = 20;

/// Time constant of the level talkers are ranked by, in ticks: 80 ms.
pub const SMOOTHING_TICKS: i64 = 4;

/// One participant's detector.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Talker {
    /// The smoothed mean-square energy.
    level: i64,
    talking: bool,
    /// Consecutive ticks that argued for the other state.
    streak: u32,
    /// The tick it last started talking in.
    since: u64,
}

impl Talker {
    /// Takes one tick's mean-square energy, at tick number `tick`.
    pub(crate) fn update(&mut self, energy: i64, tick: u64) {
        self.level += (energy - self.level) / SMOOTHING_TICKS;
        let against = if self.talking {
            energy < STOP_ENERGY
        } else {
            energy >= START_ENERGY
        };
        if !against {
            self.streak = 0;
            return;
        }
        self.streak += 1;
        let needed = if self.talking {
            STOP_TICKS
        } else {
            START_TICKS
        };
        if self.streak >= needed {
            self.talking = !self.talking;
            self.streak = 0;
            self.since = tick;
        }
    }

    /// Forgets everything: silent, and not talking.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    /// Whether the participant is talking.
    pub(crate) const fn talking(&self) -> bool {
        self.talking
    }

    /// The smoothed level talkers are ranked by.
    pub(crate) const fn level(&self) -> i64 {
        self.level
    }

    /// The tick it last started or stopped talking in.
    pub(crate) const fn since(&self) -> u64 {
        self.since
    }
}

#[cfg(test)]
mod tests {
    use super::{START_ENERGY, START_TICKS, STOP_ENERGY, STOP_TICKS, Talker};

    fn feed(talker: &mut Talker, energy: i64, ticks: u32) {
        for _ in 0..ticks {
            talker.update(energy, 0);
        }
    }

    #[test]
    fn a_click_is_not_talking() {
        let mut talker = Talker::default();
        feed(&mut talker, 100 * START_ENERGY, START_TICKS - 1);
        feed(&mut talker, 0, 1);
        feed(&mut talker, 100 * START_ENERGY, START_TICKS - 1);
        assert!(!talker.talking());
        feed(&mut talker, START_ENERGY, 1);
        assert!(talker.talking());
    }

    #[test]
    fn a_pause_shorter_than_the_hangover_is_not_stopping() {
        let mut talker = Talker::default();
        feed(&mut talker, START_ENERGY, START_TICKS);
        feed(&mut talker, 0, STOP_TICKS - 1);
        // an RMS of 250, between the two levels: neither starts nor stops,
        // and breaks the run
        feed(&mut talker, 250 * 250, 1);
        feed(&mut talker, 0, STOP_TICKS - 1);
        assert!(talker.talking());
        feed(&mut talker, STOP_ENERGY - 1, 1);
        assert!(!talker.talking());
    }

    #[test]
    fn a_level_between_the_two_thresholds_does_not_start_talking() {
        let mut talker = Talker::default();
        feed(&mut talker, START_ENERGY - 1, 10 * START_TICKS);
        assert!(!talker.talking());
    }
}
