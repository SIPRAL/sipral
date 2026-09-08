// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Deciding whether a run of sequence numbers is a stream (RFC 3550 A.1).
//!
//! Twelve octets of header are cheap to forge and cheaper to mistake: a
//! datagram from some other application, aimed at the wrong port, passes the
//! version check often enough to matter. So a source is not believed on its
//! first packet. It is believed after two in a row, and after that the
//! sequence number itself does the work: a small step forward is the stream, a
//! small step back is reordering, and a jump too large to be either is refused
//! until a second packet confirms that the far end restarted.
//!
//! Everything here is 16-bit arithmetic that wraps, so 65535 followed by 0 is
//! a step of one and not a jump of 65535.

/// The sequence number space (A.1, `RTP_SEQ_MOD`).
const SEQ_MOD: u32 = 1 << 16;

/// "no more than MAX_DROPOUT ahead of s->max_seq": a minute of gap at fifty
/// packets a second (A.1).
const MAX_DROPOUT: u32 = 3000;

/// "nor more than MAX_MISORDER behind": two seconds of reordering at the same
/// rate (A.1).
const MAX_MISORDER: u32 = 100;

/// How many packets in a row a new source has to send before it is believed
/// (A.1, `MIN_SEQUENTIAL`).
const MIN_SEQUENTIAL: u8 = 2;

/// What one sequence number did to the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeqUpdate {
    /// Not believed yet: fewer than two packets in a row have arrived from
    /// this source. A.1 allows such packets to be held and delivered once the
    /// source is valid; holding twenty milliseconds of audio to save twenty
    /// milliseconds of audio is not worth the state, so they are dropped.
    Probation,
    /// In sequence, allowing for a gap small enough to be ordinary loss.
    InOrder,
    /// Behind the highest seen, but inside the misordering window: reordered,
    /// or a duplicate. Which of the two is a question only something that
    /// remembers the packets can answer.
    Misordered,
    /// Too far from the stream to belong to it. The packet is not counted,
    /// and the next sequence number is remembered: if it arrives, the far end
    /// restarted.
    Rejected,
    /// The second of two packets far from the stream, so "the other side
    /// restarted without telling us" (A.1). The state is re-based on it.
    Restarted,
}

impl SeqUpdate {
    /// Whether the packet may be used.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::InOrder | Self::Misordered | Self::Restarted)
    }
}

/// What is remembered about one synchronization source.
#[derive(Clone, Copy, Debug, Default)]
pub struct SequenceState {
    started: bool,
    probation: u8,
    base: u16,
    max: u16,
    bad: Option<u16>,
    cycles: u32,
    received: u64,
}

impl SequenceState {
    /// A source nothing has been heard from.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            started: false,
            probation: 0,
            base: 0,
            max: 0,
            bad: None,
            cycles: 0,
            received: 0,
        }
    }

    /// Take in a sequence number and say what it was.
    pub fn update(&mut self, sequence: u16) -> SeqUpdate {
        if !self.started {
            // A.1, on first contact: max_seq is set one behind, so the very
            // next number counts as the first in-sequence packet
            self.started = true;
            self.rebase(sequence);
            self.max = sequence.wrapping_sub(1);
            self.probation = MIN_SEQUENTIAL;
        }

        if self.probation > 0 {
            if sequence == self.max.wrapping_add(1) {
                self.probation = self.probation.saturating_sub(1);
                self.max = sequence;
                if self.probation == 0 {
                    self.rebase(sequence);
                    self.received = 1;
                    return SeqUpdate::InOrder;
                }
            } else {
                // one in a row again, and this one is it
                self.probation = MIN_SEQUENTIAL.saturating_sub(1);
                self.max = sequence;
            }
            return SeqUpdate::Probation;
        }

        let step = u32::from(sequence.wrapping_sub(self.max));
        let outcome = if step < MAX_DROPOUT {
            if sequence < self.max {
                // ahead of max_seq modulo 2^16 but smaller than it: another
                // cycle of the sequence number space
                self.cycles = self.cycles.saturating_add(1);
            }
            self.max = sequence;
            SeqUpdate::InOrder
        } else if step <= SEQ_MOD - MAX_MISORDER {
            if self.bad != Some(sequence) {
                self.bad = Some(sequence.wrapping_add(1));
                return SeqUpdate::Rejected;
            }
            // "pretend this was the first packet": the loss statistics from
            // before the restart describe a stream that no longer exists
            self.rebase(sequence);
            SeqUpdate::Restarted
        } else {
            SeqUpdate::Misordered
        };
        self.received = self.received.saturating_add(1);
        outcome
    }

    /// Forget everything and wait for a first packet again. For a source that
    /// has been replaced rather than one that has moved.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Whether two packets in a row have been seen, so the source is one this
    /// receiver believes in.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.started && self.probation == 0
    }

    /// How many more packets in a row are needed before the source is valid.
    #[must_use]
    pub const fn probation(&self) -> u8 {
        self.probation
    }

    /// The highest sequence number seen, without the cycle count.
    #[must_use]
    pub const fn highest(&self) -> u16 {
        self.max
    }

    /// How many times the sequence number has wrapped since the source became
    /// valid.
    #[must_use]
    pub const fn cycles(&self) -> u32 {
        self.cycles
    }

    /// The highest sequence number seen, extended by the cycle count, so that
    /// it keeps growing across a wrap.
    #[must_use]
    pub fn extended_highest(&self) -> u64 {
        (u64::from(self.cycles) << 16) | u64::from(self.max)
    }

    /// The first sequence number of the current run.
    #[must_use]
    pub const fn base(&self) -> u16 {
        self.base
    }

    /// How many packets have been accepted since the source became valid.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// A.1's `init_seq`: start counting this stream from here.
    fn rebase(&mut self, sequence: u16) {
        self.base = sequence;
        self.max = sequence;
        // A.1 parks bad_seq outside the space "so seq == bad_seq is false"
        self.bad = None;
        self.cycles = 0;
        self.received = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{SeqUpdate, SequenceState};

    /// Feed a run of consecutive numbers and return the last outcome.
    fn run(state: &mut SequenceState, from: u16, count: u16) -> SeqUpdate {
        let mut last = SeqUpdate::Probation;
        for step in 0..count {
            last = state.update(from.wrapping_add(step));
        }
        last
    }

    #[test]
    fn a_new_source_is_not_believed_until_two_packets_arrive_in_a_row() {
        // A.1: "a source is declared valid only after MIN_SEQUENTIAL packets
        // have been received in sequence"
        let mut state = SequenceState::new();
        assert_eq!(state.update(100), SeqUpdate::Probation);
        assert!(!state.is_valid());
        assert_eq!(state.update(101), SeqUpdate::InOrder);
        assert!(state.is_valid());
        assert_eq!(state.received(), 1, "the packet that ends probation counts");
        assert_eq!(state.base(), 101, "and the stream is counted from it");
    }

    #[test]
    fn a_gap_during_probation_starts_the_count_again() {
        let mut state = SequenceState::new();
        assert_eq!(state.update(100), SeqUpdate::Probation);
        // not 101: whatever this is, it is not the stream that started at 100
        assert_eq!(state.update(900), SeqUpdate::Probation);
        assert!(!state.is_valid());
        assert_eq!(state.update(901), SeqUpdate::InOrder);
        assert!(state.is_valid());
    }

    #[test]
    fn probation_counts_the_packet_it_is_holding_out_for() {
        let mut state = SequenceState::new();
        state.update(7);
        assert_eq!(state.probation(), 1);
        state.update(7);
        assert_eq!(state.probation(), 1, "a repeat is not the next in sequence");
        assert!(!state.is_valid());
    }

    #[test]
    fn a_gap_small_enough_to_be_loss_is_still_the_same_stream() {
        // A.1: valid if "no more than MAX_DROPOUT ahead", which is 3000
        let mut state = SequenceState::new();
        run(&mut state, 1, 2);
        assert_eq!(state.update(2000), SeqUpdate::InOrder);
        assert_eq!(state.highest(), 2000);
    }

    #[test]
    fn the_sequence_number_wraps_at_65535_and_the_cycle_count_moves() {
        let mut state = SequenceState::new();
        run(&mut state, 65534, 2);
        assert_eq!(state.highest(), 65535);
        assert_eq!(state.cycles(), 0);

        assert_eq!(state.update(0), SeqUpdate::InOrder);
        assert_eq!(state.highest(), 0);
        assert_eq!(state.cycles(), 1);
        assert_eq!(
            state.extended_highest(),
            65536,
            "the extended number keeps growing across the wrap"
        );

        assert_eq!(state.update(1), SeqUpdate::InOrder);
        assert_eq!(state.extended_highest(), 65537);
    }

    #[test]
    fn a_packet_from_just_behind_the_highest_is_reordering_not_a_new_stream() {
        // A.1: valid if "not more than MAX_MISORDER behind", which is 100
        let mut state = SequenceState::new();
        run(&mut state, 500, 2);
        assert_eq!(state.update(520), SeqUpdate::InOrder);
        assert_eq!(state.update(519), SeqUpdate::Misordered);
        assert_eq!(state.highest(), 520, "a late packet does not move the top");
        // a repeat of the highest is a step of zero, which A.1 cannot tell
        // from the stream standing still; the buffer is what catches it
        assert_eq!(state.update(520), SeqUpdate::InOrder);
    }

    #[test]
    fn a_jump_too_large_to_be_either_is_refused_until_it_repeats() {
        let mut state = SequenceState::new();
        run(&mut state, 1000, 2);
        assert_eq!(state.update(40000), SeqUpdate::Rejected);
        assert_eq!(state.highest(), 1001, "a refused packet changes nothing");
        // anything but the number that would follow it puts us back to square one
        assert_eq!(state.update(50000), SeqUpdate::Rejected);
        assert_eq!(state.update(50001), SeqUpdate::Restarted);
        assert_eq!(state.highest(), 50001);
        assert_eq!(state.base(), 50001, "the counters start again");
        assert_eq!(state.received(), 1);
    }

    #[test]
    fn a_restart_keeps_the_source_valid_rather_than_sending_it_back_to_probation() {
        let mut state = SequenceState::new();
        run(&mut state, 10, 2);
        state.update(40000);
        assert_eq!(state.update(40001), SeqUpdate::Restarted);
        assert!(state.is_valid());
        assert!(SeqUpdate::Restarted.is_valid());
        assert!(!SeqUpdate::Rejected.is_valid());
        assert!(!SeqUpdate::Probation.is_valid());
    }

    #[test]
    fn a_reset_source_has_to_earn_belief_again() {
        let mut state = SequenceState::new();
        run(&mut state, 1, 2);
        assert!(state.is_valid());
        state.reset();
        assert!(!state.is_valid());
        assert_eq!(state.update(90), SeqUpdate::Probation);
    }
}
