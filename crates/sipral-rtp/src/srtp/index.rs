// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The packet index, which is mostly not on the wire, and the replay list.
//!
//! RFC 3711 §3.3.1: the index is `2^16 * ROC + SEQ`, and only the low sixteen
//! bits of it travel. A receiver has to guess the rest from the sequence
//! numbers it has already seen, which is what makes a packet that arrives
//! late across a wrap interesting: it belongs to the previous rollover, and
//! treating it as the current one would decrypt it against the wrong
//! keystream and reject it.

/// Packets behind the highest accepted one that the replay list remembers.
///
/// §3.3.2 requires at least 64. Twice that costs one more word of state and
/// buys tolerance for a burst of reordering, which is what a jitter buffer in
/// front of a bad network produces.
pub const WINDOW: u64 = 128;

/// The sender's side of the index: it owns its sequence numbers, so it only
/// has to notice them wrapping.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Sending {
    roc: u32,
    last: Option<u16>,
}

impl Sending {
    /// The index a packet with sequence number `seq` would be sent under, and
    /// the state sending it leaves behind; `None` when `seq` does not move the
    /// index forward.
    ///
    /// Forward is less than half the sequence space ahead of the last number
    /// sent, which is where a receiver's estimate (Appendix A) puts it too: a
    /// number behind that one wraps, and the rollover counter moves with it.
    /// The same number again, or one behind the last, is refused rather than
    /// sent under the index it repeats — §9.1: "the same key stream ... MUST
    /// NOT be used" twice — or under a rollover the receiver would never
    /// guess. So is a wrap past the last rollover counter there is.
    pub(crate) fn next(self, seq: u16) -> Option<(u64, Self)> {
        let roc = match self.last {
            None => self.roc,
            Some(last) => {
                let ahead = seq.wrapping_sub(last);
                if ahead == 0 || ahead >= 0x8000 {
                    return None;
                }
                if seq < last {
                    self.roc.checked_add(1)?
                } else {
                    self.roc
                }
            }
        };
        let sent = Self {
            roc,
            last: Some(seq),
        };
        Some((u64::from(roc) << 16 | u64::from(seq), sent))
    }

    /// The rollover counter, which the authentication tag covers and which a
    /// receiver joining late has to be told out of band (§3.3.1).
    pub(crate) const fn rollover(self) -> u32 {
        self.roc
    }
}

/// The receiver's estimate of where a packet sits in the stream.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Estimate {
    pub(crate) index: u64,
    rollover: u32,
    sequence: u16,
}

impl Estimate {
    /// The rollover counter the authentication tag is computed over, which is
    /// the estimated one and not the stored one — a packet from the previous
    /// rollover has to be authenticated against the counter it was sent with.
    pub(crate) fn rollover(self) -> u32 {
        self.rollover
    }
}

/// The receiver's ROC and `s_l`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Receiving {
    roc: u32,
    highest: Option<u16>,
}

impl Receiving {
    /// Start from a rollover counter supplied out of band, which §3.3.1 says
    /// a receiver joining an ongoing session must be given.
    pub(crate) const fn joining(roc: u32) -> Self {
        Self { roc, highest: None }
    }

    /// Start again where a stream had got to: its highest index accepted.
    pub(crate) fn resumed(index: u64) -> Self {
        Self {
            roc: u32::try_from(index >> 16).unwrap_or(u32::MAX),
            highest: Some(u16::try_from(index & 0xffff).unwrap_or_default()),
        }
    }

    /// Appendix A, with its signed arithmetic: pick `v` from
    /// `{ROC-1, ROC, ROC+1}` so the index lands closest to where the stream
    /// already is.
    pub(crate) fn estimate(self, seq: u16) -> Estimate {
        // §3.3.1: s_l starts as the sequence number of the first packet seen,
        // which makes the first estimate v = ROC by construction
        let highest = i32::from(self.highest.unwrap_or(seq));
        let seq_signed = i32::from(seq);
        let rollover = if highest < 32_768 {
            if seq_signed - highest > 32_768 {
                self.roc.wrapping_sub(1)
            } else {
                self.roc
            }
        } else if highest - 32_768 > seq_signed {
            self.roc.wrapping_add(1)
        } else {
            self.roc
        };

        Estimate {
            index: u64::from(rollover) << 16 | u64::from(seq),
            rollover,
            sequence: seq,
        }
    }

    /// §3.3.1's update, which happens only after the packet is authenticated.
    pub(crate) fn accept(&mut self, estimate: Estimate) {
        if estimate.rollover == self.roc.wrapping_add(1) {
            self.roc = estimate.rollover;
            self.highest = Some(estimate.sequence);
        } else if estimate.rollover == self.roc
            && self
                .highest
                .is_none_or(|highest| estimate.sequence > highest)
        {
            self.highest = Some(estimate.sequence);
        }
        // v = ROC-1 is a packet from before the wrap; it changes nothing
    }

    pub(crate) const fn rollover(self) -> u32 {
        self.roc
    }
}

/// The sliding window of §3.3.2, as the bitmap RFC 2401 suggests.
///
/// Bit zero is the highest index accepted so far, bit `n` the index `n`
/// behind it.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Replay {
    highest: u64,
    seen: u128,
    started: bool,
}

impl Replay {
    /// A list that has seen everything up to and including `highest`: what a
    /// source that was forgotten is held to when it is heard from again.
    pub(crate) const fn resumed(highest: u64) -> Self {
        Self {
            highest,
            seen: u128::MAX,
            started: true,
        }
    }

    /// The highest index recorded, once one has been.
    pub(crate) const fn highest(&self) -> Option<u64> {
        if self.started {
            Some(self.highest)
        } else {
            None
        }
    }

    /// Whether a packet at `index` may be processed: ahead of the window, or
    /// inside it and not yet seen. Nothing is recorded here — §3.3.2 updates
    /// the list only after authentication, and a forged packet must not be
    /// able to punch a hole in it.
    pub(crate) fn accepts(&self, index: u64) -> bool {
        if !self.started || index > self.highest {
            return true;
        }
        let behind = self.highest - index;
        behind < WINDOW && self.seen & (1_u128 << behind) == 0
    }

    /// Record an authenticated packet, moving the window if it is ahead.
    pub(crate) fn record(&mut self, index: u64) {
        if !self.started {
            self.started = true;
            self.highest = index;
            self.seen = 1;
            return;
        }
        if index > self.highest {
            let step = index - self.highest;
            self.seen = if step >= 128 {
                0
            } else {
                self.seen << u32::try_from(step).unwrap_or(u32::MAX)
            };
            self.seen |= 1;
            self.highest = index;
        } else {
            let behind = self.highest - index;
            if behind < WINDOW {
                self.seen |= 1_u128 << behind;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Receiving, Replay, Sending, WINDOW};

    /// Send `seq` from `sending`, keeping what it leaves behind.
    fn send(sending: &mut Sending, seq: u16) -> Option<u64> {
        let (index, sent) = sending.next(seq)?;
        *sending = sent;
        Some(index)
    }

    #[test]
    fn the_sender_counts_its_own_wraps() {
        let mut sending = Sending::default();
        assert_eq!(send(&mut sending, 65_534), Some(65_534));
        assert_eq!(send(&mut sending, 65_535), Some(65_535));
        assert_eq!(send(&mut sending, 0), Some(65_536));
        assert_eq!(send(&mut sending, 1), Some(65_537));
        assert_eq!(sending.rollover(), 1);
    }

    #[test]
    fn the_sender_never_sends_an_index_that_does_not_move_forward() {
        let mut sending = Sending::default();
        assert_eq!(send(&mut sending, 1000), Some(1000));
        // the same number again would repeat the index; one behind it would
        // have been counted a wrap, ahead of anything a receiver expects
        for refused in [1000, 999, 1, 1000_u16.wrapping_add(0x8000)] {
            assert_eq!(send(&mut sending, refused), None, "{refused}");
        }
        assert_eq!(sending.rollover(), 0, "nothing refused moved the counter");
        assert_eq!(send(&mut sending, 1001), Some(1001));
        assert_eq!(
            send(&mut sending, 1001_u16.wrapping_add(0x7fff)),
            Some(1001 + 0x7fff),
            "anything less than half the space ahead is forward"
        );
        // and past the last rollover counter there is nothing left to wrap to
        let mut last = Sending {
            roc: u32::MAX,
            last: Some(65_535),
        };
        assert_eq!(send(&mut last, 0), None);
    }

    #[test]
    fn a_resumed_stream_carries_on_from_its_highest_index() {
        let receiving = Receiving::resumed(3 * 65_536 + 40_000);
        assert_eq!(receiving.rollover(), 3);
        assert_eq!(receiving.estimate(40_001).index, 3 * 65_536 + 40_001);
        let replay = Replay::resumed(3 * 65_536 + 40_000);
        assert!(!replay.accepts(3 * 65_536 + 40_000));
        assert!(!replay.accepts(3 * 65_536 + 39_990));
        assert!(!replay.accepts(5));
        assert!(replay.accepts(3 * 65_536 + 40_001));
        assert_eq!(replay.highest(), Some(3 * 65_536 + 40_000));
        assert_eq!(Replay::default().highest(), None);
    }

    #[test]
    fn the_first_packet_sets_the_starting_point() {
        let mut receiving = Receiving::default();
        // a stream that starts at a random sequence number, as RFC 3550 wants
        let estimate = receiving.estimate(41_000);
        assert_eq!(estimate.index, 41_000);
        assert_eq!(estimate.rollover(), 0);
        receiving.accept(estimate);
        assert_eq!(receiving.estimate(41_001).index, 41_001);
    }

    #[test]
    fn a_packet_just_after_a_wrap_belongs_to_the_next_rollover() {
        let mut receiving = Receiving::default();
        receiving.accept(receiving.estimate(65_500));
        let estimate = receiving.estimate(3);
        assert_eq!(estimate.rollover(), 1);
        assert_eq!(estimate.index, 65_536 + 3);
        receiving.accept(estimate);
        assert_eq!(receiving.rollover(), 1);
    }

    // the case the RFC calls out: a packet from before the wrap that arrives
    // after it. Its index is in the old rollover, and the stored counter must
    // not move backwards
    #[test]
    fn a_straggler_from_before_the_wrap_keeps_its_old_rollover() {
        let mut receiving = Receiving::default();
        receiving.accept(receiving.estimate(65_530));
        receiving.accept(receiving.estimate(4));
        assert_eq!(receiving.rollover(), 1);

        let straggler = receiving.estimate(65_533);
        assert_eq!(straggler.rollover(), 0);
        assert_eq!(straggler.index, 65_533);
        receiving.accept(straggler);
        assert_eq!(receiving.rollover(), 1, "the stream stays where it was");
        assert_eq!(receiving.estimate(6).index, 65_536 + 6);
    }

    #[test]
    fn reordering_below_the_highest_does_not_move_it() {
        let mut receiving = Receiving::default();
        receiving.accept(receiving.estimate(100));
        receiving.accept(receiving.estimate(105));
        let late = receiving.estimate(102);
        assert_eq!(late.index, 102);
        receiving.accept(late);
        assert_eq!(receiving.estimate(106).index, 106);
    }

    #[test]
    fn a_receiver_can_be_told_where_the_stream_already_is() {
        let receiving = Receiving::joining(7);
        assert_eq!(receiving.estimate(300).index, 7 * 65_536 + 300);
    }

    #[test]
    fn every_sequence_number_across_a_wrap_agrees_with_the_sender() {
        let mut sending = Sending::default();
        let mut receiving = Receiving::default();
        let mut seq = 65_000_u16;
        for _ in 0..2000 {
            let sent = send(&mut sending, seq);
            let estimate = receiving.estimate(seq);
            assert_eq!(Some(estimate.index), sent, "sequence {seq}");
            receiving.accept(estimate);
            seq = seq.wrapping_add(1);
        }
    }

    #[test]
    fn the_window_refuses_what_it_has_already_seen() {
        let mut replay = Replay::default();
        assert!(replay.accepts(10));
        replay.record(10);
        assert!(!replay.accepts(10));
        assert!(replay.accepts(11));
        assert!(replay.accepts(9));
        replay.record(9);
        assert!(!replay.accepts(9));
    }

    #[test]
    fn the_window_refuses_what_is_too_old() {
        let mut replay = Replay::default();
        replay.record(1000);
        // written out rather than read back from `WINDOW`, so that the width
        // the documentation promises is what is checked: 128 packets, the
        // one 127 behind still in and the one 128 behind out
        assert!(replay.accepts(873));
        assert!(!replay.accepts(872));
        assert!(!replay.accepts(0));
        // and never under the floor of §3.3.2: SRTP-WINDOW-SIZE "MUST be at
        // least 64"
        const { assert!(WINDOW >= 64) };
    }

    #[test]
    fn moving_the_window_forgets_only_what_falls_out() {
        let mut replay = Replay::default();
        replay.record(100);
        replay.record(101);
        replay.record(150);
        assert!(!replay.accepts(100));
        assert!(!replay.accepts(101));
        assert!(replay.accepts(102));
        // once the window has moved past them, packets are refused for being
        // old rather than for being remembered — which is the same answer,
        // and the reason a bitmap is enough
        replay.record(150 + WINDOW);
        assert!(!replay.accepts(101));
        assert!(!replay.accepts(150));
        assert!(replay.accepts(151));
    }

    #[test]
    fn a_jump_past_the_whole_window_clears_it() {
        let mut replay = Replay::default();
        replay.record(10);
        replay.record(10_000);
        assert!(!replay.accepts(10_000));
        assert!(replay.accepts(10_000 - WINDOW + 1));
        assert!(!replay.accepts(10));
    }

    #[test]
    fn checking_does_not_record() {
        let mut replay = Replay::default();
        replay.record(500);
        assert!(replay.accepts(501));
        assert!(replay.accepts(501), "a failed packet leaves no trace");
        replay.record(501);
        assert!(!replay.accepts(501));
    }
}
