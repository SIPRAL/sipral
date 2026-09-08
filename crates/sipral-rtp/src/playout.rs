// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Putting packets back in order before anyone listens to them.
//!
//! A network delivers audio at its own pace and sometimes in its own order.
//! The buffer is what stands between that and a device that wants one frame
//! every twenty milliseconds, whatever happened on the way. It is a fixed
//! window of sequence numbers: a packet goes into the slot its number names,
//! the consumer takes them out in order, and reordering inside the window is
//! ordinary rather than an error.
//!
//! Fixed depth is the whole design here. The window is exactly as wide as the
//! ring, so a sequence number in the window names one slot and only one, which
//! makes a duplicate a single test and makes overflow impossible to reach by
//! accident. It also means the buffer cannot grow: a consumer that stops
//! pulling does not turn into unbounded memory, it turns into a counter going
//! up.
//!
//! The slot a number names is found by its distance from the window's base,
//! not by the number itself modulo the ring. That is not a stylistic choice:
//! sequence numbers wrap at sixty-five thousand and a ring of, say, ten slots
//! does not divide that, so the raw modulus stops being one-to-one exactly
//! when the window straddles the wrap — and two live packets would then land
//! in the same slot, one of them read as a duplicate of the other. The
//! distance is computed with wrapping arithmetic and is smaller than the
//! depth by the time it is used, so it is one-to-one for every depth.

use crate::wire::RtpPacket;

/// The widest window that makes sense: at twenty milliseconds a packet, ten
/// seconds of audio, which is already far past the point where a call is worth
/// listening to.
pub const MAX_DEPTH: u16 = 512;

/// Half the sequence number space. A step of at least this much forward is
/// read as a step backward, which is the only way to tell the two apart in
/// sixteen bits that wrap.
const BEHIND: u16 = 1 << 15;

/// What happened to a packet offered to the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insert {
    /// Held for playout.
    Accepted,
    /// Held, but the window had to move first, and this many packets that had
    /// not been played were thrown away to make room. A consumer that stopped
    /// pulling gets here, and so does a gap wider than the window.
    Displaced(u16),
    /// Its slot is already taken, so this is the same packet twice.
    Duplicate,
    /// Behind the playout point: whatever it carries, its turn has passed.
    Late,
}

/// What came out of the buffer.
#[derive(Debug)]
pub enum Pull<'a> {
    /// The next packet in order.
    Packet(Frame<'a>),
    /// Its sequence number came due and nothing was in the slot. Later packets
    /// are waiting, so this one is not coming.
    Missing,
    /// Nothing to play: still filling, or the far end has stopped talking.
    Empty,
}

/// One packet, ready to be decoded, borrowed from the buffer's own storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Its sequence number.
    pub sequence: u16,
    /// The sampling instant of its first octet, at the negotiated clock rate.
    pub timestamp: u32,
    /// Which format it is in.
    pub payload_type: u8,
    /// The marker bit: for audio, the first packet of a talk spurt
    /// (RFC 3551 §4.1), which is where a playout delay may be changed without
    /// anyone hearing it.
    pub marker: bool,
    /// The payload.
    pub payload: &'a [u8],
}

/// What the application reports about one stream.
///
/// Cumulative for the life of the stream, and never reset by anything the
/// buffer does on its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamStats {
    /// Packets taken in and held for playout.
    pub received: u64,
    /// Sequence numbers that came due with nothing in them, plus the ones the
    /// window moved past unfilled.
    pub lost: u64,
    /// Packets whose sequence number was already held.
    pub duplicated: u64,
    /// Packets accepted after a higher sequence number had already arrived.
    pub reordered: u64,
    /// Packets taken in and then thrown away rather than played: too late for
    /// the playout point, or pushed out of the window by a consumer that
    /// stopped pulling.
    pub discarded: u64,
}

#[derive(Debug, Default)]
struct Slot {
    filled: bool,
    sequence: u16,
    timestamp: u32,
    payload_type: u8,
    marker: bool,
    payload: Vec<u8>,
}

/// A fixed-depth de-jitter buffer for one stream.
#[derive(Debug)]
pub struct JitterBuffer {
    slots: Vec<Slot>,
    /// Which slot the window's base sits in. It moves with the base rather
    /// than being derived from the sequence number; see the module note.
    origin: usize,
    depth: u16,
    prefill: u16,
    held: u16,
    next: u16,
    highest: u16,
    anchored: bool,
    playing: bool,
    stats: StreamStats,
}

impl JitterBuffer {
    /// A buffer `depth` packets wide that starts playing out once `prefill` of
    /// them are held.
    ///
    /// The prefill is the delay the buffer trades for the reordering it can
    /// absorb: a packet that arrives while the ones ahead of it are still
    /// waiting costs nothing, and one that arrives after they have been played
    /// is lost. Both numbers are clamped into what a window can be — at least
    /// one packet, at most [`MAX_DEPTH`] — and the prefill never exceeds the
    /// depth, since a buffer that waits for more than it can hold would never
    /// start.
    #[must_use]
    pub fn new(depth: u16, prefill: u16) -> Self {
        let depth = depth.clamp(1, MAX_DEPTH);
        let mut slots = Vec::new();
        slots.resize_with(usize::from(depth), Slot::default);
        Self {
            slots,
            origin: 0,
            depth,
            prefill: prefill.min(depth),
            held: 0,
            next: 0,
            highest: 0,
            anchored: false,
            playing: false,
            stats: StreamStats::default(),
        }
    }

    /// Offer a packet.
    ///
    /// The first one anchors the window; after that the sequence number says
    /// where the packet belongs relative to what is being played. Nothing here
    /// asks whether the packet is believable — that is settled before it gets
    /// this far, which is what keeps a wild sequence number from moving the
    /// window.
    pub fn insert(&mut self, packet: &RtpPacket<'_>) -> Insert {
        let header = packet.header();
        let sequence = header.sequence;

        if !self.anchored {
            self.anchored = true;
            self.next = sequence;
            self.origin = 0;
            self.highest = sequence.wrapping_sub(1);
        }

        let ahead = sequence.wrapping_sub(self.next);
        if ahead >= BEHIND {
            self.stats.discarded = self.stats.discarded.saturating_add(1);
            return Insert::Late;
        }

        let displaced = if ahead >= self.depth {
            self.slide(sequence)
        } else {
            0
        };

        let index = self.index_of(sequence);
        if self.slots.get(index).is_some_and(|slot| slot.filled) {
            // a filled slot inside the window can only hold this very sequence
            // number: the window is exactly as wide as the ring, so the two
            // map one to one
            self.stats.duplicated = self.stats.duplicated.saturating_add(1);
            return Insert::Duplicate;
        }

        let payload = packet.payload();
        let Some(slot) = self.slots.get_mut(index) else {
            // nothing was stored, so the packet is gone; the index is a
            // modulus of a length that is never zero, so it cannot happen
            return Insert::Late;
        };
        slot.filled = true;
        slot.sequence = sequence;
        slot.timestamp = header.timestamp;
        slot.payload_type = header.payload_type;
        slot.marker = header.marker;
        // the slot keeps its allocation across packets, so a stream that has
        // been running for a while has stopped allocating altogether
        slot.payload.clear();
        slot.payload.extend_from_slice(payload);

        self.held = self.held.saturating_add(1);
        self.stats.received = self.stats.received.saturating_add(1);
        if sequence.wrapping_sub(self.highest) >= BEHIND {
            self.stats.reordered = self.stats.reordered.saturating_add(1);
        } else {
            self.highest = sequence;
        }

        if displaced > 0 {
            Insert::Displaced(displaced)
        } else {
            Insert::Accepted
        }
    }

    /// Take the next packet, if it is time for it.
    pub fn pull(&mut self) -> Pull<'_> {
        if !self.anchored {
            return Pull::Empty;
        }
        if !self.playing {
            if self.held == 0 || self.held < self.prefill {
                return Pull::Empty;
            }
            self.playing = true;
        }

        let index = self.index_of(self.next);
        if !self.slots.get(index).is_some_and(|slot| slot.filled) {
            if self.held == 0 {
                // nothing behind it either: the stream has stopped rather than
                // lost a packet, so the window waits where it is
                self.playing = false;
                return Pull::Empty;
            }
            self.advance_base(1);
            self.stats.lost = self.stats.lost.saturating_add(1);
            return Pull::Missing;
        }

        self.advance_base(1);
        self.held = self.held.saturating_sub(1);
        if self.held == 0 {
            // fill up again before playing on, or the next packet to arrive
            // late has no room to be early in
            self.playing = false;
        }

        let Some(slot) = self.slots.get_mut(index) else {
            // it was filled a moment ago, so this cannot happen either
            return Pull::Empty;
        };
        slot.filled = false;
        Pull::Packet(Frame {
            sequence: slot.sequence,
            timestamp: slot.timestamp,
            payload_type: slot.payload_type,
            marker: slot.marker,
            payload: &slot.payload,
        })
    }

    /// Throw away what is held and wait to be anchored again, keeping the
    /// counters. For a far end that has restarted its stream, where what is
    /// still in the window belongs to a stream that no longer exists.
    pub fn restart(&mut self) {
        for slot in &mut self.slots {
            slot.filled = false;
        }
        // what was waiting is thrown away, and saying so is the difference
        // between a counter that accounts for every packet taken in and one
        // that quietly loses some
        self.stats.discarded = self.stats.discarded.saturating_add(u64::from(self.held));
        self.held = 0;
        self.anchored = false;
        self.playing = false;
    }

    /// The counters.
    #[must_use]
    pub const fn stats(&self) -> StreamStats {
        self.stats
    }

    /// How many packets are waiting.
    #[must_use]
    pub const fn held(&self) -> u16 {
        self.held
    }

    /// How wide the window is.
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// The sequence number that comes out next, once the buffer has seen a
    /// first packet.
    #[must_use]
    pub const fn next_sequence(&self) -> Option<u16> {
        if self.anchored { Some(self.next) } else { None }
    }

    /// Move the window up so `sequence` lands at its far edge, and say how
    /// many packets were thrown away to do it.
    fn slide(&mut self, sequence: u16) -> u16 {
        let target = sequence.wrapping_sub(self.depth.saturating_sub(1));
        let advance = target.wrapping_sub(self.next);
        // only the window itself can hold anything, so a longer jump clears
        // the same slots as a jump of exactly one window
        let steps = advance.min(self.depth);

        let mut displaced: u16 = 0;
        let mut sequence = self.next;
        for _ in 0..steps {
            let index = self.index_of(sequence);
            if let Some(slot) = self.slots.get_mut(index)
                && slot.filled
            {
                slot.filled = false;
                displaced = displaced.saturating_add(1);
            }
            sequence = sequence.wrapping_add(1);
        }

        self.held = self.held.saturating_sub(displaced);
        self.stats.discarded = self.stats.discarded.saturating_add(u64::from(displaced));
        // what the window passed over without ever holding is loss the
        // consumer will never be told about any other way
        let skipped = u64::from(advance).saturating_sub(u64::from(displaced));
        self.stats.lost = self.stats.lost.saturating_add(skipped);
        self.advance_base(advance);
        displaced
    }

    /// Which slot holds `sequence`, by its distance from the window's base.
    fn index_of(&self, sequence: u16) -> usize {
        let len = self.slots.len();
        if len == 0 {
            return 0;
        }
        let ahead = usize::from(sequence.wrapping_sub(self.next));
        (self.origin + ahead) % len
    }

    /// Move the base of the window forward, taking the ring's origin with it.
    fn advance_base(&mut self, by: u16) {
        let len = self.slots.len();
        if len != 0 {
            self.origin = (self.origin + usize::from(by) % len) % len;
        }
        self.next = self.next.wrapping_add(by);
    }
}

#[cfg(test)]
mod tests {
    use super::{Insert, JitterBuffer, MAX_DEPTH, Pull};
    use crate::wire::{PacketBuilder, RtpHeader, RtpPacket};

    /// One packet's worth of wire bytes, with the sequence number in the
    /// payload so playout order is visible in the assertions.
    fn datagram(sequence: u16, marker: bool) -> Vec<u8> {
        let header = RtpHeader {
            marker,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence).wrapping_mul(160),
            ssrc: 0x1234_5678,
        };
        let payload = sequence.to_be_bytes();
        let mut out = vec![0; 32];
        let n = PacketBuilder::new(header, &payload)
            .write(&mut out)
            .expect("room");
        out.truncate(n);
        out
    }

    fn insert(buffer: &mut JitterBuffer, sequence: u16) -> Insert {
        let bytes = datagram(sequence, false);
        let packet = RtpPacket::parse(&bytes).expect("a packet");
        buffer.insert(&packet)
    }

    /// The sequence number of whatever comes out, or `None` for a hole.
    fn pull(buffer: &mut JitterBuffer) -> Option<u16> {
        match buffer.pull() {
            Pull::Packet(frame) => Some(frame.sequence),
            Pull::Missing | Pull::Empty => None,
        }
    }

    #[test]
    fn a_window_that_straddles_the_wrap_still_names_one_slot_per_number() {
        // the ring is indexed by distance from the base, not by the sequence
        // number itself: 65536 is not a multiple of ten, so the raw modulus
        // would put 65530 and 0 in the same slot and read the second as a
        // duplicate of the first
        let mut buffer = JitterBuffer::new(10, 1);
        for sequence in [65_530_u16, 65_531, 65_532, 65_533, 65_534, 65_535] {
            let bytes = datagram(sequence, false);
            let packet = RtpPacket::parse(&bytes).expect("a packet");
            assert_eq!(buffer.insert(&packet), Insert::Accepted);
        }
        let bytes = datagram(0, false);
        let packet = RtpPacket::parse(&bytes).expect("a packet");
        assert_eq!(
            buffer.insert(&packet),
            Insert::Accepted,
            "the packet after the wrap is live audio, not a duplicate"
        );
        assert_eq!(buffer.held(), 7);
        assert_eq!(buffer.stats().duplicated, 0);

        // and it comes out where it belongs
        for expected in [65_530_u16, 65_531, 65_532, 65_533, 65_534, 65_535, 0] {
            assert_eq!(pull(&mut buffer), Some(expected));
        }
    }

    #[test]
    fn every_depth_holds_a_full_window_across_the_wrap() {
        // the same property, stated for the depths a caller might pick rather
        // than for the one that happened to break
        for depth in 1_u16..=24 {
            let mut buffer = JitterBuffer::new(depth, 1);
            let base = 65_536_u32.wrapping_sub(u32::from(depth) / 2);
            for step in 0..depth {
                let sequence = u16::try_from((base + u32::from(step)) % 65_536).unwrap();
                let bytes = datagram(sequence, false);
                let packet = RtpPacket::parse(&bytes).expect("a packet");
                assert_eq!(
                    buffer.insert(&packet),
                    Insert::Accepted,
                    "depth {depth}, sequence {sequence}"
                );
            }
            assert_eq!(buffer.held(), depth, "depth {depth}");
            assert_eq!(buffer.stats().duplicated, 0, "depth {depth}");
        }
    }

    #[test]
    fn packets_come_out_in_sequence_order_whatever_order_they_went_in() {
        let mut buffer = JitterBuffer::new(8, 3);
        assert_eq!(insert(&mut buffer, 10), Insert::Accepted);
        assert_eq!(insert(&mut buffer, 12), Insert::Accepted);
        assert_eq!(insert(&mut buffer, 11), Insert::Accepted);
        assert_eq!(pull(&mut buffer), Some(10));
        assert_eq!(pull(&mut buffer), Some(11));
        assert_eq!(pull(&mut buffer), Some(12));
        assert_eq!(buffer.stats().reordered, 1, "11 arrived after 12");
        assert_eq!(buffer.stats().lost, 0, "reordering is not loss");
    }

    #[test]
    fn nothing_comes_out_until_the_prefill_is_there() {
        let mut buffer = JitterBuffer::new(8, 3);
        insert(&mut buffer, 1);
        assert!(matches!(buffer.pull(), Pull::Empty));
        insert(&mut buffer, 2);
        assert!(matches!(buffer.pull(), Pull::Empty));
        insert(&mut buffer, 3);
        assert_eq!(pull(&mut buffer), Some(1));
    }

    #[test]
    fn the_frame_carries_what_the_header_said() {
        let mut buffer = JitterBuffer::new(4, 1);
        let bytes = datagram(7, true);
        let packet = RtpPacket::parse(&bytes).expect("a packet");
        buffer.insert(&packet);
        let Pull::Packet(frame) = buffer.pull() else {
            panic!("a packet");
        };
        assert_eq!(frame.sequence, 7);
        assert_eq!(frame.timestamp, 7 * 160);
        assert_eq!(frame.payload_type, 0);
        assert!(frame.marker, "a talk spurt starts here");
        assert_eq!(frame.payload, 7_u16.to_be_bytes());
    }

    #[test]
    fn the_same_sequence_number_twice_is_dropped_on_the_second() {
        let mut buffer = JitterBuffer::new(8, 1);
        assert_eq!(insert(&mut buffer, 40), Insert::Accepted);
        assert_eq!(insert(&mut buffer, 40), Insert::Duplicate);
        assert_eq!(buffer.held(), 1);
        assert_eq!(buffer.stats().duplicated, 1);
        assert_eq!(buffer.stats().received, 1);
    }

    #[test]
    fn a_packet_behind_the_playout_point_has_missed_its_turn() {
        let mut buffer = JitterBuffer::new(8, 1);
        insert(&mut buffer, 100);
        insert(&mut buffer, 101);
        assert_eq!(pull(&mut buffer), Some(100));
        assert_eq!(pull(&mut buffer), Some(101));
        // 99 was in flight the whole time; the window has moved past it
        assert_eq!(insert(&mut buffer, 99), Insert::Late);
        assert_eq!(buffer.stats().discarded, 1);
        assert_eq!(buffer.stats().received, 2);
    }

    #[test]
    fn a_hole_that_comes_due_is_reported_and_the_stream_carries_on() {
        let mut buffer = JitterBuffer::new(8, 2);
        insert(&mut buffer, 5);
        insert(&mut buffer, 7);
        assert_eq!(pull(&mut buffer), Some(5));
        assert!(matches!(buffer.pull(), Pull::Missing), "6 never arrived");
        assert_eq!(pull(&mut buffer), Some(7));
        assert_eq!(buffer.stats().lost, 1);
    }

    #[test]
    fn an_empty_buffer_says_so_rather_than_declaring_a_loss() {
        let mut buffer = JitterBuffer::new(8, 1);
        assert!(matches!(buffer.pull(), Pull::Empty), "nothing has arrived");
        insert(&mut buffer, 3);
        assert_eq!(pull(&mut buffer), Some(3));
        assert!(matches!(buffer.pull(), Pull::Empty));
        assert_eq!(buffer.stats().lost, 0);
    }

    #[test]
    fn a_stalled_consumer_costs_the_oldest_packets_and_not_the_memory() {
        // the window is fixed, so a consumer that stops pulling turns into a
        // counter going up rather than a buffer growing
        let mut buffer = JitterBuffer::new(4, 1);
        for sequence in 200..204 {
            assert_eq!(insert(&mut buffer, sequence), Insert::Accepted);
        }
        assert_eq!(buffer.held(), 4);

        assert_eq!(insert(&mut buffer, 204), Insert::Displaced(1));
        assert_eq!(buffer.held(), 4, "still four, never five");
        assert_eq!(buffer.stats().discarded, 1);

        for sequence in 205..208 {
            assert_eq!(insert(&mut buffer, sequence), Insert::Displaced(1));
        }
        assert_eq!(buffer.held(), 4);
        assert_eq!(buffer.stats().discarded, 4);

        // what is left is the newest four, which is what a live call wants
        assert_eq!(pull(&mut buffer), Some(204));
        assert_eq!(pull(&mut buffer), Some(205));
        assert_eq!(pull(&mut buffer), Some(206));
        assert_eq!(pull(&mut buffer), Some(207));
        assert!(matches!(buffer.pull(), Pull::Empty));
    }

    #[test]
    fn a_jump_past_the_whole_window_clears_it_and_counts_what_was_missed() {
        let mut buffer = JitterBuffer::new(4, 1);
        insert(&mut buffer, 10);
        insert(&mut buffer, 11);
        assert_eq!(insert(&mut buffer, 40), Insert::Displaced(2));
        assert_eq!(buffer.held(), 1);
        assert_eq!(buffer.stats().discarded, 2, "10 and 11 were thrown away");
        // the window moved from 10 to 37, and what it passed over is loss
        assert_eq!(buffer.stats().lost, 25);
        // 37, 38 and 39 are still inside the window, so they are only lost
        // once their turn comes and nothing is there
        assert!(matches!(buffer.pull(), Pull::Missing));
        assert!(matches!(buffer.pull(), Pull::Missing));
        assert!(matches!(buffer.pull(), Pull::Missing));
        assert_eq!(pull(&mut buffer), Some(40));
        assert_eq!(
            buffer.stats().lost + buffer.stats().discarded,
            30,
            "thirty sequence numbers went by unheard, two of them held"
        );
    }

    #[test]
    fn the_window_follows_the_sequence_number_across_the_wrap() {
        let mut buffer = JitterBuffer::new(8, 2);
        insert(&mut buffer, 65534);
        insert(&mut buffer, 65535);
        insert(&mut buffer, 0);
        insert(&mut buffer, 1);
        assert_eq!(pull(&mut buffer), Some(65534));
        assert_eq!(pull(&mut buffer), Some(65535));
        assert_eq!(pull(&mut buffer), Some(0));
        assert_eq!(pull(&mut buffer), Some(1));
        assert_eq!(buffer.stats().lost, 0);
        assert_eq!(buffer.stats().reordered, 0);
    }

    #[test]
    fn a_restart_drops_the_stream_it_was_holding_and_keeps_the_counters() {
        let mut buffer = JitterBuffer::new(8, 1);
        insert(&mut buffer, 20);
        insert(&mut buffer, 21);
        buffer.restart();
        assert_eq!(buffer.held(), 0);
        assert_eq!(buffer.next_sequence(), None);
        assert_eq!(buffer.stats().received, 2, "the counters are cumulative");

        insert(&mut buffer, 9000);
        assert_eq!(buffer.next_sequence(), Some(9000));
        assert_eq!(pull(&mut buffer), Some(9000));
    }

    #[test]
    fn the_depth_is_clamped_to_something_a_window_can_be() {
        assert_eq!(JitterBuffer::new(0, 0).depth(), 1);
        assert_eq!(JitterBuffer::new(u16::MAX, 0).depth(), MAX_DEPTH);
        // a buffer that waited for more than it can hold would never start
        let mut buffer = JitterBuffer::new(2, 50);
        insert(&mut buffer, 1);
        insert(&mut buffer, 2);
        assert_eq!(pull(&mut buffer), Some(1));
    }
}
