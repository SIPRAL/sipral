// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The receiving half of a text conversation: RTP payloads in, typed
//! characters out, in order, once each, with the gaps marked.
//!
//! Every block is placed by sequence number. A bare T140block belongs to
//! its packet's own; inside redundancy (RFC 4103 §4) a packet carrying `n`
//! redundant generations holds copies of the primaries of the `n` packets
//! before it, oldest first, so the block `k` places from the end of the
//! redundant list belongs to sequence number `s - k`. A block for a place
//! already filled is a copy and is dropped; one for a place further ahead
//! than the next one due waits.
//!
//! A place nothing fills — every copy of it lost — holds up the text behind
//! it for a bounded time, in case the packet is only late (§5.4), and after
//! that is given up: the reader sees a missing-text marker for each place
//! lost, as §5.3 has it ("for each missing T140block"), and the text
//! resumes. A sender that started over, whose places cannot be counted, is
//! marked once.

use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};

use super::red::{RedError, RedPayload};
use super::t140::{Decoder, TextEvent};
use super::{ConfigError, Redundancy, check_payload_types};
use crate::playout::Frame;

/// How long a gap holds up the text behind it, by default.
pub const DEFAULT_REORDER_WAIT: Duration = Duration::from_secs(1);

/// Blocks held behind a gap, by default, before the gap is given up on
/// without waiting out its time.
pub const DEFAULT_MAX_PENDING: usize = 64;

/// Events held for the reader, by default, before more are dropped.
pub const DEFAULT_MAX_EVENTS: usize = 4096;

/// How far a sequence number may sit from the next one due and still be
/// the same stream; past it, the stream is taken to have started over.
const MAX_DISTANCE: u64 = 1024;

/// Where extended sequence numbers start, far enough from zero that the
/// redundant generations of the first packet never reach below it.
const BASE: u64 = 1 << 32;

/// How a [`TextReceiver`] receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiverConfig {
    /// The payload type negotiated for `t140/1000`.
    pub t140_payload_type: u8,
    /// The payload type negotiated for `red/1000`, if it was.
    pub red_payload_type: Option<u8>,
    /// How long a block may be held behind a gap no copy has filled before
    /// the gap is given up.
    pub reorder_wait: Duration,
    /// The most blocks held behind a gap; one more gives the gap up at once.
    pub max_pending: usize,
    /// The most events held for the reader; past it, text is dropped and a
    /// single [`TextEvent::Missing`] stands for it once the reader catches
    /// up.
    pub max_events: usize,
}

impl ReceiverConfig {
    /// The default settings for a `t140` payload type and, if negotiated,
    /// a `red` one.
    #[must_use]
    pub const fn new(t140_payload_type: u8, red_payload_type: Option<u8>) -> Self {
        Self {
            t140_payload_type,
            red_payload_type,
            reorder_wait: DEFAULT_REORDER_WAIT,
            max_pending: DEFAULT_MAX_PENDING,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

/// What [`TextReceiver::receive`] made of a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// It held at least one block not seen before.
    Accepted,
    /// Everything in it had already arrived, or was given up on.
    Duplicate,
    /// Neither the `t140` nor the `red` payload type: not this stream's.
    Foreign,
    /// A `red` payload whose headers do not add up.
    Malformed(RedError),
}

/// The receiving half of an RFC 4103 text stream.
///
/// Sans-I/O: [`receive`](Self::receive) takes each packet with the time it
/// arrived, [`poll`](Self::poll) is called when [`deadline`](Self::deadline)
/// says, and [`next_event`](Self::next_event) hands out what was typed.
#[derive(Clone, Debug)]
pub struct TextReceiver {
    config: ReceiverConfig,
    /// The extended sequence number of the next block due, once one packet
    /// has said where the stream is.
    expected: Option<u64>,
    /// Blocks behind a gap, with when each arrived.
    pending: BTreeMap<u64, (Vec<u8>, Duration)>,
    decoder: Decoder,
    events: VecDeque<TextEvent>,
    /// Events were dropped for want of room; a marker is owed.
    dropped: bool,
}

impl TextReceiver {
    /// A receiver for the payload types in `config`.
    ///
    /// # Errors
    /// [`ConfigError`] for payload types that do not fit seven bits or that
    /// are the same.
    pub fn new(config: ReceiverConfig) -> Result<Self, ConfigError> {
        let red = config.red_payload_type.map(|payload_type| Redundancy {
            payload_type,
            generations: 0,
        });
        check_payload_types(config.t140_payload_type, red)?;
        Ok(Self {
            config,
            expected: None,
            pending: BTreeMap::new(),
            decoder: Decoder::new(),
            events: VecDeque::new(),
            dropped: false,
        })
    }

    /// The configuration this receiver was built with.
    #[must_use]
    pub const fn config(&self) -> &ReceiverConfig {
        &self.config
    }

    /// Forget the stream, as for a new SSRC: nothing held is delivered and
    /// the next packet sets the sequence numbers afresh. Events already
    /// decoded stay for the reader.
    pub fn restart(&mut self) {
        self.expected = None;
        self.pending.clear();
        self.decoder.reset();
    }

    /// Take one packet, arrived at `now`.
    pub fn receive(&mut self, frame: Frame<'_>, now: Duration) -> Arrival {
        let t140 = self.config.t140_payload_type;
        // (how many places back from this packet, the block)
        let mut blocks: Vec<(u64, &[u8])> = Vec::new();
        let redundant: u64;
        if frame.payload_type == t140 {
            redundant = 0;
            blocks.push((0, frame.payload));
        } else if Some(frame.payload_type) == self.config.red_payload_type {
            let red = match RedPayload::parse(frame.payload) {
                Ok(red) => red,
                Err(why) => return Arrival::Malformed(why),
            };
            redundant = u64::try_from(red.redundant_count()).unwrap_or(u64::MAX);
            let mut back = redundant;
            for block in red.redundant() {
                if block.payload_type == t140 {
                    blocks.push((back, block.data));
                }
                back = back.saturating_sub(1);
            }
            if red.primary_payload_type() == t140 {
                blocks.push((0, red.primary()));
            }
        } else {
            return Arrival::Foreign;
        }

        let sequence = self.extend(frame.sequence);
        let oldest = sequence.saturating_sub(redundant);
        match self.expected {
            None => self.expected = Some(oldest),
            Some(expected) if sequence.abs_diff(expected) > MAX_DISTANCE => {
                // a sender that started over, or one that has been gone for
                // longer than any wait: whatever was between is lost
                self.give_up_all();
                self.push_event(TextEvent::Missing);
                self.decoder.reset();
                self.expected = Some(oldest);
            }
            Some(_) => {}
        }
        let expected = self.expected.unwrap_or(oldest);

        let mut fresh = false;
        for (back, data) in blocks {
            let place = sequence.saturating_sub(back);
            if place < expected || self.pending.contains_key(&place) {
                continue;
            }
            self.pending.insert(place, (data.to_vec(), now));
            fresh = true;
        }
        self.drain();
        while self.pending.len() > self.config.max_pending {
            self.skip_gap();
        }
        if fresh {
            Arrival::Accepted
        } else {
            Arrival::Duplicate
        }
    }

    /// When [`poll`](Self::poll) must next be called: when the block that
    /// has been held behind a gap the longest has waited its time, if any
    /// block is held. A wait too long for the clock to hold ends at
    /// [`Duration::MAX`].
    #[must_use]
    pub fn deadline(&self) -> Option<Duration> {
        self.pending
            .values()
            .map(|(_, arrived)| *arrived)
            .min()
            .map(|arrived| arrived.saturating_add(self.config.reorder_wait))
    }

    /// Give up on every gap that has held a block back for its whole wait
    /// by `now`.
    pub fn poll(&mut self, now: Duration) {
        while self.deadline().is_some_and(|deadline| deadline <= now) {
            self.skip_gap();
        }
    }

    /// The next thing typed, oldest first.
    pub fn next_event(&mut self) -> Option<TextEvent> {
        if let Some(event) = self.events.pop_front() {
            return Some(event);
        }
        if self.dropped {
            self.dropped = false;
            return Some(TextEvent::Missing);
        }
        None
    }

    /// Everything typed and not yet handed out, oldest first.
    pub fn events(&mut self) -> impl Iterator<Item = TextEvent> + '_ {
        core::iter::from_fn(|| self.next_event())
    }

    /// `sequence` as an extended sequence number, taken to be whichever
    /// of its wraps lies nearest the next one due.
    fn extend(&self, sequence: u16) -> u64 {
        let Some(expected) = self.expected else {
            return BASE + u64::from(sequence);
        };
        let near = u16::try_from(expected & 0xFFFF).unwrap_or(0);
        let delta = i16::from_ne_bytes(sequence.wrapping_sub(near).to_ne_bytes());
        expected
            .checked_add_signed(i64::from(delta))
            .unwrap_or(expected)
    }

    /// Hand out every block that is next in line.
    fn drain(&mut self) {
        let Some(mut expected) = self.expected else {
            return;
        };
        while let Some((data, _)) = self.pending.remove(&expected) {
            self.deliver(&data);
            expected += 1;
        }
        self.expected = Some(expected);
    }

    /// Give the first gap up: mark each place in it and carry on from the
    /// block after it.
    fn skip_gap(&mut self) {
        let Some((&first, _)) = self.pending.first_key_value() else {
            return;
        };
        if let Some(expected) = self.expected.filter(|&expected| first > expected) {
            // RFC 4103 §5.3: a marker "for each missing T140block"; a gap
            // is never wider than MAX_DISTANCE, and the event queue is
            // bounded besides
            for _ in expected..first {
                self.push_event(TextEvent::Missing);
            }
            self.decoder.reset();
        }
        self.expected = Some(first);
        self.drain();
    }

    /// Give every gap up, delivering all that is held.
    fn give_up_all(&mut self) {
        while !self.pending.is_empty() {
            self.skip_gap();
        }
    }

    fn deliver(&mut self, data: &[u8]) {
        let Self {
            decoder,
            events,
            dropped,
            config,
            ..
        } = self;
        decoder.feed(data, &mut |event| {
            push(events, dropped, config.max_events, event);
        });
    }

    fn push_event(&mut self, event: TextEvent) {
        push(
            &mut self.events,
            &mut self.dropped,
            self.config.max_events,
            event,
        );
    }
}

/// Queue `event` unless the queue is full, or has been since the reader
/// last emptied it: one marker then stands for all that was dropped.
fn push(events: &mut VecDeque<TextEvent>, dropped: &mut bool, max: usize, event: TextEvent) {
    if *dropped || events.len() >= max {
        *dropped = true;
        return;
    }
    events.push_back(event);
}

#[cfg(test)]
mod tests {
    use super::{Arrival, ReceiverConfig, TextReceiver};
    use crate::playout::Frame;
    use crate::rtt::red::{RedError, RedundantBlock, write_red};
    use crate::rtt::{SenderConfig, TextEvent, TextPacket, TextSender};
    use core::time::Duration;

    const T140: u8 = 98;
    const RED: u8 = 100;

    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    fn frame(packet: &TextPacket) -> Frame<'_> {
        Frame {
            sequence: packet.header.sequence,
            timestamp: packet.header.timestamp,
            payload_type: packet.header.payload_type,
            marker: packet.header.marker,
            payload: &packet.payload,
        }
    }

    fn bare(sequence: u16, payload: &[u8]) -> Frame<'_> {
        Frame {
            sequence,
            timestamp: 0,
            payload_type: T140,
            marker: false,
            payload,
        }
    }

    fn receiver() -> TextReceiver {
        TextReceiver::new(ReceiverConfig::new(T140, Some(RED))).unwrap()
    }

    /// One packet per word, 300 ms apart, and the flush after them.
    fn conversation(words: &[&str], first_sequence: u16) -> Vec<TextPacket> {
        let config = SenderConfig {
            send_bom: false,
            cps: None,
            ..SenderConfig::new(T140, RED)
        };
        let mut tx = TextSender::new(config, 1, first_sequence, 0).unwrap();
        let mut out = Vec::new();
        let mut now = ms(0);
        for word in words {
            tx.push(word).unwrap();
            out.extend(tx.poll(now));
            now += ms(300);
        }
        while tx.next_poll().is_some() {
            out.extend(tx.poll(now));
            now += ms(300);
        }
        out
    }

    fn transcript(rx: &mut TextReceiver) -> String {
        rx.events().map(TextEvent::as_char).collect()
    }

    #[test]
    fn packets_in_order_give_the_text_in_order() {
        let packets = conversation(&["He", "ll", "o"], 7);
        assert_eq!(packets.len(), 5);
        let mut rx = receiver();
        for packet in &packets {
            assert_eq!(rx.receive(frame(packet), ms(0)), Arrival::Accepted);
        }
        assert_eq!(transcript(&mut rx), "Hello");
        assert_eq!(rx.deadline(), None);
    }

    #[test]
    fn a_packet_twice_gives_its_text_once() {
        let packets = conversation(&["a", "b"], 0);
        let mut rx = receiver();
        rx.receive(frame(&packets[0]), ms(0));
        assert_eq!(rx.receive(frame(&packets[0]), ms(1)), Arrival::Duplicate);
        rx.receive(frame(&packets[1]), ms(2));
        rx.receive(frame(&packets[1]), ms(3));
        rx.receive(frame(&packets[0]), ms(4));
        assert_eq!(transcript(&mut rx), "ab");
    }

    #[test]
    fn one_lost_packet_is_recovered_from_the_next() {
        let packets = conversation(&["one ", "two ", "three"], 0);
        let mut rx = receiver();
        for (index, packet) in packets.iter().enumerate() {
            if index != 1 {
                rx.receive(frame(packet), ms(0));
            }
        }
        assert_eq!(transcript(&mut rx), "one two three");
        assert_eq!(rx.deadline(), None);
    }

    #[test]
    fn two_lost_packets_are_recovered_with_two_generations() {
        let packets = conversation(&["a", "b", "c", "d"], 0);
        let mut rx = receiver();
        for (index, packet) in packets.iter().enumerate() {
            if index != 1 && index != 2 {
                rx.receive(frame(packet), ms(0));
            }
        }
        assert_eq!(transcript(&mut rx), "abcd");
    }

    #[test]
    fn the_first_packet_lost_is_recovered_from_the_second() {
        let packets = conversation(&["a", "b"], 0);
        let mut rx = receiver();
        rx.receive(frame(&packets[1]), ms(0));
        assert_eq!(transcript(&mut rx), "ab");
    }

    #[test]
    fn three_lost_packets_leave_one_marker_after_the_wait() {
        let packets = conversation(&["a", "b", "c", "d", "e"], 0);
        let mut rx = receiver();
        for (index, packet) in packets.iter().enumerate() {
            // "b", "c" and "d" go, and only "c" and "d" come back as copies
            if !(1..=3).contains(&index) {
                rx.receive(frame(packet), ms(1200));
            }
        }
        // the text behind the gap waits for a late packet
        assert_eq!(transcript(&mut rx), "a");
        assert_eq!(rx.deadline(), Some(ms(2200)));
        rx.poll(ms(2199));
        assert_eq!(transcript(&mut rx), "");
        rx.poll(ms(2200));
        assert_eq!(transcript(&mut rx), "\u{FFFD}cde");
        assert_eq!(rx.deadline(), None);
        // and a straggler from the gap changes nothing
        assert_eq!(rx.receive(frame(&packets[1]), ms(2300)), Arrival::Duplicate);
        assert_eq!(transcript(&mut rx), "");
    }

    #[test]
    fn a_late_packet_that_arrives_in_time_fills_the_gap() {
        let mut rx = receiver();
        rx.receive(bare(1, b"a"), ms(0));
        rx.receive(bare(3, b"c"), ms(10));
        rx.receive(bare(4, b"d"), ms(20));
        assert_eq!(transcript(&mut rx), "a");
        assert_eq!(rx.deadline(), Some(ms(1010)));
        assert_eq!(rx.receive(bare(2, b"b"), ms(500)), Arrival::Accepted);
        assert_eq!(transcript(&mut rx), "bcd");
        assert_eq!(rx.deadline(), None);
    }

    #[test]
    fn separate_gaps_are_marked_separately() {
        let mut rx = TextReceiver::new(ReceiverConfig {
            reorder_wait: ms(100),
            ..ReceiverConfig::new(T140, None)
        })
        .unwrap();
        rx.receive(bare(1, b"a"), ms(0));
        rx.receive(bare(4, b"b"), ms(0));
        rx.receive(bare(8, b"c"), ms(0));
        rx.receive(bare(10, b"d"), ms(50));
        rx.poll(ms(100));
        // the blocks that have waited their time come out, a marker for
        // each block lost in front of them (RFC 4103 §5.3); the one that
        // arrived later still waits
        assert_eq!(
            transcript(&mut rx),
            "a\u{FFFD}\u{FFFD}b\u{FFFD}\u{FFFD}\u{FFFD}c"
        );
        assert_eq!(rx.deadline(), Some(ms(150)));
        rx.poll(ms(150));
        assert_eq!(transcript(&mut rx), "\u{FFFD}d");
        assert_eq!(rx.deadline(), None);
    }

    #[test]
    fn a_wait_too_long_to_add_to_the_clock_holds_the_gap_open() {
        let mut rx = TextReceiver::new(ReceiverConfig {
            reorder_wait: Duration::MAX,
            ..ReceiverConfig::new(T140, None)
        })
        .unwrap();
        rx.receive(bare(1, b"a"), ms(0));
        rx.receive(bare(3, b"c"), ms(10));
        assert_eq!(rx.deadline(), Some(Duration::MAX));
        rx.poll(ms(3_600_000));
        assert_eq!(transcript(&mut rx), "a");
        rx.receive(bare(2, b"b"), ms(3_600_001));
        assert_eq!(transcript(&mut rx), "bc");
    }

    #[test]
    fn a_character_split_between_packets_is_put_back_together() {
        let mut rx = receiver();
        let euro = "€".as_bytes();
        rx.receive(bare(10, &euro[..1]), ms(0));
        rx.receive(bare(11, &euro[1..]), ms(0));
        assert_eq!(transcript(&mut rx), "€");
    }

    #[test]
    fn a_character_split_by_a_loss_is_not_put_together_from_its_ends() {
        let mut rx = TextReceiver::new(ReceiverConfig {
            reorder_wait: ms(0),
            ..ReceiverConfig::new(T140, None)
        })
        .unwrap();
        let euro = "€".as_bytes();
        rx.receive(bare(10, &euro[..1]), ms(0));
        rx.receive(bare(12, &euro[2..]), ms(0));
        rx.poll(ms(0));
        // the lead octet is dropped with the loss, the stray continuation
        // octet after it is not a character
        assert_eq!(transcript(&mut rx), "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn erasures_and_new_lines_are_events() {
        let packets = conversation(&["ab\u{8}", "c\r\nd"], 0);
        let mut rx = receiver();
        for packet in &packets {
            rx.receive(frame(packet), ms(0));
        }
        assert_eq!(
            rx.events().collect::<Vec<_>>(),
            [
                TextEvent::Char('a'),
                TextEvent::Char('b'),
                TextEvent::Erase,
                TextEvent::Char('c'),
                TextEvent::NewLine,
                TextEvent::Char('d'),
            ]
        );
    }

    #[test]
    fn sequence_numbers_wrap() {
        let packets = conversation(&["x", "y", "z"], 65534);
        let mut rx = receiver();
        // 65534 arrives, then 1, carrying copies of 65535 and 0 across the
        // wrap, then the rest late
        for index in [0, 3, 2, 1, 4] {
            rx.receive(frame(&packets[index]), ms(0));
        }
        assert_eq!(transcript(&mut rx), "xyz");
    }

    #[test]
    fn a_sender_that_starts_over_is_followed_after_one_marker() {
        let mut rx = receiver();
        for packet in &conversation(&["old"], 100) {
            rx.receive(frame(packet), ms(0));
        }
        for packet in &conversation(&["new"], 40000) {
            rx.receive(frame(packet), ms(0));
        }
        assert_eq!(transcript(&mut rx), "old\u{FFFD}new");
    }

    #[test]
    fn restart_forgets_the_stream() {
        let mut rx = receiver();
        rx.receive(bare(1, b"a"), ms(0));
        rx.receive(bare(3, b"c"), ms(0));
        rx.restart();
        assert_eq!(rx.deadline(), None);
        rx.receive(bare(9000, b"z"), ms(0));
        assert_eq!(transcript(&mut rx), "az");
    }

    #[test]
    fn too_many_blocks_behind_a_gap_give_it_up_at_once() {
        let mut rx = TextReceiver::new(ReceiverConfig {
            max_pending: 3,
            ..ReceiverConfig::new(T140, None)
        })
        .unwrap();
        rx.receive(bare(1, b"a"), ms(0));
        for (sequence, text) in [(3, b"b"), (4, b"c"), (5, b"d")] {
            rx.receive(bare(sequence, text), ms(0));
        }
        assert_eq!(transcript(&mut rx), "a");
        rx.receive(bare(6, b"e"), ms(0));
        assert_eq!(transcript(&mut rx), "\u{FFFD}bcde");
    }

    #[test]
    fn a_reader_that_falls_behind_loses_text_and_is_told_so_once() {
        let mut rx = TextReceiver::new(ReceiverConfig {
            max_events: 4,
            ..ReceiverConfig::new(T140, None)
        })
        .unwrap();
        rx.receive(bare(1, b"abcdef"), ms(0));
        rx.receive(bare(2, b"gh"), ms(0));
        assert_eq!(transcript(&mut rx), "abcd\u{FFFD}");
        rx.receive(bare(3, b"ij"), ms(0));
        assert_eq!(transcript(&mut rx), "ij");
    }

    #[test]
    fn other_payload_types_and_broken_redundancy_are_not_taken() {
        let mut rx = receiver();
        let mut audio = bare(1, b"\x55\x55");
        audio.payload_type = 0;
        assert_eq!(rx.receive(audio, ms(0)), Arrival::Foreign);
        let mut broken = bare(1, &[0xE2, 0x00, 0x00, 0x05, T140, b'a']);
        broken.payload_type = RED;
        assert_eq!(
            rx.receive(broken, ms(0)),
            Arrival::Malformed(RedError::Truncated)
        );
        assert_eq!(transcript(&mut rx), "");
    }

    #[test]
    fn a_redundant_block_of_another_format_fills_nothing() {
        let mut payload = Vec::new();
        let other = RedundantBlock {
            payload_type: 0,
            timestamp_offset: 300,
            data: b"xx",
        };
        write_red(&[other], T140, b"b", &mut payload).unwrap();
        let mut rx = TextReceiver::new(ReceiverConfig {
            reorder_wait: ms(0),
            ..ReceiverConfig::new(T140, Some(RED))
        })
        .unwrap();
        rx.receive(bare(1, b"a"), ms(0));
        let mut red = bare(3, &payload);
        red.payload_type = RED;
        rx.receive(red, ms(0));
        rx.poll(ms(0));
        assert_eq!(transcript(&mut rx), "a\u{FFFD}b");
    }

    #[test]
    fn a_redundant_block_of_another_format_still_counts_as_a_generation() {
        // the oldest generation is not text, the one after it is: that one
        // still belongs to the packet just before, not two before
        let mut payload = Vec::new();
        let blocks = [
            RedundantBlock {
                payload_type: 0,
                timestamp_offset: 600,
                data: b"xx",
            },
            RedundantBlock {
                payload_type: T140,
                timestamp_offset: 300,
                data: b"b",
            },
        ];
        write_red(&blocks, T140, b"c", &mut payload).unwrap();
        let mut rx = receiver();
        rx.receive(bare(1, b"a"), ms(0));
        let mut red = bare(3, &payload);
        red.payload_type = RED;
        assert_eq!(rx.receive(red, ms(0)), Arrival::Accepted);
        assert_eq!(transcript(&mut rx), "abc");
        assert_eq!(rx.deadline(), None);
    }

    #[test]
    fn the_payload_types_are_checked() {
        assert!(TextReceiver::new(ReceiverConfig::new(T140, Some(T140))).is_err());
        assert!(TextReceiver::new(ReceiverConfig::new(128, None)).is_err());
        assert!(TextReceiver::new(ReceiverConfig::new(T140, Some(200))).is_err());
    }
}
