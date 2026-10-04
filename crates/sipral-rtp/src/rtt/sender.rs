// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The sending half of a text conversation: typed text in, RTP packets out,
//! at the pace RFC 4103 §5 sets.
//!
//! Text is not sent a character at a time. It is gathered for one
//! transmission interval and sent as one T140block (§5.1), and with
//! redundancy (§4) every packet also carries the blocks of the packets
//! before it, so one lost packet costs nothing. When the typing stops, the
//! sender keeps going only as long as the last block still owes copies —
//! a packet with an empty primary for each redundant generation — and then
//! falls silent until there is something new to say (§5.2). The first
//! packet after such a silence carries the marker bit, as RFC 4103's rules
//! for the RTP header ask (§3).
//!
//! The rate the far end declared with `cps` (§6) caps how fast characters
//! leave; anything typed faster waits in the buffer.

use core::fmt;
use core::time::Duration;
use std::collections::VecDeque;

use super::red::{MAX_BLOCK_LEN, MAX_TIMESTAMP_OFFSET, RedundantBlock, write_red};
use super::{
    BOM, CLOCK_RATE, ConfigError, DEFAULT_CPS, DEFAULT_GENERATIONS, DEFAULT_INTERVAL,
    LINE_SEPARATOR, MIN_INTERVAL, Redundancy, check_payload_types,
};
use crate::playout::clock_ticks;
use crate::wire::{BuildError, PacketBuilder, RtpHeader};

/// Characters the sender will hold unsent before it refuses more, by
/// default: at the default rate of thirty a second, over two minutes of
/// typing ahead of the wire.
pub const DEFAULT_MAX_BUFFERED: usize = 4096;

/// How a [`TextSender`] sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SenderConfig {
    /// The payload type negotiated for `t140/1000`.
    pub t140_payload_type: u8,
    /// Send inside RFC 2198 redundancy, as RFC 4103 §4 recommends, or bare
    /// T140blocks when `None`.
    pub redundancy: Option<Redundancy>,
    /// How long text is gathered before it is sent: 300 ms by default and
    /// never below 100 ms (RFC 4103 §5.1).
    pub interval: Duration,
    /// The most characters a second the far end said it can take, from the
    /// `cps` format parameter (RFC 4103 §6); `None` for no limit.
    pub cps: Option<u32>,
    /// Open the conversation with the byte order mark T.140 asks for.
    pub send_bom: bool,
    /// The most characters held unsent before [`TextSender::push`]
    /// refuses more.
    pub max_buffered: usize,
}

impl SenderConfig {
    /// The recommended settings for a `t140` payload type, sent inside
    /// `red` with two redundant generations, a 300 ms interval and the
    /// default `cps` of 30.
    #[must_use]
    pub const fn new(t140_payload_type: u8, red_payload_type: u8) -> Self {
        Self {
            t140_payload_type,
            redundancy: Some(Redundancy {
                payload_type: red_payload_type,
                generations: DEFAULT_GENERATIONS,
            }),
            interval: DEFAULT_INTERVAL,
            cps: Some(DEFAULT_CPS),
            send_bom: true,
            max_buffered: DEFAULT_MAX_BUFFERED,
        }
    }

    fn check(&self) -> Result<(), ConfigError> {
        check_payload_types(self.t140_payload_type, self.redundancy)?;
        if self.interval < MIN_INTERVAL {
            return Err(ConfigError::IntervalTooShort(self.interval));
        }
        if let Some(red) = self.redundancy {
            // the oldest copy has to be reachable with a fourteen-bit offset
            let reach = self.interval.as_millis() * u128::from(red.generations);
            if reach > u128::from(MAX_TIMESTAMP_OFFSET) {
                return Err(ConfigError::RedundancyReach(red.generations));
            }
        }
        if self.cps == Some(0) {
            return Err(ConfigError::ZeroCps);
        }
        Ok(())
    }
}

/// One packet ready to go: its header and its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextPacket {
    /// The header, the sender's SSRC included.
    pub header: RtpHeader,
    /// A `red` payload, or a bare T140block when there is no redundancy.
    pub payload: Vec<u8>,
}

impl TextPacket {
    /// The whole datagram.
    ///
    /// # Errors
    /// [`BuildError`] for a header the wire format cannot hold.
    pub fn to_datagram(&self) -> Result<Vec<u8>, BuildError> {
        let builder = PacketBuilder::new(self.header, &self.payload);
        let mut out = vec![0; builder.encoded_len()];
        let written = builder.write(&mut out)?;
        out.truncate(written);
        Ok(out)
    }
}

/// Text refused because the send buffer is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferFull {
    /// Characters the refused text would have added.
    pub offered: usize,
    /// Room left.
    pub room: usize,
}

impl fmt::Display for BufferFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} characters offered, room for {}",
            self.offered, self.room
        )
    }
}

impl core::error::Error for BufferFull {}

/// A block already sent, kept to be sent again as redundancy.
#[derive(Clone, Debug)]
struct Sent {
    timestamp: u32,
    data: Vec<u8>,
}

/// The sending half of an RFC 4103 text stream.
///
/// Sans-I/O: [`push`](Self::push) takes typed text, [`poll`](Self::poll)
/// is called with the current time whenever [`next_poll`](Self::next_poll)
/// says, and hands back a packet when one is due.
#[derive(Clone, Debug)]
pub struct TextSender {
    config: SenderConfig,
    ssrc: u32,
    sequence: u16,
    timestamp_base: u32,
    buffer: VecDeque<char>,
    /// A CR ended the last push; an LF opening the next one belongs to it.
    after_cr: bool,
    bom_owed: bool,
    history: VecDeque<Sent>,
    /// Empty-primary packets still owed so the last text is sent once per
    /// redundant generation.
    owed: u8,
    /// When the last transmission opportunity was taken, sent or not.
    last_tick: Option<Duration>,
    /// When a packet was last actually sent.
    last_sent: Option<Duration>,
    /// Rate credit in thousandths of a character.
    credit: u64,
    credit_at: Option<Duration>,
}

impl TextSender {
    /// A sender with `ssrc`, whose first packet carries `first_sequence`,
    /// and whose timestamps are `timestamp_base` plus the time given to
    /// [`poll`](Self::poll) in milliseconds.
    ///
    /// # Errors
    /// [`ConfigError`] naming what in `config` the RFCs do not allow.
    pub fn new(
        config: SenderConfig,
        ssrc: u32,
        first_sequence: u16,
        timestamp_base: u32,
    ) -> Result<Self, ConfigError> {
        config.check()?;
        Ok(Self {
            config,
            ssrc,
            sequence: first_sequence,
            timestamp_base,
            buffer: VecDeque::new(),
            after_cr: false,
            bom_owed: config.send_bom,
            history: VecDeque::new(),
            owed: 0,
            last_tick: None,
            last_sent: None,
            credit: Self::credit_cap(config),
            credit_at: None,
        })
    }

    /// The configuration this sender was built with.
    #[must_use]
    pub const fn config(&self) -> &SenderConfig {
        &self.config
    }

    /// Send under `config` from the next packet on, as a later offer and
    /// answer agreed: other payload type numbers, redundancy taken up or
    /// dropped, another `cps`. What is typed and not yet sent stays queued,
    /// and the source and its numbering carry on. Redundant copies kept for
    /// a generation `config` no longer has are dropped, and the byte order
    /// mark is not owed again.
    ///
    /// # Errors
    /// [`ConfigError`] naming what in `config` the RFCs do not allow; the
    /// sender is left as it was.
    pub fn reconfigure(&mut self, config: SenderConfig) -> Result<(), ConfigError> {
        config.check()?;
        self.config = config;
        let generations = self.generations();
        while self.history.len() > usize::from(generations) {
            self.history.pop_front();
        }
        self.owed = self.owed.min(generations);
        self.credit = self.credit.min(Self::credit_cap(config));
        Ok(())
    }

    /// Characters typed and not yet sent.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Queue typed text. A CR LF, a lone CR or a lone LF becomes the LINE
    /// SEPARATOR T.140 uses for a new line; BACKSPACE, U+0008, is sent as it
    /// is and erases at the far end.
    ///
    /// # Errors
    /// [`BufferFull`] when the text does not fit; none of it is queued then.
    pub fn push(&mut self, text: &str) -> Result<(), BufferFull> {
        let mut staged = Vec::with_capacity(text.len());
        let mut after_cr = self.after_cr;
        for c in text.chars() {
            match c {
                '\n' if after_cr => {}
                '\r' | '\n' => staged.push(LINE_SEPARATOR),
                c => staged.push(c),
            }
            after_cr = c == '\r';
        }
        let room = self.config.max_buffered.saturating_sub(self.buffer.len());
        if staged.len() > room {
            return Err(BufferFull {
                offered: staged.len(),
                room,
            });
        }
        self.after_cr = after_cr;
        self.buffer.extend(staged);
        Ok(())
    }

    /// Erase the character before the cursor at the far end.
    ///
    /// # Errors
    /// [`BufferFull`] when there is no room for the BACKSPACE.
    pub fn erase(&mut self) -> Result<(), BufferFull> {
        self.push("\u{8}")
    }

    /// Start a new line at the far end.
    ///
    /// # Errors
    /// [`BufferFull`] when there is no room for the LINE SEPARATOR.
    pub fn new_line(&mut self) -> Result<(), BufferFull> {
        self.push("\u{2028}")
    }

    /// When [`poll`](Self::poll) next has something to do: `None` while
    /// idle, with nothing typed and no redundancy owed. An opportunity too
    /// far off for the clock to hold is [`Duration::MAX`].
    #[must_use]
    pub fn next_poll(&self) -> Option<Duration> {
        if self.buffer.is_empty() && self.owed == 0 {
            return None;
        }
        Some(self.last_tick.map_or(Duration::ZERO, |tick| {
            tick.saturating_add(self.config.interval)
        }))
    }

    /// Take the transmission opportunity due at `now`, if one is: the
    /// packet to send, or `None` when it is not yet time, when there is
    /// nothing to send, or when the `cps` limit holds every waiting
    /// character back and no redundancy is owed.
    pub fn poll(&mut self, now: Duration) -> Option<TextPacket> {
        let due = self.next_poll()?;
        if now < due {
            return None;
        }
        self.refill(now);
        self.last_tick = Some(now);

        let block = self.take_block();
        if block.is_empty() && self.owed == 0 {
            // held back by the rate limit with every copy already sent:
            // silence, and the next packet opens a new burst
            return None;
        }
        let timestamp = self
            .timestamp_base
            .wrapping_add(clock_ticks(CLOCK_RATE, now));
        let payload = self.payload(&block, timestamp);
        let marker = self
            .last_sent
            .is_none_or(|sent| now >= sent.saturating_add(self.config.interval.saturating_mul(2)));
        let header = RtpHeader {
            marker,
            payload_type: self
                .config
                .redundancy
                .map_or(self.config.t140_payload_type, |red| red.payload_type),
            sequence: self.sequence,
            timestamp,
            ssrc: self.ssrc,
        };
        self.sequence = self.sequence.wrapping_add(1);
        self.last_sent = Some(now);

        let generations = self.generations();
        if block.is_empty() {
            self.owed = self.owed.saturating_sub(1);
        } else {
            self.owed = generations;
        }
        if generations > 0 {
            self.history.push_back(Sent {
                timestamp,
                data: block,
            });
            while self.history.len() > usize::from(generations) {
                self.history.pop_front();
            }
        }
        Some(TextPacket { header, payload })
    }

    fn generations(&self) -> u8 {
        self.config.redundancy.map_or(0, |red| red.generations)
    }

    /// Rate credit in thousandths of a character, capped at one interval's
    /// worth so a pause never saves up into a burst.
    fn credit_cap(config: SenderConfig) -> u64 {
        config.cps.map_or(u64::MAX, |cps| {
            let millis = u64::try_from(config.interval.as_millis()).unwrap_or(u64::MAX);
            u64::from(cps).saturating_mul(millis).max(1000)
        })
    }

    fn refill(&mut self, now: Duration) {
        let Some(cps) = self.config.cps else {
            return;
        };
        if let Some(then) = self.credit_at {
            let elapsed = u64::try_from(now.saturating_sub(then).as_millis()).unwrap_or(u64::MAX);
            self.credit = self
                .credit
                .saturating_add(u64::from(cps).saturating_mul(elapsed))
                .min(Self::credit_cap(self.config));
        }
        self.credit_at = Some(now);
    }

    /// The next T140block: as many waiting characters as the rate limit and
    /// the ten-bit block length allow, whole characters only.
    fn take_block(&mut self) -> Vec<u8> {
        let mut block = Vec::new();
        if self.buffer.is_empty() {
            return block;
        }
        let mut allowed = if self.config.cps.is_some() {
            usize::try_from(self.credit / 1000).unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };
        if allowed == 0 {
            return block;
        }
        if self.bom_owed {
            self.bom_owed = false;
            let mut utf8 = [0; 4];
            block.extend_from_slice(BOM.encode_utf8(&mut utf8).as_bytes());
        }
        let mut taken = 0_u64;
        while allowed > 0 {
            let Some(&c) = self.buffer.front() else {
                break;
            };
            if block.len() + c.len_utf8() > MAX_BLOCK_LEN {
                break;
            }
            let mut utf8 = [0; 4];
            block.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            self.buffer.pop_front();
            allowed -= 1;
            taken += 1;
        }
        if self.config.cps.is_some() {
            self.credit = self.credit.saturating_sub(taken * 1000);
        }
        block
    }

    fn payload(&self, block: &[u8], timestamp: u32) -> Vec<u8> {
        let Some(red) = self.config.redundancy else {
            return block.to_vec();
        };
        let mut redundant = Vec::with_capacity(usize::from(red.generations));
        // RFC 4103 §4.2: every block sent as primary within the generations,
        // oldest first, and nothing else: "Each redundant data block MUST
        // contain the same data as a T140block previously transmitted as
        // primary data", so the first packets of a session carry fewer
        // generations rather than blocks that were never sent, which §5.3
        // has a receiver read as empty ones
        // the empty blocks that closed the last burst go too, as §5.2 asks
        // ("Any empty T140block sent as primary data MUST be included as
        // redundant T140blocks in subsequent packets"), unless they are too
        // old for the fourteen-bit offset, which §4.1 forbids sending; the
        // history is in age order, so what is left out is always the oldest
        for sent in &self.history {
            let Some(timestamp_offset) = u16::try_from(timestamp.wrapping_sub(sent.timestamp))
                .ok()
                .filter(|offset| *offset <= MAX_TIMESTAMP_OFFSET)
            else {
                continue;
            };
            redundant.push(RedundantBlock {
                payload_type: self.config.t140_payload_type,
                timestamp_offset,
                data: &sent.data,
            });
        }
        let mut out = Vec::new();
        // every field was checked when the configuration was, and blocks
        // are cut to fit the length field
        if write_red(&redundant, self.config.t140_payload_type, block, &mut out).is_err() {
            out.clear();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{BufferFull, SenderConfig, TextPacket, TextSender};
    use crate::rtt::red::{MAX_BLOCK_LEN, RedPayload};
    use crate::rtt::{ConfigError, Redundancy};
    use crate::wire::RtpPacket;
    use core::time::Duration;

    const T140: u8 = 98;
    const RED: u8 = 100;
    const SSRC: u32 = 0x1122_3344;

    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    fn sender(config: SenderConfig) -> TextSender {
        TextSender::new(config, SSRC, 1000, 5000).unwrap()
    }

    /// (offset, block) for each redundant generation, then the primary.
    fn blocks(packet: &TextPacket) -> (Vec<(u16, Vec<u8>)>, Vec<u8>) {
        let red = RedPayload::parse(&packet.payload).unwrap();
        let redundant = red
            .redundant()
            .map(|block| {
                assert_eq!(block.payload_type, T140);
                (block.timestamp_offset, block.data.to_vec())
            })
            .collect();
        assert_eq!(red.primary_payload_type(), T140);
        (redundant, red.primary().to_vec())
    }

    #[test]
    fn the_first_packet_opens_with_the_marker_and_the_byte_order_mark() {
        let mut tx = sender(SenderConfig::new(T140, RED));
        tx.push("hi").unwrap();
        assert_eq!(tx.next_poll(), Some(Duration::ZERO));
        let packet = tx.poll(ms(20)).unwrap();
        assert!(packet.header.marker);
        assert_eq!(packet.header.payload_type, RED);
        assert_eq!(packet.header.sequence, 1000);
        assert_eq!(packet.header.ssrc, SSRC);
        // the 1000 Hz clock: the base plus the time in milliseconds
        assert_eq!(packet.header.timestamp, 5020);
        let (redundant, primary) = blocks(&packet);
        // nothing was sent before it, and a redundant block is only ever a
        // copy of one that was (RFC 4103 §4.2)
        assert!(redundant.is_empty());
        assert_eq!(primary, "\u{FEFF}hi".as_bytes());
    }

    #[test]
    fn a_sender_reconfigured_keeps_its_text_and_numbering_under_the_new_numbers() {
        let mut tx = sender(SenderConfig::new(T140, RED));
        tx.push("a").unwrap();
        let first = tx.poll(ms(0)).unwrap();
        tx.push("b").unwrap();
        // renumbered, and redundancy dropped
        let mut bare = SenderConfig::new(96, 97);
        bare.redundancy = None;
        tx.reconfigure(bare).unwrap();
        let next = tx.poll(ms(300)).unwrap();
        assert_eq!(
            next.header.payload_type, 96,
            "bare t140 under its new number"
        );
        assert_eq!(next.header.ssrc, SSRC);
        assert_eq!(
            next.header.sequence,
            first.header.sequence.wrapping_add(1),
            "the numbering carries on"
        );
        assert_eq!(next.payload, b"b", "what was queued is sent, alone");
        assert_eq!(tx.next_poll(), None, "no redundancy owed any more");
        // a configuration the RFCs forbid leaves the sender as it was
        assert!(tx.reconfigure(SenderConfig::new(96, 96)).is_err());
        assert_eq!(tx.config().t140_payload_type, 96);
        assert_eq!(tx.config().redundancy, None);
    }

    #[test]
    fn each_block_goes_out_three_times_then_the_sender_falls_silent() {
        let mut tx = sender(SenderConfig::new(T140, RED));
        tx.push("a").unwrap();
        let p1 = tx.poll(ms(0)).unwrap();
        tx.push("b").unwrap();
        assert_eq!(tx.next_poll(), Some(ms(300)));
        assert_eq!(tx.poll(ms(299)), None);
        let p2 = tx.poll(ms(300)).unwrap();
        let p3 = tx.poll(ms(600)).unwrap();
        let p4 = tx.poll(ms(900)).unwrap();
        assert_eq!(tx.next_poll(), None);
        assert_eq!(tx.poll(ms(1200)), None);

        let a = "\u{FEFF}a".as_bytes().to_vec();
        let b = b"b".to_vec();
        assert_eq!(blocks(&p1).1, a);
        assert_eq!(blocks(&p2), (vec![(300, a.clone())], b.clone()));
        // no new text: an empty primary, the copies still owed
        assert_eq!(blocks(&p3), (vec![(600, a), (300, b.clone())], vec![]));
        assert_eq!(blocks(&p4), (vec![(600, b), (300, vec![])], vec![]));
        let sequences: Vec<u16> = [&p1, &p2, &p3, &p4]
            .iter()
            .map(|p| p.header.sequence)
            .collect();
        assert_eq!(sequences, [1000, 1001, 1002, 1003]);
        assert!(p1.header.marker);
        assert!(![&p2, &p3, &p4].iter().any(|p| p.header.marker));
    }

    #[test]
    fn the_first_packet_after_a_silence_carries_the_marker() {
        let mut tx = sender(SenderConfig::new(T140, RED));
        tx.push("a").unwrap();
        let mut last = None;
        let mut now = ms(0);
        while let Some(due) = tx.next_poll() {
            now = now.max(due);
            last = tx.poll(now);
        }
        let last = last.unwrap();
        tx.push("b").unwrap();
        let resumed = tx.poll(now + ms(5000)).unwrap();
        assert!(resumed.header.marker);
        assert_eq!(
            resumed.header.sequence,
            last.header.sequence.wrapping_add(1)
        );
        // the empty blocks that closed the burst, 5300 and 5000 ms back, are
        // still within reach of the offset field, and RFC 4103 §5.2 has
        // them go as copies like any other primary
        assert_eq!(
            blocks(&resumed),
            (vec![(5300, vec![]), (5000, vec![])], b"b".to_vec())
        );
        // and only the first opens the burst
        tx.push("c").unwrap();
        assert!(!tx.poll(now + ms(5300)).unwrap().header.marker);
    }

    #[test]
    fn typing_on_without_a_pause_never_sets_the_marker_again() {
        let mut tx = sender(SenderConfig::new(T140, RED));
        let mut markers = 0;
        for tick in 0..20 {
            tx.push("x").unwrap();
            if tx.poll(ms(tick * 300)).unwrap().header.marker {
                markers += 1;
            }
        }
        assert_eq!(markers, 1);
    }

    #[test]
    fn without_redundancy_blocks_go_bare_and_nothing_is_sent_after_them() {
        let config = SenderConfig {
            redundancy: None,
            send_bom: false,
            ..SenderConfig::new(T140, RED)
        };
        let mut tx = sender(config);
        tx.push("ok").unwrap();
        let packet = tx.poll(ms(0)).unwrap();
        assert_eq!(packet.header.payload_type, T140);
        assert_eq!(packet.payload, b"ok");
        assert_eq!(tx.next_poll(), None);
    }

    #[test]
    fn the_cps_limit_holds_characters_back() {
        let config = SenderConfig {
            cps: Some(10),
            send_bom: false,
            ..SenderConfig::new(T140, RED)
        };
        let mut tx = sender(config);
        tx.push(&"z".repeat(40)).unwrap();
        let mut sent = Vec::new();
        for tick in 0..10 {
            let now = ms(tick * 300);
            let packet = tx.poll(now).unwrap();
            sent.push(blocks(&packet).1.len());
        }
        // ten a second at 300 ms is three a packet, never more
        assert_eq!(sent, [3; 10]);
        assert_eq!(tx.buffered(), 10);
    }

    #[test]
    fn a_slow_cps_skips_opportunities_and_resumes_with_the_marker() {
        let config = SenderConfig {
            cps: Some(1),
            redundancy: None,
            send_bom: false,
            ..SenderConfig::new(T140, RED)
        };
        let mut tx = sender(config);
        tx.push("abc").unwrap();
        let mut sent = Vec::new();
        for tick in 0..10 {
            let now = ms(tick * 300);
            if let Some(packet) = tx.poll(now) {
                sent.push((tick, packet.payload.clone(), packet.header.marker));
            }
        }
        // one character a second: at 0, at 1200 (the first tick a whole
        // character's credit is back), at 2400
        assert_eq!(
            sent,
            [
                (0, b"a".to_vec(), true),
                (4, b"b".to_vec(), true),
                (8, b"c".to_vec(), true),
            ]
        );
    }

    #[test]
    fn an_interval_too_long_to_add_to_the_clock_saturates() {
        let config = |interval| SenderConfig {
            redundancy: None,
            send_bom: false,
            cps: None,
            interval,
            ..SenderConfig::new(T140, RED)
        };
        // the next opportunity lies past what the clock holds
        let mut tx = sender(config(Duration::MAX));
        tx.push("a").unwrap();
        assert!(tx.poll(ms(1)).is_some());
        tx.push("b").unwrap();
        assert_eq!(tx.next_poll(), Some(Duration::MAX));
        assert_eq!(tx.poll(ms(2)), None);
        // the next opportunity fits, twice the interval does not
        let long = Duration::from_secs(u64::MAX / 2 + 1);
        let mut tx = sender(config(long));
        tx.push("a").unwrap();
        assert!(tx.poll(ms(0)).is_some());
        tx.push("b").unwrap();
        assert_eq!(tx.next_poll(), Some(long));
        assert!(!tx.poll(long).unwrap().header.marker);
    }

    #[test]
    fn without_a_cps_limit_blocks_are_cut_to_the_length_field() {
        let config = SenderConfig {
            cps: None,
            send_bom: false,
            max_buffered: 4000,
            ..SenderConfig::new(T140, RED)
        };
        let mut tx = sender(config);
        // three octets each: 341 of them fill 1023
        tx.push(&"€".repeat(400)).unwrap();
        let first = blocks(&tx.poll(ms(0)).unwrap()).1;
        assert_eq!(first.len(), MAX_BLOCK_LEN);
        let second = blocks(&tx.poll(ms(300)).unwrap()).1;
        assert_eq!(second.len(), 59 * 3);
        assert!(core::str::from_utf8(&first).is_ok());
    }

    #[test]
    fn new_lines_become_line_separators() {
        let config = SenderConfig {
            redundancy: None,
            send_bom: false,
            cps: None,
            ..SenderConfig::new(T140, RED)
        };
        let mut tx = sender(config);
        tx.push("a\r\nb\nc\r").unwrap();
        // the LF that ends a CR LF may arrive in the next push
        tx.push("\nd\re").unwrap();
        tx.new_line().unwrap();
        tx.erase().unwrap();
        let packet = tx.poll(ms(0)).unwrap();
        assert_eq!(
            packet.payload,
            "a\u{2028}b\u{2028}c\u{2028}d\u{2028}e\u{2028}\u{8}".as_bytes()
        );
    }

    #[test]
    fn a_full_buffer_refuses_the_whole_push() {
        let config = SenderConfig {
            max_buffered: 4,
            ..SenderConfig::new(T140, RED)
        };
        let mut tx = sender(config);
        tx.push("abc").unwrap();
        assert_eq!(
            tx.push("de"),
            Err(BufferFull {
                offered: 2,
                room: 1
            })
        );
        assert_eq!(tx.buffered(), 3);
        tx.push("d").unwrap();
        assert!(tx.erase().is_err());
    }

    #[test]
    fn configurations_the_rfcs_do_not_allow_are_refused() {
        let good = SenderConfig::new(T140, RED);
        let refuse = |config| TextSender::new(config, SSRC, 0, 0).err();
        assert_eq!(
            refuse(SenderConfig {
                interval: Duration::from_millis(99),
                ..good
            }),
            Some(ConfigError::IntervalTooShort(Duration::from_millis(99)))
        );
        assert!(
            TextSender::new(
                SenderConfig {
                    interval: Duration::from_millis(100),
                    ..good
                },
                SSRC,
                0,
                0
            )
            .is_ok()
        );
        assert_eq!(
            refuse(SenderConfig {
                cps: Some(0),
                ..good
            }),
            Some(ConfigError::ZeroCps)
        );
        assert_eq!(
            refuse(SenderConfig::new(T140, T140)),
            Some(ConfigError::SamePayloadType(T140))
        );
        assert_eq!(
            refuse(SenderConfig::new(128, RED)),
            Some(ConfigError::PayloadType(128))
        );
        // 55 copies 300 ms apart reach back 16.5 s, past a fourteen-bit offset
        let deep = |generations| SenderConfig {
            redundancy: Some(Redundancy {
                payload_type: RED,
                generations,
            }),
            ..good
        };
        assert_eq!(refuse(deep(55)), Some(ConfigError::RedundancyReach(55)));
        assert!(TextSender::new(deep(54), SSRC, 0, 0).is_ok());
    }

    #[test]
    fn a_copy_exactly_as_far_back_as_the_offset_field_reaches_is_allowed() {
        let one = |interval| SenderConfig {
            interval: Duration::from_millis(interval),
            redundancy: Some(Redundancy {
                payload_type: RED,
                generations: 1,
            }),
            ..SenderConfig::new(T140, RED)
        };
        assert!(TextSender::new(one(16_383), SSRC, 0, 0).is_ok());
        assert_eq!(
            TextSender::new(one(16_384), SSRC, 0, 0).err(),
            Some(ConfigError::RedundancyReach(1))
        );
    }

    #[test]
    fn a_copy_too_old_for_the_offset_field_is_left_out() {
        let config = SenderConfig {
            send_bom: false,
            ..SenderConfig::new(T140, RED)
        };
        let mut tx = sender(config);
        tx.push("a").unwrap();
        tx.poll(ms(0)).unwrap();
        tx.push("b").unwrap();
        // polled far later than asked: "a" is 20 s back, past the 16383 ms
        // RFC 4103 §4.1 forbids, so it is not sent at all
        let late = tx.poll(ms(20_000)).unwrap();
        assert_eq!(blocks(&late), (vec![], b"b".to_vec()));
        // and the next packet carries the one generation that exists
        tx.push("c").unwrap();
        let next = tx.poll(ms(20_300)).unwrap();
        assert_eq!(blocks(&next), (vec![(300, b"b".to_vec())], b"c".to_vec()));
    }

    #[test]
    fn a_packet_is_a_datagram_rtp_can_read() {
        let mut tx = sender(SenderConfig::new(T140, RED));
        tx.push("x").unwrap();
        let packet = tx.poll(ms(0)).unwrap();
        let datagram = packet.to_datagram().unwrap();
        let parsed = RtpPacket::parse(&datagram).unwrap();
        assert_eq!(parsed.header(), packet.header);
        assert_eq!(parsed.payload(), packet.payload.as_slice());
    }
}
