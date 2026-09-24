// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Putting packets back in order before anyone listens to them, and deciding
//! how long to wait for them.
//!
//! A network delivers audio at its own pace and sometimes in its own order.
//! The buffer is what stands between that and a device that wants one frame
//! every twenty milliseconds, whatever happened on the way. A packet goes into
//! the slot its sequence number names, the consumer takes them out in order,
//! and reordering inside the window is ordinary rather than an error.
//!
//! How long to wait is the whole question. A delay chosen once is wrong twice:
//! too short on the mobile leg and too long on the wired one, and it cannot be
//! right on a path whose behaviour changes during the call. So the buffer
//! watches when packets actually arrive, and aims at the delay that would have
//! covered all but the slowest few of them. It grows the moment a burst says it
//! must, and gives the delay back a frame at a time over tens of seconds, so
//! that one bad second does not cost a minute of latency.
//!
//! Changing the delay is audible if it is done while someone is talking, and
//! inaudible if it is done in a pause. So the caller says which of the two this
//! frame is — the detector lives with the codec, not here — and the buffer
//! moves only in the pauses: it drops a frame to shorten the delay, or asks for
//! one more to lengthen it. During a talk spurt it holds still and accepts
//! being wrong until the next pause, which is the trade the ear prefers.
//!
//! No signal processing happens here. When a slot comes due empty the buffer
//! says so and the codec layer conceals; when a pause is being stretched the
//! buffer says that too, and something upstream repeats a frame or plays
//! comfort noise. This crate never touches a sample.
//!
//! The ring is fixed, which is what bounds the whole thing: a consumer that
//! stops pulling does not turn into unbounded memory, it turns into a counter
//! going up. The window is exactly as wide as the ring, so a sequence number in
//! the window names one slot and only one, which makes a duplicate a single
//! test.
//!
//! The slot a number names is found by its distance from the window's base,
//! not by the number itself modulo the ring. That is not a stylistic choice:
//! sequence numbers wrap at sixty-five thousand and a ring of, say, ten slots
//! does not divide that, so the raw modulus stops being one-to-one exactly
//! when the window straddles the wrap — and two live packets would then land
//! in the same slot, one of them read as a duplicate of the other. The
//! distance is computed with wrapping arithmetic and is smaller than the
//! depth by the time it is used, so it is one-to-one for every depth.

use std::time::Duration;

use crate::voip_metrics::{BurstGapMetrics, GminTracker, PacketOutcome};
use crate::wire::RtpPacket;

/// The widest window that makes sense: at twenty milliseconds a packet, ten
/// seconds of audio, which is already far past the point where a call is worth
/// listening to. It is the ring's hard bound, not a delay target — the target
/// is chosen from what the network does and can never reach this.
pub const MAX_DEPTH: u16 = 512;

/// Half the sequence number space. A step of at least this much forward is
/// read as a step backward, which is the only way to tell the two apart in
/// sixteen bits that wrap.
const BEHIND: u16 = 1 << 15;

/// Half the timestamp space, for the same reason.
const HALF_CLOCK: u32 = 1 << 31;

/// How many packet-times of arrival delay the distribution is kept in. Sixty
/// four frames is over a second of lateness; a packet later than that is not
/// going to be played whatever the buffer does, so it only has to fall in the
/// last bucket rather than in a bucket of its own.
const DELAY_BUCKETS: usize = 64;

/// Where the target sits in the distribution of recent arrival delays, as a
/// percentage. Two packets in a hundred are allowed to arrive too late to be
/// played: the tail of a wide-area path has no end, so buying the last two
/// costs delay out of all proportion to the concealment it saves.
const TARGET_PERCENTILE: u64 = 98;

/// Packets between halvings of the delay distribution. At fifty packets a
/// second this is about two and a half seconds, which is what makes the
/// distribution recent rather than cumulative.
const DECAY_INTERVAL: u32 = 128;

/// Packets that must arrive between one step of shrink and the next. Growth is
/// immediate and shrink is this slow on purpose: being a frame too long is
/// inaudible, being a frame too short is a gap.
const SHRINK_HOLD: u32 = 150;

/// Packets each half of the fastest-arrival window covers. The fastest recent
/// arrival is what delay is measured from, and it has to be recent: the sender
/// and receiver clocks disagree by a few parts per million, so a minimum kept
/// for the whole call slowly stops describing the path at all.
const BASE_WINDOW: u32 = 512;

/// The fewest packets a pause leaves queued ahead of the playout point, the
/// one about to be played included: one in hand, beyond the target of one a
/// clean path gets.
///
/// The earpiece and the far end run on two clocks, and which of them is the
/// faster is not known until a frame has slipped. When the earpiece is the
/// slow one the slip shows as a packet more than the target, and a pause
/// drops it. When it is the fast one the slip shows as a packet fewer — and
/// at a target of one, a packet fewer is nothing at all, so the first sign
/// of it is the buffer running dry and a frame of silence played wherever
/// that falls, a word included. Stretching when the queue is below its
/// target cannot help there, since below one is empty. Keeping one frame in
/// hand is what lets a fast earpiece's slip be seen before it is a gap: the
/// queue falls to one, and the next pause stretches it back to two. The
/// frame in hand is the floor the pause's dead band sits on, so a clean
/// path's delay is two or three frames where it was one or two. That frame
/// is bought in a pause where nobody hears it being bought, and being a
/// frame long is inaudible where being a frame short is a gap.
const IN_HAND: u16 = 2;

/// Times the same packet length must repeat before it is believed over the one
/// the negotiation promised.
const SPAN_STREAK: u8 = 3;

/// `Gmin` for this buffer's burst/gap classification (RFC 3611 §4.7.2): "A
/// Gmin value of 16 is RECOMMENDED, as it results in gap characteristics
/// that correspond to good quality ... and hence differentiates nicely
/// between good and poor quality periods."
const RECOMMENDED_GMIN: u8 = 16;

/// Sixty-four bit words of recent playout history, one bit a frame.
const LOSS_WORDS: usize = 8;

/// Frames the loss rate is measured over: ten seconds at twenty milliseconds.
const LOSS_WINDOW: usize = LOSS_WORDS * 64;

/// The same, as the counter's own type.
const LOSS_CAPACITY: u16 = 512;

/// Whether the frame about to be played is speech or a pause.
///
/// The buffer only changes its delay in a pause, so this decides when it is
/// allowed to move. The detector that produces it works on decoded audio and
/// lives with the codec, which means what a caller has to hand is the verdict
/// on the frame it decoded last. That is the right answer nearly always, since
/// neither speech nor silence lasts one frame, and the cost of the exception is
/// one adjustment made a frame early or late.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    /// Someone is talking. The delay is left exactly where it is.
    Speech,
    /// A pause. Adjustments happen here and nowhere else.
    Silence,
}

/// How the buffer is sized and how far it may move.
///
/// Depth is the ring, and therefore the hard bound on memory and on how much
/// reordering can be absorbed. The three delays are the range the adaptation
/// works inside: it starts at `start_delay` and afterwards chooses for itself
/// between `min_delay` and `max_delay`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferConfig {
    /// Ring size in packets, clamped to [`MAX_DEPTH`].
    pub depth: u16,
    /// Timestamp ticks one packet covers, from the negotiated packet time —
    /// 160 for twenty milliseconds of eight kilohertz audio. It is a seed: a
    /// peer that agreed to twenty milliseconds and sends thirty is common
    /// enough that the buffer takes the real figure from the stream.
    pub packet_samples: u32,
    /// The shortest delay the buffer may settle at, in packets.
    pub min_delay: u16,
    /// Where it starts, before any arrival has been timed.
    pub start_delay: u16,
    /// The longest delay it may choose. Clamped below `depth`, so a window
    /// sitting at its target still has room for a packet that arrives out of
    /// order.
    pub max_delay: u16,
}

impl BufferConfig {
    /// A buffer for packets of `packet_samples` ticks each, sized for a call
    /// rather than for a laboratory: two seconds of ring, a start of two
    /// packets, and a ceiling around half a second.
    #[must_use]
    pub const fn new(packet_samples: u32) -> Self {
        Self {
            depth: 100,
            packet_samples,
            min_delay: 1,
            start_delay: 2,
            max_delay: 25,
        }
    }
}

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
    /// Behind the playout point: whatever it carries, its turn has passed. Its
    /// arrival time is still read, since a packet that missed its turn is the
    /// clearest thing the network ever says about how long the wait should be.
    Late,
}

/// What came out of the buffer. Every variant is one frame of the device's
/// time, so a caller that pulls at the frame rate always has something to play.
#[derive(Debug)]
pub enum Pull<'a> {
    /// The next packet in order.
    Packet(Frame<'a>),
    /// Its sequence number came due and nothing was in the slot. Later packets
    /// are waiting, so this one is not coming: conceal it.
    Conceal,
    /// The pause is being made one frame longer, on purpose, to lengthen the
    /// delay. Nothing was consumed; repeat the last frame or play comfort
    /// noise.
    Stretch,
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
    /// (RFC 3551 §4.1).
    pub marker: bool,
    /// The payload.
    pub payload: &'a [u8],
}

/// Everything a caller needs to answer "why did that call sound bad".
///
/// The counters are cumulative for the life of the stream and are never reset
/// by anything the buffer does on its own; the three delays and the loss rate
/// describe this moment and move as the call goes on.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Quality {
    /// Packets taken in and held for playout.
    pub received: u64,
    /// Sequence numbers that came due with nothing in them, plus the ones the
    /// window moved past unfilled.
    pub lost: u64,
    /// Packets that arrived behind the playout point.
    pub discarded_late: u64,
    /// Packets thrown out of the window before they could be played: pushed
    /// out by newer audio because the consumer stopped pulling, belonging to
    /// a stream that restarted underneath them, or left further back than the
    /// target when playout started.
    pub discarded_overflow: u64,
    /// Packets whose sequence number was already held.
    pub duplicates: u64,
    /// Packets accepted after a higher sequence number had already arrived.
    pub reordered: u64,
    /// Frames dropped in a pause to bring the delay down. Deliberate, and
    /// inaudible when the pause is real.
    pub shrunk: u64,
    /// Frames the caller was asked to invent in a pause to push the delay up.
    pub stretched: u64,
    /// How far behind the newest packet received the playout point currently
    /// is: the delay the far end's voice is actually suffering.
    pub delay: Duration,
    /// What the buffer is aiming at, from the arrival times it has seen.
    pub target_delay: Duration,
    /// Interarrival jitter, the smoothed mean deviation of transit time
    /// (RFC 3550 §6.4.1). Measured here from the buffer's own arrivals, so it
    /// is available on a session with RTCP switched off.
    pub jitter: Duration,
    /// Frames concealed as a fraction of frames played, over the last ten
    /// seconds or so. The cumulative counters say what the call has cost so
    /// far; this says whether it is bad right now.
    pub loss_rate: f32,
}

/// The cumulative half of [`Quality`], which is the half the buffer keeps.
#[derive(Clone, Copy, Debug, Default)]
struct Counters {
    received: u64,
    lost: u64,
    discarded_late: u64,
    discarded_overflow: u64,
    duplicates: u64,
    reordered: u64,
    shrunk: u64,
    stretched: u64,
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

/// Whether `a` is at or before `b` on a clock that wraps.
const fn at_or_before(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < HALF_CLOCK
}

/// `now` as a wrapping 32-bit reading of a clock ticking at `clock_rate`, the
/// same units an RTP timestamp is in. Wraps the way any RTP timestamp does,
/// rather than saturating the way [`crate::RtpSession::ticks`] deliberately
/// does for its own, unrelated purpose of sizing one packet's worth of
/// samples.
pub(crate) fn clock_ticks(clock_rate: u32, now: Duration) -> u32 {
    let ticks = now.as_nanos().saturating_mul(u128::from(clock_rate)) / 1_000_000_000;
    u32::try_from(ticks & 0xFFFF_FFFF).unwrap_or(0)
}

/// How long `ticks` of a `clock_rate` clock last.
fn ticks_to_duration(clock_rate: u32, ticks: u32) -> Duration {
    if clock_rate == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(u64::from(ticks) * 1_000_000_000 / u64::from(clock_rate))
}

/// What the arrival times have said, and what has been concluded from them.
#[derive(Debug)]
struct Timing {
    clock_rate: u32,
    /// Ticks one packet covers, as currently believed.
    span: u32,
    candidate: u32,
    streak: u8,
    last_sequence: u16,
    last_timestamp: u32,
    seen: bool,
    transit: Option<u32>,
    /// The jitter estimate scaled by sixteen, so §6.4.1's 1/16 gain is exact
    /// rather than rounded away at every update.
    jitter_scaled: u32,
    base_current: Option<u32>,
    base_previous: Option<u32>,
    base_age: u32,
    delays: [u32; DELAY_BUCKETS],
    delay_total: u32,
    since_decay: u32,
    since_shrink: u32,
}

impl Timing {
    fn new(clock_rate: u32, span: u32) -> Self {
        Self {
            clock_rate,
            span,
            candidate: 0,
            streak: 0,
            last_sequence: 0,
            last_timestamp: 0,
            seen: false,
            transit: None,
            jitter_scaled: 0,
            base_current: None,
            base_previous: None,
            base_age: 0,
            delays: [0; DELAY_BUCKETS],
            delay_total: 0,
            since_decay: 0,
            since_shrink: 0,
        }
    }

    /// Take one arrival: what the packet said it was sampled at, when it
    /// turned up, and, for the first packet of a talk spurt, how many ticks
    /// late it may be before its lateness is put down to the sender's clock
    /// rather than to the path.
    fn note(&mut self, sequence: u16, timestamp: u32, arrival: u32, spurt: Option<u32>) {
        self.since_decay = self.since_decay.saturating_add(1);
        self.since_shrink = self.since_shrink.saturating_add(1);
        self.learn_span(sequence, timestamp);

        // transit is the offset between the two clocks plus the path delay.
        // The offset is unknown and constant, so it cancels in everything
        // below and only the path delay is left.
        let transit = arrival.wrapping_sub(timestamp);
        // Constant, that is, while the sender's clock runs. One that stops it
        // through a pause (RFC 3550 §5.1 has the timestamp increase "regardless
        // of whether the block is transmitted in a packet or dropped as
        // silent", and some senders do not) comes back with an offset larger
        // by the whole pause, and every packet after reads as that much late:
        // the target climbs to its ceiling and stays there until the fastest
        // arrival has aged out of both windows. The first packet of a spurt is
        // the one place that is safe to take as a new start, since its own
        // lateness only ever lengthens a pause the sender chose to leave.
        if let Some(allowed) = spurt
            && self.lateness(transit).is_some_and(|late| late > allowed)
        {
            self.rebase();
        }
        if let Some(previous) = self.transit {
            let d = transit.wrapping_sub(previous).cast_signed().unsigned_abs();
            let round_off = self.jitter_scaled.saturating_add(8) >> 4;
            self.jitter_scaled = self
                .jitter_scaled
                .saturating_add(d)
                .saturating_sub(round_off);
        }
        self.transit = Some(transit);

        let relative = self.relative(transit);
        self.record(relative);
    }

    /// How much later than the fastest recent arrival this one was.
    fn relative(&mut self, transit: u32) -> u32 {
        self.base_age = self.base_age.saturating_add(1);
        if self.base_age >= BASE_WINDOW {
            self.base_previous = self.base_current;
            self.base_current = None;
            self.base_age = 0;
        }
        let current = match self.base_current {
            Some(fastest) if at_or_before(fastest, transit) => fastest,
            _ => transit,
        };
        self.base_current = Some(current);
        let base = match self.base_previous {
            Some(older) if at_or_before(older, current) => older,
            _ => current,
        };
        transit.wrapping_sub(base)
    }

    /// How much later than the fastest arrival still remembered `transit` is,
    /// without remembering it: `None` when nothing is remembered yet or it is
    /// faster still.
    fn lateness(&self, transit: u32) -> Option<u32> {
        let fastest = match (self.base_current, self.base_previous) {
            (Some(current), Some(older)) if at_or_before(older, current) => older,
            (Some(current), _) => current,
            (None, older) => older?,
        };
        at_or_before(fastest, transit).then_some(transit.wrapping_sub(fastest))
    }

    /// Forget the fastest arrivals, so the next one is measured from itself.
    const fn rebase(&mut self) {
        self.base_current = None;
        self.base_previous = None;
        self.base_age = 0;
    }

    /// Put one arrival delay in the distribution, and forget older ones.
    fn record(&mut self, relative: u32) {
        let bucket = usize::try_from(relative / self.span.max(1))
            .unwrap_or(DELAY_BUCKETS - 1)
            .min(DELAY_BUCKETS - 1);
        if let Some(count) = self.delays.get_mut(bucket) {
            *count = count.saturating_add(1);
        }
        self.delay_total = self.delay_total.saturating_add(1);

        if self.since_decay >= DECAY_INTERVAL {
            self.since_decay = 0;
            let mut total = 0_u32;
            for count in &mut self.delays {
                *count >>= 1;
                total = total.saturating_add(*count);
            }
            self.delay_total = total;
        }
    }

    /// The packet-times of delay all but the slowest few arrivals fell within.
    fn percentile(&self) -> u16 {
        if self.delay_total == 0 {
            return 0;
        }
        let threshold = u64::from(self.delay_total).saturating_mul(TARGET_PERCENTILE);
        let mut cumulative = 0_u64;
        for (bucket, count) in self.delays.iter().enumerate() {
            cumulative = cumulative.saturating_add(u64::from(*count).saturating_mul(100));
            if cumulative >= threshold {
                return u16::try_from(bucket).unwrap_or(0);
            }
        }
        u16::try_from(DELAY_BUCKETS - 1).unwrap_or(0)
    }

    /// Believe the stream over the negotiation about how long a packet is.
    ///
    /// Only a pair of consecutive sequence numbers says anything, and only a
    /// figure that repeats is acted on, so a single reordered pair or a codec
    /// changing frame size mid-spurt cannot move it.
    fn learn_span(&mut self, sequence: u16, timestamp: u32) {
        let consecutive = self.seen && sequence == self.last_sequence.wrapping_add(1);
        let step = timestamp.wrapping_sub(self.last_timestamp);
        self.seen = true;
        self.last_sequence = sequence;
        self.last_timestamp = timestamp;
        if !consecutive || step == 0 || step > self.clock_rate {
            return;
        }
        if step == self.candidate {
            self.streak = self.streak.saturating_add(1);
        } else {
            self.candidate = step;
            self.streak = 1;
        }
        if self.streak >= SPAN_STREAK && step != self.span {
            // the distribution is counted in packet-times, so it means
            // something else now and is not worth converting
            self.span = step;
            self.delays = [0; DELAY_BUCKETS];
            self.delay_total = 0;
        }
    }

    /// Forget what was tied to a stream that has ended: the transit anchors and
    /// the packet length, both of which are read off timestamps that have just
    /// been re-based. The delay distribution and the jitter estimate describe
    /// the path rather than the stream, and the path has not changed.
    fn restart(&mut self) {
        self.transit = None;
        self.rebase();
        self.seen = false;
        self.streak = 0;
        self.candidate = 0;
    }
}

/// The last few hundred frames of playout, one bit each, so the loss rate can
/// be read off a window that slides instead of one that resets.
#[derive(Debug)]
struct LossWindow {
    holes: [u64; LOSS_WORDS],
    cursor: usize,
    filled: u16,
}

impl LossWindow {
    const fn new() -> Self {
        Self {
            holes: [0; LOSS_WORDS],
            cursor: 0,
            filled: 0,
        }
    }

    fn record(&mut self, hole: bool) {
        let bit = 1_u64 << (self.cursor % 64);
        if let Some(word) = self.holes.get_mut(self.cursor / 64) {
            if hole {
                *word |= bit;
            } else {
                *word &= !bit;
            }
        }
        self.cursor = (self.cursor + 1) % LOSS_WINDOW;
        self.filled = self.filled.saturating_add(1).min(LOSS_CAPACITY);
    }

    fn rate(&self) -> f32 {
        if self.filled == 0 {
            return 0.0;
        }
        let holes = self
            .holes
            .iter()
            .fold(0_u32, |sum, word| sum.saturating_add(word.count_ones()));
        f32::from(u16::try_from(holes).unwrap_or(u16::MAX)) / f32::from(self.filled)
    }
}

/// An adaptive de-jitter buffer for one stream.
#[derive(Debug)]
pub struct JitterBuffer {
    slots: Vec<Slot>,
    /// Which slot the window's base sits in. It moves with the base rather
    /// than being derived from the sequence number; see the module note.
    origin: usize,
    depth: u16,
    clock_rate: u32,
    min_delay: u16,
    max_delay: u16,
    target: u16,
    held: u16,
    next: u16,
    highest: u16,
    /// Packets accepted since the last pull. A buffer that is starving cannot
    /// stretch its way out of it, so growth waits for evidence that audio is
    /// still arriving.
    arrived: u16,
    anchored: bool,
    playing: bool,
    timing: Timing,
    loss: LossWindow,
    counts: Counters,
    /// RFC 3611 §4.7.2's burst/gap classification, fed exactly once per
    /// sequence number as its fate is finally decided: `Received` when a
    /// held packet is played (in [`Self::pull`]), `Lost` when a slot comes
    /// due empty or the window jumps clean past it (in [`Self::pull`] and
    /// [`Self::slide`]), and `Discarded` when a held-but-unplayed packet
    /// is evicted by a window jump (`Self::slide`), passed over before
    /// playout starts (`Self::pass_over`), or thrown out with the window by
    /// [`Self::restart`] or [`Self::reformat`]. A late or duplicate
    /// arrival ([`Insert::Late`], [`Insert::Duplicate`]) contributes
    /// nothing: its sequence number was already resolved, or (duplicates)
    /// SS4.7.1 excludes it outright ("excluding duplicate packet
    /// discards"). A held-and-accepted packet is not fed here either — it
    /// still awaits the outcome [`Self::pull`] gives it later, and feeding
    /// it twice would double the count.
    gmin: GminTracker,
}

impl JitterBuffer {
    /// A buffer for a stream at `clock_rate` ticks a second.
    ///
    /// Every figure in `config` is clamped into what a window can be: the depth
    /// to at most [`MAX_DEPTH`], the delay ceiling to below the depth, the
    /// floor to at most the ceiling, and the starting delay between the two. A
    /// nonsensical configuration therefore produces a small buffer rather than
    /// a broken one.
    #[must_use]
    pub fn new(clock_rate: u32, config: &BufferConfig) -> Self {
        let depth = config.depth.clamp(1, MAX_DEPTH);
        // one packet below the ring: a window sitting exactly at its target
        // must still have somewhere to put a packet that arrives out of order
        let ceiling = depth.saturating_sub(1).max(1);
        let max_delay = config.max_delay.clamp(1, ceiling);
        let min_delay = config.min_delay.clamp(1, max_delay);
        let mut slots = Vec::new();
        slots.resize_with(usize::from(depth), Slot::default);
        Self {
            slots,
            origin: 0,
            depth,
            clock_rate: clock_rate.max(1),
            min_delay,
            max_delay,
            target: config.start_delay.clamp(min_delay, max_delay),
            held: 0,
            next: 0,
            highest: 0,
            arrived: 0,
            anchored: false,
            playing: false,
            timing: Timing::new(clock_rate.max(1), config.packet_samples.max(1)),
            loss: LossWindow::new(),
            counts: Counters::default(),
            gmin: GminTracker::new(RECOMMENDED_GMIN),
        }
    }

    /// Offer a packet, and say when it arrived.
    ///
    /// `arrival` is on whatever timeline the caller keeps, as long as it is
    /// monotonic and has the same idea of a second as everyone else; nothing
    /// here reads a clock. The first packet anchors the window; after that the
    /// sequence number says where the packet belongs relative to what is being
    /// played. Nothing here asks whether the packet is believable — that is
    /// settled before it gets this far, which is what keeps a wild sequence
    /// number from moving the window.
    pub fn insert(&mut self, packet: &RtpPacket<'_>, arrival: Duration) -> Insert {
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
            // it is unplayable, but it is also the clearest evidence there is
            // that the buffer is too short, so its arrival still counts, and
            // counts in full whatever its marker says
            self.note_arrival(sequence, header.timestamp, arrival, false);
            self.counts.discarded_late = self.counts.discarded_late.saturating_add(1);
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
            self.counts.duplicates = self.counts.duplicates.saturating_add(1);
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
        self.arrived = self.arrived.saturating_add(1);
        self.counts.received = self.counts.received.saturating_add(1);
        // a spurt opens with the newest packet there is; a marker that turns
        // up behind packets already held arrived after its own spurt had
        // started, which is lateness the path is responsible for
        let reordered = sequence.wrapping_sub(self.highest) >= BEHIND;
        if reordered {
            self.counts.reordered = self.counts.reordered.saturating_add(1);
        } else {
            self.highest = sequence;
        }
        self.note_arrival(
            sequence,
            header.timestamp,
            arrival,
            header.marker && !reordered,
        );

        if displaced > 0 {
            Insert::Displaced(displaced)
        } else {
            Insert::Accepted
        }
    }

    /// Take the next frame, and say whether the one before it was speech.
    ///
    /// One call is one frame of the device's time, whatever comes back: a
    /// packet, a request to conceal, a request to stretch a pause, or nothing
    /// at all while the buffer fills. In a pause the delay may move by one
    /// frame, either by dropping a packet that will not be missed or by asking
    /// for a frame that was never sent; during speech it does not move.
    pub fn pull(&mut self, activity: Activity) -> Pull<'_> {
        let arrived = self.arrived;
        self.arrived = 0;
        if !self.anchored {
            return Pull::Empty;
        }

        if !self.playing && !self.start() {
            return Pull::Empty;
        }

        let queued = self.queued();
        if activity == Activity::Silence {
            // the dead band is two packets wide above the floor, as it is
            // above any target: an earpiece whose frames land near the edge
            // of an arrival sees the queue go one either way from one pull
            // to the next, and a band of one would answer each of those
            // with a stretch or a shrink
            let floor = self.target.max(IN_HAND);
            if queued > floor.saturating_add(1) {
                self.shorten();
            } else if arrived > 0 && queued < floor {
                self.counts.stretched = self.counts.stretched.saturating_add(1);
                return Pull::Stretch;
            }
        }

        let index = self.index_of(self.next);
        if !self.slots.get(index).is_some_and(|slot| slot.filled) {
            if self.held == 0 {
                // nothing behind it either: the stream has stopped rather than
                // lost a packet, so the window waits where it is and fills to
                // the target again before playing on
                self.playing = false;
                return Pull::Empty;
            }
            self.advance_base(1);
            self.counts.lost = self.counts.lost.saturating_add(1);
            self.loss.record(true);
            self.gmin.observe(PacketOutcome::Lost);
            return Pull::Conceal;
        }

        self.advance_base(1);
        self.held = self.held.saturating_sub(1);
        self.loss.record(false);
        self.gmin.observe(PacketOutcome::Received);

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
    /// counters and what has been learned about the path. For a far end that
    /// has restarted its stream, where what is still in the window belongs to
    /// a stream that no longer exists.
    pub fn restart(&mut self) {
        for slot in &mut self.slots {
            slot.filled = false;
        }
        // what was waiting is thrown away, and saying so is the difference
        // between a counter that accounts for every packet taken in and one
        // that quietly loses some
        self.counts.discarded_overflow = self
            .counts
            .discarded_overflow
            .saturating_add(u64::from(self.held));
        self.discard_held();
        self.held = 0;
        self.arrived = 0;
        self.anchored = false;
        self.playing = false;
        self.timing.restart();
    }

    /// Rebuild for a stream that changed codec mid-call, keeping what the call
    /// has counted.
    ///
    /// A codec change moves the clock rate and the packet length, and those
    /// two are the units everything measured here is in: the window is sized
    /// in packets, the delay distribution is in packet-times, the jitter
    /// estimate is in ticks. None of them converts, so all of them start
    /// again.
    ///
    /// The cumulative counters do not, and that is the point of having this
    /// rather than a new buffer. They belong to the call, which has not ended:
    /// a reception report that began again from zero would tell the far end
    /// that nothing had been lost since the beginning of a stream that is
    /// seconds old, and the call's own statistics would lose everything before
    /// the re-negotiation. The same goes for what RFC 3611 §4.7 reports about
    /// the stream, which describes the RTP session rather than its format.
    pub fn reformat(&mut self, clock_rate: u32, config: &BufferConfig) {
        let mut counts = self.counts;
        // the same accounting `restart` does, for the same reason: what is in
        // the window belongs to the old format and cannot be played under the
        // new one
        counts.discarded_overflow = counts
            .discarded_overflow
            .saturating_add(u64::from(self.held));
        self.discard_held();
        let gmin = self.gmin;
        *self = Self::new(clock_rate, config);
        self.counts = counts;
        self.gmin = gmin;
    }

    /// Tell the RFC 3611 §4.7 tracker that every packet held is being thrown
    /// out unplayed. They arrived and the buffer dropped them, which is what
    /// §4.7.1's discard rate counts, and the quality ratings are computed
    /// from that rate as well as the loss.
    fn discard_held(&mut self) {
        for _ in 0..self.held {
            self.gmin.observe(PacketOutcome::Discarded);
        }
    }

    /// Everything measured about this stream.
    #[must_use]
    pub fn quality(&self) -> Quality {
        Quality {
            received: self.counts.received,
            lost: self.counts.lost,
            discarded_late: self.counts.discarded_late,
            discarded_overflow: self.counts.discarded_overflow,
            duplicates: self.counts.duplicates,
            reordered: self.counts.reordered,
            shrunk: self.counts.shrunk,
            stretched: self.counts.stretched,
            delay: self.packets_to_duration(self.queued()),
            target_delay: self.packets_to_duration(self.target),
            jitter: ticks_to_duration(self.clock_rate, self.timing.jitter_scaled >> 4),
            loss_rate: self.loss.rate(),
        }
    }

    /// RFC 3611 §4.7.1's loss and discard rates and §4.7.2's burst/gap
    /// densities and mean durations, from every sequence number this
    /// buffer has resolved so far. Durations are in whole milliseconds,
    /// from this buffer's own packet-time (`packets_to_duration(1)`), the
    /// appendix's `m`.
    #[must_use]
    pub(crate) fn burst_gap_metrics(&self) -> BurstGapMetrics {
        let packet_duration_ms =
            u32::try_from(self.packets_to_duration(1).as_millis()).unwrap_or(u32::MAX);
        self.gmin.metrics(packet_duration_ms)
    }

    /// The `Gmin` this buffer classifies bursts and gaps with (RFC 3611
    /// §4.7.2's own field of the same name), fixed at
    /// [`RECOMMENDED_GMIN`] for the life of the buffer.
    #[must_use]
    pub(crate) const fn gmin(&self) -> u8 {
        self.gmin.gmin()
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

    /// The delay being aimed at, in packets.
    #[must_use]
    pub const fn target(&self) -> u16 {
        self.target
    }

    /// The longest delay this buffer may ever choose, in milliseconds —
    /// RFC 3611 §4.7.7's "Maximum Jitter Buffer Delay" field is the
    /// momentary depth of a resizing buffer, but its "Absolute Maximum
    /// Jitter Buffer Delay" is this fixed ceiling ("For a fixed jitter
    /// buffer, this SHOULD be the same as the Maximum Jitter Buffer
    /// Delay"; for an adaptive one it is the bound the momentary figure
    /// can never cross).
    #[must_use]
    pub(crate) fn max_delay_ms(&self) -> u16 {
        u16::try_from(self.packets_to_duration(self.max_delay).as_millis()).unwrap_or(u16::MAX)
    }

    /// The sequence number that comes out next, once the buffer has seen a
    /// first packet.
    #[must_use]
    pub const fn next_sequence(&self) -> Option<u16> {
        if self.anchored { Some(self.next) } else { None }
    }

    /// How far the playout point is behind the newest packet received, in
    /// packets. This rather than the number held, because a hole in the window
    /// is still time the listener waits.
    fn queued(&self) -> u16 {
        if !self.anchored {
            return 0;
        }
        let span = self.highest.wrapping_sub(self.next);
        if span >= BEHIND {
            0
        } else {
            span.saturating_add(1)
        }
    }

    fn packets_to_duration(&self, packets: u16) -> Duration {
        let ticks = u32::from(packets).saturating_mul(self.timing.span);
        ticks_to_duration(self.clock_rate, ticks)
    }

    /// Fold one arrival into the estimate and move the target if it has to.
    fn note_arrival(&mut self, sequence: u16, timestamp: u32, arrival: Duration, opens: bool) {
        let ticks = clock_ticks(self.clock_rate, arrival);
        // up to the target is lateness the buffer already allows for, so a
        // spurt that starts inside it says nothing worth starting again for
        let allowed = u32::from(self.target).saturating_mul(self.timing.span);
        self.timing
            .note(sequence, timestamp, ticks, opens.then_some(allowed));

        let wanted = self
            .timing
            .percentile()
            .saturating_add(1)
            .clamp(self.min_delay, self.max_delay);
        if wanted > self.target {
            // a burst is answered at once: the alternative is concealing every
            // packet of it while the target creeps up
            self.target = wanted;
            self.timing.since_shrink = 0;
        } else if wanted < self.target && self.timing.since_shrink >= SHRINK_HOLD {
            self.target = self.target.saturating_sub(1).max(self.min_delay);
            self.timing.since_shrink = 0;
        }
    }

    /// Start playing, if what is held has reached the target.
    ///
    /// What is held counts from the first packet actually there, not from the
    /// playout point. A stream that stopped can come back further on than it
    /// left off, with the sequence numbers it spent while it was quiet never
    /// sent at all; counted from the playout point, that gap would start
    /// playout at once, conceal every frame of it, and then keep the whole gap
    /// as delay for as long as nobody paused. Waiting until the packets after
    /// the first one reach the target also gives a spurt whose first packets
    /// arrive out of order the time to fill in.
    ///
    /// And playout does not start on packets stranded in front of a gap
    /// longer than the target. One left on its own there, too few to start on
    /// and then a second older than anything after it, would otherwise be
    /// played first and the gap concealed after it, which is the same second
    /// of delay by another route, bought with concealment and nothing the far
    /// end said. Nobody has heard what is dropped. Packets that are held
    /// together, with no such gap between them, are all played, however many
    /// there are: that is the far end talking, and a delay that is longer than
    /// it has to be is given back in its next pause.
    fn start(&mut self) -> bool {
        if self.held == 0 {
            return false;
        }
        let gap = self.leading_gap();
        if self.queued().saturating_sub(gap) < self.target {
            return false;
        }
        self.pass_over(gap);
        let stranded = self.stranded();
        if stranded > 0 {
            self.pass_over(stranded);
            if self.queued() < self.target {
                return false;
            }
        }
        self.playing = true;
        true
    }

    /// How far on from the playout point the packet after the last gap longer
    /// than the target is, or zero when there is no such gap. Everything
    /// before that packet is stranded behind it.
    fn stranded(&self) -> u16 {
        let span = self.queued();
        let mut cut = 0;
        let mut empty = 0_u16;
        for offset in 0..span {
            let filled = self
                .slots
                .get(self.index_of(self.next.wrapping_add(offset)))
                .is_some_and(|slot| slot.filled);
            if filled {
                if empty > self.target {
                    cut = offset;
                }
                empty = 0;
            } else {
                empty += 1;
            }
        }
        cut
    }

    /// Move the playout point `count` frames on before playout has started.
    /// Nobody was listening while these came due, so what was never there is
    /// loss the counters record rather than frames anyone hears concealed, and
    /// what was held is thrown out of the window unplayed.
    fn pass_over(&mut self, count: u16) {
        for _ in 0..count {
            let index = self.index_of(self.next);
            if let Some(slot) = self.slots.get_mut(index)
                && slot.filled
            {
                slot.filled = false;
                self.held = self.held.saturating_sub(1);
                self.counts.discarded_overflow = self.counts.discarded_overflow.saturating_add(1);
                self.gmin.observe(PacketOutcome::Discarded);
            } else {
                self.counts.lost = self.counts.lost.saturating_add(1);
                self.gmin.observe(PacketOutcome::Lost);
            }
            self.advance_base(1);
        }
    }

    /// How many empty slots stand between the playout point and the first
    /// packet held.
    fn leading_gap(&self) -> u16 {
        let mut gap = 0;
        while gap < self.depth
            && !self
                .slots
                .get(self.index_of(self.next.wrapping_add(gap)))
                .is_some_and(|slot| slot.filled)
        {
            gap += 1;
        }
        gap
    }

    /// Give up the oldest frame to bring the delay down by one. A slot that is
    /// empty anyway costs nothing to skip, which is the cheapest shrink there
    /// is and the reason this looks at the slot before counting anything.
    fn shorten(&mut self) {
        let index = self.index_of(self.next);
        let filled = self.slots.get(index).is_some_and(|slot| slot.filled);
        if filled {
            if let Some(slot) = self.slots.get_mut(index) {
                slot.filled = false;
            }
            self.held = self.held.saturating_sub(1);
            self.counts.shrunk = self.counts.shrunk.saturating_add(1);
        } else {
            self.counts.lost = self.counts.lost.saturating_add(1);
        }
        self.advance_base(1);
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
        self.counts.discarded_overflow = self
            .counts
            .discarded_overflow
            .saturating_add(u64::from(displaced));
        // what the window passed over without ever holding is loss the
        // consumer will never be told about any other way
        let skipped = u64::from(advance).saturating_sub(u64::from(displaced));
        self.counts.lost = self.counts.lost.saturating_add(skipped);
        // Every one of the `advance` sequence numbers the window just
        // jumped past is resolved right here, once each: the `displaced`
        // of them that were held but never played are RFC 3611 §4.7.1
        // discards (late or, here, overflow at "the receiving jitter
        // buffer"); the rest were never received at all.
        for _ in 0..displaced {
            self.gmin.observe(PacketOutcome::Discarded);
        }
        for _ in 0..skipped {
            self.gmin.observe(PacketOutcome::Lost);
        }
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
    use std::time::Duration;

    use super::{Activity, BufferConfig, Insert, JitterBuffer, MAX_DEPTH, Pull};
    use crate::wire::{PacketBuilder, RtpHeader, RtpPacket};

    const RATE: u32 = 8000;
    const SPAN: u32 = 160;
    const FRAME: Duration = Duration::from_millis(20);

    fn config(depth: u16, start: u16) -> BufferConfig {
        BufferConfig {
            depth,
            packet_samples: SPAN,
            min_delay: 1,
            start_delay: start,
            max_delay: 25,
        }
    }

    fn buffer(depth: u16, start: u16) -> JitterBuffer {
        JitterBuffer::new(RATE, &config(depth, start))
    }

    /// One packet's worth of wire bytes, with the sequence number in the
    /// payload so playout order is visible in the assertions.
    fn datagram(sequence: u16, marker: bool, step: u32) -> Vec<u8> {
        let header = RtpHeader {
            marker,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence).wrapping_mul(step),
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

    fn insert_at(buffer: &mut JitterBuffer, sequence: u16, arrival: Duration) -> Insert {
        let bytes = datagram(sequence, false, SPAN);
        let packet = RtpPacket::parse(&bytes).expect("a packet");
        buffer.insert(&packet, arrival)
    }

    /// Inserted at the instant it would have arrived on a network with no
    /// delay variation at all, so nothing here moves the target.
    fn insert(buffer: &mut JitterBuffer, sequence: u16) -> Insert {
        insert_at(buffer, sequence, FRAME * u32::from(sequence))
    }

    /// The sequence number of whatever comes out, or `None` for anything else.
    fn pull(buffer: &mut JitterBuffer) -> Option<u16> {
        match buffer.pull(Activity::Speech) {
            Pull::Packet(frame) => Some(frame.sequence),
            Pull::Conceal | Pull::Stretch | Pull::Empty => None,
        }
    }

    #[test]
    fn a_window_that_straddles_the_wrap_still_names_one_slot_per_number() {
        // the ring is indexed by distance from the base, not by the sequence
        // number itself: 65536 is not a multiple of ten, so the raw modulus
        // would put 65530 and 0 in the same slot and read the second as a
        // duplicate of the first
        let mut buffer = buffer(10, 1);
        for sequence in [65_530_u16, 65_531, 65_532, 65_533, 65_534, 65_535] {
            assert_eq!(insert(&mut buffer, sequence), Insert::Accepted);
        }
        assert_eq!(
            insert(&mut buffer, 0),
            Insert::Accepted,
            "the packet after the wrap is live audio, not a duplicate"
        );
        assert_eq!(buffer.held(), 7);
        assert_eq!(buffer.quality().duplicates, 0);

        for expected in [65_530_u16, 65_531, 65_532, 65_533, 65_534, 65_535, 0] {
            assert_eq!(pull(&mut buffer), Some(expected));
        }
    }

    #[test]
    fn every_depth_holds_a_full_window_across_the_wrap() {
        // the same property, stated for the depths a caller might pick rather
        // than for the one that happened to break
        for depth in 1_u16..=24 {
            let mut buffer = buffer(depth, 1);
            let base = 65_536_u32.wrapping_sub(u32::from(depth) / 2);
            for step in 0..depth {
                let sequence = u16::try_from((base + u32::from(step)) % 65_536).unwrap();
                assert_eq!(
                    insert(&mut buffer, sequence),
                    Insert::Accepted,
                    "depth {depth}, sequence {sequence}"
                );
            }
            assert_eq!(buffer.held(), depth, "depth {depth}");
            assert_eq!(buffer.quality().duplicates, 0, "depth {depth}");
        }
    }

    #[test]
    fn packets_come_out_in_sequence_order_whatever_order_they_went_in() {
        let mut buffer = buffer(8, 3);
        assert_eq!(insert(&mut buffer, 10), Insert::Accepted);
        assert_eq!(insert(&mut buffer, 12), Insert::Accepted);
        assert_eq!(insert(&mut buffer, 11), Insert::Accepted);
        assert_eq!(pull(&mut buffer), Some(10));
        assert_eq!(pull(&mut buffer), Some(11));
        assert_eq!(pull(&mut buffer), Some(12));
        assert_eq!(buffer.quality().reordered, 1, "11 arrived after 12");
        assert_eq!(buffer.quality().lost, 0, "reordering is not loss");
    }

    #[test]
    fn nothing_comes_out_until_the_target_is_there() {
        let mut buffer = buffer(8, 3);
        insert(&mut buffer, 1);
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
        insert(&mut buffer, 2);
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
        insert(&mut buffer, 3);
        assert_eq!(pull(&mut buffer), Some(1));
    }

    #[test]
    fn the_frame_carries_what_the_header_said() {
        let mut buffer = buffer(4, 1);
        let bytes = datagram(7, true, SPAN);
        let packet = RtpPacket::parse(&bytes).expect("a packet");
        buffer.insert(&packet, Duration::ZERO);
        let Pull::Packet(frame) = buffer.pull(Activity::Speech) else {
            panic!("a packet");
        };
        assert_eq!(frame.sequence, 7);
        assert_eq!(frame.timestamp, 7 * SPAN);
        assert_eq!(frame.payload_type, 0);
        assert!(frame.marker, "a talk spurt starts here");
        assert_eq!(frame.payload, 7_u16.to_be_bytes());
    }

    #[test]
    fn the_same_sequence_number_twice_is_dropped_on_the_second() {
        let mut buffer = buffer(8, 1);
        assert_eq!(insert(&mut buffer, 40), Insert::Accepted);
        assert_eq!(insert(&mut buffer, 40), Insert::Duplicate);
        assert_eq!(buffer.held(), 1);
        assert_eq!(buffer.quality().duplicates, 1);
        assert_eq!(buffer.quality().received, 1);
    }

    #[test]
    fn a_packet_behind_the_playout_point_has_missed_its_turn() {
        let mut buffer = buffer(8, 1);
        insert(&mut buffer, 100);
        insert(&mut buffer, 101);
        assert_eq!(pull(&mut buffer), Some(100));
        assert_eq!(pull(&mut buffer), Some(101));
        // 99 was in flight the whole time; the window has moved past it
        assert_eq!(insert(&mut buffer, 99), Insert::Late);
        assert_eq!(buffer.quality().discarded_late, 1);
        assert_eq!(buffer.quality().received, 2);
    }

    #[test]
    fn a_late_packet_still_says_something_about_the_path() {
        // it cannot be played, but the buffer being too short for it is
        // exactly what the estimate needs to hear
        let mut buffer = buffer(8, 1);
        insert(&mut buffer, 100);
        insert(&mut buffer, 101);
        assert_eq!(pull(&mut buffer), Some(100));
        assert_eq!(pull(&mut buffer), Some(101));
        let before = buffer.quality().jitter;

        // 99 turns up two hundred milliseconds after its time
        assert_eq!(
            insert_at(&mut buffer, 99, FRAME * 99 + Duration::from_millis(200)),
            Insert::Late
        );
        assert!(
            buffer.quality().jitter > before,
            "a packet that missed its turn is still an arrival"
        );
    }

    #[test]
    fn a_hole_that_comes_due_is_reported_and_the_stream_carries_on() {
        let mut buffer = buffer(8, 2);
        insert(&mut buffer, 5);
        insert(&mut buffer, 7);
        assert_eq!(pull(&mut buffer), Some(5));
        assert!(
            matches!(buffer.pull(Activity::Speech), Pull::Conceal),
            "6 never arrived"
        );
        assert_eq!(pull(&mut buffer), Some(7));
        assert_eq!(buffer.quality().lost, 1);
    }

    #[test]
    fn an_empty_buffer_says_so_rather_than_declaring_a_loss() {
        let mut buffer = buffer(8, 1);
        assert!(
            matches!(buffer.pull(Activity::Speech), Pull::Empty),
            "nothing has arrived"
        );
        insert(&mut buffer, 3);
        assert_eq!(pull(&mut buffer), Some(3));
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
        assert_eq!(buffer.quality().lost, 0);
    }

    #[test]
    fn a_stalled_consumer_costs_the_oldest_packets_and_not_the_memory() {
        // the ring is fixed, so a consumer that stops pulling turns into a
        // counter going up rather than a buffer growing
        let mut buffer = buffer(4, 1);
        for sequence in 200..204 {
            assert_eq!(insert(&mut buffer, sequence), Insert::Accepted);
        }
        assert_eq!(buffer.held(), 4);

        assert_eq!(insert(&mut buffer, 204), Insert::Displaced(1));
        assert_eq!(buffer.held(), 4, "still four, never five");
        assert_eq!(buffer.quality().discarded_overflow, 1);

        for sequence in 205..208 {
            assert_eq!(insert(&mut buffer, sequence), Insert::Displaced(1));
        }
        assert_eq!(buffer.held(), 4);
        assert_eq!(buffer.quality().discarded_overflow, 4);

        // what is left is the newest four, which is what a live call wants
        assert_eq!(pull(&mut buffer), Some(204));
        assert_eq!(pull(&mut buffer), Some(205));
        assert_eq!(pull(&mut buffer), Some(206));
        assert_eq!(pull(&mut buffer), Some(207));
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
    }

    #[test]
    fn a_jump_past_the_whole_window_clears_it_and_counts_what_was_missed() {
        let mut buffer = buffer(4, 1);
        insert(&mut buffer, 10);
        insert(&mut buffer, 11);
        assert_eq!(insert(&mut buffer, 40), Insert::Displaced(2));
        assert_eq!(buffer.held(), 1);
        assert_eq!(
            buffer.quality().discarded_overflow,
            2,
            "10 and 11 were thrown away"
        );
        // the window moved from 10 to 37, and what it passed over is loss
        assert_eq!(buffer.quality().lost, 25);
        // 37, 38 and 39 are still inside the window, but nothing has been
        // played yet, so playout starts at the first packet there rather than
        // concealing three frames to reach it
        assert_eq!(pull(&mut buffer), Some(40));
        let quality = buffer.quality();
        assert_eq!(
            quality.lost + quality.discarded_overflow,
            30,
            "thirty sequence numbers went by unheard, two of them held"
        );
    }

    #[test]
    fn the_window_follows_the_sequence_number_across_the_wrap() {
        let mut buffer = buffer(8, 2);
        insert(&mut buffer, 65534);
        insert(&mut buffer, 65535);
        insert(&mut buffer, 0);
        insert(&mut buffer, 1);
        assert_eq!(pull(&mut buffer), Some(65534));
        assert_eq!(pull(&mut buffer), Some(65535));
        assert_eq!(pull(&mut buffer), Some(0));
        assert_eq!(pull(&mut buffer), Some(1));
        assert_eq!(buffer.quality().lost, 0);
        assert_eq!(buffer.quality().reordered, 0);
    }

    #[test]
    fn a_restart_drops_the_stream_it_was_holding_and_keeps_the_counters() {
        let mut buffer = buffer(8, 1);
        insert(&mut buffer, 20);
        insert(&mut buffer, 21);
        buffer.restart();
        assert_eq!(buffer.held(), 0);
        assert_eq!(buffer.next_sequence(), None);
        assert_eq!(buffer.quality().received, 2, "the counters are cumulative");
        assert_eq!(buffer.quality().discarded_overflow, 2);

        insert(&mut buffer, 9000);
        assert_eq!(buffer.next_sequence(), Some(9000));
        assert_eq!(pull(&mut buffer), Some(9000));
    }

    #[test]
    fn what_a_restart_or_a_new_format_throws_out_is_in_the_discard_rate() {
        // RFC 3611 §4.7.1 counts every packet the buffer drops, for overflow
        // or for anything else, in the discard rate: here eight played and
        // eight thrown out, twice, is a half of what was expected
        let mut buffer = buffer(20, 1);
        for sequence in 0..16 {
            insert(&mut buffer, sequence);
        }
        for _ in 0..8 {
            pull(&mut buffer);
        }
        buffer.restart();
        assert_eq!(buffer.quality().discarded_overflow, 8);
        assert_eq!(buffer.burst_gap_metrics().discard_rate, 128);

        for sequence in 100..116 {
            insert(&mut buffer, sequence);
        }
        for _ in 0..8 {
            pull(&mut buffer);
        }
        buffer.reformat(RATE, &config(20, 1));
        assert_eq!(buffer.quality().discarded_overflow, 16);
        assert_eq!(
            buffer.burst_gap_metrics().discard_rate,
            128,
            "the stream's figures outlive its format, as its counters do"
        );
    }

    #[test]
    fn the_configuration_is_clamped_to_something_a_window_can_be() {
        assert_eq!(JitterBuffer::new(RATE, &config(0, 0)).depth(), 1);
        assert_eq!(
            JitterBuffer::new(RATE, &config(u16::MAX, 0)).depth(),
            MAX_DEPTH
        );

        // a target of more than the ring would mean a buffer that waits for
        // more than it can hold, and would never start
        let wide = BufferConfig {
            depth: 4,
            packet_samples: SPAN,
            min_delay: 900,
            start_delay: 900,
            max_delay: 900,
        };
        let mut buffer = JitterBuffer::new(RATE, &wide);
        assert_eq!(buffer.target(), 3, "one below the ring");
        for sequence in 1..4 {
            insert(&mut buffer, sequence);
        }
        assert_eq!(pull(&mut buffer), Some(1));
    }

    #[test]
    fn a_clock_rate_of_zero_does_not_divide_by_it() {
        let mut buffer = JitterBuffer::new(0, &config(4, 1));
        insert(&mut buffer, 1);
        assert_eq!(pull(&mut buffer), Some(1));
        assert_eq!(buffer.quality().jitter, Duration::ZERO);
    }

    /// A stream where one packet in ten is three frames late, which is what a
    /// target of four packets is the right answer to.
    fn jittered(buffer: &mut JitterBuffer, from: u16, count: u16) {
        for step in 0..count {
            let sequence = from.wrapping_add(step);
            let mut arrival = FRAME * u32::from(sequence);
            if step % 10 == 0 {
                arrival += FRAME * 3;
            }
            insert_at(buffer, sequence, arrival);
            buffer.pull(Activity::Speech);
        }
    }

    fn steady(buffer: &mut JitterBuffer, from: u16, count: u16) {
        for step in 0..count {
            let sequence = from.wrapping_add(step);
            insert_at(buffer, sequence, FRAME * u32::from(sequence));
            buffer.pull(Activity::Speech);
        }
    }

    #[test]
    fn the_target_follows_the_tail_of_the_arrivals_rather_than_a_constant() {
        let mut buffer = buffer(100, 2);
        assert_eq!(buffer.target(), 2, "before anything has arrived");
        jittered(&mut buffer, 0, 120);
        assert_eq!(
            buffer.target(),
            4,
            "three frames of lateness, plus the one that has to be there"
        );
        assert_eq!(buffer.quality().target_delay, Duration::from_millis(80));
    }

    #[test]
    fn a_burst_is_answered_at_once_and_given_back_over_tens_of_seconds() {
        let mut buffer = buffer(100, 2);
        jittered(&mut buffer, 0, 120);
        assert_eq!(buffer.target(), 4);

        // four seconds of a network behaving itself is not enough
        steady(&mut buffer, 120, 200);
        assert!(
            buffer.target() >= 3,
            "one good second must not undo a bad one, got {}",
            buffer.target()
        );

        // forty is
        for block in 0..10_u16 {
            steady(&mut buffer, 320 + block * 200, 200);
        }
        assert_eq!(buffer.target(), 1, "and eventually it is all given back");
    }

    #[test]
    fn the_delay_is_left_alone_while_someone_is_talking() {
        let mut buffer = buffer(20, 1);
        for sequence in 0..8 {
            insert(&mut buffer, sequence);
        }
        // eight packets held against a target of one, which in a pause would
        // be shortened at once
        for expected in 0..8_u16 {
            assert_eq!(pull(&mut buffer), Some(expected));
        }
        let quality = buffer.quality();
        assert_eq!(quality.shrunk, 0, "nothing is dropped during speech");
        assert_eq!(quality.stretched, 0);
    }

    #[test]
    fn a_pause_is_where_the_delay_is_brought_down() {
        let mut buffer = buffer(20, 1);
        for sequence in 0..8 {
            insert(&mut buffer, sequence);
        }
        assert_eq!(buffer.target(), 1);

        // each pull drops one frame until the queue is inside the dead band,
        // so the sequence played skips every other packet on the way down
        let mut played = Vec::new();
        for _ in 0..5 {
            if let Pull::Packet(frame) = buffer.pull(Activity::Silence) {
                played.push(frame.sequence);
            }
        }
        assert_eq!(played, vec![1, 3, 5, 6, 7]);
        assert_eq!(buffer.quality().shrunk, 3);
        assert_eq!(
            buffer.quality().lost,
            0,
            "a frame given up in a pause is not a frame lost"
        );
    }

    #[test]
    fn a_pause_is_also_where_the_delay_is_pushed_up() {
        let deep = BufferConfig {
            depth: 20,
            packet_samples: SPAN,
            min_delay: 4,
            start_delay: 4,
            max_delay: 8,
        };
        let mut buffer = JitterBuffer::new(RATE, &deep);
        for sequence in 0..4 {
            insert(&mut buffer, sequence);
        }
        assert_eq!(pull(&mut buffer), Some(0));
        assert_eq!(pull(&mut buffer), Some(1));

        // three queued against a target of four, and audio still arriving
        insert(&mut buffer, 4);
        assert!(matches!(buffer.pull(Activity::Silence), Pull::Stretch));
        assert_eq!(buffer.quality().stretched, 1);

        // nothing arrived since, so a starving buffer does not stretch itself
        // into a stall
        assert!(matches!(
            buffer.pull(Activity::Silence),
            Pull::Packet(frame) if frame.sequence == 2
        ));
    }

    #[test]
    fn an_empty_slot_in_a_pause_is_the_shrink_and_costs_nothing() {
        let mut buffer = buffer(20, 1);
        for sequence in [0_u16, 2, 3, 4, 5] {
            insert(&mut buffer, sequence);
        }
        assert_eq!(pull(&mut buffer), Some(0));
        // 1 never arrived; in speech this would be a concealed frame, in a
        // pause it is a free frame off the delay
        assert!(matches!(
            buffer.pull(Activity::Silence),
            Pull::Packet(frame) if frame.sequence == 2
        ));
        assert_eq!(buffer.quality().shrunk, 0);
        assert_eq!(buffer.quality().lost, 1, "the packet is still lost");
    }

    #[test]
    fn the_loss_rate_describes_the_last_few_seconds_and_not_the_call() {
        let mut buffer = buffer(20, 1);
        for sequence in [0_u16, 1, 3, 4, 6, 7, 8, 9] {
            insert(&mut buffer, sequence);
        }
        for _ in 0..10 {
            buffer.pull(Activity::Speech);
        }
        let rate = buffer.quality().loss_rate;
        assert!(
            (rate - 0.2).abs() < 0.001,
            "two holes in ten frames, got {rate}"
        );

        // and a clean stretch pushes them out of the window
        for sequence in 10..600_u16 {
            insert(&mut buffer, sequence);
            buffer.pull(Activity::Speech);
        }
        assert!(
            buffer.quality().loss_rate < 0.001,
            "the window has moved past them"
        );
    }

    #[test]
    fn the_packet_length_is_taken_from_the_stream_and_not_from_the_promise() {
        // the answer said twenty milliseconds and the peer sends thirty, which
        // would put every delay figure out by half if the promise were trusted
        let mut buffer = buffer(20, 1);
        for sequence in 0..6_u16 {
            let bytes = datagram(sequence, false, 240);
            let packet = RtpPacket::parse(&bytes).expect("a packet");
            buffer.insert(&packet, Duration::from_millis(30) * u32::from(sequence));
        }
        assert_eq!(
            buffer.quality().delay,
            Duration::from_millis(180),
            "six packets of thirty milliseconds"
        );
    }

    /// One packet with every field the header carries chosen by the test.
    fn insert_raw(
        buffer: &mut JitterBuffer,
        sequence: u16,
        timestamp: u32,
        marker: bool,
        arrival: Duration,
    ) -> Insert {
        let header = RtpHeader {
            marker,
            payload_type: 0,
            sequence,
            timestamp,
            ssrc: 0x1234_5678,
        };
        let payload = sequence.to_be_bytes();
        let mut bytes = vec![0; 32];
        let n = PacketBuilder::new(header, &payload)
            .write(&mut bytes)
            .expect("room");
        bytes.truncate(n);
        let packet = RtpPacket::parse(&bytes).expect("a packet");
        buffer.insert(&packet, arrival)
    }

    #[test]
    fn a_sender_that_stops_its_clock_through_a_pause_does_not_cost_half_a_second() {
        // the pattern FreeSWITCH sent on a DTLS-SRTP call: two packets, 542
        // milliseconds of nothing, then a talk spurt whose timestamp carries on
        // from the last packet as though no time had passed. Measured against
        // the packets before the pause, every packet after it is half a second
        // late, and the target used to go to its ceiling and stay there for
        // over a minute.
        let mut buffer = JitterBuffer::new(RATE, &BufferConfig::new(SPAN));
        let ms = Duration::from_millis;
        insert_raw(&mut buffer, 36_099, 160, true, ms(0));
        insert_raw(&mut buffer, 36_100, 320, false, ms(22));
        let mut now = ms(22);
        while now < ms(560) {
            buffer.pull(Activity::Speech);
            now += FRAME;
        }

        let mut arrival = ms(564);
        for step in 0..250_u16 {
            let timestamp = 480 + u32::from(step) * SPAN;
            insert_raw(&mut buffer, 36_101 + step, timestamp, step == 0, arrival);
            buffer.pull(Activity::Speech);
            arrival += FRAME;
        }
        let quality = buffer.quality();
        assert!(
            buffer.target() <= 2,
            "the pause is not path delay, got a target of {}",
            buffer.target()
        );
        assert!(
            quality.delay <= ms(60),
            "the far end is heard at the delay the path needs, got {:?}",
            quality.delay
        );
        assert_eq!(quality.lost, 0);
    }

    #[test]
    fn a_spurt_that_starts_late_on_a_steady_clock_is_measured_like_any_packet() {
        // the same marker, but from a sender whose clock ran through the pause
        // and a path that delayed the spurt's first packet by a frame: inside
        // what the target already allows for, so the fastest arrivals are
        // kept, and the packets later still after it are measured against them
        let mut buffer = buffer(100, 2);
        steady(&mut buffer, 0, 60);
        insert_raw(&mut buffer, 60, 60 * SPAN, true, FRAME * 61);
        buffer.pull(Activity::Speech);
        // two frames later than the path's best, which the target now has to
        // cover; had the spurt been taken as a new start they would read as
        // one frame, measured from a packet that was itself a frame late, and
        // the target would have stayed where it was
        for sequence in [61_u16, 62] {
            insert_raw(
                &mut buffer,
                sequence,
                u32::from(sequence) * SPAN,
                false,
                FRAME * (u32::from(sequence) + 2),
            );
            buffer.pull(Activity::Speech);
        }
        assert_eq!(
            buffer.target(),
            3,
            "two frames late, plus the one that has to be there"
        );
    }

    #[test]
    fn a_stream_that_comes_back_further_on_starts_where_it_came_back() {
        // the pattern Asterisk sent on a DTLS-SRTP call: two packets, a second
        // of nothing, then the stream again fifty-one sequence numbers and a
        // second of timestamps further on. Playout used to start on the gap,
        // conceal fifty frames and keep a second of delay for as long as the
        // far end kept talking.
        let mut buffer = JitterBuffer::new(RATE, &BufferConfig::new(SPAN));
        let ms = Duration::from_millis;
        insert_raw(&mut buffer, 19_035, 160, false, ms(0));
        insert_raw(&mut buffer, 19_036, 320, false, ms(20));
        let mut now = ms(20);
        while now < ms(1_020) {
            buffer.pull(Activity::Speech);
            now += FRAME;
        }
        let lost_before = buffer.quality().lost;

        insert_raw(&mut buffer, 19_087, 8_480, false, ms(1_040));
        assert!(
            matches!(buffer.pull(Activity::Speech), Pull::Empty),
            "one packet is not yet the target"
        );
        insert_raw(&mut buffer, 19_088, 8_640, false, ms(1_060));
        assert!(matches!(
            buffer.pull(Activity::Speech),
            Pull::Packet(frame) if frame.sequence == 19_087
        ));
        let quality = buffer.quality();
        assert_eq!(quality.lost - lost_before, 50, "the gap is still loss");
        assert_eq!(quality.delay, ms(20), "and not delay");
        assert!(quality.loss_rate < 0.001, "nothing was concealed");
    }

    #[test]
    fn a_packet_left_alone_in_front_of_a_gap_is_not_played_a_second_late() {
        // the pattern Asterisk sent on the resumed DTLS-SRTP call once its
        // first packet under the new keys had been refused: one packet, too
        // few to start on, a second of nothing, and the stream again fifty
        // sequence numbers on. Playout used to start on the one packet,
        // conceal the fifty behind it, and hold the second of delay until
        // the far end paused.
        let mut buffer = JitterBuffer::new(RATE, &BufferConfig::new(SPAN));
        let ms = Duration::from_millis;
        insert_raw(&mut buffer, 42_497, 320, false, ms(70));
        let mut now = ms(70);
        while now < ms(1_100) {
            assert!(matches!(buffer.pull(Activity::Silence), Pull::Empty));
            now += FRAME;
        }

        let mut arrival = ms(1_108);
        let mut concealed = 0;
        for step in 0..50_u16 {
            let sequence = 42_548 + step;
            let timestamp = 8_480 + u32::from(step) * SPAN;
            insert_raw(&mut buffer, sequence, timestamp, false, arrival);
            if matches!(buffer.pull(Activity::Speech), Pull::Conceal) {
                concealed += 1;
            }
            arrival += FRAME;
        }
        let quality = buffer.quality();
        assert_eq!(concealed, 0, "nothing was missing from what is played");
        assert!(
            quality.delay <= ms(40),
            "the far end is heard at the target, got {:?}",
            quality.delay
        );
        assert_eq!(quality.lost, 50, "the fifty never sent are still loss");
        assert_eq!(
            quality.discarded_overflow, 1,
            "and the one left behind is thrown out unplayed"
        );
    }

    #[test]
    fn a_burst_that_raised_the_target_is_played_whole() {
        // twenty packets held up on the way and delivered together: every
        // one of them arrived late, so the target has grown to cover them by
        // the time the last is in, and none is dropped to start
        let mut buffer = buffer(100, 2);
        steady(&mut buffer, 0, 200);
        while !matches!(buffer.pull(Activity::Speech), Pull::Empty) {}
        let delivered = FRAME * 220;
        for sequence in 200..220_u16 {
            insert_at(&mut buffer, sequence, delivered);
        }
        let mut played = 0;
        while let Pull::Packet(_) = buffer.pull(Activity::Speech) {
            played += 1;
        }
        assert_eq!(played, 20, "the whole burst is heard");
        assert_eq!(buffer.quality().discarded_overflow, 0);
    }

    #[test]
    fn a_spurt_whose_first_packets_cross_on_the_way_is_not_concealed_for_it() {
        let mut buffer = buffer(20, 2);
        insert(&mut buffer, 0);
        insert(&mut buffer, 1);
        assert_eq!(pull(&mut buffer), Some(0));
        assert_eq!(pull(&mut buffer), Some(1));
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));

        // the pause ends with 3 overtaking 2
        insert(&mut buffer, 3);
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
        insert(&mut buffer, 2);
        assert_eq!(pull(&mut buffer), Some(2));
        assert_eq!(pull(&mut buffer), Some(3));
        assert_eq!(buffer.quality().lost, 0);
    }

    /// What an earpiece whose clock is off by `skew_ppm` got from a far end
    /// sending a packet every frame on a clean path, over `pulls` of its
    /// frames: how many it played, and how many times the buffer had nothing
    /// for it once playout had begun. The far end talks for sixty frames and
    /// pauses for thirty, the lab's cadenced tone, and the earpiece tells the
    /// buffer which of the two it is playing. Each pull lands up to three
    /// milliseconds either side of its tick, as a device callback does, so
    /// an arrival near a pull is sometimes before it and sometimes after.
    fn played_against_a_skew(skew_ppm: i64, pulls: u32) -> (JitterBuffer, u32, u32) {
        const FRAME_US: i64 = 20_000;
        let mut buffer = buffer(100, 1);
        let pull_every = FRAME_US * 1_000_000 / (1_000_000 + skew_ppm);
        // half a frame out of step, so no arrival and pull ever coincide
        let mut next_arrival = FRAME_US / 2 + 1;
        let mut tick = FRAME_US;
        let mut sequence = 0_u16;
        let (mut played, mut dry, mut pulled) = (0_u32, 0_u32, 0_u32);
        while pulled < pulls {
            let wobble = (i64::from(pulled) * 7_919 % 7 - 3) * 1_000;
            let next_pull = tick + wobble;
            if next_arrival < next_pull {
                let at = Duration::from_micros(u64::try_from(next_arrival).unwrap());
                insert_at(&mut buffer, sequence, at);
                sequence = sequence.wrapping_add(1);
                next_arrival += FRAME_US;
                continue;
            }
            let activity = if pulled % 90 < 60 {
                Activity::Speech
            } else {
                Activity::Silence
            };
            match buffer.pull(activity) {
                Pull::Packet(_) => played += 1,
                Pull::Empty if played > 0 => dry += 1,
                Pull::Conceal | Pull::Stretch | Pull::Empty => {}
            }
            pulled += 1;
            tick += pull_every;
        }
        (buffer, played, dry)
    }

    #[test]
    fn a_fast_earpiece_at_a_one_frame_target_is_stretched_and_never_runs_dry() {
        // 5000 ppm fast: a frame slips every four seconds, about fifty in
        // four minutes, each of which used to be a frame of silence played
        // wherever it fell, since at a target of one the queue has nowhere
        // below the target to fall to but empty
        let (buffer, _, dry) = played_against_a_skew(5_000, 12_000);
        let quality = buffer.quality();
        assert_eq!(dry, 0, "the buffer ran dry {dry} times");
        assert_eq!(buffer.target(), 1, "a clean path, and a target of one");
        assert!(
            (55..=62).contains(&quality.stretched),
            "each frame of drift is stretched into a pause, plus the one in hand, got {}",
            quality.stretched
        );
        assert_eq!(
            quality.shrunk, 0,
            "a pull either side of an arrival is not answered both ways"
        );
        assert_eq!(quality.lost, 0);
    }

    #[test]
    fn a_slow_earpiece_at_a_one_frame_target_is_still_shrunk() {
        let (buffer, _, dry) = played_against_a_skew(-5_000, 12_000);
        let quality = buffer.quality();
        assert_eq!(dry, 0);
        assert!(
            (55..=62).contains(&quality.shrunk),
            "each frame of drift is dropped from a pause, got {}",
            quality.shrunk
        );
        assert!(
            quality.stretched <= 1,
            "the frame in hand, and nothing stretched back and forth, got {}",
            quality.stretched
        );
        assert!(quality.delay <= FRAME * 2, "got {:?}", quality.delay);
    }

    #[test]
    fn a_true_earpiece_buys_its_frame_in_hand_once() {
        let (buffer, played, dry) = played_against_a_skew(0, 12_000);
        let quality = buffer.quality();
        assert_eq!(dry, 0);
        assert_eq!(quality.stretched, 1, "one frame in hand, bought in a pause");
        assert_eq!(quality.shrunk, 0);
        assert_eq!(played + 1, 12_000, "every other pull played a packet");
    }

    #[test]
    fn a_slow_clock_drift_does_not_look_like_jitter_forever() {
        // the far end's clock runs fast, so transit climbs steadily: five
        // microseconds a packet, thirty milliseconds by the end of two
        // minutes. Measured against the fastest arrival of the whole call that
        // is a frame and a half of lateness and the target would follow it;
        // measured against the fastest of the last few hundred packets it is
        // five milliseconds and nothing moves.
        let mut buffer = buffer(100, 2);
        for sequence in 0..6000_u16 {
            let drift = Duration::from_micros(u64::from(sequence) * 5);
            insert_at(&mut buffer, sequence, FRAME * u32::from(sequence) + drift);
            buffer.pull(Activity::Speech);
        }
        assert_eq!(
            buffer.target(),
            1,
            "drift accumulated over a call is not jitter"
        );
    }
}
