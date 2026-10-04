// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
//! being wrong until the next pause, which is the trade the ear prefers —
//! up to a point. A backlog, packets that piled up while nobody was pulling,
//! is not a frame or two to be wrong by: past a fixed allowance over the
//! band it means to sit in, the buffer skips it at once, pause or not, so the
//! delay a listener can be kept behind by has a bound.
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

/// The most delay, in milliseconds, the buffer holds above the top of its
/// dead band waiting for a pause to give it back in: two hundred, ten frames
/// of twenty milliseconds.
///
/// Giving delay back a frame at a time in the pauses is inaudible, and it is
/// what the buffer does with the frame or two a pair of clocks slips. A
/// backlog is another thing. Packets held up on their way in — a receive
/// loop that waited a second and a half for a device to open, then handed
/// over everything that had queued meanwhile — are played whole, since they
/// are the far end talking, and leave that second and a half behind as delay
/// for as long as nobody pauses; a far end that never stops, or a verdict
/// that never finds the pause, keeps it for the rest of the call. So past
/// this much over its band the buffer does not wait: it moves the playout
/// point up to the top of the band at once, in one jump the listener hears
/// once, and counts what it jumped as thrown out
/// ([`Quality::discarded_overflow`]). With the ceiling a path's jitter may
/// raise the target to ([`BufferConfig::max_delay`]), this is the bound on
/// the delay the listener can be kept behind by.
const EXCESS_MS: u32 = 200;

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
///
/// One frame in hand covers a slip of one frame in a talk spurt, which is
/// what any real pair of clocks makes: 250 ppm slips one every eighty
/// seconds. An earpiece fast enough to slip more than that inside one spurt
/// takes the frame in hand and then runs dry, in the middle of a word, and
/// only the pause before the spurt can be stretched to prevent it. So a
/// pause leaves this many queued or, once the earpiece's pace has been
/// measured ([`Pace::in_hand`]), the one about to be played and what it is
/// expected to slip over a spurt as long as the recent ones ([`Spurts`]),
/// whichever is more, and never more than [`DRIFT_BUDGET_MS`] of them.
const IN_HAND: u16 = 2;

/// The most delay a pause may keep in hand for the earpiece's pace, in
/// milliseconds, the one about to be played included: a hundred, which is
/// five frames of twenty milliseconds.
///
/// It covers every clock a real device runs on, with room over. Measured,
/// a laptop's own loudspeaker ran 3 ppm off the machine's crystal and that
/// crystal 9 ppm off true time (`docs/19-numbers.md`), and the widest a
/// device's clock may be off by and still meet its bus's specification is
/// 2500 ppm, a USB full-speed one's (USB 2.0 §7.1.11, ±0.25 %; ±500 ppm at
/// high speed). What a pause keeps in hand is what the pace slips over one
/// talk spurt, with the frame about to be played, half a frame for where
/// the pulls land, and a frame more for an earpiece that takes two at a
/// time; what is left of the budget carries 2500 ppm through a spurt of
/// twenty seconds and 5000 ppm through one of ten, longer than anyone talks
/// without a pause the buffer can stretch.
///
/// A skew past that is no pair of clocks but something broken — a device
/// run at a rate other than the one the stream was opened at — and chasing
/// it with delay would hide it behind a call nobody can talk over: at
/// 500 000 ppm the frames in hand for the lab's second-long spurts came to
/// 340 ms (`docs/19-numbers.md`), past the 150 ms of one-way delay ITU-T
/// G.114 finds acceptable for most conversations. So the buffer keeps no
/// more than this for the pace, runs dry for the rest, and counts every
/// frame it played as nothing ([`Quality::underruns`]), which
/// [`Quality::loss_rate`] takes in: the call says it is suffering rather
/// than quietly growing half a second of delay. The delay a path's jitter
/// calls for is another matter, and is bounded by [`BufferConfig::max_delay`]
/// alone.
const DRIFT_BUDGET_MS: u32 = 100;

/// Frames of the far end's clock the earpiece's pace is measured over before
/// the older half of the measure is forgotten: a minute at twenty
/// milliseconds. Long, because the figure it gives is a ratio of two
/// crystals, which does not change during a call, and every frame of it
/// halves what a pull landing either side of an arrival can move it by.
const PACE_WINDOW: u32 = 3_000;

/// The furthest one arrival may be ahead of the one before it, in sequence
/// numbers, and still be read as the far end's clock having run on
/// unbroken between them: a few packets lost on the way, rather than a
/// stream that stopped and started again.
const PACE_STEP: u16 = 16;

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

/// How far behind the playout point, in sequence numbers, a packet counted
/// lost may still turn up and be recounted as a discard for RFC 3611
/// §4.7.1: ten seconds at twenty milliseconds. Later than that it stays
/// lost, the "degree of lateness that triggers a loss", which §4.7.1 asks
/// to be "significantly greater than that which triggers a discard"; a
/// packet is late for a discard as soon as its turn has passed.
const LATE_WINDOW: u16 = 512;

/// Sixty-four bit words of which of the last [`LATE_WINDOW`] sequence
/// numbers were counted lost.
const LATE_WORDS: usize = LATE_WINDOW as usize / 64;

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
    /// target when playout started, or skipped as a backlog: held further
    /// behind the top of the band the delay sits in than the buffer waits for
    /// a pause to give back.
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
    /// Frames played as nothing because the buffer had run dry while the far
    /// end was still sending: the earpiece asked for audio before it had
    /// arrived, and a frame of silence or comfort noise was heard in its
    /// place, wherever that fell. Counted once playout carries on with the
    /// packet that follows the last one played on the far end's own clock,
    /// which is what tells an under-run from a far end that stopped sending
    /// or packets lost on the way: those are its pause, or [`Quality::lost`].
    /// No packet is lost or discarded by an under-run, so RFC 3611's figures
    /// do not see it; [`Quality::loss_rate`] does.
    pub underruns: u64,
    /// Frames played as nothing because the packet due in them was lost on
    /// the way and nothing behind it had arrived yet to conceal it from: the
    /// other half of the silence the earpiece heard while the far end was
    /// sending, beside [`Quality::underruns`]. Each is one of
    /// [`Quality::lost`] as well, which also holds the lost packets that
    /// were concealed; this is the share of them the listener heard as
    /// silence rather than as a frame made up in their place.
    pub silenced: u64,
    /// How far behind the newest packet received the playout point currently
    /// is: the delay the far end's voice is actually suffering.
    pub delay: Duration,
    /// What the buffer is aiming at, from the arrival times it has seen.
    pub target_delay: Duration,
    /// Interarrival jitter, the smoothed mean deviation of transit time
    /// (RFC 3550 §6.4.1). Measured here from the buffer's own arrivals, so it
    /// is available on a session with RTCP switched off.
    pub jitter: Duration,
    /// Frames concealed or lost to an under-run ([`Quality::underruns`]) as
    /// a fraction of frames played, over the last ten seconds or so. Both
    /// are a frame the listener did not get from the far end, whichever
    /// side of the network it went missing on. The cumulative counters say
    /// what the call has cost so far; this says whether it is bad right now.
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
    underruns: u64,
    silenced: u64,
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

/// How many frames of the far end's clock separate a packet from `last`, the
/// one before it on that clock, when nothing says the clock stopped between
/// them: no marker opening a new spurt (RFC 3551 §4.1), a sequence number a
/// few on at most, and a timestamp exactly as many packets on (RFC 3550
/// §5.1: it "increments monotonically and linearly in time"). `None` for
/// anything else: a pause the far end took, whether or not its timestamps
/// ran through it, or a stream that started again.
fn continues(
    last: (u16, u32),
    sequence: u16,
    timestamp: u32,
    marker: bool,
    span: u32,
) -> Option<u16> {
    let (last_sequence, last_timestamp) = last;
    let step = sequence.wrapping_sub(last_sequence);
    let on = !marker
        && (1..=PACE_STEP).contains(&step)
        && timestamp.wrapping_sub(last_timestamp) == u32::from(step).saturating_mul(span);
    on.then_some(step)
}

/// How fast the earpiece takes frames, against how fast the far end makes
/// them, and how many it takes at a time.
///
/// The two paces are counted over the same stretches of time: the pulls
/// made between one arrival and the next, and the frames of the far end's
/// clock the second is on from the first, wherever [`continues`] says that
/// clock ran unbroken between them. A pause the far end took is left out
/// whole, so a far end suppressing silence is measured over its spurts
/// alone. What is measured is the earpiece's clock and not the network's: a
/// packet held up on the way is paid back by the ones that arrive behind
/// it, and the sum over a run of arrivals is the pulls from the first to the
/// last, off by no more than the pull either side of each end.
#[derive(Debug, Default)]
struct Pace {
    /// Pulls since the last packet that was the newest to arrive.
    since: u32,
    /// And that packet's place on the far end's clock.
    last: Option<(u16, u32)>,
    pulls: u32,
    frames: u32,
    /// Runs of arrivals the sums are made of, each of which can be a pull
    /// out at either end.
    runs: u32,
    /// The frames the earpiece takes at a time, less one: the fewest pulls
    /// seen between two arrivals, over the last window of [`BURST_WINDOW`].
    /// An earpiece that takes one frame a callback pulls once between most
    /// pairs of arrivals; one whose callback is two frames long pulls twice
    /// at the same instant, and no packet ever arrives between the two.
    extra: u16,
    fewest: Option<u32>,
    seen: u8,
}

/// Arrivals that had pulls before them, per window of [`Pace::extra`].
const BURST_WINDOW: u8 = 64;

impl Pace {
    const fn pulled(&mut self) {
        self.since = self.since.saturating_add(1);
    }

    /// Take the arrival of the newest packet there is.
    fn arrived(&mut self, sequence: u16, timestamp: u32, marker: bool, span: u32) {
        let pulls = core::mem::take(&mut self.since);
        if pulls > 0 {
            self.note_burst(pulls);
        }
        let step = self
            .last
            .and_then(|last| continues(last, sequence, timestamp, marker, span));
        self.last = Some((sequence, timestamp));
        let Some(step) = step else {
            self.runs = self.runs.saturating_add(1);
            return;
        };
        self.pulls = self.pulls.saturating_add(pulls);
        self.frames = self.frames.saturating_add(u32::from(step));
        if self.frames >= PACE_WINDOW {
            self.pulls /= 2;
            self.frames /= 2;
            self.runs = self.runs.div_ceil(2);
        }
    }

    fn note_burst(&mut self, pulls: u32) {
        self.fewest = Some(self.fewest.map_or(pulls, |fewest| fewest.min(pulls)));
        self.seen = self.seen.saturating_add(1);
        if self.seen >= BURST_WINDOW {
            let fewest = self.fewest.take().unwrap_or(1);
            self.extra = u16::try_from(fewest.saturating_sub(1)).unwrap_or(u16::MAX);
            self.seen = 0;
        }
    }

    /// How many more frames than one the earpiece takes at a time.
    const fn extra(&self) -> u16 {
        self.extra
    }

    /// Forget where the far end's clock was, for a stream that has started
    /// again on another timeline; how fast the two clocks run is kept.
    const fn restart(&mut self) {
        self.last = None;
    }

    /// The frames to keep in hand for `frames` of the earpiece's own: those
    /// an earpiece at this pace takes before they have arrived, when it
    /// takes them faster than they are made, and half a frame over, rounded
    /// up, for where in a frame its pulls land against the arrivals. One for
    /// a pace no faster than the far end's once what the ends of the runs
    /// can be out by is taken off, which is every pace until the measure is
    /// long enough to say.
    fn in_hand(&self, frames: u16) -> u16 {
        // each run's pulls are out by less than one at either end, one way
        // or the other at random, so what they add up to grows as the root
        // of how many there are; this is twice that, and one more
        let noise = self.runs.isqrt().saturating_mul(2).saturating_add(1);
        let excess = self.pulls.saturating_sub(self.frames).saturating_sub(noise);
        if excess == 0 {
            return 1;
        }
        // in half frames, so the half frame over is exact
        let halves = (2 * u64::from(frames) * u64::from(excess)).div_ceil(u64::from(self.pulls));
        u16::try_from(halves.saturating_add(1).div_ceil(2))
            .unwrap_or(u16::MAX)
            .max(1)
    }
}

/// How long the far end's talk spurts have been, in frames played.
///
/// A spurt starts with a frame the caller's verdict calls speech and ends
/// with one it calls silence, or where the far end's clock says it stopped
/// sending ([`continues`]). Only the verdicts on packets count: a frame the
/// buffer had nothing for, or asked to have invented, is the buffer's own
/// and says nothing about the far end.
#[derive(Debug, Default)]
struct Spurts {
    /// Whether the last frame out was a packet, whose verdict the next pull
    /// brings.
    decoded: bool,
    speaking: bool,
    run: u16,
    /// The longest recent spurt: the last one's length or, when that was
    /// shorter, a quarter less than the figure before it, so one long
    /// spurt is remembered for the few after it and not for the call.
    length: u16,
}

impl Spurts {
    fn hear(&mut self, activity: Activity) {
        if !core::mem::take(&mut self.decoded) {
            return;
        }
        match activity {
            Activity::Speech if !self.speaking => {
                self.speaking = true;
                self.run = 1;
            }
            Activity::Speech => {}
            Activity::Silence => self.end(),
        }
    }

    /// A frame of the far end's clock played, a packet or its concealment.
    const fn consumed(&mut self) {
        if self.speaking {
            self.run = self.run.saturating_add(1);
        }
    }

    fn end(&mut self) {
        if self.speaking {
            self.speaking = false;
            self.length = self.run.max(self.length - self.length / 4);
            self.run = 0;
        }
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
    /// Packets accepted that the pulls have not yet caught up with: one more
    /// for each arrival, one less for each pull, never below nothing and
    /// never more than is held. A buffer that is starving cannot stretch its
    /// way out of it, so growth waits for evidence that audio is still
    /// arriving. An earpiece that takes two frames at once, on a device
    /// callback twice a packet long, pulls twice for the two packets that
    /// arrived since its last callback, and the second pull has that
    /// evidence as much as the first: counted since the last pull instead,
    /// the second of the pair could never stretch, and its floor held only
    /// on the first.
    arrived: u16,
    anchored: bool,
    playing: bool,
    timing: Timing,
    pace: Pace,
    spurts: Spurts,
    /// The last packet played, as its sequence number and timestamp, which
    /// the next one played is read against to tell an under-run from a
    /// pause.
    last_played: Option<(u16, u32)>,
    /// Pulls since then that had nothing to play: an under-run, or the far
    /// end's pause, which only the next packet played can say.
    silent: u32,
    loss: LossWindow,
    counts: Counters,
    /// RFC 3611 §4.7.2's burst/gap classification, fed exactly once per
    /// sequence number as its fate is finally decided, through
    /// `Self::resolve`: `Received` when a held packet is played (in
    /// [`Self::pull`]) or given up in a pause (`Self::shorten`), `Lost` when
    /// a slot comes due empty, is skipped in a pause, or is passed over, and
    /// `Discarded` when a held-but-unplayed packet is evicted by a window
    /// jump (`Self::slide`), passed over before playout starts
    /// (`Self::pass_over`), or thrown out with the window by
    /// [`Self::restart`] or [`Self::reformat`], whose empty slots are lost.
    /// A packet that turns up after its turn ([`Insert::Late`]) was already
    /// resolved as lost, and within [`LATE_WINDOW`] of the playout point it
    /// is recounted as discarded, as §4.7.1 has it; one whose turn it was
    /// played in is a duplicate, which §4.7.1 excludes outright ("excluding
    /// duplicate packet discards"), as it does an [`Insert::Duplicate`]. A
    /// held-and-accepted packet is not fed here either — it still awaits the
    /// outcome [`Self::pull`] gives it later, and feeding it twice would
    /// double the count.
    gmin: GminTracker,
    /// Which of the last [`LATE_WINDOW`] sequence numbers resolved were
    /// resolved as lost, one bit each, by sequence number: what a packet
    /// turning up late is looked up in.
    resolved_lost: [u64; LATE_WORDS],
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
            pace: Pace::default(),
            spurts: Spurts::default(),
            last_played: None,
            silent: 0,
            loss: LossWindow::new(),
            counts: Counters::default(),
            gmin: GminTracker::new(RECOMMENDED_GMIN),
            resolved_lost: [0; LATE_WORDS],
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
            if self.next.wrapping_sub(sequence) <= LATE_WINDOW && self.take_lost(sequence) {
                self.gmin.late();
            }
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
        if !reordered {
            self.pace
                .arrived(sequence, header.timestamp, header.marker, self.timing.span);
        }

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
    /// for a frame that was never sent; during speech it does not move. The
    /// one exception is a backlog more than two hundred milliseconds over the
    /// top of the band, which is skipped on this pull whatever the frame is.
    pub fn pull(&mut self, activity: Activity) -> Pull<'_> {
        self.pace.pulled();
        self.spurts.hear(activity);
        let arrived = self.arrived.min(self.held);
        self.arrived = arrived.saturating_sub(1);
        if !self.anchored {
            return Pull::Empty;
        }
        // A buffer that ran dry in the middle of a spurt played a frame of
        // silence for it, and that is the frame the caller's verdict is on.
        // It is no pause while the first packet held carries on from the
        // last one played on the far end's clock: every frame waited or
        // stretched on top of it is one more cut out of the far end's words,
        // so it is played as the spurt it is, and the frames in hand are made
        // up in the next real pause.
        let activity = if activity == Activity::Silence && self.silent > 0 && self.resumes() {
            Activity::Speech
        } else {
            activity
        };

        if !self.playing && !self.start(activity) {
            self.note_silence();
            return Pull::Empty;
        }

        // the dead band is two packets wide above the floor, as it is above
        // any target: an earpiece whose frames land near the edge of an
        // arrival sees the queue go one either way from one pull to the
        // next, and a band of one would answer each of those with a stretch
        // or a shrink. One that takes frames two at a time sees it go two,
        // and the band is a packet wider for each
        let floor = self.floor();
        let top = floor.saturating_add(1).saturating_add(self.pace.extra());
        let backlog = self.queued().saturating_sub(top);
        if backlog > self.excess() {
            // more than a pause is worth waiting for, in speech or not
            self.pass_over(backlog);
        }
        let queued = self.queued();
        if activity == Activity::Silence {
            if queued > top {
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
                self.note_silence();
                return Pull::Empty;
            }
            self.resolve(self.next, PacketOutcome::Lost);
            self.advance_base(1);
            self.counts.lost = self.counts.lost.saturating_add(1);
            self.loss.record(true);
            self.spurts.consumed();
            return Pull::Conceal;
        }

        self.resolve(self.next, PacketOutcome::Received);
        self.advance_base(1);
        self.held = self.held.saturating_sub(1);

        let Some(slot) = self.slots.get(index) else {
            // it was filled a moment ago, so this cannot happen either
            return Pull::Empty;
        };
        let (sequence, timestamp, marker) = (slot.sequence, slot.timestamp, slot.marker);
        self.played(sequence, timestamp, marker);

        let Some(slot) = self.slots.get_mut(index) else {
            // nor this, for the same slot
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

    /// The packet the next [`Self::pull`] plays, when it is already held,
    /// without taking it.
    ///
    /// After a [`Pull::Conceal`] it is the packet sent right after the lost
    /// one, if it has arrived: a codec that carries a copy of each frame in
    /// the packet after it (Opus's in-band FEC, RFC 7587 §3.3) rebuilds the
    /// lost frame out of it rather than inventing one. Nothing about the
    /// buffer moves; the next pull plays it as usual.
    #[must_use]
    pub fn following(&self) -> Option<Frame<'_>> {
        if !self.anchored {
            return None;
        }
        let slot = self.slots.get(self.index_of(self.next))?;
        slot.filled.then_some(Frame {
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
        // what was waiting is thrown away, and saying so is the difference
        // between a counter that accounts for every packet taken in and one
        // that quietly loses some
        self.throw_out_window();
        for slot in &mut self.slots {
            slot.filled = false;
        }
        self.held = 0;
        self.arrived = 0;
        self.anchored = false;
        self.playing = false;
        self.timing.restart();
        // the next packet is on another timeline, so neither the pace nor an
        // under-run can be read across to it, and nor can a spurt
        self.pace.restart();
        self.spurts.end();
        self.last_played = None;
        self.silent = 0;
        // the next packet anchors the window afresh, and nothing behind it
        // is known to have been lost
        self.resolved_lost = [0; LATE_WORDS];
    }

    /// Start RFC 3611 §4.7's figures again, for a stream that is now another
    /// source's. §4.7.1's rates are the fraction of packets "from the source
    /// ... since the beginning of reception", and the block names the source
    /// it describes, so what the last source lost or had thrown out is not
    /// the new one's to answer for. `Gmin` stays what it was (§4.7.2).
    /// The buffer's own counters belong to the call and carry on.
    pub(crate) fn begin_source(&mut self) {
        self.gmin = GminTracker::new(self.gmin.gmin());
        self.resolved_lost = [0; LATE_WORDS];
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
        // the same accounting `restart` does, for the same reason: what is in
        // the window belongs to the old format and cannot be played under the
        // new one
        self.throw_out_window();
        let counts = self.counts;
        let gmin = self.gmin;
        *self = Self::new(clock_rate, config);
        self.counts = counts;
        self.gmin = gmin;
    }

    /// Resolve every sequence number from the playout point to the newest
    /// received, as the window is thrown out unplayed: each packet held is
    /// discarded, which is what §4.7.1's discard rate counts and the quality
    /// ratings are computed from as well as the loss, and each slot still
    /// empty is a packet that never arrived and now never will.
    fn throw_out_window(&mut self) {
        let mut discarded = 0_u16;
        for offset in 0..self.queued() {
            let sequence = self.next.wrapping_add(offset);
            let filled = self
                .slots
                .get(self.index_of(sequence))
                .is_some_and(|slot| slot.filled);
            if filled {
                discarded = discarded.saturating_add(1);
                self.resolve(sequence, PacketOutcome::Discarded);
            } else {
                self.counts.lost = self.counts.lost.saturating_add(1);
                self.resolve(sequence, PacketOutcome::Lost);
            }
        }
        self.counts.discarded_overflow = self
            .counts
            .discarded_overflow
            .saturating_add(u64::from(discarded));
    }

    /// Hand the RFC 3611 §4.7 tracker the fate of `sequence`, and remember
    /// whether it was lost, for a packet that turns up after it.
    fn resolve(&mut self, sequence: u16, outcome: PacketOutcome) {
        let bit = usize::from(sequence % LATE_WINDOW);
        if let Some(word) = self.resolved_lost.get_mut(bit / 64) {
            let mask = 1_u64 << (bit % 64);
            if outcome == PacketOutcome::Lost {
                *word |= mask;
            } else {
                *word &= !mask;
            }
        }
        self.gmin.observe(outcome);
    }

    /// Whether `sequence` was resolved as lost, forgetting it if so, so a
    /// second copy of it is the duplicate it is.
    fn take_lost(&mut self, sequence: u16) -> bool {
        let bit = usize::from(sequence % LATE_WINDOW);
        let mask = 1_u64 << (bit % 64);
        self.resolved_lost.get_mut(bit / 64).is_some_and(|word| {
            let lost = *word & mask != 0;
            *word &= !mask;
            lost
        })
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
            underruns: self.counts.underruns,
            silenced: self.counts.silenced,
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
    /// it has to be is given back in its next pause — or, when it is more than
    /// [`EXCESS_MS`] over, on the first pull, by [`JitterBuffer::pull`].
    ///
    /// In a pause it waits for [`IN_HAND`] as well, which is how a spurt from
    /// a far end that sends nothing in its pauses gets its frame in hand. The
    /// buffer is empty at the end of every such pause, and a spurt started on
    /// a single packet would be stretched on the very next pull, a frame the
    /// codec conceals from the last audio it decoded — the end of the spurt
    /// before — played just ahead of the new one. Waiting instead costs the
    /// same frame, played as the pause it falls in.
    fn start(&mut self, activity: Activity) -> bool {
        if self.held == 0 {
            return false;
        }
        let wanted = if activity == Activity::Silence {
            self.floor()
        } else {
            self.target
        };
        let gap = self.leading_gap();
        if self.queued().saturating_sub(gap) < wanted {
            return false;
        }
        self.pass_over(gap);
        let stranded = self.stranded();
        if stranded > 0 {
            self.pass_over(stranded);
            if self.queued() < wanted {
                return false;
            }
        }
        self.playing = true;
        true
    }

    /// Whether the first packet held carries on from the last one played
    /// without the far end having stopped between them.
    fn resumes(&self) -> bool {
        if self.held == 0 {
            return false;
        }
        let span = self.timing.span;
        let head = self
            .slots
            .get(self.index_of(self.next.wrapping_add(self.leading_gap())))
            .filter(|slot| slot.filled);
        match (self.last_played, head) {
            (Some(last), Some(head)) => {
                continues(last, head.sequence, head.timestamp, head.marker, span).is_some()
            }
            _ => false,
        }
    }

    /// The fewest packets a pause leaves queued: the target, or the frames
    /// in hand ([`IN_HAND`]) an earpiece at the pace measured needs to
    /// carry it through a spurt as long as the recent ones without running
    /// dry, whichever is more — and never more in hand than
    /// [`JitterBuffer::drift_ceiling`].
    fn floor(&self) -> u16 {
        let slip = self.pace.in_hand(self.spurts.length);
        // a spurt that spends what is in hand ends with next to nothing
        // queued, and an earpiece that takes two frames at once takes the
        // second of them from that: it is carried in hand as well
        let burst = if slip > 1 { self.pace.extra() } else { 0 };
        let in_hand = slip
            .saturating_add(burst)
            .saturating_add(1)
            .min(self.drift_ceiling());
        self.target.max(in_hand)
    }

    /// The most packets a pause keeps in hand for the earpiece's pace:
    /// [`DRIFT_BUDGET_MS`] of them, never fewer than [`IN_HAND`] and never
    /// more than the buffer's longest delay.
    fn drift_ceiling(&self) -> u16 {
        let budget = u64::from(self.clock_rate) * u64::from(DRIFT_BUDGET_MS) / 1_000;
        let packets = budget / u64::from(self.timing.span.max(1));
        u16::try_from(packets)
            .unwrap_or(u16::MAX)
            .min(self.max_delay)
            .max(IN_HAND)
    }

    /// The most packets held above the top of the dead band before the
    /// buffer stops waiting for a pause to give them back in:
    /// [`EXCESS_MS`] of them, and never none.
    fn excess(&self) -> u16 {
        let budget = u64::from(self.clock_rate) * u64::from(EXCESS_MS) / 1_000;
        let packets = budget / u64::from(self.timing.span.max(1));
        u16::try_from(packets).unwrap_or(u16::MAX).max(1)
    }

    /// A pull with nothing to play. Once something has been played it is
    /// either an under-run or the far end's pause, and which is settled by
    /// the packet played next.
    const fn note_silence(&mut self) {
        if self.last_played.is_some() {
            self.silent = self.silent.saturating_add(1);
        }
    }

    /// A packet played: the silence before it was an under-run if the far
    /// end's clock ran on unbroken from the packet played before it, since
    /// then every frame of that silence was one it had sent, or was
    /// sending, and the earpiece asked for before it came. A packet that
    /// opens a new spurt, or is further on than a few lost ones account for,
    /// says the far end stopped, and the silence was its own pause.
    fn played(&mut self, sequence: u16, timestamp: u32, marker: bool) {
        let span = self.timing.span;
        let on = self
            .last_played
            .and_then(|last| continues(last, sequence, timestamp, marker, span));
        let silent = core::mem::take(&mut self.silent);
        if let Some(step) = on {
            // a packet lost on the way was due in one of those frames: it is
            // counted where the ones lost are, and the frame of silence that
            // stood for it as silenced; the rest of the silence is the
            // earpiece asking before the far end's next packet arrived
            let silenced = silent.min(u32::from(step) - 1);
            let underruns = silent - silenced;
            self.counts.silenced = self.counts.silenced.saturating_add(u64::from(silenced));
            self.counts.underruns = self.counts.underruns.saturating_add(u64::from(underruns));
            for _ in 0..underruns.min(u32::from(LOSS_CAPACITY)) {
                self.loss.record(true);
            }
        } else {
            self.spurts.end();
        }
        self.last_played = Some((sequence, timestamp));
        self.loss.record(false);
        self.spurts.consumed();
        self.spurts.decoded = true;
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

    /// Move the playout point `count` frames on without playing them: before
    /// playout has started, or past a backlog more than [`EXCESS_MS`] over
    /// the dead band. Nobody hears these come due, so what was never there
    /// is loss the counters record rather than frames anyone hears
    /// concealed, and what was held is thrown out of the window unplayed.
    fn pass_over(&mut self, count: u16) {
        for _ in 0..count {
            let index = self.index_of(self.next);
            if let Some(slot) = self.slots.get_mut(index)
                && slot.filled
            {
                slot.filled = false;
                self.held = self.held.saturating_sub(1);
                self.counts.discarded_overflow = self.counts.discarded_overflow.saturating_add(1);
                self.resolve(self.next, PacketOutcome::Discarded);
            } else {
                self.counts.lost = self.counts.lost.saturating_add(1);
                self.resolve(self.next, PacketOutcome::Lost);
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
    ///
    /// For RFC 3611 §4.7 the empty slot is a packet lost like any other. The
    /// frame given up is received: §4.7.1 names what makes a discard — "late
    /// or early arrival, under-run or overflow" — and a frame of a pause that
    /// arrived in time and was dropped by choice is none of them, nor is it
    /// missed by the ear, which is what the ratings computed from the discard
    /// rate stand for. It is still a packet expected, and leaving it out
    /// would take one from §4.7.1's "total number of packets expected" for
    /// every frame given up.
    fn shorten(&mut self) {
        let index = self.index_of(self.next);
        let filled = self.slots.get(index).is_some_and(|slot| slot.filled);
        if filled {
            if let Some(slot) = self.slots.get_mut(index) {
                slot.filled = false;
            }
            self.held = self.held.saturating_sub(1);
            self.counts.shrunk = self.counts.shrunk.saturating_add(1);
            self.resolve(self.next, PacketOutcome::Received);
        } else {
            self.counts.lost = self.counts.lost.saturating_add(1);
            self.resolve(self.next, PacketOutcome::Lost);
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

        // Every one of the `advance` sequence numbers the window just jumped
        // past is resolved right here, once each and in order: those held
        // but never played are RFC 3611 §4.7.1 discards (overflow at "the
        // receiving jitter buffer"); the rest were never received at all
        let mut displaced: u16 = 0;
        let mut sequence = self.next;
        for _ in 0..steps {
            let index = self.index_of(sequence);
            if let Some(slot) = self.slots.get_mut(index)
                && slot.filled
            {
                slot.filled = false;
                displaced = displaced.saturating_add(1);
                self.resolve(sequence, PacketOutcome::Discarded);
            } else {
                self.resolve(sequence, PacketOutcome::Lost);
            }
            sequence = sequence.wrapping_add(1);
        }
        for _ in steps..advance {
            self.resolve(sequence, PacketOutcome::Lost);
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

    use super::{Activity, BufferConfig, DRIFT_BUDGET_MS, Insert, JitterBuffer, MAX_DEPTH, Pull};
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
        // eight thrown out, twice, is a half of what was expected. The
        // target starts at eight, so sixteen held is not a backlog the
        // buffer would give back on its own before the restart
        let mut buffer = buffer(20, 8);
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
        buffer.reformat(RATE, &config(20, 8));
        assert_eq!(buffer.quality().discarded_overflow, 16);
        assert_eq!(
            buffer.burst_gap_metrics().discard_rate,
            128,
            "the stream's figures outlive its format, as its counters do"
        );
    }

    #[test]
    fn a_shrink_in_a_pause_is_accounted_for_in_the_rfc_3611_rates() {
        // 1 never arrives, and a pause drops the empty slot where it would
        // have been, then 3 and 5 to bring the delay down: ten sequence
        // numbers expected, one lost, and a frame given up by choice is none
        // of §4.7.1's causes of a discard
        let mut buffer = buffer(20, 1);
        for sequence in [0_u16, 2, 3, 4, 5, 6, 7, 8, 9] {
            insert(&mut buffer, sequence);
        }
        assert_eq!(pull(&mut buffer), Some(0));
        let mut played = Vec::new();
        for _ in 0..4 {
            if let Pull::Packet(frame) = buffer.pull(Activity::Silence) {
                played.push(frame.sequence);
            }
        }
        while let Some(sequence) = pull(&mut buffer) {
            played.push(sequence);
        }
        assert_eq!(played, vec![2, 4, 6, 7, 8, 9]);
        assert_eq!(buffer.quality().shrunk, 2);
        assert_eq!(buffer.quality().lost, 1);
        let metrics = buffer.burst_gap_metrics();
        assert_eq!(metrics.loss_rate, 25, "one in ten, in 256ths");
        assert_eq!(metrics.discard_rate, 0);
    }

    #[test]
    fn a_packet_that_turns_up_after_its_turn_is_a_discard_and_not_a_loss() {
        // §4.7.1 counts a packet discarded "due to late ... arrival" in the
        // discard rate, and lets a receiver call it lost only for a lateness
        // "significantly greater than that which triggers a discard"
        let mut buffer = buffer(20, 1);
        for sequence in [0_u16, 1, 3] {
            insert(&mut buffer, sequence);
        }
        assert_eq!(pull(&mut buffer), Some(0));
        assert_eq!(pull(&mut buffer), Some(1));
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Conceal));
        assert_eq!(pull(&mut buffer), Some(3));
        assert_eq!(buffer.burst_gap_metrics().loss_rate, 64);

        assert_eq!(insert(&mut buffer, 2), Insert::Late);
        let metrics = buffer.burst_gap_metrics();
        assert_eq!((metrics.loss_rate, metrics.discard_rate), (0, 64));

        // the same packet again, and one that was played arriving a second
        // time, are duplicates, which §4.7.1 leaves out of both
        assert_eq!(insert(&mut buffer, 2), Insert::Late);
        assert_eq!(insert(&mut buffer, 1), Insert::Late);
        let metrics = buffer.burst_gap_metrics();
        assert_eq!((metrics.loss_rate, metrics.discard_rate), (0, 64));
    }

    #[test]
    fn after_a_loss_the_packet_behind_it_can_be_looked_at_without_taking_it() {
        let mut buffer = buffer(20, 1);
        assert!(buffer.following().is_none(), "nothing anchored yet");
        for sequence in [0_u16, 1, 3, 4] {
            insert(&mut buffer, sequence);
        }
        assert_eq!(buffer.following().map(|frame| frame.sequence), Some(0));
        assert_eq!(pull(&mut buffer), Some(0));
        assert_eq!(pull(&mut buffer), Some(1));
        // 2 never came: concealed, and 3 is there to be looked at
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Conceal));
        assert_eq!(buffer.following().map(|frame| frame.sequence), Some(3));
        // looking took nothing: the next pull plays it
        assert_eq!(pull(&mut buffer), Some(3));
        assert_eq!(pull(&mut buffer), Some(4));
        // a gap with nothing behind it yet has nothing to show
        insert(&mut buffer, 7);
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Conceal));
        assert!(buffer.following().is_none(), "6 has not arrived");
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
        for _ in 0..4 {
            if let Pull::Packet(frame) = buffer.pull(Activity::Silence) {
                played.push(frame.sequence);
            }
        }
        assert_eq!(played, vec![1, 3, 5, 6]);
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
        // a frame of the device's time for every packet while it fills, so
        // the pulls have caught up with every arrival when it starts
        for sequence in 0..3 {
            insert(&mut buffer, sequence);
            assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
        }
        insert(&mut buffer, 3);
        assert_eq!(pull(&mut buffer), Some(0));
        assert_eq!(pull(&mut buffer), Some(1));

        // three queued against a target of four, and audio still arriving
        insert(&mut buffer, 4);
        assert!(matches!(buffer.pull(Activity::Silence), Pull::Stretch));
        assert_eq!(buffer.quality().stretched, 1);

        // nothing arrived since that the pulls have not caught up with, so a
        // starving buffer does not stretch itself into a stall
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
        played_against(skew_ppm, pulls, false)
    }

    /// As [`played_against_a_skew`], and with `silent_pauses` the far end
    /// sends nothing in its pauses, as one suppressing silence does: its
    /// sequence numbers run on unbroken, its timestamps jump the pause, and
    /// each spurt opens with a marker. The earpiece then hears a pause as
    /// whatever it played that was not a packet, and what counts as running
    /// dry is a frame without a packet inside a spurt, between one of its
    /// packets and the next.
    fn played_against(skew_ppm: i64, pulls: u32, silent_pauses: bool) -> (JitterBuffer, u32, u32) {
        const FRAME_US: i64 = 20_000;
        let mut buffer = buffer(100, 1);
        let pull_every = FRAME_US * 1_000_000 / (1_000_000 + skew_ppm);
        // half a frame out of step, so no arrival and pull ever coincide
        let mut next_arrival = FRAME_US / 2 + 1;
        let mut tick = FRAME_US;
        let mut sequence = 0_u16;
        let mut sent = 0_u32;
        let (mut played, mut dry, mut pulled) = (0_u32, 0_u32, 0_u32);
        let (mut heard_a_packet, mut empty_since_a_packet) = (false, 0_u32);
        while pulled < pulls {
            let wobble = (i64::from(pulled) * 7_919 % 7 - 3) * 1_000;
            let next_pull = tick + wobble;
            if next_arrival < next_pull {
                let talking = sent % 90 < 60;
                if talking || !silent_pauses {
                    let at = Duration::from_micros(u64::try_from(next_arrival).unwrap());
                    let opens = silent_pauses && sent.is_multiple_of(90);
                    let bytes = spurt_datagram(sequence, sent, opens);
                    let packet = RtpPacket::parse(&bytes).expect("a packet");
                    buffer.insert(&packet, at);
                    sequence = sequence.wrapping_add(1);
                }
                sent += 1;
                next_arrival += FRAME_US;
                continue;
            }
            let activity = if silent_pauses {
                if heard_a_packet {
                    Activity::Speech
                } else {
                    Activity::Silence
                }
            } else if pulled % 90 < 60 {
                Activity::Speech
            } else {
                Activity::Silence
            };
            heard_a_packet = false;
            match buffer.pull(activity) {
                Pull::Packet(frame) => {
                    if silent_pauses && !frame.marker {
                        dry += empty_since_a_packet;
                    }
                    empty_since_a_packet = 0;
                    played += 1;
                    heard_a_packet = true;
                }
                Pull::Empty if silent_pauses => empty_since_a_packet += 1,
                Pull::Empty if played > 0 => dry += 1,
                Pull::Conceal | Pull::Stretch | Pull::Empty => {}
            }
            pulled += 1;
            tick += pull_every;
        }
        (buffer, played, dry)
    }

    /// What an earpiece heard of the lab's cadenced tone, as
    /// `interop/harness` counts it: frames played as silence because the
    /// buffer had nothing, and the runs of that silence that cut the tone
    /// off — that began straight after a frame of it, or ended straight into
    /// one.
    #[derive(Debug, Default)]
    struct Heard {
        dry: u32,
        cuts: u32,
        /// The deepest the buffer was after any pull.
        deepest: Duration,
    }

    /// An earpiece whose clock is `skew_ppm` off the far end's, taking
    /// `per_callback` frames at a time the way a device callback longer than
    /// a frame does, from a far end that sends a packet every frame on a
    /// clean path: sixty frames of tone and thirty of quiet packets, the
    /// lab's cadence. The verdict handed to each pull is the one on the frame
    /// decoded last, as the facade's detector gives it: speech for a frame of
    /// the tone, silence for a quiet one or for a frame of silence played
    /// because the buffer had nothing, and whatever it was for a frame the
    /// buffer asked to have invented, which is built from the one before.
    fn heard_against(skew_ppm: i64, pulls: u32, per_callback: u32) -> (JitterBuffer, Heard) {
        heard_through(skew_ppm, pulls, per_callback, 0)
    }

    /// As [`heard_against`], with verdicts that hold speech for `hangover`
    /// frames after the last frame of the tone, as the facade's detector
    /// does for two hundred milliseconds (`sipral_media::vad`'s
    /// `DEFAULT_HANGOVER_MS`, ten frames): every frame played meanwhile,
    /// quiet packet, silence or stretch, is still called speech.
    fn heard_through(
        skew_ppm: i64,
        pulls: u32,
        per_callback: u32,
        hangover: u32,
    ) -> (JitterBuffer, Heard) {
        const FRAME_US: i64 = 20_000;
        let mut buffer = JitterBuffer::new(RATE, &BufferConfig::new(SPAN));
        let pull_every = FRAME_US * 1_000_000 / (1_000_000 + skew_ppm);
        let mut next_arrival = FRAME_US / 2 + 1;
        let mut tick = pull_every * i64::from(per_callback);
        let mut sent = 0_u32;
        let mut pulled = 0_u32;
        let mut activity = Activity::Silence;
        // frames of speech the detector still owes after the last tone
        let mut held = 0_u32;
        let quieted = |held: &mut u32| {
            if *held > 0 {
                *held -= 1;
                Activity::Speech
            } else {
                Activity::Silence
            }
        };
        let mut heard = Heard::default();
        let (mut started, mut was_tone, mut was_dry, mut counted) = (false, false, false, false);
        while pulled < pulls {
            let wobble = (i64::from(pulled) * 7_919 % 7 - 3) * 1_000;
            if next_arrival < tick + wobble {
                let sequence = u16::try_from(sent % 65_536).unwrap();
                let bytes = spurt_datagram(sequence, sent, false);
                let packet = RtpPacket::parse(&bytes).expect("a packet");
                let at = Duration::from_micros(u64::try_from(next_arrival).unwrap());
                buffer.insert(&packet, at);
                sent += 1;
                next_arrival += FRAME_US;
                continue;
            }
            for _ in 0..per_callback {
                let (tone, dry) = match buffer.pull(activity) {
                    Pull::Packet(frame) => {
                        started = true;
                        let tone = u32::from(frame.sequence) % 90 < 60;
                        activity = if tone {
                            held = hangover;
                            Activity::Speech
                        } else {
                            quieted(&mut held)
                        };
                        (tone, false)
                    }
                    Pull::Empty if started => {
                        heard.dry += 1;
                        activity = quieted(&mut held);
                        (false, true)
                    }
                    Pull::Empty => {
                        activity = quieted(&mut held);
                        (false, false)
                    }
                    Pull::Conceal | Pull::Stretch => {
                        if activity == Activity::Silence || held < hangover {
                            activity = quieted(&mut held);
                        }
                        (false, false)
                    }
                };
                if dry {
                    if was_tone {
                        heard.cuts += 1;
                        counted = true;
                    }
                } else {
                    if tone && was_dry && !counted {
                        heard.cuts += 1;
                    }
                    counted = false;
                }
                was_tone = tone;
                was_dry = dry;
                heard.deepest = heard.deepest.max(buffer.quality().delay);
                pulled += 1;
            }
            tick += pull_every * i64::from(per_callback);
        }
        (buffer, heard)
    }

    /// The `sent`th frame of the far end's clock, carried as `sequence`.
    fn spurt_datagram(sequence: u16, sent: u32, marker: bool) -> Vec<u8> {
        let header = RtpHeader {
            marker,
            payload_type: 0,
            sequence,
            timestamp: sent.wrapping_mul(SPAN),
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

    #[test]
    fn a_spurt_after_a_silent_pause_fills_its_frame_in_hand_rather_than_stretching() {
        // a far end suppressing silence empties the buffer in every pause,
        // and the next spurt starts it again. A spurt that started on one
        // packet and was stretched on the next pull would buy its frame in
        // hand with a frame of concealment built from the end of the spurt
        // before, heard just ahead of the new one; waiting for the second
        // packet buys it with a frame of the pause the earpiece was playing
        // anyway
        for skew in [0, 5_000, -5_000] {
            let (buffer, played, dry) = played_against(skew, 9_000, true);
            let quality = buffer.quality();
            assert_eq!(
                quality.stretched, 0,
                "{skew} ppm: stretched {}",
                quality.stretched
            );
            assert_eq!(
                dry, 0,
                "{skew} ppm: the buffer ran dry {dry} times in a spurt"
            );
            assert_eq!(quality.lost, 0, "{skew} ppm");
            assert!(played >= 5_900, "{skew} ppm: played {played}");
        }
    }

    #[test]
    fn a_fast_earpiece_at_a_one_frame_target_is_stretched_and_never_runs_dry() {
        // 5000 ppm fast: a frame slips every four seconds, sixty in the four
        // minutes of pulls, each of which used to be a frame of silence played
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

    #[test]
    fn an_earpiece_that_takes_two_frames_a_callback_keeps_its_frame_in_hand_on_both() {
        // a callback twice a frame long pulls twice at one instant, for the
        // two packets that arrived since the last one. The second pull is
        // the one that leaves the queue short, and it has to be able to
        // stretch a pause as much as the first; its dead band is as wide as
        // the two frames it takes at once, or a pull either side of an
        // arrival is answered with a stretch and then a shrink
        for skew in [2_000, 5_000] {
            let (buffer, heard) = heard_against(skew, 12_000, 2);
            let quality = buffer.quality();
            assert_eq!(heard.dry, 0, "{skew} ppm: ran dry {} times", heard.dry);
            assert_eq!(heard.cuts, 0, "{skew} ppm");
            let drift = u64::try_from(skew).unwrap() * 12_000 / 1_000_000;
            let net = quality.stretched - quality.shrunk;
            assert!(
                (drift..=drift + 2).contains(&net),
                "{skew} ppm: {drift} frames of drift and the one in hand, stretched {} shrunk {}",
                quality.stretched,
                quality.shrunk
            );
            assert!(quality.shrunk <= 2, "{skew} ppm: shrunk {}", quality.shrunk);
        }
        let (buffer, heard) = heard_against(-2_000, 12_000, 2);
        let quality = buffer.quality();
        assert_eq!(heard.dry, 0);
        assert!(
            (23..=25).contains(&quality.shrunk),
            "each frame of drift dropped from a pause, got {}",
            quality.shrunk
        );
        assert!(quality.stretched <= 1, "stretched {}", quality.stretched);
    }

    #[test]
    fn an_earpiece_that_slips_frames_by_the_handful_in_a_spurt_has_them_in_hand() {
        // 20 000 ppm slips a frame in a second of tone and 50 000 ppm three:
        // a frame in hand is gone before the spurt is. Once the pace and the
        // length of a spurt have been measured, each pause is stretched by
        // what the next spurt will slip, and the buffer runs dry only in the
        // seconds it takes to measure them
        for per_callback in [1, 2] {
            for skew in [20_000, 50_000] {
                let (_, measuring) = heard_against(skew, 3_000, per_callback);
                let (buffer, heard) = heard_against(skew, 24_000, per_callback);
                assert_eq!(
                    (heard.dry, heard.cuts),
                    (measuring.dry, measuring.cuts),
                    "{skew} ppm, {per_callback} a callback: dry and cut after the first minute"
                );
                assert!(
                    heard.dry < 10,
                    "{skew} ppm, {per_callback} a callback: dry {} while measuring",
                    heard.dry
                );
                assert_eq!(buffer.quality().underruns, u64::from(heard.dry));
            }
        }
        // and the same from a far end that sends nothing in its pauses, whose
        // spurts start from an empty buffer: they wait for what is to be in
        // hand, as a pause
        for skew in [20_000, 50_000] {
            let (_, _, measuring) = played_against(skew, 3_000, true);
            let (buffer, _, dry) = played_against(skew, 24_000, true);
            assert_eq!(dry, measuring, "{skew} ppm, silent pauses");
            assert!(
                dry < 10,
                "{skew} ppm, silent pauses: dry {dry} while measuring"
            );
            assert_eq!(buffer.quality().stretched, 0, "{skew} ppm");
        }
    }

    #[test]
    fn a_skew_past_the_drift_budget_runs_dry_rather_than_growing_the_delay() {
        // 500 000 ppm plays three frames for every two sent, and the lab's
        // second-long spurts would need a third of a second in hand to carry
        // it: no device runs so, and a call carrying that much delay is one
        // nobody can talk over. The buffer holds its frames in hand to the
        // budget, runs dry for the rest, and counts each frame it played as
        // nothing, so the call's loss rate says it is in trouble
        let budget = Duration::from_millis(u64::from(DRIFT_BUDGET_MS));
        for per_callback in [1, 2] {
            let (buffer, heard) = heard_against(500_000, 6_000, per_callback);
            let quality = buffer.quality();
            assert!(
                heard.deepest <= budget,
                "{per_callback} a callback: {:?} held",
                heard.deepest
            );
            assert!(
                heard.dry > 1_000,
                "{per_callback} a callback: dry {}",
                heard.dry
            );
            assert_eq!(quality.underruns, u64::from(heard.dry));
            assert!(
                quality.loss_rate >= 0.05,
                "{per_callback} a callback: a loss rate of {}",
                quality.loss_rate
            );
        }
    }

    #[test]
    fn the_detectors_hangover_leaves_a_pause_fewer_frames_to_stretch() {
        // the facade's detector calls the first two hundred milliseconds
        // after the tone speech still, and the buffer stretches only what is
        // called a pause. At any skew a device runs at, the rest of the pause
        // is ample; at one that needs every pull of a pause stretched, the
        // start of each pause runs dry instead — frames nobody hears cut, in
        // the far end's own quiet, and what `scripts/lab.sh drift` measured
        // where this simulation, with exact verdicts, measured none
        for skew in [2_000, 5_000, 50_000] {
            let (_, exact) = heard_against(skew, 6_000, 1);
            let (_, held) = heard_through(skew, 6_000, 1, 10);
            assert!(
                held.dry <= exact.dry + 2,
                "{skew} ppm: {held:?} against {exact:?}"
            );
        }
        let (_, exact) = heard_against(500_000, 6_000, 1);
        let (_, held) = heard_through(500_000, 6_000, 1, 10);
        assert_eq!(held.cuts, exact.cuts, "no more of the tone is cut");
        assert!(
            held.dry > exact.dry + 100,
            "the hangover ran dry {} times to exact verdicts' {}",
            held.dry,
            exact.dry
        );
    }

    #[test]
    fn an_earpiece_that_outruns_the_far_end_counts_the_silence_it_played() {
        let mut buffer = buffer(20, 1);
        insert(&mut buffer, 0);
        assert_eq!(pull(&mut buffer), Some(0));
        // the far end is sending, and its next packet is not here yet
        for _ in 0..3 {
            assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
        }
        insert(&mut buffer, 1);
        assert_eq!(pull(&mut buffer), Some(1));

        let quality = buffer.quality();
        assert_eq!(quality.underruns, 3);
        assert_eq!(quality.lost, 0, "nothing was lost on the way");
        assert!(
            (quality.loss_rate - 0.6).abs() < 1e-6,
            "three of the five frames played were nothing, got {}",
            quality.loss_rate
        );
        // RFC 3611 §4.7.1 counts packets, and no packet was lost or discarded
        let metrics = buffer.burst_gap_metrics();
        assert_eq!((metrics.loss_rate, metrics.discard_rate), (0, 0));
    }

    #[test]
    fn a_pause_or_a_loss_is_not_an_under_run() {
        // a far end suppressing silence stops, and comes back on a new spurt:
        // its timestamps say the frames played as nothing were its pause
        let mut paused = buffer(20, 1);
        let first = spurt_datagram(0, 0, true);
        paused.insert(&RtpPacket::parse(&first).expect("a packet"), FRAME);
        assert_eq!(pull(&mut paused), Some(0));
        for _ in 0..3 {
            assert!(matches!(paused.pull(Activity::Silence), Pull::Empty));
        }
        let next = spurt_datagram(1, 4, true);
        paused.insert(&RtpPacket::parse(&next).expect("a packet"), FRAME * 5);
        assert!(matches!(paused.pull(Activity::Silence), Pull::Empty));
        let after = spurt_datagram(2, 5, false);
        paused.insert(&RtpPacket::parse(&after).expect("a packet"), FRAME * 6);
        assert_eq!(pull(&mut paused), Some(1));
        assert_eq!(paused.quality().underruns, 0);
        assert!(paused.quality().loss_rate < 1e-6);

        // two packets lost on the way and three frames of nothing: two of
        // them are the loss, and one the earpiece being early for the third
        let mut buffer = buffer(20, 1);
        insert(&mut buffer, 0);
        assert_eq!(pull(&mut buffer), Some(0));
        for _ in 0..3 {
            assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
        }
        insert(&mut buffer, 3);
        assert_eq!(pull(&mut buffer), Some(3));
        let quality = buffer.quality();
        assert_eq!((quality.lost, quality.underruns), (2, 1));
        assert_eq!(
            quality.silenced, 2,
            "the two lost were heard as silence, and are counted as such"
        );
    }

    /// Every frame of silence heard while the far end was sending is either
    /// an under-run or a lost packet heard as silence: the two counts
    /// together are the silence, whichever way the loss fell.
    #[test]
    fn the_silence_heard_is_under_runs_and_losses_silenced() {
        let mut buffer = buffer(20, 1);
        insert(&mut buffer, 0);
        assert_eq!(pull(&mut buffer), Some(0));
        let mut heard = 0_u64;
        // one lost with a frame of silence for it; three lost with five
        // frames of silence, two of them early; one lost and concealed from
        // the packet behind it, with no silence at all
        for (next, silence) in [(2_u16, 1), (6, 5)] {
            for _ in 0..silence {
                assert!(matches!(buffer.pull(Activity::Speech), Pull::Empty));
                heard += 1;
            }
            insert(&mut buffer, next);
            assert_eq!(pull(&mut buffer), Some(next));
        }
        insert(&mut buffer, 8);
        assert!(matches!(buffer.pull(Activity::Speech), Pull::Conceal));
        assert_eq!(pull(&mut buffer), Some(8));

        let quality = buffer.quality();
        assert_eq!(quality.lost, 5);
        assert_eq!((quality.silenced, quality.underruns), (4, 2));
        assert_eq!(quality.silenced + quality.underruns, heard);
    }

    /// A minute of call on a clean path after a second and a half nobody
    /// pulled, pulled by an earpiece whose clock runs a hundred parts per
    /// million slow, with a verdict of speech on every frame: a far end that
    /// never pauses, or a detector that never finds the pause. What it
    /// returns is the buffer, how many frames it played, and the deepest it
    /// was once a second of them had been played. `held_up` delivers that
    /// second and a half together at its end, as a receive loop that waited
    /// for a device to open does; otherwise each packet arrives on time and
    /// waits, as early media nobody is playing yet does.
    fn after_a_backlog(held_up: bool) -> (JitterBuffer, u64, Duration) {
        const FRAME_US: u64 = 20_000;
        const BACKLOG: u16 = 75;
        let mut buffer = JitterBuffer::new(RATE, &BufferConfig::new(SPAN));
        let opened = FRAME_US * u64::from(BACKLOG);
        for sequence in 0..BACKLOG {
            let arrival = if held_up {
                opened
            } else {
                u64::from(sequence) * FRAME_US + 3_000
            };
            insert_at(&mut buffer, sequence, Duration::from_micros(arrival));
        }
        let pull_every = FRAME_US * 1_000_100 / 1_000_000;
        let mut next_pull = opened + FRAME_US / 2;
        let mut sequence = BACKLOG;
        let (mut played, mut deepest) = (0_u64, Duration::ZERO);
        // fifty-seven seconds, the length of the call this was seen on
        let end = opened + 57_000_000;
        while next_pull < end {
            let next_arrival = u64::from(sequence) * FRAME_US + 3_000;
            if next_arrival < next_pull {
                insert_at(&mut buffer, sequence, Duration::from_micros(next_arrival));
                sequence += 1;
                continue;
            }
            if let Pull::Packet(_) = buffer.pull(Activity::Speech) {
                played += 1;
            }
            if played > 50 {
                deepest = deepest.max(buffer.quality().delay);
            }
            next_pull += pull_every;
        }
        (buffer, played, deepest)
    }

    /// The delay a backlog leaves behind is given back within the call rather
    /// than kept for the rest of it, in speech as much as in a pause, and is
    /// never more than [`super::EXCESS_MS`] over the top of the dead band —
    /// which, with the longest delay a path's jitter may ask for, bounds it.
    /// What was given back is counted as thrown out, so every packet taken
    /// in is still accounted for.
    #[test]
    fn a_backlog_is_given_back_without_waiting_for_a_pause() {
        let allowance = Duration::from_millis(u64::from(super::EXCESS_MS));
        for held_up in [true, false] {
            let (buffer, played, deepest) = after_a_backlog(held_up);
            let quality = buffer.quality();
            assert!(
                quality.delay <= quality.target_delay + allowance + FRAME * 3,
                "held up {held_up}: the delay is {:?} against a target of {:?}",
                quality.delay,
                quality.target_delay
            );
            assert!(
                deepest <= Duration::from_millis(500) + allowance + FRAME * 3,
                "held up {held_up}: a second into the call the delay was still {deepest:?}"
            );
            assert_eq!(quality.lost, 0);
            assert!(quality.discarded_overflow > 0, "nothing was given back");
            assert_eq!(
                quality.received,
                played + quality.discarded_overflow + quality.shrunk + u64::from(buffer.held()),
                "held up {held_up}: a packet went unaccounted for"
            );
        }
    }
}
