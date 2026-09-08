// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RFC 4733 named telephone events: "telephone-event", DTMF and whatever
//! else the peer's dial plan sends, carried on its own dynamic payload type
//! in the same audio stream (§2.1) as four octets of event code, flags,
//! volume and duration in place of a codec frame.
//!
//! Sending is a state machine per event: a run of packets sharing the RTP
//! timestamp the event began at, duration growing on each one, and the
//! final packet repeated twice after the one that first carries the E bit
//! (§2.5.1.4) — three transmissions in total, since the end of a DTMF digit
//! is the one moment this stack cannot afford to lose to an ordinary
//! dropped packet.
//!
//! Receiving has the opposite problem: those three transmissions, and every
//! duration update sent before them, describe one digit, not several. What
//! identifies an event is its RTP timestamp (§2.2.1: "several RTP packets
//! may carry the same timestamp"), not the order packets happen to arrive
//! in, so the receiver here keys on that and reports once, when a packet
//! says the event ended or when a different timestamp says so by
//! implication — since the end packets are exactly the ones that can be
//! lost.
//!
//! Neither side owns the RTP sequence number or the audio timestamp; §2.1
//! requires both to come from "the same sequence number and timestamp base
//! as the regular audio channel", so this module only ever reads a
//! timestamp it is handed and never advances one on its own.

use crate::playout::Frame;
use crate::wire::put;
use core::fmt;

/// Octets a telephone-event payload takes, after the RTP header (§2.3,
/// Figure 1).
pub const EVENT_LEN: usize = 4;

/// The top of the volume field's range: "Power levels range from 0 to -63
/// dBm0" (§2.3.4), with the sign already dropped, so a quieter tone is a
/// larger number.
pub const MAX_VOLUME: u8 = 63;

/// The largest value the duration field can hold, "sufficient to express
/// event durations of up to approximately 8 seconds" at 8 kHz (§2.3.5).
/// Longer events are meant to be split into further segments (§2.5.1.3): a
/// packet reporting exactly this duration with the E bit still unset,
/// followed by a new segment whose own RTP timestamp picks up where the
/// last one left off. [`EventSender`] does not do this — real DTMF, and even
/// the V.18 text-telephony tones the RFC allows for (§3.1), stay well inside
/// eight seconds, and an event that somehow runs longer simply keeps
/// reporting this maximum until it actually ends, which costs precision on
/// a case this stack has never needed to produce.
pub const MAX_DURATION: u16 = u16::MAX;

/// One telephone-event payload: the four octets Figure 1 in §2.3 lays out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventReport {
    /// Which event this is (§2.3.1). 0-15 are the DTMF digits (§3.2);
    /// [`dtmf_digit`] names them.
    pub event: u8,
    /// Set on the packet that reports the end of the event, or of a segment
    /// (§2.3.2).
    pub end: bool,
    /// The tone's power level in dBm0, magnitude only (§2.3.4). Meaningless,
    /// and left at zero, for an event that is not a tone.
    pub volume: u8,
    /// How long the event has lasted so far, in timestamp ticks, since the
    /// RTP timestamp it began at (§2.3.5).
    pub duration: u16,
}

impl EventReport {
    /// Read a telephone-event payload.
    ///
    /// # Errors
    /// [`EventError::TooShort`] if fewer than [`EVENT_LEN`] octets are
    /// there. The R bit (§2.3.3) is read and discarded, as the RFC asks.
    pub fn parse(payload: &[u8]) -> Result<Self, EventError> {
        let Some(chunk) = payload.first_chunk::<EVENT_LEN>() else {
            return Err(EventError::TooShort { got: payload.len() });
        };
        let [event, flags, d0, d1] = *chunk;
        Ok(Self {
            event,
            end: flags & 0b1000_0000 != 0,
            // the R bit sits at 0b0100_0000; §2.3.3 has the receiver ignore it
            volume: flags & 0b0011_1111,
            duration: u16::from_be_bytes([d0, d1]),
        })
    }

    /// Write the payload into `out`, returning how many octets it took.
    ///
    /// # Errors
    /// [`EventError::Short`] for a buffer smaller than [`EVENT_LEN`], or
    /// [`EventError::Volume`] for a volume wider than the six bits the field
    /// has (§2.3.4).
    pub fn write(&self, out: &mut [u8]) -> Result<usize, EventError> {
        if self.volume > MAX_VOLUME {
            return Err(EventError::Volume(self.volume));
        }
        let Some(out) = out.get_mut(..EVENT_LEN) else {
            return Err(EventError::Short {
                need: EVENT_LEN,
                got: out.len(),
            });
        };
        let flags = (u8::from(self.end) << 7) | self.volume;
        let at = put(out, 0, &[self.event, flags]);
        Ok(put(out, at, &self.duration.to_be_bytes()))
    }
}

/// Why a telephone-event payload could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventError {
    /// Fewer than [`EVENT_LEN`] octets to read.
    TooShort {
        /// What arrived.
        got: usize,
    },
    /// Fewer than [`EVENT_LEN`] octets to write into.
    Short {
        /// Octets the payload needs.
        need: usize,
        /// Octets offered.
        got: usize,
    },
    /// A volume wider than the six bits the field has.
    Volume(u8),
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => write!(f, "{got} octets, {EVENT_LEN} needed"),
            Self::Short { need, got } => write!(f, "payload needs {need} octets, {got} offered"),
            Self::Volume(v) => write!(f, "volume {v} does not fit six bits"),
        }
    }
}

impl core::error::Error for EventError {}

/// The character Table 3 (§3.2) names for event codes 0 through 15: the ten
/// digits, star, hash, and A through D. `None` for anything at or past 16,
/// which is a real event but not a DTMF one.
#[must_use]
pub fn dtmf_digit(event: u8) -> Option<char> {
    match event {
        0..=9 => Some(char::from(b'0' + event)),
        10 => Some('*'),
        11 => Some('#'),
        12..=15 => Some(char::from(b'A' + (event - 12))),
        _ => None,
    }
}

/// One packet's worth of an outgoing event: the timestamp and marker RFC
/// 4733 fixes for the whole event (§2.2), and this transmission's payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// The RTP timestamp every packet of this event carries — the instant
    /// the event began, unmoving for as long as the event lasts (§2.2.1).
    pub timestamp: u32,
    /// Set only on the very first packet sent for this event (§2.5.1.2).
    pub marker: bool,
    /// This transmission's payload.
    pub report: EventReport,
}

/// Drives one outgoing telephone-event through the send procedure of §2.5.1:
/// updates that share a timestamp and grow in duration, then the final
/// packet with the E bit repeated twice more (§2.5.1.4), three
/// transmissions in total.
///
/// This does not touch a sequence number or advance a timestamp of its
/// own — §2.1 requires both to share the audio stream's, so the caller
/// assigns them, the same way it already does for an audio packet.
#[derive(Clone, Copy, Debug)]
pub struct EventSender {
    event: u8,
    volume: u8,
    start_timestamp: u32,
    sent: u32,
    ending: Option<Outgoing>,
    retransmits_left: u8,
}

impl EventSender {
    /// Start reporting `event` at `start_timestamp`, the RTP timestamp of
    /// the audio packet this event replaces.
    #[must_use]
    pub const fn new(event: u8, volume: u8, start_timestamp: u32) -> Self {
        Self {
            event,
            volume,
            start_timestamp,
            sent: 0,
            ending: None,
            retransmits_left: 0,
        }
    }

    /// Which event this reports.
    #[must_use]
    pub const fn event(&self) -> u8 {
        self.event
    }

    /// Whether all three transmissions of the final packet have gone out.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.retransmits_left == 0 && self.ending.is_some()
    }

    /// Build the next update while the event continues. `elapsed` is
    /// timestamp ticks since `start_timestamp`; the sender is expected to
    /// call this once per update interval — RFC 4733 recommends 50 ms
    /// (§2.5.1.2) — for as long as the event is still happening.
    ///
    /// Ticks past what the duration field can hold saturate at
    /// [`MAX_DURATION`] rather than wrapping. Calling this again after
    /// [`EventSender::end`] just hands back the same final packet, since
    /// there is nothing left to update — use [`EventSender::retransmit`] for
    /// the RFC's repeat-on-purpose scheme instead.
    pub fn update(&mut self, elapsed: u32) -> Outgoing {
        self.ending.unwrap_or_else(|| self.build(elapsed, false))
    }

    /// The event has ended. Returns the first of the three transmissions
    /// §2.5.1.4 asks for; call [`EventSender::retransmit`] twice more to
    /// send the other two. Calling this again before those two are sent just
    /// hands back the same packet.
    pub fn end(&mut self, elapsed: u32) -> Outgoing {
        if let Some(ending) = self.ending {
            return ending;
        }
        let outgoing = self.build(elapsed, true);
        self.ending = Some(outgoing);
        self.retransmits_left = 2;
        outgoing
    }

    /// One more transmission of the final packet, byte-identical to what
    /// [`EventSender::end`] returned. `None` once all three have gone out —
    /// there is nothing more to send for this event.
    pub fn retransmit(&mut self) -> Option<Outgoing> {
        let outgoing = self.ending?;
        if self.retransmits_left == 0 {
            return None;
        }
        self.retransmits_left -= 1;
        self.sent = self.sent.saturating_add(1);
        Some(outgoing)
    }

    fn build(&mut self, elapsed: u32, end: bool) -> Outgoing {
        let marker = self.sent == 0;
        self.sent = self.sent.saturating_add(1);
        Outgoing {
            timestamp: self.start_timestamp,
            marker,
            report: EventReport {
                event: self.event,
                end,
                volume: self.volume,
                duration: u16::try_from(elapsed).unwrap_or(MAX_DURATION),
            },
        }
    }
}

/// One event, once it has ended: its code, the character it names if it is
/// a DTMF digit, its volume, how long it lasted, and the timestamp that
/// identified it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported {
    /// The event code (§2.3.1).
    pub event: u8,
    /// The character [`dtmf_digit`] names for `event`, or `None` for an
    /// event at or past 16 — a real event, but not a digit.
    pub digit: Option<char>,
    /// The tone's power level, from whichever packet reported it last.
    pub volume: u8,
    /// The longest duration seen for this event, in timestamp ticks.
    pub duration: u16,
    /// The RTP timestamp that identified the event.
    pub timestamp: u32,
}

/// What one incoming frame did to the event this receiver is following.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not this receiver's payload type, or a packet with nothing left to
    /// say: one of the final packet's other two retransmissions, a stale
    /// duplicate of an event already reported, or a straggler whose
    /// timestamp is behind the event currently open, which belongs to an
    /// event that has already lapsed.
    Ignored,
    /// Extended the event already open. Nothing to report yet.
    Updated,
    /// One event finished — closed by its own end packet, superseded by a
    /// new one whose start proved it was over, or handed back by
    /// [`EventReceiver::flush`].
    Reported(Reported),
}

#[derive(Clone, Copy, Debug)]
struct Open {
    timestamp: u32,
    event: u8,
    volume: u8,
    duration: u16,
}

impl Open {
    fn finish(self) -> Reported {
        Reported {
            event: self.event,
            digit: dtmf_digit(self.event),
            volume: self.volume,
            duration: self.duration,
            timestamp: self.timestamp,
        }
    }
}

/// Half the RTP timestamp clock. A difference smaller than this is ahead of
/// what it was measured from, and one larger is behind it, which is the only
/// way to order two timestamps on a field that wraps.
const HALF_CLOCK: u32 = 1 << 31;

/// Collapses the packets RFC 4733 sends for one event — every duration
/// update, and the final packet's two retransmissions (§2.5.1.4) — into a
/// single reported digit, keyed on the RTP timestamp that identifies the
/// event (§2.2.1), which is the bug a first attempt at this almost always
/// gets wrong: reporting on every packet turns one digit into three or five.
///
/// Meant to sit downstream of the jitter buffer, fed frames in roughly
/// sequence order; a packet whose timestamp is behind the event currently
/// open is dropped rather than placed, since an event that has already
/// lapsed is not one this receiver can still report.
#[derive(Clone, Debug)]
pub struct EventReceiver {
    payload_type: u8,
    open: Option<Open>,
    last_reported: Option<u32>,
}

impl EventReceiver {
    /// Follow `payload_type`, the telephone-event payload type this call's
    /// negotiation settled on — it is chosen dynamically per §2.1, never a
    /// fixed number.
    #[must_use]
    pub const fn new(payload_type: u8) -> Self {
        Self {
            payload_type,
            open: None,
            last_reported: None,
        }
    }

    /// Take in one frame and say what it did.
    ///
    /// # Errors
    /// [`EventError::TooShort`] if the frame carries this receiver's own
    /// payload type but a payload shorter than [`EVENT_LEN`] — a malformed
    /// packet, rather than one to quietly ignore.
    pub fn receive(&mut self, frame: Frame<'_>) -> Result<Outcome, EventError> {
        if frame.payload_type != self.payload_type {
            return Ok(Outcome::Ignored);
        }
        let report = EventReport::parse(frame.payload)?;

        if self.last_reported == Some(frame.timestamp) {
            return Ok(Outcome::Ignored);
        }

        match &mut self.open {
            Some(open) if open.timestamp == frame.timestamp => {
                open.volume = report.volume;
                open.duration = open.duration.max(report.duration);
                if report.end {
                    let open = *open;
                    self.open = None;
                    self.last_reported = Some(frame.timestamp);
                    Ok(Outcome::Reported(open.finish()))
                } else {
                    Ok(Outcome::Updated)
                }
            }
            _ => {
                if !self.is_next_event(frame.timestamp) {
                    return Ok(Outcome::Ignored);
                }
                let closed = self.open.take();
                let fresh = Open {
                    timestamp: frame.timestamp,
                    event: report.event,
                    volume: report.volume,
                    duration: report.duration,
                };
                if let Some(closed) = closed {
                    // a new event started, so whatever was open before is
                    // over -- its own end packets may simply have been lost
                    // (§2.5.2.2's second criterion: "receives the next
                    // tone, distinguished by a different timestamp value").
                    // this packet's own event is not reported yet even if
                    // it already carries the end bit, since a call can only
                    // hand back one finished event and the one that was
                    // already open keeps the reporting order
                    self.open = Some(fresh);
                    self.last_reported = Some(closed.timestamp);
                    return Ok(Outcome::Reported(closed.finish()));
                }
                if report.end {
                    self.last_reported = Some(fresh.timestamp);
                    Ok(Outcome::Reported(fresh.finish()))
                } else {
                    self.open = Some(fresh);
                    Ok(Outcome::Updated)
                }
            }
        }
    }

    /// Whether `timestamp` is ahead of every event this receiver knows
    /// about, which is what makes it the next one.
    ///
    /// §2.5.2.2 closes a tone when the receiver "receives the next tone,
    /// distinguished by a different timestamp value" — the *next* one, later
    /// on the same clock. A timestamp behind what is already open is not a
    /// tone that has started, it is a report for one that has lapsed, and
    /// §2.5.2.2 says further reports for such an event "MUST be ignored".
    /// The two look identical if only the difference from the open event is
    /// tested, which is how a single reordered packet ends up reporting a
    /// digit at the wrong duration and silencing the rest of it.
    fn is_next_event(&self, timestamp: u32) -> bool {
        let Some(known) = self.open.map(|open| open.timestamp).or(self.last_reported) else {
            // nothing has been seen yet, so there is nothing to be stale
            // against
            return true;
        };
        // timestamps wrap, so "later" is the half of the circle ahead of
        // what is known rather than a plain comparison
        (1..HALF_CLOCK).contains(&timestamp.wrapping_sub(known))
    }

    /// The stream went quiet — silence, a payload type change, or the call
    /// ending — so whatever event was open is as over as it is going to
    /// get. This receiver has no clock of its own; the caller decides when
    /// that moment is. `None` if nothing was open.
    pub fn flush(&mut self) -> Option<Reported> {
        let closed = self.open.take()?;
        self.last_reported = Some(closed.timestamp);
        Some(closed.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EVENT_LEN, EventError, EventReceiver, EventReport, EventSender, MAX_DURATION, Outcome,
        Reported, dtmf_digit,
    };
    use crate::playout::Frame;

    fn frame(payload_type: u8, timestamp: u32, payload: &[u8]) -> Frame<'_> {
        Frame {
            sequence: 0,
            timestamp,
            payload_type,
            marker: false,
            payload,
        }
    }

    /// One event payload at volume zero, for the tests that care about which
    /// event and when rather than how loud.
    fn payload(event: u8, end: bool, duration: u16) -> [u8; EVENT_LEN] {
        let mut out = [0_u8; EVENT_LEN];
        EventReport {
            event,
            end,
            volume: 0,
            duration,
        }
        .write(&mut out)
        .expect("room");
        out
    }

    #[test]
    fn a_report_survives_being_written_and_read_back() {
        let report = EventReport {
            event: 7,
            end: true,
            volume: 20,
            duration: 4000,
        };
        let mut out = [0_u8; EVENT_LEN];
        let n = report.write(&mut out).expect("room");
        assert_eq!(n, EVENT_LEN);
        assert_eq!(EventReport::parse(&out).expect("a report"), report);
    }

    #[test]
    fn the_flags_octet_carries_the_bits_the_rfc_puts_there() {
        // §2.3 Figure 1: event, then E, R, volume in the second octet, then
        // duration
        let report = EventReport {
            event: 9,
            end: true,
            volume: 0b0011_1111,
            duration: 0x0102,
        };
        let mut out = [0_u8; EVENT_LEN];
        report.write(&mut out).expect("room");
        assert_eq!(out[0], 9);
        assert_eq!(out[1], 0b1011_1111, "E set, volume fills the low six bits");
        assert_eq!(out[2..4], [0x01, 0x02]);
    }

    #[test]
    fn the_r_bit_is_ignored_on_read() {
        // §2.3.3: "the receiver MUST ignore" it
        let raw = [3_u8, 0b0111_1111, 0, 10]; // E=0, R=1, volume=63
        let report = EventReport::parse(&raw).expect("a report");
        assert!(!report.end);
        assert_eq!(report.volume, 63);
    }

    #[test]
    fn a_payload_shorter_than_four_octets_is_refused() {
        assert_eq!(
            EventReport::parse(&[1, 2, 3]),
            Err(EventError::TooShort { got: 3 })
        );
        assert_eq!(
            EventReport::parse(&[]),
            Err(EventError::TooShort { got: 0 })
        );
    }

    #[test]
    fn writing_into_a_buffer_that_is_too_small_is_refused() {
        let report = EventReport {
            event: 1,
            end: false,
            volume: 0,
            duration: 1,
        };
        let mut out = [0_u8; 3];
        assert_eq!(
            report.write(&mut out),
            Err(EventError::Short {
                need: EVENT_LEN,
                got: 3
            })
        );
    }

    #[test]
    fn a_volume_wider_than_six_bits_is_refused_when_writing() {
        let report = EventReport {
            event: 1,
            end: false,
            volume: 64,
            duration: 1,
        };
        let mut out = [0_u8; EVENT_LEN];
        assert_eq!(report.write(&mut out), Err(EventError::Volume(64)));
    }

    #[test]
    fn the_sixteen_dtmf_codes_name_the_digits_star_hash_and_a_through_d() {
        // §3.2 Table 3
        let expected = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'A', 'B', 'C', 'D',
        ];
        for (event, &digit) in expected.iter().enumerate() {
            assert_eq!(dtmf_digit(u8::try_from(event).unwrap_or(0)), Some(digit));
        }
    }

    #[test]
    fn codes_at_or_past_sixteen_are_not_dtmf_digits() {
        for event in [16_u8, 17, 32, 100, 255] {
            assert_eq!(dtmf_digit(event), None, "event {event} is not a digit");
        }
    }

    #[test]
    fn the_first_packet_of_an_event_carries_the_marker_and_no_others_do() {
        // §2.5.1.2: "The first packet for an event MUST have the M bit
        // set... Intermediate packets ... MUST NOT have either the M bit
        // or the E bit set"
        let mut sender = EventSender::new(5, 10, 1000);
        let first = sender.update(160);
        assert!(first.marker);
        let second = sender.update(320);
        assert!(!second.marker);
        let ended = sender.end(480);
        assert!(!ended.marker);
    }

    #[test]
    fn duration_grows_with_elapsed_time_while_the_timestamp_stays_fixed() {
        // §2.2.1 and §2.5.1.2: same timestamp base, duration cumulative
        let mut sender = EventSender::new(5, 10, 1000);
        let a = sender.update(160);
        let b = sender.update(320);
        assert_eq!(a.timestamp, 1000);
        assert_eq!(b.timestamp, 1000);
        assert_eq!(a.report.duration, 160);
        assert_eq!(b.report.duration, 320);
        assert_eq!(a.report.event, 5);
        assert_eq!(a.report.volume, 10);
        assert!(!a.report.end);
    }

    #[test]
    fn a_duration_past_the_field_width_saturates_rather_than_wrapping() {
        let mut sender = EventSender::new(1, 0, 0);
        let out = sender.update(u32::from(u16::MAX) + 1);
        assert_eq!(
            out.report.duration, MAX_DURATION,
            "not zero, which wrapping would give"
        );
    }

    #[test]
    fn ending_the_event_repeats_the_final_packet_two_more_times_for_three_total() {
        // §2.5.1.4: "sent a total of three times"
        let mut sender = EventSender::new(2, 5, 2000);
        sender.update(160);
        let ended = sender.end(400);
        assert!(ended.report.end);
        assert_eq!(ended.report.duration, 400);
        assert!(!sender.is_done());

        let first_retransmit = sender.retransmit().expect("one more");
        assert_eq!(first_retransmit, ended);
        assert!(!sender.is_done());

        let second_retransmit = sender.retransmit().expect("the last one");
        assert_eq!(second_retransmit, ended);
        assert!(sender.is_done());

        assert_eq!(sender.retransmit(), None);
    }

    #[test]
    fn an_event_that_ends_on_its_first_packet_still_carries_the_marker() {
        let mut sender = EventSender::new(9, 1, 500);
        let ended = sender.end(80);
        assert!(ended.marker);
        assert!(ended.report.end);
        let repeat = sender.retransmit().expect("a repeat");
        assert!(repeat.marker, "the retransmission is the same packet again");
    }

    #[test]
    fn nothing_more_is_sent_once_the_three_transmissions_are_done() {
        let mut sender = EventSender::new(4, 0, 0);
        let ended = sender.end(10);
        sender.retransmit();
        sender.retransmit();
        assert!(sender.is_done());
        assert_eq!(sender.retransmit(), None);
        assert_eq!(sender.update(999), ended, "there is nothing left to update");
    }

    #[test]
    fn three_end_retransmissions_of_one_event_collapse_into_a_single_reported_digit() {
        let mut rx = EventReceiver::new(101);
        let mut out = [0_u8; EVENT_LEN];

        EventReport {
            event: 5,
            end: false,
            volume: 10,
            duration: 160,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Updated));

        EventReport {
            event: 5,
            end: false,
            volume: 10,
            duration: 320,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Updated));

        EventReport {
            event: 5,
            end: true,
            volume: 10,
            duration: 480,
        }
        .write(&mut out)
        .expect("room");
        let end_packet = out;
        let expected = Reported {
            event: 5,
            digit: Some('5'),
            volume: 10,
            duration: 480,
            timestamp: 1000,
        };
        assert_eq!(
            rx.receive(frame(101, 1000, &end_packet)),
            Ok(Outcome::Reported(expected))
        );

        // §2.5.1.4's other two transmissions of the same final packet
        assert_eq!(
            rx.receive(frame(101, 1000, &end_packet)),
            Ok(Outcome::Ignored)
        );
        assert_eq!(
            rx.receive(frame(101, 1000, &end_packet)),
            Ok(Outcome::Ignored)
        );
    }

    #[test]
    fn an_event_is_reported_when_a_new_one_starts_even_without_ever_seeing_its_end_bit() {
        // §2.5.2.2's second criterion: "receives the next tone,
        // distinguished by a different timestamp value" -- because end
        // packets can be lost
        let mut rx = EventReceiver::new(101);
        let mut out = [0_u8; EVENT_LEN];

        EventReport {
            event: 3,
            end: false,
            volume: 7,
            duration: 160,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Updated));

        EventReport {
            event: 7,
            end: false,
            volume: 7,
            duration: 160,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(
            rx.receive(frame(101, 2000, &out)),
            Ok(Outcome::Reported(Reported {
                event: 3,
                digit: Some('3'),
                volume: 7,
                duration: 160,
                timestamp: 1000,
            }))
        );
    }

    #[test]
    fn flush_reports_a_still_open_event_when_the_stream_goes_quiet() {
        let mut rx = EventReceiver::new(101);
        let mut out = [0_u8; EVENT_LEN];
        EventReport {
            event: 9,
            end: false,
            volume: 4,
            duration: 160,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Updated));

        assert_eq!(
            rx.flush(),
            Some(Reported {
                event: 9,
                digit: Some('9'),
                volume: 4,
                duration: 160,
                timestamp: 1000,
            })
        );
        assert_eq!(rx.flush(), None, "nothing left open the second time");
    }

    #[test]
    fn an_event_past_fifteen_is_reported_but_not_pretended_to_be_a_digit() {
        let mut rx = EventReceiver::new(101);
        let mut out = [0_u8; EVENT_LEN];
        EventReport {
            event: 36,
            end: true,
            volume: 0,
            duration: 10,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(
            rx.receive(frame(101, 5000, &out)),
            Ok(Outcome::Reported(Reported {
                event: 36,
                digit: None,
                volume: 0,
                duration: 10,
                timestamp: 5000,
            }))
        );
    }

    #[test]
    fn a_frame_of_another_payload_type_is_ignored_and_does_not_disturb_state() {
        let mut rx = EventReceiver::new(101);
        let mut out = [0_u8; EVENT_LEN];
        EventReport {
            event: 1,
            end: false,
            volume: 0,
            duration: 160,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Updated));

        // an unrelated payload type, even one that happens to parse as an
        // event, is none of this receiver's business
        assert_eq!(
            rx.receive(frame(8, 1000, &[0, 0, 0, 0])),
            Ok(Outcome::Ignored)
        );

        EventReport {
            event: 1,
            end: true,
            volume: 0,
            duration: 320,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(
            rx.receive(frame(101, 1000, &out)),
            Ok(Outcome::Reported(Reported {
                event: 1,
                digit: Some('1'),
                volume: 0,
                duration: 320,
                timestamp: 1000,
            })),
            "the foreign payload type left the open event untouched"
        );
    }

    #[test]
    fn a_malformed_payload_is_an_error_not_a_panic() {
        let mut rx = EventReceiver::new(101);
        assert_eq!(
            rx.receive(frame(101, 1000, &[1, 2])),
            Err(EventError::TooShort { got: 2 })
        );
    }

    #[test]
    fn duration_never_regresses_when_an_update_arrives_out_of_order() {
        let mut rx = EventReceiver::new(101);
        let mut out = [0_u8; EVENT_LEN];

        EventReport {
            event: 6,
            end: false,
            volume: 0,
            duration: 300,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Updated));

        // a smaller duration for the same event: a reordered, stale update
        EventReport {
            event: 6,
            end: false,
            volume: 0,
            duration: 200,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Updated));

        assert_eq!(
            rx.flush().map(|reported| reported.duration),
            Some(300),
            "the stale update did not roll the duration back"
        );
    }

    #[test]
    fn a_stray_repeat_of_an_already_reported_event_does_not_reopen_it() {
        let mut rx = EventReceiver::new(101);
        let mut out = [0_u8; EVENT_LEN];
        EventReport {
            event: 2,
            end: true,
            volume: 0,
            duration: 320,
        }
        .write(&mut out)
        .expect("room");
        assert!(matches!(
            rx.receive(frame(101, 1000, &out)),
            Ok(Outcome::Reported(_))
        ));

        // a much later duplicate of an intermediate update for the same,
        // already-finished event -- reordering wide enough to arrive after
        // the receiver moved on
        EventReport {
            event: 2,
            end: false,
            volume: 0,
            duration: 160,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Ignored));
    }

    #[test]
    fn a_stray_from_an_earlier_event_does_not_disturb_the_one_now_open() {
        let mut rx = EventReceiver::new(101);
        let mut out = [0_u8; EVENT_LEN];

        EventReport {
            event: 1,
            end: false,
            volume: 0,
            duration: 160,
        }
        .write(&mut out)
        .expect("room");
        rx.receive(frame(101, 1000, &out)).expect("read");
        EventReport {
            event: 1,
            end: true,
            volume: 0,
            duration: 320,
        }
        .write(&mut out)
        .expect("room");
        assert!(matches!(
            rx.receive(frame(101, 1000, &out)),
            Ok(Outcome::Reported(_))
        ));

        EventReport {
            event: 2,
            end: false,
            volume: 0,
            duration: 160,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 2000, &out)), Ok(Outcome::Updated));

        // a straggler from the first event, arriving after the second one
        // has already opened
        EventReport {
            event: 1,
            end: true,
            volume: 0,
            duration: 999,
        }
        .write(&mut out)
        .expect("room");
        assert_eq!(rx.receive(frame(101, 1000, &out)), Ok(Outcome::Ignored));

        assert_eq!(
            rx.flush(),
            Some(Reported {
                event: 2,
                digit: Some('2'),
                volume: 0,
                duration: 160,
                timestamp: 2000,
            }),
            "the second event was never touched by the straggler"
        );
    }

    #[test]
    fn a_packet_behind_the_open_event_is_stale_and_does_not_cut_it_short() {
        // §2.5.2.2 closes a tone on "the next tone, distinguished by a
        // different timestamp value" -- a next tone, later on the clock.
        // One tick earlier is a straggler, and taking it for a new event
        // reports the open one at whatever duration it had reached, then
        // swallows every packet it has left, end packet included.
        let mut rx = EventReceiver::new(101);
        assert_eq!(
            rx.receive(frame(101, 1000, &payload(4, false, 160))),
            Ok(Outcome::Updated)
        );
        assert_eq!(
            rx.receive(frame(101, 1000, &payload(4, false, 320))),
            Ok(Outcome::Updated)
        );

        assert_eq!(
            rx.receive(frame(101, 999, &payload(9, false, 80))),
            Ok(Outcome::Ignored),
            "not a digit anyone pressed"
        );

        // and the real event runs to its own end, reported once and whole
        assert_eq!(
            rx.receive(frame(101, 1000, &payload(4, false, 480))),
            Ok(Outcome::Updated)
        );
        assert_eq!(
            rx.receive(frame(101, 1000, &payload(4, true, 640))),
            Ok(Outcome::Reported(Reported {
                event: 4,
                digit: Some('4'),
                volume: 0,
                duration: 640,
                timestamp: 1000,
            }))
        );
        assert_eq!(rx.flush(), None, "with nothing invented left behind it");
    }

    #[test]
    fn a_packet_behind_the_last_reported_event_is_stale_with_nothing_open() {
        // §2.5.2.2: once a receiver can tell a packet "corresponds to an
        // event already played out and lapsed", "further reports for the
        // event MUST be ignored" -- and an event older than the last one
        // reported has certainly lapsed
        let mut rx = EventReceiver::new(101);
        assert_eq!(
            rx.receive(frame(101, 2000, &payload(7, true, 320))),
            Ok(Outcome::Reported(Reported {
                event: 7,
                digit: Some('7'),
                volume: 0,
                duration: 320,
                timestamp: 2000,
            }))
        );

        assert_eq!(
            rx.receive(frame(101, 1000, &payload(3, false, 160))),
            Ok(Outcome::Ignored)
        );
        assert_eq!(
            rx.flush(),
            None,
            "and it did not open an event that would surface at the flush"
        );
    }

    #[test]
    fn an_event_whose_timestamp_wrapped_is_still_the_next_one() {
        // RTP timestamps wrap (RFC 3550 §5.1), and a call that outlasts the
        // 32-bit clock must not have everything after the wrap read as
        // stale
        let mut rx = EventReceiver::new(101);
        let before_wrap = u32::MAX - 80;
        assert_eq!(
            rx.receive(frame(101, before_wrap, &payload(1, false, 160))),
            Ok(Outcome::Updated)
        );
        assert_eq!(
            rx.receive(frame(101, 0, &payload(2, false, 160))),
            Ok(Outcome::Reported(Reported {
                event: 1,
                digit: Some('1'),
                volume: 0,
                duration: 160,
                timestamp: before_wrap,
            })),
            "81 ticks later, on the far side of zero"
        );
    }
}
