// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Dialling into a call that is already up: the keys, and the schedule
//! `sipral-rtp` has to be driven on to put them on the wire.
//!
//! `sipral-rtp` already writes a named telephone event and already knows what
//! RFC 4733 does to the sequence number and the timestamp when one goes out.
//! What it does not have, because it never sees a frame boundary, is *when* to
//! send the next one. That is here: a queue of digits, and one packet per
//! captured frame, which §2.5.1.2 names as the natural choice — "a natural
//! interval is the spacing between non-event audio packets".
//!
//! A digit replaces the audio for as long as it lasts. That is not a
//! simplification, it is the shape of the payload format: §2.1 has events use
//! the audio stream's own sequence numbers and timestamps, and
//! `RtpSession::send_event` moves the audio clock across the event on the
//! strength of it. Sending the microphone as well would put two things on one
//! clock.
//!
//! # Why there is a queue
//!
//! Somebody entering an extension presses four keys faster than four digits
//! can be sent, and all four have to arrive. So a key pressed while another is
//! going out waits its turn instead of being refused, and the pause between
//! them is held without the application timing anything.

use std::collections::VecDeque;
use std::time::Duration;

use sipral_rtp::{EventSender, Outgoing};

/// The shortest digit legacy equipment will recognise.
///
/// RFC 4733 §2.5.2.1, quoting ITU-T Q.24 Table A-1: the switching equipment
/// surveyed "expects a minimum recognizable signal duration of 40 ms, a
/// minimum pause between signals of 40 ms". Anything shorter is a digit that
/// will be sent and not heard, so it is refused where it is asked for.
pub const SHORTEST_DIGIT: Duration = Duration::from_millis(40);

/// How long a digit lasts unless the application says otherwise.
///
/// The one default RTP, both INFO bodies and the C ABI's own `duration_ms`
/// all fall back to — `sipral_ua::dtmf::DEFAULT_DTMF_MS`, defined once so
/// that no form of DTMF holds a key longer than another when the application
/// does not name a length (8.3.11-bis). Comfortably above the floor, because
/// the floor is what the equipment in that survey managed rather than what a
/// voice response system at the far end of a lossy path will reliably pick
/// out.
pub const DEFAULT_DIGIT: Duration = Duration::from_millis(sipral_ua::dtmf::DEFAULT_DTMF_MS as u64);

/// The longest digit any form sends: `sipral_ua::dtmf::MAX_DTMF_MS`, the
/// ceiling a digit sent or received by INFO is held to, so that no form of
/// DTMF takes a length another refuses (8.3.11).
pub const LONGEST_DIGIT: Duration = Duration::from_millis(10_000);

/// The pause held between one digit and the next, from the same table.
pub const DIGIT_GAP: Duration = Duration::from_millis(60);

/// How loud a digit is sent, in dBm0 below full scale (RFC 4733 §2.3.4).
///
/// Ten is the conventional level for a generated digit: quiet enough not to be
/// clipped anywhere along the path, loud enough that a detector at the far end
/// is not deciding against the noise floor.
pub(crate) const VOLUME: u8 = 10;

/// The most digits that may be waiting.
///
/// A bound rather than a queue that grows: an application dialling from a
/// paste, or a key held down, must not be able to make one call's memory
/// unbounded. Thirty-two is longer than any real number with its prefixes.
pub(crate) const WAITING: usize = 32;

/// One key of a telephone keypad.
///
/// The sixteen RFC 4733 §3.2 gives event codes 0 to 15: the twelve on a
/// telephone, and the four extra columns of the original signalling scheme
/// that some private exchanges still use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Digit {
    /// `0` to `9`.
    Number(u8),
    /// `*`.
    Star,
    /// `#`.
    Hash,
    /// `A` to `D`.
    Letter(u8),
}

impl Digit {
    /// The key a character names, or `None` for a character no keypad has.
    ///
    /// Lower case letters count as their upper case: a dial string from a user
    /// interface is whatever was typed.
    #[must_use]
    pub const fn from_char(key: char) -> Option<Self> {
        match key {
            '0'..='9' => Some(Self::Number(key as u8 - b'0')),
            '*' => Some(Self::Star),
            '#' => Some(Self::Hash),
            'A'..='D' => Some(Self::Letter(key as u8 - b'A')),
            'a'..='d' => Some(Self::Letter(key as u8 - b'a')),
            _ => None,
        }
    }

    /// The character this key carries.
    #[must_use]
    pub const fn as_char(self) -> char {
        match self {
            Self::Number(number) => (b'0' + number % 10) as char,
            Self::Star => '*',
            Self::Hash => '#',
            Self::Letter(letter) => (b'A' + letter % 4) as char,
        }
    }

    /// The event code that carries it (RFC 4733 §3.2).
    #[must_use]
    pub const fn event(self) -> u8 {
        match self {
            Self::Number(number) => number % 10,
            Self::Star => 10,
            Self::Hash => 11,
            Self::Letter(letter) => 12 + letter % 4,
        }
    }
}

impl core::fmt::Display for Digit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buffer = [0_u8; 4];
        f.write_str(self.as_char().encode_utf8(&mut buffer))
    }
}

/// What a captured frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Due {
    /// Nothing is being dialled: the audio goes out as it would have.
    Audio,
    /// One packet of a digit, built for this frame.
    Event {
        /// What to put on the wire.
        outgoing: Outgoing,
        /// Whether this is one of §2.5.1.4's two repeats of the closing
        /// packet. Those report a duration already reported, so they move the
        /// audio clock by nothing and the frame of real time they take has to
        /// be accounted for as silence instead.
        repeat: bool,
    },
}

/// The digits a call still owes, and how far the one going out has got.
#[derive(Debug)]
pub(crate) struct Dialling {
    waiting: VecDeque<(Digit, u32)>,
    sending: Option<Sending>,
    /// Ticks of the pause still owed before the next digit may start.
    gap: u32,
    gap_ticks: u32,
}

#[derive(Clone, Copy, Debug)]
struct Sending {
    sender: EventSender,
    /// Ticks since the event began, which is the duration it reports.
    elapsed: u32,
    /// Ticks of the digit still to run.
    left: u32,
    /// Whether the closing packet has gone.
    ended: bool,
}

impl Dialling {
    /// Hold `gap_ticks` of the stream's own clock between digits.
    pub(crate) const fn new(gap_ticks: u32) -> Self {
        Self {
            waiting: VecDeque::new(),
            sending: None,
            gap: 0,
            gap_ticks,
        }
    }

    /// Add a digit lasting `ticks`, or say the queue is full.
    pub(crate) fn push(&mut self, digit: Digit, ticks: u32) -> bool {
        if self.waiting.len() >= WAITING {
            return false;
        }
        self.waiting.push_back((digit, ticks));
        true
    }

    /// Whether anything is going out or waiting to.
    pub(crate) fn is_busy(&self) -> bool {
        self.sending.is_some() || !self.waiting.is_empty()
    }

    /// How many digits are still waiting their turn.
    pub(crate) fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// Throw away what is queued and stop what is going out.
    ///
    /// The digit in flight does not get its closing packet: a call whose media
    /// is being taken away has nowhere to send one.
    pub(crate) fn clear(&mut self) {
        self.waiting.clear();
        self.sending = None;
        self.gap = 0;
    }

    /// Carry the digits this end still owes across a change of clock rate.
    ///
    /// Everything counted here is counted in the stream's own ticks, and a
    /// codec change moves what a tick is worth. Left alone, a digit queued as
    /// a fifth of a second at eight kilohertz would last a tenth at sixteen,
    /// and the far end would hear a keypress too short to register — the one
    /// failure nobody reports as a bug, because the caller simply presses
    /// again.
    ///
    /// `elapsed` is deliberately not rescaled. It is the duration already
    /// reported on the wire, and RFC 4733 §2.5.1.2 has that field only ever
    /// grow; a rescale downwards would walk it backwards mid-event.
    pub(crate) fn reformat(&mut self, was: u32, now: u32) {
        self.gap_ticks = rescale(self.gap_ticks, was, now);
        self.gap = rescale(self.gap, was, now);
        for (_, ticks) in &mut self.waiting {
            *ticks = rescale(*ticks, was, now);
        }
        if let Some(sending) = self.sending.as_mut() {
            sending.left = rescale(sending.left, was, now);
        }
    }

    /// What this frame carries, given that `frame` ticks pass in it.
    ///
    /// `start` is called only for a digit that is beginning, because the
    /// event's timestamp is the audio stream's at that instant and asking any
    /// earlier would name the wrong one.
    pub(crate) fn next<F>(&mut self, frame: u32, start: F) -> Due
    where
        F: FnOnce(u8) -> EventSender,
    {
        if let Some(due) = self.advance(frame) {
            return due;
        }
        if self.gap > 0 {
            self.gap = self.gap.saturating_sub(frame);
            return Due::Audio;
        }
        let Some((digit, ticks)) = self.waiting.pop_front() else {
            return Due::Audio;
        };
        let mut sender = start(digit.event());
        let elapsed = frame.min(ticks);
        let left = ticks.saturating_sub(frame);
        let outgoing = if left == 0 {
            sender.end(elapsed)
        } else {
            sender.update(elapsed)
        };
        self.sending = Some(Sending {
            sender,
            elapsed,
            left,
            ended: left == 0,
        });
        Due::Event {
            outgoing,
            repeat: false,
        }
    }

    /// The next packet of the digit already going out, if there is one.
    fn advance(&mut self, frame: u32) -> Option<Due> {
        let sending = self.sending.as_mut()?;
        if sending.left > 0 {
            let step = frame.min(sending.left);
            sending.elapsed = sending.elapsed.saturating_add(step);
            sending.left = sending.left.saturating_sub(step);
            let outgoing = if sending.left == 0 {
                sending.ended = true;
                sending.sender.end(sending.elapsed)
            } else {
                sending.sender.update(sending.elapsed)
            };
            return Some(Due::Event {
                outgoing,
                repeat: false,
            });
        }
        if !sending.ended {
            sending.ended = true;
            let outgoing = sending.sender.end(sending.elapsed);
            return Some(Due::Event {
                outgoing,
                repeat: false,
            });
        }
        if let Some(outgoing) = sending.sender.retransmit() {
            return Some(Due::Event {
                outgoing,
                repeat: true,
            });
        }
        self.sending = None;
        self.gap = self.gap_ticks;
        None
    }
}

/// The same span of time, counted in a different clock's ticks.
///
/// Widened to sixty-four bits first: a second of a sixteen-kilohertz digit
/// rescaled from eight would overflow nothing, but a queue full of long
/// digits multiplied before dividing is exactly where a thirty-two bit
/// product stops being one.
fn rescale(ticks: u32, was: u32, now: u32) -> u32 {
    if was == 0 || was == now {
        return ticks;
    }
    let scaled = u64::from(ticks)
        .saturating_mul(u64::from(now))
        .checked_div(u64::from(was))
        .unwrap_or(0);
    u32::try_from(scaled).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DEFAULT_DIGIT, Dialling, Digit, Due, LONGEST_DIGIT, SHORTEST_DIGIT};
    use sipral_rtp::EventSender;

    /// The timestamp the audio stream had when the digit began.
    const BEGAN: u32 = 1_000;

    fn start(event: u8) -> EventSender {
        EventSender::new(event, 10, BEGAN)
    }

    /// The digit, whether the packet closes the event, and the duration it
    /// reports — which is the whole of what a receiver reads.
    fn reported(due: Due) -> Option<(u8, bool, u16, u32, bool)> {
        match due {
            Due::Audio => None,
            Due::Event { outgoing, .. } => Some((
                outgoing.report.event,
                outgoing.report.end,
                outgoing.report.duration,
                outgoing.timestamp,
                outgoing.marker,
            )),
        }
    }

    fn event_of(due: &Due) -> Option<u8> {
        match due {
            Due::Audio => None,
            Due::Event { outgoing, .. } => Some(outgoing.report.event),
        }
    }

    #[test]
    fn every_key_of_a_keypad_has_the_event_code_rfc_4733_assigned_it() {
        for (key, event) in [
            ('0', 0),
            ('9', 9),
            ('*', 10),
            ('#', 11),
            ('A', 12),
            ('D', 15),
        ] {
            let digit = Digit::from_char(key).expect("a key");
            assert_eq!(digit.event(), event, "{key}");
            assert_eq!(digit.as_char(), key);
            assert_eq!(digit.to_string(), key.to_string());
        }
    }

    #[test]
    fn a_lower_case_letter_is_the_same_key_as_the_upper_case_one() {
        assert_eq!(Digit::from_char('b'), Digit::from_char('B'));
        assert_eq!(Digit::from_char('d').map(Digit::event), Some(15));
    }

    #[test]
    fn a_character_no_keypad_has_is_not_a_digit() {
        for key in ['E', 'e', ' ', '+', '\0', 'z', '\u{1F600}'] {
            assert_eq!(Digit::from_char(key), None, "{key:?}");
        }
    }

    #[test]
    fn the_shortest_digit_is_the_one_legacy_equipment_recognises() {
        assert_eq!(SHORTEST_DIGIT.as_millis(), 40);
        assert!(DEFAULT_DIGIT > SHORTEST_DIGIT);
    }

    /// The two lengths an error here names are the bounds the user agent
    /// validates every form against, not a second pair that could drift.
    #[test]
    fn the_bounds_named_here_are_the_ones_every_form_is_held_to() {
        assert_eq!(
            SHORTEST_DIGIT,
            Duration::from_millis(u64::from(sipral_ua::dtmf::MIN_DTMF_MS))
        );
        assert_eq!(
            LONGEST_DIGIT,
            Duration::from_millis(u64::from(sipral_ua::dtmf::MAX_DTMF_MS))
        );
    }

    /// A hundred milliseconds at eight kilohertz is 800 ticks and a frame is
    /// 160, so four updates and then the closing packet, whose duration is the
    /// whole digit. Every packet carries the timestamp the event began at
    /// (§2.5.1.2) and only the first has the marker (§2.5.1.2 again).
    #[test]
    fn a_digit_is_updated_every_frame_and_ends_on_the_frame_it_runs_out() {
        let mut dialling = Dialling::new(480);
        assert!(dialling.push(Digit::Number(5), 800));
        let seen: Vec<_> = (0..8)
            .map(|_| reported(dialling.next(160, start)))
            .collect();
        assert_eq!(
            seen,
            vec![
                Some((5, false, 160, BEGAN, true)),
                Some((5, false, 320, BEGAN, false)),
                Some((5, false, 480, BEGAN, false)),
                Some((5, false, 640, BEGAN, false)),
                Some((5, true, 800, BEGAN, false)),
                Some((5, true, 800, BEGAN, false)),
                Some((5, true, 800, BEGAN, false)),
                None,
            ]
        );
    }

    /// A digit no longer than one frame still gets its closing packet: an
    /// event with none is one the far end never learns has finished. Its one
    /// packet is both the first and the last, so it carries the marker and the
    /// E bit at once, and §2.5.1.4's two repeats of it are the same packet
    /// again — which a receiver reconciles by the timestamp, not by the
    /// marker, since §2.2.1 makes the timestamp what identifies an event.
    #[test]
    fn a_digit_shorter_than_a_frame_still_ends_properly() {
        let mut dialling = Dialling::new(480);
        assert!(dialling.push(Digit::Hash, 100));
        for _ in 0..3 {
            assert_eq!(
                reported(dialling.next(160, start)),
                Some((11, true, 100, BEGAN, true))
            );
        }
        assert_eq!(dialling.next(160, start), Due::Audio);
    }

    /// Three transmissions of the closing packet and no more, which is what
    /// §2.5.1.4 asks for.
    #[test]
    fn the_closing_packet_goes_three_times_and_stops() {
        let mut dialling = Dialling::new(0);
        assert!(dialling.push(Digit::Star, 160));
        let closing = (0..6)
            .map(|_| dialling.next(160, start))
            .filter(|due| matches!(due, Due::Event { outgoing, .. } if outgoing.report.end))
            .count();
        assert_eq!(closing, 3);
    }

    #[test]
    fn a_second_digit_waits_for_the_first_and_for_the_pause_after_it() {
        let mut dialling = Dialling::new(480);
        assert!(dialling.push(Digit::Number(1), 320));
        assert!(dialling.push(Digit::Number(2), 320));
        assert_eq!(dialling.waiting(), 2);

        let seen: Vec<_> = (0..16).map(|_| dialling.next(160, start)).collect();
        let events: Vec<u8> = seen.iter().filter_map(event_of).collect();
        // two frames of digit, then the closing packet's two repeats, each way
        assert_eq!(events, vec![1, 1, 1, 1, 2, 2, 2, 2]);

        let first_two = seen.iter().position(|due| event_of(due) == Some(2));
        let last_one = seen.iter().rposition(|due| event_of(due) == Some(1));
        assert_eq!(
            (first_two, last_one),
            (Some(7), Some(3)),
            "the digits ran together with no pause between them"
        );
        assert!(!dialling.is_busy());
    }

    #[test]
    fn a_queue_that_is_full_refuses_rather_than_growing() {
        let mut dialling = Dialling::new(480);
        for index in 0_u8..32 {
            assert!(
                dialling.push(Digit::Number(index % 10), 800),
                "digit {index} was refused"
            );
        }
        assert!(!dialling.push(Digit::Star, 800));
        assert_eq!(dialling.waiting(), 32);
    }

    #[test]
    fn clearing_stops_what_is_going_out_as_well_as_what_is_waiting() {
        let mut dialling = Dialling::new(480);
        assert!(dialling.push(Digit::Number(7), 800));
        assert!(dialling.push(Digit::Number(8), 800));
        let _ = dialling.next(160, start);
        dialling.clear();
        assert!(!dialling.is_busy());
        assert_eq!(dialling.next(160, start), Due::Audio);
    }

    #[test]
    fn nothing_queued_is_an_ordinary_audio_frame() {
        let mut dialling = Dialling::new(480);
        assert_eq!(dialling.next(160, start), Due::Audio);
        assert!(!dialling.is_busy());
    }
}
