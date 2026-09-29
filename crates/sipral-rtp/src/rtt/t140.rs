// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the octets of a T140block mean once they arrive: ITU-T T.140 text,
//! UTF-8 encoded (RFC 4103 §3.3), with the handful of control characters
//! T.140 gives a meaning to, and the missing-text marker RFC 4103 §5
//! inserts where text was lost.

use super::{BACKSPACE, BOM, LINE_SEPARATOR, MISSING_TEXT};

/// BELL, which T.140 uses as an alert to the other party.
const BELL: char = '\u{7}';
/// ESCAPE, which opens a T.140 control function such as graphic rendition.
const ESCAPE: char = '\u{1B}';
/// PARAGRAPH SEPARATOR, taken as a new line as well.
const PARAGRAPH_SEPARATOR: char = '\u{2029}';
/// The longest control sequence skipped before giving up on it; a sequence
/// that has not ended by then is not one, and what follows is text again.
const MAX_SEQUENCE: u8 = 32;

/// One thing the far end typed, in the order it typed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextEvent {
    /// A character to show.
    Char(char),
    /// Take back the last character shown: BACKSPACE, U+0008, which T.140
    /// defines as erasing the character before the cursor.
    Erase,
    /// Start a new line: LINE SEPARATOR, U+2028, which T.140 names for the
    /// purpose, or the CR LF, CR or LF a sender may use instead, a CR LF
    /// pair counting once even when split across two blocks.
    NewLine,
    /// BELL, U+0007: draw the other party's attention.
    Alert,
    /// Text was lost in transit and could not be recovered: RFC 4103 §5
    /// marks the place with one [`MISSING_TEXT`] per lost span.
    Missing,
}

impl TextEvent {
    /// The character that stands for this event in a plain transcript:
    /// the character itself, [`BACKSPACE`], [`LINE_SEPARATOR`], BELL, or
    /// [`MISSING_TEXT`].
    #[must_use]
    pub const fn as_char(self) -> char {
        match self {
            Self::Char(c) => c,
            Self::Erase => BACKSPACE,
            Self::NewLine => LINE_SEPARATOR,
            Self::Alert => BELL,
            Self::Missing => MISSING_TEXT,
        }
    }
}

/// Where the decoder is inside a control sequence it is skipping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sequence {
    /// Not in one.
    Outside,
    /// ESCAPE seen, nothing after it yet.
    Escape,
    /// ESCAPE `[` seen: a control sequence, running until a final
    /// character in `@` through `~`; the count is how far it has run.
    Control(u8),
}

/// Turns T140block octets into [`TextEvent`]s, keeping whatever state has to
/// survive a block boundary: a UTF-8 sequence cut in two, a CR waiting to
/// see whether an LF follows, a control sequence still running.
#[derive(Clone, Debug)]
pub(crate) struct Decoder {
    partial: [u8; 4],
    have: usize,
    need: usize,
    after_cr: bool,
    sequence: Sequence,
}

impl Decoder {
    pub(crate) const fn new() -> Self {
        Self {
            partial: [0; 4],
            have: 0,
            need: 0,
            after_cr: false,
            sequence: Sequence::Outside,
        }
    }

    /// Forget everything carried over from earlier blocks, as when text
    /// between them was lost: a character cut in two by the loss is not
    /// one any more.
    pub(crate) const fn reset(&mut self) {
        *self = Self::new();
    }

    /// Decode one block's octets, handing each event to `emit`.
    pub(crate) fn feed(&mut self, octets: &[u8], emit: &mut impl FnMut(TextEvent)) {
        for &octet in octets {
            self.octet(octet, emit);
        }
    }

    fn octet(&mut self, octet: u8, emit: &mut impl FnMut(TextEvent)) {
        if self.need > 0 {
            if octet & 0xC0 == 0x80 {
                if let Some(slot) = self.partial.get_mut(self.have) {
                    *slot = octet;
                }
                self.have += 1;
                if self.have == self.need {
                    self.need = 0;
                    let decoded = self
                        .partial
                        .get(..self.have)
                        .and_then(|bytes| core::str::from_utf8(bytes).ok())
                        .and_then(|text| text.chars().next());
                    self.character(decoded.unwrap_or(MISSING_TEXT), emit);
                }
                return;
            }
            // cut short: what was gathered is not a character, and this
            // octet starts afresh
            self.need = 0;
            self.character(MISSING_TEXT, emit);
        }
        let need = match octet {
            0x00..=0x7F => {
                self.character(char::from(octet), emit);
                return;
            }
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => {
                self.character(MISSING_TEXT, emit);
                return;
            }
        };
        self.partial = [octet, 0, 0, 0];
        self.have = 1;
        self.need = need;
    }

    fn character(&mut self, c: char, emit: &mut impl FnMut(TextEvent)) {
        match self.sequence {
            Sequence::Escape => {
                self.sequence = if c == '[' {
                    Sequence::Control(0)
                } else {
                    Sequence::Outside
                };
                return;
            }
            Sequence::Control(run) => {
                self.sequence = if ('@'..='~').contains(&c) || run >= MAX_SEQUENCE {
                    Sequence::Outside
                } else {
                    Sequence::Control(run + 1)
                };
                return;
            }
            Sequence::Outside => {}
        }
        let after_cr = core::mem::replace(&mut self.after_cr, false);
        match c {
            '\r' => {
                self.after_cr = true;
                emit(TextEvent::NewLine);
            }
            '\n' if after_cr => {}
            '\n' | LINE_SEPARATOR | PARAGRAPH_SEPARATOR => emit(TextEvent::NewLine),
            BACKSPACE => emit(TextEvent::Erase),
            BELL => emit(TextEvent::Alert),
            ESCAPE => self.sequence = Sequence::Escape,
            // the byte order mark T.140 opens a session with, a zero-width
            // no-break space anywhere else; either way nothing to show
            BOM => {}
            c if c.is_control() => {}
            c => emit(TextEvent::Char(c)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Decoder, TextEvent};

    fn decode(blocks: &[&[u8]]) -> Vec<TextEvent> {
        let mut decoder = Decoder::new();
        let mut out = Vec::new();
        for block in blocks {
            decoder.feed(block, &mut |event| out.push(event));
        }
        out
    }

    fn chars(text: &str) -> Vec<TextEvent> {
        text.chars().map(TextEvent::Char).collect()
    }

    #[test]
    fn plain_text_is_characters() {
        assert_eq!(decode(&[b"Hello"]), chars("Hello"));
    }

    #[test]
    fn a_character_split_across_blocks_is_put_back_together() {
        // "é" is C3 A9, "€" is E2 82 AC, "😀" is F0 9F 98 80
        let text = "é€😀";
        let bytes = text.as_bytes();
        for cut in 1..bytes.len() {
            let (a, b) = bytes.split_at(cut);
            assert_eq!(decode(&[a, b]), chars(text), "cut at {cut}");
        }
        let single: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(decode(&single), chars(text));
    }

    #[test]
    fn broken_utf8_is_a_replacement_character() {
        // a lead octet followed by ASCII, a stray continuation, an overlong
        // encoding of '/', and a surrogate half
        assert_eq!(
            decode(&[b"\xC3A", b"\x80", b"\xE0\x80\xAF", b"\xED\xA0\x80"]),
            vec![
                TextEvent::Char('\u{FFFD}'),
                TextEvent::Char('A'),
                TextEvent::Char('\u{FFFD}'),
                TextEvent::Char('\u{FFFD}'),
                TextEvent::Char('\u{FFFD}'),
            ]
        );
    }

    #[test]
    fn reset_drops_half_a_character() {
        let mut decoder = Decoder::new();
        let mut out = Vec::new();
        decoder.feed(b"\xE2\x82", &mut |e| out.push(e));
        decoder.reset();
        decoder.feed(b"\xACa", &mut |e| out.push(e));
        assert_eq!(out, vec![TextEvent::Char('\u{FFFD}'), TextEvent::Char('a')]);
    }

    #[test]
    fn backspace_erases() {
        assert_eq!(
            decode(&[b"ab\x08c"]),
            vec![
                TextEvent::Char('a'),
                TextEvent::Char('b'),
                TextEvent::Erase,
                TextEvent::Char('c'),
            ]
        );
    }

    #[test]
    fn every_new_line_convention_is_one_new_line() {
        let expected = vec![
            TextEvent::Char('a'),
            TextEvent::NewLine,
            TextEvent::Char('b'),
        ];
        assert_eq!(decode(&["a\u{2028}b".as_bytes()]), expected);
        assert_eq!(decode(&[b"a\r\nb"]), expected);
        assert_eq!(decode(&[b"a\r", b"\nb"]), expected);
        assert_eq!(decode(&[b"a\nb"]), expected);
        assert_eq!(decode(&[b"a\rb"]), expected);
        assert_eq!(
            decode(&[b"\r\r\n\n"]),
            vec![TextEvent::NewLine, TextEvent::NewLine, TextEvent::NewLine]
        );
    }

    #[test]
    fn the_byte_order_mark_shows_nothing() {
        assert_eq!(decode(&["\u{FEFF}hi".as_bytes()]), chars("hi"));
    }

    #[test]
    fn bell_alerts_and_other_controls_are_dropped() {
        assert_eq!(
            decode(&[b"\x07a\x00\x01\x7Fb", "\u{85}c".as_bytes()]),
            vec![
                TextEvent::Alert,
                TextEvent::Char('a'),
                TextEvent::Char('b'),
                TextEvent::Char('c'),
            ]
        );
    }

    #[test]
    fn control_sequences_are_skipped() {
        // select graphic rendition, split across blocks, then a two-character
        // escape
        assert_eq!(decode(&[b"a\x1B[3", b"1mb\x1Bcd"]), chars("abd"));
        // one that never ends stops being skipped after a bound
        let mut long = b"\x1B[".to_vec();
        long.extend(std::iter::repeat_n(b'1', 40));
        let events = decode(&[&long]);
        assert_eq!(events.len(), 40 - 33);
    }

    #[test]
    fn events_have_a_transcript_character() {
        assert_eq!(TextEvent::Char('x').as_char(), 'x');
        assert_eq!(TextEvent::Erase.as_char(), '\u{8}');
        assert_eq!(TextEvent::NewLine.as_char(), '\u{2028}');
        assert_eq!(TextEvent::Alert.as_char(), '\u{7}');
        assert_eq!(TextEvent::Missing.as_char(), '\u{FFFD}');
    }
}
