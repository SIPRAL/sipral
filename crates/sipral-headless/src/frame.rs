// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The envelope every message on the socket travels in (`docs/07-headless.md`):
//! one byte of kind, a big-endian length, then that many bytes of payload.
//! Audio and control share it, so nothing more specific than "kind" and "how
//! long" lives here — what a kind means is the caller's business, not this
//! module's.
//!
//! The length is big-endian to match the rest of the tree's binary framing
//! ([`crate` sibling `wire` in `sipral-rtp` writes RTP fields the same way);
//! the document does not say, so this is a choice, not a reading. The audio
//! payload inside a frame is little-endian PCM regardless — two different
//! fields, two different reasons to be what they are.

use core::fmt;

/// Bytes of header ahead of the payload: one kind byte, two length bytes.
pub const HEADER_LEN: usize = 3;

/// One message, as a view over the bytes it arrived in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    kind: u8,
    payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Which kind of message this is. What the byte values mean is
    /// [`crate::control::FrameKind`]'s business.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// The payload, exactly as long as the length field said.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Reassembles a byte stream into frames.
///
/// A frame can arrive split across any number of reads — one byte at a time
/// in the worst case — so bytes are accumulated here until a complete frame
/// exists. The length in a frame's header is trusted only up to
/// `max_payload`: past that, [`FrameDecoder::next_frame`] refuses the frame
/// as soon as the three-byte header is available, without waiting for
/// however many bytes the header claims to follow, so a hostile or corrupt
/// header cannot make this allocate space for a payload that will never
/// arrive.
#[derive(Debug)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    start: usize,
    max_payload: usize,
}

impl FrameDecoder {
    /// A decoder that refuses any frame whose declared length exceeds
    /// `max_payload`.
    #[must_use]
    pub fn new(max_payload: u16) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            max_payload: usize::from(max_payload),
        }
    }

    /// Bound every frame not read yet by `max_payload` instead.
    ///
    /// For a reader that learns what its frames may carry only from a frame
    /// it has already read — the session's audio, from
    /// [`crate::SessionOpen`] — and cannot know it when the connection opens.
    /// [`crate::payload_bound`] is the bound a session's audio calls for.
    pub fn set_max_payload(&mut self, max_payload: u16) {
        self.max_payload = usize::from(max_payload);
    }

    /// Take bytes off the transport.
    pub fn push(&mut self, bytes: &[u8]) {
        self.compact();
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame, if one has arrived.
    ///
    /// `Ok(None)` means "not yet"; call again after more bytes. An `Err` is
    /// final — a length that does not fit the session cannot be resynchronised
    /// to, since there is no way to know where the bogus frame actually ends —
    /// so the caller closes the connection.
    ///
    /// # Errors
    /// [`FrameError::PayloadTooLarge`] for a header whose length exceeds what
    /// this decoder was built to accept.
    pub fn next_frame(&mut self) -> Result<Option<Frame<'_>>, FrameError> {
        let Self {
            buf,
            start,
            max_payload,
        } = self;
        let Some(header) = buf
            .get(*start..)
            .and_then(|pending| pending.first_chunk::<HEADER_LEN>())
        else {
            return Ok(None);
        };
        let [kind, len_hi, len_lo] = *header;
        let declared = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        if declared > *max_payload {
            return Err(FrameError::PayloadTooLarge {
                declared,
                max: *max_payload,
            });
        }

        let need = HEADER_LEN + declared;
        let available = buf.len().saturating_sub(*start);
        if available < need {
            return Ok(None);
        }

        let payload_at = *start + HEADER_LEN;
        let payload = buf.get(payload_at..payload_at + declared).unwrap_or(&[]);
        *start += need;
        Ok(Some(Frame { kind, payload }))
    }

    /// How many bytes are held for a frame that is not complete yet.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }

    /// Forget everything, as after the connection was replaced.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.start = 0;
    }

    /// Drop the bytes of frames already handed out.
    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        self.buf.drain(..self.start);
        self.start = 0;
    }
}

/// Write one frame: kind, big-endian length, payload.
///
/// # Errors
/// [`FrameError::PayloadTooLarge`] if `payload` is longer than the sixteen
/// bits of the length field can hold.
pub fn write_frame(kind: u8, payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    let Ok(len) = u16::try_from(payload.len()) else {
        return Err(FrameError::PayloadTooLarge {
            declared: payload.len(),
            max: usize::from(u16::MAX),
        });
    };
    out.reserve(HEADER_LEN + payload.len());
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Why a frame could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The header's length is longer than the session allows, or longer than
    /// the wire format can express at all.
    PayloadTooLarge {
        /// What the header declared, or what a write was asked for.
        declared: usize,
        /// The bound that was exceeded.
        max: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::PayloadTooLarge { declared, max } => {
                write!(f, "payload of {declared} bytes exceeds the limit of {max}")
            }
        }
    }
}

impl core::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::{FrameDecoder, FrameError, write_frame};

    #[test]
    fn a_frame_survives_being_written_and_read_back() {
        let mut out = Vec::new();
        write_frame(7, b"hello", &mut out).expect("written");
        assert_eq!(out, [7, 0, 5, b'h', b'e', b'l', b'l', b'o']);

        let mut decoder = FrameDecoder::new(u16::MAX);
        decoder.push(&out);
        let frame = decoder.next_frame().expect("no error").expect("a frame");
        assert_eq!(frame.kind(), 7);
        assert_eq!(frame.payload(), b"hello");
        assert_eq!(decoder.pending(), 0);
    }

    #[test]
    fn an_empty_payload_is_still_a_frame() {
        let mut out = Vec::new();
        write_frame(1, b"", &mut out).expect("written");
        assert_eq!(out, [1, 0, 0]);

        let mut decoder = FrameDecoder::new(u16::MAX);
        decoder.push(&out);
        let frame = decoder.next_frame().expect("no error").expect("a frame");
        assert!(frame.payload().is_empty());
    }

    #[test]
    fn a_frame_split_across_every_possible_boundary() {
        let mut wire = Vec::new();
        write_frame(3, b"twenty milliseconds", &mut wire).expect("written");

        for cut in 1..wire.len() {
            let mut decoder = FrameDecoder::new(u16::MAX);
            decoder.push(wire.get(..cut).expect("head"));
            assert!(
                decoder.next_frame().expect("no error").is_none(),
                "cut at {cut} produced a frame early"
            );
            decoder.push(wire.get(cut..).expect("tail"));
            let frame = decoder.next_frame().expect("no error").expect("a frame");
            assert_eq!(frame.kind(), 3);
            assert_eq!(frame.payload(), b"twenty milliseconds");
        }
    }

    #[test]
    fn one_byte_at_a_time() {
        let mut wire = Vec::new();
        write_frame(2, b"pcm", &mut wire).expect("written");

        let mut decoder = FrameDecoder::new(u16::MAX);
        for i in 0..wire.len() {
            decoder.push(wire.get(i..=i).expect("one byte"));
            let last = i + 1 == wire.len();
            let got = decoder.next_frame().expect("no error");
            assert_eq!(got.is_some(), last, "at byte {i}");
        }
    }

    #[test]
    fn two_frames_in_one_push_come_out_one_at_a_time() {
        let mut wire = Vec::new();
        write_frame(1, b"first", &mut wire).expect("written");
        write_frame(2, b"second", &mut wire).expect("written");

        let mut decoder = FrameDecoder::new(u16::MAX);
        decoder.push(&wire);
        let first = decoder.next_frame().expect("no error").expect("a frame");
        assert_eq!((first.kind(), first.payload()), (1, b"first".as_slice()));
        let second = decoder.next_frame().expect("no error").expect("a frame");
        assert_eq!((second.kind(), second.payload()), (2, b"second".as_slice()));
        assert!(decoder.next_frame().expect("no error").is_none());
    }

    #[test]
    fn a_length_over_the_session_maximum_is_refused_without_waiting_for_the_payload() {
        // the header alone says this frame cannot fit; a decoder that
        // allocated 60000 bytes and waited for them would be doing exactly
        // what this guards against
        let mut decoder = FrameDecoder::new(10);
        decoder.push(&[0, 0xEA, 0x60]); // kind 0, length 60000
        assert_eq!(
            decoder.next_frame(),
            Err(FrameError::PayloadTooLarge {
                declared: 60_000,
                max: 10,
            })
        );
    }

    #[test]
    fn a_length_at_exactly_the_maximum_is_accepted() {
        let mut decoder = FrameDecoder::new(4);
        let mut wire = Vec::new();
        write_frame(0, b"abcd", &mut wire).expect("written");
        decoder.push(&wire);
        let frame = decoder.next_frame().expect("no error").expect("a frame");
        assert_eq!(frame.payload(), b"abcd");
    }

    #[test]
    fn writing_a_payload_longer_than_u16_is_refused() {
        let mut out = Vec::new();
        let payload = vec![0_u8; usize::from(u16::MAX) + 1];
        assert_eq!(
            write_frame(0, &payload, &mut out),
            Err(FrameError::PayloadTooLarge {
                declared: payload.len(),
                max: usize::from(u16::MAX),
            })
        );
        assert!(out.is_empty());
    }

    #[test]
    fn resetting_forgets_a_half_arrived_frame() {
        let mut decoder = FrameDecoder::new(u16::MAX);
        decoder.push(&[9, 0, 5, b'h', b'i']);
        assert!(decoder.pending() > 0);
        decoder.reset();
        assert_eq!(decoder.pending(), 0);

        let mut wire = Vec::new();
        write_frame(4, b"ok", &mut wire).expect("written");
        decoder.push(&wire);
        let frame = decoder.next_frame().expect("no error").expect("a frame");
        assert_eq!(frame.payload(), b"ok");
    }

    #[test]
    fn the_buffer_does_not_grow_without_bound_across_many_frames() {
        let mut decoder = FrameDecoder::new(u16::MAX);
        let mut wire = Vec::new();
        write_frame(0, b"x", &mut wire).expect("written");
        for _ in 0..500 {
            decoder.push(&wire);
            assert!(decoder.next_frame().expect("no error").is_some());
        }
        assert_eq!(decoder.pending(), 0);
    }
}
