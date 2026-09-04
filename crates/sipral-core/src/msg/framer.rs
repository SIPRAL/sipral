// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Finding messages in a byte stream.
//!
//! A datagram is its own frame; TCP and TLS are not. RFC 3261 §18.3:
//!
//! > In the case of stream-oriented transports such as TCP, the
//! > Content-Length header field indicates the size of the body. The
//! > Content-Length header field MUST be used with stream oriented
//! > transports.
//!
//! So a message here without one is refused rather than read to the end of the
//! buffer: guessing would swallow whatever followed it.
//!
//! This is the one place in the receive path that copies. A message can arrive
//! split across any number of reads, and the parser hands out spans into a
//! single contiguous buffer, so the bytes have to be accumulated somewhere.
//!
//! Between messages a peer may send keep-alives (RFC 5626 §4.4.1): a double
//! CRLF is a ping, which a server MUST answer with a single CRLF, and a single
//! CRLF is that answer. They are skipped here and counted, so the layer that
//! owns the connection can reply — see [`StreamFramer::take_ping`].
//!
//! Work is bounded per byte received rather than per call. A peer that feeds
//! one byte at a time cannot make this re-scan the whole pending buffer each
//! time: the search for the end of the headers resumes where it stopped, and
//! once the body's length is known nothing is parsed again until that many
//! bytes are actually there.

use super::error::ParseError;
use super::header::HeaderName;
use super::message::RawMessage;
use super::parse::Limits;
use super::parse::{ParseMode, parse_with_limits};
use super::span::ParseScratch;

/// Reassembles a stream into messages.
#[derive(Debug)]
pub struct StreamFramer {
    buf: Vec<u8>,
    scratch: ParseScratch,
    /// Where the message being assembled begins.
    start: usize,
    /// How far the search for the end of the headers has got.
    scanned: usize,
    /// Total bytes this message needs, once the body's length is known.
    need: Option<usize>,
    pings: u32,
    limits: Limits,
}

impl StreamFramer {
    /// A framer that refuses a message longer than `max_message_bytes`.
    #[must_use]
    pub fn new(max_message_bytes: u32) -> Self {
        Self::with_limits(Limits {
            max_message_bytes,
            ..Limits::DEFAULT
        })
    }

    /// A framer with the parser's other bounds set too.
    #[must_use]
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            buf: Vec::new(),
            scratch: ParseScratch::new(),
            start: 0,
            scanned: 0,
            need: None,
            pings: 0,
            limits,
        }
    }

    /// Take bytes off the transport.
    ///
    /// # Errors
    /// [`ParseError::MessageTooLarge`] when the message being assembled grows
    /// past the bound. There is no recovering from that on a stream — the
    /// framing is lost — so the caller closes the connection.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ParseError> {
        self.compact();
        self.buf.extend_from_slice(bytes);
        if self.pending() > self.limits.max_message_bytes as usize {
            return Err(ParseError::MessageTooLarge {
                limit: self.limits.max_message_bytes,
            });
        }
        Ok(())
    }

    /// The next complete message, if one has arrived.
    ///
    /// `Ok(None)` means "not yet"; call again after more bytes. An `Err` is
    /// final: a stream whose framing is wrong cannot be resynchronised, so
    /// the connection goes.
    ///
    /// # Errors
    /// [`ParseError::MissingContentLength`] for a message that cannot be
    /// framed, and whatever [`parse_with_limits`] refused otherwise.
    pub fn next_message(&mut self, mode: ParseMode) -> Result<Option<RawMessage<'_>>, ParseError> {
        self.skip_keepalives();

        let ready = match self.need {
            // once the length is known, nothing is parsed again until the
            // bytes are actually here
            Some(n) => self.pending() >= n,
            None => self.headers_are_complete(),
        };
        if !ready {
            return Ok(None);
        }

        let Self {
            buf,
            scratch,
            start,
            scanned,
            need,
            limits,
            ..
        } = self;
        let bytes = buf.get(*start..).unwrap_or_default();
        match parse_with_limits(bytes, scratch, mode, *limits) {
            Ok(message) => {
                // presence, not value: the parser has already framed the body
                // with it, and two that agree are its business, not ours
                if message.header_count(HeaderName::ContentLength) == 0 {
                    return Err(ParseError::MissingContentLength);
                }
                *start += message.len();
                *scanned = *start;
                *need = None;
                Ok(Some(message))
            }
            Err(ParseError::BodyTruncated {
                declared,
                available,
            }) => {
                *need = Some(
                    (*buf).len().saturating_sub(*start)
                        + (declared as usize).saturating_sub(available as usize),
                );
                Ok(None)
            }
            Err(ParseError::UnterminatedHeaders) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Consume one keep-alive ping, if one arrived.
    ///
    /// RFC 5626 §4.4.1 makes answering it a MUST for a server: one CRLF back,
    /// on the same connection.
    pub fn take_ping(&mut self) -> bool {
        if self.pings == 0 {
            return false;
        }
        self.pings -= 1;
        true
    }

    /// How many bytes are held for a message that is not complete yet.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }

    /// Forget everything, as after the connection was replaced.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.start = 0;
        self.scanned = 0;
        self.need = None;
        self.pings = 0;
    }

    /// Drop the bytes of messages already handed out.
    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        self.buf.drain(..self.start);
        self.scanned = self.scanned.saturating_sub(self.start);
        self.start = 0;
    }

    /// Skip the CRLFs a peer sends between messages, counting the pings.
    ///
    /// Only whole pairs are consumed: a lone `\r` at the end of the buffer is
    /// half of a CRLF that has not finished arriving, and eating it would
    /// desynchronise the very next message.
    fn skip_keepalives(&mut self) {
        let mut crlfs = 0_u32;
        while self.buf.get(self.start..self.start + 2) == Some(b"\r\n") {
            self.start += 2;
            crlfs += 1;
        }
        // a double CRLF is the ping; an odd one left over is the pong coming
        // back, or padding, and needs no answer
        self.pings += crlfs / 2;
        self.scanned = self.scanned.max(self.start);
    }

    /// Whether the blank line that ends the headers has arrived, resuming the
    /// search where it stopped last time.
    fn headers_are_complete(&mut self) -> bool {
        let from = self.scanned.max(self.start).saturating_sub(3);
        let Some(window) = self.buf.get(from..) else {
            return false;
        };
        if let Some(at) = find_blank_line(window) {
            self.scanned = from + at;
            return true;
        }
        self.scanned = self.buf.len();
        false
    }
}

/// Where the empty line that ends the header block begins.
fn find_blank_line(window: &[u8]) -> Option<usize> {
    window
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| window.windows(2).position(|w| w == b"\n\n"))
}

#[cfg(test)]
mod tests {
    use super::StreamFramer;
    use crate::msg::{Limits, Method, ParseError, ParseMode};

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 4\r\n\
\r\n\
v=0\n";

    const BYE: &[u8] = b"BYE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK2\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=2\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 2 BYE\r\n\
Content-Length: 0\r\n\
\r\n";

    fn framer() -> StreamFramer {
        StreamFramer::new(65_535)
    }

    #[test]
    fn a_whole_message_in_one_read() {
        let mut f = framer();
        f.push(INVITE).expect("pushed");
        let m = f
            .next_message(ParseMode::Strict)
            .expect("no error")
            .expect("a message");
        assert_eq!(m.method(), Some(Method::Invite));
        assert_eq!(m.body(), b"v=0\n");
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn a_message_split_across_every_possible_boundary() {
        for cut in 1..INVITE.len() {
            let mut f = framer();
            f.push(INVITE.get(..cut).expect("head")).expect("pushed");
            assert!(
                f.next_message(ParseMode::Strict)
                    .expect("no error")
                    .is_none(),
                "cut at {cut} produced a message early"
            );
            f.push(INVITE.get(cut..).expect("tail")).expect("pushed");
            let m = f
                .next_message(ParseMode::Strict)
                .expect("no error")
                .expect("a message");
            assert_eq!(m.method(), Some(Method::Invite));
            assert_eq!(m.body(), b"v=0\n");
        }
    }

    #[test]
    fn one_byte_at_a_time() {
        let mut f = framer();
        for i in 0..INVITE.len() {
            f.push(INVITE.get(i..=i).expect("one byte"))
                .expect("pushed");
            let last = i + 1 == INVITE.len();
            let got = f.next_message(ParseMode::Strict).expect("no error");
            assert_eq!(got.is_some(), last, "at byte {i}");
        }
    }

    #[test]
    fn two_messages_in_one_read_come_out_one_at_a_time() {
        let mut f = framer();
        let mut both = INVITE.to_vec();
        both.extend_from_slice(BYE);
        f.push(&both).expect("pushed");

        assert_eq!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .expect("first")
                .method(),
            Some(Method::Invite)
        );
        assert_eq!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .expect("second")
                .method(),
            Some(Method::Bye)
        );
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
    }

    #[test]
    fn a_keepalive_between_messages_is_skipped_and_counted() {
        // RFC 5626 4.4.1: double CRLF is a ping, single CRLF the answer
        let mut f = framer();
        f.push(b"\r\n\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(f.take_ping());
        assert!(!f.take_ping());

        f.push(b"\r\n").expect("pushed");
        f.push(INVITE).expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_some()
        );
        // a lone CRLF is the pong coming back, and needs no answer
        assert!(!f.take_ping());
    }

    #[test]
    fn half_a_crlf_is_not_consumed_until_the_rest_arrives() {
        let mut f = framer();
        f.push(b"\r").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert_eq!(f.pending(), 1);
        f.push(b"\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn a_message_without_content_length_cannot_be_framed() {
        // RFC 3261 18.3 makes the field mandatory on a stream
        let mut f = framer();
        f.push(
            b"OPTIONS sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP h;branch=z9hG4bK1\r\n\
\r\n",
        )
        .expect("pushed");
        assert_eq!(
            f.next_message(ParseMode::Strict).err(),
            Some(ParseError::MissingContentLength)
        );
    }

    #[test]
    fn a_message_larger_than_the_bound_is_refused_as_it_arrives() {
        let mut f = StreamFramer::new(200);
        let mut big = INVITE.to_vec();
        big.extend(std::iter::repeat_n(b'x', 300));
        assert_eq!(
            f.push(&big),
            Err(ParseError::MessageTooLarge { limit: 200 })
        );
    }

    #[test]
    fn a_body_that_never_finishes_arriving_stays_pending() {
        let mut f = framer();
        f.push(
            b"MESSAGE sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP h;branch=z9hG4bK1\r\n\
Content-Length: 100\r\n\
\r\n\
short",
        )
        .expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(f.pending() > 0);
    }

    #[test]
    fn conflicting_content_lengths_close_the_connection() {
        // RFC 4475 3.3.9 mcl01: "the framing error is not recoverable, and
        // the connection should be closed"
        let mut f = framer();
        f.push(
            b"OPTIONS sip:user@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP host5.example.net;branch=z9hG4bK293423\r\n\
Content-Length: 13\r\n\
Max-Forwards: 60\r\n\
Content-Length: 5\r\n\
\r\n\
There is no way to know how many octets belong here.",
        )
        .expect("pushed");
        assert!(matches!(
            f.next_message(ParseMode::Strict),
            Err(ParseError::ConflictingContentLength { .. })
        ));
    }

    #[test]
    fn a_malformed_start_line_is_an_error_the_connection_does_not_survive() {
        let mut f = framer();
        f.push(b"NOT A SIP MESSAGE\r\nContent-Length: 0\r\n\r\n")
            .expect("pushed");
        assert!(matches!(
            f.next_message(ParseMode::Strict),
            Err(ParseError::BadStartLine { .. })
        ));
    }

    #[test]
    fn the_buffer_does_not_grow_without_bound_across_messages() {
        let mut f = framer();
        for _ in 0..50 {
            f.push(BYE).expect("pushed");
            assert!(
                f.next_message(ParseMode::Strict)
                    .expect("no error")
                    .is_some()
            );
        }
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn resetting_forgets_a_half_arrived_message() {
        let mut f = framer();
        f.push(INVITE.get(..40).expect("head")).expect("pushed");
        assert!(f.pending() > 0);
        f.reset();
        assert_eq!(f.pending(), 0);
        f.push(BYE).expect("pushed");
        assert_eq!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .expect("a message")
                .method(),
            Some(Method::Bye)
        );
    }

    #[test]
    fn the_parser_bounds_are_carried_through() {
        let mut f = StreamFramer::with_limits(Limits {
            max_headers: 2,
            ..Limits::DEFAULT
        });
        f.push(INVITE).expect("pushed");
        assert!(matches!(
            f.next_message(ParseMode::Strict),
            Err(ParseError::TooManyHeaders { .. })
        ));
    }
}
