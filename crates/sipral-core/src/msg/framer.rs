// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Finding messages in a byte stream.
//!
//! A datagram is its own frame; TCP and TLS are not. RFC 3261 §18.3:
//!
//! > In the case of stream-oriented transports such as TCP, the
//! > Content-Length header field indicates the size of the body. The
//! > Content-Length header field MUST be used with stream oriented
//! > transports.
//!
//! A message without one is refused: reading to the end of the buffer would
//! swallow whatever followed. This is the one copy in the receive path, since
//! a message may arrive across many reads and the parser wants one buffer.
//!
//! Keep-alives (RFC 5626 §4.4.1): a double CRLF is a ping, a single CRLF the
//! pong. Both are skipped and counted, see [`StreamFramer::take_ping`] and
//! [`StreamFramer::take_pong`].
//!
//! Work is bounded per byte received: the header search resumes where it
//! stopped, and nothing is parsed again until the whole body is in.
//!
//! A refused message whose framing is known (head ended, one
//! `Content-Length`) is handed out as [`Framed::Refused`] and the stream reads
//! on. One past [`Limits::max_message_bytes`] is handed out as soon as its
//! head is in, and its body is skipped without being held. Lost framing is a
//! final error.

use super::error::ParseError;
use super::header::HeaderName;
use super::message::RawMessage;
use super::parse::Limits;
use super::parse::{ParseMode, declared_length, parse_with_limits};
use super::span::ParseScratch;

/// What [`StreamFramer::next_message`] found at the front of the stream.
#[derive(Debug)]
pub enum Framed<'a> {
    /// A message, whole and inside every bound.
    Message(RawMessage<'a>),
    /// A message the parser refused, whose framing is still known. The stream
    /// has already moved past it. Only the head is handed out: an answer needs
    /// nothing more (RFC 3261 §8.2.6.2).
    Refused {
        /// The start line and the header fields.
        head: &'a [u8],
        /// The whole message length its head declares.
        length: usize,
        /// Why it was refused; [`ParseError::MessageTooLarge`] whenever the
        /// declared length is past the bound.
        error: ParseError,
    },
}

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
    pongs: u32,
    /// A CRLF read as a pong that may still be the first half of a split ping.
    dangling: bool,
    /// Body bytes of an oversized message still to be skipped.
    discard: usize,
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
            pongs: 0,
            dangling: false,
            discard: 0,
            limits,
        }
    }

    /// Take bytes off the transport.
    ///
    /// Bytes owed to an oversized body are skipped first.
    ///
    /// # Errors
    /// [`ParseError::MessageTooLarge`] when the head grows past the bound
    /// without ending. Nothing then says where the message ends, so the caller
    /// closes the connection.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ParseError> {
        let skipped = self.discard.min(bytes.len());
        self.discard -= skipped;
        let bytes = bytes.get(skipped..).unwrap_or_default();
        self.compact();
        self.buf.extend_from_slice(bytes);
        if self.pending() > self.limits.max_message_bytes as usize && !self.head_fits() {
            return Err(self.too_large());
        }
        Ok(())
    }

    /// The next complete message, if one has arrived.
    ///
    /// `Ok(None)` means not yet. An `Err` is final: the stream cannot be
    /// resynchronised and the connection goes.
    ///
    /// # Errors
    /// [`ParseError::MissingContentLength`],
    /// [`ParseError::ConflictingContentLength`], [`ParseError::BadHeaderLine`]
    /// for a non-numeric `Content-Length`, [`ParseError::MessageTooLarge`] for
    /// a head past the bound.
    pub fn next_message(&mut self, mode: ParseMode) -> Result<Option<Framed<'_>>, ParseError> {
        self.skip_keepalives();

        let ready = match self.need {
            Some(n) => self.pending() >= n,
            None => self.headers_are_complete(),
        };
        if !ready {
            // a head past the bound left behind by the message in front of it
            if self.need.is_none() && self.pending() > self.limits.max_message_bytes as usize {
                return Err(self.too_large());
            }
            return Ok(None);
        }

        let Self {
            buf,
            scratch,
            start,
            scanned,
            need,
            discard,
            limits,
            ..
        } = self;
        let bytes = buf.get(*start..).unwrap_or_default();
        // only the front message: several queued ones may together pass a bound
        let bound = limits.max_message_bytes as usize;
        let window = bytes.get(..bytes.len().min(bound)).unwrap_or_default();
        let error = match parse_with_limits(window, scratch, mode, *limits) {
            Ok(message) => {
                // presence only: the parser already framed the body with it
                if message.header_count(HeaderName::ContentLength) == 0 {
                    return Err(ParseError::MissingContentLength);
                }
                *start += message.len();
                *scanned = *start;
                *need = None;
                return Ok(Some(Framed::Message(message)));
            }
            // The head has ended, so a parser that disagrees stopped at the bound or
            // reads a bare LF differently. Waiting would hold what followed forever.
            Err(error) => error,
        };

        // refused or incomplete: the head says how long it is, or framing is lost
        let (head_len, declared) = match declared_length(bytes) {
            Ok(found) => found,
            Err(ParseError::UnterminatedHeaders) => return Ok(None),
            Err(lost) => return Err(lost),
        };
        let length = head_len.saturating_add(declared as usize);
        let error = if length > bound {
            ParseError::MessageTooLarge {
                limit: limits.max_message_bytes,
            }
        } else if bytes.len() < length {
            *need = Some(length);
            return Ok(None);
        } else {
            error
        };
        let taken = length.min(bytes.len());
        *discard = length - taken;
        let from = *start;
        *start += taken;
        *scanned = *start;
        *need = None;
        let head = buf.get(from..from + head_len).unwrap_or_default();
        Ok(Some(Framed::Refused {
            head,
            length,
            error,
        }))
    }

    /// Consume one keep-alive ping, if one arrived.
    ///
    /// RFC 5626 §4.4.1: a server MUST answer with one CRLF.
    pub fn take_ping(&mut self) -> bool {
        if self.pings == 0 {
            return false;
        }
        self.pings -= 1;
        true
    }

    /// Consume one keep-alive pong, if one arrived.
    /// A ping unanswered for ten seconds means the flow is dead (§4.4.1).
    pub fn take_pong(&mut self) -> bool {
        if self.pongs == 0 {
            return false;
        }
        self.pongs -= 1;
        true
    }

    /// A ping of ours has just gone out on this connection.
    /// A ping of ours has just gone out on this connection.
    ///
    /// The next lone CRLF is the answer to it, not the second half of an
    /// earlier torn ping. Without this, two pongs in a row pair up as a ping.
    pub fn ping_sent(&mut self) {
        self.dangling = false;
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
        self.pongs = 0;
        self.dangling = false;
        self.discard = 0;
    }

    const fn too_large(&self) -> ParseError {
        ParseError::MessageTooLarge {
            limit: self.limits.max_message_bytes,
        }
    }

    /// Whether the head of the message at the front has ended, and inside the
    /// bound.
    fn head_fits(&mut self) -> bool {
        self.headers_are_complete()
            && self.scanned.saturating_sub(self.start) < self.limits.max_message_bytes as usize
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

    /// Skip the CRLFs a peer sends between messages, counting pings and pongs.
    ///
    /// Only whole pairs are consumed: a trailing `\r` may be half a CRLF.
    fn skip_keepalives(&mut self) {
        let mut crlfs = 0_u32;
        while self.buf.get(self.start..self.start + 2) == Some(b"\r\n") {
            self.start += 2;
            crlfs += 1;
        }
        self.scanned = self.scanned.max(self.start);

        // A pair is a ping, an odd CRLF is a pong reported at once: on an idle
        // connection nothing else proves the flow alive. A ping torn across reads
        // counts as a pong and then a ping, and is still answered.
        let run = crlfs + u32::from(self.dangling);
        self.pings += run / 2;
        let odd = run % 2 == 1;
        if odd && !self.dangling {
            self.pongs += 1;
        }
        // a byte that cannot continue the run ends it
        self.dangling = odd && self.buf.get(self.start).is_none_or(|byte| *byte == b'\r');
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
    use super::{Framed, StreamFramer};
    use crate::msg::{Limits, Method, ParseError, ParseMode, RawMessage};

    /// The message a call handed out, which has to be one the parser took.
    fn message(framed: Option<Framed<'_>>) -> RawMessage<'_> {
        match framed {
            Some(Framed::Message(message)) => message,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    /// The head and the error of a message that was refused.
    fn refused(framed: Option<Framed<'_>>) -> (Vec<u8>, usize, ParseError) {
        match framed {
            Some(Framed::Refused {
                head,
                length,
                error,
            }) => (head.to_vec(), length, error),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

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
        let m = message(f.next_message(ParseMode::Strict).expect("no error"));
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
            let m = message(f.next_message(ParseMode::Strict).expect("no error"));
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
            message(f.next_message(ParseMode::Strict).expect("no error")).method(),
            Some(Method::Invite)
        );
        assert_eq!(
            message(f.next_message(ParseMode::Strict).expect("no error")).method(),
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
        assert!(f.take_pong());
        assert!(!f.take_pong());
    }

    #[test]
    fn a_pong_on_its_own_is_seen_without_anything_following_it() {
        // the flow-failure timer depends on this
        let mut f = framer();
        f.push(b"\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(f.take_pong());
        assert!(!f.take_ping());
    }

    #[test]
    fn two_pongs_are_two_pongs_and_not_a_ping() {
        // a CRLF already read as a pong does not pair with the next
        let mut f = framer();
        f.push(b"\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        f.push(INVITE).expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_some()
        );
        f.push(b"\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(f.take_pong());
        assert!(f.take_pong());
        assert!(!f.take_pong());
        assert!(!f.take_ping());
    }

    #[test]
    fn a_pong_to_each_of_two_pings_is_two_pongs_and_not_a_ping() {
        // two pongs on an idle connection answer two pings
        let mut f = framer();
        f.ping_sent();
        f.push(b"\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(f.take_pong());
        f.ping_sent();
        f.push(b"\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(f.take_pong(), "the second ping was answered");
        assert!(!f.take_ping(), "and the answer is not a ping of theirs");
    }

    #[test]
    fn a_ping_torn_in_half_by_the_network_is_still_answered() {
        let mut f = framer();
        f.push(b"\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        f.push(b"\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(f.take_ping());
        assert!(!f.take_ping());
    }

    #[test]
    fn three_crlfs_in_one_read_are_a_ping_and_a_pong() {
        let mut f = framer();
        f.push(b"\r\n\r\n\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        assert!(f.take_ping());
        assert!(!f.take_ping());
        assert!(f.take_pong());
        assert!(!f.take_pong());
    }

    #[test]
    fn a_replaced_connection_forgets_the_keepalives_it_had_counted() {
        let mut f = framer();
        f.push(b"\r\n\r\n\r\n").expect("pushed");
        assert!(
            f.next_message(ParseMode::Strict)
                .expect("no error")
                .is_none()
        );
        f.reset();
        assert!(!f.take_ping());
        assert!(!f.take_pong());
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
    fn a_head_that_passes_the_bound_without_ending_is_refused_as_it_arrives() {
        let mut f = StreamFramer::new(200);
        let mut big = b"INVITE sip:bob@example.com SIP/2.0\r\nSubject: ".to_vec();
        big.extend(std::iter::repeat_n(b'x', 300));
        assert_eq!(
            f.push(&big),
            Err(ParseError::MessageTooLarge { limit: 200 })
        );
    }

    #[test]
    fn a_head_that_passes_the_bound_behind_a_message_that_kept_it_is_refused() {
        let mut f = StreamFramer::new(300);
        let mut two = BYE.to_vec();
        two.extend_from_slice(b"INVITE sip:bob@example.com SIP/2.0\r\nSubject: ");
        two.extend(std::iter::repeat_n(b'x', 400));
        f.push(&two)
            .expect("the head in front ends inside the bound");
        assert_eq!(
            message(f.next_message(ParseMode::Strict).expect("framed")).method(),
            Some(Method::Bye)
        );
        assert_eq!(
            f.next_message(ParseMode::Strict).err(),
            Some(ParseError::MessageTooLarge { limit: 300 })
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
    fn a_malformed_start_line_with_a_length_is_refused_and_the_stream_reads_on() {
        let mut f = framer();
        let mut both = b"NOT A SIP MESSAGE\r\nContent-Length: 0\r\n\r\n".to_vec();
        both.extend_from_slice(BYE);
        f.push(&both).expect("pushed");
        let (_, _, error) = refused(f.next_message(ParseMode::Strict).expect("framed"));
        assert!(
            matches!(error, ParseError::BadStartLine { .. }),
            "{error:?}"
        );
        assert_eq!(
            message(f.next_message(ParseMode::Strict).expect("framed")).method(),
            Some(Method::Bye)
        );
    }

    #[test]
    fn a_refused_message_with_no_length_closes_the_connection() {
        let mut f = framer();
        f.push(b"NOT A SIP MESSAGE\r\nSubject: x\r\n\r\n")
            .expect("pushed");
        assert_eq!(
            f.next_message(ParseMode::Strict).err(),
            Some(ParseError::MissingContentLength)
        );
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
            message(f.next_message(ParseMode::Strict).expect("no error")).method(),
            Some(Method::Bye)
        );
    }

    #[test]
    fn the_parser_bounds_are_carried_through_and_a_message_past_one_is_passed_over() {
        let mut f = StreamFramer::with_limits(Limits {
            max_headers: 2,
            ..Limits::DEFAULT
        });
        let mut both = INVITE.to_vec();
        both.extend_from_slice(b"OPTIONS sip:b@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");
        f.push(&both).expect("pushed");
        let (head, length, error) = refused(f.next_message(ParseMode::Strict).expect("framed"));
        assert_eq!(error, ParseError::TooManyHeaders { limit: 2 });
        assert_eq!(length, INVITE.len());
        assert_eq!(head, INVITE.get(..INVITE.len() - 4).expect("the head"));
        assert_eq!(
            message(f.next_message(ParseMode::Strict).expect("framed")).method(),
            Some(Method::Options)
        );
    }

    #[test]
    fn a_body_past_the_bound_is_refused_once_its_head_is_in_and_passed_over_unheld() {
        let mut f = StreamFramer::new(1_024);
        let head = b"MESSAGE sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP h;branch=z9hG4bK1\r\n\
Content-Length: 5000\r\n\
\r\n";
        let mut stream = head.to_vec();
        stream.extend(std::iter::repeat_n(b'x', 5_000));
        stream.extend_from_slice(BYE);

        let mut refusals = Vec::new();
        let mut after = Vec::new();
        for piece in stream.chunks(700) {
            f.push(piece).expect("the connection stays");
            loop {
                match f.next_message(ParseMode::Strict).expect("framed") {
                    Some(Framed::Refused {
                        head,
                        length,
                        error,
                    }) => {
                        refusals.push((head.to_vec(), length, error));
                    }
                    Some(Framed::Message(m)) => after.push(m.method().map(|m| m.to_string())),
                    None => break,
                }
            }
            assert!(f.pending() <= 1_024, "{} held", f.pending());
        }
        assert_eq!(
            refusals,
            vec![(
                head.to_vec(),
                head.len() + 5_000,
                ParseError::MessageTooLarge { limit: 1_024 }
            )]
        );
        assert_eq!(after, vec![Some("BYE".to_owned())]);
    }

    /// Feed `stream` then `junk` in pieces and report the most the framer ever
    /// held. The connection may close on the way.
    fn most_held(f: &mut StreamFramer, mode: ParseMode, stream: &[u8], junk: usize) -> usize {
        let mut most = 0;
        let filler = vec![b'x'; 512];
        let pieces = std::iter::once(stream).chain(std::iter::repeat_n(&filler[..], junk / 512));
        for piece in pieces {
            if f.push(piece).is_err() {
                return most;
            }
            loop {
                match f.next_message(mode) {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => return most.max(f.pending()),
                }
            }
            most = most.max(f.pending());
        }
        most
    }

    #[test]
    fn a_head_whose_blank_line_straddles_the_bound_is_not_waited_on_forever() {
        // empty line straddling the bound must not count as a head that fits
        for over in 1..=3 {
            let bound = 200;
            let mut head = b"OPTIONS sip:b@example.com SIP/2.0\r\n\
Content-Length: 0\r\nSubject: "
                .to_vec();
            head.extend(std::iter::repeat_n(b'x', bound + over - 4 - head.len()));
            head.extend_from_slice(b"\r\n\r\n");
            assert_eq!(head.len(), bound + over);
            for mode in [ParseMode::Strict, ParseMode::Lenient] {
                let mut f = StreamFramer::new(u32::try_from(bound).expect("small"));
                let kept = most_held(&mut f, mode, &head, 100_000);
                assert!(kept <= 2 * bound, "{over} over, {mode:?}: {kept} held");
            }
        }
    }

    #[test]
    fn a_head_ended_by_bare_line_feeds_is_not_waited_on_forever_when_strict() {
        // framer and strict parser disagree on `\n\n`; one must decide
        let head = b"OPTIONS sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP h;branch=z9hG4bK1\n\
Content-Length: 0\n\
\n";
        let mut f = StreamFramer::new(1_024);
        let kept = most_held(&mut f, ParseMode::Strict, head, 100_000);
        assert!(kept <= 2 * 1_024, "{kept} held");
    }

    #[test]
    fn several_messages_in_one_read_may_pass_the_bound_that_each_one_keeps() {
        let mut f = StreamFramer::new(u32::try_from(BYE.len()).expect("small"));
        let mut three = BYE.to_vec();
        three.extend_from_slice(BYE);
        three.extend_from_slice(BYE);
        f.push(&three).expect("each head ends inside the bound");
        for _ in 0..3 {
            assert_eq!(
                message(f.next_message(ParseMode::Strict).expect("framed")).method(),
                Some(Method::Bye)
            );
        }
        assert_eq!(f.pending(), 0);
    }
}
