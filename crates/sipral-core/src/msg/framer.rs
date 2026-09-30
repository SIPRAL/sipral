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
//! CRLF is that answer. They are skipped here and counted separately, so the
//! layer that owns the connection can reply to one and take the other as proof
//! the flow is alive — see [`StreamFramer::take_ping`] and
//! [`StreamFramer::take_pong`].
//!
//! Work is bounded per byte received rather than per call. A peer that feeds
//! one byte at a time cannot make this re-scan the whole pending buffer each
//! time: the search for the end of the headers resumes where it stopped, and
//! once the body's length is known nothing is parsed again until that many
//! bytes are actually there.
//!
//! A message the parser refuses does not cost the connection when its
//! framing is still known — its head ended, and named exactly one
//! `Content-Length`. It is handed out as [`Framed::Refused`], for the layer
//! above to answer, and the stream reads on after it. One longer than
//! [`Limits::max_message_bytes`] is handed out the same way the moment its
//! head is in, and the rest of its body is passed over as it arrives without
//! ever being held. Only framing that is lost — a head longer than the bound,
//! or one that says nothing, or two different things, about where its body
//! ends — is an error, and that one is final.

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
    /// A message the parser refused, whose framing is still known: the
    /// stream has already moved past it, and what comes after it is read as
    /// usual.
    ///
    /// Only its head is handed out — the start line and the header fields,
    /// empty line included — because that is all an answer is written from
    /// (RFC 3261 §8.2.6.2), and because the body of one past
    /// [`Limits::max_message_bytes`] is never held at all.
    Refused {
        /// The start line and the header fields.
        head: &'a [u8],
        /// How long the whole message is, body included, as its head
        /// declares it.
        length: usize,
        /// Why the parser refused it: [`ParseError::MessageTooLarge`] for one
        /// whose declared length is past the bound, whatever else is wrong
        /// with it.
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
    /// A CRLF that has been read as a pong and could still turn out to be the
    /// first half of a ping split between two reads.
    dangling: bool,
    /// Body bytes of a message refused as longer than the bound that have not
    /// arrived yet, and are to be passed over unread when they do.
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
    /// Bytes still owed to the body of a message refused as too long are
    /// passed over here, before anything is kept. What is kept may run past
    /// the bound by what one read carried, while the head at the front of it
    /// ends inside the bound: [`StreamFramer::next_message`] takes the
    /// message off the front, or refuses it, before anything more is read.
    ///
    /// # Errors
    /// [`ParseError::MessageTooLarge`] when the head of the message being
    /// assembled has grown past the bound without ending. There is no
    /// recovering from that on a stream — nothing says where the message
    /// ends — so the caller closes the connection.
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
    /// `Ok(None)` means "not yet"; call again after more bytes. A message the
    /// parser refuses is [`Framed::Refused`] rather than an error, as long as
    /// where it ends is still known, and the call after it reads on. An `Err`
    /// is final: a stream whose framing is wrong cannot be resynchronised, so
    /// the connection goes.
    ///
    /// # Errors
    /// [`ParseError::MissingContentLength`] or
    /// [`ParseError::ConflictingContentLength`] for a message that cannot be
    /// framed, [`ParseError::BadHeaderLine`] for a `Content-Length` that is
    /// not a number, and [`ParseError::MessageTooLarge`] for a head that has
    /// grown past the bound without ending.
    pub fn next_message(&mut self, mode: ParseMode) -> Result<Option<Framed<'_>>, ParseError> {
        self.skip_keepalives();

        let ready = match self.need {
            // once the length is known, nothing is parsed again until the
            // bytes are actually here
            Some(n) => self.pending() >= n,
            None => self.headers_are_complete(),
        };
        if !ready {
            // a head past the bound that never ended: what `push` refuses,
            // left behind by the message that was in front of it
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
        // the message at the front and nothing behind it: several can be
        // queued in one read, and together they may pass a bound that each
        // of them keeps
        let bound = limits.max_message_bytes as usize;
        let window = bytes.get(..bytes.len().min(bound)).unwrap_or_default();
        let error = match parse_with_limits(window, scratch, mode, *limits) {
            Ok(message) => {
                // presence, not value: the parser has already framed the body
                // with it, and two that agree are its business, not ours
                if message.header_count(HeaderName::ContentLength) == 0 {
                    return Err(ParseError::MissingContentLength);
                }
                *start += message.len();
                *scanned = *start;
                *need = None;
                return Ok(Some(Framed::Message(message)));
            }
            // the head has ended — that is what made it ready — so a parser
            // that has not seen it end either stopped at the bound, the empty
            // line straddling it, or reads a bare LF as no line end at all.
            // Neither is "not yet": waiting would hold whatever followed, past
            // every bound, since `push` lets a head that has ended grow on
            Err(error) => error,
        };

        // refused, or not all here yet: either way the head says how long
        // the message is, or the framing is lost with it
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
    /// RFC 5626 §4.4.1 makes answering it a MUST for a server: one CRLF back,
    /// on the same connection.
    pub fn take_ping(&mut self) -> bool {
        if self.pings == 0 {
            return false;
        }
        self.pings -= 1;
        true
    }

    /// Consume one keep-alive pong, if one arrived.
    ///
    /// This is the half of §4.4.1 the client depends on: a ping that is not
    /// answered within ten seconds means the flow is dead, and nothing else on
    /// an idle connection says otherwise.
    pub fn take_pong(&mut self) -> bool {
        if self.pongs == 0 {
            return false;
        }
        self.pongs -= 1;
        true
    }

    /// A ping of ours has just gone out on this connection.
    ///
    /// A lone CRLF read before now was an answer, or half of a ping torn
    /// between two reads; the next one to arrive is the answer to this ping
    /// rather than the other half of that one. Without this, a far end that
    /// pongs every ping on an idle connection would have its second pong paired
    /// with its first and read as a ping, and the ping it answered would be
    /// called unanswered.
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
    /// Only whole pairs are consumed: a lone `\r` at the end of the buffer is
    /// half of a CRLF that has not finished arriving, and eating it would
    /// desynchronise the very next message.
    fn skip_keepalives(&mut self) {
        let mut crlfs = 0_u32;
        while self.buf.get(self.start..self.start + 2) == Some(b"\r\n") {
            self.start += 2;
            crlfs += 1;
        }
        self.scanned = self.scanned.max(self.start);

        // A pair is a ping; the odd CRLF left over is a pong, and it is
        // reported the moment it arrives rather than held back to see whether a
        // second one follows. On an idle connection that second one may never
        // come, and the pong is the only thing that says the flow is alive. The
        // cost is that a ping split between two reads counts as a pong and then
        // as the ping it was, so it is still answered — four bytes torn in half
        // by the network buy the far end one keep-alive interval, and nothing
        // else.
        let run = crlfs + u32::from(self.dangling);
        self.pings += run / 2;
        let odd = run % 2 == 1;
        if odd && !self.dangling {
            self.pongs += 1;
        }
        // a byte that cannot continue the run ends it, so the next lone CRLF is
        // a pong of its own rather than the other half of this one
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
        // the flow-failure timer depends on this: the pong is usually the last
        // thing on the connection for the next twenty-five seconds
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
        // a run is only a ping when it arrives as one; a CRLF that was already
        // read as a pong does not pair up with the next message's
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
        // an idle connection to a server that answers every ping: nothing but
        // time between the two answers, and the second one answers the second
        // ping rather than completing the first
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
        // answering it is the MUST; the pong it is counted as first only costs
        // the far end a keep-alive interval
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
        // where it ends is still known, so nothing about the next one is lost
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

    /// Feed `stream` and then `junk` in pieces, taking every message off as it
    /// comes, and report the most the framer ever held; the connection may
    /// end on the way, which is also a bound.
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
        // the empty line begins inside the bound and ends past it, so the
        // head is longer than the bound by up to three bytes; reading it as
        // a head that fits and has not arrived yet held everything after it
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
        // the framer finds the end of a head at `\n\n` and the strict parser
        // does not; one of the two has to decide, or what follows piles up
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
