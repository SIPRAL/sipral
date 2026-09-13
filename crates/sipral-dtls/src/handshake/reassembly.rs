// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Putting fragmented handshake messages back together (RFC 6347 §4.2.2 and
//! §4.2.3), with a bound on everything a peer can make it hold.
//!
//! §4.2.3 obliges a receiver to "buffer it until it has the entire handshake
//! message" and to "handle overlapping fragment ranges". Taken literally that
//! is an invitation: a 24-bit length announced in a twelve-octet datagram asks
//! for sixteen megabytes, and one-octet fragments at every other offset ask
//! for a bookkeeping entry each. So a peer gets exactly what [`Limits`] says —
//! a longest message, a most pieces per message, a most messages held ahead,
//! a most octets across all of them — and a fragment that would pass one is
//! refused without disturbing what is already held.
//!
//! # When two fragments of one message disagree
//!
//! Another type, another total length, other octets where they overlap: two
//! such fragments cannot both be the sender's, and in epoch 0 neither is
//! authenticated. Keeping the first to arrive would let an injector that gets
//! one forged fragment in ahead of the genuine message refuse every genuine
//! fragment after it, and the retransmissions of those, for good — the
//! forgery never leaves. So the later one wins: what is held for that message
//! is discarded, and the disagreeing fragment starts it again.
//!
//! A genuine sender retransmits its whole flight until it is answered, so the
//! message is rebuilt by the first transmission to arrive after the last
//! injection, and an injector has to keep pace with every retransmission to
//! hold it off rather than win once. What an injector can do under any rule —
//! deliver a whole forged message first — is caught by the transcript, at
//! CertificateVerify or Finished. A message already handed out is never
//! touched.
//!
//! # When the octets held run out
//!
//! The same injector can lock a message out another way: a fragment of a
//! message announced at the longest length allowed, numbered ahead of the
//! flight where no genuine fragment comes to replace it, and a second one
//! beside it, hold every octet [`Limits::max_buffered`] allows, and no
//! genuine message fits after them. So a message nearer the next one to be
//! delivered takes its room from what is held further ahead, the furthest
//! first. Nothing is lost by it: the peer sends a message it sent again, and
//! one that is genuinely next always gets in.

use super::{Fragment, HandshakeType};
use crate::Error;

/// How much a [`Reassembler`] will hold for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The longest message body accepted, in octets.
    pub max_message_len: usize,
    /// The most disjoint pieces one incomplete message may be held in. Pieces
    /// that touch or overlap are merged, so a sender that fragments normally
    /// needs one, and a lossy path a few.
    pub max_pieces: usize,
    /// How many message sequence numbers, counting the next one expected, are
    /// held. A fragment further ahead is dropped, which §4.2.2 permits ("MAY
    /// discard it"); the peer's retransmission brings it back.
    pub max_future_messages: u16,
    /// The most body octets held across every incomplete message together.
    /// When a message runs into it, messages held further ahead give way.
    pub max_buffered: usize,
}

impl Default for Limits {
    /// A message up to 16 KiB — room for a certificate chain several
    /// RSA-4096 certificates long, where a self-signed P-256 certificate is
    /// under 500 octets — at most 32 pieces, eight messages, 32 KiB in all.
    /// The longest flight in the handshake, the server's, is five messages.
    fn default() -> Self {
        Self {
            max_message_len: 16 * 1024,
            max_pieces: 32,
            max_future_messages: 8,
            max_buffered: 32 * 1024,
        }
    }
}

/// A complete handshake message, in sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Its type.
    pub msg_type: HandshakeType,
    /// Its sequence number.
    pub message_seq: u16,
    /// Its body.
    pub body: Vec<u8>,
}

/// What became of a fragment that was not refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offered {
    /// Taken into a message not yet delivered.
    Accepted,
    /// Disagreed with what was held for the same message — another type,
    /// another total length, or other octets where the two overlap — which
    /// was discarded; this fragment starts the message again.
    Replaced,
    /// Part of a message already delivered, and so discarded (§4.2.2: "the
    /// message MUST be discarded"). The peer is retransmitting, which §4.2.4
    /// reads as a sign that the flight sent in reply was lost.
    Retransmission,
    /// Part of a message too far ahead of the next one to be held.
    TooFarAhead,
}

/// Handshake messages being put back together, handed out in sequence.
#[derive(Debug, Clone)]
pub struct Reassembler {
    /// `next_receive_seq` of §4.2.2. Wider than a message sequence number so
    /// that delivering message 65535 cannot wrap it back to 0.
    next_seq: u32,
    limits: Limits,
    pending: Vec<Partial>,
    buffered: usize,
}

#[derive(Debug, Clone)]
struct Partial {
    msg_type: HandshakeType,
    message_seq: u16,
    body: Vec<u8>,
    /// The half-open ranges of `body` received so far, sorted and disjoint.
    pieces: Vec<(usize, usize)>,
}

impl Reassembler {
    /// Expecting message 0, holding nothing.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            next_seq: 0,
            limits,
            pending: Vec::new(),
            buffered: 0,
        }
    }

    /// Expecting message `message_seq` first, holding nothing.
    ///
    /// For a server that answered the first ClientHello with a
    /// HelloVerifyRequest and kept nothing (§4.2.1): the ClientHello carrying
    /// the cookie is the first message it holds anything for, and in the
    /// example of §4.2.2 that is message 1. Started at 0 instead, it and every
    /// message after it would wait behind a message 0 the server never kept.
    #[must_use]
    pub fn expecting(limits: Limits, message_seq: u16) -> Self {
        Self {
            next_seq: u32::from(message_seq),
            limits,
            pending: Vec::new(),
            buffered: 0,
        }
    }

    /// The sequence number of the next message to be delivered.
    #[must_use]
    pub const fn next_message_seq(&self) -> u32 {
        self.next_seq
    }

    /// Body octets currently held for incomplete or undelivered messages.
    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.buffered
    }

    /// Take one received fragment.
    ///
    /// A fragment that disagrees with what is held for its message replaces
    /// it, for the reason the module documentation gives, and is reported as
    /// [`Offered::Replaced`]. A fragment that needs octets
    /// [`Limits::max_buffered`] has no room for takes them from messages held
    /// further ahead of the next one, the furthest first, as the module
    /// documentation also explains.
    ///
    /// # Errors
    ///
    /// Each leaves what is already held untouched:
    ///
    /// - [`Error::IllegalValue`] for a fragment that does not lie inside its
    ///   message, carries a body of another length than its header says, or
    ///   is empty when its message is not;
    /// - [`Error::TooLarge`] when holding it would pass one of the [`Limits`]
    ///   even with every message further ahead given up, a replacement
    ///   included.
    pub fn offer(&mut self, fragment: &Fragment<'_>) -> Result<Offered, Error> {
        let header = fragment.header;
        let seq = u32::from(header.message_seq);
        if seq < self.next_seq {
            return Ok(Offered::Retransmission);
        }
        if seq - self.next_seq >= u32::from(self.limits.max_future_messages) {
            return Ok(Offered::TooFarAhead);
        }

        let length = usize::try_from(header.length).map_err(|_| Error::TooLarge)?;
        let offset = usize::try_from(header.fragment_offset).map_err(|_| Error::IllegalValue)?;
        if usize::try_from(header.fragment_length) != Ok(fragment.body.len()) {
            return Err(Error::IllegalValue);
        }
        match offset.checked_add(fragment.body.len()) {
            Some(end) if end <= length => {}
            _ => return Err(Error::IllegalValue),
        }
        if fragment.body.is_empty() && length != 0 {
            return Err(Error::IllegalValue);
        }
        if length > self.limits.max_message_len {
            return Err(Error::TooLarge);
        }

        let max_pieces = self.limits.max_pieces;
        let replaced = match self
            .pending
            .iter_mut()
            .find(|partial| partial.message_seq == header.message_seq)
        {
            Some(held)
                if held.msg_type == header.msg_type
                    && held.body.len() == length
                    && held.agrees(offset, fragment.body) =>
            {
                held.add(offset, fragment.body, max_pieces)?;
                return Ok(Offered::Accepted);
            }
            Some(held) => Some(held.body.len()),
            None => None,
        };

        let mut fresh = Partial::new(header.msg_type, header.message_seq, length);
        fresh.add(offset, fragment.body, max_pieces)?;
        self.make_room(header.message_seq, replaced.unwrap_or(0), length)?;
        self.buffered = self
            .buffered
            .saturating_sub(replaced.unwrap_or(0))
            .saturating_add(length);
        if let Some(held) = self
            .pending
            .iter_mut()
            .find(|partial| partial.message_seq == header.message_seq)
        {
            *held = fresh;
            return Ok(Offered::Replaced);
        }
        self.pending.push(fresh);
        Ok(Offered::Accepted)
    }

    /// Room under [`Limits::max_buffered`] for `length` octets of message
    /// `message_seq`, `freed` of those held now going with what they are
    /// replaced by.
    ///
    /// What is held for messages further ahead gives way, the furthest first:
    /// the peer sends those again, and a message nearer the next one to be
    /// delivered is never refused for their sake. Otherwise two unauthenticated
    /// fragments, each announcing the longest message allowed at a sequence
    /// number no genuine message takes, would fill the budget and refuse every
    /// genuine message, and every retransmission of it, for as long as the
    /// handshake lasts. When giving all of them way would not be enough, nothing
    /// is given up.
    fn make_room(&mut self, message_seq: u16, freed: usize, length: usize) -> Result<(), Error> {
        let max_buffered = self.limits.max_buffered;
        let ahead: usize = self
            .pending
            .iter()
            .filter(|partial| partial.message_seq > message_seq)
            .map(|partial| partial.body.len())
            .sum();
        let mut kept = self.buffered.saturating_sub(freed);
        if kept.saturating_sub(ahead).saturating_add(length) > max_buffered {
            return Err(Error::TooLarge);
        }
        while kept.saturating_add(length) > max_buffered {
            let Some(furthest) = self
                .pending
                .iter()
                .enumerate()
                .filter(|(_, partial)| partial.message_seq > message_seq)
                .max_by_key(|(_, partial)| partial.message_seq)
                .map(|(index, _)| index)
            else {
                return Err(Error::TooLarge);
            };
            let given_up = self.pending.swap_remove(furthest).body.len();
            kept = kept.saturating_sub(given_up);
            self.buffered = self.buffered.saturating_sub(given_up);
        }
        Ok(())
    }

    /// The next message in sequence, once all of it has arrived.
    ///
    /// Messages are handed out strictly in order: one that completes before
    /// the message in front of it waits for that one.
    pub fn next_message(&mut self) -> Option<Message> {
        let index = self.pending.iter().position(|partial| {
            u32::from(partial.message_seq) == self.next_seq && partial.is_complete()
        })?;
        let partial = self.pending.swap_remove(index);
        self.buffered -= partial.body.len();
        self.next_seq += 1;
        Some(Message {
            msg_type: partial.msg_type,
            message_seq: partial.message_seq,
            body: partial.body,
        })
    }
}

impl Partial {
    fn new(msg_type: HandshakeType, message_seq: u16, length: usize) -> Self {
        Self {
            msg_type,
            message_seq,
            body: vec![0; length],
            pieces: Vec::new(),
        }
    }

    fn is_complete(&self) -> bool {
        self.body.is_empty() || self.pieces.as_slice() == [(0, self.body.len())]
    }

    /// Whether `bytes`, placed at `offset`, say the same as every octet
    /// already held that they overlap.
    fn agrees(&self, offset: usize, bytes: &[u8]) -> bool {
        let end = offset + bytes.len();
        self.pieces.iter().all(|&(start, stop)| {
            let from = start.max(offset);
            let to = stop.min(end);
            from >= to
                || matches!(
                    (self.body.get(from..to), bytes.get(from - offset..to - offset)),
                    (Some(held), Some(offered)) if held == offered
                )
        })
    }

    /// Take octets that [`Partial::agrees`] with what is held.
    fn add(&mut self, offset: usize, bytes: &[u8], max_pieces: usize) -> Result<(), Error> {
        let end = offset + bytes.len();
        let mut merged = Vec::with_capacity(self.pieces.len() + 1);
        let (mut new_start, mut new_end) = (offset, end);
        let mut placed = false;
        for &(start, stop) in &self.pieces {
            if stop < new_start {
                merged.push((start, stop));
            } else if start > new_end {
                if !placed {
                    merged.push((new_start, new_end));
                    placed = true;
                }
                merged.push((start, stop));
            } else {
                // overlapping or touching: one piece now
                new_start = new_start.min(start);
                new_end = new_end.max(stop);
            }
        }
        if !placed {
            merged.push((new_start, new_end));
        }
        if merged.len() > max_pieces {
            return Err(Error::TooLarge);
        }

        let slot = self.body.get_mut(offset..end).ok_or(Error::IllegalValue)?;
        slot.copy_from_slice(bytes);
        self.pieces = merged;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::FragmentHeader;
    use super::*;

    fn piece(
        msg_type: HandshakeType,
        seq: u16,
        body: &[u8],
        offset: usize,
        len: usize,
    ) -> Fragment<'_> {
        Fragment {
            header: FragmentHeader {
                msg_type,
                length: u32::try_from(body.len()).unwrap(),
                message_seq: seq,
                fragment_offset: u32::try_from(offset).unwrap(),
                fragment_length: u32::try_from(len).unwrap(),
            },
            body: &body[offset..offset + len],
        }
    }

    fn body(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i * 7 % 256).unwrap())
            .collect()
    }

    const CERT: HandshakeType = HandshakeType::CERTIFICATE;

    #[test]
    fn fragments_in_any_order_and_overlapping_make_the_message() {
        let message = body(1000);
        let mut reassembler = Reassembler::new(Limits::default());
        // the end first, then a re-fragmented overlap, then the start
        for (offset, len) in [(800, 200), (300, 600), (0, 400)] {
            assert_eq!(
                reassembler.offer(&piece(CERT, 0, &message, offset, len)),
                Ok(Offered::Accepted)
            );
        }
        assert_eq!(
            reassembler.next_message(),
            Some(Message {
                msg_type: CERT,
                message_seq: 0,
                body: message
            })
        );
        assert_eq!(reassembler.next_message(), None);
        assert_eq!(reassembler.next_message_seq(), 1);
        assert_eq!(reassembler.buffered(), 0);
    }

    #[test]
    fn nothing_is_delivered_while_a_gap_remains() {
        let message = body(100);
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler.offer(&piece(CERT, 0, &message, 0, 40)).unwrap();
        reassembler
            .offer(&piece(CERT, 0, &message, 41, 59))
            .unwrap();
        assert_eq!(reassembler.next_message(), None);
        reassembler.offer(&piece(CERT, 0, &message, 40, 1)).unwrap();
        assert_eq!(reassembler.next_message().unwrap().body, message);
    }

    #[test]
    fn messages_come_out_in_sequence_whatever_order_they_complete_in() {
        let first = body(30);
        let second = body(10);
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler
            .offer(&piece(HandshakeType::SERVER_HELLO_DONE, 1, &[], 0, 0))
            .unwrap();
        reassembler.offer(&piece(CERT, 2, &second, 0, 10)).unwrap();
        assert_eq!(reassembler.next_message(), None);
        reassembler.offer(&piece(CERT, 0, &first, 0, 30)).unwrap();
        let seqs: Vec<u16> = core::iter::from_fn(|| reassembler.next_message())
            .map(|m| m.message_seq)
            .collect();
        assert_eq!(seqs, [0, 1, 2]);
    }

    #[test]
    fn a_delivered_message_arriving_again_is_a_retransmission_and_is_not_held() {
        let message = body(20);
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler.offer(&piece(CERT, 0, &message, 0, 20)).unwrap();
        reassembler.next_message().unwrap();
        assert_eq!(
            reassembler.offer(&piece(CERT, 0, &message, 0, 20)),
            Ok(Offered::Retransmission)
        );
        assert_eq!(reassembler.buffered(), 0);
        assert_eq!(reassembler.next_message(), None);
    }

    #[test]
    fn a_stateless_server_starts_at_the_client_hello_that_carried_the_cookie() {
        // RFC 6347 §4.2.2's example: ClientHello (seq=0) is answered with a
        // HelloVerifyRequest and forgotten; ClientHello (seq=1) carries the
        // cookie, and only then does the server hold anything for the client,
        // whose next flight goes on from 2.
        let hello = body(120);
        let certificate = body(600);
        let mut reassembler = Reassembler::expecting(Limits::default(), 1);
        assert_eq!(reassembler.next_message_seq(), 1);
        reassembler
            .offer(&piece(HandshakeType::CLIENT_HELLO, 1, &hello, 0, 120))
            .unwrap();
        assert_eq!(reassembler.next_message().map(|m| m.message_seq), Some(1));
        for (offset, len) in [(300, 300), (0, 300)] {
            reassembler
                .offer(&piece(CERT, 2, &certificate, offset, len))
                .unwrap();
        }
        assert_eq!(reassembler.next_message().unwrap().body, certificate);
        // the first ClientHello, retransmitted, is behind it
        assert_eq!(
            reassembler.offer(&piece(HandshakeType::CLIENT_HELLO, 0, &hello, 0, 120)),
            Ok(Offered::Retransmission)
        );
    }

    #[test]
    fn a_message_too_far_ahead_is_dropped() {
        let message = body(5);
        let limits = Limits {
            max_future_messages: 3,
            ..Limits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        assert_eq!(
            reassembler.offer(&piece(CERT, 2, &message, 0, 5)),
            Ok(Offered::Accepted)
        );
        assert_eq!(
            reassembler.offer(&piece(CERT, 3, &message, 0, 5)),
            Ok(Offered::TooFarAhead)
        );
        assert_eq!(reassembler.buffered(), 5);
    }

    #[test]
    fn a_fragment_that_disagrees_replaces_what_is_held_for_its_message() {
        let message = body(50);
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler.offer(&piece(CERT, 0, &message, 0, 30)).unwrap();

        // another type under the same sequence number
        let other_type = piece(HandshakeType::SERVER_KEY_EXCHANGE, 0, &message, 30, 20);
        assert_eq!(reassembler.offer(&other_type), Ok(Offered::Replaced));
        assert_eq!(reassembler.buffered(), 50);
        // another total length
        let longer = body(51);
        assert_eq!(
            reassembler.offer(&piece(CERT, 0, &longer, 30, 21)),
            Ok(Offered::Replaced)
        );
        assert_eq!(reassembler.buffered(), 51);
        // other octets where it overlaps
        assert_eq!(
            reassembler.offer(&piece(CERT, 0, &message, 0, 30)),
            Ok(Offered::Replaced)
        );
        let mut altered = message.clone();
        altered[25] ^= 1;
        assert_eq!(
            reassembler.offer(&piece(CERT, 0, &altered, 20, 30)),
            Ok(Offered::Replaced)
        );
        // and the genuine octets replace the altered ones in turn, leaving
        // nothing of them behind
        assert_eq!(
            reassembler.offer(&piece(CERT, 0, &message, 0, 30)),
            Ok(Offered::Replaced)
        );
        assert_eq!(reassembler.next_message(), None);
        assert_eq!(
            reassembler.offer(&piece(CERT, 0, &message, 30, 20)),
            Ok(Offered::Accepted)
        );
        assert_eq!(reassembler.next_message().unwrap().body, message);
        assert_eq!(reassembler.buffered(), 0);
    }

    #[test]
    fn one_forged_fragment_cannot_lock_the_genuine_message_out() {
        let message = body(100);
        let forged: Vec<u8> = message.iter().map(|octet| !octet).collect();

        // the forgery lands first, and the genuine message still completes
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler.offer(&piece(CERT, 0, &forged, 0, 10)).unwrap();
        for (offset, len) in [(0, 50), (50, 50)] {
            reassembler
                .offer(&piece(CERT, 0, &message, offset, len))
                .unwrap();
        }
        assert_eq!(reassembler.next_message().unwrap().body, message);

        // the forgery lands between two genuine fragments: that transmission
        // does not complete, and the retransmission does
        let mut reassembler = Reassembler::new(Limits::default());
        reassembler.offer(&piece(CERT, 0, &message, 0, 50)).unwrap();
        reassembler.offer(&piece(CERT, 0, &forged, 40, 20)).unwrap();
        reassembler
            .offer(&piece(CERT, 0, &message, 50, 50))
            .unwrap();
        assert_eq!(reassembler.next_message(), None);
        for (offset, len) in [(0, 50), (50, 50)] {
            reassembler
                .offer(&piece(CERT, 0, &message, offset, len))
                .unwrap();
        }
        assert_eq!(reassembler.next_message().unwrap().body, message);
    }

    #[test]
    fn messages_held_further_ahead_give_way_to_one_nearer_the_next() {
        // two forged fragments announcing the longest message there is, at
        // sequence numbers the genuine flight never reaches, fill every octet
        // reassembly holds
        let limits = Limits::default();
        let longest = vec![0u8; limits.max_message_len];
        let genuine = body(600);
        let mut reassembler = Reassembler::new(limits);
        for seq in [6, 7] {
            assert_eq!(
                reassembler.offer(&piece(CERT, seq, &longest, 0, 1)),
                Ok(Offered::Accepted)
            );
        }
        assert_eq!(reassembler.buffered(), limits.max_buffered);
        // the genuine messages still get in, one after another
        for seq in 0..5 {
            assert_eq!(
                reassembler.offer(&piece(CERT, seq, &genuine, 0, 600)),
                Ok(Offered::Accepted),
                "message {seq}"
            );
            assert_eq!(
                reassembler.next_message().map(|message| message.body),
                Some(genuine.clone())
            );
        }
        // the furthest ahead gave way, and nothing more than was needed
        assert_eq!(reassembler.buffered(), limits.max_message_len);
        assert_eq!(
            reassembler.offer(&piece(CERT, 7, &longest, 0, 1)),
            Ok(Offered::Accepted)
        );
        // and a message further ahead than everything held makes no room
        assert_eq!(
            reassembler.offer(&piece(CERT, 8, &longest, 0, 1)),
            Err(Error::TooLarge)
        );
        assert_eq!(reassembler.buffered(), limits.max_buffered);

        // a replacement makes its room the same way
        let limits = Limits {
            max_message_len: 100,
            max_buffered: 120,
            ..Limits::default()
        };
        let mut reassembler = Reassembler::expecting(limits, 1);
        reassembler
            .offer(&piece(CERT, 1, &body(60), 0, 10))
            .unwrap();
        reassembler
            .offer(&piece(CERT, 2, &body(50), 0, 10))
            .unwrap();
        let longer: Vec<u8> = body(71).iter().map(|octet| !octet).collect();
        assert_eq!(
            reassembler.offer(&piece(CERT, 1, &longer, 0, 71)),
            Ok(Offered::Replaced)
        );
        assert_eq!(reassembler.buffered(), 71);
        assert_eq!(reassembler.next_message().unwrap().body, longer);
    }

    #[test]
    fn a_replacement_the_limits_refuse_leaves_what_is_held() {
        let limits = Limits {
            max_message_len: 100,
            max_buffered: 120,
            ..Limits::default()
        };
        let first = body(60);
        let second = body(50);
        let mut reassembler = Reassembler::expecting(limits, 1);
        reassembler.offer(&piece(CERT, 1, &first, 0, 10)).unwrap();
        reassembler.offer(&piece(CERT, 2, &second, 0, 10)).unwrap();
        assert_eq!(reassembler.buffered(), 110);
        // message 2 announced again at 61 octets: 60 held for message 1 makes
        // 121, and nothing is held further ahead to give way
        let longer = body(61);
        assert_eq!(
            reassembler.offer(&piece(CERT, 2, &longer, 0, 10)),
            Err(Error::TooLarge)
        );
        assert_eq!(reassembler.buffered(), 110);
        reassembler.offer(&piece(CERT, 2, &second, 10, 40)).unwrap();
        reassembler.offer(&piece(CERT, 1, &first, 10, 50)).unwrap();
        assert_eq!(reassembler.next_message().unwrap().body, first);
        assert_eq!(reassembler.next_message().unwrap().body, second);
    }

    #[test]
    fn a_fragment_whose_header_lies_about_its_body_is_refused() {
        let message = body(10);
        let mut reassembler = Reassembler::new(Limits::default());
        let mut lying = piece(CERT, 0, &message, 0, 5);
        lying.header.fragment_length = 6;
        assert_eq!(reassembler.offer(&lying), Err(Error::IllegalValue));
        let mut past_end = piece(CERT, 0, &message, 5, 5);
        past_end.header.fragment_offset = 6;
        assert_eq!(reassembler.offer(&past_end), Err(Error::IllegalValue));
        let mut empty = piece(CERT, 0, &message, 5, 0);
        empty.body = &[];
        assert_eq!(reassembler.offer(&empty), Err(Error::IllegalValue));
        assert_eq!(reassembler.buffered(), 0);
    }

    #[test]
    fn the_length_a_peer_announces_is_not_allocated_past_the_limit() {
        // with the total unbounded, the message limit is all that stands in
        // the way of the allocation
        let limits = Limits {
            max_buffered: usize::MAX,
            ..Limits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        // a twelve-octet header announcing the largest 24-bit message
        let header = FragmentHeader {
            msg_type: CERT,
            length: (1 << 24) - 1,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: 1,
        };
        assert_eq!(
            reassembler.offer(&Fragment { header, body: &[0] }),
            Err(Error::TooLarge)
        );
        assert_eq!(reassembler.buffered(), 0);
    }

    #[test]
    fn the_total_held_is_bounded_across_messages() {
        let limits = Limits {
            max_message_len: 100,
            max_buffered: 250,
            ..Limits::default()
        };
        let message = body(100);
        let mut reassembler = Reassembler::new(limits);
        reassembler.offer(&piece(CERT, 1, &message, 0, 10)).unwrap();
        reassembler.offer(&piece(CERT, 2, &message, 0, 10)).unwrap();
        assert_eq!(
            reassembler.offer(&piece(CERT, 3, &message, 0, 10)),
            Err(Error::TooLarge)
        );
        assert_eq!(reassembler.buffered(), 200);
        // more of a message already held costs nothing new
        reassembler
            .offer(&piece(CERT, 1, &message, 10, 90))
            .unwrap();
        assert_eq!(reassembler.buffered(), 200);
    }

    #[test]
    fn scattered_pieces_are_bounded_and_filling_a_gap_is_always_taken() {
        let limits = Limits {
            max_pieces: 4,
            ..Limits::default()
        };
        let message = body(20);
        let mut reassembler = Reassembler::new(limits);
        for offset in [0, 2, 4, 6] {
            reassembler
                .offer(&piece(CERT, 0, &message, offset, 1))
                .unwrap();
        }
        assert_eq!(
            reassembler.offer(&piece(CERT, 0, &message, 8, 1)),
            Err(Error::TooLarge)
        );
        // touching an existing piece does not add one
        reassembler.offer(&piece(CERT, 0, &message, 7, 1)).unwrap();
        // filling between two pieces removes one
        reassembler.offer(&piece(CERT, 0, &message, 1, 1)).unwrap();
        reassembler.offer(&piece(CERT, 0, &message, 8, 1)).unwrap();
        reassembler.offer(&piece(CERT, 0, &message, 3, 1)).unwrap();
        reassembler.offer(&piece(CERT, 0, &message, 5, 1)).unwrap();
        reassembler.offer(&piece(CERT, 0, &message, 9, 11)).unwrap();
        assert_eq!(reassembler.next_message().unwrap().body, message);
    }

    #[test]
    fn duplicates_of_a_complete_undelivered_message_are_harmless() {
        let message = body(8);
        let limits = Limits {
            max_future_messages: 2,
            ..Limits::default()
        };
        let mut reassembler = Reassembler::new(limits);
        for _ in 0..100 {
            reassembler.offer(&piece(CERT, 1, &message, 0, 8)).unwrap();
        }
        assert_eq!(reassembler.buffered(), 8);
    }
}
