// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Getting whole messages back out of a byte stream (RFC 8656 §12.5, §12.6,
//! RFC 8489 §6.2.2).
//!
//! On UDP a datagram is a message and there is nothing to do. On TCP there is
//! no such boundary, so the length field is the frame: a STUN message is
//! twenty octets plus the length in its header, and a ChannelData message is
//! four plus its length rounded up to a multiple of four. RFC 7983's
//! demultiplexing table says which of the two a frame is, from the first byte
//! alone.
//!
//! TURN over TCP exists for the network that lets nothing out but 443, which
//! is the case this whole component was written for.
//!
//! # Where TLS goes
//!
//! TURN over TLS is TURN over TCP inside a record layer, and this workspace
//! has no crypto library to build one with. So the seam is named rather than
//! filled: a caller using `Transport::Tls` owns the handshake, the certificate
//! checks and the record layer, and this crate never sees any of it. Bytes
//! come out of the caller's TLS session and go into `StreamFraming::push`;
//! bytes come out of the client and go into the caller's TLS session. Nothing
//! else about the framing changes, because at this level nothing else does —
//! which is exactly why the boundary is worth drawing here instead of
//! inventing cryptography behind it.

use core::fmt;

use crate::stun::HEADER_LEN as STUN_HEADER_LEN;

use super::channel::HEADER_LEN as CHANNEL_HEADER_LEN;

/// The largest frame either format can produce.
///
/// A STUN message is the longer of the two: twenty octets of header plus a
/// body, and the body length is always a multiple of four (RFC 8489 §5), so
/// the last three values the field could hold are not reachable.
pub const MAX_FRAME: usize = STUN_HEADER_LEN + (u16::MAX as usize & !3);

/// How the client reaches the server.
///
/// It is not what the relay speaks to the peer; that is always UDP in this
/// version of the protocol (§3.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Transport {
    /// What a client picks unless it has a reason not to.
    #[default]
    Udp,
    /// For the firewall that blocks UDP outright.
    Tcp,
    /// For the firewall that allows one port, and for the client that wants
    /// the server's certificate checked. The handshake belongs to the caller.
    Tls,
}

impl Transport {
    /// Whether messages arrive as a stream with no boundaries in it.
    #[must_use]
    pub const fn is_stream(self) -> bool {
        matches!(self, Self::Tcp | Self::Tls)
    }

    /// The port to use when nobody said otherwise (§4.1).
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 3478,
            Self::Tls => 5349,
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
        })
    }
}

/// What kind of frame a stream is holding, from its first byte (Table 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Stun,
    Channel,
}

const fn shape(first: u8) -> Option<Shape> {
    match first {
        0..=3 => Some(Shape::Stun),
        64..=79 => Some(Shape::Channel),
        _ => None,
    }
}

/// Whole messages, pulled out of a stream one at a time.
///
/// A stream that desynchronises cannot be resynchronised — there is no marker
/// to hunt for — so the first bad byte is fatal and stays fatal.
#[derive(Debug, Default)]
pub struct StreamFraming {
    buffer: Vec<u8>,
    start: usize,
    broken: Option<FrameError>,
}

impl StreamFraming {
    /// An empty framer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: Vec::new(),
            start: 0,
            broken: None,
        }
    }

    /// Add what the socket handed over.
    ///
    /// Nothing, once the stream has broken: no byte after the break can be
    /// part of a frame, and keeping them would let a peer that goes on
    /// sending grow the buffer for as long as the caller goes on reading.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.broken.is_some() {
            return;
        }
        if self.start != 0 {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        self.buffer.extend_from_slice(bytes);
    }

    /// Octets held that are not yet a whole message.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len() - self.start
    }

    /// The next whole message, if one has arrived.
    ///
    /// The slice is the message and nothing else: the padding a ChannelData
    /// message carries over a stream is consumed but not returned.
    ///
    /// # Errors
    ///
    /// A first byte that belongs to neither format, or a STUN length field
    /// that is not a whole number of words. Both mean the stream is no longer
    /// where it thinks it is, and every later call gives the same answer.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, FrameError> {
        if let Some(error) = self.broken {
            return Err(error);
        }
        let begin = self.start;
        let Some(rest) = self.buffer.get(begin..) else {
            return Ok(None);
        };
        let Some(&first) = rest.first() else {
            return Ok(None);
        };
        let Some(shape) = shape(first) else {
            return Err(self.break_off(FrameError::NotTurn(first)));
        };

        let length = match shape {
            Shape::Stun => {
                let Some(header) = rest.get(..STUN_HEADER_LEN) else {
                    return Ok(None);
                };
                let body = u16::from_be_bytes([
                    *header.get(2).unwrap_or(&0),
                    *header.get(3).unwrap_or(&0),
                ]);
                if body % 4 != 0 {
                    return Err(self.break_off(FrameError::Unaligned(body)));
                }
                STUN_HEADER_LEN + usize::from(body)
            }
            Shape::Channel => {
                let Some(header) = rest.get(..CHANNEL_HEADER_LEN) else {
                    return Ok(None);
                };
                let body = u16::from_be_bytes([
                    *header.get(2).unwrap_or(&0),
                    *header.get(3).unwrap_or(&0),
                ]);
                (CHANNEL_HEADER_LEN + usize::from(body)).div_ceil(4) * 4
            }
        };

        if rest.len() < length {
            return Ok(None);
        }
        self.start = begin + length;
        // a ChannelData message keeps its padding out of the length field, so
        // the frame handed back stops where the message does
        let kept = match shape {
            Shape::Stun => length,
            Shape::Channel => CHANNEL_HEADER_LEN
                .checked_add(usize::from(u16::from_be_bytes([
                    *rest.get(2).unwrap_or(&0),
                    *rest.get(3).unwrap_or(&0),
                ])))
                .unwrap_or(length),
        };
        Ok(self.buffer.get(begin..begin + kept))
    }

    fn break_off(&mut self, error: FrameError) -> FrameError {
        self.broken = Some(error);
        self.buffer = Vec::new();
        self.start = 0;
        error
    }
}

/// Why a stream stopped making sense.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A first byte that is neither STUN nor a channel. RFC 7983 says drop
    /// such a packet; on a stream there is nothing left to drop it from.
    NotTurn(u8),
    /// A STUN length field that is not a multiple of four, which RFC 8489 §5
    /// says it always is.
    Unaligned(u16),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotTurn(first) => write!(f, "a frame starting with 0x{first:02x}"),
            Self::Unaligned(length) => write!(f, "length {length} is not a multiple of four"),
        }
    }
}

impl core::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::{
        CHANNEL_HEADER_LEN, FrameError, MAX_FRAME, STUN_HEADER_LEN, StreamFraming, Transport,
    };
    use crate::stun::{Class, MessageBuilder, Method, TransactionId};
    use crate::turn::channel::{ChannelData, ChannelNumber};

    fn binding(id: u8) -> Vec<u8> {
        MessageBuilder::new(
            Class::Request,
            Method::BINDING,
            TransactionId::new([id; 12]),
        )
        .finish()
    }

    fn channel(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        ChannelData::encode(
            ChannelNumber::new(0x4002).expect("in range"),
            data,
            Transport::Tcp,
            &mut out,
        )
        .expect("fits");
        out
    }

    #[test]
    fn no_frame_of_either_format_can_be_longer_than_the_advertised_maximum() {
        let longest_stun = STUN_HEADER_LEN + usize::from(u16::MAX - u16::MAX % 4);
        let longest_channel = (CHANNEL_HEADER_LEN + usize::from(u16::MAX)).div_ceil(4) * 4;
        assert_eq!(MAX_FRAME, longest_stun);
        assert!(longest_channel <= MAX_FRAME);
    }

    #[test]
    fn the_default_ports_are_the_ones_the_uri_scheme_implies() {
        assert_eq!(Transport::Udp.default_port(), 3478);
        assert_eq!(Transport::Tcp.default_port(), 3478);
        assert_eq!(Transport::Tls.default_port(), 5349);
        assert!(!Transport::Udp.is_stream());
        assert!(Transport::Tcp.is_stream());
        assert!(Transport::Tls.is_stream());
    }

    #[test]
    fn two_messages_in_one_chunk_come_out_one_at_a_time() {
        let mut framer = StreamFraming::new();
        let first = binding(1);
        let second = channel(b"abc");
        let mut chunk = first.clone();
        chunk.extend_from_slice(&second);
        framer.push(&chunk);

        assert_eq!(framer.next_frame(), Ok(Some(&first[..])));
        // the padding is consumed and not handed back
        assert_eq!(framer.next_frame(), Ok(Some(&second[..7])));
        assert_eq!(framer.next_frame(), Ok(None));
        assert_eq!(framer.pending(), 0);
    }

    #[test]
    fn a_message_split_across_every_boundary_still_arrives_whole() {
        let message = binding(2);
        for cut in 0..message.len() {
            let mut framer = StreamFraming::new();
            framer.push(message.get(..cut).unwrap_or_default());
            assert_eq!(framer.next_frame(), Ok(None), "{cut}");
            framer.push(message.get(cut..).unwrap_or_default());
            assert_eq!(framer.next_frame(), Ok(Some(&message[..])), "{cut}");
        }
    }

    #[test]
    fn a_stream_fed_one_byte_at_a_time_yields_the_same_frames() {
        let mut expected = Vec::new();
        let mut wire = Vec::new();
        for index in 0..4_u8 {
            let message = if index % 2 == 0 {
                binding(index)
            } else {
                channel(&[index; 5])
            };
            wire.extend_from_slice(&message);
            expected.push(if index % 2 == 0 {
                message
            } else {
                message.get(..9).unwrap_or_default().to_vec()
            });
        }

        let mut framer = StreamFraming::new();
        let mut got = Vec::new();
        for byte in &wire {
            framer.push(&[*byte]);
            while let Some(frame) = framer.next_frame().expect("well formed") {
                got.push(frame.to_vec());
            }
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn a_first_byte_from_another_protocol_breaks_the_stream_for_good() {
        let mut framer = StreamFraming::new();
        // 22 is a DTLS record, which RFC 7983 puts in the 20 to 63 range
        framer.push(&[22, 0xfe, 0xfd, 0]);
        assert_eq!(framer.next_frame(), Err(FrameError::NotTurn(22)));
        framer.push(&binding(3));
        assert_eq!(framer.next_frame(), Err(FrameError::NotTurn(22)));
    }

    #[test]
    fn a_broken_stream_holds_nothing_more_whatever_keeps_arriving() {
        // a relay that sent one bad byte and then kept streaming, into a
        // caller that goes on reading the socket until it gets round to
        // closing it: nothing after the break can ever be a frame, so none
        // of it may be kept
        let mut framer = StreamFraming::new();
        framer.push(&[22, 0xfe, 0xfd, 0]);
        assert_eq!(framer.next_frame(), Err(FrameError::NotTurn(22)));
        for _ in 0..256 {
            framer.push(&[0_u8; 4096]);
        }
        assert_eq!(framer.pending(), 0, "a broken stream went on buffering");
        assert_eq!(framer.next_frame(), Err(FrameError::NotTurn(22)));
    }

    #[test]
    fn a_stun_length_that_is_not_whole_words_breaks_the_stream() {
        let mut message = binding(4);
        message.push(0);
        if let Some(field) = message.get_mut(2..4) {
            field.copy_from_slice(&1_u16.to_be_bytes());
        }
        let mut framer = StreamFraming::new();
        framer.push(&message);
        assert_eq!(framer.next_frame(), Err(FrameError::Unaligned(1)));
    }

    #[test]
    fn an_empty_stream_asks_for_more_rather_than_complaining() {
        let mut framer = StreamFraming::new();
        assert_eq!(framer.next_frame(), Ok(None));
        framer.push(&[]);
        assert_eq!(framer.next_frame(), Ok(None));
        assert_eq!(framer.pending(), 0);
    }

    #[test]
    fn a_zero_length_channel_message_is_a_whole_frame() {
        let mut framer = StreamFraming::new();
        framer.push(&[0x40, 0x00, 0x00, 0x00]);
        assert_eq!(framer.next_frame(), Ok(Some(&[0x40, 0x00, 0x00, 0x00][..])));
    }
}
