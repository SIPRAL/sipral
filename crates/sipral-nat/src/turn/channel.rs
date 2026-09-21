// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! ChannelData: four bytes of header instead of thirty-six (RFC 8656 §12).
//!
//! This is the reason channels exist. A Send indication wraps every packet in
//! a STUN header, an XOR-PEER-ADDRESS and a DATA attribute; on a 20 ms voice
//! frame that is more overhead than the audio in a G.729 payload. A bound
//! channel replaces all of it with a number and a length.
//!
//! The number range is not the one RFC 5766 used. RFC 7983 needed the top of
//! it back for DTLS-SRTP demultiplexing, so 0x5000 and above is reserved now
//! and a channel number always starts with a byte between 64 and 79.

use core::fmt;

use super::framing::Transport;

/// Octets before the application data.
pub const HEADER_LEN: usize = 4;

/// The lowest channel number a client may bind (§12).
pub const FIRST_CHANNEL: u16 = 0x4000;

/// The highest (§12).
pub const LAST_CHANNEL: u16 = 0x4FFF;

/// A channel number: the shorthand a bound peer is addressed by.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelNumber(u16);

impl ChannelNumber {
    /// The channel with this number, if the number is one of the 4096 the
    /// specification allows.
    #[must_use]
    pub const fn new(number: u16) -> Option<Self> {
        if number < FIRST_CHANNEL || number > LAST_CHANNEL {
            return None;
        }
        Some(Self(number))
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Debug for ChannelNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelNumber(0x{:04x})", self.0)
    }
}

impl fmt::Display for ChannelNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

/// A ChannelData message, as a view over the buffer it arrived in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelData<'a> {
    channel: ChannelNumber,
    data: &'a [u8],
}

impl<'a> ChannelData<'a> {
    /// Which channel, and therefore which peer.
    #[must_use]
    pub const fn channel(&self) -> ChannelNumber {
        self.channel
    }

    /// The application data, without the padding a stream transport adds.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Where that data sits in the frame it was read from.
    ///
    /// A channel is four octets of header and then the application's own
    /// packet, so the payload is always at the same place; this says it once
    /// rather than leaving every caller to add the header length itself.
    #[must_use]
    pub const fn range(&self) -> core::ops::Range<usize> {
        HEADER_LEN..HEADER_LEN + self.data.len()
    }

    /// Read a message that something else has already delimited.
    ///
    /// The padding a stream transport adds belongs to the frame rather than to
    /// the message, so a frame that `StreamFraming` has handed back arrives
    /// here without it, and a datagram may carry it or not.
    ///
    /// # Errors
    ///
    /// A header that does not fit, a number outside the range, or a length
    /// field that claims more than arrived.
    pub fn parse_frame(bytes: &'a [u8]) -> Result<Self, ChannelError> {
        let header = bytes
            .get(..HEADER_LEN)
            .ok_or(ChannelError::TooShort { got: bytes.len() })?;
        let number =
            u16::from_be_bytes([*header.first().unwrap_or(&0), *header.get(1).unwrap_or(&0)]);
        let channel = ChannelNumber::new(number).ok_or(ChannelError::Number(number))?;
        let length = usize::from(u16::from_be_bytes([
            *header.get(2).unwrap_or(&0),
            *header.get(3).unwrap_or(&0),
        ]));
        let data = bytes
            .get(HEADER_LEN..HEADER_LEN + length)
            .ok_or(ChannelError::Truncated {
                want: HEADER_LEN + length,
                got: bytes.len(),
            })?;
        Ok(Self { channel, data })
    }

    /// Read the message at the front of a buffer, and say how many octets it
    /// occupied there.
    ///
    /// The two transports disagree about the tail: over TCP the message "MUST
    /// be padded to a multiple of four bytes in order to ensure the alignment
    /// of subsequent messages" and the padding is outside the length field
    /// (§12.5), while over UDP the datagram boundary is the frame and padding
    /// is optional.
    ///
    /// # Errors
    ///
    /// As `parse_frame`, plus a stream message whose padding has not arrived.
    pub fn parse(bytes: &'a [u8], transport: Transport) -> Result<(Self, usize), ChannelError> {
        let message = Self::parse_frame(bytes)?;
        let consumed = framed_len(message.data.len(), transport);
        if consumed > bytes.len() {
            return Err(ChannelError::Truncated {
                want: consumed,
                got: bytes.len(),
            });
        }
        Ok((message, consumed))
    }

    /// Write a ChannelData message onto the end of a buffer.
    ///
    /// # Errors
    ///
    /// Data longer than the sixteen-bit length field can count.
    pub fn encode(
        channel: ChannelNumber,
        data: &[u8],
        transport: Transport,
        out: &mut Vec<u8>,
    ) -> Result<(), ChannelError> {
        let length = u16::try_from(data.len()).map_err(|_| ChannelError::TooLarge(data.len()))?;
        out.extend_from_slice(&channel.get().to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(data);
        let padding = framed_len(data.len(), transport) - HEADER_LEN - data.len();
        out.resize(out.len() + padding, 0);
        Ok(())
    }
}

/// How much of the wire a message with this much data occupies.
const fn framed_len(length: usize, transport: Transport) -> usize {
    if transport.is_stream() {
        (HEADER_LEN + length).div_ceil(4) * 4
    } else {
        HEADER_LEN + length
    }
}

/// Why a buffer does not hold a ChannelData message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// Shorter than the header.
    TooShort {
        /// What arrived.
        got: usize,
    },
    /// A number outside 0x4000 to 0x4FFF. Below the range it is a STUN
    /// message; above it, RFC 7983 has given the space to somebody else.
    Number(u16),
    /// The length field claims more than arrived.
    Truncated {
        /// Octets the header asks for, padding included.
        want: usize,
        /// Octets there.
        got: usize,
    },
    /// Data longer than the length field can count.
    TooLarge(usize),
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => {
                write!(f, "{got} octets, {HEADER_LEN} needed for a header")
            }
            Self::Number(number) => write!(f, "channel number 0x{number:04x} is out of range"),
            Self::Truncated { want, got } => {
                write!(f, "a message of {want} octets in a buffer of {got}")
            }
            Self::TooLarge(length) => {
                write!(f, "{length} octets do not fit the length field")
            }
        }
    }
}

impl core::error::Error for ChannelError {}

#[cfg(test)]
mod tests {
    use super::{
        ChannelData, ChannelError, ChannelNumber, FIRST_CHANNEL, HEADER_LEN, LAST_CHANNEL,
    };
    use crate::turn::framing::Transport;

    #[test]
    fn only_the_four_thousand_and_ninety_six_numbers_exist() {
        assert_eq!(ChannelNumber::new(0x3fff), None);
        assert_eq!(ChannelNumber::new(0x5000), None);
        assert_eq!(ChannelNumber::new(0xffff), None);
        assert_eq!(ChannelNumber::new(0x0000), None);
        assert_eq!(
            ChannelNumber::new(FIRST_CHANNEL).map(ChannelNumber::get),
            Some(0x4000)
        );
        assert_eq!(
            ChannelNumber::new(LAST_CHANNEL).map(ChannelNumber::get),
            Some(0x4fff)
        );
        assert_eq!(u32::from(LAST_CHANNEL - FIRST_CHANNEL) + 1, 4096);
    }

    #[test]
    fn every_legal_number_starts_with_a_byte_the_demultiplexer_expects() {
        // RFC 8656 Table 3 gives the TURN channel the first bytes 64 to 79,
        // and that has to agree with the number range or the framing of a
        // shared socket falls apart
        for number in FIRST_CHANNEL..=LAST_CHANNEL {
            let first = number.to_be_bytes();
            assert!(
                (64..=79).contains(first.first().unwrap_or(&0)),
                "0x{number:04x}"
            );
        }
    }

    #[test]
    fn a_datagram_round_trips_without_padding() {
        let channel = ChannelNumber::new(0x4001).expect("in range");
        let mut out = Vec::new();
        ChannelData::encode(channel, b"hello", Transport::Udp, &mut out).expect("fits");
        assert_eq!(out.len(), HEADER_LEN + 5);
        assert_eq!(out.first(), Some(&0x40));

        let (message, consumed) = ChannelData::parse(&out, Transport::Udp).expect("well formed");
        assert_eq!(consumed, out.len());
        assert_eq!(message.channel(), channel);
        assert_eq!(message.data(), b"hello");
    }

    #[test]
    fn a_stream_pads_to_four_and_keeps_the_length_field_honest() {
        let channel = ChannelNumber::new(0x4abc).expect("in range");
        let mut out = Vec::new();
        ChannelData::encode(channel, b"abcde", Transport::Tcp, &mut out).expect("fits");
        assert_eq!(out.len(), 12);
        assert_eq!(out.get(2..4), Some(&[0, 5][..]));
        assert_eq!(out.get(9..), Some(&[0, 0, 0][..]));

        let (message, consumed) = ChannelData::parse(&out, Transport::Tcp).expect("well formed");
        assert_eq!(consumed, 12);
        assert_eq!(message.data(), b"abcde");
    }

    #[test]
    fn padding_is_only_needed_where_the_length_is_not_already_whole_words() {
        for length in 0..16_usize {
            let payload = vec![0x5a; length];
            let mut out = Vec::new();
            ChannelData::encode(
                ChannelNumber::new(0x4000).expect("in range"),
                &payload,
                Transport::Tls,
                &mut out,
            )
            .expect("fits");
            assert_eq!(out.len() % 4, 0, "{length}");
            assert_eq!(out.len(), (HEADER_LEN + length).div_ceil(4) * 4);
            let (message, consumed) =
                ChannelData::parse(&out, Transport::Tls).expect("well formed");
            assert_eq!(consumed, out.len());
            assert_eq!(message.data().len(), length);
        }
    }

    #[test]
    fn an_empty_channel_message_is_a_message() {
        let mut out = Vec::new();
        ChannelData::encode(
            ChannelNumber::new(0x4fff).expect("in range"),
            &[],
            Transport::Udp,
            &mut out,
        )
        .expect("fits");
        assert_eq!(out, vec![0x4f, 0xff, 0, 0]);
        let (message, consumed) = ChannelData::parse(&out, Transport::Udp).expect("well formed");
        assert_eq!(consumed, 4);
        assert!(message.data().is_empty());
    }

    #[test]
    fn a_number_outside_the_range_is_refused_on_the_way_in() {
        let bytes = [0x50, 0x00, 0x00, 0x00];
        assert_eq!(
            ChannelData::parse(&bytes, Transport::Udp),
            Err(ChannelError::Number(0x5000))
        );
        let bytes = [0x3f, 0xff, 0x00, 0x00];
        assert_eq!(
            ChannelData::parse(&bytes, Transport::Udp),
            Err(ChannelError::Number(0x3fff))
        );
    }

    #[test]
    fn a_length_field_that_lies_is_caught() {
        let bytes = [0x40, 0x00, 0x00, 0x08, 1, 2, 3, 4];
        assert_eq!(
            ChannelData::parse(&bytes, Transport::Udp),
            Err(ChannelError::Truncated { want: 12, got: 8 })
        );
        for short in 0..4_usize {
            assert_eq!(
                ChannelData::parse(bytes.get(..short).unwrap_or_default(), Transport::Udp),
                Err(ChannelError::TooShort { got: short })
            );
        }
    }

    #[test]
    fn a_stream_message_whose_padding_never_arrived_is_incomplete() {
        // five octets of data need three of padding on a stream; a peer that
        // sent only the data has not sent a whole frame yet
        let bytes = [0x40, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
        assert_eq!(
            ChannelData::parse(&bytes, Transport::Tcp),
            Err(ChannelError::Truncated { want: 12, got: 9 })
        );
        assert!(ChannelData::parse(&bytes, Transport::Udp).is_ok());
    }

    #[test]
    fn a_datagram_with_trailing_bytes_reports_what_it_used() {
        let bytes = [0x40, 0x01, 0x00, 0x02, 9, 9, 0xff, 0xff];
        let (message, consumed) = ChannelData::parse(&bytes, Transport::Udp).expect("well formed");
        assert_eq!(consumed, 6);
        assert_eq!(message.data(), &[9, 9]);
    }
}
