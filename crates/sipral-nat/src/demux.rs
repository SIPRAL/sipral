// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Telling STUN from media on a socket that carries both.
//!
//! One port carries the connectivity checks and the media, because opening a
//! second one would need a second hole in the NAT that this whole component
//! exists to avoid. The first two bits are what separates them: "The most
//! significant 2 bits of every STUN message MUST be zeroes. This can be used
//! to differentiate STUN packets from other protocols when STUN is multiplexed
//! with other protocols on the same port" (RFC 8489 §5), and RTP puts its
//! version number, 2, in the same two bits (RFC 3550 §5.1).
//!
//! The two bits are the rule. The cookie and the four-byte alignment of the
//! length field are corroboration, and RFC 8489 §5 offers both for exactly
//! this: a datagram that starts with two zero bits but has neither is not a
//! STUN message anyone here should try to parse.

use crate::stun::{HEADER_LEN, MAGIC_COOKIE};

/// What a datagram off the shared socket looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Demux {
    /// Two zero bits, the magic cookie and a sensible length: hand it to the
    /// STUN layer, which will still check everything properly.
    Stun,
    /// Version two: RTP or RTCP, told apart from each other by payload type
    /// (RFC 5761), which is the media layer's business rather than this one's.
    Media,
    /// Neither. An empty datagram, a DTLS record, or noise.
    Other,
}

/// Which of the two protocols a datagram belongs to.
#[must_use]
pub fn classify(datagram: &[u8]) -> Demux {
    let Some(&first) = datagram.first() else {
        return Demux::Other;
    };
    match first & 0xc0 {
        0x00 if looks_like_stun(datagram) => Demux::Stun,
        0x80 => Demux::Media,
        _ => Demux::Other,
    }
}

fn looks_like_stun(datagram: &[u8]) -> bool {
    let Some(header) = datagram.get(..HEADER_LEN) else {
        return false;
    };
    let cookie = u32::from_be_bytes([
        *header.get(4).unwrap_or(&0),
        *header.get(5).unwrap_or(&0),
        *header.get(6).unwrap_or(&0),
        *header.get(7).unwrap_or(&0),
    ]);
    let length = u16::from_be_bytes([*header.get(2).unwrap_or(&0), *header.get(3).unwrap_or(&0)]);
    cookie == MAGIC_COOKIE && length % 4 == 0
}

#[cfg(test)]
mod tests {
    use super::{Demux, classify};
    use crate::stun::{Class, MessageBuilder, Method, TransactionId};

    fn binding_request() -> Vec<u8> {
        MessageBuilder::new(Class::Request, Method::BINDING, TransactionId::new([7; 12])).finish()
    }

    #[test]
    fn a_binding_request_is_stun() {
        assert_eq!(classify(&binding_request()), Demux::Stun);
    }

    #[test]
    fn an_rtp_packet_is_media() {
        // version 2, payload type 8, and a header that says nothing about STUN
        let packet = [0x80, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(classify(&packet), Demux::Media);
    }

    #[test]
    fn an_rtcp_packet_is_media_too() {
        let packet = [0x80, 0xc8, 0x00, 0x06, 0, 0, 0, 0];
        assert_eq!(classify(&packet), Demux::Media);
    }

    #[test]
    fn nothing_at_all_is_neither() {
        assert_eq!(classify(&[]), Demux::Other);
    }

    #[test]
    fn a_dtls_record_is_neither() {
        // content type 22, version 1.2: the leading bits are 00 but there is
        // no cookie where one would have to be
        let record = [
            0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(classify(&record), Demux::Other);
    }

    #[test]
    fn two_zero_bits_without_a_cookie_are_not_enough() {
        let mut datagram = binding_request();
        datagram[4] ^= 0xff;
        assert_eq!(classify(&datagram), Demux::Other);
    }

    #[test]
    fn a_datagram_too_short_to_hold_a_header_is_not_stun() {
        let datagram = binding_request();
        for length in 0..datagram.len() {
            assert_eq!(classify(&datagram[..length]), Demux::Other, "{length}");
        }
    }

    #[test]
    fn a_length_that_is_not_whole_words_is_not_stun() {
        let mut datagram = binding_request();
        datagram[3] = 3;
        assert_eq!(classify(&datagram), Demux::Other);
    }

    #[test]
    fn the_leading_bits_beat_everything_else() {
        // a datagram carrying the cookie in the right place but with the
        // version bits of RTP is media, because those two bits are the rule
        let mut datagram = binding_request();
        datagram[0] |= 0x80;
        assert_eq!(classify(&datagram), Demux::Media);
    }
}
