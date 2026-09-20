// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Telling STUN, DTLS and media apart on a socket that carries all three.
//!
//! One port carries the connectivity checks, the key exchange and the media,
//! because opening a second one would need a second hole in the NAT that this
//! whole component exists to avoid. The first octet is what separates them,
//! and RFC 7983 §7 is the table: 0 to 3 is STUN, 20 to 63 is DTLS, 128 to 191
//! is RTP or RTCP, and every other value belongs to something this tree does
//! not speak.
//!
//! The ranges are not arbitrary. "The most significant 2 bits of every STUN
//! message MUST be zeroes. This can be used to differentiate STUN packets
//! from other protocols when STUN is multiplexed with other protocols on the
//! same port" (RFC 8489 §5); RTP puts its version number, 2, in those same
//! two bits (RFC 3550 §5.1); and a DTLS record begins with a content type,
//! which RFC 9147 §4 draws from a range that starts above STUN's and ends
//! below RTP's. Three protocols that were each designed to be recognisable
//! beside the others, and one table that writes the result down.
//!
//! The first octet is the rule. The cookie and the four-byte alignment of the
//! length field are corroboration, and RFC 8489 §5 offers both for exactly
//! this: a datagram in STUN's range that has neither is not a STUN message
//! anyone here should try to parse. Nothing corroborates the DTLS range,
//! because a record's own header is checked by the layer that reads it and a
//! datagram that is not a record is discarded there rather than here.

use crate::stun::{HEADER_LEN, MAGIC_COOKIE};

/// What a datagram off the shared socket looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Demux {
    /// In STUN's range, with the magic cookie and a sensible length: hand it
    /// to the STUN layer, which will still check everything properly.
    Stun,
    /// A DTLS record (RFC 7983 §7): the key exchange that keys the media
    /// beside it. Whether it is well formed is the DTLS layer's business.
    Dtls,
    /// Version two: RTP or RTCP, told apart from each other by payload type
    /// (RFC 5761), which is the media layer's business rather than this one's.
    Media,
    /// None of them. An empty datagram, a protocol this tree does not speak,
    /// or noise.
    Other,
}

/// Which of the three protocols a datagram belongs to.
#[must_use]
pub fn classify(datagram: &[u8]) -> Demux {
    let Some(&first) = datagram.first() else {
        return Demux::Other;
    };
    match first {
        0..=3 if looks_like_stun(datagram) => Demux::Stun,
        20..=63 => Demux::Dtls,
        128..=191 => Demux::Media,
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
    fn a_dtls_record_is_dtls() {
        // content type 22 (handshake), version 1.2, and nothing else that
        // matters here: the first octet alone puts it in RFC 7983's range
        let record = [
            0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(classify(&record), Demux::Dtls);
    }

    #[test]
    fn every_content_type_dtls_uses_lands_in_its_own_range() {
        // ChangeCipherSpec, Alert, Handshake, ApplicationData and the
        // Heartbeat this tree does not send: every content type DTLS 1.2
        // defines is inside 20..=63, which is why the range and not a list
        for content_type in [20_u8, 21, 22, 23, 24] {
            let record = [content_type, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(classify(&record), Demux::Dtls, "{content_type}");
        }
    }

    #[test]
    fn the_edges_of_every_range_are_where_rfc_7983_puts_them() {
        // one octet either side of each boundary, because an off-by-one here
        // sends a handshake to the media layer and a media packet to nowhere
        assert_eq!(classify(&[19, 0, 0, 0]), Demux::Other);
        assert_eq!(classify(&[20, 0, 0, 0]), Demux::Dtls);
        assert_eq!(classify(&[63, 0, 0, 0]), Demux::Dtls);
        assert_eq!(classify(&[64, 0, 0, 0]), Demux::Other);
        assert_eq!(classify(&[127, 0, 0, 0]), Demux::Other);
        assert_eq!(classify(&[128, 0, 0, 0]), Demux::Media);
        assert_eq!(classify(&[191, 0, 0, 0]), Demux::Media);
        assert_eq!(classify(&[192, 0, 0, 0]), Demux::Other);
    }

    #[test]
    fn a_turn_channel_is_not_anything_this_tree_reads_here() {
        // RFC 7983 gives 64..=79 to TURN channel data, and `turn::channel`
        // reads it off the relay's own socket rather than off this one
        for first in [64_u8, 79] {
            assert_eq!(classify(&[first, 0, 0, 4, 0, 0, 0, 0]), Demux::Other);
        }
    }

    #[test]
    fn stuns_own_range_without_a_cookie_is_not_enough() {
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
    fn the_leading_octet_beats_everything_else() {
        // a datagram carrying the cookie in the right place but with the
        // version bits of RTP is media, because the first octet is the rule
        // and the cookie is only ever corroboration
        let mut datagram = binding_request();
        datagram[0] |= 0x80;
        assert_eq!(classify(&datagram), Demux::Media);
    }

    #[test]
    fn a_stun_message_type_above_the_range_is_not_stun() {
        // RFC 7983 gives STUN 0..=3, which covers every message type STUN
        // and TURN define; a first octet of 4 with a perfect cookie is
        // something else wearing STUN's clothes
        let mut datagram = binding_request();
        datagram[0] = 4;
        assert_eq!(classify(&datagram), Demux::Other);
    }
}
