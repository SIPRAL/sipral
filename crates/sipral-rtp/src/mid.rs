// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The identification-tag a bundled stream announces in its own packets (RFC
//! 8843 §15): in an RTP header extension at the start of the stream (§15,
//! carried as RFC 8285 describes and RFC 7941 names), and as an SDES item in
//! its RTCP (§15.1).
//!
//! The far end needs it to tell which of its bundled `m=` sections a packet
//! belongs to before it has learnt the SSRC. With one stream per call there
//! is one section to belong to, so this is what a peer that demultiplexes by
//! tag is owed, not something this end reads back.

use crate::wire::HeaderExtension;

/// The SDES item type of the identification-tag (RFC 8843 §15.1, §16.3).
pub const MID: u8 = 15;

/// How many RTP packets at the start of a stream carry the tag: a second of
/// 20 ms packets. RFC 8843 §15 asks for "some RTP packets at the start of the
/// session" and leaves the number to the sender.
pub const MID_PACKETS: u16 = 50;

/// RFC 8285 §4.2's profile value for the one-byte form.
const ONE_BYTE: u16 = 0xBEDE;
/// RFC 8285 §4.3's profile value for the two-byte form, with the four
/// application bits zero.
const TWO_BYTE: u16 = 0x1000;
/// The longest element the one-byte form carries (§4.2).
const ONE_BYTE_MOST: usize = 16;
/// The longest element the two-byte form carries (§4.3).
const TWO_BYTE_MOST: usize = 255;

/// The tag, ready to go on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MidTag {
    /// The extension's profile value and its data, padded to whole words
    /// (RFC 3550 §5.3.1).
    profile: u16,
    data: Vec<u8>,
    /// The tag itself, for the SDES item.
    text: Vec<u8>,
    /// RTP packets still to carry it.
    packets_left: u16,
}

impl MidTag {
    /// The tag `mid` under extension number `id`: the one-byte form for 1 to
    /// 14, the two-byte form above (RFC 8285 §4.2, §4.3). `None` for 0, for
    /// 15 with a tag too long for the two-byte form, for an empty tag, and
    /// for one longer than its form allows.
    pub(crate) fn new(id: u8, mid: &[u8]) -> Option<Self> {
        if id == 0 || mid.is_empty() {
            return None;
        }
        let (profile, mut data) = if id <= 14 && mid.len() <= ONE_BYTE_MOST {
            // §4.2: four bits of id, four of length minus one
            let length = u8::try_from(mid.len() - 1).ok()?;
            (ONE_BYTE, vec![(id << 4) | length])
        } else if mid.len() <= TWO_BYTE_MOST {
            (TWO_BYTE, vec![id, u8::try_from(mid.len()).ok()?])
        } else {
            return None;
        };
        data.extend_from_slice(mid);
        // §4.1: padding octets are zero, and the whole is a number of words
        data.resize(data.len().next_multiple_of(4), 0);
        Some(Self {
            profile,
            data,
            text: mid.to_vec(),
            packets_left: MID_PACKETS,
        })
    }

    /// The header extension for the next RTP packet, while the start of the
    /// stream lasts.
    pub(crate) fn extension(&self) -> Option<HeaderExtension<'_>> {
        (self.packets_left > 0).then_some(HeaderExtension {
            profile: self.profile,
            data: &self.data,
        })
    }

    /// One more packet went out with the extension.
    pub(crate) const fn carried(&mut self) {
        self.packets_left = self.packets_left.saturating_sub(1);
    }

    /// The tag, for the SDES item every report carries.
    pub(crate) fn text(&self) -> &[u8] {
        &self.text
    }
}

#[cfg(test)]
mod tests {
    use super::{MID_PACKETS, MidTag};

    #[test]
    fn a_short_tag_under_a_small_number_takes_the_one_byte_form() {
        let tag = MidTag::new(3, b"0").expect("a tag");
        let extension = tag.extension().expect("an extension");
        assert_eq!(extension.profile, 0xBEDE);
        // id 3, length 1 written as 0, the tag, then zero padding
        assert_eq!(extension.data, [0x30, b'0', 0, 0]);
        let sixteen = MidTag::new(14, b"0123456789abcdef").expect("a tag");
        let data = sixteen.extension().expect("an extension").data;
        assert_eq!(data.len(), 20);
        assert_eq!(data.first(), Some(&0xEF));
    }

    #[test]
    fn a_larger_number_or_a_longer_tag_takes_the_two_byte_form() {
        let tag = MidTag::new(15, b"audio").expect("a tag");
        let extension = tag.extension().expect("an extension");
        assert_eq!(extension.profile, 0x1000);
        assert_eq!(extension.data, [15, 5, b'a', b'u', b'd', b'i', b'o', 0]);
        let long = MidTag::new(2, b"seventeen octets!").expect("a tag");
        assert_eq!(long.extension().expect("an extension").profile, 0x1000);
        assert_eq!(MidTag::new(0, b"0"), None);
        assert_eq!(MidTag::new(1, b""), None);
        assert_eq!(MidTag::new(1, &[b'x'; 256]), None);
    }

    #[test]
    fn only_the_start_of_the_stream_carries_it() {
        let mut tag = MidTag::new(1, b"0").expect("a tag");
        for _ in 0..MID_PACKETS {
            assert!(tag.extension().is_some());
            tag.carried();
        }
        assert!(tag.extension().is_none());
        assert_eq!(tag.text(), b"0");
    }
}
