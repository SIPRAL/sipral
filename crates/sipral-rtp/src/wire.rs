// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The RTP header as it appears on the wire, read and written (RFC 3550 §5.1).
//!
//! Reading borrows. The CSRC list, the header extension and the payload stay
//! in the datagram the caller already owns, so looking at a packet costs no
//! allocation and no copy. Writing goes into a buffer the caller supplies, for
//! the same reason.

use core::fmt;

/// Octets of fixed header ahead of any CSRC list: "The first twelve octets are
/// present in every RTP packet" (§5.1).
pub const FIXED_HEADER_LEN: usize = 12;

/// The version this specification defines (§5.1).
pub const VERSION: u8 = 2;

/// The payload type field is seven bits (§5.1).
pub const MAX_PAYLOAD_TYPE: u8 = 127;

/// One contributing source identifier (§5.1).
const CSRC_LEN: usize = 4;

/// What an extension counts its length in: "the number of 32-bit words in the
/// extension" (§5.3.1).
const WORD_LEN: usize = 4;

/// The profile field and the length field that precede an extension (§5.3.1).
const EXTENSION_HEADER_LEN: usize = 4;

/// The CSRC count is four bits, so fifteen is all a mixer can name (§5.1).
const MAX_CSRC: usize = 15;

/// The payload types a receiver will believe.
///
/// §5.1: "A receiver MUST ignore packets with payload types that it does not
/// understand." What it understands is whatever the offer and the answer
/// settled on, so the set arrives from the caller rather than from a table
/// here — which is also what keeps anything that is not media out of the
/// stream, since the numbers a peer may send are exactly the numbers that were
/// negotiated.
///
/// Seven bits of payload type fit in one integer, so membership is a shift and
/// a test and the set is `Copy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PayloadTypes(u128);

impl PayloadTypes {
    /// A set that believes nothing.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// The same set, plus one payload type. A value above 127 cannot appear in
    /// the field, so adding one changes nothing.
    #[must_use]
    pub const fn with(self, payload_type: u8) -> Self {
        if payload_type > MAX_PAYLOAD_TYPE {
            return self;
        }
        Self(self.0 | (1_u128 << payload_type))
    }

    /// Whether a payload type is one this receiver asked for.
    #[must_use]
    pub const fn contains(self, payload_type: u8) -> bool {
        payload_type <= MAX_PAYLOAD_TYPE && self.0 & (1_u128 << payload_type) != 0
    }

    /// Whether nothing at all is accepted.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl FromIterator<u8> for PayloadTypes {
    fn from_iter<I: IntoIterator<Item = u8>>(types: I) -> Self {
        types.into_iter().fold(Self::none(), Self::with)
    }
}

/// The fields of the fixed header that carry meaning per packet (§5.1).
///
/// Version and the padding and extension bits are not here: they describe the
/// shape of the datagram rather than the media in it, and by the time there is
/// an `RtpHeader` they have already been checked and acted on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtpHeader {
    /// The marker bit. "The interpretation of the marker is defined by a
    /// profile"; for audio it means the first packet of a talk spurt
    /// (RFC 3551 §4.1).
    pub marker: bool,
    /// Which format the payload is in.
    pub payload_type: u8,
    /// Increments by one for each packet sent, and wraps.
    pub sequence: u16,
    /// The sampling instant of the first octet, at the profile's clock rate.
    pub timestamp: u32,
    /// The synchronization source: who is speaking.
    pub ssrc: u32,
}

/// The one header extension a packet may carry (§5.3.1).
///
/// The profile decides what the sixteen bits mean; RFC 3550 "does not define
/// any header extensions itself", so the data is handed on untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderExtension<'a> {
    /// The sixteen bits "defined by profile".
    pub profile: u16,
    /// The extension itself, a whole number of 32-bit words.
    pub data: &'a [u8],
}

/// A packet, as a view over the datagram it arrived in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    header: RtpHeader,
    csrc: &'a [u8],
    extension: Option<HeaderExtension<'a>>,
    payload: &'a [u8],
}

impl<'a> RtpPacket<'a> {
    /// Read a datagram.
    ///
    /// This performs the checks from Appendix A.1 that can be made without
    /// knowing anything about the sender: the version, and that every length
    /// the header claims fits in what actually arrived. Whether the payload
    /// type is one this call negotiated, and whether the sequence number
    /// belongs to a stream already being heard, are questions for a receiver
    /// that has that state — see [`crate::RtpSession`].
    ///
    /// # Errors
    /// [`PacketError`], naming what did not add up.
    pub fn parse(datagram: &'a [u8]) -> Result<Self, PacketError> {
        let Some(fixed) = datagram.first_chunk::<FIXED_HEADER_LEN>() else {
            return Err(PacketError::TooShort {
                got: datagram.len(),
            });
        };
        // §5.1 in order: V, P, X and CC; M and PT; sequence number; timestamp;
        // SSRC
        let [flags, kind, q0, q1, t0, t1, t2, t3, s0, s1, s2, s3] = *fixed;

        let version = flags >> 6;
        if version != VERSION {
            return Err(PacketError::Version(version));
        }
        let padded = flags & 0b0010_0000 != 0;
        let extended = flags & 0b0001_0000 != 0;
        let csrc_count = usize::from(flags & 0b0000_1111);

        let header = RtpHeader {
            marker: kind & 0b1000_0000 != 0,
            payload_type: kind & 0b0111_1111,
            sequence: u16::from_be_bytes([q0, q1]),
            timestamp: u32::from_be_bytes([t0, t1, t2, t3]),
            ssrc: u32::from_be_bytes([s0, s1, s2, s3]),
        };

        let after_fixed = datagram.get(FIXED_HEADER_LEN..).unwrap_or_default();
        let Some((csrc, rest)) = after_fixed.split_at_checked(csrc_count * CSRC_LEN) else {
            return Err(PacketError::TruncatedCsrc {
                declared: csrc_count * CSRC_LEN,
                available: after_fixed.len(),
            });
        };

        // "the extension length field must be less than the total packet size
        // minus the fixed header length and padding" (A.1)
        let (extension, rest) = if extended {
            let Some(head) = rest.first_chunk::<EXTENSION_HEADER_LEN>() else {
                return Err(PacketError::TruncatedExtension {
                    declared: 0,
                    available: rest.len(),
                });
            };
            let [profile_hi, profile_lo, len_hi, len_lo] = *head;
            let words = usize::from(u16::from_be_bytes([len_hi, len_lo]));
            let body = rest.get(EXTENSION_HEADER_LEN..).unwrap_or_default();
            let Some((data, rest)) = body.split_at_checked(words * WORD_LEN) else {
                return Err(PacketError::TruncatedExtension {
                    declared: words * WORD_LEN,
                    available: body.len(),
                });
            };
            let extension = HeaderExtension {
                profile: u16::from_be_bytes([profile_hi, profile_lo]),
                data,
            };
            (Some(extension), rest)
        } else {
            (None, rest)
        };

        // "If the padding bit is set ... the last octet of the padding
        // contains a count of how many padding octets should be ignored,
        // including itself" (§5.1). A.1 wants that count "less than the total
        // packet length minus the header size"; taken as written that refuses
        // a packet which is all
        // padding, which slices perfectly well and which no profile forbids,
        // so the check here is that the count fits rather than that it leaves
        // something behind
        let payload = if padded {
            let count = rest.last().copied().map_or(0, usize::from);
            if count == 0 || count > rest.len() {
                return Err(PacketError::Padding {
                    declared: count,
                    available: rest.len(),
                });
            }
            rest.get(..rest.len().saturating_sub(count))
                .unwrap_or_default()
        } else {
            rest
        };

        Ok(Self {
            header,
            csrc,
            extension,
            payload,
        })
    }

    /// The fields that carry meaning per packet.
    #[must_use]
    pub const fn header(&self) -> RtpHeader {
        self.header
    }

    /// How many contributing sources the packet names.
    #[must_use]
    pub const fn csrc_count(&self) -> usize {
        self.csrc.len() / CSRC_LEN
    }

    /// The contributing sources, in the order a mixer wrote them (§5.1).
    ///
    /// An endpoint reads them to know who is talking and does nothing else
    /// with them; only a mixer writes them.
    pub fn csrc(&self) -> impl Iterator<Item = u32> + use<'a> {
        self.csrc
            .chunks_exact(CSRC_LEN)
            .filter_map(|id| <[u8; CSRC_LEN]>::try_from(id).ok())
            .map(u32::from_be_bytes)
    }

    /// The header extension, when the X bit was set.
    #[must_use]
    pub const fn extension(&self) -> Option<HeaderExtension<'a>> {
        self.extension
    }

    /// The payload, with any padding already taken off.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl fmt::Debug for RtpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtpPacket")
            .field("header", &self.header)
            .field("csrc", &self.csrc_count())
            .field("extension", &self.extension.map(|e| e.profile))
            .field("payload", &self.payload.len())
            .finish()
    }
}

/// A packet on its way out.
///
/// Padding is never written. It exists for ciphers with a fixed block size
/// (§5.1) and nothing here encrypts, so a packet that carries no padding is
/// one fewer thing for the far end to get wrong.
#[derive(Clone, Copy, Debug)]
pub struct PacketBuilder<'a> {
    header: RtpHeader,
    csrc: &'a [u32],
    extension: Option<HeaderExtension<'a>>,
    payload: &'a [u8],
}

impl<'a> PacketBuilder<'a> {
    /// A packet with a payload and nothing optional.
    #[must_use]
    pub const fn new(header: RtpHeader, payload: &'a [u8]) -> Self {
        Self {
            header,
            csrc: &[],
            extension: None,
            payload,
        }
    }

    /// Name the contributing sources. Only a mixer has any.
    #[must_use]
    pub const fn csrc(mut self, csrc: &'a [u32]) -> Self {
        self.csrc = csrc;
        self
    }

    /// Attach the one header extension a packet may carry (§5.3.1).
    #[must_use]
    pub const fn extension(mut self, extension: HeaderExtension<'a>) -> Self {
        self.extension = Some(extension);
        self
    }

    /// How many octets [`PacketBuilder::write`] needs.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let extension = self
            .extension
            .map_or(0, |e| EXTENSION_HEADER_LEN + e.data.len());
        FIXED_HEADER_LEN + self.csrc.len() * CSRC_LEN + extension + self.payload.len()
    }

    /// Write the packet into `out`, returning how many octets it took.
    ///
    /// # Errors
    /// [`BuildError`], for a buffer too small or a packet that cannot be
    /// expressed in the header's field widths.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, BuildError> {
        if self.header.payload_type > MAX_PAYLOAD_TYPE {
            return Err(BuildError::PayloadType(self.header.payload_type));
        }
        if self.csrc.len() > MAX_CSRC {
            return Err(BuildError::TooManyCsrc(self.csrc.len()));
        }
        if let Some(extension) = self.extension {
            let words = extension.data.len() / WORD_LEN;
            if extension.data.len() % WORD_LEN != 0 || u16::try_from(words).is_err() {
                return Err(BuildError::ExtensionLength(extension.data.len()));
            }
        }
        let need = self.encoded_len();
        let Some(out) = out.get_mut(..need) else {
            return Err(BuildError::Short {
                need,
                got: out.len(),
            });
        };

        let csrc_count = u8::try_from(self.csrc.len()).unwrap_or(0);
        let flags = (VERSION << 6) | (u8::from(self.extension.is_some()) << 4) | csrc_count;
        let kind = (u8::from(self.header.marker) << 7) | self.header.payload_type;

        let mut at = put(out, 0, &[flags, kind]);
        at = put(out, at, &self.header.sequence.to_be_bytes());
        at = put(out, at, &self.header.timestamp.to_be_bytes());
        at = put(out, at, &self.header.ssrc.to_be_bytes());
        for id in self.csrc {
            at = put(out, at, &id.to_be_bytes());
        }
        if let Some(extension) = self.extension {
            let words = u16::try_from(extension.data.len() / WORD_LEN).unwrap_or(0);
            at = put(out, at, &extension.profile.to_be_bytes());
            at = put(out, at, &words.to_be_bytes());
            at = put(out, at, extension.data);
        }
        at = put(out, at, self.payload);
        Ok(at)
    }
}

/// Copy `bytes` in at `at` and say where the next field starts. A field that
/// does not fit is dropped rather than truncated, which cannot happen here
/// because the buffer was cut to [`PacketBuilder::encoded_len`] first.
///
/// Shared with `rtcp`, whose builders cut their buffers the same way.
pub(crate) fn put(out: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    let end = at.saturating_add(bytes.len());
    if let Some(room) = out.get_mut(at..end) {
        room.copy_from_slice(bytes);
    }
    end
}

/// Why a datagram is not a packet this receiver can act on.
///
/// These are the checks Appendix A.1 calls weak: they cost a few bits and they
/// catch a datagram that was misaddressed, truncated, or never RTP at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// Shorter than the fixed header.
    TooShort {
        /// What arrived.
        got: usize,
    },
    /// "RTP version field must equal 2" (A.1).
    Version(u8),
    /// The CSRC count names more identifiers than the datagram holds.
    TruncatedCsrc {
        /// Octets of CSRC list the count asks for.
        declared: usize,
        /// Octets after the fixed header.
        available: usize,
    },
    /// The extension claims more than is there.
    TruncatedExtension {
        /// Octets of extension the length field asks for.
        declared: usize,
        /// Octets after the fixed header and the CSRC list.
        available: usize,
    },
    /// The padding count is zero, or larger than what follows the header.
    Padding {
        /// The count in the last octet.
        declared: usize,
        /// Octets that follow the header.
        available: usize,
    },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort { got } => {
                write!(f, "{got} octets, {FIXED_HEADER_LEN} needed for a header")
            }
            Self::Version(v) => write!(f, "version {v}, not {VERSION}"),
            Self::TruncatedCsrc {
                declared,
                available,
            } => write!(f, "CSRC list wants {declared} octets, {available} there"),
            Self::TruncatedExtension {
                declared,
                available,
            } => write!(f, "extension wants {declared} octets, {available} there"),
            Self::Padding {
                declared,
                available,
            } => write!(f, "padding of {declared} octets in {available}"),
        }
    }
}

impl core::error::Error for PacketError {}

/// Why a packet could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The buffer is smaller than the packet.
    Short {
        /// Octets the packet takes.
        need: usize,
        /// Octets offered.
        got: usize,
    },
    /// A payload type that does not fit seven bits.
    PayloadType(u8),
    /// A named telephone event whose volume is wider than the six bits its
    /// field has (RFC 4733 §2.3.4). Audio is opaque octets here and can
    /// never produce this; an event is the one payload this layer builds
    /// rather than copies.
    EventVolume(u8),
    /// More contributing sources than the four-bit count can name.
    TooManyCsrc(usize),
    /// An extension that is not a whole number of 32-bit words, or longer than
    /// the length field can count.
    ExtensionLength(usize),
    /// The packet was built and then refused by SRTP.
    Secured(crate::srtp::SrtpError),
    /// The stream agreed to be secured and its keys have not arrived, so
    /// there is nothing to protect the packet with. Sending it anyway would
    /// put in the clear exactly the audio the negotiation asked to encrypt.
    NotKeyed,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Short { need, got } => write!(f, "packet needs {need} octets, {got} offered"),
            Self::PayloadType(pt) => write!(f, "payload type {pt} does not fit seven bits"),
            Self::EventVolume(v) => write!(f, "event volume {v} does not fit six bits"),
            Self::TooManyCsrc(n) => write!(f, "{n} contributing sources, {MAX_CSRC} is the most"),
            Self::ExtensionLength(n) => write!(f, "extension of {n} octets is not whole words"),
            Self::Secured(error) => write!(f, "the packet could not be protected: {error}"),
            Self::NotKeyed => f.write_str("the stream has no keys yet"),
        }
    }
}

impl core::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::{
        BuildError, FIXED_HEADER_LEN, HeaderExtension, PacketBuilder, PacketError, PayloadTypes,
        RtpHeader, RtpPacket,
    };

    fn header() -> RtpHeader {
        RtpHeader {
            marker: true,
            payload_type: 8,
            sequence: 0x1234,
            timestamp: 0xDEAD_BEEF,
            ssrc: 0x0BAD_F00D,
        }
    }

    #[test]
    fn a_header_survives_being_written_and_read_back() {
        let mut out = [0_u8; 64];
        let payload = b"twenty milliseconds";
        let n = PacketBuilder::new(header(), payload)
            .write(&mut out)
            .expect("room");
        assert_eq!(n, FIXED_HEADER_LEN + payload.len());

        let packet = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(packet.header(), header());
        assert_eq!(packet.payload(), payload);
        assert_eq!(packet.csrc_count(), 0);
        assert_eq!(packet.extension(), None);
    }

    #[test]
    fn the_first_two_octets_carry_the_bits_the_rfc_puts_there() {
        // §5.1: V=2 in the top two bits, then P, X, CC; then M and PT
        let mut out = [0_u8; 32];
        PacketBuilder::new(header(), b"x")
            .write(&mut out)
            .expect("room");
        assert_eq!(out[0], 0b1000_0000, "version 2, no padding, no extension");
        assert_eq!(out[1], 0b1000_1000, "marker set, payload type 8");
    }

    #[test]
    fn contributing_sources_are_read_in_the_order_a_mixer_wrote_them() {
        let mut out = [0_u8; 64];
        let sources = [0x1111_1111_u32, 0x2222_2222, 0x3333_3333];
        let n = PacketBuilder::new(header(), b"mixed")
            .csrc(&sources)
            .write(&mut out)
            .expect("room");

        let packet = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(packet.csrc_count(), 3);
        assert_eq!(packet.csrc().collect::<Vec<_>>(), sources);
        assert_eq!(packet.payload(), b"mixed");
        assert_eq!(out[0] & 0b0000_1111, 3, "the CC field counts them");
    }

    #[test]
    fn a_header_extension_is_returned_untouched() {
        // §5.3.1: sixteen bits "defined by profile", then a length in 32-bit
        // words that excludes the four octets of extension header
        let mut out = [0_u8; 64];
        let extension = HeaderExtension {
            profile: 0xBEDE,
            data: b"eightocs",
        };
        let n = PacketBuilder::new(header(), b"after")
            .extension(extension)
            .write(&mut out)
            .expect("room");

        assert_eq!(out[0] & 0b0001_0000, 0b0001_0000, "the X bit is set");
        assert_eq!(out[14..16], [0, 2], "two words, not eight octets");

        let packet = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(packet.extension(), Some(extension));
        assert_eq!(packet.payload(), b"after");
    }

    #[test]
    fn an_extension_of_zero_words_is_still_an_extension() {
        // §5.3.1: "therefore zero is a valid length"
        let mut out = [0_u8; 32];
        let extension = HeaderExtension {
            profile: 1,
            data: &[],
        };
        let n = PacketBuilder::new(header(), b"p")
            .extension(extension)
            .write(&mut out)
            .expect("room");
        let packet = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(packet.extension(), Some(extension));
        assert_eq!(packet.payload(), b"p");
    }

    #[test]
    fn padding_is_taken_off_the_payload_and_the_count_includes_itself() {
        // §5.1: "the last octet of the padding contains a count of how many
        // padding octets should be ignored, including itself"
        let mut packet = [0_u8; FIXED_HEADER_LEN + 6];
        packet[0] = 0b1010_0000;
        packet[FIXED_HEADER_LEN] = b'a';
        packet[FIXED_HEADER_LEN + 1] = b'b';
        packet[FIXED_HEADER_LEN + 5] = 4;
        let parsed = RtpPacket::parse(&packet).expect("a packet");
        assert_eq!(parsed.payload(), b"ab");
    }

    #[test]
    fn a_packet_that_is_all_padding_carries_an_empty_payload() {
        let mut packet = [0_u8; FIXED_HEADER_LEN + 4];
        packet[0] = 0b1010_0000;
        packet[FIXED_HEADER_LEN + 3] = 4;
        let parsed = RtpPacket::parse(&packet).expect("a packet");
        assert!(parsed.payload().is_empty());
    }

    #[test]
    fn a_datagram_shorter_than_the_fixed_header_is_not_a_packet() {
        assert_eq!(
            RtpPacket::parse(&[0x80, 0x08, 0, 1]),
            Err(PacketError::TooShort { got: 4 })
        );
        assert_eq!(RtpPacket::parse(&[]), Err(PacketError::TooShort { got: 0 }));
    }

    #[test]
    fn the_version_must_be_two() {
        // A.1: "RTP version field must equal 2"
        let mut packet = [0_u8; FIXED_HEADER_LEN];
        packet[0] = 0b0000_0000;
        assert_eq!(RtpPacket::parse(&packet), Err(PacketError::Version(0)));
        packet[0] = 0b0100_0000;
        assert_eq!(RtpPacket::parse(&packet), Err(PacketError::Version(1)));
        packet[0] = 0b1100_0000;
        assert_eq!(RtpPacket::parse(&packet), Err(PacketError::Version(3)));
    }

    #[test]
    fn the_length_must_accommodate_the_csrc_count() {
        // A.1: "The length of the packet must be consistent with CC"
        let mut packet = [0_u8; FIXED_HEADER_LEN + 4];
        packet[0] = 0b1000_0010;
        assert_eq!(
            RtpPacket::parse(&packet),
            Err(PacketError::TruncatedCsrc {
                declared: 8,
                available: 4,
            })
        );
    }

    #[test]
    fn an_extension_that_does_not_fit_is_refused() {
        // A.1: "the extension length field must be less than the total packet
        // size minus the fixed header length and padding"
        let mut packet = [0_u8; FIXED_HEADER_LEN + 4 + 4];
        packet[0] = 0b1001_0000;
        packet[FIXED_HEADER_LEN + 3] = 9;
        assert_eq!(
            RtpPacket::parse(&packet),
            Err(PacketError::TruncatedExtension {
                declared: 36,
                available: 4,
            })
        );

        let mut stub = [0_u8; FIXED_HEADER_LEN + 2];
        stub[0] = 0b1001_0000;
        assert_eq!(
            RtpPacket::parse(&stub),
            Err(PacketError::TruncatedExtension {
                declared: 0,
                available: 2,
            })
        );
    }

    #[test]
    fn a_padding_count_that_eats_more_than_the_packet_holds_is_refused() {
        // A.1: the count must be "less than the total packet length minus the
        // header size"
        let mut packet = [0_u8; FIXED_HEADER_LEN + 4];
        packet[0] = 0b1010_0000;
        packet[FIXED_HEADER_LEN + 3] = 200;
        assert_eq!(
            RtpPacket::parse(&packet),
            Err(PacketError::Padding {
                declared: 200,
                available: 4,
            })
        );
    }

    #[test]
    fn a_padding_count_of_zero_is_refused_because_it_counts_itself() {
        let mut packet = [0_u8; FIXED_HEADER_LEN + 4];
        packet[0] = 0b1010_0000;
        assert_eq!(
            RtpPacket::parse(&packet),
            Err(PacketError::Padding {
                declared: 0,
                available: 4,
            })
        );
    }

    #[test]
    fn the_padding_bit_set_on_an_empty_payload_is_refused() {
        let mut packet = [0_u8; FIXED_HEADER_LEN];
        packet[0] = 0b1010_0000;
        assert_eq!(
            RtpPacket::parse(&packet),
            Err(PacketError::Padding {
                declared: 0,
                available: 0,
            })
        );
    }

    #[test]
    fn writing_refuses_what_the_header_fields_cannot_express() {
        let mut out = [0_u8; 128];
        let mut wide = header();
        wide.payload_type = 200;
        assert_eq!(
            PacketBuilder::new(wide, b"x").write(&mut out),
            Err(BuildError::PayloadType(200))
        );

        let sources = [0_u32; 16];
        assert_eq!(
            PacketBuilder::new(header(), b"x")
                .csrc(&sources)
                .write(&mut out),
            Err(BuildError::TooManyCsrc(16))
        );

        let ragged = HeaderExtension {
            profile: 1,
            data: b"three",
        };
        assert_eq!(
            PacketBuilder::new(header(), b"x")
                .extension(ragged)
                .write(&mut out),
            Err(BuildError::ExtensionLength(5))
        );
    }

    #[test]
    fn writing_into_a_buffer_that_is_too_small_writes_nothing() {
        let mut out = [0_u8; 13];
        assert_eq!(
            PacketBuilder::new(header(), b"more than one").write(&mut out),
            Err(BuildError::Short { need: 25, got: 13 })
        );
        assert_eq!(out, [0_u8; 13]);
    }

    #[test]
    fn a_payload_type_set_holds_the_seven_bits_and_nothing_wider() {
        let types: PayloadTypes = [0_u8, 8, 101].into_iter().collect();
        assert!(types.contains(0));
        assert!(types.contains(8));
        assert!(types.contains(101));
        assert!(!types.contains(9));
        assert!(!types.contains(127));
        assert!(!PayloadTypes::none().contains(0));
        assert!(PayloadTypes::none().is_empty());
        // above 127 cannot appear in the field, so it cannot join the set
        assert!(!PayloadTypes::none().with(200).contains(200));
        assert!(PayloadTypes::none().with(200).is_empty());
    }
}
