// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Hello extensions (RFC 5246 §7.4.1.4), and the six a DTLS-SRTP handshake
//! carries.
//!
//! The six are read into types; any other extension is kept as it arrived,
//! because RFC 5746 §3.6 has a server "ignore any unknown extensions offered
//! by the client", and ignoring one needs its type to answer the
//! no-unsolicited-extension rule on the client side. Only syntax is checked
//! here. Whether a server may send a given extension, whether a list holds the
//! value it must — the uncompressed point format, a profile the client
//! offered — is the handshake's to decide, since it alone knows what was sent.

use crate::Error;
use crate::wire::{self, Reader};

/// `ExtensionType`, from the IANA TLS ExtensionType Values registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtensionType(pub u16);

impl ExtensionType {
    /// `supported_groups`, named `elliptic_curves` in RFC 8422 §5.1.
    pub const SUPPORTED_GROUPS: Self = Self(10);
    /// `ec_point_formats` (RFC 8422 §5.1.2).
    pub const EC_POINT_FORMATS: Self = Self(11);
    /// `signature_algorithms` (RFC 5246 §7.4.1.4.1).
    pub const SIGNATURE_ALGORITHMS: Self = Self(13);
    /// `use_srtp` (RFC 5764 §4.1.1).
    pub const USE_SRTP: Self = Self(14);
    /// `extended_master_secret` (RFC 7627 §5.1).
    pub const EXTENDED_MASTER_SECRET: Self = Self(23);
    /// `renegotiation_info` (RFC 5746 §3.2).
    pub const RENEGOTIATION_INFO: Self = Self(0xff01);
}

/// `NamedCurve`, the "TLS Supported Groups" registry (RFC 8422 §5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
    /// `secp256r1`, NIST P-256.
    pub const SECP256R1: Self = Self(23);
}

/// `ECPointFormat` (RFC 8422 §5.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcPointFormat(pub u8);

impl EcPointFormat {
    /// The only format RFC 8422 still allows for the NIST curves.
    pub const UNCOMPRESSED: Self = Self(0);
}

/// `SignatureAndHashAlgorithm` (RFC 5246 §7.4.1.4.1): a hash and the signature
/// algorithm applied over it, one octet each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureAndHash {
    /// `HashAlgorithm`.
    pub hash: u8,
    /// `SignatureAlgorithm`.
    pub signature: u8,
}

impl SignatureAndHash {
    /// `{sha256(4), ecdsa(3)}`, the only pair this crate signs or verifies.
    pub const ECDSA_SHA256: Self = Self {
        hash: 4,
        signature: 3,
    };

    pub(crate) const fn from_bytes([hash, signature]: [u8; 2]) -> Self {
        Self { hash, signature }
    }

    pub(crate) const fn to_bytes(self) -> [u8; 2] {
        [self.hash, self.signature]
    }
}

/// `SRTPProtectionProfile` (RFC 5764 §4.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SrtpProtectionProfile(pub u16);

impl SrtpProtectionProfile {
    /// AES-128 in counter mode, an 80-bit HMAC-SHA1 tag.
    pub const AES128_CM_HMAC_SHA1_80: Self = Self(0x0001);
    /// AES-128 in counter mode, a 32-bit HMAC-SHA1 tag on RTP and 80 on RTCP.
    pub const AES128_CM_HMAC_SHA1_32: Self = Self(0x0002);
    /// No encryption, an 80-bit tag. Never negotiated here: RFC 8827 §6.5
    /// forbids NULL encryption.
    pub const NULL_HMAC_SHA1_80: Self = Self(0x0005);
    /// No encryption, a 32-bit tag. Never negotiated here, for the same reason.
    pub const NULL_HMAC_SHA1_32: Self = Self(0x0006);
}

/// `UseSRTPData` (RFC 5764 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UseSrtp {
    /// The client's profiles in descending order of preference, or the one the
    /// server chose.
    pub profiles: Vec<SrtpProtectionProfile>,
    /// `srtp_mki`: empty for no MKI. RFC 8827 §6.5 forbids one in WebRTC.
    pub mki: Vec<u8>,
}

/// One hello extension.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Extension {
    /// `NamedCurveList`, in the sender's order of preference.
    SupportedGroups(Vec<NamedGroup>),
    /// `ECPointFormatList`.
    EcPointFormats(Vec<EcPointFormat>),
    /// `supported_signature_algorithms`, in descending order of preference.
    SignatureAlgorithms(Vec<SignatureAndHash>),
    /// `UseSRTPData`.
    UseSrtp(UseSrtp),
    /// `extended_master_secret`, whose data is empty.
    ExtendedMasterSecret,
    /// `RenegotiationInfo.renegotiated_connection`: empty on an initial
    /// handshake, which is the only kind this crate performs.
    RenegotiationInfo(Vec<u8>),
    /// Any other extension, kept exactly as it arrived.
    Unknown {
        /// Its type.
        extension_type: ExtensionType,
        /// Its `extension_data`.
        data: Vec<u8>,
    },
}

/// `extension_data<0..2^16-1>`.
const DATA_MAX: usize = 0xFFFF;

impl Extension {
    /// The type this extension is sent under.
    #[must_use]
    pub const fn extension_type(&self) -> ExtensionType {
        match self {
            Self::SupportedGroups(_) => ExtensionType::SUPPORTED_GROUPS,
            Self::EcPointFormats(_) => ExtensionType::EC_POINT_FORMATS,
            Self::SignatureAlgorithms(_) => ExtensionType::SIGNATURE_ALGORITHMS,
            Self::UseSrtp(_) => ExtensionType::USE_SRTP,
            Self::ExtendedMasterSecret => ExtensionType::EXTENDED_MASTER_SECRET,
            Self::RenegotiationInfo(_) => ExtensionType::RENEGOTIATION_INFO,
            Self::Unknown { extension_type, .. } => *extension_type,
        }
    }

    const fn is_typed(extension_type: ExtensionType) -> bool {
        matches!(
            extension_type,
            ExtensionType::SUPPORTED_GROUPS
                | ExtensionType::EC_POINT_FORMATS
                | ExtensionType::SIGNATURE_ALGORITHMS
                | ExtensionType::USE_SRTP
                | ExtensionType::EXTENDED_MASTER_SECRET
                | ExtensionType::RENEGOTIATION_INFO
        )
    }

    fn parse(extension_type: ExtensionType, data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(data);
        let extension = match extension_type {
            ExtensionType::SUPPORTED_GROUPS => {
                // NamedCurve named_curve_list<2..2^16-1>
                let list = r.vec16(2, 0xFFFF)?;
                Self::SupportedGroups(
                    wire::elements::<2>(list)?
                        .into_iter()
                        .map(|pair| NamedGroup(u16::from_be_bytes(pair)))
                        .collect(),
                )
            }
            ExtensionType::EC_POINT_FORMATS => {
                // ECPointFormat ec_point_format_list<1..2^8-1>
                let list = r.vec8(1, 0xFF)?;
                Self::EcPointFormats(list.iter().copied().map(EcPointFormat).collect())
            }
            ExtensionType::SIGNATURE_ALGORITHMS => {
                // SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>
                let list = r.vec16(2, 0xFFFE)?;
                Self::SignatureAlgorithms(
                    wire::elements::<2>(list)?
                        .into_iter()
                        .map(SignatureAndHash::from_bytes)
                        .collect(),
                )
            }
            ExtensionType::USE_SRTP => {
                // SRTPProtectionProfile SRTPProtectionProfiles<2..2^16-1>;
                // opaque srtp_mki<0..255>
                let list = r.vec16(2, 0xFFFF)?;
                let profiles = wire::elements::<2>(list)?
                    .into_iter()
                    .map(|pair| SrtpProtectionProfile(u16::from_be_bytes(pair)))
                    .collect();
                let mki = r.vec8(0, 0xFF)?.to_vec();
                Self::UseSrtp(UseSrtp { profiles, mki })
            }
            ExtensionType::EXTENDED_MASTER_SECRET => {
                // RFC 7627 §5.1: "The "extension_data" field of this extension is empty."
                if !data.is_empty() {
                    return Err(Error::Length);
                }
                Self::ExtendedMasterSecret
            }
            ExtensionType::RENEGOTIATION_INFO => {
                // opaque renegotiated_connection<0..255>
                Self::RenegotiationInfo(r.vec8(0, 0xFF)?.to_vec())
            }
            _ => {
                return Ok(Self::Unknown {
                    extension_type,
                    data: data.to_vec(),
                });
            }
        };
        r.finish()?;
        Ok(extension)
    }

    fn encode_data(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::SupportedGroups(groups) => wire::block(out, 2, 2, 0xFFFF, |out| {
                for group in groups {
                    wire::put_u16(out, group.0);
                }
                Ok(())
            }),
            Self::EcPointFormats(formats) => wire::block(out, 1, 1, 0xFF, |out| {
                out.extend(formats.iter().map(|format| format.0));
                Ok(())
            }),
            Self::SignatureAlgorithms(pairs) => wire::block(out, 2, 2, 0xFFFE, |out| {
                for pair in pairs {
                    out.extend_from_slice(&pair.to_bytes());
                }
                Ok(())
            }),
            Self::UseSrtp(use_srtp) => {
                wire::block(out, 2, 2, 0xFFFF, |out| {
                    for profile in &use_srtp.profiles {
                        wire::put_u16(out, profile.0);
                    }
                    Ok(())
                })?;
                wire::put_vec8(out, &use_srtp.mki, 0, 0xFF)
            }
            Self::ExtendedMasterSecret => Ok(()),
            Self::RenegotiationInfo(connection) => wire::put_vec8(out, connection, 0, 0xFF),
            Self::Unknown { data, .. } => {
                out.extend_from_slice(data);
                Ok(())
            }
        }
    }
}

/// The extensions of one hello, each type at most once, in the order they
/// were sent or pushed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Extensions {
    list: Vec<Extension>,
}

impl Extensions {
    /// No extensions. Encoded, this is a present but empty extensions block,
    /// which is not the same message as one with the block absent.
    #[must_use]
    pub const fn new() -> Self {
        Self { list: Vec::new() }
    }

    /// Add one extension.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateExtension`] when one of its type is already present,
    /// which RFC 5246 §7.4.1.4 forbids. [`Error::IllegalValue`] for an
    /// [`Extension::Unknown`] carrying the type of one of the six this crate
    /// reads, which would be encoded under that type without the checks the
    /// typed variant gets.
    pub fn push(&mut self, extension: Extension) -> Result<(), Error> {
        let extension_type = extension.extension_type();
        if matches!(extension, Extension::Unknown { .. }) && Extension::is_typed(extension_type) {
            return Err(Error::IllegalValue);
        }
        if self.get(extension_type).is_some() {
            return Err(Error::DuplicateExtension);
        }
        self.list.push(extension);
        Ok(())
    }

    /// The extension of `extension_type`, if present.
    #[must_use]
    pub fn get(&self, extension_type: ExtensionType) -> Option<&Extension> {
        self.list
            .iter()
            .find(|extension| extension.extension_type() == extension_type)
    }

    /// Every extension, in order.
    pub fn iter(&self) -> impl Iterator<Item = &Extension> {
        self.list.iter()
    }

    /// How many extensions there are.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// `supported_groups`, if present.
    #[must_use]
    pub fn supported_groups(&self) -> Option<&[NamedGroup]> {
        match self.get(ExtensionType::SUPPORTED_GROUPS) {
            Some(Extension::SupportedGroups(groups)) => Some(groups),
            _ => None,
        }
    }

    /// `ec_point_formats`, if present.
    #[must_use]
    pub fn ec_point_formats(&self) -> Option<&[EcPointFormat]> {
        match self.get(ExtensionType::EC_POINT_FORMATS) {
            Some(Extension::EcPointFormats(formats)) => Some(formats),
            _ => None,
        }
    }

    /// `signature_algorithms`, if present.
    #[must_use]
    pub fn signature_algorithms(&self) -> Option<&[SignatureAndHash]> {
        match self.get(ExtensionType::SIGNATURE_ALGORITHMS) {
            Some(Extension::SignatureAlgorithms(pairs)) => Some(pairs),
            _ => None,
        }
    }

    /// `use_srtp`, if present.
    #[must_use]
    pub fn use_srtp(&self) -> Option<&UseSrtp> {
        match self.get(ExtensionType::USE_SRTP) {
            Some(Extension::UseSrtp(use_srtp)) => Some(use_srtp),
            _ => None,
        }
    }

    /// Whether `extended_master_secret` is present.
    #[must_use]
    pub fn extended_master_secret(&self) -> bool {
        self.get(ExtensionType::EXTENDED_MASTER_SECRET).is_some()
    }

    /// `renegotiation_info`'s `renegotiated_connection`, if present.
    #[must_use]
    pub fn renegotiation_info(&self) -> Option<&[u8]> {
        match self.get(ExtensionType::RENEGOTIATION_INFO) {
            Some(Extension::RenegotiationInfo(connection)) => Some(connection),
            _ => None,
        }
    }

    /// Read the contents of `Extension extensions<0..2^16-1>`, the length
    /// prefix already taken off.
    pub(crate) fn parse(block: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(block);
        let mut list = Vec::new();
        while !r.is_empty() {
            let extension_type = ExtensionType(r.u16()?);
            let data = r.vec16(0, DATA_MAX)?;
            list.push(Extension::parse(extension_type, data)?);
        }
        // "There MUST NOT be more than one extension of the same type": one
        // pass over the types sorted, not a search of the list per extension.
        // A block of 2^16 - 1 octets holds 16383 empty extensions, and a
        // search per extension compares every pair of them — a hundred
        // million comparisons for one unauthenticated datagram's worth.
        let mut types: Vec<ExtensionType> = list.iter().map(Extension::extension_type).collect();
        types.sort_unstable();
        if types
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a == b))
        {
            return Err(Error::DuplicateExtension);
        }
        Ok(Self { list })
    }

    /// Write `Extension extensions<0..2^16-1>`, length prefix included.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::block(out, 2, 0, 0xFFFF, |out| {
            for extension in &self.list {
                wire::put_u16(out, extension.extension_type().0);
                wire::block(out, 2, 0, DATA_MAX, |out| extension.encode_data(out))?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(bytes: &[u8]) -> Result<Extension, Error> {
        let mut extensions = Extensions::parse(bytes)?;
        assert_eq!(extensions.len(), 1);
        Ok(extensions.list.remove(0))
    }

    fn encoded(extension: Extension) -> Vec<u8> {
        let mut extensions = Extensions::new();
        extensions.push(extension).unwrap();
        let mut out = Vec::new();
        extensions.encode(&mut out).unwrap();
        // drop the block's own length
        out.split_off(2)
    }

    #[test]
    fn the_octets_printed_in_the_rfcs_read_and_write_back() {
        let cases: [(&[u8], Extension); 4] = [
            // RFC 8422 §5.1.1, a client offering P-256 then P-384
            (
                &[0x00, 0x0A, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18],
                Extension::SupportedGroups(vec![NamedGroup::SECP256R1, NamedGroup(24)]),
            ),
            // RFC 8422 §5.1.2
            (
                &[0x00, 0x0B, 0x00, 0x02, 0x01, 0x00],
                Extension::EcPointFormats(vec![EcPointFormat::UNCOMPRESSED]),
            ),
            // RFC 7627 §5.1: "the entire encoding of the extension is 00 17 00 00"
            (&[0x00, 0x17, 0x00, 0x00], Extension::ExtendedMasterSecret),
            // RFC 5746 §3.2: "the entire encoding of the extension is ff 01 00 01 00"
            (
                &[0xff, 0x01, 0x00, 0x01, 0x00],
                Extension::RenegotiationInfo(Vec::new()),
            ),
        ];
        for (bytes, extension) in cases {
            assert_eq!(one(bytes), Ok(extension.clone()));
            assert_eq!(encoded(extension), bytes);
        }
    }

    #[test]
    fn use_srtp_carries_its_profiles_and_its_mki() {
        // RFC 5764 §4.1.1: profiles<2..2^16-1>, then srtp_mki<0..255>
        let bytes = [
            0x00, 0x0e, 0x00, 0x09, // use_srtp, nine octets of data
            0x00, 0x04, 0x00, 0x01, 0x00, 0x02, // _80 then _32
            0x02, 0xAB, 0xCD, // a two-octet MKI
        ];
        let expected = Extension::UseSrtp(UseSrtp {
            profiles: vec![
                SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
                SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
            ],
            mki: vec![0xAB, 0xCD],
        });
        assert_eq!(one(&bytes), Ok(expected.clone()));
        assert_eq!(encoded(expected), bytes);
    }

    #[test]
    fn signature_algorithms_are_hash_then_signature() {
        let bytes = [0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x02, 0x01];
        let parsed = Extensions::parse(&bytes).unwrap();
        assert_eq!(
            parsed.signature_algorithms(),
            Some(
                &[
                    SignatureAndHash::ECDSA_SHA256,
                    SignatureAndHash {
                        hash: 2,
                        signature: 1
                    }
                ][..]
            )
        );
    }

    #[test]
    fn an_unknown_extension_is_kept_verbatim() {
        let bytes = [0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc];
        let parsed = Extensions::parse(&bytes).unwrap();
        assert_eq!(
            parsed.get(ExtensionType(0x2b)),
            Some(&Extension::Unknown {
                extension_type: ExtensionType(0x2b),
                data: vec![0x02, 0xfe, 0xfc]
            })
        );
        let mut out = Vec::new();
        parsed.encode(&mut out).unwrap();
        assert_eq!(out[2..], bytes);
    }

    #[test]
    fn the_accessors_find_what_is_there_and_nothing_else() {
        let mut extensions = Extensions::new();
        assert!(!extensions.extended_master_secret());
        extensions.push(Extension::ExtendedMasterSecret).unwrap();
        extensions
            .push(Extension::RenegotiationInfo(Vec::new()))
            .unwrap();
        assert!(extensions.extended_master_secret());
        assert_eq!(extensions.renegotiation_info(), Some(&[][..]));
        assert_eq!(extensions.use_srtp(), None);
        assert_eq!(extensions.supported_groups(), None);
        assert_eq!(extensions.ec_point_formats(), None);
        assert_eq!(extensions.signature_algorithms(), None);
        assert_eq!(extensions.iter().count(), 2);
        assert!(!extensions.is_empty());
    }

    #[test]
    fn malformed_extension_data_is_refused() {
        let cases: [(&str, &[u8], Error); 13] = [
            (
                "odd group list",
                &[0, 10, 0, 5, 0, 3, 0, 23, 0],
                Error::Length,
            ),
            ("empty group list", &[0, 10, 0, 2, 0, 0], Error::Length),
            (
                "group list longer than data",
                &[0, 10, 0, 4, 0, 4, 0, 23],
                Error::Truncated,
            ),
            ("empty point formats", &[0, 11, 0, 1, 0], Error::Length),
            (
                "point formats trailing",
                &[0, 11, 0, 3, 1, 0, 9],
                Error::TrailingData,
            ),
            ("odd signature list", &[0, 13, 0, 3, 0, 1, 4], Error::Length),
            (
                "signature list of 2^16-1",
                &[0, 13, 0, 2, 0xFF, 0xFF],
                Error::Length,
            ),
            (
                "srtp profiles empty",
                &[0, 14, 0, 3, 0, 0, 0],
                Error::Length,
            ),
            (
                "srtp profiles odd",
                &[0, 14, 0, 6, 0, 3, 0, 1, 0, 0],
                Error::Length,
            ),
            (
                "srtp mki missing",
                &[0, 14, 0, 4, 0, 2, 0, 1],
                Error::Truncated,
            ),
            (
                "srtp trailing",
                &[0, 14, 0, 6, 0, 2, 0, 1, 0, 7],
                Error::TrailingData,
            ),
            ("ems with data", &[0, 23, 0, 1, 0], Error::Length),
            (
                "renegotiation trailing",
                &[0xff, 1, 0, 2, 0, 0],
                Error::TrailingData,
            ),
        ];
        for (what, bytes, error) in cases {
            assert_eq!(Extensions::parse(bytes).err(), Some(error), "{what}");
        }
    }

    #[test]
    fn the_block_itself_is_held_to_its_framing() {
        // data length runs past the block
        assert_eq!(Extensions::parse(&[0, 23, 0, 1]), Err(Error::Truncated));
        // half a type
        assert_eq!(Extensions::parse(&[0]), Err(Error::Truncated));
        // RFC 5246 §7.4.1.4: "There MUST NOT be more than one extension of the same type."
        assert_eq!(
            Extensions::parse(&[0, 23, 0, 0, 0, 23, 0, 0]),
            Err(Error::DuplicateExtension)
        );
        assert_eq!(
            Extensions::parse(&[0, 99, 0, 0, 0, 99, 0, 1, 7]),
            Err(Error::DuplicateExtension)
        );
        assert_eq!(Extensions::parse(&[]), Ok(Extensions::new()));
    }

    /// `count` distinct extensions of no data, none of them one of the six
    /// typed ones.
    fn distinct(count: u16) -> Vec<u8> {
        (0..count)
            .flat_map(|i| {
                let [high, low] = (0x1000 + i).to_be_bytes();
                [high, low, 0, 0]
            })
            .collect()
    }

    #[test]
    fn a_duplicate_is_found_wherever_it_sits_in_a_full_block() {
        // the most four-octet extensions a 2^16 - 1 octet block holds
        let mut block = distinct(16_383);
        assert_eq!(Extensions::parse(&block).map(|e| e.len()), Ok(16_383));
        // the last one given the first one's type
        let first = [block[0], block[1]];
        let at = block.len() - 4;
        block[at..at + 2].copy_from_slice(&first);
        assert_eq!(Extensions::parse(&block), Err(Error::DuplicateExtension));
    }

    #[test]
    fn a_full_block_costs_in_proportion_to_its_size_not_to_its_square() {
        use std::time::{Duration, Instant};
        let fastest = |block: &[u8]| {
            (0..5)
                .map(|_| {
                    let start = Instant::now();
                    let parsed = Extensions::parse(block);
                    let took = start.elapsed();
                    assert!(parsed.is_ok());
                    took
                })
                .min()
                .unwrap_or(Duration::MAX)
        };
        let small = fastest(&distinct(1023));
        let large = fastest(&distinct(16_383));
        // sixteen times the extensions: roughly sixteen times the work when
        // duplicates are found in one pass over the sorted types, roughly 256
        // when each extension is looked for among all those before it. The
        // fastest of five runs, so a descheduled run does not decide it.
        assert!(
            large < small * 64,
            "1023 extensions in {small:?}, 16383 in {large:?}"
        );
    }

    #[test]
    fn push_refuses_a_duplicate_and_an_untyped_copy_of_a_typed_extension() {
        let mut extensions = Extensions::new();
        extensions.push(Extension::ExtendedMasterSecret).unwrap();
        assert_eq!(
            extensions.push(Extension::ExtendedMasterSecret),
            Err(Error::DuplicateExtension)
        );
        assert_eq!(
            extensions.push(Extension::Unknown {
                extension_type: ExtensionType::USE_SRTP,
                data: vec![0, 2, 0, 1, 0]
            }),
            Err(Error::IllegalValue)
        );
        assert_eq!(extensions.len(), 1);
    }

    #[test]
    fn an_empty_list_is_refused_on_the_way_out_too() {
        let mut extensions = Extensions::new();
        extensions
            .push(Extension::SupportedGroups(Vec::new()))
            .unwrap();
        let mut out = vec![0xEE];
        assert_eq!(extensions.encode(&mut out), Err(Error::Length));
        assert_eq!(out, [0xEE]);
    }
}
