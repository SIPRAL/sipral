// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A self-signed X.509 v3 certificate for an ECDSA P-256 key, and the public
//! key read back out of a peer's certificate: P-256, or RSA.

use core::fmt;

use super::der::{self, Der};
use super::fingerprint::{Fingerprint, HashFunction};
use super::time;
use crate::keys::{CertifiedKey, EcdsaKey, PeerKey, RsaPeerKey};
use crate::{Error, Random};

/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2 (RFC 5758 §3.2).
const ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// `id-ecPublicKey`, 1.2.840.10045.2.1 (RFC 5480 §2.1.1).
const EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `secp256r1`, 1.2.840.10045.3.1.7 (RFC 5480 §2.1.1.1).
const SECP256R1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `rsaEncryption`, 1.2.840.113549.1.1.1 (RFC 3279 §2.3.1).
const RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// `id-at-commonName`, 2.5.4.3 (RFC 5280 Appendix A.1).
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `ub-common-name` (RFC 5280 Appendix A.1), in characters.
const MAX_COMMON_NAME: usize = 64;
/// Octets of randomness in a serial number. RFC 5280 §4.1.2.2 allows up to 20
/// octets and requires a positive value; the top bit is cleared, so the
/// encoding never needs a 21st.
const SERIAL_LEN: usize = 16;

/// `Version` v1, v2 and v3 (RFC 5280 §4.1).
const V1: u8 = 0;
const V2: u8 = 1;
const V3: u8 = 2;

/// What a self-signed certificate says beside its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateParams<'a> {
    /// The common name, used as both subject and issuer; 1 to 64 characters.
    /// Nothing checks it, so it need identify nobody — WebRTC peers put a
    /// random string here.
    pub common_name: &'a str,
    /// Start of the validity period, seconds since 1970-01-01T00:00:00Z.
    pub not_before: u64,
    /// End of the validity period, inclusive, in the same seconds.
    pub not_after: u64,
}

/// A certificate this end presents, in DER.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    /// A self-signed X.509 v3 certificate for `key`, signed by `key`.
    ///
    /// It carries what RFC 5280 §4.1 requires and nothing more: version,
    /// serial number, the `ecdsa-with-SHA256` algorithm with its parameters
    /// absent (RFC 5758 §3.2), the common name as issuer and subject, the
    /// validity period, the P-256 key under `id-ecPublicKey` with the named
    /// curve (RFC 5480 §2.1.1), and the signature as a DER `Ecdsa-Sig-Value`
    /// (RFC 3279 §2.2.3). No extensions: a DTLS-SRTP peer checks the
    /// fingerprint and nothing an extension could say. §4.1.2.1 permits v3
    /// without them.
    ///
    /// The serial number comes from `random`. Signing draws nothing, so the
    /// same key, parameters and randomness always give the same octets.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a common name empty or over 64 characters;
    /// [`Error::InvalidTime`] for a period that ends before it begins or a
    /// date past 9999.
    pub fn self_signed<R: Random + ?Sized>(
        key: &EcdsaKey,
        params: &CertificateParams<'_>,
        random: &mut R,
    ) -> Result<Self, Error> {
        let characters = params.common_name.chars().count();
        if characters == 0 || characters > MAX_COMMON_NAME {
            return Err(Error::Length);
        }
        if params.not_before > params.not_after {
            return Err(Error::InvalidTime);
        }
        let mut serial = [0u8; SERIAL_LEN];
        random.fill(&mut serial);
        if let Some(first) = serial.first_mut() {
            *first &= 0x7F;
        }
        if serial.iter().all(|&b| b == 0)
            && let Some(last) = serial.last_mut()
        {
            *last = 1;
        }

        let mut tbs = Vec::with_capacity(320);
        der::constructed(&mut tbs, der::SEQUENCE, |out| {
            der::constructed(out, der::explicit(0), |out| {
                der::write(out, der::INTEGER, &[V3])
            })?;
            der::unsigned_integer(out, &serial)?;
            signature_algorithm(out)?;
            name(out, params.common_name)?;
            der::constructed(out, der::SEQUENCE, |out| {
                time::write(out, params.not_before)?;
                time::write(out, params.not_after)
            })?;
            name(out, params.common_name)?;
            der::constructed(out, der::SEQUENCE, |out| {
                der::constructed(out, der::SEQUENCE, |out| {
                    der::write(out, der::OBJECT_IDENTIFIER, EC_PUBLIC_KEY)?;
                    der::write(out, der::OBJECT_IDENTIFIER, SECP256R1)
                })?;
                der::bit_string(out, &key.public_key())
            })
        })?;

        let signature = key.sign(&tbs)?;
        let mut certificate = Vec::with_capacity(tbs.len() + 96);
        der::constructed(&mut certificate, der::SEQUENCE, |out| {
            out.extend_from_slice(&tbs);
            signature_algorithm(out)?;
            der::bit_string(out, &signature)
        })?;
        Ok(Self { der: certificate })
    }

    /// The DER, as it goes into a Certificate message.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The `sha-256` fingerprint to put in `a=fingerprint`.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(HashFunction::Sha256, &self.der)
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

/// `AlgorithmIdentifier` for `ecdsa-with-SHA256`: RFC 5758 §3.2 has the
/// encoding "omit the parameters field".
fn signature_algorithm(out: &mut Vec<u8>) -> Result<(), Error> {
    der::constructed(out, der::SEQUENCE, |out| {
        der::write(out, der::OBJECT_IDENTIFIER, ECDSA_WITH_SHA256)
    })
}

/// A `Name` of one relative distinguished name holding one common name, as a
/// UTF8String (RFC 5280 §4.1.2.4 allows it and PrintableString only).
fn name(out: &mut Vec<u8>, common_name: &str) -> Result<(), Error> {
    der::constructed(out, der::SEQUENCE, |out| {
        der::constructed(out, der::SET, |out| {
            der::constructed(out, der::SEQUENCE, |out| {
                der::write(out, der::OBJECT_IDENTIFIER, COMMON_NAME)?;
                der::write(out, der::UTF8_STRING, common_name.as_bytes())
            })
        })
    })
}

/// A certificate's `SubjectPublicKeyInfo`, borrowed from its DER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectPublicKeyInfo<'a> {
    /// The algorithm's object identifier, its content octets only.
    pub algorithm: &'a [u8],
    /// The algorithm's parameters, the whole element, when present.
    pub parameters: Option<&'a [u8]>,
    /// The key: the octets of `subjectPublicKey`.
    pub public_key: &'a [u8],
}

impl<'a> SubjectPublicKeyInfo<'a> {
    /// Read a DER certificate as far as its public key.
    ///
    /// The structure of RFC 5280 §4.1 is followed element by element — every
    /// field must be the type it should be and in its place, and nothing may
    /// follow the last — but what the fields before the key say is not
    /// looked at, because nothing in DTLS-SRTP depends on it. The version is
    /// the one exception, since it says which optional fields may follow.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`], [`Error::TrailingData`], [`Error::IllegalValue`]
    /// or [`Error::TooLarge`] for anything that is not a DER certificate:
    /// a length DER forbids, an element of the wrong type or in the wrong
    /// place, a version other than 1, 2 or 3 or one that does not allow the
    /// optional fields present, a key with unused bits.
    pub fn from_certificate(certificate: &'a [u8]) -> Result<Self, Error> {
        Parts::parse(certificate).map(|parts| parts.key)
    }

    /// The key as P-256, when that is what it is.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] unless the algorithm is `id-ecPublicKey` with
    /// the named curve `secp256r1` — RFC 5480 §2.1.1 makes the parameters
    /// mandatory and the named curve the only form PKIX uses — and
    /// [`Error::InvalidPublicKey`] for a key that is not an uncompressed
    /// point on the curve.
    pub fn p256_key(&self) -> Result<PeerKey, Error> {
        if self.algorithm != EC_PUBLIC_KEY {
            return Err(Error::IllegalValue);
        }
        let mut parameters = Der::new(self.parameters.ok_or(Error::IllegalValue)?);
        let curve = parameters.expect(der::OBJECT_IDENTIFIER)?;
        parameters.finish()?;
        if curve.content != SECP256R1 {
            return Err(Error::IllegalValue);
        }
        PeerKey::from_uncompressed(self.public_key)
    }

    /// The key as RSA, when that is what it is.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] unless the algorithm is `rsaEncryption` with
    /// the NULL parameters RFC 3279 §2.3.1 requires ("MUST have ASN.1 type
    /// NULL"), and the key an `RSAPublicKey` of exactly two positive
    /// INTEGERs in DER; [`Error::UnacceptableRsaKey`] for one
    /// [`RsaPeerKey::from_parts`] refuses.
    pub fn rsa_key(&self) -> Result<RsaPeerKey, Error> {
        if self.algorithm != RSA_ENCRYPTION {
            return Err(Error::IllegalValue);
        }
        let mut parameters = Der::new(self.parameters.ok_or(Error::IllegalValue)?);
        let null = parameters.expect(der::NULL)?;
        parameters.finish()?;
        if !null.content.is_empty() {
            return Err(Error::IllegalValue);
        }
        let mut outer = Der::new(self.public_key);
        let key = outer.expect(der::SEQUENCE)?;
        outer.finish()?;
        let mut fields = Der::new(key.content);
        let modulus = der::positive_integer(fields.expect(der::INTEGER)?.content)?;
        let exponent = der::positive_integer(fields.expect(der::INTEGER)?.content)?;
        fields.finish()?;
        RsaPeerKey::from_parts(modulus, exponent)
    }

    /// The key, of whichever kind this crate verifies with.
    ///
    /// # Errors
    ///
    /// As [`SubjectPublicKeyInfo::p256_key`] or
    /// [`SubjectPublicKeyInfo::rsa_key`], by the algorithm named, and
    /// [`Error::IllegalValue`] for any other algorithm.
    pub fn certified_key(&self) -> Result<CertifiedKey, Error> {
        if self.algorithm == RSA_ENCRYPTION {
            self.rsa_key().map(CertifiedKey::Rsa)
        } else {
            self.p256_key().map(CertifiedKey::P256)
        }
    }
}

/// The pieces of a certificate a reader needs.
struct Parts<'a> {
    /// `tbsCertificate`, the whole element: what the signature covers.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the self-signature is checked only in tests")
    )]
    tbs: &'a [u8],
    /// `signatureAlgorithm`'s content.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the self-signature is checked only in tests")
    )]
    signature_algorithm: &'a [u8],
    /// `signatureValue`'s octets.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the self-signature is checked only in tests")
    )]
    signature: &'a [u8],
    key: SubjectPublicKeyInfo<'a>,
}

impl<'a> Parts<'a> {
    fn parse(certificate: &'a [u8]) -> Result<Self, Error> {
        let mut outer = Der::new(certificate);
        let body = outer.expect(der::SEQUENCE)?;
        outer.finish()?;

        let mut fields = Der::new(body.content);
        let tbs = fields.expect(der::SEQUENCE)?;
        let signature_algorithm = fields.expect(der::SEQUENCE)?;
        let signature = whole_octets(fields.expect(der::BIT_STRING)?.content)?;
        fields.finish()?;

        let mut tbs_fields = Der::new(tbs.content);
        let version = match tbs_fields.optional(der::explicit(0))? {
            None => V1,
            Some(explicit) => {
                let mut inner = Der::new(explicit.content);
                let integer = inner.expect(der::INTEGER)?;
                inner.finish()?;
                match integer.content {
                    [version @ (V1 | V2 | V3)] => *version,
                    _ => return Err(Error::IllegalValue),
                }
            }
        };
        let serial = tbs_fields.expect(der::INTEGER)?;
        if serial.content.is_empty() {
            return Err(Error::Length);
        }
        tbs_fields.expect(der::SEQUENCE)?; // signature
        tbs_fields.expect(der::SEQUENCE)?; // issuer
        tbs_fields.expect(der::SEQUENCE)?; // validity
        tbs_fields.expect(der::SEQUENCE)?; // subject
        let key_info = tbs_fields.expect(der::SEQUENCE)?;
        // issuerUniqueID and subjectUniqueID "If present, version MUST be v2
        // or v3"; extensions "If present, version MUST be v3"
        for tag in [der::implicit(1), der::implicit(2)] {
            if tbs_fields.optional(tag)?.is_some() && version == V1 {
                return Err(Error::IllegalValue);
            }
        }
        if tbs_fields.optional(der::explicit(3))?.is_some() && version != V3 {
            return Err(Error::IllegalValue);
        }
        tbs_fields.finish()?;

        let mut key_fields = Der::new(key_info.content);
        let algorithm = key_fields.expect(der::SEQUENCE)?;
        let public_key = whole_octets(key_fields.expect(der::BIT_STRING)?.content)?;
        key_fields.finish()?;

        let mut algorithm_fields = Der::new(algorithm.content);
        let identifier = algorithm_fields.expect(der::OBJECT_IDENTIFIER)?;
        let parameters = if algorithm_fields.is_empty() {
            None
        } else {
            Some(algorithm_fields.next()?.encoded)
        };
        algorithm_fields.finish()?;

        Ok(Self {
            tbs: tbs.encoded,
            signature_algorithm: signature_algorithm.content,
            signature,
            key: SubjectPublicKeyInfo {
                algorithm: identifier.content,
                parameters,
                public_key,
            },
        })
    }
}

/// The octets of a BIT STRING whose length is a whole number of octets, which
/// every BIT STRING a certificate carries a key or signature in is.
fn whole_octets(content: &[u8]) -> Result<&[u8], Error> {
    match content.split_first() {
        Some((0, octets)) => Ok(octets),
        Some(_) => Err(Error::IllegalValue),
        None => Err(Error::Length),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fingerprint::tests::{OPENSSL_SHA256, openssl_certificate};
    use super::super::rsa_fixtures as rsa;
    use super::*;
    use crate::handshake::SignatureAndHash;
    use crate::random::testing::Counter;

    const PARAMS: CertificateParams<'static> = CertificateParams {
        common_name: "sipral",
        not_before: 1_785_542_400,
        not_after: 1_785_542_400 + 30 * 86_400,
    };

    fn ours() -> (EcdsaKey, Certificate) {
        let mut random = Counter::new(8122);
        let key = EcdsaKey::generate(&mut random).unwrap();
        let certificate = Certificate::self_signed(&key, &PARAMS, &mut random).unwrap();
        (key, certificate)
    }

    #[test]
    fn a_self_signed_certificate_carries_its_key_and_its_own_signature() {
        let (key, certificate) = ours();
        let parts = Parts::parse(certificate.der()).unwrap();
        assert_eq!(parts.key.p256_key().unwrap(), key.peer_key());
        assert_eq!(
            parts.signature_algorithm,
            [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
        );
        assert_eq!(key.peer_key().verify(parts.tbs, parts.signature), Ok(()));
        assert_eq!(
            parts.key.parameters,
            Some(&[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07][..])
        );
    }

    #[test]
    fn the_certificate_is_the_structure_rfc_5280_describes() {
        let (key, certificate) = ours();
        let der = certificate.der();
        let mut outer = Der::new(der);
        let body = outer.expect(der::SEQUENCE).unwrap();
        let mut fields = Der::new(body.content);
        let tbs = fields.expect(der::SEQUENCE).unwrap();
        let mut tbs_fields = Der::new(tbs.content);

        // version [0] EXPLICIT INTEGER 2
        assert_eq!(
            tbs_fields.next().unwrap().encoded,
            [0xA0, 0x03, 0x02, 0x01, 0x02]
        );
        let serial = tbs_fields.expect(der::INTEGER).unwrap();
        assert!(serial.content.len() <= 16 && serial.content[0] & 0x80 == 0);
        let algorithm = tbs_fields.expect(der::SEQUENCE).unwrap();
        assert_eq!(
            algorithm.content,
            [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
        );
        let name = [
            0x30, 0x11, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x06, b's',
            b'i', b'p', b'r', b'a', b'l',
        ];
        assert_eq!(tbs_fields.next().unwrap().encoded, name);
        let validity = tbs_fields.expect(der::SEQUENCE).unwrap();
        assert_eq!(
            validity.content,
            [
                &[0x17, 0x0D][..],
                b"260801000000Z",
                &[0x17, 0x0D],
                b"260831000000Z"
            ]
            .concat()
        );
        assert_eq!(tbs_fields.next().unwrap().encoded, name);
        let key_info = tbs_fields.expect(der::SEQUENCE).unwrap();
        let mut expected_key_info = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        expected_key_info.extend_from_slice(&key.public_key());
        assert_eq!(key_info.encoded, expected_key_info);
        assert_eq!(tbs_fields.finish(), Ok(()));
    }

    #[test]
    fn the_same_inputs_give_the_same_certificate_and_its_fingerprint_is_sha_256() {
        let (_, first) = ours();
        let (_, second) = ours();
        assert_eq!(first, second);
        let fingerprint = first.fingerprint();
        assert_eq!(fingerprint.hash(), HashFunction::Sha256);
        assert!(fingerprint.matches(first.der()));
        let printed = fingerprint.to_string();
        assert!(printed.starts_with("sha-256 "));
        assert_eq!(printed.len(), "sha-256 ".len() + 32 * 3 - 1);
        assert_eq!(Fingerprint::parse(&printed), Ok(fingerprint));
        assert_eq!(
            format!("{first:?}"),
            format!("Certificate {{ fingerprint: Fingerprint({printed}) }}")
        );
    }

    #[test]
    fn what_cannot_be_written_is_refused() {
        let mut random = Counter::new(1);
        let key = EcdsaKey::generate(&mut random).unwrap();
        let with = |common_name, not_before, not_after| CertificateParams {
            common_name,
            not_before,
            not_after,
        };
        let long = "é".repeat(64);
        assert!(Certificate::self_signed(&key, &with(&long, 0, 0), &mut random).is_ok());
        let too_long = "é".repeat(65);
        let cases = [
            (with("", 0, 1), Error::Length),
            (with(&too_long, 0, 1), Error::Length),
            (with("x", 10, 9), Error::InvalidTime),
            (with("x", 0, 253_402_300_800), Error::InvalidTime),
        ];
        for (params, error) in cases {
            assert_eq!(
                Certificate::self_signed(&key, &params, &mut random).err(),
                Some(error)
            );
        }
        // RFC 5280's "no well-defined expiration date"
        let forever =
            Certificate::self_signed(&key, &with("x", 0, 253_402_300_799), &mut random).unwrap();
        assert!(forever.der().windows(15).any(|w| w == b"99991231235959Z"));
    }

    #[test]
    fn the_key_is_read_out_of_a_certificate_another_implementation_wrote() {
        let certificate = openssl_certificate();
        let info = SubjectPublicKeyInfo::from_certificate(&certificate).unwrap();
        let point: Vec<u8> = "04359696c8d34254662448c8408d17f8e32073a932f38c6d350423fe0b9eebd6f5\
                              35a59e1a5739a014430382f1363f7df8d803f11d217e07c9a21f84fafb89febb"
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(info.p256_key().unwrap().to_uncompressed().to_vec(), point);
        assert_eq!(info.public_key, point);
        // its own signature, over a tbsCertificate carrying three extensions
        let parts = Parts::parse(&certificate).unwrap();
        assert_eq!(
            info.p256_key().unwrap().verify(parts.tbs, parts.signature),
            Ok(())
        );
        assert!(
            Fingerprint::parse(OPENSSL_SHA256)
                .unwrap()
                .matches(&certificate)
        );
    }

    #[test]
    fn a_certificate_cut_short_or_extended_is_refused() {
        for certificate in [openssl_certificate(), ours().1.der().to_vec()] {
            for cut in 0..certificate.len() {
                assert!(
                    SubjectPublicKeyInfo::from_certificate(&certificate[..cut]).is_err(),
                    "cut at {cut}"
                );
            }
            let mut longer = certificate.clone();
            longer.push(0);
            assert_eq!(
                SubjectPublicKeyInfo::from_certificate(&longer),
                Err(Error::TrailingData)
            );
        }
    }

    #[test]
    fn a_certificate_der_would_not_write_is_refused() {
        let (_, certificate) = ours();
        let der = certificate.der();
        // the outer length rewritten with a leading zero octet: same value,
        // not the shortest form
        assert_eq!(der[1], 0x82);
        let mut padded = vec![0x30, 0x83, 0x00];
        padded.extend_from_slice(&der[2..]);
        assert_eq!(
            SubjectPublicKeyInfo::from_certificate(&padded),
            Err(Error::IllegalValue)
        );
        // a SET where the certificate's SEQUENCE belongs
        let mut wrong_tag = der.to_vec();
        wrong_tag[0] = der::SET;
        assert_eq!(
            SubjectPublicKeyInfo::from_certificate(&wrong_tag),
            Err(Error::IllegalValue)
        );
        // version 4
        let at = der
            .windows(5)
            .position(|w| w == [0xA0, 0x03, 0x02, 0x01, 0x02])
            .unwrap();
        let mut v4 = der.to_vec();
        v4[at + 4] = 3;
        assert_eq!(
            SubjectPublicKeyInfo::from_certificate(&v4),
            Err(Error::IllegalValue)
        );
        // the key's BIT STRING claiming unused bits
        let key_at = der
            .windows(3)
            .position(|w| w == [0x03, 0x42, 0x00])
            .unwrap();
        let mut unused = der.to_vec();
        unused[key_at + 2] = 1;
        assert_eq!(
            SubjectPublicKeyInfo::from_certificate(&unused),
            Err(Error::IllegalValue)
        );
    }

    #[test]
    fn extensions_on_a_certificate_that_is_not_v3_are_refused() {
        let certificate = openssl_certificate();
        // the OpenSSL certificate is v3 with extensions; say v2 instead
        let at = certificate
            .windows(5)
            .position(|w| w == [0xA0, 0x03, 0x02, 0x01, 0x02])
            .unwrap();
        let mut v2 = certificate.clone();
        v2[at + 4] = 1;
        assert_eq!(
            SubjectPublicKeyInfo::from_certificate(&v2),
            Err(Error::IllegalValue)
        );
    }

    #[test]
    fn only_a_p256_key_under_its_named_curve_is_a_p256_key() {
        let (key, certificate) = ours();
        let good = SubjectPublicKeyInfo::from_certificate(certificate.der()).unwrap();
        let point = key.public_key();
        let rsa: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
        let secp384r1: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
        let compressed = [&[0x02 | (point[64] & 1)][..], &point[1..33]].concat();
        let cases = [
            (
                SubjectPublicKeyInfo {
                    algorithm: rsa,
                    ..good
                },
                Error::IllegalValue,
            ),
            (
                SubjectPublicKeyInfo {
                    parameters: None,
                    ..good
                },
                Error::IllegalValue,
            ),
            (
                SubjectPublicKeyInfo {
                    parameters: Some(secp384r1),
                    ..good
                },
                Error::IllegalValue,
            ),
            (
                SubjectPublicKeyInfo {
                    parameters: Some(&[0x05, 0x00]),
                    ..good
                },
                Error::IllegalValue,
            ),
            (
                SubjectPublicKeyInfo {
                    public_key: &compressed,
                    ..good
                },
                Error::InvalidPublicKey,
            ),
        ];
        for (info, error) in cases {
            assert_eq!(info.p256_key().err(), Some(error), "{info:?}");
        }
    }

    #[test]
    fn no_change_to_a_certificate_makes_the_reader_panic() {
        // every octet at every position, not a handful of bit-flips: a flip
        // mask almost never lands on the one value — often zero, for a
        // length or a count — that would exercise a missing bounds check the
        // original octet happened to be far from.
        for certificate in [openssl_certificate(), ours().1.der().to_vec()] {
            for position in 0..certificate.len() {
                for byte in 0u8..=255 {
                    let mut mutated = certificate.clone();
                    mutated[position] = byte;
                    if let Ok(info) = SubjectPublicKeyInfo::from_certificate(&mutated) {
                        let _ = info.p256_key();
                    }
                }
            }
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn rsa(certificate: &str) -> CertifiedKey {
        SubjectPublicKeyInfo::from_certificate(&unhex(certificate))
            .unwrap()
            .certified_key()
            .unwrap()
    }

    #[test]
    fn an_rsa_key_another_implementation_certified_verifies_what_it_signed() {
        for (certificate, signature, bits) in [
            (rsa::CERTIFICATE_2048, rsa::SIGNATURE_2048, 2048),
            (rsa::CERTIFICATE_4096, rsa::SIGNATURE_4096, 4096),
        ] {
            let key = rsa(certificate);
            let CertifiedKey::Rsa(ref inner) = key else {
                panic!("an RSA certificate read as {key:?}");
            };
            assert_eq!(inner.len() * 8, bits);
            assert_eq!(key.algorithm(), SignatureAndHash::RSA_PKCS1_SHA256);
            assert_eq!(
                key.verify(
                    SignatureAndHash::RSA_PKCS1_SHA256,
                    rsa::MESSAGE,
                    &unhex(signature)
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn an_rsa_signature_that_is_not_exactly_right_is_refused() {
        let key = rsa(rsa::CERTIFICATE_2048);
        let signature = unhex(rsa::SIGNATURE_2048);
        let check = |message: &[u8], signature: &[u8]| {
            key.verify(SignatureAndHash::RSA_PKCS1_SHA256, message, signature)
        };
        // every bit of the signature matters
        for bit in 0..signature.len() * 8 {
            let mut flipped = signature.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                check(rsa::MESSAGE, &flipped),
                Err(Error::BadSignature),
                "bit {bit}"
            );
        }
        // and so does every bit of what it is over
        let mut other = rsa::MESSAGE.to_vec();
        other[0] ^= 1;
        assert_eq!(check(&other, &signature), Err(Error::BadSignature));
        // a signature one octet short or long of the modulus, even when the
        // number is the same one (RFC 8017 §8.2.2 step 1)
        let mut longer = vec![0];
        longer.extend_from_slice(&signature);
        assert_eq!(check(rsa::MESSAGE, &longer), Err(Error::BadSignature));
        assert_eq!(
            check(rsa::MESSAGE, &signature[1..]),
            Err(Error::BadSignature)
        );
        assert_eq!(check(rsa::MESSAGE, &[]), Err(Error::BadSignature));
        // a signature under another key
        assert_eq!(
            check(rsa::MESSAGE, &unhex(rsa::SIGNATURE_4096)),
            Err(Error::BadSignature)
        );
        // an ECDSA pair claimed under an RSA key
        assert_eq!(
            key.verify(SignatureAndHash::ECDSA_SHA256, rsa::MESSAGE, &signature),
            Err(Error::IllegalValue)
        );
    }

    #[test]
    fn an_rsa_key_shorter_than_2048_bits_is_refused() {
        let info = SubjectPublicKeyInfo::from_certificate(&unhex(rsa::CERTIFICATE_1024))
            .map(|info| info.certified_key());
        assert_eq!(info, Ok(Err(Error::UnacceptableRsaKey)));
    }

    #[test]
    fn only_an_rsa_key_under_rsa_encryption_with_null_parameters_is_an_rsa_key() {
        let certificate = unhex(rsa::CERTIFICATE_2048);
        let info = SubjectPublicKeyInfo::from_certificate(&certificate).unwrap();
        assert_eq!(info.p256_key().err(), Some(Error::IllegalValue));
        let (_, ecdsa) = ours();
        let p256 = SubjectPublicKeyInfo::from_certificate(ecdsa.der()).unwrap();
        assert_eq!(p256.rsa_key().err(), Some(Error::IllegalValue));

        // the NULL after the identifier, made an empty OCTET STRING of the
        // same length so that nothing around it moves
        let identifier = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
        ];
        let at = certificate
            .windows(identifier.len())
            .position(|window| window == identifier)
            .unwrap()
            + identifier.len();
        assert_eq!(certificate[at..at + 2], [0x05, 0x00]);
        let mut not_null = certificate.clone();
        not_null[at] = 0x04;
        let info = SubjectPublicKeyInfo::from_certificate(&not_null).unwrap();
        assert_eq!(info.rsa_key().err(), Some(Error::IllegalValue));
    }

    #[test]
    fn rsa_parts_no_key_can_be_made_from_are_refused() {
        let mut modulus = vec![0xC5; 256];
        modulus[255] = 0x01;
        assert!(RsaPeerKey::from_parts(&modulus, &[0x01, 0x00, 0x01]).is_ok());
        let cases: [(&str, Vec<u8>, &[u8]); 5] = [
            (
                "even",
                {
                    let mut even = modulus.clone();
                    even[255] = 0x02;
                    even
                },
                &[0x01, 0x00, 0x01],
            ),
            (
                "2047 bits",
                {
                    let mut short = modulus.clone();
                    short[0] = 0x45;
                    short
                },
                &[0x01, 0x00, 0x01],
            ),
            ("exponent 1", modulus.clone(), &[0x01]),
            (
                "exponent past 2^33 - 1",
                modulus.clone(),
                &[0x02, 0x00, 0x00, 0x00, 0x01],
            ),
            (
                "longer than 8192 bits",
                {
                    let mut long = vec![0xC5; 1025];
                    long[1024] = 0x01;
                    long
                },
                &[0x01, 0x00, 0x01],
            ),
        ];
        for (what, modulus, exponent) in cases {
            assert_eq!(
                RsaPeerKey::from_parts(&modulus, exponent).err(),
                Some(Error::UnacceptableRsaKey),
                "{what}"
            );
        }
    }
}
