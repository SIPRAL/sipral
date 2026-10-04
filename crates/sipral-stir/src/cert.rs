// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! STIR certificates (RFC 8226): reading the chain an `x5u` URI yields,
//! building a path from the signing certificate to one of the application's
//! trust anchors, and holding that path to the rules of RFC 5280 §6 this
//! crate checks.
//!
//! What is checked, for every certificate between the signing certificate
//! and the trust anchor, the signing certificate included:
//!
//! - its signature, by its issuer's key: ECDSA with SHA-256 over P-256
//!   (RFC 5758 §3.2, RFC 5480), the one algorithm STIR certificates are
//!   issued with, with the two signature algorithm fields agreeing (RFC 5280
//!   §4.1.1.2);
//! - its validity period against the time the caller gives (RFC 5280
//!   §4.1.2.5, both ends inclusive);
//! - no extension marked critical that is not processed here, and no
//!   extension twice (RFC 5280 §4.2);
//! - for every issuer below the trust anchor: basic constraints with `cA`
//!   set, a `pathLenConstraint` the path below it keeps to (RFC 5280
//!   §4.2.1.9), and `keyCertSign` if it has a key usage extension (RFC 5280
//!   §4.2.1.3);
//! - for the signing certificate: a P-256 key, `digitalSignature` if it has a
//!   key usage extension, and a TNAuthList that parses.
//!
//! A path holds at most [`MAX_CHAIN_CERTIFICATES`] certificates below its
//! trust anchor. Issuer and subject names are compared by their DER
//! encodings, which is RFC 5280 §7.1's comparison for names encoded the same
//! way and stricter than it otherwise.
//!
//! A trust anchor is taken as the application gives it: its own validity
//! period and constraints are not checked, as RFC 5280 §6.1.1 (d) treats an
//! anchor as information rather than as a certificate in the path.

use std::fmt;

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{DerSignature, VerifyingKey};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::name::Name;

use crate::base64;
use crate::der::{self, SEQUENCE};
use crate::tnauthlist::TnAuthList;
use crate::verdict::{ChainProblem, Failure, InfoProblem};

/// The most certificates a fetched chain may hold, and so the longest path
/// below a trust anchor.
pub const MAX_CHAIN_CERTIFICATES: usize = 10;
/// The largest certificate read, in octets of DER.
pub const MAX_CERTIFICATE_LEN: usize = 16 * 1024;
/// The largest chain read, in octets as fetched: ten of the largest
/// certificates, in PEM.
pub const MAX_CHAIN_LEN: usize = 256 * 1024;

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const TN_AUTH_LIST: ObjectIdentifier = ObjectIdentifier::new_unwrap(crate::tnauthlist::OID);

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM_LABEL: &str = "CERTIFICATE-----";

/// A certificate, and the octets its signature covers.
struct Parsed {
    tbs: Vec<u8>,
    certificate: Certificate,
}

impl Parsed {
    fn new(der: &[u8]) -> Result<Self, InfoProblem> {
        if der.len() > MAX_CERTIFICATE_LEN {
            return Err(InfoProblem::TooLarge);
        }
        let certificate = Certificate::from_der(der).map_err(|_| InfoProblem::Unreadable)?;
        let outer = der::only(der, SEQUENCE).map_err(|_| InfoProblem::Unreadable)?;
        let (tbs, _) =
            der::expect(outer.contents, SEQUENCE).map_err(|_| InfoProblem::Unreadable)?;
        let tbs = tbs.encoded.to_vec();
        Ok(Parsed { tbs, certificate })
    }

    fn subject(&self) -> &Name {
        self.certificate.tbs_certificate().subject()
    }

    fn issuer(&self) -> &Name {
        self.certificate.tbs_certificate().issuer()
    }

    fn key(&self) -> Option<VerifyingKey> {
        let spki = self.certificate.tbs_certificate().subject_public_key_info();
        if spki.algorithm.oid != EC_PUBLIC_KEY {
            return None;
        }
        let curve: ObjectIdentifier = spki.algorithm.parameters.as_ref()?.decode_as().ok()?;
        if curve != PRIME256V1 {
            return None;
        }
        VerifyingKey::from_sec1_bytes(spki.subject_public_key.as_bytes()?).ok()
    }

    /// Check this certificate's signature under `key`.
    fn signed_by(&self, key: &VerifyingKey, depth: usize) -> Result<(), ChainProblem> {
        let algorithm = self.certificate.signature_algorithm();
        if algorithm != self.certificate.tbs_certificate().signature()
            || algorithm.oid != ECDSA_WITH_SHA256
            || algorithm.parameters.is_some()
        {
            return Err(ChainProblem::Algorithm { depth });
        }
        let signature = self
            .certificate
            .signature()
            .as_bytes()
            .and_then(|bytes| DerSignature::from_bytes(bytes).ok())
            .ok_or(ChainProblem::Signature { depth })?;
        key.verify(&self.tbs, &signature)
            .map_err(|_| ChainProblem::Signature { depth })
    }
}

/// Split what was fetched into DER certificates: PEM (RFC 7468 §5, any
/// text outside the `CERTIFICATE` blocks ignored) or DER, one certificate
/// after another.
fn split(input: &[u8], max_len: usize, max_count: usize) -> Result<Vec<Vec<u8>>, InfoProblem> {
    if input.len() > max_len {
        return Err(InfoProblem::TooLarge);
    }
    let start = input
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(input.len());
    let rest = input.get(start..).unwrap_or_default();
    let certificates = if rest.first() == Some(&SEQUENCE) {
        split_der(rest, max_count)?
    } else {
        let text = std::str::from_utf8(input).map_err(|_| InfoProblem::Unreadable)?;
        split_pem(text, max_count)?
    };
    if certificates.is_empty() {
        Err(InfoProblem::Empty)
    } else {
        Ok(certificates)
    }
}

fn split_der(mut rest: &[u8], max_count: usize) -> Result<Vec<Vec<u8>>, InfoProblem> {
    let mut certificates = Vec::new();
    while !rest.is_empty() {
        let (certificate, tail) =
            der::expect(rest, SEQUENCE).map_err(|_| InfoProblem::Unreadable)?;
        if certificates.len() == max_count {
            return Err(InfoProblem::TooManyCertificates);
        }
        certificates.push(certificate.encoded.to_vec());
        rest = tail;
    }
    Ok(certificates)
}

fn split_pem(text: &str, max_count: usize) -> Result<Vec<Vec<u8>>, InfoProblem> {
    let mut certificates = Vec::new();
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line.strip_prefix(PEM_BEGIN) else {
            continue;
        };
        let mut body = String::new();
        let mut ended = false;
        for line in lines.by_ref() {
            if let Some(end) = line.strip_prefix(PEM_END) {
                if end != label {
                    return Err(InfoProblem::Unreadable);
                }
                ended = true;
                break;
            }
            body.extend(line.chars().filter(|c| !c.is_ascii_whitespace()));
            if body.len() > MAX_CERTIFICATE_LEN * 2 {
                return Err(InfoProblem::TooLarge);
            }
        }
        if !ended {
            return Err(InfoProblem::Unreadable);
        }
        // a key, a CRL or anything else beside the certificates is not ours
        if label != PEM_LABEL {
            continue;
        }
        if certificates.len() == max_count {
            return Err(InfoProblem::TooManyCertificates);
        }
        let der = base64::decode_standard(body.as_bytes()).map_err(|_| InfoProblem::Unreadable)?;
        certificates.push(der);
    }
    Ok(certificates)
}

/// The certificates a verifier trusts to issue STIR certificates: the STI-PA
/// approved roots, in a SHAKEN deployment.
#[derive(Clone, Default)]
pub struct TrustAnchors {
    anchors: Vec<Anchor>,
}

#[derive(Clone)]
struct Anchor {
    subject: Name,
    key: VerifyingKey,
}

/// A trust anchor that cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// Neither PEM nor DER certificates, or a certificate that does not
    /// parse.
    Unreadable,
    /// A certificate larger than [`MAX_CERTIFICATE_LEN`].
    TooLarge,
    /// No certificate at all.
    Empty,
    /// A key other than P-256, which could not have signed a STIR
    /// certificate this crate verifies.
    UnsupportedKey,
}

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AnchorError::Unreadable => "unreadable trust anchor",
            AnchorError::TooLarge => "trust anchor too large",
            AnchorError::Empty => "no trust anchor",
            AnchorError::UnsupportedKey => "trust anchor key is not P-256",
        })
    }
}

impl std::error::Error for AnchorError {}

impl TrustAnchors {
    /// No anchors yet.
    #[must_use]
    pub fn new() -> Self {
        TrustAnchors::default()
    }

    /// Add every certificate in `certificates`, PEM or DER, and say how many
    /// there were. Nothing is added unless all of them can be.
    ///
    /// # Errors
    ///
    /// An [`AnchorError`] for the first certificate that cannot be used.
    pub fn add(&mut self, certificates: &[u8]) -> Result<usize, AnchorError> {
        let split =
            split(certificates, usize::MAX, usize::MAX).map_err(|problem| match problem {
                InfoProblem::Empty => AnchorError::Empty,
                InfoProblem::TooLarge => AnchorError::TooLarge,
                _ => AnchorError::Unreadable,
            })?;
        let mut added = Vec::with_capacity(split.len());
        for der in split {
            let parsed = Parsed::new(&der).map_err(|problem| match problem {
                InfoProblem::TooLarge => AnchorError::TooLarge,
                _ => AnchorError::Unreadable,
            })?;
            let key = parsed.key().ok_or(AnchorError::UnsupportedKey)?;
            added.push(Anchor {
                subject: parsed.subject().clone(),
                key,
            });
        }
        let count = added.len();
        self.anchors.extend(added);
        Ok(count)
    }

    /// How many anchors there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether there are none, in which case nothing verifies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

impl fmt::Debug for TrustAnchors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustAnchors")
            .field("len", &self.anchors.len())
            .finish()
    }
}

/// The signing certificate of a validated path: its key and its TNAuthList.
#[derive(Debug)]
pub(crate) struct Leaf {
    pub(crate) key: VerifyingKey,
    pub(crate) tn_auth_list: Option<TnAuthList>,
}

/// Validate the chain `input` holds, its first certificate the signing one,
/// against `anchors` at `now`, seconds since the Unix epoch.
pub(crate) fn validate(input: &[u8], anchors: &TrustAnchors, now: u64) -> Result<Leaf, Failure> {
    let certificates = split(input, MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES)
        .map_err(Failure::BadInfo)?
        .into_iter()
        .map(|der| Parsed::new(&der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Failure::BadInfo)?;
    let path = build_path(&certificates, anchors)?;
    let mut leaf = None;
    for (depth, certificate) in path.iter().enumerate() {
        let checked = check(certificate, depth, now)?;
        if depth == 0 {
            leaf = Some(checked);
        } else if let Some(limit) = checked.path_len {
            // intermediates below this one, the signing certificate not
            // counted (RFC 5280 §4.2.1.9)
            if depth - 1 > usize::from(limit) {
                return Err(Failure::InvalidChain(ChainProblem::PathLength { depth }));
            }
        }
    }
    let leaf = leaf.ok_or(Failure::BadInfo(InfoProblem::Empty))?;
    let key = path
        .first()
        .and_then(|certificate| certificate.key())
        .ok_or(Failure::InvalidChain(ChainProblem::Algorithm { depth: 0 }))?;
    Ok(Leaf {
        key,
        tn_auth_list: leaf.tn_auth_list,
    })
}

/// The certificates from the signing one up to the last before a trust
/// anchor, each one's signature checked under the next one's key, or the
/// anchor's.
fn build_path<'a>(
    certificates: &'a [Parsed],
    anchors: &TrustAnchors,
) -> Result<Vec<&'a Parsed>, Failure> {
    let mut path: Vec<usize> = vec![0];
    // each round either ends or adds a certificate not yet in the path, so
    // there are at most as many rounds as certificates
    for depth in 0..certificates.len() {
        let current = path
            .last()
            .and_then(|&i| certificates.get(i))
            .ok_or(Failure::BadInfo(InfoProblem::Empty))?;
        let mut problem = None;
        for anchor in anchors
            .anchors
            .iter()
            .filter(|a| a.subject == *current.issuer())
        {
            match current.signed_by(&anchor.key, depth) {
                Ok(()) => {
                    return Ok(path.iter().filter_map(|&i| certificates.get(i)).collect());
                }
                Err(found) => {
                    problem.get_or_insert(found);
                }
            }
        }
        let mut next = None;
        for (i, candidate) in certificates.iter().enumerate() {
            if path.contains(&i) || candidate.subject() != current.issuer() {
                continue;
            }
            let Some(key) = candidate.key() else {
                problem.get_or_insert(ChainProblem::Algorithm { depth: depth + 1 });
                continue;
            };
            match current.signed_by(&key, depth) {
                Ok(()) => {
                    next = Some(i);
                    break;
                }
                Err(found) => {
                    problem.get_or_insert(found);
                }
            }
        }
        match next {
            Some(i) => path.push(i),
            None => {
                return Err(problem.map_or(Failure::Untrusted, Failure::InvalidChain));
            }
        }
    }
    Err(Failure::Untrusted)
}

/// What checking one certificate found that the path needs.
struct Checked {
    path_len: Option<u8>,
    tn_auth_list: Option<TnAuthList>,
}

/// The checks of one certificate at `depth` in the path.
fn check(certificate: &Parsed, depth: usize, now: u64) -> Result<Checked, Failure> {
    let tbs = certificate.certificate.tbs_certificate();
    let validity = tbs.validity();
    if now < validity.not_before.to_unix_duration().as_secs() {
        return Err(Failure::NotYetValid { depth });
    }
    if now > validity.not_after.to_unix_duration().as_secs() {
        return Err(Failure::Expired { depth });
    }
    let chain = |problem| Failure::InvalidChain(problem);
    let bad = || chain(ChainProblem::BadExtension { depth });
    let mut basic = None;
    let mut usage = None;
    let mut tn_auth_list = None;
    let mut seen: Vec<&ObjectIdentifier> = Vec::new();
    for extension in tbs.extensions().map(Vec::as_slice).unwrap_or_default() {
        if seen.contains(&&extension.extn_id) {
            return Err(chain(ChainProblem::DuplicateExtension { depth }));
        }
        seen.push(&extension.extn_id);
        let value = extension.extn_value.as_bytes();
        if extension.extn_id == BASIC_CONSTRAINTS {
            basic = Some(BasicConstraints::from_der(value).map_err(|_| bad())?);
        } else if extension.extn_id == KEY_USAGE {
            usage = Some(KeyUsage::from_der(value).map_err(|_| bad())?);
        } else if extension.extn_id == TN_AUTH_LIST {
            tn_auth_list = Some(TnAuthList::from_der(value).map_err(|_| bad())?);
        } else if extension.critical {
            return Err(chain(ChainProblem::CriticalExtension { depth }));
        }
    }
    if depth == 0 {
        if usage.is_some_and(|usage| !usage.0.contains(KeyUsages::DigitalSignature)) {
            return Err(chain(ChainProblem::KeyUsage { depth }));
        }
        if certificate.key().is_none() {
            return Err(chain(ChainProblem::Algorithm { depth }));
        }
        return Ok(Checked {
            path_len: None,
            tn_auth_list,
        });
    }
    let Some(basic) = basic.filter(|basic| basic.ca) else {
        return Err(chain(ChainProblem::NotCa { depth }));
    };
    if usage.is_some_and(|usage| !usage.0.contains(KeyUsages::KeyCertSign)) {
        return Err(chain(ChainProblem::KeyUsage { depth }));
    }
    Ok(Checked {
        path_len: basic.path_len_constraint,
        tn_auth_list: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpki::{Pki, pem};
    use x509_cert::der::Encode;

    #[test]
    fn the_signed_octets_are_the_encoded_tbs_certificate() {
        let pki = Pki::new();
        let parsed = Parsed::new(&pki.leaf).unwrap();
        assert_eq!(parsed.certificate.to_der().unwrap(), pki.leaf);
        assert_eq!(
            parsed.tbs,
            parsed.certificate.tbs_certificate().to_der().unwrap()
        );
    }

    #[test]
    fn pem_and_der_chains_split_alike() {
        let pki = Pki::new();
        let der: Vec<u8> = [pki.leaf.clone(), pki.intermediate.clone()].concat();
        let from_der = split(&der, MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES).unwrap();
        let text = format!(
            "leaf and intermediate\n{}\n{}",
            pem(&pki.leaf),
            pem(&pki.intermediate)
        );
        let from_pem = split(text.as_bytes(), MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES).unwrap();
        assert_eq!(from_der, vec![pki.leaf.clone(), pki.intermediate.clone()]);
        assert_eq!(from_pem, from_der);
        let crlf = text.replace('\n', "\r\n");
        assert_eq!(
            split(crlf.as_bytes(), MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES).unwrap(),
            from_der
        );
    }

    #[test]
    fn pem_blocks_of_other_labels_are_skipped() {
        let pki = Pki::new();
        let text = format!(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{}",
            pem(&pki.leaf)
        );
        assert_eq!(
            split(text.as_bytes(), MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES).unwrap(),
            vec![pki.leaf]
        );
    }

    #[test]
    fn unreadable_chains() {
        let pki = Pki::new();
        let whole = pem(&pki.leaf);
        let unterminated = whole.replace("-----END CERTIFICATE-----", "");
        let mislabelled = whole.replace("END CERTIFICATE", "END X509 CRL");
        let bad_base64 = whole.replacen("MII", "M*I", 1);
        for input in [
            unterminated.as_bytes(),
            mislabelled.as_bytes(),
            bad_base64.as_bytes(),
            &[0x30, 0x03, 0x02, 0x01][..],
            &[0xff, 0xfe][..],
        ] {
            assert_eq!(
                split(input, MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES),
                Err(InfoProblem::Unreadable)
            );
        }
        assert_eq!(
            split(b"  \n", MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES),
            Err(InfoProblem::Empty)
        );
        assert_eq!(
            split(
                b"no certificate here",
                MAX_CHAIN_LEN,
                MAX_CHAIN_CERTIFICATES
            ),
            Err(InfoProblem::Empty)
        );
    }

    #[test]
    fn chain_limits() {
        let pki = Pki::new();
        let eleven = pki.leaf.repeat(MAX_CHAIN_CERTIFICATES + 1);
        assert_eq!(
            split(&eleven, MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES),
            Err(InfoProblem::TooManyCertificates)
        );
        let ten = pki.leaf.repeat(MAX_CHAIN_CERTIFICATES);
        assert_eq!(
            split(&ten, MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES).map(|c| c.len()),
            Ok(MAX_CHAIN_CERTIFICATES)
        );
        let eleven_pem = pem(&pki.leaf).repeat(MAX_CHAIN_CERTIFICATES + 1);
        assert_eq!(
            split(eleven_pem.as_bytes(), MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES),
            Err(InfoProblem::TooManyCertificates)
        );
        let huge = vec![b' '; MAX_CHAIN_LEN + 1];
        assert_eq!(
            split(&huge, MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES),
            Err(InfoProblem::TooLarge)
        );
        let long_body = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            "A".repeat(MAX_CERTIFICATE_LEN * 2 + 4)
        );
        assert_eq!(
            split(long_body.as_bytes(), MAX_CHAIN_LEN, MAX_CHAIN_CERTIFICATES),
            Err(InfoProblem::TooLarge)
        );
        let mut big = vec![0x30, 0x82, 0x40, 0x01];
        big.resize(4 + 0x4001, 0);
        assert_eq!(Parsed::new(&big).err(), Some(InfoProblem::TooLarge));
    }

    #[test]
    fn trust_anchors_are_added_from_pem_or_der() {
        let pki = Pki::new();
        let mut anchors = TrustAnchors::new();
        assert!(anchors.is_empty());
        assert_eq!(anchors.add(&pki.root), Ok(1));
        assert_eq!(anchors.add(pem(&pki.root).as_bytes()), Ok(1));
        assert_eq!(anchors.len(), 2);
        assert_eq!(format!("{anchors:?}"), "TrustAnchors { len: 2 }");
    }

    #[test]
    fn unusable_trust_anchors() {
        let pki = Pki::new();
        let mut anchors = TrustAnchors::new();
        assert_eq!(anchors.add(b""), Err(AnchorError::Empty));
        assert_eq!(
            anchors.add(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            Err(AnchorError::Unreadable)
        );
        assert_eq!(anchors.add(&[0x30, 0x00]), Err(AnchorError::Unreadable));
        let mut big = vec![0x30, 0x82, 0x40, 0x01];
        big.resize(4 + 0x4001, 0);
        assert_eq!(anchors.add(&big), Err(AnchorError::TooLarge));
        assert_eq!(
            anchors.add(&pki.with_curve_key_other_than_p256()),
            Err(AnchorError::UnsupportedKey)
        );
        // one bad certificate keeps the good one beside it out too
        let both = [pki.root.clone(), vec![0x30, 0x00]].concat();
        assert_eq!(anchors.add(&both), Err(AnchorError::Unreadable));
        assert!(anchors.is_empty());
        assert_eq!(
            AnchorError::UnsupportedKey.to_string(),
            "trust anchor key is not P-256"
        );
    }
}
