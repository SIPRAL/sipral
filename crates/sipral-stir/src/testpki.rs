// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A throwaway PKI for the tests: a root, an intermediate and a signing
//! certificate carrying a TNAuthList, written field by field from RFC 5280
//! §4.1 and signed with keys made from fixed scalars. Nothing here is
//! committed as a file; every certificate is built when a test asks for it,
//! and each part is exposed so a test can change one field and rebuild.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use x509_cert::der::asn1::ObjectIdentifier;

use crate::base64;
use crate::der::{self, INTEGER, SEQUENCE};
use crate::tnauthlist::{TnAuthList, TnEntry};

/// The time the tests verify at: 2026-09-21.
pub(crate) const NOW: u64 = 1_790_000_000;
/// The validity every certificate gets unless a test changes it.
pub(crate) const NOT_BEFORE: u64 = 1_760_000_000;
pub(crate) const NOT_AFTER: u64 = 1_820_000_000;

pub(crate) const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub(crate) const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const PRIME256V1: &str = "1.2.840.10045.3.1.7";
const SECP384R1: &str = "1.3.132.0.34";
const COMMON_NAME: &str = "2.5.4.3";
const BASIC_CONSTRAINTS: &str = "2.5.29.19";
const KEY_USAGE: &str = "2.5.29.15";

/// `digitalSignature`, the first named bit of KeyUsage.
pub(crate) const DIGITAL_SIGNATURE: u8 = 0x80;
/// `keyCertSign`, the sixth.
pub(crate) const KEY_CERT_SIGN: u8 = 0x04;
/// `cRLSign`, the seventh.
pub(crate) const CRL_SIGN: u8 = 0x02;

/// The originating number the signing certificate covers.
pub(crate) const ORIG: &str = "12155551212";

/// Everything a certificate is built from.
#[derive(Clone)]
pub(crate) struct Spec {
    pub(crate) subject: &'static str,
    pub(crate) issuer: &'static str,
    pub(crate) public_key: Vec<u8>,
    pub(crate) curve: &'static str,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    /// basic constraints: `cA` and `pathLenConstraint`
    pub(crate) basic: Option<(bool, Option<u64>)>,
    pub(crate) key_usage: Option<u8>,
    pub(crate) tn_auth_list: Option<Vec<u8>>,
    /// further extensions: identifier, criticality, value
    pub(crate) extra: Vec<(&'static str, bool, Vec<u8>)>,
    pub(crate) algorithm: &'static str,
    /// the outer signatureAlgorithm, when it is to differ from the inner
    pub(crate) outer_algorithm: Option<&'static str>,
    /// a NULL where RFC 5758 §3.2 says the parameters are absent, in both
    pub(crate) null_parameters: bool,
}

pub(crate) fn key(scalar: u8) -> SigningKey {
    SigningKey::from_slice(&[scalar; 32]).unwrap()
}

pub(crate) fn point(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

fn oid(dotted: &str) -> Vec<u8> {
    der::write(0x06, ObjectIdentifier::new(dotted).unwrap().as_bytes())
}

fn name(common_name: &str) -> Vec<u8> {
    let mut attribute = oid(COMMON_NAME);
    attribute.extend(der::write(0x0c, common_name.as_bytes()));
    der::write(
        SEQUENCE,
        &der::write(0x31, &der::write(SEQUENCE, &attribute)),
    )
}

/// Days since the epoch to a civil date, proleptic Gregorian.
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// UTCTime through 2049, GeneralizedTime after (RFC 5280 §4.1.2.5).
fn time(seconds: u64) -> Vec<u8> {
    let (year, month, day) = civil(seconds / 86_400);
    let rest = seconds % 86_400;
    let clock = format!(
        "{month:02}{day:02}{:02}{:02}{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    );
    if year < 2050 {
        der::write(0x17, format!("{:02}{clock}", year % 100).as_bytes())
    } else {
        der::write(0x18, format!("{year:04}{clock}").as_bytes())
    }
}

fn algorithm(dotted: &str, null_parameters: bool) -> Vec<u8> {
    let mut contents = oid(dotted);
    if null_parameters {
        contents.extend([0x05, 0x00]);
    }
    der::write(SEQUENCE, &contents)
}

fn extension(dotted: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut contents = oid(dotted);
    if critical {
        contents.extend([0x01, 0x01, 0xff]);
    }
    contents.extend(der::write(0x04, value));
    der::write(SEQUENCE, &contents)
}

/// A named-bit BIT STRING of one octet, trailing zero bits dropped as DER
/// requires (X.690 §11.2.2).
fn key_usage(bits: u8) -> Vec<u8> {
    let unused = if bits == 0 { 0 } else { bits.trailing_zeros() };
    der::write(0x03, &[u8::try_from(unused).unwrap(), bits])
}

fn basic_constraints(ca: bool, path_len: Option<u64>) -> Vec<u8> {
    let mut contents = Vec::new();
    if ca {
        contents.extend([0x01, 0x01, 0xff]);
    }
    if let Some(path_len) = path_len {
        contents.extend(der::write(INTEGER, &der::unsigned_contents(path_len)));
    }
    der::write(SEQUENCE, &contents)
}

impl Spec {
    fn new(subject: &'static str, issuer: &'static str, public_key: Vec<u8>) -> Self {
        Spec {
            subject,
            issuer,
            public_key,
            curve: PRIME256V1,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            basic: None,
            key_usage: None,
            tn_auth_list: None,
            extra: Vec::new(),
            algorithm: ECDSA_WITH_SHA256,
            outer_algorithm: None,
            null_parameters: false,
        }
    }

    /// The certificate, signed by `issuer`.
    pub(crate) fn build(&self, issuer: &SigningKey) -> Vec<u8> {
        let mut spki = der::write(SEQUENCE, &[oid(EC_PUBLIC_KEY), oid(self.curve)].concat());
        let mut key_bits = vec![0];
        key_bits.extend(&self.public_key);
        spki.extend(der::write(0x03, &key_bits));
        let spki = der::write(SEQUENCE, &spki);

        let mut extensions = Vec::new();
        if let Some((ca, path_len)) = self.basic {
            extensions.extend(extension(
                BASIC_CONSTRAINTS,
                true,
                &basic_constraints(ca, path_len),
            ));
        }
        if let Some(bits) = self.key_usage {
            extensions.extend(extension(KEY_USAGE, true, &key_usage(bits)));
        }
        if let Some(list) = &self.tn_auth_list {
            extensions.extend(extension(crate::tnauthlist::OID, false, list));
        }
        for (dotted, critical, value) in &self.extra {
            extensions.extend(extension(dotted, *critical, value));
        }

        let mut tbs = der::write(0xa0, &der::write(INTEGER, &[2]));
        tbs.extend(der::write(INTEGER, &[0x01, 0x23]));
        tbs.extend(algorithm(self.algorithm, self.null_parameters));
        tbs.extend(name(self.issuer));
        tbs.extend(der::write(
            SEQUENCE,
            &[time(self.not_before), time(self.not_after)].concat(),
        ));
        tbs.extend(name(self.subject));
        tbs.extend(spki);
        if !extensions.is_empty() {
            tbs.extend(der::write(0xa3, &der::write(SEQUENCE, &extensions)));
        }
        let tbs = der::write(SEQUENCE, &tbs);

        let signature: Signature = issuer.sign(&tbs);
        let mut signature_bits = vec![0];
        signature_bits.extend(signature.to_der().as_bytes());

        let mut certificate = tbs;
        certificate.extend(algorithm(
            self.outer_algorithm.unwrap_or(self.algorithm),
            self.null_parameters,
        ));
        certificate.extend(der::write(0x03, &signature_bits));
        der::write(SEQUENCE, &certificate)
    }
}

/// The three keys and three certificates of a working chain.
pub(crate) struct Pki {
    pub(crate) root_key: SigningKey,
    pub(crate) intermediate_key: SigningKey,
    pub(crate) leaf_key: SigningKey,
    pub(crate) root: Vec<u8>,
    pub(crate) intermediate: Vec<u8>,
    pub(crate) leaf: Vec<u8>,
}

pub(crate) const ROOT: &str = "Sipral Test STI Root";
pub(crate) const INTERMEDIATE: &str = "Sipral Test STI Intermediate";
pub(crate) const LEAF: &str = "Sipral Test STI Signer";

impl Pki {
    pub(crate) fn new() -> Self {
        let root_key = key(0x11);
        let intermediate_key = key(0x22);
        let leaf_key = key(0x33);
        let mut pki = Pki {
            root: Vec::new(),
            intermediate: Vec::new(),
            leaf: Vec::new(),
            root_key,
            intermediate_key,
            leaf_key,
        };
        pki.root = pki.root_spec().build(&pki.root_key);
        pki.intermediate = pki.intermediate_spec().build(&pki.root_key);
        pki.leaf = pki.leaf_spec().build(&pki.intermediate_key);
        pki
    }

    pub(crate) fn root_spec(&self) -> Spec {
        let mut spec = Spec::new(ROOT, ROOT, point(&self.root_key));
        spec.basic = Some((true, None));
        spec.key_usage = Some(KEY_CERT_SIGN | CRL_SIGN);
        spec
    }

    pub(crate) fn intermediate_spec(&self) -> Spec {
        let mut spec = Spec::new(INTERMEDIATE, ROOT, point(&self.intermediate_key));
        spec.basic = Some((true, Some(0)));
        spec.key_usage = Some(KEY_CERT_SIGN | CRL_SIGN);
        spec
    }

    pub(crate) fn leaf_spec(&self) -> Spec {
        let mut spec = Spec::new(LEAF, INTERMEDIATE, point(&self.leaf_key));
        spec.key_usage = Some(DIGITAL_SIGNATURE);
        spec.tn_auth_list = Some(
            TnAuthList::new(vec![TnEntry::One(ORIG.to_owned())])
                .unwrap()
                .to_der(),
        );
        spec
    }

    /// The chain an `x5u` serves: signing certificate, then intermediate.
    pub(crate) fn chain(&self) -> Vec<u8> {
        [self.leaf.clone(), self.intermediate.clone()].concat()
    }

    /// A certificate whose key is on a curve other than P-256.
    pub(crate) fn with_curve_key_other_than_p256(&self) -> Vec<u8> {
        let mut spec = self.root_spec();
        spec.curve = SECP384R1;
        let mut point = vec![0x04];
        point.extend([0x5a; 96]);
        spec.public_key = point;
        spec.build(&self.root_key)
    }
}

/// `der` as a PEM certificate block (RFC 7468 §5.1), 64 characters a line.
pub(crate) fn pem(der: &[u8]) -> String {
    let body = base64::encode_standard(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[test]
fn civil_dates() {
    assert_eq!(civil(0), (1970, 1, 1));
    assert_eq!(civil(NOW / 86_400), (2026, 9, 21));
    assert_eq!(civil(11_016), (2000, 2, 29));
    assert_eq!(time(0), der::write(0x17, b"700101000000Z"));
    assert_eq!(time(2_524_608_000), der::write(0x18, b"20500101000000Z"));
}
