// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Certificate fingerprints as `a=fingerprint` carries them (RFC 8122 §5).
//!
//! ```text
//! fingerprint-attribute  =  "fingerprint" ":" hash-func SP fingerprint
//! fingerprint            =  2UHEX *(":" 2UHEX)
//! ```
//!
//! The value [`Fingerprint::parse`] reads is what follows the colon, the same
//! string `sipral-core` carries through from the SDP.

use core::fmt;

use sha2::{Digest, Sha256};

use super::sha1;
use crate::prf::HASH_LEN;
use crate::{Error, ct};

/// A hash function a fingerprint may be computed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashFunction {
    /// `sha-1`: accepted when reading, never written.
    Sha1,
    /// `sha-256`: RFC 8122 §5 "with 'SHA-256' preferred", and the hash of the
    /// certificates this crate signs, which §5.1 asks a fingerprint to use.
    Sha256,
}

impl HashFunction {
    /// The name from the "Hash Function Textual Names" registry.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha-1",
            Self::Sha256 => "sha-256",
        }
    }

    /// Octets in the digest.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => sha1::DIGEST_LEN,
            Self::Sha256 => HASH_LEN,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
        }
    }

    /// The function a `hash-func` token names. ABNF quoted strings are
    /// case-insensitive (RFC 5234 §2.3), so `SHA-256` names SHA-256 too.
    fn from_name(name: &str) -> Result<Self, Error> {
        if name.is_empty() {
            return Err(Error::IllegalValue);
        }
        if name.eq_ignore_ascii_case("sha-256") {
            Ok(Self::Sha256)
        } else if name.eq_ignore_ascii_case("sha-1") {
            Ok(Self::Sha1)
        } else {
            // sha-224, sha-384, sha-512, and md5 and md2, which §5 forbids
            // using at all
            Err(Error::UnsupportedHash)
        }
    }
}

/// A certificate fingerprint: the hash of the certificate's DER.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    hash: HashFunction,
    value: Vec<u8>,
}

impl Fingerprint {
    /// The fingerprint of `certificate`, a DER certificate, under `hash`.
    #[must_use]
    pub fn of(hash: HashFunction, certificate: &[u8]) -> Self {
        Self {
            hash,
            value: hash.digest(certificate),
        }
    }

    /// Read the value of an `a=fingerprint` attribute: `hash-func SP
    /// fingerprint`.
    ///
    /// The grammar asks for uppercase hexadecimal. Lowercase is accepted as
    /// well: which case a peer wrote the digest in says nothing about the
    /// certificate, and refusing it would fail a call over a matter of style.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedHash`] for any hash but `sha-1` and `sha-256`;
    /// [`Error::IllegalValue`] for a value that is not `name SP hex:hex...`
    /// with two hexadecimal digits in every group; [`Error::Length`] when the
    /// number of octets is not the hash's.
    pub fn parse(value: &str) -> Result<Self, Error> {
        let (name, digits) = value.split_once(' ').ok_or(Error::IllegalValue)?;
        let hash = HashFunction::from_name(name)?;
        let mut octets = Vec::with_capacity(hash.output_len());
        for group in digits.split(':') {
            let [high, low] =
                <[u8; 2]>::try_from(group.as_bytes()).map_err(|_| Error::IllegalValue)?;
            octets.push((nibble(high)? << 4) | nibble(low)?);
        }
        if octets.len() != hash.output_len() {
            return Err(Error::Length);
        }
        Ok(Self {
            hash,
            value: octets,
        })
    }

    /// The hash function.
    #[must_use]
    pub const fn hash(&self) -> HashFunction {
        self.hash
    }

    /// The digest.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Whether `certificate`, a DER certificate, is the one this fingerprint
    /// names. RFC 8122 §5.1: if it is not, "the endpoint MUST NOT establish
    /// the TLS connection".
    ///
    /// The digests are compared without stopping at the first difference.
    /// The certificate is public; what the comparison must not reveal is how
    /// close a certificate an attacker is grinding towards the expected
    /// fingerprint has come.
    #[must_use]
    pub fn matches(&self, certificate: &[u8]) -> bool {
        ct::equal(&self.hash.digest(certificate), &self.value)
    }
}

const fn nibble(digit: u8) -> Result<u8, Error> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(Error::IllegalValue),
    }
}

/// The attribute value, uppercase as the grammar writes it:
/// `sha-256 AB:CD:...`.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.hash.name())?;
        for (i, octet) in self.value.iter().enumerate() {
            let separator = if i == 0 { " " } else { ":" };
            write!(f, "{separator}{octet:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A P-256 self-signed certificate with three extensions, written by
    /// OpenSSL 3.6.4 (`openssl req -new -x509 -subj /CN=interop -sha256`), and
    /// what that tool reported about it.
    pub(crate) const OPENSSL_CERTIFICATE: &str = "\
308201793082011fa00302010202140788cecc272d216ff113ac751cb4303f93319ef4300a06082a8648ce3d04030230123110300e0603
5504030c07696e7465726f70301e170d3236303931333133303833335a170d3236313031333133303833335a30123110300e06035504030c
07696e7465726f703059301306072a8648ce3d020106082a8648ce3d03010703420004359696c8d34254662448c8408d17f8e32073a932f38c
6d350423fe0b9eebd6f535a59e1a5739a014430382f1363f7df8d803f11d217e07c9a21f84fafb89febba3533051301d0603551d0e04160414
b1da597e232f3b4bb88034bbd7db798309539e88301f0603551d23041830168014b1da597e232f3b4bb88034bbd7db798309539e88300f0603
551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100e2bdf272d5f2ade5daaf1bccfb8f39a89659474c020f3356
334648a64cf56a0102203d45e714e275d22240951a58fbe673b0ed326aef511223b9ba5a09bbfb5b17fe";
    pub(crate) const OPENSSL_SHA256: &str = "sha-256 52:E1:C6:A0:74:62:7A:A4:78:0E:87:93:3B:6B:66:E9:65:26:7C:90:96:94:45:F2:DE:01:4A:32:BE:A4:46:07";
    const OPENSSL_SHA1: &str = "sha-1 69:0B:AC:43:8B:49:3F:71:07:F0:3B:CD:CA:A1:FF:B7:4B:19:55:E9";

    pub(crate) fn openssl_certificate() -> Vec<u8> {
        let s: String = OPENSSL_CERTIFICATE.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn fingerprints_agree_with_another_implementation() {
        let certificate = openssl_certificate();
        assert_eq!(certificate.len(), 381);
        for printed in [OPENSSL_SHA256, OPENSSL_SHA1] {
            let fingerprint = Fingerprint::parse(printed).unwrap();
            assert!(fingerprint.matches(&certificate), "{printed}");
            assert_eq!(
                Fingerprint::of(fingerprint.hash(), &certificate),
                fingerprint
            );
            assert_eq!(fingerprint.to_string(), printed);
        }
        assert_eq!(
            Fingerprint::parse(OPENSSL_SHA256).unwrap().hash(),
            HashFunction::Sha256
        );
        assert_eq!(Fingerprint::parse(OPENSSL_SHA1).unwrap().value().len(), 20);
    }

    #[test]
    fn a_fingerprint_matches_no_other_certificate() {
        let certificate = openssl_certificate();
        let fingerprint = Fingerprint::parse(OPENSSL_SHA256).unwrap();
        let mut other = certificate.clone();
        *other.last_mut().unwrap() ^= 1;
        assert!(!fingerprint.matches(&other));
        let mut wrong = Fingerprint::parse(OPENSSL_SHA256).unwrap();
        wrong.value[31] ^= 1;
        assert!(!wrong.matches(&certificate));
        // the right digest under the other hash's name
        let sha1_named = Fingerprint {
            hash: HashFunction::Sha1,
            value: Fingerprint::of(HashFunction::Sha256, &certificate).value,
        };
        assert!(!sha1_named.matches(&certificate));
    }

    #[test]
    fn the_name_is_case_insensitive_and_lowercase_digits_are_read() {
        let lower = OPENSSL_SHA256.to_lowercase();
        let upper_name = OPENSSL_SHA256.replacen("sha-256", "SHA-256", 1);
        let expected = Fingerprint::parse(OPENSSL_SHA256).unwrap();
        assert_eq!(Fingerprint::parse(&lower), Ok(expected.clone()));
        assert_eq!(Fingerprint::parse(&upper_name), Ok(expected));
    }

    #[test]
    fn malformed_values_are_refused() {
        let two = "AB:CD";
        let cases: [(&str, String, Error); 11] = [
            ("md5", format!("md5 {two}"), Error::UnsupportedHash),
            ("sha-512", format!("sha-512 {two}"), Error::UnsupportedHash),
            (
                "no space",
                OPENSSL_SHA256.replacen(' ', "", 1),
                Error::IllegalValue,
            ),
            ("nothing at all", String::new(), Error::IllegalValue),
            ("no name", format!(" {two}"), Error::IllegalValue),
            ("too few octets", "sha-256 AB:CD".to_owned(), Error::Length),
            (
                "too many octets",
                format!("{OPENSSL_SHA256}:00"),
                Error::Length,
            ),
            (
                "not hex",
                OPENSSL_SHA256.replacen("52", "G2", 1),
                Error::IllegalValue,
            ),
            (
                "one digit",
                OPENSSL_SHA256.replacen("52:", "5:", 1),
                Error::IllegalValue,
            ),
            (
                "trailing colon",
                format!("{OPENSSL_SHA256}:"),
                Error::IllegalValue,
            ),
            (
                "two spaces",
                OPENSSL_SHA256.replacen(' ', "  ", 1),
                Error::IllegalValue,
            ),
        ];
        for (what, value, error) in cases {
            assert_eq!(Fingerprint::parse(&value).err(), Some(error), "{what}");
        }
        assert_eq!(Fingerprint::parse("sha-1").err(), Some(Error::IllegalValue));
    }

    #[test]
    fn debug_shows_the_attribute_value() {
        let fingerprint = Fingerprint::parse(OPENSSL_SHA1).unwrap();
        assert_eq!(
            format!("{fingerprint:?}"),
            format!("Fingerprint({OPENSSL_SHA1})")
        );
    }
}
