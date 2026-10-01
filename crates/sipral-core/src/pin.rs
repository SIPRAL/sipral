// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A TLS server certificate trusted by its SHA-256 fingerprint.
//!
//! A PBX on a LAN usually serves a certificate it signed itself, for a name
//! like `localhost` or its factory hostname, and no trust anchor an
//! application ships will ever vouch for it. The choice left to an
//! administrator without this is to turn checking off, which accepts any
//! certificate from anyone who can answer on the address. A pin is the
//! narrow alternative: the one certificate the administrator read off the PBX
//! and nothing else.
//!
//! TLS is the application's (`docs/22-tls.md`): the platform's library runs
//! the handshake and this crate never sees it. So a pin is a value an account
//! carries and a check the application's certificate verifier calls with the
//! DER bytes of the leaf certificate the server presented. What is compared
//! is SHA-256 over those exact bytes, the same digest `openssl x509
//! -fingerprint -sha256` prints and RFC 8122 §5 writes for DTLS, in constant
//! time.
//!
//! **What a pin replaces.** The whole of the platform's verdict: chain,
//! trust anchors and name. A pinned certificate is accepted when its
//! fingerprint matches and refused when it does not, whoever signed it.
//!
//! **Host names are not checked.** The pin names one certificate by every
//! byte of it, public key included, which a matching host name cannot add
//! to: an attacker who could present a certificate with this fingerprint
//! already holds this key. And the name in a PBX's own certificate is the
//! part most often wrong — `localhost`, an IP address that changed, a name
//! the phones do not use — so checking it would refuse exactly the
//! certificates pins exist for. RFC 5922's rules still apply to every
//! connection that is not pinned.
//!
//! **An expired pinned certificate is accepted, and said to be expired.** Its
//! dates were written by the same party whose key is pinned, so they add no
//! protection against anyone else, and a PBX whose self-signed certificate
//! lapsed — they are often issued for a year and never renewed — would
//! otherwise go silent in the middle of a working deployment. The verdict
//! carries the dates so that the application can warn, and an administrator
//! who wants the old certificate refused pins the new one instead.

use core::fmt;

use crate::auth::sha2::sha256;

/// The SHA-256 fingerprint of one DER certificate, trusted on its own.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificatePin([u8; 32]);

/// Why a fingerprint could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinError {
    /// Not 32 bytes of hexadecimal, with or without colons between them.
    Malformed,
    /// A hash other than SHA-256 was named.
    NotSha256,
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => {
                "a certificate pin is 32 bytes of hexadecimal, colons between them or not"
            }
            Self::NotSha256 => "a certificate pin is a SHA-256 fingerprint",
        })
    }
}

impl core::error::Error for PinError {}

/// The certificate presented is not the pinned one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinMismatch;

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the server's certificate is not the pinned one")
    }
}

impl core::error::Error for PinMismatch {}

/// A pinned certificate that matched, with what its dates say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedCertificate {
    /// Its `notBefore`, in seconds since the Unix epoch, when the DER could
    /// be read that far.
    pub not_before: Option<u64>,
    /// Its `notAfter`, the same way.
    pub not_after: Option<u64>,
    /// Whether `now` was past `notAfter`. Accepted all the same; see the
    /// module documentation.
    pub expired: bool,
    /// Whether `now` was before `notBefore`, which a clock set wrong or a
    /// certificate minted with a future date does. Accepted too.
    pub not_yet_valid: bool,
}

impl CertificatePin {
    /// A pin from the digest itself.
    #[must_use]
    pub const fn from_sha256(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The pin of `certificate`, a DER-encoded X.509 certificate: SHA-256
    /// over its bytes.
    #[must_use]
    pub fn of(certificate: &[u8]) -> Self {
        Self(sha256(certificate))
    }

    /// A fingerprint as an administrator copies it: 64 hexadecimal digits,
    /// upper or lower case, colons and spaces among them ignored, either
    /// bare or after one of the prefixes the tools that print one write,
    /// matched without regard to case:
    ///
    /// - `sha256 Fingerprint=` — `openssl x509 -fingerprint -sha256`, which
    ///   OpenSSL 3 writes `sha256 Fingerprint=` and 1.1 `SHA256 Fingerprint=`;
    /// - `sha-256 ` — RFC 8122 §5's form, the one `a=fingerprint` carries;
    /// - `SHA256=`.
    ///
    /// The same forms, by the same rule, as every binding's own reading of a
    /// pin, so that a fingerprint one layer takes no other refuses.
    ///
    /// # Errors
    /// [`PinError::NotSha256`] for another hash named in front, and
    /// [`PinError::Malformed`] for anything else that is not 32 bytes.
    pub fn parse(text: &str) -> Result<Self, PinError> {
        let text = text.trim();
        let digits = PREFIXES
            .iter()
            .find_map(|prefix| strip_prefix_ignoring_case(text, prefix))
            .unwrap_or(text);
        let mut out = [0_u8; 32];
        let mut bytes = digits
            .as_bytes()
            .iter()
            .copied()
            .filter(|byte| !matches!(*byte, b':' | b' '));
        for slot in &mut out {
            let (Some(high), Some(low)) = (bytes.next(), bytes.next()) else {
                return Err(other_hash(text));
            };
            *slot = match (nibble(high), nibble(low)) {
                (Ok(high), Ok(low)) => high << 4 | low,
                _ => return Err(other_hash(text)),
            };
        }
        if bytes.next().is_some() {
            return Err(PinError::Malformed);
        }
        Ok(Self(out))
    }

    /// The digest.
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether `leaf`, the DER bytes of the certificate the server presented
    /// first, is the pinned one. Every byte of the digest is compared
    /// whatever the first difference, so how long this takes says nothing
    /// about how close a certificate came.
    #[must_use]
    pub fn matches(&self, leaf: &[u8]) -> bool {
        equal(&self.0, &sha256(leaf))
    }

    /// [`CertificatePin::matches`], with the certificate's dates read against
    /// `unix_now`, the wall clock in seconds since the Unix epoch.
    ///
    /// # Errors
    /// [`PinMismatch`] when `leaf` is not the pinned certificate. A match is
    /// never refused for its dates; [`PinnedCertificate`] reports them.
    pub fn check(&self, leaf: &[u8], unix_now: u64) -> Result<PinnedCertificate, PinMismatch> {
        if !self.matches(leaf) {
            return Err(PinMismatch);
        }
        let (not_before, not_after) =
            validity(leaf).map_or((None, None), |(from, until)| (Some(from), Some(until)));
        Ok(PinnedCertificate {
            not_before,
            not_after,
            expired: not_after.is_some_and(|until| unix_now > until),
            not_yet_valid: not_before.is_some_and(|from| unix_now < from),
        })
    }
}

impl fmt::Debug for CertificatePin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertificatePin({self})")
    }
}

impl fmt::Display for CertificatePin {
    /// Upper-case hexadecimal, a colon between each byte, as RFC 8122 §5 and
    /// `openssl x509 -fingerprint` write one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (at, byte) in self.0.iter().enumerate() {
            if at > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// What may stand in front of the digits, lower case: OpenSSL's, RFC 8122's,
/// and the bare `SHA256=`. None of them begins another.
const PREFIXES: [&str; 3] = ["sha256 fingerprint=", "sha-256 ", "sha256="];

/// `text` after `prefix`, the prefix matched without regard to case.
fn strip_prefix_ignoring_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| text.get(prefix.len()..))
        .flatten()
}

/// Why digits that did not read as 32 bytes were refused: another hash
/// named in front of them — `sha-1 `, `SHA1 Fingerprint=`, `md5=` — or not a
/// fingerprint at all.
fn other_hash(text: &str) -> PinError {
    let head = text.split([' ', '=']).next().unwrap_or_default();
    let name = head.to_ascii_lowercase().replace(['-', '_'], "");
    let named = head.len() < text.len()
        && (name.starts_with("sha") || name.starts_with("md"))
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric());
    if named && name != "sha256" {
        PinError::NotSha256
    } else {
        PinError::Malformed
    }
}

const fn nibble(digit: u8) -> Result<u8, PinError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(PinError::Malformed),
    }
}

/// Equal in constant time: every byte is folded in whatever the first
/// difference, and the fold is kept from the optimiser, which would
/// otherwise be free to stop at the first nonzero byte.
fn equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= core::hint::black_box(a ^ b);
    }
    core::hint::black_box(difference) == 0
}

/// The tag and the contents of the DER element at the front of `bytes`, and
/// what follows it (X.690 §8.1, definite lengths only, as DER requires).
fn element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let (octets, rest) = rest.split_at_checked(count)?;
        let length = octets
            .iter()
            .fold(0_usize, |length, octet| length << 8 | usize::from(*octet));
        (length, rest)
    };
    let (contents, after) = rest.split_at_checked(length)?;
    Some((tag, contents, after))
}

const SEQUENCE: u8 = 0x30;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0] EXPLICIT Version`, in front of the serial number.
const VERSION: u8 = 0xa0;

/// A certificate's `validity` (RFC 5280 §4.1.2.5), as seconds since the Unix
/// epoch: `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version
/// OPTIONAL, serialNumber, signature, issuer, validity SEQUENCE { notBefore,
/// notAfter }, ... }, ... }`.
fn validity(certificate: &[u8]) -> Option<(u64, u64)> {
    let (SEQUENCE, certificate, _) = element(certificate)? else {
        return None;
    };
    let (SEQUENCE, tbs, _) = element(certificate)? else {
        return None;
    };
    let (tag, _, mut rest) = element(tbs)?;
    if tag == VERSION {
        // the serial number follows the version
        (_, _, rest) = element(rest)?;
    }
    // signature, then issuer
    let (_, _, rest) = element(rest)?;
    let (_, _, rest) = element(rest)?;
    let (SEQUENCE, validity, _) = element(rest)? else {
        return None;
    };
    let (from_tag, from, rest) = element(validity)?;
    let (until_tag, until, _) = element(rest)?;
    Some((time(from_tag, from)?, time(until_tag, until)?))
}

/// RFC 5280 §4.1.2.5.1 and §4.1.2.5.2: `YYMMDDHHMMSSZ` in a UTCTime, the
/// year read as 19YY from 50 up and 20YY below it, and `YYYYMMDDHHMMSSZ` in a
/// GeneralizedTime; always Zulu, always with seconds.
fn time(tag: u8, text: &[u8]) -> Option<u64> {
    let (year, rest) = match tag {
        UTC_TIME => {
            let (yy, rest) = text.split_at_checked(2)?;
            let yy = digits(yy)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, rest)
        }
        GENERALIZED_TIME => {
            let (yyyy, rest) = text.split_at_checked(4)?;
            (digits(yyyy)?, rest)
        }
        _ => return None,
    };
    let [m1, m2, d1, d2, h1, h2, n1, n2, s1, s2, b'Z'] = *rest else {
        return None;
    };
    let month = digits(&[m1, m2])?;
    let day = digits(&[d1, d2])?;
    let hour = digits(&[h1, h2])?;
    let minute = digits(&[n1, n2])?;
    let second = digits(&[s1, s2])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second.min(60))
}

fn digits(text: &[u8]) -> Option<u64> {
    text.iter().try_fold(0_u64, |value, digit| {
        digit
            .is_ascii_digit()
            .then(|| value * 10 + u64::from(digit - b'0'))
    })
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar, for
/// dates from 1970 on: the civil-from-days arithmetic run backwards, over
/// eras of 400 years that start on the first of March.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    // 719 468 days from 0000-03-01 to 1970-01-01
    (era * 146_097 + day_of_era).checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::{CertificatePin, PinError, PinMismatch, days_from_civil, equal, time, validity};

    /// One DER element, for building a certificate by hand.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(u8::try_from(contents.len()).unwrap());
        } else {
            let length = u16::try_from(contents.len()).unwrap().to_be_bytes();
            out.push(0x82);
            out.extend_from_slice(&length);
        }
        out.extend_from_slice(contents);
        out
    }

    /// The shape RFC 5280 §4.1 gives a certificate, with just enough in it
    /// to reach the dates.
    fn certificate(from: &[u8], until: &[u8], version: bool) -> Vec<u8> {
        let mut tbs = Vec::new();
        if version {
            tbs.extend(tlv(0xa0, &tlv(0x02, &[2])));
        }
        tbs.extend(tlv(0x02, &[0x01, 0x23]));
        tbs.extend(tlv(0x30, &tlv(0x06, &[0x2a, 0x86, 0x48])));
        tbs.extend(tlv(0x30, &tlv(0x31, &[0; 140])));
        let mut dates = tlv(if from.len() == 13 { 0x17 } else { 0x18 }, from);
        dates.extend(tlv(if until.len() == 13 { 0x17 } else { 0x18 }, until));
        tbs.extend(tlv(0x30, &dates));
        let mut whole = tlv(0x30, &tbs);
        whole.extend(tlv(0x30, &tlv(0x06, &[0x2a])));
        whole.extend(tlv(0x03, &[0, 0xde, 0xad]));
        tlv(0x30, &whole)
    }

    #[test]
    fn the_pin_of_a_certificate_matches_it_and_nothing_else() {
        let ours = certificate(b"250101000000Z", b"260101000000Z", true);
        let theirs = certificate(b"250101000000Z", b"260101000001Z", true);
        let pin = CertificatePin::of(&ours);
        assert!(pin.matches(&ours));
        assert!(
            !pin.matches(&theirs),
            "one bit of the dates is another certificate"
        );
        assert_eq!(pin.check(&theirs, 0), Err(PinMismatch));
    }

    #[test]
    fn a_fingerprint_is_read_in_every_form_an_administrator_copies() {
        let pin = CertificatePin::from_sha256([0xab; 32]);
        let colons = pin.to_string();
        assert_eq!(colons.len(), 95);
        assert!(colons.starts_with("AB:AB:"));
        let bare = colons.replace(':', "");
        for written in [
            colons.clone(),
            colons.to_ascii_lowercase(),
            bare.clone(),
            format!("sha-256 {colons}"),
            format!("SHA-256 {bare}"),
            format!("SHA256={colons}"),
            format!("sha256={bare}"),
            // OpenSSL 3 and OpenSSL 1.1, as `x509 -fingerprint -sha256` prints
            format!("sha256 Fingerprint={colons}"),
            format!("SHA256 Fingerprint={colons}"),
            format!("SHA256 FINGERPRINT={}", colons.to_ascii_lowercase()),
            format!("  {bare}  "),
            // colons and spaces among the digits are not counted
            colons.replace(':', " "),
            colons.replace("AB:AB:", "AB::AB"),
            format!("sha-256 {}", colons.replace(':', ": ")),
        ] {
            assert_eq!(CertificatePin::parse(&written), Ok(pin), "{written}");
        }
        for refused in [
            "",
            "AB:AB",
            &colons[..94],
            &format!("{colons}:AB"),
            &colons.replacen('A', "G", 1),
            &format!("sha-256 {}", &colons[..94]),
            &format!("Fingerprint={colons}"),
            &format!("sha256 fingerprint {colons}"),
            &format!("sha256:{colons}"),
            &colons.replace(':', "\t"),
            &format!("{bare}x"),
        ] {
            assert_eq!(
                CertificatePin::parse(refused),
                Err(PinError::Malformed),
                "{refused}"
            );
        }
        for other in [
            format!("sha-1 {colons}"),
            format!("SHA1 Fingerprint={colons}"),
            format!("md5={colons}"),
        ] {
            assert_eq!(
                CertificatePin::parse(&other),
                Err(PinError::NotSha256),
                "{other}"
            );
        }
    }

    #[test]
    fn the_dates_are_read_from_either_time_form_with_or_without_a_version() {
        let der = certificate(b"250101000000Z", b"20510315123000Z", true);
        assert_eq!(validity(&der), Some((1_735_689_600, 2_562_496_200)));
        // UTCTime 49 is 2049 and 99 is 1999 (RFC 5280 §4.1.2.5.1)
        let der = certificate(b"990101000000Z", b"491231235959Z", false);
        assert_eq!(validity(&der), Some((915_148_800, 2_524_607_999)));
        assert_eq!(time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(time(0x17, b"700101000000"), None, "always Zulu");
        assert_eq!(time(0x17, b"701301000000Z"), None, "no thirteenth month");
    }

    #[test]
    fn an_expired_pinned_certificate_is_accepted_and_said_to_be_expired() {
        let lapsed = certificate(b"200101000000Z", b"210101000000Z", true);
        let pin = CertificatePin::of(&lapsed);
        let now = 1_790_000_000;
        let verdict = pin
            .check(&lapsed, now)
            .expect("the pin decides, not the dates");
        assert!(verdict.expired);
        assert!(!verdict.not_yet_valid);
        assert_eq!(verdict.not_after, Some(1_609_459_200));

        let current = certificate(b"250101000000Z", b"350101000000Z", true);
        let verdict = CertificatePin::of(&current).check(&current, now).unwrap();
        assert!(!verdict.expired && !verdict.not_yet_valid);

        // bytes that are not a certificate still match their own pin, and
        // then no date is claimed for them
        let garbage = b"not a certificate";
        let verdict = CertificatePin::of(garbage).check(garbage, now).unwrap();
        assert_eq!((verdict.not_after, verdict.expired), (None, false));
    }

    #[test]
    fn the_calendar_is_right_at_its_edges() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 3, 1), Some(11_017));
        assert_eq!(days_from_civil(2024, 2, 29), Some(19_782));
        assert_eq!(days_from_civil(1969, 12, 31), None);
    }

    #[test]
    fn equal_compares_every_byte() {
        let base = [7_u8; 32];
        for at in 0..32 {
            let mut other = base;
            other[at] ^= 0x80;
            assert!(!equal(&base, &other), "byte {at}");
        }
        assert!(equal(&base, &base));
    }
}
