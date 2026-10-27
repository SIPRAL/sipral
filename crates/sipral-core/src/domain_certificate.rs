// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Which SIP domain a TLS server's certificate stands for (RFC 5922).
//!
//! A platform's TLS library checks a server's name by the rules HTTPS uses:
//! a `dNSName` in `subjectAltName`, a leading `*.` standing for one label.
//! RFC 5922 reads a SIP server's certificate otherwise (§7.1, §7.2):
//!
//! - a `sip:` URI in `subjectAltName` with no user part names its host as a
//!   SIP domain, and while one does, no `dNSName` counts;
//! - a `dNSName` counts only when there is no such URI;
//! - names are compared whole, case aside: no suffix, no wildcard.
//!
//! [`domain_identity`] says which of those names a domain in a certificate
//! whose chain the platform has already verified, and
//! [`DomainIdentity::accepted`] whether a connection to it is accepted: by
//! RFC 5922 alone when the application asks for that
//! ([`DomainRules::Rfc5922`]), else by the name the platform matched, with a
//! `sip:` URI accepted besides, which no platform reads
//! ([`DomainRules::Platform`]). Refusing wildcards is not the default because
//! a hosted PBX on a provider's subdomain often has one, and every other SIP
//! client accepts it. The `commonName` is never read: RFC 5922 only allows it, and a
//! name an intermediate's name constraints do not cover is the reason the
//! platforms stopped reading it. Nothing here checks a chain or a date.

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::msg::{HostRef, UriRef, UriScheme};
use crate::pin::element;

/// How a certificate names a SIP domain, as RFC 5922 §7.1 and §7.2 read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainIdentity {
    /// A `sip:` URI with no user part in `subjectAltName` names the domain.
    SipUri,
    /// There is no such URI, and a `dNSName` is the domain itself.
    DnsName,
    /// There is no such URI, and only a wildcard `dNSName` covers the domain
    /// by the HTTPS rules, which RFC 5922 §7.2 refuses.
    Wildcard,
    /// Nothing RFC 5922 reads names the domain: the certificate's `sip:` URIs
    /// name others, or neither they nor its `dNSName`s cover it.
    Unnamed,
}

/// Which rules a SIP server's certificate is read by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainRules {
    /// The platform's, the rules HTTPS uses, with a `sip:` URI that names the
    /// domain accepted besides. What other SIP clients accept, a wildcard
    /// certificate included, is accepted here too.
    #[default]
    Platform,
    /// RFC 5922 alone: a `sip:` URI that names the domain, or where there is
    /// none a `dNSName` that is the domain itself; never a wildcard.
    Rfc5922,
}

impl DomainIdentity {
    /// Whether a connection to the domain is accepted under `rules`, once the
    /// platform has verified the certificate's chain. `platform_matched` is
    /// the platform's own verdict on the name, by the HTTPS rules.
    #[must_use]
    pub const fn accepted(self, rules: DomainRules, platform_matched: bool) -> bool {
        match rules {
            DomainRules::Platform => platform_matched || matches!(self, Self::SipUri),
            DomainRules::Rfc5922 => matches!(self, Self::SipUri | Self::DnsName),
        }
    }
}

impl fmt::Display for DomainIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SipUri => "a sip: URI in the certificate names the domain",
            Self::DnsName => "a DNS name in the certificate is the domain",
            Self::Wildcard => "only a wildcard DNS name in the certificate covers the domain",
            Self::Unnamed => "nothing RFC 5922 reads in the certificate names the domain",
        })
    }
}

/// The bytes are not a DER X.509 certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotACertificate;

impl fmt::Display for NotACertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the bytes are not a DER X.509 certificate this library can read")
    }
}

impl core::error::Error for NotACertificate {}

/// How `certificate`, a DER-encoded X.509 certificate, names `domain`, a SIP
/// domain: the host of the URI the user configured (RFC 5922 §7.3), not the
/// host its SRV record led to. A trailing dot on either side is ignored.
///
/// # Errors
/// [`NotACertificate`] when the bytes cannot be read as one.
pub fn domain_identity(
    certificate: &[u8],
    domain: &str,
) -> Result<DomainIdentity, NotACertificate> {
    let names = subject_alt_names(certificate).ok_or(NotACertificate)?;
    let mut sip_uris = false;
    let mut by_dns = DomainIdentity::Unnamed;
    for (tag, value) in names {
        match tag {
            URI => {
                if let Some(host) = sip_domain(value) {
                    if host_is(host, domain) {
                        return Ok(DomainIdentity::SipUri);
                    }
                    sip_uris = true;
                }
            }
            DNS_NAME => {
                let Ok(name) = core::str::from_utf8(value) else {
                    continue;
                };
                if same_name(name, domain) {
                    by_dns = DomainIdentity::DnsName;
                } else if by_dns == DomainIdentity::Unnamed && wildcard_covers(name, domain) {
                    by_dns = DomainIdentity::Wildcard;
                }
            }
            _ => {}
        }
    }
    Ok(if sip_uris {
        DomainIdentity::Unnamed
    } else {
        by_dns
    })
}

const SEQUENCE: u8 = 0x30;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const OCTET_STRING: u8 = 0x04;
/// `[3] EXPLICIT Extensions`, the last of a `TBSCertificate`'s members.
const EXTENSIONS: u8 = 0xa3;
/// `id-ce-subjectAltName`, 2.5.29.17 (RFC 5280 §4.2.1.6).
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
/// `GeneralName`'s `[2] IMPLICIT IA5String`.
const DNS_NAME: u8 = 0x82;
/// `GeneralName`'s `[6] IMPLICIT IA5String`.
const URI: u8 = 0x86;

/// Every `GeneralName` of the certificate's `subjectAltName`, tag and value;
/// none when it has no such extension. `None` when the DER cannot be read.
fn subject_alt_names(certificate: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let (SEQUENCE, certificate, _) = element(certificate)? else {
        return None;
    };
    let (SEQUENCE, mut tbs, _) = element(certificate)? else {
        return None;
    };
    let mut names = Vec::new();
    while !tbs.is_empty() {
        let (tag, contents, after) = element(tbs)?;
        tbs = after;
        if tag != EXTENSIONS {
            continue;
        }
        let (SEQUENCE, mut extensions, _) = element(contents)? else {
            return None;
        };
        while !extensions.is_empty() {
            let (SEQUENCE, extension, after) = element(extensions)? else {
                return None;
            };
            extensions = after;
            let (OID, id, rest) = element(extension)? else {
                return None;
            };
            if id != SUBJECT_ALT_NAME {
                continue;
            }
            // `critical BOOLEAN DEFAULT FALSE` comes first when it is written
            let (mut tag, mut value, rest) = element(rest)?;
            if tag == BOOLEAN {
                (tag, value, _) = element(rest)?;
            }
            if tag != OCTET_STRING {
                return None;
            }
            let (SEQUENCE, mut general, _) = element(value)? else {
                return None;
            };
            while !general.is_empty() {
                let (tag, value, after) = element(general)?;
                general = after;
                names.push((tag, value));
            }
        }
    }
    Some(names)
}

/// The host a `sip:` URI names as a SIP domain: none for another scheme,
/// `sips:` included, or for a URI with a user part, which names a user
/// (§7.1).
fn sip_domain(uri: &[u8]) -> Option<HostRef<'_>> {
    let parsed = UriRef::parse_str(core::str::from_utf8(uri).ok()?).ok()?;
    if parsed.scheme() != UriScheme::Sip {
        return None;
    }
    let sip = parsed.sip()?;
    if sip.user.is_some() {
        return None;
    }
    Some(sip.host)
}

/// Whether a URI's host is `domain`: a name compared as DNS names are, an
/// address by value.
fn host_is(host: HostRef<'_>, domain: &str) -> bool {
    let bare = domain.trim_start_matches('[').trim_end_matches(']');
    match host {
        HostRef::Name(name) => same_name(name, domain),
        HostRef::Ipv4(address) => bare.parse::<Ipv4Addr>() == Ok(address),
        HostRef::Ipv6(address) => bare.parse::<Ipv6Addr>() == Ok(address),
    }
}

/// Two DNS names, whole and without regard to ASCII case (RFC 4343), a
/// trailing dot ignored: no suffix and no wildcard (§7.2).
fn same_name(a: &str, b: &str) -> bool {
    let a = a.strip_suffix('.').unwrap_or(a);
    let b = b.strip_suffix('.').unwrap_or(b);
    !a.is_empty() && a.eq_ignore_ascii_case(b)
}

/// Whether `pattern`, a `dNSName` such as `*.example.com`, covers `domain` by
/// the HTTPS rules: the star one whole label, under at least two more.
fn wildcard_covers(pattern: &str, domain: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some((label, rest)) = domain.split_once('.') else {
        return false;
    };
    !label.is_empty() && !label.contains('*') && suffix.contains('.') && same_name(suffix, rest)
}

#[cfg(test)]
mod tests {
    use super::DomainRules::{Platform, Rfc5922};
    use super::{DomainIdentity, NotACertificate, domain_identity};

    /// One DER element.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let length = contents.len();
        if length < 0x80 {
            out.push(u8::try_from(length).unwrap_or(0));
        } else {
            let bytes = u16::try_from(length).unwrap_or(0).to_be_bytes();
            out.push(0x82);
            out.extend_from_slice(&bytes);
        }
        out.extend_from_slice(contents);
        out
    }

    /// A certificate whose `subjectAltName` holds `names`, each a
    /// `GeneralName` tag and value; `critical` writes the flag; no extension
    /// at all with `None`.
    fn certificate(names: Option<&[(u8, &str)]>, critical: bool) -> Vec<u8> {
        let empty = tlv(0x30, &[]);
        let mut tbs = tlv(0xa0, &tlv(0x02, &[2]));
        tbs.extend(tlv(0x02, &[1]));
        for _ in 0..5 {
            // signature, issuer, validity, subject, subjectPublicKeyInfo
            tbs.extend_from_slice(&empty);
        }
        if let Some(names) = names {
            let general: Vec<u8> = names
                .iter()
                .flat_map(|(tag, value)| tlv(*tag, value.as_bytes()))
                .collect();
            let mut extension = tlv(0x06, &[0x55, 0x1d, 0x11]);
            if critical {
                extension.extend(tlv(0x01, &[0xff]));
            }
            extension.extend(tlv(0x04, &tlv(0x30, &general)));
            // another extension first, which is skipped
            let mut extensions = tlv(
                0x30,
                &[tlv(0x06, &[0x55, 0x1d, 0x13]), tlv(0x04, &tlv(0x30, &[]))].concat(),
            );
            extensions.extend(tlv(0x30, &extension));
            tbs.extend(tlv(0xa3, &tlv(0x30, &extensions)));
        }
        let mut whole = tlv(0x30, &tbs);
        whole.extend_from_slice(&empty);
        whole.extend(tlv(0x03, &[0]));
        tlv(0x30, &whole)
    }

    const URI: u8 = 0x86;
    const DNS: u8 = 0x82;

    fn named(names: &[(u8, &str)], domain: &str) -> DomainIdentity {
        domain_identity(&certificate(Some(names), false), domain).expect("a certificate")
    }

    #[test]
    fn a_sip_uri_names_its_host_and_is_accepted_whatever_the_platform_matched() {
        let identity = named(&[(URI, "sip:example.com")], "example.com");
        assert_eq!(identity, DomainIdentity::SipUri);
        assert!(identity.accepted(Rfc5922, false));
        assert!(
            identity.accepted(Platform, false),
            "the HTTPS rules never read a sip: URI, so the platform could not have matched it"
        );
        assert_eq!(
            named(&[(URI, "SIP:EXAMPLE.com;transport=tls")], "example.com."),
            DomainIdentity::SipUri,
            "scheme and name are compared without regard to case, a trailing dot aside"
        );
    }

    #[test]
    fn while_a_sip_uri_is_there_no_dns_name_counts() {
        // §7.1: a DNS identifier counts only if no sip: URI identity is found
        let identity = named(
            &[(URI, "sip:other.example"), (DNS, "example.com")],
            "example.com",
        );
        assert_eq!(identity, DomainIdentity::Unnamed);
        assert!(
            !identity.accepted(Rfc5922, true),
            "RFC 5922 alone refuses it"
        );
        assert!(
            identity.accepted(Platform, true),
            "the HTTPS rules matched it, and they stand"
        );
    }

    #[test]
    fn a_dns_name_counts_when_no_sip_uri_is_there() {
        let identity = named(
            &[(DNS, "pbx.example.com"), (DNS, "example.com")],
            "example.com",
        );
        assert_eq!(identity, DomainIdentity::DnsName);
        assert!(identity.accepted(Rfc5922, false));
    }

    #[test]
    fn a_wildcard_is_told_apart_and_refused_by_rfc_5922_alone() {
        let identity = named(&[(DNS, "*.example.com")], "pbx.example.com");
        assert_eq!(identity, DomainIdentity::Wildcard);
        assert!(!identity.accepted(Rfc5922, true));
        assert!(identity.accepted(Platform, true));
        assert!(
            !identity.accepted(Platform, false),
            "the platform's refusal stands too"
        );
        for (pattern, domain) in [
            ("*.example.com", "a.b.example.com"),
            ("*.example.com", "example.com"),
            ("*.com", "example.com"),
            ("pbx*.example.com", "pbx1.example.com"),
        ] {
            assert_eq!(
                named(&[(DNS, pattern)], domain),
                DomainIdentity::Unnamed,
                "{pattern} covered {domain}"
            );
        }
        assert_eq!(
            named(
                &[(DNS, "*.example.com"), (DNS, "pbx.example.com")],
                "pbx.example.com"
            ),
            DomainIdentity::DnsName,
            "an exact name beside the wildcard is the exact name"
        );
    }

    #[test]
    fn a_uri_naming_a_user_or_of_another_scheme_names_no_domain() {
        for uri in [
            "sip:alice@example.com",
            "sips:example.com",
            "https://example.com/",
        ] {
            assert_eq!(
                named(&[(URI, uri), (DNS, "example.com")], "example.com"),
                DomainIdentity::DnsName,
                "{uri} was read as a SIP domain identity"
            );
        }
    }

    #[test]
    fn no_suffix_is_matched() {
        assert_eq!(
            named(&[(URI, "sip:example.com")], "pbx.example.com"),
            DomainIdentity::Unnamed
        );
        assert_eq!(
            named(&[(DNS, "pbx.example.com")], "example.com"),
            DomainIdentity::Unnamed
        );
    }

    #[test]
    fn an_address_in_a_sip_uri_is_compared_by_value() {
        assert_eq!(
            named(&[(URI, "sip:192.0.2.10")], "192.0.2.10"),
            DomainIdentity::SipUri
        );
        assert_eq!(
            named(&[(URI, "sip:[2001:db8::1]")], "2001:db8:0::1"),
            DomainIdentity::SipUri
        );
        assert_eq!(
            named(&[(URI, "sip:192.0.2.10")], "192.0.2.11"),
            DomainIdentity::Unnamed
        );
    }

    #[test]
    fn a_critical_flag_is_read_past_and_no_extension_names_nothing() {
        let critical = certificate(Some(&[(URI, "sip:example.com")]), true);
        assert_eq!(
            domain_identity(&critical, "example.com"),
            Ok(DomainIdentity::SipUri)
        );
        let none = certificate(None, false);
        assert_eq!(
            domain_identity(&none, "example.com"),
            Ok(DomainIdentity::Unnamed)
        );
    }

    #[test]
    fn bytes_that_are_not_a_certificate_say_so() {
        assert_eq!(
            domain_identity(b"not DER", "example.com"),
            Err(NotACertificate)
        );
        let whole = certificate(Some(&[(URI, "sip:example.com")]), false);
        let cut = whole.get(..whole.len() - 3).unwrap_or_default();
        assert_eq!(domain_identity(cut, "example.com"), Err(NotACertificate));
    }
}
