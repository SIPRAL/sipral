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
//! ([`DomainRules::Platform`]). Since no platform reads it, no platform holds
//! it to the name constraints of the authorities above it either:
//! [`domain_identity_in_chain`] does, reading its host as the `dNSName` or
//! address it stands for. Refusing wildcards is not the default because
//! a hosted PBX on a provider's subdomain often has one, and every other SIP
//! client accepts it. The `commonName` is never read: RFC 5922 only allows it, and a
//! name an intermediate's name constraints do not cover is the reason the
//! platforms stopped reading it. Nothing here checks a chain or a date.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
/// host its SRV record led to. A trailing dot on either side is ignored, and
/// an address (`192.0.2.10`, `2001:db8::1` with or without brackets) is
/// named by a `sip:` URI alone, as the HTTPS rules never match one to a
/// `dNSName`.
///
/// The certificate is read alone: a `sip:` URI here is vouched for by no name
/// constraint of the authorities above it, which the platforms apply to
/// `dNSName`s and addresses and skip for a URI. Where those authorities are
/// at hand, [`domain_identity_in_chain`] reads it.
///
/// # Errors
/// [`NotACertificate`] when the bytes cannot be read as one.
pub fn domain_identity(
    certificate: &[u8],
    domain: &str,
) -> Result<DomainIdentity, NotACertificate> {
    let names = subject_alt_names(certificate).ok_or(NotACertificate)?;
    let address = domain
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok();
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
            DNS_NAME if !address => {
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

/// How `certificate` names `domain`, as [`domain_identity`] reads it, with
/// `issuers` the DER certificates above it in its chain, in any order: a
/// `sip:` URI names the domain only while every `nameConstraints` extension
/// among them allows the host of each of the certificate's `sip:` URIs, read
/// as the `dNSName` or `iPAddress` that would stand in its place. An
/// authority constrained to `corp.example` thereby certifies
/// `sip:pbx.corp.example` and never `sip:example.com`. A constraint on URIs
/// is not read and allows none, as `webpki` reads it; an issuer whose
/// constraints cannot be read allows none either.
///
/// # Errors
/// [`NotACertificate`] when `certificate` cannot be read as one.
pub fn domain_identity_in_chain<I>(
    certificate: &[u8],
    issuers: I,
    domain: &str,
) -> Result<DomainIdentity, NotACertificate>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let identity = domain_identity(certificate, domain)?;
    // only a sip: URI can make a certificate name a domain its issuers'
    // constraints were never checked against
    if identity != DomainIdentity::SipUri {
        return Ok(identity);
    }
    let names = subject_alt_names(certificate).ok_or(NotACertificate)?;
    let hosts: Vec<HostRef<'_>> = names
        .into_iter()
        .filter(|&(tag, _)| tag == URI)
        .filter_map(|(_, value)| sip_domain(value))
        .collect();
    for issuer in issuers {
        let Some(constraints) = extensions(issuer.as_ref(), NAME_CONSTRAINTS) else {
            return Ok(DomainIdentity::Unnamed);
        };
        for constraint in constraints {
            for &host in &hosts {
                if constraint_allows(constraint, host) != Some(true) {
                    return Ok(DomainIdentity::Unnamed);
                }
            }
        }
    }
    Ok(identity)
}

const SEQUENCE: u8 = 0x30;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const OCTET_STRING: u8 = 0x04;
/// `[3] EXPLICIT Extensions`, the last of a `TBSCertificate`'s members.
const EXTENSIONS: u8 = 0xa3;
/// `id-ce-subjectAltName`, 2.5.29.17 (RFC 5280 §4.2.1.6).
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
/// `id-ce-nameConstraints`, 2.5.29.30 (RFC 5280 §4.2.1.10).
const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
/// `NameConstraints`' `permittedSubtrees [0] GeneralSubtrees`.
const PERMITTED_SUBTREES: u8 = 0xa0;
/// `NameConstraints`' `excludedSubtrees [1] GeneralSubtrees`.
const EXCLUDED_SUBTREES: u8 = 0xa1;
/// `GeneralName`'s `[2] IMPLICIT IA5String`.
const DNS_NAME: u8 = 0x82;
/// `GeneralName`'s `[6] IMPLICIT IA5String`.
const URI: u8 = 0x86;
/// `GeneralName`'s `[7] IMPLICIT OCTET STRING`.
const IP_ADDRESS: u8 = 0x87;

/// Every `GeneralName` of the certificate's `subjectAltName`, tag and value;
/// none when it has no such extension. `None` when the DER cannot be read.
fn subject_alt_names(certificate: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut names = Vec::new();
    for value in extensions(certificate, SUBJECT_ALT_NAME)? {
        let (SEQUENCE, mut general, _) = element(value)? else {
            return None;
        };
        while !general.is_empty() {
            let (tag, value, after) = element(general)?;
            general = after;
            names.push((tag, value));
        }
    }
    Some(names)
}

/// The value of every extension `id` of the certificate, the DER its
/// `extnValue` holds; none when it has no such extension. `None` when the
/// DER cannot be read.
fn extensions<'a>(certificate: &'a [u8], id: &[u8]) -> Option<Vec<&'a [u8]>> {
    let (SEQUENCE, certificate, _) = element(certificate)? else {
        return None;
    };
    let (SEQUENCE, mut tbs, _) = element(certificate)? else {
        return None;
    };
    let mut values = Vec::new();
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
            let (OID, extension_id, rest) = element(extension)? else {
                return None;
            };
            if extension_id != id {
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
            values.push(value);
        }
    }
    Some(values)
}

/// Whether `constraints`, the value of an authority's `nameConstraints`
/// extension, lets it vouch for `host`, the host of a `sip:` URI below it,
/// read as the `dNSName` or `iPAddress` that would stand in its place (RFC
/// 5280 §4.2.1.10): inside no excluded subtree of that form, and inside one
/// of the permitted ones where there are any. `None` when the DER cannot be
/// read.
fn constraint_allows(constraints: &[u8], host: HostRef<'_>) -> Option<bool> {
    let (SEQUENCE, mut lists, _) = element(constraints)? else {
        return None;
    };
    let mut permitted = false;
    let mut inside_permitted = false;
    while !lists.is_empty() {
        let (tag, mut list, after) = element(lists)?;
        lists = after;
        let excluded = match tag {
            PERMITTED_SUBTREES => false,
            EXCLUDED_SUBTREES => true,
            _ => return None,
        };
        while !list.is_empty() {
            let (SEQUENCE, subtree, after) = element(list)? else {
                return None;
            };
            list = after;
            // `minimum` and `maximum` after the base are never written (§4.2.1.10)
            let (form, base, _) = element(subtree)?;
            let inside = match (form, host) {
                // a constraint on URIs is not read, so it allows no URI
                (URI, _) => return Some(false),
                (DNS_NAME, _) if !base.is_ascii() => return None,
                (IP_ADDRESS, _) if base.len() != 8 && base.len() != 32 => return None,
                (DNS_NAME, HostRef::Name(name)) => {
                    dns_name_inside(core::str::from_utf8(base).ok()?, name)
                }
                (IP_ADDRESS, HostRef::Ipv4(address)) => address_inside(base, &address.octets()),
                (IP_ADDRESS, HostRef::Ipv6(address)) => address_inside(base, &address.octets()),
                _ => continue,
            };
            if excluded {
                if inside {
                    return Some(false);
                }
            } else {
                permitted = true;
                inside_permitted |= inside;
            }
        }
    }
    Some(!permitted || inside_permitted)
}

/// Whether `name` is inside the `dNSName` subtree `constraint`: the name
/// itself or one under it, or with a leading dot only one under it; an empty
/// constraint holds every name. Case and a trailing dot aside.
fn dns_name_inside(constraint: &str, name: &str) -> bool {
    let constraint = constraint.strip_suffix('.').unwrap_or(constraint);
    let name = name.strip_suffix('.').unwrap_or(name);
    if constraint.is_empty() {
        return true;
    }
    let Some(split) = name.len().checked_sub(constraint.len()) else {
        return false;
    };
    let (Some(head), Some(tail)) = (name.get(..split), name.get(split..)) else {
        return false;
    };
    if !tail.eq_ignore_ascii_case(constraint) {
        return false;
    }
    if constraint.starts_with('.') {
        !head.is_empty()
    } else {
        head.is_empty() || head.ends_with('.')
    }
}

/// Whether `address` is inside the `iPAddress` subtree `base`, an address
/// and its mask of the same length; never for one of the other family.
fn address_inside(base: &[u8], address: &[u8]) -> bool {
    if base.len() != address.len() * 2 {
        return false;
    }
    let (network, mask) = base.split_at(address.len());
    address
        .iter()
        .zip(network)
        .zip(mask)
        .all(|((a, n), m)| a & m == n & m)
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
    use super::{DomainIdentity, NotACertificate, domain_identity, domain_identity_in_chain};

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
        with_extension(names.map(|names| {
            let general: Vec<u8> = names
                .iter()
                .flat_map(|(tag, value)| tlv(*tag, value.as_bytes()))
                .collect();
            let mut extension = tlv(0x06, &[0x55, 0x1d, 0x11]);
            if critical {
                extension.extend(tlv(0x01, &[0xff]));
            }
            extension.extend(tlv(0x04, &tlv(0x30, &general)));
            extension
        }))
    }

    /// An authority's certificate whose `nameConstraints` permit the
    /// subtrees `permitted` and exclude `excluded`, each a `GeneralName` tag
    /// and value.
    fn authority(permitted: &[(u8, &[u8])], excluded: &[(u8, &[u8])]) -> Vec<u8> {
        let subtrees = |tag: u8, bases: &[(u8, &[u8])]| {
            if bases.is_empty() {
                return Vec::new();
            }
            let list: Vec<u8> = bases
                .iter()
                .flat_map(|(form, base)| tlv(0x30, &tlv(*form, base)))
                .collect();
            tlv(tag, &list)
        };
        let constraints = [subtrees(0xa0, permitted), subtrees(0xa1, excluded)].concat();
        let mut extension = tlv(0x06, &[0x55, 0x1d, 0x1e]);
        extension.extend(tlv(0x01, &[0xff]));
        extension.extend(tlv(0x04, &tlv(0x30, &constraints)));
        with_extension(Some(extension))
    }

    /// A certificate with the contents of one extension, `extension`, after
    /// another that is skipped; no extension at all with `None`.
    fn with_extension(extension: Option<Vec<u8>>) -> Vec<u8> {
        let empty = tlv(0x30, &[]);
        let mut tbs = tlv(0xa0, &tlv(0x02, &[2]));
        tbs.extend(tlv(0x02, &[1]));
        for _ in 0..5 {
            // signature, issuer, validity, subject, subjectPublicKeyInfo
            tbs.extend_from_slice(&empty);
        }
        if let Some(extension) = extension {
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
    fn an_address_is_never_named_by_a_dns_name_spelling_it() {
        // the HTTPS rules match an address against an iPAddress entry alone
        for (name, domain) in [
            ("203.0.113.5", "203.0.113.5"),
            ("*.0.113.5", "203.0.113.5"),
            ("2001:db8::1", "2001:db8::1"),
            ("2001:db8::1", "[2001:db8::1]"),
        ] {
            let identity = named(&[(DNS, name)], domain);
            assert_eq!(identity, DomainIdentity::Unnamed, "{name} named {domain}");
            assert!(!identity.accepted(Rfc5922, false));
        }
        assert_eq!(
            named(
                &[(URI, "sip:203.0.113.5"), (DNS, "203.0.113.5")],
                "203.0.113.5"
            ),
            DomainIdentity::SipUri,
            "a sip: URI still names an address"
        );
    }

    const IP: u8 = 0x87;

    fn in_chain(names: &[(u8, &str)], issuers: &[Vec<u8>], domain: &str) -> DomainIdentity {
        domain_identity_in_chain(&certificate(Some(names), false), issuers, domain)
            .expect("a certificate")
    }

    #[test]
    fn a_sip_uri_names_its_host_only_where_every_issuer_may_name_it() {
        let corp = authority(&[(DNS, b"corp.example")], &[]);
        let leaf = [(URI, "sip:victim.example"), (DNS, "pbx.corp.example")];
        assert_eq!(
            in_chain(&leaf, core::slice::from_ref(&corp), "victim.example"),
            DomainIdentity::Unnamed,
            "the dNSName constraint holds for the URI's host too"
        );
        assert_eq!(
            in_chain(&leaf, &[], "victim.example"),
            DomainIdentity::SipUri,
            "no issuer, no constraint"
        );
        for (constraint, domain) in [
            (&b"corp.example"[..], "corp.example"),
            (b"corp.example", "pbx.CORP.example."),
            (b".corp.example", "pbx.corp.example"),
            (b"", "anything.example"),
        ] {
            let issuer = authority(&[(DNS, constraint), (DNS, b"other.example")], &[]);
            let uri = format!("sip:{domain}");
            assert_eq!(
                in_chain(&[(URI, &uri)], &[issuer], domain),
                DomainIdentity::SipUri,
                "{domain} is under {constraint:?}"
            );
        }
        for (constraint, domain) in [
            (&b".corp.example"[..], "corp.example"),
            (b"corp.example", "evilcorp.example"),
            (b"pbx.corp.example", "corp.example"),
        ] {
            let issuer = authority(&[(DNS, constraint)], &[]);
            let uri = format!("sip:{domain}");
            assert_eq!(
                in_chain(&[(URI, &uri)], &[issuer], domain),
                DomainIdentity::Unnamed,
                "{domain} is not under {constraint:?}"
            );
        }
        let excluding = authority(&[], &[(DNS, b"victim.example")]);
        assert_eq!(
            in_chain(
                &[(URI, "sip:victim.example")],
                &[excluding],
                "victim.example"
            ),
            DomainIdentity::Unnamed
        );
        assert_eq!(
            in_chain(
                &[(URI, "sip:pbx.corp.example"), (URI, "sip:victim.example")],
                core::slice::from_ref(&corp),
                "pbx.corp.example"
            ),
            DomainIdentity::Unnamed,
            "a second sip: URI the issuer may not name, and RFC 5922 reads none"
        );
        let unconstrained = authority(&[(IP, &[10, 0, 0, 0, 255, 0, 0, 0])], &[]);
        assert_eq!(
            in_chain(&leaf, &[unconstrained, corp], "victim.example"),
            DomainIdentity::Unnamed,
            "one issuer that may not name it is enough"
        );
    }

    #[test]
    fn an_address_in_a_sip_uri_is_held_to_the_issuers_address_ranges() {
        let ten = authority(&[(IP, &[10, 0, 0, 0, 255, 0, 0, 0])], &[]);
        assert_eq!(
            in_chain(
                &[(URI, "sip:10.1.2.3")],
                core::slice::from_ref(&ten),
                "10.1.2.3"
            ),
            DomainIdentity::SipUri
        );
        assert_eq!(
            in_chain(&[(URI, "sip:192.0.2.10")], &[ten], "192.0.2.10"),
            DomainIdentity::Unnamed
        );
        let v6 = [
            &[0x20, 0x01, 0x0d, 0xb8][..],
            &[0; 12],
            &[0xff; 4],
            &[0; 12],
        ]
        .concat();
        let documentation = authority(&[(IP, &v6)], &[]);
        assert_eq!(
            in_chain(
                &[(URI, "sip:[2001:db8::1]")],
                core::slice::from_ref(&documentation),
                "2001:db8::1"
            ),
            DomainIdentity::SipUri
        );
        assert_eq!(
            in_chain(&[(URI, "sip:192.0.2.10")], &[documentation], "192.0.2.10"),
            DomainIdentity::Unnamed,
            "an IPv4 address is in no IPv6 range"
        );
        let names_only = authority(&[(DNS, b"corp.example")], &[]);
        assert_eq!(
            in_chain(&[(URI, "sip:192.0.2.10")], &[names_only], "192.0.2.10"),
            DomainIdentity::SipUri,
            "a constraint on names leaves addresses free, as RFC 5280 reads it"
        );
    }

    #[test]
    fn a_constraint_on_uris_or_one_that_cannot_be_read_allows_no_sip_uri() {
        for issuer in [
            authority(&[(URI, b"example.com")], &[]),
            authority(&[], &[(URI, b".other.example")]),
            authority(&[(IP, &[10, 0, 0, 0])], &[]),
            b"not DER".to_vec(),
        ] {
            assert_eq!(
                in_chain(&[(URI, "sip:example.com")], &[issuer], "example.com"),
                DomainIdentity::Unnamed
            );
        }
        let corp = authority(&[(DNS, b"corp.example")], &[]);
        assert_eq!(
            in_chain(
                &[(DNS, "victim.example")],
                &[corp, b"not DER".to_vec()],
                "victim.example"
            ),
            DomainIdentity::DnsName,
            "a dNSName is the platform's to hold to the constraints, and no URI is read"
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
