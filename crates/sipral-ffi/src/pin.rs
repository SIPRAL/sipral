// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A TLS server certificate an account trusts by its SHA-256 fingerprint
//! (ABI 0.34), and the SIP domain a certificate names (ABI 1.8, with the
//! authorities above it from ABI 1.11).
//!
//! The application runs TLS (`docs/22-tls.md`); its verifier calls
//! [`sipral_account_check_certificate`] with the leaf's DER. With a pin the
//! fingerprint is the whole verdict: no chain, anchor or host name, and an
//! expired match is accepted but flagged. Without one, once the platform has
//! verified the chain, [`sipral_certificate_check_domain_in_chain`] reads the
//! leaf's name as RFC 5922 reads a SIP server's, a `sip:` URI held to the name
//! constraints of the issuers handed in; [`sipral_certificate_check_domain`]
//! reads the leaf alone.

use std::ffi::c_char;

use sipral_core::domain_certificate::{
    DomainIdentity, DomainRules, NotACertificate, domain_identity, domain_identity_in_chain,
};

use crate::abi::{Number, codes, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{handle_failed, with_stack};
use crate::status::SipralStatus;
use crate::text::{bytes, required_text};
use crate::versioned::{Versioned, read_versioned, write_versioned};

codes! {
    /// Which rules a SIP server's certificate is read by for its name, once the platform has
    /// verified its chain (RFC 5922 §7.1, §7.2; `docs/22-tls.md`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDomainRules: u32 {
        /// The platform's, the rules HTTPS uses, with a `sip:` URI in `subjectAltName` that
        /// names the domain accepted besides. What other SIP clients accept, a wildcard
        /// included, is accepted.
        Platform = 0,
        /// RFC 5922 alone: a `sip:` URI that names the domain, or, where the certificate has
        /// none, a `dNSName` that is the domain itself; never a wildcard.
        Rfc5922 = 1,
    }
}

codes! {
    /// How a certificate names a SIP domain, as RFC 5922 §7.1 and §7.2 read it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDomainIdentity: u32 {
        /// Nothing RFC 5922 reads names it: the certificate's `sip:` URIs name other domains,
        /// or neither they nor its `dNSName`s cover it.
        Unnamed = 0,
        /// A `sip:` URI with no user part in `subjectAltName` names it.
        SipUri = 1,
        /// There is no such URI, and a `dNSName` is the domain itself.
        DnsName = 2,
        /// There is no such URI, and only a wildcard `dNSName` covers it.
        Wildcard = 3,
    }
}

/// A [`SipralDomainRules`] as a caller wrote it.
pub(crate) fn domain_rules(value: u32) -> Option<DomainRules> {
    match value {
        0 => Some(DomainRules::Platform),
        1 => Some(DomainRules::Rfc5922),
        _ => None,
    }
}

const fn identity_code(identity: DomainIdentity) -> SipralDomainIdentity {
    match identity {
        DomainIdentity::SipUri => SipralDomainIdentity::SipUri,
        DomainIdentity::DnsName => SipralDomainIdentity::DnsName,
        DomainIdentity::Wildcard => SipralDomainIdentity::Wildcard,
        _ => SipralDomainIdentity::Unnamed,
    }
}

record! {
    /// What [`sipral_account_check_certificate`] found: whether the account's
    /// pin decided, and what the certificate's dates say.
    ///
    /// Set `size` to `sizeof(sipral_pinned_certificate_t)` before the call.
    #[derive(Clone, Copy)]
    pub struct SipralPinnedCertificate {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The certificate's `notBefore`, in seconds since 1 January 1970,
        /// or zero when its DER could not be read that far.
        pub not_before: u64,
        /// Its `notAfter`, the same way.
        pub not_after: u64,
        /// One: pinned and matching, accept. Zero: no pin, platform checks apply.
        pub pinned: u32,
        /// One when past `not_after`. Still accepted (a lapsed self-signed PBX
        /// would go silent); worth a warning.
        pub expired: u32,
        /// One when before `not_before`. Still accepted.
        pub not_yet_valid: u32,
        /// Zero.
        pub reserved: u32,
    }
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralPinnedCertificate {
    const NAME: &'static str = "sipral_pinned_certificate";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralPinnedCertificate, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

entry! {
    /// Check the server's leaf certificate (DER) against the account's pin:
    /// SHA-256 over the bytes, constant-time. `unix_seconds` is used only for
    /// the reported dates.
    ///
    /// `SIPRAL_STATUS_OK` with `pinned` 1: accept. With `pinned` 0: no pin,
    /// platform checks decide. `SIPRAL_STATUS_CERTIFICATE_REFUSED`: refuse;
    /// nothing written.
    ///
    /// # Safety
    ///
    /// `certificate` must be readable for `certificate_len` bytes, and
    /// `out_pinned` must point at a `sipral_pinned_certificate_t` whose
    /// `size` member says how long it is.
    fn sipral_account_check_certificate(
        stack: SipralHandle,
        account: SipralHandle,
        certificate: *const u8,
        certificate_len: usize,
        unix_seconds: u64,
        out_pinned: *mut SipralPinnedCertificate,
    ) {
        let mut out = unsafe { read_versioned(out_pinned) }?;
        let Some(leaf) = (unsafe { bytes(certificate, certificate_len, "certificate") })? else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "certificate is required and was not given",
            ));
        };
        let pin = with_stack(stack, |state| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            Ok(state
                .agent
                .account(id)
                .and_then(|config| config.pinned_certificate().copied()))
        })?;
        out.not_before = 0;
        out.not_after = 0;
        out.pinned = 0;
        out.expired = 0;
        out.not_yet_valid = 0;
        out.reserved = 0;
        if let Some(pin) = pin {
            let Ok(checked) = pin.check(leaf, unix_seconds) else {
                return Err(fail(
                    SipralStatus::CertificateRefused,
                    "the server's certificate is not the one this account pins",
                ));
            };
            out.not_before = checked.not_before.unwrap_or(0);
            out.not_after = checked.not_after.unwrap_or(0);
            out.pinned = 1;
            out.expired = u32::from(checked.expired);
            out.not_yet_valid = u32::from(checked.not_yet_valid);
        }
        unsafe { write_versioned(out_pinned, out) }
    }
}

/// The leaf, the domain and the rules a caller handed either domain check, read.
///
/// # Safety
///
/// As [`sipral_certificate_check_domain`].
unsafe fn domain_check<'a>(
    certificate: *const u8,
    certificate_len: usize,
    domain: *const c_char,
    domain_len: usize,
    rules: u32,
) -> Result<(&'a [u8], &'a str, DomainRules), Fail> {
    let Some(leaf) = (unsafe { bytes(certificate, certificate_len, "certificate") })? else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "certificate is required and was not given",
        ));
    };
    let domain = unsafe { required_text(domain, domain_len, "domain") }?;
    let Some(rules) = domain_rules(rules) else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "rules is {rules}, and the rules are 0 for the platform's with a sip: URI \
                 accepted besides, or 1 for RFC 5922 alone"
            ),
        ));
    };
    Ok((leaf, domain, rules))
}

/// The verdict on how the leaf names `domain`, its identity written to `out_identity` when
/// that is not null.
///
/// # Safety
///
/// `out_identity` must be null or point at one `sipral_domain_identity_t`.
unsafe fn domain_verdict(
    identity: Result<DomainIdentity, NotACertificate>,
    domain: &str,
    rules: DomainRules,
    platform_matched: u32,
    out_identity: *mut Number<SipralDomainIdentity>,
) -> Result<(), Fail> {
    let identity = identity.map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("certificate: {error}"),
        )
    })?;
    if !out_identity.is_null() {
        unsafe { out_identity.write(identity_code(identity) as u32) };
    }
    if identity.accepted(rules, platform_matched != 0) {
        Ok(())
    } else {
        Err(fail(
            SipralStatus::CertificateRefused,
            format!("the server's certificate does not name {domain:?}: {identity}"),
        ))
    }
}

/// The certificates handed in back to back as `issuers`, each one DER `SEQUENCE` read by its
/// own length (X.690 §8.1, definite lengths only, as DER requires); none for nothing handed
/// in. `None` when the bytes do not end where a certificate does.
fn issuer_certificates(mut run: &[u8]) -> Option<Vec<&[u8]>> {
    const SEQUENCE: u8 = 0x30;
    let mut certificates = Vec::new();
    while !run.is_empty() {
        let (&SEQUENCE, rest) = run.split_first()? else {
            return None;
        };
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
                .fold(0_usize, |length, &octet| length << 8 | usize::from(octet));
            (length, rest)
        };
        let whole = (run.len() - rest.len()).checked_add(length)?;
        let (certificate, after) = run.split_at_checked(whole)?;
        certificates.push(certificate);
        run = after;
    }
    Some(certificates)
}

entry! {
    /// Read a TLS server's leaf certificate (DER) for the SIP domain `domain`, under `rules`
    /// (ABI 1.8), once the platform has verified its chain, its dates and what else it checks.
    ///
    /// The leaf is read alone: a `sip:` URI in its `subjectAltName` is held to no name
    /// constraint of the authorities above it, which the platforms apply to a `dNSName` and
    /// skip for a URI. `sipral_certificate_check_domain_in_chain` (ABI 1.11) takes those
    /// authorities too, and is the call to make where the platform hands the chain over.
    ///
    /// `domain` is the name the connection is checked against: the host of the account's
    /// `server_uri` (RFC 5922 §7.3), not the one its SRV record led to.
    /// `platform_matched` is the platform's own verdict on the name, by the HTTPS rules: one
    /// when it accepted the name, zero when it refused the name alone, everything else having
    /// held. A refusal for any other reason stands and never reaches this call.
    ///
    /// `SIPRAL_STATUS_OK`: accept. `SIPRAL_STATUS_CERTIFICATE_REFUSED`: refuse, as a name
    /// mismatch. Either way `out_identity`, when not null, is how the certificate names the
    /// domain, for the reason given. `SIPRAL_STATUS_INVALID_ARGUMENT` for bytes that are not a
    /// certificate or for `rules` out of range.
    ///
    /// # Safety
    ///
    /// `certificate` must be readable for `certificate_len` bytes, `domain` for `domain_len`
    /// bytes, and `out_identity` must be null or point at one `sipral_domain_identity_t`.
    fn sipral_certificate_check_domain(
        certificate: *const u8,
        certificate_len: usize,
        domain: *const c_char,
        domain_len: usize,
        rules: Number<SipralDomainRules>,
        platform_matched: u32,
        out_identity: *mut Number<SipralDomainIdentity>,
    ) {
        let (leaf, domain, rules) =
            unsafe { domain_check(certificate, certificate_len, domain, domain_len, rules) }?;
        unsafe {
            domain_verdict(
                domain_identity(leaf, domain),
                domain,
                rules,
                platform_matched,
                out_identity,
            )
        }
    }
}

entry! {
    /// Read a TLS server's leaf certificate (DER) for the SIP domain `domain`, under `rules`,
    /// as `sipral_certificate_check_domain` does, with `issuers` the certificates above it in
    /// the chain the platform verified (ABI 1.11).
    ///
    /// `issuers` is their DER, one certificate after another in any order, the anchor among
    /// them or not; the chain the server sent serves where the platform hands over no chain of
    /// its own, since one more constrained authority can only refuse a `sip:` URI. A `sip:` URI
    /// names the domain only while every `nameConstraints` extension among them allows the
    /// host of each of the leaf's `sip:` URIs, read as the `dNSName` or address it stands for:
    /// an authority constrained to `corp.example` vouches for `sip:pbx.corp.example`, never for
    /// `sip:example.com`. A constraint on URIs, or one that cannot be read, allows none. A
    /// `dNSName` is the platform's to hold to those constraints, and is read as the call
    /// without issuers reads it. No issuers, a length of zero, reads the leaf alone.
    ///
    /// The answers are `sipral_certificate_check_domain`'s, `out_identity` included, and
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` besides for `issuers` that do not end where a
    /// certificate does.
    ///
    /// # Safety
    ///
    /// `certificate` must be readable for `certificate_len` bytes, `issuers` for `issuers_len`
    /// bytes, `domain` for `domain_len` bytes, and `out_identity` must be null or point at one
    /// `sipral_domain_identity_t`.
    fn sipral_certificate_check_domain_in_chain(
        certificate: *const u8,
        certificate_len: usize,
        issuers: *const u8,
        issuers_len: usize,
        domain: *const c_char,
        domain_len: usize,
        rules: Number<SipralDomainRules>,
        platform_matched: u32,
        out_identity: *mut Number<SipralDomainIdentity>,
    ) {
        let (leaf, domain, rules) =
            unsafe { domain_check(certificate, certificate_len, domain, domain_len, rules) }?;
        let run = (unsafe { bytes(issuers, issuers_len, "issuers") })?.unwrap_or_default();
        let Some(issuers) = issuer_certificates(run) else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "issuers is not one DER certificate after another",
            ));
        };
        unsafe {
            domain_verdict(
                domain_identity_in_chain(leaf, issuers, domain),
                domain,
                rules,
                platform_matched,
                out_identity,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralDomainIdentity, SipralDomainRules, SipralPinnedCertificate,
        sipral_account_check_certificate, sipral_certificate_check_domain,
        sipral_certificate_check_domain_in_chain,
    };
    use crate::account::sipral_account_add;
    use crate::account::tests::account_config;
    use crate::call::tests::account_on;
    use crate::error::last_error_text;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::{Observed, stack};
    use crate::status::SipralStatus;
    use sipral_ua::CertificatePin;
    use std::mem::size_of;
    use std::ptr;

    /// Not a real certificate: the pin is over bytes. Dates read as zero.
    const LEAF: &[u8] = b"\x30\x03\x02\x01\x07 a certificate the PBX signed itself";
    const OTHER: &[u8] = b"\x30\x03\x02\x01\x07 another certificate for the same name";

    fn out() -> SipralPinnedCertificate {
        SipralPinnedCertificate {
            size: size_of::<SipralPinnedCertificate>(),
            not_before: u64::MAX,
            not_after: u64::MAX,
            pinned: u32::MAX,
            expired: u32::MAX,
            not_yet_valid: u32::MAX,
            reserved: u32::MAX,
        }
    }

    fn pinned_account(handle: SipralHandle, pin: &str) -> (SipralStatus, SipralHandle) {
        let mut config = account_config();
        config.tls_pin_sha256 = pin.as_ptr().cast();
        config.tls_pin_sha256_len = pin.len();
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(handle, &raw const config, &raw mut account) };
        (status, account)
    }

    fn check(
        handle: SipralHandle,
        account: SipralHandle,
        leaf: &[u8],
        out: &mut SipralPinnedCertificate,
    ) -> SipralStatus {
        unsafe {
            sipral_account_check_certificate(
                handle,
                account,
                leaf.as_ptr(),
                leaf.len(),
                1_790_000_000,
                out,
            )
        }
    }

    fn colon_hex(digest: &[u8; 32]) -> String {
        digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    #[test]
    fn the_pinned_certificate_is_accepted_and_another_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let written = format!("SHA256={}", colon_hex(CertificatePin::of(LEAF).sha256()));
        let (status, account) = pinned_account(handle, &written);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        let mut matched = out();
        assert_eq!(check(handle, account, LEAF, &mut matched), SipralStatus::Ok);
        assert_eq!(matched.pinned, 1);
        assert_eq!(
            (matched.not_before, matched.not_after),
            (0, 0),
            "no dates read"
        );
        assert_eq!((matched.expired, matched.not_yet_valid), (0, 0));

        let mut refused = out();
        assert_eq!(
            check(handle, account, OTHER, &mut refused),
            SipralStatus::CertificateRefused
        );
        assert_eq!(refused.pinned, u32::MAX, "nothing is written on a refusal");
    }

    /// `openssl x509 -fingerprint -sha256` output (3.x and 1.1) and variants.
    #[test]
    fn every_printed_form_of_the_fingerprint_pins_the_certificate() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let colons = colon_hex(CertificatePin::of(LEAF).sha256());
        let bare = colons.replace(':', "");
        for written in [
            format!("sha256 Fingerprint={colons}"),
            format!("SHA256 Fingerprint={colons}"),
            format!("sha-256 {colons}"),
            format!("SHA256={bare}"),
            colons.to_ascii_lowercase(),
            colons.replace(':', " "),
        ] {
            let (status, account) = pinned_account(handle, &written);
            assert_eq!(status, SipralStatus::Ok, "{written}: {}", last_error_text());
            let mut matched = out();
            assert_eq!(
                check(handle, account, LEAF, &mut matched),
                SipralStatus::Ok,
                "{written}"
            );
            assert_eq!(matched.pinned, 1, "{written}");
        }
        let (status, _) = pinned_account(handle, &format!("SHA1 Fingerprint={colons}"));
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn an_account_that_pins_nothing_leaves_the_verdict_to_the_platform() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        let mut said = out();
        assert_eq!(check(handle, account, OTHER, &mut said), SipralStatus::Ok);
        assert_eq!(said.pinned, 0);
        assert_eq!(said.size, size_of::<SipralPinnedCertificate>());
    }

    #[test]
    fn a_pin_that_is_not_a_sha256_fingerprint_is_refused_when_the_account_is_added() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        for written in ["AB:CD", "sha-1 00", &"0".repeat(63)] {
            let (status, _) = pinned_account(handle, written);
            assert_eq!(status, SipralStatus::InvalidArgument, "{written}");
            assert!(
                last_error_text().contains("tls_pin_sha256"),
                "{}",
                last_error_text()
            );
        }
    }

    #[test]
    fn a_missing_certificate_or_result_is_a_bad_argument() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        let mut said = out();
        let status = unsafe {
            sipral_account_check_certificate(handle, account, ptr::null(), 0, 0, &raw mut said)
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        let status = unsafe {
            sipral_account_check_certificate(
                handle,
                account,
                LEAF.as_ptr(),
                LEAF.len(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    /// A self-signed certificate whose `subjectAltName` is `names`: the chain is the
    /// platform's to judge, and only the name is read here.
    fn naming(names: Vec<rcgen::SanType>) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = names;
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn domain(
        certificate: &[u8],
        name: &str,
        rules: SipralDomainRules,
        matched: bool,
    ) -> (SipralStatus, u32) {
        let mut identity = u32::MAX;
        let status = unsafe {
            sipral_certificate_check_domain(
                certificate.as_ptr(),
                certificate.len(),
                name.as_ptr().cast(),
                name.len(),
                rules as u32,
                u32::from(matched),
                &raw mut identity,
            )
        };
        (status, identity)
    }

    #[test]
    fn a_sip_uri_is_accepted_and_a_wildcard_refused_by_rfc_5922_alone() {
        let uri = |text: &str| rcgen::SanType::URI(text.try_into().unwrap());
        let dns = |text: &str| rcgen::SanType::DnsName(text.try_into().unwrap());

        let by_uri = naming(vec![uri("sip:example.com")]);
        assert_eq!(
            domain(&by_uri, "example.com", SipralDomainRules::Platform, false),
            (SipralStatus::Ok, SipralDomainIdentity::SipUri as u32),
            "the platform refused a name it never reads"
        );

        let wildcard = naming(vec![dns("*.example.com")]);
        assert_eq!(
            domain(
                &wildcard,
                "pbx.example.com",
                SipralDomainRules::Platform,
                true
            ),
            (SipralStatus::Ok, SipralDomainIdentity::Wildcard as u32)
        );
        assert_eq!(
            domain(
                &wildcard,
                "pbx.example.com",
                SipralDomainRules::Rfc5922,
                true
            ),
            (
                SipralStatus::CertificateRefused,
                SipralDomainIdentity::Wildcard as u32
            )
        );
        assert!(
            last_error_text().contains("wildcard"),
            "{}",
            last_error_text()
        );

        let exact = naming(vec![dns("example.com")]);
        assert_eq!(
            domain(&exact, "example.com", SipralDomainRules::Rfc5922, true),
            (SipralStatus::Ok, SipralDomainIdentity::DnsName as u32)
        );
        assert_eq!(
            domain(&exact, "other.example", SipralDomainRules::Platform, false),
            (
                SipralStatus::CertificateRefused,
                SipralDomainIdentity::Unnamed as u32
            ),
            "the platform's refusal stands"
        );
    }

    #[test]
    fn what_is_not_a_certificate_or_not_a_rule_is_a_bad_argument() {
        let (status, identity) = domain(LEAF, "example.com", SipralDomainRules::Platform, true);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(
            identity,
            u32::MAX,
            "nothing is written for bytes that say nothing"
        );
        let certificate = naming(vec![rcgen::SanType::DnsName(
            "example.com".try_into().unwrap(),
        )]);
        let status = unsafe {
            sipral_certificate_check_domain(
                certificate.as_ptr(),
                certificate.len(),
                "example.com".as_ptr().cast(),
                11,
                2,
                1,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("rules is 2"),
            "{}",
            last_error_text()
        );
    }

    /// A root, an intermediate it signs that may name `corp.test` and the names under it
    /// alone, and a leaf the intermediate signs naming `names`: root, intermediate, leaf.
    fn constrained_chain(names: Vec<rcgen::SanType>) -> [Vec<u8>; 3] {
        use rcgen::{
            BasicConstraints, CertificateParams, GeneralSubtree, IsCa, Issuer, KeyPair,
            KeyUsagePurpose, NameConstraints,
        };
        let authority = |constraints: Option<NameConstraints>| {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.name_constraints = constraints;
            params
        };
        let root_key = KeyPair::generate().unwrap();
        let root_params = authority(None);
        let root = root_params.self_signed(&root_key).unwrap();
        let middle_key = KeyPair::generate().unwrap();
        let middle_params = authority(Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName("corp.test".to_owned())],
            excluded_subtrees: Vec::new(),
        }));
        let middle = middle_params
            .signed_by(&middle_key, &Issuer::from_params(&root_params, &root_key))
            .unwrap();
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.subject_alt_names = names;
        let leaf = leaf
            .signed_by(
                &KeyPair::generate().unwrap(),
                &Issuer::from_params(&middle_params, &middle_key),
            )
            .unwrap();
        [
            root.der().to_vec(),
            middle.der().to_vec(),
            leaf.der().to_vec(),
        ]
    }

    fn in_chain(
        certificate: &[u8],
        issuers: &[u8],
        name: &str,
        rules: SipralDomainRules,
        matched: bool,
    ) -> (SipralStatus, u32) {
        let mut identity = u32::MAX;
        let status = unsafe {
            sipral_certificate_check_domain_in_chain(
                certificate.as_ptr(),
                certificate.len(),
                issuers.as_ptr(),
                issuers.len(),
                name.as_ptr().cast(),
                name.len(),
                rules as u32,
                u32::from(matched),
                &raw mut identity,
            )
        };
        (status, identity)
    }

    #[test]
    fn a_sip_uri_the_intermediate_may_not_name_is_refused_with_the_chain_and_not_without() {
        let sip = |uri: &str| rcgen::SanType::URI(uri.try_into().unwrap());
        let dns = |name: &str| rcgen::SanType::DnsName(name.try_into().unwrap());
        let refused = (
            SipralStatus::CertificateRefused,
            SipralDomainIdentity::Unnamed as u32,
        );
        let by_uri = (SipralStatus::Ok, SipralDomainIdentity::SipUri as u32);

        let [root, middle, leaf] =
            constrained_chain(vec![sip("sip:victim.test"), dns("pbx.corp.test")]);
        let issuers = [middle.as_slice(), root.as_slice()].concat();
        for rules in [SipralDomainRules::Platform, SipralDomainRules::Rfc5922] {
            assert_eq!(
                in_chain(&leaf, &issuers, "victim.test", rules, false),
                refused,
                "{rules:?}: a sip: URI got past the dNSName constraint above it"
            );
            assert_eq!(
                in_chain(&leaf, &middle, "victim.test", rules, false),
                refused,
                "{rules:?}: the intermediate alone constrains it"
            );
            assert_eq!(
                domain(&leaf, "victim.test", rules, false),
                by_uri,
                "{rules:?}: the leaf alone is read as it always was"
            );
            assert_eq!(
                in_chain(&leaf, &[], "victim.test", rules, false),
                by_uri,
                "{rules:?}: no issuers is the leaf alone"
            );
        }

        let [root, middle, leaf] = constrained_chain(vec![sip("sip:pbx.corp.test")]);
        let issuers = [root.as_slice(), middle.as_slice()].concat();
        for rules in [SipralDomainRules::Platform, SipralDomainRules::Rfc5922] {
            assert_eq!(
                in_chain(&leaf, &issuers, "pbx.corp.test", rules, false),
                by_uri,
                "{rules:?}: a sip: URI inside the constraint names the domain"
            );
        }
    }

    #[test]
    fn issuers_that_do_not_end_where_a_certificate_does_are_a_bad_argument() {
        let [root, middle, leaf] = constrained_chain(vec![rcgen::SanType::URI(
            "sip:pbx.corp.test".try_into().unwrap(),
        )]);
        let mut issuers = [middle.as_slice(), root.as_slice()].concat();
        issuers.pop();
        for broken in [
            issuers.as_slice(),
            b"\x04\x01\x00".as_slice(),
            b"\x30\x85\x01",
        ] {
            let (status, identity) = in_chain(
                &leaf,
                broken,
                "pbx.corp.test",
                SipralDomainRules::Platform,
                true,
            );
            assert_eq!(status, SipralStatus::InvalidArgument, "{broken:02x?}");
            assert_eq!(identity, u32::MAX, "nothing is written");
            assert!(
                last_error_text().contains("issuers"),
                "{}",
                last_error_text()
            );
        }
        let status = unsafe {
            sipral_certificate_check_domain_in_chain(
                leaf.as_ptr(),
                leaf.len(),
                ptr::null(),
                3,
                "pbx.corp.test".as_ptr().cast(),
                13,
                SipralDomainRules::Platform as u32,
                1,
                ptr::null_mut(),
            )
        };
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "null issuers with a length"
        );
    }
}
