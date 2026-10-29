// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The platform's trust on iOS, evaluated by the Security framework.
//!
//! iOS lets no application read the authorities it trusts, so the chain a server presents is
//! handed to `SecTrustEvaluateWithError` under the SSL policy for the server's name, as
//! Network.framework and `URLSession` hand it: the system's authorities, the user's own trust
//! settings and the system's rules for a server certificate hold here as they hold for every
//! app. Authorities the application adds are anchors beside the system's. The same code runs
//! on macOS in this crate's tests, against the same framework.

use std::net::IpAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use security_framework::certificate::SecCertificate;
use security_framework::policy::SecPolicy;
use security_framework::secure_transport::SslProtocolSide;
use security_framework::trust::SecTrust;
use sipral_core::domain_certificate::{DomainIdentity, DomainRules, domain_identity_in_chain};
use sipral_core::endpoint::TransportErrorKind;

use super::Trust;
use crate::failure::{Failure, TlsFailure};

/// `errSecHostNameMismatch`: everything held but the name.
const HOST_NAME_MISMATCH: i64 = -67_602;
/// `errSecCertificateExpired`.
const EXPIRED: i64 = -67_818;
/// `errSecCertificateNotValidYet`.
const NOT_VALID_YET: i64 = -67_819;

/// A server's chain, evaluated by the Security framework for its name, with the name read as
/// [`DomainRules`] reads a SIP domain's when there are rules.
#[derive(Debug)]
pub(crate) struct PlatformServer {
    /// The authorities the application trusts beside the system's.
    anchors: Vec<SecCertificate>,
    rules: Option<DomainRules>,
    provider: Arc<CryptoProvider>,
}

impl PlatformServer {
    /// The verifier for `trust` where the platform's authorities are in it; `None` for a trust
    /// that names its own authorities alone or one certificate, which `webpki` checks without
    /// the platform.
    pub(crate) fn of(
        trust: &Trust,
        rules: Option<DomainRules>,
        provider: &Arc<CryptoProvider>,
    ) -> Option<Result<Self, Failure>> {
        let added: &[CertificateDer<'static>] = match *trust {
            Trust::Platform => &[],
            Trust::PlatformAnd(ref roots) => roots,
            Trust::Only(_) | Trust::Pinned(_) => return None,
        };
        Some(Self::new(added, rules, provider))
    }

    fn new(
        added: &[CertificateDer<'static>],
        rules: Option<DomainRules>,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Self, Failure> {
        let anchors = added
            .iter()
            .map(|der| SecCertificate::from_der(der.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                Failure::new(
                    TransportErrorKind::Other,
                    TlsFailure::HandshakeRefused,
                    &format!("TLS could not be set up: an authority was refused: {error}"),
                )
            })?;
        Ok(Self {
            anchors,
            rules,
            provider: Arc::clone(provider),
        })
    }

    /// The chain evaluated for `name`, or for any name (`None`): the chain the evaluation built,
    /// leaf first and anchor last, or the Security framework's error code when it does not hold.
    fn evaluate(
        &self,
        chain: &[SecCertificate],
        name: Option<&str>,
    ) -> Result<Vec<SecCertificate>, i64> {
        let policy = SecPolicy::create_ssl(SslProtocolSide::SERVER, name);
        let mut trust = SecTrust::create_with_certificates(chain, &[policy])
            .map_err(|error| i64::from(error.code()))?;
        if !self.anchors.is_empty() {
            trust
                .set_anchor_certificates(&self.anchors)
                .and_then(|()| trust.set_trust_anchor_certificates_only(false))
                .map_err(|error| i64::from(error.code()))?;
        }
        trust
            .evaluate_with_error()
            .map_err(|error| i64::try_from(error.code()).unwrap_or(i64::MIN))?;
        Ok(trust.chain())
    }
}

/// What a code the evaluation ended with says, as rustls says it.
const fn refusal(code: i64) -> rustls::Error {
    rustls::Error::InvalidCertificate(match code {
        EXPIRED => CertificateError::Expired,
        NOT_VALID_YET => CertificateError::NotValidYet,
        HOST_NAME_MISMATCH => CertificateError::NotValidForName,
        _ => CertificateError::UnknownIssuer,
    })
}

impl ServerCertVerifier for PlatformServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chain = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|der| SecCertificate::from_der(der.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let name = match *server_name {
            ServerName::DnsName(ref name) => name.as_ref().to_owned(),
            ServerName::IpAddress(address) => IpAddr::from(address).to_string(),
            _ => return Err(refusal(HOST_NAME_MISMATCH)),
        };
        let (matched, evaluated) = match self.evaluate(&chain, Some(&name)) {
            Ok(evaluated) => (true, evaluated),
            Err(HOST_NAME_MISMATCH) => {
                // the name alone failed: the chain, its dates and the rest once more with no
                // name, so that what follows reads the name and nothing else
                (false, self.evaluate(&chain, None).map_err(refusal)?)
            }
            Err(code) => return Err(refusal(code)),
        };
        let Some(rules) = self.rules else {
            return if matched {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(refusal(HOST_NAME_MISMATCH))
            };
        };
        // the authorities the evaluation went through, an intermediate it fetched itself and
        // the anchor included, and those the server sent: one more constrained authority can
        // only refuse a sip: URI, never accept one
        let issuers = intermediates
            .iter()
            .map(|der| der.to_vec())
            .chain(evaluated.iter().skip(1).map(SecCertificate::to_der));
        let identity = domain_identity_in_chain(end_entity.as_ref(), issuers, &name)
            .unwrap_or(DomainIdentity::Unnamed);
        if identity.accepted(rules, matched) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(refusal(HOST_NAME_MISMATCH))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
        Issuer, KeyPair, KeyUsagePurpose, NameConstraints, SanType,
    };
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{CertificateError, Error};
    use sipral_core::domain_certificate::DomainRules;

    use super::PlatformServer;
    use crate::Trust;

    /// An authority of the test's own, and a leaf it signs naming `names`, valid from yesterday
    /// for thirty days and for server authentication, as Apple's rules for a server
    /// certificate require of every one, a private authority's included.
    fn signed(names: Vec<SanType>) -> (CertificateDer<'static>, CertificateDer<'static>) {
        let day = time::Duration::days(1);
        let now = time::OffsetDateTime::now_utc();
        let authority_key = KeyPair::generate().unwrap();
        let mut authority = CertificateParams::new(Vec::<String>::new()).unwrap();
        authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        authority
            .distinguished_name
            .push(DnType::CommonName, "Sipral test authority");
        authority.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        authority.not_before = now - day;
        authority.not_after = now + day * 30;
        let root = authority.self_signed(&authority_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.subject_alt_names = names;
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.not_before = now - day;
        leaf.not_after = now + day * 30;
        let leaf = leaf
            .signed_by(&key, &Issuer::from_params(&authority, &authority_key))
            .unwrap();
        (root.der().clone(), leaf.der().clone())
    }

    fn checked(
        trust: &Trust,
        rules: Option<DomainRules>,
        leaf: &CertificateDer<'_>,
        name: &str,
    ) -> Result<(), Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = PlatformServer::of(trust, rules, &provider)
            .expect("the platform's authorities are in this trust")
            .unwrap();
        server
            .verify_server_cert(
                leaf,
                &[],
                &ServerName::try_from(name.to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .map(|_| ())
    }

    fn dns(name: &str) -> SanType {
        SanType::DnsName(name.try_into().unwrap())
    }

    fn sip(uri: &str) -> SanType {
        SanType::URI(uri.try_into().unwrap())
    }

    #[test]
    fn an_authority_beside_the_platforms_vouches_for_its_names_alone() {
        let (root, leaf) = signed(vec![dns("pbx.example.test")]);
        let trust = Trust::PlatformAnd(vec![root]);
        assert!(checked(&trust, None, &leaf, "pbx.example.test").is_ok());
        assert_eq!(
            checked(&trust, None, &leaf, "other.example.test"),
            Err(Error::InvalidCertificate(CertificateError::NotValidForName))
        );
        assert_eq!(
            checked(&Trust::Platform, None, &leaf, "pbx.example.test"),
            Err(Error::InvalidCertificate(CertificateError::UnknownIssuer)),
            "the platform's authorities alone have never heard of the test's"
        );
    }

    #[test]
    fn a_sip_domain_is_read_as_rfc_5922_reads_it_once_the_chain_holds() {
        let (root, leaf) = signed(vec![sip("sip:example.test"), dns("pbx.example.test")]);
        let trust = Trust::PlatformAnd(vec![root]);
        // the platform matched no name, and the sip: URI names the domain
        assert!(checked(&trust, Some(DomainRules::Platform), &leaf, "example.test").is_ok());
        assert!(checked(&trust, Some(DomainRules::Rfc5922), &leaf, "example.test").is_ok());
        // a dNSName beside a sip: URI for another domain counts under RFC 5922 alone not at all
        assert!(
            checked(
                &trust,
                Some(DomainRules::Platform),
                &leaf,
                "pbx.example.test"
            )
            .is_ok()
        );
        assert_eq!(
            checked(
                &trust,
                Some(DomainRules::Rfc5922),
                &leaf,
                "pbx.example.test"
            ),
            Err(Error::InvalidCertificate(CertificateError::NotValidForName))
        );

        let (root, wildcard) = signed(vec![dns("*.example.test")]);
        let trust = Trust::PlatformAnd(vec![root]);
        assert!(
            checked(
                &trust,
                Some(DomainRules::Platform),
                &wildcard,
                "pbx.example.test"
            )
            .is_ok()
        );
        assert_eq!(
            checked(
                &trust,
                Some(DomainRules::Rfc5922),
                &wildcard,
                "pbx.example.test"
            ),
            Err(Error::InvalidCertificate(CertificateError::NotValidForName)),
            "RFC 5922 §7.2: no wildcard"
        );
    }

    #[test]
    fn a_sip_uri_an_intermediate_may_not_name_is_refused_under_either_rules() {
        let day = time::Duration::days(1);
        let now = time::OffsetDateTime::now_utc();
        let authority = |constraints: Option<NameConstraints>, name: &str| {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.distinguished_name.push(DnType::CommonName, name);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.name_constraints = constraints;
            params.not_before = now - day;
            params.not_after = now + day * 30;
            params
        };
        let root_key = KeyPair::generate().unwrap();
        let root_params = authority(None, "Sipral test root");
        let root = root_params.self_signed(&root_key).unwrap();
        let middle_key = KeyPair::generate().unwrap();
        let middle_params = authority(
            Some(NameConstraints {
                permitted_subtrees: vec![GeneralSubtree::DnsName("corp.test".to_owned())],
                excluded_subtrees: Vec::new(),
            }),
            "Sipral test intermediate",
        );
        let middle = middle_params
            .signed_by(&middle_key, &Issuer::from_params(&root_params, &root_key))
            .unwrap();
        let leaf = |names: Vec<SanType>| {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names = names;
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.not_before = now - day;
            params.not_after = now + day * 30;
            params
                .signed_by(
                    &KeyPair::generate().unwrap(),
                    &Issuer::from_params(&middle_params, &middle_key),
                )
                .unwrap()
                .der()
                .clone()
        };
        let trust = Trust::PlatformAnd(vec![root.der().clone()]);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let checked = |rules: DomainRules, leaf: &CertificateDer<'_>, name: &str| {
            PlatformServer::of(&trust, Some(rules), &provider)
                .expect("the platform's authorities are in this trust")
                .unwrap()
                .verify_server_cert(
                    leaf,
                    core::slice::from_ref(middle.der()),
                    &ServerName::try_from(name.to_owned()).unwrap(),
                    &[],
                    UnixTime::now(),
                )
                .map(|_| ())
        };

        let outside = leaf(vec![sip("sip:victim.test"), dns("pbx.corp.test")]);
        for rules in [DomainRules::Platform, DomainRules::Rfc5922] {
            assert_eq!(
                checked(rules, &outside, "victim.test"),
                Err(Error::InvalidCertificate(CertificateError::NotValidForName)),
                "{rules:?}: a sip: URI got past the dNSName constraint of the authority above it"
            );
        }
        let inside = leaf(vec![sip("sip:corp.test")]);
        for rules in [DomainRules::Platform, DomainRules::Rfc5922] {
            assert_eq!(
                checked(rules, &inside, "corp.test"),
                Ok(()),
                "{rules:?}: a sip: URI inside the constraint names the domain"
            );
        }
    }

    #[test]
    fn a_trust_of_its_own_authorities_or_a_pin_is_not_the_platforms() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        assert!(PlatformServer::of(&Trust::Only(Vec::new()), None, &provider).is_none());
        assert!(
            PlatformServer::of(
                &Trust::Pinned(sipral_core::pin::CertificatePin::from_sha256([7; 32])),
                None,
                &provider
            )
            .is_none()
        );
    }
}
