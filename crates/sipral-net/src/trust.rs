// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Which servers a TLS connection trusts, and which certificate this end presents.
//!
//! The four choices are the bindings' (`docs/22-tls.md`): the platform's trust store; a private
//! authority beside it; that authority alone; one certificate pinned by the SHA-256 fingerprint of
//! its DER. Nothing here turns checking off.

use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use sipral_core::domain_certificate::{DomainIdentity, DomainRules, domain_identity};
use sipral_core::endpoint::TransportErrorKind;
use sipral_core::pin::CertificatePin;

use crate::failure::{Failure, TlsFailure};

/// Which servers a TLS connection trusts.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum Trust {
    /// The authorities in the platform's trust store: the keychain's on macOS, the system
    /// store on Windows, the system's CA bundle elsewhere, `SSL_CERT_FILE` when it names one.
    #[default]
    Platform,
    /// The platform's anchors and these authorities beside them.
    PlatformAnd(Vec<CertificateDer<'static>>),
    /// These authorities alone; the platform's are not consulted.
    Only(Vec<CertificateDer<'static>>),
    /// One certificate, by the SHA-256 fingerprint of its DER. Chain, name and dates are not
    /// checked; the handshake signature is.
    Pinned(CertificatePin),
}

/// Why a list of authorities could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustError {
    /// The text holds no PEM certificate.
    NoCertificate,
    /// A PEM block could not be read.
    Unreadable(String),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoCertificate => f.write_str("the authority holds no PEM certificate"),
            Self::Unreadable(ref why) => write!(f, "the authority cannot be read: {why}"),
        }
    }
}

impl std::error::Error for TrustError {}

impl Trust {
    /// Every certificate in a PEM text, for [`Trust::PlatformAnd`] or [`Trust::Only`].
    ///
    /// # Errors
    /// [`TrustError`] when a block cannot be read or there is none.
    pub fn authorities_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TrustError> {
        let mut out = Vec::new();
        for certificate in CertificateDer::pem_slice_iter(pem) {
            out.push(certificate.map_err(|error| TrustError::Unreadable(error.to_string()))?);
        }
        if out.is_empty() {
            return Err(TrustError::NoCertificate);
        }
        Ok(out)
    }
}

/// A client certificate this end presents when a server asks for one (RFC 5246 §7.4.6,
/// RFC 8446 §4.4.2), from PEM.
///
/// Read again before every connection, as every binding does: a key that does not load or does
/// not match the certificate is [`TlsFailure::ClientKeyUnavailable`], a certificate out of its
/// dates [`TlsFailure::ClientCertificateExpired`], and neither reaches the server.
#[derive(Clone)]
pub struct ClientCertificate {
    chain: Vec<u8>,
    key: Arc<[u8]>,
}

impl fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // the key stays out of every log
        f.debug_struct("ClientCertificate")
            .field("chain_bytes", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// Why a client certificate was refused before a connection was tried.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientCertificateError {
    /// The PEM text is empty.
    Empty,
}

impl fmt::Display for ClientCertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a client certificate needs its chain and its key")
    }
}

impl std::error::Error for ClientCertificateError {}

impl ClientCertificate {
    /// The certificate, leaf first, then any intermediates the server needs, and its private key
    /// (PKCS #8, SEC 1 or PKCS #1), both as PEM.
    ///
    /// # Errors
    /// [`ClientCertificateError::Empty`] when either is empty; what is in them is read at each
    /// connection.
    pub fn from_pem(chain: &[u8], key: &[u8]) -> Result<Self, ClientCertificateError> {
        if chain.is_empty() || key.is_empty() {
            return Err(ClientCertificateError::Empty);
        }
        Ok(Self {
            chain: chain.to_vec(),
            key: Arc::from(key),
        })
    }

    /// The key and chain, checked, for one connection.
    fn certified(&self, provider: &CryptoProvider, now: u64) -> Result<CertifiedKey, Failure> {
        let unavailable = |why: String| {
            Failure::new(
                TransportErrorKind::Other,
                TlsFailure::ClientKeyUnavailable,
                &format!("the client certificate's key cannot be used: {why}"),
            )
        };
        let chain = CertificateDer::pem_slice_iter(&self.chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| unavailable(error.to_string()))?;
        let Some(leaf) = chain.first() else {
            return Err(unavailable("the chain holds no PEM certificate".to_owned()));
        };
        let key = PrivateKeyDer::from_pem_slice(&self.key)
            .map_err(|error| unavailable(error.to_string()))?;
        let certified = CertifiedKey::from_der(chain.clone(), key, provider)
            .map_err(|error| unavailable(error.to_string()))?;
        // the dates, as a pin reads them: any certificate matches its own pin
        if let Ok(dated) = CertificatePin::of(leaf.as_ref()).check(leaf.as_ref(), now)
            && (dated.expired || dated.not_yet_valid)
        {
            return Err(Failure::new(
                TransportErrorKind::Other,
                TlsFailure::ClientCertificateExpired,
                if dated.expired {
                    "the client certificate has expired"
                } else {
                    "the client certificate is not valid yet"
                },
            ));
        }
        Ok(certified)
    }
}

/// The seconds since the epoch, as a certificate's dates are read.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// A client configuration for one connection, and what it learns during the handshake.
pub(crate) struct Prepared {
    pub(crate) config: Arc<ClientConfig>,
    /// Set when the server's CertificateRequest arrived.
    pub(crate) asked: Arc<AtomicBool>,
    /// Whether this end has a certificate to present.
    pub(crate) presented: bool,
}

/// The platform's trust store, read the first time a connection of one network needs it, and
/// kept for the network's life.
#[derive(Debug, Default)]
pub(crate) struct PlatformRoots(OnceLock<Vec<CertificateDer<'static>>>);

impl PlatformRoots {
    /// The authorities the platform's store holds. One the store cannot hand over whole is left
    /// out, as the platform's own clients leave it out.
    fn get(&self) -> &[CertificateDer<'static>] {
        self.0
            .get_or_init(|| rustls_native_certs::load_native_certs().certs)
    }
}

/// The configuration for one connection: `pin` (an account's) wins over `trust`, and a chain
/// that `trust` vouches for has its name read by `rules`.
pub(crate) fn prepare(
    trust: &Trust,
    pin: Option<&CertificatePin>,
    client: Option<&ClientCertificate>,
    platform: &PlatformRoots,
    rules: DomainRules,
) -> Result<Prepared, Failure> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let refused = |why: &str| {
        Failure::new(
            TransportErrorKind::Other,
            TlsFailure::HandshakeRefused,
            &format!("TLS could not be set up: {why}"),
        )
    };
    let verifier: Arc<dyn ServerCertVerifier> = match (pin.copied(), trust) {
        (Some(pin), _) | (None, &Trust::Pinned(pin)) => Arc::new(PinnedServer {
            pin,
            provider: Arc::clone(&provider),
        }),
        (None, Trust::Platform | Trust::PlatformAnd(_) | Trust::Only(_)) => {
            let mut store = RootCertStore::empty();
            if matches!(trust, Trust::Platform | Trust::PlatformAnd(_)) {
                store.add_parsable_certificates(platform.get().iter().cloned());
            }
            if let Trust::PlatformAnd(roots) | Trust::Only(roots) = trust {
                for root in roots {
                    store
                        .add(root.clone())
                        .map_err(|error| refused(&format!("an authority was refused: {error}")))?;
                }
            }
            if store.is_empty() {
                return Err(Failure::new(
                    TransportErrorKind::Other,
                    TlsFailure::Untrusted,
                    "TLS not tried: the platform's trust store holds no authority this library \
                     can read; trust a private authority or pin the server's certificate",
                ));
            }
            let chain =
                WebPkiServerVerifier::builder_with_provider(Arc::new(store), Arc::clone(&provider))
                    .build()
                    .map_err(|error| refused(&error.to_string()))?;
            Arc::new(SipDomainServer { chain, rules })
        }
    };
    let key = match client {
        Some(client) => Some(Arc::new(client.certified(&provider, unix_now())?)),
        None => None,
    };
    let asked = Arc::new(AtomicBool::new(false));
    let presented = key.is_some();
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| refused(&error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(Presenter {
            key,
            asked: Arc::clone(&asked),
        }));
    Ok(Prepared {
        config: Arc::new(config),
        asked,
        presented,
    })
}

/// Presents this end's certificate, if it has one, and notes that the server asked.
#[derive(Debug)]
struct Presenter {
    key: Option<Arc<CertifiedKey>>,
    asked: Arc<AtomicBool>,
}

impl ResolvesClientCert for Presenter {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.asked.store(true, Ordering::Release);
        self.key.clone()
    }

    fn has_certs(&self) -> bool {
        self.key.is_some()
    }
}

/// The platform's verifier, with the server's name read as RFC 5922 reads a SIP server's
/// ([`DomainRules`]).
///
/// rustls checks the chain, the dates and revocation before the name, so a refusal for the name
/// alone means everything else held: that is when a `sip:` URI naming the domain is still
/// accepted. Under [`DomainRules::Rfc5922`] a name the HTTPS rules matched is refused unless RFC
/// 5922 reads it too, a wildcard above all.
#[derive(Debug)]
struct SipDomainServer {
    chain: Arc<WebPkiServerVerifier>,
    rules: DomainRules,
}

impl ServerCertVerifier for SipDomainServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let platform = self.chain.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let matched = match platform {
            Ok(_) => true,
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => false,
            Err(_) => return platform,
        };
        let domain = match *server_name {
            ServerName::DnsName(ref name) => name.as_ref().to_owned(),
            ServerName::IpAddress(address) => IpAddr::from(address).to_string(),
            _ => return platform,
        };
        let identity =
            domain_identity(end_entity.as_ref(), &domain).unwrap_or(DomainIdentity::Unnamed);
        if identity.accepted(self.rules, matched) {
            Ok(ServerCertVerified::assertion())
        } else if matched {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ))
        } else {
            platform
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.chain.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.chain.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chain.supported_verify_schemes()
    }
}

/// A verifier trusting one certificate by its fingerprint ([`CertificatePin`]).
///
/// The fingerprint replaces chain, anchors and host name, and a matching expired certificate is
/// accepted (`docs/22-tls.md`, "A PBX's own certificate, pinned"). The handshake signature is
/// still verified, proving the server holds the key.
#[derive(Debug)]
struct PinnedServer {
    pin: CertificatePin,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.pin
            .check(end_entity.as_ref(), now.as_secs())
            .map(|_| ServerCertVerified::assertion())
            .map_err(|_| {
                rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
            })
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
    use super::{ClientCertificate, PlatformRoots, Prepared, Trust, TrustError, prepare};
    use crate::{Failure, TlsFailure};
    use sipral_core::domain_certificate::DomainRules;
    use sipral_core::pin::CertificatePin;

    /// Prepared with a pin, so that no test reads the platform's store.
    fn presenting(client: &ClientCertificate) -> Result<Prepared, Failure> {
        let pinned = Trust::Pinned(CertificatePin::from_sha256([7; 32]));
        prepare(
            &pinned,
            None,
            Some(client),
            &PlatformRoots::default(),
            DomainRules::Platform,
        )
    }

    #[test]
    fn an_authority_without_a_certificate_is_refused_before_any_connection() {
        assert_eq!(
            Trust::authorities_from_pem(b"not a certificate").unwrap_err(),
            TrustError::NoCertificate
        );
    }

    #[test]
    fn a_client_key_that_is_not_the_certificates_is_never_offered() {
        let one = rcgen::generate_simple_self_signed(vec!["one.test".to_owned()]).unwrap();
        let two = rcgen::generate_simple_self_signed(vec!["two.test".to_owned()]).unwrap();
        let mismatched = ClientCertificate::from_pem(
            one.cert.pem().as_bytes(),
            two.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let refused = presenting(&mismatched)
            .err()
            .expect("a mismatched key is refused");
        assert_eq!(refused.tls, TlsFailure::ClientKeyUnavailable);

        let matched = ClientCertificate::from_pem(
            one.cert.pem().as_bytes(),
            one.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let prepared = presenting(&matched).unwrap();
        assert!(prepared.presented);
    }

    #[test]
    fn an_expired_client_certificate_is_never_offered() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["client.test".to_owned()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2020, 1, 2);
        let certificate = params.self_signed(&key).unwrap();
        let expired = ClientCertificate::from_pem(
            certificate.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let refused = presenting(&expired)
            .err()
            .expect("an expired certificate is refused");
        assert_eq!(refused.tls, TlsFailure::ClientCertificateExpired);
    }
}
