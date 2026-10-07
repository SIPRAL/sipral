// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One SIP connection over TLS for the examples that bring their own: a non-blocking `TcpStream`
//! with a `rustls` client. `tls.rs` signals only over this; `agent-bridge.rs` opens one when the
//! agent's address asks for TLS.
//!
//! `sipral-core` never opens TLS (`docs/01-architecture.md`): what this reads goes in as
//! `Input::StreamData`, and what the agent writes for this transport goes out through
//! [`TlsTransport::send`]. Built only with the `example-tls` feature.
#![allow(dead_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore,
    SignatureScheme,
};

use sipral::CertificatePin;

/// How the server's certificate is trusted.
pub(crate) enum Trust {
    /// By a chain to one of these roots, and by name, as `rustls` checks it.
    Roots(RootCertStore),
    /// By its fingerprint alone: a PBX's self-signed certificate.
    Pinned(CertificatePin),
}

/// A `rustls` verifier trusting one certificate by SHA-256 fingerprint
/// ([`sipral::CertificatePin`]).
///
/// The fingerprint replaces chain, anchors and host name, and a matching expired certificate is
/// accepted (see the pin's docs). The handshake signature is still verified, proving the server
/// holds the key.
#[derive(Debug)]
struct PinnedServer {
    pin: CertificatePin,
    provider: Arc<rustls::crypto::CryptoProvider>,
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
        match self.pin.check(end_entity.as_ref(), now.as_secs()) {
            Ok(pinned) => {
                if pinned.expired {
                    eprintln!("the pinned certificate has expired; accepted by its pin");
                }
                Ok(ServerCertVerified::assertion())
            }
            Err(_) => Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
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

/// One SIP connection over TLS: a non-blocking `TcpStream` with a `rustls` client, trusting the
/// platform store as read once at connect by [`rustls_native_certs`].
pub(crate) struct TlsTransport {
    pub(crate) tcp: TcpStream,
    conn: ClientConnection,
}

impl TlsTransport {
    /// The platform trust store. Separate from [`TlsTransport::connect`] so tests can pass a store
    /// with a throwaway certificate instead.
    pub(crate) fn platform_roots() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        // some platform certificates are not valid roots for rustls (expired, unsupported
        // algorithm); `add` refuses those and the rest load, so failures are ignored
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        roots
    }

    pub(crate) fn connect(remote: SocketAddr, server_name: &str, trust: Trust) -> io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?;
        let config = match trust {
            Trust::Roots(roots) => versions.with_root_certificates(roots).with_no_client_auth(),
            Trust::Pinned(pin) => versions
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedServer { pin, provider }))
                .with_no_client_auth(),
        };
        let name = ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?;
        let conn = ClientConnection::new(Arc::new(config), name).map_err(io::Error::other)?;
        let tcp = TcpStream::connect(remote)?;
        tcp.set_nonblocking(true)?;
        Ok(Self { tcp, conn })
    }

    /// Write `data` and flush the result: pending handshake flights first, then `data`'s record.
    pub(crate) fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.conn.writer().write_all(data)?;
        self.flush_tls()
    }

    fn flush_tls(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.tcp) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Read arrived ciphertext, pass each decrypted fragment to `on_data`, and let the handshake
    /// and alerts run.
    ///
    /// `read_tls` returning `Ok(0)` is the peer's FIN, not "nothing yet" (that is
    /// `Err(WouldBlock)`, handled below). Treating it as idle would hide a closed connection and
    /// `sipral-core` would never learn the transport is gone.
    pub(crate) fn poll(&mut self, mut on_data: impl FnMut(&[u8])) -> io::Result<PollOutcome> {
        let mut moved = false;
        let mut closed = false;
        loop {
            match self.conn.read_tls(&mut self.tcp) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(_) => moved = true,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        if let Err(error) = self.conn.process_new_packets() {
            // send the alert first, so the server learns of a refused certificate at once instead
            // of timing out
            let _ = self.flush_tls();
            return Err(io::Error::other(error));
        }
        let mut buffer = [0_u8; 4_096];
        loop {
            match self.conn.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    moved = true;
                    if let Some(chunk) = buffer.get(..length) {
                        on_data(chunk);
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        self.flush_tls()?;
        Ok(PollOutcome { moved, closed })
    }
}

/// What one [`TlsTransport::poll`] found: whether anything moved, and whether the peer closed.
/// Independent, since a closing read can still deliver a last fragment.
pub(crate) struct PollOutcome {
    pub(crate) moved: bool,
    pub(crate) closed: bool,
}
