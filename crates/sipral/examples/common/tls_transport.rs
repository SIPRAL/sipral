// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One SIP connection over TLS, for the examples that bring their own: a
//! non-blocking `TcpStream` with a `rustls` client on top of it. `tls.rs`
//! signals over nothing else; `agent-bridge.rs` opens one beside its UDP
//! socket when the agent's address asks for TLS.
//!
//! `sipral-core` never opens a TLS connection (`docs/01-architecture.md`,
//! "who owns the sockets, the resolver and TLS"): what this reads goes in as
//! `Input::StreamData` fragments, and what the agent writes for this
//! transport comes back out through [`TlsTransport::send`]. Built only with
//! the `example-tls` feature, which is what brings `rustls` in.
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

/// A `rustls` verifier that trusts one certificate by its SHA-256
/// fingerprint and nothing else ([`sipral::CertificatePin`]).
///
/// The fingerprint replaces the chain, the trust anchors and the host name,
/// and an expired certificate that matches is accepted, as the pin's own
/// documentation says why. The handshake signature is still verified the
/// ordinary way: a matching certificate proves nothing until the server has
/// shown it holds the certificate's private key.
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

/// One SIP connection over TLS: a non-blocking `TcpStream` with a `rustls`
/// client on top of it, checked against the platform's own trust store —
/// [`rustls_native_certs`] reads it once, at connect time, the way an
/// application that is not an example would too.
pub(crate) struct TlsTransport {
    pub(crate) tcp: TcpStream,
    conn: ClientConnection,
}

impl TlsTransport {
    /// The platform's own trust store, the way a real deployment checks a
    /// real server's certificate. Split out from [`TlsTransport::connect`]
    /// so a test can hand that one a store of its own instead — a throwaway
    /// certificate, trusted for that connection alone, rather than one more
    /// thing this process trusts everywhere.
    pub(crate) fn platform_roots() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        // A handful of certificates a platform's store carries are not valid
        // roots by rustls's own reading (an expired one, an algorithm it does
        // not implement); `add` refuses those and the rest still load, which
        // is why the failures are dropped rather than propagated.
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

    /// Hand `data` to the connection and push out whatever that produces —
    /// the handshake's own flights first, if it has not finished, then the
    /// record `data` became.
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

    /// Read whatever ciphertext has arrived, hand every decrypted fragment to
    /// `on_data`, and let the handshake and any alert run themselves.
    ///
    /// `read_tls` returning `Ok(0)` is not "nothing arrived yet" — on a
    /// non-blocking socket that is `Err(WouldBlock)`, already handled below —
    /// it is the peer's FIN, the TCP connection ending for good (the same
    /// meaning `Read::read` gives it). Conflating the two would leave a
    /// closed connection looking merely idle: `flush_tls` would keep failing
    /// silently underneath `send`, and nothing would ever tell
    /// `sipral-core` the transport is gone.
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
            // the alert saying why goes out before the connection is given
            // up, so that the server hears a refused certificate at once
            // rather than a silence it has to time out
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

/// What one [`TlsTransport::poll`] found: whether anything moved, on the wire
/// or off it, and whether the peer closed the connection — the two are
/// independent, since a closing read can still have delivered a last decrypted
/// fragment first.
pub(crate) struct PollOutcome {
    pub(crate) moved: bool,
    pub(crate) closed: bool,
}
