// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Why a connection failed, in the two coarse numbers the core and the C ABI carry, and one
//! sentence for the log.
//!
//! The classification is the one every binding makes (`bindings/python/sipral/signalling.py`,
//! `classify`), so an application sees the same reason whichever layer opened the connection.

use std::fmt;
use std::io;

use rustls::{AlertDescription, CertificateError};
use sipral_core::endpoint::TransportErrorKind;

/// The longest detail sentence the C ABI takes (`SIPRAL_TRANSPORT_DETAIL_BYTES`); longer is cut
/// at a character boundary here rather than refused there.
const DETAIL_BYTES: usize = 1_024;

/// Why a TLS connection failed, as the C ABI's `sipral_tls_failure_t` numbers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsFailure {
    /// Not a TLS failure, or one nothing here could classify.
    None,
    /// The server's certificate does not chain to a trusted authority, or is not the pinned one.
    Untrusted,
    /// The certificate is not for the name the connection was made to.
    NameMismatch,
    /// The certificate is out of its dates.
    Expired,
    /// The handshake failed for a reason that is not the certificate's.
    HandshakeRefused,
    /// The server asked for a client certificate and this end had none to present.
    ClientCertificateRequired,
    /// The server refused the client certificate this end presented.
    ClientCertificateRefused,
    /// The client certificate's private key could not be used.
    ClientKeyUnavailable,
    /// The client certificate is out of its dates, read before connecting, or the server's
    /// `certificate_expired` alert.
    ClientCertificateExpired,
}

impl TlsFailure {
    /// The number `sipral_tls_failure_t` gives this reason.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Untrusted => 1,
            Self::NameMismatch => 2,
            Self::Expired => 3,
            Self::HandshakeRefused => 4,
            Self::ClientCertificateRequired => 5,
            Self::ClientCertificateRefused => 6,
            Self::ClientKeyUnavailable => 7,
            Self::ClientCertificateExpired => 8,
        }
    }
}

/// Why a connection could not be made or kept.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Failure {
    /// What the core is told: the transaction terminates on every one of these (RFC 3261 §17).
    pub error: TransportErrorKind,
    /// For a TLS connection, why TLS refused it.
    pub tls: TlsFailure,
    /// One sentence for the log, without control characters, at most 1024 bytes.
    pub detail: String,
}

impl Failure {
    /// A failure with `detail` made fit for the log: one line, at most 1024 bytes.
    #[must_use]
    pub fn new(error: TransportErrorKind, tls: TlsFailure, detail: &str) -> Self {
        Self {
            error,
            tls,
            detail: sentence(detail),
        }
    }

    /// A failed socket call, said in `what` ("TCP to 192.0.2.1:5060").
    pub(crate) fn of_io(what: &str, error: &io::Error) -> Self {
        let kind = io_kind(error);
        Self::new(
            kind,
            TlsFailure::None,
            &format!("{what} {}: {error}", verdict(kind)),
        )
    }

    /// A refused handshake or a broken TLS connection. `presented` says whether this end offered
    /// a client certificate and `asked` whether the server asked for one, which decide what an
    /// alert about one means.
    pub(crate) fn of_tls(what: &str, error: &rustls::Error, presented: bool, asked: bool) -> Self {
        let tls = tls_reason(error, presented, asked);
        Self::new(
            TransportErrorKind::ConnectionReset,
            tls,
            &format!("{what} refused: {error}"),
        )
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for Failure {}

/// How the failure reads after "TCP to ...".
const fn verdict(kind: TransportErrorKind) -> &'static str {
    match kind {
        TransportErrorKind::ConnectionRefused => "was refused",
        TransportErrorKind::ConnectionReset => "was reset",
        TransportErrorKind::Unreachable => "is unreachable",
        TransportErrorKind::TimedOut => "timed out",
        TransportErrorKind::Closed => "was closed",
        _ => "failed",
    }
}

/// An operating system error as the core's coarse kind.
pub(crate) fn io_kind(error: &io::Error) -> TransportErrorKind {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TransportErrorKind::TimedOut,
        io::ErrorKind::ConnectionRefused => TransportErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => TransportErrorKind::ConnectionReset,
        io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NetworkDown => TransportErrorKind::Unreachable,
        io::ErrorKind::UnexpectedEof | io::ErrorKind::NotConnected => TransportErrorKind::Closed,
        _ => TransportErrorKind::Other,
    }
}

/// Whether a server's alert is about this end's certificate (RFC 8446 §6.2, RFC 5246 §7.2.2):
/// the ones a server sends for a certificate it will not take, or for none.
const fn about_certificate(alert: AlertDescription) -> bool {
    matches!(
        alert,
        AlertDescription::CertificateRequired
            | AlertDescription::BadCertificate
            | AlertDescription::UnsupportedCertificate
            | AlertDescription::CertificateRevoked
            | AlertDescription::CertificateUnknown
            | AlertDescription::UnknownCA
            | AlertDescription::AccessDenied
    )
}

/// What a rustls error says about why the connection failed.
pub(crate) fn tls_reason(error: &rustls::Error, presented: bool, asked: bool) -> TlsFailure {
    match *error {
        rustls::Error::InvalidCertificate(ref certificate) => match *certificate {
            CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. } => TlsFailure::Expired,
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                TlsFailure::NameMismatch
            }
            _ => TlsFailure::Untrusted,
        },
        rustls::Error::AlertReceived(AlertDescription::CertificateExpired) if presented => {
            TlsFailure::ClientCertificateExpired
        }
        rustls::Error::AlertReceived(alert) if about_certificate(alert) => {
            if presented {
                TlsFailure::ClientCertificateRefused
            } else {
                TlsFailure::ClientCertificateRequired
            }
        }
        // a server that asked for a certificate and got none says `handshake_failure` at TLS 1.2
        rustls::Error::AlertReceived(AlertDescription::HandshakeFailure) if asked && !presented => {
            TlsFailure::ClientCertificateRequired
        }
        _ => TlsFailure::HandshakeRefused,
    }
}

/// `text` as one line within [`DETAIL_BYTES`]: control characters become spaces, and the cut
/// falls on a character boundary.
fn sentence(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(DETAIL_BYTES));
    for character in text.trim().chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if out.len() + character.len_utf8() > DETAIL_BYTES {
            break;
        }
        out.push(character);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Failure, TlsFailure, sentence, tls_reason};
    use rustls::{AlertDescription, CertificateError};
    use sipral_core::endpoint::TransportErrorKind;
    use std::io;

    #[test]
    fn a_refused_server_certificate_is_read_as_the_bindings_read_it() {
        let reason = |error| tls_reason(&rustls::Error::InvalidCertificate(error), false, false);
        assert_eq!(reason(CertificateError::Expired), TlsFailure::Expired);
        assert_eq!(reason(CertificateError::NotValidYet), TlsFailure::Expired);
        assert_eq!(
            reason(CertificateError::NotValidForName),
            TlsFailure::NameMismatch
        );
        assert_eq!(
            reason(CertificateError::UnknownIssuer),
            TlsFailure::Untrusted
        );
        assert_eq!(
            reason(CertificateError::ApplicationVerificationFailure),
            TlsFailure::Untrusted
        );
    }

    #[test]
    fn an_alert_about_this_ends_certificate_depends_on_whether_one_was_presented() {
        let alert = |alert, presented, asked| {
            tls_reason(&rustls::Error::AlertReceived(alert), presented, asked)
        };
        assert_eq!(
            alert(AlertDescription::CertificateRequired, false, true),
            TlsFailure::ClientCertificateRequired
        );
        assert_eq!(
            alert(AlertDescription::UnknownCA, true, true),
            TlsFailure::ClientCertificateRefused
        );
        assert_eq!(
            alert(AlertDescription::CertificateExpired, true, true),
            TlsFailure::ClientCertificateExpired
        );
        assert_eq!(
            alert(AlertDescription::HandshakeFailure, false, true),
            TlsFailure::ClientCertificateRequired
        );
        assert_eq!(
            alert(AlertDescription::HandshakeFailure, false, false),
            TlsFailure::HandshakeRefused
        );
        assert_eq!(
            alert(AlertDescription::ProtocolVersion, false, false),
            TlsFailure::HandshakeRefused
        );
    }

    #[test]
    fn every_reason_has_the_number_the_c_abi_gives_it() {
        let numbers: Vec<u32> = [
            TlsFailure::None,
            TlsFailure::Untrusted,
            TlsFailure::NameMismatch,
            TlsFailure::Expired,
            TlsFailure::HandshakeRefused,
            TlsFailure::ClientCertificateRequired,
            TlsFailure::ClientCertificateRefused,
            TlsFailure::ClientKeyUnavailable,
            TlsFailure::ClientCertificateExpired,
        ]
        .iter()
        .map(|reason| reason.number())
        .collect();
        assert_eq!(numbers, (0..=8).collect::<Vec<u32>>());
    }

    #[test]
    fn a_socket_error_names_its_kind_and_says_what_failed() {
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        let failure = Failure::of_io("TCP to 192.0.2.1:5060", &refused);
        assert_eq!(failure.error, TransportErrorKind::ConnectionRefused);
        assert_eq!(failure.tls, TlsFailure::None);
        assert!(
            failure
                .detail
                .starts_with("TCP to 192.0.2.1:5060 was refused")
        );
        let timed_out = io::Error::from(io::ErrorKind::TimedOut);
        assert_eq!(
            Failure::of_io("TCP", &timed_out).error,
            TransportErrorKind::TimedOut
        );
    }

    #[test]
    fn a_detail_is_one_line_and_fits_the_abi() {
        assert_eq!(sentence(" one\ntwo\r "), "one two");
        let long = "é".repeat(800);
        let cut = sentence(&long);
        assert!(cut.len() <= 1_024);
        assert!(cut.chars().all(|character| character == 'é'));
    }
}
