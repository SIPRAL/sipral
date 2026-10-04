// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Alerts (RFC 5246 §7.2), as a DTLS record carries them.
//!
//! An alert is two octets, a level and a description, in a record of its own
//! content type. What a connection does with one — which end it, which are
//! sent, and in which epoch — is [`crate::connection`]'s business; this module
//! only reads and writes them and says which ones RFC 5246 calls fatal.

use crate::Error;
use crate::wire::Reader;

/// `AlertLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlertLevel(pub u8);

impl AlertLevel {
    /// `warning(1)`.
    pub const WARNING: Self = Self(1);
    /// `fatal(2)`.
    pub const FATAL: Self = Self(2);
}

/// `AlertDescription`: the values RFC 5246 §7.2 defines and does not mark
/// reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlertDescription(pub u8);

impl AlertDescription {
    /// `close_notify(0)`: the sender will send nothing more.
    pub const CLOSE_NOTIFY: Self = Self(0);
    /// `unexpected_message(10)`.
    pub const UNEXPECTED_MESSAGE: Self = Self(10);
    /// `bad_record_mac(20)`.
    pub const BAD_RECORD_MAC: Self = Self(20);
    /// `record_overflow(22)`.
    pub const RECORD_OVERFLOW: Self = Self(22);
    /// `decompression_failure(30)`.
    pub const DECOMPRESSION_FAILURE: Self = Self(30);
    /// `handshake_failure(40)`: no acceptable set of security parameters.
    pub const HANDSHAKE_FAILURE: Self = Self(40);
    /// `bad_certificate(42)`.
    pub const BAD_CERTIFICATE: Self = Self(42);
    /// `unsupported_certificate(43)`.
    pub const UNSUPPORTED_CERTIFICATE: Self = Self(43);
    /// `certificate_revoked(44)`.
    pub const CERTIFICATE_REVOKED: Self = Self(44);
    /// `certificate_expired(45)`.
    pub const CERTIFICATE_EXPIRED: Self = Self(45);
    /// `certificate_unknown(46)`.
    pub const CERTIFICATE_UNKNOWN: Self = Self(46);
    /// `illegal_parameter(47)`.
    pub const ILLEGAL_PARAMETER: Self = Self(47);
    /// `unknown_ca(48)`.
    pub const UNKNOWN_CA: Self = Self(48);
    /// `access_denied(49)`.
    pub const ACCESS_DENIED: Self = Self(49);
    /// `decode_error(50)`.
    pub const DECODE_ERROR: Self = Self(50);
    /// `decrypt_error(51)`: a signature or a Finished did not verify.
    pub const DECRYPT_ERROR: Self = Self(51);
    /// `protocol_version(70)`.
    pub const PROTOCOL_VERSION: Self = Self(70);
    /// `insufficient_security(71)`.
    pub const INSUFFICIENT_SECURITY: Self = Self(71);
    /// `internal_error(80)`.
    pub const INTERNAL_ERROR: Self = Self(80);
    /// `user_canceled(90)`.
    pub const USER_CANCELED: Self = Self(90);
    /// `no_renegotiation(100)`, "always a warning".
    pub const NO_RENEGOTIATION: Self = Self(100);
    /// `unsupported_extension(110)`.
    pub const UNSUPPORTED_EXTENSION: Self = Self(110);

    /// The descriptions RFC 5246 §7.2.2 calls "always fatal" (or, for
    /// `handshake_failure`, "a fatal error"), whatever level they arrive at.
    const ALWAYS_FATAL: [Self; 14] = [
        Self::UNEXPECTED_MESSAGE,
        Self::BAD_RECORD_MAC,
        Self::RECORD_OVERFLOW,
        Self::DECOMPRESSION_FAILURE,
        Self::HANDSHAKE_FAILURE,
        Self::ILLEGAL_PARAMETER,
        Self::UNKNOWN_CA,
        Self::ACCESS_DENIED,
        Self::DECODE_ERROR,
        Self::DECRYPT_ERROR,
        Self::PROTOCOL_VERSION,
        Self::INSUFFICIENT_SECURITY,
        Self::INTERNAL_ERROR,
        Self::UNSUPPORTED_EXTENSION,
    ];
}

/// One alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Alert {
    /// Warning or fatal.
    pub level: AlertLevel,
    /// What happened.
    pub description: AlertDescription,
}

impl Alert {
    /// A fatal alert.
    #[must_use]
    pub const fn fatal(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::FATAL,
            description,
        }
    }

    /// A warning.
    #[must_use]
    pub const fn warning(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::WARNING,
            description,
        }
    }

    /// Read an alert record's fragment, which is exactly two octets.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] for fewer, [`Error::TrailingData`] for more, and
    /// [`Error::IllegalValue`] for a level that is neither warning nor fatal —
    /// RFC 5246 defines no third, so such a record is invalid and is
    /// discarded like any other (RFC 6347 §4.1.2.7).
    pub fn parse(fragment: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(fragment);
        let level = AlertLevel(r.u8()?);
        let description = AlertDescription(r.u8()?);
        r.finish()?;
        if level != AlertLevel::WARNING && level != AlertLevel::FATAL {
            return Err(Error::IllegalValue);
        }
        Ok(Self { level, description })
    }

    /// The fragment.
    #[must_use]
    pub const fn encode(self) -> [u8; 2] {
        [self.level.0, self.description.0]
    }

    /// Whether receiving this ends the connection: a fatal level, or a
    /// description RFC 5246 says is always fatal even when a peer sends it
    /// as a warning.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.level == AlertLevel::FATAL
            || AlertDescription::ALWAYS_FATAL.contains(&self.description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_alert_is_a_level_then_a_description() {
        let alert = Alert::fatal(AlertDescription::BAD_CERTIFICATE);
        assert_eq!(alert.encode(), [2, 42]);
        assert_eq!(Alert::parse(&[2, 42]), Ok(alert));
        assert_eq!(
            Alert::parse(&[1, 0]),
            Ok(Alert::warning(AlertDescription::CLOSE_NOTIFY))
        );
        assert_eq!(Alert::parse(&[]), Err(Error::Truncated));
        assert_eq!(Alert::parse(&[2]), Err(Error::Truncated));
        assert_eq!(Alert::parse(&[2, 42, 0]), Err(Error::TrailingData));
        for level in [0, 3, 255] {
            assert_eq!(Alert::parse(&[level, 40]), Err(Error::IllegalValue));
        }
    }

    #[test]
    fn a_warning_ends_nothing_unless_its_description_is_always_fatal() {
        let ignorable = [
            AlertDescription::CLOSE_NOTIFY,
            AlertDescription::NO_RENEGOTIATION,
            AlertDescription::USER_CANCELED,
            AlertDescription::BAD_CERTIFICATE,
            AlertDescription::CERTIFICATE_EXPIRED,
        ];
        for description in ignorable {
            assert!(!Alert::warning(description).is_fatal(), "{description:?}");
            assert!(Alert::fatal(description).is_fatal(), "{description:?}");
        }
        for description in AlertDescription::ALWAYS_FATAL {
            assert!(Alert::warning(description).is_fatal(), "{description:?}");
        }
        // the values the list above is written from, so that a slip in a
        // constant is not also a slip in what the test expects
        let fatal_values: Vec<u8> = AlertDescription::ALWAYS_FATAL.iter().map(|d| d.0).collect();
        assert_eq!(
            fatal_values,
            [10, 20, 22, 30, 40, 47, 48, 49, 50, 51, 70, 71, 80, 110]
        );
    }

    #[test]
    fn no_fragment_makes_the_parser_panic() {
        for first in 0..=255u8 {
            for second in 0..=255u8 {
                let _ = Alert::parse(&[first, second]);
                let _ = Alert::parse(&[first, second, first]);
            }
            let _ = Alert::parse(&[first]);
        }
    }
}
