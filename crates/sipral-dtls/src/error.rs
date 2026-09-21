// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Why something in this crate was refused.

use core::fmt;

/// Why a DTLS structure, a key or a record was refused.
///
/// One type for the whole crate rather than one per module, because the
/// caller that matters — the handshake state machine — answers every one of
/// them the same way on a datagram transport: RFC 6347 §4.1.2.7 has invalid
/// records silently discarded, and a malformed handshake message ends the
/// handshake. The variants exist so that a log line can say which rule broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended inside a field it had announced.
    Truncated,
    /// Bytes were left over after a structure whose end is fixed.
    TrailingData,
    /// A length is outside the range the specification gives the field, or
    /// is not a whole number of the elements the field holds.
    Length,
    /// A field holds a value the specification does not allow in that place.
    IllegalValue,
    /// An extension type occurs twice in one hello (RFC 5246 §7.4.1.4).
    DuplicateExtension,
    /// A record, a message, a certificate or a reassembly buffer would exceed
    /// a limit — the specification's or this crate's.
    TooLarge,
    /// Application data was offered to a connection whose handshake has not
    /// completed, or that has failed or closed.
    NotConnected,
    /// The path MTU leaves no room for a single octet of handshake body.
    MtuTooSmall,
    /// A protected record did not authenticate. RFC 5288 §3 reports every
    /// AES-GCM failure this way, so a short record lands here too.
    BadRecordMac,
    /// A record's sequence number was already accepted, or is older than the
    /// replay window reaches (RFC 6347 §4.1.2.6).
    Replayed,
    /// The 48-bit sequence number or the 16-bit epoch has no value left, and
    /// RFC 6347 §4.1 forbids letting either wrap.
    SequenceExhausted,
    /// A public key is not an uncompressed point on P-256.
    InvalidPublicKey,
    /// An RSA public key is not one this crate verifies with: a modulus
    /// shorter than 2048 bits or longer than 8192, even, or not above its
    /// exponent, or an exponent out of range.
    UnacceptableRsaKey,
    /// A signature did not verify, is not a DER `Ecdsa-Sig-Value`, or is not
    /// exactly as long as the RSA modulus it claims to be under.
    BadSignature,
    /// Signing failed inside the primitive.
    SigningFailed,
    /// The caller's random source kept producing values no P-256 key can be
    /// made from. One such draw in 2^32 is expected; many in a row is a broken
    /// source.
    RandomRejected,
    /// Keying material was asked of a master secret made without the extended
    /// master secret, which RFC 7627 §5.4 forbids exporting from.
    NoExtendedMasterSecret,
    /// An exporter label collides with a label the TLS PRF uses for itself.
    ReservedLabel,
    /// A certificate fingerprint names a hash function this crate does not
    /// verify with. RFC 8122 §5 forbids MD2 and MD5 outright.
    UnsupportedHash,
    /// A validity date cannot be written: before 1970, after 9999, or a
    /// period that ends before it begins.
    InvalidTime,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "input ends inside a field",
            Self::TrailingData => "bytes left after the end of a structure",
            Self::Length => "length outside the range the field allows",
            Self::IllegalValue => "value not allowed in this field",
            Self::DuplicateExtension => "extension type appears twice",
            Self::TooLarge => "exceeds a size limit",
            Self::NotConnected => "the connection is not established",
            Self::MtuTooSmall => "path MTU leaves no room for handshake data",
            Self::BadRecordMac => "record did not authenticate",
            Self::Replayed => "record sequence number replayed or too old",
            Self::SequenceExhausted => "sequence number or epoch exhausted",
            Self::InvalidPublicKey => "not an uncompressed P-256 point",
            Self::UnacceptableRsaKey => "RSA key of a size or form not accepted",
            Self::BadSignature => "signature did not verify",
            Self::SigningFailed => "signing failed",
            Self::RandomRejected => "random source keeps producing unusable keys",
            Self::NoExtendedMasterSecret => "export refused without the extended master secret",
            Self::ReservedLabel => "exporter label collides with a PRF label",
            Self::UnsupportedHash => "fingerprint hash function not supported",
            Self::InvalidTime => "validity time cannot be encoded",
        })
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant's text, in an exhaustive match: a variant added without
    /// a line here fails to compile, not silently prints nothing.
    fn text(error: Error) -> &'static str {
        match error {
            Error::Truncated => "input ends inside a field",
            Error::TrailingData => "bytes left after the end of a structure",
            Error::Length => "length outside the range the field allows",
            Error::IllegalValue => "value not allowed in this field",
            Error::DuplicateExtension => "extension type appears twice",
            Error::TooLarge => "exceeds a size limit",
            Error::NotConnected => "the connection is not established",
            Error::MtuTooSmall => "path MTU leaves no room for handshake data",
            Error::BadRecordMac => "record did not authenticate",
            Error::Replayed => "record sequence number replayed or too old",
            Error::SequenceExhausted => "sequence number or epoch exhausted",
            Error::InvalidPublicKey => "not an uncompressed P-256 point",
            Error::UnacceptableRsaKey => "RSA key of a size or form not accepted",
            Error::BadSignature => "signature did not verify",
            Error::SigningFailed => "signing failed",
            Error::RandomRejected => "random source keeps producing unusable keys",
            Error::NoExtendedMasterSecret => "export refused without the extended master secret",
            Error::ReservedLabel => "exporter label collides with a PRF label",
            Error::UnsupportedHash => "fingerprint hash function not supported",
            Error::InvalidTime => "validity time cannot be encoded",
        }
    }

    #[test]
    fn every_variant_displays_its_own_text() {
        let every = [
            Error::Truncated,
            Error::TrailingData,
            Error::Length,
            Error::IllegalValue,
            Error::DuplicateExtension,
            Error::TooLarge,
            Error::NotConnected,
            Error::MtuTooSmall,
            Error::BadRecordMac,
            Error::Replayed,
            Error::SequenceExhausted,
            Error::InvalidPublicKey,
            Error::UnacceptableRsaKey,
            Error::BadSignature,
            Error::SigningFailed,
            Error::RandomRejected,
            Error::NoExtendedMasterSecret,
            Error::ReservedLabel,
            Error::UnsupportedHash,
            Error::InvalidTime,
        ];
        for error in every {
            assert_eq!(error.to_string(), text(error), "{error:?}");
        }
        // distinct text for distinct variants, so a log line says which rule broke
        let mut texts: Vec<&str> = every.into_iter().map(text).collect();
        texts.sort_unstable();
        texts.dedup();
        assert_eq!(texts.len(), every.len());
    }
}
