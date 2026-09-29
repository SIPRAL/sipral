// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The authentication service of RFC 8224 §5: claims in, a signed Identity
//! header field value out.

use std::fmt;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

use crate::MAX_IDENTITY_LEN;
use crate::base64;
use crate::identity::{Identity, Token, is_absolute_uri};
use crate::passport::{ALG, Claims, PPT_SHAKEN, header_value};

/// Why a PASSporT could not be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The private key is not a P-256 scalar: zero, or not below the group
    /// order.
    InvalidKey,
    /// The certificate URI is not an absolute URI.
    InvalidUri,
    /// The claims name no destination (RFC 8225 §5.2.1 requires one).
    EmptyDest,
    /// The header field would be longer than [`MAX_IDENTITY_LEN`].
    TooLong,
    /// The signature primitive refused, which a valid key never makes it do.
    Signing,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SignError::InvalidKey => "not a P-256 private key",
            SignError::InvalidUri => "the certificate URI is not an absolute URI",
            SignError::EmptyDest => "no destination",
            SignError::TooLong => "the Identity header field would be too long",
            SignError::Signing => "signing failed",
        })
    }
}

impl std::error::Error for SignError {}

/// Signs PASSporTs with one P-256 key, for one certificate.
pub struct Signer {
    key: SigningKey,
    x5u: String,
}

impl Signer {
    /// A signer holding the private key `scalar` (32 octets, big-endian)
    /// whose certificate chain is published at `x5u`.
    ///
    /// # Errors
    ///
    /// [`SignError::InvalidKey`] or [`SignError::InvalidUri`].
    pub fn new(scalar: &[u8; 32], x5u: &str) -> Result<Self, SignError> {
        let key = SigningKey::from_slice(scalar).map_err(|_| SignError::InvalidKey)?;
        if !is_absolute_uri(x5u) {
            return Err(SignError::InvalidUri);
        }
        Ok(Signer {
            key,
            x5u: x5u.to_owned(),
        })
    }

    /// The public key, as the uncompressed point of SEC 1 §2.3.3: what the
    /// certificate at `x5u` must hold.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// The PASSporT for `claims` in the JWS compact serialisation (RFC 7515
    /// §7.1), header and claims in the deterministic form of RFC 8225 §9,
    /// with `ppt: "shaken"` when [`Claims::shaken`] is set.
    ///
    /// The ECDSA nonce is derived from the key and the message as RFC 6979
    /// describes, so signing draws no randomness.
    ///
    /// # Errors
    ///
    /// [`SignError::EmptyDest`], or [`SignError::Signing`].
    pub fn passport(&self, claims: &Claims) -> Result<String, SignError> {
        let (header, payload, signature) = self.segments(claims)?;
        Ok(format!("{header}.{payload}.{signature}"))
    }

    /// The Identity header field value carrying the full PASSporT: the
    /// signed token, `info` with the certificate URI, `alg`, and `ppt` for a
    /// SHAKEN PASSporT.
    ///
    /// # Errors
    ///
    /// [`SignError::EmptyDest`], [`SignError::TooLong`], or
    /// [`SignError::Signing`].
    pub fn identity(&self, claims: &Claims) -> Result<String, SignError> {
        let (header, claims_segment, signature) = self.segments(claims)?;
        self.header_field(
            Token::Full {
                header,
                claims: claims_segment,
                signature,
            },
            claims,
        )
    }

    /// The Identity header field value carrying the compact form of RFC
    /// 8225 §7: the signature alone, for a verifier that rebuilds header and
    /// claims from the request.
    ///
    /// # Errors
    ///
    /// [`SignError::EmptyDest`], [`SignError::TooLong`], or
    /// [`SignError::Signing`].
    pub fn identity_compact(&self, claims: &Claims) -> Result<String, SignError> {
        let (_, _, signature) = self.segments(claims)?;
        self.header_field(Token::Compact { signature }, claims)
    }

    fn header_field(&self, token: Token, claims: &Claims) -> Result<String, SignError> {
        let identity = Identity {
            token,
            info: self.x5u.clone(),
            alg: Some(ALG.to_owned()),
            ppt: claims.shaken.map(|_| PPT_SHAKEN.to_owned()),
        }
        .to_string();
        if identity.len() > MAX_IDENTITY_LEN {
            return Err(SignError::TooLong);
        }
        Ok(identity)
    }

    fn segments(&self, claims: &Claims) -> Result<(String, String, String), SignError> {
        if claims.dest.is_empty() {
            return Err(SignError::EmptyDest);
        }
        let shaken = claims.shaken.is_some();
        let header = base64::encode_url(header_value(&self.x5u, shaken).canonical().as_bytes());
        let payload = base64::encode_url(claims.value(shaken).canonical().as_bytes());
        let signature: Signature = self
            .key
            .try_sign(format!("{header}.{payload}").as_bytes())
            .map_err(|_| SignError::Signing)?;
        let signature = base64::encode_url(&signature.to_bytes());
        Ok((header, payload, signature))
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("x5u", &self.x5u)
            .finish_non_exhaustive()
    }
}
