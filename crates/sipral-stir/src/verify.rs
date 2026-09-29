// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The verification service of RFC 8224 §6.2, in two steps with the fetch
//! between them left to the application.
//!
//! [`Verifier::start`] reads the Identity header field and the PASSporT in
//! it and says which certificate it needs ([`Pending::certificate_url`]).
//! The application fetches it, from a cache or over HTTPS, and hands what it
//! got to [`Pending::verify`] together with its trust anchors and the time;
//! or, if it got nothing, calls [`Pending::unavailable`]. Either way the
//! result is a [`Verdict`].

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier as _;

use crate::base64;
use crate::cert::{self, TrustAnchors};
use crate::identity::{Identity, Token};
use crate::passport::{ALG, Claims, Header, PPT_SHAKEN, header_value};
use crate::verdict::{Failure, InfoProblem, Malformed, Verdict, Verified};

/// How far `iat` may be from the time of verification, in seconds, unless
/// configured otherwise: the sixty seconds RFC 8224 §6.2 (Step 4)
/// recommends.
pub const DEFAULT_FRESHNESS: u64 = 60;

/// A verifier's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// How far `iat` may be from the time of verification, either way, in
    /// seconds, before the request is stale.
    pub freshness: u64,
    /// Whether a service provider code in the TNAuthList covers any
    /// originating number. That is what a SHAKEN certificate carries (its
    /// TNAuthList names the provider, not the numbers), so it is on by
    /// default; off, only a number or a range naming the originating number
    /// gives a certificate authority over it.
    pub accept_service_provider_codes: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            freshness: DEFAULT_FRESHNESS,
            accept_service_provider_codes: true,
        }
    }
}

/// Verifies Identity header fields under one [`Config`].
#[derive(Debug, Clone, Default)]
pub struct Verifier {
    config: Config,
}

impl Verifier {
    /// A verifier with this policy.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Verifier { config }
    }

    /// Read one Identity header field value, up to the point where the
    /// certificate is needed.
    ///
    /// `from_request` are the claims as the request itself states them: the
    /// originating and destination numbers from its From and To (or
    /// P-Asserted-Identity and Request-URI) as RFC 8224 §8.3 canonicalises
    /// them, the time from its Date header field, and, for a `shaken`
    /// PASSporT, `attest` and `origid` from wherever the deployment carries
    /// them. They are needed for the compact form (RFC 8225 §7), whose
    /// header and claims are rebuilt from them; a full form carries its own,
    /// and `from_request` is not looked at. Comparing a full form's claims
    /// with the request is the application's, with [`Verified::orig`] and
    /// [`Verified::dest`] in hand.
    ///
    /// # Errors
    ///
    /// The [`Failure`] that ends verification before any certificate is
    /// needed.
    pub fn start(&self, identity: &str, from_request: Option<&Claims>) -> Result<Pending, Failure> {
        let identity = Identity::parse(identity)?;
        let (signing_input, claims) = match &identity.token {
            Token::Full { header, claims, .. } => full(&identity, header, claims)?,
            Token::Compact { .. } => compact(&identity, from_request)?,
        };
        let signature = match &identity.token {
            Token::Full { signature, .. } | Token::Compact { signature } => signature,
        };
        let signature = base64::decode_url(signature.as_bytes())
            .map_err(|_| Failure::Malformed(Malformed::Encoding))?;
        // RFC 7518 §3.4: R and S, 32 octets each, not a DER sequence
        if signature.len() != 64 {
            return Err(Failure::Malformed(Malformed::Signature));
        }
        let signature = Signature::from_slice(&signature).map_err(|_| Failure::BadSignature)?;
        Ok(Pending {
            config: self.config,
            x5u: identity.info,
            signing_input,
            signature,
            claims,
        })
    }
}

fn decode_json(segment: &str) -> Result<Vec<u8>, Failure> {
    base64::decode_url(segment.as_bytes()).map_err(|_| Failure::Malformed(Malformed::Encoding))
}

fn full(identity: &Identity, header: &str, claims: &str) -> Result<(Vec<u8>, Claims), Failure> {
    // RFC 8224 §6.2, Step 1, before anything else: a `ppt` parameter this
    // verifier does not support means the header field is ignored, whatever
    // the PASSporT inside it says
    if identity.ppt.as_deref().is_some_and(|ppt| ppt != PPT_SHAKEN) {
        return Err(Failure::UnsupportedPpt);
    }
    let parsed = Header::from_json(&decode_json(header)?)?;
    if identity.alg.as_deref().is_some_and(|alg| alg != ALG) {
        return Err(Failure::Malformed(Malformed::AlgMismatch));
    }
    match (identity.ppt.as_deref(), parsed.shaken) {
        (None, _) | (Some(PPT_SHAKEN), true) => {}
        _ => return Err(Failure::Malformed(Malformed::PptMismatch)),
    }
    if parsed.x5u.as_ref().is_some_and(|x5u| *x5u != identity.info) {
        return Err(Failure::BadInfo(InfoProblem::Mismatch));
    }
    let claims_value = Claims::from_json(&decode_json(claims)?, parsed.shaken)?;
    Ok((format!("{header}.{claims}").into_bytes(), claims_value))
}

fn compact(
    identity: &Identity,
    from_request: Option<&Claims>,
) -> Result<(Vec<u8>, Claims), Failure> {
    let without = Failure::Malformed(Malformed::CompactWithoutClaims);
    let claims = from_request.ok_or(without)?;
    if identity.alg.as_deref().is_some_and(|alg| alg != ALG) {
        return Err(Failure::UnsupportedAlgorithm);
    }
    let shaken = match identity.ppt.as_deref() {
        None => false,
        Some(PPT_SHAKEN) => true,
        Some(_) => return Err(Failure::UnsupportedPpt),
    };
    if shaken && claims.shaken.is_none() {
        return Err(without);
    }
    if claims.dest.is_empty() {
        return Err(Failure::Malformed(Malformed::Claims));
    }
    let header = header_value(&identity.info, shaken).canonical();
    let payload = claims.value(shaken).canonical();
    let signing_input = format!(
        "{}.{}",
        base64::encode_url(header.as_bytes()),
        base64::encode_url(payload.as_bytes())
    );
    let mut claims = claims.clone();
    if !shaken {
        claims.shaken = None;
    }
    Ok((signing_input.into_bytes(), claims))
}

/// A PASSporT read and waiting for its certificate.
#[derive(Debug, Clone)]
pub struct Pending {
    config: Config,
    x5u: String,
    signing_input: Vec<u8>,
    signature: Signature,
    claims: Claims,
}

impl Pending {
    /// The URI to fetch the signer's certificate chain from: the `info`
    /// parameter.
    #[must_use]
    pub fn certificate_url(&self) -> &str {
        &self.x5u
    }

    /// The claims the signature covers, not yet verified.
    #[must_use]
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// The verdict for a certificate the application could not fetch.
    #[must_use]
    pub fn unavailable(&self) -> Verdict {
        Verdict::Invalid(Failure::BadInfo(InfoProblem::Unavailable))
    }

    /// Finish, with the chain fetched from [`Pending::certificate_url`] —
    /// PEM or DER, the signing certificate first — the application's trust
    /// anchors, and `now` in seconds since the Unix epoch, which should be
    /// when the request arrived.
    ///
    /// Freshness is checked first, then the chain, then the signature, then
    /// the TNAuthList's authority over the originating number.
    #[must_use]
    pub fn verify(&self, chain: &[u8], anchors: &TrustAnchors, now: u64) -> Verdict {
        match self.check(chain, anchors, now) {
            Ok(verified) => Verdict::Valid(verified),
            Err(failure) => Verdict::Invalid(failure),
        }
    }

    fn check(&self, chain: &[u8], anchors: &TrustAnchors, now: u64) -> Result<Verified, Failure> {
        let iat = self.claims.iat;
        if now.abs_diff(iat) > self.config.freshness {
            return Err(Failure::Stale { iat, now });
        }
        let leaf = cert::validate(chain, anchors, now)?;
        leaf.key
            .verify(&self.signing_input, &self.signature)
            .map_err(|_| Failure::BadSignature)?;
        let coverage = leaf
            .tn_auth_list
            .and_then(|list| {
                list.covers(&self.claims.orig, self.config.accept_service_provider_codes)
            })
            .ok_or(Failure::TnNotCovered)?;
        Ok(Verified {
            orig: self.claims.orig.clone(),
            dest: self.claims.dest.clone(),
            iat,
            attest: self.claims.shaken.map(|shaken| shaken.attest),
            origid: self.claims.shaken.map(|shaken| shaken.origid),
            x5u: self.x5u.clone(),
            coverage,
        })
    }
}
