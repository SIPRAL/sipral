// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a verification comes to: the caller identity it vouches for, or the
//! one reason it does not, with the SIP response RFC 8224 §6.2.2 prescribes
//! for that reason and the `verstat` value (3GPP TS 24.229) a verifier puts
//! on the identity it hands on.

use std::fmt;

use crate::passport::{Attest, Dest, OrigId, Tn};
use crate::tnauthlist::Coverage;

/// The outcome of verifying one Identity header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The signature is good, the certificate chains to a trust anchor, and
    /// the certificate has authority over the calling number.
    Valid(Verified),
    /// It is not, for this reason.
    Invalid(Failure),
}

impl Verdict {
    /// The verdict for a request that carries no Identity header field at
    /// all, which a verifier whose policy requires one answers with 428.
    #[must_use]
    pub fn missing() -> Self {
        Verdict::Invalid(Failure::MissingIdentity)
    }

    /// What to write in the `verstat` parameter of the caller's identity.
    #[must_use]
    pub fn verstat(&self) -> Verstat {
        match self {
            Verdict::Valid(_) => Verstat::TnValidationPassed,
            Verdict::Invalid(failure) => failure.verstat(),
        }
    }

    /// The response to reject the request with, when the policy is to
    /// reject a request that fails: `None` for a valid one.
    #[must_use]
    pub fn sip_response(&self) -> Option<SipResponse> {
        match self {
            Verdict::Valid(_) => None,
            Verdict::Invalid(failure) => Some(failure.sip_response()),
        }
    }
}

/// What a valid PASSporT says, and on what authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The originating number, as signed.
    pub orig: Tn,
    /// The destinations, as signed.
    pub dest: Dest,
    /// When it was signed, in seconds since the Unix epoch.
    pub iat: u64,
    /// The attestation level of a SHAKEN PASSporT (RFC 8588 §4); `None` for
    /// a PASSporT without the `shaken` extension.
    pub attest: Option<Attest>,
    /// The origination identifier of a SHAKEN PASSporT (RFC 8588 §5).
    pub origid: Option<OrigId>,
    /// Where the certificate came from.
    pub x5u: String,
    /// Which TNAuthList entry gave the certificate its authority over
    /// [`Verified::orig`].
    pub coverage: Coverage,
}

/// Why an Identity header field does not vouch for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The request carries no Identity header field.
    MissingIdentity,
    /// The header field or the PASSporT in it is not well formed.
    Malformed(Malformed),
    /// The PASSporT is signed with an algorithm other than ES256, the only
    /// one this crate verifies (RFC 8225 §4.2 makes it mandatory to
    /// support).
    UnsupportedAlgorithm,
    /// The PASSporT names a `ppt` extension other than `shaken`.
    UnsupportedPpt,
    /// `iat` is further from the time of verification than the freshness
    /// window allows (RFC 8224 §6.2.1).
    Stale {
        /// When the PASSporT says it was signed.
        iat: u64,
        /// The time it was verified at.
        now: u64,
    },
    /// The certificate the `info` parameter points at cannot be had or
    /// cannot be read.
    BadInfo(InfoProblem),
    /// The chain does not lead to any of the trust anchors given.
    Untrusted,
    /// A certificate's validity period ended before now. `depth` is its
    /// place in the path, the signing certificate being 0.
    Expired {
        /// Its place in the path.
        depth: usize,
    },
    /// A certificate's validity period has not begun yet.
    NotYetValid {
        /// Its place in the path.
        depth: usize,
    },
    /// The chain leads to a trust anchor, but breaks a rule on the way.
    InvalidChain(ChainProblem),
    /// The PASSporT's signature does not verify under the certificate's key.
    BadSignature,
    /// The certificate has no authority over the originating number: its
    /// TNAuthList (RFC 8226 §9) is missing or covers other numbers.
    TnNotCovered,
}

impl Failure {
    /// The response RFC 8224 §6.2.2 prescribes for this failure.
    #[must_use]
    pub fn sip_response(&self) -> SipResponse {
        match self {
            Failure::Stale { .. } => SipResponse::STALE_DATE,
            Failure::MissingIdentity => SipResponse::USE_IDENTITY_HEADER,
            Failure::BadInfo(_) => SipResponse::BAD_IDENTITY_INFO,
            Failure::UnsupportedAlgorithm
            | Failure::Untrusted
            | Failure::Expired { .. }
            | Failure::NotYetValid { .. }
            | Failure::InvalidChain(_) => SipResponse::UNSUPPORTED_CREDENTIAL,
            Failure::Malformed(_)
            | Failure::UnsupportedPpt
            | Failure::BadSignature
            | Failure::TnNotCovered => SipResponse::INVALID_IDENTITY_HEADER,
        }
    }

    /// The `verstat` value for a request that fails this way: no validation
    /// when there was nothing this verifier could validate, failed otherwise.
    #[must_use]
    pub fn verstat(&self) -> Verstat {
        match self {
            Failure::MissingIdentity | Failure::UnsupportedPpt => Verstat::NoTnValidation,
            _ => Verstat::TnValidationFailed,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::MissingIdentity => f.write_str("no Identity header field"),
            Failure::Malformed(what) => write!(f, "malformed Identity header field: {what}"),
            Failure::UnsupportedAlgorithm => f.write_str("the PASSporT is not signed with ES256"),
            Failure::UnsupportedPpt => f.write_str("unsupported PASSporT extension"),
            Failure::Stale { iat, now } => write!(f, "iat {iat} is stale at {now}"),
            Failure::BadInfo(what) => write!(f, "bad identity info: {what}"),
            Failure::Untrusted => f.write_str("the certificate chains to no trust anchor"),
            Failure::Expired { depth } => write!(f, "the certificate at depth {depth} expired"),
            Failure::NotYetValid { depth } => {
                write!(f, "the certificate at depth {depth} is not valid yet")
            }
            Failure::InvalidChain(what) => write!(f, "invalid certificate chain: {what}"),
            Failure::BadSignature => f.write_str("the PASSporT signature does not verify"),
            Failure::TnNotCovered => {
                f.write_str("the certificate has no authority over the originating number")
            }
        }
    }
}

impl std::error::Error for Failure {}

/// How an Identity header field or its PASSporT is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// Longer than [`crate::MAX_IDENTITY_LEN`].
    TooLong,
    /// Not the grammar of RFC 8224 §4.1.
    Syntax,
    /// A parameter appears twice.
    DuplicateParameter,
    /// A PASSporT segment is not base64url (RFC 7515 §2).
    Encoding,
    /// The PASSporT header or claims are not a JSON object.
    Json,
    /// The PASSporT header lacks `typ: "passport"`, or its `alg` is not a
    /// string (RFC 8225 §4), or it is a SHAKEN header without `x5u`.
    Header,
    /// A claim is missing or ill-formed: `iat`, `orig.tn` and `dest` always
    /// (RFC 8225 §5), `attest` and `origid` for `shaken` (RFC 8588 §4, §5).
    Claims,
    /// The header marks an extension critical (RFC 7515 §4.1.11), and none
    /// is understood here.
    Critical,
    /// The `alg` parameter disagrees with the PASSporT's own.
    AlgMismatch,
    /// The `ppt` parameter disagrees with the PASSporT's own.
    PptMismatch,
    /// The signature is not the 64 octets of an ES256 JWS signature (RFC
    /// 7518 §3.4).
    Signature,
    /// A compact form (RFC 8225 §7) arrived without the claims to rebuild it
    /// from, or with `ppt=shaken` and no `attest` and `origid` among them.
    CompactWithoutClaims,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Malformed::TooLong => "too long",
            Malformed::Syntax => "syntax",
            Malformed::DuplicateParameter => "a parameter appears twice",
            Malformed::Encoding => "not base64url",
            Malformed::Json => "not a JSON object",
            Malformed::Header => "the PASSporT header",
            Malformed::Claims => "the PASSporT claims",
            Malformed::Critical => "a critical header parameter",
            Malformed::AlgMismatch => "alg disagrees with the PASSporT",
            Malformed::PptMismatch => "ppt disagrees with the PASSporT",
            Malformed::Signature => "not an ES256 signature",
            Malformed::CompactWithoutClaims => "a compact form with nothing to rebuild it from",
        })
    }
}

/// What is wrong with the certificate the `info` parameter points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoProblem {
    /// There is no `info` parameter.
    Missing,
    /// It is not an absolute URI in angle brackets.
    InvalidUri,
    /// The PASSporT's `x5u` names a different URI.
    Mismatch,
    /// The application could not fetch it.
    Unavailable,
    /// What was fetched holds no certificate.
    Empty,
    /// What was fetched, or one certificate in it, is larger than the limits
    /// allow.
    TooLarge,
    /// It holds more than [`crate::MAX_CHAIN_CERTIFICATES`] certificates.
    TooManyCertificates,
    /// It is neither PEM nor DER certificates, or a certificate in it does
    /// not parse.
    Unreadable,
}

impl fmt::Display for InfoProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InfoProblem::Missing => "no info parameter",
            InfoProblem::InvalidUri => "info is not an absolute URI",
            InfoProblem::Mismatch => "x5u and info disagree",
            InfoProblem::Unavailable => "the certificate could not be fetched",
            InfoProblem::Empty => "no certificate",
            InfoProblem::TooLarge => "too large",
            InfoProblem::TooManyCertificates => "too many certificates",
            InfoProblem::Unreadable => "unreadable certificate",
        })
    }
}

/// A rule of certification path validation the chain breaks. `depth` counts
/// from the signing certificate, which is 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainProblem {
    /// A certificate that issues another is not a CA: no basic constraints
    /// extension with `cA` set (RFC 5280 §4.2.1.9).
    NotCa {
        /// Its place in the path.
        depth: usize,
    },
    /// A key usage extension that leaves out what the certificate is used
    /// for: `keyCertSign` on an issuer, `digitalSignature` on the signing
    /// certificate (RFC 5280 §4.2.1.3).
    KeyUsage {
        /// Its place in the path.
        depth: usize,
    },
    /// The path is longer than [`crate::MAX_CHAIN_CERTIFICATES`], or longer
    /// than an issuer's `pathLenConstraint` allows below it.
    PathLength {
        /// The certificate whose constraint is broken, or the limit's.
        depth: usize,
    },
    /// A signature algorithm other than ECDSA with SHA-256 over P-256, a key
    /// other than P-256, or a certificate whose two signature algorithm
    /// fields disagree (RFC 5280 §4.1.1.2).
    Algorithm {
        /// Its place in the path.
        depth: usize,
    },
    /// A certificate's signature does not verify under its issuer's key.
    Signature {
        /// Its place in the path.
        depth: usize,
    },
    /// A critical extension this crate does not process (RFC 5280 §4.2).
    CriticalExtension {
        /// Its place in the path.
        depth: usize,
    },
    /// The same extension twice in one certificate (RFC 5280 §4.2).
    DuplicateExtension {
        /// Its place in the path.
        depth: usize,
    },
    /// An extension this crate processes does not parse: basic constraints,
    /// key usage, or the TNAuthList of RFC 8226 §9.
    BadExtension {
        /// Its place in the path.
        depth: usize,
    },
}

impl fmt::Display for ChainProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (what, depth) = match self {
            ChainProblem::NotCa { depth } => ("an issuer that is not a CA", depth),
            ChainProblem::KeyUsage { depth } => ("a key usage that forbids it", depth),
            ChainProblem::PathLength { depth } => ("a path too long", depth),
            ChainProblem::Algorithm { depth } => ("an unsupported algorithm", depth),
            ChainProblem::Signature { depth } => ("a signature that does not verify", depth),
            ChainProblem::CriticalExtension { depth } => ("an unknown critical extension", depth),
            ChainProblem::DuplicateExtension { depth } => ("a duplicate extension", depth),
            ChainProblem::BadExtension { depth } => ("an unreadable extension", depth),
        };
        write!(f, "{what} at depth {depth}")
    }
}

/// A SIP final response: its status code and the reason phrase RFC 8224
/// gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SipResponse {
    /// The status code.
    pub code: u16,
    /// The reason phrase.
    pub reason: &'static str,
}

impl SipResponse {
    /// 403: `iat` outside the freshness window (RFC 8224 §6.2.1).
    pub const STALE_DATE: SipResponse = SipResponse {
        code: 403,
        reason: "Stale Date",
    };
    /// 428: the request needs an Identity header field and has none.
    pub const USE_IDENTITY_HEADER: SipResponse = SipResponse {
        code: 428,
        reason: "Use Identity Header",
    };
    /// 436: the `info` URI cannot be dereferenced, or does not yield a
    /// usable certificate.
    pub const BAD_IDENTITY_INFO: SipResponse = SipResponse {
        code: 436,
        reason: "Bad Identity Info",
    };
    /// 437: the credential is not one the verifier supports or trusts.
    pub const UNSUPPORTED_CREDENTIAL: SipResponse = SipResponse {
        code: 437,
        reason: "Unsupported Credential",
    };
    /// 438: the Identity header field is malformed or its signature does not
    /// vouch for the identity.
    pub const INVALID_IDENTITY_HEADER: SipResponse = SipResponse {
        code: 438,
        reason: "Invalid Identity Header",
    };
}

impl fmt::Display for SipResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.reason)
    }
}

/// The verification status a verifier attaches to the caller's identity,
/// as the `verstat` tel URI parameter of 3GPP TS 24.229.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verstat {
    /// `TN-Validation-Passed`.
    TnValidationPassed,
    /// `TN-Validation-Failed`.
    TnValidationFailed,
    /// `No-TN-Validation`.
    NoTnValidation,
}

impl Verstat {
    /// The parameter value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verstat::TnValidationPassed => "TN-Validation-Passed",
            Verstat::TnValidationFailed => "TN-Validation-Failed",
            Verstat::NoTnValidation => "No-TN-Validation",
        }
    }
}

impl fmt::Display for Verstat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_maps_to_its_response() {
        let cases = [
            (Failure::Stale { iat: 0, now: 61 }, 403, "Stale Date"),
            (Failure::MissingIdentity, 428, "Use Identity Header"),
            (
                Failure::BadInfo(InfoProblem::Unavailable),
                436,
                "Bad Identity Info",
            ),
            (
                Failure::BadInfo(InfoProblem::Missing),
                436,
                "Bad Identity Info",
            ),
            (Failure::UnsupportedAlgorithm, 437, "Unsupported Credential"),
            (Failure::Untrusted, 437, "Unsupported Credential"),
            (Failure::Expired { depth: 0 }, 437, "Unsupported Credential"),
            (
                Failure::NotYetValid { depth: 1 },
                437,
                "Unsupported Credential",
            ),
            (
                Failure::InvalidChain(ChainProblem::NotCa { depth: 1 }),
                437,
                "Unsupported Credential",
            ),
            (
                Failure::Malformed(Malformed::Syntax),
                438,
                "Invalid Identity Header",
            ),
            (Failure::UnsupportedPpt, 438, "Invalid Identity Header"),
            (Failure::BadSignature, 438, "Invalid Identity Header"),
            (Failure::TnNotCovered, 438, "Invalid Identity Header"),
        ];
        for (failure, code, reason) in cases {
            let response = failure.sip_response();
            assert_eq!(
                (response.code, response.reason),
                (code, reason),
                "{failure:?}"
            );
            assert_eq!(
                Verdict::Invalid(failure).sip_response(),
                Some(response),
                "{failure:?}"
            );
        }
        assert_eq!(SipResponse::STALE_DATE.to_string(), "403 Stale Date");
    }

    #[test]
    fn verstat_values() {
        assert_eq!(Verdict::missing().verstat().as_str(), "No-TN-Validation");
        assert_eq!(
            Verdict::Invalid(Failure::UnsupportedPpt).verstat(),
            Verstat::NoTnValidation
        );
        assert_eq!(
            Verdict::Invalid(Failure::BadSignature)
                .verstat()
                .to_string(),
            "TN-Validation-Failed"
        );
        assert_eq!(
            Verdict::Invalid(Failure::Stale { iat: 0, now: 100 }).verstat(),
            Verstat::TnValidationFailed
        );
        assert_eq!(Verstat::TnValidationPassed.as_str(), "TN-Validation-Passed");
    }

    #[test]
    fn failures_describe_themselves() {
        assert_eq!(
            Failure::InvalidChain(ChainProblem::PathLength { depth: 3 }).to_string(),
            "invalid certificate chain: a path too long at depth 3"
        );
        assert_eq!(
            Failure::BadInfo(InfoProblem::Mismatch).to_string(),
            "bad identity info: x5u and info disagree"
        );
        assert_eq!(
            Failure::Malformed(Malformed::TooLong).to_string(),
            "malformed Identity header field: too long"
        );
    }
}
