// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What this end's own verification service concluded about who is calling
//! (RFC 8224 §6.2), and what an account asks of it.
//!
//! The types are here in every build, so that what a call carries has the
//! same shape whether or not this build can verify anything; the service
//! that fills them in is `crate::stir`, behind the `stir` feature.
//! [`CallerIdentity::verification`](crate::CallerIdentity::verification) is
//! where a call carries its verdict, and
//! [`UaEvent::CallerVerified`](crate::UaEvent::CallerVerified) is where it is
//! announced.

use std::fmt;

/// How an account treats the `Identity` header fields of the calls it
/// receives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StirVerification {
    /// Verify nothing. The calls arrive as they would with no verification
    /// service at all.
    Off,
    /// Verify, and report: the verdict rides on the call and every call is
    /// delivered, whatever it says. What deciding to show a warning, or a
    /// badge, or to send a call to voicemail needs, and nothing more.
    ///
    /// The default, and only in force once the agent has trust anchors to
    /// verify against ([`UserAgent::set_stir`](crate::UserAgent::set_stir)):
    /// without any, nothing is fetched and nothing is verified, because
    /// every verdict would be the same failure.
    #[default]
    Report,
    /// Verify, and refuse a call that does not verify with the response RFC
    /// 8224 §6.2.2 prescribes for why: 428 for none (or only unsupported
    /// ones, "Use Supported PASSporT Format"), 436 for a certificate that
    /// cannot be had, 437 for one this end does not trust, 438 for a
    /// signature that does not hold, 403 "Stale Date" for one too old.
    ///
    /// In force whether or not the agent has trust anchors: an account that
    /// asked to refuse what does not verify refuses it, and with no anchors
    /// nothing verifies.
    Strict,
}

/// What a verification came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerificationOutcome {
    /// A PASSporT signed by a certificate with authority over the calling
    /// number, fresh, and naming the numbers the request does.
    Valid,
    /// One was there and does not hold: [`CallerVerification::failure`]
    /// says why.
    Invalid,
    /// Nothing this end could verify: no `Identity` header field, or only
    /// ones naming a PASSporT extension it does not support (RFC 8224 §6.2,
    /// Step 1).
    Absent,
}

/// The attestation level of a SHAKEN PASSporT (RFC 8588 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Attestation {
    /// Full: the signer knows the caller and that the caller may use the
    /// number.
    A,
    /// Partial: the signer knows the caller, not whether the number is
    /// theirs.
    B,
    /// Gateway: the signer only knows where the call entered its network.
    C,
}

impl Attestation {
    /// The claim value, `A`, `B` or `C`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
        }
    }
}

/// Why a verification did not hold, in the words a caller can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerificationFailure {
    /// No `Identity` header field.
    NoIdentity,
    /// Only `Identity` header fields naming a `ppt` this end does not
    /// support.
    UnsupportedPpt,
    /// The header field or the PASSporT in it is not well formed.
    Malformed,
    /// Signed with an algorithm other than ES256.
    UnsupportedAlgorithm,
    /// `iat` is outside the freshness window.
    Stale,
    /// The certificate could not be fetched, or did not arrive in time.
    CertificateUnavailable,
    /// What the `info` URI yielded is not a certificate chain this end can
    /// read, or the `info` parameter itself is wrong.
    CertificateUnreadable,
    /// The chain leads to no trust anchor.
    Untrusted,
    /// A certificate in the chain has expired, or is not valid yet.
    Expired,
    /// The chain breaks a rule of path validation on the way to its anchor.
    InvalidChain,
    /// The signature does not verify.
    BadSignature,
    /// The certificate has no authority over the calling number (RFC 8226
    /// §9's TNAuthList).
    NumberNotCovered,
    /// The PASSporT's `orig` is not the calling number the request names
    /// (RFC 8224 §6.2, Step 2, and §6.2.4).
    OrigMismatch,
    /// Its `dest` does not name the number the request was sent to.
    DestMismatch,
}

impl fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoIdentity => "no Identity header field",
            Self::UnsupportedPpt => "only unsupported PASSporT extensions",
            Self::Malformed => "a malformed Identity header field",
            Self::UnsupportedAlgorithm => "an algorithm other than ES256",
            Self::Stale => "a stale PASSporT",
            Self::CertificateUnavailable => "the certificate could not be fetched",
            Self::CertificateUnreadable => "the certificate could not be read",
            Self::Untrusted => "a certificate no trust anchor issued",
            Self::Expired => "a certificate outside its validity period",
            Self::InvalidChain => "a certificate chain that breaks path validation",
            Self::BadSignature => "a signature that does not verify",
            Self::NumberNotCovered => "a certificate with no authority over the calling number",
            Self::OrigMismatch => "a PASSporT signed for another calling number",
            Self::DestMismatch => "a PASSporT signed for another called number",
        })
    }
}

/// The verdict of this end's verification service on one incoming call.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallerVerification {
    /// What it came to.
    pub outcome: VerificationOutcome,
    /// Why it did not hold; `None` for a valid one.
    pub failure: Option<VerificationFailure>,
    /// What went wrong, in more detail than [`CallerVerification::failure`]
    /// can carry, for a log. `None` for a valid one.
    pub detail: Option<Box<str>>,
    /// The attestation level a valid SHAKEN PASSporT carried.
    pub attestation: Option<Attestation>,
    /// The originating number a valid PASSporT was signed for, canonical
    /// (RFC 8224 §8.3).
    pub orig: Option<Box<str>>,
    /// The origination identifier of a valid SHAKEN PASSporT (RFC 8588 §5),
    /// as a UUID.
    pub origid: Option<Box<str>>,
    /// Where the certificate came from: the `info` of the header field that
    /// was verified.
    pub certificate_url: Option<Box<str>>,
    /// The response RFC 8224 §6.2.2 prescribes for this failure, status and
    /// reason phrase, whether or not it was sent. `None` for a valid one.
    pub response: Option<(u16, Box<str>)>,
    /// Whether the call was refused with that response, which only an
    /// account set to [`StirVerification::Strict`] does.
    pub refused: bool,
}

impl CallerVerification {
    /// The `verstat` this verdict comes to (3GPP TS 24.229):
    /// `TN-Validation-Passed` for a valid one, `No-TN-Validation` where there
    /// was nothing to validate, `TN-Validation-Failed` otherwise.
    #[must_use]
    pub const fn verstat(&self) -> crate::Verstat {
        match self.outcome {
            VerificationOutcome::Valid => crate::Verstat::Passed,
            VerificationOutcome::Invalid => crate::Verstat::Failed,
            VerificationOutcome::Absent => crate::Verstat::NotValidated,
        }
    }
}
