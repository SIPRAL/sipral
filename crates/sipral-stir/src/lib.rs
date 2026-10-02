// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! STIR/SHAKEN caller authentication.
//!
//! The signing and verifying ends of RFC 8224's Identity header field, with
//! the PASSporT of RFC 8225, the `shaken` extension of RFC 8588 and the STIR
//! certificates of RFC 8226.
//!
//! # What is here
//!
//! - [`Signer`]: claims, a P-256 private key and the URI of its certificate
//!   in; an Identity header field value out, in the full form or the compact
//!   one.
//! - [`Verifier`]: an Identity header field value in; out, the URI of the
//!   certificate to fetch ([`Pending::certificate_url`]); then the fetched
//!   chain, the trust anchors and the time in, and a [`Verdict`] out: the
//!   attestation level, originating number and origination identifier of a
//!   valid PASSporT, or the one [`Failure`] that stops it, each with the SIP
//!   response of RFC 8224 §6.2.2 ([`Failure::sip_response`]) and the
//!   `verstat` value of 3GPP TS 24.229 ([`Verdict::verstat`]). The
//!   request's Date is held to the same freshness window as `iat`
//!   ([`Pending::dated`]), a [`ReplayCache`] refuses a PASSporT verified
//!   once already ([`Pending::verify_once`]), and the certificate is only
//!   ever asked for over `https` unless [`Config::info_schemes`] says
//!   otherwise.
//! - The parts both are made of, each usable alone: [`passport`] (claims,
//!   header, and the deterministic JSON of RFC 8225 §9), [`identity`] (the
//!   header field's grammar, RFC 8224 §4.1), [`tnauthlist`] (the certificate
//!   extension of RFC 8226 §9), [`TrustAnchors`].
//!
//! # Sans-I/O
//!
//! Nothing here opens a socket, reads a clock or draws a random number. The
//! certificate is fetched by the application, which is where a cache, an
//! HTTP client and its timeouts belong; the time is given; and ECDSA
//! signatures take their nonce from RFC 6979, so signing needs no
//! randomness.
//!
//! # Limits
//!
//! Everything read here may come from an attacker, and all of it is read
//! within fixed bounds, without panicking on any input: an Identity header
//! field of at most [`MAX_IDENTITY_LEN`] octets, a fetched chain of at most
//! [`MAX_CHAIN_LEN`] octets and [`MAX_CHAIN_CERTIFICATES`] certificates, each
//! at most [`MAX_CERTIFICATE_LEN`] octets of DER, and JSON nested at most
//! sixteen deep.
//!
//! No comparison here involves a secret: the one secret this crate holds is
//! a signer's private key, and every operation on it is the constant-time
//! arithmetic of the `p256` crate. What a verifier compares — signatures,
//! names, numbers, URIs — is public, and a timing difference in comparing it
//! tells an attacker nothing the message did not.
//!
//! # What is not checked
//!
//! Some of what a verification service does is policy, and stays with the
//! application:
//!
//! - **Revocation.** No CRL is fetched and no OCSP responder asked; a
//!   revoked certificate verifies until it expires. Revocation, like the
//!   fetching of the certificate itself, is I/O and deployment policy.
//! - **Anything of RFC 5280 path validation beyond what [`cert`] lists**:
//!   certificate policies, policy mappings, name constraints, and the
//!   validity period and constraints of the trust anchor itself.
//! - **Delegation.** A TNAuthList on an issuing certificate is not checked
//!   to include the signing certificate's (RFC 8226 §9 and RFC 9060); only
//!   the signing certificate's own list decides.
//! - **The request.** A full-form PASSporT's `orig` and `dest` are returned
//!   in [`Verified`], and comparing them with the request's From and To (RFC
//!   8224 §6.2) is the application's, with [`Dest::names_number`] and
//!   [`Dest::names_uri`] comparing in the canonical forms of §8.3 and §8.5
//!   ([`canonical_uri`]); so is choosing among several Identity
//!   header fields, and deciding what a verdict does to the call.
//! - **Which algorithms and extensions.** ES256 is the only algorithm and
//!   `shaken` the only `ppt`; RFC 8443's `rph` and RFC 8946's `div`, and
//!   every other extension, are refused as unsupported.
//!
//! Written from RFC 8224, RFC 8225, RFC 8226, RFC 8588, RFC 7515, RFC 7518,
//! RFC 7519, RFC 4648, RFC 7468, RFC 8259, RFC 4122, RFC 5280, RFC 5480 and
//! RFC 5758; see `docs/02-clean-room.md` for why that matters here.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
// tests say what they mean; the no-panic discipline is for the library
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

mod base64;
pub mod cert;
mod der;
pub mod identity;
mod json;
mod key;
pub mod passport;
mod sign;
pub mod tnauthlist;
mod verdict;
mod verify;

#[cfg(feature = "testing")]
pub mod testing;
// a test PKI is test code wherever it is built, and holds to the tests' own
// discipline rather than the library's
#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code
)]
mod testpki;
#[cfg(test)]
mod tests;

pub use cert::{
    AnchorError, MAX_CERTIFICATE_LEN, MAX_CHAIN_CERTIFICATES, MAX_CHAIN_LEN, TrustAnchors,
};
pub use identity::Identity;
pub use passport::{Attest, Claims, Dest, OrigId, Shaken, Tn, canonical_uri};
pub use sign::{SignError, Signer};
pub use tnauthlist::{Coverage, TnAuthList, TnEntry};
pub use verdict::{
    ChainProblem, Failure, InfoProblem, Malformed, SipResponse, Staleness, Verdict, Verified,
    Verstat,
};
pub use verify::{
    Arrival, Config, DEFAULT_FRESHNESS, DEFAULT_INFO_SCHEMES, Pending, ReplayCache, Verifier,
};

/// The longest Identity header field value read or written, in octets.
pub const MAX_IDENTITY_LEN: usize = 8 * 1024;
