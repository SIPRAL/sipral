// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Credentials for tests of the crates that sign and verify with this one:
//! a root to trust, a chain to serve at an `x5u`, and the private key of the
//! certificate at the head of that chain, whose TNAuthList (RFC 8226 §9)
//! covers the numbers asked for.
//!
//! Behind the `testing` feature. The keys are fixed scalars, so everything
//! here is public knowledge: it proves the plumbing and nothing about who
//! signed.

use crate::testpki::{self, NOT_AFTER, NOT_BEFORE, Pki};
use crate::tnauthlist::{TnAuthList, TnEntry};

/// What a test signs with and trusts.
#[derive(Clone)]
pub struct Credentials {
    /// The root, as a PEM certificate: the trust anchor.
    pub anchor: String,
    /// The chain an `x5u` serves, as PEM: the signing certificate, then the
    /// intermediate that issued it.
    pub chain: String,
    /// The signing certificate's private key, the 32-octet scalar
    /// [`Signer::new`](crate::Signer::new) takes.
    pub key: [u8; 32],
    /// When every certificate here starts being valid, in seconds since
    /// the Unix epoch.
    pub not_before: u64,
    /// And when each stops.
    pub not_after: u64,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// Credentials whose signing certificate has authority over `numbers`,
/// each a canonical telephone number (RFC 8224 §8.3).
///
/// # Panics
///
/// For a number TNAuthList cannot hold, or none at all: a test's own
/// mistake.
#[must_use]
pub fn credentials(numbers: &[&str]) -> Credentials {
    issued(
        numbers
            .iter()
            .map(|number| TnEntry::One((*number).to_owned()))
            .collect(),
    )
}

/// Credentials whose signing certificate's TNAuthList names the service
/// provider code `code` and no number, as a SHAKEN certificate does.
///
/// # Panics
///
/// For a code TNAuthList cannot hold: a test's own mistake.
#[must_use]
pub fn provider_credentials(code: &str) -> Credentials {
    issued(vec![TnEntry::Spc(code.to_owned())])
}

// a test's own mistake stops the test where it was made
#[allow(clippy::expect_used)]
fn issued(entries: Vec<TnEntry>) -> Credentials {
    let pki = Pki::new();
    let mut leaf = pki.leaf_spec();
    leaf.tn_auth_list = Some(
        TnAuthList::new(entries)
            .expect("entries a TNAuthList can hold")
            .to_der(),
    );
    let leaf = leaf.build(&pki.intermediate_key);
    let key: [u8; 32] = pki.leaf_key.to_bytes().into();
    Credentials {
        anchor: testpki::pem(&pki.root),
        chain: format!("{}{}", testpki::pem(&leaf), testpki::pem(&pki.intermediate)),
        key,
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
    }
}
