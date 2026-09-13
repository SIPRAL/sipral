// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! X.509, exactly as far as DTLS-SRTP needs it.
//!
//! Neither end of a DTLS-SRTP call trusts a certificate for what it says.
//! RFC 8122 §5 binds a certificate to the call by the fingerprint the
//! signalling carries, and that binding is all that is checked: no chain, no
//! names, no validity dates, no extensions. So this module writes the least a
//! certificate can be ([`Certificate::self_signed`]), reads a peer's only as
//! far as its public key ([`SubjectPublicKeyInfo`]), and computes and compares
//! the fingerprint ([`Fingerprint`]) that is the real check.
//!
//! Written from RFC 5280 §4.1, RFC 5480 §2, RFC 5758 §3.2, RFC 3279 §2.2.3
//! and RFC 8122 §5, with DER as ITU-T X.690 defines it.

mod certificate;
mod der;
mod fingerprint;
mod sha1;
mod time;

pub use certificate::{Certificate, CertificateParams, SubjectPublicKeyInfo};
pub use fingerprint::{Fingerprint, HashFunction};
