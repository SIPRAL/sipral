// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A TLS server certificate an account trusts by its SHA-256 fingerprint
//! (ABI 0.34).
//!
//! TLS is the application's (`docs/22-tls.md`): the platform's library runs
//! the handshake, and this library never sees it. So a pin is a value the
//! account carries — `sipral_account_config_t::tls_pin_sha256` — and a check
//! the application's certificate verifier makes, with the DER bytes of the
//! leaf certificate the server presented: [`sipral_account_check_certificate`].
//! With a pin, the fingerprint is the whole verdict. No chain, trust anchor or
//! host name is consulted, and an expired certificate that matches is accepted
//! and said to be expired, for the reasons `docs/22-tls.md` gives.

use crate::abi::record;
use crate::error::{entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{handle_failed, with_stack};
use crate::status::SipralStatus;
use crate::text::bytes;
use crate::versioned::{Versioned, read_versioned, write_versioned};

record! {
    /// What [`sipral_account_check_certificate`] found: whether the account's
    /// pin decided, and what the certificate's dates say.
    ///
    /// Set `size` to `sizeof(sipral_pinned_certificate_t)` before the call.
    #[derive(Clone, Copy)]
    pub struct SipralPinnedCertificate {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The certificate's `notBefore`, in seconds since 1 January 1970,
        /// or zero when its DER could not be read that far.
        pub not_before: u64,
        /// Its `notAfter`, the same way.
        pub not_after: u64,
        /// One when the account pins a certificate and this is it: accept
        /// the handshake, whoever signed it. Zero when the account pins
        /// none: the platform's own checks apply, as they would without
        /// this call.
        pub pinned: u32,
        /// One when `unix_seconds` is past `not_after`. Accepted all the
        /// same: its dates were written by the holder of the pinned key, and
        /// a PBX whose self-signed certificate lapsed would otherwise go
        /// silent. Worth a warning.
        pub expired: u32,
        /// One when `unix_seconds` is before `not_before`: a clock set wrong,
        /// or a certificate minted with a future date. Accepted too.
        pub not_yet_valid: u32,
        /// Zero.
        pub reserved: u32,
    }
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralPinnedCertificate {
    const NAME: &'static str = "sipral_pinned_certificate";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralPinnedCertificate, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

entry! {
    /// Check the certificate a TLS server presented against the one the
    /// account pins, from inside the application's certificate verifier.
    ///
    /// `certificate` is the DER encoding of the leaf, the first certificate
    /// the server sent, and `unix_seconds` the wall clock, which only the
    /// dates reported in `out_pinned` are read against. The fingerprint
    /// is SHA-256 over those exact bytes, compared in constant time.
    ///
    /// `SIPRAL_STATUS_OK` with `pinned` set: the certificate is the pinned
    /// one, and the handshake is to be accepted whatever its chain, its name
    /// or its dates. `SIPRAL_STATUS_CERTIFICATE_REFUSED`: the account pins a
    /// certificate and this is another; refuse the handshake, and nothing is
    /// written. `SIPRAL_STATUS_OK` with `pinned` zero: the account pins
    /// nothing, and the platform's own checks decide.
    ///
    /// # Safety
    ///
    /// `certificate` must be readable for `certificate_len` bytes, and
    /// `out_pinned` must point at a `sipral_pinned_certificate_t` whose
    /// `size` member says how long it is.
    fn sipral_account_check_certificate(
        stack: SipralHandle,
        account: SipralHandle,
        certificate: *const u8,
        certificate_len: usize,
        unix_seconds: u64,
        out_pinned: *mut SipralPinnedCertificate,
    ) {
        let mut out = unsafe { read_versioned(out_pinned) }?;
        let Some(leaf) = (unsafe { bytes(certificate, certificate_len, "certificate") })? else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "certificate is required and was not given",
            ));
        };
        let pin = with_stack(stack, |state| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            Ok(state
                .agent
                .account(id)
                .and_then(|config| config.pinned_certificate().copied()))
        })?;
        out.not_before = 0;
        out.not_after = 0;
        out.pinned = 0;
        out.expired = 0;
        out.not_yet_valid = 0;
        out.reserved = 0;
        if let Some(pin) = pin {
            let Ok(checked) = pin.check(leaf, unix_seconds) else {
                return Err(fail(
                    SipralStatus::CertificateRefused,
                    "the server's certificate is not the one this account pins",
                ));
            };
            out.not_before = checked.not_before.unwrap_or(0);
            out.not_after = checked.not_after.unwrap_or(0);
            out.pinned = 1;
            out.expired = u32::from(checked.expired);
            out.not_yet_valid = u32::from(checked.not_yet_valid);
        }
        unsafe { write_versioned(out_pinned, out) }
    }
}

#[cfg(test)]
mod tests {
    use super::{SipralPinnedCertificate, sipral_account_check_certificate};
    use crate::account::sipral_account_add;
    use crate::account::tests::account_config;
    use crate::call::tests::account_on;
    use crate::error::last_error_text;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::{Observed, stack};
    use crate::status::SipralStatus;
    use sipral_ua::CertificatePin;
    use std::mem::size_of;
    use std::ptr;

    /// Not a certificate a TLS library would take, and it does not need to
    /// be: the pin is over the bytes, whatever they are. Its dates are not
    /// readable, so they come back zero.
    const LEAF: &[u8] = b"\x30\x03\x02\x01\x07 a certificate the PBX signed itself";
    const OTHER: &[u8] = b"\x30\x03\x02\x01\x07 another certificate for the same name";

    fn out() -> SipralPinnedCertificate {
        SipralPinnedCertificate {
            size: size_of::<SipralPinnedCertificate>(),
            not_before: u64::MAX,
            not_after: u64::MAX,
            pinned: u32::MAX,
            expired: u32::MAX,
            not_yet_valid: u32::MAX,
            reserved: u32::MAX,
        }
    }

    fn pinned_account(handle: SipralHandle, pin: &str) -> (SipralStatus, SipralHandle) {
        let mut config = account_config();
        config.tls_pin_sha256 = pin.as_ptr().cast();
        config.tls_pin_sha256_len = pin.len();
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(handle, &raw const config, &raw mut account) };
        (status, account)
    }

    fn check(
        handle: SipralHandle,
        account: SipralHandle,
        leaf: &[u8],
        out: &mut SipralPinnedCertificate,
    ) -> SipralStatus {
        unsafe {
            sipral_account_check_certificate(
                handle,
                account,
                leaf.as_ptr(),
                leaf.len(),
                1_790_000_000,
                out,
            )
        }
    }

    fn colon_hex(digest: &[u8; 32]) -> String {
        digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    #[test]
    fn the_pinned_certificate_is_accepted_and_another_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let written = format!("SHA256={}", colon_hex(CertificatePin::of(LEAF).sha256()));
        let (status, account) = pinned_account(handle, &written);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        let mut matched = out();
        assert_eq!(check(handle, account, LEAF, &mut matched), SipralStatus::Ok);
        assert_eq!(matched.pinned, 1);
        assert_eq!(
            (matched.not_before, matched.not_after),
            (0, 0),
            "no dates read"
        );
        assert_eq!((matched.expired, matched.not_yet_valid), (0, 0));

        let mut refused = out();
        assert_eq!(
            check(handle, account, OTHER, &mut refused),
            SipralStatus::CertificateRefused
        );
        assert_eq!(refused.pinned, u32::MAX, "nothing is written on a refusal");
    }

    /// What `openssl x509 -fingerprint -sha256` prints, 3.x and 1.1, and
    /// the rest of the forms every layer reads alike, each pinning the same
    /// certificate across the boundary.
    #[test]
    fn every_printed_form_of_the_fingerprint_pins_the_certificate() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let colons = colon_hex(CertificatePin::of(LEAF).sha256());
        let bare = colons.replace(':', "");
        for written in [
            format!("sha256 Fingerprint={colons}"),
            format!("SHA256 Fingerprint={colons}"),
            format!("sha-256 {colons}"),
            format!("SHA256={bare}"),
            colons.to_ascii_lowercase(),
            colons.replace(':', " "),
        ] {
            let (status, account) = pinned_account(handle, &written);
            assert_eq!(status, SipralStatus::Ok, "{written}: {}", last_error_text());
            let mut matched = out();
            assert_eq!(
                check(handle, account, LEAF, &mut matched),
                SipralStatus::Ok,
                "{written}"
            );
            assert_eq!(matched.pinned, 1, "{written}");
        }
        let (status, _) = pinned_account(handle, &format!("SHA1 Fingerprint={colons}"));
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn an_account_that_pins_nothing_leaves_the_verdict_to_the_platform() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        let mut said = out();
        assert_eq!(check(handle, account, OTHER, &mut said), SipralStatus::Ok);
        assert_eq!(said.pinned, 0);
        assert_eq!(said.size, size_of::<SipralPinnedCertificate>());
    }

    #[test]
    fn a_pin_that_is_not_a_sha256_fingerprint_is_refused_when_the_account_is_added() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        for written in ["AB:CD", "sha-1 00", &"0".repeat(63)] {
            let (status, _) = pinned_account(handle, written);
            assert_eq!(status, SipralStatus::InvalidArgument, "{written}");
            assert!(
                last_error_text().contains("tls_pin_sha256"),
                "{}",
                last_error_text()
            );
        }
    }

    #[test]
    fn a_missing_certificate_or_result_is_a_bad_argument() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        let mut said = out();
        let status = unsafe {
            sipral_account_check_certificate(handle, account, ptr::null(), 0, 0, &raw mut said)
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        let status = unsafe {
            sipral_account_check_certificate(
                handle,
                account,
                LEAF.as_ptr(),
                LEAF.len(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }
}
