// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What ABI this library speaks, and whether a binding can speak it.
//!
//! The ABI has a version of its own, and it is not the crate's. A shared
//! library is loaded by a package that was generated against some header, and
//! the two are shipped separately often enough — a NuGet package next to a
//! native asset from another build, an AAR with a stale `.so` — that the
//! mismatch has to be found at load, with a sentence saying which two versions
//! disagree, rather than as a crash in the first call that reads a member that
//! was not there.

use std::mem::size_of;

use crate::abi::{constants, record};
use crate::error::{entry, fail};
use crate::status::SipralStatus;
use crate::versioned::{Versioned, write_versioned};

constants! {
    /// The ABI's major version. Nothing published against one major works
    /// against another.
    pub const SIPRAL_ABI_VERSION_MAJOR: u32 = 0;

    /// The ABI's minor version, raised by every function or struct member
    /// added.
    pub const SIPRAL_ABI_VERSION_MINOR: u32 = 5;

    /// The ABI's patch version, raised by a fix that changes no declaration.
    pub const SIPRAL_ABI_VERSION_PATCH: u32 = 0;
}

record! {
    /// The version of the ABI this library provides.
    ///
    /// Set `size` to `sizeof(sipral_abi_version_t)` before the call.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SipralAbiVersion {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// Nothing built against another major version will work.
        pub major: u32,
        /// A build with a higher minor has everything a lower one had.
        pub minor: u32,
        /// A fix that changed no declaration.
        pub patch: u32,
    }
}

// Safety: four integers, and zero is a valid value of each.
unsafe impl Versioned for SipralAbiVersion {
    const NAME: &'static str = "sipral_abi_version";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

entry! {
    /// Report the ABI version this library provides.
    ///
    /// # Safety
    ///
    /// `out_version` must point at a `sipral_abi_version_t` whose `size`
    /// member says how long it is.
    fn sipral_abi_version(out_version: *mut SipralAbiVersion) {
        unsafe {
            write_versioned(
                out_version,
                SipralAbiVersion {
                    size: size_of::<SipralAbiVersion>(),
                    major: SIPRAL_ABI_VERSION_MAJOR,
                    minor: SIPRAL_ABI_VERSION_MINOR,
                    patch: SIPRAL_ABI_VERSION_PATCH,
                },
            )
        }
    }
}

entry! {
    /// Whether this library can serve a binding generated against
    /// `major`.`minor`. Every binding calls this once, at load.
    ///
    /// `SIPRAL_STATUS_UNSUPPORTED_VERSION` when it cannot, with a last error
    /// naming both versions, which is what the binding should put in the
    /// exception it throws. The patch number is not asked for: it never
    /// changes a declaration, so it cannot make two builds disagree.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    fn sipral_abi_check(major: u32, minor: u32) {
        // while the major version is zero the ABI is not frozen and no minor
        // promises anything about another; from 1.0 on, a binding built
        // against an earlier minor of the same major keeps working
        let compatible = major == SIPRAL_ABI_VERSION_MAJOR
            && if SIPRAL_ABI_VERSION_MAJOR == 0 {
                minor == SIPRAL_ABI_VERSION_MINOR
            } else {
                minor <= SIPRAL_ABI_VERSION_MINOR
            };
        if compatible {
            return Ok(());
        }
        Err(fail(
            SipralStatus::UnsupportedVersion,
            format!(
                "this library provides ABI {SIPRAL_ABI_VERSION_MAJOR}.{SIPRAL_ABI_VERSION_MINOR} \
                 and the caller was built against {major}.{minor}"
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR, SIPRAL_ABI_VERSION_PATCH,
        SipralAbiVersion, sipral_abi_check, sipral_abi_version,
    };
    use crate::error::last_error_text;
    use crate::status::SipralStatus;
    use std::mem::size_of;
    use std::ptr;

    fn empty_version() -> SipralAbiVersion {
        SipralAbiVersion {
            size: size_of::<SipralAbiVersion>(),
            major: u32::MAX,
            minor: u32::MAX,
            patch: u32::MAX,
        }
    }

    #[test]
    fn the_library_reports_its_abi_version() {
        let mut version = empty_version();
        let status = unsafe { sipral_abi_version(&raw mut version) };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(version.major, SIPRAL_ABI_VERSION_MAJOR);
        assert_eq!(version.minor, SIPRAL_ABI_VERSION_MINOR);
        assert_eq!(version.patch, SIPRAL_ABI_VERSION_PATCH);
        assert_eq!(version.size, size_of::<SipralAbiVersion>());
    }

    #[test]
    fn a_null_version_struct_is_a_bad_argument() {
        let status = unsafe { sipral_abi_version(ptr::null_mut()) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn a_version_struct_of_the_wrong_size_is_refused() {
        let mut version = empty_version();
        version.size = size_of::<SipralAbiVersion>() - 1;
        let status = unsafe { sipral_abi_version(&raw mut version) };
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(version.major, u32::MAX, "nothing was written");
    }

    #[test]
    fn a_version_struct_from_a_newer_header_is_filled_as_far_as_this_build_goes() {
        #[repr(C)]
        struct Newer {
            head: SipralAbiVersion,
            added: u64,
        }
        let mut newer = Newer {
            head: empty_version(),
            added: u64::MAX,
        };
        newer.head.size = size_of::<Newer>();
        let status = unsafe { sipral_abi_version((&raw mut newer).cast::<SipralAbiVersion>()) };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(newer.head.major, SIPRAL_ABI_VERSION_MAJOR);
        assert_eq!(
            newer.head.size,
            size_of::<SipralAbiVersion>(),
            "the caller can see how far this build filled"
        );
        assert_eq!(newer.added, 0, "absent, rather than whatever was there");
    }

    #[test]
    fn the_version_this_library_reports_is_the_version_it_accepts() {
        let mut version = empty_version();
        assert_eq!(
            unsafe { sipral_abi_version(&raw mut version) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_abi_check(version.major, version.minor) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn another_major_version_is_refused_and_says_which_two_disagree() {
        let status = unsafe { sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR + 1, 0) };
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        let message = last_error_text();
        assert!(
            message.contains(&format!("{}.{}", SIPRAL_ABI_VERSION_MAJOR + 1, 0)),
            "the message does not name the caller: {message}"
        );
        assert!(
            message.contains(&format!(
                "{SIPRAL_ABI_VERSION_MAJOR}.{SIPRAL_ABI_VERSION_MINOR}"
            )),
            "the message does not name the library: {message}"
        );
    }

    #[test]
    fn an_unfrozen_abi_promises_nothing_between_its_minors() {
        assert_eq!(
            SIPRAL_ABI_VERSION_MAJOR, 0,
            "once the ABI freezes this rule changes and so does this test"
        );
        assert_eq!(
            unsafe { sipral_abi_check(0, SIPRAL_ABI_VERSION_MINOR + 1) },
            SipralStatus::UnsupportedVersion
        );
        assert_eq!(
            unsafe { sipral_abi_check(0, SIPRAL_ABI_VERSION_MINOR.wrapping_sub(1)) },
            SipralStatus::UnsupportedVersion
        );
    }

    #[test]
    fn a_check_that_passes_leaves_no_message_behind() {
        assert_eq!(
            unsafe { sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR + 1, 0) },
            SipralStatus::UnsupportedVersion
        );
        assert!(!last_error_text().is_empty());
        assert_eq!(
            unsafe { sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR) },
            SipralStatus::Ok
        );
        assert!(last_error_text().is_empty());
    }
}
