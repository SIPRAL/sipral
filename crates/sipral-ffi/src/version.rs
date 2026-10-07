// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What ABI this library speaks, and whether a binding can speak it.
//!
//! The ABI version is not the crate's. Bindings and native libraries ship
//! separately, so a mismatch must be caught at load, naming both versions.

use std::ffi::c_char;
use std::mem::size_of;

use crate::abi::{SURFACE, constants, record};
use crate::error::{entry, fail};
use crate::status::SipralStatus;
use crate::text::text;
use crate::versioned::{Versioned, write_versioned};

constants! {
    /// The ABI's major version. Nothing published against one major works
    /// against another; within one, a binding built against a minor works
    /// against a library at that minor or any later one.
    pub const SIPRAL_ABI_VERSION_MAJOR: u32 = 1;

    /// The ABI's minor version, raised by anything the header gains. Rules:
    /// Versioning section of `docs/08-ffi.md`.
    pub const SIPRAL_ABI_VERSION_MINOR: u32 = 2;

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
        /// Zero. Pads to alignment so later members never land in padding.
        pub reserved: u32,
    }
}

// Safety: four integers, and zero is a valid value of each.
unsafe impl Versioned for SipralAbiVersion {
    const NAME: &'static str = "sipral_abi_version";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralAbiVersion, reserved);

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
                    reserved: 0,
                    size: size_of::<SipralAbiVersion>(),
                    major: SIPRAL_ABI_VERSION_MAJOR,
                    minor: SIPRAL_ABI_VERSION_MINOR,
                    patch: SIPRAL_ABI_VERSION_PATCH,
                },
            )
        }
    }
}

/// Same major, caller minor no later than the library's. Separate so tests
/// can check libraries other than this build.
const fn serves(library: (u32, u32), caller: (u32, u32)) -> bool {
    caller.0 == library.0 && caller.1 <= library.1
}

entry! {
    /// Whether this library can serve a binding generated against
    /// `major`.`minor`: same major and a minor no later than this library's.
    /// Called once at load, before anything else.
    ///
    /// `SIPRAL_STATUS_UNSUPPORTED_VERSION` otherwise, with a last error naming
    /// both versions. The patch never changes a declaration, so it is not asked.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    fn sipral_abi_check(major: u32, minor: u32) {
        if serves(
            (SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR),
            (major, minor),
        ) {
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

entry! {
    /// How many bytes this build compiled one of the ABI's structs to.
    ///
    /// `name` is the header's type name, e.g. `sipral_stack_config_t`. An
    /// unknown name is `SIPRAL_STATUS_INVALID_ARGUMENT`. Lets a binding detect
    /// a header mismatch at load.
    ///
    /// # Safety
    ///
    /// `name` must be readable for `name_len` bytes, and `out_size` must
    /// point at one `size_t`.
    fn sipral_abi_struct_size(name: *const c_char, name_len: usize, out_size: *mut usize) {
        if out_size.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_size is null"));
        }
        let Some(wanted) = (unsafe { text(name, name_len, "name") })? else {
            return Err(fail(SipralStatus::InvalidArgument, "name is empty"));
        };
        let Some(record) = SURFACE
            .records
            .iter()
            .find(|record| record.c_name() == wanted)
        else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("this ABI has no struct called {wanted}"),
            ));
        };
        unsafe { out_size.write(record.size) };
        Ok(())
    }
}

entry! {
    /// How many of the ABI's structs carry a `size` member.
    /// Compare it with the caller's own list of structs, so a struct added to
    /// the ABI is not missed by `sipral_abi_struct_size` checks.
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_abi_versioned_count(out_count: *mut usize) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let counted = SURFACE
            .records
            .iter()
            .filter(|record| record.is_versioned())
            .count();
        unsafe { out_count.write(counted) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR, SIPRAL_ABI_VERSION_PATCH,
        SipralAbiVersion, serves, sipral_abi_check, sipral_abi_struct_size, sipral_abi_version,
        sipral_abi_versioned_count,
    };
    use crate::abi::SURFACE;
    use crate::error::last_error_text;
    use crate::status::SipralStatus;
    use std::mem::size_of;
    use std::ptr;

    fn size_of_struct(name: &str) -> Result<usize, SipralStatus> {
        let mut size = usize::MAX;
        let status =
            unsafe { sipral_abi_struct_size(name.as_ptr().cast(), name.len(), &raw mut size) };
        if status == SipralStatus::Ok {
            Ok(size)
        } else {
            Err(status)
        }
    }

    fn empty_version() -> SipralAbiVersion {
        SipralAbiVersion {
            reserved: 0,
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
    fn every_minor_of_this_major_up_to_the_librarys_own_is_served() {
        assert_ne!(
            SIPRAL_ABI_VERSION_MAJOR, 0,
            "the 1.x rule is for a frozen major"
        );
        for minor in 0..=SIPRAL_ABI_VERSION_MINOR {
            assert_eq!(
                unsafe { sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, minor) },
                SipralStatus::Ok,
                "a binding built against {SIPRAL_ABI_VERSION_MAJOR}.{minor}"
            );
        }
    }

    #[test]
    fn a_binding_built_against_a_later_minor_is_refused_and_says_which_two_disagree() {
        let later = SIPRAL_ABI_VERSION_MINOR + 1;
        assert_eq!(
            unsafe { sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, later) },
            SipralStatus::UnsupportedVersion
        );
        let message = last_error_text();
        assert!(
            message.contains(&format!("{SIPRAL_ABI_VERSION_MAJOR}.{later}")),
            "the message does not name the caller: {message}"
        );
    }

    #[test]
    fn a_library_at_a_later_minor_serves_a_binding_at_an_earlier_one() {
        assert!(serves((1, 0), (1, 0)), "equal minors");
        assert!(serves((1, 4), (1, 0)), "a newer library, an older binding");
        assert!(serves((1, 4), (1, 3)), "a newer library, an older binding");
        assert!(!serves((1, 0), (1, 1)), "an older library, a newer binding");
        assert!(!serves((1, 3), (1, 4)), "an older library, a newer binding");
        assert!(!serves((1, 4), (2, 0)), "another major, above");
        assert!(!serves((2, 0), (1, 9)), "another major, below");
    }

    /// 0.x promised nothing between minors, so every 0.x binding is refused.
    #[test]
    fn a_binding_built_against_major_zero_is_refused() {
        assert_eq!(
            unsafe { sipral_abi_check(0, 36) },
            SipralStatus::UnsupportedVersion
        );
        assert!(last_error_text().contains("0.36"), "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_abi_check(0, SIPRAL_ABI_VERSION_MINOR) },
            SipralStatus::UnsupportedVersion
        );
    }

    #[test]
    fn every_struct_of_the_abi_answers_with_the_size_it_was_compiled_to() {
        for record in SURFACE.records {
            assert_eq!(
                size_of_struct(&record.c_name()),
                Ok(record.size),
                "{} does not answer for itself",
                record.name
            );
        }
    }

    #[test]
    fn the_size_reported_is_the_size_the_compiler_settled_on() {
        assert_eq!(
            size_of_struct("sipral_abi_version_t"),
            Ok(size_of::<SipralAbiVersion>())
        );
    }

    #[test]
    fn a_struct_this_abi_never_had_is_a_bad_argument_and_says_which() {
        assert_eq!(
            size_of_struct("sipral_teleporter_t"),
            Err(SipralStatus::InvalidArgument)
        );
        assert!(
            last_error_text().contains("sipral_teleporter_t"),
            "the message does not name what was asked for: {}",
            last_error_text()
        );
    }

    #[test]
    fn the_rust_name_is_not_a_name_this_answers_to() {
        assert_eq!(
            size_of_struct("SipralAbiVersion"),
            Err(SipralStatus::InvalidArgument)
        );
        assert_eq!(
            size_of_struct("sipral_abi_version"),
            Err(SipralStatus::InvalidArgument)
        );
    }

    #[test]
    fn an_empty_or_null_name_is_a_bad_argument() {
        assert_eq!(size_of_struct(""), Err(SipralStatus::InvalidArgument));
        let mut size = 0_usize;
        assert_eq!(
            unsafe { sipral_abi_struct_size(ptr::null(), 4, &raw mut size) },
            SipralStatus::InvalidArgument
        );
    }

    #[test]
    fn the_count_is_every_record_that_carries_a_size() {
        let mut counted = usize::MAX;
        assert_eq!(
            unsafe { sipral_abi_versioned_count(&raw mut counted) },
            SipralStatus::Ok
        );
        assert_eq!(
            counted,
            SURFACE
                .records
                .iter()
                .filter(|record| record.is_versioned())
                .count()
        );
        assert!(counted > 0, "nothing carries a size, which cannot be");
    }

    #[test]
    fn every_struct_the_count_covers_answers_for_its_length() {
        let mut counted = 0_usize;
        assert_eq!(
            unsafe { sipral_abi_versioned_count(&raw mut counted) },
            SipralStatus::Ok
        );
        let answered = SURFACE
            .records
            .iter()
            .filter(|record| record.is_versioned())
            .filter(|record| size_of_struct(&record.c_name()) == Ok(record.size))
            .count();
        assert_eq!(answered, counted);
    }

    #[test]
    fn nowhere_to_put_the_count_is_a_bad_argument() {
        assert_eq!(
            unsafe { sipral_abi_versioned_count(ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
    }

    #[test]
    fn nowhere_to_put_the_answer_is_a_bad_argument() {
        let name = "sipral_abi_version_t";
        assert_eq!(
            unsafe { sipral_abi_struct_size(name.as_ptr().cast(), name.len(), ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        // the null output is reported before the unknown name
        let unknown = "sipral_nothing_t";
        assert_eq!(
            unsafe {
                sipral_abi_struct_size(unknown.as_ptr().cast(), unknown.len(), ptr::null_mut())
            },
            SipralStatus::InvalidArgument
        );
        assert!(
            crate::error::last_error_text().contains("out_size"),
            "{}",
            crate::error::last_error_text()
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
