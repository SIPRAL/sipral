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

use std::ffi::c_char;
use std::mem::size_of;

use crate::abi::{SURFACE, constants, record};
use crate::error::{entry, fail};
use crate::status::SipralStatus;
use crate::text::text;
use crate::versioned::{Versioned, write_versioned};

constants! {
    /// The ABI's major version. Nothing published against one major works
    /// against another.
    pub const SIPRAL_ABI_VERSION_MAJOR: u32 = 0;

    /// The ABI's minor version, raised by anything the header gains —
    /// everything the generator prints, and not only a function or a struct
    /// member. `sipral_abi_check` compares the major and this one; the patch it
    /// does not ask about. The
    /// rule for all three numbers is the Versioning section of
    /// `docs/08-ffi.md`, which is where the ABI contract is written down.
    pub const SIPRAL_ABI_VERSION_MINOR: u32 = 12;

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
    const MIN_SIZE: usize = crate::versioned::min_size::ABI_VERSION;

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
    /// `major`.`minor`. Called once, at load, before anything else: by the
    /// binding itself where its language gives it somewhere to call from, and
    /// by the application where it does not. The Versioning section of
    /// `docs/08-ffi.md` says which binding is which.
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

entry! {
    /// How many bytes this build compiled one of the ABI's structs to.
    ///
    /// `name` is what the header calls the type — `sipral_stack_config_t` —
    /// as bytes and a length, the way every string crosses here. A name this
    /// build has no struct for is `SIPRAL_STATUS_INVALID_ARGUMENT`, which is
    /// the answer a caller holding somebody else's header gets.
    ///
    /// Nothing in the library needs asking: the `size` member a struct
    /// carries settles a disagreement in the ordinary course of a call. This
    /// is for finding out there is one before making it. A package built
    /// against one header and loaded over a native library from another
    /// shows up here as a `sizeof` that differs, in one call at load, rather
    /// than in whichever member happened to move.
    ///
    /// # Safety
    ///
    /// `name` must be readable for `name_len` bytes, and `out_size` must
    /// point at one `size_t`.
    fn sipral_abi_struct_size(name: *const c_char, name_len: usize, out_size: *mut usize) {
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
        if out_size.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_size is null"));
        }
        unsafe { out_size.write(record.size) };
        Ok(())
    }
}

entry! {
    /// How many of the ABI's structs carry a `size` member.
    ///
    /// The companion to `sipral_abi_struct_size`, and the part of the check a
    /// caller cannot write for itself. A caller that compares lengths holds
    /// a list of the structs it knows about, and the list is what goes
    /// stale: a struct this ABI gained is one nobody thought to ask about,
    /// and a length check that covers all but the newest still passes. Ask
    /// for this number, compare it with the length of that list, and the day
    /// the ABI grows another the caller is told.
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
        SipralAbiVersion, sipral_abi_check, sipral_abi_struct_size, sipral_abi_version,
        sipral_abi_versioned_count,
    };
    use crate::abi::SURFACE;
    use crate::error::last_error_text;
    use crate::status::SipralStatus;
    use std::mem::size_of;
    use std::ptr;

    /// What C would ask: a NUL-terminated name, passed as bytes and a length
    /// the way the boundary takes every string.
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

    /// The Rust spelling is not a name the C side has, and answering to it
    /// would make two names for one struct.
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

    /// What a caller's list of structs is compared against, so that a
    /// struct added here and not there is caught on the caller's side.
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

    /// Every struct the count promises there is answers to `sipral_abi_struct_size`
    /// by the name the header gives it, since a caller walking the one uses
    /// the other.
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
