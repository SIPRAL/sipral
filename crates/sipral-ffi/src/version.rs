// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
    /// against another; within one, a binding built against a minor works
    /// against a library at that minor or any later one.
    pub const SIPRAL_ABI_VERSION_MAJOR: u32 = 1;

    /// The ABI's minor version, raised by anything the header gains —
    /// everything the generator prints, and not only a function or a struct
    /// member. `sipral_abi_check` compares the major and this one; the patch it
    /// does not ask about. The
    /// rule for all three numbers is the Versioning section of
    /// `docs/08-ffi.md`, which is where the ABI contract is written down.
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
        /// Zero. Rounds the struct up to a whole multiple of its alignment on
        /// every target, so that a member a later version appends starts at or
        /// past the length a caller built against this header declares, never
        /// in padding inside it. The library writes zero here and reads nothing
        /// from it.
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

/// Whether a library at `library` (major, minor) serves a caller built
/// against `caller`: the same major, and a minor no later than the library's.
///
/// Apart from `sipral_abi_check` so that the rule can be held to libraries
/// other than this one — a later minor than this build has is the case a
/// binding meets in the field and this build cannot show by itself.
const fn serves(library: (u32, u32), caller: (u32, u32)) -> bool {
    caller.0 == library.0 && caller.1 <= library.1
}

entry! {
    /// Whether this library can serve a binding generated against
    /// `major`.`minor`. Called once, at load, before anything else: by the
    /// binding itself where its language gives it somewhere to call from, and
    /// by the application where it does not. The Versioning section of
    /// `docs/08-ffi.md` says which binding is which.
    ///
    /// It can when `major` is this library's major and `minor` is no later
    /// than this library's minor: a later minor only appends to an earlier
    /// one, so a binding built against 1.0 loads against a library at 1.4,
    /// and one built against 1.4 is turned away by a library at 1.0, which
    /// lacks what 1.4 added.
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
        SipralAbiVersion, serves, sipral_abi_check, sipral_abi_struct_size, sipral_abi_version,
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

    /// The 1.x promise held against libraries this build is not: a library
    /// at a later minor serves a binding at an earlier one, and the reverse
    /// is refused.
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

    /// Every 0.x binding is refused, the 0.36 one with this very surface
    /// included: 0.x promised nothing between its minors, and a binding
    /// printed then was never told that 1.0 would keep its shapes.
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
        // said before the name is looked at, so the sentence is about the
        // argument that was wrong and not about a name that was not
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
