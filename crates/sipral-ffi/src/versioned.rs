// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Structs that cross the boundary carry their own size, and this is what
//! reads and writes them.
//!
//! A caller compiled against one header and a library built from a later one
//! disagree about how long a struct is. The `size` member, first and always,
//! is how they settle it: the caller writes its own `sizeof`, and neither side
//! touches a byte the other did not account for. That is what makes appending
//! a member to a released struct safe, and it is the only change a released
//! struct is allowed.
//!
//! Two rules make the arrangement honest in both directions. On the way in,
//! bytes past what this build knows are accepted only if they are all zero: a
//! caller who set a field this library has never heard of is answered
//! `SIPRAL_STATUS_NOT_SUPPORTED`, rather than served by a library that quietly
//! ignored it. The size is not the complaint — a longer struct is exactly what
//! a newer header is supposed to hand over — so the answer is not about the
//! version but about the member, which is the difference an application acts
//! on. On the way out, the
//! `size` written back says how far the library actually filled, and anything
//! past that is zeroed, so a newer caller reading an older library sees
//! absence rather than whatever was on its stack.

use std::mem::{MaybeUninit, size_of};
use std::ptr;
use std::slice;

use crate::error::{Fail, fail};
use crate::status::SipralStatus;

/// A `#[repr(C)]` struct whose first member is its own size in bytes.
///
/// # Safety
///
/// The type must be plain data: `#[repr(C)]`, no pointers it owns, no
/// invariant between its members, and valid when every one of its bytes is
/// zero. Its first member must be `size: usize`, and [`Versioned::MIN_SIZE`]
/// must be the length of the oldest published version of it.
pub(crate) unsafe trait Versioned: Copy {
    /// What the struct is called in C, for the sentence a caller reads.
    const NAME: &'static str;

    /// The shortest this build will work with.
    const MIN_SIZE: usize;

    /// Set the size member. The size a caller declared is read from its
    /// pointer instead, since by then there is no value to ask.
    fn set_declared_size(&mut self, bytes: usize);
}

/// The length each versioned struct had in the **first published header**,
/// written once as a literal and never recomputed.
///
/// This is the whole of what makes appending a member safe, and writing
/// `size_of::<Self>()` here instead — which is what every one of these used to
/// be — inverts it. [`declared_size`] refuses anything below `MIN_SIZE`, so a
/// `MIN_SIZE` that tracks the current build turns away every caller compiled
/// against yesterday's header, from a change whose entire point was to be
/// additive. The number has to stand still while the struct grows, and a
/// literal is the only thing that does.
///
/// Changing one of these is therefore a deliberate act with a reviewable diff,
/// and it is wrong in every case but one: a struct whose **first** published
/// length was not what is written here. Nothing else is a reason.
/// `bindings/c/abi-sizes.txt` is printed from this table and the gate diffs
/// it, so the change shows up twice.
pub(crate) mod min_size {
    #![allow(unreachable_pub)]
    /// `sipral_abi_version_t`
    pub const ABI_VERSION: usize = 24;
    /// `sipral_audio_device_t`
    pub const AUDIO_DEVICE: usize = 32;
    /// `sipral_audio_info_t`
    pub const AUDIO_INFO: usize = 48;
    /// `sipral_account_config_t`
    pub const ACCOUNT_CONFIG: usize = 144;
    /// `sipral_call_config_t`
    pub const CALL_CONFIG: usize = 80;
    /// `sipral_capabilities_t`
    pub const CAPABILITIES: usize = 24;
    /// `sipral_conference_t`
    pub const CONFERENCE: usize = 32;
    /// `sipral_conference_user_t`
    pub const CONFERENCE_USER: usize = 24;
    /// `sipral_codec_candidate_t`
    pub const CODEC_CANDIDATE: usize = 24;
    /// `sipral_codec_info_t`
    pub const CODEC_INFO: usize = 32;
    /// `sipral_counters_t`
    pub const COUNTERS: usize = 152;
    /// `sipral_media_info_t`
    pub const MEDIA_INFO: usize = 88;
    /// `sipral_media_packet_t`
    pub const MEDIA_PACKET: usize = 56;
    /// `sipral_path_candidate_t`
    pub const PATH_CANDIDATE: usize = 88;
    /// `sipral_poll_result_t`
    pub const POLL_RESULT: usize = 48;
    /// `sipral_progress_config_t`
    pub const PROGRESS_CONFIG: usize = 72;
    /// `sipral_consent_tone_t`
    pub const CONSENT_TONE: usize = 32;
    /// `sipral_recording_options_t`
    pub const RECORDING_OPTIONS: usize = 32;
    /// `sipral_presence_t`
    pub const PRESENCE: usize = 32;
    /// `sipral_push_echo_t`
    pub const PUSH_ECHO: usize = 24;
    /// `sipral_record_config_t`
    pub const RECORD_CONFIG: usize = 80;
    /// `sipral_stack_config_t`
    pub const STACK_CONFIG: usize = 176;
    /// `sipral_stack_settings_t`
    pub const STACK_SETTINGS: usize = 72;
    /// `sipral_stream_stats_t`
    pub const STREAM_STATS: usize = 152;
    /// `sipral_stir_config_t`
    pub const STIR_CONFIG: usize = 48;
    /// `sipral_stream_encryption_t`
    pub const STREAM_ENCRYPTION: usize = 32;
    /// `sipral_subscribe_config_t`
    pub const SUBSCRIBE_CONFIG: usize = 88;
    /// `sipral_transmit_t`
    pub const TRANSMIT: usize = 88;
    /// `sipral_transport_failure_t`
    pub const TRANSPORT_FAILURE: usize = 40;
    /// `sipral_watched_dialog_t`
    pub const WATCHED_DIALOG: usize = 32;
}

/// More than any struct here will ever be, and small enough that a size
/// member the caller left uninitialised is refused rather than obeyed. The
/// declared size decides how far the reader walks, so it is the one number a
/// caller can get catastrophically wrong.
const MAX_DECLARED_SIZE: usize = 64 * 1024;

/// What a caller says its struct is, checked as far as the size member.
///
/// # Safety
///
/// `source`, when it is not null, must point at an initialised `size` member
/// and be readable for as many bytes as that member declares.
pub(crate) unsafe fn declared_size<T: Versioned>(source: *const T) -> Result<usize, Fail> {
    if source.is_null() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("{} is null", T::NAME),
        ));
    }
    // read unaligned: the alignment is the C caller's business, and a struct
    // inside a packed one is still a struct
    let declared = unsafe { source.cast::<usize>().read_unaligned() };
    if declared < T::MIN_SIZE {
        return Err(fail(
            SipralStatus::UnsupportedVersion,
            format!(
                "{} says it is {declared} bytes and this build needs at least {}",
                T::NAME,
                T::MIN_SIZE
            ),
        ));
    }
    if declared > MAX_DECLARED_SIZE {
        return Err(fail(
            SipralStatus::UnsupportedVersion,
            format!(
                "{} says it is {declared} bytes, which is not a size any version of it has",
                T::NAME
            ),
        ));
    }
    Ok(declared)
}

/// Read a struct the caller supplied, honouring the size it declares.
///
/// Members past what the caller supplied come back zero, which is what every
/// member added to a released struct has to mean.
///
/// # Safety
///
/// `source`, when it is not null, must point at an initialised `size` member
/// and be readable for as many bytes as that member declares.
pub(crate) unsafe fn read_versioned<T: Versioned>(source: *const T) -> Result<T, Fail> {
    let declared = unsafe { declared_size(source) }?;
    let known = size_of::<T>();
    let taken = declared.min(known);

    // zero is a valid value of every member by the trait's contract, so the
    // part the caller did not send reads as absent
    let mut value: T = unsafe { MaybeUninit::zeroed().assume_init() };
    unsafe {
        ptr::copy_nonoverlapping(source.cast::<u8>(), (&raw mut value).cast::<u8>(), taken);
    }

    if declared > known {
        let extra = declared - known;
        let tail = unsafe { slice::from_raw_parts(source.cast::<u8>().add(known), extra) };
        if tail.iter().any(|byte| *byte != 0) {
            return Err(fail(
                SipralStatus::NotSupported,
                format!(
                    "{} carries {extra} bytes this build does not know, and they are not zero, so \
                     something was set that nothing here reads",
                    T::NAME
                ),
            ));
        }
    }

    value.set_declared_size(taken);
    Ok(value)
}

/// Fill in a struct the caller supplied, honouring the size it declares.
///
/// The size written back is how far this build filled, so a caller newer than
/// the library can tell which members mean anything.
///
/// # Safety
///
/// `destination`, when it is not null, must point at an initialised `size`
/// member and be writable for as many bytes as that member declares.
pub(crate) unsafe fn write_versioned<T: Versioned>(
    destination: *mut T,
    mut value: T,
) -> Result<(), Fail> {
    let declared = unsafe { declared_size(destination.cast_const()) }?;
    let known = size_of::<T>();
    let written = declared.min(known);

    value.set_declared_size(written);
    unsafe {
        ptr::copy_nonoverlapping(
            (&raw const value).cast::<u8>(),
            destination.cast::<u8>(),
            written,
        );
    }

    if declared > known {
        unsafe { ptr::write_bytes(destination.cast::<u8>().add(known), 0, declared - known) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Versioned, declared_size, read_versioned, write_versioned};
    use crate::abi::{FILLED_BY_US, MIN_SIZES, SURFACE};
    use crate::status::SipralStatus;
    use std::mem::{MaybeUninit, size_of};
    use std::ptr;

    /// The first version of a struct in some released header.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct First {
        size: usize,
        alpha: u32,
        beta: u32,
    }

    /// The same struct after a member was appended to it.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Second {
        size: usize,
        alpha: u32,
        beta: u32,
        gamma: u64,
    }

    unsafe impl Versioned for Second {
        const NAME: &'static str = "second";
        const MIN_SIZE: usize = size_of::<First>();

        fn set_declared_size(&mut self, bytes: usize) {
            self.size = bytes;
        }
    }

    fn second(gamma: u64) -> Second {
        Second {
            size: size_of::<Second>(),
            alpha: 1,
            beta: 2,
            gamma,
        }
    }

    #[test]
    fn a_null_struct_is_a_bad_argument() {
        let read = unsafe { read_versioned::<Second>(ptr::null()) };
        assert_eq!(
            read.err().map(|failure| failure.status),
            Some(SipralStatus::InvalidArgument)
        );
        let written = unsafe { write_versioned(ptr::null_mut(), second(0)) };
        assert_eq!(
            written.err().map(|failure| failure.status),
            Some(SipralStatus::InvalidArgument)
        );
    }

    #[test]
    fn a_struct_shorter_than_the_oldest_version_is_refused() {
        let mut supplied = second(9);
        supplied.size = size_of::<First>() - 1;
        let read = unsafe { read_versioned(&raw const supplied) };
        assert_eq!(
            read.err().map(|failure| failure.status),
            Some(SipralStatus::UnsupportedVersion)
        );
    }

    #[test]
    fn a_size_member_nobody_set_is_refused_before_anything_is_walked() {
        let mut supplied = second(9);
        supplied.size = usize::MAX;
        let read = unsafe { read_versioned(&raw const supplied) };
        assert_eq!(
            read.err().map(|failure| failure.status),
            Some(SipralStatus::UnsupportedVersion)
        );
        let written = unsafe { write_versioned(&raw mut supplied, second(1)) };
        assert_eq!(
            written.err().map(|failure| failure.status),
            Some(SipralStatus::UnsupportedVersion)
        );
        assert_eq!(supplied.gamma, 9, "nothing was written");
    }

    #[test]
    fn a_size_of_zero_is_refused_rather_than_read_as_empty() {
        let mut supplied = second(9);
        supplied.size = 0;
        let read = unsafe { read_versioned(&raw const supplied) };
        assert_eq!(
            read.err().map(|failure| failure.status),
            Some(SipralStatus::UnsupportedVersion)
        );
    }

    #[test]
    fn an_older_caller_gets_zero_for_what_it_never_sent() {
        let old = First {
            size: size_of::<First>(),
            alpha: 3,
            beta: 4,
        };
        let read = unsafe { read_versioned::<Second>((&raw const old).cast()) }
            .expect("the first version is still accepted");
        assert_eq!(read.alpha, 3);
        assert_eq!(read.beta, 4);
        assert_eq!(read.gamma, 0, "a member the caller has never heard of");
        assert_eq!(
            read.size,
            size_of::<First>(),
            "the size says how much came in"
        );
    }

    #[test]
    fn a_caller_of_this_version_is_read_whole() {
        let supplied = second(77);
        let read = unsafe { read_versioned(&raw const supplied) }.expect("current version");
        assert_eq!(read, supplied);
    }

    #[test]
    fn a_newer_caller_is_accepted_while_what_this_build_cannot_read_is_empty() {
        #[repr(C)]
        struct Third {
            head: Second,
            delta: u64,
        }
        let supplied = Third {
            head: Second {
                size: size_of::<Third>(),
                alpha: 5,
                beta: 6,
                gamma: 7,
            },
            delta: 0,
        };
        let read = unsafe { read_versioned((&raw const supplied).cast::<Second>()) }
            .expect("a zero tail is a tail that says nothing");
        assert_eq!(read.alpha, 5);
        assert_eq!(read.gamma, 7);
        assert_eq!(
            read.size,
            size_of::<Second>(),
            "the size is capped at what this build knows"
        );
    }

    #[test]
    fn a_newer_caller_that_set_a_member_this_build_ignores_is_told_so() {
        #[repr(C)]
        struct Third {
            head: Second,
            delta: u64,
        }
        let supplied = Third {
            head: Second {
                size: size_of::<Third>(),
                alpha: 5,
                beta: 6,
                gamma: 7,
            },
            delta: 1,
        };
        let read = unsafe { read_versioned((&raw const supplied).cast::<Second>()) };
        assert_eq!(
            read.err().map(|failure| failure.status),
            Some(SipralStatus::NotSupported),
            "the struct is a shape this build works with; the member in it is not"
        );
    }

    // the misalignment is the point: a caller may hand over a struct inside a
    // packed one, and the reader copies bytes rather than dereferencing
    #[allow(clippy::cast_ptr_alignment)]
    #[test]
    fn an_unaligned_struct_is_read_as_it_is() {
        let mut buffer = [0_u8; size_of::<Second>() + 1];
        let supplied = second(123);
        unsafe {
            ptr::copy_nonoverlapping(
                (&raw const supplied).cast::<u8>(),
                buffer.as_mut_ptr().add(1),
                size_of::<Second>(),
            );
        }
        let read = unsafe { read_versioned(buffer.as_ptr().add(1).cast::<Second>()) }
            .expect("alignment is the caller's business");
        assert_eq!(read.gamma, 123);
    }

    #[test]
    fn writing_fills_the_struct_and_says_how_far_it_went() {
        let mut destination = Second {
            size: size_of::<Second>(),
            alpha: 0,
            beta: 0,
            gamma: 0,
        };
        unsafe { write_versioned(&raw mut destination, second(31)) }.expect("current version");
        assert_eq!(destination.alpha, 1);
        assert_eq!(destination.gamma, 31);
        assert_eq!(destination.size, size_of::<Second>());
    }

    #[test]
    fn writing_into_an_older_struct_stops_at_its_end() {
        #[repr(C)]
        struct Padded {
            head: First,
            guard: u64,
        }
        let mut destination = Padded {
            head: First {
                size: size_of::<First>(),
                alpha: 0,
                beta: 0,
            },
            guard: 0xDEAD_BEEF,
        };
        unsafe { write_versioned((&raw mut destination).cast::<Second>(), second(31)) }
            .expect("the first version is still served");
        assert_eq!(destination.head.alpha, 1);
        assert_eq!(destination.head.size, size_of::<First>());
        assert_eq!(
            destination.guard, 0xDEAD_BEEF,
            "nothing past what the caller declared is touched"
        );
    }

    #[test]
    fn writing_into_a_newer_struct_zeroes_what_this_build_cannot_fill() {
        #[repr(C)]
        struct Third {
            head: Second,
            delta: u64,
        }
        let mut destination = Third {
            head: Second {
                size: size_of::<Third>(),
                alpha: 0,
                beta: 0,
                gamma: 0,
            },
            delta: 0xFFFF_FFFF,
        };
        unsafe { write_versioned((&raw mut destination).cast::<Second>(), second(31)) }
            .expect("a newer caller is served what there is");
        assert_eq!(destination.head.gamma, 31);
        assert_eq!(
            destination.head.size,
            size_of::<Second>(),
            "the caller can see how far the library filled"
        );
        assert_eq!(
            destination.delta, 0,
            "absent, rather than whatever was there"
        );
    }

    #[test]
    fn writing_into_something_too_short_is_refused_before_anything_moves() {
        let mut destination = second(0);
        destination.size = size_of::<First>() - 1;
        destination.alpha = 99;
        let written = unsafe { write_versioned(&raw mut destination, second(31)) };
        assert_eq!(
            written.err().map(|failure| failure.status),
            Some(SipralStatus::UnsupportedVersion)
        );
        assert_eq!(destination.alpha, 99, "nothing was written");
    }

    #[test]
    fn the_size_a_caller_declares_is_reported_as_it_is() {
        let supplied = second(0);
        let declared = unsafe { declared_size(&raw const supplied) }.expect("current version");
        assert_eq!(declared, size_of::<Second>());
    }

    /// Everything here copies bytes on the strength of the size member being
    /// the first one, so every type that claims the trait is asked to prove
    /// it.
    fn size_member_comes_first<T: Versioned>() {
        let mut value: T = unsafe { MaybeUninit::zeroed().assume_init() };
        value.set_declared_size(0x5A5A);
        let first = unsafe { (&raw const value).cast::<usize>().read_unaligned() };
        assert_eq!(first, 0x5A5A, "{} does not start with its size", T::NAME);
    }

    #[test]
    fn every_versioned_struct_starts_with_its_size() {
        size_member_comes_first::<Second>();
        size_member_comes_first::<crate::stack::SipralStackConfig>();
        size_member_comes_first::<crate::stack::SipralPollResult>();
        size_member_comes_first::<crate::transport::SipralTransmit>();
        size_member_comes_first::<crate::version::SipralAbiVersion>();
    }

    // -- the pinned lengths --------------------------------------------------

    /// A list of thirteen kept by hand beside a list of thirteen kept by the
    /// declarations is two lists, and they drift. This is the loop that stops
    /// them: everything in `SURFACE` that starts with a `size` either has a
    /// pinned length or is named as one the library fills itself.
    #[test]
    fn every_versioned_struct_has_a_pinned_length() {
        let mut missing = Vec::new();
        for record in SURFACE.records.iter().filter(|r| r.is_versioned()) {
            let pinned = MIN_SIZES.iter().any(|(name, _)| *name == record.name);
            let ours = FILLED_BY_US.contains(&record.name);
            if !pinned && !ours {
                missing.push(record.name);
            }
        }
        assert!(
            missing.is_empty(),
            "a struct a caller declares to us has no oldest published length, \
             so an appended member would turn every old caller away: {missing:?}"
        );
    }

    /// The other direction, which is the one that catches a rename: a pinned
    /// length for a struct that is no longer declared pins nothing.
    #[test]
    fn nothing_is_pinned_that_does_not_exist() {
        for (name, _) in MIN_SIZES {
            assert!(
                SURFACE.records.iter().any(|record| record.name == *name),
                "{name} has a pinned length and is not in the surface"
            );
        }
        for name in FILLED_BY_US {
            assert!(
                SURFACE.records.iter().any(|record| record.name == *name),
                "{name} is excused from being pinned and is not in the surface"
            );
        }
    }

    /// The invariant the pinning exists for. A pinned length above the
    /// current one would refuse a caller compiled against this very build.
    #[test]
    fn no_pinned_length_is_longer_than_the_struct_is_now() {
        for (name, pinned) in MIN_SIZES {
            let record = SURFACE
                .records
                .iter()
                .find(|record| record.name == *name)
                .expect("checked by the test above");
            assert!(
                *pinned <= record.size,
                "{name} is pinned at {pinned} and is {} bytes long: a caller \
                 built against this header would be turned away by it",
                record.size
            );
        }
    }
}
