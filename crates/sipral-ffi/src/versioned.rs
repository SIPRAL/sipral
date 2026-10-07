// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Reading and writing structs that carry their own size.
//!
//! The first member, `size`, is the caller's `sizeof`; neither side touches a
//! byte past it. Appending a member is the only change a released struct may
//! get. On the way in, unknown trailing bytes must be zero, else
//! `SIPRAL_STATUS_NOT_SUPPORTED` (the member is the problem, not the size).
//! On the way out, `size` says how far the library filled and the rest is
//! zeroed.

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
/// zero. Its first member must be `size: usize`, and [`Versioned::PIN`] must
/// name the last member of the oldest version of it the frozen ABI publishes.
pub(crate) unsafe trait Versioned: Copy {
    /// What the struct is called in C, for the sentence a caller reads.
    const NAME: &'static str;

    /// Where the oldest published version of the struct ends, written with
    /// [`pin!`] as the member it ends with.
    const PIN: Pin;

    /// The shortest this build accepts: the end of the pinned member on this
    /// target. A pin past the struct's end fails at compile time.
    const MIN_SIZE: usize = {
        assert!(
            Self::PIN.end <= size_of::<Self>(),
            "a pinned length is longer than the struct it pins"
        );
        Self::PIN.end
    };

    /// Set the size member.
    fn set_declared_size(&mut self, bytes: usize);
}

/// The length a versioned struct had in the first version of it the frozen
/// ABI publishes, held as the member that version ends with.
///
/// [`declared_size`] refuses anything below [`Versioned::MIN_SIZE`], so the
/// minimum must stand still while the struct grows, or old callers are turned
/// away. It is a member, not a literal, because the length differs per
/// target (32-bit ARM packs tighter).
///
/// Pins name the member each struct ended with at ABI minor 33, carried into
/// 1.0 unchanged. Change one only if that is wrong. `bindings/c/abi-sizes.txt`
/// prints each pin per layout and the gate diffs it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pin {
    /// The member the oldest published version ends with.
    pub(crate) member: &'static str,
    /// Where that member ends, in bytes from the start of the struct.
    pub(crate) end: usize,
}

/// The size of a member, for [`pin!`], without naming its type.
pub(crate) const fn size_of_member<R, M>(_accessor: fn(&R) -> &M) -> usize {
    size_of::<M>()
}

/// `pin!(SipralAbiVersion, reserved)`: the [`Pin`] at the end of `reserved`.
macro_rules! pin {
    ($record:ty, $member:ident) => {
        $crate::versioned::Pin {
            member: stringify!($member),
            end: ::std::mem::offset_of!($record, $member)
                + $crate::versioned::size_of_member(|value: &$record| &value.$member),
        }
    };
}

pub(crate) use pin;

/// Above any real struct; refuses an uninitialised size member before the
/// reader walks that far.
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
    // the struct may sit inside a packed one
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
/// Members past what the caller supplied come back zero.
///
/// # Safety
///
/// `source`, when it is not null, must point at an initialised `size` member
/// and be readable for as many bytes as that member declares.
pub(crate) unsafe fn read_versioned<T: Versioned>(source: *const T) -> Result<T, Fail> {
    let declared = unsafe { declared_size(source) }?;
    let known = size_of::<T>();
    let taken = declared.min(known);

    // all-zero is valid by the trait's contract
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
/// The size written back is how far this build filled.
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
        const PIN: super::Pin = super::pin!(Second, beta);

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

    // the misalignment is the point
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

    /// The copying relies on `size` being the first member.
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

    /// Every sized struct in `SURFACE` is pinned or filled by the library.
    #[test]
    fn every_versioned_struct_has_a_pinned_length() {
        let mut missing = Vec::new();
        for record in SURFACE.records.iter().filter(|r| r.is_versioned()) {
            let pinned = MIN_SIZES.iter().any(|(name, _, _)| *name == record.name);
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

    /// Catches a rename.
    #[test]
    fn nothing_is_pinned_that_does_not_exist() {
        for (name, member, _) in MIN_SIZES {
            let record = SURFACE.records.iter().find(|record| record.name == *name);
            assert!(
                record.is_some(),
                "{name} has a pinned length and is not in the surface"
            );
            assert!(
                record.is_some_and(|record| record.fields.iter().any(|f| f.name == *member)),
                "{name} is pinned through {member}, which it does not have"
            );
        }
        for name in FILLED_BY_US {
            assert!(
                SURFACE.records.iter().any(|record| record.name == *name),
                "{name} is excused from being pinned and is not in the surface"
            );
        }
    }

    /// A pin above the current length would refuse a caller of this build.
    #[test]
    fn no_pinned_length_is_longer_than_the_struct_is_now() {
        for (name, _, pinned) in MIN_SIZES {
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
