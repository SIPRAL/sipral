// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Entry points and the last error.
//!
//! A panic reaching C kills the host, so every entry point uses `entry!`,
//! which wraps the body in [`std::panic::catch_unwind`]. This is why the
//! release profile keeps `panic = unwind`. The message is per thread, so two
//! stacks never overwrite each other's.

use std::any::Any;
use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::c_char;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;

use crate::status::SipralStatus;

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

/// A failure on its way out of an entry point: the code C switches on, and
/// the sentence a person reads.
#[derive(Debug)]
pub(crate) struct Fail {
    pub(crate) status: SipralStatus,
    message: Cow<'static, str>,
}

impl Fail {
    /// The sentence, as the last error will read.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    /// The same failure, prefixed with its place, as in `headers[2]: ...`.
    pub(crate) fn within(self, place: &str) -> Self {
        Self {
            status: self.status,
            message: format!("{place}: {}", self.message).into(),
        }
    }
}

/// A failure with its explanation.
pub(crate) fn fail(status: SipralStatus, message: impl Into<Cow<'static, str>>) -> Fail {
    Fail {
        status,
        message: message.into(),
    }
}

/// Run the body of an entry point that reports a [`Fail`].
///
/// The message is set on the way out, so a success clears it even when a
/// nested call from the caller's callback failed.
pub(crate) fn guard<F>(body: F) -> SipralStatus
where
    F: FnOnce() -> Result<(), Fail>,
{
    match catch(body) {
        Ok(Ok(())) => {
            store("");
            SipralStatus::Ok
        }
        Ok(Err(failure)) => {
            store(&failure.message);
            failure.status
        }
        Err(panicked) => {
            store(&panicked);
            SipralStatus::Panic
        }
    }
}

/// Run the body of an entry point that must not touch the last error.
///
/// Only the accessor below: clobbering would break length-then-bytes reads.
pub(crate) fn guard_quiet<F>(body: F) -> SipralStatus
where
    F: FnOnce() -> Result<(), SipralStatus>,
{
    match catch(body) {
        Ok(Ok(())) => SipralStatus::Ok,
        Ok(Err(status)) => status,
        Err(_) => SipralStatus::Panic,
    }
}

/// Run the body of an entry point that returns a value rather than a status,
/// falling back to `fallback` if it panics.
pub(crate) fn guard_value<T, F>(fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    catch(body).unwrap_or(fallback)
}

fn catch<T, F>(body: F) -> Result<T, String>
where
    F: FnOnce() -> T,
{
    panic::catch_unwind(AssertUnwindSafe(body)).map_err(|payload| describe(&*payload))
}

fn describe(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        format!("panic: {text}")
    } else if let Some(text) = payload.downcast_ref::<String>() {
        format!("panic: {text}")
    } else {
        "panic with a payload that is not a string".to_owned()
    }
}

fn store(message: &str) {
    // both fail only when nobody is left to read the message
    let _ = LAST_ERROR.try_with(|slot| {
        if let Ok(mut text) = slot.try_borrow_mut() {
            text.clear();
            text.push_str(message);
        }
    });
}

fn with_message<R>(read: impl FnOnce(&str) -> R) -> Option<R> {
    LAST_ERROR
        .try_with(|slot| slot.try_borrow().ok().map(|text| read(&text)))
        .ok()
        .flatten()
}

/// Copy the message out, or say how much room it needs.
///
/// # Safety
///
/// `buffer` is written for `capacity` bytes and `out_needed` for one `size_t`.
unsafe fn copy_out(
    message: &str,
    buffer: *mut c_char,
    capacity: usize,
    out_needed: *mut usize,
) -> Result<(), SipralStatus> {
    if buffer.is_null() && capacity != 0 {
        return Err(SipralStatus::InvalidArgument);
    }
    let needed = message.len().saturating_add(1);
    if !out_needed.is_null() {
        unsafe { out_needed.write(needed) };
    }
    if capacity < needed {
        return Err(SipralStatus::BufferTooSmall);
    }
    // capacity >= needed >= 1, so the buffer is not null
    unsafe {
        ptr::copy_nonoverlapping(message.as_ptr().cast::<c_char>(), buffer, message.len());
        buffer.add(message.len()).write(0);
    }
    Ok(())
}

entry! {
    /// Copy the calling thread's last error message into `buffer`.
    ///
    /// UTF-8 with a trailing NUL. `out_needed`, when not null, always receives
    /// the size including the NUL; a null buffer with capacity zero returns
    /// it with `SIPRAL_STATUS_BUFFER_TOO_SMALL`. A buffer too small gets
    /// nothing, never a truncated message.
    ///
    /// It describes this thread's last call: the next call replaces it, a
    /// success empties it, and this call leaves it alone.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or null with a capacity
    /// of zero, and `out_needed` must point to one `size_t` or be null.
    quiet fn sipral_last_error_message(
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        let copied = with_message(|message| unsafe { copy_out(message, buffer, capacity, out_needed) });
        match copied {
            Some(result) => result,
            None => unsafe { copy_out("", buffer, capacity, out_needed) },
        }
    }
}

/// The message read the way C would, through the accessor's two calls.
#[cfg(test)]
pub(crate) fn last_error_text() -> String {
    use std::ffi::CStr;

    let mut needed = 0_usize;
    let status = unsafe { sipral_last_error_message(ptr::null_mut(), 0, &raw mut needed) };
    assert_eq!(status, SipralStatus::BufferTooSmall);
    let mut buffer: Vec<c_char> = vec![0; needed];
    let status = unsafe { sipral_last_error_message(buffer.as_mut_ptr(), needed, ptr::null_mut()) };
    assert_eq!(status, SipralStatus::Ok);
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_str()
        .expect("the message is UTF-8")
        .to_owned()
}

/// Declare an entry point.
///
/// Three shapes: reports a [`Fail`]; `quiet`, leaving the last error alone;
/// returns a value with a panic fallback.
///
/// Each also emits a same-named module holding a [`crate::abi::Function`]
/// built from the declaration's tokens; the header and bindings are printed
/// from it, so a signature is written once.
macro_rules! entry {
    (
        $(#[doc = $doc:literal])*
        fn $name:ident($($argument:ident: $type:ty),* $(,)?) $body:block
    ) => {
        $(#[doc = $doc])*
        // exported symbols are reachable through the linker
        #[allow(unreachable_pub)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name($($argument: $type),*) -> $crate::status::SipralStatus {
            $crate::error::guard(move || $body)
        }

        $crate::error::shape! {
            $name, "SipralStatus", [$($doc),*], [$($argument: $type),*]
        }
    };
    (
        $(#[doc = $doc:literal])*
        quiet fn $name:ident($($argument:ident: $type:ty),* $(,)?) $body:block
    ) => {
        $(#[doc = $doc])*
        // exported symbols are reachable through the linker
        #[allow(unreachable_pub)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name($($argument: $type),*) -> $crate::status::SipralStatus {
            $crate::error::guard_quiet(move || $body)
        }

        $crate::error::shape! {
            $name, "SipralStatus", [$($doc),*], [$($argument: $type),*]
        }
    };
    (
        $(#[doc = $doc:literal])*
        fn $name:ident($($argument:ident: $type:ty),* $(,)?)
            -> $result:ty, on_panic = $fallback:expr, $body:block
    ) => {
        $(#[doc = $doc])*
        // exported symbols are reachable through the linker
        #[allow(unreachable_pub)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name($($argument: $type),*) -> $result {
            $crate::error::guard_value($fallback, move || $body)
        }

        $crate::error::shape! {
            $name, stringify!($result), [$($doc),*], [$($argument: $type),*]
        }
    };
}

/// The half of [`entry`] that writes down what it declared.
///
/// Its own macro so that all three shapes reach for the same one, the way
/// they already reach for the same wrapper.
macro_rules! shape {
    (
        $name:ident, $returns:expr, [$($doc:literal),*], [$($argument:ident: $type:ty),*]
    ) => {
        /// What the entry point of this name is, for the header and the
        /// bindings.
        pub(crate) mod $name {
            /// The shape the declaration was made of.
            pub(crate) const ABI: $crate::abi::Function = $crate::abi::Function {
                name: stringify!($name),
                doc: &[$($doc),*],
                parameters: &[$($crate::abi::Member {
                    name: stringify!($argument),
                    rust_type: stringify!($type),
                    doc: &[],
                }),*],
                returns: $returns,
            };
        }
    };
}

pub(crate) use {entry, shape};

#[cfg(test)]
mod tests {
    use super::{fail, guard, guard_quiet, guard_value, sipral_last_error_message};
    use crate::status::SipralStatus;
    use std::ffi::{CStr, c_char};
    use std::ptr;

    /// `c_char` signedness varies by target.
    const NUL: c_char = 0;
    const UNTOUCHED: c_char = 0x7f;

    fn text_of(buffer: &[c_char]) -> String {
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_str()
            .expect("the message is UTF-8")
            .to_owned()
    }

    fn message() -> String {
        super::last_error_text()
    }

    #[test]
    fn a_call_that_succeeds_leaves_no_message() {
        let status = guard(|| Ok(()));
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(message(), "");
    }

    #[test]
    fn a_call_that_fails_explains_itself() {
        let status = guard(|| Err(fail(SipralStatus::InvalidArgument, "config is null")));
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(message(), "config is null");
    }

    #[test]
    fn the_next_call_clears_the_message() {
        assert_eq!(
            guard(|| Err(fail(SipralStatus::Busy, "in use"))),
            SipralStatus::Busy
        );
        assert_eq!(message(), "in use");
        assert_eq!(guard(|| Ok(())), SipralStatus::Ok);
        assert_eq!(message(), "");
    }

    #[test]
    fn a_panic_becomes_a_status_and_keeps_what_it_said() {
        let status = guard(|| {
            panic!("boom");
        });
        assert_eq!(status, SipralStatus::Panic);
        assert!(message().contains("boom"), "message was {:?}", message());
    }

    #[test]
    fn a_panic_with_a_formatted_payload_survives_too() {
        let which = 7;
        let status = guard(|| {
            panic!("slot {which} is wrong");
        });
        assert_eq!(status, SipralStatus::Panic);
        assert!(message().contains("slot 7"), "message was {:?}", message());
    }

    #[test]
    fn a_panic_with_a_payload_that_is_not_a_string_is_still_caught() {
        let status = guard(|| std::panic::panic_any(19_u8));
        assert_eq!(status, SipralStatus::Panic);
        assert!(!message().is_empty());
    }

    #[test]
    fn a_value_returning_entry_point_falls_back_when_it_panics() {
        let value = guard_value(-1_i32, || panic!("no"));
        assert_eq!(value, -1);
        let value = guard_value(-1_i32, || 5_i32);
        assert_eq!(value, 5);
    }

    #[test]
    fn the_quiet_wrapper_leaves_the_message_where_it_was() {
        assert_eq!(
            guard(|| Err(fail(SipralStatus::StaleHandle, "already destroyed"))),
            SipralStatus::StaleHandle
        );
        assert_eq!(
            guard_quiet(|| Err(SipralStatus::BufferTooSmall)),
            SipralStatus::BufferTooSmall
        );
        assert_eq!(message(), "already destroyed");
    }

    #[test]
    fn the_message_is_this_thread_and_no_other() {
        assert_eq!(
            guard(|| Err(fail(SipralStatus::InvalidHandle, "here"))),
            SipralStatus::InvalidHandle
        );
        let elsewhere = std::thread::spawn(|| {
            let before = message();
            assert_eq!(
                guard(|| Err(fail(SipralStatus::Busy, "there"))),
                SipralStatus::Busy
            );
            (before, message())
        })
        .join()
        .expect("the thread finished");
        assert_eq!(elsewhere, (String::new(), "there".to_owned()));
        assert_eq!(message(), "here");
    }

    #[test]
    fn asking_for_the_length_reports_the_nul_as_well() {
        assert_eq!(
            guard(|| Err(fail(SipralStatus::InvalidArgument, "four"))),
            SipralStatus::InvalidArgument
        );
        let mut needed = 0_usize;
        let status = unsafe { sipral_last_error_message(ptr::null_mut(), 0, &raw mut needed) };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(needed, 5);
    }

    #[test]
    fn a_buffer_one_byte_short_is_refused_and_left_alone() {
        assert_eq!(
            guard(|| Err(fail(SipralStatus::InvalidArgument, "four"))),
            SipralStatus::InvalidArgument
        );
        let mut buffer = [UNTOUCHED; 4];
        let mut needed = 0_usize;
        let status = unsafe { sipral_last_error_message(buffer.as_mut_ptr(), 4, &raw mut needed) };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(needed, 5);
        assert!(buffer.iter().all(|byte| *byte == UNTOUCHED));
    }

    #[test]
    fn a_buffer_of_exactly_the_right_size_is_nul_terminated() {
        assert_eq!(
            guard(|| Err(fail(SipralStatus::InvalidArgument, "four"))),
            SipralStatus::InvalidArgument
        );
        let mut buffer = [UNTOUCHED; 5];
        let status = unsafe { sipral_last_error_message(buffer.as_mut_ptr(), 5, ptr::null_mut()) };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(buffer[4], NUL);
        assert_eq!(text_of(&buffer), "four");
    }

    #[test]
    fn a_null_buffer_with_room_declared_is_a_bad_argument() {
        let status = unsafe { sipral_last_error_message(ptr::null_mut(), 16, ptr::null_mut()) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn an_empty_message_still_needs_room_for_its_nul() {
        assert_eq!(guard(|| Ok(())), SipralStatus::Ok);
        let mut needed = 0_usize;
        let status = unsafe { sipral_last_error_message(ptr::null_mut(), 0, &raw mut needed) };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(needed, 1);
        let mut buffer = [UNTOUCHED; 1];
        let status = unsafe { sipral_last_error_message(buffer.as_mut_ptr(), 1, ptr::null_mut()) };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(buffer[0], NUL);
    }

    #[test]
    fn the_message_can_be_read_twice() {
        assert_eq!(
            guard(|| Err(fail(SipralStatus::Exhausted, "no room"))),
            SipralStatus::Exhausted
        );
        assert_eq!(message(), "no room");
        assert_eq!(message(), "no room");
    }

    // Every shape of the macro must reach for its wrapper, or a panic unwinds
    // into C. `scripts/check.sh` checks nothing bypasses the macro.
    entry! {
        fn sipral_test_entry_panics() {
            panic!("from inside an entry point")
        }
    }

    entry! {
        quiet fn sipral_test_entry_panics_quietly() {
            panic!("quietly")
        }
    }

    entry! {
        fn sipral_test_entry_panics_with_a_value() -> u32, on_panic = 7, {
            panic!("with a value")
        }
    }

    #[test]
    fn a_panic_inside_an_entry_point_becomes_a_status() {
        assert_eq!(
            unsafe { sipral_test_entry_panics() },
            SipralStatus::Panic,
            "it returned rather than unwinding"
        );
        assert_eq!(message(), "panic: from inside an entry point");
    }

    #[test]
    fn the_quiet_shape_catches_too_and_still_says_nothing() {
        guard(|| Err(fail(SipralStatus::Exhausted, "kept")));
        assert_eq!(
            unsafe { sipral_test_entry_panics_quietly() },
            SipralStatus::Panic
        );
        assert_eq!(
            message(),
            "kept",
            "the quiet shape leaves the message alone even when it panics"
        );
    }

    #[test]
    fn the_shape_that_returns_a_value_falls_back_instead_of_unwinding() {
        assert_eq!(unsafe { sipral_test_entry_panics_with_a_value() }, 7);
    }

    // A shape without a descriptor would be a function no binding has.
    #[test]
    fn every_shape_writes_down_what_it_declared() {
        assert_eq!(
            sipral_test_entry_panics::ABI.name,
            "sipral_test_entry_panics"
        );
        assert_eq!(sipral_test_entry_panics::ABI.returns, "SipralStatus");
        assert!(sipral_test_entry_panics::ABI.parameters.is_empty());
        assert_eq!(
            sipral_test_entry_panics_quietly::ABI.returns,
            "SipralStatus"
        );
        assert_eq!(sipral_test_entry_panics_with_a_value::ABI.returns, "u32");
    }

    entry! {
        /// A shape with arguments, so that the recording is exercised on one.
        ///
        /// # Safety
        ///
        /// Reads nothing.
        fn sipral_test_entry_with_arguments(first: u32, second: *const c_char) {
            let _ = (first, second);
            Ok(())
        }
    }

    #[test]
    fn the_recording_carries_the_arguments_and_their_types() {
        let shape = sipral_test_entry_with_arguments::ABI;
        let names: Vec<&str> = shape.parameters.iter().map(|p| p.name).collect();
        let types: Vec<&str> = shape.parameters.iter().map(|p| p.rust_type).collect();
        assert_eq!(names, ["first", "second"]);
        assert_eq!(types, ["u32", "*const c_char"]);
        assert_eq!(
            shape.doc.first().copied(),
            Some(" A shape with arguments, so that the recording is exercised on one.")
        );
    }
}
