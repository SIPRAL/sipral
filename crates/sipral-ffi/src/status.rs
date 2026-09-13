// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What every entry point returns.
//!
//! The code says what kind of failure it was. The sentence saying which one
//! lives in the calling thread's last error, in [`crate::error`], because a
//! code that has to distinguish every reason a message can be malformed is a
//! code nobody can switch on.

use std::ffi::c_char;
use std::ptr;

use crate::abi::codes;
use crate::error::entry;

codes! {
    /// The result of a call across the C ABI.
    ///
    /// The numbers are part of the ABI. A value keeps its meaning for the life of
    /// the ABI's major version, and a new one is only ever added at the end.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum SipralStatus: i32 {
        /// The call did what it was asked to.
        Ok = 0,
        /// A pointer was null where one is required, a length disagreed with what
        /// it describes, or a value was outside what the call accepts.
        InvalidArgument = 1,
        /// The handle never came from this library, or it came from a stack
        /// other than the one it was used with.
        InvalidHandle = 2,
        /// The handle came from this library and what it named is gone: a use
        /// after free, or a second free.
        StaleHandle = 3,
        /// A versioned struct declared a size this build cannot work with, or a
        /// binding asked for an ABI this library does not provide.
        UnsupportedVersion = 4,
        /// The buffer supplied is too small. The length needed has been written to
        /// the out parameter, and nothing was written to the buffer.
        BufferTooSmall = 5,
        /// The object is already in use by another call, including one further
        /// down the same call stack. Nothing was done, and nothing blocked.
        Busy = 6,
        /// The library has no room for another object of this kind.
        Exhausted = 7,
        /// A panic was caught at the boundary. The call did not finish, and the
        /// last error carries whatever the panic said.
        Panic = 8,
        /// What was asked for cannot be done where the object is: answering a call
        /// this end placed, holding one that is not up, sending DTMF before there
        /// is a dialog to send it in. Not an argument that was wrong; a moment
        /// that was.
        WrongState = 9,
        /// The request could not be assembled or handed to a transport. Nothing
        /// went out, and nothing about the call changed.
        NotSent = 10,
        /// The value is one this ABI has a word for and this build has no code
        /// behind. Nothing was applied, and asking again will not change that.
        ///
        /// The third of the three answers a configuration call may give, and the
        /// one that has to be told apart from the other two by a machine.
        /// [`SipralStatus::InvalidArgument`] says the value is wrong and a
        /// corrected one would be taken; this says the value is right and there is
        /// nothing here to take it. [`SipralStatus::UnsupportedVersion`] is about
        /// the shape of what crossed the boundary, not about what was set in it.
        ///
        /// It exists so that "accepted and ignored" is not a thing this library
        /// can do. An application that gets it turns the control off, because the
        /// control is genuinely dead in this build; one that gets a silence
        /// instead ships a control that does nothing and finds out from a
        /// customer.
        NotSupported = 11,
    }
}

entry! {
    /// The short name of a status code, as a static NUL-terminated string, or
    /// null for a number that is not a status code.
    ///
    /// The string belongs to the library and lives as long as it is loaded.
    /// It is meant for a log line; the last error is the sentence for a human.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    fn sipral_status_name(status: i32) -> *const c_char, on_panic = ptr::null(), {
        match status {
            0 => c"ok".as_ptr(),
            1 => c"invalid argument".as_ptr(),
            2 => c"invalid handle".as_ptr(),
            3 => c"stale handle".as_ptr(),
            4 => c"unsupported version".as_ptr(),
            5 => c"buffer too small".as_ptr(),
            6 => c"busy".as_ptr(),
            7 => c"exhausted".as_ptr(),
            8 => c"panic".as_ptr(),
            9 => c"wrong state".as_ptr(),
            10 => c"not sent".as_ptr(),
            11 => c"not supported in this build".as_ptr(),
            _ => ptr::null(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SipralStatus, sipral_status_name};
    use std::ffi::CStr;

    fn name(status: i32) -> Option<String> {
        let pointer = unsafe { sipral_status_name(status) };
        if pointer.is_null() {
            return None;
        }
        Some(
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    #[test]
    fn every_status_has_a_name() {
        let all = [
            SipralStatus::Ok,
            SipralStatus::InvalidArgument,
            SipralStatus::InvalidHandle,
            SipralStatus::StaleHandle,
            SipralStatus::UnsupportedVersion,
            SipralStatus::BufferTooSmall,
            SipralStatus::Busy,
            SipralStatus::Exhausted,
            SipralStatus::Panic,
            SipralStatus::WrongState,
            SipralStatus::NotSent,
            SipralStatus::NotSupported,
        ];
        for status in all {
            let code = status as i32;
            assert!(name(code).is_some(), "no name for {status:?}");
        }
    }

    #[test]
    fn the_names_are_distinct() {
        let mut seen = Vec::new();
        for code in 0..=11 {
            let Some(text) = name(code) else {
                panic!("no name for {code}");
            };
            assert!(!seen.contains(&text), "{text} appears twice");
            seen.push(text);
        }
    }

    #[test]
    fn a_number_that_is_not_a_status_has_no_name() {
        assert!(name(12).is_none());
        assert!(name(-1).is_none());
        assert!(name(i32::MAX).is_none());
        assert!(name(i32::MIN).is_none());
    }

    /// The numbers are written out rather than walked, because a test that
    /// derives them from the declaration would move with a declaration that
    /// moved. Zero is the one with a reason of its own: C tests a status that
    /// way.
    #[test]
    fn the_numbers_are_where_they_were_published() {
        assert_eq!(SipralStatus::Ok as i32, 0);
        assert_eq!(SipralStatus::InvalidArgument as i32, 1);
        assert_eq!(SipralStatus::InvalidHandle as i32, 2);
        assert_eq!(SipralStatus::StaleHandle as i32, 3);
        assert_eq!(SipralStatus::UnsupportedVersion as i32, 4);
        assert_eq!(SipralStatus::BufferTooSmall as i32, 5);
        assert_eq!(SipralStatus::Busy as i32, 6);
        assert_eq!(SipralStatus::Exhausted as i32, 7);
        assert_eq!(SipralStatus::Panic as i32, 8);
        assert_eq!(SipralStatus::WrongState as i32, 9);
        assert_eq!(SipralStatus::NotSent as i32, 10);
        assert_eq!(SipralStatus::NotSupported as i32, 11);
    }
}
