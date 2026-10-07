// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What every entry point returns. The code is the kind of failure; the
//! sentence is in the thread's last error ([`crate::error`]).

use std::ffi::c_char;
use std::ptr;

use crate::abi::codes;
use crate::error::entry;

codes! {
    /// The result of a call across the C ABI.
    ///
    /// The numbers are ABI: stable for the major version, new ones only at the
    /// end. 17 is reserved forever and never returned.
    ///
    /// Typed `int32_t`: zero is success, failures are positive, none negative.
    /// Read an unknown status from a newer library as a failure.
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
        /// No room: an object table is full, the RTP port range is spent, or a
        /// call's queue (DTMF, payload types, real-time text) is full. Nothing
        /// was done; the last error says which. `SIPRAL_STATUS_LIMIT_REACHED`
        /// is the application's own ceiling.
        Exhausted = 7,
        /// A panic was caught at the boundary. The call did not finish; the last
        /// error carries the panic's message.
        Panic = 8,
        /// Not possible in the object's current state, e.g. answering a call
        /// this end placed, or DTMF before there is a dialog.
        WrongState = 9,
        /// The request could not be assembled or handed to a transport. Nothing
        /// went out, and the call did not change.
        NotSent = 10,
        /// The value is valid in this ABI but this build has no code for it.
        /// Nothing was applied, and retrying will not help. Unlike
        /// [`SipralStatus::InvalidArgument`], the value is not wrong; unlike
        /// [`SipralStatus::UnsupportedVersion`], it is not about struct shape.
        /// Exists so that nothing is ever silently accepted and ignored.
        NotSupported = 11,
        /// A byte stream carried something that starts no known message. A
        /// stream has no resync point: close the connection. The last error
        /// says what was lost.
        StreamBroken = 12,
        /// An audio device id the engine never listed. Refused before any
        /// platform call; `sipral_audio_device_at` lists the ids.
        NoSuchDevice = 13,
        /// The audio device cannot serve: no channels in that direction,
        /// unplugged, or the platform refused it. The last error says which.
        DeviceUnusable = 14,
        /// The platform did not answer about its audio devices within
        /// `sipral_stack_config_t::audio_probe_ms`. Nothing was done.
        DeviceTimedOut = 15,
        /// The stack already holds or awaits `sipral_stack_config_t::max_dialogs`
        /// calls. Nothing went out. An ended call makes room; a higher limit
        /// needs a new stack.
        LimitReached = 16,
        /// Refused by the security policy (ABI 0.31): unencrypted audio where
        /// SRTP is required, or a policy weaker than the account's. A refused
        /// INVITE was answered 488; an outgoing call never left.
        SecurityPolicy = 18,
        /// The recording file would not take a write (disk full, volume gone).
        /// A bad path is `SIPRAL_STATUS_INVALID_ARGUMENT` instead. The recording
        /// stopped; the file holds audio up to the last checkpoint.
        RecordingFailed = 19,
        /// The call never negotiated this, e.g. text on a call with no `m=text`
        /// stream. Only a new accepted offer changes it.
        NotNegotiated = 20,
        /// The far end's Contact never carried `isfocus` (RFC 4579 §4.1), so
        /// there is no conference to name or subscribe to.
        NotAFocus = 21,
        /// The transport has failed or closed and was not bound again. Nothing
        /// went out. Reconnect, call `sipral_stack_transport_bind`, retry.
        TransportDown = 22,
        /// A local conference would not take the call (ABI 0.32): full, the
        /// call is already conferenced or joined with `sipral_call_join`, or its
        /// codec rate is not mixed. The last error says which.
        ConferenceRefused = 23,
        /// `now_ms` was more than 50 ms behind the last reading this stack saw
        /// (ABI 0.33). Nothing was done and the clock did not move; read the
        /// clock again and retry. Repeated, it means the clock went backwards.
        ClockBehind = 24,
        /// The TLS certificate's SHA-256 fingerprint differs from
        /// `sipral_account_config_t::tls_pin_sha256` (ABI 0.34). Refuse the
        /// handshake (`docs/22-tls.md`).
        CertificateRefused = 25,
        /// About to advertise an address the peer cannot reach (ABI 0.34):
        /// loopback to a remote peer, or the unspecified address in a `Contact`.
        /// Nothing was sent; the last error names both addresses.
        /// `sipral_advertised_address` finds the right one.
        UnreachableAddress = 26,
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
            12 => c"stream broken".as_ptr(),
            13 => c"no such device".as_ptr(),
            14 => c"device unusable".as_ptr(),
            15 => c"device timed out".as_ptr(),
            16 => c"limit reached".as_ptr(),
            // 17 is reserved and never used: a permanent hole, with no name
            18 => c"refused by security policy".as_ptr(),
            19 => c"recording failed".as_ptr(),
            20 => c"not negotiated".as_ptr(),
            21 => c"not a focus".as_ptr(),
            22 => c"transport down".as_ptr(),
            23 => c"conference refused".as_ptr(),
            24 => c"clock behind".as_ptr(),
            25 => c"certificate refused".as_ptr(),
            26 => c"unreachable address".as_ptr(),
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
            SipralStatus::StreamBroken,
            SipralStatus::NoSuchDevice,
            SipralStatus::DeviceUnusable,
            SipralStatus::DeviceTimedOut,
            SipralStatus::LimitReached,
            SipralStatus::SecurityPolicy,
            SipralStatus::RecordingFailed,
            SipralStatus::NotNegotiated,
            SipralStatus::NotAFocus,
            SipralStatus::TransportDown,
            SipralStatus::ConferenceRefused,
            SipralStatus::ClockBehind,
            SipralStatus::CertificateRefused,
            SipralStatus::UnreachableAddress,
        ];
        for status in all {
            let code = status as i32;
            assert!(name(code).is_some(), "no name for {status:?}");
        }
    }

    #[test]
    fn the_names_are_distinct() {
        let mut seen = Vec::new();
        for code in (0..=16).chain(18..=26) {
            let Some(text) = name(code) else {
                panic!("no name for {code}");
            };
            assert!(!seen.contains(&text), "{text} appears twice");
            seen.push(text);
        }
    }

    #[test]
    fn a_number_that_is_not_a_status_has_no_name() {
        assert!(name(17).is_none());
        assert!(name(27).is_none());
        assert!(name(-1).is_none());
        assert!(name(i32::MAX).is_none());
        assert!(name(i32::MIN).is_none());
    }

    /// Written out, not derived, so a moved declaration fails here.
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
        assert_eq!(SipralStatus::StreamBroken as i32, 12);
        assert_eq!(SipralStatus::NoSuchDevice as i32, 13);
        assert_eq!(SipralStatus::DeviceUnusable as i32, 14);
        assert_eq!(SipralStatus::DeviceTimedOut as i32, 15);
        assert_eq!(SipralStatus::LimitReached as i32, 16);
        assert_eq!(SipralStatus::SecurityPolicy as i32, 18);
        assert_eq!(SipralStatus::RecordingFailed as i32, 19);
        assert_eq!(SipralStatus::NotNegotiated as i32, 20);
        assert_eq!(SipralStatus::NotAFocus as i32, 21);
        assert_eq!(SipralStatus::TransportDown as i32, 22);
        assert_eq!(SipralStatus::ConferenceRefused as i32, 23);
        assert_eq!(SipralStatus::ClockBehind as i32, 24);
        assert_eq!(SipralStatus::CertificateRefused as i32, 25);
        assert_eq!(SipralStatus::UnreachableAddress as i32, 26);
    }
}
