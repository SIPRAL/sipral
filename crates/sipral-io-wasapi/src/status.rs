// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What Windows returns when it refuses, and what this crate makes of it.

use core::fmt;

/// The `HRESULT` a call returned.
///
/// Held as `i32`, printed in hex (searchable), with the codes this crate can
/// meet named.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HResult(i32);

impl HResult {
    /// `S_OK`.
    pub const OK: Self = Self(0);

    /// `S_FALSE`, which several calls use to mean "not quite" rather than
    /// "no": `IsFormatSupported` returns it with a closest match attached.
    pub const FALSE: Self = Self(1);

    /// Wrap a code a call returned.
    #[must_use]
    pub const fn new(code: i32) -> Self {
        Self(code)
    }

    /// The integer underneath.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.0
    }

    /// Whether the call succeeded. The top bit is the whole of the test, so
    /// `S_FALSE` counts as success — which is exactly what it means.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        self.0 >= 0
    }

    /// The name Windows gives this code, when it is one this crate can meet.
    ///
    /// Only codes checked against their header; a wrong name is worse than none.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "S_OK",
            1 => "S_FALSE",
            E_NOINTERFACE => "E_NOINTERFACE",
            E_POINTER => "E_POINTER",
            E_OUTOFMEMORY => "E_OUTOFMEMORY",
            E_INVALIDARG => "E_INVALIDARG",
            E_NOTFOUND => "E_NOTFOUND",
            RPC_E_CHANGED_MODE => "RPC_E_CHANGED_MODE",
            AUDCLNT_E_NOT_INITIALIZED => "AUDCLNT_E_NOT_INITIALIZED",
            AUDCLNT_E_ALREADY_INITIALIZED => "AUDCLNT_E_ALREADY_INITIALIZED",
            AUDCLNT_E_WRONG_ENDPOINT_TYPE => "AUDCLNT_E_WRONG_ENDPOINT_TYPE",
            AUDCLNT_E_DEVICE_INVALIDATED => "AUDCLNT_E_DEVICE_INVALIDATED",
            AUDCLNT_E_NOT_STOPPED => "AUDCLNT_E_NOT_STOPPED",
            AUDCLNT_E_BUFFER_TOO_LARGE => "AUDCLNT_E_BUFFER_TOO_LARGE",
            AUDCLNT_E_OUT_OF_ORDER => "AUDCLNT_E_OUT_OF_ORDER",
            AUDCLNT_E_UNSUPPORTED_FORMAT => "AUDCLNT_E_UNSUPPORTED_FORMAT",
            AUDCLNT_E_INVALID_SIZE => "AUDCLNT_E_INVALID_SIZE",
            AUDCLNT_E_DEVICE_IN_USE => "AUDCLNT_E_DEVICE_IN_USE",
            AUDCLNT_E_BUFFER_OPERATION_PENDING => "AUDCLNT_E_BUFFER_OPERATION_PENDING",
            AUDCLNT_E_THREAD_NOT_REGISTERED => "AUDCLNT_E_THREAD_NOT_REGISTERED",
            AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED => "AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED",
            AUDCLNT_E_ENDPOINT_CREATE_FAILED => "AUDCLNT_E_ENDPOINT_CREATE_FAILED",
            AUDCLNT_E_SERVICE_NOT_RUNNING => "AUDCLNT_E_SERVICE_NOT_RUNNING",
            AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED => "AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED",
            AUDCLNT_E_EXCLUSIVE_MODE_ONLY => "AUDCLNT_E_EXCLUSIVE_MODE_ONLY",
            AUDCLNT_E_BUFDURATION_PERIOD_NOT_EQUAL => "AUDCLNT_E_BUFDURATION_PERIOD_NOT_EQUAL",
            AUDCLNT_E_EVENTHANDLE_NOT_SET => "AUDCLNT_E_EVENTHANDLE_NOT_SET",
            AUDCLNT_E_INCORRECT_BUFFER_SIZE => "AUDCLNT_E_INCORRECT_BUFFER_SIZE",
            AUDCLNT_E_BUFFER_SIZE_ERROR => "AUDCLNT_E_BUFFER_SIZE_ERROR",
            AUDCLNT_E_CPUUSAGE_EXCEEDED => "AUDCLNT_E_CPUUSAGE_EXCEEDED",
            AUDCLNT_E_BUFFER_ERROR => "AUDCLNT_E_BUFFER_ERROR",
            AUDCLNT_E_BUFFER_SIZE_NOT_ALIGNED => "AUDCLNT_E_BUFFER_SIZE_NOT_ALIGNED",
            AUDCLNT_E_INVALID_DEVICE_PERIOD => "AUDCLNT_E_INVALID_DEVICE_PERIOD",
            AUDCLNT_E_INVALID_STREAM_FLAG => "AUDCLNT_E_INVALID_STREAM_FLAG",
            AUDCLNT_E_RESOURCES_INVALIDATED => "AUDCLNT_E_RESOURCES_INVALIDATED",
            _ => return None,
        })
    }
}

impl fmt::Display for HResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // cast rather than sign-extend: an HRESULT is a bit pattern that is
        // read as eight hex digits, and `0xffffffff88890008` is not it
        let bits = self.0.cast_unsigned();
        match self.name() {
            Some(name) => write!(f, "0x{bits:08x} ({name})"),
            None => write!(f, "0x{bits:08x}"),
        }
    }
}

impl From<i32> for HResult {
    fn from(code: i32) -> Self {
        Self(code)
    }
}

/// `E_NOINTERFACE`, from `winerror.h`.
pub(crate) const E_NOINTERFACE: i32 = 0x8000_4002_u32.cast_signed();

/// `E_POINTER`, from `winerror.h`.
pub(crate) const E_POINTER: i32 = 0x8000_4003_u32.cast_signed();

/// `E_OUTOFMEMORY`, from `winerror.h`.
const E_OUTOFMEMORY: i32 = 0x8007_000e_u32.cast_signed();

/// `E_INVALIDARG`, from `winerror.h`.
const E_INVALIDARG: i32 = 0x8007_0057_u32.cast_signed();

/// `E_NOTFOUND`, `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`: what
/// `GetDefaultAudioEndpoint` says when the machine has no endpoint at all in
/// that direction, which is a fact about the machine and not a failure.
pub(crate) const E_NOTFOUND: i32 = 0x8007_0490_u32.cast_signed();

/// `RPC_E_CHANGED_MODE`: `CoInitializeEx` was asked for an apartment the
/// thread is already not in. It means the thread was initialised by somebody
/// else, which is a fact rather than a failure.
pub(crate) const RPC_E_CHANGED_MODE: i32 = 0x8001_0106_u32.cast_signed();

/// The audio client's facility, `FACILITY_AUDCLNT`, shifted into place with
/// the severity bit: `AUDCLNT_ERR(n)` from `Audioclient.h` is
/// `MAKE_HRESULT(SEVERITY_ERROR, FACILITY_AUDCLNT, n)`, and every code below
/// is that macro applied to the number the header gives.
const fn audclnt(code: u32) -> i32 {
    (0x8889_0000 | code).cast_signed()
}

const AUDCLNT_E_NOT_INITIALIZED: i32 = audclnt(0x001);
const AUDCLNT_E_ALREADY_INITIALIZED: i32 = audclnt(0x002);
const AUDCLNT_E_WRONG_ENDPOINT_TYPE: i32 = audclnt(0x003);
pub(crate) const AUDCLNT_E_DEVICE_INVALIDATED: i32 = audclnt(0x004);
const AUDCLNT_E_NOT_STOPPED: i32 = audclnt(0x005);
const AUDCLNT_E_BUFFER_TOO_LARGE: i32 = audclnt(0x006);
const AUDCLNT_E_OUT_OF_ORDER: i32 = audclnt(0x007);
pub(crate) const AUDCLNT_E_UNSUPPORTED_FORMAT: i32 = audclnt(0x008);
const AUDCLNT_E_INVALID_SIZE: i32 = audclnt(0x009);
const AUDCLNT_E_DEVICE_IN_USE: i32 = audclnt(0x00a);
const AUDCLNT_E_BUFFER_OPERATION_PENDING: i32 = audclnt(0x00b);
const AUDCLNT_E_THREAD_NOT_REGISTERED: i32 = audclnt(0x00c);
const AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED: i32 = audclnt(0x00e);
const AUDCLNT_E_ENDPOINT_CREATE_FAILED: i32 = audclnt(0x00f);
const AUDCLNT_E_SERVICE_NOT_RUNNING: i32 = audclnt(0x010);
const AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED: i32 = audclnt(0x011);
const AUDCLNT_E_EXCLUSIVE_MODE_ONLY: i32 = audclnt(0x012);
const AUDCLNT_E_BUFDURATION_PERIOD_NOT_EQUAL: i32 = audclnt(0x013);
const AUDCLNT_E_EVENTHANDLE_NOT_SET: i32 = audclnt(0x014);
const AUDCLNT_E_INCORRECT_BUFFER_SIZE: i32 = audclnt(0x015);
const AUDCLNT_E_BUFFER_SIZE_ERROR: i32 = audclnt(0x016);
const AUDCLNT_E_CPUUSAGE_EXCEEDED: i32 = audclnt(0x017);
const AUDCLNT_E_BUFFER_ERROR: i32 = audclnt(0x018);
const AUDCLNT_E_BUFFER_SIZE_NOT_ALIGNED: i32 = audclnt(0x019);
const AUDCLNT_E_INVALID_DEVICE_PERIOD: i32 = audclnt(0x020);
const AUDCLNT_E_INVALID_STREAM_FLAG: i32 = audclnt(0x021);
const AUDCLNT_E_RESOURCES_INVALIDATED: i32 = audclnt(0x026);

/// Why device I/O could not be set up or kept running.
///
/// Device arrivals and removals are not errors; see
/// [`DeviceEvent`](crate::DeviceEvent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A Windows call refused.
    Call {
        /// The entry point, as Microsoft documents it.
        call: &'static str,
        /// What it returned.
        status: HResult,
    },
    /// The endpoint's mix format is neither float nor integer PCM.
    SampleFormat {
        /// Bits in one sample of one channel, as the endpoint declares them.
        bits: u16,
        /// Whether the endpoint says the samples are floating point.
        floating: bool,
    },
    /// No endpoint answered: the machine has none in that direction, or the
    /// one the caller named is not there any more.
    NoDevice,
    /// The worker thread could not be started (out of threads or memory).
    NoThread,
    /// The audio thread did not answer in time (stuck in a driver call).
    /// Nothing was joined or closed: closing a handle it waits on could crash.
    Draining {
        /// Milliseconds spent waiting before giving up.
        waited_millis: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Call { call, status } => write!(f, "{call} returned {status}"),
            Self::SampleFormat { bits, floating } => write!(
                f,
                "the endpoint runs {bits}-bit {} samples, which this crate does not read",
                if floating {
                    "floating point"
                } else {
                    "integer"
                }
            ),
            Self::NoDevice => f.write_str("no audio endpoint in that direction"),
            Self::NoThread => f.write_str("the audio thread could not be started"),
            Self::Draining { waited_millis } => write!(
                f,
                "the audio thread was still running after {waited_millis} ms, so nothing was closed"
            ),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::{AUDCLNT_E_UNSUPPORTED_FORMAT, Error, HResult, audclnt};

    #[test]
    fn a_named_code_reads_as_its_name() {
        let status = HResult::new(AUDCLNT_E_UNSUPPORTED_FORMAT);
        assert!(!status.is_ok());
        assert_eq!(status.name(), Some("AUDCLNT_E_UNSUPPORTED_FORMAT"));
        assert_eq!(
            status.to_string(),
            "0x88890008 (AUDCLNT_E_UNSUPPORTED_FORMAT)"
        );
    }

    #[test]
    fn the_facility_macro_lands_where_the_header_says() {
        // AUDCLNT_ERR(0x004) is AUDCLNT_E_DEVICE_INVALIDATED, and the whole
        // family is the severity bit, facility 0x889 and the number
        assert_eq!(audclnt(0x004), 0x8889_0004_u32.cast_signed());
        assert_eq!(
            super::AUDCLNT_E_DEVICE_INVALIDATED,
            0x8889_0004_u32.cast_signed()
        );
    }

    #[test]
    fn an_unnamed_code_stays_a_number() {
        let status = HResult::new(0x8004_2317_u32.cast_signed());
        assert_eq!(status.name(), None);
        assert_eq!(status.to_string(), "0x80042317");
    }

    #[test]
    fn success_is_the_top_bit_and_nothing_else() {
        assert!(HResult::OK.is_ok());
        assert!(HResult::FALSE.is_ok());
        assert_eq!(HResult::OK.to_string(), "0x00000000 (S_OK)");
        assert_eq!(HResult::FALSE.to_string(), "0x00000001 (S_FALSE)");
        assert!(!HResult::new(super::E_POINTER).is_ok());
        assert_eq!(
            HResult::new(super::E_POINTER).to_string(),
            "0x80004003 (E_POINTER)"
        );
    }

    #[test]
    fn an_error_names_the_call_and_the_code() {
        let error = Error::Call {
            call: "IAudioClient::Initialize",
            status: HResult::new(super::AUDCLNT_E_DEVICE_IN_USE),
        };
        assert_eq!(
            error.to_string(),
            "IAudioClient::Initialize returned 0x8889000a (AUDCLNT_E_DEVICE_IN_USE)"
        );
    }

    #[test]
    fn the_rest_of_the_errors_read_as_sentences() {
        assert_eq!(
            Error::SampleFormat {
                bits: 24,
                floating: false
            }
            .to_string(),
            "the endpoint runs 24-bit integer samples, which this crate does not read"
        );
        assert_eq!(
            Error::SampleFormat {
                bits: 64,
                floating: true
            }
            .to_string(),
            "the endpoint runs 64-bit floating point samples, which this crate does not read"
        );
        assert_eq!(
            Error::NoDevice.to_string(),
            "no audio endpoint in that direction"
        );
        assert_eq!(
            Error::NoThread.to_string(),
            "the audio thread could not be started"
        );
        assert_eq!(
            Error::Draining {
                waited_millis: 2_000
            }
            .to_string(),
            "the audio thread was still running after 2000 ms, so nothing was closed"
        );
    }
}
