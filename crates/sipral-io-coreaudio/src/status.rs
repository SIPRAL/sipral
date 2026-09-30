// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the frameworks return when they refuse, and what this crate makes of it.

use core::fmt;

/// The `OSStatus` a CoreAudio call returned.
///
/// Apple names most of these as four-character codes — `'!dev'` for a device
/// identifier that is not one, `'nope'` for an operation the object does not
/// allow — and the decimal integer is unsearchable, so the display shows the
/// characters when the four bytes are printable and the number when they are
/// not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OsStatus(i32);

impl OsStatus {
    /// `noErr`.
    pub const OK: Self = Self(0);

    /// The status as the framework returned it.
    #[must_use]
    pub const fn new(code: i32) -> Self {
        Self(code)
    }

    /// The integer underneath.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.0
    }

    /// Whether the call succeeded.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        self.0 == 0
    }

    /// The four characters, in the order they are read, when all four are
    /// printable ASCII. A status that is a plain negative number has none.
    #[must_use]
    pub const fn four_char_code(self) -> Option<[u8; 4]> {
        let code = self.0.to_be_bytes();
        let [first, second, third, fourth] = code;
        if printable(first) && printable(second) && printable(third) && printable(fourth) {
            Some(code)
        } else {
            None
        }
    }
}

/// Space counts: codes like `'who '` and `'uid '` are padded with one.
const fn printable(byte: u8) -> bool {
    byte.is_ascii_graphic() || byte == b' '
}

impl fmt::Display for OsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.four_char_code() {
            Some(code) => match core::str::from_utf8(&code) {
                Ok(text) => write!(f, "'{text}' ({})", self.0),
                Err(_) => write!(f, "{}", self.0),
            },
            None => write!(f, "{}", self.0),
        }
    }
}

impl From<i32> for OsStatus {
    fn from(code: i32) -> Self {
        Self(code)
    }
}

/// Why device I/O could not be set up or kept running.
///
/// Nothing here is a device disappearing or a route changing. Those are not
/// failures — they are what a Mac with a headset does all day, and they arrive
/// as [`DeviceEvent`](crate::DeviceEvent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A framework call refused.
    Call {
        /// The entry point that refused, under the name Apple documents it by,
        /// because that is the name the status has to be looked up beside.
        call: &'static str,
        /// What it returned.
        status: OsStatus,
    },
    /// No voice-processing I/O unit is registered here. On a Mac that is a
    /// broken installation rather than a configuration to fix.
    UnitMissing,
    /// A voice-processing unit is already open in this process, and there is
    /// room for one.
    Busy,
    /// Shutting down could not establish that the framework's callbacks had
    /// left the memory they were given, so none of it was freed and none of it
    /// ever will be. Something is wedged inside the audio stack; the leak is
    /// the deliberate alternative to a realtime thread reading freed memory.
    Draining {
        /// Milliseconds spent waiting before giving up.
        waited_millis: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Call { call, status } => write!(f, "{call} returned {status}"),
            Self::UnitMissing => f.write_str("no voice-processing I/O unit on this system"),
            Self::Busy => f.write_str("a voice-processing I/O unit is already open in this process"),
            Self::Draining { waited_millis } => write!(
                f,
                "a device callback was still running after {waited_millis} ms, so nothing was freed"
            ),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::{Error, OsStatus};

    #[test]
    fn a_printable_status_reads_as_its_characters() {
        // 'nope', the illegal-operation status of the hardware layer
        let status = OsStatus::new(i32::from_be_bytes(*b"nope"));
        assert_eq!(status.four_char_code(), Some(*b"nope"));
        assert_eq!(status.to_string(), "'nope' (1852797029)");
    }

    #[test]
    fn a_status_with_a_space_in_it_still_reads() {
        let status = OsStatus::new(i32::from_be_bytes(*b"who "));
        assert_eq!(status.to_string(), "'who ' (2003332896)");
    }

    #[test]
    fn a_numeric_status_stays_a_number() {
        // kAudioUnitErr_FormatNotSupported: high bytes are 0xff, not characters
        let status = OsStatus::new(-10868);
        assert_eq!(status.four_char_code(), None);
        assert_eq!(status.to_string(), "-10868");
    }

    #[test]
    fn zero_is_not_a_code_either() {
        assert!(OsStatus::OK.is_ok());
        assert_eq!(OsStatus::OK.four_char_code(), None);
        assert_eq!(OsStatus::OK.to_string(), "0");
    }

    #[test]
    fn an_error_names_the_call_and_the_status() {
        let error = Error::Call {
            call: "AudioUnitInitialize",
            status: OsStatus::new(-10875),
        };
        assert_eq!(error.to_string(), "AudioUnitInitialize returned -10875");

        let refused = Error::Call {
            call: "AudioObjectGetPropertyData",
            status: OsStatus::new(i32::from_be_bytes(*b"!obj")),
        };
        assert_eq!(
            refused.to_string(),
            "AudioObjectGetPropertyData returned '!obj' (560947818)"
        );
    }

    #[test]
    fn the_missing_unit_says_so() {
        assert_eq!(
            Error::UnitMissing.to_string(),
            "no voice-processing I/O unit on this system"
        );
    }
}
