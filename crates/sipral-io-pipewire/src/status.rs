// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What PipeWire returns when it refuses, and what this crate makes of it.

use core::fmt;

/// The `errno` magnitude a PipeWire or SPA call returned.
///
/// The convention across `libpipewire` and SPA is a plain negated `errno`:
/// zero or a positive number is success, and a negative one is `-errno`. This
/// type stores the positive magnitude, because that is what
/// [`std::io::Error::from_raw_os_error`] and every `strerror` table index by,
/// and turns the two-argument convention of the C side into one number here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Errno(i32);

impl Errno {
    /// Read a raw return value from a PipeWire or SPA call.
    ///
    /// `None` when `code` was zero or positive: that call succeeded, and there
    /// is no `errno` to report. Otherwise the magnitude of a negative `code`.
    #[must_use]
    pub const fn from_return(code: i32) -> Option<Self> {
        if code < 0 { Some(Self(-code)) } else { None }
    }

    /// The positive `errno` number underneath.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.0
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            std::io::Error::from_raw_os_error(self.0),
            self.0
        )
    }
}

/// Why device I/O could not be set up or kept running.
///
/// Nothing here is a device disappearing or the default route changing.
/// Those are not failures — they are what a Linux desktop with a headset does
/// all day, and they arrive as [`DeviceEvent`](crate::DeviceEvent).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A `libpipewire` or SPA call returned a negative `errno`.
    Call {
        /// The entry point that refused, under the name PipeWire documents it
        /// by, because that is the name the manual and the source are read
        /// under.
        call: &'static str,
        /// What it returned.
        errno: Errno,
    },
    /// A call that reports failure with a null pointer rather than an
    /// `errno` — `pw_stream_new_simple`, `pw_context_connect`, `pw_thread_loop_new`
    /// among them — returned one.
    Refused {
        /// The entry point that returned null.
        call: &'static str,
    },
    /// The stream reported `PW_STREAM_STATE_ERROR`, with the message the
    /// server or the local adapter attached to it.
    StreamError {
        /// What PipeWire said, or an empty string when it said nothing.
        message: String,
    },
    /// No node answered: the graph has none in that direction, or the one
    /// [`DeviceChoice::Device`](crate::DeviceChoice::Device) named is not
    /// there any more. The first case is a session-manager configuration to
    /// fix rather than a fault in this crate.
    NoDevice,
    /// Shutting down could not establish that PipeWire's own realtime data
    /// thread had left the memory a stream gave it, so none of it was freed
    /// and none of it ever will be. Something is wedged in the graph; the
    /// leak is the deliberate alternative to that thread reading freed
    /// memory.
    Draining {
        /// Milliseconds spent waiting before giving up.
        waited_millis: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Call { call, errno } => write!(f, "{call} returned {errno}"),
            Self::Refused { call } => write!(f, "{call} returned null"),
            Self::StreamError { ref message } if message.is_empty() => {
                f.write_str("the stream reported an error")
            }
            Self::StreamError { ref message } => {
                write!(f, "the stream reported an error: {message}")
            }
            Self::NoDevice => f.write_str("no matching sink or source is on the graph"),
            Self::Draining { waited_millis } => write!(
                f,
                "a stream callback was still running after {waited_millis} ms, so nothing was freed"
            ),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::{Errno, Error};

    #[test]
    fn success_codes_carry_no_errno() {
        assert_eq!(Errno::from_return(0), None);
        assert_eq!(Errno::from_return(4), None);
    }

    #[test]
    fn a_negative_code_is_its_positive_magnitude() {
        // -EINVAL on Linux
        let errno = Errno::from_return(-22).expect("negative");
        assert_eq!(errno.code(), 22);
        assert!(errno.to_string().contains("(22)"));
    }

    #[test]
    fn an_error_names_the_call_and_the_errno() {
        let error = Error::Call {
            call: "pw_stream_connect",
            errno: Errno::from_return(-2).expect("negative"), // -ENOENT
        };
        assert!(error.to_string().starts_with("pw_stream_connect returned"));
        assert!(error.to_string().contains("(2)"));
    }

    #[test]
    fn a_refusal_names_the_call() {
        assert_eq!(
            Error::Refused {
                call: "pw_thread_loop_new"
            }
            .to_string(),
            "pw_thread_loop_new returned null"
        );
    }

    #[test]
    fn a_stream_error_carries_its_message_or_says_it_had_none() {
        assert_eq!(
            Error::StreamError {
                message: "connection refused".to_string()
            }
            .to_string(),
            "the stream reported an error: connection refused"
        );
        assert_eq!(
            Error::StreamError {
                message: String::new()
            }
            .to_string(),
            "the stream reported an error"
        );
    }

    #[test]
    fn no_device_and_draining_read_as_sentences() {
        assert_eq!(
            Error::NoDevice.to_string(),
            "no matching sink or source is on the graph"
        );
        assert_eq!(
            Error::Draining {
                waited_millis: 2_000
            }
            .to_string(),
            "a stream callback was still running after 2000 ms, so nothing was freed"
        );
    }
}
