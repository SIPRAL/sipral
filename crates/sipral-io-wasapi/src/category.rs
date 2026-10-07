// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a stream was opened as, and what that does and does not buy.
//!
//! The endpoint's voice processing (AEC, NS, AGC) runs only on streams
//! declared as calls via `IAudioClient2::SetClientProperties`, between
//! activation and initialisation.
//!
//! Windows cannot be asked whether anything is actually cancelling: the
//! processing is the driver's and can be switched off by the user. So
//! [`Category`] only reports what was asked and what Windows answered.

use core::fmt;

use crate::status::HResult;

/// What a stream was declared as, and whether Windows accepted.
///
/// [`Category::Communications`] does not prove echo is cancelled, but without
/// it there is certainly no system processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Category {
    /// The stream was declared `AudioCategory_Communications` before it was
    /// initialised, and Windows accepted the declaration.
    ///
    /// The stream follows the user's call device, ducks other applications,
    /// and gets the endpoint's voice processing where the driver has any.
    Communications,
    /// No `IAudioClient2` (pre-Windows 8): an ordinary stream.
    Unavailable,
    /// Communications with `AUDCLNT_STREAMOPTIONS_RAW`, accepted: call
    /// routing and ducking, no endpoint processing, as asked.
    Raw,
    /// `SetClientProperties` refused with this. The stream still opened, as
    /// an ordinary one, like [`Category::Unavailable`].
    Refused(HResult),
}

impl Category {
    /// What a `SetClientProperties` that returned `status` amounts to.
    ///
    /// Separate from the call so it can be tested off Windows.
    #[cfg(any(target_os = "windows", test))]
    pub(crate) const fn from_status(status: HResult, processing: bool) -> Self {
        match (status.is_ok(), processing) {
            (true, true) => Self::Communications,
            (true, false) => Self::Raw,
            (false, _) => Self::Refused(status),
        }
    }

    /// Whether the stream is a communications stream with the endpoint's
    /// processing behind it; [`Category::Raw`] is a call too, but has none.
    ///
    /// On `false`, attach the application's own processor
    /// (`docs/05-media.md`) with the two streams' `latency` as render delay.
    #[must_use]
    pub const fn is_communications(self) -> bool {
        matches!(self, Self::Communications)
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Communications => f.write_str("a communications stream"),
            Self::Raw => f.write_str("a communications stream past the endpoint's processing"),
            Self::Unavailable => {
                f.write_str("an ordinary stream: this client has no IAudioClient2")
            }
            Self::Refused(status) => write!(
                f,
                "an ordinary stream: IAudioClient2::SetClientProperties returned {status}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Category;
    use crate::status::HResult;

    #[test]
    fn only_a_stream_windows_accepted_the_category_for_is_a_communications_one() {
        assert!(Category::Communications.is_communications());
        assert!(!Category::Unavailable.is_communications());
        assert!(!Category::Refused(HResult::OK).is_communications());
    }

    #[test]
    fn only_a_call_that_returned_success_leaves_a_communications_stream() {
        assert_eq!(
            Category::from_status(HResult::OK, true),
            Category::Communications
        );
        assert_eq!(Category::from_status(HResult::OK, false), Category::Raw);
        assert!(
            !Category::Raw.is_communications(),
            "raw has no processing to claim"
        );
        // AUDCLNT_E_ALREADY_INITIALIZED, and E_INVALIDARG, which is what a
        // cbSize from the wrong version of the header would earn
        for refusal in [0x8889_0002_u32, 0x8007_0057] {
            let status = HResult::new(refusal.cast_signed());
            assert_eq!(
                Category::from_status(status, true),
                Category::Refused(status)
            );
            assert!(!Category::from_status(status, true).is_communications());
        }
    }

    #[test]
    fn a_refusal_carries_what_windows_said_rather_than_only_that_it_said_no() {
        // AUDCLNT_E_ALREADY_INITIALIZED, which is what a client that had been
        // initialised first would answer, and the mistake this call is
        // easiest to make
        let refused = Category::Refused(HResult::new(0x8889_0002_u32.cast_signed()));
        assert_eq!(
            refused.to_string(),
            "an ordinary stream: IAudioClient2::SetClientProperties returned \
             0x88890002 (AUDCLNT_E_ALREADY_INITIALIZED)"
        );
        assert_eq!(
            Category::Communications.to_string(),
            "a communications stream"
        );
        assert_eq!(
            Category::Unavailable.to_string(),
            "an ordinary stream: this client has no IAudioClient2"
        );
    }
}
