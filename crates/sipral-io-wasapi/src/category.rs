// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a stream was opened as, and what that does and does not buy.
//!
//! Windows applies the endpoint's own voice processing — echo cancellation,
//! noise suppression, automatic gain — to a stream that has said it is a call,
//! and to no other kind. Saying so is one call, `SetClientProperties` on
//! `IAudioClient2`, made after the client is activated and before it is
//! initialised; there is no second chance, because a client that has been
//! initialised refuses it.
//!
//! What Windows does not offer is a way to ask afterwards whether anything is
//! actually cancelling. The processing belongs to the endpoint and its driver,
//! a person can switch it off in the sound settings, and an endpoint whose
//! driver ships none reports nothing missing. So [`Category`] says what was
//! asked and what Windows said to the asking, and stops there — a type that
//! claimed more would be believed.

use core::fmt;

use crate::status::HResult;

/// What Windows was asked to treat a stream as, and what it made of the
/// asking.
///
/// [`Category::Communications`] is the answer to want. It does not promise
/// that echo is being cancelled — see the module documentation for why nothing
/// can — but it is the condition Windows attaches its own processing to, and
/// without it there is certainly none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Category {
    /// The stream was declared `AudioCategory_Communications` before it was
    /// initialised, and Windows accepted the declaration.
    ///
    /// Three things follow from it, all of them Windows's rather than this
    /// crate's: the stream follows the endpoint the user chose for calls,
    /// other applications duck under it, and the endpoint's voice processing
    /// runs on it where the driver has any.
    Communications,
    /// The client would not answer to `IAudioClient2`, so there was nothing to
    /// declare the category to and the stream is whatever Windows opens by
    /// default. `IAudioClient2` arrived in Windows 8; a machine without it is
    /// older than any supported Windows.
    Unavailable,
    /// The stream was declared `AudioCategory_Communications` with
    /// `AUDCLNT_STREAMOPTIONS_RAW`, and Windows accepted: a call for routing
    /// and ducking, with the endpoint's processing — its echo canceller
    /// among it — out of the path, as the application asked.
    Raw,
    /// `SetClientProperties` refused, carrying this.
    ///
    /// The stream still opened — the category is asked for before the client
    /// is initialised and a refusal is not fatal to it — and it is an ordinary
    /// stream, with the same consequence as [`Category::Unavailable`].
    Refused(HResult),
}

impl Category {
    /// What a `SetClientProperties` that returned `status` amounts to.
    ///
    /// Here rather than beside the call so that the one decision in the
    /// sequence can be shown to be right on a machine with no Windows on it.
    /// What is left up there is the plumbing: an identifier, a vtable slot and
    /// a structure, none of which has an opinion.
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
    /// `false` is the case worth acting on: the application's own processor is
    /// what stands between the far end and its own echo then, attached at the
    /// seam `docs/05-media.md` describes and given a render delay taken from
    /// the two streams' own `latency`.
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
