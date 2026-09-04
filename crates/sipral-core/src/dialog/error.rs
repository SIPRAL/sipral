// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a dialog can refuse.

use core::fmt;

use crate::msg::{HeaderError, UriError};

/// Why a message could not be made into a dialog, or used inside one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogError {
    /// A field a dialog is built from is missing or does not parse.
    Field(HeaderError),
    /// A URI a dialog has to keep is not a URI.
    Uri(UriError),
    /// The field that names our side of the dialog carries no tag.
    MissingTag,
    /// A response was expected and this is a request, or the other way round.
    WrongKind,
    /// The response neither opens an early dialog nor confirms one: RFC 3261
    /// §12.1 gives that power to 101-199 and 2xx alone.
    NotDialogCreating,
    /// No `Contact` to set the remote target from, or a `Contact: *`, which
    /// names every binding rather than an address to send to.
    NoRemoteTarget,
    /// ACK and CANCEL do not get a sequence number of their own — theirs is
    /// the number of the request they answer (§12.2.1.1) — so they are built
    /// from that request, not from the dialog.
    NotItsOwnRequest,
    /// The local sequence number has reached the 2**31 ceiling of §8.1.1.5.
    SequenceExhausted,
    /// No dialog of that name in this set.
    NoSuchDialog,
}

impl fmt::Display for DialogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Field(e) => write!(f, "dialog field: {e}"),
            Self::Uri(e) => write!(f, "dialog URI: {e}"),
            Self::MissingTag => f.write_str("no tag on our side of the dialog"),
            Self::WrongKind => f.write_str("request where a response was expected, or the reverse"),
            Self::NotDialogCreating => f.write_str("response does not establish a dialog"),
            Self::NoRemoteTarget => f.write_str("no Contact to take the remote target from"),
            Self::NotItsOwnRequest => {
                f.write_str("ACK and CANCEL are built from the request they answer")
            }
            Self::SequenceExhausted => f.write_str("local sequence number exhausted"),
            Self::NoSuchDialog => f.write_str("no dialog of that name here"),
        }
    }
}

impl core::error::Error for DialogError {}

impl From<HeaderError> for DialogError {
    fn from(e: HeaderError) -> Self {
        Self::Field(e)
    }
}

impl From<UriError> for DialogError {
    fn from(e: UriError) -> Self {
        Self::Uri(e)
    }
}
