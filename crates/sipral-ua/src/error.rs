// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Why something the application asked for could not be done.
//!
//! Nothing here is a registrar refusing, a password being wrong or a network
//! being down. Those are not failures of a call the application made — they
//! arrive later, as events, because they arrive later in reality. What is here
//! is a handle that names nothing, and a request that cannot be built.

use core::fmt;

use sipral_core::endpoint::{AckError, RespondError, SendError};
use sipral_core::sdp::SdpError;

use crate::call::CallState;

/// Why a user agent operation could not be started.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UaError {
    /// The handle names an account that was removed, or never added.
    NoSuchAccount,
    /// The handle names a call that has ended, or never existed.
    NoSuchCall,
    /// The handle names a subscription that has ended, or never existed.
    NoSuchSubscription,
    /// The call is not somewhere this can be done: answering one that was
    /// placed from here, acknowledging one that is not waiting for it.
    WrongState(CallState),
    /// The request could not be assembled or handed to a transport.
    Send(SendError),
    /// The response could not be sent.
    Respond(RespondError),
    /// The 2xx could not be acknowledged.
    Ack(AckError),
    /// Nothing has been described yet, so there is nothing to hold, resume or
    /// re-offer.
    NoSession,
    /// A session change is already running. §14.1 allows one INVITE at a time
    /// inside a dialog, and RFC 3311 §5.2 says the same for UPDATE.
    ChangeInProgress,
    /// Nothing can carry the change: the call is not up, so §14.1 rules out a
    /// re-INVITE, and the far end never advertised UPDATE (RFC 3311 §4).
    CannotRenegotiate,
    /// The session description could not be read.
    Sdp(SdpError),
}

impl fmt::Display for UaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoSuchAccount => f.write_str("no such account"),
            Self::NoSuchCall => f.write_str("no such call"),
            Self::NoSuchSubscription => f.write_str("no such subscription"),
            Self::WrongState(state) => write!(f, "the call is {state}"),
            Self::Send(ref error) => write!(f, "cannot send it: {error}"),
            Self::Respond(ref error) => write!(f, "cannot answer it: {error}"),
            Self::Ack(ref error) => write!(f, "cannot acknowledge it: {error}"),
            Self::NoSession => f.write_str("nothing has been described yet"),
            Self::ChangeInProgress => f.write_str("a session change is already running"),
            Self::CannotRenegotiate => {
                f.write_str("the call is not up and the far end cannot take an UPDATE")
            }
            Self::Sdp(ref error) => write!(f, "cannot read the description: {error}"),
        }
    }
}

impl core::error::Error for UaError {}

impl From<SendError> for UaError {
    fn from(error: SendError) -> Self {
        Self::Send(error)
    }
}

impl From<RespondError> for UaError {
    fn from(error: RespondError) -> Self {
        Self::Respond(error)
    }
}

impl From<AckError> for UaError {
    fn from(error: AckError) -> Self {
        Self::Ack(error)
    }
}
