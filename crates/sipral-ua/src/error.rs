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

use crate::call::CallState;

/// Why a user agent operation could not be started.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UaError {
    /// The handle names an account that was removed, or never added.
    NoSuchAccount,
    /// The handle names a call that has ended, or never existed.
    NoSuchCall,
    /// The call is not somewhere this can be done: answering one that was
    /// placed from here, acknowledging one that is not waiting for it.
    WrongState(CallState),
    /// The request could not be assembled or handed to a transport.
    Send(SendError),
    /// The response could not be sent.
    Respond(RespondError),
    /// The 2xx could not be acknowledged.
    Ack(AckError),
}

impl fmt::Display for UaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoSuchAccount => f.write_str("no such account"),
            Self::NoSuchCall => f.write_str("no such call"),
            Self::WrongState(state) => write!(f, "the call is {state}"),
            Self::Send(ref error) => write!(f, "cannot send it: {error}"),
            Self::Respond(ref error) => write!(f, "cannot answer it: {error}"),
            Self::Ack(ref error) => write!(f, "cannot acknowledge it: {error}"),
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
