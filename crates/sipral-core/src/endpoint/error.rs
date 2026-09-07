// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One enum per operation, `Display` written out by hand.
//!
//! No `thiserror`: `sipral-core` has no dependencies, and an error type is
//! where that promise would be easiest to break for the least reason.
//!
//! Nothing here is a failure of the far end. A response that never came, a
//! transport that died, a peer answering 500 — none of those are errors of an
//! operation the caller performed, and all of them arrive as events. What is
//! here is the caller asking for something that cannot be done: a request
//! missing a field it has to have, a handle that named a transaction which no
//! longer exists, bytes that are not a message.

use core::fmt;

use crate::dialog::DialogError;
use crate::msg::{BuildError, HeaderError, ParseError};

/// Why bytes handed to the endpoint could not be taken.
///
/// A malformed datagram is the normal case on a public SIP port rather than a
/// fault: nothing is broken, the packet is gone, and the caller carries on.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiveError {
    /// Bytes arrived on a transport the endpoint was never told about.
    UnknownTransport,
    /// Stream bytes arrived on a transport that is not a byte stream, or a
    /// datagram on one that is.
    WrongKindOfTransport,
    /// The bytes are not a SIP message.
    ///
    /// On a datagram this costs one packet. On a byte stream it costs the
    /// connection: framing that is wrong cannot be resynchronised, so the
    /// endpoint forgets the transport and the caller should close it.
    Malformed(ParseError),
}

impl fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnknownTransport => f.write_str("no such transport"),
            Self::WrongKindOfTransport => f.write_str("wrong kind of transport"),
            Self::Malformed(ref error) => write!(f, "malformed message: {error}"),
        }
    }
}

impl core::error::Error for ReceiveError {}

impl From<ParseError> for ReceiveError {
    fn from(error: ParseError) -> Self {
        Self::Malformed(error)
    }
}

/// Why a request could not be sent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendError {
    /// A field the request cannot go out without was not set.
    MissingField(&'static str),
    /// The request names a transport the endpoint was never told about.
    UnknownTransport,
    /// The message could not be assembled from what was given.
    Build(BuildError),
    /// The message was assembled but has no `Via` branch to be keyed on,
    /// which means it cannot become a transaction.
    NotKeyable(HeaderError),
    /// The request is too large for a datagram (RFC 3261 §18.1.1) and no
    /// stream transport is open to move it to.
    ///
    /// An `Event::TransportWanted` says what to open; the request is not
    /// held, and is sent again by the caller once it is.
    NeedsStreamTransport,
    /// The handle names a dialog that has ended, or never existed.
    NoSuchDialog,
    /// The dialog refused to produce the request: a method it does not send,
    /// or a sequence space that has run out.
    Dialog(DialogError),
    /// The method does not go out through the call it was given to. An INVITE
    /// inside a dialog is a re-INVITE: it runs on an INVITE client transaction
    /// and owns an ACK, so it goes out through [`super::Endpoint::reinvite`].
    WrongMethod,
    /// An INVITE is already running in this dialog, in one direction or the
    /// other. §14.1: "a UAC MUST NOT initiate a new INVITE transaction within
    /// a dialog while another INVITE transaction is in progress in either
    /// direction." Two that cross are answered 491 by whichever end receives
    /// the second one, so sending it buys nothing but a round trip.
    InviteInProgress,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MissingField(name) => write!(f, "no {name}"),
            Self::UnknownTransport => f.write_str("no such transport"),
            Self::Build(ref error) => write!(f, "cannot build the request: {error}"),
            Self::NotKeyable(ref error) => write!(f, "cannot key the transaction: {error}"),
            Self::NeedsStreamTransport => {
                f.write_str("too large for a datagram and no stream transport is open")
            }
            Self::NoSuchDialog => f.write_str("no such dialog"),
            Self::Dialog(ref error) => write!(f, "the dialog refused it: {error}"),
            Self::WrongMethod => f.write_str("that method does not go out on this call"),
            Self::InviteInProgress => {
                f.write_str("an INVITE is already in progress in this dialog")
            }
        }
    }
}

impl core::error::Error for SendError {}

impl From<BuildError> for SendError {
    fn from(error: BuildError) -> Self {
        Self::Build(error)
    }
}

impl From<HeaderError> for SendError {
    fn from(error: HeaderError) -> Self {
        Self::NotKeyable(error)
    }
}

/// Why a response could not be sent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RespondError {
    /// The handle names a transaction that has ended, or never existed.
    NoSuchTransaction,
    /// The response could not be assembled from what was given.
    Build(BuildError),
    /// The transaction is past the point where this response could go out:
    /// §17.2.2 discards a second final response rather than sending it.
    TooLate,
    /// The INVITE carried `Require: 100rel`, so a non-100 provisional response
    /// to it has to be sent reliably (RFC 3262 §3). Use
    /// [`super::Endpoint::respond_reliable`].
    MustBeReliable,
    /// Only 101 to 199 may be sent reliably. A 100 is hop by hop, and the
    /// mechanism is end to end.
    NotProvisional,
    /// The INVITE listed `100rel` in neither `Supported` nor `Require`, so the
    /// far end has not agreed to acknowledge one.
    NotOffered,
    /// A reliable provisional response is still unacknowledged. §3: "The UAS
    /// MUST NOT send a second reliable provisional response until the first is
    /// acknowledged."
    StillUnacknowledged,
}

impl fmt::Display for RespondError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoSuchTransaction => f.write_str("no such transaction"),
            Self::Build(ref error) => write!(f, "cannot build the response: {error}"),
            Self::TooLate => f.write_str("the transaction has already answered"),
            Self::MustBeReliable => f.write_str("this INVITE requires 100rel"),
            Self::NotProvisional => f.write_str("only 101 to 199 may be sent reliably"),
            Self::NotOffered => f.write_str("the far end did not offer 100rel"),
            Self::StillUnacknowledged => {
                f.write_str("the previous reliable response is unacknowledged")
            }
        }
    }
}

impl core::error::Error for RespondError {}

impl From<BuildError> for RespondError {
    fn from(error: BuildError) -> Self {
        Self::Build(error)
    }
}

/// Why a call could not be given up on.
///
/// There is no "too early" here. A CANCEL that cannot go yet is held until
/// the first provisional response arrives (§9.1), so asking too soon is not a
/// failure and the caller never has to time it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelError {
    /// The handle names a transaction that has ended, or never existed.
    NoSuchTransaction,
    /// A final response has already arrived, and "a CANCEL has no effect on
    /// requests that have already generated a final response".
    AlreadyAnswered,
    /// The CANCEL could not be assembled from the INVITE.
    Build(BuildError),
}

impl fmt::Display for CancelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoSuchTransaction => f.write_str("no such transaction"),
            Self::AlreadyAnswered => f.write_str("the call has already been answered"),
            Self::Build(ref error) => write!(f, "cannot build the CANCEL: {error}"),
        }
    }
}

impl core::error::Error for CancelError {}

impl From<BuildError> for CancelError {
    fn from(error: BuildError) -> Self {
        Self::Build(error)
    }
}

/// Why a 2xx could not be acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AckError {
    /// The handle names a dialog that has ended, or never existed.
    NoSuchDialog,
    /// The dialog was opened by a call somebody made to us. The ACK for a 2xx
    /// is the caller's to send, and this end is not the caller.
    NotOurCall,
    /// No 2xx has arrived on this dialog yet.
    NotAnswered,
    /// It has already been acknowledged. Retransmissions of the 2xx are
    /// answered by the endpoint from the stored bytes (§13.2.2.4).
    AlreadyAcknowledged,
    /// The ACK could not be assembled.
    Build(SendError),
}

impl fmt::Display for AckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoSuchDialog => f.write_str("no such dialog"),
            Self::NotOurCall => f.write_str("this end did not place the call"),
            Self::NotAnswered => f.write_str("nothing to acknowledge yet"),
            Self::AlreadyAcknowledged => f.write_str("already acknowledged"),
            Self::Build(ref error) => write!(f, "cannot build the ACK: {error}"),
        }
    }
}

impl core::error::Error for AckError {}

impl From<SendError> for AckError {
    fn from(error: SendError) -> Self {
        Self::Build(error)
    }
}

/// Why a reliable provisional response could not be acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrackError {
    /// The handle names a response that is no longer outstanding — a final
    /// response arrived, or it was acknowledged already.
    NoSuchResponse,
    /// The dialog it belonged to has ended.
    NoSuchDialog,
    /// The PRACK could not be assembled or sent.
    Send(SendError),
}

impl fmt::Display for PrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoSuchResponse => f.write_str("no such provisional response"),
            Self::NoSuchDialog => f.write_str("no such dialog"),
            Self::Send(ref error) => write!(f, "cannot send the PRACK: {error}"),
        }
    }
}

impl core::error::Error for PrackError {}

impl From<SendError> for PrackError {
    fn from(error: SendError) -> Self {
        Self::Send(error)
    }
}

/// Why a challenged request could not be sent again.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthRetryError {
    /// No challenge is being held under this handle. It was answered already,
    /// the refusal carried nothing this stack can answer, or the same nonce
    /// came back a second time — §22.1 does not re-try credentials that were
    /// just refused, because repeating them only locks the account.
    NoChallenge,
    /// The credentials produced nothing to send.
    NothingToAnswer,
    /// The request was inside a dialog that has since ended.
    NoSuchDialog,
    /// The retry could not be assembled or sent.
    Unsendable(SendError),
}

impl fmt::Display for AuthRetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoChallenge => f.write_str("no challenge to answer"),
            Self::NothingToAnswer => f.write_str("nothing in the challenge can be answered"),
            Self::NoSuchDialog => f.write_str("no such dialog"),
            Self::Unsendable(ref error) => write!(f, "cannot send the retry: {error}"),
        }
    }
}

impl core::error::Error for AuthRetryError {}

#[cfg(test)]
mod tests {
    use super::{ReceiveError, RespondError, SendError};
    use crate::msg::{BuildError, ParseError};

    #[test]
    fn every_error_reads_as_a_sentence() {
        assert_eq!(
            ReceiveError::UnknownTransport.to_string(),
            "no such transport"
        );
        assert_eq!(SendError::MissingField("To").to_string(), "no To");
        assert_eq!(
            SendError::NeedsStreamTransport.to_string(),
            "too large for a datagram and no stream transport is open"
        );
        assert_eq!(
            RespondError::TooLate.to_string(),
            "the transaction has already answered"
        );
    }

    #[test]
    fn the_error_underneath_is_carried_rather_than_flattened() {
        let error = ReceiveError::from(ParseError::Empty);
        assert_eq!(error, ReceiveError::Malformed(ParseError::Empty));
        assert!(error.to_string().starts_with("malformed message: "));

        let error = SendError::from(BuildError::MissingField("Via"));
        assert_eq!(error, SendError::Build(BuildError::MissingField("Via")));
    }
}
