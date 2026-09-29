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
use crate::dtmf::DtmfError;
use crate::headers::HeaderRefused;

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
    /// The account has no registrar
    /// ([`Account::unregistered`](crate::Account::unregistered)), so there is
    /// nothing to register with and no binding to give up. Nothing was built.
    NoRegistrar,
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
    /// A header field the application supplied was refused, and nothing was
    /// built: see [`crate::HeadersFor`].
    Header(HeaderRefused),
    /// A digit no keypad has, or a duration nothing holds a key for: see
    /// [`UserAgent::send_dtmf_info`](crate::UserAgent::send_dtmf_info).
    InvalidDtmf(DtmfError),
    /// A MESSAGE body is larger than RFC 3428 §8 lets this end send without
    /// positive knowledge of a congestion-safe hop: see
    /// [`Account::transport_protocol`](crate::Account::transport_protocol).
    MessageTooLarge {
        /// How large the body is.
        size: usize,
        /// The ceiling it was checked against.
        limit: usize,
    },
    /// §8: "A UAC MUST NOT initiate a new out-of-dialog MESSAGE transaction
    /// to a given URI if there is a previous out-of-dialog transaction
    /// pending for the same URI." One is still waiting for its final answer.
    /// The same section's next sentence gives an in-dialog MESSAGE the same
    /// refusal on a route not known to be congestion-controlled: "A UAC
    /// SHOULD NOT initiate overlapping MESSAGE transactions inside a
    /// dialog, and MUST NOT do so unless the route set for that dialog uses
    /// a congestion-controlled transport at every hop."
    MessagePending,
    /// A registrar keep-alive interval outside what
    /// [`UserAgent::keep_registrar_flows_alive`](crate::UserAgent::keep_registrar_flows_alive)
    /// takes: under a second, or over the two minutes RFC 4787 REQ-5 has a
    /// NAT keep a UDP flow for.
    InvalidKeepalive(core::time::Duration),
    /// A redirect was asked for with a status outside 300 to 399, or one
    /// other than 380 with nowhere to redirect to (RFC 3261 §21.3).
    NotARedirection(sipral_core::msg::StatusCode),
    /// The account signs its calls (RFC 8224 §6.1) and the agent was never
    /// told the time, which a PASSporT has to carry:
    /// [`UserAgent::set_wall_clock`](crate::UserAgent::set_wall_clock).
    /// Nothing was sent.
    NoWallClock,
    /// The account signs its calls and this one's PASSporT could not be
    /// made: a target too long for an `Identity` header field. Nothing was
    /// sent.
    Signing,
    /// The handle names a publication whose state was removed, or never
    /// existed.
    NoSuchPublication,
    /// A publication cannot do this as it stands: see
    /// [`PublishError`](crate::PublishError).
    Publish(crate::PublishError),
    /// The call's far end has not said it is a conference focus (RFC 4579
    /// §4.2): its `Contact` carried no `isfocus`.
    NotAFocus,
    /// A recording session could not be written: see
    /// [`SiprecError`](crate::siprec::SiprecError).
    Recording(crate::siprec::SiprecError),
}

impl fmt::Display for UaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoSuchAccount => f.write_str("no such account"),
            Self::NoSuchCall => f.write_str("no such call"),
            Self::NoSuchSubscription => f.write_str("no such subscription"),
            Self::WrongState(state) => write!(f, "the call is {state}"),
            Self::NoRegistrar => f.write_str("the account has no registrar and never registers"),
            Self::Send(ref error) => write!(f, "cannot send it: {error}"),
            Self::Respond(ref error) => write!(f, "cannot answer it: {error}"),
            Self::Ack(ref error) => write!(f, "cannot acknowledge it: {error}"),
            Self::NoSession => f.write_str("nothing has been described yet"),
            Self::ChangeInProgress => f.write_str("a session change is already running"),
            Self::CannotRenegotiate => {
                f.write_str("the call is not up and the far end cannot take an UPDATE")
            }
            Self::Sdp(ref error) => write!(f, "cannot read the description: {error}"),
            Self::Header(refused) => write!(f, "cannot take the header field: {refused}"),
            Self::InvalidDtmf(reason) => write!(f, "cannot send that digit: {reason}"),
            Self::MessageTooLarge { size, limit } => write!(
                f,
                "the body is {size} bytes, over the {limit}-byte ceiling for a MESSAGE this end \
                 cannot prove will not cross a congestion-unsafe hop"
            ),
            Self::MessagePending => f.write_str(
                "an out-of-dialog MESSAGE to this target is already waiting for its final answer",
            ),
            Self::InvalidKeepalive(interval) => write!(
                f,
                "a registrar keep-alive every {} ms is outside 1 000 to 120 000 ms",
                interval.as_millis()
            ),
            Self::NotARedirection(status) if (300..400).contains(&status.get()) => write!(
                f,
                "a {} with no Contact to name is not a redirection",
                status.get()
            ),
            Self::NotARedirection(status) => write!(
                f,
                "a {} is not a redirection: those are 300 to 399",
                status.get()
            ),
            Self::NoWallClock => f.write_str(
                "this account signs its calls, and the agent has not been told the time a \
                 PASSporT has to carry",
            ),
            Self::Signing => f.write_str("the PASSporT for this call could not be signed"),
            Self::NoSuchPublication => f.write_str("no such publication"),
            Self::Publish(ref error) => write!(f, "cannot publish it: {error}"),
            Self::NotAFocus => {
                f.write_str("the far end of the call did not say it is a conference focus")
            }
            Self::Recording(ref error) => write!(f, "cannot record the call: {error}"),
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
