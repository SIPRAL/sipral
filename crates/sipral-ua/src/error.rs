// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Why something the application asked for could not be done.
//!
//! A refusing registrar, a wrong password or a dead network arrive later, as
//! events. What is here is a stale handle or a request that cannot be built.

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
    /// ([`Account::unregistered`](crate::Account::unregistered)). Nothing was
    /// built.
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
    /// A session change is already running (§14.1; RFC 3311 §5.2 for UPDATE).
    ChangeInProgress,
    /// The call is not up, so no re-INVITE (§14.1), and the far end never
    /// advertised UPDATE (RFC 3311 §4).
    CannotRenegotiate,
    /// The session description could not be read.
    Sdp(SdpError),
    /// A header field the application supplied was refused, and nothing was
    /// built: see [`crate::HeadersFor`].
    Header(HeaderRefused),
    /// A digit no keypad has, or a duration nothing holds a key for: see
    /// [`UserAgent::send_dtmf_info`](crate::UserAgent::send_dtmf_info).
    InvalidDtmf(DtmfError),
    /// A MESSAGE body over the RFC 3428 §8 limit for a path not known to be
    /// congestion-safe: see
    /// [`Account::transport_protocol`](crate::Account::transport_protocol).
    MessageTooLarge {
        /// How large the body is.
        size: usize,
        /// The ceiling it was checked against.
        limit: usize,
    },
    /// A MESSAGE to the same target is still waiting for its final answer
    /// (RFC 3428 §8). In a dialog the same applies unless every hop is known
    /// to be congestion-controlled.
    MessagePending,
    /// A registrar keep-alive interval outside what
    /// [`UserAgent::keep_registrar_flows_alive`](crate::UserAgent::keep_registrar_flows_alive)
    /// takes: under a second, or over the two minutes RFC 4787 REQ-5 has a
    /// NAT keep a UDP flow for.
    InvalidKeepalive(core::time::Duration),
    /// The address about to be advertised cannot be reached by the peer:
    /// loopback to a remote peer, or unspecified in a `Contact`
    /// ([`crate::advertise`]). Nothing was sent. Use the address of the
    /// interface that routes to the peer.
    UnreachableAddress {
        /// What would have been advertised.
        advertised: std::net::IpAddr,
        /// Who it would have been advertised to.
        peer: std::net::IpAddr,
    },
    /// The account finds its server by RFC 3263
    /// ([`Account::located`](crate::Account::located)) and no lookup has
    /// answered yet. Nothing was sent.
    NotLocated,
    /// A redirect was asked for with a status outside 300 to 399, or one
    /// other than 380 with nowhere to redirect to (RFC 3261 §21.3).
    NotARedirection(sipral_core::msg::StatusCode),
    /// The account signs its calls (RFC 8224 §6.1) and the PASSporT needs the
    /// time, never given with
    /// [`UserAgent::set_wall_clock`](crate::UserAgent::set_wall_clock).
    /// Nothing was sent.
    NoWallClock,
    /// The PASSporT could not be made: the target is too long for an
    /// `Identity` header field. Nothing was sent.
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
    /// An access token that is not an RFC 6750 §2.1 `b64token`. Nothing was
    /// changed.
    InvalidAccessToken,
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
            Self::UnreachableAddress { advertised, peer } => write!(
                f,
                "{advertised} is not an address {peer} can reach this end at: bind to the \
                 address of the interface that routes to it"
            ),
            Self::NotLocated => f.write_str(
                "the account's server has not been located yet: no DNS answer has named an address",
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
            Self::InvalidAccessToken => {
                f.write_str("not an access token: RFC 6750 section 2.1 allows A-Z a-z 0-9 - . _ ~ + / and '=' padding")
            }
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
