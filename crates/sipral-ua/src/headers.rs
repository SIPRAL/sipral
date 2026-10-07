// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Header fields the application adds, and the ones it may not.
//!
//! Fields come from [`OutgoingCall::header`](crate::OutgoingCall::header),
//! [`Account::header`](crate::Account::header) and
//! [`UserAgent::respond_with_headers`](crate::UserAgent::respond_with_headers),
//! and are checked here before anything is built.
//!
//! Refused: a name that is not a token (RFC 3261 §25.1); a value with a
//! control byte (CR/LF would inject a field, the rest of C0 and DEL are not
//! `TEXT-UTF8char`); and a field the stack writes itself, since a second copy
//! makes a malformed or misleading message. [`ENDPOINT_FIELDS`] are the
//! endpoint's; the lists below are this layer's.
//!
//! Left open on purpose: `Replaces` and `Referred-By` on a call the
//! application places (taking over a dialog learned elsewhere, RFC 3891 §1;
//! refused for `UserAgent::accept_transfer`, which takes both from the
//! REFER); `Expires` on an INVITE (§13.2.1); and `Supported` on a REGISTER,
//! which a GRUU registration needs (RFC 5627 §4.1).

use core::fmt;

use sipral_core::endpoint::{ENDPOINT_FIELDS, OutgoingInDialogRequest, OutgoingResponse};
use sipral_core::msg::HeaderName;

use crate::account::Extra;
use crate::error::UaError;

/// The fields this layer writes on a call beyond the endpoint's.
const CALL_FIELDS: &[HeaderName<'static>] = &[
    // §20.5, RFC 3311 §4: a method listed but not implemented would be invited
    // and then refused
    HeaderName::Allow,
    // §20.37, RFC 3262 §4, RFC 4028 §7.1: the far end acts on these tokens
    HeaderName::Supported,
    // §20.32, RFC 3262 §3, RFC 4028 §9
    HeaderName::Require,
    // RFC 3262 §7.1: the PRACK acknowledges by this number
    HeaderName::RSeq,
    // RFC 4028 §4, §5: the stack runs the timer it negotiates
    HeaderName::SessionExpires,
    HeaderName::MinSe,
    // §22.2, §22.3: the nonce count has only one writer
    HeaderName::Authorization,
    HeaderName::ProxyAuthorization,
];

/// The fields this layer writes on a REGISTER beyond the endpoint's.
const REGISTRATION_FIELDS: &[HeaderName<'static>] = &[
    // §10.2.1, §20.19: the refresh schedule is computed from it
    HeaderName::Expires,
    // §22.2, §22.3
    HeaderName::Authorization,
    HeaderName::ProxyAuthorization,
];

/// Which messages an application's header fields go out on, because the stack
/// writes different fields on each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeadersFor {
    /// A call: its INVITE, and what the application sends for it afterwards.
    Call,
    /// A REGISTER.
    Registration,
}

impl HeadersFor {
    /// Whether one field may go out on these messages, and the field it names
    /// when it may. Compact forms count as their long form: `m` is `Contact`
    /// (§7.3.3).
    ///
    /// # Errors
    /// [`HeaderRefused`], saying why not.
    pub fn check<'a>(self, name: &'a [u8], value: &[u8]) -> Result<HeaderName<'a>, HeaderRefused> {
        let Some(field) = HeaderName::from_bytes(name) else {
            return Err(HeaderRefused::NotAName);
        };
        // a horizontal tab is linear whitespace and may sit inside a value
        if let Some(offset) = value
            .iter()
            .position(|&byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(HeaderRefused::ControlByte { offset });
        }
        let own = match self {
            Self::Call => CALL_FIELDS,
            Self::Registration => REGISTRATION_FIELDS,
        };
        match ENDPOINT_FIELDS
            .iter()
            .chain(own)
            .find(|written| **written == field)
        {
            Some(written) => Err(HeaderRefused::WrittenByTheStack(written.canonical())),
            None => Ok(field),
        }
    }

    /// Every field of a list, stopping at the first that is refused.
    pub(crate) fn check_each(self, fields: &[Extra]) -> Result<(), UaError> {
        for one in fields {
            self.check(&one.name, &one.value).map_err(UaError::Header)?;
        }
        Ok(())
    }
}

/// Why a header field an application supplied is not one this stack sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderRefused {
    /// The name is not a token (§25.1).
    NotAName,
    /// The value carries a control byte other than a horizontal tab.
    ControlByte {
        /// Where, counted from the first byte of the value.
        offset: usize,
    },
    /// A field this stack writes itself on these messages, named in its long
    /// form.
    WrittenByTheStack(&'static str),
}

impl fmt::Display for HeaderRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotAName => f.write_str("the name is not a token"),
            Self::ControlByte { offset } => write!(
                f,
                "the value carries a control byte at offset {offset}, and a line break there \
                 would start a field nobody wrote"
            ),
            Self::WrittenByTheStack(name) => write!(
                f,
                "{name} is written by the stack itself, and a second line of it is a message \
                 the two ends read differently"
            ),
        }
    }
}

impl core::error::Error for HeaderRefused {}

/// A response with the application's fields on it, after everything the stack
/// wrote.
pub(crate) fn onto_response(mut response: OutgoingResponse, fields: &[Extra]) -> OutgoingResponse {
    for one in fields {
        if let Some(name) = HeaderName::from_bytes(&one.name) {
            response = response.header(name, &one.value);
        }
    }
    response
}

/// The same, for a request inside the call's dialog.
pub(crate) fn onto_request(
    mut request: OutgoingInDialogRequest,
    fields: &[Extra],
) -> OutgoingInDialogRequest {
    for one in fields {
        if let Some(name) = HeaderName::from_bytes(&one.name) {
            request = request.header(name, &one.value);
        }
    }
    request
}
