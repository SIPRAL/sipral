// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Header fields the application adds, and the ones it may not.
//!
//! An application's fields reach the wire three ways:
//! [`OutgoingCall::header`](crate::OutgoingCall::header) on the INVITE,
//! [`Account::header`](crate::Account::header) on every REGISTER, and
//! [`UserAgent::respond_with_headers`](crate::UserAgent::respond_with_headers)
//! on what a call sends afterwards at the application's request. All three
//! are checked here, before anything is built.
//!
//! A field is refused for one of three reasons. Its name is not a token, so it
//! is not a name at all (RFC 3261 §25.1). Its value holds a control byte: CR or
//! LF would end the line and start a field the application never wrote, and
//! NUL, the rest of C0 and DEL are not `TEXT-UTF8char` and are read
//! differently by every hop on the way. Or it is a field this stack writes
//! itself on those messages, from state it keeps, and a second line of one of
//! those is not a second opinion the far end weighs: it is a malformed message,
//! or one that goes somewhere, ends somewhere or promises something the stack
//! did not mean. [`ENDPOINT_FIELDS`] are the endpoint's; the two lists below
//! are this layer's, each with its reason.
//!
//! Left open on purpose: `Replaces` and `Referred-By`, which this layer writes
//! only on the INVITE an accepted transfer places, while an application that
//! writes `Replaces` on a call it places itself is taking over a dialog it
//! learned about some other way (RFC 3891 §1); `Expires` on an INVITE, which
//! limits how long the invitation stands (§13.2.1); and `Supported` on a
//! REGISTER, where this layer writes none and a registration that wants a
//! GRUU has to (RFC 5627 §4.1).

use core::fmt;

use sipral_core::endpoint::{ENDPOINT_FIELDS, OutgoingInDialogRequest, OutgoingResponse};
use sipral_core::msg::HeaderName;

use crate::account::Extra;
use crate::error::UaError;

/// The fields this layer writes on a call beyond the endpoint's: on the INVITE,
/// on the responses to it, on the re-INVITE or UPDATE that changes the session
/// and on the BYE that ends it.
const CALL_FIELDS: &[HeaderName<'static>] = &[
    // §20.5, RFC 3311 §4: the methods this end answers, written on the INVITE,
    // on its 1xx and 2xx and on every re-INVITE. A method listed here that the
    // stack does not implement is a request the far end sends and this end
    // refuses
    HeaderName::Allow,
    // §20.37, RFC 3262 §4, RFC 4028 §7.1: the extensions this end supports.
    // The far end acts on a token it reads here, so one the stack does not
    // implement is a promise nothing keeps
    HeaderName::Supported,
    // §20.32, RFC 3262 §3, RFC 4028 §9: an extension the far end has to
    // follow, written on a reliable provisional and on a 2xx that hands the
    // refresh over
    HeaderName::Require,
    // RFC 3262 §7.1: the number of a reliable provisional, which the PRACK
    // acknowledges by
    HeaderName::RSeq,
    // RFC 4028 §4, §5: the session timer this end negotiates and then runs;
    // a second interval is a refresh nobody is doing
    HeaderName::SessionExpires,
    HeaderName::MinSe,
    // §22.2, §22.3: the answer to a challenge, drawn from the account's
    // credentials, with a nonce count that only one writer may keep
    HeaderName::Authorization,
    HeaderName::ProxyAuthorization,
];

/// The fields this layer writes on a REGISTER beyond the endpoint's.
const REGISTRATION_FIELDS: &[HeaderName<'static>] = &[
    // §10.2.1, §20.19: how long the binding is asked for, which is the
    // account's expiry and what the refresh schedule is computed from
    HeaderName::Expires,
    // §22.2, §22.3: as on a call
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
    /// when it may.
    ///
    /// The name is compared as a field, so a compact form is refused where its
    /// long form is: `m` is `Contact` (§7.3.3).
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
    /// The name is not a token, and a header field name is one (§25.1). A
    /// space or a colon in it would be read as the start of the value.
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
