// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Syntax: locating a SIP message in a buffer, without copying it.
//!
//! A parse produces spans into the caller's bytes plus an index of the header
//! fields. Values are interpreted only when something asks for them, and
//! copied only at the one seam where the stack keeps a message past the call
//! that received it.
//!
//! Written from RFC 3261 §7 and §25, and tested against the RFC 4475 corpus in
//! `fixtures/rfc4475/`.

mod addr;
mod auth;
mod error;
mod header;
mod lex;
mod message;
mod method;
mod parse;
mod route;
mod scalar;
mod span;
mod tokens;
mod uri;
mod via;

pub use addr::{ContactIter, Contacts, NameAddrRef};
pub use auth::{AuthParams, ChallengeRef, CredentialsRef};
pub use error::{HeaderError, ParseError};
pub use header::HeaderName;
pub use lex::{CommaList, LwsFields, Params, fields, is_quoted, trim, unfold, unquote};
pub use message::{FieldValues, MessageKind, OwnedMessage, RawMessage};
pub use method::{InvalidStatusCode, Method, StatusCode};
pub use parse::{Limits, ParseMode, parse, parse_with_limits};
pub use route::{RouteIter, RouteRef};
pub use scalar::{CSeq, Digits, RAck, digits, rseq};
pub use span::{HeaderSlot, ParseScratch, Span};
pub use tokens::{MediaTypeRef, TokenIter};
pub use uri::{
    HostRef, SipUriRef, UriError, UriHeaderIter, UriParamIter, UriRef, UriScheme, unescape,
};
pub use via::{MAGIC_COOKIE, Rport, ViaRef};
