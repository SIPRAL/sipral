// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The `Bearer` scheme: OAuth 2.0 access tokens in SIP (RFC 8898, RFC 6750).
//!
//! A server that takes OAuth challenges with `Bearer` where it would have
//! challenged with `Digest`, and names where a token comes from:
//!
//! ```text
//! challenge  =/  ("Bearer" LWS bearer-cln *(COMMA bearer-cln))
//! bearer-cln = realm / scope-param / authz-server-param / error-param /
//!              auth-param
//! ```
//!
//! The answer is the token itself, `Authorization: Bearer <token>` (RFC 6750
//! §2.1), in the field §22 of RFC 3261 puts any answer in: `Authorization`
//! for a 401, `Proxy-Authorization` for a 407. RFC 8898 §2 keeps every other
//! rule of §22, so a `Bearer` challenge is cached per destination and per
//! protection domain exactly as a `Digest` one is.
//!
//! What this stack does not do is fetch the token. RFC 8898 leaves the OAuth
//! exchange "out of scope", and it is the application's: a browser, a user,
//! and the list of authorization servers it trusts — §2.1.1 says the client
//! "MUST check the AS URL received in the 401/407 response against a list of
//! trusted ASs", and only the application holds that list. So a challenge is
//! read, reported with its `authz_server`, `scope` and `error`, and answered
//! with whatever token the application has supplied.
//!
//! RFC 6750 §3.1's `invalid_token` — "expired, revoked, malformed, or invalid
//! for other reasons" — is what a server says when the token it was given no
//! longer works. The token that earned it is remembered, by its SHA-256 and
//! never by its value, and not offered to that protection domain again: the
//! rule §22.1 makes for a rejected password, applied to a rejected token.
//! A new token from the application answers at once.

use std::sync::Arc;

use super::secret::Credentials;
use super::sha2::sha256;
use crate::msg::{ChallengeRef, HeaderName};

/// What a server said was wrong with the request (RFC 6750 §3.1; RFC 8898
/// §4 names `invalid_scope` as well).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BearerError {
    /// `invalid_request`: the request was malformed.
    InvalidRequest,
    /// `invalid_token`: the token is "expired, revoked, malformed, or
    /// invalid for other reasons". A new one is needed.
    InvalidToken,
    /// `insufficient_scope`: the token does not cover what was asked; the
    /// challenge's `scope` says what would.
    InsufficientScope,
    /// `invalid_scope`, which RFC 8898 §4 lists beside `invalid_token`.
    InvalidScope,
    /// Something else, as written.
    Other(Arc<str>),
}

impl BearerError {
    fn read(code: &str) -> Self {
        match code {
            "invalid_request" => Self::InvalidRequest,
            "invalid_token" => Self::InvalidToken,
            "insufficient_scope" => Self::InsufficientScope,
            "invalid_scope" => Self::InvalidScope,
            other => Self::Other(Arc::from(other)),
        }
    }

    /// The code as it is written in the `error` parameter.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::InvalidScope => "invalid_scope",
            Self::Other(code) => code,
        }
    }
}

/// A `Bearer` challenge (RFC 8898 §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerChallenge {
    /// The protection domain. Optional in the grammar; an absent one is the
    /// empty string, one domain like any other.
    pub realm: Arc<str>,
    /// The scope the token has to carry: space-separated, case-sensitive
    /// strings the authorization server defines (RFC 6749 §3.3).
    pub scope: Option<Arc<str>>,
    /// Where a token comes from: an `https` URI (RFC 8898 §4). A value
    /// that is not one is dropped, since §2.2 makes it one and a client is
    /// meant to contact it.
    pub authz_server: Option<Arc<str>>,
    /// What was wrong with the request, when the server said.
    pub error: Option<BearerError>,
    /// Whether it came from a proxy (407) rather than the endpoint (401).
    pub proxy: bool,
}

impl BearerChallenge {
    /// Read a challenge, or decide it is not a `Bearer` one.
    #[must_use]
    pub fn read(challenge: &ChallengeRef<'_>, proxy: bool) -> Option<Self> {
        if !challenge.scheme().eq_ignore_ascii_case(b"Bearer") {
            return None;
        }
        let text = |name: &str| {
            challenge
                .param(name)
                .and_then(|value| core::str::from_utf8(&value).ok().map(Arc::from))
        };
        let authz_server = text("authz_server").filter(|uri: &Arc<str>| {
            uri.get(..8)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        });
        Some(Self {
            realm: text("realm").unwrap_or_else(|| Arc::from("")),
            scope: text("scope").filter(|scope: &Arc<str>| !scope.is_empty()),
            authz_server,
            error: text("error").map(|code| BearerError::read(&code)),
            proxy,
        })
    }

    /// Which header field the answer goes in.
    #[must_use]
    pub const fn header(&self) -> HeaderName<'static> {
        if self.proxy {
            HeaderName::ProxyAuthorization
        } else {
            HeaderName::Authorization
        }
    }

    /// The answer, ready to be a header value: `Bearer <token>`. `None` for
    /// credentials that hold no access token.
    #[must_use]
    pub fn respond(credentials: &Credentials) -> Option<String> {
        let token = core::str::from_utf8(credentials.token()?).ok()?;
        Some(format!("Bearer {token}"))
    }
}

/// What a token is remembered by once it has been refused: its SHA-256,
/// which says whether a later token is the same one without keeping it.
pub(super) fn fingerprint(token: &[u8]) -> [u8; 32] {
    sha256(token)
}

/// The fingerprint of the credentials' token, if they have one.
pub(super) fn fingerprint_of(credentials: &Credentials) -> Option<[u8; 32]> {
    credentials.token().map(fingerprint)
}

/// The token a `Bearer` field carried, if `value` is one.
pub(super) fn carried_token(value: &[u8]) -> Option<&[u8]> {
    let value = trim(value);
    let scheme = value.get(..6)?;
    if !scheme.eq_ignore_ascii_case(b"Bearer") {
        return None;
    }
    let rest = value.get(6..)?;
    if !rest.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
        return None;
    }
    let token = trim(rest);
    (!token.is_empty()).then_some(token)
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |at| at + 1);
    bytes.get(start..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{BearerChallenge, BearerError, carried_token};
    use crate::auth::Credentials;
    use crate::msg::{ChallengeRef, HeaderName};

    fn read(value: &str, proxy: bool) -> Option<BearerChallenge> {
        BearerChallenge::read(&ChallengeRef::parse(value.as_bytes()).expect("parses"), proxy)
    }

    #[test]
    fn the_parameters_of_rfc_8898_are_read() {
        let challenge = read(
            "Bearer realm=\"atlanta.com\", scope=\"sip register\", \
             authz_server=\"https://as.example.com/token\", error=\"invalid_token\"",
            false,
        )
        .expect("a bearer challenge");
        assert_eq!(&*challenge.realm, "atlanta.com");
        assert_eq!(challenge.scope.as_deref(), Some("sip register"));
        assert_eq!(
            challenge.authz_server.as_deref(),
            Some("https://as.example.com/token")
        );
        assert_eq!(challenge.error, Some(BearerError::InvalidToken));
        assert_eq!(challenge.header(), HeaderName::Authorization);
    }

    #[test]
    fn the_scheme_is_matched_without_case_and_digest_is_not_bearer() {
        assert!(read("bEaReR authz_server=\"https://as.example\"", true).is_some());
        assert!(read("Digest realm=\"a\", nonce=\"b\"", false).is_none());
        let proxy = read("Bearer realm=\"p\"", true).expect("bearer");
        assert_eq!(proxy.header(), HeaderName::ProxyAuthorization);
    }

    #[test]
    fn an_authorization_server_that_is_not_https_is_dropped() {
        let challenge = read("Bearer authz_server=\"http://as.example\"", false).expect("bearer");
        assert_eq!(challenge.authz_server, None);
        assert_eq!(&*challenge.realm, "", "no realm is the empty domain");
    }

    #[test]
    fn an_unknown_error_is_kept_as_written() {
        let challenge = read("Bearer error=\"use_dpop\"", false).expect("bearer");
        assert_eq!(challenge.error.as_ref().map(BearerError::code), Some("use_dpop"));
    }

    #[test]
    fn the_answer_is_the_token_and_nothing_without_one() {
        let credentials = Credentials::bearer("eyJ0.eyJ1.c2ln").expect("a token");
        assert_eq!(
            BearerChallenge::respond(&credentials).as_deref(),
            Some("Bearer eyJ0.eyJ1.c2ln")
        );
        assert_eq!(
            BearerChallenge::respond(&Credentials::new("alice", "secret")),
            None
        );
    }

    #[test]
    fn a_carried_token_is_read_back() {
        assert_eq!(carried_token(b"Bearer abc=="), Some(&b"abc=="[..]));
        assert_eq!(carried_token(b"  bearer\tabc "), Some(&b"abc"[..]));
        assert_eq!(carried_token(b"Bearerabc"), None);
        assert_eq!(carried_token(b"Digest username=\"a\""), None);
        assert_eq!(carried_token(b"Bearer "), None);
    }
}
