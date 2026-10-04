// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Digest challenges and credentials.
//!
//! RFC 3261 §25.1, as amended by RFC 8760 §2.7:
//!
//! ```text
//! challenge      =  ("Digest" LWS digest-cln *(COMMA digest-cln))
//!                   / other-challenge
//! credentials    =  ("Digest" LWS digest-response) / other-response
//! auth-param     =  auth-param-name EQUAL ( token / quoted-string )
//! qop-options    =  "qop" EQUAL LDQUOT qop-value *("," qop-value) RDQUOT
//! message-qop    =  "qop" EQUAL qop-value
//! nc-value       =  8LHEX
//! request-digest =  LDQUOT *LHEX RDQUOT
//! ```
//!
//! The separator is a comma, not a semicolon: these fields carry a parameter
//! list where every other field carries a value plus parameters.
//!
//! Two shapes for one name. In a challenge, `qop` is a quoted, comma-separated
//! list; in credentials it is one bare token. A stack that insists on quotes
//! in both directions rejects the RFC's own worked example, which writes
//! `qop=auth` in the `Authorization` field.
//!
//! Quoting is not decoration either. `realm`, `nonce`, `cnonce`, `username`
//! and `opaque` are `quoted-string`, so a backslash escapes the byte after it.
//! `uri` and `response` are wrapped in quotes without being `quoted-string`
//! (§22.4 and RFC 8760 §2.6), so their contents are handed back exactly as
//! written: a Request-URI is not a place to be resolving escapes.
//!
//! `Authorization` and `Proxy-Authorization` are the two fields RFC 3261
//! §20.7 and §20.28 exempt from comma-joining, and several
//! `WWW-Authenticate` lines are several challenges in preference order (RFC
//! 8760 §2.3). So each line is read on its own, and nothing here joins them.
//!
//! Where the grammar names a parameter twice — once with a type, once through
//! the `auth-param` catch-all — this parses the value and lets the accessor
//! object. `nc=0000001` is seven digits, which is not `8LHEX` but is a
//! perfectly good `token`, so the field parses and [`CredentialsRef::nc`]
//! refuses. Rejecting the whole header there is a policy the RFC does not
//! ask for, and it would drop a REGISTER over a parameter nobody had to send.

use core::fmt;
use std::borrow::Cow;

use super::error::HeaderError;
use super::lex::{CommaList, LwsFields, fields, is_lws, is_quoted, trim, unquote};
use super::method::is_token_byte;

/// The parameters of one challenge or one set of credentials, in order.
///
/// Values come back as written, quotes included; [`ChallengeRef::param`] and
/// [`CredentialsRef::param`] are the unquoting way in.
#[derive(Clone, Debug)]
pub struct AuthParams<'a> {
    list: CommaList<'a>,
}

impl<'a> Iterator for AuthParams<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        // parse() has already checked every field, so anything unsplittable
        // here cannot happen
        self.list.next().and_then(split_param)
    }
}

/// A `WWW-Authenticate` or `Proxy-Authenticate` value.
#[derive(Clone, Copy, Debug)]
pub struct ChallengeRef<'a> {
    inner: Auth<'a>,
}

/// An `Authorization` or `Proxy-Authorization` value.
#[derive(Clone, Copy, Debug)]
pub struct CredentialsRef<'a> {
    inner: Auth<'a>,
}

#[derive(Clone, Copy, Debug)]
struct Auth<'a> {
    scheme: &'a [u8],
    params: &'a [u8],
}

impl<'a> Auth<'a> {
    fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let v = trim(value);
        // both branches of the grammar put LWS between the scheme and the
        // first parameter, so "Digestrealm=..." matches neither
        let end = v
            .iter()
            .copied()
            .position(is_lws)
            .ok_or(HeaderError::Malformed(
                "auth scheme is not followed by a parameter",
            ))?;
        let scheme = v.get(..end).unwrap_or_default();
        let params = trim(v.get(end..).unwrap_or_default());
        if scheme.is_empty() || !scheme.iter().copied().all(is_token_byte) {
            return Err(HeaderError::Malformed("auth-scheme is a token"));
        }
        if params.is_empty() {
            return Err(HeaderError::Malformed("auth scheme with no parameters"));
        }
        for field in CommaList::new(params) {
            let (name, value) =
                split_param(field).ok_or(HeaderError::Malformed("auth parameter needs a value"))?;
            if name.is_empty() || !name.iter().copied().all(is_token_byte) {
                return Err(HeaderError::Malformed("auth parameter name is a token"));
            }
            if !is_quoted(value) && !value.iter().copied().all(is_token_byte) {
                return Err(HeaderError::Malformed(
                    "auth parameter value is a token or a quoted string",
                ));
            }
        }
        Ok(Self { scheme, params })
    }

    const fn params(&self) -> AuthParams<'a> {
        AuthParams {
            list: CommaList::new(self.params),
        }
    }

    fn param_raw(&self, name: &str) -> Option<&'a [u8]> {
        self.params()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v)
    }

    fn param(&self, name: &str) -> Option<Cow<'a, [u8]>> {
        self.param_raw(name).map(unquote)
    }

    fn algorithm(&self) -> Option<Cow<'a, [u8]>> {
        self.param("algorithm")
    }
}

impl fmt::Display for Auth<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", String::from_utf8_lossy(self.scheme))?;
        for (i, (name, value)) in self.params().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(
                f,
                "{}={}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(value)
            )?;
        }
        Ok(())
    }
}

impl<'a> ChallengeRef<'a> {
    /// Read one challenge. One line is one challenge: RFC 8760 §2.3 offers
    /// several algorithms as several lines, in preference order.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when the scheme is not a token followed by
    /// whitespace, when there are no parameters, or when a parameter is not
    /// `name=(token / quoted-string)`.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        Ok(Self {
            inner: Auth::parse(value)?,
        })
    }

    /// The scheme, as written.
    #[must_use]
    pub const fn scheme(&self) -> &'a [u8] {
        self.inner.scheme
    }

    /// Whether the scheme is `Digest`, matched without case as §25.1 requires
    /// of every token.
    #[must_use]
    pub fn is_digest(&self) -> bool {
        self.inner.scheme.eq_ignore_ascii_case(b"Digest")
    }

    /// Every parameter, in the order written, values as written.
    #[must_use]
    pub const fn params(&self) -> AuthParams<'a> {
        self.inner.params()
    }

    /// One parameter, matched without case, unquoted.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<Cow<'a, [u8]>> {
        self.inner.param(name)
    }

    /// The protection space this challenge covers.
    #[must_use]
    pub fn realm(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("realm")
    }

    /// The server's nonce.
    #[must_use]
    pub fn nonce(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("nonce")
    }

    /// The value to echo back untouched.
    #[must_use]
    pub fn opaque(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("opaque")
    }

    /// The digest algorithm. Absent means MD5; the grammar ends in `/ token`,
    /// so an unregistered name is syntax, not an error.
    #[must_use]
    pub fn algorithm(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.algorithm()
    }

    /// Whether the nonce is stale, meaning the credentials were otherwise
    /// good and only need retrying against a fresh nonce.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] for a value that is neither `true` nor
    /// `false`. Matched without case: RFC 3261 §20.27's own example writes
    /// `stale=FALSE` against a lowercase literal.
    pub fn stale(&self) -> Result<Option<bool>, HeaderError> {
        let Some(v) = self.inner.param("stale") else {
            return Ok(None);
        };
        if v.eq_ignore_ascii_case(b"true") {
            Ok(Some(true))
        } else if v.eq_ignore_ascii_case(b"false") {
            Ok(Some(false))
        } else {
            Err(HeaderError::Malformed("stale is true or false"))
        }
    }

    /// The offered protection qualities, in the order written.
    ///
    /// A challenge writes these as one quoted, comma-separated list, which is
    /// the shape credentials do not use.
    pub fn qop(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        dequote(self.inner.param_raw("qop").unwrap_or_default())
            .split(|&b| b == b',')
            .map(trim)
            .filter(|v| !v.is_empty())
    }

    /// The URIs this challenge's protection space covers.
    ///
    /// Separated by spaces inside one pair of quotes, which is the only
    /// space-separated list in the family.
    #[must_use]
    pub fn domain(&self) -> LwsFields<'a> {
        fields(dequote(self.inner.param_raw("domain").unwrap_or_default()))
    }
}

impl<'a> CredentialsRef<'a> {
    /// Read one set of credentials.
    ///
    /// # Errors
    /// See [`ChallengeRef::parse`].
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        Ok(Self {
            inner: Auth::parse(value)?,
        })
    }

    /// The scheme, as written. RFC 4475 §3.3.7 is a well-formed REGISTER with
    /// a scheme nobody knows; refusing it is policy, not parsing.
    #[must_use]
    pub const fn scheme(&self) -> &'a [u8] {
        self.inner.scheme
    }

    /// Whether the scheme is `Digest`, matched without case.
    #[must_use]
    pub fn is_digest(&self) -> bool {
        self.inner.scheme.eq_ignore_ascii_case(b"Digest")
    }

    /// Every parameter, in the order written, values as written.
    #[must_use]
    pub const fn params(&self) -> AuthParams<'a> {
        self.inner.params()
    }

    /// One parameter, matched without case, unquoted.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<Cow<'a, [u8]>> {
        self.inner.param(name)
    }

    /// The user being authenticated.
    #[must_use]
    pub fn username(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("username")
    }

    /// The protection space these credentials answer. A proxy must not
    /// consume a value whose realm is not its own (RFC 3261 §22.3).
    #[must_use]
    pub fn realm(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("realm")
    }

    /// The nonce copied from the challenge.
    #[must_use]
    pub fn nonce(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("nonce")
    }

    /// The client's nonce.
    #[must_use]
    pub fn cnonce(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("cnonce")
    }

    /// The opaque value echoed back from the challenge.
    #[must_use]
    pub fn opaque(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("opaque")
    }

    /// The digest algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.algorithm()
    }

    /// The protection quality, one bare token here rather than the quoted
    /// list a challenge carries.
    #[must_use]
    pub fn qop(&self) -> Option<Cow<'a, [u8]>> {
        self.inner.param("qop")
    }

    /// The URI the digest was computed over, exactly as written.
    ///
    /// Quoted, but not a `quoted-string`: the quotes come off and nothing
    /// else is touched, because the contents are a Request-URI and a
    /// backslash in one is a byte, not an escape.
    #[must_use]
    pub fn uri(&self) -> Option<&'a [u8]> {
        self.inner.param_raw("uri").map(dequote)
    }

    /// The digest itself, exactly as written.
    ///
    /// Length is the algorithm's business, not the grammar's: RFC 8760 §2.7
    /// replaced `32LHEX` with `*LHEX` so a SHA-256 response fits, and allows
    /// an empty value from a client that has not been challenged yet.
    #[must_use]
    pub fn response(&self) -> Option<&'a [u8]> {
        self.inner.param_raw("response").map(dequote)
    }

    /// The nonce count.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when the value is not exactly eight
    /// lowercase hex digits. `nc-value = 8LHEX`, and `LHEX` is `DIGIT /
    /// %x61-66`, so `nc=1` and `nc=ABCDEF12` are both refused here — the
    /// field still parses, since both are good tokens, and this is where the
    /// stricter rule is applied.
    pub fn nc(&self) -> Result<Option<u32>, HeaderError> {
        let Some(v) = self.inner.param_raw("nc") else {
            return Ok(None);
        };
        let v = trim(v);
        if v.len() != 8 || !v.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(HeaderError::Malformed("nc is eight lowercase hex digits"));
        }
        let n = v.iter().fold(0_u32, |acc, &b| {
            acc * 16
                + u32::from(if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                })
        });
        Ok(Some(n))
    }
}

impl fmt::Display for ChallengeRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl fmt::Display for CredentialsRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// Take the quotes off without resolving anything inside them.
fn dequote(v: &[u8]) -> &[u8] {
    let v = trim(v);
    v.strip_prefix(b"\"")
        .and_then(|inner| inner.strip_suffix(b"\""))
        .unwrap_or(v)
}

/// The name is a token, so it cannot hold a quote, so the first `=` is the
/// one that separates.
fn split_param(field: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = field.iter().position(|&b| b == b'=')?;
    Some((
        trim(field.get(..at)?),
        trim(field.get(at + 1..).unwrap_or_default()),
    ))
}

#[cfg(test)]
mod tests {
    use super::{ChallengeRef, CredentialsRef};
    use crate::msg::HeaderError;

    const CHALLENGE: &[u8] = b"Digest\r\n\t\trealm=\"biloxi.example.com\",\r\n\t\t\
qop=\"auth,auth-int\",\r\n\t\tnonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\r\n\t\t\
opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    const CREDENTIALS: &[u8] = b"Digest username=\"bob\", realm=\"biloxi.example.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"sip:bob@biloxi.example.com\", \
qop=auth, nc=00000001, cnonce=\"0a4f113b\", \
response=\"6629fae49393a05397450978507c4ef1\", \
opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";

    fn challenge(v: &[u8]) -> ChallengeRef<'_> {
        ChallengeRef::parse(v).expect("a challenge")
    }

    fn credentials(v: &[u8]) -> CredentialsRef<'_> {
        CredentialsRef::parse(v).expect("credentials")
    }

    fn bad_challenge(v: &[u8]) -> bool {
        matches!(ChallengeRef::parse(v), Err(HeaderError::Malformed(_)))
    }

    fn bad_credentials(v: &[u8]) -> bool {
        matches!(CredentialsRef::parse(v), Err(HeaderError::Malformed(_)))
    }

    #[test]
    fn the_worked_challenge_folded_the_way_the_rfc_prints_it() {
        // RFC 3261 22.2
        let c = challenge(CHALLENGE);
        assert!(c.is_digest());
        assert_eq!(c.realm().as_deref(), Some(&b"biloxi.example.com"[..]));
        assert_eq!(
            c.nonce().as_deref(),
            Some(&b"dcd98b7102dd2f0e8b11d0f600bfb0c093"[..])
        );
        assert_eq!(
            c.opaque().as_deref(),
            Some(&b"5ccc069c403ebaf9f0171e9517f40e41"[..])
        );
        assert_eq!(c.qop().collect::<Vec<_>>(), vec![&b"auth"[..], b"auth-int"]);
        assert_eq!(c.params().count(), 4);
    }

    #[test]
    fn the_worked_credentials() {
        // RFC 3261 22.2
        let c = credentials(CREDENTIALS);
        assert!(c.is_digest());
        assert_eq!(c.username().as_deref(), Some(&b"bob"[..]));
        assert_eq!(c.uri(), Some(&b"sip:bob@biloxi.example.com"[..]));
        assert_eq!(c.qop().as_deref(), Some(&b"auth"[..]));
        assert_eq!(c.nc(), Ok(Some(1)));
        assert_eq!(c.cnonce().as_deref(), Some(&b"0a4f113b"[..]));
        assert_eq!(c.response(), Some(&b"6629fae49393a05397450978507c4ef1"[..]));
        assert_eq!(c.algorithm(), None);
    }

    #[test]
    fn qop_has_a_different_shape_in_each_direction() {
        // quoted comma list in a challenge, one bare token in credentials
        assert_eq!(
            challenge(br#"Digest realm="a", qop="auth,auth-int""#)
                .qop()
                .collect::<Vec<_>>(),
            vec![&b"auth"[..], b"auth-int"]
        );
        assert_eq!(
            challenge(br#"Digest realm="a", qop="auth""#)
                .qop()
                .collect::<Vec<_>>(),
            vec![&b"auth"[..]]
        );
        assert_eq!(challenge(br#"Digest realm="a""#).qop().count(), 0);
        assert_eq!(
            credentials(br#"Digest realm="a", qop=auth, response="ab""#)
                .qop()
                .as_deref(),
            Some(&b"auth"[..])
        );
    }

    #[test]
    fn the_scheme_is_matched_without_case_and_may_be_unknown() {
        // RFC 4475 3.3.7 regaut01: well formed, and refusing it is policy
        let c = credentials(b"NoOneKnowsThisScheme opaque-data=here");
        assert!(!c.is_digest());
        assert_eq!(c.scheme(), b"NoOneKnowsThisScheme");
        assert_eq!(c.param("opaque-data").as_deref(), Some(&b"here"[..]));

        assert!(credentials(br#"digest realm="a", response="ab""#).is_digest());
        assert!(challenge(br#"DIGEST realm="a""#).is_digest());
    }

    #[test]
    fn the_challenge_from_the_field_examples() {
        // RFC 3261 20.27, verbatim but for the domain
        let c = challenge(
            br#"Digest realm="atlanta.example.com", domain="sip:ss1.example.com", qop="auth", nonce="f84f1cec41e6cbe5aea9c8e88d359", opaque="", stale=FALSE, algorithm=MD5"#,
        );
        assert_eq!(c.stale(), Ok(Some(false)));
        assert_eq!(c.algorithm().as_deref(), Some(&b"MD5"[..]));
        assert_eq!(c.opaque().as_deref(), Some(&b""[..]));
        assert_eq!(
            c.domain().collect::<Vec<_>>(),
            vec![&b"sip:ss1.example.com"[..]]
        );
    }

    #[test]
    fn the_domain_list_is_separated_by_spaces_not_commas() {
        let c = challenge(
            br#"Digest realm="a", domain="sip:ss1.example.com sip:ss2.example.com", nonce="n""#,
        );
        assert_eq!(
            c.domain().collect::<Vec<_>>(),
            vec![&b"sip:ss1.example.com"[..], b"sip:ss2.example.com"]
        );
    }

    #[test]
    fn a_sha_256_response_is_not_too_long() {
        // RFC 8760 2.7 replaced 32LHEX with *LHEX
        let c = credentials(
            br#"Digest username="bob", realm="a", nonce="n", uri="sip:bob@example.com", algorithm=SHA-256, qop=auth, nc=00000001, cnonce="0a4f113b", response="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""#,
        );
        assert_eq!(c.algorithm().as_deref(), Some(&b"SHA-256"[..]));
        assert_eq!(c.response().map(<[u8]>::len), Some(64));
    }

    #[test]
    fn an_empty_response_is_legal_before_the_first_challenge() {
        // RFC 8760 2.7
        let c = credentials(br#"Digest username="bob", nonce="", response="""#);
        assert_eq!(c.response(), Some(&b""[..]));
        assert_eq!(c.nonce().as_deref(), Some(&b""[..]));
    }

    #[test]
    fn escapes_inside_a_quoted_parameter_are_resolved_but_the_uri_is_left_alone() {
        let c = credentials(br#"Digest username="ali\"ce", uri="sip:a@b.example", response="ab""#);
        assert_eq!(c.username().as_deref(), Some(&br#"ali"ce"#[..]));
        assert_eq!(c.uri(), Some(&b"sip:a@b.example"[..]));
    }

    #[test]
    fn a_scheme_without_whitespace_after_it_is_refused() {
        assert!(bad_credentials(br#"Digestrealm="atlanta.example.com""#));
        assert!(bad_credentials(b"Digest"));
        assert!(bad_credentials(b"Digest "));
        assert!(bad_credentials(b""));
    }

    #[test]
    fn a_missing_comma_between_parameters_is_refused() {
        // the second half is neither a token nor a quoted string
        assert!(bad_challenge(
            br#"Digest realm="atlanta.example.com" nonce="abc""#
        ));
    }

    #[test]
    fn an_unquoted_uri_is_refused_because_it_is_not_a_token_either() {
        // ':' and '@' are separators, so the catch-all cannot absorb it
        assert!(bad_credentials(
            br#"Digest username="bob", uri=sip:bob@biloxi.example.com, response="ab""#
        ));
    }

    #[test]
    fn an_unterminated_quoted_value_is_refused() {
        assert!(bad_challenge(br#"Digest realm="atlanta.example.com"#));
    }

    #[test]
    fn a_dangling_comma_is_refused() {
        assert!(bad_challenge(br#"Digest realm="atlanta.example.com","#));
        assert!(bad_challenge(br#"Digest realm="a",,nonce="n""#));
    }

    #[test]
    fn two_challenges_joined_by_a_comma_are_refused() {
        // RFC 8760 2.3 wants them as two header lines, and the grammar has
        // room for exactly one scheme keyword
        assert!(bad_challenge(
            br#"Digest realm="a", nonce="a1", Digest realm="a", nonce="a2""#
        ));
    }

    #[test]
    fn a_parameter_without_a_value_is_refused() {
        // auth-param has no flag form, unlike a URI parameter
        assert!(bad_challenge(br#"Digest realm="a", stale"#));
    }

    #[test]
    fn an_unquoted_value_that_is_a_token_still_parses() {
        // structurally it arrived through the auth-param catch-all rather
        // than through realm-value, which is a distinction the grammar makes
        // and the wire does not
        let c = challenge(b"Digest realm=atlanta.example.com, nonce=abc");
        assert_eq!(c.realm().as_deref(), Some(&b"atlanta.example.com"[..]));
    }

    #[test]
    fn a_wrong_length_nc_parses_and_the_accessor_objects() {
        let c = credentials(br#"Digest username="bob", response="ab", nc=0000001"#);
        assert!(matches!(c.nc(), Err(HeaderError::Malformed(_))));
        // uppercase is not LHEX either
        assert!(matches!(
            credentials(br#"Digest username="bob", nc=ABCDEF12"#).nc(),
            Err(HeaderError::Malformed(_))
        ));
        assert_eq!(
            credentials(br#"Digest username="bob", nc=0000000f"#).nc(),
            Ok(Some(15))
        );
        assert_eq!(credentials(br#"Digest username="bob""#).nc(), Ok(None));
    }

    #[test]
    fn stale_is_refused_when_it_is_neither_true_nor_false() {
        assert_eq!(
            challenge(br#"Digest realm="a", stale=true"#).stale(),
            Ok(Some(true))
        );
        assert_eq!(challenge(br#"Digest realm="a""#).stale(), Ok(None));
        assert!(matches!(
            challenge(br#"Digest realm="a", stale=maybe"#).stale(),
            Err(HeaderError::Malformed(_))
        ));
    }

    #[test]
    fn an_unregistered_algorithm_is_syntax_not_an_error() {
        assert_eq!(
            challenge(br#"Digest realm="a", nonce="n", algorithm=AKAv1-MD5, qop="auth""#)
                .algorithm()
                .as_deref(),
            Some(&b"AKAv1-MD5"[..])
        );
    }

    #[test]
    fn display_round_trips_the_parameters() {
        let c = credentials(br#"Digest username="bob", qop=auth, response="ab""#);
        assert_eq!(
            c.to_string(),
            r#"Digest username="bob", qop=auth, response="ab""#
        );
    }

    #[test]
    fn nothing_makes_the_auth_parser_panic() {
        for len in 0..14_usize {
            for seed in 0..96_u8 {
                let v: Vec<u8> = (0..len)
                    .map(|i| {
                        let b = seed
                            .wrapping_mul(41)
                            .wrapping_add(u8::try_from(i).unwrap_or(0));
                        match b % 8 {
                            0 => b'"',
                            1 => b'\\',
                            2 => b',',
                            3 => b'=',
                            4 => b' ',
                            5 => b'\r',
                            6 => b'\n',
                            _ => b,
                        }
                    })
                    .collect();
                if let Ok(c) = ChallengeRef::parse(&v) {
                    let _ = c.realm();
                    let _ = c.stale();
                    let _ = c.qop().count();
                    let _ = c.domain().count();
                    let _ = c.to_string();
                }
                if let Ok(c) = CredentialsRef::parse(&v) {
                    let _ = c.nc();
                    let _ = c.uri();
                    let _ = c.response();
                    let _ = c.to_string();
                }
            }
        }
    }
}
