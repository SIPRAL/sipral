// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! SIP URIs, borrowed from the buffer they arrived in.
//!
//! RFC 3261 §19.1:
//!
//! ```text
//! SIP-URI = "sip:" [ userinfo ] hostport uri-parameters [ headers ]
//! ```
//!
//! The order the pieces are found in matters. `user` may contain `;` and `?`
//! unescaped (§25.1 `user-unreserved`), so the userinfo boundary has to be
//! settled first: `sip:user;par=u%40example.net@example.com` has a user of
//! `user;par=u%40example.net` and a host of `example.com`, and a parser that
//! splits on the first `;` gets both wrong.

use core::fmt;
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The scheme of a URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UriScheme<'a> {
    /// `sip:`
    Sip,
    /// `sips:`
    Sips,
    /// `tel:` (RFC 3966).
    Tel,
    /// Anything else. A Request-URI may legally carry a scheme we do not
    /// know; answering it is the user agent's business, not the parser's.
    Other(&'a str),
}

impl UriScheme<'_> {
    /// The wire form, lowercase.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match *self {
            Self::Sip => "sip",
            Self::Sips => "sips",
            Self::Tel => "tel",
            Self::Other(s) => s,
        }
    }

    /// Whether the scheme implies TLS all the way to the peer.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        matches!(*self, Self::Sips)
    }
}

impl fmt::Display for UriScheme<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The host part of a URI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostRef<'a> {
    /// A domain name, as written.
    Name(&'a str),
    /// A literal IPv4 address.
    Ipv4(Ipv4Addr),
    /// A literal IPv6 address, written in brackets.
    Ipv6(Ipv6Addr),
}

/// Why a URI could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UriError {
    /// No scheme, or a scheme that is not a token.
    BadScheme,
    /// The host is missing.
    NoHost,
    /// The host is neither a name nor an address literal.
    BadHost,
    /// The port is not a number, or does not fit in 16 bits.
    BadPort,
    /// An IPv6 reference that never closes.
    UnclosedIpv6,
    /// Bytes that are not UTF-8, which no part of a URI may be.
    NotUtf8,
    /// A SIP URI was expected and the scheme is something else.
    NotSip,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::BadScheme => "missing or malformed scheme",
            Self::NoHost => "no host",
            Self::BadHost => "malformed host",
            Self::BadPort => "malformed port",
            Self::UnclosedIpv6 => "unclosed IPv6 reference",
            Self::NotUtf8 => "not UTF-8",
            Self::NotSip => "not a sip: or sips: URI",
        })
    }
}

impl core::error::Error for UriError {}

/// A URI, borrowed from the message it appeared in.
///
/// Only `sip:` and `sips:` have the `userinfo hostport parameters headers`
/// shape. A `tel:` URI carries a telephone subscriber and a Request-URI may
/// carry a scheme we have never heard of (RFC 4475 §3.3.2 and §3.3.4 are both
/// well-formed messages), so those are kept whole rather than forced into a
/// shape they do not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UriRef<'a> {
    /// A SIP or SIPS URI, in parts.
    Sip(SipUriRef<'a>),
    /// Any other scheme, kept as written.
    Other {
        /// The scheme.
        scheme: UriScheme<'a>,
        /// Everything after the colon.
        opaque: &'a str,
    },
}

impl<'a> UriRef<'a> {
    /// Parse a URI.
    ///
    /// # Errors
    /// See [`UriError`].
    pub fn parse(bytes: &'a [u8]) -> Result<Self, UriError> {
        let s = core::str::from_utf8(bytes).map_err(|_| UriError::NotUtf8)?;
        Self::parse_str(s)
    }

    /// Parse a URI that is already known to be UTF-8.
    ///
    /// # Errors
    /// See [`UriError`].
    pub fn parse_str(s: &'a str) -> Result<Self, UriError> {
        let (scheme, rest) = split_scheme(s)?;
        match scheme {
            UriScheme::Sip | UriScheme::Sips => {
                Ok(Self::Sip(SipUriRef::parse_after_scheme(scheme, rest)?))
            }
            _ => Ok(Self::Other {
                scheme,
                opaque: rest,
            }),
        }
    }

    /// The scheme, whichever kind of URI this is.
    #[must_use]
    pub const fn scheme(&self) -> UriScheme<'a> {
        match *self {
            Self::Sip(u) => u.scheme,
            Self::Other { scheme, .. } => scheme,
        }
    }

    /// The parts, when this is a SIP or SIPS URI.
    #[must_use]
    pub const fn sip(&self) -> Option<SipUriRef<'a>> {
        match *self {
            Self::Sip(u) => Some(u),
            Self::Other { .. } => None,
        }
    }
}

impl fmt::Display for UriRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Sip(u) => u.fmt(f),
            Self::Other { scheme, opaque } => write!(f, "{scheme}:{opaque}"),
        }
    }
}

fn split_scheme(s: &str) -> Result<(UriScheme<'_>, &str), UriError> {
    let colon = s.find(':').ok_or(UriError::BadScheme)?;
    let (scheme_str, rest) = s.split_at(colon);
    let rest = rest.get(1..).ok_or(UriError::BadScheme)?;
    if scheme_str.is_empty() || !scheme_str.bytes().all(is_scheme_byte) {
        return Err(UriError::BadScheme);
    }
    let scheme = if scheme_str.eq_ignore_ascii_case("sip") {
        UriScheme::Sip
    } else if scheme_str.eq_ignore_ascii_case("sips") {
        UriScheme::Sips
    } else if scheme_str.eq_ignore_ascii_case("tel") {
        UriScheme::Tel
    } else {
        UriScheme::Other(scheme_str)
    };
    Ok((scheme, rest))
}

/// A `sip:` or `sips:` URI, in parts.
///
/// Parameters and headers are kept as unparsed slices and walked on demand;
/// most callers ever ask for one or two of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SipUriRef<'a> {
    /// `sip`, `sips`, `tel`, or whatever was written.
    pub scheme: UriScheme<'a>,
    /// The user part, still escaped.
    pub user: Option<&'a str>,
    /// The password, still escaped. Deprecated by RFC 3261 §19.1.1 and
    /// carried only because it is still seen in the field.
    pub password: Option<&'a str>,
    /// The host.
    pub host: HostRef<'a>,
    /// The port, when one was given.
    pub port: Option<u16>,
    params: &'a str,
    headers: &'a str,
}

impl<'a> SipUriRef<'a> {
    /// Parse a `sip:` or `sips:` URI.
    ///
    /// # Errors
    /// See [`UriError`]. A URI of any other scheme is [`UriError::NotSip`].
    pub fn parse_str(s: &'a str) -> Result<Self, UriError> {
        let (scheme, rest) = split_scheme(s)?;
        match scheme {
            UriScheme::Sip | UriScheme::Sips => Self::parse_after_scheme(scheme, rest),
            _ => Err(UriError::NotSip),
        }
    }

    fn parse_after_scheme(scheme: UriScheme<'a>, rest: &'a str) -> Result<Self, UriError> {
        // userinfo first: an unescaped '@' cannot appear anywhere else
        let (userinfo, after_user) = match rest.find('@') {
            Some(at) => (
                Some(rest.get(..at).ok_or(UriError::BadScheme)?),
                rest.get(at + 1..).ok_or(UriError::BadScheme)?,
            ),
            None => (None, rest),
        };
        let (user, password) = match userinfo {
            None => (None, None),
            Some(info) => match info.find(':') {
                Some(c) => (info.get(..c), info.get(c + 1..)),
                None => (Some(info), None),
            },
        };

        // then headers, then parameters, then what is left is the hostport
        let (before_headers, headers) = match after_user.find('?') {
            Some(q) => (
                after_user.get(..q).unwrap_or_default(),
                after_user.get(q + 1..).unwrap_or_default(),
            ),
            None => (after_user, ""),
        };
        let (hostport, params) = match before_headers.find(';') {
            Some(sc) => (
                before_headers.get(..sc).unwrap_or_default(),
                before_headers.get(sc + 1..).unwrap_or_default(),
            ),
            None => (before_headers, ""),
        };

        let (host, port) = parse_hostport(hostport)?;

        Ok(Self {
            scheme,
            user,
            password,
            host,
            port,
            params,
            headers,
        })
    }

    /// The value of one URI parameter, matched case-insensitively on the
    /// name. `Some("")` for a parameter written without a value.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&'a str> {
        self.params()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.unwrap_or_default())
    }

    /// Whether a parameter is present at all, with or without a value.
    #[must_use]
    pub fn has_param(&self, name: &str) -> bool {
        self.params().any(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    /// Every URI parameter, in the order written.
    #[must_use]
    pub fn params(&self) -> UriParamIter<'a> {
        UriParamIter { rest: self.params }
    }

    /// Every URI header, in the order written.
    #[must_use]
    pub fn headers(&self) -> UriHeaderIter<'a> {
        UriHeaderIter { rest: self.headers }
    }

    /// `;lr`: the peer is a loose router (RFC 3261 §19.1.1).
    #[must_use]
    pub fn is_loose_route(&self) -> bool {
        self.has_param("lr")
    }

    /// `;transport=`.
    #[must_use]
    pub fn transport(&self) -> Option<&'a str> {
        self.param("transport")
    }

    /// `;maddr=`.
    #[must_use]
    pub fn maddr(&self) -> Option<&'a str> {
        self.param("maddr")
    }

    /// The raw parameter text, without the leading `;`.
    #[must_use]
    pub const fn params_raw(&self) -> &'a str {
        self.params
    }

    /// The raw header text, without the leading `?`.
    #[must_use]
    pub const fn headers_raw(&self) -> &'a str {
        self.headers
    }
}

impl fmt::Display for SipUriRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;
        if let Some(user) = self.user {
            f.write_str(user)?;
            if let Some(pw) = self.password {
                write!(f, ":{pw}")?;
            }
            f.write_str("@")?;
        }
        match self.host {
            HostRef::Name(n) => f.write_str(n)?,
            HostRef::Ipv4(a) => write!(f, "{a}")?,
            HostRef::Ipv6(a) => write!(f, "[{a}]")?,
        }
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        if !self.params.is_empty() {
            write!(f, ";{}", self.params)?;
        }
        if !self.headers.is_empty() {
            write!(f, "?{}", self.headers)?;
        }
        Ok(())
    }
}

/// URI parameters, parsed one at a time.
#[derive(Clone, Debug)]
pub struct UriParamIter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for UriParamIter<'a> {
    type Item = (&'a str, Option<&'a str>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let (field, rest) = match self.rest.find(';') {
            Some(i) => (self.rest.get(..i)?, self.rest.get(i + 1..)?),
            None => (self.rest, ""),
        };
        self.rest = rest;
        Some(match field.find('=') {
            Some(i) => (field.get(..i)?, field.get(i + 1..)),
            None => (field, None),
        })
    }
}

/// URI headers, parsed one at a time.
#[derive(Clone, Debug)]
pub struct UriHeaderIter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for UriHeaderIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let (field, rest) = match self.rest.find('&') {
            Some(i) => (self.rest.get(..i)?, self.rest.get(i + 1..)?),
            None => (self.rest, ""),
        };
        self.rest = rest;
        Some(match field.find('=') {
            Some(i) => (field.get(..i)?, field.get(i + 1..).unwrap_or_default()),
            None => (field, ""),
        })
    }
}

/// Undo `%` escaping (RFC 3261 §25.1 `escaped`).
///
/// Borrows when there is nothing to undo. Works on bytes because an escape
/// may legally produce one that is not valid UTF-8 on its own, and because
/// `%00` is legal and appears in the RFC 4475 corpus. A `%` that is not
/// followed by two hex digits is left alone rather than refused: that case is
/// in the corpus as a *valid* message.
#[must_use]
pub fn unescape(bytes: &[u8]) -> Cow<'_, [u8]> {
    if !bytes.contains(&b'%') {
        return Cow::Borrowed(bytes);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%'
            && let (Some(h), Some(l)) = (bytes.get(i + 1), bytes.get(i + 2))
            && let (Some(h), Some(l)) = (hex(*h), hex(*l))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(b);
        i += 1;
    }
    Cow::Owned(out)
}

const fn hex(b: u8) -> Option<u8> {
    Some(match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => return None,
    })
}

const fn is_scheme_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
}

fn parse_hostport(s: &str) -> Result<(HostRef<'_>, Option<u16>), UriError> {
    if s.is_empty() {
        return Err(UriError::NoHost);
    }
    if let Some(inner) = s.strip_prefix('[') {
        let close = inner.find(']').ok_or(UriError::UnclosedIpv6)?;
        let addr: Ipv6Addr = inner
            .get(..close)
            .ok_or(UriError::BadHost)?
            .parse()
            .map_err(|_| UriError::BadHost)?;
        let tail = inner.get(close + 1..).unwrap_or_default();
        return Ok((HostRef::Ipv6(addr), parse_port(tail)?));
    }

    let (host, tail) = match s.rfind(':') {
        Some(i) => (
            s.get(..i).unwrap_or_default(),
            s.get(i..).unwrap_or_default(),
        ),
        None => (s, ""),
    };
    if host.is_empty() {
        return Err(UriError::NoHost);
    }
    let host = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        HostRef::Ipv4(v4)
    } else if is_hostname(host) {
        HostRef::Name(host)
    } else {
        return Err(UriError::BadHost);
    };
    Ok((host, parse_port(tail)?))
}

fn parse_port(tail: &str) -> Result<Option<u16>, UriError> {
    match tail.strip_prefix(':') {
        None if tail.is_empty() => Ok(None),
        None => Err(UriError::BadPort),
        Some(digits) => {
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(UriError::BadPort);
            }
            digits.parse().map(Some).map_err(|_| UriError::BadPort)
        }
    }
}

/// Domain labels, permissive about a leading digit because the field is full
/// of hosts like `1.example.com`.
fn is_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::{HostRef, SipUriRef, UriError, UriRef, UriScheme, unescape};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn uri(s: &str) -> SipUriRef<'_> {
        SipUriRef::parse_str(s).expect("a SIP URI")
    }

    #[test]
    fn a_plain_sip_uri() {
        let u = uri("sip:bob@example.com");
        assert_eq!(u.scheme, UriScheme::Sip);
        assert_eq!(u.user, Some("bob"));
        assert_eq!(u.password, None);
        assert_eq!(u.host, HostRef::Name("example.com"));
        assert_eq!(u.port, None);
    }

    #[test]
    fn semicolons_and_question_marks_are_legal_in_the_user_part() {
        // RFC 4475 3.1.1.9, the case a naive split on ';' gets wrong
        let u = uri("sip:user;par=u%40example.net@example.com");
        assert_eq!(u.user, Some("user;par=u%40example.net"));
        assert_eq!(u.host, HostRef::Name("example.com"));
        assert_eq!(u.params().count(), 0);
    }

    #[test]
    fn escaped_nulls_survive_unescaping() {
        // RFC 4475 3.1.1.4
        let u = uri("sip:null-%00-null@example.com");
        assert_eq!(u.user, Some("null-%00-null"));
        assert_eq!(
            unescape(u.user.unwrap_or_default().as_bytes()).as_ref(),
            b"null-\x00-null"
        );
    }

    #[test]
    fn a_stray_percent_is_left_alone() {
        // RFC 4475 3.1.1.5 is a valid message
        assert_eq!(unescape(b"100%%zz").as_ref(), b"100%%zz");
        assert_eq!(unescape(b"%4").as_ref(), b"%4");
    }

    #[test]
    fn unescaping_borrows_when_there_is_nothing_to_do() {
        assert!(matches!(unescape(b"plain"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn scheme_is_case_insensitive_and_unknown_ones_are_kept() {
        assert_eq!(uri("SIP:a@b").scheme, UriScheme::Sip);
        assert_eq!(uri("SIPS:a@b").scheme, UriScheme::Sips);
        assert!(uri("sips:a@b").scheme.is_secure());
        assert!(!uri("sip:a@b").scheme.is_secure());
    }

    #[test]
    fn a_non_sip_scheme_is_kept_whole_rather_than_forced_into_a_hostport() {
        // RFC 4475 3.3.2 and 3.3.4 are well-formed messages: refusing an
        // unknown scheme is the user agent's job, not the parser's
        let tel = UriRef::parse_str("tel:+1-201-555-0123").expect("a URI");
        assert_eq!(tel.scheme(), UriScheme::Tel);
        assert_eq!(tel.sip(), None);
        assert_eq!(tel.to_string(), "tel:+1-201-555-0123");

        let odd = UriRef::parse_str("nobodyKnowsThisScheme:totally-opaque").expect("a URI");
        assert_eq!(odd.scheme(), UriScheme::Other("nobodyKnowsThisScheme"));
        assert!(odd.sip().is_none());

        assert_eq!(
            SipUriRef::parse_str("tel:+1-201-555-0123"),
            Err(UriError::NotSip)
        );
    }

    #[test]
    fn a_sip_uri_reached_through_the_enum_still_has_its_parts() {
        let u = UriRef::parse_str("sips:alice@example.com:5061").expect("a URI");
        let sip = u.sip().expect("sip parts");
        assert_eq!(sip.user, Some("alice"));
        assert_eq!(sip.port, Some(5061));
        assert!(u.scheme().is_secure());
    }

    #[test]
    fn password_is_split_off_the_user() {
        let u = uri("sip:alice:secret@example.com");
        assert_eq!(u.user, Some("alice"));
        assert_eq!(u.password, Some("secret"));
    }

    #[test]
    fn host_can_be_a_literal_address() {
        assert_eq!(
            uri("sip:192.0.2.1").host,
            HostRef::Ipv4(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(uri("sip:192.0.2.1:5060").port, Some(5060));
        assert_eq!(
            uri("sip:[2001:db8::1]").host,
            HostRef::Ipv6("2001:db8::1".parse::<Ipv6Addr>().expect("v6"))
        );
        assert_eq!(uri("sip:[2001:db8::1]:5061").port, Some(5061));
    }

    #[test]
    fn parameters_are_walked_lazily_and_matched_without_case() {
        let u = uri("sip:a@b;transport=TCP;lr;maddr=239.255.255.1");
        assert_eq!(u.transport(), Some("TCP"));
        assert_eq!(u.param("TRANSPORT"), Some("TCP"));
        assert!(u.is_loose_route());
        assert_eq!(u.param("lr"), Some(""));
        assert_eq!(u.maddr(), Some("239.255.255.1"));
        assert_eq!(u.param("nope"), None);
        assert_eq!(u.params().count(), 3);
    }

    #[test]
    fn a_valueless_parameter_is_present_but_empty() {
        let u = uri("sip:a@b;lr");
        assert!(u.has_param("lr"));
        assert_eq!(u.params().next(), Some(("lr", None)));
    }

    #[test]
    fn headers_come_after_the_parameters() {
        let u = uri("sip:a@b;transport=tcp?subject=x&priority=urgent");
        assert_eq!(u.transport(), Some("tcp"));
        let hs: Vec<_> = u.headers().collect();
        assert_eq!(hs, vec![("subject", "x"), ("priority", "urgent")]);
    }

    #[test]
    fn user_may_contain_a_question_mark_before_the_headers_start() {
        let u = uri("sip:us?er@example.com?subject=x");
        assert_eq!(u.user, Some("us?er"));
        assert_eq!(u.host, HostRef::Name("example.com"));
        assert_eq!(u.headers().next(), Some(("subject", "x")));
    }

    #[test]
    fn malformed_uris_are_refused() {
        assert_eq!(SipUriRef::parse_str("no-colon"), Err(UriError::BadScheme));
        assert_eq!(SipUriRef::parse_str(":a@b"), Err(UriError::BadScheme));
        assert_eq!(SipUriRef::parse_str("sip:"), Err(UriError::NoHost));
        assert_eq!(SipUriRef::parse_str("sip:a@"), Err(UriError::NoHost));
        assert_eq!(SipUriRef::parse_str("sip:a@b:"), Err(UriError::BadPort));
        assert_eq!(
            SipUriRef::parse_str("sip:a@b:99999"),
            Err(UriError::BadPort)
        );
        assert_eq!(SipUriRef::parse_str("sip:a@b:xy"), Err(UriError::BadPort));
        assert_eq!(
            SipUriRef::parse_str("sip:a@[2001:db8::1"),
            Err(UriError::UnclosedIpv6)
        );
        assert_eq!(
            SipUriRef::parse_str("sip:a@-bad-.invalid"),
            Err(UriError::BadHost)
        );
    }

    #[test]
    fn not_utf8_is_refused_rather_than_guessed() {
        assert_eq!(UriRef::parse(b"sip:a@\xff\xfe"), Err(UriError::NotUtf8));
    }

    #[test]
    fn display_round_trips_what_was_parsed() {
        for s in [
            "sip:bob@example.com",
            "sips:alice:pw@example.com:5061",
            "sip:192.0.2.1:5060;transport=udp",
            "sip:[2001:db8::1]:5060;lr",
            "sip:a@b;transport=tcp?subject=x",
        ] {
            assert_eq!(uri(s).to_string(), s);
        }
    }

    #[test]
    fn nothing_makes_the_uri_parser_panic() {
        for len in 0..12_usize {
            for seed in 0..96_u8 {
                let s: String = (0..len)
                    .map(|i| {
                        let b = seed
                            .wrapping_mul(37)
                            .wrapping_add(u8::try_from(i).unwrap_or(0));
                        char::from(b'!' + b % 93)
                    })
                    .collect();
                let _ = UriRef::parse_str(&s);
                let _ = SipUriRef::parse_str(&s);
                let _ = SipUriRef::parse_str(&format!("sip:{s}"));
            }
        }
    }
}
