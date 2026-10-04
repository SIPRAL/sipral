// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
use std::sync::Arc;

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
    /// More than 4 GiB of URI, which [`Uri`] records offsets into.
    TooLong,
    /// A space, a control byte, or one of `"` `<` `>`, unescaped. RFC 3261
    /// §19.1.2 has all of them escaped, and each one would end the URI early
    /// in the line or the brackets it is written back into.
    IllegalByte,
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
            Self::TooLong => "URI too long to keep",
            Self::IllegalByte => "a space, a control byte, or a quote or angle bracket, unescaped",
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
        check_bytes(s)?;
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

    /// Keep this URI past the buffer it points into.
    ///
    /// The URI is written out again from its parts, so a scheme spelled in
    /// another case and an IPv6 literal written the long way come back
    /// canonical. Those are equivalent spellings of the same URI (§19.1.4),
    /// but when the bytes themselves matter — a route set entry that has to go
    /// back on the wire exactly as it arrived — build the owned form from the
    /// original slice with [`Uri::parse`] instead.
    #[must_use]
    pub fn to_owned(&self) -> Uri {
        Uri::from_rendered(self.to_string())
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
    Ok((classify_scheme(scheme_str), rest))
}

/// Refuse the bytes that would change the shape of whatever a URI is written
/// back into (RFC 3261 §19.1.2: "URIs MUST NOT contain unescaped space and
/// control characters", and RFC 2396's delimiters are escaped too).
///
/// Whitespace ends a Request-URI, a control byte or a line break ends a header
/// line, `<` and `>` are the brackets of a `name-addr`, and `"` opens a quoted
/// string that runs past the closing bracket. Every URI this stack keeps from
/// a peer — a remote target, a route, a `Refer-To` target — is written into
/// another message later, so it is refused here, once, rather than escaped at
/// each of those places. Bytes the grammar also excludes but that shape
/// nothing (`#`, `{`, `|`, bytes above 0x7F) are left to the leniency the
/// field needs.
fn check_bytes(s: &str) -> Result<(), UriError> {
    if s.bytes()
        .any(|b| matches!(b, 0x00..=0x20 | 0x7f | b'"' | b'<' | b'>'))
    {
        return Err(UriError::IllegalByte);
    }
    Ok(())
}

fn classify_scheme(s: &str) -> UriScheme<'_> {
    if s.eq_ignore_ascii_case("sip") {
        UriScheme::Sip
    } else if s.eq_ignore_ascii_case("sips") {
        UriScheme::Sips
    } else if s.eq_ignore_ascii_case("tel") {
        UriScheme::Tel
    } else {
        UriScheme::Other(s)
    }
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
        check_bytes(s)?;
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

/// A URI kept past the buffer it arrived in.
///
/// The text is held once, in an `Arc<str>`, and the parts are recorded as
/// offsets into it. Borrowing the parsed form back out is therefore free and
/// cannot fail, and a clone shares the text instead of copying it — a dialog's
/// route set and every request built from it end up pointing at the same bytes.
///
/// There is deliberately no `PartialEq`. "Same bytes" and "same resource" are
/// different questions and `==` can only answer one of them. Worse, the second
/// one is not transitive, as RFC 3261 §19.1.4 points out itself: a URI is
/// equivalent to itself with `;security=on` and to itself with
/// `;security=off`, while those two are not equivalent to each other. So the
/// question has to be asked by name — [`Uri::as_str`] for the bytes,
/// [`Uri::equivalent`] for the resource.
#[derive(Clone)]
pub struct Uri {
    text: Arc<str>,
    parts: Parts,
}

/// The parts, as offsets into the text.
#[derive(Clone, Copy, Debug)]
enum Parts {
    Sip {
        secure: bool,
        user: Option<Slice>,
        password: Option<Slice>,
        host: OwnedHost,
        port: Option<u16>,
        params: Slice,
        headers: Slice,
    },
    Other {
        scheme: Slice,
        opaque: Slice,
    },
}

#[derive(Clone, Copy, Debug)]
enum OwnedHost {
    Name(Slice),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

/// Where one part sits in the text.
#[derive(Clone, Copy, Debug)]
struct Slice {
    start: u32,
    end: u32,
}

impl Slice {
    const EMPTY: Self = Self { start: 0, end: 0 };

    /// `part` is always a subslice of `base` here: both come out of one parse
    /// of one string. A part that is not lands on the empty slice, which is
    /// wrong but bounded, rather than on some other part's bytes.
    fn of(base: &str, part: &str) -> Self {
        let offset = (part.as_ptr() as usize).wrapping_sub(base.as_ptr() as usize);
        let end = offset.saturating_add(part.len());
        if end > base.len() {
            return Self::EMPTY;
        }
        match (u32::try_from(offset), u32::try_from(end)) {
            (Ok(start), Ok(end)) => Self { start, end },
            _ => Self::EMPTY,
        }
    }

    fn whole(base: &str) -> Self {
        Self::of(base, base)
    }

    fn get(self, base: &str) -> &str {
        let range =
            usize::try_from(self.start).unwrap_or(0)..usize::try_from(self.end).unwrap_or(0);
        base.get(range).unwrap_or_default()
    }
}

impl Uri {
    /// Parse and keep a URI.
    ///
    /// # Errors
    /// See [`UriError`].
    pub fn parse(bytes: &[u8]) -> Result<Self, UriError> {
        Self::parse_str(core::str::from_utf8(bytes).map_err(|_| UriError::NotUtf8)?)
    }

    /// Parse and keep a URI that is already known to be UTF-8.
    ///
    /// # Errors
    /// See [`UriError`].
    pub fn parse_str(s: &str) -> Result<Self, UriError> {
        if u32::try_from(s.len()).is_err() {
            return Err(UriError::TooLong);
        }
        let text: Arc<str> = Arc::from(s);
        let parts = Parts::of(&text, UriRef::parse_str(&text)?);
        Ok(Self { text, parts })
    }

    /// Take text that was written out from an already parsed URI.
    fn from_rendered(text: String) -> Self {
        let text: Arc<str> = Arc::from(text);
        let parts = match UriRef::parse_str(&text) {
            Ok(parsed) => Parts::of(&text, parsed),
            // Unreachable: the text was written from a URI that parsed. If it
            // ever is reached, keeping the whole thing opaque hands back every
            // byte it was given and claims nothing about them.
            Err(_) => Parts::Other {
                scheme: Slice::EMPTY,
                opaque: Slice::whole(&text),
            },
        };
        Self { text, parts }
    }

    /// The URI as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The URI as written, in bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// The parts, borrowed.
    #[must_use]
    pub fn as_uri_ref(&self) -> UriRef<'_> {
        match self.parts {
            Parts::Sip {
                secure,
                user,
                password,
                host,
                port,
                params,
                headers,
            } => UriRef::Sip(SipUriRef {
                scheme: if secure {
                    UriScheme::Sips
                } else {
                    UriScheme::Sip
                },
                user: user.map(|s| s.get(&self.text)),
                password: password.map(|s| s.get(&self.text)),
                host: match host {
                    OwnedHost::Name(s) => HostRef::Name(s.get(&self.text)),
                    OwnedHost::Ipv4(a) => HostRef::Ipv4(a),
                    OwnedHost::Ipv6(a) => HostRef::Ipv6(a),
                },
                port,
                params: params.get(&self.text),
                headers: headers.get(&self.text),
            }),
            Parts::Other { scheme, opaque } => UriRef::Other {
                scheme: classify_scheme(scheme.get(&self.text)),
                opaque: opaque.get(&self.text),
            },
        }
    }

    /// The scheme.
    #[must_use]
    pub fn scheme(&self) -> UriScheme<'_> {
        self.as_uri_ref().scheme()
    }

    /// The parts, when this is a SIP or SIPS URI.
    #[must_use]
    pub fn sip(&self) -> Option<SipUriRef<'_>> {
        self.as_uri_ref().sip()
    }

    /// Whether the scheme is `sips`.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        matches!(self.parts, Parts::Sip { secure: true, .. })
    }

    /// The value of one URI parameter, matched case-insensitively on the name.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.sip().and_then(|u| u.param(name))
    }

    /// Whether a parameter is present at all, with or without a value.
    #[must_use]
    pub fn has_param(&self, name: &str) -> bool {
        self.sip().is_some_and(|u| u.has_param(name))
    }

    /// `;lr`: the peer is a loose router (RFC 3261 §19.1.1).
    #[must_use]
    pub fn is_loose_route(&self) -> bool {
        self.has_param("lr")
    }

    /// The same URI, in the form it may take as a Request-URI (§19.1.5).
    ///
    /// The `method` parameter is dropped — "The method parameter MUST NOT be
    /// placed in the Request-URI" — and so are the URI headers, which name
    /// header fields for the message rather than parts of the address.
    /// Everything else stays, known or not: §19.1.5 requires the transport,
    /// maddr, ttl and user parameters to be carried over, and unknown
    /// parameters with them.
    #[must_use]
    pub fn as_request_uri(&self) -> Self {
        let Some(sip) = self.sip() else {
            return self.clone();
        };
        if sip.headers_raw().is_empty() && !sip.has_param("method") {
            return self.clone();
        }

        let mut out = String::with_capacity(self.text.len());
        out.push_str(sip.scheme.as_str());
        out.push(':');
        if let Some(user) = sip.user {
            out.push_str(user);
            if let Some(password) = sip.password {
                out.push(':');
                out.push_str(password);
            }
            out.push('@');
        }
        match sip.host {
            HostRef::Name(name) => out.push_str(name),
            HostRef::Ipv4(addr) => out.push_str(&addr.to_string()),
            HostRef::Ipv6(addr) => {
                out.push('[');
                out.push_str(&addr.to_string());
                out.push(']');
            }
        }
        if let Some(port) = sip.port {
            out.push(':');
            out.push_str(&port.to_string());
        }
        for (name, value) in sip.params() {
            if name.eq_ignore_ascii_case("method") {
                continue;
            }
            out.push(';');
            out.push_str(name);
            if let Some(value) = value {
                out.push('=');
                out.push_str(value);
            }
        }
        Self::from_rendered(out)
    }

    /// Whether two URIs address the same resource (RFC 3261 §19.1.4).
    ///
    /// Escapes are compared decoded, which is what "characters other than
    /// those in the reserved set are equivalent to their `%HEX HEX` encoding"
    /// asks for — with the one restriction that an escape standing for a
    /// character that is not unreserved stays escaped. Decoding `%3B` would
    /// turn a piece of a user name into a parameter separator, and decoding
    /// `%25` would produce a bare `%`, which is not legal in a URI at all.
    ///
    /// One simplification, said out loud because it is a deviation: URI header
    /// values are compared as text, not by the per-field rules §20 defines for
    /// each header, and the text keeps its case. Some of those rules ignore
    /// case and some do not — a `Call-ID`, the user of a URI in `to=` — and
    /// when the field's own rule is not applied, the answer that never
    /// matches where that rule would not is the one given.
    #[must_use]
    pub fn equivalent(&self, other: &Self) -> bool {
        match (self.as_uri_ref(), other.as_uri_ref()) {
            (UriRef::Sip(a), UriRef::Sip(b)) => sip_equivalent(a, b),
            // §19.1.4 is written for SIP and SIPS. Other schemes have their own
            // rules — RFC 3966 §4 for tel: — and until those are implemented the
            // only honest answer is the one that never claims a match that has
            // not been proven.
            (
                UriRef::Other {
                    scheme: a,
                    opaque: a_rest,
                },
                UriRef::Other {
                    scheme: b,
                    opaque: b_rest,
                },
            ) => a.as_str().eq_ignore_ascii_case(b.as_str()) && a_rest == b_rest,
            _ => false,
        }
    }
}

impl Parts {
    fn of(base: &str, uri: UriRef<'_>) -> Self {
        match uri {
            UriRef::Sip(u) => Self::Sip {
                secure: u.scheme.is_secure(),
                user: u.user.map(|s| Slice::of(base, s)),
                password: u.password.map(|s| Slice::of(base, s)),
                host: match u.host {
                    HostRef::Name(name) => OwnedHost::Name(Slice::of(base, name)),
                    HostRef::Ipv4(addr) => OwnedHost::Ipv4(addr),
                    HostRef::Ipv6(addr) => OwnedHost::Ipv6(addr),
                },
                port: u.port,
                params: Slice::of(base, u.params_raw()),
                headers: Slice::of(base, u.headers_raw()),
            },
            // The scheme is whatever precedes the colon the opaque part starts
            // after; taking it from the text rather than from `UriScheme` keeps
            // `tel:`, whose name is a constant, pointing at the right bytes.
            UriRef::Other { opaque, .. } => {
                let opaque = Slice::of(base, opaque);
                Self::Other {
                    scheme: Slice {
                        start: 0,
                        end: opaque.start.saturating_sub(1),
                    },
                    opaque,
                }
            }
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uri({:?})", &*self.text)
    }
}

/// Present in only one URI, and then the two never match (§19.1.4). The list
/// is the RFC's `user`, `ttl` and `method`, plus `maddr`, which gets its own
/// sentence, plus `transport`, which the RFC leaves out of the list and then
/// uses in its own example of two URIs that are *not* equivalent.
const DECISIVE_PARAMS: [&str; 5] = ["user", "ttl", "method", "maddr", "transport"];

fn sip_equivalent(a: SipUriRef<'_>, b: SipUriRef<'_>) -> bool {
    // "A SIP and SIPS URI are never equivalent."
    if a.scheme.is_secure() != b.scheme.is_secure() {
        return false;
    }
    // "Comparison of the userinfo of SIP and SIPS URIs is case-sensitive."
    if !optional_matches(a.user, b.user, Case::Sensitive)
        || !optional_matches(a.password, b.password, Case::Sensitive)
        || !hosts_match(a.host, b.host)
    {
        return false;
    }
    // "A URI omitting the optional port component will not match a URI
    // explicitly declaring port 5060."
    if a.port != b.port {
        return false;
    }
    params_match(a, b) && params_match(b, a) && headers_match(a, b) && headers_match(b, a)
}

fn params_match(a: SipUriRef<'_>, b: SipUriRef<'_>) -> bool {
    a.params().all(|(name, value)| {
        match b.params().find(|(n, _)| names_match(n, name)) {
            // "Any uri-parameter appearing in both URIs must match."
            Some((_, other)) => text_matches(
                value.unwrap_or_default(),
                other.unwrap_or_default(),
                Case::Insensitive,
            ),
            // "All other uri-parameters appearing in only one URI are ignored."
            None => !DECISIVE_PARAMS.iter().any(|k| names_match(name, k)),
        }
    })
}

/// A parameter or header name is escapable like any other part (§25.1
/// `pname`, `hname`), so `%6Daddr` is `maddr` and has to be found as one.
fn names_match(a: &str, b: &str) -> bool {
    text_matches(a, b, Case::Insensitive)
}

fn headers_match(a: SipUriRef<'_>, b: SipUriRef<'_>) -> bool {
    // "URI header components are never ignored. Any present header component
    // MUST be present in both URIs and match for the URIs to match." A name
    // may be given more than once, and fields of one name keep their order
    // (§7.3.1), so the n-th field of a name is held against the n-th field of
    // that name in the other URI. Asked both ways, that also makes the counts
    // agree.
    a.headers().enumerate().all(|(at, (name, value))| {
        let nth = a
            .headers()
            .take(at)
            .filter(|(n, _)| names_match(n, name))
            .count();
        b.headers()
            .filter(|(n, _)| names_match(n, name))
            .nth(nth)
            .is_some_and(|(_, other)| text_matches(value, other, Case::Sensitive))
    })
}

fn hosts_match(a: HostRef<'_>, b: HostRef<'_>) -> bool {
    match (a, b) {
        (HostRef::Name(a), HostRef::Name(b)) => a.eq_ignore_ascii_case(b),
        (HostRef::Ipv4(a), HostRef::Ipv4(b)) => a == b,
        (HostRef::Ipv6(a), HostRef::Ipv6(b)) => a == b,
        // "An IP address that is the result of a DNS lookup of a host name
        // does not match that host name."
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Sensitive,
    Insensitive,
}

fn optional_matches(a: Option<&str>, b: Option<&str>, case: Case) -> bool {
    match (a, b) {
        (None, None) => true,
        // "A URI omitting the user component will not match a URI that
        // includes one."
        (Some(a), Some(b)) => text_matches(a, b, case),
        _ => false,
    }
}

fn text_matches(a: &str, b: &str, case: Case) -> bool {
    let (a, b) = (decode_unreserved(a), decode_unreserved(b));
    match case {
        Case::Sensitive => a == b,
        Case::Insensitive => a.eq_ignore_ascii_case(&b),
    }
}

/// Undo the escapes that stand for unreserved characters, and write the rest
/// in one case so that `%2f` and `%2F` compare equal.
///
/// A `%` that does not start an escape is the octet `%` and comes out as
/// `%25`. Copied through bare, it would join whatever a decoded escape puts
/// after it: `%%33B` would read as `%3B`, the escape of a semicolon.
fn decode_unreserved(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%'
            && let (Some(high), Some(low)) = (bytes.get(i + 1), bytes.get(i + 2))
            && let (Some(high), Some(low)) = (hex(*high), hex(*low))
        {
            let decoded = high * 16 + low;
            if is_unreserved(decoded) {
                out.push(decoded);
            } else {
                out.push(b'%');
                out.push(hex_digit(high));
                out.push(hex_digit(low));
            }
            i += 3;
            continue;
        }
        if b == b'%' {
            out.extend_from_slice(b"%25");
        } else {
            out.push(b);
        }
        i += 1;
    }
    out
}

const fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + value - 10,
    }
}

/// RFC 2396 `unreserved = alphanum | mark`.
const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
        )
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

/// Shared with Via's sent-by, where RFC 3261 §25.1 makes the colon `SWS ":" SWS`,
/// so both halves are trimmed.
pub(super) fn parse_hostport(s: &str) -> Result<(HostRef<'_>, Option<u16>), UriError> {
    let s = s.trim_matches([' ', '\t', '\r', '\n']);
    if s.is_empty() {
        return Err(UriError::NoHost);
    }
    if let Some(inner) = s.strip_prefix('[') {
        let close = inner.find(']').ok_or(UriError::UnclosedIpv6)?;
        let literal = inner.get(..close).ok_or(UriError::BadHost)?;
        let addr = literal
            .parse::<Ipv6Addr>()
            .ok()
            .or_else(|| rfc3261_three_colons(literal))
            .ok_or(UriError::BadHost)?;
        let tail = inner.get(close + 1..).unwrap_or_default();
        return Ok((HostRef::Ipv6(addr), parse_port(tail)?));
    }

    let (host, tail) = match s.rfind(':') {
        // COLON is SWS ":" SWS where this is shared with Via's sent-by
        Some(i) => (
            s.get(..i).unwrap_or_default().trim_ascii_end(),
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

/// The IPv6 reference RFC 3261's own grammar produces and RFC 4291 does not
/// allow: `hexpart ":" IPv4address` with a `hexpart` ending in `::`, as in
/// `2001:db8:::192.0.2.1`. RFC 5118 §4.10 has an implementation tolerate it
/// and read it as the address without the extra colon.
fn rfc3261_three_colons(literal: &str) -> Option<Ipv6Addr> {
    let (head, tail) = literal.split_once(":::")?;
    let v4: Ipv4Addr = tail.parse().ok()?;
    let mut groups = [0_u16; 8];
    let mut count = 0;
    if !head.is_empty() {
        for group in head.split(':') {
            if group.is_empty() || group.len() > 4 {
                return None;
            }
            // "::" stands for at least one group, and the IPv4 tail is two
            if count == 5 {
                return None;
            }
            *groups.get_mut(count)? = u16::from_str_radix(group, 16).ok()?;
            count += 1;
        }
    }
    let [a, b, c, d] = v4.octets();
    groups[6] = u16::from_be_bytes([a, b]);
    groups[7] = u16::from_be_bytes([c, d]);
    Some(Ipv6Addr::from(groups))
}

fn parse_port(tail: &str) -> Result<Option<u16>, UriError> {
    match tail.strip_prefix(':') {
        None if tail.is_empty() => Ok(None),
        None => Err(UriError::BadPort),
        Some(digits) => {
            let digits = digits.trim_ascii_start();
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
    use super::{HostRef, SipUriRef, Uri, UriError, UriRef, UriScheme, unescape};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

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
    fn the_three_colon_form_rfc_3261s_grammar_allows_is_tolerated() {
        // RFC 5118 §4.10: "an implementation must tolerate both of the above
        // constructs", reading the address without the extra colon
        assert_eq!(
            uri("sip:user@[2001:db8:::192.0.2.1]").host,
            HostRef::Ipv6("2001:db8::192.0.2.1".parse::<Ipv6Addr>().expect("v6"))
        );
        assert_eq!(
            uri("sip:[:::192.0.2.1]:5060").host,
            HostRef::Ipv6("::192.0.2.1".parse::<Ipv6Addr>().expect("v6"))
        );
        // and nothing else that is not an IPv6 address comes in with it
        for bad in [
            "sip:[2001:db8:::1]",
            "sip:[1:2:3:4:5:6:::192.0.2.1]",
            "sip:[::::192.0.2.1]",
            "sip:[2001::db8:::192.0.2.1]",
            "sip:[20011:db8:::192.0.2.1]",
            "sip:[2001:db8:::192.0.2]",
        ] {
            assert_eq!(
                SipUriRef::parse_str(bad).map(|u| u.host),
                Err(UriError::BadHost),
                "{bad}"
            );
        }
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
    fn a_uri_holds_no_byte_that_would_end_what_it_is_written_into() {
        // §19.1.2: "URIs MUST NOT contain unescaped space and control
        // characters", and the delimiters RFC 2396 excludes have to be escaped
        // too. These are the ones that change the shape of the line a URI is
        // written back into: whitespace ends a Request-URI, a control byte or
        // a line break ends the header, '<' and '>' are the brackets of a
        // name-addr, and '"' opens a quoted string that swallows the rest.
        for uri in [
            "sip:carol>;tag=abc@example.com",
            "sip:a\"b@example.com",
            "sip:a<b@example.com",
            "sip:alice@example.com;x=\"",
            "sip:alice@example.com?subject=a>b",
            "sip:alice smith@example.com",
            "sip:alice@example.com;x=a\tb",
            "sip:alice@example.com;x=a\r\nVia: evil",
            "sip:null\0byte@example.com",
            "sip:del\u{7f}@example.com",
            "tel:+1-201-555-0123;x=>",
            "urn:service:sos<",
        ] {
            assert_eq!(
                Uri::parse_str(uri).map(|u| u.to_string()),
                Err(UriError::IllegalByte),
                "{uri:?}"
            );
            assert_eq!(
                SipUriRef::parse_str(uri).map(|u| u.to_string()),
                Err(UriError::IllegalByte),
                "{uri:?}"
            );
        }
        // the escaped forms are the way to carry those bytes, and still parse
        assert!(Uri::parse_str("sip:a%22b%3C%3E%20%00@example.com").is_ok());
    }

    #[test]
    fn whatever_a_uri_accepts_comes_back_whole_from_between_brackets() {
        // the property the refusal above buys: a URI kept from one message can
        // be written into another as <uri>;tag=t and read back as the same URI
        // with the same one parameter
        let candidates = [
            "sip:carol>;tag=abc@example.com",
            "sip:a\"b@example.com;tag=x",
            "sip:alice@example.com;x=\"",
            "sip:x<y@example.com",
            "sip:user;par=u%40example.net@example.com:5060;transport=tcp?to=x",
            "sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*:&it+has=1,weird!*pas$wo~d_too.(doesn't-it)@example.com",
            "sips:[2001:db8::1]:5061;lr",
            "tel:+1-201-555-0123",
        ];
        for text in candidates {
            let Ok(uri) = Uri::parse_str(text) else {
                continue;
            };
            let written = format!("<{uri}>;tag=t");
            let read = crate::msg::NameAddrRef::parse(written.as_bytes())
                .unwrap_or_else(|e| panic!("{written:?} does not read back: {e}"));
            assert_eq!(read.uri_bytes(), text.as_bytes(), "{written:?}");
            assert_eq!(read.params().count(), 1, "{written:?}");
            assert_eq!(read.tag().as_deref(), Some(&b"t"[..]), "{written:?}");
        }
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
                let _ = Uri::parse_str(&s);
            }
        }
    }

    // The vectors below are the ones RFC 3261 §19.1.4 gives, with the domains
    // moved to the names RFC 2606 reserves: the RFC's own examples read as
    // harvestable addresses to the tree check, and the comparison rules do not
    // care which name is written.
    fn owned(s: &str) -> Uri {
        Uri::parse_str(s).expect("a URI")
    }

    #[test]
    fn an_owned_uri_keeps_the_text_and_hands_back_the_parts() {
        // the userinfo boundary case from the module doc, kept whole
        let u = owned("sip:user;par=u%40example.net@example.com:5060;transport=tcp?to=x");
        assert_eq!(
            u.as_str(),
            "sip:user;par=u%40example.net@example.com:5060;transport=tcp?to=x"
        );
        assert_eq!(u.as_uri_ref(), UriRef::parse_str(u.as_str()).expect("same"));

        let sip = u.sip().expect("a SIP URI");
        assert_eq!(sip.user, Some("user;par=u%40example.net"));
        assert_eq!(sip.host, HostRef::Name("example.com"));
        assert_eq!(sip.port, Some(5060));
        assert_eq!(u.param("transport"), Some("tcp"));
        assert_eq!(sip.headers().collect::<Vec<_>>(), vec![("to", "x")]);
        assert!(!u.is_secure());
    }

    #[test]
    fn the_spelling_survives_the_round_trip() {
        for s in [
            "SIP:Alice@example.com;Transport=TCP",
            "sips:bob@example.net:5061",
            "sip:[2001:db8::1]:5060;lr",
            "tel:+1-201-555-0123",
            "sip:%61lice@example.com",
            "urn:service:sos",
        ] {
            let u = owned(s);
            assert_eq!(u.as_str(), s);
            assert_eq!(u.to_string(), s);
            assert_eq!(u.scheme(), UriRef::parse_str(s).expect("same").scheme());
        }
    }

    #[test]
    fn an_owned_uri_is_cheap_to_clone_and_share() {
        let u = owned("sip:proxy.example.com;lr");
        let clone = u.clone();
        assert!(clone.is_loose_route());
        assert_eq!(clone.as_str(), u.as_str());
        assert!(Arc::ptr_eq(&u.text, &clone.text), "the text is shared");
    }

    #[test]
    fn to_owned_writes_the_uri_out_from_its_parts() {
        let borrowed = UriRef::parse_str("SIP:bob@[0:0:0:0:0:0:0:1]:5060;lr").expect("a URI");
        let kept = borrowed.to_owned();
        // canonical rather than byte for byte, which is why a route set is
        // built with Uri::parse from the bytes as they arrived
        assert_eq!(kept.as_str(), "sip:bob@[::1]:5060;lr");
        assert!(kept.equivalent(&owned("SIP:bob@[0:0:0:0:0:0:0:1]:5060")));
        assert!(kept.is_loose_route());
    }

    #[test]
    fn the_rfc_lists_these_as_equivalent() {
        for (a, b) in [
            (
                "sip:%61lice@example.com;transport=TCP",
                "sip:alice@example.com;Transport=tcp",
            ),
            // the host is the case-insensitive half; the user is not, so the
            // two halves are shown apart rather than in one vector
            ("sip:ExAmPle.CoM;lr", "sip:example.com;LR"),
            ("sip:carol@example.org", "sip:carol@example.org;newparam=5"),
            ("sip:carol@example.org", "sip:carol@example.org;security=on"),
            (
                "sip:example.net;transport=tcp;method=REGISTER?to=sip:bob%40example.net",
                "sip:example.net;method=REGISTER;transport=tcp?to=sip:bob%40example.net",
            ),
            (
                "sip:alice@example.com?subject=project%20x&priority=urgent",
                "sip:alice@example.com?priority=urgent&subject=project%20x",
            ),
        ] {
            let (a, b) = (owned(a), owned(b));
            assert!(a.equivalent(&b), "{a} vs {b}");
            assert!(b.equivalent(&a), "not symmetric: {b} vs {a}");
        }
    }

    #[test]
    fn the_rfc_lists_these_as_different() {
        for (a, b, why) in [
            (
                "SIP:ALICE@example.com;Transport=udp",
                "sip:alice@example.com;Transport=UDP",
                "different usernames",
            ),
            (
                "sip:bob@example.net",
                "sip:bob@example.net:5060",
                "can resolve to different ports",
            ),
            (
                "sip:bob@example.net",
                "sip:bob@example.net;transport=udp",
                "can resolve to different transports",
            ),
            (
                "sip:bob@example.net",
                "sip:bob@example.net:6000;transport=tcp",
                "different port and transport",
            ),
            (
                "sip:carol@example.org",
                "sip:carol@example.org?Subject=next%20meeting",
                "different header component",
            ),
            (
                "sip:bob@phone21.example.org",
                "sip:bob@192.0.2.4",
                "a lookup result is not the name",
            ),
            (
                "sip:bob@example.net",
                "sips:bob@example.net",
                "a SIP and a SIPS URI are never equivalent",
            ),
        ] {
            let (a, b) = (owned(a), owned(b));
            assert!(!a.equivalent(&b), "{why}: {a} vs {b}");
            assert!(!b.equivalent(&a), "{why}, reversed: {b} vs {a}");
        }
    }

    #[test]
    fn equivalence_is_not_transitive_which_is_why_it_is_not_partial_eq() {
        let plain = owned("sip:carol@example.org");
        let on = owned("sip:carol@example.org;security=on");
        let off = owned("sip:carol@example.org;security=off");
        assert!(plain.equivalent(&on));
        assert!(plain.equivalent(&off));
        assert!(!on.equivalent(&off));
    }

    #[test]
    fn an_escape_for_a_reserved_character_is_not_the_character() {
        // decoding %3B would turn a piece of the user name into a separator
        assert!(!owned("sip:a%3Bb@example.com").equivalent(&owned("sip:a;b@example.com")));
        // and case in an escape is not case in the value
        assert!(owned("sip:a%2Fb@example.com").equivalent(&owned("sip:a%2fb@example.com")));
    }

    #[test]
    fn a_user_or_a_password_present_in_only_one_uri_never_matches() {
        // §19.1.4: "A URI omitting the user component will not match a URI
        // that includes one. A URI omitting the password component will not
        // match a URI that includes one." And the password is userinfo, so its
        // case counts.
        for (a, b, why) in [
            (
                "sip:example.com",
                "sip:alice@example.com",
                "user in one only",
            ),
            (
                "sip:alice@example.com",
                "sip:alice:secret@example.com",
                "password in one only",
            ),
            (
                "sip:alice:secret@example.com",
                "sip:alice:SECRET@example.com",
                "password case",
            ),
        ] {
            let (a, b) = (owned(a), owned(b));
            assert!(!a.equivalent(&b), "{why}: {a} vs {b}");
            assert!(!b.equivalent(&a), "{why}, reversed: {b} vs {a}");
        }
        // an escape of an unreserved character is that character there too
        assert!(
            owned("sip:alice:%73ecret@example.com")
                .equivalent(&owned("sip:alice:secret@example.com"))
        );
    }

    #[test]
    fn a_user_ttl_method_or_maddr_parameter_in_only_one_uri_never_matches() {
        // §19.1.4: "A user, ttl, or method uri-parameter appearing in only one
        // URI never matches, even if it contains the default value", and "A URI
        // that includes an maddr parameter will not match a URI that contains
        // no maddr parameter". The values are the defaults of Table 1 where
        // there is one, which is the case the rule is written for.
        let plain = owned("sip:alice@example.com");
        let matched: Vec<String> = [
            "sip:alice@example.com;user=ip",
            "sip:alice@example.com;ttl=1",
            "sip:alice@example.com;method=INVITE",
            "sip:alice@example.com;maddr=192.0.2.1",
        ]
        .into_iter()
        .map(owned)
        .filter(|with| plain.equivalent(with) || with.equivalent(&plain))
        .map(|with| with.to_string())
        .collect();
        assert!(matched.is_empty(), "matched a URI without it: {matched:?}");
    }

    #[test]
    fn a_header_named_twice_is_compared_occurrence_by_occurrence() {
        const TWO_HOPS: &str =
            "sip:alice@example.com?Route=%3Csip:p1.example.com%3E&Route=%3Csip:p2.example.com%3E";
        // a URI is equivalent to itself, whatever it carries
        assert!(owned(TWO_HOPS).equivalent(&owned(TWO_HOPS)), "{TWO_HOPS}");

        for (a, b, why) in [
            (
                "sip:alice@example.com?Route=%3Csip:p1.example.com%3E",
                "sip:alice@example.com?Route=%3Csip:p1.example.com%3E&Route=%3Csip:p1.example.com%3E",
                "one hop is not the same hop twice",
            ),
            (
                TWO_HOPS,
                "sip:alice@example.com?Route=%3Csip:p2.example.com%3E&Route=%3Csip:p1.example.com%3E",
                // §7.3.1: the relative order of fields with one name is data
                "the same hops the other way round",
            ),
        ] {
            let (a, b) = (owned(a), owned(b));
            assert!(!a.equivalent(&b), "{why}: {a} vs {b}");
            assert!(!b.equivalent(&a), "{why}, reversed: {b} vs {a}");
        }

        // while fields of different names may still come in any order
        let a = owned(
            "sip:alice@example.com?Route=%3Csip:p1.example.com%3E&subject=x&Route=%3Csip:p2.example.com%3E",
        );
        let b = owned(
            "sip:alice@example.com?subject=x&Route=%3Csip:p1.example.com%3E&Route=%3Csip:p2.example.com%3E",
        );
        assert!(a.equivalent(&b), "{a} vs {b}");
        assert!(b.equivalent(&a), "not symmetric: {b} vs {a}");
    }

    #[test]
    fn a_uri_header_value_keeps_its_case() {
        // §19.1.4 hands URI headers to "the matching rules ... defined for each
        // header field in Section 20", and several of those are not blind to
        // case: a Call-ID is "case-sensitive" (§20.8), and a URI in a To has a
        // userinfo §19.1.4 itself compares with case
        for (a, b) in [
            (
                "sip:alice@example.com?to=sip:Bob%40example.com",
                "sip:alice@example.com?to=sip:bob%40example.com",
            ),
            (
                "sip:alice@example.com?Call-ID=a84b4c76e66710",
                "sip:alice@example.com?Call-ID=A84B4C76E66710",
            ),
        ] {
            let (a, b) = (owned(a), owned(b));
            assert!(!a.equivalent(&b), "{a} vs {b}");
            assert!(!b.equivalent(&a), "reversed: {b} vs {a}");
        }
        // the name is still a header field name, which never has case (§7.3.1),
        // and the digits of an escape are still not the value's case
        for (a, b) in [
            (
                "sip:alice@example.com?Subject=lunch",
                "sip:alice@example.com?subject=lunch",
            ),
            (
                "sip:alice@example.com?subject=project%2fx",
                "sip:alice@example.com?subject=project%2Fx",
            ),
        ] {
            let (a, b) = (owned(a), owned(b));
            assert!(a.equivalent(&b), "{a} vs {b}");
            assert!(b.equivalent(&a), "not symmetric: {b} vs {a}");
        }
    }

    #[test]
    fn a_percent_that_starts_no_escape_is_not_half_of_the_next_one() {
        // "%%33B" is a lone '%', then %33 (the digit 3), then B. Decoding the
        // %33 must not glue the lone '%' to "3B" and produce the escape of a
        // semicolon, which is a different user name
        let stray = owned("sip:a%%33B@example.com");
        let semicolon = owned("sip:a%3B@example.com");
        assert!(!stray.equivalent(&semicolon), "{stray} vs {semicolon}");
        assert!(!semicolon.equivalent(&stray), "{semicolon} vs {stray}");
        // the lone '%' is the octet it is, which is what %25 writes
        assert!(stray.equivalent(&owned("sip:a%253B@example.com")));
    }

    #[test]
    fn an_escaped_parameter_or_header_name_is_the_name_it_spells() {
        // §19.1.4: "Characters other than those in the reserved set ... are
        // equivalent to their "%" HEX HEX encoding", and a name is made of
        // them. %6D is 'm', so this URI carries an maddr the other one does
        // not, which is a URI that routes somewhere else.
        let plain = owned("sip:alice@example.com");
        let routed = owned("sip:alice@example.com;%6Daddr=198.51.100.66");
        assert!(!plain.equivalent(&routed), "{plain} vs {routed}");
        assert!(!routed.equivalent(&plain), "{routed} vs {plain}");

        // and the same name spelled two ways is one parameter, compared once
        for (a, b) in [
            (
                "sip:alice@example.com;%74ransport=tcp",
                "sip:alice@example.com;transport=tcp",
            ),
            (
                "sip:alice@example.com?%73ubject=lunch",
                "sip:alice@example.com?subject=lunch",
            ),
        ] {
            let (a, b) = (owned(a), owned(b));
            assert!(a.equivalent(&b), "{a} vs {b}");
            assert!(b.equivalent(&a), "not symmetric: {b} vs {a}");
        }
        assert!(
            !owned("sip:alice@example.com;%74ransport=tcp")
                .equivalent(&owned("sip:alice@example.com;transport=udp"))
        );
    }

    #[test]
    fn an_escape_in_the_host_is_not_the_character_it_stands_for() {
        // §19.1.2: "Current implementations MUST NOT attempt to improve
        // robustness by treating received escaped characters in the host
        // component as literally equivalent to their unescaped counterpart."
        // The host grammar has no '%', so the URI does not get as far as a
        // comparison.
        assert_eq!(
            Uri::parse_str("sip:alice@ex%61mple.com").map(|u| u.to_string()),
            Err(UriError::BadHost)
        );
    }

    #[test]
    fn rfc_5954_compares_address_literals_by_value() {
        // RFC 5954 §4.2 rewrites the host rule of §19.1.4: textual forms that
        // "yield the same binary IP address" match, and these are its vectors
        for (a, b) in [
            ("sip:bob@[::ffff:192.0.2.128]", "sip:bob@[::ffff:c000:280]"),
            ("sip:bob@[2001:db8::9:1]", "sip:bob@[2001:db8::9:01]"),
            (
                "sip:bob@[0:0:0:0:0:FFFF:129.144.52.38]",
                "sip:bob@[::FFFF:129.144.52.38]",
            ),
        ] {
            let (a, b) = (owned(a), owned(b));
            assert!(a.equivalent(&b), "{a} vs {b}");
            assert!(b.equivalent(&a), "not symmetric: {b} vs {a}");
        }
    }

    #[test]
    fn a_request_uri_drops_the_method_and_the_headers() {
        // §19.1.5: "The method parameter MUST NOT be placed in the Request-URI"
        let u =
            owned("sip:bob@example.com;method=REGISTER;transport=tcp?to=sip:carol%40example.org");
        assert_eq!(
            u.as_request_uri().as_str(),
            "sip:bob@example.com;transport=tcp"
        );
        // and carries every other parameter over, known or not
        let u = owned("sip:bob@example.com:5060;maddr=192.0.2.1;ttl=1;unknown=7");
        assert_eq!(u.as_request_uri().as_str(), u.as_str());
    }

    #[test]
    fn a_scheme_we_do_not_know_is_compared_only_against_itself() {
        let tel = owned("tel:+1-201-555-0123");
        assert_eq!(tel.scheme(), UriScheme::Tel);
        assert!(tel.sip().is_none());
        assert!(tel.equivalent(&owned("TEL:+1-201-555-0123")), "scheme case");
        assert!(!tel.equivalent(&owned("tel:+1-201-555-0124")));
        assert!(!tel.equivalent(&owned("sip:+1-201-555-0123@example.com;user=phone")));
        assert_eq!(tel.as_request_uri().as_str(), tel.as_str());
    }

    #[test]
    fn what_an_owned_uri_refuses() {
        assert_eq!(Uri::parse(&[0xff]).unwrap_err(), UriError::NotUtf8);
        assert_eq!(Uri::parse_str("nocolon").unwrap_err(), UriError::BadScheme);
        assert_eq!(Uri::parse_str("sip:").unwrap_err(), UriError::NoHost);
    }
}
