// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Header field names.
//!
//! Names are case-insensitive (RFC 3261 §7.3.1) and some have a one-letter
//! compact form (§7.3.3) that means exactly the same field. Both facts live
//! here so that no accessor has to remember them.

use core::fmt;
use core::hash::{Hash, Hasher};

use super::method::is_token_byte;

/// A header field name. Known fields are recognised whatever their case and
/// whatever form they were written in; anything else is an extension.
///
/// Two names are equal when they denote the same field, so `Via`, `via` and
/// `v` are one value, and `Extension("X-Foo")` equals `Extension("x-foo")`.
#[derive(Clone, Copy, Debug, Eq)]
pub enum HeaderName<'a> {
    /// RFC 3261 §20.1.
    Accept,
    /// RFC 3261 §20.5.
    Allow,
    /// RFC 6665 §8.2, compact `u`.
    AllowEvents,
    /// RFC 3261 §20.7.
    Authorization,
    /// RFC 3261 §20.8, compact `i`.
    CallId,
    /// RFC 3261 §20.10, compact `m`.
    Contact,
    /// RFC 3261 §20.12, compact `e`.
    ContentEncoding,
    /// RFC 3261 §20.14, compact `l`.
    ContentLength,
    /// RFC 3261 §20.15, compact `c`.
    ContentType,
    /// RFC 3261 §20.16.
    CSeq,
    /// RFC 3261 §20.17.
    Date,
    /// RFC 6665 §8.2, compact `o`.
    Event,
    /// RFC 3261 §20.19.
    Expires,
    /// RFC 3261 §20.20, compact `f`.
    From,
    /// RFC 3261 §20.22.
    MaxForwards,
    /// RFC 3261 §20.23.
    MinExpires,
    /// RFC 4028 §3.
    MinSe,
    /// RFC 3261 §20.27.
    ProxyAuthenticate,
    /// RFC 3261 §20.28.
    ProxyAuthorization,
    /// RFC 3261 §20.29.
    ProxyRequire,
    /// RFC 3262 §7.2.
    RAck,
    /// RFC 3261 §20.30.
    RecordRoute,
    /// RFC 3515 §2.1, compact `r`.
    ReferTo,
    /// RFC 3892 §3, compact `b`.
    ReferredBy,
    /// RFC 3891 §6.1.
    Replaces,
    /// RFC 3261 §20.32.
    Require,
    /// RFC 3261 §20.33.
    RetryAfter,
    /// RFC 3261 §20.34.
    Route,
    /// RFC 3262 §7.1.
    RSeq,
    /// RFC 4028 §4, compact `x`.
    SessionExpires,
    /// RFC 3261 §20.36, compact `s`.
    Subject,
    /// RFC 6665 §8.2.
    SubscriptionState,
    /// RFC 3261 §20.37, compact `k`.
    Supported,
    /// RFC 3261 §20.39, compact `t`.
    To,
    /// RFC 3261 §20.40.
    Unsupported,
    /// RFC 3261 §20.41.
    UserAgent,
    /// RFC 3261 §20.42, compact `v`.
    Via,
    /// RFC 3261 §20.43.
    Warning,
    /// RFC 3261 §20.44.
    WwwAuthenticate,
    /// Anything else, kept as it was written.
    Extension(&'a str),
}

impl HeaderName<'static> {
    /// Every name this crate knows, in the order it recognises them.
    pub const KNOWN: &'static [HeaderName<'static>] = &[
        Self::Accept,
        Self::Allow,
        Self::AllowEvents,
        Self::Authorization,
        Self::CallId,
        Self::Contact,
        Self::ContentEncoding,
        Self::ContentLength,
        Self::ContentType,
        Self::CSeq,
        Self::Date,
        Self::Event,
        Self::Expires,
        Self::From,
        Self::MaxForwards,
        Self::MinExpires,
        Self::MinSe,
        Self::ProxyAuthenticate,
        Self::ProxyAuthorization,
        Self::ProxyRequire,
        Self::RAck,
        Self::RecordRoute,
        Self::ReferTo,
        Self::ReferredBy,
        Self::Replaces,
        Self::Require,
        Self::RetryAfter,
        Self::Route,
        Self::RSeq,
        Self::SessionExpires,
        Self::Subject,
        Self::SubscriptionState,
        Self::Supported,
        Self::To,
        Self::Unsupported,
        Self::UserAgent,
        Self::Via,
        Self::Warning,
        Self::WwwAuthenticate,
    ];
}

impl<'a> HeaderName<'a> {
    /// Recognise a name, in any case and in either form. `None` if the bytes
    /// are not a token, which the parser will already have refused.
    #[must_use]
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        if bytes.is_empty() || !bytes.iter().copied().all(is_token_byte) {
            return None;
        }
        for &known in HeaderName::KNOWN {
            if bytes.eq_ignore_ascii_case(known.canonical().as_bytes()) {
                return Some(known);
            }
            if let (Some(c), [only]) = (known.compact(), bytes)
                && only.eq_ignore_ascii_case(&c)
            {
                return Some(known);
            }
        }
        // a token is ASCII, so this cannot fail
        Some(Self::Extension(core::str::from_utf8(bytes).ok()?))
    }

    /// The long form, spelled as the RFC spells it.
    #[must_use]
    pub const fn canonical(&self) -> &'a str {
        match *self {
            Self::Accept => "Accept",
            Self::Allow => "Allow",
            Self::AllowEvents => "Allow-Events",
            Self::Authorization => "Authorization",
            Self::CallId => "Call-ID",
            Self::Contact => "Contact",
            Self::ContentEncoding => "Content-Encoding",
            Self::ContentLength => "Content-Length",
            Self::ContentType => "Content-Type",
            Self::CSeq => "CSeq",
            Self::Date => "Date",
            Self::Event => "Event",
            Self::Expires => "Expires",
            Self::From => "From",
            Self::MaxForwards => "Max-Forwards",
            Self::MinExpires => "Min-Expires",
            Self::MinSe => "Min-SE",
            Self::ProxyAuthenticate => "Proxy-Authenticate",
            Self::ProxyAuthorization => "Proxy-Authorization",
            Self::ProxyRequire => "Proxy-Require",
            Self::RAck => "RAck",
            Self::RecordRoute => "Record-Route",
            Self::ReferTo => "Refer-To",
            Self::ReferredBy => "Referred-By",
            Self::Replaces => "Replaces",
            Self::Require => "Require",
            Self::RetryAfter => "Retry-After",
            Self::Route => "Route",
            Self::RSeq => "RSeq",
            Self::SessionExpires => "Session-Expires",
            Self::Subject => "Subject",
            Self::SubscriptionState => "Subscription-State",
            Self::Supported => "Supported",
            Self::To => "To",
            Self::Unsupported => "Unsupported",
            Self::UserAgent => "User-Agent",
            Self::Via => "Via",
            Self::Warning => "Warning",
            Self::WwwAuthenticate => "WWW-Authenticate",
            Self::Extension(s) => s,
        }
    }

    /// The one-letter form, where the field has one.
    #[must_use]
    pub const fn compact(&self) -> Option<u8> {
        Some(match *self {
            Self::AllowEvents => b'u',
            Self::CallId => b'i',
            Self::Contact => b'm',
            Self::ContentEncoding => b'e',
            Self::ContentLength => b'l',
            Self::ContentType => b'c',
            Self::Event => b'o',
            Self::From => b'f',
            Self::ReferTo => b'r',
            Self::ReferredBy => b'b',
            Self::SessionExpires => b'x',
            Self::Subject => b's',
            Self::Supported => b'k',
            Self::To => b't',
            Self::Via => b'v',
            _ => return None,
        })
    }

    /// Whether this is a field the crate does not know.
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        matches!(*self, Self::Extension(_))
    }
}

impl PartialEq for HeaderName<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (*self, *other) {
            (Self::Extension(a), Self::Extension(b)) => a.eq_ignore_ascii_case(b),
            (Self::Extension(_), _) | (_, Self::Extension(_)) => false,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl Hash for HeaderName<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.canonical().bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
        state.write_u8(0);
    }
}

impl fmt::Display for HeaderName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::HeaderName;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn name(s: &str) -> HeaderName<'_> {
        HeaderName::from_bytes(s.as_bytes()).expect("a token")
    }

    fn hash_of(h: HeaderName<'_>) -> u64 {
        let mut s = DefaultHasher::new();
        h.hash(&mut s);
        s.finish()
    }

    #[test]
    fn every_known_name_round_trips_through_its_long_form() {
        for &known in HeaderName::KNOWN {
            assert_eq!(name(known.canonical()), known, "{known}");
        }
    }

    #[test]
    fn every_compact_form_resolves_to_its_field() {
        for &known in HeaderName::KNOWN {
            let Some(c) = known.compact() else { continue };
            let lower = [c];
            let upper = [c.to_ascii_uppercase()];
            assert_eq!(HeaderName::from_bytes(&lower), Some(known), "{known}");
            assert_eq!(HeaderName::from_bytes(&upper), Some(known), "{known}");
        }
    }

    #[test]
    fn the_fifteen_compact_forms_are_the_ones_the_rfcs_define() {
        let mut found: Vec<u8> = HeaderName::KNOWN
            .iter()
            .filter_map(HeaderName::compact)
            .collect();
        found.sort_unstable();
        // RFC 3261 §7.3.3 defines ten; u and o are RFC 6665, r is RFC 3515,
        // b is RFC 3892, x is RFC 4028
        assert_eq!(found, b"bcefiklmorstuvx".to_vec());
    }

    #[test]
    fn no_two_fields_claim_the_same_compact_form() {
        let mut seen = Vec::new();
        for &known in HeaderName::KNOWN {
            if let Some(c) = known.compact() {
                assert!(!seen.contains(&c), "{} reuses {}", known, c as char);
                seen.push(c);
            }
        }
    }

    #[test]
    fn names_are_case_insensitive() {
        assert_eq!(name("via"), HeaderName::Via);
        assert_eq!(name("ViA"), HeaderName::Via);
        assert_eq!(name("CALL-ID"), HeaderName::CallId);
        assert_eq!(name("www-authenticate"), HeaderName::WwwAuthenticate);
    }

    #[test]
    fn compact_and_long_forms_are_the_same_value() {
        assert_eq!(name("v"), name("Via"));
        assert_eq!(name("l"), name("content-length"));
        assert_eq!(name("i"), name("Call-ID"));
        assert_eq!(name("x"), name("Session-Expires"));
    }

    #[test]
    fn unknown_names_are_extensions_compared_case_insensitively() {
        assert_eq!(name("X-Foo"), name("x-foo"));
        assert_ne!(name("X-Foo"), name("X-Bar"));
        assert!(name("X-Foo").is_extension());
        assert!(!name("Via").is_extension());
    }

    #[test]
    fn an_extension_never_equals_a_known_field() {
        // "vi" is not the compact form of anything
        assert_ne!(name("vi"), HeaderName::Via);
        assert!(name("vi").is_extension());
    }

    #[test]
    fn hashing_agrees_with_equality() {
        assert_eq!(hash_of(name("v")), hash_of(name("Via")));
        assert_eq!(hash_of(name("X-Foo")), hash_of(name("x-foo")));
    }

    #[test]
    fn non_token_bytes_are_not_a_name() {
        assert_eq!(HeaderName::from_bytes(b"Bad Name"), None);
        assert_eq!(HeaderName::from_bytes(b""), None);
        assert_eq!(HeaderName::from_bytes(b"a:b"), None);
    }

    #[test]
    fn the_extension_keeps_the_spelling_it_arrived_with() {
        assert_eq!(name("X-Odd-Thing").canonical(), "X-Odd-Thing");
    }
}
