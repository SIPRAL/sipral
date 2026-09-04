// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The fields that are a list of tokens, and `Content-Type`, which is one
//! media type.
//!
//! RFC 3261 §25.1:
//!
//! ```text
//! Require        =  "Require" HCOLON option-tag *(COMMA option-tag)
//! Supported      =  ( "Supported" / "k" ) HCOLON [option-tag *(COMMA option-tag)]
//! Allow          =  "Allow" HCOLON [Method *(COMMA Method)]
//! option-tag     =  token
//! Content-Type   =  ( "Content-Type" / "c" ) HCOLON media-type
//! media-type     =  m-type SLASH m-subtype *(SEMI m-parameter)
//! ```
//!
//! An option tag is any token, registry or no registry: answering 420 to one
//! nobody knows is the user agent's decision, taken after the field has been
//! read (§19.2). Comparison is case-insensitive, like every SIP token.
//!
//! A method is not. The six RFC 3261 verbs are written into the grammar as
//! fixed byte sequences — `INVITEm = %x49.4E.56.49.54.45 ; INVITE in caps` —
//! so `Allow: invite` parses as an extension method named `invite`, not as
//! INVITE. Case-folding before the comparison claims support that was never
//! offered, which is why [`super::Method`] compares exactly.
//!
//! One deliberate leniency. `Require`, `Proxy-Require`, `Unsupported` and
//! `Content-Encoding` are written without the enclosing brackets `Supported`
//! and `Allow` have, so one entry is grammatically mandatory and an empty
//! value is a syntax error. Empty items are skipped here rather than refused:
//! an empty `Require` asks for nothing, which is what an absent `Require`
//! means too, and rejecting the message over it would cost a call to buy
//! nothing.

use core::fmt;

use super::error::HeaderError;
use super::lex::{Params, is_lws, trim};
use super::message::FieldValues;

/// The tokens of one list field, in wire order across lines and commas.
#[derive(Clone, Debug)]
pub struct TokenIter<'a> {
    values: FieldValues<'a>,
}

impl<'a> TokenIter<'a> {
    pub(super) const fn new(values: FieldValues<'a>) -> Self {
        Self { values }
    }

    /// Whether a token is in the list, matched without case.
    #[must_use]
    pub fn has(&self, token: &str) -> bool {
        self.clone()
            .any(|t| t.eq_ignore_ascii_case(token.as_bytes()))
    }
}

impl<'a> Iterator for TokenIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let value = trim(self.values.next()?);
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
}

/// A `Content-Type` value: `type/subtype` and its parameters.
#[derive(Clone, Copy, Debug)]
pub struct MediaTypeRef<'a> {
    kind: &'a [u8],
    subtype: &'a [u8],
    raw: &'a [u8],
}

impl<'a> MediaTypeRef<'a> {
    /// Read one media type.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when there is no `/`, when either half is
    /// empty, or when either half holds whitespace. `SLASH` is `SWS "/" SWS`,
    /// so `application / sdp` is the same value written wider.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let (head, _) = Params::split(value);
        let slash = head
            .iter()
            .position(|&b| b == b'/')
            .ok_or(HeaderError::Malformed("media type has no subtype"))?;
        let kind = trim(head.get(..slash).unwrap_or_default());
        let subtype = trim(head.get(slash + 1..).unwrap_or_default());
        if kind.is_empty() || subtype.is_empty() {
            return Err(HeaderError::Malformed("media type is type/subtype"));
        }
        if kind.iter().copied().any(is_lws) || subtype.iter().copied().any(is_lws) {
            return Err(HeaderError::Malformed("whitespace inside a media type"));
        }
        Ok(Self {
            kind,
            subtype,
            raw: value,
        })
    }

    /// The type, as written.
    #[must_use]
    pub const fn kind(&self) -> &'a [u8] {
        self.kind
    }

    /// The subtype, as written.
    #[must_use]
    pub const fn subtype(&self) -> &'a [u8] {
        self.subtype
    }

    /// Whether this is the given type and subtype, matched without case.
    #[must_use]
    pub fn is(&self, kind: &str, subtype: &str) -> bool {
        self.kind.eq_ignore_ascii_case(kind.as_bytes())
            && self.subtype.eq_ignore_ascii_case(subtype.as_bytes())
    }

    /// The parameters, in the order written.
    #[must_use]
    pub fn params(&self) -> Params<'a> {
        Params::split(self.raw).1
    }
}

impl fmt::Display for MediaTypeRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}",
            String::from_utf8_lossy(self.kind),
            String::from_utf8_lossy(self.subtype)
        )?;
        for (name, value) in self.params() {
            f.write_str(";")?;
            f.write_str(&String::from_utf8_lossy(name))?;
            if let Some(v) = value {
                write!(f, "={}", String::from_utf8_lossy(v))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MediaTypeRef;
    use crate::msg::HeaderError;

    fn media(v: &[u8]) -> MediaTypeRef<'_> {
        MediaTypeRef::parse(v).expect("a media type")
    }

    #[test]
    fn a_plain_media_type() {
        let m = media(b"application/sdp");
        assert_eq!(m.kind(), b"application");
        assert_eq!(m.subtype(), b"sdp");
        assert!(m.is("APPLICATION", "SDP"));
        assert!(!m.is("application", "xml"));
        assert_eq!(m.params().count(), 0);
    }

    #[test]
    fn whitespace_may_sit_around_the_slash() {
        // SLASH is SWS "/" SWS
        let m = media(b"application / sdp");
        assert!(m.is("application", "sdp"));
        let folded = media(b"multipart\r\n /mixed;boundary=x");
        assert!(folded.is("multipart", "mixed"));
        assert_eq!(folded.params().get("boundary").as_deref(), Some(&b"x"[..]));
    }

    #[test]
    fn an_unknown_subtype_is_syntax_not_an_error() {
        // RFC 4475 3.3.6 invut and 3.3.15 sdp01 are both well formed
        assert!(media(b"application/unknownformat").is("application", "unknownformat"));
        assert!(media(b"text/nobodyKnowsThis").is("text", "nobodyknowsthis"));
    }

    #[test]
    fn a_quoted_parameter_keeps_its_separators() {
        let m = media(br#"application/foo;desc="a;b,c""#);
        assert_eq!(m.params().count(), 1);
        assert_eq!(m.params().get("desc").as_deref(), Some(&b"a;b,c"[..]));
    }

    #[test]
    fn a_malformed_media_type_is_refused() {
        for v in [
            &b""[..],
            &b"application"[..],
            &b"/sdp"[..],
            &b"application/"[..],
            &b"appli cation/sdp"[..],
        ] {
            assert!(matches!(
                MediaTypeRef::parse(v),
                Err(HeaderError::Malformed(_))
            ));
        }
    }

    #[test]
    fn display_round_trips_the_value() {
        assert_eq!(media(b"application/sdp").to_string(), "application/sdp");
        assert_eq!(
            media(b"multipart/mixed;boundary=unique").to_string(),
            "multipart/mixed;boundary=unique"
        );
    }
}
