// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Multipart bodies: more than one body in one SIP message (RFC 5621).
//!
//! The syntax is MIME's, from RFC 2046 §5.1.1:
//!
//! ```text
//! boundary := 0*69<bchars> bcharsnospace
//! bchars := bcharsnospace / " "
//! bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" /
//!                  "+" / "_" / "," / "-" / "." /
//!                  "/" / ":" / "=" / "?"
//! body-part := MIME-part-headers [CRLF *OCTET]
//! close-delimiter := delimiter "--"
//! dash-boundary := "--" boundary
//! delimiter := CRLF dash-boundary
//! encapsulation := delimiter transport-padding
//!                  CRLF body-part
//! multipart-body := [preamble CRLF]
//!                   dash-boundary transport-padding CRLF
//!                   body-part *encapsulation
//!                   close-delimiter transport-padding
//!                   [CRLF epilogue]
//! transport-padding := *LWSP-char
//! ```
//!
//! The CRLF in front of a delimiter belongs to the delimiter, not to the part
//! before it, so an SDP body that ends in CRLF comes back out ending in CRLF.
//! A line that starts with the boundary but carries anything other than
//! padding after it is not a delimiter, and is read as content. That is the
//! grammar's reading; §5.1.1 forbids such a line in a part at all, and its
//! note to implementors would take the boundary at the start of any line as
//! a delimiter whatever follows it. No conforming sender writes one. The preamble
//! and the epilogue are skipped, as §5.1.1 says they are. A body without the
//! close delimiter is refused rather than guessed at: a part cut short by a
//! lost segment is not a part.
//!
//! **What a part is.** Its own `Content-Type` (absent, it is
//! `text/plain; charset=us-ascii`, §5.1, except in a `multipart/digest`,
//! where it is `message/rfc822`, §5.1.5), its own `Content-Disposition`
//! (RFC 3261 §20.11) and its own `Content-ID` (RFC 2045 §7). A part whose
//! type is itself `multipart` is read too, down to [`MultipartLimits`]'
//! depth; every other header field of a part is kept as written and can be
//! asked for by name.
//!
//! **What a receiver has to refuse.** The `handling` parameter of a part's
//! disposition says whether the part may be ignored (RFC 3261 §20.11,
//! RFC 5621 §8.2). A part that is required and not understood makes the whole
//! request one the user agent cannot process, and RFC 3261 §8.2.3 makes that a
//! 415 (Unsupported Media Type). [`Multipart::check`] walks the tree and returns
//! that part as an [`Unsupported`], whose status is the 415. The parts of a
//! `multipart/alternative` are one choice rather than several bodies (RFC 2046
//! §5.1.4): their own handling is not consulted, and the alternative as a
//! whole fails only when none of them is understood.
//!
//! **Writing one.** [`MultipartBuilder`] chooses a boundary that occurs
//! nowhere in any part — not merely nowhere at the start of a line — so no
//! part can end the body early whatever it holds.

use core::fmt;
use std::borrow::Cow;

use super::error::HeaderError;
use super::lex::{Params, is_lws, trim};
use super::method::StatusCode;
use super::tokens::MediaTypeRef;

/// The bounds a multipart body is read within.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultipartLimits {
    /// The most parts read, counting every level of nesting together.
    pub max_parts: usize,
    /// How many multipart levels there may be, the outermost included.
    pub max_depth: usize,
    /// The largest body read at all.
    pub max_bytes: usize,
    /// The most header fields one part may carry.
    pub max_part_headers: usize,
}

impl MultipartLimits {
    /// The defaults: 32 parts, 4 levels, 64 KiB, 16 fields per part.
    ///
    /// The byte bound is the one a whole message is read within
    /// ([`super::Limits::DEFAULT`]), so no body that arrived in a message is
    /// refused for its size alone. A recording session's INVITE carries two
    /// parts at one level (RFC 7866 §9.1); the rest is room.
    pub const DEFAULT: Self = Self {
        max_parts: 32,
        max_depth: 4,
        max_bytes: 65_535,
        max_part_headers: 16,
    };
}

impl Default for MultipartLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a multipart body could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MultipartError {
    /// The media type is not `multipart/*`.
    NotMultipart,
    /// The media type has no `boundary` parameter.
    NoBoundary,
    /// The boundary breaks RFC 2046 §5.1.1: empty, longer than 70
    /// characters, a character outside `bchars`, or a trailing space.
    BadBoundary,
    /// No delimiter line opens the first part.
    NoFirstBoundary,
    /// The body ends without the close delimiter.
    Unterminated,
    /// The first delimiter is the close delimiter, so there is no part.
    NoParts,
    /// A part's header section does not conform.
    BadPartHeader(&'static str),
    /// A part carries one of the fields read here more than once.
    DuplicateHeader(&'static str),
    /// A part carries more header fields than the limit.
    TooManyHeaders {
        /// The bound that was exceeded.
        limit: usize,
    },
    /// More parts than the limit, all levels counted.
    TooManyParts {
        /// The bound that was exceeded.
        limit: usize,
    },
    /// Multipart nested deeper than the limit.
    TooDeep {
        /// The bound that was exceeded.
        limit: usize,
    },
    /// The body is larger than the limit.
    TooLarge {
        /// The bound that was exceeded.
        limit: usize,
    },
    /// A value given to the builder cannot be written as a part header.
    IllegalValue(&'static str),
    /// No boundary could be found that the parts do not contain.
    NoBoundaryAvailable,
}

impl fmt::Display for MultipartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotMultipart => f.write_str("not a multipart media type"),
            Self::NoBoundary => f.write_str("multipart media type without a boundary"),
            Self::BadBoundary => f.write_str("boundary is not one RFC 2046 allows"),
            Self::NoFirstBoundary => f.write_str("no delimiter opens the first part"),
            Self::Unterminated => f.write_str("multipart body has no close delimiter"),
            Self::NoParts => f.write_str("multipart body has no part"),
            Self::BadPartHeader(what) => write!(f, "malformed part header: {what}"),
            Self::DuplicateHeader(name) => write!(f, "{name} appears twice in one part"),
            Self::TooManyHeaders { limit } => write!(f, "more than {limit} fields in one part"),
            Self::TooManyParts { limit } => write!(f, "more than {limit} parts"),
            Self::TooDeep { limit } => write!(f, "multipart nested deeper than {limit}"),
            Self::TooLarge { limit } => write!(f, "multipart body larger than {limit} bytes"),
            Self::IllegalValue(what) => write!(f, "illegal value: {what}"),
            Self::NoBoundaryAvailable => f.write_str("no boundary the parts do not contain"),
        }
    }
}

impl core::error::Error for MultipartError {}

/// Whether a body may be ignored by a receiver that does not understand it
/// (RFC 3261 §20.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Handling {
    /// The body has to be understood, or the request fails. The default.
    Required,
    /// The body may be ignored.
    Optional,
}

/// A `Content-Disposition` value: the disposition type and its parameters.
///
/// RFC 3261 §20.11:
///
/// ```text
/// Content-Disposition   =  "Content-Disposition" HCOLON
///                          disp-type *( SEMI disp-param )
/// disp-type             =  "render" / "session" / "icon" / "alert"
///                          / disp-extension-token
/// handling-param        =  "handling" EQUAL
///                          ( "optional" / "required"
///                          / other-handling )
/// ```
#[derive(Clone, Copy, Debug)]
pub struct DispositionRef<'a> {
    kind: &'a [u8],
    raw: &'a [u8],
}

impl<'a> DispositionRef<'a> {
    /// Read one disposition.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when the type is empty or holds whitespace.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let (kind, _) = Params::split(value);
        if kind.is_empty() {
            return Err(HeaderError::Malformed("disposition has no type"));
        }
        if kind.iter().copied().any(is_lws) {
            return Err(HeaderError::Malformed(
                "whitespace inside a disposition type",
            ));
        }
        Ok(Self { kind, raw: value })
    }

    /// The disposition type, as written.
    #[must_use]
    pub const fn kind(&self) -> &'a [u8] {
        self.kind
    }

    /// Whether this is the given disposition type, matched without case.
    #[must_use]
    pub fn is(&self, kind: &str) -> bool {
        self.kind.eq_ignore_ascii_case(kind.as_bytes())
    }

    /// The parameters, in the order written.
    #[must_use]
    pub fn params(&self) -> Params<'a> {
        Params::split(self.raw).1
    }

    /// The `handling` parameter.
    ///
    /// Absent, it is required (RFC 3261 §20.11). An `other-handling` value is
    /// one this stack does not know the meaning of, and the only reading that
    /// cannot lose a body the sender needed read is required.
    #[must_use]
    pub fn handling(&self) -> Handling {
        match self.params().get("handling") {
            Some(value) if value.eq_ignore_ascii_case(b"optional") => Handling::Optional,
            _ => Handling::Required,
        }
    }
}

/// Which multipart subtype a body is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultipartKind<'a> {
    /// `multipart/mixed`: independent parts, each to be processed
    /// (RFC 2046 §5.1.3).
    Mixed,
    /// `multipart/alternative`: one content in several forms, in increasing
    /// order of preference (RFC 2046 §5.1.4).
    Alternative,
    /// Any other subtype, read as `mixed` (RFC 2046 §5.1.7).
    Other(&'a [u8]),
}

/// One part of a multipart body.
#[derive(Clone, Debug)]
pub struct BodyPart<'a> {
    headers: &'a [u8],
    content_type: Option<MediaTypeRef<'a>>,
    /// The part is one of a `multipart/digest`, so untyped it is a message.
    in_digest: bool,
    disposition: Option<DispositionRef<'a>>,
    content_id: Option<&'a [u8]>,
    body: &'a [u8],
    nested: Option<Multipart<'a>>,
}

impl<'a> BodyPart<'a> {
    /// The part's `Content-Type`, when it has one.
    #[must_use]
    pub const fn content_type(&self) -> Option<MediaTypeRef<'a>> {
        self.content_type
    }

    /// Whether the part is of this type, matched without case.
    ///
    /// A part without `Content-Type` is `text/plain` (RFC 2046 §5.1), or
    /// `message/rfc822` when it is one of a `multipart/digest` (§5.1.5).
    #[must_use]
    pub fn is(&self, kind: &str, subtype: &str) -> bool {
        if let Some(media) = self.content_type {
            return media.is(kind, subtype);
        }
        let (implicit_kind, implicit_subtype) = self.implicit_type();
        kind.eq_ignore_ascii_case(implicit_kind) && subtype.eq_ignore_ascii_case(implicit_subtype)
    }

    /// The type a part without `Content-Type` has.
    const fn implicit_type(&self) -> (&'static str, &'static str) {
        if self.in_digest {
            ("message", "rfc822")
        } else {
            ("text", "plain")
        }
    }

    /// The part's `Content-Disposition`, when it has one.
    #[must_use]
    pub const fn disposition(&self) -> Option<DispositionRef<'a>> {
        self.disposition
    }

    /// Whether the part may be ignored; required unless it says otherwise.
    #[must_use]
    pub fn handling(&self) -> Handling {
        self.disposition
            .map_or(Handling::Required, |disposition| disposition.handling())
    }

    /// The part's `Content-ID` (RFC 2045 §7), without its angle brackets.
    #[must_use]
    pub const fn content_id(&self) -> Option<&'a [u8]> {
        self.content_id
    }

    /// The part's content, exactly as it was carried.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// The part read as a multipart body, when it is one.
    #[must_use]
    pub const fn nested(&self) -> Option<&Multipart<'a>> {
        self.nested.as_ref()
    }

    /// The value of any one of the part's header fields, matched without
    /// case, as written: a folded value keeps its fold.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        let mut rest = self.headers;
        while let Ok(Some((field, after))) = next_field(rest) {
            if field.0.eq_ignore_ascii_case(name.as_bytes()) {
                return Some(trim(field.1));
            }
            rest = after;
        }
        None
    }
}

/// A multipart body, read into its parts.
#[derive(Clone, Debug)]
pub struct Multipart<'a> {
    kind: MultipartKind<'a>,
    boundary: Cow<'a, [u8]>,
    parts: Vec<BodyPart<'a>>,
}

impl<'a> Multipart<'a> {
    /// Read a body whose `Content-Type` is `content_type`, within the
    /// default limits.
    ///
    /// # Errors
    /// See [`MultipartError`].
    pub fn parse(content_type: &MediaTypeRef<'a>, body: &'a [u8]) -> Result<Self, MultipartError> {
        Self::parse_with_limits(content_type, body, MultipartLimits::DEFAULT)
    }

    /// Read a body within the given limits.
    ///
    /// # Errors
    /// See [`MultipartError`].
    pub fn parse_with_limits(
        content_type: &MediaTypeRef<'a>,
        body: &'a [u8],
        limits: MultipartLimits,
    ) -> Result<Self, MultipartError> {
        if body.len() > limits.max_bytes {
            return Err(MultipartError::TooLarge {
                limit: limits.max_bytes,
            });
        }
        let mut reader = Reader {
            limits,
            parts_left: limits.max_parts,
        };
        reader.level(content_type, body, 1)
    }

    /// The subtype.
    #[must_use]
    pub const fn kind(&self) -> MultipartKind<'a> {
        self.kind
    }

    /// The boundary, as the `Content-Type` gave it.
    #[must_use]
    pub fn boundary(&self) -> &[u8] {
        &self.boundary
    }

    /// The parts of this level, in the order written.
    #[must_use]
    pub fn parts(&self) -> &[BodyPart<'a>] {
        &self.parts
    }

    /// The first part of this type at any level, depth first.
    #[must_use]
    pub fn find(&self, kind: &str, subtype: &str) -> Option<&BodyPart<'a>> {
        self.parts.iter().find_map(|part| {
            if part.is(kind, subtype) {
                return Some(part);
            }
            part.nested.as_ref()?.find(kind, subtype)
        })
    }

    /// The part with this `Content-ID` at any level, depth first, compared
    /// exactly: a `cid:` URL is resolved against it once its `cid:` prefix is
    /// dropped and its %-escapes are undone (RFC 2392 §2).
    #[must_use]
    pub fn by_content_id(&self, id: &[u8]) -> Option<&BodyPart<'a>> {
        self.parts.iter().find_map(|part| {
            if part.content_id == Some(id) {
                return Some(part);
            }
            part.nested.as_ref()?.by_content_id(id)
        })
    }

    /// For `multipart/alternative`, the most preferred part this receiver
    /// understands: the last one, since the parts come in increasing order of
    /// preference (RFC 2046 §5.1.4). For any other subtype, the first.
    #[must_use]
    pub fn preferred(&self, understood: impl Fn(&BodyPart<'a>) -> bool) -> Option<&BodyPart<'a>> {
        match self.kind {
            MultipartKind::Alternative => self.parts.iter().rev().find(|part| understood(part)),
            _ => self.parts.iter().find(|part| understood(part)),
        }
    }

    /// Whether every part the sender requires is one this receiver
    /// understands (RFC 5621 §8.2 and §8.3; answered with the 415 of §8.4).
    ///
    /// `understood` is asked about every part that is not itself multipart,
    /// and can judge its type, its disposition or both. A nested multipart
    /// part is checked by the same rule, one level down.
    ///
    /// # Errors
    /// The part that cannot be processed. Answer the request with
    /// [`Unsupported::status`].
    pub fn check(&self, understood: impl Fn(&BodyPart<'a>) -> bool) -> Result<(), Unsupported<'a>> {
        self.check_level(&understood)
    }

    fn check_level<F: Fn(&BodyPart<'a>) -> bool>(
        &self,
        understood: &F,
    ) -> Result<(), Unsupported<'a>> {
        if self.kind == MultipartKind::Alternative {
            // the handling of each alternative is not consulted: the choice
            // as a whole is what the enclosing disposition makes required
            let mut refused = None;
            for part in &self.parts {
                match part_check(part, understood) {
                    Ok(()) => return Ok(()),
                    Err(unsupported) => refused = Some(unsupported),
                }
            }
            return Err(refused.unwrap_or(Unsupported {
                content_type: None,
                implicit: ("text", "plain"),
                disposition: None,
            }));
        }
        for part in &self.parts {
            if let Err(unsupported) = part_check(part, understood)
                && part.handling() == Handling::Required
            {
                return Err(unsupported);
            }
        }
        Ok(())
    }
}

fn part_check<'a, F: Fn(&BodyPart<'a>) -> bool>(
    part: &BodyPart<'a>,
    understood: &F,
) -> Result<(), Unsupported<'a>> {
    if let Some(nested) = &part.nested {
        return nested.check_level(understood);
    }
    if understood(part) {
        Ok(())
    } else {
        Err(Unsupported {
            content_type: part.content_type,
            implicit: part.implicit_type(),
            disposition: part.disposition,
        })
    }
}

/// A required part the receiver does not understand: the request is answered
/// with 415 (RFC 3261 §8.2.3, RFC 5621 §8.4).
#[derive(Clone, Copy, Debug)]
pub struct Unsupported<'a> {
    content_type: Option<MediaTypeRef<'a>>,
    /// The type the part has when `content_type` is absent.
    implicit: (&'static str, &'static str),
    disposition: Option<DispositionRef<'a>>,
}

impl<'a> Unsupported<'a> {
    /// The part's `Content-Type`; `None` for an implicit `text/plain` (or
    /// `message/rfc822` in a `multipart/digest`).
    #[must_use]
    pub const fn content_type(&self) -> Option<MediaTypeRef<'a>> {
        self.content_type
    }

    /// The part's `Content-Disposition`, when it has one.
    #[must_use]
    pub const fn disposition(&self) -> Option<DispositionRef<'a>> {
        self.disposition
    }

    /// The response the request gets: 415 Unsupported Media Type.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    }
}

impl fmt::Display for Unsupported<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.content_type {
            Some(media) => write!(f, "required body part {media} is not understood"),
            None => write!(
                f,
                "required body part {}/{} is not understood",
                self.implicit.0, self.implicit.1
            ),
        }
    }
}

impl core::error::Error for Unsupported<'_> {}

// -- reading ---------------------------------------------------------------

struct Reader {
    limits: MultipartLimits,
    parts_left: usize,
}

impl Reader {
    fn level<'a>(
        &mut self,
        content_type: &MediaTypeRef<'a>,
        body: &'a [u8],
        depth: usize,
    ) -> Result<Multipart<'a>, MultipartError> {
        if depth > self.limits.max_depth {
            return Err(MultipartError::TooDeep {
                limit: self.limits.max_depth,
            });
        }
        if !content_type.kind().eq_ignore_ascii_case(b"multipart") {
            return Err(MultipartError::NotMultipart);
        }
        let subtype = content_type.subtype();
        let kind = if subtype.eq_ignore_ascii_case(b"mixed") {
            MultipartKind::Mixed
        } else if subtype.eq_ignore_ascii_case(b"alternative") {
            MultipartKind::Alternative
        } else {
            MultipartKind::Other(subtype)
        };
        let boundary = content_type
            .params()
            .get("boundary")
            .ok_or(MultipartError::NoBoundary)?;
        if !valid_boundary(&boundary) {
            return Err(MultipartError::BadBoundary);
        }
        let mut dash = Vec::with_capacity(boundary.len() + 4);
        dash.extend_from_slice(b"\r\n--");
        dash.extend_from_slice(&boundary);

        let in_digest = subtype.eq_ignore_ascii_case(b"digest");
        let mut parts = Vec::new();
        let mut start = opening(body, &dash)?;
        loop {
            let (at, end, close) = next_delimiter(body, start, &dash)?;
            if self.parts_left == 0 {
                return Err(MultipartError::TooManyParts {
                    limit: self.limits.max_parts,
                });
            }
            self.parts_left -= 1;
            let raw = body.get(start..at).unwrap_or_default();
            parts.push(self.part(raw, depth, in_digest)?);
            if close {
                break;
            }
            start = end;
        }
        Ok(Multipart {
            kind,
            boundary,
            parts,
        })
    }

    fn part<'a>(
        &mut self,
        raw: &'a [u8],
        depth: usize,
        in_digest: bool,
    ) -> Result<BodyPart<'a>, MultipartError> {
        // body-part := MIME-part-headers [CRLF *OCTET]; the CRLF that ends
        // the last field is part of that field, so a part with no fields
        // starts with the separating CRLF, and a part with no content has no
        // separating CRLF at all
        // and every piece stays a span of the caller's bytes, empty or not
        let (headers, body) = if let Some(body) = raw.strip_prefix(b"\r\n") {
            (raw.get(..0).unwrap_or_default(), body)
        } else if let Some(at) = find(raw, b"\r\n\r\n") {
            (
                raw.get(..at).unwrap_or_default(),
                raw.get(at + 4..).unwrap_or_default(),
            )
        } else {
            (raw, raw.get(raw.len()..).unwrap_or_default())
        };
        let mut part = BodyPart {
            headers,
            content_type: None,
            in_digest,
            disposition: None,
            content_id: None,
            body,
            nested: None,
        };
        let mut rest = headers;
        let mut count = 0;
        while let Some(((name, value), after)) = next_field(rest)? {
            count += 1;
            if count > self.limits.max_part_headers {
                return Err(MultipartError::TooManyHeaders {
                    limit: self.limits.max_part_headers,
                });
            }
            rest = after;
            if name.eq_ignore_ascii_case(b"Content-Type") {
                if part.content_type.is_some() {
                    return Err(MultipartError::DuplicateHeader("Content-Type"));
                }
                part.content_type = Some(
                    MediaTypeRef::parse(value)
                        .map_err(|_| MultipartError::BadPartHeader("Content-Type"))?,
                );
            } else if name.eq_ignore_ascii_case(b"Content-Disposition") {
                if part.disposition.is_some() {
                    return Err(MultipartError::DuplicateHeader("Content-Disposition"));
                }
                part.disposition = Some(
                    DispositionRef::parse(value)
                        .map_err(|_| MultipartError::BadPartHeader("Content-Disposition"))?,
                );
            } else if name.eq_ignore_ascii_case(b"Content-ID") {
                if part.content_id.is_some() {
                    return Err(MultipartError::DuplicateHeader("Content-ID"));
                }
                part.content_id = Some(content_id(value)?);
            }
        }
        if let Some(media) = part.content_type
            && media.kind().eq_ignore_ascii_case(b"multipart")
        {
            part.nested = Some(self.level(&media, body, depth + 1)?);
        }
        Ok(part)
    }
}

/// `msg-id = "<" addr-spec ">"` (RFC 2045 §7, RFC 822 §4.1): the brackets are
/// taken off when both are there.
fn content_id(value: &[u8]) -> Result<&[u8], MultipartError> {
    let value = trim(value);
    let id = value
        .strip_prefix(b"<")
        .and_then(|inner| inner.strip_suffix(b">"))
        .unwrap_or(value);
    if id.is_empty() {
        return Err(MultipartError::BadPartHeader("Content-ID"));
    }
    Ok(id)
}

/// Where the first part starts: past the first delimiter line.
///
/// `dash` is `CRLF "--" boundary`. The first delimiter may open the body, in
/// which case it has no CRLF of its own in front of it.
fn opening(body: &[u8], dash: &[u8]) -> Result<usize, MultipartError> {
    let bare = dash.get(2..).unwrap_or_default();
    if body.starts_with(bare) {
        match after_boundary(body, bare.len()) {
            Some((_, true)) => return Err(MultipartError::NoParts),
            Some((end, false)) => return Ok(end),
            None => (),
        }
    }
    match next_delimiter(body, 0, dash) {
        Ok((_, _, true)) => Err(MultipartError::NoParts),
        Ok((_, end, false)) => Ok(end),
        Err(_) => Err(MultipartError::NoFirstBoundary),
    }
}

/// The next delimiter at or after `from`: where its CRLF starts, where the
/// line after it starts, and whether it is the close delimiter.
fn next_delimiter(
    body: &[u8],
    from: usize,
    dash: &[u8],
) -> Result<(usize, usize, bool), MultipartError> {
    let mut search = from;
    loop {
        let rest = body.get(search..).ok_or(MultipartError::Unterminated)?;
        let at = search + find(rest, dash).ok_or(MultipartError::Unterminated)?;
        if let Some((end, close)) = after_boundary(body, at + dash.len()) {
            return Ok((at, end, close));
        }
        // the boundary starts this line but more than padding follows it:
        // content, not a delimiter
        search = at + 1;
    }
}

/// What follows a boundary at `at`: `Some((start of the next line, close))`
/// when it ends a delimiter line, `None` when the line goes on.
fn after_boundary(body: &[u8], at: usize) -> Option<(usize, bool)> {
    let rest = body.get(at..)?;
    let (close, rest) = match rest.strip_prefix(b"--") {
        Some(after) => (true, after),
        None => (false, rest),
    };
    let padding = rest
        .iter()
        .take_while(|byte| matches!(**byte, b' ' | b'\t'))
        .count();
    let consumed = body.len() - rest.len() + padding;
    let line = rest.get(padding..)?;
    if line.starts_with(b"\r\n") {
        Some((consumed + 2, close))
    } else if close && line.is_empty() {
        // [CRLF epilogue]: the close delimiter may end the body
        Some((consumed, close))
    } else {
        None
    }
}

/// RFC 2046 §5.1.1: 1 to 70 of `bchars`, the last not a space.
fn valid_boundary(boundary: &[u8]) -> bool {
    let bchar = |byte: &u8| {
        byte.is_ascii_alphanumeric()
            || matches!(
                *byte,
                b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
            )
    };
    (1..=70).contains(&boundary.len())
        && boundary.last().is_some_and(bchar)
        && boundary.iter().all(|byte| *byte == b' ' || bchar(byte))
}

type Field<'a> = (&'a [u8], &'a [u8]);

/// The next `name: value` field of a part's header section, with any fold
/// inside the value, and what follows it.
fn next_field(rest: &[u8]) -> Result<Option<(Field<'_>, &[u8])>, MultipartError> {
    if rest.is_empty() {
        return Ok(None);
    }
    let mut search = 0;
    let (end, next) = loop {
        let Some(at) = rest.get(search..).and_then(|tail| find(tail, b"\r\n")) else {
            break (rest.len(), rest.len());
        };
        let at = search + at;
        if matches!(rest.get(at + 2), Some(b' ' | b'\t')) {
            search = at + 2;
            continue;
        }
        break (at, at + 2);
    };
    let line = rest.get(..end).unwrap_or_default();
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(MultipartError::BadPartHeader("a field without a colon"))?;
    let name = line.get(..colon).unwrap_or_default();
    // RFC 822 §3.2: field-name = 1*<any CHAR, excluding CTLs, SPACE, and ":">
    if name.is_empty() || !name.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(MultipartError::BadPartHeader("a field name"));
    }
    let value = line.get(colon + 1..).unwrap_or_default();
    Ok(Some(((name, value), rest.get(next..).unwrap_or_default())))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// -- writing ---------------------------------------------------------------

/// One part to be written.
#[derive(Clone, Copy, Debug)]
pub struct Part<'a> {
    content_type: &'a str,
    disposition: Option<&'a str>,
    content_id: Option<&'a str>,
    body: &'a [u8],
}

impl<'a> Part<'a> {
    /// A part of this type with this content.
    #[must_use]
    pub const fn new(content_type: &'a str, body: &'a [u8]) -> Self {
        Self {
            content_type,
            disposition: None,
            content_id: None,
            body,
        }
    }

    /// Give the part a `Content-Disposition`, parameters included, as in
    /// `render;handling=optional`.
    #[must_use]
    pub const fn disposition(mut self, disposition: &'a str) -> Self {
        self.disposition = Some(disposition);
        self
    }

    /// Give the part a `Content-ID`, without the angle brackets.
    #[must_use]
    pub const fn content_id(mut self, id: &'a str) -> Self {
        self.content_id = Some(id);
        self
    }

    fn contains(&self, needle: &[u8]) -> bool {
        [
            self.content_type.as_bytes(),
            self.disposition.unwrap_or_default().as_bytes(),
            self.content_id.unwrap_or_default().as_bytes(),
            self.body,
        ]
        .iter()
        .any(|field| find(field, needle).is_some())
    }
}

/// Writes a multipart body.
#[derive(Clone, Debug)]
pub struct MultipartBuilder<'a> {
    subtype: &'a str,
    parts: Vec<Part<'a>>,
}

/// A written multipart body and the `Content-Type` that goes with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltMultipart {
    content_type: String,
    boundary: String,
    body: Vec<u8>,
}

impl BuiltMultipart {
    /// The value of the message's `Content-Type`, boundary included.
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// The boundary that was chosen.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The body, taken.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// How many boundaries are tried before the builder gives up. Each is 64 bits
/// drawn from the content, so a second attempt is already one in 2^64.
const BOUNDARY_ATTEMPTS: u64 = 16;

impl<'a> MultipartBuilder<'a> {
    /// A `multipart/mixed` body (RFC 2046 §5.1.3).
    #[must_use]
    pub const fn mixed() -> Self {
        Self::new("mixed")
    }

    /// A `multipart/alternative` body (RFC 2046 §5.1.4): add the parts in
    /// increasing order of preference.
    #[must_use]
    pub const fn alternative() -> Self {
        Self::new("alternative")
    }

    /// A body of another multipart subtype.
    #[must_use]
    pub const fn new(subtype: &'a str) -> Self {
        Self {
            subtype,
            parts: Vec::new(),
        }
    }

    /// Add a part.
    #[must_use]
    pub fn part(mut self, part: Part<'a>) -> Self {
        self.parts.push(part);
        self
    }

    /// Write the body.
    ///
    /// # Errors
    /// [`MultipartError::NoParts`] with no part, [`MultipartError::IllegalValue`]
    /// for a subtype, type, disposition or content ID that cannot be written,
    /// and [`MultipartError::NoBoundaryAvailable`] if every boundary tried
    /// occurs in some part.
    pub fn build(&self) -> Result<BuiltMultipart, MultipartError> {
        if self.parts.is_empty() {
            return Err(MultipartError::NoParts);
        }
        if self.subtype.is_empty() || !self.subtype.bytes().all(is_subtype_byte) {
            return Err(MultipartError::IllegalValue("subtype"));
        }
        for part in &self.parts {
            check_part(part)?;
        }
        let boundary = pick_boundary(&self.parts, seed(&self.parts))
            .ok_or(MultipartError::NoBoundaryAvailable)?;
        let mut body = Vec::new();
        for part in &self.parts {
            body.extend_from_slice(b"--");
            body.extend_from_slice(boundary.as_bytes());
            body.extend_from_slice(b"\r\nContent-Type: ");
            body.extend_from_slice(part.content_type.as_bytes());
            body.extend_from_slice(b"\r\n");
            if let Some(disposition) = part.disposition {
                body.extend_from_slice(b"Content-Disposition: ");
                body.extend_from_slice(disposition.as_bytes());
                body.extend_from_slice(b"\r\n");
            }
            if let Some(id) = part.content_id {
                body.extend_from_slice(b"Content-ID: <");
                body.extend_from_slice(id.as_bytes());
                body.extend_from_slice(b">\r\n");
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(part.body);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--");
        body.extend_from_slice(boundary.as_bytes());
        body.extend_from_slice(b"--\r\n");
        Ok(BuiltMultipart {
            content_type: format!("multipart/{};boundary={boundary}", self.subtype),
            boundary,
            body,
        })
    }
}

const fn is_subtype_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'+' | b'_')
}

fn check_part(part: &Part<'_>) -> Result<(), MultipartError> {
    let one_line = |value: &str| !value.bytes().any(|byte| byte == b'\r' || byte == b'\n');
    if !one_line(part.content_type) || MediaTypeRef::parse(part.content_type.as_bytes()).is_err() {
        return Err(MultipartError::IllegalValue("content type"));
    }
    if let Some(disposition) = part.disposition
        && (!one_line(disposition) || DispositionRef::parse(disposition.as_bytes()).is_err())
    {
        return Err(MultipartError::IllegalValue("disposition"));
    }
    if let Some(id) = part.content_id
        && (id.is_empty()
            || !id
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'<' && byte != b'>'))
    {
        return Err(MultipartError::IllegalValue("content ID"));
    }
    Ok(())
}

/// A 64-bit FNV-1a over everything the parts hold, so the boundary depends on
/// what it has to stay out of.
fn seed(parts: &[Part<'_>]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for field in [
            part.content_type.as_bytes(),
            part.disposition.unwrap_or_default().as_bytes(),
            part.content_id.unwrap_or_default().as_bytes(),
            part.body,
        ] {
            for byte in field {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
            hash ^= 0xff;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// One boundary candidate: the seed and the attempt, mixed.
fn candidate(seed: u64, attempt: u64) -> String {
    let mut mixed = seed ^ attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^= mixed >> 31;
    format!("sipral-{mixed:016x}")
}

/// The first candidate that occurs nowhere in any part.
fn pick_boundary(parts: &[Part<'_>], seed: u64) -> Option<String> {
    (0..BOUNDARY_ATTEMPTS)
        .map(|attempt| candidate(seed, attempt))
        .find(|boundary| !parts.iter().any(|part| part.contains(boundary.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn media(value: &[u8]) -> MediaTypeRef<'_> {
        MediaTypeRef::parse(value).expect("a media type")
    }

    fn read<'a>(content_type: &'a [u8], body: &'a [u8]) -> Result<Multipart<'a>, MultipartError> {
        Multipart::parse(&media(content_type), body)
    }

    /// The sample message of RFC 2046 §5.1.1, body only, lines ended in CRLF.
    const RFC2046_SAMPLE: &[u8] = b"This is the preamble.  It is to be ignored, though it\r\n\
is a handy place for composition agents to include an\r\n\
explanatory note to non-MIME conformant readers.\r\n\
\r\n\
--simple boundary\r\n\
\r\n\
This is implicitly typed plain US-ASCII text.\r\n\
It does NOT end with a linebreak.\r\n\
--simple boundary\r\n\
Content-type: text/plain; charset=us-ascii\r\n\
\r\n\
This is explicitly typed plain US-ASCII text.\r\n\
It DOES end with a linebreak.\r\n\
\r\n\
--simple boundary--\r\n\
\r\n\
This is the epilogue.  It is also to be ignored.\r\n";

    #[test]
    fn the_rfc_2046_sample_reads_as_the_rfc_describes_it() {
        let body = read(
            br#"multipart/mixed; boundary="simple boundary""#,
            RFC2046_SAMPLE,
        )
        .expect("the sample");
        assert_eq!(body.kind(), MultipartKind::Mixed);
        assert_eq!(body.boundary(), b"simple boundary");
        let [first, second] = body.parts() else {
            panic!("two parts");
        };
        assert!(first.content_type().is_none());
        assert!(first.is("text", "plain"));
        assert_eq!(
            first.body(),
            b"This is implicitly typed plain US-ASCII text.\r\nIt does NOT end with a linebreak."
        );
        assert!(second.is("text", "plain"));
        assert_eq!(
            second
                .content_type()
                .and_then(|m| m.params().get("charset"))
                .as_deref(),
            Some(&b"us-ascii"[..])
        );
        assert_eq!(
            second.body(),
            b"This is explicitly typed plain US-ASCII text.\r\nIt DOES end with a linebreak.\r\n"
        );
    }

    const SIPREC_LIKE: &[u8] = b"--foobar\r\n\
Content-Type: application/sdp\r\n\
\r\n\
v=0\r\n\
--foobar\r\n\
Content-Type: application/rs-metadata+xml\r\n\
Content-Disposition: recording-session\r\n\
Content-ID: <meta@example.com>\r\n\
\r\n\
<recording/>\r\n\
--foobar--\r\n";

    #[test]
    fn each_part_has_its_own_type_disposition_and_id() {
        let body = read(b"multipart/mixed;boundary=foobar", SIPREC_LIKE).expect("a body");
        let [sdp, meta] = body.parts() else {
            panic!("two parts");
        };
        assert!(sdp.is("application", "sdp"));
        assert_eq!(sdp.body(), b"v=0");
        assert!(sdp.disposition().is_none());
        assert!(meta.is("application", "rs-metadata+xml"));
        assert!(meta.disposition().expect("one").is("recording-session"));
        assert_eq!(meta.content_id(), Some(&b"meta@example.com"[..]));
        assert_eq!(meta.header("content-id"), Some(&b"<meta@example.com>"[..]));
        assert_eq!(meta.body(), b"<recording/>");
        assert!(
            body.by_content_id(b"meta@example.com")
                .is_some_and(|p| p.is("application", "rs-metadata+xml"))
        );
        assert!(
            body.find("application", "sdp")
                .is_some_and(|p| p.body() == b"v=0")
        );
    }

    #[test]
    fn an_untyped_part_of_a_digest_is_a_message_not_text() {
        // RFC 2046 §5.1.5: in a digest the default is message/rfc822
        let body = b"--b\r\n\r\nSubject: one\r\n\r\nx\r\n\
--b\r\nContent-Type: text/plain\r\n\r\ny\r\n--b--";
        let parsed = read(b"multipart/digest;boundary=b", body).expect("a body");
        let [untyped, typed] = parsed.parts() else {
            panic!("two parts");
        };
        assert!(untyped.is("message", "rfc822"));
        assert!(!untyped.is("text", "plain"));
        assert!(typed.is("text", "plain"));
        let refused = parsed
            .check(|p| p.is("text", "plain"))
            .expect_err("refused");
        assert_eq!(
            refused.to_string(),
            "required body part message/rfc822 is not understood"
        );
        // and everywhere else it stays text/plain
        let mixed = read(b"multipart/mixed;boundary=b", body).expect("a body");
        assert!(mixed.parts().first().is_some_and(|p| p.is("text", "plain")));
    }

    #[test]
    fn a_boundary_prefix_followed_by_more_is_content_not_a_delimiter() {
        let body = b"--b\r\n\r\nline\r\n--bx still content\r\n--b--";
        let parsed = read(b"multipart/mixed;boundary=b", body).expect("a body");
        let [part] = parsed.parts() else {
            panic!("one part");
        };
        assert_eq!(part.body(), b"line\r\n--bx still content");
    }

    #[test]
    fn transport_padding_after_a_delimiter_is_allowed() {
        let body = b"--b \t\r\n\r\none\r\n--b\t\r\n\r\ntwo\r\n--b-- ";
        let parsed = read(b"multipart/mixed;boundary=b", body).expect("a body");
        let bodies: Vec<&[u8]> = parsed.parts().iter().map(BodyPart::body).collect();
        assert_eq!(bodies, [&b"one"[..], b"two"]);
    }

    #[test]
    fn a_folded_part_header_is_one_field() {
        let body = b"--b\r\nContent-Type: application/sdp;\r\n  x=1\r\n\r\nv=0\r\n--b--";
        let parsed = read(b"multipart/mixed;boundary=b", body).expect("a body");
        let part = parsed.parts().first().expect("a part");
        assert!(part.is("application", "sdp"));
        assert_eq!(
            part.content_type()
                .and_then(|m| m.params().get("x"))
                .as_deref(),
            Some(&b"1"[..])
        );
    }

    #[test]
    fn a_part_with_headers_and_no_content_has_an_empty_body() {
        let body = b"--b\r\nContent-Type: text/plain\r\n--b--";
        let parsed = read(b"multipart/mixed;boundary=b", body).expect("a body");
        let part = parsed.parts().first().expect("a part");
        assert!(part.is("text", "plain"));
        assert!(part.body().is_empty());
        // still a span of the input, not an empty slice from elsewhere
        let input = body.as_ptr_range();
        let span = part.body().as_ptr_range();
        assert!(input.start <= span.start && span.end <= input.end);
    }

    #[test]
    fn nested_multipart_is_read_down_to_the_limit() {
        let body = b"--outer\r\n\
Content-Type: multipart/alternative;boundary=inner\r\n\
\r\n\
--inner\r\n\
Content-Type: text/plain\r\n\
\r\n\
plain\r\n\
--inner\r\n\
Content-Type: text/html\r\n\
\r\n\
<p>html</p>\r\n\
--inner--\r\n\
--outer--\r\n";
        let parsed = read(b"multipart/mixed;boundary=outer", body).expect("a body");
        let nested = parsed
            .parts()
            .first()
            .and_then(BodyPart::nested)
            .expect("nested");
        assert_eq!(nested.kind(), MultipartKind::Alternative);
        assert_eq!(nested.parts().len(), 2);
        assert!(
            parsed
                .find("text", "html")
                .is_some_and(|p| p.body() == b"<p>html</p>")
        );
        let preferred = nested
            .preferred(|p| p.is("text", "plain") || p.is("text", "html"))
            .expect("one");
        assert!(preferred.is("text", "html"));
        let only_plain = nested.preferred(|p| p.is("text", "plain")).expect("one");
        assert!(only_plain.is("text", "plain"));

        let shallow = MultipartLimits {
            max_depth: 1,
            ..MultipartLimits::DEFAULT
        };
        assert_eq!(
            Multipart::parse_with_limits(&media(b"multipart/mixed;boundary=outer"), body, shallow)
                .err(),
            Some(MultipartError::TooDeep { limit: 1 })
        );
    }

    #[test]
    fn the_part_count_is_bounded_across_every_level() {
        let mut body = Vec::new();
        for _ in 0..5 {
            body.extend_from_slice(b"--b\r\n\r\nx\r\n");
        }
        body.extend_from_slice(b"--b--");
        let ct = media(b"multipart/mixed;boundary=b");
        let four = MultipartLimits {
            max_parts: 4,
            ..MultipartLimits::DEFAULT
        };
        assert_eq!(
            Multipart::parse_with_limits(&ct, &body, four).err(),
            Some(MultipartError::TooManyParts { limit: 4 })
        );
        let five = MultipartLimits {
            max_parts: 5,
            ..MultipartLimits::DEFAULT
        };
        assert!(Multipart::parse_with_limits(&ct, &body, five).is_ok());
    }

    #[test]
    fn the_size_and_the_fields_per_part_are_bounded() {
        let ct = media(b"multipart/mixed;boundary=b");
        let small = MultipartLimits {
            max_bytes: 8,
            ..MultipartLimits::DEFAULT
        };
        assert_eq!(
            Multipart::parse_with_limits(&ct, b"--b\r\n\r\nx\r\n--b--", small).err(),
            Some(MultipartError::TooLarge { limit: 8 })
        );
        let one_field = MultipartLimits {
            max_part_headers: 1,
            ..MultipartLimits::DEFAULT
        };
        let two = b"--b\r\nContent-Type: text/plain\r\nX-A: 1\r\n\r\nx\r\n--b--";
        assert_eq!(
            Multipart::parse_with_limits(&ct, two, one_field).err(),
            Some(MultipartError::TooManyHeaders { limit: 1 })
        );
    }

    #[test]
    fn a_body_exactly_at_the_byte_bound_is_read() {
        let body = b"--b\r\n\r\nx\r\n--b--";
        let exact = MultipartLimits {
            max_bytes: body.len(),
            ..MultipartLimits::DEFAULT
        };
        let ct = media(b"multipart/mixed;boundary=b");
        assert!(Multipart::parse_with_limits(&ct, body, exact).is_ok());
    }

    #[test]
    fn a_part_header_section_is_held_to_its_grammar() {
        let ct = b"multipart/mixed;boundary=b";
        for (headers, error) in [
            (
                &b"Content-Disposition: render\r\ncontent-disposition: session\r\n"[..],
                MultipartError::DuplicateHeader("Content-Disposition"),
            ),
            (
                b"Content-ID: <a@x>\r\nContent-ID: <b@x>\r\n",
                MultipartError::DuplicateHeader("Content-ID"),
            ),
            // msg-id has an addr-spec between its brackets
            (
                b"Content-ID: <>\r\n",
                MultipartError::BadPartHeader("Content-ID"),
            ),
            // RFC 822 §3.2: no space and no control in a field name
            (
                b"Content Type: text/plain\r\n",
                MultipartError::BadPartHeader("a field name"),
            ),
            (
                b"X\x01: 1\r\n",
                MultipartError::BadPartHeader("a field name"),
            ),
        ] {
            let body = [b"--b\r\n", headers, b"\r\nx\r\n--b--"].concat();
            assert_eq!(read(ct, &body).err(), Some(error), "{headers:?}");
        }
    }

    #[test]
    fn malformed_boundaries_are_refused() {
        let long = format!("multipart/mixed;boundary={}", "a".repeat(71));
        for ct in [
            &b"multipart/mixed"[..],
            b"multipart/mixed;boundary=\"\"",
            b"multipart/mixed;boundary=\"trailing \"",
            b"multipart/mixed;boundary=\"semi;colon\"",
            b"multipart/mixed;boundary=a@b",
            long.as_bytes(),
        ] {
            let err = read(ct, b"--x\r\n\r\n\r\n--x--").expect_err("refused");
            assert!(
                matches!(
                    err,
                    MultipartError::NoBoundary | MultipartError::BadBoundary
                ),
                "{err:?}"
            );
        }
        let seventy = format!("multipart/mixed;boundary={}", "a".repeat(70));
        let body = format!("--{0}\r\n\r\nx\r\n--{0}--", "a".repeat(70));
        assert!(read(seventy.as_bytes(), body.as_bytes()).is_ok());
    }

    #[test]
    fn a_body_that_is_not_multipart_is_refused_and_says_why() {
        assert_eq!(
            read(b"application/sdp;boundary=b", b"--b\r\n\r\n\r\n--b--").err(),
            Some(MultipartError::NotMultipart)
        );
        assert_eq!(
            read(b"multipart/mixed;boundary=b", b"no delimiter at all").err(),
            Some(MultipartError::NoFirstBoundary)
        );
        assert_eq!(
            read(b"multipart/mixed;boundary=b", b"--b\r\n\r\ncut short").err(),
            Some(MultipartError::Unterminated)
        );
        assert_eq!(
            read(b"multipart/mixed;boundary=b", b"--b--\r\n").err(),
            Some(MultipartError::NoParts)
        );
        assert_eq!(
            read(
                b"multipart/mixed;boundary=b",
                b"--b\r\nno colon\r\n\r\nx\r\n--b--"
            )
            .err(),
            Some(MultipartError::BadPartHeader("a field without a colon"))
        );
        assert_eq!(
            read(
                b"multipart/mixed;boundary=b",
                b"--b\r\nContent-Type: a/b\r\ncontent-type: c/d\r\n\r\nx\r\n--b--"
            )
            .err(),
            Some(MultipartError::DuplicateHeader("Content-Type"))
        );
    }

    #[test]
    fn an_unknown_required_part_is_a_415_and_an_optional_one_is_skipped() {
        let body = b"--b\r\n\
Content-Type: application/sdp\r\n\
\r\n\
v=0\r\n\
--b\r\n\
Content-Type: application/unknown\r\n\
Content-Disposition: render;handling=optional\r\n\
\r\n\
?\r\n\
--b--";
        let parsed = read(b"multipart/mixed;boundary=b", body).expect("a body");
        let sdp_only = |p: &BodyPart<'_>| p.is("application", "sdp");
        assert!(parsed.check(sdp_only).is_ok());

        let required = b"--b\r\n\
Content-Type: application/sdp\r\n\
\r\n\
v=0\r\n\
--b\r\n\
Content-Type: application/unknown\r\n\
Content-Disposition: render\r\n\
\r\n\
?\r\n\
--b--";
        let parsed = read(b"multipart/mixed;boundary=b", required).expect("a body");
        let refused = parsed.check(sdp_only).expect_err("refused");
        assert_eq!(refused.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(
            refused
                .content_type()
                .is_some_and(|m| m.is("application", "unknown"))
        );
    }

    #[test]
    fn an_alternative_needs_one_understood_part_whatever_their_handling() {
        let body = b"--b\r\n\
Content-Type: application/x-old\r\n\
\r\n\
old\r\n\
--b\r\n\
Content-Type: application/x-new\r\n\
Content-Disposition: session;handling=optional\r\n\
\r\n\
new\r\n\
--b--";
        let parsed = read(b"multipart/alternative;boundary=b", body).expect("a body");
        assert!(parsed.check(|p| p.is("application", "x-old")).is_ok());
        let refused = parsed.check(|_| false).expect_err("none understood");
        assert!(
            refused
                .content_type()
                .is_some_and(|m| m.is("application", "x-new"))
        );
    }

    #[test]
    fn handling_defaults_to_required_and_only_optional_relaxes_it() {
        let d = |v: &'static [u8]| DispositionRef::parse(v).expect("a disposition");
        assert_eq!(d(b"session").handling(), Handling::Required);
        assert_eq!(
            d(b"session;handling=required").handling(),
            Handling::Required
        );
        assert_eq!(
            d(b"render; handling=OPTIONAL").handling(),
            Handling::Optional
        );
        assert_eq!(d(b"render;handling=later").handling(), Handling::Required);
        assert!(DispositionRef::parse(b"").is_err());
        assert!(DispositionRef::parse(b"ses sion").is_err());
    }

    #[test]
    fn what_is_built_reads_back_byte_for_byte() {
        let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n";
        let meta = b"<recording xmlns='urn:ietf:params:xml:ns:recording:1'/>";
        let built = MultipartBuilder::mixed()
            .part(Part::new("application/sdp", sdp))
            .part(
                Part::new("application/rs-metadata+xml", meta)
                    .disposition("recording-session")
                    .content_id("m1@example.com"),
            )
            .build()
            .expect("built");
        assert!(
            built
                .content_type()
                .starts_with("multipart/mixed;boundary=")
        );
        let ct = media(built.content_type().as_bytes());
        let parsed = Multipart::parse(&ct, built.body()).expect("reads back");
        assert_eq!(parsed.boundary(), built.boundary().as_bytes());
        let [first, second] = parsed.parts() else {
            panic!("two parts");
        };
        assert_eq!(first.body(), sdp);
        assert_eq!(second.body(), meta);
        assert!(
            second
                .disposition()
                .is_some_and(|d| d.is("recording-session"))
        );
        assert_eq!(second.content_id(), Some(&b"m1@example.com"[..]));
    }

    #[test]
    fn a_built_body_nests() {
        let inner = MultipartBuilder::alternative()
            .part(Part::new("text/plain", b"a"))
            .part(Part::new("text/html", b"<b>a</b>"))
            .build()
            .expect("inner");
        let outer = MultipartBuilder::mixed()
            .part(Part::new(inner.content_type(), inner.body()))
            .build()
            .expect("outer");
        assert_ne!(inner.boundary(), outer.boundary());
        let ct = media(outer.content_type().as_bytes());
        let parsed = Multipart::parse(&ct, outer.body()).expect("reads back");
        assert!(
            parsed
                .find("text", "html")
                .is_some_and(|p| p.body() == b"<b>a</b>")
        );
    }

    #[test]
    fn the_boundary_is_never_one_a_part_contains() {
        let seed = 42;
        let first = candidate(seed, 0);
        let body = format!("text before {first} and after");
        let parts = [Part::new("text/plain", body.as_bytes())];
        let chosen = pick_boundary(&parts, seed).expect("a boundary");
        assert_ne!(chosen, first);
        assert_eq!(chosen, candidate(seed, 1));

        let every: String = (0..BOUNDARY_ATTEMPTS).map(|n| candidate(seed, n)).collect();
        let parts = [Part::new("text/plain", every.as_bytes())];
        assert_eq!(pick_boundary(&parts, seed), None);
    }

    #[test]
    fn the_builder_refuses_what_it_cannot_write() {
        assert_eq!(
            MultipartBuilder::mixed().build().err(),
            Some(MultipartError::NoParts)
        );
        let injected = MultipartBuilder::mixed()
            .part(Part::new("text/plain;a=1\r\nX-Evil: 1", b"x"))
            .build();
        assert_eq!(
            injected.err(),
            Some(MultipartError::IllegalValue("content type"))
        );
        let disposition = MultipartBuilder::mixed()
            .part(Part::new("text/plain", b"x").disposition("render\r\n"))
            .build();
        assert_eq!(
            disposition.err(),
            Some(MultipartError::IllegalValue("disposition"))
        );
        let id = MultipartBuilder::mixed()
            .part(Part::new("text/plain", b"x").content_id("a>b"))
            .build();
        assert_eq!(id.err(), Some(MultipartError::IllegalValue("content ID")));
        let subtype = MultipartBuilder::new("mi xed")
            .part(Part::new("text/plain", b"x"))
            .build();
        assert_eq!(subtype.err(), Some(MultipartError::IllegalValue("subtype")));
    }

    #[test]
    fn a_long_run_of_empty_parameters_does_not_exhaust_the_stack() {
        // a part's Content-Type of one type and 60 000 empty parameters: the
        // boundary lookup walks every one of them
        let mut body = b"--b\r\nContent-Type: multipart/mixed".to_vec();
        body.extend(std::iter::repeat_n(b';', 60_000));
        body.extend_from_slice(b"\r\n\r\nx\r\n--b--");
        assert_eq!(
            read(b"multipart/mixed;boundary=b", &body).err(),
            Some(MultipartError::NoBoundary)
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let ct = media(b"multipart/mixed;boundary=b");
        let pieces: [&[u8]; 8] = [
            b"--b",
            b"\r\n",
            b"--",
            b" ",
            b":",
            b"Content-Type: multipart/mixed;boundary=b",
            b"x",
            b"\r",
        ];
        // every sequence of four pieces: a cheap exhaustive sweep of the
        // shapes the delimiter scanner has to tell apart
        for a in pieces {
            for b in pieces {
                for c in pieces {
                    for d in pieces {
                        let body = [a, b, c, d].concat();
                        let _ = Multipart::parse(&ct, &body);
                    }
                }
            }
        }
    }
}
