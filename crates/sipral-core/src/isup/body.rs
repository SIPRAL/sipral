// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The `application/ISUP` body of a SIP message (RFC 3204 §3.1), alone or
//! as one part of a `multipart/mixed` beside the session description
//! (RFC 3204 §4.1, RFC 3372 §6).
//!
//! RFC 3204 gives the type two parameters. `version` names the ISUP
//! variant, with "no constraints on the values"; `base` names a variant
//! from its Table 1 that the one in `version` derives from, for a receiver
//! that does not know the `version` string. The disposition defaults to
//! `signal`, and its `handling` to required (§6): a receiver that cannot
//! use a required body refuses the request with 415.
//!
//! [`Variant`] is what this crate makes of the two: the ITU-T family it
//! reads (ITU-T and ETSI, both written to Q.763), the ANSI and TTC ones it
//! does not, and a `version` it does not know with no `base` it does, read
//! as the ITU-T format SIP-I (ITU-T Q.1912.5) carries.

use std::borrow::Cow;

use super::{Isup, IsupError, parse};
use crate::msg::{DispositionRef, Handling, HeaderName, MediaTypeRef, Multipart, RawMessage};

/// `Content-Disposition` (RFC 3261 §20.11).
const CONTENT_DISPOSITION: HeaderName<'static> = HeaderName::Extension("Content-Disposition");

/// Which ISUP an `application/ISUP` body says it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Variant {
    /// ITU-T (`itu-t88`, `itu-t92+`) or ETSI (`etsi121`, `etsi356`): the
    /// Q.763 format this crate reads.
    Itu,
    /// ANSI (`ansi88`, `ansi00`) or Telcordia's GR-317 (`gr317`): another
    /// format, not read here.
    Ansi,
    /// TTC (`ttc87`, `ttc93+`), Japan's: not read here.
    Ttc,
    /// Neither parameter names a variant RFC 3204's Table 1 has; read as
    /// ITU-T.
    Unspecified,
}

impl Variant {
    fn of_token(token: &[u8]) -> Option<Self> {
        let token = token.to_ascii_lowercase();
        if token.starts_with(b"itu-t") || token.starts_with(b"etsi") {
            Some(Self::Itu)
        } else if token.starts_with(b"ansi") || token == b"gr317" {
            Some(Self::Ansi)
        } else if token.starts_with(b"ttc") {
            Some(Self::Ttc)
        } else {
            None
        }
    }

    /// The variant an `application/ISUP` media type's `version` names, else
    /// the one its `base` names.
    #[must_use]
    pub fn of_media(media: &MediaTypeRef<'_>) -> Self {
        let params = media.params();
        let named = |name| params.get(name).and_then(|token| Self::of_token(&token));
        named("version")
            .or_else(|| named("base"))
            .unwrap_or(Self::Unspecified)
    }

    /// Whether this crate reads the variant.
    #[must_use]
    pub const fn readable(self) -> bool {
        matches!(self, Self::Itu | Self::Unspecified)
    }
}

/// An `application/ISUP` body, found in a SIP message.
#[derive(Clone, Copy, Debug)]
pub struct IsupBody<'a> {
    bytes: &'a [u8],
    media: MediaTypeRef<'a>,
    handling: Handling,
}

impl<'a> IsupBody<'a> {
    /// The ISUP body of a message: the body itself when it is
    /// `application/ISUP`, else the first such part of a multipart body,
    /// depth first. `None` when there is none, or the multipart body does
    /// not read.
    #[must_use]
    pub fn find(message: &RawMessage<'a>) -> Option<Self> {
        let media = message.content_type().ok()?;
        let body = message.body();
        if body.is_empty() {
            return None;
        }
        if media.is("application", "isup") {
            let handling = message
                .header(CONTENT_DISPOSITION)
                .and_then(|value| DispositionRef::parse(value).ok())
                .map_or(Handling::Required, |disposition| disposition.handling());
            return Some(Self {
                bytes: body,
                media,
                handling,
            });
        }
        if !media.kind().eq_ignore_ascii_case(b"multipart") {
            return None;
        }
        let multipart = Multipart::parse(&media, body).ok()?;
        let part = multipart.find("application", "isup")?;
        Some(Self {
            bytes: part.body(),
            media: part.content_type()?,
            handling: part.handling(),
        })
    }

    /// The ISUP message, as carried.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The `version` parameter, when there is one.
    #[must_use]
    pub fn version(&self) -> Option<Cow<'a, [u8]>> {
        self.media.params().get("version")
    }

    /// The `base` parameter, when there is one.
    #[must_use]
    pub fn base(&self) -> Option<Cow<'a, [u8]>> {
        self.media.params().get("base")
    }

    /// Whether the sender let a receiver that cannot use the body ignore it.
    #[must_use]
    pub const fn handling(&self) -> Handling {
        self.handling
    }

    /// The variant `version` names, else the one `base` names.
    #[must_use]
    pub fn variant(&self) -> Variant {
        Variant::of_media(&self.media)
    }

    /// The message, read.
    ///
    /// # Errors
    /// As [`parse`].
    pub fn parse(&self) -> Result<Isup<'a>, IsupError> {
        parse(self.bytes)
    }
}
