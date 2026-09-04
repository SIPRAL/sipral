// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! `From`, `To` and `Contact`: an address, optionally named, with parameters.
//!
//! RFC 3261 §25.1:
//!
//! ```text
//! from-spec     =  ( name-addr / addr-spec ) *( SEMI from-param )
//! name-addr     =  [ display-name ] LAQUOT addr-spec RAQUOT
//! addr-spec     =  SIP-URI / SIPS-URI / absoluteURI
//! display-name  =  *(token LWS) / quoted-string
//! Contact       =  ("Contact" / "m" ) HCOLON
//!                  ( STAR / (contact-param *(COMMA contact-param)))
//! ```
//!
//! Four things decide whether this is right.
//!
//! The angle brackets say where the URI ends. Inside them `;transport=tcp` is
//! a URI parameter; without them the same text is a parameter of the header
//! field (§20.10). RFC 4475 `cparam01` and `cparam02` are one address written
//! both ways, and a stack that reports the same thing for both is wrong twice.
//!
//! `LAQUOT` is `SWS "<"` and `RAQUOT` is `">" SWS`, so the whitespace lives
//! outside the brackets. `< sip:t.watson@example.org >` is malformed, which is
//! the whole of RFC 4475 §3.1.2.14.
//!
//! A display name is a run of tokens or a quoted string, and nothing else.
//! `Bell, Alexander <sip:...>` is neither, because a comma is not a token
//! character (§3.1.2.15) — and accepting it would mean disagreeing with the
//! comma that separates `Contact` values two lines later.
//!
//! `caller<sip:caller@example.com>` has no whitespace where `*(token LWS)`
//! demands it. RFC 4475 §3.1.1.6 calls that a defect in RFC 3261 and says to
//! accept the message, so the token branch stops at the `<`.

use core::fmt;
use std::borrow::Cow;

use super::error::HeaderError;
use super::lex::{Params, fields, trim, unfold, unquote};
use super::message::FieldValues;
use super::method::is_token_byte;
use super::scalar::{Digits, digits};
use super::uri::UriRef;

/// One address, borrowed: a `From`, a `To`, or one `Contact` value.
#[derive(Clone, Copy, Debug)]
pub struct NameAddrRef<'a> {
    display: Option<&'a [u8]>,
    uri: UriRef<'a>,
    uri_bytes: &'a [u8],
    raw: &'a [u8],
    angled: bool,
}

impl<'a> NameAddrRef<'a> {
    /// Read one address. Split a `Contact` line into values with
    /// [`super::CommaList`] first; `From` and `To` carry exactly one.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] for a display name that is neither a token
    /// run nor a quoted string, an unterminated quoted string, whitespace
    /// inside the addr-spec, an unbracketed addr-spec that had to be
    /// bracketed, or an addr-spec that is not a URI.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let head = trim(Params::split(value).0);
        if head.is_empty() {
            return Err(HeaderError::Malformed("empty address"));
        }

        let (display, rest) = if head.first() == Some(&b'"') {
            let end = quoted_end(head)?;
            (head.get(..end), trim(head.get(end..).unwrap_or_default()))
        } else if let Some(open) = head.iter().position(|&b| b == b'<') {
            let name = trim(head.get(..open).unwrap_or_default());
            check_token_run(name)?;
            (
                (!name.is_empty()).then_some(name),
                head.get(open..).unwrap_or_default(),
            )
        } else {
            (None, head)
        };

        let (uri_bytes, angled) = if let Some(inner) = rest.strip_prefix(b"<") {
            let close = inner
                .iter()
                .position(|&b| b == b'>')
                .ok_or(HeaderError::Malformed("name-addr has no closing >"))?;
            if !inner.get(close + 1..).unwrap_or_default().is_empty() {
                return Err(HeaderError::Malformed("trailing bytes after the addr-spec"));
            }
            (inner.get(..close).unwrap_or_default(), true)
        } else {
            if display.is_some() {
                return Err(HeaderError::Malformed(
                    "a display name needs angle brackets",
                ));
            }
            // §20.10 and §20.20: the name-addr form is required when the
            // addr-spec holds one of these, because nothing else says where
            // the URI stops
            if rest.iter().any(|&b| b == b'?' || b == b',') {
                return Err(HeaderError::Malformed(
                    "an addr-spec with a comma or a question mark needs angle brackets",
                ));
            }
            (rest, false)
        };

        if uri_bytes.is_empty() {
            return Err(HeaderError::Malformed("no addr-spec"));
        }
        // RFC 4475 3.1.2.14: LAQUOT and RAQUOT absorb the whitespace, so none
        // of it may be left inside
        if uri_bytes.iter().any(|&b| is_lws_byte(b)) {
            return Err(HeaderError::Malformed("whitespace inside the addr-spec"));
        }
        let uri = UriRef::parse(uri_bytes).map_err(|_| HeaderError::Malformed("addr-spec"))?;

        Ok(Self {
            display,
            uri,
            uri_bytes,
            raw: value,
            angled,
        })
    }

    /// The display name, unfolded and unquoted.
    ///
    /// Quoted text is returned as it was meant: `"Mr. \"Big\" Watson"` comes
    /// back as `Mr. "Big" Watson`, and a fold inside the quotes becomes the
    /// single space it stands for.
    #[must_use]
    pub fn display_name(&self) -> Option<Cow<'a, [u8]>> {
        let raw = self.display?;
        Some(match unfold(raw) {
            Cow::Borrowed(b) => unquote(b),
            Cow::Owned(o) => Cow::Owned(unquote(&o).into_owned()),
        })
    }

    /// The display name exactly as written, quotes and folds included.
    #[must_use]
    pub const fn display_name_raw(&self) -> Option<&'a [u8]> {
        self.display
    }

    /// The address.
    #[must_use]
    pub const fn uri(&self) -> UriRef<'a> {
        self.uri
    }

    /// The address as written, without the angle brackets.
    #[must_use]
    pub const fn uri_bytes(&self) -> &'a [u8] {
        self.uri_bytes
    }

    /// Whether the URI came wrapped in `<...>`.
    ///
    /// This is what decides who owns the parameters, so it is not cosmetic:
    /// with brackets, `;lr` before the `>` is on the URI and
    /// [`NameAddrRef::params`] does not see it.
    #[must_use]
    pub const fn is_name_addr(&self) -> bool {
        self.angled
    }

    /// The parameters of the header field, in the order written. Never the
    /// URI's own.
    #[must_use]
    pub fn params(&self) -> Params<'a> {
        Params::split(self.raw).1
    }

    /// The `tag` parameter (RFC 3261 §19.3), which identifies one end of a
    /// dialog.
    #[must_use]
    pub fn tag(&self) -> Option<Cow<'a, [u8]>> {
        self.params().get("tag")
    }

    /// The `expires` parameter of a `Contact` (RFC 3261 §20.10), in seconds.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when the value is not `1*DIGIT`. A number
    /// too large for 32 bits parses; [`Digits::require`] is where that becomes
    /// an error, if the caller wants it to.
    pub fn expires(&self) -> Result<Option<Digits>, HeaderError> {
        self.params().get("expires").map(|v| digits(&v)).transpose()
    }

    /// The `q` parameter, in thousandths: `q=0.7` is `700`.
    ///
    /// `qvalue` is at most three decimals and at most 1.0, so thousandths hold
    /// every legal value exactly and a float would only add rounding.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when the value is outside
    /// `("0" ["." 0*3DIGIT]) / ("1" ["." 0*3("0")])`.
    pub fn q(&self) -> Result<Option<u16>, HeaderError> {
        self.params().get("q").map(|v| qvalue(&v)).transpose()
    }
}

impl fmt::Display for NameAddrRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.display {
            f.write_str(&String::from_utf8_lossy(name))?;
            f.write_str(" ")?;
        }
        if self.angled {
            write!(f, "<{}>", String::from_utf8_lossy(self.uri_bytes))?;
        } else {
            f.write_str(&String::from_utf8_lossy(self.uri_bytes))?;
        }
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

/// The `Contact` field of one message.
#[derive(Clone, Debug)]
pub enum Contacts<'a> {
    /// `Contact: *`. RFC 3261 §10.2.2 allows it only in a REGISTER that also
    /// carries `Expires: 0`, which one header value cannot know; that check
    /// belongs to whoever handles the request.
    Star,
    /// The addresses, in wire order, across every `Contact` line.
    Addrs(ContactIter<'a>),
}

/// Every `Contact` address of one message, in wire order.
#[derive(Clone, Debug)]
pub struct ContactIter<'a> {
    values: FieldValues<'a>,
}

impl<'a> ContactIter<'a> {
    pub(super) const fn new(values: FieldValues<'a>) -> Self {
        Self { values }
    }
}

impl<'a> Iterator for ContactIter<'a> {
    type Item = Result<NameAddrRef<'a>, HeaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.values.next().map(NameAddrRef::parse)
    }
}

const fn is_lws_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Where the quoted string starting at byte 0 ends, one past its closing
/// quote, refusing anything `qdtext` and `quoted-pair` do not cover.
fn quoted_end(v: &[u8]) -> Result<usize, HeaderError> {
    let mut i = 1;
    while let Some(&b) = v.get(i) {
        match b {
            b'"' => return Ok(i + 1),
            b'\\' => {
                // quoted-pair = "\" (%x00-09 / %x0B-0C / %x0E-7F): CR and LF
                // are carved out so an escape can never look like a fold
                let next = *v
                    .get(i + 1)
                    .ok_or(HeaderError::Malformed("quoted string ends in a backslash"))?;
                if matches!(next, b'\r' | b'\n') || next > 0x7f {
                    return Err(HeaderError::Malformed("CR and LF cannot be escaped"));
                }
                i += 2;
            }
            b'\r' | b'\n' => {
                let after = fold_end(v, i)
                    .ok_or(HeaderError::Malformed("bare CR or LF in a quoted string"))?;
                i = after;
            }
            0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f => {
                return Err(HeaderError::Malformed("control byte in a quoted string"));
            }
            _ => i += 1,
        }
    }
    // RFC 4475 3.1.2.6: there is no addr-spec in this value, only unfinished
    // qdtext, so guessing where the quote should have closed invents one
    Err(HeaderError::Malformed("unterminated quoted string"))
}

/// The end of a fold starting at `i`, or `None` if those bytes are not one.
fn fold_end(v: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    if v.get(j) == Some(&b'\r') {
        j += 1;
    }
    if v.get(j) != Some(&b'\n') {
        return None;
    }
    j += 1;
    if !matches!(v.get(j), Some(b' ' | b'\t')) {
        return None;
    }
    while matches!(v.get(j), Some(b' ' | b'\t')) {
        j += 1;
    }
    Some(j)
}

fn check_token_run(v: &[u8]) -> Result<(), HeaderError> {
    if fields(v).all(|f| f.iter().copied().all(is_token_byte)) {
        return Ok(());
    }
    Err(HeaderError::Malformed(
        "display name is neither a token run nor a quoted string",
    ))
}

fn qvalue(v: &[u8]) -> Result<u16, HeaderError> {
    let v = trim(v);
    let (whole, frac) = match v.iter().position(|&b| b == b'.') {
        Some(i) => (
            v.get(..i).unwrap_or_default(),
            v.get(i + 1..).unwrap_or_default(),
        ),
        None => (v, &b""[..]),
    };
    let base: u16 = match whole {
        b"0" => 0,
        b"1" => 1000,
        _ => return Err(HeaderError::Malformed("qvalue is 0 or 1")),
    };
    if frac.len() > 3 || !frac.iter().all(u8::is_ascii_digit) {
        return Err(HeaderError::Malformed(
            "qvalue takes at most three decimals",
        ));
    }
    if base == 1000 && frac.iter().any(|&d| d != b'0') {
        return Err(HeaderError::Malformed("qvalue is at most 1.000"));
    }
    let mut scale = 100_u16;
    let mut acc = 0_u16;
    for &d in frac {
        acc += u16::from(d - b'0') * scale;
        scale /= 10;
    }
    Ok(base + acc)
}

#[cfg(test)]
mod tests {
    use super::{NameAddrRef, qvalue};
    use crate::msg::{CommaList, HeaderError, HostRef, UriScheme};

    fn addr(v: &[u8]) -> NameAddrRef<'_> {
        NameAddrRef::parse(v).expect("an address")
    }

    fn refused(v: &[u8]) -> bool {
        matches!(NameAddrRef::parse(v), Err(HeaderError::Malformed(_)))
    }

    #[test]
    fn a_bare_addr_spec_with_a_tag() {
        // RFC 3261 20.20
        let a = addr(b"sip:+12125551212@server.example.net;tag=887s");
        assert!(a.display_name().is_none());
        assert!(!a.is_name_addr());
        assert_eq!(a.tag().as_deref(), Some(&b"887s"[..]));
        let u = a.uri().sip().expect("sip parts");
        assert_eq!(u.user, Some("+12125551212"));
        assert_eq!(u.host, HostRef::Name("server.example.net"));
    }

    #[test]
    fn a_quoted_display_name_and_space_before_the_semicolon() {
        // RFC 3261 20.20; SEMI is SWS ";" SWS
        let a = addr(br#""A. G. Bell" <sip:agb@example.com> ;tag=a48s"#);
        assert_eq!(a.display_name().as_deref(), Some(&b"A. G. Bell"[..]));
        assert!(a.is_name_addr());
        assert_eq!(a.tag().as_deref(), Some(&b"a48s"[..]));
    }

    #[test]
    fn a_token_display_name_needs_no_quotes() {
        let a = addr(b"Anonymous <sip:c8oqz84zk7z@privacy.example.org>;tag=hyh8");
        assert_eq!(a.display_name().as_deref(), Some(&b"Anonymous"[..]));
        assert_eq!(a.tag().as_deref(), Some(&b"hyh8"[..]));
    }

    #[test]
    fn a_token_display_name_may_sit_against_the_bracket() {
        // RFC 4475 3.1.1.6 lwsdisp: a known defect in the 3261 grammar, and a
        // valid message
        let a = addr(b"caller<sip:caller@example.com>;tag=323");
        assert_eq!(a.display_name().as_deref(), Some(&b"caller"[..]));
        assert_eq!(a.tag().as_deref(), Some(&b"323"[..]));
    }

    #[test]
    fn escapes_inside_a_quoted_display_name_are_resolved() {
        let a = addr(br#""Mr. \"Big\" Watson" <sip:watson@example.com>;tag=1"#);
        assert_eq!(
            a.display_name().as_deref(),
            Some(&br#"Mr. "Big" Watson"#[..])
        );
    }

    #[test]
    fn a_fold_inside_a_quoted_display_name_is_one_space() {
        let a = addr(b"\"Mr.\r\n Watson\" <sip:watson@example.com>");
        assert_eq!(a.display_name().as_deref(), Some(&b"Mr. Watson"[..]));
    }

    #[test]
    fn an_angle_bracket_inside_the_quotes_is_not_the_end_of_the_uri() {
        let a = addr(br#""9 > 5" <sip:a@b.example>;tag=2"#);
        assert_eq!(a.display_name().as_deref(), Some(&b"9 > 5"[..]));
        assert_eq!(a.uri_bytes(), b"sip:a@b.example");
        assert_eq!(a.tag().as_deref(), Some(&b"2"[..]));
    }

    #[test]
    fn brackets_decide_who_owns_the_parameters() {
        // RFC 4475 3.3.12 cparam01 and 3.3.13 cparam02: the same address, and
        // unknownparam belongs to a different object in each
        let bare = addr(b"sip:+19725552222@gw1.example.net;unknownparam");
        assert!(!bare.is_name_addr());
        assert!(bare.params().has("unknownparam"));
        assert_eq!(
            bare.uri().sip().expect("sip parts").params().count(),
            0,
            "unknownparam is not a URI parameter here"
        );

        let angled = addr(b"<sip:+19725552222@gw1.example.net;unknownparam>");
        assert!(angled.is_name_addr());
        assert_eq!(angled.params().count(), 0);
        assert!(
            angled
                .uri()
                .sip()
                .expect("sip parts")
                .has_param("unknownparam")
        );
    }

    #[test]
    fn an_unbracketed_uri_keeps_none_of_its_parameters() {
        let a = addr(b"sip:alice@atlanta.example.com;transport=tcp;tag=99");
        assert_eq!(a.uri_bytes(), b"sip:alice@atlanta.example.com");
        assert_eq!(a.params().get("transport").as_deref(), Some(&b"tcp"[..]));
        assert_eq!(a.tag().as_deref(), Some(&b"99"[..]));
        assert_eq!(a.uri().sip().expect("sip parts").transport(), None);
    }

    #[test]
    fn an_unterminated_quoted_string_is_refused() {
        // RFC 4475 3.1.2.6 quotbal
        assert!(refused(br#""Mr. J. User <sip:j.user@example.com>"#));
    }

    #[test]
    fn a_display_name_outside_the_token_alphabet_is_refused() {
        // RFC 4475 3.1.2.15 baddn
        assert!(refused(
            b"Bell, Alexander <sip:a.g.bell@example.com>;tag=43"
        ));
        assert!(refused(b"Watson, Thomas <sip:t.watson@example.org>"));
        // parentheses are not comment syntax in these fields
        assert!(refused(b"caller (comment) <sip:caller@example.com>"));
    }

    #[test]
    fn whitespace_inside_the_brackets_is_refused() {
        // RFC 4475 3.1.2.14 badaspec: LAQUOT is SWS "<", so the space belongs
        // outside
        assert!(refused(br#""Watson, Thomas" < sip:t.watson@example.org >"#));
        assert!(refused(b"<sip:a@b.example >"));
        assert!(refused(b"< sip:a@b.example>"));
        // and the same rule catches a fold that landed inside the URI
        assert!(refused(b"<sip:a@\r\n b.com>"));
    }

    #[test]
    fn an_unbracketed_addr_spec_with_a_question_mark_is_refused() {
        // RFC 4475 3.1.2.13 regbadct
        assert!(refused(
            b"sip:user@example.com?Route=%3Csip:sip.example.com%3E"
        ));
        // the same URI is fine once it is bracketed: RFC 4475 3.3.11 regescrt
        let a = addr(b"<sip:user@example.com?Route=%3Csip:sip.example.com%3E>");
        assert_eq!(
            a.uri().sip().expect("sip parts").headers().next(),
            Some(("Route", "%3Csip:sip.example.com%3E"))
        );
    }

    #[test]
    fn an_unbracketed_addr_spec_with_a_comma_is_refused() {
        // the comma is legal in userinfo, which is exactly why the brackets
        // become mandatory
        assert!(refused(b"sip:a,b@example.com"));
    }

    #[test]
    fn a_malformed_address_is_refused() {
        assert!(refused(b""));
        assert!(refused(b"   "));
        assert!(refused(b"<sip:a@b"));
        assert!(refused(b"<>"));
        assert!(refused(b"not-a-uri"));
        assert!(refused(b"<sip:a@b> junk"));
        assert!(refused(br#""name" sip:a@b"#));
        assert!(refused(b"<sip:a@b>, <sip:c@d>"));
    }

    #[test]
    fn a_non_sip_scheme_is_an_address_too() {
        let a = addr(br#""Mr. Watson" <mailto:watson@example.com>;q=0.1"#);
        assert_eq!(a.uri().scheme(), UriScheme::Other("mailto"));
        assert_eq!(a.q(), Ok(Some(100)));
    }

    #[test]
    fn a_contact_line_splits_on_the_commas_that_are_not_quoted() {
        let line = br#""Mr. Watson" <sip:watson@worcester.example.com>;q=0.7;expires=3600, "Mr. Watson" <mailto:watson@example.com>;q=0.1"#;
        let values: Vec<_> = CommaList::new(line).collect();
        assert_eq!(values.len(), 2);

        let first = addr(values.first().copied().expect("first"));
        assert_eq!(first.q(), Ok(Some(700)));
        assert_eq!(
            first.expires().expect("digits").expect("present").value,
            Some(3600)
        );

        let second = addr(values.get(1).copied().expect("second"));
        assert_eq!(second.q(), Ok(Some(100)));
        assert_eq!(second.expires(), Ok(None));
    }

    #[test]
    fn a_quoted_comma_keeps_one_value_whole() {
        let values: Vec<_> =
            CommaList::new(br#""Bell, Alexander" <sip:a.g.bell@example.com>"#).collect();
        assert_eq!(values.len(), 1);
        let a = addr(values.first().copied().expect("only"));
        assert_eq!(a.display_name().as_deref(), Some(&b"Bell, Alexander"[..]));
    }

    #[test]
    fn a_repeated_parameter_parses_and_is_left_to_the_layer_above() {
        // 7.3.1 forbids it to the sender and says nothing to the receiver
        let a = addr(b"sip:alice@atlanta.example.com;tag=1;tag=2");
        assert_eq!(a.params().count(), 2);
        assert_eq!(a.tag().as_deref(), Some(&b"1"[..]));
    }

    #[test]
    fn qvalues_are_read_in_thousandths() {
        assert_eq!(qvalue(b"0"), Ok(0));
        assert_eq!(qvalue(b"0.7"), Ok(700));
        assert_eq!(qvalue(b"0.70"), Ok(700));
        assert_eq!(qvalue(b"0.007"), Ok(7));
        assert_eq!(qvalue(b"1"), Ok(1000));
        assert_eq!(qvalue(b"1.0"), Ok(1000));
        assert_eq!(qvalue(b"1.000"), Ok(1000));
        assert!(matches!(qvalue(b"1.5"), Err(HeaderError::Malformed(_))));
        assert!(matches!(qvalue(b"0.7777"), Err(HeaderError::Malformed(_))));
        assert!(matches!(qvalue(b"2"), Err(HeaderError::Malformed(_))));
        assert!(matches!(qvalue(b"abc"), Err(HeaderError::Malformed(_))));
    }

    #[test]
    fn expires_reports_a_number_that_does_not_fit_rather_than_wrapping() {
        let a = addr(b"<sip:a@b>;expires=99999999999999999999");
        assert_eq!(a.expires().expect("digits").expect("present").value, None);
        assert!(matches!(
            addr(b"<sip:a@b>;expires=soon").expires(),
            Err(HeaderError::Malformed(_))
        ));
    }

    #[test]
    fn a_backslash_before_a_line_break_is_not_an_escape() {
        assert!(refused(b"\"Mr.\\\rWatson\" <sip:watson@example.com>;tag=1"));
        assert!(refused(b"\"Mr.\\\nWatson\" <sip:watson@example.com>;tag=1"));
    }

    #[test]
    fn display_round_trips_what_was_parsed() {
        for s in [
            &b"sip:+12125551212@server.example.net;tag=887s"[..],
            &br#""A. G. Bell" <sip:agb@example.com>;tag=a48s"#[..],
            &b"<sip:a@b;transport=tcp>;q=0.7;expires=3600"[..],
            &b"<sip:a@b>;lr"[..],
        ] {
            assert_eq!(addr(s).to_string().as_bytes(), s);
        }
    }

    #[test]
    fn nothing_makes_the_address_parser_panic() {
        for len in 0..14_usize {
            for seed in 0..96_u8 {
                let v: Vec<u8> = (0..len)
                    .map(|i| {
                        let b = seed
                            .wrapping_mul(31)
                            .wrapping_add(u8::try_from(i).unwrap_or(0));
                        match b % 9 {
                            0 => b'"',
                            1 => b'\\',
                            2 => b'<',
                            3 => b'>',
                            4 => b';',
                            5 => b'=',
                            6 => b'\r',
                            7 => b'\n',
                            _ => b,
                        }
                    })
                    .collect();
                if let Ok(a) = NameAddrRef::parse(&v) {
                    let _ = a.display_name();
                    let _ = a.tag();
                    let _ = a.q();
                    let _ = a.expires();
                    let _ = a.to_string();
                }
            }
        }
    }
}
