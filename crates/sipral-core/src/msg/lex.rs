// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The lexical rules every header value obeys, in one place.
//!
//! Three things bite every SIP parser, and all three are here rather than
//! repeated per field:
//!
//! - A value folded across lines (RFC 3261 §7.3.1) is equivalent to the same
//!   value with the fold replaced by a single space.
//! - A comma separates values only outside a quoted string and outside a
//!   `<...>` URI. `Contact: "Smith, John" <sip:j@x>` is one value, not two.
//! - The same is true of the semicolon that separates parameters.
//!
//! RFC 3261 §25.1:
//!
//! ```text
//! quoted-string  =  SWS DQUOTE *(qdtext / quoted-pair ) DQUOTE
//! quoted-pair    =  "\" (%x00-09 / %x0B-0C / %x0E-7F)
//! ```

use std::borrow::Cow;

/// Replace every fold with a single space (RFC 3261 §7.3.1).
///
/// Borrows when the value was never folded, which is the common case.
#[must_use]
pub fn unfold(value: &[u8]) -> Cow<'_, [u8]> {
    if !value.contains(&b'\n') {
        return Cow::Borrowed(value);
    }
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while let Some(&b) = value.get(i) {
        if b == b'\r' || b == b'\n' {
            // a fold is CRLF (or a bare LF from a lenient parse) plus the
            // whitespace that continues the line; all of it becomes one space
            while matches!(value.get(i), Some(b'\r' | b'\n' | b' ' | b'\t')) {
                i += 1;
            }
            out.push(b' ');
            continue;
        }
        out.push(b);
        i += 1;
    }
    Cow::Owned(out)
}

/// Drop leading and trailing linear whitespace.
///
/// A fold counts: `LWS = [*WSP CRLF] 1*WSP` (RFC 3261 §25.1), so a value that
/// begins after a continuation line begins with CRLF, and leaving those two
/// bytes in place turns whitespace into content. `Route:\r\n <sip:a@b>` would
/// otherwise arrive with a display name of CRLF.
#[must_use]
pub fn trim(value: &[u8]) -> &[u8] {
    let mut s = value;
    while let [b' ' | b'\t' | b'\r' | b'\n', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t' | b'\r' | b'\n'] = s {
        s = rest;
    }
    s
}

/// Whether a byte is one a fold or a space can be made of.
pub(super) const fn is_lws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Undo one level of quoting: strip the surrounding `"` and resolve every
/// `\x` to `x`. A value that is not quoted comes back untouched.
#[must_use]
pub fn unquote(value: &[u8]) -> Cow<'_, [u8]> {
    let trimmed = trim(value);
    let Some(inner) = trimmed
        .strip_prefix(b"\"")
        .and_then(|v| v.strip_suffix(b"\""))
    else {
        return Cow::Borrowed(trimmed);
    };
    if !inner.contains(&b'\\') {
        return Cow::Borrowed(inner);
    }
    let mut out = Vec::with_capacity(inner.len());
    let mut i = 0;
    while let Some(&b) = inner.get(i) {
        if b == b'\\'
            && let Some(&next) = inner.get(i + 1)
        {
            out.push(next);
            i += 2;
            continue;
        }
        out.push(b);
        i += 1;
    }
    Cow::Owned(out)
}

/// Whether the value is one syntactically complete quoted string and nothing
/// else.
///
/// The closing quote has to be the *first* unescaped one, not merely the last
/// byte: `"a" b="c"` starts and ends with a quote and is two values with a
/// missing separator between them.
#[must_use]
pub fn is_quoted(value: &[u8]) -> bool {
    let v = trim(value);
    quoted_len(v) == Some(v.len())
}

/// How long the quoted string starting at byte 0 is, closing quote included.
fn quoted_len(v: &[u8]) -> Option<usize> {
    if v.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while let Some(&b) = v.get(i) {
        match b {
            b'"' => return Some(i + 1),
            b'\\' => {
                v.get(i + 1)?;
                i += 2;
            }
            _ => i += 1,
        }
    }
    None
}

/// The whitespace-separated pieces of a value, folds included.
///
/// RFC 3261 §25.1 makes the separator `LWS = [*WSP CRLF] 1*WSP`, so the space
/// between the two halves of `CSeq: 1 INVITE` may be several spaces, a tab, or
/// a fold. RFC 4475's `wsinv` really does send `cseq: 0009\r\n  INVITE`, and a
/// splitter that looks for one 0x20 byte misses it.
#[derive(Clone, Debug)]
pub struct LwsFields<'a> {
    rest: &'a [u8],
}

/// Walk the whitespace-separated pieces of a value.
#[must_use]
pub const fn fields(value: &[u8]) -> LwsFields<'_> {
    LwsFields { rest: value }
}

impl<'a> Iterator for LwsFields<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
        let start = self.rest.iter().position(|&b| !is_ws(b))?;
        let rest = self.rest.get(start..)?;
        let end = rest.iter().position(|&b| is_ws(b)).unwrap_or(rest.len());
        self.rest = rest.get(end..).unwrap_or_default();
        rest.get(..end)
    }
}

/// Tracks whether the cursor is inside a quoted string or inside `<...>`.
#[derive(Clone, Copy, Debug, Default)]
struct Depth {
    in_quotes: bool,
    escaped: bool,
    in_angle: bool,
}

impl Depth {
    /// Feed one byte. Returns whether the byte is a separator candidate, that
    /// is whether it sits at the top level.
    fn step(&mut self, b: u8) -> bool {
        if self.in_quotes {
            if self.escaped {
                self.escaped = false;
            } else if b == b'\\' {
                self.escaped = true;
            } else if b == b'"' {
                self.in_quotes = false;
            }
            return false;
        }
        match b {
            b'"' => {
                self.in_quotes = true;
                false
            }
            b'<' => {
                self.in_angle = true;
                false
            }
            b'>' => {
                self.in_angle = false;
                false
            }
            _ => !self.in_angle,
        }
    }
}

/// Split a header value on `sep`, ignoring separators inside a quoted string
/// or inside `<...>`.
fn split_top_level(value: &[u8], sep: u8) -> (Option<&[u8]>, &[u8]) {
    let mut depth = Depth::default();
    for (i, &b) in value.iter().enumerate() {
        if depth.step(b) && b == sep {
            return (value.get(..i), value.get(i + 1..).unwrap_or_default());
        }
    }
    (None, value)
}

/// The comma-separated values of one header line, in order.
///
/// `Contact: "Smith, John" <sip:j@x>, <sip:k@y>` yields two, not three.
#[derive(Clone, Debug)]
pub struct CommaList<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> CommaList<'a> {
    /// Walk one header value.
    #[must_use]
    pub const fn new(value: &'a [u8]) -> Self {
        Self {
            rest: value,
            done: false,
        }
    }
}

impl<'a> Iterator for CommaList<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match split_top_level(self.rest, b',') {
            (Some(head), tail) => {
                self.rest = tail;
                Some(trim(head))
            }
            (None, all) => {
                self.done = true;
                Some(trim(all))
            }
        }
    }
}

/// The `;name[=value]` parameters of one header value, in order.
///
/// The part before the first top-level `;` is not a parameter; get it with
/// [`Params::split`].
#[derive(Clone, Debug)]
pub struct Params<'a> {
    rest: &'a [u8],
}

impl<'a> Params<'a> {
    /// Separate the value from its parameters.
    #[must_use]
    pub fn split(value: &'a [u8]) -> (&'a [u8], Self) {
        match split_top_level(value, b';') {
            (Some(head), tail) => (trim(head), Self { rest: tail }),
            (None, all) => (trim(all), Self { rest: b"" }),
        }
    }

    /// The value of one parameter, matched case-insensitively on the name.
    /// `Some(b"")` for a parameter written without one; quoting is undone.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Cow<'a, [u8]>> {
        self.clone()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v.map_or(Cow::Borrowed(&b""[..]), unquote))
    }

    /// Whether a parameter is present at all.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.clone()
            .any(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
    }
}

impl<'a> Iterator for Params<'a> {
    type Item = (&'a [u8], Option<&'a [u8]>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let field = match split_top_level(self.rest, b';') {
            (Some(head), tail) => {
                self.rest = tail;
                head
            }
            (None, all) => {
                self.rest = b"";
                all
            }
        };
        let field = trim(field);
        if field.is_empty() {
            return self.next();
        }
        Some(match split_top_level(field, b'=') {
            (Some(n), v) => (trim(n), Some(trim(v))),
            (None, n) => (trim(n), None),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CommaList, Params, is_quoted, trim, unfold, unquote};

    fn commas(v: &[u8]) -> Vec<&[u8]> {
        CommaList::new(v).collect()
    }

    #[test]
    fn unfolding_replaces_a_fold_with_one_space() {
        assert_eq!(unfold(b"one\r\n two").as_ref(), b"one two");
        assert_eq!(unfold(b"one\r\n\ttwo").as_ref(), b"one two");
        assert_eq!(unfold(b"one\r\n   \t  two").as_ref(), b"one two");
        assert_eq!(unfold(b"a\r\n b\r\n\tc").as_ref(), b"a b c");
    }

    #[test]
    fn unfolding_borrows_when_there_was_no_fold() {
        assert!(matches!(unfold(b"plain"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn trimming_takes_linear_whitespace_from_both_ends() {
        assert_eq!(trim(b"  \tx y \t "), b"x y");
        assert_eq!(trim(b""), b"");
        assert_eq!(trim(b"   "), b"");
        // a fold is whitespace too, and a value that follows one starts with
        // its CRLF
        assert_eq!(trim(b"\r\n   x y"), b"x y");
        assert_eq!(trim(b"\r\n\t"), b"");
        assert_eq!(trim(b"x\r\n "), b"x");
    }

    #[test]
    fn unquoting_strips_the_quotes_and_resolves_escapes() {
        assert_eq!(unquote(br#""Bob""#).as_ref(), b"Bob");
        assert_eq!(unquote(br#""a\"b""#).as_ref(), br#"a"b"#);
        assert_eq!(unquote(br#""a\\b""#).as_ref(), br"a\b");
        assert_eq!(unquote(b"Bob").as_ref(), b"Bob");
        assert_eq!(unquote(b"  Bob  ").as_ref(), b"Bob");
    }

    #[test]
    fn an_unbalanced_quote_is_not_a_quoted_string() {
        // RFC 4475 3.1.2.6
        assert!(!is_quoted(br#""unterminated"#));
        assert!(!is_quoted(br#""escaped closing quote\""#));
        assert!(is_quoted(br#""fine""#));
        assert!(is_quoted(br#""has \" inside""#));
        assert!(!is_quoted(b"bare"));
        // starts and ends with a quote, and is still two values with the
        // separator missing
        assert!(!is_quoted(br#""a" b="c""#));
        assert!(!is_quoted(br#""a"junk"#));
        assert!(is_quoted(br#""""#));
        assert!(!is_quoted(br#"""#));
    }

    #[test]
    fn commas_inside_a_quoted_display_name_do_not_split() {
        let vs = commas(br#""Smith, John" <sip:j@x>, <sip:k@y>"#);
        assert_eq!(vs.len(), 2);
        assert_eq!(
            vs.first().copied(),
            Some(&br#""Smith, John" <sip:j@x>"#[..])
        );
        assert_eq!(vs.get(1).copied(), Some(&b"<sip:k@y>"[..]));
    }

    #[test]
    fn commas_inside_angle_brackets_do_not_split() {
        let vs = commas(b"<sip:a@x;m=1,2>, <sip:b@y>");
        assert_eq!(vs.len(), 2);
        assert_eq!(vs.first().copied(), Some(&b"<sip:a@x;m=1,2>"[..]));
    }

    #[test]
    fn a_single_value_comes_back_whole() {
        assert_eq!(
            commas(b"SIP/2.0/UDP host;branch=z9"),
            vec![&b"SIP/2.0/UDP host;branch=z9"[..]]
        );
    }

    #[test]
    fn several_via_values_on_one_line_split() {
        let vs = commas(b"SIP/2.0/UDP a;branch=z1, SIP/2.0/TCP b;branch=z2");
        assert_eq!(vs.len(), 2);
        assert_eq!(vs.get(1).copied(), Some(&b"SIP/2.0/TCP b;branch=z2"[..]));
    }

    #[test]
    fn parameters_split_off_the_value() {
        let (head, params) = Params::split(b"<sip:a@x>;tag=1928301774;q=0.7");
        assert_eq!(head, b"<sip:a@x>");
        assert_eq!(params.get("tag").as_deref(), Some(&b"1928301774"[..]));
        assert_eq!(params.get("TAG").as_deref(), Some(&b"1928301774"[..]));
        assert_eq!(params.get("q").as_deref(), Some(&b"0.7"[..]));
        assert_eq!(params.get("nope"), None);
    }

    #[test]
    fn a_semicolon_inside_the_uri_belongs_to_the_uri() {
        let (head, params) = Params::split(b"<sip:a@x;transport=tcp>;tag=1");
        assert_eq!(head, b"<sip:a@x;transport=tcp>");
        assert_eq!(params.get("tag").as_deref(), Some(&b"1"[..]));
        assert_eq!(params.get("transport"), None);
    }

    #[test]
    fn a_semicolon_inside_a_quoted_name_belongs_to_the_name() {
        let (head, params) = Params::split(br#""a;b" <sip:c@d>;tag=2"#);
        assert_eq!(head, br#""a;b" <sip:c@d>"#);
        assert_eq!(params.clone().count(), 1);
        assert_eq!(params.get("tag").as_deref(), Some(&b"2"[..]));
    }

    #[test]
    fn a_parameter_without_a_value_is_present_and_empty() {
        let (_, params) = Params::split(b"<sip:a@x>;lr");
        assert!(params.has("lr"));
        assert_eq!(params.get("lr").as_deref(), Some(&b""[..]));
        assert_eq!(params.clone().next(), Some((&b"lr"[..], None)));
    }

    #[test]
    fn a_quoted_parameter_value_is_unquoted_on_the_way_out() {
        let (_, params) = Params::split(br#"Digest;realm="atlanta.example";nonce="xyz""#);
        assert_eq!(
            params.get("realm").as_deref(),
            Some(&b"atlanta.example"[..])
        );
        assert_eq!(params.get("nonce").as_deref(), Some(&b"xyz"[..]));
    }

    #[test]
    fn an_equals_sign_inside_a_quoted_parameter_value_does_not_split_it() {
        let (_, params) = Params::split(br#"Digest;qop="auth=1,auth-int""#);
        assert_eq!(params.get("qop").as_deref(), Some(&b"auth=1,auth-int"[..]));
    }

    #[test]
    fn empty_parameters_are_skipped_rather_than_yielded() {
        let (head, params) = Params::split(b"x;;a=1;;b=2");
        assert_eq!(head, b"x");
        assert_eq!(params.clone().count(), 2);
    }

    #[test]
    fn nothing_makes_the_lexer_panic() {
        for len in 0..14_usize {
            for seed in 0..80_u8 {
                let v: Vec<u8> = (0..len)
                    .map(|i| {
                        let b = seed
                            .wrapping_mul(29)
                            .wrapping_add(u8::try_from(i).unwrap_or(0));
                        // bias towards the bytes that drive the state machine
                        match b % 8 {
                            0 => b'"',
                            1 => b'\\',
                            2 => b'<',
                            3 => b'>',
                            4 => b',',
                            5 => b';',
                            6 => b'=',
                            _ => b,
                        }
                    })
                    .collect();
                let _ = unfold(&v);
                let _ = unquote(&v);
                let _ = is_quoted(&v);
                let n: usize = CommaList::new(&v).count();
                assert!(n <= v.len() + 1);
                let (_, p) = Params::split(&v);
                let _ = p.clone().count();
                let _ = p.get("tag");
            }
        }
    }
}
