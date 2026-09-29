// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! JSON (RFC 8259) for the two objects a PASSporT holds, both ways.
//!
//! Reading takes what any conforming writer produces, whitespace included,
//! because a received PASSporT's signature covers its octets as they arrived
//! and the object is only read, never re-serialised, on that path. It is
//! bounded in nesting and refuses a name that appears twice in one object:
//! RFC 7515 §5.2 lets a JWS reader either refuse duplicates or keep the last,
//! and refusing is the reading that cannot disagree with the signer's.
//!
//! Writing produces the deterministic form of RFC 8225 §9: members in
//! lexicographic order of their names, no whitespace, no line breaks. That is
//! the form a PASSporT is signed in, and the only form in which the compact
//! PASSporT of RFC 8225 §7 can be rebuilt by a verifier that never saw it.

use std::fmt::Write as _;

/// How deep arrays and objects may nest. A PASSporT's deepest member,
/// `dest.tn[0]`, is at depth three.
const MAX_DEPTH: usize = 16;

/// A JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    /// A number, as written: the grammar is checked, the value is not read
    /// until something asks for it.
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// Members in the order they arrived; names are unique.
    Object(Vec<(String, Value)>),
}

/// The input is not JSON, or nests deeper than [`MAX_DEPTH`], or repeats a
/// member name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Invalid;

impl Value {
    /// Parse exactly one JSON text.
    pub(crate) fn parse(input: &[u8]) -> Result<Self, Invalid> {
        let mut reader = Reader { input, at: 0 };
        reader.skip_space();
        let value = reader.value(0)?;
        reader.skip_space();
        if reader.at == input.len() {
            Ok(value)
        } else {
            Err(Invalid)
        }
    }

    /// The member called `name`, when this is an object that has one.
    pub(crate) fn get(&self, name: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members
                .iter()
                .find(|(member, _)| member == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The string, when this is one.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// A non-negative integer written without fraction or exponent, when this
    /// is one that fits a `u64`.
    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(text) if text.bytes().all(|b| b.is_ascii_digit()) => text.parse().ok(),
            _ => None,
        }
    }

    /// The deterministic serialisation of RFC 8225 §9.
    pub(crate) fn canonical(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Number(text) => out.push_str(text),
            Value::String(text) => write_string(text, out),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Value::Object(members) => {
                // ordering by UTF-8 octets is ordering by code point
                let mut sorted: Vec<&(String, Value)> = members.iter().collect();
                sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                out.push('{');
                for (i, (name, value)) in sorted.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(name, out);
                    out.push(':');
                    value.write_canonical(out);
                }
                out.push('}');
            }
        }
    }
}

/// A string, escaping only what RFC 8259 §7 requires: the quotation mark,
/// the reverse solidus and the control characters.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    fn next(&mut self) -> Result<u8, Invalid> {
        let byte = self.peek().ok_or(Invalid)?;
        self.at += 1;
        Ok(byte)
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, Invalid> {
        let end = self.at.checked_add(word.len()).ok_or(Invalid)?;
        if self.input.get(self.at..end) == Some(word) {
            self.at = end;
            Ok(value)
        } else {
            Err(Invalid)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Invalid> {
        match self.peek().ok_or(Invalid)? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(Value::String),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Invalid),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Invalid> {
        if depth > MAX_DEPTH {
            return Err(Invalid);
        }
        self.at += 1;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_space();
            if self.peek() != Some(b'"') {
                return Err(Invalid);
            }
            let name = self.string()?;
            if members.iter().any(|(existing, _)| *existing == name) {
                return Err(Invalid);
            }
            self.skip_space();
            if self.next()? != b':' {
                return Err(Invalid);
            }
            self.skip_space();
            let value = self.value(depth)?;
            members.push((name, value));
            self.skip_space();
            match self.next()? {
                b',' => {}
                b'}' => return Ok(Value::Object(members)),
                _ => return Err(Invalid),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Invalid> {
        if depth > MAX_DEPTH {
            return Err(Invalid);
        }
        self.at += 1;
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_space();
            items.push(self.value(depth)?);
            self.skip_space();
            match self.next()? {
                b',' => {}
                b']' => return Ok(Value::Array(items)),
                _ => return Err(Invalid),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    fn number(&mut self) -> Result<Value, Invalid> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        // RFC 8259 §6: no leading zero on a multi-digit integer part
        if self.peek() == Some(b'0') {
            self.at += 1;
        } else if self.digits() == 0 {
            return Err(Invalid);
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if self.digits() == 0 {
                return Err(Invalid);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                return Err(Invalid);
            }
        }
        let text = self.input.get(start..self.at).ok_or(Invalid)?;
        let text = std::str::from_utf8(text).map_err(|_| Invalid)?;
        Ok(Value::Number(text.to_owned()))
    }

    fn hex4(&mut self) -> Result<u32, Invalid> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = char::from(self.next()?).to_digit(16).ok_or(Invalid)?;
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn string(&mut self) -> Result<String, Invalid> {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            match self.next()? {
                b'"' => return String::from_utf8(out).map_err(|_| Invalid),
                b'\\' => {
                    let c = match self.next()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.escaped_char()?,
                        _ => return Err(Invalid),
                    };
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                }
                byte if byte < 0x20 => return Err(Invalid),
                byte => out.push(byte),
            }
        }
    }

    /// The character of a `\u` escape, joining a surrogate pair (RFC 8259
    /// §7) and refusing a lone half of one.
    fn escaped_char(&mut self) -> Result<char, Invalid> {
        let first = self.hex4()?;
        let code = match first {
            0xd800..=0xdbff => {
                if self.next()? != b'\\' || self.next()? != b'u' {
                    return Err(Invalid);
                }
                let second = self.hex4()?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return Err(Invalid);
                }
                0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
            }
            other => other,
        };
        // a lone low surrogate is not a scalar value, and is refused here
        char::from_u32(code).ok_or(Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(members: &[(&str, Value)]) -> Value {
        Value::Object(
            members
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone()))
                .collect(),
        )
    }

    fn string(text: &str) -> Value {
        Value::String(text.to_owned())
    }

    #[test]
    fn canonical_form_orders_members_and_drops_whitespace() {
        // the claims of RFC 8225 Appendix A, written out of order
        let claims = object(&[
            ("orig", object(&[("tn", string("12155551212"))])),
            ("iat", Value::Number("1443208345".to_owned())),
            (
                "dest",
                object(&[("uri", Value::Array(vec![string("sip:alice@example.com")]))]),
            ),
        ]);
        assert_eq!(
            claims.canonical(),
            r#"{"dest":{"uri":["sip:alice@example.com"]},"iat":1443208345,"orig":{"tn":"12155551212"}}"#
        );
    }

    #[test]
    fn canonical_form_of_a_parsed_object_with_whitespace() {
        let parsed = Value::parse(
            b" {\n \"typ\" : \"passport\",\r\n\t\"alg\":\"ES256\" , \"x5u\":\"https://cert.example.org/passport.cer\"} ",
        )
        .unwrap();
        assert_eq!(
            parsed.canonical(),
            r#"{"alg":"ES256","typ":"passport","x5u":"https://cert.example.org/passport.cer"}"#
        );
    }

    #[test]
    fn strings_escape_only_what_they_must() {
        let value = string("a\"b\\c/d\u{1}\n\u{e9}");
        assert_eq!(value.canonical(), "\"a\\\"b\\\\c/d\\u0001\\n\u{e9}\"");
        assert_eq!(Value::parse(value.canonical().as_bytes()), Ok(value));
    }

    #[test]
    fn escapes_are_read() {
        let parsed = Value::parse(br#""\u0041\/\b\f\n\r\t\ud83d\ude00""#).unwrap();
        assert_eq!(parsed, string("A/\u{8}\u{c}\n\r\t\u{1f600}"));
    }

    #[test]
    fn lone_surrogates_are_refused() {
        assert_eq!(Value::parse(br#""\ud83d""#), Err(Invalid));
        assert_eq!(Value::parse(br#""\ude00""#), Err(Invalid));
        assert_eq!(Value::parse(br#""\ud83d\u0041""#), Err(Invalid));
    }

    #[test]
    fn numbers_follow_the_grammar() {
        for good in ["0", "-0", "12", "1.5", "-1.5e10", "2E-3", "1e+2"] {
            assert_eq!(
                Value::parse(good.as_bytes()),
                Ok(Value::Number(good.to_owned())),
                "{good}"
            );
        }
        for bad in ["01", "-", "1.", ".5", "1e", "+1", "0x10", "1.e5"] {
            assert_eq!(Value::parse(bad.as_bytes()), Err(Invalid), "{bad}");
        }
    }

    #[test]
    fn integers_are_read_only_when_plain() {
        assert_eq!(
            Value::Number("1443208345".into()).as_u64(),
            Some(1_443_208_345)
        );
        assert_eq!(Value::Number("-1".into()).as_u64(), None);
        assert_eq!(Value::Number("1.0".into()).as_u64(), None);
        assert_eq!(Value::Number("1e3".into()).as_u64(), None);
        assert_eq!(Value::Number("99999999999999999999".into()).as_u64(), None);
    }

    #[test]
    fn duplicate_names_are_refused() {
        assert_eq!(Value::parse(br#"{"a":1,"a":2}"#), Err(Invalid));
        assert!(Value::parse(br#"{"a":1,"b":{"a":2}}"#).is_ok());
    }

    #[test]
    fn nesting_is_bounded() {
        let deep_enough = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(Value::parse(deep_enough.as_bytes()).is_ok());
        let too_deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(Value::parse(too_deep.as_bytes()), Err(Invalid));
        let objects = format!(
            "{}1{}",
            r#"{"a":"#.repeat(MAX_DEPTH + 1),
            "}".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(Value::parse(objects.as_bytes()), Err(Invalid));
    }

    #[test]
    fn malformed_texts_are_refused() {
        for bad in [
            "",
            "{",
            "}",
            "[1,]",
            "{\"a\"}",
            "{\"a\":}",
            "{,}",
            "{\"a\":1,}",
            "tru",
            "nul",
            "\"open",
            "\"\u{1}\"",
            "{} {}",
            "{\"a\" 1}",
            "[1 2]",
            "\"\\x\"",
            "\"\\u12\"",
        ] {
            assert_eq!(Value::parse(bad.as_bytes()), Err(Invalid), "{bad:?}");
        }
        assert_eq!(Value::parse(b"\"\xff\""), Err(Invalid));
    }

    #[test]
    fn literals_and_members_are_found() {
        let parsed = Value::parse(br#"{"t":true,"f":false,"n":null,"s":"x"}"#).unwrap();
        assert_eq!(parsed.get("t"), Some(&Value::Bool(true)));
        assert_eq!(parsed.get("f"), Some(&Value::Bool(false)));
        assert_eq!(parsed.get("n"), Some(&Value::Null));
        assert_eq!(parsed.get("s").and_then(Value::as_str), Some("x"));
        assert_eq!(parsed.get("missing"), None);
        assert_eq!(string("x").get("s"), None);
        assert_eq!(
            object(&[("b", Value::Bool(true)), ("a", Value::Null)]).canonical(),
            r#"{"a":null,"b":true}"#
        );
    }
}
