// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A JSON value, and the reader and writer for it.
//!
//! Control messages travel as JSON, and nothing in this workspace may pull in
//! a JSON crate, so this is the whole of what one needs: objects, arrays,
//! strings with their escapes, numbers, booleans, null. Malformed input is
//! refused rather than repaired — a control channel that guesses at a broken
//! message is worse than one that drops it — and nesting is bounded so a
//! hostile peer cannot recurse the parser into a stack overflow.

use core::fmt;

/// How many objects and arrays may nest inside one another.
///
/// Chosen, not measured: every message this crate defines is two or three
/// fields deep, so this leaves a wide margin while still being a number
/// rather than "however deep the call stack happens to tolerate."
const MAX_DEPTH: usize = 32;

/// A JSON value.
///
/// `Number` holds an `f64`, which is why the type derives `PartialEq` and not
/// `Eq` — the same reason floats are left out of the standard library's
/// `Ord`.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// Any JSON number. Every value this crate encodes is a small integer,
    /// which an `f64` carries exactly.
    Number(f64),
    /// A string, already unescaped.
    String(String),
    /// An array, in order.
    Array(Vec<Value>),
    /// An object, in the order its members were written. A repeated key is
    /// refused at parse time rather than resolved by "first wins" or "last
    /// wins" — see [`JsonError::DuplicateKey`].
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The value of `key` in an object, or `None` if this is not an object or
    /// has no such key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The number, if this is one.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Whether this is `null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Serialise to JSON text, appended to `out`.
    ///
    /// # Errors
    /// [`JsonError::NumberOutOfRange`] if any `Number` in the tree is NaN or
    /// infinite. Neither is a JSON token, and writing one out would hand the
    /// reader something this same module refuses to read back.
    pub fn write(&self, out: &mut String) -> Result<(), JsonError> {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Number(n) => {
                if !n.is_finite() {
                    return Err(JsonError::NumberOutOfRange);
                }
                out.push_str(&n.to_string());
            }
            Self::String(s) => write_string(s, out),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out)?;
                }
                out.push(']');
            }
            Self::Object(members) => {
                out.push('{');
                for (i, (key, value)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    /// [`Value::write`], returning a fresh `String`.
    ///
    /// # Errors
    /// See [`Value::write`].
    pub fn to_json_string(&self) -> Result<String, JsonError> {
        let mut out = String::new();
        self.write(&mut out)?;
        Ok(out)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::Number(f64::from(value))
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

/// Write `s` as a quoted JSON string, escaping what the grammar requires.
///
/// Everything else — including any non-ASCII character — is copied through
/// unescaped, which is legal: JSON text is Unicode, not ASCII.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (u32::from(c)) < 0x20 => push_unicode_escape(out, u32::from(c)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append `\uXXXX` for a code point below 0x20, the control characters with
/// no named escape of their own.
fn push_unicode_escape(out: &mut String, code: u32) {
    out.push_str("\\u");
    for shift in [12_u32, 8, 4, 0] {
        let nibble = (code >> shift) & 0xF;
        out.push(char::from_digit(nibble, 16).unwrap_or('0'));
    }
}

/// Read a JSON value from bytes.
///
/// # Errors
/// See [`JsonError`].
pub fn parse(bytes: &[u8]) -> Result<Value, JsonError> {
    let text = core::str::from_utf8(bytes).map_err(|_| JsonError::NotUtf8)?;
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos == parser.bytes.len() {
        Ok(value)
    } else {
        Err(JsonError::TrailingData { at: parser.pos })
    }
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.bump() == Some(byte) {
            Ok(())
        } else {
            Err(JsonError::Unexpected { at: self.pos })
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JsonError::Unexpected { at: self.pos }),
        }
    }

    fn literal(&mut self, text: &str, value: Value) -> Result<Value, JsonError> {
        let end = self.pos.saturating_add(text.len());
        if self.bytes.get(self.pos..end) == Some(text.as_bytes()) {
            self.pos = end;
            Ok(value)
        } else {
            Err(JsonError::Unexpected { at: self.pos })
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Unexpected { at: self.pos });
            }
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            if members.iter().any(|(k, _): &(String, Value)| *k == key) {
                return Err(JsonError::DuplicateKey { key });
            }
            members.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => break,
                _ => return Err(JsonError::Unexpected { at: self.pos }),
            }
        }
        Ok(Value::Object(members))
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => break,
                _ => return Err(JsonError::Unexpected { at: self.pos }),
            }
        }
        Ok(Value::Array(items))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                self.pos += 1;
            }
            if self.pos > start {
                // sound because every byte that stopped the run above --
                // '"', '\\', and every control byte below 0x20 -- is ASCII,
                // and a UTF-8 continuation or lead byte is always 0x80 or
                // higher, so `pos` never lands anywhere but a char boundary
                let Some(run) = self.text.get(start..self.pos) else {
                    return Err(JsonError::Unexpected { at: self.pos });
                };
                out.push_str(run);
            }
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    self.escape(&mut out)?;
                }
                _ => return Err(JsonError::UnterminatedString),
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), JsonError> {
        match self.bump() {
            Some(b'"') => out.push('"'),
            Some(b'\\') => out.push('\\'),
            Some(b'/') => out.push('/'),
            Some(b'b') => out.push('\u{8}'),
            Some(b'f') => out.push('\u{c}'),
            Some(b'n') => out.push('\n'),
            Some(b'r') => out.push('\r'),
            Some(b't') => out.push('\t'),
            Some(b'u') => out.push(self.unicode_escape()?),
            _ => return Err(JsonError::BadEscape),
        }
        Ok(())
    }

    /// One `\uXXXX`, already past the `u`, combined with a following low
    /// surrogate if the first unit needs one.
    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let unit = self.hex4()?;
        if (0xD800..=0xDBFF).contains(&unit) {
            if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                return Err(JsonError::UnpairedSurrogate);
            }
            let low = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(JsonError::UnpairedSurrogate);
            }
            let scalar = 0x1_0000 + (u32::from(unit) - 0xD800) * 0x400 + (u32::from(low) - 0xDC00);
            char::from_u32(scalar).ok_or(JsonError::UnpairedSurrogate)
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            Err(JsonError::UnpairedSurrogate)
        } else {
            char::from_u32(u32::from(unit)).ok_or(JsonError::UnpairedSurrogate)
        }
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let digit = self
                .bump()
                .and_then(hex_digit)
                .ok_or(JsonError::BadEscape)?;
            value = (value << 4) | u16::from(digit);
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(JsonError::Unexpected { at: self.pos }),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let frac_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(JsonError::Unexpected { at: self.pos });
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(JsonError::Unexpected { at: self.pos });
            }
        }
        let Some(text) = self.text.get(start..self.pos) else {
            return Err(JsonError::Unexpected { at: self.pos });
        };
        let Ok(value) = text.parse::<f64>() else {
            return Err(JsonError::Unexpected { at: start });
        };
        if value.is_finite() {
            Ok(Value::Number(value))
        } else {
            Err(JsonError::NumberOutOfRange)
        }
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Why bytes were not a JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonError {
    /// The bytes are not UTF-8. JSON text is required to be (RFC 8259 §8.1).
    NotUtf8,
    /// A token that is not any value the grammar allows, at this byte offset.
    Unexpected {
        /// Byte offset into the input.
        at: usize,
    },
    /// A string's closing quote never arrived.
    UnterminatedString,
    /// A backslash followed by something that is not one of the recognised
    /// escapes.
    BadEscape,
    /// A `\u` high surrogate with no low surrogate after it, a low surrogate
    /// with no high surrogate before it, or a low surrogate that is not in
    /// the range a high surrogate requires.
    UnpairedSurrogate,
    /// A syntactically valid number too large to be a finite `f64`.
    NumberOutOfRange,
    /// More nested objects or arrays than this module allows.
    TooDeep,
    /// Bytes remained after one complete value was read.
    TrailingData {
        /// Byte offset where the value ended.
        at: usize,
    },
    /// An object repeated a key.
    DuplicateKey {
        /// The key.
        key: String,
    },
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str("not UTF-8"),
            Self::Unexpected { at } => write!(f, "unexpected byte at offset {at}"),
            Self::UnterminatedString => f.write_str("string has no closing quote"),
            Self::BadEscape => f.write_str("backslash followed by an unknown escape"),
            Self::UnpairedSurrogate => f.write_str("a \\u surrogate with no matching pair"),
            Self::NumberOutOfRange => f.write_str("number is not a finite value"),
            Self::TooDeep => write!(f, "nesting exceeds {MAX_DEPTH} levels"),
            Self::TrailingData { at } => write!(f, "data left over after offset {at}"),
            Self::DuplicateKey { key } => write!(f, "key {key:?} repeated in one object"),
        }
    }
}

impl core::error::Error for JsonError {}

#[cfg(test)]
mod tests {
    use super::{JsonError, Value, parse};

    #[test]
    fn the_primitive_values_round_trip() {
        for text in ["null", "true", "false", "0", "-1", "1.5", "1e3", "1E-3"] {
            let value = parse(text.as_bytes()).expect("valid JSON");
            let written = value.to_json_string().expect("finite");
            assert_eq!(parse(written.as_bytes()).expect("valid JSON"), value);
        }
    }

    #[test]
    fn an_object_with_every_kind_of_member_round_trips() {
        let text = br#"{"a":1,"b":"two","c":[3,false,null],"d":{"e":true}}"#;
        let value = parse(text).expect("valid JSON");
        let Value::Object(members) = &value else {
            panic!("expected an object");
        };
        assert_eq!(members.len(), 4);
        assert_eq!(value.get("a"), Some(&Value::Number(1.0)));
        assert_eq!(value.get("b"), Some(&Value::String("two".to_owned())));

        let written = value.to_json_string().expect("finite");
        assert_eq!(parse(written.as_bytes()).expect("valid JSON"), value);
    }

    #[test]
    fn whitespace_between_tokens_is_ignored() {
        let text = b" \t\n\r{ \"a\" : 1 , \"b\" : [ 1 , 2 ] }\r\n";
        assert_eq!(
            parse(text).expect("valid JSON"),
            Value::Object(vec![
                ("a".to_owned(), Value::Number(1.0)),
                (
                    "b".to_owned(),
                    Value::Array(vec![Value::Number(1.0), Value::Number(2.0)])
                ),
            ])
        );
    }

    #[test]
    fn a_string_with_every_named_escape_decodes_to_its_character() {
        let text = br#""\"\\\/\b\f\n\r\t""#;
        assert_eq!(
            parse(text),
            Ok(Value::String("\"\\/\u{8}\u{c}\n\r\t".to_owned()))
        );
    }

    #[test]
    fn a_unicode_escape_outside_the_surrogate_range_decodes_directly() {
        assert_eq!(
            parse("\"\\u00e9\"".as_bytes()),
            Ok(Value::String("\u{e9}".to_owned()))
        );
    }

    #[test]
    fn a_surrogate_pair_combines_into_one_character_past_the_bmp() {
        // U+1F600 GRINNING FACE, encoded as the surrogate pair D83D DE00
        assert_eq!(
            parse("\"\\ud83d\\ude00\"".as_bytes()),
            Ok(Value::String("\u{1F600}".to_owned()))
        );
    }

    #[test]
    fn a_lone_high_surrogate_is_refused() {
        assert_eq!(parse(br#""\ud83d""#), Err(JsonError::UnpairedSurrogate));
        assert_eq!(parse(br#""\ud83dA""#), Err(JsonError::UnpairedSurrogate));
    }

    #[test]
    fn a_lone_low_surrogate_is_refused() {
        assert_eq!(parse(br#""\ude00""#), Err(JsonError::UnpairedSurrogate));
    }

    #[test]
    fn raw_utf8_inside_a_string_is_copied_through_untouched() {
        let text = "\"caf\u{e9} \u{1F600}\"";
        assert_eq!(
            parse(text.as_bytes()),
            Ok(Value::String("caf\u{e9} \u{1F600}".to_owned()))
        );
    }

    #[test]
    fn a_non_ascii_string_survives_the_writer_unescaped() {
        let value = Value::String("caf\u{e9}".to_owned());
        let written = value.to_json_string().expect("finite");
        assert_eq!(written, "\"caf\u{e9}\"");
        assert_eq!(parse(written.as_bytes()), Ok(value));
    }

    #[test]
    fn a_control_character_written_out_uses_a_unicode_escape() {
        let value = Value::String("\u{1}".to_owned());
        let written = value.to_json_string().expect("finite");
        assert_eq!(written, "\"\\u0001\"");
        assert_eq!(parse(written.as_bytes()), Ok(value));
    }

    #[test]
    fn an_unescaped_control_character_in_a_string_is_refused() {
        let mut text = b"\"a".to_vec();
        text.push(0x01);
        text.extend_from_slice(b"b\"");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn bytes_that_are_not_utf8_are_refused() {
        assert_eq!(parse(&[0xFF, 0xFE]), Err(JsonError::NotUtf8));
    }

    #[test]
    fn nesting_past_the_depth_bound_is_refused_not_overflowed() {
        let mut text = "[".repeat(1_000);
        text.push_str(&"]".repeat(1_000));
        assert_eq!(parse(text.as_bytes()), Err(JsonError::TooDeep));
    }

    #[test]
    fn a_duplicate_key_is_refused() {
        assert_eq!(
            parse(br#"{"a":1,"a":2}"#),
            Err(JsonError::DuplicateKey {
                key: "a".to_owned()
            })
        );
    }

    #[test]
    fn a_trailing_comma_is_refused_in_objects_and_arrays() {
        assert!(parse(br#"{"a":1,}"#).is_err());
        assert!(parse(br"[1,]").is_err());
    }

    #[test]
    fn a_leading_zero_before_more_digits_is_refused() {
        assert!(parse(b"01").is_err());
    }

    #[test]
    fn a_number_missing_digits_after_the_point_or_the_exponent_is_refused() {
        assert!(parse(b"1.").is_err());
        assert!(parse(b"1e").is_err());
        assert!(parse(b"1e+").is_err());
        assert!(parse(b".5").is_err());
    }

    #[test]
    fn a_number_too_large_to_be_a_finite_double_is_refused() {
        let text = format!("1{}", "0".repeat(400));
        assert_eq!(parse(text.as_bytes()), Err(JsonError::NumberOutOfRange));
    }

    #[test]
    fn trailing_data_after_a_complete_value_is_refused() {
        assert!(matches!(parse(b"1 2"), Err(JsonError::TrailingData { .. })));
        assert!(matches!(
            parse(br#"{"a":1} garbage"#),
            Err(JsonError::TrailingData { .. })
        ));
    }

    #[test]
    fn empty_input_is_refused() {
        assert!(parse(b"").is_err());
        assert!(parse(b"   ").is_err());
    }

    #[test]
    fn empty_object_and_array_parse_to_empty_collections() {
        assert_eq!(parse(b"{}"), Ok(Value::Object(Vec::new())));
        assert_eq!(parse(b"[]"), Ok(Value::Array(Vec::new())));
    }

    #[test]
    fn negative_zero_and_exponents_parse_to_the_right_value() {
        assert_eq!(parse(b"-0"), Ok(Value::Number(-0.0)));
        assert_eq!(parse(b"1e2"), Ok(Value::Number(100.0)));
        assert_eq!(parse(b"1.5e2"), Ok(Value::Number(150.0)));
    }
}
