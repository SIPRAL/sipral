// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Just enough JSON (RFC 8259): objects of strings written, and any document
//! read, for a payload, a JWT, a service account file and the answers APNs
//! and Google give. Numbers are kept as the text they were written as.

use std::fmt::Write as _;

/// A JSON value.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as written.
    Number(String),
    /// A string, unescaped.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object, members in order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// A member of an object.
    pub(crate) fn get(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members.iter().find(|(n, _)| n == name).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string this is, if it is one.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// The whole number this is, if it is one.
    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(text) => text.parse().ok(),
            _ => None,
        }
    }
}

/// A string literal, quoted and escaped.
pub(crate) fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// An object whose members are all strings.
pub(crate) fn object(members: &[(&str, String)]) -> String {
    let body: Vec<String> = members
        .iter()
        .map(|(name, value)| format!("{}:{}", string(name), string(value)))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// Read one JSON document, or `None` if it is not one.
pub(crate) fn parse(text: &str) -> Option<Value> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
        depth: 0,
    };
    let value = reader.value()?;
    reader.blank();
    (reader.at == reader.bytes.len()).then_some(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: u32,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn blank(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Option<Value> {
        let end = self.at + word.len();
        (self.bytes.get(self.at..end)? == word.as_bytes()).then(|| {
            self.at = end;
            value
        })
    }

    fn value(&mut self) -> Option<Value> {
        self.blank();
        match self.peek()? {
            b'{' => self.nested(Self::object),
            b'[' => self.nested(Self::array),
            b'"' => self.string().map(Value::String),
            b't' => self.literal("true", Value::Bool(true)),
            b'f' => self.literal("false", Value::Bool(false)),
            b'n' => self.literal("null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    /// A document nested deeper than this is refused rather than recursed
    /// into: nothing this crate reads is more than a few levels deep.
    fn nested(&mut self, inner: fn(&mut Self) -> Option<Value>) -> Option<Value> {
        if self.depth >= 32 {
            return None;
        }
        self.depth += 1;
        let value = inner(self);
        self.depth -= 1;
        value
    }

    fn object(&mut self) -> Option<Value> {
        self.at += 1;
        let mut members = Vec::new();
        self.blank();
        if self.peek()? == b'}' {
            self.at += 1;
            return Some(Value::Object(members));
        }
        loop {
            self.blank();
            let name = self.string()?;
            self.blank();
            if self.peek()? != b':' {
                return None;
            }
            self.at += 1;
            let value = self.value()?;
            members.push((name, value));
            self.blank();
            match self.peek()? {
                b',' => self.at += 1,
                b'}' => {
                    self.at += 1;
                    return Some(Value::Object(members));
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self) -> Option<Value> {
        self.at += 1;
        let mut items = Vec::new();
        self.blank();
        if self.peek()? == b']' {
            self.at += 1;
            return Some(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.blank();
            match self.peek()? {
                b',' => self.at += 1,
                b']' => {
                    self.at += 1;
                    return Some(Value::Array(items));
                }
                _ => return None,
            }
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.at;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.at += 1;
        }
        let text = std::str::from_utf8(self.bytes.get(start..self.at)?).ok()?;
        text.parse::<f64>()
            .ok()
            .map(|_| Value::Number(text.to_owned()))
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = std::str::from_utf8(self.bytes.get(self.at..self.at + 4)?).ok()?;
        self.at += 4;
        u32::from_str_radix(digits, 16).ok()
    }

    fn string(&mut self) -> Option<String> {
        if self.peek()? != b'"' {
            return None;
        }
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let byte = self.peek()?;
            self.at += 1;
            match byte {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let escape = self.peek()?;
                    self.at += 1;
                    let c = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&first) {
                                if self.bytes.get(self.at..self.at + 2)? != b"\\u" {
                                    return None;
                                }
                                self.at += 2;
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return None;
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else {
                                first
                            };
                            char::from_u32(code)?
                        }
                        _ => return None,
                    };
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                }
                0x00..=0x1F => return None,
                other => out.push(other),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_account_shaped_document_reads() {
        let text = r#"{ "type": "service_account", "project_id": "p-1",
            "private_key": "-----BEGIN NOTHING-----\nAB\u002fC\n-----END NOTHING-----\n",
            "n": [1, -2.5e3, true, null], "e": {} }"#;
        let value = parse(text).expect("parses");
        assert_eq!(value.get("project_id").and_then(Value::as_str), Some("p-1"));
        assert_eq!(
            value.get("private_key").and_then(Value::as_str),
            Some("-----BEGIN NOTHING-----\nAB/C\n-----END NOTHING-----\n")
        );
        assert_eq!(
            value.get("n"),
            Some(&Value::Array(vec![
                Value::Number("1".into()),
                Value::Number("-2.5e3".into()),
                Value::Bool(true),
                Value::Null
            ]))
        );
    }

    #[test]
    fn surrogate_pairs_and_garbage() {
        assert_eq!(
            parse(r#""\ud83d\ude00""#),
            Some(Value::String("\u{1F600}".into()))
        );
        assert_eq!(parse(r#"{"a":1,}"#), None);
        assert_eq!(parse(r#"{"a":1} x"#), None);
        assert_eq!(parse(&"[".repeat(100)), None);
    }

    #[test]
    fn written_strings_read_back() {
        let written = object(&[("caller", "sip:\"a\"\\b\n@x".into())]);
        let read = parse(&written).expect("parses");
        assert_eq!(
            read.get("caller").and_then(Value::as_str),
            Some("sip:\"a\"\\b\n@x")
        );
    }
}
