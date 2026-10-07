// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! JSON, written by hand: the crate has no dependencies. The care goes into
//! escaping, since a `Call-ID` is whatever the peer sent.

use core::fmt::Write as _;

/// One JSON string, quotes included, escaped per RFC 8259 §7: the quotation
/// mark, the reverse solidus, and everything below `0x20` (short form where
/// JSON has one, `\u00xx` otherwise).
pub(crate) fn string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            control if control < '\u{20}' => {
                // writing into a String cannot fail
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// The same, for bytes off the wire. The parser can be lenient, so invalid
/// UTF-8 becomes U+FFFD rather than an unparseable document.
pub(crate) fn bytes(out: &mut String, value: &[u8]) {
    string(out, &String::from_utf8_lossy(value));
}

#[cfg(test)]
mod tests {
    use super::{bytes, string};

    fn quoted(text: &str) -> String {
        let mut out = String::new();
        string(&mut out, text);
        out
    }

    #[test]
    fn a_quotation_mark_is_escaped() {
        assert_eq!(quoted(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn a_backslash_is_escaped() {
        assert_eq!(quoted(r"a\b"), r#""a\\b""#);
        // and the escape of the escape is not itself re-escaped
        assert_eq!(quoted(r#"\""#), r#""\\\"""#);
    }

    #[test]
    fn every_control_character_is_escaped() {
        for code in 0_u32..0x20 {
            let ch = char::from_u32(code).expect("a control character");
            let text = quoted(&ch.to_string());
            assert!(
                !text.contains(ch),
                "{code:#04x} went through unescaped: {text}"
            );
            assert!(text.starts_with('"') && text.ends_with('"'), "{text}");
        }
        assert_eq!(quoted("a\nb"), r#""a\nb""#);
        assert_eq!(quoted("a\rb"), r#""a\rb""#);
        assert_eq!(quoted("a\tb"), r#""a\tb""#);
        assert_eq!(quoted("a\u{8}b"), r#""a\bb""#);
        assert_eq!(quoted("a\u{c}b"), r#""a\fb""#);
        assert_eq!(quoted("a\u{1}b"), r#""a\u0001b""#);
        assert_eq!(quoted("a\u{1f}b"), r#""a\u001fb""#);
    }

    #[test]
    fn a_call_id_a_peer_made_hostile_still_parses() {
        let mut out = String::new();
        bytes(&mut out, b"call\"id\\with\nevery\tsort\x01of\x1fthing");
        assert_eq!(out, r#""call\"id\\with\nevery\tsort\u0001of\u001fthing""#);
    }

    #[test]
    fn a_byte_that_is_not_text_becomes_the_replacement_character() {
        let mut out = String::new();
        bytes(&mut out, &[b'a', 0xff, b'b']);
        assert_eq!(out, "\"a\u{fffd}b\"");
    }

    #[test]
    fn text_that_needs_nothing_is_left_alone() {
        assert_eq!(quoted("a84b4c76e66710"), "\"a84b4c76e66710\"");
        // above ASCII is legal in a JSON string as it stands
        assert_eq!(quoted("caf\u{e9}"), "\"caf\u{e9}\"");
    }
}
