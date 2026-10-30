// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! How the trace writes bytes off the wire so that the log stays text.
//!
//! A message's octets reach a line as they are only when they are text. What is not text is
//! either named in one line ([`shape`]: STUN, keep-alives, RTP, RTCP, DTLS, anything else) or,
//! inside a message that is text, written as `\xNN` per octet ([`printable`]).

use std::fmt::Write as _;

/// RFC 8489 §5's magic cookie, at offset 4 of every STUN message.
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// A STUN header's length: type, length, cookie and a 96-bit transaction id.
const STUN_HEADER: usize = 20;

/// How many leading octets a summary shows in hex.
const SHOWN: usize = 16;

/// How far into its first line a message must be text to be written as text.
const FIRST_LINE: usize = 256;

/// What the trace makes of some bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    /// Text, a SIP message or something that starts like one: written whole, through
    /// [`printable`].
    Text,
    /// Not text: one line saying what it is.
    Summary(String),
}

/// What `bytes` are, for the trace. `diagnostic` shows the leading octets of binary that is
/// neither STUN nor a keep-alive in hex; otherwise they are withheld, since nothing guarantees an
/// identifier in them was found.
pub(crate) fn shape(bytes: &[u8], diagnostic: bool) -> Shape {
    if bytes.is_empty() {
        return Shape::Summary("empty".to_owned());
    }
    if bytes.iter().all(|byte| matches!(byte, b'\r' | b'\n')) {
        return Shape::Summary(keep_alive(bytes).to_owned());
    }
    if let Some(stun) = stun(bytes) {
        return Shape::Summary(stun);
    }
    if starts_as_text(bytes) {
        return Shape::Text;
    }
    Shape::Summary(binary(bytes, diagnostic))
}

/// RFC 5626 §3.5.1: a ping is a double CRLF, its pong a single one.
fn keep_alive(bytes: &[u8]) -> &'static str {
    match bytes {
        b"\r\n\r\n" => "a keep-alive ping (CRLF CRLF)",
        b"\r\n" => "a keep-alive pong (CRLF)",
        _ => "line ends only, as a keep-alive sends",
    }
}

/// A STUN message (RFC 8489 §5: the two top bits zero and the magic cookie) named by method and
/// class, with its transaction id in hex.
fn stun(bytes: &[u8]) -> Option<String> {
    let header: &[u8; STUN_HEADER] = bytes.get(..STUN_HEADER)?.try_into().ok()?;
    let [high, low, _, _, a, b, c, d, transaction @ ..] = *header;
    if high & 0xc0 != 0 || [a, b, c, d] != MAGIC_COOKIE {
        return None;
    }
    let kind = u16::from_be_bytes([high, low]);
    let class = match ((kind >> 7) & 0b10) | ((kind >> 4) & 0b01) {
        0 => "Request",
        1 => "Indication",
        2 => "Success Response",
        _ => "Error Response",
    };
    let number = (kind & 0x000f) | ((kind >> 1) & 0x0070) | ((kind >> 2) & 0x0f80);
    // RFC 8489 §18.2 and RFC 8656 §17
    let method = match number {
        0x001 => "Binding".to_owned(),
        0x003 => "Allocate".to_owned(),
        0x004 => "Refresh".to_owned(),
        0x006 => "Send".to_owned(),
        0x007 => "Data".to_owned(),
        0x008 => "CreatePermission".to_owned(),
        0x009 => "ChannelBind".to_owned(),
        other => format!("method 0x{other:03x}"),
    };
    let mut line = format!("a STUN {method} {class}, transaction ");
    for byte in transaction {
        let _ = write!(line, "{byte:02x}");
    }
    Some(line)
}

/// Whether `bytes` start as a SIP message does, past any leading line ends (RFC 3261 §7.5): a
/// visible ASCII character, then a first line with no control character in it.
fn starts_as_text(bytes: &[u8]) -> bool {
    let rest = bytes
        .iter()
        .position(|byte| !matches!(byte, b'\r' | b'\n'))
        .and_then(|start| bytes.get(start..))
        .unwrap_or_default();
    let line = rest.split(|byte| *byte == b'\n').next().unwrap_or_default();
    rest.first().is_some_and(u8::is_ascii_graphic)
        && line
            .iter()
            .take(FIRST_LINE)
            .all(|byte| matches!(byte, b'\t' | b'\r') || (*byte >= 0x20 && *byte != 0x7f))
}

/// Binary that is not STUN: RTP, RTCP or DTLS when the first octet says so (RFC 7983 §7, and
/// RFC 5761 §4 for RTCP), and the leading octets in hex when `diagnostic`.
fn binary(bytes: &[u8], diagnostic: bool) -> String {
    let first = bytes.first().copied().unwrap_or_default();
    let second = bytes.get(1).copied().unwrap_or_default();
    let what = match first {
        20..=63 if second == 0xfe && bytes.len() >= 13 => {
            format!("not SIP: DTLS, content type {first}")
        }
        128..=191 if (192..=223).contains(&second) && bytes.len() >= 8 => {
            format!("not SIP: RTCP, packet type {second}")
        }
        128..=191 if bytes.len() >= 12 => {
            format!("not SIP: RTP, payload type {}", second & 0x7f)
        }
        _ => "not SIP and not text".to_owned(),
    };
    if diagnostic {
        let mut line = format!("{what}, starting");
        for byte in bytes.iter().take(SHOWN) {
            let _ = write!(line, " {byte:02x}");
        }
        if bytes.len() > SHOWN {
            line.push_str(" ...");
        }
        line
    } else if what.starts_with("not SIP and") {
        format!("{what}, withheld")
    } else {
        what
    }
}

/// Whether `bytes` are text as the trace writes it: UTF-8 with no control character but tab and
/// line ends, and no carriage return outside a CRLF.
pub(crate) fn is_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| printable(text.as_bytes()) == text)
}

/// `bytes` as text: what is UTF-8 and no control character stays, as do tab, line feed and a
/// carriage return before one; every other octet is written `\xNN`, so a log stays text whatever
/// a message carried.
pub(crate) fn printable(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        for (at, c) in valid.char_indices() {
            let kept = match c {
                '\t' | '\n' => true,
                '\r' => valid
                    .get(at + 1..)
                    .is_some_and(|rest| rest.starts_with('\n')),
                other => !other.is_control(),
            };
            if kept {
                out.push(c);
            } else {
                let mut octets = [0; 4];
                for byte in c.encode_utf8(&mut octets).as_bytes() {
                    let _ = write!(out, "\\x{byte:02x}");
                }
            }
        }
        for byte in chunk.invalid() {
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
    out
}

/// One WebSocket frame (RFC 6455 §5.2), as the trace writes it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    /// A text, binary or continuation frame's payload, unmasked (§5.3).
    Data(Vec<u8>),
    /// A control frame, named in one line.
    Control(String),
}

/// `bytes` read as exactly one WebSocket frame, or `None` when they are not one. An opening
/// handshake is not: the first octet of an HTTP method sets a reserved bit.
pub(crate) fn websocket_frame(bytes: &[u8]) -> Option<Frame> {
    let (&first, rest) = bytes.split_first()?;
    let (&second, rest) = rest.split_first()?;
    if first & 0x70 != 0 {
        return None;
    }
    let (len, rest) = match second & 0x7f {
        126 => {
            let (len, rest) = rest.split_at_checked(2)?;
            (usize::from(u16::from_be_bytes(len.try_into().ok()?)), rest)
        }
        127 => {
            let (len, rest) = rest.split_at_checked(8)?;
            (
                usize::try_from(u64::from_be_bytes(len.try_into().ok()?)).ok()?,
                rest,
            )
        }
        short => (usize::from(short), rest),
    };
    let (mask, payload) = if second & 0x80 == 0 {
        (None, rest)
    } else {
        let (mask, payload) = rest.split_at_checked(4)?;
        (Some(mask), payload)
    };
    if payload.len() != len {
        return None;
    }
    let open = || -> Vec<u8> {
        mask.map_or_else(
            || payload.to_vec(),
            |mask| {
                payload
                    .iter()
                    .zip(mask.iter().cycle())
                    .map(|(byte, key)| byte ^ key)
                    .collect()
            },
        )
    };
    match first & 0x0f {
        0x0..=0x2 => Some(Frame::Data(open())),
        0x8 => Some(Frame::Control(close_line(match open().get(..2) {
            Some(&[high, low]) => Some(u16::from_be_bytes([high, low])),
            _ => None,
        }))),
        0x9 => Some(Frame::Control("a WebSocket ping".to_owned())),
        0xa => Some(Frame::Control("a WebSocket pong".to_owned())),
        _ => None,
    }
}

/// The line for a WebSocket close, with its status code (RFC 6455 §7.4) when it carried one.
pub(crate) fn close_line(code: Option<u16>) -> String {
    code.map_or_else(
        || "a WebSocket close".to_owned(),
        |code| format!("a WebSocket close, status {code}"),
    )
}

/// Where the body of a message starts: after the first empty line, CRLF or bare LF.
pub(crate) fn body_start(bytes: &[u8]) -> Option<usize> {
    let crlf = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4);
    let lf = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|at| at + 2);
    match (crlf, lf) {
        (Some(crlf), Some(lf)) => Some(crlf.min(lf)),
        (one, other) => one.or(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, Shape, body_start, is_text, printable, shape, websocket_frame};

    #[test]
    fn a_websocket_frame_is_read_whole_and_anything_else_is_not_one() {
        // RFC 6455 §5.7: "Hello", unmasked and masked
        let hello = Frame::Data(b"Hello".to_vec());
        assert_eq!(
            websocket_frame(&[0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]),
            Some(Frame::Data(b"Hello".to_vec()))
        );
        assert_eq!(
            websocket_frame(&[
                0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
            ]),
            Some(hello)
        );
        let mut long = vec![0x82, 0xfe, 0x01, 0x00, 0, 0, 0, 0];
        long.extend_from_slice(&[0xab; 256]);
        assert_eq!(websocket_frame(&long), Some(Frame::Data(vec![0xab; 256])));
        assert_eq!(
            websocket_frame(&[0x88, 0x82, 0, 0, 0, 0, 0x03, 0xe8]),
            Some(Frame::Control("a WebSocket close, status 1000".to_owned()))
        );
        assert_eq!(
            websocket_frame(&[0x89, 0x80, 1, 2, 3, 4]),
            Some(Frame::Control("a WebSocket ping".to_owned()))
        );
        assert_eq!(websocket_frame(b"GET /ws HTTP/1.1\r\n\r\n"), None);
        assert_eq!(websocket_frame(&[0x81, 0x05, 0x48]), None, "cut short");
        assert_eq!(websocket_frame(&[0x83, 0x00]), None, "a reserved opcode");
    }

    #[test]
    fn text_stays_and_only_what_is_not_text_is_escaped() {
        assert_eq!(printable(b"a\tb\r\nc\nd"), "a\tb\r\nc\nd");
        assert_eq!(printable("\u{3b1}\u{4e2d}".as_bytes()), "\u{3b1}\u{4e2d}");
        assert_eq!(printable(b"\0\x1b\x7f\r"), "\\x00\\x1b\\x7f\\x0d");
        assert_eq!(printable(b"\r\xff\n"), "\\x0d\\xff\n");
        assert_eq!(printable("\u{85}".as_bytes()), "\\xc2\\x85");
        assert!(is_text(b"INVITE sip:a@b SIP/2.0\r\n\r\n"));
        assert!(!is_text(b"a\rb") && !is_text(b"\xff") && !is_text(b"\0"));
    }

    #[test]
    fn a_message_is_text_by_its_first_line_and_nothing_else_is() {
        assert_eq!(
            shape(b"\r\nOPTIONS sip:a@b SIP/2.0\r\n\r\n", false),
            Shape::Text
        );
        assert_eq!(shape(b"SIP/2.0 200 OK\r\n\r\n\0\x01", false), Shape::Text);
        assert_ne!(shape(b"A\x01B\r\n", true), Shape::Text);
        assert_ne!(shape(b" leading space", true), Shape::Text);
        // RFC 8489 §5's type bits: an Allocate error, an unknown method's indication
        let mut allocate = vec![0x01, 0x13, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42];
        allocate.extend_from_slice(&[0xab; 12]);
        let Shape::Summary(line) = shape(&allocate, false) else {
            panic!("STUN is not text");
        };
        assert_eq!(
            line,
            "a STUN Allocate Error Response, transaction abababababababababababab"
        );
        allocate[0] = 0x3e;
        allocate[1] = 0xff;
        let Shape::Summary(line) = shape(&allocate, false) else {
            panic!("STUN is not text");
        };
        assert!(
            line.starts_with("a STUN method 0xfff Indication,"),
            "{line}"
        );
    }

    #[test]
    fn the_body_starts_after_the_first_empty_line_of_either_kind() {
        assert_eq!(body_start(b"A\r\nB: c\r\n\r\nbody"), Some(11));
        assert_eq!(body_start(b"A\nB: c\n\nbody"), Some(8));
        assert_eq!(body_start(b"A\r\nB: c\r\n"), None);
    }
}
