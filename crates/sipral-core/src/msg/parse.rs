// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Locating a SIP message in a buffer, without copying any of it.

use super::error::ParseError;
use super::message::{RawMessage, StartLine};
use super::method::{Method, StatusCode, is_token_byte};
use super::span::{HeaderSlot, ParseScratch, Span};

/// How strict to be about what arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseMode {
    /// Accept anything that can be understood. The default for received
    /// traffic: real deployments emit malformed messages daily, and a stack
    /// that rejects them loses calls a competitor completes.
    Lenient,
    /// Reject anything that does not conform. Used for our own output and for
    /// the RFC 4475 corpus.
    Strict,
}

/// Bounds that stop a hostile peer from making the parser do unbounded work.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Largest message accepted.
    pub max_message_bytes: u32,
    /// Most header fields accepted.
    pub max_headers: u16,
    /// Longest single header value accepted.
    pub max_header_value_bytes: u32,
}

impl Limits {
    /// The defaults: 64 KiB, 128 headers, 4 KiB per value.
    pub const DEFAULT: Self = Self {
        max_message_bytes: 65_535,
        max_headers: 128,
        max_header_value_bytes: 4_096,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Parse one message out of `buf`, indexing it into `scratch`.
///
/// Zero-copy: no header value is materialised, only located. Both `buf` and
/// `scratch` outlive the returned view.
///
/// # Errors
/// See [`ParseError`]. Malformed input is the normal case on a public SIP
/// port, so this never panics and never allocates beyond the index.
pub fn parse<'a>(
    buf: &'a [u8],
    scratch: &'a mut ParseScratch,
    mode: ParseMode,
) -> Result<RawMessage<'a>, ParseError> {
    parse_with_limits(buf, scratch, mode, Limits::DEFAULT)
}

/// [`parse`], with bounds of your own.
///
/// # Errors
/// See [`ParseError`].
pub fn parse_with_limits<'a>(
    buf: &'a [u8],
    scratch: &'a mut ParseScratch,
    mode: ParseMode,
    limits: Limits,
) -> Result<RawMessage<'a>, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::Empty);
    }
    let total = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    if total > limits.max_message_bytes {
        return Err(ParseError::MessageTooLarge {
            limit: limits.max_message_bytes,
        });
    }

    scratch.slots.clear();

    let (line, mut pos) = read_line(buf, 0, mode).ok_or(ParseError::BadStartLine { at: 0 })?;
    let start = parse_start_line(buf, line)?;

    let mut content_length: Option<u32> = None;

    loop {
        let (line, next) = read_line(buf, pos, mode).ok_or(ParseError::UnterminatedHeaders)?;
        pos = next;
        if line.is_empty() {
            break;
        }

        let (name, mut value) = split_header(buf, line)?;

        // RFC 3261 §7.3.1: a line starting with whitespace continues the
        // previous value. The span grows over it, interior CRLF included.
        while starts_with_ws(buf, pos) {
            let (cont, after) = read_line(buf, pos, mode).ok_or(ParseError::UnterminatedHeaders)?;
            value.end = cont.end;
            pos = after;
        }
        let value = trim(buf, value);

        if value.len() > limits.max_header_value_bytes as usize {
            return Err(ParseError::HeaderValueTooLong {
                name_at: name.start,
                limit: limits.max_header_value_bytes,
            });
        }
        if scratch.slots.len() >= limits.max_headers as usize {
            return Err(ParseError::TooManyHeaders {
                limit: limits.max_headers,
            });
        }

        if is_content_length(name.slice(buf)) {
            let declared =
                parse_u32(value.slice(buf)).ok_or(ParseError::BadHeaderLine { at: name.start })?;
            match content_length {
                Some(first) if first != declared => {
                    return Err(ParseError::ConflictingContentLength {
                        first,
                        second: declared,
                    });
                }
                _ => content_length = Some(declared),
            }
        }

        scratch.slots.push(HeaderSlot { name, value });
    }

    let body_start = off(pos);
    let available = total.saturating_sub(body_start);
    let body = match content_length {
        Some(declared) if declared > available => {
            return Err(ParseError::BodyTruncated {
                declared,
                available,
            });
        }
        // anything past the declared length is another datagram's problem
        Some(declared) => Span {
            start: body_start,
            end: body_start.saturating_add(declared),
        },
        None => Span {
            start: body_start,
            end: total,
        },
    };

    Ok(RawMessage {
        buf,
        start,
        headers: &scratch.slots,
        body,
    })
}

fn parse_start_line(buf: &[u8], line: Span) -> Result<StartLine, ParseError> {
    let at = line.start;
    let bad = ParseError::BadStartLine { at };
    let s = line.slice(buf);

    if s.starts_with(b"SIP/") {
        // SIP-Version SP 3DIGIT [SP reason]
        let rest = s.strip_prefix(b"SIP/2.0 ").ok_or(bad)?;
        let digits = rest.get(..3).ok_or(bad)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(bad);
        }
        let code = digits
            .iter()
            .fold(0_u16, |acc, &d| acc * 10 + u16::from(d - b'0'));
        let code = StatusCode::new(code).map_err(|_| bad)?;

        let reason = match rest.get(3) {
            None => Span::empty(line.end),
            Some(b' ') => Span {
                start: at.saturating_add(12),
                end: line.end,
            },
            Some(_) => return Err(bad),
        };
        return Ok(StartLine::Response { code, reason });
    }

    // Method SP Request-URI SP SIP-Version, exactly one space between each
    let first = s.iter().position(|&b| b == b' ').ok_or(bad)?;
    let last = s.iter().rposition(|&b| b == b' ').ok_or(bad)?;
    if last <= first {
        return Err(bad);
    }
    let method = s.get(..first).ok_or(bad)?;
    let uri = s.get(first + 1..last).ok_or(bad)?;
    let version = s.get(last + 1..).ok_or(bad)?;

    if version != b"SIP/2.0" {
        return Err(bad);
    }
    if Method::from_bytes(method).is_none() {
        return Err(bad);
    }
    // no whitespace inside the URI, and never a name-addr: the ABNF allows
    // only SIP-URI, SIPS-URI or absoluteURI here
    if uri.is_empty() || uri.iter().any(|&b| b == b' ' || b == b'\t') || uri.starts_with(b"<") {
        return Err(bad);
    }

    Ok(StartLine::Request {
        method: Span {
            start: at,
            end: at.saturating_add(off(first)),
        },
        uri: Span {
            start: at.saturating_add(off(first + 1)),
            end: at.saturating_add(off(last)),
        },
    })
}

/// Split `name *WSP ":" value`. Whitespace before the colon is legal.
fn split_header(buf: &[u8], line: Span) -> Result<(Span, Span), ParseError> {
    let bad = ParseError::BadHeaderLine { at: line.start };
    let s = line.slice(buf);
    let colon = s.iter().position(|&b| b == b':').ok_or(bad)?;

    let raw_name = s.get(..colon).ok_or(bad)?;
    let trimmed = raw_name.trim_ascii_end();
    if trimmed.is_empty() || !trimmed.iter().copied().all(is_token_byte) {
        return Err(bad);
    }

    Ok((
        Span {
            start: line.start,
            end: line.start.saturating_add(off(trimmed.len())),
        },
        Span {
            start: line.start.saturating_add(off(colon + 1)),
            end: line.end,
        },
    ))
}

/// The content of one line, and where the next one starts. The terminator is
/// not part of the content.
fn read_line(buf: &[u8], from: usize, mode: ParseMode) -> Option<(Span, usize)> {
    let mut i = from;
    loop {
        let b = *buf.get(i)?;
        if b == b'\n' {
            let has_cr = i > from && buf.get(i - 1) == Some(&b'\r');
            if !has_cr && mode == ParseMode::Strict {
                return None;
            }
            let end = if has_cr { i - 1 } else { i };
            return Some((
                Span {
                    start: off(from),
                    end: off(end),
                },
                i + 1,
            ));
        }
        i += 1;
    }
}

fn starts_with_ws(buf: &[u8], at: usize) -> bool {
    matches!(buf.get(at), Some(b' ' | b'\t'))
}

fn trim(buf: &[u8], span: Span) -> Span {
    let is_ws = |i: u32| matches!(buf.get(i as usize), Some(b' ' | b'\t' | b'\r' | b'\n'));
    let mut start = span.start;
    let mut end = span.end;
    while start < end && is_ws(start) {
        start += 1;
    }
    while end > start && is_ws(end.saturating_sub(1)) {
        end -= 1;
    }
    Span { start, end }
}

fn is_content_length(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"Content-Length") || name.eq_ignore_ascii_case(b"l")
}

/// Digits only. No sign, no whitespace, no overflow.
fn parse_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0_u32, |acc, &d| {
        acc.checked_mul(10)?.checked_add(u32::from(d - b'0'))
    })
}

fn off(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{Limits, ParseMode, parse, parse_with_limits};
    use crate::msg::{MessageKind, Method, ParseError, ParseScratch, StatusCode};

    fn ok<'a>(buf: &'a [u8], scratch: &'a mut ParseScratch) -> crate::msg::RawMessage<'a> {
        match parse(buf, scratch, ParseMode::Strict) {
            Ok(m) => m,
            Err(e) => panic!("expected a parse, got {e}"),
        }
    }

    fn err(buf: &[u8]) -> ParseError {
        let mut scratch = ParseScratch::new();
        match parse(buf, &mut scratch, ParseMode::Strict) {
            Ok(_) => panic!("expected a rejection"),
            Err(e) => e,
        }
    }

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8\r\n\
To: Bob <sip:bob@example.com>\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 4\r\n\
\r\n\
v=0\n";

    #[test]
    fn parses_a_request() {
        let mut scratch = ParseScratch::new();
        let m = ok(INVITE, &mut scratch);
        assert_eq!(m.kind(), MessageKind::Request(Method::Invite));
        assert_eq!(m.request_uri(), Some(&b"sip:bob@example.com"[..]));
        assert_eq!(m.status(), None);
        assert_eq!(m.header_slots().len(), 6);
        assert_eq!(m.body(), b"v=0\n");
    }

    #[test]
    fn parses_a_response_with_a_reason() {
        let mut scratch = ParseScratch::new();
        let m = ok(b"SIP/2.0 180 Ringing\r\n\r\n", &mut scratch);
        assert_eq!(m.kind(), MessageKind::Response(StatusCode::RINGING));
        assert_eq!(m.reason(), Some(&b"Ringing"[..]));
        assert_eq!(m.method(), None);
    }

    #[test]
    fn empty_reason_phrase_is_legal() {
        // RFC 4475 3.1.1.13
        let mut scratch = ParseScratch::new();
        let m = ok(b"SIP/2.0 200 \r\n\r\n", &mut scratch);
        assert_eq!(m.status(), Some(StatusCode::OK));
        assert_eq!(m.reason(), Some(&b""[..]));
    }

    #[test]
    fn header_values_are_trimmed_and_whitespace_before_the_colon_is_allowed() {
        let mut scratch = ParseScratch::new();
        let m = ok(b"SIP/2.0 200 OK\r\nTO :  sip:a@b \r\n\r\n", &mut scratch);
        let (name, value) = m.raw_headers().next().unwrap_or((b"", b""));
        assert_eq!(name, b"TO");
        assert_eq!(value, b"sip:a@b");
    }

    #[test]
    fn folded_values_stay_one_header() {
        // RFC 4475 3.1.1.1 folds several header fields
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\nSubject: one\r\n two\r\n\tthree\r\n\r\n",
            &mut scratch,
        );
        assert_eq!(m.header_slots().len(), 1);
        let (_, value) = m.raw_headers().next().unwrap_or((b"", b""));
        assert_eq!(value, b"one\r\n two\r\n\tthree");
    }

    #[test]
    fn repeated_headers_are_separate_slots_in_wire_order() {
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\nVia: first\r\nVia: second\r\n\r\n",
            &mut scratch,
        );
        let vias: Vec<_> = m.raw_header_values(b"Via").collect();
        assert_eq!(vias, vec![&b"first"[..], &b"second"[..]]);
    }

    #[test]
    fn content_length_delimits_the_body_and_trailing_octets_are_ignored() {
        // RFC 4475 3.1.1.8: a second request appended to the datagram
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\nContent-Length: 3\r\n\r\nabcJUNKJUNK",
            &mut scratch,
        );
        assert_eq!(m.body(), b"abc");
    }

    #[test]
    fn compact_content_length_frames_the_body_too() {
        let mut scratch = ParseScratch::new();
        let m = ok(b"SIP/2.0 200 OK\r\nl: 2\r\n\r\nhi!!!", &mut scratch);
        assert_eq!(m.body(), b"hi");
    }

    #[test]
    fn without_content_length_the_body_is_the_rest() {
        let mut scratch = ParseScratch::new();
        let m = ok(b"SIP/2.0 200 OK\r\n\r\nwhatever", &mut scratch);
        assert_eq!(m.body(), b"whatever");
    }

    #[test]
    fn content_length_larger_than_the_message_is_refused() {
        // RFC 4475 3.1.2.2
        assert_eq!(
            err(b"SIP/2.0 200 OK\r\nContent-Length: 900\r\n\r\nshort"),
            ParseError::BodyTruncated {
                declared: 900,
                available: 5
            }
        );
    }

    #[test]
    fn negative_content_length_is_refused() {
        // RFC 4475 3.1.2.3
        assert!(matches!(
            err(b"SIP/2.0 200 OK\r\nContent-Length: -999\r\n\r\n"),
            ParseError::BadHeaderLine { .. }
        ));
    }

    #[test]
    fn overlarge_content_length_is_refused_rather_than_wrapped() {
        // RFC 4475 3.1.2.4
        assert!(matches!(
            err(b"SIP/2.0 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n"),
            ParseError::BadHeaderLine { .. }
        ));
    }

    #[test]
    fn contradictory_content_lengths_are_refused() {
        // RFC 4475 3.3.9
        assert_eq!(
            err(b"SIP/2.0 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"),
            ParseError::ConflictingContentLength {
                first: 1,
                second: 2
            }
        );
    }

    #[test]
    fn overlarge_status_code_is_refused() {
        // RFC 4475 3.1.2.19
        assert!(matches!(
            err(b"SIP/2.0 4294967296 Better Luck Next Time\r\n\r\n"),
            ParseError::BadStartLine { .. }
        ));
    }

    #[test]
    fn unknown_protocol_version_is_refused() {
        // RFC 4475 3.1.2.16
        assert!(matches!(
            err(b"OPTIONS sip:t@example.com SIP/7.0\r\n\r\n"),
            ParseError::BadStartLine { .. }
        ));
    }

    #[test]
    fn multiple_spaces_in_the_request_line_are_refused() {
        // RFC 4475 3.1.2.9
        assert!(matches!(
            err(b"INVITE  sip:a@b  SIP/2.0\r\n\r\n"),
            ParseError::BadStartLine { .. }
        ));
    }

    #[test]
    fn trailing_space_in_the_request_line_is_refused() {
        // RFC 4475 3.1.2.10
        assert!(matches!(
            err(b"INVITE sip:a@b SIP/2.0 \r\n\r\n"),
            ParseError::BadStartLine { .. }
        ));
    }

    #[test]
    fn angle_bracketed_request_uri_is_refused() {
        // RFC 4475 3.1.2.7
        assert!(matches!(
            err(b"INVITE <sip:a@b> SIP/2.0\r\n\r\n"),
            ParseError::BadStartLine { .. }
        ));
    }

    #[test]
    fn a_header_line_without_a_colon_is_refused() {
        assert!(matches!(
            err(b"SIP/2.0 200 OK\r\nFoobar roobar\r\n\r\n"),
            ParseError::BadHeaderLine { .. }
        ));
    }

    #[test]
    fn a_non_token_header_name_is_refused() {
        assert!(matches!(
            err(b"SIP/2.0 200 OK\r\nBad Name: x\r\n\r\n"),
            ParseError::BadHeaderLine { .. }
        ));
    }

    #[test]
    fn headers_that_never_end_are_refused() {
        assert_eq!(
            err(b"SIP/2.0 200 OK\r\nVia: x\r\n"),
            ParseError::UnterminatedHeaders
        );
    }

    #[test]
    fn empty_input_is_refused() {
        assert_eq!(err(b""), ParseError::Empty);
    }

    #[test]
    fn bare_lf_is_accepted_only_when_lenient() {
        let mut scratch = ParseScratch::new();
        let buf = b"SIP/2.0 200 OK\nVia: x\n\n";
        assert!(parse(buf, &mut scratch, ParseMode::Strict).is_err());
        let mut scratch = ParseScratch::new();
        assert!(parse(buf, &mut scratch, ParseMode::Lenient).is_ok());
    }

    #[test]
    fn limits_are_enforced() {
        let mut scratch = ParseScratch::new();
        let small = Limits {
            max_message_bytes: 8,
            ..Limits::DEFAULT
        };
        assert_eq!(
            parse_with_limits(INVITE, &mut scratch, ParseMode::Strict, small).err(),
            Some(ParseError::MessageTooLarge { limit: 8 })
        );

        let mut scratch = ParseScratch::new();
        let few = Limits {
            max_headers: 2,
            ..Limits::DEFAULT
        };
        assert_eq!(
            parse_with_limits(INVITE, &mut scratch, ParseMode::Strict, few).err(),
            Some(ParseError::TooManyHeaders { limit: 2 })
        );

        let mut scratch = ParseScratch::new();
        let narrow = Limits {
            max_header_value_bytes: 4,
            ..Limits::DEFAULT
        };
        assert!(matches!(
            parse_with_limits(INVITE, &mut scratch, ParseMode::Strict, narrow),
            Err(ParseError::HeaderValueTooLong { .. })
        ));
    }

    #[test]
    fn the_scratch_is_reusable_across_messages() {
        let mut scratch = ParseScratch::new();
        {
            let m = ok(INVITE, &mut scratch);
            assert_eq!(m.header_slots().len(), 6);
        }
        let m = ok(b"SIP/2.0 200 OK\r\nVia: x\r\n\r\n", &mut scratch);
        assert_eq!(m.header_slots().len(), 1);
    }

    #[test]
    fn nothing_makes_the_parser_panic() {
        // every byte pattern is either parsed or refused, never a panic
        let mut scratch = ParseScratch::new();
        for len in 0..24_usize {
            for seed in 0..64_u8 {
                let buf: Vec<u8> = (0..len)
                    .map(|i| {
                        seed.wrapping_mul(31)
                            .wrapping_add(u8::try_from(i).unwrap_or(0))
                    })
                    .collect();
                let _ = parse(&buf, &mut scratch, ParseMode::Lenient);
                let _ = parse(&buf, &mut scratch, ParseMode::Strict);
            }
        }
    }
}
