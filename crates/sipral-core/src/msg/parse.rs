// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Locating a SIP message in a buffer, without copying any of it.

use super::error::ParseError;
use super::header::HeaderName;
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
///
/// A message past one of them is not silently lost: the endpoint answers a
/// request it can still address with 400 or 513, and counts what it cannot
/// (`docs/03-core-signalling.md`, "Limits, and what a refused message gets").
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
    /// The defaults: 64 KiB, 128 headers, 16 KiB per value.
    ///
    /// The message bound is the largest UDP payload there is, so no datagram
    /// is refused for its size alone and a stream carries nothing a datagram
    /// could not. The value bound is sized against the longest fields real
    /// traffic carries on one line, not against a typical call: an RFC 8224
    /// `Identity` carrying a full PASSporT with rich call data (RFC 9795),
    /// icons and a jCard inline, runs to several kilobytes; a `History-Info`
    /// (RFC 7044) that has been through a few dozen retargets, each entry
    /// with its escaped `Reason`, comes to about as much; and a display name
    /// is whatever the caller's switch put there. Sixteen kilobytes holds
    /// each of those with room to spare while still being a quarter of the
    /// message, so one field cannot claim all of it. Every value is a span
    /// into the message buffer rather than a copy, so this bound costs no
    /// memory of its own; what it limits is how much of one message any
    /// single field's reader has to walk.
    pub const DEFAULT: Self = Self {
        max_message_bytes: 65_535,
        max_headers: 128,
        max_header_value_bytes: 16_384,
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
    if holds_a_lone_cr(buf, line) {
        return Err(ParseError::BadStartLine { at: 0 });
    }
    let start = parse_start_line(buf, line)?;

    let mut content_length: Option<u32> = None;

    loop {
        let (line, next) = read_line(buf, pos, mode).ok_or(ParseError::UnterminatedHeaders)?;
        pos = next;
        if line.is_empty() {
            break;
        }
        let bad_line = ParseError::BadHeaderLine { at: line.start };
        if holds_a_lone_cr(buf, line) {
            return Err(bad_line);
        }

        let (name, mut value) = split_header(buf, line)?;

        // RFC 3261 §7.3.1: a line starting with whitespace continues the
        // previous value. The span grows over it, interior CRLF included.
        while starts_with_ws(buf, pos) {
            let (cont, after) = read_line(buf, pos, mode).ok_or(ParseError::UnterminatedHeaders)?;
            if holds_a_lone_cr(buf, cont) {
                return Err(bad_line);
            }
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

/// What a request the parser refused still says about where an answer goes:
/// its request line and the five fields every response copies from it —
/// `Via`, `From`, `To`, `Call-ID` and `CSeq` (RFC 3261 §8.2.6.2) — and
/// nothing else.
///
/// For a message [`parse_with_limits`] refused, so that the refusal can be
/// answered rather than left for the client to retransmit into until its
/// timer gives up (§8.2: a UAS answers what it cannot process; §21.4.1 and
/// §21.5.14 say with what). Every other field is passed over unread, which is
/// what makes the answer possible when the one past a bound is one nobody
/// needs to answer; a field the answer does copy is kept whole whatever its
/// length, because an answer that changed it would answer nobody.
///
/// Bounded like the parser is: one pass over `buf`, no allocation beyond the
/// index in `scratch`, and at most `max_fields` of the five kept. Returns
/// `None` when `buf` does not start with a request line, and when more than
/// `max_fields` of them are there, since an answer missing a `Via` would be
/// routed to the wrong place. A field whose line holds a CR that ends no line
/// is left out rather than copied, for the reason [`parse_with_limits`]
/// refuses one: no header line can be written with it. A `Via` like that is
/// `None` for the same reason as a missing one: the `Via` below it would
/// route the answer. Headers that never end are read as far as they go.
///
/// A field kept whole is kept past every bound, and that includes the `Via`
/// an answer is routed by: whoever answers from this decides whether a top
/// `Via` longer than [`Limits::max_header_value_bytes`] gets a say in where
/// the answer goes (the endpoint's answer does not).
#[must_use]
pub fn salvage_request<'a>(
    buf: &'a [u8],
    scratch: &'a mut ParseScratch,
    max_fields: u16,
) -> Option<RawMessage<'a>> {
    scratch.slots.clear();
    let (line, mut pos) = read_line(buf, 0, ParseMode::Lenient)?;
    if holds_a_lone_cr(buf, line) {
        return None;
    }
    let start = parse_start_line(buf, line).ok()?;
    if !matches!(start, StartLine::Request { .. }) {
        return None;
    }

    while let Some((line, next)) = read_line(buf, pos, ParseMode::Lenient) {
        pos = next;
        if line.is_empty() {
            break;
        }
        let mut end = line.end;
        let mut writable = !holds_a_lone_cr(buf, line);
        let mut whole = true;
        while starts_with_ws(buf, pos) {
            let Some((cont, after)) = read_line(buf, pos, ParseMode::Lenient) else {
                whole = false;
                break;
            };
            writable &= !holds_a_lone_cr(buf, cont);
            end = cont.end;
            pos = after;
        }
        if !whole {
            break;
        }
        let Ok((name, value)) = split_header(buf, line) else {
            continue;
        };
        let field = HeaderName::from_bytes(name.slice(buf));
        let copied = field.is_some_and(|field| {
            matches!(
                field,
                HeaderName::Via
                    | HeaderName::From
                    | HeaderName::To
                    | HeaderName::CallId
                    | HeaderName::CSeq
            )
        });
        if !copied {
            continue;
        }
        if !writable {
            // a `Via` left out moves the one below it to the top, and the
            // answer would go where that hop's `Via` says instead
            if field == Some(HeaderName::Via) {
                return None;
            }
            continue;
        }
        if scratch.slots.len() >= usize::from(max_fields) {
            return None;
        }
        scratch.slots.push(HeaderSlot {
            name,
            value: trim(
                buf,
                Span {
                    start: value.start,
                    end,
                },
            ),
        });
    }

    Some(RawMessage {
        buf,
        start,
        headers: &scratch.slots,
        body: Span::empty(off(pos)),
    })
}

/// Where a message's head ends and how long its body says it is, read the
/// way [`parse_with_limits`] reads them, for a message that was refused for
/// something else.
///
/// A stream is framed on nothing else (§18.3), so this is what decides
/// whether a refused message can be passed over and the connection read on,
/// or whether the framing is lost with it.
///
/// # Errors
/// [`ParseError::UnterminatedHeaders`] while the head has not ended,
/// [`ParseError::MissingContentLength`] when it names no length,
/// [`ParseError::ConflictingContentLength`] when it names two, and
/// [`ParseError::BadHeaderLine`] when the length it names is not a number.
pub(crate) fn declared_length(buf: &[u8]) -> Result<(usize, u32), ParseError> {
    let (_, mut pos) =
        read_line(buf, 0, ParseMode::Lenient).ok_or(ParseError::UnterminatedHeaders)?;
    let mut declared: Option<u32> = None;
    loop {
        let (line, next) =
            read_line(buf, pos, ParseMode::Lenient).ok_or(ParseError::UnterminatedHeaders)?;
        pos = next;
        if line.is_empty() {
            break;
        }
        let mut value_end = line.end;
        while starts_with_ws(buf, pos) {
            let (cont, after) =
                read_line(buf, pos, ParseMode::Lenient).ok_or(ParseError::UnterminatedHeaders)?;
            value_end = cont.end;
            pos = after;
        }
        let Ok((name, value)) = split_header(buf, line) else {
            continue;
        };
        if !is_content_length(name.slice(buf)) {
            continue;
        }
        let value = trim(
            buf,
            Span {
                start: value.start,
                end: value_end,
            },
        );
        let length =
            parse_u32(value.slice(buf)).ok_or(ParseError::BadHeaderLine { at: name.start })?;
        match declared {
            Some(first) if first != length => {
                return Err(ParseError::ConflictingContentLength {
                    first,
                    second: length,
                });
            }
            _ => declared = Some(length),
        }
    }
    let declared = declared.ok_or(ParseError::MissingContentLength)?;
    Ok((pos, declared))
}

/// How long the value of the field whose name starts at `name_at` is, folds
/// included and surrounding whitespace not: the number
/// [`ParseError::HeaderValueTooLong`] measured against its bound.
#[must_use]
pub(crate) fn field_value_len(buf: &[u8], name_at: u32) -> Option<usize> {
    let (line, mut pos) = read_line(buf, name_at as usize, ParseMode::Lenient)?;
    let (_, value) = split_header(buf, line).ok()?;
    let mut end = value.end;
    while starts_with_ws(buf, pos) {
        let (cont, after) = read_line(buf, pos, ParseMode::Lenient)?;
        end = cont.end;
        pos = after;
    }
    Some(
        trim(
            buf,
            Span {
                start: value.start,
                end,
            },
        )
        .len(),
    )
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

/// Whether a line, terminator already cut off, still holds a CR.
///
/// RFC 3261 §25.1 has a CR in the head of a message only as half of a CRLF,
/// which ends a line or begins a fold, and `quoted-pair` leaves %x0D out, so
/// one anywhere else has no reading in either mode. It is refused rather than
/// kept because it could never be written back: every response copies `Via`,
/// `From`, `To`, `Call-ID` and `CSeq`, and a header line cannot hold the byte,
/// so a request carrying one would sit unanswered for good.
fn holds_a_lone_cr(buf: &[u8], line: Span) -> bool {
    line.slice(buf).contains(&b'\r')
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
        assert_eq!(m.request_uri_bytes(), Some(&b"sip:bob@example.com"[..]));
        let uri = m.request_uri().expect("a request").expect("a URI");
        assert_eq!(uri.sip().and_then(|s| s.user), Some("bob"));
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
    fn a_cr_that_ends_no_line_and_begins_no_fold_is_refused() {
        // §25.1: a CR in the head of a message is half of a CRLF, which ends a
        // line or begins a fold, and `quoted-pair` leaves %x0D out, so a lone
        // one has no reading. Taken in anyway, it is a message nobody can
        // answer: every response copies Via, From, To, Call-ID and CSeq, and
        // no header line can be written with that byte in it
        let mut accepted: Vec<String> = Vec::new();
        for message in [
            &b"INVITE sip:bob@example.com SIP/2.0\r\nFrom: <sip:a@example.com>;x=a\rb;tag=1\r\n\r\n"[..],
            b"INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: a\rb\r\n\r\n",
            b"INVITE sip:bob@example.com SIP/2.0\r\nSubject: one\r\n two\rthree\r\n\r\n",
            b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP h\r\r\n\r\n",
            b"INVITE sip:bob\r@example.com SIP/2.0\r\n\r\n",
        ] {
            for mode in [ParseMode::Strict, ParseMode::Lenient] {
                let mut scratch = ParseScratch::new();
                match parse(message, &mut scratch, mode) {
                    Err(ParseError::BadStartLine { .. } | ParseError::BadHeaderLine { .. }) => (),
                    other => accepted.push(format!(
                        "{mode:?} {:?}: {:?}",
                        String::from_utf8_lossy(message),
                        other.map(|m| m.len())
                    )),
                }
            }
        }
        assert!(accepted.is_empty(), "not refused: {accepted:#?}");
    }

    #[test]
    fn repeated_headers_are_separate_slots_in_wire_order() {
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\nVia: first\r\nVia: second\r\n\r\n",
            &mut scratch,
        );
        let vias: Vec<_> = m.header_values(crate::msg::HeaderName::Via).collect();
        assert_eq!(vias, vec![&b"first"[..], &b"second"[..]]);
    }

    #[test]
    fn a_field_is_found_whichever_form_it_was_written_in() {
        use crate::msg::HeaderName;
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\nv: SIP/2.0/UDP a\r\nVia: SIP/2.0/TCP b\r\ni: abc\r\n\r\n",
            &mut scratch,
        );
        assert_eq!(m.header_count(HeaderName::Via), 2);
        assert_eq!(m.header(HeaderName::Via), Some(&b"SIP/2.0/UDP a"[..]));
        assert_eq!(m.header(HeaderName::CallId), Some(&b"abc"[..]));
        assert_eq!(m.header(HeaderName::CSeq), None);
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
    fn a_from_carrying_thousands_of_bytes_of_display_name_is_read() {
        // the headless audit's INVITEs: display names of 6000 and 9000 bytes
        // drew no answer at all, because the one field was past the bound on a
        // single value and the whole request was refused
        for length in [6_000, 9_000] {
            let message = format!(
                "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: \"{}\" <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n",
                "a".repeat(length)
            );
            let mut scratch = ParseScratch::new();
            let parsed = parse(message.as_bytes(), &mut scratch, ParseMode::Lenient);
            assert!(parsed.is_ok(), "{length}: {:?}", parsed.err());
        }
    }

    #[test]
    fn a_refused_request_is_salvaged_down_to_what_an_answer_copies() {
        use super::salvage_request;
        use crate::msg::{HeaderError, HeaderName};
        let request = b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
v: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n\
Via: SIP/2.0/UDP 192.0.2.2;branch=z9hG4bK2\r\n\
not a header line\r\n\
f: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Subject: kept out\r\n\
Call-ID: one\rtwo\r\n\
CSeq: 1\r\n OPTIONS\r\n\
\r\n";
        let mut scratch = ParseScratch::new();
        let salvaged = salvage_request(request, &mut scratch, 16).expect("a request line");
        assert_eq!(salvaged.method(), Some(Method::Options));
        assert_eq!(salvaged.header_count(HeaderName::Via), 2);
        assert_eq!(salvaged.header_count(HeaderName::Subject), 0);
        assert!(salvaged.from().is_ok());
        assert!(salvaged.to().is_ok());
        assert_eq!(salvaged.cseq().map(|c| c.seq), Ok(1), "a fold is followed");
        assert_eq!(
            salvaged.call_id(),
            Err(HeaderError::Missing),
            "a lone CR could never be written back"
        );

        let mut scratch = ParseScratch::new();
        assert!(
            salvage_request(request, &mut scratch, 2).is_none(),
            "an answer missing a Via would go to the wrong place"
        );
        let mut scratch = ParseScratch::new();
        assert!(salvage_request(b"SIP/2.0 200 OK\r\nVia: x\r\n\r\n", &mut scratch, 16).is_none());
    }

    #[test]
    fn the_scalar_accessors_read_the_message() {
        use crate::msg::{HeaderError, HeaderName};
        let mut scratch = ParseScratch::new();
        let m = ok(INVITE, &mut scratch);
        assert_eq!(m.call_id(), Ok(&b"a84b4c76e66710"[..]));
        let c = m.cseq().expect("a CSeq");
        assert_eq!((c.seq, c.method), (314_159, Method::Invite));
        assert_eq!(
            m.content_length().and_then(crate::msg::Digits::require),
            Ok(4)
        );
        assert_eq!(m.max_forwards(), Err(HeaderError::Missing));
        assert_eq!(m.header_count(HeaderName::CSeq), 1);
    }

    #[test]
    fn the_address_accessors_read_the_message() {
        let mut scratch = ParseScratch::new();
        let m = ok(INVITE, &mut scratch);
        let from = m.from().expect("a From");
        assert_eq!(from.display_name().as_deref(), Some(&b"Alice"[..]));
        assert_eq!(from.tag().as_deref(), Some(&b"1928301774"[..]));
        assert_eq!(from.uri_bytes(), b"sip:alice@example.com");
        let to = m.to().expect("a To");
        assert_eq!(to.display_name().as_deref(), Some(&b"Bob"[..]));
        assert_eq!(to.tag(), None);
    }

    #[test]
    fn a_from_or_to_tag_that_is_not_a_token_is_a_malformed_field() {
        use crate::msg::HeaderError;
        const PLAIN_FROM: &str = "<sip:alice@example.com>;tag=a1";
        const PLAIN_TO: &str = "<sip:bob@example.com>";
        // §25.1: tag-param = "tag" EQUAL token. Whatever tag these accessors
        // hand out is written back after ";tag=" by the dialog, so a value that
        // is not a token there is a parameter or an address the peer added
        let message = |from: &str, to: &str| {
            format!("OPTIONS sip:bob@example.com SIP/2.0\r\nFrom: {from}\r\nTo: {to}\r\n\r\n")
                .into_bytes()
        };
        let mut accepted: Vec<String> = Vec::new();
        for param in [
            ";tag=\"a1;maddr=198.51.100.66\"",
            ";tag=a1, <sip:mallory@example.net>",
            ";tag=\"\"",
            ";tag=\"a1\\\"b\"",
            // no value at all is not a token either
            ";tag",
        ] {
            let from = format!("<sip:alice@example.com>{param}");
            let bytes = message(&from, PLAIN_TO);
            let mut scratch = ParseScratch::new();
            if !matches!(
                ok(&bytes, &mut scratch).from(),
                Err(HeaderError::Malformed(_))
            ) {
                accepted.push(format!("From: {from}"));
            }

            let to = format!("<sip:bob@example.com>{param}");
            let bytes = message(PLAIN_FROM, &to);
            let mut scratch = ParseScratch::new();
            if !matches!(
                ok(&bytes, &mut scratch).to(),
                Err(HeaderError::Malformed(_))
            ) {
                accepted.push(format!("To: {to}"));
            }
        }
        assert!(accepted.is_empty(), "read as a tag: {accepted:#?}");

        // while a token in quotes, which is not the grammar but reads as one
        // value, is still the token it holds
        let bytes = message("<sip:alice@example.com>;tag=\"a1\"", PLAIN_TO);
        let mut scratch = ParseScratch::new();
        assert_eq!(
            ok(&bytes, &mut scratch)
                .from()
                .expect("a From")
                .tag()
                .as_deref(),
            Some(&b"a1"[..])
        );
    }

    #[test]
    fn contact_values_come_from_every_line_and_every_comma() {
        use crate::msg::Contacts;
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"REGISTER sip:example.com SIP/2.0\r\n\
Contact: \"Mr. Watson\" <sip:watson@worcester.example.com>;q=0.7;expires=3600\r\n\
m: <sip:watson@example.net>;q=0.1, <sip:watson@example.org>\r\n\
\r\n",
            &mut scratch,
        );
        let Ok(Contacts::Addrs(addrs)) = m.contact() else {
            panic!("expected a list of contacts");
        };
        let hosts: Vec<_> = addrs
            .filter_map(Result::ok)
            .map(|a| a.uri_bytes().to_vec())
            .collect();
        assert_eq!(
            hosts,
            vec![
                b"sip:watson@worcester.example.com".to_vec(),
                b"sip:watson@example.net".to_vec(),
                b"sip:watson@example.org".to_vec(),
            ]
        );
    }

    #[test]
    fn the_contact_wildcard_is_the_whole_field_or_nothing() {
        use crate::msg::{Contacts, HeaderError};
        let mut scratch = ParseScratch::new();
        assert!(matches!(
            ok(
                b"REGISTER sip:example.com SIP/2.0\r\nContact: *\r\nExpires: 0\r\n\r\n",
                &mut scratch,
            )
            .contact(),
            Ok(Contacts::Star)
        ));

        let mut scratch = ParseScratch::new();
        // RFC 3261 25.1: the grammar offers STAR or the list, never both
        assert!(matches!(
            ok(
                b"REGISTER sip:example.com SIP/2.0\r\nContact: *\r\nContact: <sip:a@b.example>\r\n\r\n",
                &mut scratch,
            )
            .contact(),
            Err(HeaderError::Malformed(_))
        ));
    }

    #[test]
    fn a_message_with_no_contact_has_no_contacts_rather_than_an_error() {
        use crate::msg::Contacts;
        let mut scratch = ParseScratch::new();
        let m = ok(INVITE, &mut scratch);
        let Ok(Contacts::Addrs(addrs)) = m.contact() else {
            panic!("expected a list of contacts");
        };
        assert_eq!(addrs.count(), 0);
    }

    #[test]
    fn validation_is_the_question_a_uas_asks_before_answering() {
        let mut scratch = ParseScratch::new();
        assert_eq!(ok(INVITE, &mut scratch).validate(), Ok(()));

        let cases: [(&[u8], &str); 5] = [
            // RFC 4475 3.1.2.17: CSeq names a different method
            (
                b"INVITE sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\n\
Call-ID: c\r\nCSeq: 8 OPTIONS\r\n\r\n",
                "CSeq",
            ),
            // RFC 4475 3.1.2.11: escaped headers in the Request-URI
            (
                b"INVITE sip:b@example.com?Route=%3Csip:p.example.com%3E SIP/2.0\r\n\
Via: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\n\
Call-ID: c\r\nCSeq: 8 INVITE\r\n\r\n",
                "Request-URI",
            ),
            // RFC 4475 3.1.2.1: the fault is in the second Via value
            (
                b"INVITE sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.15;;,;,,\r\n\
From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\n\
Call-ID: c\r\nCSeq: 8 INVITE\r\n\r\n",
                "Via",
            ),
            // RFC 4475 3.1.2.9: a Date in a zone nobody can read
            (
                b"INVITE sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\n\
Call-ID: c\r\nCSeq: 8 INVITE\r\nDate: Fri, 01 Jan 2010 16:00:00 EST\r\n\r\n",
                "Date",
            ),
            // RFC 4475 3.3.8: a field that may appear once, twice
            (
                b"INVITE sip:b@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>\r\n\
Call-ID: c\r\nCall-ID: d\r\nCSeq: 8 INVITE\r\n\r\n",
                "Call-ID",
            ),
        ];
        for (buf, field) in cases {
            let mut scratch = ParseScratch::new();
            let m = ok(buf, &mut scratch);
            let invalid = m.validate().expect_err("expected a rejection");
            assert_eq!(invalid.field, field, "{}", String::from_utf8_lossy(buf));
        }
    }

    #[test]
    fn a_response_is_validated_without_a_method_to_compare_against() {
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
From: <sip:a@example.com>;tag=1\r\nTo: <sip:b@example.com>;tag=2\r\n\
Call-ID: c\r\nCSeq: 8 INVITE\r\n\r\n",
            &mut scratch,
        );
        assert_eq!(m.validate(), Ok(()));
    }

    #[test]
    fn the_transaction_key_follows_the_ack_to_the_invite_that_owns_it() {
        let mut scratch = ParseScratch::new();
        assert_eq!(
            ok(INVITE, &mut scratch).transaction_lookup_method(),
            Ok(Method::Invite)
        );

        // 17.2.1: the INVITE server transaction absorbs the ACK to a non-2xx
        let mut scratch = ParseScratch::new();
        assert_eq!(
            ok(
                b"ACK sip:bob@example.com SIP/2.0\r\nCSeq: 1 ACK\r\n\r\n",
                &mut scratch
            )
            .transaction_lookup_method(),
            Ok(Method::Invite)
        );

        // a CANCEL is its own transaction even though it borrows the branch
        let mut scratch = ParseScratch::new();
        assert_eq!(
            ok(
                b"CANCEL sip:bob@example.com SIP/2.0\r\nCSeq: 1 CANCEL\r\n\r\n",
                &mut scratch
            )
            .transaction_lookup_method(),
            Ok(Method::Cancel)
        );

        // 17.1.3: a response is matched on the branch and the CSeq method
        let mut scratch = ParseScratch::new();
        assert_eq!(
            ok(
                b"SIP/2.0 200 OK\r\nCSeq: 314159 INVITE\r\n\r\n",
                &mut scratch
            )
            .transaction_lookup_method(),
            Ok(Method::Invite)
        );

        let mut scratch = ParseScratch::new();
        assert_eq!(
            ok(b"SIP/2.0 200 OK\r\n\r\n", &mut scratch).transaction_lookup_method(),
            Err(crate::msg::HeaderError::Missing)
        );
    }

    #[test]
    fn every_challenge_line_is_its_own_challenge() {
        // RFC 8760 2.3: several algorithms, most preferred first, one line
        // each — joining them would make a value the grammar cannot read back
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 401 Unauthorized\r\n\
WWW-Authenticate: Digest realm=\"example.com\", nonce=\"a1\", algorithm=SHA-256, qop=\"auth\"\r\n\
WWW-Authenticate: Digest realm=\"example.com\", nonce=\"a2\", algorithm=MD5, qop=\"auth\"\r\n\
Proxy-Authenticate: Digest realm=\"proxy.example.com\", nonce=\"p1\"\r\n\
\r\n",
            &mut scratch,
        );
        let offered: Vec<_> = m
            .www_authenticate()
            .map(|c| c.expect("a challenge"))
            .map(|c| c.algorithm().unwrap_or_default().into_owned())
            .collect();
        assert_eq!(offered, vec![b"SHA-256".to_vec(), b"MD5".to_vec()]);

        // a separate credential space, not another entry in the same one
        let proxy: Vec<_> = m
            .proxy_authenticate()
            .map(|c| c.expect("a challenge"))
            .map(|c| c.realm().unwrap_or_default().into_owned())
            .collect();
        assert_eq!(proxy, vec![b"proxy.example.com".to_vec()]);
    }

    #[test]
    fn an_unknown_auth_scheme_is_well_formed() {
        // RFC 4475 3.3.7 regaut01
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"REGISTER sip:example.com SIP/2.0\r\n\
Authorization: NoOneKnowsThisScheme opaque-data=here\r\n\
\r\n",
            &mut scratch,
        );
        let c = m
            .authorization()
            .next()
            .expect("one value")
            .expect("credentials");
        assert!(!c.is_digest());
        assert_eq!(c.scheme(), b"NoOneKnowsThisScheme");
        assert_eq!(m.proxy_authorization().count(), 0);
    }

    #[test]
    fn the_list_fields_read_across_lines_and_commas() {
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"INVITE sip:x@example.com SIP/2.0\r\n\
Supported: 100rel, timer\r\n\
k: replaces\r\n\
Require: 100rel\r\n\
Allow: INVITE, ACK, BYE, invite\r\n\
Accept: application/sdp\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\
\r\n",
            &mut scratch,
        );
        assert_eq!(
            m.supported().collect::<Vec<_>>(),
            vec![&b"100rel"[..], b"timer", b"replaces"]
        );
        assert!(m.supported().has("TIMER"));
        assert!(!m.supported().has("norefersub"));
        assert!(m.require().has("100rel"));
        assert!(m.content_type().expect("a type").is("application", "sdp"));
        assert_eq!(m.accept().count(), 1);

        // the standard verbs are fixed-case literals in the grammar
        assert_eq!(
            m.allow().collect::<Vec<_>>(),
            vec![
                Method::Invite,
                Method::Ack,
                Method::Bye,
                Method::Extension("invite"),
            ]
        );
    }

    #[test]
    fn an_absent_list_field_is_empty_rather_than_an_error() {
        let mut scratch = ParseScratch::new();
        let m = ok(INVITE, &mut scratch);
        assert_eq!(m.supported().count(), 0);
        assert_eq!(m.require().count(), 0);
        assert_eq!(m.allow().count(), 0);
        assert_eq!(m.www_authenticate().count(), 0);
    }

    #[test]
    fn route_rows_combine_in_the_order_they_arrived() {
        // RFC 3261 7.3.1: the same three entries in another order are "valid
        // but not equivalent", so nothing here sorts or dedupes
        let hops = |buf: &'static [u8]| {
            let mut scratch = ParseScratch::new();
            ok(buf, &mut scratch)
                .route()
                .filter_map(Result::ok)
                .map(|r| r.uri().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            hops(
                b"INVITE sip:x@example.com SIP/2.0\r\n\
Route: <sip:alice@atlanta.example.com>\r\n\
Route: <sip:bob@biloxi.example.com>, <sip:carol@chicago.example.com>\r\n\
\r\n"
            ),
            vec![
                "sip:alice@atlanta.example.com",
                "sip:bob@biloxi.example.com",
                "sip:carol@chicago.example.com",
            ]
        );
        assert_eq!(
            hops(
                b"INVITE sip:x@example.com SIP/2.0\r\n\
Route: <sip:bob@biloxi.example.com>\r\n\
Route: <sip:alice@atlanta.example.com>\r\n\
Route: <sip:carol@chicago.example.com>\r\n\
\r\n"
            ),
            vec![
                "sip:bob@biloxi.example.com",
                "sip:alice@atlanta.example.com",
                "sip:carol@chicago.example.com",
            ]
        );
    }

    #[test]
    fn record_route_comes_back_in_wire_order_for_both_sides_to_use() {
        // 12.1.1 takes these in order and 12.1.2 in reverse; reversing here
        // would make one of the two wrong
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\n\
Record-Route: <sip:server10.example.com;lr>,\r\n              <sip:bigbox3.example.com;lr>\r\n\
\r\n",
            &mut scratch,
        );
        let hops: Vec<_> = m
            .record_route()
            .map(|r| r.expect("an entry"))
            .map(|r| (r.uri().to_string(), r.is_loose_route()))
            .collect();
        assert_eq!(
            hops,
            vec![
                ("sip:server10.example.com;lr".to_owned(), true),
                ("sip:bigbox3.example.com;lr".to_owned(), true),
            ]
        );
    }

    #[test]
    fn via_values_come_back_in_the_order_a_response_must_follow() {
        use crate::msg::HostRef;
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP first;branch=z9hG4bK1, SIP/2.0/TCP second;branch=z9hG4bK2\r\n\
v: SIP/2.0/TLS third;branch=z9hG4bK3\r\n\
\r\n",
            &mut scratch,
        );
        let hosts: Vec<_> = m.via().filter_map(Result::ok).map(|v| v.host).collect();
        assert_eq!(
            hosts,
            vec![
                HostRef::Name("first"),
                HostRef::Name("second"),
                HostRef::Name("third"),
            ]
        );
        assert_eq!(m.top_via().expect("top").host, HostRef::Name("first"));
    }

    #[test]
    fn a_message_with_no_via_says_so_rather_than_guessing() {
        use crate::msg::HeaderError;
        let mut scratch = ParseScratch::new();
        let m = ok(b"SIP/2.0 200 OK\r\n\r\n", &mut scratch);
        assert_eq!(m.top_via(), Err(HeaderError::Missing));
        assert_eq!(m.via().count(), 0);
    }

    #[test]
    fn a_field_that_may_appear_once_and_appears_twice_is_refused() {
        // RFC 4475 3.3.8
        use crate::msg::HeaderError;
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\nCall-ID: one\r\nCall-ID: two\r\n\r\n",
            &mut scratch,
        );
        assert_eq!(m.call_id(), Err(HeaderError::UnexpectedRepeat));
    }

    #[test]
    fn a_cseq_folded_between_its_number_and_its_method_still_reads() {
        // RFC 4475 3.1.1.1 wsinv
        let mut scratch = ParseScratch::new();
        let m = ok(
            b"SIP/2.0 200 OK\r\ncseq: 0009\r\n  INVITE\r\n\r\n",
            &mut scratch,
        );
        let c = m.cseq().expect("a CSeq");
        assert_eq!((c.seq, c.method), (9, Method::Invite));
    }

    #[test]
    fn an_owned_message_outlives_the_buffer_it_was_parsed_from() {
        use crate::msg::HeaderName;
        let owned = {
            let buf = INVITE.to_vec();
            let mut scratch = ParseScratch::new();
            let m = ok(&buf, &mut scratch);
            m.to_owned()
        };
        let m = owned.as_raw();
        assert_eq!(m.kind(), MessageKind::Request(Method::Invite));
        assert_eq!(m.header(HeaderName::CallId), Some(&b"a84b4c76e66710"[..]));
        assert_eq!(m.header_slots().len(), 6);
        assert_eq!(m.body(), b"v=0\n");
    }

    #[test]
    fn owning_a_message_leaves_the_trailing_octets_behind() {
        // RFC 4475 3.1.1.8: a second request sharing the datagram
        let mut scratch = ParseScratch::new();
        let buf = b"SIP/2.0 200 OK\r\nContent-Length: 3\r\n\r\nabcJUNKJUNKJUNK";
        let owned = ok(buf, &mut scratch).to_owned();
        assert_eq!(owned.as_raw().body(), b"abc");
        assert_eq!(owned.len(), buf.len() - "JUNKJUNKJUNK".len());
        assert!(!owned.is_empty());
    }

    #[test]
    fn cloning_an_owned_message_shares_its_bytes() {
        let mut scratch = ParseScratch::new();
        let a = ok(INVITE, &mut scratch).to_owned();
        let b = a.clone();
        assert!(std::sync::Arc::ptr_eq(&a.bytes(), &b.bytes()));
        assert_eq!(a.as_raw().body(), b.as_raw().body());
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
