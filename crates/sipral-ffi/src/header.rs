// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Header fields in, and header fields out.
//!
//! In: an array of [`SipralHeader`] beside its length, on
//! `sipral_call_config_t` for the INVITE, on `sipral_account_config_t` for
//! every REGISTER, and handed to `sipral_call_set_headers` for what a call
//! sends afterwards. Every field is checked before anything is built: the name
//! a token, the value one line of text, and not a field the stack writes itself
//! on those messages. The list of those, with the reason for each, is
//! `docs/04-ua.md`, and [`sipral_ua::HeadersFor`] is the one place it is kept.
//! A refusal says which element it was.
//!
//! Out: four accessors over the parser this library already runs, so that no
//! binding writes one of its own to read `P-Asserted-Identity`, `Diversion` or
//! an `X-` field out of the message an event carries. One of each pair counts
//! and the other reaches an occurrence by index, and what comes back is an
//! offset into the bytes they were given rather than a pointer, because those
//! bytes are the caller's: a binding that copied them across the boundary holds
//! its own copy, and an offset means the same thing in both.

use std::ffi::c_char;
use std::slice;

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, RawMessage, parse};
use sipral_ua::HeadersFor;

use crate::abi::record;
use crate::error::{Fail, entry, fail};
use crate::status::SipralStatus;
use crate::text::{bytes, required_text, text};

/// More fields than any application puts on one message, and few enough that
/// a length nobody set is refused before an element is read.
const MAX_HEADERS: usize = 64;

record! {
    /// One header field an application hands over: a name and a value, UTF-8,
    /// neither NUL-terminated.
    ///
    /// Always an element of an array whose length travels beside it, which is
    /// why it carries no `size`: an array is strided by the length of its
    /// element, so a member appended here would move every element after the
    /// first. A header field is a name and a value, and this never grows.
    #[derive(Clone, Copy)]
    pub struct SipralHeader {
        /// The field name, `X-Conversation-Id`. A compact form is the field it
        /// abbreviates.
        pub name: *const c_char,
        /// How many bytes of it.
        pub name_len: usize,
        /// The value, as it goes on the line after the colon. Null or empty
        /// for a field with an empty value.
        pub value: *const c_char,
        /// How many bytes of it.
        pub value_len: usize,
    }
}

/// The fields a caller handed over, checked, borrowing the caller's memory for
/// the length of the call.
///
/// `user_agent_written` says the stack writes a `User-Agent` of its own on
/// these messages, from `sipral_stack_config_t::user_agent`, so that a second
/// is refused like every other field the stack writes.
///
/// # Safety
///
/// `pointer`, when it is not null, must be readable for `len` elements, and
/// every name and value in them readable for the length beside it.
pub(crate) unsafe fn supplied<'a>(
    pointer: *const SipralHeader,
    len: usize,
    on: HeadersFor,
    user_agent_written: bool,
) -> Result<Vec<(HeaderName<'a>, &'a [u8])>, Fail> {
    if len > MAX_HEADERS {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "headers_len is {len}, and no message takes more than {MAX_HEADERS} fields of an \
                 application's"
            ),
        ));
    }
    if pointer.is_null() {
        if len == 0 {
            return Ok(Vec::new());
        }
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("headers is null and headers_len says {len}"),
        ));
    }
    let handed = unsafe { slice::from_raw_parts(pointer, len) };
    handed
        .iter()
        .enumerate()
        .map(|(index, one)| {
            unsafe { checked(one, on, user_agent_written) }
                .map_err(|failure| failure.within(&format!("headers[{index}]")))
        })
        .collect()
}

/// One of them.
///
/// # Safety
///
/// As [`supplied`], for this element.
unsafe fn checked<'a>(
    one: &SipralHeader,
    on: HeadersFor,
    user_agent_written: bool,
) -> Result<(HeaderName<'a>, &'a [u8]), Fail> {
    let name = unsafe { required_text(one.name, one.name_len, "name") }?;
    // text, not bytes: every string this ABI puts in a header field is UTF-8
    // with no control byte in it, a tab included
    let value = unsafe { text(one.value, one.value_len, "value") }?.unwrap_or("");
    let field = on
        .check(name.as_bytes(), value.as_bytes())
        .map_err(|refused| fail(SipralStatus::InvalidArgument, refused.to_string()))?;
    if user_agent_written && field == HeaderName::UserAgent {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "User-Agent is written by the stack, from sipral_stack_config_t::user_agent, and a \
             second line of it is a message the two ends read differently",
        ));
    }
    Ok((field, value.as_bytes()))
}

/// How the occurrences of one field are counted.
#[derive(Clone, Copy)]
enum Counted {
    /// A line at a time, whatever the value holds.
    Lines,
    /// A value at a time, across lines and across the commas in them.
    Elements,
}

/// The message and the field name an accessor was handed, checked.
///
/// # Safety
///
/// `message` must be readable for `message_len` bytes and `name` for
/// `name_len`, for as long as what comes back is used.
unsafe fn asked<'a>(
    message: *const u8,
    message_len: usize,
    name: *const c_char,
    name_len: usize,
) -> Result<(&'a [u8], HeaderName<'a>), Fail> {
    let Some(whole) = (unsafe { bytes(message, message_len, "message") })? else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "message is required and was not given",
        ));
    };
    let wanted = unsafe { required_text(name, name_len, "name") }?;
    let Some(field) = HeaderName::from_bytes(wanted.as_bytes()) else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("name is {wanted:?}, which is not a token and so names no header field"),
        ));
    };
    Ok((whole, field))
}

/// The message, parsed the way the stack parses what arrives.
///
/// Lenient, because a message the stack took in and reported is not refused a
/// second time on the way to reading it.
fn parsed<'a>(whole: &'a [u8], scratch: &'a mut ParseScratch) -> Result<RawMessage<'a>, Fail> {
    parse(whole, scratch, ParseMode::Lenient).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("message is not a SIP message: {error}"),
        )
    })
}

/// How many occurrences of `field` the message holds.
fn count_in(whole: &[u8], field: HeaderName<'_>, counted: Counted) -> Result<usize, Fail> {
    let mut scratch = ParseScratch::new();
    let message = parsed(whole, &mut scratch)?;
    Ok(match counted {
        Counted::Lines => message.header_count(field),
        Counted::Elements => message.field_values(field).count(),
    })
}

/// Where the occurrence at `index` is, as an offset into `whole` and a length.
fn span_in(
    whole: &[u8],
    field: HeaderName<'_>,
    counted: Counted,
    index: usize,
) -> Result<(usize, usize), Fail> {
    let mut scratch = ParseScratch::new();
    let message = parsed(whole, &mut scratch)?;
    let found = match counted {
        Counted::Lines => message.header_values(field).nth(index),
        Counted::Elements => message.field_values(field).nth(index),
    };
    let Some(value) = found else {
        let said = match counted {
            Counted::Lines => format!("is on {} lines", message.header_count(field)),
            Counted::Elements => format!("holds {} values", message.field_values(field).count()),
        };
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("index is {index}, and {field} {said}"),
        ));
    };
    Ok((offset_in(whole, value)?, value.len()))
}

/// Where a slice of `within` starts inside it.
///
/// Every value the parser hands back is a slice of the buffer it parsed, so
/// this is never refused; the check is there for the day that stops being so,
/// which would otherwise be an offset pointing at somebody else's bytes.
fn offset_in(within: &[u8], part: &[u8]) -> Result<usize, Fail> {
    part.as_ptr()
        .addr()
        .checked_sub(within.as_ptr().addr())
        .filter(|start| start.saturating_add(part.len()) <= within.len())
        .ok_or_else(|| {
            fail(
                SipralStatus::Panic,
                "a value the parser returned is not inside the message it parsed",
            )
        })
}

entry! {
    /// How many lines a header field is on, in a whole SIP message.
    ///
    /// The message is any SIP message in bytes: the one an event carries in
    /// `sipral_event_t::message`, or one the application came by some other
    /// way. The name is matched the way the parser matches it, without regard to
    /// case, and a compact form and its long form are one field (RFC 3261
    /// §7.3.3): `i` counts the `Call-ID` lines, and `Call-ID` counts a line
    /// written `i:`. A field that is not there is a count of zero, not a
    /// failure.
    ///
    /// # Safety
    ///
    /// `message` must be readable for `message_len` bytes and `name` for
    /// `name_len`, and `out_count` must point at one `size_t`.
    fn sipral_message_header_count(
        message: *const u8,
        message_len: usize,
        name: *const c_char,
        name_len: usize,
        out_count: *mut usize,
    ) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let (whole, field) = unsafe { asked(message, message_len, name, name_len) }?;
        let count = count_in(whole, field, Counted::Lines)?;
        unsafe { out_count.write(count) };
        Ok(())
    }
}

entry! {
    /// Where one line of a header field is, in a whole SIP message.
    ///
    /// `index` counts from zero in the order the lines arrived, and has to be
    /// below what `sipral_message_header_count` says for the same name: past it
    /// is `SIPRAL_STATUS_INVALID_ARGUMENT`. `out_offset` and `out_len` then say
    /// where the value sits inside `message`, trimmed at both ends and otherwise
    /// as it arrived, a line fold included. An offset rather than a pointer,
    /// because the bytes are the caller's, and a binding that copied them across
    /// the boundary holds its own copy.
    ///
    /// One line of a field whose value is a comma-separated list may hold
    /// several values; `sipral_message_header_element` reaches those.
    ///
    /// # Safety
    ///
    /// As `sipral_message_header_count`, with `out_offset` and `out_len` each
    /// pointing at one `size_t`.
    fn sipral_message_header(
        message: *const u8,
        message_len: usize,
        name: *const c_char,
        name_len: usize,
        index: usize,
        out_offset: *mut usize,
        out_len: *mut usize,
    ) {
        if out_offset.is_null() || out_len.is_null() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "out_offset and out_len are both required",
            ));
        }
        let (whole, field) = unsafe { asked(message, message_len, name, name_len) }?;
        let (offset, len) = span_in(whole, field, Counted::Lines, index)?;
        unsafe {
            out_offset.write(offset);
            out_len.write(len);
        }
        Ok(())
    }
}

entry! {
    /// How many values a field whose value is a comma-separated list holds,
    /// across every line it is on.
    ///
    /// RFC 3261 §7.3.1 makes two values on one line, with a comma between them,
    /// and the same two values on two lines one and the same message, and a
    /// proxy is free to turn either into the other. So this counts values
    /// rather than lines, split at every comma that is not inside quotes or
    /// angle brackets. Otherwise as `sipral_message_header_count`.
    ///
    /// Only for a field defined as a list: `P-Asserted-Identity`, `Diversion`,
    /// `Contact`, `Supported`. Any other is split at a comma its value holds as
    /// text, like the one in a `Date` or the ones between the parameters of a
    /// challenge, and `sipral_message_header_count` is the call for it.
    ///
    /// # Safety
    ///
    /// As `sipral_message_header_count`.
    fn sipral_message_header_element_count(
        message: *const u8,
        message_len: usize,
        name: *const c_char,
        name_len: usize,
        out_count: *mut usize,
    ) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let (whole, field) = unsafe { asked(message, message_len, name, name_len) }?;
        let count = count_in(whole, field, Counted::Elements)?;
        unsafe { out_count.write(count) };
        Ok(())
    }
}

entry! {
    /// Where one value of a list field is, across every line the field is on.
    ///
    /// `index` counts values in the order they arrived, and has to be below what
    /// `sipral_message_header_element_count` says for the same name. Otherwise
    /// as `sipral_message_header`.
    ///
    /// # Safety
    ///
    /// As `sipral_message_header`.
    fn sipral_message_header_element(
        message: *const u8,
        message_len: usize,
        name: *const c_char,
        name_len: usize,
        index: usize,
        out_offset: *mut usize,
        out_len: *mut usize,
    ) {
        if out_offset.is_null() || out_len.is_null() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "out_offset and out_len are both required",
            ));
        }
        let (whole, field) = unsafe { asked(message, message_len, name, name_len) }?;
        let (offset, len) = span_in(whole, field, Counted::Elements, index)?;
        unsafe {
            out_offset.write(offset);
            out_len.write(len);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        sipral_message_header, sipral_message_header_count, sipral_message_header_element,
        sipral_message_header_element_count,
    };
    use crate::error::last_error_text;
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::ptr;

    /// A 200 with a field on two lines, one of them a list with a comma inside
    /// quotes, a `Date` with a comma of its own, a `Call-ID` written compact
    /// and a field with nothing after the colon.
    const MESSAGE: &[u8] = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-headers\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:bob@example.com>;tag=b\r\n\
i: headers-1@192.0.2.10\r\n\
CSeq: 1 INVITE\r\n\
Diversion: <sip:desk@example.com>;reason=no-answer, \"Front, Desk\" <sip:front@example.com>\r\n\
Date: Sun, 13 Sep 2026 10:00:00 GMT\r\n\
diversion: <sip:mobile@example.com>;reason=unconditional\r\n\
X-Empty:\r\n\
Content-Length: 0\r\n\
\r\n";

    type Count =
        unsafe extern "C" fn(*const u8, usize, *const c_char, usize, *mut usize) -> SipralStatus;

    type Reach = unsafe extern "C" fn(
        *const u8,
        usize,
        *const c_char,
        usize,
        usize,
        *mut usize,
        *mut usize,
    ) -> SipralStatus;

    /// How many, asked the way C asks.
    fn count(counter: Count, message: &[u8], name: &str) -> usize {
        let mut count = usize::MAX;
        let status = unsafe {
            counter(
                message.as_ptr(),
                message.len(),
                name.as_ptr().cast::<c_char>(),
                name.len(),
                &raw mut count,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        count
    }

    /// The bytes one occurrence covers, read through the offset and the length
    /// the accessor answered with.
    fn reach(
        reacher: Reach,
        message: &[u8],
        name: &str,
        index: usize,
    ) -> Result<Vec<u8>, SipralStatus> {
        let (mut offset, mut len) = (usize::MAX, usize::MAX);
        let status = unsafe {
            reacher(
                message.as_ptr(),
                message.len(),
                name.as_ptr().cast::<c_char>(),
                name.len(),
                index,
                &raw mut offset,
                &raw mut len,
            )
        };
        if status != SipralStatus::Ok {
            return Err(status);
        }
        Ok(message[offset..offset + len].to_vec())
    }

    #[test]
    fn every_line_of_a_field_is_counted_and_reached_in_the_order_it_arrived() {
        assert_eq!(count(sipral_message_header_count, MESSAGE, "Diversion"), 2);
        assert_eq!(
            reach(sipral_message_header, MESSAGE, "Diversion", 0),
            Ok(
                b"<sip:desk@example.com>;reason=no-answer, \"Front, Desk\" <sip:front@example.com>"
                    .to_vec()
            )
        );
        assert_eq!(
            reach(sipral_message_header, MESSAGE, "Diversion", 1),
            Ok(b"<sip:mobile@example.com>;reason=unconditional".to_vec())
        );
        assert_eq!(
            reach(sipral_message_header, MESSAGE, "Diversion", 2),
            Err(SipralStatus::InvalidArgument),
            "an index past the count"
        );
        // a line is a line, whatever commas it holds
        assert_eq!(count(sipral_message_header_count, MESSAGE, "Date"), 1);
        assert_eq!(
            reach(sipral_message_header, MESSAGE, "Date", 0),
            Ok(b"Sun, 13 Sep 2026 10:00:00 GMT".to_vec())
        );
    }

    #[test]
    fn every_value_of_a_list_is_counted_across_its_lines_and_its_commas() {
        assert_eq!(
            count(sipral_message_header_element_count, MESSAGE, "Diversion"),
            3
        );
        let values: Vec<Vec<u8>> = (0..3)
            .map(|index| {
                reach(sipral_message_header_element, MESSAGE, "Diversion", index).expect("a value")
            })
            .collect();
        assert_eq!(
            values,
            [
                b"<sip:desk@example.com>;reason=no-answer".to_vec(),
                b"\"Front, Desk\" <sip:front@example.com>".to_vec(),
                b"<sip:mobile@example.com>;reason=unconditional".to_vec(),
            ],
            "the comma inside the quotes is not a separator"
        );
        assert_eq!(
            reach(sipral_message_header_element, MESSAGE, "Diversion", 3),
            Err(SipralStatus::InvalidArgument)
        );
    }

    #[test]
    fn a_compact_name_finds_its_long_form_and_the_long_form_finds_a_compact_line() {
        for name in ["Call-ID", "call-id", "i"] {
            assert_eq!(
                count(sipral_message_header_count, MESSAGE, name),
                1,
                "{name}"
            );
            assert_eq!(
                reach(sipral_message_header, MESSAGE, name, 0),
                Ok(b"headers-1@192.0.2.10".to_vec()),
                "{name}"
            );
        }
        assert_eq!(
            reach(sipral_message_header, MESSAGE, "t", 0),
            Ok(b"<sip:bob@example.com>;tag=b".to_vec())
        );
    }

    #[test]
    fn a_field_that_is_not_there_is_a_count_of_zero_and_an_empty_one_is_there() {
        assert_eq!(
            count(sipral_message_header_count, MESSAGE, "P-Asserted-Identity"),
            0
        );
        assert_eq!(
            count(
                sipral_message_header_element_count,
                MESSAGE,
                "P-Asserted-Identity"
            ),
            0
        );
        assert_eq!(count(sipral_message_header_count, MESSAGE, "X-Empty"), 1);
        assert_eq!(
            reach(sipral_message_header, MESSAGE, "X-Empty", 0),
            Ok(Vec::new())
        );
    }

    #[test]
    fn a_name_that_is_not_a_token_and_bytes_that_are_not_a_message_are_refused() {
        assert_eq!(
            reach(sipral_message_header, MESSAGE, "X-Two Words", 0),
            Err(SipralStatus::InvalidArgument)
        );
        assert_eq!(
            reach(sipral_message_header_element, MESSAGE, "Diversion:", 0),
            Err(SipralStatus::InvalidArgument)
        );
        assert_eq!(
            reach(sipral_message_header, b"hello\r\n\r\n", "Call-ID", 0),
            Err(SipralStatus::InvalidArgument)
        );
        assert_eq!(
            reach(sipral_message_header, b"", "Call-ID", 0),
            Err(SipralStatus::InvalidArgument)
        );
        let name = "Call-ID";
        let refused = unsafe {
            sipral_message_header_count(
                MESSAGE.as_ptr(),
                MESSAGE.len(),
                name.as_ptr().cast::<c_char>(),
                name.len(),
                ptr::null_mut(),
            )
        };
        assert_eq!(refused, SipralStatus::InvalidArgument);
    }

    #[test]
    fn a_compact_form_registered_after_rfc_3261_finds_its_long_form() {
        // Identity keeps "y" (RFC 8224 §13.1), and RFC 3841 §12 registers a, j
        // and d: a line written compact is the field its long name asks for
        const COMPACT: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-compact\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: compact-1@192.0.2.10\r\n\
CSeq: 1 INVITE\r\n\
y: signed-7;info=<https://cert.example.org/passport.cer>\r\n\
a: *;audio\r\n\
j: *;video\r\n\
d: proxy, recurse\r\n\
Content-Length: 0\r\n\
\r\n";
        for (long, compact, value) in [
            (
                "Identity",
                "y",
                &b"signed-7;info=<https://cert.example.org/passport.cer>"[..],
            ),
            ("Accept-Contact", "a", &b"*;audio"[..]),
            ("Reject-Contact", "j", &b"*;video"[..]),
            ("Request-Disposition", "d", &b"proxy, recurse"[..]),
        ] {
            assert_eq!(
                count(sipral_message_header_count, COMPACT, long),
                1,
                "{long}"
            );
            assert_eq!(
                reach(sipral_message_header, COMPACT, long, 0),
                Ok(value.to_vec()),
                "{long}"
            );
            assert_eq!(
                count(sipral_message_header_count, COMPACT, compact),
                1,
                "{compact}"
            );
        }
    }

    #[test]
    fn a_message_with_bare_lf_line_endings_is_read_the_way_the_stack_already_took_it_in() {
        // the receive path this message would have arrived on accepts a bare
        // LF (`ParseMode::Lenient`); an accessor reading it back a second time
        // must not refuse what was already let in once
        const BARE_LF: &[u8] = b"SIP/2.0 200 OK\nX-Loose: yes\n\n";
        assert_eq!(count(sipral_message_header_count, BARE_LF, "X-Loose"), 1);
        assert_eq!(
            reach(sipral_message_header, BARE_LF, "X-Loose", 0),
            Ok(b"yes".to_vec())
        );
    }
}
