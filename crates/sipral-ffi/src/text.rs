// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Text coming in, and why none of it is trusted.
//!
//! Every string that crosses into the library is a pointer and a length. Not a
//! NUL-terminated one: a caller whose display name came from a text field can
//! hand over bytes with a NUL in the middle, and a library that stopped there
//! would send half of what it was given without saying so. The length is what
//! it is.
//!
//! Everything that ends up in a header field is checked for the two bytes that
//! would end the field early. A display name carrying CR or LF is not a name
//! with a formatting problem, it is a header the caller did not write appearing
//! in a message the caller thinks it wrote, and §7.3.1 gives a receiver no way
//! to tell the difference. So they are refused at the boundary, where the
//! caller still knows which string it passed.

use std::ffi::c_char;
use std::ptr;
use std::slice;
use std::str;

use crate::error::{Fail, fail};
use crate::status::SipralStatus;

/// More than any field this ABI accepts, and small enough that a length a
/// caller never set is refused rather than walked.
const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Bytes a caller supplied, as they are.
///
/// `None` for a null pointer with a length of zero, which is how a caller says
/// it has nothing to give. A null pointer with a length is a caller that got
/// its arguments the wrong way round, and is refused.
///
/// # Safety
///
/// `pointer`, when it is not null, must be readable for `len` bytes and must
/// stay so for as long as the returned slice is used.
pub(crate) unsafe fn bytes<'a>(
    pointer: *const u8,
    len: usize,
    name: &'static str,
) -> Result<Option<&'a [u8]>, Fail> {
    if len > MAX_TEXT_BYTES {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} says it is {len} bytes, which is longer than this ABI accepts"),
        ));
    }
    if pointer.is_null() {
        if len == 0 {
            return Ok(None);
        }
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} is null and says it is {len} bytes long"),
        ));
    }
    if len == 0 {
        return Ok(None);
    }
    Ok(Some(unsafe { slice::from_raw_parts(pointer, len) }))
}

/// Text a caller supplied, checked for being UTF-8 and for being one line.
///
/// # Safety
///
/// As [`bytes`].
pub(crate) unsafe fn text<'a>(
    pointer: *const c_char,
    len: usize,
    name: &'static str,
) -> Result<Option<&'a str>, Fail> {
    let Some(raw) = (unsafe { bytes(pointer.cast::<u8>(), len, name) })? else {
        return Ok(None);
    };
    let Ok(text) = str::from_utf8(raw) else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} is not UTF-8"),
        ));
    };
    if let Some(offset) = text.bytes().position(is_field_ending) {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "{name} carries a control byte at offset {offset}, and a header field written \
                 from it would not be the field the caller meant"
            ),
        ));
    }
    Ok(Some(text))
}

/// Text a caller had to supply.
///
/// # Safety
///
/// As [`bytes`].
pub(crate) unsafe fn required_text<'a>(
    pointer: *const c_char,
    len: usize,
    name: &'static str,
) -> Result<&'a str, Fail> {
    match unsafe { text(pointer, len, name) }? {
        Some(text) => Ok(text),
        None => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} is required and was not given"),
        )),
    }
}

/// Whether a byte would end a header field, or is one no field may carry.
///
/// §7.3.1 folds a field across lines on CRLF followed by whitespace, so both
/// halves of a line ending are how a field ends and neither belongs inside a
/// value the caller supplied. The rest of the C0 range and DEL are refused
/// with them: none of them is `TEXT-UTF8char`, and a value that carries one is
/// a value some receiver on the path will read differently.
pub(crate) const fn is_field_ending(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
}

/// Bytes going the other way: copied into a buffer the caller owns, with the
/// length written whether or not the buffer was long enough.
///
/// `out_len` receives what it takes before the capacity is looked at, so a
/// caller that passes a null buffer and a capacity of zero learns how much
/// room to bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL` — which is the
/// question being asked, not a failure.
///
/// Not [`crate::diagnostics::copy_out`], which is for text: that one appends a
/// NUL and counts it in the length. These bytes are opaque and can contain a
/// NUL, so a terminator would be both a byte too many and a place for a
/// reader to stop early.
///
/// # Safety
///
/// `buffer` must be writable for `capacity` bytes or be null with a capacity
/// of zero, and `out_len` must point at one `size_t` or be null.
pub(crate) unsafe fn copy_bytes_out(
    taken: &[u8],
    buffer: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> Result<(), Fail> {
    if buffer.is_null() && capacity != 0 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "buffer is null and capacity is not zero",
        ));
    }
    if !out_len.is_null() {
        unsafe { out_len.write(taken.len()) };
    }
    if capacity < taken.len() {
        return Err(fail(
            SipralStatus::BufferTooSmall,
            format!(
                "{} bytes are needed to hold this and {capacity} were given",
                taken.len()
            ),
        ));
    }
    if taken.is_empty() {
        return Ok(());
    }
    // the capacity reaches a length that is not zero, so the buffer is not
    // null
    unsafe { ptr::copy_nonoverlapping(taken.as_ptr(), buffer, taken.len()) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_TEXT_BYTES, bytes, required_text, text};
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::ptr;

    fn as_text(supplied: &str) -> Result<Option<&str>, SipralStatus> {
        unsafe { text(supplied.as_ptr().cast::<c_char>(), supplied.len(), "field") }
            .map_err(|failure| failure.status)
    }

    #[test]
    fn text_comes_through_as_it_was_given() {
        assert_eq!(
            as_text("sip:alice@example.com"),
            Ok(Some("sip:alice@example.com"))
        );
    }

    #[test]
    fn nothing_is_nothing_rather_than_an_empty_string() {
        let empty = unsafe { text(ptr::null(), 0, "field") }.expect("null and empty is absent");
        assert_eq!(empty, None);
        assert_eq!(as_text(""), Ok(None), "a length of zero says the same");
    }

    #[test]
    fn a_null_pointer_with_a_length_is_a_bad_argument() {
        let refused = unsafe { text(ptr::null(), 4, "field") };
        assert_eq!(
            refused.err().map(|failure| failure.status),
            Some(SipralStatus::InvalidArgument)
        );
    }

    #[test]
    fn a_length_nobody_set_is_refused_before_a_byte_is_read() {
        let supplied = "short";
        let refused = unsafe { text(supplied.as_ptr().cast::<c_char>(), usize::MAX, "field") };
        assert_eq!(
            refused.err().map(|failure| failure.status),
            Some(SipralStatus::InvalidArgument)
        );
        let refused = unsafe { bytes(supplied.as_ptr(), MAX_TEXT_BYTES + 1, "field") };
        assert_eq!(
            refused.err().map(|failure| failure.status),
            Some(SipralStatus::InvalidArgument)
        );
    }

    #[test]
    fn text_that_is_not_utf8_is_refused() {
        let supplied = [0xff_u8, 0xfe];
        let refused = unsafe { text(supplied.as_ptr().cast::<c_char>(), supplied.len(), "field") };
        assert_eq!(
            refused.err().map(|failure| failure.status),
            Some(SipralStatus::InvalidArgument)
        );
    }

    #[test]
    fn a_string_that_would_smuggle_a_header_is_refused() {
        assert_eq!(
            as_text("Alice\r\nContact: <sip:elsewhere@example.net>"),
            Err(SipralStatus::InvalidArgument)
        );
        assert_eq!(as_text("Alice\rBob"), Err(SipralStatus::InvalidArgument));
        assert_eq!(as_text("Alice\nBob"), Err(SipralStatus::InvalidArgument));
        assert_eq!(as_text("Alice\tBob"), Err(SipralStatus::InvalidArgument));
        assert_eq!(as_text("Alice\0Bob"), Err(SipralStatus::InvalidArgument));
        assert_eq!(
            as_text("Alice\u{7f}Bob"),
            Err(SipralStatus::InvalidArgument)
        );
    }

    #[test]
    fn text_that_stops_at_a_nul_is_not_what_arrives() {
        // the length is what counts, so a caller cannot shorten what it sends
        // by putting a NUL in the middle of it; it is refused instead
        let supplied = "one\0two";
        assert_eq!(as_text(supplied), Err(SipralStatus::InvalidArgument));
    }

    #[test]
    fn text_above_the_ascii_range_is_kept() {
        assert_eq!(as_text("Ana Popa"), Ok(Some("Ana Popa")));
        assert_eq!(as_text("\u{1f4de}"), Ok(Some("\u{1f4de}")));
    }

    #[test]
    fn what_is_required_says_so_when_it_is_missing() {
        let refused = unsafe { required_text(ptr::null(), 0, "aor") };
        let failure = refused.expect_err("a missing required field fails");
        assert_eq!(failure.status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn bytes_are_taken_whole_including_the_ones_text_refuses() {
        let supplied = b"v=0\r\no=- 0 0 IN IP4 192.0.2.1\r\n";
        let taken = unsafe { bytes(supplied.as_ptr(), supplied.len(), "sdp") }
            .expect("a body is not a header field");
        assert_eq!(taken, Some(supplied.as_slice()));
    }
}
