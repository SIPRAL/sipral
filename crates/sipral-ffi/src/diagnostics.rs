// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the stack decided, and the session it decided it about.
//!
//! The diagnostic record (`docs/14-diagnostics.md`) is safe to send unread. A
//! replay recording (`docs/18-replay.md`) is not: it holds the messages, and a
//! message can hold whatever the peer put in it.
//!
//! # The record
//!
//! [`sipral_call_record_json`] and [`sipral_stack_diagnostics_json`] serialise
//! `Endpoint::call_record` and `Endpoint::endpoint_record`. They copy out like
//! [`crate::error::sipral_last_error_message`]: `out_needed` always gets the
//! length including the NUL, and a buffer too small is
//! `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written.
//!
//! # The recording
//!
//! [`sipral_stack_recording_start`] and [`sipral_stack_recording_stop`] drive
//! [`sipral_ua::UserAgent`]'s recorder, which feeds a
//! [`sipral_core::replay::Recorder`] from [`sipral_ua::UserAgent::receive`] and
//! [`sipral_ua::UserAgent::handle_timeout`], on a seed derived one way from
//! `entropy`.
//!
//! **It never records what this end sent.** Neither call is offered a byte this
//! stack wrote, so this end's SRTP key never reaches the file (8.2.4,
//! `docs/18-replay.md`). What the far end sent is recorded as it arrived, key
//! included.
//!
//! A second start replaces the running recording; [`crate::record`] refuses a
//! second audio `start` because its file is already open, while a replay
//! recording has no file until [`sipral_stack_recording_stop`]. Stopping one
//! never started is `SIPRAL_STATUS_WRONG_STATE`, as for
//! `sipral_media_record_stop`.

use std::ffi::c_char;
use std::ptr;

use sipral_core::dialog::CallId;

use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{handle_failed, with_stack};
use crate::status::SipralStatus;
use crate::text::text;

/// Copy `text` into the caller's buffer, or say how much room it needs.
///
/// Set by [`crate::error::sipral_last_error_message`]. `out_needed` always
/// gets the length including the NUL, so capacity zero with a null buffer
/// learns the length (`SIPRAL_STATUS_BUFFER_TOO_SMALL`). A buffer too small
/// gets nothing, so a multi-byte character is never cut.
///
/// # Safety
///
/// `buffer` must be writable for `capacity` bytes or be null with a capacity
/// of zero, and `out_needed` must point at one `size_t` or be null.
pub(crate) unsafe fn copy_out(
    text: &str,
    buffer: *mut c_char,
    capacity: usize,
    out_needed: *mut usize,
) -> Result<(), Fail> {
    if buffer.is_null() && capacity != 0 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "buffer is null and capacity is not zero",
        ));
    }
    let needed = text.len().saturating_add(1);
    if !out_needed.is_null() {
        unsafe { out_needed.write(needed) };
    }
    if capacity < needed {
        return Err(fail(
            SipralStatus::BufferTooSmall,
            format!("{needed} bytes are needed to hold this and {capacity} were given"),
        ));
    }
    // `needed` >= 1, so a capacity reaching it means a non-null buffer
    unsafe {
        ptr::copy_nonoverlapping(text.as_ptr().cast::<c_char>(), buffer, text.len());
        buffer.add(text.len()).write(0);
    }
    Ok(())
}

entry! {
    /// Copy one call's diagnostic record into `buffer`, as the JSON
    /// `docs/14-diagnostics.md` describes.
    ///
    /// Readable during the call and after it, until the record is evicted
    /// (`sipral_stack_config_t::diagnostic_records` are kept, 32 when zero).
    /// An evicted or still empty record answers `SIPRAL_STATUS_OK` with `{}`.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// document, with the length needed in `out_needed`.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be null.
    fn sipral_call_record_json(
        stack: SipralHandle,
        call: SipralHandle,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        let json = with_stack(stack, |state| {
            let handle = state.calls.get(call).map_err(handle_failed)?;
            let identity = state.agent.call_identity(handle).ok_or_else(|| {
                fail(
                    SipralStatus::WrongState,
                    "this call has no diagnostic identity yet",
                )
            })?;
            let call_id = CallId::new(&identity.call_id);
            Ok(state
                .agent
                .endpoint()
                .call_record(&call_id)
                .map_or_else(|| "{}".to_owned(), sipral_core::diag::Record::to_json))
        })?;
        unsafe { copy_out(&json, buffer, capacity, out_needed) }
    }
}

entry! {
    /// Copy the whole diagnostic document into `buffer`: what a bug report
    /// carries, as the JSON `docs/14-diagnostics.md` describes.
    ///
    /// The endpoint's own record (decisions outside any call), then one record
    /// per call still held, and the count of evicted records.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// document, with the length needed in `out_needed`.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be null.
    fn sipral_stack_diagnostics_json(
        stack: SipralHandle,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        let json = with_stack(stack, |state| Ok(state.agent.endpoint().diagnostics_json()))?;
        unsafe { copy_out(&json, buffer, capacity, out_needed) }
    }
}

entry! {
    /// Start recording the signalling this stack is fed (`docs/18-replay.md`).
    /// Starting moves the stack onto a fresh seed derived one way from
    /// `entropy`; the recording carries that seed, never `entropy`, and
    /// stopping moves the stack on again. It records what arrives, never what
    /// this end sent.
    ///
    /// `note` is one line of prose for whoever opens the file later, or null
    /// for none.
    ///
    /// A running recording is replaced, not refused: nothing is written until
    /// `sipral_stack_recording_stop`.
    ///
    /// # Safety
    ///
    /// `note` must be readable for `note_len` bytes or be null with a length
    /// of zero.
    fn sipral_stack_recording_start(stack: SipralHandle, note: *const c_char, note_len: usize) {
        let note = unsafe { text(note, note_len, "note") }?;
        with_stack(stack, |state| {
            state.agent.start_recording(note);
            Ok(())
        })
    }
}

entry! {
    /// Stop the recording [`sipral_stack_recording_start`] began, and copy
    /// the text of it into `buffer` (`docs/18-replay.md`).
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when no recording is running. Also
    /// `SIPRAL_STATUS_WRONG_STATE`, with the reason in the last error, when a
    /// message could not go in the text format (a non-text body); then nothing
    /// is produced, since a recording missing a message would replay differently.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// text, with the length needed in `out_needed`; asking again returns the
    /// same recording. Once copied out whole, the recording is gone from the stack.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be null.
    fn sipral_stack_recording_stop(
        stack: SipralHandle,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        with_stack(stack, |state| {
            let text = match state.agent.stop_recording() {
                None => {
                    return Err(fail(
                        SipralStatus::WrongState,
                        "no recording is running on this stack",
                    ));
                }
                Some(Ok(recording)) => recording.to_text(),
                Some(Err(error)) => {
                    // not a buffer-size problem, so no retry to keep it for
                    state.agent.clear_stopped_recording();
                    return Err(fail(
                        SipralStatus::WrongState,
                        format!("the recording could not be produced: {error}"),
                    ));
                }
            };
            let outcome = unsafe { copy_out(&text, buffer, capacity, out_needed) };
            if outcome.is_ok() {
                state.agent.clear_stopped_recording();
            }
            outcome
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        sipral_call_record_json, sipral_stack_diagnostics_json, sipral_stack_recording_start,
        sipral_stack_recording_stop,
    };
    use crate::account::sipral_account_register;
    use crate::call::tests::{
        accepted, account_on, deliver, managed_config, media_line, one, place,
    };
    use crate::error::last_error_text;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::media::SipralSrtp;
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::ptr;

    fn as_text(value: &str) -> (*const c_char, usize) {
        (value.as_ptr().cast::<c_char>(), value.len())
    }

    /// Call `read` with a null buffer to learn the length, then with a buffer
    /// that size.
    fn read_text(
        read: impl Fn(*mut c_char, usize, *mut usize) -> SipralStatus,
    ) -> (SipralStatus, String) {
        let mut needed = usize::MAX;
        let first = read(ptr::null_mut(), 0, &raw mut needed);
        if first != SipralStatus::BufferTooSmall {
            return (first, String::new());
        }
        let mut buffer = vec![0_u8; needed];
        let second = read(
            buffer.as_mut_ptr().cast::<c_char>(),
            buffer.len(),
            ptr::null_mut(),
        );
        let text = if second == SipralStatus::Ok {
            String::from_utf8_lossy(&buffer[..needed - 1]).into_owned()
        } else {
            String::new()
        };
        (second, text)
    }

    fn diagnostics_of(stack: SipralHandle) -> (SipralStatus, String) {
        read_text(|buffer, capacity, out_needed| unsafe {
            sipral_stack_diagnostics_json(stack, buffer, capacity, out_needed)
        })
    }

    fn record_of(stack: SipralHandle, call: SipralHandle) -> (SipralStatus, String) {
        read_text(|buffer, capacity, out_needed| unsafe {
            sipral_call_record_json(stack, call, buffer, capacity, out_needed)
        })
    }

    fn start(stack: SipralHandle, note: Option<&str>) -> SipralStatus {
        let (note, note_len) = note.map_or((ptr::null(), 0), as_text);
        unsafe { sipral_stack_recording_start(stack, note, note_len) }
    }

    fn stop(stack: SipralHandle) -> (SipralStatus, String) {
        read_text(|buffer, capacity, out_needed| unsafe {
            sipral_stack_recording_stop(stack, buffer, capacity, out_needed)
        })
    }

    /// D1: the REGISTER sent is recorded in the endpoint's record as JSON.
    #[test]
    fn the_endpoint_writes_down_a_register_it_sent() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_000);
        let (status, json) = diagnostics_of(handle);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(json.contains("\"reason\":\"request.sent\""), "{json}");
        assert!(json.contains("\"method\":\"REGISTER\""), "{json}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// D1: the endpoint record comes first with a null call id; no call handle
    /// is invalid.
    #[test]
    fn a_stack_with_no_calls_has_an_empty_endpoint_record_and_no_call_to_ask_about() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (status, json) = diagnostics_of(handle);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(
            json.contains("\"records\":[{\"call_id\":null"),
            "the endpoint's own record is not first, or is not null: {json}"
        );
        let (status, json) = record_of(handle, SIPRAL_HANDLE_NONE);
        assert_eq!(status, SipralStatus::InvalidHandle, "{json}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// D1: a buffer too small reports the length and writes nothing.
    #[test]
    fn a_buffer_too_small_is_said_and_nothing_is_written() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut needed = 0_usize;
        let status =
            unsafe { sipral_stack_diagnostics_json(handle, ptr::null_mut(), 0, &raw mut needed) };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert!(
            needed > 2,
            "an empty document is at least {{\"records_dropped\":0,..."
        );
        let mut one_byte = [0x7f_u8; 1];
        let mut ignored = 0_usize;
        let status = unsafe {
            sipral_stack_diagnostics_json(
                handle,
                one_byte.as_mut_ptr().cast::<c_char>(),
                1,
                &raw mut ignored,
            )
        };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(one_byte, [0x7f], "a byte was written despite the refusal");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// D2: stopping a recording never started is `SIPRAL_STATUS_WRONG_STATE`.
    #[test]
    fn stopping_a_recording_that_was_never_started_says_so() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (status, text) = stop(handle);
        assert_eq!(status, SipralStatus::WrongState);
        assert!(text.is_empty());
        assert!(
            last_error_text().contains("no recording"),
            "{}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// D2: a second start replaces the first rather than refusing it.
    #[test]
    fn a_second_start_replaces_the_first_recording_rather_than_refusing_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            start(handle, Some("first")),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_000);
        assert_eq!(
            start(handle, Some("second")),
            SipralStatus::Ok,
            "a running recording refused a second start"
        );
        let (status, text) = stop(handle);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(
            text.contains("note second") && !text.contains("note first"),
            "the first recording's note survived the second start: {text}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// D2: a recording of an answered SRTP call does not carry the key this
    /// end offered: the key is read from the INVITE sent and must be absent
    /// from the recording.
    #[test]
    fn a_recorded_srtp_call_does_not_carry_the_key_this_end_offered() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |config| {
            config.srtp = SipralSrtp::Required as u32;
        });
        assert_eq!(
            start(handle, Some("8.2.4, one leg only")),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let (status, _call) = place(handle, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        let body = String::from_utf8_lossy(&invite).into_owned();
        assert!(body.contains("a=crypto:"), "no key offered: {body}");
        let own_key = own_offered_key(&body);

        let far_end_key = "inline:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let secure_answer = format!(
            "v=0\r\n\
             o=bob 1 1 IN IP4 203.0.113.5\r\n\
             s=-\r\n\
             c=IN IP4 203.0.113.5\r\n\
             t=0 0\r\n\
             m=audio 41000 RTP/SAVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 {far_end_key}\r\n\
             a=sendrecv\r\n"
        );
        deliver(
            handle,
            &accepted(&invite, secure_answer.as_bytes(), true),
            1_050,
        );
        poll(handle, 1_050);

        let (status, text) = stop(handle);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(
            text.contains("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            "the far end's own key should still be readable, proving this is a real \
             capture and not an empty one: {text}"
        );
        assert!(
            !text.contains(&own_key),
            "the caller's own negotiated key rode along in its own recording: {text}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The base64 key of this end's `a=crypto` line.
    fn own_offered_key(sdp: &str) -> String {
        let line = sdp
            .lines()
            .find(|line| line.starts_with("a=crypto:"))
            .expect("a crypto line was offered");
        let params = line
            .split_whitespace()
            .nth(2)
            .expect("a crypto line names a key after the suite");
        params
            .strip_prefix("inline:")
            .expect("the key method is inline")
            .split('|')
            .next()
            .expect("a key value")
            .to_owned()
    }

    /// D2: a multi-line note is refused at start, before a recorder is made.
    #[test]
    fn a_note_that_is_not_one_line_is_refused_before_anything_starts() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let status = start(handle, Some("two\r\nlines"));
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("note"), "{}", last_error_text());
        let (status, _) = stop(handle);
        assert_eq!(
            status,
            SipralStatus::WrongState,
            "the refused note still started a recording"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
