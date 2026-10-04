// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the stack decided, and the session it decided it about.
//!
//! Two artefacts, both meant to leave the process and both documented where
//! they are built: the diagnostic record (`docs/14-diagnostics.md`), which is
//! safe to send without being read, and a replay recording
//! (`docs/18-replay.md`), which is not — a recording holds the messages
//! themselves, and a message can hold whatever the peer put in it.
//!
//! # The record
//!
//! [`sipral_call_record_json`] and [`sipral_stack_diagnostics_json`] are
//! `Endpoint::call_record` and `Endpoint::endpoint_record`, serialised. Both
//! copy into a caller's buffer the way [`crate::error::sipral_last_error_message`]
//! does: `out_needed` always receives the number of bytes the text needs
//! including the trailing NUL, and a buffer too small for the whole of it is
//! `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written to it.
//!
//! # The recording
//!
//! [`sipral_stack_recording_start`] and [`sipral_stack_recording_stop`] are
//! [`sipral_ua::UserAgent`]'s own recorder, the one thing here that is new
//! rather than a read of something the layer below already keeps: nothing
//! before this needed a driver that fed a [`sipral_core::replay::Recorder`]
//! beside every [`sipral_ua::UserAgent::receive`] and
//! [`sipral_ua::UserAgent::handle_timeout`], so that driving is done inside
//! `UserAgent` itself now, on a seed drawn for the recording from a stream
//! derived one way from the one the agent was built with (`entropy` on
//! `sipral_stack_create`), and it is done for every caller of this crate
//! rather than once for this one.
//!
//! **What it does not do, on purpose: it never records what this end sent.**
//! [`sipral_ua::UserAgent::receive`] offers the recorder the input before
//! touching it and [`sipral_ua::UserAgent::handle_timeout`] offers it the
//! moment, and neither is ever offered a byte this stack wrote — there is no
//! third call to make that offer from, because nothing else here reads a
//! transmit queue. A caller's own negotiated SRTP key is written into the
//! offer or the answer this end sends and nowhere else, so it never reaches
//! the recorder and never reaches the file (8.2.4, `docs/18-replay.md`).
//! What arrives from the far end is a different matter and is recorded
//! exactly as it arrived, key included if the far end put one in its SDP —
//! the same limit the core's own doc states, and this crate adds nothing
//! that would make it worse.
//!
//! Starting a recording that is already running replaces it rather than
//! refusing, the one place this module's two features disagree in shape with
//! [`crate::record`]'s per-call audio recording, which refuses a second
//! `start` outright. The two are not the same decision to make: an audio
//! recording is a file opened on this end's disk and a second `start` would
//! leave one of the two files with only half a conversation in it, silently.
//! A replay recording has no file yet — [`sipral_stack_recording_stop`] is
//! the only place one is produced — so a second `start` costs nothing but the
//! frames taken since the first, and a caller that meant to keep those would
//! not have asked to start again. Stopping one that was never started is
//! `SIPRAL_STATUS_WRONG_STATE`, the same as `sipral_media_record_stop`
//! answers it, because both are "nothing here to stop" and a caller reads the
//! same status for it whichever recording it asked about.

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
/// The shape every entry point here that hands text back uses:
/// [`crate::error::sipral_last_error_message`] set it, and this crate has had
/// no second one to write text out with until now. `out_needed` always receives
/// the number of bytes `text` needs including a trailing NUL, so a caller
/// that passes a capacity of zero and a null buffer learns the length and
/// gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`. Nothing is written to a buffer too
/// small to hold the whole of it, so a multi-byte character is never cut in
/// half.
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
    // `needed` is at least one, so a capacity that reaches it is not zero and
    // the buffer is therefore not null
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
    /// Readable at any point in the call's life, and for as long after it as
    /// the endpoint has not evicted the record to make room for a newer one —
    /// how many are kept is `sipral_stack_config_t::diagnostic_records`,
    /// 32 when it is zero. A call whose
    /// record has been evicted, or that has had nothing decided about it yet,
    /// answers `SIPRAL_STATUS_OK` with `{}`: an empty record is still a
    /// record, and refusing to read one that happens to be empty would make
    /// a caller unable to tell "nothing yet" from "something went wrong".
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
    /// That is the endpoint's own record — everything decided outside any
    /// call — and then one record per call still held, in the same document,
    /// with the number of records evicted to make room. It is deliberately
    /// the whole of it rather than the endpoint's half: a report that arrives
    /// without the calls it is about answers nothing, and
    /// [`sipral_call_record_json`] is already the way to ask about one call.
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
    /// Start recording the signalling this stack is fed from here on
    /// (`docs/18-replay.md`), on a seed of its own. Starting moves every
    /// branch, tag and `Call-ID` the stack draws from here on onto a fresh
    /// seed, derived one way from the `entropy` `sipral_stack_create` was
    /// given; the recording carries that seed and never `entropy`, and
    /// stopping moves the stack on again, so nothing drawn after the stop
    /// can be worked out from the file. Read `docs/18-replay.md` before
    /// reaching for this: it records what arrives, exactly as it arrived,
    /// and never what this end sent.
    ///
    /// `note` is one line of prose for whoever opens the file later, or null
    /// for none.
    ///
    /// A recording already running is replaced, not refused. Nothing is
    /// written until `sipral_stack_recording_stop`, so a second start costs
    /// only the frames taken since the first; `sipral_media_record_start`
    /// refuses a second start because its file is already open on disk.
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
    /// `SIPRAL_STATUS_WRONG_STATE` when no recording is running, the same
    /// answer `sipral_media_record_stop` gives for the same question about
    /// an audio recording. `SIPRAL_STATUS_WRONG_STATE` again, with the reason
    /// in the last error, when something this session was fed could not go
    /// in the recording — a message with a body that is not text is the one
    /// way that happens — in which case nothing is written to `buffer` and
    /// the recording is not produced at all: a text format that quietly left
    /// out the one message it could not spell would replay into a different
    /// session and say nothing about it.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// text, with the length needed in `out_needed` — asking again with a bigger
    /// buffer answers the same recording rather than stopping a new one,
    /// so a caller that does not yet know how big a buffer to bring may ask
    /// twice: once to be told, once to be handed the text. Once a call here
    /// copies the whole of it out, the recording is gone from the stack, the
    /// same as `sipral_last_error_message` empties the slot it reads on a
    /// call that succeeds.
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
                    // an error is not a matter of buffer size, so there is no
                    // second call to keep it alive for
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

    /// Call `read` with a null buffer to learn the length, then again with a
    /// buffer that size — the two-call shape every text-out entry point here
    /// answers to, proved once rather than at each call site.
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

    /// D1: registering writes at least one decision — the REGISTER this
    /// stack sent — into the endpoint's own record, and it comes back as
    /// well-formed JSON naming the reason `docs/14-diagnostics.md` gives it.
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

    /// D1: a call's own record is reachable by its handle and answers
    /// `{}` before anything has been decided about a stack that has none —
    /// proving the fallback rather than asserting it never runs.
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

    /// D1: a buffer with no room at all reports how much it needs and writes
    /// nothing, the same as `sipral_last_error_message` does.
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

    /// D2: stopping one that was never started is the same
    /// `SIPRAL_STATUS_WRONG_STATE` `sipral_media_record_stop` answers for an
    /// audio recording asked the same question.
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

    /// D2: starting a second recording replaces the first rather than
    /// refusing it — the opposite of what `sipral_media_record_start`
    /// answers for a second audio recording, and `crate::diagnostics` says
    /// why the two features disagree.
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

    /// D2, the reason this feature exists at all: a recording of a live,
    /// answered SRTP call, taken from the caller's own side, does not carry
    /// the key the caller's own offer put on the wire. Proved the same way
    /// `sipral/src/tests.rs` proves it for the layer below — by reading the
    /// key back out of the INVITE this stack actually sent, then reading the
    /// finished recording and asserting that value is nowhere in it.
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

    /// The base64 of this end's own `a=crypto` line, read the same way the
    /// facade's own tests read one (`sipral/src/tests.rs`), so a test that
    /// changed the SDP fixture above would change what this looks for too.
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

    /// D2: a note that would not be one line of text is refused where it is
    /// given, before a recorder is even made — the caller finds out from the
    /// call that took the bad argument rather than from the one that tries
    /// to stop a recording it never knew was spoiled.
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
