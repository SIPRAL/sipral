// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! SIP MESSAGE (RFC 3428): one function out, three events in.
//!
//! The protocol (size policy of §8, one pending transaction per URI, the
//! 408/503 of RFC 3261 §8.1.3.1) lives in `sipral-ua`. Message waiting (RFC
//! 3842) is `sipral_account_subscribe` to `message-summary`, which raises
//! `SIPRAL_EVENT_KIND_MESSAGES_WAITING`.

use std::ffi::c_char;

use sipral_core::msg::Uri;

use crate::call::ua_failed;
use crate::error::{entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{handle_failed, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{bytes, required_text};

entry! {
    /// Send an instant message outside any dialog (RFC 3428 §3).
    ///
    /// The handle written back names the send until
    /// `SIPRAL_EVENT_KIND_MESSAGE_SENT` reports its outcome, even a transport
    /// failure. `body` is taken as raw bytes.
    ///
    /// # Safety
    ///
    /// `target` and `content_type` must be readable for their lengths, and
    /// UTF-8. `body` must be readable for `body_len` bytes, or null with a
    /// length of zero. `out_message` must point at one `sipral_handle_t`.
    fn sipral_account_message(
        stack: SipralHandle,
        account: SipralHandle,
        target: *const c_char,
        target_len: usize,
        content_type: *const c_char,
        content_type_len: usize,
        body: *const u8,
        body_len: usize,
        out_message: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_message.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_message is null"));
        }
        let target = unsafe { required_text(target, target_len, "target") }?;
        let Ok(uri) = Uri::parse(target.as_bytes()) else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("target is {target:?}, which is not a URI"),
            ));
        };
        let content_type = unsafe { required_text(content_type, content_type_len, "content_type") }?;
        let body = unsafe { bytes(body, body_len, "body") }?.unwrap_or_default();
        with_stack_at(stack, now_ms, |state, now| {
            let named = state.accounts.get(account).map_err(handle_failed)?;
            let made = state
                .agent
                .message(named, uri.clone(), content_type.as_bytes(), body, now)
                .map_err(|error| ua_failed(&error))?;
            let handle = state.messages.insert(made).map_err(|status| {
                fail(
                    status,
                    "this stack has handed out every message handle it has room for",
                )
            })?;
            unsafe { out_message.write(handle) };
            Ok(())
        })
    }
}
