// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Calls: placed, answered, held, handed on, hung up.
//!
//! Every call here is named by a handle of this stack's, and every one of them
//! takes the time from the caller, for the same reason poll does: nothing in
//! this library reads a clock, so a retransmission schedule that started at an
//! instant the caller did not name would be one the caller cannot reason
//! about.
//!
//! A call is placed with a session description and answered with one. Offering
//! nothing and letting the far end offer in its 2xx is legal (§13.2.1) and is
//! deliberately not reachable from here: the answer would then have to travel
//! in the ACK, written by an application that has no media layer on this side
//! of the boundary to write it with.
//!
//! DTMF goes out as INFO. RFC 4733's telephone-event lives in the RTP stream,
//! and there is no RTP on this side of the boundary; `application/dtmf-relay`
//! is what every switch that takes DTMF over signalling takes, and it is what
//! a stack with no media path can send.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::sync::Arc;

use sipral_core::endpoint::OutgoingInDialogRequest;
use sipral_core::msg::{HeaderName, Method, StatusCode, Uri};
use sipral_ua::{ForkPolicy, OutgoingCall, UaError};

use crate::error::{Fail, entry, fail};
use crate::event::{SipralCallState, call_state};
use crate::handle::SipralHandle;
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{bytes, required_text, text};
use crate::versioned::{Versioned, read_versioned};

/// What one DTMF tone lasts when the caller does not say (RFC 4733 §2.5.2.2
/// has no figure; every switch that generates one uses about this).
const DEFAULT_DTMF_MS: u32 = 160;

/// Longer than any key is held, and short enough that a caller who passed
/// milliseconds where it meant seconds finds out.
const MAX_DTMF_MS: u32 = 10_000;

/// The sixteen events a keypad has (RFC 4733 §3.2, Table 3).
const KEYPAD: &[u8] = b"0123456789*#ABCD";

/// What a call is placed with.
///
/// Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before
/// filling anything in.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralCallConfig {
    /// `sizeof` this struct, as the caller's header declares it.
    pub size: usize,
    /// Who to call, as a URI. UTF-8, not NUL-terminated.
    pub target: *const c_char,
    /// How many bytes of it.
    pub target_len: usize,
    /// The session description to offer. Required.
    pub sdp: *const u8,
    /// How many bytes of it.
    pub sdp_len: usize,
    /// Where to send the INVITE, as `host:port`, or null to send it where the
    /// account registers — which is the outbound proxy for a registered line,
    /// and the reason a phone behind a NAT works at all.
    pub destination: *const c_char,
    /// How many bytes of it.
    pub destination_len: usize,
    /// Whether to keep every branch a proxy forks the INVITE into. Zero keeps
    /// the first that answers and hangs up the rest, which is what a telephone
    /// does.
    pub keep_all_forks: u32,
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and all-zero is valid: every pointer is null beside a length of
// zero.
unsafe impl Versioned for SipralCallConfig {
    const NAME: &'static str = "sipral_call_config";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// Why the layer below would not do it.
pub(crate) fn ua_failed(error: &UaError) -> Fail {
    let status = match *error {
        // the handle was live here, so the layer below disagreeing means what
        // it named has just gone
        UaError::NoSuchAccount | UaError::NoSuchCall => SipralStatus::StaleHandle,
        UaError::WrongState(_)
        | UaError::NoSession
        | UaError::ChangeInProgress
        | UaError::CannotRenegotiate => SipralStatus::WrongState,
        UaError::Sdp(_) => SipralStatus::InvalidArgument,
        _ => SipralStatus::NotSent,
    };
    fail(status, error.to_string())
}

/// The same, for the endpoint underneath when this ABI drives it directly.
fn send_failed(error: &impl core::fmt::Display) -> Fail {
    fail(SipralStatus::NotSent, error.to_string())
}

fn status_code(code: u32) -> Result<StatusCode, Fail> {
    let refuse = || {
        fail(
            SipralStatus::InvalidArgument,
            format!("{code} is not a SIP status code"),
        )
    };
    let narrowed = u16::try_from(code).map_err(|_| refuse())?;
    StatusCode::new(narrowed).map_err(|_| refuse())
}

fn call_uri(supplied: &str) -> Result<Uri, Fail> {
    Uri::parse_str(supplied).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("target is {supplied:?}, which is not a URI: {error}"),
        )
    })
}

/// The session description a call is placed or answered with.
///
/// # Safety
///
/// `sdp` must be readable for `len` bytes.
unsafe fn description(sdp: *const u8, len: usize) -> Result<Option<Arc<[u8]>>, Fail> {
    Ok(unsafe { bytes(sdp, len, "sdp") }?.map(Arc::from))
}

/// Turn what crossed the boundary into a call to place.
///
/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn outgoing_from(
    state: &StackState,
    config: &SipralCallConfig,
) -> Result<OutgoingCall, Fail> {
    let target = unsafe { required_text(config.target, config.target_len, "target") }?;
    let Some(offer) = (unsafe { description(config.sdp, config.sdp_len) })? else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "a call placed from here carries an offer, because the answer to one that does not \
             has to be written into the ACK",
        ));
    };
    let mut outgoing = OutgoingCall::new(call_uri(target)?).offer(offer);
    if let Some(elsewhere) =
        unsafe { text(config.destination, config.destination_len, "destination") }?
    {
        let Ok(address) = elsewhere.parse::<SocketAddr>() else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("destination is {elsewhere:?}, which is not an address and a port"),
            ));
        };
        outgoing = outgoing.to_address(state.transport, address);
    }
    if config.keep_all_forks != 0 {
        outgoing = outgoing.forks(ForkPolicy::KeepAll);
    }
    if let Some(ref named) = state.user_agent {
        outgoing = outgoing.header(HeaderName::UserAgent, named);
    }
    Ok(outgoing)
}

entry! {
    /// Place a call, and write its handle to `out_call`.
    ///
    /// The handle exists from here on, before any dialog does, because there
    /// has to be something to hang up with while the INVITE is still in
    /// flight. A proxy that forks the INVITE gives the branches handles of
    /// their own, reported as `SIPRAL_EVENT_KIND_CALL_FORKED`.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_call` at one `sipral_handle_t`.
    fn sipral_call_place(
        stack: SipralHandle,
        account: SipralHandle,
        config: *const SipralCallConfig,
        out_call: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_call.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_call is null"));
        }
        let config = unsafe { read_versioned(config) }?;
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            let outgoing = unsafe { outgoing_from(state, &config) }?;
            let placed = state
                .agent
                .call(id, &outgoing, now)
                .map_err(|error| ua_failed(&error))?;
            state
                .calls
                .name_of(placed)
                .map_err(|status| fail(status, "no room for another call on this stack"))
        })?;
        unsafe { out_call.write(handle) };
        Ok(())
    }
}

entry! {
    /// Say a call that came in is ringing.
    ///
    /// A description makes it a 183 Session Progress rather than a 180
    /// Ringing, because 180 with a body is a contradiction the far end has to
    /// guess at. Pass none for the ordinary case.
    ///
    /// # Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    fn sipral_call_ring(
        stack: SipralHandle,
        call: SipralHandle,
        sdp: *const u8,
        sdp_len: usize,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let early = unsafe { description(sdp, sdp_len) }?;
            state
                .agent
                .ring(id, early, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Answer a call that came in.
    ///
    /// `sdp` is the answer to the offer the INVITE carried, and is required:
    /// answering with nothing puts the offer on this end and the answer in the
    /// far end's ACK, which this ABI has no way to hand back.
    ///
    /// # Safety
    ///
    /// `sdp` must be readable for `sdp_len` bytes.
    fn sipral_call_answer(
        stack: SipralHandle,
        call: SipralHandle,
        sdp: *const u8,
        sdp_len: usize,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let Some(answer) = (unsafe { description(sdp, sdp_len) })? else {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    "answering a call needs a session description",
                ));
            };
            state
                .agent
                .answer(id, Some(answer), now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Refuse a call that came in, with a status of your choosing.
    ///
    /// 486 Busy Here for a line that is in use, 603 Decline for a person who
    /// does not want to talk. The difference is what a proxy does next.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_reject(
        stack: SipralHandle,
        call: SipralHandle,
        status: u32,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let status = status_code(status)?;
            state
                .agent
                .reject(id, status, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Hang up, whatever the call is doing.
    ///
    /// A CANCEL before it is answered, a BYE after, a refusal for one that
    /// came in and has not been answered. A call that is already ending is
    /// left alone rather than refused.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_hangup(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .agent
                .hangup(id, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Put a call on hold (RFC 3264 §8.4).
    ///
    /// The description is the stack's to write: the one already negotiated
    /// with every stream's direction changed. Asking for a hold that is
    /// already in place sends nothing and succeeds.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_hold(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state.agent.hold(id, now).map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Take it off hold again.
    ///
    /// Every stream goes back to the direction it had before, which is not
    /// always both ways: one that was offered receive-only is resumed
    /// receive-only.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_resume(stack: SipralHandle, call: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .agent
                .resume(id, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Accept a change the far end offered, reported as
    /// `SIPRAL_EVENT_KIND_SESSION_OFFERED`.
    ///
    /// `sdp` is the answer to the offer it carried, and is left out only for a
    /// request that carried none. A re-INVITE nobody answers is retransmitted
    /// and then ends the call, so this or [`sipral_call_reject_session`] has
    /// to follow that event.
    ///
    /// # Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    fn sipral_call_accept_session(
        stack: SipralHandle,
        call: SipralHandle,
        sdp: *const u8,
        sdp_len: usize,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let answer = unsafe { bytes(sdp, sdp_len, "sdp") }?;
            state
                .agent
                .accept_reoffer(id, answer, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Refuse one instead. The session stands exactly as it was (§14.1).
    ///
    /// 488 Not Acceptable Here is the status that says the description was the
    /// problem rather than the request.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_reject_session(
        stack: SipralHandle,
        call: SipralHandle,
        status: u32,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let status = status_code(status)?;
            state
                .agent
                .reject_reoffer(id, status, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Send DTMF on a call that is up, one INFO per digit.
    ///
    /// `digits` are `0` to `9`, `*`, `#` and `A` to `D`, the sixteen events of
    /// RFC 4733 §3.2, in the order they were pressed. `duration_ms` is how
    /// long each one is said to have been held, or zero for 160 ms.
    ///
    /// # Safety
    ///
    /// `digits` must be readable for `digits_len` bytes.
    fn sipral_call_send_dtmf(
        stack: SipralHandle,
        call: SipralHandle,
        digits: *const c_char,
        digits_len: usize,
        duration_ms: u32,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let pressed = unsafe { required_text(digits, digits_len, "digits") }?;
            let keys = keypad(pressed)?;
            let held = tone_length(duration_ms)?;
            let Some(dialog) = state.agent.call_dialog(id) else {
                return Err(fail(
                    SipralStatus::WrongState,
                    "the call has no dialog to send an INFO in, so it is not up yet",
                ));
            };
            for key in keys {
                let request = OutgoingInDialogRequest::new(Method::Info)
                    .body(b"application/dtmf-relay", dtmf_body(key, held));
                state
                    .agent
                    .endpoint()
                    .request_in_dialog(dialog, &request, now)
                    .map_err(|error| send_failed(&error))?;
            }
            Ok(())
        })
    }
}

/// The digits, upper-cased, or which one was not a key.
fn keypad(pressed: &str) -> Result<Vec<u8>, Fail> {
    let mut keys = Vec::with_capacity(pressed.len());
    for (index, key) in pressed.bytes().enumerate() {
        let key = key.to_ascii_uppercase();
        if !KEYPAD.contains(&key) {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("digit {index} is not one of the sixteen a keypad has"),
            ));
        }
        keys.push(key);
    }
    if keys.is_empty() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "there are no digits to send",
        ));
    }
    Ok(keys)
}

fn tone_length(duration_ms: u32) -> Result<u32, Fail> {
    match duration_ms {
        0 => Ok(DEFAULT_DTMF_MS),
        held if held <= MAX_DTMF_MS => Ok(held),
        held => Err(fail(
            SipralStatus::InvalidArgument,
            format!("a tone of {held} ms is longer than any key is held"),
        )),
    }
}

/// One key, in the two lines every switch that takes DTMF over signalling
/// reads: which event it was, and for how long.
fn dtmf_body(key: u8, duration_ms: u32) -> Arc<[u8]> {
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(b"Signal=");
    body.push(key);
    body.extend_from_slice(b"\r\nDuration=");
    body.extend_from_slice(duration_ms.to_string().as_bytes());
    body.extend_from_slice(b"\r\n");
    Arc::from(body)
}

entry! {
    /// Ask the far end to call somebody else, and hang up when it has
    /// (RFC 3515).
    ///
    /// A blind transfer: nobody consults the destination first. This end stays
    /// in the call until the transfer has succeeded, because hanging up first
    /// turns a transfer that failed into a call that vanished. Progress
    /// arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS` and then
    /// `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
    ///
    /// # Safety
    ///
    /// `target` must be readable for `target_len` bytes.
    fn sipral_call_transfer(
        stack: SipralHandle,
        call: SipralHandle,
        target: *const c_char,
        target_len: usize,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let target = unsafe { required_text(target, target_len, "target") }?;
            let target = call_uri(target)?;
            state
                .agent
                .transfer(id, &target, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Call the transfer target, so that there is somebody to hand the call
    /// to, and write the new call's handle to `out_call`.
    ///
    /// The consultation leg of an attended transfer. It is answered like any
    /// other call, and [`sipral_call_transfer_to`] is what follows. Putting
    /// `call` on hold first is the application's: it is a session change, and
    /// this stack does not make those uninvited.
    ///
    /// # Safety
    ///
    /// As [`sipral_call_place`].
    fn sipral_call_consult(
        stack: SipralHandle,
        call: SipralHandle,
        config: *const SipralCallConfig,
        out_call: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_call.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_call is null"));
        }
        let config = unsafe { read_versioned(config) }?;
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let outgoing = unsafe { outgoing_from(state, &config) }?;
            let placed = state
                .agent
                .consult(id, &outgoing, now)
                .map_err(|error| ua_failed(&error))?;
            state
                .calls
                .name_of(placed)
                .map_err(|status| fail(status, "no room for another call on this stack"))
        })?;
        unsafe { out_call.write(handle) };
        Ok(())
    }
}

entry! {
    /// Hand `call` to the far end of `other` (RFC 3891).
    ///
    /// The attended half of a transfer: `other` is normally the consultation
    /// call, and the party at its far end replaces the call it already has
    /// rather than answering a second one. Any call that is up may be named.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_transfer_to(
        stack: SipralHandle,
        call: SipralHandle,
        other: SipralHandle,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let other = state.calls.get(other).map_err(handle_failed)?;
            state
                .agent
                .transfer_to(id, other, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Take a transfer that was asked for, place the call it names, and write
    /// that call's handle to `out_call`.
    ///
    /// # Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`.
    fn sipral_call_accept_transfer(
        stack: SipralHandle,
        call: SipralHandle,
        out_call: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_call.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_call is null"));
        }
        let handle = with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let placed = state
                .agent
                .accept_transfer(id, now)
                .map_err(|error| ua_failed(&error))?;
            state
                .calls
                .name_of(placed)
                .map_err(|status| fail(status, "no room for another call on this stack"))
        })?;
        unsafe { out_call.write(handle) };
        Ok(())
    }
}

entry! {
    /// Refuse one instead.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_reject_transfer(
        stack: SipralHandle,
        call: SipralHandle,
        status: u32,
        now_ms: u64,
    ) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let status = status_code(status)?;
            state
                .agent
                .reject_transfer(id, status, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Where a call is, as a `SipralCallState`.
    ///
    /// A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the
    /// poll that delivers `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, and
    /// `SIPRAL_STATUS_STALE_HANDLE` after that.
    ///
    /// # Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    fn sipral_call_state(stack: SipralHandle, call: SipralHandle, out_state: *mut u32) {
        if out_state.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_state is null"));
        }
        let state = with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let where_it_is = state.agent.call_state(id).map_or(
                // the handle is still ours and the layer below has let the
                // call go, which is what being over looks like from here
                SipralCallState::Terminated,
                |state| call_state(Some(state)),
            );
            Ok(where_it_is as u32)
        })?;
        unsafe { out_state.write(state) };
        Ok(())
    }
}

entry! {
    /// Which way a call is held: `out_here` is set when this end asked the far
    /// end to stop sending, `out_there` when the far end asked this one.
    /// Either may be null.
    ///
    /// # Safety
    ///
    /// `out_here` and `out_there` must each be null or point at one
    /// `uint32_t`.
    fn sipral_call_hold_state(
        stack: SipralHandle,
        call: SipralHandle,
        out_here: *mut u32,
        out_there: *mut u32,
    ) {
        let held = with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state.agent.hold_state(id).ok_or_else(|| {
                fail(
                    SipralStatus::WrongState,
                    "the call has described nothing yet, so it is held neither way",
                )
            })
        })?;
        if !out_here.is_null() {
            unsafe { out_here.write(u32::from(held.local)) };
        }
        if !out_there.is_null() {
            unsafe { out_there.write(u32::from(held.remote)) };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralCallConfig, dtmf_body, keypad, sipral_call_accept_session, sipral_call_answer,
        sipral_call_consult, sipral_call_hangup, sipral_call_hold, sipral_call_hold_state,
        sipral_call_place, sipral_call_reject, sipral_call_reject_session, sipral_call_resume,
        sipral_call_ring, sipral_call_send_dtmf, sipral_call_state, sipral_call_transfer,
        sipral_call_transfer_to, tone_length,
    };
    use crate::account::{SipralAccountConfig, sipral_account_add};
    use crate::error::last_error_text;
    use crate::event::{SipralCallState, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::{Observed, poll, stack};
    use crate::stack::{sipral_stack_destroy, with_stack};
    use crate::status::SipralStatus;
    use sipral_core::endpoint::Input;
    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};
    use std::ffi::c_char;
    use std::net::SocketAddr;
    use std::ptr;

    const AOR: &str = "sip:alice@example.com";
    const REGISTRAR: &str = "sip:example.com";
    const CONTACT: &str = "sip:alice@192.0.2.10:5060";
    const PEER: &str = "203.0.113.5:5060";
    const TARGET: &str = "sip:bob@example.com";

    const OFFER: &[u8] = b"v=0\r\n\
o=alice 1 1 IN IP4 192.0.2.10\r\n\
s=-\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 40000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

    const ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

    /// What the far end answers a hold with: it will receive, and not send
    /// (RFC 3264 §6.1).
    const HELD_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 2 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=recvonly\r\n";

    fn as_text(value: &str) -> (*const c_char, usize) {
        (value.as_ptr().cast::<c_char>(), value.len())
    }

    fn peer() -> SocketAddr {
        PEER.parse().expect("a written address")
    }

    fn local() -> SocketAddr {
        crate::stack::tests::BIND
            .parse()
            .expect("a written address")
    }

    fn account_config() -> SipralAccountConfig {
        let (aor, aor_len) = as_text(AOR);
        let (registrar, registrar_len) = as_text(REGISTRAR);
        let (contact, contact_len) = as_text(CONTACT);
        let (registrar_address, registrar_address_len) = as_text(PEER);
        SipralAccountConfig {
            size: size_of::<SipralAccountConfig>(),
            aor,
            aor_len,
            registrar,
            registrar_len,
            contact,
            contact_len,
            registrar_address,
            registrar_address_len,
            display_name: ptr::null(),
            display_name_len: 0,
            auth_user: ptr::null(),
            auth_user_len: 0,
            auth_password: ptr::null(),
            auth_password_len: 0,
            instance_id: ptr::null(),
            instance_id_len: 0,
            expires_seconds: 0,
        }
    }

    fn call_config() -> SipralCallConfig {
        let (target, target_len) = as_text(TARGET);
        SipralCallConfig {
            size: size_of::<SipralCallConfig>(),
            target,
            target_len,
            sdp: OFFER.as_ptr(),
            sdp_len: OFFER.len(),
            destination: ptr::null(),
            destination_len: 0,
            keep_all_forks: 0,
        }
    }

    /// A stack with one account, ready to place a call.
    fn line(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        let config = account_config();
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        (handle, account)
    }

    fn place(
        stack: SipralHandle,
        account: SipralHandle,
        config: &SipralCallConfig,
        now_ms: u64,
    ) -> (SipralStatus, SipralHandle) {
        let mut call = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_place(stack, account, ptr::from_ref(config), &raw mut call, now_ms)
        };
        (status, call)
    }

    fn state_of(stack: SipralHandle, call: SipralHandle) -> u32 {
        let mut state = u32::MAX;
        let status = unsafe { sipral_call_state(stack, call, &raw mut state) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        state
    }

    /// What the stack wanted written, taken before a poll drops it.
    fn sent(stack: SipralHandle) -> Vec<Vec<u8>> {
        with_stack(stack, |state| {
            let mut all = Vec::new();
            while let Some(transmit) = state.agent.poll_transmit() {
                all.push(transmit.payload.to_vec());
            }
            Ok(all)
        })
        .expect("the stack is live")
    }

    /// The one message the stack wanted written.
    fn one(stack: SipralHandle) -> Vec<u8> {
        let mut all = sent(stack);
        assert_eq!(all.len(), 1, "expected exactly one message out");
        all.pop().unwrap_or_default()
    }

    fn field(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message");
        message.header(name).unwrap_or_default().to_vec()
    }

    fn start_line(bytes: &[u8]) -> String {
        String::from_utf8_lossy(
            bytes
                .split(|byte| *byte == b'\r')
                .next()
                .unwrap_or_default(),
        )
        .into_owned()
    }

    /// The 200 the far end answers an INVITE with: the same dialog, a tag of
    /// its own, somewhere to send the ACK, and the answer to the offer.
    ///
    /// The tag is added only to the first one. A re-INVITE goes out inside a
    /// dialog whose `To` already carries it, and a second tag would name a
    /// dialog nobody is in.
    fn accepted(request: &[u8], body: &[u8], first: bool) -> Vec<u8> {
        let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
        for (name, value) in [
            ("Via", field(request, HeaderName::Via)),
            ("From", field(request, HeaderName::From)),
            ("To", {
                let mut to = field(request, HeaderName::To);
                if first {
                    to.extend_from_slice(b";tag=farend");
                }
                to
            }),
            ("Call-ID", field(request, HeaderName::CallId)),
            ("CSeq", field(request, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Contact: <sip:bob@203.0.113.5:5060>\r\n");
        out.extend_from_slice(b"Content-Type: application/sdp\r\n");
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out
    }

    fn deliver(stack: SipralHandle, message: &[u8], now_ms: u64) {
        with_stack(stack, |state| {
            let now = state.instant(now_ms)?;
            let transport = state.transport;
            state
                .agent
                .receive(
                    Input::Datagram {
                        transport,
                        remote: peer(),
                        local: local(),
                        data: message,
                    },
                    now,
                )
                .expect("a well formed datagram");
            Ok(())
        })
        .expect("the stack is live");
    }

    /// A call this end placed and the far end answered.
    fn connected(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let (handle, account) = line(observed);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        assert!(start_line(&invite).starts_with("INVITE"));
        deliver(handle, &accepted(&invite, ANSWER, true), 1_100);
        let result = poll(handle, 1_100);
        assert!(result.events_delivered >= 2);
        assert_eq!(
            state_of(handle, call),
            SipralCallState::Confirmed as u32,
            "the call did not come up"
        );
        (handle, call)
    }

    /// An INVITE from somebody else, addressed here.
    fn invitation() -> Vec<u8> {
        let mut out = b"INVITE sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-a-call-in\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=farend\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: a-call-in@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@203.0.113.5:5060>\r\n\
Content-Type: application/sdp\r\n"
            .to_vec();
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", ANSWER.len()).as_bytes());
        out.extend_from_slice(ANSWER);
        out
    }

    /// The handle the one incoming-call event named.
    fn called(observed: &Observed) -> SipralHandle {
        observed
            .events
            .iter()
            .zip(observed.named.iter())
            .find(|(event, _)| event.1 == SipralEventKind::IncomingCall)
            .map(|(_, named)| named.1)
            .expect("an incoming call was reported")
    }

    #[test]
    fn a_call_that_comes_in_is_named_reported_ringing_and_answered() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        assert_ne!(call, SIPRAL_HANDLE_NONE);
        assert_eq!(state_of(handle, call), SipralCallState::Incoming as u32);
        // the 100 Trying the core sent by itself
        let _ = sent(handle);

        assert_eq!(
            unsafe { sipral_call_ring(handle, call, ptr::null(), 0, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(start_line(&one(handle)).starts_with("SIP/2.0 180"));
        assert_eq!(state_of(handle, call), SipralCallState::Ringing as u32);

        assert_eq!(
            unsafe { sipral_call_answer(handle, call, ANSWER.as_ptr(), ANSWER.len(), 1_200) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let accepted = one(handle);
        assert!(start_line(&accepted).starts_with("SIP/2.0 200"));
        assert_eq!(
            field(&accepted, HeaderName::ContentType),
            b"application/sdp"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_that_comes_in_can_be_refused_with_the_status_it_deserves() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        deliver(handle, &invitation(), 1_000);
        poll(handle, 1_000);
        let call = called(&observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_reject(handle, call, 603, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(start_line(&one(handle)).starts_with("SIP/2.0 603"));
        poll(handle, 1_100);
        assert!(observed.kinds().contains(&SipralEventKind::CallEnded));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_is_placed_and_the_invite_goes_out() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(call, SIPRAL_HANDLE_NONE);
        assert_eq!(state_of(handle, call), SipralCallState::Calling as u32);
        let invite = one(handle);
        assert!(start_line(&invite).starts_with("INVITE sip:bob@example.com"));
        assert_eq!(field(&invite, HeaderName::ContentType), b"application/sdp");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_placed_without_an_offer_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let mut config = call_config();
        config.sdp = ptr::null();
        config.sdp_len = 0;
        assert_eq!(
            place(handle, account, &config, 0).0,
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The rule that an offerless INVITE gets its answer in the ACK is
    /// RFC 3261 §13.2.1 (Creating the Initial INVITE); §14.1 is UAC behavior
    /// for a re-INVITE that modifies a session already up, a different rule
    /// this same file cites correctly elsewhere. The needle is assembled at
    /// runtime so this test does not just match its own assertion.
    #[test]
    fn the_module_doc_cites_the_section_that_puts_the_answer_in_the_ack() {
        let source = include_str!("call.rs");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("is legal ({section}13.2.1) and is")),
            "offering nothing and answering in the ACK is §13.2.1, not §14.1"
        );
    }

    #[test]
    fn a_target_that_is_not_a_uri_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let mut config = call_config();
        (config.target, config.target_len) = as_text("bob");
        assert_eq!(
            place(handle, account, &config, 0).0,
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_destination_that_is_a_name_is_refused_because_nothing_here_resolves_one() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let mut config = call_config();
        (config.destination, config.destination_len) = as_text("proxy.example.com:5060");
        assert_eq!(
            place(handle, account, &config, 0).0,
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn placing_a_call_on_an_account_that_is_gone_is_stale() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        assert_eq!(
            unsafe { crate::account::sipral_account_remove(handle, account) },
            SipralStatus::Ok
        );
        assert_eq!(
            place(handle, account, &call_config(), 0).0,
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_that_was_answered_is_confirmed_and_the_application_is_told() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        assert!(
            observed.kinds().contains(&SipralEventKind::CallConfirmed),
            "{:?}",
            observed.kinds()
        );
        let named = observed
            .events
            .iter()
            .zip(observed.named.iter())
            .find(|(event, _)| event.1 == SipralEventKind::CallConfirmed)
            .map(|(_, named)| named.1);
        assert_eq!(named, Some(call), "the event names the call it is about");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    fn held_state(stack: SipralHandle, call: SipralHandle) -> (u32, u32) {
        let mut here = u32::MAX;
        let mut there = u32::MAX;
        let status = unsafe { sipral_call_hold_state(stack, call, &raw mut here, &raw mut there) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        (here, there)
    }

    #[test]
    fn holding_a_call_that_is_up_writes_the_description_and_sends_it() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_hold(handle, call, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let reinvite = one(handle);
        assert!(start_line(&reinvite).starts_with("INVITE"));
        let offered = String::from_utf8_lossy(&reinvite).into_owned();
        assert!(
            offered.contains("a=sendonly"),
            "the held description is not the one that went out: {offered}"
        );
        assert_eq!(
            held_state(handle, call),
            (0, 0),
            "the hold is offered, and it is not in effect until it is taken"
        );

        deliver(handle, &accepted(&reinvite, HELD_ANSWER, false), 2_100);
        poll(handle, 2_100);
        assert_eq!(held_state(handle, call), (1, 0));
        assert!(
            observed.kinds().contains(&SipralEventKind::SessionChanged),
            "{:?}",
            observed.kinds()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// `HELD_ANSWER` carries `a=recvonly`, which per RFC 4566 means the party
    /// that wrote it — the far end — will receive and not send. The doc
    /// comment above the constant had the two swapped. The needle is
    /// assembled at runtime so this test does not just match its own
    /// assertion.
    #[test]
    fn the_held_answer_doc_matches_what_recvonly_means() {
        let source = include_str!("call.rs");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!(
                "it will receive, and not send\n    /// (RFC 3264 {section}6.1)"
            )),
            "a=recvonly means the far end receives and does not send"
        );
    }

    #[test]
    fn resuming_a_call_that_was_never_held_sends_nothing_and_succeeds() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_resume(handle, call, 2_000) },
            SipralStatus::Ok
        );
        assert!(sent(handle).is_empty());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn holding_a_call_that_is_not_up_says_so_rather_than_saying_nothing() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        assert_eq!(
            unsafe { sipral_call_hold(handle, call, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn dtmf_goes_out_as_one_info_per_key() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        let (digits, digits_len) = as_text("1#d");
        assert_eq!(
            unsafe { sipral_call_send_dtmf(handle, call, digits, digits_len, 0, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let written = sent(handle);
        assert_eq!(written.len(), 3, "one INFO per key");
        for (message, expected) in written.iter().zip(["Signal=1", "Signal=#", "Signal=D"]) {
            assert!(start_line(message).starts_with("INFO"));
            assert_eq!(
                field(message, HeaderName::ContentType),
                b"application/dtmf-relay"
            );
            let body = String::from_utf8_lossy(message).into_owned();
            assert!(body.contains(expected), "{body}");
            assert!(body.contains("Duration=160"), "{body}");
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn what_this_abi_has_no_word_for_is_counted_rather_than_delivered() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        poll(handle, 1_000);
        // an OPTIONS is what a proxy pings a phone with, and this vocabulary
        // has no word for one; the count is what admits that rather than a
        // silence the caller cannot tell from nothing happening
        let ping = b"OPTIONS sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-are-you-there\r\n\
Max-Forwards: 70\r\n\
From: <sip:proxy@example.com>;tag=asking\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: are-you-there@203.0.113.5\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
        deliver(handle, ping, 1_100);

        let before = observed.events.len();
        let result = poll(handle, 1_100);
        assert_eq!(
            result.events_unclaimed, 1,
            "the OPTIONS was neither delivered nor counted"
        );
        assert_eq!(
            observed.events.len(),
            before,
            "and nothing carrying no information reached the callback"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn dtmf_on_a_call_that_is_not_up_says_so() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        let (digits, digits_len) = as_text("1");
        assert_eq!(
            unsafe { sipral_call_send_dtmf(handle, call, digits, digits_len, 0, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn only_the_sixteen_keys_a_keypad_has_are_digits() {
        assert_eq!(
            keypad("0123456789*#ABCD").ok(),
            Some(b"0123456789*#ABCD".to_vec())
        );
        assert_eq!(keypad("abcd").ok(), Some(b"ABCD".to_vec()));
        for refused in ["1 2", "E", "1e", "", "+", "\u{00e9}"] {
            assert!(
                keypad(refused).is_err(),
                "{refused:?} was taken for a keypad"
            );
        }
    }

    /// RFC 4733's section 3 has only 3.1, 3.2 and 3.3; the sixteen DTMF event
    /// codes are Table 3 in 3.2. A doc comment pointing at a section that
    /// does not exist is a defect cbindgen would copy into the public header
    /// verbatim, so it is checked here rather than left to be noticed by eye.
    ///
    /// The needles are assembled at runtime, not written as one literal, so
    /// this test inspecting its own file does not just match itself.
    #[test]
    fn the_keypad_doc_cites_a_section_rfc_4733_actually_has() {
        let source = include_str!("call.rs");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("(RFC 4733 {section}3.2, Table 3)")),
            "the KEYPAD constant should point at Table 3 in §3.2"
        );
        assert!(
            source.contains(&format!(
                "RFC 4733 {section}3.2, in the order they were pressed"
            )),
            "sipral_call_send_dtmf's doc should point at §3.2 as well"
        );
    }

    #[test]
    fn a_tone_length_nobody_holds_a_key_for_is_refused() {
        assert_eq!(tone_length(0).ok(), Some(super::DEFAULT_DTMF_MS));
        assert_eq!(tone_length(100).ok(), Some(100));
        assert_eq!(
            tone_length(super::MAX_DTMF_MS).ok(),
            Some(super::MAX_DTMF_MS)
        );
        assert!(tone_length(super::MAX_DTMF_MS + 1).is_err());
        assert!(tone_length(u32::MAX).is_err());
    }

    #[test]
    fn one_key_is_two_lines() {
        let body = dtmf_body(b'5', 160);
        assert_eq!(body.as_ref(), b"Signal=5\r\nDuration=160\r\n");
    }

    #[test]
    fn hanging_up_a_call_that_is_up_sends_a_bye_and_ends_it() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        assert_eq!(
            unsafe { sipral_call_hangup(handle, call, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let bye = one(handle);
        assert!(start_line(&bye).starts_with("BYE"));
        // the BYE is out and the dialog is gone with it; what is left is the
        // event that says so, and the handle lives until it is delivered
        assert_eq!(state_of(handle, call), SipralCallState::Terminated as u32);

        poll(handle, 2_000);
        assert!(observed.kinds().contains(&SipralEventKind::CallEnded));
        let mut state = u32::MAX;
        assert_eq!(
            unsafe { sipral_call_state(handle, call, &raw mut state) },
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_that_was_hung_up_answers_stale_to_a_second_attempt() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        assert_eq!(
            unsafe { sipral_call_hangup(handle, call, 2_000) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_call_hangup(handle, call, 2_001) },
            SipralStatus::StaleHandle,
            "the call is gone from the moment it ends, not from the poll that says so"
        );
        assert_eq!(
            unsafe { sipral_call_hold(handle, call, 2_002) },
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_this_end_placed_cannot_be_answered_or_rejected_as_if_it_came_in() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        assert_eq!(
            unsafe { sipral_call_answer(handle, call, ANSWER.as_ptr(), ANSWER.len(), 0) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_reject(handle, call, 486, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn answering_with_no_description_is_refused_before_the_state_is_looked_at() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        assert_eq!(
            unsafe { sipral_call_answer(handle, call, ptr::null(), 0, 0) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_number_that_is_not_a_status_code_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        for refused in [0_u32, 99, 700, 1_000, u32::MAX] {
            assert_eq!(
                unsafe { sipral_call_reject(handle, call, refused, 0) },
                SipralStatus::InvalidArgument,
                "{refused} was taken for a status code"
            );
            assert_eq!(
                unsafe { sipral_call_reject_session(handle, call, refused, 0) },
                SipralStatus::InvalidArgument
            );
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_transfer_of_a_call_that_is_not_up_says_so() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 0);
        let (target, target_len) = as_text("sip:carol@example.com");
        assert_eq!(
            unsafe { sipral_call_transfer(handle, call, target, target_len, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_transfer_to(handle, call, call, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_blind_transfer_of_a_call_that_is_up_sends_a_refer() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        let _ = sent(handle);
        let (target, target_len) = as_text("sip:carol@example.com");
        assert_eq!(
            unsafe { sipral_call_transfer(handle, call, target, target_len, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let refer = one(handle);
        assert!(start_line(&refer).starts_with("REFER"));
        let body = String::from_utf8_lossy(&refer).into_owned();
        assert!(body.contains("sip:carol@example.com"), "{body}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_consultation_call_is_a_call_of_its_own() {
        let mut observed = Observed::default();
        let (handle, first) = connected(&mut observed);
        let _ = sent(handle);
        let config = call_config();
        let mut second = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_call_consult(
                handle,
                first,
                ptr::from_ref(&config),
                &raw mut second,
                2_000,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(second, first);
        assert_eq!(state_of(handle, second), SipralCallState::Calling as u32);
        assert!(start_line(&one(handle)).starts_with("INVITE"));
        // handing the first call to a leg that is still ringing is refused:
        // there is no dialog to name in a Replaces
        assert_eq!(
            unsafe { sipral_call_transfer_to(handle, first, second, 2_100) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn accepting_a_change_nobody_offered_says_so() {
        let mut observed = Observed::default();
        let (handle, call) = connected(&mut observed);
        assert_eq!(
            unsafe { sipral_call_accept_session(handle, call, ptr::null(), 0, 2_000) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_reject_session(handle, call, 488, 2_000) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_handle_from_one_stack_does_not_open_another() {
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let (first, account) = line(&mut first_observed);
        let (second, _) = line(&mut second_observed);
        let (_, call) = place(first, account, &call_config(), 0);
        assert_eq!(
            unsafe { sipral_call_hangup(second, call, 0) },
            SipralStatus::InvalidHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(first) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(second) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_that_ended_leaves_a_stale_handle_behind() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let (_, call) = place(handle, account, &call_config(), 1_000);
        let invite = one(handle);
        // 486 Busy Here: the call is over and nothing is going to revive it
        let mut refused = b"SIP/2.0 486 Busy Here\r\n".to_vec();
        for name in [
            HeaderName::Via,
            HeaderName::From,
            HeaderName::To,
            HeaderName::CallId,
            HeaderName::CSeq,
        ] {
            refused.extend_from_slice(name.canonical().as_bytes());
            refused.extend_from_slice(b": ");
            refused.extend_from_slice(&field(&invite, name));
            refused.extend_from_slice(b"\r\n");
        }
        refused.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        deliver(handle, &refused, 1_100);
        let result = poll(handle, 1_100);
        assert!(result.events_delivered >= 2);
        assert!(observed.kinds().contains(&SipralEventKind::CallEnded));
        let mut state = u32::MAX;
        assert_eq!(
            unsafe { sipral_call_state(handle, call, &raw mut state) },
            SipralStatus::StaleHandle,
            "the handle outlived the call it named"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_null_out_parameter_is_a_bad_argument() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let config = call_config();
        assert_eq!(
            unsafe {
                sipral_call_place(handle, account, ptr::from_ref(&config), ptr::null_mut(), 0)
            },
            SipralStatus::InvalidArgument
        );
        let (_, call) = place(handle, account, &config, 0);
        assert_eq!(
            unsafe { sipral_call_state(handle, call, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn every_call_entry_point_refuses_a_handle_that_names_nothing() {
        let mut observed = Observed::default();
        let (handle, _) = line(&mut observed);
        let (digits, digits_len) = as_text("1");
        let (target, target_len) = as_text(TARGET);
        let refused = [
            unsafe { sipral_call_hangup(handle, SIPRAL_HANDLE_NONE, 0) },
            unsafe { sipral_call_hold(handle, SIPRAL_HANDLE_NONE, 0) },
            unsafe { sipral_call_resume(handle, SIPRAL_HANDLE_NONE, 0) },
            unsafe { sipral_call_reject(handle, SIPRAL_HANDLE_NONE, 486, 0) },
            unsafe {
                sipral_call_answer(handle, SIPRAL_HANDLE_NONE, ANSWER.as_ptr(), ANSWER.len(), 0)
            },
            unsafe { sipral_call_send_dtmf(handle, SIPRAL_HANDLE_NONE, digits, digits_len, 0, 0) },
            unsafe { sipral_call_transfer(handle, SIPRAL_HANDLE_NONE, target, target_len, 0) },
            unsafe { sipral_call_transfer_to(handle, SIPRAL_HANDLE_NONE, SIPRAL_HANDLE_NONE, 0) },
        ];
        for status in refused {
            assert_eq!(status, SipralStatus::InvalidHandle);
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
