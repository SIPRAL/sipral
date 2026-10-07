// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Turning an INVITE away before C ever hears of it (A8, D7).
//!
//! The work is in `crates/sipral-ua/src/screening.rs`. This module exposes the
//! policy (`sipral_stack_screen`), the rate floor (`sipral_stack_invite_limit`)
//! and the counters of what either refused.
//!
//! **The policy runs inside the stack's lock.** Every other callback, including
//! [`SipralEventCallback`](crate::event::SipralEventCallback), runs after the
//! lock is released (`docs/08-ffi.md`). A screening decision must come before
//! the INVITE does anything, and that INVITE is being read inside
//! `sipral_stack_receive_datagram` or `sipral_stack_receive_stream`, which
//! hold the lock. So [`SipralScreenCallback`] runs inside it.
//!
//! Entry points take the lock without waiting (`stack.rs::lock`) and answer
//! `SIPRAL_STATUS_BUSY` when it is held, so a callback re-entering its own
//! stack gets an error, not a deadlock. Another stack is unaffected.
//! [`crate::stack::sipral_stack_destroy`] on this stack is safe from here: the
//! screening call holds its own share of the stack until it returns.

use std::ffi::{c_char, c_void};
use std::ptr;
use std::time::Duration;

use sipral_core::msg::StatusCode;
use sipral_ua::{Incoming, Rate, RateError, Screen, Screening};

use crate::abi::{alias, constants, record};
use crate::error::{entry, fail};
use crate::handle::SipralHandle;
use crate::stack::with_stack;
use crate::status::SipralStatus;

record! {
    /// What [`SipralScreenCallback`] reads about one INVITE, before it has
    /// had any effect.
    ///
    /// Read `size` first, like [`crate::event::SipralEvent`]. `message` and
    /// `source` borrow from a request still being processed: read nothing after
    /// the callback returns.
    #[derive(Clone, Copy)]
    pub struct SipralScreenRequest {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The stack the INVITE arrived on.
        pub stack: SipralHandle,
        /// The far end of the bytes, as `host:port`. Null and zero for a byte
        /// stream bound without naming its far end.
        pub source: *const c_char,
        /// How many bytes of it.
        pub source_len: usize,
        /// The INVITE, whole and unparsed; `sipral_message_header` and its
        /// companions read headers out of it.
        pub message: *const u8,
        /// How many bytes of it.
        pub message_len: usize,
    }
}

constants! {
    /// The answer that lets an INVITE through.
    ///
    /// Any other answer refuses. Acceptance is 200, not zero, because zero is
    /// what a binding returns when the listener threw, or what an unfilled
    /// answer leaves; neither may admit a call.
    pub const SIPRAL_SCREEN_ACCEPT: u32 = 200;

    /// The default burst: ten INVITEs from one address at once.
    ///
    /// With [`SIPRAL_INVITE_LIMIT_EVERY_MS`], the floor every stack starts with.
    /// An INVITE past it is answered 480 and counted in
    /// `sipral_counters_t::screened_refused_by_rate`; no event is raised.
    pub const SIPRAL_INVITE_LIMIT_BURST: u32 = 10;

    /// The default interval: one more INVITE every two seconds.
    pub const SIPRAL_INVITE_LIMIT_EVERY_MS: u64 = 2_000;

    /// The voice-agent preset's burst: 128 at once.
    ///
    /// For a headless service taking every call from one trunk or proxy. Use
    /// with [`SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS`]. Equal to the default
    /// `max_dialogs`, so a rush hits that ceiling (503) before the rate.
    pub const SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST: u32 = 128;

    /// The voice-agent preset's interval: one more INVITE every 50 ms.
    pub const SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS: u64 = 50;
}

alias! {
    /// The screening policy: called once per INVITE, before it has any
    /// effect. Installed with [`crate::screening::sipral_stack_screen`].
    ///
    /// **It runs with the stack's lock held** (see the module docs), unlike
    /// [`SipralEventCallback`](crate::event::SipralEventCallback). **It must
    /// not call back into the stack it was given**, from any thread; such a
    /// call is answered `SIPRAL_STATUS_BUSY`. Another stack is fine. It must
    /// not unwind across the boundary.
    ///
    /// `request` and what it points at are valid for this call only.
    ///
    /// **The answer is a SIP status code.** `SIPRAL_SCREEN_ACCEPT` (200) lets
    /// the INVITE through as if no policy were installed. 400 to 699 refuses
    /// with that status. Anything else refuses with 500: zero (a listener that
    /// threw), a 1xx (would leave the transaction open), another 2xx, or a 3xx
    /// (no `Contact` to redirect to).
    pub type SipralScreenCallback = fn(request: *const SipralScreenRequest, user_data: *mut c_void) -> u32;
}

/// A [`Screen`] that hands the decision to a C callback.
///
/// `user_data` is the caller's pointer, never read here, only handed back to
/// `callback`. Screening runs under the stack's lock, so it is called on the
/// one thread inside an entry point on this stack.
struct CScreen {
    stack: SipralHandle,
    callback:
        unsafe extern "C" fn(request: *const SipralScreenRequest, user_data: *mut c_void) -> u32,
    user_data: *mut c_void,
}

// Safety: see the struct's doc comment.
unsafe impl Send for CScreen {}

impl Screen for CScreen {
    fn on_invite(&mut self, invite: &Incoming<'_>) -> Screening {
        let source = invite.source().map(|address| address.to_string());
        let message = invite.request().as_raw().as_bytes();
        let request = SipralScreenRequest {
            size: size_of::<SipralScreenRequest>(),
            stack: self.stack,
            source: source
                .as_deref()
                .map_or(ptr::null(), |text| text.as_ptr().cast::<c_char>()),
            source_len: source.as_deref().map_or(0, str::len),
            message: message.as_ptr(),
            message_len: message.len(),
        };
        // Safety: `callback` is called under the `SipralScreenCallback`
        // contract (no unwind, no re-entry into `self.stack`, enforced by the
        // stack's lock). `request` borrows `message` and `source`, both alive
        // and untouched for this call.
        let answer = unsafe { (self.callback)(&raw const request, self.user_data) };
        if answer == SIPRAL_SCREEN_ACCEPT {
            return Screening::Take;
        }
        // Only a failure status (>= 400) refuses as itself; 1xx, other 2xx
        // and 3xx cannot be carried out, so they are treated like no answer.
        let status = u16::try_from(answer)
            .ok()
            .and_then(|code| StatusCode::new(code).ok())
            .filter(|status| status.get() >= 400)
            .unwrap_or(StatusCode::SERVER_ERROR);
        Screening::Refuse(status)
    }
}

entry! {
    /// Install, replace, or remove the screening policy for one stack.
    ///
    /// Every INVITE that passes [`sipral_stack_invite_limit`] reaches this
    /// callback before ringing, before `SIPRAL_EVENT_KIND_INCOMING_CALL` and
    /// before a call handle exists. A refused INVITE gets the named status
    /// (500 if it does not refuse) and is forgotten: no event, no handle. One
    /// answered `SIPRAL_SCREEN_ACCEPT` arrives as with no policy.
    ///
    /// `NULL` removes the policy. A second call replaces the first, on this
    /// stack only.
    ///
    /// The no re-entry and no unwind rules are on [`SipralScreenCallback`].
    ///
    /// # Safety
    ///
    /// `callback`, when not null, is called on whichever thread is feeding
    /// this stack bytes, while the policy is installed. `user_data` is handed
    /// back untouched and never read here.
    ///
    /// **`user_data` must outlive the last call, which may come after
    /// `sipral_stack_destroy` returns:** a receive already running on another
    /// thread holds its own share of the stack and still asks the policy. Free
    /// it once no thread is inside this stack. Replacing or removing the
    /// policy takes the lock, so once it returns the old callback is not asked
    /// again.
    fn sipral_stack_screen(
        stack: SipralHandle,
        callback: SipralScreenCallback,
        user_data: *mut c_void,
    ) {
        with_stack(stack, |state| {
            match callback {
                Some(callback) => state.agent.screen(CScreen {
                    stack,
                    callback,
                    user_data,
                }),
                None => state.agent.unscreen(),
            }
            Ok(())
        })
    }
}

entry! {
    /// How fast one source address may offer this stack an INVITE (A8).
    ///
    /// `burst` calls from one address pass at once; one more is earned every
    /// `every_ms` (see [`Rate`]). The default is ten, then one every 2000 ms;
    /// loose because most legitimate calls come from the registrar's address.
    ///
    /// A zero `burst` or zero `every_ms` is `SIPRAL_STATUS_INVALID_ARGUMENT`
    /// and changes nothing: one admits no call, the other never limits.
    ///
    /// The floor is checked before [`sipral_stack_screen`]'s policy: a source
    /// past it never reaches the callback and is counted in
    /// `screened_refused_by_rate` or `screened_refused_by_crowding`.
    ///
    /// **It counts by source address.** An INVITE on a byte stream bound
    /// without a far end has no address and always passes to the policy (where
    /// [`SipralScreenRequest::source`] is null). Naming `remote` in
    /// `sipral_stack_transport_bind` puts a stream under this floor.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_stack_invite_limit(stack: SipralHandle, every_ms: u64, burst: u32) {
        let rate = Rate::new(burst, Duration::from_millis(every_ms))
            .map_err(|error: RateError| fail(SipralStatus::InvalidArgument, error.to_string()))?;
        with_stack(stack, |state| {
            state.agent.limit_invites(rate);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SIPRAL_SCREEN_ACCEPT, SipralScreenRequest, sipral_stack_invite_limit, sipral_stack_screen,
    };
    use crate::call::tests::{account_on, deliver, sent};
    use crate::counters::{SipralCounters, sipral_stack_counters};
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    /// An INVITE to this end; `tag` makes `Call-ID` and branch distinct.
    fn invitation(tag: &str) -> Vec<u8> {
        format!(
            "INVITE sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-screening-{tag}\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=screening-{tag}\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: screening-{tag}@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@203.0.113.5:5060>\r\n\
Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    fn start_line(message: &[u8]) -> String {
        let end = message
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .unwrap_or(message.len());
        String::from_utf8_lossy(&message[..end]).into_owned()
    }

    /// Whether any message this stack wanted written starts with `status`.
    fn sent_status(handle: SipralHandle, status: &str) -> bool {
        sent(handle)
            .iter()
            .any(|message| start_line(message).starts_with(status))
    }

    /// A `sipral_counters_t` with every member at zero.
    fn zero_counters() -> SipralCounters {
        SipralCounters {
            size: size_of::<SipralCounters>(),
            registrations_attempted: 0,
            registrations_succeeded: 0,
            registrations_failed_rejected: 0,
            registrations_failed_bad_credentials: 0,
            registrations_failed_unreachable: 0,
            registrations_failed_redirected: 0,
            calls_ended_local_hangup: 0,
            calls_ended_remote_hangup: 0,
            calls_ended_refused: 0,
            calls_ended_cancelled: 0,
            calls_ended_unreachable: 0,
            calls_ended_fork_lost: 0,
            calls_ended_abandoned: 0,
            calls_ended_expired: 0,
            media_gaps: 0,
            jitter_buffer_events: 0,
            stream_transport_wanted: 0,
            active_calls: 0,
            events_dropped: 0,
            farewells_dropped: 0,
            screened_refused_by_policy: 0,
            screened_refused_by_rate: 0,
            screened_refused_by_crowding: 0,
            screened_refused_by_replaces: 0,
            requests_retransmitted: 0,
            responses_retransmitted: 0,
            transactions_timed_out: 0,
            requests_refused_at_limit: 0,
        }
    }

    fn counters_of(handle: SipralHandle) -> SipralCounters {
        let mut out = zero_counters();
        let status = unsafe { sipral_stack_counters(handle, &raw mut out) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        out
    }

    /// A stack with one account, ready to be screened.
    fn line(observed: &mut Observed) -> SipralHandle {
        let handle = stack(observed);
        let _ = account_on(handle);
        handle
    }

    unsafe extern "C" fn accept_all(
        _request: *const SipralScreenRequest,
        _user_data: *mut c_void,
    ) -> u32 {
        SIPRAL_SCREEN_ACCEPT
    }

    /// Refuses with the status in `user_data`, a test-owned `AtomicU32`.
    unsafe extern "C" fn refuse_with_held_status(
        request: *const SipralScreenRequest,
        user_data: *mut c_void,
    ) -> u32 {
        let wanted = unsafe { &*user_data.cast::<AtomicU32>() };
        let seen = unsafe { &*request };
        assert_eq!(seen.size, size_of::<SipralScreenRequest>());
        wanted.load(Ordering::SeqCst)
    }

    /// Takes every INVITE and counts it in `user_data`, a test-owned
    /// `AtomicU32`. Also checks the request.
    unsafe extern "C" fn count_and_take(
        request: *const SipralScreenRequest,
        user_data: *mut c_void,
    ) -> u32 {
        let seen = unsafe { &*request };
        assert_eq!(seen.size, size_of::<SipralScreenRequest>());
        assert!(!seen.message.is_null());
        assert!(seen.message_len > 0);
        let count = unsafe { &*user_data.cast::<AtomicU32>() };
        count.fetch_add(1, Ordering::SeqCst);
        SIPRAL_SCREEN_ACCEPT
    }

    /// Calls back into its own stack (forbidden), stores the status in
    /// `user_data` (an `AtomicI32`), then takes the INVITE.
    unsafe extern "C" fn reenter_and_take(
        request: *const SipralScreenRequest,
        user_data: *mut c_void,
    ) -> u32 {
        let seen = unsafe { &*request };
        let answered = unsafe { &*user_data.cast::<AtomicI32>() };
        let status = unsafe { sipral_stack_invite_limit(seen.stack, 2_000, 10) };
        answered.store(status as i32, Ordering::SeqCst);
        SIPRAL_SCREEN_ACCEPT
    }

    /// Re-entry from a policy is answered `SIPRAL_STATUS_BUSY`, not a
    /// deadlock, and the INVITE is still decided.
    #[test]
    fn a_policy_that_calls_back_into_its_own_stack_is_refused_rather_than_deadlocked() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        let answered = AtomicI32::new(i32::MIN);
        assert_eq!(
            unsafe {
                sipral_stack_screen(
                    handle,
                    Some(reenter_and_take),
                    std::ptr::from_ref(&answered).cast_mut().cast::<c_void>(),
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );

        deliver(handle, &invitation("reentrant"), 1_000);
        poll(handle, 1_000);

        assert_eq!(
            answered.load(Ordering::SeqCst),
            SipralStatus::Busy as i32,
            "a policy that called back into its own stack was not refused where it stood"
        );
        assert!(
            observed.kinds().contains(&SipralEventKind::IncomingCall),
            "the INVITE the policy took did not arrive: {:?}",
            observed.kinds()
        );
    }

    /// An answer that is not a decision refuses with 500. Zero matters most:
    /// it is what a listener that threw returns.
    #[test]
    fn an_answer_that_is_not_a_decision_refuses_rather_than_admits() {
        for (answer, why) in [
            (0_u32, "a listener that threw, or one that answered nothing"),
            (7, "a number that is no SIP status at all"),
            (201, "a 2xx that is not the one acceptance is spelled with"),
            (
                100,
                "a 1xx, which would leave the transaction open for ever",
            ),
            (180, "a 1xx that looks like an answer and is not one"),
            (302, "a 3xx, which redirects nowhere without a Contact"),
        ] {
            let mut observed = Observed::default();
            let handle = line(&mut observed);
            let wanted = AtomicU32::new(answer);
            assert_eq!(
                unsafe {
                    sipral_stack_screen(
                        handle,
                        Some(refuse_with_held_status),
                        std::ptr::from_ref(&wanted).cast_mut().cast::<c_void>(),
                    )
                },
                SipralStatus::Ok,
                "{}",
                last_error_text()
            );

            deliver(handle, &invitation("a"), 1_000);
            poll(handle, 1_000);

            assert!(
                !observed.kinds().contains(&SipralEventKind::IncomingCall),
                "{why}: the INVITE reached the application anyway: {:?}",
                observed.kinds()
            );
            assert!(
                sent_status(handle, "SIP/2.0 500"),
                "{why}: 500 is what an answer nobody can read has to become"
            );
            assert_eq!(counters_of(handle).screened_refused_by_policy, 1, "{why}");
            assert_eq!(
                unsafe { crate::stack::sipral_stack_destroy(handle) },
                SipralStatus::Ok
            );
        }
    }

    #[test]
    fn an_invite_the_policy_refuses_raises_no_incoming_call_event_and_the_counter_moves() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        let wanted = AtomicU32::new(603);
        let status = unsafe {
            sipral_stack_screen(
                handle,
                Some(refuse_with_held_status),
                std::ptr::from_ref(&wanted).cast_mut().cast::<c_void>(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        deliver(handle, &invitation("a"), 1_000);
        poll(handle, 1_000);

        assert!(
            !observed.kinds().contains(&SipralEventKind::IncomingCall),
            "a refused INVITE must never reach the application: {:?}",
            observed.kinds()
        );
        assert!(
            sent_status(handle, "SIP/2.0 603"),
            "the policy's own status was not what went out"
        );

        let read = counters_of(handle);
        assert_eq!(read.screened_refused_by_policy, 1);
        assert_eq!(read.screened_refused_by_rate, 0);
    }

    #[test]
    fn an_invite_the_policy_takes_arrives_exactly_as_it_would_with_no_policy_at_all() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        let status = unsafe { sipral_stack_screen(handle, Some(accept_all), std::ptr::null_mut()) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        deliver(handle, &invitation("b"), 1_000);
        poll(handle, 1_000);

        assert!(
            observed.kinds().contains(&SipralEventKind::IncomingCall),
            "an accepted INVITE was not reported: {:?}",
            observed.kinds()
        );
        assert_eq!(counters_of(handle).screened_refused_by_policy, 0);
    }

    #[test]
    fn a_null_callback_removes_the_policy() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        let wanted = AtomicU32::new(603);
        assert_eq!(
            unsafe {
                sipral_stack_screen(
                    handle,
                    Some(refuse_with_held_status),
                    std::ptr::from_ref(&wanted).cast_mut().cast::<c_void>(),
                )
            },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_stack_screen(handle, None, std::ptr::null_mut()) },
            SipralStatus::Ok
        );

        deliver(handle, &invitation("c"), 1_000);
        poll(handle, 1_000);

        assert!(
            observed.kinds().contains(&SipralEventKind::IncomingCall),
            "removing the policy did not let the next INVITE through: {:?}",
            observed.kinds()
        );
    }

    #[test]
    fn the_request_the_policy_reads_names_the_whole_invite_and_runs_exactly_once() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        let seen = AtomicU32::new(0);
        assert_eq!(
            unsafe {
                sipral_stack_screen(
                    handle,
                    Some(count_and_take),
                    std::ptr::from_ref(&seen).cast_mut().cast::<c_void>(),
                )
            },
            SipralStatus::Ok
        );

        deliver(handle, &invitation("d"), 1_000);
        poll(handle, 1_000);

        assert_eq!(
            seen.load(Ordering::SeqCst),
            1,
            "the policy ran exactly once"
        );
        assert!(observed.kinds().contains(&SipralEventKind::IncomingCall));
    }

    #[test]
    fn a_burst_of_one_admits_the_first_invite_and_the_rate_floor_refuses_the_second() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_invite_limit(handle, 60_000, 1) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );

        deliver(handle, &invitation("e1"), 1_000);
        poll(handle, 1_000);
        assert!(observed.kinds().contains(&SipralEventKind::IncomingCall));

        deliver(handle, &invitation("e2"), 1_010);
        poll(handle, 1_010);
        assert_eq!(
            observed
                .kinds()
                .iter()
                .filter(|kind| **kind == SipralEventKind::IncomingCall)
                .count(),
            1,
            "the second INVITE from the same source must not be reported either: {:?}",
            observed.kinds()
        );
        assert!(sent_status(handle, "SIP/2.0 480"));

        let read = counters_of(handle);
        assert_eq!(read.screened_refused_by_rate, 1);
        assert_eq!(read.screened_refused_by_policy, 0);
    }

    #[test]
    fn a_zero_burst_or_a_zero_interval_is_a_bad_argument_and_changes_nothing() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_invite_limit(handle, 1_000, 0) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_stack_invite_limit(handle, 0, 5) },
            SipralStatus::InvalidArgument
        );
    }

    #[test]
    fn a_stale_handle_is_refused_rather_than_installed_on_nothing() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_stack_screen(handle, Some(accept_all), std::ptr::null_mut()) },
            SipralStatus::StaleHandle
        );
        assert_eq!(
            unsafe { sipral_stack_invite_limit(handle, 1_000, 5) },
            SipralStatus::StaleHandle
        );
        assert_eq!(
            unsafe {
                sipral_stack_screen(SIPRAL_HANDLE_NONE, Some(accept_all), std::ptr::null_mut())
            },
            SipralStatus::InvalidHandle
        );
    }

    /// The published rates are the stack's own, and the preset is accepted.
    #[test]
    fn the_published_rates_are_the_ones_the_stack_applies() {
        use super::{
            SIPRAL_INVITE_LIMIT_BURST, SIPRAL_INVITE_LIMIT_EVERY_MS,
            SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST, SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS,
        };
        use sipral_ua::Rate;
        use std::time::Duration;

        let default = Rate::default();
        assert_eq!(default.burst(), SIPRAL_INVITE_LIMIT_BURST);
        assert_eq!(
            default.every(),
            Some(Duration::from_millis(SIPRAL_INVITE_LIMIT_EVERY_MS))
        );
        let preset = Rate::voice_agent();
        assert_eq!(preset.burst(), SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST);
        assert_eq!(
            preset.every(),
            Some(Duration::from_millis(
                SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS
            ))
        );
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        assert_eq!(
            unsafe {
                sipral_stack_invite_limit(
                    handle,
                    SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS,
                    SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }
}
