// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Turning an INVITE away before C ever hears of it (A8, D7).
//!
//! `crates/sipral-ua/src/screening.rs` already does the work: a policy
//! consulted before a call exists, and a floor that costs a flood nothing
//! more than a token bucket. This module is the two ways an application
//! reaches it — `sipral_stack_screen` for the policy, `sipral_stack_invite_limit`
//! for the floor — and the counters that say what either one refused.
//!
//! **Where this runs is the whole reason it is not a small wrapper.** Every
//! other callback in this ABI, [`SipralEventCallback`](crate::event::SipralEventCallback)
//! included, is answered from outside the stack's own lock: a poll takes what
//! it has to say into a queue and only then lets the lock go, so calling back
//! into the library from inside that callback is an ordinary call
//! (`docs/08-ffi.md`, "Nothing is held while the callback runs"). A screening
//! decision cannot wait for that moment, because it has to be made before the
//! INVITE it is about is allowed to do anything at all, and that INVITE is
//! being read in the middle of the very call — `sipral_stack_receive_datagram`
//! or `sipral_stack_receive_stream` — that is holding the lock. So
//! [`SipralScreenCallback`] runs *inside* it, which nothing else this ABI
//! calls back on does, and its own doc comment says so before it says
//! anything else.
//!
//! **The rule that follows is enforced, not merely written down.** Every
//! entry point that takes a stack takes its lock without waiting
//! (`crates/sipral-ffi/src/stack.rs::lock`); one that finds it already held
//! answers `SIPRAL_STATUS_BUSY` and touches nothing. A screening callback
//! that called back into the very stack it was given — `sipral_stack_poll`,
//! another receive, a hangup — would find that lock held by the call it is
//! itself running inside of, on the very same thread, and would be answered
//! `SIPRAL_STATUS_BUSY` rather than left to deadlock. Calling into a
//! *different* stack is unaffected, since each stack's lock is its own, and
//! [`crate::stack::sipral_stack_destroy`] on *this* stack is safe even from in
//! here, for the same reason it is safe from inside the event callback: the
//! call that is screening holds its own share of the stack until it returns,
//! so nothing is freed underneath it. None of that makes re-entering the
//! library from in here a good idea — it is answered with an error rather
//! than run — which is exactly why the doc comment forbids it outright rather
//! than describing what happens if it is tried anyway.

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
    /// had any effect at all.
    ///
    /// Filled by the library and handed to the callback as a `const`
    /// pointer, the same shape [`crate::event::SipralEvent`] is: read `size`
    /// before anything past it, and read nothing once the callback has
    /// returned, since `message` — and `source`, when it is not null —
    /// borrow from a request that is still in the middle of being processed
    /// and are not this ABI's to keep alive a moment longer. The answer does
    /// not travel in here: the callback returns it.
    #[derive(Clone, Copy)]
    pub struct SipralScreenRequest {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The stack the INVITE arrived on.
        pub stack: SipralHandle,
        /// The far end of the bytes it arrived in, as `host:port` — the same
        /// text form every address in this ABI takes. Null and zero for a
        /// byte stream the application bound without naming its far end.
        pub source: *const c_char,
        /// How many bytes of it.
        pub source_len: usize,
        /// The INVITE, whole and unparsed. `sipral_message_header` and its
        /// three companions read any header out of these bytes the way they
        /// read any other message this ABI hands over.
        pub message: *const u8,
        /// How many bytes of it.
        pub message_len: usize,
    }
}

constants! {
    /// The answer that lets an INVITE through, and the reason it is a status
    /// code rather than a flag.
    ///
    /// A policy answers with what it wants said: 200 to let the call arrive,
    /// or the status to refuse it with. Making acceptance 200 rather than
    /// zero is the whole safety property of this mechanism — zero is what a
    /// binding hands back when the application's listener threw, and what a
    /// caller who filled nothing in leaves behind, and neither of those may
    /// mean "let the stranger in".
    pub const SIPRAL_SCREEN_ACCEPT: u32 = 200;

    /// The burst a stack starts with: ten INVITEs from one address at once.
    ///
    /// With [`SIPRAL_INVITE_LIMIT_EVERY_MS`], the floor every stack has from
    /// `sipral_stack_create` on. An INVITE past it is answered 480 and
    /// counted in `sipral_counters_t::screened_refused_by_rate`; nothing is
    /// raised for it.
    pub const SIPRAL_INVITE_LIMIT_BURST: u32 = 10;

    /// The interval a stack starts with: one more INVITE every two seconds.
    pub const SIPRAL_INVITE_LIMIT_EVERY_MS: u64 = 2_000;

    /// The voice-agent preset's burst: a hundred and twenty-eight at once.
    ///
    /// For a headless service that takes every call from one trunk or proxy,
    /// where the default's ten-then-one-every-two-seconds answers a
    /// campaign's twelfth caller 480. Handed to `sipral_stack_invite_limit`
    /// with [`SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS`]. The burst is the
    /// default `max_dialogs`, so that a rush is turned away by the ceiling on
    /// calls held, with a 503, before it is by the rate.
    pub const SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST: u32 = 128;

    /// The voice-agent preset's interval: one more INVITE every fifty
    /// milliseconds, twenty a second.
    pub const SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS: u64 = 50;
}

alias! {
    /// The screening policy: consulted once for every INVITE, before it has
    /// any effect. Installed with [`crate::screening::sipral_stack_screen`].
    ///
    /// **It runs with the stack's own lock held**, which is the opposite of
    /// [`SipralEventCallback`](crate::event::SipralEventCallback) and is the
    /// whole reason this type's module documentation exists — read it there.
    /// In consequence: **this callback must not call back into the stack it
    /// was given**, on this thread or on any other. Doing so does not
    /// deadlock — every entry point that takes a stack takes its lock
    /// without waiting and answers `SIPRAL_STATUS_BUSY` rather than block —
    /// but it is refused outright rather than relied on, and a policy that
    /// tries it gets an error code back instead of the call it wanted made.
    /// A *different* stack is unaffected. It must not unwind, for the same
    /// reason nothing in this ABI may: a panic that reached C across this
    /// boundary would take the host process with it.
    ///
    /// `request` and everything it points at belong to the library and are
    /// valid for the duration of this one call and no longer.
    ///
    /// **The answer is a SIP status code, and the numbers are chosen so that
    /// no answer at all is a refusal.** `SIPRAL_SCREEN_ACCEPT` — 200 — lets
    /// the INVITE through, exactly as it would arrive with no policy
    /// installed. Anything else is a refusal, answered with that status when
    /// that status refuses — 400 to 699 — and with 500 when it does not.
    ///
    /// Three ranges do not refuse, and each fails the same way. Zero is what
    /// a binding hands back when the application's own listener threw and
    /// the exception was caught at the boundary, and it is no status at all.
    /// A 1xx is a provisional answer: it would leave the caller ringing at a
    /// call this end has already forgotten, holding a server transaction
    /// nothing here will ever answer. A 2xx that is not the one acceptance
    /// is spelled with accepts nothing, and a 3xx redirects nowhere without
    /// a `Contact` this ABI has no way to give it. So a policy whose answer
    /// went missing does not let a stranger in on the strength of it, and a
    /// policy that meant to refuse and named a number that cannot refuse is
    /// a bug to fix rather than a reason to wave one through.
    pub type SipralScreenCallback = fn(request: *const SipralScreenRequest, user_data: *mut c_void) -> u32;
}

/// A [`Screen`] that hands the decision to a C callback.
///
/// # Safety
///
/// `user_data` is the caller's own pointer. Nothing here reads through it;
/// it is only ever handed back to the same `callback` it arrived with, on
/// whichever thread ends up calling into this stack — which, since screening
/// runs with the stack's lock held, is always the one thread that is inside
/// an entry point on it at that moment.
struct CScreen {
    stack: SipralHandle,
    callback:
        unsafe extern "C" fn(request: *const SipralScreenRequest, user_data: *mut c_void) -> u32,
    user_data: *mut c_void,
}

// Safety: see the struct's own doc comment above.
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
        // Safety: `callback` is the caller's own function, called under the
        // contract `SipralScreenCallback`'s doc comment states — it must not
        // unwind, and it must not call back into `self.stack`, which is
        // enforced elsewhere by that stack's own lock rather than by anything
        // here. `request` borrows from `message` and `source`, both alive
        // for the whole of this call and touched by nothing else while it
        // runs.
        let answer = unsafe { (self.callback)(&raw const request, self.user_data) };
        if answer == SIPRAL_SCREEN_ACCEPT {
            return Screening::Take;
        }
        // A refusal is a failure status and nothing else. A status code is
        // anything from 100 to 699, and three of those ranges do not refuse
        // an INVITE: a 1xx leaves the transaction open and the caller ringing
        // at a call this end has already forgotten, a 2xx that is not the one
        // acceptance is spelled with accepts nothing, and a 3xx without a
        // `Contact` redirects nowhere. A policy that named one of those has
        // not made a decision this ABI can carry out, and the rule for that
        // is the rule for an answer that never arrived.
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
    /// Every INVITE that survives [`sipral_stack_invite_limit`] reaches this
    /// callback before anything else does: before ringing, before
    /// `SIPRAL_EVENT_KIND_INCOMING_CALL`, before a call handle exists for
    /// anybody to answer or reject. What the callback refuses is answered
    /// with the SIP status it named — when that status refuses, and with 500
    /// when it does not — and forgotten — no event, no handle,
    /// nothing for the application to clean up — and what it takes, by
    /// answering `SIPRAL_SCREEN_ACCEPT`, arrives exactly as it would with no
    /// policy installed at all.
    ///
    /// `callback` given as `NULL` removes the policy: every INVITE reaches
    /// the application again, the way it did before this was ever called.
    /// Calling this a second time with a callback replaces the first outright,
    /// on this stack alone — a different stack's policy, if it has one, is
    /// untouched.
    ///
    /// The rule that the callback must not call back into this stack, and
    /// must not unwind, is on [`SipralScreenCallback`] and is the reason
    /// this module's own documentation exists; read it there before wiring
    /// one up.
    ///
    /// # Safety
    ///
    /// `callback`, when not null, is called on whichever thread is inside an
    /// entry point that is feeding this stack bytes, for as long as the
    /// policy stays installed. `user_data` is handed back to it untouched on
    /// every call and read by nothing here.
    ///
    /// **Whatever `user_data` points at has to outlive the last call, and the
    /// last call is not `sipral_stack_destroy` returning.** A destroy takes
    /// this thread's share of the stack away; a receive already running on
    /// another thread holds one of its own until it is done, and the policy
    /// it is in the middle of asking is still asked. So the moment to free
    /// what the pointer names is once no thread is inside this stack any
    /// more, which is the application's own knowledge and not something this
    /// ABI can answer. Replacing the policy, or removing it with `NULL`, has
    /// the same shape: it takes the stack's lock, so it cannot run while a
    /// policy is being asked, and once it returns the callback that was
    /// there is not asked again.
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
    /// `burst` calls from one address are let through at once; one more is
    /// earned every `every_ms` after that. What either number means is
    /// exactly what [`Rate`] already means by it — `sipral_stack_create`'s
    /// default is ten at once and one every two thousand milliseconds,
    /// loose on purpose, because in most deployments every legitimate call
    /// arrives from the one address a phone registered with.
    ///
    /// A `burst` of zero, or an `every_ms` of zero, is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` and changes nothing: the first admits
    /// no call ever, the first or the one after a week of quiet, and the
    /// second earns a token in no time, which is a limit that never limits.
    /// There is deliberately no way to ask for that from C, since a
    /// deployment that wants no floor at all can simply never call this.
    ///
    /// The floor is asked before [`sipral_stack_screen`]'s own policy is: a
    /// source that has exhausted it never reaches the callback at all, and is
    /// counted in `sipral_counters_t::screened_refused_by_rate` or
    /// `screened_refused_by_crowding`, never in `screened_refused_by_policy`.
    ///
    /// **It counts by source address, so it counts nothing it cannot name.**
    /// An INVITE that arrived on a byte stream the application bound without
    /// saying where the far end is has no address on it, and this floor lets
    /// every one of those through to the policy — which is where a caller who
    /// cannot identify a stream's far end has to decide, the same way
    /// [`SipralScreenRequest::source`] being null is what it has to decide
    /// on. Naming the far end in `sipral_stack_transport_bind`'s `remote` is
    /// what puts a stream under this floor at all.
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

    /// An INVITE from somebody else, addressed here, distinguished by
    /// `Call-ID` and `Via` branch so that two calls to this in one test are
    /// two different INVITEs rather than a retransmission of the first.
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

    /// A `sipral_counters_t` with every member at zero, the way a stack that
    /// has done nothing reads.
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
        // left at zero, which is what the caller finds it at already
    }

    /// Refuses every INVITE with the status held in `user_data`, an
    /// `AtomicU32` the test owns.
    unsafe extern "C" fn refuse_with_held_status(
        request: *const SipralScreenRequest,
        user_data: *mut c_void,
    ) -> u32 {
        let wanted = unsafe { &*user_data.cast::<AtomicU32>() };
        let seen = unsafe { &*request };
        assert_eq!(seen.size, size_of::<SipralScreenRequest>());
        wanted.load(Ordering::SeqCst)
    }

    /// Takes every INVITE, and counts how many it saw in `user_data`, an
    /// `AtomicU32` the test owns — the request itself is also checked, so
    /// that a policy that never reads it still fails this one.
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

    /// Calls back into the stack it was given — which the contract forbids —
    /// leaves what that answered in `user_data`, an `AtomicI32` the test
    /// owns, and then takes the INVITE.
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

    /// The rule this mechanism's documentation states in three places, and
    /// the reason it is a rule rather than a deadlock.
    ///
    /// A policy runs with the stack's lock held, so it must not call back
    /// into the stack it was given. What happens when one does is not a hang:
    /// every entry point takes that lock without waiting and answers
    /// `SIPRAL_STATUS_BUSY` where it stands. The INVITE it was asked about is
    /// decided all the same — a policy that broke the rule still answered.
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

    /// The safety property of the whole mechanism: an answer that is not a
    /// decision refuses, and 500 is what goes out.
    ///
    /// Zero is the case that matters, because zero is what arrives when the
    /// application's own listener threw and the binding caught it at the
    /// boundary, and it is what a caller who answered nothing at all leaves
    /// behind. A policy whose answer went missing must not wave a stranger
    /// in on the strength of it. The other two are the same rule at the
    /// edges: a number that is no SIP status, and a 2xx that is not the one
    /// number acceptance is spelled with.
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

    /// The numbers the header publishes are the ones the stack runs with,
    /// and the preset is one `sipral_stack_invite_limit` takes.
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
