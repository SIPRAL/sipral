// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! D3's health counters, across the boundary: one struct, one call, one copy.
//!
//! `sipral::Counters` is already cheap to read — a struct copy, nothing
//! walked — and this module does nothing to that but carry it across in the
//! shape every other reading in this ABI takes: a caller-supplied buffer,
//! filled in place, versioned by its own `size` so a build that adds a
//! counter later is still read correctly by a binding compiled against a
//! shorter one.
//!
//! What crosses is flat integers rather than the nested
//! [`sipral::RegistrationFailureCounts`] and [`sipral::CallDispositionCounts`]
//! the Rust API groups them under: C has no tuple structs to nest a `struct`
//! inside a `struct` for free, and a name like `registrations_failed_rejected`
//! costs nothing a binding was not already going to spend turning it back
//! into whatever shape its own language prefers.

use sipral::Counters;

use crate::abi::record;
use crate::error::entry;
use crate::handle::SipralHandle;
use crate::stack::with_stack;
use crate::versioned::{Versioned, declared_size, write_versioned};

record! {
    /// D3's flat set of health counters for one stack, since it was created.
    ///
    /// Every member here is monotonic except `active_calls`, which is a gauge:
    /// it can be read as smaller than an earlier reading, and none of the others
    /// ever will be. Set `size` to `sizeof(sipral_counters_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralCounters {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A REGISTER went out, counted once per attempt including a retry.
        pub registrations_attempted: u64,
        /// The registrar granted a binding.
        pub registrations_succeeded: u64,
        /// The registrar refused, and will refuse the same request again.
        pub registrations_failed_rejected: u64,
        /// The password was wrong, or there was none to answer a challenge with.
        pub registrations_failed_bad_credentials: u64,
        /// The registrar did not answer, or said it could not serve this now.
        pub registrations_failed_unreachable: u64,
        /// The registrar moved.
        pub registrations_failed_redirected: u64,
        /// This end hung up.
        pub calls_ended_local_hangup: u64,
        /// The far end hung up.
        pub calls_ended_remote_hangup: u64,
        /// The far end refused it: busy, declined, not found.
        pub calls_ended_refused: u64,
        /// Given up before it was answered, from either end.
        pub calls_ended_cancelled: u64,
        /// Nothing came back, or the transport died.
        pub calls_ended_unreachable: u64,
        /// Another branch of the same fork was kept and this one was not.
        pub calls_ended_fork_lost: u64,
        /// The branch was still ringing when the answer window closed.
        pub calls_ended_abandoned: u64,
        /// The session timer ran out and no refresh arrived.
        pub calls_ended_expired: u64,
        /// How many times inbound audio stopped for longer than the configured
        /// threshold while signalling stayed healthy (B5).
        pub media_gaps: u64,
        /// How many times a call's jitter buffer had to shrink or stretch the
        /// stream to keep its delay where it was aiming.
        pub jitter_buffer_events: u64,
        /// How many times a request would not fit a datagram and there was no
        /// stream to the destination to put it on, so the stack asked for one
        /// (RFC 3261 §18.1.1, B1).
        ///
        /// A request promoted onto a connection that already existed does not
        /// raise it; those are in the diagnostic record instead.
        pub stream_transport_wanted: u64,
        /// Calls with media running right now. The one gauge in this struct: it
        /// moves both ways, and it is what every other member here is not.
        pub active_calls: u64,
    }
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each — a stack that has done nothing reads all zero.
unsafe impl Versioned for SipralCounters {
    const NAME: &'static str = "sipral_counters";
    const MIN_SIZE: usize = crate::versioned::min_size::COUNTERS;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

fn counters_of(counters: Counters) -> SipralCounters {
    SipralCounters {
        size: size_of::<SipralCounters>(),
        registrations_attempted: counters.registrations_attempted.get(),
        registrations_succeeded: counters.registrations_succeeded.get(),
        registrations_failed_rejected: counters.registrations_failed.rejected.get(),
        registrations_failed_bad_credentials: counters.registrations_failed.bad_credentials.get(),
        registrations_failed_unreachable: counters.registrations_failed.unreachable.get(),
        registrations_failed_redirected: counters.registrations_failed.redirected.get(),
        calls_ended_local_hangup: counters.calls_ended.local_hangup.get(),
        calls_ended_remote_hangup: counters.calls_ended.remote_hangup.get(),
        calls_ended_refused: counters.calls_ended.refused.get(),
        calls_ended_cancelled: counters.calls_ended.cancelled.get(),
        calls_ended_unreachable: counters.calls_ended.unreachable.get(),
        calls_ended_fork_lost: counters.calls_ended.fork_lost.get(),
        calls_ended_abandoned: counters.calls_ended.abandoned.get(),
        calls_ended_expired: counters.calls_ended.expired.get(),
        media_gaps: counters.media_gaps.get(),
        jitter_buffer_events: counters.jitter_buffer_events.get(),
        stream_transport_wanted: counters.stream_transport_wanted.get(),
        active_calls: counters.active_calls.get(),
    }
}

entry! {
    /// D3's health counters for one stack, since it was created.
    ///
    /// Cheap enough to sample on a timer and ship as telemetry: reading this
    /// is one struct copy on top of the call itself, the same as
    /// `sipral_media_statistics` and for the same reason — nothing here walks
    /// the call table or a session to answer.
    ///
    /// # Safety
    ///
    /// `out_counters` must point at a `sipral_counters_t` whose `size` member
    /// says how long it is.
    fn sipral_stack_counters(stack: SipralHandle, out_counters: *mut SipralCounters) {
        // checked before the handle is even looked up, so a caller that got
        // its size wrong is told that rather than something about the stack
        unsafe { declared_size(out_counters.cast_const()) }?;
        let counters = with_stack(stack, |state| Ok(counters_of(state.engine.counters())))?;
        unsafe { write_versioned(out_counters, counters) }
    }
}

#[cfg(test)]
mod tests {
    use super::{SipralCounters, sipral_stack_counters};
    use crate::call::tests::{hangup, media_call};
    use crate::error::last_error_text;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::Observed;
    use crate::status::SipralStatus;

    fn zeroed() -> SipralCounters {
        SipralCounters {
            size: size_of::<SipralCounters>(),
            registrations_attempted: u64::MAX,
            registrations_succeeded: u64::MAX,
            registrations_failed_rejected: u64::MAX,
            registrations_failed_bad_credentials: u64::MAX,
            registrations_failed_unreachable: u64::MAX,
            registrations_failed_redirected: u64::MAX,
            calls_ended_local_hangup: u64::MAX,
            calls_ended_remote_hangup: u64::MAX,
            calls_ended_refused: u64::MAX,
            calls_ended_cancelled: u64::MAX,
            calls_ended_unreachable: u64::MAX,
            calls_ended_fork_lost: u64::MAX,
            calls_ended_abandoned: u64::MAX,
            calls_ended_expired: u64::MAX,
            media_gaps: u64::MAX,
            jitter_buffer_events: u64::MAX,
            stream_transport_wanted: u64::MAX,
            active_calls: u64::MAX,
        }
    }

    fn counters(stack: SipralHandle) -> SipralCounters {
        let mut out = zeroed();
        let status = unsafe { sipral_stack_counters(stack, &raw mut out) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        out
    }

    #[test]
    fn a_stack_that_has_done_nothing_reads_every_counter_at_zero() {
        let mut observed = Observed::default();
        let stack = crate::stack::tests::stack(&mut observed);
        let read = counters(stack);
        assert_eq!(read.registrations_attempted, 0);
        assert_eq!(read.calls_ended_local_hangup, 0);
        assert_eq!(read.media_gaps, 0);
        assert_eq!(read.jitter_buffer_events, 0);
        assert_eq!(read.stream_transport_wanted, 0);
        assert_eq!(read.active_calls, 0);
    }

    #[test]
    fn a_call_with_media_moves_the_active_calls_gauge_and_hanging_up_undoes_it() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        assert_eq!(
            counters(stack).active_calls,
            1,
            "the call has audio running"
        );

        hangup(stack, call, 5_000);
        let after = counters(stack);
        assert_eq!(
            after.active_calls, 0,
            "the session is gone once the call ends"
        );
        assert_eq!(
            after.calls_ended_local_hangup, 1,
            "this stack is the one that hung up"
        );
        assert_eq!(
            after.calls_ended_refused, 0,
            "not the disposition that happened"
        );
    }

    #[test]
    fn a_null_out_parameter_is_a_bad_argument() {
        let mut observed = Observed::default();
        let stack = crate::stack::tests::stack(&mut observed);
        let status = unsafe { sipral_stack_counters(stack, std::ptr::null_mut()) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn a_counters_struct_that_declares_the_wrong_size_is_refused() {
        let mut observed = Observed::default();
        let stack = crate::stack::tests::stack(&mut observed);
        let mut out = zeroed();
        out.size = size_of::<SipralCounters>() - 1;
        let status = unsafe { sipral_stack_counters(stack, &raw mut out) };
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(out.registrations_attempted, u64::MAX, "nothing was written");
    }

    /// The size is checked before the handle is even looked up: a stack that
    /// was never created and a counters struct too short to be any version of
    /// this one both fail, and the size is the one this answers with.
    #[test]
    fn a_counters_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut out = zeroed();
        out.size = crate::versioned::min_size::COUNTERS - 1;
        assert_eq!(
            unsafe { sipral_stack_counters(SIPRAL_HANDLE_NONE, &raw mut out) },
            SipralStatus::UnsupportedVersion
        );
    }

    #[test]
    fn a_stale_handle_is_reported_rather_than_read() {
        let mut observed = Observed::default();
        let stack = crate::stack::tests::stack(&mut observed);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
        let mut out = zeroed();
        let status = unsafe { sipral_stack_counters(stack, &raw mut out) };
        assert_eq!(status, SipralStatus::StaleHandle);
    }
}
