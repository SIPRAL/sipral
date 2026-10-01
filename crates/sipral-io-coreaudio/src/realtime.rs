// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A thread of the caller's run as audio: Mach's time-constraint policy.
//!
//! The device's own callbacks already run on a real-time thread the
//! framework made; a thread that feeds them — a pump that encodes the
//! microphone and mixes the calls once a frame — does not, and the
//! scheduler takes the processor away from an ordinary thread whenever
//! something busier wants it. A thread under the time-constraint policy is
//! scheduled ahead of every ordinary one for the `computation` it declared in
//! every `period`, and is let go back to an ordinary one by the kernel if it
//! ever takes more than it said, so a promise that turns out wrong costs the
//! thread its place and not the machine its responsiveness.
//!
//! Written from `<mach/thread_policy.h>`, `<mach/mach_time.h>` and
//! `<pthread.h>` as the SDK ships them.

use core::ffi::c_void;
use core::time::Duration;

use crate::status::{Error, OsStatus};

/// `THREAD_TIME_CONSTRAINT_POLICY`.
const TIME_CONSTRAINT_POLICY: u32 = 2;

/// `THREAD_TIME_CONSTRAINT_POLICY_COUNT`: the struct's size in `integer_t`s.
const TIME_CONSTRAINT_POLICY_COUNT: u32 = 4;

/// `struct thread_time_constraint_policy`, every time in the units of
/// `mach_absolute_time`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TimeConstraintPolicy {
    period: u32,
    computation: u32,
    constraint: u32,
    /// `boolean_t`.
    preemptible: i32,
}

/// `struct mach_timebase_info`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    /// `pthread_t pthread_self(void)`.
    #[link_name = "pthread_self"]
    fn current_thread() -> *mut c_void;

    /// `mach_port_t pthread_mach_thread_np(pthread_t)`: the thread's Mach
    /// port, which the thread owns and nobody deallocates.
    #[link_name = "pthread_mach_thread_np"]
    fn mach_thread_of(thread: *mut c_void) -> u32;

    /// `kern_return_t thread_policy_set(thread_act_t thread,
    /// thread_policy_flavor_t flavor, thread_policy_t policy_info,
    /// mach_msg_type_number_t count)`.
    #[link_name = "thread_policy_set"]
    fn set_policy(thread: u32, flavor: u32, info: *const TimeConstraintPolicy, count: u32) -> i32;

    /// `kern_return_t thread_policy_get(thread_act_t thread,
    /// thread_policy_flavor_t flavor, thread_policy_t policy_info,
    /// mach_msg_type_number_t *count, boolean_t *get_default)`.
    #[link_name = "thread_policy_get"]
    fn get_policy(
        thread: u32,
        flavor: u32,
        info: *mut TimeConstraintPolicy,
        count: *mut u32,
        get_default: *mut i32,
    ) -> i32;

    /// `kern_return_t mach_timebase_info(mach_timebase_info_t info)`.
    #[link_name = "mach_timebase_info"]
    fn timebase(info: *mut TimebaseInfo) -> i32;
}

/// What one tick of `mach_absolute_time` is, as a fraction of a nanosecond.
fn timebase_info() -> Option<TimebaseInfo> {
    let mut info = TimebaseInfo::default();
    // SAFETY: `info` is a live out-parameter of the declared type.
    let status = unsafe { timebase(&raw mut info) };
    (status == 0 && info.numer != 0 && info.denom != 0).then_some(info)
}

/// `duration` in ticks of `mach_absolute_time`.
fn ticks(duration: Duration, info: TimebaseInfo) -> u32 {
    let nanos = duration.as_nanos();
    let ticks = nanos.saturating_mul(u128::from(info.denom)) / u128::from(info.numer);
    u32::try_from(ticks).unwrap_or(u32::MAX)
}

/// Ticks of `mach_absolute_time` as a duration.
fn duration(ticks: u32, info: TimebaseInfo) -> Duration {
    let nanos = u128::from(ticks).saturating_mul(u128::from(info.numer)) / u128::from(info.denom);
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// The calling thread's own Mach port.
fn this_thread() -> u32 {
    // SAFETY: neither call has a precondition; the port answered belongs to
    // the calling thread for as long as it runs.
    unsafe { mach_thread_of(current_thread()) }
}

/// Run the calling thread under the time-constraint policy: woken every
/// `period`, needing `computation` of it, which has to be done within
/// `constraint` of the period's start. Preemptible, so that a longer
/// computation is shared out rather than run in one piece.
///
/// # Errors
/// [`Error::Call`] naming `thread_policy_set` and what it returned, or
/// `mach_timebase_info` when the clock's units could not be read.
pub fn run_as_audio(
    period: Duration,
    computation: Duration,
    constraint: Duration,
) -> Result<(), Error> {
    let info = timebase_info().ok_or(Error::Call {
        call: "mach_timebase_info",
        status: OsStatus::new(-1),
    })?;
    let policy = TimeConstraintPolicy {
        period: ticks(period, info),
        computation: ticks(computation, info),
        constraint: ticks(constraint, info),
        preemptible: 1,
    };
    // SAFETY: the policy is a live local of the flavour named, and the count
    // is its size in the units the call counts in.
    let status = unsafe {
        set_policy(
            this_thread(),
            TIME_CONSTRAINT_POLICY,
            &raw const policy,
            TIME_CONSTRAINT_POLICY_COUNT,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Call {
            call: "thread_policy_set",
            status: OsStatus::new(status),
        })
    }
}

/// The period the calling thread runs under the time-constraint policy
/// with, or `None` for a thread that runs as any other.
#[must_use]
pub fn audio_period() -> Option<Duration> {
    let info = timebase_info()?;
    let mut policy = TimeConstraintPolicy::default();
    let mut count = TIME_CONSTRAINT_POLICY_COUNT;
    let mut get_default: i32 = 0;
    // SAFETY: every pointer is a live local of the type declared, and the
    // count says how many `integer_t`s the policy has room for.
    let status = unsafe {
        get_policy(
            this_thread(),
            TIME_CONSTRAINT_POLICY,
            &raw mut policy,
            &raw mut count,
            &raw mut get_default,
        )
    };
    // the default answered is what a thread with no policy of its own has
    (status == 0 && get_default == 0).then(|| duration(policy.period, info))
}

#[cfg(test)]
mod tests {
    use super::{audio_period, run_as_audio};
    use core::time::Duration;

    #[test]
    fn a_thread_runs_as_audio_once_asked_and_not_before() {
        let answer = std::thread::spawn(|| {
            let before = audio_period();
            let asked = run_as_audio(
                Duration::from_millis(20),
                Duration::from_millis(5),
                Duration::from_millis(15),
            );
            (before, asked, audio_period())
        })
        .join()
        .unwrap();
        assert_eq!(answer.0, None, "an ordinary thread ran as audio");
        assert_eq!(answer.1, Ok(()));
        let period = answer.2.expect("the policy did not take");
        // the clock's units are not nanoseconds everywhere: rounding through
        // them loses less than a microsecond
        assert!(
            period.abs_diff(Duration::from_millis(20)) < Duration::from_micros(1),
            "{period:?}"
        );
        // and the policy is the thread's own, not the process's
        assert_eq!(audio_period(), None);
    }
}
