// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A thread of the caller's at the priority Android gives audio.
//!
//! AAudio runs its own callback threads under `SCHED_FIFO` when the audio
//! server lets it; an application cannot put a thread of its own there, for
//! want of the capability. What it can do — what the SDK's
//! `Process.setThreadPriority(THREAD_PRIORITY_URGENT_AUDIO)` does — is set
//! the thread's nice value to the one the platform reserves for audio that
//! must not wait, which the process's limits allow. That is what a thread
//! that feeds AAudio's streams from outside their callbacks asks for here.
//!
//! Written from bionic's `<sys/resource.h>` and `<unistd.h>` and the SDK's
//! reference for `android.os.Process`.

/// `PRIO_PROCESS`: with a thread's id, the one thread.
const PRIO_PROCESS: i32 = 0;

/// `android.os.Process.THREAD_PRIORITY_URGENT_AUDIO`.
pub const URGENT_AUDIO: i32 = -19;

unsafe extern "C" {
    /// `int setpriority(int which, id_t who, int prio)`.
    #[link_name = "setpriority"]
    fn set_priority(which: i32, who: u32, priority: i32) -> i32;

    /// `int getpriority(int which, id_t who)`.
    #[link_name = "getpriority"]
    fn get_priority(which: i32, who: u32) -> i32;

    /// `pid_t gettid(void)`.
    #[link_name = "gettid"]
    fn thread_id() -> i32;
}

/// The calling thread's own id, as `id_t`.
fn this_thread() -> u32 {
    // SAFETY: no precondition; the id names the calling thread.
    u32::try_from(unsafe { thread_id() }).unwrap_or(0)
}

/// Run the calling thread at [`URGENT_AUDIO`]: `true` when the platform
/// took it, `false` when it refused and the thread runs as before.
#[must_use]
pub fn urgent_audio_thread() -> bool {
    // SAFETY: plain values; the call changes only the thread named.
    unsafe { set_priority(PRIO_PROCESS, this_thread(), URGENT_AUDIO) == 0 }
}

/// The calling thread's nice value.
#[must_use]
pub fn thread_priority() -> i32 {
    // SAFETY: plain values; the call reads only the thread named.
    unsafe { get_priority(PRIO_PROCESS, this_thread()) }
}
