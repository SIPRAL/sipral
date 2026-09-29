// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The engine's log, through a callback, and its state, on demand.
//!
//! Two questions an application asks when something has gone wrong in the
//! field, and neither the event stream nor the diagnostic record answers.
//! "What was the stack doing" is a log: [`sipral_stack_log`] installs a
//! callback that receives the engine's lines at the levels asked for. "What
//! was the stack holding when it crashed" is a snapshot: [`sipral_stack_state`]
//! copies out one bounded text of accounts, calls, transports, media
//! sessions, the last errors and the counters, from any thread.
//!
//! **The log callback is never called with the stack held.** Everything the
//! engine has to say is queued while an entry point holds the stack, and
//! handed to the callback only once that entry point has let it go — at the
//! end of the same call, on the same thread — so calling back into the
//! library from inside it, this stack included, is an ordinary call, as it is
//! from the event callback. One delivery runs at a time: a thread that
//! finishes an entry point while another is delivering leaves its lines
//! queued, and the next entry point or poll to finish delivers them, so they
//! arrive in order and never on two threads at once.
//!
//! **A flood cannot stall the stack.** Lines pass a token bucket —
//! `sipral::BURST` at once, `sipral::PER_SECOND` a second after that, on the
//! stack's own clock — and wait in a queue of at most `sipral::QUEUE_CEILING`.
//! What either turns away is counted, never waited for, and the next line
//! delivered carries the count in [`SipralLogRecord::suppressed`].
//!
//! **Nothing either one writes carries a secret or a person.** Both go
//! through the redaction `docs/14-diagnostics.md` describes: user parts,
//! numbers and IP literals become pseudonyms keyed with a secret derived from
//! this stack's `media_seed` — never from `entropy`, which a replay recording
//! carries in clear — and credentials and SDES keys are dropped outright. The
//! log and the snapshot share the key, so an address reads as the same
//! pseudonym in both.

use std::collections::VecDeque;
use std::ffi::{c_char, c_void};
use std::fmt::Write as _;
use std::sync::Arc;

use sipral::{Log, LogLevel, LogRecord, RedactionMode, Redactor};

use crate::abi::{alias, codes, constants, record};
use crate::diagnostics::copy_out;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{StackState, with_stack};
use crate::status::SipralStatus;

codes! {
    /// How loud a log line is, for [`sipral_stack_log`] and
    /// [`SipralLogRecord::level`]. Higher is more detailed: a stack logging
    /// at `SIPRAL_LOG_LEVEL_INFO` delivers errors, warnings and information.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralLogLevel: u32 {
        /// Nothing: the log is off. What a stack starts with.
        Off = 0,
        /// Something failed and the application is likely to see the effect.
        Error = 1,
        /// Something went wrong that the stack worked around, or is about to
        /// matter: a registration refused, audio that stopped arriving.
        Warn = 2,
        /// What an operator wants in a log file: a registration granted, a
        /// call arriving, confirmed or ending, media starting.
        Info = 3,
        /// Every event the stack raises, every decision its diagnostic record
        /// writes down, and every call into this ABI it refused.
        Debug = 4,
        /// Every SIP message in and out, whole and redacted.
        Trace = 5,
    }
}

constants! {
    /// The longest text [`sipral_stack_state`] writes, its NUL included: a
    /// buffer of this many bytes always has room.
    pub const SIPRAL_STATE_TEXT_MAX: usize = 16384;
}

/// The text limit without its NUL.
const STATE_TEXT_LIMIT: usize = SIPRAL_STATE_TEXT_MAX - 1;

/// How many refused calls a stack remembers for its state.
const LAST_ERRORS: usize = 8;

/// How often, at most, a poll that raised something refreshes the snapshot
/// kept for [`sipral_stack_state`] to hand out while the stack is busy.
const SNAPSHOT_EVERY_MS: u64 = 1000;

record! {
    /// One log line, as [`SipralLogCallback`] reads it.
    ///
    /// Filled by the library and handed over as a `const` pointer: read
    /// `size` before anything past it, and nothing once the callback has
    /// returned — the two strings are the library's and live for the call
    /// alone.
    #[derive(Clone, Copy)]
    pub struct SipralLogRecord {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The stack the line is about.
        pub stack: SipralHandle,
        /// A `SipralLogLevel`, never `SIPRAL_LOG_LEVEL_OFF`.
        pub level: u32,
        /// Which part of the stack wrote it — `registration`, `call`,
        /// `media`, `decision`, `sip`, `api` — as UTF-8, not NUL-terminated.
        pub target: *const c_char,
        /// How many bytes of it.
        pub target_len: usize,
        /// The line, already redacted, as UTF-8, not NUL-terminated. A
        /// `SIPRAL_LOG_LEVEL_TRACE` line holding a whole message has line
        /// breaks in it.
        pub message: *const c_char,
        /// How many bytes of it.
        pub message_len: usize,
        /// How many lines the rate limit or the queue ceiling turned away
        /// since the line before this one. Zero almost always.
        pub suppressed: u64,
    }
}

alias! {
    /// Where a stack's log lines go. Installed with
    /// [`crate::log::sipral_stack_log`].
    ///
    /// Called on whichever thread has just finished a call into this stack,
    /// after the stack has been let go and with nothing of the library held,
    /// so it may call back into the library — this stack included — as an
    /// ordinary call. One line at a time, and never on two threads at once.
    /// It must not unwind, for the reason nothing in this ABI may.
    ///
    /// `record` and everything it points at belong to the library and are
    /// valid for the duration of this one call and no longer.
    pub type SipralLogCallback = fn(record: *const SipralLogRecord, user_data: *mut c_void);
}

/// A [`sipral::LogSink`] that hands each line to a C callback.
struct CSink {
    stack: SipralHandle,
    callback: unsafe extern "C" fn(record: *const SipralLogRecord, user_data: *mut c_void),
    user_data: *mut c_void,
}

// Safety: `user_data` is the caller's own pointer, never read here, and only
// handed back to the callback it arrived with; `sipral_stack_log`'s safety
// section says the callback may be called from any thread that calls into
// the stack, which is the caller's arrangement to make safe.
unsafe impl Send for CSink {}
// Safety: as above; nothing here is ever mutated after construction.
unsafe impl Sync for CSink {}

impl CSink {
    fn deliver(&self, line: &LogRecord<'_>) {
        let record = SipralLogRecord {
            size: size_of::<SipralLogRecord>(),
            stack: self.stack,
            level: line.level as u32,
            target: line.target.as_ptr().cast::<c_char>(),
            target_len: line.target.len(),
            message: line.message.as_ptr().cast::<c_char>(),
            message_len: line.message.len(),
            suppressed: line.suppressed,
        };
        // Safety: the caller's own function, under the contract
        // `SipralLogCallback` states; `record` borrows from `line`, alive
        // for the whole call.
        unsafe { (self.callback)(&raw const record, self.user_data) };
    }
}

entry! {
    /// Send this stack's log to `callback`, at `level` and louder — or turn
    /// it off with `SIPRAL_LOG_LEVEL_OFF` or a null callback.
    ///
    /// A stack is created with its log off, and a log that is off costs
    /// nothing: no line is formatted for it. Calling this again replaces the
    /// callback and the level, on this stack alone; lines already waiting go
    /// to the new callback. Turning the log off drops what was waiting.
    ///
    /// What each level carries, how lines are rate-limited and how they are
    /// redacted is in this module's documentation and in
    /// `docs/17-observability.md`. A level above `SIPRAL_LOG_LEVEL_TRACE` is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` and changes nothing.
    ///
    /// # Safety
    ///
    /// `callback`, when not null, is called from inside later calls into this
    /// stack on whichever thread made them, once the stack has been let go
    /// (see [`SipralLogCallback`]). `user_data` is handed back to it untouched
    /// and must stay valid until the log is turned off or replaced and no
    /// thread is inside this stack any more.
    fn sipral_stack_log(
        stack: SipralHandle,
        level: u32,
        callback: SipralLogCallback,
        user_data: *mut c_void,
    ) {
        let wanted = match level {
            0 => None,
            other => Some(LogLevel::from_number(other).ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("{other} is not a log level; SIPRAL_LOG_LEVEL_TRACE is 5, the most"),
                )
            })?),
        };
        with_stack(stack, |state| {
            match (wanted, callback) {
                (Some(level), Some(callback)) => {
                    let sink = CSink {
                        stack,
                        callback,
                        user_data,
                    };
                    state.log.enable(level, Arc::new(move |line| sink.deliver(line)));
                }
                _ => state.log.disable(),
            }
            Ok(())
        })
    }
}

/// What a stack remembers beside itself for [`sipral_stack_state`], reachable
/// without the stack's own lock.
#[derive(Default)]
pub(crate) struct Watch {
    /// The last calls into this stack that were refused, newest last: when,
    /// with what, and the sentence.
    errors: VecDeque<(u64, SipralStatus, String)>,
    /// The last snapshot taken with the stack held, and when: what a caller
    /// is handed while another thread is inside.
    snapshot: Option<(u64, String)>,
}

impl Watch {
    /// Remember a refusal.
    pub(crate) fn refused(&mut self, at_ms: u64, failure: &Fail) {
        if self.errors.len() == LAST_ERRORS {
            self.errors.pop_front();
        }
        self.errors
            .push_back((at_ms, failure.status, failure.message().to_owned()));
    }

    /// Keep a fresh snapshot, unless one was kept less than
    /// [`SNAPSHOT_EVERY_MS`] ago.
    pub(crate) fn refresh(&mut self, stack: SipralHandle, state: &StackState) {
        let at = state.polled_at_ms();
        if let Some((then, _)) = &self.snapshot
            && at.saturating_sub(*then) < SNAPSHOT_EVERY_MS
        {
            return;
        }
        let text = self.render(stack, state);
        self.snapshot = Some((at, text));
    }

    /// The whole snapshot, taken now, with the stack held.
    pub(crate) fn render(&self, stack: SipralHandle, state: &StackState) -> String {
        let now = state.last_instant();
        let mut extra = String::new();
        let _ = writeln!(extra, "transports: {}", state.transports.len());
        for (id, protocol) in state.transports.listed() {
            let _ = writeln!(extra, "  transport {id}: {}", protocol.as_str());
        }
        let _ = writeln!(
            extra,
            "queues: events dropped {}, farewells dropped {}, farewells waiting {}",
            state.events_dropped,
            state.farewells_dropped,
            state.farewells.len()
        );
        let endpoint = state.agent.endpoint_ref();
        let repeated = endpoint.retransmissions();
        let _ = writeln!(
            extra,
            "signalling: requests retransmitted {}, responses retransmitted {}, transactions \
             timed out {}, refused at a limit {}",
            repeated.requests,
            repeated.responses,
            repeated.timeouts,
            endpoint.refused()
        );
        match state.engine.rtp_ports() {
            Some(range) => {
                let _ = writeln!(
                    extra,
                    "rtp ports: {}..{}, {} pairs, {} reserved",
                    range.min(),
                    range.max(),
                    range.pairs(),
                    state.engine.rtp_ports_reserved()
                );
            }
            None => extra.push_str("rtp ports: any, chosen by the application\n"),
        }
        let _ = writeln!(
            extra,
            "log: {}, {} lines suppressed",
            state.log.level().map_or("off", LogLevel::as_str),
            state.log.suppressed()
        );
        let _ = writeln!(extra, "last errors: {}", self.errors.len());
        for (at, status, message) in &self.errors {
            let _ = writeln!(extra, "  at {at} ms, {status:?}: {message}");
        }
        let mut redactor = Redactor::new(RedactionMode::Hash(state.pseudonym_key().to_vec()));
        let head = format!(
            "stack {stack}, taken at {} ms with the stack held\n",
            state.polled_at_ms()
        );
        let body = state.engine.state(&state.agent, now).render(
            &extra,
            &mut redactor,
            STATE_TEXT_LIMIT.saturating_sub(head.len()),
        );
        head + &body
    }

    /// What to hand out while the stack is held — by another thread, or by
    /// the very call this one was made from inside.
    fn stale(&self, stack: SipralHandle) -> String {
        match &self.snapshot {
            Some((at, text)) => format!(
                "stack {stack} was in use when asked; this is the snapshot the last poll kept at \
                 {at} ms\n{}",
                text.split_once('\n')
                    .map_or(text.as_str(), |(_, rest)| rest)
            ),
            None => format!(
                "stack {stack} was in use when asked, and no poll has kept a snapshot yet\n"
            ),
        }
    }
}

entry! {
    /// Copy a snapshot of everything this stack is holding into `buffer`, as
    /// text for a crash report: its accounts and their registrations, its
    /// calls and their states, its transports, its media sessions, the last
    /// calls into it that were refused, its queues, its RTP port range and
    /// its counters — redacted, and never longer than
    /// `SIPRAL_STATE_TEXT_MAX` bytes with the NUL, so a buffer that size
    /// always has room.
    ///
    /// Safe from any thread, including one the stack is busy on, and never
    /// waits. When no other thread is inside the stack the snapshot is taken
    /// there and then; when one is, what comes back is the last snapshot a
    /// poll kept — polls keep one at most once a second, and only when
    /// something happened — and its first line says so and when it was
    /// taken. A call's media session that a thread is in the middle of a
    /// frame on is reported as busy rather than waited for.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`, with the length needed in `out_len`,
    /// when it does not fit; `out_len` may be null.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_len` must point at one `size_t` or be null.
    fn sipral_stack_state(
        stack: SipralHandle,
        buffer: *mut c_char,
        capacity: usize,
        out_len: *mut usize,
    ) {
        let text = crate::stack::state_text(stack)?;
        unsafe { copy_out(&text, buffer, capacity, out_len) }
    }
}

/// The snapshot text for a stack whose entry is in hand: fresh when its lock
/// is free, the kept one otherwise.
pub(crate) fn snapshot_of(
    stack: SipralHandle,
    state: Option<&StackState>,
    watch: &mut Watch,
) -> String {
    match state {
        Some(state) => {
            let text = watch.render(stack, state);
            watch.snapshot = Some((state.polled_at_ms(), text.clone()));
            text
        }
        None => watch.stale(stack),
    }
}

/// The key a stack's pseudonyms are made with: its `media_seed`, which is
/// secret and never written anywhere, under a label of its own so that
/// nothing else keyed from that seed can ever be the same key.
pub(crate) fn pseudonym_key(media_seed: &[u8; 32]) -> Vec<u8> {
    let mut key = media_seed.to_vec();
    key.extend_from_slice(b"sipral log and state pseudonyms");
    key
}

/// A new, silent log for a stack.
pub(crate) fn log_for(key: &[u8]) -> Log {
    Log::new(key)
}

#[cfg(test)]
mod tests {
    use super::{
        SIPRAL_STATE_TEXT_MAX, SipralLogLevel, SipralLogRecord, sipral_stack_log,
        sipral_stack_state,
    };
    use crate::call::tests::{account_on, invitation};
    use crate::counters::{SipralCounters, sipral_stack_counters};
    use crate::error::last_error_text;
    use crate::handle::SipralHandle;
    use crate::ports::sipral_stack_rtp_port_reserve;
    use crate::screening::{SIPRAL_SCREEN_ACCEPT, SipralScreenRequest, sipral_stack_screen};
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use crate::transport::sipral_stack_receive_datagram;
    use std::ffi::{c_char, c_void};
    use std::ptr;
    use std::sync::Mutex;

    /// Every line a stack's log delivered, and what calling back into that
    /// stack from inside the callback answered.
    #[derive(Default)]
    struct Heard {
        lines: Mutex<Vec<(u32, String, String, u64)>>,
        reentered: Mutex<Vec<SipralStatus>>,
    }

    fn text(pointer: *const c_char, len: usize) -> String {
        let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) };
        String::from_utf8(bytes.to_vec()).expect("UTF-8")
    }

    unsafe extern "C" fn heard(record: *const SipralLogRecord, user_data: *mut c_void) {
        let heard = unsafe { &*user_data.cast::<Heard>() };
        let record = unsafe { &*record };
        assert_eq!(record.size, size_of::<SipralLogRecord>());
        heard.lines.lock().unwrap().push((
            record.level,
            text(record.target, record.target_len),
            text(record.message, record.message_len),
            record.suppressed,
        ));
        // the stack is not held while this runs: a call into it is ordinary
        let mut counters = SipralCounters {
            size: size_of::<SipralCounters>(),
            ..unsafe { std::mem::zeroed() }
        };
        let status = unsafe { sipral_stack_counters(record.stack, &raw mut counters) };
        heard.reentered.lock().unwrap().push(status);
    }

    fn listen(handle: SipralHandle, level: SipralLogLevel, heard: &Heard) {
        let status = unsafe {
            sipral_stack_log(
                handle,
                level as u32,
                Some(self::heard),
                ptr::from_ref(heard).cast_mut().cast::<c_void>(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    }

    /// A call this stack refuses: it has no RTP range to hand a port out of.
    fn refuse(handle: SipralHandle) -> SipralStatus {
        let mut port = 0_u32;
        unsafe { sipral_stack_rtp_port_reserve(handle, &raw mut port) }
    }

    fn receive(handle: SipralHandle, message: &[u8], now_ms: u64) {
        let from = "203.0.113.5:5060";
        let status = unsafe {
            sipral_stack_receive_datagram(
                handle,
                0,
                message.as_ptr(),
                message.len(),
                from.as_ptr().cast::<c_char>(),
                from.len(),
                ptr::null(),
                0,
                now_ms,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    }

    #[test]
    fn a_stack_logs_nothing_until_asked_and_nothing_once_turned_off() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let heard = Heard::default();
        listen(handle, SipralLogLevel::Off, &heard);
        assert_eq!(refuse(handle), SipralStatus::WrongState);
        listen(handle, SipralLogLevel::Debug, &heard);
        assert_eq!(refuse(handle), SipralStatus::WrongState);
        assert_eq!(heard.lines.lock().unwrap().len(), 1);
        let status = unsafe { sipral_stack_log(handle, 3, None, ptr::null_mut()) };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(refuse(handle), SipralStatus::WrongState);
        assert_eq!(
            heard.lines.lock().unwrap().len(),
            1,
            "a null callback is off"
        );
    }

    #[test]
    fn a_level_past_trace_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let heard = Heard::default();
        let status = unsafe {
            sipral_stack_log(
                handle,
                6,
                Some(self::heard),
                ptr::from_ref(&heard).cast_mut().cast::<c_void>(),
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    /// The line about a refused call arrives at the end of that same call,
    /// with the stack let go: the callback's own call into it is answered.
    #[test]
    fn the_callback_runs_with_the_stack_let_go_and_may_call_back_into_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let heard = Heard::default();
        listen(handle, SipralLogLevel::Debug, &heard);
        assert_eq!(refuse(handle), SipralStatus::WrongState);
        let lines = heard.lines.lock().unwrap().clone();
        assert_eq!(lines.len(), 1, "{lines:?}");
        let (level, target, message, suppressed) = &lines[0];
        assert_eq!(*level, SipralLogLevel::Debug as u32);
        assert_eq!(target, "api");
        assert!(message.starts_with("refused, WrongState: "), "{message}");
        assert_eq!(*suppressed, 0);
        assert_eq!(*heard.reentered.lock().unwrap(), [SipralStatus::Ok]);
    }

    /// Every message in and out at trace, whole, and with nobody in it.
    #[test]
    fn trace_carries_every_message_redacted() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let _ = account_on(handle);
        let heard = Heard::default();
        listen(handle, SipralLogLevel::Trace, &heard);
        receive(handle, &invitation(), 1_000);
        let _ = poll(handle, 1_000);
        let lines = heard.lines.lock().unwrap().clone();
        let sip: Vec<&String> = lines
            .iter()
            .filter(|(_, target, _, _)| target == "sip")
            .map(|(_, _, message, _)| message)
            .collect();
        assert!(
            sip.iter().any(|line| line.contains("INVITE sip:")),
            "{lines:#?}"
        );
        for (_, _, line, _) in &lines {
            for personal in ["alice", "bob", "203.0.113.5", "192.0.2.10"] {
                assert!(!line.contains(personal), "{personal} in {line}");
            }
        }
        assert!(
            lines
                .iter()
                .any(|(_, target, line, _)| target == "call" && line.contains("incoming")),
            "{lines:#?}"
        );
    }

    /// Ten thousand refusals at one instant reach the callback as one burst,
    /// and the next line after the bucket refills says how many went.
    #[test]
    fn a_flood_of_lines_is_cut_to_the_rate_and_counted() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let heard = Heard::default();
        listen(handle, SipralLogLevel::Debug, &heard);
        for _ in 0..10_000 {
            let _ = refuse(handle);
        }
        assert_eq!(heard.lines.lock().unwrap().len(), sipral::BURST as usize);
        let _ = poll(handle, 5_000);
        let _ = refuse(handle);
        let lines = heard.lines.lock().unwrap();
        let (_, _, _, suppressed) = lines.last().expect("a line after the flood");
        assert_eq!(*suppressed, 10_000 - u64::from(sipral::BURST));
    }

    fn state_of(handle: SipralHandle) -> String {
        let mut buffer = vec![0_u8; SIPRAL_STATE_TEXT_MAX];
        let mut len = 0_usize;
        let status = unsafe {
            sipral_stack_state(
                handle,
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
                &raw mut len,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(len <= SIPRAL_STATE_TEXT_MAX);
        buffer.truncate(len - 1);
        String::from_utf8(buffer).expect("UTF-8")
    }

    #[test]
    fn the_state_names_accounts_calls_transports_and_errors_with_nobody_in_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let _ = account_on(handle);
        receive(handle, &invitation(), 1_000);
        let _ = poll(handle, 1_000);
        assert_eq!(refuse(handle), SipralStatus::WrongState);
        let text = state_of(handle);
        for expected in [
            "taken at 1000 ms with the stack held",
            "accounts: 1",
            "calls: 1",
            "incoming",
            "transports: 1",
            "transport 0: UDP",
            "signalling: requests retransmitted 0, responses retransmitted 0, transactions timed \
             out 0, refused at a limit 0",
            "rtp ports: any",
            "log: off",
            "last errors: 1",
            "WrongState",
            "counters: ",
        ] {
            assert!(text.contains(expected), "{expected} missing from:\n{text}");
        }
        for personal in ["alice", "bob", "203.0.113.5", "192.0.2.10"] {
            assert!(!text.contains(personal), "{personal} in:\n{text}");
        }
    }

    #[test]
    fn a_buffer_too_small_for_the_state_is_told_the_length() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut len = 0_usize;
        let status = unsafe { sipral_stack_state(handle, ptr::null_mut(), 0, &raw mut len) };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert!(len > 1 && len <= SIPRAL_STATE_TEXT_MAX);
    }

    /// What `sipral_stack_state` answered from inside a screening policy,
    /// which runs with the stack held.
    static FROM_INSIDE: Mutex<Option<String>> = Mutex::new(None);

    unsafe extern "C" fn snapshot_from_inside(
        request: *const SipralScreenRequest,
        _user_data: *mut c_void,
    ) -> u32 {
        let stack = unsafe { &*request }.stack;
        *FROM_INSIDE.lock().unwrap() = Some(state_of(stack));
        SIPRAL_SCREEN_ACCEPT
    }

    /// A stack that is held answers at once with the snapshot its last poll
    /// kept, and says so, rather than waiting or refusing.
    #[test]
    fn the_state_of_a_busy_stack_is_the_last_snapshot_kept_and_says_so() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let _ = account_on(handle);
        let _ = poll(handle, 500);
        let status =
            unsafe { sipral_stack_screen(handle, Some(snapshot_from_inside), ptr::null_mut()) };
        assert_eq!(status, SipralStatus::Ok);
        receive(handle, &invitation(), 1_000);
        let text = FROM_INSIDE.lock().unwrap().take().expect("the policy ran");
        assert!(text.contains("was in use when asked"), "{text}");
        assert!(text.contains("kept at 500 ms"), "{text}");
        assert!(text.contains("accounts: 1"), "{text}");
    }
}
