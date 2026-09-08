// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A stack: made, polled, destroyed — and the two rules a binding author will
//! otherwise have to guess.
//!
//! Everything the library has to tell the application arrives on one callback,
//! and the callback runs inside [`sipral_stack_poll`] and nowhere else. That
//! is the whole reason poll exists. A stack that called back from a thread of
//! its own would make every binding reason about which thread it is on, and
//! Swift, .NET and Kotlin each answer that question differently; a stack that
//! calls back only where it was polled has nothing to answer.
//!
//! The clock arrives the same way. Nothing here reads one — except once, at
//! creation, to have an origin for the milliseconds the caller counts from —
//! because the layers below own no time either: the caller says what time it
//! is on every call that can put something on the wire, and a clock that goes
//! backwards is a caller bug reported as one rather than a timer that never
//! fires.
//!
//! # May one stack be used from two threads at once?
//!
//! No. A stack may be used from *any* thread, and from a different thread on
//! every call, but only from one thread at a time: the second concurrent call
//! gets `SIPRAL_STATUS_BUSY` and does nothing. It does not block, and it does
//! not queue.
//!
//! That is the conservative answer, and it is chosen because it is the one
//! that stays true. A library that promised safe concurrent use would owe that
//! promise to every future member of every future state; one that blocked
//! would owe the caller a guarantee about how long, which nothing here can
//! give while a callback is running on the other thread. Busy costs a binding
//! one lock it was going to take anyway, and a binding written against Busy
//! keeps working if the answer is ever widened. One written against a promise
//! of concurrency cannot be made to work if it is not.
//!
//! # May the library be re-entered from inside the event callback?
//!
//! No, with one exception. The callback runs while the stack is held, so every
//! call naming that stack from inside it returns `SIPRAL_STATUS_BUSY` — a
//! binding cannot deadlock itself by answering an event with a request, and it
//! cannot see a stack halfway through delivering one. What a binding does with
//! an event is copy what it needs and act after poll returns.
//!
//! The exception is [`sipral_stack_destroy`], which works from inside the
//! callback and always will. It takes nothing but the handle table, and what
//! the poll is holding stays alive until that poll returns, so a binding whose
//! event handler is where its object gets disposed does not need a queue of
//! deferred frees to be correct.
//!
//! Everything that names no stack — the last error, the status names, the ABI
//! version — is callable from anywhere at any time, including from inside the
//! callback and from any number of threads.

use std::ffi::{c_char, c_void};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use sipral_core::endpoint::{EndpointConfig, Input, TransportId, TransportProtocol};
use sipral_core::transaction::TimerConfig;
use sipral_ua::{AccountId, CallHandle, UaEvent, UserAgent};

use crate::error::{Fail, entry, fail};
use crate::event::{SipralEvent, SipralEventCallback, Vocabulary};
use crate::handle::{HandleTable, SipralHandle};
use crate::names::Names;
use crate::status::SipralStatus;
use crate::text::{bytes, required_text, text};
use crate::versioned::{Versioned, declared_size, read_versioned, write_versioned};

static STACKS: HandleTable<StackEntry> = HandleTable::new();

/// Thirty-two bytes, which is what the endpoint derives every branch
/// parameter, tag and `Call-ID` from.
const SEED_BYTES: usize = 32;

/// The one transport a stack is bound to. Nothing here opens it.
const TRANSPORT: TransportId = TransportId(0);

/// What a stack speaks. Names for `sipral_stack_config_t::transport`.
///
/// Zero is not one of them: a stack is told what it is speaking, because
/// guessing wrong in the direction of the plainest transport is how a caller
/// that meant TLS ends up on the wire in the clear.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralTransport {
    /// UDP.
    Udp = 1,
    /// TCP.
    Tcp = 2,
    /// TLS over TCP.
    Tls = 3,
    /// WebSocket.
    Ws = 4,
    /// WebSocket over TLS.
    Wss = 5,
}

/// What a stack is created with.
///
/// Set `size` to `sizeof(sipral_stack_config_t)` and zero the rest before
/// filling anything in. Four members have to be filled: the callback, the
/// transport, the address this end is reachable at, and the entropy. Nothing
/// here can be guessed on the caller's behalf.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralStackConfig {
    /// `sizeof` this struct, as the caller's header declares it.
    pub size: usize,
    /// Where events go. Required: a stack with nowhere to report to is a
    /// stack whose failures are invisible.
    pub event_callback: SipralEventCallback,
    /// Handed back to the callback untouched. The library never reads it.
    pub event_user_data: *mut c_void,
    /// A [`SipralTransport`].
    pub transport: u32,
    /// The address the far end reaches this one at, as `host:port`, UTF-8 and
    /// not NUL-terminated.
    ///
    /// It goes in every `Via`, so it is the address a response has to come
    /// back to rather than whatever a wildcard socket was bound to. Nothing
    /// here opens a socket or resolves a name.
    pub bind_address: *const c_char,
    /// How many bytes of it.
    pub bind_address_len: usize,
    /// What to put in `User-Agent`, or null for none.
    pub user_agent: *const c_char,
    /// How many bytes of it.
    pub user_agent_len: usize,
    /// Thirty-two bytes of entropy, from the platform's own generator.
    ///
    /// Every branch parameter, tag and `Call-ID` is derived from it, and
    /// §19.3 wants a tag unguessable — cryptographically random, not a
    /// counter or a clock. Two stacks must never be given the same bytes.
    pub entropy: *const u8,
    /// How many bytes of it. Thirty-two.
    pub entropy_len: usize,
    /// T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
    pub timer_t1_ms: u64,
    /// T2 in milliseconds, or zero for four seconds.
    pub timer_t2_ms: u64,
    /// T4 in milliseconds, or zero for five seconds.
    pub timer_t4_ms: u64,
}

// Safety: the trait's contract. Plain data, no invariant between the members,
// and all-zero is a valid value of each: a null function pointer is `None`, a
// null user pointer is a user pointer the library never reads anyway, and a
// zero length beside a null pointer is how a caller says it has nothing to
// give. A zeroed struct is refused, but it is refused by reading it, not by
// being undefined.
unsafe impl Versioned for SipralStackConfig {
    const NAME: &'static str = "sipral_stack_config";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// What one call to [`sipral_stack_poll`] did.
///
/// Set `size` to `sizeof(sipral_poll_result_t)` before the call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralPollResult {
    /// How many bytes of this struct the library filled in.
    pub size: usize,
    /// Events handed to the callback during this poll.
    pub events_delivered: usize,
    /// Events the stack raised that this ABI has no word for yet.
    ///
    /// Counted rather than delivered: an event carrying nothing a binding can
    /// act on is noise, and a number that is not zero is the honest measure of
    /// how far this vocabulary is behind the stack's.
    pub events_unclaimed: usize,
    /// Bytes the stack produced and this build had nowhere to send.
    ///
    /// There is no transport entry point yet, so what the stack wrote is
    /// counted and dropped rather than left to grow. Every non-zero count is a
    /// message that would have gone out.
    pub transmits_discarded: usize,
    /// Whether there is a deadline at all. Zero means nothing is scheduled and
    /// the next poll can wait for input.
    pub has_deadline: u32,
    /// How long from `now_ms` until the stack has something to do, when
    /// `has_deadline` says there is one. Zero means it is already due.
    pub next_poll_in_ms: u64,
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralPollResult {
    const NAME: &'static str = "sipral_poll_result";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// One stack. The lock is what makes a call from inside the callback an error
/// code instead of a deadlock, and a call from a second thread an error code
/// instead of a wait.
struct StackEntry {
    state: Mutex<StackState>,
}

/// Everything one stack is.
pub(crate) struct StackState {
    callback: unsafe extern "C" fn(event: *const SipralEvent, user_data: *mut c_void),
    user_data: *mut c_void,
    pub(crate) agent: UserAgent,
    pub(crate) accounts: Names<AccountId>,
    pub(crate) calls: Names<CallHandle>,
    /// The transport every account and every call uses. There is one.
    pub(crate) transport: TransportId,
    /// What goes in `User-Agent`, when the caller wanted one.
    pub(crate) user_agent: Option<Box<[u8]>>,
    /// What `now_ms` of zero means. Read once, from the only clock this
    /// library ever looks at, and never compared with a later reading.
    origin: Instant,
    /// The last time the caller said it was, so that a clock going backwards
    /// is caught where it happens.
    polled_at_ms: u64,
    /// Whether the first poll has said the stack is running.
    started: bool,
}

// Safety: the user pointer is the caller's and is only ever handed back to
// the caller's own callback, on whichever thread the caller polls from. What
// it points at, and where it may be touched, is the caller's arrangement; the
// library reads none of it. Everything else in here is `Send` on its own.
unsafe impl Send for StackState {}

impl StackState {
    /// The caller's clock, as an instant the layers below can use.
    pub(crate) fn instant(&self, now_ms: u64) -> Result<Instant, Fail> {
        self.origin
            .checked_add(Duration::from_millis(now_ms))
            .ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("now_ms is {now_ms}, which is further ahead than a clock reaches"),
                )
            })
    }

    /// Move the stack's clock to `now_ms`, refusing one that went backwards.
    pub(crate) fn advance(&mut self, now_ms: u64) -> Result<Instant, Fail> {
        if now_ms < self.polled_at_ms {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "now_ms is {now_ms} after this stack was last used at {}, and a clock that \
                     goes backwards stops timers from firing",
                    self.polled_at_ms
                ),
            ));
        }
        let now = self.instant(now_ms)?;
        self.polled_at_ms = now_ms;
        Ok(now)
    }

    /// Hand one event to the callback, on this thread, with the stack held.
    fn deliver(&self, event: &SipralEvent) {
        // still holding this stack's lock, which is what turns a call back
        // into it from in here into SIPRAL_STATUS_BUSY
        unsafe { (self.callback)(std::ptr::from_ref(event), self.user_data) };
    }
}

pub(crate) fn handle_failed(status: SipralStatus) -> Fail {
    let explanation = match status {
        SipralStatus::StaleHandle => "what the handle named is gone",
        SipralStatus::InvalidHandle => "not a handle from this library",
        _ => "the handle cannot be used",
    };
    fail(status, explanation)
}

/// Do something to a stack, or say why not.
///
/// The one way in. Every entry point that names a stack goes through here, so
/// the two rules at the top of this module hold for all of them at once
/// rather than one function at a time.
pub(crate) fn with_stack<R>(
    stack: SipralHandle,
    act: impl FnOnce(&mut StackState) -> Result<R, Fail>,
) -> Result<R, Fail> {
    let entry = STACKS.get(stack).map_err(handle_failed)?;
    let mut held = lock(&entry)?;
    act(&mut held)
}

/// The same, for something that happens at a time the caller names.
pub(crate) fn with_stack_at<R>(
    stack: SipralHandle,
    now_ms: u64,
    act: impl FnOnce(&mut StackState, Instant) -> Result<R, Fail>,
) -> Result<R, Fail> {
    with_stack(stack, |state| {
        let now = state.advance(now_ms)?;
        act(state, now)
    })
}

fn lock(entry: &Arc<StackEntry>) -> Result<MutexGuard<'_, StackState>, Fail> {
    match entry.state.try_lock() {
        Ok(state) => Ok(state),
        // a panic was caught while this stack was held; what is behind the
        // lock is whole between statements
        Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => Err(fail(
            SipralStatus::Busy,
            "this stack is in use by another call, which may be one further down this call stack",
        )),
    }
}

fn transport_of(value: u32) -> Result<TransportProtocol, Fail> {
    match value {
        1 => Ok(TransportProtocol::Udp),
        2 => Ok(TransportProtocol::Tcp),
        3 => Ok(TransportProtocol::Tls),
        4 => Ok(TransportProtocol::Ws),
        5 => Ok(TransportProtocol::Wss),
        0 => Err(fail(
            SipralStatus::InvalidArgument,
            "a stack has to be told which transport it is speaking",
        )),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{other} is not a transport this library speaks"),
        )),
    }
}

/// A duration a caller gave in milliseconds, or the default it left at zero.
fn interval(millis: u64, default: Duration) -> Duration {
    if millis == 0 {
        default
    } else {
        Duration::from_millis(millis)
    }
}

entry! {
    /// Create a stack, and write its handle to `out_stack`.
    ///
    /// The handle is written only if this returns `SIPRAL_STATUS_OK`. A stack
    /// that is created must be destroyed with [`sipral_stack_destroy`].
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_stack_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_stack` at one `sipral_handle_t`.
    fn sipral_stack_create(config: *const SipralStackConfig, out_stack: *mut SipralHandle) {
        if out_stack.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_stack is null"));
        }
        let config = unsafe { read_versioned(config) }?;
        let Some(callback) = config.event_callback else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "a stack needs an event callback",
            ));
        };
        let protocol = transport_of(config.transport)?;
        let bound = unsafe {
            required_text(config.bind_address, config.bind_address_len, "bind_address")
        }?;
        let Ok(local) = bound.parse::<SocketAddr>() else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("bind_address is {bound:?}, which is not an address and a port"),
            ));
        };
        let named = unsafe { text(config.user_agent, config.user_agent_len, "user_agent") }?;
        let seed = seed_from(unsafe { bytes(config.entropy, config.entropy_len, "entropy") }?)?;

        let mut timers = TimerConfig::DEFAULT;
        timers.t1 = interval(config.timer_t1_ms, TimerConfig::DEFAULT.t1);
        timers.t2 = interval(config.timer_t2_ms, TimerConfig::DEFAULT.t2);
        timers.t4 = interval(config.timer_t4_ms, TimerConfig::DEFAULT.t4);
        let mut endpoint = EndpointConfig::default();
        endpoint.timers = timers;

        let origin = Instant::now();
        let mut agent = UserAgent::new(endpoint, seed);
        // the socket is the caller's; what the stack is told is the address
        // the far end will answer to, which is what goes in every Via
        let bound = agent.receive(
            Input::TransportBound {
                transport: TRANSPORT,
                protocol,
                local,
                remote: None,
            },
            origin,
        );
        if bound.is_err() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "the transport could not be bound",
            ));
        }

        let entry = StackEntry {
            state: Mutex::new(StackState {
                callback,
                user_data: config.event_user_data,
                agent,
                accounts: Names::new(),
                calls: Names::new(),
                transport: TRANSPORT,
                user_agent: named.map(|name| Box::from(name.as_bytes())),
                origin,
                polled_at_ms: 0,
                started: false,
            }),
        };
        let handle = STACKS
            .insert(entry)
            .map_err(|status| fail(status, "no room for another stack"))?;
        unsafe { out_stack.write(handle) };
        Ok(())
    }
}

fn seed_from(entropy: Option<&[u8]>) -> Result<[u8; SEED_BYTES], Fail> {
    let supplied = entropy.unwrap_or_default();
    <[u8; SEED_BYTES]>::try_from(supplied).map_err(|_| {
        fail(
            SipralStatus::InvalidArgument,
            format!(
                "entropy is {} bytes and a stack needs exactly {SEED_BYTES}, from the platform's \
                 own generator",
                supplied.len()
            ),
        )
    })
}

entry! {
    /// Destroy a stack.
    ///
    /// The handle is dead the moment this returns, and a second destroy is
    /// `SIPRAL_STATUS_STALE_HANDLE` rather than a corrupted heap. Called from
    /// inside the callback it is still safe: what the poll is holding stays
    /// alive until that poll returns. No account is de-registered and no call
    /// is hung up; a stack that has to leave politely does that first.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_stack_destroy(stack: SipralHandle) {
        // dropping the last share of the entry here is what frees it; a poll
        // running on another thread holds one of its own until it is done
        STACKS.remove(stack).map_err(handle_failed)?;
        Ok(())
    }
}

entry! {
    /// Let the stack do its work, and deliver what it has to say.
    ///
    /// `now_ms` is the caller's monotonic clock in milliseconds. It must not
    /// go backwards between calls on the same stack; one that does is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` and nothing is delivered.
    ///
    /// The event callback is called from inside this function, on this
    /// thread. A call back into the same stack from the callback returns
    /// `SIPRAL_STATUS_BUSY` and does nothing, so a binding cannot deadlock
    /// itself by answering an event with a request.
    ///
    /// `result` may be null for a caller that does not want the counts.
    ///
    /// # Safety
    ///
    /// `result` must be null or point at a `sipral_poll_result_t` whose `size`
    /// member says how long it is.
    fn sipral_stack_poll(stack: SipralHandle, now_ms: u64, result: *mut SipralPollResult) {
        let counted = with_stack(stack, |state| {
            let now = state.advance(now_ms)?;
            // the result struct is checked before anything is delivered: a
            // caller that got its size wrong should not also lose the events
            if !result.is_null() {
                unsafe { declared_size(result.cast_const()) }?;
            }
            Ok(run(stack, state, now))
        })?;

        if !result.is_null() {
            unsafe { write_versioned(result, counted) }?;
        }
        Ok(())
    }
}

/// One poll: time passes, events go out, output is counted.
fn run(stack: SipralHandle, state: &mut StackState, now: Instant) -> SipralPollResult {
    state.agent.handle_timeout(now);

    let mut delivered = 0_usize;
    let mut unclaimed = 0_usize;

    if !state.started {
        state.started = true;
        let event = crate::event::started(stack);
        state.deliver(&event);
        delivered = delivered.saturating_add(1);
    }

    while let Some(raised) = state.agent.poll_event() {
        let mut known = Vocabulary {
            stack,
            agent: &state.agent,
            accounts: &mut state.accounts,
            calls: &mut state.calls,
        };
        let Some(event) = crate::event::translate(&mut known, &raised) else {
            unclaimed = unclaimed.saturating_add(1);
            continue;
        };
        state.deliver(&event);
        delivered = delivered.saturating_add(1);
        // the handle is retired only after the application has been told, so
        // that the event that says a call is over can still name it
        if let UaEvent::CallEnded { call, .. } = raised {
            state.calls.forget(call);
        }
    }

    let mut discarded = 0_usize;
    while state.agent.poll_transmit().is_some() {
        discarded = discarded.saturating_add(1);
    }

    let deadline = state.agent.poll_timeout();
    SipralPollResult {
        size: size_of::<SipralPollResult>(),
        events_delivered: delivered,
        events_unclaimed: unclaimed,
        transmits_discarded: discarded,
        has_deadline: u32::from(deadline.is_some()),
        next_poll_in_ms: deadline.map_or(0, |at| {
            u64::try_from(at.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        SipralPollResult, SipralStackConfig, SipralTransport, sipral_stack_create,
        sipral_stack_destroy, sipral_stack_poll,
    };
    use crate::error::last_error_text;
    use crate::event::{SipralEvent, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::status::SipralStatus;
    use std::ffi::{c_char, c_void};
    use std::ptr;

    pub(crate) const BIND: &str = "192.0.2.10:5060";
    pub(crate) const SEED: [u8; 32] = [7; 32];

    /// What a caller of the C API would keep behind its user pointer.
    #[derive(Default)]
    pub(crate) struct Observed {
        pub(crate) events: Vec<(SipralHandle, SipralEventKind, usize)>,
        /// The handles the events named, in order.
        pub(crate) named: Vec<(SipralHandle, SipralHandle)>,
        /// Filled by the callbacks that call back into the library.
        reentrant_status: Option<SipralStatus>,
        destroy_status: Option<SipralStatus>,
    }

    impl Observed {
        pub(crate) fn kinds(&self) -> Vec<SipralEventKind> {
            self.events.iter().map(|event| event.1).collect()
        }
    }

    pub(crate) unsafe extern "C" fn record(event: *const SipralEvent, user_data: *mut c_void) {
        let observed = unsafe { &mut *user_data.cast::<Observed>() };
        let event = unsafe { &*event };
        observed.events.push((event.stack, event.kind, event.size));
        observed.named.push((event.account, event.call));
    }

    unsafe extern "C" fn poll_again(event: *const SipralEvent, user_data: *mut c_void) {
        let observed = unsafe { &mut *user_data.cast::<Observed>() };
        let event = unsafe { &*event };
        observed.events.push((event.stack, event.kind, event.size));
        observed.reentrant_status =
            Some(unsafe { sipral_stack_poll(event.stack, 0, ptr::null_mut()) });
    }

    unsafe extern "C" fn destroy_from_inside(event: *const SipralEvent, user_data: *mut c_void) {
        let observed = unsafe { &mut *user_data.cast::<Observed>() };
        let event = unsafe { &*event };
        observed.events.push((event.stack, event.kind, event.size));
        observed.destroy_status = Some(unsafe { sipral_stack_destroy(event.stack) });
    }

    pub(crate) fn config(
        callback: unsafe extern "C" fn(*const SipralEvent, *mut c_void),
        observed: &mut Observed,
    ) -> SipralStackConfig {
        SipralStackConfig {
            size: size_of::<SipralStackConfig>(),
            event_callback: Some(callback),
            event_user_data: ptr::from_mut(observed).cast::<c_void>(),
            transport: SipralTransport::Udp as u32,
            bind_address: BIND.as_ptr().cast::<c_char>(),
            bind_address_len: BIND.len(),
            user_agent: ptr::null(),
            user_agent_len: 0,
            entropy: SEED.as_ptr(),
            entropy_len: SEED.len(),
            timer_t1_ms: 0,
            timer_t2_ms: 0,
            timer_t4_ms: 0,
        }
    }

    pub(crate) fn create(config: &SipralStackConfig) -> (SipralStatus, SipralHandle) {
        let mut handle = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_stack_create(ptr::from_ref(config), &raw mut handle) };
        (status, handle)
    }

    /// A stack with a callback that only writes down what it was given.
    pub(crate) fn stack(observed: &mut Observed) -> SipralHandle {
        let config = config(record, observed);
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok);
        handle
    }

    pub(crate) fn poll_result() -> SipralPollResult {
        SipralPollResult {
            size: size_of::<SipralPollResult>(),
            events_delivered: usize::MAX,
            events_unclaimed: usize::MAX,
            transmits_discarded: usize::MAX,
            has_deadline: u32::MAX,
            next_poll_in_ms: u64::MAX,
        }
    }

    /// Poll, and hand back what it counted.
    pub(crate) fn poll(handle: SipralHandle, now_ms: u64) -> SipralPollResult {
        let mut result = poll_result();
        let status = unsafe { sipral_stack_poll(handle, now_ms, &raw mut result) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        result
    }

    #[test]
    fn a_stack_is_created_and_destroyed() {
        let mut observed = Observed::default();
        let (status, handle) = create(&config(record, &mut observed));
        assert_eq!(status, SipralStatus::Ok);
        assert_ne!(handle, SIPRAL_HANDLE_NONE);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_null_config_is_a_bad_argument() {
        let mut handle = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_stack_create(ptr::null(), &raw mut handle) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(handle, SIPRAL_HANDLE_NONE, "nothing was written");
    }

    #[test]
    fn a_null_out_parameter_is_a_bad_argument() {
        let mut observed = Observed::default();
        let config = config(record, &mut observed);
        let status = unsafe { sipral_stack_create(ptr::from_ref(&config), ptr::null_mut()) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn a_config_that_declares_the_wrong_size_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.size = size_of::<SipralStackConfig>() - 1;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);

        config.size = 0;
        let (status, _) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
    }

    #[test]
    fn a_config_from_a_newer_header_is_taken_as_far_as_this_build_knows() {
        #[repr(C)]
        struct Newer {
            head: SipralStackConfig,
            added: u64,
        }
        let mut observed = Observed::default();
        let mut newer = Newer {
            head: config(record, &mut observed),
            added: 0,
        };
        newer.head.size = size_of::<Newer>();
        let mut handle = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_stack_create(
                (&raw const newer).cast::<SipralStackConfig>(),
                &raw mut handle,
            )
        };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        newer.added = 1;
        let status = unsafe {
            sipral_stack_create(
                (&raw const newer).cast::<SipralStackConfig>(),
                &raw mut handle,
            )
        };
        assert_eq!(
            status,
            SipralStatus::UnsupportedVersion,
            "a member this build would ignore is not ignored quietly"
        );
    }

    #[test]
    fn a_stack_without_a_callback_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.event_callback = None;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);
    }

    #[test]
    fn a_stack_that_was_not_told_its_transport_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.transport = 0;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
        config.transport = 99;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    #[test]
    fn every_transport_this_library_names_is_one_it_takes() {
        let all = [
            SipralTransport::Udp,
            SipralTransport::Tcp,
            SipralTransport::Tls,
            SipralTransport::Ws,
            SipralTransport::Wss,
        ];
        for protocol in all {
            let mut observed = Observed::default();
            let mut config = config(record, &mut observed);
            config.transport = protocol as u32;
            let (status, handle) = create(&config);
            assert_eq!(status, SipralStatus::Ok, "{protocol:?}");
            assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        }
    }

    #[test]
    fn an_address_that_is_not_one_is_refused_and_says_what_it_was_given() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let nonsense = "example.com";
        config.bind_address = nonsense.as_ptr().cast::<c_char>();
        config.bind_address_len = nonsense.len();
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("example.com"));

        config.bind_address = ptr::null();
        config.bind_address_len = 0;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    #[test]
    fn an_ipv6_address_is_an_address() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let bind = "[2001:db8::1]:5060";
        config.bind_address = bind.as_ptr().cast::<c_char>();
        config.bind_address_len = bind.len();
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_stack_with_the_wrong_amount_of_entropy_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.entropy_len = 31;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("31"));

        config.entropy = ptr::null();
        config.entropy_len = 0;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    /// RFC 3261 §8.1.1.7 (Via) only requires the branch parameter to be
    /// unique across space and time; the "cryptographically random"
    /// requirement the entropy field's doc leans on is §19.3, Tags. The
    /// needle is assembled at runtime so this test does not just match its
    /// own assertion.
    #[test]
    fn the_entropy_doc_cites_tags_not_via_for_unguessability() {
        // the needle spans a line break, and a Windows checkout puts a CR in
        // front of it
        let source = include_str!("stack.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("{section}19.3 wants a tag unguessable")),
            "the cryptographic-randomness requirement is in §19.3, not §8.1.1.7"
        );
    }

    #[test]
    fn a_user_agent_string_that_would_smuggle_a_header_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let hostile = "sipral\r\nContact: <sip:elsewhere@example.net>";
        config.user_agent = hostile.as_ptr().cast::<c_char>();
        config.user_agent_len = hostile.len();
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    #[test]
    fn the_first_poll_says_the_stack_is_running_and_the_second_says_nothing() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);

        let result = poll(handle, 1_000);
        assert_eq!(result.events_delivered, 1);
        assert_eq!(result.size, size_of::<SipralPollResult>());

        let result = poll(handle, 1_001);
        assert_eq!(result.events_delivered, 0);

        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(
            observed.events,
            vec![(handle, SipralEventKind::Started, size_of::<SipralEvent>())]
        );
    }

    #[test]
    fn a_stack_with_nothing_to_do_has_no_deadline() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let result = poll(handle, 0);
        assert_eq!(result.has_deadline, 0);
        assert_eq!(result.next_poll_in_ms, 0);
        assert_eq!(result.transmits_discarded, 0);
        assert_eq!(result.events_unclaimed, 0);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn poll_takes_a_null_result_from_a_caller_that_does_not_want_the_count() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(observed.events.len(), 1);
    }

    #[test]
    fn a_result_struct_of_the_wrong_size_costs_no_events() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);

        let mut result = poll_result();
        result.size = size_of::<SipralPollResult>() - 1;
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, &raw mut result) },
            SipralStatus::UnsupportedVersion
        );
        assert!(observed.events.is_empty(), "nothing was delivered");

        let result = poll(handle, 0);
        assert_eq!(result.events_delivered, 1, "the event was still waiting");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_clock_that_goes_backwards_is_refused_and_says_by_how_much() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 5_000, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 4_999, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        let message = last_error_text();
        assert!(
            message.contains("4999") && message.contains("5000"),
            "the message names neither instant: {message}"
        );
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 5_000, ptr::null_mut()) },
            SipralStatus::Ok,
            "the same instant twice is not backwards"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_clock_as_far_ahead_as_it_counts_is_answered_rather_than_overflowing() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        // adding half a billion years to an instant is a panic on a platform
        // whose clock is narrow enough, and a panic here would be a status
        // code the caller cannot recover from
        let status = unsafe { sipral_stack_poll(handle, u64::MAX, ptr::null_mut()) };
        assert!(
            status == SipralStatus::Ok || status == SipralStatus::InvalidArgument,
            "an instant that far ahead answered {status:?}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn polling_a_stack_that_was_never_created_is_an_invalid_handle() {
        assert_eq!(
            unsafe { sipral_stack_poll(SIPRAL_HANDLE_NONE, 0, ptr::null_mut()) },
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            unsafe { sipral_stack_destroy(SIPRAL_HANDLE_NONE) },
            SipralStatus::InvalidHandle
        );
    }

    #[test]
    fn polling_a_destroyed_stack_is_a_stale_handle() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, ptr::null_mut()) },
            SipralStatus::StaleHandle
        );
        assert!(observed.events.is_empty());
    }

    #[test]
    fn destroying_a_stack_twice_is_a_stale_handle() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_destroy(handle) },
            SipralStatus::StaleHandle
        );
    }

    #[test]
    fn calling_back_into_a_stack_from_its_own_callback_is_busy_and_not_a_deadlock() {
        let mut observed = Observed::default();
        let (status, handle) = create(&config(poll_again, &mut observed));
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(observed.reentrant_status, Some(SipralStatus::Busy));
        assert!(
            last_error_text().is_empty(),
            "the poll succeeded, so what failed inside it is not this thread's last error"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_stack_destroyed_from_inside_its_own_callback_survives_the_poll() {
        let mut observed = Observed::default();
        let (status, handle) = create(&config(destroy_from_inside, &mut observed));
        assert_eq!(status, SipralStatus::Ok);
        let mut result = poll_result();
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, &raw mut result) },
            SipralStatus::Ok
        );
        assert_eq!(observed.destroy_status, Some(SipralStatus::Ok));
        assert_eq!(result.events_delivered, 1);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 1, ptr::null_mut()) },
            SipralStatus::StaleHandle
        );
        assert_eq!(
            unsafe { sipral_stack_destroy(handle) },
            SipralStatus::StaleHandle
        );
    }

    #[test]
    fn two_stacks_do_not_share_a_thing() {
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack(&mut first_observed);
        let second = stack(&mut second_observed);
        assert_ne!(first, second);

        assert_eq!(
            unsafe { sipral_stack_poll(first, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(unsafe { sipral_stack_destroy(first) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(second, 0, ptr::null_mut()) },
            SipralStatus::Ok,
            "destroying one stack leaves the other alone"
        );
        assert_eq!(unsafe { sipral_stack_destroy(second) }, SipralStatus::Ok);
        assert_eq!(first_observed.events.len(), 1);
        assert_eq!(second_observed.events.len(), 1);
        assert_eq!(
            first_observed.events.first().map(|event| event.0),
            Some(first)
        );
        assert_eq!(
            second_observed.events.first().map(|event| event.0),
            Some(second)
        );
    }

    #[test]
    fn a_stack_can_be_polled_from_another_thread_than_the_one_that_made_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let polled =
            std::thread::spawn(move || unsafe { sipral_stack_poll(handle, 7, ptr::null_mut()) })
                .join()
                .expect("the thread finished");
        assert_eq!(polled, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 6, ptr::null_mut()) },
            SipralStatus::InvalidArgument,
            "the clock is the stack's, not the thread's"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(observed.events.len(), 1);
    }

    #[test]
    fn the_event_says_which_stack_it_is_about() {
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack(&mut first_observed);
        let second = stack(&mut second_observed);
        assert_eq!(
            unsafe { sipral_stack_poll(second, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert!(first_observed.events.is_empty());
        assert_eq!(
            second_observed.events,
            vec![(second, SipralEventKind::Started, size_of::<SipralEvent>())]
        );
        assert_eq!(unsafe { sipral_stack_destroy(first) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(second) }, SipralStatus::Ok);
    }

    #[test]
    fn what_the_stack_holds_can_move_between_threads() {
        const fn moves<T: Send>() {}
        moves::<sipral_ua::UserAgent>();
    }
}
