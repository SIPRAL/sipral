// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One event, one callback, one tagged union.
//!
//! Everything the stack has to say arrives as a [`SipralEvent`]: a size, the
//! handles it is about, a kind, and a union whose arm the kind names. One
//! struct rather than one callback per kind, because a binding that registers
//! fourteen function pointers has fourteen chances to leave one null, and
//! because a kind added later then costs a caller nothing — it reads the
//! kind it does not know and ignores it.
//!
//! Nothing inside the union is an enumerated type. A union arm the library did
//! not write holds whatever the arm it did write put there, and reading a Rust
//! enum out of bits that were never one of its values is undefined behaviour,
//! so every enumerated member in there is a plain integer whose names are
//! declared next to it. The head of the struct, which is written every time,
//! keeps its types.
//!
//! Pointers in an event belong to the library and are valid for the duration of
//! the callback and no longer. A binding copies what it wants out before it
//! returns; there is nothing to free.

use std::ffi::{c_char, c_void};
use std::time::Duration;

use sipral_ua::{
    CallEndReason, CallHandle, CallState, RegistrationFailure, RegistrationState, UaEvent,
    UserAgent,
};

use crate::error::entry;
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::names::Names;

/// Declare the event number space, once.
///
/// Everything that has to agree about an event's number is written here and
/// generated from here: the enum, the name a log line prints, and the number
/// the two are indexed by. A kind cannot be added to one of those and missed in
/// the other, because there is only one place to add it.
///
/// A number is spent by appearing in this list, live or reserved, and the
/// generated assertion is that the list runs `1, 2, 3, …` with nothing repeated
/// and no hole. A hole is what two features fall into: each takes the number
/// after the last live kind, each builds, and the one that lands second has
/// silently renamed an event that a shipped binding already knows. A reserved
/// line is that hole filled in advance — the number belongs to a named feature
/// before the feature is written, so taking it is reading rather than choosing.
///
/// Removing or reordering a line is what `docs/08-ffi.md` forbids outright, and
/// what the assertion turns from a released mistake into a build failure.
macro_rules! event_kinds {
    (
        $(
            $(#[$about:meta])*
            $number:literal = $variant:ident, $name:literal;
        )*
        $(
            reserved $held:literal = $feature:literal;
        )*
    ) => {
        /// What an event is about.
        ///
        /// The numbers are part of the ABI and are only ever added to. A
        /// binding that meets a kind it does not know must ignore that event
        /// rather than refuse it, which is what makes adding one safe.
        ///
        /// Numbers already spent on features this build does not have, so that
        /// two of them cannot arrive holding the same one:
        ///
        $(#[doc = concat!(" - `", stringify!($held), "` — ", $feature)])*
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum SipralEventKind {
            $(
                $(#[$about])*
                $variant = $number,
            )*
        }

        impl SipralEventKind {
            /// Every kind this build has, in the order their numbers were
            /// spent.
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];
        }

        entry! {
            /// The short name of an event kind, as a static NUL-terminated
            /// string, or null for a number this build has no kind for.
            ///
            /// The string belongs to the library and lives as long as it is
            /// loaded. A number that is reserved for a feature this build does
            /// not have answers null, the same as one that was never spent: a
            /// name for something that cannot arrive would be a name for
            /// nothing.
            ///
            /// # Safety
            ///
            /// Reads no memory the caller owns, and is safe to call from any
            /// thread.
            fn sipral_event_kind_name(kind: u32) -> *const c_char, on_panic = std::ptr::null(), {
                match kind {
                    $($number => $name.as_ptr(),)*
                    _ => std::ptr::null(),
                }
            }
        }

        // every number in the list, live and reserved, against the one it has
        // to be: this is the build failure that a collision, a hole or a
        // reordering becomes
        const _: () = {
            let mut next = 1_u32;
            $(
                assert!(
                    $number == next,
                    "an event kind's number is not the one after the last: the numbers this ABI \
                     has spent run 1, 2, 3, … and nothing may repeat, move or leave a hole"
                );
                next += 1;
            )*
            $(
                assert!(
                    $held == next,
                    "a reserved event number is not the one after the last: reservations continue \
                     the same run, so that the number a feature takes is already written down"
                );
                next += 1;
            )*
        };
    };
}

event_kinds! {
    /// The stack is running on this thread.
    ///
    /// The first event on every stack, delivered by the first poll and never
    /// again. A binding that has a callback to hand out, a queue to open or a
    /// thread to name has somewhere definite to do it, before anything that
    /// matters can arrive.
    1 = Started, c"started";
    /// A registration moved: it went out, it took, it is being refreshed, it
    /// was given up, or it failed. `payload.registration` says which, and
    /// `account` says whose.
    2 = RegistrationChanged, c"registration changed";
    /// Somebody is calling. Answer, ring, or reject it.
    3 = IncomingCall, c"incoming call";
    /// A call this end placed is getting somewhere short of an answer.
    4 = CallProgress, c"call progress";
    /// A proxy forked the INVITE and a second phone is ringing.
    /// `payload.call.other` is the branch that has just appeared.
    5 = CallForked, c"call forked";
    /// The call is up.
    6 = CallConfirmed, c"call confirmed";
    /// The session inside a live call changed: a hold, a resume, or an offer
    /// either end made and had accepted.
    7 = SessionChanged, c"session changed";
    /// The far end offered a change this stack has no policy for. The
    /// transaction is held open: answer it or refuse it, or the call ends.
    8 = SessionOffered, c"session offered";
    /// A change this end offered was refused. The session stands as it was.
    9 = SessionChangeFailed, c"session change failed";
    /// The far end asked this one to call somebody else.
    10 = TransferRequested, c"transfer requested";
    /// A transfer this end asked for is under way.
    11 = TransferProgress, c"transfer progress";
    /// And how it ended.
    12 = TransferDone, c"transfer done";
    /// A call arrived carrying a `Replaces` and took over one already up.
    /// `payload.call.other` is the one being replaced.
    13 = CallReplaced, c"call replaced";
    /// The call is over, and its handle is stale from here on.
    14 = CallEnded, c"call ended";

    // Held for what `docs/13-client-requirements.md` already commits to, so
    // that six features written in six branches cannot arrive holding the same
    // number. Taking one means turning its line into a kind above, in place.
    reserved 15 = "a subscription's state changed (A1)";
    reserved 16 = "the set of audio devices changed (A2)";
    reserved 17 = "stream statistics (A6)";
    reserved 18 = "a request was promoted to a stream transport (B1)";
    reserved 19 = "media stopped arriving (B5)";
    reserved 20 = "a call was announced and never arrived (C2)";
}

/// Where a registration is. Names for `sipral_registration_event_t::state`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralRegistrationState {
    /// The account is gone, or has never been asked about.
    Unknown = 0,
    /// Configured and not registered. Nothing has been sent.
    Idle = 1,
    /// A REGISTER is in flight and there is no binding yet.
    Registering = 2,
    /// The registrar holds a binding.
    Registered = 3,
    /// A refresh is in flight. The binding stands until it is answered.
    Refreshing = 4,
    /// Something recoverable went wrong and the next attempt is scheduled.
    Retrying = 5,
    /// The binding was given up on purpose.
    Unregistered = 6,
    /// The registrar refused in a way that trying again cannot fix.
    Failed = 7,
}

/// Why a registration is not live. Names for
/// `sipral_registration_event_t::failure`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralRegistrationFailure {
    /// Nothing failed.
    None = 0,
    /// The registrar refused, and will refuse the same request again.
    Rejected = 1,
    /// The password was wrong, or there was none to answer with.
    BadCredentials = 2,
    /// The registrar is not answering, or says it cannot serve this now.
    Unreachable = 3,
    /// The registrar moved. Following it needs an address, which is the
    /// caller's to resolve.
    Redirected = 4,
}

/// Where a call is. Names for `sipral_call_event_t::state`, and what
/// `sipral_call_state` writes.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralCallState {
    /// The call is gone, or has never been asked about.
    Unknown = 0,
    /// The INVITE has gone and nothing has come back.
    Calling = 1,
    /// Somebody is calling and this end has not answered.
    Incoming = 2,
    /// The far end is ringing, or this end said it is.
    Ringing = 3,
    /// There is audio before anybody answered.
    EarlyMedia = 4,
    /// Up.
    Confirmed = 5,
    /// Up, in order to be transferred: the second leg of an attended transfer.
    Consulting = 6,
    /// A CANCEL or a BYE has gone and is not answered yet.
    Terminating = 7,
    /// Over.
    Terminated = 8,
}

/// Why a call is over. Names for `sipral_call_event_t::end_reason`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralCallEndReason {
    /// The call is not over.
    None = 0,
    /// This end hung up.
    LocalHangup = 1,
    /// The far end hung up.
    RemoteHangup = 2,
    /// The far end refused it: busy, declined, not found.
    Refused = 3,
    /// Given up before it was answered, from either end.
    Cancelled = 4,
    /// Nothing came back, or the transport died.
    Unreachable = 5,
    /// Another branch of the same fork was kept and this one was not.
    ForkLost = 6,
    /// The branch was still ringing when the answer window closed.
    Abandoned = 7,
    /// The session timer ran out and no refresh arrived.
    Expired = 8,
}

/// What a [`SipralEventKind::RegistrationChanged`] carries.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralRegistrationEvent {
    /// A [`SipralRegistrationState`].
    pub state: u32,
    /// A [`SipralRegistrationFailure`], zero when nothing failed.
    pub failure: u32,
    /// The status the registrar answered with, or zero when none arrived.
    pub status_code: u32,
    /// The binding's granted lifetime, zero unless it is live.
    pub expires_ms: u64,
    /// How long until the refresh, zero unless one is scheduled.
    pub refresh_in_ms: u64,
    /// How long until the next attempt. Only meaningful while the state is
    /// retrying, which is exactly when the stack is going to try again.
    pub retry_in_ms: u64,
}

/// What every call event carries.
///
/// Not every member means something in every kind, and the ones that do not
/// are zero. A zero here always reads as absent rather than as a value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralCallEvent {
    /// A [`SipralCallState`].
    pub state: u32,
    /// A [`SipralCallEndReason`], zero while the call is alive.
    pub end_reason: u32,
    /// The status a response carried, or zero.
    pub status_code: u32,
    /// The other call this event is also about: the sibling of a fork, or the
    /// call that was replaced. [`SIPRAL_HANDLE_NONE`] otherwise.
    pub other: SipralHandle,
    /// Whether this end has asked the far end to stop sending.
    pub held_here: u32,
    /// Whether the far end has asked this one to.
    pub held_there: u32,
    /// What this end is describing, and how long it is.
    pub local_sdp: *const u8,
    /// How many bytes of it.
    pub local_sdp_len: usize,
    /// And what the far end is.
    pub remote_sdp: *const u8,
    /// How many bytes of it.
    pub remote_sdp_len: usize,
    /// When a refused session change goes out again by itself, zero when it is
    /// not going to.
    pub retry_in_ms: u64,
}

/// What a transfer event carries.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralTransferEvent {
    /// What the far end's own call is doing, or zero.
    pub status_code: u32,
    /// Whether the request named a dialog to replace, which is what makes a
    /// transfer attended rather than blind.
    pub attended: u32,
    /// Who to call, as UTF-8. Not NUL-terminated.
    pub target: *const c_char,
    /// How many bytes of it.
    pub target_len: usize,
}

/// The arm of an event that its kind names.
///
/// Reading any other arm reads bytes the library did not write for it.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SipralEventPayload {
    /// For [`SipralEventKind::RegistrationChanged`].
    pub registration: SipralRegistrationEvent,
    /// For every call kind.
    pub call: SipralCallEvent,
    /// For [`SipralEventKind::TransferRequested`],
    /// [`SipralEventKind::TransferProgress`] and
    /// [`SipralEventKind::TransferDone`].
    pub transfer: SipralTransferEvent,
}

/// Something the library has to tell the application.
///
/// The pointer handed to the callback is the library's, and it is valid for
/// the duration of that call and no longer. `size` says how much of the
/// struct this build filled in, and a binding reads no further than that. The
/// union stays the last member for the same reason: an arm that grows grows
/// the tail, which is the one place a released struct may change.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralEvent {
    /// How many bytes of this struct are meaningful.
    pub size: usize,
    /// The stack it is about.
    pub stack: SipralHandle,
    /// What it is.
    pub kind: SipralEventKind,
    /// The account it is about, or [`SIPRAL_HANDLE_NONE`].
    pub account: SipralHandle,
    /// The call it is about, or [`SIPRAL_HANDLE_NONE`].
    pub call: SipralHandle,
    /// The SIP message behind it, whole and unparsed, when there is one.
    ///
    /// A reason phrase, a `Retry-After`, the `Contact` of a redirect and the
    /// caller's display name all live here and none of them is worth a member
    /// of its own. Null when the event came from no single message.
    pub message: *const u8,
    /// How many bytes of it.
    pub message_len: usize,
    /// The arm [`SipralEvent::kind`] names.
    pub payload: SipralEventPayload,
}

/// The one callback a stack has.
///
/// It is called from inside `sipral_stack_poll`, on the thread that called it,
/// with the `user_data` the stack was created with. It must not unwind, and it
/// must not call back into the stack it was given: see [`crate::stack`].
pub type SipralEventCallback =
    Option<unsafe extern "C" fn(event: *const SipralEvent, user_data: *mut c_void)>;

impl SipralEvent {
    /// An event with nothing in it but its kind, for a kind to fill in.
    ///
    /// The payload is written whole, never a member at a time: a union member
    /// is a place the library has to know it owns before it writes through it,
    /// and one assignment of the arm the kind names is the way to be sure.
    fn of(stack: SipralHandle, kind: SipralEventKind, payload: SipralEventPayload) -> Self {
        Self {
            size: size_of::<Self>(),
            stack,
            kind,
            account: SIPRAL_HANDLE_NONE,
            call: SIPRAL_HANDLE_NONE,
            message: std::ptr::null(),
            message_len: 0,
            payload,
        }
    }
}

impl SipralCallEvent {
    /// Nothing said about anything, for a kind to fill in.
    const fn empty() -> Self {
        Self {
            state: SipralCallState::Unknown as u32,
            end_reason: SipralCallEndReason::None as u32,
            status_code: 0,
            other: SIPRAL_HANDLE_NONE,
            held_here: 0,
            held_there: 0,
            local_sdp: std::ptr::null(),
            local_sdp_len: 0,
            remote_sdp: std::ptr::null(),
            remote_sdp_len: 0,
            retry_in_ms: 0,
        }
    }
}

/// The first event on every stack.
pub(crate) fn started(stack: SipralHandle) -> SipralEvent {
    SipralEvent::of(
        stack,
        SipralEventKind::Started,
        SipralEventPayload {
            call: SipralCallEvent::empty(),
        },
    )
}

/// Everything one translation needs to reach.
pub(crate) struct Vocabulary<'a> {
    pub(crate) stack: SipralHandle,
    pub(crate) agent: &'a UserAgent,
    pub(crate) accounts: &'a mut Names<sipral_ua::AccountId>,
    pub(crate) calls: &'a mut Names<CallHandle>,
}

/// Say a user agent event the way C says it.
///
/// `None` for one this ABI has no word for. Nothing is invented: an event that
/// would arrive carrying only its own existence tells a binding nothing it can
/// act on, and the poll result counts them instead so that the gap is a number
/// rather than a silence.
///
/// The pointers in what comes back borrow from `event`, so it has to outlive
/// the callback it is handed to.
pub(crate) fn translate(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    if let Some(out) = about_registration(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_call(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_session(known, event) {
        return Some(out);
    }
    if let Some(out) = about_a_call_ending(known, event) {
        return Some(out);
    }
    about_a_transfer(known, event)
}

fn about_registration(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::Registering { account }
        | UaEvent::Refreshing { account }
        | UaEvent::Unregistered { account } => {
            let payload = registration_payload(known, account, None);
            Some(registration_event(known, account, payload))
        }
        UaEvent::Registered {
            account,
            expires,
            refresh_in,
        } => {
            let mut payload = registration_payload(known, account, None);
            payload.expires_ms = millis(expires);
            payload.refresh_in_ms = millis(refresh_in);
            Some(registration_event(known, account, payload))
        }
        UaEvent::RegistrationFailed {
            account,
            reason,
            status,
            retry_in,
            ref response,
        } => {
            let mut payload = registration_payload(known, account, Some(reason));
            payload.status_code = status_of(status);
            payload.retry_in_ms = retry_in.map_or(0, millis);
            let mut out = registration_event(known, account, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

fn about_a_call(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::IncomingCall {
            call,
            account,
            ref request,
        } => {
            let payload = call_payload(known, call);
            let mut out = call_event(known, SipralEventKind::IncomingCall, call, payload);
            out.account = account
                .and_then(|id| known.accounts.name_of(id).ok())
                .unwrap_or(SIPRAL_HANDLE_NONE);
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::CallProgress {
            call,
            status,
            ref response,
            ..
        } => {
            let mut payload = call_payload(known, call);
            payload.status_code = u32::from(status.get());
            let mut out = call_event(known, SipralEventKind::CallProgress, call, payload);
            attach(&mut out, Some(response));
            Some(out)
        }
        UaEvent::CallForked { call, sibling } => {
            let mut payload = call_payload(known, call);
            payload.other = known.calls.name_of(sibling).unwrap_or(SIPRAL_HANDLE_NONE);
            Some(call_event(
                known,
                SipralEventKind::CallForked,
                call,
                payload,
            ))
        }
        UaEvent::CallConfirmed {
            call, ref response, ..
        } => {
            let payload = call_payload(known, call);
            let mut out = call_event(known, SipralEventKind::CallConfirmed, call, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

fn about_a_session(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::SessionChanged {
            call,
            hold,
            ref local,
            ref remote,
        } => {
            let mut payload = call_payload(known, call);
            payload.held_here = u32::from(hold.local);
            payload.held_there = u32::from(hold.remote);
            if let Some(sdp) = local.as_deref() {
                payload.local_sdp = sdp.as_ptr();
                payload.local_sdp_len = sdp.len();
            }
            if let Some(sdp) = remote.as_deref() {
                payload.remote_sdp = sdp.as_ptr();
                payload.remote_sdp_len = sdp.len();
            }
            Some(call_event(
                known,
                SipralEventKind::SessionChanged,
                call,
                payload,
            ))
        }
        UaEvent::Reoffer { call, ref request } => {
            let payload = call_payload(known, call);
            let mut out = call_event(known, SipralEventKind::SessionOffered, call, payload);
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::SessionChangeFailed {
            call,
            status,
            retry_in,
            ref response,
        } => {
            let mut payload = call_payload(known, call);
            payload.status_code = status_of(status);
            payload.retry_in_ms = retry_in.map_or(0, millis);
            let mut out = call_event(known, SipralEventKind::SessionChangeFailed, call, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

fn about_a_call_ending(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::CallReplaced { call, replaced } => {
            let mut payload = call_payload(known, call);
            payload.other = known.calls.name_of(replaced).unwrap_or(SIPRAL_HANDLE_NONE);
            Some(call_event(
                known,
                SipralEventKind::CallReplaced,
                call,
                payload,
            ))
        }
        UaEvent::CallEnded {
            call,
            reason,
            status,
            ref response,
        } => {
            let mut payload = call_payload(known, call);
            // the layer below has already let the call go, so the state is
            // said here rather than asked for
            payload.state = SipralCallState::Terminated as u32;
            payload.end_reason = end_reason(reason) as u32;
            payload.status_code = status_of(status);
            let mut out = call_event(known, SipralEventKind::CallEnded, call, payload);
            attach(&mut out, response.as_ref());
            Some(out)
        }
        _ => None,
    }
}

fn about_a_transfer(known: &mut Vocabulary<'_>, event: &UaEvent) -> Option<SipralEvent> {
    match *event {
        UaEvent::TransferRequested {
            call,
            ref target,
            attended,
            ref request,
        } => {
            let uri = target.as_bytes();
            let payload = SipralTransferEvent {
                status_code: 0,
                attended: u32::from(attended),
                target: uri.as_ptr().cast::<c_char>(),
                target_len: uri.len(),
            };
            let mut out = transfer_event(known, SipralEventKind::TransferRequested, call, payload);
            attach(&mut out, Some(request));
            Some(out)
        }
        UaEvent::TransferProgress { call, status } => Some(transfer_event(
            known,
            SipralEventKind::TransferProgress,
            call,
            reported(status.get()),
        )),
        UaEvent::TransferDone { call, status } => Some(transfer_event(
            known,
            SipralEventKind::TransferDone,
            call,
            reported(status.get()),
        )),
        // a protocol event this stack has no policy for and this ABI has no
        // word for; the poll result counts it, and the layer below is free to
        // grow a vocabulary faster than this one.
        //
        // This arm cannot be deleted to make the compiler demand a translation
        // for every new one: `UaEvent` is `#[non_exhaustive]`, so a match on it
        // outside its own crate is required to have a wildcard. What that
        // buys is a layer below that can add an event without breaking this
        // one, and what it costs is that the compiler cannot notice a kind
        // this ABI has not caught up with. The number space above is where the
        // guarantee lives instead, because that is where a mistake would be
        // permanent.
        _ => None,
    }
}

fn registration_payload(
    known: &Vocabulary<'_>,
    account: sipral_ua::AccountId,
    failure: Option<RegistrationFailure>,
) -> SipralRegistrationEvent {
    SipralRegistrationEvent {
        state: registration_state(known.agent.registration_state(account)) as u32,
        failure: failure.map_or(SipralRegistrationFailure::None, registration_failure) as u32,
        status_code: 0,
        expires_ms: 0,
        refresh_in_ms: 0,
        retry_in_ms: 0,
    }
}

fn registration_event(
    known: &mut Vocabulary<'_>,
    account: sipral_ua::AccountId,
    payload: SipralRegistrationEvent,
) -> SipralEvent {
    let mut out = SipralEvent::of(
        known.stack,
        SipralEventKind::RegistrationChanged,
        SipralEventPayload {
            registration: payload,
        },
    );
    out.account = known
        .accounts
        .name_of(account)
        .unwrap_or(SIPRAL_HANDLE_NONE);
    out
}

fn call_payload(known: &Vocabulary<'_>, call: CallHandle) -> SipralCallEvent {
    SipralCallEvent {
        state: call_state(known.agent.call_state(call)) as u32,
        ..SipralCallEvent::empty()
    }
}

fn call_event(
    known: &mut Vocabulary<'_>,
    kind: SipralEventKind,
    call: CallHandle,
    payload: SipralCallEvent,
) -> SipralEvent {
    let mut out = SipralEvent::of(known.stack, kind, SipralEventPayload { call: payload });
    out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    out
}

fn transfer_event(
    known: &mut Vocabulary<'_>,
    kind: SipralEventKind,
    call: CallHandle,
    payload: SipralTransferEvent,
) -> SipralEvent {
    let mut out = SipralEvent::of(known.stack, kind, SipralEventPayload { transfer: payload });
    out.call = known.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    out
}

/// A transfer event that says only what the far end reported.
fn reported(status: u16) -> SipralTransferEvent {
    SipralTransferEvent {
        status_code: u32::from(status),
        attended: 0,
        target: std::ptr::null(),
        target_len: 0,
    }
}

fn status_of(status: Option<sipral_core::msg::StatusCode>) -> u32 {
    status.map_or(0, |code| u32::from(code.get()))
}

/// Point the event at the message it came from, which the caller of the
/// callback still owns.
fn attach(event: &mut SipralEvent, message: Option<&sipral_core::msg::OwnedMessage>) {
    if let Some(message) = message {
        let raw = message.as_raw().as_bytes();
        event.message = raw.as_ptr();
        event.message_len = raw.len();
    }
}

/// Milliseconds, saturating rather than wrapping: a duration too long to
/// count is one no caller is waiting for anyway.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn registration_state(state: Option<RegistrationState>) -> SipralRegistrationState {
    match state {
        Some(RegistrationState::Idle) => SipralRegistrationState::Idle,
        Some(RegistrationState::Registering) => SipralRegistrationState::Registering,
        Some(RegistrationState::Registered) => SipralRegistrationState::Registered,
        Some(RegistrationState::Refreshing) => SipralRegistrationState::Refreshing,
        Some(RegistrationState::Retrying) => SipralRegistrationState::Retrying,
        Some(RegistrationState::Unregistered) => SipralRegistrationState::Unregistered,
        Some(RegistrationState::Failed) => SipralRegistrationState::Failed,
        // nothing to ask about, or a state the layer below has grown and this
        // ABI has no number for; saying so beats picking one that is wrong
        None | Some(_) => SipralRegistrationState::Unknown,
    }
}

fn registration_failure(failure: RegistrationFailure) -> SipralRegistrationFailure {
    match failure {
        RegistrationFailure::Rejected => SipralRegistrationFailure::Rejected,
        RegistrationFailure::BadCredentials => SipralRegistrationFailure::BadCredentials,
        RegistrationFailure::Unreachable => SipralRegistrationFailure::Unreachable,
        RegistrationFailure::Redirected => SipralRegistrationFailure::Redirected,
        _ => SipralRegistrationFailure::None,
    }
}

pub(crate) fn call_state(state: Option<CallState>) -> SipralCallState {
    match state {
        Some(CallState::Calling) => SipralCallState::Calling,
        Some(CallState::Incoming) => SipralCallState::Incoming,
        Some(CallState::Ringing) => SipralCallState::Ringing,
        Some(CallState::EarlyMedia) => SipralCallState::EarlyMedia,
        Some(CallState::Confirmed) => SipralCallState::Confirmed,
        Some(CallState::Consulting) => SipralCallState::Consulting,
        Some(CallState::Terminating) => SipralCallState::Terminating,
        Some(CallState::Terminated) => SipralCallState::Terminated,
        None | Some(_) => SipralCallState::Unknown,
    }
}

fn end_reason(reason: CallEndReason) -> SipralCallEndReason {
    match reason {
        CallEndReason::LocalHangup => SipralCallEndReason::LocalHangup,
        CallEndReason::RemoteHangup => SipralCallEndReason::RemoteHangup,
        CallEndReason::Refused => SipralCallEndReason::Refused,
        CallEndReason::Cancelled => SipralCallEndReason::Cancelled,
        CallEndReason::Unreachable => SipralCallEndReason::Unreachable,
        CallEndReason::ForkLost => SipralCallEndReason::ForkLost,
        CallEndReason::Abandoned => SipralCallEndReason::Abandoned,
        CallEndReason::Expired => SipralCallEndReason::Expired,
        _ => SipralCallEndReason::None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralCallEndReason, SipralCallEvent, SipralCallState, SipralEvent, SipralEventKind,
        SipralEventPayload, SipralRegistrationFailure, SipralRegistrationState, call_state,
        end_reason, millis, registration_state, sipral_event_kind_name,
    };
    use sipral_ua::{CallEndReason, CallState, RegistrationState};
    use std::ffi::CStr;
    use std::time::Duration;

    fn name(kind: u32) -> Option<String> {
        let pointer = unsafe { sipral_event_kind_name(kind) };
        if pointer.is_null() {
            return None;
        }
        Some(
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    fn started(stack: u64) -> SipralEvent {
        SipralEvent::of(
            stack,
            SipralEventKind::Started,
            SipralEventPayload {
                call: SipralCallEvent::empty(),
            },
        )
    }

    #[test]
    fn the_size_member_comes_first_and_says_how_big_the_struct_is() {
        let event = started(9);
        assert_eq!(event.size, size_of::<SipralEvent>());
        let first = unsafe { (&raw const event).cast::<usize>().read_unaligned() };
        assert_eq!(first, size_of::<SipralEvent>());
    }

    #[test]
    fn an_empty_event_names_neither_an_account_nor_a_call() {
        let event = started(9);
        assert_eq!(event.stack, 9);
        assert_eq!(event.account, 0);
        assert_eq!(event.call, 0);
        assert!(event.message.is_null());
        assert_eq!(event.message_len, 0);
    }

    #[test]
    fn the_union_is_the_last_member_so_that_an_arm_can_grow() {
        let event = started(1);
        let base = (&raw const event).cast::<u8>() as usize;
        let payload = (&raw const event.payload).cast::<u8>() as usize;
        let offset = payload - base;
        assert_eq!(
            offset + size_of_val(&event.payload),
            size_of::<SipralEvent>()
        );
    }

    #[test]
    fn every_state_the_layer_below_has_is_named_here() {
        let all = [
            (RegistrationState::Idle, SipralRegistrationState::Idle),
            (
                RegistrationState::Registering,
                SipralRegistrationState::Registering,
            ),
            (
                RegistrationState::Registered,
                SipralRegistrationState::Registered,
            ),
            (
                RegistrationState::Refreshing,
                SipralRegistrationState::Refreshing,
            ),
            (
                RegistrationState::Retrying,
                SipralRegistrationState::Retrying,
            ),
            (
                RegistrationState::Unregistered,
                SipralRegistrationState::Unregistered,
            ),
            (RegistrationState::Failed, SipralRegistrationState::Failed),
        ];
        for (state, expected) in all {
            assert_eq!(registration_state(Some(state)), expected);
        }
        assert_eq!(registration_state(None), SipralRegistrationState::Unknown);
    }

    #[test]
    fn every_call_state_the_layer_below_has_is_named_here() {
        let all = [
            (CallState::Calling, SipralCallState::Calling),
            (CallState::Incoming, SipralCallState::Incoming),
            (CallState::Ringing, SipralCallState::Ringing),
            (CallState::EarlyMedia, SipralCallState::EarlyMedia),
            (CallState::Confirmed, SipralCallState::Confirmed),
            (CallState::Consulting, SipralCallState::Consulting),
            (CallState::Terminating, SipralCallState::Terminating),
            (CallState::Terminated, SipralCallState::Terminated),
        ];
        for (state, expected) in all {
            assert_eq!(call_state(Some(state)), expected);
        }
        assert_eq!(call_state(None), SipralCallState::Unknown);
    }

    #[test]
    fn every_reason_a_call_ends_for_is_named_here() {
        let all = [
            (CallEndReason::LocalHangup, SipralCallEndReason::LocalHangup),
            (
                CallEndReason::RemoteHangup,
                SipralCallEndReason::RemoteHangup,
            ),
            (CallEndReason::Refused, SipralCallEndReason::Refused),
            (CallEndReason::Cancelled, SipralCallEndReason::Cancelled),
            (CallEndReason::Unreachable, SipralCallEndReason::Unreachable),
            (CallEndReason::ForkLost, SipralCallEndReason::ForkLost),
            (CallEndReason::Abandoned, SipralCallEndReason::Abandoned),
            (CallEndReason::Expired, SipralCallEndReason::Expired),
        ];
        for (reason, expected) in all {
            assert_eq!(end_reason(reason), expected);
        }
    }

    #[test]
    fn nothing_that_means_absent_shares_a_number_with_something_that_does_not() {
        assert_eq!(SipralRegistrationState::Unknown as u32, 0);
        assert_eq!(SipralRegistrationFailure::None as u32, 0);
        assert_eq!(SipralCallState::Unknown as u32, 0);
        assert_eq!(SipralCallEndReason::None as u32, 0);
    }

    /// The numbers are written out rather than walked. A test that derived
    /// them from the declaration would agree with a declaration that had moved
    /// them, which is the one thing `docs/08-ffi.md` says can never happen.
    #[test]
    fn the_event_numbers_are_where_they_were_published() {
        assert_eq!(SipralEventKind::Started as u32, 1);
        assert_eq!(SipralEventKind::RegistrationChanged as u32, 2);
        assert_eq!(SipralEventKind::IncomingCall as u32, 3);
        assert_eq!(SipralEventKind::CallProgress as u32, 4);
        assert_eq!(SipralEventKind::CallForked as u32, 5);
        assert_eq!(SipralEventKind::CallConfirmed as u32, 6);
        assert_eq!(SipralEventKind::SessionChanged as u32, 7);
        assert_eq!(SipralEventKind::SessionOffered as u32, 8);
        assert_eq!(SipralEventKind::SessionChangeFailed as u32, 9);
        assert_eq!(SipralEventKind::TransferRequested as u32, 10);
        assert_eq!(SipralEventKind::TransferProgress as u32, 11);
        assert_eq!(SipralEventKind::TransferDone as u32, 12);
        assert_eq!(SipralEventKind::CallReplaced as u32, 13);
        assert_eq!(SipralEventKind::CallEnded as u32, 14);
        assert_eq!(SipralEventKind::ALL.len(), 14, "and there are no others");
    }

    #[test]
    fn every_kind_has_a_name_of_its_own() {
        let mut seen = Vec::new();
        for kind in SipralEventKind::ALL {
            let Some(text) = name(*kind as u32) else {
                panic!("no name for {kind:?}");
            };
            assert!(!seen.contains(&text), "{text} names two kinds");
            seen.push(text);
        }
    }

    /// The reserved numbers are the mechanism, so this is the test of it: a
    /// number that is spoken for but not built answers exactly like one that
    /// was never spent, and a feature that takes it has to say so in the one
    /// declaration before this build will name it.
    #[test]
    fn a_number_held_for_a_feature_this_build_lacks_names_nothing() {
        for held in 15..=20_u32 {
            assert_eq!(name(held), None, "{held} is reserved, not live");
        }
        assert_eq!(name(21), None, "past the last reservation");
        assert_eq!(name(0), None, "no kind is zero");
        assert_eq!(name(u32::MAX), None);
    }

    #[test]
    fn a_duration_too_long_to_count_saturates_rather_than_wrapping() {
        assert_eq!(millis(Duration::from_secs(1)), 1_000);
        assert_eq!(millis(Duration::ZERO), 0);
        assert_eq!(millis(Duration::MAX), u64::MAX);
    }
}
