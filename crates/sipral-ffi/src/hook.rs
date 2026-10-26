// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Seeing, changing or dropping every SIP message on its way out and in.
//!
//! The work is in `crates/sipral-core/src/endpoint/hook.rs`. This module installs a C callback
//! as the endpoint's hook (`sipral_stack_message_hook`).
//!
//! **The hook runs inside the stack's lock**, like [`crate::screening::SipralScreenCallback`]: a
//! message in is read inside `sipral_stack_receive_datagram` or `sipral_stack_receive_stream`, a
//! message out is handed over inside the entry point that drains the stack, and both hold it. A
//! hook that calls back into its own stack gets `SIPRAL_STATUS_BUSY`.

use std::ffi::{c_char, c_void};

use sipral_core::endpoint::{Direction, HookedMessage, Verdict};

use crate::abi::{Number, alias, constants, record};
use crate::error::{entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{SipralTransport, with_stack};
use crate::status::SipralStatus;

record! {
    /// One message as [`SipralMessageHookCallback`] sees it.
    ///
    /// Read `size` first, like [`crate::event::SipralEvent`]. `message` and `remote` borrow from a
    /// message still being processed: read nothing after the callback returns.
    #[derive(Clone, Copy)]
    pub struct SipralHookedMessage {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The stack the message belongs to.
        pub stack: SipralHandle,
        /// `SIPRAL_HOOK_OUTGOING` or `SIPRAL_HOOK_INCOMING`.
        pub direction: u32,
        /// What it travels over, as a `SipralTransport`; zero for one this ABI has no name for.
        pub transport: Number<SipralTransport>,
        /// The far end, as `host:port`: where it goes, or where it came from.
        pub remote: *const c_char,
        /// How many bytes of it.
        pub remote_len: usize,
        /// The message, from its start line to the end of its body; `sipral_message_header` and
        /// its companions read headers out of it.
        pub message: *const u8,
        /// How many bytes of it.
        pub message_len: usize,
    }
}

/// Where [`sipral_hooked_message_replace`] puts its bytes, one per thread.
enum Slot {
    /// No hook is running on this thread.
    Idle,
    /// A hook is running, and has handed over these bytes, or none yet.
    Running(Option<Box<[u8]>>),
}

std::thread_local! {
    /// The callback runs on the thread that asks it, so the replacement never crosses threads.
    static REPLACEMENT: std::cell::RefCell<Slot> = const { std::cell::RefCell::new(Slot::Idle) };
}

constants! {
    /// [`SipralHookedMessage::direction`]: about to be handed to the transport.
    pub const SIPRAL_HOOK_OUTGOING: u32 = 1;
    /// [`SipralHookedMessage::direction`]: just read, not yet parsed.
    pub const SIPRAL_HOOK_INCOMING: u32 = 2;

    /// The answer that lets the message on as it is. Zero, so a callback that failed before
    /// answering changes nothing.
    pub const SIPRAL_HOOK_KEEP: u32 = 0;
    /// The answer that puts the bytes given to `sipral_hooked_message_replace` in the message's
    /// place. With none given, the message goes on as it is.
    pub const SIPRAL_HOOK_REPLACE: u32 = 1;
    /// The answer that stops the message: not sent, or not read. A transaction whose message is
    /// dropped retransmits and times out as if it were lost.
    pub const SIPRAL_HOOK_DROP: u32 = 2;
}

alias! {
    /// The message hook: called once per SIP message out and once per message in. Installed
    /// with [`crate::hook::sipral_stack_message_hook`].
    ///
    /// **It runs with the stack's lock held** (see the module docs). **It must not call back into
    /// the stack it was given**, from any thread; such a call is answered `SIPRAL_STATUS_BUSY`.
    /// It must not unwind across the boundary, and should return quickly: every message waits
    /// for it.
    ///
    /// `hooked` and what it points at are valid for this call only.
    ///
    /// **The answer** is `SIPRAL_HOOK_KEEP`, `SIPRAL_HOOK_REPLACE` (after handing the new message
    /// to `sipral_hooked_message_replace`) or `SIPRAL_HOOK_DROP`; any other value keeps the
    /// message.
    pub type SipralMessageHookCallback = fn(hooked: *const SipralHookedMessage, user_data: *mut c_void) -> u32;
}

/// The C callback as the endpoint's hook. `user_data` is the caller's pointer, never read here.
struct CHook {
    stack: SipralHandle,
    callback:
        unsafe extern "C" fn(hooked: *const SipralHookedMessage, user_data: *mut c_void) -> u32,
    user_data: *mut c_void,
}

// Safety: the hook runs under the stack's lock, on the one thread inside an entry point on this
// stack; `user_data` is only handed back.
unsafe impl Send for CHook {}

impl CHook {
    fn ask(&self, hooked: &HookedMessage<'_>) -> Verdict {
        let remote = hooked.remote.to_string();
        let message = SipralHookedMessage {
            size: size_of::<SipralHookedMessage>(),
            stack: self.stack,
            direction: match hooked.direction {
                Direction::Incoming => SIPRAL_HOOK_INCOMING,
                _ => SIPRAL_HOOK_OUTGOING,
            },
            transport: SipralTransport::named(hooked.protocol),
            remote: remote.as_ptr().cast::<c_char>(),
            remote_len: remote.len(),
            message: hooked.bytes.as_ptr(),
            message_len: hooked.bytes.len(),
        };
        // a hook that, against its contract, reached another stack's hook on this thread would
        // find its own slot taken: the outer one is put back afterwards
        let outer = REPLACEMENT.with(|slot| slot.replace(Slot::Running(None)));
        // Safety: `callback` is called under the `SipralMessageHookCallback` contract (no unwind,
        // no re-entry into `self.stack`, enforced by the stack's lock). `message` borrows
        // `remote` and the message's bytes, both alive and untouched for this call.
        let answer = unsafe { (self.callback)(&raw const message, self.user_data) };
        let replacement = match REPLACEMENT.with(|slot| slot.replace(outer)) {
            Slot::Running(bytes) => bytes,
            Slot::Idle => None,
        };
        match (answer, replacement) {
            (SIPRAL_HOOK_DROP, _) => Verdict::Drop,
            (SIPRAL_HOOK_REPLACE, Some(bytes)) => Verdict::Replace(bytes),
            _ => Verdict::Keep,
        }
    }
}

entry! {
    /// Hand the message hook the bytes to use instead of the message it was called with; the
    /// callback then answers `SIPRAL_HOOK_REPLACE`. The bytes are copied, so they need to live
    /// only for this call. `Content-Length` must match the body: an outgoing message is sent as
    /// it is given, an incoming one is read as if it had arrived so. A second call replaces the
    /// first.
    ///
    /// The replacement belongs to the hook running on the calling thread, so it names no message:
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` when no hook is running on this thread, or `bytes` is null
    /// with a length.
    ///
    /// # Safety
    ///
    /// Call it only from inside a [`SipralMessageHookCallback`]. `bytes` must point at `bytes_len`
    /// readable bytes.
    fn sipral_hooked_message_replace(bytes: *const u8, bytes_len: usize) {
        if bytes.is_null() && bytes_len > 0 {
            return Err(fail(SipralStatus::InvalidArgument, "bytes are needed"));
        }
        let copied: Box<[u8]> = if bytes_len == 0 {
            Box::default()
        } else {
            // Safety: the caller promises `bytes_len` readable bytes at `bytes`, checked non-null
            // above.
            unsafe { std::slice::from_raw_parts(bytes, bytes_len) }.into()
        };
        REPLACEMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            match &mut *slot {
                Slot::Running(current) => {
                    *current = Some(copied);
                    Ok(())
                }
                Slot::Idle => Err(fail(
                    SipralStatus::InvalidArgument,
                    "no message hook is running on this thread",
                )),
            }
        })
    }
}

entry! {
    /// Install, replace, or remove the message hook for one stack.
    ///
    /// Every SIP message this stack sends passes the callback just before it is handed to the
    /// transport, retransmissions included, and every message it receives passes it just after
    /// it arrives, before it is read: a datagram whole, a byte stream one framed message at a
    /// time. Keep-alives are not messages and never reach it. `docs/03-core-signalling.md`,
    /// "A message hook".
    ///
    /// `NULL` removes the hook. A second call replaces the first, on this stack only.
    ///
    /// The no re-entry and no unwind rules are on [`SipralMessageHookCallback`].
    ///
    /// # Safety
    ///
    /// `callback`, when not null, is called on whichever thread is inside this stack, while the
    /// hook is installed. `user_data` is handed back untouched and never read here.
    ///
    /// **`user_data` must outlive the last call, which may come after `sipral_stack_destroy`
    /// returns:** an entry point already running on another thread holds its own share of the
    /// stack. Replacing or removing the hook takes the lock, so once it returns the old callback
    /// is not called again.
    fn sipral_stack_message_hook(
        stack: SipralHandle,
        callback: SipralMessageHookCallback,
        user_data: *mut c_void,
    ) {
        with_stack(stack, |state| {
            let hook = callback.map(|callback| {
                let hook = CHook {
                    stack,
                    callback,
                    user_data,
                };
                Box::new(move |hooked: &HookedMessage<'_>| hook.ask(hooked))
                    as sipral_core::endpoint::MessageHook
            });
            state.agent.endpoint().set_message_hook(hook);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SIPRAL_HOOK_DROP, SIPRAL_HOOK_INCOMING, SIPRAL_HOOK_KEEP, SIPRAL_HOOK_OUTGOING,
        SIPRAL_HOOK_REPLACE, SipralHookedMessage, sipral_hooked_message_replace,
        sipral_stack_message_hook,
    };
    use crate::call::tests::{account_on, deliver, sent};
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::SipralHandle;
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use sipral_core::endpoint::Rewrite;
    use std::ffi::c_void;
    use std::sync::Mutex;

    /// An INVITE to this end; `tag` makes `Call-ID` and branch distinct.
    fn invitation(tag: &str) -> Vec<u8> {
        format!(
            "INVITE sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-hook-{tag}\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=hook-{tag}\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: hook-{tag}@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@203.0.113.5:5060>\r\n\
Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    fn line(observed: &mut Observed) -> SipralHandle {
        let handle = stack(observed);
        let _ = account_on(handle);
        handle
    }

    fn install(
        handle: SipralHandle,
        callback: unsafe extern "C" fn(*const SipralHookedMessage, *mut c_void) -> u32,
        user_data: *mut c_void,
    ) {
        let status = unsafe { sipral_stack_message_hook(handle, Some(callback), user_data) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    }

    /// Adds `X-Tenant: blue` to every message going out; writes down each direction it saw in
    /// `user_data`, a test-owned `Mutex<Vec<u32>>`.
    unsafe extern "C" fn tag_outgoing(
        hooked: *const SipralHookedMessage,
        user_data: *mut c_void,
    ) -> u32 {
        let seen = unsafe { &*hooked };
        assert_eq!(seen.size, size_of::<SipralHookedMessage>());
        let directions = unsafe { &*user_data.cast::<Mutex<Vec<u32>>>() };
        if let Ok(mut directions) = directions.lock() {
            directions.push(seen.direction);
        }
        if seen.direction != SIPRAL_HOOK_OUTGOING {
            return SIPRAL_HOOK_KEEP;
        }
        let bytes = unsafe { std::slice::from_raw_parts(seen.message, seen.message_len) };
        let Ok(mut rewrite) = Rewrite::parse(bytes) else {
            return SIPRAL_HOOK_KEEP;
        };
        rewrite.set("X-Tenant", b"blue");
        let out = rewrite.finish();
        let status = unsafe { sipral_hooked_message_replace(out.as_ptr(), out.len()) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        SIPRAL_HOOK_REPLACE
    }

    unsafe extern "C" fn drop_incoming(
        hooked: *const SipralHookedMessage,
        _user_data: *mut c_void,
    ) -> u32 {
        if unsafe { &*hooked }.direction == SIPRAL_HOOK_INCOMING {
            SIPRAL_HOOK_DROP
        } else {
            SIPRAL_HOOK_KEEP
        }
    }

    /// Answers REPLACE without handing over any bytes: the message goes on unchanged.
    unsafe extern "C" fn replace_with_nothing(
        _hooked: *const SipralHookedMessage,
        _user_data: *mut c_void,
    ) -> u32 {
        SIPRAL_HOOK_REPLACE
    }

    #[test]
    fn an_answer_to_an_incoming_call_carries_the_field_the_hook_adds() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        let directions = Mutex::new(Vec::new());
        install(
            handle,
            tag_outgoing,
            std::ptr::from_ref(&directions).cast_mut().cast::<c_void>(),
        );
        deliver(handle, &invitation("tagged"), 1_000);
        poll(handle, 1_000);
        let out = sent(handle);
        assert!(!out.is_empty(), "the INVITE was answered");
        for message in &out {
            let read = Rewrite::parse(message).expect("a message as sent");
            assert_eq!(read.values("X-Tenant").collect::<Vec<_>>(), [b"blue"]);
        }
        let directions = directions.into_inner().unwrap_or_default();
        assert_eq!(directions.first(), Some(&SIPRAL_HOOK_INCOMING));
        assert!(directions.contains(&SIPRAL_HOOK_OUTGOING));
    }

    #[test]
    fn an_incoming_call_the_hook_drops_never_rings_and_removing_the_hook_lets_the_next_in() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        install(handle, drop_incoming, std::ptr::null_mut());
        deliver(handle, &invitation("dropped"), 1_000);
        poll(handle, 1_000);
        assert!(!observed.kinds().contains(&SipralEventKind::IncomingCall));
        assert!(
            sent(handle).is_empty(),
            "nothing answered a message never read"
        );

        let status = unsafe { sipral_stack_message_hook(handle, None, std::ptr::null_mut()) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        deliver(handle, &invitation("admitted"), 2_000);
        poll(handle, 2_000);
        assert!(observed.kinds().contains(&SipralEventKind::IncomingCall));
    }

    #[test]
    fn a_replace_with_no_bytes_given_keeps_the_message() {
        let mut observed = Observed::default();
        let handle = line(&mut observed);
        install(handle, replace_with_nothing, std::ptr::null_mut());
        deliver(handle, &invitation("unchanged"), 1_000);
        poll(handle, 1_000);
        assert!(observed.kinds().contains(&SipralEventKind::IncomingCall));
    }

    #[test]
    fn a_replacement_outside_a_hook_is_refused() {
        let status = unsafe { sipral_hooked_message_replace(b"x".as_ptr(), 1) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("no message hook"));
        let status = unsafe { sipral_hooked_message_replace(std::ptr::null(), 1) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }
}
