// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A call announced by a push notification, and the binding refresh that goes
//! with it (RFC 8599).
//!
//! On a phone the ringing screen exists before the call does. The operating
//! system delivers a notification, the process gets one run loop to raise a
//! call screen, and only then does anything SIP happen — a REGISTER to prove
//! the path is up, and an INVITE that arrives some time afterwards, or never.
//! `docs/15-mobile.md` is the whole story; this module is the doorway into it
//! from C.
//!
//! [`sipral_account_announce`] is what an application calls the moment it is
//! woken, with whoever the push said is calling. Two things happen: the
//! binding is refreshed at once, because §4.1.3 makes that a MUST for a woken
//! agent, and the INVITE that follows is matched to the announcement. Which of
//! the two comes back depends on a race the application cannot control — the
//! INVITE may already have arrived while the notification was still crossing —
//! so both are written back and exactly one of them names something.
//!
//! [`sipral_account_refresh_binding`] is the same refresh without an
//! announcement, for the periodic wake-up a proxy sends to keep a suspended
//! device reachable (§5.5).
//!
//! # What the registrar said back
//!
//! [`sipral_account_push_echo`] reads RFC 8599 §8.2's `Feature-Caps` answer:
//! whether the network said it will actually ask for notifications of the
//! type this account asked for, and how long before the binding lapses it
//! insists on seeing a refresh. It matters more than it looks: a phone that
//! lets itself be suspended because it believes the network will wake it, when
//! the network never said so, is a phone that stops ringing.
//!
//! # The two events
//!
//! `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` says the INVITE for an announcement has
//! arrived, and it is queued immediately before the
//! `SIPRAL_EVENT_KIND_INCOMING_CALL` for the same call — never without one —
//! so that an application reading its events in order is told which screen the
//! call belongs to before it is told there is a call at all.
//!
//! `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` says one never arrived. It is
//! not an error: a wake-up chain has a notification service, a proxy, a bucket
//! timer and a radio in it, and this is the only place that says which end
//! gave up. The screen the application raised can come down.

use std::ffi::c_char;

use sipral_core::msg::Uri;
use sipral_ua::{Announced, AnnouncementId};

use crate::abi::record;
use crate::call::ua_failed;
use crate::error::{Fail, entry, fail};
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::stack::{handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::required_text;
use crate::versioned::{Versioned, declared_size, write_versioned};

record! {
    /// What the registrar said about push, in the 2xx to a REGISTER that
    /// asked for it (RFC 8599 §8.2).
    #[derive(Clone, Copy)]
    pub struct SipralPushEcho {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// Whether the network said it will ask for notifications of the type
        /// this account asked for. Zero means it did not say so, which §4.1.1
        /// makes "MUST NOT assume they are coming" rather than "they are not":
        /// an application that suspends itself on the strength of a push it
        /// was never promised stops ringing.
        pub accepted: u32,
        /// Whether `refresh_lead_ms` was sent at all.
        pub has_refresh_lead: u32,
        /// How long before the binding lapses the network insists on seeing a
        /// refresh, from a `sip.pnsreg` indicator (§4.1.4), in milliseconds.
        /// Zero when the network sent none, which `has_refresh_lead` is how to
        /// tell from a lead of zero.
        pub refresh_lead_ms: u64,
    }
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and the library is the only one that fills it in.
unsafe impl Versioned for SipralPushEcho {
    const NAME: &'static str = "sipral_push_echo";
    const MIN_SIZE: usize = crate::versioned::min_size::PUSH_ECHO;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// The announcement a handle names, or why it names nothing.
fn announcement_of(
    state: &crate::stack::StackState,
    announcement: SipralHandle,
) -> Result<AnnouncementId, Fail> {
    state.announcements.get(announcement).map_err(handle_failed)
}

entry! {
    /// A call is expected on this account, announced by a push (C2).
    ///
    /// `caller` is whoever the notification said is calling, as a SIP URI.
    /// The binding is refreshed at once on whatever path exists — §4.1.3
    /// makes that a MUST for a woken agent, and a transport the application
    /// has not opened yet is the ordinary shape of a wake-up, so the REGISTER
    /// is owed and goes the moment one is bound.
    ///
    /// Exactly one of the two values written back names something, and which
    /// one is a race the caller cannot control:
    ///
    /// - `out_announcement` when nothing has arrived yet. The INVITE that
    ///   matches will be reported as `SIPRAL_EVENT_KIND_CALL_ANNOUNCED`
    ///   naming this announcement, immediately before the
    ///   `SIPRAL_EVENT_KIND_INCOMING_CALL` for the same call; and
    ///   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` when none does.
    /// - `out_call` when the INVITE beat the push. The screen just raised
    ///   belongs to that call handle, and no announcement was recorded for it
    ///   to answer. A `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` still arrives for it
    ///   when the incoming-call event has not been delivered yet, because the
    ///   two are queued together and in that order; once it has, this return
    ///   value is the only word about the match there will be.
    ///
    /// An account with no registrar has no binding to refresh, and for one of
    /// those only the matching happens.
    ///
    /// # Safety
    ///
    /// `caller` must be readable for `caller_len` bytes, and each of
    /// `out_announcement` and `out_call` must point at one `sipral_handle_t`.
    fn sipral_account_announce(
        stack: SipralHandle,
        account: SipralHandle,
        caller: *const c_char,
        caller_len: usize,
        out_announcement: *mut SipralHandle,
        out_call: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_announcement.is_null() || out_call.is_null() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "out_announcement and out_call are both written and neither may be null",
            ));
        }
        let text = unsafe { required_text(caller, caller_len, "caller") }?;
        let Ok(uri) = Uri::parse(text.as_bytes()) else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("caller is {text:?}, which is not a URI"),
            ));
        };
        with_stack_at(stack, now_ms, |state, now| {
            let named = state.accounts.get(account).map_err(handle_failed)?;
            let found = state
                .agent
                .announce(named, uri, now)
                .map_err(|error| ua_failed(&error))?;
            let (announcement, call) = match found {
                Announced::Waiting(id) => {
                    let handle = state.announcements.insert(id).map_err(|status| {
                        fail(
                            status,
                            "this stack has handed out every announcement handle it has room for",
                        )
                    })?;
                    (handle, SIPRAL_HANDLE_NONE)
                }
                Announced::Arrived(call) => {
                    let handle = state.calls.name_of(call).map_err(|status| {
                        fail(status, "this stack has no room left to name the call")
                    })?;
                    (SIPRAL_HANDLE_NONE, handle)
                }
            };
            unsafe { out_announcement.write(announcement) };
            unsafe { out_call.write(call) };
            Ok(())
        })
    }
}

entry! {
    /// Refresh the binding now, without announcing anything (C3).
    ///
    /// For the periodic wake-up a proxy sends to keep a suspended device's
    /// binding alive (RFC 8599 §5.5). A push is evidence that the path to the
    /// proxy is working, so a back-off earned by an earlier outage is not
    /// what to wait for now and is dropped.
    ///
    /// Nothing is sent when a REGISTER is already in flight, which is already
    /// the fastest path, or when the registration has failed in a way trying
    /// again cannot fix — repeating a password that was refused is how an
    /// account gets locked out, and a push does not change that. Both of those
    /// are `SIPRAL_STATUS_OK`: the refresh was asked for and the answer is
    /// that nothing needed sending.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers,
    /// which has no binding to refresh: it is the account that is wrong for
    /// this call, not the build that is missing the feature. A send that could
    /// not happen because no transport is bound yet is reported too, and is
    /// not fatal: the refresh is remembered and goes out the moment one is.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_account_refresh_binding(stack: SipralHandle, account: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let named = state.accounts.get(account).map_err(handle_failed)?;
            state
                .agent
                .refresh_binding(named, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Stop expecting an announced call.
    ///
    /// The user dismissed the screen, or the application decided the wake-up
    /// was stale. `SIPRAL_STATUS_WRONG_STATE` when it had already been
    /// fulfilled or had already expired, which is not a mistake: the event
    /// that said so and this call can cross.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_announcement_forget(stack: SipralHandle, announcement: SipralHandle) {
        with_stack(stack, |state| {
            let named = announcement_of(state, announcement)?;
            if state.agent.forget_announcement(named) {
                Ok(())
            } else {
                Err(fail(
                    SipralStatus::WrongState,
                    "this announcement had already been answered by a call or had already run \
                     out of time",
                ))
            }
        })
    }
}

entry! {
    /// What the registrar said about push, in the 2xx to the REGISTER that
    /// asked for it.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` when this account did not ask for push,
    /// or when no binding it could have been said about is standing — none
    /// granted yet, one given up, or one that has lapsed.
    ///
    /// # Safety
    ///
    /// `out_echo` must point at a `sipral_push_echo_t` whose `size` member
    /// says how long it is.
    fn sipral_account_push_echo(
        stack: SipralHandle,
        account: SipralHandle,
        out_echo: *mut SipralPushEcho,
    ) {
        unsafe { declared_size(out_echo.cast_const()) }?;
        with_stack(stack, |state| {
            let named = state.accounts.get(account).map_err(handle_failed)?;
            let Some(echo) = state.agent.push_echo(named) else {
                return Err(fail(
                    SipralStatus::NotSupported,
                    "this account has no answer about push: either it never asked for any, or no \
                     binding it could have been said about is standing",
                ));
            };
            let lead = echo.refresh_lead();
            let out = SipralPushEcho {
                size: size_of::<SipralPushEcho>(),
                accepted: u32::from(echo.accepted()),
                has_refresh_lead: u32::from(lead.is_some()),
                refresh_lead_ms: lead
                    .map_or(0, |held| u64::try_from(held.as_millis()).unwrap_or(u64::MAX)),
            };
            unsafe { write_versioned(out_echo, out) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralPushEcho, sipral_account_announce, sipral_account_push_echo,
        sipral_account_refresh_binding, sipral_announcement_forget,
    };
    use crate::account::{SipralAccountConfig, sipral_account_add, sipral_account_register};
    use crate::call::tests::{deliver, sent};
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::ptr;

    fn as_text(text: &str) -> (*const c_char, usize) {
        (text.as_ptr().cast::<c_char>(), text.len())
    }

    /// An account woken through Apple's service, which is what a phone is.
    fn woken(handle: SipralHandle, wakes_itself: bool) -> SipralHandle {
        let mut config = crate::account::tests::account_config();
        (config.push_provider, config.push_provider_len) = as_text("apns");
        (config.push_prid, config.push_prid_len) = as_text("device=token+with/reserved");
        (config.push_param, config.push_param_len) = as_text("org.example.phone");
        config.push_wakes_itself = u32::from(wakes_itself);
        let mut account = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_account_add(handle, ptr::from_ref(&config), &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    /// The REGISTER an account sends, as text.
    fn registered(handle: SipralHandle, account: SipralHandle) -> String {
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let all = sent(handle);
        let register = all
            .iter()
            .find(|message| message.starts_with(b"REGISTER "))
            .unwrap_or_else(|| panic!("no REGISTER went out, in {} messages", all.len()));
        String::from_utf8_lossy(register).into_owned()
    }

    /// A phone that is actually registered, which is what a woken one is: a
    /// binding refresh is not sent while a REGISTER is still in flight,
    /// because that is already the fastest path there is.
    fn bound(handle: SipralHandle, account: SipralHandle) {
        let register = registered(handle, account);
        deliver(handle, &accepted_push(&register).into_bytes(), 1_100);
        poll(handle, 1_100);
        // and far enough past it that the REGISTER's own transaction has been
        // let go of: a refresh asked for while one is still in flight is not
        // sent, because that is already the fastest path there is
        poll(handle, 30_000);
        let _ = sent(handle);
    }

    #[test]
    fn the_push_parameters_go_on_the_register_contact_and_nowhere_else() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = woken(handle, true);

        let register = registered(handle, account);
        let contact = register
            .lines()
            .find(|line| line.starts_with("Contact: "))
            .unwrap_or_else(|| panic!("no Contact in:\n{register}"));
        assert!(contact.contains(";pn-provider=apns"), "{contact}");
        assert!(contact.contains(";pn-param=org.example.phone"), "{contact}");
        // §8.7: a token carrying characters the SIP grammar does not take is
        // escaped rather than sent raw or refused. `=` is one of those and
        // `/` is not -- RFC 3261 §25.1 puts `/` in `param-unreserved` -- so
        // escaping it as well would be a second spelling of the same token,
        // and a device token that does not round-trip is a phone that never
        // rings
        assert!(
            contact.contains(";pn-prid=device%3Dtoken+with/reserved"),
            "the identifier did not survive the wire: {contact}"
        );
        assert!(
            contact.contains(";+sip.pnsreg"),
            "the account said it wakes itself and the Contact does not: {contact}"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn an_account_that_does_not_wake_itself_says_nothing_about_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = woken(handle, false);
        let register = registered(handle, account);
        assert!(
            !register.contains("+sip.pnsreg"),
            "a phone that cannot wake itself claimed it can:\n{register}"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_service_with_no_device_or_a_device_with_no_service_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        for (provider, prid, wakes, why) in [
            (Some("apns"), None, 0, "a service with nothing to wake"),
            (None, Some("token"), 0, "a device with no service"),
            (None, None, 1, "a refresh rule for push nobody asked for"),
        ] {
            let mut config: SipralAccountConfig = crate::account::tests::account_config();
            if let Some(provider) = provider {
                (config.push_provider, config.push_provider_len) = as_text(provider);
            }
            if let Some(prid) = prid {
                (config.push_prid, config.push_prid_len) = as_text(prid);
            }
            config.push_wakes_itself = wakes;
            let mut account = SIPRAL_HANDLE_NONE;
            assert_eq!(
                unsafe { sipral_account_add(handle, ptr::from_ref(&config), &raw mut account) },
                SipralStatus::InvalidArgument,
                "{why} was accepted"
            );
            assert_eq!(account, SIPRAL_HANDLE_NONE, "{why}");
        }
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// The whole of C2: woken, a screen raised, the binding refreshed, and the
    /// INVITE that follows named as the one the screen belongs to.
    #[test]
    fn an_announced_call_is_matched_to_the_invite_that_answers_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = woken(handle, true);
        bound(handle, account);

        let caller = "sip:bob@example.com";
        let mut announcement = SIPRAL_HANDLE_NONE;
        let mut call = SIPRAL_HANDLE_NONE;
        let (text, len) = as_text(caller);
        assert_eq!(
            unsafe {
                sipral_account_announce(
                    handle,
                    account,
                    text,
                    len,
                    &raw mut announcement,
                    &raw mut call,
                    31_000,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_ne!(announcement, SIPRAL_HANDLE_NONE, "nothing was announced");
        assert_eq!(call, SIPRAL_HANDLE_NONE, "a call arrived before the push");
        // §4.1.3: a woken agent refreshes its binding, whatever else it does
        let after = sent(handle);
        assert!(
            after
                .iter()
                .any(|message| message.starts_with(b"REGISTER ")),
            "the wake-up did not refresh the binding"
        );

        deliver(handle, &invitation(caller), 31_100);
        poll(handle, 31_100);

        let kinds = observed.kinds();
        let announced = kinds
            .iter()
            .position(|kind| *kind == SipralEventKind::CallAnnounced)
            .unwrap_or_else(|| panic!("no announcement was answered, in {kinds:?}"));
        let incoming = kinds
            .iter()
            .position(|kind| *kind == SipralEventKind::IncomingCall)
            .unwrap_or_else(|| panic!("no call came in, in {kinds:?}"));
        assert!(
            announced < incoming,
            "the call was reported before the screen it belongs to was named: {kinds:?}"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// The other half: nothing arrives, and the screen comes down on an event
    /// rather than on a timer of the application's own.
    #[test]
    fn an_announced_call_that_never_arrives_is_reported_as_missing() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = woken(handle, true);
        bound(handle, account);

        let mut announcement = SIPRAL_HANDLE_NONE;
        let mut call = SIPRAL_HANDLE_NONE;
        let (text, len) = as_text("sip:bob@example.com");
        assert_eq!(
            unsafe {
                sipral_account_announce(
                    handle,
                    account,
                    text,
                    len,
                    &raw mut announcement,
                    &raw mut call,
                    31_000,
                )
            },
            SipralStatus::Ok
        );

        // twenty seconds is the window, and nothing came through it
        poll(handle, 31_000 + 21_000);

        assert!(
            observed
                .kinds()
                .contains(&SipralEventKind::AnnouncedCallMissing),
            "the screen was left up: {:?}",
            observed.kinds()
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn an_announcement_can_be_forgotten_once_and_not_twice() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = woken(handle, true);
        bound(handle, account);

        let mut announcement = SIPRAL_HANDLE_NONE;
        let mut call = SIPRAL_HANDLE_NONE;
        let (text, len) = as_text("sip:bob@example.com");
        assert_eq!(
            unsafe {
                sipral_account_announce(
                    handle,
                    account,
                    text,
                    len,
                    &raw mut announcement,
                    &raw mut call,
                    31_000,
                )
            },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_announcement_forget(handle, announcement) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { sipral_announcement_forget(handle, announcement) },
            SipralStatus::WrongState,
            "forgetting it twice was taken as a second announcement"
        );
        // and nothing is waited for any more
        poll(handle, 31_000 + 21_000);
        assert!(
            !observed
                .kinds()
                .contains(&SipralEventKind::AnnouncedCallMissing),
            "an announcement that was forgotten was still waited for"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn what_the_registrar_said_about_push_is_readable() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = woken(handle, true);
        let mut echo = SipralPushEcho {
            size: size_of::<SipralPushEcho>(),
            accepted: 0,
            has_refresh_lead: 0,
            refresh_lead_ms: 0,
        };
        // nothing has answered yet, and a guess would be the one thing that
        // must not be made here
        assert_eq!(
            unsafe { sipral_account_push_echo(handle, account, &raw mut echo) },
            SipralStatus::NotSupported
        );

        let register = registered(handle, account);
        deliver(handle, &accepted_push(&register).into_bytes(), 1_100);
        poll(handle, 1_100);

        assert_eq!(
            unsafe { sipral_account_push_echo(handle, account, &raw mut echo) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(echo.accepted, 1, "the registrar said yes and this says no");
        assert_eq!(echo.has_refresh_lead, 1);
        assert_eq!(echo.refresh_lead_ms, 121_000);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn refreshing_the_binding_of_an_account_that_never_registers_says_so() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = crate::account::tests::account_config();
        config.registrar = ptr::null();
        config.registrar_len = 0;
        let mut account = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_account_add(handle, ptr::from_ref(&config), &raw mut account) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { sipral_account_refresh_binding(handle, account, 2_000) },
            SipralStatus::InvalidArgument,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// An INVITE from the caller a push announced.
    fn invitation(caller: &str) -> Vec<u8> {
        format!(
            "INVITE sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-announced\r\n\
Max-Forwards: 70\r\n\
From: <{caller}>;tag=announced\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: announced@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@203.0.113.5:5060>\r\n\
Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    /// A 200 to the REGISTER that says the network will ask for notifications
    /// of the type this account asked for (RFC 8599 §8.2).
    fn accepted_push(register: &str) -> String {
        let field = |name: &str| {
            register
                .lines()
                .find(|line| line.starts_with(&format!("{name}: ")))
                .map_or_else(
                    || panic!("no {name} in:\n{register}"),
                    |line| line[name.len() + 2..].to_owned(),
                )
        };
        format!(
            "SIP/2.0 200 OK\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {};tag=registrar\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
Contact: {}\r\n\
Feature-Caps: *;+sip.pns=\"apns\";+sip.pnsreg=\"121\"\r\n\
Expires: 3600\r\n\
Content-Length: 0\r\n\r\n",
            field("Via"),
            field("From"),
            field("To"),
            field("Call-ID"),
            field("CSeq"),
            field("Contact"),
        )
    }
}
