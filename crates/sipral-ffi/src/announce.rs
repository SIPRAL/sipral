// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call announced by a push notification, and the binding refresh that goes
//! with it (RFC 8599).
//!
//! On a phone the ringing screen exists before the call: the push arrives,
//! then a REGISTER, then maybe an INVITE. See `docs/15-mobile.md`.
//!
//! [`sipral_account_announce`] refreshes the binding (a MUST for a woken agent,
//! §4.1.3) and matches the following INVITE to the announcement. The INVITE may
//! win the race, so it writes back both values and exactly one names something.
//! [`sipral_account_refresh_binding`] is the refresh alone (§5.5);
//! [`sipral_account_push_echo`] reads the registrar's `Feature-Caps` (§8.2).
//!
//! `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` is queued right before the matching
//! `SIPRAL_EVENT_KIND_INCOMING_CALL`, so the screen is named first.
//! `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` says none arrived; not an error.

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
        /// Whether the network promised pushes of the requested type. Zero
        /// means not promised (§4.1.1): do not suspend relying on a push.
        pub accepted: u32,
        /// Whether `refresh_lead_ms` was sent at all.
        pub has_refresh_lead: u32,
        /// How long before expiry the network wants a refresh, from
        /// `sip.pnsreg` (§4.1.4), in milliseconds; zero when not sent.
        pub refresh_lead_ms: u64,
    }
}

// Safety: plain data, filled only by the library.
unsafe impl Versioned for SipralPushEcho {
    const NAME: &'static str = "sipral_push_echo";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralPushEcho, refresh_lead_ms);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

fn announcement_of(
    state: &crate::stack::StackState,
    announcement: SipralHandle,
) -> Result<AnnouncementId, Fail> {
    state.announcements.get(announcement).map_err(handle_failed)
}

entry! {
    /// A call is expected on this account, announced by a push (C2).
    ///
    /// `caller` is the SIP URI the push named. The binding is refreshed at
    /// once (§4.1.3); with no transport bound yet, the REGISTER goes when one
    /// is. Without a registrar, only the matching happens.
    ///
    /// Exactly one of the two outputs names something:
    ///
    /// - `out_announcement` when nothing arrived yet. The matching INVITE
    ///   raises `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` right before its
    ///   `SIPRAL_EVENT_KIND_INCOMING_CALL`, or
    ///   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` if none comes.
    /// - `out_call` when the INVITE beat the push. If the incoming-call event
    ///   was already delivered, this is the only report of the match.
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
    /// For a proxy's periodic wake-up (RFC 8599 §5.5). A push proves the path
    /// works, so any back-off from an earlier outage is dropped.
    ///
    /// `SIPRAL_STATUS_OK` without sending when a REGISTER is in flight or the
    /// failure is permanent (retrying a refused password locks accounts out).
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers.
    /// With no transport bound yet the failure is reported, and the refresh
    /// goes out once one is.
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
    /// Stop expecting an announced call. `SIPRAL_STATUS_WRONG_STATE` when it
    /// was already fulfilled or expired; the event and this call can cross.
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
    /// What the registrar said about push in its 2xx to REGISTER.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` when the account did not ask for push or
    /// has no standing binding.
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

    /// Registered, with the REGISTER transaction gone: a refresh is not sent
    /// while one is in flight.
    fn bound(handle: SipralHandle, account: SipralHandle) {
        let register = registered(handle, account);
        deliver(handle, &accepted_push(&register).into_bytes(), 1_100);
        poll(handle, 1_100);
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
        // §8.7: escape what the grammar refuses (`=`), but not `/`, which is
        // `param-unreserved` (RFC 3261 §25.1); the token must round-trip
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

        // past the twenty-second window
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
        // no answer yet, so no guess
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

    /// A 200 to the REGISTER that accepts push (RFC 8599 §8.2).
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
