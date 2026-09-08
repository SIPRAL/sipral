// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Accounts: configured, registered, given up.
//!
//! An account is one relationship with one registrar, and several of them live
//! in one stack without sharing anything. Adding one sends nothing;
//! [`sipral_account_register`] is what puts a REGISTER on the wire, and from
//! then on the binding is refreshed, retried and backed off without another
//! call. What the application hears about is the state, not the transactions.
//!
//! Three things here are the caller's and cannot be defaulted. The address the
//! REGISTER is sent to, because resolving a registrar's name is I/O; the
//! `Contact` this end is reachable at, because a library that never opened a
//! socket does not know what the world sees; and the instance identifier,
//! because RFC 5626 §4.1 wants one that survives a power cycle and nothing
//! here has storage.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::time::Duration;

use sipral_core::auth::Credentials;
use sipral_core::msg::{HeaderName, Uri};
use sipral_ua::Account;

use crate::call::ua_failed;
use crate::error::{Fail, entry, fail};
use crate::event::registration_state;
use crate::handle::SipralHandle;
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{required_text, text};
use crate::versioned::{Versioned, read_versioned};

/// What an account is configured with.
///
/// Set `size` to `sizeof(sipral_account_config_t)` and zero the rest before
/// filling anything in.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralAccountConfig {
    /// `sizeof` this struct, as the caller's header declares it.
    pub size: usize,
    /// The address of record, `sip:alice@example.com`. UTF-8, not
    /// NUL-terminated.
    pub aor: *const c_char,
    /// How many bytes of it.
    pub aor_len: usize,
    /// Where the REGISTER is addressed, `sip:example.com`, no user part.
    pub registrar: *const c_char,
    /// How many bytes of it.
    pub registrar_len: usize,
    /// Where this endpoint can be reached, as it goes in `Contact`.
    pub contact: *const c_char,
    /// How many bytes of it.
    pub contact_len: usize,
    /// Where the REGISTER actually goes, as `host:port`. An address, not a
    /// name: RFC 3263 resolution is the caller's.
    pub registrar_address: *const c_char,
    /// How many bytes of it.
    pub registrar_address_len: usize,
    /// The display name that goes in `From`, or null for none.
    pub display_name: *const c_char,
    /// How many bytes of it.
    pub display_name_len: usize,
    /// The user name to answer a challenge with, or null for an account that
    /// answers none.
    pub auth_user: *const c_char,
    /// How many bytes of it.
    pub auth_user_len: usize,
    /// The password that goes with it. Copied out of the caller's memory; what
    /// happens to the caller's copy is the caller's.
    pub auth_password: *const c_char,
    /// How many bytes of it.
    pub auth_password_len: usize,
    /// The `+sip.instance` URN of RFC 5626 §4.1, or null for none.
    pub instance_id: *const c_char,
    /// How many bytes of it.
    pub instance_id_len: usize,
    /// How long a binding to ask for, or zero for an hour. What the registrar
    /// grants wins over it either way.
    pub expires_seconds: u64,
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and all-zero is valid: every pointer is null beside a length of
// zero, which is how a caller says it has nothing to give.
unsafe impl Versioned for SipralAccountConfig {
    const NAME: &'static str = "sipral_account_config";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// Read a URI a caller supplied, and say which field it was when it will not
/// parse.
fn uri(supplied: &str, name: &'static str) -> Result<Uri, Fail> {
    Uri::parse_str(supplied).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {supplied:?}, which is not a URI: {error}"),
        )
    })
}

fn address(supplied: &str, name: &'static str) -> Result<SocketAddr, Fail> {
    supplied.parse::<SocketAddr>().map_err(|_| {
        fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {supplied:?}, which is not an address and a port"),
        )
    })
}

/// Turn what crossed the boundary into an account, or say what was wrong.
///
/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn account_from(state: &StackState, config: &SipralAccountConfig) -> Result<Account, Fail> {
    let aor = unsafe { required_text(config.aor, config.aor_len, "aor") }?;
    let registrar = unsafe { required_text(config.registrar, config.registrar_len, "registrar") }?;
    let contact = unsafe { required_text(config.contact, config.contact_len, "contact") }?;
    let remote = unsafe {
        required_text(
            config.registrar_address,
            config.registrar_address_len,
            "registrar_address",
        )
    }?;
    let display = unsafe { text(config.display_name, config.display_name_len, "display_name") }?;
    let user = unsafe { text(config.auth_user, config.auth_user_len, "auth_user") }?;
    let password = unsafe {
        text(
            config.auth_password,
            config.auth_password_len,
            "auth_password",
        )
    }?;
    let instance = unsafe { text(config.instance_id, config.instance_id_len, "instance_id") }?;

    let mut account = Account::new(
        uri(aor, "aor")?,
        uri(registrar, "registrar")?,
        uri(contact, "contact")?,
        state.transport,
        address(remote, "registrar_address")?,
    );
    if let Some(display) = display {
        account = account.display_name(display);
    }
    match (user, password) {
        (Some(user), Some(password)) => {
            account = account.credentials(Credentials::new(user, password));
        }
        (None, None) => {}
        // half a credential answers nothing, and an account that silently
        // stopped answering challenges looks like a wrong password
        _ => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "auth_user and auth_password go together, and only one was given",
            ));
        }
    }
    if let Some(instance) = instance {
        account = account.instance_id(instance);
    }
    if config.expires_seconds != 0 {
        account = account.expires(Duration::from_secs(config.expires_seconds));
    }
    if let Some(ref named) = state.user_agent {
        account = account.header(HeaderName::UserAgent, named);
    }
    Ok(account)
}

entry! {
    /// Configure an account, and write its handle to `out_account`.
    ///
    /// Nothing is sent. The account exists until [`sipral_account_remove`] or
    /// until the stack is destroyed.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_account_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_account` at one `sipral_handle_t`.
    fn sipral_account_add(
        stack: SipralHandle,
        config: *const SipralAccountConfig,
        out_account: *mut SipralHandle,
    ) {
        if out_account.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_account is null"));
        }
        let config = unsafe { read_versioned(config) }?;
        let handle = with_stack(stack, |state| {
            let account = unsafe { account_from(state, &config) }?;
            let id = state.agent.add_account(account);
            state.accounts.insert(id).map_err(|status| {
                state.agent.remove_account(id);
                fail(status, "no room for another account on this stack")
            })
        })?;
        unsafe { out_account.write(handle) };
        Ok(())
    }
}

entry! {
    /// Forget an account, and everything scheduled for it.
    ///
    /// Nothing is sent: an account being removed may be one whose registrar is
    /// unreachable, and waiting on that is not this call's job. Give the
    /// binding up politely with [`sipral_account_unregister`] first when it
    /// matters.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_account_remove(stack: SipralHandle, account: SipralHandle) {
        with_stack(stack, |state| {
            let id = state.accounts.remove(account).map_err(handle_failed)?;
            state.agent.remove_account(id);
            Ok(())
        })
    }
}

entry! {
    /// Register, and keep the binding alive until told otherwise.
    ///
    /// Refreshes, credential retries and the back-off after an outage all
    /// happen without another call. What stops them is
    /// [`sipral_account_unregister`], or a refusal that trying again cannot
    /// fix. Every step of it arrives as a `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_account_register(stack: SipralHandle, account: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            state
                .agent
                .register(id, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
    ///
    /// Only this device's binding. A `Contact: *` would remove every binding
    /// the address of record has, including the one belonging to the desk
    /// phone somebody else is holding.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_account_unregister(stack: SipralHandle, account: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            state
                .agent
                .unregister(id, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Where an account's registration is, as a `SipralRegistrationState`.
    ///
    /// # Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    fn sipral_account_registration_state(
        stack: SipralHandle,
        account: SipralHandle,
        out_state: *mut u32,
    ) {
        if out_state.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_state is null"));
        }
        let state = with_stack(stack, |state| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            Ok(registration_state(state.agent.registration_state(id)) as u32)
        })?;
        unsafe { out_state.write(state) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralAccountConfig, sipral_account_add, sipral_account_register,
        sipral_account_registration_state, sipral_account_remove, sipral_account_unregister,
    };
    use crate::error::last_error_text;
    use crate::event::{SipralEventKind, SipralRegistrationState};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::ptr;

    const AOR: &str = "sip:alice@example.com";
    const REGISTRAR: &str = "sip:example.com";
    const CONTACT: &str = "sip:alice@192.0.2.10:5060";
    const ADDRESS: &str = "203.0.113.5:5060";

    fn text(value: &str) -> (*const c_char, usize) {
        (value.as_ptr().cast::<c_char>(), value.len())
    }

    fn account_config() -> SipralAccountConfig {
        let (aor, aor_len) = text(AOR);
        let (registrar, registrar_len) = text(REGISTRAR);
        let (contact, contact_len) = text(CONTACT);
        let (registrar_address, registrar_address_len) = text(ADDRESS);
        SipralAccountConfig {
            size: size_of::<SipralAccountConfig>(),
            aor,
            aor_len,
            registrar,
            registrar_len,
            contact,
            contact_len,
            registrar_address,
            registrar_address_len,
            display_name: ptr::null(),
            display_name_len: 0,
            auth_user: ptr::null(),
            auth_user_len: 0,
            auth_password: ptr::null(),
            auth_password_len: 0,
            instance_id: ptr::null(),
            instance_id_len: 0,
            expires_seconds: 0,
        }
    }

    fn add(stack: SipralHandle, config: &SipralAccountConfig) -> (SipralStatus, SipralHandle) {
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(stack, ptr::from_ref(config), &raw mut account) };
        (status, account)
    }

    fn state_of(stack: SipralHandle, account: SipralHandle) -> u32 {
        let mut state = u32::MAX;
        let status = unsafe { sipral_account_registration_state(stack, account, &raw mut state) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        state
    }

    #[test]
    fn an_account_is_added_and_starts_idle() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (status, account) = add(handle, &account_config());
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(account, SIPRAL_HANDLE_NONE);
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Idle as u32
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn two_accounts_on_one_stack_are_two_handles() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (_, first) = add(handle, &account_config());
        let (_, second) = add(handle, &account_config());
        assert_ne!(first, second);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_removed_account_is_stale_and_stays_stale() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (_, account) = add(handle, &account_config());
        assert_eq!(
            unsafe { sipral_account_remove(handle, account) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_account_remove(handle, account) },
            SipralStatus::StaleHandle
        );
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 0) },
            SipralStatus::StaleHandle
        );
        let mut state = u32::MAX;
        assert_eq!(
            unsafe { sipral_account_registration_state(handle, account, &raw mut state) },
            SipralStatus::StaleHandle
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_account_handle_from_one_stack_does_not_open_another() {
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack(&mut first_observed);
        let second = stack(&mut second_observed);
        let (_, account) = add(first, &account_config());
        assert_eq!(
            unsafe { sipral_account_register(second, account, 0) },
            SipralStatus::InvalidHandle,
            "the second stack has never handed out that handle"
        );
        assert_eq!(unsafe { sipral_stack_destroy(first) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(second) }, SipralStatus::Ok);
    }

    #[test]
    fn an_address_of_record_that_is_not_a_uri_is_refused_and_says_which_field() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        let nonsense = "alice";
        (config.aor, config.aor_len) = text(nonsense);
        let (status, account) = add(handle, &config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(account, SIPRAL_HANDLE_NONE);
        let message = last_error_text();
        assert!(message.contains("aor"), "{message}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn every_field_an_account_cannot_do_without_is_asked_for() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let missing: [fn(&mut SipralAccountConfig); 4] = [
            |config| (config.aor, config.aor_len) = (ptr::null(), 0),
            |config| (config.registrar, config.registrar_len) = (ptr::null(), 0),
            |config| (config.contact, config.contact_len) = (ptr::null(), 0),
            |config| {
                (config.registrar_address, config.registrar_address_len) = (ptr::null(), 0);
            },
        ];
        for leave_out in missing {
            let mut config = account_config();
            leave_out(&mut config);
            assert_eq!(add(handle, &config).0, SipralStatus::InvalidArgument);
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_registrar_address_that_is_a_name_is_refused_because_nothing_here_resolves_one() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        let name = "example.com:5060";
        (config.registrar_address, config.registrar_address_len) = text(name);
        assert_eq!(add(handle, &config).0, SipralStatus::InvalidArgument);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn half_a_credential_is_refused_rather_than_quietly_ignored() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        (config.auth_user, config.auth_user_len) = text("alice");
        assert_eq!(add(handle, &config).0, SipralStatus::InvalidArgument);

        let mut config = account_config();
        (config.auth_password, config.auth_password_len) = text("hunter2");
        assert_eq!(add(handle, &config).0, SipralStatus::InvalidArgument);

        let mut config = account_config();
        (config.auth_user, config.auth_user_len) = text("alice");
        (config.auth_password, config.auth_password_len) = text("hunter2");
        assert_eq!(add(handle, &config).0, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_display_name_that_would_smuggle_a_header_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        (config.display_name, config.display_name_len) =
            text("Alice\r\nRoute: <sip:elsewhere@example.net;lr>");
        assert_eq!(add(handle, &config).0, SipralStatus::InvalidArgument);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn registering_puts_a_register_on_the_wire_and_says_so() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (_, account) = add(handle, &account_config());
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Registering as u32
        );

        let result = poll(handle, 1_000);
        assert_eq!(result.events_delivered, 2, "started, then the registration");
        assert_eq!(
            result.transmits_discarded, 1,
            "the REGISTER this build has nowhere to send"
        );
        assert_eq!(result.has_deadline, 1, "a retransmission is scheduled");
        assert_eq!(
            observed.kinds(),
            vec![
                SipralEventKind::Started,
                SipralEventKind::RegistrationChanged
            ]
        );
        assert_eq!(
            observed.named.get(1).map(|named| named.0),
            Some(account),
            "the event names the account it is about"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn unregistering_a_binding_that_was_never_made_still_asks_politely() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (_, account) = add(handle, &account_config());
        assert_eq!(
            unsafe { sipral_account_unregister(handle, account, 0) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Unregistered as u32
        );
        assert_eq!(poll(handle, 0).transmits_discarded, 1);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// RFC 3261 §10.2.5 is Setting the Internal Clock; the rule that a UA
    /// removes a binding by sending `Expires: 0` is §10.2.2, Removing
    /// Bindings. The needle is assembled at runtime so this test does not
    /// just match its own assertion.
    #[test]
    fn the_unregister_doc_cites_removing_bindings_not_the_clock() {
        let source = include_str!("account.rs");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("`Expires: 0` ({section}10.2.2)")),
            "removing a binding with Expires: 0 is §10.2.2, not §10.2.5"
        );
    }

    #[test]
    fn an_account_call_on_a_stack_that_is_gone_is_stale() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (_, account) = add(handle, &account_config());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 0) },
            SipralStatus::StaleHandle
        );
    }

    #[test]
    fn a_null_out_parameter_is_a_bad_argument() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let config = account_config();
        assert_eq!(
            unsafe { sipral_account_add(handle, ptr::from_ref(&config), ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        let (_, account) = add(handle, &config);
        assert_eq!(
            unsafe { sipral_account_registration_state(handle, account, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_config_that_declares_the_wrong_size_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        config.size = size_of::<SipralAccountConfig>() - 1;
        assert_eq!(add(handle, &config).0, SipralStatus::UnsupportedVersion);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
