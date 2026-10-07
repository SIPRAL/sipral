// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Where requests actually go: name resolution answered by the application.
//!
//! Nothing below owns a resolver, as nothing owns a socket: a lookup would
//! block, impose a DNS client and break replay.
//!
//! [`sipral_stack_resolved`] answers a
//! [`SIPRAL_EVENT_KIND_RESOLVE_NEEDED`](crate::event::SipralEventKind::ResolveNeeded)
//! (RFC 3261 §12.2.1.1, RFC 3263 §4) with a priority list; RFC 3263 §4.3 takes
//! the first usable one and keeps the rest for failover.
//! [`sipral_account_retarget`] moves an account's next REGISTER while keeping
//! its `Call-ID`, sequence and credentials.
//!
//! Neither opens a transport, and nothing times out: an unanswered request
//! leaves the dialog on its first flow, which RFC 3261 §8.1.2 allows.

use std::ffi::c_char;
use std::net::SocketAddr;

use crate::abi::Number;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::address;
use crate::stack::{SipralTransport, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::required_text;

/// The addresses a caller wrote, in order: comma-separated `host:port`. An
/// IPv6 literal is bracketed (RFC 3261 §19.1.1), so it holds no comma.
fn addresses_in(list: &str) -> Result<Vec<SocketAddr>, Fail> {
    let mut out = Vec::new();
    for (index, written) in list.split(',').map(str::trim).enumerate() {
        if written.is_empty() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "addresses names nothing at position {index}, so the list has a stray comma"
                ),
            ));
        }
        let Ok(parsed) = written.parse::<SocketAddr>() else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "addresses names {written} at position {index}, which is not a host:port \
                     this library can read; a name is what this call answers, not what it takes"
                ),
            ));
        };
        out.push(parsed);
    }
    Ok(out)
}

entry! {
    /// Say where a dialog's next hop actually is.
    ///
    /// The answer to
    /// [`SIPRAL_EVENT_KIND_RESOLVE_NEEDED`](crate::event::SipralEventKind::ResolveNeeded),
    /// with `dialog` the handle that event carried. `addresses` is
    /// comma-separated `host:port` in RFC 3263 §4.3 priority order: the first
    /// one with an open transport of the wanted protocol is taken, the rest
    /// are kept for failover.
    ///
    /// `protocol` is a [`SipralTransport`] when the lookup named one (NAPTR,
    /// SRV), or zero to keep the flow's protocol. It is never opened: an
    /// address on an unbound protocol is passed over; answer again after
    /// [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind).
    ///
    /// `SIPRAL_STATUS_OK` with nothing changed when no address is reachable.
    /// `SIPRAL_STATUS_STALE_HANDLE` for a dialog that has ended. No `now_ms`:
    /// nothing here is timed.
    ///
    /// # Safety
    ///
    /// `addresses` must be readable for `addresses_len` bytes.
    fn sipral_stack_resolved(
        stack: SipralHandle,
        dialog: SipralHandle,
        addresses: *const c_char,
        addresses_len: usize,
        protocol: Number<SipralTransport>,
    ) {
        let list = unsafe { required_text(addresses, addresses_len, "addresses") }?;
        let addresses = addresses_in(list)?;
        let wanted = match protocol {
            0 => None,
            named => Some(crate::stack::transport_of(named)?.protocol()),
        };
        with_stack(stack, |state| {
            let named = state.dialogs.get(dialog).map_err(handle_failed)?;
            state.agent.endpoint().resolved(named, &addresses, wanted);
            Ok(())
        })
    }
}

entry! {
    /// Point an account's registration at another address.
    ///
    /// For a registrar with several targets. The binding's `Call-ID`,
    /// sequence and credentials are kept, so the registrar sees the same
    /// device continuing. A REGISTER in flight or booked is superseded at
    /// once; retargeting to the current address is `SIPRAL_STATUS_OK` and
    /// sends nothing.
    ///
    /// `registrar_address` is `host:port`, not a name.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for an account with no registrar.
    ///
    /// # Safety
    ///
    /// `registrar_address` must be readable for `registrar_address_len`
    /// bytes.
    fn sipral_account_retarget(
        stack: SipralHandle,
        account: SipralHandle,
        registrar_address: *const c_char,
        registrar_address_len: usize,
        now_ms: u64,
    ) {
        let remote = unsafe {
            address(
                registrar_address,
                registrar_address_len,
                "registrar_address",
            )
        }?;
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            state
                .agent
                .retarget(id, remote, now)
                .map_err(|error| crate::call::ua_failed(&error))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{sipral_account_retarget, sipral_stack_resolved};
    use crate::call::tests::{
        accepted, account_on, as_text, call_config, deliver, one, place, sent, start_line,
    };
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::SipralTransport;
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use crate::transport::tests::drain_addressed;
    use std::ptr;

    /// Not the old flow's address.
    const ELSEWHERE: &str = "198.51.100.7:5080";

    /// A call answered with a `Contact` that names a host, so the next hop
    /// needs a resolver.
    fn called_a_name(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        let account = account_on(handle);
        let (status, call) = place(handle, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        assert!(start_line(&invite).starts_with("INVITE"));
        let named = String::from_utf8_lossy(&accepted(&invite, b"", true))
            .replace("<sip:bob@203.0.113.5:5060>", "<sip:bob@bob.example.com>")
            .into_bytes();
        deliver(handle, &named, 1_100);
        poll(handle, 1_100);
        let _ = sent(handle);
        (handle, call)
    }

    #[test]
    fn a_dialog_whose_next_hop_is_a_name_reaches_c() {
        let mut observed = Observed::default();
        let (handle, _) = called_a_name(&mut observed);
        assert!(
            observed.kinds().contains(&SipralEventKind::ResolveNeeded),
            "the request died between the core and the callback: {:?}",
            observed.kinds()
        );
        let asked = observed.resolves.first().expect("one request");
        assert_eq!(asked.host, "bob.example.com");
        assert_eq!(asked.port, 0, "no port, so RFC 3263 4.2 is the caller's");
        assert_eq!(asked.protocol, 0, "no transport named either");
        assert_ne!(asked.dialog, SIPRAL_HANDLE_NONE, "nothing to answer with");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn answering_moves_where_the_dialogs_requests_go() {
        let mut observed = Observed::default();
        let (handle, call) = called_a_name(&mut observed);
        let dialog = observed.resolves.first().expect("one request").dialog;
        let (addresses, addresses_len) = as_text(ELSEWHERE);
        assert_eq!(
            unsafe { sipral_stack_resolved(handle, dialog, addresses, addresses_len, 0) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { crate::call::sipral_call_hangup(handle, call, 1_200) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = drain_addressed(handle);
        let bye = out
            .iter()
            .find(|(message, _)| start_line(message).starts_with("BYE"))
            .expect("the BYE");
        assert_eq!(bye.1, ELSEWHERE, "the answer did not move the dialog");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn ignoring_the_request_leaves_the_call_where_it_was() {
        let mut observed = Observed::default();
        let (handle, call) = called_a_name(&mut observed);
        assert_eq!(
            unsafe { crate::call::sipral_call_hangup(handle, call, 1_200) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = drain_addressed(handle);
        let bye = out
            .iter()
            .find(|(message, _)| start_line(message).starts_with("BYE"))
            .expect("the BYE");
        assert_ne!(bye.1, ELSEWHERE);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// RFC 3263 4.3: the first reachable address is taken.
    #[test]
    fn a_list_is_taken_in_the_order_it_was_written() {
        let mut observed = Observed::default();
        let (handle, call) = called_a_name(&mut observed);
        let dialog = observed.resolves.first().expect("one request").dialog;
        let written = format!("{ELSEWHERE},192.0.2.200:5060");
        let (addresses, addresses_len) =
            (written.as_ptr().cast::<std::ffi::c_char>(), written.len());
        assert_eq!(
            unsafe { sipral_stack_resolved(handle, dialog, addresses, addresses_len, 0) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { crate::call::sipral_call_hangup(handle, call, 1_200) },
            SipralStatus::Ok
        );
        let out = drain_addressed(handle);
        let bye = out
            .iter()
            .find(|(message, _)| start_line(message).starts_with("BYE"))
            .expect("the BYE");
        assert_eq!(bye.1, ELSEWHERE, "the first usable one was not taken");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_name_in_the_address_list_is_refused_because_nothing_here_resolves_one() {
        let mut observed = Observed::default();
        let (handle, _) = called_a_name(&mut observed);
        let dialog = observed.resolves.first().expect("one request").dialog;
        let (addresses, addresses_len) = as_text("bob.example.com:5060");
        assert_eq!(
            unsafe { sipral_stack_resolved(handle, dialog, addresses, addresses_len, 0) },
            SipralStatus::InvalidArgument
        );
        assert!(
            last_error_text().contains("bob.example.com"),
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_stray_comma_and_an_empty_list_are_refused() {
        let mut observed = Observed::default();
        let (handle, _) = called_a_name(&mut observed);
        let dialog = observed.resolves.first().expect("one request").dialog;
        let (with_comma, with_comma_len) = as_text("198.51.100.7:5080,,192.0.2.200:5060");
        assert_eq!(
            unsafe { sipral_stack_resolved(handle, dialog, with_comma, with_comma_len, 0) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_stack_resolved(handle, dialog, ptr::null(), 0, 0) },
            SipralStatus::InvalidArgument,
            "an answer with no address in it was taken"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_protocol_this_abi_names_nothing_for_is_refused_before_the_stack() {
        let mut observed = Observed::default();
        let (handle, _) = called_a_name(&mut observed);
        let dialog = observed.resolves.first().expect("one request").dialog;
        let (addresses, addresses_len) = as_text(ELSEWHERE);
        assert_eq!(
            unsafe { sipral_stack_resolved(handle, dialog, addresses, addresses_len, 99) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// This stack has only UDP bound, so an answer naming TCP changes nothing.
    #[test]
    fn an_address_on_a_protocol_nothing_here_speaks_is_passed_over() {
        let mut observed = Observed::default();
        let (handle, call) = called_a_name(&mut observed);
        let dialog = observed.resolves.first().expect("one request").dialog;
        let (addresses, addresses_len) = as_text(ELSEWHERE);
        assert_eq!(
            unsafe {
                sipral_stack_resolved(
                    handle,
                    dialog,
                    addresses,
                    addresses_len,
                    SipralTransport::Tcp as u32,
                )
            },
            SipralStatus::Ok,
            "a protocol nothing has bound is not a caller mistake"
        );
        assert_eq!(
            unsafe { crate::call::sipral_call_hangup(handle, call, 1_200) },
            SipralStatus::Ok
        );
        let out = drain_addressed(handle);
        let bye = out
            .iter()
            .find(|(message, _)| start_line(message).starts_with("BYE"))
            .expect("the BYE");
        assert_ne!(bye.1, ELSEWHERE, "an unbound protocol was used anyway");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_dialog_handle_from_nowhere_is_refused() {
        let mut observed = Observed::default();
        let (handle, _) = called_a_name(&mut observed);
        let (addresses, addresses_len) = as_text(ELSEWHERE);
        assert_eq!(
            unsafe {
                sipral_stack_resolved(handle, SIPRAL_HANDLE_NONE, addresses, addresses_len, 0)
            },
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_retargeted_account_registers_at_the_new_address() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        assert_eq!(
            unsafe { crate::account::sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let first = drain_addressed(handle);
        let (early, was) = first
            .iter()
            .find(|(message, _)| start_line(message).starts_with("REGISTER"))
            .expect("the first REGISTER");
        assert_ne!(*was, ELSEWHERE);

        let (address, address_len) = as_text(ELSEWHERE);
        assert_eq!(
            unsafe { sipral_account_retarget(handle, account, address, address_len, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let second = drain_addressed(handle);
        let (later, now) = second
            .iter()
            .find(|(message, _)| start_line(message).starts_with("REGISTER"))
            .expect("the REGISTER the retarget sent");
        assert_eq!(now, ELSEWHERE, "the retarget did not move the REGISTER");
        assert_eq!(
            call_id_of(early),
            call_id_of(later),
            "the binding lost its Call-ID"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn retargeting_to_a_name_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        let (address, address_len) = as_text("example.com:5060");
        assert_eq!(
            unsafe { sipral_account_retarget(handle, account, address, address_len, 1_000) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// Stale, not invalid: this library minted the handle.
    #[test]
    fn retargeting_an_account_on_a_stack_that_is_gone_is_stale() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
        let (address, address_len) = as_text(ELSEWHERE);
        assert_eq!(
            unsafe { sipral_account_retarget(handle, account, address, address_len, 1_000) },
            SipralStatus::StaleHandle
        );
    }

    /// The `Call-ID` line of a REGISTER.
    fn call_id_of(message: &[u8]) -> String {
        let text = String::from_utf8_lossy(message);
        text.lines()
            .find(|line| line.to_ascii_lowercase().starts_with("call-id:"))
            .unwrap_or_default()
            .to_owned()
    }
}
