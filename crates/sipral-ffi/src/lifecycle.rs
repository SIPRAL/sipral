// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Sleep and network facts from the operating system, handed across the
//! boundary (`docs/16-lifecycle.md`).
//!
//! The clock stops while a machine is suspended, so a stack that slept eight
//! hours believes eight milliseconds passed and its bindings still valid. Only
//! the platform knows otherwise, so the application calls these entry points.
//!
//! [`sipral_stack_suspending`] has a hard deadline and sends nothing.
//! [`sipral_stack_resumed`] is the other side. [`sipral_stack_network_changed`]
//! is cheap and meant to be called often; its return value says whether
//! anything happened. [`sipral_stack_interface_lost`] and
//! [`sipral_stack_name_resolution_lost`] are the two failures that look alive:
//! with no interface nothing is tried; with no resolver only bindings aimed at
//! a name stop being trusted. [`sipral_account_rebind`] hands over the
//! transport or address recovery asked for, before its wait runs out.
//!
//! These make [`SIPRAL_REGISTRATION_STATE_UNVERIFIED`] and
//! [`SIPRAL_REGISTRATION_STATE_RESTORED`](crate::event::SipralRegistrationState::Restored)
//! reachable from C; [`SIPRAL_EVENT_KIND_RECOVERY`](crate::event::SipralEventKind::Recovery)
//! says a recovery finished.
//!
//! [`SIPRAL_REGISTRATION_STATE_UNVERIFIED`]: crate::event::SipralRegistrationState::Unverified

use std::ffi::c_char;
use std::net::IpAddr;
use std::time::Duration;

use sipral_core::endpoint::TransportId;
use sipral_core::msg::Uri;
use sipral_ua::{Link, Network, Recovery, SnapshotError};

use crate::abi::{Number, codes, record};
use crate::call::ua_failed;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::address;
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{bytes, copy_bytes_out, required_text, text};
use crate::versioned::{Versioned, declared_size, write_versioned};

codes! {
    /// What kind of link the application is on: `from_link` and `to_link` on
    /// [`sipral_stack_network_changed`].
    ///
    /// Only [`SipralLink::Down`] changes what is done. The rest makes a change
    /// of kind over an unchanged address (a tunnel, Wi-Fi to cellular) visible.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralLink: u32 {
        /// There is no usable interface.
        Down = 0,
        /// Cable.
        Wired = 1,
        /// Wireless local network.
        Wifi = 2,
        /// A mobile network.
        Cellular = 3,
        /// A tunnel over one of the others.
        Tunnel = 4,
    }
}

codes! {
    /// What a change of network is worth doing about:
    /// [`sipral_stack_network_changed`]'s `out_recovery`. Returned directly, so
    /// a laptop flipping access points gets [`SipralRecovery::Nothing`] without
    /// reading an event or sending a REGISTER.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRecovery: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// Nothing this stack uses is different; nothing is done or sent.
        Nothing = 1,
        /// The address stands, so the transports do; what is upstream may not.
        Reregister = 2,
        /// A wake: the existing transport is tried first, a new one asked for
        /// only if it is dead. Started by [`sipral_stack_resumed`], never
        /// returned here.
        Reprove = 3,
        /// The address is gone; the application must open a transport again.
        Rebuild = 4,
        /// Packets can leave and names cannot be turned into addresses.
        Resolve = 5,
        /// There is no interface. Nothing is tried until there is one.
        Detach = 6,
    }
}

/// A transport this stack has bound, or why the number is not one. Duplicates
/// [`crate::transport::named`] to avoid coupling sibling modules.
fn transport_named(state: &StackState, transport: u32) -> Result<TransportId, Fail> {
    state.transports.resolve(transport).ok_or_else(|| {
        fail(
            SipralStatus::InvalidArgument,
            format!(
                "transport {transport} is not one this stack has; sipral_stack_transport_bind \
                 is what adds one, and 0 is SIPRAL_TRANSPORT_MAIN, which every stack has from \
                 its creation"
            ),
        )
    })
}

fn link_of(value: u32, name: &'static str) -> Result<Link, Fail> {
    match value {
        0 => Ok(Link::Down),
        1 => Ok(Link::Wired),
        2 => Ok(Link::Wifi),
        3 => Ok(Link::Cellular),
        4 => Ok(Link::Tunnel),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {other}, which is not a SIPRAL_LINK this library names"),
        )),
    }
}

/// A [`Recovery`] as C reads it.
const fn recovery_code(recovery: Recovery) -> SipralRecovery {
    match recovery {
        Recovery::Nothing => SipralRecovery::Nothing,
        Recovery::Reregister => SipralRecovery::Reregister,
        Recovery::Reprove => SipralRecovery::Reprove,
        Recovery::Rebuild => SipralRecovery::Rebuild,
        Recovery::Resolve => SipralRecovery::Resolve,
        Recovery::Detach => SipralRecovery::Detach,
        // `#[non_exhaustive]`
        _ => SipralRecovery::Unknown,
    }
}

/// One side of [`sipral_stack_network_changed`], from C arguments.
///
/// # Safety
///
/// `address`, when it is not null, must be readable for `address_len` bytes,
/// and `interface`, when it is not null, must be readable for
/// `interface_len` bytes.
#[allow(clippy::too_many_arguments)]
unsafe fn network_of(
    link: u32,
    link_name: &'static str,
    address: *const c_char,
    address_len: usize,
    address_name: &'static str,
    interface: *const c_char,
    interface_len: usize,
    interface_name: &'static str,
    resolves: u32,
) -> Result<Network, Fail> {
    let link = link_of(link, link_name)?;
    let mut network = Network::new(link).resolves(resolves != 0);
    if let Some(supplied) = unsafe { text(address, address_len, address_name) }? {
        let parsed = supplied.parse::<IpAddr>().map_err(|_| {
            fail(
                SipralStatus::InvalidArgument,
                format!("{address_name} is {supplied:?}, which is not an IPv4 or IPv6 literal"),
            )
        })?;
        network = network.address(parsed);
    }
    if let Some(supplied) = unsafe { text(interface, interface_len, interface_name) }? {
        network = network.interface(supplied);
    }
    Ok(network)
}

/// The `contact` URI, or why it will not parse.
fn contact_uri(supplied: &str) -> Result<Uri, Fail> {
    Uri::parse_str(supplied).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("contact is {supplied:?}, which is not a URI: {error}"),
        )
    })
}

record! {
    /// What was standing when [`sipral_stack_suspending`] was called. Set
    /// `size` to `sizeof(sipral_suspending_t)` first.
    ///
    /// Counts only: no allocation in the suspend window. All of it is past
    /// tense when read, and nothing was sent about any of it.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralSuspending {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// Bindings that read as live and do not any more.
        pub unverified: usize,
        /// Subscriptions whose last notification stopped being evidence.
        pub subscriptions: usize,
        /// Calls that were up, left untouched: hanging up because the machine
        /// blinked is worse than learning later that a call is gone.
        pub calls: usize,
    }
}

// Safety: integers only; all-zero means nothing was standing.
unsafe impl Versioned for SipralSuspending {
    const NAME: &'static str = "sipral_suspending";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralSuspending, calls);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

entry! {
    /// The operating system says this process stops shortly.
    ///
    /// Synchronous, bounded by accounts and subscriptions, infallible. Nothing
    /// is sent (`docs/16-lifecycle.md` says why de-registering here is wrong)
    /// and nothing stays scheduled. Calls are left as they are. `out_report`
    /// receives the counts.
    ///
    /// # Safety
    ///
    /// `out_report` must point at a `sipral_suspending_t` whose `size` member
    /// says how long it is.
    fn sipral_stack_suspending(
        stack: SipralHandle,
        now_ms: u64,
        out_report: *mut SipralSuspending,
    ) {
        // size first, so a wrong size is reported as such
        unsafe { declared_size(out_report.cast_const()) }?;
        let report = with_stack_at(stack, now_ms, |state, now| Ok(state.agent.suspending(now)))?;
        let out = SipralSuspending {
            size: size_of::<SipralSuspending>(),
            unverified: report.unverified,
            subscriptions: report.subscriptions,
            calls: report.calls,
        };
        unsafe { write_versioned(out_report, out) }
    }
}

entry! {
    /// The process is awake again.
    ///
    /// An unmeasurable time passed and any transport may be dead. Beliefs are
    /// dropped and proved again, on the existing transport first (most wakes
    /// are short); [`sipral_account_rebind`] supplies a new one when asked.
    /// Safe without a matching [`sipral_stack_suspending`]: some platforms
    /// only notify on the way back.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_stack_resumed(stack: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            state.agent.resumed(now);
            Ok(())
        })
    }
}

entry! {
    /// The network changed; before and after are described.
    ///
    /// `*_link` is a [`SipralLink`]. `*_address` is the local address the
    /// transports are bound to, an IP literal without port; a change
    /// invalidates every transport and binding. `*_interface` is the
    /// platform's interface id, only compared, since two networks can hand out
    /// the same address. `*_resolves` says whether names resolve there, the
    /// one failure that looks healthy. Address and interface may be null with
    /// zero length.
    ///
    /// `out_recovery`, which may be null, receives a [`SipralRecovery`].
    /// Cheap enough to call on every notification: usually the answer is
    /// `SIPRAL_RECOVERY_NOTHING` and nothing happens.
    ///
    /// # Safety
    ///
    /// Every address and interface pointer must be readable for the length
    /// beside it or null with a length of zero, and `out_recovery` must point
    /// at one `uint32_t` or be null.
    fn sipral_stack_network_changed(
        stack: SipralHandle,
        from_link: Number<SipralLink>,
        from_address: *const c_char,
        from_address_len: usize,
        from_interface: *const c_char,
        from_interface_len: usize,
        from_resolves: u32,
        to_link: Number<SipralLink>,
        to_address: *const c_char,
        to_address_len: usize,
        to_interface: *const c_char,
        to_interface_len: usize,
        to_resolves: u32,
        now_ms: u64,
        out_recovery: *mut Number<SipralRecovery>,
    ) {
        let from = unsafe {
            network_of(
                from_link,
                "from_link",
                from_address,
                from_address_len,
                "from_address",
                from_interface,
                from_interface_len,
                "from_interface",
                from_resolves,
            )
        }?;
        let to = unsafe {
            network_of(
                to_link,
                "to_link",
                to_address,
                to_address_len,
                "to_address",
                to_interface,
                to_interface_len,
                "to_interface",
                to_resolves,
            )
        }?;
        let recovery = with_stack_at(stack, now_ms, |state, now| {
            Ok(state.agent.network_changed(&from, &to, now))
        })?;
        if !out_recovery.is_null() {
            unsafe { out_recovery.write(recovery_code(recovery) as u32) };
        }
        Ok(())
    }
}

entry! {
    /// There is no usable interface. Nothing is tried or scheduled until
    /// [`sipral_stack_network_changed`] reports one back; the opposite of
    /// [`sipral_stack_name_resolution_lost`].
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_stack_interface_lost(stack: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            state.agent.interface_lost(now);
            Ok(())
        })
    }
}

entry! {
    /// Names no longer become addresses.
    ///
    /// Everything looks healthy while every address learned from a name may
    /// be wrong. Bindings whose registrar is a name stop being trusted; ones
    /// aimed at a literal address keep running.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_stack_name_resolution_lost(stack: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            state.agent.name_resolution_lost(now);
            Ok(())
        })
    }
}

entry! {
    /// Point an account at a transport and an address again.
    ///
    /// `remote` is where its requests go, `host:port`. `contact` is required:
    /// after an address change the old one is unreachable, and keeping it
    /// would register a binding that receives nothing.
    ///
    /// `transport` must already exist:
    /// [`SIPRAL_TRANSPORT_MAIN`](crate::transport::SIPRAL_TRANSPORT_MAIN) or
    /// one [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind)
    /// bound; anything else is `SIPRAL_STATUS_INVALID_ARGUMENT`. This does not
    /// open one.
    ///
    /// When recovery is waiting for it, the next rung runs at once instead of
    /// waiting out the back-off. Otherwise the account is still repointed and
    /// the next REGISTER uses it.
    ///
    /// # Safety
    ///
    /// `remote` must be readable for `remote_len` bytes and `contact` for
    /// `contact_len` bytes.
    fn sipral_account_rebind(
        stack: SipralHandle,
        account: SipralHandle,
        transport: u32,
        remote: *const c_char,
        remote_len: usize,
        contact: *const c_char,
        contact_len: usize,
        now_ms: u64,
    ) {
        let remote = unsafe { address(remote, remote_len, "remote") }?;
        let contact_text = unsafe { required_text(contact, contact_len, "contact") }?;
        let contact = contact_uri(contact_text)?;
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            let transport = transport_named(state, transport)?;
            state
                .agent
                .rebind(id, transport, remote, &contact, now)
                .map_err(|error| ua_failed(&error))?;
            // rewrite the Contact to a known public address, as on add
            crate::nat::Nat::contacts_changed(state, now);
            Ok(())
        })
    }
}

/// Why a snapshot would not be read back. Unnumbered reasons of the
/// `#[non_exhaustive]` [`SnapshotError`] map to a refused argument.
fn snapshot_failed(error: SnapshotError) -> Fail {
    let status = match error {
        // written by a newer header: answered as a short struct is
        SnapshotError::FromTheFuture { .. } => SipralStatus::UnsupportedVersion,
        // nothing to restore into, as `sipral_account_refresh_binding` says
        SnapshotError::NotRegistering => SipralStatus::NotSupported,
        _ => SipralStatus::InvalidArgument,
    };
    fail(status, error.to_string())
}

entry! {
    /// Mark the process start, the zero of [`sipral_account_time_to_ready`].
    ///
    /// Only the application knows the moment its users wait from. Each call
    /// clears and restarts every account's measurement.
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_stack_cold_start(stack: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            state.agent.cold_start(now);
            Ok(())
        })
    }
}

entry! {
    /// Write an account's registration down, so a later start can carry it
    /// on without a full handshake.
    ///
    /// `out_len` always receives the size; a null `buffer` with `capacity`
    /// zero asks for it and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`. Nothing is
    /// written to a short buffer.
    ///
    /// **The bytes are opaque; parsing them is not part of this ABI.** They are
    /// versioned and a build reads only its known layouts. Storing and
    /// protecting them is the application's: they name an address of record.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when there is nothing to keep: never
    /// registered, never will, failed, or given up. The clock is read, not
    /// moved, so a snapshot on the way into suspend cannot reject a later
    /// `now_ms`.
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// `capacity` of zero, and `out_len` must point at one `size_t` or be
    /// null.
    fn sipral_account_freeze(
        stack: SipralHandle,
        account: SipralHandle,
        buffer: *mut u8,
        capacity: usize,
        out_len: *mut usize,
        now_ms: u64,
    ) {
        with_stack(stack, |state| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            let now = state.instant(now_ms)?;
            let Some(snapshot) = state.agent.freeze_registration(id, now) else {
                return Err(fail(
                    SipralStatus::WrongState,
                    "this account has no registration worth writing down: it has never \
                     registered, it never will, or the binding it had is gone",
                ));
            };
            unsafe { copy_bytes_out(&snapshot, buffer, capacity, out_len) }
        })
    }
}

entry! {
    /// Read one back, on an account that was added and has not registered.
    ///
    /// `asleep_ms` is how long the snapshot sat unused: only the application
    /// knows, since no wall clock is read here and instants die with the
    /// process. The binding keeps what it had left, less that.
    ///
    /// The account comes up
    /// [`SIPRAL_REGISTRATION_STATE_RESTORED`](crate::event::SipralRegistrationState::Restored),
    /// not registered, until the refresh this books confirms it.
    ///
    /// Refused with the account unchanged: `SIPRAL_STATUS_UNSUPPORTED_VERSION`
    /// for bytes a newer build wrote, `SIPRAL_STATUS_NOT_SUPPORTED` for an
    /// account that does not register, `SIPRAL_STATUS_INVALID_ARGUMENT` for
    /// bytes that are not a snapshot, are damaged, or belong to another
    /// address of record (which would register somebody else).
    ///
    /// # Safety
    ///
    /// `snapshot` must be readable for `snapshot_len` bytes.
    fn sipral_account_thaw(
        stack: SipralHandle,
        account: SipralHandle,
        snapshot: *const u8,
        snapshot_len: usize,
        asleep_ms: u64,
        now_ms: u64,
    ) {
        let Some(snapshot) = (unsafe { bytes(snapshot, snapshot_len, "snapshot") })? else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "snapshot is empty, and there is nothing in no bytes to restore",
            ));
        };
        let asleep = Duration::from_millis(asleep_ms);
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            state
                .agent
                .thaw_registration(id, snapshot, asleep, now)
                .map_err(snapshot_failed)
        })
    }
}

entry! {
    /// How long this account took to become reachable, from
    /// [`sipral_stack_cold_start`]. A queue's ring timeout must exceed it, or
    /// a waking phone is always skipped.
    ///
    /// `out_has_value` and `out_ms` are zero until there is an answer: before
    /// registration, for an account that never registers, or with no cold
    /// start declared. Zero with `out_has_value` set is a real answer.
    ///
    /// # Safety
    ///
    /// `out_has_value` must point at one `uint32_t` and `out_ms` at one
    /// `uint64_t`.
    fn sipral_account_time_to_ready(
        stack: SipralHandle,
        account: SipralHandle,
        out_has_value: *mut u32,
        out_ms: *mut u64,
    ) {
        if out_has_value.is_null() || out_ms.is_null() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "out_has_value or out_ms is null",
            ));
        }
        let ready = with_stack(stack, |state| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            Ok(state.agent.time_to_ready(id))
        })?;
        unsafe {
            out_has_value.write(u32::from(ready.is_some()));
            out_ms.write(
                ready.map_or(0, |took| u64::try_from(took.as_millis()).unwrap_or(u64::MAX)),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralLink, SipralRecovery, SipralSuspending, sipral_account_freeze, sipral_account_rebind,
        sipral_account_thaw, sipral_account_time_to_ready, sipral_stack_cold_start,
        sipral_stack_interface_lost, sipral_stack_name_resolution_lost,
        sipral_stack_network_changed, sipral_stack_resumed, sipral_stack_suspending,
    };
    use crate::account::SipralAccountConfig;
    use crate::account::tests::state_of;
    use crate::error::last_error_text;
    use crate::event::{
        SipralEvent, SipralEventKind, SipralRecoveryOutcome, SipralRegistrationState,
    };
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::{Observed, config, create, poll, stack};
    use crate::status::SipralStatus;
    use crate::transport::SIPRAL_TRANSPORT_MAIN;
    use crate::transport::tests::drain;
    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};
    use std::ffi::{c_char, c_void};
    use std::ptr;

    const REGISTRAR: &str = "203.0.113.9:5060";

    fn text(supplied: &'static str) -> (*const c_char, usize) {
        (supplied.as_ptr().cast::<c_char>(), supplied.len())
    }

    /// An account whose registrar is a name, so it needs a resolver.
    fn named_account() -> SipralAccountConfig {
        let (aor, aor_len) = text("sip:alice@example.com");
        let (registrar, registrar_len) = text("sip:example.com");
        let (contact, contact_len) = text("sip:alice@192.0.2.10:5060");
        let (registrar_address, registrar_address_len) = text(REGISTRAR);
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
            headers: ptr::null(),
            headers_len: 0,
            transport: 0,
            push_provider: ptr::null(),
            push_provider_len: 0,
            push_prid: ptr::null(),
            push_prid_len: 0,
            push_param: ptr::null(),
            push_param_len: 0,
            push_wakes_itself: 0,
            quality_report_uri: ptr::null(),
            quality_report_uri_len: 0,
            session_timer: 0,
            session_interval_seconds: 0,
            privacy: 0,
            trusted_peers: ptr::null(),
            trusted_peers_len: 0,
            srtp: 0,
            srtp_suites: ptr::null(),
            srtp_suites_len: 0,
            stir_verification: 0,
            stir_key: ptr::null(),
            stir_key_len: 0,
            stir_certificate_url: ptr::null(),
            stir_certificate_url_len: 0,
            stir_orig: ptr::null(),
            stir_orig_len: 0,
            stir_origid: ptr::null(),
            stir_origid_len: 0,
            stir_attestation: 0,
            recording_in_clear: 0,
            keepalive_ms: 0,
            server_uri: ptr::null(),
            server_uri_len: 0,
            tls_pin_sha256: ptr::null(),
            tls_pin_sha256_len: 0,
            server_naptr: 0,
            reserved: 0,
            stream_protocol: 0,
            reserved_35: 0,
            realms: std::ptr::null(),
            realms_len: 0,
            websocket_host: std::ptr::null(),
            websocket_host_len: 0,
            websocket_resource: std::ptr::null(),
            websocket_resource_len: 0,
        }
    }

    /// One pointed at a literal address, which never needed a resolver.
    fn literal_account() -> SipralAccountConfig {
        let mut config = named_account();
        let (aor, aor_len) = text("sip:bob@example.com");
        let (registrar, registrar_len) = text(REGISTRAR);
        config.aor = aor;
        config.aor_len = aor_len;
        config.registrar = registrar;
        config.registrar_len = registrar_len;
        config
    }

    fn add(stack: SipralHandle, config: &SipralAccountConfig) -> SipralHandle {
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            crate::account::sipral_account_add(stack, ptr::from_ref(config), &raw mut account)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    fn register(stack: SipralHandle, account: SipralHandle, now_ms: u64) {
        assert_eq!(
            unsafe { crate::account::sipral_account_register(stack, account, now_ms) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
    }

    fn header(message: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let parsed = parse(message, &mut scratch, ParseMode::Lenient).expect("a message");
        parsed.header(name).unwrap_or_default().to_vec()
    }

    /// The 200 a registrar sends for a binding it kept, copied through the
    /// way a real one is.
    fn granted(request: &[u8], seconds: u32) -> Vec<u8> {
        let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
        for (name, value) in [
            ("Via", header(request, HeaderName::Via)),
            ("From", header(request, HeaderName::From)),
            ("To", header(request, HeaderName::To)),
            ("Call-ID", header(request, HeaderName::CallId)),
            ("CSeq", header(request, HeaderName::CSeq)),
            ("Contact", header(request, HeaderName::Contact)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("Expires: {seconds}\r\n").as_bytes());
        out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        out
    }

    fn receive(stack: SipralHandle, message: &[u8], now_ms: u64) {
        let status = unsafe {
            crate::transport::sipral_stack_receive_datagram(
                stack,
                SIPRAL_TRANSPORT_MAIN,
                message.as_ptr(),
                message.len(),
                REGISTRAR.as_ptr().cast::<c_char>(),
                REGISTRAR.len(),
                ptr::null(),
                0,
                now_ms,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    }

    /// One account, registered for an hour, with nothing left waiting on the
    /// wire.
    fn registered(
        observed: &mut Observed,
        config: &SipralAccountConfig,
        now_ms: u64,
    ) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        let account = add(handle, config);
        register(handle, account, now_ms);
        let mut out = drain(handle);
        let request = out.pop().expect("the REGISTER");
        receive(handle, &granted(&request, 3_600), now_ms);
        (handle, account)
    }

    fn zeroed_report() -> SipralSuspending {
        SipralSuspending {
            size: size_of::<SipralSuspending>(),
            unverified: usize::MAX,
            subscriptions: usize::MAX,
            calls: usize::MAX,
        }
    }

    fn suspending(handle: SipralHandle, now_ms: u64) -> SipralSuspending {
        let mut out = zeroed_report();
        let status = unsafe { sipral_stack_suspending(handle, now_ms, &raw mut out) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        out
    }

    #[test]
    fn suspending_counts_what_it_found_and_sends_nothing() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Registered as u32
        );

        let report = suspending(handle, 1_100);
        assert_eq!(report.unverified, 1, "the one binding this stack had");
        assert_eq!(report.subscriptions, 0);
        assert_eq!(report.calls, 0);
        assert!(
            drain(handle).is_empty(),
            "nothing is sent on the way to sleep"
        );
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Unverified as u32,
            "a cached registration still reading as valid is the failure this state exists for"
        );
    }

    #[test]
    fn a_null_report_pointer_is_a_bad_argument() {
        let mut observed = Observed::default();
        let (handle, _) = registered(&mut observed, &named_account(), 1_000);
        let status = unsafe { sipral_stack_suspending(handle, 1_100, ptr::null_mut()) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn a_report_struct_shorter_than_its_min_size_is_unsupported_version() {
        let mut observed = Observed::default();
        let (handle, _) = registered(&mut observed, &named_account(), 1_000);
        let mut out = zeroed_report();
        // one byte short of the pin, on any target
        out.size = <SipralSuspending as crate::versioned::Versioned>::MIN_SIZE - 1;
        let status = unsafe { sipral_stack_suspending(handle, 1_100, &raw mut out) };
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(out.unverified, usize::MAX, "nothing was written");
    }

    /// The recovery event captured whole: `Observed` does not know its
    /// payload (the same pattern as `transport.rs`).
    #[derive(Default)]
    struct Recoveries {
        seen: Vec<(SipralEventKind, u32, u32, u32, u32)>,
    }

    unsafe extern "C" fn keep_recovery(event: *const SipralEvent, user_data: *mut c_void) {
        let observed = unsafe { &mut *user_data.cast::<Recoveries>() };
        let event = unsafe { &*event };
        if event.kind != SipralEventKind::Recovery {
            return;
        }
        let recovery = unsafe { event.payload.recovery };
        observed.seen.push((
            event.kind,
            recovery.state,
            recovery.rung,
            recovery.reason,
            recovery.unverified,
        ));
    }

    #[test]
    fn resumed_registers_again_and_a_grant_reports_recovery() {
        let mut recoveries = Recoveries::default();
        let mut settings = config(keep_recovery, &mut Observed::default());
        settings.event_user_data = ptr::from_mut(&mut recoveries).cast::<c_void>();
        let (status, handle) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = add(handle, &named_account());
        register(handle, account, 1_000);
        let mut out = drain(handle);
        let request = out.pop().expect("the REGISTER");
        receive(handle, &granted(&request, 3_600), 1_000);

        suspending(handle, 2_000);
        assert_eq!(
            unsafe { sipral_stack_resumed(handle, 2_004) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let mut out = drain(handle);
        let request = out
            .pop()
            .expect("one REGISTER, on the transport already there");
        receive(handle, &granted(&request, 3_600), 2_004);
        poll(handle, 2_004);

        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Registered as u32
        );
        assert_eq!(
            recoveries.seen,
            vec![(
                SipralEventKind::Recovery,
                SipralRecoveryOutcome::Running as u32,
                0,
                0,
                0
            )],
            "one recovery event, reporting the path proved again"
        );
    }

    #[test]
    fn resumed_is_safe_without_a_matching_suspending() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        assert_eq!(
            unsafe { sipral_stack_resumed(handle, 1_004) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        // a resume that never slept still proves what it held again
        let mut out = drain(handle);
        let request = out.pop().expect("a REGISTER");
        receive(handle, &granted(&request, 3_600), 1_004);
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Registered as u32
        );
    }

    fn address(text_value: &'static str) -> (*const c_char, usize) {
        text(text_value)
    }

    #[allow(clippy::too_many_arguments)]
    fn network_changed(
        handle: SipralHandle,
        from_link: SipralLink,
        from_address: &'static str,
        from_interface: &'static str,
        to_link: SipralLink,
        to_address: &'static str,
        to_interface: &'static str,
        now_ms: u64,
    ) -> (SipralStatus, u32) {
        let (source_address, source_address_len) = address(from_address);
        let (source_interface, source_interface_len) = address(from_interface);
        let (destination_address, destination_address_len) = address(to_address);
        let (destination_interface, destination_interface_len) = address(to_interface);
        let mut recovery = u32::MAX;
        let status = unsafe {
            sipral_stack_network_changed(
                handle,
                from_link as u32,
                source_address,
                source_address_len,
                source_interface,
                source_interface_len,
                1,
                to_link as u32,
                destination_address,
                destination_address_len,
                destination_interface,
                destination_interface_len,
                1,
                now_ms,
                &raw mut recovery,
            )
        };
        (status, recovery)
    }

    #[test]
    fn the_same_network_twice_does_nothing_and_says_so() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        let (status, recovery) = network_changed(
            handle,
            SipralLink::Wifi,
            "192.0.2.1",
            "en0",
            SipralLink::Wifi,
            "192.0.2.1",
            "en0",
            1_100,
        );
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(recovery, SipralRecovery::Nothing as u32);
        assert!(drain(handle).is_empty());
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Registered as u32,
            "a binding nothing happened to is still a binding"
        );

        // and nothing is announced: a recovery that never happened is
        // indistinguishable from a real one
        poll(handle, 1_200);
        assert!(
            !observed
                .events
                .iter()
                .any(|(_, kind, _)| *kind == SipralEventKind::Recovery),
            "a change that changed nothing announced a recovery: {:?}",
            observed.events
        );
    }

    #[test]
    fn a_changed_address_rebuilds_and_untrusts_the_binding() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        let (status, recovery) = network_changed(
            handle,
            SipralLink::Wifi,
            "192.0.2.1",
            "en0",
            SipralLink::Wired,
            "198.51.100.4",
            "en5",
            1_100,
        );
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(recovery, SipralRecovery::Rebuild as u32);
        assert!(
            drain(handle).is_empty(),
            "the transport is bound to an address that is gone"
        );
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Unverified as u32
        );
    }

    #[test]
    fn an_unnamed_link_is_a_bad_argument() {
        let mut observed = Observed::default();
        let (handle, _) = registered(&mut observed, &named_account(), 1_000);
        let (status, _) = network_changed(
            handle,
            SipralLink::Wifi,
            "192.0.2.1",
            "en0",
            SipralLink::Wifi,
            "192.0.2.1",
            "en0",
            1_100,
        );
        assert_eq!(status, SipralStatus::Ok);

        let mut recovery = u32::MAX;
        let (fa, fa_len) = address("192.0.2.1");
        let status = unsafe {
            sipral_stack_network_changed(
                handle,
                99,
                fa,
                fa_len,
                ptr::null(),
                0,
                1,
                2,
                fa,
                fa_len,
                ptr::null(),
                0,
                1,
                1_200,
                &raw mut recovery,
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("from_link"),
            "{}",
            last_error_text()
        );
    }

    #[test]
    fn interface_lost_stops_everything_and_tries_nothing() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        assert_eq!(
            unsafe { sipral_stack_interface_lost(handle, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(drain(handle).is_empty());
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Unverified as u32
        );
    }

    #[test]
    fn losing_the_resolver_untrusts_only_the_bindings_that_needed_one() {
        let mut observed = Observed::default();
        let (handle, named) = registered(&mut observed, &named_account(), 1_000);
        let literal = add(handle, &literal_account());
        register(handle, literal, 1_000);
        let mut out = drain(handle);
        let request = out.pop().expect("the second REGISTER");
        receive(handle, &granted(&request, 3_600), 1_000);
        let _ = poll(handle, 1_000);
        let before = observed.events.len();

        assert_eq!(
            unsafe { sipral_stack_name_resolution_lost(handle, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = poll(handle, 1_100);
        assert_eq!(
            state_of(handle, named),
            SipralRegistrationState::Unverified as u32
        );
        // the untrusted binding is also an event on the next poll
        let said: Vec<(SipralEventKind, SipralHandle)> = observed
            .events
            .iter()
            .zip(&observed.named)
            .skip(before)
            .map(|(event, named)| (event.1, named.0))
            .collect();
        assert!(
            said.contains(&(SipralEventKind::RegistrationChanged, named)),
            "the resolver went and nothing was said about the account that needed it: {said:?}"
        );
        assert!(
            !said.contains(&(SipralEventKind::RegistrationChanged, literal)),
            "{said:?}"
        );
        assert_eq!(
            state_of(handle, literal),
            SipralRegistrationState::Registered as u32,
            "a literal address does not stop being one when a resolver dies"
        );
        assert!(
            drain(handle).is_empty(),
            "an address learned from a name is not a thing to send to now"
        );
    }

    #[test]
    fn rebind_points_the_account_at_a_new_contact_before_the_next_register() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        let (remote, remote_len) = text(REGISTRAR);
        let (contact, contact_len) = text("sip:alice@198.51.100.7:5060");
        let status = unsafe {
            sipral_account_rebind(
                handle,
                account,
                SIPRAL_TRANSPORT_MAIN,
                remote,
                remote_len,
                contact,
                contact_len,
                1_100,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        // resumed re-registers on the contact rebind just set
        assert_eq!(
            unsafe { sipral_stack_resumed(handle, 1_100) },
            SipralStatus::Ok
        );
        let mut out = drain(handle);
        let request = out.pop().expect("a REGISTER");
        let contact_header = header(&request, HeaderName::Contact);
        assert!(
            contact_header
                .windows(11)
                .any(|window| window == b"198.51.100."),
            "the new contact was not on the REGISTER: {}",
            String::from_utf8_lossy(&contact_header)
        );
    }

    #[test]
    fn rebind_on_an_account_that_was_removed_is_a_stale_handle() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        assert_eq!(
            unsafe { crate::account::sipral_account_remove(handle, account) },
            SipralStatus::Ok
        );
        let (remote, remote_len) = text(REGISTRAR);
        let (contact, contact_len) = text("sip:alice@198.51.100.7:5060");
        let status = unsafe {
            sipral_account_rebind(
                handle,
                account,
                SIPRAL_TRANSPORT_MAIN,
                remote,
                remote_len,
                contact,
                contact_len,
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::StaleHandle);
    }

    #[test]
    fn rebind_on_a_handle_this_library_never_minted_is_an_invalid_handle() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (remote, remote_len) = text(REGISTRAR);
        let (contact, contact_len) = text("sip:alice@198.51.100.7:5060");
        let status = unsafe {
            sipral_account_rebind(
                handle,
                SIPRAL_HANDLE_NONE,
                SIPRAL_TRANSPORT_MAIN,
                remote,
                remote_len,
                contact,
                contact_len,
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::InvalidHandle);
    }

    #[test]
    fn rebind_refuses_a_transport_this_stack_does_not_have() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        let (remote, remote_len) = text(REGISTRAR);
        let (contact, contact_len) = text("sip:alice@198.51.100.7:5060");
        let status = unsafe {
            sipral_account_rebind(
                handle,
                account,
                7,
                remote,
                remote_len,
                contact,
                contact_len,
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains('7'), "{}", last_error_text());
    }

    #[test]
    fn rebind_requires_a_contact() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        let (remote, remote_len) = text(REGISTRAR);
        let status = unsafe {
            sipral_account_rebind(
                handle,
                account,
                SIPRAL_TRANSPORT_MAIN,
                remote,
                remote_len,
                ptr::null(),
                0,
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    fn freeze(handle: SipralHandle, account: SipralHandle, now_ms: u64) -> (SipralStatus, Vec<u8>) {
        let mut needed = usize::MAX;
        let asked = unsafe {
            sipral_account_freeze(handle, account, ptr::null_mut(), 0, &raw mut needed, now_ms)
        };
        if asked != SipralStatus::BufferTooSmall {
            return (asked, Vec::new());
        }
        let mut room = vec![0_u8; needed];
        let mut written = usize::MAX;
        let status = unsafe {
            sipral_account_freeze(
                handle,
                account,
                room.as_mut_ptr(),
                room.len(),
                &raw mut written,
                now_ms,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            written, needed,
            "the second answer disagreed with the first"
        );
        (status, room)
    }

    fn thaw(
        handle: SipralHandle,
        account: SipralHandle,
        snapshot: &[u8],
        asleep_ms: u64,
        now_ms: u64,
    ) -> SipralStatus {
        unsafe {
            sipral_account_thaw(
                handle,
                account,
                snapshot.as_ptr(),
                snapshot.len(),
                asleep_ms,
                now_ms,
            )
        }
    }

    fn time_to_ready(handle: SipralHandle, account: SipralHandle) -> Option<u64> {
        let mut has_value = u32::MAX;
        let mut took = u64::MAX;
        let status = unsafe {
            sipral_account_time_to_ready(handle, account, &raw mut has_value, &raw mut took)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        if has_value == 0 {
            assert_eq!(took, 0, "no answer came with a number anyway");
            return None;
        }
        Some(took)
    }

    /// A frozen registration thaws in a new process as restored, not
    /// registered.
    #[test]
    fn a_frozen_registration_comes_back_restored() {
        let mut observed = Observed::default();
        let (first, account) = registered(&mut observed, &named_account(), 1_000);
        let (status, snapshot) = freeze(first, account, 1_100);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert!(!snapshot.is_empty(), "a binding froze to nothing");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(first) },
            SipralStatus::Ok
        );

        let mut woken = Observed::default();
        let second = stack(&mut woken);
        let restored = add(second, &named_account());
        assert_eq!(
            thaw(second, restored, &snapshot, 60_000, 1_000),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            state_of(second, restored),
            SipralRegistrationState::Restored as u32,
            "a binding nobody has confirmed came back as evidence"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(second) },
            SipralStatus::Ok
        );
    }

    /// A null buffer with zero capacity asks how much room is needed.
    #[test]
    fn freezing_into_no_room_says_how_much_is_needed() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        let mut needed = usize::MAX;
        assert_eq!(
            unsafe {
                sipral_account_freeze(handle, account, ptr::null_mut(), 0, &raw mut needed, 1_100)
            },
            SipralStatus::BufferTooSmall
        );
        assert!(needed > 0 && needed != usize::MAX, "{needed}");

        // one byte short is still too small, nothing written
        let mut room = vec![0xAB_u8; needed];
        let mut written = usize::MAX;
        assert_eq!(
            unsafe {
                sipral_account_freeze(
                    handle,
                    account,
                    room.as_mut_ptr(),
                    needed - 1,
                    &raw mut written,
                    1_100,
                )
            },
            SipralStatus::BufferTooSmall
        );
        assert_eq!(written, needed);
        assert!(
            room.iter().all(|byte| *byte == 0xAB),
            "a buffer too short was written to anyway"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// Nothing worth keeping says so, rather than returning zero bytes.
    #[test]
    fn freezing_an_account_that_never_registered_is_wrong_state() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = add(handle, &named_account());
        let mut needed = usize::MAX;
        assert_eq!(
            unsafe {
                sipral_account_freeze(handle, account, ptr::null_mut(), 0, &raw mut needed, 1_000)
            },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// The one mix-up that would otherwise send a REGISTER for somebody else.
    #[test]
    fn thawing_another_accounts_snapshot_is_refused_and_changes_nothing() {
        let mut observed = Observed::default();
        let (first, account) = registered(&mut observed, &named_account(), 1_000);
        let (_, snapshot) = freeze(first, account, 1_100);

        let elsewhere = add(first, &literal_account());
        assert_eq!(
            thaw(first, elsewhere, &snapshot, 0, 1_200),
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            state_of(first, elsewhere),
            SipralRegistrationState::Idle as u32,
            "the account that refused the snapshot was changed anyway"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(first) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn bytes_that_are_not_a_snapshot_are_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = add(handle, &named_account());
        assert_eq!(
            thaw(handle, account, b"not a snapshot", 0, 1_000),
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            thaw(handle, account, &[], 0, 1_000),
            SipralStatus::InvalidArgument,
            "no bytes at all were read as a snapshot"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// A thawed snapshot keeps what it had less the time it slept; one slept
    /// past its life refreshes at once.
    #[test]
    fn what_a_snapshot_has_left_is_what_the_application_says_it_slept_through() {
        let mut observed = Observed::default();
        let (first, account) = registered(&mut observed, &named_account(), 1_000);
        let (_, snapshot) = freeze(first, account, 1_100);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(first) },
            SipralStatus::Ok
        );

        let mut woken = Observed::default();
        let second = stack(&mut woken);
        let restored = add(second, &named_account());
        // an hour's grant, a day's sleep
        assert_eq!(
            thaw(second, restored, &snapshot, 86_400_000, 1_000),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            state_of(second, restored),
            SipralRegistrationState::Restored as u32
        );
        let result = crate::stack::tests::poll(second, 1_001);
        assert!(
            result.has_deadline == 1 && result.next_poll_in_ms < 1_000,
            "a binding with nothing left is due in {} ms, not at once",
            result.next_poll_in_ms
        );
        // and the refresh is really sent
        crate::stack::tests::poll(second, 2_000);
        assert!(
            !drain(second).is_empty(),
            "nothing was sent for a binding that had run out"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(second) },
            SipralStatus::Ok
        );
    }

    /// A non-registering account is told apart from a wrong snapshot.
    #[test]
    fn thawing_into_an_account_that_never_registers_is_not_supported() {
        let mut observed = Observed::default();
        let (first, account) = registered(&mut observed, &named_account(), 1_000);
        let (_, snapshot) = freeze(first, account, 1_100);

        let mut trunk = named_account();
        trunk.registrar = ptr::null();
        trunk.registrar_len = 0;
        let unregistered = add(first, &trunk);
        assert_eq!(
            thaw(first, unregistered, &snapshot, 0, 1_200),
            SipralStatus::NotSupported
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(first) },
            SipralStatus::Ok
        );
    }

    /// Measured from the declared cold start; no number before registering.
    #[test]
    fn time_to_ready_is_measured_from_the_cold_start_the_application_declared() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = add(handle, &named_account());
        assert_eq!(
            time_to_ready(handle, account),
            None,
            "an account that has not registered was given a number"
        );

        assert_eq!(
            unsafe { sipral_stack_cold_start(handle, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        register(handle, account, 1_000);
        let mut out = drain(handle);
        let request = out.pop().expect("the REGISTER");
        receive(handle, &granted(&request, 3_600), 1_880);
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Registered as u32
        );
        assert_eq!(
            time_to_ready(handle, account),
            Some(880),
            "the launch was not measured from where the application put it"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// Without a cold start there is no answer.
    #[test]
    fn time_to_ready_says_nothing_when_no_cold_start_was_declared() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Registered as u32
        );
        assert_eq!(time_to_ready(handle, account), None);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_null_out_pointer_on_time_to_ready_is_a_bad_argument() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        let mut took = u64::MAX;
        assert_eq!(
            unsafe {
                sipral_account_time_to_ready(handle, account, ptr::null_mut(), &raw mut took)
            },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// After `sipral_account_unregister` the state reads `UNREGISTERED` at
    /// once; the registrar's 200 raises one `REGISTRATION_CHANGED`.
    #[test]
    fn unregistered_is_read_at_once_and_the_registrars_answer_is_an_event() {
        let mut observed = Observed::default();
        let (handle, account) = registered(&mut observed, &named_account(), 1_000);
        poll(handle, 1_000);
        let changes = |observed: &Observed| {
            observed
                .kinds()
                .iter()
                .filter(|kind| **kind == SipralEventKind::RegistrationChanged)
                .count()
        };
        let before = changes(&observed);
        assert_eq!(
            unsafe { crate::account::sipral_account_unregister(handle, account, 2_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Unregistered as u32,
            "read before anything was written"
        );
        poll(handle, 2_000);
        let mut out = drain(handle);
        let request = out.pop().expect("the REGISTER that gives the binding up");
        assert_eq!(header(&request, HeaderName::Expires), b"0");
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Unregistered as u32,
            "read while the registrar has not answered"
        );
        assert_eq!(changes(&observed), before, "an event before the answer");
        receive(handle, &granted(&request, 0), 2_100);
        poll(handle, 2_100);
        assert_eq!(changes(&observed), before + 1, "the answer raised nothing");
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Unregistered as u32
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }
}
