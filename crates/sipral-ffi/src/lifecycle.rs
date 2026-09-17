// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the operating system knows about sleep and about the network, handed
//! across the boundary.
//!
//! `docs/16-lifecycle.md` is the specification this module implements: the
//! clock does not advance while a machine is suspended, so a stack that slept
//! for eight hours comes back believing eight milliseconds passed and every
//! binding it holds still valid. Nothing this library can measure contradicts
//! that belief — only the platform knows, on the notification it already
//! delivers, which is why these six entry points exist and why they are the
//! application's to call rather than something this library could infer.
//!
//! [`sipral_stack_suspending`] is a hard deadline: the process stops shortly
//! and nothing here sends anything, because a datagram handed to a socket the
//! operating system is about to stop servicing is a hope with a cost, not a
//! guarantee. [`sipral_stack_resumed`] is the other side of it, and
//! [`sipral_stack_network_changed`] is the one of the six meant to be called
//! often and cheaply — most of the time nothing this stack uses is different,
//! and the decision returned says so without a caller having to read an
//! event for it. [`sipral_stack_interface_lost`] and
//! [`sipral_stack_name_resolution_lost`] are the two ways a network can fail
//! while it looks alive, and they get opposite treatment: with no interface
//! nothing is tried, and with no resolver only the bindings that were pointed
//! at a name stop being trusted. [`sipral_account_rebind`] is how an
//! application hands over what the ladder asked for — a transport, or an
//! address — before the wait for it runs out on its own.
//!
//! Every one of them moves [`SIPRAL_REGISTRATION_STATE_UNVERIFIED`] and
//! [`SIPRAL_REGISTRATION_STATE_RESTORED`](crate::event::SipralRegistrationState::Restored)
//! from names a C caller could only read to states it can actually cause, and
//! [`SIPRAL_EVENT_KIND_RECOVERY`](crate::event::SipralEventKind::Recovery) is
//! the event that says a ladder finished, one way or the other.
//!
//! [`SIPRAL_REGISTRATION_STATE_UNVERIFIED`]: crate::event::SipralRegistrationState::Unverified

use std::ffi::c_char;
use std::net::IpAddr;

use sipral_core::endpoint::TransportId;
use sipral_core::msg::Uri;
use sipral_ua::{Link, Network, Recovery};

use crate::abi::{codes, record};
use crate::call::ua_failed;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::address;
use crate::stack::{StackState, handle_failed, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{required_text, text};
use crate::versioned::{Versioned, declared_size, write_versioned};

codes! {
    /// What kind of link the application is on. Names for `from_link` and
    /// `to_link` on [`sipral_stack_network_changed`].
    ///
    /// Coarse on purpose: nothing here changes what is sent, and the one
    /// value that changes what is *done* is [`SipralLink::Down`]. The rest is
    /// carried so that a change of kind over an unchanged address — a tunnel
    /// coming up, a phone moving from Wi-Fi to a mobile network that kept the
    /// address — is visible as a change at all.
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
    /// What a change of network is worth doing about. Names for
    /// [`sipral_stack_network_changed`]'s `out_recovery`.
    ///
    /// Returned from the call itself, so an application does not have to read
    /// an event to find out whether anything happened: a laptop that flips
    /// between two access points all day gets [`SipralRecovery::Nothing`]
    /// every time and never sends a REGISTER over it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRecovery: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// Nothing this stack uses is different. Nothing is done and nothing
        /// is sent.
        Nothing = 1,
        /// The address still stands, so the transports do. What is upstream
        /// of it may not.
        Reregister = 2,
        /// A wake: the transport already there is used first, and a new one
        /// is asked for only once it turns out to be dead. Never returned by
        /// this entry point; it is what [`sipral_stack_resumed`] starts.
        Reprove = 3,
        /// The address is gone. Everything bound to it is unusable and the
        /// application has to open a transport again.
        Rebuild = 4,
        /// Packets can leave and names cannot be turned into addresses.
        Resolve = 5,
        /// There is no interface. Nothing is tried until there is one.
        Detach = 6,
    }
}

/// A transport this stack has bound, or why the number given is not one.
///
/// [`crate::transport::named`] is the same check on the same table; it is
/// `pub(crate)` there and this stays its own three lines rather than a
/// dependency between the two sibling modules for one comparison.
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

/// What a number names, or why it names none.
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

/// What a change of network is worth doing about, said the way a C caller
/// reads it.
const fn recovery_code(recovery: Recovery) -> SipralRecovery {
    match recovery {
        Recovery::Nothing => SipralRecovery::Nothing,
        Recovery::Reregister => SipralRecovery::Reregister,
        Recovery::Reprove => SipralRecovery::Reprove,
        Recovery::Rebuild => SipralRecovery::Rebuild,
        Recovery::Resolve => SipralRecovery::Resolve,
        Recovery::Detach => SipralRecovery::Detach,
        // `Recovery` is `#[non_exhaustive]`: a value this build has not met
        // yet is as safe to call unknown as one it cannot lose track of.
        _ => SipralRecovery::Unknown,
    }
}

/// One side of [`sipral_stack_network_changed`], built from what crossed the
/// boundary.
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

/// A URI a caller supplied, or why it will not parse.
fn contact_uri(supplied: &str) -> Result<Uri, Fail> {
    Uri::parse_str(supplied).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("contact is {supplied:?}, which is not a URI: {error}"),
        )
    })
}

record! {
    /// What was standing when the process was told it is about to stop
    /// ([`sipral_stack_suspending`]'s `out_report`).
    ///
    /// Set `size` to `sizeof(sipral_suspending_t)` before the call. Counts
    /// and nothing else, because the window this is produced in is one where
    /// an allocation that grows with the number of accounts is a cost with no
    /// upper bound worth paying. Everything in it is already past tense by
    /// the time it is read: the bindings have stopped being evidence, the
    /// subscriptions have stopped being evidence, and nothing was sent about
    /// either.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralSuspending {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// Bindings that read as live and do not any more.
        pub unverified: usize,
        /// Subscriptions whose last notification stopped being evidence.
        pub subscriptions: usize,
        /// Calls that were up. Nothing was sent about them and nothing was
        /// changed: a lid closing and opening again is seconds, and hanging
        /// up a live call because the machine blinked is worse than finding
        /// out a few seconds later that it is gone.
        pub calls: usize,
    }
}

// Safety: three integers with no invariant between them, and all-zero is a
// stack that had nothing standing when it was told to sleep.
unsafe impl Versioned for SipralSuspending {
    const NAME: &'static str = "sipral_suspending";
    // Pinned here as a literal, the way every other struct in this crate
    // pins its oldest published length, rather than in
    // `crate::versioned::min_size` beside them: three branches land a bullet
    // of task 8.4.13 in this same crate at once, and that module is not one
    // any of them may touch without colliding with the other two. The
    // integrator folds this into the shared table when the branches land.
    const MIN_SIZE: usize = 32;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

entry! {
    /// The operating system says this process stops shortly.
    ///
    /// Everything reached from here is synchronous, bounded by the number of
    /// accounts and subscriptions, and cannot fail. Nothing is sent — see
    /// `docs/16-lifecycle.md` for why a graceful de-registration is the wrong
    /// thing to attempt in this window rather than the obvious one — and
    /// nothing stays scheduled: a stack that is suspended and never resumed
    /// has no deadline to fire and no work left behind.
    ///
    /// Calls that are up are left exactly as they are. A lid closing and
    /// opening again is seconds, and hanging up a live call because the
    /// machine blinked is worse than finding out a few seconds later that it
    /// is gone.
    ///
    /// `out_report` receives what was found: bindings that stopped being
    /// evidence, subscriptions whose last notification stopped being
    /// evidence, and calls left untouched.
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
        // checked before the handle is even looked up, so a caller that got
        // its size wrong is told that rather than something about the stack
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
    /// Arbitrary time has passed — arbitrary, not measurable, because the
    /// clock this stack is driven by did not run while the machine was
    /// suspended — and every transport may be dead. What was believed is
    /// dropped and proved again: the transport already there is used first,
    /// because most wakes are short and it still works, and
    /// [`sipral_account_rebind`] is how the application hands over a new one
    /// once this stack says it needs one.
    ///
    /// Safe to call without a matching [`sipral_stack_suspending`]. Some
    /// platforms only notify on the way back.
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
    /// The network is a different one, described before and after in as much
    /// detail as the decision needs.
    ///
    /// `from_link`/`to_link` is a [`SipralLink`]. `*_address` is the local
    /// address this stack's transports are bound to, as an IPv4 or IPv6
    /// literal with no port — a change of it invalidates every transport and
    /// every binding at once. `*_interface` is the platform's own identity
    /// for the interface, never parsed and only ever compared to another one
    /// of itself; two networks can hand out the same address, and a phone
    /// that walks from one office to another gets away with it until a call
    /// comes in. `*_resolves` is whether a name can become an address there,
    /// because that is the one failure that leaves everything else looking
    /// healthy. Any of the four address or interface arguments may be null
    /// with a length of zero, for a fact the application has none to give.
    ///
    /// `out_recovery` receives what was decided, as a [`SipralRecovery`], so
    /// this is safe to call as often as the platform delivers the
    /// notification — most of the time nothing this stack uses is different,
    /// and `SIPRAL_RECOVERY_NOTHING` is the whole of what happens. It may be
    /// null.
    ///
    /// # Safety
    ///
    /// Every address and interface pointer must be readable for the length
    /// beside it or null with a length of zero, and `out_recovery` must point
    /// at one `uint32_t` or be null.
    fn sipral_stack_network_changed(
        stack: SipralHandle,
        from_link: u32,
        from_address: *const c_char,
        from_address_len: usize,
        from_interface: *const c_char,
        from_interface_len: usize,
        from_resolves: u32,
        to_link: u32,
        to_address: *const c_char,
        to_address_len: usize,
        to_interface: *const c_char,
        to_interface_len: usize,
        to_resolves: u32,
        now_ms: u64,
        out_recovery: *mut u32,
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
    /// There is no usable interface.
    ///
    /// Distinct from [`sipral_stack_name_resolution_lost`] because the
    /// recovery is the opposite one: with nothing that can leave, nothing is
    /// tried and nothing is scheduled, which is the cheapest this stack ever
    /// is. The way out is [`sipral_stack_network_changed`], the notification
    /// every platform delivers when an interface comes back.
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
    /// The dangerous one: the interface is up and packets leave, so
    /// everything reads healthy, while every address this stack learned from
    /// a name may now stand for somewhere else. A binding whose registrar was
    /// written as a name stops being evidence; one pointed at a literal
    /// address never needed a resolver and is left running.
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
    /// `remote` is the far end this account's requests go to now, as
    /// `host:port`. `contact` is where this endpoint can be reached, as it
    /// goes in `Contact`; it is not optional, because after a change of
    /// address the old one names somewhere the far end cannot reach, and a
    /// stack that let it stand would register a binding that silently
    /// receives nothing.
    ///
    /// `transport` must be one this stack already has —
    /// [`SIPRAL_TRANSPORT_MAIN`](crate::transport::SIPRAL_TRANSPORT_MAIN) or
    /// a further one [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind)
    /// has bound — and any other number is `SIPRAL_STATUS_INVALID_ARGUMENT`:
    /// this call points an account at a transport, it does not open one.
    ///
    /// Safe to call whether or not this stack is waiting for it. When it is,
    /// answering climbs the next rung at once rather than waiting out the
    /// rest of the back-off — the application answering in milliseconds is
    /// the normal case, and there is nothing to be gained by making a wake
    /// take a further half minute. When it is not, this still repoints the
    /// account, and the next REGISTER this stack sends for it — a refresh, or
    /// the next rung of a ladder started afterwards — uses what was given
    /// here.
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
                .map_err(|error| ua_failed(&error))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralLink, SipralRecovery, SipralSuspending, sipral_account_rebind,
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

    // -- suspending ------------------------------------------------------

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
        out.size = 31;
        let status = unsafe { sipral_stack_suspending(handle, 1_100, &raw mut out) };
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(out.unverified, usize::MAX, "nothing was written");
    }

    // -- resumed -----------------------------------------------------------

    /// The event this module reports, captured whole rather than reduced to
    /// its kind: `crate::stack::tests::Observed` does not know this payload's
    /// shape, and this is the same pattern `transport.rs` uses to read the
    /// registration event's message out of the callback.
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
        // a resume on a stack that never slept still distrusts what it held
        // and proves it again
        let mut out = drain(handle);
        let request = out.pop().expect("a REGISTER");
        receive(handle, &granted(&request, 3_600), 1_004);
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::Registered as u32
        );
    }

    // -- network_changed -----------------------------------------------------

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

        // and nothing is announced, which is the half a phone would feel:
        // a device that reports the same network on every wake would raise a
        // recovery it never made, and an application cannot tell that one
        // from the real thing
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

    // -- interface_lost --------------------------------------------------

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

    // -- name_resolution_lost ----------------------------------------------

    #[test]
    fn losing_the_resolver_untrusts_only_the_bindings_that_needed_one() {
        let mut observed = Observed::default();
        let (handle, named) = registered(&mut observed, &named_account(), 1_000);
        let literal = add(handle, &literal_account());
        register(handle, literal, 1_000);
        let mut out = drain(handle);
        let request = out.pop().expect("the second REGISTER");
        receive(handle, &granted(&request, 3_600), 1_000);

        assert_eq!(
            unsafe { sipral_stack_name_resolution_lost(handle, 1_100) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            state_of(handle, named),
            SipralRegistrationState::Unverified as u32
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

    // -- rebind --------------------------------------------------------------

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

        // resumed distrusts the binding and re-registers it, on the contact
        // rebind just set
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
}
