// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Accounts: configured, registered, given up.
//!
//! An account is one identity, usually with one registrar behind it, and
//! several of them live in one stack without sharing anything. Adding one sends
//! nothing; [`sipral_account_register`] is what puts a REGISTER on the wire, and
//! from then on the binding is refreshed, retried and backed off without another
//! call. What the application hears about is the state, not the transactions.
//!
//! An account configured with no registrar never registers at all. It is a
//! trunk that knows this end by the address its requests come from: its state
//! reads `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` from the moment it is
//! added, registering it is refused, and what it places goes to
//! `registrar_address`, which for it is the outbound proxy.
//!
//! Three things here are the caller's and cannot be defaulted. The address
//! requests are sent to, because resolving a server's name is I/O; the
//! `Contact` this end is reachable at, because a library that never opened a
//! socket does not know what the world sees; and the instance identifier,
//! because RFC 5626 §4.1 wants one that survives a power cycle and nothing
//! here has storage.

use std::ffi::c_char;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use sipral::AccountSrtp;
use sipral_core::auth::Credentials;
use sipral_core::msg::{HeaderName, Uri};
use sipral_ua::{Account, HeadersFor, Push};

use crate::abi::record;
use crate::call::ua_failed;
use crate::error::{Fail, entry, fail};
use crate::event::registration_state;
use crate::handle::SipralHandle;
use crate::header::{SipralHeader, supplied};
use crate::media::media_failed;
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{required_text, text};
use crate::versioned::{Versioned, read_versioned};

record! {
    /// What an account is configured with.
    ///
    /// Set `size` to `sizeof(sipral_account_config_t)` and zero the rest before
    /// filling anything in.
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
        ///
        /// A `registrar_len` of zero makes an account that never registers: a
        /// trunk that knows this end by the address its requests come from.
        /// Its state is `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` for as long
        /// as it exists, and `sipral_account_register` refuses it.
        pub registrar: *const c_char,
        /// How many bytes of it.
        pub registrar_len: usize,
        /// Where this endpoint can be reached, as it goes in `Contact`.
        pub contact: *const c_char,
        /// How many bytes of it.
        pub contact_len: usize,
        /// Where this account's requests go, as `host:port`: the registrar's
        /// address for an account that registers, and the outbound proxy for
        /// one configured with no registrar. A call that names no destination
        /// of its own goes here either way, so it is required either way. An
        /// address, not a name: RFC 3263 resolution is the caller's.
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
        /// How long a binding to ask for, or zero for an hour.
        ///
        /// A `delta-seconds`, so §20.19 bounds it at 2³²−1 and anything above that
        /// is refused rather than sent as a number no registrar will read. What the
        /// registrar grants wins over the request either way, and the granted
        /// figure is what `sipral_registration_event_t::expires_ms` carries — that
        /// is where the effective value is read back, not here.
        pub expires_seconds: u64,
        /// Header fields to put on every REGISTER this account sends, in the
        /// order given, or null for none.
        ///
        /// Checked when the account is added, as `sipral_call_config_t::headers`
        /// is, against what the stack writes on a REGISTER: `Expires` is the
        /// stack's there, because it is `expires_seconds`, and `Supported` is the
        /// application's, because a registration asking for a GRUU has to say
        /// so. Refused for an account with no registrar, which sends no REGISTER
        /// to put them on.
        pub headers: *const SipralHeader,
        /// How many elements `headers` has.
        pub headers_len: usize,
        /// Which transport this account's REGISTER and every request it
        /// places go out on: [`SIPRAL_TRANSPORT_MAIN`](crate::transport::SIPRAL_TRANSPORT_MAIN)
        /// for zero, which is what a caller that leaves this at zero already
        /// gets, or a further number
        /// [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind)
        /// has bound. A number this stack has never bound is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`, naming it.
        ///
        /// Appended at the tail (task 8.4.10); the pinned `MIN_SIZE` is
        /// unmoved, and what a caller built before this member existed never
        /// sent reads as the zero that already means "the main transport".
        pub transport: u32,
        /// The push notification service to be woken through, as its
        /// registered name: `apns`, `fcm`, `webpush` (RFC 8599 §4.1.1). Null
        /// for an account that is not woken by push, which is every account on
        /// a machine that does not suspend.
        ///
        /// These four go on the `Contact` of this account's REGISTER and on no
        /// other request, ever: §4.1 says so because a `pn-prid` in the
        /// `Contact` of an INVITE hands the far end a token that wakes this
        /// device whenever it likes. The de-registration that gives the binding
        /// up leaves the identifier out, which §4.1.2 also requires.
        pub push_provider: *const c_char,
        /// How many bytes of it.
        pub push_provider_len: usize,
        /// The resource identifier the service issued for this installation —
        /// the device token. Required when `push_provider` is given, and
        /// refused without one.
        ///
        /// Whatever it holds is percent-escaped where the SIP grammar needs it
        /// (§8.7), because an APNs token carries `=` and a Web Push identifier
        /// is a whole URL.
        pub push_prid: *const c_char,
        /// How many bytes of it.
        pub push_prid_len: usize,
        /// The extra value a service needs beside the identifier: the
        /// application bundle for Apple, the sender for Firebase. §4.1.1 makes
        /// it mandatory "if required for the specific PNS", so it is optional
        /// here and the service decides.
        pub push_param: *const c_char,
        /// How many bytes of it.
        pub push_param_len: usize,
        /// Nonzero to say this device can send a binding refresh without being
        /// woken by a push, which §4.1.4 makes it declare with a
        /// `+sip.pnsreg` media feature tag.
        ///
        /// It is the application's fact and not this library's to guess: a
        /// process the operating system has suspended has no timer that runs,
        /// and one that claims otherwise gets a registrar that stops sending
        /// the wake-ups the device is relying on.
        pub push_wakes_itself: u32,
        /// Where this account's end-of-call voice quality reports go (RFC
        /// 6035, carried by a PUBLISH, RFC 3903), or null to send none.
        ///
        /// Appended at the tail (task 8.6.9); the pinned `MIN_SIZE` is
        /// unmoved, and what a caller built before this member existed
        /// never sent reads as the null that already means "send none".
        pub quality_report_uri: *const c_char,
        /// How many bytes of it.
        pub quality_report_uri_len: usize,
        /// A [`SipralSessionTimer`](crate::identity::SipralSessionTimer): how
        /// this account's calls ask for a session timer (RFC 4028). Zero is
        /// the stack's default, thirty minutes. ABI 0.29, appended at the
        /// tail like every member after the pinned `MIN_SIZE`.
        pub session_timer: u32,
        /// The interval to ask for under `SIPRAL_SESSION_TIMER_INTERVAL`, in
        /// seconds: at least 90, RFC 4028 §5's floor. Read for nothing else.
        pub session_interval_seconds: u64,
        /// `SIPRAL_PRIVACY_*` bits: place every call from this account
        /// anonymously (RFC 3323), asking for these. `SIPRAL_PRIVACY_ID` is
        /// "withhold my number". `From` becomes `"Anonymous"
        /// <sip:anonymous@anonymous.invalid>`, `Privacy` carries the bits,
        /// and the account's own identity goes in `P-Asserted-Identity` only
        /// toward a peer in `trusted_peers`. Zero asks for none.
        pub privacy: u32,
        /// The peers this account trusts (RFC 3325's trust domain), as IP
        /// addresses separated by commas: usually the registrar or the trunk.
        /// A call arriving from one of them has its asserted identity read
        /// (`sipral_call_event_t::asserted_uri`); from anywhere else it is
        /// left out. And once any are named, a call placed toward any other
        /// peer carries no `P-Asserted-Identity` or `P-Preferred-Identity`,
        /// whoever wrote it. Null and zero trusts nobody.
        pub trusted_peers: *const c_char,
        /// How many bytes of it.
        pub trusted_peers_len: usize,
        /// A `SipralSrtp`: what this account's calls do about SRTP, over the
        /// stack's own `srtp` — offered, required, DTLS-SRTP, or DTLS-SRTP
        /// falling back to SDES — or zero for the stack's. A call placed from
        /// it may name a stricter policy of its own and never a looser one
        /// (`SIPRAL_STATUS_SECURITY_POLICY`), and an INVITE it cannot answer
        /// under it is refused with 488. ABI 0.31, like every member below.
        pub srtp: u32,
        /// The SRTP suites this account's calls run, most preferred first,
        /// as RFC 4568 §6.2 and RFC 7714 §14.2 name them and separated by
        /// commas: `AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80`. The `a=crypto`
        /// lines an SDES offer carries, the lines an SDES answer takes, and
        /// the DTLS-SRTP profiles a handshake offers and accepts — GCM among
        /// them only if named. Null for this build's own. Every line is in
        /// the INVITE: past two or three over UDP it needs a stream.
        pub srtp_suites: *const c_char,
        /// How many bytes of it.
        pub srtp_suites_len: usize,
        /// A `SipralStirVerification`: what this account does with the
        /// `Identity` header fields of the calls it receives (RFC 8224 §6.2).
        /// Zero reports, once `sipral_stack_stir` has given the stack trust
        /// anchors.
        pub stir_verification: u32,
        /// The P-256 private key this account signs its calls with (RFC 8224
        /// §6.1): the bare 32-octet scalar, or an `EC PRIVATE KEY` or
        /// `PRIVATE KEY` in DER or PEM. Null and zero signs nothing. Needs the
        /// wall clock `sipral_stack_stir` gives the stack in `unix_seconds`;
        /// `SIPRAL_STATUS_WRONG_STATE` without it.
        pub stir_key: *const u8,
        /// How many bytes of it.
        pub stir_key_len: usize,
        /// Where the certificate chain for `stir_key` is published: the
        /// `x5u` and `info` of every PASSporT this account signs. Required
        /// with `stir_key`, and only with it.
        pub stir_certificate_url: *const c_char,
        /// How many bytes of it.
        pub stir_certificate_url_len: usize,
        /// The telephone number this account signs as, canonicalised by
        /// RFC 8224 §8.3's first step, or null for the number in `aor`'s user
        /// part.
        pub stir_orig: *const c_char,
        /// How many bytes of it.
        pub stir_orig_len: usize,
        /// The origination identifier every call it signs claims (RFC 8588
        /// §5), a UUID, or null for one the stack draws for the account.
        pub stir_origid: *const c_char,
        /// How many bytes of it.
        pub stir_origid_len: usize,
        /// A `SipralAttestation`: the level it claims (RFC 8588 §4), zero for
        /// full attestation, `A`.
        pub stir_attestation: u32,
    }
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and all-zero is valid: every pointer is null beside a length of
// zero, which is how a caller says it has nothing to give.
unsafe impl Versioned for SipralAccountConfig {
    const NAME: &'static str = "sipral_account_config";
    const MIN_SIZE: usize = crate::versioned::min_size::ACCOUNT_CONFIG;

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

/// How long a binding to ask for, inside what an `Expires` can say.
///
/// §20.19 makes it a number of seconds "between 0 and (2**32)-1". A larger one
/// still writes a header field, and every registrar that reads the grammar
/// refuses the request — which reaches the application as a registration that
/// will not take, four hundred milliseconds and one wire round trip after the
/// mistake was made rather than at the call that made it.
fn expiry(seconds: u64) -> Result<Duration, Fail> {
    if u32::try_from(seconds).is_err() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "expires_seconds is {seconds}, and an Expires is a number of seconds up to {}",
                u32::MAX
            ),
        ));
    }
    Ok(Duration::from_secs(seconds))
}

/// What an account's calls ask for, from what crossed the boundary: the
/// session timer (RFC 4028), the privacy (RFC 3323), and the peers whose
/// asserted identities it believes (RFC 3325).
///
/// # Safety
///
/// `config.trusted_peers` must be readable for `config.trusted_peers_len`
/// bytes or null with a length of zero.
unsafe fn with_call_options(
    mut account: Account,
    config: &SipralAccountConfig,
) -> Result<Account, Fail> {
    account = match config.session_timer {
        0 => account,
        1 => account.session_interval(None),
        2 if config.session_interval_seconds >= 90 => {
            account.session_interval(Some(Duration::from_secs(config.session_interval_seconds)))
        }
        2 => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "session_interval_seconds is {}, under RFC 4028 section 5's floor of 90",
                    config.session_interval_seconds
                ),
            ));
        }
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("session_timer is {other}, which is not a SIPRAL_SESSION_TIMER"),
            ));
        }
    };
    account = account.privacy(crate::identity::privacy_of(config.privacy)?);
    let trusted = unsafe {
        text(
            config.trusted_peers,
            config.trusted_peers_len,
            "trusted_peers",
        )
    }?;
    for peer in trusted
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|peer| !peer.is_empty())
    {
        let address = peer.parse::<IpAddr>().map_err(|_| {
            fail(
                SipralStatus::InvalidArgument,
                format!("{peer:?} in trusted_peers is not an IP address"),
            )
        })?;
        account = account.trust(address);
    }
    Ok(account)
}

fn address(supplied: &str, name: &'static str) -> Result<SocketAddr, Fail> {
    supplied.parse::<SocketAddr>().map_err(|_| {
        fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {supplied:?}, which is not an address and a port"),
        )
    })
}

/// The push service an account asks to be woken through, or nothing when it
/// asked for none.
///
/// # Safety
///
/// Every push pointer in `config` must be readable for the length beside it.
unsafe fn push_from(config: &SipralAccountConfig) -> Result<Option<Push>, Fail> {
    let provider = unsafe {
        text(
            config.push_provider,
            config.push_provider_len,
            "push_provider",
        )
    }?;
    let prid = unsafe { text(config.push_prid, config.push_prid_len, "push_prid") }?;
    let param = unsafe { text(config.push_param, config.push_param_len, "push_param") }?;
    let (Some(provider), Some(prid)) = (provider, prid) else {
        // a provider with no identifier is a `Contact` naming a service and no
        // device, which a registrar takes and nothing ever wakes
        if provider.is_some() || prid.is_some() || param.is_some() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "push_provider and push_prid go together: a service with no device to wake, or a \
                 device with no service to wake it through, is a binding nothing ever rings",
            ));
        }
        if config.push_wakes_itself != 0 {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "push_wakes_itself says how an account already asking for push refreshes its \
                 binding, and this one asks for none",
            ));
        }
        return Ok(None);
    };
    let mut push = Push::new(provider, prid);
    if let Some(param) = param {
        push = push.param(param);
    }
    if config.push_wakes_itself != 0 {
        push = push.wakes_itself();
    }
    Ok(Some(push))
}

/// Turn what crossed the boundary into an account, or say what was wrong.
///
/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn account_from(state: &StackState, config: &SipralAccountConfig) -> Result<Account, Fail> {
    let aor = unsafe { required_text(config.aor, config.aor_len, "aor") }?;
    // no registrar is an account that never registers, not a mistake
    let registrar = unsafe { text(config.registrar, config.registrar_len, "registrar") }?;
    let contact = unsafe { required_text(config.contact, config.contact_len, "contact") }?;
    let remote = unsafe {
        text(
            config.registrar_address,
            config.registrar_address_len,
            "registrar_address",
        )
    }?;
    // said for the trunk in its own words, because a caller who left the
    // registrar out on purpose reads "required" as a contradiction
    let Some(remote) = remote else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            if registrar.is_some() {
                "registrar_address is required and was not given"
            } else {
                "registrar_address is required and was not given: with registrar_len zero the \
                 account never registers, and registrar_address is the outbound proxy every \
                 request it places is sent to"
            },
        ));
    };
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
    let quality_report_uri = unsafe {
        text(
            config.quality_report_uri,
            config.quality_report_uri_len,
            "quality_report_uri",
        )
    }?;
    let asked = unsafe {
        supplied(
            config.headers,
            config.headers_len,
            HeadersFor::Registration,
            state.user_agent.is_some(),
        )
    }?;
    // accepted and never sent would be a field the application believes is
    // on the wire
    if registrar.is_none() && !asked.is_empty() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "headers go on the REGISTER, and with registrar_len zero the account never sends one",
        ));
    }

    let aor = uri(aor, "aor")?;
    let registrar = registrar
        .map(|registrar| uri(registrar, "registrar"))
        .transpose()?;
    let contact = uri(contact, "contact")?;
    let remote = address(remote, "registrar_address")?;
    let transport = crate::transport::named(state, config.transport)?;
    let mut account = match registrar {
        Some(registrar) => Account::new(aor, registrar, contact, transport, remote),
        None => Account::unregistered(aor, contact, transport, remote),
    };
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
    if let Some(quality_report_uri) = quality_report_uri {
        account = account.quality_report_uri(uri(quality_report_uri, "quality_report_uri")?);
    }
    if let Some(push) = unsafe { push_from(config) }? {
        account = account.push(push);
    }
    account = unsafe { with_call_options(account, config) }?;
    account = unsafe { crate::security::with_stir(state, account, config) }?;
    if config.expires_seconds != 0 {
        account = account.expires(expiry(config.expires_seconds)?);
    }
    if let Some(ref named) = state.user_agent {
        account = account.header(HeaderName::UserAgent, named);
    }
    for (name, value) in asked {
        account = account.header(name, value);
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
        // read before the stack is locked, like a call's own, so a value this
        // ABI names nothing for never reaches the point of building anything
        let srtp = AccountSrtp {
            policy: crate::media::srtp_policy(config.srtp, "srtp")?,
            suites: crate::security::srtp_suites(unsafe {
                text(config.srtp_suites, config.srtp_suites_len, "srtp_suites")
            }?)?,
        };
        let handle = with_stack(stack, |state| {
            let account = unsafe { account_from(state, &config) }?;
            let id = state.agent.add_account(account);
            if let Err(error) = state.engine.set_account_srtp(id, srtp.clone()) {
                state.agent.remove_account(id);
                return Err(media_failed(&error));
            }
            let handle = state.accounts.insert(id).map_err(|status| {
                state.agent.remove_account(id);
                let _ = state.engine.set_account_srtp(id, AccountSrtp::default());
                fail(status, "no room for another account on this stack")
            })?;
            // behind a NAT whose answer is already in, the account starts out
            // on the public address rather than waiting for the next refresh
            // to say so; it has not registered, so nothing is sent
            let now = state.last_instant();
            crate::nat::Nat::contacts_changed(state, now);
            Ok(handle)
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
            // the default is the engine's own, which is what forgets it
            let _ = state.engine.set_account_srtp(id, AccountSrtp::default());
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
    /// An account configured with no registrar never registers, and this
    /// answers `SIPRAL_STATUS_INVALID_ARGUMENT` for it with nothing sent.
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
    /// An account configured with no registrar has no binding to give up, and
    /// is refused the way `sipral_account_register` refuses it.
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
    /// An account configured with no registrar answers
    /// `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, always.
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
pub(crate) mod tests {
    use super::{
        SipralAccountConfig, sipral_account_add, sipral_account_register,
        sipral_account_registration_state, sipral_account_remove, sipral_account_unregister,
    };
    use crate::call::sipral_call_place;
    use crate::call::tests::call_config;
    use crate::error::last_error_text;
    use crate::event::{SipralEventKind, SipralRegistrationState};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle, StackTags};
    use crate::media::SIPRAL_ADDRESS_BYTES;
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, config, create, poll, record, stack, stack_on};
    use crate::status::SipralStatus;
    use crate::transport::tests::drain;
    use crate::transport::{SIPRAL_MESSAGE_BYTES, SipralTransmit, sipral_stack_poll_transmit};
    use std::ffi::{CStr, c_char};
    use std::ptr;

    const AOR: &str = "sip:alice@example.com";
    const REGISTRAR: &str = "sip:example.com";
    const CONTACT: &str = "sip:alice@192.0.2.10:5060";
    const ADDRESS: &str = "203.0.113.5:5060";

    fn text(value: &str) -> (*const c_char, usize) {
        (value.as_ptr().cast::<c_char>(), value.len())
    }

    pub(crate) fn account_config() -> SipralAccountConfig {
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
        }
    }

    /// The same, for an account that never registers: no registrar, and the
    /// address is the outbound proxy its requests go to.
    fn trunk_config() -> SipralAccountConfig {
        SipralAccountConfig {
            registrar: ptr::null(),
            registrar_len: 0,
            ..account_config()
        }
    }

    /// Everything the stack wants written, and where each message is going,
    /// through the C ABI and nothing else.
    fn written(stack: SipralHandle) -> Vec<(Vec<u8>, String)> {
        let mut message = vec![0_u8; SIPRAL_MESSAGE_BYTES];
        let mut destination: [c_char; SIPRAL_ADDRESS_BYTES] = [0; SIPRAL_ADDRESS_BYTES];
        let mut source: [c_char; SIPRAL_ADDRESS_BYTES] = [0; SIPRAL_ADDRESS_BYTES];
        let mut all = Vec::new();
        loop {
            let mut transmit = SipralTransmit {
                size: size_of::<SipralTransmit>(),
                transport: u32::MAX,
                protocol: u32::MAX,
                data: message.as_mut_ptr(),
                capacity: message.len(),
                len: usize::MAX,
                destination: destination.as_mut_ptr(),
                destination_capacity: destination.len(),
                destination_len: usize::MAX,
                source: source.as_mut_ptr(),
                source_capacity: source.len(),
                source_len: usize::MAX,
            };
            let status = unsafe { sipral_stack_poll_transmit(stack, &raw mut transmit) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if transmit.len == 0 {
                return all;
            }
            let bytes = message.get(..transmit.len).unwrap_or_default().to_vec();
            let to = unsafe { CStr::from_ptr(destination.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            all.push((bytes, to));
        }
    }

    fn add(stack: SipralHandle, config: &SipralAccountConfig) -> (SipralStatus, SipralHandle) {
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(stack, ptr::from_ref(config), &raw mut account) };
        (status, account)
    }

    pub(crate) fn state_of(stack: SipralHandle, account: SipralHandle) -> u32 {
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
        // tags of its own, so both stacks start at the first generation the way
        // every stack did before a handle carried one; tags from the process's
        // own set come back carrying whatever other tests minted, and can refuse
        // the handle for a reason that has nothing to do with its stack
        static TAGS: StackTags = StackTags::new();
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack_on(&TAGS, &mut first_observed);
        let second = stack_on(&TAGS, &mut second_observed);
        let (_, foreign) = add(first, &account_config());
        let (_, own) = add(second, &account_config());
        // both stacks number their accounts from the same first slot, so the
        // two handles differ in nothing but the stack they carry
        assert_ne!(foreign, own);
        assert_eq!(
            unsafe { sipral_account_register(second, foreign, 0) },
            SipralStatus::InvalidHandle,
            "the handle opened the second stack's own account"
        );
        let message = last_error_text();
        assert!(
            message.contains("minted by another stack"),
            "the refusal does not say why: {message}"
        );
        assert!(
            drain(second).is_empty(),
            "the second stack's own account was registered"
        );
        assert_eq!(state_of(second, own), SipralRegistrationState::Idle as u32);
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
        // the registrar is not among them: an account without one is a trunk
        let missing: [fn(&mut SipralAccountConfig); 3] = [
            |config| (config.aor, config.aor_len) = (ptr::null(), 0),
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
    fn an_account_with_no_registrar_is_added_and_says_it_never_registers() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (status, account) = add(handle, &trunk_config());
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(account, SIPRAL_HANDLE_NONE);
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::NotRegistering as u32,
            "not idle: idle is one sipral_account_register away from a binding"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn an_account_with_no_registrar_still_has_to_say_where_its_requests_go() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = trunk_config();
        (config.registrar_address, config.registrar_address_len) = (ptr::null(), 0);
        let (status, account) = add(handle, &config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(account, SIPRAL_HANDLE_NONE);
        let message = last_error_text();
        assert!(
            message.contains("registrar_address") && message.contains("never registers"),
            "the refusal has to name the member and say why an account without a registrar \
             still needs it: {message}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn registering_an_account_with_no_registrar_is_refused_and_sends_nothing() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (_, account) = add(handle, &trunk_config());
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::InvalidArgument
        );
        let message = last_error_text();
        assert!(message.contains("no registrar"), "{message}");
        assert_eq!(
            unsafe { sipral_account_unregister(handle, account, 1_000) },
            SipralStatus::InvalidArgument
        );

        poll(handle, 1_000);
        assert!(
            drain(handle).is_empty(),
            "a REGISTER was written for an account with no registrar"
        );
        assert_eq!(
            observed.kinds(),
            vec![SipralEventKind::Started],
            "a registration was reported for an account that has none"
        );
        assert_eq!(
            state_of(handle, account),
            SipralRegistrationState::NotRegistering as u32
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_on_an_account_with_no_registrar_goes_to_the_address_it_was_given() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (status, account) = add(handle, &trunk_config());
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let config = call_config();
        let mut call = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_place(handle, account, ptr::from_ref(&config), &raw mut call, 0) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );

        poll(handle, 0);
        let out = written(handle);
        assert!(
            out.first()
                .is_some_and(|(bytes, _)| bytes.starts_with(b"INVITE ")),
            "the call went nowhere"
        );
        let destinations: Vec<&str> = out.iter().map(|(_, to)| to.as_str()).collect();
        assert!(
            destinations.iter().all(|to| *to == ADDRESS),
            "everything the account placed goes to the proxy it was given: {destinations:?}"
        );
        assert!(
            !out.iter().any(|(bytes, _)| bytes.starts_with(b"REGISTER ")),
            "a REGISTER went out beside the call"
        );
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

    /// §20.19 bounds an `Expires` at 2³²−1 seconds. A larger figure still
    /// writes a header field, so without this the mistake surfaces as a
    /// registration the registrar refuses rather than as the call that made it.
    #[test]
    fn an_expiry_longer_than_the_header_can_carry_is_refused_where_it_is_set() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        config.expires_seconds = u64::from(u32::MAX) + 1;
        assert_eq!(add(handle, &config).0, SipralStatus::InvalidArgument);
        let message = last_error_text();
        assert!(message.contains("expires_seconds"), "{message}");

        config.expires_seconds = u64::from(u32::MAX);
        assert_eq!(
            add(handle, &config).0,
            SipralStatus::Ok,
            "the largest one an Expires can say is one it can say"
        );
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
        assert_eq!(result.has_deadline, 1, "a retransmission is scheduled");
        let out = drain(handle);
        assert_eq!(out.len(), 1, "one REGISTER, ready to be written");
        assert!(
            out.first()
                .is_some_and(|first| first.starts_with(b"REGISTER "))
        );
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
        poll(handle, 0);
        let out = drain(handle);
        assert_eq!(out.len(), 1);
        assert!(
            out.first()
                .is_some_and(|first| first.starts_with(b"REGISTER "))
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// RFC 3261 §10.2.5 is Setting the Internal Clock; the rule that a UA
    /// removes a binding by sending `Expires: 0` is §10.2.2, Removing
    /// Bindings. The needle is assembled at runtime so this test does not
    /// just match its own assertion.
    #[test]
    fn the_unregister_doc_cites_removing_bindings_not_the_clock() {
        // the needle spans a line break, and a Windows checkout puts a CR in
        // front of it
        let source = include_str!("account.rs").replace("\r\n", "\n");
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
        // one byte short of the oldest published length: anything between that
        // and this build's own is an older caller, and is taken
        let mut config = account_config();
        config.size = crate::versioned::min_size::ACCOUNT_CONFIG - 1;
        assert_eq!(add(handle, &config).0, SipralStatus::UnsupportedVersion);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The size is checked before the handle is even looked up: a stack that
    /// was never created and a config too short to be any version of this one
    /// both fail, and the size is the one this answers with.
    #[test]
    fn an_account_config_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut config = account_config();
        config.size = crate::versioned::min_size::ACCOUNT_CONFIG - 1;
        assert_eq!(
            add(SIPRAL_HANDLE_NONE, &config).0,
            SipralStatus::UnsupportedVersion
        );
    }

    fn header_of(name: &'static str, value: &'static str) -> crate::header::SipralHeader {
        let (name, name_len) = text(name);
        let (value, value_len) = text(value);
        crate::header::SipralHeader {
            name,
            name_len,
            value,
            value_len,
        }
    }

    #[test]
    fn fields_an_account_is_given_go_on_its_register() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let line = [header_of("X-Line", "3")];
        let mut config = account_config();
        config.headers = line.as_ptr();
        config.headers_len = line.len();
        let (status, account) = add(handle, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 1_000);
        let out = drain(handle);
        let register = out.first().expect("a REGISTER");
        assert!(register.starts_with(b"REGISTER "));
        let wire = String::from_utf8_lossy(register);
        assert!(wire.contains("\r\nX-Line: 3\r\n"), "{wire}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_field_the_stack_writes_on_a_register_is_refused_where_it_is_set() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let expiring = [header_of("X-Line", "3"), header_of("Expires", "60")];
        let mut config = account_config();
        config.headers = expiring.as_ptr();
        config.headers_len = expiring.len();
        let (status, account) = add(handle, &config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(account, SIPRAL_HANDLE_NONE);
        let message = last_error_text();
        assert!(
            message.contains("headers[1]") && message.contains("Expires"),
            "{message}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn fields_for_an_account_that_never_registers_are_refused_rather_than_never_sent() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let line = [header_of("X-Line", "3")];
        let mut config = trunk_config();
        config.headers = line.as_ptr();
        config.headers_len = line.len();
        let (status, account) = add(handle, &config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(account, SIPRAL_HANDLE_NONE);
        let message = last_error_text();
        assert!(message.contains("never sends one"), "{message}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn the_stacks_own_user_agent_is_not_written_twice_on_a_register() {
        let mut observed = Observed::default();
        let mut stack_config = config(record, &mut observed);
        (stack_config.user_agent, stack_config.user_agent_len) = text("Sipral-Test/1");
        let (status, handle) = create(&stack_config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let second = [header_of("User-Agent", "Somebody-Else/2")];
        let mut config = account_config();
        config.headers = second.as_ptr();
        config.headers_len = second.len();
        let (status, account) = add(handle, &config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(account, SIPRAL_HANDLE_NONE);
        assert!(
            last_error_text().contains("User-Agent"),
            "{}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
