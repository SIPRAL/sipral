// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Accounts: configured, registered, given up.
//!
//! An account is one identity, usually with one registrar; accounts in one
//! stack share nothing. Adding one sends nothing; [`sipral_account_register`]
//! starts the REGISTER, and the binding is then refreshed, retried and backed
//! off on its own. The application hears the state, not the transactions.
//!
//! An account with no registrar never registers: a trunk known by its source
//! address. Its state is `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`,
//! registering is refused, and its requests go to `registrar_address`, the
//! outbound proxy.
//!
//! The caller must supply the destination address (resolving is I/O), the
//! `Contact` (only the caller knows what the world sees), and the instance id
//! (RFC 5626 §4.1 wants one that survives a power cycle; nothing here stores).

use std::ffi::c_char;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use sipral::AccountSrtp;
use sipral_core::auth::Credentials;
use sipral_core::msg::{HeaderName, Uri};
use sipral_ua::{Account, CertificatePin, HeadersFor, Push};

use crate::abi::{Number, record};
use crate::call::ua_failed;
use crate::error::{Fail, entry, fail};
use crate::event::{SipralRegistrationState, registration_state};
use crate::handle::SipralHandle;
use crate::header::{SipralHeader, supplied};
use crate::identity::SipralSessionTimer;
use crate::media::{SipralSrtp, SipralToggle, media_failed, toggled};
use crate::security::{SipralAttestation, SipralStirVerification};
use crate::stack::{SipralTransport, StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{required_text, text};
use crate::versioned::{Versioned, read_versioned};

record! {
    /// What an account is configured with. Set `size` to
    /// `sizeof(sipral_account_config_t)` and zero the rest first.
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
        /// A `registrar_len` of zero makes a trunk that never registers: its
        /// state stays `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, and
        /// `sipral_account_register` refuses it.
        pub registrar: *const c_char,
        /// How many bytes of it.
        pub registrar_len: usize,
        /// Where this endpoint can be reached, as it goes in `Contact`.
        pub contact: *const c_char,
        /// How many bytes of it.
        pub contact_len: usize,
        /// Where this account's requests go, as `host:port`: the registrar, or
        /// the outbound proxy for an account with no registrar. Calls without
        /// a destination go here too. Required unless `server_uri` is given;
        /// an address, not a name.
        pub registrar_address: *const c_char,
        /// How many bytes of it.
        pub registrar_address_len: usize,
        /// The display name that goes in `From`, or null for none.
        pub display_name: *const c_char,
        /// How many bytes of it.
        pub display_name_len: usize,
        /// The user name to answer a challenge with, or null for none.
        pub auth_user: *const c_char,
        /// How many bytes of it.
        pub auth_user_len: usize,
        /// The password that goes with it, copied.
        pub auth_password: *const c_char,
        /// How many bytes of it.
        pub auth_password_len: usize,
        /// The `+sip.instance` URN of RFC 5626 §4.1, or null for none.
        pub instance_id: *const c_char,
        /// How many bytes of it.
        pub instance_id_len: usize,
        /// How long a binding to ask for, or zero for an hour.
        ///
        /// Above 2³²−1 is refused (§20.19 `delta-seconds`). The registrar's
        /// grant wins, and is read back in
        /// `sipral_registration_event_t::expires_ms`.
        pub expires_seconds: u64,
        /// Header fields for every REGISTER of this account, in order, or null.
        ///
        /// Checked on add as `sipral_call_config_t::headers` is: `Expires` is
        /// the stack's (`expires_seconds`), `Supported` the application's (for
        /// GRUU). Refused for an account with no registrar.
        pub headers: *const SipralHeader,
        /// How many elements `headers` has.
        pub headers_len: usize,
        /// The transport for this account's REGISTER and requests:
        /// [`SIPRAL_TRANSPORT_MAIN`](crate::transport::SIPRAL_TRANSPORT_MAIN)
        /// for zero, or a number
        /// [`sipral_stack_transport_bind`](crate::transport::sipral_stack_transport_bind)
        /// has bound. An unbound number is `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub transport: u32,
        /// The push service to be woken through, by registered name: `apns`,
        /// `fcm`, `webpush` (RFC 8599 §4.1.1). Null for no push.
        ///
        /// The push parameters go only on this account's REGISTER `Contact`
        /// (§4.1): on an INVITE `pn-prid` would let the far end wake this
        /// device at will. De-registration leaves the identifier out (§4.1.2).
        pub push_provider: *const c_char,
        /// How many bytes of it.
        pub push_provider_len: usize,
        /// The device token the service issued. Required with
        /// `push_provider`, and refused without it. Percent-escaped where SIP
        /// needs it (§8.7): APNs tokens carry `=`, Web Push ids are URLs.
        pub push_prid: *const c_char,
        /// How many bytes of it.
        pub push_prid_len: usize,
        /// The extra value a service needs: the bundle for Apple, the sender
        /// for Firebase. Optional; §4.1.1 lets the service decide.
        pub push_param: *const c_char,
        /// How many bytes of it.
        pub push_param_len: usize,
        /// Nonzero when this device can refresh its binding without a push,
        /// declared with `+sip.pnsreg` (§4.1.4). Only the application knows:
        /// a suspended process runs no timer, and a false claim stops the
        /// registrar's wake-ups.
        pub push_wakes_itself: u32,
        /// Where end-of-call quality reports go (RFC 6035 over PUBLISH, RFC
        /// 3903), or null for none.
        pub quality_report_uri: *const c_char,
        /// How many bytes of it.
        pub quality_report_uri_len: usize,
        /// A [`SipralSessionTimer`]: how this account's calls ask for a
        /// session timer (RFC 4028). Zero is the default, thirty minutes.
        pub session_timer: Number<SipralSessionTimer>,
        /// The interval to ask for under `SIPRAL_SESSION_TIMER_INTERVAL`, in
        /// seconds: at least 90, RFC 4028 §5's floor. Read for nothing else.
        pub session_interval_seconds: u64,
        /// `SIPRAL_PRIVACY_*` bits: place every call anonymously (RFC 3323).
        /// `From` becomes `"Anonymous" <sip:anonymous@anonymous.invalid>`,
        /// `Privacy` carries the bits, and `P-Asserted-Identity` goes only to
        /// a peer in `trusted_peers`. Zero asks for none.
        pub privacy: u32,
        /// Trusted peers (RFC 3325's trust domain), comma-separated IP
        /// addresses. Only their asserted identity is read
        /// (`sipral_call_event_t::asserted_uri`). Once any are named, calls to
        /// other peers carry no `P-Asserted-Identity` or `P-Preferred-Identity`.
        /// Null trusts nobody.
        pub trusted_peers: *const c_char,
        /// How many bytes of it.
        pub trusted_peers_len: usize,
        /// A `SipralSrtp` over the stack's `srtp`, or zero for the stack's.
        /// A call may be stricter, never looser
        /// (`SIPRAL_STATUS_SECURITY_POLICY`); an INVITE it cannot meet gets
        /// 488.
        pub srtp: Number<SipralSrtp>,
        /// The SRTP suites, most preferred first, comma-separated, as RFC 4568
        /// §6.2 and RFC 7714 §14.2 name them:
        /// `AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80`. Used for SDES and the
        /// DTLS-SRTP profiles; GCM only if named. Null for this build's own.
        /// Each line goes in the INVITE: more than two or three need a stream
        /// transport.
        pub srtp_suites: *const c_char,
        /// How many bytes of it.
        pub srtp_suites_len: usize,
        /// A `SipralStirVerification`: what to do with received `Identity`
        /// fields (RFC 8224 §6.2). Zero reports, once `sipral_stack_stir` gave
        /// trust anchors.
        pub stir_verification: Number<SipralStirVerification>,
        /// The P-256 key this account signs calls with (RFC 8224 §6.1): the
        /// bare 32-octet scalar, or `EC PRIVATE KEY` / `PRIVATE KEY` in DER or
        /// PEM. Null signs nothing. Needs the wall clock from
        /// `sipral_stack_stir`, else `SIPRAL_STATUS_WRONG_STATE`.
        pub stir_key: *const u8,
        /// How many bytes of it.
        pub stir_key_len: usize,
        /// Where the chain for `stir_key` is published (`x5u` and `info`).
        /// Required with `stir_key`, and only with it.
        pub stir_certificate_url: *const c_char,
        /// How many bytes of it.
        pub stir_certificate_url_len: usize,
        /// The number this account signs as, canonicalised by RFC 8224 §8.3's
        /// first step, or null for `aor`'s user part.
        pub stir_orig: *const c_char,
        /// How many bytes of it.
        pub stir_orig_len: usize,
        /// The origination id every signed call claims (RFC 8588 §5), a UUID,
        /// or null for one the stack draws.
        pub stir_origid: *const c_char,
        /// How many bytes of it.
        pub stir_origid_len: usize,
        /// A `SipralAttestation` (RFC 8588 §4); zero is full, `A`.
        pub stir_attestation: Number<SipralAttestation>,
        /// A `SipralToggle`: whether an encrypted call may be recorded
        /// (`sipral_call_record_to`) in the clear. Off by default: copies go as
        /// SRTP with SDES keys (RFC 4568), and a stream the server refuses
        /// that way gets nothing (RFC 7866 §12.2).
        ///
        /// Sixty-four bits wide so it starts past an older layout's trailing
        /// padding, which old callers may leave unwritten.
        pub recording_in_clear: u64,
        /// How often, in milliseconds, to keep the flow to the registrar (or
        /// outbound proxy) open regardless of STUN; zero defers to
        /// `sipral_stack_config_t::registrar_keepalive`.
        ///
        /// For a NAT that forgets UDP flows before the REGISTER refresh. UDP
        /// sends a lone double CRLF (RFC 3261 §7.5); TCP and TLS ping at this
        /// interval (RFC 5626 §4.4.1). Jittered to 80-100%. From 1 000 to
        /// 120 000, else `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub keepalive_ms: u64,
        /// The server as a URI whose host RFC 3263 locates
        /// (`sip:pbx.example.com`, `sips:example.com:5061`), in place of
        /// `registrar_address`: exactly one is given. The registrar, or the
        /// outbound proxy for an account that does not register.
        ///
        /// Lookups go to the application's resolver via
        /// `SIPRAL_EVENT_KIND_LOOKUP_WANTED` and `sipral_account_looked_up`;
        /// ordering, SRV ranking and fallback are the stack's. The first
        /// REGISTER waits for the first answer; a call before it with no
        /// destination is `SIPRAL_STATUS_WRONG_STATE`. An out-of-dialog
        /// request that times out, fails its transport or gets 503 moves to
        /// the next address (§4.3). The name is looked up again when the TTL
        /// runs out or recovery asks. A port skips SRV; a numeric host asks
        /// nothing.
        pub server_uri: *const c_char,
        /// How many bytes of it.
        pub server_uri_len: usize,
        /// The SHA-256 fingerprint of the one TLS certificate this account
        /// trusts, for a self-signed PBX: 64 hex digits, any case, colons and
        /// spaces ignored, bare or after `sha256 Fingerprint=` (openssl),
        /// `sha-256 ` (RFC 8122) or `SHA256=`, any case. Anything else is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`. Null for none.
        ///
        /// The application's verifier asks `sipral_account_check_certificate`;
        /// with a pin the fingerprint is the whole verdict (`docs/22-tls.md`).
        pub tls_pin_sha256: *const c_char,
        /// How many bytes of it.
        pub tls_pin_sha256_len: usize,
        /// A `SipralToggle`: ask NAPTR before SRV for `server_uri`'s domain
        /// (RFC 3263 §4.1). Off by default; refused without `server_uri`.
        pub server_naptr: Number<SipralToggle>,
        /// Zero.
        pub reserved: u32,
        /// A [`SipralTransport`]: the protocol of a connection of this
        /// account's own to its server, which the application opens, or zero.
        ///
        /// For an account on TCP or TLS beside one on the stack's UDP, in one
        /// stack. With TCP, TLS, WS or WSS the stack raises
        /// `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` with the protocol and address
        /// (`request_bytes` and `limit_bytes` zero); the account then uses
        /// whatever transport of that protocol the application binds there with
        /// `sipral_stack_transport_bind`, including one bound before. Until
        /// then the REGISTER waits; after ten seconds it fails as unreachable
        /// and the retry asks again. A non-registering account asks on add;
        /// any account asks again when the connection fails or closes. A call
        /// before the bind is `SIPRAL_STATUS_TRANSPORT_DOWN`. In-call requests
        /// keep their INVITE's connection, and requests arriving on it match
        /// this account first. `SIPRAL_TRANSPORT_UDP` only describes
        /// `transport`.
        pub stream_protocol: Number<SipralTransport>,
        /// Zero.
        pub reserved_35: u32,
        /// The realms the password answers, one per line (a realm may hold a
        /// comma, never a line break), or null for the default.
        ///
        /// The password answers only the account's own server (RFC 3261
        /// §22.1). By default that is the realms of the server's first
        /// challenge and of every REGISTER challenge; a proxy relaying a far
        /// end's 401 gets nothing, and `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED`
        /// says so. When calls are challenged under a realm REGISTERs never
        /// see (an SBC or proxy with its own realm), name all of them here.
        /// Empty lines are skipped; realms compare exactly (§22.1).
        pub realms: *const c_char,
        /// How many bytes of it.
        pub realms_len: usize,
    }
}

/// The realms `config` names, one per line, or `None` by default. Any control
/// byte but the line feed, or a list with no realm, is refused.
///
/// # Safety
///
/// `config.realms` must be readable for `config.realms_len` bytes.
unsafe fn realms_of(config: &SipralAccountConfig) -> Result<Option<Vec<&str>>, Fail> {
    let raw =
        unsafe { crate::text::bytes(config.realms.cast::<u8>(), config.realms_len, "realms") }?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let Ok(text) = std::str::from_utf8(raw) else {
        return Err(fail(SipralStatus::InvalidArgument, "realms is not UTF-8"));
    };
    let mut named = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.bytes().any(crate::text::is_field_ending) {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "realms carries a control byte other than the line feed between two realms",
            ));
        }
        if !line.is_empty() {
            named.push(line);
        }
    }
    if named.is_empty() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "realms names no realm: null, for the default, is how to name none",
        ));
    }
    Ok(Some(named))
}

// Safety: plain data, and all-zero is valid: every pointer null beside a zero
// length.
unsafe impl Versioned for SipralAccountConfig {
    const NAME: &'static str = "sipral_account_config";
    const PIN: crate::versioned::Pin =
        crate::versioned::pin!(SipralAccountConfig, recording_in_clear);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// Parse a caller's URI, naming the field when it fails.
fn uri(supplied: &str, name: &'static str) -> Result<Uri, Fail> {
    Uri::parse_str(supplied).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {supplied:?}, which is not a URI: {error}"),
        )
    })
}

/// How long a binding to ask for, inside what an `Expires` can say (§20.19:
/// up to 2³²−1). Refused here, not later by the registrar.
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

/// Apply the session timer (RFC 4028), privacy (RFC 3323) and trusted peers
/// (RFC 3325).
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

/// The push service an account asks to be woken through, if any.
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
        // a provider without a device is a binding nothing ever wakes
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

/// Where requests go: `registrar_address`, or `server_uri` for RFC 3263 to
/// locate; exactly one.
///
/// # Safety
///
/// `config.registrar_address` and `config.server_uri` must be readable for
/// the lengths beside them.
unsafe fn destination_of(
    config: &SipralAccountConfig,
    registering: bool,
) -> Result<(SocketAddr, Option<Uri>), Fail> {
    let remote = unsafe {
        text(
            config.registrar_address,
            config.registrar_address_len,
            "registrar_address",
        )
    }?;
    let server = unsafe { text(config.server_uri, config.server_uri_len, "server_uri") }?;
    match (remote, server) {
        (Some(_), Some(_)) => Err(fail(
            SipralStatus::InvalidArgument,
            "server_uri and registrar_address both name where this account's requests go: \
             give the address, or the URI whose server is located, not both",
        )),
        (Some(remote), None) => Ok((address(remote, "registrar_address")?, None)),
        // located: the first answer gives the address, nothing goes before it
        (None, Some(server)) => Ok((
            SocketAddr::from(([0, 0, 0, 0], 0)),
            Some(uri(server, "server_uri")?),
        )),
        // a trunk's caller left the registrar out on purpose: explain why the
        // address is still needed
        (None, None) => Err(fail(
            SipralStatus::InvalidArgument,
            if registering {
                "registrar_address or server_uri is required and neither was given"
            } else {
                "registrar_address or server_uri is required and neither was given: with \
                 registrar_len zero the account never registers, and registrar_address is the \
                 outbound proxy every request it places is sent to"
            },
        )),
    }
}

/// How an account reaches its server: RFC 3263 location (NAPTR when asked),
/// its own keep-alive, and a pinned TLS certificate.
///
/// # Safety
///
/// `config.tls_pin_sha256` must be readable for the length beside it.
unsafe fn with_reach(
    mut account: Account,
    config: &SipralAccountConfig,
    server: Option<Uri>,
) -> Result<Account, Fail> {
    let naptr = toggled(config.server_naptr, "server_naptr", false)?;
    match server {
        Some(server) => {
            account = account.locate(server);
            if naptr {
                account = account.naptr();
            }
        }
        None if naptr => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "server_naptr asks how server_uri is located, and no server_uri was given",
            ));
        }
        None => {}
    }
    if config.keepalive_ms != 0 {
        account = account
            .keepalive(Duration::from_millis(config.keepalive_ms))
            .map_err(|error| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("keepalive_ms: {error}"),
                )
            })?;
    }
    let pin = unsafe {
        text(
            config.tls_pin_sha256,
            config.tls_pin_sha256_len,
            "tls_pin_sha256",
        )
    }?;
    if let Some(pin) = pin {
        let pin = CertificatePin::parse(pin).map_err(|error| {
            fail(
                SipralStatus::InvalidArgument,
                format!("tls_pin_sha256 is {pin:?}: {error}"),
            )
        })?;
        account = account.tls_pin(pin);
    }
    Ok(account)
}

/// The password, held to [`text`]'s rules (UTF-8, one line) but refused
/// without naming the offending offset: an error that may be logged must not
/// describe a secret. The TURN password is read the same way (`crate::nat`).
///
/// # Safety
///
/// `config.auth_password` must be readable for `config.auth_password_len`
/// bytes, or be null with a length of zero.
unsafe fn password_of(config: &SipralAccountConfig) -> Result<Option<&str>, Fail> {
    let raw = unsafe {
        crate::text::bytes(
            config.auth_password.cast::<u8>(),
            config.auth_password_len,
            "auth_password",
        )
    }?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    match std::str::from_utf8(raw) {
        Ok(password) if !password.bytes().any(crate::text::is_field_ending) => Ok(Some(password)),
        _ => Err(fail(
            SipralStatus::InvalidArgument,
            "auth_password is not usable text: it must be UTF-8 on one line",
        )),
    }
}

/// Turn what crossed the boundary into an account, or say what was wrong.
///
/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn account_from(state: &StackState, config: &SipralAccountConfig) -> Result<Account, Fail> {
    let aor = unsafe { required_text(config.aor, config.aor_len, "aor") }?;
    let registrar = unsafe { text(config.registrar, config.registrar_len, "registrar") }?;
    let contact = unsafe { required_text(config.contact, config.contact_len, "contact") }?;
    let (remote, server) = unsafe { destination_of(config, registrar.is_some()) }?;
    let display = unsafe { text(config.display_name, config.display_name_len, "display_name") }?;
    let user = unsafe { text(config.auth_user, config.auth_user_len, "auth_user") }?;
    let password = unsafe { password_of(config) }?;
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
    // refused rather than accepted and never sent
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
    let transport = crate::transport::named(state, config.transport)?;
    let mut account = match registrar {
        Some(registrar) => Account::new(aor, registrar, contact, transport, remote),
        None => Account::unregistered(aor, contact, transport, remote),
    };
    if config.stream_protocol != 0 {
        let protocol = crate::stack::transport_of(config.stream_protocol)
            .map_err(|_| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "stream_protocol is {}, which is not a SIPRAL_TRANSPORT",
                        config.stream_protocol
                    ),
                )
            })?
            .protocol();
        account = account.on_stream(protocol);
    }
    account = unsafe { with_reach(account, config, server) }?;
    if let Some(named) = unsafe { realms_of(config) }? {
        account = account.realms(&named);
    }
    if let Some(display) = display {
        account = account.display_name(display);
    }
    match (user, password) {
        (Some(user), Some(password)) => {
            account = account.credentials(Credentials::new(user, password));
        }
        (None, None) => {}
        // half a credential would silently stop answering challenges, which
        // looks like a wrong password
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
    /// Configure an account and write its handle to `out_account`. Nothing is
    /// sent. It lives until [`sipral_account_remove`] or the stack's end.
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
        // read before locking the stack, so an unknown value builds nothing
        let srtp = AccountSrtp {
            policy: crate::media::srtp_policy(config.srtp, "srtp")?,
            suites: crate::security::srtp_suites(unsafe {
                text(config.srtp_suites, config.srtp_suites_len, "srtp_suites")
            }?)?,
            recording_in_clear: crate::media::toggled(
                u32::try_from(config.recording_in_clear).unwrap_or(u32::MAX),
                "recording_in_clear",
                false,
            )?,
            // no C switch: the stack's default, SDES on any transport
            sdes_signalling: None,
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
            // behind a known NAT the account starts on the public address;
            // nothing is sent, since it has not registered
            let now = state.last_instant();
            crate::nat::Nat::contacts_changed(state, now);
            Ok(handle)
        })?;
        unsafe { out_account.write(handle) };
        Ok(())
    }
}

entry! {
    /// Forget an account and everything scheduled for it. Nothing is sent: its
    /// registrar may be unreachable. Call [`sipral_account_unregister`] first
    /// to give the binding up.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_account_remove(stack: SipralHandle, account: SipralHandle) {
        with_stack(stack, |state| {
            let id = state.accounts.remove(account).map_err(handle_failed)?;
            state.agent.remove_account(id);
            // the engine's default forgets the account's policy
            let _ = state.engine.set_account_srtp(id, AccountSrtp::default());
            Ok(())
        })
    }
}

entry! {
    /// Register, and keep the binding alive until told otherwise.
    ///
    /// Refreshes, credential retries and back-off happen on their own until
    /// [`sipral_account_unregister`] or a refusal retrying cannot fix. Each
    /// step arrives as `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`. An account
    /// with no registrar gets `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent.
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
    /// Only this device's binding: `Contact: *` would remove every binding of
    /// the address of record. An account with no registrar is refused as
    /// `sipral_account_register` refuses it.
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
    /// Where an account's registration is, as a `SipralRegistrationState`;
    /// always `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` with no registrar.
    ///
    /// # Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    fn sipral_account_registration_state(
        stack: SipralHandle,
        account: SipralHandle,
        out_state: *mut Number<SipralRegistrationState>,
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

entry! {
    /// Give an account the OAuth 2.0 access token its server asked for
    /// (RFC 8898), replacing any it had. A `token_len` of zero removes it; a
    /// password stays.
    ///
    /// Answers `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, or renews ahead of expiry.
    /// From the next request, a `Bearer` challenge from the account's own
    /// server (and every request its cached challenge covers) gets
    /// `Authorization: Bearer <token>` (RFC 6750 §2.1); with `Digest` and
    /// `Bearer` offered for one realm, the token answers. A refused token is
    /// never resent. Nothing is sent now; a registration that failed for want
    /// of a token restarts with `sipral_account_register`.
    ///
    /// The application fetches tokens. The token is copied, kept out of logs
    /// and diagnostics, and wiped when replaced. A token that is not RFC 6750
    /// §2.1's `b64token` is `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing changed,
    /// the error not describing it.
    ///
    /// # Safety
    ///
    /// `token` must be readable for `token_len` bytes, or be null with a
    /// length of zero.
    fn sipral_account_set_access_token(
        stack: SipralHandle,
        account: SipralHandle,
        token: *const c_char,
        token_len: usize,
    ) {
        let raw = unsafe { crate::text::bytes(token.cast::<u8>(), token_len, "token") }?;
        let token = match raw {
            None => None,
            Some(raw) => match std::str::from_utf8(raw) {
                Ok(token) if sipral_core::auth::is_access_token(token) => Some(token),
                _ => {
                    return Err(fail(
                        SipralStatus::InvalidArgument,
                        "token is not an access token: RFC 6750 section 2.1 allows letters, \
                         digits, - . _ ~ + / and trailing = padding",
                    ));
                }
            },
        };
        with_stack(stack, |state| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            state
                .agent
                .set_access_token(id, token)
                .map_err(|error| ua_failed(&error))
        })
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
        }
    }

    /// A trunk: no registrar, the address is its outbound proxy.
    fn trunk_config() -> SipralAccountConfig {
        SipralAccountConfig {
            registrar: ptr::null(),
            registrar_len: 0,
            ..account_config()
        }
    }

    /// Everything queued to write, with destinations, through the C ABI.
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
        // own tags, so both stacks start at the same generation regardless of
        // other tests
        static TAGS: StackTags = StackTags::new();
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack_on(&TAGS, &mut first_observed);
        let second = stack_on(&TAGS, &mut second_observed);
        let (_, foreign) = add(first, &account_config());
        let (_, own) = add(second, &account_config());
        // the handles differ only in the stack they carry
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

    /// An account keep-alive goes to its proxy at its interval without STUN,
    /// and not at all unless asked.
    #[test]
    fn an_account_keepalive_goes_to_its_proxy_at_its_own_interval() {
        let crlf = |out: &[(Vec<u8>, String)]| {
            out.iter()
                .filter(|(bytes, to)| bytes == b"\r\n\r\n" && to == ADDRESS)
                .count()
        };
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (status, _) = add(
            handle,
            &SipralAccountConfig {
                keepalive_ms: 1_000,
                ..trunk_config()
            },
        );
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        poll(handle, 0);
        let _ = written(handle);
        poll(handle, 1_000);
        assert_eq!(crlf(&written(handle)), 1, "one at the interval");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let (status, _) = add(handle, &trunk_config());
        assert_eq!(status, SipralStatus::Ok);
        poll(handle, 0);
        poll(handle, 1_000);
        assert_eq!(crlf(&written(handle)), 0, "none unless asked for");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        for millis in [999, 120_001] {
            let (status, _) = add(
                handle,
                &SipralAccountConfig {
                    keepalive_ms: millis,
                    ..trunk_config()
                },
            );
            assert_eq!(status, SipralStatus::InvalidArgument, "{millis}");
            assert!(
                last_error_text().contains("keepalive_ms"),
                "{}",
                last_error_text()
            );
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A loopback `Contact` toward another machine is refused with its own
    /// status, nothing sent, for a REGISTER and a trunk call.
    #[test]
    fn a_loopback_contact_toward_another_machine_is_refused_as_unreachable() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        (config.contact, config.contact_len) = text("sip:alice@127.0.0.1:5060");
        let (status, account) = add(handle, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_account_register(handle, account, 1_000) },
            SipralStatus::UnreachableAddress
        );
        let said = last_error_text();
        assert!(
            said.contains("127.0.0.1") && said.contains("203.0.113.5"),
            "{said}"
        );
        assert!(drain(handle).is_empty(), "nothing went");

        let mut trunk = trunk_config();
        (trunk.contact, trunk.contact_len) = text("sip:alice@127.0.0.1:5060");
        let (status, account) = add(handle, &trunk);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let call = call_config();
        let mut placed = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_place(handle, account, ptr::from_ref(&call), &raw mut placed, 0) },
            SipralStatus::UnreachableAddress
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

    /// A bad password is refused without the error saying where or what.
    #[test]
    fn a_password_refused_is_refused_without_describing_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        for password in [&b"hunte\x01r2"[..], &b"hunte\xffr2"[..]] {
            let mut config = account_config();
            (config.auth_user, config.auth_user_len) = text("alice");
            config.auth_password = password.as_ptr().cast();
            config.auth_password_len = password.len();
            assert_eq!(add(handle, &config).0, SipralStatus::InvalidArgument);
            let said = last_error_text();
            assert!(said.contains("auth_password"), "{said}");
            assert!(!said.contains('5') && !said.contains("offset"), "{said}");
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// §20.19 bounds an `Expires` at 2³²−1 seconds; above is refused on add.
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

    /// Removing a binding with `Expires: 0` is §10.2.2, not §10.2.5. The
    /// needle is built at runtime so the test does not match itself.
    #[test]
    fn the_unregister_doc_cites_removing_bindings_not_the_clock() {
        // a Windows checkout adds CRs
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
        // one byte short of the oldest published length
        let mut config = account_config();
        config.size =
            <crate::account::SipralAccountConfig as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(add(handle, &config).0, SipralStatus::UnsupportedVersion);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The size is checked before the handle is looked up.
    #[test]
    fn an_account_config_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut config = account_config();
        config.size =
            <crate::account::SipralAccountConfig as crate::versioned::Versioned>::MIN_SIZE - 1;
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
