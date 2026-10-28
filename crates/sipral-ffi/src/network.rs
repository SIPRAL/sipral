// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Networking ready to use (ABI 1.6): the sockets, the TLS and RFC 3263's lookups run for a
//! stack by the library, for an application that would otherwise write them.
//!
//! Everything else in this ABI leaves the I/O to the caller (`crate::transport`). These entry
//! points hand it to `sipral-net` instead: the stack's UDP socket, a TCP or TLS connection for
//! every `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`, an answer for every
//! `SIPRAL_EVENT_KIND_LOOKUP_WANTED`, a UDP socket for each call's media. The events still reach
//! the application's callback, after the component has read them; `docs/26-network.md` has the
//! whole of it.
//!
//! # Registering over TLS, and a call, with no socket of the application's
//!
//! ```c
//! sipral_network_config_t net = { .size = sizeof net };       /* the platform's trust store */
//! char found[256], local[64];
//! sipral_network_locate(&net, "sips:example.com", 16, SIPRAL_TRANSPORT_TLS,
//!                       found, sizeof found, NULL);           /* RFC 3263: NAPTR, SRV, A */
//! sipral_advertised_address("0.0.0.0:0", 9, found, strcspn(found, ","), local, sizeof local, NULL);
//! /* bind_address = local, an account with server_uri "sips:example.com" and
//!    stream_protocol SIPRAL_TRANSPORT_TLS */
//! sipral_stack_create(&config, &stack);
//! sipral_network_start(stack, &net, now_ms());
//! sipral_account_add(stack, &line, &account);
//! sipral_account_register(stack, account, now_ms());
//! for (;;)
//!     sipral_network_run(stack, now_ms(), 20);   /* poll, write, wait, read, answer */
//! ```
//!
//! A call's media socket comes from [`sipral_network_media_open`], whose address goes in
//! `sipral_call_config_t::media_address`; once the call's media handle exists,
//! [`sipral_network_media_attach`] has the component read and write it, and
//! [`sipral_network_media_capture`] sends a frame of the microphone.
//!
//! On a stack with `SIPRAL_NAT_STUN` the component carries each media socket's STUN and TURN
//! too (ABI 1.9): it names the socket with `sipral_stack_nat_map`, sends what
//! `sipral_stack_poll_stun` queues and hands back what arrives, and opens the connection to the
//! TURN server that `SIPRAL_EVENT_KIND_TURN_STREAM` asks for over TCP or TLS, checked by the
//! `turn_*` members of `sipral_network_config_t`. The application waits for the socket's
//! `SIPRAL_EVENT_KIND_NAT_MAPPING`, and with a `turn_server` its `SIPRAL_EVENT_KIND_NAT_RELAY`,
//! before it places or answers a call on it.
//!
//! A build without the `network` feature has every entry point here and answers
//! `SIPRAL_STATUS_NOT_SUPPORTED`; `SIPRAL_FEATURE_NETWORK` says which build this is.

use std::ffi::c_char;

use crate::abi::{Number, codes, record};
use crate::error::entry;
#[cfg(not(feature = "network"))]
use crate::error::fail;
use crate::handle::SipralHandle;
use crate::pin::SipralDomainRules;
use crate::stack::SipralTransport;
#[cfg(not(feature = "network"))]
use crate::status::SipralStatus;
use crate::versioned::{Versioned, read_versioned};

#[cfg(feature = "network")]
mod driver;
#[cfg(all(test, feature = "network"))]
mod tests;

codes! {
    /// Which servers a TLS connection the component makes trusts. Names for
    /// `sipral_network_config_t::trust`; an account's `tls_pin_sha256` wins over it for the
    /// connections to that account's server.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralNetworkTrust: u32 {
        /// The authorities in the platform's trust store.
        Platform = 0,
        /// The platform's, and those in `authority_pem` beside them.
        PlatformAndAuthority = 1,
        /// Only those in `authority_pem`.
        OnlyAuthority = 2,
        /// Only the certificate whose SHA-256 fingerprint is `pin_sha256`; chain, name and
        /// dates are not checked (`docs/22-tls.md`).
        Pinned = 3,
    }
}

record! {
    /// How the networking component connects and resolves (ABI 1.6). Set `size` to
    /// `sizeof(sipral_network_config_t)` and zero the rest first: zero everywhere is the
    /// platform's trust store and resolver, and no client certificate.
    #[derive(Clone, Copy)]
    pub struct SipralNetworkConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// A [`SipralNetworkTrust`].
        pub trust: Number<SipralNetworkTrust>,
        /// Zero.
        pub reserved: u32,
        /// PEM certificates of the authorities trusted with
        /// `SIPRAL_NETWORK_TRUST_PLATFORM_AND_AUTHORITY` or `_ONLY_AUTHORITY`. Not
        /// NUL-terminated.
        pub authority_pem: *const c_char,
        /// How many bytes of it.
        pub authority_pem_len: usize,
        /// The fingerprint for `SIPRAL_NETWORK_TRUST_PINNED`, written as
        /// `sipral_account_config_t::tls_pin_sha256` is.
        pub pin_sha256: *const c_char,
        /// How many bytes of it.
        pub pin_sha256_len: usize,
        /// The client certificate presented when a server asks for one, leaf first, then any
        /// intermediates, as PEM; null for none.
        pub client_certificate_pem: *const c_char,
        /// How many bytes of it.
        pub client_certificate_pem_len: usize,
        /// Its private key as PEM (PKCS #8, SEC 1 or PKCS #1); required with the certificate.
        pub client_key_pem: *const c_char,
        /// How many bytes of it.
        pub client_key_pem_len: usize,
        /// The name servers to ask, comma-separated `host:port`; null for the system's
        /// resolver configuration.
        pub name_servers: *const c_char,
        /// How many bytes of it.
        pub name_servers_len: usize,
        /// The name every TLS server's certificate is checked against; null for the host of
        /// the account's `server_uri` (RFC 5922 section 7.3), else the address connected to.
        pub tls_server_name: *const c_char,
        /// How many bytes of it.
        pub tls_server_name_len: usize,
        /// How long connecting, and then a TLS handshake, may each take; zero for 8000.
        pub connect_timeout_ms: u32,
        /// Zero.
        pub reserved_end: u32,
        /// A [`SipralDomainRules`] (ABI 1.8): how a server's certificate is read for its name
        /// once its chain is trusted. Zero is the platform's rules with a `sip:` URI that names
        /// the domain accepted besides.
        pub domain_rules: Number<SipralDomainRules>,
        /// Zero.
        pub reserved_rules: u32,
        /// A [`SipralNetworkTrust`] for the TURN server a media socket reaches over TLS
        /// (`sipral_stack_config_t::turn_transport`, ABI 1.9); zero for the platform's. Its
        /// certificate is checked against `turn_server_name` as HTTPS checks a host's, not as
        /// a SIP domain's.
        pub turn_trust: Number<SipralNetworkTrust>,
        /// Zero.
        pub reserved_turn: u32,
        /// `authority_pem` for the TURN server.
        pub turn_authority_pem: *const c_char,
        /// How many bytes of it.
        pub turn_authority_pem_len: usize,
        /// `pin_sha256` for the TURN server.
        pub turn_pin_sha256: *const c_char,
        /// How many bytes of it.
        pub turn_pin_sha256_len: usize,
        /// The name the TURN server's certificate is checked against; null for the address
        /// `turn_server` names.
        pub turn_server_name: *const c_char,
        /// How many bytes of it.
        pub turn_server_name_len: usize,
        /// The client certificate presented when the TURN server asks for one, as
        /// `client_certificate_pem` is written; null for none.
        pub turn_client_certificate_pem: *const c_char,
        /// How many bytes of it.
        pub turn_client_certificate_pem_len: usize,
        /// Its private key, as `client_key_pem` is written; required with the certificate.
        pub turn_client_key_pem: *const c_char,
        /// How many bytes of it.
        pub turn_client_key_pem_len: usize,
    }
}

// Safety: integers and borrowed pointers with their lengths; all-zero is the default.
unsafe impl Versioned for SipralNetworkConfig {
    const NAME: &'static str = "sipral_network_config";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralNetworkConfig, reserved_end);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// What a build without the component answers.
#[cfg(not(feature = "network"))]
fn not_built() -> crate::error::Fail {
    fail(
        SipralStatus::NotSupported,
        "this library was built without the networking component (the `network` feature of \
         sipral-ffi); SIPRAL_FEATURE_NETWORK says so before a stack is made",
    )
}

/// What the stack's destruction leaves of its network: nothing.
pub(crate) fn forget(stack: SipralHandle) {
    #[cfg(feature = "network")]
    driver::forget(stack);
    #[cfg(not(feature = "network"))]
    let _ = stack;
}

entry! {
    /// Have the library run this stack's networking (ABI 1.6).
    ///
    /// From now on [`sipral_network_run`] does what the loop of `sipral_stack_poll`,
    /// `sipral_stack_poll_transmit` and `sipral_stack_receive_*` has the application do. The
    /// stack must have been created on `SIPRAL_TRANSPORT_UDP` with a `bind_address` that names
    /// an interface (`sipral_advertised_address` finds it), else `SIPRAL_STATUS_WRONG_STATE`:
    /// its socket is bound there now, at the port the system chooses when it named zero, and
    /// accounts on TCP or TLS reach their servers on connections of their own
    /// (`stream_protocol`), which are the component's too. Every
    /// `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` is answered with a connection bound under a number
    /// from 2^31 up, every `SIPRAL_EVENT_KIND_LOOKUP_WANTED` with the resolver's answer, and a
    /// connection that fails is reported with `sipral_stack_transport_failed_with`, its reason
    /// in `sipral_transport_failed_event_t::tls` as the bindings give it.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when it already runs; `SIPRAL_STATUS_INVALID_ARGUMENT` for a
    /// configuration that cannot be read, saying which member; `SIPRAL_STATUS_TRANSPORT_DOWN`
    /// when the socket cannot be bound or the resolver's configuration read;
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without the component.
    ///
    /// # Safety
    ///
    /// `config` must be null, for the defaults, or point at a `sipral_network_config_t` whose
    /// buffers are readable for their lengths.
    fn sipral_network_start(stack: SipralHandle, config: *const SipralNetworkConfig, now_ms: u64) {
        let config = if config.is_null() {
            None
        } else {
            Some(unsafe { read_versioned(config) }?)
        };
        #[cfg(feature = "network")]
        {
            unsafe { driver::start(stack, config.as_ref(), now_ms) }
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = (stack, config, now_ms);
            Err(not_built())
        }
    }
}

entry! {
    /// One turn of the loop the component runs for this stack (ABI 1.6): poll the stack, write
    /// what it queued, act on what it asked for, then wait up to `wait_ms` — less when a timer
    /// of the stack's is due sooner — for anything to arrive, hand it in, and poll and write
    /// again. The callback runs inside it, on this thread, as it does inside
    /// `sipral_stack_poll`, and may call any entry point here but this one.
    ///
    /// `now_ms` is the caller's monotonic clock, as everywhere else. Call it in a loop; nothing
    /// in the library calls it for the application. `SIPRAL_STATUS_WRONG_STATE` before
    /// [`sipral_network_start`], `SIPRAL_STATUS_BUSY` from inside its own callback.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_network_run(stack: SipralHandle, now_ms: u64, wait_ms: u32) {
        #[cfg(feature = "network")]
        {
            driver::run(stack, now_ms, wait_ms)
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = (stack, now_ms, wait_ms);
            Err(not_built())
        }
    }
}

entry! {
    /// Stop running this stack's networking (ABI 1.6): every socket and connection the
    /// component opened is closed, its media sockets with them, and the stack's events go to
    /// the callback alone again. The stack is told nothing; a stack about to be destroyed needs
    /// no stop, since `sipral_stack_destroy` does the same. `SIPRAL_STATUS_WRONG_STATE` when it
    /// was not running.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_network_stop(stack: SipralHandle) {
        #[cfg(feature = "network")]
        {
            driver::stop(stack)
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = stack;
            Err(not_built())
        }
    }
}

entry! {
    /// Where RFC 3263 finds `server_uri`'s server for `protocol`, before any stack exists
    /// (ABI 1.6): NAPTR when the domain publishes it, SRV, then A or AAAA, ranked as the stack
    /// ranks them, every address comma-separated `host:port` and NUL-terminated into `buffer`.
    ///
    /// For the address to name in `bind_address` and `Contact`, with
    /// `sipral_advertised_address` toward the first of them. `config` is the resolver's (null
    /// for the system's); this blocks for as long as the lookups take, ten seconds each at
    /// most. `SIPRAL_STATUS_UNREACHABLE_ADDRESS` when the DNS names no address,
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` with `out_needed` set when they do not fit.
    ///
    /// # Safety
    ///
    /// `config` must be null or point at a readable `sipral_network_config_t`, `server_uri`
    /// must be readable for `server_uri_len` bytes, `buffer` writable for `capacity` bytes or
    /// null with a capacity of zero, and `out_needed` null or pointing at one `size_t`.
    fn sipral_network_locate(
        config: *const SipralNetworkConfig,
        server_uri: *const c_char,
        server_uri_len: usize,
        protocol: Number<SipralTransport>,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        let config = if config.is_null() {
            None
        } else {
            Some(unsafe { read_versioned(config) }?)
        };
        #[cfg(feature = "network")]
        {
            unsafe {
                driver::locate(
                    config.as_ref(),
                    server_uri,
                    server_uri_len,
                    protocol,
                    buffer,
                    capacity,
                    out_needed,
                )
            }
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = (config, server_uri, server_uri_len, protocol, buffer, capacity, out_needed);
            Err(not_built())
        }
    }
}

entry! {
    /// Open a UDP socket for one call's media (ABI 1.6), on the address the stack advertises,
    /// at a port from its RTP range when it has one (the odd one above kept for RTCP), and
    /// write its `host:port`, NUL-terminated, into `buffer`, for
    /// `sipral_call_config_t::media_address` or an answer's.
    ///
    /// `capacity` must be at least `SIPRAL_ADDRESS_BYTES`, so that nothing is opened that
    /// could not be named: below it is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with `out_needed` set
    /// and nothing opened. `SIPRAL_STATUS_WRONG_STATE` before [`sipral_network_start`] or on a
    /// stack that advertises a wildcard address, `SIPRAL_STATUS_EXHAUSTED` when the range has
    /// no free pair.
    ///
    /// On a stack with `SIPRAL_NAT_STUN` the next [`sipral_network_run`] names the socket with
    /// `sipral_stack_nat_map` (ABI 1.9) and carries its STUN and TURN from then on, over UDP or
    /// on the TURN connection the component opens: place or answer the call on it once
    /// `SIPRAL_EVENT_KIND_NAT_MAPPING` about it has come, and with a `turn_server` its
    /// `SIPRAL_EVENT_KIND_NAT_RELAY` too, as the stack requires.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes and `out_needed` null or pointing at one
    /// `size_t`.
    fn sipral_network_media_open(
        stack: SipralHandle,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        #[cfg(feature = "network")]
        {
            unsafe { driver::media_open(stack, buffer, capacity, out_needed) }
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = (stack, buffer, capacity, out_needed);
            Err(not_built())
        }
    }
}

entry! {
    /// Give a call's media to the socket [`sipral_network_media_open`] opened at `address`
    /// (ABI 1.6), once `sipral_call_media` has minted its handle: from now on every packet that
    /// arrives there goes to `sipral_media_receive`, and what `sipral_media_poll_transmit`,
    /// `sipral_media_poll_rtcp` and the call's RTCP goodbye hand out leaves from it, inside
    /// [`sipral_network_run`], or on its TURN connection when the stack marks it so. Before,
    /// what arrives goes to `sipral_stack_receive_stun`, which keeps the STUN and TURN servers'
    /// answers and the far end's early checks for the call (ABI 1.9). The socket closes, and
    /// its port goes back, when the call ends.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an address the component has no socket at.
    ///
    /// # Safety
    ///
    /// `address` must be readable for `address_len` bytes.
    fn sipral_network_media_attach(
        stack: SipralHandle,
        address: *const c_char,
        address_len: usize,
        call: SipralHandle,
        media: SipralHandle,
    ) {
        let local = unsafe { crate::media::address(address, address_len, "address") }?;
        #[cfg(feature = "network")]
        {
            driver::media_attach(stack, local, call, media)
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = (stack, local, call, media);
            Err(not_built())
        }
    }
}

entry! {
    /// One frame of the microphone, encoded by `sipral_media_capture` and sent from the media
    /// socket the call's handle is attached to (ABI 1.6). The frame is as
    /// `sipral_media_capture` takes it, `sample_count` samples at the codec's rate; a frame
    /// with nothing to send, on hold, sends nothing and is `SIPRAL_STATUS_OK`.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a handle no socket is attached to.
    ///
    /// # Safety
    ///
    /// `samples` must be readable for `sample_count` samples.
    fn sipral_network_media_capture(
        stack: SipralHandle,
        media: SipralHandle,
        now_ms: u64,
        samples: *const i16,
        sample_count: usize,
    ) {
        #[cfg(feature = "network")]
        {
            unsafe { driver::media_capture(stack, media, now_ms, samples, sample_count) }
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = (stack, media, now_ms, samples, sample_count);
            Err(not_built())
        }
    }
}

entry! {
    /// Close the media socket at `address` (ABI 1.6), and give its port back to the stack's
    /// range. For a socket whose call never came to media; one whose call ended has closed
    /// already. A socket the stack's STUN client was told of is released at the next
    /// [`sipral_network_run`] with `sipral_stack_nat_unmap`, its relay given back from it with
    /// a Refresh of lifetime zero (RFC 8656 §8), and closed then (ABI 1.9).
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an address the component has no socket at.
    ///
    /// # Safety
    ///
    /// `address` must be readable for `address_len` bytes.
    fn sipral_network_media_close(stack: SipralHandle, address: *const c_char, address_len: usize) {
        let local = unsafe { crate::media::address(address, address_len, "address") }?;
        #[cfg(feature = "network")]
        {
            driver::media_close(stack, local)
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = (stack, local);
            Err(not_built())
        }
    }
}

#[cfg(all(test, not(feature = "network")))]
mod built_without {
    use super::{sipral_network_run, sipral_network_start};
    use crate::capabilities::{SIPRAL_FEATURE_NETWORK, SipralCapabilities, sipral_capabilities};
    use crate::error::last_error_text;
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, stack};
    use crate::status::SipralStatus;
    use std::ptr;

    #[test]
    fn a_build_without_the_component_says_so_before_and_when_asked() {
        let mut capabilities = SipralCapabilities {
            size: size_of::<SipralCapabilities>(),
            codec_count: 0,
            transports: 0,
            features: 0,
        };
        assert_eq!(
            unsafe { sipral_capabilities(&raw mut capabilities) },
            SipralStatus::Ok
        );
        assert_eq!(capabilities.features & SIPRAL_FEATURE_NETWORK, 0);

        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            unsafe { sipral_network_start(handle, ptr::null(), 0) },
            SipralStatus::NotSupported
        );
        assert!(last_error_text().contains("SIPRAL_FEATURE_NETWORK"));
        assert_eq!(
            unsafe { sipral_network_run(handle, 0, 0) },
            SipralStatus::NotSupported
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
