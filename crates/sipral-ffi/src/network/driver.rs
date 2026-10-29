// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The networking component's loop, behind the `network` feature.
//!
//! It is the loop `crate::transport` and every binding write, written once: it calls the same
//! entry points an application would — `sipral_stack_poll`, `sipral_stack_poll_transmit`,
//! `sipral_stack_receive_*`, `sipral_stack_transport_bind`,
//! `sipral_stack_transport_failed_with`, the media calls, and for a media socket's STUN and
//! TURN `sipral_stack_nat_map`, `sipral_stack_poll_stun`, `sipral_stack_receive_stun` and
//! `sipral_stack_turn_*` — so the stack cannot tell it from one, and reads the events it needs
//! through the stack's observer before the callback does. Sockets, connections and lookups are
//! `sipral-net`'s.

use std::collections::HashMap;
use std::ffi::c_char;
use std::net::SocketAddr;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sipral_core::endpoint::{
    AddressFamily, Query, RecordType, TransportErrorKind, TransportId, TransportProtocol,
};
use sipral_core::msg::Uri;
use sipral_core::pin::CertificatePin;
use sipral_net::{
    ClientCertificate, Failure, Happening, HostTrust, MediaSender, Network, NetworkConfig,
    Resolver, StreamSender, StreamTarget, TlsFailure, Trust,
};
use sipral_ua::StreamIdentity;

use super::SipralNetworkConfig;
use crate::diagnostics::copy_out;
use crate::error::{Fail, answered, fail};
use crate::event::{SipralEvent, SipralEventKind};
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::media::{
    SIPRAL_ADDRESS_BYTES, SIPRAL_MEDIA_PACKET_BYTES, SipralMediaPacket, sipral_media_capture,
    sipral_media_poll_rtcp, sipral_media_poll_transmit, sipral_media_receive,
    sipral_stack_poll_farewell,
};
use crate::nat::{
    SipralTurnStream, sipral_stack_nat_map, sipral_stack_nat_unmap, sipral_stack_poll_stun,
    sipral_stack_receive_stun, sipral_stack_turn_closed, sipral_stack_turn_connected,
    sipral_stack_turn_receive,
};
use crate::ports::{sipral_stack_rtp_port_release, sipral_stack_rtp_port_reserve};
use crate::stack::{
    Observer, SipralPollResult, SipralTransport, handle_failed, sipral_stack_poll, transport_of,
    with_stack, with_stack_at,
};
use crate::status::SipralStatus;
use crate::text::{bytes, required_text, text};
use crate::transport::{
    SIPRAL_MESSAGE_BYTES, SIPRAL_TRANSPORT_MAIN, SipralTransmit, SipralTransportFailure,
    identities_asked, sipral_stack_poll_transmit, sipral_stack_receive_datagram,
    sipral_stack_receive_stream, sipral_stack_stream_closed, sipral_stack_transport_bind,
    sipral_stack_transport_failed_with,
};

/// The first transport number the component binds its connections under; the ones below are
/// the application's to choose.
const FIRST_STREAM: u32 = 1 << 31;

/// The longest one turn waits when the stack has no timer due.
const IDLE: Duration = Duration::from_secs(1);

/// How long what must reach the stack waits for it while another thread is inside it.
const PATIENCE: Duration = Duration::from_millis(500);

/// What the observer noted for the component, during a poll.
enum Seen {
    Wanted {
        protocol: TransportProtocol,
        destination: SocketAddr,
        /// Asked for a request that outgrew a datagram (RFC 3261 §18.1.1), not for an
        /// account's own connection.
        outgrown: bool,
    },
    Lookup {
        account: SipralHandle,
        query: Query,
    },
    Failed {
        transport: u32,
    },
    Ended {
        call: SipralHandle,
    },
    /// A media socket's connection to the TURN server, to open or to close.
    Turn {
        open: bool,
        protocol: TransportProtocol,
        local: SocketAddr,
        server: SocketAddr,
    },
}

/// One connection the component opened, or is opening.
#[derive(Clone)]
struct Stream {
    protocol: TransportProtocol,
    destination: SocketAddr,
    bound: bool,
    /// What it is checked against, and so whose requests it carries.
    identity: StreamIdentity,
}

/// Where a media socket stands with the stack's STUN client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Naming {
    /// To be named with `sipral_stack_nat_map` at the next turn.
    Asking,
    /// Named.
    Named,
    /// Closed by the application while named: released with `sipral_stack_nat_unmap` at the
    /// next turn, then closed.
    Releasing,
    /// Not named: the stack asks no STUN server.
    Never,
}

/// One media socket the component opened.
#[derive(Clone, Copy)]
struct Media {
    /// The call and its media handle, once attached.
    attached: Option<(SipralHandle, SipralHandle)>,
    /// The port reserved from the stack's range, to give back if no call took it.
    reserved: Option<u32>,
    named: Naming,
}

/// One media socket's connection to the TURN server (RFC 8656 §3.1), under the transport number
/// it was opened as.
#[derive(Clone, Copy)]
struct Relay {
    /// The media socket: the connection's name in the calls that take one.
    local: SocketAddr,
    /// Whether it is open, and the stack told.
    open: bool,
}

/// What the loop keeps between turns, under one lock that a poll never holds.
struct Driver {
    network: Network,
    server_name: Option<String>,
    /// What the TURN server's certificate is checked against, and by.
    turn_name: Option<String>,
    turn_trust: HostTrust,
    /// The address the stack's socket is bound at.
    local: SocketAddr,
    next: u32,
    streams: HashMap<u32, Stream>,
    relays: HashMap<u32, Relay>,
    media: HashMap<SocketAddr, Media>,
    /// One message or packet at a time, written by the stack.
    out: Vec<u8>,
}

/// One stack's network.
struct Shared {
    stack: SipralHandle,
    notes: Arc<Mutex<Vec<Seen>>>,
    driver: Mutex<Driver>,
    running: AtomicBool,
    /// Each attached media handle's socket, under a lock of its own so that capturing a frame
    /// never waits for a turn of the loop.
    senders: Mutex<HashMap<SipralHandle, (SocketAddr, MediaSender)>>,
    /// Each open TURN connection, by its media socket, for the frames marked for it.
    relay_senders: Mutex<HashMap<SocketAddr, StreamSender>>,
}

/// Every stack the component runs.
static NETWORKS: Mutex<Vec<(SipralHandle, Arc<Shared>)>> = Mutex::new(Vec::new());

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // a panic caught at the boundary while held: the maps are whole between statements
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn find(stack: SipralHandle) -> Result<Arc<Shared>, Fail> {
    locked(&NETWORKS)
        .iter()
        .find(|(handle, _)| *handle == stack)
        .map(|(_, shared)| Arc::clone(shared))
        .ok_or_else(|| {
            fail(
                SipralStatus::WrongState,
                "the networking component is not running for this stack: \
                 sipral_network_start first",
            )
        })
}

/// The caller's clock moved on by what this turn has taken so far.
struct Clock {
    at_ms: u64,
    since: Instant,
}

impl Clock {
    fn new(at_ms: u64) -> Self {
        Self {
            at_ms,
            since: Instant::now(),
        }
    }

    fn now(&self) -> u64 {
        let elapsed = u64::try_from(self.since.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.at_ms.saturating_add(elapsed)
    }
}

/// How the configuration's members read, or which one does not.
struct Settings {
    network: NetworkConfig,
    server_name: Option<String>,
    turn_name: Option<String>,
    turn_trust: HostTrust,
}

/// The members that say which servers are trusted and what is presented to them: the SIP
/// servers' (`prefix` empty) or the TURN server's (`turn_`), read.
struct Trusting<'a> {
    prefix: &'static str,
    trust: u32,
    authority: Option<&'a [u8]>,
    pin: Option<&'a str>,
    certificate: Option<&'a [u8]>,
    key: Option<&'a [u8]>,
}

/// The configuration, read; zero everywhere, or none, is the defaults.
unsafe fn settings_of(config: Option<&SipralNetworkConfig>) -> Result<Settings, Fail> {
    let mut network = NetworkConfig::default();
    let Some(config) = config else {
        return Ok(Settings {
            network,
            server_name: None,
            turn_name: None,
            turn_trust: HostTrust::default(),
        });
    };
    let invalid = |message: String| fail(SipralStatus::InvalidArgument, message);
    // PEM is lines, so read as bytes rather than as a header's text
    let sip = Trusting {
        prefix: "",
        trust: config.trust,
        authority: unsafe {
            bytes(
                config.authority_pem.cast(),
                config.authority_pem_len,
                "authority_pem",
            )
        }?,
        pin: unsafe { text(config.pin_sha256, config.pin_sha256_len, "pin_sha256") }?,
        certificate: unsafe {
            bytes(
                config.client_certificate_pem.cast(),
                config.client_certificate_pem_len,
                "client_certificate_pem",
            )
        }?,
        key: unsafe {
            bytes(
                config.client_key_pem.cast(),
                config.client_key_pem_len,
                "client_key_pem",
            )
        }?,
    };
    network.trust = trust_of(&sip)?;
    network.client_certificate = presented(&sip)?;
    let turn = Trusting {
        prefix: "turn_",
        trust: config.turn_trust,
        authority: unsafe {
            bytes(
                config.turn_authority_pem.cast(),
                config.turn_authority_pem_len,
                "turn_authority_pem",
            )
        }?,
        pin: unsafe {
            text(
                config.turn_pin_sha256,
                config.turn_pin_sha256_len,
                "turn_pin_sha256",
            )
        }?,
        certificate: unsafe {
            bytes(
                config.turn_client_certificate_pem.cast(),
                config.turn_client_certificate_pem_len,
                "turn_client_certificate_pem",
            )
        }?,
        key: unsafe {
            bytes(
                config.turn_client_key_pem.cast(),
                config.turn_client_key_pem_len,
                "turn_client_key_pem",
            )
        }?,
    };
    let turn_trust = HostTrust::new(trust_of(&turn)?, presented(&turn)?);
    let turn_name = unsafe {
        text(
            config.turn_server_name,
            config.turn_server_name_len,
            "turn_server_name",
        )
    }?
    .map(str::to_owned);
    let mut settings = settings_rest(config, network, invalid)?;
    settings.turn_name = turn_name;
    settings.turn_trust = turn_trust;
    Ok(settings)
}

/// Which servers the members trust.
fn trust_of(members: &Trusting<'_>) -> Result<Trust, Fail> {
    let invalid = |message: String| fail(SipralStatus::InvalidArgument, message);
    let Trusting {
        prefix,
        authority,
        pin,
        ..
    } = *members;
    let roots = || match authority {
        None => Err(invalid(format!(
            "{prefix}authority_pem is required when {prefix}trust names an authority"
        ))),
        Some(pem) => Trust::authorities_from_pem(pem)
            .map_err(|error| invalid(format!("{prefix}authority_pem: {error}"))),
    };
    let trust = match members.trust {
        0 => Trust::Platform,
        1 => Trust::PlatformAnd(roots()?),
        2 => Trust::Only(roots()?),
        3 => {
            let Some(pin) = pin else {
                return Err(invalid(format!(
                    "{prefix}pin_sha256 is required with SIPRAL_NETWORK_TRUST_PINNED"
                )));
            };
            Trust::Pinned(
                CertificatePin::parse(pin)
                    .map_err(|error| invalid(format!("{prefix}pin_sha256 is {pin:?}: {error}")))?,
            )
        }
        other => {
            return Err(invalid(format!(
                "{prefix}trust is {other}, and a trust is 0 for the platform's, 1 for an \
                 authority beside it, 2 for that authority alone or 3 for a pinned certificate"
            )));
        }
    };
    if members.trust != 3 && pin.is_some() {
        let own = if prefix.is_empty() {
            ": an account's own pin is tls_pin_sha256"
        } else {
            ""
        };
        return Err(invalid(format!(
            "{prefix}pin_sha256 is given and {prefix}trust is not SIPRAL_NETWORK_TRUST_PINNED{own}"
        )));
    }
    if matches!(members.trust, 0 | 3) && authority.is_some() {
        return Err(invalid(format!(
            "{prefix}authority_pem is given and {prefix}trust names no authority"
        )));
    }
    Ok(trust)
}

/// The client certificate the members present, if any.
fn presented(members: &Trusting<'_>) -> Result<Option<ClientCertificate>, Fail> {
    let prefix = members.prefix;
    match (members.certificate, members.key) {
        (None, None) => Ok(None),
        (Some(certificate), Some(key)) => ClientCertificate::from_pem(certificate, key)
            .map(Some)
            .map_err(|error| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("{prefix}client_certificate_pem: {error}"),
                )
            }),
        _ => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "a client certificate needs {prefix}client_certificate_pem and \
                 {prefix}client_key_pem both"
            ),
        )),
    }
}

/// The resolver, the patience and the rules, after the trust.
fn settings_rest(
    config: &SipralNetworkConfig,
    mut network: NetworkConfig,
    invalid: impl Fn(String) -> Fail,
) -> Result<Settings, Fail> {
    let servers = unsafe { text(config.name_servers, config.name_servers_len, "name_servers") }?;
    if let Some(servers) = servers {
        for (index, written) in servers.split(',').map(str::trim).enumerate() {
            let server = written.parse::<SocketAddr>().map_err(|_| {
                invalid(format!(
                    "name_servers names {written:?} at position {index}, which is not a host:port"
                ))
            })?;
            network.name_servers.push(server);
        }
    }
    if config.connect_timeout_ms != 0 {
        network.connect_timeout = Duration::from_millis(u64::from(config.connect_timeout_ms));
    }
    network.domain_rules = crate::pin::domain_rules(config.domain_rules).ok_or_else(|| {
        invalid(format!(
            "domain_rules is {}, and the rules are 0 for the platform's with a sip: URI accepted \
             besides, or 1 for RFC 5922 alone",
            config.domain_rules
        ))
    })?;
    let server_name = unsafe {
        text(
            config.tls_server_name,
            config.tls_server_name_len,
            "tls_server_name",
        )
    }?
    .map(str::to_owned);
    Ok(Settings {
        network,
        server_name,
        turn_name: None,
        turn_trust: HostTrust::default(),
    })
}

/// What the component needs from one event.
fn seen(event: &SipralEvent) -> Option<Seen> {
    match event.kind {
        SipralEventKind::TransportWanted => {
            // Safety: the arm the kind names
            let wanted = unsafe { event.payload.transport_wanted };
            let protocol = transport_of(wanted.protocol).ok()?.protocol();
            let destination =
                unsafe { text(wanted.destination, wanted.destination_len, "destination") }
                    .ok()??
                    .parse()
                    .ok()?;
            Some(Seen::Wanted {
                protocol,
                destination,
                outgrown: wanted.request_bytes != 0 || wanted.limit_bytes != 0,
            })
        }
        SipralEventKind::LookupWanted => {
            // Safety: the arm the kind names
            let lookup = unsafe { event.payload.locate };
            let name = unsafe { text(lookup.name, lookup.name_len, "name") }.ok()??;
            let record = match lookup.record {
                1 => RecordType::Naptr,
                2 => RecordType::Srv,
                3 => RecordType::A,
                4 => RecordType::Aaaa,
                _ => return None,
            };
            Some(Seen::Lookup {
                account: event.account,
                query: Query::new(name, record),
            })
        }
        SipralEventKind::TransportFailed => Some(Seen::Failed {
            // Safety: the arm the kind names
            transport: unsafe { event.payload.transport_failed }.transport,
        }),
        SipralEventKind::CallEnded => Some(Seen::Ended { call: event.call }),
        SipralEventKind::TurnStream => {
            // Safety: the arm the kind names
            let asked = unsafe { event.payload.turn_stream };
            let local = unsafe { text(asked.local, asked.local_len, "local") }
                .ok()??
                .parse()
                .ok()?;
            let server = unsafe { text(asked.server, asked.server_len, "server") }
                .ok()??
                .parse()
                .ok()?;
            let protocol = if asked.protocol == SipralTransport::Tls as u32 {
                TransportProtocol::Tls
            } else {
                TransportProtocol::Tcp
            };
            Some(Seen::Turn {
                open: asked.state == SipralTurnStream::Open as u32,
                protocol,
                local,
                server,
            })
        }
        _ => None,
    }
}

/// What a call into the stack answered, read for whether it is worth asking again.
trait Answered {
    /// Another thread was inside the stack, or its clock ran ahead of this one.
    fn wait_and_ask_again(&self) -> bool;
}

impl Answered for SipralStatus {
    fn wait_and_ask_again(&self) -> bool {
        matches!(self, Self::Busy | Self::ClockBehind)
    }
}

impl<T> Answered for Result<T, Fail> {
    fn wait_and_ask_again(&self) -> bool {
        self.as_ref()
            .is_err_and(|failure| failure.status.wait_and_ask_again())
    }
}

/// `call` until the stack takes it: another thread inside the stack answers
/// `SIPRAL_STATUS_BUSY`, and one whose clock ran ahead `SIPRAL_STATUS_CLOCK_BEHIND`, for half a
/// second at most. What a connection carried is handed in so, never dropped, since a stream
/// with a hole in it cannot be read again; so is what the stack is told only once, such as a
/// connection lost, and what a connection is checked against.
fn patiently<T: Answered>(mut call: impl FnMut() -> T) -> T {
    let since = Instant::now();
    loop {
        let answer = call();
        if !answer.wait_and_ask_again() || since.elapsed() >= PATIENCE {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// One of the calls that take a media socket's name and the time.
type Said = unsafe extern "C" fn(SipralHandle, *const c_char, usize, u64) -> SipralStatus;

/// Tell the stack something about the media socket at `local`.
fn tell(stack: SipralHandle, said: Said, local: SocketAddr, clock: &Clock) -> SipralStatus {
    let named = local.to_string();
    patiently(|| unsafe { said(stack, named.as_ptr().cast(), named.len(), clock.now()) })
}

/// The next number a connection of the component's is opened under.
fn next_transport(driver: &mut Driver) -> u32 {
    let id = driver.next;
    driver.next = driver.next.checked_add(1).unwrap_or(FIRST_STREAM);
    id
}

/// `sipral_transport_t`'s number for a protocol.
const fn number_of(protocol: TransportProtocol) -> u32 {
    match protocol {
        TransportProtocol::Tcp => SipralTransport::Tcp as u32,
        TransportProtocol::Tls => SipralTransport::Tls as u32,
        TransportProtocol::Ws => SipralTransport::Ws as u32,
        TransportProtocol::Wss => SipralTransport::Wss as u32,
        _ => SipralTransport::Udp as u32,
    }
}

/// `sipral_transport_error_t`'s number for a kind.
const fn error_number(error: TransportErrorKind) -> u32 {
    match error {
        TransportErrorKind::ConnectionRefused => 1,
        TransportErrorKind::ConnectionReset => 2,
        TransportErrorKind::Unreachable => 3,
        TransportErrorKind::TimedOut => 4,
        TransportErrorKind::Closed => 5,
        _ => 0,
    }
}

/// Bind `transport` on the stack, as an application would.
fn bind(
    stack: SipralHandle,
    transport: u32,
    protocol: TransportProtocol,
    local: SocketAddr,
    remote: Option<SocketAddr>,
    now_ms: u64,
) -> Result<(), Fail> {
    let local = local.to_string();
    let remote = remote.map(|remote| remote.to_string());
    let (far, far_len) = remote.as_deref().map_or((ptr::null(), 0), |remote| {
        (remote.as_ptr().cast::<c_char>(), remote.len())
    });
    answered(
        patiently(|| unsafe {
            sipral_stack_transport_bind(
                stack,
                transport,
                number_of(protocol),
                local.as_ptr().cast(),
                local.len(),
                far,
                far_len,
                now_ms,
                ptr::null_mut(),
            )
        }),
        "sipral_stack_transport_bind",
    )
}

/// Tell the stack why a transport failed, as `sipral_stack_transport_failed_with` takes it.
fn report(stack: SipralHandle, transport: u32, failure: &Failure, now_ms: u64) {
    let told = SipralTransportFailure {
        size: size_of::<SipralTransportFailure>(),
        transport,
        error: error_number(failure.error),
        tls: failure.tls.number(),
        detail: failure.detail.as_ptr().cast(),
        detail_len: failure.detail.len(),
    };
    // a transport the stack has meanwhile forgotten has nothing waiting on it
    let _ =
        patiently(|| unsafe { sipral_stack_transport_failed_with(stack, &raw const told, now_ms) });
}

pub(super) unsafe fn start(
    stack: SipralHandle,
    config: Option<&SipralNetworkConfig>,
    now_ms: u64,
) -> Result<(), Fail> {
    let settings = unsafe { settings_of(config) }?;
    let mut networks = locked(&NETWORKS);
    if networks.iter().any(|(handle, _)| *handle == stack) {
        return Err(fail(
            SipralStatus::WrongState,
            "the networking component already runs for this stack",
        ));
    }
    let (local, speaks) = with_stack(stack, |state| Ok((state.local, state.speaks)))?;
    if speaks != SipralTransport::Udp || local.ip().is_unspecified() {
        return Err(fail(
            SipralStatus::WrongState,
            format!(
                "the networking component runs a stack created on UDP at a named address, and \
                 this one is on {speaks:?} at {local}: name the interface in bind_address \
                 (sipral_advertised_address finds it), and give accounts on TCP or TLS a \
                 connection of their own with stream_protocol"
            ),
        ));
    }
    let mut network = Network::new(settings.network).map_err(|error| {
        fail(
            SipralStatus::TransportDown,
            format!("the resolver could not start: {error}"),
        )
    })?;
    let bound = network
        .bind_datagram(TransportId(SIPRAL_TRANSPORT_MAIN), local)
        .map_err(|error| {
            fail(
                SipralStatus::TransportDown,
                format!("the stack's socket could not be bound at {local}: {error}"),
            )
        })?;
    if bound != local {
        bind(
            stack,
            SIPRAL_TRANSPORT_MAIN,
            TransportProtocol::Udp,
            bound,
            None,
            now_ms,
        )?;
    }
    let notes = Arc::new(Mutex::new(Vec::new()));
    let noting = Arc::clone(&notes);
    let observer: Observer = Arc::new(move |event: &SipralEvent| {
        if let Some(note) = seen(event) {
            locked(&noting).push(note);
        }
    });
    with_stack(stack, |state| {
        state.observer = Some(observer);
        Ok(())
    })?;
    networks.push((
        stack,
        Arc::new(Shared {
            stack,
            notes,
            driver: Mutex::new(Driver {
                network,
                server_name: settings.server_name,
                turn_name: settings.turn_name,
                turn_trust: settings.turn_trust,
                local: bound,
                next: FIRST_STREAM,
                streams: HashMap::new(),
                relays: HashMap::new(),
                media: HashMap::new(),
                out: vec![0; SIPRAL_MESSAGE_BYTES],
            }),
            running: AtomicBool::new(false),
            senders: Mutex::new(HashMap::new()),
            relay_senders: Mutex::new(HashMap::new()),
        }),
    ));
    Ok(())
}

pub(super) fn stop(stack: SipralHandle) -> Result<(), Fail> {
    let shared = {
        let mut networks = locked(&NETWORKS);
        let Some(at) = networks.iter().position(|(handle, _)| *handle == stack) else {
            return Err(fail(
                SipralStatus::WrongState,
                "the networking component is not running for this stack",
            ));
        };
        networks.swap_remove(at).1
    };
    // a stack destroyed meanwhile has no observer left to take
    let _ = with_stack(stack, |state| {
        state.observer = None;
        Ok(())
    });
    drop(shared);
    Ok(())
}

pub(crate) fn forget(stack: SipralHandle) {
    let gone = {
        let mut networks = locked(&NETWORKS);
        networks
            .iter()
            .position(|(handle, _)| *handle == stack)
            .map(|at| networks.swap_remove(at))
    };
    drop(gone);
}

pub(super) fn run(stack: SipralHandle, now_ms: u64, wait_ms: u32) -> Result<(), Fail> {
    let shared = find(stack)?;
    if shared.running.swap(true, Ordering::AcqRel) {
        return Err(fail(
            SipralStatus::Busy,
            "sipral_network_run is already running for this stack, on this thread inside its \
             callback or on another",
        ));
    }
    let clock = Clock::new(now_ms);
    let done = turn(&shared, &clock).and_then(|due| {
        let wait = Duration::from_millis(u64::from(wait_ms)).min(due);
        let arrived = locked(&shared.driver).network.wait(Some(wait));
        feed(&shared, arrived, &clock);
        turn(&shared, &clock).map(|_| ())
    });
    shared.running.store(false, Ordering::Release);
    if done.as_ref().is_err_and(|failure| {
        matches!(
            failure.status,
            SipralStatus::InvalidHandle | SipralStatus::StaleHandle
        )
    }) {
        forget(stack);
    }
    done
}

/// Poll the stack, then do everything that follows from it; how long until it is due again.
fn turn(shared: &Shared, clock: &Clock) -> Result<Duration, Fail> {
    let stack = shared.stack;
    let mut polled = SipralPollResult {
        size: size_of::<SipralPollResult>(),
        events_delivered: 0,
        events_unclaimed: 0,
        transmits_discarded: 0,
        has_deadline: 0,
        next_poll_in_ms: 0,
    };
    // with no lock of the component's held: the callback may call back into it
    answered(
        unsafe { sipral_stack_poll(stack, clock.now(), &raw mut polled) },
        "sipral_stack_poll",
    )?;
    let mut driver = locked(&shared.driver);
    farewells(shared, &mut driver, clock);
    let released = name(shared, &mut driver, clock);
    stun(shared, &mut driver, clock);
    close_released(shared, &mut driver, &released);
    media(shared, &mut driver, clock);
    act(shared, &mut driver);
    flush(stack, &mut driver, clock);
    Ok(if polled.has_deadline == 0 {
        IDLE
    } else {
        Duration::from_millis(polled.next_poll_in_ms).min(IDLE)
    })
}

/// Name the media sockets opened since the last turn to the stack's STUN client, and release
/// those the application closed while named; returns the released ones, to close once what
/// their release queued has been sent.
fn name(shared: &Shared, driver: &mut Driver, clock: &Clock) -> Vec<SocketAddr> {
    let mut released = Vec::new();
    let waiting: Vec<(SocketAddr, Naming)> = driver
        .media
        .iter()
        .filter(|(_, media)| matches!(media.named, Naming::Asking | Naming::Releasing))
        .map(|(local, media)| (*local, media.named))
        .collect();
    for (local, named) in waiting {
        if named == Naming::Releasing {
            // the relay's Refresh of lifetime zero waits in the STUN queue (RFC 8656 §8)
            let _ = tell(shared.stack, sipral_stack_nat_unmap, local, clock);
            released.push(local);
            continue;
        }
        let status = tell(shared.stack, sipral_stack_nat_map, local, clock);
        if let Some(media) = driver.media.get_mut(&local) {
            // without SIPRAL_NAT_STUN the stack asks nothing about any socket
            media.named = if status == SipralStatus::Ok {
                Naming::Named
            } else {
                Naming::Never
            };
        }
    }
    released
}

/// Close the media sockets released this turn, now that their release has been sent.
fn close_released(shared: &Shared, driver: &mut Driver, released: &[SocketAddr]) {
    for local in released {
        let Some(media) = driver.media.remove(local) else {
            continue;
        };
        driver.network.close_media(*local);
        if let Some(port) = media.reserved {
            let _ = patiently(|| unsafe { sipral_stack_rtp_port_release(shared.stack, port) });
        }
    }
}

/// Send what the stack's STUN and TURN clients queued for the media sockets: their mappings,
/// their relays' Allocates, permissions and refreshes, and a call's traffic before it has a
/// media handle.
fn stun(shared: &Shared, driver: &mut Driver, clock: &Clock) {
    let mut destination = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    let mut source = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    loop {
        let mut transmit = transmit_into(&mut driver.out, &mut destination, &mut source);
        let status = unsafe { sipral_stack_poll_stun(shared.stack, &raw mut transmit) };
        if status != SipralStatus::Ok || transmit.len == 0 {
            return;
        }
        let (Some(to), Some(from)) = (
            written_address(&destination, transmit.destination_len),
            written_address(&source, transmit.source_len),
        ) else {
            continue;
        };
        send_from(
            shared,
            driver,
            Leaving {
                local: from,
                to,
                protocol: transmit.protocol,
                len: transmit.len,
            },
            clock,
        );
    }
}

/// The transmit record over the driver's buffers.
fn transmit_into(
    out: &mut [u8],
    destination: &mut [c_char],
    source: &mut [c_char],
) -> SipralTransmit {
    SipralTransmit {
        size: size_of::<SipralTransmit>(),
        transport: 0,
        protocol: 0,
        data: out.as_mut_ptr(),
        capacity: out.len(),
        len: 0,
        destination: destination.as_mut_ptr(),
        destination_capacity: destination.len(),
        destination_len: 0,
        source: source.as_mut_ptr(),
        source_capacity: source.len(),
        source_len: 0,
    }
}

/// What the connections asked for meanwhile, opened, or closed after what was queued for them.
fn act(shared: &Shared, driver: &mut Driver) {
    let noted = std::mem::take(&mut *locked(&shared.notes));
    let mut later = Vec::new();
    for note in noted {
        match note {
            Seen::Wanted {
                protocol,
                destination,
                outgrown,
            } => {
                if !open_stream(shared, driver, protocol, destination, outgrown) {
                    // asked again at the next turn: a connection checked against a guess would
                    // refuse the right server, or accept the wrong one
                    later.push(Seen::Wanted {
                        protocol,
                        destination,
                        outgrown,
                    });
                }
            }
            Seen::Lookup { account, query } => driver.network.look_up(account, query),
            Seen::Failed { transport } => {
                if driver.streams.remove(&transport).is_some() {
                    driver.network.close(TransportId(transport));
                }
            }
            Seen::Ended { call } => {
                let ended: Vec<SocketAddr> = driver
                    .media
                    .iter()
                    .filter(|(_, media)| media.attached.is_some_and(|(of, _)| of == call))
                    .map(|(local, _)| *local)
                    .collect();
                for local in ended {
                    // the port came back to the range with the call
                    driver.media.remove(&local);
                    driver.network.close_media(local);
                    locked(&shared.senders).retain(|_, (at, _)| *at != local);
                }
            }
            Seen::Turn {
                open: true,
                protocol,
                local,
                server,
            } => {
                // asked for again: the old one's allocation went with it (RFC 8656 §3.2)
                let old: Vec<u32> = relays_of(driver, local);
                for id in old {
                    forget_relay(shared, driver, id);
                }
                let id = next_transport(driver);
                driver.network.connect_host(
                    TransportId(id),
                    protocol,
                    server,
                    driver.turn_name.clone(),
                    &driver.turn_trust,
                );
                driver.relays.insert(id, Relay { local, open: false });
            }
            Seen::Turn {
                open: false, local, ..
            } => {
                // what was queued for it has been written: stun and farewells ran first
                for id in relays_of(driver, local) {
                    forget_relay(shared, driver, id);
                }
            }
        }
    }
    if !later.is_empty() {
        // ahead of what a poll noted meanwhile, in the order they were asked
        locked(&shared.notes).splice(0..0, later);
    }
}

/// Open the connections the stack asked for: one for each identity waiting for a connection
/// there (`sipral_ua`'s flow module), or for a request that outgrew a datagram one checked
/// against the first account there, unless one being made answers it too. Each is said to the
/// stack to be checked against its identity before it is bound, so it carries the accounts of
/// that identity alone. `false` when the stack could not be read yet, with nothing done.
fn open_stream(
    shared: &Shared,
    driver: &mut Driver,
    protocol: TransportProtocol,
    destination: SocketAddr,
    outgrown: bool,
) -> bool {
    if protocol == TransportProtocol::Udp {
        return true;
    }
    let opening = patiently(|| {
        with_stack(shared.stack, |state| {
            let identities = identities_asked(state, protocol, destination, outgrown);
            let mut opening = Vec::new();
            for identity in identities {
                let same = driver
                    .streams
                    .iter()
                    .find(|(_, stream)| {
                        stream.protocol == protocol
                            && stream.destination == destination
                            && stream.identity == identity
                    })
                    .map(|(id, stream)| (*id, stream.bound));
                // the one being made answers this ask too
                if same.is_some_and(|(_, bound)| !bound) {
                    continue;
                }
                let id = next_transport(driver);
                state.agent.stream_opening(
                    TransportId(id),
                    protocol,
                    destination,
                    identity.clone(),
                );
                opening.push((id, identity, same.map(|(given_up, _)| given_up)));
            }
            Ok(opening)
        })
    });
    let opening = match opening {
        Ok(opening) => opening,
        // a stack destroyed meanwhile has nothing waiting
        Err(failure) => return !failure.status.wait_and_ask_again(),
    };
    for (id, identity, given_up) in opening {
        // the stack has given that one up: a new one in its place
        if let Some(old) = given_up {
            driver.streams.remove(&old);
            driver.network.close(TransportId(old));
        }
        let name = driver
            .server_name
            .clone()
            .or_else(|| identity.server_name().map(str::to_owned));
        let target = StreamTarget::new(name, identity.pin().copied());
        driver
            .network
            .connect(TransportId(id), protocol, destination, target);
        driver.streams.insert(
            id,
            Stream {
                protocol,
                destination,
                bound: false,
                identity,
            },
        );
    }
    true
}

/// The TURN connections of the media socket at `local`.
fn relays_of(driver: &Driver, local: SocketAddr) -> Vec<u32> {
    driver
        .relays
        .iter()
        .filter(|(_, relay)| relay.local == local)
        .map(|(id, _)| *id)
        .collect()
}

/// Close a TURN connection without a word to the stack, which asked for it closed or already
/// knows it broke.
fn forget_relay(shared: &Shared, driver: &mut Driver, id: u32) -> Option<Relay> {
    let relay = driver.relays.remove(&id)?;
    driver.network.close(TransportId(id));
    locked(&shared.relay_senders).remove(&relay.local);
    Some(relay)
}

/// A TURN connection lost: closed, and the stack told, which loses the socket's relay.
fn lose_relay(shared: &Shared, driver: &mut Driver, id: u32, clock: &Clock) {
    if let Some(relay) = forget_relay(shared, driver, id) {
        let _ = tell(shared.stack, sipral_stack_turn_closed, relay.local, clock);
    }
}

/// Write everything the stack queued.
fn flush(stack: SipralHandle, driver: &mut Driver, clock: &Clock) {
    let mut destination = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    let mut source = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    loop {
        let mut transmit = transmit_into(&mut driver.out, &mut destination, &mut source);
        let status = unsafe { sipral_stack_poll_transmit(stack, &raw mut transmit) };
        if status == SipralStatus::BufferTooSmall && transmit.len > driver.out.len() {
            // a WebSocket frame of a message near the limit is longer than any message, and the
            // stack keeps it first in line until it is offered room for it
            driver.out.resize(transmit.len, 0);
            continue;
        }
        if status != SipralStatus::Ok || transmit.len == 0 {
            return;
        }
        let Some(to) = written_address(&destination, transmit.destination_len) else {
            continue;
        };
        let payload = driver.out.get(..transmit.len).unwrap_or_default();
        if let Err(failure) = driver
            .network
            .send(TransportId(transmit.transport), to, payload)
            && driver.streams.remove(&transmit.transport).is_some()
        {
            report(stack, transmit.transport, &failure, clock.now());
        }
    }
}

/// An address the library wrote into a caller's buffer.
fn written_address(buffer: &[c_char], len: usize) -> Option<SocketAddr> {
    let bytes: Vec<u8> = buffer
        .get(..len)?
        .iter()
        .flat_map(|byte| byte.to_ne_bytes())
        .collect();
    std::str::from_utf8(&bytes).ok()?.parse().ok()
}

/// A media packet buffer over the driver's.
fn packet(out: &mut [u8], destination: &mut [c_char]) -> SipralMediaPacket {
    SipralMediaPacket {
        size: size_of::<SipralMediaPacket>(),
        data: out.as_mut_ptr(),
        capacity: out.len(),
        len: 0,
        destination: destination.as_mut_ptr(),
        destination_capacity: destination.len(),
        destination_len: 0,
        protocol: 0,
        reserved: 0,
    }
}

/// Whether bytes the stack marked with `protocol` leave as a datagram from the media socket,
/// rather than on its TURN connection over TCP or TLS.
const fn as_datagram(protocol: u32) -> bool {
    protocol == SipralTransport::Udp as u32 || protocol == 0
}

/// Bytes in the driver's buffer, and where they go.
#[derive(Clone, Copy)]
struct Leaving {
    /// The media socket they leave from, or whose TURN connection carries them.
    local: SocketAddr,
    to: SocketAddr,
    protocol: u32,
    len: usize,
}

/// Send the first `leaving.len` bytes of the driver's buffer: from the media socket as a
/// datagram, or whole on its TURN connection when the stack marked them for it, already framed
/// (RFC 8656 §12.5). A connection that will not take them is lost, and the stack told.
fn send_from(shared: &Shared, driver: &mut Driver, leaving: Leaving, clock: &Clock) {
    let Some(payload) = driver.out.get(..leaving.len) else {
        return;
    };
    if as_datagram(leaving.protocol) {
        // a refused datagram is one destination's; the media watchdog notices silence
        let _ = driver
            .network
            .send_media(leaving.local, leaving.to, payload);
        return;
    }
    let open = driver
        .relays
        .iter()
        .find(|(_, relay)| relay.local == leaving.local && relay.open)
        .map(|(id, _)| *id);
    // bytes for a connection that is not open have nothing to go on; the stack's own timers
    // notice what they were for
    let Some(id) = open else {
        return;
    };
    if driver
        .network
        .send(TransportId(id), leaving.to, payload)
        .is_err()
    {
        lose_relay(shared, driver, id, clock);
    }
}

/// Send what `packet` holds for the media socket at `local`.
fn send_packet(
    shared: &Shared,
    driver: &mut Driver,
    local: SocketAddr,
    packet: &SipralMediaPacket,
    destination: &[c_char],
    clock: &Clock,
) {
    let Some(to) = written_address(destination, packet.destination_len) else {
        return;
    };
    let leaving = Leaving {
        local,
        to,
        protocol: packet.protocol,
        len: packet.len,
    };
    send_from(shared, driver, leaving, clock);
}

/// Every attached call's handshake, connectivity checks and RTCP.
fn media(shared: &Shared, driver: &mut Driver, clock: &Clock) {
    let attached: Vec<(SocketAddr, SipralHandle)> = driver
        .media
        .iter()
        .filter_map(|(local, media)| media.attached.map(|(_, handle)| (*local, handle)))
        .collect();
    let mut destination = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    for (local, handle) in attached {
        for poll in [sipral_media_poll_transmit, sipral_media_poll_rtcp] {
            loop {
                let mut out = std::mem::take(&mut driver.out);
                let mut polled = packet(&mut out, &mut destination);
                let status = unsafe { poll(handle, clock.now(), &raw mut polled) };
                driver.out = out;
                if status != SipralStatus::Ok || polled.len == 0 {
                    break;
                }
                send_packet(shared, driver, local, &polled, &destination, clock);
            }
        }
    }
}

/// The RTCP goodbyes of calls that ended, and their relays given back, from their own sockets.
fn farewells(shared: &Shared, driver: &mut Driver, clock: &Clock) {
    let mut destination = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    loop {
        let mut call = SIPRAL_HANDLE_NONE;
        let mut out = std::mem::take(&mut driver.out);
        let mut polled = packet(&mut out, &mut destination);
        let status =
            unsafe { sipral_stack_poll_farewell(shared.stack, &raw mut call, &raw mut polled) };
        driver.out = out;
        if status != SipralStatus::Ok || polled.len == 0 {
            return;
        }
        let from = driver
            .media
            .iter()
            .find(|(_, media)| media.attached.is_some_and(|(of, _)| of == call))
            .map(|(local, _)| *local);
        if let Some(local) = from {
            send_packet(shared, driver, local, &polled, &destination, clock);
        }
    }
}

/// Hand everything that arrived to the stack, as an application would.
fn feed(shared: &Shared, arrived: Vec<Happening>, clock: &Clock) {
    let stack = shared.stack;
    for happening in arrived {
        let Some(happening) = relayed(shared, happening, clock) else {
            continue;
        };
        match happening {
            Happening::Datagram {
                transport,
                remote,
                local,
                data,
            } => {
                let from = remote.to_string();
                let to = local.to_string();
                let _ = unsafe {
                    sipral_stack_receive_datagram(
                        stack,
                        transport.0,
                        data.as_ptr(),
                        data.len(),
                        from.as_ptr().cast(),
                        from.len(),
                        to.as_ptr().cast(),
                        to.len(),
                        clock.now(),
                    )
                };
            }
            Happening::StreamData { transport, data } => {
                // a stream the stack could not read any more it has let go of itself
                let _ = patiently(|| unsafe {
                    sipral_stack_receive_stream(
                        stack,
                        transport.0,
                        data.as_ptr(),
                        data.len(),
                        clock.now(),
                    )
                });
            }
            Happening::Connected {
                transport,
                protocol,
                local,
                remote,
                early,
            } => connected(shared, transport.0, protocol, local, remote, &early, clock),
            Happening::ConnectFailed {
                transport, failure, ..
            }
            | Happening::StreamFailed { transport, failure } => {
                locked(&shared.driver).streams.remove(&transport.0);
                report(stack, transport.0, &failure, clock.now());
            }
            Happening::StreamClosed { transport } => {
                locked(&shared.driver).streams.remove(&transport.0);
                let _ = patiently(|| unsafe {
                    sipral_stack_stream_closed(stack, transport.0, clock.now())
                });
            }
            Happening::LookedUp { tag, query, answer } => {
                // an account removed while its lookup ran has nothing to answer
                let _ = patiently(|| {
                    with_stack_at(stack, clock.now(), |state, now| {
                        let id = state.accounts.get(tag).map_err(handle_failed)?;
                        state
                            .agent
                            .looked_up(id, &query, answer.clone(), now)
                            .map_err(|error| crate::call::ua_failed(&error))
                    })
                });
            }
            Happening::Media {
                local,
                remote,
                mut data,
            } => media_arrived(shared, local, remote, &mut data, clock),
            _ => {}
        }
    }
}

/// A packet on a media socket: the call's once its handle is attached; before, the STUN
/// server's and the TURN server's answers and the far end's early checks, which the stack keeps
/// for the call. What the stack refuses is dropped, and counted there.
fn media_arrived(
    shared: &Shared,
    local: SocketAddr,
    remote: SocketAddr,
    data: &mut [u8],
    clock: &Clock,
) {
    let known = locked(&shared.driver)
        .media
        .get(&local)
        .map(|media| media.attached);
    let from = remote.to_string();
    match known {
        Some(Some((_, handle))) => {
            let mut arrival: u32 = 0;
            let _ = unsafe {
                sipral_media_receive(
                    handle,
                    data.as_mut_ptr(),
                    data.len(),
                    from.as_ptr().cast(),
                    from.len(),
                    clock.now(),
                    &raw mut arrival,
                )
            };
        }
        Some(None) => {
            let to = local.to_string();
            let _ = unsafe {
                sipral_stack_receive_stun(
                    shared.stack,
                    data.as_ptr(),
                    data.len(),
                    from.as_ptr().cast(),
                    from.len(),
                    to.as_ptr().cast(),
                    to.len(),
                    clock.now(),
                )
            };
        }
        None => {}
    }
}

/// A happening on a media socket's TURN connection, handed to the stack as an application
/// would hand it; any other is given back.
fn relayed(shared: &Shared, happening: Happening, clock: &Clock) -> Option<Happening> {
    let transport = match happening {
        Happening::Connected { transport, .. }
        | Happening::ConnectFailed { transport, .. }
        | Happening::StreamData { transport, .. }
        | Happening::StreamClosed { transport }
        | Happening::StreamFailed { transport, .. } => transport.0,
        _ => return Some(happening),
    };
    let mut driver = locked(&shared.driver);
    let Some(relay) = driver.relays.get(&transport).copied() else {
        return Some(happening);
    };
    match happening {
        Happening::Connected { early, .. } => {
            if let Some(sender) = driver.network.stream_sender(TransportId(transport)) {
                locked(&shared.relay_senders).insert(relay.local, sender);
            }
            if let Some(open) = driver.relays.get_mut(&transport) {
                open.open = true;
            }
            drop(driver);
            let told = tell(
                shared.stack,
                sipral_stack_turn_connected,
                relay.local,
                clock,
            );
            if told != SipralStatus::Ok {
                // the stack no longer wants it: the socket was released meanwhile
                forget_relay(shared, &mut locked(&shared.driver), transport);
            } else if !early.is_empty() {
                turn_bytes(shared, transport, relay.local, &early, clock);
            }
        }
        Happening::StreamData { data, .. } => {
            drop(driver);
            turn_bytes(shared, transport, relay.local, &data, clock);
        }
        // refused, closed or broken: the relay goes with it (RFC 8656 §3.2)
        _ => lose_relay(shared, &mut driver, transport, clock),
    }
    None
}

/// Bytes off a TURN connection, for the stack to put back together.
fn turn_bytes(shared: &Shared, transport: u32, local: SocketAddr, data: &[u8], clock: &Clock) {
    let named = local.to_string();
    let status = patiently(|| unsafe {
        sipral_stack_turn_receive(
            shared.stack,
            named.as_ptr().cast(),
            named.len(),
            data.as_ptr(),
            data.len(),
            clock.now(),
        )
    });
    if status == SipralStatus::StreamBroken {
        // nothing in the stream says where the next message starts: the stack has let the relay
        // go, and the connection follows
        forget_relay(shared, &mut locked(&shared.driver), transport);
    }
}

/// A connection made: bound on the stack, and what the server said meanwhile handed in.
fn connected(
    shared: &Shared,
    transport: u32,
    protocol: TransportProtocol,
    local: SocketAddr,
    remote: SocketAddr,
    early: &[u8],
    clock: &Clock,
) {
    let stack = shared.stack;
    match bind(stack, transport, protocol, local, Some(remote), clock.now()) {
        Ok(()) => {
            if let Some(stream) = locked(&shared.driver).streams.get_mut(&transport) {
                stream.bound = true;
            }
            if !early.is_empty() {
                let _ = patiently(|| unsafe {
                    sipral_stack_receive_stream(
                        stack,
                        transport,
                        early.as_ptr(),
                        early.len(),
                        clock.now(),
                    )
                });
            }
        }
        Err(refused) => {
            let mut driver = locked(&shared.driver);
            driver.streams.remove(&transport);
            driver.network.close(TransportId(transport));
            drop(driver);
            let failure = Failure::new(
                TransportErrorKind::Other,
                TlsFailure::None,
                &format!(
                    "connected to {remote}, and the stack would not bind it: {}",
                    refused.message()
                ),
            );
            report(stack, transport, &failure, clock.now());
        }
    }
}

pub(super) unsafe fn locate(
    config: Option<&SipralNetworkConfig>,
    server_uri: *const c_char,
    server_uri_len: usize,
    protocol: u32,
    buffer: *mut c_char,
    capacity: usize,
    out_needed: *mut usize,
) -> Result<(), Fail> {
    let settings = unsafe { settings_of(config) }?;
    let written = unsafe { required_text(server_uri, server_uri_len, "server_uri") }?;
    let uri = Uri::parse_str(written).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("server_uri is {written:?}, which is not a URI: {error}"),
        )
    })?;
    let protocol = transport_of(protocol)?.protocol();
    let servers = &settings.network.name_servers;
    let resolver = if servers.is_empty() {
        Resolver::system()
    } else {
        Resolver::with_servers(servers)
    }
    .map_err(|error| {
        fail(
            SipralStatus::TransportDown,
            format!("the resolver could not start: {error}"),
        )
    })?;
    let mut targets = Vec::new();
    let mut last = None;
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        match resolver.locate(&uri, protocol, family, true) {
            Ok(found) => targets.extend(found.targets),
            Err(error) => last = Some(error),
        }
    }
    if targets.is_empty() {
        return Err(fail(
            SipralStatus::UnreachableAddress,
            format!(
                "{written} was not located: {}",
                last.map_or_else(|| "no address".to_owned(), |error| error.to_string())
            ),
        ));
    }
    let listed: Vec<String> = targets.iter().map(ToString::to_string).collect();
    unsafe { copy_out(&listed.join(","), buffer, capacity, out_needed) }
}

pub(super) unsafe fn media_open(
    stack: SipralHandle,
    buffer: *mut c_char,
    capacity: usize,
    out_needed: *mut usize,
) -> Result<(), Fail> {
    if capacity < SIPRAL_ADDRESS_BYTES {
        if !out_needed.is_null() {
            unsafe { out_needed.write(SIPRAL_ADDRESS_BYTES) };
        }
        return Err(fail(
            SipralStatus::BufferTooSmall,
            format!(
                "capacity is {capacity}, and a media socket is opened only into a buffer of \
                 SIPRAL_ADDRESS_BYTES ({SIPRAL_ADDRESS_BYTES}) or more"
            ),
        ));
    }
    let shared = find(stack)?;
    let mut port = 0_u32;
    let reserved = match unsafe { sipral_stack_rtp_port_reserve(stack, &raw mut port) } {
        SipralStatus::Ok => Some(port),
        // a stack without a range leaves the port to the system
        SipralStatus::WrongState => None,
        other => return answered(other, "sipral_stack_rtp_port_reserve"),
    };
    let mut driver = locked(&shared.driver);
    let at = SocketAddr::new(
        driver.local.ip(),
        reserved
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or(0),
    );
    if at.port() != 0 {
        // a port the stack hands out is one no call holds: a socket still open there is an
        // ended call's whose end the loop has not acted on yet, as when this is called from
        // that call's CALL_ENDED callback
        let stale: Vec<SocketAddr> = driver
            .media
            .keys()
            .filter(|local| local.port() == at.port())
            .copied()
            .collect();
        for local in stale {
            driver.media.remove(&local);
            driver.network.close_media(local);
            locked(&shared.senders).retain(|_, (to, _)| *to != local);
        }
    }
    let since = Instant::now();
    let opened = loop {
        let opened = driver.network.open_media(at);
        // a socket closed at that port a moment ago is let go by its reader within its read
        // timeout, and by a sender an audio thread holds once its frame is out
        let closing = opened
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::AddrInUse);
        if !closing || at.port() == 0 || since.elapsed() >= PATIENCE {
            break opened;
        }
        drop(driver);
        std::thread::sleep(Duration::from_millis(5));
        driver = locked(&shared.driver);
    };
    let bound = match opened {
        Ok(bound) => bound,
        Err(error) => {
            drop(driver);
            if let Some(port) = reserved {
                let _ = patiently(|| unsafe { sipral_stack_rtp_port_release(stack, port) });
            }
            return Err(fail(
                SipralStatus::TransportDown,
                format!("no media socket could be bound at {at}: {error}"),
            ));
        }
    };
    driver.media.insert(
        bound,
        Media {
            attached: None,
            reserved,
            // named at the next turn, with that turn's clock
            named: Naming::Asking,
        },
    );
    drop(driver);
    unsafe { copy_out(&bound.to_string(), buffer, capacity, out_needed) }
}

pub(super) fn media_attach(
    stack: SipralHandle,
    local: SocketAddr,
    call: SipralHandle,
    media: SipralHandle,
) -> Result<(), Fail> {
    let shared = find(stack)?;
    let mut driver = locked(&shared.driver);
    let Some(socket) = driver.media.get_mut(&local) else {
        return Err(no_socket(local));
    };
    socket.attached = Some((call, media));
    // a port a call took comes back with it
    socket.reserved = None;
    // a call described before its socket was named has no mapping to wait for
    if socket.named == Naming::Asking {
        socket.named = Naming::Never;
    }
    let sender = driver
        .network
        .media_sender(local)
        .ok_or_else(|| no_socket(local))?;
    drop(driver);
    locked(&shared.senders).insert(media, (local, sender));
    Ok(())
}

fn no_socket(local: SocketAddr) -> Fail {
    fail(
        SipralStatus::InvalidArgument,
        format!("the networking component has no media socket at {local}"),
    )
}

pub(super) unsafe fn media_capture(
    stack: SipralHandle,
    media: SipralHandle,
    now_ms: u64,
    samples: *const i16,
    sample_count: usize,
) -> Result<(), Fail> {
    let shared = find(stack)?;
    // the senders' locks alone, never the loop's: an audio thread must not wait out a turn
    let Some((local, sender)) = locked(&shared.senders).get(&media).cloned() else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "no media socket of the networking component is attached to this media handle",
        ));
    };
    let mut destination = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    let mut out = vec![0_u8; SIPRAL_MEDIA_PACKET_BYTES];
    let mut captured = packet(&mut out, &mut destination);
    let status =
        unsafe { sipral_media_capture(media, now_ms, samples, sample_count, &raw mut captured) };
    answered(status, "sipral_media_capture")?;
    let (Some(to), Some(payload)) = (
        written_address(&destination, captured.destination_len),
        out.get(..captured.len),
    ) else {
        return Ok(());
    };
    if payload.is_empty() {
        return Ok(());
    }
    if as_datagram(captured.protocol) {
        // a refused datagram is one destination's; the media watchdog notices silence
        let _ = sender.send(to, payload);
    } else {
        // the map's lock let go before the write: a connection slow to take it holds up only
        // this thread, never the loop that closes or replaces it
        let relay = locked(&shared.relay_senders).get(&local).cloned();
        if let Some(relay) = relay {
            // a connection that will not take it is heard ending by its reader, which tells the
            // stack
            let _ = relay.send(payload);
        }
    }
    Ok(())
}

pub(super) fn media_close(stack: SipralHandle, local: SocketAddr) -> Result<(), Fail> {
    let shared = find(stack)?;
    let mut driver = locked(&shared.driver);
    let Some(socket) = driver.media.get_mut(&local) else {
        return Err(no_socket(local));
    };
    if socket.attached.is_none() && matches!(socket.named, Naming::Named | Naming::Releasing) {
        // released at the next turn, its relay given back from it, and closed then
        socket.named = Naming::Releasing;
        return Ok(());
    }
    let Some(socket) = driver.media.remove(&local) else {
        return Err(no_socket(local));
    };
    driver.network.close_media(local);
    drop(driver);
    locked(&shared.senders).retain(|_, (at, _)| *at != local);
    if let Some(port) = socket.reserved {
        let _ = patiently(|| unsafe { sipral_stack_rtp_port_release(stack, port) });
    }
    Ok(())
}
