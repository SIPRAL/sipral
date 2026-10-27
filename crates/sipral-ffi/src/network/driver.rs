// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The networking component's loop, behind the `network` feature.
//!
//! It is the loop `crate::transport` and every binding write, written once: it calls the same
//! entry points an application would — `sipral_stack_poll`, `sipral_stack_poll_transmit`,
//! `sipral_stack_receive_*`, `sipral_stack_transport_bind`,
//! `sipral_stack_transport_failed_with`, the media calls — so the stack cannot tell it from
//! one, and reads the events it needs through the stack's observer before the callback does.
//! Sockets, connections and lookups are `sipral-net`'s.

use std::collections::HashMap;
use std::ffi::c_char;
use std::net::{IpAddr, SocketAddr};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sipral_core::endpoint::{
    AddressFamily, Query, RecordType, TransportErrorKind, TransportId, TransportProtocol,
};
use sipral_core::msg::{HostRef, Uri};
use sipral_core::pin::CertificatePin;
use sipral_net::{
    ClientCertificate, Failure, Happening, MediaSender, Network, NetworkConfig, Resolver,
    StreamTarget, TlsFailure, Trust,
};

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
use crate::ports::{sipral_stack_rtp_port_release, sipral_stack_rtp_port_reserve};
use crate::stack::{
    Observer, SipralPollResult, SipralTransport, handle_failed, sipral_stack_poll, transport_of,
    with_stack, with_stack_at,
};
use crate::status::SipralStatus;
use crate::text::{bytes, required_text, text};
use crate::transport::{
    SIPRAL_MESSAGE_BYTES, SIPRAL_TRANSPORT_MAIN, SipralTransmit, SipralTransportFailure,
    sipral_stack_poll_transmit, sipral_stack_receive_datagram, sipral_stack_receive_stream,
    sipral_stack_stream_closed, sipral_stack_transport_bind, sipral_stack_transport_failed_with,
};

/// The first transport number the component binds its connections under; the ones below are
/// the application's to choose.
const FIRST_STREAM: u32 = 1 << 31;

/// The longest one turn waits when the stack has no timer due.
const IDLE: Duration = Duration::from_secs(1);

/// What the observer noted for the component, during a poll.
enum Seen {
    Wanted {
        protocol: TransportProtocol,
        destination: SocketAddr,
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
}

/// One connection the component opened, or is opening.
#[derive(Clone, Copy)]
struct Stream {
    protocol: TransportProtocol,
    destination: SocketAddr,
    bound: bool,
}

/// One media socket the component opened.
#[derive(Clone, Copy)]
struct Media {
    /// The call and its media handle, once attached.
    attached: Option<(SipralHandle, SipralHandle)>,
    /// The port reserved from the stack's range, to give back if no call took it.
    reserved: Option<u32>,
}

/// What the loop keeps between turns, under one lock that a poll never holds.
struct Driver {
    network: Network,
    server_name: Option<String>,
    /// The address the stack's socket is bound at.
    local: SocketAddr,
    next: u32,
    streams: HashMap<u32, Stream>,
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
}

/// The configuration, read; zero everywhere, or none, is the defaults.
unsafe fn settings_of(config: Option<&SipralNetworkConfig>) -> Result<Settings, Fail> {
    let mut network = NetworkConfig::default();
    let Some(config) = config else {
        return Ok(Settings {
            network,
            server_name: None,
        });
    };
    let invalid = |message: String| fail(SipralStatus::InvalidArgument, message);
    network.trust = unsafe { trust_of(config) }?;
    let certificate = unsafe {
        bytes(
            config.client_certificate_pem.cast(),
            config.client_certificate_pem_len,
            "client_certificate_pem",
        )
    }?;
    let key = unsafe {
        bytes(
            config.client_key_pem.cast(),
            config.client_key_pem_len,
            "client_key_pem",
        )
    }?;
    settings_rest(config, network, certificate, key, invalid)
}

/// The members of the configuration that say which servers are trusted.
unsafe fn trust_of(config: &SipralNetworkConfig) -> Result<Trust, Fail> {
    let invalid = |message: String| fail(SipralStatus::InvalidArgument, message);
    // PEM is lines, so read as bytes rather than as a header's text
    let authority = unsafe {
        bytes(
            config.authority_pem.cast(),
            config.authority_pem_len,
            "authority_pem",
        )
    }?;
    let pin = unsafe { text(config.pin_sha256, config.pin_sha256_len, "pin_sha256") }?;
    let roots = || match authority {
        None => Err(invalid(
            "authority_pem is required when trust names an authority".to_owned(),
        )),
        Some(pem) => Trust::authorities_from_pem(pem)
            .map_err(|error| invalid(format!("authority_pem: {error}"))),
    };
    let trust = match config.trust {
        0 => Trust::Platform,
        1 => Trust::PlatformAnd(roots()?),
        2 => Trust::Only(roots()?),
        3 => {
            let Some(pin) = pin else {
                return Err(invalid(
                    "pin_sha256 is required with SIPRAL_NETWORK_TRUST_PINNED".to_owned(),
                ));
            };
            Trust::Pinned(
                CertificatePin::parse(pin)
                    .map_err(|error| invalid(format!("pin_sha256 is {pin:?}: {error}")))?,
            )
        }
        other => {
            return Err(invalid(format!(
                "trust is {other}, and a trust is 0 for the platform's, 1 for an authority beside \
                 it, 2 for that authority alone or 3 for a pinned certificate"
            )));
        }
    };
    if config.trust != 3 && pin.is_some() {
        return Err(invalid(
            "pin_sha256 is given and trust is not SIPRAL_NETWORK_TRUST_PINNED: an account's own \
             pin is tls_pin_sha256"
                .to_owned(),
        ));
    }
    if matches!(config.trust, 0 | 3) && authority.is_some() {
        return Err(invalid(
            "authority_pem is given and trust names no authority".to_owned(),
        ));
    }
    Ok(trust)
}

/// The client certificate, the resolver and the patience, after the trust.
fn settings_rest(
    config: &SipralNetworkConfig,
    mut network: NetworkConfig,
    certificate: Option<&[u8]>,
    key: Option<&[u8]>,
    invalid: impl Fn(String) -> Fail,
) -> Result<Settings, Fail> {
    network.client_certificate = match (certificate, key) {
        (None, None) => None,
        (Some(certificate), Some(key)) => Some(
            ClientCertificate::from_pem(certificate, key)
                .map_err(|error| invalid(format!("client_certificate_pem: {error}")))?,
        ),
        _ => {
            return Err(invalid(
                "a client certificate needs client_certificate_pem and client_key_pem both"
                    .to_owned(),
            ));
        }
    };
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
        _ => None,
    }
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
        unsafe {
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
        },
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
    let _ = unsafe { sipral_stack_transport_failed_with(stack, &raw const told, now_ms) };
}

/// The name and the pin a TLS connection to `destination` is checked against: the configured
/// name, else the host of the `server_uri` of the account located there (RFC 5922 §7.3); the
/// pin of that account, or of the one whose registrar URI names that address.
fn target_for(
    stack: SipralHandle,
    destination: SocketAddr,
    configured: Option<&String>,
) -> StreamTarget {
    let found = with_stack(stack, |state| {
        for id in state.agent.accounts() {
            let Some(account) = state.agent.account(id) else {
                continue;
            };
            let located = state.agent.located_targets(id).contains(&destination);
            let named_here = account
                .registrar()
                .and_then(Uri::sip)
                .is_some_and(|sip| literal(sip.host) == Some(destination.ip()));
            if !located && !named_here {
                continue;
            }
            let name = located
                .then(|| account.server().and_then(host_name))
                .flatten();
            return Ok((name, account.pinned_certificate().copied()));
        }
        Ok((None, None))
    });
    let (name, pin) = found.unwrap_or((None, None));
    StreamTarget::new(configured.cloned().or(name), pin)
}

/// A URI's host, when it is a name.
fn host_name(uri: &Uri) -> Option<String> {
    match uri.sip()?.host {
        HostRef::Name(name) => Some(name.to_owned()),
        HostRef::Ipv4(_) | HostRef::Ipv6(_) => None,
    }
}

/// A URI host's address, when it is a literal one.
const fn literal(host: HostRef<'_>) -> Option<IpAddr> {
    match host {
        HostRef::Ipv4(address) => Some(IpAddr::V4(address)),
        HostRef::Ipv6(address) => Some(IpAddr::V6(address)),
        HostRef::Name(_) => None,
    }
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
                local: bound,
                next: FIRST_STREAM,
                streams: HashMap::new(),
                media: HashMap::new(),
                out: vec![0; SIPRAL_MESSAGE_BYTES],
            }),
            running: AtomicBool::new(false),
            senders: Mutex::new(HashMap::new()),
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
    farewells(stack, &mut driver);
    media(&mut driver, clock);
    act(shared, &mut driver);
    flush(stack, &mut driver, clock);
    Ok(if polled.has_deadline == 0 {
        IDLE
    } else {
        Duration::from_millis(polled.next_poll_in_ms).min(IDLE)
    })
}

/// What the observer noted: connections to open or let go, lookups to make, media to close.
fn act(shared: &Shared, driver: &mut Driver) {
    let noted = std::mem::take(&mut *locked(&shared.notes));
    for note in noted {
        match note {
            Seen::Wanted {
                protocol,
                destination,
            } => {
                if protocol == TransportProtocol::Udp {
                    continue;
                }
                let same = driver
                    .streams
                    .iter()
                    .find(|(_, stream)| {
                        stream.protocol == protocol && stream.destination == destination
                    })
                    .map(|(id, stream)| (*id, stream.bound));
                match same {
                    // the one being made answers this ask too
                    Some((_, false)) => continue,
                    // the stack has given that one up: a new one in its place
                    Some((id, true)) => {
                        driver.streams.remove(&id);
                        driver.network.close(TransportId(id));
                    }
                    None => {}
                }
                let id = driver.next;
                driver.next = driver.next.checked_add(1).unwrap_or(FIRST_STREAM);
                let target = target_for(shared.stack, destination, driver.server_name.as_ref());
                driver
                    .network
                    .connect(TransportId(id), protocol, destination, target);
                driver.streams.insert(
                    id,
                    Stream {
                        protocol,
                        destination,
                        bound: false,
                    },
                );
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
        }
    }
}

/// Write everything the stack queued.
fn flush(stack: SipralHandle, driver: &mut Driver, clock: &Clock) {
    let mut destination = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    let mut source = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    loop {
        let mut transmit = SipralTransmit {
            size: size_of::<SipralTransmit>(),
            transport: 0,
            protocol: 0,
            data: driver.out.as_mut_ptr(),
            capacity: driver.out.len(),
            len: 0,
            destination: destination.as_mut_ptr(),
            destination_capacity: destination.len(),
            destination_len: 0,
            source: source.as_mut_ptr(),
            source_capacity: source.len(),
            source_len: 0,
        };
        let status = unsafe { sipral_stack_poll_transmit(stack, &raw mut transmit) };
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

/// Whether a packet leaves as a datagram from the call's socket, rather than on a TURN
/// connection over TCP or TLS, which the component does not carry yet.
const fn relayed_by_udp(packet: &SipralMediaPacket) -> bool {
    packet.protocol == SipralTransport::Udp as u32 || packet.protocol == 0
}

/// Send what `packet` holds from the media socket at `local`; a relayed packet for a TURN
/// connection is not the component's to carry.
fn send_packet(
    driver: &Driver,
    local: SocketAddr,
    packet: &SipralMediaPacket,
    destination: &[c_char],
) {
    if !relayed_by_udp(packet) {
        return;
    }
    let Some(to) = written_address(destination, packet.destination_len) else {
        return;
    };
    if let Some(payload) = driver.out.get(..packet.len) {
        // a refused datagram is one destination's; the media watchdog notices silence
        let _ = driver.network.send_media(local, to, payload);
    }
}

/// Every attached call's handshake, connectivity checks and RTCP.
fn media(driver: &mut Driver, clock: &Clock) {
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
                send_packet(driver, local, &polled, &destination);
            }
        }
    }
}

/// The RTCP goodbyes of calls that ended, from their own sockets.
fn farewells(stack: SipralHandle, driver: &mut Driver) {
    let mut destination = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    loop {
        let mut call = SIPRAL_HANDLE_NONE;
        let mut out = std::mem::take(&mut driver.out);
        let mut polled = packet(&mut out, &mut destination);
        let status = unsafe { sipral_stack_poll_farewell(stack, &raw mut call, &raw mut polled) };
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
            send_packet(driver, local, &polled, &destination);
        }
    }
}

/// Hand everything that arrived to the stack, as an application would.
fn feed(shared: &Shared, arrived: Vec<Happening>, clock: &Clock) {
    let stack = shared.stack;
    for happening in arrived {
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
                let _ = unsafe {
                    sipral_stack_receive_stream(
                        stack,
                        transport.0,
                        data.as_ptr(),
                        data.len(),
                        clock.now(),
                    )
                };
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
                let _ = unsafe { sipral_stack_stream_closed(stack, transport.0, clock.now()) };
            }
            Happening::LookedUp { tag, query, answer } => {
                // an account removed while its lookup ran has nothing to answer
                let _ = with_stack_at(stack, clock.now(), |state, now| {
                    let id = state.accounts.get(tag).map_err(handle_failed)?;
                    state
                        .agent
                        .looked_up(id, &query, answer, now)
                        .map_err(|error| crate::call::ua_failed(&error))
                });
            }
            Happening::Media {
                local,
                remote,
                mut data,
            } => {
                let attached = locked(&shared.driver)
                    .media
                    .get(&local)
                    .and_then(|media| media.attached);
                // before its handle exists, a call's socket hears nothing worth keeping
                if let Some((_, handle)) = attached {
                    let from = remote.to_string();
                    let mut arrival: u32 = 0;
                    // what was dropped, and why, the stack counts itself
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
            }
            _ => {}
        }
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
                let _ = unsafe {
                    sipral_stack_receive_stream(
                        stack,
                        transport,
                        early.as_ptr(),
                        early.len(),
                        clock.now(),
                    )
                };
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
    let opened = driver.network.open_media(at);
    let bound = match opened {
        Ok(bound) => bound,
        Err(error) => {
            drop(driver);
            if let Some(port) = reserved {
                let _ = unsafe { sipral_stack_rtp_port_release(stack, port) };
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
    // the senders' lock alone, never the loop's: an audio thread must not wait out a turn
    let Some(sender) = locked(&shared.senders)
        .get(&media)
        .map(|(_, sender)| sender.clone())
    else {
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
    if captured.len > 0
        && relayed_by_udp(&captured)
        && let Some(to) = written_address(&destination, captured.destination_len)
        && let Some(payload) = out.get(..captured.len)
    {
        // a refused datagram is one destination's; the media watchdog notices silence
        let _ = sender.send(to, payload);
    }
    Ok(())
}

pub(super) fn media_close(stack: SipralHandle, local: SocketAddr) -> Result<(), Fail> {
    let shared = find(stack)?;
    let mut driver = locked(&shared.driver);
    let Some(socket) = driver.media.remove(&local) else {
        return Err(no_socket(local));
    };
    driver.network.close_media(local);
    drop(driver);
    locked(&shared.senders).retain(|_, (at, _)| *at != local);
    if let Some(port) = socket.reserved {
        let _ = unsafe { sipral_stack_rtp_port_release(stack, port) };
    }
    Ok(())
}
