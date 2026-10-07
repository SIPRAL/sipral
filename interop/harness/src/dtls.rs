// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One DTLS-SRTP handshake over a real UDP socket, against an implementation
//! this project did not write.
//!
//! ```text
//! sipral-interop --dtls client <host:port> <a=fingerprint value> <profiles>
//! sipral-interop --dtls server <bind address:port> <a=fingerprint value> <profiles>
//! ```
//!
//! `profiles` is a comma-separated list of RFC 5764 §4.1.2 and RFC 7714
//! §14.2 profile numbers in hexadecimal, most preferred first (`0001` is
//! `SRTP_AES128_CM_HMAC_SHA1_80`, `0007` `SRTP_AEAD_AES_128_GCM`). The
//! fingerprint is what the peer's signalling would carry. Before the
//! handshake this end prints its own certificate's fingerprint, the value its
//! signalling would carry, as `fingerprint <value>`; then either
//!
//! ```text
//! keyed <profile> <keying material>
//! ```
//!
//! with the exporter's output laid out as RFC 5764 §4.2 lays it out --
//! client key, server key, client salt, server salt -- in uppercase
//! hexadecimal, which is exactly what `openssl s_client`/`s_server
//! -keymatexport EXTRACTOR-dtls_srtp` print for the same session; or
//! `refused <why>` with the failure this end reported. Exit status 0 when
//! keyed, 3 when refused, 1 when the handshake never ended or could not
//! start. `scripts/lab.sh dtls-interop` (interop/dtls/run.sh) judges the
//! lines against what OpenSSL printed.

use std::fmt::Write as _;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use sipral_dtls::handshake::SrtpProtectionProfile;
use sipral_dtls::keys::EcdsaKey;
use sipral_dtls::x509::{Certificate, CertificateParams, Fingerprint};
use sipral_dtls::{Config, Connection, Event, Random, Role, SrtpKeying};

/// How long a handshake may take before it is called hung: the first
/// retransmission comes after one second, and a peer on the same host
/// answers in milliseconds.
const PATIENCE: Duration = Duration::from_secs(20);

/// The operating system's randomness.
struct OsRandom;

impl Random for OsRandom {
    fn fill(&mut self, dest: &mut [u8]) {
        // getrandom(2) does not fail once the pool is initialised, and a
        // harness that cannot draw keys has nothing to test: stop rather
        // than key a handshake with zeros
        if getrandom::getrandom(dest).is_err() {
            std::process::abort();
        }
    }
}

fn hex(octets: &[u8]) -> String {
    octets.iter().fold(String::new(), |mut out, octet| {
        let _ = write!(out, "{octet:02X}");
        out
    })
}

/// The exporter's output in RFC 5764 §4.2's order, from this end's view of
/// it.
fn keying_material(keys: &SrtpKeying) -> Vec<u8> {
    let (client_key, server_key, client_salt, server_salt) = match keys.role() {
        Role::Client => (
            keys.local_master_key(),
            keys.remote_master_key(),
            keys.local_master_salt(),
            keys.remote_master_salt(),
        ),
        Role::Server => (
            keys.remote_master_key(),
            keys.local_master_key(),
            keys.remote_master_salt(),
            keys.local_master_salt(),
        ),
    };
    [client_key, server_key, client_salt, server_salt].concat()
}

fn profiles(list: &str) -> Option<Vec<SrtpProtectionProfile>> {
    list.split(',')
        .map(|item| {
            u16::from_str_radix(item.trim(), 16)
                .ok()
                .map(SrtpProtectionProfile)
        })
        .collect()
}

/// `sipral-interop --dtls ...`, the arguments after `--dtls`.
pub(crate) fn run(args: &[String]) -> ExitCode {
    let [role, address, fingerprint, list] = args else {
        eprintln!("usage: --dtls client|server <address:port> <a=fingerprint value> <profiles>");
        return ExitCode::from(2);
    };
    let role = match role.as_str() {
        "client" => Role::Client,
        "server" => Role::Server,
        other => {
            eprintln!("not a role: {other}");
            return ExitCode::from(2);
        }
    };
    let Some(address) = address
        .to_socket_addrs()
        .ok()
        .and_then(|mut found| found.next())
    else {
        eprintln!("not an address: {address}");
        return ExitCode::from(2);
    };
    let Ok(fingerprint) = Fingerprint::parse(fingerprint) else {
        eprintln!("not an a=fingerprint value: {fingerprint}");
        return ExitCode::from(2);
    };
    let Some(profiles) = profiles(list) else {
        eprintln!("not a list of profile numbers: {list}");
        return ExitCode::from(2);
    };
    match handshake(role, address, fingerprint, profiles) {
        Ok(code) => code,
        Err(why) => {
            println!("hung {why}");
            ExitCode::FAILURE
        }
    }
}

fn handshake(
    role: Role,
    address: SocketAddr,
    fingerprint: Fingerprint,
    profiles: Vec<SrtpProtectionProfile>,
) -> Result<ExitCode, String> {
    let key = EcdsaKey::generate(&mut OsRandom).map_err(|why| format!("no key: {why}"))?;
    let params = CertificateParams {
        common_name: "sipral-interop",
        not_before: 1_767_225_600,
        not_after: 1_767_225_600 + 365 * 86_400 * 5,
    };
    let certificate = Certificate::self_signed(&key, &params, &mut OsRandom)
        .map_err(|why| format!("no certificate: {why}"))?;
    println!("fingerprint {}", certificate.fingerprint());

    let mut config = Config::new(role, key, certificate, vec![fingerprint]);
    config.srtp_profiles = profiles;
    // this end's own cookie exchange, as a server, is the default and stays
    // on: OpenSSL's s_client has to go through it
    let socket = open(role, address)?;
    let start = Instant::now();
    let mut end = Connection::new(config, &mut OsRandom, start)
        .map_err(|why| format!("the configuration: {why}"))?;
    let mut peer = match role {
        Role::Client => Some(address),
        Role::Server => None,
    };
    let mut buffer = vec![0_u8; 65_536];
    loop {
        if let Some(to) = peer {
            while let Some(datagram) = end.poll_transmit() {
                socket
                    .send_to(&datagram, to)
                    .map_err(|why| format!("send: {why}"))?;
            }
        }
        while let Some(event) = end.poll_event() {
            match event {
                Event::Connected(keys) => {
                    println!(
                        "keyed {:04X} {}",
                        keys.profile().0,
                        hex(&keying_material(&keys))
                    );
                    // the peer's last flight may have to be sent again if
                    // ours was lost; a close tells it the session is over
                    end.close();
                    flush(&socket, &mut end, peer);
                    return Ok(ExitCode::SUCCESS);
                }
                Event::Failed(failure) => {
                    println!("refused {failure:?}");
                    flush(&socket, &mut end, peer);
                    return Ok(ExitCode::from(3));
                }
                Event::ApplicationData(_) | Event::Closed => {}
            }
        }
        let now = Instant::now();
        if now.duration_since(start) > PATIENCE {
            return Err(format!("no outcome after {} s", PATIENCE.as_secs()));
        }
        let wait = end
            .poll_timeout()
            .map_or(Duration::from_millis(200), |deadline| {
                deadline.saturating_duration_since(now)
            })
            .clamp(Duration::from_millis(10), Duration::from_millis(200));
        socket
            .set_read_timeout(Some(wait))
            .map_err(|why| format!("timeout: {why}"))?;
        match socket.recv_from(&mut buffer) {
            Ok((len, from)) => {
                if peer.is_none() {
                    peer = Some(from);
                }
                if peer == Some(from) {
                    end.handle_datagram(buffer.get(..len).unwrap_or_default(), Instant::now());
                }
            }
            Err(why)
                if matches!(
                    why.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            // a client's ICMP port unreachable before the server is up
            Err(why) if why.kind() == std::io::ErrorKind::ConnectionRefused => {}
            Err(why) => return Err(format!("receive: {why}")),
        }
        end.handle_timeout(Instant::now());
    }
}

/// A client's socket, on any port; a server's, bound where it listens.
/// Neither is connected: what arrives from anywhere but the peer is
/// dropped by the loop, and both send with `send_to`.
fn open(role: Role, address: SocketAddr) -> Result<UdpSocket, String> {
    let local = match role {
        Role::Client if address.is_ipv4() => "0.0.0.0:0".parse(),
        Role::Client => "[::]:0".parse(),
        Role::Server => Ok(address),
    }
    .map_err(|why| format!("an address: {why}"))?;
    UdpSocket::bind::<SocketAddr>(local).map_err(|why| format!("bind: {why}"))
}

/// The last datagrams out, an alert or a `close_notify`, sent once and not
/// waited on: the outcome is already decided.
fn flush(socket: &UdpSocket, end: &mut Connection, peer: Option<SocketAddr>) {
    if let Some(to) = peer {
        while let Some(datagram) = end.poll_transmit() {
            let _ = socket.send_to(&datagram, to);
        }
    }
}
