// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! `call.rs`, over TLS instead of a plain UDP socket.
//!
//! Same IVR, same script, same "no account, no configuration" shape — only
//! the transport underneath the signalling changes. `sipral-core` never
//! opens a TLS connection and never will (`docs/01-architecture.md`, "who
//! owns the sockets, the resolver and TLS"): `TransportProtocol::Tls`
//! describes a transport the caller has already secured, bytes go in as
//! `Input::StreamData` fragments rather than whole `Input::Datagram`s, and
//! `sipral_core::msg::StreamFramer` — reached from inside the endpoint, not
//! from here — finds the messages in them on `Content-Length` (§18.3). This
//! file is that application half: a TCP connection wrapped in a TLS client
//! [`rustls`] runs entirely on its own, checked against the platform's trust
//! store the way a real deployment would check a real registrar's
//! certificate.
//!
//! `rustls` is this example's own dependency and nobody else's — behind the
//! `example-tls` feature, off by default, reached by nothing else this crate
//! ships. Run it with
//!
//! ```text
//! cargo run --example tls --features example-tls
//! ```
//!
//! and, exactly like `call.rs`, add `--wav out.wav` on a machine with no
//! audio device. `--pin <sha-256 fingerprint>` trusts the server's
//! certificate by its fingerprint instead of by the platform's trust store —
//! what a PBX serving a certificate it signed itself needs
//! ([`sipral::CertificatePin`], `docs/22-tls.md`).

#[path = "common/entropy.rs"]
mod entropy;
#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/srv.rs"]
mod srv;
#[path = "common/tls_transport.rs"]
mod tls_transport;
#[path = "common/wav.rs"]
mod wav;

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sipral::{
    Account, CallHandle, CertificatePin, CodecCatalog, DEFAULT_DIGIT, EndpointConfig, Event, Input,
    MediaConfig, MediaEngine, MediaEvent, OutgoingCall, TransportId, TransportProtocol, UaEvent,
    Uri, UserAgent, WallClock,
};

#[cfg(any(target_os = "macos", target_os = "ios"))]
use sipral_io_coreaudio::{Stream, StreamConfig, StreamFormat};

use media_socket::MediaSocket;
use tls_transport::{TlsTransport, Trust};

/// sip2sip.info's own test extension, the same one `call.rs` dials — see its
/// own module doc for what it does.
const TARGET: &str = "sip:thetestcall@sip2sip.info";
const HOST: &str = "sip2sip.info";
/// RFC 3261 §19.1's default `sips` port; also what sip2sip.info listens with
/// TLS on.
const TLS_PORT: u16 = 5061;

const GREETING: Duration = Duration::from_millis(1_500);
/// The same script as `call.rs`, and timed the same way for the same reason:
/// the digits wait for the IVR to finish asking for them.
const SCRIPT: &[(Duration, &str)] = &[(GREETING, "2"), (Duration::from_millis(8_000), "1234#")];
const CEILING: Duration = Duration::from_secs(25);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wav_path = wav_path_from_args();

    // the domain's `_sips._tcp` record; the certificate is still checked
    // against the domain itself, which is what RFC 5922 §4 has a client do
    let remote: SocketAddr = srv::resolve(HOST, "_sips._tcp", TLS_PORT)?;
    let now = Instant::now();
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());

    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])?;
    let engine = MediaEngine::new(
        catalog,
        MediaConfig::default(),
        WallClock::from_unix(now, unix_seconds, 0),
        entropy::seed()?,
    );
    let agent = UserAgent::new(EndpointConfig::default(), entropy::seed()?)?;
    let trust = match pin_from_args()? {
        Some(pin) => Trust::Pinned(pin),
        None => Trust::Roots(TlsTransport::platform_roots()),
    };
    let mut endpoint = Endpoint::connect(remote, HOST, trust, agent, engine, now)?;

    let aor = Uri::parse_str("sip:sipral-example@invalid.example")?;
    let contact = Uri::parse_str(&format!("sip:sipral-example@{}", endpoint.local))?;
    let account = endpoint.add_account(Account::unregistered(
        aor,
        contact,
        endpoint.transport,
        remote,
    ));

    let outgoing =
        OutgoingCall::new(Uri::parse_str(TARGET)?).to_address(endpoint.transport, remote);
    let call = place(&mut endpoint, account, outgoing, now)?;
    println!("calling {TARGET} over TLS ...");

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let mut speaker = if wav_path.is_none() {
        let mut stream = Stream::open(StreamConfig::new(StreamFormat::narrowband()))?;
        stream.start()?;
        Some(stream)
    } else {
        None
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let (heard, sample_rate_hz) = converse(&mut endpoint, call, |room| {
        if let Some(stream) = speaker.as_mut() {
            let _ = stream.write(room);
        }
    });
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let (heard, sample_rate_hz) = converse(&mut endpoint, call, |_room| {});

    if let Some(path) = wav_path_or_default(wav_path) {
        wav::write(&path, sample_rate_hz, &heard)?;
        println!("wrote {} samples ({path})", heard.len());
    }
    Ok(())
}

/// The call itself, once it is placed — identical in shape to `call.rs`'s own
/// [`converse`], because nothing about running the call differs once the SIP
/// bytes are already flowing; only how they got there does.
fn converse(
    endpoint: &mut Endpoint,
    call: CallHandle,
    mut play: impl FnMut(&[i16]),
) -> (Vec<i16>, u32) {
    let mut heard: Vec<i16> = Vec::new();
    let mut sample_rate_hz = 8_000_u32;
    let mut confirmed_at: Option<Instant> = None;
    let mut next_step = 0_usize;
    let mut ended = false;
    let deadline = Instant::now() + CEILING;

    while !ended && Instant::now() < deadline {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::CallConfirmed { call: this, .. }) if this == call => {
                    println!("connected");
                    confirmed_at = Some(now);
                }
                Event::Signalling(UaEvent::CallEnded {
                    call: this, reason, ..
                }) if this == call => {
                    println!("call ended: {reason}");
                    ended = true;
                }
                Event::Media {
                    call: this,
                    event: MediaEvent::Started { codec, .. },
                } if this == call => {
                    println!("media started on {}", codec.encoding_name());
                }
                _ => {}
            }
        }

        next_step = send_scripted_digit(endpoint, call, confirmed_at, next_step, now);

        endpoint.run_media(now, |this, media, session, now| {
            if this != call {
                return;
            }
            sample_rate_hz = session.sample_rate();
            media.turn(
                session,
                now,
                |room| room.fill(0),
                |room| {
                    heard.extend_from_slice(room);
                    play(room);
                },
            );
        });

        endpoint.timers(now);
        if !endpoint.read_stream(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    if !ended {
        hang_up_and_drain(endpoint, call);
    }
    (heard, sample_rate_hz)
}

/// The next entry of [`SCRIPT`] due, if the call has connected and its time
/// has come: sent, and the index of the one after it. Otherwise `next_step`
/// unchanged.
fn send_scripted_digit(
    endpoint: &mut Endpoint,
    call: CallHandle,
    confirmed_at: Option<Instant>,
    next_step: usize,
    now: Instant,
) -> usize {
    let Some(started) = confirmed_at else {
        return next_step;
    };
    let Some((at, digits)) = SCRIPT.get(next_step) else {
        return next_step;
    };
    if now < started + *at {
        return next_step;
    }
    if let Some(mut session) = endpoint.engine.session(call) {
        println!("sending {digits}");
        let _ = session.dial(digits, DEFAULT_DIGIT);
    }
    next_step + 1
}

/// Hang up a call [`converse`] gave up on rather than one the far end ended,
/// and give the BYE a moment to actually leave before the process does.
fn hang_up_and_drain(endpoint: &mut Endpoint, call: CallHandle) {
    let _ = endpoint.agent.hangup(call, Instant::now());
    let settle = Instant::now() + Duration::from_millis(500);
    while Instant::now() < settle {
        let now = Instant::now();
        endpoint.pump(now);
        endpoint.timers(now);
        if !endpoint.read_stream(now) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// `--wav <path>`, when it was given.
fn wav_path_from_args() -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--wav" {
            return args.next();
        }
    }
    None
}

/// What `--pin` named, read as a SHA-256 fingerprint.
fn pin_from_args() -> Result<Option<CertificatePin>, sipral::PinError> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--pin" {
            return args
                .next()
                .as_deref()
                .map(CertificatePin::parse)
                .transpose();
        }
    }
    Ok(None)
}

/// Where to write the WAV file: what `--wav` named, or, on a target with no
/// audio device to play through instead, `tls.wav`.
fn wav_path_or_default(explicit: Option<String>) -> Option<String> {
    if explicit.is_some() {
        return explicit;
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        Some("tls.wav".to_owned())
    }
}

// -- the SIP and media endpoint on top of the TLS transport -------------------

/// A user agent and a media engine, with the TLS connection above for SIP and
/// a plain UDP socket per call for RTP — `sips:` secures the signalling, not
/// the media, and nothing here asks it to.
struct Endpoint {
    agent: UserAgent,
    engine: MediaEngine,
    sip: TlsTransport,
    local: SocketAddr,
    transport: TransportId,
    media: HashMap<CallHandle, MediaSocket>,
}

impl Endpoint {
    fn connect(
        remote: SocketAddr,
        server_name: &str,
        trust: Trust,
        mut agent: UserAgent,
        engine: MediaEngine,
        now: Instant,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let sip = TlsTransport::connect(remote, server_name, trust)?;
        let local = sip.tcp.local_addr()?;
        let transport = TransportId(1);
        agent.receive(
            Input::TransportBound {
                transport,
                protocol: TransportProtocol::Tls,
                local,
                remote: Some(remote),
            },
            now,
        )?;
        Ok(Self {
            agent,
            engine,
            sip,
            local,
            transport,
            media: HashMap::new(),
        })
    }

    fn pump(&mut self, now: Instant) -> Vec<Event> {
        self.flush();
        let mut events = Vec::new();
        while let Some(event) = self.engine.poll_event(&mut self.agent, now) {
            events.push(event);
        }
        events
    }

    fn flush(&mut self) {
        while let Some(transmit) = self.agent.poll_transmit() {
            let _ = self.sip.send(&transmit.payload);
        }
    }

    /// Read whatever the TLS connection has, and feed it in as the byte
    /// stream it is (`Input::StreamData`) rather than as a whole datagram —
    /// the one difference this endpoint has from `common/udp_endpoint.rs`'s.
    /// A connection the peer closed is reported as `Input::StreamClosed`, the
    /// same way a real transport would, so `sipral-core` fails whatever was
    /// waiting on it instead of a caller here quietly polling a dead socket
    /// until its own ceiling gives up on it.
    fn read_stream(&mut self, now: Instant) -> bool {
        let Self {
            sip,
            agent,
            transport,
            ..
        } = self;
        let outcome = sip.poll(|chunk| {
            let _ = agent.receive(
                Input::StreamData {
                    transport: *transport,
                    data: chunk,
                },
                now,
            );
        });
        match outcome {
            Ok(outcome) => {
                if outcome.closed {
                    let _ = agent.receive(
                        Input::StreamClosed {
                            transport: *transport,
                        },
                        now,
                    );
                }
                outcome.moved
            }
            Err(_) => false,
        }
    }

    fn run_media(
        &mut self,
        now: Instant,
        mut per_call: impl FnMut(CallHandle, &mut MediaSocket, &mut sipral::MediaSession, Instant),
    ) {
        for call in self.engine.active().collect::<Vec<_>>() {
            let Some(mut session) = self.engine.session(call) else {
                continue;
            };
            if let Some(media) = self.media.get_mut(&call) {
                per_call(call, media, &mut session, now);
            }
        }
        while let Some((call, destination, payload)) = self.engine.poll_rtcp(now) {
            if let Some(media) = self.media.get(&call) {
                media.send_rtcp(destination, &payload);
            }
        }
        while let Some((call, destination, payload)) = self.engine.poll_farewell() {
            if let Some(media) = self.media.get(&call) {
                media.send_rtcp(destination, &payload);
            }
        }
        #[cfg(any(feature = "dtls", feature = "ice"))]
        while let Some((call, destination, payload)) = self.engine.poll_transmit(now) {
            if let Some(media) = self.media.get(&call) {
                media.send(destination, &payload);
            }
        }
    }

    fn timers(&mut self, now: Instant) {
        self.engine.handle_timeout(now);
        self.agent.handle_timeout(now);
    }

    fn add_account(&mut self, account: Account) -> sipral::AccountId {
        self.agent.add_account(account)
    }
}

/// Bind an RTP socket, place `outgoing` on it, and remember the socket under
/// the call handle placing it mints — the same reordering
/// `common/udp_endpoint.rs::place` exists for, and for the same reason.
///
/// # Errors
/// Whatever binding the RTP socket or placing the call returns.
fn place(
    endpoint: &mut Endpoint,
    account: sipral::AccountId,
    outgoing: OutgoingCall,
    now: Instant,
) -> Result<CallHandle, Box<dyn std::error::Error>> {
    let media = MediaSocket::bind(now)?;
    let port = media.port()?;
    let local = SocketAddr::new(endpoint.local.ip(), port);
    let call = endpoint
        .engine
        .place(&mut endpoint.agent, account, outgoing, local, now)?;
    endpoint.media.insert(call, media);
    Ok(call)
}

#[cfg(test)]
mod tests {
    // this test's own shortcuts; the no-panic discipline above is for what
    // ships
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use std::io::{self, Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;
    use std::thread;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig, ServerConnection};

    use super::*;

    /// `sip2sip.info`'s own reachability from a given machine says nothing
    /// about whether this file's transport is right; this does, against a
    /// server on loopback with a certificate minted for the test alone
    /// (never committed, never reused) and forgotten the moment it ends: a
    /// TLS handshake completes, and a SIP-shaped byte stream both directions
    /// write survives it whole — through [`TlsTransport`] exactly as
    /// `Endpoint` drives it, not around it.
    #[test]
    fn handshake_and_stream_survive_the_round_trip() {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(signed.cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(signed.signing_key.serialize_der());

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let remote = listener.local_addr().unwrap();

        const REQUEST: &[u8] = b"OPTIONS sip:test@localhost SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        const RESPONSE: &[u8] = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";

        let server_cert = cert_der.clone();
        let server = thread::spawn(move || -> Vec<u8> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![server_cert], PrivateKeyDer::Pkcs8(key_der))
                .unwrap();
            let mut conn = ServerConnection::new(Arc::new(config)).unwrap();
            let (mut tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

            let mut request = vec![0_u8; REQUEST.len()];
            tls.read_exact(&mut request).unwrap();
            tls.write_all(RESPONSE).unwrap();
            request
        });

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client = TlsTransport::connect(remote, "localhost", Trust::Roots(roots)).unwrap();

        let mut sent = false;
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while received.len() < RESPONSE.len() && Instant::now() < deadline {
            if !sent {
                sent = client.send(REQUEST).is_ok();
            }
            let _ = client.poll(|chunk| received.extend_from_slice(chunk));
            thread::sleep(Duration::from_millis(5));
        }

        let request_the_server_saw = server.join().expect("the server thread panicked");
        assert_eq!(
            request_the_server_saw, REQUEST,
            "the server read something other than what the client sent"
        );
        assert_eq!(
            received, RESPONSE,
            "the client read something other than what the server sent"
        );
    }

    /// A server on loopback with a self-signed certificate for `name`, valid
    /// between the two years, answering one request; its certificate in DER
    /// and its address. What it read, or why the handshake failed, comes
    /// back from the thread.
    fn pbx(
        name: &str,
        from: i32,
        until: i32,
    ) -> (Vec<u8>, SocketAddr, thread::JoinHandle<io::Result<Vec<u8>>>) {
        let (der, key) = mint(name, from, until);
        let key_der = PrivatePkcs8KeyDer::from(key.serialize_der());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let remote = listener.local_addr().unwrap();
        let server_cert = CertificateDer::from(der.clone());
        let server = thread::spawn(move || -> io::Result<Vec<u8>> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![server_cert], PrivateKeyDer::Pkcs8(key_der))
                .unwrap();
            let mut conn = ServerConnection::new(Arc::new(config)).unwrap();
            let (mut tcp, _) = listener.accept()?;
            tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let mut request = vec![0_u8; PING.len()];
            tls.read_exact(&mut request)?;
            tls.write_all(PONG)?;
            Ok(request)
        });
        (der, remote, server)
    }

    /// A self-signed certificate for `name`, valid between the two years, in
    /// DER, and its key.
    fn mint(name: &str, from: i32, until: i32) -> (Vec<u8>, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.not_before = rcgen::date_time_ymd(from, 1, 1);
        params.not_after = rcgen::date_time_ymd(until, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        (der, key)
    }

    const PING: &[u8] = b"OPTIONS sip:pbx SIP/2.0\r\nContent-Length: 0\r\n\r\n";
    const PONG: &[u8] = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";

    /// Send `PING` and read until `PONG` has arrived, the connection fails,
    /// or ten seconds pass.
    fn exchange(client: &mut TlsTransport) -> io::Result<Vec<u8>> {
        let mut sent = false;
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while received.len() < PONG.len() && Instant::now() < deadline {
            if !sent {
                client.send(PING)?;
                sent = true;
            }
            let outcome = client.poll(|chunk| received.extend_from_slice(chunk))?;
            if outcome.closed {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(received)
    }

    /// The PBX's own certificate, trusted by its fingerprint alone: a name
    /// that does not match and no root that vouches for it, and the
    /// connection carries SIP both ways.
    #[test]
    fn a_pinned_self_signed_certificate_is_trusted_by_its_fingerprint_alone() {
        let (der, remote, server) = pbx("factory-default.invalid", 2024, 2099);
        let pin = CertificatePin::parse(&CertificatePin::of(&der).to_string()).unwrap();
        let mut client = TlsTransport::connect(remote, "localhost", Trust::Pinned(pin)).unwrap();
        assert_eq!(exchange(&mut client).unwrap(), PONG);
        assert_eq!(server.join().unwrap().unwrap(), PING);
    }

    /// Any other certificate is refused in the handshake, before a byte of
    /// SIP is written to it.
    #[test]
    fn a_certificate_other_than_the_pinned_one_is_refused_in_the_handshake() {
        let (_, remote, server) = pbx("localhost", 2024, 2099);
        let (other, _) = mint("localhost", 2024, 2099);
        let pin = CertificatePin::of(&other);
        let mut client = TlsTransport::connect(remote, "localhost", Trust::Pinned(pin)).unwrap();
        let refused = exchange(&mut client).expect_err("the handshake is refused");
        assert!(refused.to_string().contains("certificate"), "{refused}");
        assert!(
            server.join().unwrap().is_err(),
            "the server read no request"
        );
    }

    /// The certificate lapsed years ago, and it is still the pinned one: the
    /// connection goes, as `sipral::CertificatePin` decides.
    #[test]
    fn an_expired_pinned_certificate_still_connects() {
        let (der, remote, server) = pbx("localhost", 2018, 2020);
        let pin = CertificatePin::of(&der);
        let mut client = TlsTransport::connect(remote, "localhost", Trust::Pinned(pin)).unwrap();
        assert_eq!(exchange(&mut client).unwrap(), PONG);
        assert_eq!(server.join().unwrap().unwrap(), PING);
    }
}
