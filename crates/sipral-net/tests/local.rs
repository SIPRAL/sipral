// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The network against servers of its own on loopback: a TLS server with a throwaway authority,
//! with and without a client certificate required, and a DNS server answering from a table.
//!
//! Nothing here reaches past `127.0.0.1`, and nothing is committed: every certificate is made for
//! the run.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SRV};
use hickory_proto::rr::{Name, RData, Record as DnsRecord, RecordType as DnsType};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use sipral_core::endpoint::{
    AddressFamily, Answer, Query, Record, RecordType, TransportErrorKind, TransportId,
    TransportProtocol,
};
use sipral_core::msg::Uri;
use sipral_core::pin::CertificatePin;
use sipral_net::{
    ClientCertificate, DomainRules, Failure, Happening, Network, NetworkConfig, Resolver,
    StreamTarget, TlsFailure, Trust,
};

const NAME: &str = "pbx.test";

/// A throwaway authority, and certificates it signs.
struct Pki {
    params: CertificateParams,
    key: KeyPair,
    der: CertificateDer<'static>,
    pem: String,
}

impl Pki {
    fn new(common_name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params.self_signed(&key).unwrap();
        Self {
            der: certificate.der().clone(),
            pem: certificate.pem(),
            params,
            key,
        }
    }

    /// A leaf for `names`, valid now unless `expired`, and its PEM.
    fn leaf(&self, names: &[&str], expired: bool) -> (Vec<CertificateDer<'static>>, KeyPair) {
        let (chain, key, _) = self.leaf_pem(names, expired);
        (chain, key)
    }

    /// A leaf whose `subjectAltName` is `names`, as they are, valid now.
    fn leaf_naming(&self, names: Vec<SanType>) -> (Vec<CertificateDer<'static>>, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = names;
        let issuer = Issuer::from_params(&self.params, &self.key);
        let certificate = params.signed_by(&key, &issuer).unwrap();
        (vec![certificate.der().clone()], key)
    }

    fn leaf_pem(
        &self,
        names: &[&str],
        expired: bool,
    ) -> (Vec<CertificateDer<'static>>, KeyPair, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        if expired {
            params.not_before = date_time_ymd(2020, 1, 1);
            params.not_after = date_time_ymd(2020, 1, 2);
        }
        let issuer = Issuer::from_params(&self.params, &self.key);
        let certificate = params.signed_by(&key, &issuer).unwrap();
        (vec![certificate.der().clone()], key, certificate.pem())
    }
}

fn private(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

/// What a server is made with.
struct Serving {
    chain: Vec<CertificateDer<'static>>,
    key: KeyPair,
    /// Require a client certificate this authority signed.
    clients: Option<CertificateDer<'static>>,
    tls12_only: bool,
}

/// A TLS server on loopback that echoes what it reads, one connection at a time.
fn tls_server(serving: Serving) -> SocketAddr {
    let config = server_config(serving);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { continue };
            let config = Arc::clone(&config);
            thread::spawn(move || {
                tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut stream = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
                let mut buffer = [0_u8; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).is_err() {
                                return;
                            }
                            let _ = stream.flush();
                        }
                    }
                }
            });
        }
    });
    address
}

/// When a server that says `close_notify` goes on sending bytes after it, which RFC 8446 §6.1
/// has the client ignore.
#[derive(Clone, Copy, Debug)]
enum Afterwards {
    /// Right after the handshake, with a stray byte a moment later.
    AtOnce,
    /// On the client's first message, with 5000 stray bytes in the same write.
    InOneWrite,
    /// On the client's first message, after its echo in the same write, with a stray byte a
    /// moment later.
    AfterAnEcho,
}

/// A TLS server on loopback for one connection, which closes it as `afterwards` says and keeps
/// the socket open after.
fn closing_tls_server(serving: Serving, afterwards: Afterwards) -> SocketAddr {
    let config = server_config(serving);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let Ok((mut tcp, _)) = listener.accept() else {
            return;
        };
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut server = ServerConnection::new(config).unwrap();
        while server.is_handshaking() {
            if server.complete_io(&mut tcp).is_err() {
                return;
            }
        }
        if !matches!(afterwards, Afterwards::AtOnce) {
            let mut buffer = [0_u8; 4096];
            let Ok(read) = rustls::Stream::new(&mut server, &mut tcp).read(&mut buffer) else {
                return;
            };
            if matches!(afterwards, Afterwards::AfterAnEcho) {
                server.writer().write_all(&buffer[..read]).unwrap();
            }
        }
        server.send_close_notify();
        let mut wire = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut wire).unwrap();
        }
        if matches!(afterwards, Afterwards::InOneWrite) {
            wire.extend_from_slice(&[0x17; 5000]);
        }
        if tcp.write_all(&wire).is_err() {
            return;
        }
        if !matches!(afterwards, Afterwards::InOneWrite) {
            thread::sleep(Duration::from_millis(300));
            if tcp.write_all(b"x").is_err() {
                return;
            }
        }
        let mut rest = [0_u8; 64];
        while matches!(tcp.read(&mut rest), Ok(read) if read > 0) {}
    });
    address
}

/// The rustls configuration a test server is made with.
fn server_config(serving: Serving) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if serving.tls12_only {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .unwrap();
    let builder = match serving.clients {
        Some(authority) => {
            let mut roots = RootCertStore::empty();
            roots.add(authority).unwrap();
            builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                    .build()
                    .unwrap(),
            )
        }
        None => builder.with_no_client_auth(),
    };
    Arc::new(
        builder
            .with_single_cert(serving.chain, private(&serving.key))
            .unwrap(),
    )
}

/// A plain TCP server on loopback that echoes.
fn tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(mut tcp) = tcp else { continue };
            thread::spawn(move || {
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = tcp.read(&mut buffer) {
                    if read == 0 || tcp.write_all(&buffer[..read]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

fn network(trust: Trust, client: Option<ClientCertificate>) -> Network {
    let mut config = NetworkConfig::default();
    config.trust = trust;
    config.client_certificate = client;
    config.connect_timeout = Duration::from_secs(5);
    Network::new(config).unwrap()
}

/// Everything the network says until `done` picks something out, or ten seconds pass.
fn until<T>(network: &mut Network, mut done: impl FnMut(Happening) -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        for happening in network.wait(Some(Duration::from_millis(100))) {
            if let Some(found) = done(happening) {
                return found;
            }
        }
    }
    panic!("nothing came in ten seconds");
}

/// Connect `transport`, and the connection's outcome.
fn dial(
    network: &mut Network,
    protocol: TransportProtocol,
    remote: SocketAddr,
    target: StreamTarget,
) -> Result<SocketAddr, Failure> {
    let transport = TransportId(7);
    network.connect(transport, protocol, remote, target);
    until(network, |happening| match happening {
        Happening::Connected { local, .. } => Some(Ok(local)),
        Happening::ConnectFailed { failure, .. } => Some(Err(failure)),
        _ => None,
    })
}

/// Send `message` on the connection and read the echo back whole.
fn echoed(network: &mut Network, message: &[u8]) -> Vec<u8> {
    let transport = TransportId(7);
    network
        .send(transport, "127.0.0.1:9".parse().unwrap(), message)
        .unwrap();
    let mut heard = Vec::new();
    until(network, |happening| {
        if let Happening::StreamData { data, .. } = happening {
            heard.extend_from_slice(&data);
        }
        (heard.len() >= message.len()).then(|| heard.clone())
    })
}

fn named(name: &str) -> StreamTarget {
    StreamTarget::new(Some(name.to_owned()), None)
}

#[test]
fn a_tls_connection_to_a_private_authority_carries_messages_both_ways() {
    let pki = Pki::new("Sipral test authority");
    let (chain, key) = pki.leaf(&[NAME], false);
    let server = tls_server(Serving {
        chain,
        key,
        clients: None,
        tls12_only: false,
    });
    let mut network = network(Trust::Only(vec![pki.der.clone()]), None);
    let local = dial(&mut network, TransportProtocol::Tls, server, named(NAME)).unwrap();
    assert!(local.ip().is_loopback());
    let message = b"OPTIONS sip:pbx.test SIP/2.0\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(echoed(&mut network, message), message);
}

#[test]
fn the_authority_read_from_pem_is_trusted_beside_or_instead_of_the_platforms() {
    let pki = Pki::new("Sipral test authority");
    let roots = Trust::authorities_from_pem(pki.pem.as_bytes()).unwrap();
    assert_eq!(roots.len(), 1);
    let (chain, key) = pki.leaf(&[NAME], false);
    let server = tls_server(Serving {
        chain,
        key,
        clients: None,
        tls12_only: true,
    });
    let mut only = network(Trust::Only(roots.clone()), None);
    dial(&mut only, TransportProtocol::Tls, server, named(NAME)).unwrap();
    assert_eq!(echoed(&mut only, b"ping"), b"ping");

    let mut beside = network(Trust::PlatformAnd(roots), None);
    dial(&mut beside, TransportProtocol::Tls, server, named(NAME)).unwrap();
    assert_eq!(echoed(&mut beside, b"pong"), b"pong");
}

#[test]
fn every_refused_server_certificate_says_why() {
    let pki = Pki::new("Sipral test authority");
    let only = || network(Trust::Only(vec![pki.der.clone()]), None);
    let serve = |names: &[&str], expired| {
        let (chain, key) = pki.leaf(names, expired);
        tls_server(Serving {
            chain,
            key,
            clients: None,
            tls12_only: false,
        })
    };

    let other_name = serve(&["wrong.test"], false);
    let refused = dial(&mut only(), TransportProtocol::Tls, other_name, named(NAME)).unwrap_err();
    assert_eq!(refused.tls, TlsFailure::NameMismatch, "{refused}");
    assert_eq!(refused.error, TransportErrorKind::ConnectionReset);
    assert!(refused.detail.starts_with("TLS to 127.0.0.1:"), "{refused}");

    let expired = serve(&[NAME], true);
    let refused = dial(&mut only(), TransportProtocol::Tls, expired, named(NAME)).unwrap_err();
    assert_eq!(refused.tls, TlsFailure::Expired, "{refused}");

    // the platform has never heard of this authority
    let good = serve(&[NAME], false);
    let refused = dial(
        &mut network(Trust::Platform, None),
        TransportProtocol::Tls,
        good,
        named(NAME),
    )
    .unwrap_err();
    assert_eq!(refused.tls, TlsFailure::Untrusted, "{refused}");

    let stranger = Pki::new("Another authority");
    let refused = dial(
        &mut network(Trust::Only(vec![stranger.der.clone()]), None),
        TransportProtocol::Tls,
        good,
        named(NAME),
    )
    .unwrap_err();
    assert_eq!(refused.tls, TlsFailure::Untrusted, "{refused}");
}

#[test]
fn a_sip_uri_names_the_domain_and_rfc_5922_alone_refuses_a_wildcard() {
    let pki = Pki::new("Sipral test authority");
    let uri = |text: &str| SanType::URI(text.try_into().unwrap());
    let dns = |text: &str| SanType::DnsName(text.try_into().unwrap());
    let serve = |names: Vec<SanType>| {
        let (chain, key) = pki.leaf_naming(names);
        tls_server(Serving {
            chain,
            key,
            clients: None,
            tls12_only: false,
        })
    };
    let under = |rules: DomainRules| {
        let mut config = NetworkConfig::default();
        config.trust = Trust::Only(vec![pki.der.clone()]);
        config.connect_timeout = Duration::from_secs(5);
        config.domain_rules = rules;
        Network::new(config).unwrap()
    };
    let verdict = |server: SocketAddr, name: &str, rules: DomainRules| {
        dial(
            &mut under(rules),
            TransportProtocol::Tls,
            server,
            named(name),
        )
        .map(|_| ())
    };
    let mismatch = |outcome: Result<(), Failure>, what: &str| match outcome {
        Err(refused) => assert_eq!(refused.tls, TlsFailure::NameMismatch, "{what}: {refused}"),
        Ok(()) => panic!("{what} was accepted"),
    };

    // RFC 5922's own form, which the HTTPS rules never read
    let by_uri = serve(vec![uri("sip:pbx.test")]);
    for rules in [DomainRules::Platform, DomainRules::Rfc5922] {
        verdict(by_uri, NAME, rules).unwrap_or_else(|refused| panic!("{rules:?}: {refused}"));
    }

    let wildcard = serve(vec![dns("*.example.test")]);
    verdict(wildcard, "pbx.example.test", DomainRules::Platform).unwrap();
    mismatch(
        verdict(wildcard, "pbx.example.test", DomainRules::Rfc5922),
        "a wildcard under RFC 5922 alone",
    );

    // while a sip: URI is there, RFC 5922 counts no DNS name
    let elsewhere = serve(vec![uri("sip:other.test"), dns(NAME)]);
    verdict(elsewhere, NAME, DomainRules::Platform).unwrap();
    mismatch(
        verdict(elsewhere, NAME, DomainRules::Rfc5922),
        "a DNS name beside a sip: URI for another domain",
    );

    let by_dns = serve(vec![dns(NAME)]);
    verdict(by_dns, NAME, DomainRules::Rfc5922).unwrap();

    let other = serve(vec![uri("sip:other.test")]);
    for rules in [DomainRules::Platform, DomainRules::Rfc5922] {
        mismatch(verdict(other, NAME, rules), "a sip: URI for another domain");
    }
}

#[test]
fn a_pinned_certificate_is_the_whole_verdict() {
    let pki = Pki::new("Sipral test authority");
    // another name, and expired: a pin looks at neither
    let (chain, key) = pki.leaf(&["factory-name.local"], true);
    let pin = CertificatePin::of(chain[0].as_ref());
    let server = tls_server(Serving {
        chain,
        key,
        clients: None,
        tls12_only: false,
    });
    let mut pinned = network(Trust::Pinned(pin), None);
    dial(&mut pinned, TransportProtocol::Tls, server, named(NAME)).unwrap();
    assert_eq!(echoed(&mut pinned, b"pinned"), b"pinned");

    // a connection's own pin wins over the network's trust
    let mut platform = network(Trust::Platform, None);
    dial(
        &mut platform,
        TransportProtocol::Tls,
        server,
        StreamTarget::new(Some(NAME.to_owned()), Some(pin)),
    )
    .unwrap();

    let other = CertificatePin::of(pki.der.as_ref());
    let refused = dial(
        &mut network(Trust::Pinned(other), None),
        TransportProtocol::Tls,
        server,
        named(NAME),
    )
    .unwrap_err();
    assert_eq!(refused.tls, TlsFailure::Untrusted, "{refused}");
}

#[test]
fn a_server_that_requires_a_client_certificate_is_told_apart_from_one_that_refuses_it() {
    let pki = Pki::new("Sipral test authority");
    let clients = Pki::new("Sipral client authority");
    for tls12_only in [false, true] {
        let (chain, key) = pki.leaf(&[NAME], false);
        let server = tls_server(Serving {
            chain,
            key,
            clients: Some(clients.der.clone()),
            tls12_only,
        });

        let refused = dial(
            &mut network(Trust::Only(vec![pki.der.clone()]), None),
            TransportProtocol::Tls,
            server,
            named(NAME),
        )
        .unwrap_err();
        assert_eq!(
            refused.tls,
            TlsFailure::ClientCertificateRequired,
            "TLS 1.2 only {tls12_only}: {refused}"
        );

        let stranger = Pki::new("Another authority");
        let (_, key, pem) = stranger.leaf_pem(&["client.test"], false);
        let strangers =
            ClientCertificate::from_pem(pem.as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        let refused = dial(
            &mut network(Trust::Only(vec![pki.der.clone()]), Some(strangers)),
            TransportProtocol::Tls,
            server,
            named(NAME),
        )
        .unwrap_err();
        assert_eq!(
            refused.tls,
            TlsFailure::ClientCertificateRefused,
            "TLS 1.2 only {tls12_only}: {refused}"
        );

        let (_, key, pem) = clients.leaf_pem(&["client.test"], false);
        let ours =
            ClientCertificate::from_pem(pem.as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        let mut network = network(Trust::Only(vec![pki.der.clone()]), Some(ours));
        dial(&mut network, TransportProtocol::Tls, server, named(NAME)).unwrap();
        assert_eq!(echoed(&mut network, b"admitted"), b"admitted");
    }
}

#[test]
fn plain_tcp_carries_messages_and_nothing_listening_is_refused() {
    let server = tcp_server();
    let mut network = network(Trust::Platform, None);
    dial(
        &mut network,
        TransportProtocol::Tcp,
        server,
        StreamTarget::default(),
    )
    .unwrap();
    assert_eq!(echoed(&mut network, b"over tcp"), b"over tcp");

    let gone = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = gone.local_addr().unwrap();
    drop(gone);
    let refused = dial(
        &mut network,
        TransportProtocol::Tcp,
        address,
        StreamTarget::default(),
    )
    .unwrap_err();
    assert_eq!(refused.error, TransportErrorKind::ConnectionRefused);
}

#[test]
fn a_plain_tcp_write_the_server_never_reads_gives_up_and_the_connection_ends() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = listener.local_addr().unwrap();
    let (keep, kept) = mpsc::channel::<()>();
    thread::spawn(move || {
        // accepted and never read, and held open until the test is done
        let held = listener.accept();
        let _ = kept.recv();
        drop(held);
    });
    let mut config = NetworkConfig::default();
    config.connect_timeout = Duration::from_secs(3);
    let mut network = Network::new(config).unwrap();
    dial(
        &mut network,
        TransportProtocol::Tcp,
        server,
        StreamTarget::default(),
    )
    .unwrap();
    let sender = network.stream_sender(TransportId(7)).unwrap();
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        // an audio thread's writes, only faster: the buffers fill and a write stops returning
        let chunk = vec![0_u8; 64 * 1024];
        let refused = loop {
            if let Err(error) = sender.send(&chunk) {
                break error;
            }
        };
        let _ = done.send(refused.kind());
    });
    assert!(
        finished.recv_timeout(Duration::from_secs(30)).is_ok(),
        "a write to a server that never reads never gave up"
    );
    // half a message is on the wire: nothing after it can be read, so the connection ends
    until(&mut network, |happening| match happening {
        Happening::StreamClosed { transport } | Happening::StreamFailed { transport, .. }
            if transport == TransportId(7) =>
        {
            Some(())
        }
        _ => None,
    });
    drop(keep);
}

#[test]
fn a_connection_closed_while_it_was_being_made_is_never_reported() {
    let pki = Pki::new("Sipral test authority");
    let (chain, key) = pki.leaf(&[NAME], false);
    let server = tls_server(Serving {
        chain,
        key,
        clients: None,
        tls12_only: false,
    });
    let mut network = network(Trust::Only(vec![pki.der.clone()]), None);
    network.connect(TransportId(9), TransportProtocol::Tls, server, named(NAME));
    assert!(network.close(TransportId(9)));
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let heard = network.wait(Some(Duration::from_millis(100)));
        assert!(heard.is_empty(), "a closed connection said {heard:?}");
    }
    let refused = network
        .send(TransportId(9), server, b"too late")
        .unwrap_err();
    assert_eq!(refused.error, TransportErrorKind::Closed);
}

#[test]
fn bytes_after_a_close_notify_end_the_connection_and_never_hold_its_writer() {
    let pki = Pki::new("Sipral test authority");
    let message = b"OPTIONS sip:pbx.test SIP/2.0\r\nContent-Length: 0\r\n\r\n";
    for afterwards in [
        Afterwards::AtOnce,
        Afterwards::InOneWrite,
        Afterwards::AfterAnEcho,
    ] {
        let (chain, key) = pki.leaf(&[NAME], false);
        let server = closing_tls_server(
            Serving {
                chain,
                key,
                clients: None,
                tls12_only: false,
            },
            afterwards,
        );
        let mut network = network(Trust::Only(vec![pki.der.clone()]), None);
        network.connect(TransportId(7), TransportProtocol::Tls, server, named(NAME));
        let mut heard = Vec::new();
        let mut closed = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !closed && Instant::now() < deadline {
            for happening in network.wait(Some(Duration::from_millis(100))) {
                match happening {
                    Happening::Connected { early, .. } => {
                        heard.extend_from_slice(&early);
                        // `None` when the close came in the same wait, and nothing can be
                        // held any more
                        if let Some(sender) = network.stream_sender(TransportId(7)) {
                            if !matches!(afterwards, Afterwards::AtOnce) {
                                sender.send(message).unwrap();
                            }
                            // the stray bytes are in by then
                            thread::sleep(Duration::from_secs(1));
                            let (done, finished) = mpsc::channel();
                            thread::spawn(move || {
                                let _ = sender.send(b"too late");
                                let _ = done.send(());
                            });
                            assert!(
                                finished.recv_timeout(Duration::from_secs(10)).is_ok(),
                                "{afterwards:?}: a write waited on the reader"
                            );
                        }
                    }
                    Happening::ConnectFailed { failure, .. }
                    | Happening::StreamFailed { failure, .. } => {
                        panic!("{afterwards:?}: {failure:?}")
                    }
                    Happening::StreamData { data, .. } => heard.extend_from_slice(&data),
                    Happening::StreamClosed { .. } => closed = true,
                    _ => {}
                }
            }
        }
        assert!(closed, "{afterwards:?}: the close was never heard");
        let echo: &[u8] = if matches!(afterwards, Afterwards::AfterAnEcho) {
            message
        } else {
            b""
        };
        assert_eq!(heard, echo, "{afterwards:?}");
    }
}

#[test]
fn datagrams_and_media_arrive_with_both_addresses() {
    let mut network = network(Trust::Platform, None);
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let signalling = network.bind_datagram(TransportId(0), loopback).unwrap();
    let media = network.open_media(loopback).unwrap();
    assert_ne!(signalling.port(), 0);

    let far = UdpSocket::bind(loopback).unwrap();
    far.send_to(b"REGISTER", signalling).unwrap();
    far.send_to(b"rtp", media).unwrap();
    let mut seen = (false, false);
    let far_end = far.local_addr().unwrap();
    until(&mut network, |happening| {
        match happening {
            Happening::Datagram {
                transport,
                remote,
                local,
                data,
            } => {
                assert_eq!(
                    (transport, remote, local),
                    (TransportId(0), far_end, signalling)
                );
                assert_eq!(data, b"REGISTER");
                seen.0 = true;
            }
            Happening::Media {
                local,
                remote,
                data,
            } => {
                assert_eq!(
                    (local, remote, data.as_slice()),
                    (media, far_end, &b"rtp"[..])
                );
                seen.1 = true;
            }
            other => panic!("{other:?}"),
        }
        (seen.0 && seen.1).then_some(())
    });

    network.send(TransportId(0), far_end, b"200").unwrap();
    network.send_media(media, far_end, b"rtcp").unwrap();
    let mut buffer = [0_u8; 64];
    far.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (read, from) = far.recv_from(&mut buffer).unwrap();
    assert_eq!((&buffer[..read], from), (&b"200"[..], signalling));
    let (read, from) = far.recv_from(&mut buffer).unwrap();
    assert_eq!((&buffer[..read], from), (&b"rtcp"[..], media));

    assert!(network.close_media(media));
    assert!(network.send_media(media, far_end, b"gone").is_err());
    let wildcard = network
        .bind_datagram(TransportId(1), "0.0.0.0:0".parse().unwrap())
        .unwrap_err();
    assert_eq!(wildcard.kind(), ErrorKind::InvalidInput);
}

/// A name server on loopback that answers from `table`, and NXDOMAIN for any other name.
fn dns_server(table: HashMap<(String, DnsType), Vec<RData>>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok((read, from)) = socket.recv_from(&mut buffer) {
            let Ok(request) = Message::from_vec(&buffer[..read]) else {
                continue;
            };
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.authoritative = true;
            response.metadata.recursion_desired = request.metadata.recursion_desired;
            response.metadata.recursion_available = true;
            for query in &request.queries {
                response.add_query(query.clone());
                let name = query.name().to_utf8().trim_end_matches('.').to_lowercase();
                let known = table.keys().any(|(known, _)| *known == name);
                match table.get(&(name, query.query_type())) {
                    Some(answers) => {
                        for answer in answers {
                            response.add_answer(DnsRecord::from_rdata(
                                query.name().clone(),
                                300,
                                answer.clone(),
                            ));
                        }
                    }
                    None if !known => response.metadata.response_code = ResponseCode::NXDomain,
                    None => {}
                }
            }
            let _ = socket.send_to(&response.to_vec().unwrap(), from);
        }
    });
    address
}

fn srv_table(port: u16) -> HashMap<(String, DnsType), Vec<RData>> {
    let mut table = HashMap::new();
    table.insert(
        ("_sips._tcp.example.test".to_owned(), DnsType::SRV),
        vec![RData::SRV(SRV::new(
            10,
            0,
            port,
            Name::from_ascii("pbx.example.test.").unwrap(),
        ))],
    );
    table.insert(
        ("pbx.example.test".to_owned(), DnsType::A),
        vec![RData::A(A(Ipv4Addr::LOCALHOST))],
    );
    table
}

#[test]
fn a_domain_with_no_address_is_located_by_its_srv_record() {
    let dns = dns_server(srv_table(5061));
    let resolver = Resolver::with_servers(&[dns]).unwrap();

    let srv = resolver.look_up(&Query::new("_sips._tcp.example.test", RecordType::Srv));
    let Answer::Records(records) = srv else {
        panic!("{srv:?}");
    };
    let [Record::Srv(ref record)] = records[..] else {
        panic!("{records:?}");
    };
    assert_eq!(
        (record.priority, record.port, &*record.target),
        (10, 5061, "pbx.example.test")
    );
    assert_eq!(record.ttl, Duration::from_secs(300));

    assert_eq!(
        resolver.look_up(&Query::new("nowhere.example.test", RecordType::A)),
        Answer::Nothing
    );
    assert_eq!(
        resolver.look_up(&Query::new("example.test", RecordType::Srv)),
        Answer::Nothing
    );

    let uri = Uri::parse_str("sips:example.test").unwrap();
    let located = resolver
        .locate(&uri, TransportProtocol::Tls, AddressFamily::Ipv4, false)
        .unwrap();
    assert_eq!(
        located.targets,
        ["127.0.0.1:5061".parse::<SocketAddr>().unwrap()]
    );
}

#[test]
fn a_name_found_by_srv_is_reached_over_tls_checked_against_the_domain() {
    let pki = Pki::new("Sipral test authority");
    // the certificate names the SIP domain, not the host its SRV record points at (RFC 5922 §7.3)
    let (chain, key) = pki.leaf(&["example.test"], false);
    let server = tls_server(Serving {
        chain,
        key,
        clients: None,
        tls12_only: false,
    });
    let dns = dns_server(srv_table(server.port()));
    let mut config = NetworkConfig::default();
    config.trust = Trust::Only(vec![pki.der.clone()]);
    config.name_servers = vec![dns];
    let mut network = Network::new(config).unwrap();

    network.look_up(42, Query::new("_sips._tcp.example.test", RecordType::Srv));
    let (tag, answer) = until(&mut network, |happening| match happening {
        Happening::LookedUp { tag, answer, .. } => Some((tag, answer)),
        _ => None,
    });
    assert_eq!(tag, 42);
    assert!(matches!(answer, Answer::Records(ref records) if records.len() == 1));

    let uri = Uri::parse_str("sips:example.test").unwrap();
    let located = network
        .resolver()
        .locate(&uri, TransportProtocol::Tls, AddressFamily::Ipv4, false)
        .unwrap();
    assert_eq!(located.targets, [server]);
    dial(
        &mut network,
        TransportProtocol::Tls,
        located.targets[0],
        named("example.test"),
    )
    .unwrap();
    assert_eq!(echoed(&mut network, b"located"), b"located");
}
