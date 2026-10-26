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
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SRV};
use hickory_proto::rr::{Name, RData, Record as DnsRecord, RecordType as DnsType};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
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
    ClientCertificate, Failure, Happening, Network, NetworkConfig, Resolver, StreamTarget,
    TlsFailure, Trust,
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
    let config = Arc::new(
        builder
            .with_single_cert(serving.chain, private(&serving.key))
            .unwrap(),
    );
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
