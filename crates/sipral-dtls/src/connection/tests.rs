// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Two ends shaking hands over an in-memory path that loses, duplicates,
//! reorders and fragments, and every refusal the handshake owes.

use std::time::{Duration, Instant};

use super::*;
use crate::handshake::{
    ClientHello, EcPointFormat, Extension, ExtensionType, Extensions, FragmentHeader,
    HelloVerifyRequest, ServerHello, SignatureAndHash, UseSrtp, encode_message, fragments,
};
use crate::random::testing::Counter;
use crate::record::{MAX_SEQUENCE, RecordHeader, encode_plaintext, records};
use crate::x509::{CertificateParams, HashFunction};

const PARAMS: CertificateParams<'static> = CertificateParams {
    common_name: "sipral",
    not_before: 1_785_542_400,
    not_after: 1_785_542_400 + 30 * 86_400,
};

/// A key and its certificate.
struct Identity {
    key: EcdsaKey,
    certificate: Certificate,
}

fn identity(seed: u64) -> Identity {
    let mut random = Counter::new(seed);
    let key = EcdsaKey::generate(&mut random).unwrap();
    let certificate = Certificate::self_signed(&key, &PARAMS, &mut random).unwrap();
    Identity { key, certificate }
}

/// `me` in `role`, expecting `peer`'s certificate.
fn config(role: Role, me: &Identity, peer: &Identity) -> Config {
    Config::new(
        role,
        me.key.clone(),
        me.certificate.clone(),
        vec![peer.certificate.fingerprint()],
    )
}

fn drain(end: &mut Connection) -> Vec<Vec<u8>> {
    core::iter::from_fn(|| end.poll_transmit()).collect()
}

fn events(end: &mut Connection) -> Vec<Event> {
    core::iter::from_fn(|| end.poll_event()).collect()
}

fn deliver(end: &mut Connection, datagrams: &[Vec<u8>], now: Instant) {
    for datagram in datagrams {
        end.handle_datagram(datagram, now);
    }
}

/// The keys of the one Connected event among `events`, which hold no failure.
fn keyed(events: &[Event]) -> &SrtpKeying {
    assert!(
        !events.iter().any(|event| matches!(event, Event::Failed(_))),
        "{events:?}"
    );
    let mut connected = events.iter().filter_map(|event| match event {
        Event::Connected(keys) => Some(keys),
        _ => None,
    });
    let keys = connected
        .next()
        .unwrap_or_else(|| panic!("never connected: {events:?}"));
    assert!(connected.next().is_none(), "connected twice: {events:?}");
    keys
}

/// The one failure among `events`, which release no keys.
fn refused(events: &[Event]) -> Failure {
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Connected(_))),
        "keys were released: {events:?}"
    );
    let failures: Vec<Failure> = events
        .iter()
        .filter_map(|event| match event {
            Event::Failed(failure) => Some(*failure),
            _ => None,
        })
        .collect();
    assert_eq!(failures.len(), 1, "{events:?}");
    failures[0]
}

fn assert_keyed_alike(one: &SrtpKeying, other: &SrtpKeying) {
    assert_eq!(one.role(), other.role().peer());
    assert_eq!(one.profile(), other.profile());
    assert_eq!(one.local_master_key(), other.remote_master_key());
    assert_eq!(one.local_master_salt(), other.remote_master_salt());
    assert_eq!(one.remote_master_key(), other.local_master_key());
    assert_eq!(one.remote_master_salt(), other.local_master_salt());
    assert_ne!(one.local_master_key(), one.remote_master_key());
}

/// Every epoch-0 handshake fragment of a datagram: its record's sequence
/// number, its header, its body.
fn plaintext_fragments(datagram: &[u8]) -> Vec<(u64, FragmentHeader, Vec<u8>)> {
    records(datagram)
        .map(Result::unwrap)
        .filter(|record| {
            record.header.epoch == 0 && record.header.content_type == ContentType::HANDSHAKE
        })
        .flat_map(|record| {
            fragments(record.fragment)
                .map(|fragment| {
                    let fragment = fragment.unwrap();
                    (
                        record.header.sequence,
                        fragment.header,
                        fragment.body.to_vec(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Whether a datagram carries any part of a message of `msg_type` in epoch 0.
fn carries(datagram: &[u8], msg_type: HandshakeType) -> bool {
    plaintext_fragments(datagram)
        .iter()
        .any(|(_, header, _)| header.msg_type == msg_type)
}

/// The datagram with every whole epoch-0 message of `msg_type` passed
/// through `change`, and every other record written back as it was.
fn rewrite(datagram: &[u8], msg_type: HandshakeType, change: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    for record in records(datagram) {
        let record = record.unwrap();
        if record.header.epoch != 0 || record.header.content_type != ContentType::HANDSHAKE {
            record.header.encode(&mut out).unwrap();
            out.extend_from_slice(record.fragment);
            continue;
        }
        let mut payload = Vec::new();
        for fragment in fragments(record.fragment) {
            let fragment = fragment.unwrap();
            let header = fragment.header;
            if header.msg_type == msg_type && header.fragment_length == header.length {
                let body = change(fragment.body);
                encode_message(msg_type, header.message_seq, &body, &mut payload).unwrap();
            } else {
                fragment.encode(&mut payload).unwrap();
            }
        }
        encode_plaintext(
            record.header.content_type,
            record.header.version,
            0,
            record.header.sequence,
            &payload,
            &mut out,
        )
        .unwrap();
    }
    out
}

fn without(extensions: Option<&Extensions>, dropped: ExtensionType) -> Extensions {
    let mut kept = Extensions::new();
    for extension in extensions.unwrap().iter() {
        if extension.extension_type() != dropped {
            kept.push(extension.clone()).unwrap();
        }
    }
    kept
}

fn edit_client_hello(body: &[u8], edit: &dyn Fn(&mut ClientHello)) -> Vec<u8> {
    let mut hello = ClientHello::parse(body).unwrap();
    edit(&mut hello);
    let mut out = Vec::new();
    hello.encode(&mut out).unwrap();
    out
}

fn edit_server_hello(body: &[u8], edit: &dyn Fn(&mut ServerHello)) -> Vec<u8> {
    let mut hello = ServerHello::parse(body).unwrap();
    edit(&mut hello);
    let mut out = Vec::new();
    hello.encode(&mut out).unwrap();
    out
}

/// What a path does to the datagrams on it.
#[derive(Debug, Clone, Copy)]
struct Path {
    /// Per cent of copies lost.
    loss: u32,
    /// Per cent of datagrams sent twice.
    duplicate: u32,
    /// Each copy is late by up to this much, so datagrams overtake each other.
    jitter: Duration,
    /// No datagram may be longer.
    mtu: usize,
}

impl Path {
    const CLEAN: Self = Self {
        loss: 0,
        duplicate: 0,
        jitter: Duration::ZERO,
        mtu: DEFAULT_MAX_DATAGRAM,
    };
}

type Tamper = Box<dyn FnMut(usize, Vec<u8>) -> Vec<u8>>;

/// Two ends and the path between them, run on simulated time.
struct Pair {
    ends: [Connection; 2],
    events: [Vec<Event>; 2],
    path: Path,
    random: Counter,
    /// In flight: when it lands, at which end, the octets.
    flying: Vec<(Instant, usize, Vec<u8>)>,
    /// Everything either end sent, in order, with the index of the sender.
    sent: Vec<(usize, Vec<u8>)>,
    tamper: Option<Tamper>,
    start: Instant,
    now: Instant,
}

impl Pair {
    fn new(configs: [Config; 2], path: Path, seed: u64) -> Self {
        let start = Instant::now();
        let [first, second] = configs;
        let ends = [
            Connection::new(first, &mut Counter::new(seed * 10 + 1), start).unwrap(),
            Connection::new(second, &mut Counter::new(seed * 10 + 2), start).unwrap(),
        ];
        Self {
            ends,
            events: [Vec::new(), Vec::new()],
            path,
            random: Counter::new(seed * 10 + 3),
            flying: Vec::new(),
            sent: Vec::new(),
            tamper: None,
            start,
            now: start,
        }
    }

    fn draw(&mut self, below: u32) -> u32 {
        let mut octets = [0u8; 4];
        self.random.fill(&mut octets);
        u32::from_be_bytes(octets) % below
    }

    fn pump(&mut self) {
        for from in 0..2 {
            while let Some(datagram) = self.ends[from].poll_transmit() {
                assert!(
                    datagram.len() <= self.path.mtu,
                    "a datagram of {} octets on a path of {}",
                    datagram.len(),
                    self.path.mtu
                );
                self.sent.push((from, datagram.clone()));
                let datagram = match self.tamper.as_mut() {
                    Some(tamper) => tamper(from, datagram),
                    None => datagram,
                };
                let copies = if self.draw(100) < self.path.duplicate {
                    2
                } else {
                    1
                };
                for _ in 0..copies {
                    if self.draw(100) < self.path.loss {
                        continue;
                    }
                    let jitter = u32::try_from(self.path.jitter.as_millis()).unwrap();
                    let late = if jitter == 0 {
                        0
                    } else {
                        self.draw(jitter + 1)
                    };
                    let lands = self.now + Duration::from_millis(u64::from(late));
                    self.flying.push((lands, 1 - from, datagram.clone()));
                }
            }
            while let Some(event) = self.ends[from].poll_event() {
                self.events[from].push(event);
            }
        }
    }

    /// Run until nothing is left to happen, or `limit` of simulated time
    /// has passed.
    fn run(&mut self, limit: Duration) {
        let until = self.start + limit;
        for _ in 0..100_000 {
            self.pump();
            let next = [
                self.ends[0].poll_timeout(),
                self.ends[1].poll_timeout(),
                self.flying.iter().map(|(lands, _, _)| *lands).min(),
            ]
            .into_iter()
            .flatten()
            .min();
            let Some(next) = next else {
                return;
            };
            if next > until {
                return;
            }
            self.now = self.now.max(next);
            let now = self.now;
            let mut landing: Vec<(Instant, usize, Vec<u8>)> = Vec::new();
            let mut index = 0;
            while index < self.flying.len() {
                if self.flying[index].0 <= now {
                    landing.push(self.flying.remove(index));
                } else {
                    index += 1;
                }
            }
            landing.sort_by_key(|(lands, _, _)| *lands);
            for (_, to, datagram) in landing {
                self.ends[to].handle_datagram(&datagram, now);
                self.pump();
            }
            for end in &mut self.ends {
                end.handle_timeout(now);
            }
        }
        panic!("the simulation did not settle");
    }

    fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Whether `from` sent some message of `msg_type` in more than one piece.
    fn fragmented(&self, from: usize, msg_type: HandshakeType) -> bool {
        self.sent
            .iter()
            .filter(|(sender, _)| *sender == from)
            .flat_map(|(_, datagram)| plaintext_fragments(datagram))
            .any(|(_, header, _)| {
                header.msg_type == msg_type && header.fragment_length < header.length
            })
    }
}

fn pair_configs(first_role: Role, first: &Identity, second: &Identity) -> [Config; 2] {
    [
        config(first_role, first, second),
        config(first_role.peer(), second, first),
    ]
}

#[test]
fn both_role_orders_complete_on_a_clean_path_with_and_without_a_cookie_exchange() {
    let (one, other) = (identity(1), identity(2));
    for first_role in [Role::Client, Role::Server] {
        for cookie_exchange in [true, false] {
            let mut configs = pair_configs(first_role, &one, &other);
            for config in &mut configs {
                config.cookie_exchange = cookie_exchange;
            }
            let mut pair = Pair::new(configs, Path::CLEAN, 7);
            pair.run(Duration::from_secs(5));

            let first = keyed(&pair.events[0]);
            let second = keyed(&pair.events[1]);
            assert_eq!(first.role(), first_role);
            assert_keyed_alike(first, second);
            // both ends offer every keyable profile, strongest first, so a
            // clean path settles on the strongest they share
            assert_eq!(first.profile(), SrtpProtectionProfile::AEAD_AES_256_GCM);
            assert_eq!(
                pair.ends.each_ref().map(Connection::state),
                [State::Connected; 2]
            );
            // nothing was lost, so nothing waited for a timer
            assert_eq!(pair.elapsed(), Duration::ZERO);
            let client = usize::from(first_role == Role::Server);
            let hellos = pair
                .sent
                .iter()
                .filter(|(from, datagram)| {
                    *from == client && carries(datagram, HandshakeType::CLIENT_HELLO)
                })
                .count();
            assert_eq!(hellos, if cookie_exchange { 2 } else { 1 });
            assert!(pair.ends.iter().all(|end| end.poll_timeout().is_none()));
            if cookie_exchange {
                // RFC 6347 §4.2.1: the HelloVerifyRequest goes out under the
                // record sequence number of the ClientHello it answers, and
                // the first ServerHello under that of the ClientHello that
                // carried the cookie
                let records_of = |from: usize, msg_type: HandshakeType| -> Vec<u64> {
                    pair.sent
                        .iter()
                        .filter(|(sender, _)| *sender == from)
                        .flat_map(|(_, datagram)| plaintext_fragments(datagram))
                        .filter(|(_, header, _)| header.msg_type == msg_type)
                        .map(|(record, _, _)| record)
                        .collect()
                };
                let hello_records = records_of(client, HandshakeType::CLIENT_HELLO);
                assert_eq!(
                    records_of(1 - client, HandshakeType::HELLO_VERIFY_REQUEST),
                    hello_records[..1]
                );
                assert_eq!(
                    records_of(1 - client, HandshakeType::SERVER_HELLO),
                    hello_records[1..]
                );
            }
        }
    }
}

#[test]
fn a_lossy_duplicating_reordering_path_that_fragments_the_certificate_still_completes() {
    let (one, other) = (identity(1), identity(2));
    let path = Path {
        loss: 20,
        duplicate: 20,
        jitter: Duration::from_millis(80),
        mtu: 220,
    };
    for seed in 0..12u64 {
        let first_role = if seed % 2 == 0 {
            Role::Client
        } else {
            Role::Server
        };
        let mut configs = pair_configs(first_role, &one, &other);
        for config in &mut configs {
            config.max_datagram = path.mtu;
            config.cookie_exchange = seed % 4 < 2;
        }
        let mut pair = Pair::new(configs, path, seed);
        pair.run(Duration::from_secs(300));

        let first = keyed(&pair.events[0]);
        let second = keyed(&pair.events[1]);
        assert_eq!(first.role(), first_role, "seed {seed}");
        assert_keyed_alike(first, second);
        // both certificates travelled in pieces
        assert!(
            pair.fragmented(0, HandshakeType::CERTIFICATE),
            "seed {seed}"
        );
        assert!(
            pair.fragmented(1, HandshakeType::CERTIFICATE),
            "seed {seed}"
        );
    }
}

#[test]
fn the_timer_starts_at_a_second_doubles_stops_at_sixty_and_then_gives_up() {
    let (one, other) = (identity(1), identity(2));
    let mut config = config(Role::Client, &one, &other);
    config.retransmission.attempts = 8;
    let start = Instant::now();
    let mut client = Connection::new(config, &mut Counter::new(3), start).unwrap();
    let first = drain(&mut client);
    assert_eq!(first.len(), 1);
    let first_fragments = plaintext_fragments(&first[0]);
    let [(first_record, first_header, ref first_body)] = first_fragments[..] else {
        panic!("one ClientHello in one record");
    };

    let mut at = start;
    for (retransmission, wait) in (1u64..).zip([1u64, 2, 4, 8, 16, 32, 60, 60]) {
        let due = at + Duration::from_secs(wait);
        assert_eq!(
            client.poll_timeout(),
            Some(due),
            "retransmission {retransmission}"
        );
        client.handle_timeout(due.checked_sub(Duration::from_millis(1)).unwrap());
        assert!(
            drain(&mut client).is_empty(),
            "early, retransmission {retransmission}"
        );
        client.handle_timeout(due);
        let again = drain(&mut client);
        assert_eq!(again.len(), 1, "retransmission {retransmission}");
        // the same message under the same message_seq, in a new record
        let fragments = plaintext_fragments(&again[0]);
        let [(record, header, ref body)] = fragments[..] else {
            panic!("one ClientHello in one record");
        };
        assert_eq!(
            (header, body),
            (first_header, first_body),
            "retransmission {retransmission}"
        );
        assert_eq!(record, first_record + retransmission);
        at = due;
    }

    let due = at + Duration::from_secs(60);
    assert_eq!(client.poll_timeout(), Some(due));
    client.handle_timeout(due);
    // no alert for a peer that never answered
    assert_eq!(drain(&mut client), [] as [std::vec::Vec<u8>; 0]);
    assert_eq!(refused(&events(&mut client)), Failure::Timeout);
    assert_eq!(client.state(), State::Failed);
    assert_eq!(client.poll_timeout(), None);
}

#[test]
fn a_doubled_timer_is_kept_for_the_next_flight_until_one_needs_no_retransmission() {
    let (one, other) = (identity(1), identity(2));
    // (whether the server exchanges cookies, whether the first ClientHello
    // is lost, the wait flight 3 starts with, the wait flight 5 starts with)
    let cases = [
        (false, false, None, 1),
        (false, true, None, 2),
        // flight 1 needed a retransmission and flight 3 carries its doubled
        // value; flight 3 needed none, and flight 5 starts afresh
        (true, true, Some(2), 1),
    ];
    for (cookie_exchange, lose_the_first_hello, flight3_wait, flight5_wait) in cases {
        let start = Instant::now();
        let mut client = Connection::new(
            config(Role::Client, &one, &other),
            &mut Counter::new(1),
            start,
        )
        .unwrap();
        let mut server_config = config(Role::Server, &other, &one);
        server_config.cookie_exchange = cookie_exchange;
        let mut server = Connection::new(server_config, &mut Counter::new(2), start).unwrap();
        let case = format!("cookies {cookie_exchange}, first hello lost {lose_the_first_hello}");

        let mut now = start;
        let mut hello = drain(&mut client);
        if lose_the_first_hello {
            now += Duration::from_secs(1);
            client.handle_timeout(now);
            hello = drain(&mut client);
        }
        deliver(&mut server, &hello, now);
        let mut answer = drain(&mut server);
        if let Some(wait) = flight3_wait {
            deliver(&mut client, &answer, now);
            let second_hello = drain(&mut client);
            assert_eq!(
                client.poll_timeout(),
                Some(now + Duration::from_secs(wait)),
                "{case}"
            );
            deliver(&mut server, &second_hello, now);
            answer = drain(&mut server);
        }
        deliver(&mut client, &answer, now);
        let flight5 = drain(&mut client);
        assert!(!flight5.is_empty(), "{case}");
        assert_eq!(
            client.poll_timeout(),
            Some(now + Duration::from_secs(flight5_wait)),
            "{case}"
        );

        deliver(&mut server, &flight5, now);
        deliver(&mut client, &drain(&mut server), now);
        keyed(&events(&mut client));
        keyed(&events(&mut server));
    }
}

/// A client and a cookie-less server taken to the moment after each flight,
/// driven by hand.
struct ByHand {
    client: Connection,
    server: Connection,
    now: Instant,
}

impl ByHand {
    fn new(max_datagram: usize) -> Self {
        let (one, other) = (identity(1), identity(2));
        let now = Instant::now();
        let mut client_config = config(Role::Client, &one, &other);
        client_config.max_datagram = max_datagram;
        let mut server_config = config(Role::Server, &other, &one);
        server_config.cookie_exchange = false;
        server_config.max_datagram = max_datagram;
        Self {
            client: Connection::new(client_config, &mut Counter::new(1), now).unwrap(),
            server: Connection::new(server_config, &mut Counter::new(2), now).unwrap(),
            now,
        }
    }

    /// ClientHello to the server, and flight 4 back.
    fn flight4(&mut self) -> Vec<Vec<u8>> {
        let hello = drain(&mut self.client);
        deliver(&mut self.server, &hello, self.now);
        drain(&mut self.server)
    }

    fn later(&mut self, by: Duration) -> Instant {
        self.now += by;
        self.now
    }
}

#[test]
fn a_retransmitted_flight_is_answered_with_the_last_flight_and_never_processed_twice() {
    // part of flight 4, then that part again: the flight being waited for is
    // on its way, and nothing is sent back for it
    let mut hand = ByHand::new(200);
    let flight4 = hand.flight4();
    assert!(flight4.len() > 2);
    deliver(&mut hand.client, &flight4[..1], hand.now);
    let now = hand.later(Duration::from_millis(600));
    deliver(&mut hand.client, &flight4[..1], now);
    assert_eq!(drain(&mut hand.client), [] as [std::vec::Vec<u8>; 0]);
    deliver(&mut hand.client, &flight4[1..], now);
    assert!(carries(
        &drain(&mut hand.client).concat(),
        HandshakeType::CLIENT_KEY_EXCHANGE
    ));

    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    let flight5_sent = hand.now;
    let flight5 = drain(&mut hand.client);
    let exchange = |datagrams: &[Vec<u8>]| {
        datagrams
            .iter()
            .flat_map(|datagram| plaintext_fragments(datagram))
            .find(|(_, header, _)| header.msg_type == HandshakeType::CLIENT_KEY_EXCHANGE)
            .map(|(_, _, body)| body)
    };

    // the client: flight 4 arriving again at once is a duplicate and is
    // answered by nothing; later it is the server not having heard flight 5,
    // and is answered by flight 5 — the same ephemeral key, not a new one
    let now = hand.later(Duration::from_millis(100));
    deliver(&mut hand.client, &flight4, now);
    assert_eq!(drain(&mut hand.client), [] as [std::vec::Vec<u8>; 0]);
    let now = hand.later(Duration::from_millis(500));
    deliver(&mut hand.client, &flight4, now);
    let again = drain(&mut hand.client);
    assert_ne!(again, [] as [std::vec::Vec<u8>; 0]);
    assert_eq!(exchange(&again), exchange(&flight5));
    assert!(events(&mut hand.client).is_empty());
    // the retransmission is unauthenticated in epoch 0, so it does not touch
    // the give-up deadline: it is still the one flight 5 started with
    assert_eq!(
        hand.client.poll_timeout(),
        Some(flight5_sent + Duration::from_secs(1))
    );

    // the server completes on flight 5, and again on its retransmission sends
    // flight 6 and nothing else
    deliver(&mut hand.server, &flight5, now);
    let flight6 = drain(&mut hand.server);
    assert_ne!(flight6, [] as [std::vec::Vec<u8>; 0]);
    keyed(&events(&mut hand.server));
    let now = hand.later(Duration::from_secs(1));
    deliver(&mut hand.server, &again, now);
    let flight6_again = drain(&mut hand.server);
    assert_eq!(
        flight6_again.iter().map(Vec::len).collect::<Vec<_>>(),
        flight6.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert_ne!(flight6_again, flight6, "new record sequence numbers");
    assert!(events(&mut hand.server).is_empty());
    assert_eq!(hand.server.state(), State::Connected);

    // the client takes whichever copy of flight 6 arrives first, once
    deliver(&mut hand.client, &flight6_again, now);
    deliver(&mut hand.client, &flight6, now);
    keyed(&events(&mut hand.client));
    assert_eq!(drain(&mut hand.client), [] as [std::vec::Vec<u8>; 0]);
    assert_eq!(hand.client.poll_timeout(), None);
}

/// A 25-octet plaintext epoch-0 record holding one empty fragment of message
/// `message_seq` — the shape `on_peer_retransmission` answers, and the
/// shortest thing an off-path attacker who can spoof the peer's address can
/// forge without a single key: no certificate, no master secret, nothing
/// that ties it to whoever actually owns the handshake.
fn forged_retransmission(msg_type: HandshakeType, message_seq: u16) -> Vec<u8> {
    let mut fragment = Vec::new();
    encode_message(msg_type, message_seq, &[], &mut fragment).unwrap();
    let mut datagram = Vec::new();
    encode_plaintext(
        ContentType::HANDSHAKE,
        ProtocolVersion::DTLS_1_2,
        0,
        u64::from(message_seq),
        &fragment,
        &mut datagram,
    )
    .unwrap();
    datagram
}

#[test]
fn a_forged_stream_of_epoch_zero_retransmissions_cannot_delay_giving_up() {
    // The client sends its last flight and the real server falls silent —
    // gone, or simply never heard from again. An off-path attacker who can
    // spoof the server's address forges a retransmission of the ServerHello
    // the client already has, at the fastest rate `on_peer_retransmission`
    // still answers rather than ignoring as too soon. If that forged prompt
    // could push the give-up deadline back, this stream would hold the
    // handshake open forever; it must not, so the schedule below runs with
    // the stream going the whole time and checks every deadline against it.
    const INITIAL: Duration = Duration::from_millis(200);
    const ATTEMPTS: u32 = 3;
    let (one, other) = (identity(1), identity(2));
    let mut client_config = config(Role::Client, &one, &other);
    client_config.retransmission = Retransmission {
        initial: INITIAL,
        max: INITIAL,
        attempts: ATTEMPTS,
    };
    let mut server_config = config(Role::Server, &other, &one);
    server_config.cookie_exchange = false;
    let start = Instant::now();
    let mut client = Connection::new(client_config, &mut Counter::new(1), start).unwrap();
    let mut server = Connection::new(server_config, &mut Counter::new(2), start).unwrap();

    let hello = drain(&mut client);
    deliver(&mut server, &hello, start);
    let flight4 = drain(&mut server);
    deliver(&mut client, &flight4, start);
    let flight5 = drain(&mut client);
    assert!(!flight5.is_empty(), "the client's last flight");
    assert_eq!(client.state(), State::Handshaking);
    let sent_at = start;

    let probe = forged_retransmission(HandshakeType::SERVER_HELLO, 0);
    let step = INITIAL / 2;
    let mut now = sent_at;
    for retransmission in 1..=ATTEMPTS {
        let due = sent_at + INITIAL * retransmission;
        while now + step <= due {
            now += step;
            client.handle_datagram(&probe, now);
            drain(&mut client);
        }
        assert_eq!(
            client.poll_timeout(),
            Some(due),
            "retransmission {retransmission}: a forged retransmission must not move the deadline"
        );
        client.handle_timeout(due);
        assert!(
            !drain(&mut client).is_empty(),
            "retransmission {retransmission}: the real schedule still retransmits"
        );
        assert!(
            events(&mut client).is_empty(),
            "retransmission {retransmission}"
        );
        now = due;
    }

    let due = sent_at + INITIAL * (ATTEMPTS + 1);
    while now + step <= due {
        now += step;
        client.handle_datagram(&probe, now);
        drain(&mut client);
    }
    client.handle_timeout(due);
    assert_eq!(refused(&events(&mut client)), Failure::Timeout);
    assert_eq!(client.state(), State::Failed);
}

#[test]
fn a_certificate_matching_no_signalled_fingerprint_is_refused_at_either_end() {
    let (one, other, stranger) = (identity(1), identity(2), identity(3));
    for checker in [Role::Client, Role::Server] {
        let mut configs = pair_configs(Role::Client, &one, &other);
        let at = usize::from(checker == Role::Server);
        configs[at].peer_fingerprints = vec![stranger.certificate.fingerprint()];
        let mut pair = Pair::new(configs, Path::CLEAN, 11);
        pair.run(Duration::from_secs(10));

        assert_eq!(refused(&pair.events[at]), Failure::FingerprintMismatch);
        assert_eq!(
            refused(&pair.events[1 - at]),
            Failure::PeerAlert(AlertDescription::BAD_CERTIFICATE)
        );
    }
}

#[test]
fn the_fingerprints_under_the_most_preferred_hash_are_the_ones_the_certificate_must_match() {
    let (one, other, stranger) = (identity(1), identity(2), identity(3));
    let der = other.certificate.der();
    let right_256 = Fingerprint::of(HashFunction::Sha256, der);
    let right_1 = Fingerprint::of(HashFunction::Sha1, der);
    let wrong_256 = Fingerprint::of(HashFunction::Sha256, stranger.certificate.der());
    let wrong_1 = Fingerprint::of(HashFunction::Sha1, stranger.certificate.der());
    let right_384 = Fingerprint::of(HashFunction::Sha384, der);
    let right_512 = Fingerprint::of(HashFunction::Sha512, der);
    let wrong_384 = Fingerprint::of(HashFunction::Sha384, stranger.certificate.der());
    let wrong_512 = Fingerprint::of(HashFunction::Sha512, stranger.certificate.der());
    let cases = [
        (vec![right_256.clone()], true),
        (vec![right_1.clone()], true),
        (vec![wrong_256.clone(), right_256.clone()], true),
        (vec![wrong_1.clone(), right_1.clone()], true),
        // SHA-256 is offered, so the SHA-1 one is not looked at
        (vec![wrong_256.clone(), right_1.clone()], false),
        (vec![right_1, wrong_256.clone()], false),
        (vec![right_256.clone(), wrong_1.clone()], true),
        (vec![wrong_1], false),
        // SHA-512 over SHA-384 over SHA-256 (RFC 8122 §5.1 leaves the order
        // to this end)
        (vec![right_512.clone()], true),
        (vec![right_384.clone()], true),
        (vec![wrong_512.clone(), right_256.clone()], false),
        (vec![right_512.clone(), wrong_256.clone()], true),
        (vec![wrong_384.clone(), right_256], false),
        (vec![right_384.clone(), wrong_256], true),
        (vec![wrong_512.clone(), right_384.clone()], false),
        (vec![right_512, wrong_384, right_384], true),
        (vec![wrong_512], false),
    ];
    for (fingerprints, matches) in cases {
        let mut config = config(Role::Client, &one, &other);
        config.peer_fingerprints = fingerprints.clone();
        let settings = Settings::from_config(config).unwrap();
        assert_eq!(
            settings.fingerprint_matches(der),
            matches,
            "{fingerprints:?}"
        );
    }
}

#[test]
fn a_peer_without_the_extended_master_secret_is_refused_at_either_end() {
    let (one, other) = (identity(1), identity(2));
    // (whose hello loses the extension, the index of the end that refuses it)
    for (hello, refuser) in [
        (HandshakeType::CLIENT_HELLO, 1),
        (HandshakeType::SERVER_HELLO, 0),
    ] {
        let mut pair = Pair::new(pair_configs(Role::Client, &one, &other), Path::CLEAN, 13);
        pair.tamper = Some(Box::new(move |_, datagram| {
            rewrite(&datagram, hello, &|body| {
                if hello == HandshakeType::CLIENT_HELLO {
                    edit_client_hello(body, &|h| {
                        h.extensions = Some(without(
                            h.extensions.as_ref(),
                            ExtensionType::EXTENDED_MASTER_SECRET,
                        ));
                    })
                } else {
                    edit_server_hello(body, &|h| {
                        h.extensions = Some(without(
                            h.extensions.as_ref(),
                            ExtensionType::EXTENDED_MASTER_SECRET,
                        ));
                    })
                }
            })
        }));
        pair.run(Duration::from_secs(10));
        assert_eq!(
            refused(&pair.events[refuser]),
            Failure::NoExtendedMasterSecret,
            "{hello:?}"
        );
        assert_eq!(
            refused(&pair.events[1 - refuser]),
            Failure::PeerAlert(AlertDescription::HANDSHAKE_FAILURE),
            "{hello:?}"
        );
    }
}

#[test]
fn a_peer_with_no_srtp_profile_in_common_is_refused() {
    let (one, other) = (identity(1), identity(2));

    // profiles that do not meet
    let mut configs = pair_configs(Role::Client, &one, &other);
    configs[0].srtp_profiles = vec![SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32];
    configs[1].srtp_profiles = vec![SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80];
    let mut pair = Pair::new(configs, Path::CLEAN, 17);
    pair.run(Duration::from_secs(10));
    assert_eq!(refused(&pair.events[1]), Failure::NoSrtpProfile);
    assert_eq!(
        refused(&pair.events[0]),
        Failure::PeerAlert(AlertDescription::HANDSHAKE_FAILURE)
    );

    // and the server picks from the client's list in its own order
    let mut configs = pair_configs(Role::Client, &one, &other);
    configs[1].srtp_profiles = vec![
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
    ];
    let mut pair = Pair::new(configs, Path::CLEAN, 17);
    pair.run(Duration::from_secs(10));
    assert_eq!(
        keyed(&pair.events[0]).profile(),
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32
    );

    // use_srtp missing from either hello (index of the hello's sender, of
    // the end that refuses)
    for (hello, refuser) in [
        (HandshakeType::CLIENT_HELLO, 1),
        (HandshakeType::SERVER_HELLO, 0),
    ] {
        let mut pair = Pair::new(pair_configs(Role::Client, &one, &other), Path::CLEAN, 19);
        pair.tamper = Some(Box::new(move |_, datagram| {
            rewrite(&datagram, hello, &|body| {
                if hello == HandshakeType::CLIENT_HELLO {
                    edit_client_hello(body, &|h| {
                        h.extensions =
                            Some(without(h.extensions.as_ref(), ExtensionType::USE_SRTP));
                    })
                } else {
                    edit_server_hello(body, &|h| {
                        h.extensions =
                            Some(without(h.extensions.as_ref(), ExtensionType::USE_SRTP));
                    })
                }
            })
        }));
        pair.run(Duration::from_secs(10));
        assert_eq!(
            refused(&pair.events[refuser]),
            Failure::NoSrtpProfile,
            "{hello:?}"
        );
    }

    // a server that names a profile the client did not offer
    let mut configs = pair_configs(Role::Client, &one, &other);
    configs[0].srtp_profiles = vec![SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80];
    let mut pair = Pair::new(configs, Path::CLEAN, 23);
    pair.tamper = Some(Box::new(|_, datagram| {
        rewrite(&datagram, HandshakeType::SERVER_HELLO, &|body| {
            edit_server_hello(body, &|h| {
                let mut extensions = without(h.extensions.as_ref(), ExtensionType::USE_SRTP);
                extensions
                    .push(Extension::UseSrtp(UseSrtp {
                        profiles: vec![SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32],
                        mki: Vec::new(),
                    }))
                    .unwrap();
                h.extensions = Some(extensions);
            })
        })
    }));
    pair.run(Duration::from_secs(10));
    assert_eq!(refused(&pair.events[0]), Failure::IllegalParameter);
}

/// RFC 7714 §14.2's two GCM profiles are this stack's own preference by
/// default (`both_role_orders_complete_on_a_clean_path...` above), but a
/// peer that only ever offers the two AES-128-CM profiles from RFC 5764
/// still completes on one of those -- the server's GCM preference is never
/// forced on a client that did not offer it.
#[test]
fn a_client_offering_only_aes_128_cm_still_completes_on_it() {
    let (one, other) = (identity(1), identity(2));
    let mut configs = pair_configs(Role::Client, &one, &other);
    configs[0].srtp_profiles = vec![
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
    ];
    let mut pair = Pair::new(configs, Path::CLEAN, 29);
    pair.run(Duration::from_secs(10));
    // the server's own order still puts AES128_CM_HMAC_SHA1_80 ahead of _32
    // among what this client offered
    assert_eq!(
        keyed(&pair.events[1]).profile(),
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80
    );
    assert_eq!(
        pair.ends.each_ref().map(Connection::state),
        [State::Connected; 2]
    );
}

/// The `use_srtp` profiles of every ClientHello `from` sent.
fn offered_profiles(pair: &Pair, from: usize) -> Vec<Vec<SrtpProtectionProfile>> {
    pair.sent
        .iter()
        .filter(|(sender, _)| *sender == from)
        .flat_map(|(_, datagram)| plaintext_fragments(datagram))
        .filter(|(_, header, _)| header.msg_type == HandshakeType::CLIENT_HELLO)
        .map(|(_, _, body)| {
            let hello = ClientHello::parse(&body).unwrap();
            hello
                .extensions
                .unwrap()
                .use_srtp()
                .unwrap()
                .profiles
                .clone()
        })
        .collect()
}

/// RFC 5764 §4.1.1: the client offers its profiles "in descending order of
/// preference", and the server answers with one of them, chosen here in the
/// server's own configured order. A peer offering only the RFC 5764 AES-CM
/// profiles, a peer offering only the RFC 7714 §14.2 GCM ones, and two ends
/// with nothing in common are each met with the peer as client and as
/// server.
#[test]
fn a_profile_is_agreed_in_the_servers_order_or_the_handshake_fails_for_want_of_one() {
    use SrtpProtectionProfile as P;
    let (one, other) = (identity(1), identity(2));
    let cm = vec![P::AES128_CM_HMAC_SHA1_80, P::AES128_CM_HMAC_SHA1_32];
    let gcm = vec![P::AEAD_AES_128_GCM, P::AEAD_AES_256_GCM];
    let every = KEYABLE.to_vec();
    // the client's list, the server's, what they agree on
    let cases: [(&[P], &[P], Option<P>); 9] = [
        (&cm, &every, Some(P::AES128_CM_HMAC_SHA1_80)),
        (&every, &cm, Some(P::AES128_CM_HMAC_SHA1_80)),
        (&gcm, &every, Some(P::AEAD_AES_256_GCM)),
        (&every, &gcm, Some(P::AEAD_AES_128_GCM)),
        (&gcm, &cm, None),
        (&cm, &gcm, None),
        (&[P::AEAD_AES_128_GCM], &[P::AEAD_AES_256_GCM], None),
        (&every, &every, Some(P::AEAD_AES_256_GCM)),
        (
            &every,
            &[P::AES128_CM_HMAC_SHA1_32, P::AEAD_AES_128_GCM],
            Some(P::AES128_CM_HMAC_SHA1_32),
        ),
    ];
    for (seed, (client, server, agreed)) in (31..).zip(cases) {
        let what = format!("client {client:?}, server {server:?}");
        let mut configs = pair_configs(Role::Client, &one, &other);
        configs[0].srtp_profiles = client.to_vec();
        configs[1].srtp_profiles = server.to_vec();
        let mut pair = Pair::new(configs, Path::CLEAN, seed);
        pair.run(Duration::from_secs(10));

        // the client offered its own list, in its own order, every time
        let offers = offered_profiles(&pair, 0);
        assert!(!offers.is_empty(), "{what}");
        assert!(offers.iter().all(|offer| offer == client), "{what}");

        if let Some(profile) = agreed {
            let (client_keys, server_keys) = (keyed(&pair.events[0]), keyed(&pair.events[1]));
            assert_eq!(client_keys.profile(), profile, "{what}");
            assert_keyed_alike(client_keys, server_keys);
        } else {
            assert_eq!(refused(&pair.events[1]), Failure::NoSrtpProfile, "{what}");
            assert_eq!(
                refused(&pair.events[0]),
                Failure::PeerAlert(AlertDescription::HANDSHAKE_FAILURE),
                "{what}"
            );
        }
    }
}

/// RFC 5764 §4.2 exports `2 * (master_key_len + master_salt_len)` octets, the
/// lengths being the negotiated profile's: RFC 7714 §12 gives both GCM
/// profiles a 96-bit salt, and a 128- or 256-bit key.
#[test]
fn each_profile_keys_both_directions_at_its_own_widths() {
    use SrtpProtectionProfile as P;
    let (one, other) = (identity(1), identity(2));
    let widths = [
        (P::AEAD_AES_256_GCM, 32, 12),
        (P::AEAD_AES_128_GCM, 16, 12),
        (P::AES128_CM_HMAC_SHA1_80, 16, 14),
        (P::AES128_CM_HMAC_SHA1_32, 16, 14),
    ];
    for (seed, (profile, key, salt)) in (41..).zip(widths) {
        for first_role in [Role::Client, Role::Server] {
            let mut configs = pair_configs(first_role, &one, &other);
            for config in &mut configs {
                config.srtp_profiles = vec![profile];
            }
            let mut pair = Pair::new(configs, Path::CLEAN, seed);
            pair.run(Duration::from_secs(10));
            let (first, second) = (keyed(&pair.events[0]), keyed(&pair.events[1]));
            assert_eq!(first.profile(), profile);
            assert_keyed_alike(first, second);
            for keys in [first, second] {
                assert_eq!(keys.local_master_key().len(), key, "{profile:?}");
                assert_eq!(keys.remote_master_key().len(), key, "{profile:?}");
                assert_eq!(keys.local_master_salt().len(), salt, "{profile:?}");
                assert_eq!(keys.remote_master_salt().len(), salt, "{profile:?}");
                assert_ne!(keys.local_master_salt(), keys.remote_master_salt());
            }
        }
    }
}

/// The ClientHello body with `use_srtp` holding no profiles and no MKI: the
/// octets `00 0e 00 03 00 00 00`, which `<2..2^16-1>` does not allow and no
/// encoder here will write.
fn with_empty_use_srtp(body: &[u8]) -> Vec<u8> {
    let stripped = edit_client_hello(body, &|h| {
        h.extensions = Some(without(h.extensions.as_ref(), ExtensionType::USE_SRTP));
    });
    let hello = ClientHello::parse(&stripped).unwrap();
    let mut block = Vec::new();
    hello.extensions.unwrap().encode(&mut block).unwrap();
    let mut out = stripped[..stripped.len() - block.len()].to_vec();
    let mut inner = block[2..].to_vec();
    inner.extend_from_slice(&[0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&inner);
    assert!(ClientHello::parse(&out).is_err());
    out
}

#[test]
fn an_empty_use_srtp_is_a_hello_that_does_not_parse() {
    // at a server holding no state, it is discarded like any unreadable
    // datagram: nothing is sent back, and nothing is kept
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let hello = drain(&mut hand.client);
    let emptied: Vec<Vec<u8>> = hello
        .iter()
        .map(|datagram| rewrite(datagram, HandshakeType::CLIENT_HELLO, &with_empty_use_srtp))
        .collect();
    deliver(&mut hand.server, &emptied, hand.now);
    assert_eq!(drain(&mut hand.server), [] as [std::vec::Vec<u8>; 0]);
    assert!(events(&mut hand.server).is_empty());
    assert_eq!(hand.server.state(), State::Handshaking);
    // and the genuine hello is still answered afterwards
    deliver(&mut hand.server, &hello, hand.now);
    assert_ne!(drain(&mut hand.server), [] as [std::vec::Vec<u8>; 0]);

    // in a ServerHello, it fails the client's handshake
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4: Vec<Vec<u8>> = hand
        .flight4()
        .iter()
        .map(|datagram| {
            rewrite(datagram, HandshakeType::SERVER_HELLO, &|body| {
                let mut out = body.to_vec();
                let hello = ServerHello::parse(body).unwrap();
                let at = out.len()
                    - hello.extensions.as_ref().map_or(0, |e| {
                        let mut block = Vec::new();
                        e.encode(&mut block).unwrap();
                        block.len()
                    });
                let mut block = Vec::new();
                without(hello.extensions.as_ref(), ExtensionType::USE_SRTP)
                    .encode(&mut block)
                    .unwrap();
                let mut inner = block[2..].to_vec();
                inner.extend_from_slice(&[0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00]);
                out.truncate(at);
                out.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
                out.extend_from_slice(&inner);
                out
            })
        })
        .collect();
    deliver(&mut hand.client, &flight4, hand.now);
    assert!(matches!(
        refused(&events(&mut hand.client)),
        Failure::Malformed(_)
    ));
}

/// A hello body with its `use_srtp` replaced by one whose `extension_data`
/// is the raw `data`, which may be octets no encoder here will write.
/// `extensions` are the body's own, read out of it.
fn with_raw_use_srtp(body: &[u8], extensions: Option<&Extensions>, data: &[u8]) -> Vec<u8> {
    let mut block = Vec::new();
    extensions.unwrap().encode(&mut block).unwrap();
    let mut out = body[..body.len() - block.len()].to_vec();
    let mut kept = Vec::new();
    without(extensions, ExtensionType::USE_SRTP)
        .encode(&mut kept)
        .unwrap();
    let mut inner = kept[2..].to_vec();
    inner.extend_from_slice(&ExtensionType::USE_SRTP.0.to_be_bytes());
    inner.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    inner.extend_from_slice(data);
    out.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

/// `UseSRTPData` bodies RFC 5764 §4.1.1's syntax does not allow:
/// `SRTPProtectionProfiles<2..2^16-1>` of two-octet profiles, then
/// `srtp_mki<0..255>`, and nothing after.
const MALFORMED_USE_SRTP: [(&str, &[u8]); 6] = [
    ("no data at all", &[]),
    (
        "profile list longer than the extension",
        &[0, 6, 0, 7, 0, 8],
    ),
    ("profile list of odd length", &[0, 3, 0, 7, 0, 0]),
    ("no MKI length", &[0, 2, 0, 7]),
    ("MKI longer than the extension", &[0, 2, 0, 7, 4, 0xAA]),
    ("octets after the MKI", &[0, 2, 0, 7, 0, 0]),
];

#[test]
fn a_malformed_use_srtp_in_a_client_hello_is_discarded_without_an_answer() {
    for (what, data) in MALFORMED_USE_SRTP {
        let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
        let hello = drain(&mut hand.client);
        let broken: Vec<Vec<u8>> = hello
            .iter()
            .map(|datagram| {
                rewrite(datagram, HandshakeType::CLIENT_HELLO, &|body| {
                    let parsed = ClientHello::parse(body).unwrap();
                    let out = with_raw_use_srtp(body, parsed.extensions.as_ref(), data);
                    assert!(ClientHello::parse(&out).is_err(), "{what}");
                    out
                })
            })
            .collect();
        deliver(&mut hand.server, &broken, hand.now);
        assert!(drain(&mut hand.server).is_empty(), "{what}");
        assert!(events(&mut hand.server).is_empty(), "{what}");
        assert_eq!(hand.server.state(), State::Handshaking, "{what}");
        // the genuine hello is still answered afterwards
        deliver(&mut hand.server, &hello, hand.now);
        assert!(!drain(&mut hand.server).is_empty(), "{what}");
    }
}

#[test]
fn a_malformed_use_srtp_in_a_server_hello_fails_the_clients_handshake() {
    for (what, data) in MALFORMED_USE_SRTP {
        let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
        let flight4: Vec<Vec<u8>> = hand
            .flight4()
            .iter()
            .map(|datagram| {
                rewrite(datagram, HandshakeType::SERVER_HELLO, &|body| {
                    let parsed = ServerHello::parse(body).unwrap();
                    with_raw_use_srtp(body, parsed.extensions.as_ref(), data)
                })
            })
            .collect();
        deliver(&mut hand.client, &flight4, hand.now);
        assert!(
            matches!(refused(&events(&mut hand.client)), Failure::Malformed(_)),
            "{what}"
        );
        assert_eq!(hand.client.state(), State::Failed, "{what}");
    }
}

/// RFC 5764 §4.1.1: a server that "cannot make use of the MKI" the client
/// offered returns "an empty "srtp_mki" value". This one never uses an MKI
/// (RFC 8827 §6.5 forbids one), so a ClientHello carrying one is answered
/// on its profiles alone.
#[test]
fn a_client_mki_is_answered_with_an_empty_one() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let hello: Vec<Vec<u8>> = drain(&mut hand.client)
        .iter()
        .map(|datagram| {
            rewrite(datagram, HandshakeType::CLIENT_HELLO, &|body| {
                edit_client_hello(body, &|h| {
                    let mut extensions = without(h.extensions.as_ref(), ExtensionType::USE_SRTP);
                    extensions
                        .push(Extension::UseSrtp(UseSrtp {
                            profiles: vec![SrtpProtectionProfile::AEAD_AES_128_GCM],
                            mki: vec![1, 2, 3, 4],
                        }))
                        .unwrap();
                    h.extensions = Some(extensions);
                })
            })
        })
        .collect();
    deliver(&mut hand.server, &hello, hand.now);
    let answers: Vec<UseSrtp> = drain(&mut hand.server)
        .iter()
        .flat_map(|datagram| plaintext_fragments(datagram))
        .filter(|(_, header, _)| header.msg_type == HandshakeType::SERVER_HELLO)
        .map(|(_, _, body)| {
            let hello = ServerHello::parse(&body).unwrap();
            hello.extensions.unwrap().use_srtp().unwrap().clone()
        })
        .collect();
    assert_eq!(
        answers,
        [UseSrtp {
            profiles: vec![SrtpProtectionProfile::AEAD_AES_128_GCM],
            mki: Vec::new(),
        }]
    );
    assert!(events(&mut hand.server).is_empty());
}

/// RFC 5764 §4.1.1: the server's `use_srtp` carries "a single
/// SRTPProtectionProfile value that the server has chosen" from the client's
/// list, and §4.1.3 aborts a handshake whose server names an MKI the client
/// did not offer. Each is refused with illegal_parameter, GCM profiles
/// included.
#[test]
fn a_server_use_srtp_the_client_cannot_accept_is_refused() {
    use SrtpProtectionProfile as P;
    let cases = [
        (
            "an MKI the client did not offer",
            KEYABLE.to_vec(),
            vec![P::AEAD_AES_256_GCM],
            vec![9],
        ),
        (
            "two profiles",
            KEYABLE.to_vec(),
            vec![P::AEAD_AES_256_GCM, P::AEAD_AES_128_GCM],
            Vec::new(),
        ),
        (
            "a GCM profile to a client offering only AES-CM",
            vec![P::AES128_CM_HMAC_SHA1_80, P::AES128_CM_HMAC_SHA1_32],
            vec![P::AEAD_AES_128_GCM],
            Vec::new(),
        ),
        (
            "an AES-CM profile to a client offering only GCM",
            vec![P::AEAD_AES_256_GCM, P::AEAD_AES_128_GCM],
            vec![P::AES128_CM_HMAC_SHA1_80],
            Vec::new(),
        ),
    ];
    let (one, other) = (identity(1), identity(2));
    for (seed, (what, client_profiles, answer, mki)) in (51..).zip(cases) {
        let mut configs = pair_configs(Role::Client, &one, &other);
        configs[0].srtp_profiles = client_profiles;
        let mut pair = Pair::new(configs, Path::CLEAN, seed);
        pair.tamper = Some(Box::new(move |_, datagram| {
            rewrite(&datagram, HandshakeType::SERVER_HELLO, &|body| {
                edit_server_hello(body, &|h| {
                    let mut extensions = without(h.extensions.as_ref(), ExtensionType::USE_SRTP);
                    extensions
                        .push(Extension::UseSrtp(UseSrtp {
                            profiles: answer.clone(),
                            mki: mki.clone(),
                        }))
                        .unwrap();
                    h.extensions = Some(extensions);
                })
            })
        }));
        pair.run(Duration::from_secs(10));
        assert_eq!(
            refused(&pair.events[0]),
            Failure::IllegalParameter,
            "{what}"
        );
        assert_eq!(
            refused(&pair.events[1]),
            Failure::PeerAlert(AlertDescription::ILLEGAL_PARAMETER),
            "{what}"
        );
    }
}

#[test]
fn a_finished_that_does_not_match_the_transcript_releases_nothing_at_either_end() {
    fn corrupt_finished(end: &mut Connection) {
        let flight = end.core.flight.as_mut().unwrap();
        let body = flight
            .iter_mut()
            .find_map(|item| match item {
                Item::Handshake { msg_type, body, .. } if *msg_type == HandshakeType::FINISHED => {
                    Some(body)
                }
                _ => None,
            })
            .unwrap();
        body[0] ^= 1;
    }

    // the server checks the client's: flight 5 is lost, and its
    // retransmission carries a Finished protected correctly and wrong
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    drop(drain(&mut hand.client));
    corrupt_finished(&mut hand.client);
    let now = hand.later(Duration::from_secs(1));
    hand.client.handle_timeout(now);
    deliver(&mut hand.server, &drain(&mut hand.client), now);
    assert_eq!(refused(&events(&mut hand.server)), Failure::BadFinished);
    deliver(&mut hand.client, &drain(&mut hand.server), now);
    assert_eq!(
        refused(&events(&mut hand.client)),
        Failure::PeerAlert(AlertDescription::DECRYPT_ERROR)
    );

    // the client checks the server's: flight 6 is lost, and the copy the
    // client's retransmission draws out is wrong
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    deliver(&mut hand.server, &drain(&mut hand.client), hand.now);
    drop(drain(&mut hand.server));
    keyed(&events(&mut hand.server));
    corrupt_finished(&mut hand.server);
    let now = hand.later(Duration::from_secs(1));
    hand.client.handle_timeout(now);
    deliver(&mut hand.server, &drain(&mut hand.client), now);
    deliver(&mut hand.client, &drain(&mut hand.server), now);
    assert_eq!(refused(&events(&mut hand.client)), Failure::BadFinished);
}

#[test]
fn application_data_waits_for_the_finished_and_what_came_before_it_is_dropped() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    assert_eq!(
        hand.client.send_application_data(b"too soon"),
        Err(Error::NotConnected)
    );
    deliver(&mut hand.server, &drain(&mut hand.client), hand.now);
    keyed(&events(&mut hand.server));
    // flight 6 is lost; the server, connected, sends data behind it
    drop(drain(&mut hand.server));
    hand.server.send_application_data(b"early").unwrap();
    deliver(&mut hand.client, &drain(&mut hand.server), hand.now);
    assert!(events(&mut hand.client).is_empty());
    assert_eq!(hand.client.state(), State::Handshaking);

    let now = hand.later(Duration::from_secs(1));
    hand.client.handle_timeout(now);
    deliver(&mut hand.server, &drain(&mut hand.client), now);
    deliver(&mut hand.client, &drain(&mut hand.server), now);
    let seen = events(&mut hand.client);
    keyed(&seen);
    assert_eq!(seen.len(), 1, "{seen:?}");

    hand.server.send_application_data(b"late").unwrap();
    hand.client.send_application_data(b"back").unwrap();
    deliver(&mut hand.client, &drain(&mut hand.server), now);
    deliver(&mut hand.server, &drain(&mut hand.client), now);
    for (end, expected) in [
        (&mut hand.client, &b"late"[..]),
        (&mut hand.server, b"back"),
    ] {
        let seen = events(end);
        assert!(
            matches!(&seen[..], [Event::ApplicationData(data)] if data == expected),
            "{seen:?}"
        );
    }
}

#[test]
fn a_finished_in_the_clear_is_discarded_and_the_protected_one_still_counts() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    let flight5 = drain(&mut hand.client);
    // everything of flight 5 but the protected Finished
    let clear = epoch_zero_only(&flight5);
    deliver(&mut hand.server, &clear, hand.now);
    let finished_seq = numbered_after(&clear);
    let mut forged = Vec::new();
    encode_message(
        HandshakeType::FINISHED,
        finished_seq,
        &[0x5A; 12],
        &mut forged,
    )
    .unwrap();
    let mut datagram = Vec::new();
    encode_plaintext(
        ContentType::HANDSHAKE,
        ProtocolVersion::DTLS_1_2,
        0,
        99,
        &forged,
        &mut datagram,
    )
    .unwrap();
    deliver(&mut hand.server, &[datagram], hand.now);
    assert!(events(&mut hand.server).is_empty());
    assert_eq!(drain(&mut hand.server), [] as [std::vec::Vec<u8>; 0]);
    assert_eq!(hand.server.state(), State::Handshaking);

    deliver(&mut hand.server, &flight5, hand.now);
    keyed(&events(&mut hand.server));
}

/// Every datagram with its epoch-1 records taken out: a flight as it would
/// arrive had everything protected in it been lost.
fn epoch_zero_only(datagrams: &[Vec<u8>]) -> Vec<Vec<u8>> {
    datagrams
        .iter()
        .map(|datagram| {
            let mut out = Vec::new();
            for record in records(datagram).map(Result::unwrap) {
                if record.header.epoch == 0 {
                    record.header.encode(&mut out).unwrap();
                    out.extend_from_slice(record.fragment);
                }
            }
            out
        })
        .filter(|datagram| !datagram.is_empty())
        .collect()
}

/// The `message_seq` after the last epoch-0 handshake message of a flight:
/// the number its Finished carries.
fn numbered_after(datagrams: &[Vec<u8>]) -> u16 {
    datagrams
        .iter()
        .flat_map(|datagram| plaintext_fragments(datagram))
        .map(|(_, header, _)| header.message_seq)
        .max()
        .unwrap()
        + 1
}

#[test]
fn a_forged_hello_request_takes_no_number_from_the_genuine_flight() {
    // before the keys: a HelloRequest under the ServerHello's number, then
    // the genuine flight 4, which is still read from its first message
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(
        &mut hand.client,
        &[forged_retransmission(HandshakeType::HELLO_REQUEST, 0)],
        hand.now,
    );
    deliver(&mut hand.client, &flight4, hand.now);
    let flight5 = drain(&mut hand.client);
    assert!(carries(
        &flight5.concat(),
        HandshakeType::CLIENT_KEY_EXCHANGE
    ));
    assert!(events(&mut hand.client).is_empty());

    // after flight 5: a HelloRequest under the number the server's Finished
    // will carry, which would make the genuine Finished look like a
    // retransmission and leave the handshake to time out
    let finished_seq = numbered_after(&flight4);
    deliver(
        &mut hand.client,
        &[forged_retransmission(
            HandshakeType::HELLO_REQUEST,
            finished_seq,
        )],
        hand.now,
    );
    deliver(&mut hand.server, &flight5, hand.now);
    keyed(&events(&mut hand.server));
    deliver(&mut hand.client, &drain(&mut hand.server), hand.now);
    keyed(&events(&mut hand.client));
    assert_eq!(hand.client.state(), State::Connected);
}

#[test]
fn once_only_the_finished_is_due_an_epoch_zero_message_at_or_past_it_is_discarded() {
    // the client, after flight 5: a ServerHelloDone under the Finished's
    // number, and one past it, would end the handshake as out of place
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    let flight5 = drain(&mut hand.client);
    let finished_seq = numbered_after(&flight4);
    for seq in [finished_seq, finished_seq + 1] {
        deliver(
            &mut hand.client,
            &[forged_retransmission(HandshakeType::SERVER_HELLO_DONE, seq)],
            hand.now,
        );
    }
    assert!(events(&mut hand.client).is_empty());
    assert_eq!(hand.client.state(), State::Handshaking);
    // what came before the Finished is still a retransmission, and answered
    let now = hand.later(Duration::from_secs(1));
    deliver(&mut hand.client, &flight4, now);
    assert!(carries(
        &drain(&mut hand.client).concat(),
        HandshakeType::CLIENT_KEY_EXCHANGE
    ));

    // the server, once CertificateVerify is in: the same, under the number
    // of the client's Finished
    let clear = epoch_zero_only(&flight5);
    deliver(&mut hand.server, &clear, now);
    assert_eq!(hand.server.state(), State::Handshaking);
    let finished_seq = numbered_after(&clear);
    for (msg_type, seq) in [
        (HandshakeType::CERTIFICATE_VERIFY, finished_seq),
        (HandshakeType::CLIENT_KEY_EXCHANGE, finished_seq + 1),
        (HandshakeType::HELLO_REQUEST, finished_seq),
    ] {
        deliver(
            &mut hand.server,
            &[forged_retransmission(msg_type, seq)],
            now,
        );
    }
    assert!(events(&mut hand.server).is_empty());
    assert_eq!(drain(&mut hand.server), [] as [std::vec::Vec<u8>; 0]);
    assert_eq!(hand.server.state(), State::Handshaking);

    deliver(&mut hand.server, &flight5, now);
    keyed(&events(&mut hand.server));
    deliver(&mut hand.client, &drain(&mut hand.server), now);
    keyed(&events(&mut hand.client));
}

#[test]
fn a_connected_server_answers_only_an_authenticated_retransmission_of_the_last_flight() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    let flight5 = drain(&mut hand.client);
    deliver(&mut hand.server, &flight5, hand.now);
    keyed(&events(&mut hand.server));
    assert!(!drain(&mut hand.server).is_empty(), "flight 6");

    // epoch-0 fragments from before flight 6, forged or not, are answered by
    // nothing: one well past the quiet gap each time
    let now = hand.later(Duration::from_secs(1));
    for (msg_type, seq) in [
        (HandshakeType::CLIENT_HELLO, 0),
        (HandshakeType::CERTIFICATE, 1),
    ] {
        deliver(
            &mut hand.server,
            &[forged_retransmission(msg_type, seq)],
            now,
        );
        assert!(drain(&mut hand.server).is_empty(), "{msg_type:?}");
    }
    let now = hand.later(Duration::from_secs(1));
    deliver(&mut hand.server, &epoch_zero_only(&flight5), now);
    assert_eq!(drain(&mut hand.server), [] as [std::vec::Vec<u8>; 0]);

    // the client's own retransmission carries its Finished, protected under
    // a new record number, and is answered with flight 6
    hand.client.handle_timeout(hand.now);
    let again = drain(&mut hand.client);
    assert_ne!(again, [] as [std::vec::Vec<u8>; 0]);
    let now = hand.later(Duration::from_secs(1));
    deliver(&mut hand.server, &again, now);
    let flight6 = drain(&mut hand.server);
    assert_ne!(flight6, [] as [std::vec::Vec<u8>; 0]);
    assert!(events(&mut hand.server).is_empty());
    deliver(&mut hand.client, &flight6, now);
    keyed(&events(&mut hand.client));
}

/// The ClientHello of `hello` under another record sequence number.
fn renumbered(hello: &[Vec<u8>], sequence: u64) -> Vec<Vec<u8>> {
    hello
        .iter()
        .map(|datagram| {
            let mut out = Vec::new();
            for record in records(datagram).map(Result::unwrap) {
                let header = RecordHeader {
                    sequence,
                    ..record.header
                };
                header.encode(&mut out).unwrap();
                out.extend_from_slice(record.fragment);
            }
            out
        })
        .collect()
}

#[test]
fn a_server_does_not_start_its_epoch_zero_above_two_to_the_forty_seventh() {
    for (sequence, accepted) in [
        (1 << 47, true),
        ((1 << 47) + 1, false),
        (MAX_SEQUENCE, false),
    ] {
        let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
        let hello = renumbered(&drain(&mut hand.client), sequence);
        deliver(&mut hand.server, &hello, hand.now);
        let answer = drain(&mut hand.server);
        if accepted {
            assert!(carries(&answer.concat(), HandshakeType::SERVER_HELLO));
            let (record, _, _) = plaintext_fragments(&answer[0])
                .into_iter()
                .find(|(_, header, _)| header.msg_type == HandshakeType::SERVER_HELLO)
                .unwrap();
            assert_eq!(
                record, sequence,
                "the ServerHello goes under the ClientHello's number"
            );
            assert!(events(&mut hand.server).is_empty());
        } else {
            assert_eq!(
                refused(&events(&mut hand.server)),
                Failure::IllegalParameter,
                "{sequence}"
            );
            assert!(!carries(&answer.concat(), HandshakeType::SERVER_HELLO));
            assert_eq!(hand.server.state(), State::Failed);
        }
    }
}

#[test]
fn one_forged_certificate_fragment_does_not_lock_the_genuine_certificate_out() {
    let mut hand = ByHand::new(200);
    let flight4 = hand.flight4();
    let (_, genuine, _) = flight4
        .iter()
        .flat_map(|datagram| plaintext_fragments(datagram))
        .find(|(_, header, _)| header.msg_type == HandshakeType::CERTIFICATE)
        .unwrap();
    assert!(
        genuine.fragment_length < genuine.length,
        "the certificate is cut"
    );
    // ten octets of the certificate's opening, wrong, ahead of the real thing
    let forged = Fragment {
        header: FragmentHeader {
            fragment_offset: 0,
            fragment_length: 10,
            ..genuine
        },
        body: &[0xEE; 10],
    };
    let mut payload = Vec::new();
    forged.encode(&mut payload).unwrap();
    let mut datagram = Vec::new();
    encode_plaintext(
        ContentType::HANDSHAKE,
        ProtocolVersion::DTLS_1_2,
        0,
        7,
        &payload,
        &mut datagram,
    )
    .unwrap();
    deliver(&mut hand.client, &[datagram], hand.now);

    deliver(&mut hand.client, &flight4, hand.now);
    assert!(events(&mut hand.client).is_empty());
    let flight5 = drain(&mut hand.client);
    assert!(
        flight5
            .iter()
            .any(|datagram| carries(datagram, HandshakeType::CLIENT_KEY_EXCHANGE)),
        "the client answered flight 4"
    );
}

#[test]
fn forged_messages_past_the_flight_do_not_crowd_the_genuine_flight_out() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    let last = flight4
        .iter()
        .flat_map(|datagram| plaintext_fragments(datagram))
        .map(|(_, header, _)| header.message_seq)
        .max()
        .unwrap();
    // one octet each of two messages announced at the longest length
    // reassembly takes, numbered past flight 4 and the Finished after it,
    // where no genuine fragment ever comes to replace them
    let limits = Limits::default();
    assert_eq!(limits.max_buffered, 2 * limits.max_message_len);
    for (message_seq, record_sequence) in [(last + 2, 7), (last + 3, 8)] {
        let forged = Fragment {
            header: FragmentHeader {
                msg_type: HandshakeType::CERTIFICATE,
                length: u32::try_from(limits.max_message_len).unwrap(),
                message_seq,
                fragment_offset: 0,
                fragment_length: 1,
            },
            body: &[0xEE],
        };
        let mut payload = Vec::new();
        forged.encode(&mut payload).unwrap();
        let mut datagram = Vec::new();
        encode_plaintext(
            ContentType::HANDSHAKE,
            ProtocolVersion::DTLS_1_2,
            0,
            record_sequence,
            &payload,
            &mut datagram,
        )
        .unwrap();
        deliver(&mut hand.client, &[datagram], hand.now);
    }

    deliver(&mut hand.client, &flight4, hand.now);
    assert!(events(&mut hand.client).is_empty());
    assert!(
        drain(&mut hand.client)
            .iter()
            .any(|datagram| carries(datagram, HandshakeType::CLIENT_KEY_EXCHANGE)),
        "the client answered flight 4"
    );
}

#[test]
fn a_listening_server_reads_nothing_but_a_client_hello() {
    let (one, other) = (identity(1), identity(2));
    let now = Instant::now();
    for cookie_exchange in [true, false] {
        let case = format!("cookies {cookie_exchange}");
        let mut server_config = config(Role::Server, &other, &one);
        server_config.cookie_exchange = cookie_exchange;
        let mut server = Connection::new(server_config, &mut Counter::new(2), now).unwrap();

        // a protected record, which no key it has can open, is not kept
        let mut protected = Vec::new();
        RecordHeader {
            content_type: ContentType::HANDSHAKE,
            version: ProtocolVersion::DTLS_1_2,
            epoch: 1,
            sequence: 0,
            length: 40,
        }
        .encode(&mut protected)
        .unwrap();
        protected.extend_from_slice(&[0xAB; 40]);
        server.handle_datagram(&protected, now);
        assert!(server.core.early.is_empty(), "{case}");

        // and alerts in the clear, which anyone can forge before any hello,
        // end nothing: neither a fatal one nor close_notify
        for alert in [
            Alert::fatal(AlertDescription::HANDSHAKE_FAILURE),
            Alert::warning(AlertDescription::CLOSE_NOTIFY),
        ] {
            let mut datagram = Vec::new();
            encode_plaintext(
                ContentType::ALERT,
                ProtocolVersion::DTLS_1_2,
                0,
                3,
                &alert.encode(),
                &mut datagram,
            )
            .unwrap();
            server.handle_datagram(&datagram, now);
        }
        assert!(events(&mut server).is_empty(), "{case}");
        assert!(drain(&mut server).is_empty(), "{case}");
        assert_eq!(server.state(), State::Handshaking, "{case}");

        // the genuine client still gets its handshake
        let mut client = Connection::new(
            config(Role::Client, &one, &other),
            &mut Counter::new(1),
            now,
        )
        .unwrap();
        for _ in 0..4 {
            deliver(&mut server, &drain(&mut client), now);
            deliver(&mut client, &drain(&mut server), now);
        }
        keyed(&events(&mut client));
        keyed(&events(&mut server));
    }
}

#[test]
fn a_renegotiation_numbered_afresh_as_rfc_6347_numbers_it_is_refused_too() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    deliver(&mut hand.server, &drain(&mut hand.client), hand.now);
    deliver(&mut hand.client, &drain(&mut hand.server), hand.now);
    keyed(&events(&mut hand.client));
    keyed(&events(&mut hand.server));
    let now = hand.later(Duration::from_secs(1));

    // §4.2.2: "The first message each side transmits in each handshake always
    // has message_seq = 0", "the HelloRequest will have message_seq = 0"
    let request = |end: &mut Connection, msg_type: HandshakeType| {
        let mut fragment = Vec::new();
        encode_message(msg_type, 0, &[], &mut fragment).unwrap();
        let (write, protection) = end.core.writer.epoch1.as_mut().unwrap();
        let mut datagram = Vec::new();
        protection
            .seal(
                ContentType::HANDSHAKE,
                ProtocolVersion::DTLS_1_2,
                write.epoch(),
                write.next_sequence().unwrap(),
                &fragment,
                &mut datagram,
            )
            .unwrap();
        datagram
    };
    let refusal = |asker: &Connection, answer: &[Vec<u8>]| {
        assert_eq!(answer.len(), 1, "one datagram");
        let mut in_answer = records(&answer[0]).map(Result::unwrap);
        let record = in_answer.next().unwrap();
        assert!(in_answer.next().is_none(), "one record");
        assert_eq!(record.header.epoch, 1);
        assert_eq!(record.header.content_type, ContentType::ALERT);
        let (_, protection) = asker.core.read1.as_ref().unwrap();
        let mut plaintext = Vec::new();
        protection.open(&record, &mut plaintext).unwrap();
        Alert::parse(&plaintext).unwrap()
    };

    let hello_request = request(&mut hand.server, HandshakeType::HELLO_REQUEST);
    hand.client.handle_datagram(&hello_request, now);
    let answer = drain(&mut hand.client);
    assert_eq!(
        refusal(&hand.server, &answer),
        Alert::warning(AlertDescription::NO_RENEGOTIATION)
    );

    let client_hello = request(&mut hand.client, HandshakeType::CLIENT_HELLO);
    hand.server.handle_datagram(&client_hello, now);
    let answer = drain(&mut hand.server);
    assert_eq!(
        refusal(&hand.client, &answer),
        Alert::warning(AlertDescription::NO_RENEGOTIATION)
    );

    for end in [&mut hand.client, &mut hand.server] {
        assert!(events(end).is_empty());
        assert_eq!(end.state(), State::Connected);
    }
}

#[test]
fn close_notify_is_answered_and_closes_both_ends() {
    let (one, other) = (identity(1), identity(2));
    let mut pair = Pair::new(pair_configs(Role::Server, &one, &other), Path::CLEAN, 29);
    pair.run(Duration::from_secs(5));
    keyed(&pair.events[0]);
    keyed(&pair.events[1]);
    let sent = pair.sent.len();

    pair.ends[0].close();
    assert_eq!(pair.ends[0].state(), State::Closed);
    pair.run(Duration::from_secs(5));
    assert!(matches!(pair.events[1].last(), Some(Event::Closed)));
    assert_eq!(pair.ends[1].state(), State::Closed);
    // one close_notify each way, and nothing after
    assert_eq!(pair.sent.len(), sent + 2);
    assert_eq!(pair.sent[sent].0, 0);
    assert_eq!(pair.sent[sent + 1].0, 1);
    assert_eq!(pair.events[0].len(), 1);
    for end in &mut pair.ends {
        assert_eq!(end.send_application_data(b"x"), Err(Error::NotConnected));
    }
}

#[test]
fn a_renegotiation_is_refused_with_a_warning_and_the_connection_carries_on() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    deliver(&mut hand.server, &drain(&mut hand.client), hand.now);
    deliver(&mut hand.client, &drain(&mut hand.server), hand.now);
    keyed(&events(&mut hand.client));
    keyed(&events(&mut hand.server));

    // (the end that asks, the message it asks with)
    let asks = [
        (&mut hand.server, HandshakeType::HELLO_REQUEST),
        (&mut hand.client, HandshakeType::CLIENT_HELLO),
    ];
    let mut requests = Vec::new();
    for (end, msg_type) in asks {
        let mut fragment = Vec::new();
        encode_message(msg_type, end.core.send_seq, &[], &mut fragment).unwrap();
        let (write, protection) = end.core.writer.epoch1.as_mut().unwrap();
        let mut datagram = Vec::new();
        protection
            .seal(
                ContentType::HANDSHAKE,
                ProtocolVersion::DTLS_1_2,
                write.epoch(),
                write.next_sequence().unwrap(),
                &fragment,
                &mut datagram,
            )
            .unwrap();
        requests.push(datagram);
    }
    let now = hand.now;
    for (end, request) in [
        (&mut hand.client, &requests[0]),
        (&mut hand.server, &requests[1]),
    ] {
        end.handle_datagram(request, now);
        let answer = drain(end);
        assert_eq!(answer.len(), 1);
        let (record, _) = Record::parse(&answer[0]).unwrap();
        assert_eq!(record.header.epoch, 1);
        assert_eq!(record.header.content_type, ContentType::ALERT);
        assert!(events(end).is_empty());
        assert_eq!(end.state(), State::Connected);
    }
}

#[test]
fn a_configuration_no_handshake_can_come_of_is_refused() {
    let (one, other) = (identity(1), identity(2));
    let now = Instant::now();
    let make = |config: Config| Connection::new(config, &mut Counter::new(1), now).err();
    let base = || config(Role::Client, &one, &other);

    let mut c = base();
    c.peer_fingerprints.clear();
    assert_eq!(make(c), Some(Error::IllegalValue));
    let mut c = base();
    c.srtp_profiles.clear();
    assert_eq!(make(c), Some(Error::IllegalValue));
    let mut c = base();
    c.srtp_profiles = vec![SrtpProtectionProfile::NULL_HMAC_SHA1_80];
    assert_eq!(make(c), Some(Error::IllegalValue));
    let mut c = base();
    c.srtp_profiles = vec![
        SrtpProtectionProfile::AEAD_AES_128_GCM,
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
        SrtpProtectionProfile::AEAD_AES_128_GCM,
    ];
    assert_eq!(make(c), Some(Error::IllegalValue));
    let mut c = base();
    c.certificate = other.certificate.clone();
    assert_eq!(make(c), Some(Error::IllegalValue));
    let mut c = base();
    c.retransmission.initial = Duration::ZERO;
    assert_eq!(make(c), Some(Error::IllegalValue));
    let mut c = base();
    c.retransmission.max = Duration::from_millis(999);
    assert_eq!(make(c), Some(Error::IllegalValue));
    let mut c = base();
    c.max_datagram = record::HEADER_LEN + record::GCM_OVERHEAD + handshake::HEADER_LEN;
    assert_eq!(make(c), Some(Error::MtuTooSmall));
    let mut c = base();
    c.max_datagram = record::HEADER_LEN + record::GCM_OVERHEAD + handshake::HEADER_LEN + 1;
    assert_eq!(make(c), None);
}

#[test]
fn nothing_secret_is_printed() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    deliver(&mut hand.server, &drain(&mut hand.client), hand.now);
    let seen = events(&mut hand.server);
    let keys = keyed(&seen);
    assert_eq!(
        format!("{keys:?} {:?}", hand.server),
        "SrtpKeying { role: Server, profile: SrtpProtectionProfile(8), .. } \
         Connection { role: Server, state: Connected, .. }"
    );
}

#[test]
fn every_failure_says_which_rule_broke_and_sends_the_alert_it_names() {
    let every = [
        (Failure::FingerprintMismatch, Some(42)),
        (Failure::UnusableCertificate, Some(43)),
        (Failure::NoCertificate, Some(40)),
        (Failure::NoExtendedMasterSecret, Some(40)),
        (Failure::NoSrtpProfile, Some(40)),
        (Failure::NoCommonParameters, Some(40)),
        (Failure::ProtocolVersion, Some(70)),
        (Failure::IllegalParameter, Some(47)),
        (Failure::UnsupportedExtension, Some(110)),
        (Failure::Renegotiation, Some(40)),
        (Failure::BadSignature, Some(51)),
        (Failure::BadFinished, Some(51)),
        (Failure::UnexpectedMessage, Some(10)),
        (Failure::Malformed(Error::Truncated), Some(50)),
        (Failure::PeerAlert(AlertDescription::BAD_CERTIFICATE), None),
        (Failure::Timeout, None),
        (Failure::Internal(Error::SequenceExhausted), Some(80)),
    ];
    for (failure, alert) in every {
        assert_eq!(failure.alert().map(|d| d.0), alert, "{failure:?}");
        // an exhaustive match, so a variant added without a line above fails
        // to compile rather than going untested
        match failure {
            Failure::FingerprintMismatch
            | Failure::UnusableCertificate
            | Failure::NoCertificate
            | Failure::NoExtendedMasterSecret
            | Failure::NoSrtpProfile
            | Failure::NoCommonParameters
            | Failure::ProtocolVersion
            | Failure::IllegalParameter
            | Failure::UnsupportedExtension
            | Failure::Renegotiation
            | Failure::BadSignature
            | Failure::BadFinished
            | Failure::UnexpectedMessage
            | Failure::Malformed(_)
            | Failure::PeerAlert(_)
            | Failure::Timeout
            | Failure::Internal(_) => {}
        }
    }
    let mut texts: Vec<String> = every
        .iter()
        .map(|(failure, _)| failure.to_string())
        .collect();
    texts.sort_unstable();
    texts.dedup();
    assert_eq!(texts.len(), every.len());
}

#[test]
fn a_listening_server_holds_nothing_for_hellos_it_cannot_read_or_that_carry_no_cookie() {
    let (one, other) = (identity(1), identity(2));
    let now = Instant::now();
    let mut server = Connection::new(
        config(Role::Server, &other, &one),
        &mut Counter::new(2),
        now,
    )
    .unwrap();
    let mut client = Connection::new(
        config(Role::Client, &one, &other),
        &mut Counter::new(1),
        now,
    )
    .unwrap();
    let hello = drain(&mut client).remove(0);

    // every octet of a genuine hello changed in turn, and every truncation:
    // each is answered at most with a HelloVerifyRequest, and none moves the
    // server out of listening or makes it panic
    for position in 0..hello.len() {
        for flip in [0x01, 0x80, 0xFF] {
            let mut mutated = hello.clone();
            mutated[position] ^= flip;
            server.handle_datagram(&mutated, now);
        }
        server.handle_datagram(&hello[..position], now);
    }
    let mut random = Counter::new(0xD715);
    let mut noise = [0u8; 300];
    for round in 0..2000 {
        random.fill(&mut noise);
        server.handle_datagram(&noise[..round % noise.len()], now);
    }
    for answer in drain(&mut server) {
        assert!(carries(&answer, HandshakeType::HELLO_VERIFY_REQUEST));
    }
    assert!(events(&mut server).is_empty());
    assert!(matches!(&server.handshake, Handshake::Server(s) if s.is_listening()));
    assert_eq!(server.poll_timeout(), None);
}

#[test]
fn a_finished_that_overtakes_the_key_exchange_is_held_until_the_keys_exist() {
    let mut hand = ByHand::new(200);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    let mut flight5 = drain(&mut hand.client);
    assert!(flight5.len() > 2);
    let last = records(flight5.last().unwrap())
        .map(Result::unwrap)
        .last()
        .unwrap();
    assert_eq!(last.header.epoch, 1, "the protected Finished comes last");
    // it arrives first, before the Certificate the keys wait behind
    flight5.reverse();
    deliver(&mut hand.server, &flight5, hand.now);
    keyed(&events(&mut hand.server));
}

#[test]
fn a_plaintext_alert_ends_a_handshake_and_not_an_established_connection() {
    let alert = |description| {
        let mut datagram = Vec::new();
        encode_plaintext(
            ContentType::ALERT,
            ProtocolVersion::DTLS_1_2,
            0,
            5,
            &Alert::fatal(description).encode(),
            &mut datagram,
        )
        .unwrap();
        datagram
    };

    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    drop(hand.flight4());
    deliver(
        &mut hand.client,
        &[alert(AlertDescription::HANDSHAKE_FAILURE)],
        hand.now,
    );
    assert_eq!(
        refused(&events(&mut hand.client)),
        Failure::PeerAlert(AlertDescription::HANDSHAKE_FAILURE)
    );
    // a peer's alert is not answered with one
    assert_eq!(drain(&mut hand.client), [] as [std::vec::Vec<u8>; 0]);

    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    deliver(&mut hand.server, &drain(&mut hand.client), hand.now);
    deliver(&mut hand.client, &drain(&mut hand.server), hand.now);
    keyed(&events(&mut hand.client));
    keyed(&events(&mut hand.server));
    let now = hand.now;
    for end in [&mut hand.client, &mut hand.server] {
        end.handle_datagram(&alert(AlertDescription::HANDSHAKE_FAILURE), now);
        assert!(events(end).is_empty());
        assert_eq!(end.state(), State::Connected);
    }
}

/// The index of the end whose message is rewritten — the client is 0 —, the
/// message, the rewrite, why the other end refuses it, and the alert it sends.
type Rewrite = (
    usize,
    HandshakeType,
    fn(&[u8]) -> Vec<u8>,
    Failure,
    AlertDescription,
);

/// A ClientHello the server refuses, one way per rule.
fn client_hello_rewrites() -> [Rewrite; 6] {
    [
        (
            0,
            HandshakeType::CLIENT_HELLO,
            |body| edit_client_hello(body, &|h| h.client_version = ProtocolVersion::DTLS_1_0),
            Failure::ProtocolVersion,
            AlertDescription::PROTOCOL_VERSION,
        ),
        (
            0,
            HandshakeType::CLIENT_HELLO,
            |body| edit_client_hello(body, &|h| h.compression_methods = vec![1]),
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        (
            0,
            HandshakeType::CLIENT_HELLO,
            |body| edit_client_hello(body, &|h| h.cipher_suites = vec![CipherSuite(0xC02F)]),
            Failure::NoCommonParameters,
            AlertDescription::HANDSHAKE_FAILURE,
        ),
        (
            0,
            HandshakeType::CLIENT_HELLO,
            |body| {
                edit_client_hello(body, &|h| {
                    h.extensions = Some(without(
                        h.extensions.as_ref(),
                        ExtensionType::SIGNATURE_ALGORITHMS,
                    ));
                })
            },
            Failure::NoCommonParameters,
            AlertDescription::HANDSHAKE_FAILURE,
        ),
        (
            0,
            HandshakeType::CLIENT_HELLO,
            |body| {
                edit_client_hello(body, &|h| {
                    let mut extensions =
                        without(h.extensions.as_ref(), ExtensionType::RENEGOTIATION_INFO);
                    extensions
                        .push(Extension::RenegotiationInfo(vec![1; 12]))
                        .unwrap();
                    h.extensions = Some(extensions);
                })
            },
            Failure::Renegotiation,
            AlertDescription::HANDSHAKE_FAILURE,
        ),
        (
            0,
            HandshakeType::CLIENT_HELLO,
            |body| {
                edit_client_hello(body, &|h| {
                    let mut extensions =
                        without(h.extensions.as_ref(), ExtensionType::EC_POINT_FORMATS);
                    extensions
                        .push(Extension::EcPointFormats(vec![EcPointFormat(1)]))
                        .unwrap();
                    h.extensions = Some(extensions);
                })
            },
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
    ]
}

/// The last octet of a message body, flipped: for `ServerKeyExchange` and
/// `CertificateVerify`, whose signature is the body's last field, this
/// invalidates the signature and touches nothing else.
fn flip_last_octet(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    let last = out.len() - 1;
    out[last] ^= 1;
    out
}

/// A ServerKeyExchange that names `{sha256, rsa}` for its signature, the
/// signature itself untouched: `curve_type`, `named_curve`, the point with its
/// one-octet length, and then the pair (RFC 8422 §5.4).
fn server_key_exchange_claiming_rsa(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    let pair = 4 + usize::from(out[3]);
    out[pair + 1] = SignatureAndHash::RSA_PKCS1_SHA256.signature;
    out
}

/// A CertificateVerify that names `{sha256, rsa}`, its pair being the first
/// two octets (RFC 5246 §4.7).
fn certificate_verify_claiming_rsa(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out[1] = SignatureAndHash::RSA_PKCS1_SHA256.signature;
    out
}

/// A ServerHello the client refuses, and a client Certificate the server
/// refuses, one way per rule.
fn later_rewrites() -> [Rewrite; 10] {
    [
        // a suite this client offers, but not the one the server's P-256
        // certificate can sign for (RFC 8422 §2.2)
        (
            1,
            HandshakeType::SERVER_HELLO,
            |body| {
                edit_server_hello(body, &|h| {
                    h.cipher_suite = CipherSuite::ECDHE_RSA_WITH_AES_128_GCM_SHA256;
                })
            },
            Failure::UnusableCertificate,
            AlertDescription::UNSUPPORTED_CERTIFICATE,
        ),
        // an RSA pair claimed for a signature under a P-256 key, each way
        (
            1,
            HandshakeType::SERVER_KEY_EXCHANGE,
            server_key_exchange_claiming_rsa,
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        (
            0,
            HandshakeType::CERTIFICATE_VERIFY,
            certificate_verify_claiming_rsa,
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        (
            1,
            HandshakeType::SERVER_HELLO,
            |body| edit_server_hello(body, &|h| h.server_version = ProtocolVersion::DTLS_1_0),
            Failure::ProtocolVersion,
            AlertDescription::PROTOCOL_VERSION,
        ),
        (
            1,
            HandshakeType::SERVER_HELLO,
            |body| edit_server_hello(body, &|h| h.compression_method = 1),
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        (
            1,
            HandshakeType::SERVER_HELLO,
            |body| {
                edit_server_hello(body, &|h| {
                    let mut extensions = h.extensions.clone().unwrap();
                    extensions
                        .push(Extension::Unknown {
                            extension_type: ExtensionType(0x1234),
                            data: Vec::new(),
                        })
                        .unwrap();
                    h.extensions = Some(extensions);
                })
            },
            Failure::UnsupportedExtension,
            AlertDescription::UNSUPPORTED_EXTENSION,
        ),
        (
            1,
            HandshakeType::SERVER_HELLO,
            |body| {
                edit_server_hello(body, &|h| {
                    let mut extensions = without(h.extensions.as_ref(), ExtensionType::USE_SRTP);
                    extensions
                        .push(Extension::UseSrtp(UseSrtp {
                            profiles: vec![SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80],
                            mki: vec![7],
                        }))
                        .unwrap();
                    h.extensions = Some(extensions);
                })
            },
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        (
            0,
            HandshakeType::CERTIFICATE,
            |_| vec![0, 0, 0],
            Failure::NoCertificate,
            AlertDescription::HANDSHAKE_FAILURE,
        ),
        (
            1,
            HandshakeType::SERVER_KEY_EXCHANGE,
            flip_last_octet,
            Failure::BadSignature,
            AlertDescription::DECRYPT_ERROR,
        ),
        (
            0,
            HandshakeType::CERTIFICATE_VERIFY,
            flip_last_octet,
            Failure::BadSignature,
            AlertDescription::DECRYPT_ERROR,
        ),
    ]
}

#[test]
fn each_way_a_hello_or_certificate_can_be_wrong_is_refused_with_its_own_reason() {
    let (one, other) = (identity(1), identity(2));
    for (sender, msg_type, edit, reason, alert) in
        client_hello_rewrites().into_iter().chain(later_rewrites())
    {
        let mut pair = Pair::new(pair_configs(Role::Client, &one, &other), Path::CLEAN, 31);
        pair.tamper = Some(Box::new(move |from, datagram| {
            if from == sender {
                rewrite(&datagram, msg_type, &edit)
            } else {
                datagram
            }
        }));
        pair.run(Duration::from_secs(10));
        assert_eq!(refused(&pair.events[1 - sender]), reason, "{msg_type:?}");
        assert_eq!(
            refused(&pair.events[sender]),
            Failure::PeerAlert(alert),
            "{msg_type:?} {reason:?}"
        );
    }
}

/// A Certificate message body carrying one certificate (RFC 5246 §7.4.2).
fn certificate_body(der: &[u8]) -> Vec<u8> {
    let one = u32::try_from(der.len()).unwrap().to_be_bytes();
    let list = u32::try_from(der.len() + 3).unwrap().to_be_bytes();
    let mut body = list[1..].to_vec();
    body.extend_from_slice(&one[1..]);
    body.extend_from_slice(der);
    body
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_client_that_certifies_with_rsa_is_held_to_the_rsa_pair_and_its_signature() {
    // A server told to expect an RSA certificate, and a client whose
    // Certificate is rewritten to carry it: the key is read, so what the
    // CertificateVerify then claims is checked against an RSA key. Nothing
    // here can sign with RSA, so both cases are refusals — the right one each.
    type Verify = fn(&[u8]) -> Vec<u8>;
    let rsa_certificate = unhex(crate::x509::rsa_fixtures::CERTIFICATE_2048);
    let rsa_fingerprint = Fingerprint::of(HashFunction::Sha256, &rsa_certificate);
    let (one, other) = (identity(1), identity(2));
    let cases: [(Verify, Failure, AlertDescription); 2] = [
        // the P-256 pair the client really used, now under an RSA key
        (
            <[u8]>::to_vec,
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        // the RSA pair, over a modulus-length signature that is not one
        (
            |_| {
                let mut out = vec![0x04, 0x01, 0x01, 0x00];
                out.extend(core::iter::repeat_n(0x5A, 256));
                out
            },
            Failure::BadSignature,
            AlertDescription::DECRYPT_ERROR,
        ),
    ];
    for (verify, reason, alert) in cases {
        let mut configs = pair_configs(Role::Client, &one, &other);
        configs[1] = Config::new(
            Role::Server,
            other.key.clone(),
            other.certificate.clone(),
            vec![rsa_fingerprint.clone()],
        );
        let mut pair = Pair::new(configs, Path::CLEAN, 37);
        let certificate = rsa_certificate.clone();
        pair.tamper = Some(Box::new(move |from, datagram| {
            if from != 0 {
                return datagram;
            }
            let swapped = rewrite(&datagram, HandshakeType::CERTIFICATE, &|_| {
                certificate_body(&certificate)
            });
            rewrite(&swapped, HandshakeType::CERTIFICATE_VERIFY, &verify)
        }));
        pair.run(Duration::from_secs(10));
        assert_eq!(refused(&pair.events[1]), reason);
        assert_eq!(refused(&pair.events[0]), Failure::PeerAlert(alert));
    }
}

/// A HelloVerifyRequest the client is holding open for, under `message_seq`,
/// carrying `cookie`.
fn hello_verify_request_datagram(message_seq: u16, cookie: u8) -> Vec<u8> {
    let mut body = Vec::new();
    HelloVerifyRequest {
        server_version: ProtocolVersion::DTLS_1_0,
        cookie: vec![cookie; 8],
    }
    .encode(&mut body)
    .unwrap();
    let mut fragment = Vec::new();
    encode_message(
        HandshakeType::HELLO_VERIFY_REQUEST,
        message_seq,
        &body,
        &mut fragment,
    )
    .unwrap();
    let mut datagram = Vec::new();
    encode_plaintext(
        ContentType::HANDSHAKE,
        ProtocolVersion::DTLS_1_2,
        0,
        u64::from(message_seq),
        &fragment,
        &mut datagram,
    )
    .unwrap();
    datagram
}

#[test]
fn a_server_that_keeps_asking_for_a_new_cookie_is_eventually_given_up_on() {
    // RFC 6347 §4.2.1 lets a server send more than one HelloVerifyRequest
    // (it changed its secret); a server that never stops is not one the
    // handshake can ever get past, so the client gives up on it.
    let (one, other) = (identity(1), identity(2));
    let now = Instant::now();
    let mut client = Connection::new(
        config(Role::Client, &one, &other),
        &mut Counter::new(1),
        now,
    )
    .unwrap();
    assert!(!drain(&mut client).is_empty(), "the first ClientHello");

    for round in 0..4u16 {
        client.handle_datagram(&hello_verify_request_datagram(round, 1), now);
        assert!(events(&mut client).is_empty(), "round {round}");
        assert!(
            !drain(&mut client).is_empty(),
            "round {round}: the client answers with a fresh ClientHello"
        );
        assert_eq!(client.state(), State::Handshaking, "round {round}");
    }
    // the fifth HelloVerifyRequest is one too many
    client.handle_datagram(&hello_verify_request_datagram(4, 1), now);
    assert_eq!(refused(&events(&mut client)), Failure::UnexpectedMessage);
    assert_eq!(client.state(), State::Failed);
}

#[test]
fn an_alert_before_this_ends_own_change_cipher_spec_is_sent_in_epoch_zero() {
    // the server installs its epoch-1 keys as soon as it reads the client's
    // ClientKeyExchange, well before it sends its own ChangeCipherSpec and
    // Finished; a bad Finished from the client is refused before that point,
    // so the alert saying why goes out in the epoch this end is still
    // writing in — epoch 0, not the epoch its read keys happen to occupy.
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    drop(drain(&mut hand.client));
    {
        let flight = hand.client.core.flight.as_mut().unwrap();
        let body = flight
            .iter_mut()
            .find_map(|item| match item {
                Item::Handshake { msg_type, body, .. } if *msg_type == HandshakeType::FINISHED => {
                    Some(body)
                }
                _ => None,
            })
            .unwrap();
        body[0] ^= 1;
    }
    let now = hand.later(Duration::from_secs(1));
    hand.client.handle_timeout(now);
    deliver(&mut hand.server, &drain(&mut hand.client), now);
    assert_eq!(refused(&events(&mut hand.server)), Failure::BadFinished);

    let sent = drain(&mut hand.server);
    assert_eq!(sent.len(), 1);
    let (record, rest) = Record::parse(&sent[0]).unwrap();
    assert_eq!(rest, []);
    assert_eq!(
        record.header.epoch, 0,
        "the server had not sent its own ChangeCipherSpec yet"
    );
    assert_eq!(record.header.content_type, ContentType::ALERT);
    assert_eq!(
        Alert::parse(record.fragment).unwrap(),
        Alert::fatal(AlertDescription::DECRYPT_ERROR)
    );
}

#[test]
fn a_server_holds_at_most_eight_epoch_one_records_before_its_own_keys_exist() {
    // a server that has accepted a ClientHello, but not yet the
    // ClientKeyExchange that lets it install its epoch-1 keys, is exactly
    // the "a few epoch-1 records" case the module documentation describes:
    // bounded, not unbounded, so a peer cannot make it hold an arbitrary
    // amount on its way to the keys.
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    drop(hand.flight4());
    assert!(hand.server.core.read1.is_none());
    for sequence in 0..20u64 {
        let mut datagram = Vec::new();
        RecordHeader {
            content_type: ContentType::HANDSHAKE,
            version: ProtocolVersion::DTLS_1_2,
            epoch: 1,
            sequence,
            length: 12,
        }
        .encode(&mut datagram)
        .unwrap();
        datagram.extend_from_slice(&[0xAB; 12]);
        hand.server.handle_datagram(&datagram, hand.now);
    }
    assert_eq!(hand.server.core.early.len(), 8);
}

/// What a man in the middle who cannot sign might still rewrite, one way per
/// rule: a suite or version the client never offered, a curve it never
/// offered, a point that is not on the curve, a request for a certificate
/// kind it cannot present.
fn downgrade_rewrites() -> [Rewrite; 6] {
    [
        // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: the same key, never offered
        (
            1,
            HandshakeType::SERVER_HELLO,
            |body| edit_server_hello(body, &|h| h.cipher_suite = CipherSuite(0xC02C)),
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        // DTLS 1.3's version number in a ServerHello
        (
            1,
            HandshakeType::SERVER_HELLO,
            |body| {
                edit_server_hello(body, &|h| {
                    h.server_version = ProtocolVersion {
                        major: 254,
                        minor: 252,
                    };
                })
            },
            Failure::ProtocolVersion,
            AlertDescription::PROTOCOL_VERSION,
        ),
        // secp384r1 named in place of secp256r1: curve_type, then the group
        (
            1,
            HandshakeType::SERVER_KEY_EXCHANGE,
            |body| {
                let mut out = body.to_vec();
                out[1..3].copy_from_slice(&0x0018u16.to_be_bytes());
                out
            },
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        // the client's point moved off the curve: the last octet of y
        (
            0,
            HandshakeType::CLIENT_KEY_EXCHANGE,
            flip_last_octet,
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        // the client's point in the compressed form RFC 8422 deprecates
        (
            0,
            HandshakeType::CLIENT_KEY_EXCHANGE,
            |body| {
                let mut out = body.to_vec();
                out[1] = 0x03;
                out
            },
            Failure::IllegalParameter,
            AlertDescription::ILLEGAL_PARAMETER,
        ),
        // a request naming neither kind of key this client certifies with
        (
            1,
            HandshakeType::CERTIFICATE_REQUEST,
            |body| {
                let mut out = body.to_vec();
                let count = usize::from(out[0]);
                for kind in &mut out[1..=count] {
                    *kind = 2;
                }
                out
            },
            Failure::NoCommonParameters,
            AlertDescription::HANDSHAKE_FAILURE,
        ),
    ]
}

#[test]
fn a_suite_version_curve_or_point_that_was_never_offered_is_refused() {
    let (one, other) = (identity(1), identity(2));
    for (sender, msg_type, edit, reason, alert) in downgrade_rewrites() {
        let mut pair = Pair::new(pair_configs(Role::Client, &one, &other), Path::CLEAN, 37);
        pair.tamper = Some(Box::new(move |from, datagram| {
            if from == sender {
                rewrite(&datagram, msg_type, &edit)
            } else {
                datagram
            }
        }));
        pair.run(Duration::from_secs(10));
        assert_eq!(refused(&pair.events[1 - sender]), reason, "{msg_type:?}");
        assert_eq!(
            refused(&pair.events[sender]),
            Failure::PeerAlert(alert),
            "{msg_type:?} {reason:?}"
        );
    }
}

#[test]
fn a_hello_rewritten_on_the_path_to_a_later_version_is_caught_by_the_transcript() {
    let (one, other) = (identity(1), identity(2));
    let mut pair = Pair::new(pair_configs(Role::Client, &one, &other), Path::CLEAN, 41);
    pair.tamper = Some(Box::new(|from, datagram| {
        if from == 0 {
            rewrite(&datagram, HandshakeType::CLIENT_HELLO, &|body| {
                edit_client_hello(body, &|h| {
                    h.client_version = ProtocolVersion {
                        major: 254,
                        minor: 252,
                    };
                })
            })
        } else {
            datagram
        }
    }));
    pair.run(Duration::from_secs(10));
    // the server answers a later version with 1.2, as RFC 5246 §E.1 has it,
    // and the client's CertificateVerify, over the hello it really sent, no
    // longer verifies over the one the server saw
    let server_hello = pair
        .sent
        .iter()
        .filter(|(from, _)| *from == 1)
        .flat_map(|(_, datagram)| plaintext_fragments(datagram))
        .find(|(_, header, _)| header.msg_type == HandshakeType::SERVER_HELLO)
        .map(|(_, _, body)| ServerHello::parse(&body).unwrap())
        .unwrap();
    assert_eq!(server_hello.server_version, ProtocolVersion::DTLS_1_2);
    assert_eq!(refused(&pair.events[1]), Failure::BadSignature);
}

#[test]
fn a_replayed_protected_record_is_delivered_once_and_a_relabelled_one_never() {
    let mut hand = ByHand::new(DEFAULT_MAX_DATAGRAM);
    let flight4 = hand.flight4();
    deliver(&mut hand.client, &flight4, hand.now);
    deliver(&mut hand.server, &drain(&mut hand.client), hand.now);
    deliver(&mut hand.client, &drain(&mut hand.server), hand.now);
    keyed(&events(&mut hand.client));
    keyed(&events(&mut hand.server));

    hand.client.send_application_data(b"once").unwrap();
    let record = drain(&mut hand.client);
    for _ in 0..3 {
        deliver(&mut hand.server, &record, hand.now);
    }
    let seen = events(&mut hand.server);
    assert!(
        matches!(&seen[..], [Event::ApplicationData(data)] if data == b"once"),
        "{seen:?}"
    );

    // the same record relabelled epoch 2: no epoch past 1 is read at all
    let mut relabelled = record.concat();
    relabelled[3..5].copy_from_slice(&2u16.to_be_bytes());
    // and renumbered within epoch 1: the window lets it through, and the
    // tag, whose additional data carries the number, does not
    let mut renumbered = record.concat();
    renumbered[10] ^= 0x40;
    deliver(&mut hand.server, &[relabelled, renumbered], hand.now);
    assert!(events(&mut hand.server).is_empty());
    assert_eq!(hand.server.state(), State::Connected);
}
