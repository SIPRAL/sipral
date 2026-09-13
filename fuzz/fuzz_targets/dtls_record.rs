// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Hostile datagrams, through the DTLS record layer and into a handshake.
//!
//! Every octet a DTLS endpoint reads arrives before any of it is
//! authenticated: the record header with its epoch and 48-bit sequence
//! number, the length that says where the next record begins, the handshake
//! fragment headers inside a record, and the reassembly they drive. A
//! protected record gets as far as the replay window and the authentication
//! tag under a key the fuzzer cannot know, which is the point -- what is under
//! test is everything ahead of that check, none of which may panic.
//!
//! The input is a run of datagrams, two octets of length in front of each,
//! since a DTLS datagram routinely needs more than one octet to say how long it
//! is. The whole run goes three ways, each kept across the run so the state
//! that only exists between datagrams is reached:
//!
//! - through `records`, the plaintext limit, the handshake fragments, one
//!   `Reassembler` and the message parser behind it, and through
//!   `GcmProtection::open` behind one `ReplayWindow`;
//! - into a server `Connection` without a cookie exchange, so a ClientHello the
//!   fuzzer finds gets past the stateless door and drives the handshake;
//! - into a client `Connection`, whose ClientHello is already out and which
//!   reads whatever arrives as a server's flights.
//!
//! Both ends are made from fixed keys and a fixed random source -- the ones
//! `tools/fuzz-seeds` makes them from -- so a seed recorded from a real
//! handshake takes the server, or the client, through to its Finished.

#![no_main]

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use sipral_dtls::handshake::{self, HandshakeMessage, Limits, Offered, Reassembler};
use sipral_dtls::keys::EcdsaKey;
use sipral_dtls::record::{self, ContentType, GcmProtection, ReplayWindow};
use sipral_dtls::x509::{Certificate, CertificateParams};
use sipral_dtls::{Config, Connection, Random, Role};

/// The seeds of the two ends' random sources.
const SERVER_SEED: u64 = 0x5E;
const CLIENT_SEED: u64 = 0xC1;

/// A linear congruential sequence: the same octets every run, and nothing
/// fit to key a real handshake with.
struct Fixed(u64);

impl Random for Fixed {
    fn fill(&mut self, dest: &mut [u8]) {
        for octet in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *octet = self.0.to_be_bytes()[0];
        }
    }
}

fn identity(scalar: u8, seed: u64) -> (EcdsaKey, Certificate) {
    let params = CertificateParams {
        common_name: "sipral-fuzz",
        not_before: 1_785_542_400,
        not_after: 1_788_134_400,
    };
    let key = EcdsaKey::from_scalar(&[scalar; 32]).expect("a scalar below the group order");
    let certificate =
        Certificate::self_signed(&key, &params, &mut Fixed(seed)).expect("a certificate");
    (key, certificate)
}

/// The server's configuration and the client's, made once.
fn configs() -> &'static (Config, Config) {
    static CONFIGS: OnceLock<(Config, Config)> = OnceLock::new();
    CONFIGS.get_or_init(|| {
        let (server_key, server_certificate) = identity(0x5E, SERVER_SEED);
        let (client_key, client_certificate) = identity(0xC1, CLIENT_SEED);
        let mut server = Config::new(
            Role::Server,
            server_key,
            server_certificate.clone(),
            vec![client_certificate.fingerprint()],
        );
        server.cookie_exchange = false;
        let client = Config::new(
            Role::Client,
            client_key,
            client_certificate,
            vec![server_certificate.fingerprint()],
        );
        (server, client)
    })
}

fn start() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

fuzz_target!(|data: &[u8]| {
    let (server_config, client_config) = configs();
    let mut now = start();
    let mut server = Connection::new(server_config.clone(), &mut Fixed(SERVER_SEED), now)
        .expect("the server's configuration is valid");
    let mut client = Connection::new(client_config.clone(), &mut Fixed(CLIENT_SEED), now)
        .expect("the client's configuration is valid");
    let protection = GcmProtection::new(&[0x42; 16], &[0x24; 4]);
    let mut window = ReplayWindow::new();
    let mut reassembler = Reassembler::new(Limits::default());

    let mut rest = data;
    while let Some((length, tail)) = rest.split_first_chunk::<2>() {
        let take = usize::from(u16::from_be_bytes(*length)).min(tail.len());
        let (datagram, tail) = tail.split_at(take);
        rest = tail;
        // a quarter of a second a datagram, so a long run reaches the
        // retransmission timers too
        now += Duration::from_millis(250);

        for record in record::records(datagram) {
            let Ok(record) = record else {
                break;
            };
            if record.header.epoch == 0 {
                if record.header.content_type != ContentType::HANDSHAKE {
                    continue;
                }
                let Ok(payload) = record.plaintext() else {
                    continue;
                };
                for fragment in handshake::fragments(payload) {
                    let Ok(fragment) = fragment else {
                        break;
                    };
                    if matches!(
                        reassembler.offer(&fragment),
                        Ok(Offered::Accepted | Offered::Replaced)
                    ) {
                        while let Some(message) = reassembler.next_message() {
                            let _ = HandshakeMessage::parse(message.msg_type, &message.body);
                        }
                    }
                }
            } else if window.check(record.header.sequence).is_ok() {
                let mut opened = Vec::new();
                if protection.open(&record, &mut opened).is_ok() {
                    window.accept(record.header.sequence);
                }
            }
        }

        for end in [&mut server, &mut client] {
            end.handle_datagram(datagram, now);
            end.handle_timeout(now);
            while end.poll_transmit().is_some() {}
            while end.poll_event().is_some() {}
        }
    }
});
