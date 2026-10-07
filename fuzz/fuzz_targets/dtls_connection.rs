// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Two real DTLS ends, a client and a server, with the fuzzer sitting on the
//! path between them.
//!
//! `dtls_record` plays the peer itself, so it only reaches what a handshake
//! does with octets it could have written. This target keeps both ends
//! honest and gives the fuzzer the path instead: it delivers, drops,
//! duplicates, reorders, truncates and flips bits in what each end sends,
//! slips datagrams of its own in beside them, lets time pass, and closes or
//! sends application data from either end -- so every state of both state
//! machines is reached with a real peer on the far side, in every order the
//! path can produce.
//!
//! The first octet configures the pair: the server's cookie exchange, small
//! datagrams that fragment every flight, which SRTP profiles each end accepts
//! and whether the client expects the server's certificate or another's. The
//! rest is a program, one operation an octet and its operands after it.
//!
//! Past not panicking, what has to hold whatever the path did:
//!
//! - an end reports `Connected` at most once, and nothing at all after it
//!   failed or closed;
//! - application data only ever arrives at an end that is connected;
//! - two ends that both connected exported the same SRTP keys, each the
//!   other's mirror, under one profile both of them accept;
//! - a client that expected another certificate never connects.
//!
//! Both ends are built from the fixed keys and random source `dtls_record`
//! uses, and `tools/fuzz-seeds` writes programs that take them through a
//! whole handshake.

#![no_main]

use std::collections::VecDeque;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use sipral_dtls::handshake::SrtpProtectionProfile;
use sipral_dtls::keys::EcdsaKey;
use sipral_dtls::x509::{Certificate, CertificateParams};
use sipral_dtls::{Config, Connection, Event, Random, Role, SrtpKeying, State};

const SERVER_SEED: u64 = 0x5E;
const CLIENT_SEED: u64 = 0xC1;
const STRANGER_SEED: u64 = 0x77;

/// Datagrams held on the path in one direction, at most: a program that
/// duplicates without delivering cannot grow it without end.
const QUEUE: usize = 64;

/// The datagram size that fragments every flight past the first.
const SMALL_DATAGRAM: usize = 300;

/// A linear congruential sequence, octet for octet the one `dtls_record`
/// builds its ends from.
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

/// The server's identity, the client's, and a third certificate neither
/// end holds, made once.
fn identities() -> &'static [(EcdsaKey, Certificate); 3] {
    static IDENTITIES: OnceLock<[(EcdsaKey, Certificate); 3]> = OnceLock::new();
    IDENTITIES.get_or_init(|| {
        [
            identity(0x5E, SERVER_SEED),
            identity(0xC1, CLIENT_SEED),
            identity(0x77, STRANGER_SEED),
        ]
    })
}

fn start() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

/// The profiles one end accepts, out of two bits of the configuration octet.
fn profiles(choice: u8) -> Vec<SrtpProtectionProfile> {
    match choice & 3 {
        0 => vec![
            SrtpProtectionProfile::AEAD_AES_256_GCM,
            SrtpProtectionProfile::AEAD_AES_128_GCM,
            SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
            SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
        ],
        1 => vec![SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80],
        2 => vec![SrtpProtectionProfile::AEAD_AES_128_GCM],
        _ => vec![
            SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
            SrtpProtectionProfile::AEAD_AES_256_GCM,
        ],
    }
}

/// One end, what it reported, and what it has sent that the path holds.
struct End {
    connection: Connection,
    profiles: Vec<SrtpProtectionProfile>,
    keys: Option<SrtpKeying>,
    finished: bool,
    sent: VecDeque<Vec<u8>>,
}

impl End {
    fn new(config: Config, seed: u64, now: Instant) -> Self {
        let profiles = config.srtp_profiles.clone();
        Self {
            connection: Connection::new(config, &mut Fixed(seed), now)
                .expect("the configuration is valid"),
            profiles,
            keys: None,
            finished: false,
            sent: VecDeque::new(),
        }
    }

    /// Take what the end wrote onto the path and check what it reported.
    fn collect(&mut self) {
        while let Some(datagram) = self.connection.poll_transmit() {
            if self.sent.len() < QUEUE {
                self.sent.push_back(datagram);
            }
        }
        while let Some(event) = self.connection.poll_event() {
            assert!(!self.finished, "an event after the end failed or closed: {event:?}");
            match event {
                Event::Connected(keys) => {
                    assert!(self.keys.is_none(), "connected twice");
                    assert!(
                        self.profiles.contains(&keys.profile()),
                        "keyed under a profile this end does not accept"
                    );
                    self.keys = Some(keys);
                }
                Event::ApplicationData(_) => {
                    assert!(self.keys.is_some(), "application data before the handshake");
                }
                Event::Failed(_) | Event::Closed => self.finished = true,
            }
        }
        if self.finished {
            assert!(
                matches!(self.connection.state(), State::Failed | State::Closed),
                "the end reported its end but is {:?}",
                self.connection.state()
            );
        }
    }
}

/// The operands of a program, read off its front.
struct Program<'a>(&'a [u8]);

impl Program<'_> {
    fn octet(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn take(&mut self, n: usize) -> &[u8] {
        let (taken, rest) = self.0.split_at(n.min(self.0.len()));
        self.0 = rest;
        taken
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&setup, program)) = data.split_first() else {
        return;
    };
    let [server_identity, client_identity, stranger] = identities();
    let mut now = start();

    let mut server_config = Config::new(
        Role::Server,
        server_identity.0.clone(),
        server_identity.1.clone(),
        vec![client_identity.1.fingerprint()],
    );
    server_config.cookie_exchange = setup & 1 != 0;
    server_config.srtp_profiles = profiles(setup >> 2);

    let expected = if setup & 0x40 != 0 { stranger } else { server_identity };
    let mut client_config = Config::new(
        Role::Client,
        client_identity.0.clone(),
        client_identity.1.clone(),
        vec![expected.1.fingerprint()],
    );
    client_config.srtp_profiles = profiles(setup >> 4);

    if setup & 2 != 0 {
        server_config.max_datagram = SMALL_DATAGRAM;
        client_config.max_datagram = SMALL_DATAGRAM;
    }

    let mut ends = [
        End::new(client_config, CLIENT_SEED, now),
        End::new(server_config, SERVER_SEED, now),
    ];
    ends[0].collect();

    let mut program = Program(program);
    while let Some(op) = program.octet() {
        // the end the operation is about: for the path, the one whose
        // datagrams are moved; the other end is where they arrive
        let from = usize::from(op & 1);
        let to = 1 - from;
        match (op >> 1) & 7 {
            // deliver the oldest datagram
            0 => {
                if let Some(datagram) = ends[from].sent.pop_front() {
                    ends[to].connection.handle_datagram(&datagram, now);
                }
            }
            // lose it
            1 => {
                ends[from].sent.pop_front();
            }
            // deliver it and keep it, to be delivered again
            2 => {
                if let Some(datagram) = ends[from].sent.front().cloned() {
                    ends[to].connection.handle_datagram(&datagram, now);
                }
            }
            // reorder: the second oldest goes to the front
            3 => {
                if ends[from].sent.len() > 1 {
                    ends[from].sent.swap(0, 1);
                }
            }
            // flip the bits of one octet, then deliver it
            4 => {
                let at = usize::from(program.octet().unwrap_or(0));
                let mask = program.octet().unwrap_or(1);
                if let Some(mut datagram) = ends[from].sent.pop_front() {
                    if !datagram.is_empty() {
                        let at = at % datagram.len();
                        datagram[at] ^= mask;
                    }
                    ends[to].connection.handle_datagram(&datagram, now);
                }
            }
            // a datagram of the fuzzer's own
            5 => {
                let len = usize::from(program.octet().unwrap_or(0));
                let datagram = program.take(len).to_vec();
                ends[to].connection.handle_datagram(&datagram, now);
            }
            // time passes, a tenth of a second a step
            6 => {
                let steps = program.octet().unwrap_or(0);
                now += Duration::from_millis(100) * u32::from(steps);
                for end in &mut ends {
                    end.connection.handle_timeout(now);
                }
            }
            // the end itself acts
            _ => match program.octet().unwrap_or(0) % 4 {
                0 => ends[from].connection.close(),
                1 => {
                    let len = usize::from(program.octet().unwrap_or(0));
                    let payload = program.take(len).to_vec();
                    let sent = ends[from].connection.send_application_data(&payload);
                    assert_eq!(
                        sent.is_ok(),
                        ends[from].connection.state() == State::Connected,
                        "application data accepted or refused against the state"
                    );
                }
                2 => {
                    let len = usize::from(program.octet().unwrap_or(0));
                    if let Some(datagram) = ends[from].sent.front_mut() {
                        datagram.truncate(len);
                    }
                }
                _ => {
                    // a datagram delivered to the end that sent it
                    if let Some(datagram) = ends[from].sent.pop_front() {
                        ends[from].connection.handle_datagram(&datagram, now);
                    }
                }
            },
        }
        for end in &mut ends {
            end.collect();
        }
    }

    if setup & 0x40 != 0 {
        assert!(
            ends[0].keys.is_none(),
            "the client connected to a certificate it did not expect"
        );
    }
    if let [
        End {
            keys: Some(client), ..
        },
        End {
            keys: Some(server), ..
        },
    ] = &ends
    {
        assert_eq!(client.role(), Role::Client);
        assert_eq!(server.role(), Role::Server);
        assert_eq!(client.profile(), server.profile());
        assert_eq!(client.local_master_key(), server.remote_master_key());
        assert_eq!(client.local_master_salt(), server.remote_master_salt());
        assert_eq!(client.remote_master_key(), server.local_master_key());
        assert_eq!(client.remote_master_salt(), server.local_master_salt());
        assert_ne!(client.local_master_key(), client.remote_master_key());
    }
});
