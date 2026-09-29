// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a DTLS-SRTP handshake exports, put to the use it is exported for:
//! the SRTP suites `sipral-rtp` implements, keyed with it.
//!
//! RFC 5764 §4.2 exports each direction's master key and salt at the widths
//! the negotiated profile's SRTP transform takes; RFC 7714 §14.2 registers
//! `SRTP_AEAD_AES_128_GCM` and `SRTP_AEAD_AES_256_GCM` as the profiles of the
//! `AEAD_AES_128_GCM` and `AEAD_AES_256_GCM` transforms, whose master salt
//! RFC 7714 §12 fixes at twelve octets. These tests hold the exporter to
//! those widths against the suites themselves, and carry one RTP packet each
//! way under keys a full in-process handshake produced.

// a test says what it means; the no-panic discipline is for the library
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::Instant;

use sipral_dtls::exporter::{master_key_len, master_salt_len};
use sipral_dtls::handshake::SrtpProtectionProfile;
use sipral_dtls::keys::EcdsaKey;
use sipral_dtls::x509::{Certificate, CertificateParams};
use sipral_dtls::{Config, Connection, Event, Random, Role, SrtpKeying};
use sipral_rtp::srtp::{Master, Policy, Security, SrtpError, Suite};

/// SplitMix64: reproducible, and useless for anything but a test.
struct Seeded(u64);

impl Random for Seeded {
    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_be_bytes()[..chunk.len()]);
        }
    }
}

const PARAMS: CertificateParams<'static> = CertificateParams {
    common_name: "sipral",
    not_before: 1_785_542_400,
    not_after: 1_785_542_400 + 30 * 86_400,
};

/// The SRTP transform RFC 5764 §4.1.2 and RFC 7714 §14.2 name for each
/// profile this stack keys.
fn suite_of(profile: SrtpProtectionProfile) -> Suite {
    match profile {
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80 => Suite::AesCm80,
        SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32 => Suite::AesCm32,
        SrtpProtectionProfile::AEAD_AES_128_GCM => Suite::AeadAes128Gcm,
        SrtpProtectionProfile::AEAD_AES_256_GCM => Suite::AeadAes256Gcm,
        other => panic!("{other:?} is not a profile this stack keys"),
    }
}

const KEYABLE: [SrtpProtectionProfile; 4] = [
    SrtpProtectionProfile::AEAD_AES_256_GCM,
    SrtpProtectionProfile::AEAD_AES_128_GCM,
    SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
    SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
];

#[test]
fn every_keyable_profile_exports_the_widths_its_srtp_suite_takes() {
    for profile in KEYABLE {
        let suite = suite_of(profile);
        assert_eq!(
            master_key_len(profile),
            Some(suite.key_len()),
            "{profile:?}"
        );
        assert_eq!(
            master_salt_len(profile),
            Some(suite.salt_len()),
            "{profile:?}"
        );
    }
    // and the default offer is exactly those four, GCM first
    let mut random = Seeded(1);
    let key = EcdsaKey::generate(&mut random).unwrap();
    let certificate = Certificate::self_signed(&key, &PARAMS, &mut random).unwrap();
    let fingerprint = certificate.fingerprint();
    let config = Config::new(Role::Client, key, certificate, vec![fingerprint]);
    assert_eq!(config.srtp_profiles, KEYABLE);
}

/// Both ends of a handshake over a lossless path, run to completion, each
/// offering and accepting only `profile`.
fn handshake(profile: SrtpProtectionProfile, client_first: bool) -> [SrtpKeying; 2] {
    let mut random = Seeded(u64::from(profile.0) * 2 + u64::from(client_first));
    let mut identity = || {
        let key = EcdsaKey::generate(&mut random).unwrap();
        let certificate = Certificate::self_signed(&key, &PARAMS, &mut random).unwrap();
        (key, certificate)
    };
    let (client_key, client_certificate) = identity();
    let (server_key, server_certificate) = identity();
    let mut client = Config::new(
        Role::Client,
        client_key,
        client_certificate.clone(),
        vec![server_certificate.fingerprint()],
    );
    let mut server = Config::new(
        Role::Server,
        server_key,
        server_certificate,
        vec![client_certificate.fingerprint()],
    );
    client.srtp_profiles = vec![profile];
    server.srtp_profiles = vec![profile];

    let now = Instant::now();
    let mut ends = [
        Connection::new(client, &mut Seeded(11), now).unwrap(),
        Connection::new(server, &mut Seeded(12), now).unwrap(),
    ];
    if !client_first {
        ends.reverse();
    }
    let mut keys: [Option<SrtpKeying>; 2] = [None, None];
    for _ in 0..64 {
        for from in 0..2 {
            while let Some(datagram) = ends[from].poll_transmit() {
                ends[1 - from].handle_datagram(&datagram, now);
            }
            while let Some(event) = ends[from].poll_event() {
                match event {
                    Event::Connected(keying) => keys[from] = Some(keying),
                    other => panic!("{profile:?}: {other:?}"),
                }
            }
        }
        if keys.iter().all(Option::is_some) {
            let [first, second] = keys;
            return [first.unwrap(), second.unwrap()];
        }
    }
    panic!("{profile:?}: the handshake did not complete");
}

/// This end's SRTP, keyed as RFC 5764 §4.2 says: its own key and salt for
/// what it sends, the peer's for what arrives.
fn security(keying: &SrtpKeying) -> Security {
    let policy = Policy::new(suite_of(keying.profile()));
    Security::new(
        policy,
        Master::new(keying.local_master_key(), keying.local_master_salt()),
        policy,
        Master::new(keying.remote_master_key(), keying.remote_master_salt()),
    )
}

/// An RTP packet of twenty octets of payload, with room after it for the
/// protection `room` adds.
fn rtp(ssrc: u32, sequence: u16, room: usize) -> (Vec<u8>, usize) {
    let mut packet = vec![0x80, 111];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend((0..20).map(|octet: u8| octet.wrapping_mul(7)));
    let len = packet.len();
    packet.resize(len + room, 0);
    (packet, len)
}

/// `from` protects one packet, `to` opens it; returns what went on the wire.
fn carry(from: &mut Security, to: &mut Security, ssrc: u32, suite: Suite) -> Vec<u8> {
    let (mut packet, len) = rtp(ssrc, 4711, from.rtp_overhead());
    let plain = packet[..len].to_vec();
    let protected = from.protect_rtp(&mut packet, len).unwrap();
    assert_eq!(protected, len + suite.tag());
    let wire = packet[..protected].to_vec();
    // the header travels in the clear, as associated data; the payload not
    assert_eq!(wire[..12], plain[..12]);
    assert_ne!(wire[12..len], plain[12..]);

    let mut arrived = wire.clone();
    let opened = to.unprotect_rtp(&mut arrived).unwrap();
    assert_eq!(arrived[..opened], plain[..]);
    wire
}

#[test]
fn a_gcm_packet_crosses_each_way_under_the_keys_a_handshake_exported() {
    for profile in [
        SrtpProtectionProfile::AEAD_AES_128_GCM,
        SrtpProtectionProfile::AEAD_AES_256_GCM,
    ] {
        for client_first in [true, false] {
            let [first, second] = handshake(profile, client_first);
            assert_eq!(first.profile(), profile);
            assert_eq!(second.profile(), profile);
            assert_eq!(first.role().peer(), second.role());
            let suite = suite_of(profile);
            assert!(suite.is_aead());
            assert_eq!(suite.tag(), 16);

            let (mut one, mut other) = (security(&first), security(&second));
            carry(&mut one, &mut other, 0x1111_1111, suite);
            let wire = carry(&mut other, &mut one, 0x2222_2222, suite);

            // an altered payload octet is caught by the GCM tag
            let mut forged = wire.clone();
            forged[14] ^= 1;
            let mut fresh = security(&first);
            assert_eq!(
                fresh.unprotect_rtp(&mut forged),
                Err(SrtpError::NotAuthentic)
            );

            // and one direction's keys do not open the other's packets: the
            // sender keyed with its own half cannot read what it sent
            let mut mirror = security(&second);
            let mut again = wire.clone();
            assert_eq!(
                mirror.unprotect_rtp(&mut again),
                Err(SrtpError::NotAuthentic)
            );
        }
    }
}
