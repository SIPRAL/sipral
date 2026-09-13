// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Hostile handshake messages, through every reader a DTLS handshake puts them
//! through.
//!
//! The first octet is the message type and the rest the body: what the
//! reassembler hands over once a message is whole. A body that parses is
//! written back and must come out as the same octets, because a handshake
//! hashes what it received and signs over the hash -- a message that changed
//! between being read and being written would put another transcript under
//! the signature. Past the parser, the readers a handshake reaches from each
//! message: the cookie check on a ClientHello, the key and fingerprint of a
//! certificate, the point of a key exchange, the signature of a
//! ServerKeyExchange or CertificateVerify. And the same octets through the
//! alert, ChangeCipherSpec and fragment header parsers, which are the other
//! things a handshake record carries.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use sipral_dtls::Random;
use sipral_dtls::alert::Alert;
use sipral_dtls::handshake::{
    ChangeCipherSpec, CookieSecret, Fragment, HandshakeMessage, HandshakeType,
};
use sipral_dtls::keys::{EcdsaKey, PeerKey};
use sipral_dtls::x509::{Fingerprint, HashFunction, SubjectPublicKeyInfo};

/// The same octet every time.
struct Fixed(u8);

impl Random for Fixed {
    fn fill(&mut self, dest: &mut [u8]) {
        dest.fill(self.0);
    }
}

/// A key to check signatures against, and a cookie secret, made once.
fn fixtures() -> &'static (PeerKey, CookieSecret) {
    static FIXTURES: OnceLock<(PeerKey, CookieSecret)> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let key = EcdsaKey::from_scalar(&[0x5E; 32]).expect("a scalar below the group order");
        (key.peer_key(), CookieSecret::generate(&mut Fixed(7)))
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = Alert::parse(data);
    let _ = ChangeCipherSpec::parse(data);
    let _ = Fragment::parse(data);

    let Some((&msg_type, body)) = data.split_first() else {
        return;
    };
    let msg_type = HandshakeType(msg_type);
    let Ok(message) = HandshakeMessage::parse(msg_type, body) else {
        return;
    };
    let mut written = Vec::new();
    message
        .encode_body(&mut written)
        .expect("a message that was read can be written");
    assert_eq!(
        written, body,
        "{msg_type:?} does not write back what it read"
    );

    let (peer, secret) = fixtures();
    match &message {
        HandshakeMessage::ClientHello(hello) => {
            let _ = secret.verify(&[192, 0, 2, 1, 0x13, 0xC4], hello);
        }
        HandshakeMessage::Certificate(certificate) => {
            if let Some(first) = certificate.certificate_list.first() {
                let _ = Fingerprint::of(HashFunction::Sha1, first).matches(first);
                if let Ok(info) = SubjectPublicKeyInfo::from_certificate(first) {
                    let _ = info.p256_key();
                }
            }
        }
        HandshakeMessage::ServerKeyExchange(exchange) => {
            let _ = PeerKey::from_uncompressed(&exchange.public);
            if let Ok(content) = exchange.signed_content(&[1; 32], &[2; 32]) {
                let _ = peer.verify(&content, &exchange.signed_params.signature);
            }
        }
        HandshakeMessage::ClientKeyExchange(exchange) => {
            let _ = PeerKey::from_uncompressed(&exchange.public);
        }
        HandshakeMessage::CertificateVerify(verify) => {
            let _ = peer.verify_digest(&[0x33; 32], &verify.signed.signature);
        }
        _ => {}
    }
});
