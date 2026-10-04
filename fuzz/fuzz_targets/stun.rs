// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Anything at all, through the STUN message parser and every accessor a
//! binding client or an ICE agent calls on a message it did not send.
//!
//! `Message::parse` reads a datagram that can arrive from any address that
//! reaches the media socket, since STUN and media share a port by design
//! (`demux`). No input reaches a panic, the comprehension check and the two
//! integrity verifiers run on attacker-chosen bytes without one, and a
//! message this parser accepts is walked the way a binding client or the ICE
//! layer would read it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_nat::stun::{AttributeType, Message};

const FAKE_KEY: &[u8] = b"not the real short-term or long-term key";

fuzz_target!(|data: &[u8]| {
    let Ok(message) = Message::parse(data) else {
        return;
    };
    walk(&message);

    // a message parsed whole must also parse as a prefix of itself, and
    // `parse_prefix` must never claim more of the buffer than `parse` did
    let prefixed = Message::parse_prefix(data).expect("parse succeeded, so parse_prefix must");
    assert_eq!(prefixed.as_bytes().len(), message.as_bytes().len());

    // a longer buffer with the same message at the front is still a prefix
    let mut extended = data.to_vec();
    extended.extend_from_slice(b"\0\0\0\0trailing");
    let prefixed = Message::parse_prefix(&extended).expect("a valid prefix with junk after it");
    assert_eq!(prefixed.as_bytes(), message.as_bytes());
});

fn walk(message: &Message<'_>) {
    let _ = message.class();
    let _ = message.method();
    let _ = message.transaction_id();
    let _ = message.check_comprehension();
    let _ = message.xor_mapped_address();
    let _ = message.mapped_address();
    let _ = message.alternate_server();
    let _ = message.username();
    let _ = message.realm();
    let _ = message.nonce();
    let _ = message.software();
    let _ = message.password_algorithms();
    let _ = message.offered_password_algorithms().count();
    let _ = message.error_code();
    let _ = message.unknown_attributes().count();
    let _ = message.priority();
    let _ = message.use_candidate();
    let _ = message.ice_controlled();
    let _ = message.ice_controlling();
    let _ = message.has_integrity();
    let _ = message.verify_integrity(FAKE_KEY);
    let _ = message.verify_integrity_sha256(FAKE_KEY);
    let _ = message.verify_fingerprint();
    for attribute in message.attributes() {
        let _ = attribute;
    }
    for kind in [
        AttributeType::MAPPED_ADDRESS,
        AttributeType::XOR_MAPPED_ADDRESS,
        AttributeType::ERROR_CODE,
    ] {
        let _ = message.find(kind);
        let _ = message.find_all(kind).count();
    }
}
