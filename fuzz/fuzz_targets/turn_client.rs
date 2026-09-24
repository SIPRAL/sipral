// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A TURN client driven by a relay that answers whatever it likes: every
//! response it writes, every datagram it sends unasked, and the clock.
//!
//! `turn` fuzzes the framing and ChannelData underneath; this fuzzes the state
//! machine above them, where a response is not just parsed but decides what
//! the client believes: that an allocation exists and where, how long it
//! lasts, which peers may reach it, which nonce and which password algorithm
//! to sign with next. The relay is the one party the client has to believe,
//! and a hostile or broken one must still not be able to make it panic, loop,
//! grow without bound or hand back a range that does not index the datagram.
//!
//! The input is a program. The first byte is the configuration; then each
//! instruction is an opcode, a length and that many bytes. An `answer`
//! instruction answers the last request the client sent, with its own method
//! and transaction id, so that the fuzzer spends nothing guessing ninety-six
//! random bits and everything on what a response can say; it can sign the
//! answer with the key the configured credential derives, under either
//! algorithm, which is what reaches the paths behind the integrity check.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_core::auth::DigestAlgorithm;
use sipral_nat::stun::{
    AttributeType, Class, LongTermCredentials, Message, MessageBuilder, TransactionId,
};
use sipral_nat::turn::{
    AddressFamily, EvenPort, FamilyRequest, Input, Transport, TurnClient, TurnConfig,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The credential the client is configured with, and the realm the seeds
/// name, which together are the key an answer is signed under.
const USER: &str = "fuzz";
const PASSWORD: &str = "secret";
const REALM: &str = "fuzz.test";

/// Instructions run before the input is called spent.
const TURNS: usize = 64;

/// The codes an `answer` picks from by its second byte: every one the client
/// treats differently, then any other in the range by arithmetic.
const CODES: [u16; 14] = [
    300, 400, 401, 403, 420, 437, 438, 440, 441, 442, 443, 486, 500, 508,
];

fuzz_target!(|data: &[u8]| {
    let Some((&shape, mut program)) = data.split_first() else {
        return;
    };
    let families = match (shape >> 1) & 3 {
        0 => FamilyRequest::Whatever,
        1 => FamilyRequest::Only(AddressFamily::V4),
        2 => FamilyRequest::Only(AddressFamily::V6),
        _ => FamilyRequest::Dual,
    };
    let even_port = (shape & 8 != 0).then_some(if families == FamilyRequest::Dual {
        EvenPort::Even
    } else {
        EvenPort::EvenAndReserveNext
    });
    let config = TurnConfig {
        transport: if shape & 1 == 0 {
            Transport::Udp
        } else {
            Transport::Tcp
        },
        credentials: (shape & 32 == 0).then(|| LongTermCredentials::new(USER, PASSWORD)),
        families,
        even_port,
        dont_fragment: shape & 16 != 0,
        lifetime: (shape & 64 != 0).then_some(Duration::from_secs(600)),
        ..TurnConfig::default()
    };
    let md5 = key(DigestAlgorithm::Md5);
    let sha256 = key(DigestAlgorithm::Sha256);

    let start = Instant::now();
    let mut now = start;
    let mut ids = 0_u32;
    let mut client = TurnClient::new(config);
    feed(&mut client, &mut ids);
    if client.allocate(now).is_err() {
        return;
    }
    let mut last: Option<Vec<u8>> = None;

    for _ in 0..TURNS {
        while let Some(out) = client.poll_transmit() {
            assert!(
                Message::parse(&out).is_ok(),
                "a control message this client wrote does not parse"
            );
            last = Some(out);
        }
        let Some((&op, rest)) = program.split_first() else {
            break;
        };
        let Some((&len, rest)) = rest.split_first() else {
            break;
        };
        let cut = usize::from(len).min(rest.len());
        let (payload, rest) = rest.split_at(cut);
        program = rest;

        match op % 6 {
            0 => {
                if let Some(request) = last.as_deref()
                    && let Some(response) = answer(request, payload, &md5, &sha256)
                {
                    input(&mut client, &response, now);
                }
            }
            1 => input(&mut client, payload, now),
            2 => {
                let step = payload.get(..2).map_or(1_000, |pair| {
                    u64::from(u16::from_be_bytes([pair[0], pair[1]]))
                });
                now += Duration::from_millis(step.saturating_mul(100).max(1));
                client.handle_timeout(now);
            }
            3 => client.permit(peer(payload).ip(), now),
            4 => {
                let _bound = client.bind_channel(peer(payload), now);
            }
            _ => {
                let mut out = vec![0xee];
                let body = payload.get(3..).unwrap_or_default();
                if client.send_to(peer(payload), body, &mut out).is_ok() {
                    assert!(out.len() > 1 + body.len(), "a wrapping that wrote nothing");
                    assert_eq!(out[0], 0xee, "send_to overwrote what the caller had");
                }
            }
        }

        feed(&mut client, &mut ids);
        let mut events = 0_usize;
        while client.poll_event().is_some() {
            events += 1;
            assert!(events < 10_000, "one instruction raised events without end");
        }
    }
    assert!(now >= start);
});

/// Keep the client's pool full with ids nobody else holds.
fn feed(client: &mut TurnClient, ids: &mut u32) {
    while client.transaction_ids_wanted() > 0 {
        *ids = ids.wrapping_add(1);
        let mut bytes = [0x5a_u8; 12];
        bytes[..4].copy_from_slice(&ids.to_be_bytes());
        client.supply_transaction_id(TransactionId::new(bytes));
    }
}

/// Hand the client a datagram, and hold whatever it hands back to the one
/// promise it makes about it.
fn input(client: &mut TurnClient, bytes: &[u8], now: Instant) {
    if let Input::Data { range, .. } = client.handle_input(bytes, now) {
        assert!(
            range.start <= range.end && range.end <= bytes.len(),
            "a range that does not index what was passed in"
        );
    }
}

/// `MD5` or `SHA-256` of `user:realm:password`, the long-term key
/// (RFC 8489 §9.2.2), from the hex digest the SIP digest code already writes.
fn key(algorithm: DigestAlgorithm) -> Vec<u8> {
    let hex = algorithm.hash(format!("{USER}:{REALM}:{PASSWORD}").as_bytes());
    hex.as_bytes()
        .chunks(2)
        .filter_map(|pair| u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// A peer address out of the first bytes of a payload: IPv4 or IPv6 by the
/// top bit of the first, a port from the next two.
fn peer(payload: &[u8]) -> SocketAddr {
    let first = payload.first().copied().unwrap_or(0);
    let port = payload
        .get(1..3)
        .map_or(40_000, |pair| u16::from_be_bytes([pair[0], pair[1]]));
    let ip = if first & 0x80 == 0 {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, first))
    } else {
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            0,
            0,
            0,
            0,
            u16::from(first),
        ))
    };
    SocketAddr::new(ip, port)
}

/// The relay's answer to `request`, as the payload of an `answer` says.
///
/// The first byte: bit 0 an error rather than a success, bits 1 and 2 how it
/// is signed (none, MESSAGE-INTEGRITY under the MD5 key,
/// MESSAGE-INTEGRITY-SHA256 under the SHA-256 key, MESSAGE-INTEGRITY under
/// the SHA-256 key), bit 3 a FINGERPRINT. The second picks the error code.
/// The rest is attributes, each a two-byte type, a one-byte length and the
/// value; an address type with a six- or eighteen-byte value is an IPv4 or
/// IPv6 address and port, written XORed with this answer's id so that the
/// seeds need not know it.
fn answer(request: &[u8], payload: &[u8], md5: &[u8], sha256: &[u8]) -> Option<Vec<u8>> {
    let message = Message::parse(request).ok()?;
    if message.class() != Class::Request {
        return None;
    }
    let flags = payload.first().copied().unwrap_or(0);
    let error = flags & 1 != 0;
    let class = if error { Class::Error } else { Class::Success };
    let mut builder = MessageBuilder::new(class, message.method(), message.transaction_id());
    if error {
        let pick = payload.get(1).copied().unwrap_or(0);
        let code = if pick < 128 {
            CODES[usize::from(pick) % CODES.len()]
        } else {
            300 + u16::from(pick - 128) * 3
        };
        builder.add_error_code(code, b"fuzz").ok()?;
    }

    let mut rest = payload.get(2..).unwrap_or_default();
    while let [high, low, len, tail @ ..] = rest {
        let kind = AttributeType::new(u16::from_be_bytes([*high, *low]));
        let cut = usize::from(*len).min(tail.len());
        let (value, after) = tail.split_at(cut);
        rest = after;
        let address = matches!(
            kind,
            AttributeType::XOR_RELAYED_ADDRESS
                | AttributeType::XOR_MAPPED_ADDRESS
                | AttributeType::XOR_PEER_ADDRESS
        );
        let _ignored = match (address, value.len()) {
            (true, 6) => builder.add_xor_address(kind, v4(value)),
            (true, 18) => builder.add_xor_address(kind, v6(value)),
            _ => builder.add(kind, value),
        };
    }

    let _ignored = match (flags >> 1) & 3 {
        1 => builder.add_message_integrity(md5),
        2 => builder.add_message_integrity_sha256(sha256),
        3 => builder.add_message_integrity(sha256),
        _ => Ok(()),
    };
    if flags & 8 != 0 {
        let _ignored = builder.add_fingerprint();
    }
    Some(builder.finish())
}

fn v4(value: &[u8]) -> SocketAddr {
    let mut octets = [0_u8; 4];
    octets.copy_from_slice(&value[..4]);
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(octets)),
        u16::from_be_bytes([value[4], value[5]]),
    )
}

fn v6(value: &[u8]) -> SocketAddr {
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&value[..16]);
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(octets)),
        u16::from_be_bytes([value[16], value[17]]),
    )
}
