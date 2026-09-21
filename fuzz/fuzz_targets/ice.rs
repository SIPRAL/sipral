// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A full-role ICE agent driven the way a hostile network drives one: the
//! peer's candidate lines, then arbitrary datagrams from arbitrary sources on
//! the media port, interleaved with the clock.
//!
//! This is the one seam in the stack that is open to anybody before a key
//! exists. RFC 8445 §5.1.1 has the agent bind a port and answer connectivity
//! checks on it, which means every byte of `handle_datagram` runs on input
//! from an unauthenticated stranger — earlier than SRTP, earlier than the DTLS
//! handshake, earlier than anything that could have established who the peer
//! is. `stun` and `turn` fuzz the message layer underneath; this fuzzes the
//! state machine above it, where a datagram is not just parsed but changes
//! what the agent believes about its peer.
//!
//! The order the agent demands — `new`, `add_stream`, `gather`, `set_remote`
//! — is built here rather than fuzzed, because an agent that never reached
//! `gather` answers `Received::Foreign` to everything and would fuzz nothing.
//! What the input steers is the role, the peer's credentials and candidates,
//! and then every datagram.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_nat::ice::{
    Candidate, ComponentId, Credentials, IceAgent, IceConfig, Received, RemoteIce, Role,
};
use sipral_nat::stun::TransactionId;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The port this agent says it is on. Loopback and the unspecified address
/// are refused by the agent (RFC 8445 §5.1.1.1), so the documentation range
/// of RFC 5737 is what a host candidate can be made of here.
const BASE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40_000);

/// Enough turns of the loop to reach nomination at the default pacing without
/// letting a pathological input run the fuzzer out of its budget.
const TURNS: usize = 64;

/// Where a datagram can claim to come from. A fuzzer that only ever sends
/// from one address never exercises the peer-reflexive path, and one that
/// sends from a fresh address every time never exercises the retransmission
/// path, so the input picks.
const SOURCES: [SocketAddr; 4] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 40_002),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 3478),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 51_000),
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        40_004,
    ),
];

fuzz_target!(|data: &[u8]| {
    // the first three bytes are the shape, the rest is the network
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let Some((&count, rest)) = rest.split_first() else {
        return;
    };
    let Some((&cut, wire)) = rest.split_first() else {
        return;
    };

    let start = Instant::now();
    let mut now = start;

    // credentials of the shape RFC 8839 §5.4 gives them, since anything else
    // is refused before a single byte of the network is read and the whole
    // input would be spent on that one branch
    let Ok(local) = Credentials::new("8hhY", "asd88fgpdd777uzjYhagZg") else {
        return;
    };
    // every flag reads so that a zero byte is the ordinary call: this end
    // offered, the peer is a full agent that speaks RFC 8445, and the stream
    // is not one an ALG has rewritten
    let role = Role::initial_full(shape & 1 == 0, shape & 2 != 0);

    let Ok(mut agent) = IceAgent::new(IceConfig::default(), local, role, u64::from(shape)) else {
        return;
    };
    let Ok(stream) = agent.add_stream(&[(ComponentId::RTP, BASE)]) else {
        return;
    };
    if agent.gather(now).is_err() {
        return;
    }

    // the peer's half of the exchange: its credentials, and as many candidate
    // lines as the input asked for, spelled the way RFC 8839 §5.1 spells them
    let candidates: Vec<Candidate> = (0..usize::from(count) % 8)
        .filter_map(|n| {
            Candidate::parse(&format!(
                "1 1 UDP {} 192.0.2.{} {} typ host",
                2_113_929_216_u32 - n as u32,
                n + 2,
                40_000 + n * 2
            ))
        })
        .collect();
    let remote = RemoteIce {
        ufrag: "9uB6".to_owned(),
        pwd: "YH75Fviy6338Vbrhrlp8Yh".to_owned(),
        lite: shape & 4 != 0,
        ice2: shape & 8 == 0,
        candidates,
        pacing: None,
        mismatch: shape & 16 != 0,
    };
    if agent.set_remote(stream, &remote, now).is_err() {
        return;
    }

    // the network, cut into datagrams at a width the input chooses so that one
    // seed covers both a single large packet and a storm of small ones
    let width = usize::from(cut).max(1);
    let mut datagrams = wire.chunks(width);
    let mut out = Vec::new();

    // where the datagrams claim to come from, chosen by the top two bits so
    // that a seed can aim at the peer's own candidate rather than having the
    // address fall out of whatever its first byte happens to be
    let from = SOURCES[usize::from(shape >> 6) % SOURCES.len()];

    for turn in 0..TURNS {
        // the agent draws no randomness of its own: an empty pool is not an
        // error but a stall, and a fuzzer that let it stall would only ever
        // be testing the stall. The ids are distinct within a turn as well as
        // across turns, because thirty-two identical ones would collapse
        // every outstanding transaction onto the same row.
        let mut nth = 0_u8;
        while agent.transaction_ids_wanted() > 0 {
            let mut id = [0_u8; 12];
            id[0] = shape;
            id[1] = cut;
            id[2] = u8::try_from(turn & 0xff).unwrap_or(0);
            id[3] = nth;
            nth = nth.wrapping_add(1);
            agent.supply_transaction_id(TransactionId::new(id));
        }

        if let Some(datagram) = datagrams.next() {
            let before = agent.selected_pair(stream, ComponentId::RTP);
            match agent.handle_datagram(BASE, from, datagram, now) {
                Received::Data { data, .. } => {
                    assert!(
                        data.len() <= datagram.len(),
                        "unwrapping a datagram made it longer"
                    );
                }
                Received::Consumed => {}
                // a datagram the agent says it did not recognise must not have
                // changed what it believes: `Foreign` is the answer for bytes
                // that are not its, and bytes that are not its do not get to
                // choose where the media goes
                Received::Foreign => assert_eq!(
                    agent.selected_pair(stream, ComponentId::RTP),
                    before,
                    "a datagram the agent called Foreign moved the selected pair"
                ),
            }
        }

        agent.handle_timeout(now);

        // every probe the agent emits has to leave from a socket it was given,
        // or the application cannot send it at all
        while let Some(transmit) = agent.poll_transmit() {
            assert_eq!(transmit.source, BASE, "a probe from a socket nobody bound");
            assert!(!transmit.data.is_empty(), "an empty probe");
        }
        while agent.poll_event().is_some() {}

        // and whatever route it hands back for media has to be one datagram's
        // worth, appended to what the caller already had
        out.clear();
        out.push(0x80);
        if agent
            .send(stream, ComponentId::RTP, &[0_u8; 172], &mut out, now)
            .is_ok()
        {
            assert!(out.len() > 1, "a route that wrote nothing");
            assert_eq!(out[0], 0x80, "send overwrote what the caller had");
        }

        now += agent.deadline().map_or(Duration::from_millis(50), |at| {
            at.saturating_duration_since(now)
                .max(Duration::from_millis(1))
        });
    }

    // the clock only ever went forwards
    assert!(now >= start);
});
