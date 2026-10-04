// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The lite agent's own state machine, driven directly rather than through
//! `IceAgent` (which the `ice` target already fuzzes, and which reaches
//! `LiteAgent` only over a simulated network, not with a fuzzer's bytes).
//!
//! A lite agent is a STUN server and nothing past that (RFC 8445 §7.3, §7.3.2):
//! `answer_binding_request` is the whole of what a stranger's bytes can drive,
//! and it runs on every one of them before any credential is proven, the same
//! seam `ice.rs` documents for the full role. What this target adds beyond
//! that one is `LiteAgent::restart`, mid-session, under credentials the
//! target keeps feeding requests against — the old and the new — and the one
//! invariant a lite agent has no full agent's checklist to fall back on for:
//! a controlled agent facing a peer this session believes may be full must
//! never become controlling (`crates/sipral-nat/src/ice/agent.rs`,
//! RFC 8445 §6.1.1, §8.2).

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_nat::ice::{CheckAnswer, ComponentId, LiteAgent, Role};
use sipral_nat::stun::Message;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The one address this agent answers on; a lite agent never checks a
/// request's destination against anything, so a single value exercises
/// exactly as much of `answer_binding_request` as several would.
const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40_000);

/// Where a datagram can claim to come from: the peer's own candidate, a
/// stranger's, and a v6 one, so a peer-reflexive-shaped address is reachable
/// without every seed having to spell one out.
const SOURCES: [SocketAddr; 3] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 3478),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 51_000),
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        40_004,
    ),
];

/// The credentials a restart moves to, fixed rather than drawn from the
/// input: what matters is that a request signed under them differs from one
/// signed under the session's first pair, not which bytes they are.
const RESTARTED_UFRAG: &str = "zK2q";
const RESTARTED_PWD: &str = "N92uWmv93jd6XoQeprLska";

fuzz_target!(|data: &[u8]| {
    // the first byte is the shape, the second how wide a datagram is cut,
    // the rest the network (RFC 8839 §5.4 credentials are fixed, the same
    // way the `ice` target fixes them, since anything else is refused before
    // a single byte of the network is read)
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let Some((&cut, wire)) = rest.split_first() else {
        return;
    };

    let we_are_offerer = shape & 1 != 0;
    let peer_is_lite = shape & 2 != 0;
    let role = Role::initial(we_are_offerer, peer_is_lite);
    let mut agent = LiteAgent::new(
        "8hhY".to_owned(),
        "asd88fgpdd777uzjYhagZg".to_owned(),
        role,
        u64::from(shape),
    );

    // RFC 8445 §6.1.1: against a full peer — the only peer that ever reaches
    // this agent's answering side at all, since §8.2 has two lite agents
    // exchange no connectivity checks — the controlled role is not
    // negotiable, so nothing below may ever move this agent out of it.
    let started_controlled = role == Role::Controlled;

    let width = usize::from(cut).max(1);
    let mut restarted = false;

    for (turn, chunk) in wire.chunks(width).enumerate() {
        // the first byte of each chunk steers which component answers, where
        // the datagram claims to come from, and whether this turn restarts
        // the session; the rest is the datagram itself
        let Some((&marker, datagram)) = chunk.split_first() else {
            continue;
        };

        if marker & 1 != 0 && !restarted {
            agent.restart(RESTARTED_UFRAG.to_owned(), RESTARTED_PWD.to_owned());
            restarted = true;
        }

        let component = if marker & 2 == 0 {
            ComponentId::RTP
        } else {
            ComponentId::RTCP
        };
        let from = SOURCES[usize::from(marker >> 2) % SOURCES.len()];
        let before = agent.valid_pair(component);

        match agent.answer_binding_request(component, LOCAL, from, datagram) {
            Some(CheckAnswer::Signed(bytes) | CheckAnswer::Refused(bytes)) => {
                assert!(
                    Message::parse(&bytes).is_ok(),
                    "an answer that does not parse as STUN, turn {turn}"
                );
            }
            // not a request this agent answers at all -- the wrong class or
            // method, a bad FINGERPRINT, or simply not STUN -- and bytes
            // that get no answer do not get to move a pair either
            None => assert_eq!(
                agent.valid_pair(component),
                before,
                "an unanswered datagram moved the valid pair, turn {turn}"
            ),
        }

        assert!(
            !started_controlled || agent.role() == Role::Controlled,
            "a controlled lite agent switched to controlling, turn {turn}"
        );
    }
});
