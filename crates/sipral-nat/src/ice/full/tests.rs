// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Tests for the full agent: its steps one at a time against hand-built
//! messages, and whole sessions between agents over the simulated network in
//! [`sim_tests`].

mod network_tests;
mod sim_tests;
mod unit_tests;

use std::net::SocketAddr;

use crate::ice::{
    ComponentId, Credentials, IceAgent, IceConfig, RemoteIce, Role, StreamId, TurnServer,
};
use sim_tests::{STUN_SERVER, TURN_SERVER, address};

/// Credentials in the shape RFC 8839 §5.4 wants, different per name.
fn credentials(name: &str) -> Credentials {
    Credentials::new(
        &format!("{name}frag"),
        &format!("{name}password0123456789abcd"),
    )
    .expect("well-formed credentials")
}

fn config(stun: bool, turn: bool) -> IceConfig {
    IceConfig {
        stun_servers: if stun {
            vec![address(STUN_SERVER)]
        } else {
            Vec::new()
        },
        turn_servers: if turn {
            vec![TurnServer {
                address: address(TURN_SERVER),
                credentials: None,
                transport: crate::turn::Transport::Udp,
            }]
        } else {
            Vec::new()
        },
        ..IceConfig::default()
    }
}

/// An agent with one stream of one component on one host address.
fn agent(
    config: IceConfig,
    name: &str,
    role: Role,
    tiebreaker: u64,
    host: SocketAddr,
) -> (IceAgent, StreamId) {
    let mut agent =
        IceAgent::new(config, credentials(name), role, tiebreaker).expect("a valid configuration");
    let stream = agent
        .add_stream(&[(ComponentId::RTP, host)])
        .expect("a usable host address");
    (agent, stream)
}

/// What the peer would read out of this agent's description.
fn remote_of(agent: &IceAgent, stream: StreamId) -> RemoteIce {
    RemoteIce {
        ufrag: agent.local_credentials().ufrag().to_owned(),
        pwd: agent.local_credentials().pwd().to_owned(),
        lite: false,
        ice2: true,
        candidates: agent.local_candidates(stream),
        pacing: Some(agent.ta()),
        mismatch: false,
    }
}
