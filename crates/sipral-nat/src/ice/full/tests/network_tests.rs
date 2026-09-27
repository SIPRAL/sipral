// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Whole sessions: two agents, the NATs between them, and what they end up
//! selecting.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use super::sim_tests::{Filtering, Mapping, Network, address};
use super::{agent, config, credentials, remote_of};
use crate::ice::full::checks::build_check;
use crate::ice::{
    CandidateType, ComponentId, HostAddresses, IceConfig, IceEvent, IceState, LiteAgent,
    RelayOutcome, RemoteIce, Role, SelectedPair, SendError, SharedRelay, gather,
};
use crate::stun::{Class, Message, MessageBuilder, Method, TransactionId, error_code};

const A_HOST: &str = "10.0.0.2:5000";
const B_HOST: &str = "10.1.0.2:6000";
const A_PUBLIC_HOST: &str = "198.51.100.10:5000";
const B_PUBLIC_HOST: &str = "198.51.100.20:6000";

fn gathered(net: &Network, index: usize) -> bool {
    net.peer(index)
        .saw(|event| *event == IceEvent::GatheringComplete)
}

fn completed(net: &Network, index: usize) -> bool {
    net.peer(index).saw(|event| *event == IceEvent::Completed)
}

fn exchange(net: &mut Network, a: usize, b: usize) {
    let now = net.now;
    let (a_stream, b_stream) = (net.peer(a).stream, net.peer(b).stream);
    let from_a = remote_of(&net.peer(a).agent, a_stream);
    let from_b = remote_of(&net.peer(b).agent, b_stream);
    net.peer_mut(a)
        .agent
        .set_remote(a_stream, &from_b, now)
        .expect("the peer's parameters");
    net.peer_mut(b)
        .agent
        .set_remote(b_stream, &from_a, now)
        .expect("the peer's parameters");
}

/// Gather on both sides, exchange what was gathered, and run until both
/// complete or `limit` passes.
fn connect(net: &mut Network, a: usize, b: usize, limit: Duration) -> bool {
    gather_both(net, a, b);
    exchange(net, a, b);
    net.run_until(limit, |n| completed(n, a) && completed(n, b))
}

fn gather_both(net: &mut Network, a: usize, b: usize) {
    for index in [a, b] {
        let now = net.now;
        net.peer_mut(index)
            .agent
            .gather(now)
            .expect("gathering starts");
    }
    assert!(
        net.run_until(Duration::from_secs(10), |n| gathered(n, a)
            && gathered(n, b)),
        "gathering finished"
    );
}

fn selected(net: &Network, index: usize) -> SelectedPair {
    let peer = net.peer(index);
    peer.agent
        .selected_pair(peer.stream, ComponentId::RTP)
        .expect("a selected pair")
}

/// Route a media packet through the agent and put it on the wire.
fn talk(net: &mut Network, from: usize, payload: &[u8]) -> Result<(), SendError> {
    let now = net.now;
    let peer = net.peer_mut(from);
    let stream = peer.stream;
    let mut out = Vec::new();
    let route = peer
        .agent
        .send(stream, ComponentId::RTP, payload, &mut out, now)?;
    net.send_from(from, route.source, route.destination, out);
    Ok(())
}

fn assert_media_flows(net: &mut Network, a: usize, b: usize) {
    talk(net, a, b"\x80\x00from a").expect("a route from a");
    talk(net, b, b"\x80\x00from b").expect("a route from b");
    net.run_for(Duration::from_millis(200));
    assert!(
        net.peer(b)
            .received
            .iter()
            .any(|data| data == b"\x80\x00from a"),
        "b heard a"
    );
    assert!(
        net.peer(a)
            .received
            .iter()
            .any(|data| data == b"\x80\x00from b"),
        "a heard b"
    );
}

fn nat_pair(net: &mut Network, mapping: Mapping, filtering: Filtering) -> (usize, usize) {
    (
        net.add_nat("192.0.2.1", mapping, filtering),
        net.add_nat("192.0.2.2", mapping, filtering),
    )
}

#[test]
fn two_agents_on_the_open_internet_select_the_host_pair() {
    let mut net = Network::new(1);
    let (a_agent, a_stream) = agent(
        config(false, false),
        "A",
        Role::Controlling,
        10,
        address(A_PUBLIC_HOST),
    );
    let (b_agent, b_stream) = agent(
        config(false, false),
        "B",
        Role::Controlled,
        20,
        address(B_PUBLIC_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_PUBLIC_HOST)], None);
    let b = net.add_full(b_agent, b_stream, &[address(B_PUBLIC_HOST)], None);

    assert!(connect(&mut net, a, b, Duration::from_secs(10)));
    let (from_a, from_b) = (selected(&net, a), selected(&net, b));
    assert_eq!(from_a.local, address(A_PUBLIC_HOST));
    assert_eq!(from_a.remote, address(B_PUBLIC_HOST));
    assert_eq!(from_a.local_kind, CandidateType::Host);
    assert_eq!(from_a.remote_kind, CandidateType::Host);
    assert_eq!((from_b.local, from_b.remote), (from_a.remote, from_a.local));
    assert_eq!(net.peer(a).agent.state(), IceState::Completed);
    assert_media_flows(&mut net, a, b);
}

#[test]
fn endpoint_independent_mapping_with_address_dependent_filtering_selects_the_reflexive_pair() {
    let mut net = Network::new(2);
    let (nat_a, nat_b) = nat_pair(
        &mut net,
        Mapping::EndpointIndependent,
        Filtering::AddressDependent,
    );
    let (a_agent, a_stream) = agent(
        config(true, false),
        "A",
        Role::Controlling,
        10,
        address(A_HOST),
    );
    let (b_agent, b_stream) = agent(
        config(true, false),
        "B",
        Role::Controlled,
        20,
        address(B_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], Some(nat_a));
    let b = net.add_full(b_agent, b_stream, &[address(B_HOST)], Some(nat_b));

    assert!(connect(&mut net, a, b, Duration::from_secs(20)));
    let (from_a, from_b) = (selected(&net, a), selected(&net, b));
    assert_eq!(
        from_a.local_kind,
        CandidateType::ServerReflexive,
        "{from_a:?}"
    );
    assert_eq!(
        from_a.remote_kind,
        CandidateType::ServerReflexive,
        "{from_a:?}"
    );
    assert_eq!(from_a.local.ip().to_string(), "192.0.2.1");
    assert_eq!(from_a.remote.ip().to_string(), "192.0.2.2");
    assert_eq!((from_b.local, from_b.remote), (from_a.remote, from_a.local));
    assert_media_flows(&mut net, a, b);
}

#[test]
fn a_symmetric_nat_on_both_sides_forces_a_relayed_pair() {
    let mut net = Network::new(3);
    let (nat_a, nat_b) = nat_pair(
        &mut net,
        Mapping::AddressAndPortDependent,
        Filtering::AddressAndPortDependent,
    );
    let (a_agent, a_stream) = agent(
        config(true, true),
        "A",
        Role::Controlling,
        10,
        address(A_HOST),
    );
    let (b_agent, b_stream) = agent(
        config(true, true),
        "B",
        Role::Controlled,
        20,
        address(B_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], Some(nat_a));
    let b = net.add_full(b_agent, b_stream, &[address(B_HOST)], Some(nat_b));

    assert!(connect(&mut net, a, b, Duration::from_secs(60)));
    for index in [a, b] {
        let pair = selected(&net, index);
        assert!(
            pair.local_kind == CandidateType::Relay || pair.remote_kind == CandidateType::Relay,
            "{pair:?}"
        );
    }
    assert_media_flows(&mut net, a, b);
    // the side whose own candidate is relayed binds a channel for the media
    assert!(
        net.turn
            .allocations
            .iter()
            .any(|allocation| !allocation.channels.is_empty())
    );
}

#[test]
fn an_allocation_the_application_made_carries_the_call_and_is_given_back() {
    // the same two symmetric NATs, with agents that name no server at all:
    // the relays are allocated outside them, handed over, and have to do
    // everything one the agent gathered itself would
    let mut net = Network::new(31);
    let (nat_a, nat_b) = nat_pair(
        &mut net,
        Mapping::AddressAndPortDependent,
        Filtering::AddressAndPortDependent,
    );
    let (a_agent, a_stream) = agent(
        config(false, false),
        "A",
        Role::Controlling,
        10,
        address(A_HOST),
    );
    let (b_agent, b_stream) = agent(
        config(false, false),
        "B",
        Role::Controlled,
        20,
        address(B_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], Some(nat_a));
    let b = net.add_full(b_agent, b_stream, &[address(B_HOST)], Some(nat_b));
    for (index, host) in [(a, A_HOST), (b, B_HOST)] {
        let now = net.now;
        net.peer_mut(index)
            .agent
            .gather(now)
            .expect("gathering starts");
        let client = net.allocate_outside(index, address(host));
        let relayed = client.relayed_addresses()[0];
        let peer = net.peer_mut(index);
        let stream = peer.stream;
        peer.agent
            .add_relayed(
                stream,
                ComponentId::RTP,
                address(host),
                net_turn(),
                client,
                now,
            )
            .expect("an allocated client is taken over");
        let candidates = net.peer(index).agent.local_candidates(stream);
        let relay = candidates
            .iter()
            .find(|candidate| candidate.kind == CandidateType::Relay)
            .expect("a relayed candidate");
        assert_eq!(relay.address, relayed);
        // and the server-reflexive one the Allocate response named beside it
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.kind == CandidateType::ServerReflexive)
        );
    }
    exchange(&mut net, a, b);
    assert!(net.run_until(Duration::from_secs(60), |n| completed(n, a)
        && completed(n, b)));
    for index in [a, b] {
        let pair = selected(&net, index);
        assert!(
            pair.local_kind == CandidateType::Relay || pair.remote_kind == CandidateType::Relay,
            "{pair:?}"
        );
    }
    assert_media_flows(&mut net, a, b);
    assert_eq!(net.turn.allocations.len(), 2);

    // the call ends: both allocations go back at once, not ten minutes later
    for index in [a, b] {
        let now = net.now;
        net.peer_mut(index).agent.release_relays(now);
    }
    net.run_for(Duration::from_millis(200));
    assert!(
        net.turn.allocations.is_empty(),
        "a Refresh of lifetime 0 each"
    );
}

#[test]
fn a_client_with_no_allocation_is_not_taken_over() {
    let (mut agent, stream) = agent(
        config(false, false),
        "A",
        Role::Controlling,
        10,
        address(A_HOST),
    );
    let now = std::time::Instant::now();
    agent.gather(now).expect("gathering starts");
    let idle = crate::turn::TurnClient::new(crate::turn::TurnConfig::default());
    assert_eq!(
        agent.add_relayed(
            stream,
            ComponentId::RTP,
            address(A_HOST),
            net_turn(),
            idle,
            now
        ),
        Err(crate::ice::IceError::NotAllocated)
    );
}

#[test]
fn an_agent_that_never_runs_hands_its_relay_back_whole() {
    let mut net = Network::new(32);
    let (a_agent, a_stream) = agent(
        config(false, false),
        "A",
        Role::Controlling,
        10,
        address(A_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], None);
    let client = net.allocate_outside(a, address(A_HOST));
    let relayed = client.relayed_addresses()[0];
    let now = net.now;

    // an offer written around the relay, and refused before it left
    let (mut refused, stream) = agent(
        config(false, false),
        "B",
        Role::Controlling,
        20,
        address(A_HOST),
    );
    refused.gather(now).expect("gathering starts");
    refused
        .add_relayed(
            stream,
            ComponentId::RTP,
            address(A_HOST),
            net_turn(),
            client,
            now,
        )
        .expect("an allocated client is taken over");
    let mut back = refused.into_relays();
    assert_eq!(back.len(), 1);
    let (server, client) = back.remove(0);
    assert_eq!(server, net_turn());
    assert!(client.is_allocated(), "still live on its server");

    // and the next call on the socket offers it again
    let (mut taker, stream) = agent(
        config(false, false),
        "C",
        Role::Controlling,
        30,
        address(A_HOST),
    );
    taker.gather(now).expect("gathering starts");
    taker
        .add_relayed(
            stream,
            ComponentId::RTP,
            address(A_HOST),
            server,
            client,
            now,
        )
        .expect("the handed-back client is taken over again");
    assert!(
        taker
            .local_candidates(stream)
            .iter()
            .any(|candidate| candidate.kind == CandidateType::Relay && candidate.address == relayed)
    );
    // one given back already is not handed out a second time
    taker.release_relays(now);
    assert!(taker.into_relays().is_empty());
}

fn net_turn() -> std::net::SocketAddr {
    address(super::sim_tests::TURN_SERVER)
}

#[test]
fn a_symmetric_nat_facing_address_dependent_filtering_meets_on_a_peer_reflexive_candidate() {
    let mut net = Network::new(4);
    let nat_a = net.add_nat(
        "192.0.2.1",
        Mapping::AddressAndPortDependent,
        Filtering::AddressAndPortDependent,
    );
    let nat_b = net.add_nat(
        "192.0.2.2",
        Mapping::EndpointIndependent,
        Filtering::AddressDependent,
    );
    let (a_agent, a_stream) = agent(
        config(true, false),
        "A",
        Role::Controlling,
        10,
        address(A_HOST),
    );
    let (b_agent, b_stream) = agent(
        config(true, false),
        "B",
        Role::Controlled,
        20,
        address(B_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], Some(nat_a));
    let b = net.add_full(b_agent, b_stream, &[address(B_HOST)], Some(nat_b));

    assert!(connect(&mut net, a, b, Duration::from_secs(60)));
    let (from_a, from_b) = (selected(&net, a), selected(&net, b));
    // the mapping a's NAT made towards b is not the one the STUN server saw,
    // so both ends learn it from the checks themselves
    assert_eq!(
        from_a.local_kind,
        CandidateType::PeerReflexive,
        "{from_a:?}"
    );
    assert_eq!(
        from_b.remote_kind,
        CandidateType::PeerReflexive,
        "{from_b:?}"
    );
    assert_eq!(from_a.local, from_b.remote);
    assert_media_flows(&mut net, a, b);
}

fn role_conflict(start: Role) {
    for (a_tiebreaker, b_tiebreaker) in [(100, 200), (200, 100)] {
        let mut net = Network::new(5);
        let (a_agent, a_stream) = agent(
            config(false, false),
            "A",
            start,
            a_tiebreaker,
            address(A_PUBLIC_HOST),
        );
        let (b_agent, b_stream) = agent(
            config(false, false),
            "B",
            start,
            b_tiebreaker,
            address(B_PUBLIC_HOST),
        );
        let a = net.add_full(a_agent, a_stream, &[address(A_PUBLIC_HOST)], None);
        let b = net.add_full(b_agent, b_stream, &[address(B_PUBLIC_HOST)], None);

        assert!(
            connect(&mut net, a, b, Duration::from_secs(20)),
            "{start:?}"
        );
        let (larger, smaller) = if a_tiebreaker > b_tiebreaker {
            (a, b)
        } else {
            (b, a)
        };
        // RFC 8445 SS7.3.1.1: the larger tiebreaker ends up controlling,
        // whichever role both sides started in
        assert_eq!(
            net.peer(larger).agent.role(),
            Role::Controlling,
            "{start:?}"
        );
        assert_eq!(
            net.peer(smaller).agent.role(),
            Role::Controlled,
            "{start:?}"
        );
        let switched = if start == Role::Controlling {
            smaller
        } else {
            larger
        };
        let stayed = if start == Role::Controlling {
            larger
        } else {
            smaller
        };
        let flipped = if start == Role::Controlling {
            Role::Controlled
        } else {
            Role::Controlling
        };
        assert!(
            net.peer(switched)
                .saw(|event| *event == IceEvent::RoleChanged(flipped))
        );
        assert!(
            !net.peer(stayed)
                .saw(|event| matches!(event, IceEvent::RoleChanged(_)))
        );
        let (from_a, from_b) = (selected(&net, a), selected(&net, b));
        assert_eq!((from_b.local, from_b.remote), (from_a.remote, from_a.local));
        assert_media_flows(&mut net, a, b);
    }
}

#[test]
fn two_agents_that_both_start_controlling_settle_on_the_larger_tiebreaker() {
    role_conflict(Role::Controlling);
}

#[test]
fn two_agents_that_both_start_controlled_settle_on_the_larger_tiebreaker() {
    role_conflict(Role::Controlled);
}

fn open_pair(net: &mut Network) -> (usize, usize) {
    let (a_agent, a_stream) = agent(
        config(false, false),
        "A",
        Role::Controlling,
        10,
        address(A_PUBLIC_HOST),
    );
    let (b_agent, b_stream) = agent(
        config(false, false),
        "B",
        Role::Controlled,
        20,
        address(B_PUBLIC_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_PUBLIC_HOST)], None);
    let b = net.add_full(b_agent, b_stream, &[address(B_PUBLIC_HOST)], None);
    assert!(connect(net, a, b, Duration::from_secs(10)));
    (a, b)
}

#[test]
fn a_restart_selects_again_while_the_old_pair_keeps_carrying_media() {
    let mut net = Network::new(6);
    let (a, b) = open_pair(&mut net);

    net.peer_mut(a)
        .agent
        .restart(credentials("Anew"))
        .expect("new credentials");
    net.peer_mut(b)
        .agent
        .restart(credentials("Bnew"))
        .expect("new credentials");
    assert_eq!(net.peer(a).agent.state(), IceState::Running);

    // before the new exchange: media keeps going over the old pair, and so
    // does consent on it, under the old credentials
    net.run_for(Duration::from_secs(40));
    assert!(
        !net.peer(a)
            .saw(|event| matches!(event, IceEvent::ConsentLost { .. }))
    );
    assert!(
        !net.peer(b)
            .saw(|event| matches!(event, IceEvent::ConsentLost { .. }))
    );
    net.peer_mut(b).received.clear();
    assert_media_flows(&mut net, a, b);

    let (a_seen, b_seen) = (net.peer(a).events.len(), net.peer(b).events.len());
    exchange(&mut net, a, b);
    let done = |n: &Network| {
        n.peer(a).events[a_seen..]
            .iter()
            .any(|(_, event)| *event == IceEvent::Completed)
            && n.peer(b).events[b_seen..]
                .iter()
                .any(|(_, event)| *event == IceEvent::Completed)
    };
    assert!(net.run_until(Duration::from_secs(10), done));
    assert_eq!(net.peer(a).agent.state(), IceState::Completed);
    assert_media_flows(&mut net, a, b);

    // once the new session has selected, the old credentials open nothing
    let old_a = credentials("A");
    let check = build_check(
        TransactionId::new([0x77; 12]),
        &old_a,
        "Bfrag",
        1_845_501_695,
        false,
        false,
        20,
    )
    .expect("a check");
    net.capture = true;
    net.captured.clear();
    net.inject(address(A_PUBLIC_HOST), address(B_PUBLIC_HOST), &check);
    let reply = net
        .captured
        .iter()
        .find(|packet| packet.source == address(A_PUBLIC_HOST))
        .expect("an answer");
    let message = Message::parse(&reply.data).expect("STUN");
    assert_eq!(message.class(), Class::Error);
    assert_eq!(
        message.error_code().map(|error| error.code()),
        Some(error_code::UNAUTHENTICATED)
    );
}

#[test]
fn consent_is_lost_thirty_seconds_after_the_path_goes_silent_and_sending_stops() {
    let mut net = Network::new(7);
    let (a, _b) = open_pair(&mut net);
    let silent_from = net.now;
    net.cut = true;

    let lost = |n: &Network| {
        n.peer(a)
            .saw(|event| matches!(event, IceEvent::ConsentLost { .. }))
    };
    assert!(net.run_until(Duration::from_secs(40), lost));
    let at = net
        .peer(a)
        .when(|event| matches!(event, IceEvent::ConsentLost { .. }))
        .expect("the moment");
    // the last renewal came at most one check interval (six seconds with the
    // jitter) before the silence, and consent lasts thirty seconds from it
    let silence = at - silent_from;
    assert!(
        silence >= Duration::from_secs(24) && silence <= Duration::from_secs(31),
        "{silence:?}"
    );
    assert_eq!(
        talk(&mut net, a, b"\x80\x00late"),
        Err(SendError::NoConsent)
    );
}

#[test]
fn a_keepalive_fills_a_quiet_pair_when_consent_checks_are_paced_slower_than_tr() {
    // RFC 8445 SS11: "agents that are not sending media, or that are using
    // an application protocol that itself provides for keepalives, still
    // need to send a keepalive" - a Binding indication, unauthenticated, at
    // least every Tr (fifteen seconds by default). With consent checks (RFC
    // 7675) on their default five-second period this never has a gap to
    // fill; configuring a slower one opens the gap the keepalive is for.
    let mut net = Network::new(14);
    let slow_consent = IceConfig {
        consent_interval: Duration::from_secs(20),
        ..config(false, false)
    };
    let (a_agent, a_stream) = agent(
        slow_consent.clone(),
        "A",
        Role::Controlling,
        10,
        address(A_PUBLIC_HOST),
    );
    let (b_agent, b_stream) = agent(
        slow_consent,
        "B",
        Role::Controlled,
        20,
        address(B_PUBLIC_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_PUBLIC_HOST)], None);
    let b = net.add_full(b_agent, b_stream, &[address(B_PUBLIC_HOST)], None);
    assert!(connect(&mut net, a, b, Duration::from_secs(10)));

    net.capture = true;
    net.captured.clear();
    let is_indication = |data: &[u8]| {
        Message::parse(data).is_ok_and(|message| message.class() == Class::Indication)
    };
    assert!(
        net.run_until(Duration::from_secs(18), |n| n.captured.iter().any(
            |packet| packet.source == address(A_PUBLIC_HOST) && is_indication(&packet.data)
        )),
        "no keepalive left a"
    );
}

#[test]
fn consent_holds_for_as_long_as_the_peer_answers() {
    let mut net = Network::new(8);
    let (a, b) = open_pair(&mut net);
    net.run_for(Duration::from_secs(120));
    for index in [a, b] {
        assert!(
            !net.peer(index)
                .saw(|event| matches!(event, IceEvent::ConsentLost { .. }))
        );
    }
    assert_media_flows(&mut net, a, b);
}

#[test]
fn an_authenticated_403_revokes_consent_at_once_and_an_unsigned_one_does_not() {
    let mut net = Network::new(9);
    let (a, _b) = open_pair(&mut net);
    net.capture = true;
    net.captured.clear();
    net.cut = true;
    let is_request = |data: &[u8]| {
        Message::parse(data).is_ok_and(|message| {
            message.class() == Class::Request && message.method() == Method::BINDING
        })
    };
    assert!(net.run_until(Duration::from_secs(10), |n| {
        n.captured
            .iter()
            .any(|packet| packet.source == address(A_PUBLIC_HOST) && is_request(&packet.data))
    }));
    let request = net
        .captured
        .iter()
        .find(|packet| packet.source == address(A_PUBLIC_HOST) && is_request(&packet.data))
        .expect("a consent check")
        .data
        .clone();
    let id = Message::parse(&request).expect("STUN").transaction_id();
    let forbidden = |signed: bool| {
        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, id);
        builder
            .add_error_code(403, b"Forbidden")
            .expect("error code");
        if signed {
            builder
                .add_message_integrity(credentials("B").pwd().as_bytes())
                .expect("integrity");
        }
        builder.add_fingerprint().expect("fingerprint");
        builder.finish()
    };

    net.inject(
        address(A_PUBLIC_HOST),
        address(B_PUBLIC_HOST),
        &forbidden(false),
    );
    assert!(
        !net.peer(a)
            .saw(|event| matches!(event, IceEvent::ConsentLost { .. }))
    );

    net.inject(
        address(A_PUBLIC_HOST),
        address(B_PUBLIC_HOST),
        &forbidden(true),
    );
    assert!(
        net.peer(a)
            .saw(|event| matches!(event, IceEvent::ConsentLost { .. }))
    );
    assert_eq!(
        talk(&mut net, a, b"\x80\x00late"),
        Err(SendError::NoConsent)
    );
}

#[test]
fn a_lossy_path_between_the_peers_still_selects_a_pair() {
    for seed in [3, 5, 8, 13] {
        let mut net = Network::new(seed);
        let (nat_a, nat_b) = nat_pair(
            &mut net,
            Mapping::EndpointIndependent,
            Filtering::AddressDependent,
        );
        let (a_agent, a_stream) = agent(
            config(true, false),
            "A",
            Role::Controlling,
            10,
            address(A_HOST),
        );
        let (b_agent, b_stream) = agent(
            config(true, false),
            "B",
            Role::Controlled,
            20,
            address(B_HOST),
        );
        let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], Some(nat_a));
        let b = net.add_full(b_agent, b_stream, &[address(B_HOST)], Some(nat_b));
        gather_both(&mut net, a, b);
        // the loss starts once both sides know where they appear from: a
        // gathering that lost every request it made leaves these two NATs no
        // path at all, which is a fact about the network rather than about
        // the checks under test
        net.set_loss(30);
        exchange(&mut net, a, b);
        assert!(
            net.run_until(Duration::from_secs(60), |n| completed(n, a)
                && completed(n, b)),
            "seed {seed}"
        );
        assert!(net.dropped > 0, "seed {seed}: the path lost nothing");
        let (from_a, from_b) = (selected(&net, a), selected(&net, b));
        assert_eq!(
            (from_b.local, from_b.remote),
            (from_a.remote, from_a.local),
            "seed {seed}"
        );
    }
}

#[test]
fn a_full_agent_takes_control_and_completes_against_a_lite_peer() {
    let mut net = Network::new(10);
    let nat = net.add_nat(
        "192.0.2.1",
        Mapping::EndpointIndependent,
        Filtering::AddressDependent,
    );
    let lite_socket = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 50), 7000);
    let lite = LiteAgent::new(
        "Lfrag".to_owned(),
        "Lpassword0123456789abcd".to_owned(),
        Role::Controlled,
        5,
    );
    let lite_index = net.add_lite(lite, lite_socket.into());
    let (a_agent, a_stream) = agent(
        config(true, false),
        "A",
        Role::initial_full(false, false),
        10,
        address(A_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], Some(nat));

    let now = net.now;
    net.peer_mut(a).agent.gather(now).expect("gathering starts");
    assert!(net.run_until(Duration::from_secs(10), |n| gathered(n, a)));
    let remote = RemoteIce {
        ufrag: "Lfrag".to_owned(),
        pwd: "Lpassword0123456789abcd".to_owned(),
        lite: true,
        ice2: true,
        candidates: gather(&[(
            ComponentId::RTP,
            HostAddresses {
                v4: Some(lite_socket),
                v6: None,
            },
        )]),
        pacing: None,
        mismatch: false,
    };
    let now = net.now;
    net.peer_mut(a)
        .agent
        .set_remote(a_stream, &remote, now)
        .expect("the lite peer's parameters");
    // RFC 8445 SS6.1.1: "The full agent MUST take the controlling role"
    assert_eq!(net.peer(a).agent.role(), Role::Controlling);

    assert!(net.run_until(Duration::from_secs(10), |n| completed(n, a)));
    let pair = selected(&net, a);
    assert_eq!(pair.remote, lite_socket.into());
    let accepted = net
        .lite(lite_index)
        .agent
        .valid_pair(ComponentId::RTP)
        .expect("the lite agent accepted the nomination");
    assert_eq!(accepted.remote, pair.local);
    assert_eq!(accepted.local, pair.remote);
}

#[test]
fn relays_nobody_selected_are_given_back_three_seconds_after_completion() {
    let mut net = Network::new(11);
    let (nat_a, nat_b) = nat_pair(
        &mut net,
        Mapping::EndpointIndependent,
        Filtering::AddressDependent,
    );
    let (a_agent, a_stream) = agent(
        config(true, true),
        "A",
        Role::Controlling,
        10,
        address(A_HOST),
    );
    let (b_agent, b_stream) = agent(
        config(true, true),
        "B",
        Role::Controlled,
        20,
        address(B_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], Some(nat_a));
    let b = net.add_full(b_agent, b_stream, &[address(B_HOST)], Some(nat_b));
    assert!(connect(&mut net, a, b, Duration::from_secs(20)));
    assert_ne!(selected(&net, a).local_kind, CandidateType::Relay);
    assert_ne!(selected(&net, a).remote_kind, CandidateType::Relay);
    assert_eq!(net.turn.allocations.len(), 2);

    net.run_for(Duration::from_millis(2_500));
    assert_eq!(
        net.turn.allocations.len(),
        2,
        "not yet: RFC 8445 SS8.3.1 waits three seconds"
    );
    net.run_for(Duration::from_secs(1));
    assert!(net.turn.allocations.is_empty());
    // and a description written now no longer offers them
    let peer = net.peer(a);
    assert!(
        peer.agent
            .local_candidates(peer.stream)
            .iter()
            .all(|candidate| candidate.kind != CandidateType::Relay)
    );
}

#[test]
fn the_peer_arriving_before_gathering_ends_still_reaches_the_relay() {
    let mut net = Network::new(12);
    let (nat_a, nat_b) = nat_pair(
        &mut net,
        Mapping::AddressAndPortDependent,
        Filtering::AddressAndPortDependent,
    );
    // only a has a relay, so a's relayed candidate is the one path there is
    let (a_agent, a_stream) = agent(
        config(true, true),
        "A",
        Role::Controlling,
        10,
        address(A_HOST),
    );
    let (b_agent, b_stream) = agent(
        config(true, false),
        "B",
        Role::Controlled,
        20,
        address(B_HOST),
    );
    let a = net.add_full(a_agent, a_stream, &[address(A_HOST)], Some(nat_a));
    let b = net.add_full(b_agent, b_stream, &[address(B_HOST)], Some(nat_b));

    let now = net.now;
    net.peer_mut(b).agent.gather(now).expect("gathering starts");
    assert!(net.run_until(Duration::from_secs(10), |n| gathered(n, b)));

    // a hears from b while its own relay is still being allocated
    let now = net.now;
    let from_b = remote_of(&net.peer(b).agent, b_stream);
    net.peer_mut(a).agent.gather(now).expect("gathering starts");
    net.peer_mut(a)
        .agent
        .set_remote(a_stream, &from_b, now)
        .expect("the peer's parameters");
    assert!(net.run_until(Duration::from_secs(10), |n| gathered(n, a)));
    let from_a = remote_of(&net.peer(a).agent, a_stream);
    let now = net.now;
    net.peer_mut(b)
        .agent
        .set_remote(b_stream, &from_a, now)
        .expect("the peer's parameters");

    assert!(net.run_until(Duration::from_secs(60), |n| completed(n, a)
        && completed(n, b)));
    assert_eq!(selected(&net, a).local_kind, CandidateType::Relay);
    assert_media_flows(&mut net, a, b);
}

const C_HOST: &str = "10.2.0.2:7000";

/// A forked call on the caller's side: one socket behind a symmetric NAT,
/// one allocation made from it, and an agent per branch — the same
/// credentials, the same candidates, the relay shared — facing two phones,
/// each behind a symmetric NAT of its own with only a server-reflexive
/// candidate to offer. The relay is the one path to either phone.
fn forked_over_one_relay(net: &mut Network) -> ([usize; 2], [usize; 2], SharedRelay) {
    let nat_a = net.add_nat(
        "192.0.2.1",
        Mapping::AddressAndPortDependent,
        Filtering::AddressAndPortDependent,
    );
    let mut branches = [0; 2];
    for slot in &mut branches {
        let (branch, stream) = agent(
            config(false, false),
            "A",
            Role::Controlling,
            10,
            address(A_HOST),
        );
        *slot = net.add_full(branch, stream, &[address(A_HOST)], Some(nat_a));
    }
    let mut phones = [0; 2];
    for (slot, (name, host, public)) in phones
        .iter_mut()
        .zip([("B", B_HOST, "192.0.2.2"), ("C", C_HOST, "192.0.2.3")])
    {
        let nat = net.add_nat(
            public,
            Mapping::AddressAndPortDependent,
            Filtering::AddressAndPortDependent,
        );
        let (phone, stream) = agent(
            config(true, false),
            name,
            Role::Controlled,
            20,
            address(host),
        );
        *slot = net.add_full(phone, stream, &[address(host)], Some(nat));
    }
    for index in branches.into_iter().chain(phones) {
        let now = net.now;
        net.peer_mut(index)
            .agent
            .gather(now)
            .expect("gathering starts");
    }
    let client = net.allocate_outside(branches[0], address(A_HOST));
    let relay = SharedRelay::new(net_turn(), client);
    for branch in branches {
        let now = net.now;
        let peer = net.peer_mut(branch);
        let stream = peer.stream;
        peer.agent
            .add_shared_relay(stream, ComponentId::RTP, address(A_HOST), &relay, now)
            .expect("a live allocation is taken up");
    }
    assert!(net.run_until(Duration::from_secs(10), |n| {
        phones.iter().all(|phone| gathered(n, *phone))
    }));
    (branches, phones, relay)
}

/// Every peer address a CreatePermission to the TURN server named over the
/// next `span` of simulated time.
fn permissions_asked_over(net: &mut Network, span: Duration) -> Vec<std::net::IpAddr> {
    net.capture = true;
    net.captured.clear();
    net.run_for(span);
    net.capture = false;
    net.captured
        .iter()
        .filter(|packet| packet.destination == net_turn())
        .filter_map(|packet| Message::parse(&packet.data).ok())
        .filter(|message| message.method() == crate::turn::method::CREATE_PERMISSION)
        .flat_map(|message| {
            message
                .find_all(crate::stun::AttributeType::XOR_PEER_ADDRESS)
                .filter_map(|value| {
                    crate::stun::address::decode_xor(value, message.transaction_id())
                })
                .map(|peer| peer.ip())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn two_branches_of_a_fork_each_run_their_own_checks_over_one_relay() {
    let mut net = Network::new(41);
    let (branches, phones, relay) = forked_over_one_relay(&mut net);
    let [first, second] = branches;
    // one offer went to both phones: both agents advertise what it named
    let offered = |index: usize| {
        let peer = net.peer(index);
        peer.agent.local_candidates(peer.stream)
    };
    assert_eq!(offered(first), offered(second));
    assert!(
        offered(first)
            .iter()
            .any(|candidate| candidate.kind == CandidateType::Relay)
    );
    assert_eq!(relay.holders(), 2);

    // each phone answers its own branch (RFC 8839 §7)
    for (branch, phone) in branches.into_iter().zip(phones) {
        exchange(&mut net, branch, phone);
    }
    assert!(net.run_until(Duration::from_secs(60), |n| {
        branches
            .iter()
            .chain(&phones)
            .all(|index| completed(n, *index))
    }));
    let [b, c] = phones;
    for (branch, phone) in [(first, b), (second, c)] {
        let pair = selected(&net, branch);
        assert_eq!(pair.local_kind, CandidateType::Relay, "{pair:?}");
        // the pair each branch found leads to its own phone
        assert_eq!(pair.remote.ip(), selected(&net, phone).local.ip());
    }
    // one allocation carries both, with each phone's address let through
    assert_eq!(net.turn.allocations.len(), 1);
    let allocation = &net.turn.allocations[0];
    for public in ["192.0.2.2", "192.0.2.3"] {
        let public: std::net::IpAddr = public.parse().unwrap();
        assert!(allocation.permissions.contains(&public), "{public}");
    }

    // media on both, each to its own branch and never to the other's
    for (index, payload) in [
        (first, &b"\x80\x00to b"[..]),
        (second, b"\x80\x00to c"),
        (b, b"\x80\x00from b"),
        (c, b"\x80\x00from c"),
    ] {
        talk(&mut net, index, payload).expect("a route");
    }
    net.run_for(Duration::from_millis(200));
    let heard = |index: usize, what: &[u8]| {
        net.peer(index)
            .received
            .iter()
            .any(|data| data.as_slice() == what)
    };
    assert!(heard(b, b"\x80\x00to b") && !heard(b, b"\x80\x00to c"));
    assert!(heard(c, b"\x80\x00to c") && !heard(c, b"\x80\x00to b"));
    assert!(heard(first, b"\x80\x00from b") && !heard(first, b"\x80\x00from c"));
    assert!(heard(second, b"\x80\x00from c") && !heard(second, b"\x80\x00from b"));

    // the second branch loses: it lets go of the relay, and the first one's
    // call goes on through it
    let now = net.now;
    net.peer_mut(second).agent.release_relays(now);
    net.run_for(Duration::from_millis(200));
    assert_eq!(relay.holders(), 1);
    let fate = |index: usize| {
        net.peer(index)
            .agent
            .relay_report()
            .iter()
            .map(|relay| relay.outcome)
            .collect::<Vec<_>>()
    };
    assert_eq!(fate(second), vec![RelayOutcome::Released]);
    assert_eq!(fate(first), vec![RelayOutcome::Selected]);
    assert_eq!(
        net.turn.allocations.len(),
        1,
        "given back while a branch still used it"
    );
    net.peer_mut(b).received.clear();
    net.peer_mut(first).received.clear();
    assert_media_flows(&mut net, first, b);
    // and the phone that lost is left to lapse at the server (RFC 8656
    // §2.3 has no way to take a permission back): the renewals name only
    // the phone still in the call
    let renewed = permissions_asked_over(&mut net, Duration::from_secs(301));
    let lost: std::net::IpAddr = "192.0.2.3".parse().unwrap();
    let kept: std::net::IpAddr = "192.0.2.2".parse().unwrap();
    assert!(renewed.contains(&kept), "{renewed:?}");
    assert!(!renewed.contains(&lost), "{renewed:?}");
    assert_media_flows(&mut net, first, b);

    // the call ends: the last holder gives it back
    let now = net.now;
    net.peer_mut(first).agent.release_relays(now);
    net.run_for(Duration::from_millis(200));
    assert!(net.turn.allocations.is_empty(), "a Refresh of lifetime 0");
    assert_eq!(relay.holders(), 0);
}
