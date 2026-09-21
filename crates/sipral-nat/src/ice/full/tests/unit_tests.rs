// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One agent at a time, against messages written by hand.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::sim_tests::{STUN_SERVER, TURN_SERVER, address};
use super::{agent, config, credentials};
use crate::ice::{
    Candidate, CandidateType, ComponentId, Credentials, Foundation, IceAgent, IceConfig, IceError,
    IceEvent, IceState, PairState, Received, RemoteIce, Role, StreamId, Transmit, pair_priority,
};
use crate::stun::{
    AttributeType, Class, Integrity, Message, MessageBuilder, Method, TransactionId, error_code,
};

const LOCAL: &str = "198.51.100.10:5000";
const PEER: &str = "198.51.100.20:6000";
const PEER_PRIORITY: u32 = 1_845_501_695;

struct Ids(u32);

impl Ids {
    fn feed(&mut self, agent: &mut IceAgent) {
        while agent.transaction_ids_wanted() > 0 {
            self.0 += 1;
            let mut bytes = [0xaa_u8; 12];
            bytes[..4].copy_from_slice(&self.0.to_be_bytes());
            agent.supply_transaction_id(TransactionId::new(bytes));
        }
    }
}

fn drain(agent: &mut IceAgent) -> Vec<Transmit> {
    let mut all = Vec::new();
    while let Some(transmit) = agent.poll_transmit() {
        all.push(transmit);
    }
    all
}

fn events(agent: &mut IceAgent) -> Vec<IceEvent> {
    let mut all = Vec::new();
    while let Some(event) = agent.poll_event() {
        all.push(event);
    }
    all
}

fn host(at: &str, priority: u32, foundation: &str) -> Candidate {
    Candidate {
        foundation: Foundation::parse(foundation).expect("a foundation"),
        component: ComponentId::RTP,
        priority,
        address: address(at),
        kind: CandidateType::Host,
        related: None,
    }
}

fn from_peer(candidates: Vec<Candidate>) -> RemoteIce {
    RemoteIce {
        ufrag: "Bfrag".to_owned(),
        pwd: credentials("B").pwd().to_owned(),
        lite: false,
        ice2: true,
        candidates,
        pacing: None,
        mismatch: false,
    }
}

/// A host-only agent that has finished gathering.
fn gathered(role: Role, config: IceConfig) -> (IceAgent, StreamId, Ids, Instant) {
    let now = Instant::now();
    let (mut agent, stream) = agent(config, "A", role, 10, address(LOCAL));
    let mut ids = Ids(0);
    ids.feed(&mut agent);
    agent.gather(now).expect("gathering starts");
    (agent, stream, ids, now)
}

/// A check from the peer, signed with this agent's password.
fn check_from_peer(id: u8, priority: Option<u32>, use_candidate: bool) -> Vec<u8> {
    let mut builder = MessageBuilder::new(
        Class::Request,
        Method::BINDING,
        TransactionId::new([id; 12]),
    );
    builder
        .add(AttributeType::USERNAME, b"Afrag:Bfrag")
        .expect("username");
    if let Some(priority) = priority {
        builder
            .add_u32(AttributeType::PRIORITY, priority)
            .expect("priority");
    }
    if use_candidate {
        builder
            .add_flag(AttributeType::USE_CANDIDATE)
            .expect("use-candidate");
    }
    builder
        .add_u64(AttributeType::ICE_CONTROLLED, 20)
        .expect("role");
    builder
        .add_message_integrity(credentials("A").pwd().as_bytes())
        .expect("integrity");
    builder.add_fingerprint().expect("fingerprint");
    builder.finish()
}

/// A response from the peer to one of this agent's checks, signed with the
/// peer's password.
fn response(id: TransactionId, class: Class, fill: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
    let mut builder = MessageBuilder::new(class, Method::BINDING, id);
    fill(&mut builder);
    builder
        .add_message_integrity(credentials("B").pwd().as_bytes())
        .expect("integrity");
    builder.add_fingerprint().expect("fingerprint");
    builder.finish()
}

fn requests(sent: &[Transmit]) -> Vec<(SocketAddr, TransactionId)> {
    sent.iter()
        .filter_map(|transmit| {
            let message = Message::parse(&transmit.data).ok()?;
            (message.class() == Class::Request)
                .then(|| (transmit.destination, message.transaction_id()))
        })
        .collect()
}

#[test]
fn credentials_outside_the_shape_rfc_8839_gives_them_are_refused() {
    assert!(Credentials::new("abcd", "0123456789abcdefghij+/").is_ok());
    for (ufrag, pwd) in [
        ("abc", "0123456789abcdefghij+/"),
        (&"u".repeat(33), "0123456789abcdefghij+/"),
        ("abcd", "0123456789abcdefghij+"),
        ("ab-d", "0123456789abcdefghij+/"),
        ("abcd", "0123456789 bcdefghij+/"),
    ] {
        assert_eq!(
            Credentials::new(ufrag, pwd),
            Err(IceError::InvalidCredentials),
            "{ufrag} {pwd}"
        );
    }
}

#[test]
fn a_restart_has_to_change_both_the_fragment_and_the_password() {
    let (mut agent, ..) = gathered(Role::Controlling, config(false, false));
    let same_ufrag = Credentials::new("Afrag", "anotherpassword0123456789").expect("shape");
    let same_pwd = Credentials::new("Anew", credentials("A").pwd()).expect("shape");
    assert_eq!(
        agent.restart(credentials("A")),
        Err(IceError::SameCredentials)
    );
    assert_eq!(agent.restart(same_ufrag), Err(IceError::SameCredentials));
    assert_eq!(agent.restart(same_pwd), Err(IceError::SameCredentials));
    assert_eq!(agent.restart(credentials("Anew")), Ok(()));
    assert_eq!(agent.local_credentials().ufrag(), "Anewfrag");
}

#[test]
fn the_peer_changing_its_credentials_without_a_restart_is_refused() {
    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, config(false, false));
    let first = from_peer(vec![host(PEER, PEER_PRIORITY, "1")]);
    assert_eq!(agent.set_remote(stream, &first, now), Ok(()));
    assert_eq!(agent.set_remote(stream, &first, now), Ok(()));
    let mut changed = first;
    changed.ufrag = "Cfrag".to_owned();
    assert_eq!(
        agent.set_remote(stream, &changed, now),
        Err(IceError::RestartRequired)
    );
}

#[test]
fn loopback_unspecified_and_deprecated_addresses_are_not_host_candidates() {
    let mut agent =
        IceAgent::new(IceConfig::default(), credentials("A"), Role::Controlling, 1).expect("agent");
    for bad in [
        "127.0.0.1:5000",
        "0.0.0.0:5000",
        "[::1]:5000",
        "[fec0::1]:5000",
        "[::ffff:192.0.2.1]:5000",
        "[::c000:201]:5000",
        "198.51.100.10:0",
    ] {
        assert_eq!(
            agent.add_stream(&[(ComponentId::RTP, address(bad))]),
            Err(IceError::NoUsableHost),
            "{bad}"
        );
    }
    let stream = agent
        .add_stream(&[
            (ComponentId::RTP, address("127.0.0.1:5000")),
            (ComponentId::RTP, address(LOCAL)),
        ])
        .expect("one usable address");
    agent.gather(Instant::now()).expect("gathering starts");
    let addresses: Vec<SocketAddr> = agent
        .local_candidates(stream)
        .iter()
        .map(|candidate| candidate.address)
        .collect();
    assert_eq!(addresses, vec![address(LOCAL)]);
}

#[test]
fn a_check_before_the_answer_is_answered_at_once_and_checked_back_once_the_answer_arrives() {
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, config(false, false));
    let request = check_from_peer(1, Some(PEER_PRIORITY), false);
    assert_eq!(
        agent.handle_datagram(address(LOCAL), address(PEER), &request, now),
        Received::Consumed
    );
    let replies = drain(&mut agent);
    assert_eq!(replies.len(), 1);
    let reply = Message::parse(&replies[0].data).expect("STUN");
    assert_eq!(reply.class(), Class::Success);
    assert_eq!(reply.xor_mapped_address(), Some(address(PEER)));
    assert_eq!(replies[0].destination, address(PEER));

    // no password to check back with yet
    agent.handle_timeout(now);
    assert!(drain(&mut agent).is_empty());

    // an answer with no candidates at all: the peer is known only from its
    // check (RFC 8445 SS7.3.1.3)
    agent
        .set_remote(stream, &from_peer(Vec::new()), now)
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let sent = drain(&mut agent);
    assert_eq!(requests(&sent).len(), 1);
    let check = Message::parse(&sent[0].data).expect("STUN");
    assert_eq!(sent[0].destination, address(PEER));
    assert_eq!(check.username(), Some(&b"Bfrag:Afrag"[..]));
    assert_eq!(
        check.verify_integrity(credentials("B").pwd().as_bytes()),
        Integrity::Valid
    );
    assert!(check.ice_controlling().is_some());
    assert!(agent.remotes.iter().any(|remote| {
        remote.candidate.kind == CandidateType::PeerReflexive
            && remote.candidate.address == address(PEER)
            && remote.candidate.priority == PEER_PRIORITY
    }));
}

#[test]
fn a_check_without_priority_is_refused_with_a_signed_400() {
    let (mut agent, _stream, _ids, now) = gathered(Role::Controlling, config(false, false));
    let request = check_from_peer(2, None, false);
    agent.handle_datagram(address(LOCAL), address(PEER), &request, now);
    let replies = drain(&mut agent);
    assert_eq!(replies.len(), 1);
    let reply = Message::parse(&replies[0].data).expect("STUN");
    assert_eq!(
        reply.error_code().map(|error| error.code()),
        Some(error_code::BAD_REQUEST)
    );
    assert_eq!(
        reply.verify_integrity(credentials("A").pwd().as_bytes()),
        Integrity::Valid
    );
    assert!(agent.early.is_empty());
}

#[test]
fn a_response_from_where_the_check_was_not_sent_fails_the_pair() {
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, config(false, false));
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let (_, id) = requests(&drain(&mut agent))[0];
    let answer = response(id, Class::Success, |builder| {
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(LOCAL))
            .expect("mapped");
    });
    agent.handle_datagram(address(LOCAL), address("198.51.100.99:6000"), &answer, now);
    assert_eq!(agent.pairs[0].state, PairState::Failed);

    // the pair is gone at once; the checklist is not. RFC 8863 has the agent
    // wait out `patience` first, because the peer may yet arrive with a check
    // that forms a pair this end could not form for itself
    assert!(!events(&mut agent).contains(&IceEvent::StreamFailed { stream }));
    agent.handle_timeout(now + IceConfig::default().patience);
    assert!(events(&mut agent).contains(&IceEvent::StreamFailed { stream }));
}

#[test]
fn a_response_that_arrives_on_the_wrong_local_candidate_fails_the_pair() {
    // RFC 8445 SS7.2.5.2.1: a response is symmetric only when it "was sent
    // from the same IP address and port to which the Binding request was
    // sent, and ... received on the same host candidate from which the
    // Binding request was sent" - the right peer address alone is not
    // enough; it has to also arrive on the local candidate the check left
    // from, not merely a local candidate this agent owns.
    let now = Instant::now();
    let local_rtcp = address("198.51.100.10:5001");
    let peer_rtcp = address("198.51.100.20:6001");
    let mut agent = IceAgent::new(
        config(false, false),
        credentials("A"),
        Role::Controlling,
        10,
    )
    .expect("an agent");
    let stream = agent
        .add_stream(&[
            (ComponentId::RTP, address(LOCAL)),
            (ComponentId::RTCP, local_rtcp),
        ])
        .expect("usable hosts");
    let mut ids = Ids(0);
    ids.feed(&mut agent);
    agent.gather(now).expect("gathering starts");
    let rtcp = Candidate {
        component: ComponentId::RTCP,
        address: peer_rtcp,
        priority: PEER_PRIORITY - 1,
        ..host(PEER, PEER_PRIORITY, "1")
    };
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1"), rtcp]),
            now,
        )
        .expect("the answer");

    // only the RTP pair's check goes out: it and the RTCP pair share a
    // foundation, and RTP's lower component id is unfrozen first
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let sent = requests(&drain(&mut agent));
    assert_eq!(sent.len(), 1);
    let (destination, rtp_id) = sent[0];
    assert_eq!(destination, address(PEER));

    let answer = response(rtp_id, Class::Success, |builder| {
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(LOCAL))
            .expect("mapped");
    });
    // the right peer address, but delivered as if it arrived on the RTCP
    // socket rather than the RTP one the check actually left from
    agent.handle_datagram(local_rtcp, address(PEER), &answer, now);
    let rtp_pair = agent
        .pairs
        .iter()
        .find(|pair| pair.component == ComponentId::RTP)
        .expect("the RTP pair");
    assert_eq!(rtp_pair.state, PairState::Failed);
}

#[test]
fn a_487_switches_the_role_changes_the_tiebreaker_and_checks_the_pair_again() {
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, config(false, false));
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let (_, id) = requests(&drain(&mut agent))[0];
    let before = agent.tiebreaker;

    let conflict = response(id, Class::Error, |builder| {
        builder
            .add_error_code(error_code::ROLE_CONFLICT, b"Role Conflict")
            .expect("code");
    });
    agent.handle_datagram(address(LOCAL), address(PEER), &conflict, now);
    assert_eq!(agent.role(), Role::Controlled);
    assert_ne!(agent.tiebreaker, before);
    assert!(events(&mut agent).contains(&IceEvent::RoleChanged(Role::Controlled)));
    assert_eq!(agent.pairs[0].state, PairState::Waiting);

    ids.feed(&mut agent);
    let later = now + agent.ta();
    agent.handle_timeout(later);
    let sent = drain(&mut agent);
    let again = Message::parse(&sent[0].data).expect("STUN");
    assert_eq!(again.ice_controlled(), Some(agent.tiebreaker));
    assert!(again.ice_controlling().is_none());
}

#[test]
fn an_unsigned_487_is_not_believed() {
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, config(false, false));
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let (_, id) = requests(&drain(&mut agent))[0];
    let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, id);
    builder
        .add_error_code(error_code::ROLE_CONFLICT, b"Role Conflict")
        .expect("code");
    builder.add_fingerprint().expect("fingerprint");
    agent.handle_datagram(address(LOCAL), address(PEER), &builder.finish(), now);
    assert_eq!(agent.role(), Role::Controlling);
    assert_eq!(agent.pairs[0].state, PairState::InProgress);
}

#[test]
fn a_flood_of_sources_is_held_to_the_remote_candidate_and_pair_limits() {
    let limits = IceConfig {
        max_remote_candidates: 8,
        max_pairs: 5,
        ..config(false, false)
    };
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, limits);
    agent
        .set_remote(stream, &from_peer(Vec::new()), now)
        .expect("the answer");
    let mut answered = 0;
    for index in 0..200_u16 {
        let source = SocketAddr::new("203.0.113.9".parse().expect("ip"), 10_000 + index);
        let request = check_from_peer(
            u8::try_from(index % 250).expect("fits"),
            Some(PEER_PRIORITY),
            false,
        );
        ids.feed(&mut agent);
        agent.handle_datagram(address(LOCAL), source, &request, now);
        answered += drain(&mut agent)
            .iter()
            .filter(|transmit| {
                Message::parse(&transmit.data)
                    .is_ok_and(|message| message.class() == Class::Success)
            })
            .count();
    }
    assert_eq!(answered, 200, "every check is still answered");
    assert!(agent.remotes.len() <= 8, "{}", agent.remotes.len());
    assert!(agent.pairs.len() <= 5, "{}", agent.pairs.len());
    for step in 0..400_u64 {
        ids.feed(&mut agent);
        agent.handle_timeout(now + Duration::from_millis(50 * step));
        drain(&mut agent);
        assert!(agent.checks.len() <= 16, "{}", agent.checks.len());
    }
}

/// A nominating check from a controlling peer under this USERNAME, signed
/// with this agent's password.
fn nomination_from_peer(id: u8, username: &[u8]) -> Vec<u8> {
    let mut builder = MessageBuilder::new(
        Class::Request,
        Method::BINDING,
        TransactionId::new([id; 12]),
    );
    builder
        .add(AttributeType::USERNAME, username)
        .expect("username");
    builder
        .add_u32(AttributeType::PRIORITY, PEER_PRIORITY)
        .expect("priority");
    builder
        .add_flag(AttributeType::USE_CANDIDATE)
        .expect("use-candidate");
    builder
        .add_u64(AttributeType::ICE_CONTROLLING, 20)
        .expect("role");
    builder
        .add_message_integrity(credentials("A").pwd().as_bytes())
        .expect("integrity");
    builder.add_fingerprint().expect("fingerprint");
    builder.finish()
}

#[test]
fn a_nomination_the_bounds_leave_no_room_for_is_refused_rather_than_answered_and_dropped() {
    // RFC 8445 SS7.3.1.5: "If the controlled agent does not accept the request
    // from the controlling agent, the controlled agent MUST reject the
    // nomination request with an appropriate error code response (e.g., 400)"
    let no_room_for_the_source = IceConfig {
        max_remote_candidates: 1,
        ..config(false, false)
    };
    let no_room_for_the_pair = IceConfig {
        max_pairs: 1,
        ..config(false, false)
    };
    for (case, limits) in [
        ("remote candidates", no_room_for_the_source),
        ("pairs", no_room_for_the_pair),
    ] {
        let (mut agent, stream, mut ids, now) = gathered(Role::Controlled, limits);
        agent
            .set_remote(
                stream,
                &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
                now,
            )
            .expect("the answer");
        ids.feed(&mut agent);
        agent.handle_timeout(now);
        drain(&mut agent);

        // the peer, from behind a NAT nobody advertised, nominates the pair
        // its own check validated; one of the bounds is already full
        let behind_nat = address("192.0.2.77:40000");
        agent.handle_datagram(
            address(LOCAL),
            behind_nat,
            &nomination_from_peer(3, b"Afrag:Bfrag"),
            now,
        );
        let sent = drain(&mut agent);
        let reply = sent
            .iter()
            .find(|transmit| transmit.destination == behind_nat)
            .expect("an answer to the nomination");
        let message = Message::parse(&reply.data).expect("STUN");
        let followed = agent.pairs.iter().any(|pair| {
            agent
                .remotes
                .get(pair.remote)
                .is_some_and(|remote| remote.candidate.address == behind_nat)
        });
        assert!(
            message.class() == Class::Error || followed,
            "{case}: the nomination was answered with {:?} and then dropped",
            message.class()
        );
        assert_eq!(
            message.error_code().map(|error| error.code()),
            Some(error_code::BAD_REQUEST),
            "{case}"
        );
        assert_eq!(
            message.verify_integrity(credentials("A").pwd().as_bytes()),
            Integrity::Valid,
            "{case}"
        );
    }
}

#[test]
fn the_checklist_set_keeps_only_the_highest_priority_pairs_under_the_limit() {
    let limits = IceConfig {
        max_pairs: 10,
        ..config(false, false)
    };
    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, limits);
    let candidates: Vec<Candidate> = (0..30_u32)
        .map(|index| {
            let at = format!("203.0.113.{}:6000", index + 1);
            host(&at, 1_000 + index, &(index + 1).to_string())
        })
        .collect();
    agent
        .set_remote(stream, &from_peer(candidates), now)
        .expect("the answer");
    assert_eq!(agent.pairs.len(), 10);
    let lowest_kept = agent
        .pairs
        .iter()
        .filter_map(|pair| agent.remotes.get(pair.remote))
        .map(|remote| remote.candidate.priority)
        .min();
    assert_eq!(lowest_kept, Some(1_020));
}

#[test]
fn a_pair_never_crosses_address_families_or_link_local_with_global() {
    // RFC 8445 SS6.1.2.2: pairs form only "of the same component and of the
    // same IP address family" (checked against the *base*, since a
    // server-reflexive candidate's own family always matches its base's);
    // link-local addresses "MUST NOT be paired with other than link-local
    // addresses" (SS6.1.2.2).
    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, config(false, false));
    let v6_global = Candidate {
        address: address("[2001:db8::9]:6000"),
        ..host(PEER, PEER_PRIORITY, "1")
    };
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1"), v6_global]),
            now,
        )
        .expect("the answer");
    assert_eq!(
        agent.pairs.len(),
        1,
        "an IPv6 remote candidate paired with an IPv4 host"
    );
    assert_eq!(
        agent.remotes[agent.pairs[0].remote].candidate.address,
        address(PEER)
    );

    // a link-local IPv6 host base only pairs with another link-local address
    let link_local_host = address("[fe80::1]:5000");
    let mut agent = IceAgent::new(
        config(false, false),
        credentials("A"),
        Role::Controlling,
        10,
    )
    .expect("an agent");
    let stream = agent
        .add_stream(&[(ComponentId::RTP, link_local_host)])
        .expect("a usable host");
    let mut ids = Ids(0);
    ids.feed(&mut agent);
    agent.gather(now).expect("gathering starts");
    let link_local_peer = Candidate {
        address: address("[fe80::2]:6000"),
        ..host(PEER, PEER_PRIORITY, "1")
    };
    let global_peer = Candidate {
        address: address("[2001:db8::2]:6000"),
        ..host(PEER, PEER_PRIORITY - 1, "2")
    };
    agent
        .set_remote(
            stream,
            &from_peer(vec![link_local_peer.clone(), global_peer]),
            now,
        )
        .expect("the answer");
    assert_eq!(
        agent.pairs.len(),
        1,
        "a global IPv6 remote candidate paired with a link-local host"
    );
    assert_eq!(
        agent.remotes[agent.pairs[0].remote].candidate.address,
        link_local_peer.address
    );
}

#[test]
fn a_peers_candidates_are_filtered_and_bounded_the_same_way_a_check_source_is() {
    // the SDP path into add_remote_candidates applies the same RFC 8445
    // SS5.1.2 and SS7.3.1.3 checks the peer-reflexive learning path does:
    // a priority of zero or past 2^31-1, a wildcard port or address, a
    // component this stream does not have, and a bound on how many are kept
    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, config(false, false));
    let garbage = vec![
        host("203.0.113.1:6000", 0, "1"),
        host("203.0.113.2:6000", 0x8000_0000, "2"),
        Candidate {
            address: address("203.0.113.3:0"),
            ..host("203.0.113.3:1", 1_000, "3")
        },
        Candidate {
            address: address("0.0.0.0:6000"),
            ..host("0.0.0.0:6000", 1_000, "4")
        },
        Candidate {
            component: ComponentId::RTCP,
            ..host("203.0.113.5:6000", 1_000, "5")
        },
    ];
    let good = host(PEER, PEER_PRIORITY, "6");
    let mut offered = garbage;
    offered.push(good.clone());
    offered.push(good.clone()); // a duplicate address, also dropped
    agent
        .set_remote(stream, &from_peer(offered), now)
        .expect("the answer");
    assert_eq!(agent.remotes.len(), 1, "{:?}", agent.remotes.len());
    assert_eq!(agent.remotes[0].candidate.address, good.address);

    // the bound on the SDP path is exact, not approximate
    let limited = IceConfig {
        max_remote_candidates: 3,
        ..config(false, false)
    };
    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, limited);
    let many: Vec<Candidate> = (0..10_u32)
        .map(|index| {
            let at = format!("203.0.113.{}:6000", index + 10);
            host(&at, 1_000 + index, &(index + 10).to_string())
        })
        .collect();
    agent
        .set_remote(stream, &from_peer(many), now)
        .expect("the answer");
    assert_eq!(agent.remotes.len(), 3, "{:?}", agent.remotes.len());
}

#[test]
fn a_pairs_priority_uses_the_controlling_agents_candidate_as_g() {
    // RFC 8445 SS6.1.2.3: G is "the priority for the candidate provided by
    // the controlling agent, and D is the priority for the candidate
    // provided by the controlled agent" - whichever side that is, not
    // whichever side is local.
    const HOST_PRIORITY: u32 = 2_130_706_431; // candidate_priority(Host, 65535, RTP)
    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, config(false, false));
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    assert_eq!(
        agent.pairs[0].priority,
        pair_priority(HOST_PRIORITY, PEER_PRIORITY)
    );

    let (mut agent, stream, _ids, now) = gathered(Role::Controlled, config(false, false));
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    assert_eq!(
        agent.pairs[0].priority,
        pair_priority(PEER_PRIORITY, HOST_PRIORITY)
    );
}

/// Hand a nomination to the agent and insist it is refused with a signed 400.
fn assert_refused(
    agent: &mut IceAgent,
    local: SocketAddr,
    from: SocketAddr,
    request: &[u8],
    now: Instant,
    case: &str,
) {
    agent.handle_datagram(local, from, request, now);
    let sent = drain(agent);
    let reply = sent
        .iter()
        .find(|transmit| transmit.destination == from)
        .unwrap_or_else(|| panic!("{case}: no answer"));
    let message = Message::parse(&reply.data).expect("STUN");
    assert_eq!(
        message.class(),
        Class::Error,
        "{case}: the nomination was answered with {:?} and then dropped",
        message.class()
    );
    assert_eq!(
        message.error_code().map(|error| error.code()),
        Some(error_code::BAD_REQUEST),
        "{case}"
    );
    assert_eq!(
        message.verify_integrity(credentials("A").pwd().as_bytes()),
        Integrity::Valid,
        "{case}"
    );
}

#[test]
fn a_nomination_the_agent_will_not_act_on_is_refused_on_every_path() {
    // RFC 8445 SS7.3.1.5, as in the test above, for the paths that drop a
    // nomination for a reason other than a full bound

    // the stream's checklist has Failed
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlled, config(false, false));
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let (_, id) = requests(&drain(&mut agent))[0];
    let elsewhere = response(id, Class::Success, |builder| {
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(LOCAL))
            .expect("mapped");
    });
    agent.handle_datagram(
        address(LOCAL),
        address("198.51.100.99:6000"),
        &elsewhere,
        now,
    );
    // the checklist Fails once patience runs out, not on the response itself
    let now = now + IceConfig::default().patience;
    agent.handle_timeout(now);
    assert!(events(&mut agent).contains(&IceEvent::StreamFailed { stream }));
    assert_refused(
        &mut agent,
        address(LOCAL),
        address(PEER),
        &nomination_from_peer(4, b"Afrag:Bfrag"),
        now,
        "a failed checklist",
    );

    // signed with this agent's password, but naming a peer fragment this
    // stream does not hold, so there is no password to check back with
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlled, config(false, false));
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    drain(&mut agent);
    assert_refused(
        &mut agent,
        address(LOCAL),
        address(PEER),
        &nomination_from_peer(5, b"Afrag:Cfrag"),
        now,
        "another peer's fragment",
    );

    // a component the stream no longer has: the peer offered component 1
    // only, which reduces the stream to it (SS6.1.2.2)
    let now = Instant::now();
    let local_rtcp = address("198.51.100.10:5001");
    let mut agent = IceAgent::new(config(false, false), credentials("A"), Role::Controlled, 10)
        .expect("an agent");
    let stream = agent
        .add_stream(&[
            (ComponentId::RTP, address(LOCAL)),
            (ComponentId::RTCP, local_rtcp),
        ])
        .expect("usable hosts");
    let mut ids = Ids(0);
    ids.feed(&mut agent);
    agent.gather(now).expect("gathering starts");
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    drain(&mut agent);
    assert_refused(
        &mut agent,
        local_rtcp,
        address("198.51.100.20:6001"),
        &nomination_from_peer(6, b"Afrag:Bfrag"),
        now,
        "a component the stream no longer has",
    );
}

#[test]
fn a_stream_whose_checklist_failed_carries_nothing_and_selects_nothing() {
    // RFC 8445 SS12.1: "Unless an agent is able to produce a selected pair for
    // each component associated with a data stream, the agent MUST NOT
    // continue sending data for any component associated with that data
    // stream"
    let now = Instant::now();
    let local_rtcp = address("198.51.100.10:5001");
    let peer_rtcp = address("198.51.100.20:6001");
    let mut agent = IceAgent::new(config(false, false), credentials("A"), Role::Controlled, 10)
        .expect("an agent");
    let stream = agent
        .add_stream(&[
            (ComponentId::RTP, address(LOCAL)),
            (ComponentId::RTCP, local_rtcp),
        ])
        .expect("usable hosts");
    let mut ids = Ids(0);
    ids.feed(&mut agent);
    agent.gather(now).expect("gathering starts");
    let rtcp = Candidate {
        component: ComponentId::RTCP,
        address: peer_rtcp,
        priority: PEER_PRIORITY - 1,
        ..host(PEER, PEER_PRIORITY, "1")
    };
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1"), rtcp]),
            now,
        )
        .expect("the answer");

    // the RTP pair's own check goes out and is not answered yet
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let first = requests(&drain(&mut agent));
    assert_eq!(first.len(), 1);
    let (_, rtp_first) = first[0];

    // the peer nominates both components before either pair has succeeded
    agent.handle_datagram(
        local_rtcp,
        peer_rtcp,
        &nomination_from_peer(7, b"Afrag:Bfrag"),
        now,
    );
    agent.handle_datagram(
        address(LOCAL),
        address(PEER),
        &nomination_from_peer(8, b"Afrag:Bfrag"),
        now,
    );
    drain(&mut agent);

    // the triggered checks: RTCP first, then RTP again
    let mut triggered = Vec::new();
    let mut at = now;
    while triggered.len() < 2 && at < now + Duration::from_secs(1) {
        at += agent.ta();
        ids.feed(&mut agent);
        agent.handle_timeout(at);
        triggered.extend(requests(&drain(&mut agent)));
    }
    let (rtcp_check, _) = triggered
        .iter()
        .find(|(destination, _)| *destination == peer_rtcp)
        .map(|(destination, id)| (*id, *destination))
        .expect("a triggered check on the RTCP pair");

    // RTCP's nominated check comes back from somewhere else: the pair fails,
    // and with it the checklist (SS7.2.5.3.4)
    let elsewhere = response(rtcp_check, Class::Success, |builder| {
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, local_rtcp)
            .expect("mapped");
    });
    agent.handle_datagram(local_rtcp, address("198.51.100.99:6001"), &elsewhere, at);
    assert!(events(&mut agent).contains(&IceEvent::StreamFailed { stream }));

    // and only now does the answer to RTP's first, cancelled check arrive
    let late = response(rtp_first, Class::Success, |builder| {
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(LOCAL))
            .expect("mapped");
    });
    agent.handle_datagram(address(LOCAL), address(PEER), &late, at);

    let mut out = Vec::new();
    assert!(
        agent
            .send(stream, ComponentId::RTP, b"\x80\x00media", &mut out, at)
            .is_err(),
        "data was routed on a stream whose checklist Failed"
    );
    assert_eq!(agent.selected_pair(stream, ComponentId::RTP), None);
    let until = at + Duration::from_secs(10);
    while at < until {
        at += Duration::from_millis(250);
        ids.feed(&mut agent);
        agent.handle_timeout(at);
        let sent = requests(&drain(&mut agent));
        assert!(
            sent.is_empty(),
            "a Binding request left for a failed stream: {sent:?}"
        );
    }
}

#[test]
fn the_pair_limit_never_discards_a_pair_a_check_has_already_validated() {
    // RFC 8445 SS8.1.1: the controlling agent "MUST eventually pick one and
    // only one candidate pair and generate a check for that pair with the
    // USE-CANDIDATE attribute set", by repeating "the connectivity check
    // that produced this valid pair"
    let limits = IceConfig {
        max_pairs: 1,
        ..config(false, false)
    };
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, limits);
    let first = host("203.0.113.1:6000", 1_000, "1");
    agent
        .set_remote(stream, &from_peer(vec![first.clone()]), now)
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let (destination, id) = requests(&drain(&mut agent))[0];
    assert_eq!(destination, first.address);
    let answer = response(id, Class::Success, |builder| {
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(LOCAL))
            .expect("mapped");
    });
    agent.handle_datagram(address(LOCAL), first.address, &answer, now);

    // the same peer, the same credentials, one better candidate more: the
    // set is at its limit of one pair
    let better = host("203.0.113.2:6000", 3_000, "2");
    agent
        .set_remote(stream, &from_peer(vec![first.clone(), better.clone()]), now)
        .expect("more candidates");

    let mut at = now;
    let mut nominated = false;
    while at < now + Duration::from_secs(5) && !nominated {
        ids.feed(&mut agent);
        agent.handle_timeout(at);
        for transmit in drain(&mut agent) {
            let Ok(message) = Message::parse(&transmit.data) else {
                continue;
            };
            if message.class() != Class::Request {
                continue;
            }
            if transmit.destination == better.address {
                // the better pair does not work: its answer comes back from
                // somewhere else
                let refused = response(message.transaction_id(), Class::Success, |builder| {
                    builder
                        .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(LOCAL))
                        .expect("mapped");
                });
                agent.handle_datagram(address(LOCAL), address("203.0.113.99:6000"), &refused, at);
            } else if transmit.destination == first.address && message.use_candidate() {
                nominated = true;
            }
        }
        at += Duration::from_millis(10);
    }
    assert!(
        nominated,
        "the only valid pair was never nominated; pairs: {:?}",
        agent
            .pairs
            .iter()
            .map(|pair| (pair.remote, pair.state))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_server_reflexive_candidate_is_advertised_but_checked_from_its_base() {
    let now = Instant::now();
    let (mut agent, stream) = agent(
        config(true, false),
        "A",
        Role::Controlling,
        10,
        address(LOCAL),
    );
    let mut ids = Ids(0);
    ids.feed(&mut agent);
    agent.gather(now).expect("gathering starts");
    agent.handle_timeout(now);
    let sent = drain(&mut agent);
    let (server, id) = requests(&sent)[0];
    assert_eq!(server, address(STUN_SERVER));
    let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, id);
    builder
        .add_xor_address(
            AttributeType::XOR_MAPPED_ADDRESS,
            address("192.0.2.1:40000"),
        )
        .expect("mapped");
    agent.handle_datagram(address(LOCAL), server, &builder.finish(), now);
    assert!(events(&mut agent).contains(&IceEvent::GatheringComplete));
    let kinds: Vec<CandidateType> = agent
        .local_candidates(stream)
        .iter()
        .map(|candidate| candidate.kind)
        .collect();
    assert_eq!(
        kinds,
        vec![CandidateType::Host, CandidateType::ServerReflexive]
    );

    // RFC 8445 SS6.1.2.4: the pair from the reflexive candidate becomes the
    // host pair and is pruned against it
    agent
        .set_remote(
            stream,
            &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
            now,
        )
        .expect("the answer");
    assert_eq!(agent.pairs.len(), 1);
    assert_eq!(
        agent.locals[agent.pairs[0].local].candidate.kind,
        CandidateType::Host
    );
}

#[test]
fn gathering_gives_up_on_a_silent_server_when_the_timeout_says_so() {
    let now = Instant::now();
    let (mut agent, stream) = agent(
        config(true, true),
        "A",
        Role::Controlling,
        10,
        address(LOCAL),
    );
    let mut ids = Ids(0);
    let mut at = now;
    ids.feed(&mut agent);
    agent.gather(now).expect("gathering starts");
    let mut done_at = None;
    while at < now + Duration::from_secs(10) {
        ids.feed(&mut agent);
        agent.handle_timeout(at);
        for transmit in drain(&mut agent) {
            assert!(
                [address(STUN_SERVER), address(TURN_SERVER)].contains(&transmit.destination),
                "{transmit:?}"
            );
        }
        if done_at.is_none() && events(&mut agent).contains(&IceEvent::GatheringComplete) {
            done_at = Some(at);
        }
        at = agent
            .deadline()
            .filter(|deadline| *deadline > at)
            .unwrap_or(at + Duration::from_millis(10));
    }
    assert_eq!(done_at, Some(now + Duration::from_secs(5)));
    assert_eq!(agent.local_candidates(stream).len(), 1);
}

#[test]
fn checks_go_out_no_faster_than_ta() {
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, config(false, false));
    let candidates = vec![
        host("203.0.113.1:6000", 3_000, "1"),
        host("203.0.113.2:6000", 2_000, "2"),
        host("203.0.113.3:6000", 1_000, "3"),
    ];
    agent
        .set_remote(stream, &from_peer(candidates), now)
        .expect("the answer");
    ids.feed(&mut agent);
    agent.handle_timeout(now);
    assert_eq!(requests(&drain(&mut agent)).len(), 1);
    assert_eq!(agent.deadline(), Some(now + agent.ta()));

    ids.feed(&mut agent);
    let early = (now + agent.ta())
        .checked_sub(Duration::from_millis(1))
        .expect("an instant a millisecond earlier");
    agent.handle_timeout(early);
    assert!(requests(&drain(&mut agent)).is_empty());

    ids.feed(&mut agent);
    agent.handle_timeout(now + agent.ta());
    let second = requests(&drain(&mut agent));
    assert_eq!(second.len(), 1);
    // and in priority order
    assert_eq!(second[0].0, address("203.0.113.2:6000"));
}

#[test]
fn ta_is_the_larger_of_the_two_proposals_within_a_bound() {
    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, config(false, false));
    let mut remote = from_peer(Vec::new());
    remote.pacing = Some(Duration::from_millis(80));
    agent.set_remote(stream, &remote, now).expect("the answer");
    assert_eq!(agent.ta(), Duration::from_millis(80));

    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, config(false, false));
    remote.pacing = Some(Duration::from_millis(20));
    agent.set_remote(stream, &remote, now).expect("the answer");
    assert_eq!(agent.ta(), Duration::from_millis(50));

    let (mut agent, stream, _ids, now) = gathered(Role::Controlling, config(false, false));
    remote.pacing = Some(Duration::from_secs(3_600));
    agent.set_remote(stream, &remote, now).expect("the answer");
    assert_eq!(agent.ta(), Duration::from_secs(10));
}

#[test]
fn a_peer_that_proposes_no_pacing_counts_as_proposing_the_default() {
    // RFC 8445 SS14.2: "Both agents MUST use the higher value of the proposed
    // values. If an agent does not propose a value, the default value is used
    // for that agent when comparing which value is higher." A lite peer never
    // proposes one (RFC 8839 SS4.3.1), so this is also every lite peer.
    let fast = IceConfig {
        ta: Duration::from_millis(20),
        ..config(false, false)
    };
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, fast);
    assert_eq!(agent.ta(), Duration::from_millis(20));
    let candidates = vec![
        host("203.0.113.1:6000", 3_000, "1"),
        host("203.0.113.2:6000", 2_000, "2"),
    ];
    agent
        .set_remote(stream, &from_peer(candidates), now)
        .expect("the answer");
    assert_eq!(agent.ta(), Duration::from_millis(50));

    ids.feed(&mut agent);
    agent.handle_timeout(now);
    assert_eq!(requests(&drain(&mut agent)).len(), 1);
    ids.feed(&mut agent);
    agent.handle_timeout(now + Duration::from_millis(20));
    assert!(
        requests(&drain(&mut agent)).is_empty(),
        "a second check 20 ms after the first"
    );
}

#[test]
fn one_pair_per_foundation_starts_waiting_and_its_success_unfreezes_the_rest() {
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, config(false, false));
    let candidates = vec![
        host("203.0.113.1:6000", 3_000, "7"),
        host("203.0.113.1:6002", 2_000, "7"),
    ];
    agent
        .set_remote(stream, &from_peer(candidates), now)
        .expect("the answer");
    let states: Vec<PairState> = agent.pairs.iter().map(|pair| pair.state).collect();
    assert_eq!(states, vec![PairState::Waiting, PairState::Frozen]);

    ids.feed(&mut agent);
    agent.handle_timeout(now);
    let (destination, id) = requests(&drain(&mut agent))[0];
    assert_eq!(destination, address("203.0.113.1:6000"));
    // with the first In-Progress, the second stays Frozen: its foundation has
    // a pair under way (RFC 8445 SS6.1.4.2, step 2)
    ids.feed(&mut agent);
    agent.handle_timeout(now + agent.ta());
    assert!(requests(&drain(&mut agent)).is_empty());
    assert_eq!(agent.pairs[1].state, PairState::Frozen);

    let answer = response(id, Class::Success, |builder| {
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(LOCAL))
            .expect("mapped");
    });
    agent.handle_datagram(address(LOCAL), destination, &answer, now + agent.ta());
    assert_eq!(agent.pairs[0].state, PairState::Succeeded);
    assert_eq!(agent.pairs[1].state, PairState::Waiting);
}

/// A small generator, so that the inputs below are the same on every run.
struct Noise(u64);

impl Noise {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn byte(&mut self) -> u8 {
        self.next().to_be_bytes()[0]
    }
}

#[test]
fn no_datagram_panics_the_agent_in_any_state() {
    let sources = [
        address(PEER),
        address(STUN_SERVER),
        address(TURN_SERVER),
        address("203.0.113.77:1"),
    ];
    let mut noise = Noise(0x5eed_1ce5);
    for phase in 0..3 {
        let now = Instant::now();
        let (mut agent, stream) = agent(
            config(true, true),
            "A",
            Role::Controlling,
            10,
            address(LOCAL),
        );
        let mut ids = Ids(0);
        ids.feed(&mut agent);
        if phase > 0 {
            agent.gather(now).expect("gathering starts");
        }
        if phase > 1 {
            agent
                .set_remote(
                    stream,
                    &from_peer(vec![host(PEER, PEER_PRIORITY, "1")]),
                    now,
                )
                .expect("the answer");
        }
        let valid_check = check_from_peer(9, Some(PEER_PRIORITY), true);
        let mut at = now;
        for round in 0..3_000_u64 {
            let datagram: Vec<u8> = match round % 3 {
                0 => {
                    let length = usize::from(noise.byte() % 120);
                    (0..length).map(|_| noise.byte()).collect()
                }
                1 => {
                    let mut mutated = valid_check.clone();
                    let position = usize::try_from(noise.next()).unwrap_or(0) % mutated.len();
                    mutated[position] ^= noise.byte() | 1;
                    mutated
                }
                _ => {
                    // a STUN header with a random class, method and body
                    let mut header = vec![noise.byte() & 0x3f, noise.byte(), 0, 8];
                    header.extend_from_slice(&0x2112_a442_u32.to_be_bytes());
                    header.extend((0..20).map(|_| noise.byte()));
                    header
                }
            };
            let source = sources[usize::from(noise.byte()) % sources.len()];
            ids.feed(&mut agent);
            let _ = agent.handle_datagram(address(LOCAL), source, &datagram, at);
            at += Duration::from_millis(u64::from(noise.byte() % 50));
            agent.handle_timeout(at);
            drain(&mut agent);
            events(&mut agent);
            let _ = agent.deadline();
        }
    }
}

/// The case RFC 8863 is written for, and the one that used to have no way
/// out: a peer whose candidates this agent cannot pair with anything, so no
/// check is ever sent and none of the paths that fail a checklist is ever
/// reached.
///
/// Before the timer this checklist stayed Running for the life of the call
/// with `deadline()` answering `None` — so a caller that slept until the
/// agent next had something to do slept for ever, on a call that was never
/// going to carry a packet.
#[test]
fn a_checklist_that_never_had_a_pair_is_waited_on_and_then_fails() {
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, config(false, false));
    // an IPv6 candidate against an IPv4 base: RFC 8445 §6.1.2.2 pairs only
    // candidates of the same family, so nothing can be formed
    let mut unpairable = host("198.51.100.20:6000", PEER_PRIORITY, "1");
    unpairable.address = address("[2001:db8::1]:6000");
    agent
        .set_remote(stream, &from_peer(vec![unpairable]), now)
        .expect("the answer");
    ids.feed(&mut agent);

    assert!(agent.pairs.is_empty(), "nothing should have paired");
    assert_eq!(agent.state(), IceState::Running);

    // the agent now has something to do, and says when
    let deadline = agent
        .deadline()
        .expect("a checklist with no pairs has a deadline");
    assert!(
        deadline <= now + IceConfig::default().patience,
        "the wait is bounded by patience"
    );

    // and it is patience, not a moment less
    agent.handle_timeout(
        now + IceConfig::default()
            .patience
            .saturating_sub(Duration::from_millis(1)),
    );
    assert!(!events(&mut agent).contains(&IceEvent::StreamFailed { stream }));

    agent.handle_timeout(now + IceConfig::default().patience);
    let told = events(&mut agent);
    assert!(
        told.contains(&IceEvent::StreamFailed { stream }),
        "{told:?}"
    );
    assert!(told.contains(&IceEvent::Failed), "{told:?}");
    assert_eq!(agent.state(), IceState::Failed);
}

/// The other half of the same rule: patience is not a delay on failure, it is
/// a window in which the peer can still connect the call. A check that
/// arrives inside it forms a peer-reflexive pair and the checklist lives.
#[test]
fn a_peer_that_arrives_inside_the_wait_still_connects_the_call() {
    // controlling here, because the check the peer sends says ICE-CONTROLLED
    // and two agents that both believe they are controlled is a role
    // conflict, which is a different rule being tested somewhere else
    let (mut agent, stream, mut ids, now) = gathered(Role::Controlling, config(false, false));
    let mut unpairable = host("198.51.100.20:6000", PEER_PRIORITY, "1");
    unpairable.address = address("[2001:db8::1]:6000");
    agent
        .set_remote(stream, &from_peer(vec![unpairable]), now)
        .expect("the answer");
    ids.feed(&mut agent);
    assert!(agent.pairs.is_empty());

    // the peer reaches us from an address nobody named, a round trip before
    // patience would have run out
    let arrived = now
        + IceConfig::default()
            .patience
            .saturating_sub(Duration::from_secs(1));
    agent.handle_datagram(
        address(LOCAL),
        address(PEER),
        &check_from_peer(9, Some(PEER_PRIORITY), false),
        arrived,
    );
    assert!(
        !agent.pairs.is_empty(),
        "a check from a source nobody knew is a peer-reflexive pair (RFC 8445 §7.3.1.3)"
    );

    // and the checklist is not failed at the moment the old wait would have
    // expired, because it now has something to check
    agent.handle_timeout(now + IceConfig::default().patience);
    assert!(!events(&mut agent).contains(&IceEvent::StreamFailed { stream }));
    assert_eq!(agent.state(), IceState::Running);
}
