// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A WebSocket the agent runs, against a server scripted here.
//!
//! The server is the bytes RFC 6455 says one writes: a 101 that answers the
//! key the agent drew, frames that are not masked, a ping, a close. What is
//! checked is what goes the other way — the handshake first and the REGISTER
//! held behind it, every frame masked, the `.invalid` name in the `Via` and
//! the `Contact` (RFC 7118 Appendix B.1) — and that a connection which fails
//! or closes is retired and told the way a TCP one is.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Event, Input, TransportId, TransportProtocol};
use sipral_core::msg::HeaderName;

use crate::EndpointConfig;
use crate::account::Account;
use crate::agent::UserAgent;
use crate::event::UaEvent;
use crate::tests::{events, header, reply, uri};
use crate::websocket::{OPENING_WAIT, PING_EVERY, PONG_WAIT, WebSocketTarget, accept_for};

const WS: TransportId = TransportId(3);

fn local() -> SocketAddr {
    "192.0.2.1:40000".parse().unwrap()
}

fn server() -> SocketAddr {
    "192.0.2.9:8088".parse().unwrap()
}

/// An agent with a WebSocket to [`server`] bound and an account on it.
fn connected(now: Instant) -> UserAgent {
    let mut agent = UserAgent::new(EndpointConfig::default(), [21; 32]).unwrap();
    agent.set_websocket_target(
        server(),
        WebSocketTarget::new("pbx.example.com", "/ws").unwrap(),
    );
    agent.add_account(Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri("sip:alice@192.0.2.1:40000"),
        WS,
        server(),
    ));
    agent
        .receive(
            Input::TransportBound {
                transport: WS,
                protocol: TransportProtocol::Ws,
                local: local(),
                remote: Some(server()),
            },
            now,
        )
        .unwrap();
    agent
}

fn written(agent: &mut UserAgent) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(transmit) = agent.poll_transmit() {
        assert_eq!(transmit.transport, WS);
        assert_eq!(transmit.protocol, TransportProtocol::Ws);
        out.push(transmit.payload.to_vec());
    }
    out
}

/// A frame as the client wrote it: checked to be final and masked, and
/// unmasked.
fn unmasked(frame: &[u8]) -> (u8, Vec<u8>) {
    assert_eq!(frame[0] & 0x80, 0x80, "final");
    assert_eq!(frame[1] & 0x80, 0x80, "a client masks every frame");
    let (length, at) = match frame[1] & 0x7F {
        126 => (usize::from(u16::from_be_bytes([frame[2], frame[3]])), 4),
        127 => (
            usize::try_from(u64::from_be_bytes(frame[2..10].try_into().unwrap())).unwrap(),
            10,
        ),
        short => (usize::from(short), 2),
    };
    let mask = &frame[at..at + 4];
    let payload: Vec<u8> = frame[at + 4..]
        .iter()
        .zip(mask.iter().cycle())
        .map(|(byte, key)| byte ^ key)
        .collect();
    assert_eq!(payload.len(), length);
    (frame[0] & 0x0F, payload)
}

fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    if payload.len() < 126 {
        out.push(u8::try_from(payload.len()).unwrap());
    } else {
        out.push(126);
        out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

fn feed(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
    agent
        .receive(
            Input::StreamData {
                transport: WS,
                data: bytes,
            },
            now,
        )
        .unwrap();
}

/// The server's 101, for the handshake the agent wrote.
fn accepted(handshake: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(handshake.to_vec()).unwrap();
    let key = text
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap();
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: sip\r\n\r\n",
        accept_for(key)
    )
    .into_bytes()
}

fn flow_failed(events: &[UaEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, UaEvent::Unclaimed(Event::FlowFailed { transport }) if *transport == WS))
}

/// Bound, the REGISTER sent, the handshake answered: the REGISTER, as the
/// server reads it.
fn opened(agent: &mut UserAgent, now: Instant) -> Vec<u8> {
    let account = agent.accounts()[0];
    agent.register(account, now).unwrap();
    let out = written(agent);
    assert_eq!(
        out.len(),
        1,
        "the handshake, and the REGISTER held behind it"
    );
    let handshake = &out[0];
    assert!(handshake.starts_with(b"GET /ws HTTP/1.1\r\nHost: pbx.example.com\r\n"));
    feed(agent, &accepted(handshake), now);
    let out = written(agent);
    assert_eq!(out.len(), 1);
    let (opcode, register) = unmasked(&out[0]);
    assert_eq!(opcode, 1, "SIP that is UTF-8 goes as text");
    register
}

#[test]
fn a_register_waits_for_the_handshake_and_names_the_invalid_host() {
    let t0 = Instant::now();
    let mut agent = connected(t0);
    let register = opened(&mut agent, t0);
    assert!(register.starts_with(b"REGISTER sip:example.com SIP/2.0\r\n"));

    let via = String::from_utf8(header(&register, HeaderName::Via)).unwrap();
    let name = via
        .strip_prefix("SIP/2.0/WS ")
        .and_then(|rest| rest.split(';').next())
        .unwrap()
        .to_owned();
    assert!(name.ends_with(".invalid"), "{via}");
    assert_eq!(
        String::from_utf8(header(&register, HeaderName::Contact)).unwrap(),
        format!("<sip:alice@{name};transport=ws>")
    );

    // the 200 comes back in a frame of its own, with the Via it was sent
    let ok = reply(
        &register,
        200,
        "OK",
        &format!("Contact: <sip:alice@{name};transport=ws>;expires=600\r\n"),
    );
    feed(&mut agent, &server_frame(1, &ok), t0);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::Registered { .. })),
        "registered over the WebSocket"
    );
}

#[test]
fn a_ping_is_answered_and_a_quiet_connection_is_pinged_until_it_fails() {
    let t0 = Instant::now();
    let mut agent = connected(t0);
    opened(&mut agent, t0);

    feed(&mut agent, &server_frame(9, b"hi"), t0);
    let out = written(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(unmasked(&out[0]), (0xA, b"hi".to_vec()), "a pong, echoing");

    let t1 = t0 + PING_EVERY;
    assert!(agent.poll_timeout().is_some_and(|due| due <= t1));
    agent.handle_timeout(t1);
    let out = written(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(unmasked(&out[0]).0, 9, "a ping");
    events(&mut agent);

    // a pong keeps it; none for long enough fails it
    feed(&mut agent, &server_frame(0xA, b""), t1);
    agent.handle_timeout(t1 + PONG_WAIT);
    assert!(!flow_failed(&events(&mut agent)));
    let t2 = t1 + PING_EVERY + Duration::from_secs(1);
    agent.handle_timeout(t2);
    written(&mut agent);
    agent.handle_timeout(t2 + PONG_WAIT);
    assert!(flow_failed(&events(&mut agent)));
    assert!(agent.websocket_failure(WS).unwrap().1.contains("no pong"));
    assert!(!agent.runs_websocket(WS));
}

#[test]
fn a_refused_handshake_fails_the_connection_and_says_why() {
    let t0 = Instant::now();
    let mut agent = connected(t0);
    written(&mut agent);
    feed(
        &mut agent,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        t0,
    );
    assert!(flow_failed(&events(&mut agent)));
    assert!(agent.websocket_failure(WS).unwrap().1.contains("404"));
    assert!(agent.endpoint().bound_transport(WS).is_none(), "retired");
}

#[test]
fn an_unanswered_handshake_fails_in_its_own_time() {
    let t0 = Instant::now();
    let mut agent = connected(t0);
    written(&mut agent);
    agent.handle_timeout(t0 + OPENING_WAIT);
    assert!(flow_failed(&events(&mut agent)));
}

#[test]
fn a_close_is_answered_with_its_code_and_the_connection_retired() {
    let t0 = Instant::now();
    let mut agent = connected(t0);
    opened(&mut agent, t0);
    feed(&mut agent, &server_frame(8, &1001_u16.to_be_bytes()), t0);
    let out = written(&mut agent);
    assert_eq!(unmasked(&out[0]), (8, 1001_u16.to_be_bytes().to_vec()));
    assert!(flow_failed(&events(&mut agent)));
    assert!(agent.websocket_failure(WS).unwrap().1.contains("1001"));
}

#[test]
fn this_end_closes_with_1000_sends_nothing_after_and_is_done_at_the_answer() {
    let t0 = Instant::now();
    let mut agent = connected(t0);
    opened(&mut agent, t0);
    assert!(agent.close_websocket(WS, t0));
    assert!(!agent.close_websocket(WS, t0), "already closing");
    let out = written(&mut agent);
    assert_eq!(unmasked(&out[0]), (8, 1000_u16.to_be_bytes().to_vec()));

    // a request the endpoint writes now does not go, and a ping is not
    // answered: nothing follows a close (RFC 6455 §5.5.1)
    let account = agent.accounts()[0];
    let _ = agent.unregister(account, t0);
    feed(&mut agent, &server_frame(9, b""), t0);
    assert!(written(&mut agent).is_empty());

    feed(&mut agent, &server_frame(8, &1000_u16.to_be_bytes()), t0);
    assert!(
        written(&mut agent).is_empty(),
        "the server's close is not answered again"
    );
    assert!(flow_failed(&events(&mut agent)));
    assert_eq!(
        agent.websocket_failure(WS).map(|(kind, _)| kind),
        Some(sipral_core::endpoint::TransportErrorKind::Closed)
    );
}

#[test]
fn a_close_the_server_never_answers_is_given_up_on() {
    let t0 = Instant::now();
    let mut agent = connected(t0);
    opened(&mut agent, t0);
    agent.close_websocket(WS, t0);
    written(&mut agent);
    agent.handle_timeout(t0 + PONG_WAIT);
    assert!(flow_failed(&events(&mut agent)));
    assert!(!agent.runs_websocket(WS));
}

#[test]
fn an_account_on_a_websocket_of_its_own_asks_for_the_connection_again() {
    let t0 = Instant::now();
    let mut agent = UserAgent::new(EndpointConfig::default(), [22; 32]).unwrap();
    let account = agent.add_account(
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1:40000"),
            TransportId(1),
            server(),
        )
        .on_stream(TransportProtocol::Ws),
    );
    let wanted = |events: &[UaEvent]| {
        events.iter().any(|event| {
            matches!(
                event,
                UaEvent::Unclaimed(Event::TransportWanted {
                    protocol: TransportProtocol::Ws,
                    destination,
                    ..
                }) if *destination == server()
            )
        })
    };
    agent.register(account, t0).unwrap();
    assert!(wanted(&events(&mut agent)), "asked for the connection");
    agent
        .receive(
            Input::TransportBound {
                transport: WS,
                protocol: TransportProtocol::Ws,
                local: local(),
                remote: Some(server()),
            },
            t0,
        )
        .unwrap();
    let out = written(&mut agent);
    feed(&mut agent, &accepted(&out[0]), t0);
    let out = written(&mut agent);
    let (_, register) = unmasked(&out[0]);
    assert!(register.starts_with(b"REGISTER "));
    let ok = reply(&register, 200, "OK", "");
    feed(&mut agent, &server_frame(1, &ok), t0);
    events(&mut agent);

    // the server goes away; the account asks for a connection again
    agent
        .receive(Input::StreamClosed { transport: WS }, t0)
        .unwrap();
    assert!(!agent.runs_websocket(WS));
    agent.handle_timeout(t0 + Duration::from_secs(1));
    assert!(wanted(&events(&mut agent)), "asked again");
}

/// The handshake an account of its own on a WebSocket opens with.
fn handshake_of(account: Account, target: Option<WebSocketTarget>) -> String {
    let t0 = Instant::now();
    let mut agent = UserAgent::new(EndpointConfig::default(), [23; 32]).unwrap();
    if let Some(target) = target {
        agent.set_websocket_target(server(), target);
    }
    agent.add_account(account.on_stream(TransportProtocol::Wss));
    agent
        .receive(
            Input::TransportBound {
                transport: WS,
                protocol: TransportProtocol::Wss,
                local: local(),
                remote: Some(server()),
            },
            t0,
        )
        .unwrap();
    let transmit = agent.poll_transmit().unwrap();
    String::from_utf8(transmit.payload.to_vec()).unwrap()
}

fn plain_account() -> Account {
    Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri("sip:alice@192.0.2.1:40000"),
        TransportId(1),
        server(),
    )
}

#[test]
fn an_account_names_the_resource_and_host_of_its_own_websocket() {
    let account = plain_account()
        .websocket_target(Some("sip.example.com"), Some("/sip?tenant=7"))
        .unwrap();
    let handshake = handshake_of(account, None);
    assert!(
        handshake.starts_with("GET /sip?tenant=7 HTTP/1.1\r\nHost: sip.example.com\r\n"),
        "{handshake}"
    );
}

#[test]
fn an_account_naming_only_the_resource_keeps_the_address_as_host() {
    let account = plain_account().websocket_target(None, Some("/")).unwrap();
    let handshake = handshake_of(account, None);
    assert!(
        handshake.starts_with("GET / HTTP/1.1\r\nHost: 192.0.2.9:8088\r\n"),
        "{handshake}"
    );
    let handshake = handshake_of(plain_account(), None);
    assert!(
        handshake.starts_with("GET /ws HTTP/1.1\r\nHost: 192.0.2.9:8088\r\n"),
        "{handshake}"
    );
}

#[test]
fn a_target_set_for_the_address_wins_over_the_account() {
    let account = plain_account()
        .websocket_target(None, Some("/account"))
        .unwrap();
    let target = WebSocketTarget::new("edge.example.com", "/edge").unwrap();
    let handshake = handshake_of(account, Some(target));
    assert!(handshake.starts_with("GET /edge HTTP/1.1\r\nHost: edge.example.com\r\n"));
}

#[test]
fn an_account_refuses_a_target_a_request_cannot_carry() {
    use crate::websocket::TargetError;
    assert_eq!(
        plain_account().websocket_target(None, Some("ws")).err(),
        Some(TargetError::Resource)
    );
    assert_eq!(
        plain_account().websocket_target(None, Some("/a#b")).err(),
        Some(TargetError::Resource)
    );
    assert_eq!(
        plain_account().websocket_target(Some("a/b"), None).err(),
        Some(TargetError::Host)
    );
    assert_eq!(
        plain_account().websocket_target(Some(""), None).err(),
        Some(TargetError::Host)
    );
}

#[test]
fn an_account_of_its_own_on_a_websocket_names_the_invalid_host_whatever_address_it_gave() {
    let t0 = Instant::now();
    let mut agent = UserAgent::new(EndpointConfig::default(), [24; 32]).unwrap();
    // the address of another socket, as a layer's default Contact names it
    let account = agent.add_account(
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1:5060;transport=ws"),
            TransportId(1),
            server(),
        )
        .on_stream(TransportProtocol::Ws),
    );
    agent
        .receive(
            Input::TransportBound {
                transport: WS,
                protocol: TransportProtocol::Ws,
                local: local(),
                remote: Some(server()),
            },
            t0,
        )
        .unwrap();
    agent.register(account, t0).unwrap();
    let out = written(&mut agent);
    feed(&mut agent, &accepted(&out[0]), t0);
    let out = written(&mut agent);
    let (_, register) = unmasked(&out[0]);
    let contact = String::from_utf8(header(&register, HeaderName::Contact)).unwrap();
    assert!(contact.contains(".invalid"), "{contact}");
    assert!(!contact.contains("192.0.2.1"), "{contact}");
}
