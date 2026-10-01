// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Whose challenge an account's password answers (RFC 3261 §22.1): its own
//! server's, for the account's realms, and nobody else's — not the far end of
//! a call, not a peer reached directly, not a proxy passing on a far end's own
//! 401 under a realm of its choosing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use sipral_core::msg::HeaderName;

use crate::event::ChallengeRefusal;
use crate::tests::{
    ANSWER, UDP, account, agent, answered, deliver, events, header, outgoing, reply, sent, text,
    transmits, uri,
};
use crate::{AccountId, CallEndReason, Credentials, RegistrationFailure, UaEvent, UserAgent};

/// A far end at an address of its own, not the account's server.
fn far_end() -> SocketAddr {
    "198.51.100.20:5060".parse().expect("an address")
}

/// A refusal of `request` carrying `field`, with the `To` tag a UAS puts on
/// it.
fn challenge(request: &[u8], status: u16, field: &str) -> Vec<u8> {
    let to = text(request, HeaderName::To);
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag=far")
    };
    let reason = if status == 401 {
        "Unauthorized"
    } else {
        "Proxy Authentication Required"
    };
    let mut out = format!("SIP/2.0 {status} {reason}\r\n").into_bytes();
    for (name, value) in [
        ("Via", header(request, HeaderName::Via)),
        ("From", header(request, HeaderName::From)),
        ("To", to.into_bytes()),
        ("Call-ID", header(request, HeaderName::CallId)),
        ("CSeq", header(request, HeaderName::CSeq)),
    ] {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(field.as_bytes());
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

/// A `WWW-Authenticate` for `realm`, with a nonce of the challenger's own.
fn www(realm: &str, nonce: &str) -> String {
    format!("WWW-Authenticate: Digest realm=\"{realm}\", nonce=\"{nonce}\", qop=\"auth\"\r\n")
}

fn proxy_auth(realm: &str) -> String {
    format!("Proxy-Authenticate: Digest realm=\"{realm}\", nonce=\"p-{realm}\", qop=\"auth\"\r\n")
}

fn with_password(agent: &mut UserAgent, realms: &[&str]) -> AccountId {
    let account = account().credentials(Credentials::new("alice", "open sesame"));
    let account = if realms.is_empty() {
        account
    } else {
        account.realms(realms)
    };
    agent.add_account(account)
}

fn declined(seen: &[UaEvent]) -> Option<(SocketAddr, Vec<Arc<str>>, ChallengeRefusal)> {
    seen.iter().find_map(|event| match event {
        UaEvent::ChallengeDeclined {
            from, realms, why, ..
        } => Some((*from, realms.clone(), *why)),
        _ => None,
    })
}

fn invites(out: &[Vec<u8>]) -> usize {
    out.iter()
        .filter(|bytes| bytes.starts_with(b"INVITE "))
        .count()
}

/// Register, the registrar challenging under `realm` and then granting.
fn registered_under(agent: &mut UserAgent, id: AccountId, realm: &str, now: Instant) {
    agent.register(id, now).expect("the REGISTER goes");
    let first = sent(agent);
    deliver(
        agent,
        &challenge(&first, 401, &www(realm, "registrar")),
        now,
    );
    let retry = sent(agent);
    assert!(
        !header(&retry, HeaderName::Authorization).is_empty(),
        "the registrar's own challenge is answered"
    );
    deliver(
        agent,
        &reply(
            &retry,
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n",
        ),
        now,
    );
    events(agent);
}

#[test]
fn a_far_end_reached_directly_gets_no_answer_whatever_realm_it_names() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = with_password(&mut agent, &[]);
    registered_under(&mut agent, id, "example.com", t0);

    let call = agent
        .call(id, &outgoing().to_address(UDP, far_end()), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    // the account's own realm, which a far end can name as easily as any
    deliver(
        &mut agent,
        &challenge(&invite, 401, &www("example.com", "far")),
        t0,
    );
    let out = transmits(&mut agent);
    assert_eq!(invites(&out), 0, "nothing answers it");
    let seen = events(&mut agent);
    let (from, realms, why) = declined(&seen).expect("the application is told why");
    assert_eq!(from, far_end());
    assert_eq!(realms, vec![Arc::from("example.com")]);
    assert_eq!(why, ChallengeRefusal::NotTheAccountsServer);
    let ended = seen.iter().find_map(|event| match event {
        UaEvent::CallEnded {
            call: ended,
            reason,
            status,
            ..
        } if *ended == call => Some((*reason, status.map(crate::StatusCode::get))),
        _ => None,
    });
    assert_eq!(ended, Some((CallEndReason::Refused, Some(401))));
    let at = |wanted: fn(&UaEvent) -> bool| seen.iter().position(wanted);
    assert!(
        at(|event| matches!(event, UaEvent::ChallengeDeclined { .. }))
            < at(|event| matches!(event, UaEvent::CallEnded { .. })),
        "the reason comes first"
    );

    // the same call through the account's own server is answered
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &challenge(&invite, 401, &www("example.com", "server")),
        t0,
    );
    let retry = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the retry");
    assert!(!header(&retry, HeaderName::Authorization).is_empty());
    assert!(declined(&events(&mut agent)).is_none());
}

#[test]
fn the_realm_the_server_first_challenged_with_is_the_only_one_answered() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = with_password(&mut agent, &[]);
    registered_under(&mut agent, id, "example.com", t0);

    // a proxy passing on somebody else's challenge, under their realm
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &challenge(&invite, 407, &proxy_auth("callee.example")),
        t0,
    );
    assert_eq!(invites(&transmits(&mut agent)), 0);
    let (from, realms, why) = declined(&events(&mut agent)).expect("declined");
    assert_eq!(from, crate::tests::registrar());
    assert_eq!(realms, vec![Arc::from("callee.example")]);
    assert_eq!(why, ChallengeRefusal::NotTheAccountsRealm);

    // the server's own realm, by its proxy, is answered
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &challenge(&invite, 407, &proxy_auth("example.com")),
        t0,
    );
    let retry = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the retry");
    assert!(!header(&retry, HeaderName::ProxyAuthorization).is_empty());
}

#[test]
fn a_realm_named_on_the_account_is_the_only_one_its_server_is_answered_for() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = with_password(&mut agent, &["pbx.example"]);
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    deliver(
        &mut agent,
        &challenge(&first, 401, &www("example.com", "registrar")),
        t0,
    );
    assert!(transmits(&mut agent).is_empty(), "no REGISTER goes again");
    let seen = events(&mut agent);
    let (_, _, why) = declined(&seen).expect("declined");
    assert_eq!(why, ChallengeRefusal::NotTheAccountsRealm);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            UaEvent::RegistrationFailed {
                reason: RegistrationFailure::BadCredentials,
                ..
            }
        )),
        "{seen:?}"
    );

    let mut named = crate::tests::agent(t0);
    let id = with_password(&mut named, &["pbx.example"]);
    registered_under(&mut named, id, "pbx.example", t0);
}

/// A call placed to a far end at its own address, and up: what is sent
/// inside it goes there.
fn up_with_far_end(agent: &mut UserAgent, id: AccountId, now: Instant) -> crate::CallHandle {
    let call = agent
        .call(id, &outgoing().to_address(UDP, far_end()), now)
        .expect("the INVITE goes");
    let invite = sent(agent);
    let ok = String::from_utf8(answered(&invite, 200, "OK", "far", Some(ANSWER)))
        .expect("text")
        .replace("<sip:bob@192.0.2.9>", "<sip:bob@198.51.100.20>");
    deliver(agent, ok.as_bytes(), now);
    let ack = sent(agent);
    assert!(ack.starts_with(b"ACK sip:bob@198.51.100.20"));
    events(agent);
    call
}

#[test]
fn a_far_end_challenging_a_reinvite_gets_no_answer_and_the_call_stays_up() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = with_password(&mut agent, &[]);
    registered_under(&mut agent, id, "example.com", t0);
    let call = up_with_far_end(&mut agent, id, t0);

    agent.hold(call, t0).expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
    assert!(reinvite.starts_with(b"INVITE sip:bob@198.51.100.20"));
    deliver(
        &mut agent,
        &challenge(&reinvite, 401, &www("example.com", "far")),
        t0,
    );
    let out = transmits(&mut agent);
    assert_eq!(invites(&out), 0, "the re-INVITE does not go again");
    let seen = events(&mut agent);
    let (from, _, why) = declined(&seen).expect("declined");
    assert_eq!(from, far_end());
    assert_eq!(why, ChallengeRefusal::NotTheAccountsServer);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            UaEvent::SessionChangeFailed { call: failed, status: Some(status), .. }
                if *failed == call && status.get() == 401
        )),
        "{seen:?}"
    );
    assert!(agent.call_state(call).is_some(), "the call is still up");

    // and a BYE it challenges is not answered either
    agent.hangup(call, t0).expect("the BYE goes");
    let bye = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"BYE "))
        .expect("the BYE");
    deliver(
        &mut agent,
        &challenge(&bye, 401, &www("example.com", "far-again")),
        t0,
    );
    assert!(
        !transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"BYE ")),
        "the BYE does not go again"
    );
    assert!(declined(&events(&mut agent)).is_some());
}

#[test]
fn a_declined_challenge_is_not_answered_ahead_of_the_next_request() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = with_password(&mut agent, &[]);
    registered_under(&mut agent, id, "example.com", t0);

    agent
        .call(id, &outgoing().to_address(UDP, far_end()), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &challenge(&invite, 401, &www("example.com", "far")),
        t0,
    );
    transmits(&mut agent);
    assert!(declined(&events(&mut agent)).is_some());

    // §22.2's answer ahead of a challenge, to the same destination: the
    // challenge declined above is not what it answers
    agent
        .message(id, uri("sip:bob@example.com"), b"text/plain", b"hello", t0)
        .expect("the MESSAGE goes");
    let message = sent(&mut agent);
    assert!(message.starts_with(b"MESSAGE "));
    assert!(
        header(&message, HeaderName::Authorization).is_empty(),
        "{}",
        String::from_utf8_lossy(&message)
    );
}
