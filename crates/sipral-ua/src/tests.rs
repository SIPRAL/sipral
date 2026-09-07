// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A registrar, scripted, on a fake clock.
//!
//! Everything a registration does happens over hours: a binding granted, a
//! refresh three quarters of the way through, an outage, a back-off that
//! doubles. None of it is worth waiting for, and none of it has to be — the
//! clock is a parameter, so a day of a phone's life runs in a few microseconds
//! and the interesting minute is the one the test picks.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, RawMessage, parse};

use crate::account::{Account, AccountId};
use crate::agent::UserAgent;
use crate::call::{CallEndReason, CallHandle, CallState, ForkPolicy, OutgoingCall};
use crate::event::{RegistrationFailure, RegistrationState, UaEvent};
use crate::{
    Credentials, EndpointConfig, Input, StatusCode, TransportId, TransportProtocol, UaError, Uri,
};

const UDP: TransportId = TransportId(1);
const HOUR: Duration = Duration::from_hours(1);

fn local() -> SocketAddr {
    "192.0.2.1:5060".parse().expect("a local address")
}

fn registrar() -> SocketAddr {
    "192.0.2.9:5060".parse().expect("the registrar's address")
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

/// A user agent with one UDP transport bound.
fn agent(now: Instant) -> UserAgent {
    let mut agent = UserAgent::new(EndpointConfig::default(), [11; 32]);
    agent
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            now,
        )
        .expect("binding a transport");
    agent
}

fn account() -> Account {
    Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri("sip:alice@192.0.2.1"),
        UDP,
        registrar(),
    )
}

/// Everything the agent wants written, drained.
fn transmits(agent: &mut UserAgent) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(transmit) = agent.poll_transmit() {
        out.push(transmit.payload.to_vec());
    }
    out
}

/// The one message the agent wanted written.
fn sent(agent: &mut UserAgent) -> Vec<u8> {
    let mut all = transmits(agent);
    assert_eq!(all.len(), 1, "expected exactly one message out");
    all.pop().unwrap_or_default()
}

fn events(agent: &mut UserAgent) -> Vec<UaEvent> {
    let mut out = Vec::new();
    while let Some(event) = agent.poll_event() {
        out.push(event);
    }
    out
}

fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
    let mut scratch = ParseScratch::new();
    f(&parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message"))
}

fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
    with(bytes, |message| {
        message.header(name).unwrap_or_default().to_vec()
    })
}

/// A response to a request the agent wrote, echoing what §8.2.6.2 requires.
fn reply(request: &[u8], status: u16, reason: &str, extra: &str) -> Vec<u8> {
    let mut out = format!("SIP/2.0 {status} {reason}\r\n").into_bytes();
    for (name, value) in [
        ("Via", header(request, HeaderName::Via)),
        ("From", header(request, HeaderName::From)),
        ("To", header(request, HeaderName::To)),
        ("Call-ID", header(request, HeaderName::CallId)),
        ("CSeq", header(request, HeaderName::CSeq)),
    ] {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(extra.as_bytes());
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

/// The 200 a registrar sends: the binding it kept, and for how long.
fn granted(request: &[u8], seconds: u32) -> Vec<u8> {
    reply(
        request,
        200,
        "OK",
        &format!("Contact: <sip:alice@192.0.2.1>;expires={seconds}\r\n"),
    )
}

fn deliver(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
    agent
        .receive(
            Input::Datagram {
                transport: UDP,
                remote: registrar(),
                local: local(),
                data: bytes,
            },
            now,
        )
        .expect("a well formed datagram");
}

/// Register and take the 200, leaving the binding live.
fn registered(agent: &mut UserAgent, account: AccountId, seconds: u32, now: Instant) {
    agent.register(account, now).expect("the REGISTER goes");
    let request = sent(agent);
    deliver(agent, &granted(&request, seconds), now);
    events(agent);
}

// -- what goes out -----------------------------------------------------------

#[test]
fn a_register_carries_the_address_of_record_in_both_directions() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().display_name("Alice"));
    agent.register(id, t0).expect("the REGISTER goes");

    let bytes = sent(&mut agent);
    assert!(
        bytes.starts_with(b"REGISTER sip:example.com SIP/2.0\r\n"),
        "10.2: the Request-URI names the registrar, with no user part"
    );
    assert_eq!(header(&bytes, HeaderName::To), b"<sip:alice@example.com>");
    let from = header(&bytes, HeaderName::From);
    let from = String::from_utf8_lossy(&from);
    assert!(
        from.starts_with("\"Alice\" <sip:alice@example.com>"),
        "{from}"
    );
    assert!(from.contains(";tag="), "8.1.1.3 wants a From tag: {from}");
    assert_eq!(
        header(&bytes, HeaderName::Contact),
        b"<sip:alice@192.0.2.1>"
    );
    assert_eq!(header(&bytes, HeaderName::Expires), b"3600");
    assert_eq!(header(&bytes, HeaderName::CSeq), b"1 REGISTER");
}

#[test]
fn every_registration_of_one_boot_cycle_shares_a_call_id_and_moves_the_number() {
    // 10.2.4: "A UA SHOULD use the same Call-ID for all registrations during a
    // single boot cycle", and the number grows so a refresh is not a replay
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the first REGISTER");
    let first = sent(&mut agent);
    deliver(&mut agent, &granted(&first, 3_600), t0);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = sent(&mut agent);

    assert_eq!(
        header(&first, HeaderName::CallId),
        header(&refresh, HeaderName::CallId)
    );
    assert_eq!(header(&refresh, HeaderName::CSeq), b"2 REGISTER");
}

#[test]
fn two_accounts_share_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let work = agent.add_account(account());
    let home = agent.add_account(account());
    agent.register(work, t0).expect("the first REGISTER");
    agent.register(home, t0).expect("the second REGISTER");

    let all = transmits(&mut agent);
    assert_eq!(all.len(), 2);
    assert_ne!(
        header(&all[0], HeaderName::CallId),
        header(&all[1], HeaderName::CallId)
    );
    assert_ne!(work, home);
}

#[test]
fn an_instance_id_rides_on_the_contact_and_nothing_else_does() {
    // RFC 5626 4.1's +sip.instance, without the reg-id that would claim
    // Outbound support this stack does not have
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id =
        agent.add_account(account().instance_id("urn:uuid:f81d4fae-7ced-11d0-a765-00a0c91e6bf6"));
    agent.register(id, t0).expect("the REGISTER goes");

    let contact = header(&sent(&mut agent), HeaderName::Contact);
    let contact = String::from_utf8_lossy(&contact);
    assert_eq!(
        contact,
        "<sip:alice@192.0.2.1>;+sip.instance=\"urn:uuid:f81d4fae-7ced-11d0-a765-00a0c91e6bf6\""
    );
    assert!(!contact.contains("reg-id"), "outbound is not claimed here");
}

#[test]
fn a_request_for_an_account_that_is_gone_names_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.remove_account(id);
    assert_eq!(agent.register(id, t0), Err(UaError::NoSuchAccount));
    assert!(transmits(&mut agent).is_empty());
}

// -- what the registrar grants -----------------------------------------------

#[test]
fn the_granted_expiry_wins_over_the_one_asked_for() {
    // 10.2.4: the UA "updates the expiration time interval according to the
    // expires parameter" the registrar echoed back
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().expires(HOUR));
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    assert_eq!(header(&request, HeaderName::Expires), b"3600");

    deliver(&mut agent, &granted(&request, 120), t0);
    let bound = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::Registered {
                expires,
                refresh_in,
                ..
            } => Some((expires, refresh_in)),
            _ => None,
        })
        .expect("the binding is live");
    assert_eq!(bound.0, Duration::from_secs(120));
    assert_eq!(
        bound.1,
        Duration::from_secs(90),
        "two minutes granted refreshes thirty seconds before it lapses"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
}

#[test]
fn a_contact_the_registrar_rewrote_does_not_read_as_a_removal() {
    // a registrar behind a NAT echoes an address that is not the one we sent,
    // and concluding "refused" from that would drop a working registration
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(
            &request,
            200,
            "OK",
            "Contact: <sip:alice@198.51.100.4:41234>;expires=600\r\nExpires: 600\r\n",
        ),
        t0,
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Registered { expires, .. } if expires == Duration::from_secs(600))),
        "the Expires header is the fallback when our contact is not recognisable"
    );
}

#[test]
fn a_binding_granted_for_nothing_is_not_a_binding() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    deliver(&mut agent, &granted(&request, 0), t0);

    assert!(events(&mut agent).iter().any(|event| matches!(
        *event,
        UaEvent::RegistrationFailed {
            reason: RegistrationFailure::Rejected,
            ..
        }
    )));
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Failed)
    );
}

#[test]
fn the_refresh_goes_by_itself_and_says_so() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    registered(&mut agent, id, 3_600, t0);
    agent.handle_timeout(t0 + Duration::from_secs(3_059));
    assert!(
        transmits(&mut agent).is_empty(),
        "0.85 of the granted hour, and not a second sooner"
    );

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    assert!(
        sent(&mut agent).starts_with(b"REGISTER "),
        "the refresh went without being asked for"
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Refreshing { .. }))
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Refreshing),
        "the binding stands until the refresh is answered"
    );
}

// -- credentials -------------------------------------------------------------

#[test]
fn a_challenge_is_answered_from_the_account_without_asking() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "open sesame")));
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    assert!(header(&first, HeaderName::Authorization).is_empty());

    deliver(
        &mut agent,
        &reply(
            &first,
            401,
            "Unauthorized",
            "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", qop=\"auth\"\r\n",
        ),
        t0,
    );
    let retry = sent(&mut agent);
    let credentials = header(&retry, HeaderName::Authorization);
    let credentials = String::from_utf8_lossy(&credentials);
    assert!(credentials.starts_with("Digest "), "{credentials}");
    assert!(credentials.contains("username=\"alice\""), "{credentials}");
    assert!(credentials.contains("nonce=\"abc123\""), "{credentials}");
    assert!(
        !credentials.contains("open sesame"),
        "the password does not travel: {credentials}"
    );
    assert_eq!(header(&retry, HeaderName::CSeq), b"2 REGISTER");

    deliver(&mut agent, &granted(&retry, 3_600), t0);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Registered { .. }))
    );
}

#[test]
fn a_password_that_is_refused_twice_stops_rather_than_locking_the_account() {
    // 22.1: the same nonce coming back without `stale` means the password was
    // wrong. Sending it again is how an account gets locked out
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "wrong")));
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    let refusal =
        "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", qop=\"auth\"\r\n";

    deliver(&mut agent, &reply(&first, 401, "Unauthorized", refusal), t0);
    let retry = sent(&mut agent);
    events(&mut agent);

    deliver(&mut agent, &reply(&retry, 401, "Unauthorized", refusal), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "nothing goes out a third time"
    );
    let failed = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::RegistrationFailed {
                reason, retry_in, ..
            } => Some((reason, retry_in)),
            _ => None,
        })
        .expect("the refusal is reported");
    assert_eq!(failed.0, RegistrationFailure::BadCredentials);
    assert_eq!(failed.1, None, "no retry: it would be refused the same way");
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Failed)
    );
}

#[test]
fn a_challenge_with_no_password_to_answer_it_stops_there() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);

    deliver(
        &mut agent,
        &reply(
            &first,
            401,
            "Unauthorized",
            "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", qop=\"auth\"\r\n",
        ),
        t0,
    );
    assert!(transmits(&mut agent).is_empty());
    assert!(events(&mut agent).iter().any(|event| matches!(
        *event,
        UaEvent::RegistrationFailed {
            reason: RegistrationFailure::BadCredentials,
            ..
        }
    )));
}

// -- when it goes wrong ------------------------------------------------------

#[test]
fn a_refusal_that_will_be_refused_again_stops_and_says_what_it_was() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    deliver(&mut agent, &reply(&request, 403, "Forbidden", ""), t0);

    let failed = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::RegistrationFailed {
                reason,
                status,
                retry_in,
                response,
                ..
            } => Some((reason, status, retry_in, response)),
            _ => None,
        })
        .expect("the refusal is reported");
    assert_eq!(failed.0, RegistrationFailure::Rejected);
    assert_eq!(failed.1.map(sipral_core::msg::StatusCode::get), Some(403));
    assert_eq!(failed.2, None);
    assert!(failed.3.is_some(), "the refusal rides whole");
    assert!(
        failed
            .0
            .hint()
            .is_some_and(|hint| hint.contains("max_contacts")),
        "the server setting that causes this is worth naming"
    );

    agent.handle_timeout(t0 + HOUR);
    assert!(
        transmits(&mut agent).is_empty(),
        "nothing is scheduled, however long we wait"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Failed)
    );
}

#[test]
fn a_registrar_that_is_not_answering_is_tried_again_later() {
    // 10.2.7: "the UAC SHOULD NOT immediately re-attempt a registration to the
    // same registrar" after a timeout
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the REGISTER goes");
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(32));
    // timer E retransmitted the REGISTER all through those thirty-two seconds
    transmits(&mut agent);
    let failed = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::RegistrationFailed {
                reason, retry_in, ..
            } => Some((reason, retry_in)),
            _ => None,
        })
        .expect("timer F fired");
    assert_eq!(failed.0, RegistrationFailure::Unreachable);
    let wait = failed.1.expect("a retry is scheduled");
    assert!(
        wait >= Duration::from_secs(30) && wait <= Duration::from_secs(60),
        "RFC 5626 4.5's first retry lands between 30 and 60 seconds: {wait:?}"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Retrying)
    );

    agent.handle_timeout(t0 + Duration::from_secs(32) + wait);
    assert!(
        sent(&mut agent).starts_with(b"REGISTER "),
        "and it goes by itself"
    );
}

#[test]
fn a_retry_after_can_push_the_wait_out_but_not_pull_it_in() {
    // RFC 5626 4.5: "a 503 response ... with a Retry-After header field value
    // may cause the UA to wait longer"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(&request, 503, "Service Unavailable", "Retry-After: 600\r\n"),
        t0,
    );

    let wait = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::RegistrationFailed { retry_in, .. } => retry_in,
            _ => None,
        })
        .expect("a retry is scheduled");
    assert_eq!(wait, Duration::from_secs(600));
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Retrying)
    );

    agent.handle_timeout(t0 + wait.saturating_sub(Duration::from_secs(1)));
    assert!(transmits(&mut agent).is_empty(), "not before it is due");
    agent.handle_timeout(t0 + wait);
    assert!(sent(&mut agent).starts_with(b"REGISTER "));
}

#[test]
fn the_backoff_doubles_across_consecutive_failures() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let mut at = t0;
    let mut waits = Vec::new();

    for _ in 0..4 {
        agent.register(id, at).expect("the REGISTER goes");
        let request = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(&request, 500, "Server Internal Error", ""),
            at,
        );
        let wait = events(&mut agent)
            .into_iter()
            .find_map(|event| match event {
                UaEvent::RegistrationFailed { retry_in, .. } => retry_in,
                _ => None,
            })
            .expect("a retry is scheduled");
        waits.push(wait);
        at += wait;
    }

    // W = min(1800, 30 * 2^n), and the wait is drawn from the top half of it
    for (n, wait) in waits.iter().enumerate() {
        let bound = Duration::from_secs(30 * (1 << (n + 1)));
        assert!(*wait <= bound, "attempt {n}: {wait:?} above {bound:?}");
        assert!(*wait >= bound / 2, "attempt {n}: {wait:?} below half");
    }
}

#[test]
fn a_success_forgets_the_failures_that_came_before_it() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(&request, 500, "Server Internal Error", ""),
        t0,
    );
    events(&mut agent);

    registered(&mut agent, id, 3_600, t0 + Duration::from_secs(60));
    agent.handle_timeout(t0 + Duration::from_secs(60) + Duration::from_secs(3_060));
    let refresh = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(&refresh, 500, "Server Internal Error", ""),
        t0 + Duration::from_secs(3_120),
    );
    let wait = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::RegistrationFailed { retry_in, .. } => retry_in,
            _ => None,
        })
        .expect("a retry is scheduled");
    assert!(
        wait <= Duration::from_secs(60),
        "the counter went back to zero: {wait:?}"
    );
}

#[test]
fn a_registrar_that_demands_a_longer_binding_gets_one() {
    // 10.2.8: retry "after making the expiration interval ... equal to or
    // greater than the ... Min-Expires header field"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().expires(Duration::from_secs(60)));
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    assert_eq!(header(&first, HeaderName::Expires), b"60");

    deliver(
        &mut agent,
        &reply(&first, 423, "Interval Too Brief", "Min-Expires: 3600\r\n"),
        t0,
    );
    let second = sent(&mut agent);
    assert_eq!(header(&second, HeaderName::Expires), b"3600");
    assert_eq!(header(&second, HeaderName::CSeq), b"2 REGISTER");

    deliver(&mut agent, &granted(&second, 3_600), t0);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Registered { .. }))
    );
    let _ = id;
}

#[test]
fn a_second_423_is_the_registrar_contradicting_itself() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().expires(Duration::from_secs(60)));
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(&first, 423, "Interval Too Brief", "Min-Expires: 3600\r\n"),
        t0,
    );
    let second = sent(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &reply(&second, 423, "Interval Too Brief", "Min-Expires: 7200\r\n"),
        t0,
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "asking a third time would loop"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Failed)
    );
}

#[test]
fn a_registrar_that_moved_is_reported_rather_than_chased() {
    // following a 3xx needs an address, and resolving one is the caller's
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(
            &request,
            301,
            "Moved Permanently",
            "Contact: <sip:registrar.example.net>\r\n",
        ),
        t0,
    );

    let response = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::RegistrationFailed {
                reason: RegistrationFailure::Redirected,
                response,
                ..
            } => response,
            _ => None,
        })
        .expect("the redirect is reported");
    assert_eq!(
        response.as_raw().header(HeaderName::Contact),
        Some(&b"<sip:registrar.example.net>"[..]),
        "with the address to try instead"
    );
    assert!(transmits(&mut agent).is_empty());
}

// -- giving it up ------------------------------------------------------------

#[test]
fn unregistering_removes_this_binding_and_not_everybody_elses() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    registered(&mut agent, id, 3_600, t0);

    agent.unregister(id, t0).expect("the de-registration goes");
    let bytes = sent(&mut agent);
    assert_eq!(header(&bytes, HeaderName::Expires), b"0");
    assert_eq!(
        header(&bytes, HeaderName::Contact),
        b"<sip:alice@192.0.2.1>",
        "our own binding, not the star that would remove every one"
    );

    deliver(&mut agent, &reply(&bytes, 200, "OK", ""), t0);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Unregistered { .. }))
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Unregistered)
    );

    agent.handle_timeout(t0 + HOUR);
    assert!(
        transmits(&mut agent).is_empty(),
        "the refresh that was scheduled is gone with the binding"
    );
}

// -- what this layer does not claim ------------------------------------------

#[test]
fn a_request_this_layer_has_no_policy_for_is_passed_through_whole() {
    // an INFO inside a call: nothing here has an opinion about it, so it
    // reaches the application as the core wrote it rather than being dropped
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("in1", Some(OFFER)), t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "in1ack", 1), t0);
    events(&mut agent);

    deliver(&mut agent, &in_dialog(&ok, "INFO", "in1info", 2), t0);
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::Unclaimed(sipral_core::endpoint::Event::IncomingInDialog { .. })
        )),
        "nothing is dropped on the way through"
    );
}

#[test]
fn the_plumbing_of_a_registration_does_not_reach_the_application() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    registered(&mut agent, id, 3_600, t0);

    // the REGISTER transaction ends on timer K, and that is not news
    agent.handle_timeout(t0 + Duration::from_secs(5));
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::Unclaimed(_))),
        "a transaction ending is this layer's business"
    );
}

// -- calls -------------------------------------------------------------------

const OFFER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
const ANSWER: &[u8] = b"v=0\r\no=- 2 2 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";

fn outgoing() -> OutgoingCall {
    OutgoingCall::new(uri("sip:bob@example.com")).offer(Arc::from(OFFER))
}

/// A response to a request the agent wrote, with a `To` tag that names a
/// dialog and a body when there is one.
fn answered(request: &[u8], status: u16, reason: &str, tag: &str, body: Option<&[u8]>) -> Vec<u8> {
    let to = String::from_utf8_lossy(&header(request, HeaderName::To)).into_owned();
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag={tag}")
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
    out.extend_from_slice(b"Contact: <sip:bob@192.0.2.9>\r\n");
    match body {
        Some(sdp) => {
            out.extend_from_slice(b"Content-Type: application/sdp\r\n");
            out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", sdp.len()).as_bytes());
            out.extend_from_slice(sdp);
        }
        None => out.extend_from_slice(b"Content-Length: 0\r\n\r\n"),
    }
    out
}

/// An INVITE arriving from the far end.
fn incoming_invite(branch: &str, body: Option<&[u8]>) -> Vec<u8> {
    let mut out = format!(
        "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@example.com>\r\n\
Call-ID: incoming-{branch}\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.0.2.9>\r\n"
    )
    .into_bytes();
    match body {
        Some(sdp) => {
            out.extend_from_slice(b"Content-Type: application/sdp\r\n");
            out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", sdp.len()).as_bytes());
            out.extend_from_slice(sdp);
        }
        None => out.extend_from_slice(b"Content-Length: 0\r\n\r\n"),
    }
    out
}

/// A request from the far end inside a dialog we answered, mirroring the
/// tags of the 200 we sent.
fn in_dialog(ours: &[u8], method: &str, branch: &str, cseq: u32) -> Vec<u8> {
    let from = String::from_utf8_lossy(&header(ours, HeaderName::From)).into_owned();
    let to = String::from_utf8_lossy(&header(ours, HeaderName::To)).into_owned();
    let call_id = String::from_utf8_lossy(&header(ours, HeaderName::CallId)).into_owned();
    format!(
        "{method} sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: {from}\r\n\
To: {to}\r\n\
Call-ID: {call_id}\r\n\
CSeq: {cseq} {method}\r\n\
Content-Length: 0\r\n\
\r\n"
    )
    .into_bytes()
}

fn ended(agent: &mut UserAgent) -> Option<(CallHandle, CallEndReason)> {
    events(agent).into_iter().find_map(|event| match event {
        UaEvent::CallEnded { call, reason, .. } => Some((call, reason)),
        _ => None,
    })
}

/// Place a call, take the 200, and be up.
fn call_up(agent: &mut UserAgent, account: AccountId, now: Instant) -> (CallHandle, Vec<u8>) {
    let call = agent
        .call(account, &outgoing(), now)
        .expect("the INVITE goes");
    let invite = sent(agent);
    deliver(
        agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        now,
    );
    let ack = sent(agent);
    events(agent);
    (call, ack)
}

#[test]
fn an_invite_carries_the_account_identity_and_the_offer() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().display_name("Alice"));
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");

    let bytes = sent(&mut agent);
    assert!(bytes.starts_with(b"INVITE sip:bob@example.com SIP/2.0\r\n"));
    assert_eq!(header(&bytes, HeaderName::To), b"<sip:bob@example.com>");
    assert!(
        String::from_utf8_lossy(&header(&bytes, HeaderName::From))
            .starts_with("\"Alice\" <sip:alice@example.com>")
    );
    // 8.1.1.8: a request that can establish a dialog carries a Contact
    assert_eq!(
        header(&bytes, HeaderName::Contact),
        b"<sip:alice@192.0.2.1>"
    );
    assert!(bytes.ends_with(OFFER));
}

#[test]
fn a_call_rings_then_connects_and_is_acknowledged_without_being_asked() {
    // 13.2.2.4 leaves the ACK to the layer above; a 2xx nobody acknowledges is
    // retransmitted for 32 seconds and then hung up at the far end
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);

    deliver(
        &mut agent,
        &answered(&invite, 180, "Ringing", "desk", None),
        t0,
    );
    let progress = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallProgress { state, status, .. } => Some((state, status)),
            _ => None,
        })
        .expect("the far end is ringing");
    assert_eq!(progress, (CallState::Ringing, StatusCode::RINGING));
    assert_eq!(agent.call_state(call), Some(CallState::Ringing));

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let ack = sent(&mut agent);
    assert!(ack.starts_with(b"ACK sip:bob@192.0.2.9 SIP/2.0\r\n"));
    assert_eq!(header(&ack, HeaderName::CSeq), b"1 ACK");

    let confirmed = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallConfirmed {
                call,
                answer_wanted,
                response,
            } => Some((call, answer_wanted, response)),
            _ => None,
        })
        .expect("the call is up");
    assert_eq!(confirmed.0, call);
    assert!(!confirmed.1, "we offered, so the ACK needed nothing");
    assert_eq!(
        confirmed.2.map(|r| r.as_raw().body().to_vec()),
        Some(ANSWER.to_vec()),
        "the answer is in the 2xx, whole"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_progress_response_with_a_body_is_early_media() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 183, "Session Progress", "desk", Some(ANSWER)),
        t0,
    );
    assert_eq!(agent.call_state(call), Some(CallState::EarlyMedia));
}

#[test]
fn a_call_placed_without_an_offer_waits_for_the_answer_before_it_acknowledges() {
    // 14.1: "a UAC MAY send a re-INVITE with no session description, in which
    // case the first reliable non-failure response will contain the offer"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent
        .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert!(invite.ends_with(b"Content-Length: 0\r\n\r\n"));

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(OFFER)),
        t0,
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "nothing to acknowledge with yet"
    );
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::CallConfirmed {
                answer_wanted: true,
                ..
            }
        )),
        "the application is asked for one"
    );

    agent
        .acknowledge(call, Some(ANSWER), t0)
        .expect("the ACK goes");
    let ack = sent(&mut agent);
    assert!(ack.ends_with(ANSWER), "the answer travels in the ACK");
    assert_eq!(
        agent.acknowledge(call, Some(ANSWER), t0),
        Err(UaError::WrongState(CallState::Confirmed)),
        "and only once"
    );
}

#[test]
fn a_refused_call_says_what_it_was_refused_with() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 486, "Busy Here", "desk", None),
        t0,
    );

    let end = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallEnded {
                call,
                reason,
                status,
                response,
            } => Some((call, reason, status, response.is_some())),
            _ => None,
        })
        .expect("the call was refused");
    assert_eq!(
        end,
        (
            call,
            CallEndReason::Refused,
            StatusCode::new(486).ok(),
            true
        )
    );
    assert_eq!(agent.call_state(call), None, "the handle is stale");
}

#[test]
fn hanging_up_before_the_answer_is_a_cancel_and_after_it_is_a_bye() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());

    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    // 9.1: a CANCEL may not go before a provisional response, and the endpoint
    // holds it until one arrives
    agent.hangup(call, t0).expect("the hangup is taken");
    assert!(transmits(&mut agent).is_empty());
    deliver(
        &mut agent,
        &answered(&invite, 180, "Ringing", "desk", None),
        t0,
    );
    let cancel = sent(&mut agent);
    assert!(cancel.starts_with(b"CANCEL sip:bob@example.com SIP/2.0\r\n"));
    deliver(
        &mut agent,
        &answered(&invite, 487, "Request Terminated", "desk", None),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::Cancelled)
    );

    let (call, _) = call_up(&mut agent, id, t0);
    agent.hangup(call, t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    assert!(bye.starts_with(b"BYE sip:bob@192.0.2.9 SIP/2.0\r\n"));
    assert_eq!(header(&bye, HeaderName::CSeq), b"2 BYE");
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::LocalHangup)
    );
}

#[test]
fn the_answer_to_our_bye_is_not_news() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);
    agent.hangup(call, t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    events(&mut agent);

    deliver(&mut agent, &reply(&bye, 200, "OK", ""), t0);
    assert!(
        events(&mut agent).is_empty(),
        "the call ended when the BYE went, not when it was answered"
    );
}

#[test]
fn a_cancel_that_lost_its_race_leaves_a_call_that_is_hung_up() {
    // the 200 crossed the CANCEL. 13.2.2.4 still wants the ACK, and only then
    // can the call be ended
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 180, "Ringing", "desk", None),
        t0,
    );
    events(&mut agent);
    agent.hangup(call, t0).expect("the CANCEL goes");
    transmits(&mut agent);

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(
        out.iter().any(|bytes| bytes.starts_with(b"ACK ")),
        "the 2xx is acknowledged whether or not it was wanted"
    );
    assert!(out.iter().any(|bytes| bytes.starts_with(b"BYE ")));
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::LocalHangup)
    );
}

// -- forks -------------------------------------------------------------------

#[test]
fn a_fork_becomes_two_calls_and_the_second_answer_is_still_acknowledged() {
    // 13.2.2.4 does not make the ACK conditional on wanting the call
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);

    deliver(
        &mut agent,
        &answered(&invite, 180, "Ringing", "desk", None),
        t0,
    );
    deliver(
        &mut agent,
        &answered(&invite, 180, "Ringing", "mobile", None),
        t0,
    );
    let sibling = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallForked { call, sibling } => Some((call, sibling)),
            _ => None,
        })
        .expect("a proxy forked it");
    assert_eq!(sibling.0, call);
    assert_ne!(sibling.1, call);

    // the desk answers first and is kept
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));

    // and then the mobile answers too
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "mobile", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(
        out.iter().any(|bytes| bytes.starts_with(b"ACK ")),
        "the branch that lost is acknowledged"
    );
    assert!(
        out.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "and then hung up"
    );
    assert_eq!(
        agent.call_state(call),
        Some(CallState::Confirmed),
        "the one that was kept is untouched"
    );
}

#[test]
fn keeping_every_branch_hangs_none_of_them_up() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent
        .call(id, &outgoing().forks(ForkPolicy::KeepAll), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "mobile", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(out.iter().any(|bytes| bytes.starts_with(b"ACK ")));
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "both legs are wanted"
    );
    let confirmed: Vec<_> = events(&mut agent)
        .into_iter()
        .filter_map(|event| match event {
            UaEvent::CallConfirmed { call, .. } => Some(call),
            _ => None,
        })
        .collect();
    assert_eq!(confirmed.len(), 1);
    assert_ne!(confirmed.first().copied(), Some(call));
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

// -- calls that come in ------------------------------------------------------

#[test]
fn a_call_that_comes_in_is_matched_to_the_line_it_was_addressed_to() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    deliver(&mut agent, &incoming_invite("in1", Some(OFFER)), t0);
    transmits(&mut agent);

    let incoming = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall {
                call,
                account,
                request,
            } => Some((call, account, request)),
            _ => None,
        })
        .expect("somebody is calling");
    assert_eq!(incoming.1, Some(id), "the To names the account");
    assert_eq!(incoming.2.as_raw().body(), OFFER);
    assert_eq!(agent.call_state(incoming.0), Some(CallState::Incoming));
}

#[test]
fn ringing_then_answering_puts_the_call_up_when_the_ack_arrives() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("in1", Some(OFFER)), t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");

    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);
    assert!(ringing.starts_with(b"SIP/2.0 180 Ringing\r\n"));
    assert_eq!(agent.call_state(call), Some(CallState::Ringing));

    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    assert!(ok.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert_eq!(header(&ok, HeaderName::Contact), b"<sip:alice@192.0.2.1>");
    assert!(ok.ends_with(ANSWER));
    assert_ne!(
        agent.call_state(call),
        Some(CallState::Confirmed),
        "the 2xx is still being retransmitted until the ACK arrives"
    );

    deliver(&mut agent, &in_dialog(&ok, "ACK", "in1ack", 1), t0);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::CallConfirmed { .. }))
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn the_far_end_hanging_up_is_answered_without_being_asked() {
    // 15.1.2: the dialog is over the moment the BYE arrives, and answering it
    // 200 is the only thing left to do
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("in1", Some(OFFER)), t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "in1ack", 1), t0);
    events(&mut agent);

    deliver(&mut agent, &in_dialog(&ok, "BYE", "in1bye", 2), t0);
    let answer = sent(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert_eq!(ended(&mut agent), Some((call, CallEndReason::RemoteHangup)));
}

#[test]
fn refusing_a_call_says_so_with_the_status_that_was_chosen() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("in1", Some(OFFER)), t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");

    agent
        .reject(call, StatusCode::new(603).expect("a status"), t0)
        .expect("the refusal goes");
    assert!(sent(&mut agent).starts_with(b"SIP/2.0 603 Decline\r\n"));
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::LocalHangup)
    );
}

#[test]
fn hanging_up_a_call_that_has_not_been_answered_refuses_it() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("in1", None), t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");

    agent.hangup(call, t0).expect("it is refused");
    assert!(sent(&mut agent).starts_with(b"SIP/2.0 486 Busy Here\r\n"));
}

#[test]
fn a_caller_that_gives_up_stops_the_ringing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("in1", None), t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");
    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);

    let cancel = String::from(
        "CANCEL sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKin1;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@example.com>\r\n\
Call-ID: incoming-in1\r\n\
CSeq: 1 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n",
    )
    .into_bytes();
    deliver(&mut agent, &cancel, t0);

    let out = transmits(&mut agent);
    assert!(
        out.iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 200 OK\r\n")),
        "9.2 answers the CANCEL unconditionally"
    );
    assert!(
        out.iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 487 Request Terminated\r\n")),
        "and the INVITE too"
    );
    assert_eq!(ended(&mut agent), Some((call, CallEndReason::Cancelled)));
    let _ = ringing;
}

#[test]
fn a_call_and_a_registration_do_not_confuse_each_other() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    registered(&mut agent, id, 3_600, t0);
    let (call, _) = call_up(&mut agent, id, t0);
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    assert!(
        sent(&mut agent).starts_with(b"REGISTER "),
        "the refresh is not disturbed by a call being up"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}
