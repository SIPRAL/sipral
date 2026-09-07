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
use std::time::{Duration, Instant};

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, RawMessage, parse};

use crate::account::{Account, AccountId};
use crate::agent::UserAgent;
use crate::event::{RegistrationFailure, RegistrationState, UaEvent};
use crate::{Credentials, EndpointConfig, Input, TransportId, TransportProtocol, UaError, Uri};

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
fn a_call_arriving_is_passed_through_whole() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let invite = b"INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKin1;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>\r\n\
Call-ID: incoming-1\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.0.2.9>\r\n\
Content-Length: 0\r\n\
\r\n";
    deliver(&mut agent, invite, t0);

    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::Unclaimed(sipral_core::endpoint::Event::IncomingInvite { .. })
        )),
        "calls are the core's until the stage that owns them is written"
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
