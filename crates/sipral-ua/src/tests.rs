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
use crate::session::Hold;
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

fn text(bytes: &[u8], name: HeaderName<'_>) -> String {
    String::from_utf8_lossy(&header(bytes, name)).into_owned()
}

/// A request the far end sends inside a dialog.
fn peer_request(
    from: &str,
    to: &str,
    call_id: &str,
    method: &str,
    branch: &str,
    cseq: u32,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = format!(
        "{method} sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: {from}\r\n\
To: {to}\r\n\
Call-ID: {call_id}\r\n\
CSeq: {cseq} {method}\r\n\
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
    peer_request(
        &text(ours, HeaderName::From),
        &text(ours, HeaderName::To),
        &text(ours, HeaderName::CallId),
        method,
        branch,
        cseq,
        None,
    )
}

/// And one inside a dialog this end opened, where From and To are the other
/// way round because they are written by whoever sends.
fn reversed(ours: &[u8], method: &str, branch: &str, cseq: u32, body: Option<&[u8]>) -> Vec<u8> {
    peer_request(
        &text(ours, HeaderName::To),
        &text(ours, HeaderName::From),
        &text(ours, HeaderName::CallId),
        method,
        branch,
        cseq,
        body,
    )
}

fn body_of(bytes: &[u8]) -> String {
    with(bytes, |message| {
        String::from_utf8_lossy(message.body()).into_owned()
    })
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

    // the call's own session timer is due by now too, so both go out
    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let written = transmits(&mut agent);
    assert!(
        written.iter().any(|bytes| bytes.starts_with(b"REGISTER ")),
        "the refresh is not disturbed by a call being up: {}",
        written.len()
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

// -- hold, resume, and the offers that follow --------------------------------

/// What the far end sends when it puts us on hold (RFC 3264 §8.4).
const THEIR_HOLD: &[u8] = b"v=0\r\no=- 2 3 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\na=sendonly\r\n";
/// The same thing the way RFC 2543 did it, which §8.4 still requires everyone
/// to understand.
const THEIR_OLD_HOLD: &[u8] = b"v=0\r\no=- 2 3 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";
/// Their answer to a hold of ours: §6.1 leaves them nothing else.
const THEIR_RECVONLY: &[u8] = b"v=0\r\no=- 2 3 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\na=recvonly\r\n";
/// A different codec, which is a renegotiation and not a hold.
const THEIR_NEW_CODEC: &[u8] = b"v=0\r\no=- 2 3 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 8\r\n";

/// The last thing the agent wrote, for the cases where a 100 Trying goes
/// first.
fn last(agent: &mut UserAgent) -> Vec<u8> {
    transmits(agent).pop().expect("at least one message out")
}

/// The same response, with an `Allow` that says UPDATE is understood
/// (RFC 3311 §4).
fn with_allow(response: &[u8]) -> Vec<u8> {
    let head = response
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(response.len(), |at| at + 1);
    let mut out = Vec::with_capacity(response.len() + 40);
    out.extend_from_slice(&response[..head]);
    out.extend_from_slice(b"Allow: INVITE, ACK, CANCEL, BYE, UPDATE\r\n");
    out.extend_from_slice(&response[head..]);
    out
}

fn session_changed(agent: &mut UserAgent) -> Option<Hold> {
    events(agent).into_iter().find_map(|event| match event {
        UaEvent::SessionChanged { hold, .. } => Some(hold),
        _ => None,
    })
}

/// Place a call, be up, and hold it: the re-INVITE as it went out.
fn on_hold(agent: &mut UserAgent, account: AccountId, now: Instant) -> (CallHandle, Vec<u8>) {
    let (call, _) = call_up(agent, account, now);
    agent.hold(call, now).expect("the re-INVITE goes");
    (call, sent(agent))
}

#[test]
fn a_call_says_it_can_take_an_update() {
    // RFC 3311 §4: the INVITE and the 2xx both advertise it, because that is
    // the only way the far end learns an UPDATE is worth sending
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert!(
        String::from_utf8_lossy(&header(&invite, HeaderName::Allow)).contains("UPDATE"),
        "the INVITE lists UPDATE"
    );

    deliver(&mut agent, &incoming_invite("allow1", Some(OFFER)), t0);
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
    assert!(String::from_utf8_lossy(&header(&ok, HeaderName::Allow)).contains("UPDATE"));
}

#[test]
fn pressing_hold_offers_the_same_session_with_the_direction_turned_down() {
    // 8.4: "If the stream to be placed on hold was previously a sendrecv media
    // stream, it is placed on hold by marking it as sendonly"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);

    assert!(reinvite.starts_with(b"INVITE sip:bob@192.0.2.9 SIP/2.0\r\n"));
    assert_eq!(header(&reinvite, HeaderName::CSeq), b"2 INVITE");
    // 8.1.1.8 makes it a MUST on anything that can refresh a target
    assert_eq!(
        header(&reinvite, HeaderName::Contact),
        b"<sip:alice@192.0.2.1>"
    );
    let offer = body_of(&reinvite);
    assert!(offer.contains("a=sendonly\r\n"), "{offer}");
    assert!(offer.contains("m=audio 8000 RTP/AVP 0\r\n"), "{offer}");
    // RFC 3264 §8: "the version in the origin field MUST increment by one"
    assert!(offer.contains("o=- 1 2 IN IP4 192.0.2.1\r\n"), "{offer}");
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(false));

    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    let ack = sent(&mut agent);
    assert!(ack.starts_with(b"ACK sip:bob@192.0.2.9 SIP/2.0\r\n"));
    // 13.2.2.4: the ACK takes the CSeq of the request it acknowledges
    assert_eq!(header(&ack, HeaderName::CSeq), b"2 ACK");
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: true,
            remote: false
        })
    );
}

#[test]
fn resuming_puts_back_the_direction_the_stream_started_with() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);
    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.resume(call, t0).expect("the re-INVITE goes");
    let again = sent(&mut agent);
    let offer = body_of(&again);
    assert!(offer.contains("a=sendrecv\r\n"), "{offer}");
    assert!(offer.contains("o=- 1 3 IN IP4 192.0.2.1\r\n"), "{offer}");

    deliver(
        &mut agent,
        &answered(&again, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(
        agent.hold_state(call),
        Some(Hold {
            local: false,
            remote: false
        })
    );
}

#[test]
fn holding_a_call_that_is_already_held_sends_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);
    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.hold(call, t0).expect("nothing to do");
    assert!(
        transmits(&mut agent).is_empty(),
        "a hold that is already in place is not a session change"
    );
}

#[test]
fn a_confirmed_call_changes_by_reinvite_even_when_update_is_allowed() {
    // RFC 3311 §5.1: "Although UPDATE can be used on confirmed dialogs, it is
    // RECOMMENDED that a re-INVITE be used instead"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mut ok = answered(&invite, 200, "OK", "desk", Some(ANSWER));
    ok = with_allow(&ok);
    deliver(&mut agent, &ok, t0);
    transmits(&mut agent);
    events(&mut agent);

    agent.hold(call, t0).expect("the change goes");
    let change = sent(&mut agent);
    assert!(
        change.starts_with(b"INVITE "),
        "a confirmed dialog re-INVITEs"
    );
}

#[test]
fn an_early_session_changes_by_update_because_a_second_invite_is_forbidden() {
    // 14.1: "a UAC MUST NOT initiate a new INVITE transaction within a dialog
    // while another INVITE transaction is in progress"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let progress = with_allow(&answered(
        &invite,
        183,
        "Session Progress",
        "desk",
        Some(ANSWER),
    ));
    deliver(&mut agent, &progress, t0);
    events(&mut agent);

    agent.hold(call, t0).expect("the UPDATE goes");
    let change = sent(&mut agent);
    assert!(
        change.starts_with(b"UPDATE sip:bob@192.0.2.9 SIP/2.0\r\n"),
        "{}",
        String::from_utf8_lossy(&change)
    );
    assert!(body_of(&change).contains("a=sendonly\r\n"));
}

#[test]
fn an_early_session_cannot_change_when_the_far_end_never_offered_update() {
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

    assert_eq!(agent.hold(call, t0), Err(UaError::CannotRenegotiate));
    assert!(transmits(&mut agent).is_empty());
}

#[test]
fn the_far_end_holding_us_is_answered_and_reported() {
    // 8.4: "The recipient of an offer for a stream on-hold SHOULD NOT
    // automatically return an answer with the corresponding stream on hold" —
    // and 6.1 leaves recvonly as the only answer to sendonly anyway
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "theirhold", 1, Some(THEIR_HOLD)),
        t0,
    );
    let answer = last(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    let body = body_of(&answer);
    assert!(body.contains("a=recvonly\r\n"), "{body}");
    assert!(body.contains("m=audio 8000 RTP/AVP 0\r\n"), "{body}");
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: false,
            remote: true
        })
    );
    assert_eq!(agent.hold_state(call).map(|hold| hold.remote), Some(true));
}

#[test]
fn a_hold_written_the_way_rfc_2543_did_it_is_still_a_hold() {
    // 8.4: "An agent MUST be capable of receiving SDP with a connection
    // address of 0.0.0.0"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "oldhold", 1, Some(THEIR_OLD_HOLD)),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(agent.hold_state(call).map(|hold| hold.remote), Some(true));
}

#[test]
fn an_offer_that_changes_the_codecs_is_the_applications() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "codec", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    assert!(
        transmits(&mut agent)
            .iter()
            .all(|bytes| bytes.starts_with(b"SIP/2.0 100 ")),
        "nothing is answered on the application's behalf"
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Reoffer { .. })),
        "a codec change needs a device this layer does not have"
    );

    agent
        .accept_reoffer(call, Some(ANSWER), t0)
        .expect("the 200 goes");
    let answer = sent(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert!(body_of(&answer).contains("m=audio 9000 RTP/AVP 0\r\n"));
}

#[test]
fn a_description_that_cannot_be_read_is_refused_with_488_and_a_warning() {
    // 14.2: "the UAS can reject it by returning a 488 (Not Acceptable Here)
    // response ... This response SHOULD include a Warning header field"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "junk", 1, Some(b"v=9\r\nnot sdp\r\n")),
        t0,
    );
    let refusal = last(&mut agent);
    assert!(refusal.starts_with(b"SIP/2.0 488 "));
    assert!(
        String::from_utf8_lossy(&header(&refusal, HeaderName::Warning)).starts_with("399 "),
        "20.43's miscellaneous warning"
    );
}

#[test]
fn a_reinvite_with_no_offer_is_answered_with_one_and_the_answer_comes_in_the_ack() {
    // 14.1: a re-INVITE may carry no description, "in which case the first
    // reliable non-failure response will contain the offer"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(&mut agent, &reversed(&ack, "INVITE", "empty", 1, None), t0);
    let answer = last(&mut agent);
    let offer = body_of(&answer);
    assert!(offer.contains("m=audio 8000 RTP/AVP 0\r\n"), "{offer}");
    assert!(offer.contains("o=- 1 2 IN IP4 192.0.2.1\r\n"), "{offer}");
    events(&mut agent);

    deliver(
        &mut agent,
        &reversed(&ack, "ACK", "emptyack", 1, Some(THEIR_HOLD)),
        t0,
    );
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: false,
            remote: true
        }),
        "the answer to an offer in a 2xx travels in the ACK"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn an_update_that_crosses_an_offer_of_ours_is_refused_with_491() {
    // RFC 3311 §5.2: "if an UPDATE is received that contains an offer, and the
    // UAS has generated an offer ... to which it has not yet received an
    // answer, the UAS MUST reject the UPDATE with a 491 response"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    agent.hold(call, t0).expect("the hold goes");
    let _ = sent(&mut agent);

    deliver(
        &mut agent,
        &reversed(&ack, "UPDATE", "crossed", 1, Some(THEIR_HOLD)),
        t0,
    );
    let refusal = last(&mut agent);
    assert!(
        refusal.starts_with(b"SIP/2.0 491 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
}

#[test]
fn a_refused_change_leaves_the_session_exactly_as_it_was() {
    // 14.1: "the session parameters MUST remain unchanged, as if no re-INVITE
    // had been issued"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);

    deliver(
        &mut agent,
        &answered(&reinvite, 488, "Not Acceptable Here", "desk", None),
        t0,
    );
    transmits(&mut agent);
    let failure = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::SessionChangeFailed {
                status, retry_in, ..
            } => Some((status, retry_in)),
            _ => None,
        })
        .expect("the change was refused");
    assert_eq!(failure.0.map(StatusCode::get), Some(488));
    assert_eq!(failure.1, None, "a 488 is not worth trying again");
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(false));
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn two_changes_that_cross_back_off_once_and_then_give_up() {
    // 14.1: "the UAC SHOULD attempt the re-INVITE once more, if it still
    // desires for that session modification to take place"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);

    deliver(
        &mut agent,
        &answered(&reinvite, 491, "Request Pending", "desk", None),
        t0,
    );
    transmits(&mut agent);
    let wait = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::SessionChangeFailed { retry_in, .. } => retry_in,
            _ => None,
        })
        .expect("491 says to wait and try again");
    // the end that generated the Call-ID draws from 2.1 to 4 seconds
    assert!(
        wait >= Duration::from_millis(2_100) && wait <= Duration::from_secs(4),
        "{wait:?}"
    );

    agent.handle_timeout(t0 + wait);
    let again = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the change goes out again");
    assert_eq!(header(&again, HeaderName::CSeq), b"3 INVITE");
    events(&mut agent);

    deliver(
        &mut agent,
        &answered(&again, 491, "Request Pending", "desk", None),
        t0 + wait,
    );
    transmits(&mut agent);
    let second = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::SessionChangeFailed { retry_in, .. } => Some(retry_in),
            _ => None,
        })
        .expect("and is refused again");
    assert_eq!(second, None, "once more, not until it works");
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(false));
}

#[test]
fn a_call_answered_and_never_acknowledged_is_ended_with_a_bye() {
    // 13.3.1.4: "If the UAS generates a 2xx response and never receives an
    // ACK, it SHOULD generate a BYE to terminate the dialog." Nothing else
    // will: the far end is not answering, and the line would stay busy
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("noack", Some(OFFER)), t0);
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
        .expect("the 200 goes");
    transmits(&mut agent);
    events(&mut agent);

    // 64*T1 with nothing coming back
    agent.handle_timeout(t0 + Duration::from_secs(33));
    let bye = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"BYE "))
        .expect("the dialog is ended rather than left standing");
    assert!(bye.starts_with(b"BYE sip:bob@192.0.2.9 SIP/2.0\r\n"));
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::Unreachable)
    );
}

#[test]
fn a_call_that_was_acknowledged_ends_nothing_when_the_transaction_retires() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("acked", Some(OFFER)), t0);
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
        .expect("the 200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "ackedack", 1), t0);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(33));
    assert!(transmits(&mut agent).is_empty(), "nothing to say");
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_reinvite_with_no_offer_is_refused_while_an_offer_of_theirs_is_unanswered() {
    // RFC 3311 §5.2, and 14.1's rule that one offer/answer exchange finishes
    // before the next starts. A re-INVITE with no description asks *this* end
    // to offer, so it is the same exchange starting over and not exempt
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "UPDATE", "theirs", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Reoffer { .. })),
        "the codec change is the application's"
    );
    transmits(&mut agent);

    deliver(&mut agent, &reversed(&ack, "INVITE", "empty", 2, None), t0);
    let refusal = last(&mut agent);
    assert!(
        refusal.starts_with(b"SIP/2.0 500 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert!(
        !header(&refusal, HeaderName::RetryAfter).is_empty(),
        "5.2 wants it to say when to come back"
    );
}

#[test]
fn a_change_the_far_end_is_waiting_on_is_answered_when_the_call_ends() {
    // 15.1.2: "The UAS MUST still respond to any pending requests received for
    // that dialog. It is RECOMMENDED that a 487 (Request Terminated) response
    // be generated to those pending requests."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "UPDATE", "pending", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    events(&mut agent);
    transmits(&mut agent);

    agent.hangup(call, t0).expect("the BYE goes");
    let written = transmits(&mut agent);
    assert!(
        written.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "the call ends"
    );
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 487 ")),
        "and their request is not left unanswered"
    );
}

#[test]
fn an_offer_the_application_wrote_gets_a_version_that_has_moved() {
    // RFC 3264 §8: "the version in the origin field MUST increment by one" —
    // and its other half, that an unchanged version promises unchanged bytes,
    // is a promise the stack is not going to let an application break
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);

    // the same version the call was placed with
    agent.reoffer(call, OFFER, t0).expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
    let offer = body_of(&reinvite);
    assert!(offer.contains("o=- 1 2 IN IP4 192.0.2.1\r\n"), "{offer}");
}

// -- session timers ----------------------------------------------------------

/// A 2xx that settles the timer the way a server that understands RFC 4028
/// does: an interval, and which end refreshes it.
fn timed(request: &[u8], body: Option<&[u8]>, session: &str) -> Vec<u8> {
    let mut out = answered(request, 200, "OK", "desk", body);
    let head = out
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(out.len(), |at| at + 1);
    let mut with = out[..head].to_vec();
    with.extend_from_slice(format!("Session-Expires: {session}\r\n").as_bytes());
    with.extend_from_slice(&out[head..]);
    out = with;
    out
}

#[test]
fn an_invite_says_it_understands_session_timers_and_asks_for_one() {
    // 7.1: Supported goes on every request, and the interval is what §4
    // recommends
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");

    let invite = sent(&mut agent);
    let supported = String::from_utf8_lossy(&header(&invite, HeaderName::Supported)).into_owned();
    assert!(supported.contains("timer"), "{supported}");
    assert_eq!(header(&invite, HeaderName::SessionExpires), b"1800");
    // 7.1 recommends leaving the refresher out so the negotiation settles it
    assert!(
        !String::from_utf8_lossy(&header(&invite, HeaderName::SessionExpires))
            .contains("refresher")
    );
}

#[test]
fn an_account_can_ask_for_no_timer_at_all() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().session_interval(None));
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");

    let invite = sent(&mut agent);
    assert!(header(&invite, HeaderName::SessionExpires).is_empty());
    // but it still says it understands them, because that is what lets the far
    // end ask
    assert!(
        String::from_utf8_lossy(&header(&invite, HeaderName::Supported)).contains("timer"),
        "7.1 puts Supported on every request either way"
    );
}

#[test]
fn the_refresher_sends_a_refresh_at_half_the_interval() {
    // 7.2: "once half the session interval has elapsed"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &timed(&invite, Some(ANSWER), "600;refresher=uac"),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(299));
    assert!(transmits(&mut agent).is_empty(), "not yet");

    agent.handle_timeout(t0 + Duration::from_secs(300));
    let refresh = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the session is kept alive");
    assert_eq!(
        header(&refresh, HeaderName::SessionExpires),
        b"600;refresher=uac"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_refresh_repeats_the_description_it_already_agreed() {
    // 7.4: "a re-INVITE SHOULD contain one, even if the details of the session
    // have not changed. In that case, the offer MUST indicate that it has not
    // changed" — and RFC 3264 §8 says an unchanged version is how that is said
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &timed(&invite, Some(ANSWER), "600;refresher=uac"),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(300));
    let refresh = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the refresh");
    let offer = body_of(&refresh);
    assert!(offer.contains("o=- 1 1 IN IP4 192.0.2.1\r\n"), "{offer}");
}

#[test]
fn the_end_that_does_not_refresh_hangs_up_when_nothing_arrives() {
    // 10: "it SHOULD send a BYE to terminate the session, slightly before the
    // session expiration", by the minimum of 32 seconds and a third of it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &timed(&invite, Some(ANSWER), "600;refresher=uas"),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    // 600 - 32, because a third of 600 is more than 32
    agent.handle_timeout(t0 + Duration::from_secs(567));
    assert!(transmits(&mut agent).is_empty(), "not yet");

    agent.handle_timeout(t0 + Duration::from_secs(568));
    let bye = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"BYE "))
        .expect("the session ran out");
    assert!(bye.starts_with(b"BYE sip:bob@192.0.2.9 SIP/2.0\r\n"));
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::Expired)
    );
    assert_eq!(agent.call_state(call), None);
}

#[test]
fn a_refresh_that_arrives_puts_the_clock_back() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &timed(&invite, Some(ANSWER), "600;refresher=uas"),
        t0,
    );
    let ack = sent(&mut agent);
    events(&mut agent);

    // their refresh, most of the way through
    let mut refresh = reversed(&ack, "UPDATE", "keepalive", 1, None);
    let head = refresh
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(refresh.len(), |at| at + 1);
    let mut with = refresh[..head].to_vec();
    with.extend_from_slice(b"Session-Expires: 600;refresher=uas\r\n");
    with.extend_from_slice(&refresh[head..]);
    refresh = with;
    deliver(&mut agent, &refresh, t0 + Duration::from_secs(500));
    let answer = last(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert_eq!(
        header(&answer, HeaderName::SessionExpires),
        b"600;refresher=uas",
        "the answer says what is still agreed"
    );

    // the old deadline passes and nothing happens, because the clock moved
    agent.handle_timeout(t0 + Duration::from_secs(569));
    assert!(transmits(&mut agent).is_empty());
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_422_asks_again_with_the_interval_that_was_demanded() {
    // 7.3: the retry is a new transaction that "SHOULD have the same value as
    // the Call-ID, To, and From of the previous request"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let first = sent(&mut agent);
    assert_eq!(header(&first, HeaderName::CSeq), b"1 INVITE");

    deliver(
        &mut agent,
        &reply(
            &first,
            422,
            "Session Interval Too Small",
            "Min-SE: 1200\r\n",
        ),
        t0,
    );
    let again = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("it is asked again, not given up on");

    assert_eq!(header(&again, HeaderName::CSeq), b"2 INVITE");
    assert_eq!(
        header(&again, HeaderName::CallId),
        header(&first, HeaderName::CallId),
        "the same call, asked again"
    );
    assert_eq!(header(&again, HeaderName::SessionExpires), b"1200");
    // 7.4: once a floor has been demanded it rides on every request after it
    assert_eq!(header(&again, HeaderName::MinSe), b"1200");
    assert_eq!(agent.call_state(call), Some(CallState::Calling));

    // and a second 422 is the far end contradicting itself
    deliver(
        &mut agent,
        &reply(
            &again,
            422,
            "Session Interval Too Small",
            "Min-SE: 1800\r\n",
        ),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::Refused),
        "asked once more, not for ever"
    );
}

#[test]
fn an_interval_below_the_floor_is_refused_with_the_floor() {
    // 9: a UAS may reject with 422 and MUST say its minimum, which "MUST NOT
    // be lower than 90 seconds"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let mut invite = incoming_invite("brief", Some(OFFER));
    let head = invite
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(invite.len(), |at| at + 1);
    let mut with = invite[..head].to_vec();
    with.extend_from_slice(b"Supported: timer\r\nSession-Expires: 30\r\n");
    with.extend_from_slice(&invite[head..]);
    invite = with;
    deliver(&mut agent, &invite, t0);

    let refusal = last(&mut agent);
    assert!(refusal.starts_with(b"SIP/2.0 422 "));
    assert_eq!(header(&refusal, HeaderName::MinSe), b"90");
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::IncomingCall { .. })),
        "nothing the application has to decide"
    );
}

#[test]
fn answering_a_call_settles_the_timer_in_the_2xx() {
    // 9: "The UAS MUST set the value of the refresher parameter in the
    // Session-Expires header field in the 2xx response."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let mut invite = incoming_invite("timed", Some(OFFER));
    let head = invite
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(invite.len(), |at| at + 1);
    let mut with = invite[..head].to_vec();
    with.extend_from_slice(b"Supported: timer\r\nSession-Expires: 600\r\n");
    with.extend_from_slice(&invite[head..]);
    invite = with;
    deliver(&mut agent, &invite, t0);
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
        .expect("the 200 goes");

    let ok = sent(&mut agent);
    // the far end expressed no preference, so this end takes the work: it is
    // the uas of this dialog
    assert_eq!(
        header(&ok, HeaderName::SessionExpires),
        b"600;refresher=uas"
    );
    assert!(
        header(&ok, HeaderName::Require).is_empty(),
        "9 only demands a Require when the other end has to act"
    );
}

// -- reliable provisional responses ------------------------------------------

/// The same message with extra header fields, inserted after the start line.
fn plus(message: &[u8], extra: &str) -> Vec<u8> {
    let head = message
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(message.len(), |at| at + 1);
    let mut out = message[..head].to_vec();
    out.extend_from_slice(extra.as_bytes());
    out.extend_from_slice(&message[head..]);
    out
}

/// An INVITE that arrives asking for reliable provisional responses.
fn incoming_100rel(branch: &str, require: bool) -> Vec<u8> {
    let list = if require { "Require" } else { "Supported" };
    plus(
        &incoming_invite(branch, Some(OFFER)),
        &format!("{list}: 100rel\r\n"),
    )
}

fn call_arriving(agent: &mut UserAgent, bytes: &[u8], now: Instant) -> CallHandle {
    deliver(agent, bytes, now);
    transmits(agent);
    events(agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling")
}

#[test]
fn a_provisional_goes_reliably_when_the_invite_asked_for_it() {
    // 3: "The UAS MUST send any non-100 provisional response reliably if the
    // initial request contained a Require header field with the option tag"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_100rel("rel1", true), t0);

    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);
    assert!(ringing.starts_with(b"SIP/2.0 180 "));
    assert!(
        String::from_utf8_lossy(&header(&ringing, HeaderName::Require)).contains("100rel"),
        "3: a reliable provisional carries Require: 100rel"
    );
    assert!(
        !header(&ringing, HeaderName::RSeq).is_empty(),
        "3: and an RSeq"
    );
}

#[test]
fn a_provisional_does_not_go_reliably_when_nothing_asked_for_it() {
    // 3: "If the request did not include either a Supported or Require header
    // field indicating this feature, the UAS MUST NOT send the provisional
    // response reliably"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("plain", Some(OFFER)), t0);

    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);
    assert!(header(&ringing, HeaderName::RSeq).is_empty());
    assert!(header(&ringing, HeaderName::Require).is_empty());
}

#[test]
fn a_prack_is_answered_and_the_response_stops_being_retransmitted() {
    // 3: "it MUST be responded to with a 2xx response"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_100rel("rel2", true), t0);
    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);
    let rseq = String::from_utf8_lossy(&header(&ringing, HeaderName::RSeq)).into_owned();

    let prack = plus(
        &in_dialog(&ringing, "PRACK", "rel2prack", 2),
        &format!("RAck: {rseq} 1 INVITE\r\n"),
    );
    deliver(&mut agent, &prack, t0);
    let answer = last(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert_eq!(header(&answer, HeaderName::CSeq), b"2 PRACK");
}

#[test]
fn the_2xx_waits_for_a_reliable_response_that_carried_a_description() {
    // 5: "the UAS MUST delay sending the 2xx until the provisional response is
    // acknowledged". Two unanswered offers on the wire at once is a session
    // negotiated twice
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_100rel("rel3", true), t0);

    agent
        .ring(call, Some(Arc::from(ANSWER)), t0)
        .expect("183 with early media");
    let progress = sent(&mut agent);
    assert!(progress.starts_with(b"SIP/2.0 183 "));

    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("the answer is taken");
    assert!(
        transmits(&mut agent).is_empty(),
        "the 200 is held until the 183 is acknowledged"
    );

    let rseq = String::from_utf8_lossy(&header(&progress, HeaderName::RSeq)).into_owned();
    let prack = plus(
        &in_dialog(&progress, "PRACK", "rel3prack", 2),
        &format!("RAck: {rseq} 1 INVITE\r\n"),
    );
    deliver(&mut agent, &prack, t0);
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 200 OK\r\n")
                && header(bytes, HeaderName::CSeq) == b"1 INVITE"),
        "and goes the moment it is"
    );
}

#[test]
fn an_offer_in_a_reliable_response_is_answered_in_the_prack() {
    // 5: "If the UAC receives an offer in a reliable provisional response, it
    // MUST generate an answer in the PRACK."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    // no offer of ours, so theirs comes back in the provisional
    let call = agent
        .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);

    let progress = plus(
        &answered(&invite, 183, "Session Progress", "desk", Some(ANSWER)),
        "Require: 100rel\r\nRSeq: 314\r\n",
    );
    deliver(&mut agent, &progress, t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "nothing is acknowledged until there is an answer to put in it"
    );
    let wanted = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallProgress { answer_wanted, .. } => Some(answer_wanted),
            _ => None,
        })
        .expect("the progress is reported");
    assert!(wanted, "and the application is told an answer is owed");

    agent
        .answer_early(call, OFFER, t0)
        .expect("the PRACK carries it");
    let prack = sent(&mut agent);
    assert!(prack.starts_with(b"PRACK "));
    assert_eq!(header(&prack, HeaderName::RAck), b"314 1 INVITE");
    assert!(body_of(&prack).contains("m=audio 8000 RTP/AVP 0\r\n"));
}

#[test]
fn a_require_nobody_here_implements_is_refused_with_420() {
    // 8.2.2.3: the response says which token it was, so the far end can try
    // again without it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(
        &mut agent,
        &plus(
            &incoming_invite("odd", Some(OFFER)),
            "Require: gruu, 100rel\r\n",
        ),
        t0,
    );

    let refusal = last(&mut agent);
    assert!(refusal.starts_with(b"SIP/2.0 420 "));
    assert_eq!(header(&refusal, HeaderName::Unsupported), b"gruu");
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::IncomingCall { .. })),
        "there is nothing for the application to decide"
    );
}
