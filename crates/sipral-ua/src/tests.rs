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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sipral_core::diag::Reason;
use sipral_core::dialog::CallId;
use sipral_core::endpoint::Event;
use sipral_core::msg::{HeaderName, Method, ParseMode, ParseScratch, RawMessage, parse};
use sipral_core::sdp;

use crate::account::{Account, AccountId};
use crate::agent::UserAgent;
use crate::call::{CallEndReason, CallHandle, CallState, ForkPolicy, OutgoingCall, OutgoingExtras};
use crate::dialoginfo::{DialogInfoTable, DialogPhase};
use crate::event::{RegistrationFailure, RegistrationState, UaEvent};
use crate::session::Hold;
use crate::subscription::{Subscribe, SubscriptionEnd, SubscriptionHandle, SubscriptionState};
use crate::{
    Credentials, EndpointConfig, Incoming, Input, Rate, RateError, Refusals, Replacing,
    STREAM_WAIT, Screen, Screening, StatusCode, TransportId, TransportProtocol, UaError, Uri,
};

pub(crate) const UDP: TransportId = TransportId(1);
const TCP: TransportId = TransportId(2);
const HOUR: Duration = Duration::from_hours(1);

pub(crate) fn local() -> SocketAddr {
    "192.0.2.1:5060".parse().expect("a local address")
}

pub(crate) fn registrar() -> SocketAddr {
    "192.0.2.9:5060".parse().expect("the registrar's address")
}

/// A second SRV target, or a migrated registrar: an address that is not
/// [`registrar`].
fn elsewhere() -> SocketAddr {
    "198.51.100.7:5060".parse().expect("another address")
}

pub(crate) fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

/// A user agent with one UDP transport bound.
pub(crate) fn agent(now: Instant) -> UserAgent {
    let mut agent = UserAgent::new(EndpointConfig::default(), [11; 32]).unwrap();
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

/// As [`agent`], with a configuration of the caller's own rather than
/// [`EndpointConfig::default`].
fn agent_with(config: EndpointConfig, now: Instant) -> UserAgent {
    let mut agent = UserAgent::new(config, [11; 32]).unwrap();
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

pub(crate) fn account() -> Account {
    Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri("sip:alice@192.0.2.1"),
        UDP,
        registrar(),
    )
}

/// Everything the agent wants written, drained.
pub(crate) fn transmits(agent: &mut UserAgent) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(transmit) = agent.poll_transmit() {
        out.push(transmit.payload.to_vec());
    }
    out
}

/// The one message the agent wanted written.
pub(crate) fn sent(agent: &mut UserAgent) -> Vec<u8> {
    let mut all = transmits(agent);
    assert_eq!(all.len(), 1, "expected exactly one message out");
    all.pop().unwrap_or_default()
}

pub(crate) fn events(agent: &mut UserAgent) -> Vec<UaEvent> {
    let mut out = Vec::new();
    while let Some(event) = agent.poll_event() {
        out.push(event);
    }
    out
}

pub(crate) fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
    let mut scratch = ParseScratch::new();
    f(&parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message"))
}

pub(crate) fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
    with(bytes, |message| {
        message.header(name).unwrap_or_default().to_vec()
    })
}

/// A response to a request the agent wrote, echoing what §8.2.6.2 requires.
pub(crate) fn reply(request: &[u8], status: u16, reason: &str, extra: &str) -> Vec<u8> {
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

pub(crate) fn deliver(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
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

/// A user agent whose account registers over a byte stream, which is the only
/// kind of transport RFC 5626 §4.4.1 keep-alives run on.
fn over_tcp(now: Instant) -> (UserAgent, AccountId) {
    let mut agent = UserAgent::new(EndpointConfig::default(), [12; 32]).unwrap();
    agent
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(registrar()),
            },
            now,
        )
        .expect("binding TCP");
    let account = agent.add_account(Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri("sip:alice@192.0.2.1"),
        TCP,
        registrar(),
    ));
    (agent, account)
}

fn stream(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
    agent
        .receive(
            Input::StreamData {
                transport: TCP,
                data: bytes,
            },
            now,
        )
        .expect("bytes on a stream");
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
        "<sip:alice@192.0.2.1>;+sip.instance=\"<urn:uuid:f81d4fae-7ced-11d0-a765-00a0c91e6bf6>\""
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

// -- an account that never registers -----------------------------------------

/// Where an account with no registrar sends what it places. Not the
/// registrar's address, so a request that went there out of habit shows.
fn proxy() -> SocketAddr {
    "198.51.100.20:5060".parse().expect("the proxy's address")
}

/// A trunk: known to the far end by its address, with nobody to register
/// with.
fn trunk() -> Account {
    Account::unregistered(
        uri("sip:pbx@example.com"),
        uri("sip:pbx@192.0.2.1"),
        UDP,
        proxy(),
    )
}

#[test]
fn an_account_without_a_registrar_is_refused_a_register_before_anything_is_built() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(trunk());
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::NotRegistering)
    );
    assert_eq!(agent.register(id, t0), Err(UaError::NoRegistrar));
    assert_eq!(agent.unregister(id, t0), Err(UaError::NoRegistrar));
    assert!(
        transmits(&mut agent).is_empty(),
        "a REGISTER went somewhere"
    );
    assert_eq!(
        agent.endpoint().in_flight(),
        (0, 0),
        "a transaction was opened for it"
    );
    assert!(
        events(&mut agent).is_empty(),
        "a registration was reported for an account that has none"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::NotRegistering)
    );
    assert_eq!(
        agent.idle().registrations,
        0,
        "something was scheduled for it"
    );
}

#[test]
fn an_account_without_a_registrar_places_its_calls_at_the_proxy_and_never_registers() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(trunk());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");

    // a day of this layer's timers and the endpoint's, retransmissions and
    // all, kept with where each message was going
    let mut out = Vec::new();
    let mut at = t0;
    for _ in 0..48 {
        while let Some(transmit) = agent.poll_transmit() {
            out.push(transmit);
        }
        at += Duration::from_secs(1_800);
        agent.handle_timeout(at);
    }
    while let Some(transmit) = agent.poll_transmit() {
        out.push(transmit);
    }

    assert!(
        out.first()
            .is_some_and(|first| first.payload.starts_with(b"INVITE ")),
        "the call went nowhere"
    );
    assert!(
        out.iter().all(|transmit| transmit.destination == proxy()),
        "everything the account placed goes to its proxy"
    );
    assert!(
        !out.iter()
            .any(|transmit| transmit.payload.starts_with(b"REGISTER ")),
        "a REGISTER went out for an account with no registrar"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::NotRegistering)
    );
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

// -- what the registrar says beside the binding ------------------------------

/// This device's instance, as the account is configured with it: without the
/// angle brackets, which the registrar below puts back the way RFC 5627 §9
/// writes them.
const INSTANCE: &str = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
const PUBLIC_GRUU: &str = "sip:alice@example.com;gr=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
const TEMPORARY_GRUU: &str = "sip:tgruu.7hs==jd7vnzga5w7fajsc7-ajd6fabz0f8g5@example.com;gr";
/// The `Contact` an account with no GRUU to use writes on a dialog.
const CONFIGURED: &str =
    "<sip:alice@192.0.2.1>;+sip.instance=\"<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>\"";
/// A two-hop service route with a fold in the middle of it (RFC 3608 §6.4.1),
/// and two associated identities, one of them a telephone number (RFC 7315).
const SERVICES: &str = "Service-Route: <sip:p2.example.com;lr>,\r\n <sip:hsp.example.com;lr>\r\n ;role=home\r\n\
P-Associated-URI: <sip:alice.smith@example.com>, <tel:+15551234567>\r\n";

fn gruu_account() -> Account {
    account().instance_id(INSTANCE)
}

/// A 200 that grants the binding, with both GRUUs on this device's contact and
/// `extra` beside them. The desk phone on the same address of record comes
/// first, with GRUUs of its own that are not this device's to use.
fn serviced(request: &[u8], temporary: &str, extra: &str) -> Vec<u8> {
    reply(
        request,
        200,
        "OK",
        &format!(
            "Contact: <sip:alice@192.0.2.77>;+sip.instance=\"<urn:uuid:00000000-0000-0000-0000-0000000d35c0>\"\
             ;pub-gruu=\"sip:alice@example.com;gr=urn:uuid:00000000-0000-0000-0000-0000000d35c0\"\
             ;temp-gruu=\"sip:tgruu.desk@example.com;gr\";expires=3600\r\n\
             Contact: <sip:alice@192.0.2.1>;pub-gruu=\"{PUBLIC_GRUU}\";temp-gruu=\"{temporary}\"\
             ;+sip.instance=\"<{INSTANCE}>\";expires=3600\r\n{extra}"
        ),
    )
}

/// Register, and take a 200 carrying both GRUUs and `extra`.
fn serviced_registration(agent: &mut UserAgent, id: AccountId, extra: &str, now: Instant) {
    agent.register(id, now).expect("the REGISTER goes");
    let request = sent(agent);
    deliver(agent, &serviced(&request, TEMPORARY_GRUU, extra), now);
    events(agent);
}

/// Every `Route` value of a message, in order, across lines and commas.
fn routes(bytes: &[u8]) -> Vec<Vec<u8>> {
    with(bytes, |message| {
        message
            .field_values(HeaderName::Route)
            .map(<[u8]>::to_vec)
            .collect()
    })
}

fn angled(uri: &str) -> Vec<u8> {
    format!("<{uri}>").into_bytes()
}

fn registered_info(agent: &mut UserAgent) -> Option<crate::RegistrarInfo> {
    events(agent).into_iter().find_map(|event| match event {
        UaEvent::Registered { info, .. } => Some(info),
        _ => None,
    })
}

#[test]
fn a_registrar_that_says_more_than_the_binding_is_heard_on_the_event() {
    // RFC 3608 §6.1, RFC 5627 §4.2 and RFC 7315 §4.1, all in one 200
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    // §4.1: a registrar hands no GRUU to a REGISTER that did not ask for one
    assert_eq!(header(&request, HeaderName::Supported), b"gruu");
    deliver(
        &mut agent,
        &serviced(&request, TEMPORARY_GRUU, SERVICES),
        t0,
    );

    let (response, info) = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::Registered { response, info, .. } => Some((response, info)),
            _ => None,
        })
        .expect("the binding is live");
    let raw = response.as_raw();
    assert_eq!(raw.status(), Some(StatusCode::OK));
    assert_eq!(
        raw.header(HeaderName::Extension("P-Associated-URI")),
        Some(&b"<sip:alice.smith@example.com>, <tel:+15551234567>"[..]),
        "the 200 rides whole"
    );
    assert_eq!(
        info.service_route().collect::<Vec<_>>(),
        vec![
            &b"<sip:p2.example.com;lr>"[..],
            &b"<sip:hsp.example.com;lr> ;role=home"[..]
        ],
        "in the registrar's order, and each on one line"
    );
    assert_eq!(info.public_gruu().map(Uri::as_str), Some(PUBLIC_GRUU));
    assert_eq!(
        info.temporary_gruu().map(Uri::as_str),
        Some(TEMPORARY_GRUU),
        "this device's, and not the desk phone's"
    );
    assert_eq!(
        info.associated()
            .iter()
            .map(Uri::as_str)
            .collect::<Vec<_>>(),
        vec!["sip:alice.smith@example.com", "tel:+15551234567"]
    );
    assert_eq!(
        agent
            .registrar_info(id, t0)
            .and_then(|kept| kept.public_gruu().map(Uri::as_str)),
        Some(PUBLIC_GRUU)
    );
}

#[test]
fn an_instance_is_matched_by_the_rules_of_its_urn_and_not_byte_for_byte() {
    // RFC 5626 §4.1: URN equality for the namespace, RFC 2141 lexical
    // equality where it is not understood, and RFC 4122 §3 for a UUID
    let t0 = Instant::now();
    let gruu_of = |configured: &str, echoed: &str| {
        let mut agent = self::agent(t0);
        let id = agent.add_account(account().instance_id(configured));
        agent.register(id, t0).expect("the REGISTER goes");
        let request = sent(&mut agent);
        let ok = reply(
            &request,
            200,
            "OK",
            &format!(
                "Contact: <sip:alice@192.0.2.1>;pub-gruu=\"{PUBLIC_GRUU}\"\
                 ;+sip.instance=\"<{echoed}>\";expires=3600\r\n"
            ),
        );
        deliver(&mut agent, &ok, t0);
        registered_info(&mut agent)
            .and_then(|info| info.public_gruu().map(|gruu| gruu.as_str().to_owned()))
    };

    assert_eq!(
        gruu_of(INSTANCE, &INSTANCE.to_ascii_uppercase()).as_deref(),
        Some(PUBLIC_GRUU),
        "a UUID URN echoed in capitals is still this device"
    );
    assert_eq!(
        gruu_of(INSTANCE, "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf7"),
        None,
        "one digit off is another device"
    );
    assert_eq!(
        gruu_of("urn:example:Device1", "URN:EXAMPLE:Device1").as_deref(),
        Some(PUBLIC_GRUU),
        "the prefix and the namespace are compared without regard to case"
    );
    assert_eq!(
        gruu_of("urn:example:Device1", "urn:example:device1"),
        None,
        "the rest of a URN outside a namespace understood here is compared exactly"
    );
}

#[test]
fn an_instance_echoed_without_the_angle_brackets_the_rfc_asks_for_is_still_matched() {
    // RFC 3840 §9 wraps the URN in "<" and ">" inside the quoted string, but a
    // registrar that echoes back what a non-conforming peer sent — or what it
    // received before this stack wrote the brackets itself — must not cost a
    // UA its own GRUU over a detail the far end got wrong
    let t0 = Instant::now();
    let mut agent = self::agent(t0);
    let id = agent.add_account(account().instance_id(INSTANCE));
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    let ok = reply(
        &request,
        200,
        "OK",
        &format!(
            "Contact: <sip:alice@192.0.2.1>;pub-gruu=\"{PUBLIC_GRUU}\"\
             ;+sip.instance=\"{INSTANCE}\";expires=3600\r\n"
        ),
    );
    deliver(&mut agent, &ok, t0);
    let info = registered_info(&mut agent).expect("the binding stands");
    assert_eq!(info.public_gruu().map(Uri::as_str), Some(PUBLIC_GRUU));
}

#[test]
fn the_next_invite_travels_the_service_route_and_names_the_public_gruu() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    // RFC 3608 §6.1: preloaded, and "the UA MUST preserve the order"
    assert_eq!(
        routes(&invite),
        vec![
            b"<sip:p2.example.com;lr>".to_vec(),
            b"<sip:hsp.example.com;lr> ;role=home".to_vec()
        ]
    );
    // RFC 5627 §4.4, written bare the way §9 writes it
    assert_eq!(header(&invite, HeaderName::Contact), angled(PUBLIC_GRUU));
}

#[test]
fn supported_names_gruu_on_the_invite_and_the_responses_that_answer_one() {
    // RFC 5627 §4.4 SHOULD: "a UA SHOULD include a Supported header field
    // with the option tag gruu in requests and responses it generates"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    assert!(
        String::from_utf8_lossy(&header(&sent(&mut agent), HeaderName::Supported)).contains("gruu"),
        "the INVITE this end sends"
    );

    let call = call_arriving(&mut agent, &incoming_invite("gr-sup", Some(OFFER)), t0);
    agent.ring(call, None, t0).expect("180 goes");
    assert!(
        String::from_utf8_lossy(&header(&sent(&mut agent), HeaderName::Supported)).contains("gruu"),
        "the 180 this end sends"
    );
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    assert!(
        String::from_utf8_lossy(&header(&sent(&mut agent), HeaderName::Supported)).contains("gruu"),
        "the 200 this end sends"
    );
}

#[test]
fn an_account_with_no_instance_does_not_ask_for_gruu_on_a_call() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    assert!(
        !String::from_utf8_lossy(&header(&sent(&mut agent), HeaderName::Supported))
            .contains("gruu"),
        "no instance identifier, nothing to ask a GRUU for"
    );
}

#[test]
fn a_require_of_gruu_is_honoured_once_the_account_has_asked_for_one() {
    // the negative of this is `a_require_nobody_here_implements_is_refused_with_420`
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    deliver(
        &mut agent,
        &plus(
            &incoming_invite("gr-req", Some(OFFER)),
            "Require: gruu, 100rel\r\n",
        ),
        t0,
    );
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::IncomingCall { .. })),
        "gruu is understood by this account, so the call reaches the application"
    );
}

#[test]
fn the_refresh_does_not_travel_the_service_route_it_would_replace() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = sent(&mut agent);
    assert!(refresh.starts_with(b"REGISTER "));
    assert!(
        routes(&refresh).is_empty(),
        "a stale route could never be replaced if the refresh had to travel it"
    );
    assert_eq!(header(&refresh, HeaderName::Supported), b"gruu");
    assert!(
        text(&refresh, HeaderName::Contact).starts_with("<sip:alice@192.0.2.1>"),
        "RFC 5627 §4.1: the binding registered is the device's, never a GRUU"
    );
}

#[test]
fn a_supported_the_application_added_is_folded_in_with_gruu() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account().header(HeaderName::Supported, b"path"));
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    assert_eq!(
        with(&request, |message| message
            .header_count(HeaderName::Supported)),
        1
    );
    assert_eq!(header(&request, HeaderName::Supported), b"path, gruu");

    let plain = agent.add_account(account());
    agent.register(plain, t0).expect("the REGISTER goes");
    assert!(
        header(&sent(&mut agent), HeaderName::Supported).is_empty(),
        "an account with no instance cannot be given a GRUU, and does not ask"
    );
}

#[test]
fn a_call_that_comes_in_is_answered_from_the_gruu() {
    // RFC 5627 §4.4: "a 2xx or 18x response to an INVITE which contains a To
    // tag"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);
    deliver(&mut agent, &incoming_invite("gr1", Some(OFFER)), t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");

    agent.ring(call, None, t0).expect("180 goes");
    assert_eq!(
        header(&sent(&mut agent), HeaderName::Contact),
        angled(PUBLIC_GRUU)
    );
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    assert_eq!(
        header(&sent(&mut agent), HeaderName::Contact),
        angled(PUBLIC_GRUU)
    );
}

#[test]
fn a_refresh_that_leaves_the_service_route_out_clears_it() {
    // RFC 3608 §6.1: "If there is no Service-Route header field in the
    // response, the UA clears any service route for that address-of-record"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    let later = t0 + Duration::from_secs(3_060);
    agent.handle_timeout(later);
    let refresh = sent(&mut agent);
    let second = "sip:tgruu.second@example.com;gr";
    deliver(&mut agent, &serviced(&refresh, second, ""), later);
    let info = registered_info(&mut agent).expect("the refresh was granted");
    assert_eq!(info.service_route().len(), 0);
    assert!(info.associated().is_empty());
    let call_id = CallId::new(&header(&refresh, HeaderName::CallId));
    assert!(
        agent
            .endpoint()
            .call_record(&call_id)
            .is_some_and(|record| record.decisions().all(|decision| !matches!(
                decision.reason,
                Reason::ServiceRouteIgnored | Reason::GruuIgnored | Reason::AssociatedUriIgnored
            ))),
        "a field left out is not a field garbled"
    );
    // RFC 5627 §4.2: "The UA will receive a new temporary GRUU in each
    // successful REGISTER response"
    assert_eq!(info.temporary_gruu().map(Uri::as_str), Some(second));

    agent.call(id, &outgoing(), later).expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert!(
        routes(&invite).is_empty(),
        "the cleared route is not travelled"
    );
    assert_eq!(header(&invite, HeaderName::Contact), angled(PUBLIC_GRUU));
}

#[test]
fn what_a_registrar_garbled_is_not_trusted_and_is_written_down() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    let garbled = reply(
        &request,
        200,
        "OK",
        &format!(
            // a strict router beside a loose one, which RFC 3608 §5 rules out;
            // a public GRUU with no `gr`, and a temporary one with a header in
            // it; an associated identity outside the name-addr RFC 7315 asks for
            "Service-Route: <sip:p1.example.com;lr>, <sip:p2.example.com>\r\n\
             Contact: <sip:alice@192.0.2.1>;+sip.instance=\"<{INSTANCE}>\";expires=3600\
             ;pub-gruu=\"sip:alice@example.com\";temp-gruu=\"sip:tgruu.9@example.com;gr?Subject=x\"\r\n\
             P-Associated-URI: sip:bare@example.com\r\n"
        ),
    );
    deliver(&mut agent, &garbled, t0);

    let info = registered_info(&mut agent)
        .expect("what the registrar garbled does not undo the binding it granted");
    assert_eq!(
        info.service_route().len(),
        0,
        "a route with a hop it cannot travel is no route"
    );
    assert!(info.public_gruu().is_none(), "a URI with no gr is no GRUU");
    assert!(info.temporary_gruu().is_none());
    assert!(info.associated().is_empty());

    let call_id = CallId::new(&header(&request, HeaderName::CallId));
    let written: Vec<Reason> = agent
        .endpoint()
        .call_record(&call_id)
        .expect("the REGISTER has a record")
        .decisions()
        .map(|decision| decision.reason)
        .collect();
    for reason in [
        Reason::ServiceRouteIgnored,
        Reason::GruuIgnored,
        Reason::AssociatedUriIgnored,
    ] {
        assert!(written.contains(&reason), "no {reason} in {written:?}");
    }

    agent
        .call(id, &outgoing(), t0)
        .expect("the INVITE still goes");
    let invite = sent(&mut agent);
    assert!(routes(&invite).is_empty());
    assert_eq!(text(&invite, HeaderName::Contact), CONFIGURED);
}

#[test]
fn an_associated_uri_with_a_control_byte_in_it_is_not_reported() {
    // the list rides out to the application whole (§4.1's own event), and a
    // byte that never belongs in a URI is not something this stack repeats
    // just because a name-addr around it parsed
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    let hostile = reply(
        &request,
        200,
        "OK",
        "P-Associated-URI: <sip:ali\u{1}ce@example.com>\r\n",
    );
    deliver(&mut agent, &hostile, t0);
    let info = registered_info(&mut agent).expect("the binding stands");
    assert!(
        info.associated().is_empty(),
        "a control byte in the middle of it is not a byte a URI is written with"
    );
    let call_id = CallId::new(&header(&request, HeaderName::CallId));
    assert!(
        agent
            .endpoint()
            .call_record(&call_id)
            .is_some_and(|record| record
                .decisions()
                .any(|decision| decision.reason == Reason::AssociatedUriIgnored)),
        "the refusal is written down"
    );
}

#[test]
fn a_gruu_that_would_close_its_own_brackets_never_reaches_a_contact() {
    // RFC 5627 §7: the quoted string "MUST contain a SIP URI", and no SIP URI
    // holds a `>`, a `<` or a space (RFC 3261 §25.1). Unquoted and put back in
    // angle brackets, this one would end the Contact early and start a second
    // one that names somebody else
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    let hostile = reply(
        &request,
        200,
        "OK",
        &format!(
            "Contact: <sip:alice@192.0.2.1>;+sip.instance=\"<{INSTANCE}>\";expires=3600\
             ;pub-gruu=\"sip:alice@example.com;gr=x>,<sip:mallory@203.0.113.66\"\r\n"
        ),
    );
    deliver(&mut agent, &hostile, t0);
    let info = registered_info(&mut agent).expect("the binding stands");
    assert!(
        info.public_gruu().is_none(),
        "a value no SIP URI can hold is not a GRUU"
    );
    let call_id = CallId::new(&header(&request, HeaderName::CallId));
    assert!(
        agent
            .endpoint()
            .call_record(&call_id)
            .is_some_and(|record| record
                .decisions()
                .any(|decision| decision.reason == Reason::GruuIgnored)),
        "the refusal is written down"
    );

    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert_eq!(
        with(&invite, |message| message
            .field_values(HeaderName::Contact)
            .count()),
        1,
        "one Contact, and it is this device's"
    );
    assert_eq!(text(&invite, HeaderName::Contact), CONFIGURED);
}

#[test]
fn two_pub_gruus_on_one_contact_answer_the_same_question_twice() {
    // a second value is not a correction of the first; taking either would be
    // guessing which one the registrar meant
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    let confused = reply(
        &request,
        200,
        "OK",
        &format!(
            "Contact: <sip:alice@192.0.2.1>;+sip.instance=\"<{INSTANCE}>\";expires=3600\
             ;pub-gruu=\"{PUBLIC_GRUU}\";pub-gruu=\"sip:alice@example.com;gr=other\"\r\n"
        ),
    );
    deliver(&mut agent, &confused, t0);
    let info = registered_info(&mut agent).expect("the binding stands");
    assert!(
        info.public_gruu().is_none(),
        "two answers to the same question is not one taken over the other"
    );
    let call_id = CallId::new(&header(&request, HeaderName::CallId));
    assert!(
        agent
            .endpoint()
            .call_record(&call_id)
            .is_some_and(|record| record
                .decisions()
                .any(|decision| decision.reason == Reason::GruuIgnored)),
        "the refusal is written down"
    );
}

#[test]
fn a_service_route_hop_no_uri_can_hold_is_not_preloaded() {
    // RFC 3608 §6.3: every element "MUST conform to the syntax of a Route
    // element", and a `|` is in no SIP URI. Preloaded, it would ride on every
    // INVITE the account sends, and a strict next hop refuses every one
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    let hostile = reply(
        &request,
        200,
        "OK",
        "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n\
         Service-Route: <sip:p1.example.com;lr;x=a|b>\r\n",
    );
    deliver(&mut agent, &hostile, t0);
    let info = registered_info(&mut agent).expect("the binding stands");
    assert_eq!(info.service_route().len(), 0);
    let call_id = CallId::new(&header(&request, HeaderName::CallId));
    assert!(
        agent
            .endpoint()
            .call_record(&call_id)
            .is_some_and(|record| record
                .decisions()
                .any(|decision| decision.reason == Reason::ServiceRouteIgnored)),
        "the refusal is written down"
    );
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    assert!(routes(&sent(&mut agent)).is_empty());
}

#[test]
fn a_service_route_hop_with_a_header_component_is_not_preloaded() {
    // a hop carries a `?` component here only to smuggle a header into
    // whatever reads it next, and this stack is not the one meant to read it:
    // a preloaded route is a place this account writes to, not one it takes
    // instructions from
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    let hostile = reply(
        &request,
        200,
        "OK",
        "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n\
         Service-Route: <sip:p1.example.com;lr?Subject=x>\r\n",
    );
    deliver(&mut agent, &hostile, t0);
    let info = registered_info(&mut agent).expect("the binding stands");
    assert_eq!(info.service_route().len(), 0);
    let call_id = CallId::new(&header(&request, HeaderName::CallId));
    assert!(
        agent
            .endpoint()
            .call_record(&call_id)
            .is_some_and(|record| record
                .decisions()
                .any(|decision| decision.reason == Reason::ServiceRouteIgnored)),
        "the refusal is written down"
    );
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    assert!(routes(&sent(&mut agent)).is_empty());
}

#[test]
fn a_binding_the_stack_stopped_believing_in_lends_nothing_to_the_next_call() {
    // RFC 5627 §4.4: a UA "MUST have an active registration prior to using a
    // GRUU". A clock that did not run while the machine slept still reads the
    // binding as fifty minutes from lapsing, which is why a suspend makes it
    // unverified; what the registrar said about it is no better evidence
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    agent.suspending(t0);
    events(&mut agent);
    let woke = t0 + Duration::from_millis(4);
    assert!(
        agent.registrar_info(id, woke).is_none(),
        "an unverified binding has nothing the registrar said to lend"
    );
    agent.resumed(woke);
    transmits(&mut agent);
    events(&mut agent);

    agent.call(id, &outgoing(), woke).expect("the INVITE goes");
    let invite = transmits(&mut agent)
        .into_iter()
        .find(|message| message.starts_with(b"INVITE "))
        .expect("an INVITE");
    assert!(
        routes(&invite).is_empty(),
        "no service route from before the machine slept"
    );
    assert_eq!(text(&invite, HeaderName::Contact), CONFIGURED);
}

#[test]
fn nothing_the_registrar_said_outlives_the_binding_it_said_it_about() {
    // RFC 5627 §4.4: a UA "MUST NOT reuse a GRUU learned through a previous
    // registration that has lapsed"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    let lapsed = t0 + Duration::from_secs(3_600);
    assert!(agent.registrar_info(id, lapsed).is_none());
    agent
        .call(id, &outgoing(), lapsed)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert!(routes(&invite).is_empty());
    assert_eq!(text(&invite, HeaderName::Contact), CONFIGURED);
}

#[test]
fn a_refused_refresh_forgets_the_service_route_and_keeps_the_gruu() {
    // RFC 3608 §6.1: "If the re-registration request is refused ... the UA
    // SHOULD discard any stored service route"; RFC 5627 §4.2: a failed one
    // "does not remove, delete, or otherwise invalidate the GRUU"
    for (status, reason) in [(403, "Forbidden"), (503, "Service Unavailable")] {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(gruu_account());
        serviced_registration(&mut agent, id, SERVICES, t0);

        let later = t0 + Duration::from_secs(3_060);
        agent.handle_timeout(later);
        let refresh = sent(&mut agent);
        deliver(&mut agent, &reply(&refresh, status, reason, ""), later);
        events(&mut agent);

        agent.call(id, &outgoing(), later).expect("the INVITE goes");
        let invite = only(&transmits(&mut agent), "INVITE ");
        assert!(routes(&invite).is_empty(), "{status}: the route is dropped");
        assert_eq!(
            header(&invite, HeaderName::Contact),
            angled(PUBLIC_GRUU),
            "{status}: the binding stands until it lapses, and so does its GRUU"
        );
    }
}

#[test]
fn a_refresh_nobody_answered_keeps_the_service_route() {
    // a timeout is no answer at all, and says nothing about the route
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    let later = t0 + Duration::from_secs(3_060);
    agent.handle_timeout(later);
    transmits(&mut agent);
    let failed = later + Duration::from_secs(32);
    agent.handle_timeout(failed);
    transmits(&mut agent);
    events(&mut agent);
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Retrying)
    );

    agent
        .call(id, &outgoing(), failed)
        .expect("the INVITE goes");
    let invite = only(&transmits(&mut agent), "INVITE ");
    assert_eq!(routes(&invite).len(), 2);
}

#[test]
fn an_anonymous_call_names_a_temporary_gruu_and_never_the_public_one() {
    // RFC 5627 §3.3: "use one of its temporary GRUUs for anonymous calls, and
    // use its public GRUU otherwise"
    let privacy = HeaderName::Extension("Privacy");
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);
    agent
        .call(id, &outgoing().header(privacy, b"id"), t0)
        .expect("the INVITE goes");
    assert_eq!(
        header(&sent(&mut agent), HeaderName::Contact),
        angled(TEMPORARY_GRUU)
    );
    agent
        .call(id, &outgoing().header(privacy, b"none"), t0)
        .expect("the INVITE goes");
    assert_eq!(
        header(&sent(&mut agent), HeaderName::Contact),
        angled(PUBLIC_GRUU),
        "none is not a request for privacy"
    );

    // a registrar that gave only the public one
    let mut agent = self::agent(t0);
    let id = agent.add_account(gruu_account());
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    let public_only = reply(
        &request,
        200,
        "OK",
        &format!(
            "Contact: <sip:alice@192.0.2.1>;pub-gruu=\"{PUBLIC_GRUU}\"\
             ;+sip.instance=\"<{INSTANCE}>\";expires=3600\r\n"
        ),
    );
    deliver(&mut agent, &public_only, t0);
    events(&mut agent);
    agent
        .call(id, &outgoing().header(privacy, b"id"), t0)
        .expect("the INVITE goes");
    assert_eq!(
        text(&sent(&mut agent), HeaderName::Contact),
        CONFIGURED,
        "the public GRUU names the address of record the call is hiding"
    );
}

#[test]
fn a_reinvite_stops_naming_a_gruu_once_its_registration_has_lapsed() {
    // RFC 5627 §4.4: "MUST NOT reuse a GRUU learned through a previous
    // registration that has lapsed" -- a re-INVITE sent long into a call must
    // not keep repeating the Contact the INVITE opened with, unlike a
    // subscription's refresh, which already reads it fresh
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);
    let (call, _ack) = call_up(&mut agent, id, t0);

    // the binding was granted for 3600s and nothing has refreshed it
    let later = t0 + Duration::from_secs(3_700);
    agent.hold(call, later).expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
    assert_eq!(
        text(&reinvite, HeaderName::Contact),
        CONFIGURED,
        "the registration that issued the GRUU has lapsed"
    );
}

#[test]
fn a_call_that_outlives_its_account_still_names_a_contact() {
    // RFC 3261 §8.1.1.8 and §12.2.1.1: a re-INVITE carries the Contact the
    // far end retargets to, and an empty one is no URI at all. The account
    // being removed takes its registration with it, so there is no GRUU left
    // to name, but the plain contact the call was placed from still is one
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent.remove_account(id);
    agent.hold(call, t0).expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
    assert_eq!(
        text(&reinvite, HeaderName::Contact),
        "<sip:alice@192.0.2.1>",
        "{}",
        String::from_utf8_lossy(&reinvite)
    );
}

/// Whether any `Supported` field of a message lists `gruu`.
fn supports_gruu(bytes: &[u8]) -> bool {
    with(bytes, |message| {
        message
            .field_values(HeaderName::Supported)
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"gruu"))
    })
}

#[test]
fn supported_names_gruu_on_a_reinvite_and_on_the_answer_to_one() {
    // RFC 5627 §4.4 lists "a 2xx or 18x response to an INVITE which contains a
    // To tag" and asks for `Supported: gruu` on what a UA generates; a
    // re-INVITE is an INVITE, and so is the one the far end sends
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);
    let (call, ack) = call_up(&mut agent, id, t0);

    agent.hold(call, t0).expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
    assert!(
        supports_gruu(&reinvite),
        "the re-INVITE this end sends: {}",
        String::from_utf8_lossy(&reinvite)
    );
    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "gr-theirs", 1, Some(THEIR_HOLD)),
        t0,
    );
    let answer = last(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert!(
        supports_gruu(&answer),
        "the 200 this end sends to the far end's re-INVITE: {}",
        String::from_utf8_lossy(&answer)
    );
}

#[test]
fn a_call_sent_somewhere_else_takes_neither_the_route_nor_the_gruu() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    let elsewhere: SocketAddr = "192.0.2.200:5060".parse().expect("an address");
    agent
        .call(id, &outgoing().to_address(UDP, elsewhere), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert!(routes(&invite).is_empty());
    assert_eq!(text(&invite, HeaderName::Contact), CONFIGURED);

    agent
        .call(id, &outgoing().to_address(UDP, registrar()), t0)
        .expect("the INVITE goes");
    assert_eq!(
        routes(&sent(&mut agent)).len(),
        2,
        "naming the address the account registers with is not somewhere else"
    );
}

#[test]
fn giving_the_binding_up_forgets_what_the_registrar_said_about_it() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    agent.unregister(id, t0).expect("the REGISTER goes");
    let removal = sent(&mut agent);
    deliver(&mut agent, &reply(&removal, 200, "OK", ""), t0);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Unregistered { .. }))
    );
    assert!(agent.registrar_info(id, t0).is_none());

    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert!(routes(&invite).is_empty());
    assert_eq!(text(&invite, HeaderName::Contact), CONFIGURED);
}

#[test]
fn a_subscription_travels_the_service_route_and_refreshes_from_the_gruu() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    agent
        .subscribe(
            id,
            &Subscribe::new(uri("sip:bob@example.com"), "presence"),
            t0,
        )
        .expect("the SUBSCRIBE goes");
    let subscribe = sent(&mut agent);
    assert_eq!(routes(&subscribe).len(), 2);
    assert_eq!(header(&subscribe, HeaderName::Contact), angled(PUBLIC_GRUU));

    deliver(
        &mut agent,
        &answered(&subscribe, 200, "OK", "notifier", None),
        t0,
    );
    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            1,
            "notifier",
            "presence",
            "active;expires=600",
            None,
            "",
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(590));
    let refresh = only(&transmits(&mut agent), "SUBSCRIBE ");
    // RFC 5627 §4.4: a target refresh names the GRUU too; the route is the
    // dialog's own by now
    assert_eq!(header(&refresh, HeaderName::Contact), angled(PUBLIC_GRUU));
    assert!(routes(&refresh).is_empty());
}

#[test]
fn supported_names_gruu_on_the_subscribe_and_its_refresh() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    agent
        .subscribe(
            id,
            &Subscribe::new(uri("sip:bob@example.com"), "presence"),
            t0,
        )
        .expect("the SUBSCRIBE goes");
    let subscribe = sent(&mut agent);
    assert!(String::from_utf8_lossy(&header(&subscribe, HeaderName::Supported)).contains("gruu"));

    deliver(
        &mut agent,
        &answered(&subscribe, 200, "OK", "notifier", None),
        t0,
    );
    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            1,
            "notifier",
            "presence",
            "active;expires=600",
            None,
            "",
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(590));
    let refresh = only(&transmits(&mut agent), "SUBSCRIBE ");
    assert!(String::from_utf8_lossy(&header(&refresh, HeaderName::Supported)).contains("gruu"));
}

#[test]
fn a_restored_registration_carries_nothing_the_registrar_said() {
    // RFC 5627 §4.2 discards the temporary GRUUs of another Call-ID, and a
    // restored registration is not evidence of anything
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    let snapshot = agent
        .freeze_registration(id, t0)
        .expect("a live binding is written down");
    agent
        .thaw_registration(id, &snapshot, Duration::ZERO, t0)
        .expect("its own snapshot reads back");
    assert!(agent.registrar_info(id, t0).is_none());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert!(routes(&invite).is_empty());
    assert_eq!(text(&invite, HeaderName::Contact), CONFIGURED);
}

#[test]
fn a_binding_granted_for_nothing_takes_its_gruus_with_it() {
    // RFC 5627 §5.3: a contact that is removed loses its GRUUs with it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);

    let later = t0 + Duration::from_secs(3_060);
    agent.handle_timeout(later);
    let refresh = sent(&mut agent);
    deliver(&mut agent, &granted(&refresh, 0), later);
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Failed)
    );
    assert!(agent.registrar_info(id, later).is_none());
    agent.call(id, &outgoing(), later).expect("the INVITE goes");
    assert_eq!(
        text(
            &only(&transmits(&mut agent), "INVITE "),
            HeaderName::Contact
        ),
        CONFIGURED
    );
}

#[test]
fn a_registrar_that_says_more_than_is_carried_is_not_trusted() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    let hops = |count: usize| {
        (1..=count)
            .map(|n| format!("<sip:p{n}.example.com;lr>"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let identities = |count: usize| {
        (1..=count)
            .map(|n| format!("<sip:alias{n}@example.com>"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let saying = |request: &[u8], routes: usize, aliases: usize, user: usize| {
        let gruu = format!("sip:{}@example.com;gr", "u".repeat(user));
        reply(
            request,
            200,
            "OK",
            &format!(
                "Service-Route: {}\r\n\
                 Contact: <sip:alice@192.0.2.1>;+sip.instance=\"<{INSTANCE}>\";expires=3600\
                 ;pub-gruu=\"{gruu}\"\r\n\
                 P-Associated-URI: {}\r\n",
                hops(routes),
                identities(aliases)
            ),
        )
    };

    // one past every bound: nine hops, thirty-three identities, and a GRUU
    // of 513 bytes
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    deliver(&mut agent, &saying(&request, 9, 33, 494), t0);
    let info = registered_info(&mut agent).expect("the binding is still granted");
    assert_eq!(
        info.service_route().len(),
        0,
        "nine hops on every INVITE is not a route this stack carries"
    );
    assert!(
        info.associated().is_empty(),
        "thirty-three identities are more than are kept"
    );
    assert!(
        info.public_gruu().is_none(),
        "a GRUU longer than any registrar mints is not taken"
    );

    // and at every bound, all of it is kept
    let later = t0 + Duration::from_secs(3_060);
    agent.handle_timeout(later);
    let refresh = sent(&mut agent);
    deliver(&mut agent, &saying(&refresh, 8, 32, 493), later);
    let info = registered_info(&mut agent).expect("the refresh is granted");
    assert_eq!(info.service_route().len(), 8);
    assert_eq!(info.associated().len(), 32);
    assert_eq!(
        info.public_gruu().map(|gruu| gruu.as_str().len()),
        Some(512)
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
fn a_registrar_that_draws_a_new_nonce_every_time_still_only_gets_three_answers() {
    // the guard below this one turns on the nonce being the same. A registrar
    // that draws a fresh one for every refusal and never says `stale` walks
    // past it, and the exchange then runs one wrong password per round trip
    // for as long as the process lives -- which is the lock-out §22.1 is
    // about, arrived at the long way round. Nothing on the wire tells that
    // apart from a server ageing its nonces honestly, so the count is what
    // stops it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "wrong")));
    agent.register(id, t0).expect("the REGISTER goes");

    let mut answers = 0;
    let mut request = sent(&mut agent);
    for round in 0..12 {
        let refusal = format!(
            "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n{round}\", qop=\"auth\"\r\n"
        );
        deliver(
            &mut agent,
            &reply(&request, 401, "Unauthorized", &refusal),
            t0,
        );
        let out = transmits(&mut agent);
        events(&mut agent);
        let Some(next) = out.into_iter().next() else {
            break;
        };
        answers += 1;
        request = next;
    }
    assert_eq!(
        answers, 3,
        "the account was offered a wrong password {answers} times"
    );
    // and it is reported as what it is, rather than left ringing: the same
    // refusal the same-nonce guard produces, reached the other way
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Failed),
        "it stopped, but said nothing about why"
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

/// An account registered after one challenge, and the REGISTER that answered
/// it.
fn challenged_and_granted(agent: &mut UserAgent, id: AccountId, now: Instant) -> Vec<u8> {
    agent.register(id, now).expect("the REGISTER goes");
    let first = sent(agent);
    deliver(
        agent,
        &reply(&first, 401, "Unauthorized", REGISTRAR_CHALLENGE),
        now,
    );
    let retry = sent(agent);
    deliver(agent, &granted(&retry, 3_600), now);
    events(agent);
    retry
}

/// The one the registrar in these tests makes.
const REGISTRAR_CHALLENGE: &str =
    "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", qop=\"auth\"\r\n";

#[test]
fn a_refresh_carries_the_credentials_instead_of_paying_for_a_second_refusal() {
    // §22.2: "UAs SHOULD cache the credentials for a given value of the To
    // header field and 'realm' and attempt to re-use these values on the next
    // request for that destination." An hourly refresh that does not is an
    // hourly round trip nobody needed, and C3 counts round trips
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "open sesame")));
    challenged_and_granted(&mut agent, id, t0);

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = sent(&mut agent);
    let carried =
        String::from_utf8_lossy(&header(&refresh, HeaderName::Authorization)).into_owned();
    assert!(carried.starts_with("Digest "), "{carried}");
    assert!(carried.contains("nonce=\"abc123\""), "{carried}");
    assert!(carried.contains("nc=00000002"), "{carried}");
    assert_eq!(header(&refresh, HeaderName::CSeq), b"2 REGISTER");

    // and the registrar believes it the first time, so there is no second
    // round trip to pay for
    deliver(
        &mut agent,
        &granted(&refresh, 3_600),
        t0 + Duration::from_secs(3_060),
    );
    assert!(transmits(&mut agent).is_empty(), "nothing had to go again");
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
}

#[test]
fn a_refresh_whose_nonce_has_expired_answers_the_new_one_and_stops_there() {
    // RFC 7616 §3.3: `stale` says the nonce aged out and the credentials did
    // not. One more attempt is what the registrar is asking for
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "open sesame")));
    challenged_and_granted(&mut agent, id, t0);

    let at = t0 + Duration::from_secs(3_060);
    agent.handle_timeout(at);
    let refresh = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(
            &refresh,
            401,
            "Unauthorized",
            "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"def456\", \
qop=\"auth\", stale=true\r\n",
        ),
        at,
    );

    let answered = sent(&mut agent);
    let carried =
        String::from_utf8_lossy(&header(&answered, HeaderName::Authorization)).into_owned();
    assert!(carried.contains("nonce=\"def456\""), "{carried}");
    assert!(carried.contains("nc=00000001"), "a fresh nonce: {carried}");

    deliver(&mut agent, &granted(&answered, 3_600), at);
    assert!(transmits(&mut agent).is_empty(), "and it stopped there");
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
}

#[test]
fn a_refresh_with_a_password_the_registrar_refuses_still_stops_after_one_attempt() {
    // the lock-out guard has to hold for credentials that went out ahead of
    // the challenge as well as for ones that answered it: the registrar sees
    // one wrong password per refresh, not two
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "open sesame")));
    challenged_and_granted(&mut agent, id, t0);

    let at = t0 + Duration::from_secs(3_060);
    agent.handle_timeout(at);
    let refresh = sent(&mut agent);
    // the same nonce, and no `stale`: §22.1's "credentials that have just been
    // rejected"
    deliver(
        &mut agent,
        &reply(&refresh, 401, "Unauthorized", REGISTRAR_CHALLENGE),
        at,
    );

    assert!(
        transmits(&mut agent).is_empty(),
        "nothing goes out a second time"
    );
    let failed = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::RegistrationFailed { reason, .. } => Some(reason),
            _ => None,
        })
        .expect("the refusal is reported");
    assert_eq!(failed, RegistrationFailure::BadCredentials);
}

#[test]
fn an_account_with_no_password_is_no_worse_off_than_before() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    registered(&mut agent, id, 3_600, t0);

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = sent(&mut agent);
    assert!(header(&refresh, HeaderName::Authorization).is_empty());
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

// -- a registrar that moves ---------------------------------------------

#[test]
fn a_registrar_that_does_not_answer_is_retargeted_to_the_next_srv_target() {
    // the scenario the plan names: a registrar that does not answer, a
    // retarget to the second SRV target, a REGISTER on the new address
    // carrying the same Call-ID with the sequence number continued
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("the first REGISTER goes");
    let first = sent(&mut agent);
    assert_eq!(header(&first, HeaderName::CSeq), b"1 REGISTER");

    // timer F: thirty-two seconds and nothing ever came back
    agent.handle_timeout(t0 + Duration::from_secs(32));
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::RegistrationFailed { .. })),
        "the registrar's silence is a failure this layer can observe"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Retrying),
        "backed off, not given up on"
    );

    agent
        .retarget(id, elsewhere(), t0 + Duration::from_secs(32))
        .expect("retargeting a registered account");
    let retried = agent.poll_transmit().expect("the retarget resent at once");
    assert_eq!(
        retried.destination,
        elsewhere(),
        "the second SRV target, not the one that never answered"
    );
    assert_eq!(header(&retried.payload, HeaderName::CSeq), b"2 REGISTER");
    assert_eq!(
        header(&retried.payload, HeaderName::CallId),
        header(&first, HeaderName::CallId),
        "one Call-ID for the whole boot cycle, 10.2.4"
    );
}

#[test]
fn a_retarget_mid_refresh_supersedes_it_rather_than_restarting_the_binding() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    registered(&mut agent, id, 3_600, t0);

    // a refresh goes out and is left unanswered, in flight, when the
    // registrar's address changes under it
    let t1 = t0 + crate::registration::refresh_after(Duration::from_secs(3_600));
    agent.handle_timeout(t1);
    let refresh = sent(&mut agent);
    assert_eq!(header(&refresh, HeaderName::CSeq), b"2 REGISTER");
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Refreshing)
    );

    agent
        .retarget(id, elsewhere(), t1)
        .expect("retargeting mid-refresh");
    let superseding = agent
        .poll_transmit()
        .expect("the account's next attempt goes at once");
    assert_eq!(superseding.destination, elsewhere());
    assert_eq!(
        header(&superseding.payload, HeaderName::CSeq),
        b"3 REGISTER",
        "the sequence number keeps growing rather than restarting"
    );
    assert_eq!(
        header(&superseding.payload, HeaderName::CallId),
        header(&refresh, HeaderName::CallId),
        "the same binding, not a new one"
    );

    // the refresh still out there on the old address is nobody's business
    // any more: answering it does not confuse the account that moved on.
    // `send_register`'s "one entry per account" rule already drops the old
    // attempt's ownership the moment the superseding one is sent, so this
    // arrives unclaimed rather than being read as this account's refresh
    // succeeding
    deliver(&mut agent, &granted(&refresh, 3_600), t1);
    let seen = events(&mut agent);
    assert!(
        !seen
            .iter()
            .any(|event| matches!(event, UaEvent::Registered { account, .. } if *account == id)),
        "a stale 200 from the address this account moved off of must not \
         read as this account's registration succeeding: {seen:?}"
    );
}

#[test]
fn retargeting_to_the_address_an_account_is_already_on_does_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    registered(&mut agent, id, 3_600, t0);

    agent
        .retarget(id, registrar(), t0)
        .expect("retargeting to the same address");
    assert!(
        agent.poll_transmit().is_none(),
        "nothing needed sending: the account was already there"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
}

#[test]
fn a_trunk_has_no_registrar_to_retarget() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(trunk());
    assert_eq!(
        agent.retarget(id, elsewhere(), t0),
        Err(UaError::NoRegistrar)
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

/// A de-registration the registrar refused for now, or never answered, is
/// retried as a de-registration: an account the application asked to leave
/// never asks for its binding back on a retry.
#[test]
fn a_de_registration_that_failed_is_retried_as_one_and_never_registers_again() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    registered(&mut agent, id, 3_600, t0);
    let retry_in = |agent: &mut UserAgent| {
        events(agent)
            .into_iter()
            .find_map(|event| match event {
                UaEvent::RegistrationFailed { retry_in, .. } => retry_in,
                _ => None,
            })
            .expect("a retry is scheduled")
    };

    agent.unregister(id, t0).expect("the de-registration goes");
    let leaving = sent(&mut agent);
    assert_eq!(header(&leaving, HeaderName::Expires), b"0");
    deliver(
        &mut agent,
        &reply(&leaving, 500, "Server Internal Error", ""),
        t0,
    );
    let wait = retry_in(&mut agent);
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Unregistered),
        "an account on its way out is not retrying a registration"
    );

    // the retry, which this time goes unanswered until the transaction
    // gives up on it (RFC 3261 §17.1.2.2, Timer F)
    let mut at = t0 + wait;
    agent.handle_timeout(at);
    let again = sent(&mut agent);
    assert!(again.starts_with(b"REGISTER "));
    assert_eq!(
        header(&again, HeaderName::Expires),
        b"0",
        "the retry asked for the binding back"
    );
    let gave_up = at + Duration::from_secs(33);
    while at < gave_up {
        at += Duration::from_millis(500);
        agent.handle_timeout(at);
        let _ = transmits(&mut agent);
    }
    let wait = retry_in(&mut agent);

    at += wait;
    agent.handle_timeout(at);
    let third = sent(&mut agent);
    assert_eq!(
        header(&third, HeaderName::Expires),
        b"0",
        "the retry after a timeout asked for the binding back"
    );
    deliver(&mut agent, &reply(&third, 200, "OK", ""), at);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Unregistered { .. }))
    );
    agent.handle_timeout(at + HOUR);
    assert!(
        transmits(&mut agent).is_empty(),
        "an account that left sent something more"
    );
}

// -- what this layer does not claim ------------------------------------------

#[test]
fn a_request_this_layer_has_no_policy_for_is_passed_through_whole() {
    // an INFO in a call that is not DTMF, handed over because the
    // application said it answers those itself: it reaches the application
    // as the core wrote it rather than being dropped. INFO used to be this
    // test's example unconditionally, and then MESSAGE, then PUBLISH; 8.3.11
    // and 8.6.5 gave the first two a policy of their own, and 8.7.4 has
    // every in-dialog request nothing claims answered here, so only what
    // the application asked for still proves the point
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.hand_over_info(true);
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

    let info = carrying(
        &in_dialog(&ok, "INFO", "in1info", 2),
        "application/media_control+xml",
        "",
        "<media_control/>",
    );
    deliver(&mut agent, &info, t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "the application answers it"
    );
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            event,
            UaEvent::Unclaimed(sipral_core::endpoint::Event::IncomingInDialog { request, .. })
                if request.as_raw().body() == b"<media_control/>"
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

pub(crate) const OFFER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
pub(crate) const ANSWER: &[u8] =
    b"v=0\r\no=- 2 2 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";

pub(crate) fn outgoing() -> OutgoingCall {
    OutgoingCall::new(uri("sip:bob@example.com")).offer(Arc::from(OFFER))
}

/// A response to a request the agent wrote, with a `To` tag that names a
/// dialog and a body when there is one.
pub(crate) fn answered(
    request: &[u8],
    status: u16,
    reason: &str,
    tag: &str,
    body: Option<&[u8]>,
) -> Vec<u8> {
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
pub(crate) fn incoming_invite(branch: &str, body: Option<&[u8]>) -> Vec<u8> {
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

pub(crate) fn text(bytes: &[u8], name: HeaderName<'_>) -> String {
    String::from_utf8_lossy(&header(bytes, name)).into_owned()
}

/// A request the far end sends inside a dialog.
pub(crate) fn peer_request(
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
pub(crate) fn in_dialog(ours: &[u8], method: &str, branch: &str, cseq: u32) -> Vec<u8> {
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
pub(crate) fn reversed(
    ours: &[u8],
    method: &str,
    branch: &str,
    cseq: u32,
    body: Option<&[u8]>,
) -> Vec<u8> {
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

/// An INFO from the far end, inside a dialog this end opened (mirroring
/// `reversed`'s tags), carrying a body of whatever `Content-Type` the caller
/// names — `reversed`'s own body is always `application/sdp`, which the DTMF
/// bodies never are.
fn incoming_info(
    ack: &[u8],
    branch: &str,
    cseq: u32,
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut out = format!(
        "INFO sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: {}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {cseq} INFO\r\n\
Contact: <sip:bob@192.0.2.9>\r\n",
        text(ack, HeaderName::To),
        text(ack, HeaderName::From),
        text(ack, HeaderName::CallId),
    )
    .into_bytes();
    if let Some(content_type) = content_type {
        out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

fn body_of(bytes: &[u8]) -> String {
    with(bytes, |message| {
        String::from_utf8_lossy(message.body()).into_owned()
    })
}

pub(crate) fn ended(agent: &mut UserAgent) -> Option<(CallHandle, CallEndReason)> {
    events(agent).into_iter().find_map(|event| match event {
        UaEvent::CallEnded { call, reason, .. } => Some((call, reason)),
        _ => None,
    })
}

/// Place a call, take the 200, and be up.
pub(crate) fn call_up(
    agent: &mut UserAgent,
    account: AccountId,
    now: Instant,
) -> (CallHandle, Vec<u8>) {
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

/// Place the second leg of an attended transfer and have the target answer it.
fn consulted(agent: &mut UserAgent, from: CallHandle, now: Instant) -> (CallHandle, Vec<u8>) {
    let call = agent
        .consult(from, &outgoing(), now)
        .expect("the consultation INVITE goes");
    let invite = sent(agent);
    deliver(
        agent,
        &answered(&invite, 200, "OK", "target", Some(ANSWER)),
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
                ..
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

/// The INVITE's server transaction stays for 64*T1 after its 2xx (RFC 6026
/// §7.1), long enough for an application that answers from two places --
/// its own code and the system call screen -- to answer a second time. That
/// second answer used to send another 200 and put the call back to waiting
/// for an ACK, and the hangup after it sent no BYE.
#[test]
fn a_call_answered_once_is_not_answered_again() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("twice", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    assert!(ok.starts_with(b"SIP/2.0 200 OK\r\n"));

    assert!(matches!(
        agent.answer(call, Some(Arc::from(ANSWER)), t0),
        Err(UaError::WrongState(_))
    ));
    assert!(
        transmits(&mut agent).is_empty(),
        "no second 200 before the ACK"
    );

    let to = String::from_utf8_lossy(&header(&ok, HeaderName::To)).into_owned();
    let ack = format!(
        "ACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKtwice-ack;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: {to}\r\n\
Call-ID: incoming-twice\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n"
    );
    deliver(&mut agent, ack.as_bytes(), t0);
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::CallConfirmed { .. })),
        "the ACK confirms the call"
    );

    assert!(matches!(
        agent.answer(call, Some(Arc::from(ANSWER)), t0),
        Err(UaError::WrongState(CallState::Confirmed))
    ));
    assert!(
        transmits(&mut agent).is_empty(),
        "no second 200 after the ACK"
    );
    assert_eq!(
        agent.calls.get(&call).map(|held| held.state),
        Some(CallState::Confirmed)
    );

    agent.hangup(call, t0).expect("the BYE goes");
    assert!(sent(&mut agent).starts_with(b"BYE sip:bob@192.0.2.9 SIP/2.0\r\n"));
}

/// A quality report is asked for after the `CallEnded` event that names the
/// call, which is exactly the moment `finish` (`calls.rs`) has already
/// forgotten it. Without the snapshot `finish` stashes right before that,
/// `send_quality_report` would find no account to publish to at all —
/// silently, since it reports "nothing to do" the same way it does for a
/// call whose account never asked for a report.
#[test]
fn a_quality_report_still_finds_its_account_once_the_call_that_ended_is_forgotten() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().quality_report_uri(uri("sip:collector.example.org")));
    let (call, _) = call_up(&mut agent, id, t0);
    agent.hangup(call, t0).expect("the BYE goes");
    sent(&mut agent);
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::LocalHangup)
    );
    assert!(
        !agent.calls.contains_key(&call),
        "the fixture only proves what it claims to if the call is really gone"
    );

    let sent_report = agent
        .send_quality_report(call, &quality_metrics(), t0)
        .expect("a transport is bound, so the PUBLISH goes");
    assert!(
        sent_report,
        "the account asked for a report and the call is known well enough \
         to publish about, even though `finish` already forgot it"
    );
    let publish = sent(&mut agent);
    assert!(publish.starts_with(b"PUBLISH sip:collector.example.org SIP/2.0\r\n"));
}

/// A minimal, valid set of figures for [`crate::QualityReportMetrics`]: only
/// the account and call bookkeeping matters to the test that uses this, not
/// what the report says.
fn quality_metrics() -> crate::QualityReportMetrics {
    crate::QualityReportMetrics {
        local_addr: local(),
        local_ssrc: 1,
        remote_addr: registrar(),
        remote_ssrc: 2,
        start: std::time::SystemTime::UNIX_EPOCH,
        stop: std::time::SystemTime::UNIX_EPOCH,
        payload_type: 0,
        payload_desc: "PCMU",
        sample_rate: 8_000,
        loss_rate: 0,
        discard_rate: 0,
        burst_density: 0,
        burst_duration_ms: 0,
        gap_density: 0,
        gap_duration_ms: 0,
        gmin: 16,
        round_trip_delay_ms: 0,
        end_system_delay_ms: 0,
        jitter_buffer_adaptive: 0,
        jitter_buffer_rate: 0,
        jitter_buffer_nominal_ms: 0,
        jitter_buffer_maximum_ms: 0,
        jitter_buffer_abs_max_ms: 0,
        r_factor: None,
        mos_lq_x10: None,
        mos_cq_x10: None,
        remote: None,
    }
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

// -- credentials on a call ---------------------------------------------------

/// What a PBX challenges with: its own, as a UAS (§22.2), rather than a
/// proxy's Proxy-Authenticate (§22.3).
const CHALLENGE: &str = "WWW-Authenticate: Digest realm=\"asterisk\", \
                         nonce=\"abc123\", qop=\"auth\"\r\n";

fn credentialled() -> Account {
    account().credentials(Credentials::new("alice", "open sesame"))
}

/// A refusal that carries a challenge, with the `To` tag a UAS puts on it.
fn challenge(request: &[u8], status: u16, reason: &str, field: &str) -> Vec<u8> {
    let to = text(request, HeaderName::To);
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag=ast")
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

/// The 401 a PBX answers a request of ours with.
fn unauthorized(request: &[u8]) -> Vec<u8> {
    challenge(request, 401, "Unauthorized", CHALLENGE)
}

/// The one request out of `out` written with `method`.
fn only(out: &[Vec<u8>], method: &str) -> Vec<u8> {
    let mut found = out
        .iter()
        .filter(|bytes| bytes.starts_with(method.as_bytes()));
    let first = found
        .next()
        .unwrap_or_else(|| panic!("no {method} went out"));
    assert!(found.next().is_none(), "more than one {method} went out");
    first.clone()
}

/// What the credentials on a retry have to say, whichever header they are in.
fn credentials_of(bytes: &[u8], name: HeaderName<'_>) -> String {
    let value = text(bytes, name);
    assert!(value.starts_with("Digest "), "{value}");
    assert!(value.contains("username=\"alice\""), "{value}");
    assert!(value.contains("nonce=\"abc123\""), "{value}");
    assert!(
        !value.contains("open sesame"),
        "the password does not travel: {value}"
    );
    value
}

#[test]
fn an_invite_a_pbx_challenges_goes_again_with_credentials() {
    // 8.1.3.5: a 401 is answered by sending the request again with credentials
    // for the challenge, not by reporting the call refused. Asterisk
    // challenges as a UAS, so the challenge is WWW-Authenticate and the answer
    // is Authorization (§22.2)
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let first = sent(&mut agent);
    assert!(header(&first, HeaderName::Authorization).is_empty());

    deliver(&mut agent, &unauthorized(&first), t0);

    let out = transmits(&mut agent);
    // 17.1.1.3: the refusal is acknowledged before anything else happens
    let _ = only(&out, "ACK ");
    let retry = only(&out, "INVITE ");
    credentials_of(&retry, HeaderName::Authorization);
    // §22.2: the retry moves the CSeq on, and it is a new transaction
    assert_eq!(header(&retry, HeaderName::CSeq), b"2 INVITE");
    assert_ne!(
        text(&retry, HeaderName::Via),
        text(&first, HeaderName::Via),
        "a new branch is a new transaction"
    );
    assert_eq!(
        header(&retry, HeaderName::CallId),
        header(&first, HeaderName::CallId)
    );

    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::CallEnded { .. })),
        "the call is still being placed"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Calling));

    deliver(
        &mut agent,
        &answered(&retry, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let ack = sent(&mut agent);
    assert!(ack.starts_with(b"ACK "));
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_call_challenged_twice_with_the_same_nonce_gives_up_rather_than_looping() {
    // 22.1: the same nonce back without `stale` means the password was wrong,
    // and the registration path already stops there. A call does the same
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let first = sent(&mut agent);

    deliver(&mut agent, &unauthorized(&first), t0);
    let retry = only(&transmits(&mut agent), "INVITE ");
    events(&mut agent);

    deliver(&mut agent, &unauthorized(&retry), t0);
    let out = transmits(&mut agent);
    let _ = only(&out, "ACK ");
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"INVITE ")),
        "nothing goes out a third time"
    );
    assert_eq!(
        ended(&mut agent),
        Some((call, CallEndReason::Refused)),
        "the refusal is reported once the challenge has run out"
    );
    assert_eq!(agent.call_state(call), None);
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

#[test]
fn keeping_every_branch_still_hangs_up_one_that_answers_after_the_call_is_over() {
    // §13.2.2.4: every 2xx is acknowledged, and "if, after acknowledging any
    // 2xx response to an INVITE, the UAC does not want to continue with that
    // dialog, then the UAC MUST terminate the dialog by sending a BYE". The
    // call this INVITE placed has been hung up; the transaction still passes
    // the mobile's 2xx up inside timer M, and nobody here wants it
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
    agent.hangup(call, t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    deliver(&mut agent, &reply(&bye, 200, "OK", ""), t0);
    events(&mut agent);

    let later = t0 + Duration::from_secs(2);
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        later,
    );
    let out = transmits(&mut agent);
    assert!(
        out.iter()
            .any(|bytes| bytes.starts_with(b"ACK ") && tagged(bytes, "mobile")),
        "every 2xx is acknowledged: {out:?}"
    );
    assert!(
        out.iter()
            .any(|bytes| bytes.starts_with(b"BYE sip:bob@192.0.2.77 ") && tagged(bytes, "mobile")),
        "and the dialog nobody wants is ended: {out:?}"
    );
    let said = events(&mut agent);
    assert!(confirmed_calls(&said).is_empty(), "{said:?}");

    // the window closes with the transaction, and nothing is kept past it
    agent.handle_timeout(t0 + Duration::from_secs(64));
    transmits(&mut agent);
    events(&mut agent);
    assert!(agent.kept_branches.is_empty());
}

#[test]
fn keeping_every_branch_mints_a_late_one_beside_the_sibling_still_up() {
    // the call placed is over, its sibling is not: a third branch answering
    // now is one more leg of the fork the application asked to keep whole
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
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    transmits(&mut agent);
    let mobile = confirmed_calls(&events(&mut agent))
        .into_iter()
        .find(|confirmed| *confirmed != call)
        .expect("the mobile is a call of its own");
    agent.hangup(call, t0).expect("the BYE goes");
    transmits(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "voicemail", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(
        out.iter()
            .any(|bytes| bytes.starts_with(b"ACK ") && tagged(bytes, "voicemail")),
        "{out:?}"
    );
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "every leg is wanted: {out:?}"
    );
    let said = events(&mut agent);
    let forked = said.iter().find_map(|event| match *event {
        UaEvent::CallForked { call, sibling } if call == mobile => Some(sibling),
        _ => None,
    });
    let forked = forked.expect("a sibling of the leg still up");
    assert_eq!(confirmed_calls(&said), [forked]);
    assert_eq!(agent.call_state(mobile), Some(CallState::Confirmed));
}

#[test]
fn a_2xx_after_the_call_was_refused_is_acknowledged_and_hung_up() {
    // a proxy forwards every 2xx, even after the 486 it already sent
    // upstream (§16.7 step 5); the transaction passes it up (RFC 6026 §8.4),
    // and the call it would have been is over. §13.2.2.4: ACK, then BYE
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 486, "Busy Here", "desk", None),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::Refused)
    );

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(
        out.iter()
            .any(|bytes| bytes.starts_with(b"ACK sip:bob@192.0.2.77 ") && tagged(bytes, "mobile")),
        "{out:?}"
    );
    assert!(
        out.iter()
            .any(|bytes| bytes.starts_with(b"BYE sip:bob@192.0.2.77 ") && tagged(bytes, "mobile")),
        "{out:?}"
    );
    let said = events(&mut agent);
    assert!(confirmed_calls(&said).is_empty(), "{said:?}");
    assert!(
        !said
            .iter()
            .any(|event| matches!(event, UaEvent::Unclaimed(Event::Established { .. }))),
        "{said:?}"
    );

    // timer D ends the transaction, and the window with it
    agent.handle_timeout(t0 + Duration::from_secs(32));
    transmits(&mut agent);
    events(&mut agent);
    assert!(agent.kept_branches.is_empty());
}

/// What the second phone a proxy forked the INVITE to describes: a session
/// of its own, at an address of its own.
const MOBILE_ANSWER: &[u8] = b"v=0\r\no=- 3 3 IN IP4 192.0.2.77\r\ns=-\r\n\
c=IN IP4 192.0.2.77\r\nt=0 0\r\nm=audio 7000 RTP/AVP 0\r\n";

/// A response from that second phone: its own tag, and its own `Contact`.
fn from_the_mobile(request: &[u8], status: u16, reason: &str, body: Option<&[u8]>) -> Vec<u8> {
    String::from_utf8(answered(request, status, reason, "mobile", body))
        .expect("text")
        .replace("<sip:bob@192.0.2.9>", "<sip:bob@192.0.2.77>")
        .into_bytes()
}

/// The desk phone rings first and the mobile second, so the call placed is
/// the desk's early dialog and the mobile is its sibling.
fn rung_on_two_phones(
    agent: &mut UserAgent,
    invite: &[u8],
    call: CallHandle,
    now: Instant,
) -> CallHandle {
    deliver(agent, &answered(invite, 180, "Ringing", "desk", None), now);
    deliver(agent, &from_the_mobile(invite, 180, "Ringing", None), now);
    let sibling = events(agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallForked {
                call: parent,
                sibling,
            } if parent == call => Some(sibling),
            _ => None,
        })
        .expect("a proxy forked it");
    transmits(agent);
    sibling
}

fn confirmed_calls(said: &[UaEvent]) -> Vec<CallHandle> {
    said.iter()
        .filter_map(|event| match *event {
            UaEvent::CallConfirmed { call, .. } => Some(call),
            _ => None,
        })
        .collect()
}

fn ended_calls(said: &[UaEvent]) -> Vec<(CallHandle, CallEndReason)> {
    said.iter()
        .filter_map(|event| match *event {
            UaEvent::CallEnded { call, reason, .. } => Some((call, reason)),
            _ => None,
        })
        .collect()
}

fn tagged(bytes: &[u8], tag: &str) -> bool {
    text(bytes, HeaderName::To).contains(&format!("tag={tag}"))
}

#[test]
fn a_second_branch_that_answers_first_is_the_branch_kept() {
    // A proxy rang the desk and the mobile in parallel and the mobile was
    // picked up. KeepFirst keeps the first branch that answers, whichever it
    // is: the proxy has just forwarded that 2xx and is cancelling the desk,
    // so hanging up the mobile here would lose the call outright
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    let ack = only(&out, "ACK ");
    assert!(ack.starts_with(b"ACK sip:bob@192.0.2.77 "), "{out:?}");
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "the branch that answered first was hung up"
    );
    let said = events(&mut agent);
    assert_eq!(confirmed_calls(&said), vec![mobile], "{said:?}");
    assert_eq!(
        ended_calls(&said),
        vec![(call, CallEndReason::ForkLost)],
        "the desk that never answered is let go, and says why"
    );
    assert_eq!(agent.call_state(mobile), Some(CallState::Confirmed));
    assert_eq!(agent.call_state(call), None);
    assert_eq!(
        agent.call_identity(mobile).map(|identity| identity.call_id),
        Some(Box::from(header(&invite, HeaderName::CallId))),
        "the branch kept is the call placed: same Call-ID, same parties"
    );

    // the desk answers anyway, too late: acknowledged, and then hung up
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "desk"), "{out:?}");
    assert!(tagged(&only(&out, "BYE "), "desk"), "{out:?}");
    assert!(
        events(&mut agent).is_empty(),
        "a branch already let go is news to nobody"
    );
    assert_eq!(
        agent.call_state(mobile),
        Some(CallState::Confirmed),
        "the branch kept is untouched"
    );

    // and the branch kept is a call like any other: a hold goes to the
    // mobile, in its dialog, from the session its 2xx described
    agent.hold(mobile, t0).expect("the kept branch can be held");
    let reinvite = sent(&mut agent);
    assert!(
        reinvite.starts_with(b"INVITE sip:bob@192.0.2.77 "),
        "{}",
        String::from_utf8_lossy(&reinvite)
    );
    assert!(tagged(&reinvite, "mobile"));
    assert!(body_of(&reinvite).contains("a=sendonly"));
}

#[test]
fn a_first_branch_that_answers_first_is_kept_and_its_siblings_let_go() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "desk"));
    assert!(!out.iter().any(|bytes| bytes.starts_with(b"BYE ")));
    let said = events(&mut agent);
    assert_eq!(confirmed_calls(&said), vec![call]);
    assert_eq!(ended_calls(&said), vec![(mobile, CallEndReason::ForkLost)]);

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "mobile"));
    assert!(tagged(&only(&out, "BYE "), "mobile"));
    assert!(events(&mut agent).is_empty());
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn two_answers_read_together_keep_the_one_that_arrived_first() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);

    // both in before anything is written or reported
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    let acks: Vec<&Vec<u8>> = out
        .iter()
        .filter(|bytes| bytes.starts_with(b"ACK "))
        .collect();
    assert_eq!(acks.len(), 2, "every 2xx is acknowledged: {out:?}");
    assert!(tagged(&only(&out, "BYE "), "desk"), "{out:?}");
    let said = events(&mut agent);
    assert_eq!(confirmed_calls(&said), vec![mobile], "{said:?}");
    assert_eq!(ended_calls(&said), vec![(call, CallEndReason::ForkLost)]);
    assert_eq!(agent.call_state(mobile), Some(CallState::Confirmed));
}

#[test]
fn a_branch_that_answers_after_the_call_was_given_up_is_hung_up() {
    // the CANCEL covers every branch at the proxy (§16.10), and a 2xx that
    // crossed it on the mobile is acknowledged and hung up like one that
    // crossed it on the desk: nothing is kept of a call the user put down
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);
    agent.hangup(call, t0).expect("the CANCEL goes");
    only(&transmits(&mut agent), "CANCEL ");
    events(&mut agent);

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "mobile"), "{out:?}");
    assert!(tagged(&only(&out, "BYE "), "mobile"));
    let said = events(&mut agent);
    assert!(
        confirmed_calls(&said).is_empty(),
        "a call on its way down was reported up: {said:?}"
    );
    assert_eq!(
        ended_calls(&said),
        vec![(mobile, CallEndReason::LocalHangup)],
        "a call hung up is not a fork lost"
    );
    // and the desk, which the proxy stopped ringing, goes when the window
    // for answers closes (§13.2.2.4)
    agent.handle_timeout(t0 + Duration::from_secs(40));
    transmits(&mut agent);
    assert!(agent.call_state(call).is_none());
}

#[test]
fn a_transfer_answered_on_a_second_branch_is_reported_answered() {
    // RFC 3515 §2.4.4: the transferor hears how the call it asked for went,
    // and the mobile picking up is that call answered, not a 408
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (_call, placed, invite) = refer_taken(&mut agent, t0);
    rung_on_two_phones(&mut agent, &invite, placed, t0);

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let said = notifies(&transmits(&mut agent));
    assert!(
        said.iter().any(|(state, body)| body.starts_with("SIP/2.0 200")
            && state.starts_with("terminated")),
        "the transferor is never told the target answered: {said:?}"
    );
    events(&mut agent);
    // the answer window closing, with the desk long let go, says nothing new:
    // what goes out then is the NOTIFYs already sent, unanswered in this test
    agent.handle_timeout(t0 + Duration::from_secs(40));
    let later = notifies(&transmits(&mut agent));
    assert!(
        later
            .iter()
            .all(|(_, body)| body.starts_with("SIP/2.0 1") || body.starts_with("SIP/2.0 200")),
        "the desk that was let go reported the transfer failed: {later:?}"
    );
}

#[test]
fn a_consultation_answered_on_a_second_branch_is_still_the_consultation() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);
    let second = agent
        .consult(first, &outgoing(), t0)
        .expect("the consultation INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, second, t0);
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert_eq!(agent.call_state(mobile), Some(CallState::Consulting));
    // the first call is still consulting, with the mobile now: one
    // consultation at a time, even after the branch it was placed on ended
    assert!(matches!(
        agent.consult(first, &outgoing(), t0),
        Err(UaError::WrongState(_))
    ));
    assert!(transmits(&mut agent).is_empty());

    agent
        .transfer_to(first, mobile, t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    let refer_to = String::from_utf8_lossy(&header(&refer, HeaderName::ReferTo)).into_owned();
    assert!(refer_to.contains("%3Bto-tag%3Dmobile"), "{refer_to}");
}

#[test]
fn a_branch_that_answers_after_the_kept_one_has_ended_is_still_hung_up() {
    // §13.2.2.4 keeps the answer window open for 64*T1 after the first 2xx,
    // whatever became of the call it confirmed: the desk was kept and hung up
    // already, and the mobile answering now is acknowledged and let go
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    rung_on_two_phones(&mut agent, &invite, call, t0);
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    agent.hangup(call, t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    deliver(&mut agent, &reply(&bye, 200, "OK", ""), t0);
    let said = events(&mut agent);
    assert_eq!(ended_calls(&said), vec![(call, CallEndReason::LocalHangup)]);
    assert_eq!(agent.call_state(call), None);

    let later = t0 + Duration::from_secs(5);
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        later,
    );
    let out = transmits(&mut agent);
    let ack = only(&out, "ACK ");
    assert!(tagged(&ack, "mobile"), "{out:?}");
    let bye = only(&out, "BYE ");
    assert!(tagged(&bye, "mobile"));
    assert!(bye.starts_with(b"BYE sip:bob@192.0.2.77 "));
    assert!(
        events(&mut agent).is_empty(),
        "a call already over came back to life"
    );
}

/// Hang up the one call a 2xx left standing: the BYE this layer sent by
/// itself, answered.
fn bye_answered(agent: &mut UserAgent, out: &[Vec<u8>], now: Instant) {
    let bye = only(out, "BYE ");
    deliver(agent, &reply(&bye, 200, "OK", ""), now);
}

#[test]
fn a_second_branch_answering_a_call_given_up_before_it_rang_is_hung_up() {
    // the user put the call down before anything came back, so the CANCEL
    // never left (§9.1) and the desk's 2xx is acknowledged and hung up. The
    // call is over once that BYE is answered, and the mobile's 2xx inside
    // the answer window still owes an ACK and a BYE (§13.2.2.4)
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    agent.hangup(call, t0).expect("the CANCEL waits");
    assert!(transmits(&mut agent).is_empty(), "a CANCEL before a 1xx");
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "desk"), "{out:?}");
    bye_answered(&mut agent, &out, t0);
    events(&mut agent);
    assert_eq!(agent.call_state(call), None);

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "mobile"), "{out:?}");
    assert!(tagged(&only(&out, "BYE "), "mobile"));
    let said = events(&mut agent);
    assert!(
        !said.iter().any(|event| matches!(
            *event,
            UaEvent::CallForked { .. } | UaEvent::CallConfirmed { .. }
        )),
        "a call the user put down came back: {said:?}"
    );
}

#[test]
fn a_second_branch_answering_after_a_cancel_lost_on_the_first_is_hung_up() {
    // the CANCEL crossed the desk's 2xx, which was acknowledged and hung up,
    // and that BYE has been answered: the mobile's 2xx arriving after it is
    // one more the CANCEL lost to
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
    agent.hangup(call, t0).expect("the CANCEL goes");
    only(&transmits(&mut agent), "CANCEL ");
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "desk"), "{out:?}");
    bye_answered(&mut agent, &out, t0);
    events(&mut agent);
    assert_eq!(agent.call_state(call), None);

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "mobile"), "{out:?}");
    assert!(tagged(&only(&out, "BYE "), "mobile"));
    let said = events(&mut agent);
    assert!(
        !said.iter().any(|event| matches!(
            *event,
            UaEvent::CallForked { .. } | UaEvent::CallConfirmed { .. }
        )),
        "a call the user put down came back: {said:?}"
    );
}

#[test]
fn two_branches_that_both_cross_a_cancel_are_each_acknowledged_and_hung_up_once() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);
    agent.hangup(call, t0).expect("the CANCEL goes");
    only(&transmits(&mut agent), "CANCEL ");
    events(&mut agent);

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "mobile"), "{out:?}");
    assert!(tagged(&only(&out, "BYE "), "mobile"));
    events(&mut agent);

    // the desk's 2xx crossed the CANCEL too, and the desk's call is still
    // waiting for the window to close
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "desk"), "{out:?}");
    assert!(tagged(&only(&out, "BYE "), "desk"), "{out:?}");
    let said = events(&mut agent);
    assert!(confirmed_calls(&said).is_empty(), "{said:?}");
    assert_eq!(agent.call_state(mobile), None);
}

#[test]
fn a_branch_never_heard_of_that_answers_after_one_was_kept_is_hung_up() {
    // the proxy forwards every 2xx (§16.7 step 5), including one from a
    // branch whose provisionals never reached this end
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
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "mobile"), "{out:?}");
    assert!(tagged(&only(&out, "BYE "), "mobile"));
    let said = events(&mut agent);
    assert!(
        !said.iter().any(|event| matches!(
            *event,
            UaEvent::CallForked { .. } | UaEvent::CallConfirmed { .. } | UaEvent::CallEnded { .. }
        )),
        "a branch too late became a call: {said:?}"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_branch_let_go_that_rings_again_is_news_to_nobody() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    // the desk, which the proxy is cancelling, rings once more on its way
    deliver(
        &mut agent,
        &answered(&invite, 180, "Ringing", "desk", None),
        t0,
    );
    deliver(
        &mut agent,
        &answered(&invite, 183, "Session Progress", "desk", Some(ANSWER)),
        t0,
    );
    let said = events(&mut agent);
    assert!(said.is_empty(), "a branch let go still reports: {said:?}");
    assert!(transmits(&mut agent).is_empty());
    assert_eq!(agent.call_state(mobile), Some(CallState::Confirmed));
}

#[test]
fn a_second_branch_kept_is_reached_at_its_own_contact_along_its_own_route() {
    // §12.1.2: the dialog the mobile's 2xx opened has its own remote target
    // (the Contact) and its own route set (the Record-Route, reversed), and
    // every request inside it — a hold, a transfer, the BYE — follows them
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);
    let routed = String::from_utf8(from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)))
        .expect("text")
        .replace(
            "Contact: <sip:bob@192.0.2.77>\r\n",
            "Record-Route: <sip:edge.example.com;lr>\r\n\
             Contact: <sip:bob@192.0.2.77>\r\n",
        )
        .into_bytes();
    deliver(&mut agent, &routed, t0);
    let ack = only(&transmits(&mut agent), "ACK ");
    assert!(ack.starts_with(b"ACK sip:bob@192.0.2.77 "));
    assert_eq!(text(&ack, HeaderName::Route), "<sip:edge.example.com;lr>");
    events(&mut agent);

    agent.hold(mobile, t0).expect("the hold goes");
    let reinvite = sent(&mut agent);
    assert!(reinvite.starts_with(b"INVITE sip:bob@192.0.2.77 "));
    assert!(tagged(&reinvite, "mobile"));
    assert_eq!(
        text(&reinvite, HeaderName::Route),
        "<sip:edge.example.com;lr>"
    );
    assert_eq!(
        header(&reinvite, HeaderName::CallId),
        header(&invite, HeaderName::CallId)
    );
    deliver(
        &mut agent,
        &from_the_mobile(&reinvite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent
        .transfer(mobile, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    assert!(
        refer.starts_with(b"REFER sip:bob@192.0.2.77 "),
        "{}",
        String::from_utf8_lossy(&refer)
    );
    assert!(tagged(&refer, "mobile"));
    assert_eq!(text(&refer, HeaderName::Route), "<sip:edge.example.com;lr>");
    deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
    transmits(&mut agent);
    events(&mut agent);

    agent.hangup(mobile, t0).expect("the BYE goes");
    let bye = only(&transmits(&mut agent), "BYE ");
    assert!(bye.starts_with(b"BYE sip:bob@192.0.2.77 "));
    assert!(tagged(&bye, "mobile"));
    assert_eq!(text(&bye, HeaderName::Route), "<sip:edge.example.com;lr>");
}

#[test]
fn a_second_branch_kept_refreshes_the_session_the_call_placed_asked_for() {
    // RFC 4028 §7.2: a 2xx that says nothing about timers leaves the session
    // on the interval the INVITE asked for, with this end refreshing it. The
    // INVITE was the call placed's, and the mobile's branch kept is that call
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().session_interval(Some(Duration::from_secs(600))));
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert_eq!(header(&invite, HeaderName::SessionExpires), b"600");
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(300));
    let refresh = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the kept branch's session is never refreshed");
    assert!(refresh.starts_with(b"INVITE sip:bob@192.0.2.77 "));
    assert!(tagged(&refresh, "mobile"));
    assert_eq!(agent.call_state(mobile), Some(CallState::Confirmed));
}

#[test]
fn the_answer_window_closing_forgets_the_branch_kept() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert_eq!(agent.kept_branches.len(), 1);

    // Timer M, 64*T1 after the first 2xx (RFC 6026 §7.2)
    agent.handle_timeout(t0 + Duration::from_secs(33));
    transmits(&mut agent);
    events(&mut agent);
    assert!(agent.kept_branches.is_empty(), "the window stayed open");
    assert_eq!(agent.call_state(mobile), Some(CallState::Confirmed));
}

#[test]
fn keeping_every_branch_leaves_the_first_ringing_when_a_second_answers() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent
        .call(id, &outgoing().forks(ForkPolicy::KeepAll), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "mobile"));
    let said = events(&mut agent);
    assert_eq!(confirmed_calls(&said), vec![mobile]);
    assert!(ended_calls(&said).is_empty(), "{said:?}");
    assert_eq!(agent.call_state(call), Some(CallState::Ringing));
    assert!(agent.kept_branches.is_empty());

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(tagged(&only(&out, "ACK "), "desk"));
    assert!(!out.iter().any(|bytes| bytes.starts_with(b"BYE ")));
    assert_eq!(confirmed_calls(&events(&mut agent)), vec![call]);
}

#[test]
fn an_offerless_call_keeps_the_second_branch_and_leaves_the_answer_to_it() {
    // the offer comes back in the 2xx and the answer goes in the ACK, which
    // only the application can write: the branch kept waits for it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent
        .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    let mobile = rung_on_two_phones(&mut agent, &invite, call, t0);
    deliver(
        &mut agent,
        &from_the_mobile(&invite, 200, "OK", Some(MOBILE_ANSWER)),
        t0,
    );
    assert!(transmits(&mut agent).is_empty(), "an ACK with no answer");
    let said = events(&mut agent);
    assert!(said.iter().any(|event| matches!(
        *event,
        UaEvent::CallConfirmed {
            call: confirmed,
            answer_wanted: true,
            ..
        } if confirmed == mobile
    )));
    assert_eq!(ended_calls(&said), vec![(call, CallEndReason::ForkLost)]);
    agent
        .acknowledge(mobile, Some(OFFER), t0)
        .expect("the ACK goes");
    let ack = sent(&mut agent);
    assert!(ack.starts_with(b"ACK sip:bob@192.0.2.77 "));
    assert!(tagged(&ack, "mobile"));
    assert_eq!(agent.call_state(mobile), Some(CallState::Confirmed));
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
                ..
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

/// The same held call, re-offered on PCMA with the direction turned back up.
const RESUMED_ON_PCMA: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 8\r\na=sendrecv\r\n";
/// What the far end says to it.
const THEIR_PCMA: &[u8] = b"v=0\r\no=- 2 4 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 8\r\n";

#[test]
fn a_reoffer_that_resumes_a_held_call_leaves_it_resumed() {
    // the flag used to be kept from before the re-offer, so a description
    // that resumed the call left it reading as held — and the next hold,
    // finding it held already, sent nothing and said it had worked
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

    agent
        .reoffer(call, RESUMED_ON_PCMA, t0)
        .expect("the re-INVITE goes");
    let again = sent(&mut agent);
    deliver(
        &mut agent,
        &answered(&again, 200, "OK", "desk", Some(THEIR_PCMA)),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: false,
            remote: false
        })
    );

    agent.hold(call, t0).expect("the re-INVITE goes");
    let held = sent(&mut agent);
    assert!(held.starts_with(b"INVITE "), "the second hold went nowhere");
    assert!(body_of(&held).contains("a=sendonly\r\n"));
}

#[test]
fn a_codec_change_keeps_a_held_call_held() {
    // RFC 3264 §8.3.2 changes the formats and nothing else: whoever wrote the
    // description said sendrecv, and the call is still held
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

    agent
        .change_formats(call, RESUMED_ON_PCMA, t0)
        .expect("the re-INVITE goes");
    let change = sent(&mut agent);
    let offer = body_of(&change);
    assert!(offer.contains("m=audio 8000 RTP/AVP 8\r\n"), "{offer}");
    assert!(offer.contains("a=sendonly\r\n"), "{offer}");
    assert!(!offer.contains("a=sendrecv\r\n"), "{offer}");
    // RFC 3264 §8: past the hold's own version, whatever the caller wrote
    assert!(offer.contains("o=- 1 3 IN IP4 192.0.2.1\r\n"), "{offer}");
    deliver(
        &mut agent,
        &answered(&change, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(true));
}

#[test]
fn a_codec_change_on_a_call_held_from_the_far_end_does_not_hold_it_from_here() {
    // this end's last description is its answer to their hold, recvonly — a
    // statement about what they asked for, which copied into an offer would
    // tell them this end will not send either
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "theirhold", 1, Some(THEIR_HOLD)),
        t0,
    );
    deliver(&mut agent, &reversed(&ack, "ACK", "theirack", 1, None), t0);
    transmits(&mut agent);
    events(&mut agent);

    let copied: &[u8] = b"v=0\r\no=- 1 2 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 8\r\na=recvonly\r\n";
    agent
        .change_formats(call, copied, t0)
        .expect("the re-INVITE goes");
    let offer = body_of(&sent(&mut agent));
    assert!(offer.contains("a=sendrecv\r\n"), "{offer}");
    assert!(!offer.contains("a=recvonly\r\n"), "{offer}");
}

/// A call keyed by SDES, from both ends.
const SECURED_OFFER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n";
const SECURED_ANSWER: &[u8] = b"v=0\r\no=- 2 2 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\n";
/// The far end holding it, every line it had repeated.
const THEIR_SECURED_HOLD: &[u8] =
    b"v=0\r\no=- 2 3 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\n\
a=sendonly\r\n";

#[test]
fn a_hold_from_the_far_end_on_a_secured_call_goes_to_whoever_holds_the_keys() {
    // the answer has to name the tag it took with this end's own key
    // (RFC 4568 §5.1.2), which is not a line this layer can write: the one it
    // used to write had no key at all, and the end that asked for the hold
    // saw its negotiation fail
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let placed = OutgoingCall::new(uri("sip:bob@example.com")).offer(Arc::from(SECURED_OFFER));
    agent.call(id, &placed, t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(SECURED_ANSWER)),
        t0,
    );
    let ack = sent(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "keyedhold", 1, Some(THEIR_SECURED_HOLD)),
        t0,
    );
    assert!(
        transmits(&mut agent)
            .iter()
            .all(|bytes| bytes.starts_with(b"SIP/2.0 100 ")),
        "the hold was answered by a layer holding no key"
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Reoffer { .. })),
        "the hold never reached the layer that can answer it"
    );
}

#[test]
fn an_answer_written_for_a_call_held_here_keeps_it_held() {
    // the application answers the far end's codec change the way it answers
    // any offer, sendrecv. Sent as written, that takes the call off hold on
    // the wire while this end still says it is held
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);
    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    let ack = sent(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "codecwhileheld", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    let listening: &[u8] = b"v=0\r\no=- 1 4 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 8\r\na=sendrecv\r\n";
    agent
        .accept_reoffer(call, listening, t0)
        .expect("the 200 goes");
    let answer = body_of(&sent(&mut agent));
    assert!(answer.contains("a=sendonly\r\n"), "{answer}");
    assert!(!answer.contains("a=sendrecv\r\n"), "{answer}");
    assert!(answer.contains("m=audio 8000 RTP/AVP 8\r\n"), "{answer}");
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(true));
}

#[test]
fn an_answer_with_nothing_held_goes_out_byte_for_byte() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "codec", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    // written oddly on purpose: a layer that re-wrote it would tidy it
    let odd: &[u8] = b"v=0\r\no=- 1 2 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\na=sendrecv\r\nm=audio 8000 RTP/AVP 8\r\n";
    agent.accept_reoffer(call, odd, t0).expect("the 200 goes");
    assert_eq!(body_of(&sent(&mut agent)).as_bytes(), odd);
}

#[test]
fn an_answer_that_cannot_be_read_leaves_the_offer_waiting_to_be_answered() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "codec", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    assert!(matches!(
        agent.accept_reoffer(call, b"not a description", t0),
        Err(UaError::Sdp(_))
    ));
    agent
        .reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, t0)
        .expect("the request is still there to be refused");
    assert!(sent(&mut agent).starts_with(b"SIP/2.0 488 "));
}

#[test]
fn a_refresh_the_application_answers_still_says_what_the_session_timer_is() {
    // RFC 4028 §9: the 2xx to a refresh carries Session-Expires. A refresh
    // that also changes the codec is handed up, and its answer used to go
    // without one
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

    let mut refresh = reversed(&ack, "INVITE", "timedcodec", 1, Some(THEIR_NEW_CODEC));
    let head = refresh
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(refresh.len(), |at| at + 1);
    let mut with = refresh[..head].to_vec();
    with.extend_from_slice(b"Session-Expires: 600;refresher=uas\r\n");
    with.extend_from_slice(&refresh[head..]);
    refresh = with;
    deliver(&mut agent, &refresh, t0 + Duration::from_secs(300));
    transmits(&mut agent);
    events(&mut agent);

    agent
        .accept_reoffer(call, ANSWER, t0 + Duration::from_secs(300))
        .expect("the 200 goes");
    let answer = sent(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert_eq!(
        header(&answer, HeaderName::SessionExpires),
        b"600;refresher=uas"
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
fn the_answer_to_an_update_of_ours_reaches_the_session_it_belongs_to() {
    // an UPDATE is a non-INVITE transaction, and so is a REGISTER; the answer
    // to one has to survive the layer that owns the other
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
    let update = sent(&mut agent);
    deliver(
        &mut agent,
        &answered(&update, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: true,
            remote: false
        })
    );
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(true));
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
        .accept_reoffer(call, ANSWER, t0)
        .expect("the 200 goes");
    let answer = sent(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert!(body_of(&answer).contains("m=audio 9000 RTP/AVP 0\r\n"));
}

#[test]
fn an_accepted_reoffers_answer_past_the_configured_sdp_bound_is_refused() {
    let t0 = Instant::now();
    let mut config = EndpointConfig::default();
    config.sdp_limits = sdp::Limits {
        max_media: 1,
        ..sdp::Limits::DEFAULT
    };
    let mut agent = agent_with(config, t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "codec", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    let two_streams: &[u8] = b"v=0\r\no=- 2 2 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\nm=video 9002 RTP/AVP 31\r\n";
    let err = agent
        .accept_reoffer(call, two_streams, t0)
        .expect_err("a second stream is past the configured bound");
    assert_eq!(
        err,
        UaError::Sdp(sdp::SdpError::TooManyStreams { limit: 1 })
    );
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

/// The INVITEs among what went out, in order.
fn invites_in(written: &[Vec<u8>]) -> Vec<Vec<u8>> {
    written
        .iter()
        .filter(|bytes| bytes.starts_with(b"INVITE "))
        .cloned()
        .collect()
}

#[test]
fn a_resume_asked_for_while_the_hold_is_on_its_way_goes_once_the_hold_is_answered() {
    // 14.1: "If there is an ongoing INVITE client transaction, the TU MUST
    // wait until the transaction reaches the completed or terminated state
    // before initiating the new INVITE." The resume used to be measured
    // against the hold agreed so far, which the hold still on its way had not
    // moved, so it was taken as done already: accepted, and never sent
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);

    agent
        .resume(call, t0)
        .expect("taken, to go once the hold is answered");
    assert!(
        transmits(&mut agent).is_empty(),
        "nothing goes while the hold's INVITE is in progress"
    );

    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(
        written
            .first()
            .is_some_and(|bytes| bytes.starts_with(b"ACK ")),
        "the hold is acknowledged first"
    );
    let resume = invites_in(&written)
        .pop()
        .expect("the resume goes once the hold is complete");
    assert_eq!(header(&resume, HeaderName::CSeq), b"3 INVITE");
    let offer = body_of(&resume);
    assert!(offer.contains("a=sendrecv\r\n"), "{offer}");
    assert!(offer.contains("o=- 1 3 IN IP4 192.0.2.1\r\n"), "{offer}");
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: true,
            remote: false
        }),
        "the hold is still reported, as it was agreed"
    );

    deliver(
        &mut agent,
        &answered(&resume, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: false,
            remote: false
        })
    );
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(false));
}

#[test]
fn a_hold_asked_for_again_while_a_resume_waits_takes_the_resume_back() {
    // what waits is the state the application last asked for, not a list of
    // presses: hold, resume, hold again leaves a hold to be answered and
    // nothing after it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);
    agent.resume(call, t0).expect("waits");
    agent
        .hold(call, t0)
        .expect("the hold on its way already says this");
    assert!(transmits(&mut agent).is_empty());

    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(
        invites_in(&written).is_empty(),
        "nothing is left to change: {} message(s) went",
        written.len()
    );
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(true));
}

#[test]
fn a_resume_waiting_behind_a_refused_hold_finds_nothing_to_resume() {
    // 14.1: after a refusal "the session parameters MUST remain unchanged",
    // so the call was never held and the resume has nothing to send; the
    // refusal itself is still reported
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);
    agent.resume(call, t0).expect("waits");

    deliver(
        &mut agent,
        &answered(&reinvite, 488, "Not Acceptable Here", "desk", None),
        t0,
    );
    assert!(invites_in(&transmits(&mut agent)).is_empty());
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            event,
            UaEvent::SessionChangeFailed {
                status: Some(status),
                ..
            } if status.get() == 488
        )),
        "the hold's refusal reaches the application"
    );
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(false));
}

#[test]
fn a_resume_asked_for_while_a_hold_waits_out_a_491_goes_after_the_retry() {
    // 14.1's wait after a 491 is part of the same change: the resume goes
    // once the hold's second attempt is answered, not in the middle of it
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

    agent.resume(call, t0).expect("waits for the hold");
    assert!(transmits(&mut agent).is_empty());

    agent.handle_timeout(t0 + wait);
    let again = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the hold goes out again");
    assert!(body_of(&again).contains("a=sendonly\r\n"));
    deliver(
        &mut agent,
        &answered(&again, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0 + wait,
    );
    let resume = invites_in(&transmits(&mut agent))
        .pop()
        .expect("and then the resume");
    assert_eq!(header(&resume, HeaderName::CSeq), b"4 INVITE");
    assert!(body_of(&resume).contains("a=sendrecv\r\n"));
}

#[test]
fn a_resume_waiting_on_a_call_that_ends_goes_with_the_call() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    agent.hold(call, t0).expect("the hold goes");
    transmits(&mut agent);
    agent.resume(call, t0).expect("waits");

    deliver(&mut agent, &reversed(&ack, "BYE", "gone", 1, None), t0);
    let written = transmits(&mut agent);
    assert!(
        invites_in(&written).is_empty(),
        "nothing is offered into a call that has ended"
    );
    let told = events(&mut agent);
    assert!(
        told.iter()
            .any(|event| matches!(event, UaEvent::CallEnded { .. })),
        "{told:?}"
    );
    assert!(
        !told
            .iter()
            .any(|event| matches!(event, UaEvent::SessionChangeFailed { status: None, .. })),
        "the ending is the last word, not a resume that failed: {told:?}"
    );
    assert!(agent.holds_waiting.is_empty());
}

#[test]
fn a_written_offer_asked_for_while_a_change_is_on_its_way_is_refused_out_loud() {
    // a description the application wrote cannot wait: it was written
    // against the session as it stood, and the change in progress is about
    // to move that. So it is refused with a status, never taken and lost
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = on_hold(&mut agent, id, t0);

    assert_eq!(
        agent.reoffer(call, RESUMED_ON_PCMA, t0),
        Err(UaError::ChangeInProgress)
    );
    assert_eq!(
        agent.change_formats(call, RESUMED_ON_PCMA, t0),
        Err(UaError::ChangeInProgress)
    );
    assert!(transmits(&mut agent).is_empty());
}

#[test]
fn a_hold_asked_for_while_the_far_ends_offer_waits_on_the_application_goes_after_the_answer() {
    // 14.1 forbids a new INVITE "while another INVITE transaction is in
    // progress in either direction", and one the application has not
    // answered yet is in progress here
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "codec", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::Reoffer { .. })),
        "a codec change is the application's to answer"
    );

    agent.hold(call, t0).expect("waits for the answer");
    assert!(transmits(&mut agent).is_empty());

    agent
        .accept_reoffer(call, THEIR_PCMA, t0)
        .expect("answered");
    let written = transmits(&mut agent);
    assert!(
        written
            .first()
            .is_some_and(|bytes| bytes.starts_with(b"SIP/2.0 200 ")),
        "the far end's offer is answered first"
    );
    let hold = invites_in(&written).pop().expect("then the hold goes");
    assert!(body_of(&hold).contains("a=sendonly\r\n"));
}

#[test]
fn a_hold_asked_for_while_this_ends_offer_waits_for_the_ack_goes_after_it() {
    // a re-INVITE with no offer is answered with ours, and the answer to that
    // travels in the ACK (§13.2.2.4). RFC 3264 §4 lets no new offer go until
    // it has, so the hold waits for the ACK
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    deliver(&mut agent, &reversed(&ack, "INVITE", "empty", 1, None), t0);
    transmits(&mut agent);
    events(&mut agent);

    agent.hold(call, t0).expect("waits for the ACK");
    assert!(
        invites_in(&transmits(&mut agent)).is_empty(),
        "no offer while ours is unanswered"
    );

    deliver(
        &mut agent,
        &reversed(&ack, "ACK", "emptyack", 1, Some(ANSWER)),
        t0,
    );
    let hold = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the hold goes once the answer is in");
    assert!(body_of(&hold).contains("a=sendonly\r\n"));
}

#[test]
fn a_hold_asked_for_during_a_session_refresh_goes_after_it() {
    // RFC 4028 §7.4 sends the refresh as a re-INVITE when the far end never
    // allowed UPDATE, and that is an INVITE in progress like any other
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

    let due = t0 + Duration::from_secs(300);
    agent.handle_timeout(due);
    let refresh = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the refresh");
    agent.hold(call, due).expect("waits for the refresh");
    assert!(transmits(&mut agent).is_empty());

    deliver(
        &mut agent,
        &timed(&refresh, Some(ANSWER), "600;refresher=uac"),
        due,
    );
    let hold = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the hold goes once the refresh is answered");
    assert!(body_of(&hold).contains("a=sendonly\r\n"));
}

#[test]
fn three_presses_behind_a_hold_on_its_way_send_the_last_one_once() {
    // resume, hold, resume while the hold is unanswered: what waits is the
    // last word, and it goes once, with the version one past the hold's
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);
    agent.resume(call, t0).expect("waits");
    agent.hold(call, t0).expect("takes the resume back");
    agent.resume(call, t0).expect("waits again");
    assert!(transmits(&mut agent).is_empty());

    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    let invites = invites_in(&transmits(&mut agent));
    assert_eq!(invites.len(), 1, "one resume, not one per press");
    let offer = body_of(&invites[0]);
    assert!(offer.contains("a=sendrecv\r\n"), "{offer}");
    assert!(offer.contains("o=- 1 3 IN IP4 192.0.2.1\r\n"), "{offer}");

    deliver(
        &mut agent,
        &answered(&invites[0], 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    assert!(
        invites_in(&transmits(&mut agent)).is_empty(),
        "nothing is left waiting once the resume is answered"
    );
    assert_eq!(agent.hold_state(call).map(|hold| hold.local), Some(false));
}

#[test]
fn a_written_offer_refused_while_a_change_runs_does_not_use_up_a_version() {
    // RFC 3264 §8: the version in a new offer "MUST increment by one from the
    // previous SDP". An offer refused here before it was ever written on the
    // wire was not said, so the one written again afterwards is the next
    // number, not the one after it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);
    assert!(body_of(&reinvite).contains("o=- 1 2 IN IP4 192.0.2.1\r\n"));
    assert_eq!(
        agent.reoffer(call, RESUMED_ON_PCMA, t0),
        Err(UaError::ChangeInProgress)
    );
    assert_eq!(
        agent.change_formats(call, RESUMED_ON_PCMA, t0),
        Err(UaError::ChangeInProgress)
    );

    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    transmits(&mut agent);
    agent
        .reoffer(call, RESUMED_ON_PCMA, t0)
        .expect("nothing is running now");
    let offer = body_of(&sent(&mut agent));
    assert!(offer.contains("o=- 1 3 IN IP4 192.0.2.1\r\n"), "{offer}");
}

#[test]
fn a_hold_refused_before_it_could_go_does_not_use_up_a_version() {
    // a call still ringing, to a far end that never allowed UPDATE, cannot
    // carry a hold at all (RFC 3311 §4); the refusal comes before anything
    // is written, so the next offer is still one past the last one said
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
    transmits(&mut agent);
    assert_eq!(agent.hold(call, t0), Err(UaError::CannotRenegotiate));

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    agent.hold(call, t0).expect("the call is up");
    let offer = body_of(&sent(&mut agent));
    assert!(offer.contains("o=- 1 2 IN IP4 192.0.2.1\r\n"), "{offer}");
}

/// Our hold, refused with a 491 and waiting out the interval §14.1 draws.
fn hold_told_to_wait(
    agent: &mut UserAgent,
    account: AccountId,
    now: Instant,
) -> (CallHandle, Vec<u8>, Duration) {
    let (call, ack) = call_up(agent, account, now);
    agent.hold(call, now).expect("the re-INVITE goes");
    let reinvite = sent(agent);
    deliver(
        agent,
        &answered(&reinvite, 491, "Request Pending", "desk", None),
        now,
    );
    transmits(agent);
    let wait = events(agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::SessionChangeFailed { retry_in, .. } => retry_in,
            _ => None,
        })
        .expect("491 says to wait and try again");
    (call, ack, wait)
}

#[test]
fn the_far_ends_offer_in_the_wait_after_a_491_is_answered_not_refused() {
    // 14.2 answers 491 to an INVITE that arrives "while an INVITE it had sent
    // on that dialog is in progress". Ours was over the moment the 491 came
    // back; the far end's own retry lands in the wait §14.1 drew for us, and
    // refusing it would leave its change failed for good
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack, wait) = hold_told_to_wait(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "theirs", 2, Some(THEIR_HOLD)),
        t0,
    );
    let answer = last(&mut agent);
    assert!(
        answer.starts_with(b"SIP/2.0 200 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(body_of(&answer).contains("o=- 1 3 IN IP4 192.0.2.1\r\n"));
    deliver(&mut agent, &reversed(&ack, "ACK", "theirsack", 2, None), t0);
    transmits(&mut agent);
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: false,
            remote: true
        })
    );

    agent.handle_timeout(t0 + wait);
    let again = invites_in(&transmits(&mut agent))
        .pop()
        .expect("our hold goes once more");
    let offer = body_of(&again);
    assert!(
        offer.contains("o=- 1 4 IN IP4 192.0.2.1\r\n"),
        "one past the answer written in the wait, never behind it: {offer}"
    );
    deliver(
        &mut agent,
        &answered(&again, 200, "OK", "desk", Some(THEIR_HOLD)),
        t0 + wait,
    );
    transmits(&mut agent);
    assert_eq!(
        agent.hold_state(call),
        Some(Hold {
            local: true,
            remote: true
        })
    );
}

#[test]
fn a_reinvite_asking_for_an_offer_in_the_wait_after_a_491_holds_the_retry_until_its_ack() {
    // the far end's re-INVITE with no description asks this end to offer in
    // the 2xx (§14.1), and the answer to that offer can only come in the ACK
    // (§13.2.2.4, RFC 3264 §4: no new offer before the last is answered). Our
    // hold's retry falls due while that answer is still owed, so it waits;
    // the ACK brings the answer, and the retry then goes, written over the
    // session the answer settled rather than the one the 491 interrupted
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack, wait) = hold_told_to_wait(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "askoffer", 2, None),
        t0,
    );
    let ok = last(&mut agent);
    assert!(
        ok.starts_with(b"SIP/2.0 200 "),
        "{}",
        String::from_utf8_lossy(&ok)
    );
    let offered = body_of(&ok);
    assert!(
        offered.contains("o=- 1 3 IN IP4 192.0.2.1\r\n"),
        "{offered}"
    );
    assert!(
        !offered.contains("a=sendonly"),
        "the offer in the 2xx is the session as agreed, not the hold still waiting: {offered}"
    );
    events(&mut agent);

    agent.handle_timeout(t0 + wait);
    assert!(
        invites_in(&transmits(&mut agent)).is_empty(),
        "an offer of ours is still unanswered, so no second one goes"
    );
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::SessionChangeFailed { .. })),
        "and the hold has not failed, it waits"
    );
    assert_eq!(
        agent.hold_state(call),
        Some(Hold {
            local: false,
            remote: false
        })
    );

    // the ACK carries the answer to the offer in our 2xx
    let answer: &[u8] = b"v=0\r\no=- 2 3 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";
    let acked = t0 + wait + Duration::from_millis(100);
    deliver(
        &mut agent,
        &reversed(&ack, "ACK", "askofferack", 2, Some(answer)),
        acked,
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "an ACK is never answered, and the retry is not due yet"
    );
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: false,
            remote: false
        }),
        "the answer in the ACK is taken"
    );

    let later = acked + Duration::from_secs(5);
    agent.handle_timeout(later);
    let again = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the hold goes once the offer in our 2xx has its answer");
    let offer = body_of(&again);
    assert!(offer.contains("a=sendonly\r\n"), "{offer}");
    assert!(
        offer.contains("o=- 1 4 IN IP4 192.0.2.1\r\n"),
        "one past the offer written in the wait: {offer}"
    );
    deliver(
        &mut agent,
        &answered(&again, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        later,
    );
    transmits(&mut agent);
    assert_eq!(
        agent.hold_state(call),
        Some(Hold {
            local: true,
            remote: false
        })
    );
}

#[test]
fn an_offer_that_arrives_before_the_ack_carrying_the_answer_to_ours_is_refused_491() {
    // RFC 3311 §5.2, which this agent applies to both requests: "if an UPDATE
    // is received that contains an offer, and the UAS has generated an offer
    // (in an UPDATE, PRACK or INVITE) to which it has not yet received an
    // answer, the UAS MUST reject the UPDATE with a 491 response". An offer
    // this end put in a 2xx is unanswered until the ACK arrives, and a
    // request that overtakes that ACK — or asks for a second offer, which
    // RFC 3264 §4 forbids before the first is answered — is told to wait
    for (method, body) in [
        ("INVITE", None),
        ("INVITE", Some(THEIR_HOLD)),
        ("UPDATE", Some(THEIR_HOLD)),
    ] {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let (call, ack) = call_up(&mut agent, id, t0);
        deliver(
            &mut agent,
            &reversed(&ack, "INVITE", "askoffer", 2, None),
            t0,
        );
        let ok = last(&mut agent);
        assert!(ok.starts_with(b"SIP/2.0 200 "), "{method}");
        events(&mut agent);

        deliver(
            &mut agent,
            &reversed(&ack, method, "overtaking", 3, body),
            t0,
        );
        let refusal = last(&mut agent);
        assert!(
            refusal.starts_with(b"SIP/2.0 491 "),
            "{method} {}: {}",
            body.is_some(),
            String::from_utf8_lossy(&refusal)
        );
        assert!(
            !events(&mut agent).iter().any(|event| matches!(
                event,
                UaEvent::Reoffer { .. } | UaEvent::SessionChanged { .. }
            )),
            "{method}"
        );

        // and once the ACK has brought the answer, the same change is taken
        let answer: &[u8] = b"v=0\r\no=- 2 3 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";
        deliver(
            &mut agent,
            &reversed(&ack, "ACK", "askofferack", 2, Some(answer)),
            t0,
        );
        transmits(&mut agent);
        events(&mut agent);
        deliver(&mut agent, &reversed(&ack, method, "again", 4, body), t0);
        let taken = last(&mut agent);
        assert!(
            taken.starts_with(b"SIP/2.0 200 "),
            "{method}: {}",
            String::from_utf8_lossy(&taken)
        );
        assert!(agent.call_state(call).is_some());
    }
}

/// The application's answer to `THEIR_NEW_CODEC`, one version past our hold.
const OUR_PCMA_ANSWER: &[u8] = b"v=0\r\no=- 1 3 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 8\r\n";

#[test]
fn a_retry_due_while_the_far_ends_offer_waits_on_the_application_waits_too() {
    // the retry after a 491 is a new INVITE, and 14.1 forbids one while the
    // far end's is still in progress here; it waits rather than failing
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack, wait) = hold_told_to_wait(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "codec", 2, Some(THEIR_NEW_CODEC)),
        t0,
    );
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::Reoffer { .. })),
        "the codec change reaches the application"
    );

    agent.handle_timeout(t0 + wait);
    assert!(invites_in(&transmits(&mut agent)).is_empty());
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::SessionChangeFailed { .. })),
        "the hold is still on its way"
    );

    agent
        .accept_reoffer(call, OUR_PCMA_ANSWER, t0 + wait)
        .expect("answered");
    transmits(&mut agent);
    let later = t0 + wait + Duration::from_secs(5);
    agent.handle_timeout(later);
    let again = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the hold goes once the far end's change is over");
    let offer = body_of(&again);
    assert!(offer.contains("a=sendonly\r\n"), "{offer}");
    assert!(
        offer.contains("m=audio 8000 RTP/AVP 8\r\n"),
        "written over the codec the far end moved the call to, not back to the old one: {offer}"
    );
    assert!(offer.contains("o=- 1 4 IN IP4 192.0.2.1\r\n"), "{offer}");
}

#[test]
fn an_application_offer_told_to_wait_is_not_sent_over_a_change_made_in_the_wait() {
    // the application's description was written against the session before
    // the far end's change was answered; sent afterwards it would undo that
    // change, so it is reported as not made, as a reoffer asked for while a
    // change runs is refused
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    agent
        .reoffer(call, RESUMED_ON_PCMA, t0)
        .expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
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

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "theirs", 2, Some(THEIR_HOLD)),
        t0,
    );
    assert!(last(&mut agent).starts_with(b"SIP/2.0 200 "));
    deliver(&mut agent, &reversed(&ack, "ACK", "theirsack", 2, None), t0);
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + wait);
    assert!(
        invites_in(&transmits(&mut agent)).is_empty(),
        "the stale description does not go"
    );
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            UaEvent::SessionChangeFailed {
                status: None,
                retry_in: None,
                ..
            }
        )),
        "{seen:?}"
    );
    agent
        .reoffer(call, RESUMED_ON_PCMA, t0 + wait)
        .expect("written again, it goes");
    let offer = body_of(&sent(&mut agent));
    assert!(offer.contains("o=- 1 4 IN IP4 192.0.2.1\r\n"), "{offer}");
}

#[test]
fn a_refresh_told_to_wait_repeats_the_session_as_the_wait_left_it() {
    // RFC 4028 §7.4 has a refresh offer the session unchanged. When the far
    // end's own change was answered in the wait after a 491, "unchanged" is
    // what that answer said — not what the refresh carried the first time,
    // whose version is now behind it
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
    let ack = sent(&mut agent);
    events(&mut agent);

    let due = t0 + Duration::from_secs(300);
    agent.handle_timeout(due);
    let refresh = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the refresh");
    assert!(body_of(&refresh).contains("o=- 1 1 IN IP4 192.0.2.1\r\n"));
    deliver(
        &mut agent,
        &answered(&refresh, 491, "Request Pending", "desk", None),
        due,
    );
    transmits(&mut agent);

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "theirs", 2, Some(THEIR_HOLD)),
        due,
    );
    let answer = last(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 "));
    assert!(body_of(&answer).contains("o=- 1 2 IN IP4 192.0.2.1\r\n"));
    deliver(
        &mut agent,
        &reversed(&ack, "ACK", "theirsack", 2, None),
        due,
    );
    transmits(&mut agent);

    agent.handle_timeout(due + Duration::from_secs(5));
    let again = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the refresh goes once more");
    let offer = body_of(&again);
    assert!(offer.contains("o=- 1 2 IN IP4 192.0.2.1\r\n"), "{offer}");
    assert!(offer.contains("a=recvonly\r\n"), "{offer}");
}

#[test]
fn a_refresh_due_while_a_hold_is_on_its_way_does_not_cross_it() {
    // the other order: the session timer falls due with our hold still
    // unanswered. A refresh then would be a second INVITE in progress
    // (§14.1), so it waits a quarter of the interval and goes after the hold
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

    let pressed = t0 + Duration::from_secs(299);
    agent.hold(call, pressed).expect("the hold goes");
    let hold = invites_in(&transmits(&mut agent)).pop().expect("the hold");
    agent.handle_timeout(t0 + Duration::from_secs(300));
    let cseq = header(&hold, HeaderName::CSeq);
    assert!(
        invites_in(&transmits(&mut agent))
            .iter()
            .all(|again| header(again, HeaderName::CSeq) == cseq),
        "the hold is retransmitted, and no refresh goes while it is in progress"
    );

    deliver(
        &mut agent,
        &timed(&hold, Some(THEIR_RECVONLY), "600;refresher=uac"),
        t0 + Duration::from_secs(301),
    );
    transmits(&mut agent);
    assert_eq!(agent.hold_state(call).map(|held| held.local), Some(true));
    agent.handle_timeout(t0 + Duration::from_secs(450));
    let refresh = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the refresh goes once the hold is over");
    assert_ne!(header(&refresh, HeaderName::CSeq), cseq);
    assert!(
        body_of(&refresh).contains("a=sendonly\r\n"),
        "and repeats the held session"
    );
}

#[test]
fn an_ack_that_brings_no_answer_does_not_leave_the_next_hold_waiting_for_one() {
    // §13.2.2.4 lets the answer to an offer in a 2xx travel only in the ACK.
    // A peer that sends the ACK empty has not answered and never will, and a
    // hold asked for afterwards goes at once instead of waiting forever
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    deliver(&mut agent, &reversed(&ack, "INVITE", "empty", 1, None), t0);
    transmits(&mut agent);
    deliver(&mut agent, &reversed(&ack, "ACK", "emptyack", 1, None), t0);
    transmits(&mut agent);
    events(&mut agent);

    agent.hold(call, t0).expect("nothing is running");
    let hold = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the hold goes at once");
    assert!(body_of(&hold).contains("a=sendonly\r\n"));
}

#[test]
fn a_hold_waiting_on_a_call_hung_up_here_is_never_sent() {
    // the application hangs up while its hold waits behind a change still
    // on its way: the BYE ends the dialog, and nothing is offered into it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, reinvite) = on_hold(&mut agent, id, t0);
    agent.resume(call, t0).expect("waits");
    agent.hangup(call, t0).expect("the BYE goes");
    let written = transmits(&mut agent);
    assert!(written.iter().any(|bytes| bytes.starts_with(b"BYE ")));

    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    assert!(
        invites_in(&transmits(&mut agent)).is_empty(),
        "nothing is offered into a call that is ending"
    );
    assert!(agent.holds_waiting.is_empty());
    let seen = events(&mut agent);
    assert!(
        !seen
            .iter()
            .any(|event| matches!(event, UaEvent::SessionChangeFailed { .. })),
        "the call's end is the last word on it, not a failed change: {seen:?}"
    );
}

#[test]
fn a_hold_waiting_on_a_call_the_far_end_hangs_up_is_never_sent() {
    // the far end's BYE arrives while our resume waits behind our hold; the
    // hold's 200 comes after it, and nothing goes into the dead dialog
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    agent.hold(call, t0).expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
    agent.resume(call, t0).expect("waits");
    deliver(&mut agent, &reversed(&ack, "BYE", "bye", 2, None), t0);
    transmits(&mut agent);
    deliver(
        &mut agent,
        &answered(&reinvite, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    assert!(
        invites_in(&transmits(&mut agent)).is_empty(),
        "nothing is offered into a call that has ended"
    );
    assert!(agent.holds_waiting.is_empty());
    let seen = events(&mut agent);
    assert!(
        seen.iter()
            .any(|event| matches!(event, UaEvent::CallEnded { .. })),
        "{seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|event| matches!(event, UaEvent::SessionChangeFailed { .. })),
        "{seen:?}"
    );
    assert_eq!(agent.resume(call, t0), Err(UaError::NoSuchCall));
}

#[test]
fn a_resume_behind_a_hold_told_to_wait_goes_after_the_retry_one_version_on() {
    // hold, 491, resume pressed in the wait: the retry repeats the hold under
    // its own version (nothing was said in between), and the resume follows
    // it one past — never two resumes, never a skipped number
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack, wait) = hold_told_to_wait(&mut agent, id, t0);
    agent.resume(call, t0).expect("waits behind the retry");
    assert!(transmits(&mut agent).is_empty());

    agent.handle_timeout(t0 + wait);
    let retry = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the hold goes once more");
    let offered = body_of(&retry);
    assert!(offered.contains("a=sendonly\r\n"), "{offered}");
    assert!(
        offered.contains("o=- 1 2 IN IP4 192.0.2.1\r\n"),
        "{offered}"
    );

    deliver(
        &mut agent,
        &answered(&retry, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0 + wait,
    );
    let resumes = invites_in(&transmits(&mut agent));
    assert_eq!(resumes.len(), 1, "one resume");
    let offered = body_of(&resumes[0]);
    assert!(offered.contains("a=sendrecv\r\n"), "{offered}");
    assert!(
        offered.contains("o=- 1 3 IN IP4 192.0.2.1\r\n"),
        "{offered}"
    );
}

#[test]
fn a_refresh_told_to_wait_still_asks_for_the_session_timer() {
    // RFC 4028 §7.4: a refresh carries Session-Expires, and it is a refresh
    // on its second attempt as on its first. Sent again as a plain change it
    // would ask for no timer, and its 2xx would be reported as a session
    // change although nothing changed
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

    let due = t0 + Duration::from_secs(300);
    agent.handle_timeout(due);
    let refresh = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the refresh");
    assert!(!header(&refresh, HeaderName::SessionExpires).is_empty());
    deliver(
        &mut agent,
        &answered(&refresh, 491, "Request Pending", "desk", None),
        due,
    );
    transmits(&mut agent);
    events(&mut agent);

    let later = due + Duration::from_secs(5);
    agent.handle_timeout(later);
    let again = invites_in(&transmits(&mut agent))
        .pop()
        .expect("the refresh goes once more");
    assert_ne!(
        header(&again, HeaderName::CSeq),
        header(&refresh, HeaderName::CSeq)
    );
    assert_eq!(
        header(&again, HeaderName::SessionExpires),
        header(&refresh, HeaderName::SessionExpires),
        "the second attempt is still a refresh"
    );
    assert_eq!(body_of(&again), body_of(&refresh), "the session, unchanged");

    deliver(
        &mut agent,
        &timed(&again, Some(ANSWER), "600;refresher=uac"),
        later,
    );
    transmits(&mut agent);
    let seen = events(&mut agent);
    assert!(
        !seen
            .iter()
            .any(|event| matches!(event, UaEvent::SessionChanged { .. })),
        "a refresh changes nothing to report: {seen:?}"
    );
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
fn an_update_offer_nobody_answers_stops_blocking_the_next_one_once_the_endpoint_answers_408() {
    // RFC 3311 §5.2 refuses a second offer only while the first is still
    // unanswered. The endpoint's 408 at 64·T1 is that answer, and from then
    // on the far end may offer again: it is not told 500 for good
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &reversed(&ack, "UPDATE", "forgotten", 1, Some(THEIR_NEW_CODEC)),
        t0,
    );
    events(&mut agent);
    transmits(&mut agent);

    let later = t0 + Duration::from_secs(33);
    agent.handle_timeout(later);
    assert!(
        transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 408 ")),
        "the endpoint answers the UPDATE nobody did"
    );

    deliver(
        &mut agent,
        &reversed(&ack, "UPDATE", "afterwards", 2, Some(THEIR_NEW_CODEC)),
        later,
    );
    assert!(
        transmits(&mut agent)
            .iter()
            .all(|bytes| !bytes.starts_with(b"SIP/2.0 500 ")),
        "the next offer is refused as too soon"
    );
    assert!(
        events(&mut agent).iter().any(
            |event| matches!(event, UaEvent::Reoffer { call: offered, .. } if *offered == call)
        ),
        "the next offer reaches the application"
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

#[test]
fn a_reoffer_past_the_configured_sdp_bound_is_refused() {
    // EndpointConfig::sdp_limits is read once at construction and threaded
    // through every sdp::parse_with_limits call this layer makes; an
    // application-written re-INVITE is one of them
    let t0 = Instant::now();
    let mut config = EndpointConfig::default();
    config.sdp_limits = sdp::Limits {
        max_media: 1,
        ..sdp::Limits::DEFAULT
    };
    let mut agent = agent_with(config, t0);
    let id = agent.add_account(account());
    // the initial offer and answer each carry one stream, inside the
    // configured bound
    let (call, _) = call_up(&mut agent, id, t0);

    let two_streams: &[u8] = b"v=0\r\no=- 1 2 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\nm=video 8002 RTP/AVP 31\r\n";
    let err = agent
        .reoffer(call, two_streams, t0)
        .expect_err("a second stream is past the configured bound");
    assert_eq!(
        err,
        UaError::Sdp(sdp::SdpError::TooManyStreams { limit: 1 })
    );
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
fn a_refresh_sent_as_a_reinvite_names_gruu_in_supported() {
    // RFC 5627 §4.4: `Supported: gruu` on what a UA generates, and a session
    // refresh the far end did not allow as an UPDATE goes as a re-INVITE
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);
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
    assert!(
        supports_gruu(&refresh),
        "{}",
        String::from_utf8_lossy(&refresh)
    );
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

#[test]
fn a_retry_that_rang_past_its_half_interval_is_still_asked_only_once() {
    // 10: "the UAC SHOULD NOT continuously retry the request if the server
    // indicates the same error response". The retry after a 422 carries the
    // timer that remembers it was already raised, and that memory has to
    // survive the retry ringing for longer than half the interval it asked for.
    // A tagged 180 with a Contact opens an early dialog and an untagged one
    // does not, and the timer meets a different early return for each
    for early_dialog in [true, false] {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        agent.call(id, &outgoing(), t0).expect("the INVITE goes");
        let first = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(&first, 422, "Session Interval Too Small", "Min-SE: 120\r\n"),
            t0,
        );
        let again = transmits(&mut agent)
            .into_iter()
            .find(|bytes| bytes.starts_with(b"INVITE "))
            .expect("it is asked again");
        events(&mut agent);

        let ringing = if early_dialog {
            answered(&again, 180, "Ringing", "desk", None)
        } else {
            reply(&again, 180, "Ringing", "")
        };
        deliver(&mut agent, &ringing, t0);
        transmits(&mut agent);
        events(&mut agent);
        // half of the 120 seconds the retry asked for
        agent.handle_timeout(t0 + Duration::from_secs(60));
        transmits(&mut agent);
        events(&mut agent);

        deliver(
            &mut agent,
            &reply(
                &again,
                422,
                "Session Interval Too Small",
                "Min-SE: 1800\r\n",
            ),
            t0 + Duration::from_secs(61),
        );
        assert!(
            transmits(&mut agent)
                .iter()
                .all(|bytes| !bytes.starts_with(b"INVITE ")),
            "a third INVITE went (early dialog: {early_dialog}): the far end can keep \
             this call asking for ever"
        );
        assert_eq!(
            ended(&mut agent).map(|(_, reason)| reason),
            Some(CallEndReason::Refused),
            "asked once more, not for ever (early dialog: {early_dialog})"
        );
    }
}

#[test]
fn a_refresh_that_fell_due_before_the_ack_still_goes_before_the_session_expires() {
    // 7.2 and 9: the session expiration runs from the 2xx, and the refresher
    // "MUST generate a refresh before the session expiration". With a T1 of two
    // seconds the INVITE server transaction waits 128 s for the ACK, so an ACK
    // that arrives after half of a 90 s interval is still an ACK
    let t0 = Instant::now();
    let mut config = EndpointConfig::default();
    config.timers.t1 = Duration::from_secs(2);
    let mut agent = UserAgent::new(config, [11; 32]).unwrap();
    agent
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            t0,
        )
        .expect("binding a transport");
    agent.add_account(account());
    let invite = plus(
        &incoming_invite("lateack", Some(OFFER)),
        "Supported: timer\r\nSession-Expires: 90\r\nAllow: INVITE, ACK, BYE, CANCEL, UPDATE\r\n",
    );
    let call = call_arriving(&mut agent, &invite, t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("the 200 goes");
    let ok = sent(&mut agent);
    assert_eq!(header(&ok, HeaderName::SessionExpires), b"90;refresher=uas");

    // half the interval passes with the 2xx still unacknowledged
    agent.handle_timeout(t0 + Duration::from_secs(45));
    transmits(&mut agent);
    events(&mut agent);

    let mut at = t0 + Duration::from_secs(50);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "lateack2", 1), at);
    transmits(&mut agent);
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
    events(&mut agent);

    let expiry = t0 + Duration::from_secs(90);
    let mut refreshed = false;
    for _ in 0..64 {
        let Some(next) = agent.poll_timeout() else {
            break;
        };
        let next = next.max(at);
        if next >= expiry {
            break;
        }
        agent.handle_timeout(next);
        at = next;
        if transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"UPDATE ") || bytes.starts_with(b"INVITE "))
        {
            refreshed = true;
            break;
        }
    }
    assert!(
        refreshed,
        "the session this end promised to refresh runs out with no refresh sent"
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

pub(crate) fn call_arriving(agent: &mut UserAgent, bytes: &[u8], now: Instant) -> CallHandle {
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

/// The same request carrying `body` under `content_type`, and `extra` header
/// fields, in place of whatever body it had.
fn carrying(request: &[u8], content_type: &str, extra: &str, body: &str) -> Vec<u8> {
    let text = String::from_utf8(request.to_vec()).expect("text");
    let end = text.find("\r\n\r\n").expect("a header section");
    let head = text[..end]
        .split("\r\n")
        .filter(|line| !line.starts_with("Content-Type:") && !line.starts_with("Content-Length:"))
        .fold(String::new(), |mut head, line| {
            head.push_str(line);
            head.push_str("\r\n");
            head
        });
    format!(
        "{head}Content-Type: {content_type}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A body of a type this agent does not read: the ISDN User Part message a
/// SIP-T gateway sends beside, or instead of, a session description.
const ISUP: &str = "\u{1}\u{2}\u{3}";

#[test]
fn a_prack_with_a_body_this_agent_cannot_read_is_refused_415_and_acknowledges_nothing() {
    // RFC 3261 §8.2.3 comes before anything a request's method asks for, a
    // PRACK's 2xx included: a body that is not a session description is
    // refused with an Accept that says what is read. RFC 3262 §3 counts a
    // PRACK as the acknowledgement only once §8.2 has let it through, so the
    // provisional stays unacknowledged and the 2xx held behind it stays held
    // until the PRACK the far end sends again with a body it can read
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_100rel("rel415", true), t0);
    agent
        .ring(call, Some(Arc::from(ANSWER)), t0)
        .expect("183 with early media");
    let progress = sent(&mut agent);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("the answer is taken");
    assert!(transmits(&mut agent).is_empty());

    let rseq = String::from_utf8_lossy(&header(&progress, HeaderName::RSeq)).into_owned();
    let prack = carrying(
        &in_dialog(&progress, "PRACK", "rel415prack", 2),
        "application/isup",
        &format!("RAck: {rseq} 1 INVITE\r\n"),
        ISUP,
    );
    deliver(&mut agent, &prack, t0);
    let written = transmits(&mut agent);
    let refusal = written
        .iter()
        .find(|bytes| header(bytes, HeaderName::CSeq) == b"2 PRACK")
        .expect("the PRACK is answered");
    assert!(
        refusal.starts_with(b"SIP/2.0 415 "),
        "{}",
        String::from_utf8_lossy(refusal)
    );
    assert_eq!(header(refusal, HeaderName::Accept), b"application/sdp");
    assert!(
        !written
            .iter()
            .any(|bytes| header(bytes, HeaderName::CSeq) == b"1 INVITE"),
        "the 2xx the provisional held went for a PRACK that acknowledged nothing"
    );

    // the far end sends it again with nothing in it, and that one lets the
    // 2xx go
    let again = plus(
        &in_dialog(&progress, "PRACK", "rel415again", 3),
        &format!("RAck: {rseq} 1 INVITE\r\n"),
    );
    deliver(&mut agent, &again, t0);
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 200 OK\r\n")
                && header(bytes, HeaderName::CSeq) == b"3 PRACK"),
        "the PRACK sent again is matched and answered"
    );
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 200 OK\r\n")
                && header(bytes, HeaderName::CSeq) == b"1 INVITE"),
        "the 2xx the provisional held goes"
    );
}

/// A call rung with early media on a 183 sent reliably and answered at once,
/// so that its 2xx is held behind the 183 (RFC 3262 §5): the call, the 183,
/// and the `RAck` a PRACK for it carries.
fn early_media_held(
    agent: &mut UserAgent,
    branch: &str,
    now: Instant,
) -> (CallHandle, Vec<u8>, String) {
    let call = call_arriving(agent, &incoming_100rel(branch, true), now);
    agent
        .ring(call, Some(Arc::from(ANSWER)), now)
        .expect("183 with early media");
    let progress = sent(agent);
    agent
        .answer(call, Some(Arc::from(ANSWER)), now)
        .expect("the answer is taken");
    assert!(transmits(agent).is_empty(), "the 200 is held");
    let rseq = String::from_utf8_lossy(&header(&progress, HeaderName::RSeq)).into_owned();
    (call, progress, format!("RAck: {rseq} 1 INVITE\r\n"))
}

/// Whether the 2xx to the INVITE is among what was written.
fn invite_answered(written: &[Vec<u8>]) -> bool {
    written.iter().any(|bytes| {
        bytes.starts_with(b"SIP/2.0 200 OK\r\n") && header(bytes, HeaderName::CSeq) == b"1 INVITE"
    })
}

/// The answer to the PRACK with `CSeq` `cseq`, among what was written.
fn prack_answer(written: &[Vec<u8>], cseq: u32) -> Vec<u8> {
    let wanted = format!("{cseq} PRACK");
    written
        .iter()
        .find(|bytes| header(bytes, HeaderName::CSeq) == wanted.as_bytes())
        .cloned()
        .expect("the PRACK is answered")
}

#[test]
fn a_prack_that_requires_an_extension_is_refused_420_and_acknowledges_nothing() {
    // RFC 3261 §8.2.2.3 asks every request its Require, and RFC 3262 §3 has
    // a PRACK processed "according to the procedures of Sections 8.2 and
    // 12.2.2 of RFC 3261": a PRACK demanding an extension this agent lacks
    // is a 420 naming it, and one refused so has acknowledged nothing — the
    // 2xx held behind the 183 waits for the PRACK sent again without it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (_call, progress, rack) = early_media_held(&mut agent, "rel420", t0);

    let prack = plus(
        &in_dialog(&progress, "PRACK", "rel420prack", 2),
        &format!("{rack}Require: foo\r\n"),
    );
    deliver(&mut agent, &prack, t0);
    let written = transmits(&mut agent);
    let refusal = prack_answer(&written, 2);
    assert!(
        refusal.starts_with(b"SIP/2.0 420 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert_eq!(header(&refusal, HeaderName::Unsupported), b"foo");
    assert!(
        !invite_answered(&written),
        "the held 2xx went for a refused PRACK"
    );

    // without the extension, the same RAck is matched and lets the 2xx go
    deliver(
        &mut agent,
        &plus(&in_dialog(&progress, "PRACK", "rel420again", 3), &rack),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(prack_answer(&written, 3).starts_with(b"SIP/2.0 200 OK\r\n"));
    assert!(
        invite_answered(&written),
        "the 2xx the provisional held goes"
    );
}

/// An offer from the far end over what [`OFFER`] described, with its `o=`
/// version moved on and `extra` after its one stream.
fn their_new_offer(format: &str, extra: &str) -> Vec<u8> {
    format!(
        "v=0\r\no=- 1 2 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP {format}\r\n{extra}"
    )
    .into_bytes()
}

#[test]
fn an_offer_in_a_prack_that_only_holds_the_call_is_answered_in_its_2xx() {
    // RFC 3262 §5: "If the UAS receives a PRACK with an offer, it MUST place
    // the answer in the 2xx to the PRACK", and a hold asks nothing this
    // layer has to hand up
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (call, progress, rack) = early_media_held(&mut agent, "relhold", t0);
    events(&mut agent);

    let offer = their_new_offer("0", "a=sendonly\r\n");
    let prack = carrying(
        &in_dialog(&progress, "PRACK", "relholdprack", 2),
        "application/sdp",
        &rack,
        std::str::from_utf8(&offer).expect("text"),
    );
    deliver(&mut agent, &prack, t0);
    let written = transmits(&mut agent);
    let answer = prack_answer(&written, 2);
    assert!(
        answer.starts_with(b"SIP/2.0 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    let body = body_of(&answer);
    assert!(body.contains("a=recvonly\r\n"), "{body}");
    assert!(
        invite_answered(&written),
        "the 2xx the provisional held goes"
    );
    assert_eq!(agent.hold_state(call).map(|hold| hold.remote), Some(true));
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::SessionChanged { call: changed, .. } if *changed == call)),
        "the application is told what the session is now"
    );
}

#[test]
fn an_offer_in_a_prack_this_layer_cannot_answer_is_the_applications_and_its_answer_goes_in_the_2xx()
{
    // an offer on another codec needs what only the application holds: it is
    // handed up the way a re-offer is, the PRACK held open for it, and the
    // answer goes in the PRACK's 2xx — never a 2xx with no body and the
    // offer dropped. The 2xx held behind the 183 goes once the PRACK is
    // answered, not before
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (call, progress, rack) = early_media_held(&mut agent, "relcodec", t0);
    events(&mut agent);

    let offer = their_new_offer("8", "");
    let prack = carrying(
        &in_dialog(&progress, "PRACK", "relcodecprack", 2),
        "application/sdp",
        &rack,
        std::str::from_utf8(&offer).expect("text"),
    );
    deliver(&mut agent, &prack, t0);
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .all(|bytes| header(bytes, HeaderName::CSeq) != b"2 PRACK"),
        "the PRACK was answered before anyone had an answer to its offer"
    );
    assert!(!invite_answered(&written));
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            event,
            UaEvent::Reoffer { call: offered, request }
                if *offered == call && request.as_raw().method() == Some(Method::Prack)
        )),
        "the offer reaches the application"
    );

    let ours = b"v=0\r\no=- 2 3 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 8\r\n";
    agent
        .accept_reoffer(call, ours, t0)
        .expect("the answer goes");
    let written = transmits(&mut agent);
    let answer = prack_answer(&written, 2);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert_eq!(body_of(&answer).as_bytes(), ours);
    assert!(
        header(&answer, HeaderName::Contact).is_empty(),
        "RFC 3262 §6 leaves Contact out of a PRACK's 2xx"
    );
    assert!(
        invite_answered(&written),
        "the 2xx the provisional held goes"
    );
}

#[test]
fn an_offer_in_a_prack_the_application_refuses_leaves_the_provisional_unacknowledged() {
    // refused, the PRACK acknowledged nothing (RFC 3262 §3 counts only one
    // §8.2 and the method let through): the 2xx stays held behind the 183,
    // and the PRACK the far end sends again without the offer lets it go
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (call, progress, rack) = early_media_held(&mut agent, "relrefuse", t0);
    let offer = their_new_offer("8", "");
    let prack = carrying(
        &in_dialog(&progress, "PRACK", "relrefuseprack", 2),
        "application/sdp",
        &rack,
        std::str::from_utf8(&offer).expect("text"),
    );
    deliver(&mut agent, &prack, t0);
    transmits(&mut agent);
    events(&mut agent);

    agent
        .reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, t0)
        .expect("the refusal goes");
    let written = transmits(&mut agent);
    assert!(prack_answer(&written, 2).starts_with(b"SIP/2.0 488 "));
    assert!(
        !invite_answered(&written),
        "the held 2xx went for a refused PRACK"
    );

    deliver(
        &mut agent,
        &plus(&in_dialog(&progress, "PRACK", "relrefuseagain", 3), &rack),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(prack_answer(&written, 3).starts_with(b"SIP/2.0 200 OK\r\n"));
    assert!(invite_answered(&written));
}

#[test]
fn an_offer_in_a_prack_nobody_answers_lets_the_held_2xx_go_once_the_endpoint_answers_408() {
    // the endpoint matched the PRACK to the 183 when it arrived and stopped
    // retransmitting it (RFC 3262 §3): once its own 408 has answered the
    // offer nobody else did, the 2xx held behind the 183 goes, and the call
    // takes offers again
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (call, progress, rack) = early_media_held(&mut agent, "relforgot", t0);
    let offer = their_new_offer("8", "");
    let prack = carrying(
        &in_dialog(&progress, "PRACK", "relforgotprack", 2),
        "application/sdp",
        &rack,
        std::str::from_utf8(&offer).expect("text"),
    );
    deliver(&mut agent, &prack, t0);
    assert!(!invite_answered(&transmits(&mut agent)));
    events(&mut agent);

    let later = t0 + Duration::from_secs(33);
    agent.handle_timeout(later);
    let written = transmits(&mut agent);
    assert!(prack_answer(&written, 2).starts_with(b"SIP/2.0 408 "));
    assert!(
        invite_answered(&written),
        "the 2xx the provisional held goes"
    );
    assert!(
        agent
            .reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, later)
            .is_err(),
        "the change is no longer anyone's to answer"
    );
}

#[test]
fn a_session_description_in_a_prack_that_cannot_be_read_is_refused_488() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (_call, progress, rack) = early_media_held(&mut agent, "relgarbled", t0);
    let prack = carrying(
        &in_dialog(&progress, "PRACK", "relgarbledprack", 2),
        "application/sdp",
        &rack,
        "not a description",
    );
    deliver(&mut agent, &prack, t0);
    let written = transmits(&mut agent);
    let refusal = prack_answer(&written, 2);
    assert!(
        refusal.starts_with(b"SIP/2.0 488 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert!(!header(&refusal, HeaderName::Warning).is_empty());
    assert!(!invite_answered(&written));
}

#[test]
fn the_answer_in_a_prack_to_an_offer_in_a_reliable_183_is_taken() {
    // RFC 3262 §5: an INVITE with no offer, a reliable 183 carrying this
    // end's, and the answer in the PRACK. Read as a new offer, it was
    // compared with a session that had no far end yet and dropped
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(
        &mut agent,
        &plus(&incoming_invite("reloffered", None), "Require: 100rel\r\n"),
        t0,
    );
    agent
        .ring(call, Some(Arc::from(ANSWER)), t0)
        .expect("183 with this end's offer");
    let progress = sent(&mut agent);
    let rseq = String::from_utf8_lossy(&header(&progress, HeaderName::RSeq)).into_owned();
    events(&mut agent);

    let prack = carrying(
        &in_dialog(&progress, "PRACK", "relofferedprack", 2),
        "application/sdp",
        &format!("RAck: {rseq} 1 INVITE\r\n"),
        std::str::from_utf8(OFFER).expect("text"),
    );
    deliver(&mut agent, &prack, t0);
    let answer = prack_answer(&transmits(&mut agent), 2);
    assert!(answer.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert!(body_of(&answer).is_empty(), "an answer is not answered");
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            UaEvent::SessionChanged { call: changed, remote: Some(remote), .. }
                if *changed == call && remote.as_ref() == OFFER
        )),
        "{seen:?}"
    );
}

#[test]
fn a_reinvite_or_update_with_a_body_this_agent_cannot_read_is_refused_415() {
    // RFC 3261 §8.2.3, asked of every request and not only the INVITE that
    // opens a call: "the UAS MUST reject the request with a 415", with an
    // Accept "listing the types of all bodies it understands". Handed over,
    // the body was answered later with whatever the application made of it
    for method in ["INVITE", "UPDATE"] {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let (call, ack) = call_up(&mut agent, id, t0);
        let before = agent.hold_state(call);
        let request = carrying(
            &reversed(&ack, method, "isup", 2, None),
            "application/isup",
            "Session-Expires: 1800;refresher=uas\r\n",
            ISUP,
        );
        deliver(&mut agent, &request, t0);
        let answer = last(&mut agent);
        assert!(
            answer.starts_with(b"SIP/2.0 415 "),
            "{method}: {}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(header(&answer, HeaderName::Accept), b"application/sdp");
        let said = events(&mut agent);
        assert!(
            !said.iter().any(|event| matches!(
                event,
                UaEvent::Reoffer { .. } | UaEvent::SessionChanged { .. }
            )),
            "{method}: {said:?}"
        );
        assert_eq!(agent.hold_state(call), before, "{method}");

        // encoded the way this agent does not decode, it is refused with the
        // encodings this agent does
        let request = carrying(
            &reversed(&ack, method, "gzip", 3, None),
            "application/sdp",
            "Content-Encoding: gzip\r\n",
            "v=0\r\n",
        );
        deliver(&mut agent, &request, t0);
        let answer = last(&mut agent);
        assert!(answer.starts_with(b"SIP/2.0 415 "), "{method}");
        assert_eq!(
            header(&answer, HeaderName::Extension("Accept-Encoding")),
            b"identity"
        );
    }
}

#[test]
fn a_body_its_sender_marked_optional_is_ignored_rather_than_refused() {
    // §8.2.3 refuses a body "not optional (as indicated by the
    // Content-Disposition header field)", and §20.11's handling=optional is
    // the sender saying it may be ignored: a re-INVITE carrying nothing else
    // asks for an offer (§14.1), and an UPDATE only refreshes the target
    for (method, offers) in [("INVITE", true), ("UPDATE", false)] {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let (_, ack) = call_up(&mut agent, id, t0);
        let request = carrying(
            &reversed(&ack, method, "optional", 2, None),
            "application/isup",
            "Content-Disposition: signal;handling=optional\r\n",
            ISUP,
        );
        deliver(&mut agent, &request, t0);
        let answer = last(&mut agent);
        assert!(
            answer.starts_with(b"SIP/2.0 200 "),
            "{method}: {}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(
            body_of(&answer).contains("m=audio"),
            offers,
            "{method}: {}",
            String::from_utf8_lossy(&answer)
        );
        assert!(
            !events(&mut agent)
                .iter()
                .any(|event| matches!(event, UaEvent::Reoffer { .. })),
            "{method}"
        );
    }
}

/// One request of `method`, arriving where this agent takes it, and what the
/// agent wrote and said about it: the handler behind each entry of `Allow`.
fn allowed_request_arriving(method: &str) -> (Vec<Vec<u8>>, Vec<UaEvent>) {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let out_of_dialog = |method: &str, extra: &str, body: &str| {
        let request = peer_request(
            "<sip:bob@example.com>;tag=allowed",
            "<sip:alice@example.com>",
            &format!("allowed-{method}"),
            method,
            &format!("allowed{method}"),
            1,
            None,
        );
        if body.is_empty() {
            plus(&request, extra)
        } else {
            carrying(&request, "text/plain", extra, body)
        }
    };
    let request = match method {
        "INVITE" => incoming_invite("allowedinvite", Some(OFFER)),
        "ACK" => {
            let call = call_arriving(&mut agent, &incoming_invite("allowedack", Some(OFFER)), t0);
            agent
                .answer(call, Some(Arc::from(ANSWER)), t0)
                .expect("200 goes");
            in_dialog(&sent(&mut agent), "ACK", "allowedack", 1)
        }
        "CANCEL" => {
            let invite = incoming_invite("allowedcancel", Some(OFFER));
            call_arriving(&mut agent, &invite, t0);
            String::from_utf8(incoming_invite("allowedcancel", None))
                .expect("text")
                .replacen("INVITE ", "CANCEL ", 1)
                .replace("CSeq: 1 INVITE", "CSeq: 1 CANCEL")
                .into_bytes()
        }
        "PRACK" => {
            let call = call_arriving(&mut agent, &incoming_100rel("allowedprack", true), t0);
            agent.ring(call, None, t0).expect("180 goes");
            let ringing = sent(&mut agent);
            let rseq = text(&ringing, HeaderName::RSeq);
            plus(
                &in_dialog(&ringing, "PRACK", "allowedprack", 2),
                &format!("RAck: {rseq} 1 INVITE\r\n"),
            )
        }
        "OPTIONS" => out_of_dialog("OPTIONS", "", ""),
        "MESSAGE" => out_of_dialog("MESSAGE", "", "hello"),
        // §4.1.3 of RFC 6665 answers one nobody subscribed to, and that
        // answer is the subscription handler's
        "NOTIFY" => out_of_dialog(
            "NOTIFY",
            "Event: message-summary\r\nSubscription-State: active\r\n",
            "",
        ),
        in_a_call => {
            let (_, ack) = call_up(&mut agent, id, t0);
            let request = reversed(&ack, in_a_call, "allowedincall", 2, None);
            match in_a_call {
                "BYE" | "UPDATE" => request,
                "REFER" => plus(&request, "Refer-To: <sip:carol@example.com>\r\n"),
                "INFO" => carrying(
                    &request,
                    "application/dtmf-relay",
                    "",
                    "Signal=7\r\nDuration=200\r\n",
                ),
                other => panic!("Allow lists {other}, and nothing here says what takes it"),
            }
        }
    };
    transmits(&mut agent);
    events(&mut agent);
    deliver(&mut agent, &request, t0);
    (transmits(&mut agent), events(&mut agent))
}

#[test]
fn allow_lists_exactly_the_methods_this_agent_has_a_handler_for() {
    // §20.5: "The Allow header field lists the set of methods supported by
    // the UA generating the message", and a 405 carries it (§21.4.6). Each
    // method listed arrives where it is taken and is neither refused as
    // unsupported nor left to the application, which has no way to answer
    // it; each one RFC 3261 and its extensions define that is not listed is
    // refused 405 with that same list
    let listed: Vec<&str> = std::str::from_utf8(crate::renegotiate::ALLOW)
        .expect("text")
        .split(',')
        .map(str::trim)
        .collect();
    for method in &listed {
        let (written, said) = allowed_request_arriving(method);
        let answers: Vec<u16> = written
            .iter()
            .filter(|bytes| bytes.starts_with(b"SIP/2.0 "))
            .filter(|bytes| text(bytes, HeaderName::CSeq).ends_with(method))
            .map(|bytes| with(bytes, |m| m.status().map_or(0, StatusCode::get)))
            .collect();
        assert!(
            answers
                .iter()
                .all(|status| *status != 405 && *status != 501),
            "{method} is listed and refused: {answers:?}"
        );
        assert!(
            !said.iter().any(|event| matches!(
                event,
                UaEvent::Unclaimed(
                    Event::IncomingOutOfDialog { .. }
                        | Event::IncomingInDialog { .. }
                        | Event::IncomingInvite { .. }
                        | Event::IncomingReinvite { .. }
                )
            )),
            "{method} is listed and nothing here took it: {said:?}"
        );
        let expected: &[u16] = match *method {
            // an ACK is never answered (§17.1.1.3), and an INVITE or a
            // REFER waits on the application, with only a 100 on the wire
            "ACK" | "REFER" => &[],
            "INVITE" => &[100],
            "NOTIFY" => &[481],
            _ => &[200],
        };
        let mut answers = answers;
        answers.sort_unstable();
        assert_eq!(answers, expected, "{method}");
    }

    // every method RFC 3261 and the extensions this stack reads define, so
    // that one taken and left out of the list is caught as surely as one
    // listed and not taken
    let defined = [
        "INVITE",
        "ACK",
        "CANCEL",
        "BYE",
        "OPTIONS",
        "REGISTER",
        "PRACK",
        "SUBSCRIBE",
        "NOTIFY",
        "PUBLISH",
        "INFO",
        "REFER",
        "MESSAGE",
        "UPDATE",
    ];
    assert!(
        listed.iter().all(|method| defined.contains(method)),
        "{listed:?}"
    );
    let t0 = Instant::now();
    for unlisted in defined
        .into_iter()
        .filter(|method| !listed.contains(method))
    {
        let mut agent = agent(t0);
        agent.add_account(account());
        let request = peer_request(
            "<sip:bob@example.com>;tag=unlisted",
            "<sip:alice@example.com>",
            &format!("unlisted-{unlisted}"),
            unlisted,
            &format!("unlisted{unlisted}"),
            1,
            None,
        );
        deliver(&mut agent, &request, t0);
        let answer = last(&mut agent);
        assert!(answer.starts_with(b"SIP/2.0 405 "), "{unlisted}");
        assert_eq!(
            header(&answer, HeaderName::Allow),
            crate::renegotiate::ALLOW,
            "{unlisted}"
        );
    }
}

#[test]
fn an_early_answer_past_the_configured_sdp_bound_is_refused() {
    let t0 = Instant::now();
    let mut config = EndpointConfig::default();
    config.sdp_limits = sdp::Limits {
        max_media: 1,
        ..sdp::Limits::DEFAULT
    };
    let mut agent = agent_with(config, t0);
    let id = agent.add_account(account());
    let call = agent
        .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    let progress = plus(
        &answered(&invite, 183, "Session Progress", "desk", Some(ANSWER)),
        "Require: 100rel\r\nRSeq: 314\r\n",
    );
    deliver(&mut agent, &progress, t0);
    events(&mut agent);

    let two_streams: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\nm=video 8002 RTP/AVP 31\r\n";
    let err = agent
        .answer_early(call, two_streams, t0)
        .expect_err("a second stream is past the configured bound");
    assert_eq!(
        err,
        UaError::Sdp(sdp::SdpError::TooManyStreams { limit: 1 })
    );
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

// -- calls nobody asked for --------------------------------------------------

/// One of the machines that dial every extension at three in the morning.
fn scanner(last: u8) -> SocketAddr {
    format!("198.51.100.{last}:5060")
        .parse()
        .expect("a scanner's address")
}

/// The same as [`deliver`], from an address of the test's choosing.
fn deliver_from(agent: &mut UserAgent, bytes: &[u8], from: SocketAddr, now: Instant) {
    agent
        .receive(
            Input::Datagram {
                transport: UDP,
                remote: from,
                local: local(),
                data: bytes,
            },
            now,
        )
        .expect("a well formed datagram");
}

/// How many of these are somebody calling.
fn ringing(agent: &mut UserAgent) -> usize {
    events(agent)
        .iter()
        .filter(|event| matches!(**event, UaEvent::IncomingCall { .. }))
        .count()
}

#[test]
fn a_screened_invite_is_never_heard_and_leaves_nothing_behind() {
    // A8: the policy runs before any user-visible effect, which means before
    // the event and before there is a call to have an event about
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.screen(|_: &Incoming<'_>| Screening::Refuse(StatusCode::new(480).expect("a status")));

    deliver_from(
        &mut agent,
        &incoming_invite("scan", Some(OFFER)),
        scanner(1),
        t0,
    );

    assert!(last(&mut agent).starts_with(b"SIP/2.0 480 Temporarily Unavailable\r\n"));
    assert!(
        agent.calls.is_empty() && agent.by_server.is_empty(),
        "nothing was written down that a caller could observe"
    );
    assert!(
        events(&mut agent).is_empty(),
        "and the application was told nothing at all"
    );
    assert_eq!(agent.refusals().by_policy, 1);
}

#[test]
fn a_policy_that_takes_the_call_changes_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.screen(|_: &Incoming<'_>| Screening::Take);

    deliver(&mut agent, &incoming_invite("in1", Some(OFFER)), t0);
    transmits(&mut agent);

    let incoming = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall {
                call,
                account,
                request,
                ..
            } => Some((call, account, request)),
            _ => None,
        })
        .expect("somebody is calling");
    assert_eq!(incoming.1, Some(id));
    assert_eq!(incoming.2.as_raw().body(), OFFER);
    assert_eq!(agent.call_state(incoming.0), Some(CallState::Incoming));
    assert_eq!(agent.refusals(), Refusals::default());
}

#[test]
fn the_policy_decides_from_where_it_came_from_and_what_it_says() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.screen(|invite: &Incoming<'_>| {
        let stranger = invite
            .source()
            .is_some_and(|source| source.ip() == scanner(1).ip());
        let asked_for_alice = invite
            .request()
            .as_raw()
            .header(HeaderName::To)
            .is_some_and(|to| to.windows(5).any(|part| part == b"alice"));
        if stranger && asked_for_alice {
            Screening::Refuse(StatusCode::BUSY_HERE)
        } else {
            Screening::Take
        }
    });

    deliver_from(
        &mut agent,
        &incoming_invite("s1", Some(OFFER)),
        scanner(1),
        t0,
    );
    assert!(last(&mut agent).starts_with(b"SIP/2.0 486 "));
    assert_eq!(ringing(&mut agent), 0);

    // the same request from the address the phone is registered with
    deliver(&mut agent, &incoming_invite("s2", Some(OFFER)), t0);
    transmits(&mut agent);
    assert_eq!(ringing(&mut agent), 1, "not everybody is a scanner");
}

#[test]
fn an_invite_on_a_stream_is_screened_by_the_far_end_of_the_connection() {
    // there is no address on the bytes here: it is the one the application
    // named when it said the connection was open
    let t0 = Instant::now();
    let (mut agent, _) = over_tcp(t0);
    agent.screen(|invite: &Incoming<'_>| match invite.source() {
        Some(source) if source == registrar() => Screening::Refuse(StatusCode::BUSY_HERE),
        _ => Screening::Take,
    });

    stream(&mut agent, &incoming_invite("tcp1", Some(OFFER)), t0);

    assert!(last(&mut agent).starts_with(b"SIP/2.0 486 "));
    assert_eq!(ringing(&mut agent), 0);
}

#[test]
fn a_source_dialling_faster_than_the_limit_stops_being_heard() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.limit_invites(Rate::new(2, Duration::from_secs(30)).expect("a usable rate"));

    for attempt in 0..2 {
        let invite = incoming_invite(&format!("burst{attempt}"), Some(OFFER));
        deliver_from(&mut agent, &invite, scanner(1), t0);
    }
    transmits(&mut agent);
    assert_eq!(ringing(&mut agent), 2, "the burst is what a phone does");

    deliver_from(
        &mut agent,
        &incoming_invite("over", Some(OFFER)),
        scanner(1),
        t0,
    );
    assert!(last(&mut agent).starts_with(b"SIP/2.0 480 Temporarily Unavailable\r\n"));
    assert_eq!(ringing(&mut agent), 0);
    assert_eq!(agent.refusals().by_rate, 1);
    assert_eq!(agent.calls.len(), 2, "the two that were taken, and no more");

    // and the allowance comes back when the source stops hammering
    let later = t0 + Duration::from_secs(30);
    deliver_from(
        &mut agent,
        &incoming_invite("after", Some(OFFER)),
        scanner(1),
        later,
    );
    transmits(&mut agent);
    assert_eq!(ringing(&mut agent), 1);
}

#[test]
fn a_stream_with_no_far_end_named_is_limited_as_itself() {
    // a connection the application bound without saying who was at the other
    // end has no address on its bytes; counted by address it was not counted
    // at all, and a scanner on it rang the phone as fast as it could write
    let t0 = Instant::now();
    let mut agent = UserAgent::new(EndpointConfig::default(), [13; 32]).unwrap();
    let anonymous = |transport| Input::TransportBound {
        transport,
        protocol: TransportProtocol::Tcp,
        local: local(),
        remote: None,
    };
    let on = |agent: &mut UserAgent, transport, bytes: &[u8], now| {
        agent
            .receive(
                Input::StreamData {
                    transport,
                    data: bytes,
                },
                now,
            )
            .expect("bytes on a stream");
    };
    let other = TransportId(3);
    for transport in [TCP, other] {
        agent.receive(anonymous(transport), t0).expect("bound");
    }
    agent.add_account(account());
    agent.limit_invites(Rate::new(1, Duration::from_secs(30)).expect("a usable rate"));

    on(&mut agent, TCP, &incoming_invite("anon1", Some(OFFER)), t0);
    transmits(&mut agent);
    assert_eq!(ringing(&mut agent), 1, "the first is inside the burst");

    on(&mut agent, TCP, &incoming_invite("anon2", Some(OFFER)), t0);
    assert!(last(&mut agent).starts_with(b"SIP/2.0 480 "));
    assert_eq!(ringing(&mut agent), 0);
    assert_eq!(agent.refusals().by_rate, 1);

    // another connection is another caller, as another address would be
    on(
        &mut agent,
        other,
        &incoming_invite("anon3", Some(OFFER)),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(ringing(&mut agent), 1);

    // and a connection that closed takes what it spent with it: the next one
    // handed the same identifier starts with a full allowance
    agent
        .receive(Input::StreamClosed { transport: TCP }, t0)
        .expect("closed");
    agent.receive(anonymous(TCP), t0).expect("bound again");
    transmits(&mut agent);
    events(&mut agent);
    on(&mut agent, TCP, &incoming_invite("anon4", Some(OFFER)), t0);
    transmits(&mut agent);
    assert_eq!(ringing(&mut agent), 1);
    assert_eq!(agent.refusals().by_rate, 1);
}

#[test]
fn a_new_source_port_is_not_a_new_caller() {
    // changing the port costs a scanner nothing, so the allowance is kept
    // against the address it would have to own to hear an answer
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.limit_invites(Rate::new(1, Duration::from_secs(30)).expect("a usable rate"));

    deliver_from(
        &mut agent,
        &incoming_invite("p1", Some(OFFER)),
        scanner(1),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(ringing(&mut agent), 1);

    let moved = SocketAddr::new(scanner(1).ip(), 41_234);
    deliver_from(&mut agent, &incoming_invite("p2", Some(OFFER)), moved, t0);
    assert!(last(&mut agent).starts_with(b"SIP/2.0 480 "));
    assert_eq!(ringing(&mut agent), 0);
    assert_eq!(agent.refusals().by_rate, 1);
}

#[test]
fn the_limit_is_one_sources_and_not_everybodys() {
    // a scanner that has used up its own allowance must not be able to spend
    // the switchboard's with it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.limit_invites(Rate::new(1, Duration::from_secs(30)).expect("a usable rate"));

    deliver_from(
        &mut agent,
        &incoming_invite("s1", Some(OFFER)),
        scanner(1),
        t0,
    );
    deliver_from(
        &mut agent,
        &incoming_invite("s2", Some(OFFER)),
        scanner(1),
        t0,
    );
    transmits(&mut agent);
    assert_eq!(ringing(&mut agent), 1);

    deliver(&mut agent, &incoming_invite("pbx", Some(OFFER)), t0);
    transmits(&mut agent);
    assert_eq!(
        ringing(&mut agent),
        1,
        "the call from the proxy still rings"
    );
    assert_eq!(agent.refusals().by_rate, 1);
}

#[test]
fn the_limit_answers_before_the_policy_is_troubled_with_a_flood() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.limit_invites(Rate::new(1, Duration::from_secs(30)).expect("a usable rate"));
    agent.screen(|_: &Incoming<'_>| Screening::Refuse(StatusCode::BUSY_HERE));

    deliver_from(
        &mut agent,
        &incoming_invite("s1", Some(OFFER)),
        scanner(1),
        t0,
    );
    assert!(
        last(&mut agent).starts_with(b"SIP/2.0 486 "),
        "the first one reached the policy"
    );

    deliver_from(
        &mut agent,
        &incoming_invite("s2", Some(OFFER)),
        scanner(1),
        t0,
    );
    assert!(
        last(&mut agent).starts_with(b"SIP/2.0 480 "),
        "the second was refused by the limit, which never asked"
    );
    assert_eq!(agent.refusals().by_policy, 1);
    assert_eq!(agent.refusals().by_rate, 1);
}

#[test]
fn what_was_refused_is_counted_from_the_beginning_and_not_from_the_last_look() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.screen(|_: &Incoming<'_>| Screening::Refuse(StatusCode::BUSY_HERE));

    for attempt in 0..3 {
        let invite = incoming_invite(&format!("scan{attempt}"), Some(OFFER));
        deliver_from(&mut agent, &invite, scanner(1), t0);
        transmits(&mut agent);
        assert_eq!(
            agent.refusals().by_policy,
            attempt + 1,
            "reading the counter does not empty it"
        );
    }
}

#[test]
fn a_refusal_is_decided_before_anything_else_looks_at_the_invite() {
    // §8.2.2.3 has this INVITE refused with a 420, and that refusal is decided
    // by the call handler further down the chain. A screened INVITE never
    // reaches it, so the answer is the policy's rather than the protocol's
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.screen(|_: &Incoming<'_>| Screening::Refuse(StatusCode::new(480).expect("a status")));

    deliver_from(
        &mut agent,
        &plus(
            &incoming_invite("odd", Some(OFFER)),
            "Require: gruu, 100rel\r\n",
        ),
        scanner(1),
        t0,
    );

    assert!(last(&mut agent).starts_with(b"SIP/2.0 480 "));
    assert_eq!(agent.refusals().by_policy, 1);
}

#[test]
fn a_screened_invite_never_tells_the_far_end_that_the_number_rings() {
    // A8's "before any user-visible effect" is also what the caller sees. The
    // 100 §17.2.1 lets a server transaction send says the request is being
    // worked on and nothing about who is behind it; a 180 or a 183 would say
    // that a telephone is ringing, which is the whole of what a scanner dials
    // to find out
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.screen(|_: &Incoming<'_>| Screening::Refuse(StatusCode::new(480).expect("a status")));

    deliver_from(
        &mut agent,
        &incoming_invite("quiet", Some(OFFER)),
        scanner(1),
        t0,
    );

    let written = transmits(&mut agent);
    let heads: Vec<_> = written
        .iter()
        .map(|message| String::from_utf8_lossy(&message[..15]).into_owned())
        .collect();
    assert_eq!(heads, ["SIP/2.0 100 Try", "SIP/2.0 480 Tem"], "{heads:?}");
}

#[test]
fn a_flood_from_many_addresses_is_counted_apart_from_one_source_calling_too_fast() {
    // the same 480 from the far end, and two different things to do about it:
    // one is the limit set too tight, the other is a table with no seat left
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.limit_invites(Rate::new(1, Duration::from_secs(600)).expect("a usable rate"));

    // one call each from more addresses than there are seats
    for last in 0..=200u8 {
        let invite = incoming_invite(&format!("flood{last}"), Some(OFFER));
        deliver_from(&mut agent, &invite, scanner(last), t0);
        transmits(&mut agent);
        events(&mut agent);
    }

    let refused = agent.refusals();
    assert!(refused.by_crowding > 0, "{refused:?}");
    assert_eq!(refused.by_rate, 0, "nobody called twice: {refused:?}");
    assert_eq!(refused.by_policy, 0);
}

#[test]
fn the_limit_that_took_effect_is_the_one_that_reads_back() {
    // B2: applied, and the effective value reads back
    let t0 = Instant::now();
    let mut agent = agent(t0);
    assert_eq!(agent.invite_limit(), Rate::default());

    let asked = Rate::new(3, Duration::from_secs(11)).expect("a usable rate");
    agent.limit_invites(asked);
    assert_eq!(agent.invite_limit(), asked);
    assert_eq!(agent.invite_limit().burst(), 3);
    assert_eq!(
        agent.invite_limit().every(),
        Some(Duration::from_secs(11)),
        "the interval was not rounded, capped or read as something else"
    );
}

#[test]
fn a_limit_that_would_admit_nothing_is_refused_where_it_is_set() {
    // and refused there rather than at the door, so that the deployment which
    // wrote it hears about it instead of a caller who never gets through
    assert_eq!(
        Rate::new(0, Duration::from_secs(2)),
        Err(RateError::NoBurst)
    );
    assert_eq!(Rate::new(4, Duration::ZERO), Err(RateError::NoInterval));

    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    agent.limit_invites(Rate::unlimited());
    for attempt in 0..50 {
        let invite = incoming_invite(&format!("open{attempt}"), Some(OFFER));
        deliver_from(&mut agent, &invite, scanner(1), t0);
        transmits(&mut agent);
    }
    assert_eq!(
        agent.refusals(),
        Refusals::default(),
        "asking for no limit is how a deployment gets none"
    );
}

// -- transfer ----------------------------------------------------------------

/// The `tag=` parameter of a header value.
fn tag_of(bytes: &[u8], name: HeaderName<'_>) -> String {
    let value = String::from_utf8_lossy(&header(bytes, name)).into_owned();
    value
        .split(";tag=")
        .nth(1)
        .map(|rest| rest.split(';').next().unwrap_or("").to_owned())
        .unwrap_or_default()
}

// -- §8.2.2.3, on every request and not only the one that opens a call -------

/// The `Unsupported` header of the 420 among what went out.
///
/// Not `only`: an INVITE gets a 100 from the core before anything above it
/// has an opinion, so the 420 shares the batch with it.
fn refused_extension(out: &[Vec<u8>]) -> String {
    let answer = out
        .iter()
        .find(|bytes| bytes.starts_with(b"SIP/2.0 420 "))
        .unwrap_or_else(|| {
            panic!(
                "no 420 went out; what did: {:?}",
                out.iter()
                    .map(
                        |bytes| String::from_utf8_lossy(bytes.get(..12).unwrap_or(bytes))
                            .into_owned()
                    )
                    .collect::<Vec<_>>()
            )
        });
    text(answer, HeaderName::Unsupported)
}

#[test]
fn an_update_demanding_an_extension_we_lack_is_refused_rather_than_applied() {
    // the INVITE that opens a call was already refused; a request inside one
    // was not, and a session change honoured because nobody read its Require
    // is a change that has to be undone rather than declined
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    let theirs = plus(
        &reversed(&ack, "UPDATE", "req", 1, None),
        "Require: rendering-of-the-caller-in-oils\r\n",
    );
    deliver(&mut agent, &theirs, t0);

    assert_eq!(
        refused_extension(&transmits(&mut agent)),
        "rendering-of-the-caller-in-oils"
    );
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Reoffer { .. })),
        "the application is not asked about a request that was refused"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_reinvite_demanding_an_extension_we_lack_is_refused_on_its_own_transaction() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);

    let theirs = plus(
        &reversed(&ack, "INVITE", "req2", 1, Some(THEIR_HOLD)),
        "Require: rendering-of-the-caller-in-oils\r\n",
    );
    deliver(&mut agent, &theirs, t0);

    assert_eq!(
        refused_extension(&transmits(&mut agent)),
        "rendering-of-the-caller-in-oils"
    );
}

#[test]
fn only_the_tags_we_do_not_know_are_listed_back() {
    // "list in it those options it does not understand amongst those in the
    // Require header field" -- the ones we do understand are not a complaint
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);

    let theirs = plus(
        &reversed(&ack, "UPDATE", "req3", 1, None),
        "Require: timer, oils, replaces, gilt\r\n",
    );
    deliver(&mut agent, &theirs, t0);

    assert_eq!(refused_extension(&transmits(&mut agent)), "oils, gilt");
}

#[test]
fn an_extension_we_do_implement_is_not_refused() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);

    let theirs = plus(
        &reversed(&ack, "UPDATE", "req4", 1, Some(THEIR_HOLD)),
        "Require: timer\r\n",
    );
    deliver(&mut agent, &theirs, t0);

    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 200 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
}

#[test]
fn an_options_demanding_an_extension_we_lack_is_refused_too() {
    // §8.2.2.3 says a UAS, not an INVITE, and the OPTIONS handler answers 200
    // to anything it is given
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let _ = agent.add_account(account());

    let probe = concat!(
        "OPTIONS sip:alice@192.0.2.1 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKopt\r\n",
        "From: <sip:probe@192.0.2.9>;tag=p1\r\n",
        "To: <sip:alice@192.0.2.1>\r\n",
        "Call-ID: opt-require\r\n",
        "CSeq: 1 OPTIONS\r\n",
        "Max-Forwards: 70\r\n",
        "Require: rendering-of-the-caller-in-oils\r\n",
        "Content-Length: 0\r\n\r\n",
    );
    deliver(&mut agent, probe.as_bytes(), t0);

    assert_eq!(
        refused_extension(&transmits(&mut agent)),
        "rendering-of-the-caller-in-oils"
    );
}

#[test]
fn a_notify_for_another_event_package_is_not_eaten_as_a_transfer_report() {
    // RFC 6665 §8.2.1 makes the Event header what identifies a notification,
    // and a dialog carries as many packages as anybody subscribed to. A phone
    // watching this line sends `dialog`; a mailbox sends `message-summary`.
    // Claiming those on the method alone answered them 200, dropped the body,
    // and reported a transfer that nobody asked for.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = only(&transmits(&mut agent), "REFER ");
    deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
    events(&mut agent);

    let theirs = plus(
        &reversed(&ack, "NOTIFY", "blf", 1, None),
        "Event: dialog\r\nSubscription-State: active\r\n",
    );
    deliver(&mut agent, &theirs, t0);

    let out = transmits(&mut agent);
    let answer = only(&out, "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 481 "),
        "§4.1.3: a notification matching no subscription is refused, not \
         swallowed: {}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        !events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::TransferDone { .. } | UaEvent::TransferProgress { .. }
        )),
        "somebody else's notification is not news about our transfer"
    );

    // and the transfer's own subscription still works afterwards
    deliver(&mut agent, &notify(&ack, 2, "200 OK", "terminated"), t0);
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::TransferDone { .. })),
        "the refer package is still claimed"
    );
}

/// A NOTIFY from the transferee, reporting how the referred call is going.
fn notify(ours: &[u8], cseq: u32, status: &str, state: &str) -> Vec<u8> {
    let body = format!("SIP/2.0 {status}\r\n");
    let head = reversed(ours, "NOTIFY", &format!("nfy{cseq}"), cseq, None);
    let head = plus(
        &head,
        &format!("Event: refer\r\nSubscription-State: {state}\r\n"),
    );
    // put the sipfrag in, replacing the empty body
    let text = String::from_utf8_lossy(&head).into_owned();
    let text = text.replace(
        "Content-Length: 0\r\n\r\n",
        &format!(
            "Content-Type: message/sipfrag;version=2.0\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    );
    text.into_bytes()
}

#[test]
fn a_blind_transfer_refers_the_far_end_and_waits_to_be_told() {
    // 2.4.4: the far end reports in NOTIFYs, and this end does not hang up
    // until it knows the transfer worked
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    assert!(refer.starts_with(b"REFER sip:bob@192.0.2.9 SIP/2.0\r\n"));
    assert_eq!(
        header(&refer, HeaderName::ReferTo),
        b"<sip:carol@example.com>"
    );
    // 2: "REFER creates a dialog ... hence MUST contain a single Contact"
    assert_eq!(
        header(&refer, HeaderName::Contact),
        b"<sip:alice@192.0.2.1>"
    );
    deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
    events(&mut agent);

    deliver(&mut agent, &notify(&ack, 1, "100 Trying", "active"), t0);
    transmits(&mut agent);
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::TransferProgress { status, .. } if status == StatusCode::TRYING
        )),
        "the far end is trying"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));

    deliver(
        &mut agent,
        &notify(&ack, 2, "200 OK", "terminated;reason=noresource"),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(
        written.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "and now this end is not in the call any more"
    );
    assert!(events(&mut agent).iter().any(|event| matches!(
        *event,
        UaEvent::TransferDone { status, .. } if status == StatusCode::OK
    )));
}

#[test]
fn the_refer_this_call_sends_names_its_own_from_as_referred_by_not_its_contact() {
    // RFC 3892 §1: Referred-By identifies the referrer, and the identity a
    // call's own From already showed the far end discloses nothing new; its
    // Contact is a different thing, and can now be a GRUU (RFC 5627 §4.4)
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(gruu_account());
    serviced_registration(&mut agent, id, SERVICES, t0);
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    assert_eq!(
        header(&refer, HeaderName::Contact),
        angled(PUBLIC_GRUU),
        "sanity: the Contact is the GRUU this test is telling Referred-By apart from"
    );
    let referred_by = text(&refer, HeaderName::ReferredBy);
    assert!(
        referred_by.contains("alice@example.com"),
        "names the account's own From, not its Contact: {referred_by}"
    );
    assert!(
        !referred_by.contains("gr="),
        "and never a GRUU: {referred_by}"
    );
}

#[test]
fn the_refer_an_answered_call_sends_names_the_address_it_answered_as() {
    // RFC 3261 §12.1.1: the local URI of a dialog this end answered is the To
    // of the INVITE, and every request this end sends in it carries that as
    // its From. The line was found by its contact, not its address of record,
    // so the address the call presented is the number that was dialled -- and
    // the Referred-By that names this end names that, not the account's
    // address of record the far end was never shown
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let _ = agent.add_account(account());
    let invite = String::from_utf8(incoming_invite("rb-in", Some(OFFER)))
        .expect("an INVITE in text")
        .replace(
            "To: Alice <sip:alice@example.com>",
            "To: <sip:+15551234567@example.com;user=phone>",
        );
    let call = call_arriving(&mut agent, invite.as_bytes(), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "rb-inack", 1), t0);
    events(&mut agent);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    assert!(
        text(&refer, HeaderName::From).starts_with("<sip:+15551234567@example.com;user=phone>"),
        "sanity: the From this end writes in the dialog: {}",
        String::from_utf8_lossy(&refer)
    );
    assert_eq!(
        text(&refer, HeaderName::ReferredBy),
        "<sip:+15551234567@example.com;user=phone>"
    );
}

#[test]
fn a_transfer_that_failed_leaves_the_call_exactly_where_it_was() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
    events(&mut agent);

    deliver(
        &mut agent,
        &notify(&ack, 1, "486 Busy Here", "terminated;reason=noresource"),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(
        !written.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "nothing was transferred, so nothing was given up"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));

    // the terminated NOTIFY is the last word on the subscription the 202
    // opened (§2.4.7), so the seat it took is free again
    agent
        .transfer(call, &uri("sip:dave@example.com"), t0)
        .expect("the seat is free once the subscription itself has ended");
    assert_eq!(
        header(&sent(&mut agent), HeaderName::ReferTo),
        b"<sip:dave@example.com>"
    );
}

#[test]
fn a_refer_that_timed_out_leaves_the_call_able_to_ask_again() {
    // Timer F expires with nothing back at all, and the far end never opened
    // a subscription to free later: the seat has to go back here or the call
    // could never transfer again
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    sent(&mut agent);
    events(&mut agent);

    // 64*T1 is 32 seconds at the default T1. Nothing drains the
    // retransmissions Timer E queued along the way -- they are still
    // sitting in the transmit queue, the same as any other timer jump this
    // file makes in one bound rather than one retransmission at a time --
    // so they are drained here rather than mistaken for the second REFER
    agent.handle_timeout(t0 + Duration::from_secs(33));
    transmits(&mut agent);
    events(&mut agent);

    let second = agent.transfer(call, &uri("sip:dave@example.com"), t0);
    assert!(second.is_ok(), "{second:?}");
    assert_eq!(
        header(&sent(&mut agent), HeaderName::ReferTo),
        b"<sip:dave@example.com>"
    );
}

#[test]
fn a_refer_whose_transport_failed_leaves_the_call_able_to_ask_again() {
    // RFC 3261 §8.1.3.1's other unanswered case: the transport gave up
    // rather than the timer, and the seat is owed back the same way.
    //
    // The call's own INVITE client transaction sits in RFC 6026's
    // `Accepted` state for Timer M -- the same 64*T1 as the REFER's own
    // Timer F -- so it is let run out first: failing the transport at the
    // moment the call went up would fail that still-open transaction too,
    // over the same transport, and end the call before the REFER's own
    // seat could ever be asked about again.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    let t1 = t0 + Duration::from_secs(33);
    agent.handle_timeout(t1);
    transmits(&mut agent);
    events(&mut agent);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t1)
        .expect("the REFER goes");
    sent(&mut agent);
    events(&mut agent);

    agent
        .receive(
            Input::TransportFailed {
                transport: UDP,
                error: sipral_core::endpoint::TransportErrorKind::Unreachable,
            },
            t1,
        )
        .expect("the failure is taken");
    transmits(&mut agent);
    events(&mut agent);
    assert_eq!(
        agent.call_state(call),
        Some(CallState::Confirmed),
        "the REFER's own transaction was the only one left on that transport"
    );

    // the network came back, the way it would for a real flow
    agent
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            t1,
        )
        .expect("binding a transport again");

    let second = agent.transfer(call, &uri("sip:dave@example.com"), t1);
    assert!(second.is_ok(), "{second:?}");
    assert_eq!(
        header(&sent(&mut agent), HeaderName::ReferTo),
        b"<sip:dave@example.com>"
    );
}

#[test]
fn a_subscription_ended_before_any_final_status_leaves_the_call_able_to_ask_again() {
    // RFC 3515 §2.4.4: "agents accepting REFER and not wishing to hold
    // subscription state can terminate the subscription with this initial
    // NOTIFY", and §2.4.5 has a NOTIFY sent while the reference is still
    // pending carry a 100. Nothing follows a terminated subscription (RFC
    // 6665 §4.1.3), so whatever its body said -- a provisional status, or one
    // this end cannot read at all -- the seat that REFER held goes back.
    for body in ["100 Trying", "not a status line"] {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let (call, ack) = call_up(&mut agent, id, t0);
        agent
            .transfer(call, &uri("sip:carol@example.com"), t0)
            .expect("the REFER goes");
        let refer = sent(&mut agent);
        deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
        events(&mut agent);

        deliver(
            &mut agent,
            &notify(&ack, 1, body, "terminated;reason=noresource"),
            t0,
        );
        transmits(&mut agent);
        events(&mut agent);
        assert_eq!(agent.call_state(call), Some(CallState::Confirmed), "{body}");

        let second = agent.transfer(call, &uri("sip:dave@example.com"), t0);
        assert!(second.is_ok(), "{body}: {second:?}");
        assert_eq!(
            header(&sent(&mut agent), HeaderName::ReferTo),
            b"<sip:dave@example.com>",
            "{body}"
        );
    }
}

#[test]
fn an_attended_transfer_names_the_dialog_it_wants_replaced() {
    // RFC 3891 §6.1: exactly one to-tag and one from-tag, and they name the
    // dialog from the point of view of the end being replaced
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);
    let (second, ack) = call_up(&mut agent, id, t0);

    agent
        .transfer_to(first, second, t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    let refer_to = String::from_utf8_lossy(&header(&refer, HeaderName::ReferTo)).into_owned();
    assert!(refer_to.contains("?Replaces="), "{refer_to}");
    // the semicolons are escaped, or they would end the URI header
    assert!(!refer_to.contains(";to-tag"), "{refer_to}");
    assert!(refer_to.contains("%3Bto-tag%3D"), "{refer_to}");

    let ours = tag_of(&ack, HeaderName::From);
    let theirs = tag_of(&ack, HeaderName::To);
    assert!(
        refer_to.contains(&format!("%3Bfrom-tag%3D{ours}")),
        "{refer_to}"
    );
    assert!(
        refer_to.contains(&format!("%3Bto-tag%3D{theirs}")),
        "{refer_to}"
    );
}

#[test]
fn an_attended_transfer_names_its_own_dialog_whatever_the_target_contact_carried() {
    // RFC 3261 Table 1 allows no URI headers in a dialog's Contact, and a
    // receiver "SHOULD ignore" them. Written through into the Refer-To they
    // are not ignored: the `?Replaces=` added after them becomes part of the
    // last header's value, so the transferee reads the Replaces the target
    // wrote into its own Contact instead of the one naming this dialog.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);
    let second = agent
        .call(id, &outgoing(), t0)
        .expect("the second INVITE goes");
    let invite = sent(&mut agent);
    let answer = String::from_utf8_lossy(&answered(&invite, 200, "OK", "desk", Some(ANSWER)))
        .replace(
            "Contact: <sip:bob@192.0.2.9>",
            "Contact: <sip:bob@192.0.2.9;method=BYE?Replaces=other%3Bto-tag%3Dx%3Bfrom-tag%3Dy>",
        );
    deliver(&mut agent, answer.as_bytes(), t0);
    let ack = sent(&mut agent);
    events(&mut agent);

    agent
        .transfer_to(first, second, t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    let refer_to = header(&refer, HeaderName::ReferTo);
    let addr = sipral_core::msg::NameAddrRef::parse(&refer_to).expect("a Refer-To");
    let target = addr.uri().sip().expect("a SIP target");
    let headers: Vec<(&str, &str)> = target.headers().collect();
    let written = String::from_utf8_lossy(&refer_to);
    assert_eq!(headers.len(), 1, "one URI header, the Replaces: {written}");
    let (name, value) = headers.first().copied().unwrap_or_default();
    assert_eq!(name, "Replaces", "{written}");
    let replaces =
        String::from_utf8_lossy(&sipral_core::msg::unescape(value.as_bytes())).into_owned();
    let call_id = String::from_utf8_lossy(&header(&ack, HeaderName::CallId)).into_owned();
    assert_eq!(
        replaces,
        format!(
            "{call_id};to-tag={};from-tag={}",
            tag_of(&ack, HeaderName::To),
            tag_of(&ack, HeaderName::From)
        ),
        "{written}"
    );
    // and a method parameter, which a Contact cannot carry either, is not
    // passed on as the method the transferee should use
    assert!(!target.has_param("method"), "{written}");
}

#[test]
fn a_refer_that_arrives_is_the_applications_to_take_or_refuse() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("ref1", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "ref1ack", 1), t0);
    events(&mut agent);

    let refer = plus(
        &in_dialog(&ok, "REFER", "ref1refer", 2),
        "Refer-To: <sip:carol@example.com>\r\n",
    );
    deliver(&mut agent, &refer, t0);
    let asked = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::TransferRequested {
                call,
                target,
                attended,
                ..
            } => Some((call, target, attended)),
            _ => None,
        })
        .expect("somebody wants a transfer");
    assert_eq!(asked.0, call);
    assert_eq!(asked.1.as_bytes(), b"sip:carol@example.com");
    assert!(!asked.2, "no Replaces, so a blind one");
    assert!(
        transmits(&mut agent).is_empty(),
        "nothing is answered on the application's behalf"
    );

    let placed = agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the transfer is taken");
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 202 ")),
        "2.4.2 wants a 202 before the transaction expires"
    );
    assert!(
        written.iter().any(|bytes| bytes.starts_with(b"NOTIFY ")),
        "2.4.4 makes the subscription real at once"
    );
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"INVITE sip:carol@example.com")),
        "and the call it asked for is placed"
    );
    assert_eq!(agent.call_state(placed), Some(CallState::Calling));
}

#[test]
fn a_refer_can_be_refused() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("ref2", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "ref2ack", 1), t0);
    events(&mut agent);

    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "ref2refer", 2),
            "Refer-To: <sip:carol@example.com>\r\n",
        ),
        t0,
    );
    events(&mut agent);
    let refused = StatusCode::new(603).expect("603");
    agent
        .reject_transfer(call, refused, t0)
        .expect("the refusal goes");
    assert!(sent(&mut agent).starts_with(b"SIP/2.0 603 "));
}

#[test]
fn a_refer_nobody_answered_in_time_leaves_the_call_able_to_be_asked_again() {
    // RFC 3515 §2.4.2 has the answer go "before the REFER transaction
    // expires". Left alone, the endpoint answers it 408 at 64·T1 and the
    // transaction ends; the call used to keep it as a transfer still being
    // decided, and every REFER after it on the call was answered 491
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("reflapse", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "reflapseack", 1), t0);
    events(&mut agent);

    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "reflapse1", 2),
            "Refer-To: <sip:carol@example.com>\r\n",
        ),
        t0,
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::TransferRequested { .. }))
    );
    // nobody answers it: the endpoint's 408, and then the transaction's end
    let mut now = t0;
    let mut timed_out = false;
    while let Some(due) = agent.poll_timeout() {
        if due > t0 + Duration::from_secs(120) {
            break;
        }
        now = due;
        agent.handle_timeout(now);
        timed_out |= transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 408 "));
    }
    assert!(timed_out, "the endpoint answered the REFER nobody took");
    events(&mut agent);
    assert!(
        matches!(
            agent.accept_transfer(call, None, OutgoingExtras::default(), now),
            Err(UaError::WrongState(_))
        ),
        "a transaction that no longer exists cannot be answered"
    );

    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "reflapse2", 3),
            "Refer-To: <sip:dave@example.com>\r\n",
        ),
        now,
    );
    assert!(
        transmits(&mut agent)
            .iter()
            .all(|bytes| !bytes.starts_with(b"SIP/2.0 491 ")),
        "the next REFER was refused for a transfer nobody was running"
    );
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            event,
            UaEvent::TransferRequested { target, .. } if target.as_bytes() == b"sip:dave@example.com"
        )),
        "the next REFER is the application's to take"
    );
}

#[test]
fn a_refer_with_the_wrong_number_of_targets_is_a_bad_request() {
    // 2.4.2: "MUST return a 400 (Bad Request) if the request contained zero or
    // more than one Refer-To header field values"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("ref3", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "ref3ack", 1), t0);
    events(&mut agent);

    deliver(
        &mut agent,
        &plus(&in_dialog(&ok, "REFER", "ref3refer", 2), ""),
        t0,
    );
    assert!(sent(&mut agent).starts_with(b"SIP/2.0 400 "));
}

#[test]
fn a_refer_to_whose_target_would_break_out_of_its_brackets_is_a_bad_request() {
    // The target of a REFER is written into the INVITE the transfer places, as
    // `To: <target>`. A '>' inside it closes those brackets early: this one
    // would reach the third party as `To: <sip:carol>;tag=abc@example.com>`,
    // an out-of-dialog INVITE carrying a To tag the referrer chose. RFC 3261
    // §19.1.2 does not let a URI hold the byte unescaped, and 2.4.2 of RFC 3515
    // answers a Refer-To that cannot be used with a 400.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("ref4", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "ref4ack", 1), t0);
    events(&mut agent);

    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "ref4refer", 2),
            "Refer-To: <sip:carol>;tag=abc@example.com>\r\n",
        ),
        t0,
    );
    assert!(sent(&mut agent).starts_with(b"SIP/2.0 400 "));
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::TransferRequested { .. })),
        "nothing is offered to the application"
    );
}

#[test]
fn a_replaces_that_unescapes_to_a_control_byte_makes_the_refer_to_a_bad_request() {
    // The Replaces in a Refer-To is escaped inside the URI and unescaped to go
    // onto the INVITE the transfer places, so an escape is how a control byte
    // reaches a header line this end writes to a third party. RFC 3891 §6.1
    // makes the value a Call-ID and token parameters, neither of which can
    // hold one, and RFC 3261 §19.1.5 has a URI that forms an invalid request
    // treated as invalid rather than sent. RFC 3515 2.4.2 answers a Refer-To
    // that cannot be acted on with a 400.
    let t0 = Instant::now();
    let mut accepted: Vec<&str> = Vec::new();
    for (n, escaped) in [
        "call%00x%3Bto-tag%3Da%3Bfrom-tag%3Db",
        "call%3Bto-tag%3Da%3Bfrom-tag%3Db%0D%0AContact:%20%3Csip:mallory@example.net%3E",
        "call%3Bto-tag%3Da%01%3Bfrom-tag%3Db",
        "call%3Bto-tag%3Da%3Bfrom-tag%3Db%7F",
    ]
    .into_iter()
    .enumerate()
    {
        let mut agent = agent(t0);
        agent.add_account(account());
        let branch = format!("rep{n}");
        let call = call_arriving(&mut agent, &incoming_invite(&branch, Some(OFFER)), t0);
        agent
            .answer(call, Some(Arc::from(ANSWER)), t0)
            .expect("200 goes");
        let ok = sent(&mut agent);
        deliver(
            &mut agent,
            &in_dialog(&ok, "ACK", &format!("{branch}ack"), 1),
            t0,
        );
        events(&mut agent);

        deliver(
            &mut agent,
            &plus(
                &in_dialog(&ok, "REFER", &format!("{branch}refer"), 2),
                &format!("Refer-To: <sip:carol@example.com?Replaces={escaped}>\r\n"),
            ),
            t0,
        );
        let refused = transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 400 "));
        let offered = events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::TransferRequested { .. }));
        if !refused || offered {
            accepted.push(escaped);
        }
    }
    assert!(accepted.is_empty(), "taken as a transfer: {accepted:#?}");
}

#[test]
fn an_invite_whose_fields_arrived_folded_is_answered() {
    // RFC 3261 §7.3.1 lets any field value continue on the next line, and
    // §8.2.6.2 has every response copy the request's Via, From, To, Call-ID and
    // CSeq. Copied with the fold's line break still in them, not one response
    // could be written: no 100, no 200, not even the refusal hanging up sends,
    // and the INVITE server transaction waited for an answer that never came.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let invite = String::from_utf8_lossy(&incoming_invite("fold1", Some(OFFER)))
        .replace(
            "Via: SIP/2.0/UDP 192.0.2.9:5060;",
            "Via: SIP/2.0/UDP\r\n 192.0.2.9:5060;",
        )
        .replace(
            "From: Bob <sip:bob@example.com>;tag=bobtag",
            "From: Bob\r\n <sip:bob@example.com>;tag=bobtag",
        )
        .replace(
            "To: Alice <sip:alice@example.com>",
            "To: Alice\r\n\t<sip:alice@example.com>",
        )
        .replace("Call-ID: incoming-fold1", "Call-ID:\r\n incoming-fold1")
        .replace("CSeq: 1 INVITE", "CSeq: 1\r\n  INVITE");
    deliver(&mut agent, invite.as_bytes(), t0);
    let trying = transmits(&mut agent);
    assert!(
        trying
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 100 ")),
        "no 100 Trying for a folded INVITE"
    );
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("the 200 can be written");
    let ok = sent(&mut agent);
    assert!(ok.starts_with(b"SIP/2.0 200 "));
    // and each field it copied is the request's, with the fold as one space
    assert_eq!(text(&ok, HeaderName::CallId), "incoming-fold1");
    assert_eq!(text(&ok, HeaderName::CSeq), "1 INVITE");
    assert!(
        text(&ok, HeaderName::From).starts_with("Bob <sip:bob@example.com>;tag=bobtag"),
        "{}",
        text(&ok, HeaderName::From)
    );
    assert_eq!(
        tag_of(&ok, HeaderName::From),
        "bobtag",
        "the peer's tag reads back"
    );
}

#[test]
fn a_message_holding_a_lone_cr_leaves_nothing_waiting_on_an_answer() {
    // A CR that neither ends a line nor begins a fold used to be taken in and
    // then could never be written back. An INVITE carrying one in its From
    // became a call that could not be answered, refused or hung up; a REFER
    // carrying one in its Referred-By, which RFC 3892 §2.2 copies onto the
    // INVITE the transfer places, was answered 202 and then placed nothing.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let lone_cr = |agent: &mut UserAgent, bytes: &[u8]| {
        agent.receive(
            Input::Datagram {
                transport: UDP,
                remote: registrar(),
                local: local(),
                data: bytes,
            },
            t0,
        )
    };
    let invite = String::from_utf8_lossy(&incoming_invite("lonecr1", Some(OFFER))).replace(
        "From: Bob <sip:bob@example.com>;tag=bobtag",
        "From: Bob <sip:bob@example.com>;x=a\rb;tag=bobtag",
    );
    assert!(
        lone_cr(&mut agent, invite.as_bytes()).is_err(),
        "an INVITE with a lone CR is not a well formed datagram"
    );
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::IncomingCall { .. })),
        "a call nothing can be written for was offered"
    );
    transmits(&mut agent);

    let call = call_arriving(&mut agent, &incoming_invite("lonecr2", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "lonecr2ack", 1), t0);
    events(&mut agent);
    let refer = plus(
        &in_dialog(&ok, "REFER", "lonecr2refer", 2),
        "Refer-To: <sip:carol@example.com>\r\nReferred-By: <sip:alice@example.com>;x=a\rb\r\n",
    );
    assert!(
        lone_cr(&mut agent, &refer).is_err(),
        "a REFER with a lone CR is not a well formed datagram"
    );
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::TransferRequested { .. })),
        "a transfer that could never be placed was offered"
    );
}

#[test]
fn a_replaces_that_names_nothing_is_refused_rather_than_answered() {
    // RFC 3891 §3: "If no match is found, the UAS rejects the INVITE and
    // returns a 481 Call/Transaction Does Not Exist response."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(
        &mut agent,
        &plus(
            &incoming_invite("rep1", Some(OFFER)),
            "Replaces: nosuchcall;to-tag=a;from-tag=b\r\n",
        ),
        t0,
    );
    assert!(last(&mut agent).starts_with(b"SIP/2.0 481 "));
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::IncomingCall { .. }))
    );
}

#[test]
fn a_replaces_that_names_a_live_call_takes_it_over() {
    // RFC 3891 §3: "it accepts the new INVITE by sending a 200-class response,
    // and shuts down the replaced dialog by sending a BYE."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let first = call_arriving(&mut agent, &incoming_invite("rep2", Some(OFFER)), t0);
    agent
        .answer(first, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "rep2ack", 1), t0);
    events(&mut agent);

    let ours = tag_of(&ok, HeaderName::To);
    let theirs = tag_of(&ok, HeaderName::From);
    let call_id = String::from_utf8_lossy(&header(&ok, HeaderName::CallId)).into_owned();
    let replacing = plus(
        &incoming_invite("rep3", Some(OFFER)),
        &format!("Replaces: {call_id};to-tag={ours};from-tag={theirs}\r\n"),
    );
    deliver(&mut agent, &replacing, t0);
    transmits(&mut agent);
    let second = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("the replacing call arrives for the application to answer");

    agent
        .answer(second, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let written = transmits(&mut agent);
    assert!(
        written.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "and the one it replaced is shut down"
    );
    assert!(events(&mut agent).iter().any(|event| matches!(
        *event,
        UaEvent::CallReplaced { replaced, .. } if replaced == first
    )));
}

/// The victim: a confirmed incoming call, and the three identifiers an
/// attacker would have to know to name it in a `Replaces`.
fn call_to_take_over(agent: &mut UserAgent, now: Instant) -> (CallHandle, String) {
    let first = call_arriving(agent, &incoming_invite("rep4", Some(OFFER)), now);
    agent
        .answer(first, Some(Arc::from(ANSWER)), now)
        .expect("200 goes");
    let ok = sent(agent);
    deliver(agent, &in_dialog(&ok, "ACK", "rep4ack", 1), now);
    events(agent);
    let ours = tag_of(&ok, HeaderName::To);
    let theirs = tag_of(&ok, HeaderName::From);
    let call_id = String::from_utf8_lossy(&header(&ok, HeaderName::CallId)).into_owned();
    (
        first,
        format!("Replaces: {call_id};to-tag={ours};from-tag={theirs}\r\n"),
    )
}

#[test]
fn a_replaces_from_a_stranger_is_forbidden_and_leaves_the_call_it_named_alone() {
    // RFC 3891 §3: "the UA MUST verify that the initiator of the new INVITE is
    // authorized to replace the matched dialog", and "MUST leave the matched
    // dialog unchanged". The three identifiers travel in every packet of the
    // call, so knowing them is not being the far end.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (first, replaces) = call_to_take_over(&mut agent, t0);

    let replacing = plus(&incoming_invite("rep5", Some(OFFER)), &replaces);
    deliver_from(&mut agent, &replacing, scanner(7), t0);
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 403 ")),
        "the stranger is refused: {:?}",
        written
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .collect::<Vec<_>>()
    );
    assert!(
        !written.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "and the call it named is not hung up"
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::IncomingCall { .. })),
        "nothing is offered to the application to answer"
    );
    assert_eq!(agent.call_state(first), Some(CallState::Confirmed));
}

#[test]
fn naming_the_peer_in_a_header_the_sender_wrote_does_not_authorise_a_replaces() {
    // §8 wants the peer "properly authenticated using a standard SIP
    // mechanism". `From` and `Referred-By` are plain fields on the very
    // INVITE being judged, so a sender that can write one can write both.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (first, replaces) = call_to_take_over(&mut agent, t0);

    // `From` already names the call's own far end, and this adds the
    // `Referred-By` RFC 3891 §3 treats as authorisation by the replaced party
    let replacing = plus(
        &incoming_invite("rep6", Some(OFFER)),
        &format!("{replaces}Referred-By: <sip:bob@example.com>\r\n"),
    );
    deliver_from(&mut agent, &replacing, scanner(7), t0);
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 403 ")),
        "an unsigned header is not an identity"
    );
    assert_eq!(agent.call_state(first), Some(CallState::Confirmed));
}

#[test]
fn a_replaces_refused_for_want_of_authority_is_counted() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (_, replaces) = call_to_take_over(&mut agent, t0);
    assert_eq!(agent.refusals().by_replaces, 0);

    let replacing = plus(&incoming_invite("rep7", Some(OFFER)), &replaces);
    deliver_from(&mut agent, &replacing, scanner(7), t0);
    transmits(&mut agent);
    assert_eq!(agent.refusals().by_replaces, 1);
}

#[test]
fn two_replaces_header_fields_are_a_bad_request() {
    // §3: "if it appears more than once, the UAS MUST reject the request with
    // a 400 Bad Request response" — the gate above must not be reading one
    // value while the far end acted on the other
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (first, replaces) = call_to_take_over(&mut agent, t0);

    let replacing = plus(
        &incoming_invite("rep8", Some(OFFER)),
        &format!("{replaces}Replaces: nosuchcall;to-tag=a;from-tag=b\r\n"),
    );
    deliver(&mut agent, &replacing, t0);
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 400 ")),
        "two of them is not one of them"
    );
    assert_eq!(agent.call_state(first), Some(CallState::Confirmed));
}

// -- who gets the last word on a Replaces ------------------------------------

/// What the hook was asked about, as the test reads it back: the call named,
/// whether it came in on that call's own flow, and whether it says who
/// referred it.
type Asked = Arc<Mutex<Option<(CallHandle, bool, bool)>>>;

/// A policy that answers whatever it was built with, and writes down what it
/// was asked about.
struct Policy {
    replaces: Screening,
    saw: Asked,
}

impl Policy {
    fn answering(replaces: Screening) -> (Self, Asked) {
        let saw = Asked::default();
        (
            Self {
                replaces,
                saw: Arc::clone(&saw),
            },
            saw,
        )
    }
}

impl Screen for Policy {
    fn on_invite(&mut self, _: &Incoming<'_>) -> Screening {
        Screening::Take
    }

    fn on_replaces(&mut self, invite: &Incoming<'_>, named: Replacing) -> Screening {
        if let Ok(mut saw) = self.saw.lock() {
            *saw = Some((
                named.call(),
                named.same_flow(),
                invite.referred_by().is_some(),
            ));
        }
        self.replaces
    }
}

/// What the policy wrote down, if it ran at all.
fn asked(saw: &Asked) -> Option<(CallHandle, bool, bool)> {
    saw.lock().ok().and_then(|saw| *saw)
}

#[test]
fn a_policy_written_before_the_hook_existed_still_refuses_the_stranger() {
    // the hook is defaulted, so a policy that only screens INVITEs -- which
    // is every policy that could have been written until now -- gets exactly
    // the behaviour it had
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (first, replaces) = call_to_take_over(&mut agent, t0);
    agent.screen(|_: &Incoming<'_>| Screening::Take);

    let replacing = plus(&incoming_invite("hook1", Some(OFFER)), &replaces);
    deliver_from(&mut agent, &replacing, scanner(7), t0);
    assert!(
        transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 403 ")),
        "the default is the strict rule"
    );
    assert_eq!(agent.call_state(first), Some(CallState::Confirmed));
    assert_eq!(agent.refusals().by_replaces, 1);
}

#[test]
fn an_application_can_take_a_transferee_that_did_not_come_through_the_proxy() {
    // The real deployment the strict rule refuses: an attended transfer whose
    // transferee reaches this end directly instead of through the line's
    // proxy. Nothing about the INVITE proves it is one -- the application is
    // what knows the deployment, and this is where it says so.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (first, replaces) = call_to_take_over(&mut agent, t0);
    agent.screen(Policy::answering(Screening::Take).0);

    let replacing = plus(
        &incoming_invite("hook2", Some(OFFER)),
        &format!("{replaces}Referred-By: <sip:bob@example.com>\r\n"),
    );
    deliver_from(&mut agent, &replacing, scanner(7), t0);
    let written = transmits(&mut agent);
    assert!(
        !written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 403 ")),
        "the application took it: {:?}",
        written
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(agent.refusals().by_replaces, 0);
    let offered = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("the transferee's call is offered to the application");

    // and taking it is what hands the call over, exactly as an on-path one
    agent
        .answer(offered, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let written = transmits(&mut agent);
    assert!(
        written.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "§3: the replaced dialog is shut down when the new one is answered"
    );
    assert!(
        events(&mut agent).iter().any(
            |event| matches!(*event, UaEvent::CallReplaced { replaced, .. } if replaced == first)
        ),
        "and the application is told which call it lost"
    );
}

#[test]
fn an_application_can_refuse_a_replaces_that_arrived_on_the_calls_own_flow() {
    // the hook tightens as well as it loosens: the address a call's
    // signalling travels over is one thing an application may know is not
    // enough, and behind an outbound proxy it is every INVITE that arrives
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (first, replaces) = call_to_take_over(&mut agent, t0);
    agent.screen(Policy::answering(Screening::Refuse(StatusCode::BUSY_HERE)).0);

    let replacing = plus(&incoming_invite("hook3", Some(OFFER)), &replaces);
    deliver(&mut agent, &replacing, t0);
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 486 ")),
        "the application's answer is the one that goes: {:?}",
        written
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .collect::<Vec<_>>()
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::IncomingCall { .. })),
        "and nothing is offered to answer"
    );
    assert_eq!(agent.call_state(first), Some(CallState::Confirmed));
}

#[test]
fn the_hook_is_told_which_call_is_being_taken_and_how_it_was_reached() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (first, replaces) = call_to_take_over(&mut agent, t0);
    let (policy, saw) = Policy::answering(Screening::Take);
    agent.screen(policy);

    // on the call's own flow, with the field RFC 3892 §2.2 has a transferee
    // copy from the REFER that asked for the transfer
    let replacing = plus(
        &incoming_invite("hook4", Some(OFFER)),
        &format!("{replaces}Referred-By: <sip:bob@example.com>\r\n"),
    );
    deliver(&mut agent, &replacing, t0);
    transmits(&mut agent);
    let seen = asked(&saw).expect("the hook ran");
    assert_eq!(seen.0, first, "the call that would be hung up");
    assert!(seen.1, "it came in on that call's own flow");
    assert!(seen.2, "and it says who referred it");
}

#[test]
fn a_replaces_that_names_nothing_never_reaches_the_application() {
    // §3 answers it 481 before there is anything to decide, and a stranger
    // guessing identifiers does not get to run application code by doing it
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    call_to_take_over(&mut agent, t0);
    let (policy, saw) = Policy::answering(Screening::Take);
    agent.screen(policy);

    let replacing = plus(
        &incoming_invite("hook5", Some(OFFER)),
        "Replaces: nosuchcall;to-tag=a;from-tag=b\r\n",
    );
    deliver_from(&mut agent, &replacing, scanner(7), t0);
    assert!(
        transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 481 ")),
    );
    assert!(asked(&saw).is_none(), "the hook was never troubled with it");
}

// -- a NOTIFY nobody asked for -----------------------------------------------

/// The same, reporting on the REFER whose `CSeq` is `id` (RFC 3515 §2.4.6).
fn notify_about(ours: &[u8], cseq: u32, id: u32, status: &str, state: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(&notify(ours, cseq, status, state)).into_owned();
    text.replace("Event: refer\r\n", &format!("Event: refer;id={id}\r\n"))
        .into_bytes()
}

/// The number the far end would put in an `id` to name this REFER.
fn cseq_of(request: &[u8]) -> u32 {
    text(request, HeaderName::CSeq)
        .split_whitespace()
        .next()
        .and_then(|number| number.parse().ok())
        .expect("a CSeq with a number in it")
}

#[test]
fn a_transfer_report_nobody_asked_for_is_refused_rather_than_acted_on() {
    // RFC 3515 §2.4.4: "REFER is the only mechanism that can create a
    // subscription to event refer." This end sent no REFER, so there is no
    // subscription here and §4.1.3 of RFC 6665 has one answer for a
    // notification against none: 481. Acting on it instead let the far end of
    // any established call drive a transfer this end never asked for, and the
    // last NOTIFY of one hangs the call up.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &notify(&ack, 1, "200 OK", "terminated;reason=noresource"),
        t0,
    );
    let written = transmits(&mut agent);
    let answer = only(&written, "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 481 "),
        "a subscription this end never opened: {}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        !written.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "and the call is not given up on a stranger's say-so"
    );
    assert!(
        !events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::TransferDone { .. } | UaEvent::TransferProgress { .. }
        )),
        "nor is a transfer nobody asked for reported as one"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_transfer_report_that_names_another_refer_is_not_this_ones() {
    // §2.4.6: from the second REFER in a dialog on, each NOTIFY "MUST include
    // an id parameter in the Event header field containing the sequence
    // number of the REFER" it reports on. One that names a REFER this end did
    // not send reports on a subscription that does not exist here.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = only(&transmits(&mut agent), "REFER ");
    deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
    events(&mut agent);

    deliver(
        &mut agent,
        &notify_about(&ack, 1, cseq_of(&refer) + 7, "200 OK", "active"),
        t0,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 481 "),
        "another REFER's report: {}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::TransferDone { .. })),
        "and it is not news about ours"
    );

    // and the one that names ours is
    deliver(
        &mut agent,
        &notify_about(
            &ack,
            2,
            cseq_of(&refer),
            "200 OK",
            "terminated;reason=noresource",
        ),
        t0,
    );
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::TransferDone { .. })),
        "the id that names our REFER is our subscription"
    );
}

#[test]
fn a_report_arriving_after_the_subscription_ended_is_refused() {
    // §2.4.7 makes the terminated NOTIFY the last word, and RFC 6665 §4.1.3
    // has everything after it answered 481 rather than acted on
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = only(&transmits(&mut agent), "REFER ");
    deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
    deliver(
        &mut agent,
        &notify(&ack, 1, "486 Busy Here", "terminated;reason=noresource"),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &notify(&ack, 2, "200 OK", "terminated;reason=noresource"),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(
        only(&written, "SIP/2.0 ").starts_with(b"SIP/2.0 481 "),
        "the subscription ended with the NOTIFY before it"
    );
    assert!(
        !written.iter().any(|bytes| bytes.starts_with(b"BYE ")),
        "a transfer that failed does not succeed on a second report"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_refer_that_was_refused_leaves_no_subscription_to_report_on() {
    // §2.4.2: a 2xx is what obliges the far end to "create a subscription and
    // send notifications". A REFER that was refused created none.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = only(&transmits(&mut agent), "REFER ");
    deliver(&mut agent, &reply(&refer, 603, "Declined", ""), t0);
    events(&mut agent);

    deliver(
        &mut agent,
        &notify(&ack, 1, "200 OK", "terminated;reason=noresource"),
        t0,
    );
    let written = transmits(&mut agent);
    assert!(
        only(&written, "SIP/2.0 ").starts_with(b"SIP/2.0 481 "),
        "nothing here asked for it"
    );
    assert!(!written.iter().any(|bytes| bytes.starts_with(b"BYE ")));
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

// -- RFC 3892: the INVITE carries on who asked for the transfer --------------

#[test]
fn the_invite_a_transfer_places_carries_the_referred_by_that_asked_for_it() {
    // RFC 3892 §2.2: "A UA accepting a REFER request (a referee) to a SIP URI
    // ... MUST copy any Referred-By header field" into the request it
    // triggers. Demoting the field from authorisation does not remove the
    // obligation to pass it on: the far end may have a policy that reads it.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("rby1", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "rby1ack", 1), t0);
    events(&mut agent);

    let refer = plus(
        &in_dialog(&ok, "REFER", "rby1refer", 2),
        "Refer-To: <sip:carol@example.com>\r\n\
         Referred-By: <sip:bob@example.com>;cid=%3C20398@example.com%3E\r\n",
    );
    deliver(&mut agent, &refer, t0);
    events(&mut agent);

    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the transfer is taken");
    let invite = only(&transmits(&mut agent), "INVITE sip:carol@example.com");
    assert_eq!(
        header(&invite, HeaderName::ReferredBy),
        b"<sip:bob@example.com>;cid=%3C20398@example.com%3E",
        "the value travels whole, parameters and all"
    );
}

#[test]
fn a_folded_referred_by_still_reaches_the_invite_the_transfer_places() {
    // RFC 3261 §7.3.1 lets any header field value be folded across lines, and
    // the parser keeps a fold's interior CRLF on purpose — unfolding belongs
    // to whoever consumes the value. This one is copied onto a request we
    // send, so a bare CRLF left in the middle of it is a second header field
    // to whatever reads the result. Before this was unfolded, a folded
    // `Referred-By` made `accept_transfer` fail outright, with no way back.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("rby3", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "rby3ack", 1), t0);
    events(&mut agent);

    let refer = plus(
        &in_dialog(&ok, "REFER", "rby3refer", 2),
        "Refer-To: <sip:carol@example.com>\r\n\
         Referred-By: <sip:bob@example.com>\r\n\
         \t;cid=%3C20398@example.com%3E\r\n",
    );
    deliver(&mut agent, &refer, t0);
    events(&mut agent);

    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("a folded header field is not a reason to refuse the transfer");
    let invite = only(&transmits(&mut agent), "INVITE sip:carol@example.com");
    assert_eq!(
        header(&invite, HeaderName::ReferredBy),
        b"<sip:bob@example.com> ;cid=%3C20398@example.com%3E",
        "the fold is gone and the value travels whole"
    );
}

#[test]
fn two_referred_by_values_on_one_line_are_two_values() {
    // §7.3.1 makes several lines of one field and one line with commas the
    // same message, so a guard that counts LINES reads two values as one and
    // copies whichever came first — which is how a sender would make the far
    // end read one field while this end acted on the other.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("rby4", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "rby4ack", 1), t0);
    events(&mut agent);

    let refer = plus(
        &in_dialog(&ok, "REFER", "rby4refer", 2),
        "Refer-To: <sip:carol@example.com>\r\n\
         Referred-By: <sip:bob@example.com>, <sip:mallory@example.net>\r\n",
    );
    deliver(&mut agent, &refer, t0);
    events(&mut agent);

    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the transfer is taken");
    let invite = only(&transmits(&mut agent), "INVITE sip:carol@example.com");
    assert_eq!(
        header(&invite, HeaderName::ReferredBy),
        b"",
        "two values are two values, however they are written, and neither is passed on"
    );
}

#[test]
fn a_refer_with_two_referred_by_fields_passes_none_of_them_on() {
    // §2.1: "A REFER request MUST NOT contain more than one Referred-By
    // header field value." Which of two to copy is not ours to guess, and the
    // transfer itself is not worth refusing over it.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("rby2", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "rby2ack", 1), t0);
    events(&mut agent);

    let refer = plus(
        &in_dialog(&ok, "REFER", "rby2refer", 2),
        "Refer-To: <sip:carol@example.com>\r\n\
         Referred-By: <sip:bob@example.com>\r\n\
         Referred-By: <sip:mallory@example.net>\r\n",
    );
    deliver(&mut agent, &refer, t0);
    events(&mut agent);

    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the transfer is taken");
    let invite = only(&transmits(&mut agent), "INVITE sip:carol@example.com");
    assert!(
        header(&invite, HeaderName::ReferredBy).is_empty(),
        "neither of them is copied: {}",
        text(&invite, HeaderName::ReferredBy)
    );
}

// -- the consultation call ---------------------------------------------------

#[test]
fn a_consultation_call_says_what_it_is_while_it_is_up() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);

    let second = agent
        .consult(first, &outgoing(), t0)
        .expect("the second INVITE goes");
    let invite = sent(&mut agent);
    assert_eq!(agent.call_state(second), Some(CallState::Calling));

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "target", Some(ANSWER)),
        t0,
    );
    sent(&mut agent);
    events(&mut agent);
    assert_eq!(agent.call_state(second), Some(CallState::Consulting));
    // and it is a confirmed dialog in every other sense, so everything a call
    // can do it can do
    assert!(
        agent
            .call_state(second)
            .is_some_and(CallState::is_confirmed)
    );
    assert_eq!(agent.call_state(first), Some(CallState::Confirmed));
}

#[test]
fn the_attended_transfer_hands_over_the_call_the_consultation_named() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);
    let (second, ack) = consulted(&mut agent, first, t0);
    assert_eq!(agent.call_state(second), Some(CallState::Consulting));

    agent
        .transfer_to(first, second, t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    let refer_to = String::from_utf8_lossy(&header(&refer, HeaderName::ReferTo)).into_owned();
    // §6.1: the dialog named is the consultation call's, from the target's
    // point of view
    assert!(
        refer_to.contains(&format!("%3Bto-tag%3D{}", tag_of(&ack, HeaderName::To))),
        "{refer_to}"
    );
}

#[test]
fn a_call_that_is_not_up_can_neither_consult_nor_be_handed_over() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);

    // still ringing: there is no dialog to name in a Replaces, and RFC 3891 §3
    // has the far end refuse one that names an early dialog it did not open
    let ringing = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    transmits(&mut agent);
    assert_eq!(
        agent.transfer_to(first, ringing, t0),
        Err(UaError::WrongState(CallState::Calling))
    );
    assert_eq!(
        agent.consult(ringing, &outgoing(), t0),
        Err(UaError::WrongState(CallState::Calling))
    );
}

#[test]
fn one_consultation_at_a_time() {
    // two would leave the application to say which one the transfer meant, and
    // the whole point of naming the state is that it does not have to
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);
    let (second, _) = consulted(&mut agent, first, t0);

    assert_eq!(
        agent.consult(first, &outgoing(), t0),
        Err(UaError::WrongState(CallState::Confirmed))
    );
    // until the first consultation is over, and then it can be tried again
    agent.hangup(second, t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    deliver(&mut agent, &reply(&bye, 200, "OK", ""), t0);
    events(&mut agent);
    agent
        .consult(first, &outgoing(), t0)
        .expect("a second attempt at the target");
}

#[test]
fn a_consultation_call_cannot_consult_in_its_turn() {
    // a chain of them names no transfer at all: the second leg would be both
    // the call being handed over and the one it is handed to
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);
    let (second, _) = consulted(&mut agent, first, t0);

    assert_eq!(
        agent.consult(second, &outgoing(), t0),
        Err(UaError::WrongState(CallState::Consulting))
    );
    assert!(transmits(&mut agent).is_empty(), "and nothing was placed");
}

#[test]
fn a_change_the_target_asks_for_leaves_the_consultation_a_consultation() {
    // the ACK for a re-INVITE arrives on the dialog, not on the INVITE that
    // founded it, so it says nothing about what the call is for. A target that
    // puts the consultation on hold does not turn it into an ordinary call
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);
    let (second, ack) = consulted(&mut agent, first, t0);
    assert_eq!(agent.call_state(second), Some(CallState::Consulting));

    deliver(
        &mut agent,
        &reversed(&ack, "INVITE", "targethold", 1, Some(THEIR_HOLD)),
        t0,
    );
    let answer = last(&mut agent);
    assert!(
        answer.starts_with(b"SIP/2.0 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    deliver(&mut agent, &reversed(&ack, "ACK", "targetack", 1, None), t0);
    events(&mut agent);

    assert_eq!(agent.call_state(second), Some(CallState::Consulting));
    assert!(
        agent.transfer_to(first, second, t0).is_ok(),
        "and it is still the leg the transfer names"
    );
}

#[test]
fn a_consultation_whose_reason_hung_up_is_an_ordinary_call_again() {
    // the transferor gave up on the transfer and stayed with the target; there
    // is nobody left to hand over, so the state says so
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (first, _) = call_up(&mut agent, id, t0);
    let (second, _) = consulted(&mut agent, first, t0);

    agent.hangup(first, t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    deliver(&mut agent, &reply(&bye, 200, "OK", ""), t0);
    events(&mut agent);
    assert_eq!(agent.call_state(first), None);
    assert_eq!(agent.call_state(second), Some(CallState::Confirmed));
}

// -- a flow that dies under a registration -----------------------------------

/// Let the flow answer its first keep-alive, which is the explicit indication
/// RFC 5626 §4.4 asks for before a missing pong may count against it, and put
/// the second one on the wire. Returns when the second one went.
fn second_ping(agent: &mut UserAgent) -> Instant {
    let first = agent.poll_timeout().expect("a keepalive is due");
    agent.handle_timeout(first);
    transmits(agent);
    stream(agent, b"\r\n", first + Duration::from_millis(40));
    let second = agent.poll_timeout().expect("the next keepalive");
    agent.handle_timeout(second);
    assert_eq!(transmits(agent), vec![b"\r\n\r\n".to_vec()]);
    second
}

#[test]
fn a_ping_that_is_never_answered_takes_the_registration_with_it() {
    // RFC 5626 §4.4: "If a flow with a registration has failed, the UA follows
    // the procedures in Section 4.2 to form a new flow to replace the failed
    // one" — forming it is the application's, and everything before it is not
    let t0 = Instant::now();
    let (mut agent, id) = over_tcp(t0);
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    stream(&mut agent, &granted(&request, 3_600), t0);
    events(&mut agent);
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );

    let ping_at = second_ping(&mut agent);
    agent.handle_timeout(ping_at + Duration::from_secs(10));
    let events = events(&mut agent);
    assert!(
        events.iter().any(|event| matches!(
            *event,
            UaEvent::RegistrationFailed {
                account,
                reason: RegistrationFailure::Unreachable,
                retry_in: Some(_),
                ..
            } if account == id
        )),
        "{events:?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            *event,
            UaEvent::Unclaimed(sipral_core::endpoint::Event::FlowFailed { .. })
        )),
        "the application owns the socket and has to be told to close it"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Retrying)
    );
}

#[test]
fn a_pong_leaves_the_registration_alone() {
    let t0 = Instant::now();
    let (mut agent, id) = over_tcp(t0);
    agent.register(id, t0).expect("the REGISTER goes");
    let request = sent(&mut agent);
    stream(&mut agent, &granted(&request, 3_600), t0);
    events(&mut agent);

    let ping_at = agent.poll_timeout().expect("a keepalive is due");
    agent.handle_timeout(ping_at);
    transmits(&mut agent);
    stream(&mut agent, b"\r\n", ping_at + Duration::from_secs(1));

    agent.handle_timeout(ping_at + Duration::from_secs(10));
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::RegistrationFailed { .. })),
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
}

// -- challenges inside a call ------------------------------------------------
//
// §22.2 does not stop at the request that opened the dialog. A PBX that
// challenges one request challenges all of them, and every one of these was
// answered by giving up until an Asterisk in the lab said otherwise.

#[test]
fn a_bye_a_pbx_challenges_goes_again_with_credentials() {
    // 15.1.1: the BYE is what ends the call, so one refused for want of
    // credentials leaves the far end holding a call this end has hung up
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let (call, _) = call_up(&mut agent, id, t0);

    agent.hangup(call, t0).expect("the BYE goes");
    let first = only(&transmits(&mut agent), "BYE ");
    assert!(header(&first, HeaderName::Authorization).is_empty());

    deliver(&mut agent, &unauthorized(&first), t0);

    let retry = only(&transmits(&mut agent), "BYE ");
    credentials_of(&retry, HeaderName::Authorization);
    // §22.2 moves the CSeq on. The dialog is gone -- the BYE ended it -- so
    // the number comes from the request that was refused
    assert_eq!(header(&retry, HeaderName::CSeq), b"3 BYE");
    assert_ne!(text(&retry, HeaderName::Via), text(&first, HeaderName::Via));
    assert_eq!(
        header(&retry, HeaderName::CallId),
        header(&first, HeaderName::CallId)
    );
}

#[test]
fn a_bye_challenged_twice_with_the_same_nonce_stops() {
    // 22.1: the same nonce back is the password being wrong, and a client that
    // keeps answering it locks the account
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let (call, _) = call_up(&mut agent, id, t0);

    agent.hangup(call, t0).expect("the BYE goes");
    let first = only(&transmits(&mut agent), "BYE ");
    deliver(&mut agent, &unauthorized(&first), t0);
    let retry = only(&transmits(&mut agent), "BYE ");

    deliver(&mut agent, &unauthorized(&retry), t0);
    assert!(
        !transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"BYE ")),
        "nothing goes out a third time"
    );
}

#[test]
fn a_reinvite_a_pbx_challenges_is_offered_again_with_credentials() {
    // 14.1: the session stays as it was until the change is taken, and a
    // challenge is not the far end declining the change
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let (call, _) = call_up(&mut agent, id, t0);

    agent.hold(call, t0).expect("the re-INVITE goes");
    let first = only(&transmits(&mut agent), "INVITE ");
    assert!(header(&first, HeaderName::Authorization).is_empty());

    deliver(&mut agent, &unauthorized(&first), t0);

    let out = transmits(&mut agent);
    // 17.1.1.3: the refusal is acknowledged first
    let _ = only(&out, "ACK ");
    let retry = only(&out, "INVITE ");
    credentials_of(&retry, HeaderName::Authorization);
    assert_eq!(header(&retry, HeaderName::CSeq), b"3 INVITE");
    assert!(body_of(&retry).contains("a=sendonly\r\n"), "the same offer");
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::SessionChangeFailed { .. })),
        "a challenge is not a refusal"
    );

    deliver(
        &mut agent,
        &answered(&retry, 200, "OK", "desk", Some(THEIR_RECVONLY)),
        t0,
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::SessionChanged { .. })),
        "the change goes through on the retry"
    );
}

#[test]
fn an_update_a_pbx_challenges_goes_again_with_credentials() {
    // the same rule, over the request an early dialog has to use (RFC 3311)
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &with_allow(&answered(
            &invite,
            183,
            "Session Progress",
            "desk",
            Some(ANSWER),
        )),
        t0,
    );
    events(&mut agent);

    agent.hold(call, t0).expect("the UPDATE goes");
    let first = only(&transmits(&mut agent), "UPDATE ");

    deliver(&mut agent, &unauthorized(&first), t0);

    let retry = only(&transmits(&mut agent), "UPDATE ");
    credentials_of(&retry, HeaderName::Authorization);
    assert_ne!(
        header(&retry, HeaderName::CSeq),
        header(&first, HeaderName::CSeq)
    );
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::SessionChangeFailed { .. })),
    );
}

#[test]
fn an_offer_challenged_twice_is_reported_refused_once() {
    // the give-up path has to end in the refusal the application was waiting
    // for, not in silence
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let (call, _) = call_up(&mut agent, id, t0);

    agent.hold(call, t0).expect("the re-INVITE goes");
    let first = only(&transmits(&mut agent), "INVITE ");
    deliver(&mut agent, &unauthorized(&first), t0);
    let retry = only(&transmits(&mut agent), "INVITE ");
    events(&mut agent);

    deliver(&mut agent, &unauthorized(&retry), t0);
    let out = transmits(&mut agent);
    let _ = only(&out, "ACK ");
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"INVITE ")),
        "nothing goes out a third time"
    );
    let reported: Vec<_> = events(&mut agent)
        .into_iter()
        .filter(|event| matches!(*event, UaEvent::SessionChangeFailed { .. }))
        .collect();
    assert_eq!(reported.len(), 1, "reported once, and only once");
    assert!(matches!(
        reported.first(),
        Some(UaEvent::SessionChangeFailed {
            status: Some(status),
            ..
        }) if status.get() == 401
    ));
    assert_eq!(
        agent.call_state(call),
        Some(CallState::Confirmed),
        "14.1: the call is where it was"
    );
}

#[test]
fn a_refer_a_pbx_challenges_goes_again_with_credentials() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let (call, ack) = call_up(&mut agent, id, t0);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let first = only(&transmits(&mut agent), "REFER ");

    deliver(&mut agent, &unauthorized(&first), t0);

    let retry = only(&transmits(&mut agent), "REFER ");
    credentials_of(&retry, HeaderName::Authorization);
    assert_eq!(
        header(&retry, HeaderName::ReferTo),
        b"<sip:carol@example.com>"
    );
    assert_ne!(
        header(&retry, HeaderName::CSeq),
        header(&first, HeaderName::CSeq)
    );

    // and the transfer runs to its end on the retry's subscription, which is
    // the one the far end names: RFC 3515 §2.4.6's `id` is the CSeq of the
    // REFER that opened it, and the REFER that opened it is the retry
    deliver(&mut agent, &reply(&retry, 202, "Accepted", ""), t0);
    events(&mut agent);
    deliver(
        &mut agent,
        &notify_about(&ack, 1, cseq_of(&retry), "200 OK", "terminated"),
        t0,
    );
    transmits(&mut agent);
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::TransferDone { call: reported, .. } if reported == call
        )),
        "the transfer is reported on the retry"
    );
}

#[test]
fn a_refer_challenged_on_an_account_with_no_password_leaves_no_subscription() {
    // The challenge arrives, the account has nothing to answer it with, and
    // the REFER is never sent again. RFC 3515 §2.4.2 obliges the far end to
    // open a subscription on a 2xx and on nothing else, so that REFER opened
    // none — and a record of one left standing here would accept transfer
    // reports nobody promised, from anyone already inside the dialog.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = only(&transmits(&mut agent), "REFER ");

    deliver(&mut agent, &unauthorized(&refer), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "there is no password, so nothing goes again"
    );
    events(&mut agent);

    // a report on the REFER that was never accepted is not this end's news
    deliver(
        &mut agent,
        &notify_about(&ack, 1, cseq_of(&refer), "200 OK", "terminated"),
        t0,
    );
    transmits(&mut agent);
    assert!(
        !events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::TransferDone { call: reported, .. } if reported == call
        )),
        "a transfer nobody accepted is not reported as done"
    );

    // and the seat came back, so the call can be transferred again
    agent
        .transfer(call, &uri("sip:dave@example.com"), t0)
        .expect("the call is free to ask again");
}

#[test]
fn a_refer_that_was_refused_leaves_the_call_able_to_ask_again() {
    // the seat a REFER takes has to be given back, or the first refusal is the
    // last transfer that call will ever attempt
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = only(&transmits(&mut agent), "REFER ");
    deliver(&mut agent, &reply(&refer, 603, "Decline", ""), t0);
    events(&mut agent);

    agent
        .transfer(call, &uri("sip:dave@example.com"), t0)
        .expect("a second transfer may be asked for");
    let again = only(&transmits(&mut agent), "REFER ");
    assert_eq!(
        header(&again, HeaderName::ReferTo),
        b"<sip:dave@example.com>"
    );
}

// -- subscriptions (RFC 6665) ------------------------------------------------

/// The `dialog` package a busy lamp field watches (RFC 4235 §3.1).
const DIALOG: &str = "dialog";

fn watching(extension: &str) -> Subscribe {
    Subscribe::new(uri(&format!("sip:{extension}@example.com")), DIALOG)
}

/// A notification from whoever answered a SUBSCRIBE we wrote.
///
/// §4.4.1 matches it to the SUBSCRIBE on three things, and all three are taken
/// from that request here: the `Call-ID`, the `To` tag — which is the `From`
/// tag of the SUBSCRIBE — and the `Event`.
fn notification(
    subscribe: &[u8],
    cseq: u32,
    tag: &str,
    state: &str,
    body: Option<(&str, &str)>,
) -> Vec<u8> {
    notification_of(subscribe, cseq, tag, DIALOG, state, body, "")
}

fn notification_of(
    subscribe: &[u8],
    cseq: u32,
    tag: &str,
    event: &str,
    state: &str,
    body: Option<(&str, &str)>,
    extra: &str,
) -> Vec<u8> {
    let mut out = format!(
        "NOTIFY sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKn{tag}{cseq}\r\n\
Max-Forwards: 70\r\n\
From: {};tag={tag}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {cseq} NOTIFY\r\n\
Contact: <sip:notifier@192.0.2.9>\r\n\
Event: {event}\r\n\
Subscription-State: {state}\r\n\
{extra}",
        text(subscribe, HeaderName::To),
        text(subscribe, HeaderName::From),
        text(subscribe, HeaderName::CallId),
    )
    .into_bytes();
    match body {
        Some((kind, document)) => {
            out.extend_from_slice(format!("Content-Type: {kind}\r\n").as_bytes());
            out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", document.len()).as_bytes());
            out.extend_from_slice(document.as_bytes());
        }
        None => out.extend_from_slice(b"Content-Length: 0\r\n\r\n"),
    }
    out
}

/// One dialog-info document saying where the watched extension is.
fn dialog_info(version: u32, full: bool, phase: &str) -> String {
    let state = if full { "full" } else { "partial" };
    format!(
        "<?xml version=\"1.0\"?>\
<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"{version}\" \
state=\"{state}\" entity=\"sip:201@example.com\">\
<dialog id=\"d1\"><state>{phase}</state></dialog></dialog-info>"
    )
}

/// The 200 a notifier sends to a SUBSCRIBE, which §3.1.1 makes carry the
/// duration it actually granted.
fn accepted(subscribe: &[u8], seconds: u32) -> Vec<u8> {
    reply(
        subscribe,
        200,
        "OK",
        &format!("Expires: {seconds}\r\nContact: <sip:notifier@192.0.2.9>\r\n"),
    )
}

/// Subscribe, take the 200 and the first notification, and leave it active.
fn subscribed(
    agent: &mut UserAgent,
    account: AccountId,
    now: Instant,
) -> (SubscriptionHandle, Vec<u8>) {
    let handle = agent
        .subscribe(account, &watching("201"), now)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(agent), "SUBSCRIBE ");
    deliver(agent, &accepted(&subscribe, 3_600), now);
    deliver(
        agent,
        &notification(&subscribe, 1, "notifier", "active;expires=3600", None),
        now,
    );
    transmits(agent);
    events(agent);
    (handle, subscribe)
}

#[test]
fn a_subscribe_carries_what_the_event_framework_puts_in_it() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");

    let bytes = only(&transmits(&mut agent), "SUBSCRIBE ");
    assert!(bytes.starts_with(b"SUBSCRIBE sip:201@example.com SIP/2.0\r\n"));
    // §3.1.2: "Subscribers MUST include exactly one Event header field in
    // SUBSCRIBE requests"
    assert_eq!(header(&bytes, HeaderName::Event), b"dialog");
    // §3.1.1: "SUBSCRIBE requests SHOULD contain an Expires header field"
    assert_eq!(header(&bytes, HeaderName::Expires), b"3600");
    // §8.1.1.8 of RFC 3261: a request that can establish a dialog carries one
    assert_eq!(
        header(&bytes, HeaderName::Contact),
        b"<sip:alice@192.0.2.1>"
    );
    assert_eq!(header(&bytes, HeaderName::To), b"<sip:201@example.com>");
    assert!(text(&bytes, HeaderName::From).contains(";tag="));
    assert_eq!(header(&bytes, HeaderName::CSeq), b"1 SUBSCRIBE");
    assert!(
        header(&bytes, HeaderName::Accept).is_empty(),
        "§3.1.3 leaves the body type to the package when none is asked for"
    );
}

#[test]
fn the_dialog_is_opened_by_the_notify_and_takes_its_route_set_from_it() {
    // §4.4.1: "Because the dialog usage is established by the NOTIFY request,
    // the route set at the subscriber is taken from the NOTIFY request itself,
    // as opposed to the route set present in the 200-class response to the
    // SUBSCRIBE request."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");

    // the 200 record-routes through one proxy and the NOTIFY through another;
    // only the NOTIFY's may be followed
    deliver(
        &mut agent,
        &reply(
            &subscribe,
            200,
            "OK",
            "Expires: 3600\r\nRecord-Route: <sip:wrong.example.com;lr>\r\n",
        ),
        t0,
    );
    let notify = notification_of(
        &subscribe,
        1,
        "notifier",
        DIALOG,
        "active;expires=3600",
        None,
        "Record-Route: <sip:right.example.com;lr>\r\n",
    );
    deliver(&mut agent, &notify, t0);
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = only(&transmits(&mut agent), "SUBSCRIBE ");
    assert_eq!(
        header(&refresh, HeaderName::Route),
        b"<sip:right.example.com;lr>",
        "the route set is the NOTIFY's"
    );
    assert!(
        text(&refresh, HeaderName::To).contains(";tag=notifier"),
        "and the dialog knows who answered"
    );
}

#[test]
fn a_refresh_continues_the_numbering_the_subscribe_started() {
    // the dialog does not exist when the SUBSCRIBE goes, so nothing in
    // RFC 3261 §12 has counted it. Starting the refresh at one again is a CSeq
    // running backwards, which §12.2.2 answers with a 500
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, subscribe) = subscribed(&mut agent, id, t0);
    assert_eq!(header(&subscribe, HeaderName::CSeq), b"1 SUBSCRIBE");

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = only(&transmits(&mut agent), "SUBSCRIBE ");
    assert_eq!(header(&refresh, HeaderName::CSeq), b"2 SUBSCRIBE");
    assert_eq!(
        header(&refresh, HeaderName::CallId),
        header(&subscribe, HeaderName::CallId),
        "a refresh is the same dialog, not a new subscription"
    );
    assert_eq!(header(&refresh, HeaderName::Expires), b"3600");
}

#[test]
fn a_notification_that_beats_the_two_hundred_still_makes_the_subscription() {
    // §4.1.2.4: "Due to the potential for out-of-order messages, packet loss,
    // and forking, the subscriber MUST be prepared to receive NOTIFY requests
    // before the SUBSCRIBE transaction has completed."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");

    deliver(
        &mut agent,
        &notification(&subscribe, 1, "notifier", "active;expires=3600", None),
        t0,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 200 "),
        "not a 481: {}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Active)
    );

    // and the 200 that follows changes nothing that has already happened
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Active)
    );
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::Subscribed { subscription, state: SubscriptionState::Active, .. }
                if subscription == handle
        )),
        "the state is an event"
    );
}

#[test]
fn a_subscription_that_cannot_be_sent_is_an_event_and_leaves_nothing_behind() {
    // the requirement's own sentence. The interface the account named has gone
    // — an address that no longer exists, a socket closed under it — and there
    // is no round trip in which to notice
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri("sip:alice@192.0.2.1"),
        TransportId(9),
        registrar(),
    ));
    let quiet = agent.poll_timeout();

    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the handle is minted before anything is sent");

    let reported = events(&mut agent);
    assert!(
        matches!(
            reported.as_slice(),
            [UaEvent::SubscriptionEnded {
                subscription,
                reason: SubscriptionEnd::Unreachable,
                retry_in: None,
                ..
            }] if *subscription == handle
        ),
        "one event, and it says it is not coming back: {reported:?}"
    );
    assert!(transmits(&mut agent).is_empty());
    assert_eq!(
        agent.subscription_state(handle),
        None,
        "the handle names nothing"
    );
    assert!(agent.dialog_info(handle).is_none());
    assert_eq!(
        agent.poll_timeout(),
        quiet,
        "nothing was scheduled, so there is nothing to come back for"
    );

    // and a year later there is still nothing to trip over
    agent.handle_timeout(t0 + Duration::from_secs(31_536_000));
    assert!(events(&mut agent).is_empty());
    assert!(transmits(&mut agent).is_empty());
}

#[test]
fn a_refresh_that_cannot_be_sent_is_the_same_event_on_a_live_subscription() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (handle, _) = subscribed(&mut agent, id, t0);

    // the transport goes while the subscription is settled and its refresh is
    // most of an hour out
    agent.remove_account(id);
    agent.handle_timeout(t0 + Duration::from_secs(3_060));

    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::SubscriptionEnded {
                subscription,
                reason: SubscriptionEnd::Unreachable,
                ..
            } if subscription == handle
        )),
        "a refresh that cannot go is reported the same way"
    );
    assert_eq!(agent.subscription_state(handle), None);
    agent.handle_timeout(t0 + Duration::from_secs(31_536_000));
    assert!(transmits(&mut agent).is_empty());
}

#[test]
fn thirty_extensions_go_up_in_one_pass_and_not_thirty_round_trips() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let wanted: Vec<Subscribe> = (200..230)
        .map(|extension| watching(&extension.to_string()))
        .collect();

    let handles = agent
        .subscribe_many(id, &wanted, t0)
        .expect("the batch goes");
    assert_eq!(handles.len(), 30);

    // one drain, thirty requests: nothing waited for anything
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 30, "thirty SUBSCRIBEs, in one pass");
    let mut call_ids: Vec<Vec<u8>> = out
        .iter()
        .map(|bytes| {
            assert!(bytes.starts_with(b"SUBSCRIBE "));
            header(bytes, HeaderName::CallId)
        })
        .collect();
    call_ids.sort_unstable();
    call_ids.dedup();
    assert_eq!(call_ids.len(), 30, "each is its own subscription");
    assert!(
        handles
            .iter()
            .all(|handle| agent.subscription_state(*handle) == Some(SubscriptionState::Requesting))
    );
}

#[test]
fn a_batch_reports_the_one_that_could_not_go_and_sends_the_rest() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let wanted = vec![
        watching("201"),
        // an address the account was never told about
        watching("202").to_address(TransportId(9), registrar()),
        watching("203"),
    ];

    let handles = agent
        .subscribe_many(id, &wanted, t0)
        .expect("the batch goes");
    assert_eq!(handles.len(), 3, "every target is named, including the one");
    assert_eq!(transmits(&mut agent).len(), 2);
    assert_eq!(agent.subscription_state(handles[1]), None);
    assert_eq!(
        agent.subscription_state(handles[2]),
        Some(SubscriptionState::Requesting),
        "the one behind it was not stopped"
    );
}

#[test]
fn a_subscription_nothing_notifies_is_over_when_timer_n_fires() {
    // §4.1.2.4: "If this Timer N expires prior to the receipt of a NOTIFY
    // request, the subscriber considers the subscription failed, and cleans up
    // any state associated with the subscription attempt."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    events(&mut agent);

    // 64*T1 is 32 seconds at the default T1
    agent.handle_timeout(t0 + Duration::from_secs(31));
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Requesting),
        "a cheerful 200 does not make a subscription"
    );

    agent.handle_timeout(t0 + Duration::from_secs(33));
    let ended = events(&mut agent);
    assert!(
        ended.iter().any(|event| matches!(
            *event,
            UaEvent::SubscriptionEnded {
                reason: SubscriptionEnd::NoNotify,
                retry_in: Some(_),
                ..
            }
        )),
        "{ended:?}"
    );
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Retrying)
    );
}

#[test]
fn a_terminated_notification_says_why_and_the_reason_decides_what_follows() {
    // §4.1.3's reason codes, and the three it tells clients not to come back
    // from
    for (reason, expected, comes_back) in [
        ("rejected", SubscriptionEnd::Rejected, false),
        ("noresource", SubscriptionEnd::NoResource, false),
        ("invariant", SubscriptionEnd::Invariant, false),
        ("probation", SubscriptionEnd::Probation, true),
        ("deactivated", SubscriptionEnd::Deactivated, true),
        ("giveup", SubscriptionEnd::GaveUp, true),
        ("timeout", SubscriptionEnd::Timeout, true),
    ] {
        assert_eq!(
            expected.as_reason(),
            Some(reason),
            "the wire token reads back as it was written"
        );
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let (handle, subscribe) = subscribed(&mut agent, id, t0);

        deliver(
            &mut agent,
            &notification(
                &subscribe,
                2,
                "notifier",
                &format!("terminated;reason={reason}"),
                None,
            ),
            t0,
        );
        transmits(&mut agent);
        let reported = events(&mut agent);
        assert!(
            reported.iter().any(|event| matches!(
                *event,
                UaEvent::SubscriptionEnded {
                    subscription,
                    reason: got,
                    retry_in,
                    ..
                } if subscription == handle
                    && got == expected
                    && retry_in.is_some() == comes_back
            )),
            "{reason}: {reported:?}"
        );
        assert_eq!(
            agent.subscription_state(handle).is_some(),
            comes_back,
            "{reason} leaves {} behind",
            if comes_back { "a retry" } else { "nothing" }
        );
    }
}

#[test]
fn a_probation_notification_waits_at_least_as_long_as_it_was_asked_to() {
    // §4.1.3: "If a retry-after parameter is also present, the client SHOULD
    // wait at least the number of seconds specified by that parameter"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (handle, subscribe) = subscribed(&mut agent, id, t0);
    deliver(
        &mut agent,
        &notification(
            &subscribe,
            2,
            "notifier",
            "terminated;reason=probation;retry-after=1800",
            None,
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(1_799));
    assert!(transmits(&mut agent).is_empty(), "not before it was asked");
    agent.handle_timeout(t0 + Duration::from_secs(1_801));
    let again = only(&transmits(&mut agent), "SUBSCRIBE ");
    // §4.1.2.2: "an unrelated initial SUBSCRIBE request with a freshly
    // generated Call-ID and a new, unique From tag"
    assert_ne!(
        header(&again, HeaderName::CallId),
        header(&subscribe, HeaderName::CallId)
    );
    assert_ne!(
        text(&again, HeaderName::From),
        text(&subscribe, HeaderName::From)
    );
    assert_eq!(header(&again, HeaderName::CSeq), b"1 SUBSCRIBE");
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Requesting),
        "the handle the application holds survives the re-subscription"
    );
}

#[test]
fn the_duration_the_notifier_states_wins_over_the_one_asked_for() {
    // §4.1.3: under active, "the subscriber SHOULD take it as the
    // authoritative subscription duration and adjust accordingly"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    deliver(
        &mut agent,
        &notification(&subscribe, 1, "notifier", "active;expires=120", None),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    // 0.85 of an hour would be 3060 seconds away; two minutes puts the refresh
    // ninety seconds out, which is the thirty-second margin
    agent.handle_timeout(t0 + Duration::from_secs(89));
    assert!(transmits(&mut agent).is_empty());
    agent.handle_timeout(t0 + Duration::from_secs(91));
    assert!(!transmits(&mut agent).is_empty(), "the notifier's number");
}

#[test]
fn a_subscription_nothing_refreshes_lapses_when_the_notifier_said_it_would() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (handle, _) = subscribed(&mut agent, id, t0);

    // every refresh is lost, so nothing renews it and the hour runs out
    agent.handle_timeout(t0 + Duration::from_secs(3_601));
    let ended = events(&mut agent);
    assert!(
        ended.iter().any(|event| matches!(
            *event,
            UaEvent::SubscriptionEnded {
                reason: SubscriptionEnd::Expired,
                ..
            }
        )),
        "{ended:?}"
    );
    assert_eq!(agent.subscription_state(handle), None);
}

#[test]
fn is_worth_retrying_agrees_with_what_a_subscription_actually_does() {
    // Both a lapse and a `terminated;reason=timeout` NOTIFY read like a
    // failure that could go differently on a second try, and both of the
    // paths that can end a subscription for a reason — a lapse through
    // `fire_subscription_timers`, a `terminated` NOTIFY through
    // `on_subscription_over` — go through the one function that asks
    // `is_worth_retrying`. The enum and what is left behind must agree.
    assert!(!SubscriptionEnd::Expired.is_worth_retrying());
    assert!(SubscriptionEnd::Timeout.is_worth_retrying());

    let t0 = Instant::now();

    // the lapse: nothing refreshed it before the granted hour ran out
    {
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let (handle, _) = subscribed(&mut agent, id, t0);
        agent.handle_timeout(t0 + Duration::from_secs(3_601));
        let ended = events(&mut agent);
        assert!(
            ended.iter().any(|event| matches!(
                *event,
                UaEvent::SubscriptionEnded {
                    reason: SubscriptionEnd::Expired,
                    retry_in: None,
                    ..
                }
            )),
            "{ended:?}"
        );
        assert_eq!(
            agent.subscription_state(handle),
            None,
            "is_worth_retrying says Expired is not, and nothing is left to retry"
        );
    }

    // the recoverable reason: the notifier says so itself
    {
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let (handle, subscribe) = subscribed(&mut agent, id, t0);
        deliver(
            &mut agent,
            &notification(&subscribe, 2, "notifier", "terminated;reason=timeout", None),
            t0,
        );
        transmits(&mut agent);
        let ended = events(&mut agent);
        assert!(
            ended.iter().any(|event| matches!(
                *event,
                UaEvent::SubscriptionEnded {
                    reason: SubscriptionEnd::Timeout,
                    retry_in: Some(_),
                    ..
                }
            )),
            "{ended:?}"
        );
        assert_eq!(
            agent.subscription_state(handle),
            Some(SubscriptionState::Retrying),
            "is_worth_retrying says Timeout is, and a retry is scheduled"
        );
    }
}

#[test]
fn a_notification_nobody_subscribed_to_is_refused() {
    // §4.1.3: "the subscriber should check that it matches at least one of its
    // outstanding subscriptions; if not, it MUST return a 481"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let unsolicited = b"NOTIFY sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKprobe\r\n\
Max-Forwards: 70\r\n\
From: <sip:probe@example.net>;tag=probe\r\n\
To: <sip:alice@192.0.2.1>;tag=guessed\r\n\
Call-ID: not-ours\r\n\
CSeq: 1 NOTIFY\r\n\
Contact: <sip:probe@192.0.2.9>\r\n\
Event: message-summary\r\n\
Subscription-State: active\r\n\
Content-Length: 0\r\n\r\n";
    deliver(&mut agent, unsolicited, t0);

    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 481 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
}

#[test]
fn a_notification_for_another_package_on_our_own_dialog_is_refused_489() {
    // §4.1.3: "If, for some reason, the event package designated in the Event
    // header field of the NOTIFY request is not supported, the subscriber will
    // respond with a 489 (Bad Event) response."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, subscribe) = subscribed(&mut agent, id, t0);

    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            2,
            "notifier",
            "message-summary",
            "active",
            None,
            "",
        ),
        t0,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 489 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
}

#[test]
fn an_event_that_carries_an_id_we_never_sent_does_not_match_ours() {
    // §8.2.1: "An Event header field containing an id parameter never matches
    // an Event header field without an id parameter."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");

    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            1,
            "notifier",
            "dialog;id=4321",
            "active;expires=3600",
            None,
            "",
        ),
        t0,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 489 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Requesting),
        "and it did not take the subscription with it"
    );
}

#[test]
fn a_transfer_notification_still_reaches_the_transfer_handler() {
    // the seam. A subscription machine that claims every NOTIFY swallows the
    // one RFC 3515 §2.4.4 opens with a REFER, and a transfer stops being
    // reported
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    subscribed(&mut agent, id, t0);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = only(&transmits(&mut agent), "REFER ");
    deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
    events(&mut agent);

    deliver(&mut agent, &notify(&ack, 1, "200 OK", "terminated"), t0);
    transmits(&mut agent);
    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::TransferDone { call: reported, .. } if reported == call
        )),
        "the transfer package is still the transfer handler's"
    );
}

#[test]
fn a_notification_in_a_call_that_belongs_to_no_subscription_is_still_refused() {
    // this used to be answered by the transfer handler, and moved when the
    // subscription machine took over §4.1.3
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, ack) = call_up(&mut agent, id, t0);

    let stray = plus(
        &reversed(&ack, "NOTIFY", "stray", 9, None),
        "Event: message-summary\r\nSubscription-State: active\r\n",
    );
    deliver(&mut agent, &stray, t0);
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 481 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
}

#[test]
fn the_lamp_reads_the_document_and_says_nothing_once_the_subscription_stops() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    deliver(
        &mut agent,
        &notification(
            &subscribe,
            1,
            "notifier",
            "active;expires=3600",
            Some((
                "application/dialog-info+xml",
                &dialog_info(0, true, "confirmed"),
            )),
        ),
        t0,
    );
    transmits(&mut agent);

    let reported = events(&mut agent);
    assert!(
        reported.iter().any(|event| matches!(
            *event,
            UaEvent::Notified { subscription, info: Some(ref info), .. }
                if subscription == handle && info.version == 0
        )),
        "{reported:?}"
    );
    assert_eq!(
        agent.dialog_info(handle).and_then(DialogInfoTable::phase),
        Some(DialogPhase::Confirmed),
        "the extension is on a call"
    );

    // the notifier hands the subscription on, so nothing is known any more
    deliver(
        &mut agent,
        &notification(
            &subscribe,
            2,
            "notifier",
            "terminated;reason=deactivated",
            None,
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert!(
        agent.dialog_info(handle).is_none(),
        "a table nothing refreshes is not evidence that anybody is free"
    );
}

#[test]
fn a_partial_document_with_a_gap_asks_for_full_state_back() {
    // RFC 4235 §4.3: "If the document did not contain full state, the
    // subscriber SHOULD generate a refresh request (SUBSCRIBE) to trigger a
    // full state notification."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, subscribe) = subscribed(&mut agent, id, t0);

    deliver(
        &mut agent,
        &notification(
            &subscribe,
            2,
            "notifier",
            "active;expires=3600",
            Some((
                "application/dialog-info+xml",
                &dialog_info(0, true, "confirmed"),
            )),
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    // version 7 where 1 was due: six notifications were lost, and this one
    // only says what changed
    deliver(
        &mut agent,
        &notification(
            &subscribe,
            3,
            "notifier",
            "active;expires=3600",
            Some((
                "application/dialog-info+xml",
                &dialog_info(7, false, "early"),
            )),
        ),
        t0,
    );
    let out = transmits(&mut agent);
    assert!(
        out.iter().any(|bytes| bytes.starts_with(b"SUBSCRIBE ")),
        "the gap is chased with a refresh"
    );
}

#[test]
fn a_document_that_will_not_read_leaves_the_lamp_where_it_was() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (handle, subscribe) = subscribed(&mut agent, id, t0);
    deliver(
        &mut agent,
        &notification(
            &subscribe,
            2,
            "notifier",
            "active;expires=3600",
            Some((
                "application/dialog-info+xml",
                &dialog_info(0, true, "confirmed"),
            )),
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &notification(
            &subscribe,
            3,
            "notifier",
            "active;expires=3600",
            Some(("application/dialog-info+xml", "<!DOCTYPE lol [ <!ENTITY")),
        ),
        t0,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 200 "),
        "the NOTIFY is answered"
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::Notified { info: None, .. })),
        "and the body it could not read is reported as none"
    );
    assert_eq!(
        agent.dialog_info(handle).and_then(DialogInfoTable::phase),
        Some(DialogPhase::Confirmed),
        "the last thing a working notifier said still stands"
    );
}

#[test]
fn an_unsubscribe_asks_with_expires_zero_and_waits_for_the_last_word() {
    // §4.1.2.3, and §4.4.1: "the subscription is not considered terminated
    // until the NOTIFY transaction with a Subscription-State of terminated
    // completes"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (handle, subscribe) = subscribed(&mut agent, id, t0);

    agent.unsubscribe(handle, t0).expect("the request goes");
    let last = only(&transmits(&mut agent), "SUBSCRIBE ");
    assert_eq!(header(&last, HeaderName::Expires), b"0");
    deliver(&mut agent, &accepted(&last, 0), t0);
    assert!(
        agent.subscription_state(handle).is_some(),
        "it is not over until the notifier says so"
    );

    deliver(
        &mut agent,
        &notification(&subscribe, 2, "notifier", "terminated;reason=timeout", None),
        t0,
    );
    transmits(&mut agent);
    let reported = events(&mut agent);
    assert!(
        reported.iter().any(|event| matches!(
            *event,
            UaEvent::SubscriptionEnded {
                reason: SubscriptionEnd::Unsubscribed,
                retry_in: None,
                ..
            }
        )),
        "the reason is what we asked for, not what the notifier called it: \
         {reported:?}"
    );
    assert_eq!(agent.subscription_state(handle), None);
    agent.handle_timeout(t0 + Duration::from_secs(31_536_000));
    assert!(transmits(&mut agent).is_empty());
}

#[test]
fn a_challenged_subscribe_goes_again_with_credentials_and_keeps_its_numbering() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "secret")));
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let first = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(
        &mut agent,
        &reply(
            &first,
            401,
            "Unauthorized",
            "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\"\r\n",
        ),
        t0,
    );

    let retry = only(&transmits(&mut agent), "SUBSCRIBE ");
    // §22.2: "it MUST increment the CSeq header field value"
    assert_eq!(header(&retry, HeaderName::CSeq), b"2 SUBSCRIBE");
    credentials_of(&retry, HeaderName::Authorization);

    deliver(&mut agent, &accepted(&retry, 3_600), t0);
    deliver(
        &mut agent,
        &notification(&retry, 1, "notifier", "active;expires=3600", None),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Active)
    );

    // and the dialog continues from where the answered SUBSCRIBE left off
    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = only(&transmits(&mut agent), "SUBSCRIBE ");
    assert_eq!(header(&refresh, HeaderName::CSeq), b"3 SUBSCRIBE");
}

#[test]
fn a_subscribe_challenged_with_the_nonce_the_register_answered_goes_again() {
    // Asterisk draws its nonce from the clock, so a SUBSCRIBE sent in the
    // same second as the REGISTER is refused with the nonce the REGISTER
    // already answered. The lab's mailbox flow ended there, refused: the
    // SUBSCRIBE had carried no credentials, so nothing had been rejected.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "secret")));
    let clock_nonce = "WWW-Authenticate: Digest realm=\"asterisk\",\
nonce=\"1790030428/0c6e1bb101ec6dce559767230783f15f\",opaque=\"2388489800029c2e\",\
algorithm=MD5,qop=\"auth\"\r\n";
    agent.register(id, t0).expect("the REGISTER goes");
    let register = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(&register, 401, "Unauthorized", clock_nonce),
        t0,
    );
    let answered = sent(&mut agent);
    deliver(&mut agent, &granted(&answered, 300), t0);
    events(&mut agent);

    let aor = agent.account(id).expect("the account").aor().clone();
    let handle = agent
        .subscribe(id, &Subscribe::new(aor, "message-summary"), t0)
        .expect("the SUBSCRIBE goes");
    let first = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(
        &mut agent,
        &reply(&first, 401, "Unauthorized", clock_nonce),
        t0,
    );

    let retry = only(&transmits(&mut agent), "SUBSCRIBE ");
    let credentials =
        String::from_utf8_lossy(&header(&retry, HeaderName::Authorization)).into_owned();
    assert!(
        credentials.contains("nc=00000002"),
        "the nonce counts on from the REGISTER's answer: {credentials}"
    );
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Requesting),
        "still asking, not ended"
    );
}

#[test]
fn a_challenge_that_comes_back_a_second_time_is_the_password_being_wrong() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().credentials(Credentials::new("alice", "wrong")));
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let first = only(&transmits(&mut agent), "SUBSCRIBE ");
    let refusal = "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\"\r\n";
    deliver(&mut agent, &reply(&first, 401, "Unauthorized", refusal), t0);
    let retry = only(&transmits(&mut agent), "SUBSCRIBE ");
    events(&mut agent);
    deliver(&mut agent, &reply(&retry, 401, "Unauthorized", refusal), t0);

    let reported = events(&mut agent);
    assert!(
        reported.iter().any(|event| matches!(
            *event,
            UaEvent::SubscriptionEnded {
                reason: SubscriptionEnd::Refused,
                retry_in: None,
                ..
            }
        )),
        "§22.1's second refusal is not retried: {reported:?}"
    );
    assert_eq!(agent.subscription_state(handle), None);
}

#[test]
fn a_refresh_refused_with_a_five_hundred_leaves_the_subscription_standing() {
    // §4.1.2.2: "the original subscription is still considered valid for the
    // duration of the most recently known Expires value"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (handle, _) = subscribed(&mut agent, id, t0);

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(
        &mut agent,
        &reply(&refresh, 500, "Server Internal Error", ""),
        t0 + Duration::from_secs(3_060),
    );

    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Active),
        "one bad refresh is not the end of a subscription"
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::SubscriptionEnded { .. })),
        "and nothing said it was"
    );
    assert!(agent.dialog_info(handle).is_some());
}

#[test]
fn a_refresh_refused_with_a_four_eighty_one_ends_it() {
    // the same section's other half: 404, 405, 410, 416, 480-485, 489, 501 and
    // 604 mean the subscription is gone
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (handle, _) = subscribed(&mut agent, id, t0);

    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let refresh = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(
        &mut agent,
        &reply(&refresh, 481, "Subscription Does Not Exist", ""),
        t0 + Duration::from_secs(3_060),
    );

    let reported = events(&mut agent);
    assert!(
        reported.iter().any(|event| matches!(
            *event,
            UaEvent::SubscriptionEnded {
                reason: SubscriptionEnd::Refused,
                retry_in: None,
                ..
            }
        )),
        "{reported:?}"
    );
    assert_eq!(agent.subscription_state(handle), None);
}

#[test]
fn a_four_eighty_nine_says_the_package_is_not_supported_and_stops() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &reply(&subscribe, 489, "Bad Event", ""), t0);

    let reported = events(&mut agent);
    assert!(
        reported.iter().any(|event| matches!(
            *event,
            UaEvent::SubscriptionEnded {
                reason: SubscriptionEnd::BadEvent,
                retry_in: None,
                ..
            }
        )),
        "{reported:?}"
    );
    assert_eq!(agent.subscription_state(handle), None);
    agent.handle_timeout(t0 + Duration::from_secs(31_536_000));
    assert!(transmits(&mut agent).is_empty());
}

#[test]
fn one_subscribe_answered_by_two_notifiers_installs_two_subscriptions() {
    // §4.1.4 and RFC 4235 §3.9: "Subscribers to this package MUST be prepared
    // to install subscription state for each NOTIFY generated as a result of a
    // single SUBSCRIBE."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);

    for tag in ["desk", "mobile"] {
        deliver(
            &mut agent,
            &notification(&subscribe, 1, tag, "active;expires=3600", None),
            t0,
        );
    }
    for answer in transmits(&mut agent) {
        assert!(
            answer.starts_with(b"SIP/2.0 200 "),
            "{}",
            String::from_utf8_lossy(&answer)
        );
    }
    let sibling = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::SubscriptionForked {
                subscription,
                sibling,
            } if subscription == handle => Some(sibling),
            _ => None,
        });
    let sibling = sibling.expect("the second notifier gets a subscription of its own");
    assert_eq!(
        agent.subscription_state(handle),
        Some(SubscriptionState::Active)
    );
    assert_eq!(
        agent.subscription_state(sibling),
        Some(SubscriptionState::Active)
    );

    // and each refreshes in its own dialog
    agent.handle_timeout(t0 + Duration::from_secs(3_060));
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 2, "one refresh each");
    let mut tags: Vec<String> = out
        .iter()
        .map(|bytes| text(bytes, HeaderName::To))
        .collect();
    tags.sort();
    assert!(tags[0].contains(";tag=desk"), "{tags:?}");
    assert!(tags[1].contains(";tag=mobile"), "{tags:?}");
}

#[test]
fn a_second_notifier_after_timer_n_has_passed_is_refused() {
    // §4.1.2.4: "After the expiration of Timer N, the subscriber SHOULD reject
    // any such NOTIFY requests that would otherwise establish a new dialog
    // usage with a 481"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(
        &mut agent,
        &notification(&subscribe, 1, "desk", "active;expires=3600", None),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    let late = t0 + Duration::from_secs(40);
    agent.handle_timeout(late);
    transmits(&mut agent);
    deliver(
        &mut agent,
        &notification(&subscribe, 1, "mobile", "active;expires=3600", None),
        late,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 481 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
}

#[test]
fn a_dead_flow_stops_the_lamp_saying_anything() {
    // the failure this is for: the socket goes while somebody is on a call,
    // the refresh is fifty minutes away, and the lamp shows them free
    let t0 = Instant::now();
    let (mut agent, id) = over_tcp(t0);
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    stream(&mut agent, &accepted(&subscribe, 3_600), t0);
    stream(
        &mut agent,
        &notification(
            &subscribe,
            1,
            "notifier",
            "active;expires=3600",
            Some((
                "application/dialog-info+xml",
                &dialog_info(0, true, "confirmed"),
            )),
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert_eq!(
        agent.dialog_info(handle).and_then(DialogInfoTable::phase),
        Some(DialogPhase::Confirmed)
    );

    // RFC 5626 §4.4.1 calls the flow dead when a keep-alive goes ten seconds
    // unanswered on a flow that has answered one, and the core takes the
    // transport down
    let ping_at = second_ping(&mut agent);
    agent.handle_timeout(ping_at + Duration::from_secs(10));

    assert!(
        events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::SubscriptionEnded {
                subscription,
                reason: SubscriptionEnd::Unreachable,
                retry_in: Some(_),
                ..
            } if subscription == handle
        )),
        "the subscription says it is not live"
    );
    assert!(
        agent.dialog_info(handle).is_none(),
        "and nothing may be read out of what it last held"
    );
}

// -- the allowance, on every path that answers a challenge -------------------

/// A challenge with a nonce nobody has seen before, and no `stale`.
///
/// The shape §22.1's guard cannot see: the nonce is never the same twice, so
/// "the same nonce means the password was wrong" never fires.
fn fresh_challenge(request: &[u8], round: u32) -> Vec<u8> {
    let field = format!(
        "WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"n{round}\", qop=\"auth\"\r\n"
    );
    challenge(request, 401, "Unauthorized", &field)
}

#[test]
fn a_pbx_that_draws_a_new_nonce_every_time_gets_at_most_three_answers_for_a_call() {
    // one wrong password per round trip, for as long as the process lives, is
    // how an account gets locked out
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");

    let mut last = sent(&mut agent);
    let mut credentialled_invites = 0;
    for round in 0..8 {
        deliver(&mut agent, &fresh_challenge(&last, round), t0);
        let out = transmits(&mut agent);
        // the ACK for the 401 always goes; the retry may not
        let Some(retry) = out.iter().find(|bytes| bytes.starts_with(b"INVITE ")) else {
            break;
        };
        assert!(
            !header(retry, HeaderName::Authorization).is_empty(),
            "a retry without credentials is not an answer"
        );
        credentialled_invites += 1;
        last = retry.clone();
    }

    assert_eq!(
        credentialled_invites, 3,
        "the PBX rotates its nonce, so only the count stops this"
    );
    assert!(
        matches!(ended(&mut agent), Some((_, CallEndReason::Refused))),
        "and the application is told, rather than left waiting"
    );
}

#[test]
fn a_notifier_that_draws_a_new_nonce_every_time_gets_at_most_three_answers() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    agent
        .subscribe(
            id,
            &Subscribe::new(uri("sip:bob@example.com"), "presence"),
            t0,
        )
        .expect("the SUBSCRIBE goes");

    let mut last = sent(&mut agent);
    let mut credentialled_subscribes = 0;
    for round in 0..8 {
        deliver(&mut agent, &fresh_challenge(&last, round), t0);
        let out = transmits(&mut agent);
        let Some(retry) = out.iter().find(|bytes| bytes.starts_with(b"SUBSCRIBE ")) else {
            break;
        };
        assert!(!header(retry, HeaderName::Authorization).is_empty());
        credentialled_subscribes += 1;
        last = retry.clone();
    }

    assert_eq!(credentialled_subscribes, 3);
    let ended = events(&mut agent).into_iter().any(|event| {
        matches!(
            event,
            UaEvent::SubscriptionEnded {
                reason: SubscriptionEnd::Refused,
                ..
            }
        )
    });
    assert!(ended, "the subscription is over and the application knows");
}

#[test]
fn a_bye_a_pbx_keeps_challenging_still_ends_the_call() {
    // §15.1.1: the BYE is what ends the call, so one that can never be
    // authenticated leaves the far end holding a call this end hung up. That
    // half cannot be fixed from here. What can be, and is, is this end: the
    // dialog ends when the BYE transaction gets a final answer whatever the
    // answer is, so the application is told once and the call does not sit
    // in Terminating waiting for a retry the allowance has stopped.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let (call, _) = call_up(&mut agent, id, t0);

    agent.hangup(call, t0).expect("the BYE goes");
    let mut last = only(&transmits(&mut agent), "BYE ");
    for round in 0..8 {
        deliver(&mut agent, &fresh_challenge(&last, round), t0);
        let out = transmits(&mut agent);
        let Some(retry) = out.iter().find(|bytes| bytes.starts_with(b"BYE ")) else {
            break;
        };
        last = retry.clone();
    }

    assert_eq!(
        ended(&mut agent),
        Some((call, CallEndReason::LocalHangup)),
        "this end decided to hang up, and the call is over whatever the PBX says"
    );
}

#[test]
fn a_refer_a_pbx_keeps_challenging_gives_the_transfer_seat_back() {
    // the seat taken when the REFER went out used to be kept for the life of
    // the call, so every later transfer was refused here before anything was
    // sent
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let (call, _) = call_up(&mut agent, id, t0);

    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let mut last = only(&transmits(&mut agent), "REFER ");
    for round in 0..8 {
        deliver(&mut agent, &fresh_challenge(&last, round), t0);
        let out = transmits(&mut agent);
        let Some(retry) = out.iter().find(|bytes| bytes.starts_with(b"REFER ")) else {
            break;
        };
        last = retry.clone();
    }

    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::TransferDone { .. })),
        "the transfer did not happen, and that is news"
    );
    agent
        .transfer(call, &uri("sip:dave@example.com"), t0)
        .expect("the call is free to be transferred again");
}

/// RFC 8599 §4.1 keeps `pn-prid` off every request but REGISTER, because a
/// token that wakes this device is one the far end must not be handed. A log
/// file is a worse place for it than an INVITE, because it is kept.
#[test]
fn printing_an_agent_prints_no_push_token() {
    const TOKEN: &str = "a1b2c3d4-this-wakes-the-device";
    const PARAM: &str = "com.example.app.voip";
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account().push(crate::account::Push::new("apns", TOKEN).param(PARAM)));

    let printed = format!("{agent:?}");
    assert!(
        printed.contains("apns"),
        "the provider is not the secret and is worth seeing: {printed}"
    );
    assert!(
        !printed.contains(TOKEN),
        "the push token reached a debug print"
    );
    assert!(
        !printed.contains(PARAM),
        "the push parameter reached a debug print"
    );
}

/// Every NOTIFY that went out, as its subscription state and its body.
fn notifies(out: &[Vec<u8>]) -> Vec<(String, String)> {
    out.iter()
        .filter(|bytes| bytes.starts_with(b"NOTIFY "))
        .map(|bytes| {
            (
                String::from_utf8_lossy(&header(bytes, HeaderName::SubscriptionState)).into_owned(),
                body_of(bytes),
            )
        })
        .collect()
}

/// Take a REFER and place the call it asked for.
fn refer_taken(agent: &mut UserAgent, now: Instant) -> (CallHandle, CallHandle, Vec<u8>) {
    let call = call_arriving(agent, &incoming_invite("prb", Some(OFFER)), now);
    agent
        .answer(call, Some(Arc::from(ANSWER)), now)
        .expect("200 goes");
    let ok = sent(agent);
    deliver(agent, &in_dialog(&ok, "ACK", "prback", 1), now);
    events(agent);
    deliver(
        agent,
        &plus(
            &in_dialog(&ok, "REFER", "prbrefer", 2),
            "Refer-To: <sip:carol@example.com>\r\n",
        ),
        now,
    );
    events(agent);
    let placed = agent
        .accept_transfer(call, None, OutgoingExtras::default(), now)
        .expect("the transfer is taken");
    let written = transmits(agent);
    let invite = only(&written, "INVITE ");
    assert_eq!(
        notifies(&written).len(),
        1,
        "2.4.5's 100 Trying goes when the transfer is taken"
    );
    events(agent);
    (call, placed, invite)
}

#[test]
fn a_referred_call_that_was_refused_still_says_so() {
    // RFC 3515 2.4.4 has the transferee report the result, and 2.4.7 makes the
    // last NOTIFY of the subscription say it is over
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (_call, _placed, invite) = refer_taken(&mut agent, t0);

    deliver(
        &mut agent,
        &answered(&invite, 486, "Busy Here", "carol", None),
        t0,
    );
    let after = transmits(&mut agent);
    let said = notifies(&after);
    assert!(
        said.iter()
            .any(|(state, body)| body.starts_with("SIP/2.0 486") && state.starts_with("terminated")),
        "the transferor is never told the target was busy: {said:?}"
    );
}

#[test]
fn a_referred_call_that_was_never_answered_still_says_so() {
    // the same, with nothing coming back at all: Timer B, and the transferor
    // is left holding a subscription that is never closed
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let (_call, _placed, _invite) = refer_taken(&mut agent, t0);

    agent.handle_timeout(t0 + Duration::from_secs(40));
    let after = transmits(&mut agent);
    let said = notifies(&after);
    assert!(
        said.iter()
            .any(|(state, _)| state.starts_with("terminated")),
        "the subscription the REFER opened is never closed: {said:?}"
    );
}

#[test]
fn one_call_cannot_be_transferred_twice_at_once() {
    // `transfer` documents UaError::WrongState "for a call that is ... already
    // transferring", and the seat exists to enforce it. A 202 Accepted is a
    // final answer to the REFER, but RFC 3515 2.4.2 has it open a
    // subscription rather than close the matter, so it must not free the seat.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the first REFER goes");
    let first = only(&transmits(&mut agent), "REFER ");
    deliver(&mut agent, &reply(&first, 202, "Accepted", ""), t0);
    events(&mut agent);

    let second = agent.transfer(call, &uri("sip:dave@example.com"), t0);
    let written = transmits(&mut agent);
    let refers: Vec<Vec<u8>> = written
        .iter()
        .filter(|bytes| bytes.starts_with(b"REFER "))
        .cloned()
        .collect();
    assert!(
        second.is_err() && refers.is_empty(),
        "a second transfer opens a second implicit subscription in the same \
         dialog while the first has not said it is done: {second:?}"
    );
}

#[test]
fn a_notify_about_a_transfer_names_which_refer_it_reports_on() {
    // §2.4.6: "for the second and subsequent REFER requests a UA receives in
    // a given dialog, it MUST include an id parameter in the Event header
    // field of each NOTIFY... This id parameter MAY be included in NOTIFYs to
    // the first REFER." Carried always, so the transferor never has to guess
    // which REFER a report is about.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("idcall", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "idack", 1), t0);
    events(&mut agent);
    let refer = plus(
        &in_dialog(&ok, "REFER", "idrefer", 7),
        "Refer-To: <sip:carol@example.com>\r\n",
    );
    deliver(&mut agent, &refer, t0);
    events(&mut agent);
    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the transfer is taken");
    let notify = only(&transmits(&mut agent), "NOTIFY ");
    assert_eq!(
        header(&notify, HeaderName::Event),
        b"refer;id=7",
        "the NOTIFY does not say which REFER it reports on: {}",
        String::from_utf8_lossy(&header(&notify, HeaderName::Event))
    );
}

#[test]
fn accepting_a_transfer_places_the_call_with_the_offer_given() {
    // the transfer target has to be told something to answer, exactly as any
    // other call this end places; accept_transfer used to place the INVITE
    // with nothing at all, whatever the application gave it here
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("medcall", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "medack", 1), t0);
    events(&mut agent);
    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "medrefer", 2),
            "Refer-To: <sip:carol@example.com>\r\n",
        ),
        t0,
    );
    events(&mut agent);

    agent
        .accept_transfer(call, Some(Arc::from(OFFER)), OutgoingExtras::default(), t0)
        .expect("the transfer is taken");
    let invite = only(&transmits(&mut agent), "INVITE ");
    assert!(
        body_of(&invite).contains("m=audio"),
        "the INVITE a transfer places carries no offer: {}",
        body_of(&invite)
    );
}

/// A REFER that arrived on a call this end answered, with `refer_lines` on
/// it, offered to the application and not yet taken or refused.
fn a_refer_waiting(
    agent: &mut UserAgent,
    branch: &str,
    refer_lines: &str,
    t0: Instant,
) -> CallHandle {
    agent.add_account(account());
    let call = call_arriving(agent, &incoming_invite(branch, Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(agent);
    deliver(
        agent,
        &in_dialog(&ok, "ACK", &format!("{branch}ack"), 1),
        t0,
    );
    events(agent);
    deliver(
        agent,
        &plus(
            &in_dialog(&ok, "REFER", &format!("{branch}refer"), 2),
            refer_lines,
        ),
        t0,
    );
    assert!(
        events(agent)
            .iter()
            .any(|event| matches!(event, UaEvent::TransferRequested { .. })),
        "the REFER was offered"
    );
    call
}

/// A field `accept_transfer` refuses is refused before the REFER is touched:
/// no 202, no NOTIFY, no INVITE, and the transfer still there to take. Every
/// refusal the INVITE would earn counts, a line break in a value included —
/// found only once the call is built, it would come after the 202 had gone.
#[test]
fn a_header_field_refused_on_a_transfer_leaves_the_refer_to_be_taken() {
    let t0 = Instant::now();
    for (n, (name, value, why)) in [
        (
            HeaderName::Allow,
            &b"INVITE, BYE"[..],
            crate::HeaderRefused::WrittenByTheStack("Allow"),
        ),
        (
            conversation_id(),
            &b"c-7\r\nContact: <sip:elsewhere@example.net>"[..],
            crate::HeaderRefused::ControlByte { offset: 3 },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut agent = agent(t0);
        let call = a_refer_waiting(
            &mut agent,
            &format!("xhdr{n}"),
            "Refer-To: <sip:carol@example.com>\r\n",
            t0,
        );
        let fields = [(name, value)];
        let refused = agent.accept_transfer(
            call,
            None,
            OutgoingExtras {
                headers: &fields,
                ..OutgoingExtras::default()
            },
            t0,
        );
        assert_eq!(refused, Err(UaError::Header(why)), "{name}");
        let written: Vec<String> = transmits(&mut agent)
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .collect();
        assert!(written.is_empty(), "{name}: {written:#?}");

        let taken = agent.accept_transfer(call, None, OutgoingExtras::default(), t0);
        assert!(
            taken.is_ok(),
            "{name}: the refusal used the REFER up: {taken:?}"
        );
    }
}

/// RFC 3891 §3 has an INVITE with more than one `Replaces` refused with a
/// 400, and RFC 3892 §3 gives `Referred-By` one referrer. On the INVITE an
/// accepted transfer places both are the REFER's, never the application's,
/// so one of its own is refused before the REFER is touched.
#[test]
fn a_replaces_or_referred_by_of_the_applications_is_refused_on_a_transfer() {
    let t0 = Instant::now();
    for (n, name, value) in [
        (
            0,
            HeaderName::Replaces,
            &b"other@192.0.2.1;to-tag=x;from-tag=y"[..],
        ),
        (1, HeaderName::ReferredBy, &b"<sip:mallory@example.net>"[..]),
    ] {
        let mut agent = agent(t0);
        let call = a_refer_waiting(
            &mut agent,
            &format!("xrep{n}"),
            "Refer-To: <sip:carol@example.com?Replaces=call%3Bto-tag%3Da%3Bfrom-tag%3Db>\r\n\
             Referred-By: <sip:bob@example.com>\r\n",
            t0,
        );
        let fields = [(name, value)];
        let refused = agent.accept_transfer(
            call,
            None,
            OutgoingExtras {
                headers: &fields,
                ..OutgoingExtras::default()
            },
            t0,
        );
        assert_eq!(
            refused,
            Err(UaError::Header(crate::HeaderRefused::WrittenByTheStack(
                name.canonical()
            ))),
            "{name}"
        );
        assert!(transmits(&mut agent).is_empty(), "{name}: nothing went out");

        agent
            .accept_transfer(call, None, OutgoingExtras::default(), t0)
            .expect("the REFER is still there to take");
        let invite = only(&transmits(&mut agent), "INVITE sip:carol@example.com");
        assert_eq!(
            with(&invite, |message| message.header_count(name)),
            1,
            "{name}: the REFER's, and only the REFER's"
        );
    }
}

/// §2.4.6 gives every NOTIFY an `id` precisely because a dialog may carry
/// more than one REFER. This end keeps one transfer per call, so the second
/// has to be refused rather than taken over the first: taking it would throw
/// away the first's transaction, the call it placed and the `id` its own
/// NOTIFYs are tagged with, and the transferor would be told about the wrong
/// transfer.
#[test]
fn a_second_refer_on_one_call_waits_rather_than_replacing_the_first() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(&mut agent, &incoming_invite("two1", Some(OFFER)), t0);
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "two1ack", 1), t0);
    events(&mut agent);

    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "two1ref", 2),
            "Refer-To: <sip:carol@example.com>\r\n",
        ),
        t0,
    );
    events(&mut agent);
    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the first transfer is taken");
    transmits(&mut agent);
    events(&mut agent);

    // a second one, while the first is still running
    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "two2ref", 3),
            "Refer-To: <sip:dave@example.com>\r\n",
        ),
        t0,
    );
    let answered = transmits(&mut agent);
    assert!(
        answered
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 491 ")),
        "the second REFER was not told to wait: {:?}",
        answered
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes.get(..16).unwrap_or_default()).into_owned())
            .collect::<Vec<_>>()
    );
    assert!(
        !events(&mut agent)
            .into_iter()
            .any(|event| matches!(event, UaEvent::TransferRequested { .. })),
        "the application was asked to take a transfer it cannot hold"
    );
}

// -- §18.1.1 on what this layer sends inside a dialog ------------------------

/// The same message from a far end whose URI alone is more than a datagram may
/// carry, at the same address, so that every request in the dialog it opens
/// or refreshes outgrows the datagram and nothing about the next hop changes.
fn from_afar(message: &[u8]) -> Vec<u8> {
    let padding = "y".repeat(1_400);
    let mut moved = String::from_utf8_lossy(message).into_owned();
    for user in ["bob", "notifier"] {
        moved = moved.replace(
            &format!("Contact: <sip:{user}@192.0.2.9>"),
            &format!("Contact: <sip:{user}@192.0.2.9;x={padding}>"),
        );
    }
    assert_ne!(moved.as_bytes(), message, "a Contact to move");
    moved.into_bytes()
}

/// The stream the endpoint asked for, open to the far end.
fn open_the_stream(agent: &mut UserAgent, now: Instant) {
    agent
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(registrar()),
            },
            now,
        )
        .expect("binding TCP");
}

/// Everything the agent wants written, with the transport each goes on.
fn written(agent: &mut UserAgent) -> Vec<(TransportId, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some(transmit) = agent.poll_transmit() {
        out.push((transmit.transport, transmit.payload.to_vec()));
    }
    out
}

/// What went out, the way a failing assertion should say it.
fn listed(out: &[(TransportId, Vec<u8>)]) -> Vec<String> {
    out.iter()
        .map(|(transport, bytes)| {
            format!(
                "{} bytes on {transport:?}: {}",
                bytes.len(),
                String::from_utf8_lossy(bytes.get(..16).unwrap_or_default())
            )
        })
        .collect()
}

/// Nothing of this method went out, over anything.
fn not_written(out: &[(TransportId, Vec<u8>)], method: &str) {
    assert!(
        !out.iter()
            .any(|(_, bytes)| bytes.starts_with(method.as_bytes())),
        "{:?}",
        listed(out)
    );
}

/// The one message of this method, which has to have gone on the stream.
fn on_the_stream(out: &[(TransportId, Vec<u8>)], method: &str) -> Vec<u8> {
    let found: Vec<&(TransportId, Vec<u8>)> = out
        .iter()
        .filter(|(_, bytes)| bytes.starts_with(method.as_bytes()))
        .collect();
    assert_eq!(found.len(), 1, "one {method:?} in {:?}", listed(out));
    let (transport, bytes) = found[0];
    assert_eq!(*transport, TCP, "{method:?} went on {transport:?}");
    bytes.clone()
}

#[test]
fn an_ack_too_big_for_a_datagram_waits_for_the_stream_and_the_call_is_up_meanwhile() {
    // §13.2.2.4 makes the ACK this layer's to send, so when §18.1.1 refuses it
    // a datagram there is nobody to hand the refusal to. Dropped, it left the
    // far end retransmitting its 200 until it hung up
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let ok = from_afar(&answered(&invite, 200, "OK", "desk", Some(ANSWER)));
    deliver(&mut agent, &ok, t0);

    let out = written(&mut agent);
    assert!(out.is_empty(), "{:?}", listed(&out));
    let confirmed: Vec<bool> = events(&mut agent)
        .iter()
        .filter_map(|event| match *event {
            UaEvent::CallConfirmed { answer_wanted, .. } => Some(answer_wanted),
            _ => None,
        })
        .collect();
    assert_eq!(
        confirmed,
        vec![false],
        "the call is up, and its ACK owes the application nothing"
    );

    // the far end repeats its 200 while it waits, and it is the same answer
    let later = t0 + Duration::from_millis(500);
    deliver(&mut agent, &ok, later);
    let out = written(&mut agent);
    assert!(out.is_empty(), "{:?}", listed(&out));
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::CallConfirmed { .. })),
        "one call, confirmed once"
    );

    // what the application asks for meanwhile is refused back to it the way
    // a first send is, and changes nothing
    assert_eq!(
        agent.hangup(call, later),
        Err(UaError::Send(
            sipral_core::endpoint::SendError::NeedsStreamTransport
        ))
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));

    open_the_stream(&mut agent, later);
    let ack = on_the_stream(&written(&mut agent), "ACK ");
    assert_eq!(header(&ack, HeaderName::CSeq), b"1 ACK");

    agent.hangup(call, later).expect("the BYE goes");
    on_the_stream(&written(&mut agent), "BYE ");
}

#[test]
fn an_answer_owed_in_a_prack_is_still_owed_when_the_prack_needs_a_stream() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent
        .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &from_afar(&plus(
            &answered(&invite, 183, "Session Progress", "desk", Some(ANSWER)),
            "Require: 100rel\r\nRSeq: 314\r\n",
        )),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    assert_eq!(
        agent.answer_early(call, OFFER, t0),
        Err(UaError::Send(
            sipral_core::endpoint::SendError::NeedsStreamTransport
        )),
        "the refusal the application can act on, not a call in the wrong state"
    );
    let out = written(&mut agent);
    assert!(out.is_empty(), "{:?}", listed(&out));

    open_the_stream(&mut agent, t0);
    agent
        .answer_early(call, OFFER, t0)
        .expect("the same answer goes once it can");
    let prack = on_the_stream(&written(&mut agent), "PRACK ");
    assert!(body_of(&prack).contains("m=audio 8000 RTP/AVP 0\r\n"));
}

#[test]
fn a_prack_this_layer_owes_waits_for_the_stream_rather_than_being_dropped() {
    // RFC 3262 §3: the far end retransmits the provisional until it is
    // acknowledged, and then refuses the INVITE with a 5xx
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &from_afar(&plus(
            &answered(&invite, 183, "Session Progress", "desk", None),
            "Require: 100rel\r\nRSeq: 7\r\n",
        )),
        t0,
    );
    not_written(&written(&mut agent), "PRACK ");
    events(&mut agent);

    open_the_stream(&mut agent, t0);
    let prack = on_the_stream(&written(&mut agent), "PRACK ");
    assert_eq!(header(&prack, HeaderName::RAck), b"7 1 INVITE");
}

#[test]
fn the_ack_to_a_session_change_waits_for_the_stream_rather_than_being_dropped() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_, reinvite) = on_hold(&mut agent, id, t0);
    // the 200 refreshes the target (§12.2.1.2), and its ACK is the first
    // request to carry the new one
    deliver(
        &mut agent,
        &from_afar(&answered(
            &reinvite,
            200,
            "OK",
            "desk",
            Some(THEIR_RECVONLY),
        )),
        t0,
    );
    not_written(&written(&mut agent), "ACK ");
    assert_eq!(
        session_changed(&mut agent),
        Some(Hold {
            local: true,
            remote: false
        }),
        "the change was taken"
    );

    open_the_stream(&mut agent, t0);
    let ack = on_the_stream(&written(&mut agent), "ACK ");
    assert_eq!(header(&ack, HeaderName::CSeq), b"2 ACK");
}

#[test]
fn a_transfer_report_waits_for_the_stream_rather_than_being_dropped() {
    // RFC 3515 §2.4.4 owes the referrer the report, and nothing but this layer
    // knows that it is owed
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(
        &mut agent,
        &from_afar(&incoming_invite("far", Some(OFFER))),
        t0,
    );
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "farack", 1), t0);
    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "farrefer", 2),
            "Refer-To: <sip:carol@example.com>\r\n",
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the transfer is taken");
    let out = written(&mut agent);
    assert!(
        out.iter()
            .any(|(_, bytes)| bytes.starts_with(b"INVITE sip:carol")),
        "the call it asked for is placed: {:?}",
        listed(&out)
    );
    not_written(&out, "NOTIFY ");

    open_the_stream(&mut agent, t0);
    let notify = on_the_stream(&written(&mut agent), "NOTIFY ");
    assert!(body_of(&notify).starts_with("SIP/2.0 100"));
}

#[test]
fn the_bye_for_a_2xx_nobody_acknowledged_waits_for_the_stream() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(
        &mut agent,
        &from_afar(&incoming_invite("farnoack", Some(OFFER))),
        t0,
    );
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("the 200 goes");
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(33));
    not_written(&written(&mut agent), "BYE ");
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::Unreachable)
    );

    open_the_stream(&mut agent, t0 + Duration::from_secs(34));
    on_the_stream(&written(&mut agent), "BYE ");
}

#[test]
fn the_bye_for_a_session_that_ran_out_waits_for_the_stream() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &from_afar(&timed(&invite, Some(ANSWER), "600;refresher=uas")),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent.handle_timeout(t0 + Duration::from_secs(568));
    not_written(&written(&mut agent), "BYE ");
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::Expired)
    );

    // the ACK was waiting too, and goes first
    open_the_stream(&mut agent, t0 + Duration::from_secs(569));
    let out = written(&mut agent);
    on_the_stream(&out, "ACK ");
    on_the_stream(&out, "BYE ");
    let order: Vec<bool> = out
        .iter()
        .map(|(_, bytes)| bytes.starts_with(b"ACK "))
        .collect();
    assert_eq!(order, vec![true, false], "{:?}", listed(&out));
}

#[test]
fn a_hangup_this_layer_decided_on_waits_for_the_stream() {
    // the 200 crossed the CANCEL: §13.2.2.4 still wants the ACK, and the call
    // is ended after it, both on the stream once there is one
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
        &from_afar(&answered(&invite, 200, "OK", "desk", Some(ANSWER))),
        t0,
    );
    let out = written(&mut agent);
    not_written(&out, "ACK ");
    not_written(&out, "BYE ");
    assert_eq!(ended(&mut agent), None, "not over until the BYE has gone");

    open_the_stream(&mut agent, t0);
    let out = written(&mut agent);
    on_the_stream(&out, "ACK ");
    on_the_stream(&out, "BYE ");
    assert_eq!(
        ended(&mut agent).map(|(_, reason)| reason),
        Some(CallEndReason::LocalHangup)
    );
}

#[test]
fn a_change_offered_again_after_491_waits_for_the_stream_rather_than_failing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    open_the_stream(&mut agent, t0);
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &from_afar(&answered(&invite, 200, "OK", "desk", Some(ANSWER))),
        t0,
    );
    on_the_stream(&written(&mut agent), "ACK ");
    events(&mut agent);

    agent.hold(call, t0).expect("the re-INVITE goes");
    let reinvite = on_the_stream(&written(&mut agent), "INVITE ");
    stream(
        &mut agent,
        &answered(&reinvite, 491, "Request Pending", "desk", None),
        t0,
    );
    written(&mut agent);
    events(&mut agent);

    // the connection goes before §14.1's wait is over
    agent
        .receive(Input::StreamClosed { transport: TCP }, t0)
        .expect("the stream closes");
    written(&mut agent);
    events(&mut agent);

    let retry = t0 + Duration::from_secs(5);
    agent.handle_timeout(retry);
    not_written(&written(&mut agent), "INVITE ");
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::SessionChangeFailed { .. })),
        "a change not sent yet is not a change that failed"
    );

    open_the_stream(&mut agent, retry);
    let again = on_the_stream(&written(&mut agent), "INVITE ");
    assert!(body_of(&again).contains("a=sendonly\r\n"));
}

#[test]
fn a_refresh_too_big_for_a_datagram_waits_for_the_stream_and_the_subscription_stands() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    deliver(
        &mut agent,
        &from_afar(&notification(
            &subscribe,
            1,
            "notifier",
            "active;expires=3600",
            None,
        )),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    let due = t0 + Duration::from_secs(3_060);
    agent.handle_timeout(due);
    not_written(&written(&mut agent), "SUBSCRIBE ");
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::SubscriptionEnded { .. })),
        "a refresh not sent yet has not failed"
    );
    assert!(agent.subscription_state(handle).is_some());

    open_the_stream(&mut agent, due);
    on_the_stream(&written(&mut agent), "SUBSCRIBE ");
}

#[test]
fn a_dialog_that_ends_takes_what_was_waiting_to_be_sent_in_it() {
    // with no stream ever bound — a build that binds one transport and no
    // other — every call whose ACK outgrew the datagram would otherwise leave
    // one behind for the life of the process
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    let ok = from_afar(&answered(&invite, 200, "OK", "desk", Some(ANSWER)));
    deliver(&mut agent, &ok, t0);
    events(&mut agent);
    assert_eq!(agent.parked.len(), 1, "the ACK is waiting");

    // the far end gives up on it and hangs up
    let later = t0 + Duration::from_secs(32);
    deliver(&mut agent, &reversed(&ok, "BYE", "farbye", 2, None), later);
    assert_eq!(ended(&mut agent), Some((call, CallEndReason::RemoteHangup)));
    assert!(agent.parked.is_empty(), "{:?}", agent.parked);

    open_the_stream(&mut agent, later);
    not_written(&written(&mut agent), "ACK ");
}

/// How many times the endpoint asked for a connection.
fn connections_asked_for(seen: &[UaEvent]) -> usize {
    seen.iter()
        .filter(|event| {
            matches!(
                **event,
                UaEvent::Unclaimed(sipral_core::endpoint::Event::TransportWanted { .. })
            )
        })
        .count()
}

#[test]
fn a_2xx_repeated_after_a_lost_cancel_race_asks_for_no_second_connection() {
    // §13.2.2.4: the far end repeats its 200 until the ACK arrives, and the
    // endpoint reports each repeat for as long as no ACK is kept. The ACK and
    // the BYE that ends the call are already waiting for the stream; asking
    // for them again opens a connection per repeat
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

    let ok = from_afar(&answered(&invite, 200, "OK", "desk", Some(ANSWER)));
    deliver(&mut agent, &ok, t0);
    not_written(&written(&mut agent), "ACK ");
    assert_eq!(
        connections_asked_for(&events(&mut agent)),
        2,
        "one for the ACK, one for the BYE"
    );

    let later = t0 + Duration::from_millis(500);
    deliver(&mut agent, &ok, later);
    let out = written(&mut agent);
    not_written(&out, "ACK ");
    not_written(&out, "BYE ");
    assert_eq!(
        connections_asked_for(&events(&mut agent)),
        0,
        "both are already waiting for the connection asked for"
    );

    open_the_stream(&mut agent, later);
    let out = written(&mut agent);
    on_the_stream(&out, "ACK ");
    on_the_stream(&out, "BYE ");
}

#[test]
fn transfer_reports_waiting_for_a_stream_do_not_pile_up_behind_each_other() {
    // RFC 3515 §2.4.5: each NOTIFY body "provides a complete statement of the
    // status of the referred action", with no deltas, so one written later
    // says everything one still waiting would have. The referred call's far
    // end decides how many provisional responses there are, and none of them
    // may leave a report behind that nothing ever sends
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(
        &mut agent,
        &from_afar(&incoming_invite("far", Some(OFFER))),
        t0,
    );
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "farack", 1), t0);
    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "farrefer", 2),
            "Refer-To: <sip:carol@example.com>\r\n",
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the transfer is taken");
    let out = written(&mut agent);
    let placed = out
        .iter()
        .find(|(_, bytes)| bytes.starts_with(b"INVITE sip:carol"))
        .map(|(_, bytes)| bytes.clone())
        .expect("the call the transfer asked for");
    not_written(&out, "NOTIFY ");

    let ringing = answered(&placed, 180, "Ringing", "carol", None);
    for _ in 0..50 {
        deliver(&mut agent, &ringing, t0);
    }
    not_written(&written(&mut agent), "NOTIFY ");
    events(&mut agent);
    assert_eq!(agent.parked.len(), 1, "{:?}", agent.parked);

    open_the_stream(&mut agent, t0);
    let notify = on_the_stream(&written(&mut agent), "NOTIFY ");
    assert!(
        body_of(&notify).starts_with("SIP/2.0 180"),
        "the latest word on the transfer: {}",
        body_of(&notify)
    );
}

#[test]
fn a_second_transfers_report_waiting_for_a_stream_leaves_the_first_transfers_last_word() {
    // RFC 3515 §2.4.6: two REFERs in one dialog are two subscriptions, told
    // apart by the `id` on `Event`. A report on the second says nothing about
    // the first, whose closing NOTIFY (§2.4.7) is still owed
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = call_arriving(
        &mut agent,
        &from_afar(&incoming_invite("far", Some(OFFER))),
        t0,
    );
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "farack", 1), t0);
    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "farrefer", 2),
            "Refer-To: <sip:carol@example.com>\r\n",
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the first transfer is taken");
    let placed = written(&mut agent)
        .into_iter()
        .find(|(_, bytes)| bytes.starts_with(b"INVITE sip:carol"))
        .map(|(_, bytes)| bytes)
        .expect("the call the first transfer asked for");
    deliver(
        &mut agent,
        &answered(&placed, 486, "Busy Here", "carol", None),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    deliver(
        &mut agent,
        &plus(
            &in_dialog(&ok, "REFER", "farrefer2", 3),
            "Refer-To: <sip:dave@example.com>\r\n",
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    agent
        .accept_transfer(call, None, OutgoingExtras::default(), t0)
        .expect("the second transfer is taken");
    not_written(&written(&mut agent), "NOTIFY ");

    open_the_stream(&mut agent, t0);
    let bodies: Vec<String> = written(&mut agent)
        .iter()
        .filter(|(_, bytes)| bytes.starts_with(b"NOTIFY "))
        .map(|(_, bytes)| body_of(bytes))
        .collect();
    assert!(
        bodies.iter().any(|body| body.starts_with("SIP/2.0 486")),
        "the first transfer's last word: {bodies:?}"
    );
    assert!(
        bodies.iter().any(|body| body.starts_with("SIP/2.0 100")),
        "the second transfer's first: {bodies:?}"
    );
}

// -- the application's own header fields ---------------------------------------

fn conversation_id() -> HeaderName<'static> {
    HeaderName::Extension("X-Conversation-Id")
}

/// An INVITE that came in, and the call it became.
fn a_call_that_came_in(agent: &mut UserAgent, branch: &str, now: Instant) -> CallHandle {
    deliver(agent, &incoming_invite(branch, Some(OFFER)), now);
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
fn a_ring_and_an_answer_carry_the_fields_the_application_set() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = a_call_that_came_in(&mut agent, "labelled", t0);
    let asserted = HeaderName::Extension("P-Asserted-Identity");
    agent
        .respond_with_headers(
            call,
            &[
                (conversation_id(), &b"c-7"[..]),
                (asserted, &b"<sip:alice@example.com>"[..]),
            ],
        )
        .expect("two fields nothing else writes");

    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);
    assert_eq!(header(&ringing, conversation_id()), b"c-7");

    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    assert!(ok.starts_with(b"SIP/2.0 200 OK\r\n"));
    assert_eq!(
        header(&ok, conversation_id()),
        b"c-7",
        "kept for the 200, not spent on the 180"
    );
    assert_eq!(header(&ok, asserted), b"<sip:alice@example.com>");
}

#[test]
fn a_hangup_carries_the_fields_as_they_were_last_replaced() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = a_call_that_came_in(&mut agent, "relabelled", t0);
    let asserted = HeaderName::Extension("P-Asserted-Identity");
    agent
        .respond_with_headers(
            call,
            &[
                (conversation_id(), &b"c-7"[..]),
                (asserted, &b"<sip:alice@example.com>"[..]),
            ],
        )
        .expect("two fields nothing else writes");
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("200 goes");
    let ok = sent(&mut agent);
    deliver(&mut agent, &in_dialog(&ok, "ACK", "relabelledack", 1), t0);
    events(&mut agent);

    agent
        .respond_with_headers(call, &[(conversation_id(), &b"c-8"[..])])
        .expect("replaced");
    agent.hangup(call, t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    assert!(bye.starts_with(b"BYE "));
    assert_eq!(header(&bye, conversation_id()), b"c-8");
    assert!(
        header(&bye, asserted).is_empty(),
        "replaced whole rather than merged"
    );
}

#[test]
fn a_refusal_carries_the_fields_the_application_set() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = a_call_that_came_in(&mut agent, "refusedlabel", t0);
    agent
        .respond_with_headers(call, &[(conversation_id(), &b"c-7"[..])])
        .expect("set");
    agent
        .reject(call, StatusCode::BUSY_HERE, t0)
        .expect("486 goes");
    let busy = sent(&mut agent);
    assert!(busy.starts_with(b"SIP/2.0 486"));
    assert_eq!(header(&busy, conversation_id()), b"c-7");
}

#[test]
fn a_hold_carries_the_fields_the_application_set_on_its_re_invite() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);
    agent
        .respond_with_headers(call, &[(conversation_id(), &b"c-7"[..])])
        .expect("set");
    agent.hold(call, t0).expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
    assert!(reinvite.starts_with(b"INVITE "));
    assert_eq!(header(&reinvite, conversation_id()), b"c-7");
}

#[test]
fn a_forked_siblings_hold_carries_the_fields_staged_before_the_fork() {
    // §13.2.2: one INVITE can open several dialogs; a sibling minted for a
    // later branch is still the same labelled call, not a blank one
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let first = agent
        .call(id, &outgoing().forks(ForkPolicy::KeepAll), t0)
        .expect("the INVITE goes");
    agent
        .respond_with_headers(first, &[(conversation_id(), &b"c-7"[..])])
        .expect("set before either branch answered");
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
    transmits(&mut agent);
    let sibling = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallConfirmed { call, .. } if call != first => Some(call),
            _ => None,
        })
        .expect("the second branch is a sibling of its own");

    agent.hold(sibling, t0).expect("the re-INVITE goes");
    let reinvite = sent(&mut agent);
    assert!(reinvite.starts_with(b"INVITE "));
    assert_eq!(
        header(&reinvite, conversation_id()),
        b"c-7",
        "a branch minted after the fields were staged carries them too"
    );
}

#[test]
fn a_refresh_offered_again_after_491_carries_none_of_the_applications_fields() {
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
    agent
        .respond_with_headers(call, &[(conversation_id(), &b"c-7"[..])])
        .expect("set");

    // RFC 4028 §7.2: the refresher keeps the session alive by itself, with a
    // re-INVITE when the far end never allowed UPDATE
    let due = t0 + Duration::from_secs(300);
    agent.handle_timeout(due);
    let refresh = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the refresh");
    assert!(header(&refresh, conversation_id()).is_empty());
    events(&mut agent);

    // RFC 3261 §14.1: a 491 is tried once more, and it is still the refresh
    deliver(
        &mut agent,
        &answered(&refresh, 491, "Request Pending", "desk", None),
        due,
    );
    transmits(&mut agent);
    let wait = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::SessionChangeFailed { retry_in, .. } => retry_in,
            _ => None,
        })
        .expect("491 says to wait and try again");
    agent.handle_timeout(due + wait);
    let again = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the refresh goes out again");
    assert!(
        header(&again, conversation_id()).is_empty(),
        "a refresh the stack sent by itself is not the application speaking, the second time either"
    );
}

#[test]
fn a_bye_this_layer_sends_by_itself_carries_none_of_the_applications_fields() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    agent
        .respond_with_headers(call, &[(conversation_id(), &b"c-7"[..])])
        .expect("set");

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
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    // the mobile answers too, and loses: acknowledged, and hung up by this
    // layer on its own
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "mobile", Some(ANSWER)),
        t0,
    );
    let out = transmits(&mut agent);
    let bye = out
        .iter()
        .find(|bytes| bytes.starts_with(b"BYE "))
        .expect("the branch that lost is hung up");
    assert!(
        header(bye, conversation_id()).is_empty(),
        "a hangup nobody asked for is not the application speaking"
    );
}

#[test]
fn a_field_the_stack_writes_is_refused_on_a_call_before_anything_is_built() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    for (name, value) in [
        (HeaderName::Contact, &b"<sip:elsewhere@example.net>"[..]),
        (HeaderName::SessionExpires, &b"90"[..]),
    ] {
        let refused = agent.call(id, &outgoing().header(name, value), t0);
        assert_eq!(
            refused,
            Err(UaError::Header(crate::HeaderRefused::WrittenByTheStack(
                name.canonical()
            )))
        );
        assert!(
            transmits(&mut agent).is_empty(),
            "{name}: nothing was built"
        );
    }
    // a compact name is the field it abbreviates (RFC 3261 §7.3.3)
    assert_eq!(
        crate::HeadersFor::Call.check(b"m", b"<sip:elsewhere@example.net>"),
        Err(crate::HeaderRefused::WrittenByTheStack("Contact"))
    );
}

#[test]
fn a_refused_replacement_keeps_the_fields_that_were_set_before() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = a_call_that_came_in(&mut agent, "keptlabel", t0);
    agent
        .respond_with_headers(call, &[(conversation_id(), &b"c-7"[..])])
        .expect("set");
    let refused = agent.respond_with_headers(
        call,
        &[
            (conversation_id(), &b"c-8"[..]),
            (HeaderName::Allow, &b"INVITE, BYE"[..]),
        ],
    );
    assert_eq!(
        refused,
        Err(UaError::Header(crate::HeaderRefused::WrittenByTheStack(
            "Allow"
        )))
    );

    agent.ring(call, None, t0).expect("180 goes");
    let ringing = sent(&mut agent);
    assert_eq!(
        header(&ringing, conversation_id()),
        b"c-7",
        "a refusal keeps none of the new fields"
    );
    assert_eq!(
        with(&ringing, |message| message.header_count(HeaderName::Allow)),
        1,
        "and the stack's Allow is the only one"
    );
}

#[test]
fn a_field_the_stack_writes_on_a_register_is_refused_and_is_the_applications_on_an_invite() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().header(HeaderName::Expires, b"60"));
    assert_eq!(
        agent.register(id, t0),
        Err(UaError::Header(crate::HeaderRefused::WrittenByTheStack(
            "Expires"
        )))
    );
    assert!(transmits(&mut agent).is_empty(), "nothing was built");

    // on an INVITE it limits how long the invitation stands (§13.2.1), and
    // nothing here writes one
    agent
        .call(id, &outgoing().header(HeaderName::Expires, b"30"), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert_eq!(header(&invite, HeaderName::Expires), b"30");
}

#[test]
fn a_value_that_would_break_the_line_is_refused() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let call = a_call_that_came_in(&mut agent, "brokenlabel", t0);
    let refused = agent.respond_with_headers(
        call,
        &[(
            conversation_id(),
            &b"c-7\r\nContact: <sip:elsewhere@example.net>"[..],
        )],
    );
    assert_eq!(
        refused,
        Err(UaError::Header(crate::HeaderRefused::ControlByte {
            offset: 3
        }))
    );
    assert_eq!(
        crate::HeadersFor::Call.check(b"X-Conversation-Id", b"c\x007"),
        Err(crate::HeaderRefused::ControlByte { offset: 1 })
    );
    assert_eq!(
        crate::HeadersFor::Call.check(b"X-Conversation-Id", b"c\t7"),
        Ok(conversation_id()),
        "a tab is whitespace"
    );
}

#[test]
fn a_name_that_is_not_a_token_is_refused() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let refused = agent.call(
        id,
        &outgoing().header(HeaderName::Extension("X-Two Words"), b"1"),
        t0,
    );
    assert_eq!(
        refused,
        Err(UaError::Header(crate::HeaderRefused::NotAName))
    );
    assert!(transmits(&mut agent).is_empty());
    assert_eq!(
        crate::HeadersFor::Call.check(b"X-Colon:", b"1"),
        Err(crate::HeaderRefused::NotAName)
    );
}

// -- DTMF by SIP INFO (8.3.11) -----------------------------------------------

#[test]
fn a_refusal_of_the_info_reaches_the_application_named_with_the_digit_and_the_status() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "5", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the INFO goes");
    let info = sent(&mut agent);
    assert!(String::from_utf8_lossy(&info).starts_with("INFO "));
    assert_eq!(
        header(&info, HeaderName::ContentType),
        b"application/dtmf-relay"
    );

    deliver(
        &mut agent,
        &reply(&info, 415, "Unsupported Media Type", ""),
        t0,
    );
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent {
                call: reported,
                digit: '5',
                status,
            } if reported == call && status.get() == 415
        )),
        "{seen:?}"
    );
}

#[test]
fn a_success_of_the_info_is_also_reported_as_dtmf_sent() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "#", crate::DtmfInfoForm::Plain, 0, t0)
        .expect("the INFO goes");
    let info = sent(&mut agent);
    assert_eq!(header(&info, HeaderName::ContentType), b"application/dtmf");
    assert!(body_of(&info).ends_with('#'), "{}", body_of(&info));

    deliver(&mut agent, &reply(&info, 200, "OK", ""), t0);
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent {
                call: reported,
                digit: '#',
                status,
            } if reported == call && status.get() == 200
        )),
        "{seen:?}"
    );
}

#[test]
fn an_incoming_relay_and_an_incoming_plain_info_are_each_reported_as_a_received_digit() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &incoming_info(
            &ack,
            "relayin",
            51,
            Some("application/dtmf-relay"),
            b"Signal=7\r\nDuration=200\r\n",
        ),
        t0,
    );
    let answer = sent(&mut agent);
    assert!(String::from_utf8_lossy(&answer).starts_with("SIP/2.0 200 OK"));
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfReceived {
                call: reported,
                digit: '7',
                held_ms: Some(200),
            } if reported == call
        )),
        "{seen:?}"
    );

    deliver(
        &mut agent,
        &incoming_info(&ack, "plainin", 52, Some("application/dtmf"), b"9"),
        t0,
    );
    let answer = sent(&mut agent);
    assert!(String::from_utf8_lossy(&answer).starts_with("SIP/2.0 200 OK"));
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfReceived {
                call: reported,
                digit: '9',
                held_ms: None,
            } if reported == call
        )),
        "{seen:?}"
    );
}

/// 8.3.11-bis(c): a peer that held a key for no time at all said so, and
/// this end used to report the hundred-millisecond default in its place —
/// the same mistake `duration_ms` makes on purpose for a length nobody
/// asked to send, applied to a length the peer did name.
#[test]
fn a_received_duration_of_zero_is_reported_as_zero_not_the_default() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &incoming_info(
            &ack,
            "zeroin",
            51,
            Some("application/dtmf-relay"),
            b"Signal=6\r\nDuration=0\r\n",
        ),
        t0,
    );
    let answer = sent(&mut agent);
    assert!(String::from_utf8_lossy(&answer).starts_with("SIP/2.0 200 OK"));
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfReceived {
                call: reported,
                digit: '6',
                held_ms: Some(0),
            } if reported == call
        )),
        "{seen:?}"
    );
}

/// 8.3.11-bis(a): only `application/dtmf-relay` and `application/dtmf` are
/// read as a digit. Every other INFO reaches the application unanswered —
/// but only once it has said it answers them itself: see the next test for
/// what happens when it has not.
#[test]
fn a_content_type_neither_form_uses_reaches_an_application_that_asked_unanswered() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.hand_over_info(true);
    let id = agent.add_account(account());
    let (_call, ack) = call_up(&mut agent, id, t0);

    deliver(
        &mut agent,
        &incoming_info(&ack, "wrongtype", 51, Some("application/sdp"), b"v=0\r\n"),
        t0,
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "a body this stack does not read is not this stack's to answer"
    );
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            UaEvent::Unclaimed(Event::IncomingInDialog { request, .. })
                if request.as_raw().method() == Some(Method::Info)
        )),
        "the INFO should reach the application unclaimed: {seen:?}"
    );
    assert!(
        seen.iter()
            .all(|event| !matches!(event, UaEvent::DtmfReceived { .. })),
        "nothing is reported for a body this stack never read"
    );
}

/// An INFO this agent does not read as a digit is answered by RFC 6086
/// §4.2.2 rather than left for an application with no way to answer it: a
/// peer whose INFO is never answered retransmits it for thirty-two seconds
/// and then, by RFC 3261 §12.2.1.2, ends the call.
#[test]
fn an_info_that_is_not_dtmf_is_answered_by_the_info_framework() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_call, ack) = call_up(&mut agent, id, t0);

    // legacy usage with a body this agent cannot read: 415, and the Accept
    // names the two forms it does
    deliver(
        &mut agent,
        &incoming_info(
            &ack,
            "mediactl",
            51,
            Some("application/media_control+xml"),
            b"<media_control/>",
        ),
        t0,
    );
    let answer = last(&mut agent);
    assert!(
        answer.starts_with(b"SIP/2.0 415 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(
        header(&answer, HeaderName::Accept),
        b"application/dtmf-relay, application/dtmf"
    );

    // no body at all, which some equipment sends to see the call is there:
    // "the UA MUST send a 200 (OK) response"
    deliver(&mut agent, &incoming_info(&ack, "bare", 52, None, b""), t0);
    assert!(last(&mut agent).starts_with(b"SIP/2.0 200 "));

    // an Info Package this agent never said it would take: 469, with the
    // (empty) list of the ones it would
    let packaged = plus(
        &incoming_info(&ack, "package", 53, Some("application/foo"), b"x"),
        "Info-Package: foo\r\n",
    );
    deliver(&mut agent, &packaged, t0);
    let answer = last(&mut agent);
    assert!(
        answer.starts_with(b"SIP/2.0 469 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        String::from_utf8_lossy(&answer).contains("\r\nRecv-Info: \r\n"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::Unclaimed(_))),
        "nothing answered here is also handed on"
    );
}

#[test]
fn a_request_inside_a_call_that_nothing_here_takes_is_answered_rather_than_left() {
    // RFC 5057 §5.3 matches each to a usage, and §5.1 says which answer
    // costs no more than the transaction: 405 with Allow for what this agent
    // recognises and does not take, 501 for what it does not recognise
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_call, ack) = call_up(&mut agent, id, t0);

    for (method, cseq, status) in [
        ("SUBSCRIBE", 60, "405"),
        ("PUBLISH", 61, "405"),
        ("FROBNICATE", 62, "501"),
    ] {
        let request = plus(
            &reversed(&ack, method, &format!("unclaimed{cseq}"), cseq, None),
            "Event: presence\r\n",
        );
        deliver(&mut agent, &request, t0);
        let answer = last(&mut agent);
        assert!(
            answer.starts_with(format!("SIP/2.0 {status} ").as_bytes()),
            "{method}: {}",
            String::from_utf8_lossy(&answer)
        );
        if status == "405" {
            assert!(
                String::from_utf8_lossy(&header(&answer, HeaderName::Allow)).contains("INVITE"),
                "{method}"
            );
        }
    }
    // and an OPTIONS inside the call is answered as one outside it is (§11.2)
    deliver(
        &mut agent,
        &reversed(&ack, "OPTIONS", "inside", 63, None),
        t0,
    );
    let answer = last(&mut agent);
    assert!(answer.starts_with(b"SIP/2.0 200 "));
    assert!(!header(&answer, HeaderName::Allow).is_empty());
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::Unclaimed(_))),
        "nothing answered here is also handed on"
    );
}

#[test]
fn an_invite_usage_request_in_a_subscriptions_dialog_is_481() {
    // RFC 5057 §5.3: "A dialog can have at most one invite usage, so any
    // INVITE, UPDATE, PRACK, ACK, CANCEL, BYE, or INFO requests belong to
    // it", and a subscription's dialog has none: 481 ends that usage, which
    // does not exist, and nothing else (§5.1)
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_handle, subscribe) = subscribed(&mut agent, id, t0);
    let from = format!("{};tag=notifier", text(&subscribe, HeaderName::To));
    let to = text(&subscribe, HeaderName::From);
    let call_id = text(&subscribe, HeaderName::CallId);

    for (method, cseq, status) in [
        ("UPDATE", 70, "481"),
        ("INFO", 71, "481"),
        ("REFER", 72, "403"),
    ] {
        deliver(
            &mut agent,
            &peer_request(
                &from,
                &to,
                &call_id,
                method,
                &format!("sub{cseq}"),
                cseq,
                None,
            ),
            t0,
        );
        let answer = last(&mut agent);
        assert!(
            answer.starts_with(format!("SIP/2.0 {status} ").as_bytes()),
            "{method}: {}",
            String::from_utf8_lossy(&answer)
        );
    }
    deliver(
        &mut agent,
        &peer_request(&from, &to, &call_id, "INVITE", "subinvite", 73, Some(OFFER)),
        t0,
    );
    assert!(
        transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 481 ")),
        "a re-INVITE in a dialog with no call is answered too"
    );
}

#[test]
fn a_malformed_relay_body_is_400_and_reports_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_call, ack) = call_up(&mut agent, id, t0);

    // no Signal= at all, which names no digit
    deliver(
        &mut agent,
        &incoming_info(
            &ack,
            "malformed",
            51,
            Some("application/dtmf-relay"),
            b"Duration=160\r\n",
        ),
        t0,
    );
    let answer = sent(&mut agent);
    assert!(
        String::from_utf8_lossy(&answer).starts_with("SIP/2.0 400 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::DtmfReceived { .. })),
        "nothing is reported for a body that names no digit"
    );
}

#[test]
fn an_oversized_body_is_400_and_reports_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_call, ack) = call_up(&mut agent, id, t0);

    // large enough to be nothing this convention ever carries, and comfortably
    // inside the message-size limit parsing enforces beneath this layer, so
    // it is this parser's own bound that is being exercised here rather than
    // the transport's
    let huge = vec![b'5'; 8_192];
    deliver(
        &mut agent,
        &incoming_info(&ack, "huge", 51, Some("application/dtmf"), &huge),
        t0,
    );
    let answer = sent(&mut agent);
    assert!(
        String::from_utf8_lossy(&answer).starts_with("SIP/2.0 400 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::DtmfReceived { .. }))
    );
}

#[test]
fn an_invalid_digit_or_duration_is_refused_before_anything_is_sent() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    assert_eq!(
        agent.send_dtmf_info(call, "E", crate::DtmfInfoForm::Relay, 0, t0),
        Err(UaError::InvalidDtmf(crate::DtmfError::UnknownDigit))
    );
    assert_eq!(
        agent.send_dtmf_info(call, "5", crate::DtmfInfoForm::Relay, 10_001, t0),
        Err(UaError::InvalidDtmf(crate::DtmfError::ToneTooLong(10_001)))
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "a refused digit or duration sends nothing"
    );
}

#[test]
fn a_401_challenge_to_the_info_still_reports_dtmf_sent_on_the_retry() {
    // the retry is a new transaction, so the digit it carries has to follow
    // it there too, or a PBX that challenges mid-dialog requests would leave
    // every INFO's answer unreported
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "3", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the INFO goes");
    let first = only(&transmits(&mut agent), "INFO ");
    deliver(&mut agent, &unauthorized(&first), t0);
    events(&mut agent);

    let retry = only(&transmits(&mut agent), "INFO ");
    credentials_of(&retry, HeaderName::Authorization);
    deliver(&mut agent, &reply(&retry, 200, "OK", ""), t0);
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent {
                call: reported,
                digit: '3',
                status,
            } if reported == call && status.get() == 200
        )),
        "the digit followed the retried transaction: {seen:?}"
    );
}

#[test]
fn an_info_nobody_answers_reaches_the_application_as_a_408() {
    // RFC 3261 §8.1.3.1: "When a timeout error is received from the
    // transaction layer, it MUST be treated as if a 408 (Request Timeout)
    // status code has been received"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "5", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the INFO goes");
    only(&transmits(&mut agent), "INFO ");
    events(&mut agent);

    // past Timer F, 64·T1 (§17.1.2.2), with nothing back
    let later = t0 + Duration::from_secs(33);
    agent.handle_timeout(later);
    transmits(&mut agent);
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent {
                call: reported,
                digit: '5',
                status,
            } if reported == call && status.get() == 408
        )),
        "{seen:?}"
    );
}

#[test]
fn an_info_challenged_on_an_account_with_no_password_reaches_the_application_as_its_401() {
    // nothing can answer the challenge, so the 401 is the last word on this
    // digit, and it is as much the application's news as a 415 would be
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "9", crate::DtmfInfoForm::Plain, 0, t0)
        .expect("the INFO goes");
    let info = only(&transmits(&mut agent), "INFO ");
    deliver(&mut agent, &unauthorized(&info), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "there is no password, so nothing goes again"
    );
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent {
                call: reported,
                digit: '9',
                status,
            } if reported == call && status.get() == 401
        )),
        "{seen:?}"
    );
}

#[test]
fn an_info_whose_transport_failed_reaches_the_application_as_a_503() {
    // RFC 3261 §8.1.3.1: a fatal transport error "MUST be treated as a 503
    // (Service Unavailable) status code"
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "1", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the INFO goes");
    only(&transmits(&mut agent), "INFO ");
    events(&mut agent);

    agent
        .receive(
            Input::TransportFailed {
                transport: UDP,
                error: sipral_core::endpoint::TransportErrorKind::Unreachable,
            },
            t0,
        )
        .expect("the failure is taken");
    transmits(&mut agent);
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent {
                call: reported,
                digit: '1',
                status,
            } if reported == call && status.get() == 503
        )),
        "{seen:?}"
    );
}

// -- a string of digits, one INFO at a time (8.3.11-bis(b)) ------------------

/// The whole point: over UDP, overlapping non-INVITE transactions can arrive
/// in any order, so the second and third digit must not go out until the one
/// ahead of them has a final answer.
#[test]
fn a_string_of_digits_goes_out_one_info_at_a_time() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "1#D", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the string is accepted");
    // only the first digit went; the transmit queue would carry a second one
    // if the whole string had been sent at once
    let first = sent(&mut agent);
    assert!(body_of(&first).contains("Signal=1"), "{}", body_of(&first));
    assert!(
        events(&mut agent).is_empty(),
        "nothing has answered the first digit yet"
    );

    deliver(&mut agent, &reply(&first, 200, "OK", ""), t0);
    let second = sent(&mut agent);
    assert!(
        body_of(&second).contains("Signal=#"),
        "{}",
        body_of(&second)
    );
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent { digit: '1', status, .. } if status.get() == 200
        )),
        "{seen:?}"
    );

    deliver(&mut agent, &reply(&second, 200, "OK", ""), t0);
    let third = sent(&mut agent);
    assert!(body_of(&third).contains("Signal=D"), "{}", body_of(&third));
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent { digit: '#', status, .. } if status.get() == 200
        )),
        "{seen:?}"
    );

    deliver(&mut agent, &reply(&third, 200, "OK", ""), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "there was nothing left to send after the third digit"
    );
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent { digit: 'D', status, .. } if status.get() == 200
        )),
        "{seen:?}"
    );
}

/// A non-2xx anywhere in the middle ends the sequence there: the digits still
/// waiting are discarded rather than sent out of order.
#[test]
fn a_refusal_mid_string_discards_the_digits_still_waiting() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "123", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the string is accepted");
    let first = sent(&mut agent);
    events(&mut agent);

    deliver(&mut agent, &reply(&first, 200, "OK", ""), t0);
    let second = sent(&mut agent);
    events(&mut agent);

    deliver(&mut agent, &reply(&second, 486, "Busy Here", ""), t0);
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent { digit: '2', status, .. } if status.get() == 486
        )),
        "the digit that ended the sequence is what names it: {seen:?}"
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "a 486 on the second digit means the third is never sent"
    );
}

/// The far end answering the digit ahead of it is not the only way a queued
/// digit's own INFO never goes out: `request_in_dialog` can refuse the
/// dialog's own request too, and until now nothing told the application that
/// digit was ever attempted.
///
/// The dialog is cleared by hand between the two, rather than through a
/// message: it stands for whatever `request_in_dialog` would refuse the
/// second digit's own send for, and no sequence of wire messages makes that
/// send fail while leaving the first digit's own answer untouched, since the
/// second is attempted synchronously while the first's answer is still being
/// handled.
#[test]
fn a_digit_whose_own_send_fails_is_reported_undelivered_and_the_rest_are_dropped() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "123", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the string is accepted");
    let first = sent(&mut agent);
    events(&mut agent);

    agent.calls.get_mut(&call).expect("the call").dialog = None;

    deliver(&mut agent, &reply(&first, 200, "OK", ""), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "the second digit could not go out, so the third never gets a turn"
    );
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent { digit: '1', status, .. } if status.get() == 200
        )),
        "the first digit's own answer is unaffected: {seen:?}"
    );
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent { digit: '2', status, .. } if status.get() == 503
        )),
        "the digit that could not be sent is 503, the status a request that \
         could not even go out already stands for (RFC 3261 §8.1.3.1): {seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|event| matches!(*event, UaEvent::DtmfSent { digit: '3', .. })),
        "the third digit was never attempted: {seen:?}"
    );
}

/// The whole string is validated before anything goes out: one bad character
/// anywhere refuses the call and sends nothing, not even the keys ahead of
/// it.
#[test]
fn an_invalid_character_anywhere_in_the_string_sends_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    assert_eq!(
        agent.send_dtmf_info(call, "12E4", crate::DtmfInfoForm::Relay, 0, t0),
        Err(UaError::InvalidDtmf(crate::DtmfError::UnknownDigit))
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "a bad character anywhere in the string refuses the whole of it"
    );
}

/// 8.3.11-ter(e): only the application can grow a call's DTMF queue, by
/// handing over strings faster than the far end answers, so sixty-four —
/// the one in flight and everything waiting behind it — is as far as one
/// call's queue goes.
#[test]
fn a_call_holding_sixty_four_digits_refuses_a_sixty_fifth() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "1", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the first digit goes at once");
    sent(&mut agent);
    events(&mut agent);

    let sixty_three_more = "2".repeat(63);
    agent
        .send_dtmf_info(call, &sixty_three_more, crate::DtmfInfoForm::Relay, 0, t0)
        .expect("one in flight and sixty-three waiting is sixty-four in all");
    assert!(
        transmits(&mut agent).is_empty(),
        "every one of the sixty-three waits behind the first"
    );

    assert_eq!(
        agent.send_dtmf_info(call, "9", crate::DtmfInfoForm::Relay, 0, t0),
        Err(UaError::InvalidDtmf(crate::DtmfError::UnknownDigit)),
        "a sixty-fifth takes the call's queue past sixty-four"
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "nothing of the refused digit went out"
    );

    // the same refusal on a call holding nothing yet: a string longer than
    // the queue could ever hold sends not even its first character
    let (other, _ack) = call_up(&mut agent, id, t0);
    let too_long = "3".repeat(65);
    assert_eq!(
        agent.send_dtmf_info(other, &too_long, crate::DtmfInfoForm::Relay, 0, t0),
        Err(UaError::InvalidDtmf(crate::DtmfError::UnknownDigit))
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "a string too long for the queue to ever hold is refused before any of it is sent"
    );
}

/// A string handed over while a digit of an earlier one still waits for its
/// answer goes behind it. A keypad that hands over one key per press is the
/// ordinary case, and an INFO sent the moment its key was pressed would
/// overlap the one ahead of it and could arrive first. Each key keeps the
/// body it was asked for, and once the last answer is in, nothing is left
/// for the next key to wait behind.
#[test]
fn a_string_handed_over_while_a_digit_is_in_flight_waits_behind_it() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "12", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the first string is accepted");
    let first = sent(&mut agent);
    assert!(body_of(&first).contains("Signal=1"), "{}", body_of(&first));

    agent
        .send_dtmf_info(call, "3", crate::DtmfInfoForm::Plain, 0, t0)
        .expect("the second string is accepted");
    assert!(
        transmits(&mut agent).is_empty(),
        "the second string went out while the first digit was still unanswered"
    );

    deliver(&mut agent, &reply(&first, 200, "OK", ""), t0);
    let second = sent(&mut agent);
    assert!(
        body_of(&second).contains("Signal=2"),
        "{}",
        body_of(&second)
    );

    deliver(&mut agent, &reply(&second, 200, "OK", ""), t0);
    let third = sent(&mut agent);
    assert_eq!(header(&third, HeaderName::ContentType), b"application/dtmf");
    assert_eq!(body_of(&third), "3");

    deliver(&mut agent, &reply(&third, 200, "OK", ""), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "there was nothing left to send after the third digit"
    );
    events(&mut agent);

    agent
        .send_dtmf_info(call, "4", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("a key pressed later is accepted");
    let fourth = sent(&mut agent);
    assert!(
        body_of(&fourth).contains("Signal=4"),
        "{}",
        body_of(&fourth)
    );
}

/// A sequence a refusal or a timeout ended leaves nothing behind for a later
/// key to wait for: the next one goes out at once.
#[test]
fn a_key_pressed_after_a_sequence_ended_goes_out_at_once() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "56", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the string is accepted");
    let refused = sent(&mut agent);
    deliver(&mut agent, &reply(&refused, 486, "Busy Here", ""), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "the digit behind a refusal is discarded"
    );
    events(&mut agent);

    agent
        .send_dtmf_info(call, "7", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("a key after a refusal is accepted");
    let unanswered = sent(&mut agent);
    assert!(
        body_of(&unanswered).contains("Signal=7"),
        "{}",
        body_of(&unanswered)
    );

    // past Timer F, 64·T1 (§17.1.2.2), with nothing back
    let later = t0 + Duration::from_secs(33);
    agent.handle_timeout(later);
    transmits(&mut agent);
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::DtmfSent { digit: '7', status, .. } if status.get() == 408
        )),
        "{seen:?}"
    );

    agent
        .send_dtmf_info(call, "8", crate::DtmfInfoForm::Relay, 0, later)
        .expect("a key after a timeout is accepted");
    let after = sent(&mut agent);
    assert!(body_of(&after).contains("Signal=8"), "{}", body_of(&after));
}

/// 8.3.11-bis(d): one default, a hundred milliseconds, for a digit sent by
/// INFO without a length of its own.
#[test]
fn an_info_sent_without_a_duration_carries_the_hundred_millisecond_default() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);

    agent
        .send_dtmf_info(call, "5", crate::DtmfInfoForm::Relay, 0, t0)
        .expect("the INFO goes");
    let info = sent(&mut agent);
    assert!(
        body_of(&info).contains("Duration=100"),
        "{}",
        body_of(&info)
    );
}

#[test]
fn an_oversized_relay_body_is_400_even_when_it_names_a_digit() {
    // a good Signal= on top of kilobytes of padding: the plain form's
    // one-character rule refuses an oversized body of its own by accident,
    // and nothing refused the relay form's
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (_call, ack) = call_up(&mut agent, id, t0);

    let mut huge = b"Signal=5\r\nDuration=160\r\n".to_vec();
    huge.resize(8_192, b' ');
    deliver(
        &mut agent,
        &incoming_info(&ack, "hugerelay", 51, Some("application/dtmf-relay"), &huge),
        t0,
    );
    let answer = sent(&mut agent);
    assert!(
        String::from_utf8_lossy(&answer).starts_with("SIP/2.0 400 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::DtmfReceived { .. })),
        "nothing is reported for a body no one digit needs"
    );
}

/// 8.3.11-bis(a): an INFO with no `Content-Type` names no body this stack
/// reads either, so an application that said it answers the INFOs this
/// stack does not read gets it unanswered, and gives RFC 6086 §4.2.2's 200
/// itself. Without that, this layer gives it
/// (`an_info_that_is_not_dtmf_is_answered_by_the_info_framework`).
#[test]
fn an_info_with_no_body_at_all_reaches_an_application_that_asked_unanswered() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.hand_over_info(true);
    let id = agent.add_account(account());
    let (_call, ack) = call_up(&mut agent, id, t0);

    deliver(&mut agent, &incoming_info(&ack, "empty", 51, None, b""), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "an INFO with no body this stack reads is not this stack's to answer"
    );
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            UaEvent::Unclaimed(Event::IncomingInDialog { request, .. })
                if request.as_raw().method() == Some(Method::Info)
        )),
        "the INFO should reach the application unclaimed: {seen:?}"
    );
    assert!(
        seen.iter()
            .all(|event| !matches!(event, UaEvent::DtmfReceived { .. })),
        "an INFO with no body names no digit"
    );
}

// -- MESSAGE (RFC 3428) -------------------------------------------------

/// An out-of-dialog MESSAGE addressed to this account's line, as a far end
/// would send it.
fn incoming_message(content_type: &str, body: &[u8], branch: &str) -> Vec<u8> {
    let mut out = format!(
        "MESSAGE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch}\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag={branch}\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: msg-{branch}\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Type: {content_type}\r\n\
Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[test]
fn an_out_of_dialog_message_carries_no_contact_and_reports_a_200() {
    // §4: "User Agents MUST NOT insert Contact header fields into MESSAGE
    // requests." §7: a 200 means this end delivered it.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .message(id, uri("sip:bob@example.com"), b"text/plain", b"hello", t0)
        .expect("the MESSAGE goes");
    let request = only(&transmits(&mut agent), "MESSAGE ");
    assert!(header(&request, HeaderName::Contact).is_empty());
    assert_eq!(header(&request, HeaderName::To), b"<sip:bob@example.com>");

    deliver(&mut agent, &reply(&request, 200, "OK", ""), t0);
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::MessageSent { message, status, .. }
                if message == handle && status == StatusCode::OK
        )),
        "{seen:?}"
    );
}

#[test]
fn a_202_from_a_relay_is_told_apart_from_a_200() {
    // §4: "If the UAC receives a 202 Accepted response, the message has been
    // delivered to a gateway, store and forward server, or some other
    // service that may eventually deliver the message."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .message(id, uri("sip:bob@example.com"), b"text/plain", b"hi", t0)
        .expect("the MESSAGE goes");
    let request = only(&transmits(&mut agent), "MESSAGE ");
    deliver(&mut agent, &reply(&request, 202, "Accepted", ""), t0);
    let seen = events(&mut agent);
    assert!(seen.iter().any(|event| matches!(
        *event,
        UaEvent::MessageSent { status, .. } if status.get() == 202
    )));
}

#[test]
fn a_timed_out_message_is_reported_with_408() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .message(id, uri("sip:bob@example.com"), b"text/plain", b"hi", t0)
        .expect("the MESSAGE goes");
    transmits(&mut agent);
    agent.handle_timeout(t0 + Duration::from_secs(64));
    let seen = events(&mut agent);
    assert!(seen.iter().any(|event| matches!(
        *event,
        UaEvent::MessageSent { status, .. } if status == StatusCode::REQUEST_TIMEOUT
    )));
}

#[test]
fn a_second_out_of_dialog_message_to_the_same_target_is_refused_while_the_first_is_pending() {
    // §8: "A UAC MUST NOT initiate a new out-of-dialog MESSAGE transaction to
    // a given URI if there is a previous out-of-dialog transaction pending
    // for the same URI."
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .message(id, uri("sip:bob@example.com"), b"text/plain", b"one", t0)
        .expect("the first MESSAGE goes");
    assert_eq!(
        agent.message(id, uri("sip:bob@example.com"), b"text/plain", b"two", t0),
        Err(UaError::MessagePending)
    );
    // a different target is unaffected
    assert!(
        agent
            .message(id, uri("sip:carol@example.com"), b"text/plain", b"two", t0)
            .is_ok()
    );
}

#[test]
fn a_body_over_the_udp_ceiling_is_refused_unless_the_transport_is_congestion_controlled() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let big = vec![b'x'; 1301];
    let plain = agent.add_account(account());
    assert_eq!(
        agent.message(plain, uri("sip:bob@example.com"), b"text/plain", &big, t0),
        Err(UaError::MessageTooLarge {
            size: 1301,
            limit: 1300,
        })
    );

    // the account's own transport now actually is a byte stream, not just
    // told it is one, so the ceiling this policy lifts is the only thing
    // standing between the send and the wire
    let (mut agent, _) = over_tcp(t0);
    let tcp = agent.add_account(
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1"),
            TCP,
            registrar(),
        )
        .transport_protocol(TransportProtocol::Tcp),
    );
    assert!(
        agent
            .message(tcp, uri("sip:bob@example.com"), b"text/plain", &big, t0)
            .is_ok(),
        "a congestion-controlled transport is not held to 8's ceiling"
    );
}

#[test]
fn an_incoming_message_is_answered_200_and_delivered_whole() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let account_id = agent.add_account(account());
    deliver(
        &mut agent,
        &incoming_message("text/plain", b"hi there", "m1"),
        t0,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(answer.starts_with(b"SIP/2.0 200 "));
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            UaEvent::MessageReceived { account: Some(id), call: None, request }
                if *id == account_id && request.as_raw().body() == b"hi there"
        )),
        "{seen:?}"
    );
}

#[test]
fn a_content_type_nobody_declared_is_refused_415_with_an_accept() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(
        &mut agent,
        &incoming_message("application/xml", b"<x/>", "m2"),
        t0,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(
        answer.starts_with(b"SIP/2.0 415 "),
        "{}",
        text(&answer, HeaderName::CallId)
    );
    assert!(
        header(&answer, HeaderName::Accept)
            .windows(b"text/plain".len())
            .any(|window| window == b"text/plain")
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::MessageReceived { .. })),
        "a refused body is not delivered"
    );
}

#[test]
fn a_content_type_the_account_declared_is_taken() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account().accepts_message_type(b"application/xml"));
    deliver(
        &mut agent,
        &incoming_message("application/xml", b"<x/>", "m3"),
        t0,
    );
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(answer.starts_with(b"SIP/2.0 200 "));
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::MessageReceived { .. }))
    );
}

#[test]
fn a_body_over_the_incoming_ceiling_is_refused_413() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    let huge = vec![b'x'; 32 * 1024 + 1];
    deliver(&mut agent, &incoming_message("text/plain", &huge, "m4"), t0);
    let answer = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(answer.starts_with(b"SIP/2.0 413 "));
}

/// A MESSAGE from the far end, inside a dialog this end opened (mirroring
/// `reversed`'s tags, the way `incoming_info` does for an INFO).
fn incoming_message_in_dialog(ack: &[u8], branch: &str, cseq: u32, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "MESSAGE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: {}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {cseq} MESSAGE\r\n\
Content-Type: text/plain\r\n\
Content-Length: {}\r\n\r\n",
        text(ack, HeaderName::To),
        text(ack, HeaderName::From),
        text(ack, HeaderName::CallId),
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[test]
fn a_message_sent_inside_a_call_rides_the_dialog_and_is_reported_back() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);

    let handle = agent
        .message_in_call(call, b"text/plain", b"in a call", t0)
        .expect("the MESSAGE goes inside the dialog");
    let request = only(&transmits(&mut agent), "MESSAGE ");
    // the same Call-ID the ACK travelled on: it is this call's dialog
    assert_eq!(
        header(&request, HeaderName::CallId),
        header(&ack, HeaderName::CallId)
    );
    deliver(&mut agent, &reply(&request, 200, "OK", ""), t0);
    assert!(events(&mut agent).iter().any(|event| matches!(
        *event,
        UaEvent::MessageSent { message, status: StatusCode::OK, .. } if message == handle
    )));

    // and a MESSAGE the far end sends inside the same dialog names the call
    deliver(
        &mut agent,
        &incoming_message_in_dialog(&ack, "inmsg", 2, b"reply"),
        t0,
    );
    let answered = only(&transmits(&mut agent), "SIP/2.0 ");
    assert!(answered.starts_with(b"SIP/2.0 200 "));
    assert!(events(&mut agent).iter().any(|event| matches!(
        event,
        UaEvent::MessageReceived { call: Some(reported), .. } if *reported == call
    )));
}

#[test]
fn a_second_in_dialog_message_is_refused_on_a_route_not_known_to_be_congestion_controlled() {
    // §8: "A UAC SHOULD NOT initiate overlapping MESSAGE transactions inside
    // a dialog, and MUST NOT do so unless the route set for that dialog uses
    // a congestion-controlled transport at every hop." The default account
    // says nothing about its transport, so it gets the conservative MUST NOT.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);

    agent
        .message_in_call(call, b"text/plain", b"first", t0)
        .expect("the first MESSAGE goes");
    assert_eq!(
        agent.message_in_call(call, b"text/plain", b"second", t0),
        Err(UaError::MessagePending),
        "a second one is refused while the first has not been answered"
    );
}

#[test]
fn overlapping_in_dialog_messages_are_allowed_once_the_transport_is_congestion_controlled() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account().transport_protocol(TransportProtocol::Tcp));
    let (call, _) = call_up(&mut agent, id, t0);

    agent
        .message_in_call(call, b"text/plain", b"first", t0)
        .expect("the first MESSAGE goes");
    assert!(
        agent
            .message_in_call(call, b"text/plain", b"second", t0)
            .is_ok(),
        "a congestion-controlled route is not held to the MUST NOT"
    );
}

#[test]
fn a_second_in_dialog_message_is_allowed_once_the_first_has_been_answered() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);

    agent
        .message_in_call(call, b"text/plain", b"first", t0)
        .expect("the first MESSAGE goes");
    let request = only(&transmits(&mut agent), "MESSAGE ");
    deliver(&mut agent, &reply(&request, 200, "OK", ""), t0);
    events(&mut agent);
    assert!(
        agent
            .message_in_call(call, b"text/plain", b"second", t0)
            .is_ok(),
        "the first has settled, so this is not an overlap any more"
    );
}

// -- Message waiting indication (RFC 3842) -------------------------------

/// The `message-summary` package's body, as §4.1's own example writes it.
fn simple_message_summary(
    waiting: bool,
    new: u32,
    old: u32,
    urgent_new: u32,
    urgent_old: u32,
) -> String {
    format!(
        "Messages-Waiting: {}\r\n\
Message-Account: sip:alice@vmail.example.com\r\n\
Voice-Message: {new}/{old} ({urgent_new}/{urgent_old})\r\n",
        if waiting { "yes" } else { "no" }
    )
}

#[test]
fn a_message_summary_notify_raises_the_counts_it_carried() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(
            id,
            &Subscribe::new(uri("sip:alice@vmail.example.com"), "message-summary"),
            t0,
        )
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    let body = simple_message_summary(true, 2, 8, 0, 2);
    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            1,
            "notifier",
            "message-summary",
            "active;expires=3600",
            Some(("application/simple-message-summary", &body)),
            "",
        ),
        t0,
    );
    transmits(&mut agent);
    let seen = events(&mut agent);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            UaEvent::MessagesWaiting {
                subscription,
                waiting: true,
                new: 2,
                old: 8,
                urgent_new: 0,
                urgent_old: 2,
                ..
            } if subscription == handle
        )),
        "{seen:?}"
    );
    let summary = agent
        .message_summary(handle)
        .expect("the subscription is live and has a summary");
    assert_eq!(
        summary.account.as_deref(),
        Some("sip:alice@vmail.example.com")
    );
}

#[test]
fn message_summary_says_nothing_once_the_subscription_stops() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(
            id,
            &Subscribe::new(uri("sip:alice@vmail.example.com"), "message-summary"),
            t0,
        )
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    let body = simple_message_summary(true, 1, 0, 0, 0);
    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            1,
            "notifier",
            "message-summary",
            "active;expires=3600",
            Some(("application/simple-message-summary", &body)),
            "",
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert!(agent.message_summary(handle).is_some());

    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            2,
            "notifier",
            "message-summary",
            "terminated;reason=timeout",
            None,
            "",
        ),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert!(
        agent.message_summary(handle).is_none(),
        "a subscription that is not live is not evidence about the mailbox"
    );
}

// -- presence (RFC 3856) and publication (RFC 3903) --------------------------

/// A presence document about `entity`, open or closed, with the RPID
/// activity `activity` when there is one.
fn pidf(entity: &str, open: bool, activity: Option<&str>) -> String {
    let person = activity.map_or_else(String::new, |activity| {
        format!(
            "<dm:person id=\"p1\"><rpid:activities><rpid:{activity}/></rpid:activities>\
</dm:person>"
        )
    });
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" \
xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\" \
xmlns:rpid=\"urn:ietf:params:xml:ns:pidf:rpid\" entity=\"{entity}\">\
<tuple id=\"t1\"><status><basic>{}</basic></status></tuple>{person}</presence>",
        if open { "open" } else { "closed" }
    )
}

/// The presence publications' news, in order.
fn published(agent: &mut UserAgent) -> Vec<crate::PublishEvent> {
    events(agent)
        .into_iter()
        .filter_map(|event| match event {
            UaEvent::Publication { event, .. } => Some(event),
            _ => None,
        })
        .collect()
}

fn presence_of(activity: crate::presence::Activity) -> crate::presence::Presence {
    let mut presence = crate::presence::Presence::new("sip:alice@example.com");
    presence.tuples.push(crate::presence::Tuple::new(
        "t1",
        crate::presence::Basic::Open,
    ));
    presence.person = Some(crate::presence::Person {
        id: Box::from("p1"),
        activities: vec![activity],
    });
    presence
}

#[test]
fn a_presence_notify_is_read_into_the_presentitys_document() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(
            id,
            &Subscribe::new(uri("sip:bob@example.com"), crate::PRESENCE_EVENT),
            t0,
        )
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    let body = pidf("sip:bob@example.com", true, Some("on-the-phone"));
    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            1,
            "notifier",
            "presence",
            "active;expires=3600",
            Some(("application/pidf+xml", &body)),
            "",
        ),
        t0,
    );
    transmits(&mut agent);
    let told: Vec<_> = events(&mut agent)
        .into_iter()
        .filter_map(|event| match event {
            UaEvent::PresenceChanged {
                subscription,
                presence,
            } => Some((subscription, presence)),
            _ => None,
        })
        .collect();
    assert_eq!(told.len(), 1, "one document, one piece of news");
    assert_eq!(told[0].0, handle);
    assert!(told[0].1.is_open());
    assert_eq!(
        told[0].1.activities(),
        &[crate::presence::Activity::OnThePhone]
    );
    assert_eq!(
        agent.presence(handle).map(|held| &*held.entity),
        Some("sip:bob@example.com")
    );

    // a body that will not read leaves the last good one standing
    deliver(
        &mut agent,
        &notification_of(
            &subscribe,
            2,
            "notifier",
            "presence",
            "active;expires=3600",
            Some(("application/pidf+xml", "<presence")),
            "",
        ),
        t0,
    );
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::PresenceChanged { .. }))
    );
    assert!(
        agent
            .presence(handle)
            .is_some_and(crate::presence::Presence::is_open)
    );
}

#[test]
fn a_dialog_subscription_is_never_read_as_presence() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .subscribe(id, &watching("201"), t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    deliver(&mut agent, &accepted(&subscribe, 3_600), t0);
    let body = pidf("sip:201@example.com", true, None);
    deliver(
        &mut agent,
        &notification(
            &subscribe,
            1,
            "notifier",
            "active;expires=3600",
            Some(("application/pidf+xml", &body)),
        ),
        t0,
    );
    transmits(&mut agent);
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(*event, UaEvent::PresenceChanged { .. }))
    );
    assert!(agent.presence(handle).is_none());
}

#[test]
fn presence_is_published_for_the_account_and_refreshed_under_its_entity_tag() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .publish_presence(id, &presence_of(crate::presence::Activity::Away), t0)
        .expect("the PUBLISH goes");
    let publish = only(&transmits(&mut agent), "PUBLISH ");
    assert!(publish.starts_with(b"PUBLISH sip:alice@example.com SIP/2.0\r\n"));
    assert_eq!(text(&publish, HeaderName::Event), "presence");
    assert_eq!(text(&publish, HeaderName::Expires), "3600");
    assert_eq!(
        text(&publish, HeaderName::ContentType),
        "application/pidf+xml"
    );
    assert!(text(&publish, HeaderName::To).contains("sip:alice@example.com"));
    assert!(body_of(&publish).contains("<rpid:away/>"));
    assert!(header(&publish, HeaderName::Extension("SIP-If-Match")).is_empty());

    deliver(
        &mut agent,
        &reply(
            &publish,
            200,
            "OK",
            "SIP-ETag: dx200xyz\r\nExpires: 1800\r\n",
        ),
        t0,
    );
    assert!(matches!(
        published(&mut agent).as_slice(),
        [crate::PublishEvent::Published { etag, .. }] if &**etag == "dx200xyz"
    ));
    assert_eq!(agent.publication_etag(handle), Some("dx200xyz"));

    let due = agent
        .publication_deadline()
        .expect("a refresh is scheduled");
    assert!(due <= t0 + Duration::from_secs(1_800));
    assert!(agent.poll_timeout().is_some_and(|wake| wake <= due));
    agent.handle_timeout(due);
    let refresh = only(&transmits(&mut agent), "PUBLISH ");
    assert_eq!(
        text(&refresh, HeaderName::Extension("SIP-If-Match")),
        "dx200xyz"
    );
    assert!(body_of(&refresh).is_empty(), "a refresh carries no body");
}

#[test]
fn a_publish_challenged_is_answered_with_the_accounts_credentials() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    agent
        .publish_presence(id, &presence_of(crate::presence::Activity::Busy), t0)
        .expect("the PUBLISH goes");
    let publish = only(&transmits(&mut agent), "PUBLISH ");
    deliver(&mut agent, &unauthorized(&publish), t0);
    let retried = only(&transmits(&mut agent), "PUBLISH ");
    credentials_of(&retried, HeaderName::Authorization);
    assert!(
        published(&mut agent).is_empty(),
        "a challenge answered is nobody's news"
    );
    deliver(
        &mut agent,
        &reply(&retried, 200, "OK", "SIP-ETag: e1\r\nExpires: 3600\r\n"),
        t0,
    );
    assert!(matches!(
        published(&mut agent).as_slice(),
        [crate::PublishEvent::Published { .. }]
    ));
}

#[test]
fn a_publish_challenged_with_nothing_to_answer_it_is_refused() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .publish_presence(id, &presence_of(crate::presence::Activity::Busy), t0)
        .expect("the PUBLISH goes");
    let publish = only(&transmits(&mut agent), "PUBLISH ");
    deliver(&mut agent, &unauthorized(&publish), t0);
    assert!(
        transmits(&mut agent)
            .iter()
            .all(|out| !out.starts_with(b"PUBLISH "))
    );
    assert_eq!(
        published(&mut agent),
        vec![crate::PublishEvent::Failed {
            reason: crate::PublishFailure::Refused,
            status: Some(StatusCode::UNAUTHORIZED),
        }]
    );
}

#[test]
fn a_second_presence_modifies_the_publication_the_first_made() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let first = agent
        .publish_presence(id, &presence_of(crate::presence::Activity::Away), t0)
        .expect("the PUBLISH goes");
    let publish = only(&transmits(&mut agent), "PUBLISH ");
    deliver(
        &mut agent,
        &reply(&publish, 200, "OK", "SIP-ETag: e1\r\nExpires: 3600\r\n"),
        t0,
    );
    published(&mut agent);
    let second = agent
        .publish_presence(id, &presence_of(crate::presence::Activity::Meeting), t0)
        .expect("the modification goes");
    assert_eq!(first, second, "one presence per account");
    assert_eq!(agent.presence_publication(id), Some(first));
    let modify = only(&transmits(&mut agent), "PUBLISH ");
    assert_eq!(text(&modify, HeaderName::Extension("SIP-If-Match")), "e1");
    assert!(body_of(&modify).contains("<rpid:meeting/>"));
}

#[test]
fn unpublishing_removes_the_state_and_lets_the_handle_go() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .publish(
            id,
            &crate::Publish::new("presence"),
            "application/pidf+xml",
            Arc::from(pidf("sip:alice@example.com", true, None).as_bytes()),
            t0,
        )
        .expect("the PUBLISH goes");
    let publish = only(&transmits(&mut agent), "PUBLISH ");
    deliver(
        &mut agent,
        &reply(&publish, 200, "OK", "SIP-ETag: e9\r\nExpires: 3600\r\n"),
        t0,
    );
    published(&mut agent);
    agent.unpublish(handle, t0).expect("the removal goes");
    let removal = only(&transmits(&mut agent), "PUBLISH ");
    assert_eq!(text(&removal, HeaderName::Expires), "0");
    assert_eq!(text(&removal, HeaderName::Extension("SIP-If-Match")), "e9");
    deliver(&mut agent, &reply(&removal, 200, "OK", ""), t0);
    assert_eq!(published(&mut agent), vec![crate::PublishEvent::Removed]);
    assert_eq!(agent.unpublish(handle, t0), Err(UaError::NoSuchPublication));
    assert_eq!(
        agent.publication_deadline(),
        None,
        "nothing left to refresh"
    );
}

#[test]
fn a_publication_that_never_reached_the_compositor_is_let_go_at_once() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let handle = agent
        .publish_presence(id, &presence_of(crate::presence::Activity::Away), t0)
        .expect("the PUBLISH goes");
    let publish = only(&transmits(&mut agent), "PUBLISH ");
    deliver(&mut agent, &reply(&publish, 489, "Bad Event", ""), t0);
    published(&mut agent);
    agent.unpublish(handle, t0).expect("nothing to remove");
    assert!(transmits(&mut agent).is_empty());
    assert_eq!(published(&mut agent), vec![crate::PublishEvent::Removed]);
    assert_eq!(agent.presence_publication(id), None);
}

// -- conference focus (RFC 4579) ----------------------------------------------

/// A response whose `Contact` says the far end is the focus of `conference`.
fn answered_by_focus(invite: &[u8], conference: &str) -> Vec<u8> {
    String::from_utf8(answered(invite, 200, "OK", "focus", Some(ANSWER)))
        .expect("text")
        .replace(
            "Contact: <sip:bob@192.0.2.9>\r\n",
            &format!("Contact: <{conference}>;isfocus\r\n"),
        )
        .into_bytes()
}

#[test]
fn a_call_placed_as_the_focus_says_isfocus_in_every_contact_it_sends() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent
        .call(id, &outgoing().focus(), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert_eq!(
        text(&invite, HeaderName::Contact),
        "<sip:alice@192.0.2.1>;isfocus"
    );
    assert!(agent.is_focus(call));
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    agent.hold(call, t0).expect("the re-INVITE goes");
    let reinvite = only(&transmits(&mut agent), "INVITE ");
    assert!(text(&reinvite, HeaderName::Contact).ends_with(";isfocus"));

    agent.set_focus(call, false).expect("the call is there");
    assert!(!agent.is_focus(call));
}

#[test]
fn an_incoming_call_answered_as_the_focus_says_so_in_its_answer() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &incoming_invite("focus1", Some(OFFER)), t0);
    transmits(&mut agent);
    let call = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("the call arrived");
    agent.set_focus(call, true).expect("the call is there");
    agent
        .answer(call, Some(Arc::from(ANSWER)), t0)
        .expect("the 200 goes");
    let ok = only(&transmits(&mut agent), "SIP/2.0 200");
    assert!(text(&ok, HeaderName::Contact).ends_with(";isfocus"));
}

#[test]
fn a_far_end_that_is_a_focus_names_its_conference_and_can_be_subscribed_to() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &answered_by_focus(&invite, "sip:conf42@192.0.2.9"),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);
    assert_eq!(
        agent
            .call_conference(call)
            .map(|conference| conference.to_string()),
        Some("sip:conf42@192.0.2.9".to_owned())
    );
    agent
        .subscribe_call_conference(call, t0)
        .expect("the SUBSCRIBE goes");
    let subscribe = only(&transmits(&mut agent), "SUBSCRIBE ");
    assert!(subscribe.starts_with(b"SUBSCRIBE sip:conf42@192.0.2.9 SIP/2.0\r\n"));
    assert_eq!(text(&subscribe, HeaderName::Event), "conference");
    assert_ne!(
        text(&subscribe, HeaderName::CallId),
        text(&invite, HeaderName::CallId),
        "outside the INVITE's dialog, as RFC 4579 §3.4 asks"
    );
}

#[test]
fn a_far_end_that_is_not_a_focus_has_no_conference_to_subscribe_to() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);
    assert!(agent.call_conference(call).is_none());
    assert_eq!(
        agent.subscribe_call_conference(call, t0),
        Err(UaError::NotAFocus)
    );
}

// -- recording sessions (RFC 7866) --------------------------------------------

#[test]
fn a_recording_session_requires_siprec_and_carries_the_offer_and_the_metadata() {
    let t0 = Instant::now();
    // over a stream: an offer and its metadata outgrow what RFC 3261
    // §18.1.1 lets go as one datagram, which is why recorders listen on TCP
    let (mut agent, id) = over_tcp(t0);
    let call = crate::siprec::RecordedCall {
        session_id: crate::siprec::metadata_id([7; 16]),
        parties: vec![crate::siprec::RecordedParty {
            id: crate::siprec::metadata_id([8; 16]),
            aor: "sip:alice@example.com".to_owned(),
            name: None,
            sends: vec![crate::siprec::RecordedStream {
                id: crate::siprec::metadata_id([9; 16]),
                label: "1".to_owned(),
            }],
        }],
        ..crate::siprec::RecordedCall::default()
    };
    let offer = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\na=sendonly\r\na=label:1\r\n";
    let outgoing = OutgoingCall::new(uri("sip:srs@example.com"))
        .offer(Arc::from(&offer[..]))
        .recording_session(&call.metadata())
        .expect("the metadata is writable");
    agent.call(id, &outgoing, t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    assert_eq!(text(&invite, HeaderName::Require), "siprec");
    assert_eq!(
        text(&invite, HeaderName::Contact),
        "<sip:alice@192.0.2.1>;+sip.src"
    );
    assert!(text(&invite, HeaderName::ContentType).starts_with("multipart/mixed;"));
    let read = with(&invite, |message| {
        crate::siprec::read_recording_offer(message).map(|offer| {
            (
                offer.sdp.to_vec(),
                offer.metadata.participants.len(),
                offer.metadata.streams.len(),
            )
        })
    })
    .expect("an SRS reads it back");
    assert_eq!(read, (offer.to_vec(), 1, 1));
}

#[test]
fn new_metadata_goes_in_a_re_offer_that_defines_the_labels_it_names() {
    let t0 = Instant::now();
    let (mut agent, id) = over_tcp(t0);
    let mut call = crate::siprec::RecordedCall {
        session_id: crate::siprec::metadata_id([1; 16]),
        parties: vec![crate::siprec::RecordedParty {
            id: crate::siprec::metadata_id([2; 16]),
            aor: "sip:alice@example.com".to_owned(),
            name: None,
            sends: vec![crate::siprec::RecordedStream {
                id: crate::siprec::metadata_id([3; 16]),
                label: "1".to_owned(),
            }],
        }],
        ..crate::siprec::RecordedCall::default()
    };
    let offer = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\na=sendonly\r\na=label:1\r\n";
    let recording = agent
        .call(
            id,
            &OutgoingCall::new(uri("sip:srs@example.com"))
                .offer(Arc::from(&offer[..]))
                .recording_session(&call.metadata())
                .expect("writable"),
            t0,
        )
        .expect("the INVITE goes");
    let invite = only(&transmits(&mut agent), "INVITE ");
    let answer = b"v=0\r\no=srs 5 5 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\na=recvonly\r\n";
    stream(
        &mut agent,
        &answered(&invite, 200, "OK", "srs", Some(answer)),
        t0,
    );
    transmits(&mut agent);
    events(&mut agent);

    call.parties[0].name = Some("Alice".to_owned());
    agent
        .update_recording_metadata(recording, &call.metadata(), t0)
        .expect("the re-offer goes");
    let reinvite = only(&transmits(&mut agent), "INVITE ");
    assert!(text(&reinvite, HeaderName::ContentType).starts_with("multipart/mixed;"));
    let (sdp, name) = with(&reinvite, |message| {
        crate::siprec::read_recording_offer(message).map(|read| {
            (
                String::from_utf8_lossy(read.sdp).into_owned(),
                read.metadata.participants[0].name_ids[0].names[0]
                    .text
                    .clone(),
            )
        })
    })
    .expect("the SRS reads the update");
    assert!(sdp.contains("a=label:1"), "the labels it names: {sdp}");
    assert!(sdp.contains("o=- 1 2 IN IP4"), "the next version: {sdp}");
    assert_eq!(name, "Alice");
}

/// A recording session's INVITE, as an SRC sends it: `Require: siprec`,
/// `+sip.src`, and the offer and metadata as one multipart body.
fn recording_invite() -> Vec<u8> {
    let call = crate::siprec::RecordedCall {
        session_id: crate::siprec::metadata_id([4; 16]),
        parties: vec![crate::siprec::RecordedParty {
            id: crate::siprec::metadata_id([5; 16]),
            aor: "sip:bob@example.com".to_owned(),
            name: None,
            sends: vec![crate::siprec::RecordedStream {
                id: crate::siprec::metadata_id([6; 16]),
                label: "1".to_owned(),
            }],
        }],
        ..crate::siprec::RecordedCall::default()
    };
    let offer = b"v=0\r\no=- 1 1 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\na=sendonly\r\na=label:1\r\n";
    let body = crate::siprec::recording_session_body(offer, &call.metadata()).expect("a body");
    let mut out = format!(
        "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKsrc1;rport\r\nMax-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=src\r\nTo: <sip:alice@example.com>\r\n\
Call-ID: recording@example.com\r\nCSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.0.2.9>;+sip.src\r\nRequire: siprec\r\n\
Content-Type: {}\r\nContent-Length: {}\r\n\r\n",
        body.content_type(),
        body.body().len()
    )
    .into_bytes();
    out.extend_from_slice(body.body());
    out
}

#[test]
fn a_recording_session_is_refused_420_unless_the_agent_takes_them() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(account());
    deliver(&mut agent, &recording_invite(), t0);
    let refusal = only(&transmits(&mut agent), "SIP/2.0 420");
    assert_eq!(text(&refusal, HeaderName::Unsupported), "siprec");

    let mut server = self::agent(t0);
    server.add_account(account());
    server.accept_recording_sessions(true);
    deliver(&mut server, &recording_invite(), t0);
    assert!(
        transmits(&mut server)
            .iter()
            .all(|out| !out.starts_with(b"SIP/2.0 4")),
        "taken, not refused"
    );
    let call = events(&mut server)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("the recording session arrived");
    let answer = b"v=0\r\no=srs 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=recvonly\r\n";
    server
        .answer(call, Some(Arc::from(&answer[..])), t0)
        .expect("the recording session is answered");
    let ok = only(&transmits(&mut server), "SIP/2.0 200");
    assert!(body_of(&ok).contains("m=audio 30000"));
}

#[test]
fn metadata_for_a_call_that_is_not_a_recording_session_is_refused() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _) = call_up(&mut agent, id, t0);
    let metadata = crate::siprec::RecordingMetadata::new(crate::siprec::DataMode::Complete);
    assert!(matches!(
        agent.update_recording_metadata(call, &metadata, t0),
        Err(UaError::WrongState(_))
    ));
    assert!(transmits(&mut agent).is_empty());
}

// -- §18.1.1 on a retry, when the stream never comes -------------------------

/// An offer with the two SDES suites an account offering both writes, the
/// stronger first.
const TWO_SUITES: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/SAVP 0\r\n\
a=crypto:1 AEAD_AES_256_GCM inline:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdA==\r\n\
a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNk\r\n";

/// A 401 whose nonce is long enough that answering it takes a request past
/// what a datagram may carry.
fn long_challenge(request: &[u8], nonce_bytes: usize) -> Vec<u8> {
    let nonce = "n".repeat(nonce_bytes);
    challenge(
        request,
        401,
        "Unauthorized",
        &format!(
            "WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"{nonce}\", qop=\"auth\"\r\n"
        ),
    )
}

fn secure_call() -> OutgoingCall {
    OutgoingCall::new(uri("sip:bob@example.com")).offer(Arc::from(TWO_SUITES))
}

/// The size the retry asked a stream for.
fn wanted_bytes(said: &[UaEvent]) -> Option<usize> {
    said.iter().find_map(|event| match *event {
        UaEvent::Unclaimed(Event::TransportWanted { request_bytes, .. }) => Some(request_bytes),
        _ => None,
    })
}

/// A call challenged with a nonce that pushes its retry over the line, on an
/// agent built with `config`: the call, and what the challenge left said.
fn challenged_past_the_line(
    config: EndpointConfig,
    nonce_bytes: usize,
    now: Instant,
) -> (UserAgent, CallHandle, Vec<UaEvent>) {
    let mut agent = agent_with(config, now);
    let id = agent.add_account(credentialled());
    let call = agent
        .call(id, &secure_call(), now)
        .expect("the INVITE goes");
    let first = sent(&mut agent);
    deliver(&mut agent, &long_challenge(&first, nonce_bytes), now);
    let out = transmits(&mut agent);
    let _ = only(&out, "ACK ");
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"INVITE ")),
        "the retry is over the line and waits"
    );
    let said = events(&mut agent);
    (agent, call, said)
}

/// What the call ended with: reason, status and the causes.
fn call_end(said: &[UaEvent]) -> Option<(CallEndReason, Option<StatusCode>, Vec<crate::Reason>)> {
    said.iter().find_map(|event| match *event {
        UaEvent::CallEnded {
            reason,
            status,
            ref causes,
            ..
        } => Some((reason, status, causes.to_vec())),
        _ => None,
    })
}

#[test]
fn a_challenged_invite_over_the_line_goes_over_the_stream_once_one_is_bound() {
    let t0 = Instant::now();
    let (mut agent, call, said) = challenged_past_the_line(EndpointConfig::default(), 900, t0);
    assert!(
        wanted_bytes(&said).is_some_and(|bytes| bytes > 1_300),
        "the application is asked for a stream: {said:?}"
    );
    assert!(call_end(&said).is_none(), "the call is still being placed");
    assert_eq!(agent.call_state(call), Some(CallState::Calling));

    let later = t0 + Duration::from_millis(80);
    open_the_stream(&mut agent, later);
    let retry = on_the_stream(&written(&mut agent), "INVITE ");
    credentials_of_long(&retry);
    assert!(
        text(&retry, HeaderName::Via).starts_with("SIP/2.0/TCP "),
        "§18.1.1 and §8.1.1.7: the Via names the transport it went on: {}",
        text(&retry, HeaderName::Via)
    );
    // §8.1.1.8: the Contact is where this end is reached for the rest of
    // the dialog, and that is still the socket that listens; the connection
    // carried one request, and its local port takes no new ones
    assert_eq!(text(&retry, HeaderName::Contact), "<sip:alice@192.0.2.1>");
    assert_eq!(
        body_of(&retry).matches("a=crypto:").count(),
        2,
        "over a stream the offer goes whole"
    );
    assert_eq!(header(&retry, HeaderName::CSeq), b"2 INVITE");

    // and nothing is given up on later: the wait ended when the stream came
    agent.handle_timeout(later + STREAM_WAIT);
    assert!(call_end(&events(&mut agent)).is_none());
    stream(
        &mut agent,
        &answered(&retry, 200, "OK", "desk", Some(ANSWER)),
        later,
    );
    on_the_stream(&written(&mut agent), "ACK ");
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

fn credentials_of_long(bytes: &[u8]) {
    let value = text(bytes, HeaderName::Authorization);
    assert!(value.starts_with("Digest "), "{value}");
    assert!(value.contains("username=\"alice\""), "{value}");
}

#[test]
fn a_challenged_invite_no_stream_carries_ends_with_the_limit_named_when_the_wait_runs_out() {
    let t0 = Instant::now();
    let (mut agent, call, said) = challenged_past_the_line(EndpointConfig::default(), 900, t0);
    let size = wanted_bytes(&said).expect("a stream was asked for");
    assert_eq!(
        agent.poll_timeout().map(|due| due <= t0 + STREAM_WAIT),
        Some(true),
        "the wait is on the agent's clock"
    );

    agent.handle_timeout(t0 + (STREAM_WAIT.saturating_sub(Duration::from_millis(1))));
    assert!(call_end(&events(&mut agent)).is_none(), "not yet");

    agent.handle_timeout(t0 + STREAM_WAIT);
    let out = transmits(&mut agent);
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"INVITE ")),
        "one suite fewer is still over the line, so nothing goes"
    );
    let (reason, status, causes) =
        call_end(&events(&mut agent)).expect("the call ends rather than hanging");
    assert_eq!(reason, CallEndReason::Unreachable);
    assert_eq!(status.map(StatusCode::get), Some(513));
    assert_eq!(causes.len(), 1, "{causes:?}");
    assert_eq!(causes[0].cause, Some(513));
    let said = causes[0].text.as_deref().unwrap_or_default();
    assert!(said.contains(&format!("{size} bytes")), "{said}");
    assert!(said.contains("1300-byte"), "{said}");
    assert!(said.contains("18.1.1"), "{said}");
    assert_eq!(agent.call_state(call), None);
    assert_eq!(
        agent.poll_timeout().filter(|due| *due <= t0 + STREAM_WAIT),
        None
    );
}

#[test]
fn the_application_saying_no_stream_ends_the_call_at_once() {
    let t0 = Instant::now();
    let (mut agent, call, _) = challenged_past_the_line(EndpointConfig::default(), 900, t0);
    let soon = t0 + Duration::from_millis(3);
    agent.stream_unavailable(soon);
    let (reason, status, _) = call_end(&events(&mut agent)).expect("ended now, not in ten seconds");
    assert_eq!(reason, CallEndReason::Unreachable);
    assert_eq!(status.map(StatusCode::get), Some(513));
    assert_eq!(agent.call_state(call), None);
    // a stream bound afterwards finds nothing left to send
    open_the_stream(&mut agent, soon);
    not_written(&written(&mut agent), "INVITE ");
}

#[test]
fn a_retry_one_suite_would_fit_goes_over_the_datagram_with_one_suite() {
    let t0 = Instant::now();
    // how large the whole retry is, measured on an agent that asks for it
    let (_, _, said) = challenged_past_the_line(EndpointConfig::default(), 900, t0);
    let whole = wanted_bytes(&said).expect("the size of the retry");
    // then the same exchange where the line falls between the retry with two
    // suites and the retry with one; the seed is the same, so the bytes are
    let mut config = EndpointConfig::default();
    config.datagram_limit.max_datagram_bytes = u32::try_from(whole - 10).expect("a size");
    let (mut agent, call, said) = challenged_past_the_line(config, 900, t0);
    assert_eq!(wanted_bytes(&said), Some(whole));

    agent.stream_unavailable(t0);
    let retry = only(&transmits(&mut agent), "INVITE ");
    assert!(retry.len() <= whole - 10, "{} bytes", retry.len());
    credentials_of_long(&retry);
    let body = body_of(&retry);
    assert_eq!(body.matches("a=crypto:").count(), 1, "{body}");
    assert!(
        body.contains("a=crypto:2 AES_CM_128_HMAC_SHA1_80 "),
        "the suite kept is the one every SDES answerer takes, under its tag: {body}"
    );
    assert!(
        text(&retry, HeaderName::Via).starts_with("SIP/2.0/UDP "),
        "{}",
        text(&retry, HeaderName::Via)
    );
    assert!(call_end(&events(&mut agent)).is_none());
    assert_eq!(agent.call_state(call), Some(CallState::Calling));

    deliver(
        &mut agent,
        &answered(&retry, 200, "OK", "desk", Some(ANSWER)),
        t0,
    );
    assert!(sent(&mut agent).starts_with(b"ACK "));
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

/// A server on UDP alone, and a stack configured to set §18.1.1 aside for it
/// (`DatagramLimit::without_stream_bytes`): once no stream is coming, the
/// whole retry — both suites — goes over the datagram, whether the
/// application said so or the wait ran out, and the call carries on.
#[test]
fn a_challenged_invite_goes_whole_over_the_datagram_when_the_setting_allows_it() {
    let t0 = Instant::now();
    let (_, _, said) = challenged_past_the_line(EndpointConfig::default(), 900, t0);
    let whole = wanted_bytes(&said).expect("the size of the retry");
    let mut config = EndpointConfig::default();
    config.datagram_limit.without_stream_bytes = Some(u32::try_from(whole).expect("a size"));

    for told in [true, false] {
        let (mut agent, call, said) = challenged_past_the_line(config, 900, t0);
        assert_eq!(wanted_bytes(&said), Some(whole), "§18.1.1 first");
        assert!(transmits(&mut agent).is_empty(), "the retry waits");
        let when = if told {
            agent.stream_unavailable(t0);
            t0
        } else {
            agent.handle_timeout(t0 + STREAM_WAIT);
            t0 + STREAM_WAIT
        };
        let retry = only(&transmits(&mut agent), "INVITE ");
        assert_eq!(retry.len(), whole);
        credentials_of_long(&retry);
        assert_eq!(body_of(&retry).matches("a=crypto:").count(), 2);
        assert!(text(&retry, HeaderName::Via).starts_with("SIP/2.0/UDP "));
        assert!(call_end(&events(&mut agent)).is_none(), "told {told}");
        let recorded = agent
            .endpoint()
            .call_record(&CallId::new(&header(&retry, HeaderName::CallId)))
            .expect("the call's record")
            .decisions()
            .filter(|decision| decision.reason.as_str() == "transport.kept.datagram")
            .filter_map(|decision| decision.measure)
            .collect::<Vec<_>>();
        assert_eq!(recorded.len(), 1, "told {told}");
        assert_eq!(recorded[0].size, whole);

        deliver(
            &mut agent,
            &answered(&retry, 200, "OK", "desk", Some(ANSWER)),
            when,
        );
        assert!(sent(&mut agent).starts_with(b"ACK "));
        assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
    }

    // a byte short of the whole retry, the one with a single suite is what
    // goes over the datagram
    config.datagram_limit.without_stream_bytes = Some(u32::try_from(whole - 1).expect("a size"));
    let (mut agent, call, _) = challenged_past_the_line(config, 900, t0);
    agent.stream_unavailable(t0);
    let retry = only(&transmits(&mut agent), "INVITE ");
    assert!(retry.len() < whole, "{} bytes", retry.len());
    assert_eq!(body_of(&retry).matches("a=crypto:").count(), 1);
    assert!(text(&retry, HeaderName::Via).starts_with("SIP/2.0/UDP "));
    assert_eq!(agent.call_state(call), Some(CallState::Calling));

    // and a setting no larger than §18.1.1's own line reaches nothing: the
    // call ends as it would without one
    config.datagram_limit.without_stream_bytes = Some(1_300);
    let (mut agent, _, _) = challenged_past_the_line(config, 900, t0);
    agent.stream_unavailable(t0);
    assert!(
        !transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"INVITE "))
    );
    let (reason, status, _) = call_end(&events(&mut agent)).expect("ended");
    assert_eq!(reason, CallEndReason::Unreachable);
    assert_eq!(status.map(StatusCode::get), Some(513));
}

#[test]
fn a_register_whose_answer_outgrew_the_datagram_fails_as_too_large_rather_than_as_a_password() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    deliver(&mut agent, &long_challenge(&first, 1_400), t0);
    assert!(transmits(&mut agent).is_empty(), "the retry waits");
    let said = events(&mut agent);
    assert!(wanted_bytes(&said).is_some(), "{said:?}");
    assert!(
        !said
            .iter()
            .any(|event| matches!(*event, UaEvent::RegistrationFailed { .. })),
        "{said:?}"
    );

    agent.stream_unavailable(t0);
    let failures: Vec<(RegistrationFailure, Option<u16>, Option<Duration>)> = events(&mut agent)
        .iter()
        .filter_map(|event| match *event {
            UaEvent::RegistrationFailed {
                reason,
                status,
                retry_in,
                ..
            } => Some((reason, status.map(StatusCode::get), retry_in)),
            _ => None,
        })
        .collect();
    assert_eq!(
        failures,
        vec![(RegistrationFailure::Unreachable, Some(513), None)],
        "once, and not as credentials refused"
    );
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Failed)
    );
    open_the_stream(&mut agent, t0);
    not_written(&written(&mut agent), "REGISTER ");
}

#[test]
fn a_register_whose_answer_outgrew_the_datagram_goes_over_the_stream() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(credentialled());
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    deliver(&mut agent, &long_challenge(&first, 1_400), t0);
    events(&mut agent);
    open_the_stream(&mut agent, t0);
    let retry = on_the_stream(&written(&mut agent), "REGISTER ");
    credentials_of_long(&retry);
    assert!(text(&retry, HeaderName::Via).starts_with("SIP/2.0/TCP "));
}

/// A MESSAGE whose challenge carries a nonce long enough that the answer
/// outgrows the datagram, and what the challenge left said.
fn message_challenged_past_the_line(
    now: Instant,
) -> (UserAgent, crate::MessageHandle, Vec<UaEvent>) {
    let mut agent = agent(now);
    let id = agent.add_account(credentialled());
    let handle = agent
        .message(id, uri("sip:bob@example.com"), b"text/plain", b"hello", now)
        .expect("the MESSAGE goes");
    let first = only(&transmits(&mut agent), "MESSAGE ");
    deliver(&mut agent, &long_challenge(&first, 1_400), now);
    assert!(
        !transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"MESSAGE ")),
        "the retry waits"
    );
    let said = events(&mut agent);
    (agent, handle, said)
}

/// The statuses a MESSAGE was reported sent with.
fn message_outcomes(said: &[UaEvent]) -> Vec<u16> {
    said.iter()
        .filter_map(|event| match *event {
            UaEvent::MessageSent { status, .. } => Some(status.get()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_message_whose_answer_outgrew_the_datagram_waits_for_the_stream_rather_than_failing_as_refused()
{
    let t0 = Instant::now();
    let (mut agent, handle, said) = message_challenged_past_the_line(t0);
    assert!(wanted_bytes(&said).is_some(), "{said:?}");
    assert_eq!(
        message_outcomes(&said),
        Vec::<u16>::new(),
        "a challenge whose answer has not gone yet says nothing about the password"
    );
    open_the_stream(&mut agent, t0);
    let retry = on_the_stream(&written(&mut agent), "MESSAGE ");
    credentials_of_long(&retry);
    stream(&mut agent, &reply(&retry, 200, "OK", ""), t0);
    let said = events(&mut agent);
    assert!(
        said.iter().any(|event| matches!(
            *event,
            UaEvent::MessageSent { message, status, .. }
                if message == handle && status == StatusCode::OK
        )),
        "{said:?}"
    );
}

#[test]
fn a_message_whose_answer_outgrew_the_datagram_is_reported_too_large_when_no_stream_comes() {
    let t0 = Instant::now();
    let (mut agent, _, _) = message_challenged_past_the_line(t0);
    agent.handle_timeout(t0 + STREAM_WAIT);
    assert_eq!(message_outcomes(&events(&mut agent)), vec![513]);
    open_the_stream(&mut agent, t0 + STREAM_WAIT);
    not_written(&written(&mut agent), "MESSAGE ");
}

/// A presence PUBLISH whose challenge pushes the answer past the datagram.
fn publish_challenged_past_the_line(now: Instant) -> UserAgent {
    let mut agent = agent(now);
    let id = agent.add_account(credentialled());
    agent
        .publish_presence(id, &presence_of(crate::presence::Activity::Busy), now)
        .expect("the PUBLISH goes");
    let publish = only(&transmits(&mut agent), "PUBLISH ");
    deliver(&mut agent, &long_challenge(&publish, 1_400), now);
    assert!(
        !transmits(&mut agent)
            .iter()
            .any(|bytes| bytes.starts_with(b"PUBLISH ")),
        "the retry waits"
    );
    agent
}

#[test]
fn a_publish_whose_answer_outgrew_the_datagram_goes_over_the_stream() {
    let t0 = Instant::now();
    let mut agent = publish_challenged_past_the_line(t0);
    assert!(
        published(&mut agent).is_empty(),
        "a challenge whose answer has not gone yet is nobody's news"
    );
    open_the_stream(&mut agent, t0);
    let retry = on_the_stream(&written(&mut agent), "PUBLISH ");
    credentials_of_long(&retry);
    stream(
        &mut agent,
        &reply(&retry, 200, "OK", "SIP-ETag: e1\r\nExpires: 3600\r\n"),
        t0,
    );
    assert!(matches!(
        published(&mut agent).as_slice(),
        [crate::PublishEvent::Published { .. }]
    ));
}

#[test]
fn a_publish_whose_answer_outgrew_the_datagram_fails_as_unreachable_when_no_stream_comes() {
    let t0 = Instant::now();
    let mut agent = publish_challenged_past_the_line(t0);
    published(&mut agent);
    agent.stream_unavailable(t0);
    assert_eq!(
        published(&mut agent),
        vec![crate::PublishEvent::Failed {
            reason: crate::PublishFailure::Unreachable,
            status: StatusCode::new(513).ok(),
        }]
    );
    open_the_stream(&mut agent, t0);
    not_written(&written(&mut agent), "PUBLISH ");
}

/// A call up over UDP whose re-INVITE a proxy challenges with a nonce long
/// enough that the answer outgrows the datagram.
fn hold_challenged_past_the_line(now: Instant) -> (UserAgent, CallHandle) {
    let mut agent = agent(now);
    let id = agent.add_account(credentialled());
    let call = agent.call(id, &outgoing(), now).expect("the INVITE goes");
    let invite = sent(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "desk", Some(ANSWER)),
        now,
    );
    assert!(sent(&mut agent).starts_with(b"ACK "));
    events(&mut agent);

    agent.hold(call, now).expect("the re-INVITE goes");
    let reinvite = only(&transmits(&mut agent), "INVITE ");
    deliver(&mut agent, &long_challenge(&reinvite, 1_400), now);
    let out = transmits(&mut agent);
    assert!(
        !out.iter().any(|bytes| bytes.starts_with(b"INVITE ")),
        "the retry waits"
    );
    (agent, call)
}

#[test]
fn a_challenged_reinvite_over_the_line_waits_for_the_stream_rather_than_failing_as_refused() {
    let t0 = Instant::now();
    let (mut agent, call) = hold_challenged_past_the_line(t0);
    assert!(
        !events(&mut agent)
            .iter()
            .any(|event| matches!(*event, UaEvent::SessionChangeFailed { .. })),
        "a change whose answer has not been sent yet has not failed"
    );
    open_the_stream(&mut agent, t0);
    let retry = on_the_stream(&written(&mut agent), "INVITE ");
    credentials_of_long(&retry);
    assert!(body_of(&retry).contains("a=sendonly\r\n"));
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_challenged_reinvite_no_stream_carries_fails_as_too_large_and_the_call_stays() {
    let t0 = Instant::now();
    let (mut agent, call) = hold_challenged_past_the_line(t0);
    events(&mut agent);
    agent.handle_timeout(t0 + STREAM_WAIT);
    let failed: Vec<Option<u16>> = events(&mut agent)
        .iter()
        .filter_map(|event| match *event {
            UaEvent::SessionChangeFailed { status, .. } => Some(status.map(StatusCode::get)),
            _ => None,
        })
        .collect();
    assert_eq!(failed, vec![Some(513)]);
    assert_eq!(
        agent.call_state(call),
        Some(CallState::Confirmed),
        "§14.1: a change that failed leaves the session as it was"
    );
}

#[test]
fn a_hangup_waiting_for_a_stream_the_application_cannot_open_ends_the_call_here() {
    // the same crossing as above, and this time the stream is refused: the
    // call is over at this end with the limit named, and the ACK and the BYE
    // that could never go are not kept for a stream that is not coming
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
        &from_afar(&answered(&invite, 200, "OK", "desk", Some(ANSWER))),
        t0,
    );
    written(&mut agent);
    assert_eq!(ended(&mut agent), None);

    // the wait running out leaves what the far end is owed where it is
    agent.handle_timeout(t0 + STREAM_WAIT);
    assert_eq!(ended(&mut agent), None);

    agent.stream_unavailable(t0 + STREAM_WAIT);
    let (reason, status, causes) = call_end(&events(&mut agent)).expect("the call ends");
    assert_eq!(reason, CallEndReason::LocalHangup);
    assert_eq!(status.map(StatusCode::get), Some(513));
    assert_eq!(causes.first().and_then(|cause| cause.cause), Some(513));
    assert_eq!(agent.call_state(call), None);
    open_the_stream(&mut agent, t0 + STREAM_WAIT);
    let out = written(&mut agent);
    not_written(&out, "ACK ");
    not_written(&out, "BYE ");
}
