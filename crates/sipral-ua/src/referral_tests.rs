// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A REFER outside any dialog, scripted on a fake clock (RFC 3515, RFC 4488),
//! and the subscription a taken REFER opens, in a call or out of one.
//!
//! The far end here is a switchboard at 192.0.2.9 asking the phone at
//! 192.0.2.1 to ring Carol: RFC 3515 §4.1's own flow, with this end as
//! Agent B.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, RawMessage, StatusCode, parse};

use crate::account::{Account, AccountId};
use crate::agent::UserAgent;
use crate::call::{CallHandle, CallState, OutgoingExtras};
use crate::event::UaEvent;
use crate::{
    EndpointConfig, Incoming, Input, Rate, Screening, TransportId, TransportProtocol, Uri,
};

const UDP: TransportId = TransportId(1);
/// A transport nothing ever bound, for a line whose calls cannot leave.
const NOWHERE: TransportId = TransportId(9);

const OFFER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
const ANSWER: &[u8] = b"v=0\r\no=- 2 2 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

fn agent(now: Instant) -> UserAgent {
    let mut agent = UserAgent::new(EndpointConfig::default(), [23; 32]).expect("an agent");
    agent
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: "192.0.2.1:5060".parse().expect("an address"),
                remote: None,
            },
            now,
        )
        .expect("binding a transport");
    agent
}

fn line(transport: TransportId) -> Account {
    Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri("sip:alice@192.0.2.1"),
        transport,
        "192.0.2.9:5060".parse().expect("the proxy"),
    )
}

/// An agent that takes referrals, with the one line they are addressed to.
fn taking(now: Instant) -> (UserAgent, AccountId) {
    let mut agent = agent(now);
    let account = agent.add_account(line(UDP));
    agent.allow_referrals(true);
    (agent, account)
}

fn deliver_from(agent: &mut UserAgent, remote: &str, bytes: &[u8], now: Instant) {
    agent
        .receive(
            Input::Datagram {
                transport: UDP,
                remote: remote.parse().expect("an address"),
                local: "192.0.2.1:5060".parse().expect("an address"),
                data: bytes,
            },
            now,
        )
        .expect("a well formed datagram");
}

fn deliver(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
    deliver_from(agent, "192.0.2.9:5060", bytes, now);
}

fn transmits(agent: &mut UserAgent) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(transmit) = agent.poll_transmit() {
        out.push(transmit.payload.to_vec());
    }
    out
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

fn text(bytes: &[u8], name: HeaderName<'_>) -> String {
    with(bytes, |message| {
        String::from_utf8_lossy(message.header(name).unwrap_or_default()).into_owned()
    })
}

fn body(bytes: &[u8]) -> String {
    with(bytes, |message| {
        String::from_utf8_lossy(message.body()).into_owned()
    })
}

fn status_of(bytes: &[u8]) -> Option<u16> {
    with(bytes, |message| message.status().map(StatusCode::get))
}

/// The one message out of `out` that starts with `start`.
fn only(out: &[Vec<u8>], start: &str) -> Vec<u8> {
    let mut found = out
        .iter()
        .filter(|bytes| bytes.starts_with(start.as_bytes()));
    let first = found
        .next()
        .unwrap_or_else(|| panic!("nothing starting {start:?} went out"));
    assert!(found.next().is_none(), "more than one {start:?} went out");
    first.clone()
}

/// Every NOTIFY in `out`, as its `Subscription-State` and its body.
fn notifies(out: &[Vec<u8>]) -> Vec<(String, String)> {
    out.iter()
        .filter(|bytes| bytes.starts_with(b"NOTIFY "))
        .map(|bytes| (text(bytes, HeaderName::SubscriptionState), body(bytes)))
        .collect()
}

/// A REFER outside any dialog, from the switchboard, asking for Carol.
fn referral(branch: &str, extra: &str) -> Vec<u8> {
    format!(
        "REFER sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:switchboard@example.com>;tag=sb-{branch}\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: click-{branch}@192.0.2.9\r\n\
CSeq: 93809823 REFER\r\n\
Contact: <sip:switchboard@192.0.2.9>\r\n\
Refer-To: <sip:carol@example.com>\r\n\
Referred-By: <sip:switchboard@example.com>\r\n\
{extra}Content-Length: 0\r\n\
\r\n"
    )
    .into_bytes()
}

/// What `referral` without one of its own lines.
fn without(message: &[u8], header: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(message);
    text.split_inclusive("\r\n")
        .filter(|line| !line.starts_with(header))
        .collect::<String>()
        .into_bytes()
}

/// A response to a request the agent wrote, from its far end.
fn reply(request: &[u8], status: u16, reason: &str, tag: &str, extra: &str) -> Vec<u8> {
    let to = text(request, HeaderName::To);
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag={tag}")
    };
    format!(
        "SIP/2.0 {status} {reason}\r\n\
Via: {}\r\n\
From: {}\r\n\
To: {to}\r\n\
Call-ID: {}\r\n\
CSeq: {}\r\n\
{extra}Content-Length: 0\r\n\
\r\n",
        text(request, HeaderName::Via),
        text(request, HeaderName::From),
        text(request, HeaderName::CallId),
        text(request, HeaderName::CSeq),
    )
    .into_bytes()
}

/// Carol's phone ringing, in the early dialog its tag makes.
fn ringing(invite: &[u8]) -> Vec<u8> {
    reply(
        invite,
        180,
        "Ringing",
        "carol",
        "Contact: <sip:carol@192.0.2.9>\r\n",
    )
}

/// The 200 that answers an INVITE, with its session description.
fn answered(invite: &[u8], tag: &str) -> Vec<u8> {
    let head = reply(invite, 200, "OK", tag, "Contact: <sip:carol@192.0.2.9>\r\n");
    let head = String::from_utf8_lossy(&head).replace(
        "Content-Length: 0\r\n\r\n",
        &format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n",
            ANSWER.len()
        ),
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(ANSWER);
    out
}

/// The switchboard's 200 to every NOTIFY in `out`.
fn acknowledge(agent: &mut UserAgent, out: &[Vec<u8>], now: Instant) {
    for notify in out.iter().filter(|bytes| bytes.starts_with(b"NOTIFY ")) {
        deliver(agent, &reply(notify, 200, "OK", "unused", ""), now);
    }
    transmits(agent);
}

/// A request from the switchboard inside the dialog the 202 made.
fn from_the_referrer(
    accepted: &[u8],
    method: &str,
    branch: &str,
    cseq: u32,
    extra: &str,
) -> Vec<u8> {
    format!(
        "{method} sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: {}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {cseq} {method}\r\n\
Contact: <sip:switchboard@192.0.2.9>\r\n\
{extra}Content-Length: 0\r\n\
\r\n",
        text(accepted, HeaderName::From),
        text(accepted, HeaderName::To),
        text(accepted, HeaderName::CallId),
    )
    .into_bytes()
}

/// A referral delivered and handed over, with nothing answered yet.
fn asked(agent: &mut UserAgent, branch: &str, extra: &str, now: Instant) -> CallHandle {
    deliver(agent, &referral(branch, extra), now);
    let out = transmits(agent);
    assert!(
        out.iter().all(|bytes| !bytes.starts_with(b"SIP/2.0 ")),
        "nothing is answered on the application's behalf: {:?}",
        out.iter()
            .map(|bytes| String::from_utf8_lossy(bytes))
            .collect::<Vec<_>>()
    );
    events(agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::ReferralRequested { referral, .. } => Some(referral),
            _ => None,
        })
        .expect("the application was asked")
}

/// A referral taken: the 202, the NOTIFYs and the INVITE it placed.
fn taken(
    agent: &mut UserAgent,
    branch: &str,
    now: Instant,
) -> (CallHandle, CallHandle, Vec<Vec<u8>>) {
    let referral = asked(agent, branch, "", now);
    let placed = agent
        .accept_transfer(
            referral,
            Some(Arc::from(OFFER)),
            OutgoingExtras::default(),
            now,
        )
        .expect("the referral is taken");
    (referral, placed, transmits(agent))
}

// -- off, which is the default ----------------------------------------------

#[test]
fn a_refer_outside_a_dialog_is_refused_403_until_the_application_takes_them() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(line(UDP));
    assert!(!agent.allows_referrals(), "off unless asked for");

    deliver(&mut agent, &referral("off", ""), t0);
    let out = transmits(&mut agent);
    // RFC 3261 §21.4.4: understood, and not fulfilled. Not 481, which would
    // say it names a dialog, and not 405, which would say this end does not
    // do REFER
    assert_eq!(out.len(), 1);
    assert_eq!(
        status_of(&out[0]),
        Some(403),
        "{}",
        String::from_utf8_lossy(&out[0])
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::ReferralRequested { .. })),
        "and nobody is asked"
    );
}

#[test]
fn a_refer_whose_to_names_a_dialog_this_end_lacks_is_481_either_way() {
    let t0 = Instant::now();
    for allowed in [false, true] {
        let mut agent = agent(t0);
        agent.add_account(line(UDP));
        agent.allow_referrals(allowed);
        let stray = String::from_utf8_lossy(&referral("tagged", "")).replace(
            "To: <sip:alice@example.com>",
            "To: <sip:alice@example.com>;tag=gone",
        );
        deliver(&mut agent, stray.as_bytes(), t0);
        let out = transmits(&mut agent);
        assert_eq!(out.len(), 1);
        assert_eq!(status_of(&out[0]), Some(481), "allowed: {allowed}");
        assert!(
            events(&mut agent)
                .iter()
                .all(|event| !matches!(event, UaEvent::ReferralRequested { .. }))
        );
    }
}

// -- on ------------------------------------------------------------------------

#[test]
fn a_referral_reaches_the_application_with_its_line_target_and_referrer() {
    let t0 = Instant::now();
    let (mut agent, account) = taking(t0);
    deliver(&mut agent, &referral("ask", ""), t0);
    assert!(
        transmits(&mut agent).is_empty(),
        "nothing answered for the application"
    );
    let (referral, line, target, attended, referred_by) = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::ReferralRequested {
                referral,
                account,
                target,
                attended,
                referred_by,
                ..
            } => Some((referral, account, target, attended, referred_by)),
            _ => None,
        })
        .expect("the application was asked");
    assert_eq!(line, account, "the line its To names");
    assert_eq!(target.as_bytes(), b"sip:carol@example.com");
    assert!(!attended, "no Replaces, so a blind one");
    assert_eq!(
        referred_by.as_deref(),
        Some(&b"<sip:switchboard@example.com>"[..])
    );
    assert!(agent.referral_waiting(referral));
    assert_eq!(
        agent.call_state(referral),
        None,
        "a referral is not a call, whatever its handle's kind"
    );
}

#[test]
fn taking_a_referral_answers_202_opens_the_subscription_and_places_the_call() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    let (referral, placed, out) = taken(&mut agent, "take", t0);

    // §2.4.2's 202, whose To tag makes the dialog (§12.1.1), and a Contact
    // to send the rest of it to
    let accepted = only(&out, "SIP/2.0 202 ");
    let tag = with(&accepted, |message| {
        message
            .to()
            .ok()
            .and_then(|to| to.tag().map(|tag| tag.to_vec()))
    })
    .expect("the 202 names a To tag");
    assert!(!tag.is_empty());
    assert_eq!(
        text(&accepted, HeaderName::Contact),
        "<sip:alice@192.0.2.1>"
    );

    // §2.4.4: the NOTIFY is in the REFER's own dialog, "as if the REFER had
    // been a SUBSCRIBE", addressed to the REFER's Contact
    let notify = only(&out, "NOTIFY ");
    assert!(notify.starts_with(b"NOTIFY sip:switchboard@192.0.2.9 "));
    assert_eq!(text(&notify, HeaderName::CallId), "click-take@192.0.2.9");
    assert_eq!(
        text(&notify, HeaderName::To),
        "<sip:switchboard@example.com>;tag=sb-take"
    );
    assert!(
        text(&notify, HeaderName::From)
            .ends_with(&format!(";tag={}", String::from_utf8_lossy(&tag))),
        "the From tag is the 202's To tag: {}",
        text(&notify, HeaderName::From)
    );
    assert_eq!(text(&notify, HeaderName::Event), "refer;id=93809823");
    // RFC 6665 §4.2.2: an active subscription says how long it has
    assert_eq!(
        text(&notify, HeaderName::SubscriptionState),
        "active;expires=3600"
    );
    assert_eq!(body(&notify), "SIP/2.0 100 Trying\r\n");
    assert_eq!(
        text(&notify, HeaderName::ContentType),
        "message/sipfrag;version=2.0"
    );

    // and the call, from the line, with the REFER's Referred-By on it
    let invite = only(&out, "INVITE ");
    assert!(invite.starts_with(b"INVITE sip:carol@example.com "));
    assert_eq!(
        text(&invite, HeaderName::ReferredBy),
        "<sip:switchboard@example.com>"
    );
    assert_eq!(agent.call_state(placed), Some(CallState::Calling));
    assert!(!agent.referral_waiting(referral), "answered");
    assert_eq!(
        agent.accept_transfer(referral, None, OutgoingExtras::default(), t0),
        Err(crate::UaError::NoSuchCall),
        "and cannot be taken twice"
    );

    // each answer the call gets is reported, and the last one ends it
    deliver(&mut agent, &ringing(&invite), t0);
    let ringing = transmits(&mut agent);
    assert_eq!(
        notifies(&ringing),
        vec![(
            "active;expires=3600".to_owned(),
            "SIP/2.0 180 Ringing\r\n".to_owned()
        )]
    );
    let later = t0 + Duration::from_secs(10);
    deliver(&mut agent, &answered(&invite, "carol"), later);
    let up = transmits(&mut agent);
    assert!(up.iter().any(|bytes| bytes.starts_with(b"ACK ")));
    assert_eq!(
        notifies(&up),
        vec![(
            "terminated;reason=noresource".to_owned(),
            "SIP/2.0 200 OK\r\n".to_owned()
        )],
        "§2.4.7: the last NOTIFY ends the subscription"
    );
    assert_eq!(agent.call_state(placed), Some(CallState::Confirmed));

    // the dialog is gone with it: a refresh now names nothing
    let subscribe = from_the_referrer(
        &accepted,
        "SUBSCRIBE",
        "late",
        93_809_824,
        "Event: refer\r\nExpires: 60\r\n",
    );
    deliver(&mut agent, &subscribe, later);
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(status_of(&out[0]), Some(481));
}

#[test]
fn a_referral_can_be_refused_with_the_applications_own_status() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    let referral = asked(&mut agent, "no", "", t0);
    agent
        .reject_transfer(referral, StatusCode::new(603).expect("603"), t0)
        .expect("the refusal goes");
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 1, "the refusal and nothing after it");
    assert_eq!(status_of(&out[0]), Some(603));
    assert!(!agent.referral_waiting(referral));
    assert_eq!(
        agent.reject_transfer(referral, StatusCode::BUSY_HERE, t0),
        Err(crate::UaError::NoSuchCall)
    );
}

#[test]
fn a_referral_whose_line_is_gone_is_not_taken_and_can_still_be_refused() {
    let t0 = Instant::now();
    let (mut agent, account) = taking(t0);
    let referral = asked(&mut agent, "gone", "", t0);
    agent.remove_account(account);
    assert_eq!(
        agent.accept_transfer(
            referral,
            Some(Arc::from(OFFER)),
            OutgoingExtras::default(),
            t0
        ),
        Err(crate::UaError::NoSuchAccount),
        "there is no line to call from and no Contact to answer with"
    );
    assert!(transmits(&mut agent).is_empty(), "nothing went");
    assert!(agent.referral_waiting(referral), "and it is still there");
    agent
        .reject_transfer(referral, StatusCode::new(480).expect("480"), t0)
        .expect("refused");
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(status_of(&out[0]), Some(480));
}

#[test]
fn a_referral_nobody_answers_lapses_with_its_transaction() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    let referral = asked(&mut agent, "late", "", t0);
    let deadline = agent.poll_timeout().expect("something is due");
    assert!(
        deadline <= t0 + Duration::from_secs(32),
        "64*T1 at the latest"
    );

    agent.handle_timeout(t0 + Duration::from_secs(32));
    let out = transmits(&mut agent);
    assert_eq!(
        out.iter()
            .filter_map(|bytes| status_of(bytes))
            .collect::<Vec<_>>(),
        vec![408],
        "one answer, and it is the timeout"
    );
    let lapsed = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::ReferralLapsed { referral, status } => Some((referral, status)),
            _ => None,
        });
    assert_eq!(lapsed, Some((referral, StatusCode::REQUEST_TIMEOUT)));
    assert!(!agent.referral_waiting(referral));
    assert_eq!(
        agent.accept_transfer(referral, None, OutgoingExtras::default(), t0),
        Err(crate::UaError::NoSuchCall),
        "a spent handle takes nothing"
    );
}

#[test]
fn refer_sub_false_is_granted_with_no_dialog_and_no_notify() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    let referral = asked(&mut agent, "quiet", "Refer-Sub: false\r\n", t0);
    agent
        .accept_transfer(
            referral,
            Some(Arc::from(OFFER)),
            OutgoingExtras::default(),
            t0,
        )
        .expect("taken");
    let out = transmits(&mut agent);
    let accepted = only(&out, "SIP/2.0 202 ");
    // RFC 4488 §4: "it MUST insert the "Refer-Sub" header field set to
    // "false" in the 2xx response"
    assert_eq!(text(&accepted, HeaderName::Extension("Refer-Sub")), "false");
    assert!(
        notifies(&out).is_empty(),
        "no implicit subscription, so no NOTIFY"
    );
    let invite = only(&out, "INVITE ");
    deliver(&mut agent, &answered(&invite, "carol"), t0);
    assert!(
        notifies(&transmits(&mut agent)).is_empty(),
        "and none when the call is answered either"
    );
}

#[test]
fn a_referral_is_screened_as_an_invite_is() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    agent.limit_invites(Rate::new(1, Duration::from_secs(60)).expect("a rate"));
    asked(&mut agent, "first", "", t0);
    deliver(&mut agent, &referral("second", ""), t0);
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(
        status_of(&out[0]),
        Some(480),
        "the rate limit an INVITE meets"
    );
    assert_eq!(agent.refusals().by_rate, 1);

    let (mut agent, _) = taking(t0);
    agent.screen(|incoming: &Incoming<'_>| {
        if incoming.request().as_raw().method() == Some(sipral_core::msg::Method::Refer) {
            Screening::Refuse(StatusCode::new(603).expect("603"))
        } else {
            Screening::Take
        }
    });
    deliver(&mut agent, &referral("policy", ""), t0);
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(
        status_of(&out[0]),
        Some(603),
        "the application's own policy"
    );
    assert!(
        events(&mut agent)
            .iter()
            .all(|event| !matches!(event, UaEvent::ReferralRequested { .. }))
    );
}

#[test]
fn a_referral_that_cannot_be_acted_on_is_refused_at_once() {
    let t0 = Instant::now();
    let cases: [(&str, Vec<u8>, u16); 4] = [
        // §2: "MUST contain a single Contact header field value"
        (
            "no contact",
            without(&referral("nocontact", ""), "Contact:"),
            400,
        ),
        // §2.4.2: exactly one Refer-To
        (
            "no refer-to",
            without(&referral("noreferto", ""), "Refer-To:"),
            400,
        ),
        // §2.4.2: "A UA not capable of accessing non-SIP URIs SHOULD NOT
        // accept REFER requests to them"
        (
            "not sip",
            String::from_utf8_lossy(&referral("http", ""))
                .replace("<sip:carol@example.com>", "<http://example.com/>")
                .into_bytes(),
            403,
        ),
        // RFC 3261 §8.2.2.1: no line here, no account to place the call from
        (
            "no line",
            String::from_utf8_lossy(&referral("stranger", ""))
                .replace("REFER sip:alice@192.0.2.1", "REFER sip:mallory@192.0.2.1")
                .replace(
                    "To: <sip:alice@example.com>",
                    "To: <sip:mallory@example.com>",
                )
                .into_bytes(),
            404,
        ),
    ];
    for (what, bytes, status) in cases {
        let (mut agent, _) = taking(t0);
        deliver(&mut agent, &bytes, t0);
        let out = transmits(&mut agent);
        assert_eq!(out.len(), 1, "{what}");
        assert_eq!(status_of(&out[0]), Some(status), "{what}");
        assert!(
            events(&mut agent)
                .iter()
                .all(|event| !matches!(event, UaEvent::ReferralRequested { .. })),
            "{what}: nobody is asked"
        );
    }
}

#[test]
fn only_so_many_referrals_are_held_at_once() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    agent.limit_invites(Rate::unlimited());
    for n in 0..16 {
        asked(&mut agent, &format!("many{n}"), "", t0);
    }
    deliver(&mut agent, &referral("one-too-many", ""), t0);
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(status_of(&out[0]), Some(486));
}

#[test]
fn a_referral_whose_call_cannot_leave_ends_its_subscription_with_503() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    // the line names a transport nothing bound, so the REFER is answered on
    // its own flow and the call it asks for has nowhere to go
    agent.add_account(line(NOWHERE));
    agent.allow_referrals(true);
    let referral = asked(&mut agent, "stuck", "", t0);
    let refused = agent.accept_transfer(
        referral,
        Some(Arc::from(OFFER)),
        OutgoingExtras::default(),
        t0,
    );
    assert!(
        matches!(refused, Err(crate::UaError::Send(_))),
        "{refused:?}"
    );
    let out = transmits(&mut agent);
    only(&out, "SIP/2.0 202 ");
    // §2.4.5's own minimal example for "the reference failed"
    assert_eq!(
        notifies(&out),
        vec![
            (
                "active;expires=3600".to_owned(),
                "SIP/2.0 100 Trying\r\n".to_owned()
            ),
            (
                "terminated;reason=noresource".to_owned(),
                "SIP/2.0 503 Service Unavailable\r\n".to_owned()
            ),
        ]
    );
}

// -- the subscription ------------------------------------------------------------

#[test]
fn the_referrer_can_end_the_subscription_and_the_call_goes_on() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    let (_, placed, out) = taken(&mut agent, "unsub", t0);
    let accepted = only(&out, "SIP/2.0 202 ");
    let invite = only(&out, "INVITE ");

    let unsubscribe = from_the_referrer(
        &accepted,
        "SUBSCRIBE",
        "unsub2",
        93_809_824,
        "Event: refer;id=93809823\r\nExpires: 0\r\n",
    );
    deliver(&mut agent, &unsubscribe, t0);
    let out = transmits(&mut agent);
    let ok = only(&out, "SIP/2.0 200 ");
    assert_eq!(text(&ok, HeaderName::Expires), "0");
    // RFC 6665 §4.1.2.3: "a successful unsubscription will also trigger a
    // final NOTIFY request", and §4.2.1.4 says with what reason
    assert_eq!(
        notifies(&out),
        vec![(
            "terminated;reason=timeout".to_owned(),
            "SIP/2.0 100 Trying\r\n".to_owned()
        )]
    );

    // RFC 3515 §2.4.4: ending the subscription "is not an indication that
    // the referenced request should be withdrawn"
    assert_eq!(agent.call_state(placed), Some(CallState::Calling));
    deliver(&mut agent, &answered(&invite, "carol"), t0);
    let up = transmits(&mut agent);
    assert!(up.iter().any(|bytes| bytes.starts_with(b"ACK ")));
    assert!(notifies(&up).is_empty(), "and nobody is told about it");
    assert_eq!(agent.call_state(placed), Some(CallState::Confirmed));
}

#[test]
fn a_refresh_is_granted_no_longer_than_the_subscription_and_answered_with_the_state() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    let (_, _, out) = taken(&mut agent, "refresh", t0);
    let accepted = only(&out, "SIP/2.0 202 ");
    let invite = only(&out, "INVITE ");
    deliver(&mut agent, &ringing(&invite), t0);
    transmits(&mut agent);

    let later = t0 + Duration::from_secs(20);
    let refresh = from_the_referrer(
        &accepted,
        "SUBSCRIBE",
        "refresh2",
        93_809_824,
        "Event: refer\r\nExpires: 7200\r\n",
    );
    deliver(&mut agent, &refresh, later);
    let out = transmits(&mut agent);
    // RFC 6665 §4.2.1.4: "MAY shorten ... but MUST NOT increase it"
    assert_eq!(
        text(&only(&out, "SIP/2.0 200 "), HeaderName::Expires),
        "3600"
    );
    // §4.2.1.2: a refresh accepted is followed by a NOTIFY at once, with the
    // whole state
    assert_eq!(
        notifies(&out),
        vec![(
            "active;expires=3600".to_owned(),
            "SIP/2.0 180 Ringing\r\n".to_owned()
        )]
    );
}

#[test]
fn a_subscription_nobody_refreshes_ends_with_timeout() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    let (_, placed, out) = taken(&mut agent, "lapse", t0);
    let invite = only(&out, "INVITE ");
    // the switchboard takes every NOTIFY, so nothing is still being
    // retransmitted an hour on
    acknowledge(&mut agent, &out, t0);
    deliver(&mut agent, &ringing(&invite), t0);
    let out = transmits(&mut agent);
    acknowledge(&mut agent, &out, t0);

    let hour = t0 + Duration::from_secs(3600);
    assert!(agent.poll_timeout().is_some_and(|at| at <= hour));
    agent.handle_timeout(hour);
    assert_eq!(
        notifies(&transmits(&mut agent)),
        vec![(
            "terminated;reason=timeout".to_owned(),
            "SIP/2.0 180 Ringing\r\n".to_owned()
        )],
        "RFC 6665 §4.2.1.4's NOTIFY for a subscription that was not refreshed"
    );
    assert_eq!(
        agent.call_state(placed),
        Some(CallState::Ringing),
        "the call rings on"
    );
}

#[test]
fn a_subscribe_for_refer_that_matches_no_subscription_is_403() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    // outside any dialog: §2.4.4, "REFER is the only mechanism that can
    // create a subscription to event refer"
    let fresh = String::from_utf8_lossy(&referral("sub", ""))
        .replace("REFER sip:", "SUBSCRIBE sip:")
        .replace("CSeq: 93809823 REFER", "CSeq: 1 SUBSCRIBE")
        .replace(
            "Refer-To: <sip:carol@example.com>\r\n",
            "Event: refer\r\nExpires: 60\r\n",
        );
    deliver(&mut agent, fresh.as_bytes(), t0);
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(status_of(&out[0]), Some(403));

    // and inside a referral's dialog, naming another REFER than the one that
    // opened it (§2.4.6)
    let (_, _, out) = taken(&mut agent, "other", t0);
    let accepted = only(&out, "SIP/2.0 202 ");
    let other = from_the_referrer(
        &accepted,
        "SUBSCRIBE",
        "other2",
        93_809_824,
        "Event: refer;id=5\r\nExpires: 60\r\n",
    );
    deliver(&mut agent, &other, t0);
    let out = transmits(&mut agent);
    assert_eq!(out.len(), 1);
    assert_eq!(status_of(&out[0]), Some(403));
}

#[test]
fn norefersub_is_an_extension_this_end_understands() {
    let t0 = Instant::now();
    let (mut agent, _) = taking(t0);
    // RFC 4488 §4 and RFC 3261 §8.2.2.3: a Require of a tag this end
    // implements is not a 420
    let referral = asked(
        &mut agent,
        "require",
        "Require: norefersub\r\nRefer-Sub: false\r\n",
        t0,
    );
    assert!(agent.referral_waiting(referral));
}

// -- the same subscription, opened by a REFER inside a call -------------------

/// A call from the switchboard, answered and acknowledged: the 200 this end
/// sent, which the REFERs below are written against.
fn in_a_call(agent: &mut UserAgent, branch: &str, now: Instant) -> (CallHandle, Vec<u8>) {
    let invite = format!(
        "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:switchboard@example.com>;tag=call-{branch}\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: call-{branch}@192.0.2.9\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:switchboard@192.0.2.9>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\
\r\n",
        ANSWER.len()
    );
    let mut invite = invite.into_bytes();
    invite.extend_from_slice(ANSWER);
    deliver(agent, &invite, now);
    transmits(agent);
    let call = events(agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::IncomingCall { call, .. } => Some(call),
            _ => None,
        })
        .expect("somebody is calling");
    agent
        .answer(call, Some(Arc::from(OFFER)), now)
        .expect("the 200 goes");
    let ok = only(&transmits(agent), "SIP/2.0 200 ");
    let ack = from_the_referrer(&ok, "ACK", &format!("{branch}ack"), 1, "");
    deliver(agent, &ack, now);
    events(agent);
    (call, ok)
}

/// A REFER inside that call, asking for Carol.
fn refer_in(ok: &[u8], branch: &str, cseq: u32, extra: &str) -> Vec<u8> {
    from_the_referrer(
        ok,
        "REFER",
        branch,
        cseq,
        &format!("Refer-To: <sip:carol@example.com>\r\n{extra}"),
    )
}

#[test]
fn a_transfer_in_a_call_says_how_long_its_subscription_runs() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(line(UDP));
    let (call, ok) = in_a_call(&mut agent, "xfer", t0);
    deliver(&mut agent, &refer_in(&ok, "xferrefer", 2, ""), t0);
    events(&mut agent);
    agent
        .accept_transfer(call, Some(Arc::from(OFFER)), OutgoingExtras::default(), t0)
        .expect("taken");
    // RFC 6665 §4.2.2: "If the value of the "Subscription-State" header
    // field is "active" or "pending", the notifier MUST also include ... an
    // "expires" parameter"
    assert_eq!(
        notifies(&transmits(&mut agent)),
        vec![(
            "active;expires=3600".to_owned(),
            "SIP/2.0 100 Trying\r\n".to_owned()
        )]
    );
}

#[test]
fn refer_sub_false_in_a_call_is_granted_and_leaves_the_call_free_to_be_referred_again() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(line(UDP));
    let (call, ok) = in_a_call(&mut agent, "quietxfer", t0);
    deliver(
        &mut agent,
        &refer_in(&ok, "quietrefer", 2, "Refer-Sub: false\r\n"),
        t0,
    );
    events(&mut agent);
    agent
        .accept_transfer(call, Some(Arc::from(OFFER)), OutgoingExtras::default(), t0)
        .expect("taken");
    let out = transmits(&mut agent);
    assert_eq!(
        text(
            &only(&out, "SIP/2.0 202 "),
            HeaderName::Extension("Refer-Sub")
        ),
        "false",
        "RFC 4488 §4: the 2xx that grants it says so"
    );
    assert!(notifies(&out).is_empty(), "and no NOTIFY follows");
    only(&out, "INVITE ");

    // no subscription is open, so a second REFER is not pending behind one
    deliver(&mut agent, &refer_in(&ok, "quietrefer2", 3, ""), t0);
    assert!(
        transmits(&mut agent)
            .iter()
            .all(|bytes| status_of(bytes) != Some(491)),
        "nothing is pending"
    );
    assert!(
        events(&mut agent)
            .iter()
            .any(|event| matches!(event, UaEvent::TransferRequested { .. }))
    );
}

#[test]
fn a_transfer_whose_call_cannot_leave_ends_its_subscription_with_503() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    agent.add_account(line(NOWHERE));
    let (call, ok) = in_a_call(&mut agent, "stuckxfer", t0);
    deliver(&mut agent, &refer_in(&ok, "stuckrefer", 2, ""), t0);
    events(&mut agent);
    let refused =
        agent.accept_transfer(call, Some(Arc::from(OFFER)), OutgoingExtras::default(), t0);
    assert!(
        matches!(refused, Err(crate::UaError::Send(_))),
        "{refused:?}"
    );
    let out = transmits(&mut agent);
    assert_eq!(
        notifies(&out),
        vec![
            (
                "active;expires=3600".to_owned(),
                "SIP/2.0 100 Trying\r\n".to_owned()
            ),
            (
                "terminated;reason=noresource".to_owned(),
                "SIP/2.0 503 Service Unavailable\r\n".to_owned()
            ),
        ],
        "the transferor is told, rather than left with a 100 nothing follows"
    );
    // and the seat is free again: the subscription is over
    deliver(&mut agent, &refer_in(&ok, "stuckrefer2", 3, ""), t0);
    assert!(
        transmits(&mut agent)
            .iter()
            .all(|bytes| status_of(bytes) != Some(491))
    );
}
